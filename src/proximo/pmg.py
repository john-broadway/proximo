"""Proximo PMG (Proxmox Mail Gateway) lane — backend + tool/plan surface.

Separate backend because PMG is a distinct service from the PVE host:
- API base: https://<pmg-host>:8006/api2/json  (same port as PVE, different host)
- Auth:     ticket-based — CONFIRMED against PMG 9.1:
              POST /access/ticket → {ticket, CSRFPreventionToken}
              Cookie: PMGAuthCookie=<ticket>  (all authenticated requests)
              CSRFPreventionToken: <token>     (mutations only — POST/PUT/DELETE)
            No API tokens in PMG (the only APIToken code in PMG is its PBS-client).
- Paths:    /nodes/{node}/...  /config/...  /statistics/...  /quarantine/...

Most endpoint paths and response shapes are "PMG 9.1 live-verified" via the W1–W5 PMG live-smoke
(auth, read shapes, CRUD cycles, service restart, RuleDB paths). Remaining "Smoke-confirm:" notes
flag specific response field names or edge-case constraints that are not yet confirmed by live-smoke.

Security posture mirrors pbs.py (and is stricter on TLS):
- Password read at login time from password_path; NEVER logged or cached on disk.
- Ticket + CSRF cached in memory only; cleared on 401 and refreshed by a single re-login.
- TLS verification prefers ca_bundle over disabling. FAIL-CLOSED: constructing a
  PmgBackend with verify_tls=False AND no ca_bundle raises — the credential-bearing
  backend refuses to send credentials over a completely unverified channel.
- Input validators use \\Z (not $) to block trailing-newline bypass.
"""

from __future__ import annotations

import ipaddress
import os
import re
import threading
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote

import httpx

from ._secretfile import refuse_exposed_secret
from ._tls import fingerprint_pinned_context, httpx_verify, parse_verify_tls
from ._validate import redact_secrets
from .backends import ProximoError, fingerprint_refused
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# Node name: Proxmox node names are alphanumeric + hyphen; no slash or control chars.
# Smoke-confirm: exact accepted charset for PMG node names (may differ from PVE).
_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}\Z")

# Quarantine mail ID: used as a URL path segment — reject traversal, control chars,
# slash, and semicolons. Exact format is PMG-version-specific.
# Smoke-confirm: exact format of PMG quarantine mail IDs.
_MAIL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


def _check_node(node: str) -> str:
    # Do NOT strip — stripping defeats \Z trailing-newline protection.
    s = str(node)
    if not _NODE_RE.match(s):
        raise ProximoError(
            f"invalid PMG node name: {node!r} "
            "(must start with alnum, then alnum/hyphen, <=64 chars, no control chars)"
        )
    return s


def _check_mail_id(mail_id: str) -> str:
    # Do NOT strip — \Z must catch trailing newlines.
    s = str(mail_id)
    if not _MAIL_ID_RE.match(s):
        raise ProximoError(
            f"invalid quarantine mail ID: {mail_id!r} "
            "(start with alnum, then alnum/._/-, <=128 chars, no slash or control chars)"
        )
    return s


# Tracker IDs are used as a URL path segment in /nodes/{node}/tracker/{id}. They are mail/queue-ish
# tokens (alnum plus a few mail chars); a slash, '..', or query/fragment metachar would be path
# traversal or request injection. We allow a permissive mail charset but reject the structural chars.
_TRACKER_ID_BAD = ("/", "\\", "?", "#", "%", "\x00", "\r", "\n", "\t", " ")


def _check_tracker_id(tracker_id: str) -> str:
    s = str(tracker_id)
    if not s or ".." in s or any(c in s for c in _TRACKER_ID_BAD):
        raise ProximoError(
            f"invalid tracker id: {tracker_id!r} "
            "(no '/', '\\', '..', '?', '#', '%', whitespace or control chars — path-segment safe)"
        )
    return s


# Service name: PMG service names are alphanumeric + hyphen (e.g. pmg-smtp-filter, spamassassin).
# Same charset as node names — protects against path traversal when used as a URL segment.
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}\Z")


def _check_service(service: str) -> str:
    # Do NOT strip — \Z must catch trailing newlines.
    s = str(service)
    if not _SERVICE_RE.match(s):
        raise ProximoError(
            f"invalid PMG service name: {service!r} "
            "(must start with alnum, then alnum/hyphen, <=64 chars, no control chars)"
        )
    return s


# --- Wave 1b: PMG APT-plane validators ---
# Schema truth: .scratch/api-schemas-2026-07-15/methods-pmg.json (`/apt`) cross-checked against
# the live api-viewer full schema (pmg.proxmox.com/pmg-docs/api-viewer/apidoc.js, fetched
# 2026-07-15 since the scratch snapshot carries no param-level detail). PMG's apt shapes mirror
# PVE's exactly (same permissive digest/handle validators, same synchronous changelog text
# return) — unlike PBS, which documents strict sha256-digest and lowercase-handle patterns.
_PMG_APT_PACKAGE_RE = re.compile(r"^[a-z0-9][-+.a-z0-9:]+\Z")
_PMG_APT_REPO_PATH_RE = re.compile(r"^/[^\x00-\x1f\x7f]*\Z")
_PMG_APT_HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}\Z")
_PMG_APT_DIGEST_RE = re.compile(r"^[0-9a-fA-F]{1,80}\Z")


def _check_pmg_apt_package_name(name: str) -> str:
    """Validate an APT package name — PMG's own upstream changelog pattern (identical to PVE's)."""
    s = str(name)
    if not _PMG_APT_PACKAGE_RE.match(s):
        raise ProximoError(
            f"invalid package name: {name!r} "
            "(must start with lowercase alnum, then lowercase alnum/-+.:, min length 2)"
        )
    return s


def _check_pmg_apt_repo_path(path: str) -> str:
    """Validate an APT repository config file path (absolute, no control chars, no traversal)."""
    s = str(path)
    if not _PMG_APT_REPO_PATH_RE.match(s):
        raise ProximoError(f"invalid repository file path: {path!r} (must be an absolute path)")
    if ".." in s.split("/"):
        raise ProximoError(f"path traversal not allowed in repository path: {path!r}")
    return s


def _check_pmg_apt_index(index: int) -> int:
    """Validate a repository entry index (0-based position within its file)."""
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ProximoError(f"invalid repository index: {index!r} (must be a non-negative integer)")
    return index


# PMG APT digest/handle validators below are client-side tightening: PMG's schema places no pattern
# constraints (digest: maxLength 80 only; handle: unconstrained). Defensive for real-world Proxmox
# values (hex digests, alnum-hyphen handles), not schema-mandated.
def _check_pmg_apt_handle(handle: str) -> str:
    """Validate a standard-repository handle (shape-only — PMG's schema documents no fixed
    pattern, same posture as PVE's shape-only validator)."""
    s = str(handle)
    if not _PMG_APT_HANDLE_RE.match(s):
        raise ProximoError(
            f"invalid repository handle: {handle!r} "
            "(must start with alnum, then alnum/hyphen, max 64 chars)"
        )
    return s


def _check_pmg_apt_digest(digest: str | None) -> str | None:
    """Validate an optional optimistic-concurrency digest (hex, <=80 chars per schema — PMG's
    schema documents maxLength 80 with no pattern, same posture as PVE)."""
    if digest is None:
        return None
    s = str(digest)
    if not _PMG_APT_DIGEST_RE.match(s):
        raise ProximoError(f"invalid digest: {digest!r} (expected hex string, max 80 chars)")
    return s


# Valid quarantine action values (pmgsh ls-verified path: POST /quarantine/content).
_QUARANTINE_ACTIONS = frozenset({
    "deliver", "delete", "mark-seen", "mark-unseen", "blocklist", "welcomelist",
})


# ---------------------------------------------------------------------------
# W3 Validators
# ---------------------------------------------------------------------------

# Domain name: used as URL path segment — reject traversal (slashes, ..), control chars.
# Allows alphanumeric, dots, hyphens, underscores (standard DNS charset including underscore
# labels like _dmarc.example.com). Leading hyphen is still rejected (starts with alnum or _).
_DOMAIN_RE = re.compile(r"^[A-Za-z0-9_]([A-Za-z0-9._-]*[A-Za-z0-9_])?\Z")


def _check_domain(domain: str) -> str:
    # Do NOT strip — \Z must catch trailing newlines.
    s = str(domain)
    if not _DOMAIN_RE.match(s):
        raise ProximoError(
            f"invalid domain: {domain!r} "
            "(must start with alnum, allow alnum/dots/hyphens/underscores, "
            "no slash or control chars)"
        )
    return s


def _check_cidr(cidr: str) -> str:
    """Validate a CIDR network expression using the stdlib ipaddress module.

    Uses strict=False so host bits are tolerated (e.g. '192.168.1.1/24'
    is accepted as '192.168.1.0/24'). Trailing whitespace and newlines
    cause ValueError in the stdlib parser and are therefore rejected.
    """
    try:
        ipaddress.ip_network(str(cidr), strict=False)
    except ValueError as exc:
        raise ProximoError(
            f"invalid CIDR: {cidr!r} — {exc}"
        ) from exc
    return str(cidr)


# Transport protocol: PMG 9.1 live-verified via pmgsh help /config/transport.
_TRANSPORT_PROTOCOLS = frozenset({"smtp", "lmtp"})


def _check_transport_protocol(protocol: str) -> str:
    if protocol not in _TRANSPORT_PROTOCOLS:
        raise ProximoError(
            f"invalid transport protocol: {protocol!r}. "
            f"Must be one of: {', '.join(sorted(_TRANSPORT_PROTOCOLS))}"
        )
    return protocol


# Service action: valid actions for /nodes/{node}/services/{service}/{action}.
# PMG 9.1 live-verified via pmgsh ls.
_SERVICE_ACTIONS = frozenset({"start", "stop", "restart", "reload"})


def _check_service_action(action: str) -> str:
    if action not in _SERVICE_ACTIONS:
        raise ProximoError(
            f"invalid service action: {action!r}. "
            f"Must be one of: {', '.join(sorted(_SERVICE_ACTIONS))}"
        )
    return action


# ---------------------------------------------------------------------------
# PmgConfig
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PmgConfig:
    """Configuration for the PMG API backend.

    All credentials are referenced by PATH — values are read at call time
    and never logged, so the secrets vault is never echoed.

    env vars:
        PROXIMO_PMG_BASE_URL       required  https://<host>:8006/api2/json
        PROXIMO_PMG_PASSWORD_PATH  required  file containing the PMG user password
        PROXIMO_PMG_USERNAME       optional  default "root@pam"
        PROXIMO_PMG_NODE           optional  default "pmg"
        PROXIMO_PMG_VERIFY_TLS     optional  default "true"; set "false" to skip (warn)
        PROXIMO_PMG_CA_BUNDLE      optional  path to CA cert bundle (preferred over disabling TLS)
        PROXIMO_PMG_FINGERPRINT    optional  WIRE-ENFORCED exact-cert SHA-256 pin (self-signed PMG)
    """

    base_url: str        # e.g. "https://pmg.example.lan:8006/api2/json"
    password_path: str   # file containing the PMG user password (read at login time)
    username: str = "root@pam"
    node: str = "pmg"
    verify_tls: bool = True
    ca_bundle: str | None = None
    fingerprint: str | None = None  # WIRE-ENFORCED exact-cert pin — see PmgBackend.__init__

    @classmethod
    def from_env(cls) -> PmgConfig:
        try:
            base_url = os.environ["PROXIMO_PMG_BASE_URL"]
            password_path = os.environ["PROXIMO_PMG_PASSWORD_PATH"]
        except KeyError as e:
            raise RuntimeError(
                f"Missing required PMG env var: {e.args[0]}. "
                "Set PROXIMO_PMG_BASE_URL and PROXIMO_PMG_PASSWORD_PATH to configure "
                "the Proxmox Mail Gateway backend."
            ) from e

        username = os.environ.get("PROXIMO_PMG_USERNAME", "root@pam")
        node = os.environ.get("PROXIMO_PMG_NODE", "pmg")
        verify_tls = parse_verify_tls(os.environ.get("PROXIMO_PMG_VERIFY_TLS", "true"))
        ca_bundle = os.environ.get("PROXIMO_PMG_CA_BUNDLE") or None
        fingerprint = os.environ.get("PROXIMO_PMG_FINGERPRINT") or None

        if not verify_tls and not ca_bundle and not fingerprint:
            warnings.warn(
                "PROXIMO_PMG_VERIFY_TLS=false with no CA bundle and no fingerprint — "
                "talking to the PMG API without cert validation.",
                stacklevel=2,
            )

        refuse_exposed_secret(password_path, "PMG password file")
        return cls(
            base_url=base_url.rstrip("/"),
            password_path=password_path,
            username=username,
            node=node,
            verify_tls=verify_tls,
            ca_bundle=ca_bundle,
            fingerprint=fingerprint,
        )



    @classmethod
    def from_target(cls, fields: dict) -> PmgConfig:
        """Build a PMG config from a named registry remote (see proximo.targets)."""
        try:
            base_url = fields["base_url"]
            password_path = fields["password_path"]
        except KeyError as e:
            raise RuntimeError(f"target missing required field: {e.args[0]}") from e
        username = fields.get("username", "root@pam")
        node = fields.get("node", "pmg")
        verify_tls = parse_verify_tls(fields.get("verify_tls", "true"))
        ca_bundle = fields.get("ca_bundle") or None
        fingerprint = fields.get("fingerprint") or None
        if not verify_tls and not ca_bundle and not fingerprint:
            warnings.warn(
                "PMG target verify_tls=false with no CA bundle and no fingerprint — "
                "talking to the PMG API without cert validation.",
                stacklevel=2,
            )
        refuse_exposed_secret(password_path, "PMG password file")
        return cls(
            base_url=base_url.rstrip("/"),
            password_path=password_path,
            username=username,
            node=node,
            verify_tls=verify_tls,
            ca_bundle=ca_bundle,
            fingerprint=fingerprint,
        )


# ---------------------------------------------------------------------------
# PmgBackend
# ---------------------------------------------------------------------------

class PmgBackend:
    """Management via the Proxmox Mail Gateway REST API using ticket-based auth.

    Auth flow CONFIRMED against PMG 9.1:
    - Login: POST /access/ticket with form params {username, password}
      → {ticket, CSRFPreventionToken}
    - Reads (GET): Cookie: PMGAuthCookie=<ticket>
    - Mutations (POST/PUT/DELETE): Cookie: PMGAuthCookie=<ticket>
                                   CSRFPreventionToken: <token>
    - On HTTP 401 from any call: clear the cached ticket, re-login ONCE, retry.
      If the retry also returns 401, raise_for_status raises.
    - Tickets expire (~2 h); login is lazy — first authenticated call triggers it.

    No API tokens — PMG has none of its own (the only APIToken code in PMG is its
    client for talking to a PBS backup server, not PMG's own auth).

    Self-contained: does NOT depend on ProximoConfig. Use PmgConfig.from_env()
    or construct PmgConfig directly for tests.
    """

    def __init__(self, config: PmgConfig):
        self.config = config
        if config.fingerprint:
            # WIRE-ENFORCED pin: exact-cert SHA-256 match replaces CA/hostname validation
            # (self-signed PMG). Mismatch closes the socket before credentials are sent.
            try:
                ctx = fingerprint_pinned_context(config.fingerprint)
            except ValueError as e:
                raise fingerprint_refused("PMG", e) from e
            self._client = httpx.Client(base_url=config.base_url, verify=ctx, timeout=60)
            self._ticket = None
            self._csrf = None
            self._lock = threading.Lock()
            return
        verify: bool | str = config.ca_bundle if config.ca_bundle else config.verify_tls
        # FAIL-CLOSED: this backend sends credentials on login. Refuse to construct
        # over a completely unverified channel (verify_tls=False AND no ca_bundle AND no
        # fingerprint). A ca_bundle, a pin, or system CA trust is required.
        if verify is False:
            raise ProximoError(
                "refusing to send PMG credentials over unverified TLS: set PROXIMO_PMG_FINGERPRINT "
                "to the cert's SHA-256 (self-signed PMG), PROXIMO_PMG_CA_BUNDLE to the PMG CA cert, "
                "or PROXIMO_PMG_VERIFY_TLS=true."
            )
        self._client = httpx.Client(base_url=config.base_url, verify=httpx_verify(verify), timeout=60)
        self._ticket: str | None = None
        self._csrf: str | None = None
        self._lock = threading.Lock()

    def _login(self) -> None:
        """POST /access/ticket to obtain a session ticket and CSRF token.

        Password is read from config.password_path at call time — NEVER logged,
        never stored beyond the local scope of this method.
        """
        with open(self.config.password_path, encoding="utf-8") as f:
            password = f.read().strip()
        r = self._client.post(
            "/access/ticket",
            data={"username": self.config.username, "password": password},
        )
        r.raise_for_status()
        data = r.json()["data"]
        self._ticket = data["ticket"]
        self._csrf = data["CSRFPreventionToken"]

    def _ensure_ticket(self) -> None:
        """Lazy login — only calls _login() if no cached ticket exists.

        Uses double-checked locking so concurrent threads that both see
        ``_ticket is None`` don't each trigger a separate login: the second
        thread to acquire the lock re-checks and skips the call.
        """
        if self._ticket is None:
            with self._lock:
                if self._ticket is None:
                    self._login()

    def _cookie_headers(self) -> dict[str, str]:
        """Headers for read (GET) requests — cookie only, no CSRF."""
        return {"Cookie": f"PMGAuthCookie={self._ticket}"}

    def _mutation_headers(self) -> dict[str, str]:
        """Headers for mutation (POST/PUT/DELETE) requests — cookie + CSRF."""
        return {
            "Cookie": f"PMGAuthCookie={self._ticket}",
            "CSRFPreventionToken": self._csrf or "",
        }

    def _get(self, path: str, params: dict | None = None):
        self._ensure_ticket()
        r = self._client.get(path, headers=self._cookie_headers(), params=params or {})
        if r.status_code == 401:
            with self._lock:
                self._ticket = None
                self._csrf = None
                self._login()
            r = self._client.get(path, headers=self._cookie_headers(), params=params or {})
        r.raise_for_status()
        return r.json().get("data")

    @staticmethod
    def _form(d: dict | None) -> dict:
        # PMG (like PVE/PBS) wants booleans as 1/0; a raw Python bool serializes to 'true'/'false'
        # and may be rejected. Coerce so any tool may pass a native bool.
        return {k: (1 if v is True else 0 if v is False else v) for k, v in (d or {}).items()}

    def _post(self, path: str, data: dict | None = None):
        self._ensure_ticket()
        r = self._client.post(path, headers=self._mutation_headers(), data=self._form(data))
        if r.status_code == 401:
            with self._lock:
                self._ticket = None
                self._csrf = None
                self._login()
            r = self._client.post(path, headers=self._mutation_headers(), data=self._form(data))
        r.raise_for_status()
        return r.json().get("data")

    def _put(self, path: str, data: dict | None = None):
        self._ensure_ticket()
        r = self._client.put(path, headers=self._mutation_headers(), data=self._form(data))
        if r.status_code == 401:
            with self._lock:
                self._ticket = None
                self._csrf = None
                self._login()
            r = self._client.put(path, headers=self._mutation_headers(), data=self._form(data))
        r.raise_for_status()
        return r.json().get("data")

    def _delete(self, path: str, params: dict | None = None):
        self._ensure_ticket()
        r = self._client.delete(path, headers=self._mutation_headers(), params=params or {})
        if r.status_code == 401:
            with self._lock:
                self._ticket = None
                self._csrf = None
                self._login()
            r = self._client.delete(path, headers=self._mutation_headers(), params=params or {})
        r.raise_for_status()
        return r.json().get("data")


# ---------------------------------------------------------------------------
# READ operations — no plan needed; audited by the server layer
# ---------------------------------------------------------------------------

def node_version(api: PmgBackend, node: str) -> dict:
    """Get PMG version.

    GET /version

    PMG 9.1 live-verified: version is global (not per-node); /nodes/{node}/version
    returns 501. The ``node`` parameter is accepted for API compatibility but unused.
    """
    _check_node(node)  # validate node param even though it is not used in the path
    return api._get("/version") or {}


def access_permissions(api: PmgBackend) -> list:
    """Get users and their roles from the authenticated PMG instance.

    GET /access/users

    PMG 9.1 live-verified: PMG has no /access/permissions endpoint (that is PVE-only).
    The closest equivalent is /access/users, which returns each user's assigned role
    (e.g. 'root', 'admin', 'audit'). Used by pmg_doctor to show the credential context.
    """
    return api._get("/access/users") or []


def node_status(api: PmgBackend, node: str) -> dict:
    """Get node cpu/mem/disk/uptime status.

    GET /nodes/{node}/status

    PMG 9.1 live-verified path via pmg-smoke.py W1 (node_status round-trip PASS).
    """
    node = _check_node(node)
    return api._get(f"/nodes/{node}/status") or {}


# ---------------------------------------------------------------------------
# APT plane (Wave 1b, 2026-07-15): patch-visibility + repository governance.
# Schema truth: .scratch/api-schemas-2026-07-15/methods-pmg.json (`/apt`) + the live api-viewer
# full schema (pmg.proxmox.com/pmg-docs/api-viewer/apidoc.js) — PMG's shapes mirror PVE's
# exactly (see the validator-block comment above). HONESTY LINE (every apt_* docstring in this
# plane, mirrored from PVE Wave 1a): Proxmox's API deliberately does not expose upgrade
# execution; the upgrade itself happens at your console. These methods govern visibility and
# repo config only.
# ---------------------------------------------------------------------------

def apt_updates_list(api: PmgBackend, node: str) -> list[dict]:
    """List available package updates (cached apt index) on a PMG node.

    GET /nodes/{node}/apt/update

    Smoke-confirm: shape not live-verified. Expected per-package dicts per schema truth.
    """
    node = _check_node(node)
    return api._get(f"/nodes/{node}/apt/update") or []


def apt_changelog(api: PmgBackend, name: str, node: str, version: str | None = None) -> str:
    """Get a package's changelog text on a PMG node.

    GET /nodes/{node}/apt/changelog?name=…[&version=…]

    Smoke-confirm: shape not live-verified. `name` is validated against PMG's own upstream
    package-name pattern (identical to PVE's). The returned text is UPSTREAM/package-
    maintainer-authored (not Proxmox-authored) — classified taint.ADVERSARIAL_TOOLS, like
    pve_apt_changelog and pbs_apt_changelog.
    """
    node = _check_node(node)
    _check_pmg_apt_package_name(name)
    params: dict = {"name": name}
    if version is not None:
        params["version"] = version
    return api._get(f"/nodes/{node}/apt/changelog", params=params) or ""


def apt_repositories_get(api: PmgBackend, node: str) -> dict:
    """Get the current APT repository configuration of a PMG node.

    GET /nodes/{node}/apt/repositories

    Smoke-confirm: shape not live-verified. Expected {files, errors, digest, infos,
    standard-repos} per schema truth.
    """
    node = _check_node(node)
    return api._get(f"/nodes/{node}/apt/repositories") or {}


def apt_versions(api: PmgBackend, node: str) -> list[dict]:
    """Get installed versions of important Proxmox packages on a PMG node.

    GET /nodes/{node}/apt/versions

    Smoke-confirm: shape not live-verified. Expected per-package dicts per schema truth.
    """
    node = _check_node(node)
    return api._get(f"/nodes/{node}/apt/versions") or []


def apt_update_refresh(
    api: PmgBackend, node: str, notify: bool | None = None, quiet: bool | None = None,
) -> str | None:
    """Resynchronize the APT package index on a PMG node (apt-get update).

    POST /nodes/{node}/apt/update  →  task identifier string (async)

    Refreshes the index ONLY — does not install or upgrade any package.
    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: exact return shape (task id string vs null).
    """
    node = _check_node(node)
    body = {k: v for k, v in {"notify": notify, "quiet": quiet}.items() if v is not None}
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/nodes/{node}/apt/update", body)


def apt_repository_set(
    api: PmgBackend,
    path: str,
    index: int,
    node: str,
    enabled: bool | None = None,
    digest: str | None = None,
) -> None:
    """Enable/disable one APT repository entry on a PMG node, by file path + index.

    POST /nodes/{node}/apt/repositories  body: {path, index, enabled?, digest?}  →  null

    digest (hex, <=80 chars) asserts the current config file digest for optimistic-concurrency —
    forwarded when the caller supplies it.
    MUTATION — confirm-gated + audited at the server layer.
    """
    node = _check_node(node)
    _check_pmg_apt_repo_path(path)
    _check_pmg_apt_index(index)
    _check_pmg_apt_digest(digest)
    body: dict = {"path": path, "index": index}
    if enabled is not None:
        body["enabled"] = enabled
    if digest is not None:
        body["digest"] = digest
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/nodes/{node}/apt/repositories", body)


def apt_repository_add(
    api: PmgBackend, handle: str, node: str, digest: str | None = None,
) -> None:
    """Add a standard repository to the configuration on a PMG node.

    PUT /nodes/{node}/apt/repositories  body: {handle, digest?}  →  null

    digest (hex, <=80 chars) asserts the current config file digest for optimistic-concurrency —
    forwarded when the caller supplies it.
    MUTATION — confirm-gated + audited at the server layer.
    """
    node = _check_node(node)
    _check_pmg_apt_handle(handle)
    _check_pmg_apt_digest(digest)
    body: dict = {"handle": handle}
    if digest is not None:
        body["digest"] = digest
    # MUTATION — confirm-gated + audited at the server layer.
    return api._put(f"/nodes/{node}/apt/repositories", body)


def relay_config(api: PmgBackend) -> dict:
    """Get SMTP relay/smarthost configuration.

    GET /config/mail

    PMG 9.1 live-verified: relay/smarthost settings live in /config/mail (not a
    separate /config/relay path that does not exist). Returns the full mail section
    which includes relay host, relay port, and other SMTP delivery settings.
    """
    return api._get("/config/mail") or {}


def domains_list(api: PmgBackend) -> list[dict]:
    """List managed mail domains.

    GET /config/domains

    PMG 9.1 live-verified path via pmg-smoke.py W1 (domains_list PASS) and W3
    (domain_create → domains_list → domain_delete full cycle).
    """
    return api._get("/config/domains") or []


def statistics_mail(
    api: PmgBackend,
) -> dict:
    """Get mail delivery statistics for today (totals since midnight).

    GET /statistics/mail

    PMG 9.1 live-verified: /statistics/mail returns today's aggregate counters
    (count_in, count_out, spam, virus, bytes, …). It does NOT accept start/end
    query parameters — passing them causes HTTP 400. For time-ranged data use
    /statistics/mailcount instead.
    """
    return api._get("/statistics/mail") or {}


def quarantine_spam(
    api: PmgBackend,
) -> list[dict]:
    """List quarantined spam messages.

    GET /quarantine/spam

    PMG 9.1 live-verified: the spam quarantine list is at /quarantine/spam (not the
    non-existent /quarantine/mails). The endpoint does not accept limit/start query
    parameters — passing them causes HTTP 400.

    For virus quarantine use /quarantine/virus. For attachment quarantine use
    /quarantine/attachment.
    """
    return api._get("/quarantine/spam") or []


# ---------------------------------------------------------------------------
# MUTATION operations — confirm-gated at the server layer
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# PLAN functions — pure factories; no mutation; the PLAN pillar
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# W2 READ operations
# ---------------------------------------------------------------------------

def _epoch_range_params(start: int | None, end: int | None) -> dict:
    """Validate optional Unix-epoch start/end params and return as a starttime/endtime dict.

    Shared by every PMG read op that maps tool start/end → API starttime/endtime
    query params (statistics/tracker/quarantine time-range filters).
    """
    params: dict = {}
    if start is not None:
        try:
            params["starttime"] = int(start)
        except (ValueError, TypeError) as exc:
            raise ProximoError(
                f"invalid start: {start!r} (must be an integer Unix epoch)"
            ) from exc
    if end is not None:
        try:
            params["endtime"] = int(end)
        except (ValueError, TypeError) as exc:
            raise ProximoError(
                f"invalid end: {end!r} (must be an integer Unix epoch)"
            ) from exc
    return params


def statistics_domains(
    api: PmgBackend,
    start: int | None = None,
    end: int | None = None,
) -> list[dict]:
    """Get per-domain mail statistics.

    GET /statistics/domains

    PMG 9.1 live-verified path via pmgsh ls.
    Maps tool start/end epoch params → starttime/endtime query params.
    """
    params = _epoch_range_params(start, end)
    return api._get("/statistics/domains", params=params if params else None) or []


def statistics_virus(
    api: PmgBackend,
    start: int | None = None,
    end: int | None = None,
) -> list[dict]:
    """Get virus statistics.

    GET /statistics/virus

    PMG 9.1 live-verified path via pmgsh ls.
    Maps tool start/end epoch params → starttime/endtime query params.
    """
    params = _epoch_range_params(start, end)
    return api._get("/statistics/virus", params=params if params else None) or []


def statistics_spamscores(
    api: PmgBackend,
    start: int | None = None,
    end: int | None = None,
) -> list[dict]:
    """Get spam score distribution statistics.

    GET /statistics/spamscores

    PMG 9.1 live-verified path via pmgsh ls.
    Maps tool start/end epoch params → starttime/endtime query params.
    """
    params = _epoch_range_params(start, end)
    return api._get("/statistics/spamscores", params=params if params else None) or []


def statistics_recent(api: PmgBackend, hours: int = 1) -> list[dict]:
    """Get recent mail statistics.

    GET /statistics/recent

    PMG 9.1 live-verified path via pmgsh ls.
    hours: 1-24 (window of recent mail activity to retrieve).
    """
    try:
        h = int(hours)
    except (ValueError, TypeError) as exc:
        raise ProximoError(f"invalid hours: {hours!r} — must be an integer") from exc
    return api._get("/statistics/recent", params={"hours": h}) or []


def quarantine_blocklist_list(
    api: PmgBackend,
    pmail: str | None = None,
) -> list[dict]:
    """List blocklist entries.

    GET /quarantine/blocklist

    PMG 9.1 live-verified: the API requires pmail for root@pam (and scopes
    the result to that user's blocklist for non-root users). When pmail is
    not provided it defaults to api.config.username (the authenticated user).
    pmail: optional per-user mail address — overrides the default username scope.
    """
    effective_pmail = pmail if pmail is not None else api.config.username
    return api._get("/quarantine/blocklist", params={"pmail": effective_pmail}) or []


def postfix_qshape(api: PmgBackend, node: str) -> list[dict]:
    """Get Postfix queue shape (queue sizes and message-age distribution).

    GET /nodes/{node}/postfix/qshape

    PMG 9.1 live-verified: returns a list of dicts, one row per domain
    (plus a TOTAL row), each with queue-age bucket counts.
    """
    node = _check_node(node)
    return api._get(f"/nodes/{node}/postfix/qshape") or []


def spam_config(api: PmgBackend) -> dict:
    """Get PMG spam filter configuration.

    GET /config/spam

    PMG 9.1 live-verified path via pmgsh ls.
    """
    return api._get("/config/spam") or {}


def service_status(api: PmgBackend, service: str, node: str | None = None) -> dict:
    """Get the status of a PMG system service.

    GET /nodes/{node}/services/{service}/state

    PMG 9.1 live-verified path via pmgsh ls.
    service: service name (e.g. 'postfix', 'pmgproxy', 'pmgdaemon', 'pmgmirror',
             'pmgtunnel', 'pmg-smtp-filter', 'clamav', 'spamassassin').
             No hardcoded enum — any valid name is accepted; unknown names return
             a PMG 404. Must be alphanumeric + hyphen (no path traversal).
    """
    service = _check_service(service)
    node = _check_node(node or "pmg")
    return api._get(f"/nodes/{node}/services/{service}/state") or {}


# ---------------------------------------------------------------------------
# W2 MUTATION operations — confirm-gated at the server layer
# ---------------------------------------------------------------------------

def quarantine_blocklist_add(
    api: PmgBackend,
    address: str,
    pmail: str | None = None,
) -> object:
    """Add an address to the quarantine blocklist.

    POST /quarantine/blocklist

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified: pmail is required by PMG for root@pam (and scopes
    the entry to that user's blocklist for non-root users). When pmail is not
    provided it defaults to api.config.username.
    address: the email address or domain to blocklist.
    pmail: optional per-user mail address — overrides the default username scope.
    """
    effective_pmail = pmail if pmail is not None else api.config.username
    body: dict = {"address": address, "pmail": effective_pmail}
    return api._post("/quarantine/blocklist", data=body)


def quarantine_blocklist_remove(
    api: PmgBackend,
    address: str,
    pmail: str | None = None,
) -> object:
    """Remove an address from the quarantine blocklist.

    DELETE /quarantine/blocklist?address=<address>&pmail=<pmail>

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified: the delete is issued via DELETE /quarantine/blocklist
    with address and pmail as query parameters (not a path segment — PMG 9.1
    returns 501 for DELETE /quarantine/blocklist/{address}).
    When pmail is not provided it defaults to api.config.username.
    """
    effective_pmail = pmail if pmail is not None else api.config.username
    return api._delete("/quarantine/blocklist",
                       params={"address": address, "pmail": effective_pmail})


def quarantine_action(
    api: PmgBackend,
    action: str,
    mail_ids: str,
) -> object:
    """Apply an action to one or more quarantined messages.

    POST /quarantine/content

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-proven 2026-06-26: path via pmgsh ls + delete/deliver executed
    against real quarantined GTUBE messages.
    action: one of deliver|delete|mark-seen|mark-unseen|blocklist|welcomelist.
    mail_ids: mail ID or comma-separated list of mail IDs to act on.
    """
    if action not in _QUARANTINE_ACTIONS:
        raise ProximoError(
            f"invalid quarantine action: {action!r}. "
            f"Must be one of: {', '.join(sorted(_QUARANTINE_ACTIONS))}"
        )
    return api._post("/quarantine/content", data={"action": action, "id": mail_ids})


def postfix_flush(api: PmgBackend, node: str) -> object:
    """Flush all Postfix queues (attempt immediate re-delivery of deferred mail).

    POST /nodes/{node}/postfix/flush_queues

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path via pmgsh ls.
    """
    node = _check_node(node)
    return api._post(f"/nodes/{node}/postfix/flush_queues")


# ---------------------------------------------------------------------------
# W2 PLAN functions — pure factories; no mutation; the PLAN pillar
# ---------------------------------------------------------------------------

def _quarantine_scope(pmail: str | None, default_pmail: str | None, list_name: str) -> tuple[str, str]:
    """Truthful per-user scope for the quarantine block/welcomelist PLANs. PMG {block,welcome}lists are
    PER-USER; the executor always sends pmail, defaulting to the authenticated user (api.config.username)
    — so the effect is NEVER global. Returns (change_suffix, blast_line). ``default_pmail`` is the
    executor's default (the authenticated PMG user); when known it is named so the preview matches the
    exact request that will run. Earlier versions rendered '(global)/all users' here — a false blast
    radius on the PLAN surface (2026-07-10 audit H1)."""
    effective = pmail if pmail is not None else default_pmail
    who = effective or "the authenticated PMG user"
    suffix = f" for {who}"
    line = (
        f"scope: per-user ({who}) — this is {who}'s personal {list_name}, NOT a site-wide filter"
        + ("" if pmail is not None else "; pmail defaulted to the authenticated PMG user")
    )
    return suffix, line


def plan_quarantine_blocklist_add(
    address: str, pmail: str | None = None, default_pmail: str | None = None
) -> Plan:
    """Preview adding an address to the quarantine blocklist.  PURE — no API call.

    RISK_LOW: adds an entry to the blocklist; does not delete any existing messages.
    Only future mail from the address is affected.
    """
    scope, scope_line = _quarantine_scope(pmail, default_pmail, "blocklist")
    return Plan(
        action="pmg_quarantine_blocklist_add",
        target="quarantine/blocklist",
        change=f"add '{address}' to the quarantine blocklist{scope}",
        current={},
        blast_radius=[
            f"future messages from '{address}' will be blocked and quarantined",
            scope_line,
            "additive: does not delete any existing quarantine entries or messages",
            "only future inbound mail matching this address/domain is affected",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: adds one blocklist entry; no messages or data deleted",
            "LOW: only future mail is affected, not existing quarantine or mailbox contents",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: POST /quarantine/blocklist.",
    )


def plan_quarantine_action(action: str, mail_ids: str) -> Plan:
    """Preview applying an action to quarantined messages.  PURE — no API call.

    RISK_MEDIUM: action may be destructive (e.g. delete permanently removes messages).
    Validates the action enum before building the plan.
    """
    if action not in _QUARANTINE_ACTIONS:
        raise ProximoError(
            f"invalid quarantine action: {action!r}. "
            f"Must be one of: {', '.join(sorted(_QUARANTINE_ACTIONS))}"
        )
    return Plan(
        action="pmg_quarantine_action",
        target="quarantine/content",
        change=f"apply action '{action}' to quarantined message(s): {mail_ids}",
        current={},
        blast_radius=[
            f"action '{action}' applied to: {mail_ids}",
            "deliver: releases message(s) to recipient(s) — additive, no quarantine data deleted",
            "delete: permanently removes message(s) from quarantine — IRREVERSIBLE",
            "mark-seen/mark-unseen: metadata change only — no messages delivered or deleted",
            "blocklist/welcomelist: adds sender to the respective list — additive",
            "live-proven 2026-06-26: delete and deliver both confirmed on real GTUBE messages",
        ],
        risk=RISK_HIGH if action == "delete" else RISK_MEDIUM,
        risk_reasons=[
            "HIGH for action='delete': permanently and irreversibly removes quarantined messages",
            "other actions (deliver, mark-*, blocklist, welcomelist) are MEDIUM — reversible or additive",
        ],
        note=(
            "PMG 9.1 live-proven 2026-06-26: POST /quarantine/content with action=delete "
            "and action=deliver both execute correctly against real quarantined messages. "
            "delete: entry permanently removed. deliver: entry removed, message released."
        ),
    )


def plan_postfix_flush(node: str) -> Plan:
    """Preview flushing all Postfix queues.  PURE — no API call.

    RISK_LOW: attempts immediate re-delivery of deferred mail; no data is deleted.
    """
    node = _check_node(node)
    return Plan(
        action="pmg_postfix_flush",
        target=f"pmg/{node}/postfix/flush_queues",
        change=f"flush all Postfix mail queues on node '{node}'",
        current={},
        blast_radius=[
            f"triggers immediate re-delivery attempt for all deferred mail on '{node}'",
            "may cause a burst of outbound SMTP connections during the flush",
            "no messages are deleted — deferred mail that cannot be delivered stays deferred",
            "additive: queue flush is a standard mail server operation",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: no mail is deleted; flush only attempts re-delivery of deferred messages",
            "LOW: standard Postfix operation; temporary connection burst is expected behavior",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: POST /nodes/{node}/postfix/flush_queues.",
    )


# ---------------------------------------------------------------------------
# APT plane PLAN factories (Wave 1b, 2026-07-15)
# ---------------------------------------------------------------------------

def plan_apt_update_refresh(
    node: str, notify: bool | None = None, quiet: bool | None = None,
) -> Plan:
    """Plan for pmg_apt_update_refresh — resynchronize the APT package index (apt-get update).

    No CAPTURE: refreshing the index is idempotent (re-running it any time is always safe) —
    there is no meaningful "current index state" to snapshot for revert.
    """
    node = _check_node(node)
    return Plan(
        action="pmg_apt_update_refresh",
        target=f"pmg/{node}/apt/update",
        change=f"resynchronize the APT package index on PMG node '{node}' (apt-get update)",
        current={},
        blast_radius=[
            f"node/{node} APT package index cache — refreshes available-update metadata only; "
            "does NOT install or upgrade any package (Proxmox's API deliberately does not "
            "expose upgrade execution — the upgrade itself happens at your console)"
        ],
        risk=RISK_LOW,
        risk_reasons=["no package state change — only refreshes the local index cache"],
        note="Idempotent — safe to re-run any time; no revert needed.",
    )


def plan_apt_repository_set(
    api: PmgBackend,
    path: str,
    index: int,
    node: str,
    enabled: bool | None = None,
    digest: str | None = None,
) -> Plan:
    """Plan for pmg_apt_repository_set — enable/disable one repository entry by path+index.

    CAPTURE-or-declare: reads current repository state via GET /apt/repositories (reuses
    apt_repositories_get) and looks up the file+index entry's current shape; a successful read
    that simply finds no match degrades to current={} (honest empty snapshot), not a failure —
    only a raised exception on the read itself sets complete=False.
    """
    node = _check_node(node)
    _check_pmg_apt_repo_path(path)
    _check_pmg_apt_index(index)
    _check_pmg_apt_digest(digest)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        result = api._get(f"/nodes/{node}/apt/repositories") or {}
        for f in result.get("files") or []:
            if f.get("path") == path:
                current["file_digest"] = f.get("digest")
                repos = f.get("repositories") or []
                if 0 <= index < len(repos):
                    current["entry"] = repos[index]
                break
    except Exception:
        complete = False
        note_capture = " Could not capture current repository state — no guided revert available."
    changes = {k: v for k, v in {"enabled": enabled}.items() if v is not None}
    return Plan(
        action="pmg_apt_repository_set",
        target=f"pmg/{node}/apt/repositories:{path}#{index}",
        change=f"change repository entry {index} in {path!r} on PMG node '{node}': {changes}",
        current=current,
        blast_radius=[
            f"node/{node} APT sources — {path!r} entry {index}: changes where packages come "
            "from; the NEXT apt-get upgrade (run at your console — this API does not execute "
            "it) pulls from the new set"
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "changes which repository entry is enabled/disabled — affects package provenance "
            "for the next upgrade"
        ],
        complete=complete,
        note=(
            "Revert by re-applying the captured enabled-state with pmg_apt_repository_set."
            + note_capture
        ),
    )


def plan_apt_repository_add(
    api: PmgBackend, handle: str, node: str, digest: str | None = None,
) -> Plan:
    """Plan for pmg_apt_repository_add — add a standard repository to the configuration.

    CAPTURE-or-declare: reads current repository state via GET /apt/repositories (reuses
    apt_repositories_get) and looks up the handle's current standard-repo status; a successful
    read that simply finds no match degrades to current={} (honest empty snapshot — the handle
    was never added), not a failure — only a raised exception on the read itself sets
    complete=False.
    """
    node = _check_node(node)
    _check_pmg_apt_handle(handle)
    _check_pmg_apt_digest(digest)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        result = api._get(f"/nodes/{node}/apt/repositories") or {}
        standard = result.get("standard-repos") or []
        current = next((r for r in standard if r.get("handle") == handle), {})
    except Exception:
        complete = False
        note_capture = " Could not capture current standard-repo status — no guided revert available."
    return Plan(
        action="pmg_apt_repository_add",
        target=f"pmg/{node}/apt/repositories:{handle}",
        change=f"add standard repository {handle!r} to the configuration on PMG node '{node}'",
        current=current,
        blast_radius=[
            f"node/{node} APT sources — adds {handle!r}; the NEXT apt-get upgrade (run at your "
            "console — this API does not execute it) additionally pulls packages from it"
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["adds a new package source — affects package provenance for the next upgrade"],
        complete=complete,
        note=(
            "No automatic revert: removing an added repository requires pmg_apt_repository_set "
            "to disable the resulting entry (there is no repository-delete endpoint)."
            + note_capture
        ),
    )


# ---------------------------------------------------------------------------
# W3 READ operations
# ---------------------------------------------------------------------------

def quarantine_welcomelist_list(
    api: PmgBackend,
    pmail: str | None = None,
) -> list[dict]:
    """List quarantine welcomelist entries.

    GET /quarantine/welcomelist

    PMG 9.1 live-verified path via pmgsh ls.
    pmail: optional per-user mail address — scopes the list to that user.
    When pmail is not provided it defaults to api.config.username (PMG requires it for root@pam).
    """
    effective_pmail = pmail if pmail is not None else api.config.username
    return api._get("/quarantine/welcomelist", params={"pmail": effective_pmail}) or []


# ---------------------------------------------------------------------------
# W3 MUTATION operations — confirm-gated at the server layer
# ---------------------------------------------------------------------------

def domain_create(api: PmgBackend, domain: str, comment: str | None = None) -> object:
    """Create a managed mail domain.

    POST /config/domains

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path via pmgsh ls.
    domain: domain name to manage (e.g. 'example.com').
    """
    domain = _check_domain(domain)
    body: dict = {"domain": domain}
    if comment is not None:
        body["comment"] = comment
    return api._post("/config/domains", data=body)


def domain_delete(api: PmgBackend, domain: str) -> object:
    """Delete a managed mail domain.

    DELETE /config/domains/{domain}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path via pmgsh ls.
    """
    domain = _check_domain(domain)
    return api._delete(f"/config/domains/{domain}")


def transport_create(
    api: PmgBackend,
    domain: str,
    host: str,
    comment: str | None = None,
    port: int = 25,
    protocol: str = "smtp",
    use_mx: bool = True,
) -> object:
    """Create a mail transport rule.

    POST /config/transport

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path via pmgsh ls.
    domain: destination domain for this transport rule.
    host: next-hop relay host.
    port: TCP port (1-65535, default 25).
    protocol: smtp or lmtp (default smtp).
    use_mx: use MX lookup for the host (default True).
    """
    domain = _check_domain(domain)
    protocol = _check_transport_protocol(protocol)
    try:
        port_int = int(port)
    except (ValueError, TypeError) as exc:
        raise ProximoError(f"invalid port: {port!r} — must be an integer") from exc
    if not (1 <= port_int <= 65535):
        raise ProximoError(
            f"invalid port: {port!r} — must be an integer in 1-65535"
        )
    body: dict = {
        "domain": domain, "host": host, "port": port_int,
        "protocol": protocol, "use_mx": use_mx,
    }
    if comment is not None:
        body["comment"] = comment
    return api._post("/config/transport", data=body)


def transport_delete(api: PmgBackend, domain: str) -> object:
    """Delete a mail transport rule.

    DELETE /config/transport/{domain}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path via pmgsh ls.
    """
    domain = _check_domain(domain)
    return api._delete(f"/config/transport/{domain}")


def mynetworks_add(api: PmgBackend, cidr: str, comment: str | None = None) -> object:
    """Add a network to the PMG mynetworks (trusted relay) list.

    POST /config/mynetworks

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path via pmgsh ls.
    cidr: network in CIDR notation (e.g. '10.0.0.0/8').
    """
    cidr = _check_cidr(cidr)
    body: dict = {"cidr": cidr}
    if comment is not None:
        body["comment"] = comment
    return api._post("/config/mynetworks", data=body)


def mynetworks_remove(api: PmgBackend, cidr: str) -> object:
    """Remove a network from the PMG mynetworks (trusted relay) list.

    DELETE /config/mynetworks/{cidr}  (cidr is URL-encoded: / → %2F)

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path via pmgsh ls.
    The slash in the CIDR is percent-encoded so PMG does not treat it as a path separator.
    """
    cidr = _check_cidr(cidr)
    encoded = quote(cidr, safe="")
    return api._delete(f"/config/mynetworks/{encoded}")


def spam_config_update(
    api: PmgBackend,
    bounce_score: int | None = None,
    clamav_heuristic_score: int | None = None,
    extract_text: bool | None = None,
    languages: str | None = None,
    maxspamsize: int | None = None,
    rbl_checks: bool | None = None,
    use_awl: bool | None = None,
    use_bayes: bool | None = None,
    use_razor: bool | None = None,
    wl_bounce_relays: str | None = None,
    delete: str | None = None,
) -> object:
    """Update PMG spam filter configuration.

    PUT /config/spam

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path via pmgsh ls.
    Only fields that are not None are sent — PMG keeps omitted fields at their current values.
    Bool fields are coerced to 1/0 by PmgBackend._put → _form (PMG API expects integers).
    delete: comma-separated list of field names to reset to their defaults.
    """
    # Filter None values before building the body — sending null would override PMG defaults.
    body = {k: v for k, v in {
        "bounce_score": bounce_score,
        "clamav_heuristic_score": clamav_heuristic_score,
        "extract_text": extract_text,
        "languages": languages,
        "maxspamsize": maxspamsize,
        "rbl_checks": rbl_checks,
        "use_awl": use_awl,
        "use_bayes": use_bayes,
        "use_razor": use_razor,
        "wl_bounce_relays": wl_bounce_relays,
        "delete": delete,
    }.items() if v is not None}
    return api._put("/config/spam", data=body)


def quarantine_welcomelist_add(
    api: PmgBackend,
    address: str,
    pmail: str | None = None,
) -> object:
    """Add an address to the quarantine welcomelist.

    POST /quarantine/welcomelist

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path via pmgsh ls.
    address: email address or domain to add.
    pmail: optional per-user mail address — defaults to api.config.username.
    """
    effective_pmail = pmail if pmail is not None else api.config.username
    body: dict = {"address": address, "pmail": effective_pmail}
    return api._post("/quarantine/welcomelist", data=body)


def quarantine_welcomelist_remove(
    api: PmgBackend,
    address: str,
    pmail: str | None = None,
) -> object:
    """Remove an address from the quarantine welcomelist.

    DELETE /quarantine/welcomelist  (address + pmail as query params, not a path segment)

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path via pmgsh ls.
    When pmail is not provided it defaults to api.config.username.
    """
    effective_pmail = pmail if pmail is not None else api.config.username
    return api._delete("/quarantine/welcomelist",
                       params={"address": address, "pmail": effective_pmail})


def service_control(
    api: PmgBackend,
    service: str,
    action: str,
    node: str | None = None,
) -> object:
    """Start, stop, restart, or reload a PMG system service.

    POST /nodes/{node}/services/{service}/{action}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path via pmgsh ls.
    service: service name (e.g. 'postfix', 'pmgproxy', 'pmgdaemon').
             Validated against the service-name charset (no path traversal).
    action: start|stop|restart|reload.
    WARNING: stop on postfix/pmgproxy/pmgdaemon interrupts mail delivery until manually restarted.
    """
    service = _check_service(service)
    action = _check_service_action(action)
    effective_node = _check_node(node or "pmg")
    return api._post(f"/nodes/{effective_node}/services/{service}/{action}")


# ---------------------------------------------------------------------------
# W3 PLAN functions — pure factories; no mutation; the PLAN pillar
# ---------------------------------------------------------------------------

def plan_domain_create(domain: str, comment: str | None = None) -> Plan:
    """Preview creating a managed mail domain.  PURE — no API call.

    RISK_LOW: additive — adds a domain entry; does not affect existing mail flow.
    """
    domain = _check_domain(domain)
    return Plan(
        action="pmg_domain_create",
        target="config/domains",
        change=f"create managed mail domain '{domain}'",
        current={},
        blast_radius=[
            f"adds '{domain}' to PMG's managed mail domain list",
            "additive: does not affect existing domains or current mail flow",
            "the domain becomes available for routing and filter rules",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: creates one domain entry; no existing config or mail deleted",
            "LOW: new domain is inactive until routing rules reference it",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: POST /config/domains.",
    )


def plan_domain_delete(domain: str) -> Plan:
    """Preview deleting a managed mail domain.  PURE — no API call.

    RISK_MEDIUM: removes a domain configuration; mail routing may be affected.
    """
    domain = _check_domain(domain)
    return Plan(
        action="pmg_domain_delete",
        target=f"config/domains/{domain}",
        change=f"delete managed mail domain '{domain}'",
        current={},
        blast_radius=[
            f"removes '{domain}' from PMG's managed mail domain list",
            "mail routing rules referencing this domain may break after deletion",
            "review dependent transport and filter rules before removing a domain",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: removes a domain; routing rules referencing it may stop working",
            "review dependent transport and filter rules before confirming",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: DELETE /config/domains/{domain}.",
    )


def plan_transport_create(
    domain: str,
    host: str,
    comment: str | None = None,
    port: int = 25,
    protocol: str = "smtp",
    use_mx: bool = True,
) -> Plan:
    """Preview creating a mail transport rule.  PURE — no API call.

    RISK_LOW: additive — adds a transport rule; does not affect existing rules.
    """
    domain = _check_domain(domain)
    protocol = _check_transport_protocol(protocol)
    return Plan(
        action="pmg_transport_create",
        target="config/transport",
        change=f"create transport rule: '{domain}' → '{host}:{port}' via {protocol}",
        current={},
        blast_radius=[
            f"mail for '{domain}' will be routed to '{host}' on port {port} via {protocol}",
            f"MX lookup: {'enabled' if use_mx else 'disabled'}",
            "additive: does not change routing for other domains",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: creates one transport rule; no existing rules or mail deleted",
            "LOW: affects only new mail routing for the specified domain",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: POST /config/transport.",
    )


def plan_transport_delete(domain: str) -> Plan:
    """Preview deleting a mail transport rule.  PURE — no API call.

    RISK_MEDIUM: removes an explicit routing rule; mail may fall back to default routing.
    """
    domain = _check_domain(domain)
    return Plan(
        action="pmg_transport_delete",
        target=f"config/transport/{domain}",
        change=f"delete transport rule for domain '{domain}'",
        current={},
        blast_radius=[
            f"removes the explicit transport rule for '{domain}'",
            f"mail for '{domain}' will fall back to PMG's default routing (MX lookup)",
            "verify fallback routing is intentional before confirming",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: removes an explicit routing rule; fallback routing takes over",
            "if the domain requires special routing, removal may cause misdelivery",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: DELETE /config/transport/{domain}.",
    )


def plan_mynetworks_add(cidr: str, comment: str | None = None) -> Plan:
    """Preview adding a network to the PMG mynetworks trusted relay list.  PURE — no API call.

    RISK_LOW: additive — grants trusted relay status to a CIDR range.
    """
    cidr = _check_cidr(cidr)
    return Plan(
        action="pmg_mynetworks_add",
        target="config/mynetworks",
        change=f"add '{cidr}' to PMG trusted relay (mynetworks) list",
        current={},
        blast_radius=[
            f"hosts in '{cidr}' will be trusted as relay senders (may bypass spam checks)",
            "only add CIDRs you control — trusted relays can reduce filtering effectiveness",
            "additive: does not affect existing mynetworks entries",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: adds one network entry; no existing config or mail deleted",
            "LOW: effect is to trust a new IP range as a relay — review the CIDR carefully",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: POST /config/mynetworks.",
    )


def plan_mynetworks_remove(cidr: str) -> Plan:
    """Preview removing a network from the PMG mynetworks trusted relay list.  PURE — no API call.

    RISK_MEDIUM: removes trusted relay status; hosts in the CIDR become subject to filtering.
    """
    cidr = _check_cidr(cidr)
    return Plan(
        action="pmg_mynetworks_remove",
        target="config/mynetworks",
        change=f"remove '{cidr}' from PMG trusted relay (mynetworks) list",
        current={},
        blast_radius=[
            f"hosts in '{cidr}' will no longer be trusted as relay senders",
            "mail from those hosts will be subject to spam/RBL filtering",
            "internal mail servers in this range will need an alternative relay path",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: removes relay trust; internal senders in the range may be rejected",
            "verify no production mail servers are in this range before confirming",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: DELETE /config/mynetworks/{cidr}.",
    )


def plan_spam_config_update(**kwargs: object) -> Plan:
    """Preview updating PMG spam filter configuration.  PURE — no API call.

    RISK_MEDIUM: changes spam filtering behavior; affects all inbound mail immediately.
    Raises ProximoError if no fields are provided (all-None update is a no-op).
    """
    # Filter Nones — the same logic the op uses before building the PUT body.
    changes = {k: v for k, v in kwargs.items() if v is not None}
    if not changes:
        raise ProximoError(
            "pmg_spam_config_update: at least one field must be provided "
            "(all values are None — nothing to update)"
        )
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_spam_config_update",
        target="config/spam",
        change=f"update spam filter configuration: {change_summary}",
        current={},
        blast_radius=[
            "spam scoring/filtering changes take effect immediately on new inbound mail",
            "lowering thresholds may cause legitimate mail to be quarantined (false positives)",
            "raising thresholds may allow more spam through (false negatives)",
            f"fields being changed: {', '.join(sorted(changes.keys()))}",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: spam filter changes affect all inbound mail immediately",
            "incorrect thresholds can cause false positives or false negatives at scale",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: PUT /config/spam.",
    )


def plan_quarantine_welcomelist_add(
    address: str, pmail: str | None = None, default_pmail: str | None = None
) -> Plan:
    """Preview adding an address to the quarantine welcomelist.  PURE — no API call.

    RISK_LOW: additive — adds a welcomelist entry; future mail from the address bypasses quarantine.
    """
    scope, scope_line = _quarantine_scope(pmail, default_pmail, "welcomelist")
    return Plan(
        action="pmg_quarantine_welcomelist_add",
        target="quarantine/welcomelist",
        change=f"add '{address}' to the quarantine welcomelist{scope}",
        current={},
        blast_radius=[
            f"future messages from '{address}' will bypass quarantine checks",
            scope_line,
            "additive: does not delete any existing quarantine entries or messages",
            "only future inbound mail matching this address/domain is affected",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: adds one welcomelist entry; no messages or data deleted",
            "LOW: only future mail is affected, not existing quarantine or mailbox contents",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: POST /quarantine/welcomelist.",
    )


def plan_quarantine_welcomelist_remove(
    address: str, pmail: str | None = None, default_pmail: str | None = None
) -> Plan:
    """Preview removing an address from the quarantine welcomelist.  PURE — no API call.

    RISK_LOW: removes a welcomelist entry; mail from the address is re-evaluated normally.
    """
    scope, scope_line = _quarantine_scope(pmail, default_pmail, "welcomelist")
    return Plan(
        action="pmg_quarantine_welcomelist_remove",
        target="quarantine/welcomelist",
        change=f"remove '{address}' from the quarantine welcomelist{scope}",
        current={},
        blast_radius=[
            f"future messages from '{address}' will again be subject to spam/quarantine checks",
            scope_line,
            "existing quarantine state is unaffected — only future mail is re-evaluated",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "LOW: removes one welcomelist entry; no messages deleted",
            "mail from the address will be spam-filtered again going forward",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: DELETE /quarantine/welcomelist.",
    )


def plan_quarantine_blocklist_remove(
    address: str, pmail: str | None = None, default_pmail: str | None = None
) -> Plan:
    """Preview removing an address from the quarantine blocklist.  PURE — no API call.

    RISK_LOW: removes a blocklist entry; mail from the address will be re-evaluated normally.

    The executor (quarantine_blocklist_remove) was added in W2; this plan function
    completes the PLAN pillar so the server tool can gate with dry-run.
    """
    scope, scope_line = _quarantine_scope(pmail, default_pmail, "blocklist")
    return Plan(
        action="pmg_quarantine_blocklist_remove",
        target="quarantine/blocklist",
        change=f"remove '{address}' from the quarantine blocklist{scope}",
        current={},
        blast_radius=[
            f"future messages from '{address}' will no longer be automatically blocked",
            scope_line,
            "existing quarantine entries are unaffected — only future mail is re-evaluated",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "LOW: removes one blocklist entry; no messages deleted",
            "mail from the address will be spam-filtered normally going forward",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: DELETE /quarantine/blocklist.",
    )


def plan_service_control(service: str, action: str, node: str | None = None) -> Plan:
    """Preview starting, stopping, restarting, or reloading a PMG service.  PURE — no API call.

    RISK_HIGH for `action="stop"` on a mail-flow-critical service (postfix/pmg-smtp-filter),
    RISK_MEDIUM otherwise (Wave-9b-review MAJOR fix). This dispatcher and `pmg_node.py`'s
    `plan_service_stop` both build `POST /nodes/{node}/services/{service}/stop` for the same
    inputs — they must agree on risk tier, or a caller can route around the escalation by
    picking whichever tool rates lower. `_MAIL_CRITICAL_SERVICES` is imported (deferred, see
    below) from `pmg_node.py` rather than duplicated, so the two tools share one source of
    truth for the critical-service set.

    Validates the action enum before building the plan.
    """
    service = _check_service(service)
    action = _check_service_action(action)
    effective_node = node or "pmg"
    # Deferred import: pmg_node.py imports from pmg.py at module top (PmgBackend, _check_service,
    # _check_node, ...), so a module-top import here would be circular. Local import (mirrors
    # doctor.py's `from . import server` deferred-import precedent) keeps _MAIL_CRITICAL_SERVICES
    # a single source of truth shared with pmg_node.py's plan_service_stop/_service_stop_risk.
    from .pmg_node import _MAIL_CRITICAL_SERVICES

    mail_critical_stop = action == "stop" and service in _MAIL_CRITICAL_SERVICES
    risk = RISK_HIGH if mail_critical_stop else RISK_MEDIUM
    blast_radius = [
        f"service '{service}' will be {action}ed on node '{effective_node}'",
        "stop on postfix/pmgproxy/pmgdaemon interrupts mail delivery until manually restarted",
        "restart causes a brief service interruption; reload is typically non-disruptive",
        "start on a stopped service resumes mail processing",
        "effect is immediate on the live running service",
    ]
    risk_reasons = [
        "MEDIUM: stop/restart of postfix or pmg core services halts mail delivery",
        "service outage may persist until the service is manually restarted if start fails",
    ]
    if mail_critical_stop:
        blast_radius.append(
            f"*** {service!r} is mail-flow-critical *** — stopping it halts ALL mail delivery "
            "through this PMG node"
        )
        risk_reasons = [
            f"HIGH: {service!r} is mail-flow-critical — stopping it halts ALL mail delivery",
            "service outage may persist until the service is manually restarted if start fails",
        ]
    return Plan(
        action="pmg_service_control",
        target=f"pmg/{effective_node}/services/{service}/{action}",
        change=f"{action} service '{service}' on PMG node '{effective_node}'",
        current={},
        blast_radius=blast_radius,
        risk=risk,
        risk_reasons=risk_reasons,
        note="PMG 9.1 live-verified path via pmgsh ls: POST /nodes/{node}/services/{service}/{action}.",
    )


# ---------------------------------------------------------------------------
# W4 Validators
# ---------------------------------------------------------------------------

# RRD timeframe values (PMG 9.1 live-verified).
_RRDDATA_TIMEFRAMES = frozenset({"hour", "day", "week", "month", "year"})


def _check_rrddata_timeframe(timeframe: str) -> str:
    s = str(timeframe)
    if s not in _RRDDATA_TIMEFRAMES:
        raise ProximoError(
            f"invalid rrddata timeframe: {timeframe!r}. "
            f"Must be one of: {', '.join(sorted(_RRDDATA_TIMEFRAMES))}"
        )
    return s


# RRD consolidation function values (PMG 9.1 live-verified).
_RRDDATA_CF = frozenset({"AVERAGE", "MAX"})


def _check_rrddata_cf(cf: str) -> str:
    s = str(cf)
    if s not in _RRDDATA_CF:
        raise ProximoError(
            f"invalid rrddata cf: {cf!r}. "
            f"Must be one of: {', '.join(sorted(_RRDDATA_CF))}"
        )
    return s


# Backup notify values (PMG 9.1 live-verified).
_NOTIFY_VALUES = frozenset({"always", "error", "never"})


def _check_backup_notify(notify: str) -> str:
    s = str(notify)
    if s not in _NOTIFY_VALUES:
        raise ProximoError(
            f"invalid backup notify: {notify!r}. "
            f"Must be one of: {', '.join(sorted(_NOTIFY_VALUES))}"
        )
    return s


# Quarantine type values (PMG 9.1 live-verified: /quarantine/spamusers quarantine-type param).
_QUARANTINE_TYPE_VALUES = frozenset({"attachment", "spam", "virus"})


def _check_quarantine_type(quarantine_type: str) -> str:
    s = str(quarantine_type)
    if s not in _QUARANTINE_TYPE_VALUES:
        raise ProximoError(
            f"invalid quarantine_type: {quarantine_type!r}. "
            f"Must be one of: {', '.join(sorted(_QUARANTINE_TYPE_VALUES))}"
        )
    return s


# ---------------------------------------------------------------------------
# W4 READ operations
# ---------------------------------------------------------------------------


def tracker_list(
    api: PmgBackend,
    node: str,
    start: int | None = None,
    end: int | None = None,
    from_: str | None = None,
    target: str | None = None,
    xfilter: str | None = None,
    ndr: bool | None = None,
    greylist: bool | None = None,
    limit: int = 2000,
) -> list[dict]:
    """List mail tracking entries.

    GET /nodes/{node}/tracker

    PMG 9.1 live-verified path via pmgsh ls.
    Maps start/end epoch params → starttime/endtime query params.
    from_: envelope-sender filter (Python keyword-safe alias for 'from').
    limit: max results 0–100000 (default 2000).
    """
    node = _check_node(node)
    params = _epoch_range_params(start, end)
    params["limit"] = int(limit)
    if from_ is not None:
        params["from"] = from_
    if target is not None:
        params["target"] = target
    if xfilter is not None:
        params["xfilter"] = xfilter
    if ndr is not None:
        params["ndr"] = 1 if ndr else 0
    if greylist is not None:
        params["greylist"] = 1 if greylist else 0
    return api._get(f"/nodes/{node}/tracker", params=params) or []


def tracker_detail(
    api: PmgBackend,
    node: str,
    id_: str,
    start: int | None = None,
    end: int | None = None,
) -> list[dict]:
    """Get tracking detail for a specific mail ID.

    GET /nodes/{node}/tracker/{id}

    PMG 9.1 live-verified path via pmgsh ls.
    id_: mail/queue tracker ID, validated path-segment-safe (no traversal/injection metachars).
    Maps start/end epoch params → starttime/endtime query params.
    """
    node = _check_node(node)
    id_ = _check_tracker_id(id_)
    params = _epoch_range_params(start, end)
    return api._get(
        f"/nodes/{node}/tracker/{id_}", params=params if params else None
    ) or []


def quarantine_virus(
    api: PmgBackend,
    pmail: str | None = None,
    start: int | None = None,
    end: int | None = None,
) -> list[dict]:
    """List virus quarantine entries.

    GET /quarantine/virus

    PMG 9.1 live-verified path via pmgsh ls.
    pmail: per-user scope — defaults to api.config.username (mirrors W2 blocklist pattern).
    Maps start/end epoch params → starttime/endtime query params.
    """
    effective_pmail = pmail if pmail is not None else api.config.username
    params = _epoch_range_params(start, end)
    params["pmail"] = effective_pmail
    return api._get("/quarantine/virus", params=params) or []


def quarantine_attachment(
    api: PmgBackend,
    pmail: str | None = None,
    start: int | None = None,
    end: int | None = None,
) -> list[dict]:
    """List attachment quarantine entries.

    GET /quarantine/attachment

    PMG 9.1 live-verified path via pmgsh ls.
    pmail: per-user scope — defaults to api.config.username (mirrors W2 blocklist pattern).
    Maps start/end epoch params → starttime/endtime query params.
    """
    effective_pmail = pmail if pmail is not None else api.config.username
    params = _epoch_range_params(start, end)
    params["pmail"] = effective_pmail
    return api._get("/quarantine/attachment", params=params) or []


def quarantine_virusstatus(api: PmgBackend) -> dict:
    """Get virus quarantine status summary.

    GET /quarantine/virusstatus

    PMG 9.1 live-verified path via pmgsh ls.
    """
    return api._get("/quarantine/virusstatus") or {}


def quarantine_spamstatus(api: PmgBackend) -> dict:
    """Get spam quarantine status summary.

    GET /quarantine/spamstatus

    PMG 9.1 live-verified path via pmgsh ls.
    """
    return api._get("/quarantine/spamstatus") or {}


def quarantine_spamusers(
    api: PmgBackend,
    start: int | None = None,
    end: int | None = None,
    quarantine_type: str = "spam",
) -> list[dict]:
    """List users with quarantined mail entries.

    GET /quarantine/spamusers

    PMG 9.1 live-verified path via pmgsh ls.
    quarantine_type: spam|virus|attachment (default spam).
    NOTE: Python arg 'quarantine_type' maps to API param 'quarantine-type' (hyphen).
    Maps start/end epoch params → starttime/endtime query params.
    """
    quarantine_type = _check_quarantine_type(quarantine_type)
    params = _epoch_range_params(start, end)
    params["quarantine-type"] = quarantine_type
    return api._get("/quarantine/spamusers", params=params) or []


def statistics_mailcount(
    api: PmgBackend,
    start: int | None = None,
    end: int | None = None,
    timespan: int = 3600,
) -> list[dict]:
    """Get per-bucket mail count statistics.

    GET /statistics/mailcount

    PMG 9.1 live-verified path via pmgsh ls.
    timespan: histogram bucket size in seconds, 3600–31622400 (default 3600 = 1 hour).
    Maps start/end epoch params → starttime/endtime query params.
    """
    try:
        timespan_int = int(timespan)
    except (ValueError, TypeError) as exc:
        raise ProximoError(
            f"invalid timespan: {timespan!r} — must be an integer"
        ) from exc
    if not (3600 <= timespan_int <= 31622400):
        raise ProximoError(
            f"invalid timespan: {timespan!r} — must be in range 3600–31622400"
        )
    params = _epoch_range_params(start, end)
    params["timespan"] = timespan_int
    return api._get("/statistics/mailcount", params=params) or []


def statistics_sender(
    api: PmgBackend,
    start: int | None = None,
    end: int | None = None,
    filter_: str | None = None,
    orderby: str | None = None,
) -> list[dict]:
    """Get per-sender mail statistics.

    GET /statistics/sender

    PMG 9.1 live-verified path via pmgsh ls.
    filter_: optional search string (maps to API param 'filter').
    orderby: accepted for API compatibility but SILENTLY IGNORED.
             PMG 9.1 live-verified: /statistics/sender does not have an 'orderby'
             parameter; passing it causes HTTP 400 'Parameter verification failed.'
    Maps start/end epoch params → starttime/endtime query params.
    """
    params = _epoch_range_params(start, end)
    if filter_ is not None:
        params["filter"] = filter_
    # orderby is NOT sent to PMG — /statistics/sender rejects it with HTTP 400.
    # Accepted as a parameter so callers with older Proximo integrations don't break.
    return api._get("/statistics/sender", params=params if params else None) or []


def statistics_receiver(
    api: PmgBackend,
    start: int | None = None,
    end: int | None = None,
    filter_: str | None = None,
    orderby: str | None = None,
) -> list[dict]:
    """Get per-recipient mail statistics.

    GET /statistics/receiver

    PMG 9.1 live-verified path via pmgsh ls.
    filter_: optional search string (maps to API param 'filter').
    orderby: optional sort spec — raw passthrough, no validation.
    Maps start/end epoch params → starttime/endtime query params.
    """
    params = _epoch_range_params(start, end)
    if filter_ is not None:
        params["filter"] = filter_
    if orderby is not None:
        params["orderby"] = orderby
    return api._get("/statistics/receiver", params=params if params else None) or []


def node_syslog(
    api: PmgBackend,
    node: str,
    limit: int | None = None,
    service: str | None = None,
    since: str | None = None,
    until: str | None = None,
    start: int | None = None,
) -> list[dict]:
    """Get PMG node syslog entries.

    GET /nodes/{node}/syslog

    PMG 9.1 live-verified path via pmgsh ls.
    limit: max entries to return.
    service: filter by systemd service name.
    since/until: time range (syslog timestamp format or epoch).
    start: pagination offset (record index).
    """
    node = _check_node(node)
    params: dict = {}
    if limit is not None:
        params["limit"] = int(limit)
    if service is not None:
        params["service"] = service
    if since is not None:
        params["since"] = since
    if until is not None:
        params["until"] = until
    if start is not None:
        params["start"] = int(start)
    return api._get(f"/nodes/{node}/syslog", params=params if params else None) or []


def node_rrddata(
    api: PmgBackend,
    node: str,
    timeframe: str,
    cf: str | None = None,
) -> list[dict]:
    """Get PMG node RRD performance data.

    GET /nodes/{node}/rrddata

    PMG 9.1 live-verified path via pmgsh ls.
    timeframe: REQUIRED — hour|day|week|month|year.
    cf: consolidation function AVERAGE|MAX (optional).
    """
    node = _check_node(node)
    timeframe = _check_rrddata_timeframe(timeframe)
    params: dict = {"timeframe": timeframe}
    if cf is not None:
        cf = _check_rrddata_cf(cf)
        params["cf"] = cf
    return api._get(f"/nodes/{node}/rrddata", params=params) or []


def tasks_list(
    api: PmgBackend,
    node: str,
    start: int | None = None,
    limit: int | None = None,
    userfilter: str | None = None,
    errors: bool | None = None,
    typefilter: str | None = None,
    since: int | None = None,
    until: int | None = None,
    statusfilter: str | None = None,
) -> list[dict]:
    """List PMG tasks on a node.

    GET /nodes/{node}/tasks

    PMG 9.1 live-verified path via pmgsh ls.
    start: pagination offset; limit: max entries.
    errors: if True, return only failed tasks.
    """
    node = _check_node(node)
    params: dict = {}
    if start is not None:
        params["start"] = int(start)
    if limit is not None:
        params["limit"] = int(limit)
    if userfilter is not None:
        params["userfilter"] = userfilter
    if errors is not None:
        params["errors"] = 1 if errors else 0
    if typefilter is not None:
        params["typefilter"] = typefilter
    if since is not None:
        params["since"] = int(since)
    if until is not None:
        params["until"] = int(until)
    if statusfilter is not None:
        params["statusfilter"] = statusfilter
    return api._get(f"/nodes/{node}/tasks", params=params if params else None) or []


# ---------------------------------------------------------------------------
# W4 MUTATION operations
# ---------------------------------------------------------------------------


def backup_create(
    api: PmgBackend,
    node: str,
    notify: str = "never",
    statistic: bool = True,
) -> object:
    """Create a PMG configuration backup.

    POST /nodes/{node}/backup

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path via pmgsh ls.
    notify: always|error|never (default never).
    statistic: include mail statistics in backup (default True).
    Backup file is written to /var/lib/pmg/backup/ on the target node.
    """
    node = _check_node(node)
    notify = _check_backup_notify(notify)
    body: dict = {"notify": notify, "statistic": statistic}
    return api._post(f"/nodes/{node}/backup", data=body)


# ---------------------------------------------------------------------------
# W4 PLAN functions
# ---------------------------------------------------------------------------


def plan_backup_create(
    node: str,
    notify: str = "never",
    statistic: bool = True,
) -> Plan:
    """Preview creating a PMG configuration backup.  PURE — no API call.

    RISK_LOW: additive — writes a new backup .tar.gz to /var/lib/pmg/backup/.
    No existing backups or configuration data is deleted.
    """
    node = _check_node(node)
    notify = _check_backup_notify(notify)
    return Plan(
        action="pmg_backup_create",
        target=f"pmg/{node}/backup",
        change=f"create PMG configuration backup on node '{node}'",
        current={},
        blast_radius=[
            f"writes a backup .tar.gz to /var/lib/pmg/backup/ on node '{node}'",
            "additive: creates a new backup file; no existing backups or config deleted",
            f"notify: '{notify}' — "
            f"{'always' if notify == 'always' else 'on error only' if notify == 'error' else 'never'}",
            f"statistic: {'included' if statistic else 'excluded'} from backup",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: writes one new backup .tar.gz file; no live service is stopped",
            "LOW: backup reads current config and writes an archive; no state is deleted",
        ],
        note="PMG 9.1 live-verified path via pmgsh ls: POST /nodes/{node}/backup.",
    )


# ---------------------------------------------------------------------------
# W5a Validators
# ---------------------------------------------------------------------------

# RuleDB rule ID: PMG ruledb uses positive integer IDs as URL path segments.
# Reject any non-digit content (slashes, dots, control chars) to block traversal.
_RULEDB_ID_RE = re.compile(r"^\d+\Z")


def _check_ruledb_id(id_: str) -> str:
    # Do NOT strip — \Z must catch trailing newlines.
    s = str(id_)
    if not _RULEDB_ID_RE.match(s):
        raise ProximoError(
            f"invalid ruledb rule ID: {id_!r} "
            "(must be a positive integer string, e.g. '100'; no slashes or control chars)"
        )
    return s


# Object group name: used as a URL path segment in /config/ruledb/who|what|when/{ogroup}/...
# Allows alphanumeric + hyphen + underscore; starts with alnum; ≤64 chars.
_OGROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")


def _check_ogroup(ogroup: str) -> str:
    # Do NOT strip — \Z must catch trailing newlines.
    s = str(ogroup)
    if not _OGROUP_RE.match(s):
        raise ProximoError(
            f"invalid object group name: {ogroup!r} "
            "(must start with alnum, then alnum/hyphen/underscore, "
            "≤64 chars, no slashes or control chars)"
        )
    return s


# ---------------------------------------------------------------------------
# W5a READ operations — RuleDB filtering engine inventory/observability
# ---------------------------------------------------------------------------


def ruledb_rules_list(api: PmgBackend) -> list[dict]:
    """List all PMG RuleDB rules (hydrated rule list).

    GET /config/ruledb/rules

    PMG 9.1 pmgsh-verified path.
    Returns the full hydrated rule list including from/to/what/when/actions.
    """
    return api._get("/config/ruledb/rules") or []


def ruledb_rule_get(api: PmgBackend, id_: str) -> dict:
    """Get a PMG RuleDB rule's configuration.

    GET /config/ruledb/rules/{id}/config

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    """
    id_ = _check_ruledb_id(id_)
    return api._get(f"/config/ruledb/rules/{id_}/config") or {}


def ruledb_rule_from_list(api: PmgBackend, id_: str) -> list[dict]:
    """List the 'from' objects attached to a PMG RuleDB rule.

    GET /config/ruledb/rules/{id}/from

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    """
    id_ = _check_ruledb_id(id_)
    return api._get(f"/config/ruledb/rules/{id_}/from") or []


def ruledb_rule_to_list(api: PmgBackend, id_: str) -> list[dict]:
    """List the 'to' objects attached to a PMG RuleDB rule.

    GET /config/ruledb/rules/{id}/to

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    """
    id_ = _check_ruledb_id(id_)
    return api._get(f"/config/ruledb/rules/{id_}/to") or []


def ruledb_rule_what_list(api: PmgBackend, id_: str) -> list[dict]:
    """List the 'what' objects attached to a PMG RuleDB rule.

    GET /config/ruledb/rules/{id}/what

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    """
    id_ = _check_ruledb_id(id_)
    return api._get(f"/config/ruledb/rules/{id_}/what") or []


def ruledb_rule_when_list(api: PmgBackend, id_: str) -> list[dict]:
    """List the 'when' objects attached to a PMG RuleDB rule.

    GET /config/ruledb/rules/{id}/when

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    """
    id_ = _check_ruledb_id(id_)
    return api._get(f"/config/ruledb/rules/{id_}/when") or []


def ruledb_rule_actions_list(api: PmgBackend, id_: str) -> list[dict]:
    """List the 'actions' objects attached to a PMG RuleDB rule (config-embed reading).

    GET /config/ruledb/rules/{id}/config  (extracts the 'action' field)

    CORRECTED Wave 8a (was: "GET .../actions returns 501, PMG dropped the endpoint"): the plural
    `/config/ruledb/rules/{id}/actions` path was NEVER a real PMG API endpoint at all — checked
    programmatically against the full 425-method apidoc, zero hits for any object family on this
    plane (from/to/what/when/action all use singular URL segments). A 501 on an undeclared path
    segment is unsurprising, not evidence PMG dropped a feature. The true structural sibling of
    ruledb_rule_from_list/to_list/what_list/when_list is the singular
    GET /config/ruledb/rules/{id}/action — see pmg_ruledb_rule_action_groups_list for that direct
    read (schema types it bare [{id}], but the live response is richer — id+name+info). This
    function keeps its EXISTING behavior unchanged (reads .../config and extracts the embedded
    'action' key). Live-verified 2026-07-17 (lab PMG 9.1): the embed EXISTS (full observed config
    keys = [action, active, direction, from, id, name, priority, to, what, when]) and, with an
    attached action group, this function's extraction matches the singular endpoint's output
    byte-for-byte.
    id_: rule ID (positive integer string, e.g. '100').
    """
    id_ = _check_ruledb_id(id_)
    cfg = api._get(f"/config/ruledb/rules/{id_}/config") or {}
    return cfg.get("action") or []


# ---------------------------------------------------------------------------
# Generic ruledb group-kind CRUD helpers — who/what/when object groups are
# byte-for-byte identical PMG RuleDB endpoints save for the "who"/"what"/"when"
# URL path segment. The public who_*/what_*/when_* functions below are thin
# shims over these so every call site's URL/params/method/return shape stays
# exactly what it was before the collapse.
# ---------------------------------------------------------------------------


def _ruledb_groups_list(api: PmgBackend, kind: str) -> list[dict]:
    return api._get(f"/config/ruledb/{kind}") or []


def _ruledb_group_get(api: PmgBackend, kind: str, ogroup: str) -> dict:
    ogroup = _check_ruledb_id(ogroup)
    return api._get(f"/config/ruledb/{kind}/{ogroup}/config") or {}


def _ruledb_group_objects(api: PmgBackend, kind: str, ogroup: str) -> list[dict]:
    ogroup = _check_ruledb_id(ogroup)
    return api._get(f"/config/ruledb/{kind}/{ogroup}/objects") or []


def who_groups_list(api: PmgBackend) -> list[dict]:
    """List all PMG RuleDB 'who' object groups.

    GET /config/ruledb/who

    PMG 9.1 pmgsh-verified path.
    """
    return _ruledb_groups_list(api, "who")


def who_group_get(api: PmgBackend, ogroup: str) -> dict:
    """Get a PMG RuleDB 'who' object group's configuration.

    GET /config/ruledb/who/{ogroup}/config

    PMG 9.1 live-verified: ogroup must be the numeric ID string from
    who_groups_list (e.g. '2'), NOT the group name (e.g. 'Blocklist').
    Passing a name causes PMG to return HTTP 400 Parameter verification failed.
    ogroup: numeric ID string (e.g. '2') from who_groups_list response.
    """
    return _ruledb_group_get(api, "who", ogroup)


def who_group_objects(api: PmgBackend, ogroup: str) -> list[dict]:
    """List the objects in a PMG RuleDB 'who' object group.

    GET /config/ruledb/who/{ogroup}/objects

    PMG 9.1 live-verified: ogroup must be the numeric ID string from
    who_groups_list (e.g. '2'), NOT the group name (e.g. 'Blocklist').
    ogroup: numeric ID string (e.g. '2') from who_groups_list response.
    """
    return _ruledb_group_objects(api, "who", ogroup)


def what_groups_list(api: PmgBackend) -> list[dict]:
    """List all PMG RuleDB 'what' object groups.

    GET /config/ruledb/what

    PMG 9.1 pmgsh-verified path.
    """
    return _ruledb_groups_list(api, "what")


def what_group_get(api: PmgBackend, ogroup: str) -> dict:
    """Get a PMG RuleDB 'what' object group's configuration.

    GET /config/ruledb/what/{ogroup}/config

    PMG 9.1 live-verified: ogroup must be the numeric ID string from
    what_groups_list (e.g. '8'), NOT the group name (e.g. 'DangerousContent').
    Passing a name causes PMG to return HTTP 400 Parameter verification failed.
    ogroup: numeric ID string (e.g. '8') from what_groups_list response.
    """
    return _ruledb_group_get(api, "what", ogroup)


def what_group_objects(api: PmgBackend, ogroup: str) -> list[dict]:
    """List the objects in a PMG RuleDB 'what' object group.

    GET /config/ruledb/what/{ogroup}/objects

    PMG 9.1 live-verified: ogroup must be the numeric ID string from
    what_groups_list (e.g. '8'), NOT the group name.
    ogroup: numeric ID string (e.g. '8') from what_groups_list response.
    """
    return _ruledb_group_objects(api, "what", ogroup)


def when_groups_list(api: PmgBackend) -> list[dict]:
    """List all PMG RuleDB 'when' object groups.

    GET /config/ruledb/when

    PMG 9.1 pmgsh-verified path.
    """
    return _ruledb_groups_list(api, "when")


def when_group_get(api: PmgBackend, ogroup: str) -> dict:
    """Get a PMG RuleDB 'when' object group's configuration.

    GET /config/ruledb/when/{ogroup}/config

    PMG 9.1 live-verified: ogroup must be the numeric ID string from
    when_groups_list (e.g. '4'), NOT the group name (e.g. 'OfficeHours').
    Passing a name causes PMG to return HTTP 400 Parameter verification failed.
    ogroup: numeric ID string (e.g. '4') from when_groups_list response.
    """
    return _ruledb_group_get(api, "when", ogroup)


def when_group_objects(api: PmgBackend, ogroup: str) -> list[dict]:
    """List the objects in a PMG RuleDB 'when' object group.

    GET /config/ruledb/when/{ogroup}/objects

    PMG 9.1 live-verified: ogroup must be the numeric ID string from
    when_groups_list (e.g. '4'), NOT the group name.
    ogroup: numeric ID string (e.g. '4') from when_groups_list response.
    """
    return _ruledb_group_objects(api, "when", ogroup)


def action_objects_list(api: PmgBackend) -> list[dict]:
    """List all PMG RuleDB action objects (including non-editable).

    GET /config/ruledb/action/objects

    PMG 9.1 pmgsh-verified path.
    Returns all action objects; each entry carries an 'editable' flag.
    Non-editable action objects are built-in and cannot be modified via the API.
    """
    return api._get("/config/ruledb/action/objects") or []


def ruledb_digest(api: PmgBackend) -> dict:
    """Get the PMG RuleDB digest (change-detection hash).

    GET /config/ruledb/digest

    PMG 9.1 pmgsh-verified path.
    The digest changes whenever any ruledb configuration is modified.
    Use to detect configuration drift without fetching the full rule list.
    """
    return api._get("/config/ruledb/digest") or {}


# ---------------------------------------------------------------------------
# W5b Validators
# ---------------------------------------------------------------------------

# WHO object type enum: type controls the sub-path for object CRUD.
# "ldapuser" added Wave 8a (schema-verified: POST/PUT /config/ruledb/who/{ogroup}/ldapuser take
# 'account' + 'profile', both REQUIRED upstream though threaded here as optional kwargs like every
# other type-specific field on this dispatcher) — additive, the 6 pre-existing values unaffected.
_WHO_OBJECT_TYPES = frozenset({"email", "domain", "regex", "ip", "network", "ldap", "ldapuser"})


def _check_who_object_type(type_: str) -> str:
    if type_ not in _WHO_OBJECT_TYPES:
        raise ProximoError(
            f"invalid who-object type: {type_!r}. "
            f"Must be one of: {', '.join(sorted(_WHO_OBJECT_TYPES))}"
        )
    return type_


# ---------------------------------------------------------------------------
# W5b MUTATION operations — object-group CRUD + who-object CRUD
# ---------------------------------------------------------------------------


def _ruledb_group_create(
    api: PmgBackend,
    kind: str,
    name: str,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> object:
    body: dict = {"name": name}
    if info is not None:
        body["info"] = info
    if and_ is not None:
        body["and"] = and_
    if invert is not None:
        body["invert"] = invert
    return api._post(f"/config/ruledb/{kind}", data=body)


def _ruledb_group_update(
    api: PmgBackend,
    kind: str,
    ogroup: str,
    name: str | None = None,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> object:
    ogroup = _check_ruledb_id(ogroup)
    body: dict = {}
    if name is not None:
        body["name"] = name
    if info is not None:
        body["info"] = info
    if and_ is not None:
        body["and"] = and_
    if invert is not None:
        body["invert"] = invert
    return api._put(f"/config/ruledb/{kind}/{ogroup}/config", data=body)


def _ruledb_group_delete(api: PmgBackend, kind: str, ogroup: str) -> object:
    ogroup = _check_ruledb_id(ogroup)
    return api._delete(f"/config/ruledb/{kind}/{ogroup}")


def who_group_create(
    api: PmgBackend,
    name: str,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> object:
    """Create a PMG RuleDB 'who' object group.

    POST /config/ruledb/who

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    name: group name.
    info: optional description.
    and_: Python alias for the API param 'and' (bool; AND vs OR logic for group members).
    invert: if True, the group match is inverted.
    Returns the numeric ogroup ID assigned by PMG.
    """
    return _ruledb_group_create(api, "who", name, info, and_, invert)


def who_group_update(
    api: PmgBackend,
    ogroup: str,
    name: str | None = None,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> object:
    """Update a PMG RuleDB 'who' object group's configuration.

    PUT /config/ruledb/who/{ogroup}/config

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '2') from who_groups_list response.
    Only non-None fields are sent; omitted fields keep their current values.
    """
    return _ruledb_group_update(api, "who", ogroup, name, info, and_, invert)


def who_group_delete(api: PmgBackend, ogroup: str) -> object:
    """Delete a PMG RuleDB 'who' object group.

    DELETE /config/ruledb/who/{ogroup}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '2') from who_groups_list response.
    WARNING: also removes all objects within the group.
    """
    return _ruledb_group_delete(api, "who", ogroup)


def what_group_create(
    api: PmgBackend,
    name: str,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> object:
    """Create a PMG RuleDB 'what' object group.

    POST /config/ruledb/what

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    name: group name.
    info: optional description.
    and_: Python alias for the API param 'and' (bool; AND vs OR logic for group members).
    invert: if True, the group match is inverted.
    Returns the numeric ogroup ID assigned by PMG.
    """
    return _ruledb_group_create(api, "what", name, info, and_, invert)


def what_group_update(
    api: PmgBackend,
    ogroup: str,
    name: str | None = None,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> object:
    """Update a PMG RuleDB 'what' object group's configuration.

    PUT /config/ruledb/what/{ogroup}/config

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '8') from what_groups_list response.
    Only non-None fields are sent; omitted fields keep their current values.
    """
    return _ruledb_group_update(api, "what", ogroup, name, info, and_, invert)


def what_group_delete(api: PmgBackend, ogroup: str) -> object:
    """Delete a PMG RuleDB 'what' object group.

    DELETE /config/ruledb/what/{ogroup}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '8') from what_groups_list response.
    WARNING: also removes all objects within the group.
    """
    return _ruledb_group_delete(api, "what", ogroup)


def when_group_create(
    api: PmgBackend,
    name: str,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> object:
    """Create a PMG RuleDB 'when' object group.

    POST /config/ruledb/when

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    name: group name.
    info: optional description.
    and_: Python alias for the API param 'and' (bool; AND vs OR logic for group members).
    invert: if True, the group match is inverted.
    Returns the numeric ogroup ID assigned by PMG.
    """
    return _ruledb_group_create(api, "when", name, info, and_, invert)


def when_group_update(
    api: PmgBackend,
    ogroup: str,
    name: str | None = None,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> object:
    """Update a PMG RuleDB 'when' object group's configuration.

    PUT /config/ruledb/when/{ogroup}/config

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '4') from when_groups_list response.
    Only non-None fields are sent; omitted fields keep their current values.
    """
    return _ruledb_group_update(api, "when", ogroup, name, info, and_, invert)


def when_group_delete(api: PmgBackend, ogroup: str) -> object:
    """Delete a PMG RuleDB 'when' object group.

    DELETE /config/ruledb/when/{ogroup}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '4') from when_groups_list response.
    WARNING: also removes all objects within the group.
    """
    return _ruledb_group_delete(api, "when", ogroup)


def _who_object_body(
    type_: str,
    *,
    email: str | None = None,
    domain: str | None = None,
    regex: str | None = None,
    ip: str | None = None,
    cidr: str | None = None,
    mode: str | None = None,
    profile: str | None = None,
    group: str | None = None,
    account: str | None = None,
) -> dict:
    """Build the type-dispatched request body shared by who_object_add/update."""
    body: dict = {}
    if type_ == "email":
        if email is not None:
            body["email"] = email
    elif type_ == "domain":
        if domain is not None:
            body["domain"] = domain
    elif type_ == "regex":
        if regex is not None:
            body["regex"] = regex
    elif type_ == "ip":
        if ip is not None:
            body["ip"] = ip
    elif type_ == "network":
        if cidr is not None:
            body["cidr"] = cidr
    elif type_ == "ldap":
        if mode is not None:
            body["mode"] = mode
        if profile is not None:
            body["profile"] = profile
        if group is not None:
            body["group"] = group
    elif type_ == "ldapuser":
        # Wave 8a: schema-verified POST/PUT /config/ruledb/who/{ogroup}/ldapuser fields are
        # 'account' (LDAP user account name) + 'profile' (LDAP profile ID) — the 'profile' kwarg
        # already exists on this dispatcher (threaded for "ldap"); only 'account' is new.
        if account is not None:
            body["account"] = account
        if profile is not None:
            body["profile"] = profile
    return body


def who_object_add(
    api: PmgBackend,
    ogroup: str,
    type_: str,
    *,
    email: str | None = None,
    domain: str | None = None,
    regex: str | None = None,
    ip: str | None = None,
    cidr: str | None = None,
    mode: str | None = None,
    profile: str | None = None,
    group: str | None = None,
    account: str | None = None,
) -> object:
    """Add an object to a PMG RuleDB 'who' object group.

    POST /config/ruledb/who/{ogroup}/{type}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path (ldapuser: Wave 8a, schema-verified, not yet live-verified).
    ogroup: numeric ID string (e.g. '2') from who_groups_list response.
    type_: email|domain|regex|ip|network|ldap|ldapuser — controls the sub-path.
    Type-specific fields (send only relevant non-None fields):
        email:    email (str)
        domain:   domain (str)
        regex:    regex (str)
        ip:       ip (str)
        network:  cidr (str)
        ldap:     mode (any|none|group), profile (str), group (str)
        ldapuser: account (str), profile (str)
    NOTE: if the group is already bound to a rule, the new object affects
    mail matching immediately on add.
    """
    ogroup = _check_ruledb_id(ogroup)
    type_ = _check_who_object_type(type_)
    body = _who_object_body(
        type_, email=email, domain=domain, regex=regex, ip=ip,
        cidr=cidr, mode=mode, profile=profile, group=group, account=account,
    )
    return api._post(f"/config/ruledb/who/{ogroup}/{type_}", data=body)


def who_object_update(
    api: PmgBackend,
    ogroup: str,
    type_: str,
    id_: str,
    *,
    email: str | None = None,
    domain: str | None = None,
    regex: str | None = None,
    ip: str | None = None,
    cidr: str | None = None,
    mode: str | None = None,
    profile: str | None = None,
    group: str | None = None,
    account: str | None = None,
) -> object:
    """Update an object in a PMG RuleDB 'who' object group.

    PUT /config/ruledb/who/{ogroup}/{type}/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path (ldapuser: Wave 8a, schema-verified, not yet live-verified).
    ogroup: numeric ID string (e.g. '2') from who_groups_list response.
    type_: email|domain|regex|ip|network|ldap|ldapuser — controls the sub-path.
    id_: object ID (numeric string) from who_group_objects response.
    All type-specific fields are optional; only non-None fields are sent.
    """
    ogroup = _check_ruledb_id(ogroup)
    type_ = _check_who_object_type(type_)
    id_ = _check_ruledb_id(id_)
    body = _who_object_body(
        type_, email=email, domain=domain, regex=regex, ip=ip,
        cidr=cidr, mode=mode, profile=profile, group=group, account=account,
    )
    return api._put(f"/config/ruledb/who/{ogroup}/{type_}/{id_}", data=body)


def who_object_delete(api: PmgBackend, ogroup: str, id_: str) -> object:
    """Delete an object from a PMG RuleDB 'who' object group.

    DELETE /config/ruledb/who/{ogroup}/objects/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '2') from who_groups_list response.
    id_: object ID (numeric string) from who_group_objects response.
    Object DELETE always goes through /objects/{id} regardless of type.
    """
    ogroup = _check_ruledb_id(ogroup)
    id_ = _check_ruledb_id(id_)
    return api._delete(f"/config/ruledb/who/{ogroup}/objects/{id_}")


# ---------------------------------------------------------------------------
# W5b PLAN functions — object-group CRUD + who-object CRUD (PURE — no API call)
# ---------------------------------------------------------------------------


def plan_who_group_create(
    name: str,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> Plan:
    """Preview creating a PMG RuleDB 'who' object group.  PURE — no API call.

    RISK_LOW: additive — creates an empty group; affects no mail until attached
    to a rule (W5d).
    """
    return Plan(
        action="pmg_who_group_create",
        target="config/ruledb/who",
        change=f"create 'who' object group '{name}'",
        current={},
        blast_radius=[
            f"creates an empty 'who' object group named '{name}'",
            "additive: does not affect existing groups, objects, or mail flow",
            "the group has no effect until attached to a rule (W5d)",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: creates one empty group; no existing config or mail deleted",
            "LOW: group is inactive until bound to a rule",
        ],
        note="PMG 9.1 pmgsh-verified path: POST /config/ruledb/who.",
    )


def plan_who_group_update(
    ogroup: str,
    name: str | None = None,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> Plan:
    """Preview updating a PMG RuleDB 'who' object group's configuration.  PURE — no API call.

    RISK_MEDIUM: modifies an existing group; if bound to a rule, the change
    affects mail matching immediately.
    """
    ogroup = _check_ruledb_id(ogroup)
    changes = {k: v for k, v in {"name": name, "info": info, "and": and_, "invert": invert}.items()
               if v is not None}
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_who_group_update",
        target=f"config/ruledb/who/{ogroup}/config",
        change=(f"update 'who' object group {ogroup} config: {change_summary}"
                if changes else f"update 'who' object group {ogroup} config"),
        current={},
        blast_radius=[
            f"modifies the configuration of 'who' group {ogroup}",
            "if the group is bound to an active rule, matching changes take effect immediately",
            "review all rules referencing this group before confirming",
            (f"fields being changed: {change_summary}" if changes
             else "no fields specified — this is a no-op update"),
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: modifies an existing group; active rules referencing it are affected",
            "logic changes (and/invert) can flip rule matching for live mail",
        ],
        note="PMG 9.1 pmgsh-verified path: PUT /config/ruledb/who/{ogroup}/config.",
    )


def plan_who_group_delete(ogroup: str) -> Plan:
    """Preview deleting a PMG RuleDB 'who' object group.  PURE — no API call.

    RISK_MEDIUM: removes the group and all its objects; rules referencing it
    may break.
    """
    ogroup = _check_ruledb_id(ogroup)
    return Plan(
        action="pmg_who_group_delete",
        target=f"config/ruledb/who/{ogroup}",
        change=f"delete 'who' object group {ogroup}",
        current={},
        blast_radius=[
            f"permanently removes 'who' group {ogroup} and all its objects",
            "rules that reference this group will lose their 'from' match condition",
            "affected rules may start matching all senders or become invalid",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: deletes a group and all contained objects; cannot be undone without re-creating",
            "rules referencing the deleted group may mismatch or fail",
        ],
        note="PMG 9.1 pmgsh-verified path: DELETE /config/ruledb/who/{ogroup}.",
    )


def plan_what_group_create(
    name: str,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> Plan:
    """Preview creating a PMG RuleDB 'what' object group.  PURE — no API call.

    RISK_LOW: additive — creates an empty group; affects no mail until attached
    to a rule (W5d).
    """
    return Plan(
        action="pmg_what_group_create",
        target="config/ruledb/what",
        change=f"create 'what' object group '{name}'",
        current={},
        blast_radius=[
            f"creates an empty 'what' object group named '{name}'",
            "additive: does not affect existing groups, objects, or mail flow",
            "the group has no effect until attached to a rule (W5d)",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: creates one empty group; no existing config or mail deleted",
            "LOW: group is inactive until bound to a rule",
        ],
        note="PMG 9.1 pmgsh-verified path: POST /config/ruledb/what.",
    )


def plan_what_group_update(
    ogroup: str,
    name: str | None = None,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> Plan:
    """Preview updating a PMG RuleDB 'what' object group's configuration.  PURE — no API call.

    RISK_MEDIUM: modifies an existing group; if bound to a rule, the change
    affects mail matching immediately.
    """
    ogroup = _check_ruledb_id(ogroup)
    changes = {k: v for k, v in {"name": name, "info": info, "and": and_, "invert": invert}.items()
               if v is not None}
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_what_group_update",
        target=f"config/ruledb/what/{ogroup}/config",
        change=(f"update 'what' object group {ogroup} config: {change_summary}"
                if changes else f"update 'what' object group {ogroup} config"),
        current={},
        blast_radius=[
            f"modifies the configuration of 'what' group {ogroup}",
            "if the group is bound to an active rule, matching changes take effect immediately",
            "review all rules referencing this group before confirming",
            (f"fields being changed: {change_summary}" if changes
             else "no fields specified — this is a no-op update"),
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: modifies an existing group; active rules referencing it are affected",
            "logic changes (and/invert) can flip rule matching for live mail",
        ],
        note="PMG 9.1 pmgsh-verified path: PUT /config/ruledb/what/{ogroup}/config.",
    )


def plan_what_group_delete(ogroup: str) -> Plan:
    """Preview deleting a PMG RuleDB 'what' object group.  PURE — no API call.

    RISK_MEDIUM: removes the group and all its objects; rules referencing it
    may break.
    """
    ogroup = _check_ruledb_id(ogroup)
    return Plan(
        action="pmg_what_group_delete",
        target=f"config/ruledb/what/{ogroup}",
        change=f"delete 'what' object group {ogroup}",
        current={},
        blast_radius=[
            f"permanently removes 'what' group {ogroup} and all its objects",
            "rules that reference this group will lose their 'what' match condition",
            "affected rules may start matching all content or become invalid",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: deletes a group and all contained objects; cannot be undone without re-creating",
            "rules referencing the deleted group may mismatch or fail",
        ],
        note="PMG 9.1 pmgsh-verified path: DELETE /config/ruledb/what/{ogroup}.",
    )


def plan_when_group_create(
    name: str,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> Plan:
    """Preview creating a PMG RuleDB 'when' object group.  PURE — no API call.

    RISK_LOW: additive — creates an empty group; affects no mail until attached
    to a rule (W5d).
    """
    return Plan(
        action="pmg_when_group_create",
        target="config/ruledb/when",
        change=f"create 'when' object group '{name}'",
        current={},
        blast_radius=[
            f"creates an empty 'when' object group named '{name}'",
            "additive: does not affect existing groups, objects, or mail flow",
            "the group has no effect until attached to a rule (W5d)",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: creates one empty group; no existing config or mail deleted",
            "LOW: group is inactive until bound to a rule",
        ],
        note="PMG 9.1 pmgsh-verified path: POST /config/ruledb/when.",
    )


def plan_when_group_update(
    ogroup: str,
    name: str | None = None,
    info: str | None = None,
    and_: bool | None = None,
    invert: bool | None = None,
) -> Plan:
    """Preview updating a PMG RuleDB 'when' object group's configuration.  PURE — no API call.

    RISK_MEDIUM: modifies an existing group; if bound to a rule, the change
    affects mail matching immediately.
    """
    ogroup = _check_ruledb_id(ogroup)
    changes = {k: v for k, v in {"name": name, "info": info, "and": and_, "invert": invert}.items()
               if v is not None}
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_when_group_update",
        target=f"config/ruledb/when/{ogroup}/config",
        change=(f"update 'when' object group {ogroup} config: {change_summary}"
                if changes else f"update 'when' object group {ogroup} config"),
        current={},
        blast_radius=[
            f"modifies the configuration of 'when' group {ogroup}",
            "if the group is bound to an active rule, matching changes take effect immediately",
            "review all rules referencing this group before confirming",
            (f"fields being changed: {change_summary}" if changes
             else "no fields specified — this is a no-op update"),
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: modifies an existing group; active rules referencing it are affected",
            "logic changes (and/invert) can flip rule matching for live mail",
        ],
        note="PMG 9.1 pmgsh-verified path: PUT /config/ruledb/when/{ogroup}/config.",
    )


def plan_when_group_delete(ogroup: str) -> Plan:
    """Preview deleting a PMG RuleDB 'when' object group.  PURE — no API call.

    RISK_MEDIUM: removes the group and all its objects; rules referencing it
    may break.
    """
    ogroup = _check_ruledb_id(ogroup)
    return Plan(
        action="pmg_when_group_delete",
        target=f"config/ruledb/when/{ogroup}",
        change=f"delete 'when' object group {ogroup}",
        current={},
        blast_radius=[
            f"permanently removes 'when' group {ogroup} and all its objects",
            "rules that reference this group will lose their 'when' match condition",
            "affected rules may match at all times or become invalid",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: deletes a group and all contained objects; cannot be undone without re-creating",
            "rules referencing the deleted group may mismatch or fail",
        ],
        note="PMG 9.1 pmgsh-verified path: DELETE /config/ruledb/when/{ogroup}.",
    )


def plan_who_object_add(
    ogroup: str,
    type_: str,
    *,
    email: str | None = None,
    domain: str | None = None,
    regex: str | None = None,
    ip: str | None = None,
    cidr: str | None = None,
    mode: str | None = None,
    profile: str | None = None,
    group: str | None = None,
    account: str | None = None,
) -> Plan:
    """Preview adding an object to a PMG RuleDB 'who' object group.  PURE — no API call.

    RISK_LOW: additive — adds one object to the group. NOTE: if the group is
    already bound to a rule, the new object affects mail matching immediately.
    """
    ogroup = _check_ruledb_id(ogroup)
    type_ = _check_who_object_type(type_)
    return Plan(
        action="pmg_who_object_add",
        target=f"config/ruledb/who/{ogroup}/{type_}",
        change=f"add {type_} object to 'who' group {ogroup}",
        current={},
        blast_radius=[
            f"adds one {type_} object to 'who' group {ogroup}",
            "additive: no existing objects are removed or modified",
            f"WARNING: if group {ogroup} is already bound to a rule, the new object "
            "affects mail matching immediately on add",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: adds one object; no existing config or mail deleted",
            "LOW overall — but immediate effect if group is in an active rule",
        ],
        note=(
            f"PMG 9.1 pmgsh-verified path: POST /config/ruledb/who/{{ogroup}}/{type_}."
            if type_ != "ldapuser"
            else "Schema-verified path (Smoke-confirm — not yet live-tested): "
                 "POST /config/ruledb/who/{ogroup}/ldapuser."
        ),
    )


def plan_who_object_update(
    ogroup: str,
    type_: str,
    id_: str,
    *,
    email: str | None = None,
    domain: str | None = None,
    regex: str | None = None,
    ip: str | None = None,
    cidr: str | None = None,
    mode: str | None = None,
    profile: str | None = None,
    group: str | None = None,
    account: str | None = None,
) -> Plan:
    """Preview updating an object in a PMG RuleDB 'who' object group.  PURE — no API call.

    RISK_MEDIUM: modifies an existing object; if the group is bound to an active
    rule, the change affects mail matching immediately.
    """
    ogroup = _check_ruledb_id(ogroup)
    type_ = _check_who_object_type(type_)
    id_ = _check_ruledb_id(id_)
    # Reuse the same type-dispatch body-builder the op uses, so the preview shows
    # exactly what would be sent — not just which object is being touched.
    changes = _who_object_body(
        type_, email=email, domain=domain, regex=regex, ip=ip,
        cidr=cidr, mode=mode, profile=profile, group=group, account=account,
    )
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_who_object_update",
        target=f"config/ruledb/who/{ogroup}/{type_}/{id_}",
        change=(f"update {type_} object {id_} in 'who' group {ogroup}: {change_summary}"
                if changes else f"update {type_} object {id_} in 'who' group {ogroup}"),
        current={},
        blast_radius=[
            f"modifies {type_} object {id_} in 'who' group {ogroup}",
            "if the group is bound to an active rule, the change takes effect immediately",
            "verify the new value matches your intended mail filter target",
            (f"fields being changed: {change_summary}" if changes
             else "no fields specified — this is a no-op update"),
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: modifies an existing object; active rules referencing the group are affected",
            "incorrect value could allow or block unintended mail immediately",
        ],
        note=(
            f"PMG 9.1 pmgsh-verified path: PUT /config/ruledb/who/{{ogroup}}/{type_}/{{id}}."
            if type_ != "ldapuser"
            else "Schema-verified path (Smoke-confirm — not yet live-tested): "
                 "PUT /config/ruledb/who/{ogroup}/ldapuser/{id}."
        ),
    )


def plan_who_object_delete(ogroup: str, id_: str) -> Plan:
    """Preview deleting an object from a PMG RuleDB 'who' object group.  PURE — no API call.

    RISK_MEDIUM: removes an existing object; if the group is bound to an active
    rule, the change affects mail matching immediately.
    """
    ogroup = _check_ruledb_id(ogroup)
    id_ = _check_ruledb_id(id_)
    return Plan(
        action="pmg_who_object_delete",
        target=f"config/ruledb/who/{ogroup}/objects/{id_}",
        change=f"delete object {id_} from 'who' group {ogroup}",
        current={},
        blast_radius=[
            f"permanently removes object {id_} from 'who' group {ogroup}",
            "if the group is bound to an active rule, the deletion takes effect immediately",
            "senders/addresses previously matched by this object will no longer match",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: removes an existing object; cannot be undone without re-adding",
            "active rules referencing the group immediately lose this match entry",
        ],
        note="PMG 9.1 pmgsh-verified path: DELETE /config/ruledb/who/{ogroup}/objects/{id}.",
    )


# ---------------------------------------------------------------------------
# W5c Validators
# ---------------------------------------------------------------------------

# WHAT object type enum: type controls the sub-path for what-object CRUD.
_WHAT_OBJECT_TYPES = frozenset({
    "contenttype",
    "matchfield",
    "spamfilter",
    "virusfilter",
    "filenamefilter",
    "archivefilter",
    "archivefilenamefilter",
})


def _check_what_object_type(type_: str) -> str:
    if type_ not in _WHAT_OBJECT_TYPES:
        raise ProximoError(
            f"invalid what-object type: {type_!r}. "
            f"Must be one of: {', '.join(sorted(_WHAT_OBJECT_TYPES))}"
        )
    return type_


# Disclaimer position enum.
_DISCLAIMER_POSITIONS = frozenset({"start", "end"})


def _check_action_position(position: str) -> str:
    if position not in _DISCLAIMER_POSITIONS:
        raise ProximoError(
            f"invalid disclaimer position: {position!r}. "
            f"Must be one of: {', '.join(sorted(_DISCLAIMER_POSITIONS))}"
        )
    return position


# Action object compound ID: format is {ogroup}_{objid} (e.g. '13_26').
# Both parts must be digit-only; reject traversal, control chars, and anything else.
_ACTION_OBJECT_ID_RE = re.compile(r"^\d+_\d+\Z")


def _check_action_object_id(id_: str) -> str:
    """Validate a compound action object ID (e.g. '13_26' = ogroup_objid)."""
    s = str(id_)
    if not _ACTION_OBJECT_ID_RE.match(s):
        raise ProximoError(
            f"invalid action object ID: {id_!r} "
            "(must be compound ogroup_objid format, e.g. '13_26')"
        )
    return s


# ---------------------------------------------------------------------------
# W5c MUTATION operations — WHAT-object CRUD
# ---------------------------------------------------------------------------


def _what_object_body(
    type_: str,
    *,
    contenttype: str | None = None,
    only_content: bool | None = None,
    field: str | None = None,
    value: str | None = None,
    top_part_only: bool | None = None,
    spamlevel: int | None = None,
    filename: str | None = None,
) -> dict:
    """Build the type-dispatched request body shared by what_object_add/update."""
    body: dict = {}
    if type_ in ("contenttype", "archivefilter"):
        if contenttype is not None:
            body["contenttype"] = contenttype
        if only_content is not None:
            body["only-content"] = only_content
    elif type_ == "matchfield":
        if field is not None:
            body["field"] = field
        if value is not None:
            body["value"] = value
        if top_part_only is not None:
            body["top-part-only"] = top_part_only
    elif type_ == "spamfilter":
        if spamlevel is not None:
            body["spamlevel"] = spamlevel
    elif type_ in ("filenamefilter", "archivefilenamefilter"):
        if filename is not None:
            body["filename"] = filename
    # virusfilter: empty body (no type-specific fields)
    return body


def what_object_add(
    api: PmgBackend,
    ogroup: str,
    type_: str,
    *,
    contenttype: str | None = None,
    only_content: bool | None = None,
    field: str | None = None,
    value: str | None = None,
    top_part_only: bool | None = None,
    spamlevel: int | None = None,
    filename: str | None = None,
) -> object:
    """Add an object to a PMG RuleDB 'what' object group.

    POST /config/ruledb/what/{ogroup}/{type}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '8') from what_groups_list response.
    type_: contenttype|matchfield|spamfilter|virusfilter|filenamefilter|
           archivefilter|archivefilenamefilter — controls the sub-path.
    Type-specific fields (send only relevant non-None fields):
        contenttype:           contenttype(str), only_content(bool → 'only-content')
        matchfield:            field(str), value(str), top_part_only(bool → 'top-part-only')
        spamfilter:            spamlevel(int)
        virusfilter:           (no type-specific fields; empty body)
        filenamefilter:        filename(str)
        archivefilter:         contenttype(str), only_content(bool → 'only-content')
        archivefilenamefilter: filename(str)
    NOTE: if the group is already bound to a rule, the new object affects
    mail matching immediately on add.
    """
    ogroup = _check_ruledb_id(ogroup)
    type_ = _check_what_object_type(type_)
    body = _what_object_body(
        type_, contenttype=contenttype, only_content=only_content, field=field,
        value=value, top_part_only=top_part_only, spamlevel=spamlevel, filename=filename,
    )
    return api._post(f"/config/ruledb/what/{ogroup}/{type_}", data=body)


def what_object_update(
    api: PmgBackend,
    ogroup: str,
    type_: str,
    id_: str,
    *,
    contenttype: str | None = None,
    only_content: bool | None = None,
    field: str | None = None,
    value: str | None = None,
    top_part_only: bool | None = None,
    spamlevel: int | None = None,
    filename: str | None = None,
) -> object:
    """Update an object in a PMG RuleDB 'what' object group.

    PUT /config/ruledb/what/{ogroup}/{type}/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '8') from what_groups_list response.
    type_: contenttype|matchfield|spamfilter|virusfilter|filenamefilter|
           archivefilter|archivefilenamefilter — controls the sub-path.
    id_: object ID (numeric string) from what_group_objects response.
    All type-specific fields are optional; only non-None fields are sent.
    """
    ogroup = _check_ruledb_id(ogroup)
    type_ = _check_what_object_type(type_)
    id_ = _check_ruledb_id(id_)
    body = _what_object_body(
        type_, contenttype=contenttype, only_content=only_content, field=field,
        value=value, top_part_only=top_part_only, spamlevel=spamlevel, filename=filename,
    )
    return api._put(f"/config/ruledb/what/{ogroup}/{type_}/{id_}", data=body)


def what_object_delete(api: PmgBackend, ogroup: str, id_: str) -> object:
    """Delete an object from a PMG RuleDB 'what' object group.

    DELETE /config/ruledb/what/{ogroup}/objects/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '8') from what_groups_list response.
    id_: object ID (numeric string) from what_group_objects response.
    Object DELETE always goes through /objects/{id} regardless of type.
    """
    ogroup = _check_ruledb_id(ogroup)
    id_ = _check_ruledb_id(id_)
    return api._delete(f"/config/ruledb/what/{ogroup}/objects/{id_}")


# ---------------------------------------------------------------------------
# W5c MUTATION operations — WHEN-object CRUD
# ---------------------------------------------------------------------------


def when_object_add(
    api: PmgBackend,
    ogroup: str,
    *,
    start: str,
    end: str,
) -> object:
    """Add a timeframe object to a PMG RuleDB 'when' object group.

    POST /config/ruledb/when/{ogroup}/timeframe

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '4') from when_groups_list response.
    start: time in H:i format (e.g. '08:00').
    end: time in H:i format (e.g. '17:00').
    """
    ogroup = _check_ruledb_id(ogroup)
    body: dict = {"start": start, "end": end}
    return api._post(f"/config/ruledb/when/{ogroup}/timeframe", data=body)


def when_object_update(
    api: PmgBackend,
    ogroup: str,
    id_: str,
    *,
    start: str,
    end: str,
) -> object:
    """Update a timeframe object in a PMG RuleDB 'when' object group.

    PUT /config/ruledb/when/{ogroup}/timeframe/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '4') from when_groups_list response.
    id_: object ID (numeric string) from when_group_objects response.
    Both start and end are required — PMG 9.1 timeframe PUT enforces both
    even for a single-field change; a partial body returns 400.
    """
    ogroup = _check_ruledb_id(ogroup)
    id_ = _check_ruledb_id(id_)
    body: dict = {"start": start, "end": end}
    return api._put(f"/config/ruledb/when/{ogroup}/timeframe/{id_}", data=body)


def when_object_delete(api: PmgBackend, ogroup: str, id_: str) -> object:
    """Delete an object from a PMG RuleDB 'when' object group.

    DELETE /config/ruledb/when/{ogroup}/objects/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    ogroup: numeric ID string (e.g. '4') from when_groups_list response.
    id_: object ID (numeric string) from when_group_objects response.
    Object DELETE always goes through /objects/{id} regardless of type.
    """
    ogroup = _check_ruledb_id(ogroup)
    id_ = _check_ruledb_id(id_)
    return api._delete(f"/config/ruledb/when/{ogroup}/objects/{id_}")


# ---------------------------------------------------------------------------
# W5c MUTATION operations — ACTION CRUD
# ---------------------------------------------------------------------------


def action_bcc_create(
    api: PmgBackend,
    *,
    name: str,
    target: str,
    info: str | None = None,
    original: bool | None = None,
) -> object:
    """Create a BCC action object in the PMG RuleDB.

    POST /config/ruledb/action/bcc

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    name: action object name.
    target: target email address for BCC.
    info: optional description.
    original: if True, send the ORIGINAL, unmodified message to the BCC target (PMG's "send original
        mail" flag) instead of the processed/modified copy — it controls WHICH version is sent, not who
        receives it (the recipient is always `target`).
    """
    body: dict = {"name": name, "target": target}
    if info is not None:
        body["info"] = info
    if original is not None:
        body["original"] = original
    return api._post("/config/ruledb/action/bcc", data=body)


def action_bcc_update(
    api: PmgBackend,
    id_: str,
    *,
    name: str | None = None,
    target: str | None = None,
    info: str | None = None,
    original: bool | None = None,
) -> object:
    """Update a BCC action object in the PMG RuleDB.

    PUT /config/ruledb/action/bcc/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: compound action object ID (e.g. '13_26') from action_objects_list.
    Only non-None fields are sent; omitted fields keep their current values.
    """
    id_ = _check_action_object_id(id_)
    body: dict = {}
    if name is not None:
        body["name"] = name
    if target is not None:
        body["target"] = target
    if info is not None:
        body["info"] = info
    if original is not None:
        body["original"] = original
    return api._put(f"/config/ruledb/action/bcc/{id_}", data=body)


def action_field_create(
    api: PmgBackend,
    *,
    name: str,
    field: str,
    value: str,
    info: str | None = None,
) -> object:
    """Create a field-modification action object in the PMG RuleDB.

    POST /config/ruledb/action/field

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    name: action object name.
    field: mail header field to set.
    value: value to assign to the header field.
    info: optional description.
    """
    body: dict = {"name": name, "field": field, "value": value}
    if info is not None:
        body["info"] = info
    return api._post("/config/ruledb/action/field", data=body)


def action_field_update(
    api: PmgBackend,
    id_: str,
    *,
    name: str,
    field: str,
    value: str,
    info: str | None = None,
) -> object:
    """Update a field-modification action object in the PMG RuleDB.

    PUT /config/ruledb/action/field/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: compound action object ID (e.g. '13_26') from action_objects_list.
    name, field, value are all required — PMG 9.1 field action PUT requires
    all three even for a single-field change; a partial body returns 400.
    info: optional description.
    """
    id_ = _check_action_object_id(id_)
    body: dict = {"name": name, "field": field, "value": value}
    if info is not None:
        body["info"] = info
    return api._put(f"/config/ruledb/action/field/{id_}", data=body)


def action_notification_create(
    api: PmgBackend,
    *,
    name: str,
    to: str,
    subject: str,
    body_text: str,
    info: str | None = None,
    attach: bool | None = None,
) -> object:
    """Create a notification action object in the PMG RuleDB.

    POST /config/ruledb/action/notification

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    name: action object name.
    to: recipient email address for the notification.
    subject: notification email subject.
    body_text: notification email body (maps to API param 'body').
    info: optional description.
    attach: if True, attach the original message to the notification.
    """
    body: dict = {"name": name, "to": to, "subject": subject, "body": body_text}
    if info is not None:
        body["info"] = info
    if attach is not None:
        body["attach"] = attach
    return api._post("/config/ruledb/action/notification", data=body)


def action_notification_update(
    api: PmgBackend,
    id_: str,
    *,
    name: str,
    to: str,
    subject: str,
    body_text: str,
    info: str | None = None,
    attach: bool | None = None,
) -> object:
    """Update a notification action object in the PMG RuleDB.

    PUT /config/ruledb/action/notification/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: compound action object ID (e.g. '13_26') from action_objects_list.
    name, to, subject, body_text are all required — PMG 9.1 notification
    action PUT requires all four even for a single-field change; a partial
    body returns 400.  body_text maps to API param 'body'.
    info: optional description. attach: attach original message.
    """
    id_ = _check_action_object_id(id_)
    body: dict = {"name": name, "to": to, "subject": subject, "body": body_text}
    if info is not None:
        body["info"] = info
    if attach is not None:
        body["attach"] = attach
    return api._put(f"/config/ruledb/action/notification/{id_}", data=body)


def action_disclaimer_create(
    api: PmgBackend,
    *,
    name: str,
    disclaimer: str,
    info: str | None = None,
    position: str | None = None,
    add_separator: bool | None = None,
) -> object:
    """Create a disclaimer action object in the PMG RuleDB.

    POST /config/ruledb/action/disclaimer

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    name: action object name.
    disclaimer: disclaimer text to append/prepend.
    info: optional description.
    position: start|end — where to insert the disclaimer (default: end).
    add_separator: if True, add a separator line (maps to API param 'add-separator').
    """
    if position is not None:
        position = _check_action_position(position)
    body: dict = {"name": name, "disclaimer": disclaimer}
    if info is not None:
        body["info"] = info
    if position is not None:
        body["position"] = position
    if add_separator is not None:
        body["add-separator"] = add_separator
    return api._post("/config/ruledb/action/disclaimer", data=body)


def action_disclaimer_update(
    api: PmgBackend,
    id_: str,
    *,
    name: str | None = None,
    disclaimer: str | None = None,
    info: str | None = None,
    position: str | None = None,
    add_separator: bool | None = None,
) -> object:
    """Update a disclaimer action object in the PMG RuleDB.

    PUT /config/ruledb/action/disclaimer/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: compound action object ID (e.g. '13_26') from action_objects_list.
    position: start|end (validated if provided).
    add_separator: maps to API param 'add-separator'.
    Only non-None fields are sent; omitted fields keep their current values.
    """
    id_ = _check_action_object_id(id_)
    if position is not None:
        position = _check_action_position(position)
    body: dict = {}
    if name is not None:
        body["name"] = name
    if disclaimer is not None:
        body["disclaimer"] = disclaimer
    if info is not None:
        body["info"] = info
    if position is not None:
        body["position"] = position
    if add_separator is not None:
        body["add-separator"] = add_separator
    return api._put(f"/config/ruledb/action/disclaimer/{id_}", data=body)


def action_removeattachments_create(
    api: PmgBackend,
    *,
    name: str,
    text: str,
    info: str | None = None,
    all_: bool | None = None,
    quarantine: bool | None = None,
) -> object:
    """Create a remove-attachments action object in the PMG RuleDB.

    POST /config/ruledb/action/removeattachments

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    name: action object name.
    text: replacement text for removed attachments.
    info: optional description.
    all_: Python alias for API param 'all' (bool; if True, remove all attachments).
    quarantine: if True, quarantine removed attachments.
    """
    body: dict = {"name": name, "text": text}
    if info is not None:
        body["info"] = info
    if all_ is not None:
        body["all"] = all_
    if quarantine is not None:
        body["quarantine"] = quarantine
    return api._post("/config/ruledb/action/removeattachments", data=body)


def action_removeattachments_update(
    api: PmgBackend,
    id_: str,
    *,
    name: str | None = None,
    text: str | None = None,
    info: str | None = None,
    all_: bool | None = None,
    quarantine: bool | None = None,
) -> object:
    """Update a remove-attachments action object in the PMG RuleDB.

    PUT /config/ruledb/action/removeattachments/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: compound action object ID (e.g. '13_26') from action_objects_list.
    all_: Python alias for API param 'all' (bool).
    Only non-None fields are sent; omitted fields keep their current values.
    """
    id_ = _check_action_object_id(id_)
    body: dict = {}
    if name is not None:
        body["name"] = name
    if text is not None:
        body["text"] = text
    if info is not None:
        body["info"] = info
    if all_ is not None:
        body["all"] = all_
    if quarantine is not None:
        body["quarantine"] = quarantine
    return api._put(f"/config/ruledb/action/removeattachments/{id_}", data=body)


def action_delete(api: PmgBackend, id_: str) -> object:
    """Delete an action object from the PMG RuleDB.

    DELETE /config/ruledb/action/objects/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: compound action object ID (e.g. '13_26') from action_objects_list.
    NOTE: PMG rejects deletion of non-editable (built-in) system action objects.
    If the API returns an error for a non-editable action, that error is surfaced cleanly.
    Only action objects with 'editable: true' in action_objects_list can be deleted.
    """
    id_ = _check_action_object_id(id_)
    return api._delete(f"/config/ruledb/action/objects/{id_}")


# ---------------------------------------------------------------------------
# W5c PLAN functions — WHAT/WHEN/ACTION CRUD (PURE — no API call)
# ---------------------------------------------------------------------------


def plan_what_object_add(
    ogroup: str,
    type_: str,
    *,
    contenttype: str | None = None,
    only_content: bool | None = None,
    field: str | None = None,
    value: str | None = None,
    top_part_only: bool | None = None,
    spamlevel: int | None = None,
    filename: str | None = None,
) -> Plan:
    """Preview adding an object to a PMG RuleDB 'what' object group.  PURE — no API call.

    RISK_LOW: additive — adds one object to the group. NOTE: if the group is
    already bound to a rule, the new object affects mail matching immediately.
    """
    ogroup = _check_ruledb_id(ogroup)
    type_ = _check_what_object_type(type_)
    return Plan(
        action="pmg_what_object_add",
        target=f"config/ruledb/what/{ogroup}/{type_}",
        change=f"add {type_} object to 'what' group {ogroup}",
        current={},
        blast_radius=[
            f"adds one {type_} object to 'what' group {ogroup}",
            "additive: no existing objects are removed or modified",
            f"WARNING: if group {ogroup} is already bound to a rule, the new object "
            "affects mail matching immediately on add",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: adds one object; no existing config or mail deleted",
            "LOW overall — but immediate effect if group is in an active rule",
        ],
        note=f"PMG 9.1 pmgsh-verified path: POST /config/ruledb/what/{{ogroup}}/{type_}.",
    )


def plan_what_object_update(
    ogroup: str,
    type_: str,
    id_: str,
    *,
    contenttype: str | None = None,
    only_content: bool | None = None,
    field: str | None = None,
    value: str | None = None,
    top_part_only: bool | None = None,
    spamlevel: int | None = None,
    filename: str | None = None,
) -> Plan:
    """Preview updating an object in a PMG RuleDB 'what' object group.  PURE — no API call.

    RISK_MEDIUM: modifies an existing object; if the group is bound to an active
    rule, the change affects mail matching immediately.
    """
    ogroup = _check_ruledb_id(ogroup)
    type_ = _check_what_object_type(type_)
    id_ = _check_ruledb_id(id_)
    # Reuse the same type-dispatch body-builder the op uses, so the preview shows
    # exactly what would be sent — not just which object is being touched.
    changes = _what_object_body(
        type_, contenttype=contenttype, only_content=only_content, field=field,
        value=value, top_part_only=top_part_only, spamlevel=spamlevel, filename=filename,
    )
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_what_object_update",
        target=f"config/ruledb/what/{ogroup}/{type_}/{id_}",
        change=(f"update {type_} object {id_} in 'what' group {ogroup}: {change_summary}"
                if changes else f"update {type_} object {id_} in 'what' group {ogroup}"),
        current={},
        blast_radius=[
            f"modifies {type_} object {id_} in 'what' group {ogroup}",
            "if the group is bound to an active rule, the change takes effect immediately",
            "verify the new value matches your intended mail content filter target",
            (f"fields being changed: {change_summary}" if changes
             else "no fields specified — this is a no-op update"),
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: modifies an existing object; active rules referencing the group are affected",
            "incorrect value could allow or block unintended mail content immediately",
        ],
        note=f"PMG 9.1 pmgsh-verified path: PUT /config/ruledb/what/{{ogroup}}/{type_}/{{id}}.",
    )


def plan_what_object_delete(ogroup: str, id_: str) -> Plan:
    """Preview deleting an object from a PMG RuleDB 'what' object group.  PURE — no API call.

    RISK_MEDIUM: removes an existing object; if the group is bound to an active
    rule, the change affects mail matching immediately.
    """
    ogroup = _check_ruledb_id(ogroup)
    id_ = _check_ruledb_id(id_)
    return Plan(
        action="pmg_what_object_delete",
        target=f"config/ruledb/what/{ogroup}/objects/{id_}",
        change=f"delete object {id_} from 'what' group {ogroup}",
        current={},
        blast_radius=[
            f"permanently removes object {id_} from 'what' group {ogroup}",
            "if the group is bound to an active rule, the deletion takes effect immediately",
            "content types/patterns previously matched by this object will no longer match",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: removes an existing object; cannot be undone without re-adding",
            "active rules referencing the group immediately lose this content match entry",
        ],
        note="PMG 9.1 pmgsh-verified path: DELETE /config/ruledb/what/{ogroup}/objects/{id}.",
    )


def plan_when_object_add(ogroup: str, *, start: str, end: str) -> Plan:
    """Preview adding a timeframe object to a PMG RuleDB 'when' object group.  PURE — no API call.

    RISK_LOW: additive — adds one timeframe object to the group. NOTE: if the group is
    already bound to a rule, the new timeframe affects rule scheduling immediately.
    """
    ogroup = _check_ruledb_id(ogroup)
    return Plan(
        action="pmg_when_object_add",
        target=f"config/ruledb/when/{ogroup}/timeframe",
        change=f"add timeframe {start}-{end} to 'when' group {ogroup}",
        current={},
        blast_radius=[
            f"adds timeframe {start}–{end} to 'when' group {ogroup}",
            "additive: no existing timeframes are removed or modified",
            f"WARNING: if group {ogroup} is already bound to a rule, the new timeframe "
            "affects rule scheduling immediately on add",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: adds one timeframe; no existing config or mail deleted",
            "LOW overall — but immediate effect if group is in an active rule",
        ],
        note="PMG 9.1 pmgsh-verified path: POST /config/ruledb/when/{ogroup}/timeframe.",
    )


def plan_when_object_update(
    ogroup: str,
    id_: str,
    *,
    start: str | None = None,
    end: str | None = None,
) -> Plan:
    """Preview updating a timeframe object in a PMG RuleDB 'when' object group.  PURE — no API call.

    RISK_MEDIUM: modifies an existing timeframe; if the group is bound to an active
    rule, the change affects rule scheduling immediately.
    """
    ogroup = _check_ruledb_id(ogroup)
    id_ = _check_ruledb_id(id_)
    changes = {k: v for k, v in {"start": start, "end": end}.items() if v is not None}
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_when_object_update",
        target=f"config/ruledb/when/{ogroup}/timeframe/{id_}",
        change=(f"update timeframe object {id_} in 'when' group {ogroup}: {change_summary}"
                if changes else f"update timeframe object {id_} in 'when' group {ogroup}"),
        current={},
        blast_radius=[
            f"modifies timeframe object {id_} in 'when' group {ogroup}",
            "if the group is bound to an active rule, the change takes effect immediately",
            "verify the new start/end times match your intended scheduling window",
            (f"fields being changed: {change_summary}" if changes
             else "no fields specified — this is a no-op update"),
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: modifies an existing timeframe; active rules referencing the group are affected",
            "incorrect time window could enable or disable rule matching at unintended hours",
        ],
        note="PMG 9.1 pmgsh-verified path: PUT /config/ruledb/when/{ogroup}/timeframe/{id}.",
    )


def plan_when_object_delete(ogroup: str, id_: str) -> Plan:
    """Preview deleting a timeframe object from a PMG RuleDB 'when' object group.  PURE — no API call.

    RISK_MEDIUM: removes an existing timeframe; if the group is bound to an active
    rule, the change affects rule scheduling immediately.
    """
    ogroup = _check_ruledb_id(ogroup)
    id_ = _check_ruledb_id(id_)
    return Plan(
        action="pmg_when_object_delete",
        target=f"config/ruledb/when/{ogroup}/objects/{id_}",
        change=f"delete timeframe object {id_} from 'when' group {ogroup}",
        current={},
        blast_radius=[
            f"permanently removes timeframe object {id_} from 'when' group {ogroup}",
            "if the group is bound to an active rule, the deletion takes effect immediately",
            "the time window removed will no longer constrain rule scheduling",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: removes an existing timeframe; cannot be undone without re-adding",
            "active rules referencing the group may now fire at all times if no timeframes remain",
        ],
        note="PMG 9.1 pmgsh-verified path: DELETE /config/ruledb/when/{ogroup}/objects/{id}.",
    )


def plan_action_bcc_create(name: str, target: str) -> Plan:
    """Preview creating a BCC action object in the PMG RuleDB.  PURE — no API call.

    RISK_LOW: additive — creates a new BCC action object; does not affect existing rules
    until the action is attached to a rule (W5d).
    """
    return Plan(
        action="pmg_action_bcc_create",
        target="config/ruledb/action/bcc",
        change=f"create BCC action '{name}' targeting '{target}'",
        current={},
        blast_radius=[
            f"creates a new BCC action object named '{name}' with target '{target}'",
            "additive: does not affect existing action objects or mail flow",
            "the action has no effect until attached to a rule (W5d)",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: creates one action object; no existing config or mail deleted",
            "LOW: action is inactive until bound to a rule",
        ],
        note="PMG 9.1 pmgsh-verified path: POST /config/ruledb/action/bcc.",
    )


def plan_action_bcc_update(
    id_: str,
    name: str | None = None,
    target: str | None = None,
    info: str | None = None,
    original: bool | None = None,
) -> Plan:
    """Preview updating a BCC action object in the PMG RuleDB.  PURE — no API call.

    RISK_MEDIUM: modifies an existing action; active rules referencing it are affected.
    """
    id_ = _check_action_object_id(id_)
    changes = {k: v for k, v in
               {"name": name, "target": target, "info": info, "original": original}.items()
               if v is not None}
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_action_bcc_update",
        target=f"config/ruledb/action/bcc/{id_}",
        change=(f"update BCC action object {id_}: {change_summary}"
                if changes else f"update BCC action object {id_}"),
        current={},
        blast_radius=[
            f"modifies BCC action object {id_}",
            "if the action is attached to an active rule, the change takes effect immediately",
            "BCC target change affects where copies of matched mail are sent",
            (f"fields being changed: {change_summary}" if changes
             else "no fields specified — this is a no-op update"),
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: modifies an existing action; active rules referencing it are affected",
            "incorrect target could BCC mail to unintended recipients",
        ],
        note="PMG 9.1 pmgsh-verified path: PUT /config/ruledb/action/bcc/{id}.",
    )


def plan_action_field_create(name: str, field: str, value: str) -> Plan:
    """Preview creating a field-modification action object in the PMG RuleDB.  PURE — no API call.

    RISK_LOW: additive — creates a new field action object; inactive until attached to a rule.
    """
    return Plan(
        action="pmg_action_field_create",
        target="config/ruledb/action/field",
        change=f"create field action '{name}': set {field}={value!r}",
        current={},
        blast_radius=[
            f"creates a new field action named '{name}' that sets header '{field}' to '{value}'",
            "additive: does not affect existing action objects or mail flow",
            "the action has no effect until attached to a rule (W5d)",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: creates one action object; no existing config or mail deleted",
            "LOW: action is inactive until bound to a rule",
        ],
        note="PMG 9.1 pmgsh-verified path: POST /config/ruledb/action/field.",
    )


def plan_action_field_update(
    id_: str,
    name: str | None = None,
    field: str | None = None,
    value: str | None = None,
    info: str | None = None,
) -> Plan:
    """Preview updating a field-modification action object in the PMG RuleDB.  PURE — no API call.

    RISK_MEDIUM: modifies an existing action; active rules referencing it are affected.
    """
    id_ = _check_action_object_id(id_)
    changes = {k: v for k, v in
               {"name": name, "field": field, "value": value, "info": info}.items()
               if v is not None}
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_action_field_update",
        target=f"config/ruledb/action/field/{id_}",
        change=(f"update field action object {id_}: {change_summary}"
                if changes else f"update field action object {id_}"),
        current={},
        blast_radius=[
            f"modifies field action object {id_}",
            "if the action is attached to an active rule, the change takes effect immediately",
            "field change affects what header value is injected into matched messages",
            (f"fields being changed: {change_summary}" if changes
             else "no fields specified — this is a no-op update"),
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: modifies an existing action; active rules referencing it are affected",
            "incorrect field/value could inject wrong headers into matched messages",
        ],
        note="PMG 9.1 pmgsh-verified path: PUT /config/ruledb/action/field/{id}.",
    )


def plan_action_notification_create(name: str, to: str) -> Plan:
    """Preview creating a notification action object in the PMG RuleDB.  PURE — no API call.

    RISK_LOW: additive — creates a new notification action object; inactive until attached.
    """
    return Plan(
        action="pmg_action_notification_create",
        target="config/ruledb/action/notification",
        change=f"create notification action '{name}' sending to '{to}'",
        current={},
        blast_radius=[
            f"creates a new notification action named '{name}' that sends to '{to}'",
            "additive: does not affect existing action objects or mail flow",
            "the action has no effect until attached to a rule (W5d)",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: creates one action object; no existing config or mail deleted",
            "LOW: action is inactive until bound to a rule",
        ],
        note="PMG 9.1 pmgsh-verified path: POST /config/ruledb/action/notification.",
    )


def plan_action_notification_update(
    id_: str,
    name: str | None = None,
    to: str | None = None,
    subject: str | None = None,
    body_text: str | None = None,
    info: str | None = None,
    attach: bool | None = None,
) -> Plan:
    """Preview updating a notification action object in the PMG RuleDB.  PURE — no API call.

    RISK_MEDIUM: modifies an existing action; active rules referencing it are affected.
    """
    id_ = _check_action_object_id(id_)
    changes = {k: v for k, v in
               {"name": name, "to": to, "subject": subject, "body": body_text,
                "info": info, "attach": attach}.items()
               if v is not None}
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_action_notification_update",
        target=f"config/ruledb/action/notification/{id_}",
        change=(f"update notification action object {id_}: {change_summary}"
                if changes else f"update notification action object {id_}"),
        current={},
        blast_radius=[
            f"modifies notification action object {id_}",
            "if the action is attached to an active rule, the change takes effect immediately",
            "recipient/subject/body changes affect notifications sent for matched mail",
            (f"fields being changed: {change_summary}" if changes
             else "no fields specified — this is a no-op update"),
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: modifies an existing action; active rules referencing it are affected",
            "incorrect recipient could send notifications to unintended addresses",
        ],
        note="PMG 9.1 pmgsh-verified path: PUT /config/ruledb/action/notification/{id}.",
    )


def plan_action_disclaimer_create(name: str) -> Plan:
    """Preview creating a disclaimer action object in the PMG RuleDB.  PURE — no API call.

    RISK_LOW: additive — creates a new disclaimer action object; inactive until attached.
    """
    return Plan(
        action="pmg_action_disclaimer_create",
        target="config/ruledb/action/disclaimer",
        change=f"create disclaimer action '{name}'",
        current={},
        blast_radius=[
            f"creates a new disclaimer action named '{name}'",
            "additive: does not affect existing action objects or mail flow",
            "the action has no effect until attached to a rule (W5d)",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: creates one action object; no existing config or mail deleted",
            "LOW: action is inactive until bound to a rule",
        ],
        note="PMG 9.1 pmgsh-verified path: POST /config/ruledb/action/disclaimer.",
    )


def plan_action_disclaimer_update(
    id_: str,
    name: str | None = None,
    disclaimer: str | None = None,
    info: str | None = None,
    position: str | None = None,
    add_separator: bool | None = None,
) -> Plan:
    """Preview updating a disclaimer action object in the PMG RuleDB.  PURE — no API call.

    RISK_MEDIUM: modifies an existing action; active rules referencing it are affected.
    """
    id_ = _check_action_object_id(id_)
    changes = {k: v for k, v in
               {"name": name, "disclaimer": disclaimer, "info": info,
                "position": position, "add-separator": add_separator}.items()
               if v is not None}
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_action_disclaimer_update",
        target=f"config/ruledb/action/disclaimer/{id_}",
        change=(f"update disclaimer action object {id_}: {change_summary}"
                if changes else f"update disclaimer action object {id_}"),
        current={},
        blast_radius=[
            f"modifies disclaimer action object {id_}",
            "if the action is attached to an active rule, the change takes effect immediately",
            "disclaimer text/position changes affect all messages matched by rules using this action",
            (f"fields being changed: {change_summary}" if changes
             else "no fields specified — this is a no-op update"),
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: modifies an existing action; active rules referencing it are affected",
            "disclaimer change affects all mail processed by rules using this action",
        ],
        note="PMG 9.1 pmgsh-verified path: PUT /config/ruledb/action/disclaimer/{id}.",
    )


def plan_action_removeattachments_create(name: str) -> Plan:
    """Preview creating a remove-attachments action object in the PMG RuleDB.  PURE — no API call.

    RISK_LOW: additive — creates a new remove-attachments action object; inactive until attached.
    """
    return Plan(
        action="pmg_action_removeattachments_create",
        target="config/ruledb/action/removeattachments",
        change=f"create remove-attachments action '{name}'",
        current={},
        blast_radius=[
            f"creates a new remove-attachments action named '{name}'",
            "additive: does not affect existing action objects or mail flow",
            "the action has no effect until attached to a rule (W5d)",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive: creates one action object; no existing config or mail deleted",
            "LOW: action is inactive until bound to a rule",
        ],
        note="PMG 9.1 pmgsh-verified path: POST /config/ruledb/action/removeattachments.",
    )


def plan_action_removeattachments_update(
    id_: str,
    name: str | None = None,
    text: str | None = None,
    info: str | None = None,
    all_: bool | None = None,
    quarantine: bool | None = None,
) -> Plan:
    """Preview updating a remove-attachments action object in the PMG RuleDB.  PURE — no API call.

    RISK_MEDIUM: modifies an existing action; active rules referencing it are affected.
    """
    id_ = _check_action_object_id(id_)
    changes = {k: v for k, v in
               {"name": name, "text": text, "info": info,
                "all": all_, "quarantine": quarantine}.items()
               if v is not None}
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_action_removeattachments_update",
        target=f"config/ruledb/action/removeattachments/{id_}",
        change=(f"update remove-attachments action object {id_}: {change_summary}"
                if changes else f"update remove-attachments action object {id_}"),
        current={},
        blast_radius=[
            f"modifies remove-attachments action object {id_}",
            "if the action is attached to an active rule, the change takes effect immediately",
            "changes to all/quarantine/text affect how attachments are removed from matched mail",
            (f"fields being changed: {change_summary}" if changes
             else "no fields specified — this is a no-op update"),
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: modifies an existing action; active rules referencing it are affected",
            "quarantine behavior change affects where stripped attachments are stored",
        ],
        note="PMG 9.1 pmgsh-verified path: PUT /config/ruledb/action/removeattachments/{id}.",
    )


def plan_action_delete(id_: str) -> Plan:
    """Preview deleting an action object from the PMG RuleDB.  PURE — no API call.

    RISK_MEDIUM: deletes an action object; rules referencing it will lose the action.
    NOTE: PMG rejects deletion of non-editable (built-in) system action objects.
    """
    id_ = _check_action_object_id(id_)
    return Plan(
        action="pmg_action_delete",
        target=f"config/ruledb/action/objects/{id_}",
        change=f"delete action object {id_}",
        current={},
        blast_radius=[
            f"permanently removes action object {id_} from the PMG RuleDB",
            "rules that reference this action will lose it upon next evaluation",
            "WARNING: PMG rejects deletion of non-editable (built-in) system actions",
            "check 'editable' flag in pmg_action_objects_list before confirming",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: deletes an action object; cannot be undone without re-creating",
            "rules referencing this action may stop applying the intended action",
        ],
        note="PMG 9.1 pmgsh-verified path: DELETE /config/ruledb/action/objects/{id}.",
    )


# ---------------------------------------------------------------------------
# W5d Validators
# ---------------------------------------------------------------------------


def _check_direction(direction: int) -> int:
    """Validate a PMG rule direction value: 0 (in), 1 (out), or 2 (both)."""
    try:
        d = int(direction)
    except (ValueError, TypeError) as exc:
        raise ProximoError(
            f"invalid direction: {direction!r} — must be 0 (in), 1 (out), or 2 (both)"
        ) from exc
    if d not in (0, 1, 2):
        raise ProximoError(
            f"invalid direction: {direction!r} — must be 0 (in), 1 (out), or 2 (both)"
        )
    return d


def _check_priority(priority: int) -> int:
    """Validate a PMG rule priority value: integer in range 0-100."""
    try:
        p = int(priority)
    except (ValueError, TypeError) as exc:
        raise ProximoError(
            f"invalid priority: {priority!r} — must be an integer in range 0-100"
        ) from exc
    if not (0 <= p <= 100):
        raise ProximoError(
            f"invalid priority: {priority!r} — must be in range 0-100"
        )
    return p


# ---------------------------------------------------------------------------
# W5d MUTATION operations — rule CRUD + rule↔group attach/detach
# ---------------------------------------------------------------------------


def ruledb_rule_create(
    api: PmgBackend,
    name: str,
    priority: int,
    active: bool = False,
    direction: int | None = None,
    from_and: bool | None = None,
    from_invert: bool | None = None,
    to_and: bool | None = None,
    to_invert: bool | None = None,
    what_and: bool | None = None,
    what_invert: bool | None = None,
    when_and: bool | None = None,
    when_invert: bool | None = None,
) -> object:
    """Create a PMG RuleDB rule.

    POST /config/ruledb/rules

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    name: rule name.
    priority: 0-100 (lower = higher priority in PMG processing order).
    active: whether the rule is active — DEFAULTS TO FALSE (safety default).
            Rules control live mail processing; confirm active=True only when
            the rule configuration has been verified.
    direction: 0=inbound, 1=outbound, 2=both.
    from_and/from_invert/to_and/to_invert/what_and/what_invert/when_and/when_invert:
        bool flags controlling AND/invert logic for each slot — maps to the
        hyphen-param API names (from-and, from-invert, etc.).
    Returns the numeric rule ID assigned by PMG.
    """
    priority_int = _check_priority(priority)
    body: dict = {"name": name, "priority": priority_int, "active": active}
    if direction is not None:
        body["direction"] = _check_direction(direction)
    if from_and is not None:
        body["from-and"] = from_and
    if from_invert is not None:
        body["from-invert"] = from_invert
    if to_and is not None:
        body["to-and"] = to_and
    if to_invert is not None:
        body["to-invert"] = to_invert
    if what_and is not None:
        body["what-and"] = what_and
    if what_invert is not None:
        body["what-invert"] = what_invert
    if when_and is not None:
        body["when-and"] = when_and
    if when_invert is not None:
        body["when-invert"] = when_invert
    return api._post("/config/ruledb/rules", data=body)


def ruledb_rule_update(
    api: PmgBackend,
    id_: str,
    name: str | None = None,
    priority: int | None = None,
    active: bool | None = None,
    direction: int | None = None,
    from_and: bool | None = None,
    from_invert: bool | None = None,
    to_and: bool | None = None,
    to_invert: bool | None = None,
    what_and: bool | None = None,
    what_invert: bool | None = None,
    when_and: bool | None = None,
    when_invert: bool | None = None,
) -> object:
    """Update a PMG RuleDB rule's configuration.

    PUT /config/ruledb/rules/{id}/config

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    All fields are optional; only non-None values are sent.
    WARNING: setting active=True activates the rule and begins live mail processing.
    """
    id_ = _check_ruledb_id(id_)
    body: dict = {}
    if name is not None:
        body["name"] = name
    if priority is not None:
        body["priority"] = _check_priority(priority)
    if active is not None:
        body["active"] = active
    if direction is not None:
        body["direction"] = _check_direction(direction)
    if from_and is not None:
        body["from-and"] = from_and
    if from_invert is not None:
        body["from-invert"] = from_invert
    if to_and is not None:
        body["to-and"] = to_and
    if to_invert is not None:
        body["to-invert"] = to_invert
    if what_and is not None:
        body["what-and"] = what_and
    if what_invert is not None:
        body["what-invert"] = what_invert
    if when_and is not None:
        body["when-and"] = when_and
    if when_invert is not None:
        body["when-invert"] = when_invert
    return api._put(f"/config/ruledb/rules/{id_}/config", data=body)


def ruledb_rule_delete(api: PmgBackend, id_: str) -> object:
    """Delete a PMG RuleDB rule.

    DELETE /config/ruledb/rules/{id}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    WARNING: permanently removes the rule and detaches all group bindings.
    """
    id_ = _check_ruledb_id(id_)
    return api._delete(f"/config/ruledb/rules/{id_}")


def ruledb_rule_from_attach(api: PmgBackend, id_: str, ogroup: str) -> object:
    """Attach a 'from' (sender/who) object group to a PMG RuleDB rule.

    POST /config/ruledb/rules/{id}/from

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    ogroup: numeric ID of the who-group to attach (from pmg_who_groups_list).
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return api._post(f"/config/ruledb/rules/{id_}/from", data={"ogroup": ogroup})


def ruledb_rule_from_detach(api: PmgBackend, id_: str, ogroup: str) -> object:
    """Detach a 'from' (sender/who) object group from a PMG RuleDB rule.

    DELETE /config/ruledb/rules/{id}/from/{ogroup}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    ogroup: numeric ID of the who-group to detach.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return api._delete(f"/config/ruledb/rules/{id_}/from/{ogroup}")


def ruledb_rule_to_attach(api: PmgBackend, id_: str, ogroup: str) -> object:
    """Attach a 'to' (recipient/who) object group to a PMG RuleDB rule.

    POST /config/ruledb/rules/{id}/to

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    ogroup: numeric ID of the who-group to attach (from pmg_who_groups_list).
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return api._post(f"/config/ruledb/rules/{id_}/to", data={"ogroup": ogroup})


def ruledb_rule_to_detach(api: PmgBackend, id_: str, ogroup: str) -> object:
    """Detach a 'to' (recipient/who) object group from a PMG RuleDB rule.

    DELETE /config/ruledb/rules/{id}/to/{ogroup}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    ogroup: numeric ID of the who-group to detach.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return api._delete(f"/config/ruledb/rules/{id_}/to/{ogroup}")


def ruledb_rule_what_attach(api: PmgBackend, id_: str, ogroup: str) -> object:
    """Attach a 'what' (content) object group to a PMG RuleDB rule.

    POST /config/ruledb/rules/{id}/what

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    ogroup: numeric ID of the what-group to attach (from pmg_what_groups_list).
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return api._post(f"/config/ruledb/rules/{id_}/what", data={"ogroup": ogroup})


def ruledb_rule_what_detach(api: PmgBackend, id_: str, ogroup: str) -> object:
    """Detach a 'what' (content) object group from a PMG RuleDB rule.

    DELETE /config/ruledb/rules/{id}/what/{ogroup}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    ogroup: numeric ID of the what-group to detach.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return api._delete(f"/config/ruledb/rules/{id_}/what/{ogroup}")


def ruledb_rule_when_attach(api: PmgBackend, id_: str, ogroup: str) -> object:
    """Attach a 'when' (timeframe) object group to a PMG RuleDB rule.

    POST /config/ruledb/rules/{id}/when

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    ogroup: numeric ID of the when-group to attach (from pmg_when_groups_list).
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return api._post(f"/config/ruledb/rules/{id_}/when", data={"ogroup": ogroup})


def ruledb_rule_when_detach(api: PmgBackend, id_: str, ogroup: str) -> object:
    """Detach a 'when' (timeframe) object group from a PMG RuleDB rule.

    DELETE /config/ruledb/rules/{id}/when/{ogroup}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 pmgsh-verified path.
    id_: rule ID (positive integer string, e.g. '100').
    ogroup: numeric ID of the when-group to detach.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return api._delete(f"/config/ruledb/rules/{id_}/when/{ogroup}")


def ruledb_rule_action_attach(api: PmgBackend, id_: str, ogroup: str) -> object:
    """Attach an action object group to a PMG RuleDB rule.

    POST /config/ruledb/rules/{id}/action

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path: singular /action (not /actions — that path returns 501).
    id_: rule ID (positive integer string, e.g. '100').
    ogroup: numeric group-ID of the action group to attach (the integer part before '_' in
        a compound action id like '13_26'; from pmg_action_objects_list).
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return api._post(f"/config/ruledb/rules/{id_}/action", data={"ogroup": ogroup})


def ruledb_rule_action_detach(api: PmgBackend, id_: str, ogroup: str) -> object:
    """Detach an action object group from a PMG RuleDB rule.

    DELETE /config/ruledb/rules/{id}/action/{ogroup}

    MUTATION — confirm-gated + audited at the server layer.

    PMG 9.1 live-verified path: singular /action (not /actions — that path returns 501).
    id_: rule ID (positive integer string, e.g. '100').
    ogroup: numeric group-ID of the action group to detach.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return api._delete(f"/config/ruledb/rules/{id_}/action/{ogroup}")


# ---------------------------------------------------------------------------
# W5d PLAN functions — rule CRUD + attach/detach (PURE — no API call)
# ---------------------------------------------------------------------------

_RULE_MAIL_FLOW_WARNING = (
    "Rules control live mail processing. An active rule (active=1) at low priority "
    "with broad who/what groups can affect ALL mail flow."
)


def plan_ruledb_rule_create(
    name: str,
    priority: int,
    active: bool = False,
    direction: int | None = None,
    from_and: bool | None = None,
    from_invert: bool | None = None,
    to_and: bool | None = None,
    to_invert: bool | None = None,
    what_and: bool | None = None,
    what_invert: bool | None = None,
    when_and: bool | None = None,
    when_invert: bool | None = None,
) -> Plan:
    """Preview creating a PMG RuleDB rule.  PURE — no API call.

    RISK_MEDIUM: rules control live mail processing.
    active DEFAULTS TO FALSE — inactive rules do not affect mail flow until activated.
    """
    priority_int = _check_priority(priority)
    if direction is not None:
        _check_direction(direction)
    dir_str = {0: "inbound", 1: "outbound", 2: "both"}.get(
        direction if direction is not None else -1, "not set"
    )
    return Plan(
        action="pmg_ruledb_rule_create",
        target="config/ruledb/rules",
        change=f"create RuleDB rule '{name}' (priority={priority_int}, active={active})",
        current={},
        blast_radius=[
            f"creates rule '{name}' with priority={priority_int}, direction={dir_str}",
            f"active={active} — {'RULE IS INACTIVE: will not affect mail flow until activated'
               if not active else 'RULE IS ACTIVE: will affect live mail processing immediately'}",
            _RULE_MAIL_FLOW_WARNING,
            "attach who/what/when/action groups before activating to ensure correct scope",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: rules control live mail processing; even an inactive rule becomes "
            "active if updated with active=True",
            "LOW risk when active=False (default); review all group attachments before activating",
        ],
        note="PMG 9.1 pmgsh-verified path: POST /config/ruledb/rules.",
    )


def plan_ruledb_rule_update(
    id_: str,
    name: str | None = None,
    priority: int | None = None,
    active: bool | None = None,
    direction: int | None = None,
    from_and: bool | None = None,
    from_invert: bool | None = None,
    to_and: bool | None = None,
    to_invert: bool | None = None,
    what_and: bool | None = None,
    what_invert: bool | None = None,
    when_and: bool | None = None,
    when_invert: bool | None = None,
) -> Plan:
    """Preview updating a PMG RuleDB rule's configuration.  PURE — no API call.

    RISK_MEDIUM: modifying a rule can change live mail processing immediately
    if the rule is active.  Setting active=True activates the rule.
    """
    id_ = _check_ruledb_id(id_)
    if priority is not None:
        _check_priority(priority)
    if direction is not None:
        _check_direction(direction)
    active_note = (
        "WARNING: setting active=True activates the rule and begins live mail processing"
        if active is True
        else "active flag is not being changed by this update"
        if active is None
        else "setting active=False deactivates the rule (stops mail processing)"
    )
    # `active` already gets its own dedicated note above — disclose the remaining fields here.
    changes = {k: v for k, v in {
        "name": name, "priority": priority, "direction": direction,
        "from-and": from_and, "from-invert": from_invert,
        "to-and": to_and, "to-invert": to_invert,
        "what-and": what_and, "what-invert": what_invert,
        "when-and": when_and, "when-invert": when_invert,
    }.items() if v is not None}
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    return Plan(
        action="pmg_ruledb_rule_update",
        target=f"config/ruledb/rules/{id_}/config",
        change=(f"update RuleDB rule {id_} configuration: {change_summary}"
                if changes else f"update RuleDB rule {id_} configuration"),
        current={},
        blast_radius=[
            f"modifies configuration of rule {id_}",
            active_note,
            _RULE_MAIL_FLOW_WARNING,
            "changes to an active rule take effect immediately on new mail",
            (f"fields being changed: {change_summary}" if changes
             else "no fields specified (other than possibly active) — see active flag above"),
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: rule config changes can alter live mail processing immediately",
            "setting active=True starts processing mail against this rule's groups",
        ],
        note="PMG 9.1 pmgsh-verified path: PUT /config/ruledb/rules/{id}/config.",
    )


def plan_ruledb_rule_delete(id_: str) -> Plan:
    """Preview deleting a PMG RuleDB rule.  PURE — no API call.

    RISK_MEDIUM: permanently removes the rule and all its group bindings.
    """
    id_ = _check_ruledb_id(id_)
    return Plan(
        action="pmg_ruledb_rule_delete",
        target=f"config/ruledb/rules/{id_}",
        change=f"delete RuleDB rule {id_}",
        current={},
        blast_radius=[
            f"permanently removes rule {id_} from the PMG RuleDB",
            "all group attachments (from/to/what/when/action) are also removed",
            "if the rule was active, its mail processing effect stops immediately",
            "the rule cannot be recovered without re-creation and re-attachment of groups",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: permanently removes a rule; cannot be undone without full re-creation",
            "if active, the rule's mail filtering effect stops on deletion",
        ],
        note="PMG 9.1 pmgsh-verified path: DELETE /config/ruledb/rules/{id}.",
    )


def _attach_detach_plan(
    action: str,
    target: str,
    change: str,
    id_: str,
    ogroup: str,
    slot: str,
    verb: str,
) -> Plan:
    """Shared plan builder for rule↔group attach/detach operations."""
    return Plan(
        action=action,
        target=target,
        change=change,
        current={},
        blast_radius=[
            f"{verb}s '{slot}' group {ogroup} {'to' if 'attach' in action else 'from'} rule {id_}",
            "modifies which mail a rule matches; only affects flow if the rule is active",
            _RULE_MAIL_FLOW_WARNING,
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            f"MEDIUM: {verb}ing a group modifies rule matching scope",
            "only affects live mail if the rule is active; confirm rule state before proceeding",
        ],
        note=f"PMG 9.1 pmgsh-verified path: {target.replace('config/', '/config/', 1)}.",
    )


def plan_ruledb_rule_from_attach(id_: str, ogroup: str) -> Plan:
    """Preview attaching a 'from' (sender/who) group to a PMG RuleDB rule.  PURE — no API call.

    RISK_MEDIUM: modifies which mail a rule matches; only affects flow if the rule is active.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return _attach_detach_plan(
        action="pmg_ruledb_rule_from_attach",
        target=f"config/ruledb/rules/{id_}/from",
        change=f"attach 'from' group {ogroup} to rule {id_}",
        id_=id_, ogroup=ogroup, slot="from", verb="attach",
    )


def plan_ruledb_rule_from_detach(id_: str, ogroup: str) -> Plan:
    """Preview detaching a 'from' (sender/who) group from a PMG RuleDB rule.  PURE — no API call.

    RISK_MEDIUM: modifies which mail a rule matches; only affects flow if the rule is active.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return _attach_detach_plan(
        action="pmg_ruledb_rule_from_detach",
        target=f"config/ruledb/rules/{id_}/from/{ogroup}",
        change=f"detach 'from' group {ogroup} from rule {id_}",
        id_=id_, ogroup=ogroup, slot="from", verb="detach",
    )


def plan_ruledb_rule_to_attach(id_: str, ogroup: str) -> Plan:
    """Preview attaching a 'to' (recipient/who) group to a PMG RuleDB rule.  PURE — no API call.

    RISK_MEDIUM: modifies which mail a rule matches; only affects flow if the rule is active.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return _attach_detach_plan(
        action="pmg_ruledb_rule_to_attach",
        target=f"config/ruledb/rules/{id_}/to",
        change=f"attach 'to' group {ogroup} to rule {id_}",
        id_=id_, ogroup=ogroup, slot="to", verb="attach",
    )


def plan_ruledb_rule_to_detach(id_: str, ogroup: str) -> Plan:
    """Preview detaching a 'to' (recipient/who) group from a PMG RuleDB rule.  PURE — no API call.

    RISK_MEDIUM: modifies which mail a rule matches; only affects flow if the rule is active.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return _attach_detach_plan(
        action="pmg_ruledb_rule_to_detach",
        target=f"config/ruledb/rules/{id_}/to/{ogroup}",
        change=f"detach 'to' group {ogroup} from rule {id_}",
        id_=id_, ogroup=ogroup, slot="to", verb="detach",
    )


def plan_ruledb_rule_what_attach(id_: str, ogroup: str) -> Plan:
    """Preview attaching a 'what' (content) group to a PMG RuleDB rule.  PURE — no API call.

    RISK_MEDIUM: modifies which mail a rule matches; only affects flow if the rule is active.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return _attach_detach_plan(
        action="pmg_ruledb_rule_what_attach",
        target=f"config/ruledb/rules/{id_}/what",
        change=f"attach 'what' group {ogroup} to rule {id_}",
        id_=id_, ogroup=ogroup, slot="what", verb="attach",
    )


def plan_ruledb_rule_what_detach(id_: str, ogroup: str) -> Plan:
    """Preview detaching a 'what' (content) group from a PMG RuleDB rule.  PURE — no API call.

    RISK_MEDIUM: modifies which mail a rule matches; only affects flow if the rule is active.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return _attach_detach_plan(
        action="pmg_ruledb_rule_what_detach",
        target=f"config/ruledb/rules/{id_}/what/{ogroup}",
        change=f"detach 'what' group {ogroup} from rule {id_}",
        id_=id_, ogroup=ogroup, slot="what", verb="detach",
    )


def plan_ruledb_rule_when_attach(id_: str, ogroup: str) -> Plan:
    """Preview attaching a 'when' (timeframe) group to a PMG RuleDB rule.  PURE — no API call.

    RISK_MEDIUM: modifies which mail a rule matches; only affects flow if the rule is active.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return _attach_detach_plan(
        action="pmg_ruledb_rule_when_attach",
        target=f"config/ruledb/rules/{id_}/when",
        change=f"attach 'when' group {ogroup} to rule {id_}",
        id_=id_, ogroup=ogroup, slot="when", verb="attach",
    )


def plan_ruledb_rule_when_detach(id_: str, ogroup: str) -> Plan:
    """Preview detaching a 'when' (timeframe) group from a PMG RuleDB rule.  PURE — no API call.

    RISK_MEDIUM: modifies which mail a rule matches; only affects flow if the rule is active.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return _attach_detach_plan(
        action="pmg_ruledb_rule_when_detach",
        target=f"config/ruledb/rules/{id_}/when/{ogroup}",
        change=f"detach 'when' group {ogroup} from rule {id_}",
        id_=id_, ogroup=ogroup, slot="when", verb="detach",
    )


def plan_ruledb_rule_action_attach(id_: str, ogroup: str) -> Plan:
    """Preview attaching an action group to a PMG RuleDB rule.  PURE — no API call.

    RISK_MEDIUM: modifies which mail a rule matches; only affects flow if the rule is active.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return _attach_detach_plan(
        action="pmg_ruledb_rule_action_attach",
        target=f"config/ruledb/rules/{id_}/action",
        change=f"attach action group {ogroup} to rule {id_}",
        id_=id_, ogroup=ogroup, slot="action", verb="attach",
    )


def plan_ruledb_rule_action_detach(id_: str, ogroup: str) -> Plan:
    """Preview detaching an action group from a PMG RuleDB rule.  PURE — no API call.

    RISK_MEDIUM: modifies which mail a rule matches; only affects flow if the rule is active.
    """
    id_ = _check_ruledb_id(id_)
    ogroup = _check_ruledb_id(ogroup)
    return _attach_detach_plan(
        action="pmg_ruledb_rule_action_detach",
        target=f"config/ruledb/rules/{id_}/action/{ogroup}",
        change=f"detach action group {ogroup} from rule {id_}",
        id_=id_, ogroup=ogroup, slot="action", verb="detach",
    )


# ---------------------------------------------------------------------------
# W6a — Wave 8a: ruledb per-object reads + ldapuser (extension, above) + the direct singular
# rule<->action-group read + RuleDB factory reset.
#
# (pmg.py's OWN section-marker sequence — W2/W3/W4/W5a-d/W6a — is independent of the
# cross-plane campaign's "Wave 8" label; see .scratch/2026-07-15-full-surface-campaign.md's
# Wave 8 decomposition note on this exact point.)
#
# Coordinator rulings (.scratch/2026-07-15-full-surface-campaign.md, "Wave 8 decomposition",
# binding, SUPERSEDE the scout draft where they differ):
#   RULING 1 — factory reset BUILT as pmg_ruledb_reset, RISK_HIGH (the wave's only above-MEDIUM
#     rating). Required plan shape: CAPTURE current scope and render the toll, with the FIRST
#     blast_radius line stating Proximo has no undo for this call.
#   RULING 2 — the new direct singular rule<->action-group read is named
#     pmg_ruledb_rule_action_groups_list, NOT the sibling-symmetric pmg_ruledb_rule_action_list —
#     deliberately breaking naming symmetry with from_list/to_list/what_list/when_list to avoid a
#     real one-letter typo collision with the already-shipped, differently-shaped
#     pmg_ruledb_rule_actions_list (plural).
#   RULING 4 — ldapuser EXTENDS _WHO_OBJECT_TYPES/_who_object_body (done above in the existing
#     W5b section) rather than a separate code path — additive-compat proven by the untouched
#     pre-existing test suite.
#
# Taint: all 9 reads below are REVIEWED_TRUSTED. who/what-object content is operator-authored
# match criteria (email/domain/regex/ip/cidr/ldap-mode/account); when-object content is a pure
# H:i schedule; action-object content is operator-authored templates/targets (bcc target, header
# field/value, notification subject/body, disclaimer text, removeattachments replacement text);
# the rule<->action-group read returns bare [{id: int}], the same shape/trust level as the
# already-shipped from_list/to_list/what_list/when_list siblings. None of the 9 carry wire-learned
# or externally-authored bytes — none belong in taint.ADVERSARIAL_TOOLS (see
# tests/test_taint_classification_complete.py's Wave 8a block for the full per-tool citation).
#
# Every per-object GET response on this whole region is schema-thin: the apidoc types ONLY
# {id: <type>} in `returns.properties` for every family (who/what/when/action) — verified across
# the whole plane, not spot-checked. Live-verified 2026-07-17 (lab PMG 9.1): every family smoked
# (who/what/when/action bcc/field/disclaimer/notification/removeattachments) returned its full
# type-specific fields — the apidoc's {id}-only shape is under-documentation, not the true return
# shape. ldapuser excepted (no LDAP profile in the sealed lab — stays Smoke-confirm).
# ---------------------------------------------------------------------------


def who_object_get(api: PmgBackend, ogroup: str, type_: str, id_: str) -> dict:
    """Get a PMG RuleDB 'who' object's settings.

    GET /config/ruledb/who/{ogroup}/{type}/{id}

    Wave 8a, schema-verified path (ldapuser variant: Smoke-confirm — no LDAP profile in the
    sealed lab).
    ogroup: numeric ID string (e.g. '2') from who_groups_list response.
    type_: email|domain|regex|ip|network|ldap|ldapuser — controls the sub-path (7 values,
    ldapuser included).
    id_: object ID (numeric string) from who_group_objects response.
    Live-verified 2026-07-17 (lab PMG 9.1, email variant): returns the full object fields
    (keys=[descr,email,id,ogroup,otype,otype_text,receivertest]), richer than the apidoc's
    {id}-only declared shape.
    """
    ogroup = _check_ruledb_id(ogroup)
    type_ = _check_who_object_type(type_)
    id_ = _check_ruledb_id(id_)
    return api._get(f"/config/ruledb/who/{ogroup}/{type_}/{id_}") or {}


def what_object_get(api: PmgBackend, ogroup: str, type_: str, id_: str) -> dict:
    """Get a PMG RuleDB 'what' object's settings.

    GET /config/ruledb/what/{ogroup}/{type}/{id}

    Wave 8a, schema-verified path.
    ogroup: numeric ID string (e.g. '8') from what_groups_list response.
    type_: contenttype|matchfield|spamfilter|virusfilter|filenamefilter|archivefilter|
    archivefilenamefilter (7 values) — controls the sub-path.
    id_: object ID (numeric string) from what_group_objects response.
    Live-verified 2026-07-17 (lab PMG 9.1, contenttype variant): returns the full object fields
    (keys=[contenttype,descr,id,ogroup,only-content,otype,otype_text,receivertest]), richer than
    the apidoc's {id}-only declared shape.
    """
    ogroup = _check_ruledb_id(ogroup)
    type_ = _check_what_object_type(type_)
    id_ = _check_ruledb_id(id_)
    return api._get(f"/config/ruledb/what/{ogroup}/{type_}/{id_}") or {}


def when_object_get(api: PmgBackend, ogroup: str, id_: str) -> dict:
    """Get a PMG RuleDB 'when' (timeframe) object's settings.

    GET /config/ruledb/when/{ogroup}/timeframe/{id}

    Wave 8a, schema-verified path.
    ogroup: numeric ID string (e.g. '4') from when_groups_list response. Unlike who/what, 'when'
    has only ONE object type (timeframe) — no type_ param, mirrors the shipped when_object_add.
    id_: object ID (numeric string) from when_group_objects response.
    Live-verified 2026-07-17 (lab PMG 9.1): returns the full object fields
    (keys=[descr,end,id,ogroup,otype,otype_text,receivertest,start]), richer than the apidoc's
    {id}-only declared shape.
    """
    ogroup = _check_ruledb_id(ogroup)
    id_ = _check_ruledb_id(id_)
    return api._get(f"/config/ruledb/when/{ogroup}/timeframe/{id_}") or {}


def action_bcc_get(api: PmgBackend, id_: str) -> dict:
    """Get a PMG RuleDB BCC action object's settings.

    GET /config/ruledb/action/bcc/{id}

    Wave 8a, schema-verified path.
    id_: compound action object ID (e.g. '13_26', {ogroup}_{objid} format) from
    pmg_action_objects_list.
    Live-verified 2026-07-17 (lab PMG 9.1): returns the full object fields
    (keys=[descr,editable,id,info,name,ogroup,original,otype,otype_text,receivertest,target]),
    richer than the apidoc's {id}-only declared shape.
    """
    id_ = _check_action_object_id(id_)
    return api._get(f"/config/ruledb/action/bcc/{id_}") or {}


def action_field_get(api: PmgBackend, id_: str) -> dict:
    """Get a PMG RuleDB field-modification action object's settings.

    GET /config/ruledb/action/field/{id}

    Wave 8a, schema-verified path. Live-verified 2026-07-17 (lab PMG 9.1): returns the full
    type-specific object fields, richer than the apidoc's {id}-only declared shape (see
    action_bcc_get's docstring for the observed field list).
    id_: compound action object ID (e.g. '13_26', {ogroup}_{objid} format) from
    pmg_action_objects_list.
    """
    id_ = _check_action_object_id(id_)
    return api._get(f"/config/ruledb/action/field/{id_}") or {}


def action_notification_get(api: PmgBackend, id_: str) -> dict:
    """Get a PMG RuleDB notification action object's settings.

    GET /config/ruledb/action/notification/{id}

    Wave 8a, schema-verified path. Live-verified 2026-07-17 (lab PMG 9.1): returns the full
    type-specific object fields, richer than the apidoc's {id}-only declared shape (see
    action_bcc_get's docstring for the observed field list).
    id_: compound action object ID (e.g. '13_26', {ogroup}_{objid} format) from
    pmg_action_objects_list.
    """
    id_ = _check_action_object_id(id_)
    return api._get(f"/config/ruledb/action/notification/{id_}") or {}


def action_disclaimer_get(api: PmgBackend, id_: str) -> dict:
    """Get a PMG RuleDB disclaimer action object's settings.

    GET /config/ruledb/action/disclaimer/{id}

    Wave 8a, schema-verified path. Live-verified 2026-07-17 (lab PMG 9.1): returns the full
    type-specific object fields, richer than the apidoc's {id}-only declared shape (see
    action_bcc_get's docstring for the observed field list).
    id_: compound action object ID (e.g. '13_26', {ogroup}_{objid} format) from
    pmg_action_objects_list.
    """
    id_ = _check_action_object_id(id_)
    return api._get(f"/config/ruledb/action/disclaimer/{id_}") or {}


def action_removeattachments_get(api: PmgBackend, id_: str) -> dict:
    """Get a PMG RuleDB remove-attachments action object's settings.

    GET /config/ruledb/action/removeattachments/{id}

    Wave 8a, schema-verified path. Live-verified 2026-07-17 (lab PMG 9.1): returns the full
    type-specific object fields, richer than the apidoc's {id}-only declared shape (see
    action_bcc_get's docstring for the observed field list).
    id_: compound action object ID (e.g. '13_26', {ogroup}_{objid} format) from
    pmg_action_objects_list.
    """
    id_ = _check_action_object_id(id_)
    return api._get(f"/config/ruledb/action/removeattachments/{id_}") or {}


def ruledb_rule_action_groups_list(api: PmgBackend, id_: str) -> list[dict]:
    """List the action-group ids DIRECTLY attached to a PMG RuleDB rule (singular endpoint).

    GET /config/ruledb/rules/{id}/action

    Live-verified 2026-07-17 (lab PMG 9.1): the schema types the item shape as bare [{id: int}] —
    byte-for-byte the same shape as the already-shipped ruledb_rule_from_list/to_list/what_list/
    when_list siblings (all four schema-verified identical: {items: {properties: {id: {type:
    integer}}}, type: array}) — but the REAL response is richer: [{'info': '', 'name': ...,
    'id': ...}], id+name+info, not just id.

    NOT THE SAME as ruledb_rule_actions_list (plural name, shipped earlier): that function reads
    GET /config/ruledb/rules/{id}/config and extracts an embedded 'action' key. Live-verified
    2026-07-17: the embed IS present in the real response, and the two tools return identical
    lists for the same rule — no config-embed indirection risk, confirmed against a live rule
    with an attached action group (see that function's own corrected docstring).

    id_: rule ID (positive integer string, e.g. '100').
    """
    id_ = _check_ruledb_id(id_)
    return api._get(f"/config/ruledb/rules/{id_}/action") or []


def ruledb_reset(api: PmgBackend) -> object:
    """FACTORY RESET the entire PMG RuleDB.

    POST /config/ruledb

    MUTATION — confirm-gated + audited at the server layer. RISK_HIGH (see plan_ruledb_reset) —
    the only rating above MEDIUM this wave produces.

    Wave 8a, schema-verified path — not yet live-verified (Smoke-confirm). Wipes EVERY rule, every
    who/what/when object group, and every action object back to PMG factory defaults, in one call.
    Zero params accepted upstream (schema: parameters additionalProperties: 0, no properties key
    at all) — nothing to configure or scope. Returns None (schema: returns type null;
    synchronous — never "submitted"). `protected: 1`, admin-only permission.

    NO UNDO exists for this call: no staged/pending state to discard first (unlike SDN's
    rollback, which discards a bounded pending changeset — this resets the LIVE ruledb directly),
    no dry-run companion, no scoping parameter. Take pmg_backup_create first.
    """
    return api._post("/config/ruledb", data={})


def _ruledb_reset_capture_count(
    label: str, read: Callable[[], list],
) -> tuple[int | None, str | None]:
    """Best-effort trusted-plane capture helper for plan_ruledb_reset: returns (count, fail_note).

    Never raises — a capture-read failure degrades to an honest note rather than blocking the
    plan (the ceph.py _cmd_safety_note fail-open precedent: a plan must still render when PMG is
    partially unreachable). All five capture sources plan_ruledb_reset passes here are
    REVIEWED_TRUSTED reads already shipped on this plane (ruledb_rules_list / who/what/
    when_groups_list / action_objects_list) — the plain try/except capture path is used; no
    taint-marking machinery is needed (unlike ceph.py's capture_adversarial_current, reserved for
    ADVERSARIAL-classified capture sources).
    """
    try:
        return len(read() or []), None
    except Exception as e:  # noqa: BLE001 — deliberate: ANY capture-read failure degrades honestly
        return None, f"{label} count capture failed: {type(e).__name__}: {e}"


def plan_ruledb_reset(api: PmgBackend) -> Plan:
    """Preview a PMG RuleDB FACTORY RESET.  NOT pure — captures the current scope via 5
    best-effort trusted-plane reads (rules, who/what/when groups, action objects), each degrading
    to an honest note on failure rather than blocking the plan from rendering.

    RISK_HIGH — the wave's only rating above MEDIUM. The alternative to a governed Proximo tool
    is the SAME wipe via ungoverned GUI/pmgsh access with zero preview and zero audit trail; this
    plan renders the toll and states, as its FIRST blast_radius line, that Proximo has no undo for
    this call. Categorically no undo: no staged/pending state to discard (unlike SDN rollback), no
    dry-run companion, no scoping parameter accepted upstream (schema: additionalProperties: 0).
    """
    counts: dict[str, int | None] = {}
    fail_notes: list[str] = []
    for key, reader in (
        ("rules", lambda: ruledb_rules_list(api)),
        ("who_groups", lambda: who_groups_list(api)),
        ("what_groups", lambda: what_groups_list(api)),
        ("when_groups", lambda: when_groups_list(api)),
        ("action_objects", lambda: action_objects_list(api)),
    ):
        count, fail = _ruledb_reset_capture_count(key, reader)
        counts[key] = count
        if fail:
            fail_notes.append(fail)

    def _fmt(key: str) -> str:
        v = counts[key]
        return str(v) if v is not None else "an unknown number of"

    toll = (
        f"{_fmt('rules')} rules, {_fmt('who_groups')} who / {_fmt('what_groups')} what / "
        f"{_fmt('when_groups')} when groups, {_fmt('action_objects')} action objects "
        "will be reset to factory defaults"
    )
    blast = [
        "Proximo has NO undo for this; take pmg_backup_create first.",
        toll,
        *fail_notes,
    ]
    return Plan(
        action="pmg_ruledb_reset", target="pmg/config/ruledb",
        change=("factory-reset the ENTIRE PMG RuleDB "
                "(rules + who/what/when groups + action objects)"),
        current=counts, blast_radius=blast, risk=RISK_HIGH,
        risk_reasons=[
            "wipes the entire mail-filtering ruledb in one call — every rule, every "
            "who/what/when group, every action object",
            "no undo, no staged state, no scoping parameter accepted upstream",
        ],
        complete=not fail_notes,
    )


# ===========================================================================
# Wave 9c: LDAP profiles + fetchmail (full-surface campaign, 2026-07-17)
# ===========================================================================
# Schema truth: `.scratch/api-schemas-2026-07-15/pmg-apidoc-live-2026-07-17.json`,
# `/config/ldap[/{profile}[/config|/sync|/users[/{email}]|/groups[/{gid}]]]` and
# `/config/fetchmail[/{id}]` — all 15 methods read field-by-field for this build (the exact set
# classified `"chunk": "9c"` in `.scratch/sdd/wave-9-classification.json`), never assumed from the
# draft's prose alone. Extends pmg.py/tools/pmg_mail.py per campaign RULING 5 (both families are
# mail-plane: LDAP profiles feed the already-shipped `ldapuser` who-object type; fetchmail is a
# sibling mail-source config family) — NOT a new module.
#
# THE SECRET CONTRACT (this chunk's headline; binding per the wave-9 draft §5 + campaign doc):
#  - LDAP `bindpw`: `GET /config/ldap` (list) types a rich, closed item shape (comment/disable/
#    gcount/mcount/mode/profile/server1/server2/ucount) — `bindpw` is CONFIRMED ABSENT there, not
#    merely thin. `GET /config/ldap/{profile}/config` (single-profile) declares a bare
#    `returns: {}` — ZERO properties documented at all, i.e. genuinely schema-thin/unconfirmed
#    either way. Contract: never-in-ledger on write (create/update — both the mutation's ledger
#    detail AND any CAPTURE-then-plan display); DEFENSIVE read-strip on the single-profile GET
#    regardless of the schema's silence (the 5b/7c "strip even if schema says absent" discipline —
#    silence is not evidence of absence).
#  - Fetchmail `pass`: CONFIRMED ECHOED on BOTH `GET /config/fetchmail` (list) AND
#    `GET /config/fetchmail/{id}` (single) — both schemas explicitly type `pass` (maxLength 64).
#    This is NOT schema-thin — the secret is genuinely there. Contract: MANDATORY read-strip (not
#    merely defensive) on both reads; never-in-ledger on write.
#  - No OTHER secret-shaped field exists anywhere in this chunk's 15-method schema (checked
#    field-by-field): no token/key/cert/hmac field on ldap sync or fetchmail. `cafile` (LDAP,
#    create/update) is a filesystem PATH to a CA cert file, not a secret value itself — passed
#    through unredacted (a path/identifier, not a credential).
#
# Taint: LDAP profile CRUD/config/sync + fetchmail CRUD are operator-authored config —
# REVIEWED_TRUSTED (same channel as this file's other config-CRUD families). LDAP users/groups
# (`ldap_users_list`/`ldap_user_emails_get`/`ldap_groups_list`/`ldap_group_members_get`) return
# content PULLED FROM THE EXTERNAL LDAP DIRECTORY (account/dn/pmail/email/gid — literal directory
# entries, not anything PMG's own operator typed) — whoever controls that directory (or an entry
# within it) controls these bytes, the same "externally-authored content over an
# operator-configured channel" reasoning that landed `pbs_remote_scan`/`pve_ceph_metadata` in
# `taint.ADVERSARIAL_TOOLS` — ADVERSARIAL.
#
# digest: ONLY `PUT /config/ldap/{profile}/config` carries a `digest` param (maxLength 64, no
# pattern) among this chunk's 15 methods — schema-verified field-by-field; no other 9c method
# accepts one (create/sync/fetchmail create+update+delete all lack it) — forwarded where present,
# never invented elsewhere (the Wave 9a "don't invent a digest param" lesson).
#
# gid: `GET /config/ldap/{profile}/groups/{gid}` types `gid` as a bare JSON *number*
# (`typetext: <number>`), not this plane's usual string-id shape — accepted here as `int`, no
# invented bound (the LDAP directory's own opaque numeric group id).
#
# fetchmail_create's return: the live schema types it a plain STRING described exactly as
# "Unique ID" (pattern `[A-Za-z0-9]+`, maxLength 16) — NOT one of this campaign's ambiguous-string
# shapes (no UPID/status-message uncertainty here), so it is recorded like any other real create
# return (outcome="ok"), not outcome="submitted".

# --- Validators ---

_LDAP_PROFILE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}\Z")


def _check_ldap_profile(profile: str) -> str:
    # Do NOT strip — \Z must catch trailing newlines (this file's own established discipline).
    s = str(profile)
    if not _LDAP_PROFILE_RE.match(s):
        raise ProximoError(
            f"invalid LDAP profile id: {profile!r} "
            "(pve-configid format: alnum/./_/-, start with alnum/underscore, <=64 chars, "
            "no control chars)"
        )
    return s


_LDAP_MODES = frozenset({"ldap", "ldaps", "ldap+starttls"})


def _check_ldap_mode(mode: str) -> str:
    m = str(mode)
    if m not in _LDAP_MODES:
        raise ProximoError(f"invalid LDAP mode: {mode!r} (expected one of {sorted(_LDAP_MODES)})")
    return m


def _check_ldap_port(port) -> int:
    try:
        p = int(port)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid LDAP port: {port!r} (must be an integer)") from exc
    if not (1 <= p <= 65535):
        raise ProximoError(f"invalid LDAP port: {port!r} (must be 1-65535)")
    return p


def _check_ldap_server_address(value: str, label: str) -> str:
    """maxLength 256 — the schema's own bound on server1/server2 (format 'address'), not an
    invented one."""
    s = str(value)
    if len(s) > 256:
        raise ProximoError(f"invalid {label}: too long ({len(s)} chars, max 256)")
    return s


def _check_ldap_comment(value: str) -> str:
    """maxLength 4096 — the schema's own bound on LDAP profile comment."""
    s = str(value)
    if len(s) > 4096:
        raise ProximoError(f"invalid comment: too long ({len(s)} chars, max 4096)")
    return s


def _check_ldap_config_digest(digest: str | None) -> str | None:
    """maxLength 64, no pattern — the schema's own bound on PUT /config/ldap/{profile}/config's
    digest (a SEPARATE, narrower validator from pmg_node.py's own node-/config digest
    (maxLength 40) and pmg.py's APT-plane `_PMG_APT_DIGEST_RE` (maxLength 80) — this codebase's
    per-field digest-validator precedent, not a shared one)."""
    if digest is None:
        return None
    s = str(digest)
    if len(s) > 64:
        raise ProximoError(f"invalid digest: too long ({len(s)} chars, max 64)")
    return s


_EMAIL_RE = re.compile(r"^[^\s\\@]+@[^\s/\\@]+\Z")


def _check_email_address(value: str, label: str = "email") -> str:
    """Matches the live schema's own email pattern (LDAP user email / fetchmail target), copied
    verbatim in spirit: local part excludes whitespace/backslash/@, domain part additionally
    excludes slash. minLength 3 / maxLength 512 are the schema's own bounds."""
    s = str(value)
    if not (3 <= len(s) <= 512) or not _EMAIL_RE.match(s):
        raise ProximoError(
            f"invalid {label}: {value!r} (must match PMG's own email pattern, 3-512 chars)"
        )
    return s


def _check_ldap_gid(gid) -> int:
    """LDAP group id — schema types this a bare JSON number (fact above), the external
    directory's own opaque numeric group id. No invented bound."""
    try:
        return int(gid)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid LDAP group id: {gid!r} (must be an integer)") from exc


_FETCHMAIL_ID_RE = re.compile(r"^[A-Za-z0-9]{1,16}\Z")


def _check_fetchmail_id(id_: str) -> str:
    s = str(id_)
    if not _FETCHMAIL_ID_RE.match(s):
        raise ProximoError(f"invalid fetchmail id: {id_!r} (alphanumeric only, 1-16 chars)")
    return s


_FETCHMAIL_PROTOCOLS = frozenset({"pop3", "imap"})


def _check_fetchmail_protocol(protocol: str) -> str:
    p = str(protocol)
    if p not in _FETCHMAIL_PROTOCOLS:
        raise ProximoError(
            f"invalid fetchmail protocol: {protocol!r} "
            f"(expected one of {sorted(_FETCHMAIL_PROTOCOLS)})"
        )
    return p


def _check_fetchmail_port(port) -> int:
    try:
        p = int(port)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid fetchmail port: {port!r} (must be an integer)") from exc
    if not (1 <= p <= 65535):
        raise ProximoError(f"invalid fetchmail port: {port!r} (must be 1-65535)")
    return p


def _check_fetchmail_interval(interval) -> int:
    try:
        n = int(interval)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid fetchmail interval: {interval!r} (must be an integer)") from exc
    if not (1 <= n <= 2016):
        raise ProximoError(f"invalid fetchmail interval: {interval!r} (must be 1-2016)")
    return n


def _check_fetchmail_user(user: str) -> str:
    """maxLength 64, minLength 1 — the schema's own bound."""
    s = str(user)
    if not (1 <= len(s) <= 64):
        raise ProximoError(f"invalid fetchmail user: {user!r} (must be 1-64 chars)")
    return s


# Secret-shaped fields — THE SECRET CONTRACT (module section docstring above).
_LDAP_SECRET_KEYS = frozenset({"bindpw"})
_FETCHMAIL_SECRET_KEYS = frozenset({"pass"})


def _redact_ldap_secrets(d: dict) -> dict:
    """Mask `bindpw` before it enters a Plan/ledger surface — the shared
    `_validate.redact_secrets` mechanic over this family's own key set."""
    return redact_secrets(d, _LDAP_SECRET_KEYS)


def _strip_ldap_secrets_at_read(data: dict) -> dict:
    """Read-layer strip for `ldap_profile_config_get` — `bindpw` REMOVED entirely (not masked),
    mirroring `sdn_objects.py`'s `_strip_secrets_at_read`/`pbs_metrics.py`'s `influxdb_http_get`
    mechanism. Applied DEFENSIVELY here: the schema is bare (`returns: {}`, zero properties
    declared) so whether bindpw ever echoes is genuinely unconfirmed — silence is not evidence of
    absence (the Wave 5b lesson)."""
    return {k: v for k, v in data.items() if k not in _LDAP_SECRET_KEYS}


def _redact_fetchmail_secrets(d: dict) -> dict:
    """Mask `pass` before it enters a Plan/ledger surface — same idiom as `_redact_ldap_secrets`."""
    return redact_secrets(d, _FETCHMAIL_SECRET_KEYS)


def _strip_fetchmail_secrets_at_read(data: dict) -> dict:
    """Read-layer strip for `fetchmail_list`/`fetchmail_get` — `pass` REMOVED entirely. MANDATORY
    here (not merely defensive): both the live list AND single-item schemas explicitly type `pass`
    (maxLength 64) — a CONFIRMED, not hypothetical, leak path."""
    return {k: v for k, v in data.items() if k not in _FETCHMAIL_SECRET_KEYS}


# --- LDAP profile backend functions ---

def ldap_profiles_list(api: PmgBackend) -> list[dict]:
    """List configured LDAP profiles.

    GET /config/ldap

    Schema-rich item shape (comment/disable/gcount/mcount/mode/profile/server1/server2/ucount) —
    `bindpw` CONFIRMED ABSENT here, not merely thin. REVIEWED_TRUSTED (operator-authored config).
    Defensively strip bindpw from each item anyway (same mechanism as fetchmail_list), mirroring
    the read-layer strip on ldap_profile_config_get.
    """
    items = api._get("/config/ldap") or []
    return [_strip_ldap_secrets_at_read(i) if isinstance(i, dict) else i for i in items]


def ldap_profile_config_get(api: PmgBackend, profile: str) -> dict:
    """Read one LDAP profile's full configuration.

    GET /config/ldap/{profile}/config

    Schema declares a bare `returns: {}` — ZERO properties documented, genuinely thin/unconfirmed
    whether `bindpw` echoes back. DEFENSIVE read-strip applied regardless (silence is not evidence
    of absence). REVIEWED_TRUSTED (operator-authored config; the strip is a secret-handling
    concern, not a taint one).
    """
    profile = _check_ldap_profile(profile)
    data = api._get(f"/config/ldap/{profile}/config") or {}
    return _strip_ldap_secrets_at_read(data)


def _ldap_profile_field_kwargs(
    mode: str | None = None,
    port: int | None = None,
    basedn: str | None = None,
    binddn: str | None = None,
    bindpw: str | None = None,
    comment: str | None = None,
    filter: str | None = None,  # noqa: A002 — matches PMG's own param name (pbs_access.py precedent)
    groupbasedn: str | None = None,
    groupclass: str | None = None,
    mailattr: str | None = None,
    accountattr: str | None = None,
    cafile: str | None = None,
    verify: bool | None = None,
    server1: str | None = None,
    server2: str | None = None,
    disable: bool | None = None,
) -> dict:
    """Shared field-collection + validation for the LDAP profile create/update family — used by
    BOTH the backend functions (ldap_profile_create/ldap_profile_config_update) and the plan
    factories (plan_ldap_profile_create/plan_ldap_profile_config_update), so the same 16-field
    branching isn't hand-duplicated four times (and stays a single place to keep validators in
    sync — a code-quality/complexity extraction, not a behavior change)."""
    kw: dict = {}
    if mode is not None:
        kw["mode"] = _check_ldap_mode(mode)
    if port is not None:
        kw["port"] = _check_ldap_port(port)
    if basedn is not None:
        kw["basedn"] = basedn
    if binddn is not None:
        kw["binddn"] = binddn
    if bindpw is not None:
        kw["bindpw"] = bindpw
    if comment is not None:
        kw["comment"] = _check_ldap_comment(comment)
    if filter is not None:
        kw["filter"] = filter
    if groupbasedn is not None:
        kw["groupbasedn"] = groupbasedn
    if groupclass is not None:
        kw["groupclass"] = groupclass
    if mailattr is not None:
        kw["mailattr"] = mailattr
    if accountattr is not None:
        kw["accountattr"] = accountattr
    if cafile is not None:
        kw["cafile"] = cafile
    if verify is not None:
        kw["verify"] = bool(verify)
    if server1 is not None:
        kw["server1"] = _check_ldap_server_address(server1, "server1")
    if server2 is not None:
        kw["server2"] = _check_ldap_server_address(server2, "server2")
    if disable is not None:
        kw["disable"] = bool(disable)
    return kw


def ldap_profile_create(
    api: PmgBackend,
    profile: str,
    server1: str,
    mode: str | None = None,
    port: int | None = None,
    basedn: str | None = None,
    binddn: str | None = None,
    bindpw: str | None = None,
    comment: str | None = None,
    filter: str | None = None,  # noqa: A002 — matches PMG's own param name (pbs_access.py precedent)
    groupbasedn: str | None = None,
    groupclass: str | None = None,
    mailattr: str | None = None,
    accountattr: str | None = None,
    cafile: str | None = None,
    verify: bool | None = None,
    server2: str | None = None,
    disable: bool | None = None,
) -> object:
    """Add an LDAP profile.

    POST /config/ldap  body: {profile, server1, mode?, port?, basedn?, binddn?, bindpw?, ...}

    `server1` is the ONLY other schema-required field besides `profile` (maxLength 256, format
    'address'). `bindpw` is a SECRET — forwarded raw here (the create must actually work) but
    never recorded to the ledger — see plan_ldap_profile_create's redaction. `cafile` is a
    filesystem PATH to a CA cert, not a secret value itself.
    """
    profile = _check_ldap_profile(profile)
    server1 = _check_ldap_server_address(server1, "server1")
    data: dict = {
        "profile": profile, "server1": server1,
        **_ldap_profile_field_kwargs(
            mode=mode, port=port, basedn=basedn, binddn=binddn, bindpw=bindpw, comment=comment,
            filter=filter, groupbasedn=groupbasedn, groupclass=groupclass, mailattr=mailattr,
            accountattr=accountattr, cafile=cafile, verify=verify, server2=server2,
            disable=disable,
        ),
    }
    return api._post("/config/ldap", data)


def ldap_profile_delete(api: PmgBackend, profile: str) -> object:
    """Delete an LDAP profile.

    DELETE /config/ldap/{profile}
    """
    profile = _check_ldap_profile(profile)
    return api._delete(f"/config/ldap/{profile}")


def ldap_profile_config_update(
    api: PmgBackend,
    profile: str,
    mode: str | None = None,
    port: int | None = None,
    basedn: str | None = None,
    binddn: str | None = None,
    bindpw: str | None = None,
    comment: str | None = None,
    filter: str | None = None,  # noqa: A002
    groupbasedn: str | None = None,
    groupclass: str | None = None,
    mailattr: str | None = None,
    accountattr: str | None = None,
    cafile: str | None = None,
    verify: bool | None = None,
    server1: str | None = None,
    server2: str | None = None,
    disable: bool | None = None,
    delete: str | None = None,
    digest: str | None = None,
) -> object:
    """Update LDAP profile settings.

    PUT /config/ldap/{profile}/config  body: {..., delete?, digest?}

    Every field is optional on update (unlike create, where server1 is required). `digest`
    (maxLength 64, no pattern) is the ONE digest-bearing method in this chunk — schema-verified,
    forwarded where given, never invented elsewhere. `bindpw` is a SECRET — forwarded raw but
    never recorded to the ledger — see plan_ldap_profile_config_update's redaction.
    """
    profile = _check_ldap_profile(profile)
    data = _ldap_profile_field_kwargs(
        mode=mode, port=port, basedn=basedn, binddn=binddn, bindpw=bindpw, comment=comment,
        filter=filter, groupbasedn=groupbasedn, groupclass=groupclass, mailattr=mailattr,
        accountattr=accountattr, cafile=cafile, verify=verify, server1=server1, server2=server2,
        disable=disable,
    )
    if not data and not delete:
        raise ProximoError(
            "ldap_profile_config_update requires at least one field to set or delete"
        )
    if delete is not None:
        data["delete"] = delete
    digest = _check_ldap_config_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/config/ldap/{profile}/config", data)


def ldap_profile_sync(api: PmgBackend, profile: str) -> object:
    """Synchronize LDAP users to the local database.

    POST /config/ldap/{profile}/sync

    Pulls/overwrites the LOCAL cached LDAP user/group snapshot for this profile from the
    configured directory server(s). No params beyond `profile`; returns null.
    """
    profile = _check_ldap_profile(profile)
    return api._post(f"/config/ldap/{profile}/sync", data={})


def ldap_users_list(api: PmgBackend, profile: str) -> list[dict]:
    """List LDAP users cached for one profile.

    GET /config/ldap/{profile}/users

    ADVERSARIAL: `account`/`dn`/`pmail` are pulled directly from the external LDAP directory —
    whoever controls that directory (or an entry within it) controls these bytes, not PMG's own
    operator (the pbs_remote_scan/pve_ceph_metadata precedent).
    """
    profile = _check_ldap_profile(profile)
    return api._get(f"/config/ldap/{profile}/users") or []


def ldap_user_emails_get(api: PmgBackend, profile: str, email: str) -> list[dict]:
    """Get all email addresses for one LDAP user.

    GET /config/ldap/{profile}/users/{email}

    ADVERSARIAL: `email` values returned are directory-authored (same reasoning as
    ldap_users_list).
    """
    profile = _check_ldap_profile(profile)
    email = _check_email_address(email, "email")
    return api._get(f"/config/ldap/{profile}/users/{email}") or []


def ldap_groups_list(api: PmgBackend, profile: str) -> list[dict]:
    """List LDAP groups cached for one profile.

    GET /config/ldap/{profile}/groups

    ADVERSARIAL: `dn`/`gid` are directory-authored (same reasoning as ldap_users_list).
    """
    profile = _check_ldap_profile(profile)
    return api._get(f"/config/ldap/{profile}/groups") or []


def ldap_group_members_get(api: PmgBackend, profile: str, gid) -> list[dict]:
    """List one LDAP group's members.

    GET /config/ldap/{profile}/groups/{gid}

    `gid` is a bare JSON number on this schema (the directory's own opaque numeric group id), not
    this plane's usual string-id shape. ADVERSARIAL: `account`/`dn`/`pmail` are directory-authored
    (same reasoning as ldap_users_list).
    """
    profile = _check_ldap_profile(profile)
    gid = _check_ldap_gid(gid)
    return api._get(f"/config/ldap/{profile}/groups/{gid}") or []


# --- fetchmail backend functions ---

def fetchmail_list(api: PmgBackend) -> list[dict]:
    """List fetchmail users.

    GET /config/fetchmail

    `pass` CONFIRMED ECHOED on this endpoint's live schema (maxLength 64) — MANDATORY read-strip
    applied here (not merely defensive; the schema is rich, not thin).
    """
    items = api._get("/config/fetchmail") or []
    return [_strip_fetchmail_secrets_at_read(i) if isinstance(i, dict) else i for i in items]


def fetchmail_get(api: PmgBackend, id_: str) -> dict:
    """Read one fetchmail user's configuration.

    GET /config/fetchmail/{id}

    `pass` CONFIRMED ECHOED on this endpoint's live schema too — MANDATORY read-strip.
    """
    id_ = _check_fetchmail_id(id_)
    data = api._get(f"/config/fetchmail/{id_}") or {}
    return _strip_fetchmail_secrets_at_read(data)


def fetchmail_create(
    api: PmgBackend,
    server: str,
    user: str,
    password: str,
    target: str,
    protocol: str,
    enable: bool | None = None,
    interval: int | None = None,
    keep: bool | None = None,
    port: int | None = None,
    ssl: bool | None = None,
) -> object:
    """Create a fetchmail user configuration.

    POST /config/fetchmail  body: {server, user, pass, target, protocol, ...}  ->  the NEW entry's
    server-generated `id` (string, [A-Za-z0-9]+, <=16 chars) — NOT ambiguous (the schema explicitly
    documents "Unique ID"), recorded/returned like any other real return value, not an
    outcome="submitted" ambiguous-string case.

    `server`/`user`/`password`/`target`/`protocol` are SCHEMA-REQUIRED (none carries an `optional`
    flag). `password` (wire key `pass`) is a SECRET — forwarded raw here (the create must actually
    work) but never recorded to the ledger — see plan_fetchmail_create's redaction.
    """
    server = str(server)
    user = _check_fetchmail_user(user)
    target = _check_email_address(target, "target")
    protocol = _check_fetchmail_protocol(protocol)
    data: dict = {
        "server": server, "user": user, "pass": password,
        "target": target, "protocol": protocol,
    }
    if enable is not None:
        data["enable"] = bool(enable)
    if interval is not None:
        data["interval"] = _check_fetchmail_interval(interval)
    if keep is not None:
        data["keep"] = bool(keep)
    if port is not None:
        data["port"] = _check_fetchmail_port(port)
    if ssl is not None:
        data["ssl"] = bool(ssl)
    return api._post("/config/fetchmail", data)


def fetchmail_update(
    api: PmgBackend,
    id_: str,
    server: str | None = None,
    user: str | None = None,
    password: str | None = None,
    target: str | None = None,
    protocol: str | None = None,
    enable: bool | None = None,
    interval: int | None = None,
    keep: bool | None = None,
    port: int | None = None,
    ssl: bool | None = None,
) -> object:
    """Update a fetchmail user configuration.

    PUT /config/fetchmail/{id}

    Every field is optional on update (unlike create). `password` (wire key `pass`) is a SECRET —
    forwarded raw but never recorded to the ledger — see plan_fetchmail_update's redaction.
    """
    id_ = _check_fetchmail_id(id_)
    data: dict = {}
    if server is not None:
        data["server"] = str(server)
    if user is not None:
        data["user"] = _check_fetchmail_user(user)
    if password is not None:
        data["pass"] = password
    if target is not None:
        data["target"] = _check_email_address(target, "target")
    if protocol is not None:
        data["protocol"] = _check_fetchmail_protocol(protocol)
    if enable is not None:
        data["enable"] = bool(enable)
    if interval is not None:
        data["interval"] = _check_fetchmail_interval(interval)
    if keep is not None:
        data["keep"] = bool(keep)
    if port is not None:
        data["port"] = _check_fetchmail_port(port)
    if ssl is not None:
        data["ssl"] = bool(ssl)
    if not data:
        raise ProximoError("fetchmail_update requires at least one field to update")
    return api._put(f"/config/fetchmail/{id_}", data)


def fetchmail_delete(api: PmgBackend, id_: str) -> object:
    """Delete a fetchmail configuration entry.

    DELETE /config/fetchmail/{id}
    """
    id_ = _check_fetchmail_id(id_)
    return api._delete(f"/config/fetchmail/{id_}")


# --- Plan factories: LDAP ---

def plan_ldap_profile_create(
    profile: str,
    server1: str,
    mode: str | None = None,
    port: int | None = None,
    basedn: str | None = None,
    binddn: str | None = None,
    bindpw: str | None = None,
    comment: str | None = None,
    filter: str | None = None,  # noqa: A002
    groupbasedn: str | None = None,
    groupclass: str | None = None,
    mailattr: str | None = None,
    accountattr: str | None = None,
    cafile: str | None = None,
    verify: bool | None = None,
    server2: str | None = None,
    disable: bool | None = None,
) -> Plan:
    """Preview creating an LDAP profile. PURE (no CAPTURE — brand new profile, nothing to
    snapshot). Validates the same fields ldap_profile_create validates, so a bad value is rejected
    on the dry-run path too (the Wave 7c/9a discipline — don't defer validation to confirm=True).

    RISK_MEDIUM — a config that reaches into an external directory; the already-shipped `ldapuser`
    who-object type can match against users this profile pulls in once synced. SECRET CONTRACT:
    `bindpw` masked to '[redacted]' before entering the Plan.
    """
    profile = _check_ldap_profile(profile)
    server1 = _check_ldap_server_address(server1, "server1")
    kw: dict = {
        "profile": profile, "server1": server1,
        **_ldap_profile_field_kwargs(
            mode=mode, port=port, basedn=basedn, binddn=binddn, bindpw=bindpw, comment=comment,
            filter=filter, groupbasedn=groupbasedn, groupclass=groupclass, mailattr=mailattr,
            accountattr=accountattr, cafile=cafile, verify=verify, server2=server2,
            disable=disable,
        ),
    }
    return Plan(
        action="pmg_ldap_profile_create", target=f"config/ldap/{profile}",
        change=f"create LDAP profile {profile!r}: {_redact_ldap_secrets(kw)}",
        current={},
        blast_radius=[
            f"new LDAP directory profile {profile!r} pointed at {server1!r} — inert until "
            "pmg_ldap_profile_sync pulls users/groups, or a who-object of mode=ldapuser "
            "references this profile",
            "no directory content is pulled by this call alone",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["adds a new external-directory integration reachable by the mail filter"],
        note="bindpw is UNCONDITIONALLY redacted — only \"[redacted]\" appears in the plan and "
             "the audit ledger.",
    )


def plan_ldap_profile_delete(api: PmgBackend, profile: str) -> Plan:
    """Preview deleting an LDAP profile. CAPTURE: reads current profile config via
    ldap_profile_config_get (already bindpw-stripped at the read layer) and redacts it AGAIN
    defensively before it enters Plan.current (belt-and-suspenders, mirrors sdn_objects.py's own
    two-layer idiom). RISK_MEDIUM.
    """
    profile = _check_ldap_profile(profile)
    current: dict = {}
    read_failed = False
    try:
        current = _redact_ldap_secrets(ldap_profile_config_get(api, profile))
    except Exception:
        read_failed = True
    blast = [
        f"deletes LDAP profile {profile!r} — the directory connection config is gone",
        "who-objects of mode=ldapuser referencing this profile lose their directory source; "
        "referential-integrity effect is asserted BY ANALOGY only (this schema's own terse "
        "delete description does not state a refusal-on-reference behavior) — Smoke-confirm",
        "locally-cached users/groups synced from this profile are NOT automatically purged "
        "(no cascade-delete documented on this endpoint)",
        "no undo: re-create the profile with pmg_ldap_profile_create (bindpw must be "
        "re-supplied — it is never captured/displayed here)",
    ]
    if read_failed:
        blast.append("could not read the current LDAP profile config — prior value UNKNOWN")
    return Plan(
        action="pmg_ldap_profile_delete", target=f"config/ldap/{profile}",
        change=f"delete LDAP profile {profile!r}", current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["removes an external-directory integration the mail filter may rely on"],
        complete=not read_failed,
        note="bindpw (if present in current) is UNCONDITIONALLY redacted.",
    )


def plan_ldap_profile_config_update(
    api: PmgBackend,
    profile: str,
    mode: str | None = None,
    port: int | None = None,
    basedn: str | None = None,
    binddn: str | None = None,
    bindpw: str | None = None,
    comment: str | None = None,
    filter: str | None = None,  # noqa: A002
    groupbasedn: str | None = None,
    groupclass: str | None = None,
    mailattr: str | None = None,
    accountattr: str | None = None,
    cafile: str | None = None,
    verify: bool | None = None,
    server1: str | None = None,
    server2: str | None = None,
    disable: bool | None = None,
    delete: str | None = None,
) -> Plan:
    """Preview updating an LDAP profile's configuration. CAPTURE: reads current config via
    ldap_profile_config_get (already bindpw-stripped) and redacts it AGAIN defensively. A fresh
    bindpw passed as a NEW value here (not captured from a read) is masked the same way.
    Validates fields eagerly (the dry-run path rejects a bad value too). RISK_MEDIUM. No `digest`
    parameter here — mirrors pmg_node.py's plan_config_set (digest is an optimistic-concurrency
    lock relevant only at execution time, not to the preview).
    """
    profile = _check_ldap_profile(profile)
    kw = _ldap_profile_field_kwargs(
        mode=mode, port=port, basedn=basedn, binddn=binddn, bindpw=bindpw, comment=comment,
        filter=filter, groupbasedn=groupbasedn, groupclass=groupclass, mailattr=mailattr,
        accountattr=accountattr, cafile=cafile, verify=verify, server1=server1, server2=server2,
        disable=disable,
    )
    if not kw and not delete:
        raise ProximoError(
            "ldap_profile_config_update requires at least one field to set or delete"
        )
    current: dict = {}
    read_failed = False
    try:
        current = _redact_ldap_secrets(ldap_profile_config_get(api, profile))
    except Exception:
        read_failed = True
    parts = [f"{k}={v}" for k, v in sorted(_redact_ldap_secrets(kw).items())]
    if delete:
        parts.append(f"-{delete}")
    blast = [f"changes LDAP profile {profile!r}'s directory connection settings"]
    if "bindpw" in kw:
        blast.append("rotates the bind password used to authenticate to the directory server")
    if read_failed:
        blast.append("could not read current LDAP profile config — prior value UNKNOWN")
    return Plan(
        action="pmg_ldap_profile_config_update", target=f"config/ldap/{profile}/config",
        change=f"update LDAP profile {profile!r}: {', '.join(parts) or '(none)'}",
        current=current, blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["changes an external-directory integration's connection settings"],
        complete=not read_failed,
        note="bindpw is UNCONDITIONALLY redacted — only \"[redacted]\" appears in the plan and "
             "the audit ledger.",
    )


def plan_ldap_profile_sync(profile: str) -> Plan:
    """Preview synchronizing LDAP users to the local database. PURE — no CAPTURE: this endpoint
    triggers a directory pull, not a config change with a prior value to snapshot, and the honest
    count of affected local users/groups lives behind ADVERSARIAL-classified reads
    (ldap_users_list/ldap_groups_list) that plan factories on this plane deliberately do not call
    (mirrors sdn_objects.py's own ipam_status precedent: nothing here bypasses _audited() to read
    an ADVERSARIAL-classified source inside a plan factory). RISK_MEDIUM.
    """
    profile = _check_ldap_profile(profile)
    return Plan(
        action="pmg_ldap_profile_sync", target=f"config/ldap/{profile}/sync",
        change=f"synchronize LDAP users/groups for profile {profile!r} to the local database",
        current={},
        blast_radius=[
            f"overwrites the LOCAL cached user/group snapshot for LDAP profile {profile!r} with "
            "a fresh pull from the configured directory server(s)",
            "who-objects of mode=ldapuser referencing this profile may match differently after "
            "this runs (group membership changes on the directory side take effect locally)",
            "no dry-run companion; PMG exposes no 'preview sync' endpoint",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "pulls and overwrites the local LDAP user/group cache from an external directory"
        ],
        note="No CAPTURE — the affected-record count is not rendered here (it lives behind "
             "ADVERSARIAL-classified reads this plan factory deliberately does not call).",
    )


# --- Plan factories: fetchmail ---

def plan_fetchmail_create(
    server: str,
    user: str,
    password: str,
    target: str,
    protocol: str,
    enable: bool | None = None,
    interval: int | None = None,
    keep: bool | None = None,
    port: int | None = None,
    ssl: bool | None = None,
) -> Plan:
    """Preview creating a fetchmail account. PURE (no CAPTURE — the id is server-generated, there
    is no prior entry to snapshot). Validates the same fields fetchmail_create validates.

    RISK_MEDIUM — PMG will periodically log into a THIRD-PARTY mail account and pull mail into a
    local target address. SECRET CONTRACT: `password` (wire key `pass`) masked to '[redacted]'
    before entering the Plan.
    """
    server = str(server)
    user = _check_fetchmail_user(user)
    target = _check_email_address(target, "target")
    protocol = _check_fetchmail_protocol(protocol)
    kw: dict = {"server": server, "user": user, "pass": password, "target": target,
                "protocol": protocol}
    if enable is not None:
        kw["enable"] = bool(enable)
    if interval is not None:
        kw["interval"] = _check_fetchmail_interval(interval)
    if keep is not None:
        kw["keep"] = bool(keep)
    if port is not None:
        kw["port"] = _check_fetchmail_port(port)
    if ssl is not None:
        kw["ssl"] = bool(ssl)
    return Plan(
        action="pmg_fetchmail_create", target="config/fetchmail",
        change=f"create fetchmail account: {_redact_fetchmail_secrets(kw)}",
        current={},
        blast_radius=[
            f"new fetchmail poll of {user!r}@{server!r} ({protocol}) delivering into {target!r}",
            "PMG will periodically log into this THIRD-PARTY mailbox with the given credentials",
            "the assigned id is server-generated and returned by the mutation — the entry cannot "
            "be looked up before confirm=True runs",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["configures periodic authenticated polling of an external mail account"],
        note="pass is UNCONDITIONALLY redacted — only \"[redacted]\" appears in the plan and the "
             "audit ledger.",
    )


def plan_fetchmail_update(
    api: PmgBackend,
    id_: str,
    server: str | None = None,
    user: str | None = None,
    password: str | None = None,
    target: str | None = None,
    protocol: str | None = None,
    enable: bool | None = None,
    interval: int | None = None,
    keep: bool | None = None,
    port: int | None = None,
    ssl: bool | None = None,
) -> Plan:
    """Preview updating a fetchmail account. CAPTURE: reads current config via fetchmail_get
    (already pass-stripped at the read layer) and redacts it AGAIN defensively. A fresh password
    passed as a NEW value here is masked the same way. RISK_MEDIUM.
    """
    id_ = _check_fetchmail_id(id_)
    kw: dict = {}
    if server is not None:
        kw["server"] = str(server)
    if user is not None:
        kw["user"] = _check_fetchmail_user(user)
    if password is not None:
        kw["pass"] = password
    if target is not None:
        kw["target"] = _check_email_address(target, "target")
    if protocol is not None:
        kw["protocol"] = _check_fetchmail_protocol(protocol)
    if enable is not None:
        kw["enable"] = bool(enable)
    if interval is not None:
        kw["interval"] = _check_fetchmail_interval(interval)
    if keep is not None:
        kw["keep"] = bool(keep)
    if port is not None:
        kw["port"] = _check_fetchmail_port(port)
    if ssl is not None:
        kw["ssl"] = bool(ssl)
    if not kw:
        raise ProximoError("fetchmail_update requires at least one field to update")
    current: dict = {}
    read_failed = False
    try:
        current = _redact_fetchmail_secrets(fetchmail_get(api, id_))
    except Exception:
        read_failed = True
    parts = [f"{k}={v}" for k, v in sorted(_redact_fetchmail_secrets(kw).items())]
    blast = [f"changes fetchmail account {id_!r}'s poll configuration"]
    if "pass" in kw:
        blast.append("rotates the password used to authenticate to the remote mailbox")
    if read_failed:
        blast.append("could not read current fetchmail config — prior value UNKNOWN")
    return Plan(
        action="pmg_fetchmail_update", target=f"config/fetchmail/{id_}",
        change=f"update fetchmail account {id_!r}: {', '.join(parts)}",
        current=current, blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["changes periodic authenticated polling of an external mail account"],
        complete=not read_failed,
        note="pass is UNCONDITIONALLY redacted — only \"[redacted]\" appears in the plan and the "
             "audit ledger.",
    )


def plan_fetchmail_delete(api: PmgBackend, id_: str) -> Plan:
    """Preview deleting a fetchmail account. CAPTURE: reads current config via fetchmail_get
    (already pass-stripped) and redacts it AGAIN defensively before it enters Plan.current.
    RISK_MEDIUM.
    """
    id_ = _check_fetchmail_id(id_)
    current: dict = {}
    read_failed = False
    try:
        current = _redact_fetchmail_secrets(fetchmail_get(api, id_))
    except Exception:
        read_failed = True
    blast = [
        f"stops polling for fetchmail account {id_!r} — the remote mailbox is no longer checked",
        "mail already delivered to the local target stays; nothing already-fetched is undone",
        "no undo: re-create with pmg_fetchmail_create (the password must be re-supplied — it is "
        "never captured/displayed here)",
    ]
    if read_failed:
        blast.append("could not read current fetchmail config — prior value UNKNOWN")
    return Plan(
        action="pmg_fetchmail_delete", target=f"config/fetchmail/{id_}",
        change=f"delete fetchmail account {id_!r}", current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["removes a configured external-mail poll the target mailbox may rely on"],
        complete=not read_failed,
        note="pass (if present in current) is UNCONDITIONALLY redacted.",
    )


# ---------------------------------------------------------------------------
# Wave 9d — mail routing config remainder: domains/transport/mynetworks GET+PUT
# halves, tlspolicy, tls-inbound-domains, mimetypes, regextest. Extends
# pmg.py/tools/pmg_mail.py per campaign RULING 5 (same file as the already-shipped
# domain_create/transport_create/mynetworks_add). Exactly the 18 methods
# classified "chunk": "9d" in .scratch/sdd/wave-9-classification.json — no more,
# no fewer.
#
# Schema ground truth: .scratch/api-schemas-2026-07-15/pmg-apidoc-live-2026-07-17.json,
# re-walked per-method for this chunk (not carried from the draft's prose alone).
#
# Facts (binding, this chunk):
# 1. No secret-shaped field appears anywhere in this chunk's 18 schemas (checked every
#    param/return property name individually) — domains/transport/mynetworks/tlspolicy/
#    tls-inbound-domains/mimetypes/regextest carry no password/key/token/bindpw/pass-shaped
#    field at all. All 18 tools are REVIEWED_TRUSTED, no read-strip contract needed.
# 2. domain_update's `comment` and mynetworks_update's `comment` and tlspolicy_update's
#    `policy` are SCHEMA-REQUIRED (no `optional` flag in the live schema) — a genuine
#    full-replace, not a partial update; pass the current value back unchanged to leave it
#    alone. transport_update's fields (host/comment/port/protocol/use_mx) ARE all
#    `optional: 1` — a real partial update, hence the at-least-one-field guard there only.
# 3. Path-identity fields (domain/cidr/destination) are declared in the live schema's PUT
#    `parameters.properties` (an artifact of Proxmox's api-doc format listing every matched
#    route parameter, path or body) but are NEVER resent in the request body — matching the
#    established pmg_node.py `network_update` precedent (iface/node also appear in that
#    endpoint's schema properties and are also never resent). Only genuine body content
#    (comment/policy/host/port/protocol/use_mx) is sent.
# 4. GET /config/tls-inbound-domains is schema-typed as a bare array of STRINGS
#    (`items: {type: string}`), unlike every sibling LIST in this chunk (which return arrays
#    of dicts) — a real shape divergence, not an oversight; `tls_inbound_domains_list`
#    returns `list[str]`.
# 5. POST /config/regextest returns `type: number` (schema-confirmed) — Smoke-confirm
#    whether it's a boolean-shaped 0/1 or a match count; passed through unchanged, no shape
#    invented.
# 6. `regextest` is POST-verbed but a PURE EVALUATOR — no PMG state is read or written
#    (unlike `pbs_s3_check`, also POST/PUT-verbed-but-non-mutating, which stays confirm-gated
#    because IT makes a real outbound network call with side effects on the remote endpoint).
#    regextest has no side effect of any kind, so it is classified all the way to "plain read,
#    no PLAN/confirm ceremony" at the tool layer — audited like any other read, per the task
#    brief's own instruction to argue the verb-vs-effect call rather than default it.
# 7. `_check_tls_destination` is a NEW, permissive validator: the live schema documents
#    neither a maxLength nor a pattern for format 'transport-domain-or-nexthop' (unlike
#    domain/cidr, whose charsets are already schema-verified via _check_domain/_check_cidr).
#    A destination is either a plain domain or a Postfix-style next-hop (e.g.
#    '[relay.example.com]:587', 'relay.example.com:25') — bracket and colon are legitimate
#    content, so no character-class is invented beyond the structural path-segment guard
#    this file's other URL-path-segment validators already apply (mirrors
#    `_check_tracker_id`'s posture). Percent-encoded via `quote(..., safe="")` when used as a
#    URL path segment, matching `mynetworks_remove`'s own CIDR slash-encoding discipline.
# 8. TLS policy direction matters (this chunk's one direction-aware family): a weaker
#    `policy` value (e.g. 'none'/'may') DOWNGRADES TLS enforcement for a destination; a
#    stronger value (e.g. 'secure'/'verify'/'dane') TIGHTENS it. PMG's schema documents no
#    closed enum for this field (format 'tls-policy-strict' on write, 'tls-policy' on read),
#    so no specific value is validated beyond non-empty — the direction is called out in
#    blast_radius text instead, not enforced mechanically.
# ---------------------------------------------------------------------------

# --- Wave 9d validators ---

# Destination for tlspolicy: format 'transport-domain-or-nexthop' (fact #7 above). Reused for
# both GET/PUT/DELETE /config/tlspolicy/{destination} and the POST/PUT body field.
_TLS_DESTINATION_BAD = ("/", "\\", "?", "#", "%", "\x00", "\r", "\n", "\t", " ")


def _check_tls_destination(destination: str) -> str:
    s = str(destination)
    if not s or ".." in s or any(c in s for c in _TLS_DESTINATION_BAD):
        raise ProximoError(
            f"invalid destination: {destination!r} "
            "(non-empty, no '/', '\\', '..', '?', '#', '%', whitespace, or control chars)"
        )
    return s


def _check_regextest_field(value: str, label: str) -> str:
    """maxLength 1024 — the schema's own bound on POST /config/regextest's regex/text fields."""
    s = str(value)
    if len(s) > 1024:
        raise ProximoError(f"invalid {label}: too long ({len(s)} chars, max 1024)")
    return s


# --- Wave 9d READ operations ---

def domain_get(api: PmgBackend, domain: str) -> dict:
    """Read a managed mail domain's comment.

    GET /config/domains/{domain}

    Sibling single-item read of the already-shipped domains_list (the LIST form). Use
    domain_update to change the comment.
    """
    domain = _check_domain(domain)
    return api._get(f"/config/domains/{domain}") or {}


def transport_list(api: PmgBackend) -> list[dict]:
    """List mail transport map entries.

    GET /config/transport
    """
    return api._get("/config/transport") or []


def transport_get(api: PmgBackend, domain: str) -> dict:
    """Read a single mail transport map entry.

    GET /config/transport/{domain}
    """
    domain = _check_domain(domain)
    return api._get(f"/config/transport/{domain}") or {}


def mynetworks_list(api: PmgBackend) -> list[dict]:
    """List PMG mynetworks (trusted relay) entries.

    GET /config/mynetworks
    """
    return api._get("/config/mynetworks") or []


def mynetworks_get(api: PmgBackend, cidr: str) -> dict:
    """Read a single mynetworks entry's comment.

    GET /config/mynetworks/{cidr}  (cidr is URL-encoded: / -> %2F, matching mynetworks_remove)
    """
    cidr = _check_cidr(cidr)
    encoded = quote(cidr, safe="")
    return api._get(f"/config/mynetworks/{encoded}") or {}


def tlspolicy_list(api: PmgBackend) -> list[dict]:
    """List TLS policy entries (per-destination TLS enforcement overrides).

    GET /config/tlspolicy
    """
    return api._get("/config/tlspolicy") or []


def tlspolicy_get(api: PmgBackend, destination: str) -> dict:
    """Read a single TLS policy entry.

    GET /config/tlspolicy/{destination}  (destination is URL-encoded — next-hop syntax can
    carry '[' ']' ':' characters)
    """
    destination = _check_tls_destination(destination)
    encoded = quote(destination, safe="")
    return api._get(f"/config/tlspolicy/{encoded}") or {}


def tls_inbound_domains_list(api: PmgBackend) -> list[str]:
    """List domains for which TLS is enforced on INCOMING connections.

    GET /config/tls-inbound-domains

    Schema-confirmed: returns a bare array of domain-name strings (`items: {type: string}`),
    NOT an array of dicts — the one shape divergence from every sibling LIST in this chunk
    (fact #4 above).
    """
    return api._get("/config/tls-inbound-domains") or []


def mimetypes_list(api: PmgBackend) -> list[dict]:
    """Get PMG's built-in MIME type list.

    GET /config/mimetypes
    """
    return api._get("/config/mimetypes") or []


def regextest(api: PmgBackend, regex: str, text: str) -> float:
    """Test a regex (case-insensitive) against sample text, evaluated server-side by PMG.

    POST /config/regextest

    Classified by EFFECT, not verb (fact #6 above): a pure evaluator, no PMG state read or
    written, no outbound network call — carries no PLAN/confirm ceremony, just an audited call
    like any other read. regex/text: each capped at 1024 chars (the schema's own maxLength).
    Returns a bare number (schema-typed) — Smoke-confirm whether it is boolean-shaped (0/1) or
    a match count (fact #5); passed through unchanged, no shape invented.
    """
    regex = _check_regextest_field(regex, "regex")
    text = _check_regextest_field(text, "text")
    return api._post("/config/regextest", data={"regex": regex, "text": text})


# --- Wave 9d MUTATION operations — confirm-gated at the server layer ---

def domain_update(api: PmgBackend, domain: str, comment: str) -> object:
    """Update a managed mail domain's comment. Full replace — `comment` is SCHEMA-REQUIRED (no
    partial-update path for a domain's own comment, fact #2 above); pass "" to clear it.

    PUT /config/domains/{domain}

    MUTATION — confirm-gated + audited at the server layer.
    """
    domain = _check_domain(domain)
    return api._put(f"/config/domains/{domain}", data={"comment": str(comment)})


def transport_update(
    api: PmgBackend,
    domain: str,
    host: str | None = None,
    comment: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    use_mx: bool | None = None,
) -> object:
    """Update a mail transport rule. Partial update — every field but `domain` (the path
    identity) is optional (fact #2 above); at least one must be provided.

    PUT /config/transport/{domain}

    MUTATION — confirm-gated + audited at the server layer.
    """
    domain = _check_domain(domain)
    data: dict = {}
    if host is not None:
        data["host"] = host
    if comment is not None:
        data["comment"] = comment
    if port is not None:
        try:
            port_int = int(port)
        except (ValueError, TypeError) as exc:
            raise ProximoError(f"invalid port: {port!r} — must be an integer") from exc
        if not (1 <= port_int <= 65535):
            raise ProximoError(f"invalid port: {port!r} — must be an integer in 1-65535")
        data["port"] = port_int
    if protocol is not None:
        data["protocol"] = _check_transport_protocol(protocol)
    if use_mx is not None:
        data["use_mx"] = bool(use_mx)
    if not data:
        raise ProximoError("transport_update requires at least one field to update")
    return api._put(f"/config/transport/{domain}", data=data)


def mynetworks_update(api: PmgBackend, cidr: str, comment: str) -> object:
    """Update a mynetworks entry's comment. Full replace — `comment` is SCHEMA-REQUIRED (fact #2
    above); pass "" to clear it.

    PUT /config/mynetworks/{cidr}  (cidr is URL-encoded: / -> %2F, matching mynetworks_remove)

    MUTATION — confirm-gated + audited at the server layer.
    """
    cidr = _check_cidr(cidr)
    encoded = quote(cidr, safe="")
    return api._put(f"/config/mynetworks/{encoded}", data={"comment": str(comment)})


def tlspolicy_create(api: PmgBackend, destination: str, policy: str) -> object:
    """Add a TLS policy entry for a destination (domain or next-hop).

    POST /config/tlspolicy

    MUTATION — confirm-gated + audited at the server layer.
    DIRECTION MATTERS (fact #8 above): a weaker `policy` value (e.g. 'none'/'may') DOWNGRADES
    TLS enforcement to this destination; a stronger value (e.g. 'secure'/'verify'/'dane')
    TIGHTENS it. PMG's schema documents no closed enum for this field — no value is validated
    beyond non-empty here.
    """
    destination = _check_tls_destination(destination)
    policy = str(policy)
    if not policy:
        raise ProximoError("tlspolicy_create requires a non-empty policy value")
    return api._post("/config/tlspolicy", data={"destination": destination, "policy": policy})


def tlspolicy_update(api: PmgBackend, destination: str, policy: str) -> object:
    """Update a TLS policy entry's policy value. Full replace — `policy` is SCHEMA-REQUIRED
    (fact #2 above).

    PUT /config/tlspolicy/{destination}

    MUTATION — confirm-gated + audited at the server layer.
    DIRECTION MATTERS — see tlspolicy_create; changing an existing entry's policy can either
    tighten or loosen TLS enforcement for this destination depending on the new value.
    """
    destination = _check_tls_destination(destination)
    policy = str(policy)
    if not policy:
        raise ProximoError("tlspolicy_update requires a non-empty policy value")
    encoded = quote(destination, safe="")
    return api._put(f"/config/tlspolicy/{encoded}", data={"policy": policy})


def tlspolicy_delete(api: PmgBackend, destination: str) -> object:
    """Delete a TLS policy entry — the destination reverts to PMG's default TLS policy (this
    endpoint does not disclose what that default is).

    DELETE /config/tlspolicy/{destination}

    MUTATION — confirm-gated + audited at the server layer.
    """
    destination = _check_tls_destination(destination)
    encoded = quote(destination, safe="")
    return api._delete(f"/config/tlspolicy/{encoded}")


def tls_inbound_domains_create(api: PmgBackend, domain: str) -> object:
    """Add a domain to the TLS-inbound-enforced list (incoming connections delivering mail FOR
    this domain must use TLS).

    POST /config/tls-inbound-domains

    MUTATION — confirm-gated + audited at the server layer.
    """
    domain = _check_domain(domain)
    return api._post("/config/tls-inbound-domains", data={"domain": domain})


def tls_inbound_domains_delete(api: PmgBackend, domain: str) -> object:
    """Remove a domain from the TLS-inbound-enforced list — incoming mail for this domain is no
    longer required to arrive over TLS.

    DELETE /config/tls-inbound-domains/{domain}

    MUTATION — confirm-gated + audited at the server layer.
    """
    domain = _check_domain(domain)
    return api._delete(f"/config/tls-inbound-domains/{domain}")


# --- Wave 9d PLAN functions — pure factories; no mutation; the PLAN pillar ---

def plan_domain_update(domain: str, comment: str) -> Plan:
    """Preview updating a managed mail domain's comment.  PURE — no API call.

    RISK_LOW: cosmetic — comment has no effect on mail routing or filtering.
    """
    domain = _check_domain(domain)
    return Plan(
        action="pmg_domain_update",
        target=f"config/domains/{domain}",
        change=f"set domain {domain!r}'s comment to {comment!r}",
        current={},
        blast_radius=[
            f"replaces the comment stored with domain {domain!r}",
            "cosmetic only: does not affect mail routing, filtering, or the domain's active status",
        ],
        risk=RISK_LOW,
        risk_reasons=["LOW: comment-only field, no operational effect"],
        note="PMG 9.1 schema-verified path: PUT /config/domains/{domain}. comment is "
             "schema-required — this is a full replace, not a partial update.",
    )


def plan_transport_update(
    domain: str,
    host: str | None = None,
    comment: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    use_mx: bool | None = None,
) -> Plan:
    """Preview updating a mail transport rule.  PURE — no API call.
    Raises ProximoError if no fields are provided (all-None update is a no-op).

    RISK_MEDIUM: changing host/port/protocol/use_mx changes where mail for this domain is
    actually delivered, effective immediately; changing only `comment` is cosmetic — rated
    MEDIUM uniformly since a single call may combine both.
    """
    domain = _check_domain(domain)
    changes = {k: v for k, v in {
        "host": host, "comment": comment, "port": port, "protocol": protocol, "use_mx": use_mx,
    }.items() if v is not None}
    if not changes:
        raise ProximoError(
            "pmg_transport_update: at least one field must be provided (all values are None)"
        )
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    blast = [f"changes transport rule for domain {domain!r}: {change_summary}"]
    if {"host", "port", "protocol", "use_mx"} & set(changes):
        blast.append(
            f"mail for {domain!r} is rerouted / delivered differently immediately — verify the "
            "new host/port/protocol/use_mx before confirming"
        )
    if set(changes) == {"comment"}:
        blast.append("comment-only change: no effect on actual mail routing")
    return Plan(
        action="pmg_transport_update",
        target=f"config/transport/{domain}",
        change=f"update transport rule for domain {domain!r}: {change_summary}",
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["MEDIUM: can change where mail for this domain is actually delivered"],
        note="PMG 9.1 schema-verified path: PUT /config/transport/{domain}. All fields but "
             "domain are optional — a genuine partial update.",
    )


def plan_mynetworks_update(cidr: str, comment: str) -> Plan:
    """Preview updating a mynetworks entry's comment.  PURE — no API call.

    RISK_LOW: cosmetic — comment does not change which networks are trusted as relays.
    """
    cidr = _check_cidr(cidr)
    return Plan(
        action="pmg_mynetworks_update",
        target=f"config/mynetworks/{cidr}",
        change=f"set mynetworks entry {cidr!r}'s comment to {comment!r}",
        current={},
        blast_radius=[
            f"replaces the comment stored with mynetworks entry {cidr!r}",
            "cosmetic only: does not change relay-trust for this CIDR",
        ],
        risk=RISK_LOW,
        risk_reasons=["LOW: comment-only field, no operational effect"],
        note="PMG 9.1 schema-verified path: PUT /config/mynetworks/{cidr}. comment is "
             "schema-required — this is a full replace, not a partial update.",
    )


# Postfix's own known TLS-policy-map security levels (the vocabulary this tool family's
# docstrings already name; the live apidoc's `tls-policy`/`tls-policy-strict` formats carry no
# `enum` — there is no closed schema list to check against, so this is the honest ceiling: known
# tiers get classified, anything else gets an explicit "unrecognized" fallback, never a guess).
_TLS_POLICY_WEAK = frozenset({"none", "may"})
_TLS_POLICY_STRONG = frozenset({"encrypt", "dane", "dane-only", "fingerprint", "secure", "verify"})


def _tls_policy_direction_line(policy: str, destination: str) -> str:
    """Classify the actual `policy` value against Postfix's known TLS-level vocabulary and return
    ONE affirmative line naming the direction *this* value takes — never both directions recited
    as static disclaimer prose. Falls back to an honest "unrecognized" line rather than guessing
    when `policy` matches neither known tier."""
    if policy in _TLS_POLICY_WEAK:
        return (
            f"DOWNGRADES/does not enforce TLS for mail to {destination!r} — mail may be sent "
            "in the clear"
        )
    if policy in _TLS_POLICY_STRONG:
        return (
            f"ENFORCES/requires TLS for mail to {destination!r} — mail may be deferred/bounced "
            "if the destination cannot meet it"
        )
    return (
        f"{policy!r} is not a recognized TLS policy tier — verify the security direction "
        "yourself before confirming"
    )


def plan_tlspolicy_create(destination: str, policy: str) -> Plan:
    """Preview adding a TLS policy entry.  PURE — no API call.

    RISK_MEDIUM: changes TLS enforcement posture for one destination immediately.
    """
    destination = _check_tls_destination(destination)
    return Plan(
        action="pmg_tlspolicy_create",
        target="config/tlspolicy",
        change=f"add TLS policy for {destination!r}: policy={policy!r}",
        current={},
        blast_radius=[
            f"sets TLS enforcement policy {policy!r} for destination {destination!r}",
            _tls_policy_direction_line(policy, destination),
            "additive: does not affect any other destination's policy",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: changes real mail security posture for one destination; direction depends "
            "on the policy value — review it before confirming",
        ],
        note="PMG 9.1 schema-verified path: POST /config/tlspolicy.",
    )


def plan_tlspolicy_update(destination: str, policy: str) -> Plan:
    """Preview updating a TLS policy entry's policy value.  PURE — no API call.

    RISK_MEDIUM: same direction-aware reasoning as plan_tlspolicy_create. Unlike create, update
    is a pure factory with no capture of the destination's CURRENT policy (current={} always) —
    it states the RESULTING enforcement level this call sets, and explicitly does not claim a
    before/after delta it has no way to see.
    """
    destination = _check_tls_destination(destination)
    return Plan(
        action="pmg_tlspolicy_update",
        target=f"config/tlspolicy/{destination}",
        change=f"update TLS policy for {destination!r}: policy={policy!r}",
        current={},
        blast_radius=[
            f"replaces the TLS enforcement policy for destination {destination!r} with "
            f"{policy!r}",
            _tls_policy_direction_line(policy, destination),
            "this preview does not capture the destination's PRIOR policy value (PURE, no "
            "read) — the line above states the RESULTING enforcement level only, not a "
            "before/after delta",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: changes real mail security posture for one destination; direction depends "
            "on the new policy value",
        ],
        note="PMG 9.1 schema-verified path: PUT /config/tlspolicy/{destination}. policy is "
             "schema-required — a full replace.",
    )


def plan_tlspolicy_delete(destination: str) -> Plan:
    """Preview deleting a TLS policy entry.  PURE — no API call.

    RISK_MEDIUM: removes an explicit override; the destination falls back to PMG's default TLS
    policy (this endpoint does not disclose what that default is).
    """
    destination = _check_tls_destination(destination)
    return Plan(
        action="pmg_tlspolicy_delete",
        target=f"config/tlspolicy/{destination}",
        change=f"delete TLS policy entry for {destination!r}",
        current={},
        blast_radius=[
            f"removes the explicit TLS policy override for {destination!r}",
            "the destination falls back to PMG's default TLS policy — verify what that default "
            "enforces before confirming, especially if the override was tightening security",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: removes an explicit security-posture override; fallback behavior is not "
            "disclosed by this endpoint",
        ],
        note="PMG 9.1 schema-verified path: DELETE /config/tlspolicy/{destination}.",
    )


def plan_tls_inbound_domains_create(domain: str) -> Plan:
    """Preview adding a domain to the TLS-inbound-enforced list.  PURE — no API call.

    RISK_LOW: additive — tightens security for incoming mail addressed to this domain.
    """
    domain = _check_domain(domain)
    return Plan(
        action="pmg_tls_inbound_domains_create",
        target="config/tls-inbound-domains",
        change=f"require TLS on incoming connections for domain {domain!r}",
        current={},
        blast_radius=[
            f"incoming SMTP connections delivering mail for {domain!r} must now use TLS",
            "senders that cannot negotiate TLS will be deferred/bounced delivering to this "
            "domain — a real availability tradeoff for a security tightening",
            "additive: does not affect enforcement for any other domain",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "LOW: tightens security (the safe direction); the deferred-mail tradeoff is the "
            "operator's own explicit choice",
        ],
        note="PMG 9.1 schema-verified path: POST /config/tls-inbound-domains.",
    )


def plan_tls_inbound_domains_delete(domain: str) -> Plan:
    """Preview removing a domain from the TLS-inbound-enforced list.  PURE — no API call.

    RISK_LOW mechanically (a config-list removal, easily reversed with
    pmg_tls_inbound_domains_create) — but this is the security-LOOSENING direction, not the
    tightening one (direction-aware per fact #8's convention, extended to this sibling family).
    """
    domain = _check_domain(domain)
    return Plan(
        action="pmg_tls_inbound_domains_delete",
        target=f"config/tls-inbound-domains/{domain}",
        change=f"stop requiring TLS on incoming connections for domain {domain!r}",
        current={},
        blast_radius=[
            f"incoming SMTP connections delivering mail for {domain!r} are no longer required "
            "to use TLS — mail may arrive in the clear afterward",
            "this LOOSENS security for this domain — confirm this is intentional",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "LOW by mechanical consequence (easily reversed), but flagged: this is the "
            "security-LOOSENING direction, not the tightening one",
        ],
        note="PMG 9.1 schema-verified path: DELETE /config/tls-inbound-domains/{domain}.",
    )


# ---------------------------------------------------------------------------
# Wave 9e — DKIM + customscores. Extends pmg.py per campaign RULING 5 (same file as the
# already-shipped domains/transport/tlspolicy families — Wave 9d). Exactly the 15 methods
# classified "chunk": "9e" in .scratch/sdd/wave-9-classification.json — no more, no fewer.
#
# Schema ground truth: .scratch/api-schemas-2026-07-15/pmg-apidoc-live-2026-07-17.json,
# re-walked per-method for this chunk (not carried from the task brief's prose alone).
#
# Facts (binding, this chunk):
# 1. NO secret-shaped field appears anywhere in this chunk's 15 schemas (checked every
#    param/return property individually — this is the task brief's own instruction, verified
#    rather than assumed). DKIM's private signing key is GENERATED SERVER-SIDE by
#    POST /config/dkim/selector and NEVER appears in ANY read response: GET
#    /config/dkim/selector types only {keysize, record, selector} — `record` is the PUBLIC key
#    rendered as a DNS TXT record (schema format 'pmg-dkim-record'). There is no "upload a
#    private key" endpoint anywhere in this family — this is the task brief's first branch
#    exactly ("no secret param at all on the write"). The DNS TXT record is PUBLIC BY DESIGN (it
#    exists so mail recipients can verify signatures) — it is not redacted anywhere in this
#    chunk; inventing a redaction contract for it would misrepresent public DNS content as a
#    secret. `digest` (customscores only) is an optimistic-concurrency token, not a secret
#    (matches the already-shipped LDAP-config/node-config `digest` precedent).
# 2. `digest` support (customscores only — §3 Fact 9 of the wave draft): create_score (POST),
#    edit_score (PUT .../{name}), delete_score (DELETE .../{name}), and apply_score_changes
#    (bulk PUT, bare) all carry an optional `digest` (maxLength 64) — forwarded when given, never
#    invented. `revert_score_changes` (bulk DELETE, bare) carries NO digest param
#    (schema-verified: its `parameters` is bare `{additionalProperties: 0}`) — none added here.
#    Mirrors pmg_node.py's own plan_config_set precedent: PLAN factories in this chunk take NO
#    `digest` parameter at all (it is an optimistic-concurrency lock relevant only at execution
#    time, never to the preview) — only the wire functions and tool wrappers accept it.
# 3. DKIM `domain` uses the SAME schema format ('transport-domain') as the already-shipped
#    pmg_domain_* family — reuses `_check_domain` rather than inventing a near-duplicate
#    validator. DKIM `selector` uses format 'dns-name' — the same DNS-label charset
#    `_check_domain` already enforces (including underscore-led labels) — reused for the same
#    reason. Neither field is ever used as a URL path segment in this chunk (bare
#    `/config/dkim/selector`, no `{selector}` in any path here), so no percent-encoding is
#    needed for `selector`; `domain` IS a path segment for the `/config/dkim/domains/{domain}`
#    family, matching `_check_domain`'s existing path-segment-safety guarantee.
# 4. `customscores` `name` is schema-pattern-anchored (`[a-zA-Z_\-.0-9]+`, NO maxLength stated)
#    — a new validator enforces exactly this pattern, nothing more (no invented length cap where
#    the schema states none, matching the `_check_tls_destination` "don't invent beyond the
#    schema" discipline).
# 5. `POST /config/dkim/selector`'s own description states plainly: "Generate a new private key
#    for selector. All future mail will be signed with the new key!" — a genuine
#    mail-continuity risk (existing DKIM-aligned mail flows can fail alignment until the new DNS
#    TXT record propagates and any external DNS is updated), not a data-destructive one. Rated
#    RISK_MEDIUM: this is the SAME shape as the already-shipped, already-reviewed
#    `ldap_profile_config_update`/`fetchmail_update` "rotates a credential/key the mail pipeline
#    depends on" MEDIUM precedent (bindpw rotation, fetchmail password rotation) — a rotation of
#    security-relevant material with a continuity cost, not a HIGH-class data-destruction/
#    irreversible-authority-change event. `force` (optional) is PMG's own protective gate against
#    silently clobbering an existing key (asserted from the description's own wording "Overwrite
#    existing key," not independently proven — Smoke-confirm the actual refusal behavior).
# 6. `PUT /config/customscores` (apply_score_changes, bulk) returns `type: string`
#    (Smoke-confirm: UPID or plain status string — unresolved from schema alone, mirrors
#    `pmg_node_network_reload`'s identical ambiguity) — confirm=True records outcome="submitted"
#    with the raw string in both the response envelope and the ledger's own detail.raw_result,
#    per the established idiom. Every OTHER mutation in this chunk returns `type: null`
#    (schema-confirmed) — sync, outcome="ok".
# 7. `DELETE /config/customscores` (revert_score_changes, bulk, bare) reverts ALL custom score
#    changes at once — a step above the per-item delete; the plan states this plainly. No
#    per-item CAPTURE is possible here or for `customscores_apply` — PMG's own schema gives no
#    "list of what would revert/apply" companion read (mirrors `plan_ldap_profile_sync`'s own
#    "nothing capturable" reasoning).
# 8. Direction-aware text (9d lesson: classify the ACTUAL value passed, never recite both
#    directions statically): `customscores_create` classifies the score's own SIGN (positive =
#    toward spam, negative = toward ham/whitelisting, zero = neutral) — no history needed for a
#    brand-new assignment. `customscores_update` CAPTURES the prior score (no secret involved,
#    safe to read) and states whether the new value RAISES or LOWERS it — a real before/after
#    delta, not just a resulting-value guess (the task brief's own instruction: "raising a score
#    toward spam vs lowering toward ham" is only knowable relative to the PRIOR value).
# ---------------------------------------------------------------------------

# --- Wave 9e validators ---

# customscores rule name: schema-pattern-anchored, NO maxLength stated (fact #4 above) — used as
# a URL path segment for GET/PUT/DELETE .../{name}, so the pattern itself already excludes '/'.
_CUSTOMSCORE_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+\Z")


def _check_customscore_name(name: str) -> str:
    s = str(name)
    if not _CUSTOMSCORE_NAME_RE.match(s):
        raise ProximoError(
            f"invalid custom score name: {name!r} "
            "(schema pattern: letters, digits, '_', '-', '.' only, at least 1 char)"
        )
    return s


def _check_customscores_digest(digest: str | None) -> str | None:
    """maxLength 64 (schema) — a SEPARATE, narrower validator from `_check_ldap_config_digest`
    (per-field digest-validator precedent, not a shared one — pmg.py's own Wave 9c note)."""
    if digest is None:
        return None
    s = str(digest)
    if len(s) > 64:
        raise ProximoError(f"invalid digest: too long ({len(s)} chars, max 64)")
    return s


def _check_customscore_score(score) -> float:
    """schema type 'number' — no min/max stated. Accepts int or float input, always returns
    float so callers get a consistent type for direction/sign comparisons."""
    try:
        return float(score)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid score: {score!r} — must be a number") from exc


def _check_dkim_keysize(keysize) -> int:
    """schema minimum 1024, no maximum stated ('1024 - N')."""
    try:
        k = int(keysize)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid keysize: {keysize!r} — must be an integer") from exc
    if k < 1024:
        raise ProximoError(f"invalid keysize: {k} — must be >= 1024 (schema minimum)")
    return k


def _customscore_sign_line(score: float) -> str:
    """Classify a BRAND-NEW score assignment by its own sign — no prior value exists to diff
    against, so this states the resulting classification effect directly (fact #8 above)."""
    if score > 0:
        return f"a positive score ({score!r}) marks matching mail MORE spam-like"
    if score < 0:
        return f"a negative score ({score!r}) marks matching mail LESS spam-like (a whitelisting effect)"
    return "a score of 0 is neutral — no effect on spam classification"


def _customscore_delta_line(old_score: float, new_score: float) -> str:
    """Classify an EXISTING score's change by comparing old vs new — a real before/after delta,
    not a resulting-value guess (fact #8 above)."""
    if new_score > old_score:
        return (
            f"RAISES the score from {old_score!r} to {new_score!r} — toward spam "
            "(matching mail scored MORE spam-like)"
        )
    if new_score < old_score:
        return (
            f"LOWERS the score from {old_score!r} to {new_score!r} — toward ham "
            "(matching mail scored LESS spam-like)"
        )
    return f"leaves the score unchanged at {new_score!r}"


# --- Wave 9e READ operations ---

def dkim_domains_list(api: PmgBackend) -> list[dict]:
    """List DKIM-sign domains.

    GET /config/dkim/domains
    """
    return api._get("/config/dkim/domains") or []


def dkim_domain_get(api: PmgBackend, domain: str) -> dict:
    """Read a DKIM-sign domain's comment.

    GET /config/dkim/domains/{domain}
    """
    domain = _check_domain(domain)
    return api._get(f"/config/dkim/domains/{domain}") or {}


def dkim_selector_get(api: PmgBackend) -> dict:
    """Get the PUBLIC key for the configured DKIM selector, rendered as a DNS TXT record.

    GET /config/dkim/selector

    Returns {"keysize": ..., "record": ..., "selector": ...} — schema-confirmed: the PRIVATE
    signing key NEVER appears here (fact #1 above). `record` is meant to be published in DNS —
    it is public BY DESIGN, not redacted.
    """
    return api._get("/config/dkim/selector") or {}


def dkim_selectors_list(api: PmgBackend) -> list[dict]:
    """Get a list of all existing DKIM selectors.

    GET /config/dkim/selectors
    """
    return api._get("/config/dkim/selectors") or []


def customscores_list(api: PmgBackend) -> list[dict]:
    """List custom SpamAssassin scores.

    GET /config/customscores
    """
    return api._get("/config/customscores") or []


def customscores_get(api: PmgBackend, name: str) -> dict:
    """Get a single custom SpamAssassin score.

    GET /config/customscores/{name}
    """
    name = _check_customscore_name(name)
    return api._get(f"/config/customscores/{name}") or {}


# --- Wave 9e MUTATION operations — confirm-gated at the server layer ---

def dkim_domain_create(api: PmgBackend, domain: str, comment: str | None = None) -> object:
    """Add a DKIM-sign domain.

    POST /config/dkim/domains

    MUTATION — confirm-gated + audited at the server layer.
    """
    domain = _check_domain(domain)
    data: dict = {"domain": domain}
    if comment is not None:
        data["comment"] = str(comment)
    return api._post("/config/dkim/domains", data=data)


def dkim_domain_update(api: PmgBackend, domain: str, comment: str) -> object:
    """Update a DKIM-sign domain's comment. Full replace — `comment` is SCHEMA-REQUIRED.

    PUT /config/dkim/domains/{domain}

    MUTATION — confirm-gated + audited at the server layer. `domain` is path-identity — never
    resent in the body (matches the already-shipped pmg_node.py network_update /
    pmg_domain_update precedent).
    """
    domain = _check_domain(domain)
    return api._put(f"/config/dkim/domains/{domain}", data={"comment": str(comment)})


def dkim_domain_delete(api: PmgBackend, domain: str) -> object:
    """Delete a DKIM-sign domain.

    DELETE /config/dkim/domains/{domain}

    MUTATION — confirm-gated + audited at the server layer.
    """
    domain = _check_domain(domain)
    return api._delete(f"/config/dkim/domains/{domain}")


def dkim_selector_generate(
    api: PmgBackend, selector: str, keysize: int, force: bool | None = None,
) -> object:
    """Generate a new DKIM private key for a selector. PMG's own description: "All future mail
    will be signed with the new key!" (fact #5 above).

    POST /config/dkim/selector

    MUTATION — confirm-gated + audited at the server layer. `selector` uses format 'dns-name' —
    validated with `_check_domain` (fact #3 above; NOT a URL path segment here).
    """
    selector = _check_domain(selector)
    keysize = _check_dkim_keysize(keysize)
    data: dict = {"selector": selector, "keysize": keysize}
    if force is not None:
        data["force"] = bool(force)
    return api._post("/config/dkim/selector", data=data)


def customscores_create(
    api: PmgBackend,
    name: str,
    score,
    comment: str | None = None,
    digest: str | None = None,
) -> object:
    """Create a custom SpamAssassin score.

    POST /config/customscores

    MUTATION — confirm-gated + audited at the server layer. `digest` (optimistic-concurrency,
    optional, maxLength 64) is forwarded when given, never invented (fact #2 above).
    """
    name = _check_customscore_name(name)
    score = _check_customscore_score(score)
    data: dict = {"name": name, "score": score}
    if comment is not None:
        data["comment"] = str(comment)
    digest = _check_customscores_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._post("/config/customscores", data=data)


def customscores_update(
    api: PmgBackend,
    name: str,
    score,
    comment: str | None = None,
    digest: str | None = None,
) -> object:
    """Edit a custom SpamAssassin score. Full replace — `score` is SCHEMA-REQUIRED.

    PUT /config/customscores/{name}

    MUTATION — confirm-gated + audited at the server layer. `name` is path-identity — never
    resent in the body.
    """
    name = _check_customscore_name(name)
    score = _check_customscore_score(score)
    data: dict = {"score": score}
    if comment is not None:
        data["comment"] = str(comment)
    digest = _check_customscores_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/config/customscores/{name}", data=data)


def customscores_delete(api: PmgBackend, name: str, digest: str | None = None) -> object:
    """Delete a custom SpamAssassin score.

    DELETE /config/customscores/{name}

    MUTATION — confirm-gated + audited at the server layer. `digest`, if given, is forwarded as
    a query parameter (matches the already-shipped `quarantine_blocklist_remove` DELETE-with-
    query-params precedent — DELETE carries no body in this codebase's PmgBackend).
    """
    name = _check_customscore_name(name)
    digest = _check_customscores_digest(digest)
    params: dict = {}
    if digest is not None:
        params["digest"] = digest
    return api._delete(f"/config/customscores/{name}", params=params or None)


def customscores_revert_all(api: PmgBackend) -> object:
    """Revert ALL custom SpamAssassin score changes at once — a step above the per-item delete
    (fact #7 above).

    DELETE /config/customscores

    MUTATION — confirm-gated + audited at the server layer. No `digest` param (schema-verified:
    bare `parameters`) — not invented here.
    """
    return api._delete("/config/customscores")


def customscores_apply(
    api: PmgBackend, digest: str | None = None, restart_daemon: bool | None = None,
) -> object:
    """Apply staged custom SpamAssassin score changes.

    PUT /config/customscores

    MUTATION — confirm-gated + audited at the server layer. Returns a STRING (schema-confirmed,
    fact #6 above) — Smoke-confirm whether it's a UPID or a plain status message; passed through
    unchanged, no shape invented. `restart-daemon`, if set, ALSO restarts pmg-smtp-filter — per
    PMG's own description, "necessary for the changes to work."
    """
    data: dict = {}
    digest = _check_customscores_digest(digest)
    if digest is not None:
        data["digest"] = digest
    if restart_daemon is not None:
        data["restart-daemon"] = bool(restart_daemon)
    return api._put("/config/customscores", data=data)


# --- Wave 9e PLAN functions — pure factories; no mutation; the PLAN pillar ---
# No `digest` parameter on ANY plan factory below (fact #2 above): it is an optimistic-
# concurrency lock relevant only at execution time, never to the preview — mirrors
# `plan_ldap_profile_config_update`'s own documented reasoning exactly.

def plan_dkim_domain_create(domain: str, comment: str | None = None) -> Plan:
    """Preview adding a DKIM-sign domain.  PURE — no API call.

    RISK_LOW: additive — DKIM signing does not begin for a domain here until the operator's own
    mail-flow configuration routes it there and a selector/key exist (fact #1 — the private key
    is a separate, server-generated resource this call does not touch).
    """
    domain = _check_domain(domain)
    return Plan(
        action="pmg_dkim_domain_create",
        target="config/dkim/domains",
        change=f"add DKIM-sign domain {domain!r}" + (f", comment={comment!r}" if comment else ""),
        current={},
        blast_radius=[
            f"registers {domain!r} as a DKIM-sign domain",
            "additive: does not affect any other domain's DKIM configuration",
        ],
        risk=RISK_LOW,
        risk_reasons=["LOW: additive registration, no signing occurs without a configured selector/key"],
        note="PMG 9.1 schema-verified path: POST /config/dkim/domains.",
    )


def plan_dkim_domain_update(domain: str, comment: str) -> Plan:
    """Preview updating a DKIM-sign domain's comment.  PURE — no API call (mirrors
    plan_domain_update's own "cosmetic, no capture" precedent for the sibling /config/domains
    family).

    RISK_LOW: cosmetic — does not affect whether/how mail for this domain is DKIM-signed.
    """
    domain = _check_domain(domain)
    return Plan(
        action="pmg_dkim_domain_update",
        target=f"config/dkim/domains/{domain}",
        change=f"set DKIM domain {domain!r}'s comment to {comment!r}",
        current={},
        blast_radius=[
            f"replaces the comment stored with DKIM domain {domain!r}",
            "cosmetic only: does not affect whether/how mail for this domain is DKIM-signed",
        ],
        risk=RISK_LOW,
        risk_reasons=["LOW: comment-only field, no operational effect"],
        note="PMG 9.1 schema-verified path: PUT /config/dkim/domains/{domain}. comment is "
             "schema-required — this is a full replace, not a partial update.",
    )


def plan_dkim_domain_delete(domain: str) -> Plan:
    """Preview deleting a DKIM-sign domain.  PURE — no API call (mirrors plan_domain_delete's own
    precedent for the sibling /config/domains family — a real deletion, not a cosmetic change).

    RISK_MEDIUM: removes DKIM signing configuration for this domain; outbound mail from that
    domain stops being DKIM-signed until reconfigured — matches the
    plan_customscores_delete/plan_tlspolicy_delete/plan_domain_delete "removes a live
    configuration → real operational effect, no undo" MEDIUM precedent.
    """
    domain = _check_domain(domain)
    return Plan(
        action="pmg_dkim_domain_delete",
        target=f"config/dkim/domains/{domain}",
        change=f"delete DKIM-sign domain {domain!r}",
        current={},
        blast_radius=[
            f"removes {domain!r} from the DKIM-sign domain list — outbound mail for this domain "
            "is no longer DKIM-signed by PMG afterward",
            "the shared selector/key (if any) is NOT deleted — only this domain's registration",
            "no undo: re-add with pmg_dkim_domain_create",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: removes DKIM signing configuration for this domain — outbound mail from "
            "this domain stops being DKIM-signed until reconfigured, a sender-authentication "
            "regression, not merely a cosmetic/reversible config change",
        ],
        note="PMG 9.1 schema-verified path: DELETE /config/dkim/domains/{domain}.",
    )


def plan_dkim_selector_generate(
    api: PmgBackend, selector: str, keysize: int, force: bool | None = None,
) -> Plan:
    """Preview generating a new DKIM private key for a selector.  CAPTURE via dkim_selector_get
    (no secret involved — the PRIVATE key never appears in this read, fact #1 above) so the plan
    can state the rotation impact directly rather than deferring entirely to a before/after
    manual diff (mirrors plan_customscores_update/_delete's own capture-before-mutate reasoning).

    RISK_MEDIUM (fact #5 above): PMG's own description states plainly "All future mail will be
    signed with the new key!" — a genuine mail-continuity risk, not data-destructive. Matches the
    ALREADY-SHIPPED `ldap_profile_config_update`/`fetchmail_update` "rotates a credential/key the
    mail pipeline depends on" MEDIUM precedent, not a HIGH-class irreversible/destructive event.
    """
    selector = _check_domain(selector)
    keysize = _check_dkim_keysize(keysize)
    current: dict = {}
    read_failed = False
    try:
        current = dkim_selector_get(api)
    except Exception:
        read_failed = True
    blast = [
        "*** ALL FUTURE MAIL WILL BE SIGNED WITH THE NEW KEY *** (PMG's own wording) — the "
        "OLD key immediately stops being used to sign outbound mail",
    ]
    if read_failed:
        blast.append(
            "could not read the current selector — current selector unavailable, cannot state "
            "which prior selector/key this rotates"
        )
    else:
        prior = current.get("selector")
        if prior:
            blast.append(
                f"rotates the signing selector away from the current {prior!r}: mail signed "
                "with the previous selector fails DKIM validation at receivers until the new "
                "public record is published to DNS"
            )
        else:
            blast.append(
                "no DKIM selector is currently configured (per this read) — not a rotation of "
                "an existing selector"
            )
    blast.append(
        "receivers checking DKIM alignment against the OLD DNS TXT record will see "
        "signatures fail to verify until the NEW record (from pmg_dkim_selector_get, run "
        "AFTER this call) is published in DNS — a real deliverability/continuity risk during "
        "the propagation window"
    )
    blast.append(
        "if a key already exists for this selector, PMG's own `force` flag governs whether "
        "it is silently overwritten or the call is refused (asserted from the field's own "
        "description, not independently proven — Smoke-confirm the actual refusal behavior)"
    )
    blast.append(
        "no undo: the OLD key is gone once this executes — there is no 'restore prior key' "
        "primitive on this endpoint"
    )
    return Plan(
        action="pmg_dkim_selector_generate",
        target="config/dkim/selector",
        change=f"generate a new DKIM private key for selector {selector!r} (keysize={keysize})",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: rotates cryptographic signing material the mail pipeline depends on — a "
            "continuity risk during DNS propagation, not a data-destructive or irreversible-"
            "authority-change event (matches the shipped bindpw/fetchmail-password rotation "
            "precedent)",
        ],
        complete=not read_failed,
        note="PMG 9.1 schema-verified path: POST /config/dkim/selector. Compare "
             "pmg_dkim_selector_get's output before and after this call, and update external DNS "
             "with the NEW record promptly.",
    )


def plan_customscores_create(
    name: str, score, comment: str | None = None,
) -> Plan:
    """Preview creating a custom SpamAssassin score.  PURE — no API call (a brand-new rule name;
    nothing pre-existing to snapshot, mirrors plan_ldap_profile_create's own "nothing to
    snapshot" reasoning).

    RISK_LOW: additive — assigns a NEW rule a score; no EXISTING mail-classification behavior
    changes (unlike update/delete, which touch an already-active override — RISK_MEDIUM there).
    States the resulting classification direction from the score's own sign (fact #8 above) —
    classify-don't-recite (9d lesson).
    """
    name = _check_customscore_name(name)
    score = _check_customscore_score(score)
    return Plan(
        action="pmg_customscores_create",
        target="config/customscores",
        change=f"create custom score {name!r}: score={score!r}"
               + (f", comment={comment!r}" if comment else ""),
        current={},
        blast_radius=[
            f"assigns rule {name!r} a custom SpamAssassin score of {score!r}",
            _customscore_sign_line(score),
            "additive: no other rule's score is affected",
        ],
        risk=RISK_LOW,
        risk_reasons=["LOW: additive — a brand-new rule score, no existing classification changes"],
        note="PMG 9.1 schema-verified path: POST /config/customscores.",
    )


def plan_customscores_update(
    api: PmgBackend, name: str, score, comment: str | None = None,
) -> Plan:
    """Preview editing a custom SpamAssassin score. CAPTURE: reads the current score via
    customscores_get (no secret involved — safe to read) so the plan can state whether this
    RAISES or LOWERS it (fact #8 above) — a real before/after delta, not a resulting-value guess.

    RISK_MEDIUM: changes an EXISTING mail-classification override, effective immediately.
    """
    name = _check_customscore_name(name)
    score = _check_customscore_score(score)
    current: dict = {}
    read_failed = False
    try:
        current = customscores_get(api, name)
    except Exception:
        read_failed = True
    blast = [f"changes custom score {name!r}'s value to {score!r}"]
    if read_failed:
        blast.append(
            "could not read the current score — prior value UNKNOWN, cannot state whether this "
            "raises or lowers it"
        )
    elif "score" in current:
        try:
            blast.append(_customscore_delta_line(float(current["score"]), score))
        except (TypeError, ValueError):
            blast.append(f"sets the score to {score!r} (prior value not numeric — no delta shown)")
    else:
        blast.append(f"sets the score to {score!r} (prior value not returned by this read)")
    blast.append("takes effect for mail scored AFTER this change; already-scored mail is unaffected")
    return Plan(
        action="pmg_customscores_update",
        target=f"config/customscores/{name}",
        change=f"update custom score {name!r}: score={score!r}"
               + (f", comment={comment!r}" if comment else ""),
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: changes spam-classification behavior for mail matching this rule, "
            "effective immediately",
        ],
        complete=not read_failed,
        note="PMG 9.1 schema-verified path: PUT /config/customscores/{name}. score is "
             "schema-required — this is a full replace.",
    )


def plan_customscores_delete(api: PmgBackend, name: str) -> Plan:
    """Preview deleting a custom SpamAssassin score. CAPTURE via customscores_get.

    RISK_MEDIUM: removes an operator override; the rule reverts to SpamAssassin's BUILT-IN
    default score, which this endpoint does not disclose (asserted, not fabricated — matches the
    plan_tlspolicy_delete "does not disclose what the default is" honesty precedent).
    """
    name = _check_customscore_name(name)
    current: dict = {}
    read_failed = False
    try:
        current = customscores_get(api, name)
    except Exception:
        read_failed = True
    blast = [
        f"removes the custom score override for rule {name!r}",
        "the rule reverts to SpamAssassin's BUILT-IN default score — this endpoint does not "
        "disclose what that default is",
        "no undo: re-create with pmg_customscores_create (the prior value is shown above if the "
        "read succeeded)",
    ]
    if read_failed:
        blast.append("could not read the current score — prior value UNKNOWN")
    return Plan(
        action="pmg_customscores_delete",
        target=f"config/customscores/{name}",
        change=f"delete custom score {name!r}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["MEDIUM: removes an active spam-classification override"],
        complete=not read_failed,
        note="PMG 9.1 schema-verified path: DELETE /config/customscores/{name}.",
    )


def plan_customscores_revert_all() -> Plan:
    """Preview reverting ALL custom SpamAssassin score changes at once.  PURE — no per-item
    CAPTURE is possible: PMG's own schema gives no "list of what would revert" companion read
    (fact #7 above) — the affected-rule count is honestly not rendered here, mirrors
    plan_ldap_profile_sync's own "nothing capturable" reasoning.

    RISK_MEDIUM: a step above a single per-item delete — every custom score override is reverted
    in one call.
    """
    return Plan(
        action="pmg_customscores_revert_all",
        target="config/customscores",
        change="revert ALL custom SpamAssassin score changes",
        current={},
        blast_radius=[
            "reverts EVERY custom score override back to SpamAssassin's built-in defaults — not "
            "scoped to one rule",
            "no per-item preview is possible (PMG exposes no 'list pending changes' companion "
            "read) — the affected-rule count is not rendered here",
            "no undo: re-create any needed overrides individually with pmg_customscores_create",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["MEDIUM: reverts ALL custom score overrides at once, not scoped to one rule"],
        note="PMG 9.1 schema-verified path: DELETE /config/customscores (bare, no digest param — "
             "schema-verified).",
    )


def plan_customscores_apply(restart_daemon: bool | None = None) -> Plan:
    """Preview applying staged custom SpamAssassin score changes.  PURE — no per-item CAPTURE
    (same reasoning as plan_customscores_revert_all).

    RISK_MEDIUM. Returns a STRING (fact #6 above) — Smoke-confirm whether it's a UPID or a plain
    status message.
    """
    blast = ["applies ALL staged custom SpamAssassin score changes at once"]
    if restart_daemon:
        blast.append(
            "restart_daemon=True: ALSO restarts pmg-smtp-filter — a brief mail-filtering "
            "interruption on this node while it restarts"
        )
    else:
        blast.append(
            "restart_daemon not set: per PMG's own description this is 'necessary for the "
            "changes to work' — staged changes may not take effect until pmg-smtp-filter is "
            "next restarted some other way"
        )
    return Plan(
        action="pmg_customscores_apply",
        target="config/customscores",
        change="apply staged custom SpamAssassin score changes"
               + (" and restart pmg-smtp-filter" if restart_daemon else ""),
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["MEDIUM: applies all staged spam-classification changes at once"],
        note="PMG 9.1 schema-verified path: PUT /config/customscores (bare). Returns a bare "
             "string (Smoke-confirm: UPID vs status message) — passed through unchanged, no "
             "shape invented.",
    )


# ===========================================================================
# Wave 9f: PBS remote config + node-side PBS backup jobs (full-surface campaign, 2026-07-17)
# ===========================================================================
# Schema truth: `.scratch/api-schemas-2026-07-15/pmg-apidoc-live-2026-07-17.json`,
# `/config/pbs[/{remote}]` and `/nodes/{node}/pbs[/{remote}/snapshot[/{backup-id}[/{backup-time}
# [/verify]]]|/{remote}/timer]` — all 15 methods read field-by-field for this build (the exact set
# classified `"chunk": "9f"` in `.scratch/sdd/wave-9-classification.json`), never assumed from the
# draft's prose alone. Extends pmg.py/tools/pmg_mail.py per campaign RULING 5 (PBS-remote config +
# node-side backup jobs are node-infra, small enough to share this file rather than earning their
# own module — matches the draft's own §2 chunk assignment).
#
# CROSS-TOOL DISTINCTION (draft's own instruction): PMG's `/config/pbs` is a DIFFERENT PRODUCT and
# a DIFFERENT ENDPOINT from the PBS-plane's own `pbs_remote_*` tools (`pbs_config.py`/
# `tools/pbs.py`, `GET/POST/PUT/DELETE /config/remote[/{name}]`) — that family configures a PBS
# DATASTORE's own sync-source (pull FROM another PBS); THIS family configures PMG's own
# INTEGRATION to push its mail-filter configuration/rule-database TO a PBS instance for backup.
# Same secret shape (password), same "credential-bearing remote link" risk reasoning, but a
# genuinely separate tool surface on a genuinely separate product — every tool docstring below
# says so explicitly so a caller reading either isn't confused about which remote it touches (the
# pmg_welcomelist-vs-quarantine_welcomelist disambiguation precedent from 8b, RULING 5 applied
# here).
#
# THE SECRET CONTRACT (this chunk's headline; binding per the wave-9 draft §5 + campaign doc — TWO
# CONFIRMED-echoing secrets, the 9c/5b/5d idiom extended to a pair):
#  - `password` and `encryption-key`: CONFIRMED ECHOED on BOTH list forms (`GET /config/pbs`,
#    `GET /nodes/{node}/pbs`) — both schemas explicitly type both fields in the item shape (the
#    node-side list is literally the same PBS-remote-config item shape, scoped per-node). This is
#    NOT schema-thin — the secrets are genuinely there. Contract: MANDATORY read-strip (not merely
#    defensive) on BOTH list forms. The single-item `GET /config/pbs/{remote}` declares a bare
#    `returns: {}` (ZERO properties documented — genuinely thin/unconfirmed either way, the Wave
#    7/8/9c "single-item GET thinness" pattern) — DEFENSIVE strip applied regardless (silence is
#    not evidence of absence). Never-in-ledger on write (create/update: neither field's raw value,
#    nor a possible server-generated `encryption-key` returned in the CREATE/UPDATE response body
#    itself when the caller passes `encryption-key='autogen'` — schema fact: `config.
#    encryption-key` is "the auto-generated encryption key, only returned when one was newly
#    generated." The tool's own `result` DOES carry it back to the caller — they need their
#    generated key, there is no second copy — but the ledger `detail` never does, applying the
#    TFA-recovery-code "secret in a mutation's own RETURN" precedent proactively, ahead of chunk
#    9h).
#  - `fingerprint` and `master-pubkey` are PUBLIC, argued not defaulted: `fingerprint` is the
#    remote PBS's own TLS cert SHA-256 fingerprint (verification material a client needs to trust
#    the remote — the identical role a cert fingerprint plays everywhere else in this codebase;
#    `pbs_config.py`'s own module docstring states the same reasoning for the PBS-plane's sibling
#    field); `master-pubkey` is a base64 PEM PUBLIC RSA key used to encrypt a COPY of the
#    encryption-key for master-key-recovery purposes — by definition a public key, never a secret.
#    Both pass through UNREDACTED in every plan/ledger surface.
#  - Hunt for a THIRD secret (7d law): checked every 9f method's params+returns field-by-field — no
#    other token/key/cert/hmac-shaped field exists on this chunk's schema. `datastore`/`namespace`/
#    `username`/`server`/`port`/`notify`/`disable`/`include-statistics`/the six `keep-*` counters
#    are all plain identifiers/config, not secrets. `username` on this family is a PBS
#    user-or-API-token-ID string (`user@realm` or a tokenid), not the secret itself — the secret
#    half of an API-token credential is exactly `password` (PMG's own field description: "Password
#    or API token secret for the user").
#
# Taint: PBS-remote CONFIG reads (`pmg_pbs_remote_list`/`_get`, `pmg_node_pbs_jobs_list`) are
# operator-authored config (after the mandatory/defensive secret-strip above) — REVIEWED_TRUSTED,
# same channel as this file's other config-CRUD families. `pmg_node_pbs_snapshots_list` and
# `pmg_node_pbs_snapshot_get` return snapshot/backup-id/backup-time labels stored on the REMOTE PBS
# instance — externally-authored content (whoever wrote those backups, or compromised the remote,
# controls these strings) — the exact `pbs_snapshots_list` cross-plane precedent — ADVERSARIAL.
# Every mutation on this chunk returns either `null`, a schema-confirmed-ambiguous STRING, or (for
# `remote_create`/`remote_update`) a small typed dict with no free-text/externally-authored field —
# REVIEWED_TRUSTED regardless of blast radius (taint classifies the RETURN channel, not the
# mutation's consequences, the standing rule since Wave 4c/4d).
#
# digest: schema-verified field-by-field — ONLY `PUT /config/pbs/{remote}` (remote_update) carries
# a `digest` param (maxLength 64, no pattern) among this chunk's 15 methods. Forwarded when given,
# never invented elsewhere (the Wave 9a "don't invent a digest param" lesson).
#
# Callable-outcome (verified per method, never recited): `POST /config/pbs` (remote_create) and
# `PUT /config/pbs/{remote}` (remote_update) both return a small typed OBJECT (`{remote, config?}`)
# — NOT ambiguous, recorded outcome="ok". `DELETE /config/pbs/{remote}` (remote_delete), `DELETE
# .../snapshot/{backup-id}/{backup-time}` (snapshot_forget), and `POST`/`DELETE .../timer`
# (timer_create/timer_delete) all schema-type `returns: null` — outcome="ok". `POST .../snapshot`
# (snapshot_create, PMG's own `run_backup`) and `POST .../snapshot/{backup-id}/{backup-time}`
# (snapshot_restore, PMG's own `restore`) both schema-type a bare STRING with no UPID-vs-
# status-message resolution possible from the schema alone — outcome="submitted", the raw string
# recorded BOTH in the response `result` and the ledger's own `detail.raw_result` (the 9a/9b
# `network_reload`/`backup_restore` idiom, not invented fresh here). `POST .../verify`
# (snapshot_verify) is schema-CONFIRMED a UPID ("description": "UPID of the verification task on
# the Proxmox Backup Server.") — genuinely NOT ambiguous, so it is treated like `pbs_verify_start`'s
# own precedent: outcome="submitted" (an async task was started on the remote, not finished),
# without the raw_result hedge that only applies to a genuinely unresolved shape.
#
# Risk (argued per method, cross-tool-consistent):
#  - `pmg_pbs_remote_create`/`_update`: RISK_MEDIUM — creates/updates a PERSISTENT
#    CREDENTIAL-BEARING link to an external PBS instance, the exact `pbs_remote_create`/
#    `pbs_s3_client_create` "not LOW despite reading like additive config" reasoning.
#  - `pmg_pbs_remote_delete`: RISK_MEDIUM — mirrors `pbs_remote_delete` exactly.
#  - `pmg_node_pbs_snapshot_create` (run_backup): RISK_MEDIUM, argued not defaulted — PMG's own
#    schema states this "Create[s] a new backup and prune[s] the backup group afterwards, if
#    configured": additive (a new backup) AND may remove older backups per the remote's own
#    keep-* retention settings — structurally the SAME "adds AND may remove data" shape that rates
#    `plan_pbs_job_run`'s own "sync" job-type tier RISK_MEDIUM (not the flat RISK_HIGH reserved for
#    a bare "prune" job whose ENTIRE purpose is deletion) — this call's primary purpose is the
#    backup, prune is a configured-retention side effect, matching the sync precedent's reasoning
#    more closely than the prune precedent's.
#  - `pmg_node_pbs_snapshot_forget`: RISK_HIGH — permanently destroys a specific recovery point on
#    the remote, no undo — the exact `pbs_snapshot_delete` precedent (verified: that plan's own
#    docstring says the identical thing).
#  - `pmg_node_pbs_snapshot_restore`: RISK_HIGH, no undo — overwrites LIVE PMG state from a remote
#    snapshot, the exact `pmg_node_backup_restore` precedent (9b) extended to a remote source —
#    same `config`/`database`/`statistic` flags, same ruledb-scope capture reuse
#    (`_ruledb_reset_capture_count`, called directly since this module already defines it).
#  - `pmg_node_pbs_snapshot_verify`: RISK_LOW — non-destructive integrity check, the exact
#    `pbs_verify_start` precedent (verified: that plan's own docstring says the identical thing).
#  - `pmg_node_pbs_timer_create`/`_delete`: RISK_LOW — additive/removes a SCHEDULE only, no backup
#    data touched, the exact `pbs_job_create`/`pbs_job_delete` precedent.
#
# backup-id / backup-time: schema gives NO pattern/length bound for either (unlike this plane's
# other path-identity fields) — validated defensively (reject '/', '..', control chars) without
# inventing a bound, per this codebase's "no invented bound" discipline. `backup-time` is typed a
# plain STRING here ("RFC 3339 format" per the schema's own description) — a DELIBERATE DIVERGENCE
# from `pbs.py`'s own `_check_backup_time` (which validates a Unix-epoch INTEGER, PBS's own native
# API convention) — verified field-by-field against THIS chunk's own live schema, not copied from
# the sibling plane's convention.

# --- Validators ---

_PBS_REMOTE_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}\Z")


def _check_pbs_remote_id(remote: str) -> str:
    # Do NOT strip — \Z must catch trailing newlines (this file's own established discipline).
    s = str(remote)
    if not _PBS_REMOTE_ID_RE.match(s):
        raise ProximoError(
            f"invalid PBS remote id: {remote!r} "
            "(pve-configid format: alnum/./_/-, start with alnum/underscore, <=64 chars, "
            "no control chars)"
        )
    return s


_PBS_DATASTORE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*\Z")


def _check_pbs_datastore(value: str) -> str:
    s = str(value)
    if not _PBS_DATASTORE_RE.match(s):
        raise ProximoError(
            f"invalid PBS datastore name: {value!r} "
            "(alnum/./_/-, start with alnum/underscore, no control chars)"
        )
    return s


def _check_pbs_remote_server(value: str) -> str:
    """maxLength 256, format 'address' — the schema's own bound, mirrors
    `_check_ldap_server_address`'s identical convention (a fresh per-family copy)."""
    s = str(value)
    if len(s) > 256:
        raise ProximoError(f"invalid PBS remote server: too long ({len(s)} chars, max 256)")
    return s


_PBS_REMOTE_USERNAME_RE = re.compile(r"^[^\s\\@]+@[^\s/\\@]+\Z")


def _check_pbs_remote_username(value: str) -> str:
    """pattern `(?:[^\\s\\\\@]+\\@[^\\s\\/\\\\@]+)`, minLength 3, maxLength 512 — the schema's own
    bound (structurally identical to `_check_email_address`'s pattern, a fresh per-family copy —
    this is a PBS username/token-id, not an email address)."""
    s = str(value)
    if not (3 <= len(s) <= 512) or not _PBS_REMOTE_USERNAME_RE.match(s):
        raise ProximoError(
            f"invalid PBS remote username: {value!r} (must match user@realm/tokenid shape, "
            "3-512 chars)"
        )
    return s


_PBS_REMOTE_FINGERPRINT_RE = re.compile(r"^(?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}\Z")


def _check_pbs_remote_fingerprint(value: str) -> str:
    """SHA-256 fingerprint, colon-separated hex byte pairs — PUBLIC verification material, not a
    secret (module section docstring above). Fresh per-family copy of the same shape validated
    elsewhere in this codebase (`pbs_s3.py`/`pbs_tape_media.py`/`sdn_objects.py`)."""
    s = str(value)
    if not _PBS_REMOTE_FINGERPRINT_RE.match(s):
        raise ProximoError(
            f"invalid PBS remote fingerprint: {value!r} "
            "(expected SHA-256, 32 colon-separated hex byte pairs)"
        )
    return s


def _check_pbs_remote_port(port) -> int:
    try:
        p = int(port)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid PBS remote port: {port!r} (must be an integer)") from exc
    if not (1 <= p <= 65535):
        raise ProximoError(f"invalid PBS remote port: {port!r} (must be 1-65535)")
    return p


_PBS_REMOTE_NAMESPACE_RE = re.compile(
    r"^(?:(?:[A-Za-z0-9_][A-Za-z0-9._\-]*)/){0,7}(?:[A-Za-z0-9_][A-Za-z0-9._\-]*)?\Z"
)


def _check_pbs_remote_namespace(value: str) -> str:
    """maxLength 256, pattern `(?:(?:[A-Za-z0-9_][A-Za-z0-9._-]*)/){0,7}(?:...)?` — the schema's
    own bound on `namespace`, confirmed identical on BOTH `POST /config/pbs` and
    `PUT /config/pbs/{remote}`. Empty string is the root NS (the schema's own "defaults to the
    root NS" description), matched by the pattern's 0-repetition + optional-final-segment shape.

    NOT reused from `pbs.py`'s `_check_namespace` (imported as-is by `pdm.py` for the PBS-plane's
    OWN namespace field, proxying to a live PBS remote) — checked field-by-field, and the two
    diverge in BOTH directions: `_check_namespace` has no maxLength/depth bound and permits
    characters (spaces, other punctuation) this schema's pattern excludes, while separately
    rejecting some schema-legal substrings (an internal '..' inside a segment, e.g. 'a..b', is
    schema-legal here but `_check_namespace` blanket-rejects any '..' substring anywhere). A
    fresh per-family copy enforcing the ACTUAL schema pattern is used instead — the same "fresh
    per-family copy" convention as `_check_pbs_remote_username`/`_check_pbs_remote_fingerprint`/
    `_check_pbs_remote_server` above.
    """
    s = str(value)
    if len(s) > 256:
        raise ProximoError(
            f"invalid PBS remote namespace: too long ({len(s)} chars, max 256)"
        )
    if not _PBS_REMOTE_NAMESPACE_RE.match(s):
        raise ProximoError(
            f"invalid PBS remote namespace: {value!r} "
            "(each level: alnum/underscore start then alnum/./_/-, '/'-separated, max 8 levels)"
        )
    return s


def _check_pbs_keep_count(value, field: str) -> int:
    """The six `keep-{last,hourly,daily,weekly,monthly,yearly}` retention counters — schema
    `minimum: 0` on all six, no invented upper bound."""
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid {field}: {value!r} (must be an integer)") from exc
    if n < 0:
        raise ProximoError(f"invalid {field}: {value!r} (must be >= 0)")
    return n


def _check_pbs_remote_digest(digest: str | None) -> str | None:
    """maxLength 64, no pattern — the schema's own bound on PUT /config/pbs/{remote}'s digest, a
    SEPARATE per-field validator (this codebase's established digest-validator precedent: each
    endpoint's own digest gets its own copy, e.g. `_check_ldap_config_digest`/
    `_check_customscores_digest`/`_check_config_digest`)."""
    if digest is None:
        return None
    s = str(digest)
    if len(s) > 64:
        raise ProximoError(f"invalid digest: too long ({len(s)} chars, max 64)")
    return s


_PBS_REMOTE_DELETE_MAXLEN = 4096


def _check_pbs_remote_delete_list(value: str) -> str:
    """format 'pve-configid-list', maxLength 4096 — bounds-only (mirrors this file's own
    `ldap_profile_config_update`'s bare-passthrough `delete` convention: a comma-joined string, not
    individually parsed here)."""
    s = str(value)
    if len(s) > _PBS_REMOTE_DELETE_MAXLEN:
        raise ProximoError(
            f"invalid delete: too long ({len(s)} chars, max {_PBS_REMOTE_DELETE_MAXLEN})"
        )
    return s


def _check_pbs_snapshot_backup_id(value: str) -> str:
    """Schema gives NO pattern/length bound for `backup-id` on this family (unlike
    `pbs.py`'s own `_BACKUP_ID_RE`-bounded validator) — defensive-only: reject empty, '/'
    (path-segment safety), '..' (traversal), and control chars, no invented length cap."""
    s = str(value)
    if not s:
        raise ProximoError("backup_id must not be empty")
    if "/" in s or ".." in s or any(ord(c) < 0x20 for c in s):
        raise ProximoError(
            f"invalid backup_id: {value!r} (no '/', no '..', no control chars)"
        )
    return s


def _check_pbs_snapshot_backup_time(value: str) -> str:
    """Schema types `backup-time` a plain STRING ("RFC 3339 format") on this family — a DELIBERATE
    DIVERGENCE from `pbs.py`'s own `_check_backup_time` (Unix-epoch INTEGER, PBS's native API
    convention), verified field-by-field against THIS chunk's own live schema. No pattern/length
    bound given — defensive-only: reject empty, '/', and control chars."""
    s = str(value)
    if not s or "/" in s or any(ord(c) < 0x20 for c in s):
        raise ProximoError(
            f"invalid backup_time: {value!r} (must be a non-empty RFC 3339 string, no '/', "
            "no control chars)"
        )
    return s


_PBS_TIMER_SCHEDULE_RE = re.compile(r"^[0-9a-zA-Z*.:,\-/ ]+\Z")


def _check_pbs_timer_schedule(value: str) -> str:
    s = str(value)
    if not _PBS_TIMER_SCHEDULE_RE.match(s):
        raise ProximoError(f"invalid timer schedule: {value!r} (systemd OnCalendar charset)")
    return s


_PBS_TIMER_DELAY_RE = re.compile(r"^[0-9a-zA-Z. ]+\Z")


def _check_pbs_timer_delay(value: str) -> str:
    s = str(value)
    if not _PBS_TIMER_DELAY_RE.match(s):
        raise ProximoError(f"invalid timer delay: {value!r} (systemd RandomizedDelaySec charset)")
    return s


# --- Secret-shaped fields — THE SECRET CONTRACT (module section docstring above) ---
_PBS_REMOTE_SECRET_KEYS = frozenset({"password", "encryption-key"})


def _redact_pbs_remote_secrets(d: dict) -> dict:
    """Mask `password`/`encryption-key` before entering a Plan/ledger surface — the shared
    `_validate.redact_secrets` mechanic over this family's own key set. `fingerprint`/
    `master-pubkey` are PUBLIC and are NOT in this set — deliberately left visible."""
    return redact_secrets(d, _PBS_REMOTE_SECRET_KEYS)


def _strip_pbs_remote_secrets_at_read(data: dict) -> dict:
    """Read-layer strip for `pbs_remote_list`/`pbs_remote_get`/`node_pbs_jobs_list` — `password`
    and `encryption-key` REMOVED entirely. MANDATORY on both list forms (CONFIRMED echoing on the
    live schema — a real leak path, not defense-in-depth); applied DEFENSIVELY on the single-item
    read too (schema is bare there — silence is not evidence of absence)."""
    return {k: v for k, v in data.items() if k not in _PBS_REMOTE_SECRET_KEYS}


# --- Backend functions: PBS remote config (/config/pbs) ---

def pbs_remote_list(api: PmgBackend) -> list[dict]:
    """List all configured PBS remote instances PMG can back up its own config to.

    GET /config/pbs

    `password`/`encryption-key` CONFIRMED echoed in the live item schema — MANDATORY strip, not
    defensive (fact above). REVIEWED_TRUSTED after the strip (operator-authored config).
    """
    items = api._get("/config/pbs") or []
    return [_strip_pbs_remote_secrets_at_read(i) if isinstance(i, dict) else i for i in items]


def pbs_remote_get(api: PmgBackend, remote: str) -> dict:
    """Read one PBS remote's configuration.

    GET /config/pbs/{remote}

    Schema declares a bare `returns: {}` — genuinely thin/unconfirmed whether the secrets echo
    here. DEFENSIVE strip applied regardless.
    """
    remote = _check_pbs_remote_id(remote)
    data = api._get(f"/config/pbs/{remote}") or {}
    return _strip_pbs_remote_secrets_at_read(data)


def _pbs_remote_field_kwargs(
    datastore: str | None = None,
    server: str | None = None,
    disable: bool | None = None,
    encryption_key: str | None = None,
    fingerprint: str | None = None,
    include_statistics: bool | None = None,
    keep_daily: int | None = None,
    keep_hourly: int | None = None,
    keep_last: int | None = None,
    keep_monthly: int | None = None,
    keep_weekly: int | None = None,
    keep_yearly: int | None = None,
    master_pubkey: str | None = None,
    namespace: str | None = None,
    notify: str | None = None,
    password: str | None = None,
    port: int | None = None,
    username: str | None = None,
) -> dict:
    """Shared field-collection + validation for the PBS-remote create/update family — used by BOTH
    the backend functions AND the plan factories, so the same 18-field branching isn't
    hand-duplicated four times (mirrors `_ldap_profile_field_kwargs`'s own extraction rationale).
    `datastore`/`server` are accepted here as OPTIONAL (update's own schema shape); create() checks
    their required-ness itself before calling this helper.
    """
    kw: dict = {}
    if datastore is not None:
        kw["datastore"] = _check_pbs_datastore(datastore)
    if server is not None:
        kw["server"] = _check_pbs_remote_server(server)
    if disable is not None:
        kw["disable"] = bool(disable)
    if encryption_key is not None:
        kw["encryption-key"] = str(encryption_key)
    if fingerprint is not None:
        kw["fingerprint"] = _check_pbs_remote_fingerprint(fingerprint)
    if include_statistics is not None:
        kw["include-statistics"] = bool(include_statistics)
    if keep_daily is not None:
        kw["keep-daily"] = _check_pbs_keep_count(keep_daily, "keep-daily")
    if keep_hourly is not None:
        kw["keep-hourly"] = _check_pbs_keep_count(keep_hourly, "keep-hourly")
    if keep_last is not None:
        kw["keep-last"] = _check_pbs_keep_count(keep_last, "keep-last")
    if keep_monthly is not None:
        kw["keep-monthly"] = _check_pbs_keep_count(keep_monthly, "keep-monthly")
    if keep_weekly is not None:
        kw["keep-weekly"] = _check_pbs_keep_count(keep_weekly, "keep-weekly")
    if keep_yearly is not None:
        kw["keep-yearly"] = _check_pbs_keep_count(keep_yearly, "keep-yearly")
    if master_pubkey is not None:
        kw["master-pubkey"] = str(master_pubkey)
    if namespace is not None:
        kw["namespace"] = _check_pbs_remote_namespace(namespace)
    if notify is not None:
        kw["notify"] = _check_backup_notify(notify)
    if password is not None:
        kw["password"] = password
    if port is not None:
        kw["port"] = _check_pbs_remote_port(port)
    if username is not None:
        kw["username"] = _check_pbs_remote_username(username)
    return kw


def pbs_remote_create(
    api: PmgBackend,
    remote: str,
    datastore: str,
    server: str,
    disable: bool | None = None,
    encryption_key: str | None = None,
    fingerprint: str | None = None,
    include_statistics: bool | None = None,
    keep_daily: int | None = None,
    keep_hourly: int | None = None,
    keep_last: int | None = None,
    keep_monthly: int | None = None,
    keep_weekly: int | None = None,
    keep_yearly: int | None = None,
    master_pubkey: str | None = None,
    namespace: str | None = None,
    notify: str | None = None,
    password: str | None = None,
    port: int | None = None,
    username: str | None = None,
) -> object:
    """Add a PBS remote instance.

    POST /config/pbs  body: {remote, datastore, server, ...}  -> {remote, config?}

    `datastore`/`server` are the ONLY other schema-required fields besides `remote`. `password`/
    `encryption-key` are SECRETS — forwarded raw here (the create must actually work) but never
    recorded to the ledger — see plan_pbs_remote_create's redaction. The response MAY carry a
    server-generated `config.encryption-key` when `encryption_key='autogen'` — passed through
    unchanged, never stripped from the return (the caller needs it), but the server layer's ledger
    detail never includes the raw response either (see tools/pmg_mail.py's wrapper). `fingerprint`/
    `master-pubkey` are PUBLIC — forwarded and never redacted. `namespace` (PBS namespace in the
    datastore, defaults to the root NS) is a plain identifier, not a secret — forwarded as-is.
    """
    remote = _check_pbs_remote_id(remote)
    data: dict = {
        "remote": remote,
        "datastore": _check_pbs_datastore(datastore),
        "server": _check_pbs_remote_server(server),
        **_pbs_remote_field_kwargs(
            disable=disable, encryption_key=encryption_key, fingerprint=fingerprint,
            include_statistics=include_statistics, keep_daily=keep_daily, keep_hourly=keep_hourly,
            keep_last=keep_last, keep_monthly=keep_monthly, keep_weekly=keep_weekly,
            keep_yearly=keep_yearly, master_pubkey=master_pubkey, namespace=namespace,
            notify=notify, password=password, port=port, username=username,
        ),
    }
    return api._post("/config/pbs", data)


def pbs_remote_update(
    api: PmgBackend,
    remote: str,
    datastore: str | None = None,
    server: str | None = None,
    disable: bool | None = None,
    encryption_key: str | None = None,
    fingerprint: str | None = None,
    include_statistics: bool | None = None,
    keep_daily: int | None = None,
    keep_hourly: int | None = None,
    keep_last: int | None = None,
    keep_monthly: int | None = None,
    keep_weekly: int | None = None,
    keep_yearly: int | None = None,
    master_pubkey: str | None = None,
    namespace: str | None = None,
    notify: str | None = None,
    password: str | None = None,
    port: int | None = None,
    username: str | None = None,
    delete: str | None = None,
    digest: str | None = None,
) -> object:
    """Update PBS remote settings.

    PUT /config/pbs/{remote}  body: {..., delete?, digest?}  -> {remote, config?}

    Every field is optional on update (unlike create, where datastore/server are required).
    `remote` is path-identity — never resent in the body. `digest` (maxLength 64, no pattern) is
    the ONE digest-bearing method in this chunk — schema-verified, forwarded where given, never
    invented elsewhere. `password`/`encryption-key` are SECRETS — forwarded raw but never recorded
    to the ledger — see plan_pbs_remote_update's redaction. `namespace` is a plain identifier, not
    a secret — forwarded as-is, and alone satisfies the "at least one field" requirement below.
    """
    remote = _check_pbs_remote_id(remote)
    data = _pbs_remote_field_kwargs(
        datastore=datastore, server=server, disable=disable, encryption_key=encryption_key,
        fingerprint=fingerprint, include_statistics=include_statistics, keep_daily=keep_daily,
        keep_hourly=keep_hourly, keep_last=keep_last, keep_monthly=keep_monthly,
        keep_weekly=keep_weekly, keep_yearly=keep_yearly, master_pubkey=master_pubkey,
        namespace=namespace, notify=notify, password=password, port=port, username=username,
    )
    if not data and not delete:
        raise ProximoError("pbs_remote_update requires at least one field to set or delete")
    if delete is not None:
        data["delete"] = _check_pbs_remote_delete_list(delete)
    digest = _check_pbs_remote_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/config/pbs/{remote}", data)


def pbs_remote_delete(api: PmgBackend, remote: str) -> object:
    """Delete a PBS remote.

    DELETE /config/pbs/{remote}

    Returns None. Any node-side backup jobs/timers referencing this remote will fail afterward.
    """
    remote = _check_pbs_remote_id(remote)
    return api._delete(f"/config/pbs/{remote}")


# --- Backend functions: node-side PBS backup jobs (/nodes/{node}/pbs) ---

def node_pbs_jobs_list(api: PmgBackend, node: str) -> list[dict]:
    """List all configured PBS backup jobs on this node.

    GET /nodes/{node}/pbs

    Literally the SAME item schema as `pbs_remote_list` (the global `/config/pbs`), scoped
    per-node — `password`/`encryption-key` CONFIRMED echoed here too. MANDATORY strip, same
    mechanism as `pbs_remote_list`. Distinct from `/config/pbs` (the global remote-instance list)
    and from `/nodes/{node}/pbs/{remote}` (the per-remote directory-index stub, dispositioned, not
    built).
    """
    node = _check_node(node)
    items = api._get(f"/nodes/{node}/pbs") or []
    return [_strip_pbs_remote_secrets_at_read(i) if isinstance(i, dict) else i for i in items]


def node_pbs_snapshots_list(api: PmgBackend, node: str, remote: str) -> list[dict]:
    """List snapshots stored on a PBS remote.

    GET /nodes/{node}/pbs/{remote}/snapshot

    ADVERSARIAL: `backup-id`/`backup-time` are stored on the REMOTE PBS instance — externally-
    authored content, the exact `pbs_snapshots_list` cross-plane precedent.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    return api._get(f"/nodes/{node}/pbs/{remote}/snapshot") or []


def node_pbs_snapshot_create(
    api: PmgBackend, node: str, remote: str,
    notify: str | None = None, statistic: bool | None = None,
) -> object:
    """Create a new backup and prune the backup group afterwards, if configured.

    POST /nodes/{node}/pbs/{remote}/snapshot

    Returns a schema-typed STRING — ambiguous (UPID vs plain status message unresolved from the
    schema alone; Smoke-confirm). `notify` defaults to 'never' upstream if omitted (schema
    default); forwarded only when given.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    data: dict = {}
    if notify is not None:
        data["notify"] = _check_backup_notify(notify)
    if statistic is not None:
        data["statistic"] = bool(statistic)
    return api._post(f"/nodes/{node}/pbs/{remote}/snapshot", data)


def node_pbs_snapshot_get(api: PmgBackend, node: str, remote: str, backup_id: str) -> list[dict]:
    """Get snapshots from a specific backup-id stored on a PBS remote.

    GET /nodes/{node}/pbs/{remote}/snapshot/{backup-id}

    Despite the singular name (PMG's own upstream method name is `get_group_snapshots`), this
    returns an ARRAY (all snapshots under that backup-id) — schema-verified, not assumed from the
    tool's own name. ADVERSARIAL — same reasoning as node_pbs_snapshots_list.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    backup_id = _check_pbs_snapshot_backup_id(backup_id)
    return api._get(f"/nodes/{node}/pbs/{remote}/snapshot/{backup_id}") or []


def node_pbs_snapshot_forget(
    api: PmgBackend, node: str, remote: str, backup_id: str, backup_time: str,
) -> object:
    """Forget (permanently delete) a snapshot on a PBS remote.

    DELETE /nodes/{node}/pbs/{remote}/snapshot/{backup-id}/{backup-time}

    Returns None. RISK_HIGH (see plan_node_pbs_snapshot_forget) — no undo.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    backup_id = _check_pbs_snapshot_backup_id(backup_id)
    backup_time = _check_pbs_snapshot_backup_time(backup_time)
    return api._delete(f"/nodes/{node}/pbs/{remote}/snapshot/{backup_id}/{backup_time}")


def node_pbs_snapshot_restore(
    api: PmgBackend, node: str, remote: str, backup_id: str, backup_time: str,
    config: bool = False, database: bool = True, statistic: bool = False,
) -> object:
    """Restore the system configuration from a PBS remote snapshot.

    POST /nodes/{node}/pbs/{remote}/snapshot/{backup-id}/{backup-time}
    body: {config, database, statistic}  (all three schema defaults sent explicitly, matching the
    already-shipped `backup_restore`'s (9b) deterministic-payload convention)

    Returns a schema-typed STRING — ambiguous (Smoke-confirm). RISK_HIGH (see
    plan_node_pbs_snapshot_restore) — overwrites live PMG state, no undo.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    backup_id = _check_pbs_snapshot_backup_id(backup_id)
    backup_time = _check_pbs_snapshot_backup_time(backup_time)
    data = {"config": bool(config), "database": bool(database), "statistic": bool(statistic)}
    return api._post(f"/nodes/{node}/pbs/{remote}/snapshot/{backup_id}/{backup_time}", data)


def node_pbs_snapshot_verify(
    api: PmgBackend, node: str, remote: str, backup_id: str, backup_time: str,
) -> str:
    """Verify a snapshot. Starts a verification task on the PBS remote and returns its UPID.

    POST /nodes/{node}/pbs/{remote}/snapshot/{backup-id}/{backup-time}/verify

    Returns a schema-CONFIRMED UPID (not ambiguous — the description says so explicitly).
    RISK_LOW — non-destructive integrity check.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    backup_id = _check_pbs_snapshot_backup_id(backup_id)
    backup_time = _check_pbs_snapshot_backup_time(backup_time)
    return api._post(f"/nodes/{node}/pbs/{remote}/snapshot/{backup_id}/{backup_time}/verify", {})


def node_pbs_timer_get(api: PmgBackend, node: str, remote: str) -> dict:
    """Get the backup schedule (systemd timer spec) for a PBS remote.

    GET /nodes/{node}/pbs/{remote}/timer

    Returns {delay?, next-run?, remote?, schedule?, unitfile?}. REVIEWED_TRUSTED.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    return api._get(f"/nodes/{node}/pbs/{remote}/timer") or {}


def node_pbs_timer_create(
    api: PmgBackend, node: str, remote: str,
    schedule: str | None = None, delay: str | None = None,
) -> object:
    """Create a backup schedule for a PBS remote.

    POST /nodes/{node}/pbs/{remote}/timer

    `schedule` (systemd OnCalendar, schema default 'daily') and `delay` (systemd
    RandomizedDelaySec, schema default '5min') are both optional — forwarded only when given, so
    PMG applies its own defaults on omission. Returns None.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    data: dict = {}
    if schedule is not None:
        data["schedule"] = _check_pbs_timer_schedule(schedule)
    if delay is not None:
        data["delay"] = _check_pbs_timer_delay(delay)
    return api._post(f"/nodes/{node}/pbs/{remote}/timer", data)


def node_pbs_timer_delete(api: PmgBackend, node: str, remote: str) -> object:
    """Delete the backup schedule for a PBS remote.

    DELETE /nodes/{node}/pbs/{remote}/timer

    Returns None. Existing backups/snapshots on the remote are untouched; only the SCHEDULE is
    removed.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    return api._delete(f"/nodes/{node}/pbs/{remote}/timer")


# --- Wave 9f PLAN functions — pure/CAPTURE factories; no mutation; the PLAN pillar ---

def plan_pbs_remote_create(
    remote: str,
    datastore: str,
    server: str,
    disable: bool | None = None,
    encryption_key: str | None = None,
    fingerprint: str | None = None,
    include_statistics: bool | None = None,
    keep_daily: int | None = None,
    keep_hourly: int | None = None,
    keep_last: int | None = None,
    keep_monthly: int | None = None,
    keep_weekly: int | None = None,
    keep_yearly: int | None = None,
    master_pubkey: str | None = None,
    namespace: str | None = None,
    notify: str | None = None,
    password: str | None = None,
    port: int | None = None,
    username: str | None = None,
) -> Plan:
    """Preview adding a PBS remote instance. PURE — no API call (a brand-new remote id; nothing
    pre-existing to snapshot, mirrors plan_ldap_profile_create/plan_fetchmail_create's own
    "nothing to snapshot" reasoning).

    RISK_MEDIUM: creates a PERSISTENT CREDENTIAL-BEARING link to an external PBS instance (mirrors
    pbs_remote_create/pbs_s3_client_create's own "not LOW despite reading like additive config"
    reasoning).
    """
    remote = _check_pbs_remote_id(remote)
    datastore = _check_pbs_datastore(datastore)
    server = _check_pbs_remote_server(server)
    kw = _pbs_remote_field_kwargs(
        disable=disable, encryption_key=encryption_key, fingerprint=fingerprint,
        include_statistics=include_statistics, keep_daily=keep_daily, keep_hourly=keep_hourly,
        keep_last=keep_last, keep_monthly=keep_monthly, keep_weekly=keep_weekly,
        keep_yearly=keep_yearly, master_pubkey=master_pubkey, namespace=namespace,
        notify=notify, password=password, port=port, username=username,
    )
    shown = {"remote": remote, "datastore": datastore, "server": server,
             **_redact_pbs_remote_secrets(kw)}
    blast = [
        f"registers PBS remote {remote!r} ({server!r}, datastore {datastore!r}) as a backup "
        "target for this PMG install",
        "PMG will authenticate to this THIRD-PARTY PBS instance with the given credentials",
    ]
    if encryption_key == "autogen":
        blast.append(
            "encryption-key='autogen': PBS will generate a NEW encryption key — it is returned "
            "ONCE in the create response's config.encryption-key and NEVER recorded to the "
            "ledger; capture it from the tool's own response immediately, there is no second copy"
        )
    return Plan(
        action="pmg_pbs_remote_create", target="config/pbs",
        change=f"create PBS remote {remote!r}: {shown}",
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: creates a PERSISTENT CREDENTIAL-BEARING link to an external PBS instance "
            "(mirrors pbs_remote_create/pbs_s3_client_create's own reasoning)",
        ],
        note="password/encryption-key are UNCONDITIONALLY redacted — only \"[redacted]\" appears "
             "in the plan and the audit ledger; fingerprint/master-pubkey are PUBLIC and shown "
             "as-is.",
    )


def plan_pbs_remote_update(
    api: PmgBackend,
    remote: str,
    datastore: str | None = None,
    server: str | None = None,
    disable: bool | None = None,
    encryption_key: str | None = None,
    fingerprint: str | None = None,
    include_statistics: bool | None = None,
    keep_daily: int | None = None,
    keep_hourly: int | None = None,
    keep_last: int | None = None,
    keep_monthly: int | None = None,
    keep_weekly: int | None = None,
    keep_yearly: int | None = None,
    master_pubkey: str | None = None,
    namespace: str | None = None,
    notify: str | None = None,
    password: str | None = None,
    port: int | None = None,
    username: str | None = None,
    delete: str | None = None,
) -> Plan:
    """Preview updating a PBS remote's settings. CAPTURE: reads current config via pbs_remote_get
    (already secret-stripped) and redacts it AGAIN defensively. A fresh password/encryption-key
    passed as a NEW value here is masked the same way. RISK_MEDIUM. No `digest` parameter here —
    mirrors plan_ldap_profile_config_update's own reasoning (digest is an optimistic-concurrency
    lock relevant only at execution time, not to the preview).
    """
    remote = _check_pbs_remote_id(remote)
    kw = _pbs_remote_field_kwargs(
        datastore=datastore, server=server, disable=disable, encryption_key=encryption_key,
        fingerprint=fingerprint, include_statistics=include_statistics, keep_daily=keep_daily,
        keep_hourly=keep_hourly, keep_last=keep_last, keep_monthly=keep_monthly,
        keep_weekly=keep_weekly, keep_yearly=keep_yearly, master_pubkey=master_pubkey,
        namespace=namespace, notify=notify, password=password, port=port, username=username,
    )
    if not kw and not delete:
        raise ProximoError("pbs_remote_update requires at least one field to set or delete")
    current: dict = {}
    read_failed = False
    try:
        current = _redact_pbs_remote_secrets(pbs_remote_get(api, remote))
    except Exception:
        read_failed = True
    parts = [f"{k}={v}" for k, v in sorted(_redact_pbs_remote_secrets(kw).items())]
    if delete:
        parts.append(f"-{delete}")
    blast = [f"changes PBS remote {remote!r}'s connection/retention settings"]
    if "password" in kw or "encryption-key" in kw:
        blast.append("rotates credentials used to authenticate to the remote PBS instance")
    if encryption_key == "autogen":
        blast.append(
            "encryption-key='autogen': PBS will generate a NEW key — returned ONCE in the "
            "response's config.encryption-key, never recorded to the ledger"
        )
    if read_failed:
        blast.append("could not read current PBS remote config — prior value UNKNOWN")
    return Plan(
        action="pmg_pbs_remote_update", target=f"config/pbs/{remote}",
        change=f"update PBS remote {remote!r}: {', '.join(parts) or '(none)'}",
        current=current, blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[
            "changes a credential-bearing external-system link's connection/retention settings",
        ],
        complete=not read_failed,
        note="password/encryption-key are UNCONDITIONALLY redacted — only \"[redacted]\" appears "
             "in the plan and the audit ledger. fingerprint/master-pubkey are PUBLIC and shown "
             "as-is.",
    )


def plan_pbs_remote_delete(api: PmgBackend, remote: str) -> Plan:
    """Preview deleting a PBS remote. CAPTURE: reads current config via pbs_remote_get (already
    secret-stripped) and redacts it AGAIN defensively before it enters Plan.current. RISK_MEDIUM
    (mirrors plan_ldap_profile_delete/pbs_remote_delete's own reasoning).
    """
    remote = _check_pbs_remote_id(remote)
    current: dict = {}
    read_failed = False
    try:
        current = _redact_pbs_remote_secrets(pbs_remote_get(api, remote))
    except Exception:
        read_failed = True
    blast = [
        f"removes PBS remote {remote!r} — any node-side backup jobs/timers referencing it will "
        "fail afterward",
        "re-adding requires the password/encryption-key to be re-supplied (never captured/"
        "displayed here)",
        "no undo: re-create with pmg_pbs_remote_create",
    ]
    if read_failed:
        blast.append("could not read current PBS remote config — prior value UNKNOWN")
    return Plan(
        action="pmg_pbs_remote_delete", target=f"config/pbs/{remote}",
        change=f"delete PBS remote {remote!r}", current=current, blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[
            "removes a configured external-system backup target; referencing jobs/timers break",
        ],
        complete=not read_failed,
        note="password/encryption-key (if present in current) are UNCONDITIONALLY redacted.",
    )


def plan_node_pbs_snapshot_create(
    node: str, remote: str, notify: str | None = None, statistic: bool | None = None,
) -> Plan:
    """Preview triggering a PBS backup of this PMG's rule database/config to a remote. PURE — no
    API call (the honest affected-count lives behind the remote's own snapshot listing, which this
    plan does not call — mirrors plan_ldap_profile_sync/plan_pbs_job_run's own "nothing capturable
    ahead of a trigger" reasoning).

    RISK_MEDIUM, argued not defaulted: PMG's own schema states this call ALSO prunes the backup
    group afterward, if configured — additive (a new backup) AND may remove older backups per the
    remote's own keep-* retention — the SAME "adds AND may remove data" shape that rates
    plan_pbs_job_run's own "sync" job-type tier RISK_MEDIUM, not the flat RISK_HIGH reserved for a
    bare "prune" job whose entire purpose is deletion.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    if notify is not None:
        notify = _check_backup_notify(notify)
    blast = [
        f"triggers an immediate backup of {node!r}'s PMG rule database/config to PBS remote "
        f"{remote!r}",
        "PMG's own schema states this ALSO prunes the backup group afterward, if configured — "
        "older backups on the remote may be removed per its own keep-* retention settings "
        "(mirrors plan_pbs_job_run's own 'sync' tier: adds AND may remove data, not a bare "
        "additive call)",
        "returns a STRING (UPID vs plain status message unresolved from schema alone — "
        "Smoke-confirm)",
    ]
    change = f"trigger a PBS backup of {node!r}'s PMG config to remote {remote!r}"
    if notify is not None:
        change += f" (notify={notify!r})"
    if statistic is not None:
        change += f" (statistic={statistic})"
    return Plan(
        action="pmg_node_pbs_snapshot_create",
        target=f"pmg/node/{node}/pbs/{remote}/snapshot",
        change=change, current={}, blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[
            "adds a new backup AND may prune older ones per the remote's configured retention — "
            "not a bare additive call",
        ],
        note="Async — the returned string may be a UPID; check pmg_node_pbs_snapshots_list "
             "afterward to confirm.",
    )


def plan_node_pbs_snapshot_forget(
    node: str, remote: str, backup_id: str, backup_time: str,
) -> Plan:
    """Preview forgetting (permanently deleting) a snapshot on a PBS remote. PURE — no API call
    (mirrors pbs_snapshot_delete's own precedent for the PBS-plane's sibling call: no capture, the
    destructive fact stands on its own).

    RISK_HIGH: permanently destroys a specific recovery point on the remote; no undo.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    backup_id = _check_pbs_snapshot_backup_id(backup_id)
    backup_time = _check_pbs_snapshot_backup_time(backup_time)
    return Plan(
        action="pmg_node_pbs_snapshot_forget",
        target=f"pmg/node/{node}/pbs/{remote}/snapshot/{backup_id}/{backup_time}",
        change=(f"forget (permanently delete) snapshot {backup_id!r}@{backup_time!r} on PBS "
                f"remote {remote!r}"),
        current={},
        blast_radius=[
            f"PERMANENTLY DELETES backup snapshot {backup_id!r}@{backup_time!r} on remote "
            f"{remote!r}",
            "this removes a specific recovery point on the remote — it cannot be restored",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "permanently destroys a specific recovery point on the remote PBS instance; no undo "
            "(mirrors pbs_snapshot_delete's identical reasoning)",
        ],
        note="PMG 9.1 schema-verified path: DELETE /nodes/{node}/pbs/{remote}/snapshot/"
             "{backup-id}/{backup-time}.",
    )


def plan_node_pbs_snapshot_restore(
    api: PmgBackend, node: str, remote: str, backup_id: str, backup_time: str,
    config: bool = False, database: bool = True, statistic: bool = False,
) -> Plan:
    """Preview restoring PMG state from a REMOTE PBS snapshot. NOT pure — best-effort CAPTURE:
    (1) confirms the target snapshot actually exists via `node_pbs_snapshot_get`, degrading
    honestly on any read failure — mirrors `plan_backup_restore`'s (9b) own existence pre-check
    exactly, adapted to a remote lookup (`node_pbs_snapshot_get`) in place of `backup_list`; (2)
    when `database=True` (the schema default), reuses this file's own
    `_ruledb_reset_capture_count` + rules/who/what/when/action-object readers VERBATIM — the SAME
    helper `plan_ruledb_reset`/`plan_backup_restore` (9b, local-file restore) use, since
    `database=True` replaces the identical ruledb region.

    RISK_HIGH, unconditional. NO UNDO exists: PMG exposes no restore-preview/diff endpoint for this
    call either — mirrors plan_backup_restore's own "no undo" first blast_radius line exactly,
    extended to a REMOTE source. Take a fresh pmg_node_pbs_snapshot_create beforehand.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    backup_id = _check_pbs_snapshot_backup_id(backup_id)
    backup_time = _check_pbs_snapshot_backup_time(backup_time)

    # Existence check (best-effort, degrades honestly) — mirrors plan_backup_restore's (9b)
    # identical pattern extended to a REMOTE source: confirm the target snapshot is actually
    # present before building the restore plan, rather than silently skipping this half of the
    # precedent while claiming to mirror it exactly.
    exists: bool | None = None
    fail_notes: list[str] = []
    try:
        snaps = node_pbs_snapshot_get(api, node, remote, backup_id) or []
        times = {s.get("backup-time") for s in snaps if isinstance(s, dict)}
        exists = backup_time in times
    except Exception as e:
        fail_notes.append(f"snapshot existence check failed: {type(e).__name__}: {e}")

    counts: dict[str, int | None] = {}
    if database:
        for key, reader in (
            ("rules", lambda: ruledb_rules_list(api)),
            ("who_groups", lambda: who_groups_list(api)),
            ("what_groups", lambda: what_groups_list(api)),
            ("when_groups", lambda: when_groups_list(api)),
            ("action_objects", lambda: action_objects_list(api)),
        ):
            count, fail = _ruledb_reset_capture_count(key, reader)
            counts[key] = count
            if fail:
                fail_notes.append(fail)

    blast = ["Proximo has NO undo for this; take a fresh pmg_node_pbs_snapshot_create first."]
    if exists is False:
        blast.append(
            f"restore will FAIL — snapshot {backup_id!r}@{backup_time!r} was not found via "
            "pmg_node_pbs_snapshot_get"
        )
    elif exists is None:
        blast.append(
            f"could not confirm snapshot {backup_id!r}@{backup_time!r} exists via "
            "pmg_node_pbs_snapshot_get"
        )
    if database:
        def _fmt(key: str) -> str:
            v = counts.get(key)
            return str(v) if v is not None else "an unknown number of"

        blast.append(
            f"REPLACES the entire rule database: {_fmt('rules')} rules, {_fmt('who_groups')} "
            f"who / {_fmt('what_groups')} what / {_fmt('when_groups')} when groups, "
            f"{_fmt('action_objects')} action objects — same scope as pmg_ruledb_reset/"
            "pmg_node_backup_restore"
        )
        if statistic:
            blast.append("ALSO restores mail statistics databases (statistic=True)")
    else:
        blast.append("database=False: the rule database is left untouched")

    if config:
        blast.append(
            "ALSO restores the PMG system configuration from the remote snapshot — Proximo "
            "cannot enumerate the exact scope of 'system configuration' from PMG's schema alone; "
            "treat this as replacing node-wide settings, not just the ruledb"
        )

    blast.extend(fail_notes)

    return Plan(
        action="pmg_node_pbs_snapshot_restore",
        target=f"pmg/node/{node}/pbs/{remote}/snapshot/{backup_id}/{backup_time}",
        change=(f"restore PMG state from PBS remote {remote!r} snapshot {backup_id!r}@"
                f"{backup_time!r} (config={config}, database={database}, statistic={statistic})"),
        current=counts,
        blast_radius=blast,
        risk=RISK_HIGH,
        risk_reasons=[
            "overwrites live PMG state from a REMOTE snapshot with no undo primitive and no "
            "restore-preview/diff endpoint",
            "database=True (the default) replaces the ENTIRE rule database, matching "
            "pmg_ruledb_reset/pmg_node_backup_restore's own destructive scope",
        ],
        complete=not fail_notes,
        note=("No dry-run companion exists upstream. Take a fresh "
              "pmg_node_pbs_snapshot_create before running this with confirm=True."),
    )


def plan_node_pbs_snapshot_verify(
    node: str, remote: str, backup_id: str, backup_time: str,
) -> Plan:
    """Preview verifying a snapshot on a PBS remote. PURE — no API call.

    RISK_LOW: non-destructive integrity check — reads and verifies chunk checksums on the remote;
    no data is modified. Matches pbs_verify_start's identical precedent.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    backup_id = _check_pbs_snapshot_backup_id(backup_id)
    backup_time = _check_pbs_snapshot_backup_time(backup_time)
    return Plan(
        action="pmg_node_pbs_snapshot_verify",
        target=f"pmg/node/{node}/pbs/{remote}/snapshot/{backup_id}/{backup_time}/verify",
        change=f"verify snapshot {backup_id!r}@{backup_time!r} on PBS remote {remote!r}",
        current={},
        blast_radius=[
            "non-destructive integrity check — reads and verifies chunk checksums on the remote; "
            "no data is modified",
            "heavy I/O on the remote PBS instance; may impact its own backup/restore performance "
            "while running",
        ],
        risk=RISK_LOW,
        risk_reasons=["non-destructive integrity check, the pbs_verify_start precedent"],
        note="Schema-confirmed UPID return (an async task on the REMOTE PBS instance) — track via "
             "that instance's own task list, not pve_task_wait/pve_task_status.",
    )


def plan_node_pbs_timer_create(
    api: PmgBackend, node: str, remote: str,
    schedule: str | None = None, delay: str | None = None,
) -> Plan:
    """Preview creating a backup schedule for a PBS remote. CAPTURE: best-effort reads the
    existing timer (degrades honestly on failure) so the plan can flag whether one already appears
    configured — PMG's own create-vs-overwrite behavior here is unconfirmed from the schema alone.

    RISK_LOW: additive scheduling config only — no backup data touched, matches
    pbs_job_create's precedent.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    if schedule is not None:
        schedule = _check_pbs_timer_schedule(schedule)
    if delay is not None:
        delay = _check_pbs_timer_delay(delay)
    current: dict = {}
    read_failed = False
    try:
        current = node_pbs_timer_get(api, node, remote)
    except Exception:
        read_failed = True
    blast = [f"schedules automatic PBS backups of {node!r}'s PMG config to remote {remote!r}"]
    if current.get("schedule") or current.get("next-run"):
        blast.append(
            f"a timer already appears configured (schedule={current.get('schedule')!r}) — "
            "PMG's own create-vs-overwrite behavior here is unconfirmed from the schema alone; "
            "Smoke-confirm whether this silently replaces it or refuses"
        )
    if read_failed:
        blast.append("could not read the current timer — prior state UNKNOWN")
    change = f"create backup schedule for remote {remote!r} on node {node!r}"
    if schedule is not None:
        change += f" (schedule={schedule!r})"
    if delay is not None:
        change += f" (delay={delay!r})"
    return Plan(
        action="pmg_node_pbs_timer_create",
        target=f"pmg/node/{node}/pbs/{remote}/timer",
        change=change, current=current, blast_radius=blast,
        risk=RISK_LOW,
        risk_reasons=["additive scheduling config — no backup data touched, matches pbs_job_create"],
        complete=not read_failed,
    )


def plan_node_pbs_timer_delete(api: PmgBackend, node: str, remote: str) -> Plan:
    """Preview deleting the backup schedule for a PBS remote. CAPTURE: best-effort reads the
    current timer (degrades honestly on failure).

    RISK_LOW: config-only — deletes the SCHEDULE, not backup data, matches pbs_job_delete's
    precedent.
    """
    node = _check_node(node)
    remote = _check_pbs_remote_id(remote)
    current: dict = {}
    read_failed = False
    try:
        current = node_pbs_timer_get(api, node, remote)
    except Exception:
        read_failed = True
    blast = [
        f"removes the scheduled backup timer for PBS remote {remote!r} on node {node!r}",
        "existing backups/snapshots already on the remote are untouched",
        "a backup already in progress when this runs is not affected",
    ]
    if read_failed:
        blast.append("could not read the current timer — prior state UNKNOWN")
    return Plan(
        action="pmg_node_pbs_timer_delete",
        target=f"pmg/node/{node}/pbs/{remote}/timer",
        change=f"delete backup schedule for remote {remote!r} on node {node!r}",
        current=current, blast_radius=blast,
        risk=RISK_LOW,
        risk_reasons=["config-only — deletes the schedule, not backup data, matches pbs_job_delete"],
        complete=not read_failed,
    )


# ===========================================================================
# Wave 9g: ACME accounts/plugins + node cert order/renew/revoke + custom-cert upload
# (full-surface campaign, 2026-07-17)
# ===========================================================================
# Schema truth: `.scratch/api-schemas-2026-07-15/pmg-apidoc-live-2026-07-17.json`,
# `/config/acme/{account[/{name}],plugins[/{id}],tos,meta,directories,challenge-schema}` and
# `/nodes/{node}/certificates/{acme,custom}/{type}` — all 19 methods read field-by-field for this
# build (the exact set classified `"chunk": "9g"` in `.scratch/sdd/wave-9-classification.json`),
# never assumed from the draft's prose alone. Extends pmg.py/tools/pmg_mail.py per campaign
# RULING 5/2 (ACME + node certs are node-infra small enough to share this file — NOT a new
# module; only 9h/9i earn `pmg_identity.py`).
#
# KEY REUSE (dispatch brief's own instruction): this is the SAME upstream ACME implementation
# already shipped for PBS (`pbs_acme.py`, Wave 3b) and PVE (`acme_certs.py`). Every redaction/
# risk/taint decision below was checked against `pbs_acme.py` FIRST and mirrored wherever this
# schema agrees; every place THIS schema disagrees is an explicit, argued PMG-vs-PBS/PVE
# divergence below — never silently copied.
#
# ---------------------------------------------------------------------------------------------
# PMG-vs-PBS/PVE DIVERGENCE TABLE (schema-verified, not assumed):
#  1. **PMG HAS node cert revoke** (`DELETE /nodes/{node}/certificates/acme/{type}` —
#     `revoke_acme_cert`) — PBS has none (fact #1 of pbs_acme.py); PMG matches PVE's
#     `pve_acme_cert_revoke` instead.
#  2. **PMG's node cert endpoints carry a real `{type}` PATH SEGMENT** (`enum: [api, smtp]`,
#     "The TLS certificate type (API or SMTP certificate)") — NEITHER PVE nor PBS has this; both
#     address a single literal `certificate` slot. PMG genuinely runs TWO independent TLS certs
#     per node (the pmgproxy management-API cert and the postfix SMTP-TLS cert) — every node-cert
#     tool below takes an explicit `cert_type` param (avoids shadowing the `type` builtin) and
#     every docstring says which service a given type protects.
#  3. **PMG's ACME-account create/update/delete ALL declare `returns: {"type": "string"}`** —
#     PBS's identical trio declares `null` (pbs_acme.py fact #9). Unconfirmed shape (task-UPID?
#     plain status? the account's own location URL?) — treated with the same honesty as this
#     file's own `network_reload`/`backup_restore`/`snapshot_create` precedent: outcome=
#     "submitted", raw value recorded in BOTH the response and the ledger's own `detail.
#     raw_result`, never assumed synchronous.
#  4. **PMG's node cert order/renew/revoke ALSO declare `returns: {"type": "string"}`** — PVE's
#     identical trio returns a confirmed task UPID (`acme_certs.py`'s own docstrings); PBS has no
#     revoke and its order/renew return `null` (fact #2). A genuinely THIRD shape on this one
#     family across the three planes — same "submitted + raw_result" honesty as #3, NOT assumed
#     to be a UPID just because PVE's sibling is one.
#  5. **PMG's ACME plugin `type` (challenge type) DOES declare a closed enum** (`{dns,
#     standalone}`) — PBS's identical field is a bare open string (pbs_acme.py fact #8). Small,
#     protocol-level, unlikely to grow (ACME challenge TYPES are an ACME-protocol concept, not a
#     provider catalog) — validated strictly against the enum, unlike `api` below.
#  6. **PMG's ACME plugin `api` (DNS provider shortcode) ALSO declares a closed enum — currently
#     ~155 provider names.** Deliberately NOT hardcoded here despite being real (unlike #5): this
#     is a third-party DNS-provider catalog (acme.sh's own dnsapi list) that grows with every
#     upstream PMG/acme.sh release; hardcoding today's snapshot risks Proximo becoming a stale
#     gatekeeper that REJECTS a provider PMG itself already supports after its next update. Same
#     reasoning pbs_acme.py's fact #8 gives for its OWN (enum-less) `type` field, applied here
#     even though PMG's schema currently ships a concrete list PBS's never did — validated by a
#     defensive charset (lowercase alnum/underscore/hyphen) instead. Argued divergence, flagged
#     for the reviewer: the alternative (hardcode the enum) is defensible too, just a different
#     staleness/strictness trade-off.
#  7. **PMG's ACME plugin LIST is genuinely thin** (`GET /config/acme/plugins` returns only
#     `{"plugin": <id>}` per item, schema-confirmed) — UNLIKE PBS, whose list returns the FULL
#     config including the raw `data` credential blob (pbs_acme.py fact #4, MANDATORY strip
#     there). PMG's single-item `GET /config/acme/plugins/{id}` is bare/untyped (`{"type":
#     "object"}`) — genuinely unconfirmed either way. Both are DEFENSIVELY stripped of `data`
#     anyway (the mature post-9c-review discipline: strip regardless of confirmed absence, cost
#     is trivial) — see THE SECRET CONTRACT below.
#  8. **PMG's ACME plugin `delete` (update-time property-clear) is typed a plain STRING**
#     (format 'pve-configid-list', maxLength 4096) — PBS's identical field is `list[str]`
#     (pbs_acme.py's own `_check_plugin_delete_props`). Matches THIS FILE's own established
#     string-typed `delete` convention (`ldap_profile_config_update`, `pbs_remote_update`), not
#     PBS's list convention — validated as a comma-joined string against the SAME closed set of
#     THIS endpoint's own writable optional properties (api/data/disable/nodes/validation-delay).
#  9. **PMG's custom-cert-upload response is a RICH typed object** (filename/fingerprint/issuer/
#     notafter/notbefore/pem/public-key-bits/public-key-type/san/subject — all PUBLIC cert
#     material, schema-confirmed) — richer than PVE's own thin/Smoke-confirm dict-or-None
#     (`node_lifecycle.py`'s `pve_node_cert_upload`). No private-key field anywhere in this
#     return — confirmed field-by-field, matching THE SECRET CONTRACT's "no read-side concern"
#     entry for `key` below.
#  10. **`GET /config/acme/meta` has no PBS equivalent at all** (pbs_acme.py's own endpoint table
#      never lists it) — a genuinely NEW read this wave, not a PBS-parity gap. Same caller-chosen-
#      `directory`-URL shape as `tos` — ADVERSARIAL for the identical reason.
#  11. **PMG's `PUT /config/acme/account/{name}` (account_update) explicitly documents that
#      calling it with NO new fields is a MEANINGFUL, valid action** ("not specifying any new
#      account information triggers a refresh") — a deliberate, schema-stated EXCEPTION to this
#      codebase's usual "at least one field" guard (mirrors pbs_acme.py, which also has no such
#      guard on its own `acme_account_update`). No guard is added here either.
#
# ---------------------------------------------------------------------------------------------
# THE SECRET CONTRACT (three shapes, per the dispatch brief's own framing — §5 of the draft):
#  - **ACME account `eab-hmac-key` + `eab-kid`** (External Account Binding, POST-only per PMG's
#    own schema — PUT/update accepts only `contact`): never confirmed to echo on ANY account read
#    (list item schema is blank/`{}`; single-item GET's declared properties are
#    `account/directory/location/tos` only, no EAB field anywhere) — DEFENSIVE strip on both list
#    and single-item read anyway (silence is not evidence of absence, the standing doctrine).
#    Never-in-ledger on `account_create` (the only verb that accepts these fields at all).
#  - **ACME plugin `data`** (base64 DNS-API credential blob): DEFENSIVE strip on BOTH
#    `pmg_acme_plugin_list` (schema-confirmed thin/id-only — divergence #7 above) AND
#    `pmg_acme_plugin_get` (schema-bare) — mirrors `_redact_plugin_kw` from BOTH `pbs_acme.py`
#    and `acme_certs.py` exactly for the write-side redaction (create/update never let `data`
#    reach a plan string or the ledger). Direct reuse of the established idiom, fresh per-family
#    copy per this codebase's convention (not cross-imported).
#  - **Custom cert upload `key`** (PEM private key, REQUIRED on `POST .../certificates/custom/
#    {type}` per PMG's own schema — `optional: 0`, unlike PVE's optional `key`): UNCONDITIONALLY
#    redacted — never enters the plan factory, the ledger, or `Plan.current`/`change`/`blast_
#    radius`, mirroring `node_lifecycle.py`'s `_key_fingerprint()` "never even a hash" posture
#    exactly. No read anywhere on this plane ever returns raw key material (divergence #9) — the
#    richer response is 100% safe to pass straight through.
#  - **ACME `tos`/`meta` directory-URL fetch**: `pmg_acme_tos`/`pmg_acme_meta` both accept a
#    caller-chosen `directory` (a CA directory URL) and the PMG HOST fetches it live — the exact
#    `pbs_acme_tos` precedent (Wave 3b), extended to a SECOND endpoint here (divergence #10).
#    Both are classified ADVERSARIAL in `taint.py` and both validate `directory` https-only,
#    STRICTER than the schema (which permits bare `^https?://.*`) — RFC 8555 §7.1 requires https
#    for ACME directories anyway, and this closes the same SSRF-shaped gap `pbs_acme.py`'s
#    `_check_acme_url` review finding closed. `pmg_acme_account_create`'s own `directory`/
#    `tos_url` params get the SAME https-only validator (a mutation, not a plain read, but the
#    PMG host still makes the same outbound connection).
#  - Hunt for a THIRD/FOURTH secret (the 7d/9f law): checked every 9g method's params+returns
#    field-by-field — no other token/key/cert/hmac-shaped field exists beyond the three above.
#    `contact`/`tos_url`/`directory` are CA-facing metadata, not secrets. `certificates` (the
#    cert chain) is PUBLIC and appears in plans/logs. `nodes` (which cluster nodes use a plugin)
#    is a plain identifier list. `fingerprint`/`issuer`/`subject`/`san`/`pem` on the custom-cert-
#    upload response are all PUBLIC cert material (divergence #9).
#
# Taint: `pmg_acme_tos`/`pmg_acme_meta` are ADVERSARIAL (see THE SECRET CONTRACT above). Every
# other read on this chunk is REVIEWED_TRUSTED after the defensive secret-strip: account/plugin
# list+get are operator-authored config (post-strip), `directories`/`challenge_schema` are
# PMG's own static built-in catalogs (no caller-influenced URL — unlike tos/meta, these two take
# NO `directory` param at all). Every mutation's return is either `null`, a schema-CONFIRMED-
# ambiguous STRING (divergences #3/#4), or (custom-cert-upload) a small typed PUBLIC-cert-only
# object — REVIEWED_TRUSTED regardless of blast radius (taint classifies the RETURN channel, not
# the mutation's consequences — the standing rule since Wave 4c/4d).
#
# digest: schema-verified field-by-field — ONLY `PUT /config/acme/plugins/{id}` (plugin_update)
# carries a `digest` param among this chunk's 19 methods (maxLength 64, no pattern — a fresh
# per-family copy, this file's own established "each family gets its own digest validator"
# convention). Forwarded only where the schema offers it, never invented elsewhere (the Wave 9a
# "don't invent a digest param" lesson).
#
# Callable-outcome (verified per method, never recited — divergences #3/#4 above):
#  `POST/PUT/DELETE /config/acme/account[/{name}]` (account create/update/delete) and
#  `POST/PUT/DELETE /nodes/{node}/certificates/acme/{type}` (cert order/renew/revoke) ALL
#  schema-type a bare STRING with no UPID-vs-status-message resolution possible from the schema
#  alone — outcome="submitted", the raw string recorded BOTH in the response `result` and the
#  ledger's own `detail.raw_result` (the 9a/9b/9f `network_reload`/`backup_restore`/
#  `snapshot_create` idiom, not invented fresh here). `POST/PUT/DELETE /config/acme/plugins[/
#  {id}]` (plugin create/update/delete) all schema-type `returns: null` — outcome="ok".
#  `DELETE /nodes/{node}/certificates/custom/{type}` (custom_delete) also types `null` —
#  outcome="ok". `POST /nodes/{node}/certificates/custom/{type}` (custom_upload) types a small
#  RICH object (divergence #9) — NOT ambiguous, outcome="ok".
#
# Risk (argued per method, cross-tool-consistent with the shipped PBS/PVE siblings — the 9e
# "ratings consistent with twins" lesson):
#  - `pmg_acme_account_create`: RISK_MEDIUM — registers with the external CA, matches
#    `pbs_acme_account_create` exactly.
#  - `pmg_acme_account_update`: RISK_LOW — contact-metadata update only (or a bare CA refresh per
#    divergence #11), no cert impact, matches `pbs_acme_account_update` exactly.
#  - `pmg_acme_account_delete`: RISK_HIGH — DEACTIVATES the account AT THE CA (not just local
#    config removal), matches `pbs_acme_account_delete`/`acme_certs.py`'s identical rating.
#  - `pmg_acme_plugin_create`/`_update`: RISK_MEDIUM — creates/updates a credential-bearing DNS
#    challenge plugin, matches `pbs_acme_plugin_create`/`_update` exactly.
#  - `pmg_acme_plugin_delete`: RISK_HIGH — breaks auto-renewal for every domain using this
#    plugin's challenge method, matches `pbs_acme_plugin_delete` exactly.
#  - `pmg_node_cert_acme_order`/`_renew`: RISK_MEDIUM — CA-validated, installs ONLY on a
#    successful challenge (a failure cannot lock you out), matches `pve_acme_cert_order`/
#    `_renew`'s and `pbs_acme_cert_order`/`_renew`'s identical reasoning.
#  - `pmg_node_cert_acme_revoke`: RISK_HIGH, IRREVERSIBLE at the CA — matches
#    `pve_acme_cert_revoke` exactly (the tool PBS never shipped, divergence #1).
#  - `pmg_node_cert_custom_upload`: RISK_HIGH, no undo — matches `pve_node_cert_upload`/
#    `pbs_node_cert_upload`'s identical "a malformed cert/key can lock you out" reasoning, NOT
#    downgraded to MEDIUM despite the draft's own hedge (consistent-rating-with-twins). PMG's own
#    dual-cert-type model (divergence #2) makes the BLAST TEXT direction-aware rather than the
#    RISK tier conditional: `cert_type='api'` names web-UI/API lockout, `cert_type='smtp'` names
#    mail-TLS/relay breakage — both HIGH, argued per the Wave-7b direction-aware-docstring lesson
#    the draft itself cites, not a flat generic warning repeated for both.
#  - `pmg_node_cert_custom_delete`: RISK_MEDIUM — reverts to PMG's self-signed cert for that slot,
#    recoverable by re-uploading, matches `pve_node_cert_delete`/`pbs_node_cert_delete` exactly.
#  - Reads: all RISK-free (not mutations); taint classification above.
#
# CAPTURE evidence (deferred import, mirrors `plan_service_control`'s own established
# `pmg_node.py` cross-reference precedent above): `plan_node_cert_acme_revoke`/
# `plan_node_cert_custom_upload`/`plan_node_cert_custom_delete` all best-effort read
# `pmg_node.py`'s already-shipped `certificates_info` (9a, `GET /nodes/{node}/certificates/info`
# — PUBLIC cert data only) as EVIDENCE of what is about to be replaced/removed, degrading
# honestly (`complete=False`) on a read failure — mirrors `acme_certs.py`'s own
# `plan_acme_cert_revoke` CAPTURE-as-evidence idiom exactly. `pmg_node_cert_acme_order`/`_renew`
# stay PURE (no read) — matches `acme_certs.py`'s identical order/renew-vs-revoke split.

# --- Validators ---

# ACME account name: format 'pve-configid' per the live schema, default 'default' — no length
# bound declared; a defensive 256-char cap (not schema-derived), matching pbs_acme.py's own
# account-name bound exactly for the identical field shape.
_ACME_ACCOUNT_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,255}\Z")


def _check_acme_account_name(name: str) -> str:
    # Do NOT strip — \Z must catch trailing newlines (this file's own established discipline).
    s = str(name)
    if not _ACME_ACCOUNT_NAME_RE.match(s):
        raise ProximoError(
            f"invalid ACME account name: {name!r} "
            "(pve-configid format: alnum/./_/-, start with alnum/underscore, <=256 chars, "
            "no control chars)"
        )
    return s


# ACME plugin ID: format 'pve-configid' per the live schema — no length bound declared; a
# defensive 64-char cap (not schema-derived), matching this file's own `_check_pbs_remote_id`
# and `acme_certs.py`'s PVE-side plugin-id bound.
_ACME_PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,63}\Z")


def _check_acme_plugin_id(plugin_id: str) -> str:
    s = str(plugin_id)
    if not _ACME_PLUGIN_ID_RE.match(s):
        raise ProximoError(
            f"invalid ACME plugin ID: {plugin_id!r} "
            "(pve-configid format: alnum/./_/-, start with alnum/underscore, <=64 chars, "
            "no control chars)"
        )
    return s


# ACME plugin challenge type: schema-confirmed closed enum (divergence #5 above) — small and
# protocol-level, validated strictly (unlike `api` below).
_ACME_CHALLENGE_TYPES = frozenset({"dns", "standalone"})


def _check_acme_challenge_type(value: str) -> str:
    s = str(value)
    if s not in _ACME_CHALLENGE_TYPES:
        raise ProximoError(
            f"invalid ACME plugin challenge type: {value!r} "
            f"(expected one of {sorted(_ACME_CHALLENGE_TYPES)})"
        )
    return s


# ACME plugin DNS-provider API name: schema currently declares a ~155-entry enum, deliberately
# NOT hardcoded here (divergence #6 above — staleness risk on a fast-growing third-party
# catalog). Defensive charset only: lowercase alnum/underscore/hyphen, a generous bound.
_ACME_PLUGIN_API_RE = re.compile(r"^[a-z0-9_-]{1,64}\Z")


def _check_acme_plugin_api(value: str) -> str:
    s = str(value)
    if not _ACME_PLUGIN_API_RE.match(s):
        raise ProximoError(
            f"invalid ACME plugin API/provider name: {value!r} "
            "(expected lowercase alnum/_/-, 1-64 chars — the live schema's own enum is a "
            "~155-entry third-party DNS-provider catalog that grows every acme.sh release; "
            "validated defensively by charset instead of a hardcoded list — see pmg_acme_challenge_"
            "schema for PMG's own live catalog)"
        )
    return s


# ACME account `contact`: format 'email-list' per the live schema — a comma-separated list of
# RFC 8555-style contact addresses (conventionally "mailto:user@example.com", but a bare
# "user@example.com" is accepted too — the charset below permits both). No length bound
# declared; a defensive 1024-char cap on the whole value.
_ACME_CONTACT_ADDR_RE = re.compile(r"^[^\s\\@,]+@[^\s/\\@,]+\Z")


def _check_acme_contact(value: str) -> str:
    s = str(value)
    if len(s) > 1024:
        raise ProximoError(f"invalid ACME contact: too long ({len(s)} chars, max 1024)")
    for part in s.split(","):
        if not _ACME_CONTACT_ADDR_RE.match(part):
            raise ProximoError(
                f"invalid ACME contact address: {part!r} in {value!r} "
                "(comma-separated email-list; each address must match user@domain shape "
                "or mailto:user@domain, no whitespace)"
            )
    return s


# ACME directory/ToS URLs: schema declares a bare `^https?://.*` pattern (permits http) — this
# validator is STRICTER THAN SCHEMA BY CHOICE, mirroring pbs_acme.py's own `_check_acme_url`
# review finding exactly: the value makes the PMG HOST issue an outbound fetch, so https-only is
# enforced (RFC 8555 §7.1 requires https for ACME directories anyway) plus no whitespace/control
# chars (header/path-injection guard).
_MAX_ACME_URL_LEN = 512


def _check_acme_directory_url(url: str, field: str) -> str:
    s = str(url)
    if (
        not s.startswith("https://")
        or len(s) > _MAX_ACME_URL_LEN
        or any(c.isspace() or ord(c) < 0x20 for c in s)
    ):
        raise ProximoError(
            f"invalid {field}: {url!r} (must be an https:// URL, no whitespace/control "
            f"characters, <={_MAX_ACME_URL_LEN} chars)"
        )
    return s


def _check_acme_plugin_digest(digest: str | None) -> str | None:
    """maxLength 64, no pattern — the schema's own bound on `PUT /config/acme/plugins/{id}`'s
    digest (a SEPARATE, narrower-by-convention validator from every other per-family digest
    check in this file — `_check_ldap_config_digest`/`_check_customscores_digest`/
    `_check_pbs_remote_digest` — each family keeps its own copy, not a shared one)."""
    if digest is None:
        return None
    s = str(digest)
    if len(s) > 64:
        raise ProximoError(f"invalid digest: too long ({len(s)} chars, max 64)")
    return s


def _check_acme_plugin_nodes(value: str) -> str:
    """format 'pve-node-list' per the live schema — a comma-separated list of PMG node names
    restricting which node(s) run this plugin. Each segment validated with `_check_node` (this
    file's own node-name validator); the joined, validated string is what reaches the wire."""
    s = str(value)
    parts = [p for p in s.split(",")]
    if not parts or any(not p for p in parts):
        raise ProximoError(f"invalid ACME plugin nodes: {value!r} (comma-separated node names)")
    for p in parts:
        _check_node(p)
    return s


_ACME_PLUGIN_DELETE_MAXLEN = 4096

# The closed set of THIS endpoint's own writable optional properties (id/type/digest/delete are
# not themselves deletable) — derived from `PUT /config/acme/plugins/{id}`'s own schema, the same
# closed-set discipline `pbs_acme.py`'s `_check_plugin_delete_props` applies to its own
# list[str]-typed sibling field (divergence #8 above: PMG types this a comma-STRING, not a list).
_ACME_PLUGIN_DELETE_PROPS = frozenset({"api", "data", "disable", "nodes", "validation-delay"})


def _check_acme_plugin_delete_props(value: str) -> str:
    s = str(value)
    if not s:
        raise ProximoError("delete must not be empty")
    if len(s) > _ACME_PLUGIN_DELETE_MAXLEN:
        raise ProximoError(
            f"invalid delete: too long ({len(s)} chars, max {_ACME_PLUGIN_DELETE_MAXLEN})"
        )
    for prop in s.split(","):
        if prop not in _ACME_PLUGIN_DELETE_PROPS:
            raise ProximoError(
                f"invalid ACME plugin delete property: {prop!r} in {value!r} "
                f"(expected one of {sorted(_ACME_PLUGIN_DELETE_PROPS)})"
            )
    return s


_MAX_ACME_VALIDATION_DELAY = 172800


def _check_acme_validation_delay(value) -> int:
    # Reject non-int types outright (a float like 12.9 must not silently truncate — the Wave 3b
    # review finding, mirrored here). bool is an int subclass — reject it too.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProximoError(f"invalid validation-delay: {value!r} (must be an integer)")
    if not (0 <= value <= _MAX_ACME_VALIDATION_DELAY):
        raise ProximoError(
            f"invalid validation-delay: {value} (must be 0-{_MAX_ACME_VALIDATION_DELAY} "
            "per the live schema)"
        )
    return value


# Node cert type: schema-confirmed closed enum (divergence #2 above) — PMG's dual-cert-slot
# model (the management-API cert vs the postfix SMTP-TLS cert).
_PMG_CERT_TYPES = frozenset({"api", "smtp"})


def _check_pmg_cert_type(value: str) -> str:
    s = str(value)
    if s not in _PMG_CERT_TYPES:
        raise ProximoError(
            f"invalid PMG certificate type: {value!r} (expected one of {sorted(_PMG_CERT_TYPES)})"
        )
    return s


# --- Redaction helpers ---

_ACME_ACCOUNT_SECRET_KEYS = frozenset({"eab-hmac-key", "eab-kid"})
_ACME_PLUGIN_SECRET_KEYS = frozenset({"data"})


def _redact_acme_account_kw(kw: dict) -> dict:
    """Mask `eab-hmac-key`/`eab-kid` before they enter a plan string or the ledger — defensive on
    the CAPTURE-read side (module section docstring above: no account read schema declares
    either field, but redacted anyway rather than assume that never changes)."""
    return redact_secrets(kw, _ACME_ACCOUNT_SECRET_KEYS)


def _redact_acme_plugin_kw(kw: dict) -> dict:
    """Mask the DNS-provider credential blob (`data`) before it enters a plan string or the
    ledger. Mirrors `_redact_plugin_kw` from BOTH `pbs_acme.py` and `acme_certs.py` exactly."""
    return redact_secrets(kw, _ACME_PLUGIN_SECRET_KEYS)


def _strip_acme_account_secrets_at_read(data: dict) -> dict:
    """Read-layer strip for `acme_account_list`/`acme_account_get` — DEFENSIVE (neither read
    schema confirms `eab-hmac-key`/`eab-kid` echo, but silence is not evidence of absence, the
    standing doctrine)."""
    return {k: v for k, v in data.items() if k not in _ACME_ACCOUNT_SECRET_KEYS}


def _strip_acme_plugin_secrets_at_read(data: dict) -> dict:
    """Read-layer strip for `acme_plugins_list`/`acme_plugin_get` — DEFENSIVE (the list schema is
    confirmed THIN/id-only — divergence #7 — and the single-item GET is schema-bare; stripped
    regardless of confirmed absence, the mature post-9c-review discipline)."""
    return {k: v for k, v in data.items() if k not in _ACME_PLUGIN_SECRET_KEYS}


# --- Backend functions: ACME accounts ---

def acme_account_list(api: PmgBackend) -> list[dict]:
    """List registered ACME account names.

    GET /config/acme/account

    Schema declares a blank per-item shape (`{}`) — genuinely thin/unconfirmed. DEFENSIVE strip
    of eab-hmac-key/eab-kid applied anyway.
    """
    items = api._get("/config/acme/account") or []
    return [_strip_acme_account_secrets_at_read(i) if isinstance(i, dict) else i for i in items]


def acme_account_get(api: PmgBackend, name: str = "default") -> dict:
    """Read one ACME account's full detail.

    GET /config/acme/account/{name}

    Returns {account (yaml-rendered), directory, location, tos} — no eab-hmac-key/eab-kid field
    declared anywhere in this schema. DEFENSIVE strip applied anyway.
    """
    name = _check_acme_account_name(name)
    data = api._get(f"/config/acme/account/{name}") or {}
    return _strip_acme_account_secrets_at_read(data)


# --- Backend functions: ACME plugins ---

def acme_plugins_list(api: PmgBackend, plugin_type: str | None = None) -> list[dict]:
    """List all configured ACME DNS/standalone challenge plugins.

    GET /config/acme/plugins

    Schema-confirmed THIN item shape (`{"plugin": <id>}` only, divergence #7 above) — does NOT
    echo `data` per the schema, but DEFENSIVELY stripped anyway (the mature post-9c discipline).
    """
    params = {}
    if plugin_type is not None:
        params["type"] = _check_acme_challenge_type(plugin_type)
    items = api._get("/config/acme/plugins", params=params or None) or []
    return [_strip_acme_plugin_secrets_at_read(i) if isinstance(i, dict) else i for i in items]


def acme_plugin_get(api: PmgBackend, plugin_id: str) -> dict:
    """Read one ACME plugin's full config.

    GET /config/acme/plugins/{id}

    Schema-bare (`{"type": "object"}`, genuinely unconfirmed whether `data` echoes here) —
    DEFENSIVELY stripped anyway.
    """
    plugin_id = _check_acme_plugin_id(plugin_id)
    data = api._get(f"/config/acme/plugins/{plugin_id}") or {}
    return _strip_acme_plugin_secrets_at_read(data)


# --- Backend functions: ACME CA metadata (tos/meta/directories/challenge-schema) ---

def acme_tos(api: PmgBackend, directory: str | None = None) -> str | None:
    """Retrieve the ACME Terms-of-Service URL for a CA directory. Deprecated by PMG in favor of
    acme_meta, per the schema's own description — kept here since PMG still exposes it.

    GET /config/acme/tos

    ADVERSARIAL: the PMG host fetches `directory` (caller-chosen, https-only validated) live —
    the response content is authored by whoever controls that URL.
    """
    if directory is not None:
        directory = _check_acme_directory_url(directory, "directory")
    params = {"directory": directory} if directory is not None else None
    return api._get("/config/acme/tos", params=params)


def acme_meta(api: PmgBackend, directory: str | None = None) -> dict:
    """Retrieve ACME directory meta information (externalAccountRequired, termsOfService,
    caaIdentities, website).

    GET /config/acme/meta

    ADVERSARIAL: same caller-chosen-`directory`-fetch shape as acme_tos (divergence #10 — PBS
    has no equivalent endpoint at all).
    """
    if directory is not None:
        directory = _check_acme_directory_url(directory, "directory")
    params = {"directory": directory} if directory is not None else None
    return api._get("/config/acme/meta", params=params) or {}


def acme_directories(api: PmgBackend) -> list[dict]:
    """List PMG's built-in catalog of known ACME CA directory endpoints (name + URL pairs).

    GET /config/acme/directories

    No params — static catalog, REVIEWED_TRUSTED (no caller-influenced URL fetch here, unlike
    tos/meta above).
    """
    return api._get("/config/acme/directories") or []


def acme_challenge_schema(api: PmgBackend) -> list[dict]:
    """List the catalog of known ACME challenge plugin types (id/name/schema/type per entry) —
    the live parameter schema each real `plugin_type`+`api`+`data` combination must satisfy.

    GET /config/acme/challenge-schema

    No params — static catalog, REVIEWED_TRUSTED.
    """
    return api._get("/config/acme/challenge-schema") or []


# --- Backend functions: ACME account mutations ---

def acme_account_create(
    api: PmgBackend,
    contact: str,
    name: str | None = None,
    directory: str | None = None,
    eab_hmac_key: str | None = None,
    eab_kid: str | None = None,
    tos_url: str | None = None,
) -> object:
    """Register a new ACME account with the CA.

    POST /config/acme/account

    Returns a STRING (schema-confirmed, divergence #3) — Smoke-confirm the exact shape; passed
    through unchanged, no shape invented. `name` defaults to PMG's own 'default' if omitted.
    MUTATION — confirm-gated + audited at the server layer.
    """
    contact = _check_acme_contact(contact)
    data: dict = {"contact": contact}
    if name is not None:
        data["name"] = _check_acme_account_name(name)
    if directory is not None:
        data["directory"] = _check_acme_directory_url(directory, "directory")
    if eab_hmac_key is not None:
        data["eab-hmac-key"] = eab_hmac_key
    if eab_kid is not None:
        data["eab-kid"] = eab_kid
    if tos_url is not None:
        data["tos_url"] = _check_acme_directory_url(tos_url, "tos_url")
    return api._post("/config/acme/account", data=data)


def acme_account_update(api: PmgBackend, name: str = "default", contact: str | None = None) -> object:
    """Update ACME account contact info — or, per PMG's own description, trigger a CA refresh if
    `contact` is omitted entirely (divergence #11: a deliberate, schema-stated exception to the
    usual "at least one field" guard — none is enforced here).

    PUT /config/acme/account/{name}

    Returns a STRING (schema-confirmed, divergence #3). MUTATION — confirm-gated + audited at
    the server layer.
    """
    name = _check_acme_account_name(name)
    data: dict = {}
    if contact is not None:
        data["contact"] = _check_acme_contact(contact)
    return api._put(f"/config/acme/account/{name}", data=data)


def acme_account_delete(api: PmgBackend, name: str = "default", force: bool = False) -> object:
    """DEACTIVATE an ACME account at the CA (not just local config removal) and delete the local
    record.

    DELETE /config/acme/account/{name}

    `force`: delete local data even if the CA refuses to deactivate. Returns a STRING
    (schema-confirmed, divergence #3). MUTATION — confirm-gated + audited at the server layer.
    """
    name = _check_acme_account_name(name)
    params = {"force": 1} if force else {}
    return api._delete(f"/config/acme/account/{name}", params=params or None)


# --- Backend functions: ACME plugin mutations ---

def acme_plugin_create(
    api: PmgBackend,
    plugin_id: str,
    plugin_type: str,
    dns_api: str | None = None,
    data: str | None = None,
    disable: bool | None = None,
    nodes: str | None = None,
    validation_delay: int | None = None,
) -> None:
    """Create an ACME DNS/standalone challenge plugin.

    POST /config/acme/plugins

    `dns_api` (client param name — PMG's own wire field is literally `api`, the DNS provider
    shortcode; renamed to dodge the collision, mirrors pbs_acme.py's identical convention).
    `data` = base64-encoded DNS provider credential blob (never-in-ledger, THE SECRET CONTRACT).
    Returns null. MUTATION — confirm-gated + audited at the server layer.
    """
    plugin_id = _check_acme_plugin_id(plugin_id)
    plugin_type = _check_acme_challenge_type(plugin_type)
    body: dict = {"id": plugin_id, "type": plugin_type}
    if dns_api is not None:
        body["api"] = _check_acme_plugin_api(dns_api)
    if data is not None:
        body["data"] = data
    if disable is not None:
        body["disable"] = bool(disable)
    if nodes is not None:
        body["nodes"] = _check_acme_plugin_nodes(nodes)
    if validation_delay is not None:
        body["validation-delay"] = _check_acme_validation_delay(validation_delay)
    return api._post("/config/acme/plugins", data=body)


def acme_plugin_update(
    api: PmgBackend,
    plugin_id: str,
    dns_api: str | None = None,
    data: str | None = None,
    disable: bool | None = None,
    nodes: str | None = None,
    validation_delay: int | None = None,
    digest: str | None = None,
    delete: str | None = None,
) -> None:
    """Update an ACME DNS/standalone challenge plugin.

    PUT /config/acme/plugins/{id}

    `digest` is the ONLY optimistic-lock on this chunk (module section fact above). `delete` is a
    comma-string closed to THIS endpoint's own writable optional properties (divergence #8).
    Returns null. MUTATION — confirm-gated + audited at the server layer.
    """
    plugin_id = _check_acme_plugin_id(plugin_id)
    body: dict = {}
    if dns_api is not None:
        body["api"] = _check_acme_plugin_api(dns_api)
    if data is not None:
        body["data"] = data
    if disable is not None:
        body["disable"] = bool(disable)
    if nodes is not None:
        body["nodes"] = _check_acme_plugin_nodes(nodes)
    if validation_delay is not None:
        body["validation-delay"] = _check_acme_validation_delay(validation_delay)
    if digest is not None:
        body["digest"] = _check_acme_plugin_digest(digest)
    if delete is not None:
        body["delete"] = _check_acme_plugin_delete_props(delete)
    return api._put(f"/config/acme/plugins/{plugin_id}", data=body)


def acme_plugin_delete(api: PmgBackend, plugin_id: str) -> None:
    """Delete an ACME DNS/standalone challenge plugin.

    DELETE /config/acme/plugins/{id}

    Returns null. MUTATION — confirm-gated + audited at the server layer.
    """
    plugin_id = _check_acme_plugin_id(plugin_id)
    return api._delete(f"/config/acme/plugins/{plugin_id}")


# --- Backend functions: node cert order/renew/revoke (ACME-issued) ---

def node_cert_acme_order(
    api: PmgBackend, node: str, cert_type: str, force: bool = False,
) -> object:
    """Order a NEW ACME certificate for one of the node's two cert slots.

    POST /nodes/{node}/certificates/acme/{type}

    `cert_type` in {api, smtp} — PMG's dual-cert-slot model (divergence #2). Returns a STRING
    (schema-confirmed, divergence #4) — Smoke-confirm the exact shape, no UPID assumed. MUTATION
    — confirm-gated + audited at the server layer.
    """
    node = _check_node(node)
    cert_type = _check_pmg_cert_type(cert_type)
    data = {"force": 1} if force else {}
    return api._post(f"/nodes/{node}/certificates/acme/{cert_type}", data=data)


def node_cert_acme_renew(
    api: PmgBackend, node: str, cert_type: str, force: bool = False,
) -> object:
    """Renew the node's existing ACME certificate for one cert slot, if within its renewal lead
    time (or always, if force).

    PUT /nodes/{node}/certificates/acme/{type}

    Returns a STRING (schema-confirmed, divergence #4). MUTATION — confirm-gated + audited at
    the server layer.
    """
    node = _check_node(node)
    cert_type = _check_pmg_cert_type(cert_type)
    data = {"force": 1} if force else {}
    return api._put(f"/nodes/{node}/certificates/acme/{cert_type}", data=data)


def node_cert_acme_revoke(api: PmgBackend, node: str, cert_type: str) -> object:
    """Revoke the node's ACME certificate for one cert slot AT THE CA. IRREVERSIBLE.

    DELETE /nodes/{node}/certificates/acme/{type}

    PMG's own tool PBS never shipped (divergence #1). Returns a STRING (schema-confirmed,
    divergence #4). MUTATION — confirm-gated + audited at the server layer.
    """
    node = _check_node(node)
    cert_type = _check_pmg_cert_type(cert_type)
    return api._delete(f"/nodes/{node}/certificates/acme/{cert_type}")


# --- Backend functions: node custom-cert upload/delete ---

def node_cert_custom_upload(
    api: PmgBackend,
    node: str,
    cert_type: str,
    certificates: str,
    key: str,
    force: bool = False,
    restart: bool = False,
) -> dict:
    """Upload or replace the custom TLS certificate + key for one of the node's two cert slots.

    POST /nodes/{node}/certificates/custom/{type}

    `key` is REQUIRED per PMG's own schema (unlike PVE's optional key) — UNCONDITIONALLY
    redacted (THE SECRET CONTRACT), never passed to this function's caller in any logged form.
    Returns a RICH typed object (filename/fingerprint/issuer/notafter/notbefore/pem/public-key-
    bits/public-key-type/san/subject — all PUBLIC, divergence #9) — outcome="ok", no shape
    ambiguity. MUTATION — confirm-gated + audited at the server layer.
    """
    node = _check_node(node)
    cert_type = _check_pmg_cert_type(cert_type)
    data: dict = {"certificates": certificates, "key": key}
    if force:
        data["force"] = 1
    if restart:
        data["restart"] = 1
    return api._post(f"/nodes/{node}/certificates/custom/{cert_type}", data=data) or {}


def node_cert_custom_delete(
    api: PmgBackend, node: str, cert_type: str, restart: bool = False,
) -> None:
    """Delete the custom TLS certificate + key for one of the node's two cert slots — PMG
    reverts to its self-signed cert for that slot.

    DELETE /nodes/{node}/certificates/custom/{type}

    Returns null. MUTATION — confirm-gated + audited at the server layer.
    """
    node = _check_node(node)
    cert_type = _check_pmg_cert_type(cert_type)
    params = {"restart": 1} if restart else {}
    return api._delete(f"/nodes/{node}/certificates/custom/{cert_type}", params=params or None)


# --- Plan factories: ACME accounts ---

def plan_acme_account_create(
    contact: str,
    name: str | None = None,
    directory: str | None = None,
    eab_hmac_key: str | None = None,
    eab_kid: str | None = None,
    tos_url: str | None = None,
) -> Plan:
    """Preview registering an ACME account. PURE — no API read (PMG may assign the account name
    itself if `name` is omitted, so there is nothing existing to read — mirrors
    `pbs_acme.py`'s own `plan_acme_account_create` reasoning exactly).

    RISK_MEDIUM: registers with the external CA.
    """
    kw = {
        "name": _check_acme_account_name(name) if name is not None else None,
        "directory": _check_acme_directory_url(directory, "directory") if directory is not None else None,
        "eab-hmac-key": eab_hmac_key, "eab-kid": eab_kid,
        "tos_url": _check_acme_directory_url(tos_url, "tos_url") if tos_url is not None else None,
    }
    kw = {k: v for k, v in kw.items() if v is not None}
    contact = _check_acme_contact(contact)
    tgt = f"config/acme/account/{name}" if name else "config/acme/account"
    return Plan(
        action="pmg_acme_account_create",
        target=tgt,
        change=f"register PMG ACME account (contact: {contact!r}): {_redact_acme_account_kw(kw)}",
        current={},
        blast_radius=["registers a new ACME account with the CA (no existing config affected)"],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "sends account registration to the ACME CA directory",
            "depends on correct contact email + TOS acceptance",
        ],
        note=(
            "Additive config. Delete with pmg_acme_account_delete to deactivate. "
            "Smoke-confirm: exact response shape (schema types it a bare string)."
        ),
    )


def plan_acme_account_update(api: PmgBackend, name: str = "default", contact: str | None = None) -> Plan:
    """Preview an ACME account contact update — or a bare CA refresh if contact is omitted
    (divergence #11 above; no "at least one field" guard here, matching PMG's own schema
    statement + `pbs_acme.py`'s identical twin). CAPTURE: best-effort reads current config for
    honesty (redacted defensively).

    RISK_LOW: metadata update (or refresh) only, no cert impact.
    """
    name = _check_acme_account_name(name)
    if contact is not None:
        contact = _check_acme_contact(contact)
    current: dict = {}
    read_failed = False
    try:
        current = _redact_acme_account_kw(acme_account_get(api, name))
    except Exception:
        read_failed = True
    change = (
        f"update PMG ACME account {name!r}: {_redact_acme_account_kw({'contact': contact})}"
        if contact is not None
        else f"refresh PMG ACME account {name!r} with the CA (no new fields — PMG's own "
             "'not specifying any new account information triggers a refresh')"
    )
    return Plan(
        action="pmg_acme_account_update",
        target=f"config/acme/account/{name}",
        change=change,
        current=current,
        blast_radius=["updates contact info (or refreshes status) on the CA side — no cert impact"],
        risk=RISK_LOW,
        risk_reasons=["contact metadata update/refresh — does not affect cert issuance or renewal"],
        complete=not read_failed,
        note=(
            "No snapshot primitive on this plane. Current config captured above — "
            "re-apply contact via pmg_acme_account_update to revert."
            + (" Could not read current config — prior value UNKNOWN." if read_failed else "")
        ),
    )


def plan_acme_account_delete(api: PmgBackend, name: str = "default", force: bool = False) -> Plan:
    """Preview deleting an ACME account. IRREVERSIBLE — see honesty note. RISK_HIGH (matches
    `acme_certs.py`/`pbs_acme.py`'s identical rating exactly). CAPTURE: reads current config as
    EVIDENCE ONLY — this does NOT enable restore.

    The account key is gone; only a NEW CA registration can be made.
    """
    name = _check_acme_account_name(name)
    current: dict = {}
    read_failed = False
    try:
        current = _redact_acme_account_kw(acme_account_get(api, name))
    except Exception:
        read_failed = True
    force_note = " (force: delete local data even if the CA refuses to deactivate)" if force else ""
    return Plan(
        action="pmg_acme_account_delete",
        target=f"config/acme/account/{name}",
        change=f"IRREVERSIBLE: deactivate and delete PMG ACME account {name!r} from the CA{force_note}",
        current=current,
        blast_radius=[
            "ACME account deactivated at the CA — no new cert orders or renewals possible",
            "any TLS cert using this account will NOT renew — TLS lockout at expiry",
            "domains depending on this account require re-registration with a new account",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "IRREVERSIBLE: account key is destroyed; re-registration creates a NEW account, "
            "not a restore of this one",
            "TLS lockout risk: if this is the only ACME account, all auto-renewal stops",
        ],
        complete=not read_failed,
        note=(
            "IRREVERSIBLE. Current config captured above is for EVIDENCE ONLY — "
            "it does NOT enable restore. The account key is not recoverable. "
            "A new account can be registered with pmg_acme_account_create, "
            "but it will be a different CA account, not this one."
            + (" Could not read current config — prior value UNKNOWN." if read_failed else "")
        ),
    )


# --- Plan factories: ACME plugins ---

def plan_acme_plugin_create(plugin_id: str, plugin_type: str, **kw) -> Plan:
    """Preview creating an ACME DNS/standalone challenge plugin. PURE — no API read.
    `validation_delay` validated here too (not just at execution) — caught at PLAN time.

    RISK_MEDIUM.
    """
    plugin_id = _check_acme_plugin_id(plugin_id)
    plugin_type = _check_acme_challenge_type(plugin_type)
    if kw.get("dns_api") is not None:
        _check_acme_plugin_api(kw["dns_api"])
    if kw.get("nodes") is not None:
        _check_acme_plugin_nodes(kw["nodes"])
    if kw.get("validation_delay") is not None:
        _check_acme_validation_delay(kw["validation_delay"])
    return Plan(
        action="pmg_acme_plugin_create",
        target=f"config/acme/plugins/{plugin_id}",
        change=f"create PMG ACME plugin {plugin_id!r} (type={plugin_type!r}): {_redact_acme_plugin_kw(kw)}",
        current={},
        blast_radius=["adds a new ACME DNS/standalone challenge plugin (no existing config affected)"],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "DNS challenge plugin stores API credentials for the DNS provider",
            "incorrect credentials silently break cert issuance until renewal is attempted",
        ],
        note=(
            "Additive config. Delete with pmg_acme_plugin_delete to remove. "
            "Smoke-confirm: exact POST body shape against a live PMG instance."
        ),
    )


def plan_acme_plugin_update(api: PmgBackend, plugin_id: str, **kw) -> Plan:
    """Preview updating an ACME DNS/standalone challenge plugin. CAPTURE: best-effort reads
    current config (redacted — `data` is defensively stripped at the read layer already, redacted
    AGAIN here). `digest`/`delete`/`validation_delay` validated here too (early-validation
    contract this codebase established for every other confirm-gated PUT).

    RISK_MEDIUM.
    """
    plugin_id = _check_acme_plugin_id(plugin_id)
    if kw.get("dns_api") is not None:
        _check_acme_plugin_api(kw["dns_api"])
    if kw.get("nodes") is not None:
        _check_acme_plugin_nodes(kw["nodes"])
    if kw.get("validation_delay") is not None:
        _check_acme_validation_delay(kw["validation_delay"])
    if kw.get("digest") is not None:
        _check_acme_plugin_digest(kw["digest"])
    if kw.get("delete") is not None:
        _check_acme_plugin_delete_props(kw["delete"])
    current: dict = {}
    read_failed = False
    try:
        current = _redact_acme_plugin_kw(acme_plugin_get(api, plugin_id))
    except Exception:
        read_failed = True
    return Plan(
        action="pmg_acme_plugin_update",
        target=f"config/acme/plugins/{plugin_id}",
        change=f"update PMG ACME plugin {plugin_id!r}: {_redact_acme_plugin_kw(kw)}",
        current=current,
        blast_radius=[
            "changes challenge credentials/config for all domains using this plugin",
            "incorrect new credentials break cert renewal for those domains",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "modifies DNS provider credentials/config — invalid update breaks challenge at "
            "next renewal",
        ],
        complete=not read_failed,
        note=(
            "No snapshot primitive on this plane. Current config captured above (credential "
            "redacted) — re-apply it manually to revert."
            + (" Could not read current config — prior value UNKNOWN." if read_failed else "")
        ),
    )


def plan_acme_plugin_delete(api: PmgBackend, plugin_id: str) -> Plan:
    """Preview deleting an ACME DNS/standalone challenge plugin. RISK_HIGH — cert renewal breaks.
    CAPTURE: reads current config, redacted (load-bearing defensively — see module section
    docstring above)."""
    plugin_id = _check_acme_plugin_id(plugin_id)
    current: dict = {}
    read_failed = False
    try:
        current = _redact_acme_plugin_kw(acme_plugin_get(api, plugin_id))
    except Exception:
        read_failed = True
    return Plan(
        action="pmg_acme_plugin_delete",
        target=f"config/acme/plugins/{plugin_id}",
        change=f"delete PMG ACME plugin {plugin_id!r}",
        current=current,
        blast_radius=[
            "all domains using this plugin can no longer complete DNS/standalone challenges",
            "cert renewal fails at next renewal attempt — TLS lockout at cert expiry",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "auto-renewal breaks for all domains referencing this plugin",
            "TLS lockout risk if no fallback challenge method is configured",
        ],
        complete=not read_failed,
        note=(
            "No UNDO primitive on this plane. Current config captured above (credential "
            "redacted) — re-create with pmg_acme_plugin_create to restore, but credentials must "
            "be re-supplied by the caller (the raw value is never returned in a usable form here)."
            + (" Could not read current config — prior value UNKNOWN." if read_failed else "")
        ),
    )


# --- Plan factories: node cert order/renew/revoke (ACME-issued) ---

def plan_node_cert_acme_order(node: str, cert_type: str, force: bool = False) -> Plan:
    """Preview ordering a new ACME cert for one cert slot. PURE — no API read (matches
    `acme_certs.py`'s identical order-vs-revoke split).

    RISK_MEDIUM — CA-validated, installs only on success.
    """
    node = _check_node(node)
    cert_type = _check_pmg_cert_type(cert_type)
    slot_note = "the pmgproxy management-API TLS cert" if cert_type == "api" else "the postfix SMTP-TLS cert"
    return Plan(
        action="pmg_node_cert_acme_order",
        target=f"node/{node}/certificates/acme/{cert_type}",
        change=(
            f"order a new ACME TLS certificate for node {node!r}'s {cert_type!r} slot ({slot_note})"
            + (" (force: overwrite existing custom certificate files)" if force else "")
        ),
        current={},
        blast_radius=[
            f"requests a cert from the configured ACME CA for {slot_note}",
            "on SUCCESS, PMG installs the cert; on a failed DNS/HTTP challenge, the existing "
            "cert is left untouched",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "lower risk than pmg_node_cert_custom_upload (HIGH): the cert is CA-validated and "
            "installed ONLY on a successful challenge — a failure cannot lock you out",
            "talks to the public CA — repeated orders can hit CA rate limits",
        ],
        note=(
            "Returns a STRING per PMG's own schema (divergence #4) — Smoke-confirm whether it's "
            "a task UPID or a plain status message; recorded as-is, no shape invented. Revert to "
            "self-signed with pmg_node_cert_custom_delete if this cert misbehaves."
        ),
    )


def plan_node_cert_acme_renew(node: str, cert_type: str, force: bool = False) -> Plan:
    """Preview renewing the existing ACME cert for one cert slot. PURE — no API read.

    RISK_MEDIUM — same install-on-success guarantee as order.
    """
    node = _check_node(node)
    cert_type = _check_pmg_cert_type(cert_type)
    slot_note = "the pmgproxy management-API TLS cert" if cert_type == "api" else "the postfix SMTP-TLS cert"
    return Plan(
        action="pmg_node_cert_acme_renew",
        target=f"node/{node}/certificates/acme/{cert_type}",
        change=(
            f"renew the existing ACME TLS certificate for node {node!r}'s {cert_type!r} slot "
            f"({slot_note})"
            + (" (force: renew even if not within the renewal lead time)" if force else "")
        ),
        current={},
        blast_radius=[
            f"renews the existing ACME cert for {slot_note} from the configured CA",
            "on SUCCESS, PMG installs the renewed cert; on a failed challenge, the existing "
            "cert is left untouched",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "CA-validated renew, installed only on success; a failure cannot lock you out",
            "talks to the public CA — repeated renews can hit CA rate limits",
        ],
        note=(
            "Same STRING-return honesty as pmg_node_cert_acme_order (divergence #4) — no shape "
            "assumed. Revert to self-signed with pmg_node_cert_custom_delete if a renewed cert "
            "misbehaves."
        ),
    )


def plan_node_cert_acme_revoke(api: PmgBackend, node: str, cert_type: str) -> Plan:
    """Preview revoking the node's ACME cert for one cert slot AT THE CA. IRREVERSIBLE.

    RISK_HIGH — matches `pve_acme_cert_revoke` (the tool PBS never shipped, divergence #1).
    CAPTURE: best-effort reads `pmg_node.py`'s `certificates_info` (PUBLIC cert data) as evidence
    of what is about to be revoked — mirrors `acme_certs.py`'s own `plan_acme_cert_revoke`
    evidence-capture idiom exactly.
    """
    node = _check_node(node)
    cert_type = _check_pmg_cert_type(cert_type)
    # Deferred import (mirrors plan_service_control's established pmg_node.py cross-reference
    # above — pmg_node.py imports from pmg.py at module top, so a module-top import here would
    # be circular).
    from .pmg_node import certificates_info

    current: dict = {}
    read_failed = False
    try:
        current = {"certificates": certificates_info(api, node)}
    except Exception:
        read_failed = True
    slot_note = "the pmgproxy management-API TLS cert" if cert_type == "api" else "the postfix SMTP-TLS cert"
    return Plan(
        action="pmg_node_cert_acme_revoke",
        target=f"node/{node}/certificates/acme/{cert_type}",
        change=f"IRREVERSIBLE: revoke node {node!r}'s {cert_type!r}-slot ACME TLS certificate "
               f"({slot_note}) at the CA",
        current=current,
        blast_radius=[
            f"the {cert_type!r}-slot cert is revoked at the CA — clients that check revocation "
            "will reject it",
            f"PMG keeps serving the now-revoked cert on {slot_note} until a new one is "
            "ordered/installed",
            "a fresh order (pmg_node_cert_acme_order) is required to restore a valid TLS chain",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "IRREVERSIBLE at the CA: a revoked cert cannot be un-revoked; only a NEW order "
            "restores trust",
            "TLS-trust loss for clients honoring revocation; CA rate limits may delay re-issue",
        ],
        complete=not read_failed,
        note=(
            "IRREVERSIBLE. Revocation cannot be undone — only a new pmg_node_cert_acme_order "
            "restores a valid cert. Rarely needed (key compromise). NOT a way to 'reset' a cert "
            "— use pmg_node_cert_custom_delete to fall back to self-signed WITHOUT revoking at "
            "the CA."
            + (" Could not read current cert info — prior state UNKNOWN." if read_failed else "")
        ),
    )


# --- Plan factories: node custom-cert upload/delete ---

def plan_node_cert_custom_upload(
    api: PmgBackend,
    certificates: str,
    node: str,
    cert_type: str,
    force: bool = False,
    restart: bool = False,
) -> Plan:
    """Preview uploading/replacing the custom TLS certificate for one cert slot.

    RISK_HIGH, no undo — matches `pve_node_cert_upload`/`pbs_node_cert_upload`'s identical
    "a malformed cert/key can lock you out" reasoning (NOT downgraded despite the draft's own
    hedge — consistent-rating-with-twins). `key` NEVER appears in this function — unconditional
    redaction (THE SECRET CONTRACT); only the cert body (public) is used to build the preview.
    CAPTURE: best-effort reads `pmg_node.py`'s `certificates_info` as evidence of what is about
    to be replaced.
    """
    node = _check_node(node)
    cert_type = _check_pmg_cert_type(cert_type)
    from .pmg_node import certificates_info

    current: dict = {}
    read_failed = False
    try:
        current = {"certificates": certificates_info(api, node)}
    except Exception:
        read_failed = True
    # UNCONDITIONAL: key never passed to or from this function. The server tool holds the key;
    # only {"key": "[redacted]"} reaches the ledger.
    cert_preview = certificates[:64] + ("…" if len(certificates) > 64 else "")
    if cert_type == "api":
        slot_note = "the pmgproxy management-API TLS cert"
        lockout_note = "a malformed cert/key can lock you out of the PMG web UI + API"
    else:
        slot_note = "the postfix SMTP-TLS cert"
        lockout_note = "a malformed cert/key breaks encrypted mail delivery/relay TLS for this node"
    return Plan(
        action="pmg_node_cert_custom_upload",
        target=f"node/{node}/certificates/custom/{cert_type}",
        change=(
            f"upload custom TLS certificate to node {node!r}'s {cert_type!r} slot ({slot_note}) "
            f"(cert body: {cert_preview!r})"
            + (" (force=True: overwrite existing cert files)" if force else "")
            + (" (restart=True: restarts the affected service)" if restart else "")
        ),
        current=current,
        blast_radius=[f"node TLS certificate ({slot_note}): {lockout_note}"]
        + (["restart=True also restarts the affected service (brief interruption)"] if restart else []),
        risk=RISK_HIGH,
        risk_reasons=[
            f"{lockout_note}; no undo — re-upload a working cert or use "
            "pmg_node_cert_custom_delete to revert to self-signed",
        ],
        complete=not read_failed,
        note=(
            "No undo: once uploaded, revert by re-uploading a good cert or by deleting the "
            "custom cert (pmg_node_cert_custom_delete) to fall back to PMG's self-signed cert "
            "for this slot. Private key is unconditionally redacted from the ledger."
            + (" Could not read current cert info — prior state UNKNOWN." if read_failed else "")
        ),
    )


def plan_node_cert_custom_delete(node: str, cert_type: str, restart: bool = False) -> Plan:
    """Preview deleting the custom TLS certificate for one cert slot — PMG reverts to its
    self-signed cert for that slot.

    RISK_MEDIUM — recoverable, matches `pve_node_cert_delete`/`pbs_node_cert_delete` exactly.
    PURE — no API read (mirrors those siblings' own PURE convention for the delete direction).
    """
    node = _check_node(node)
    cert_type = _check_pmg_cert_type(cert_type)
    slot_note = "the pmgproxy management-API TLS cert" if cert_type == "api" else "the postfix SMTP-TLS cert"
    return Plan(
        action="pmg_node_cert_custom_delete",
        target=f"node/{node}/certificates/custom/{cert_type}",
        change=(
            f"remove the custom TLS certificate from node {node!r}'s {cert_type!r} slot "
            f"({slot_note}); PMG reverts to its self-signed cert for this slot"
            + (" (restart=True: restarts the affected service)" if restart else "")
        ),
        current={},
        blast_radius=[
            f"node TLS certificate ({slot_note}): removes the custom cert — PMG reverts to "
            "self-signed; clients will see a TLS warning until a new cert is uploaded/ordered"
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            f"removes the custom TLS certificate for {slot_note} — PMG reverts to self-signed; "
            "recoverable by re-uploading/re-ordering a certificate"
        ],
        note=(
            "Recoverable: PMG reverts to its self-signed certificate for this slot. Re-upload "
            "with pmg_node_cert_custom_upload or re-order with pmg_node_cert_acme_order to "
            "restore custom TLS."
        ),
    )


# ===========================================================================
# Wave 9j (2026-07-18, the FINAL chunk — CLOSES the PMG plane): quarantine + statistics
# remainder. Extends this file (RULING 5) — direct siblings of the already-shipped
# pmg_quarantine_*/pmg_statistics_* families above.
#
# RULING 4 — pmg_quarantine_link_get returns a BEARER-CREDENTIAL-EQUIVALENT value from a plain
# GET (`{"link": "..."}`). PMG's own description: "grants full access to that recipient's
# quarantine, so only pass it to the legitimate owner." never-in-ledger on the read's OWN
# logged return — the campaign's first plain-read-return redaction.
#
# PLUMBING FINDING (resolves ⚖️ §4.4 — NO extension needed): server._audited()'s ledger write
# (`audit.record(..., detail=_untrusted_detail(action, detail), ...)`) NEVER auto-includes a
# read's own `fn()` return value — it logs EXACTLY the `detail` dict the wrapper hands it, nothing
# more. Every read-tool wrapper in this file (and in pmg_node.py/pmg_identity.py) either passes NO
# `detail=` at all, or passes a small caller-controlled dict of the ASK (never the ANSWER) — the
# "raw_result" idiom used for ambiguous-string MUTATION returns elsewhere in this file is the ONLY
# place a read/mutation's own VALUE ever nears the ledger, and that idiom is deliberately
# mutation-only, applied per-tool, never automatic. The plumbing therefore ALREADY supports
# "never-in-ledger on a read's own return" — by construction (the wrapper controls exactly what
# `detail` contains), not by a redaction mechanism that needed building. `pmg_quarantine_link_get`
# (tools/pmg_mail.py) passes `detail={"mail": mail}` — the non-secret WHO-asked identifier, same
# audit-trail convention as e.g. `pmg_pbs_remote_create` keeping `remote` visible in its own
# ledger detail while stripping `password`/`encryption-key` — but NEVER passes the read's own
# `link` return value into `detail`, so the secret reaches the caller (via `_audited`'s plain
# pass-through return for non-mutations) and NEVER the ledger. Proven empirically — not just by
# inspection — with a raw-ledger-bytes sweep in
# tests/test_confirm_sweep_pmg_quarantine_statistics.py.
#
# TAINT determination — argued per-tool (6d law), not defaulted to the draft's flat
# "REVIEWED_TRUSTED" guess for the whole statistics family:
#   - quarantine_content_get / quarantine_attachments_list: ADVERSARIAL — full attacker-authored
#     email content (subject/from/sender/header/the first 4096 bytes of raw content) and
#     attacker-controllable attachment filenames, respectively. Direct siblings of the
#     already-shipped pmg_quarantine_spam/virus/attachment family (also ADVERSARIAL).
#   - quarantine_link_get / quarantine_users_list / quarantine_sendlink: REVIEWED_TRUSTED — the
#     link is PMG-GENERATED (not attacker content — a SECRET-handling concern instead, see
#     RULING 4 above, an orthogonal axis); quarusers lists PMG's own per-mailbox BL/WL
#     configuration (operator-managed local settings, not external mail content); sendlink's own
#     return is `null`.
#   - statistics_contact / statistics_detail / statistics_recentreceivers /
#     statistics_recentsenders: ADVERSARIAL — each return schema carries a literal EXTERNAL
#     address field (`contact`; `sender`/`receiver`; `receiver`; `sender`, respectively) —
#     MATCH-TWINS to the already-shipped ADVERSARIAL pmg_statistics_sender/receiver/domains (the
#     9e review's own "ratings consistent with shipped twins" law, applied here to taint).
#   - statistics_maildistribution / statistics_rejectcount: REVIEWED_TRUSTED — both return
#     SCHEMA-CONFIRMED pure aggregate-numeric fields only (hour index + in/out/spam/virus/bounce
#     counts; time index + RBL/PREGREET reject counts) — zero address or free-text field anywhere
#     in either return schema. Twin of pmg_statistics_mailcount (already REVIEWED_TRUSTED).
#
# "wire EVERY field" (9f law): the ALREADY-SHIPPED statistics_domains/virus/spamscores functions
# above only implement start/end, even though their own schemas ALSO document day/month/year — a
# pre-existing gap in those three, out of THIS chunk's scope to retrofit. The four Wave-9j reads
# whose schema documents day/month/year (contact/detail/maildistribution/rejectcount) wire them
# in FULL here via the new `_day_month_year_params` helper below — a genuine improvement over the
# older siblings' pattern, not a copy of their gap.
# ===========================================================================


_QUARUSERS_LIST_VALUES = frozenset({"BL", "WL"})


def _check_quarusers_list(value: str) -> str:
    s = str(value)
    if s not in _QUARUSERS_LIST_VALUES:
        raise ProximoError(
            f"invalid quarusers list filter: {value!r}. "
            f"Must be one of: {', '.join(sorted(_QUARUSERS_LIST_VALUES))}"
        )
    return s


_STATISTICS_DETAIL_TYPES = frozenset({"contact", "sender", "receiver"})


def _check_statistics_detail_type(value: str) -> str:
    s = str(value)
    if s not in _STATISTICS_DETAIL_TYPES:
        raise ProximoError(
            f"invalid statistics detail type: {value!r}. "
            f"Must be one of: {', '.join(sorted(_STATISTICS_DETAIL_TYPES))}"
        )
    return s


def _day_month_year_params(day: int | None, month: int | None, year: int | None) -> dict:
    """Validate optional day(1-31)/month(1-12)/year(1900-3000) statistics params — the schema's
    own bounds on every Wave 9j statistics read that documents them. A fresh per-chunk helper
    (matches this file's own "fresh copy per family" convention) rather than retrofitting the
    older statistics_domains/virus/spamscores siblings, which don't wire these fields at all.
    """
    params: dict = {}
    if day is not None:
        try:
            d = int(day)
        except (ValueError, TypeError) as exc:
            raise ProximoError(f"invalid day: {day!r} (must be an integer)") from exc
        if not (1 <= d <= 31):
            raise ProximoError(f"invalid day: {day!r} (must be 1-31)")
        params["day"] = d
    if month is not None:
        try:
            m = int(month)
        except (ValueError, TypeError) as exc:
            raise ProximoError(f"invalid month: {month!r} (must be an integer)") from exc
        if not (1 <= m <= 12):
            raise ProximoError(f"invalid month: {month!r} (must be 1-12)")
        params["month"] = m
    if year is not None:
        try:
            y = int(year)
        except (ValueError, TypeError) as exc:
            raise ProximoError(f"invalid year: {year!r} (must be an integer)") from exc
        if not (1900 <= y <= 3000):
            raise ProximoError(f"invalid year: {year!r} (must be 1900-3000)")
        params["year"] = y
    return params


def _check_recent_hours(hours) -> int:
    try:
        h = int(hours)
    except (ValueError, TypeError) as exc:
        raise ProximoError(f"invalid hours: {hours!r} — must be an integer") from exc
    if not (1 <= h <= 24):
        raise ProximoError(f"invalid hours: {hours!r} — must be 1-24")
    return h


def _check_recent_limit(limit) -> int:
    try:
        n = int(limit)
    except (ValueError, TypeError) as exc:
        raise ProximoError(f"invalid limit: {limit!r} — must be an integer") from exc
    if not (1 <= n <= 50):
        raise ProximoError(f"invalid limit: {limit!r} — must be 1-50")
    return n


# ---------------------------------------------------------------------------
# W9j READ operations — quarantine remainder
# ---------------------------------------------------------------------------

def quarantine_users_list(api: PmgBackend, list_: str | None = None) -> list[dict]:
    """List users with welcomelist/blocklist quarantine settings.

    GET /quarantine/quarusers

    REVIEWED_TRUSTED: PMG's own per-mailbox BL/WL configuration (operator-managed local
    settings), not external mail content.
    list_: optional filter, 'BL' (blocklist) or 'WL' (welcomelist) users only; omit for both
    (maps to the API's own 'list' query param).
    """
    params: dict = {}
    if list_ is not None:
        params["list"] = _check_quarusers_list(list_)
    return api._get("/quarantine/quarusers", params=params if params else None) or []


def quarantine_content_get(
    api: PmgBackend,
    id_: str,
    images: bool | None = None,
    raw: bool | None = None,
) -> dict:
    """Get the full content of one quarantined email.

    GET /quarantine/content

    ADVERSARIAL: the return carries attacker-authored mail content (subject/from/sender/header/
    the first 4096 bytes of the raw body) — direct sibling of pmg_quarantine_spam/virus/attachment.
    id_: quarantine mail ID (e.g. from pmg_quarantine_spam/pmg_quarantine_virus).
    images: load externally-hosted images too (only effective in 'on-demand' viewimages mode).
    raw: return raw eml data, deactivating the normal size limit.
    """
    id_ = _check_mail_id(id_)
    params: dict = {"id": id_}
    if images is not None:
        params["images"] = 1 if images else 0
    if raw is not None:
        params["raw"] = 1 if raw else 0
    return api._get("/quarantine/content", params=params) or {}


def quarantine_attachments_list(api: PmgBackend, id_: str) -> list[dict]:
    """List attachments on one quarantined email.

    GET /quarantine/listattachments

    ADVERSARIAL: attachment filenames are attacker-controllable — matches
    pmg_quarantine_content_get's own reasoning.
    id_: quarantine mail ID (e.g. from pmg_quarantine_spam/pmg_quarantine_virus).
    """
    id_ = _check_mail_id(id_)
    return api._get("/quarantine/listattachments", params={"id": id_}) or []


def quarantine_link_get(api: PmgBackend, mail: str) -> dict:
    """Get a quarantine login link for a recipient's mailbox.

    GET /quarantine/link

    RULING 4 (module section above): the returned `link` IS a bearer credential — PMG's own
    description: "grants full access to that recipient's quarantine, so only pass it to the
    legitimate owner." never-in-ledger on the tool wrapper's own logged return (see
    pmg_quarantine_link_get in tools/pmg_mail.py — it passes `detail={"mail": mail}`, the
    non-secret WHO-asked identifier, but never the `link` value itself).
    mail: recipient email address.
    """
    mail = _check_email_address(mail, "mail")
    return api._get("/quarantine/link", params={"mail": mail}) or {}


# ---------------------------------------------------------------------------
# W9j MUTATION — quarantine sendlink
# ---------------------------------------------------------------------------

def quarantine_sendlink(api: PmgBackend, mail: str) -> None:
    """Send a REAL quarantine login link email to `mail`.

    POST /quarantine/sendlink

    MUTATION — confirm-gated + audited at the server layer. Returns null (synchronous).
    """
    mail = _check_email_address(mail, "mail")
    return api._post("/quarantine/sendlink", data={"mail": mail})


def plan_quarantine_sendlink(mail: str) -> Plan:
    """Preview sending a REAL quarantine login link email. PURE — no API call.

    RISK_LOW — matches pbs_notification_target_test's precedent exactly: a real side-effect (an
    email IS delivered) with NO PMG config state change and no revert primitive (the email
    itself cannot be recalled once sent).
    """
    mail = _check_email_address(mail, "mail")
    return Plan(
        action="pmg_quarantine_sendlink",
        target="quarantine/sendlink",
        change=f"send a REAL quarantine login link email to {mail!r}",
        current={},
        blast_radius=[
            f"a REAL email is sent to {mail!r} containing a quarantine login link",
            "that link is itself a bearer credential — it grants full access to that "
            "recipient's quarantine (see pmg_quarantine_link_get); a misdirected `mail` "
            "address sends the quarantine-access capability to the wrong recipient",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "side-effect only — no PMG config state changes",
            "a real email IS delivered and cannot be recalled — no revert primitive",
            "bearer-credential delivery is a secret-handling concern (never-in-ledger contract), "
            "orthogonal to the risk tier (which rates state-change, not secret transport)",
        ],
        note=(
            "Matches pbs_notification_target_test's RISK_LOW precedent: real side effect, no "
            "state change. Unlike pmg_quarantine_link_get (which returns the link directly to "
            "the caller), this tool never surfaces the link itself — only PMG's mailer does."
        ),
    )


# ---------------------------------------------------------------------------
# W9j READ operations — statistics remainder
# ---------------------------------------------------------------------------

def statistics_contact(
    api: PmgBackend,
    start: int | None = None,
    end: int | None = None,
    filter_: str | None = None,
    orderby: str | None = None,
    day: int | None = None,
    month: int | None = None,
    year: int | None = None,
) -> list[dict]:
    """Get per-contact-address mail statistics.

    GET /statistics/contact

    ADVERSARIAL: `contact` is an external address literal — matches pmg_statistics_sender/
    receiver/domains' own reasoning exactly (match-twins).
    filter_: optional contact-address search string (maps to API param 'filter').
    orderby: optional sort spec — raw passthrough, unconfirmed whether PMG accepts it here
    (pmg_statistics_sender is CONFIRMED to reject it — Smoke-confirm before relying on this).
    day/month/year: optional calendar-window filters (schema bounds: day 1-31, month 1-12,
    year 1900-3000) — wired in full here (see module section above re: the older
    statistics_domains/virus/spamscores siblings' day/month/year gap).
    Maps start/end epoch params → starttime/endtime query params.
    """
    params = _epoch_range_params(start, end)
    params.update(_day_month_year_params(day, month, year))
    if filter_ is not None:
        params["filter"] = filter_
    if orderby is not None:
        params["orderby"] = orderby
    return api._get("/statistics/contact", params=params if params else None) or []


def statistics_detail(
    api: PmgBackend,
    address: str,
    type_: str,
    start: int | None = None,
    end: int | None = None,
    filter_: str | None = None,
    orderby: str | None = None,
    day: int | None = None,
    month: int | None = None,
    year: int | None = None,
) -> list[dict]:
    """Get detailed per-message statistics for one address.

    GET /statistics/detail

    ADVERSARIAL: return items carry `sender`/`receiver` address literals — match-twins to
    pmg_statistics_sender/receiver.
    address: REQUIRED — the email address to get detail statistics for.
    type_: REQUIRED — 'contact'|'sender'|'receiver' (maps to API param 'type').
    filter_: optional address search string (maps to API param 'filter').
    orderby: optional sort spec — raw passthrough, unconfirmed acceptance (see
    statistics_contact's own note).
    day/month/year: optional calendar-window filters, wired in full (see module section above).
    Maps start/end epoch params → starttime/endtime query params.
    """
    address = _check_email_address(address, "address")
    type_ = _check_statistics_detail_type(type_)
    params = _epoch_range_params(start, end)
    params.update(_day_month_year_params(day, month, year))
    params["address"] = address
    params["type"] = type_
    if filter_ is not None:
        params["filter"] = filter_
    if orderby is not None:
        params["orderby"] = orderby
    return api._get("/statistics/detail", params=params) or []


def statistics_maildistribution(
    api: PmgBackend,
    start: int | None = None,
    end: int | None = None,
    day: int | None = None,
    month: int | None = None,
    year: int | None = None,
) -> list[dict]:
    """Get spam-mail counts grouped by spam score.

    GET /statistics/maildistribution

    REVIEWED_TRUSTED: every return field is a pure aggregate integer/number (hour index, in/out
    counts, spam/virus/bounce counts) — no address or free-text field anywhere in the schema.
    Count for score 10 includes mails with spam score > 10 (PMG's own description).
    day/month/year: optional calendar-window filters, wired in full (see module section above).
    Maps start/end epoch params → starttime/endtime query params.
    """
    params = _epoch_range_params(start, end)
    params.update(_day_month_year_params(day, month, year))
    return api._get("/statistics/maildistribution", params=params if params else None) or []


def statistics_recentreceivers(
    api: PmgBackend,
    hours: int = 12,
    limit: int = 5,
) -> list[dict]:
    """Get the top recent mail receivers (including spam).

    GET /statistics/recentreceivers

    ADVERSARIAL: `receiver` is an external address literal — match-twins to
    pmg_statistics_receiver.
    hours: lookback window, 1-24 (default 12, PMG's own schema default).
    limit: max receivers to return, 1-50 (default 5, PMG's own schema default).
    """
    h = _check_recent_hours(hours)
    n = _check_recent_limit(limit)
    return api._get("/statistics/recentreceivers", params={"hours": h, "limit": n}) or []


def statistics_recentsenders(
    api: PmgBackend,
    hours: int = 12,
    limit: int = 5,
) -> list[dict]:
    """Get the top recent mail senders (including spam).

    GET /statistics/recentsenders

    ADVERSARIAL: `sender` is an external address literal — match-twins to pmg_statistics_sender.
    hours: lookback window, 1-24 (default 12, PMG's own schema default).
    limit: max senders to return, 1-50 (default 5, PMG's own schema default).
    """
    h = _check_recent_hours(hours)
    n = _check_recent_limit(limit)
    return api._get("/statistics/recentsenders", params={"hours": h, "limit": n}) or []


def statistics_rejectcount(
    api: PmgBackend,
    start: int | None = None,
    end: int | None = None,
    day: int | None = None,
    month: int | None = None,
    year: int | None = None,
    timespan: int = 3600,
) -> list[dict]:
    """Get early-SMTP-reject counts (RBL/PREGREET rejects with postscreen).

    GET /statistics/rejectcount

    REVIEWED_TRUSTED: every return field is a pure aggregate integer (time index, RBL/PREGREET
    reject counts) — no address or free-text field anywhere in the schema. Twin of
    pmg_statistics_mailcount (already REVIEWED_TRUSTED).
    timespan: histogram bucket size in seconds, 3600-31622400 (default 3600 = 1 hour) — same
    bounds/idiom as pmg_statistics_mailcount.
    day/month/year: optional calendar-window filters, wired in full (see module section above).
    Maps start/end epoch params → starttime/endtime query params.
    """
    try:
        timespan_int = int(timespan)
    except (ValueError, TypeError) as exc:
        raise ProximoError(f"invalid timespan: {timespan!r} — must be an integer") from exc
    if not (3600 <= timespan_int <= 31622400):
        raise ProximoError(f"invalid timespan: {timespan!r} — must be in range 3600-31622400")
    params = _epoch_range_params(start, end)
    params.update(_day_month_year_params(day, month, year))
    params["timespan"] = timespan_int
    return api._get("/statistics/rejectcount", params=params) or []
