"""Proximo PDM (Proxmox Datacenter Manager) lane.

PDM is a fleet-management appliance that aggregates PVE and PBS remotes.
The read plane (22 DIAGNOSE tools) is live-verified. Section F adds the
fleet-control MUTATION methods (power / migrate / snapshot via the remote proxy),
surfaced by the pdm_fleet.py tools with full PLAN/PROVE/UNDO — LIVE-PROVEN
2026-07-06 end-to-end against a real PDM 1.1.4 + nested PVE 9.2 cluster
(pdm-fleet-smoke.py: power stop/start, snapshot create/rollback(+auto-undo)/delete,
online migrate node→node and back, 92-entry PROVE chain verified). The live run
surfaced three bugs since fixed: remote-qualified UPID parsing (below), JSON-boolean
serialization (PDM's typed API rejects PVE-style 1), and surfacing the auto-undo
safety-snapshot name to the caller.

API topology:
  - PDM base:  https://<host>:8443/api2/json  (not :8006)
  - Auth:      Authorization: PDMAPIToken <tokenid>:<secret>
               (SPACE separator — NOT '=' like PVE/PBS)
  - PDM is single-node; node defaults to "localhost"
  - PDM proxies remotes through a FLAT surface:
      PVE: /pve/remotes/<remote>/<subpath>   (no /api2/json)
      PBS: /pbs/remotes/<remote>/<subpath>   (no /api2/json)

Anti-boxing seam:
  _pve_remote_get(remote, subpath, params) and
  _pbs_remote_get(remote, subpath, params) are loop-ready primitives that
  make per-remote fan-out straightforward without implementing it here.

VERIFIED live shapes (PDM 1.1, 2026-06-27):
  GET /ping              → {"data":"pong"}
  GET /version           → {"data":{"release":"4","repoid":"...","version":"1.1"}}
  GET /remotes/remote    → {"data":[{"id":"...","type":"pbs"|"pve",...}],"digest":"..."}
  GET /remotes/remote/{id}/version → proxies to the remote's /version
  GET /remotes/remote/{id}/config  → remote config (no secrets)
  GET /resources/list    → {"data":[{"remote":"...","resources":[...]}]}
  GET /resources/status  → {"data":{"failed_remotes":N,"lxc":{...},"remotes":N,...}}
  GET /remotes/tasks/list → {"data":[]}
  GET /access/acl        → {"data":[{"path":"/","propagate":true,"roleid":"Auditor",...}],"digest":"..."}
  GET /access/roles      → {"data":[{"comment":"...","privs":[...],"roleid":"Auditor"},...]}
  GET /access/users      → {"data":[{"enable":true,"userid":"proximo@pdm"},...],"digest":"..."}
  GET /nodes/localhost/status  (live-prove-pending: probe hit empty node; shape equals PVE node status)
  D-group (PBS per-remote) — LIVE-VERIFIED (PDM 1.1 → PBS 4.2, 2026-06-27):
    GET /pbs/remotes/{remote}/status                          → PBS node status dict
    GET /pbs/remotes/{remote}/datastore                       → [{"name","path"}, ...]
    GET /pbs/remotes/{remote}/datastore/{store}/snapshots     → [...]
  C-group (PVE per-remote) — LIVE-PROVEN (PDM 1.1.4 → PVE 9.2 cluster, 2026-07-06):
    GET  /pve/remotes/{remote}/resources | cluster-status | nodes | qemu | lxc | {kind}/{vmid}/config
    POST /pve/remotes/{remote}/{kind}/{vmid}/{start|stop|shutdown|resume} | migrate | snapshot | .../rollback
    NOTE: proxied POSTs return a REMOTE-QUALIFIED upid ("pve:<remote>!UPID:..."); the per-remote
          task endpoint REJECTS the bare form. Booleans MUST be JSON true, not 1.
  GET /remotes/metric-collection/status → 403 for Auditor token — EXCLUDED from surface

Security posture mirrors pbs.py (and is stricter on TLS):
- Token read at call time from the token-path file; NEVER logged.
- TLS verification prefers ca_bundle over disabling. FAIL-CLOSED: constructing a
  PdmBackend with verify_tls=false AND no ca_bundle raises.
- Input validators use \\Z (not $) to block trailing-newline bypass.

env vars:
    PROXIMO_PDM_BASE_URL     required  https://<host>:8443
                                       (/api2/json appended automatically if absent)
    PROXIMO_PDM_TOKEN_PATH   required  file containing TOKENID:SECRET  (e.g. proximo@pdm!token:secret)
    PROXIMO_PDM_VERIFY_TLS   optional  default "true"; set "false" to skip (warn + fail-closed)
    PROXIMO_PDM_CA_BUNDLE    optional  path to CA cert bundle (preferred over disabling TLS)
"""

from __future__ import annotations

import os
import re
import warnings
from dataclasses import dataclass

import httpx

from ._secretfile import refuse_exposed_secret
from ._tls import fingerprint_pinned_context, httpx_verify, parse_verify_tls
from .backends import ProximoError, fingerprint_refused
from .pbs import _check_namespace

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# Remote name: path segment in /pve/remotes/<remote>/... — reject traversal.
# PDM remote names are alphanumeric + hyphen/underscore (same charset as PBS store names).
# \Z (not $) — Python's $ matches before a trailing newline, so "remote\n" would slip through.
_REMOTE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")

# VMID: numeric 100–999999999
_VMID_RE = re.compile(r"^[1-9][0-9]{2,8}\Z")

# Datastore name (PBS): alphanumeric + hyphen/underscore; no slash or control chars.
_DATASTORE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")

# Node name: hostname characters; no slash.
_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def _check_remote(remote: str) -> str:
    """Validate a PDM remote name (path segment for /pve/remotes or /pbs/remotes/<remote>/...)."""
    s = str(remote)
    if not _REMOTE_RE.match(s):
        raise ProximoError(
            f"invalid PDM remote name: {remote!r} "
            "(must start with alnum, then alnum/_/-, <=64 chars, no slash or control chars)"
        )
    return s


def _check_vmid(vmid: int | str) -> str:
    """Validate a VMID (100–999999999); returns as string for URL use."""
    s = str(vmid)
    if not _VMID_RE.match(s):
        raise ProximoError(
            f"invalid VMID: {vmid!r} (must be 100–999999999)"
        )
    return s


def _check_datastore(datastore: str) -> str:
    """Validate a PBS datastore name (path segment for remote PBS proxy calls)."""
    s = str(datastore)
    if not _DATASTORE_RE.match(s):
        raise ProximoError(
            f"invalid datastore name: {datastore!r} "
            "(must start with alnum, then alnum/_/-, <=64 chars, no slash or control chars)"
        )
    return s


def _check_node(node: str) -> str:
    """Validate a PDM node name (hostname characters)."""
    s = str(node)
    if not _NODE_RE.match(s):
        raise ProximoError(
            f"invalid PDM node name: {node!r} "
            "(must start with alnum, then alnum/._/-, <=64 chars)"
        )
    return s


def _check_opt(val: str, name: str) -> str:
    """Reject control chars and over-long values in optional query params (defence-in-depth).

    Free-form query values (kind/snapshot/state/path) don't get a tight charset like the
    path-segment validators, but they must never carry control chars (header/log injection,
    newline bypass) or unbounded length. \\x00-\\x1f covers NUL + newline + the C0 set.
    """
    s = str(val)
    if len(s) > 256 or re.search(r"[\x00-\x1f]", s):
        raise ProximoError(f"invalid {name}: control chars or >256 chars")
    return s


# Guest kinds and the power actions PDM's proxy actually exposes (invent nothing:
# PDM proxies no reboot/suspend, and lxc has no resume — see the schema).
_GUEST_KINDS = ("qemu", "lxc")
_POWER_ACTIONS = {
    "qemu": ("start", "stop", "shutdown", "resume"),
    "lxc": ("start", "stop", "shutdown"),
}


def _check_kind(kind: str) -> str:
    """Validate a guest kind (qemu|lxc) — a path segment on the remote proxy."""
    s = str(kind)
    if s not in _GUEST_KINDS:
        raise ProximoError(f"invalid guest kind: {kind!r} (must be one of {_GUEST_KINDS})")
    return s


def _check_power_action(kind: str, action: str) -> str:
    """Validate a power action for the given kind against what PDM proxies.

    qemu: start/stop/shutdown/resume; lxc: start/stop/shutdown. No reboot, no
    suspend — PDM exposes no proxy for them, so we refuse rather than invent one.
    """
    k = _check_kind(kind)
    a = str(action)
    allowed = _POWER_ACTIONS[k]
    if a not in allowed:
        raise ProximoError(
            f"invalid power action {action!r} for {k}: PDM proxies {allowed} (no reboot/suspend)"
        )
    return a


# Snapshot name: PVE charset (start alpha, then alnum/_/-, <=40) — path segment for
# /snapshot/{snapname}, so it must reject slash/traversal/control chars.
_SNAPNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,39}\Z")


def _check_snapname(snapname: str) -> str:
    """Validate a snapshot name (path segment for delete/rollback)."""
    s = str(snapname)
    if not _SNAPNAME_RE.match(s):
        raise ProximoError(
            f"invalid snapshot name: {snapname!r} (start with a letter, then alnum/_/-, <=40 chars)"
        )
    return s


# Proxmox task UPID: "UPID:node:pid:pstart:starttime:type:id:user:" — used as a URL path segment,
# so allowlist the real charset and require the UPID: prefix. Rejects %-encoded traversal, '/', '?',
# '#' — stricter than a bare control-char check (defence matches the other path validators).
# PDM's proxied POSTs return a REMOTE-QUALIFIED upid — "<type>:<remote>!UPID:..." (e.g.
# "pve:pve-test1!UPID:...") — and its per-remote task endpoint REJECTS the bare "UPID:..." form
# (live-proven 2026-07-06), so allow that optional prefix. The prefix charset stays inside the
# path-safe allowlist (no '/'), so it cannot smuggle traversal.
_UPID_RE = re.compile(r"^(?:[a-z]{2,10}:[A-Za-z0-9._-]{1,60}!)?UPID:[A-Za-z0-9@!:._-]{1,220}\Z")


def _check_upid(upid: str) -> str:
    """Validate a task UPID used as a path segment (bare or PDM remote-qualified)."""
    s = str(upid)
    if not _UPID_RE.match(s):
        raise ProximoError(
            f"invalid task UPID: {upid!r} (must be a 'UPID:...' or '<type>:<remote>!UPID:...' task id)"
        )
    return s


# Credential-shaped keys stripped from any config/user/remote dict before it leaves the backend.
# Defence-in-depth: the PDM Auditor token should never see a secret, but a future PDM regression
# must not be able to hand one to the caller through this read surface.
# Substring match (not exact-match only): a compound key like "client_secret" or "api_key"
# carries the same marker word and must be caught too — "tokensecret" needs no separate entry
# since "token" and "secret" already match it as substrings.
_SECRET_KEY_MARKERS = ("token", "password", "secret", "key")


def _strip_secret_value(v: object) -> object:
    """Recursively sanitise a value — descends into nested dicts and lists."""
    if isinstance(v, dict):
        return _strip_secrets(v)
    if isinstance(v, list):
        return [_strip_secret_value(i) for i in v]
    return v


def _strip_secrets(d: dict) -> dict:
    """Return a COPY of d with credential-shaped keys removed (case-insensitive, recursive).

    Handles nested dicts and lists so a credential-shaped key cannot survive
    in any casing (Token, PASSWORD, TokenSecret, ...) or nesting depth.
    Returns a new dict — the caller's dict is never mutated.
    Defence-in-depth: the PDM Auditor token should never see a secret, but a
    future PDM regression must not be able to hand one to the caller through
    this read surface.
    """
    return {
        k: _strip_secret_value(v)
        for k, v in d.items()
        if not any(marker in k.lower() for marker in _SECRET_KEY_MARKERS)
    }


# ---------------------------------------------------------------------------
# PdmConfig
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PdmConfig:
    """Configuration for the PDM API backend.

    All credentials are referenced by PATH — values are read at call time
    and never logged, so the secrets vault is never echoed.

    env vars:
        PROXIMO_PDM_BASE_URL     required  https://<host>:8443
                                           (/api2/json appended automatically if absent)
        PROXIMO_PDM_TOKEN_PATH   required  file containing TOKENID:SECRET
        PROXIMO_PDM_VERIFY_TLS   optional  default "true"; set "false" to skip (warn + fail-closed)
        PROXIMO_PDM_CA_BUNDLE    optional  path to CA cert bundle (preferred over disabling TLS)
        PROXIMO_PDM_FINGERPRINT  optional  WIRE-ENFORCED exact-cert SHA-256 pin (self-signed PDM)
    """

    base_url: str          # e.g. "https://pdm.example.com:8443/api2/json"
    token_path: str        # file containing: TOKENID:SECRET  (run-but-not-read)
    verify_tls: bool = True
    ca_bundle: str | None = None
    fingerprint: str | None = None  # WIRE-ENFORCED exact-cert pin — see PdmBackend.__init__

    @staticmethod
    def _normalize_base_url(base_url: str) -> str:
        """Append /api2/json if the URL has no path (common PDM usage is just the host:port).

        Shared by from_env and from_target so both heads normalise identically.
        """
        url = base_url.rstrip("/")
        if not url.endswith("/api2/json"):
            url = url + "/api2/json"
        return url

    @staticmethod
    def _warn_unverified_tls(source: str) -> None:
        """Fail-open-but-loud warning when TLS verification is disabled with no CA bundle.

        Shared by from_env and from_target; `source` is the full leading phrase
        (e.g. "PROXIMO_PDM_VERIFY_TLS=false" or "PDM target verify_tls=false").
        """
        warnings.warn(
            f"{source} with no CA bundle — "
            "talking to the PDM API without cert validation.",
            stacklevel=3,
        )

    @classmethod
    def from_env(cls) -> PdmConfig:
        try:
            base_url = os.environ["PROXIMO_PDM_BASE_URL"]
            token_path = os.environ["PROXIMO_PDM_TOKEN_PATH"]
        except KeyError as e:
            raise RuntimeError(
                f"Missing required PDM env var: {e.args[0]}. "
                "Set PROXIMO_PDM_BASE_URL and PROXIMO_PDM_TOKEN_PATH to use pdm_* tools."
            ) from e

        url = cls._normalize_base_url(base_url)

        verify_tls = parse_verify_tls(os.environ.get("PROXIMO_PDM_VERIFY_TLS", "true"))
        ca_bundle = os.environ.get("PROXIMO_PDM_CA_BUNDLE") or None
        fingerprint = os.environ.get("PROXIMO_PDM_FINGERPRINT") or None

        if not verify_tls and not ca_bundle and not fingerprint:
            cls._warn_unverified_tls("PROXIMO_PDM_VERIFY_TLS=false")

        refuse_exposed_secret(token_path, "PDM token file")
        return cls(
            base_url=url,
            token_path=token_path,
            verify_tls=verify_tls,
            ca_bundle=ca_bundle,
            fingerprint=fingerprint,
        )

    @classmethod
    def from_target(cls, fields: dict) -> PdmConfig:
        """Build a PDM config from a named registry remote (see proximo.targets)."""
        try:
            base_url = fields["base_url"]
            token_path = fields["token_path"]
        except KeyError as e:
            raise RuntimeError(f"target missing required field: {e.args[0]}") from e
        url = cls._normalize_base_url(base_url)
        verify_tls = parse_verify_tls(fields.get("verify_tls", "true"))
        ca_bundle = fields.get("ca_bundle") or None
        fingerprint = fields.get("fingerprint") or None
        if not verify_tls and not ca_bundle and not fingerprint:
            cls._warn_unverified_tls("PDM target verify_tls=false")
        refuse_exposed_secret(token_path, "PDM token file")
        return cls(
            base_url=url,
            token_path=token_path,
            verify_tls=verify_tls,
            ca_bundle=ca_bundle,
            fingerprint=fingerprint,
        )


# ---------------------------------------------------------------------------
# PdmBackend
# ---------------------------------------------------------------------------

class PdmBackend:
    """Management via the Proxmox Datacenter Manager REST API using a PDM API token.

    Self-contained: does NOT depend on ProximoConfig.  Use PdmConfig.from_env()
    or construct PdmConfig directly for tests.

    PDM auth header: Authorization: PDMAPIToken TOKENID:SECRET
    (SPACE separator — NOT '=' like PVE/PBS)
    """

    def __init__(self, config: PdmConfig):
        self.config = config
        if config.fingerprint:
            # WIRE-ENFORCED pin: exact-cert SHA-256 match replaces CA/hostname validation
            # (self-signed PDM). Mismatch closes the socket before the token is sent.
            try:
                ctx = fingerprint_pinned_context(config.fingerprint)
            except ValueError as e:
                raise fingerprint_refused("PDM", e) from e
            self._client = httpx.Client(base_url=config.base_url, verify=ctx, timeout=60)
            return
        verify: bool | str = config.ca_bundle if config.ca_bundle else config.verify_tls
        # FAIL-CLOSED: this backend sends a real API-token secret on every request. Refuse
        # to construct it over a completely unverified channel (verify_tls=false AND no
        # ca_bundle AND no fingerprint).
        if verify is False:
            raise ProximoError(
                "refusing to send the PDM token over unverified TLS: set PROXIMO_PDM_FINGERPRINT "
                "to the cert's SHA-256 (self-signed PDM), PROXIMO_PDM_CA_BUNDLE to the PDM CA cert, "
                "or PROXIMO_PDM_VERIFY_TLS=true."
            )
        self._client = httpx.Client(base_url=config.base_url, verify=httpx_verify(verify), timeout=60)

    def _auth_header(self) -> dict[str, str]:
        # Token file holds: TOKENID:SECRET  (e.g. proximo@pdm!token:secret)
        # Header: Authorization: PDMAPIToken TOKENID:SECRET
        # NOTE: SPACE separator (not '=' like PBSAPIToken= / PVEAPIToken=)
        # Read at call time; NEVER logged.
        with open(self.config.token_path, encoding="utf-8") as f:
            token = f.read().strip()
        return {"Authorization": f"PDMAPIToken {token}"}

    def _get(self, path: str, params: dict | None = None):
        r = self._client.get(path, headers=self._auth_header(), params=params or {})
        r.raise_for_status()
        return r.json().get("data")

    def _post(self, path: str, data: dict | None = None, params: dict | None = None):
        """POST a mutation. Body goes as JSON; token read at call time, never logged."""
        r = self._client.post(path, headers=self._auth_header(), json=data or {}, params=params or {})
        r.raise_for_status()
        return r.json().get("data")

    def _delete(self, path: str, params: dict | None = None):
        """DELETE a resource (e.g. a snapshot). Token read at call time, never logged."""
        r = self._client.delete(path, headers=self._auth_header(), params=params or {})
        r.raise_for_status()
        return r.json().get("data")

    # --- Anti-boxing seam: remote-proxy primitives ---

    def _pve_remote_get(self, remote: str, subpath: str, params: dict | None = None):
        """Proxy a read to a PVE remote registered in PDM.

        PDM exposes a FLAT proxy surface under /pve/remotes/<remote>/<subpath>
        (no /api2/json — PDM re-shapes the PVE API into its own endpoints).
        This primitive is the loop-ready hook for future per-remote fan-out.
        """
        r = _check_remote(remote)
        path = f"/pve/remotes/{r}/{subpath.lstrip('/')}"
        return self._get(path, params)

    def _pbs_remote_get(self, remote: str, subpath: str, params: dict | None = None):
        """Proxy a read to a PBS remote registered in PDM.

        PDM exposes a FLAT proxy surface under /pbs/remotes/<remote>/<subpath>
        (no /api2/json — PDM re-shapes the PBS API into its own endpoints).
        This primitive is the loop-ready hook for future per-remote fan-out.
        """
        r = _check_remote(remote)
        path = f"/pbs/remotes/{r}/{subpath.lstrip('/')}"
        return self._get(path, params)

    def _pve_remote_post(self, remote: str, subpath: str, data: dict | None = None,
                         params: dict | None = None):
        """Proxy a POST mutation to a PVE remote registered in PDM.

        Same flat scheme as _pve_remote_get (/pve/remotes/<remote>/<subpath>), for
        the guest-lifecycle mutations PDM proxies (power/migrate/snapshot).
        """
        r = _check_remote(remote)
        path = f"/pve/remotes/{r}/{subpath.lstrip('/')}"
        return self._post(path, data, params)

    def _pve_remote_delete(self, remote: str, subpath: str, params: dict | None = None):
        """Proxy a DELETE to a PVE remote registered in PDM (e.g. snapshot delete)."""
        r = _check_remote(remote)
        path = f"/pve/remotes/{r}/{subpath.lstrip('/')}"
        return self._delete(path, params)

    # ---------------------------------------------------------------------------
    # A: PDM self + topology
    # ---------------------------------------------------------------------------

    def ping(self) -> str:
        """GET /ping → "pong" (health check)."""
        return self._get("/ping") or ""

    def version(self) -> dict:
        """GET /version → {release, repoid, version}."""
        return self._get("/version") or {}

    def node_status(self, node: str = "localhost") -> dict:
        """GET /nodes/{node}/status → node resource stats.

        PDM is a single-node appliance; node defaults to "localhost".
        Shape equals PVE node status; live-prove-pending (probe hit empty-node path).
        """
        n = _check_node(node)
        return self._get(f"/nodes/{n}/status") or {}

    def remotes_list(self) -> list[dict]:
        """GET /remotes/remote → list of registered PVE/PBS remotes.

        Each entry carries a (normally empty) 'token' field; credential-shaped keys are
        stripped before returning (defence-in-depth — the read surface never emits a secret).
        """
        result = self._get("/remotes/remote") or []
        return [_strip_secrets(r) for r in result if isinstance(r, dict)]

    def remote_version(self, remote_id: str) -> dict:
        """GET /remotes/remote/{id}/version → remote version info.

        Smoke-confirm: exact response shape (PDM proxies to the remote's /version).
        """
        rid = _check_remote(remote_id)
        return self._get(f"/remotes/remote/{rid}/version") or {}

    def remote_config_get(self, remote_id: str) -> dict:
        """GET /remotes/remote/{id}/config → remote configuration.

        Credential-shaped keys are stripped before returning (defence-in-depth):
        a PDM regression must not be able to hand a secret to the caller.
        """
        rid = _check_remote(remote_id)
        return _strip_secrets(self._get(f"/remotes/remote/{rid}/config") or {})

    # ---------------------------------------------------------------------------
    # B: Fleet aggregate
    # ---------------------------------------------------------------------------

    def resources_list(self, params: dict | None = None) -> list[dict]:
        """GET /resources/list → flat list of all fleet resources (VMs, LXCs, etc.)."""
        return self._get("/resources/list", params) or []

    def resources_status(self, params: dict | None = None) -> dict:
        """GET /resources/status → aggregated fleet status counters."""
        return self._get("/resources/status", params) or {}

    # ---------------------------------------------------------------------------
    # C: PVE per-remote reads (proxied)
    # ---------------------------------------------------------------------------

    def pve_resources(self, remote: str, kind: str | None = None) -> list[dict]:
        """GET /pve/remotes/{remote}/resources → resource list.

        kind: optional filter (vm, storage, node, sdn, ...) — passed as query 'kind'.
        Shape equals PVE cluster/resources; live-proven 2026-06-27 against a registered PVE remote.
        """
        params = {}
        if kind is not None:
            params["kind"] = _check_opt(kind, "kind")
        return self._pve_remote_get(remote, "resources", params or None) or []

    def pve_cluster_status(self, remote: str) -> list[dict]:
        """GET /pve/remotes/{remote}/cluster-status → cluster nodes.

        Shape equals PVE cluster/status; live-proven 2026-06-27 against a registered PVE remote.
        """
        return self._pve_remote_get(remote, "cluster-status") or []

    def pve_node_list(self, remote: str) -> list[dict]:
        """GET /pve/remotes/{remote}/nodes → list of PVE nodes.

        Shape equals PVE /nodes; live-proven 2026-06-27 against a registered PVE remote.
        """
        return self._pve_remote_get(remote, "nodes") or []

    def _guest_list(self, kind: str, remote: str, node: str | None = None) -> list[dict]:
        """GET /pve/remotes/{remote}/{kind} → guest list (cluster-wide).

        Shared body for pve_qemu_list/pve_lxc_list — node is an OPTIONAL filter,
        passed as query 'node' (PDM's guest list is cluster-wide).
        """
        params = {}
        if node is not None:
            params["node"] = _check_node(node)
        return self._pve_remote_get(remote, kind, params or None) or []

    def _guest_config(self, kind: str, remote: str, vmid: int | str, node: str | None = None,
                      snapshot: str | None = None, state: str = "active") -> dict:
        """GET /pve/remotes/{remote}/{kind}/{vmid}/config → guest config.

        Shared body for pve_qemu_config/pve_lxc_config — node, snapshot are OPTIONAL
        query params (node is NOT required); state is REQUIRED by PDM (enum; "active" =
        current config) and defaults to "active" — PDM rejects the request with 400 if
        it is omitted.
        """
        v = _check_vmid(vmid)
        params = {"state": _check_opt(state, "state")}
        if node is not None:
            params["node"] = _check_node(node)
        if snapshot is not None:
            params["snapshot"] = _check_opt(snapshot, "snapshot")
        return self._pve_remote_get(remote, f"{kind}/{v}/config", params) or {}

    def pve_qemu_list(self, remote: str, node: str | None = None) -> list[dict]:
        """GET /pve/remotes/{remote}/qemu → VM list (cluster-wide).

        node: OPTIONAL filter, passed as query 'node' (PDM's qemu list is cluster-wide).
        Shape equals PVE qemu list; live-proven 2026-06-27 against a registered PVE remote.
        """
        return self._guest_list("qemu", remote, node)

    def pve_qemu_config(self, remote: str, vmid: int | str, node: str | None = None,
                        snapshot: str | None = None, state: str = "active") -> dict:
        """GET /pve/remotes/{remote}/qemu/{vmid}/config → VM config.

        node, snapshot: OPTIONAL query params (node is NOT required).
        state: REQUIRED by PDM (enum; "active" = current config) — defaults to "active".
               PDM rejects the request with 400 if it is omitted.
        Live-proven 2026-06-27 against a registered PVE remote.
        """
        return self._guest_config("qemu", remote, vmid, node, snapshot, state)

    def pve_lxc_list(self, remote: str, node: str | None = None) -> list[dict]:
        """GET /pve/remotes/{remote}/lxc → LXC list (cluster-wide).

        node: OPTIONAL filter, passed as query 'node' (PDM's lxc list is cluster-wide).
        Shape equals PVE lxc list; live-proven 2026-06-27 against a registered PVE remote.
        """
        return self._guest_list("lxc", remote, node)

    def pve_lxc_config(self, remote: str, vmid: int | str, node: str | None = None,
                       snapshot: str | None = None, state: str = "active") -> dict:
        """GET /pve/remotes/{remote}/lxc/{vmid}/config → LXC config.

        node, snapshot: OPTIONAL query params (node is NOT required).
        state: REQUIRED by PDM (enum; "active" = current config) — defaults to "active".
               PDM rejects the request with 400 if it is omitted.
        Live-proven 2026-06-27 against a registered PVE remote.
        """
        return self._guest_config("lxc", remote, vmid, node, snapshot, state)

    # ---------------------------------------------------------------------------
    # D: PBS per-remote reads (proxied)
    # ---------------------------------------------------------------------------

    def pbs_remote_status(self, remote: str) -> dict:
        """GET /pbs/remotes/{remote}/status → PBS node status (cpu/memory/uptime/etc.).

        Live-verified (PDM 1.1 → PBS 4.2, 2026-06-27).
        """
        return self._pbs_remote_get(remote, "status") or {}

    def pbs_datastores_list(self, remote: str) -> list[dict]:
        """GET /pbs/remotes/{remote}/datastore → datastore list.

        Live-verified shape: [{"name": <store>, "path": <fs-path>}, ...]
        (PDM 1.1 → PBS 4.2, 2026-06-27).
        """
        return self._pbs_remote_get(remote, "datastore") or []

    def pbs_snapshots_list(self, remote: str, datastore: str,
                           ns: str | None = None) -> list[dict]:
        """GET /pbs/remotes/{remote}/datastore/{datastore}/snapshots → snapshot list.

        ns: optional namespace filter (query 'ns').
        Live-verified path (PDM 1.1 → PBS 4.2, 2026-06-27; empty datastore returned []).
        """
        ds = _check_datastore(datastore)
        params = {}
        if ns is not None:
            ns = _check_namespace(ns)
            params["ns"] = ns
        return self._pbs_remote_get(remote, f"datastore/{ds}/snapshots",
                                    params or None) or []

    # ---------------------------------------------------------------------------
    # E: Tasks + access
    # ---------------------------------------------------------------------------

    def tasks_list(self, params: dict | None = None) -> list[dict]:
        """GET /remotes/tasks/list → recent PDM tasks across all remotes."""
        return self._get("/remotes/tasks/list", params) or []

    def acl_list(self, path: str | None = None, exact: bool | None = None) -> list[dict]:
        """GET /access/acl → access control entries.

        path: optional ACL path filter (e.g. "/").
        exact: if True, return only the exact path, not inherited entries.
        """
        params: dict = {}
        if path is not None:
            params["path"] = _check_opt(path, "path")
        if exact is not None:
            params["exact"] = 1 if exact else 0
        return self._get("/access/acl", params or None) or []

    def roles_list(self) -> list[dict]:
        """GET /access/roles → all defined roles and their privileges."""
        return self._get("/access/roles") or []

    def users_list(self, include_tokens: bool | None = None) -> list[dict]:
        """GET /access/users → all PDM users.

        include_tokens: if True, include API token entries.
        Credential-shaped keys are stripped from each entry before returning
        (defence-in-depth — the read surface never emits a secret).
        """
        params: dict = {}
        if include_tokens is not None:
            params["include_tokens"] = 1 if include_tokens else 0
        result = self._get("/access/users", params or None) or []
        return [_strip_secrets(u) for u in result if isinstance(u, dict)]

    # ---------------------------------------------------------------------------
    # F: Fleet control — guest lifecycle mutations (proxied to a PVE remote)
    #
    # PDM proxies these on EXISTING guests only. Create/clone is NOT proxiable
    # (no collection-level POST on the remote proxy) — out of scope, not invented.
    # All are task-backed (return a UPID): the tool records "submitted", never "ok".
    # LIVE-PROVEN 2026-07-06 against real PDM 1.1.4 + nested PVE 9.2: power/snapshot/rollback/
    # in-cluster migrate (pdm-fleet-smoke.py) AND cross-remote remote-migrate — a real
    # datacenter-to-datacenter MOVE, source→target with delete, PROVE-chain verified
    # (pdm-remote-migrate-smoke.py, source labclu → standalone pve-test4). The live run
    # caught the target-bridge/target-storage scalar-vs-array bug the mocks had encoded.
    # ---------------------------------------------------------------------------

    def guest_power(self, remote: str, kind: str, vmid: int | str, action: str) -> str:
        """POST /pve/remotes/{remote}/{kind}/{vmid}/{action} → task UPID.

        Proxied power on an existing guest. action ∈ start/stop/shutdown (+resume for qemu);
        PDM proxies no reboot/suspend, so those are refused rather than invented.
        """
        k = _check_kind(kind)
        v = _check_vmid(vmid)
        a = _check_power_action(k, action)
        return self._pve_remote_post(remote, f"{k}/{v}/{a}")

    def guest_status(self, remote: str, kind: str, vmid: int | str) -> dict:
        """GET /pve/remotes/{remote}/{kind}/{vmid}/status → live guest state.

        Read used by the planner to preview a mutation (no-op detection, risk).
        """
        k = _check_kind(kind)
        v = _check_vmid(vmid)
        return self._pve_remote_get(remote, f"{k}/{v}/status") or {}

    def guest_migrate(self, remote: str, kind: str, vmid: int | str, target: str,
                      online: bool = False, target_storage: str | None = None) -> str:
        """POST /pve/remotes/{remote}/{kind}/{vmid}/migrate → task UPID.

        In-cluster migration. `target` is a node name; `online` migrates a running guest.
        `target_storage` optionally maps the guest's storage to a different target storage
        on the destination node (e.g. 'local-lvm:local-lvm') — sent as a single-element array,
        mirroring guest_remote_migrate's target-storage: PDM's typed API rejects a scalar there
        ('Expected array - got scalar value', 400). Booleans are sent as JSON true (PDM's typed
        API rejects int 1); flags omitted unless set.
        """
        k = _check_kind(kind)
        v = _check_vmid(vmid)
        t = _check_node(target)
        body: dict = {"target": t}
        if online:
            body["online"] = True
        if target_storage is not None:
            body["target-storage"] = [_check_opt(target_storage, "target-storage")]
        return self._pve_remote_post(remote, f"{k}/{v}/migrate", body)

    def guest_remote_migrate(self, remote: str, kind: str, vmid: int | str, target_remote: str,
                             target_bridge: str, target_storage: str, target_vmid: int | str | None = None,
                             online: bool = False, delete: bool = False) -> str:
        """POST /pve/remotes/{remote}/{kind}/{vmid}/remote-migrate → task UPID.

        Cross-remote (datacenter-to-datacenter) migration. `target_remote` is the destination
        remote ID; target-bridge and target-storage mappings are REQUIRED by the API.
        `delete` removes the source guest after a successful move — a destructive flag,
        off unless set.
        """
        k = _check_kind(kind)
        v = _check_vmid(vmid)
        tr = _check_remote(target_remote)
        tb = _check_opt(target_bridge, "target-bridge")
        ts = _check_opt(target_storage, "target-storage")
        if not tb.strip() or not ts.strip():
            raise ProximoError(
                "remote-migrate requires non-empty target_bridge and target_storage mappings "
                "(e.g. 'vmbr0:vmbr0', 'local-lvm:local-lvm')"
            )
        # target-bridge/target-storage are repeatable mapping params — PDM's typed API rejects
        # a scalar ("Expected array - got scalar value", 400). Send single-element arrays.
        body: dict = {"target": tr, "target-bridge": [tb], "target-storage": [ts]}
        if target_vmid is not None:
            body["target-vmid"] = _check_vmid(target_vmid)
        if online:
            body["online"] = True
        if delete:
            body["delete"] = True
        return self._pve_remote_post(remote, f"{k}/{v}/remote-migrate", body)

    def snapshot_create(self, remote: str, kind: str, vmid: int | str, snapname: str,
                        description: str | None = None, vmstate: bool = False) -> str:
        """POST /pve/remotes/{remote}/{kind}/{vmid}/snapshot → task UPID.

        `vmstate` includes the VM's RAM state (qemu). This is also the auto-UNDO
        primitive: a safety snapshot taken before a rollback.
        """
        k = _check_kind(kind)
        v = _check_vmid(vmid)
        s = _check_snapname(snapname)
        body: dict = {"snapname": s}
        if description is not None:
            body["description"] = _check_opt(description, "description")
        if vmstate:
            body["vmstate"] = True
        return self._pve_remote_post(remote, f"{k}/{v}/snapshot", body)

    def snapshot_delete(self, remote: str, kind: str, vmid: int | str, snapname: str) -> str:
        """DELETE /pve/remotes/{remote}/{kind}/{vmid}/snapshot/{snapname} → task UPID.

        Not reversible (a deleted snapshot cannot be recovered) — no UNDO primitive.
        """
        k = _check_kind(kind)
        v = _check_vmid(vmid)
        s = _check_snapname(snapname)
        return self._pve_remote_delete(remote, f"{k}/{v}/snapshot/{s}")

    def snapshot_rollback(self, remote: str, kind: str, vmid: int | str, snapname: str) -> str:
        """POST /pve/remotes/{remote}/{kind}/{vmid}/snapshot/{snapname}/rollback → task UPID.

        DESTRUCTIVE: discards current state back to the snapshot. The tool takes an
        auto safety-snapshot first (fail-closed), so the pre-rollback state is recoverable.
        """
        k = _check_kind(kind)
        v = _check_vmid(vmid)
        s = _check_snapname(snapname)
        return self._pve_remote_post(remote, f"{k}/{v}/snapshot/{s}/rollback")

    def task_status(self, remote: str, upid: str) -> dict:
        """GET /pve/remotes/{remote}/tasks/{upid}/status → proxied task status.

        Used by the auto-undo path to WAIT for a safety snapshot to actually finish
        before a rollback (fail-closed). The UPID is opaque but must be a single path
        segment — reject control chars and any '/'.
        """
        u = _check_upid(upid)
        return self._pve_remote_get(remote, f"tasks/{u}/status") or {}
