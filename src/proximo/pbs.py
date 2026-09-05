"""Proximo PBS (Proxmox Backup Server) lane — backend + tool/plan surface.

Separate backend because PBS is a distinct service from the PVE host:
- API base: https://<pbs-host>:8007/api2/json  (not :8006)
- Auth:     PBSAPIToken= (not PVEAPIToken=)
- Paths:    /admin/datastore/...  (not /nodes/{node}/...)

VERIFIED live shapes (PBS 4.2, re-proved 2026-06-26):
  GET /admin/datastore
    → [{"backend-type":"filesystem","comment":null,"mount-status":"nonremovable","store":"test-ds"}, ...]
    NOTE: the identity field is "store" (not "name"). The 2026-06-08 doc shape was WRONG —
    it showed "name" and "path" which are config-plane fields (from GET /config/datastore/{name}).
    GET /admin/datastore returns: store, backend-type, comment, mount-status.

  GET /admin/datastore/{store}/gc
    → {"disk-bytes":int,"disk-chunks":int,"index-data-bytes":int,"index-file-count":int,
       "last-run-endtime":epoch,"last-run-state":str,"pending-bytes":int,"pending-chunks":int,
       "removed-bad":int,"removed-bytes":int,"removed-chunks":int,"still-bad":int,
       "store":str,"upid":str|null}
    (keys re-verified; "next-run" and "schedule" absent on PBS 4.2 unless a schedule is set)

  GET /admin/datastore/{store}/status
    → {"avail":int,"backend-type":str,"total":int,"used":int}

  GET /admin/datastore/{store}/namespace
    → [{"ns": ""}, ...]   (root namespace is empty string "")

  PUT  /admin/datastore/{store}/protected
    body: {backup-type, backup-id, backup-time, protected:1|0, ns?}  → null on success

  GET/PUT /admin/datastore/{store}/notes
    body (PUT): {backup-type, backup-id, backup-time, notes:str, ns?}  → null on success
    GET params: backup-type, backup-id, backup-time, ns   → str (the notes, may be empty string)

  POST /admin/datastore/{store}/change-owner   ← POST (NOT PUT) — re-verified 2026-06-26
    body: {backup-type, backup-id, new-owner, ns?}  → null on success

  POST /config/datastore   → UPID (async worker task)
  GET  /config/datastore/{name}  → {name:str, path:str, comment?:str, gc-schedule?:str, ...}
  PUT  /config/datastore/{name}  → null on success
  DELETE /config/datastore/{name}  → UPID (async worker task)

  POST /config/remote   → null on success (not a UPID)
  PUT  /config/remote/{name}  → null on success
  DELETE /config/remote/{name}  → null on success
    body auth field: "auth-id" (VERIFIED) not "authid" or "userid"

  POST /config/traffic-control  (name in body)  → null on success
  PUT  /config/traffic-control/{name}  → null on success
  DELETE /config/traffic-control/{name}  → null on success
    GET /config/traffic-control/{name} on NONEXISTENT returns 400 (not 404) — both mean create.

  POST /config/{sync|verify|prune}  (id in body)  → null on success
  GET  /config/{sync|verify|prune}/{id}  → {id, store, schedule?, comment?, ...}
  PUT  /config/{sync|verify|prune}/{id}  → null on success
  DELETE /config/{sync|verify|prune}/{id}  → null on success

  POST /admin/datastore/{store}/verify  → UPID (async task)
  POST /admin/datastore/{store}/prune   body: {backup-type, backup-id, keep-*, dry-run:1?}
    NOTE: backup-type + backup-id are REQUIRED (the group must exist — no group → 400 ENOENT).

  POST /admin/datastore/{store}/namespace  body: {name, parent?}  → null on success
  DELETE /admin/datastore/{store}/namespace?ns=&delete-groups=?  → null on success

  POST /admin/datastore/{store}/gc  → UPID (async task)

All shapes above are VERIFIED live against PBS 4.2 (pbs-test CT31339, 2026-06-26).
Remaining "Smoke-confirm:" comments name specific unverified field/param details.

Security posture mirrors backends.py (and is stricter on TLS):
- Token read at call time from the token-path file; NEVER logged.
- TLS verification prefers ca_bundle over disabling. FAIL-CLOSED: constructing a
  PbsBackend with verify_tls=false AND no ca_bundle raises — the token-bearing backend
  refuses to send the secret over a completely unverified channel.
- Fingerprint is WIRE-ENFORCED: when set, an exact-cert SHA-256 pin replaces
  CA/hostname validation (the proxmox-backup-client --fingerprint idiom) — mismatch closes
  the socket before the token header is sent. A pin alone is sufficient verification.
- Input validators use \\Z (not $) to block trailing-newline bypass.
"""

from __future__ import annotations

import os
import re
import warnings
from dataclasses import dataclass

import httpx

from ._secretfile import refuse_exposed_secret
from ._tls import fingerprint_pinned_context, httpx_verify, parse_verify_tls
from ._validate import check_digest
from .backends import ProximoError, fingerprint_refused
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# Store name: path segment in /admin/datastore/{store}/... — reject traversal.
# PBS datastore names are alphanumeric + hyphen/underscore; no slash or control chars.
# \Z (not $) — Python's $ matches before a trailing newline, so "store\n" would slip through.
# Smoke-confirm: exact accepted charset against a live PBS with non-ASCII / special names.
_STORE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")

# Namespace: PBS namespaces ARE hierarchical (slash-delimited levels), so we cannot
# blanket-reject '/'.  Reject: '..', control chars (including newline), and traversal
# patterns. An empty string is the root namespace (valid).
# Smoke-confirm: exact allowed charset and depth limits against a live PBS.
_NS_UNSAFE_RE = re.compile(r"\.\.|[\x00-\x1f]|//")

# Backup types: documented PBS values.
# Smoke-confirm: full set of accepted values on the live PBS version.
_VALID_BACKUP_TYPES = frozenset({"vm", "ct", "host"})

# backup-id is typically a VMID (numeric) or a name, goes as a query/body param.
# Reject newlines and path-traversal chars; be permissive otherwise (Smoke-confirm exact charset).
_BACKUP_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def _check_store(store: str) -> str:
    # Do NOT strip — stripping defeats \Z trailing-newline protection.
    s = str(store)
    if not _STORE_RE.match(s):
        raise ProximoError(
            f"invalid PBS datastore name: {store!r} "
            "(must start with alnum, then alnum/_/-, <=64 chars, no slash or control chars)"
        )
    return s


# PBS node names are hostnames used as a URL path segment (/nodes/{node}/...). Validate the
# hostname charset so a crafted value can't traverse the path or inject query/control chars.
_PBS_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,63}\Z")


def _check_pbs_node(node: str) -> str:
    s = str(node)
    if not _PBS_NODE_RE.match(s):
        raise ProximoError(
            f"invalid PBS node name: {node!r} "
            "(hostname charset only: alnum/./-, <=64 chars, no slash or control chars)"
        )
    return s


def _check_namespace(ns: str | None) -> str | None:
    """Validate a PBS namespace string (may contain '/' for nested; may be empty = root).

    Rejects: '..', control chars (incl. newline), double-slash.
    Smoke-confirm: full accepted charset + max depth against a live PBS.
    """
    if ns is None:
        return None
    s = str(ns)
    if _NS_UNSAFE_RE.search(s) or s.startswith("/") or s.endswith("/"):
        raise ProximoError(
            f"invalid PBS namespace: {ns!r} "
            "(rejects '..', control chars, '//', leading/trailing '/'; "
            "nested levels use single '/', root is the empty string)"
        )
    return s


def _check_backup_type(backup_type: str | None) -> str | None:
    if backup_type is None:
        return None
    # Do NOT strip — newlines and control chars must be rejected, not silently removed.
    bt = str(backup_type)
    if bt not in _VALID_BACKUP_TYPES:
        raise ProximoError(
            f"invalid backup_type: {backup_type!r} "
            f"(expected one of {sorted(_VALID_BACKUP_TYPES)})"
        )
    return bt


def _check_backup_id(backup_id: str | None) -> str | None:
    if backup_id is None:
        return None
    # Do NOT strip — \Z must catch trailing newlines.
    bid = str(backup_id)
    if not _BACKUP_ID_RE.match(bid):
        raise ProximoError(
            f"invalid backup_id: {backup_id!r} "
            "(start with alnum, then alnum/._/-, <=64 chars, no control chars)"
        )
    return bid


def _check_backup_time(backup_time) -> int:
    """Validate a backup timestamp (Unix epoch integer)."""
    try:
        t = int(backup_time)
    except (ValueError, TypeError) as exc:
        raise ProximoError(
            f"invalid backup_time: {backup_time!r} (must be an integer Unix epoch)"
        ) from exc
    if t <= 0:
        raise ProximoError(
            f"invalid backup_time: {backup_time!r} (must be a positive epoch)"
        )
    return t


def _check_namespace_component(name: str) -> str:
    """Validate a single namespace name component (no '/' — used for namespace_create 'name').

    Does NOT strip — control chars and newlines must be rejected, not silently removed.
    Smoke-confirm: whether PBS namespace_create 'name' is a single component or a full path.
    """
    s = str(name)
    if not s:
        raise ProximoError("namespace name must not be empty")
    if "/" in s or _NS_UNSAFE_RE.search(s) or any(c < " " for c in s):
        raise ProximoError(
            f"invalid namespace name component: {name!r} "
            "(single component: no '/', no '..', no control chars)"
        )
    return s


# --- Wave 1b: PBS APT-plane validators ---
# Schema truth: .scratch/api-schemas-2026-07-15/methods-pbs.json (`/apt`) cross-checked against
# the live api-viewer full schema (pbs.proxmox.com/docs/api-viewer/apidoc.js, fetched 2026-07-15
# since the scratch snapshot carries no param-level detail) AND the upstream Rust source
# (src/api2/node/apt.rs, proxmox-backup git). PBS's shapes differ from PVE's in two places (the
# other five params match PVE's shape exactly): digest is a STRICT sha256 hex (64 lowercase hex
# chars, pattern `^[a-f0-9]{64}$` — proxmox_config_digest::ConfigDigest), and handle is a STRICT
# lowercase-leading pattern (`^[a-z][a-z0-9]*(-[a-z0-9]+)*$` — APTRepositoryHandle), unlike PVE's
# shape-only permissive validators for both.
#
# apt_get_changelog's `returns` metadata in the generated schema claims UPID_SCHEMA (an async
# task identifier) — but the actual handler (`fn apt_get_changelog(...) -> Result<String, Error>`
# calling `proxmox_apt::get_changelog(&options)` directly, no `WorkerTask::new_thread` spawn) is
# synchronous and returns the changelog text itself, exactly like PVE/PMG. The UPID_SCHEMA
# annotation appears to be a copy-paste artifact from the adjacent `apt_update_database` handler
# (which DOES spawn a WorkerTask) — cross-checked directly against the Rust source, not just the
# generated doc. Treated here as returning `str` (the changelog text), matching PVE/PMG.
_PBS_APT_PACKAGE_RE = re.compile(r"^[a-z0-9][-+.a-z0-9:]+\Z")
_PBS_APT_REPO_PATH_RE = re.compile(r"^/[^\x00-\x1f\x7f]*\Z")
_PBS_APT_HANDLE_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*\Z")


def _check_pbs_apt_package_name(name: str) -> str:
    """Validate an APT package name — PBS's own upstream changelog pattern (identical to PVE's)."""
    s = str(name)
    if not _PBS_APT_PACKAGE_RE.match(s):
        raise ProximoError(
            f"invalid package name: {name!r} "
            "(must start with lowercase alnum, then lowercase alnum/-+.:, min length 2)"
        )
    return s


def _check_pbs_apt_repo_path(path: str) -> str:
    """Validate an APT repository config file path (absolute, no control chars, no traversal)."""
    s = str(path)
    if not _PBS_APT_REPO_PATH_RE.match(s):
        raise ProximoError(f"invalid repository file path: {path!r} (must be an absolute path)")
    if ".." in s.split("/"):
        raise ProximoError(f"path traversal not allowed in repository path: {path!r}")
    return s


def _check_pbs_apt_index(index: int) -> int:
    """Validate a repository entry index (0-based position within its file)."""
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ProximoError(f"invalid repository index: {index!r} (must be a non-negative integer)")
    return index


def _check_pbs_apt_handle(handle: str) -> str:
    """Validate a standard-repository handle — PBS's own strict upstream pattern (APTRepositoryHandle:
    lowercase-leading, alnum/hyphen groups), unlike PVE/PMG's shape-only permissive validator."""
    s = str(handle)
    if not _PBS_APT_HANDLE_RE.match(s):
        raise ProximoError(
            f"invalid repository handle: {handle!r} "
            "(PBS requires: lowercase letter, then lowercase alnum, optionally hyphen-separated "
            "lowercase alnum groups — e.g. 'no-subscription')"
        )
    return s


# PBS's APT digest is its standard strict ConfigDigest (exactly 64 lowercase hex — a SHA-256
# digest), i.e. the SAME shape as every PBS/PMG config-plane digest, so it shares the
# plane-neutral `_validate.check_digest`. PVE/PMG's APT validators stay their own: genuinely
# divergent (hex up to 80 chars, mixed case).
_check_pbs_apt_digest = check_digest


# ---------------------------------------------------------------------------
# PbsConfig
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PbsConfig:
    """Configuration for the PBS API backend.

    All credentials are referenced by PATH — values are read at call time
    and never logged, so the secrets vault is never echoed.

    env vars:
        PROXIMO_PBS_BASE_URL     required  https://<host>:8007/api2/json
        PROXIMO_PBS_TOKEN_PATH   required  file containing USER@REALM!TOKENID:SECRET
        PROXIMO_PBS_VERIFY_TLS   optional  default "true"; set "false" to skip (warn)
        PROXIMO_PBS_CA_BUNDLE    optional  path to CA cert bundle (preferred over disabling TLS)
        PROXIMO_PBS_FINGERPRINT  optional  SHA-256 fingerprint of the PBS cert (the form the
                                           GUI shows). WIRE-ENFORCED: exact-cert pin replaces
                                           CA/hostname validation; mismatch refuses pre-request.
    """

    base_url: str          # e.g. "https://pbs.example.lan:8007/api2/json"
    token_path: str        # file containing: USER@REALM!TOKENID:SECRET  (run-but-not-read)
    verify_tls: bool = True
    ca_bundle: str | None = None
    fingerprint: str | None = None  # WIRE-ENFORCED exact-cert pin — see module docstring

    @classmethod
    def from_env(cls) -> PbsConfig:
        try:
            base_url = os.environ["PROXIMO_PBS_BASE_URL"]
            token_path = os.environ["PROXIMO_PBS_TOKEN_PATH"]
        except KeyError as e:
            raise RuntimeError(
                f"Missing required PBS env var: {e.args[0]}. "
                "To list PVE-side backup archives without PBS config, use pve_backup_list "
                "against a pbs-type storage (it goes through the PVE token you already have)."
            ) from e

        verify_tls = parse_verify_tls(os.environ.get("PROXIMO_PBS_VERIFY_TLS", "true"))
        ca_bundle = os.environ.get("PROXIMO_PBS_CA_BUNDLE") or None
        fingerprint = os.environ.get("PROXIMO_PBS_FINGERPRINT") or None

        if not verify_tls and not ca_bundle and not fingerprint:
            warnings.warn(
                "PROXIMO_PBS_VERIFY_TLS=false with no CA bundle and no fingerprint — "
                "talking to the PBS API without cert validation.",
                stacklevel=2,
            )

        refuse_exposed_secret(token_path, "PBS token file")
        return cls(
            base_url=base_url.rstrip("/"),
            token_path=token_path,
            verify_tls=verify_tls,
            ca_bundle=ca_bundle,
            fingerprint=fingerprint,
        )



    @classmethod
    def from_target(cls, fields: dict) -> PbsConfig:
        """Build a PBS config from a named registry remote (see proximo.targets)."""
        try:
            base_url = fields["base_url"]
            token_path = fields["token_path"]
        except KeyError as e:
            raise RuntimeError(f"target missing required field: {e.args[0]}") from e
        verify_tls = parse_verify_tls(fields.get("verify_tls", "true"))
        ca_bundle = fields.get("ca_bundle") or None
        fingerprint = fields.get("fingerprint") or None
        if not verify_tls and not ca_bundle and not fingerprint:
            warnings.warn(
                "PBS target verify_tls=false with no CA bundle and no fingerprint — "
                "talking to the PBS API without cert validation.",
                stacklevel=2,
            )
        refuse_exposed_secret(token_path, "PBS token file")
        return cls(
            base_url=base_url.rstrip("/"),
            token_path=token_path,
            verify_tls=verify_tls,
            ca_bundle=ca_bundle,
            fingerprint=fingerprint,
        )


# ---------------------------------------------------------------------------
# PbsBackend
# ---------------------------------------------------------------------------

class PbsBackend:
    """Management via the Proxmox Backup Server REST API using a PBS API token.

    Self-contained: does NOT depend on ProximoConfig.  Use PbsConfig.from_env()
    or construct PbsConfig directly for tests.

    PBS auth header: PBSAPIToken=USER@REALM!TOKENID:SECRET
    (token file holds the full 'USER@REALM!TOKENID:SECRET' string verbatim;
    the colon before the secret is PBS convention — Smoke-confirm the exact
    separator character against a live PBS auth test).
    """

    def __init__(self, config: PbsConfig):
        self.config = config
        if config.fingerprint:
            # WIRE-ENFORCED pin (the proxmox-backup-client --fingerprint idiom): the pin
            # replaces CA/hostname validation with an exact-certificate match — checked
            # post-handshake, socket closed on mismatch before the token header is sent.
            # A garbled pin refuses loudly here, never degrades into "no pin".
            try:
                ctx = fingerprint_pinned_context(config.fingerprint)
            except ValueError as e:
                raise fingerprint_refused("PBS", e) from e
            self._client = httpx.Client(base_url=config.base_url, verify=ctx, timeout=60)
            return
        verify: bool | str = config.ca_bundle if config.ca_bundle else config.verify_tls
        # FAIL-CLOSED: this backend sends a real API-token secret on every request. Refuse
        # to construct it over a completely unverified channel (verify_tls=false AND no
        # ca_bundle AND no fingerprint pin).
        if verify is False:
            raise ProximoError(
                "refusing to send the PBS token over unverified TLS: set PROXIMO_PBS_FINGERPRINT "
                "to the server cert's SHA-256 (the PBS GUI shows it; strongest for self-signed), "
                "or PROXIMO_PBS_CA_BUNDLE to the PBS CA cert, or PROXIMO_PBS_VERIFY_TLS=true."
            )
        self._client = httpx.Client(base_url=config.base_url, verify=httpx_verify(verify), timeout=60)

    def _auth_header(self) -> dict[str, str]:
        # Token file holds: USER@REALM!TOKENID:SECRET  (e.g. backup@pbs!token:secret)
        # Header: PBSAPIToken=USER@REALM!TOKENID:SECRET
        # Read at call time; NEVER logged.
        with open(self.config.token_path, encoding="utf-8") as f:
            token = f.read().strip()
        return {"Authorization": f"PBSAPIToken={token}"}

    def _get(self, path: str, params: dict | None = None):
        r = self._client.get(path, headers=self._auth_header(), params=params or {})
        r.raise_for_status()
        return r.json().get("data")

    @staticmethod
    def _form(d: dict | None) -> dict:
        # PBS (like PVE) wants booleans as 1/0; a raw Python bool serializes to 'true'/'false'
        # and is rejected. Coerce so any tool may pass a native bool. Ints pass through.
        return {k: (1 if v is True else 0 if v is False else v) for k, v in (d or {}).items()}

    def _post(self, path: str, data: dict | None = None):
        r = self._client.post(path, headers=self._auth_header(), data=self._form(data))
        r.raise_for_status()
        return r.json().get("data")

    def _put(self, path: str, data: dict | None = None):
        r = self._client.request("PUT", path, headers=self._auth_header(), data=self._form(data))
        r.raise_for_status()
        return r.json().get("data")

    def _delete(self, path: str, params: dict | None = None):
        r = self._client.request(
            "DELETE", path, headers=self._auth_header(), params=self._form(params)
        )
        r.raise_for_status()
        return r.json().get("data")


def _check_delete_list(delete: list[str] | None) -> list[str] | None:
    """Shared guard for every PBS `delete: list[str] | None` updater param (`data["delete"] =
    list(delete)` forwarded to `PbsBackend._put`/`_post`, PUT-encoded via `_form()` above).

    `None` passes through unchanged (no `delete` key at all — the caller isn't clearing
    anything). A non-empty list passes through as a `list` (normalizes tuples etc., same as the
    `list(delete)` call sites it replaces).

    `[]` RAISES. httpx's `data=` form encoding treats a dict value that is an empty *list* as
    zero repeated `key=value` pairs — the key never appears in the encoded body at all (verified
    directly against `PbsBackend._put`, Wave 5b review finding 1; contrast a non-empty list,
    which DOES round-trip via repeated-key form encoding, e.g. `delete=a&delete=b`). Every
    `plan_*_update` factory in this family used to advertise `delete=[]` in the dry-run `change`
    string on the theory that "it's a real wire payload the execute side sends" — that theory was
    false: confirm=True with `delete=[]` silently sends no `delete` param at all, a PLAN/PROVE
    parity gap. Rather than keep disclosing a payload that never reaches the wire, reject the
    empty case outright, loudly, at both plan-build and execute time — an empty delete list names
    nothing to clear, so there is no honest wire payload to send or preview.
    """
    if delete is None:
        return None
    if not delete:
        raise ProximoError(
            "delete list must name at least one property to reset — an empty list is dropped "
            "by the transport and would be a silent no-op"
        )
    return list(delete)


# ---------------------------------------------------------------------------
# READ operations — no plan needed; audited by the server layer
# ---------------------------------------------------------------------------

def datastore_list(api: PbsBackend) -> list[dict]:
    """List all datastores on the PBS server.

    GET /admin/datastore

    VERIFIED response shape (PBS 4.2, 2026-06-26):
      [{"backend-type": "filesystem", "comment": null,
        "mount-status": "nonremovable", "store": "test-ds"}, ...]

    Identity field is "store" (not "name"). To get the full config including path,
    gc-schedule, etc., call GET /config/datastore/{name} (used by datastore_get in pbs_config.py).
    """
    return api._get("/admin/datastore") or []


def datastore_status(api: PbsBackend, store: str) -> dict:
    """Get usage statistics for a PBS datastore.

    GET /admin/datastore/{store}/status

    Smoke-confirm: response field names — expected {total, used, avail, ...}
    but exact set and types not live-verified.
    """
    store = _check_store(store)
    return api._get(f"/admin/datastore/{store}/status") or {}


def gc_status(api: PbsBackend, store: str) -> dict:
    """Get GC (garbage collection) status for a PBS datastore.

    GET /admin/datastore/{store}/gc

    VERIFIED response shape (PBS 4.2.1, 2026-06-08):
      {"disk-bytes": int, "disk-chunks": int, "index-data-bytes": int,
       "index-file-count": int, "next-run": epoch, "pending-bytes": int,
       "pending-chunks": int, "removed-bad": int, "removed-bytes": int,
       "removed-chunks": int, "schedule": str, "still-bad": int,
       "store": str, "upid": str | null}
    """
    store = _check_store(store)
    return api._get(f"/admin/datastore/{store}/gc") or {}


def snapshots_list(
    api: PbsBackend,
    store: str,
    ns: str | None = None,
    backup_type: str | None = None,
    backup_id: str | None = None,
) -> list[dict]:
    """List backup snapshots in a PBS datastore, with optional filters.

    GET /admin/datastore/{store}/snapshots[?ns=&backup-type=&backup-id=]

    ns:          PBS namespace (hierarchical, e.g. 'team/prod'); None = root namespace.
    backup_type: 'vm', 'ct', or 'host' (Smoke-confirm full accepted set).
    backup_id:   e.g. '100' for VM 100 (Smoke-confirm exact format + accepted chars).

    Smoke-confirm: response field names per snapshot — expected {backup-id, backup-time,
    backup-type, files, owner, protected, verification, ...} but not live-verified.
    Smoke-confirm: whether 'ns' param is omitted for root or must be sent as empty string.
    """
    store = _check_store(store)
    ns = _check_namespace(ns)
    backup_type = _check_backup_type(backup_type)
    backup_id = _check_backup_id(backup_id)

    params: dict = {}
    if ns is not None:
        params["ns"] = ns
    if backup_type is not None:
        params["backup-type"] = backup_type
    if backup_id is not None:
        params["backup-id"] = backup_id

    return api._get(f"/admin/datastore/{store}/snapshots", params=params) or []


def namespace_list(
    api: PbsBackend,
    store: str,
    parent: str | None = None,
    max_depth: int | None = None,
) -> list[dict]:
    """List namespaces within a PBS datastore.

    GET /admin/datastore/{store}/namespace[?parent=&max-depth=]

    parent:    parent namespace to list under (None = root).
    max_depth: limit recursion depth (Smoke-confirm exact param name 'max-depth' vs 'max_depth').

    Smoke-confirm: response shape — expected [{"ns": str, ...}] but not live-verified.
    Smoke-confirm: exact query param names (hyphenated vs underscored).
    """
    store = _check_store(store)
    parent = _check_namespace(parent)

    params: dict = {}
    if parent is not None:
        params["parent"] = parent
    if max_depth is not None:
        try:
            d = int(max_depth)
        except (ValueError, TypeError) as exc:
            raise ProximoError(
                f"invalid max_depth: {max_depth!r} (must be an integer)"
            ) from exc
        params["max-depth"] = d  # Smoke-confirm: hyphenated vs underscored

    return api._get(f"/admin/datastore/{store}/namespace", params=params) or []


def tasks_list(
    api: PbsBackend,
    node: str = "localhost",
    limit: int | None = None,
    running: bool | None = None,
    errors: bool | None = None,
) -> list[dict]:
    """List tasks on a PBS node.

    GET /nodes/{node}/tasks[?limit=&running=&errors=]

    node:    PBS node name; defaults to 'localhost' (standard single-node PBS hostname).
             PBS is typically a single-node service — no node config on PbsConfig.
    limit:   maximum number of tasks to return.
    running: if True, return only currently running tasks.
    errors:  if True, return only tasks that ended with an error.

    Smoke-confirm: exact field names returned per task entry.
    Smoke-confirm: whether 'running' and 'errors' are accepted as boolean query params.
    """
    node = _check_pbs_node(node)
    params: dict = {}
    if limit is not None:
        try:
            params["limit"] = int(limit)
        except (ValueError, TypeError) as exc:
            raise ProximoError(
                f"invalid limit: {limit!r} (must be an integer)"
            ) from exc
    if running is not None:
        params["running"] = running
    if errors is not None:
        params["errors"] = errors
    return api._get(f"/nodes/{node}/tasks", params=params) or []


# ---------------------------------------------------------------------------
# APT plane (Wave 1b, 2026-07-15): patch-visibility + repository governance.
# Schema truth: .scratch/api-schemas-2026-07-15/methods-pbs.json (`/apt`) + the live api-viewer
# full schema + the upstream Rust source (src/api2/node/apt.rs) — see the validator-block comment
# above for the digest/handle/changelog cross-check notes. HONESTY LINE (every apt_* docstring in
# this plane, mirrored from PVE Wave 1a): Proxmox's API deliberately does not expose upgrade
# execution; the upgrade itself happens at your console. These methods govern visibility and repo
# config only.
# ---------------------------------------------------------------------------

def apt_updates_list(api: PbsBackend, node: str = "localhost") -> list[dict]:
    """List available package updates (cached apt index) on a PBS node.

    GET /nodes/{node}/apt/update

    Smoke-confirm: shape not live-verified. Expected per-package dicts (Package/Title/
    Description/Origin/Version/OldVersion/Priority/Section/Arch/ExtraInfo) per schema truth.
    """
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/apt/update") or []


def apt_changelog(api: PbsBackend, name: str, node: str = "localhost", version: str | None = None) -> str:
    """Get a package's changelog text on a PBS node.

    GET /nodes/{node}/apt/changelog?name=…[&version=…]

    Smoke-confirm: shape not live-verified. `name` is validated against PBS's own upstream
    package-name pattern (identical to PVE's). The returned text is UPSTREAM/package-
    maintainer-authored (not Proxmox-authored) — classified taint.ADVERSARIAL_TOOLS, like
    pve_apt_changelog and pmg_apt_changelog. See the validator-block comment above: despite the
    generated schema's `returns: UPID_SCHEMA` annotation, the upstream Rust handler is
    synchronous and returns the changelog text directly (cross-checked against the Rust source).
    """
    node = _check_pbs_node(node)
    _check_pbs_apt_package_name(name)
    params: dict = {"name": name}
    if version is not None:
        params["version"] = version
    return api._get(f"/nodes/{node}/apt/changelog", params=params) or ""


def apt_repositories_get(api: PbsBackend, node: str = "localhost") -> dict:
    """Get the current APT repository configuration of a PBS node.

    GET /nodes/{node}/apt/repositories

    Smoke-confirm: shape not live-verified. Expected {files, errors, digest, infos,
    standard-repos} per schema truth (APTRepositoriesResult).
    """
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/apt/repositories") or {}


def apt_versions(api: PbsBackend, node: str = "localhost") -> list[dict]:
    """Get installed versions of important Proxmox Backup Server packages on a PBS node.

    GET /nodes/{node}/apt/versions

    Smoke-confirm: shape not live-verified. Expected per-package dicts (Package/Version/
    OldVersion/Arch/... — the PBS-specific package list, e.g. proxmox-backup-server) per
    schema truth.
    """
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/apt/versions") or []


# ---------------------------------------------------------------------------
# MUTATION operations — confirm-gated at the server layer
# ---------------------------------------------------------------------------

def apt_update_refresh(
    api: PbsBackend, node: str = "localhost", notify: bool | None = None, quiet: bool | None = None,
) -> str | None:
    """Resynchronize the APT package index on a PBS node (apt-get update).

    POST /nodes/{node}/apt/update  →  UPID (async PBS task; upstream Rust handler genuinely
    spawns a WorkerTask here, unlike the changelog endpoint's doc-annotation artifact above).

    Refreshes the index ONLY — does not install or upgrade any package.
    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: response is a UPID string vs null.
    """
    node = _check_pbs_node(node)
    body = {k: v for k, v in {"notify": notify, "quiet": quiet}.items() if v is not None}
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/nodes/{node}/apt/update", body)


def apt_repository_set(
    api: PbsBackend,
    path: str,
    index: int,
    node: str = "localhost",
    enabled: bool | None = None,
    digest: str | None = None,
) -> None:
    """Enable/disable one APT repository entry on a PBS node, by file path + index.

    POST /nodes/{node}/apt/repositories  body: {path, index, enabled?, digest?}  →  null

    digest (SHA-256 hex, exactly 64 chars) asserts the current config file digest for
    optimistic-concurrency — forwarded when the caller supplies it.
    MUTATION — confirm-gated + audited at the server layer.
    """
    node = _check_pbs_node(node)
    _check_pbs_apt_repo_path(path)
    _check_pbs_apt_index(index)
    _check_pbs_apt_digest(digest)
    body: dict = {"path": path, "index": index}
    if enabled is not None:
        body["enabled"] = enabled
    if digest is not None:
        body["digest"] = digest
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/nodes/{node}/apt/repositories", body)


def apt_repository_add(
    api: PbsBackend, handle: str, node: str = "localhost", digest: str | None = None,
) -> None:
    """Add a standard repository to the configuration on a PBS node.

    PUT /nodes/{node}/apt/repositories  body: {handle, digest?}  →  null

    digest (SHA-256 hex, exactly 64 chars) asserts the current config file digest for
    optimistic-concurrency — forwarded when the caller supplies it.
    MUTATION — confirm-gated + audited at the server layer.
    """
    node = _check_pbs_node(node)
    _check_pbs_apt_handle(handle)
    _check_pbs_apt_digest(digest)
    body: dict = {"handle": handle}
    if digest is not None:
        body["digest"] = digest
    # MUTATION — confirm-gated + audited at the server layer.
    return api._put(f"/nodes/{node}/apt/repositories", body)


def gc_start(api: PbsBackend, store: str) -> str:
    """Start a GC (garbage collection) run on a PBS datastore.

    POST /admin/datastore/{store}/gc  →  UPID (async PBS task)

    GC permanently removes unreferenced chunks and frees disk space.
    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: response is a UPID string (async task) vs null.
    """
    store = _check_store(store)
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/admin/datastore/{store}/gc")


def verify_start(
    api: PbsBackend,
    store: str,
    ns: str | None = None,
    backup_type: str | None = None,
    backup_id: str | None = None,
) -> str:
    """Start an integrity verification run on a PBS datastore.

    POST /admin/datastore/{store}/verify  →  UPID (async PBS task)

    Non-destructive: reads and checks chunk checksums; no data is modified.
    Heavy I/O — may impact backup performance while running.

    body params (all optional):
      ns:          namespace to restrict verification to.
      backup-type: 'vm', 'ct', or 'host'.
      backup-id:   specific backup ID.

    MUTATION — confirm-gated + audited at the server layer (starts an async task).

    Smoke-confirm: exact body param names (hyphenated vs underscored).
    Smoke-confirm: whether partial-verification params are honored or the API ignores them.
    """
    store = _check_store(store)
    ns = _check_namespace(ns)
    backup_type = _check_backup_type(backup_type)
    backup_id = _check_backup_id(backup_id)

    data: dict = {}
    if ns is not None:
        data["ns"] = ns
    if backup_type is not None:
        data["backup-type"] = backup_type  # Smoke-confirm: hyphenated param name
    if backup_id is not None:
        data["backup-id"] = backup_id  # Smoke-confirm: hyphenated param name

    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/admin/datastore/{store}/verify", data)


def prune(
    api: PbsBackend,
    store: str,
    keep_last: int | None = None,
    keep_daily: int | None = None,
    keep_weekly: int | None = None,
    keep_monthly: int | None = None,
    keep_yearly: int | None = None,
    ns: str | None = None,
    backup_type: str | None = None,
    backup_id: str | None = None,
    dry_run: bool = True,
) -> list[dict]:
    """Prune backup snapshots in a PBS datastore per a retention policy.

    POST /admin/datastore/{store}/prune

    dry_run DEFAULTS TO True — safe preview mode that returns the prune decisions
    without deleting anything.  Set dry_run=False ONLY after reviewing the plan
    (plan_prune with dry_run=False is RISK_HIGH — deletes recovery points permanently).

    Returns a list of prune decision dicts: {backup-time, keep: bool, ...}.

    body params (Smoke-confirm all hyphenated param names against live PBS):
      keep-last, keep-daily, keep-weekly, keep-monthly, keep-yearly
      ns, backup-type, backup-id
      dry-run: 1 when dry_run=True

    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: exact hyphenated param names (keep-last vs keep_last etc.).
    Smoke-confirm: response shape per entry — expected {backup-time, keep, ...}.
    Smoke-confirm: whether 'ns' is required when the datastore has namespaces.
    """
    store = _check_store(store)
    ns = _check_namespace(ns)
    backup_type = _check_backup_type(backup_type)
    backup_id = _check_backup_id(backup_id)

    data: dict = {}

    # Retention policy knobs — Smoke-confirm: hyphenated param names
    for py_name, api_name in (
        (keep_last, "keep-last"),
        (keep_daily, "keep-daily"),
        (keep_weekly, "keep-weekly"),
        (keep_monthly, "keep-monthly"),
        (keep_yearly, "keep-yearly"),
    ):
        if py_name is not None:
            try:
                data[api_name] = int(py_name)
            except (ValueError, TypeError) as exc:
                raise ProximoError(
                    f"invalid {api_name}: {py_name!r} (must be an integer)"
                ) from exc

    if ns is not None:
        data["ns"] = ns
    if backup_type is not None:
        data["backup-type"] = backup_type  # Smoke-confirm
    if backup_id is not None:
        data["backup-id"] = backup_id  # Smoke-confirm

    if dry_run:
        data["dry-run"] = 1  # Smoke-confirm: 'dry-run' vs 'dry_run' param name

    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/admin/datastore/{store}/prune", data) or []


def snapshot_delete(
    api: PbsBackend,
    store: str,
    backup_type: str,
    backup_id: str,
    backup_time: int,
    ns: str | None = None,
) -> object:
    """Delete a specific backup snapshot from a PBS datastore.

    DELETE /admin/datastore/{store}/snapshots?backup-type=&backup-id=&backup-time=[&ns=]

    Permanently destroys the named snapshot (a recovery point). No undo.

    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: whether params go as query params (preferred per REST DELETE conventions)
    vs request body. Documented as query params in PBS API viewer — using params= here.
    Smoke-confirm: hyphenated param names (backup-type, backup-id, backup-time).
    Smoke-confirm: return value (expected null on success).
    """
    store = _check_store(store)
    backup_type = _check_backup_type(backup_type)  # type: ignore[assignment]
    backup_id = _check_backup_id(backup_id)  # type: ignore[assignment]
    backup_time = _check_backup_time(backup_time)
    ns = _check_namespace(ns)

    params: dict = {
        "backup-type": backup_type,   # Smoke-confirm: hyphenated
        "backup-id": backup_id,
        "backup-time": backup_time,
    }
    if ns is not None:
        params["ns"] = ns

    # MUTATION — confirm-gated + audited at the server layer.
    return api._delete(f"/admin/datastore/{store}/snapshots", params=params)


def namespace_create(
    api: PbsBackend,
    store: str,
    name: str,
    parent: str | None = None,
) -> object:
    """Create a namespace within a PBS datastore.

    POST /admin/datastore/{store}/namespace
    Body: {name: str, parent?: str}

    name:   single namespace component (no '/').
    parent: parent namespace path (hierarchical); None = create under root.

    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: whether 'name' is a single component or a full path.
    Smoke-confirm: response shape (expected null or {ns: str} on success).
    """
    store = _check_store(store)
    name = _check_namespace_component(name)
    parent = _check_namespace(parent)

    data: dict = {"name": name}
    if parent is not None:
        data["parent"] = parent

    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/admin/datastore/{store}/namespace", data)


def namespace_delete(
    api: PbsBackend,
    store: str,
    ns: str,
    delete_groups: bool = False,
) -> object:
    """Delete a namespace from a PBS datastore.

    DELETE /admin/datastore/{store}/namespace?ns=&[delete-groups=1]

    ns:            namespace to delete (required).
    delete_groups: when True, also deletes all backup groups/snapshots inside the namespace.
                   THIS ESCALATES TO RISK_HIGH — see plan_namespace_delete.

    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: exact param names and whether they go as query vs body.
    Smoke-confirm: response shape (expected null on success).
    Smoke-confirm: whether 'delete-groups' is the correct param name (vs 'delete_groups').
    """
    store = _check_store(store)
    ns_val = _check_namespace(ns)
    if ns_val is None or ns_val == "":
        raise ProximoError("namespace to delete must not be empty")

    params: dict = {"ns": ns_val}
    if delete_groups:
        params["delete-groups"] = 1  # Smoke-confirm: 'delete-groups' param name

    # MUTATION — confirm-gated + audited at the server layer.
    return api._delete(f"/admin/datastore/{store}/namespace", params=params)


# ---------------------------------------------------------------------------
# PLAN functions — pure factories; no mutation; the PLAN pillar
# ---------------------------------------------------------------------------

def _scope_description(
    store: str,
    ns: str | None = None,
    backup_type: str | None = None,
    backup_id: str | None = None,
) -> str:
    """Human-readable scope string shared by plan_prune and plan_verify_start."""
    parts = [f"datastore '{store}'"]
    if ns is not None:
        parts.append(f"namespace '{ns}'")
    if backup_type is not None:
        parts.append(f"type '{backup_type}'")
    if backup_id is not None:
        parts.append(f"id '{backup_id}'")
    return " / ".join(parts)


def plan_gc_start(store: str) -> Plan:
    """Preview starting a GC run on a PBS datastore.  PURE — no API call.

    RISK_HIGH:
    - GC permanently removes unreferenced chunks to reclaim disk space.
    - I/O-heavy and long-running; impacts backup/restore throughput while active.
    - If chunk references are corrupt, GC can remove data that is still referenced
      by an in-flight or partially-uploaded backup (a very rare but real blast radius).
    - No undo: removed chunks cannot be recovered.
    """
    store = _check_store(store)
    return Plan(
        action="pbs_gc_start",
        target=f"datastore/{store}",
        change=f"start GC on PBS datastore '{store}'",
        current={},
        blast_radius=[
            f"permanently removes unreferenced chunks from datastore '{store}'",
            "freed disk space is NOT recoverable; no undo",
            "I/O-heavy — may impact concurrent backup/restore operations",
            "in rare cases (corrupt references), GC can remove chunks still needed; "
            "verify datastore integrity first",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "GC permanently destroys storage chunks — no undo",
            "long-running I/O operation with cluster-wide impact on backup throughput",
        ],
        note=(
            "GC is async — returns a UPID; poll task status for completion. "
            "Ensure no backups are actively uploading before starting GC."
        ),
    )


def plan_prune(
    store: str,
    keep_last: int | None = None,
    keep_daily: int | None = None,
    keep_weekly: int | None = None,
    keep_monthly: int | None = None,
    keep_yearly: int | None = None,
    ns: str | None = None,
    backup_type: str | None = None,
    backup_id: str | None = None,
    dry_run: bool = True,
) -> Plan:
    """Preview a prune operation on a PBS datastore.  PURE — no API call.

    dry_run=True  → RISK_LOW:  preview only — returns what WOULD be pruned; deletes nothing.
    dry_run=False → RISK_HIGH: DELETES backup snapshots per retention policy; no undo.

    The 'keep_*' parameters define the retention policy:
    - keep_last:    retain the N most recent backups regardless of time.
    - keep_daily:   retain the last N days (one backup per day).
    - keep_weekly:  retain the last N weeks.
    - keep_monthly: retain the last N months.
    - keep_yearly:  retain the last N years.

    Deleted backups are recovery points — destroying them permanently reduces your
    restore options.  NEVER claim this operation is "safe" even with dry_run=True
    (a dry run does not change state; that is not the same as safe).
    """
    store = _check_store(store)
    ns = _check_namespace(ns)
    backup_type = _check_backup_type(backup_type)
    backup_id = _check_backup_id(backup_id)

    policy_parts = []
    for label, val in (
        ("keep-last", keep_last),
        ("keep-daily", keep_daily),
        ("keep-weekly", keep_weekly),
        ("keep-monthly", keep_monthly),
        ("keep-yearly", keep_yearly),
    ):
        if val is not None:
            policy_parts.append(f"{label}={val}")
    policy_str = ", ".join(policy_parts) if policy_parts else "(no keep policy set — ALL may be pruned)"

    scope_str = _scope_description(store, ns, backup_type, backup_id)

    if dry_run:
        return Plan(
            action="pbs_prune",
            target=f"datastore/{store}",
            change=f"prune preview (dry-run) on {scope_str} — policy: {policy_str}",
            current={},
            blast_radius=[
                "DRY RUN — preview only; NO backups will be deleted",
                f"shows which snapshots WOULD be removed under policy: {policy_str}",
                "to execute: re-call prune() with dry_run=False (that is RISK_HIGH)",
            ],
            risk=RISK_LOW,
            risk_reasons=["dry_run=True — no state change; returns prune decisions without deleting"],
            note=(
                "LOW means 'does not change state', NOT 'safe'. "
                "Review the returned decisions carefully before executing with dry_run=False."
            ),
        )
    else:
        return Plan(
            action="pbs_prune",
            target=f"datastore/{store}",
            change=f"EXECUTE prune on {scope_str} — policy: {policy_str}",
            current={},
            blast_radius=[
                f"PERMANENTLY DELETES backup snapshots from {scope_str}",
                f"retention policy: {policy_str}",
                "deleted backups are RECOVERY POINTS — they cannot be recovered",
                "no undo: once pruned, those restore points are gone",
                "run with dry_run=True first to preview what will be deleted",
            ],
            risk=RISK_HIGH,
            risk_reasons=[
                "prune with dry_run=False DELETES backup snapshots permanently",
                "deleted backups are the UNDO substrate itself — this destroys recovery points",
                "no undo available",
            ],
            note=(
                "Prune is the operation that deletes backup snapshots per retention policy. "
                "GC (separate) is needed afterward to actually reclaim the freed disk space."
            ),
        )


def plan_snapshot_delete(
    store: str,
    backup_type: str,
    backup_id: str,
    backup_time: int,
    ns: str | None = None,
) -> Plan:
    """Preview deleting a specific PBS backup snapshot.  PURE — no API call.

    RISK_HIGH: permanently destroys a specific recovery point; no undo.
    """
    store = _check_store(store)
    backup_type = _check_backup_type(backup_type)  # type: ignore[assignment]
    backup_id = _check_backup_id(backup_id)  # type: ignore[assignment]
    backup_time = _check_backup_time(backup_time)
    ns = _check_namespace(ns)

    ns_note = f" in namespace '{ns}'" if ns else ""
    target_desc = (
        f"{backup_type}/{backup_id}@{backup_time}{ns_note} "
        f"in datastore '{store}'"
    )

    return Plan(
        action="pbs_snapshot_delete",
        target=f"datastore/{store}/{backup_type}/{backup_id}@{backup_time}",
        change=f"delete backup snapshot: {target_desc}",
        current={},
        blast_radius=[
            f"PERMANENTLY DELETES backup snapshot: {target_desc}",
            "this removes a specific recovery point — it cannot be restored",
            "no undo: the snapshot data is gone once removed",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "deletes a backup snapshot (a recovery point) permanently",
            "no undo available — the specific restore point is destroyed",
        ],
        note=(
            "Deleting a snapshot does not immediately reclaim disk space — "
            "run GC afterward to free unreferenced chunks."
        ),
    )


def plan_namespace_create(
    store: str,
    name: str,
    parent: str | None = None,
) -> Plan:
    """Preview creating a namespace in a PBS datastore.  PURE — no API call.

    RISK_LOW: additive operation — creates a new namespace hierarchy node.
    No existing data is touched.
    """
    store = _check_store(store)
    name = _check_namespace_component(name)
    parent = _check_namespace(parent)

    parent_note = f" under parent '{parent}'" if parent else " at root"
    full_path = f"{parent}/{name}" if parent else name

    return Plan(
        action="pbs_namespace_create",
        target=f"datastore/{store}/namespace/{full_path}",
        change=f"create namespace '{name}'{parent_note} in datastore '{store}'",
        current={},
        blast_radius=[
            f"creates namespace '{full_path}' in datastore '{store}' (additive — no data changed)",
        ],
        risk=RISK_LOW,
        risk_reasons=["additive — creates a namespace; no existing data is modified or deleted"],
        note=(
            "Smoke-confirm: whether namespace_create 'name' is a single component or a full path."
        ),
    )


def plan_namespace_delete(
    store: str,
    ns: str,
    delete_groups: bool = False,
) -> Plan:
    """Preview deleting a namespace from a PBS datastore.  PURE — no API call.

    delete_groups=False → RISK_MEDIUM: deletes an empty namespace; no backup data lost.
    delete_groups=True  → RISK_HIGH:   deletes the namespace AND all backup groups/snapshots
                          inside it — permanently destroys recovery points; no undo.
    """
    store = _check_store(store)
    ns_val = _check_namespace(ns)
    if ns_val is None or ns_val == "":
        raise ProximoError("namespace to delete must not be empty")

    if delete_groups:
        return Plan(
            action="pbs_namespace_delete",
            target=f"datastore/{store}/namespace/{ns_val}",
            change=f"delete namespace '{ns_val}' AND all its backup groups/snapshots "
                   f"from datastore '{store}'",
            current={},
            blast_radius=[
                f"PERMANENTLY DELETES namespace '{ns_val}' and ALL backup groups/snapshots inside it",
                f"datastore: '{store}'",
                "all recovery points inside the namespace are destroyed — no undo",
                "this is equivalent to bulk snapshot deletion for everything under the namespace",
            ],
            risk=RISK_HIGH,
            risk_reasons=[
                "delete_groups=True: deletes ALL backup groups and snapshots inside the namespace",
                "permanently destroys recovery points; no undo",
            ],
            note=(
                "Smoke-confirm: 'delete-groups' is the correct PBS API param name. "
                "Verify no active backups are running inside this namespace before deleting."
            ),
        )
    else:
        return Plan(
            action="pbs_namespace_delete",
            target=f"datastore/{store}/namespace/{ns_val}",
            change=f"delete namespace '{ns_val}' from datastore '{store}' "
                   f"(namespace must be empty — no backup groups deleted)",
            current={},
            blast_radius=[
                f"deletes namespace '{ns_val}' from datastore '{store}'",
                "namespace must be empty (no groups/snapshots); PBS will reject if non-empty",
                "no backup data is deleted by this operation",
                "to delete a non-empty namespace, use delete_groups=True (RISK_HIGH)",
            ],
            risk=RISK_MEDIUM,
            risk_reasons=[
                "removes a namespace container; backup data inside would need delete_groups=True",
                "medium risk: structural change, but no data deleted when delete_groups=False",
            ],
            note=(
                "Smoke-confirm: PBS behavior when namespace is non-empty and delete_groups=False "
                "(expected rejection, but verify error shape)."
            ),
        )


def plan_verify_start(
    store: str,
    ns: str | None = None,
    backup_type: str | None = None,
    backup_id: str | None = None,
) -> Plan:
    """Preview starting a PBS verification run.  PURE — no API call.

    RISK_LOW: non-destructive integrity check — reads and verifies chunk checksums;
    no data is modified. Heavy I/O; may impact backup/restore performance while running.
    """
    store = _check_store(store)
    ns = _check_namespace(ns)
    backup_type = _check_backup_type(backup_type)
    backup_id = _check_backup_id(backup_id)

    scope_str = _scope_description(store, ns, backup_type, backup_id)

    return Plan(
        action="pbs_verify_start",
        target=f"datastore/{store}",
        change=f"start integrity verification on {scope_str}",
        current={},
        blast_radius=[
            f"reads and verifies chunk checksums for {scope_str}",
            "NON-DESTRUCTIVE — no data is modified or deleted",
            "I/O-heavy: may impact backup/restore throughput while running",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "read-only integrity check — no data modification",
            "non-destructive; LOW means 'does not change state', not 'safe'",
        ],
        note=(
            "Verify is async — returns a UPID; poll task status for completion. "
            "I/O load may be significant on large datastores."
        ),
    )


# ---------------------------------------------------------------------------
# APT plane PLAN factories (Wave 1b, 2026-07-15)
# ---------------------------------------------------------------------------

def plan_apt_update_refresh(
    node: str = "localhost", notify: bool | None = None, quiet: bool | None = None,
) -> Plan:
    """Plan for pbs_apt_update_refresh — resynchronize the APT package index (apt-get update).

    No CAPTURE: refreshing the index is idempotent (re-running it any time is always safe) —
    there is no meaningful "current index state" to snapshot for revert.
    """
    node = _check_pbs_node(node)
    return Plan(
        action="pbs_apt_update_refresh",
        target=f"nodes/{node}/apt/update",
        change=f"resynchronize the APT package index on PBS node '{node}' (apt-get update)",
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
    api: PbsBackend,
    path: str,
    index: int,
    node: str = "localhost",
    enabled: bool | None = None,
    digest: str | None = None,
) -> Plan:
    """Plan for pbs_apt_repository_set — enable/disable one repository entry by path+index.

    CAPTURE-or-declare: reads current repository state via GET /apt/repositories (reuses
    apt_repositories_get) and looks up the file+index entry's current shape; a successful read
    that simply finds no match degrades to current={} (honest empty snapshot), not a failure —
    only a raised exception on the read itself sets complete=False.
    """
    node = _check_pbs_node(node)
    _check_pbs_apt_repo_path(path)
    _check_pbs_apt_index(index)
    _check_pbs_apt_digest(digest)
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
        action="pbs_apt_repository_set",
        target=f"nodes/{node}/apt/repositories:{path}#{index}",
        change=f"change repository entry {index} in {path!r} on PBS node '{node}': {changes}",
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
            "Revert by re-applying the captured enabled-state with pbs_apt_repository_set."
            + note_capture
        ),
    )


def plan_apt_repository_add(
    api: PbsBackend, handle: str, node: str = "localhost", digest: str | None = None,
) -> Plan:
    """Plan for pbs_apt_repository_add — add a standard repository to the configuration.

    CAPTURE-or-declare: reads current repository state via GET /apt/repositories (reuses
    apt_repositories_get) and looks up the handle's current standard-repo status; a successful
    read that simply finds no match degrades to current={} (honest empty snapshot — the handle
    was never added), not a failure — only a raised exception on the read itself sets
    complete=False.
    """
    node = _check_pbs_node(node)
    _check_pbs_apt_handle(handle)
    _check_pbs_apt_digest(digest)
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
        action="pbs_apt_repository_add",
        target=f"nodes/{node}/apt/repositories:{handle}",
        change=f"add standard repository {handle!r} to the configuration on PBS node '{node}'",
        current=current,
        blast_radius=[
            f"node/{node} APT sources — adds {handle!r}; the NEXT apt-get upgrade (run at your "
            "console — this API does not execute it) additionally pulls packages from it"
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["adds a new package source — affects package provenance for the next upgrade"],
        complete=complete,
        note=(
            "No automatic revert: removing an added repository requires pbs_apt_repository_set "
            "to disable the resulting entry (there is no repository-delete endpoint)."
            + note_capture
        ),
    )
