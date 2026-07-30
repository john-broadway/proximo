"""Proximo backends: the two halves of Proxmox control.

ApiBackend  -> management via the Proxmox REST API + scoped token.
ExecBackend -> in-container work via ssh -> pct exec (the API has no LXC-exec endpoint).

Security posture:
- The token is read from disk at call time and NEVER logged.
- ExecBackend shells out to the operator's existing `ssh` host alias; no password handling.
- The CTID allowlist is enforced (fail-closed) before any exec.
- API path components (vmid/kind/node) are validated, not trusted.
- TLS verification prefers a CA bundle over disabling verification.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from dataclasses import dataclass
from urllib.parse import quote, urlencode

import httpx

from ._tls import fingerprint_pinned_context, httpx_verify
from .config import ProximoConfig

# NB: \Z (not $) — Python's $ matches before a trailing newline, so "valid\n" would slip through.
_VALID_KINDS = frozenset({"lxc", "qemu"})

# QEMU agent command allow-lists: CLOSED sets — no arbitrary string goes into the URL path.
# These are the canonical sets; qemu_agent.py imports them so validators stay in sync.
# Command names match PVE docs; the GET/POST dispatch is VERIFIED live (PVE 9.2, see below),
# though the guest-agent JSON each read command returns is guest-dependent (not a fixed shape).
_VALID_AGENT_INFO_CMDS = frozenset({
    "ping", "info", "get-fsinfo", "get-host-name", "get-osinfo", "get-time",
    "get-timezone", "get-users", "get-vcpus", "network-get-interfaces",
    "get-memory-blocks", "fsfreeze-status",
    # exec-status is dispatched separately (requires pid); kept here for allowlist completeness
    # but agent_simple() does NOT accept it — route through agent_exec_status() instead.
})
_VALID_AGENT_FS_CMDS = frozenset({"fsfreeze-freeze", "fsfreeze-thaw", "fstrim"})
# Union used by agent_simple(); intentionally excludes exec-status (needs separate pid param).
_VALID_AGENT_SIMPLE_CMDS = _VALID_AGENT_INFO_CMDS | _VALID_AGENT_FS_CMDS
# PVE serves agent READ commands as GET; ACTION commands (ping + fsfreeze-* + fstrim, and counter-
# intuitively fsfreeze-status) as POST. VERIFIED live against PVE 9.2 (a POST to a get-* path 501s).
_AGENT_GET_CMDS = frozenset({
    "info", "get-host-name", "get-osinfo", "get-time", "get-timezone", "get-users",
    "get-vcpus", "network-get-interfaces", "get-memory-blocks", "get-fsinfo",
})
_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\Z")
# Snapshot name: PVE requires a leading letter, then letters/digits/_/- (hyphen on newer PVE).
# Also the gate against path traversal in the {snapname} URL segment (no '/', '..', spaces, newline).
_SNAPNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,39}\Z")
# Task UPID: "UPID:node:pid:pstart:starttime:type:id:user:" — colon-delimited, no '/'. Length-capped.
_UPID_RE = re.compile(r"^UPID:[A-Za-z0-9._:@!-]{1,256}\Z")

# --- Wave 4: node-lifecycle validators ---
# Disk device path: must start with /dev/; allow letters, digits, slash, underscore, hyphen.
# \Z anchor prevents trailing-newline bypass. Component check (split on '/') rejects '..'.
# Smoke-confirm: PVE accepts any /dev/... path; closed-ish rather than an exact allowlist.
_DISK_RE = re.compile(r"^/dev/[a-zA-Z0-9/_-]+\Z")

# Storage backend: closed set — no arbitrary string goes into the URL path.
_VALID_BACKENDS = frozenset({"lvm", "lvmthin", "zfs", "directory"})

# Storage name: alnum + underscore + hyphen; must start with alnum; max 64 chars.
_STORAGE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")

# Timezone: IANA tz format (Region/City, UTC, etc.). Letters, digits, underscore, plus, hyphen,
# slash allowed. \Z anchor prevents trailing-newline bypass.
# Smoke-confirm: PVE accepts any valid IANA timezone string; this is a safe superset.
_TIMEZONE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,63}\Z")


class ProximoError(RuntimeError):
    """Operational error surfaced to the caller (never carries secrets)."""


def _check_vmid(vmid: str) -> str:
    if not re.fullmatch(r"[0-9]+", str(vmid)):  # ASCII 0-9 only; str.isdigit() also accepts Unicode digits
        raise ProximoError(f"invalid vmid: {vmid!r} (must be numeric)")
    return str(vmid)


# Guest OS username (qemu-agent set-user-password): non-empty, no C0 control chars / DEL, <=256.
# \Z anchor rejects trailing-newline slip-through.
_USERNAME_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,256}\Z")


def _check_username(username: str) -> str:
    if not _USERNAME_RE.match(str(username)):
        raise ProximoError(f"invalid username: {username!r} (1-256 chars, no control characters)")
    return str(username)


def _check_kind(kind: str) -> str:
    if kind not in _VALID_KINDS:
        raise ProximoError(f"unsupported guest kind: {kind!r} (expected lxc|qemu)")
    return kind


def _check_node(node: str | None) -> None:
    if node is not None and not _NODE_RE.match(node):
        raise ProximoError(f"invalid node name: {node!r}")


def _check_snapname(snapname: str) -> str:
    s = str(snapname)
    if s == "current":
        raise ProximoError("'current' is reserved by Proxmox (the live state); choose another name")
    if not _SNAPNAME_RE.match(s):
        raise ProximoError(
            f"invalid snapshot name: {snapname!r} (start with a letter, then letters/digits/_/-, <=40)"
        )
    return s


def _check_upid(upid: str) -> str:
    if not _UPID_RE.match(str(upid)):
        raise ProximoError(f"invalid task upid: {upid!r}")
    return str(upid)


def _check_disk(disk: str) -> str:
    """Validate a block device path (e.g. /dev/sdb). Rejects traversal and non-/dev/ paths."""
    s = str(disk)
    if not _DISK_RE.match(s):
        raise ProximoError(
            f"invalid disk device path: {disk!r} "
            "(must start with /dev/ then letters/digits/underscore/hyphen/slash)"
        )
    # Component-level traversal check: no '..' segment after splitting on '/'.
    if ".." in s.split("/"):
        raise ProximoError(f"path traversal not allowed in disk path: {disk!r}")
    return s


def _check_backend(backend: str) -> str:
    """Validate a storage backend type against the closed set {lvm, lvmthin, zfs, directory}."""
    if backend not in _VALID_BACKENDS:
        raise ProximoError(
            f"unsupported storage backend: {backend!r} "
            f"(valid: {sorted(_VALID_BACKENDS)!r})"
        )
    return backend


def _check_storage_name(name: str) -> str:
    """Validate a storage backend name (alnum + underscore/hyphen; starts with alnum)."""
    s = str(name)
    if not _STORAGE_NAME_RE.match(s):
        raise ProximoError(
            f"invalid storage name: {name!r} "
            "(must start with alnum, then alnum/underscore/hyphen, max 64 chars)"
        )
    return s


def _check_timezone(tz: str) -> str:
    """Validate a timezone string (IANA format, e.g. America/Chicago, UTC)."""
    s = str(tz)
    if not _TIMEZONE_RE.match(s):
        raise ProximoError(
            f"invalid timezone: {tz!r} "
            "(expected IANA format, e.g. 'America/Chicago', 'UTC', 'Europe/Berlin')"
        )
    return s


# --- Wave 1a: PVE APT-plane validators ---
# Package name: matches PVE's own upstream changelog-endpoint pattern
# (PVE::API2::APT changelog 'name' param: qr/[a-z0-9][-+.a-z0-9:]+/, cross-checked against the
# upstream Perl source 2026-07-15) — lowercase alnum, then lowercase alnum/-+.: , min length 2.
_APT_PACKAGE_RE = re.compile(r"^[a-z0-9][-+.a-z0-9:]+\Z")

# Repository config file path: absolute, no control chars, no traversal (mirrors _check_file_path
# below — apt/repositories 'path' is a filesystem path, e.g. /etc/apt/sources.list.d/pve.sources).
_APT_REPO_PATH_RE = re.compile(r"^/[^\x00-\x1f\x7f]*\Z")

# Standard-repo handle: shape-only — the valid set (no-subscription/enterprise/test, plus
# product/codename-specific ceph-* variants) is version/product-dependent, not a fixed enum
# upstream. Alnum + hyphen, leading alnum, capped length; no arbitrary string into the URL body.
_APT_HANDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}\Z")

# Digest: PVE's config-file content hash (hex, sha1/sha256-shaped), maxLength 80 per the upstream
# schema (PVE::API2::APT add_repository/change_repository 'digest' param).
_APT_DIGEST_RE = re.compile(r"^[0-9a-fA-F]{1,80}\Z")


def _check_apt_package_name(name: str) -> str:
    """Validate an APT package name against PVE's own changelog-endpoint pattern."""
    s = str(name)
    if not _APT_PACKAGE_RE.match(s):
        raise ProximoError(
            f"invalid package name: {name!r} "
            "(must start with lowercase alnum, then lowercase alnum/-+.:, min length 2)"
        )
    return s


def _check_apt_repo_path(path: str) -> str:
    """Validate an APT repository config file path (absolute, no control chars, no traversal)."""
    s = str(path)
    if not _APT_REPO_PATH_RE.match(s):
        raise ProximoError(f"invalid repository file path: {path!r} (must be an absolute path)")
    if ".." in s.split("/"):
        raise ProximoError(f"path traversal not allowed in repository path: {path!r}")
    return s


def _check_apt_index(index: int) -> int:
    """Validate a repository entry index (0-based position within its file)."""
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ProximoError(f"invalid repository index: {index!r} (must be a non-negative integer)")
    return index


# APT digest/handle validators below are client-side tightening: PVE's schema places no pattern
# constraints (digest: maxLength 80 only; handle: unconstrained). Defensive for real-world Proxmox
# values (hex digests, alnum-hyphen handles), not schema-mandated.
def _check_apt_handle(handle: str) -> str:
    """Validate a standard-repository handle (shape-only — the valid set is version/product-dependent)."""
    s = str(handle)
    if not _APT_HANDLE_RE.match(s):
        raise ProximoError(
            f"invalid repository handle: {handle!r} "
            "(must start with alnum, then alnum/hyphen, max 64 chars)"
        )
    return s


def _check_apt_digest(digest: str | None) -> str | None:
    """Validate an optional optimistic-concurrency digest (hex, <=80 chars per schema)."""
    if digest is None:
        return None
    s = str(digest)
    if not _APT_DIGEST_RE.match(s):
        raise ProximoError(f"invalid digest: {digest!r} (expected hex string, max 80 chars)")
    return s


# --- Wave 6a: PVE Ceph-plane validators (core observability + flags) ---
# Schema truth: .scratch/api-schemas-2026-07-15/wave6-pve-ceph-schema.json.

# The 11 Ceph flags — closed enum per schema (GET/PUT /cluster/ceph/flags[/{flag}]).
_CEPH_FLAGS = frozenset({
    "nobackfill", "nodeep-scrub", "nodown", "noin", "noout", "norebalance",
    "norecover", "noscrub", "notieragent", "noup", "pause",
})


def _check_ceph_flag(flag: str) -> str:
    """Validate a Ceph cluster flag name against the closed schema enum (11 flags)."""
    s = str(flag)
    if s not in _CEPH_FLAGS:
        raise ProximoError(f"unsupported ceph flag: {flag!r} (valid: {sorted(_CEPH_FLAGS)!r})")
    return s


_CEPH_METADATA_SCOPES = frozenset({"all", "versions"})


def _check_ceph_metadata_scope(scope: str) -> str:
    """Validate the optional `scope` param of GET /cluster/ceph/metadata."""
    if scope not in _CEPH_METADATA_SCOPES:
        raise ProximoError(
            f"unsupported ceph metadata scope: {scope!r} (valid: {sorted(_CEPH_METADATA_SCOPES)!r})"
        )
    return scope


_CEPH_CMD_SAFETY_ACTIONS = frozenset({"stop", "destroy"})
_CEPH_CMD_SAFETY_SERVICES = frozenset({"osd", "mon", "mds"})


def _check_ceph_cmd_safety_action(action: str) -> str:
    """Validate the `action` param of GET /nodes/{node}/ceph/cmd-safety (closed enum)."""
    if action not in _CEPH_CMD_SAFETY_ACTIONS:
        raise ProximoError(
            f"unsupported ceph cmd-safety action: {action!r} "
            f"(valid: {sorted(_CEPH_CMD_SAFETY_ACTIONS)!r})"
        )
    return action


def _check_ceph_cmd_safety_service(service: str) -> str:
    """Validate the `service` param of GET /nodes/{node}/ceph/cmd-safety (closed enum)."""
    if service not in _CEPH_CMD_SAFETY_SERVICES:
        raise ProximoError(
            f"unsupported ceph cmd-safety service: {service!r} "
            f"(valid: {sorted(_CEPH_CMD_SAFETY_SERVICES)!r})"
        )
    return service


# Ceph service-instance id (an OSD number, or a mon/mds name): shape-only — no fixed enum
# upstream (id-shape varies by service type). Non-empty, no control characters, capped length
# (defense-in-depth, mirrors _check_username). \Z anchor rejects trailing-newline slip-through.
_CEPH_SERVICE_ID_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,200}\Z")


def _check_ceph_service_id(service_id: str) -> str:
    """Validate the `id` param of GET /nodes/{node}/ceph/cmd-safety (service instance id)."""
    s = str(service_id)
    if not _CEPH_SERVICE_ID_RE.match(s):
        raise ProximoError(
            f"invalid ceph service id: {service_id!r} (1-200 chars, no control characters)"
        )
    return s


# config-keys: one or more "<section>:<config key>" items separated by ';', ',' or ' ' — mirrors
# the live schema pattern (PVE::API2::Ceph cfg/value 'config-keys' param), max 4096 chars per
# schema. Client-side tightening: PVE's own pattern uses Perl case-insensitive inline groups
# ((?^i:...)); this is the equivalent case-both-ways character class.
_CEPH_CONFIG_KEY_ITEM = r"[0-9A-Za-z._-]+:[0-9A-Za-z_-]+"
_CEPH_CONFIG_KEYS_RE = re.compile(rf"^{_CEPH_CONFIG_KEY_ITEM}(?:[;, ]{_CEPH_CONFIG_KEY_ITEM})*\Z")


def _check_ceph_config_keys(config_keys: str) -> str:
    """Validate GET /nodes/{node}/ceph/cfg/value's `config-keys` param against the schema's
    '<section>:<key>[;|,| <section>:<key>]*' format, max 4096 chars."""
    s = str(config_keys)
    if len(s) > 4096:
        raise ProximoError("invalid ceph config-keys: too long (max 4096 chars)")
    if not _CEPH_CONFIG_KEYS_RE.match(s):
        raise ProximoError(
            f"invalid ceph config-keys: {config_keys!r} "
            "(expected '<section>:<key>[;|,| <section>:<key>]*')"
        )
    return s


def _check_ceph_log_bound(value: int | None, field: str) -> int | None:
    """Validate the optional `limit`/`start` params of GET /nodes/{node}/ceph/log (schema:
    `minimum: 0` for both, no declared maximum). None means "omit" and passes through
    unvalidated — this is a bound check, not a required-field check.

    Wave 6a review Finding 3: mirrors observability.py's _check_count/_check_lastentries idiom
    used by pve_node_journal/pve_node_syslog (a caller-supplied negative int must fail fast with
    a friendly local error, not sail through to a raw PVE 400). Duplicated here rather than
    imported: observability.py imports FROM backends.py, so the reverse import would be
    circular — same precedent as _check_file_path's own duplication note above.
    """
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ProximoError(f"invalid ceph log {field}: {value!r} (must be a non-negative integer)")
    return value


# --- Wave 6b: PVE Ceph-plane validators (services lifecycle) ---
# Schema truth: .scratch/api-schemas-2026-07-15/wave6-pve-ceph-schema.json.

# Mon/mgr/mds daemon id (monid / mgr {id} / mds {name}) — one shared shape across all three per
# the live schema (identical pattern verbatim on every one of mon POST/DELETE, mgr POST/DELETE,
# mds POST/DELETE): single alnum, optionally followed by alnum/hyphen ending in alnum (no
# leading/trailing hyphen, non-empty). maxLength 200 is schema-declared on the CREATE (POST) side
# only; DESTROY (DELETE) declares no maxLength at all — capped here anyway for all call sites,
# client-side defense-in-depth, mirroring _check_ceph_service_id's own undeclared-but-capped
# precedent from Wave 6a.
_CEPH_DAEMON_ID_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\Z")


def _check_ceph_daemon_id(value: str, label: str) -> str:
    """Validate a Ceph mon/mgr/mds daemon id (monid / mgr id / mds name) against the shared
    schema pattern. `label` names the field in the error message (e.g. 'monid', 'mgr id',
    'mds name') since one regex serves all three."""
    s = str(value)
    if len(s) > 200:
        raise ProximoError(f"invalid ceph {label}: too long (max 200 chars)")
    if not _CEPH_DAEMON_ID_RE.match(s):
        raise ProximoError(
            f"invalid ceph {label}: {value!r} "
            "(alnum, optionally hyphenated, no leading/trailing hyphen, non-empty)"
        )
    return s


# Ceph service target for start/stop/restart: (ceph|mon|mds|osd|mgr)(.<id>)?, default
# 'ceph.target' — the <id> suffix reuses the exact same alnum/hyphen shape as the daemon-id
# pattern above (schema: PVE::API2::Ceph{Start,Stop,Restart}Ceph.pm, identical pattern on all 3).
_CEPH_SERVICE_RE = re.compile(
    r"^(ceph|mon|mds|osd|mgr)(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)?\Z"
)


def _check_ceph_service(service: str) -> str:
    """Validate the `service` param of POST /nodes/{node}/ceph/{start,stop,restart}."""
    s = str(service)
    if not _CEPH_SERVICE_RE.match(s):
        raise ProximoError(
            f"invalid ceph service: {service!r} "
            "(expected '(ceph|mon|mds|osd|mgr)[.<id>]', e.g. 'ceph.target', 'mon.pve1')"
        )
    return s


def _check_ceph_init_bound(value: int | None, field: str, lo: int, hi: int) -> int | None:
    """Validate an optional bounded integer param of POST /nodes/{node}/ceph/init (min_size:
    1-7, size: 1-7, pg_bits: 6-14 per schema). None means "omit" and passes through unvalidated.
    Mirrors _check_ceph_log_bound's shape (Wave 6a review Finding 3 precedent) — a caller-supplied
    out-of-range int must fail fast locally, not sail through to a raw PVE 400."""
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not (lo <= value <= hi):
        raise ProximoError(f"invalid ceph init {field}: {value!r} (must be an integer {lo}-{hi})")
    return value


def _check_ceph_init_network(value: str | None, field: str) -> str | None:
    """Validate an optional network/cluster-network param of POST /nodes/{node}/ceph/init
    (format: CIDR, maxLength 128 per schema). Length-only: the schema gives no explicit regex
    pattern for its own 'CIDR' format (unlike e.g. the daemon-id/service patterns above), and
    Ceph's public/cluster network config legitimately accepts comma-separated multi-CIDR values —
    inventing a single-CIDR regex here risks being WRONG (rejecting valid multi-network strings)
    rather than merely permissive. None means "omit" and passes through unvalidated."""
    if value is None:
        return None
    s = str(value)
    if len(s) > 128:
        raise ProximoError(f"invalid ceph init {field}: too long (max 128 chars)")
    return s


# --- Wave 6c: PVE Ceph-plane validators (OSD) ---
# Schema truth: .scratch/api-schemas-2026-07-15/wave6-pve-ceph-schema.json.


def _check_ceph_osdid(osdid: int) -> int:
    """Validate a Ceph OSD id (schema: type integer, required on every OSD-scoped endpoint).
    0 is a VALID osdid (the first OSD ever created) — this is an isinstance+equality check,
    NEVER a truthiness check, so osdid=0 is never mistaken for "missing" (the Wave 6b falsy-id
    lesson — Finding 2, `monid=""` — applied here to a numeric id instead of a string one)."""
    if not isinstance(osdid, int) or isinstance(osdid, bool) or osdid < 0:
        raise ProximoError(f"invalid ceph osdid: {osdid!r} (must be a non-negative integer)")
    return osdid


# OSD device type for GET .../osd/{osdid}/lv-info — closed 3-value enum, schema default 'block'
# (the default is applied by the caller, not here — None means "omit", forwarded unset).
_CEPH_OSD_LV_TYPES = frozenset({"block", "db", "wal"})


def _check_ceph_osd_lv_type(value: str) -> str:
    """Validate the optional `type` query param of GET .../osd/{osdid}/lv-info (closed enum)."""
    if value not in _CEPH_OSD_LV_TYPES:
        raise ProximoError(
            f"unsupported ceph osd lv-info type: {value!r} "
            f"(valid: {sorted(_CEPH_OSD_LV_TYPES)!r})"
        )
    return value


def _check_ceph_osd_min(value: float | None, field: str, minimum: float) -> float | None:
    """Validate an optional LOWER-BOUNDED-ONLY numeric param of POST /nodes/{node}/ceph/osd
    (schema declares only a `minimum`, no `maximum`: db_dev_size >= 1, wal_dev_size >= 0.5).
    None means "omit" and passes through unvalidated. Mirrors _check_ceph_init_bound's shape but
    one-sided (no upper bound exists upstream for either of these, unlike min_size/size/pg_bits)."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProximoError(f"invalid ceph osd {field}: {value!r} (must be a number >= {minimum})")
    if value < minimum:
        raise ProximoError(f"invalid ceph osd {field}: {value!r} (must be >= {minimum})")
    return value


def _check_ceph_osd_int_min(value: int | None, field: str, minimum: int) -> int | None:
    """Validate an optional LOWER-BOUNDED-ONLY integer param of POST /nodes/{node}/ceph/osd
    (schema: osds-per-device >= 1, integer). A separate function from _check_ceph_osd_min
    (rather than a shared `integer=` flag) so the return type stays a clean `int | None` for
    pyright — a union return would force every caller to narrow it back down. None means "omit"
    and passes through unvalidated."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProximoError(f"invalid ceph osd {field}: {value!r} (must be an integer >= {minimum})")
    if value < minimum:
        raise ProximoError(f"invalid ceph osd {field}: {value!r} (must be >= {minimum})")
    return value


# Ceph OSD device path (dev/db_dev/wal_dev on POST /nodes/{node}/ceph/osd): a Ceph-SCOPED
# widening of _check_disk's charset, NOT a loosening of the shared validator itself — other
# planes (node_disk_wipe/node_disk_initgpt) still rely on _check_disk's stricter shape. Wave 6c
# review Finding 1 (MAJOR, 2026-07-16): _check_disk's [a-zA-Z0-9/_-] class rejects real-world,
# PVE-documented, commonly-recommended stable device paths precisely relevant to this mutation
# (osds-per-device's own description: "Only useful for fast NVMe devices") — e.g.
# /dev/disk/by-id/nvme-eui.<hex> (dot) and /dev/disk/by-path/pci-0000:00:1f.2-ata-1 (colon).
# This class adds '.', ':', '+', '=' (also covers by-id names like ata-FOO_BAR=serial) — still a
# conservative WHITELIST (not a blacklist): whitespace, backslashes, and shell metacharacters
# are excluded simply by not being in the allowed set, same discipline as _check_disk itself.
_CEPH_OSD_DEV_RE = re.compile(r"^/dev/[a-zA-Z0-9/_.:+=-]+\Z")


def _check_ceph_osd_dev(disk: str) -> str:
    """Validate a Ceph OSD device path (dev/db_dev/wal_dev). Like _check_disk (must start with
    /dev/, no '..' traversal) but with a wider, still-conservative charset that admits '.', ':',
    '+', '=' for the by-id/by-path stable device names operators are specifically steered toward
    for Ceph OSD dev/db_dev/wal_dev (to avoid /dev/sdX renumbering across a reboot) — see Wave 6c
    review Finding 1. Scoped to Ceph OSD create only: does NOT loosen the shared _check_disk,
    which node_disk_wipe/node_disk_initgpt keep relying on for their own (raw /dev/sdX-only)
    convention."""
    s = str(disk)
    if not _CEPH_OSD_DEV_RE.match(s):
        raise ProximoError(
            f"invalid ceph osd device path: {disk!r} "
            "(must start with /dev/ then letters/digits/underscore/hyphen/slash/dot/colon/plus/equals)"
        )
    # Component-level traversal check: no '..' segment after splitting on '/' (mirrors
    # _check_disk's own check — the wider charset above doesn't touch this).
    if ".." in s.split("/"):
        raise ProximoError(f"path traversal not allowed in disk path: {disk!r}")
    return s


# --- Wave 6d: PVE Ceph-plane validators (pools + CephFS) ---
# Schema truth: .scratch/api-schemas-2026-07-15/wave6-pve-ceph-schema.json.

# Ceph pool name (POST/PUT/DELETE .../pool[/{name}]) and CephFS name (POST/DELETE .../fs/{name})
# share the IDENTICAL schema pattern verbatim: '^[^:/\s]+$' (no colon, slash, or whitespace).
# DELETE .../pool/{name} and GET .../pool/{name}/status declare NO pattern for their own `name`
# param (just `type: string`) — applied here anyway, defense-in-depth: a legitimately-CREATED
# pool/fs can never have a name violating the create-side pattern in the first place (mirrors the
# Wave 6b _check_ceph_daemon_id precedent: DELETE declares no maxLength either, capped anyway).
_CEPH_NAME_RE = re.compile(r"^[^:/\s]+\Z")


def _check_ceph_pool_or_fs_name(value: str, label: str) -> str:
    """Validate a Ceph pool name or CephFS name against the shared schema pattern (no colon,
    slash, or whitespace). `label` names the field in the error message (e.g. 'pool name',
    'fs name') since one regex serves both — mirrors _check_ceph_daemon_id's label-parameterized
    shape."""
    s = str(value)
    if not _CEPH_NAME_RE.match(s):
        raise ProximoError(
            f"invalid ceph {label}: {value!r} (must not contain ':', '/', or whitespace)"
        )
    return s


_CEPH_FS_DEFAULT_NAME = "cephfs"


def _check_ceph_fs_name_or_default(name: str | None) -> str:
    """Resolve POST /nodes/{node}/ceph/fs/{name}'s own schema default ('cephfs') client-side:
    `name` is ALSO the URL path segment for that request and cannot itself be "omitted" from an
    HTTP request, so a caller-omitted name must resolve to the literal default BEFORE the URL is
    built. Mirrors the Wave 6b mon/mgr/mds `_ceph_daemon_target` "default: nodename" Build nuance
    — but here the schema default is a FIXED LITERAL string ('cephfs'), not the caller's node
    name, so this is a plain function (no `node`/`self` needed), not an ApiBackend method."""
    return _check_ceph_pool_or_fs_name(name, "fs name") if name is not None else _CEPH_FS_DEFAULT_NAME


_CEPH_POOL_APPLICATIONS = frozenset({"rbd", "cephfs", "rgw"})


def _check_ceph_pool_application(value: str) -> str:
    """Validate the `application` param of POST/PUT .../pool[/{name}] (closed 3-value enum)."""
    if value not in _CEPH_POOL_APPLICATIONS:
        raise ProximoError(
            f"unsupported ceph pool application: {value!r} "
            f"(valid: {sorted(_CEPH_POOL_APPLICATIONS)!r})"
        )
    return value


_CEPH_POOL_AUTOSCALE_MODES = frozenset({"on", "off", "warn"})


def _check_ceph_pool_autoscale_mode(value: str) -> str:
    """Validate the `pg_autoscale_mode` param of POST/PUT .../pool[/{name}] (closed 3-value
    enum)."""
    if value not in _CEPH_POOL_AUTOSCALE_MODES:
        raise ProximoError(
            f"unsupported ceph pool pg_autoscale_mode: {value!r} "
            f"(valid: {sorted(_CEPH_POOL_AUTOSCALE_MODES)!r})"
        )
    return value


def _check_ceph_bounded_int(value: int | None, label: str, lo: int, hi: int) -> int | None:
    """Validate an optional BOTH-SIDES-BOUNDED integer param shared by pool/fs create+set
    (schema: pool min_size/size both 1-7, pool pg_num 1-32768; fs pg_num 8-32768). None means
    "omit" and passes through unvalidated. `label` names the FULL field (e.g. 'pool min_size',
    'fs pg_num') so the error message reads correctly for whichever plane calls it — mirrors
    _check_ceph_daemon_id's/_check_ceph_pool_or_fs_name's label-parameterized shape, rather than
    reusing _check_ceph_init_bound's own hardcoded 'ceph init' wording (which would misleadingly
    say 'ceph init pg_num' for a pool/fs mutation that has nothing to do with cluster init)."""
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or not (lo <= value <= hi):
        raise ProximoError(f"invalid ceph {label}: {value!r} (must be an integer {lo}-{hi})")
    return value


def _check_ceph_pool_upper_bound(value: int | None, field: str, maximum: int) -> int | None:
    """Validate an optional UPPER-BOUNDED-ONLY integer param of POST/PUT .../pool[/{name}]
    (schema: pg_num_min declares only a `maximum` of 32768, no `minimum` key at all — the live
    typetext is literally '<integer> (-N - 32768)'). None means "omit" and passes through
    unvalidated. A separate one-sided validator from _check_ceph_init_bound (which requires both
    a lo AND a hi) — mirrors _check_ceph_osd_min's one-sided shape, but bounded from the OTHER
    side (upper, not lower)."""
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value > maximum:
        raise ProximoError(f"invalid ceph pool {field}: {value!r} (must be an integer <= {maximum})")
    return value


_CEPH_POOL_TARGET_SIZE_RE = re.compile(r"^(\d+(\.\d+)?)([KMGT])?\Z")


def _check_ceph_pool_target_size(value: str) -> str:
    """Validate the `target_size` param of POST/PUT .../pool[/{name}] against the schema's own
    pattern: a plain number optionally suffixed with one of K/M/G/T (e.g. '10G', '500M')."""
    s = str(value)
    if not _CEPH_POOL_TARGET_SIZE_RE.match(s):
        raise ProximoError(
            f"invalid ceph pool target_size: {value!r} "
            "(expected a number optionally suffixed with K/M/G/T, e.g. '10G')"
        )
    return s


def _check_ceph_pool_ratio(value: float | None) -> float | None:
    """Validate the optional `target_size_ratio` param of POST/PUT .../pool[/{name}] (schema:
    bare `number`, no declared minimum/maximum). None means "omit" and passes through
    unvalidated — this is a type-only check (a caller-supplied bool or non-numeric value must
    fail fast locally, matching every other numeric-typed optional on this plane)."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProximoError(f"invalid ceph pool target_size_ratio: {value!r} (must be a number)")
    return value


# erasure-coding is PVE's own propertyString wire format (schema `format` block: required
# k>=2/m>=1; optional device-class/failure-domain/profile strings) — validated by PARSING
# (comma-separated key=value pairs against this closed field set), not by inventing a
# nested-object param shape for one field on one endpoint. See _check_ceph_pool_erasure_coding.
_CEPH_EC_REQUIRED_FIELDS = frozenset({"k", "m"})
_CEPH_EC_ALLOWED_FIELDS = frozenset({"k", "m", "device-class", "failure-domain", "profile"})


def _check_ceph_pool_erasure_coding(value: str) -> str:
    """Validate the `erasure-coding` propertyString param of POST .../pool. The ORIGINAL string
    is returned unchanged on success (this is what the ceph.py module docstring's "pass through
    as a validated string" line means) — PVE's own propertyString wire format is reused verbatim
    rather than Proximo inventing a different param shape for this one field."""
    s = str(value)
    if not s:
        raise ProximoError("invalid ceph pool erasure-coding: empty string")
    seen: dict[str, str] = {}
    for part in s.split(","):
        if "=" not in part:
            raise ProximoError(
                f"invalid ceph pool erasure-coding: malformed field {part!r} (expected key=value)"
            )
        k, _, v = part.partition("=")
        k = k.strip()
        if k not in _CEPH_EC_ALLOWED_FIELDS:
            raise ProximoError(
                f"invalid ceph pool erasure-coding: unsupported field {k!r} "
                f"(valid: {sorted(_CEPH_EC_ALLOWED_FIELDS)!r})"
            )
        if k in seen:
            raise ProximoError(f"invalid ceph pool erasure-coding: duplicate field {k!r}")
        seen[k] = v.strip()
    missing = _CEPH_EC_REQUIRED_FIELDS - seen.keys()
    if missing:
        raise ProximoError(
            f"invalid ceph pool erasure-coding: missing required field(s) {sorted(missing)!r}"
        )
    try:
        k_val = int(seen["k"])
    except ValueError as e:
        raise ProximoError(
            f"invalid ceph pool erasure-coding: k must be an integer, got {seen['k']!r}"
        ) from e
    if k_val < 2:
        raise ProximoError(f"invalid ceph pool erasure-coding: k must be >= 2, got {k_val}")
    try:
        m_val = int(seen["m"])
    except ValueError as e:
        raise ProximoError(
            f"invalid ceph pool erasure-coding: m must be an integer, got {seen['m']!r}"
        ) from e
    if m_val < 1:
        raise ProximoError(f"invalid ceph pool erasure-coding: m must be >= 1, got {m_val}")
    return s


# Absolute-path file validator for qemu-agent file-read/file-write.
# Must start with '/'; reject ALL C0 control chars (incl. CR/LF/TAB) and DEL — these have no
# place in a path and are the header/URL-injection vectors. Printable chars (incl. space, which
# is legal in guest paths) are allowed and percent-encoded by the caller.
# \Z anchor prevents trailing-newline slip-through (same discipline as _NODE_RE).
#
# NOTE: qemu_agent.py imports backends (not the reverse), so _check_file_path is intentionally
# duplicated here. If you move it, update the import in qemu_agent.py to pull from backends
# instead of redefining it locally.
_FILE_PATH_RE = re.compile(r"^/[^\x00-\x1f\x7f]*\Z")


def _check_file_path(path: str) -> str:
    """Validate an absolute guest file path (defense-in-depth: called at the backend layer)."""
    if not _FILE_PATH_RE.match(path):
        raise ProximoError(
            f"invalid file path: {path!r} (must be an absolute path starting with '/')"
        )
    if ".." in path.split("/"):
        raise ProximoError(f"path traversal not allowed: {path!r}")
    return path


# Cert-pin env var per plane — the one thing fingerprint_refused() cannot derive from the
# plane name alone (PVE's own var has no plane infix, unlike PBS/PMG/PDM's).
_FINGERPRINT_ENV_VARS = {
    "PVE": "PROXIMO_FINGERPRINT",
    "PBS": "PROXIMO_PBS_FINGERPRINT",
    "PMG": "PROXIMO_PMG_FINGERPRINT",
    "PDM": "PROXIMO_PDM_FINGERPRINT",
}


def fingerprint_refused(plane: str, error: ValueError) -> ProximoError:
    """Translate a garbled cert-pin ValueError (from fingerprint_pinned_context) into a
    remedy-naming refusal. Shared by all four backend __init__ methods (PVE here, PBS/PMG/PDM
    import this) so the message names the exact env var for that plane and the expected shape,
    instead of forwarding the validator's raw ValueError with no pointer to the fix.
    """
    env_var = _FINGERPRINT_ENV_VARS[plane]
    return ProximoError(
        f"invalid {plane} fingerprint for {env_var} — expected the 64-char SHA-256 hex "
        f"digest (e.g. from `openssl x509 -fingerprint -sha256 -noout -in cert.pem`), "
        f"got: {error}"
    )


@dataclass
class ExecResult:
    ctid: str
    command: str
    returncode: int
    stdout: str
    stderr: str


class ExecBackend:
    """Runs commands inside an LXC via `ssh <target> pct exec <ctid> -- ...` (or local `pct`).

    This path is irreducible: Proxmox has no REST endpoint for container exec
    (it uses lxc-attach / kernel namespaces). Verified 2026-06-07.
    """

    def __init__(self, config: ProximoConfig):
        self.config = config

    def run(self, ctid: str, command: list[str], *, timeout: int = 60) -> ExecResult:
        # Defense-in-depth: enforce the opt-in gate AT the backend, not only at the server
        # layer. A future caller reaching ExecBackend.run() directly must not bypass the
        # PROXIMO_ENABLE_EXEC opt-in and ride on the allowlist alone.
        if not self.config.enable_exec:
            raise ProximoError("in-container exec is disabled (set PROXIMO_ENABLE_EXEC=1 to enable)")
        _check_vmid(ctid)  # defense-in-depth: validate before allowlist/quoting, like ApiBackend
        if not self.config.ct_permitted(ctid):
            raise ProximoError(
                f"CTID {ctid} is not on the exec allowlist (fail-closed: an empty or "
                "non-matching PROXIMO_CT_ALLOWLIST denies everything) — add it via "
                "PROXIMO_CT_ALLOWLIST (comma-separated CTIDs, or '*' for all)"
            )
        if self.config.is_local:
            # On the PVE host: call pct directly — no ssh, no quote layer.
            argv = ["pct", "exec", str(ctid), "--", *command]
        else:
            remote = "pct exec " + shlex.quote(str(ctid)) + " -- " + shlex.join(command)
            argv = ["ssh", self.config.ssh_target, remote]
        # S603/S607: we intentionally invoke PATH-resolved `ssh`/`pct` with non-shell argv.
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)  # noqa: S603, S607
        return ExecResult(str(ctid), shlex.join(command), proc.returncode, proc.stdout, proc.stderr)

    def psql(self, ctid: str, sql: str, *, db: str = "postgres", user: str = "postgres",
             timeout: int = 60) -> ExecResult:
        """psql convenience: runs as the db OS user, no shell-quote gymnastics for the caller."""
        inner = f"psql -d {shlex.quote(db)} -v ON_ERROR_STOP=1 -c {shlex.quote(sql)}"
        return self.run(ctid, ["su", user, "-c", inner], timeout=timeout)

    def logs(self, ctid: str, unit: str, *, lines: int = 50) -> ExecResult:
        return self.run(ctid, ["journalctl", "-u", unit, "-n", str(lines), "--no-pager"])


class ApiBackend:
    """Management via the Proxmox REST API using a scoped API token."""

    def __init__(self, config: ProximoConfig):
        self.config = config
        if config.fingerprint:
            # WIRE-ENFORCED pin: the PVE node's cert is signed by the per-cluster "PVE Cluster
            # Manager CA" that no public root trusts, so a pin (exact-cert SHA-256) replaces
            # CA/hostname validation — mismatch closes the socket before the token is sent.
            # Same mechanism as PbsBackend; a garbled pin refuses loudly here.
            try:
                ctx = fingerprint_pinned_context(config.fingerprint)
            except ValueError as e:
                raise fingerprint_refused("PVE", e) from e
            self._client = httpx.Client(base_url=config.api_base_url, verify=ctx, timeout=30)
            return
        verify: bool | str = config.ca_bundle if config.ca_bundle else config.verify_tls
        # FAIL-CLOSED: every request carries the PVE API-token secret. Refuse to construct
        # this client over a completely unverified channel (verify_tls=false AND no
        # ca_bundle AND no fingerprint) — same rule PbsBackend enforces for the PBS token.
        if verify is False:
            raise ProximoError(
                "refusing to send the PVE token over unverified TLS: set PROXIMO_FINGERPRINT "
                "to the node cert's SHA-256 (strongest for a self-signed PVE), PROXIMO_CA_BUNDLE "
                "to the cluster CA, or PROXIMO_VERIFY_TLS=true. A read-only token is still a "
                "credential — it must not cross an unverified channel."
            )
        self._client = httpx.Client(base_url=config.api_base_url, verify=httpx_verify(verify), timeout=30)

    def _auth_header(self) -> dict[str, str]:
        # Token file holds: USER@REALM!TOKENID=SECRET  (e.g. root@pam!proximo=<uuid>).
        # Header format verified vs PVE docs 2026-06-07: PVEAPIToken=..., no Bearer, no CSRF.
        # Read at call time; never logged.
        with open(self.config.token_path, encoding="utf-8") as f:
            token = f.read().strip()
        return {"Authorization": f"PVEAPIToken={token}"}

    def _resolve_node(self, node: str | None) -> str:
        """Validate `node` (if given) and resolve it, defaulting to the configured node."""
        _check_node(node)
        return node or self.config.node

    def _get(self, path: str):
        r = self._client.get(path, headers=self._auth_header())
        r.raise_for_status()
        return r.json().get("data")

    @staticmethod
    def _form(d: dict | None) -> dict:
        # PVE's API type-checker wants booleans as 1/0 — Python's bool serializes to 'true'/'false',
        # which PVE rejects ("type check ('boolean') failed - got 'false'"). Coerce so any tool may
        # pass a native bool and get the wire form PVE accepts. Ints pass through (1 is True == False).
        # None is DROPPED, not sent: an unset optional must be omitted, never serialized as "None".
        return {k: (1 if v is True else 0 if v is False else v)
                for k, v in (d or {}).items() if v is not None}

    def _post(self, path: str, data: dict | None = None):
        r = self._client.post(path, headers=self._auth_header(), data=self._form(data))
        r.raise_for_status()
        return r.json().get("data")

    def _delete(self, path: str, params: dict | None = None):
        r = self._client.request("DELETE", path, headers=self._auth_header(), params=self._form(params))
        r.raise_for_status()
        return r.json().get("data")

    def _put(self, path: str, data: dict | None = None):
        r = self._client.request("PUT", path, headers=self._auth_header(), data=self._form(data))
        r.raise_for_status()
        return r.json().get("data")

    def version(self) -> dict:
        """GET /version — Proxmox version/release. A successful call also proves the token can
        reach + authenticate to the API (used by the DOCTOR preflight)."""
        return self._get("/version") or {}

    def access_permissions(self, path: str | None = None) -> dict:
        """GET /access/permissions — the CALLING token's effective privileges, as {path: {priv: 1}}.
        No `path` => the full map across every path, so scoped (e.g. pool-only) grants stay visible."""
        # url-encode the caller-supplied path so '&'/'#'/space cannot inject extra query params
        q = f"?path={quote(path, safe='/')}" if path else ""
        return self._get(f"/access/permissions{q}") or {}

    def node_status(self, node: str | None = None) -> dict:
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/status")

    def list_guests(self, node: str | None = None) -> list[dict]:
        n = self._resolve_node(node)
        lxc = self._get(f"/nodes/{n}/lxc") or []
        qemu = self._get(f"/nodes/{n}/qemu") or []
        return [{**g, "type": "lxc"} for g in lxc] + [{**g, "type": "qemu"} for g in qemu]

    def guest_status(self, vmid: str, kind: str = "lxc", node: str | None = None) -> dict:
        vmid, kind = _check_vmid(vmid), _check_kind(kind)
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/{kind}/{vmid}/status/current")

    def guest_power(self, vmid: str, action: str, kind: str = "lxc", node: str | None = None) -> dict:
        vmid, kind = _check_vmid(vmid), _check_kind(kind)
        n = self._resolve_node(node)
        if action not in {"start", "stop", "reboot", "shutdown"}:
            raise ProximoError(f"unsupported power action: {action}")
        # MUTATION — the server layer must confirm-gate + audit before calling this.
        return self._post(f"/nodes/{n}/{kind}/{vmid}/status/{action}")

    # --- snapshots (UNDO pillar). Create/rollback/delete are ASYNC — they return a task UPID. ---

    def _snap_base(self, vmid: str, kind: str, node: str | None) -> str:
        vmid, kind = _check_vmid(vmid), _check_kind(kind)
        n = self._resolve_node(node)
        return f"/nodes/{n}/{kind}/{vmid}/snapshot"

    def snapshot_list(self, vmid: str, kind: str = "lxc", node: str | None = None) -> list[dict]:
        return self._get(self._snap_base(vmid, kind, node)) or []

    def snapshot_create(self, vmid: str, snapname: str, kind: str = "lxc", node: str | None = None,
                        description: str | None = None) -> str:
        snapname = _check_snapname(snapname)
        data = {"snapname": snapname}
        if description:
            data["description"] = description
        # MUTATION — confirm-gated + audited at the server layer.
        return self._post(self._snap_base(vmid, kind, node), data)

    def snapshot_rollback(self, vmid: str, snapname: str, kind: str = "lxc",
                          node: str | None = None) -> str:
        snapname = _check_snapname(snapname)
        # DESTRUCTIVE — discards changes since the snapshot. Confirm-gated + audited at the server layer.
        return self._post(f"{self._snap_base(vmid, kind, node)}/{snapname}/rollback")

    def snapshot_delete(self, vmid: str, snapname: str, kind: str = "lxc", node: str | None = None,
                        force: bool = False) -> str:
        snapname = _check_snapname(snapname)
        params = {"force": 1} if force else None
        return self._delete(f"{self._snap_base(vmid, kind, node)}/{snapname}", params)

    def task_status(self, upid: str, node: str | None = None) -> dict:
        n = self._resolve_node(node)
        upid = _check_upid(upid)
        return self._get(f"/nodes/{n}/tasks/{upid}/status")

    # --- node reads (DIAGNOSE pillar) ---

    def node_storage(self, node: str | None = None) -> list[dict]:
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/storage") or []

    def node_tasks(self, node: str | None = None, limit: int = 50) -> list[dict]:
        n = self._resolve_node(node)
        limit = int(limit)  # int-cast: never let an arbitrary string into the query string
        if limit <= 0:
            limit = 50
        return self._get(f"/nodes/{n}/tasks?limit={limit}") or []

    # --- qemu-agent plane (Wave 3) ---
    # Defense-in-depth: gate enforced HERE so a future caller reaching these methods directly
    # cannot bypass the PROXIMO_ENABLE_AGENT opt-in + VMID allowlist.
    # Gate order mirrors ExecBackend.run(): enable → vmid → permitted → node.

    def _agent_gate(self, vmid: str, node: str | None) -> tuple[str, str]:
        """Enforce the agent gate and return (checked_vmid, resolved_node)."""
        if not self.config.enable_agent:
            raise ProximoError(
                "qemu-agent ops are disabled (set PROXIMO_ENABLE_AGENT=1 to enable)"
            )
        vmid = _check_vmid(vmid)
        if not self.config.agent_permitted(vmid):
            raise ProximoError(
                f"VMID {vmid} is not on the agent allowlist (fail-closed: an empty or "
                "non-matching PROXIMO_AGENT_ALLOWLIST denies everything) — add it via "
                "PROXIMO_AGENT_ALLOWLIST (comma-separated VMIDs, or '*' for all)"
            )
        return vmid, self._resolve_node(node)

    def agent_simple(self, vmid: str, node: str | None, command: str) -> dict:
        """Issue a no-parameter agent command (ping / info / get-* / fsfreeze-* / fstrim).

        VERIFIED live (PVE 9.2): read commands are GET, action commands are POST — routed by
        _AGENT_GET_CMDS. A POST to a get-* path returns 501 (method not implemented).
        """
        if command not in _VALID_AGENT_SIMPLE_CMDS:
            raise ProximoError(
                f"unsupported agent command: {command!r} "
                f"(valid: {sorted(_VALID_AGENT_SIMPLE_CMDS)!r})"
            )
        vmid, n = self._agent_gate(vmid, node)
        path = f"/nodes/{n}/qemu/{vmid}/agent/{command}"
        if command in _AGENT_GET_CMDS:
            return self._get(path) or {}
        return self._post(path) or {}

    def agent_exec(self, vmid: str, node: str | None, command: list[str]) -> dict:
        """POST an exec command to the guest agent and return the pid immediately.

        VERIFIED live (PVE 9.2): body={'command': [argv list]} is accepted; returns {"pid": <int>}.
        Poll agent_exec_status for completion.
        """
        vmid, n = self._agent_gate(vmid, node)
        return self._post(f"/nodes/{n}/qemu/{vmid}/agent/exec", {"command": command}) or {}

    def agent_exec_status(self, vmid: str, node: str | None, pid: int) -> dict:
        """GET the status of a running guest-agent exec by pid.

        VERIFIED live (PVE 9.2): GET .../agent/exec-status?pid=<n> returns
        {'exited': bool, 'exitcode': int, 'out-data': str, 'err-data': str} — out-data is plain
        text (NOT base64) for a normal exec.
        """
        vmid, n = self._agent_gate(vmid, node)
        return self._get(f"/nodes/{n}/qemu/{vmid}/agent/exec-status?pid={int(pid)}") or {}

    def agent_file_read(self, vmid: str, node: str | None, file: str) -> dict:
        """GET file content from the guest via the agent.

        VERIFIED live (PVE 9.2): GET .../agent/file-read?file=<path> returns
        {'bytes-read': int, 'content': str} (plain text round-trips exactly).
        """
        vmid, n = self._agent_gate(vmid, node)
        _check_file_path(file)  # defense-in-depth: validate even on a direct backend call
        # Percent-encode the validated path so '&'/'?'/'#'/space cannot inject query params or
        # break the request; _check_file_path already rejects control chars and traversal.
        return self._get(f"/nodes/{n}/qemu/{vmid}/agent/file-read?file={quote(file, safe='/')}") or {}

    def agent_file_write(self, vmid: str, node: str | None, file: str, content: str) -> None:
        """POST file content to the guest via the agent.

        VERIFIED live (PVE 9.2): POST .../agent/file-write with body {'file', 'content'} writes the
        file; text content round-trips byte-identical via file-read. Smoke-confirm: binary content
        (whether an 'encode'/base64 param is needed) is not yet exercised.
        """
        vmid, n = self._agent_gate(vmid, node)
        _check_file_path(file)  # defense-in-depth: validate even on a direct backend call
        self._post(f"/nodes/{n}/qemu/{vmid}/agent/file-write", {"file": file, "content": content})

    def agent_set_password(self, vmid: str, node: str | None, username: str, password: str) -> None:
        """POST to set a guest user's password via the agent.

        VERIFIED live (PVE 9.2): POST .../agent/set-user-password with body {'username', 'password'}
        succeeds. Password is NEVER logged; only a redaction marker reaches the ledger.
        """
        vmid, n = self._agent_gate(vmid, node)
        _check_username(username)  # defense-in-depth: validate even on a direct backend call
        self._post(
            f"/nodes/{n}/qemu/{vmid}/agent/set-user-password",
            {"username": username, "password": password},
        )

    # --- node-lifecycle plane (Wave 4) ---

    def node_disks_list(self, node: str | None = None) -> list:
        """GET /nodes/{node}/disks/list — physical disk inventory.

        VERIFIED live (PVE 9.2): GET; entries carry devpath/health/size/model/serial/used.
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/disks/list") or []

    def node_disk_smart(self, disk: str, node: str | None = None) -> dict:
        """GET /nodes/{node}/disks/smart?disk=… — SMART health data.

        VERIFIED live (PVE 9.2): GET is the READ form (returns {health, type, text/attributes}) —
        it does NOT trigger a self-test.
        """
        _check_disk(disk)
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/disks/smart?disk={quote(disk, safe='/')}") or {}

    def node_disk_wipe(self, disk: str, node: str | None = None) -> str | None:
        """PUT /nodes/{node}/disks/wipedisk — wipe all data/partition table on a disk.

        Smoke-confirm: PUT /disks/wipedisk with body {disk: …} — shape not live-verified.
        Returns the worker UPID (async, like the sibling disk/storage ops). IRREVERSIBLE.
        """
        _check_disk(disk)
        n = self._resolve_node(node)
        return self._put(f"/nodes/{n}/disks/wipedisk", {"disk": disk})  # Smoke-confirm: PUT, async UPID

    def node_disk_initgpt(self, disk: str, node: str | None = None) -> str | None:
        """POST /nodes/{node}/disks/initgpt — write a new GPT partition table.

        Smoke-confirm: POST /disks/initgpt with body {disk: …} — shape not live-verified.
        IRREVERSIBLE — existing partition table is overwritten.
        """
        _check_disk(disk)
        n = self._resolve_node(node)
        return self._post(f"/nodes/{n}/disks/initgpt", {"disk": disk})  # Smoke-confirm: POST

    def node_storage_backend_list(self, backend: str, node: str | None = None) -> list | dict:
        """GET /nodes/{node}/disks/{backend} — list storage backends of a type.

        VERIFIED live (PVE 9.2): GET. Shape is heterogeneous — lvm returns a VG TREE (dict with
        nested children); lvmthin/zfs/directory return a list. Returned raw.
        """
        _check_backend(backend)
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/disks/{backend}") or []

    def node_storage_backend_create(
        self, backend: str, name: str, node: str | None = None, **kw: object
    ) -> str | None:
        """POST /nodes/{node}/disks/{backend} — create a storage backend.

        Smoke-confirm: POST /disks/{backend} with body including name + backend-specific params
        — shape not live-verified. Returns a task UPID (async).
        """
        _check_backend(backend)
        _check_storage_name(name)
        n = self._resolve_node(node)
        body = {"name": name, **kw}
        return self._post(f"/nodes/{n}/disks/{backend}", body)  # Smoke-confirm: POST

    def node_storage_backend_delete(
        self, backend: str, name: str, node: str | None = None, cleanup: bool = False
    ) -> str | None:
        """DELETE /nodes/{node}/disks/{backend}/{name} — destroy a storage backend.

        Smoke-confirm: DELETE /disks/{backend}/{name} — shape not live-verified.
        IRREVERSIBLE for zfs/lvm/lvmthin backends.
        """
        _check_backend(backend)
        _check_storage_name(name)
        n = self._resolve_node(node)
        params = {"cleanup-disks": 1} if cleanup else None
        return self._delete(  # Smoke-confirm: DELETE
            f"/nodes/{n}/disks/{backend}/{name}", params=params
        )

    def node_time_get(self, node: str | None = None) -> dict:
        """GET /nodes/{node}/time — current time and timezone of the node.

        VERIFIED live (PVE 9.2): GET returns {localtime, time, timezone}. (CAPTURE source for time_set.)
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/time") or {}

    def node_time_set(self, timezone: str, node: str | None = None) -> None:
        """PUT /nodes/{node}/time — set the node timezone.

        Smoke-confirm: PUT /nodes/{node}/time with body {timezone: …} — shape not live-verified.
        """
        _check_timezone(timezone)
        n = self._resolve_node(node)
        self._put(f"/nodes/{n}/time", {"timezone": timezone})  # Smoke-confirm: PUT

    def node_hosts_get(self, node: str | None = None) -> dict:
        """GET /nodes/{node}/hosts — current /etc/hosts content.

        VERIFIED live (PVE 9.2): GET returns {data, digest}. (CAPTURE source for hosts_set.)
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/hosts") or {}

    def node_hosts_set(
        self, data: str, node: str | None = None, digest: str | None = None
    ) -> None:
        """POST /nodes/{node}/hosts — replace /etc/hosts.

        Smoke-confirm: POST /nodes/{node}/hosts with body {data, [digest]} — shape not live-verified.
        """
        n = self._resolve_node(node)
        body: dict = {"data": data}
        if digest is not None:
            body["digest"] = digest
        self._post(f"/nodes/{n}/hosts", body)  # Smoke-confirm: POST

    def node_dns_set(
        self,
        node: str | None = None,
        search: str | None = None,
        dns1: str | None = None,
        dns2: str | None = None,
        dns3: str | None = None,
    ) -> None:
        """PUT /nodes/{node}/dns — update DNS resolver config.

        Smoke-confirm: PUT /nodes/{node}/dns with body {search?, dns1?, dns2?, dns3?}
        — shape not live-verified.
        """
        n = self._resolve_node(node)
        body = {
            k: v for k, v in
            {"search": search, "dns1": dns1, "dns2": dns2, "dns3": dns3}.items()
            if v is not None
        }
        self._put(f"/nodes/{n}/dns", body)  # Smoke-confirm: PUT

    # --- Wave 1a: APT plane (patch-visibility + repository governance) ---
    # Schema truth: .scratch/api-schemas-2026-07-15/methods-pve.json (`/apt`) + the upstream
    # PVE::API2::APT.pm Perl source (param names/types cross-checked 2026-07-15). NONE of these
    # seven are live-verified yet — every method below carries its own Smoke-confirm comment.
    # HONESTY: Proxmox's API deliberately does not expose upgrade execution; the upgrade itself
    # happens at your console. These methods govern visibility and repo config only.

    def apt_updates_list(self, node: str | None = None) -> list[dict]:
        """GET /nodes/{node}/apt/update — list available package updates (cached apt index).

        Smoke-confirm: GET /apt/update — shape not live-verified. Expected per-package dicts
        (Package/Title/Description/Origin/Version/OldVersion/Priority/Section/Arch) per schema
        truth (PVE::API2::APT list_updates).
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/apt/update") or []

    def apt_update_refresh(
        self, node: str | None = None, notify: bool | None = None, quiet: bool | None = None
    ) -> str | None:
        """POST /nodes/{node}/apt/update — resynchronize the APT package index (apt-get update).

        Smoke-confirm: POST /apt/update with body {notify?, quiet?} — shape not live-verified.
        Returns a worker task UPID (async) per schema truth (PVE::API2::APT update_database).
        Refreshes the index ONLY — does not install or upgrade any package.
        """
        n = self._resolve_node(node)
        body = {k: v for k, v in {"notify": notify, "quiet": quiet}.items() if v is not None}
        return self._post(f"/nodes/{n}/apt/update", body)  # Smoke-confirm: POST

    def apt_changelog(self, name: str, node: str | None = None, version: str | None = None) -> str:
        """GET /nodes/{node}/apt/changelog — package changelog text.

        Smoke-confirm: GET /apt/changelog?name=…[&version=…] — shape not live-verified.
        `name` is validated against PVE's own upstream package-name pattern. The returned text
        is UPSTREAM/package-maintainer-authored (not Proxmox-authored) — classified
        taint.ADVERSARIAL_TOOLS, unlike the other six apt_* tools.
        """
        _check_apt_package_name(name)
        n = self._resolve_node(node)
        q = f"?name={quote(name, safe='')}"
        if version is not None:
            q += f"&version={quote(version, safe='')}"
        return self._get(f"/nodes/{n}/apt/changelog{q}") or ""

    def apt_repositories_get(self, node: str | None = None) -> dict:
        """GET /nodes/{node}/apt/repositories — current APT repository configuration.

        Smoke-confirm: GET /apt/repositories — shape not live-verified. Expected
        {files, errors, digest, infos, standard-repos} per schema truth
        (PVE::API2::APT repositories).
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/apt/repositories") or {}

    def apt_repository_set(
        self,
        path: str,
        index: int,
        node: str | None = None,
        enabled: bool | None = None,
        digest: str | None = None,
    ) -> None:
        """POST /nodes/{node}/apt/repositories — enable/disable one repository entry by path+index.

        Smoke-confirm: POST /apt/repositories with body {path, index, enabled?, digest?}
        — shape not live-verified. digest forwarded for optimistic-concurrency when supplied.
        """
        _check_apt_repo_path(path)
        _check_apt_index(index)
        _check_apt_digest(digest)
        n = self._resolve_node(node)
        body: dict = {"path": path, "index": index}
        if enabled is not None:
            body["enabled"] = enabled
        if digest is not None:
            body["digest"] = digest
        self._post(f"/nodes/{n}/apt/repositories", body)  # Smoke-confirm: POST

    def apt_repository_add(
        self, handle: str, node: str | None = None, digest: str | None = None
    ) -> None:
        """PUT /nodes/{node}/apt/repositories — add a standard repository to the configuration.

        Smoke-confirm: PUT /apt/repositories with body {handle, digest?} — shape not live-verified.
        digest forwarded for optimistic-concurrency when supplied.
        """
        _check_apt_handle(handle)
        _check_apt_digest(digest)
        n = self._resolve_node(node)
        body: dict = {"handle": handle}
        if digest is not None:
            body["digest"] = digest
        self._put(f"/nodes/{n}/apt/repositories", body)  # Smoke-confirm: PUT

    def apt_versions(self, node: str | None = None) -> list[dict]:
        """GET /nodes/{node}/apt/versions — installed versions of important Proxmox packages.

        Smoke-confirm: GET /apt/versions — shape not live-verified. Expected per-package dicts
        (Package/Version/OldVersion + CurrentState/RunningKernel/ManagerVersion) per schema
        truth (PVE::API2::APT versions).
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/apt/versions") or []

    # --- Wave 6a: Ceph plane (core observability + flags) ---
    # Schema truth: .scratch/api-schemas-2026-07-15/wave6-pve-ceph-schema.json (37 paths, 48
    # methods, extracted from the live PVE apidoc pulled 2026-07-15). NONE of these are
    # live-verified yet — no Ceph cluster exists in the sealed vmbr1 lab today; every method
    # below carries its own Smoke-confirm comment. UNDO HONESTY: nothing on this plane is
    # PVE-snapshottable — no rollback primitive exists (same class as firewall/SDN/ACL).

    def ceph_status(self) -> dict:
        """GET /cluster/ceph/status — cluster-wide Ceph health/status.

        Smoke-confirm: GET /cluster/ceph/status — shape not live-verified. /nodes/{node}/ceph/
        status is a documented IDENTICAL alias per schema truth; not built as a separate tool.
        """
        return self._get("/cluster/ceph/status") or {}

    def ceph_metadata(self, scope: str | None = None) -> dict:
        """GET /cluster/ceph/metadata[?scope=] — per-daemon Ceph metadata (mon/mgr/mds/osd/node).

        Smoke-confirm: GET /cluster/ceph/metadata[?scope=] — shape not live-verified. `scope`
        in {all, versions} per schema (server-side default "all" when omitted).
        """
        q = ""
        if scope is not None:
            _check_ceph_metadata_scope(scope)
            q = f"?scope={scope}"
        return self._get(f"/cluster/ceph/metadata{q}") or {}

    def ceph_flags_list(self) -> list[dict]:
        """GET /cluster/ceph/flags — status of all 11 Ceph cluster flags.

        Smoke-confirm: GET /cluster/ceph/flags — shape not live-verified. Expected
        [{name, value, description}, ...] per schema truth.
        """
        return self._get("/cluster/ceph/flags") or []

    def ceph_flag_get(self, flag: str) -> bool:
        """GET /cluster/ceph/flags/{flag} — current value of one Ceph cluster flag.

        Smoke-confirm: GET /cluster/ceph/flags/{flag} — shape not live-verified. Returns a bare
        boolean per schema truth.
        """
        _check_ceph_flag(flag)
        return self._get(f"/cluster/ceph/flags/{flag}")

    def ceph_flags_set(self, flags: dict) -> str | None:
        """PUT /cluster/ceph/flags — bulk set/unset multiple Ceph flags at once. `flags` keys
        are WIRE flag names (already validated + hyphenated by the caller, tools/pve_ceph.py's
        `_ceph_flags_changes`); each True sets the flag, False unsets it, and any flag simply
        absent from the dict is left untouched. Runs as a worker task; returns a UPID to follow,
        per schema truth ("Runs as a worker task").

        Smoke-confirm: PUT /cluster/ceph/flags with a body of tri-state optional booleans —
        shape not live-verified.
        """
        for k in flags:
            _check_ceph_flag(k)
        return self._put("/cluster/ceph/flags", dict(flags))  # Smoke-confirm: PUT

    def ceph_flag_set(self, flag: str, value: bool) -> None:
        """PUT /cluster/ceph/flags/{flag} — set or clear (unset) a single Ceph flag. Runs
        SYNCHRONOUSLY (unlike the bulk PUT above, which forks a worker task) per schema truth;
        PVE returns null.

        Smoke-confirm: PUT /cluster/ceph/flags/{flag} with body {value} — shape not live-verified.
        """
        _check_ceph_flag(flag)
        self._put(f"/cluster/ceph/flags/{flag}", {"value": value})  # Smoke-confirm: PUT

    def ceph_cfg_db(self, node: str | None = None) -> list[dict]:
        """GET /nodes/{node}/ceph/cfg/db — the Ceph configuration database (mon config-db entries).

        Smoke-confirm: GET /ceph/cfg/db — shape not live-verified. Expected per-entry dicts
        (name/section/value/level/mask/can_update_at_runtime) per schema truth.
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/ceph/cfg/db") or []

    def ceph_cfg_raw(self, node: str | None = None) -> str:
        """GET /nodes/{node}/ceph/cfg/raw — the raw ceph.conf file content.

        Smoke-confirm: GET /ceph/cfg/raw — shape not live-verified. Expected plain INI-style text.
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/ceph/cfg/raw") or ""

    def ceph_cfg_value(self, config_keys: str, node: str | None = None) -> dict:
        """GET /nodes/{node}/ceph/cfg/value?config-keys=… — configured values for specific
        ceph.conf / mon-config-db keys. `config_keys` is validated client-side against the
        schema's '<section>:<key>[;|,| ...]' format (max 4096 chars).

        Smoke-confirm: GET /ceph/cfg/value — shape not live-verified. Expected a two-level
        {section: {key: value}} map per schema truth (underscores normalised to hyphens in the
        response, regardless of how they're written in `config_keys`).
        """
        _check_ceph_config_keys(config_keys)
        n = self._resolve_node(node)
        q = quote(config_keys, safe="")
        return self._get(f"/nodes/{n}/ceph/cfg/value?config-keys={q}") or {}

    def ceph_crush(self, node: str | None = None) -> str:
        """GET /nodes/{node}/ceph/crush — the OSD CRUSH map, decompiled to text.

        Smoke-confirm: GET /ceph/crush — shape not live-verified. Expected plaintext
        `crushtool -d`-style output.
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/ceph/crush") or ""

    def ceph_log(
        self, node: str | None = None, limit: int | None = None, start: int | None = None
    ) -> list[dict]:
        """GET /nodes/{node}/ceph/log[?limit=][&start=] — Ceph log lines. ADVERSARIAL:
        free-text log lines (taint.ADVERSARIAL_TOOLS), same rationale as pve_node_journal/
        pve_node_syslog.

        Smoke-confirm: GET /ceph/log — shape not live-verified. Expected [{n, t}, ...]
        (line number + text) per schema truth.
        """
        limit = _check_ceph_log_bound(limit, "limit")
        start = _check_ceph_log_bound(start, "start")
        n = self._resolve_node(node)
        # urlencode (not manual string-building): a caller-supplied limit/start is int-typed by
        # the wrapper's Field annotation, but this stays defensive against a direct backend call.
        query = {k: v for k, v in {"limit": limit, "start": start}.items() if v is not None}
        q = f"?{urlencode(query)}" if query else ""
        return self._get(f"/nodes/{n}/ceph/log{q}") or []

    def ceph_rules(self, node: str | None = None) -> list[dict]:
        """GET /nodes/{node}/ceph/rules — list configured Ceph CRUSH rule names.

        Smoke-confirm: GET /ceph/rules — shape not live-verified. Expected [{name}, ...] per
        schema truth.
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/ceph/rules") or []

    def ceph_cmd_safety(
        self, action: str, service: str, service_id: str, node: str | None = None
    ) -> dict:
        """GET /nodes/{node}/ceph/cmd-safety?action=&service=&id= — Ceph's own heuristic
        advisory on whether it is currently safe to stop/destroy a mon/mds/osd instance.
        ADVISORY ONLY — callers must never treat this as a gate (see the pve_ceph_cmd_safety
        wrapper docstring: an unreachable check becomes an honest note, never a fabricated
        safe=true).

        Smoke-confirm: GET /ceph/cmd-safety — shape not live-verified. Expected
        {safe: bool, status?: str} per schema truth (status = human-readable reason when not
        safe; absent when Ceph returned no message).
        """
        _check_ceph_cmd_safety_action(action)
        _check_ceph_cmd_safety_service(service)
        _check_ceph_service_id(service_id)
        n = self._resolve_node(node)
        q = urlencode({"action": action, "service": service, "id": service_id})
        return self._get(f"/nodes/{n}/ceph/cmd-safety?{q}") or {}

    # --- Wave 6b: Ceph plane (services lifecycle) ---
    # Schema truth: .scratch/api-schemas-2026-07-15/wave6-pve-ceph-schema.json. Same
    # Smoke-confirm / UNDO-honesty posture as the 6a block above — no rollback primitive on this
    # plane (same class as firewall/SDN/ACL).

    def _ceph_daemon_target(
        self, node: str | None, explicit_id: str | None, label: str
    ) -> tuple[str, str]:
        """Resolve (node, id) for a mon/mgr/mds CREATE whose id param (monid / id / name) is,
        mechanically, a REQUIRED URL path segment — even though the live schema lists it as
        'optional, default: nodename'. That default can only make sense if the CALLER resolves it
        before the request is built (a raw HTTP path segment cannot itself be "omitted"): the flat
        api-viewer schema documents `node` and the id param side-by-side in the same 'parameters'
        block regardless of which one is a true independent input vs. a path segment with a
        client-resolved default. Wave 6b build nuance — see wave-6b-report.md."""
        n = self._resolve_node(node)
        ident = _check_ceph_daemon_id(explicit_id, label) if explicit_id is not None else n
        return n, ident

    def ceph_mon_list(self, node: str | None = None) -> list[dict]:
        """GET /nodes/{node}/ceph/mon — Ceph monitors known to this node's view of the monmap.

        Smoke-confirm: GET /ceph/mon — shape not live-verified. Expected [{name, host, addr,
        ceph_version, ceph_version_short, direxists, quorum, rank, service, state}, ...] per
        schema truth.
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/ceph/mon") or []

    def ceph_mon_create(
        self, node: str | None = None, monid: str | None = None, mon_address: str | None = None
    ) -> str:
        """POST /nodes/{node}/ceph/mon/{monid} — create a Ceph Monitor. Auto-creates a Manager
        too if this is the FIRST monitor (schema truth). `monid` defaults to the nodename when
        omitted (see _ceph_daemon_target). `mon_address` overrides the autodetected monitor IP(s)
        — must be in Ceph's public network(s) (schema: format ip-list; no fixed regex given
        upstream, forwarded as-is).

        Smoke-confirm: POST /ceph/mon/{monid} — shape not live-verified. Returns a worker task
        UPID (async) per schema truth (returns: string).
        """
        n, mid = self._ceph_daemon_target(node, monid, "monid")
        body: dict = {}
        if mon_address is not None:
            body["mon-address"] = mon_address
        return self._post(f"/nodes/{n}/ceph/mon/{mid}", body)  # Smoke-confirm: POST

    def ceph_mon_destroy(self, monid: str, node: str | None = None) -> str:
        """DELETE /nodes/{node}/ceph/mon/{monid} — destroy a Ceph Monitor. Refuses to remove the
        LAST monitor of the cluster (schema truth); does not destroy any Manager on the same node.

        Smoke-confirm: DELETE /ceph/mon/{monid} — shape not live-verified. Returns a worker task
        UPID (async) per schema truth (returns: string).
        """
        mid = _check_ceph_daemon_id(monid, "monid")
        n = self._resolve_node(node)
        return self._delete(f"/nodes/{n}/ceph/mon/{mid}")  # Smoke-confirm: DELETE

    def ceph_mgr_list(self, node: str | None = None) -> list[dict]:
        """GET /nodes/{node}/ceph/mgr — Ceph managers known to this node's view of the mgrmap.

        Smoke-confirm: GET /ceph/mgr — shape not live-verified. Expected [{name, host, addr,
        ceph_version, ceph_version_short, direxists, service, state}, ...] per schema truth.
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/ceph/mgr") or []

    def ceph_mgr_create(self, node: str | None = None, mgr_id: str | None = None) -> str:
        """POST /nodes/{node}/ceph/mgr/{id} — create a Ceph Manager. `mgr_id` defaults to the
        nodename when omitted (see _ceph_daemon_target). Named `mgr_id` here (not `id`) to avoid
        shadowing the `id` builtin — mirrors the pve_ceph_cmd_safety `id`->`service_id` rename
        precedent from Wave 6a; the wire body/path still uses the literal `id` the schema names.

        Smoke-confirm: POST /ceph/mgr/{id} — shape not live-verified. Returns a worker task UPID
        (async) per schema truth (returns: string).
        """
        n, mid = self._ceph_daemon_target(node, mgr_id, "mgr id")
        return self._post(f"/nodes/{n}/ceph/mgr/{mid}")  # Smoke-confirm: POST

    def ceph_mgr_destroy(self, mgr_id: str, node: str | None = None) -> str:
        """DELETE /nodes/{node}/ceph/mgr/{id} — destroy a Ceph Manager. cmd-safety's service enum
        is {osd, mon, mds} — NO mgr — so no upstream heuristic safety check exists for this
        destroy (the plan factory states this plainly rather than inventing one).

        Smoke-confirm: DELETE /ceph/mgr/{id} — shape not live-verified. Returns a worker task UPID
        (async) per schema truth (returns: string).
        """
        mid = _check_ceph_daemon_id(mgr_id, "mgr id")
        n = self._resolve_node(node)
        return self._delete(f"/nodes/{n}/ceph/mgr/{mid}")  # Smoke-confirm: DELETE

    def ceph_mds_list(self, node: str | None = None) -> list[dict]:
        """GET /nodes/{node}/ceph/mds — Ceph metadata servers known to this node's view of the
        MDS map.

        Smoke-confirm: GET /ceph/mds — shape not live-verified. Expected [{name, host, addr,
        ceph_version, ceph_version_short, direxists, fs_name, rank, service, standby_replay,
        state}, ...] per schema truth.
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/ceph/mds") or []

    def ceph_mds_create(
        self, node: str | None = None, name: str | None = None, hotstandby: bool | None = None
    ) -> str:
        """POST /nodes/{node}/ceph/mds/{name} — create a Ceph Metadata Server (MDS). `name`
        defaults to the nodename when omitted (see _ceph_daemon_target). `hotstandby` (default
        False per schema): the daemon polls and replays an active MDS's log for faster failover,
        at the cost of more idle resources.

        Smoke-confirm: POST /ceph/mds/{name} — shape not live-verified. Returns a worker task
        UPID (async) per schema truth (returns: string).
        """
        n, nm = self._ceph_daemon_target(node, name, "mds name")
        body: dict = {}
        if hotstandby is not None:
            body["hotstandby"] = hotstandby
        return self._post(f"/nodes/{n}/ceph/mds/{nm}", body)  # Smoke-confirm: POST

    def ceph_mds_destroy(self, name: str, node: str | None = None) -> str:
        """DELETE /nodes/{node}/ceph/mds/{name} — destroy a Ceph Metadata Server.

        Smoke-confirm: DELETE /ceph/mds/{name} — shape not live-verified. Returns a worker task
        UPID (async) per schema truth (returns: string).
        """
        nm = _check_ceph_daemon_id(name, "mds name")
        n = self._resolve_node(node)
        return self._delete(f"/nodes/{n}/ceph/mds/{nm}")  # Smoke-confirm: DELETE

    def ceph_init(
        self,
        node: str | None = None,
        cluster_network: str | None = None,
        disable_cephx: bool | None = None,
        min_size: int | None = None,
        network: str | None = None,
        pg_bits: int | None = None,
        size: int | None = None,
    ) -> None:
        """POST /nodes/{node}/ceph/init — create the initial Ceph default configuration and set
        up symlinks. IDEMPOTENT on re-call per schema truth: if a [global] section already exists
        in ceph.conf, the existing fsid/auth/pool defaults are preserved and most parameters are
        silently ignored. `cluster_network` REQUIRES `network` also be set (schema: "requires":
        "network") — enforced here, before the request is built. `min_size`/`size` bounded 1-7,
        `pg_bits` bounded 6-14 (schema minimum/maximum) — validated client-side.

        Smoke-confirm: POST /ceph/init — shape not live-verified in practice, but the schema is
        unambiguous here (returns: null) — this is a genuine synchronous null-returner, not a
        defensively-typed guess.
        """
        n = self._resolve_node(node)
        if cluster_network is not None and network is None:
            raise ProximoError(
                "ceph_init: cluster_network requires network to also be set (schema: "
                "'requires': 'network')"
            )
        min_size = _check_ceph_init_bound(min_size, "min_size", 1, 7)
        size = _check_ceph_init_bound(size, "size", 1, 7)
        pg_bits = _check_ceph_init_bound(pg_bits, "pg_bits", 6, 14)
        cluster_network = _check_ceph_init_network(cluster_network, "cluster-network")
        network = _check_ceph_init_network(network, "network")
        body = {
            k: v for k, v in {
                "cluster-network": cluster_network,
                "disable_cephx": disable_cephx,
                "min_size": min_size,
                "network": network,
                "pg_bits": pg_bits,
                "size": size,
            }.items() if v is not None
        }
        return self._post(f"/nodes/{n}/ceph/init", body)  # Smoke-confirm: POST

    def ceph_service_start(self, node: str | None = None, service: str | None = None) -> str:
        """POST /nodes/{node}/ceph/start — start Ceph service(s). `service` matches
        `(ceph|mon|mds|osd|mgr)(.<id>)?`, defaulting to 'ceph.target' when omitted (schema).

        Smoke-confirm: POST /ceph/start — shape not live-verified. Returns a worker task UPID
        (async) per schema truth (returns: string).
        """
        n = self._resolve_node(node)
        body: dict = {}
        if service is not None:
            body["service"] = _check_ceph_service(service)
        return self._post(f"/nodes/{n}/ceph/start", body)  # Smoke-confirm: POST

    def ceph_service_stop(self, node: str | None = None, service: str | None = None) -> str:
        """POST /nodes/{node}/ceph/stop — stop Ceph service(s). `service` matches
        `(ceph|mon|mds|osd|mgr)(.<id>)?`, defaulting to 'ceph.target' when omitted (schema).
        HALTS I/O for the targeted storage daemon(s) — see pve_ceph_service_stop's RISK_HIGH
        docstring.

        Smoke-confirm: POST /ceph/stop — shape not live-verified. Returns a worker task UPID
        (async) per schema truth (returns: string).
        """
        n = self._resolve_node(node)
        body: dict = {}
        if service is not None:
            body["service"] = _check_ceph_service(service)
        return self._post(f"/nodes/{n}/ceph/stop", body)  # Smoke-confirm: POST

    def ceph_service_restart(self, node: str | None = None, service: str | None = None) -> str:
        """POST /nodes/{node}/ceph/restart — restart Ceph service(s). `service` matches
        `(ceph|mon|mds|osd|mgr)(.<id>)?`, defaulting to 'ceph.target' when omitted (schema).

        Smoke-confirm: POST /ceph/restart — shape not live-verified. Returns a worker task UPID
        (async) per schema truth (returns: string).
        """
        n = self._resolve_node(node)
        body: dict = {}
        if service is not None:
            body["service"] = _check_ceph_service(service)
        return self._post(f"/nodes/{n}/ceph/restart", body)  # Smoke-confirm: POST

    # --- Wave 6c: Ceph plane (OSD) ---
    # Schema truth: .scratch/api-schemas-2026-07-15/wave6-pve-ceph-schema.json. Same
    # Smoke-confirm / UNDO-honesty posture as the 6a/6b blocks above.

    def ceph_osd_tree(self, node: str | None = None) -> dict:
        """GET /nodes/{node}/ceph/osd — Ceph OSD list/tree: a nested CRUSH bucket structure
        (root -> children -> ... -> OSD leaves). ADVERSARIAL: per-node properties (status/
        weight/in/usage/latencies/...) are daemon-self-reported and the schema types the whole
        structure additionalProperties:1 (open, untyped) — see ceph.py's Taint section.

        Smoke-confirm: GET /ceph/osd — shape not live-verified. Expected {flags?, root: {id,
        name, type, children: [...]}} per schema truth (leaves carry an OSD's numeric `id`).
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/ceph/osd") or {}

    def ceph_osd_lv_info(
        self, osdid: int, node: str | None = None, lv_type: str | None = None
    ) -> dict:
        """GET /nodes/{node}/ceph/osd/{osdid}/lv-info[?type=] — an OSD's logical-volume details
        (LVM-reported via `lvs`, on the SAME host administering this OSD). `lv_type` in
        {block, db, wal} (named to avoid shadowing the `type` builtin — the wire query param is
        still the schema's literal `type`), schema default 'block'.

        Smoke-confirm: GET /ceph/osd/{osdid}/lv-info — shape not live-verified. Expected
        {creation_time, lv_name, lv_path, lv_size, lv_uuid, vg_name} per schema truth.
        """
        osdid = _check_ceph_osdid(osdid)
        n = self._resolve_node(node)
        q = ""
        if lv_type is not None:
            _check_ceph_osd_lv_type(lv_type)
            q = f"?type={lv_type}"
        return self._get(f"/nodes/{n}/ceph/osd/{osdid}/lv-info{q}") or {}

    def ceph_osd_metadata(self, osdid: int, node: str | None = None) -> dict:
        """GET /nodes/{node}/ceph/osd/{osdid}/metadata — per-OSD details (devices[] + an osd{}
        identity/address block). ADVERSARIAL: the osd{} sub-object carries hostname/back_addr/
        front_addr/hb_back_addr/hb_front_addr — the SAME daemon-self-reported identity/address
        fields that made pve_ceph_metadata's aggregated view ADVERSARIAL in Wave 6a; this is that
        exact channel's single-OSD drill-down, not a different one.

        Smoke-confirm: GET /ceph/osd/{osdid}/metadata — shape not live-verified. Expected
        {devices: [...], osd: {...}} per schema truth.
        """
        osdid = _check_ceph_osdid(osdid)
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/ceph/osd/{osdid}/metadata") or {}

    def ceph_osd_create(
        self,
        dev: str,
        node: str | None = None,
        crush_device_class: str | None = None,
        db_dev: str | None = None,
        db_dev_size: float | None = None,
        wal_dev: str | None = None,
        wal_dev_size: float | None = None,
        encrypted: bool | None = None,
        osds_per_device: int | None = None,
    ) -> str:
        """POST /nodes/{node}/ceph/osd — create a new OSD, consuming+formatting `dev`. RISK_HIGH
        (see pve_ceph_osd_create's docstring). `dev`/`db_dev`/`wal_dev` are validated with the
        Ceph-scoped `_check_ceph_osd_dev` block-device-path validator — the schema itself
        declares no format/pattern for these three params, but a deliberate, stricter-than-schema
        tightening for the single highest-risk mutation on this whole plane (a wrong/malformed
        device string here formats real hardware) is still worth doing; `_check_ceph_osd_dev` is
        a Ceph-scoped WIDENING of the shared `_check_disk` charset (adds '.', ':', '+', '=') so
        by-id/by-path stable device names (e.g. `/dev/disk/by-id/nvme-eui.<hex>`,
        `/dev/disk/by-path/pci-<bus>:<dev>.<fn>-...`) — the exact reference an operator reaches
        for on THIS plane to avoid `/dev/sdX` renumbering — are accepted rather than locally
        rejected (Wave 6c review Finding 1, MAJOR: the plain `_check_disk` reuse this shipped
        with first was too strict for its own highest-risk mutation). `_check_disk` itself is
        UNCHANGED — `node_disk_wipe`/`node_disk_initgpt` keep relying on its stricter shape.
        `crush_device_class` is forwarded unvalidated (no schema pattern; free-form label like
        'ssd'/'hdd'/'nvme' or a custom class) — mirrors mon_create's own `mon_address` "no regex
        given, don't invent one" posture. Schema-declared constraints enforced client-side:
        db_dev_size REQUIRES db_dev; wal_dev_size REQUIRES wal_dev (both schema "requires").
        `osds-per-device` is documented "Mutually exclusive with 'db_dev' and 'wal_dev'" in the
        schema's own param description (prose, not a formal requires/conflicts field) — enforced
        here anyway to fail fast locally rather than a guaranteed upstream rejection.

        Smoke-confirm: POST /ceph/osd — shape not live-verified. Returns a worker task UPID
        (async) per schema truth (returns: string). The new OSD's id is NOT in this response —
        only knowable after the task completes, by reading pve_ceph_osd_tree.
        """
        dev = _check_ceph_osd_dev(dev)
        n = self._resolve_node(node)
        if db_dev_size is not None and db_dev is None:
            raise ProximoError(
                "ceph_osd_create: db_dev_size requires db_dev to also be set (schema: "
                "'requires': 'db_dev')"
            )
        if wal_dev_size is not None and wal_dev is None:
            raise ProximoError(
                "ceph_osd_create: wal_dev_size requires wal_dev to also be set (schema: "
                "'requires': 'wal_dev')"
            )
        if osds_per_device is not None and (db_dev is not None or wal_dev is not None):
            raise ProximoError(
                "ceph_osd_create: osds_per_device is mutually exclusive with db_dev/wal_dev "
                "(schema param description, not a formal requires/conflicts field)"
            )
        if db_dev is not None:
            db_dev = _check_ceph_osd_dev(db_dev)
        if wal_dev is not None:
            wal_dev = _check_ceph_osd_dev(wal_dev)
        db_dev_size = _check_ceph_osd_min(db_dev_size, "db_dev_size", 1)
        wal_dev_size = _check_ceph_osd_min(wal_dev_size, "wal_dev_size", 0.5)
        osds_per_device = _check_ceph_osd_int_min(osds_per_device, "osds-per-device", 1)
        body = {
            k: v for k, v in {
                "dev": dev, "crush-device-class": crush_device_class, "db_dev": db_dev,
                "db_dev_size": db_dev_size, "wal_dev": wal_dev, "wal_dev_size": wal_dev_size,
                "encrypted": encrypted, "osds-per-device": osds_per_device,
            }.items() if v is not None
        }
        return self._post(f"/nodes/{n}/ceph/osd", body)  # Smoke-confirm: POST

    def ceph_osd_destroy(
        self, osdid: int, node: str | None = None, cleanup: bool | None = None
    ) -> str:
        """DELETE /nodes/{node}/ceph/osd/{osdid}[?cleanup=] — destroy an OSD. `cleanup=True`
        also destroys the underlying logical volumes (ceph-volume lvm zap --destroy + pvremove),
        removes the volume group's physical volume, and wipes any leftover journal/block.db/
        block.wal partitions from filestore OSDs (schema); without it, LVs/partitions are left
        intact for inspection.

        Smoke-confirm: DELETE /ceph/osd/{osdid} — shape not live-verified. Returns a worker task
        UPID (async) per schema truth (returns: string).
        """
        osdid = _check_ceph_osdid(osdid)
        n = self._resolve_node(node)
        params = {"cleanup": cleanup} if cleanup is not None else None
        return self._delete(f"/nodes/{n}/ceph/osd/{osdid}", params=params)  # Smoke-confirm: DELETE

    def ceph_osd_in(self, osdid: int, node: str | None = None) -> None:
        """POST /nodes/{node}/ceph/osd/{osdid}/in — mark an OSD 'in' (rejoins the CRUSH acting
        set; data rebalances BACK onto it). Runs SYNCHRONOUSLY per schema truth (returns: null).

        Smoke-confirm: POST /ceph/osd/{osdid}/in — shape not live-verified.
        """
        osdid = _check_ceph_osdid(osdid)
        n = self._resolve_node(node)
        return self._post(f"/nodes/{n}/ceph/osd/{osdid}/in")  # Smoke-confirm: POST

    def ceph_osd_out(self, osdid: int, node: str | None = None) -> None:
        """POST /nodes/{node}/ceph/osd/{osdid}/out — mark an OSD 'out' (excluded from the CRUSH
        acting set; triggers data rebalance/recovery AWAY from it). Runs SYNCHRONOUSLY per
        schema truth (returns: null).

        Smoke-confirm: POST /ceph/osd/{osdid}/out — shape not live-verified.
        """
        osdid = _check_ceph_osdid(osdid)
        n = self._resolve_node(node)
        return self._post(f"/nodes/{n}/ceph/osd/{osdid}/out")  # Smoke-confirm: POST

    def ceph_osd_scrub(
        self, osdid: int, node: str | None = None, deep: bool | None = None
    ) -> None:
        """POST /nodes/{node}/ceph/osd/{osdid}/scrub[?deep=] — instruct an OSD to scrub (light,
        or deep when deep=True). Runs SYNCHRONOUSLY per schema truth (returns: null). No logical
        state change; a deep scrub is I/O-heavy while it runs.

        Smoke-confirm: POST /ceph/osd/{osdid}/scrub — shape not live-verified.
        """
        osdid = _check_ceph_osdid(osdid)
        n = self._resolve_node(node)
        body: dict = {}
        if deep is not None:
            body["deep"] = deep
        return self._post(f"/nodes/{n}/ceph/osd/{osdid}/scrub", body)  # Smoke-confirm: POST

    # --- Wave 6d: Ceph plane (pools + CephFS) — CLOSES Wave 6 ---
    # Schema truth: .scratch/api-schemas-2026-07-15/wave6-pve-ceph-schema.json. Same
    # node-resolution/proxyto="node" pattern as every other Ceph method above.

    def ceph_pool_list(self, node: str | None = None) -> list[dict]:
        """GET /nodes/{node}/ceph/pool — all pools + their current settings.

        Smoke-confirm: GET /ceph/pool — shape not live-verified. Expected [{pool, pool_name,
        type, size, min_size, pg_num, pg_num_min, pg_num_final, pg_autoscale_mode, crush_rule,
        crush_rule_name, bytes_used, percent_used, target_size, target_size_ratio,
        application_metadata, autoscale_status}, ...] per schema truth.
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/ceph/pool") or []

    def ceph_pool_status(
        self, name: str, node: str | None = None, verbose: bool | None = None
    ) -> dict:
        """GET /nodes/{node}/ceph/pool/{name}/status[?verbose=] — one pool's current settings
        (+ usage/IO statistics when verbose=True).

        Smoke-confirm: GET /ceph/pool/{name}/status — shape not live-verified. Expected {id,
        name, application, application_list, crush_rule, min_size, size, pg_num, pg_num_min,
        pgp_num, pg_autoscale_mode, target_size, target_size_ratio, autoscale_status, fast_read,
        hashpspool, nodelete, nopgchange, nosizechange, noscrub, nodeep-scrub, use_gmt_hitset,
        write_fadvise_dontneed, statistics?} per schema truth — `statistics` is only present
        when verbose=True.
        """
        name = _check_ceph_pool_or_fs_name(name, "pool name")
        n = self._resolve_node(node)
        q = f"?{urlencode({'verbose': 1 if verbose else 0})}" if verbose is not None else ""
        return self._get(f"/nodes/{n}/ceph/pool/{name}/status{q}") or {}

    def ceph_pool_create(
        self,
        name: str,
        node: str | None = None,
        add_storages: bool | None = None,
        application: str | None = None,
        crush_rule: str | None = None,
        erasure_coding: str | None = None,
        min_size: int | None = None,
        pg_autoscale_mode: str | None = None,
        pg_num: int | None = None,
        pg_num_min: int | None = None,
        size: int | None = None,
        target_size: str | None = None,
        target_size_ratio: float | None = None,
    ) -> str:
        """POST /nodes/{node}/ceph/pool — create a Ceph pool. RISK_MEDIUM (see
        pve_ceph_pool_create's docstring). `add_storages` schema-defaults False for replicated
        pools and True for erasure-coded pools — left None (server-applies-default) unless the
        caller sets it explicitly. `crush_rule` here is the RULE NAME (string) — a DIFFERENT
        type than the numeric `crush_rule` id returned by ceph_pool_list/ceph_pool_status (see
        ceph.py module docstring's Wave 6d "Schema divergences" section). `erasure_coding` is
        PVE's own propertyString wire format, validated by parsing
        (_check_ceph_pool_erasure_coding) then passed through unchanged.

        Smoke-confirm: POST /ceph/pool — shape not live-verified. Returns a worker task UPID
        (async) per schema truth (returns: string).
        """
        name = _check_ceph_pool_or_fs_name(name, "pool name")
        n = self._resolve_node(node)
        if application is not None:
            application = _check_ceph_pool_application(application)
        if erasure_coding is not None:
            erasure_coding = _check_ceph_pool_erasure_coding(erasure_coding)
        min_size = _check_ceph_bounded_int(min_size, "pool min_size", 1, 7)
        size = _check_ceph_bounded_int(size, "pool size", 1, 7)
        pg_num = _check_ceph_bounded_int(pg_num, "pool pg_num", 1, 32768)
        pg_num_min = _check_ceph_pool_upper_bound(pg_num_min, "pg_num_min", 32768)
        if pg_autoscale_mode is not None:
            pg_autoscale_mode = _check_ceph_pool_autoscale_mode(pg_autoscale_mode)
        if target_size is not None:
            target_size = _check_ceph_pool_target_size(target_size)
        target_size_ratio = _check_ceph_pool_ratio(target_size_ratio)
        body = {
            k: v for k, v in {
                "name": name, "add_storages": add_storages, "application": application,
                "crush_rule": crush_rule, "erasure-coding": erasure_coding, "min_size": min_size,
                "pg_autoscale_mode": pg_autoscale_mode, "pg_num": pg_num,
                "pg_num_min": pg_num_min, "size": size, "target_size": target_size,
                "target_size_ratio": target_size_ratio,
            }.items() if v is not None
        }
        return self._post(f"/nodes/{n}/ceph/pool", body)  # Smoke-confirm: POST

    def ceph_pool_set(
        self,
        name: str,
        node: str | None = None,
        application: str | None = None,
        crush_rule: str | None = None,
        min_size: int | None = None,
        pg_autoscale_mode: str | None = None,
        pg_num: int | None = None,
        pg_num_min: int | None = None,
        size: int | None = None,
        target_size: str | None = None,
        target_size_ratio: float | None = None,
    ) -> str:
        """PUT /nodes/{node}/ceph/pool/{name} — change an existing pool's settings. RISK_MEDIUM:
        a pg_num change triggers cluster rebalance (see pve_ceph_pool_set's docstring). No
        add_storages/erasure-coding here — PUT does not accept either (create-only per schema).

        Smoke-confirm: PUT /ceph/pool/{name} — shape not live-verified. Returns a worker task
        UPID (async) per schema truth (returns: string).
        """
        name = _check_ceph_pool_or_fs_name(name, "pool name")
        n = self._resolve_node(node)
        if application is not None:
            application = _check_ceph_pool_application(application)
        min_size = _check_ceph_bounded_int(min_size, "pool min_size", 1, 7)
        size = _check_ceph_bounded_int(size, "pool size", 1, 7)
        pg_num = _check_ceph_bounded_int(pg_num, "pool pg_num", 1, 32768)
        pg_num_min = _check_ceph_pool_upper_bound(pg_num_min, "pg_num_min", 32768)
        if pg_autoscale_mode is not None:
            pg_autoscale_mode = _check_ceph_pool_autoscale_mode(pg_autoscale_mode)
        if target_size is not None:
            target_size = _check_ceph_pool_target_size(target_size)
        target_size_ratio = _check_ceph_pool_ratio(target_size_ratio)
        body = {
            k: v for k, v in {
                "application": application, "crush_rule": crush_rule, "min_size": min_size,
                "pg_autoscale_mode": pg_autoscale_mode, "pg_num": pg_num,
                "pg_num_min": pg_num_min, "size": size, "target_size": target_size,
                "target_size_ratio": target_size_ratio,
            }.items() if v is not None
        }
        return self._put(f"/nodes/{n}/ceph/pool/{name}", body)  # Smoke-confirm: PUT

    def ceph_pool_destroy(
        self,
        name: str,
        node: str | None = None,
        force: bool | None = None,
        remove_ecprofile: bool | None = None,
        remove_storages: bool | None = None,
    ) -> str:
        """DELETE /nodes/{node}/ceph/pool/{name} — destroy a pool. RISK_HIGH, UNRECOVERABLE via
        the API (see pve_ceph_pool_destroy's docstring). `force` is NEVER defaulted on here —
        forwarded only when the caller explicitly sets it (schema: "destroys pool even if in
        use"). `remove_ecprofile` schema-defaults True; `remove_storages` schema-defaults False —
        both left None (server-applies-default) unless the caller sets them.

        Smoke-confirm: DELETE /ceph/pool/{name} — shape not live-verified. Returns a worker task
        UPID (async) per schema truth (returns: string).
        """
        name = _check_ceph_pool_or_fs_name(name, "pool name")
        n = self._resolve_node(node)
        params = {
            k: v for k, v in {
                "force": force, "remove_ecprofile": remove_ecprofile,
                "remove_storages": remove_storages,
            }.items() if v is not None
        }
        return self._delete(f"/nodes/{n}/ceph/pool/{name}", params=params)  # Smoke-confirm: DELETE

    def ceph_fs_list(self, node: str | None = None) -> list[dict]:
        """GET /nodes/{node}/ceph/fs — configured CephFS filesystems.

        Smoke-confirm: GET /ceph/fs — shape not live-verified. Expected [{name, metadata_pool,
        metadata_pool_id, data_pool, data_pool_ids, data_pools}, ...] per schema truth
        (data_pool/metadata_pool are kept for backwards compat; data_pools/data_pool_ids carry
        the FULL set for a multi-data-pool filesystem).
        """
        n = self._resolve_node(node)
        return self._get(f"/nodes/{n}/ceph/fs") or []

    def ceph_fs_create(
        self,
        node: str | None = None,
        name: str | None = None,
        add_storage: bool | None = None,
        pg_num: int | None = None,
    ) -> str:
        """POST /nodes/{node}/ceph/fs/{name} — create a Ceph filesystem. `name` schema-defaults
        to the FIXED LITERAL 'cephfs' when omitted — resolved client-side via
        `_check_ceph_fs_name_or_default` since `name` is ALSO the URL path segment (see that
        function's docstring). RISK_MEDIUM (see pve_ceph_fs_create's docstring).

        Smoke-confirm: POST /ceph/fs/{name} — shape not live-verified. Returns a worker task
        UPID (async) per schema truth (returns: string).
        """
        nm = _check_ceph_fs_name_or_default(name)
        n = self._resolve_node(node)
        pg_num = _check_ceph_bounded_int(pg_num, "fs pg_num", 8, 32768)
        body = {
            k: v for k, v in {"add-storage": add_storage, "pg_num": pg_num}.items()
            if v is not None
        }
        return self._post(f"/nodes/{n}/ceph/fs/{nm}", body)  # Smoke-confirm: POST

    def ceph_fs_destroy(
        self,
        name: str,
        node: str | None = None,
        remove_pools: bool | None = None,
        remove_storages: bool | None = None,
    ) -> str:
        """DELETE /nodes/{node}/ceph/fs/{name} — destroy a Ceph filesystem. Refuses upstream
        while a 'cephfs' PVE storage entry still references it and is not disabled, UNLESS
        remove-storages is set (schema truth). RISK_HIGH, UNRECOVERABLE via the API (see
        pve_ceph_fs_destroy's docstring).

        Smoke-confirm: DELETE /ceph/fs/{name} — shape not live-verified. Returns a worker task
        UPID (async) per schema truth (returns: string).
        """
        name = _check_ceph_pool_or_fs_name(name, "fs name")
        n = self._resolve_node(node)
        params = {
            k: v for k, v in {
                "remove-pools": remove_pools, "remove-storages": remove_storages,
            }.items() if v is not None
        }
        return self._delete(f"/nodes/{n}/ceph/fs/{name}", params=params)  # Smoke-confirm: DELETE

    def node_cert_upload(
        self,
        certificates: str,
        node: str | None = None,
        key: str | None = None,
        force: bool = False,
        restart: bool = False,
    ) -> dict | None:
        """POST /nodes/{node}/certificates/custom — upload a custom TLS certificate.

        Smoke-confirm: POST /certificates/custom with body {certificates, [key], force, restart}
        — shape not live-verified.
        Private key (key) is NEVER logged by the caller — only {"key": "[redacted]"} reaches the ledger.
        """
        n = self._resolve_node(node)
        body: dict = {
            "certificates": certificates,
            "force": int(force),
            "restart": int(restart),
        }
        if key is not None:
            body["key"] = key
        return self._post(f"/nodes/{n}/certificates/custom", body)  # Smoke-confirm: POST

    def node_cert_delete(self, node: str | None = None, restart: bool = False) -> None:
        """DELETE /nodes/{node}/certificates/custom — remove the custom TLS cert.

        Smoke-confirm: DELETE /certificates/custom [?restart=1] — shape not live-verified.
        """
        n = self._resolve_node(node)
        params = {"restart": 1} if restart else None
        self._delete(f"/nodes/{n}/certificates/custom", params=params)  # Smoke-confirm: DELETE

    def node_startall(self, node: str | None = None, vms: str | None = None) -> str | None:
        """POST /nodes/{node}/startall — start all (or filtered) guests.

        Smoke-confirm: POST /startall [body {vms: CSV}] — shape not live-verified.
        Returns a task UPID or None.
        """
        n = self._resolve_node(node)
        body: dict | None = {"vms": vms} if vms is not None else None
        return self._post(f"/nodes/{n}/startall", body)  # Smoke-confirm: POST

    def node_stopall(self, node: str | None = None, vms: str | None = None) -> str | None:
        """POST /nodes/{node}/stopall — stop all (or filtered) guests.

        Smoke-confirm: POST /stopall [body {vms: CSV}] — shape not live-verified.
        Returns a task UPID or None.
        """
        n = self._resolve_node(node)
        body: dict | None = {"vms": vms} if vms is not None else None
        return self._post(f"/nodes/{n}/stopall", body)  # Smoke-confirm: POST

    def node_migrateall(
        self,
        target: str,
        node: str | None = None,
        vms: str | None = None,
        maxworkers: int | None = None,
    ) -> str | None:
        """POST /nodes/{node}/migrateall — migrate all (or filtered) guests to another node.

        Smoke-confirm: POST /migrateall with body {target, [vms], [maxworkers]}
        — shape not live-verified.
        Returns a task UPID or None.
        """
        _check_node(target)
        n = self._resolve_node(node)
        body: dict = {"target": target}
        if vms is not None:
            body["vms"] = vms
        if maxworkers is not None:
            body["maxworkers"] = int(maxworkers)
        return self._post(f"/nodes/{n}/migrateall", body)  # Smoke-confirm: POST
