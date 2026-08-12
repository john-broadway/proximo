"""PBS node OS administration — dns/time/network/certificates/services/subscription/status/
tasks/journal/syslog.

Wave 2c of the full-surface campaign (`.scratch/2026-07-15-full-surface-campaign.md`, "2c — PBS
node OS admin"). Mirrors the PVE node-lifecycle/observability split (`node_lifecycle.py` +
`observability.py`) but for PBS's own `/nodes/{node}/...` surface — a DIFFERENT concern from
`pbs_access.py` (identity/ACL/realms/TFA), so it lives in its own module pair, same as
`pve_node.py` is its own file alongside `pve_access.py`.

Schema truth: the LIVE api-viewer schema, https://pbs.proxmox.com/docs/api-viewer/apidoc.js,
pulled 2026-07-15 — every path/verb/param below was read directly from the live JSON-Schema
`parameters`/`returns` blocks (`.scratch/api-schemas-2026-07-15/methods-pbs.json` carries
path+verb only, no param detail, matching the discipline already established in pbs_access.py).
NONE of this module is live-verified against a running PBS yet — every backend function is
schema-derived only; "Smoke-confirm:" comments name the specific unverified detail.

Endpoint table (all under /nodes/{node}/..., node defaults to "localhost" — PBS is typically
single-node; PbsConfig carries no node field, mirrors pbs.py's tasks_list/apt_* precedent of
`node: str = "localhost"` rather than PVE's `node or cfg.node`):

  DNS:
    GET  /dns                        — dns_get             (read)
    PUT  /dns                        — dns_set              (MUTATION, MEDIUM)

  Time:
    GET  /time                       — time_get             (read)
    PUT  /time                       — time_set              (MUTATION, LOW)

  Network:
    GET    /network                  — network_list         (read)
    GET    /network/{iface}          — network_iface_get    (read)
    POST   /network                  — network_iface_create (MUTATION, MEDIUM — staged)
    PUT    /network/{iface}          — network_iface_update (MUTATION, MEDIUM — staged)
    DELETE /network/{iface}          — network_iface_delete (MUTATION, MEDIUM — staged)
    PUT    /network                  — network_reload       (MUTATION, HIGH — applies staged->live)
    DELETE /network                  — network_revert       (MUTATION, LOW — discards staged)

  Certificates:
    GET    /certificates/info        — certificates_list    (read)
    POST   /certificates/custom      — cert_upload           (MUTATION, HIGH, no undo)
    DELETE /certificates/custom      — cert_delete            (MUTATION, MEDIUM)

  Services:
    GET  /services                          — services_list  (read)
    GET  /services/{service}/state          — service_status (read)
    POST /services/{service}/{action}       — service_control (MUTATION, lockout-aware)

  Subscription:
    GET    /subscription             — subscription_get      (read)
    PUT    /subscription             — subscription_set      (MUTATION, MEDIUM — installs a key)
    POST   /subscription             — subscription_check    (MUTATION, LOW — online refresh)
    DELETE /subscription             — subscription_delete   (MUTATION, MEDIUM)

  Status:
    GET  /status                     — node_status            (read)
    (POST /status "Reboot or shutdown the node" EXISTS on the live schema — deliberately
    EXCLUDED, see EXCLUSION below.)

  Tasks (pbs_tasks_list/GET /tasks already shipped in an earlier wave — see backup_schedules.py /
  pbs.py's tasks_list, registered as the `pbs_tasks_list` tool; NOT rebuilt here):
    GET    /tasks/{upid}/status      — task_status            (read)
    GET    /tasks/{upid}/log         — task_log                (read)
    DELETE /tasks/{upid}             — task_stop                (MUTATION, HIGH)

  Logs:
    GET  /journal                    — journal                 (read; ADVERSARIAL — free text)
    GET  /syslog                     — syslog                   (read; ADVERSARIAL — free text)

SCHEMA DIFFERENCES FROM PVE (confirmed against the live PVE schema too, not assumed):
  - PBS has NO /nodes/{node}/hosts endpoint at all. PVE exposes GET/POST /nodes/{node}/hosts for
    /etc/hosts management (pve_node_hosts_get/pve_node_hosts_set); PBS's api-viewer schema has no
    'host' substring anywhere in its ~250 paths. This is a genuine PBS/PVE gap, not an oversight —
    no pbs_node_hosts_get/set tools exist in this module. (The campaign's own Wave-2-decomposition
    note guessed "hosts(config)" for this wave without checking the live schema; corrected here.)
  - PVE's /nodes/{node}/status ALSO has a POST "Reboot or shutdown a node" (identical shape to
    PBS's) — and Proximo has never built a tool for either. Node-level reboot/shutdown is
    deliberately excluded on BOTH planes (see EXCLUSION below), so this is parity, not a PBS-only
    gap.
  - PBS's network iface create/update mark 'type' OPTIONAL (schema: `optional: 1` on both POST and
    PUT) — unlike PVE, where create requires 'type' and update's schema documents it as the SOLE
    required param (network.py's own `network_iface_update` reads the interface's current type and
    injects it as a workaround). PBS needs no such workaround: `network_iface_update` here is a
    plain pass-through of whatever fields are supplied.
  - PBS's iface type enum is {loopback, eth, bridge, bond, vlan, alias, unknown} — no OVS
    (Open vSwitch) types, unlike PVE's {bridge, bond, eth, alias, vlan, OVSBridge, OVSBond,
    OVSPort, OVSIntPort}. PBS adds 'unknown' as an explicit type PVE doesn't have.
  - PBS's DELETE /nodes/{node}/network ("Revert network configuration changes") and PVE's own
    (identical path+verb) both exist on their respective live schemas, but Proximo has never built
    either side before this wave — pbs_node_network_revert here is a genuinely new tool, not a
    PVE-parity gap.
  - PBS's certificates/custom POST and DELETE both document a `restart` param as "UI compatibility
    parameter, ignored" — unlike PVE, where `restart` genuinely reloads pveproxy. Deliberately NOT
    exposed here (same discipline as pbs_access.py's PUT /access/users 'password': exposing a
    working-looking no-op parameter would mislead a caller into thinking it does something).
  - PBS's /nodes/{node}/subscription exposes FOUR verbs (GET/POST/PUT/DELETE) — and so does PVE's
    equivalent (checked on the live PVE schema, 2026-07-15: PVE also exposes all four, DELETE
    included). This is NOT a PBS-vs-PVE schema difference. It IS a difference vs Proximo's OWN
    coverage: pve_node_subscription is read-only in this codebase (only GET was ever built), so
    subscription_check (POST — "Check and update subscription status", contacts Proxmox's server)
    and subscription_delete (DELETE — "Delete subscription info") have no pve_node_* counterpart
    to mirror — a gap in our PVE coverage, not in PVE's API.
  - PBS's task-log endpoint additionally exposes `download` (whole-file-download mode, "can't be
    used in conjunction with other parameters" per its own schema) and `test-status` (side-effect
    flag). Neither is exposed here — `download` changes the response content-type entirely (a
    different shape than the list-of-lines this module returns) and `test-status` is a
    status-refresh side effect unrelated to reading the log; task_log here mirrors PVE's own
    task_log signature (start/limit) for interface consistency across planes.
  - PBS additionally exposes GET /nodes/{node}/config (general node settings: description,
    email-from, http-proxy, task-log-max-days, consent-text, default-lang, ciphers, PLUS
    acme/acmedomain0-4 — ACME account/domain assignment fields) and GET /nodes/{node}/report (a
    free-text diagnostic bundle) and GET /nodes/{node}/rrd (telemetry). None of the three are built
    in this wave: /config's mutable surface is dominated by ACME identity assignment (Wave 3's
    territory, `.scratch/2026-07-15-full-surface-campaign.md`); /report and /rrd were not named in
    this wave's tool list and are deferred rather than scope-crept in.

EXCLUSION: POST /nodes/{node}/status ("Reboot or shutdown the node") is deliberately excluded —
mirrors node_lifecycle.py's own EXCLUSION of POST /nodes/{node}/execute on the PVE side (too
dangerous for the default surface) and, confirmed above, PVE has never built a tool for its own
identically-shaped POST /nodes/{node}/status either. A future PROXIMO_ENABLE_NODE_POWER wave could
add either side under a separate opt-in gate.

Security posture:
- All path components validated with \\Z-anchored regexes (trailing-newline bypass rejected),
  mirroring pbs_access.py's `_reject_dot_traversal` discipline where a value flows into a URL path.
- iface: charset-validated (letters/digits/._- , 1-15 chars — the 15-char cap is a DEFENSIVE choice
  mirroring PVE's own IFNAMSIZ-based cap; PBS's schema itself declares no length limit).
- service: same charset discipline as PVE's observability.py `_check_service` (letters/digits/
  ._- only, <=64 chars) — PBS's schema declares no pattern for the 'service' path param either;
  this validator is defensive, not schema-derived.
- digest: PBS's own `^[a-f0-9]{64}$` optimistic-concurrency-lock pattern, validated by the
  shared plane-neutral `_validate.check_digest` (the A11 consolidation retired the per-module
  copies; genuinely divergent digests like pmg.py's `_PMG_APT_DIGEST_RE` keep their own).
- Cert private key: UNCONDITIONALLY redacted — never appears in plan, change, current, detail, or
  ledger, even with redact_ledger=False. `_key_fingerprint()` mirrors node_lifecycle.py's own
  helper of the same name verbatim (independent copy, same contract).
- CAPTURE-or-declare: dns_set's plan factory reads current DNS config before planning; on read
  failure -> complete=False + an honest note (mirrors node_lifecycle.py's plan_node_dns_set).

Service-control lockout set: PBS's own critical daemons — 'proxmox-backup' (privileged backend/
task-worker daemon), 'proxmox-backup-proxy' (the API/web frontend — losing it drops management
access), plus the same host-level essentials PVE's own lockout set names (networking, sshd/ssh,
ifupdown2, chrony) since a PBS host still depends on them for connectivity/access. PBS has no
cluster-quorum daemon (corosync/pve-cluster) and no PVE-style firewall service — both omitted, not
carried over blindly. Smoke-confirm: the exact systemd unit names on a live PBS host (this set is
curated from PBS's own package/service naming conventions, not read from a live `services_list`).
"""

from __future__ import annotations

import re

from ._validate import check_digest as _check_digest
from .backends import ProximoError, _check_timezone, _check_upid
from .pbs import PbsBackend, _check_pbs_node
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# Interface name: PBS's own pattern is /^[A-Za-z0-9_][A-Za-z0-9._-]*$/ (source: POST/PUT/GET
# 'iface' property pattern, live api-viewer 2026-07-15) — no length cap documented. The 15-char
# cap here is a DEFENSIVE addition (Linux IFNAMSIZ-1), mirroring network.py's own _IFACE_RE.
_IFACE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,14}\Z")

# PBS's network interface type enum (source: GET /network response items[].type / POST+PUT
# 'type' property enum, live api-viewer). Notably has NO OVS types (unlike PVE) and adds
# 'unknown' + 'loopback' as explicit values.
_VALID_IFACE_TYPES = frozenset({"loopback", "eth", "bridge", "bond", "vlan", "alias", "unknown"})

# service: letters/digits/._- only, <=64 chars — mirrors observability.py's PVE _check_service
# charset exactly (PBS's schema declares no pattern for this path param; defensive, not derived).
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

_VALID_SERVICE_ACTIONS = frozenset({"start", "stop", "restart", "reload"})

# Services whose stop/restart/reload can sever management access on a PBS host. Curated — see
# module docstring's "Service-control lockout set" section for the rationale per entry.
_PBS_LOCKOUT_SERVICES: frozenset[str] = frozenset({
    "proxmox-backup",
    "proxmox-backup-proxy",
    "networking",
    "sshd",
    "ssh",
    "ifupdown2",
    "chrony",
    "chronyd",
})


def _reject_dot_traversal(s: str, label: str) -> None:
    """Reject a '.'/'..'-containing identifier that flows into a URL path segment — mirrors
    pbs_access.py's identical guard and network.py's PVE-side iface guard."""
    if s == "." or ".." in s:
        raise ProximoError(f"invalid {label}: {s!r} — path-traversal segment rejected")


def _check_iface(iface: str) -> str:
    s = str(iface)
    _reject_dot_traversal(s, "interface name")
    if not _IFACE_RE.match(s):
        raise ProximoError(
            f"invalid interface name: {iface!r} "
            "(letters/digits/._- only, 1-15 chars, starting with alnum/underscore)"
        )
    return s


def _check_iface_type(iface_type: str) -> str:
    t = str(iface_type)
    if t not in _VALID_IFACE_TYPES:
        raise ProximoError(
            f"invalid PBS interface type: {iface_type!r} (expected one of {sorted(_VALID_IFACE_TYPES)})"
        )
    return t


def _check_service(service: str) -> str:
    s = str(service)
    if not _SERVICE_RE.match(s):
        raise ProximoError(
            f"invalid service name: {service!r} "
            "(letters/digits/._- only, start with alnum, <=64 chars)"
        )
    return s


def _check_service_action(action: str) -> str:
    a = str(action).strip()
    if a not in _VALID_SERVICE_ACTIONS:
        raise ProximoError(
            f"invalid service action: {action!r} (expected one of {sorted(_VALID_SERVICE_ACTIONS)})"
        )
    return a


def _normalize_service_name(service: str) -> str:
    name = service.lower()
    if name.endswith(".service"):
        name = name[: -len(".service")]
    return name


def _is_lockout_service(service: str) -> bool:
    return _normalize_service_name(service) in _PBS_LOCKOUT_SERVICES


def _key_fingerprint() -> dict:
    """Unconditional redaction for TLS private keys — never store even a hash. Independent copy
    of node_lifecycle.py's helper of the same name; same contract."""
    return {"key": "[redacted]"}


def _join_delete_props(delete_props) -> str:
    # Smoke-confirm: PBS's accepted array encoding for 'delete' (comma-joined here, matching
    # pbs_access.py's own `_join_delete_props` convention).
    if isinstance(delete_props, (list, tuple)):
        return ",".join(delete_props)
    return str(delete_props)


def _check_nonneg_int(value, field: str) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid {field}: {value!r} (must be an integer)") from exc
    if n < 0:
        raise ProximoError(f"invalid {field}: {value!r} (must be >= 0)")
    return n


# ---------------------------------------------------------------------------
# Backend functions — DNS
# ---------------------------------------------------------------------------

def dns_get(api: PbsBackend, node: str = "localhost") -> dict:
    """GET /nodes/{node}/dns — read DNS resolver settings (search/dns1/dns2/dns3/digest)."""
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/dns") or {}


def dns_set(
    api: PbsBackend,
    node: str = "localhost",
    search: str | None = None,
    dns1: str | None = None,
    dns2: str | None = None,
    dns3: str | None = None,
    delete_props: list[str] | None = None,
    digest: str | None = None,
) -> object:
    """PUT /nodes/{node}/dns — update DNS resolver settings. Returns None on success.

    Smoke-confirm: whether 'delete' (property-name list) is accepted as comma-joined form data
    (mirrors the open question already carried by pbs_access.py's `_join_delete_props`)."""
    node = _check_pbs_node(node)
    data: dict = {}
    if search is not None:
        data["search"] = search
    if dns1 is not None:
        data["dns1"] = dns1
    if dns2 is not None:
        data["dns2"] = dns2
    if dns3 is not None:
        data["dns3"] = dns3
    if delete_props is not None:
        data["delete"] = _join_delete_props(delete_props)
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/nodes/{node}/dns", data or None)


# ---------------------------------------------------------------------------
# Backend functions — Time
# ---------------------------------------------------------------------------

def time_get(api: PbsBackend, node: str = "localhost") -> dict:
    """GET /nodes/{node}/time — read server time + timezone ({localtime, time, timezone})."""
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/time") or {}


def time_set(api: PbsBackend, timezone: str, node: str = "localhost") -> object:
    """PUT /nodes/{node}/time — set the node's timezone. Returns None on success."""
    timezone = _check_timezone(timezone)
    node = _check_pbs_node(node)
    return api._put(f"/nodes/{node}/time", {"timezone": timezone})


# ---------------------------------------------------------------------------
# Backend functions — Network
# ---------------------------------------------------------------------------

def network_list(api: PbsBackend, node: str = "localhost") -> list[dict]:
    """GET /nodes/{node}/network — list network interfaces (with config digest).

    Returns a list of interface dicts (active/altnames/autostart/bond*/bridge_*/cidr*/comments*/
    gateway*/method*/mtu/name/options*/slaves/type/vlan-*)."""
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/network") or []


def network_iface_get(api: PbsBackend, iface: str, node: str = "localhost") -> dict:
    """GET /nodes/{node}/network/{iface} — read one interface's configuration."""
    iface = _check_iface(iface)
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/network/{iface}") or {}


def network_iface_create(
    api: PbsBackend,
    iface: str,
    node: str = "localhost",
    iface_type: str | None = None,
    **opts,
) -> object:
    """POST /nodes/{node}/network — create a network interface configuration (staged, written to
    interfaces.new — not live until network_reload). Returns None.

    'iface' is the SOLE schema-required field — PBS's own schema marks 'type' OPTIONAL on create
    (unlike PVE, which requires it). iface_type, if given, is validated against PBS's own enum.
    """
    iface = _check_iface(iface)
    node = _check_pbs_node(node)
    if "type" in opts or "iface" in opts:
        raise ProximoError(
            "opts must not contain reserved keys 'type' or 'iface' — "
            "pass iface_type as its own argument"
        )
    data: dict = {"iface": iface}
    if iface_type is not None:
        data["type"] = _check_iface_type(iface_type)
    data.update(opts)
    return api._post(f"/nodes/{node}/network", data)


def network_iface_update(
    api: PbsBackend,
    iface: str,
    node: str = "localhost",
    iface_type: str | None = None,
    delete_props: list[str] | None = None,
    digest: str | None = None,
    **opts,
) -> object:
    """PUT /nodes/{node}/network/{iface} — update an interface's configuration (staged — not live
    until network_reload). Returns None.

    Unlike PVE (whose update endpoint REQUIRES 'type' and whose own network_iface_update reads the
    current type and injects it as a workaround), PBS's schema marks 'type' optional here too — a
    plain field update needs no current-state read first.
    """
    iface = _check_iface(iface)
    node = _check_pbs_node(node)
    if "type" in opts:
        raise ProximoError("opts must not contain the reserved key 'type' — pass iface_type instead")
    data: dict = {}
    if iface_type is not None:
        data["type"] = _check_iface_type(iface_type)
    data.update(opts)
    if delete_props is not None:
        data["delete"] = _join_delete_props(delete_props)
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/nodes/{node}/network/{iface}", data or None)


def network_iface_delete(api: PbsBackend, iface: str, node: str = "localhost", digest: str | None = None) -> object:
    """DELETE /nodes/{node}/network/{iface} — remove an interface's staged configuration (not live
    until network_reload). Returns None."""
    iface = _check_iface(iface)
    node = _check_pbs_node(node)
    params: dict = {}
    digest = _check_digest(digest)
    if digest is not None:
        params["digest"] = digest
    return api._delete(f"/nodes/{node}/network/{iface}", params=params or None)


def network_reload(api: PbsBackend, node: str = "localhost") -> object:
    """PUT /nodes/{node}/network — "Reload network configuration (requires ifupdown2)": applies
    whatever is staged in interfaces.new, making it live. Returns None.

    *** CONNECTIVITY-LOCKOUT RISK *** — mirrors PVE's own network_apply.
    """
    node = _check_pbs_node(node)
    return api._put(f"/nodes/{node}/network")


def network_revert(api: PbsBackend, node: str = "localhost") -> object:
    """DELETE /nodes/{node}/network — "Revert network configuration changes": discards whatever is
    staged in interfaces.new, WITHOUT touching the live config. Returns None. Safe undo primitive
    for network_iface_create/update/delete, before network_reload is ever called."""
    node = _check_pbs_node(node)
    return api._delete(f"/nodes/{node}/network")


# ---------------------------------------------------------------------------
# Backend functions — Certificates
# ---------------------------------------------------------------------------

def certificates_list(api: PbsBackend, node: str = "localhost") -> list[dict]:
    """GET /nodes/{node}/certificates/info — list TLS certificates configured on the node."""
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/certificates/info") or []


def cert_upload(
    api: PbsBackend,
    certificates: str,
    key: str | None = None,
    node: str = "localhost",
    force: bool = False,
) -> list[dict]:
    """POST /nodes/{node}/certificates/custom — upload a custom TLS certificate (+optional key).

    NOTE: PBS's own schema documents the 'restart' param on this endpoint as "UI compatibility
    parameter, ignored" — deliberately NOT exposed here (see module docstring). Returns a list of
    certificate-info dicts (unlike PVE's dict-shaped return for the analogous call).
    """
    node = _check_pbs_node(node)
    data: dict = {"certificates": certificates}
    if key is not None:
        data["key"] = str(key)
    if force:
        data["force"] = True
    return api._post(f"/nodes/{node}/certificates/custom", data) or []


def cert_delete(api: PbsBackend, node: str = "localhost") -> object:
    """DELETE /nodes/{node}/certificates/custom — remove the custom cert; PBS regenerates a
    self-signed one. NOTE: 'restart' is deliberately not exposed (see module docstring). Returns
    None."""
    node = _check_pbs_node(node)
    return api._delete(f"/nodes/{node}/certificates/custom")


# ---------------------------------------------------------------------------
# Backend functions — Services
# ---------------------------------------------------------------------------

def services_list(api: PbsBackend, node: str = "localhost") -> list[dict]:
    """GET /nodes/{node}/services — list systemd services (desc/name/service/state/unit-state)."""
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/services") or []


def service_status(api: PbsBackend, service: str, node: str = "localhost") -> dict:
    """GET /nodes/{node}/services/{service}/state — read one service's current state.

    Smoke-confirm: PBS's own apidoc documents this GET's return type as `null` — a schema quirk
    (same pattern noted elsewhere in this codebase's PBS coverage, e.g. pbs_access.py's TFA-entry
    GET); treated here as an untyped read, returning whatever the server sends."""
    service = _check_service(service)
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/services/{service}/state") or {}


def service_control(api: PbsBackend, service: str, action: str, node: str = "localhost") -> object:
    """POST /nodes/{node}/services/{service}/{action} — action in {start,stop,restart,reload}.
    Returns None (PBS's schema documents a null return for all four action endpoints — unlike
    PVE, which returns a UPID). Smoke-confirm: whether a live PBS actually returns null
    synchronously or a task UPID for any of the four."""
    service = _check_service(service)
    action = _check_service_action(action)
    node = _check_pbs_node(node)
    return api._post(f"/nodes/{node}/services/{service}/{action}")


# ---------------------------------------------------------------------------
# Backend functions — Subscription
# ---------------------------------------------------------------------------

def subscription_get(api: PbsBackend, node: str = "localhost") -> dict:
    """GET /nodes/{node}/subscription — read subscription status."""
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/subscription") or {}


def subscription_set(api: PbsBackend, key: str, node: str = "localhost") -> object:
    """PUT /nodes/{node}/subscription — install a subscription key and check it. Returns None."""
    node = _check_pbs_node(node)
    return api._put(f"/nodes/{node}/subscription", {"key": key})


def subscription_check(api: PbsBackend, node: str = "localhost", force: bool = False) -> object:
    """POST /nodes/{node}/subscription — "Check and update subscription status": contacts
    Proxmox's server to refresh the cached status. force=True always re-checks even if the cache
    is fresh. Returns None."""
    node = _check_pbs_node(node)
    data = {"force": True} if force else None
    return api._post(f"/nodes/{node}/subscription", data)


def subscription_delete(api: PbsBackend, node: str = "localhost") -> object:
    """DELETE /nodes/{node}/subscription — remove the locally-stored subscription info. Returns
    None. Reversible: re-install the key with subscription_set."""
    node = _check_pbs_node(node)
    return api._delete(f"/nodes/{node}/subscription")


# ---------------------------------------------------------------------------
# Backend functions — Status
# ---------------------------------------------------------------------------

def node_status(api: PbsBackend, node: str = "localhost") -> dict:
    """GET /nodes/{node}/status — node memory/CPU/(root) disk usage. Read-only.

    EXCLUSION: POST /nodes/{node}/status ("Reboot or shutdown the node") exists on the live
    schema but is deliberately not built here — see module docstring."""
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/status") or {}


# ---------------------------------------------------------------------------
# Backend functions — Tasks (list already shipped as pbs_tasks_list; status/log/stop are new)
# ---------------------------------------------------------------------------

def task_status(api: PbsBackend, upid: str, node: str = "localhost") -> dict:
    """GET /nodes/{node}/tasks/{upid}/status — one task's status (status/exitstatus/pid/...).

    Raw UPID in path — colons are pchar-valid (RFC 3986 SS3.3); do NOT url-encode."""
    upid = _check_upid(upid)
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/tasks/{upid}/status") or {}


def task_log(
    api: PbsBackend,
    upid: str,
    node: str = "localhost",
    start: int = 0,
    limit: int = 50,
) -> list[dict]:
    """GET /nodes/{node}/tasks/{upid}/log?start=&limit= — a task's log lines.

    Mirrors PVE's own task_log signature (start/limit) for cross-plane consistency. PBS
    additionally exposes 'download' (whole-file mode, incompatible with other params per its own
    schema) and 'test-status' — neither is exposed here (see module docstring)."""
    upid = _check_upid(upid)
    node = _check_pbs_node(node)
    start = _check_nonneg_int(start, "start")
    limit = _check_nonneg_int(limit, "limit")
    return api._get(f"/nodes/{node}/tasks/{upid}/log", params={"start": start, "limit": limit}) or []


def task_stop(api: PbsBackend, upid: str, node: str = "localhost") -> object:
    """DELETE /nodes/{node}/tasks/{upid} — "Try to stop a task." Returns None (a cancellation
    signal — the task may run briefly before it observes it; mirrors PVE's task_stop contract).

    Raw UPID in path — colons are pchar-valid; do NOT url-encode."""
    upid = _check_upid(upid)
    node = _check_pbs_node(node)
    return api._delete(f"/nodes/{node}/tasks/{upid}")


# ---------------------------------------------------------------------------
# Backend functions — Journal / Syslog
# ---------------------------------------------------------------------------

def journal(
    api: PbsBackend,
    node: str = "localhost",
    lastentries: int | None = None,
    since: int | None = None,
    until: int | None = None,
    startcursor: str | None = None,
    endcursor: str | None = None,
) -> list[str]:
    """GET /nodes/{node}/journal — systemd journal entries. Returns a list of plain journal-line
    STRINGS (PBS's own schema: `returns.items.type == "string"`, identical shape to PVE's
    node_journal). since/until are UNIX epoch integers — and PVE's /journal since/until are ALSO
    integers (verified against the live PVE schema, 2026-07-15), so this is NOT a PBS/PVE
    difference; the free-text date-time-string form is on /syslog (both planes), not /journal.
    startcursor/endcursor are cursor-pagination tokens, mutually exclusive with since/until per the
    schema's own field descriptions (PVE's /journal exposes the same two — not PBS-only; not
    enforced client-side, PBS validates)."""
    node = _check_pbs_node(node)
    params: dict = {}
    if lastentries is not None:
        params["lastentries"] = _check_nonneg_int(lastentries, "lastentries")
    if since is not None:
        params["since"] = int(since)
    if until is not None:
        params["until"] = int(until)
    if startcursor is not None:
        params["startcursor"] = str(startcursor)
    if endcursor is not None:
        params["endcursor"] = str(endcursor)
    return api._get(f"/nodes/{node}/journal", params=params or None) or []


def syslog(
    api: PbsBackend,
    node: str = "localhost",
    limit: int | None = None,
    start: int | None = None,
    since: str | None = None,
    until: str | None = None,
    service: str | None = None,
) -> list[dict]:
    """GET /nodes/{node}/syslog — classic syslog entries. Returns a list of {n, t} dicts (n=line
    number, t=text) — same shape PVE's node_syslog documents. since/until here are free-text
    date-time strings (unlike the /journal endpoint's epoch integers — on both planes). 'service'
    optionally filters to one systemd unit's lines (PVE's /syslog exposes the same param — verified
    against the live PVE schema, 2026-07-15; not PBS-only)."""
    node = _check_pbs_node(node)
    params: dict = {}
    if limit is not None:
        params["limit"] = _check_nonneg_int(limit, "limit")
    if start is not None:
        params["start"] = _check_nonneg_int(start, "start")
    if since is not None:
        params["since"] = str(since)
    if until is not None:
        params["until"] = str(until)
    if service is not None:
        params["service"] = _check_service(service)
    return api._get(f"/nodes/{node}/syslog", params=params or None) or []


# ---------------------------------------------------------------------------
# Plan factories — DNS / Time (CAPTURE-or-declare)
# ---------------------------------------------------------------------------

def plan_dns_set(
    api: PbsBackend,
    node: str = "localhost",
    search: str | None = None,
    dns1: str | None = None,
    dns2: str | None = None,
    dns3: str | None = None,
) -> Plan:
    """Preview updating PBS node DNS config. CAPTURE-or-declare: reads GET /dns first; on failure
    -> complete=False. RISK_MEDIUM (mirrors node_lifecycle.py's plan_node_dns_set)."""
    node = _check_pbs_node(node)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        result = dns_get(api, node)
        current = {k: result[k] for k in ("search", "dns1", "dns2", "dns3") if k in result}
    except Exception:
        complete = False
        note_capture = " Could not capture current DNS config — no guided revert available."

    changes = {k: v for k, v in {"search": search, "dns1": dns1, "dns2": dns2, "dns3": dns3}.items() if v is not None}
    return Plan(
        action="pbs_node_dns_set",
        target=f"pbs/node/{node}/dns",
        change=f"update DNS resolver config on PBS node {node!r}: {changes}",
        current=current,
        blast_radius=[f"node/{node} DNS resolver config — affects name resolution for backup jobs and remote sync"],
        risk=RISK_MEDIUM,
        risk_reasons=["DNS config change takes effect immediately; incorrect config can break name resolution"],
        complete=complete,
        note="Revert by re-applying the captured DNS settings with pbs_node_dns_set." + note_capture,
    )


def plan_time_set(api: PbsBackend, timezone: str, node: str = "localhost") -> Plan:
    """Preview setting PBS node timezone. CAPTURE-or-declare: reads GET /time first. RISK_LOW
    (mirrors node_lifecycle.py's plan_node_time_set)."""
    timezone = _check_timezone(timezone)
    node = _check_pbs_node(node)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        result = time_get(api, node)
        current = {"timezone": result.get("timezone", "unknown")}
    except Exception:
        complete = False
        note_capture = " Could not capture current timezone — no guided revert available."
    return Plan(
        action="pbs_node_time_set",
        target=f"pbs/node/{node}/time",
        change=f"set PBS node timezone to {timezone!r}",
        current=current,
        blast_radius=[f"node/{node} timezone configuration"],
        risk=RISK_LOW,
        risk_reasons=["timezone change takes effect immediately on the node"],
        complete=complete,
        note="Revert by re-applying the captured timezone with pbs_node_time_set." + note_capture,
    )


# ---------------------------------------------------------------------------
# Plan factories — Network
# ---------------------------------------------------------------------------

def plan_network_iface_create(
    api: PbsBackend,
    iface: str,
    node: str = "localhost",
    iface_type: str | None = None,
    opts: dict | None = None,
) -> Plan:
    """Preview creating a PBS network interface. Reads network_list (a safe read) to detect
    collision. RISK_MEDIUM: staged, not live until pbs_node_network_reload."""
    iface = _check_iface(iface)
    node = _check_pbs_node(node)
    if iface_type is not None:
        iface_type = _check_iface_type(iface_type)

    taken = False
    check_error: str | None = None
    try:
        ifaces = network_list(api, node) or []
        taken = any(i.get("name") == iface or i.get("iface") == iface for i in ifaces)
    except Exception as e:
        check_error = type(e).__name__

    if check_error is not None:
        blast = [f"collision check failed ({check_error}) — could not confirm {iface!r} is free"]
        reasons = [f"staged create of interface {iface!r} on {node}", "collision check unavailable"]
    elif taken:
        blast = [f"create will FAIL — interface {iface!r} already exists on {node}"]
        reasons = [f"{iface!r} is already configured on {node}; create will be rejected by PBS"]
    else:
        blast = [
            f"stages new interface {iface!r} on {node} (written to interfaces.new)",
            "change is NOT live until pbs_node_network_reload is run",
        ]
        reasons = [f"staged configuration change: creates interface {iface!r} on {node}",
                   "reversible before reload: pbs_node_network_revert discards it"]

    if opts:
        blast.append("staged fields: " + ", ".join(f"{k}={opts[k]}" for k in sorted(opts)))
    if iface_type:
        blast.append(f"type={iface_type!r}")

    return Plan(
        action="pbs_node_network_iface_create",
        target=f"pbs/node/{node}/network/{iface}",
        change=f"create interface {iface!r} on {node} (staged)",
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=reasons,
        note=("Staged (interfaces.new) — no live effect until pbs_node_network_reload, which carries "
              "RISK_HIGH (connectivity-lockout). Discard the staged change with pbs_node_network_revert."),
    )


def plan_network_iface_update(
    api: PbsBackend,
    iface: str,
    node: str = "localhost",
    iface_type: str | None = None,
    opts: dict | None = None,
) -> Plan:
    """Preview updating a PBS network interface. Reads current config (a safe read). RISK_MEDIUM:
    staged, not live until pbs_node_network_reload."""
    iface = _check_iface(iface)
    node = _check_pbs_node(node)
    if iface_type is not None:
        iface_type = _check_iface_type(iface_type)
    opts = opts or {}

    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = network_iface_get(api, iface, node)
    except Exception:
        complete = False
        note_capture = " Could not read current config for this interface."

    blast = [
        f"updates interface {iface!r} on {node} (staged — written to interfaces.new)",
        "change is NOT live until pbs_node_network_reload is run",
    ]
    if opts:
        blast.append("staged fields: " + ", ".join(f"{k}={opts[k]}" for k in sorted(opts)))
    if iface_type:
        blast.append(f"type={iface_type!r}")

    return Plan(
        action="pbs_node_network_iface_update",
        target=f"pbs/node/{node}/network/{iface}",
        change=f"update interface {iface!r} on {node} (staged)",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[f"staged modification of existing interface {iface!r} on {node}",
                      "reversible before reload: pbs_node_network_revert discards it"],
        complete=complete,
        note=("Staged (interfaces.new) — no live effect until pbs_node_network_reload (RISK_HIGH)." + note_capture),
    )


def plan_network_iface_delete(api: PbsBackend, iface: str, node: str = "localhost") -> Plan:
    """Preview deleting a PBS network interface's staged config. RISK_MEDIUM: staged removal, not
    live until pbs_node_network_reload."""
    iface = _check_iface(iface)
    node = _check_pbs_node(node)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = network_iface_get(api, iface, node)
    except Exception:
        complete = False
        note_capture = " Could not read current config for this interface."
    return Plan(
        action="pbs_node_network_iface_delete",
        target=f"pbs/node/{node}/network/{iface}",
        change=f"remove interface {iface!r} from {node}'s staged config (interfaces.new)",
        current=current,
        blast_radius=[
            f"stages removal of interface {iface!r} on {node} — NOT live until pbs_node_network_reload",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[f"staged removal of interface {iface!r} on {node}",
                      "reversible before reload: pbs_node_network_revert discards the staged removal"],
        complete=complete,
        note=("Staged — no live effect until pbs_node_network_reload (RISK_HIGH)." + note_capture),
    )


def plan_network_reload(node: str = "localhost") -> Plan:
    """Preview applying staged PBS network changes. RISK_HIGH, unconditional — mirrors
    network.py's plan_network_apply: a mis-applied config can lose SSH/API connectivity, requiring
    console/physical recovery. No pre-read of pending state (PBS exposes no diff/pending-preview
    endpoint for /network — unlike PVE's own network read, whose entries can carry a 'pending'
    marker in some versions); the absence of that signal does not make this any less HIGH."""
    node = _check_pbs_node(node)
    return Plan(
        action="pbs_node_network_reload",
        target=f"pbs/node/{node}/network",
        change=f"apply staged network configuration changes on {node} (interfaces.new -> live)",
        current={},
        blast_radius=[
            f"*** CONNECTIVITY-LOCKOUT RISK *** node/{node}: a misconfigured interface can drop "
            "SSH/API access; recovery requires console or physical access",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "applying a misconfigured network interface can lose connectivity to the node; "
            "no automatic undo",
        ],
        note=("RISK_HIGH is unconditional — review staged changes (pbs_node_network_list/"
              "pbs_node_network_iface_get) before reload. To discard staged changes instead, use "
              "pbs_node_network_revert."),
    )


def plan_network_revert(node: str = "localhost") -> Plan:
    """Preview discarding staged PBS network changes. RISK_LOW: this is the safe undo — it never
    touches the live config, only interfaces.new."""
    node = _check_pbs_node(node)
    return Plan(
        action="pbs_node_network_revert",
        target=f"pbs/node/{node}/network",
        change=f"discard staged network configuration changes on {node} (interfaces.new discarded)",
        current={},
        blast_radius=[
            f"node/{node}: any un-applied pbs_node_network_iface_create/update/delete staged "
            "edits are lost",
        ],
        risk=RISK_LOW,
        risk_reasons=["reverts only the STAGED (interfaces.new) file — the live config is untouched"],
        note=(
            "Safe: does not affect live connectivity. Re-stage changes with the iface "
            "create/update/delete tools if needed."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — Certificates
# ---------------------------------------------------------------------------

def plan_cert_upload(certificates: str, node: str = "localhost", force: bool = False) -> Plan:
    """Preview uploading a custom TLS cert to a PBS node. RISK_HIGH, no undo. Key NEVER appears
    here — unconditional redaction (mirrors node_lifecycle.py's plan_node_cert_upload)."""
    node = _check_pbs_node(node)
    cert_preview = certificates[:64] + ("…" if len(certificates) > 64 else "")
    return Plan(
        action="pbs_node_cert_upload",
        target=f"pbs/node/{node}/certificates/custom",
        change=f"upload custom TLS certificate to PBS node {node!r} (cert body: {cert_preview!r})"
               + (" (force=True: overwrite existing)" if force else ""),
        current={},
        blast_radius=["node TLS certificate: a malformed cert/key pair can lock you out of the PBS web UI and API"],
        risk=RISK_HIGH,
        risk_reasons=["a malformed cert/key can lock you out of the PBS web UI + API; no undo — "
                      "re-upload a working cert or use pbs_node_cert_delete to revert to self-signed"],
        note=("No undo: revert by re-uploading a good cert or deleting the custom cert "
              "(pbs_node_cert_delete) to fall back to PBS's self-signed cert. Private key is "
              "unconditionally redacted from the ledger."),
    )


def plan_cert_delete(node: str = "localhost") -> Plan:
    """Preview deleting the custom TLS cert on a PBS node. RISK_MEDIUM: recoverable — PBS reverts
    to self-signed."""
    node = _check_pbs_node(node)
    return Plan(
        action="pbs_node_cert_delete",
        target=f"pbs/node/{node}/certificates/custom",
        change=f"remove the custom TLS certificate on PBS node {node!r}; PBS reverts to self-signed",
        current={},
        blast_radius=[
            "node TLS certificate: removes the custom cert — clients see a TLS warning until a "
            "new cert is uploaded",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "removes the custom TLS certificate — PBS reverts to self-signed; recoverable by re-uploading",
        ],
        note="Recoverable: re-upload a certificate with pbs_node_cert_upload to restore custom TLS.",
    )


# ---------------------------------------------------------------------------
# Plan factories — Services
# ---------------------------------------------------------------------------

def plan_service_control(service: str, action: str, node: str = "localhost") -> Plan:
    """Preview a service control action on a PBS node. PURE — no API call.

    Risk classification mirrors observability.py's plan_node_service_control exactly, adapted for
    PBS's own lockout set: stop/restart/reload of a lockout service -> RISK_HIGH; start of a
    lockout service -> RISK_LOW (additive); stop/restart of a non-lockout service -> RISK_MEDIUM;
    start/reload of a non-lockout service -> RISK_LOW. No automatic undo for any of these.
    """
    service = _check_service(service)
    action = _check_service_action(action)
    node = _check_pbs_node(node)

    is_lockout = _is_lockout_service(service)
    normalized = _normalize_service_name(service)
    no_undo_note = "UNDO is NOT automatic — apply the inverse action manually to revert."

    if is_lockout and action in ("stop", "restart", "reload"):
        risk = RISK_HIGH
        reasons = [
            f"'{service}' is in the PBS management-plane lockout set (normalized: {normalized!r}) — "
            f"{action} can sever SSH access, break backup/restore jobs (proxmox-backup), or break "
            "the web UI/API (proxmox-backup-proxy)",
            "no automatic recovery path exists if management access is lost",
        ]
        blast = [
            f"MANAGEMENT-PLANE RISK: {action} '{service}' on PBS node {node}",
            "CANNOT be automatically undone — apply the inverse action manually",
        ]
    elif is_lockout and action == "start":
        risk = RISK_LOW
        reasons = [f"'start' of '{service}' is additive — does not sever management access"]
        blast = [f"starts service '{service}' on {node}", "additive — does not remove management access"]
    elif action in ("stop", "restart"):
        risk = RISK_MEDIUM
        reasons = [f"'{action}' of '{service}' modifies service state — brief downtime possible for dependents"]
        blast = [f"{action}s service '{service}' on {node}", "brief disruption to dependent processes is possible"]
    else:
        risk = RISK_LOW
        reasons = [f"'{action}' of '{service}' is low-impact"]
        blast = [f"{action}s service '{service}' on {node}"]

    blast.append(no_undo_note)
    return Plan(
        action="pbs_node_service_control",
        target=f"pbs/node/{node}/services/{service}:{action}",
        change=f"{action} service '{service}' on PBS node {node}",
        current={},
        blast_radius=blast,
        risk=risk,
        risk_reasons=reasons,
        note=no_undo_note,
    )


# ---------------------------------------------------------------------------
# Plan factories — Subscription
# ---------------------------------------------------------------------------

def plan_subscription_set(key: str, node: str = "localhost") -> Plan:
    """Preview installing a PBS subscription key. RISK_MEDIUM: changes the node's entitlement
    record (feature gating / support eligibility), reversible via pbs_node_subscription_delete."""
    node = _check_pbs_node(node)
    return Plan(
        action="pbs_node_subscription_set",
        target=f"pbs/node/{node}/subscription",
        change=f"install and validate a subscription key on PBS node {node!r}",
        current={},
        blast_radius=[f"node/{node} subscription record — changes entitlement/support-level state"],
        risk=RISK_MEDIUM,
        risk_reasons=["installs a new subscription key, contacting Proxmox's server to validate it"],
        note="Revert with pbs_node_subscription_delete (removes the record) or install a different key.",
    )


def plan_subscription_check(node: str = "localhost", force: bool = False) -> Plan:
    """Preview refreshing PBS subscription status. RISK_LOW: an online status refresh, no
    identity/key change (mirrors the Wave 1 apt_update_refresh precedent: index/status refresh
    only, still PLAN-gated + audited like every mutation)."""
    node = _check_pbs_node(node)
    return Plan(
        action="pbs_node_subscription_check",
        target=f"pbs/node/{node}/subscription",
        change=f"check and refresh subscription status on PBS node {node!r}" + (" (force=True)" if force else ""),
        current={},
        blast_radius=[f"node/{node} subscription cache — refreshed from Proxmox's server; no key/identity change"],
        risk=RISK_LOW,
        risk_reasons=["refreshes cached subscription status only; no state change to the installed key"],
    )


def plan_subscription_delete(node: str = "localhost") -> Plan:
    """Preview removing PBS subscription info. RISK_MEDIUM: reversible via
    pbs_node_subscription_set (re-install the key)."""
    node = _check_pbs_node(node)
    return Plan(
        action="pbs_node_subscription_delete",
        target=f"pbs/node/{node}/subscription",
        change=f"delete subscription info on PBS node {node!r}",
        current={},
        blast_radius=[
            f"node/{node} subscription record removed — entitlement/support-level state "
            "reverts to unlicensed",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["removes the locally-stored subscription record"],
        note="Reversible: re-install a key with pbs_node_subscription_set.",
    )


# ---------------------------------------------------------------------------
# Plan factories — Tasks
# ---------------------------------------------------------------------------

def plan_task_stop(upid: str, node: str = "localhost") -> Plan:
    """Preview stopping (cancelling) a running PBS task. RISK_HIGH — mirrors PVE's own
    plan_task_stop (tasks_pools.py): stopping a backup/restore/verify/sync/GC task mid-flight can
    leave the target datastore/snapshot in an inconsistent state, with NO undo. (Deliberately
    HIGH, not the MEDIUM a first pass might guess — matching PVE's actual shipped rating for the
    identical operation on the sibling plane.)"""
    upid = _check_upid(upid)
    node = _check_pbs_node(node)
    return Plan(
        action="pbs_node_task_stop",
        target=upid,
        change=f"stop (cancel) task {upid} on PBS node {node!r}",
        current={},
        blast_radius=[
            "stopping a backup/restore/verify/sync/prune/GC task mid-flight can leave the target "
            "datastore or snapshot in an inconsistent or partial state",
            "the task may not stop immediately — PBS sends a cancellation signal, the task observes "
            "it at its next checkpoint",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "interrupting a running task can leave PBS-side state inconsistent; no undo for an "
            "interrupted task",
        ],
        note=(
            "No undo: inspect datastore/snapshot state manually after stopping; re-run the "
            "operation if needed."
        ),
    )
