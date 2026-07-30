"""OBSERVABILITY pillar — node service management + telemetry/diagnostics reads.

Exposes PVE node-scoped service state, journal/syslog, RRD telemetry, DNS config,
subscription info, and certificates as read-only MCP tools.  One mutation:
node_service_control (POST /nodes/{node}/services/{service}/state/{action}) is
PLAN-gated and confirm-gated at the server layer.

Trust thesis:
- Reads are read-only; no confirm required.
- Service control is the highest-stakes operation here: stopping the wrong service
  (pveproxy, pvedaemon, sshd, corosync, networking) can lock out all management
  access or break cluster quorum — the plan makes that explicit BEFORE any action fires.
- A curated LOCKOUT_SERVICES set is checked case-insensitively and tolerant of a
  trailing .service suffix so "sshd.service" and "SSHD" both match.

Endpoint-shape risks flagged with "Smoke-confirm:" where not verified live.
"""

from __future__ import annotations

import re
from urllib.parse import urlencode

from .backends import ProximoError, _check_kind, _check_node, _check_vmid
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Local validators
# ---------------------------------------------------------------------------

# Valid timeframe values for node RRD data.
_VALID_TIMEFRAMES = frozenset({"hour", "day", "week", "month", "year"})

# Valid consolidation function values for node RRD data.
_VALID_CF = frozenset({"AVERAGE", "MAX"})

# Valid actions for node_service_control.
_VALID_SERVICE_ACTIONS = frozenset({"start", "stop", "restart", "reload"})

# Service name: letters, digits, hyphens, underscores, dots — no shell metacharacters.
# Optional trailing ".service" suffix is handled via normalization in _check_service.
# \Z (not $) blocks embedded-newline bypass.
_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

# Maximum journal/syslog entries to request in a single call.
_MAX_LASTENTRIES = 5000

# Services whose stop/restart/reload can sever management access or break cluster quorum.
# Membership is checked after lowercasing and stripping a trailing ".service" suffix.
_LOCKOUT_SERVICES: frozenset[str] = frozenset({
    "networking",
    "pveproxy",
    "pvedaemon",
    "pve-cluster",
    "corosync",
    "sshd",
    "ssh",
    "ifupdown2",
    "pve-firewall",
    "chrony",
})


def _normalize_service_name(service: str) -> str:
    """Lowercase and strip a trailing '.service' suffix for lockout-set membership checks."""
    name = service.lower()
    if name.endswith(".service"):
        name = name[: -len(".service")]
    return name


def _check_service(service: str) -> str:
    """Validate a PVE service name.  Rejects shell metacharacters and embedded newlines.

    Accepts names with an optional trailing '.service' suffix (systemd unit style).
    Returns the validated string as-is (the API accepts either form).

    NOTE: we do NOT strip() here — a leading/trailing space or embedded newline IS
    the attack vector; stripping would swallow it before the regex blocks it.
    The \\Z anchor (not $) prevents newline bypass at the end.
    """
    s = str(service)
    if not _SERVICE_RE.match(s):
        raise ProximoError(
            f"invalid service name: {service!r} "
            "(letters/digits/._/- only, start with alnum, <=64 chars)"
        )
    return s


def _check_timeframe(timeframe: str) -> str:
    tf = str(timeframe).strip()
    if tf not in _VALID_TIMEFRAMES:
        raise ProximoError(
            f"invalid timeframe: {timeframe!r} "
            f"(expected one of {sorted(_VALID_TIMEFRAMES)})"
        )
    return tf


def _check_cf(cf: str) -> str:
    c = str(cf).strip().upper()
    if c not in _VALID_CF:
        raise ProximoError(
            f"invalid consolidation function: {cf!r} "
            f"(expected one of {sorted(_VALID_CF)})"
        )
    return c


def _check_count(value: int | str, field: str) -> int:
    try:
        n = int(value)
    except (ValueError, TypeError) as exc:
        raise ProximoError(
            f"invalid {field}: {value!r} (must be a positive integer)"
        ) from exc
    if n <= 0:
        raise ProximoError(
            f"invalid {field}: {value!r} (must be > 0)"
        )
    if n > _MAX_LASTENTRIES:
        raise ProximoError(
            f"{field} {n} exceeds maximum ({_MAX_LASTENTRIES}); use a smaller window"
        )
    return n


def _check_lastentries(lastentries: int) -> int:
    return _check_count(lastentries, "lastentries")


def _check_service_action(action: str) -> str:
    a = str(action).strip()
    if a not in _VALID_SERVICE_ACTIONS:
        raise ProximoError(
            f"invalid service action: {action!r} "
            f"(expected one of {sorted(_VALID_SERVICE_ACTIONS)})"
        )
    return a


# ---------------------------------------------------------------------------
# READ operations — no confirm, no plan; audited by the server layer
# ---------------------------------------------------------------------------

def node_services_list(api, node: str | None = None) -> list[dict]:
    """List all services on a PVE node.

    GET /nodes/{node}/services
    Returns a list of service dicts — each entry typically contains
    {service, name, state, desc, ...}.

    Smoke-confirm: verify field names (service vs name vs unit) and that 'state'
    is a string like 'running'/'dead'/'inactive' on the live PVE API.
    """
    _check_node(node)
    n = node or api.config.node
    return api._get(f"/nodes/{n}/services") or []


def node_service_status(api, service: str, node: str | None = None) -> dict:
    """Get the current state of a single service on a PVE node.

    GET /nodes/{node}/services/{service}/state
    Returns a dict with service state details.

    Smoke-confirm: verify exact response shape — expected keys include
    {service, name, state, desc, ...} but may vary by PVE version.
    """
    service = _check_service(service)
    _check_node(node)
    n = node or api.config.node
    return api._get(f"/nodes/{n}/services/{service}/state") or {}


def node_rrddata(
    api,
    node: str | None = None,
    timeframe: str = "hour",
    cf: str | None = None,
) -> list[dict]:
    """Get RRD (round-robin database) telemetry for a PVE node.

    GET /nodes/{node}/rrddata?timeframe={tf}[&cf={cf}]

    timeframe: one of 'hour', 'day', 'week', 'month', 'year'.
    cf: optional consolidation function — 'AVERAGE' or 'MAX'.
        If omitted, the PVE default is used.
    Returns a list of time-series data points.

    Smoke-confirm: verify the response shape (list of dicts with time + metric keys);
    verify the 'cf' query param name and accepted values on live PVE.
    """
    _check_node(node)
    timeframe = _check_timeframe(timeframe)
    n = node or api.config.node
    path = f"/nodes/{n}/rrddata?timeframe={timeframe}"
    if cf is not None:
        cf = _check_cf(cf)
        path = f"{path}&cf={cf}"
    return api._get(path) or []


def guest_rrddata(
    api,
    vmid: str,
    kind: str = "lxc",
    node: str | None = None,
    timeframe: str = "hour",
    cf: str | None = None,
) -> list[dict]:
    """Get RRD telemetry for a single guest (VM or container).

    GET /nodes/{node}/{kind}/{vmid}/rrddata?timeframe={tf}[&cf={cf}]

    Same contract as node_rrddata, scoped to one guest: timeframe hour/day/week/month/year,
    optional cf AVERAGE/MAX. Returns time-series points (cpu fraction, mem/maxmem bytes,
    disk/net counters; exact keys vary by PVE version). Feeds the Tier-1 baseline rollups
    (proximo_baseline) — the one place memory-layer code reads PVE, by design.
    """
    vmid, kind = _check_vmid(vmid), _check_kind(kind)
    _check_node(node)
    timeframe = _check_timeframe(timeframe)
    n = node or api.config.node
    path = f"/nodes/{n}/{kind}/{vmid}/rrddata?timeframe={timeframe}"
    if cf is not None:
        cf = _check_cf(cf)
        path = f"{path}&cf={cf}"
    return api._get(path) or []


def node_journal(
    api,
    node: str | None = None,
    lastentries: int = 100,
    since: str | None = None,
    until: str | None = None,
) -> list[str]:
    """Fetch journal entries from a PVE node.

    GET /nodes/{node}/journal[?lastentries=N][&since=TIMESTAMP][&until=TIMESTAMP]

    lastentries: number of recent entries to return (1–5000, default 100).
    since: optional start timestamp (format PVE expects — typically Unix epoch seconds
           or ISO 8601; Smoke-confirm exact format accepted by live PVE).
    until: optional end timestamp (same format).

    Returns a list of journal-line STRINGS (VERIFIED live against PVE 9.1.7, 2026-06-08:
    the endpoint returns a JSON array of plain strings — the first element is a journal
    cursor token, the rest are formatted log lines — NOT a list of dicts).

    Smoke-confirm: verify the accepted timestamp format for since/until and the query
    param names against the target PVE version.
    """
    _check_node(node)
    lastentries = _check_lastentries(lastentries)
    n = node or api.config.node
    # Build the query with urlencode so a value cannot smuggle extra params: a `since`
    # like "X&lastentries=99999" becomes "since=X%26lastentries%3D99999", not a second
    # parameter. (Free-text since/until are the injection vector — lastentries is an int.)
    query: dict[str, str] = {"lastentries": str(lastentries)}
    if since is not None:
        query["since"] = str(since)
    if until is not None:
        query["until"] = str(until)
    path = f"/nodes/{n}/journal?" + urlencode(query)
    return api._get(path) or []


def node_syslog(api, node: str | None = None, limit: int = 100) -> list[dict]:
    """Fetch syslog entries from a PVE node.

    GET /nodes/{node}/syslog[?limit=N]

    Note: on modern PVE (≥7), syslog may be superseded by the journal endpoint.
    This endpoint may return an empty list or an error on systemd-only systems.

    Smoke-confirm: verify availability on the target PVE version; verify the response
    shape (list of {n, t} dicts where n=line-number, t=text, per PVE API viewer).
    """
    _check_node(node)
    n_entries = _check_count(limit, "limit")
    n = node or api.config.node
    return api._get(f"/nodes/{n}/syslog?limit={n_entries}") or []


def node_dns_get(api, node: str | None = None) -> dict:
    """Get the DNS configuration of a PVE node.

    GET /nodes/{node}/dns
    Returns a dict with the node's DNS settings.

    Smoke-confirm: verify response keys — expected {search, dns1, dns2, dns3}
    but field names may vary across PVE versions.
    """
    _check_node(node)
    n = node or api.config.node
    return api._get(f"/nodes/{n}/dns") or {}


def node_subscription(api, node: str | None = None) -> dict:
    """Get the subscription status of a PVE node.

    GET /nodes/{node}/subscription
    Returns a dict with subscription details.

    Smoke-confirm: verify response shape — expected fields include
    {status, productname, checktime, nextduedate, level, ...}.
    """
    _check_node(node)
    n = node or api.config.node
    return api._get(f"/nodes/{n}/subscription") or {}


def node_certificates_info(api, node: str | None = None) -> list[dict]:
    """List TLS certificates configured on a PVE node.

    GET /nodes/{node}/certificates/info
    Returns a list of certificate info dicts.

    Smoke-confirm: verify response shape — expected fields include
    {filename, subject, issuer, notbefore, notafter, san, fingerprint, pem, ...}
    but field names may differ by PVE version.
    """
    _check_node(node)
    n = node or api.config.node
    return api._get(f"/nodes/{n}/certificates/info") or []


# ---------------------------------------------------------------------------
# MUTATION operations — confirm-gated + plan-first at the server layer
# ---------------------------------------------------------------------------

def node_service_control(
    api,
    service: str,
    action: str,
    node: str | None = None,
) -> str | None:
    """Start, stop, restart, or reload a service on a PVE node.

    POST /nodes/{node}/services/{service}/{action}

    action: one of 'start', 'stop', 'restart', 'reload'.
    Returns a UPID string (async PVE task) — poll task_status to confirm completion.

    MUTATION — confirm-gated + audited at the server layer.

    Schema-verified 2026-07-06 (pve-docs api-viewer): the mutation endpoints are
    /nodes/{node}/services/{service}/{start|stop|restart|reload}; /state is the
    GET-only status endpoint (the earlier /state/{action} guess was wrong).
    Smoke-confirm: UPID returned (vs None) per action; 'reload' availability per service.
    """
    service = _check_service(service)
    action = _check_service_action(action)
    _check_node(node)
    n = node or api.config.node
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/nodes/{n}/services/{service}/{action}")


# ---------------------------------------------------------------------------
# PLAN functions — pure factories; no mutation; the PLAN pillar
# ---------------------------------------------------------------------------

def _is_lockout_service(service: str) -> bool:
    """Return True if 'service' matches a lockout service, case-insensitive.

    Tolerant of a trailing '.service' suffix — 'sshd.service' and 'SSHD' both match.
    """
    return _normalize_service_name(service) in _LOCKOUT_SERVICES


def plan_node_service_control(
    service: str,
    action: str,
    node: str | None = None,
) -> Plan:
    """Preview a service control action on a PVE node.  PURE — no API call.

    Risk classification:
    - 'stop'/'restart'/'reload' of a LOCKOUT service → RISK_HIGH:
        The full lockout set is networking, pveproxy, pvedaemon, pve-cluster, corosync,
        sshd, ssh, ifupdown2, pve-firewall, and chrony.  Stopping or restarting any of
        them can sever the management plane, lock you out of SSH, or break cluster quorum.
        ('start' of a lockout service is additive → RISK_LOW.)
    - 'stop'/'restart' of a non-lockout service → RISK_MEDIUM.
    - 'start'/'reload' of a non-lockout service → RISK_LOW.

    UNDO: there is no automatic undo for a service control action — no snapshot
    equivalent applies here.  The inverse action (start after stop, etc.) must be
    applied manually.  This is stated explicitly in the blast radius.
    """
    service = _check_service(service)
    action = _check_service_action(action)
    _check_node(node)

    node_label = node or "<default>"
    is_lockout = _is_lockout_service(service)
    normalized = _normalize_service_name(service)

    no_undo_note = (
        "UNDO is NOT automatic — there is no snapshot equivalent for service control. "
        "To revert, apply the inverse action manually."
    )

    if is_lockout and action in ("stop", "restart", "reload"):
        risk = RISK_HIGH
        risk_reasons = [
            f"'{service}' is in the management-plane lockout set "
            f"(normalized: '{normalized}') — {action} can sever SSH access, "
            "break the PVE web UI (pveproxy/pvedaemon), break cluster quorum "
            "(corosync/pve-cluster), or drop all network connectivity (networking/ifupdown2)",
            "no automatic recovery path exists if management access is lost",
        ]
        blast = [
            f"MANAGEMENT-PLANE RISK: {action} '{service}' on node {node_label}",
            f"'{service}' controls {_lockout_description(normalized)} — "
            f"{action} may lock you out of PVE or break cluster quorum",
            "CANNOT be automatically undone — apply the inverse action manually",
        ]
    elif is_lockout and action == "start":
        # 'start' of a lockout service is additive — the service may already be running,
        # but starting it does not remove access.
        risk = RISK_LOW
        risk_reasons = [
            f"'start' of '{service}' is additive — brings the service up; "
            "does not sever management access",
        ]
        blast = [
            f"starts service '{service}' on node {node_label}",
            "additive action — does not remove management access",
            "CANNOT be automatically undone — apply the inverse action (stop) manually",
        ]
    elif action in ("stop", "restart"):
        risk = RISK_MEDIUM
        risk_reasons = [
            f"'{action}' of '{service}' modifies service state — brief downtime possible "
            "for anything depending on this service",
        ]
        blast = [
            f"{action}s service '{service}' on node {node_label}",
            "brief disruption to dependent processes is possible",
            "CANNOT be automatically undone — apply the inverse action manually",
        ]
    else:
        # start or reload of a non-lockout service
        risk = RISK_LOW
        risk_reasons = [
            f"'{action}' of '{service}' is low-impact — "
            + ("additive (start)" if action == "start" else "reload signals the service to re-read its config"),
        ]
        blast = [
            f"{action}s service '{service}' on node {node_label}",
            "CANNOT be automatically undone — apply the inverse action manually",
        ]

    return Plan(
        action="pve_node_service_control",
        target=f"{node_label}/{service}:{action}",
        change=f"{action} service '{service}' on node {node_label}",
        current={},
        blast_radius=blast,
        risk=risk,
        risk_reasons=risk_reasons,
        note=no_undo_note,
    )


def _lockout_description(normalized: str) -> str:
    """Return a short human description of why a lockout service is critical."""
    _descriptions: dict[str, str] = {
        "networking": "host network interfaces (losing it drops all connectivity)",
        "pveproxy": "PVE web API/UI proxy (losing it drops management web access)",
        "pvedaemon": "core PVE daemon (losing it breaks all API operations)",
        "pve-cluster": "PVE cluster filesystem (losing it isolates the node from the cluster)",
        "corosync": "cluster corosync messaging (losing it breaks quorum)",
        "sshd": "SSH daemon (losing it locks out shell access)",
        "ssh": "SSH daemon (losing it locks out shell access)",
        "ifupdown2": "network interface management (losing it can drop all connectivity)",
        "pve-firewall": "PVE firewall rule enforcement (reload/restart changes active rules)",
        "chrony": "NTP time synchronization (stopping it causes clock drift)",
    }
    return _descriptions.get(normalized, "a critical system service")
