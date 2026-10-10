"""CLUSTER / HA / MIGRATION pillar — cluster-wide reads, HA resource management, guest migration.

Trust thesis shines brightest here: migration + HA changes are high-stakes — the PLAN
pillar makes the blast radius explicit before any mutation fires.

Key structural notes vs the node-scoped modules (storage, backup, provisioning):
- Cluster-level reads (/cluster/...) are NOT node-scoped — no /nodes/{node} prefix.
- Only guest_migrate is node-scoped: POST /nodes/{node}/{kind}/{vmid}/migrate.
- HA SIDs are prefixed "vm:" (qemu) or "ct:" (lxc) — NOT "qemu:" or "lxc:".
- Migration is ASYNC (returns UPID); HA add/remove are SYNCHRONOUS pmxcfs config writes
  whose effect is carried out asynchronously by the cluster CRM. Don't validate HA return
  as a UPID; outcome="ok" is honest there. Confirm at live smoke.
- LXC has NO live migration (no zero-downtime path). online=True for LXC sends restart=1,
  which is a stop→move→start cycle — real downtime. RISK_HIGH for any migrate where
  downtime is possible (offline always; online LXC always; online QEMU = MEDIUM because
  it is designed for live transfer, but can still fail without shared storage).

Endpoint-shape risks flagged throughout with "Smoke-confirm:" comments.
"""

from __future__ import annotations

import re

import httpx

from .backends import ProximoError, _check_kind, _check_node, _check_vmid, guest_absent
from .planning import RISK_HIGH, RISK_MEDIUM, RISK_NONE, Plan, _max_risk

# HA rule comments are stored in pmxcfs line-based config — a control char/newline can corrupt it,
# the SAME threat class the access modules guard (deliberate per-module duplication). 2026-07-10 L9.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _check_freetext(value: str, field: str) -> str:
    """Reject control characters/newlines in an HA freetext field (raw value, no strip)."""
    s = str(value)
    if _CONTROL_RE.search(s):
        raise ProximoError(
            f"invalid {field}: {value!r} — control characters and newlines are not allowed"
        )
    return s

# ---------------------------------------------------------------------------
# Local validators
# ---------------------------------------------------------------------------

# HA SID prefix by PVE kind-name
_HA_SID_PREFIX: dict[str, str] = {"qemu": "vm", "lxc": "ct"}

# Valid resource_type values for GET /cluster/resources?type=
_VALID_RESOURCE_TYPES = frozenset({"vm", "storage", "node", "sdn"})

# Valid initial HA resource states (passed as 'state' to ha_resource_add)
_VALID_HA_STATES = frozenset({"started", "stopped", "enabled", "disabled", "ignored"})

# HA group name: letters/digits/underscores/hyphens, must start with letter or digit.
# Colon is explicitly excluded — a colon in a group name would break SID parsing.
# \Z (not $) blocks embedded-newline bypass.
_HA_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,39}\Z")

# HA SID: "vm:100" or "ct:200" — validated explicitly by _build_sid; stored here for direct-sid checks.
_HA_SID_RE = re.compile(r"^(?:vm|ct):[0-9]+\Z")


def _check_ha_group(group: str) -> str:
    g = str(group).strip()
    if not _HA_GROUP_RE.match(g):
        raise ProximoError(
            f"invalid HA group name: {group!r} (letters/digits/_/- only, start with alnum, <=40)"
        )
    return g


def _build_sid(vmid: str, kind: str) -> str:
    """Construct the HA SID from a validated vmid + kind ('vm:100' or 'ct:200').

    PVE HA resource IDs use 'vm:' for QEMU and 'ct:' for LXC, NOT 'qemu:'/'lxc:'.
    Smoke-confirm: verify this prefix mapping on a live PVE during the first HA smoke test.
    """
    prefix = _HA_SID_PREFIX.get(kind)
    if prefix is None:
        # Should be unreachable after _check_kind, but be defensive.
        raise ProximoError(f"unsupported kind for HA SID: {kind!r}")
    return f"{prefix}:{vmid}"


def _check_target_node(target: str) -> str:
    """Target node name for migration — same rules as _check_node but required (never None)."""
    t = str(target).strip()
    if not t:
        raise ProximoError("target node must not be empty")
    # Delegate to _check_node's regex by passing as a non-None value.
    _check_node(t)
    return t


# ---------------------------------------------------------------------------
# READ operations — no confirm, no plan; audited by the server layer
# ---------------------------------------------------------------------------

def cluster_status(api) -> list[dict]:
    """Get overall cluster status (nodes, quorum, version).

    GET /cluster/status
    Returns a list of status records from PVE.

    Smoke-confirm: verify the response shape: list of {name, type, id, nodeid, ip, online,
    level, local, votes} dicts — field names confirmed against PVE API viewer.
    """
    return api._get("/cluster/status") or []


def cluster_resources(api, resource_type: str | None = None) -> list[dict]:
    """List all resources across the cluster (VMs, nodes, storage, SDN).

    GET /cluster/resources[?type=vm|storage|node|sdn]

    resource_type: optional filter — one of 'vm', 'storage', 'node', 'sdn'.
    Returns a list of resource dicts from PVE.

    Smoke-confirm: verify the ?type= query values against a live PVE. The frozenset here
    matches the documented PVE API viewer values; the actual accepted set may differ.
    """
    if resource_type is not None:
        if resource_type not in _VALID_RESOURCE_TYPES:
            raise ProximoError(
                f"invalid resource_type: {resource_type!r} "
                f"(expected one of {sorted(_VALID_RESOURCE_TYPES)})"
            )
        return api._get(f"/cluster/resources?type={resource_type}") or []
    return api._get("/cluster/resources") or []


def _is_ha_groups_migrated(exc: httpx.HTTPStatusError) -> bool:
    """True if this is PVE 9's 'HA groups removed → use rules' 500.

    PVE 9 returns HTTP 500 with reason 'cannot index groups: ha groups have been migrated
    to rules'. We match on status 500 + the 'migrated to rules' marker across reason_phrase,
    body text, and the exception string (REST-confirmed against PVE 9.1.7, 2026-06-08) — a
    transient/unrelated 500 is NOT swallowed (it re-raises).
    """
    resp = getattr(exc, "response", None)
    if resp is None or getattr(resp, "status_code", None) != 500:
        return False
    parts = [str(getattr(resp, "reason_phrase", "") or ""), str(exc)]
    body = getattr(resp, "text", None)
    if isinstance(body, str):  # best-effort: include the response body when available
        parts.append(body)
    return "migrated to rules" in " ".join(parts).lower()


def ha_groups_list(api) -> list[dict]:
    """List all HA resource groups.

    GET /cluster/ha/groups
    Returns a list of group config dicts from PVE.

    PVE-version note: PVE 9 REMOVED HA groups (migrated to HA *rules*) — the API returns
    HTTP 500 'ha groups have been migrated to rules'. That is translated here into a clear
    ProximoError pointing at ha_rules_list (pve_ha_rules_list), rather than surfacing a raw
    500. On PVE 8 it returns the group config list as before. REST-confirmed (PVE 9.1.7).

    Smoke-confirm (PVE 8): verify returned fields — expected {group, nodes, restricted,
    nofailback, comment} but field names may vary across PVE versions.
    """
    try:
        return api._get("/cluster/ha/groups") or []
    except httpx.HTTPStatusError as exc:
        if _is_ha_groups_migrated(exc):
            raise ProximoError(
                "HA groups were removed in PVE 9 (migrated to HA rules). "
                "Use ha_rules_list (pve_ha_rules_list) instead."
            ) from exc
        raise


def ha_rules_list(api) -> list[dict]:
    """List HA rules — the PVE 9 replacement for HA groups.

    GET /cluster/ha/rules
    Returns a list of HA rule dicts (e.g. node-affinity rules); empty list when none.
    REST-confirmed present against PVE 9.1.7 (2026-06-08).
    """
    return api._get("/cluster/ha/rules") or []


def ha_resources_list(api) -> list[dict]:
    """List all HA resources (managed guests).

    GET /cluster/ha/resources
    Returns a list of HA resource dicts from PVE.

    Smoke-confirm: verify returned fields — expected {sid, type, state, group, max_restart,
    max_relocate, ...} but field names vary by PVE version.
    """
    return api._get("/cluster/ha/resources") or []


# ---------------------------------------------------------------------------
# MUTATION operations — each is confirm-gated + plan-first at the server layer
# ---------------------------------------------------------------------------

def guest_migrate(
    api,
    vmid: str,
    target: str,
    kind: str = "lxc",
    node: str | None = None,
    online: bool = False,
) -> str:
    """Migrate a guest to a different node.

    POST /nodes/{node}/{kind}/{vmid}/migrate  →  UPID (async PVE task)

    node: source node (defaults to api.config.node).
    target: destination node (required, non-empty).
    online:
      - QEMU: online=True sends 'online=1' (live migration, zero-downtime path; requires shared storage).
      - LXC: 'live migration' doesn't exist — online=True sends 'restart=1' (stop→move→start cycle;
        this is still real downtime). See plan_migrate for honest blast radius per kind.
      - online=False (default): offline migration (guest must be stopped OR restart accepted).

    Returns a UPID string. Migration is ASYNC — outcome="submitted" in the ledger; poll task_status
    to confirm completion.

    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: verify the exact param name for LXC restart migration ('restart' vs 'online');
    verify QEMU live migration param name ('online'); verify UPID is always returned vs None for
    same-node noop; verify 'with-local-disks' param is available for offline QEMU migration.
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)
    target = _check_target_node(target)
    n = node or api.config.node

    data: dict = {"target": target}
    if online:
        if kind == "qemu":
            # QEMU live migration: 'online=1'
            # Smoke-confirm: verify this param name against PVE API viewer.
            data["online"] = 1
        else:
            # LXC "restart" migration: stop-on-source, start-on-target — NOT zero-downtime.
            # Smoke-confirm: verify 'restart' is the correct param name for LXC.
            data["restart"] = 1

    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/nodes/{n}/{kind}/{vmid}/migrate", data)


def ha_resource_add(
    api,
    vmid: str,
    kind: str = "lxc",
    group: str | None = None,
    state: str | None = None,
    max_restart: int | None = None,
    max_relocate: int | None = None,
) -> object:
    """Add a guest to HA management.

    POST /cluster/ha/resources
    Body: {sid, group?, state?, max_restart?, max_relocate?}

    sid is constructed from kind + vmid: 'vm:100' (qemu) or 'ct:100' (lxc).

    PVE-version note: the 'group' param is PVE-8-only — PVE 9 removed HA groups (migrated to
    HA rules). On PVE 9, omit 'group'; node affinity is expressed via HA rules instead.

    Returns the PVE response (typically None — this is a SYNCHRONOUS pmxcfs config write,
    NOT an async task; do NOT validate the return as a UPID). The CRM then carries out the
    desired state asynchronously.

    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: verify body param names ('sid', 'group', 'state', 'max_restart',
    'max_relocate'); verify the endpoint returns null (no UPID) on success; verify whether
    'sid' is a required param vs 'type'+'id' decomposed; verify whether 'group' is required
    or optional (HA config may default to no group = any node).
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    if group is not None:
        group = _check_ha_group(group)
    if state is not None and state not in _VALID_HA_STATES:
        raise ProximoError(
            f"invalid HA state: {state!r} (expected one of {sorted(_VALID_HA_STATES)})"
        )

    sid = _build_sid(vmid, kind)
    data: dict = {"sid": sid}
    if group is not None:
        data["group"] = group
    if state is not None:
        data["state"] = state
    if max_restart is not None:
        try:
            data["max_restart"] = int(max_restart)
        except (ValueError, TypeError) as exc:
            raise ProximoError(
                f"invalid max_restart: {max_restart!r} (must be an integer)"
            ) from exc
    if max_relocate is not None:
        try:
            data["max_relocate"] = int(max_relocate)
        except (ValueError, TypeError) as exc:
            raise ProximoError(
                f"invalid max_relocate: {max_relocate!r} (must be an integer)"
            ) from exc

    # MUTATION — confirm-gated + audited at the server layer.
    return api._post("/cluster/ha/resources", data)


def ha_resource_remove(api, vmid: str, kind: str = "lxc") -> object:
    """Remove a guest from HA management.

    DELETE /cluster/ha/resources/{sid}
    sid: 'vm:100' (qemu) or 'ct:100' (lxc)

    Returns the PVE response (typically None — synchronous pmxcfs config write, not a UPID).

    MUTATION — confirm-gated + audited at the server layer.

    Smoke-confirm: verify DELETE /cluster/ha/resources/{sid} with the raw colon (e.g. 'vm:100')
    in the path — colon is a valid pchar in RFC 3986 and PVE's routing handles it unencoded,
    but confirm on a live instance that URL-encoding ('vm%3A100') is NOT required and does not
    break the match.
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    sid = _build_sid(vmid, kind)
    # Raw SID in path — colon is pchar-valid; do NOT quote() here.
    # MUTATION — confirm-gated + audited at the server layer.
    return api._delete(f"/cluster/ha/resources/{sid}")


# ---------------------------------------------------------------------------
# PLAN functions — pure factories; no mutation; the PLAN pillar
# ---------------------------------------------------------------------------

def plan_migrate(
    api,
    vmid: str,
    target: str,
    kind: str = "lxc",
    node: str | None = None,
    online: bool = False,
) -> Plan:
    """Preview migrating a guest to another node.

    Reads guest_status (a safe read) to show live state (running/stopped, name, uptime).
    If the status read fails, uncertainty is disclosed — not smoothed over.

    Risk:
    - QEMU + online=True  → RISK_MEDIUM: live migration is designed to be near-seamless,
      but still requires shared storage and can fail (failover ≠ zero-risk).
    - All other paths     → RISK_HIGH: guest downtime is possible or certain.
      * Offline migration (online=False, any kind): guest must be stopped / brief downtime.
      * LXC + online=True ('restart' migration): stop → move → start = confirmed downtime.

    UNDO: migration cannot be undone automatically — there is no disk snapshot equivalent.
    To revert, migrate back manually. This is stated in the blast radius — NEVER claim undo.
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)
    target = _check_target_node(target)
    n = node or api.config.node

    current: dict = {}
    check_failed = False
    try:
        gs = api.guest_status(vmid, kind, node)
        current = {k: gs[k] for k in ("status", "name", "uptime") if k in gs}
    except Exception as e:
        if guest_absent(e, api=api, vmid=vmid, kind=kind):  # 404, or 500 "not on this node" + empty cluster roster
            # Confirmed not found — the migrate will fail. Still flag accurately.
            current = {}
        else:
            check_failed = True

    name = current.get("name", "unknown")
    status = current.get("status", "unknown")

    if check_failed:
        # Cannot confirm guest state — disclose uncertainty; do not imply safety.
        blast = [
            f"could NOT confirm state of {kind}/{vmid} — if it exists, this migrates it "
            f"from {n} to {target!r}; downtime risk depends on guest state and kind",
        ]
        reasons = [
            f"status check for {kind}/{vmid} failed — migrate may succeed or fail depending on live state",
            "RISK_HIGH maintained: uncertainty is not a safety signal",
        ]
        risk = RISK_HIGH
    elif not current:
        # Status read gave 404 — guest not found; migrate will fail.
        blast = [f"migrate will FAIL — {kind}/{vmid} not found on {n}; nothing would move"]
        reasons = [f"{kind}/{vmid} not found — migrate will be rejected by PVE"]
        risk = RISK_HIGH
    elif online and kind == "qemu":
        # QEMU live migration: designed for near-zero downtime, but NOT a guarantee.
        blast = [
            f"LIVE-migrates {kind}/{vmid} (name={name!r}, {status}) from {n} to {target!r}",
            "near-seamless for running guests — requires shared storage; can still fail mid-transfer",
            "CANNOT be automatically undone — to revert, migrate back manually",
        ]
        reasons = [
            "QEMU live migration: designed for zero-downtime but requires shared storage",
            "a failed mid-transfer live migration may leave the guest in an inconsistent state",
        ]
        risk = RISK_MEDIUM
    elif online and kind == "lxc":
        # LXC 'restart' migration — stop-on-source, move, start-on-target = real downtime.
        blast = [
            f"RESTART-migrates {kind}/{vmid} (name={name!r}, {status}) from {n} to {target!r}",
            "LXC does NOT support live migration — 'online' means stop→move→start (REAL DOWNTIME)",
            "CANNOT be automatically undone — to revert, migrate back manually",
        ]
        reasons = [
            "LXC restart migration: stop-on-source, move, start-on-target — confirmed downtime",
            "the guest will be briefly offline during the migration",
        ]
        risk = RISK_HIGH
    else:
        # Offline migration — guest must be stopped (or PVE will reject).
        blast = [
            f"offline-migrates {kind}/{vmid} (name={name!r}, currently {status}) from {n} to {target!r}",
            "offline migration: guest must be stopped; brief storage transfer downtime",
            "CANNOT be automatically undone — to revert, migrate back manually",
        ]
        reasons = [
            "offline migration: guest must be stopped for the transfer",
            "downtime proportional to disk size and network bandwidth",
        ]
        risk = RISK_HIGH

    # Disk-residency blast: only when the guest is confirmed to exist (the check_failed / not-found
    # paths above already say "state unknown" / "will FAIL"). Names the disks whose storage is local
    # or not available on the target — the migration would copy them (with-local-disks) or fail.
    # Lazy import: cluster_ops is imported BY blast, so a top-level import would be circular.
    affected: list[dict] = []
    complete = True
    if current:
        from .blast import migrate_blast
        mb = migrate_blast(api, vmid, kind, node, target, online)
        blast.extend(mb.summary_lines)
        affected = mb.affected
        complete = mb.complete
        risk = _max_risk(risk, RISK_HIGH if mb.max_severity == "high" else RISK_NONE)

    return Plan(
        action="pve_guest_migrate",
        target=f"{kind}/{vmid}->{target}",
        change=f"migrate {kind} {vmid} from {n} to {target} (online={online})",
        current=current,
        blast_radius=blast,
        risk=risk,
        risk_reasons=reasons,
        affected=affected,
        complete=complete,
        note=(
            "Migration is async — outcome='submitted'; poll task_status for completion. "
            "UNDO is NOT available for migration — no disk snapshot applies across nodes."
        ),
    )


def plan_ha_resource_add(
    vmid: str,
    kind: str = "lxc",
    group: str | None = None,
    state: str | None = None,
    max_restart: int | None = None,
    max_relocate: int | None = None,
) -> Plan:
    """Preview adding a guest to HA management.  PURE — no API call needed.

    Risk:
    - state='stopped' → RISK_HIGH: the CRM will stop the guest to enforce the desired state
      (confirmed downtime).
    - All other states / no state → RISK_MEDIUM: adds HA protection; no immediate guest
      action expected unless the CRM detects a failover condition.

    UNDO: remove the HA resource via ha_resource_remove (documented in blast radius).
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    if group is not None:
        group = _check_ha_group(group)
    if state is not None and state not in _VALID_HA_STATES:
        raise ProximoError(
            f"invalid HA state: {state!r} (expected one of {sorted(_VALID_HA_STATES)})"
        )

    sid = _build_sid(vmid, kind)
    group_note = f" in group '{group}'" if group else " (no group; CRM picks any eligible node)"
    state_note = f"initial state: {state!r}" if state else "initial state: default (PVE chooses)"

    if state == "stopped":
        # CRM will stop the guest to enforce state — confirmed downtime.
        risk = RISK_HIGH
        reasons = [
            f"state='stopped' instructs the CRM to STOP {kind}/{vmid} — confirmed downtime",
            "the CRM enforces the desired state immediately after HA registration",
        ]
        blast = [
            f"adds {kind}/{vmid} (SID={sid}) to HA management{group_note} — {state_note}",
            f"CRM will STOP {kind}/{vmid} to enforce state='stopped' — guest goes offline",
            "to undo: remove from HA via ha_resource_remove; guest will NOT be auto-restarted",
        ]
    else:
        risk = RISK_MEDIUM
        reasons = [
            f"adds {kind}/{vmid} to HA; no immediate stop/failover expected for state={(state or 'default')!r}",
            "the CRM may start the guest if state='started' and it is currently down",
        ]
        blast = [
            f"adds {kind}/{vmid} (SID={sid}) to HA management{group_note} — {state_note}",
            "HA management enables automatic failover on node failure",
            "to undo: remove from HA via ha_resource_remove",
        ]

    if max_restart is not None:
        warn = " — CRM will NOT auto-restart this guest on failure" if max_restart == 0 else ""
        blast = blast + [f"max_restart={max_restart}{warn}"]
    if max_relocate is not None:
        warn = " — CRM will NOT relocate this guest to another node on failure" if max_relocate == 0 else ""
        blast = blast + [f"max_relocate={max_relocate}{warn}"]
    return Plan(
        action="pve_ha_resource_add",
        target=sid,
        change=f"add {kind}/{vmid} (SID={sid}) to HA" + (f" group={group}" if group else "")
               + (f" state={state}" if state else "")
               + (f" max_restart={max_restart}" if max_restart is not None else "")
               + (f" max_relocate={max_relocate}" if max_relocate is not None else ""),
        current={},
        blast_radius=blast,
        risk=risk,
        risk_reasons=reasons,
        note=(
            "HA add is a synchronous pmxcfs config write — no UPID returned. "
            "The CRM enforces the desired state asynchronously. "
            "Smoke-confirm: verify return is null (not UPID) on live PVE."
        ),
    )


def plan_ha_resource_remove(vmid: str, kind: str = "lxc") -> Plan:
    """Preview removing a guest from HA management.  PURE — no API call needed.

    RISK_MEDIUM: removes automated failover protection; the guest itself is NOT stopped or
    touched. The blast radius is the LOSS of HA protection (reversible; re-add via ha_resource_add).
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    sid = _build_sid(vmid, kind)

    return Plan(
        action="pve_ha_resource_remove",
        target=sid,
        change=f"remove {kind}/{vmid} (SID={sid}) from HA management",
        current={},
        blast_radius=[
            f"removes {kind}/{vmid} (SID={sid}) from HA — automated failover protection is lost",
            "the guest itself is NOT stopped or affected; only the HA CRM stops managing it",
            "to re-add protection: ha_resource_add",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "removes failover protection — if the host node fails, this guest will NOT be automatically restarted",
            "no data loss or downtime on this guest directly; protection is removed, not enforced",
        ],
        note=(
            "HA remove is a synchronous pmxcfs config write — no UPID returned. "
            "Smoke-confirm: verify return is null on live PVE; verify the raw colon in "
            "DELETE /cluster/ha/resources/vm:100 (or ct:100) is not URL-encoded."
        ),
    )


# ===========================================================================
# HA RULES — the PVE 9 replacement for HA groups (node-affinity / resource-affinity)
# ---------------------------------------------------------------------------
# Grounded against live PVE 9.1.7 schema (2026-06-14):
#   POST   /cluster/ha/rules          {rule, type, resources, comment?, disable?}
#     [type=node-affinity]      + {nodes: <node>[:<pri>],..., strict?}
#     [type=resource-affinity]  + {affinity: positive|negative}
#   PUT    /cluster/ha/rules/{rule}    {comment?, disable?, resources?, type?, nodes?, strict?,
#                                       affinity?, delete?: csv, digest?}
#   DELETE /cluster/ha/rules/{rule}    (no params)
#
# HA *groups* CRUD is intentionally NOT built: on PVE 9 the groups endpoints 500 at runtime
# ("ha groups have been migrated to rules"), so group-CRUD tools would be dead on modern PVE
# and un-live-provable. ha_groups_list already translates that 500 into a clear pointer here.
#
# Rules are config-file state (pmxcfs) — SYNCHRONOUS writes, no UPID, NO snapshot UNDO; revert
# is the inverse op. A rule is inert until its `resources` are HA-managed; once they are, it
# constrains CRM placement (RISK_MEDIUM — may trigger migration; strict node-affinity can strand
# a guest if all its nodes are down).
# ===========================================================================

_VALID_RULE_TYPES = frozenset({"node-affinity", "resource-affinity"})
_VALID_AFFINITY = frozenset({"positive", "negative"})
_HA_RULE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,39}\Z")


def _check_ha_rule(rule: str) -> str:
    r = str(rule).strip()
    if not _HA_RULE_RE.match(r):
        raise ProximoError(
            f"invalid HA rule name: {rule!r} (letters/digits/_/- only, start with alnum, <=40)"
        )
    return r


def _check_rule_type(rule_type: str) -> str:
    t = str(rule_type).strip()
    if t not in _VALID_RULE_TYPES:
        raise ProximoError(
            f"invalid HA rule type: {rule_type!r} (expected one of {sorted(_VALID_RULE_TYPES)})"
        )
    return t


def _check_ha_resources(resources: str) -> str:
    """Validate the HA resources list 'vm:100,ct:101' — each token must be a valid HA SID.

    Reject bad prefixes / non-numeric ids (these flow into the request body, and a malformed
    list would be silently accepted-then-rejected by PVE; fail-closed here with a clear error)."""
    raw = str(resources).strip()
    tokens = [t.strip() for t in raw.split(",") if t.strip()]
    if not tokens:
        raise ProximoError("HA rule requires at least one resource (e.g. 'vm:100' or 'vm:100,ct:101')")
    for t in tokens:
        if not _HA_SID_RE.match(t):
            raise ProximoError(
                f"invalid HA resource id: {t!r} (expected 'vm:<vmid>' or 'ct:<vmid>')"
            )
    return ",".join(tokens)


def ha_rule_create(
    api,
    rule: str,
    rule_type: str,
    resources: str,
    comment: str | None = None,
    disable: bool = False,
    nodes: str | None = None,
    strict: bool = False,
    affinity: str | None = None,
) -> object:
    """Create an HA rule. MUTATION — confirm-gated + audited at the server layer.

    POST /cluster/ha/rules
    node-affinity     requires `nodes` ('node[:pri],...'); optional `strict`.
    resource-affinity requires `affinity` ('positive' keep together | 'negative' keep apart).
    Synchronous pmxcfs write (no UPID). No UNDO: delete the rule to revert.
    """
    rule = _check_ha_rule(rule)
    rule_type = _check_rule_type(rule_type)
    resources = _check_ha_resources(resources)
    data: dict = {"rule": rule, "type": rule_type, "resources": resources}
    if comment is not None:
        data["comment"] = _check_freetext(comment, "comment")
    if disable:
        data["disable"] = 1
    if rule_type == "node-affinity":
        if not nodes:
            raise ProximoError("node-affinity rule requires `nodes` (e.g. 'pve1:2,pve2')")
        data["nodes"] = str(nodes)
        if strict:
            data["strict"] = 1
    else:  # resource-affinity
        if affinity is None:
            raise ProximoError("resource-affinity rule requires `affinity` ('positive' or 'negative')")
        if affinity not in _VALID_AFFINITY:
            raise ProximoError(
                f"invalid affinity: {affinity!r} (expected one of {sorted(_VALID_AFFINITY)})"
            )
        data["affinity"] = affinity
    return api._post("/cluster/ha/rules", data)


def ha_rule_update(
    api,
    rule: str,
    comment: str | None = None,
    disable: bool | None = None,
    resources: str | None = None,
    rule_type: str | None = None,
    nodes: str | None = None,
    strict: bool | None = None,
    affinity: str | None = None,
    delete: list | str | None = None,
    digest: str | None = None,
) -> object:
    """Update an HA rule. MUTATION — confirm-gated + audited at the server layer.

    PUT /cluster/ha/rules/{rule}. Requires at least one field to change. No UNDO.
    `delete` unsets keys (list or csv). May trigger CRM migration of affected resources.
    """
    rule = _check_ha_rule(rule)
    data: dict = {}
    if comment is not None:
        data["comment"] = _check_freetext(comment, "comment")
    if disable is not None:
        data["disable"] = 1 if disable else 0
    if resources is not None:
        data["resources"] = _check_ha_resources(resources)
    if rule_type is not None:
        data["type"] = _check_rule_type(rule_type)
    if nodes is not None:
        data["nodes"] = str(nodes)
    if strict is not None:
        data["strict"] = 1 if strict else 0
    if affinity is not None:
        if affinity not in _VALID_AFFINITY:
            raise ProximoError(
                f"invalid affinity: {affinity!r} (expected one of {sorted(_VALID_AFFINITY)})"
            )
        data["affinity"] = affinity
    if delete:
        keys = delete if isinstance(delete, list) else [k.strip() for k in str(delete).split(",")]
        data["delete"] = ",".join(k for k in keys if k)
    if not data:
        raise ProximoError(
            "ha_rule_update requires at least one field to change "
            "(comment/disable/resources/type/nodes/strict/affinity/delete)"
        )
    # PVE's PUT requires the `type` discriminator to validate the conditional schema — a
    # comment-only update without it returns '400 Parameter verification failed'. If the caller
    # didn't supply `type`, fetch the rule's current type (mirrors firewall_rule_remove fetching
    # the digest the API needs). Live-surfaced against PVE 9.2 (2026-06-14).
    if "type" not in data:
        current, _ = _find_ha_rule(api, rule)
        if current.get("type"):
            data["type"] = current["type"]
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/cluster/ha/rules/{rule}", data)


def ha_rule_delete(api, rule: str) -> object:
    """Delete an HA rule. MUTATION — confirm-gated + audited at the server layer.

    DELETE /cluster/ha/rules/{rule}  (no params). Affected resources lose this placement
    constraint — the CRM may migrate them. No UNDO: re-create the rule to revert.
    """
    rule = _check_ha_rule(rule)
    return api._delete(f"/cluster/ha/rules/{rule}")


def _find_ha_rule(api, rule: str) -> tuple[dict, bool]:
    """One safe read of an HA rule's current config. Returns (rule_dict, read_failed).

    read_failed distinguishes a genuinely-absent rule from an unreadable one, so the
    update/delete plans never present a failed read as a confirmed empty/absent rule.
    """
    try:
        rules = ha_rules_list(api) or []
    except Exception:
        return {}, True
    found = next((r for r in rules if r.get("rule") == rule or r.get("id") == rule), None)
    if not found:
        return {}, False
    return {k: found[k] for k in ("rule", "type", "resources", "nodes", "strict", "affinity",
                                  "disable", "comment") if k in found}, False


def plan_ha_rule_create(
    rule: str,
    rule_type: str,
    resources: str,
    nodes: str | None = None,
    strict: bool = False,
    affinity: str | None = None,
    disable: bool = False,
) -> Plan:
    """Preview creating an HA rule. PURE. RISK_MEDIUM — constrains CRM placement of the
    affected resources (inert until they are HA-managed)."""
    rule = _check_ha_rule(rule)
    rule_type = _check_rule_type(rule_type)
    resources = _check_ha_resources(resources)
    blast = [
        f"creates HA {rule_type} rule '{rule}' over resources [{resources}]",
        "affects CRM placement only once these resources are HA-managed (otherwise inert)",
        "no UNDO: HA rules are pmxcfs config, not a guest snapshot; revert by deleting the rule",
    ]
    # Validate the conditional-required fields EXACTLY as ha_rule_create does, so a dry-run
    # never previews a create that confirm would reject (plan/op parity).
    if rule_type == "node-affinity":
        if not nodes:
            raise ProximoError("node-affinity rule requires `nodes` (e.g. 'pve1:2,pve2')")
        blast.insert(1, f"node-affinity: prefers/binds the resource(s) to nodes [{nodes}]")
        if strict:
            blast.insert(2,
                "strict: the resource(s) may run ONLY on those nodes — if all are down the "
                "guest stays STOPPED (availability risk)")
    else:  # resource-affinity (rule_type already validated to be one of the two)
        if affinity is None:
            raise ProximoError("resource-affinity rule requires `affinity` ('positive' or 'negative')")
        if affinity not in _VALID_AFFINITY:
            raise ProximoError(
                f"invalid affinity: {affinity!r} (expected one of {sorted(_VALID_AFFINITY)})"
            )
        if affinity == "negative":
            blast.insert(1, "negative resource-affinity: keeps the resources on SEPARATE nodes "
                            "— may block start if too few eligible nodes")
        else:
            blast.insert(1, "positive resource-affinity: keeps the resources TOGETHER on one node")
    if disable:
        blast.append("rule is created DISABLED — no effect until enabled")
    return Plan(
        action="pve_ha_rule_create",
        target=f"ha/rules/{rule}",
        change=f"create HA {rule_type} rule '{rule}' over [{resources}]",
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[
            "HA rules constrain where the CRM may place resources — can trigger migration / block start",
        ],
        note="HA rule create is a synchronous pmxcfs config write (no UPID).",
    )


def plan_ha_rule_update(
    api,
    rule: str,
    comment: str | None = None,
    disable: bool | None = None,
    resources: str | None = None,
    rule_type: str | None = None,
    nodes: str | None = None,
    strict: bool | None = None,
    affinity: str | None = None,
    delete: list | str | None = None,
) -> Plan:
    """Preview updating an HA rule. Reads the current rule (one safe read). RISK_MEDIUM —
    may trigger CRM migration of affected resources."""
    rule = _check_ha_rule(rule)
    current, read_failed = _find_ha_rule(api, rule)
    changed = [k for k, v in (("comment", comment), ("disable", disable), ("resources", resources),
                              ("type", rule_type), ("nodes", nodes), ("strict", strict),
                              ("affinity", affinity)) if v is not None]
    # `delete` UNSETS keys (e.g. strict/nodes/affinity) — a real placement change the dry-run
    # must disclose, so surface it in the preview rather than hiding it (redteam fix).
    delete_keys = (
        list(delete) if isinstance(delete, list)
        else [k.strip() for k in str(delete).split(",") if k.strip()]
    ) if delete else []
    if delete_keys:
        changed.append(f"delete({','.join(delete_keys)})")
    summary = ", ".join(changed) or "(no fields)"
    blast = [
        f"updates HA rule '{rule}': {summary}",
        "affected resources may be migrated by the CRM to satisfy the new constraint",
        "no UNDO: revert by updating the rule back to its previous values",
    ]
    if read_failed:
        blast.insert(0, f"current rule state UNKNOWN (read failed) — cannot confirm what '{rule}' is today")
    return Plan(
        action="pve_ha_rule_update",
        target=f"ha/rules/{rule}",
        change=f"update HA rule '{rule}': {summary}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["changing an HA rule alters CRM placement — can trigger migration"],
        note="HA rule update is a synchronous pmxcfs config write (no UPID).",
    )


def plan_ha_rule_delete(api, rule: str) -> Plan:
    """Preview deleting an HA rule. Reads the current rule (one safe read). RISK_MEDIUM —
    affected resources lose the placement constraint; the CRM may migrate them."""
    rule = _check_ha_rule(rule)
    current, read_failed = _find_ha_rule(api, rule)
    blast = [
        f"removes HA rule '{rule}' — its resources lose this placement constraint",
        "the CRM may migrate the affected resources once the constraint is gone",
        "no UNDO: re-create the rule to revert",
    ]
    if read_failed:
        blast.insert(0, f"current rule state UNKNOWN (read failed) — cannot confirm what '{rule}' constrains")
    return Plan(
        action="pve_ha_rule_delete",
        target=f"ha/rules/{rule}",
        change=f"delete HA rule '{rule}'",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["removing an HA rule lifts a placement constraint — can trigger migration"],
        note="HA rule delete is a synchronous pmxcfs config write (no UPID).",
    )
