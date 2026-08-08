"""PROVISION pillar — create / clone / delete guests (the most destructive ops on the platform).

Every mutating function returns a UPID (task ID) for tracking via task_status.
Every plan function reads live state (one safe read) to surface facts and detect collisions,
then returns a Plan the caller can inspect before confirming.

Hard rules mirrored from the codebase:
- Validators fire on every path/id component before it enters a URL.
- Plans are HONEST — HIGH is maintained even when the op would fail; no false-safety claims.
- The absence of a HIGH flag is NOT a safety signal (curated, not exhaustive).
- No self-gating: the server layer adds confirm-gating + audit; these functions are pure ops.
"""

from __future__ import annotations

from .backends import ProximoError, _check_kind, _check_node, _check_vmid
from .blast import guest_destroy_blast
from .cluster_ops import cluster_resources
from .planning import RISK_HIGH, RISK_MEDIUM, Plan


def _truthy_option(v) -> bool:
    """Interpret a PVE-style boolean option value (1/0, true/false, yes/no, on/off)."""
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


def _cluster_guests(api, node: str | None) -> tuple[list[dict], str | None, bool]:
    """Guest list for VMID collision / source-exists checks. PVE VMIDs are CLUSTER-unique, so read
    cluster-wide (cluster_resources) first; fall back to the node-scoped list_guests if that read
    fails, disclosing the narrower scope. 2026-07-10 audit L14: the check used to be node-scoped only,
    so a vmid taken on another node slipped through and the plan wrongly promised a clean create.
    Returns (guests, check_error, node_scoped_only)."""
    try:
        return cluster_resources(api, "vm") or [], None, False
    except Exception:  # noqa: S110 — cluster-wide read unavailable; fall back to the node-scoped read
        pass
    try:
        return api.list_guests(node) or [], None, True
    except Exception as e:
        return [], type(e).__name__, True

# ---------------------------------------------------------------------------
# Local validators
# ---------------------------------------------------------------------------

def _check_ostemplate(ostemplate: str) -> str:
    """Non-empty check; PVE validates format on its side."""
    s = str(ostemplate).strip()
    if not s:
        raise ProximoError("ostemplate must not be empty")
    return s


def _check_storage(storage: str) -> str:
    """Non-empty check; PVE validates existence on its side."""
    s = str(storage).strip()
    if not s:
        raise ProximoError("storage must not be empty")
    return s


def _same_vmid(a, b) -> bool:
    """Compare vmids numerically (Proxmox returns int; callers pass validated strings). Avoids the
    string-mismatch bug where '0500' != 500-as-'500' would miss a real collision."""
    try:
        return int(a) == int(b)
    except (TypeError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Mutation operations — each validates params, builds exact PVE URL, returns UPID
# ---------------------------------------------------------------------------

def create_container(
    api,
    vmid: str,
    ostemplate: str,
    storage: str,
    node: str | None = None,
    **opts,
) -> str:
    """Create a new LXC container.

    POST /nodes/{node}/lxc  →  UPID

    Extra keyword args (rootfs, hostname, memory, cores, net0, …) are passed through
    as form data — PVE validates them.
    """
    vmid = _check_vmid(vmid)
    _check_node(node)
    ostemplate = _check_ostemplate(ostemplate)
    storage = _check_storage(storage)
    n = node or api.config.node
    data = {"vmid": vmid, "ostemplate": ostemplate, "storage": storage, **opts}
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/nodes/{n}/lxc", data)


def create_vm(
    api,
    vmid: str,
    node: str | None = None,
    **opts,
) -> str:
    """Create a new QEMU VM.

    POST /nodes/{node}/qemu  →  UPID

    Extra keyword args (name, memory, cores, net0, scsi0, …) are passed through
    as form data — PVE validates them.
    """
    vmid = _check_vmid(vmid)
    _check_node(node)
    n = node or api.config.node
    data = {"vmid": vmid, **opts}
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/nodes/{n}/qemu", data)


def clone_guest(
    api,
    vmid: str,
    newid: str,
    kind: str = "lxc",
    node: str | None = None,
    name: str | None = None,
    full: bool = False,
    pool: str | None = None,
    storage: str | None = None,
) -> str:
    """Clone an existing LXC or QEMU guest to a new VMID.

    POST /nodes/{node}/{kind}/{vmid}/clone  →  UPID

    full=False (default): linked clone — requires the source to be a template.
    full=True: full copy — independent disk; slower but no template requirement.
    storage: target storage for the full clone's disks (e.g. to keep a clone off the source
        storage). PVE honors this ONLY for a full clone — a linked clone must stay on the source
        storage — so we refuse `storage` without `full` rather than send a request PVE will reject.
    """
    vmid = _check_vmid(vmid)
    newid = _check_vmid(newid)
    kind = _check_kind(kind)
    _check_node(node)
    if storage is not None and not full:
        raise ProximoError(
            "storage (target storage) is only valid for a full clone (full=True) — a linked clone "
            "must stay on the source storage; PVE would reject a storage override."
        )
    n = node or api.config.node
    data: dict = {"newid": newid}
    if full:
        data["full"] = 1
    if name is not None:
        data["name"] = name
    if pool is not None:
        data["pool"] = pool
    if storage is not None:
        data["storage"] = storage
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/nodes/{n}/{kind}/{vmid}/clone", data)


def delete_guest(
    api,
    vmid: str,
    kind: str = "lxc",
    node: str | None = None,
    purge: bool = False,
    force: bool = False,
) -> str:
    """Permanently delete a guest and its disks.

    DELETE /nodes/{node}/{kind}/{vmid}  →  UPID

    purge=True: also removes the guest from backup jobs, HA, and replication config.
    force=True: attempt deletion even if the guest is running.

    This is the single most destructive operation on the platform — irreversible.
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)
    n = node or api.config.node
    params: dict = {}
    if purge:
        params["purge"] = 1
    if force:
        params["force"] = 1
    # DESTRUCTIVE MUTATION — confirm-gated + audited at the server layer.
    return api._delete(f"/nodes/{n}/{kind}/{vmid}", params or None)


# ---------------------------------------------------------------------------
# Plan functions — each returns a Plan for caller inspection (PLAN pillar)
# ---------------------------------------------------------------------------

def plan_create(
    api,
    vmid: str,
    kind: str = "lxc",
    node: str | None = None,
    options: dict | None = None,
) -> Plan:
    """Preview creating a new guest with the given vmid.

    Reads list_guests (a safe read) to detect whether vmid is already in use.
    If the collision check itself fails, that uncertainty is disclosed — the absence
    of a HIGH flag is not a safety signal.

    *options* are the create params that will actually be sent (cores, memory, unprivileged,
    password, …). They are surfaced in the plan so the preview/ledger reflect the real mutation
    (the `password` option is redacted). An LXC created privileged — i.e. `unprivileged` absent
    or falsy, which is the PVE default — escalates the plan to RISK_HIGH.
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)

    guests, check_error, node_scoped_only = _cluster_guests(api, node)
    # Proxmox returns vmid as int; compare numerically so '0500' vs 500 can't slip the check.
    taken = check_error is None and any(_same_vmid(g.get("vmid"), vmid) for g in guests)

    if check_error is not None:
        blast = [
            f"collision check failed ({check_error}) — could not confirm vmid {vmid} is free; "
            "create may fail if already in use"
        ]
        reasons = [
            f"resource consumption: creates a new {kind} {vmid}",
            "collision check unavailable — absence of HIGH flag is not a safety signal",
        ]
    elif taken:
        blast = [f"create will FAIL — vmid {vmid} already in use"]
        reasons = [f"vmid {vmid} is already taken; create will be rejected by PVE"]
    else:
        blast = [f"new {kind}/{vmid} will be created, consuming resources (disk, memory, CPU allocation)"]
        reasons = [f"resource consumption: creates a new {kind} {vmid}"]
    if node_scoped_only and check_error is None:
        blast = blast + [
            f"collision check was NODE-SCOPED to {node!r} only (cluster-wide read unavailable) — a "
            "vmid already used on ANOTHER node would not be caught here (VMIDs are cluster-unique)"
        ]

    options = options or {}
    # PVE LXC create is PRIVILEGED BY DEFAULT: the real API param is `unprivileged` (default 0);
    # there is NO `privileged` param (PVE silently ignores one). A container is privileged unless
    # `unprivileged` is truthy — INCLUDING when the option is omitted entirely (the PVE default),
    # which is the common path. QEMU has no such notion. The old check read a non-existent
    # `privileged` key, so an actually-privileged container was planned MEDIUM with no warning.
    privileged = kind == "lxc" and not _truthy_option(options.get("unprivileged", 0))
    # surface what will actually be created — redact the `password` create-option (a secret)
    opt_display = {k: ("[redacted]" if k == "password" else v) for k, v in options.items()}
    if opt_display:
        blast = blast + [f"create options: {opt_display}"]
    if privileged:
        blast = blast + [
            "PRIVILEGED container (unprivileged=0 — the PVE create default): shares host UID 0, "
            "guest-root escape == host-root; pass unprivileged=1 for an isolated container"
        ]
        reasons = reasons + ["privileged LXC: host-equivalent root; container isolation is weaker (HIGH)"]
    return Plan(
        action="pve_create",
        target=f"{kind}/{vmid}",
        change=f"create {kind} {vmid}" + (f" with {opt_display}" if opt_display else ""),
        current={},
        blast_radius=blast,
        risk=RISK_HIGH if privileged else RISK_MEDIUM,
        risk_reasons=reasons,
    )


def _source_nic_bridges(api, kind: str, vmid: str, node: str | None) -> list[str]:
    """Bridges the source guest's NIC(s) attach to (for the SDN.Use disclosure). Best-effort: returns
    [] if the source config can't be read — disclosure must never break the plan."""
    try:
        cfg = api._get(f"/nodes/{node or api.config.node}/{kind}/{vmid}/config") or {}
    except Exception:
        return []
    return sorted({
        part.strip()[len("bridge="):]
        for key, val in cfg.items()
        if key.startswith("net") and key[3:].isdigit() and isinstance(val, str)
        for part in val.split(",")
        if part.strip().startswith("bridge=")
    })


def plan_clone(
    api,
    vmid: str,
    newid: str,
    kind: str = "lxc",
    node: str | None = None,
    storage: str | None = None,
    full: bool = False,
    name: str | None = None,
    pool: str | None = None,
) -> Plan:
    """Preview cloning guest vmid to newid.

    Reads list_guests (a safe read) to detect whether newid is already in use.
    full=False (default) is a LINKED clone — copy-on-write, requires the source to be a template;
    full=True is a full independent copy. `storage` is only honored for a full clone (the op refuses
    it otherwise), so the plan must reflect `full` to describe the actual result.
    """
    vmid = _check_vmid(vmid)
    newid = _check_vmid(newid)
    kind = _check_kind(kind)
    _check_node(node)

    guests, check_error, node_scoped_only = _cluster_guests(api, node)
    # Compare numerically (Proxmox returns int); check BOTH that newid is free and the source exists.
    taken = check_error is None and any(_same_vmid(g.get("vmid"), newid) for g in guests)
    source_found = check_error is not None or any(_same_vmid(g.get("vmid"), vmid) for g in guests)

    if check_error is not None:
        blast = [
            f"check failed ({check_error}) — could not confirm newid {newid} is free or that "
            f"source {kind}/{vmid} exists; clone may fail"
        ]
        reasons = [
            f"resource consumption: clones {kind}/{vmid} → {newid}",
            "collision/source check unavailable — absence of HIGH flag is not a safety signal",
        ]
    elif taken:
        blast = [f"clone will FAIL — vmid {newid} already in use"]
        reasons = [f"newid {newid} is already taken; clone will be rejected by PVE"]
    elif not source_found:
        blast = [f"clone will FAIL — source {kind}/{vmid} not found; nothing would be cloned"]
        reasons = [f"source {kind}/{vmid} does not exist; clone will be rejected by PVE"]
    elif full:
        blast = [
            f"clones {kind}/{vmid} → {newid} (new independent guest, FULL clone); "
            "consumes additional disk and resource allocation"
        ]
        reasons = [f"resource consumption: full clone of {kind}/{vmid} to {newid}"]
    else:
        blast = [
            f"clones {kind}/{vmid} → {newid} (LINKED clone — copy-on-write, depends on the source "
            f"{kind}/{vmid}, which must be a template; PVE rejects a linked clone of a non-template)"
        ]
        reasons = [
            f"linked clone of {kind}/{vmid} to {newid} — requires the source to be a template "
            "(use full=True for an independent copy)"
        ]
    if node_scoped_only and check_error is None:
        blast = blast + [
            f"collision/source check was NODE-SCOPED to {node!r} only (cluster-wide read unavailable) "
            "— a newid used on another node, or a source template on another node, may be missed"
        ]

    if storage is not None:
        if full:
            blast = blast + [f"full-clone disks target storage '{storage}'"]
        else:
            blast = blast + [
                f"⚠ storage override '{storage}' requires full=True — this clone will be REFUSED "
                "(a linked clone must stay on the source storage)"
            ]

    # Disclose the SDN.Use-on-bridge requirement (PVE 8+) for the cloned guest's NIC(s).
    bridges = _source_nic_bridges(api, kind, vmid, node)
    if bridges:
        blast = blast + [
            f"attaches NIC(s) to bridge(s) {', '.join(bridges)} — PVE 8+ requires SDN.Use on "
            "that bridge to clone a guest carrying a NIC"
        ]

    if name is not None:
        blast = blast + [f"new guest display name: '{name}'"]
    if pool is not None:
        blast = blast + [f"placed in resource pool '{pool}' — controls which tokens can manage the clone"]
    return Plan(
        action="pve_clone",
        target=f"{kind}/{vmid}→{newid}",
        change=(f"clone {kind} {vmid} to {newid}"
                + (f" as '{name}'" if name else "") + (f" in pool '{pool}'" if pool else "")),
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=reasons,
    )


def plan_delete(
    api,
    vmid: str,
    kind: str = "lxc",
    node: str | None = None,
    purge: bool = False,
    force: bool = False,
) -> Plan:
    """Preview permanently deleting a guest.

    Reads guest_status (a safe read) to show what's being destroyed (name, status).
    Then gathers the full blast-radius cascade (what PVE will refuse, what references
    are left dangling vs cleaned up, what is intrinsically removed).
    RISK_HIGH regardless of outcome — destruction is irreversible if it proceeds;
    not-found means the op would fail, not that it's safe.
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)

    # defaults for check_failed / not_found branches — no cascade on a guest that may not exist
    cascade_affected: list[dict] = []
    cascade_complete: bool = True

    current: dict = {}
    found = True
    check_failed = False
    try:
        gs = api.guest_status(vmid, kind, node)
        current = {k: gs[k] for k in ("status", "name") if k in gs}
    except Exception as e:
        # Only a definitive 404 is "confirmed absent". A transient error must NOT be reported as
        # "nothing would be destroyed" — that would be a false-safety claim on the platform's most
        # destructive op.
        resp = getattr(e, "response", None)
        if resp is not None and getattr(resp, "status_code", None) == 404:
            found = False
        else:
            check_failed = True

    name = current.get("name", "unknown")
    status = current.get("status", "unknown")

    if check_failed:
        # Existence UNKNOWN — if the guest exists, this destroys it. RISK_HIGH; no false safety.
        # The structured honesty flag must reflect that the cascade could not be enumerated:
        # existence itself is an unreadable edge, so complete=False (not just an honest blast string).
        cascade_complete = False
        blast = [
            f"could NOT verify whether {kind}/{vmid} exists; if it does, this PERMANENTLY destroys "
            "it and its disk(s) — irreversible"
        ]
        reasons = [
            f"existence check for {kind}/{vmid} failed — cannot confirm what (if anything) is destroyed",
            "RISK_HIGH maintained: uncertainty is not a safety signal",
        ]
    elif not found:
        # Confirmed absent (404): the delete will fail — nothing gets destroyed.
        # RISK_HIGH is maintained (plan_rollback precedent); blast does NOT claim destruction.
        blast = [f"delete will FAIL — {kind}/{vmid} not found; nothing would be destroyed"]
        reasons = [
            f"{kind}/{vmid} not found — delete will fail",
            "RISK_HIGH maintained: not-found is a failure state, not a safety signal",
        ]
    else:
        blast = [
            f"PERMANENTLY destroys {kind}/{vmid} (name={name}, currently {status}) "
            "and its disk(s) — irreversible"
        ]
        if purge:
            blast.append(
                f"+ if configured, removes {kind}/{vmid} from backup jobs / HA / replication (purge=true)"
            )
        reasons = [
            f"destroys {kind}/{vmid} (name={name}, status={status}) and all its disks — irreversible",
            "delete is the single most destructive guest operation; no undo once confirmed",
        ]
        if purge:
            reasons.append(
                "purge also removes the guest from backup, HA, and replication config where configured"
            )

        # --- cascade: what destroying this guest actually does (purge/force-conditional) ---
        gdb = guest_destroy_blast(api, vmid, kind, node, purge, force)
        blast.extend(gdb.summary_lines)
        reasons.extend(gdb.risk_reasons)
        cascade_affected = gdb.affected
        cascade_complete = gdb.complete

    return Plan(
        action="pve_delete",
        target=f"{kind}/{vmid}",
        change=f"delete {kind} {vmid}" + (" (purge)" if purge else ""),
        current=current,
        blast_radius=blast,
        risk=RISK_HIGH,
        risk_reasons=reasons,
        affected=cascade_affected,
        complete=cascade_complete,
    )
