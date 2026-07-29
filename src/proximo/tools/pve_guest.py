"""PVE guest lifecycle: node/guest status & power, snapshots/undo, in-container diagnostics (read), backup &
restore, provisioning, storage/ISO, guest config edit, disk ops, and cloud-init/template tools.

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.backends import _check_vmid
from proximo.cloudinit import (
    capture_cloudinit_undo,
    cloudinit_get,
    cloudinit_set,
    plan_cloudinit_set,
    plan_template_convert,
    template_convert,
)
from proximo.config_edit import (
    guest_config_get,
    guest_config_revert,
    guest_config_set,
    plan_config_revert,
    plan_config_set,
)
from proximo.diagnose import (
    diagnose_container,
    diagnose_node,
)
from proximo.disk_ops import (
    disk_move,
    disk_resize,
    plan_disk_move,
    plan_disk_resize,
)
from proximo.doctor import doctor_check
from proximo.planning import (
    plan_power,
    plan_rollback,
    plan_snapshot_create,
    plan_snapshot_delete,
)
from proximo.projection import envelope_rows, project_rows
from proximo.provisioning import (
    clone_guest,
    create_container,
    create_vm,
    delete_guest,
    plan_clone,
    plan_create,
    plan_delete,
)
from proximo.server import (
    _audited,
    _blocked_allowlist,
    _exec_disabled,
    _plan,
    tool,
)
from proximo.storage import (
    content_delete,
    plan_content_delete,
    plan_storage_download,
    storage_content,
    storage_download_url,
    storage_status,
)

# --- Management (REST API, read) ---

@tool()
def pve_node_status(
    node: Annotated[str | None, Field(description="PVE node name to query. Omit to use the configured default node.")] = None,
) -> dict:
    """READ-ONLY: read Proxmox node health and resource status. Returns node metrics including
    total capacity, current usage, CPU, memory, disk state, and operational status. See pve_diagnose
    for detailed per-node diagnostics including failed tasks."""
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_status", node or cfg.node, lambda: api.node_status(node))


@tool()
def pve_list_guests(
    node: Annotated[str | None, Field(description="PVE node name to list guests on. Omit to list guests across the whole cluster.")] = None,
    fields: Annotated[str | None, Field(description="Response fields: omit for the lean default (vmid/name/type/status/uptime/tags), `all` for the full payload, or a comma-separated field list.")] = None,
) -> dict:
    """READ-ONLY: list all VMs and LXC containers on a node with their current state. Returns
    a counted envelope — total, by_status, and `guests`: the rows in the lean default set
    (vmid, name, type lxc|qemu, status, uptime, tags). Trust total/by_status for count
    questions; they are computed server-side from the full listing. Pass fields='all' for raw
    rows (per-guest counters, PSI pressure metrics) or fields='vmid,mem,...' to pick columns.
    For one guest's runtime detail use pve_guest_status; for its stored config use
    pve_guest_config_get."""
    cfg, api, _, _ = _proximo_server._svc()
    rows = _audited("pve_list_guests", node or cfg.node, lambda: api.list_guests(node))
    lean = project_rows(rows, fields, ("vmid", "name", "type", "status", "uptime", "tags"))
    return envelope_rows(rows, lean, "guests", "status")


@tool()
def pve_guest_status(
    vmid: Annotated[str, Field(description="Numeric ID of the guest — VMID for a QEMU VM or CTID for an LXC container.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
) -> dict:
    """Read the operational status and current configuration of a single guest (kind='lxc' or
    'qemu') (read-only). Returns the guest's runtime state and resource utilization
    (CPU/memory/disk/network/uptime) — operational metrics, not its stored configuration.
    Use pve_guest_config_get for the full configuration."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_guest_status", f"{kind}/{vmid}", lambda: api.guest_status(vmid, kind, node))


# --- Management (REST API, MUTATION — confirm-gated) ---

@tool()
def pve_guest_power(
    vmid: Annotated[str, Field(description="Numeric ID of the guest — VMID for a QEMU VM or CTID for an LXC container.")],
    action: Annotated[str, Field(description="Power action to perform: `start`, `stop`, `reboot`, or `shutdown`.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN with blast radius; set `true` to execute the action.")] = False,
) -> dict:
    """MUTATION: start/stop/reboot/shutdown a guest.

    Dry-run by default: without confirm=True you get a PLAN — the exact change, the guest's live
    state, blast radius, and risk (with no-op detection) — recorded to the ledger even on a
    one-shot confirm=True call (no plan, no mutation). confirm=True submits the action (async)
    and returns the task UPID — poll it with pve_task_status.
    """
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}:{action}"
    plan = _plan("pve_guest_power", target, lambda: plan_power(api, vmid, action, kind, node))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    # PVE guest power is task-backed (POST .../status/{action} returns a UPID) — async, like the
    # identical-shape node_service_control. Record "submitted", never "ok": the ledger must not claim
    # the guest stopped/started when only the task was accepted.
    return _audited("pve_guest_power", target, lambda: api.guest_power(vmid, action, kind, node),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


# --- Snapshots / UNDO (REST API). Create/rollback/delete are ASYNC -> return a task UPID. ---

@tool()
def pve_snapshot_list(
    vmid: Annotated[str, Field(description="Numeric ID of the guest — VMID for a QEMU VM or CTID for an LXC container.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
) -> list[dict]:
    """List a guest's snapshots (read-only). Returns each snapshot's name, description, parent,
    and creation time, plus the synthetic 'current' node showing live state. Works for both VMs
    and containers (kind='qemu' or 'lxc'). Use pve_snapshot_create / pve_rollback to act on them."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_snapshot_list", f"{kind}/{vmid}", lambda: api.snapshot_list(vmid, kind, node))


@tool()
def pve_snapshot_create(
    vmid: Annotated[str, Field(description="Numeric ID of the guest — VMID for a QEMU VM or CTID for an LXC container.")],
    snapname: Annotated[str, Field(description="Name for the new snapshot.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    description: Annotated[str | None, Field(description="Optional free-text description stored on the snapshot.")] = None,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN; set `true` to execute the snapshot creation.")] = False,
) -> dict:
    """MUTATION: create a snapshot (a restore point). Dry-run by default; confirm=True to execute.
    Async — returns the task UPID; poll pve_task_status. Needs snapshot-capable storage (ZFS/BTRFS/LVM-thin).
    To restore to a snapshot use pve_rollback; to remove one use pve_snapshot_delete; to list them
    use pve_snapshot_list."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}:{snapname}"
    plan = _plan("pve_snapshot_create", target, lambda: plan_snapshot_create(vmid, snapname, kind))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_snapshot_create", target,
                    lambda: api.snapshot_create(vmid, snapname, kind, node, description),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


@tool()
def pve_rollback(
    vmid: Annotated[str, Field(description="Numeric ID of the guest — VMID for a QEMU VM or CTID for an LXC container.")],
    snapname: Annotated[str, Field(description="Name of the snapshot to roll the guest back to.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN with blast radius; set `true` to execute the rollback.")] = False,
) -> dict:
    """MUTATION (DESTRUCTIVE): roll a guest back to a snapshot — discards ALL changes since it.
    Dry-run by default (the PLAN spells out the blast radius); confirm=True to execute. Async —
    returns the task UPID, poll with pve_task_status. To create a restore point first use
    pve_snapshot_create."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}:{snapname}"
    plan = _plan("pve_rollback", target, lambda: plan_rollback(api, vmid, snapname, kind, node))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_rollback", target,
                    lambda: api.snapshot_rollback(vmid, snapname, kind, node),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


@tool()
def pve_snapshot_delete(
    vmid: Annotated[str, Field(description="Numeric ID of the guest — VMID for a QEMU VM or CTID for an LXC container.")],
    snapname: Annotated[str, Field(description="Name of the snapshot to delete.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    force: Annotated[bool, Field(description="Force removal even if the snapshot has children or the backend reports an inconsistent state.")] = False,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN; set `true` to execute the deletion.")] = False,
) -> dict:
    """MUTATION: delete a snapshot (removes a restore point) — you can't roll back to it afterward.
    Dry-run by default; confirm=True to execute. Async — returns the task UPID, poll with
    pve_task_status. To create a snapshot instead of removing one use pve_snapshot_create."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}:{snapname}"
    plan = _plan("pve_snapshot_delete", target, lambda: plan_snapshot_delete(vmid, snapname, kind))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_snapshot_delete", target,
                    lambda: api.snapshot_delete(vmid, snapname, kind, node, force),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


@tool()
def pve_task_status(
    upid: Annotated[str, Field(description="Proxmox task UPID (unique process ID) returned by an async operation.")],
    node: Annotated[str | None, Field(description="PVE node the task is running on. Omit to resolve it automatically.")] = None,
) -> dict:
    """READ-ONLY: get an async Proxmox task's status by its UPID — running vs stopped, plus the
    exit status once it has finished.

    No state change. Use it to poll long-running ops (migrate, snapshot, rollback, backup) that
    return a UPID. Returns a dict with `status` and `exitstatus`. To block until the task completes
    use pve_task_wait, and for its log output use pve_task_log. Pass `node` for a task on a
    non-default node; omitting it falls back to the configured default node (the UPID is not parsed for the node)."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_task_status", upid, lambda: api.task_status(upid, node))


# --- In-container (read) ---

@tool()
def ct_logs(
    ctid: Annotated[str, Field(description="Numeric CTID of the LXC container to read logs from.")],
    unit: Annotated[str, Field(description="Name of the systemd unit to tail journalctl for (e.g. `nginx.service`).")],
    lines: Annotated[int, Field(description="Number of most-recent log lines to return.")] = 50,
) -> dict:
    """READ-ONLY: tail journalctl for a systemd unit inside a container. Returns the command's
    returncode, stdout, and stderr. Gated by the CTID allowlist when PROXIMO_ENABLE_EXEC is set;
    fails closed (returns a disclosed blocked status, not an exception) if exec is disabled or the
    CTID isn't allowed. For a fixed evidence battery instead of one unit's logs use ct_diagnose;
    for an arbitrary in-container command use ct_exec."""
    cfg, _, exec_, _ = _proximo_server._svc()
    detail = {"unit": unit, "lines": lines}
    if not cfg.enable_exec:
        return _exec_disabled("ct_logs", str(ctid), detail, mutation=False)
    ctid = _check_vmid(ctid)  # L07: validate CTID format at server layer before allowlist gate
    if not cfg.ct_permitted(ctid):
        return _blocked_allowlist("ct_logs", str(ctid), detail, mutation=False)

    def _do() -> dict:
        r = exec_.logs(ctid, unit, lines=lines)
        return {"returncode": r.returncode, "stdout": r.stdout, "stderr": r.stderr}

    return _audited("ct_logs", str(ctid), _do, detail=detail)


@tool()
def ct_diagnose(
    ctid: Annotated[str, Field(description="Numeric CTID of the LXC container to diagnose.")],
    kind: Annotated[str, Field(description="Guest type; only `lxc` is meaningful here since diagnostics are container-specific.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the container runs on. Omit to resolve it automatically from the cluster.")] = None,
) -> dict:
    """READ-ONLY: gather 'what's broken' evidence for a container — API status + a fixed read-only
    in-container battery (failed units, disk, recent errors, memory, listening ports) + advisory flags.

    No mutation, no confirm. Returns a dict with the gathered sections and a flags list. The
    in-container probes need PROXIMO_ENABLE_EXEC and the CTID allowlist (same as ct_logs); with
    exec off it returns the API-only part and discloses the skipped probes. For node-level
    evidence use pve_diagnose."""
    cfg, api, exec_, _ = _proximo_server._svc()
    ctid = _check_vmid(ctid)  # L07: validate CTID at server layer before the allowlist gate / ledger target
    target = f"{kind}/{ctid}"
    if cfg.enable_exec and not cfg.ct_permitted(ctid):
        return _blocked_allowlist("ct_diagnose", str(ctid), mutation=False)
    use_exec = exec_ if cfg.enable_exec else None
    return _audited("ct_diagnose", target, lambda: diagnose_container(api, use_exec, ctid, kind, node))


@tool()
def pve_diagnose(
    node: Annotated[str | None, Field(description="PVE node to gather health evidence for. Omit to use the configured default node.")] = None,
) -> dict:
    """READ-ONLY: gather one node's health evidence in a single call — node status, storage usage,
    recent failed tasks, and advisory flags — for triage.

    No state change and no side effects. This inspects *node* health; to instead verify your token's
    connectivity and effective permissions use pve_doctor, and for in-container evidence use
    ct_diagnose. Returns a dict of the gathered sections; omit `node` to use the configured default."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_diagnose", node or "node", lambda: diagnose_node(api, node))


@tool()
def pve_doctor() -> dict:
    """READ-ONLY preflight: check API connectivity + the calling token's effective permissions, and
    report what this token CAN and CANNOT do — with the privilege + role to grant for each gap. Run
    this FIRST after install to verify your config/token before wiring Proximo into an MCP client.
    Returns a dict with reachable/version, the can/cannot capability map, config, and advisory flags."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_doctor", "preflight", lambda: doctor_check(api), mutation=False)


# --- Provisioning (REST API, async). create/clone are additive; delete is DESTRUCTIVE. ---

@tool()
def pve_create_container(
    vmid: Annotated[str, Field(description="Numeric CTID to assign to the new LXC container.")],
    ostemplate: Annotated[str, Field(description="Storage volume ID of the OS template to install, e.g. `local:vztmpl/debian-12-standard_12.2-1_amd64.tar.zst`.")],
    storage: Annotated[str, Field(description="Storage backend name to place the container's root filesystem on.")],
    node: Annotated[str | None, Field(description="PVE node to create the container on. Omit to use the configured default node.")] = None,
    options: Annotated[dict | None, Field(description="Extra Proxmox create params (e.g. cores, memory, net0, rootfs, password) merged into the request.")] = None,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN; set `true` to execute the creation.")] = False,
) -> dict:
    """MUTATION: create a new LXC container. Dry-run by default; confirm=True. Async — returns a
    UPID (poll with pve_task_status). `options` carries extra create params (cores, memory, net0,
    rootfs, password, ...). For a QEMU VM use pve_create_vm; to copy an existing guest instead
    use pve_clone."""
    _, api, _, _ = _proximo_server._svc()
    target = f"lxc/{vmid}"
    plan = _plan("pve_create_container", target,
                 lambda: plan_create(api, vmid, "lxc", node,
                                     {"ostemplate": ostemplate, "storage": storage, **(options or {})}))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited(
        "pve_create_container", target,
        lambda: create_container(api, vmid, ostemplate, storage, node, **(options or {})),
        mutation=True, outcome="submitted", detail={"confirmed": True})


@tool()
def pve_create_vm(
    vmid: Annotated[str, Field(description="Numeric VMID to assign to the new QEMU VM.")],
    node: Annotated[str | None, Field(description="PVE node to create the VM on. Omit to use the configured default node.")] = None,
    options: Annotated[dict | None, Field(description="Extra Proxmox create params (e.g. cores, memory, net0, scsi0, ostype) merged into the request.")] = None,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN; set `true` to execute the creation.")] = False,
) -> dict:
    """MUTATION: create a new QEMU VM. Dry-run by default; confirm=True. Async — returns a UPID
    (poll with pve_task_status). `options` carries create params (cores, memory, net0, scsi0,
    ostype, ...). For an LXC container use pve_create_container; to copy an existing guest
    instead use pve_clone."""
    _, api, _, _ = _proximo_server._svc()
    target = f"qemu/{vmid}"
    plan = _plan("pve_create_vm", target, lambda: plan_create(api, vmid, "qemu", node, options or {}))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_create_vm", target,
                    lambda: create_vm(api, vmid, node, **(options or {})),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


@tool()
def pve_clone(
    vmid: Annotated[str, Field(description="Numeric ID of the source guest to clone — VMID for a QEMU VM or CTID for an LXC container.")],
    newid: Annotated[str, Field(description="Numeric ID to assign to the new cloned guest.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the source guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    name: Annotated[str | None, Field(description="Name to give the new cloned guest.")] = None,
    full: Annotated[bool, Field(description="If true, make a full independent copy of the disks; if false (default), make a space-saving linked clone.")] = False,
    pool: Annotated[str | None, Field(description="Resource pool to place the new guest in — needed when the calling token is pool-scoped.")] = None,
    storage: Annotated[str | None, Field(description="Target storage for the full clone's disks (full=True only); keeps the clone off the source storage. Refused for a linked clone.")] = None,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN; set `true` to execute the clone.")] = False,
) -> dict:
    """MUTATION: clone a guest to a new id. Dry-run by default; confirm=True. Async — returns a
    UPID (poll with pve_task_status). pool: place the new guest in a resource pool (needed when
    the token is pool-scoped). storage: target storage for the full clone's disks (full=True
    only) — keeps a clone off the source storage; refused for a linked clone (PVE only honors it
    on a full clone). To create a guest from scratch instead use pve_create_vm / pve_create_container."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}->{newid}"
    plan = _plan("pve_clone", target,
                 lambda: plan_clone(api, vmid, newid, kind, node, storage, full, name, pool))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_clone", target,
                    lambda: clone_guest(api, vmid, newid, kind, node, name, full, pool, storage),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


@tool()
def pve_delete_guest(
    vmid: Annotated[str, Field(description="Numeric ID of the guest to destroy — VMID for a QEMU VM or CTID for an LXC container.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    purge: Annotated[bool, Field(description="If true, also remove the guest from replication/backup jobs and HA resources referencing it.")] = False,
    force: Annotated[bool, Field(description="Force removal even if the guest is still running or the backend reports an inconsistent state.")] = False,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN naming exactly what will be destroyed; set `true` to execute.")] = False,
) -> dict:
    """MUTATION (DESTRUCTIVE, IRREVERSIBLE): permanently destroy a guest and its disks. Dry-run by
    default — the PLAN names exactly what will be destroyed, including cascade effects on backup/
    HA/replication references. confirm=True to execute. Async — returns the task UPID; poll with
    pve_task_status. No undo once confirmed."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}"
    plan = _plan("pve_delete_guest", target, lambda: plan_delete(api, vmid, kind, node, purge, force))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_delete_guest", target,
                    lambda: delete_guest(api, vmid, kind, node, purge, force),
                    mutation=True, outcome="submitted", detail={"confirmed": True, "purge": purge})


# --- Storage / ISO / templates (REST API) ---

@tool()
def pve_storage_content(
    storage: Annotated[str, Field(description="Storage backend name to list content from.")],
    node: Annotated[str | None, Field(description="PVE node hosting the storage. Omit to use the configured default node.")] = None,
    content: Annotated[str | None, Field(description="Filter by content type: `iso`, `vztmpl`, or `backup`. Omit to list all content.")] = None,
) -> list[dict]:
    """READ-ONLY: list the volumes a storage holds — ISO images, container templates, backups, disks.

    No state change. Optionally filter by content type (iso | vztmpl | backup); omit to list all.
    Returns a list of volume dicts (volid, size, content type, …); use it to find a volid to pass to
    restore/clone tools. To *define* a new storage use pve_storage_create."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_storage_content", storage,
                    lambda: storage_content(api, storage, node, content))


@tool()
def pve_storage_status(
    storage: Annotated[str, Field(description="Storage backend name to read capacity and state for.")],
    node: Annotated[str | None, Field(description="PVE node hosting the storage. Omit to use the configured default node.")] = None,
) -> dict:
    """Read a storage backend's capacity and state (read-only). Returns total size, used space,
    available free space, and enabled status. Use pve_storage_content to list ISOs, templates,
    and backups stored on it."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_storage_status", storage, lambda: storage_status(api, storage, node))


@tool()
def pve_storage_download(
    storage: Annotated[str, Field(description="Storage backend name to download the file into.")],
    content: Annotated[str, Field(description="Content type of the downloaded file: `iso` or `vztmpl`.")],
    url: Annotated[str, Field(description="Source URL to download the ISO or CT template from.")],
    filename: Annotated[str, Field(description="Filename to save the downloaded content as on the storage.")],
    node: Annotated[str | None, Field(description="PVE node hosting the storage. Omit to use the configured default node.")] = None,
    checksum: Annotated[str | None, Field(description="Expected checksum of the downloaded file, used to verify integrity.")] = None,
    checksum_algorithm: Annotated[str | None, Field(description="Algorithm the checksum was computed with (e.g. `sha256`). Required if checksum is given.")] = None,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN; set `true` to execute the download.")] = False,
) -> dict:
    """MUTATION: download an ISO (content=iso) or CT template (content=vztmpl) from a URL into a
    storage. Dry-run by default; confirm=True. Async — returns a UPID (poll with pve_task_status).
    The URL and its content are operator-trusted — Proximo does not verify or sandbox what it
    fetches. Use pve_storage_content to see what's already on a storage."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{storage}:{filename}"
    plan = _plan("pve_storage_download", target,
                 lambda: plan_storage_download(storage, content, url, filename))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited(
        "pve_storage_download", target,
        lambda: storage_download_url(api, storage, content, url, filename, node,
                                     checksum, checksum_algorithm),
        mutation=True, outcome="submitted", detail={"confirmed": True})


@tool()
def pve_storage_content_delete(
    storage: Annotated[str, Field(description="Storage backend name the content volume lives on.")],
    volid: Annotated[str, Field(description="Volume ID of the content to delete (ISO, template, or backup), e.g. `local:vztmpl/debian-12.tar.zst`.")],
    node: Annotated[str | None, Field(description="PVE node hosting the storage. Omit to use the configured default node.")] = None,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN — HIGH risk for a backup volume; set `true` to execute the deletion.")] = False,
) -> dict:
    """MUTATION: delete a content volume (ISO / template / backup / disk image) from storage.
    Dry-run by default — escalates to HIGH risk for a backup volume or a disk still attached to a
    guest; confirm=True to execute. Async — returns a UPID or null. Use pve_storage_content to
    find a volid first."""
    _, api, _, _ = _proximo_server._svc()
    plan = _plan("pve_storage_content_delete", volid, lambda: plan_content_delete(api, storage, volid))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_storage_content_delete", volid,
                    lambda: content_delete(api, storage, volid, node),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


# --- Guest config edit (REST API). Config PUT is SYNCHRONOUS -> outcome="ok". ---

@tool()
def pve_guest_config_get(
    vmid: Annotated[str, Field(description="Numeric ID of the guest — VMID for a QEMU VM or CTID for an LXC container.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
) -> dict:
    """READ-ONLY: read a guest's current configuration (kind='lxc' or 'qemu'). Returns the
    complete config dict with cores, memory, network, disks, metadata, and all settings. Use
    pve_guest_config_set to mutate; capture the returned dict to enable rollback via
    pve_guest_config_revert."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_guest_config_get", f"{kind}/{vmid}",
                    lambda: guest_config_get(api, vmid, kind, node))


@tool()
def pve_guest_config_set(
    vmid: Annotated[str, Field(description="Numeric ID of the guest — VMID for a QEMU VM or CTID for an LXC container.")],
    changes: Annotated[dict, Field(description="Config keys to change, e.g. {'cores': 4, 'memory': 2048, 'onboot': 1}.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN with the per-key diff; set `true` to execute.")] = False,
) -> dict:
    """MUTATION: edit a guest's config (cores/memory/net/onboot/...). Dry-run by default — the PLAN
    shows the exact per-key diff; confirm=True to execute. Synchronous — returns
    {prior_config, applied, deleted}; prior_config is what makes the change revertible via
    pve_guest_config_revert."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}"
    plan = _plan("pve_guest_config_set", target,
                 lambda: plan_config_set(api, vmid, changes, kind, node))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_guest_config_set", target,
                    lambda: guest_config_set(api, vmid, changes, kind, node),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_guest_config_revert(
    vmid: Annotated[str, Field(description="Numeric ID of the guest — VMID for a QEMU VM or CTID for an LXC container.")],
    prior_config: Annotated[dict, Field(description="The prior config dict previously returned by pve_guest_config_set, to re-apply.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN; set `true` to execute the revert.")] = False,
) -> dict:
    """MUTATION (UNDO): re-apply a previously captured guest config (the prior_config returned by
    pve_guest_config_set). Dry-run by default; confirm=True to execute. Synchronous — returns
    {reverted_to_keys, deleted, skipped_unsettable}; computed/read-only keys in prior_config are
    silently skipped rather than rejected."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}"
    plan = _plan("pve_guest_config_revert", target,
                 lambda: plan_config_revert(api, vmid, prior_config, kind, node))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_guest_config_revert", target,
                    lambda: guest_config_revert(api, vmid, prior_config, kind, node),
                    mutation=True, outcome="ok", detail={"confirmed": True})


# --- Disk ops (REST API). Resize/move are async -> task UPID -> outcome="submitted". ---

@tool()
def pve_disk_resize(
    vmid: Annotated[str, Field(description="Numeric ID of the guest — VMID for a QEMU VM or CTID for an LXC container.")],
    disk: Annotated[str, Field(description="Disk key to resize, e.g. `scsi0` or `rootfs`.")],
    size: Annotated[str, Field(description="New size, as a grow-only delta like `+10G` (shrinking is refused as destructive).")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN; set `true` to execute the resize.")] = False,
) -> dict:
    """MUTATION: grow a guest disk (e.g. size='+10G'). GROW ONLY — a shrink is refused as
    destructive, and an ambiguous absolute size is refused too unless the current size can be
    verified first. Dry-run by default; confirm=True to execute. Async — returns a task UPID
    (poll with pve_task_status). To move a disk to different storage instead use pve_disk_move."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}:{disk}"
    plan = _plan("pve_disk_resize", target,
                 lambda: plan_disk_resize(api, vmid, disk, size, kind, node))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_disk_resize", target,
                    lambda: disk_resize(api, vmid, disk, size, kind, node),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


@tool()
def pve_disk_move(
    vmid: Annotated[str, Field(description="Numeric ID of the guest — VMID for a QEMU VM or CTID for an LXC container.")],
    disk: Annotated[str, Field(description="Disk key to move, e.g. `scsi0` or `rootfs`.")],
    target_storage: Annotated[str, Field(description="Storage backend name to move the disk to.")],
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "lxc",
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    delete_source: Annotated[bool, Field(description="If true, delete the source copy after the move (HIGH risk); if false (default), keep it.")] = False,
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN; set `true` to execute the move.")] = False,
) -> dict:
    """MUTATION: move a guest disk to another storage. Dry-run by default — the PLAN shows
    source->target and whether the source copy is deleted (delete_source=True is HIGH, no easy
    undo). confirm=True to execute. Async — returns a task UPID (poll with pve_task_status). To
    grow a disk in place instead of relocating it use pve_disk_resize."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}:{disk}"
    plan = _plan("pve_disk_move", target,
                 lambda: plan_disk_move(api, vmid, disk, target_storage, kind, node, delete_source))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_disk_move", target,
                    lambda: disk_move(api, vmid, disk, target_storage, kind, node, delete_source),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


# --- Cloud-init + template (REST API, QEMU). Config POST is synchronous -> outcome="ok". ---

@tool()
def pve_cloudinit_get(
    vmid: Annotated[str, Field(description="Numeric VMID of the QEMU guest to read cloud-init config from.")],
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    kind: Annotated[str, Field(description="Guest type; cloud-init applies to `qemu` guests.")] = "qemu",
) -> dict:
    """Read a QEMU guest's cloud-init configuration (read-only). Returns cloud-init fields
    (ciuser, sshkeys, ipconfigN, cipassword placeholder) with secret fields masked for safety.
    Use pve_cloudinit_set to mutate it; the set operation auto-captures an undo record for
    rollback."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_cloudinit_get", f"{kind}/{vmid}",
                    lambda: cloudinit_get(api, vmid, node, kind))


@tool()
def pve_cloudinit_set(
    vmid: Annotated[str, Field(description="Numeric VMID of the QEMU guest to set cloud-init config on.")],
    changes: Annotated[dict, Field(description="Cloud-init fields to change, e.g. {'ciuser': 'admin', 'sshkeys': '...', 'ipconfig0': 'ip=dhcp'}.")],
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    kind: Annotated[str, Field(description="Guest type; cloud-init applies to `qemu` guests.")] = "qemu",
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN with secrets masked; set `true` to execute.")] = False,
) -> dict:
    """MUTATION: set cloud-init fields (ciuser/sshkeys/ipconfigN/...) on a QEMU guest — kind='lxc'
    is refused (cloud-init is QEMU-only). Dry-run by default with secrets masked in the PLAN;
    confirm=True to execute. Synchronous; the return carries a top-level undo_record key beside
    status/result (secret fields excluded). Effects apply on next reboot + cloud-init regen, not live. Read current
    values with pve_cloudinit_get."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}"
    plan = _plan("pve_cloudinit_set", target,
                 lambda: plan_cloudinit_set(api, vmid, changes, node, kind))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    # Capture the prior cloud-init config (secret-stripped) BEFORE the set, so the result carries
    # a real undo_record. A config edit is not blocked on undo-capture failure (unlike exec) — but
    # the degraded UNDO must NOT be silent: surface it in the status AND the PROVE ledger (M-1).
    try:
        undo = capture_cloudinit_undo(api, vmid, node, kind)
        outcome = "ok"
    except Exception as e:
        undo = {"prior_ci_config": None,
                "secret_undo_caveat": f"undo capture failed: {type(e).__name__}"}
        outcome = "ok:undo_unavailable"  # mutation ran, but no rollback was captured — recorded, not silent
    envelope = _audited("pve_cloudinit_set", target,
                        lambda: cloudinit_set(api, vmid, changes, node, kind),
                        mutation=True, outcome=outcome, detail={"confirmed": True})
    envelope["undo_record"] = undo
    return envelope


@tool()
def pve_template_convert(
    vmid: Annotated[str, Field(description="Numeric ID of the guest to convert into a template.")],
    node: Annotated[str | None, Field(description="PVE node the guest runs on. Omit to resolve it automatically from the cluster.")] = None,
    kind: Annotated[str, Field(description="Guest type: `lxc` for a container or `qemu` for a VM.")] = "qemu",
    confirm: Annotated[bool, Field(description="Leave `false` (default) to get a dry-run PLAN flagging this as HIGH/irreversible; set `true` to execute.")] = False,
) -> dict:
    """MUTATION (IRREVERSIBLE): convert a guest into a template — effectively one-way; kind='lxc'
    is refused (this endpoint is QEMU-only — LXC uses a separate, out-of-scope template endpoint).
    Dry-run by default (the PLAN flags it HIGH/irreversible, and separately warns if the guest is
    already a template); confirm=True executes, recorded as submitted (async)."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}"
    plan = _plan("pve_template_convert", target,
                 lambda: plan_template_convert(api, vmid, node, kind))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_template_convert", target,
                    lambda: template_convert(api, vmid, node, kind),
                    mutation=True, outcome="submitted", detail={"confirmed": True})
