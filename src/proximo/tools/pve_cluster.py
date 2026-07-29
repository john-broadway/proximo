"""PVE cluster & HA, task control + resource pools, and storage administration (storage.cfg CRUD).

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.cluster_ops import (
    cluster_resources,
    cluster_status,
    guest_migrate,
    ha_groups_list,
    ha_resource_add,
    ha_resource_remove,
    ha_resources_list,
    ha_rule_create,
    ha_rule_delete,
    ha_rule_update,
    ha_rules_list,
    plan_ha_resource_add,
    plan_ha_resource_remove,
    plan_ha_rule_create,
    plan_ha_rule_delete,
    plan_ha_rule_update,
    plan_migrate,
)
from proximo.projection import envelope_rows, project_rows
from proximo.server import (
    _audited,
    _plan,
    tool,
)
from proximo.storage_admin import (
    plan_storage_create,
    plan_storage_delete,
    plan_storage_update,
    storage_config_get,
    storage_config_list,
    storage_create,
    storage_delete,
    storage_update,
)
from proximo.tasks_pools import (
    plan_pool_create,
    plan_pool_delete,
    plan_pool_update,
    plan_task_stop,
    pool_create,
    pool_delete,
    pool_get,
    pool_update,
    pools_list,
    task_log,
    task_stop,
    tasks_list,
    wait_for_task,
)

# --- Cluster & HA (REST API, read) ---

@tool()
def pve_cluster_status() -> list[dict]:
    """Retrieve the cluster's overall status: nodes, quorum state, and the corosync
    config version (read-only). Returns a list of status dicts with node names, types, online
    status, and quorum info. Use pve_cluster_resources to list all resources across the cluster."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_cluster_status", "cluster/status", lambda: cluster_status(api))


@tool()
def pve_cluster_resources(
    resource_type: Annotated[str | None, Field(description="Optional filter: 'vm', 'storage', 'node', or 'sdn'; omit to list all resource types.")] = None,
    fields: Annotated[str | None, Field(description="Response fields: omit for the lean default (id/type/node/status/name/vmid/storage/uptime), `all` for the full payload, or a comma-separated field list.")] = None,
) -> dict:
    """READ-ONLY: list all resources across the cluster (VMs, nodes, storage, SDN).

    resource_type: optional filter — 'vm', 'storage', 'node', or 'sdn'; omit for all types.
    No state change. Returns a counted envelope — total, by_type, and `resources`: dicts in
    the lean identity/state set (shape still varies by type; a key is kept only where the row
    has it). Trust total/by_type for count questions; they are computed server-side. Pass
    fields='all' for raw rows with usage counters, or fields='id,mem,...' to pick columns. For
    overall cluster health/quorum use pve_cluster_status; to list only guests use
    pve_list_guests."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/resources/{resource_type or 'all'}"
    rows = _audited("pve_cluster_resources", tgt,
                    lambda: cluster_resources(api, resource_type))
    lean = project_rows(rows, fields,
                        ("id", "type", "node", "status", "name", "vmid", "storage", "uptime"))
    return envelope_rows(rows, lean, "resources", "type")


@tool()
def pve_ha_groups_list() -> list[dict]:
    """READ-ONLY: list all HA resource groups. PVE-8 only — PVE 9 migrated groups to rules
    (use pve_ha_rules_list); on PVE 9 this raises a clear ProximoError pointing there instead
    of a raw 500. No state change. Returns a list of group dicts (group, nodes, restricted,
    comment) on PVE 8."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_ha_groups_list", "cluster/ha/groups", lambda: ha_groups_list(api))


@tool()
def pve_ha_rules_list() -> list[dict]:
    """READ-ONLY: list High-Availability rules on the cluster (PVE 9+).

    No state change. PVE 9 replaced HA groups with rules; on PVE 8 use pve_ha_groups_list instead.
    Returns a list of rule dicts. To see which guests are actually HA-managed use pve_ha_resources_list."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_ha_rules_list", "cluster/ha/rules", lambda: ha_rules_list(api))


@tool()
def pve_ha_resources_list() -> list[dict]:
    """List all guests managed by HA (High Availability) with their current HA settings
    (read-only). Returns a list of HA resource dicts with SID, type, state, group, and restart
    settings. Use pve_ha_groups_list or pve_ha_rules_list to view HA placement rules, not for
    resource enumeration."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_ha_resources_list", "cluster/ha/resources",
                    lambda: ha_resources_list(api))


# --- Cluster & HA (REST API, MUTATION — confirm-gated) ---

@tool()
def pve_guest_migrate(
    vmid: Annotated[str, Field(description="Numeric VMID/CTID of the guest to migrate.")],
    target: Annotated[str, Field(description="Destination node name to migrate the guest to.")],
    kind: Annotated[str, Field(description="Guest type: 'lxc' or 'qemu'.")] = "lxc",
    node: Annotated[str | None, Field(description="Source node name; defaults to the configured node.")] = None,
    online: Annotated[bool, Field(description="QEMU: live migration (zero-downtime, needs shared storage). LXC: stop-move-start restart migration (real downtime). False = offline migration.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the migration.")] = False,
) -> dict:
    """MUTATION: migrate a guest to a different node. Dry-run by default — the PLAN shows the
    guest's live state, the source→target, and the honest blast radius (LXC 'online' is
    stop→move→start, NOT zero-downtime; QEMU live migration requires shared storage).
    confirm=True to execute. Async — returns a task UPID; poll with pve_task_status. To drive
    the same move through PDM instead, use pdm_pve_lxc_migrate or pdm_pve_qemu_migrate.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"{kind}/{vmid}->{target}"
    plan = _plan("pve_guest_migrate", tgt,
                 lambda: plan_migrate(api, vmid, target, kind, node, online))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_guest_migrate", tgt,
                    lambda: guest_migrate(api, vmid, target, kind, node, online),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


@tool()
def pve_ha_resource_add(
    vmid: Annotated[str, Field(description="Numeric VMID/CTID of the guest to add to HA management.")],
    kind: Annotated[str, Field(description="Guest type: 'lxc' or 'qemu'.")] = "lxc",
    group: Annotated[str | None, Field(description="HA group to assign (PVE 8 only; PVE 9 removed groups in favor of HA rules — omit on PVE 9).")] = None,
    state: Annotated[str | None, Field(description="Desired HA state, e.g. 'started', 'stopped', 'disabled' ('stopped' has the CRM stop the guest).")] = None,
    max_restart: Annotated[int | None, Field(description="Max number of restart attempts the CRM makes before giving up.")] = None,
    max_relocate: Annotated[int | None, Field(description="Max number of relocation attempts the CRM makes before giving up.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the change.")] = False,
) -> dict:
    """MUTATION: add a guest to HA management. Dry-run by default — the PLAN shows the SID,
    group, initial state, and blast radius (state='stopped' is HIGH: CRM will stop the guest).
    confirm=True to execute. Synchronous (pmxcfs config write; CRM enforces state asynchronously) —
    typically returns null, not a UPID. To remove HA management use pve_ha_resource_remove.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"ha:{kind}/{vmid}"
    plan = _plan("pve_ha_resource_add", tgt,
                 lambda: plan_ha_resource_add(vmid, kind, group, state, max_restart, max_relocate))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_ha_resource_add", tgt,
                    lambda: ha_resource_add(api, vmid, kind, group, state, max_restart, max_relocate),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_ha_resource_remove(
    vmid: Annotated[str, Field(description="Numeric VMID/CTID of the guest to remove from HA management.")],
    kind: Annotated[str, Field(description="Guest type: 'lxc' or 'qemu'.")] = "lxc",
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the change.")] = False,
) -> dict:
    """MUTATION: remove a guest from HA management. Dry-run by default — the PLAN shows the SID
    and that this loses automated failover protection (guest itself is NOT stopped).
    confirm=True to execute. Synchronous (pmxcfs config write) — typically returns null, not a
    UPID. To re-add HA management use pve_ha_resource_add.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"ha:{kind}/{vmid}"
    plan = _plan("pve_ha_resource_remove", tgt,
                 lambda: plan_ha_resource_remove(vmid, kind))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_ha_resource_remove", tgt,
                    lambda: ha_resource_remove(api, vmid, kind),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_ha_rule_create(
    rule: Annotated[str, Field(description="New HA rule ID (name used to reference this rule).")],
    rule_type: Annotated[str, Field(description="Rule type: 'node-affinity' (requires nodes) or 'resource-affinity' (requires affinity).")],
    resources: Annotated[str, Field(description="Comma-separated HA resource SIDs the rule applies to, e.g. 'vm:100,ct:101'.")],
    comment: Annotated[str | None, Field(description="Free-text comment stored with the rule.")] = None,
    disable: Annotated[bool, Field(description="If True, the rule is created disabled (no effect until enabled).")] = False,
    nodes: Annotated[str | None, Field(description="Comma-separated node list with optional priority, e.g. 'pve1:2,pve2' — required for rule_type='node-affinity'.")] = None,
    strict: Annotated[bool, Field(description="node-affinity only: if True, resources may run ONLY on the listed nodes (availability risk if all are down).")] = False,
    affinity: Annotated[str | None, Field(description="'positive' (keep resources together) or 'negative' (keep resources apart) — required for rule_type='resource-affinity'.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the change.")] = False,
) -> dict:
    """MUTATION: create an HA rule (the PVE 9 replacement for HA groups). Dry-run by default — the
    PLAN shows the rule type, resources, and placement effect. `rule_type` is 'node-affinity'
    (needs `nodes`; optional `strict`) or 'resource-affinity' (needs `affinity` positive|negative).
    confirm=True to execute. Synchronous (pmxcfs config write, no UPID). RISK_MEDIUM — constrains
    CRM placement. View rules with pve_ha_rules_list; change one with pve_ha_rule_update.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"ha/rules/{rule}"
    plan = _plan("pve_ha_rule_create", tgt,
                 lambda: plan_ha_rule_create(rule, rule_type, resources, nodes, strict, affinity, disable))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_ha_rule_create", tgt,
                    lambda: ha_rule_create(api, rule, rule_type, resources, comment, disable,
                                           nodes, strict, affinity),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_ha_rule_update(
    rule: Annotated[str, Field(description="HA rule ID to update.")],
    comment: Annotated[str | None, Field(description="New free-text comment for the rule.")] = None,
    disable: Annotated[bool | None, Field(description="True to disable the rule, False to enable it, omit to leave unchanged.")] = None,
    resources: Annotated[str | None, Field(description="New comma-separated HA resource SIDs the rule applies to, e.g. 'vm:100,ct:101'.")] = None,
    rule_type: Annotated[str | None, Field(description="New rule type: 'node-affinity' or 'resource-affinity'.")] = None,
    nodes: Annotated[str | None, Field(description="New comma-separated node list with optional priority, e.g. 'pve1:2,pve2' (node-affinity rules).")] = None,
    strict: Annotated[bool | None, Field(description="node-affinity only: True restricts resources to ONLY the listed nodes.")] = None,
    affinity: Annotated[str | None, Field(description="'positive' or 'negative' (resource-affinity rules).")] = None,
    delete: Annotated[list[str] | None, Field(description="List of field names to unset on the rule, e.g. ['strict', 'nodes'].")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-locking; PUT is rejected if the stored digest differs.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the change.")] = False,
) -> dict:
    """MUTATION: update an HA rule. Dry-run by default — the PLAN shows the current rule and the
    fields being changed. `delete` unsets keys. confirm=True to execute. Synchronous (pmxcfs
    config write, no UPID). RISK_MEDIUM — may trigger CRM migration of affected resources.
    To create a new rule use pve_ha_rule_create; to remove one use pve_ha_rule_delete.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"ha/rules/{rule}"
    plan = _plan("pve_ha_rule_update", tgt,
                 lambda: plan_ha_rule_update(api, rule, comment, disable, resources, rule_type,
                                             nodes, strict, affinity, delete))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_ha_rule_update", tgt,
                    lambda: ha_rule_update(api, rule, comment, disable, resources, rule_type,
                                           nodes, strict, affinity, delete, digest),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_ha_rule_delete(
    rule: Annotated[str, Field(description="HA rule ID to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete an HA rule. Dry-run by default — the PLAN shows the current rule and that
    its resources lose this placement constraint (CRM may migrate them). confirm=True to execute.
    Synchronous (pmxcfs config write, no UPID) — no undo; re-create with pve_ha_rule_create to
    revert. RISK_MEDIUM.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"ha/rules/{rule}"
    plan = _plan("pve_ha_rule_delete", tgt, lambda: plan_ha_rule_delete(api, rule))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_ha_rule_delete", tgt,
                    lambda: ha_rule_delete(api, rule),
                    mutation=True, outcome="ok", detail={"confirmed": True})


# --- Task control + resource pools (read) ---

@tool()
def pve_tasks_list(
    node: Annotated[str | None, Field(description="Node to list tasks from; defaults to the configured node.")] = None,
    limit: Annotated[int, Field(description="Max number of most-recent tasks to return, max 1000 (0 or negative is rejected).")] = 50,
    errors: Annotated[bool, Field(description="If True, only return tasks that ended in error.")] = False,
    vmid: Annotated[str | None, Field(description="Optional VMID/CTID to filter tasks to a single guest.")] = None,
    typefilter: Annotated[str | None, Field(description="Optional task-type filter, e.g. 'vzdump', 'qmigrate' (PVE task type string).")] = None,
    statusfilter: Annotated[str | None, Field(description="Optional status filter, e.g. 'running', 'stopped'.")] = None,
) -> list[dict]:
    """READ-ONLY: list recent tasks on a node. limit max 1000 (higher is truncated; 0 or negative
    is rejected). No state change; returns a list of task dicts. Use pve_task_log for a task's full log.

    Caveat: this is a windowed, per-node slice — node defaults to the configured node, and
    only the `limit` most-recent tasks return. A task on another node or outside the window
    is absent without being dead. Never conclude a backup failed from absence here — verify
    against pve_backup_list or pbs_snapshots_list."""
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_tasks_list", node or cfg.node,
                    lambda: tasks_list(api, node, limit, errors, vmid, typefilter, statusfilter))


@tool()
def pve_task_log(
    upid: Annotated[str, Field(description="The task's Unique Process ID (UPID) string returned by an async operation.")],
    node: Annotated[str | None, Field(description="Node the task ran on; defaults to the configured node.")] = None,
    start: Annotated[int, Field(description="Line offset to start returning log output from (for pagination).")] = 0,
    limit: Annotated[int, Field(description="Max number of log lines to return.")] = 50,
) -> list[dict]:
    """Retrieve a task's log output by UPID (read-only). Returns the task's log lines with
    line numbers, paginated via start/limit. Use pve_task_wait for completion polling, or
    pve_tasks_list to find a UPID."""
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_task_log", upid, lambda: task_log(api, upid, node, start, limit))


@tool()
def pve_task_wait(
    upid: Annotated[str, Field(description="The task's Unique Process ID (UPID) string to poll for completion.")],
    node: Annotated[str | None, Field(description="Node the task ran on; defaults to the configured node.")] = None,
    timeout: Annotated[int, Field(description="Max seconds to wait for the task to reach a terminal state, clamped to 1-600.")] = 120,
    interval: Annotated[int, Field(description="Seconds between status polls, clamped to 1-60.")] = 2,
) -> dict:
    """Block until an async Proxmox task reaches a terminal state — or the timeout — then report the
    outcome (read). The ergonomic complement to the submit-an-async-op tools (migrate / backup /
    restore / clone / rollback / snapshot + guest create) that return a UPID: wait for completion
    without hand-rolling a pve_task_status poll loop.

    Returns {upid, finished, succeeded, status, exitstatus, timed_out, polls}. `succeeded` is
    fail-closed (finished AND exitstatus == "OK"); a failed or timed-out task is reported, not raised.
    timeout is clamped 1..600s, interval 1..60s. Use pve_task_log for the full log.

    (Proximo's native UPID model — NOT the MCP Tasks protocol, which was removed from the spec.)"""
    _, api, _, _ = _proximo_server._svc()
    t = max(1, min(int(timeout), 600))
    iv = max(1, min(int(interval), 60))

    def _do() -> dict:
        r = wait_for_task(lambda: api.task_status(upid, node), timeout=t, interval=iv)
        r["upid"] = upid
        return r

    return _audited("pve_task_wait", upid, _do)


@tool()
def pve_pools_list() -> list[dict]:
    """List all resource pools defined cluster-wide (read-only). Returns a list of pool dicts
    with pool IDs and optional comments. Use pve_pool_get to fetch a pool's detailed
    configuration and complete member list."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_pools_list", "cluster/pools", lambda: pools_list(api))


@tool()
def pve_pool_get(poolid: Annotated[str, Field(description="Pool ID to look up.")]) -> dict:
    """Retrieve a single resource pool's configuration and complete member list by pool ID
    (read-only). Returns the pool's config including all VMs and storage resources assigned.
    Use pve_pools_list to enumerate all pools."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_pool_get", f"pool/{poolid}", lambda: pool_get(api, poolid))


# --- Task control + resource pools (mutation) ---

@tool()
def pve_task_stop(
    upid: Annotated[str, Field(description="The task's Unique Process ID (UPID) string to cancel.")],
    node: Annotated[str | None, Field(description="Node the task is running on; defaults to the configured node.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the cancellation.")] = False,
) -> dict:
    """MUTATION (HIGH): stop (cancel) a running task. Dry-run by default — the PLAN warns that
    stopping a backup/restore/migration/clone mid-flight can leave the target inconsistent, with
    NO undo. confirm=True to execute. Synchronous cancellation signal (returns null, not a UPID) —
    the task may run briefly before it sees the signal. Find UPIDs to stop via pve_tasks_list."""
    _, api, _, _ = _proximo_server._svc()
    plan = _plan("pve_task_stop", upid, lambda: plan_task_stop(upid, node))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_task_stop", upid,
                    lambda: task_stop(api, upid, node),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_pool_create(
    poolid: Annotated[str, Field(description="New pool ID to create.")],
    comment: Annotated[str | None, Field(description="Free-text comment stored with the pool.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: create an (empty) resource pool. Dry-run by default (PLAN = additive, LOW).
    confirm=True to execute. Synchronous — typically returns null, no members yet; add
    guests/storage with pve_pool_update."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"pool/{poolid}"
    plan = _plan("pve_pool_create", tgt, lambda: plan_pool_create(poolid, comment))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_pool_create", tgt,
                    lambda: pool_create(api, poolid, comment),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_pool_update(
    poolid: Annotated[str, Field(description="Pool ID to update.")],
    vms: Annotated[str | None, Field(description="Comma-separated VMID/CTID list to add or remove from the pool.")] = None,
    storage: Annotated[str | None, Field(description="Comma-separated storage ID list to add or remove from the pool.")] = None,
    delete: Annotated[bool, Field(description="False (default) adds the given vms/storage as members; True removes them instead.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the change.")] = False,
) -> dict:
    """MUTATION: add (delete=False) or remove (delete=True) pool members. Dry-run by default —
    the PLAN notes membership re-scopes ACL coverage. confirm=True to execute. Synchronous, no
    UPID. delete=True with no vms/storage is refused (ambiguous). To remove the pool itself use
    pve_pool_delete."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"pool/{poolid}"
    plan = _plan("pve_pool_update", tgt,
                 lambda: plan_pool_update(poolid, vms, storage, delete))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_pool_update", tgt,
                    lambda: pool_update(api, poolid, vms, storage, delete),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_pool_delete(
    poolid: Annotated[str, Field(description="Pool ID to delete; the pool must be empty first.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a resource pool. Dry-run by default — the PLAN warns ACLs on /pool/{poolid}
    are orphaned and the pool must be empty first (members are NOT deleted; empty it first with
    pve_pool_update). confirm=True to execute. Synchronous — returns null."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"pool/{poolid}"
    plan = _plan("pve_pool_delete", tgt, lambda: plan_pool_delete(api, poolid))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_pool_delete", tgt,
                    lambda: pool_delete(api, poolid),
                    mutation=True, outcome="ok", detail={"confirmed": True})


# --- Storage administration (storage.cfg CRUD) ---

@tool()
def pve_storage_config_list() -> list[dict]:
    """READ-ONLY: list all storage definitions from storage.cfg cluster-wide. No state change.
    Returns a list of storage dicts with IDs, types, paths, and server addresses. Use
    pve_storage_config_get to fetch a single storage's complete configuration."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_storage_config_list", "cluster/storage",
                    lambda: storage_config_list(api))


@tool()
def pve_storage_config_get(storage: Annotated[str, Field(description="Storage ID to look up.")]) -> dict:
    """Retrieve a single storage definition from storage.cfg by storage ID (read-only).
    Returns the storage's complete configuration including type, paths, servers, and access
    settings. Use pve_storage_config_list to enumerate all storages."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_storage_config_get", f"storage/{storage}",
                    lambda: storage_config_get(api, storage))


@tool()
def pve_storage_create(
    storage: Annotated[str, Field(description="New storage ID (name used across the cluster).")],
    storage_type: Annotated[str, Field(description="PVE storage driver type, e.g. 'dir', 'nfs', 'pbs'.")],
    content: Annotated[str | None, Field(description="Comma-separated content types to allow, e.g. 'iso,backup,images'.")] = None,
    path: Annotated[str | None, Field(description="Filesystem path (required for storage_type='dir').")] = None,
    server: Annotated[str | None, Field(description="Remote host address (required for nfs/cifs/pbs).")] = None,
    export: Annotated[str | None, Field(description="NFS export path (required for storage_type='nfs').")] = None,
    nodes: Annotated[str | None, Field(description="Comma-separated node list this storage is available on; omit for all nodes.")] = None,
    disable: Annotated[bool, Field(description="If True, storage is created in a disabled state.")] = False,
    shared: Annotated[bool, Field(description="If True, marks storage as shared across all nodes.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: define a new cluster storage entry in storage.cfg (dir / nfs / pbs / cifs / …).

    This registers a storage *definition* the cluster can use; it does NOT format disks or provision
    a backend — to create a disk-backed backend (lvm/zfs/directory) on a node use
    pve_node_storage_backend_create. Required params depend on storage_type (dir needs `path`; nfs
    needs `server`+`export`). MEDIUM risk — a bad definition can fail to mount and slow cluster
    storage enumeration; no existing data is touched. Dry-run by default (returns a PLAN);
    confirm=True writes storage.cfg (the confirm result payload is typically null)."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"storage/{storage}"
    plan = _plan("pve_storage_create", tgt,
                 lambda: plan_storage_create(storage, storage_type, content, path, server,
                                             export, nodes, disable, shared))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_storage_create", tgt,
                    lambda: storage_create(api, storage, storage_type, content, path,
                                          server, export, nodes, disable, shared),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_storage_update(
    storage: Annotated[str, Field(description="Storage ID to update.")],
    content: Annotated[str | None, Field(description="New comma-separated content type list, e.g. 'iso,backup,images'.")] = None,
    nodes: Annotated[str | None, Field(description="New comma-separated node restriction list.")] = None,
    disable: Annotated[bool | None, Field(description="True to disable, False to enable, omit to leave unchanged.")] = None,
    shared: Annotated[bool | None, Field(description="True/False to set sharedness; omit to leave unchanged (must stay None for network-backed types like nfs/cifs/pbs, which reject an explicit shared flag).")] = None,
    delete: Annotated[str | None, Field(description="Comma-separated list of config fields to unset on the storage definition.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the change.")] = False,
) -> dict:
    """MUTATION: update a storage definition. Dry-run by default (disable=True warns guests lose
    disk access cluster-wide; a `nodes` change strands guests on excluded nodes). confirm=True to
    execute (synchronous, no UPID). The storage type itself can't be changed here — use
    pve_storage_delete then pve_storage_create instead."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"storage/{storage}"
    plan = _plan("pve_storage_update", tgt,
                 lambda: plan_storage_update(api, storage, content, nodes, disable, shared, delete))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_storage_update", tgt,
                    lambda: storage_update(api, storage, content, nodes, disable, shared, delete),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_storage_delete(
    storage: Annotated[str, Field(description="Storage ID to remove cluster-wide (definition only; data on disk is not erased).")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION (HIGH): remove a storage definition cluster-wide. Dry-run by default — the PLAN
    warns guest disks/backups living only there become inaccessible (data not erased). confirm=True
    executes — typically returns null; no undo except re-adding via pve_storage_create with the
    same config."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"storage/{storage}"
    plan = _plan("pve_storage_delete", tgt, lambda: plan_storage_delete(api, storage))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_storage_delete", tgt,
                    lambda: storage_delete(api, storage),
                    mutation=True, outcome="ok", detail={"confirmed": True})
