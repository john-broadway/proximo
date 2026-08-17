"""PDM (Proxmox Datacenter Manager) read-only tools.

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.projection import (
    cap_newest,
    classify_task_outcome,
    envelope_rows,
    envelope_windowed,
    project_rows,
)
from proximo.server import (
    _audited,
    tool,
)

# --- PDM (Proxmox Datacenter Manager) read-only ---

@tool()
def pdm_ping() -> str:
    """READ-ONLY: health check the PDM appliance.

    No state change. Returns the string 'pong' on success; raises on connection/auth failure.
    For version details instead of a bare health check, use pdm_version. Needs PROXIMO_PDM_*
    config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_ping", "pdm/ping", lambda: pdm.ping())


@tool()
def pdm_version() -> dict:
    """READ-ONLY: get the PDM appliance's own version info.

    No state change. Returns a dict with release, repoid, and version. For a lightweight health
    check instead, use pdm_ping. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_version", "pdm/version", lambda: pdm.version())


@tool()
def pdm_node_status(
    node: Annotated[str, Field(description="PDM node name; PDM is single-node so this defaults to 'localhost'.")] = "localhost",
) -> dict:
    """READ-ONLY: get resource stats for the PDM appliance's own node (not a managed remote's node).

    No state change. Returns a dict shaped like PVE node status; live-prove-pending (not yet
    confirmed live). Defaults to node='localhost' since PDM is single-node. For a managed PVE
    node's status instead, use pve_node_status. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_node_status", f"pdm/nodes/{node}", lambda: pdm.node_status(node))


@tool()
def pdm_remotes_list() -> list[dict]:
    """READ-ONLY: list all PVE/PBS remotes registered in PDM (the datacenters/backup targets it manages).

    No state change. Returns a list of remote dicts; credential-shaped keys (token/password/secret)
    are stripped before returning. For one remote's version or config use pdm_remote_version /
    pdm_remote_config_get. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_remotes_list", "pdm/remotes", lambda: pdm.remotes_list())


@tool()
def pdm_remote_version(
    remote_id: Annotated[str, Field(description="Remote name as shown in pdm_remotes_list.")],
) -> dict:
    """READ-ONLY: get version info for one PDM-registered remote, proxied through PDM.

    No state change. Returns a dict (the remote's own /version response). To see all registered
    remotes first, use pdm_remotes_list. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_remote_version", f"pdm/remotes/{remote_id}",
                    lambda: pdm.remote_version(remote_id))


@tool()
def pdm_remote_config_get(
    remote_id: Annotated[str, Field(description="Remote name as shown in pdm_remotes_list.")],
) -> dict:
    """READ-ONLY: get configuration for one PDM-registered remote.

    No state change. Returns a dict; credential-shaped keys (token/password/secret) are stripped
    before returning. To see all registered remotes first, use pdm_remotes_list. Needs
    PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_remote_config_get", f"pdm/remotes/{remote_id}",
                    lambda: pdm.remote_config_get(remote_id))


@tool()
def pdm_resources_list() -> dict:
    """READ-ONLY: list every fleet resource (VMs, LXCs, storage, etc.) across ALL PDM-registered remotes.

    No state change. Returns a counted envelope — total, by_type, and `resources`: the
    resource dicts. Trust total/by_type for count questions; they are computed server-side
    from the full listing. For counters instead of the full list, use pdm_resources_status;
    to scope to one remote, use pdm_pve_resources. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    rows = _audited("pdm_resources_list", "pdm/resources/list", lambda: pdm.resources_list())
    return envelope_rows(rows, rows, "resources", "type")


@tool()
def pdm_resources_status() -> dict:
    """READ-ONLY: aggregated fleet status counters (running VMs, LXCs, failed remotes, etc.)
    across all PDM-registered remotes.

    No state change. Returns a dict of counters. For the underlying per-resource list, use
    pdm_resources_list. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_resources_status", "pdm/resources/status",
                    lambda: pdm.resources_status())


@tool()
def pdm_pve_resources(
    remote: Annotated[str, Field(description="PDM-registered PVE remote name, from pdm_remotes_list.")],
    kind: Annotated[str | None, Field(description="Optional resource-type filter, e.g. 'vm', 'storage', 'node', 'sdn'.")] = None,
) -> dict:
    """READ-ONLY: list resources on ONE PDM-registered PVE remote, proxied through PDM.

    No state change. Returns a counted envelope — total, by_type, and `resources`: dicts
    shaped like PVE's cluster/resources (live-proven 2026-06-27); kind optionally filters by
    type (vm, storage, node, sdn, ...). To query the cluster directly without PDM, use
    pve_cluster_resources. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    rows = _audited("pdm_pve_resources", f"pdm/pve/{remote}/resources",
                    lambda: pdm.pve_resources(remote, kind))
    return envelope_rows(rows, rows, "resources", "type")


@tool()
def pdm_pve_cluster_status(
    remote: Annotated[str, Field(description="PDM-registered PVE remote name, from pdm_remotes_list.")],
) -> list[dict]:
    """READ-ONLY: get cluster status for ONE PDM-registered PVE remote, proxied through PDM.

    No state change. Returns a list of dicts shaped like PVE's cluster/status (live-proven
    2026-06-27). To query the cluster directly without PDM, use pve_cluster_status. Needs
    PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_pve_cluster_status", f"pdm/pve/{remote}/cluster-status",
                    lambda: pdm.pve_cluster_status(remote))


@tool()
def pdm_pve_node_list(
    remote: Annotated[str, Field(description="PDM-registered PVE remote name, from pdm_remotes_list.")],
) -> list[dict]:
    """READ-ONLY: list PVE nodes in a PDM-registered remote's cluster, proxied through PDM.

    No state change. Returns a list of dicts shaped like PVE's /nodes endpoint (live-proven
    2026-06-27). Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_pve_node_list", f"pdm/pve/{remote}/nodes",
                    lambda: pdm.pve_node_list(remote))


@tool()
def pdm_pve_qemu_list(
    remote: Annotated[str, Field(description="PDM-registered PVE remote name, from pdm_remotes_list.")],
    node: Annotated[str | None, Field(description="Optional PVE node name to restrict the listing to; omit to list cluster-wide.")] = None,
) -> dict:
    """READ-ONLY: list VMs across a PDM-registered PVE remote (cluster-wide), proxied through PDM.

    No state change. Returns a counted envelope — total, by_status, and `vms`: dicts shaped
    like PVE's qemu list (live-proven 2026-06-27); node optionally filters to one PVE node.
    Trust total/by_status for count questions. For one VM's config use pdm_pve_qemu_config;
    to query the cluster directly without PDM, use pve_list_guests. Needs PROXIMO_PDM_*
    config."""
    _, pdm = _proximo_server._pdm()
    rows = _audited("pdm_pve_qemu_list", f"pdm/pve/{remote}/qemu",
                    lambda: pdm.pve_qemu_list(remote, node))
    return envelope_rows(rows, rows, "vms", "status")


@tool()
def pdm_pve_qemu_config(
    remote: Annotated[str, Field(description="PDM-registered PVE remote name, from pdm_remotes_list.")],
    vmid: Annotated[str, Field(description="Numeric VM ID on the remote.")],
    node: Annotated[str | None, Field(description="Optional PVE node name; not required for PDM to resolve the VM.")] = None,
    snapshot: Annotated[str | None, Field(description="Optional snapshot name to read config from instead of the live config.")] = None,
    state: Annotated[str, Field(description="PDM config-state selector, required by the PDM API; 'active' returns the current config.")] = "active",
) -> dict:
    """READ-ONLY: get a VM's config from a PDM-registered PVE remote, proxied through PDM.

    No state change. Returns a dict (live-proven 2026-06-27). state defaults to "active" and is
    REQUIRED by PDM's API (it 400s if omitted); node/snapshot are optional. To query the cluster
    directly without PDM, use pve_guest_config_get. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_pve_qemu_config", f"pdm/pve/{remote}/qemu/{vmid}",
                    lambda: pdm.pve_qemu_config(remote, vmid, node, snapshot, state))


@tool()
def pdm_pve_lxc_list(
    remote: Annotated[str, Field(description="PDM-registered PVE remote name, from pdm_remotes_list.")],
    node: Annotated[str | None, Field(description="Optional PVE node name to restrict the listing to; omit to list cluster-wide.")] = None,
) -> dict:
    """READ-ONLY: list LXC containers across a PDM-registered PVE remote (cluster-wide), proxied
    through PDM.

    No state change. Returns a counted envelope — total, by_status, and `containers`: dicts
    shaped like PVE's lxc list (live-proven 2026-06-27); node optionally filters to one PVE
    node. Trust total/by_status for count questions. For one container's config use
    pdm_pve_lxc_config; to query the cluster directly without PDM, use pve_list_guests. Needs
    PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    rows = _audited("pdm_pve_lxc_list", f"pdm/pve/{remote}/lxc",
                    lambda: pdm.pve_lxc_list(remote, node))
    return envelope_rows(rows, rows, "containers", "status")


@tool()
def pdm_pve_lxc_config(
    remote: Annotated[str, Field(description="PDM-registered PVE remote name, from pdm_remotes_list.")],
    vmid: Annotated[str, Field(description="Numeric CT ID on the remote.")],
    node: Annotated[str | None, Field(description="Optional PVE node name; not required for PDM to resolve the container.")] = None,
    snapshot: Annotated[str | None, Field(description="Optional snapshot name to read config from instead of the live config.")] = None,
    state: Annotated[str, Field(description="PDM config-state selector, required by the PDM API; 'active' returns the current config.")] = "active",
) -> dict:
    """READ-ONLY: get an LXC container's config from a PDM-registered PVE remote, proxied through PDM.

    No state change. Returns a dict (live-proven 2026-06-27). state defaults to "active" and is
    REQUIRED by PDM's API (it 400s if omitted); node/snapshot are optional. To query the cluster
    directly without PDM, use pve_guest_config_get. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_pve_lxc_config", f"pdm/pve/{remote}/lxc/{vmid}",
                    lambda: pdm.pve_lxc_config(remote, vmid, node, snapshot, state))


@tool()
def pdm_pbs_remote_status(
    remote: Annotated[str, Field(description="PDM-registered PBS remote name, from pdm_remotes_list.")],
) -> dict:
    """READ-ONLY: get node status (cpu/memory/uptime, etc.) for a PDM-registered PBS remote,
    proxied through PDM.

    No state change. Returns a dict (live-verified, PDM 1.1 -> PBS 4.2). For the remote's
    datastores, use pdm_pbs_datastores_list. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_pbs_remote_status", f"pdm/pbs/{remote}/status",
                    lambda: pdm.pbs_remote_status(remote))


@tool()
def pdm_pbs_datastores_list(
    remote: Annotated[str, Field(description="PDM-registered PBS remote name, from pdm_remotes_list.")],
) -> list[dict]:
    """READ-ONLY: list datastores on a PDM-registered PBS remote, proxied through PDM.

    No state change. Returns [{"name", "path"}, ...] (live-verified, PDM 1.1 -> PBS 4.2). For
    snapshots within a datastore use pdm_pbs_snapshots_list; to query PBS directly without PDM,
    use pbs_datastores_list. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_pbs_datastores_list", f"pdm/pbs/{remote}/datastore",
                    lambda: pdm.pbs_datastores_list(remote))


@tool()
def pdm_pbs_snapshots_list(
    remote: Annotated[str, Field(description="PDM-registered PBS remote name, from pdm_remotes_list.")],
    datastore: Annotated[str, Field(description="PBS datastore name on the remote to list snapshots from.")],
    ns: Annotated[str | None, Field(description="Optional PBS namespace filter; omit to use the default namespace.")] = None,
    limit: Annotated[int | None, Field(description="Optional cap: return only the NEWEST N snapshots by backup-time. A limited listing is NOT evidence of absence — omit for the complete list. Zero/negative is rejected.")] = None,
) -> list[dict]:
    """READ-ONLY: list backup snapshots in one datastore on a PDM-registered PBS remote, proxied
    through PDM. `limit` returns only the newest N — a capped slice is never evidence a
    snapshot is absent; omit it to verify one.

    No state change. Returns a list of snapshot dicts (empty list if the datastore has none);
    live-verified (PDM 1.1 -> PBS 4.2). ns optionally filters by namespace. To query PBS
    directly without PDM, use pbs_snapshots_list. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_pbs_snapshots_list",
                    f"pdm/pbs/{remote}/datastore/{datastore}/snapshots",
                    lambda: cap_newest(pdm.pbs_snapshots_list(remote, datastore, ns),
                                       limit, "backup-time"))


@tool()
def pdm_tasks_list(
    limit: Annotated[int | None, Field(description="Optional cap: return only the NEWEST N tasks by starttime. A limited listing is NOT evidence of absence — omit for the complete list. Zero/negative is rejected.")] = None,
    fields: Annotated[str | None, Field(description="Response fields: omit for the lean default (upid/node/worker_type/worker_id/user/status/starttime/endtime), `all` for the full payload, or a comma-separated field list.")] = None,
) -> dict:
    """READ-ONLY: list recent PDM tasks (queued/running/finished operations) across all
    registered remotes. No state change. Needs PROXIMO_PDM_* config.

    Returns a windowed envelope — returned, by_outcome, and `tasks`: the rows in the lean
    default set. by_outcome (running/ok/warnings/failed/unknown) is classified server-side
    from each raw row's endtime + status, so a custom projection cannot skew it.

    Two PDM-specific shapes, both live-proven 2026-08-13 and both easy to get wrong:
    `upid` is REMOTE-QUALIFIED (`pve:pve-test4!UPID:pve-test4:…`), not the bare UPID the other
    planes return, and `node` names the REMOTE's node — it is the only place the remote's
    identity appears outside that prefix, which is why the lean set keeps it. Columns are
    `worker_type`/`worker_id` as on PBS, NOT PVE's `type`/`id`.

    Live-proven: finished rows carry `status` "OK" or the raw error TEXT (e.g. "snapshot
    feature is not available", "Cluster join aborted!"), so bucketing on that string would
    hand a model a fresh key per failure — by_outcome exists to stop that.

    `limit` returns only the newest N by starttime; a limited listing is NOT evidence of
    absence. Unlike PBS and PMG, which push `limit` into the query and truncate server-side,
    PDM's endpoint is asked for everything it will give and THIS server applies the cap. So
    `returned` counts what was kept, and there is still no `total`: what the endpoint itself
    windows before answering has not been measured, and a number we have not proven describes
    the population must not wear its name. For a target remote's own task list directly, use
    pve_tasks_list."""
    _, pdm = _proximo_server._pdm()
    rows = _audited("pdm_tasks_list", "pdm/remotes/tasks",
                    lambda: cap_newest(pdm.tasks_list(), limit, "starttime"))
    lean = project_rows(rows, fields,
                        ("upid", "node", "worker_type", "worker_id", "user", "status",
                         "starttime", "endtime"))
    return envelope_windowed(rows, lean, "tasks", classify_task_outcome)


@tool()
def pdm_acl_list(
    path: Annotated[str | None, Field(description="Optional ACL path filter, e.g. '/'; omit to list all entries.")] = None,
    exact: Annotated[bool, Field(description="If true, match the given path exactly rather than including sub-paths.")] = False,
) -> list[dict]:
    """READ-ONLY: list PDM's own access control entries (who can use PDM, not a managed remote's ACL).

    No state change. Returns a list of ACL entry dicts. exact=True restricts to the given path
    instead of including sub-paths. For a managed PVE cluster's ACL instead of PDM's own, use
    pve_acl_list. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_acl_list", "pdm/access/acl",
                    lambda: pdm.acl_list(path, exact))


@tool()
def pdm_roles_list() -> list[dict]:
    """READ-ONLY: list PDM's own roles and their privileges (not a managed remote's roles).

    No state change. Returns a list of role dicts. For a managed PVE cluster's roles instead of
    PDM's own, use pve_roles_list. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_roles_list", "pdm/access/roles", lambda: pdm.roles_list())


@tool()
def pdm_users_list(
    include_tokens: Annotated[bool, Field(description="If true, include API token entries alongside user accounts.")] = False,
) -> list[dict]:
    """READ-ONLY: list PDM's own user accounts (not a managed remote's users).

    No state change. Returns a list of user dicts; credential-shaped keys are stripped before
    returning. include_tokens=True also includes API token entries. For a managed PVE cluster's
    users instead of PDM's own, use pve_users_list. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_users_list", "pdm/access/users",
                    lambda: pdm.users_list(include_tokens))
