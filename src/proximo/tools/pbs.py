"""PBS (Proxmox Backup Server) deep read/mutation tools plus the PBS config + safety plane (datastores,
namespaces, remotes, traffic control, prune/verify/GC).

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.backup_schedules import pbs_scheduled_jobs_list
from proximo.pbs import (
    apt_changelog as pbs_apt_changelog_op,
)
from proximo.pbs import (
    apt_repositories_get as pbs_apt_repositories_get_op,
)
from proximo.pbs import (
    apt_repository_add as pbs_apt_repository_add_op,
)
from proximo.pbs import (
    apt_repository_set as pbs_apt_repository_set_op,
)
from proximo.pbs import (
    apt_update_refresh as pbs_apt_update_refresh_op,
)
from proximo.pbs import (
    apt_updates_list as pbs_apt_updates_list_op,
)
from proximo.pbs import (
    apt_versions as pbs_apt_versions_op,
)
from proximo.pbs import (
    datastore_list as pbs_datastore_list_op,
)
from proximo.pbs import (
    datastore_status as pbs_datastore_status_op,
)
from proximo.pbs import (
    gc_start as pbs_gc_start_op,
)
from proximo.pbs import (
    gc_status as pbs_gc_status_op,
)
from proximo.pbs import (
    namespace_create as pbs_namespace_create_op,
)
from proximo.pbs import (
    namespace_delete as pbs_namespace_delete_op,
)
from proximo.pbs import (
    namespace_list as pbs_namespace_list_op,
)
from proximo.pbs import (
    plan_apt_repository_add as pbs_plan_apt_repository_add,
)
from proximo.pbs import (
    plan_apt_repository_set as pbs_plan_apt_repository_set,
)
from proximo.pbs import (
    plan_apt_update_refresh as pbs_plan_apt_update_refresh,
)
from proximo.pbs import (
    plan_gc_start as pbs_plan_gc_start,
)
from proximo.pbs import (
    plan_namespace_create as pbs_plan_namespace_create,
)
from proximo.pbs import (
    plan_namespace_delete as pbs_plan_namespace_delete,
)
from proximo.pbs import (
    plan_prune as pbs_plan_prune,
)
from proximo.pbs import (
    plan_snapshot_delete as pbs_plan_snapshot_delete,
)
from proximo.pbs import (
    plan_verify_start as pbs_plan_verify_start,
)
from proximo.pbs import (
    prune as pbs_prune_op,
)
from proximo.pbs import (
    snapshot_delete as pbs_snapshot_delete_op,
)
from proximo.pbs import (
    snapshots_list as pbs_snapshots_list_op,
)
from proximo.pbs import (
    tasks_list as pbs_tasks_list_op,
)
from proximo.pbs import (
    verify_start as pbs_verify_start_op,
)
from proximo.pbs_config import (
    _remote_password_fingerprint,
)
from proximo.pbs_config import (
    datastore_create as pbs_cfg_datastore_create,
)
from proximo.pbs_config import (
    datastore_delete as pbs_cfg_datastore_delete,
)
from proximo.pbs_config import (
    datastore_get as pbs_cfg_datastore_get,
)
from proximo.pbs_config import (
    datastore_update as pbs_cfg_datastore_update,
)
from proximo.pbs_config import (
    group_change_owner as pbs_cfg_group_change_owner,
)
from proximo.pbs_config import (
    plan_datastore_create as pbs_plan_datastore_create,
)
from proximo.pbs_config import (
    plan_datastore_delete as pbs_plan_datastore_delete,
)
from proximo.pbs_config import (
    plan_datastore_update as pbs_plan_datastore_update,
)
from proximo.pbs_config import (
    plan_group_change_owner as pbs_plan_group_change_owner,
)
from proximo.pbs_config import (
    plan_remote_create as pbs_plan_remote_create,
)
from proximo.pbs_config import (
    plan_remote_delete as pbs_plan_remote_delete,
)
from proximo.pbs_config import (
    plan_remote_update as pbs_plan_remote_update,
)
from proximo.pbs_config import (
    plan_snapshot_notes_set as pbs_plan_snapshot_notes_set,
)
from proximo.pbs_config import (
    plan_snapshot_protected_set as pbs_plan_snapshot_protected_set,
)
from proximo.pbs_config import (
    plan_traffic_control_delete as pbs_plan_traffic_control_delete,
)
from proximo.pbs_config import (
    plan_traffic_control_upsert as pbs_plan_traffic_control_upsert,
)
from proximo.pbs_config import (
    remote_create as pbs_cfg_remote_create,
)
from proximo.pbs_config import (
    remote_delete as pbs_cfg_remote_delete,
)
from proximo.pbs_config import (
    remote_get as pbs_cfg_remote_get,
)
from proximo.pbs_config import (
    remote_update as pbs_cfg_remote_update,
)
from proximo.pbs_config import (
    remotes_list as pbs_cfg_remotes_list,
)
from proximo.pbs_config import (
    snapshot_notes_set as pbs_cfg_snapshot_notes_set,
)
from proximo.pbs_config import (
    snapshot_protected_set as pbs_cfg_snapshot_protected_set,
)
from proximo.pbs_config import (
    traffic_control_delete as pbs_cfg_traffic_control_delete,
)
from proximo.pbs_config import (
    traffic_control_upsert as pbs_cfg_traffic_control_upsert,
)
from proximo.pbs_config import (
    traffic_controls_list as pbs_cfg_traffic_controls_list,
)
from proximo.projection import cap_newest, classify_task_outcome, envelope_windowed, project_rows
from proximo.server import (
    _audited,
    _plan,
    run_governed,
    tool,
)

# --- PBS (Proxmox Backup Server) deep (read) ---

@tool()
def pbs_datastores_list() -> list[dict]:
    """READ-ONLY: List all PBS datastores. Returns datastore objects with store name,
    backend type, and mount status. Use pbs_datastore_status for runtime usage statistics
    or pbs_datastore_get for full configuration. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_datastores_list", "pbs/datastores",
                    lambda: pbs_datastore_list_op(pbs))


@tool()
def pbs_datastore_status(
    store: Annotated[str, Field(description="PBS datastore name.")],
) -> dict:
    """READ-ONLY: Get runtime usage statistics for one PBS datastore. Returns total
    capacity, used bytes, and available bytes. Use pbs_datastores_list to enumerate
    datastores (with backend type) or pbs_gc_status for garbage-collection state."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_datastore_status", f"pbs/{store}",
                    lambda: pbs_datastore_status_op(pbs, store))


@tool()
def pbs_gc_status(
    store: Annotated[str, Field(description="PBS datastore name.")],
) -> dict:
    """READ-ONLY: Get garbage-collection status for one PBS datastore. Returns current GC
    state, disk/index statistics, and pending/removed chunk counts (the GC schedule field
    appears only when a schedule is configured on the datastore).
    Use pbs_gc_start to execute garbage collection or pbs_datastore_status for capacity."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_gc_status", f"pbs/{store}/gc", lambda: pbs_gc_status_op(pbs, store))


@tool()
def pbs_snapshots_list(
    store: Annotated[str, Field(description="PBS datastore name.")],
    ns: Annotated[str | None, Field(description="Namespace path to filter by; omit for the root namespace.")] = None,
    backup_type: Annotated[str | None, Field(description="Backup type filter: 'vm', 'ct', or 'host'.")] = None,
    backup_id: Annotated[
        str | None, Field(description="Backup group ID (e.g. VMID/CTID or host name) to filter by."),
    ] = None,
    limit: Annotated[int | None, Field(description="Optional cap: return only the NEWEST N snapshots by backup-time. A limited listing is NOT evidence of absence — omit for the complete ground-truth list. Zero/negative is rejected.")] = None,
) -> list[dict]:
    """READ-ONLY: list backup snapshots in a PBS datastore with optional filters. Returns
    snapshot metadata including backup type, ID, timestamp, size, owner, and protection
    status; filter by namespace, backup_type (vm/ct/host), or backup_id. `limit` returns only
    the newest N — a capped slice is never evidence a snapshot is absent; omit it to verify
    one. To delete one use pbs_snapshot_delete; to change its protected flag or notes use
    pbs_snapshot_protected_set or pbs_snapshot_notes_set."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_snapshots_list", f"pbs/{store}",
                    lambda: cap_newest(
                        pbs_snapshots_list_op(pbs, store, ns, backup_type, backup_id),
                        limit, "backup-time"))


@tool()
def pbs_namespaces_list(
    store: Annotated[str, Field(description="PBS datastore name.")],
    parent: Annotated[
        str | None, Field(description="Parent namespace path to list children of; omit for the root namespace."),
    ] = None,
    max_depth: Annotated[int | None, Field(description="Maximum recursion depth below the parent namespace.")] = None,
) -> list[dict]:
    """READ-ONLY: List namespaces within a PBS datastore with optional hierarchical filtering.
    Returns each namespace's hierarchical path (the `ns` field); optionally filter by
    parent namespace or limit recursion depth. Use pbs_namespace_create to add namespaces."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_namespaces_list", f"pbs/{store}",
                    lambda: pbs_namespace_list_op(pbs, store, parent, max_depth))


@tool()
def pbs_remotes_list() -> list[dict]:
    """READ-ONLY: list all PBS remote sync-sources. Returns a list of remote config dicts;
    passwords are never included (PBS never returns them, and this strips defensively too).
    Use pbs_remote_get for one remote's config. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_remotes_list", "pbs/config/remote",
                    lambda: pbs_cfg_remotes_list(pbs))


@tool()
def pbs_remote_get(
    name: Annotated[str, Field(description="PBS remote sync-source name.")],
) -> dict:
    """READ-ONLY: get the config of one PBS remote sync-source by name. Returns a dict; no
    password returned. Use pbs_remotes_list to list all remotes, or pbs_remote_update to
    change this one. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_remote_get", f"pbs/config/remote/{name}",
                    lambda: pbs_cfg_remote_get(pbs, name))


@tool()
def pbs_traffic_controls_list() -> list[dict]:
    """READ-ONLY: list all PBS traffic-control bandwidth-limit rules. Returns active rules
    with their rate-in/rate-out limits, network targets, and comment. Use
    pbs_traffic_control_upsert to create or modify rules. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_traffic_controls_list", "pbs/config/traffic-control",
                    lambda: pbs_cfg_traffic_controls_list(pbs))


@tool()
def pbs_jobs_list(
    job_type: Annotated[str, Field(description="Scheduled-job type to list: 'sync', 'verify', or 'prune'.")],
) -> list[dict]:
    """READ-ONLY: list all PBS scheduled jobs of the given type. job_type = sync|verify|prune.
    Returns all jobs with their configs; raises on invalid job_type. Use pbs_job_create,
    pbs_job_update, or pbs_job_delete to manage one. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_jobs_list", f"pbs/config/{job_type}",
                    lambda: pbs_scheduled_jobs_list(pbs, job_type))


@tool()
def pbs_tasks_list(
    node: Annotated[
        str, Field(description="PBS node name; defaults to 'localhost' (standard single-node PBS name)."),
    ] = "localhost",
    limit: Annotated[int | None, Field(description="Maximum number of tasks to return.")] = None,
    running: Annotated[bool | None, Field(description="If True, return only currently-running tasks.")] = None,
    errors: Annotated[bool | None, Field(description="If True, return only tasks that ended in error. Live-proven on PBS: this returns WARNINGS rows.")] = None,
    fields: Annotated[str | None, Field(description="Response fields: omit for the lean default (upid/worker_type/worker_id/user/status/starttime/endtime), `all` for the full payload, or a comma-separated field list.")] = None,
) -> dict:
    """READ-ONLY: list PBS tasks on a node. Defaults to 'localhost' (standard single-node PBS
    name). Use this to check on a UPID returned by pbs_gc_start, pbs_verify_start,
    pbs_datastore_create, or pbs_datastore_delete. Needs PROXIMO_PBS_* config.

    Returns a windowed envelope — returned, by_outcome, and `tasks`: the rows in the lean
    default set. by_outcome (running/ok/warnings/failed/unknown) is classified server-side
    from each raw row's endtime + status, so a custom projection cannot skew it.

    PBS names its columns `worker_type`/`worker_id`, NOT PVE's `type`/`id` — same concept,
    different key. Asking for PVE's names here is REFUSED with the available names listed,
    not answered with quietly thinner rows — except on a window that returned zero rows,
    where there is nothing to validate against and the empty list comes back empty.

    Live-proven on PBS 4.2 (2026-08-13): a RUNNING row omits BOTH `endtime` and `status`
    entirely; a finished row carries `status` "OK" or "WARNINGS: n". errors=True returns the
    WARNINGS rows.

    The counts describe ONLY the returned window: with `limit` set, PBS truncates before this
    server sees a row, so an all-ok by_outcome must NEVER be read as "no task ever failed" —
    a failure older than the window is simply not in it."""
    _, pbs = _proximo_server._pbs()
    rows = _audited("pbs_tasks_list", f"pbs/nodes/{node}/tasks",
                    lambda: pbs_tasks_list_op(pbs, node, limit, running, errors))
    lean = project_rows(rows, fields,
                        ("upid", "worker_type", "worker_id", "user", "status", "starttime", "endtime"))
    return envelope_windowed(rows, lean, "tasks", classify_task_outcome)


@tool()
def pbs_datastore_get(
    name: Annotated[str, Field(description="PBS datastore name.")],
) -> dict:
    """READ-ONLY: Get full config of one PBS datastore by name. Returns path, gc-schedule, etc.
    For runtime usage stats use pbs_datastore_status instead. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_datastore_get", f"pbs/config/datastore/{name}",
                    lambda: pbs_cfg_datastore_get(pbs, name))


# --- PBS deep (mutation) ---

@tool()
def pbs_gc_start(
    store: Annotated[str, Field(description="PBS datastore name to run garbage collection on.")],
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION (HIGH): start garbage collection on a PBS datastore. Dry-run by default — GC
    permanently removes unreferenced chunks (no undo). confirm=True to execute; returns the
    UPID (async task) — check progress with pbs_gc_status or pbs_tasks_list."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/{store}/gc"
    return run_governed(
        "pbs_gc_start", tgt,
        plan=lambda: pbs_plan_gc_start(store),
        execute=lambda: pbs_gc_start_op(pbs, store),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_verify_start(
    store: Annotated[str, Field(description="PBS datastore name to verify.")],
    ns: Annotated[
        str | None, Field(description="Namespace path to scope verification to; omit for the root namespace."),
    ] = None,
    backup_type: Annotated[str | None, Field(description="Backup type filter: 'vm', 'ct', or 'host'.")] = None,
    backup_id: Annotated[
        str | None, Field(description="Backup group ID (e.g. VMID/CTID or host name) to scope verification to."),
    ] = None,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION: start an integrity verification run on a PBS datastore. Dry-run by default —
    non-destructive (read-only check) but heavy I/O. confirm=True to execute; returns the
    UPID (async task) — check progress with pbs_tasks_list."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/{store}/verify"
    return run_governed(
        "pbs_verify_start", tgt,
        plan=lambda: pbs_plan_verify_start(store, ns, backup_type, backup_id),
        execute=lambda: pbs_verify_start_op(pbs, store, ns, backup_type, backup_id),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_prune(
    store: Annotated[str, Field(description="PBS datastore name to prune.")],
    keep_last: Annotated[int | None, Field(description="Number of most-recent backups to always keep.")] = None,
    keep_daily: Annotated[int | None, Field(description="Number of daily backups to keep.")] = None,
    keep_weekly: Annotated[int | None, Field(description="Number of weekly backups to keep.")] = None,
    keep_monthly: Annotated[int | None, Field(description="Number of monthly backups to keep.")] = None,
    keep_yearly: Annotated[int | None, Field(description="Number of yearly backups to keep.")] = None,
    ns: Annotated[
        str | None, Field(description="Namespace path to scope pruning to; omit for the root namespace."),
    ] = None,
    backup_type: Annotated[str | None, Field(description="Backup type filter: 'vm', 'ct', or 'host'.")] = None,
    backup_id: Annotated[
        str | None, Field(description="Backup group ID (e.g. VMID/CTID or host name) to scope pruning to."),
    ] = None,
    dry_run: Annotated[
        bool, Field(description="PBS-side preview: True (default) previews only; False actually deletes snapshots."),
    ] = True,
    confirm: Annotated[
        bool, Field(description="Proximo dry-run gate: True executes (subject to dry_run); default only plans."),
    ] = False,
) -> dict:
    """MUTATION: prune backup snapshots per a retention policy. TWO safety gates: confirm
    (Proximo dry-run vs execute) AND dry_run (PBS-side preview). dry_run=True (default) only
    previews; dry_run=False DELETES recovery points (PLAN is HIGH, no undo). confirm=True to
    execute. Synchronous — returns prune decisions. For one specific snapshot use
    pbs_snapshot_delete instead."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/{store}/prune"
    return run_governed(
        "pbs_prune", tgt,
        plan=lambda: pbs_plan_prune(store, keep_last, keep_daily, keep_weekly,
                                        keep_monthly, keep_yearly, ns, backup_type,
                                        backup_id, dry_run),
        execute=lambda: pbs_prune_op(pbs, store, keep_last, keep_daily,
                                        keep_weekly, keep_monthly, keep_yearly,
                                        ns, backup_type, backup_id, dry_run),
        confirm=confirm, detail={"dry_run": dry_run})


@tool()
def pbs_snapshot_delete(
    store: Annotated[str, Field(description="PBS datastore name.")],
    backup_type: Annotated[str, Field(description="Backup type of the snapshot: 'vm', 'ct', or 'host'.")],
    backup_id: Annotated[str, Field(description="Backup group ID (e.g. VMID/CTID or host name).")],
    backup_time: Annotated[
        int, Field(description="Snapshot timestamp as a Unix epoch integer, identifying the exact backup run."),
    ],
    ns: Annotated[
        str | None, Field(description="Namespace path the snapshot lives in; omit for the root namespace."),
    ] = None,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION (HIGH): delete a specific backup snapshot (a recovery point) from a PBS
    datastore. Dry-run by default. Permanent — no undo. confirm=True to execute. Synchronous.
    To shield a snapshot instead of deleting it use pbs_snapshot_protected_set(protected=True);
    for bulk retention-based deletion use pbs_prune."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/{store}/{backup_type}/{backup_id}"
    return run_governed(
        "pbs_snapshot_delete", tgt,
        plan=lambda: pbs_plan_snapshot_delete(store, backup_type, backup_id, backup_time, ns),
        execute=lambda: pbs_snapshot_delete_op(pbs, store, backup_type, backup_id, backup_time, ns),
        confirm=confirm)


@tool()
def pbs_namespace_create(
    store: Annotated[str, Field(description="PBS datastore name.")],
    name: Annotated[str, Field(description="Namespace name/segment to create.")],
    parent: Annotated[
        str | None, Field(description="Parent namespace path to create under; omit for the root namespace."),
    ] = None,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION: create a namespace within a PBS datastore. Dry-run by default (additive, LOW).
    confirm=True to execute — returns {"status": "ok", "result": null}. Use pbs_namespaces_list to check for
    name collisions first, or pbs_namespace_delete to remove one."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/{store}/namespace/{name}"
    return run_governed(
        "pbs_namespace_create", tgt,
        plan=lambda: pbs_plan_namespace_create(store, name, parent),
        execute=lambda: pbs_namespace_create_op(pbs, store, name, parent),
        confirm=confirm)


@tool()
def pbs_namespace_delete(
    store: Annotated[str, Field(description="PBS datastore name.")],
    ns: Annotated[str, Field(description="Namespace path to delete.")],
    delete_groups: Annotated[
        bool, Field(description="If True, deletes groups/snapshots in namespace (HIGH, no undo); else must be empty."),
    ] = False,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION: delete a namespace from a PBS datastore. Dry-run by default — delete_groups=True
    is HIGH (it deletes all backup groups/snapshots inside the namespace, no undo). confirm=True
    to execute — returns {"status": "ok", "result": null}. Use pbs_namespaces_list to confirm it's empty first,
    or pbs_namespace_create to recreate an empty namespace afterward."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/{store}/namespace/{ns}"
    return run_governed(
        "pbs_namespace_delete", tgt,
        plan=lambda: pbs_plan_namespace_delete(store, ns, delete_groups),
        execute=lambda: pbs_namespace_delete_op(pbs, store, ns, delete_groups),
        confirm=confirm)


# --- PBS config + safety plane (Wave 5) ---

@tool()
def pbs_datastore_create(
    name: Annotated[str, Field(description="Name for the new PBS datastore.")],
    path: Annotated[str, Field(description="Filesystem path on the PBS node where the datastore will be created.")],
    gc_schedule: Annotated[
        str | None, Field(description="Garbage-collection schedule as a PBS calendar-event string (e.g. 'daily')."),
    ] = None,
    prune_schedule: Annotated[
        str | None, Field(description="Prune-job schedule as a PBS calendar-event string (e.g. 'daily')."),
    ] = None,
    notification_mode: Annotated[
        str | None, Field(description="Notification delivery mode for this datastore (PBS notification-mode value)."),
    ] = None,
    comment: Annotated[str | None, Field(description="Free-text comment/description for the datastore.")] = None,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION (MEDIUM): create a new PBS datastore at the given path.

    Dry-run by default — additive, but a misconfigured path can conflict with existing storage.
    PBS datastore creation is an async worker task (UPID) → outcome='submitted' (not 'ok').
    No rollback primitive. confirm=True to execute. Use pbs_datastores_list to check for
    name/path collisions first, or pbs_datastore_update to modify it afterward.

    POST /config/datastore
    Smoke-confirm: gc-schedule / prune-schedule / notification-mode param names; sync-vs-async.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{name}"
    return run_governed(
        "pbs_datastore_create", tgt,
        plan=lambda: pbs_plan_datastore_create(
                     name, path, gc_schedule=gc_schedule,
                     prune_schedule=prune_schedule,
                     notification_mode=notification_mode, comment=comment),
        execute=lambda: pbs_cfg_datastore_create(
                        pbs, name, path, gc_schedule=gc_schedule,
                        prune_schedule=prune_schedule,
                        notification_mode=notification_mode, comment=comment),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_datastore_update(
    name: Annotated[str, Field(description="PBS datastore name to update.")],
    gc_schedule: Annotated[
        str | None, Field(description="Garbage-collection schedule as a PBS calendar-event string (e.g. 'daily')."),
    ] = None,
    prune_schedule: Annotated[
        str | None, Field(description="Prune-job schedule as a PBS calendar-event string (e.g. 'daily')."),
    ] = None,
    notification_mode: Annotated[
        str | None, Field(description="Notification delivery mode for this datastore (PBS notification-mode value)."),
    ] = None,
    comment: Annotated[str | None, Field(description="Free-text comment/description for the datastore.")] = None,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION (MEDIUM): update PBS datastore configuration. Dry-run by default.

    CAPTURE: reads current config before planning; on read failure the plan is marked incomplete.
    Changing gc-schedule / prune-schedule affects data retention cluster-wide.
    No rollback primitive — revert by re-applying the captured config. confirm=True to execute.
    Use pbs_datastore_get to inspect current config, or pbs_datastore_delete to remove the
    datastore instead.

    PUT /config/datastore/{name}
    Smoke-confirm: accepted param names (hyphenated vs underscored).
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{name}"
    return run_governed(
        "pbs_datastore_update", tgt,
        plan=lambda: pbs_plan_datastore_update(
                     pbs, name, gc_schedule=gc_schedule,
                     prune_schedule=prune_schedule,
                     notification_mode=notification_mode, comment=comment),
        execute=lambda: pbs_cfg_datastore_update(
                        pbs, name, gc_schedule=gc_schedule,
                        prune_schedule=prune_schedule,
                        notification_mode=notification_mode, comment=comment),
        confirm=confirm)


@tool()
def pbs_datastore_delete(
    name: Annotated[str, Field(description="PBS datastore name to delete.")],
    destroy_data: Annotated[
        bool, Field(description="If True, destroys all backup data (HIGH, no undo); default only detaches config."),
    ] = False,
    keep_job_configs: Annotated[
        bool, Field(description="If True, keep job configs referencing this datastore instead of removing them."),
    ] = False,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION: delete a PBS datastore. Dry-run by default. RISK IS CONDITIONAL:

    destroy_data=False (default) → MEDIUM: detaches the datastore config; backup CHUNKS
      REMAIN ON DISK and the datastore is re-addable to recover.
    destroy_data=True → HIGH, IRREVERSIBLE: PERMANENTLY DESTROYS ALL backup data in the
      named datastore — no recovery possible.

    PBS deletion is an async worker task (UPID) → outcome='submitted'. confirm=True to execute.
    To recover from a destroy_data=False detach, re-add with pbs_datastore_create at the
    same path.

    DELETE /config/datastore/{name}
    Smoke-confirm: destroy-data / keep-job-configs param names; sync-vs-async.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{name}"
    return run_governed(
        "pbs_datastore_delete", tgt,
        plan=lambda: pbs_plan_datastore_delete(
                     name, destroy_data=destroy_data, keep_job_configs=keep_job_configs),
        execute=lambda: pbs_cfg_datastore_delete(
                        pbs, name, destroy_data=destroy_data,
                        keep_job_configs=keep_job_configs),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_snapshot_protected_set(
    store: Annotated[str, Field(description="PBS datastore name.")],
    backup_type: Annotated[str, Field(description="Backup type of the snapshot: 'vm', 'ct', or 'host'.")],
    backup_id: Annotated[str, Field(description="Backup group ID (e.g. VMID/CTID or host name).")],
    backup_time: Annotated[
        int, Field(description="Snapshot timestamp as a Unix epoch integer, identifying the exact backup run."),
    ],
    protected: Annotated[
        bool, Field(description="True shields the snapshot from pruning/GC (LOW); False allows auto-deletion (HIGH)."),
    ],
    ns: Annotated[
        str | None, Field(description="Namespace path the snapshot lives in; omit for the root namespace."),
    ] = None,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION: set or clear the protected flag on a PBS snapshot. RISK IS CONDITIONAL:

    protected=True  → LOW:  shields the snapshot from pruning and GC (protective).
    protected=False → HIGH: SILENTLY re-enables pruning/GC — this recovery point can now
      be auto-deleted by the next prune job or GC run. No undo once auto-deleted.

    No PBS snapshot primitive for rollback. Dry-run by default. confirm=True to execute.
    To annotate rather than protect a snapshot use pbs_snapshot_notes_set; to delete it
    outright use pbs_snapshot_delete.

    PUT /admin/datastore/{store}/protected
    Smoke-confirm: exact path + param names (backup-type, backup-id, backup-time, protected).
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/{store}/{backup_type}/{backup_id}@{backup_time}/protected"
    return run_governed(
        "pbs_snapshot_protected_set", tgt,
        plan=lambda: pbs_plan_snapshot_protected_set(
                     store, backup_type, backup_id, backup_time, protected, ns),
        execute=lambda: pbs_cfg_snapshot_protected_set(
                        pbs, store, backup_type, backup_id, backup_time, protected, ns),
        confirm=confirm)


@tool()
def pbs_snapshot_notes_set(
    store: Annotated[str, Field(description="PBS datastore name.")],
    backup_type: Annotated[str, Field(description="Backup type of the snapshot: 'vm', 'ct', or 'host'.")],
    backup_id: Annotated[str, Field(description="Backup group ID (e.g. VMID/CTID or host name).")],
    backup_time: Annotated[
        int, Field(description="Snapshot timestamp as a Unix epoch integer, identifying the exact backup run."),
    ],
    notes: Annotated[
        str, Field(description="Free-text notes to attach to the snapshot, replacing any existing notes."),
    ],
    ns: Annotated[
        str | None, Field(description="Namespace path the snapshot lives in; omit for the root namespace."),
    ] = None,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION (LOW): annotate a PBS snapshot with notes. Dry-run by default.

    CAPTURE: reads current notes before planning; on failure the plan is marked incomplete.
    Does not affect backup data, retention, or protection — to shield the snapshot from
    pruning/GC use pbs_snapshot_protected_set instead.
    No PBS snapshot primitive — revert by re-applying the captured notes. confirm=True to execute.

    PUT /admin/datastore/{store}/notes
    Smoke-confirm: exact endpoint path + param names (backup-type, backup-id, backup-time).
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/{store}/{backup_type}/{backup_id}@{backup_time}/notes"
    return run_governed(
        "pbs_snapshot_notes_set", tgt,
        plan=lambda: pbs_plan_snapshot_notes_set(
                     pbs, store, backup_type, backup_id, backup_time, notes, ns),
        execute=lambda: pbs_cfg_snapshot_notes_set(
                        pbs, store, backup_type, backup_id, backup_time, notes, ns),
        confirm=confirm)


@tool()
def pbs_group_change_owner(
    store: Annotated[str, Field(description="PBS datastore name.")],
    backup_type: Annotated[str, Field(description="Backup type of the group: 'vm', 'ct', or 'host'.")],
    backup_id: Annotated[str, Field(description="Backup group ID (e.g. VMID/CTID or host name).")],
    new_owner: Annotated[
        str, Field(description="PBS auth ID (user@realm or api-token) to become the new owner of the backup group."),
    ],
    ns: Annotated[
        str | None, Field(description="Namespace path the backup group lives in; omit for the root namespace."),
    ] = None,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION (MEDIUM): reassign the owner of a PBS backup group. Dry-run by default.

    The new owner controls deletion and prune of this backup group.
    The previous owner loses those permissions immediately. Use pbs_snapshots_list to see
    the group's current owner first.
    No PBS snapshot primitive — revert by re-assigning the owner back. confirm=True to execute.

    POST /admin/datastore/{store}/change-owner
    Smoke-confirm: exact path + new-owner vs owner param name.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/{store}/{backup_type}/{backup_id}/owner"
    return run_governed(
        "pbs_group_change_owner", tgt,
        plan=lambda: pbs_plan_group_change_owner(
                     store, backup_type, backup_id, new_owner, ns),
        execute=lambda: pbs_cfg_group_change_owner(
                        pbs, store, backup_type, backup_id, new_owner, ns),
        confirm=confirm)


@tool()
def pbs_remote_create(
    name: Annotated[str, Field(description="Name for the new PBS remote sync-source.")],
    host: Annotated[str, Field(description="Hostname or IP address of the remote PBS server.")],
    auth_id: Annotated[
        str, Field(description="PBS auth ID (user@realm or api-token) used to authenticate to the remote."),
    ],
    password: Annotated[
        str, Field(description="Password or API token secret for auth_id; redacted from all plans/logs/ledger."),
    ],
    fingerprint: Annotated[
        str | None, Field(description="TLS cert fingerprint of the remote PBS server (public data, not redacted)."),
    ] = None,
    port: Annotated[
        int | None, Field(description="TCP port of the remote PBS API; defaults to the standard PBS port if omitted."),
    ] = None,
    comment: Annotated[str | None, Field(description="Free-text comment/description for the remote.")] = None,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION (MEDIUM): create a PBS remote sync-source. Dry-run by default.

    PRIVATE PASSWORD REDACTION: 'password' is a remote user credential. It is
    UNCONDITIONALLY redacted from the server-side plan, change, current state, detail,
    and audit ledger. Only {"password":"[redacted]"} is recorded on those surfaces.
    L02 NOTE: the MCP tool-call itself is a structured JSON object in which 'password' appears
    as a plain parameter — it is visible in the LLM's output token stream and in any MCP client
    log. This is an MCP-protocol property; server-side redaction protects the ledger only.
    The TLS cert 'fingerprint' is PUBLIC data — it is NOT redacted.

    No rollback primitive — revert by deleting the remote (pbs_remote_delete). confirm=True to execute.

    POST /config/remote
    Smoke-confirm: auth-id vs authid param name; port param name.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/remote/{name}"
    # UNCONDITIONAL: password never passes through the plan factory or into the ledger.
    pw_detail = _remote_password_fingerprint()
    return run_governed(
        "pbs_remote_create", tgt,
        plan=lambda: pbs_plan_remote_create(
                     name, host, auth_id, fingerprint=fingerprint,
                     port=port, comment=comment),
        execute=lambda: pbs_cfg_remote_create(
                        pbs, name, host, auth_id, password,
                        fingerprint=fingerprint, port=port, comment=comment),
        confirm=confirm, surface=pw_detail)


@tool()
def pbs_remote_update(
    name: Annotated[str, Field(description="PBS remote sync-source name to update.")],
    host: Annotated[str | None, Field(description="New hostname or IP address of the remote PBS server.")] = None,
    auth_id: Annotated[
        str | None, Field(description="New PBS auth ID (user@realm or api-token) used to authenticate to the remote."),
    ] = None,
    password: Annotated[
        str | None, Field(description="New password or API token secret; redacted from plans/logs/ledger."),
    ] = None,
    fingerprint: Annotated[
        str | None, Field(description="New TLS cert fingerprint of the remote PBS server (public data, not redacted)."),
    ] = None,
    port: Annotated[int | None, Field(description="New TCP port of the remote PBS API.")] = None,
    comment: Annotated[str | None, Field(description="New free-text comment/description for the remote.")] = None,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION (MEDIUM): update an existing PBS remote. Dry-run by default.

    CAPTURE: reads current (non-secret) config before planning; on failure plan is marked incomplete.
    PRIVATE PASSWORD REDACTION: if 'password' is provided it is UNCONDITIONALLY redacted from the
    server-side plan, change, current state, detail, and audit ledger.
    L02 NOTE: the MCP tool-call itself is a structured JSON object in which 'password' appears as
    a plain parameter — visible in the LLM's output token stream and any MCP client log.
    This is an MCP-protocol property; server-side redaction protects the ledger only.
    The TLS cert 'fingerprint' is PUBLIC and appears in plans/logs for audit.
    No rollback primitive — revert by re-applying captured config. confirm=True to execute.
    Use pbs_remote_get to inspect current config first.

    PUT /config/remote/{name}
    Smoke-confirm: auth-id param name; whether partial PUT is accepted.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/remote/{name}"
    # UNCONDITIONAL if password provided: never into plan factory or ledger.
    pw_detail = _remote_password_fingerprint() if password is not None else {}
    plan = _plan("pbs_remote_update", tgt,
                 lambda: pbs_plan_remote_update(
                     pbs, name, host=host, auth_id=auth_id,
                     fingerprint=fingerprint, port=port, comment=comment))
    if not confirm:
        resp = {"status": "plan", **plan.as_dict()}
        if pw_detail:
            resp.update(pw_detail)
        return resp
    return _audited("pbs_remote_update", tgt,
                    lambda: pbs_cfg_remote_update(
                        pbs, name, host=host, auth_id=auth_id,
                        password=password, fingerprint=fingerprint,
                        port=port, comment=comment),
                    mutation=True, outcome="ok",
                    detail={**pw_detail, "confirmed": True})


@tool()
def pbs_remote_delete(
    name: Annotated[str, Field(description="PBS remote sync-source name to delete.")],
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION (MEDIUM): remove a PBS remote and its stored credentials. Dry-run by default.

    After deletion: any sync jobs referencing this remote break; re-add needs the password
    re-supplied. No rollback primitive — re-create with pbs_remote_create to recover.
    confirm=True to execute.

    DELETE /config/remote/{name}
    Smoke-confirm: response shape on success.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/remote/{name}"
    return run_governed(
        "pbs_remote_delete", tgt,
        plan=lambda: pbs_plan_remote_delete(name),
        execute=lambda: pbs_cfg_remote_delete(pbs, name),
        confirm=confirm)


@tool()
def pbs_traffic_control_upsert(
    name: Annotated[
        str, Field(description="Traffic-control rule name; creates it if new, updates it if it already exists."),
    ],
    rate_in: Annotated[int | None, Field(description="Sustained inbound bandwidth limit in bytes/second.")] = None,
    rate_out: Annotated[int | None, Field(description="Sustained outbound bandwidth limit in bytes/second.")] = None,
    network: Annotated[str | None, Field(description="Network/CIDR this rule applies to.")] = None,
    burst_in: Annotated[int | None, Field(description="Inbound burst bandwidth allowance in bytes.")] = None,
    burst_out: Annotated[int | None, Field(description="Outbound burst bandwidth allowance in bytes.")] = None,
    timeframe: Annotated[
        str | None, Field(description="Time window this rule is active (PBS traffic-control timeframe format)."),
    ] = None,
    comment: Annotated[str | None, Field(description="Free-text comment/description for the rule.")] = None,
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION: create or update a PBS traffic-control (bandwidth-limit) rule. Dry-run by default.

    Detects create-vs-update by reading the existing rule config (CAPTURE on update path):
      create → LOW:    additive, no existing rule changed.
      update → MEDIUM: changing rate limits can throttle backups or saturate the network.

    A too-low rate-in or rate-out throttles PBS backups to a crawl.
    No rollback primitive. confirm=True to execute. Use pbs_traffic_controls_list to see
    existing rules first, or pbs_traffic_control_delete to remove one.

    POST (create) or PUT (update) /config/traffic-control[/{name}]
    Smoke-confirm: create-vs-update dispatch; rate-in/rate-out/burst-in/burst-out/timeframe param names.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/traffic-control/{name}"
    return run_governed(
        "pbs_traffic_control_upsert", tgt,
        plan=lambda: pbs_plan_traffic_control_upsert(
                     pbs, name, rate_in=rate_in, rate_out=rate_out, network=network,
                     burst_in=burst_in, burst_out=burst_out, timeframe=timeframe,
                     comment=comment),
        execute=lambda: pbs_cfg_traffic_control_upsert(
                        pbs, name, rate_in=rate_in, rate_out=rate_out, network=network,
                        burst_in=burst_in, burst_out=burst_out, timeframe=timeframe,
                        comment=comment),
        confirm=confirm)


@tool()
def pbs_traffic_control_delete(
    name: Annotated[str, Field(description="Traffic-control rule name to delete.")],
    confirm: Annotated[
        bool, Field(description="Set True to execute; False (default) only returns the dry-run plan."),
    ] = False,
) -> dict:
    """MUTATION (MEDIUM): remove a PBS traffic-control (bandwidth-limit) rule. Dry-run by default.

    After deletion: backups run unthrottled on the matched network.
    Recoverable by re-creating the rule with pbs_traffic_control_upsert. confirm=True to execute.

    DELETE /config/traffic-control/{name}
    Smoke-confirm: response shape on success.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/traffic-control/{name}"
    return run_governed(
        "pbs_traffic_control_delete", tgt,
        plan=lambda: pbs_plan_traffic_control_delete(name),
        execute=lambda: pbs_cfg_traffic_control_delete(pbs, name),
        confirm=confirm)


# --- PBS APT plane (patch-visibility + repository governance, Wave 1b) ---
#
# HONESTY LINE, shipped in every docstring below: Proxmox's API deliberately does not expose
# upgrade execution; the upgrade itself happens at your console. This tool governs visibility
# and repo config only.
#
# PBS is typically single-node — node defaults to "localhost" directly (PbsConfig carries no
# .node field), matching pbs_tasks_list's existing precedent, unlike PVE/PMG's "node or cfg.node"
# idiom.


@tool()
def pbs_apt_updates_list(
    node: Annotated[str, Field(description="PBS node name; defaults to 'localhost' (standard single-node PBS name).")] = "localhost",
) -> list[dict]:
    """READ-ONLY: list available package updates (cached apt index) on a PBS node.

    GET /nodes/{node}/apt/update. Smoke-confirm: shape not live-verified — expected per-package
    dicts (Package/Title/Description/Origin/Version/OldVersion/Priority/Section/Arch). Proxmox's
    API deliberately does not expose upgrade execution; the upgrade itself happens at your
    console. This tool governs visibility only. To refresh this list first use
    pbs_apt_update_refresh. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_apt_updates_list", f"pbs/nodes/{node}/apt/update",
                    lambda: pbs_apt_updates_list_op(pbs, node))


@tool()
def pbs_apt_changelog(
    name: Annotated[str, Field(description="Package name to fetch the changelog for (e.g. as listed by pbs_apt_updates_list).")],
    node: Annotated[str, Field(description="PBS node name; defaults to 'localhost' (standard single-node PBS name).")] = "localhost",
    version: Annotated[str | None, Field(description="Specific package version to fetch the changelog for; omit for the latest available.")] = None,
) -> str:
    """READ-ONLY: get a package's changelog text on a PBS node.

    GET /nodes/{node}/apt/changelog?name=…[&version=…]. Smoke-confirm: shape not live-verified.
    The returned text is UPSTREAM/package-maintainer-authored (not Proxmox-authored) —
    classified ADVERSARIAL content (taint.ADVERSARIAL_TOOLS), like pve_apt_changelog and
    pmg_apt_changelog. Proxmox's API deliberately does not expose upgrade execution; the upgrade
    itself happens at your console. This tool governs visibility only. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_apt_changelog", f"pbs/nodes/{node}/apt/changelog:{name}",
                    lambda: pbs_apt_changelog_op(pbs, name, node, version))


@tool()
def pbs_apt_repositories_get(
    node: Annotated[str, Field(description="PBS node name; defaults to 'localhost' (standard single-node PBS name).")] = "localhost",
) -> dict:
    """READ-ONLY: get the current APT repository configuration of a PBS node.

    GET /nodes/{node}/apt/repositories. Smoke-confirm: shape not live-verified — expected
    {files, errors, digest, infos, standard-repos}. `files[].path` + entry index are the
    coordinates pbs_apt_repository_set needs; `standard-repos[].handle` is what
    pbs_apt_repository_add needs. Proxmox's API deliberately does not expose upgrade execution;
    the upgrade itself happens at your console. This tool governs visibility and repo config
    only. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_apt_repositories_get", f"pbs/nodes/{node}/apt/repositories",
                    lambda: pbs_apt_repositories_get_op(pbs, node))


@tool()
def pbs_apt_versions(
    node: Annotated[str, Field(description="PBS node name; defaults to 'localhost' (standard single-node PBS name).")] = "localhost",
) -> list[dict]:
    """READ-ONLY: get installed versions of important Proxmox Backup Server packages on a PBS node.

    GET /nodes/{node}/apt/versions. Smoke-confirm: shape not live-verified — expected
    per-package dicts (Package/Version/OldVersion + Arch/...). Proxmox's API deliberately does
    not expose upgrade execution; the upgrade itself happens at your console. This tool governs
    visibility only. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_apt_versions", f"pbs/nodes/{node}/apt/versions",
                    lambda: pbs_apt_versions_op(pbs, node))


@tool()
def pbs_apt_update_refresh(
    node: Annotated[str, Field(description="PBS node name; defaults to 'localhost' (standard single-node PBS name).")] = "localhost",
    notify: Annotated[bool | None, Field(description="If True, ask PBS to send a notification email about newly available packages.")] = None,
    quiet: Annotated[bool | None, Field(description="If True, ask PBS to omit progress output suitable only for interactive logging.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the index refresh.")] = False,
) -> dict:
    """MUTATION: resynchronize the APT package index on a PBS node (apt-get update).

    RISK_LOW: no package state change — refreshes the local index cache only. Proxmox's API
    deliberately does not expose upgrade execution; the upgrade itself happens at your console.
    This tool governs visibility only — it does NOT install or upgrade any package. Idempotent —
    safe to re-run any time. Dry-run by default (returns a PLAN); confirm=True executes (POST,
    Smoke-confirm) and returns {"status": "submitted"|"ok", "result": <task UPID | None>}.
    Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/nodes/{node}/apt/update"
    plan = _plan("pbs_apt_update_refresh", tgt,
                 lambda: pbs_plan_apt_update_refresh(node, notify, quiet))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    # apt_update_refresh() is documented "Returns a task UPID" but backends.py types it
    # `str | None` defensively (same honesty posture as pve_apt_update_refresh) — a fixed
    # outcome="submitted" would falsely claim an in-flight task if PBS ever answers
    # synchronously. _audited()'s callable-outcome form resolves the honest label from the
    # actual result.
    return _audited("pbs_apt_update_refresh", tgt,
                    lambda: pbs_apt_update_refresh_op(pbs, node, notify, quiet),
                    mutation=True, outcome=lambda result: "ok" if result is None else "submitted",
                    detail={"confirmed": True,
                            **({"notify": notify} if notify is not None else {}),
                            **({"quiet": quiet} if quiet is not None else {})})


@tool()
def pbs_apt_repository_set(
    path: Annotated[str, Field(description="Absolute path of the sources file containing the repository entry (as returned by pbs_apt_repositories_get).")],
    index: Annotated[int, Field(description="0-based index of the repository entry within that file (as returned by pbs_apt_repositories_get).")],
    node: Annotated[str, Field(description="PBS node name; defaults to 'localhost' (standard single-node PBS name).")] = "localhost",
    enabled: Annotated[bool | None, Field(description="Set the entry's enabled state; omit to leave the enabled state unchanged.")] = None,
    digest: Annotated[str | None, Field(description="Expected SHA-256 content digest (64 hex chars) of the repositories file, for optimistic-concurrency conflict detection.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the change.")] = False,
) -> dict:
    """MUTATION: enable/disable one APT repository entry on a PBS node, by file path + index.

    RISK_MEDIUM: changes where packages come from — affects the NEXT upgrade's package
    provenance. CAPTURE: reads current repository state before planning (also readable directly
    via pbs_apt_repositories_get); if unreadable -> complete=False. Proxmox's API deliberately
    does not expose upgrade execution; the upgrade itself happens at your console. This tool
    governs repo config only. Dry-run by default (returns a PLAN); confirm=True executes (POST,
    Smoke-confirm) and returns {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/nodes/{node}/apt/repositories:{path}#{index}"
    return run_governed(
        "pbs_apt_repository_set", tgt,
        plan=lambda: pbs_plan_apt_repository_set(pbs, path, index, node, enabled, digest),
        execute=lambda: pbs_apt_repository_set_op(pbs, path, index, node, enabled, digest),
        confirm=confirm, detail={"path": path, "index": index})


@tool()
def pbs_apt_repository_add(
    handle: Annotated[str, Field(description="Handle identifying the standard repository to add (as returned by pbs_apt_repositories_get's standard-repos list, e.g. 'no-subscription'). PBS requires a lowercase-leading handle.")],
    node: Annotated[str, Field(description="PBS node name; defaults to 'localhost' (standard single-node PBS name).")] = "localhost",
    digest: Annotated[str | None, Field(description="Expected SHA-256 content digest (64 hex chars) of the repositories file, for optimistic-concurrency conflict detection.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the addition.")] = False,
) -> dict:
    """MUTATION: add a standard repository to the configuration on a PBS node.

    RISK_MEDIUM: adds a new package source — affects the NEXT upgrade's package provenance.
    CAPTURE: reads current repository state before planning (also readable directly via
    pbs_apt_repositories_get); if unreadable -> complete=False. No automatic revert: removing an
    added repository requires pbs_apt_repository_set to disable the resulting entry (there is no
    repository-delete endpoint). Proxmox's API deliberately does not expose upgrade execution;
    the upgrade itself happens at your console. This tool governs repo config only. Dry-run by
    default (returns a PLAN); confirm=True executes (PUT, Smoke-confirm) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/nodes/{node}/apt/repositories:{handle}"
    return run_governed(
        "pbs_apt_repository_add", tgt,
        plan=lambda: pbs_plan_apt_repository_add(pbs, handle, node, digest),
        execute=lambda: pbs_apt_repository_add_op(pbs, handle, node, digest),
        confirm=confirm, detail={"handle": handle})
