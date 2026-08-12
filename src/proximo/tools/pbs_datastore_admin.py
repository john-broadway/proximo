"""PBS datastore-admin remainder wrappers (Wave 5d, full-surface campaign — the ACTUAL PBS
plane closer, built from the Wave 5c adversarial review's Finding 1+2 endpoint list). See
`proximo.pbs_datastore_admin` module docstring for the full endpoint table, the schema-verified
facts, and the risk-rating reasoning; see `proximo.pbs_admin`'s PLANE-CLOSE HONESTY NOTE for the
now-self-contained exclusion list this module completes.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_datastore_admin import (
    datastore_active_operations,
    datastore_mount,
    datastore_prune,
    datastore_rrd,
    datastore_s3_refresh,
    datastore_unmount,
    datastores_usage,
    group_delete,
    group_move,
    group_notes_get,
    group_notes_set,
    groups_list,
    namespace_move,
    plan_datastore_mount,
    plan_datastore_prune,
    plan_datastore_s3_refresh,
    plan_datastore_unmount,
    plan_group_delete,
    plan_group_move,
    plan_group_notes_set,
    plan_namespace_move,
    remote_scan,
    remote_scan_groups,
    remote_scan_namespaces,
    snapshot_protected_get,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)


def _submitted_or_ok(result) -> str:
    """Outcome resolver for the six UPID-declared mutations (module docstring fact #3):
    schema-faithful "submitted" when the UPID arrives, honest "ok" if a PBS version returns
    nothing — the same callable idiom as pbs_job_run/pve_backup_delete."""
    return "submitted" if result else "ok"


# --- Reads: group management ---

@tool()
def pbs_groups_list(
    store: Annotated[str, Field(description="PBS datastore name.")],
    ns: Annotated[str | None, Field(description="Namespace to list groups in; omit for the root namespace.")] = None,
) -> list[dict]:
    """READ-ONLY: list backup groups in a PBS datastore (backup-type/backup-id, snapshot count,
    last-backup time, owner, files, comment). ADVERSARIAL: backup ids and the notes-derived
    comment are guest/operator-influenced free text (pbs_snapshots_list precedent). Group-level
    view — pbs_snapshots_list shows the individual snapshots inside a group. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{store}/groups" + (f"/{ns}" if ns else "")
    return _audited("pbs_groups_list", tgt, lambda: groups_list(pbs, store, ns))


@tool()
def pbs_group_notes_get(
    store: Annotated[str, Field(description="PBS datastore name.")],
    backup_type: Annotated[str, Field(description="Backup type: vm, ct, or host.")],
    backup_id: Annotated[str, Field(description="Backup group ID (e.g. VMID/CTID or host name).")],
    ns: Annotated[str | None, Field(description="Namespace; omit for the root namespace.")] = None,
) -> str:
    """READ-ONLY: get the full free-text notes body for a backup GROUP — distinct from the
    snapshot-level pbs_snapshot_notes_set/get pair (group vs. individual snapshot). ADVERSARIAL
    (free text). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{store}/group-notes/{backup_type}/{backup_id}" + (f"/{ns}" if ns else "")
    return _audited("pbs_group_notes_get", tgt,
                    lambda: group_notes_get(pbs, store, backup_type, backup_id, ns))


@tool()
def pbs_snapshot_protected_get(
    store: Annotated[str, Field(description="PBS datastore name.")],
    backup_type: Annotated[str, Field(description="Backup type: vm, ct, or host.")],
    backup_id: Annotated[str, Field(description="Backup group ID.")],
    backup_time: Annotated[int, Field(description="Snapshot timestamp (Unix epoch).")],
    ns: Annotated[str | None, Field(description="Namespace; omit for the root namespace.")] = None,
) -> object:
    """READ-ONLY: query the protection flag for a specific backup snapshot — the READ half of
    the shipped pbs_snapshot_protected_set. The live schema declares this endpoint's return
    type null despite implying a real answer (the plausible return is the protection boolean the
    paired PUT sets) — passed through as-is. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = (f"pbs/datastore/{store}/protected/{backup_type}/{backup_id}@{backup_time}"
           + (f"/{ns}" if ns else ""))
    return _audited("pbs_snapshot_protected_get", tgt,
                    lambda: snapshot_protected_get(pbs, store, backup_type, backup_id,
                                                   backup_time, ns))


# --- Reads: telemetry odds ---

@tool()
def pbs_datastore_rrd(
    store: Annotated[str, Field(description="PBS datastore name.")],
    cf: Annotated[str, Field(description="RRD consolidation function: 'MAX' or 'AVERAGE'. REQUIRED — no server-side default.")],
    timeframe: Annotated[str, Field(description="Rolling RRD window ENDING NOW: hour, day, week, month, year, or decade. REQUIRED — no server-side default. 'day' is the last ~24 hours, NOT the calendar day; no start/end is accepted, so a specific date is not available.")],
) -> dict:
    """READ-ONLY: datastore stats telemetry (I/O, usage over time) — the datastore-level
    parallel of pbs_node_rrd. The live schema declares returns:null despite real data —
    best-effort dict passthrough. REVIEWED_TRUSTED (rrddata precedent). Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_datastore_rrd", f"pbs/datastore/{store}/rrd",
                    lambda: datastore_rrd(pbs, store, cf, timeframe))


@tool()
def pbs_datastore_active_operations(
    store: Annotated[str, Field(description="PBS datastore name.")],
) -> dict:
    """READ-ONLY: in-flight operation counts for a datastore (expected read/write counters —
    the live schema declares returns:null, and its description is a copy-paste artifact; see
    proximo.pbs_datastore_admin fact #9). Useful before pbs_datastore_unmount. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_datastore_active_operations",
                    f"pbs/datastore/{store}/active-operations",
                    lambda: datastore_active_operations(pbs, store))


@tool()
def pbs_datastores_usage() -> list[dict]:
    """READ-ONLY: capacity usage + estimated-full dates for every datastore (avail, error,
    estimated-full-date via linear regression over the last month's RRD data, gc-status).
    Distinct from pbs_metrics_status (performance samples) — this is capacity planning. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_datastores_usage", "pbs/status/datastore-usage",
                    lambda: datastores_usage(pbs))


# --- Reads: remote discovery (the read-side of pbs_pull/pbs_push) ---

@tool()
def pbs_remote_scan(
    name: Annotated[str, Field(description="Remote ID (a configured remote.cfg entry — see pbs_remotes_list).")],
) -> list[dict]:
    """READ-ONLY: list the datastores accessible on a configured remote PBS — discover what
    exists BEFORE pbs_pull/pbs_push instead of guessing remote_store blind. ADVERSARIAL: the
    returned store names/comments/maintenance messages are authored on the REMOTE PBS
    (pbs_s3_list_buckets precedent — externally-authored content). Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_remote_scan", f"pbs/remote/{name}/scan",
                    lambda: remote_scan(pbs, name))


@tool()
def pbs_remote_scan_groups(
    name: Annotated[str, Field(description="Remote ID.")],
    store: Annotated[str, Field(description="Datastore name on the remote.")],
    namespace: Annotated[str | None, Field(description="Namespace on the remote datastore to list groups in. NOTE: this endpoint's wire param is 'namespace', not 'ns' — a schema divergence from the /admin/datastore siblings.")] = None,
) -> list[dict]:
    """READ-ONLY: list backup groups on a remote's datastore — discover what a pbs_pull would
    transfer (or what a pbs_push group_filter should target) before running it. ADVERSARIAL
    (remote-authored group ids + comments). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = (f"pbs/remote/{name}/scan/{store}/groups"
           + (f"/{namespace}" if namespace else ""))
    return _audited("pbs_remote_scan_groups", tgt,
                    lambda: remote_scan_groups(pbs, name, store, namespace))


@tool()
def pbs_remote_scan_namespaces(
    name: Annotated[str, Field(description="Remote ID.")],
    store: Annotated[str, Field(description="Datastore name on the remote.")],
) -> list[dict]:
    """READ-ONLY: list namespaces on a remote's datastore — discover valid remote_ns values for
    pbs_pull/pbs_push before running them. ADVERSARIAL (remote-authored namespace names +
    comments). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_remote_scan_namespaces", f"pbs/remote/{name}/scan/{store}/namespaces",
                    lambda: remote_scan_namespaces(pbs, name, store))


# --- Mutations: group management ---

@tool()
def pbs_group_delete(
    store: Annotated[str, Field(description="PBS datastore name.")],
    backup_type: Annotated[str, Field(description="Backup type: vm, ct, or host.")],
    backup_id: Annotated[str, Field(description="Backup group ID whose ENTIRE group (all snapshots) will be deleted.")],
    ns: Annotated[str | None, Field(description="Namespace; omit for the root namespace.")] = None,
    error_on_protected: Annotated[bool | None, Field(description="Upstream default TRUE: fail if the group contains any protected snapshot. False = delete all UNPROTECTED snapshots, keep protected ones, and SUCCEED as a partial delete.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete an ENTIRE backup group including ALL its snapshots.

    RISK_HIGH — bulk-destructive: one call removes every recovery point for this guest/host in
    this namespace; strictly more destructive than pbs_snapshot_delete (one snapshot) and the
    same class as pbs_namespace_delete(delete_groups=True). No undo. Check pbs_groups_list /
    pbs_snapshots_list first — the PLAN deliberately does not pull that content in itself.
    Dry-run by default; confirm=True executes (DELETE /admin/datastore/{store}/groups) and
    returns {"status": "ok", "result": {removed-groups, removed-snapshots,
    protected-snapshots}} — a SYNCHRONOUS stats object, not a task UPID; verify the counters,
    especially protected-snapshots when error_on_protected=False (a nonzero value means a
    PARTIAL delete). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{store}/groups/{backup_type}/{backup_id}" + (f"/{ns}" if ns else "")
    return run_governed(
        "pbs_group_delete", tgt,
        plan=lambda: plan_group_delete(
        store, backup_type, backup_id, ns, error_on_protected,
    ),
        execute=lambda: group_delete(pbs, store, backup_type, backup_id, ns, error_on_protected),
        confirm=confirm, detail={"store": store, "backup_type": backup_type, "backup_id": backup_id})


@tool()
def pbs_group_notes_set(
    store: Annotated[str, Field(description="PBS datastore name.")],
    backup_type: Annotated[str, Field(description="Backup type: vm, ct, or host.")],
    backup_id: Annotated[str, Field(description="Backup group ID.")],
    notes: Annotated[str, Field(description="The notes body (multiline text; the first line becomes the group's 'comment' in listings).")],
    ns: Annotated[str | None, Field(description="Namespace; omit for the root namespace.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes.")] = False,
) -> dict:
    """MUTATION: set the notes body for a backup GROUP (distinct from the snapshot-level
    pbs_snapshot_notes_set).

    RISK_LOW: annotation metadata only — no backup data, retention, or protection is changed.
    Dry-run by default (CAPTUREs the current notes for guided revert, mirroring
    pbs_snapshot_notes_set); confirm=True executes (PUT /admin/datastore/{store}/group-notes,
    synchronous — PBS returns null) and returns {"status": "ok", "result": None}. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{store}/group-notes/{backup_type}/{backup_id}" + (f"/{ns}" if ns else "")
    return run_governed(
        "pbs_group_notes_set", tgt,
        plan=lambda: plan_group_notes_set(
        pbs, store, backup_type, backup_id, notes, ns,
    ),
        execute=lambda: group_notes_set(pbs, store, backup_type, backup_id, notes, ns),
        confirm=confirm)


@tool()
def pbs_group_move(
    store: Annotated[str, Field(description="PBS datastore name (source and target — same datastore).")],
    backup_type: Annotated[str, Field(description="Backup type: vm, ct, or host.")],
    backup_id: Annotated[str, Field(description="Backup group ID to move.")],
    ns: Annotated[str | None, Field(description="SOURCE namespace; omit for the root namespace.")] = None,
    target_ns: Annotated[str | None, Field(description="TARGET namespace; omit for the root namespace.")] = None,
    merge_group: Annotated[bool | None, Field(description="Upstream default TRUE: if the group already exists in the target namespace, merge snapshots into it (requires matching ownership and non-overlapping snapshot times). False = fail instead.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the move.")] = False,
) -> dict:
    """MUTATION: move a backup group to a different namespace within the same datastore.

    RISK_MEDIUM — data-relocating, not destroying: sync/verify/prune jobs, ACL paths, and
    pull/push targets scoped to the OLD namespace silently stop seeing this group afterward.
    Dry-run by default (the PLAN discloses source ns, target ns, and the merge behavior
    including the upstream default); confirm=True executes (POST
    /admin/datastore/{store}/move-group, async — UPID; a null return records "ok") and tracks
    with pbs_tasks_list. Reverse with a second pbs_group_move. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{store}/move-group/{backup_type}/{backup_id}"
    return run_governed(
        "pbs_group_move", tgt,
        plan=lambda: plan_group_move(
        store, backup_type, backup_id, ns, target_ns, merge_group,
    ),
        execute=lambda: group_move(pbs, store, backup_type, backup_id, ns, target_ns, merge_group),
        confirm=confirm, outcome=_submitted_or_ok, detail={"ns": ns, "target_ns": target_ns})


@tool()
def pbs_namespace_move(
    store: Annotated[str, Field(description="PBS datastore name (source and target — same datastore).")],
    ns: Annotated[str, Field(description="SOURCE namespace to move. Must be non-empty — the root namespace cannot be relocated.")],
    target_ns: Annotated[str, Field(description="TARGET parent namespace. Empty string = move into the root namespace.")],
    delete_source: Annotated[bool | None, Field(description="Upstream default TRUE: the source namespace tree is REMOVED after the move. False = keep the (now-empty) source tree.")] = None,
    max_depth: Annotated[int | None, Field(description="Recursion depth 0-7. Upstream default 7 = FULL recursion — omitting it moves EVERYTHING under ns.")] = None,
    merge_groups: Annotated[bool | None, Field(description="Upstream default TRUE: same-name groups already in the target get the moved snapshots merged in. False = fail on conflict.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the move.")] = False,
) -> dict:
    """MUTATION: move a backup namespace INCLUDING ALL CHILD NAMESPACES AND GROUPS to a new
    location within the same datastore.

    RISK_HIGH — the widest-blast-radius non-deleting mutation on this plane: the whole tree
    relocates (max_depth defaults to full recursion upstream), the SOURCE tree is then REMOVED
    (delete_source defaults TRUE upstream), and every job (sync/prune/verify/tape), ACL path,
    and pull/push target referencing the old namespace path breaks or silently matches nothing
    afterward. Data survives at the target. Dry-run by default (the PLAN discloses every
    where-data-lands param including both upstream defaults); confirm=True executes (POST
    /admin/datastore/{store}/move-namespace, async — UPID; a null return records "ok"). No
    single-call undo. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{store}/move-namespace/{ns}"
    return run_governed(
        "pbs_namespace_move", tgt,
        plan=lambda: plan_namespace_move(
        store, ns, target_ns, delete_source, max_depth, merge_groups,
    ),
        execute=lambda: namespace_move(pbs, store, ns, target_ns, delete_source, max_depth,
                               merge_groups),
        confirm=confirm, outcome=_submitted_or_ok, detail={"ns": ns, "target_ns": target_ns, "delete_source": delete_source})


# --- Mutations: datastore lifecycle + whole-datastore prune ---

@tool()
def pbs_datastore_mount(
    store: Annotated[str, Field(description="Removable PBS datastore name to mount.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the mount.")] = False,
) -> dict:
    """MUTATION: mount a removable datastore.

    RISK_MEDIUM — availability transition: the datastore becomes available, run-on-mount jobs
    fire. Dry-run by default; confirm=True executes (POST /admin/datastore/{store}/mount,
    async — UPID; a null return records "ok"); track with pbs_tasks_list. Reverse with
    pbs_datastore_unmount. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{store}/mount"
    return run_governed(
        "pbs_datastore_mount", tgt,
        plan=lambda: plan_datastore_mount(store),
        execute=lambda: datastore_mount(pbs, store),
        confirm=confirm, outcome=_submitted_or_ok)


@tool()
def pbs_datastore_unmount(
    store: Annotated[str, Field(description="Removable PBS datastore name to unmount.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the unmount.")] = False,
) -> dict:
    """MUTATION: unmount the removable device backing a datastore.

    RISK_MEDIUM — the datastore becomes UNAVAILABLE: in-flight operations are aborted and every
    job targeting it fails until re-mounted (check pbs_datastore_active_operations first).
    Dry-run by default; confirm=True executes (POST /admin/datastore/{store}/unmount, async —
    UPID; a null return records "ok"). Reverse with pbs_datastore_mount. Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{store}/unmount"
    return run_governed(
        "pbs_datastore_unmount", tgt,
        plan=lambda: plan_datastore_unmount(store),
        execute=lambda: datastore_unmount(pbs, store),
        confirm=confirm, outcome=_submitted_or_ok)


@tool()
def pbs_datastore_s3_refresh(
    store: Annotated[str, Field(description="S3-backed PBS datastore name to refresh.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the refresh.")] = False,
) -> dict:
    """MUTATION: refresh a datastore's contents from its S3 backend into the local cache store.

    RISK_MEDIUM — the local cache is overwritten/reconciled from the remote object store, and
    the datastore passes through 's3-refresh' maintenance mode while the task runs. Dry-run by
    default; confirm=True executes (PUT /admin/datastore/{store}/s3-refresh, async — UPID; a
    null return records "ok"). No undo — the cache is rebuilt. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{store}/s3-refresh"
    return run_governed(
        "pbs_datastore_s3_refresh", tgt,
        plan=lambda: plan_datastore_s3_refresh(store),
        execute=lambda: datastore_s3_refresh(pbs, store),
        confirm=confirm, outcome=_submitted_or_ok)


@tool()
def pbs_datastore_prune(
    store: Annotated[str, Field(description="PBS datastore name.")],
    keep_last: Annotated[int | None, Field(description="Number of backups to keep (>=1).")] = None,
    keep_hourly: Annotated[int | None, Field(description="Number of hourly backups to keep (>=1). NOT available on the single-group pbs_prune — this endpoint alone exposes it.")] = None,
    keep_daily: Annotated[int | None, Field(description="Number of daily backups to keep (>=1).")] = None,
    keep_weekly: Annotated[int | None, Field(description="Number of weekly backups to keep (>=1).")] = None,
    keep_monthly: Annotated[int | None, Field(description="Number of monthly backups to keep (>=1).")] = None,
    keep_yearly: Annotated[int | None, Field(description="Number of yearly backups to keep (>=1).")] = None,
    ns: Annotated[str | None, Field(description="Namespace to scope the prune to; omit for the root namespace.")] = None,
    max_depth: Annotated[int | None, Field(description="Namespace recursion depth 0-7; omit for automatic full recursion.")] = None,
    dry_run: Annotated[bool, Field(description="True (THIS TOOL'S default — the schema's own default is false): report what would be pruned without deleting. Set False to actually delete.")] = True,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes (which, with dry_run=True, still deletes nothing).")] = False,
) -> dict:
    """MUTATION: prune EVERY backup group in a datastore/namespace tree per a retention policy —
    the WHOLE-DATASTORE prune, schema-distinct from the single-group pbs_prune (which scopes to
    one backup-type+backup-id and cannot recurse namespaces).

    dry_run=True (this tool's default — a deliberate flip of the schema's own false default,
    same as pbs_prune's) → RISK_LOW preview; dry_run=False → RISK_HIGH: PERMANENTLY DELETES
    snapshots across every group in scope; with NO keep_* set, ALL prunable snapshots are
    candidates. Dry-run-PLAN by default; confirm=True executes (POST
    /admin/datastore/{store}/prune-datastore, async — UPID; a null return records "ok"); the
    prune decisions land in the task log (pbs_tasks_list). GC afterward reclaims the space.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/datastore/{store}/prune-datastore"
    return run_governed(
        "pbs_datastore_prune", tgt,
        plan=lambda: plan_datastore_prune(
        store, keep_last, keep_hourly, keep_daily, keep_weekly, keep_monthly, keep_yearly,
        ns, max_depth, dry_run,
    ),
        execute=lambda: datastore_prune(pbs, store, keep_last, keep_hourly, keep_daily, keep_weekly,
                                keep_monthly, keep_yearly, ns, max_depth, dry_run),
        confirm=confirm, outcome=_submitted_or_ok, detail={"dry_run": dry_run})
