"""PVE backup & restore plus scheduled planes: ad-hoc backup/restore, PVE backup jobs, replication jobs, and PBS
scheduled jobs / realm sync.

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.backup import (
    backup_delete,
    backup_list,
    plan_backup,
    plan_backup_delete,
    plan_restore,
    restore_guest,
    vzdump_backup,
)
from proximo.backup_schedules import (
    backup_job_create,
    backup_job_delete,
    backup_job_list,
    backup_job_update,
    pbs_scheduled_job_create,
    pbs_scheduled_job_delete,
    pbs_scheduled_job_run,
    pbs_scheduled_job_update,
    plan_backup_job_create,
    plan_backup_job_delete,
    plan_backup_job_update,
    plan_pbs_job_create,
    plan_pbs_job_delete,
    plan_pbs_job_run,
    plan_pbs_job_update,
    plan_pbs_realm_sync,
    plan_replication_create,
    plan_replication_delete,
    plan_replication_update,
    replication_create,
    replication_delete,
    replication_update,
)
from proximo.backup_schedules import (
    pbs_realm_sync as pbs_realm_sync_op,
)
from proximo.freshness import backup_freshness
from proximo.projection import cap_newest
from proximo.server import (
    _audited,
    _plan,
    tool,
)

# --- Backup & restore (REST API, async -> UPID) ---

@tool()
def pve_backup(
    vmid: Annotated[str, Field(description="Numeric ID of the guest (VM or CT) to back up.")],
    storage: Annotated[str, Field(description="Storage ID to write the backup archive to.")],
    mode: Annotated[str, Field(description="Backup mode: snapshot (online, brief) | suspend (RAM-quiesced pause) | stop (HALTS the guest).")] = "snapshot",
    compress: Annotated[str, Field(description="Compression algorithm for the archive, e.g. zstd, gzip, lzo, or 0 (no compression).")] = "zstd",
    kind: Annotated[str, Field(description="Guest type: lxc or qemu.")] = "lxc",
    node: Annotated[str | None, Field(description="Proxmox node hosting the guest; defaults to the configured node if omitted.")] = None,
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the backup.")] = False,
) -> dict:
    """MUTATION: back up a guest with vzdump. Dry-run by default; confirm=True to execute.
    mode: snapshot (online, brief) | suspend | stop (HALTS the guest). Async — returns a task UPID.
    This is a one-off run; for a recurring schedule use pve_backup_job_create instead."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}"
    plan = _plan("pve_backup", target, lambda: plan_backup(vmid, storage, mode, kind))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_backup", target,
                    lambda: vzdump_backup(api, vmid, storage, mode, compress, node),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


@tool()
def pve_backup_list(
    storage: Annotated[str, Field(description="Storage ID to list backup archives from.")],
    node: Annotated[str | None, Field(description="Proxmox node hosting the storage; defaults to the configured node if omitted.")] = None,
    limit: Annotated[int | None, Field(description="Optional cap: return only the NEWEST N archives by ctime. A limited listing is NOT evidence of absence — omit for the complete ground-truth list. Zero/negative is rejected.")] = None,
) -> list[dict]:
    """READ-ONLY: list backup archives in a storage. Ground truth for whether a backup exists —
    a backup missing from a pve_tasks_list slice (other node, or outside its limit window)
    still shows here. Returns a list of dicts (volid, size, ctime, …). `limit` returns only
    the newest N — a capped slice is never evidence a backup is absent; omit it to verify one."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_backup_list", storage,
                    lambda: cap_newest(backup_list(api, storage, node), limit, "ctime"))


@tool()
def pve_backup_freshness(
    max_age_hours: Annotated[float | None, Field(description="Override for max acceptable backup age in hours; if omitted, age expectation is derived from each guest's backup job schedule.")] = None,
    grace_hours: Annotated[float, Field(description="Hours of slack padded onto each job's parsed cadence before a backup is flagged stale.")] = 6.0,
) -> dict:
    """READ-ONLY: backup-freshness fence — walks ACTUAL backup archives per guest and compares
    their age against what enabled backup jobs promise; a job or task reporting OK is never
    treated as evidence a backup exists. Verdicts per guest: fresh | stale | never | uncovered |
    unknown; an unreadable storage always yields unknown + complete=false, never a clean bill.
    Returns a dict of {guests, jobs, counts, flags, complete, …}. For the raw archive list use
    pve_backup_list; for job configuration use pve_backup_job_list."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_backup_freshness", "cluster/backup-freshness",
                    lambda: backup_freshness(api, max_age_hours, grace_hours))


@tool()
def pve_backup_delete(
    storage: Annotated[str, Field(description="Storage ID holding the backup archive.")],
    volid: Annotated[str, Field(description="Volume ID of the backup archive to delete (as returned by pve_backup_list).")],
    node: Annotated[str | None, Field(description="Proxmox node hosting the storage; defaults to the configured node if omitted.")] = None,
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a backup archive (removes a recovery point). Dry-run by default; confirm=True
    to execute. Irreversible — deleting the last backup of a guest leaves no recovery point; the
    PLAN reports how many other backups of the same guest remain. Check the archive list first with
    pve_backup_list. Async — may return a task UPID or null depending on storage."""
    _, api, _, _ = _proximo_server._svc()
    plan = _plan("pve_backup_delete", volid, lambda: plan_backup_delete(api, storage, volid))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    # backup_delete() may return None for a synchronous (dir-storage) delete rather than a task
    # UPID (backup.py's own documented contract) -- a fixed outcome="submitted" would then falsely
    # claim an already-finished delete is still in-flight, in BOTH the returned status and the
    # ledger's own record. _audited()'s callable-outcome form resolves the honest label from the
    # actual result, after backup_delete() runs, so the ledger is honest too (not just the envelope).
    return _audited("pve_backup_delete", volid,
                    lambda: backup_delete(api, storage, volid, node),
                    mutation=True, outcome=lambda result: "ok" if result is None else "submitted",
                    detail={"confirmed": True})


@tool()
def pve_restore(
    vmid: Annotated[str, Field(description="Numeric ID for the restored guest — new if free, existing to overwrite.")],
    archive: Annotated[str, Field(description="Volume ID of the backup archive to restore from.")],
    storage: Annotated[str, Field(description="Storage ID to restore the guest's disks onto (LXC only; ignored for QEMU).")],
    kind: Annotated[str, Field(description="Guest type: lxc or qemu.")] = "lxc",
    node: Annotated[str | None, Field(description="Proxmox node to restore onto; defaults to the configured node if omitted.")] = None,
    force: Annotated[bool, Field(description="If vmid already exists, overwrite/destroy the existing guest instead of failing.")] = False,
    pool: Annotated[str | None, Field(description="Resource pool to place the restored guest in.")] = None,
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the restore.")] = False,
) -> dict:
    """MUTATION (DESTRUCTIVE if it overwrites an existing guest): restore a guest from a backup
    archive. Dry-run by default — the PLAN reads live guest state and states whether it CREATES or
    OVERWRITES. confirm=True to execute. Async — returns a task UPID. Find the archive's volid
    first with pve_backup_list."""
    _, api, _, _ = _proximo_server._svc()
    target = f"{kind}/{vmid}"
    plan = _plan("pve_restore", target, lambda: plan_restore(api, vmid, archive, kind, node, force))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_restore", target,
                    lambda: restore_guest(api, vmid, archive, storage, kind, node, force, pool),
                    mutation=True, outcome="submitted", detail={"confirmed": True, "force": force})


# --- Backup Schedules (Plane B) — PVE backup jobs, replication, PBS scheduled jobs ---

@tool()
def pve_backup_job_list() -> dict:
    """READ-ONLY: list all PVE cluster backup jobs and guests not covered by any job.
    Returns {jobs: [...], unprotected_guests: [...]}. For the actual archives on storage use
    pve_backup_list; for a per-guest freshness verdict against these jobs' promises use
    pve_backup_freshness."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_backup_job_list", "cluster/backup",
                    lambda: backup_job_list(api))


@tool()
def pve_backup_job_create(
    job_id: Annotated[str, Field(description="Unique ID for the new PVE backup job.")],
    schedule: Annotated[str, Field(description="Proxmox calendar-event schedule string, e.g. 'sat 02:00' or a systemd.time-style spec.")],
    storage: Annotated[str, Field(description="Storage ID the job writes backups to.")],
    mode: Annotated[str | None, Field(description="Backup mode: snapshot | suspend | stop; defaults to Proxmox's own default if omitted.")] = None,
    compress: Annotated[str | None, Field(description="Compression algorithm for archives, e.g. zstd, gzip, lzo, or 0 (no compression).")] = None,
    vmid: Annotated[str | None, Field(description="CSV of guest IDs to include; mutually exclusive with all_guests and pool.")] = None,
    all_guests: Annotated[bool | None, Field(description="If true, back up every guest on the cluster; mutually exclusive with vmid and pool.")] = None,
    pool: Annotated[str | None, Field(description="Resource pool of guests to back up; mutually exclusive with vmid and all_guests.")] = None,
    exclude: Annotated[str | None, Field(description="CSV of guest IDs to exclude when all_guests=True.")] = None,
    enabled: Annotated[bool | None, Field(description="Whether the job is active; defaults to enabled if omitted.")] = None,
    comment: Annotated[str | None, Field(description="Free-text note stored on the job.")] = None,
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PVE cluster backup job — a persistent vzdump schedule, distinct from a
    one-off pve_backup run. Dry-run by default; confirm=True to execute and returns synchronously
    (no task UPID). Config-only; existing backups are NOT affected. Guest selection is mutually
    exclusive — pass at most one of vmid, all_guests, or pool; exclude filters all_guests. To
    modify an existing job use pve_backup_job_update; to remove one use pve_backup_job_delete."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/backup/{job_id}"
    # all_guests -> PVE's `all` wire field (the tool name avoids shadowing the builtin).
    # Falsy all_guests collapses to None so it behaves exactly like omitting it (no all=0 leak).
    sel = {"vmid": vmid, "all": all_guests or None, "pool": pool, "exclude": exclude}
    plan = _plan("pve_backup_job_create", tgt,
                 lambda: plan_backup_job_create(job_id, schedule, storage,
                                                mode=mode, compress=compress,
                                                enabled=enabled, comment=comment, **sel))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_backup_job_create", tgt,
                    lambda: backup_job_create(api, job_id, schedule, storage,
                                             mode=mode, compress=compress,
                                             enabled=enabled, comment=comment, **sel),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_backup_job_update(
    job_id: Annotated[str, Field(description="ID of the existing PVE backup job to update.")],
    schedule: Annotated[str | None, Field(description="New Proxmox calendar-event schedule string; omit to leave unchanged.")] = None,
    storage: Annotated[str | None, Field(description="New storage ID for the job's backups; omit to leave unchanged.")] = None,
    mode: Annotated[str | None, Field(description="New backup mode: snapshot | suspend | stop; omit to leave unchanged.")] = None,
    compress: Annotated[str | None, Field(description="New compression algorithm, e.g. zstd, gzip, lzo, or 0 (no compression); omit to leave unchanged.")] = None,
    vmid: Annotated[str | None, Field(description="New CSV of guest IDs the job covers; omit to leave unchanged.")] = None,
    enabled: Annotated[bool | None, Field(description="Whether the job is active; omit to leave unchanged.")] = None,
    comment: Annotated[str | None, Field(description="New free-text note; omit to leave unchanged.")] = None,
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the update.")] = False,
) -> dict:
    """MUTATION: update a PVE cluster backup job. Dry-run by default — the PLAN captures current
    config so you can revert manually; confirm=True to execute and returns synchronously (no task
    UPID). Config-only; no impact on existing backups. To create a new job use
    pve_backup_job_create; to remove one use pve_backup_job_delete."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/backup/{job_id}"
    plan = _plan("pve_backup_job_update", tgt,
                 lambda: plan_backup_job_update(api, job_id, schedule=schedule,
                                                storage=storage, mode=mode,
                                                compress=compress, vmid=vmid,
                                                enabled=enabled, comment=comment))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_backup_job_update", tgt,
                    lambda: backup_job_update(api, job_id, schedule=schedule,
                                             storage=storage, mode=mode, compress=compress,
                                             vmid=vmid, enabled=enabled, comment=comment),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_backup_job_delete(
    job_id: Annotated[str, Field(description="ID of the PVE backup job to delete.")],
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PVE cluster backup job. Dry-run by default — the PLAN captures current
    config (no snapshot/UNDO primitive on this plane; re-create with pve_backup_job_create to
    restore the schedule). confirm=True to execute and returns synchronously (no task UPID).
    Schedule removed; existing backups are NOT deleted."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/backup/{job_id}"
    plan = _plan("pve_backup_job_delete", tgt,
                 lambda: plan_backup_job_delete(api, job_id))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_backup_job_delete", tgt,
                    lambda: backup_job_delete(api, job_id),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_replication_create(
    rep_id: Annotated[str, Field(description="Unique ID for the new replication job.")],
    rep_type: Annotated[str, Field(description="Replication job type, typically 'local'.")],
    target: Annotated[str, Field(description="Target node (or node/storage) to replicate to.")],
    schedule: Annotated[str | None, Field(description="Proxmox calendar-event schedule string; omit for the default cadence.")] = None,
    rate: Annotated[float | None, Field(description="Bandwidth limit in MB/s; omit for unlimited.")] = None,
    disable: Annotated[bool | None, Field(description="If true, create the job in a disabled state.")] = None,
    comment: Annotated[str | None, Field(description="Free-text note stored on the job.")] = None,
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PVE replication job. Dry-run by default; confirm=True to execute and
    returns synchronously (no task UPID) — additive, no existing data affected. rep_type is
    typically 'local'. To modify an existing job use pve_replication_update; to remove one use
    pve_replication_delete."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/replication/{rep_id}"
    plan = _plan("pve_replication_create", tgt,
                 lambda: plan_replication_create(rep_id, rep_type, target,
                                                 schedule=schedule, rate=rate,
                                                 disable=disable, comment=comment))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_replication_create", tgt,
                    lambda: replication_create(api, rep_id, rep_type, target,
                                              schedule=schedule, rate=rate,
                                              disable=disable, comment=comment),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_replication_update(
    rep_id: Annotated[str, Field(description="ID of the existing replication job to update.")],
    schedule: Annotated[str | None, Field(description="New Proxmox calendar-event schedule string; omit to leave unchanged.")] = None,
    rate: Annotated[float | None, Field(description="New bandwidth limit in MB/s; omit to leave unchanged.")] = None,
    disable: Annotated[bool | None, Field(description="Whether the job is disabled; omit to leave unchanged.")] = None,
    comment: Annotated[str | None, Field(description="New free-text note; omit to leave unchanged.")] = None,
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the update.")] = False,
) -> dict:
    """MUTATION: update a PVE replication job. Dry-run by default — the PLAN captures current
    config for manual revert; confirm=True to execute and returns synchronously (no task UPID).
    Config-only; in-flight replication is not immediately disrupted. To create a new job use
    pve_replication_create; to remove one use pve_replication_delete."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/replication/{rep_id}"
    plan = _plan("pve_replication_update", tgt,
                 lambda: plan_replication_update(api, rep_id, schedule=schedule,
                                                 rate=rate, disable=disable,
                                                 comment=comment))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_replication_update", tgt,
                    lambda: replication_update(api, rep_id, schedule=schedule,
                                              rate=rate, disable=disable, comment=comment),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pve_replication_delete(
    rep_id: Annotated[str, Field(description="ID of the replication job to delete.")],
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PVE replication job. Dry-run by default — the PLAN captures current
    config (no UNDO primitive on this plane; re-create with pve_replication_create to restore).
    confirm=True to execute and returns synchronously (no task UPID). Replication ceases; existing
    replicated data on the target is NOT removed."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/replication/{rep_id}"
    plan = _plan("pve_replication_delete", tgt,
                 lambda: plan_replication_delete(api, rep_id))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pve_replication_delete", tgt,
                    lambda: replication_delete(api, rep_id),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pbs_job_create(
    job_type: Annotated[str, Field(description="PBS job type: sync | verify | prune.")],
    job_id: Annotated[str, Field(description="Unique ID for the new PBS scheduled job.")],
    store: Annotated[str | None, Field(description="PBS datastore the job operates on.")] = None,
    schedule: Annotated[str | None, Field(description="Proxmox calendar-event schedule string for the job.")] = None,
    ns: Annotated[str | None, Field(description="PBS namespace the job operates on; omit for the root namespace.")] = None,
    comment: Annotated[str | None, Field(description="Free-text note stored on the job.")] = None,
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PBS scheduled job. job_type = sync|verify|prune. Dry-run by default;
    confirm=True to execute and returns synchronously (no task UPID) — additive, no existing data
    affected. Needs PROXIMO_PBS_* config. To modify use pbs_job_update, to remove use
    pbs_job_delete, or to run it once immediately (bypassing the schedule) use pbs_job_run."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/{job_type}/{job_id}"
    plan = _plan("pbs_job_create", tgt,
                 lambda: plan_pbs_job_create(job_type, job_id, store=store,
                                             schedule=schedule, ns=ns, comment=comment))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_job_create", tgt,
                    lambda: pbs_scheduled_job_create(pbs, job_type, job_id, store=store,
                                                     schedule=schedule, ns=ns,
                                                     comment=comment),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pbs_job_update(
    job_type: Annotated[str, Field(description="PBS job type: sync | verify | prune.")],
    job_id: Annotated[str, Field(description="ID of the existing PBS scheduled job to update.")],
    schedule: Annotated[str | None, Field(description="New Proxmox calendar-event schedule string; omit to leave unchanged.")] = None,
    ns: Annotated[str | None, Field(description="New PBS namespace the job operates on; omit to leave unchanged.")] = None,
    comment: Annotated[str | None, Field(description="New free-text note; omit to leave unchanged.")] = None,
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the update.")] = False,
) -> dict:
    """MUTATION: update a PBS scheduled job. job_type = sync|verify|prune. Dry-run by default —
    the PLAN captures current config for manual revert; confirm=True to execute and returns
    synchronously (no task UPID). Config-only; existing backup data is unaffected. Needs
    PROXIMO_PBS_* config. To create use pbs_job_create; to remove use pbs_job_delete."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/{job_type}/{job_id}"
    plan = _plan("pbs_job_update", tgt,
                 lambda: plan_pbs_job_update(pbs, job_type, job_id, schedule=schedule,
                                             ns=ns, comment=comment))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_job_update", tgt,
                    lambda: pbs_scheduled_job_update(pbs, job_type, job_id,
                                                     schedule=schedule, ns=ns,
                                                     comment=comment),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pbs_job_delete(
    job_type: Annotated[str, Field(description="PBS job type: sync | verify | prune.")],
    job_id: Annotated[str, Field(description="ID of the PBS scheduled job to delete.")],
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PBS scheduled job. job_type = sync|verify|prune. Dry-run by default —
    the PLAN captures current config (no UNDO primitive; re-create with pbs_job_create to restore
    the schedule). confirm=True to execute and returns synchronously (no task UPID). Schedule
    removed, backup data NOT deleted. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/{job_type}/{job_id}"
    plan = _plan("pbs_job_delete", tgt,
                 lambda: plan_pbs_job_delete(pbs, job_type, job_id))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_job_delete", tgt,
                    lambda: pbs_scheduled_job_delete(pbs, job_type, job_id),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pbs_job_run(
    job_type: Annotated[str, Field(description="PBS job type: sync | verify | prune.")],
    job_id: Annotated[str, Field(description="ID of the PBS scheduled job to trigger immediately.")],
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the run.")] = False,
) -> dict:
    """MUTATION: trigger a PBS scheduled job immediately, outside its normal schedule.
    job_type = sync|verify|prune. Dry-run by default; confirm=True to execute. SCHEMA QUIRK
    (live PBS apidoc, 2026-07-15, Wave 5c review Finding 4): POST /admin/{type}/{id}/run
    declares returns:null for all three types — when PBS returns nothing the run completed (or
    at least was accepted) synchronously and the status is "ok"; if a UPID does come back
    (the schema may be under-documented), the status is "submitted" and pbs_tasks_list tracks
    it. Risk depends on job_type: prune runs permanently DELETE snapshots per the retention
    policy, sync may add/remove directory data, verify is read-only. Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/admin/{job_type}/{job_id}"
    plan = _plan("pbs_job_run", tgt,
                 lambda: plan_pbs_job_run(job_type, job_id))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    # Wave 5c review Finding 4: the live schema declares /admin/{prune,sync,verify}/{id}/run
    # ALL return null — a hardcoded outcome="submitted" recorded a synchronously-completed
    # trigger as still in-flight, in both the envelope and the raw ledger. Same callable-outcome
    # fix as pve_backup_delete above; pbs_scheduled_job_run coerces null to "" (`... or ""`), so
    # the resolver keys on falsy, not `is None`.
    return _audited("pbs_job_run", tgt,
                    lambda: pbs_scheduled_job_run(pbs, job_type, job_id),
                    mutation=True,
                    outcome=lambda result: "submitted" if result else "ok",
                    detail={"confirmed": True})


@tool()
def pbs_realm_sync(
    realm: Annotated[str, Field(description="PBS LDAP/AD auth realm ID to sync users from.")],
    remove_vanished: Annotated[bool | None, Field(description="If true, also delete PBS users no longer present in the directory.")] = None,
    dry_run: Annotated[bool | None, Field(description="If true, ask PBS itself to preview the sync without applying it (separate from the tool's own confirm gate).")] = None,
    confirm: Annotated[bool, Field(description="Gate: false returns a dry-run PLAN, true executes the sync.")] = False,
) -> dict:
    """MUTATION: sync PBS auth realm (LDAP/AD) users into PBS. Dry-run by default; confirm=True to
    execute. Async — returns a UPID; check progress with pbs_tasks_list. remove_vanished=True
    additionally DELETES PBS users no longer present in the directory (recoverable only by
    re-sync, not a true undo). Needs PROXIMO_PBS_* config. (2026-07-10 audit: the old 'scope'
    param was dropped — PBS /sync has no such field.)"""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/access/domains/{realm}"
    plan = _plan("pbs_realm_sync", tgt,
                 lambda: plan_pbs_realm_sync(realm,
                                             remove_vanished=remove_vanished,
                                             dry_run=dry_run))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_realm_sync", tgt,
                    lambda: pbs_realm_sync_op(pbs, realm,
                                              remove_vanished=remove_vanished,
                                              dry_run=dry_run),
                    mutation=True, outcome="submitted", detail={"confirmed": True})
