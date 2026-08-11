"""PBS tape media CATALOG + tape-backup JOBS + backup/restore wrappers (Wave 4d, full-surface
campaign) — `.scratch/2026-07-15-full-surface-campaign.md`, "Wave 4 decomposition (PBS tape)",
"4d — media catalog + jobs + backup/restore". See `proximo.pbs_tape_jobs` module docstring for
the full endpoint table, the schema-verified facts, and the risk-rating reasoning. This wave
CLOSES Wave 4 (PBS tape).
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_tape_jobs import (
    plan_tape_backup,
    plan_tape_backup_job_create,
    plan_tape_backup_job_delete,
    plan_tape_backup_job_run,
    plan_tape_backup_job_update,
    plan_tape_media_destroy,
    plan_tape_media_move,
    plan_tape_media_status_set,
    plan_tape_restore,
    tape_backup,
    tape_backup_job_create,
    tape_backup_job_delete,
    tape_backup_job_get,
    tape_backup_job_list,
    tape_backup_job_run,
    tape_backup_job_update,
    tape_media_content,
    tape_media_destroy,
    tape_media_list,
    tape_media_move,
    tape_media_sets,
    tape_media_status_get,
    tape_media_status_set,
    tape_restore,
)
from proximo.projection import cap_newest
from proximo.server import (
    _audited,
    _plan,
    tool,
)

# --- Reads: Media catalog ---

@tool()
def pbs_tape_media_list(
    pool: Annotated[str | None, Field(description="Filter to one media pool (2-32 chars).")] = None,
    update_status: Annotated[bool, Field(description="If True, ask PBS to refresh tape library status (may contact the changer) before listing. DEFAULTS FALSE here — PBS's own upstream default is True; this tool never triggers that refresh unless explicitly asked.")] = False,
    update_status_changer: Annotated[str | None, Field(description="Scope the status refresh to one changer (only meaningful with update_status=True).")] = None,
    limit: Annotated[int | None, Field(description="Optional cap: return only the NEWEST N media by ctime. A limited listing is NOT evidence of absence — omit for the complete list. Zero/negative is rejected.")] = None,
) -> list[dict]:
    """READ-ONLY: list registered backup media, optionally filtered to one pool. ADVERSARIAL:
    entries carry label-text (physical media label/barcode), no return-side pattern constraint.
    `limit` returns only the newest N — a capped slice is never evidence media is absent.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_media_list", "pbs/tape/media/list",
                    lambda: cap_newest(
                        tape_media_list(pbs, pool, update_status, update_status_changer),
                        limit, "ctime"))


@tool()
def pbs_tape_media_content(
    backup_id: Annotated[str | None, Field(description="Filter to one backup ID.")] = None,
    backup_type: Annotated[str | None, Field(description="Filter to one backup type: 'vm', 'ct', or 'host'.")] = None,
    label_text: Annotated[str | None, Field(description="Filter to one media label/barcode (2-32 chars).")] = None,
    media: Annotated[str | None, Field(description="Filter to one media UUID.")] = None,
    media_set: Annotated[str | None, Field(description="Filter to one media-set UUID.")] = None,
    pool: Annotated[str | None, Field(description="Filter to one media pool (2-32 chars).")] = None,
    limit: Annotated[int | None, Field(description="Optional cap: return only the NEWEST N snapshots by backup-time. A limited listing is NOT evidence of absence — omit for the complete list. Zero/negative is rejected.")] = None,
) -> list[dict]:
    """READ-ONLY: list media content — the snapshot inventory recorded across tape. `limit`
    returns only the newest N; a capped slice is never evidence a snapshot is absent. ADVERSARIAL:
    carries `snapshot` (guest-influenced backup id/type/time) AND `label-text` — matches the
    pbs_snapshots_list precedent. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_media_content", "pbs/tape/media/content",
                    lambda: cap_newest(
                        tape_media_content(pbs, backup_id, backup_type, label_text, media, media_set, pool),
                        limit, "backup-time"))


@tool()
def pbs_tape_media_sets(
    limit: Annotated[int | None, Field(description="Optional cap: return only the NEWEST N media sets by media-set-ctime. A limited listing is NOT evidence of absence — omit for the complete list. Zero/negative is rejected.")] = None,
) -> list[dict]:
    """READ-ONLY: list media sets. `limit` returns only the newest N; a capped slice is never
    evidence a media set is absent. REVIEWED_TRUSTED: no label-text field in this response at all
    — media-set-name is PBS-generated from the owning pool's operator-authored template, not
    physical-media content (a deliberate divergence from a naive "media_list/media_sets both
    carry labels" reading — see module docstring's Taint section). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_media_sets", "pbs/tape/media/media-sets",
                    lambda: cap_newest(tape_media_sets(pbs), limit, "media-set-ctime"))


@tool()
def pbs_tape_media_status_get(
    uuid: Annotated[str, Field(description="Media UUID (from pbs_tape_media_list).")],
) -> dict:
    """READ-ONLY: get one medium's current status. The live schema declares this endpoint returns
    null despite the description implying real data (a genuine schema quirk) — best-effort
    passthrough. ADVERSARIAL (conservative default under genuine ambiguity about the real return
    shape). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_media_status_get", f"pbs/tape/media/list/{uuid}/status",
                    lambda: tape_media_status_get(pbs, uuid))


# --- Reads: Tape backup jobs ---

@tool()
def pbs_tape_backup_job_list() -> list[dict]:
    """READ-ONLY: list configured PBS tape backup jobs. REVIEWED_TRUSTED: operator-authored
    scheduled-job config. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_backup_job_list", "pbs/config/tape-backup-job",
                    lambda: tape_backup_job_list(pbs))


@tool()
def pbs_tape_backup_job_get(
    job_id: Annotated[str, Field(description="Tape backup job ID (3-32 chars).")],
) -> dict:
    """READ-ONLY: get one PBS tape backup job's full config. REVIEWED_TRUSTED. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_backup_job_get", f"pbs/config/tape-backup-job/{job_id}",
                    lambda: tape_backup_job_get(pbs, job_id))


# --- Mutations: Media catalog ---

@tool()
def pbs_tape_media_destroy(
    label_text: Annotated[str | None, Field(description="Media label/barcode identifying which medium to destroy (2-32 chars). At least one of label_text/uuid is required.")] = None,
    uuid: Annotated[str | None, Field(description="Media UUID identifying which medium to destroy. At least one of label_text/uuid is required.")] = None,
    force: Annotated[bool | None, Field(description="Force removal even if this media is used in a media set.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the destroy.")] = False,
) -> dict:
    """MUTATION: COMPLETELY REMOVES a tape medium from PBS's database.

    RISK_HIGH: permanent, no undo — PBS's own description, verbatim: "completely remove from
    database". THE HTTP VERB IS GET, BUT THE EFFECT IS DESTRUCTIVE — the verb is not the safety
    signal here; this tool is PLAN-gated and confirm-gated exactly like every POST/PUT/DELETE
    mutation on this server. Dry-run by default (returns a PLAN, and the dry-run path never
    reaches the PBS API even though the real call is a GET); confirm=True executes
    (GET /tape/media/destroy) and returns {"status": "ok", "result": None}. Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    ident = label_text or uuid or "?"
    tgt = f"pbs/tape/media/destroy/{ident}"
    plan = _plan("pbs_tape_media_destroy", tgt,
                 lambda: plan_tape_media_destroy(label_text, uuid, force))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_tape_media_destroy", tgt,
                    lambda: tape_media_destroy(pbs, label_text, uuid, force),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pbs_tape_media_status_set(
    uuid: Annotated[str, Field(description="Media UUID.")],
    status: Annotated[str | None, Field(description="New status: 'full', 'damaged', or 'retired'. Omit to CLEAR the manual override (revert to PBS's internally-managed writable/unknown state). 'writable'/'unknown' are rejected — PBS manages those internally.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the status change.")] = False,
) -> dict:
    """MUTATION: set (or clear) a tape medium's manual status override.

    RISK_MEDIUM: changes whether PBS considers this medium available for future writes —
    reversible by calling this again. Dry-run by default (returns a PLAN); confirm=True executes
    (POST /tape/media/list/{uuid}/status) and returns {"status": "ok", "result": None}. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/media/list/{uuid}/status"
    plan = _plan("pbs_tape_media_status_set", tgt,
                 lambda: plan_tape_media_status_set(uuid, status))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_tape_media_status_set", tgt,
                    lambda: tape_media_status_set(pbs, uuid, status),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pbs_tape_media_move(
    label_text: Annotated[str | None, Field(description="Media label/barcode identifying which medium to move. At least one of label_text/uuid is required.")] = None,
    uuid: Annotated[str | None, Field(description="Media UUID identifying which medium to move. At least one of label_text/uuid is required.")] = None,
    vault_name: Annotated[str | None, Field(description="Vault to move the medium's location to (3-32 chars). OMIT to set location to OFFLINE instead — not a no-op.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the location change.")] = False,
) -> dict:
    """MUTATION: change a tape medium's LOCATION bookkeeping (to a vault, or to offline).

    RISK_MEDIUM: does not physically move anything — updates PBS's own tracking field. A
    scheduled job/inventory expecting this medium online in a changer fails to find it until the
    bookkeeping matches reality again. Dry-run by default (returns a PLAN); confirm=True executes
    (POST /tape/media/move) and returns {"status": "ok", "result": None}. Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    ident = label_text or uuid or "?"
    tgt = f"pbs/tape/media/move/{ident}"
    plan = _plan("pbs_tape_media_move", tgt,
                 lambda: plan_tape_media_move(label_text, uuid, vault_name))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_tape_media_move", tgt,
                    lambda: tape_media_move(pbs, label_text, uuid, vault_name),
                    mutation=True, outcome="ok", detail={"confirmed": True})


# --- Mutations: Tape backup jobs (config) ---

@tool()
def pbs_tape_backup_job_create(
    job_id: Annotated[str, Field(description="New tape backup job ID (3-32 chars).")],
    drive: Annotated[str, Field(description="Drive identifier (3-32 chars).")],
    pool: Annotated[str, Field(description="Media pool name (2-32 chars).")],
    store: Annotated[str, Field(description="Datastore name (3-32 chars).")],
    comment: Annotated[str | None, Field(description="Optional comment (<=128 chars).")] = None,
    eject_media: Annotated[bool | None, Field(description="Eject media upon job completion.")] = None,
    export_media_set: Annotated[bool | None, Field(description="Export media set upon job completion.")] = None,
    group_filter: Annotated[list[str] | None, Field(description="Group filters, e.g. 'type:vm', 'group:GROUP', 'regex:RE', optionally prefixed 'exclude:'/'include:'.")] = None,
    latest_only: Annotated[bool | None, Field(description="Back up latest snapshots only.")] = None,
    max_depth: Annotated[int | None, Field(description="How many namespace levels to operate on (0-7, default 7).")] = None,
    notification_mode: Annotated[str | None, Field(description="'legacy-sendmail' or 'notification-system' (default).")] = None,
    notify_user: Annotated[str | None, Field(description="User ID to notify (user@realm).")] = None,
    ns: Annotated[str | None, Field(description="Namespace to operate on.")] = None,
    schedule: Annotated[str | None, Field(description="Calendar-event schedule string for automatic runs.")] = None,
    worker_threads: Annotated[int | None, Field(description="Number of worker threads (1-32, default 1).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PBS tape backup job.

    RISK_LOW: additive — no existing job/pool/drive config is affected. Dry-run by default
    (returns a PLAN); confirm=True executes (POST /config/tape-backup-job, synchronous — PBS
    returns null) and returns {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/tape-backup-job/{job_id}"
    plan = _plan("pbs_tape_backup_job_create", tgt, lambda: plan_tape_backup_job_create(
        job_id, drive, pool, store, comment, eject_media, export_media_set, group_filter,
        latest_only, max_depth, notification_mode, notify_user, ns, schedule, worker_threads,
    ))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_tape_backup_job_create", tgt, lambda: tape_backup_job_create(
        pbs, job_id, drive, pool, store, comment, eject_media, export_media_set, group_filter,
        latest_only, max_depth, notification_mode, notify_user, ns, schedule, worker_threads,
    ), mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pbs_tape_backup_job_update(
    job_id: Annotated[str, Field(description="ID of the existing tape backup job to update.")],
    drive: Annotated[str | None, Field(description="New drive identifier.")] = None,
    pool: Annotated[str | None, Field(description="New media pool name.")] = None,
    store: Annotated[str | None, Field(description="New datastore name.")] = None,
    comment: Annotated[str | None, Field(description="New comment.")] = None,
    eject_media: Annotated[bool | None, Field(description="Eject media upon job completion.")] = None,
    export_media_set: Annotated[bool | None, Field(description="Export media set upon job completion.")] = None,
    group_filter: Annotated[list[str] | None, Field(description="New group filters.")] = None,
    latest_only: Annotated[bool | None, Field(description="Back up latest snapshots only.")] = None,
    max_depth: Annotated[int | None, Field(description="New namespace depth (0-7).")] = None,
    notification_mode: Annotated[str | None, Field(description="'legacy-sendmail' or 'notification-system'.")] = None,
    notify_user: Annotated[str | None, Field(description="New notify-user (user@realm).")] = None,
    ns: Annotated[str | None, Field(description="New namespace.")] = None,
    schedule: Annotated[str | None, Field(description="New calendar-event schedule.")] = None,
    worker_threads: Annotated[int | None, Field(description="New worker-thread count (1-32).")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned.")] = None,
    delete: Annotated[list[str] | None, Field(description="Property names to clear.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: update a PBS tape backup job.

    RISK_MEDIUM: changes which drive/pool/store/schedule/filters this SCHEDULED job uses on its
    next run. Dry-run by default (captures current config into the PLAN); confirm=True executes
    (PUT /config/tape-backup-job/{id}, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/tape-backup-job/{job_id}"
    plan = _plan("pbs_tape_backup_job_update", tgt, lambda: plan_tape_backup_job_update(
        pbs, job_id, drive, pool, store, comment, eject_media, export_media_set, group_filter,
        latest_only, max_depth, notification_mode, notify_user, ns, schedule, worker_threads,
        digest, delete,
    ))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_tape_backup_job_update", tgt, lambda: tape_backup_job_update(
        pbs, job_id, drive, pool, store, comment, eject_media, export_media_set, group_filter,
        latest_only, max_depth, notification_mode, notify_user, ns, schedule, worker_threads,
        digest, delete,
    ), mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pbs_tape_backup_job_delete(
    job_id: Annotated[str, Field(description="ID of the tape backup job to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PBS tape backup job.

    RISK_MEDIUM: future automatic tape backups for this job's schedule/guest-filter STOP
    SILENTLY — no error, no alert. Media already written to tape is untouched. Dry-run by
    default (captures current config); confirm=True executes (DELETE
    /config/tape-backup-job/{id}, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. No UNDO primitive — re-create with
    pbs_tape_backup_job_create. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/tape-backup-job/{job_id}"
    plan = _plan("pbs_tape_backup_job_delete", tgt, lambda: plan_tape_backup_job_delete(pbs, job_id))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_tape_backup_job_delete", tgt,
                    lambda: tape_backup_job_delete(pbs, job_id),
                    mutation=True, outcome="ok", detail={"confirmed": True})


@tool()
def pbs_tape_backup_job_run(
    job_id: Annotated[str, Field(description="ID of the tape backup job to run manually.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the run.")] = False,
) -> dict:
    """MUTATION: manually run a preconfigured tape backup job, right now.

    RISK_MEDIUM: triggers a real tape backup using the job's configured drive/pool/store/filters
    — the drive is busy for the duration. Dry-run by default (returns a PLAN); confirm=True
    executes (POST /tape/backup/{id}). SCHEMA QUIRK: this endpoint returns null (unlike the
    one-off pbs_tape_backup, which returns a UPID) — returns {"status": "ok", "result": None},
    never "submitted". Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/backup/{job_id}"
    plan = _plan("pbs_tape_backup_job_run", tgt, lambda: plan_tape_backup_job_run(job_id))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_tape_backup_job_run", tgt,
                    lambda: tape_backup_job_run(pbs, job_id),
                    mutation=True, outcome="ok", detail={"confirmed": True})


# --- Mutations: One-off backup + restore ---

@tool()
def pbs_tape_backup(
    drive: Annotated[str, Field(description="Drive identifier (3-32 chars).")],
    pool: Annotated[str, Field(description="Media pool name (2-32 chars).")],
    store: Annotated[str, Field(description="Datastore name to back up (3-32 chars, a single identifier — NOT the comma-separated mapping shape pbs_tape_restore's store uses).")],
    eject_media: Annotated[bool | None, Field(description="Eject media upon completion.")] = None,
    export_media_set: Annotated[bool | None, Field(description="Export media set upon completion.")] = None,
    force_media_set: Annotated[bool | None, Field(description="Ignore the pool's allocation policy and start a new media-set.")] = None,
    group_filter: Annotated[list[str] | None, Field(description="Group filters.")] = None,
    latest_only: Annotated[bool | None, Field(description="Back up latest snapshots only.")] = None,
    max_depth: Annotated[int | None, Field(description="Namespace depth (0-7).")] = None,
    notification_mode: Annotated[str | None, Field(description="'legacy-sendmail' or 'notification-system'.")] = None,
    notify_user: Annotated[str | None, Field(description="Notify-user (user@realm).")] = None,
    ns: Annotated[str | None, Field(description="Namespace to back up.")] = None,
    worker_threads: Annotated[int | None, Field(description="Worker-thread count (1-32).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the backup.")] = False,
) -> dict:
    """MUTATION: one-off tape backup — back up a datastore to a tape pool right now, no
    schedule/job-id involved.

    RISK_MEDIUM: writes datastore contents to tape, drive busy for the duration. Dry-run by
    default (returns a PLAN); confirm=True executes (POST /tape/backup) and returns
    {"status": "submitted", "result": "<UPID>"}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/backup/{store}"
    plan = _plan("pbs_tape_backup", tgt, lambda: plan_tape_backup(
        drive, pool, store, eject_media, export_media_set, force_media_set, group_filter,
        latest_only, max_depth, notification_mode, notify_user, ns, worker_threads,
    ))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_tape_backup", tgt, lambda: tape_backup(
        pbs, drive, pool, store, eject_media, export_media_set, force_media_set, group_filter,
        latest_only, max_depth, notification_mode, notify_user, ns, worker_threads,
    ), mutation=True, outcome="submitted", detail={"confirmed": True})


@tool()
def pbs_tape_restore(
    drive: Annotated[str, Field(description="Drive identifier (3-32 chars).")],
    media_set: Annotated[str, Field(description="Media set UUID to restore from.")],
    store: Annotated[str, Field(description="Datastore MAPPING — comma-separated (<source>=)?<target> entries, e.g. 'a=b,e' maps source 'a' to target 'b' and everything else to default 'e'. NOT the same shape as pbs_tape_backup's plain single-identifier store.")],
    namespaces: Annotated[list[str] | None, Field(description="Namespace mappings: 'store=<name>[,max-depth=<int>][,source=<ns>][,target=<ns>]' entries. Omit to restore into default namespaces (auto-created as needed).")] = None,
    notification_mode: Annotated[str | None, Field(description="'legacy-sendmail' or 'notification-system'.")] = None,
    notify_user: Annotated[str | None, Field(description="Notify-user (user@realm).")] = None,
    owner: Annotated[str | None, Field(description="Authentication ID to own restored snapshots (user@realm or user@realm!token-name).")] = None,
    snapshots: Annotated[list[str] | None, Field(description="Selective restore: specific snapshots as 'store:[ns/namespace/...]type/id/time'. Omit to restore the WHOLE media-set.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the restore.")] = False,
) -> dict:
    """MUTATION: restore data from a tape media-set into a datastore.

    RISK_HIGH: WRITES into an existing datastore; namespaces are AUTO-CREATED as needed; PBS's
    own schema does not state what happens if a target snapshot already exists at the
    destination (Smoke-confirm — may overwrite, skip, or fail per-snapshot); a media-set can
    span many snapshots across many namespaces in one call. Dry-run by default (returns a PLAN);
    confirm=True executes (POST /tape/restore) and returns
    {"status": "submitted", "result": "<UPID>"}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    # media_set is an open string (no schema pattern) — embedded via !r so an out-of-charset
    # byte can never ride raw into the ledger target, including on the plan-build ERROR path
    # where the audit record is written before validation completes (Wave 4d review finding 3).
    tgt = f"pbs/tape/restore/{media_set!r}"
    plan = _plan("pbs_tape_restore", tgt, lambda: plan_tape_restore(
        drive, media_set, store, namespaces, notification_mode, notify_user, owner, snapshots,
    ))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited("pbs_tape_restore", tgt, lambda: tape_restore(
        pbs, drive, media_set, store, namespaces, notification_mode, notify_user, owner, snapshots,
    ), mutation=True, outcome="submitted", detail={"confirmed": True})
