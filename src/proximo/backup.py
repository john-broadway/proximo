"""BACKUP & RESTORE pillar — vzdump-based backup operations + planning.

Follows Proximo's exact idiom:
- Op functions build requests and return results/UPIDs; they do NOT self-gate.
  The server layer adds confirm-gating + audit before calling these.
- Plan functions are pure (plan_restore does one safe read to detect existing vmid).
- All path components are validated before going into URLs.
- volid validation + URL-encoding is two-layered: format check AND traversal rejection.
- RISK_LOW means "does not change state in the guest", NOT "safe".
  RISK_HIGH on destructive ops (restore-overwrite, stop-mode backup, backup-delete).
"""

from __future__ import annotations

import re
from urllib.parse import quote

from .backends import ProximoError, _check_kind, _check_node, _check_vmid
from .doctor import collect_priv_flags, holds
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan
from .storage import _check_storage  # reuse: same regex/rule, no duplication

# --- valid modes + compression for vzdump ---
_VALID_MODES = frozenset({"snapshot", "suspend", "stop"})
_VALID_COMPRESS = frozenset({"zstd", "gzip", "lzo", "0", "1"})

# volid looks like:  local:backup/vzdump-lxc-102-2026_06_08.tar.zst
# Allowed characters: alnum, ':', '/', '.', '_', '-'  (no other shell-special chars)
# A volid is '<storage>:<path>'. The storage id (before the FIRST colon) is a plain id; the path
# MAY contain further colons — PBS volids embed an RFC3339 snapshot time (…/2026-07-09T02:00:00Z)
# whose HH:MM:SS carries colons. No '..' components. \Z (not $) prevents trailing-newline bypass.
_VOLID_RE = re.compile(r"^[A-Za-z0-9._:/-]+\Z")
_STORAGE_PART_RE = re.compile(r"^[A-Za-z0-9._-]+\Z")  # storage id: no ':' or '/'


def _check_volid(volid: str) -> str:
    """Validate a Proxmox volume-id (e.g. local:backup/vzdump-lxc-102-2026_06_08.tar.zst, or a PBS
    archive like pbs:backup/vm/100/2026-07-09T02:00:00Z).

    Layers:
    1. Character-set validation (rejects shell-specials) + explicit traversal rejection ('..').
    2. Partition on the FIRST colon: the storage id is validated strictly (no ':' / '/'); the path
       part may itself contain ':' (PBS RFC3339 snapshot times). 2026-07-10 audit H1: the old
       `count(':') != 1` rule rejected every PBS-backed archive, disabling restore/prune from PBS.
    Returns the raw volid (not URL-encoded); callers must quote() before inserting into a path.
    """
    v = str(volid)
    if ".." in v:
        raise ProximoError(f"invalid volid: {volid!r} (path traversal rejected)")
    if not _VOLID_RE.match(v):
        raise ProximoError(
            f"invalid volid: {volid!r} (unexpected characters — expected alnum plus : / . _ -)"
        )
    storage_part, sep, path_part = v.partition(":")
    if not sep or not storage_part or not path_part:
        raise ProximoError(
            f"invalid volid: {volid!r} (expected 'storage:path' with both parts non-empty)"
        )
    if not _STORAGE_PART_RE.match(storage_part):
        raise ProximoError(
            f"invalid volid: {volid!r} (storage id must be letters/digits/._- with no ':' or '/')"
        )
    if any(seg == "" for seg in path_part.split("/")):
        raise ProximoError(f"invalid volid: {volid!r} (empty path segment rejected)")
    return v


# ── OPERATIONS ─────────────────────────────────────────────────────────────────


def vzdump_backup(
    api,
    vmid: str,
    storage: str,
    mode: str = "snapshot",
    compress: str = "zstd",
    node: str | None = None,
) -> str:
    """Trigger a vzdump backup of vmid to storage.  Returns a task UPID string.

    POST /nodes/{node}/vzdump
    Body: {vmid, storage, mode, compress}
    """
    vmid = _check_vmid(vmid)
    storage = _check_storage(storage)
    _check_node(node)
    if mode not in _VALID_MODES:
        raise ProximoError(f"invalid backup mode: {mode!r} (expected snapshot|suspend|stop)")
    if compress not in _VALID_COMPRESS:
        raise ProximoError(
            f"invalid compress: {compress!r} (expected one of {sorted(_VALID_COMPRESS)})"
        )
    n = node or api.config.node
    data = {"vmid": vmid, "storage": storage, "mode": mode, "compress": compress}
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/nodes/{n}/vzdump", data)


def backup_list(api, storage: str, node: str | None = None) -> list[dict]:
    """List backup archives on a storage.  Returns a list of volume dicts (volid, size, ctime, …).

    GET /nodes/{node}/storage/{storage}/content?content=backup
    """
    storage = _check_storage(storage)
    _check_node(node)
    n = node or api.config.node
    return api._get(f"/nodes/{n}/storage/{storage}/content?content=backup") or []


def storage_blind_reason(api, storage: str) -> str | None:
    """Why this token could NOT have seen a backup volume on `storage`, or None if it could.

    PVE filters backup volumes OUT of the content listing per volume (check_volume_access):
    seeing one needs Datastore.AllocateSpace on the storage AND VM.Backup on the owner guest,
    or Datastore.Allocate on the storage as a bypass. A token without them gets 200 + [] on a
    storage full of archives (live-found 2026-07-09 by the freshness fence; the plain listing
    kept saying "no backups" until 2026-09-16). Only PROVABLE blindness is reported: no
    Datastore.Allocate on the storage and (no AllocateSpace on it, or VM.Backup held on no path
    at all). An unreadable or EMPTY permission map proves nothing and returns None.
    """
    try:
        raw = api.access_permissions()
    except Exception:
        return None
    # A map with no entries is not a map to reason from: a token holding NOTHING could not have
    # listed the storage's content in the first place (403, never 200 + []), so reaching here
    # with {} means a malformed or stubbed read. Proves nothing; say nothing.
    if not isinstance(raw, dict) or not raw:
        return None
    flags = collect_priv_flags(raw)
    spath = f"/storage/{storage}"
    if holds(flags, "Datastore.Allocate", spath):
        return None
    has_space = holds(flags, "Datastore.AllocateSpace", spath)
    # VM.Backup held ANYWHERE counts as sight. PVE's filter is per volume (the owner guest), so a
    # token granted on /vms/999 alone sees only guest 999's archives and [] then truthfully means
    # "none for the guests you were granted" — that scope is the admin's decision, and SETUP.md
    # says so. Only a token that can see NO guest's archives is blind for the listing.
    if has_space and flags.get("VM.Backup"):
        return None
    missing = ("VM.Backup on the guests" if has_space
               else f"Datastore.AllocateSpace on {spath} and VM.Backup on the guests")
    return (
        f"no backup archives visible on '{storage}', and this token cannot see backup volumes "
        f"there: PVE hides them from the content listing (200 + empty) unless the token holds "
        f"Datastore.AllocateSpace on {spath} AND VM.Backup on the owner guest (or "
        f"Datastore.Allocate on {spath}). Missing: {missing}. The archives may exist. Grant a "
        f"sighted role to the token AND its user, e.g. "
        f"pveum role add ProximoBackupSight -privs 'Datastore.Audit,Datastore.AllocateSpace,"
        f"VM.Audit,VM.Backup' then pveum acl modify {spath} --tokens '<user@realm!token>' "
        f"--roles ProximoBackupSight and the same on /vms (or /vms/<id>), then list again."
    )


def backup_list_sighted(api, storage: str, node: str | None = None) -> list[dict]:
    """`backup_list`, refusing to report an EMPTY storage the token could not have seen into.

    Non-empty listings return as-is (no permissions read: PVE already showed the volumes).
    Empty + provably blind raises ProximoError carrying the grant recipe; empty + sighted (or
    unprovable) returns []. A read tool that answers "nothing" while blind is lying.
    """
    archives = backup_list(api, storage, node)
    if archives:
        return archives
    reason = storage_blind_reason(api, storage)
    if reason:
        raise ProximoError(reason)
    return []


def backup_delete(api, storage: str, volid: str, node: str | None = None):
    """Delete a backup archive.  Returns a task UPID — or None for synchronous (dir-storage) deletes.

    DELETE /nodes/{node}/storage/{storage}/content/{url-encoded-volid}

    Endpoint-shape uncertainty: directory-backed storage may return None (synchronous delete)
    rather than a UPID. Do NOT validate the return as a UPID; return raw. Confirm at live smoke.
    """
    storage = _check_storage(storage)
    volid = _check_volid(volid)
    _check_node(node)
    n = node or api.config.node
    quoted = quote(volid, safe="")
    # DESTRUCTIVE — confirm-gated + audited at the server layer.
    return api._delete(f"/nodes/{n}/storage/{storage}/content/{quoted}")


def restore_guest(
    api,
    vmid: str,
    archive: str,
    storage: str,
    kind: str = "lxc",
    node: str | None = None,
    force: bool = False,
    pool: str | None = None,
) -> str:
    """Restore a guest from a backup archive.  Returns a task UPID.

    LXC:  POST /nodes/{node}/lxc   body {vmid, ostemplate: archive, storage, restore: 1}
    QEMU: POST /nodes/{node}/qemu  body {vmid, archive, force: 1 if force}

    Note: QEMU restore does NOT send storage or restore:1 — these are LXC-only params.
    Endpoint-shape uncertainty: confirm at live smoke whether QEMU needs additional params
    (e.g. format, pool) for non-trivial configs.
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)
    archive = _check_volid(archive)  # the backup source is a volid — validate like backup_delete
    n = node or api.config.node
    # DESTRUCTIVE — confirm-gated + audited at the server layer.
    if kind == "lxc":
        storage = _check_storage(storage)
        data: dict = {"vmid": vmid, "ostemplate": archive, "storage": storage, "restore": 1}
        if force:
            data["force"] = 1
        if pool is not None:
            data["pool"] = pool
        return api._post(f"/nodes/{n}/lxc", data)
    else:  # qemu
        data = {"vmid": vmid, "archive": archive}
        if force:
            data["force"] = 1
        if pool is not None:
            data["pool"] = pool
        return api._post(f"/nodes/{n}/qemu", data)


# ── PLAN FUNCTIONS ─────────────────────────────────────────────────────────────


def plan_backup(
    vmid: str,
    storage: str,
    mode: str = "snapshot",
    kind: str = "lxc",
) -> Plan:
    """Preview a vzdump backup.  PURE — no API call needed.

    Risk varies by mode:
    - snapshot → RISK_LOW: online backup; guest stays live. Brief I/O/CPU spike.
    - suspend  → RISK_MEDIUM: guest is briefly suspended (RAM quiesced); short pause.
    - stop     → RISK_HIGH: guest is stopped for the backup; service downtime.
    """
    _check_vmid(vmid)
    _check_kind(kind)
    _check_storage(storage)
    if mode not in _VALID_MODES:
        raise ProximoError(f"invalid backup mode: {mode!r} (expected snapshot|suspend|stop)")

    if mode == "snapshot":
        risk = RISK_LOW
        reasons = ["online backup (snapshot mode) — guest stays running"]
        blast = [
            f"backs up {kind}/{vmid} to storage '{storage}' without halting the guest",
            "brief I/O and CPU spike during backup; guest stays online",
        ]
    elif mode == "suspend":
        risk = RISK_MEDIUM
        reasons = ["guest is briefly suspended (RAM quiesced) during backup — short service pause"]
        blast = [
            f"backs up {kind}/{vmid} to storage '{storage}'",
            "guest is SUSPENDED briefly while memory is frozen; short-lived service interruption",
        ]
    else:  # mode == "stop"
        risk = RISK_HIGH
        reasons = ["stop mode HALTS the guest for the backup duration — downtime"]
        blast = [
            f"STOPS {kind}/{vmid} for the backup duration, then restarts it",
            "guest is OFFLINE during the backup; any connected clients will be disconnected",
        ]

    return Plan(
        action="pve_backup",
        target=f"{kind}/{vmid}",
        change=f"vzdump backup {kind} {vmid} to {storage} (mode={mode})",
        current={},
        blast_radius=blast,
        risk=risk,
        risk_reasons=reasons,
    )


def plan_restore(
    api,
    vmid: str,
    archive: str,
    kind: str = "lxc",
    node: str | None = None,
    force: bool = False,
) -> Plan:
    """Preview a guest restore.  Reads live state (one safe read) to detect existing vmid.

    - vmid exists + force=True  → RISK_HIGH: overwrites and destroys the running guest.
    - vmid exists + force=False → RISK_MEDIUM: restore will fail; documents why without contradiction.
    - vmid not found            → RISK_MEDIUM: creates a new guest from the archive.
    """
    vmid = _check_vmid(vmid)
    kind = _check_kind(kind)
    _check_node(node)

    # One safe read to detect if the vmid already exists. Three outcomes — and we must NOT collapse
    # them: a transient failure is NOT evidence of absence. Claiming "creates new, no overwrite" when
    # the guest might actually exist is exactly the false-safety this project forbids.
    existing = None
    check_failed = False
    try:
        existing = api.guest_status(vmid, kind, node)  # success → vmid exists
    except Exception as e:
        # Only a definitive 404 means "confirmed absent". Timeout / 5xx / permission = UNKNOWN.
        resp = getattr(e, "response", None)
        if resp is not None and getattr(resp, "status_code", None) == 404:
            existing = None          # confirmed not found
        else:
            check_failed = True      # could not determine — assume nothing

    if existing is not None:
        name = existing.get("name") or vmid
        current = {k: existing[k] for k in ("status", "name") if k in existing}
        if force:
            risk = RISK_HIGH
            reasons = [
                "force restore OVERWRITES and DESTROYS the existing guest — all data since last backup is lost"
            ]
            blast = [
                f"OVERWRITES and DESTROYS existing {kind}/{vmid} (name={name!r}), "
                f"replacing it with the backup archive '{archive}'",
                "existing guest disks, config, and snapshots will be lost",
            ]
        else:
            # Exists but force not set → the restore FAILS at PVE; no changes are made.
            # No contradiction: state "will fail" clearly without claiming it also destroys.
            risk = RISK_MEDIUM
            reasons = [
                f"{kind}/{vmid} already exists and force is not set — restore will be rejected by PVE"
            ]
            blast = [
                f"restore will FAIL — {vmid} exists and force is not set; "
                "no changes would be made to the existing guest",
            ]
    elif check_failed:
        # Existence UNKNOWN. Never claim "creates new" (could be an overwrite). With force, the worst
        # case is destroying an existing guest → rate HIGH; without force the worst case is a failed
        # restore → MEDIUM. Either way, disclose the uncertainty rather than imply safety.
        current = {}
        if force:
            risk = RISK_HIGH
            reasons = [
                "could not verify whether the target exists — with force, if it DOES exist this "
                "OVERWRITES and DESTROYS it (absence of confirmation is not a safety signal)",
            ]
            blast = [
                f"could NOT confirm whether {kind}/{vmid} exists; with force=True, if it exists this "
                f"OVERWRITES and DESTROYS it with archive '{archive}'",
            ]
        else:
            risk = RISK_MEDIUM
            reasons = [
                "could not verify whether the target exists — if it does not, this creates a new "
                "guest; if it does, the restore is rejected (force not set). No overwrite without force.",
            ]
            blast = [
                f"could NOT confirm whether {kind}/{vmid} exists; if absent this creates it from "
                f"archive '{archive}', if present the restore is rejected (force not set)",
            ]
    else:
        current = {}
        risk = RISK_MEDIUM
        reasons = [f"{kind}/{vmid} not found — restore will create a new guest from the archive"]
        blast = [
            f"creates {kind}/{vmid} from backup archive '{archive}'",
            "new guest is created; no existing guest is overwritten",
        ]

    return Plan(
        action="pve_restore",
        target=f"{kind}/{vmid}",
        change=f"restore {kind} {vmid} from archive '{archive}' (force={force})",
        current=current,
        blast_radius=blast,
        risk=risk,
        risk_reasons=reasons,
    )


_BACKUP_VMID_RE = re.compile(r"vzdump-(?:lxc|qemu|openvz)-(\d+)-")


def _vmid_from_backup_volid(volid: str) -> str | None:
    """The guest vmid embedded in a vzdump backup volid (e.g. '…/vzdump-lxc-102-…' → '102')."""
    m = _BACKUP_VMID_RE.search(volid)
    return m.group(1) if m else None


def plan_backup_delete(api, storage: str, volid: str) -> Plan:
    """Preview a backup archive deletion.

    RISK_HIGH: a backup is a disaster-recovery copy of last resort; deleting it is unrecoverable.
    Blast-radius coverage: reads the storage's backup list and reports whether OTHER recovery points
    of the same guest remain — deleting the LAST backup leaves no recovery point. A read failure or an
    unparseable guest id is disclosed (complete=False), never read as 'other copies exist'.
    """
    _check_storage(storage)
    _check_volid(volid)

    blast = [
        f"PERMANENTLY removes backup archive '{volid}' — a recovery point is destroyed; "
        "you cannot restore from it afterward",
    ]
    reasons = [
        "deletes a disaster-recovery backup; the data it holds is permanently gone — unrecoverable",
    ]
    affected: list[dict] = []
    complete = True

    vmid = _vmid_from_backup_volid(volid)
    try:
        from .storage import storage_content
        backups = storage_content(api, storage, content="backup") or []
        if vmid is None:
            match = next((b for b in backups if b.get("volid") == volid), None)
            if match is not None and match.get("vmid") not in (None, ""):
                vmid = str(match.get("vmid"))
        if vmid is not None:
            siblings = [b for b in backups
                        if str(b.get("vmid", "")) == str(vmid) and b.get("volid") != volid]
            remaining = len(siblings)
            affected.append({"vmid": str(vmid), "remaining": remaining,
                             "severity": "high",
                             "effect": ("LAST recovery point — NO other backup of this guest remains"
                                        if remaining == 0
                                        else f"{remaining} other backup(s) of this guest remain")})
            if remaining == 0:
                blast.append(
                    f"this is the LAST backup of guest {vmid} — deleting it leaves NO other recovery point"
                )
                reasons.append(f"last remaining backup of guest {vmid} — no other recovery point")
            else:
                blast.append(f"{remaining} other backup(s) of guest {vmid} remain after this deletion")
        else:
            complete = False
            blast.append(
                "could not determine which guest this backup belongs to — cannot count remaining "
                "recovery points (absence of a count is NOT a safety signal)"
            )
    except Exception as exc:
        complete = False
        blast.append(
            f"could NOT read the backup list ({type(exc).__name__}) — cannot confirm whether other "
            "recovery points of this guest remain; absence of a count is NOT a safety signal"
        )
        reasons.append("backup list read failed — remaining-copy count unknown")

    return Plan(
        action="pve_backup_delete",
        target=f"{storage}:{volid}",
        change=f"delete backup archive '{volid}' from storage '{storage}'",
        current={},
        blast_radius=blast,
        risk=RISK_HIGH,
        risk_reasons=reasons,
        affected=affected,
        complete=complete,
    )
