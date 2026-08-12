"""PBS tape hardware config plane — drive CRUD, changer CRUD, and hardware autodetection scans
(Wave 4a of the full-surface campaign, `.scratch/2026-07-15-full-surface-campaign.md`,
"Wave 4 decomposition (PBS tape)", "4a — tape hardware config"). No PVE sibling exists — tape is
PBS-only — so idioms are mirrored from the freshest PBS waves (`pbs_disks.py` Wave 2d,
`pbs_notifications.py` Wave 3a, `pbs_acme.py` Wave 3b) rather than diffed against a PVE module.

Schema truth: `.scratch/api-schemas-2026-07-15/wave4-pbs-tape-schema.json` (the live PBS
apidoc.js, pulled 2026-07-15). Media pools, tape-backup jobs, encryption keys (4b), drive/changer
*operations* (status/load/unload/label/format/catalog, 4c), and media catalog/backup/restore (4d)
are separate later chunks of this wave — not built here.

Endpoint table (12 tools total — 6 read, 6 mutation):

  GET    /config/drive                — pbs_tape_drive_list     (read)
  GET    /config/drive/{name}         — pbs_tape_drive_get      (read)
  GET    /config/changer              — pbs_tape_changer_list   (read)
  GET    /config/changer/{name}       — pbs_tape_changer_get    (read)
  GET    /tape/scan-drives            — pbs_tape_scan_drives    (read)
  GET    /tape/scan-changers          — pbs_tape_scan_changers  (read)
  POST   /config/drive                — pbs_tape_drive_create   (MUTATION, MEDIUM)
  PUT    /config/drive/{name}         — pbs_tape_drive_update   (MUTATION, MEDIUM)
  DELETE /config/drive/{name}         — pbs_tape_drive_delete   (MUTATION, LOW)
  POST   /config/changer              — pbs_tape_changer_create (MUTATION, MEDIUM)
  PUT    /config/changer/{name}       — pbs_tape_changer_update (MUTATION, MEDIUM)
  DELETE /config/changer/{name}       — pbs_tape_changer_delete (MUTATION, LOW)

SCHEMA-VERIFIED FACTS (binding on this build — from the live schema, not memory):

  1. **No `node` parameter anywhere on this plane.** Unlike `pbs_disks.py`'s
     `/nodes/{node}/disks/...` convention (Wave 2d), every one of these 6 paths is host-wide —
     confirmed: none of `/config/drive[/{name}]`, `/config/changer[/{name}]`,
     `/tape/scan-drives`, `/tape/scan-changers` has a `node` property in its parameter schema.
     PBS tape hardware config is not node-scoped at this API surface.
  2. **`name` (drive/changer identifier) is IDENTICAL on both resources**: pattern
     `/^(?:[A-Za-z0-9_][A-Za-z0-9._\\-]*)$/`, minLength 3, maxLength 32, confirmed on every one
     of drive-list-item/drive-GET/drive-POST/drive-PUT/drive-DELETE and the equivalent 5 changer
     endpoints, AND on drive's own `changer` field (which references a changer identifier by the
     same pattern). One shared validator (`_check_tape_id`) covers all three uses. Per the
     campaign brief's instruction to check for the `/^A|B$/` alternation-precedence authoring
     slip documented in `pbs_disks.py`'s REGEX STRICTNESS NOTE: this pattern has NO `|`
     alternation at all — nothing to correct here beyond the usual bare-`$` -> `\\Z` re-anchor
     this codebase always applies (trailing-newline-bypass discipline).
  3. **`digest` optimistic-lock exists on PUT only, never on POST** — confirmed: neither
     `/config/drive` POST nor `/config/changer` POST has a `digest` property; both PUTs do
     (`/^[a-f0-9]{64}$/`, re-anchored `\\Z` here same as `pbs_notifications.py`/`pbs_acme.py`).
     Forwarded only where the schema offers it, validated at PLAN time too (not just execution)
     — same early-validation contract those two modules established.
  4. **`export-slots` (changer only) is wire-typed `string`, not an array**, despite its
     `format` block describing an array of integers and its `typetext` reading
     `[<integer>, ...]` — the schema's own `description` is explicit: "A list of slot numbers,
     COMMA SEPARATED." This is the same PVE::JSONSchema convention `pbs_disks.py`'s
     `devices` (comma-separated disk list) already established — exposed here as a plain
     `export_slots: str | None` (e.g. `"1,2,3"`), validated comma-by-comma as positive integers
     (`_check_export_slots`), not converted to/from a Python list.
  5. **`changer-drivenum` is bounded 0-255, default 0, requires `changer` to mean anything**
     (schema description: "Associated changer drive number (requires option changer)") —
     Proximo does not enforce the "requires changer" co-constraint client-side (the live PBS API
     will reject an inconsistent combination on `confirm=True`; inventing a stricter client-side
     rule here would risk diverging from PBS's actual enforcement).
  6. **All 6 mutations return `null` per the schema** (every POST/PUT/DELETE on this plane
     declares `"returns": {"type": "null"}`) — SYNCHRONOUS config ops, not async task UPIDs.
     Every wrapper records outcome="ok", never "submitted" — same convention
     `pbs_notifications.py`/`pbs_acme.py`'s config CRUD already established.
  7. **No secret-shaped field anywhere on this plane.** Neither drive nor changer config carries
     a credential (unlike notifications' token/password/secret/header or ACME's eab_hmac_key/
     plugin data) — no redaction machinery is needed here.
  8. **PUT's `delete` enum differs per resource**: drive PUT accepts
     `["changer", "changer-drivenum"]`; changer PUT accepts
     `["export-slots", "eject-before-unload"]`. Neither is validated against its closed enum
     client-side — same "pass the list through, let the live API enforce its own enum" posture
     `pbs_notifications.py`'s `notification_matcher_set`'s own `delete` param already takes.

RISK RATING (module-specific reasoning — the campaign brief set a MEDIUM ceiling for creates/
updates and a LOW-MEDIUM band for deletes, mirroring how `pbs_notifications.py` rated its config
deletes):
  - **create/update = RISK_MEDIUM** (a step up from `pbs_notifications.py`'s uniform RISK_LOW):
    unlike a notification endpoint (which only affects whether an ALERT gets delivered), a
    drive/changer `path` maps an identifier directly onto a REAL host SCSI-generic device node.
    A wrong `path` on create, or a `path`/`changer` change on update, means a future tape job
    silently targets the wrong physical drive/changer/robot the next time it runs — a materially
    different failure mode than a missed notification.
  - **delete = RISK_LOW** (mirrors `pbs_notifications.py`'s own delete rating exactly, per the
    brief): removing the config mapping does NOT touch the tape hardware or any data already
    written to tape (confirmed: neither DELETE description mentions data/media at all, only "a
    drive/changer configuration") — it only breaks the identifier a tape-backup-job config
    references, the same "silently fails until re-created" shape `pbs_notifications.py`'s own
    endpoint/matcher deletes already carry.

Security posture:
  - All path components (`name`) validated with a \\Z-anchored regex (trailing-newline bypass
    rejected), mirroring every other PBS module in this codebase.
  - `digest` re-anchored \\Z, validated at both PLAN time and execution time.
  - No snapshot/UNDO primitive on this plane (config is re-creatable, not restorable) — every
    mutation plan says so explicitly. update/delete plans CAPTURE the live current config (no
    secrets to redact on this plane — see fact #7) so a caller has what it needs to re-apply.
  - Taint: all 12 tools are REVIEWED_TRUSTED. The two scan reads (`pbs_tape_scan_drives`/
    `pbs_tape_scan_changers`) return device-reported vendor/model/serial strings — hardware-
    authored, not guest/attacker-authored — matching the precedent already set by
    `pve_hardware_list` and `pbs_node_disks_list`/`pbs_node_disk_smart` (both REVIEWED_TRUSTED
    despite also carrying autodetected vendor/model/serial fields). No divergence from that
    precedent found; not reclassified adversarial.

VERIFIED live shapes: None — all backend functions carry "Smoke-confirm:" comments; every shape
here is schema-derived, not live-proven against a running PBS.
"""

from __future__ import annotations

import re

from ._validate import check_digest as _check_digest
from .backends import ProximoError
from .pbs import PbsBackend, _check_delete_list
from .planning import RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# Drive/changer identifier — shared by drive.name, changer.name, and drive.changer (a reference
# to a changer identifier). Schema pattern has no `|` alternation (module docstring fact #2) —
# mirrored directly, just \Z-re-anchored per this codebase's trailing-newline-bypass discipline.
# Length (3-32) enforced separately since the regex itself doesn't encode it.
_TAPE_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*\Z")


def _check_tape_id(value: str) -> str:
    s = str(value)
    if not (3 <= len(s) <= 32) or not _TAPE_ID_RE.match(s):
        raise ProximoError(
            f"invalid PBS tape drive/changer identifier: {value!r} (must start with alnum or "
            "underscore, then alnum/./_/-, 3-32 chars)"
        )
    return s


def _check_changer_drivenum(value: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid changer-drivenum: {value!r} (must be an integer)") from exc
    if not (0 <= n <= 255):
        raise ProximoError(f"invalid changer-drivenum: {value!r} (must be 0-255)")
    return n


def _check_export_slots(value: str) -> str:
    """Comma-separated positive integers — wire shape is a plain string (module docstring
    fact #4), not a JSON array. Mirrors pbs_disks.py's `_check_devices_csv` shape."""
    s = str(value)
    parts = s.split(",")
    if not parts or any(not p for p in parts):
        raise ProximoError(
            f"invalid export-slots list: {value!r} — comma-separated positive integers, no "
            "empty segments"
        )
    for p in parts:
        try:
            n = int(p)
        except ValueError as exc:
            raise ProximoError(
                f"invalid export-slots list: {value!r} — {p!r} is not an integer"
            ) from exc
        if n < 1:
            raise ProximoError(
                f"invalid export-slots list: {value!r} — slot numbers must be >= 1 (got {n})"
            )
    return s


# ---------------------------------------------------------------------------
# Backend functions — reads
# ---------------------------------------------------------------------------

def tape_drive_list(api: PbsBackend) -> list[dict]:
    """GET /config/drive — list configured LTO SCSI tape drives (with config digest).
    Smoke-confirm: response shape."""
    return api._get("/config/drive") or []


def tape_drive_get(api: PbsBackend, name: str) -> dict:
    """GET /config/drive/{name} — one drive's full config. Smoke-confirm: response shape."""
    name = _check_tape_id(name)
    return api._get(f"/config/drive/{name}") or {}


def tape_changer_list(api: PbsBackend) -> list[dict]:
    """GET /config/changer — list configured SCSI tape changers (with config digest).
    Smoke-confirm: response shape."""
    return api._get("/config/changer") or []


def tape_changer_get(api: PbsBackend, name: str) -> dict:
    """GET /config/changer/{name} — one changer's full config. Smoke-confirm: response shape."""
    name = _check_tape_id(name)
    return api._get(f"/config/changer/{name}") or {}


def tape_scan_drives(api: PbsBackend) -> list[dict]:
    """GET /tape/scan-drives — autodetect tape drives attached to the PBS host (Linux SCSI
    generic device nodes). Returns {kind, major, minor, model, path, serial, vendor} per device
    — hardware-reported, not config. No params. Smoke-confirm: response shape."""
    return api._get("/tape/scan-drives") or []


def tape_scan_changers(api: PbsBackend) -> list[dict]:
    """GET /tape/scan-changers — autodetect SCSI tape changers attached to the PBS host. Same
    response shape as tape_scan_drives. No params. Smoke-confirm: response shape."""
    return api._get("/tape/scan-changers") or []


# ---------------------------------------------------------------------------
# Backend functions — mutations, Drives
# ---------------------------------------------------------------------------

def tape_drive_create(
    api: PbsBackend,
    name: str,
    path: str,
    changer: str | None = None,
    changer_drivenum: int | None = None,
) -> None:
    """POST /config/drive — name+path required, changer/changer-drivenum optional. Returns null
    (synchronous). MUTATION — confirm-gated + audited at the server layer."""
    name = _check_tape_id(name)
    data: dict = {"name": name, "path": str(path)}
    if changer is not None:
        data["changer"] = _check_tape_id(changer)
    if changer_drivenum is not None:
        data["changer-drivenum"] = _check_changer_drivenum(changer_drivenum)
    api._post("/config/drive", data)


def tape_drive_update(
    api: PbsBackend,
    name: str,
    path: str | None = None,
    changer: str | None = None,
    changer_drivenum: int | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> None:
    """PUT /config/drive/{name} — all fields optional except the path name. Returns null
    (synchronous). MUTATION — confirm-gated + audited at the server layer."""
    name = _check_tape_id(name)
    data: dict = {}
    if path is not None:
        data["path"] = str(path)
    if changer is not None:
        data["changer"] = _check_tape_id(changer)
    if changer_drivenum is not None:
        data["changer-drivenum"] = _check_changer_drivenum(changer_drivenum)
    if digest is not None:
        data["digest"] = _check_digest(digest)
    if delete is not None:
        data["delete"] = _check_delete_list(delete)
    api._put(f"/config/drive/{name}", data)


def tape_drive_delete(api: PbsBackend, name: str) -> None:
    """DELETE /config/drive/{name}. Config is re-creatable; does NOT touch tape hardware or
    media. Returns null (synchronous). MUTATION — confirm-gated + audited at the server layer."""
    name = _check_tape_id(name)
    api._delete(f"/config/drive/{name}")


# ---------------------------------------------------------------------------
# Backend functions — mutations, Changers
# ---------------------------------------------------------------------------

def tape_changer_create(
    api: PbsBackend,
    name: str,
    path: str,
    eject_before_unload: bool | None = None,
    export_slots: str | None = None,
) -> None:
    """POST /config/changer — name+path required, eject-before-unload/export-slots optional.
    Returns null (synchronous). MUTATION — confirm-gated + audited at the server layer."""
    name = _check_tape_id(name)
    data: dict = {"name": name, "path": str(path)}
    if eject_before_unload is not None:
        data["eject-before-unload"] = bool(eject_before_unload)
    if export_slots is not None:
        data["export-slots"] = _check_export_slots(export_slots)
    api._post("/config/changer", data)


def tape_changer_update(
    api: PbsBackend,
    name: str,
    path: str | None = None,
    eject_before_unload: bool | None = None,
    export_slots: str | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> None:
    """PUT /config/changer/{name} — all fields optional except the path name. Returns null
    (synchronous). MUTATION — confirm-gated + audited at the server layer."""
    name = _check_tape_id(name)
    data: dict = {}
    if path is not None:
        data["path"] = str(path)
    if eject_before_unload is not None:
        data["eject-before-unload"] = bool(eject_before_unload)
    if export_slots is not None:
        data["export-slots"] = _check_export_slots(export_slots)
    if digest is not None:
        data["digest"] = _check_digest(digest)
    if delete is not None:
        data["delete"] = _check_delete_list(delete)
    api._put(f"/config/changer/{name}", data)


def tape_changer_delete(api: PbsBackend, name: str) -> None:
    """DELETE /config/changer/{name}. Config is re-creatable; does NOT touch tape hardware or
    media. Returns null (synchronous). MUTATION — confirm-gated + audited at the server layer."""
    name = _check_tape_id(name)
    api._delete(f"/config/changer/{name}")


# ---------------------------------------------------------------------------
# Plan factories — Drives
# ---------------------------------------------------------------------------

def plan_tape_drive_create(
    name: str,
    path: str,
    changer: str | None = None,
    changer_drivenum: int | None = None,
) -> Plan:
    """Plan creating a PBS tape drive config. RISK_MEDIUM (module docstring's RISK RATING note —
    maps an identifier onto real host hardware). PURE — no API read."""
    _check_tape_id(name)
    if changer is not None:
        _check_tape_id(changer)
    if changer_drivenum is not None:
        _check_changer_drivenum(changer_drivenum)
    extra = []
    if changer is not None:
        extra.append(f"changer={changer!r}")
    if changer_drivenum is not None:
        extra.append(f"changer-drivenum={changer_drivenum}")
    extra_note = f" ({', '.join(extra)})" if extra else ""
    return Plan(
        action="pbs_tape_drive_create",
        target=f"pbs/config/drive/{name}",
        change=f"create PBS tape drive {name!r} at device path {path!r}{extra_note}",
        current={},
        blast_radius=[
            f"adds a new tape drive identifier {name!r} pointing at host device {path!r} — no "
            "existing drive/changer/job config is affected",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            f"maps identifier {name!r} onto real host hardware at {path!r} — a wrong device "
            "path means a future tape job silently targets the wrong physical drive",
        ],
        note=(
            "No snapshot primitive on this plane. Config is re-creatable — delete with "
            "pbs_tape_drive_delete and re-create to correct a mistake."
        ),
    )


def plan_tape_drive_update(
    api: PbsBackend,
    name: str,
    path: str | None = None,
    changer: str | None = None,
    changer_drivenum: int | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> Plan:
    """Plan updating a PBS tape drive config. CAPTURE: reads current config (no secrets on this
    plane — module docstring fact #7 — nothing to redact). `digest`/`changer_drivenum` validated
    here too (not just at execution) so a bad value is caught at PLAN time."""
    _check_tape_id(name)
    if changer is not None:
        _check_tape_id(changer)
    if changer_drivenum is not None:
        _check_changer_drivenum(changer_drivenum)
    if digest is not None:
        _check_digest(digest)
    current = tape_drive_get(api, name)
    extra = []
    if path is not None:
        extra.append(f"path={path!r}")
    if changer is not None:
        extra.append(f"changer={changer!r}")
    if changer_drivenum is not None:
        extra.append(f"changer-drivenum={changer_drivenum}")
    # `is not None`, NOT truthiness — but delete=[] is REJECTED, not disclosed: httpx's form
    # encoding drops an empty-list value entirely, so a disclosed "delete=[]" would never match
    # what confirm=True actually sends (Wave 5b review finding 1, corrects the Wave 4a comment
    # this replaced, which wrongly called delete=[] "a real wire payload the execute side sends").
    if delete is not None:
        extra.append(f"delete={_check_delete_list(delete)!r}")
    change_desc = ", ".join(extra) if extra else "no fields changed"
    return Plan(
        action="pbs_tape_drive_update",
        target=f"pbs/config/drive/{name}",
        change=f"update PBS tape drive {name!r}: {change_desc}",
        current=current,
        blast_radius=[
            f"tape drive {name!r}: changes which host device / changer association future tape "
            "jobs use — a job scheduled against this drive is affected on its next run",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            f"repoints identifier {name!r} at (potentially) different physical hardware — a "
            "scheduled tape backup/restore using this drive next targets whatever device the "
            "new config names",
        ],
        note=(
            "No snapshot primitive on this plane. Current config captured above — re-apply it "
            "manually (pbs_tape_drive_update) to revert."
        ),
    )


def plan_tape_drive_delete(api: PbsBackend, name: str) -> Plan:
    """Plan deleting a PBS tape drive config. CAPTURE: reads current config for honesty/restore
    material. RISK_LOW (module docstring's RISK RATING note — config-only, no data/hardware
    touched, mirrors pbs_notifications.py's delete rating)."""
    _check_tape_id(name)
    current = tape_drive_get(api, name)
    return Plan(
        action="pbs_tape_drive_delete",
        target=f"pbs/config/drive/{name}",
        change=f"delete PBS tape drive {name!r}",
        current=current,
        blast_radius=[
            f"removes tape drive {name!r}'s config — tape-backup jobs referencing this drive "
            "fail until it is re-created; the tape hardware itself and any data on tape are "
            "untouched",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "config-only removal — does not touch tape media or drive hardware, re-creatable",
        ],
        note=(
            "No UNDO primitive on this plane. Config is re-creatable — re-create with "
            "pbs_tape_drive_create using the captured current config above (path/changer/"
            "changer-drivenum) to restore. WARN: tape-backup jobs referencing this drive fail "
            "until it is restored."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — Changers
# ---------------------------------------------------------------------------

def plan_tape_changer_create(
    name: str,
    path: str,
    eject_before_unload: bool | None = None,
    export_slots: str | None = None,
) -> Plan:
    """Plan creating a PBS tape changer config. RISK_MEDIUM (same reasoning as
    plan_tape_drive_create). PURE — no API read."""
    _check_tape_id(name)
    if export_slots is not None:
        _check_export_slots(export_slots)
    extra = []
    if eject_before_unload is not None:
        extra.append(f"eject-before-unload={bool(eject_before_unload)}")
    if export_slots is not None:
        extra.append(f"export-slots={export_slots!r}")
    extra_note = f" ({', '.join(extra)})" if extra else ""
    return Plan(
        action="pbs_tape_changer_create",
        target=f"pbs/config/changer/{name}",
        change=f"create PBS tape changer {name!r} at device path {path!r}{extra_note}",
        current={},
        blast_radius=[
            f"adds a new tape changer identifier {name!r} pointing at host device {path!r} — no "
            "existing drive/changer/job config is affected",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            f"maps identifier {name!r} onto real host hardware at {path!r} — a wrong device "
            "path means a future tape job silently targets the wrong physical changer/robot",
        ],
        note=(
            "No snapshot primitive on this plane. Config is re-creatable — delete with "
            "pbs_tape_changer_delete and re-create to correct a mistake."
        ),
    )


def plan_tape_changer_update(
    api: PbsBackend,
    name: str,
    path: str | None = None,
    eject_before_unload: bool | None = None,
    export_slots: str | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> Plan:
    """Plan updating a PBS tape changer config. CAPTURE: reads current config (no secrets on
    this plane — nothing to redact). `digest`/`export_slots` validated here too (not just at
    execution) so a bad value is caught at PLAN time."""
    _check_tape_id(name)
    if export_slots is not None:
        _check_export_slots(export_slots)
    if digest is not None:
        _check_digest(digest)
    current = tape_changer_get(api, name)
    extra = []
    if path is not None:
        extra.append(f"path={path!r}")
    if eject_before_unload is not None:
        extra.append(f"eject-before-unload={bool(eject_before_unload)}")
    if export_slots is not None:
        extra.append(f"export-slots={export_slots!r}")
    # `is not None`, NOT truthiness — same contract as the drive side: delete=[] is REJECTED,
    # not disclosed (Wave 5b review finding 1).
    if delete is not None:
        extra.append(f"delete={_check_delete_list(delete)!r}")
    change_desc = ", ".join(extra) if extra else "no fields changed"
    return Plan(
        action="pbs_tape_changer_update",
        target=f"pbs/config/changer/{name}",
        change=f"update PBS tape changer {name!r}: {change_desc}",
        current=current,
        blast_radius=[
            f"tape changer {name!r}: changes which host device this identifier maps to, and/or "
            "its export-slot/eject behavior — drives associated with this changer are affected "
            "on their next job run",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            f"repoints identifier {name!r} at (potentially) different physical hardware — a "
            "scheduled tape job using an associated drive next targets whatever changer the new "
            "config names",
        ],
        note=(
            "No snapshot primitive on this plane. Current config captured above — re-apply it "
            "manually (pbs_tape_changer_update) to revert."
        ),
    )


def plan_tape_changer_delete(api: PbsBackend, name: str) -> Plan:
    """Plan deleting a PBS tape changer config. CAPTURE: reads current config for honesty/restore
    material. RISK_LOW (mirrors pbs_notifications.py's delete rating, per the campaign brief)."""
    _check_tape_id(name)
    current = tape_changer_get(api, name)
    return Plan(
        action="pbs_tape_changer_delete",
        target=f"pbs/config/changer/{name}",
        change=f"delete PBS tape changer {name!r}",
        current=current,
        blast_radius=[
            f"removes tape changer {name!r}'s config — drives associated with this changer fail "
            "to load/unload until it is re-created; the tape hardware itself and any data on "
            "tape are untouched",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "config-only removal — does not touch tape media or changer hardware, re-creatable",
        ],
        note=(
            "No UNDO primitive on this plane. Config is re-creatable — re-create with "
            "pbs_tape_changer_create using the captured current config above (path/"
            "export-slots/eject-before-unload) to restore. WARN: drives associated with this "
            "changer fail to load/unload until it is restored."
        ),
    )
