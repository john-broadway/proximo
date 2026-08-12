"""PBS tape hardware config wrappers (Wave 4a, full-surface campaign) —
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 4 decomposition (PBS tape)",
"4a — tape hardware config". See `proximo.pbs_tape_config` module docstring for the full
endpoint table, the schema-verified facts, and the risk-rating reasoning.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_tape_config import (
    plan_tape_changer_create,
    plan_tape_changer_delete,
    plan_tape_changer_update,
    plan_tape_drive_create,
    plan_tape_drive_delete,
    plan_tape_drive_update,
    tape_changer_create,
    tape_changer_delete,
    tape_changer_get,
    tape_changer_list,
    tape_changer_update,
    tape_drive_create,
    tape_drive_delete,
    tape_drive_get,
    tape_drive_list,
    tape_drive_update,
    tape_scan_changers,
    tape_scan_drives,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Reads: Drives ---

@tool()
def pbs_tape_drive_list() -> list[dict]:
    """READ-ONLY: list configured PBS tape drives (LTO SCSI, with config digest). Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_drive_list", "pbs/config/drive", lambda: tape_drive_list(pbs))


@tool()
def pbs_tape_drive_get(
    name: Annotated[str, Field(description="Drive identifier (3-32 chars, alnum/underscore start, then alnum/./_/-).")],
) -> dict:
    """READ-ONLY: get one PBS tape drive's config. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_drive_get", f"pbs/config/drive/{name}",
                    lambda: tape_drive_get(pbs, name))


# --- Reads: Changers ---

@tool()
def pbs_tape_changer_list() -> list[dict]:
    """READ-ONLY: list configured PBS SCSI tape changers (with config digest). Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_changer_list", "pbs/config/changer", lambda: tape_changer_list(pbs))


@tool()
def pbs_tape_changer_get(
    name: Annotated[str, Field(description="Tape changer identifier (3-32 chars, alnum/underscore start, then alnum/./_/-).")],
) -> dict:
    """READ-ONLY: get one PBS tape changer's config. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_changer_get", f"pbs/config/changer/{name}",
                    lambda: tape_changer_get(pbs, name))


# --- Reads: Hardware scans ---

@tool()
def pbs_tape_scan_drives() -> list[dict]:
    """READ-ONLY: autodetect tape drives attached to the PBS host (Linux SCSI-generic device
    nodes). Returns kind/major/minor/model/path/serial/vendor per device — device-reported, not
    operator config (same taint posture as pve_hardware_list / pbs_node_disks_list). No params.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_scan_drives", "pbs/tape/scan-drives", lambda: tape_scan_drives(pbs))


@tool()
def pbs_tape_scan_changers() -> list[dict]:
    """READ-ONLY: autodetect SCSI tape changers attached to the PBS host. Same response shape as
    pbs_tape_scan_drives — device-reported, not operator config. No params. Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_scan_changers", "pbs/tape/scan-changers",
                    lambda: tape_scan_changers(pbs))


# --- Mutations: Drives ---

@tool()
def pbs_tape_drive_create(
    name: Annotated[str, Field(description="New drive identifier (3-32 chars, alnum/underscore start, then alnum/./_/-).")],
    path: Annotated[str, Field(description="Path to the LTO SCSI-generic tape device, e.g. '/dev/sg0'.")],
    changer: Annotated[str | None, Field(description="Optional tape changer identifier this drive is loaded by.")] = None,
    changer_drivenum: Annotated[int | None, Field(description="Optional changer drive slot number (0-255, default 0; only meaningful with 'changer' set).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PBS tape drive config.

    RISK_MEDIUM: maps 'name' onto real host hardware at 'path' — a wrong path means a future
    tape job silently targets the wrong physical drive. Dry-run by default (returns a PLAN);
    confirm=True executes (POST /config/drive, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/drive/{name}"
    return run_governed(
        "pbs_tape_drive_create", tgt,
        plan=lambda: plan_tape_drive_create(name, path, changer, changer_drivenum),
        execute=lambda: tape_drive_create(pbs, name, path, changer, changer_drivenum),
        confirm=confirm)


@tool()
def pbs_tape_drive_update(
    name: Annotated[str, Field(description="Name of the existing tape drive to update.")],
    path: Annotated[str | None, Field(description="New device path, e.g. '/dev/sg0'.")] = None,
    changer: Annotated[str | None, Field(description="New tape changer identifier association.")] = None,
    changer_drivenum: Annotated[int | None, Field(description="New changer drive slot number (0-255).")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned. If set and stale, PBS rejects the update.")] = None,
    delete: Annotated[list[str] | None, Field(description="Property names to clear: 'changer' and/or 'changer-drivenum'.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: update a PBS tape drive config.

    RISK_MEDIUM: repoints 'name' at (potentially) different physical hardware — a scheduled tape
    job using this drive next targets whatever device the new config names. Dry-run by default
    (captures current config into the PLAN); confirm=True executes (PUT /config/drive/{name},
    synchronous — PBS returns null) and returns {"status": "ok", "result": None}. No snapshot
    primitive; re-apply the captured config to revert. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/drive/{name}"
    return run_governed(
        "pbs_tape_drive_update", tgt,
        plan=lambda: plan_tape_drive_update(pbs, name, path, changer, changer_drivenum, digest, delete),
        execute=lambda: tape_drive_update(pbs, name, path, changer, changer_drivenum, digest, delete),
        confirm=confirm)


@tool()
def pbs_tape_drive_delete(
    name: Annotated[str, Field(description="Name of the tape drive to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PBS tape drive config.

    RISK_LOW: config-only — does not touch tape media or drive hardware, re-creatable. Dry-run
    by default (captures current config); confirm=True executes (DELETE /config/drive/{name},
    synchronous — PBS returns null) and returns {"status": "ok", "result": None}. No UNDO
    primitive — tape-backup jobs referencing this drive fail until it is re-created with
    pbs_tape_drive_create. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/drive/{name}"
    return run_governed(
        "pbs_tape_drive_delete", tgt,
        plan=lambda: plan_tape_drive_delete(pbs, name),
        execute=lambda: tape_drive_delete(pbs, name),
        confirm=confirm)


# --- Mutations: Changers ---

@tool()
def pbs_tape_changer_create(
    name: Annotated[str, Field(description="New tape changer identifier (3-32 chars, alnum/underscore start, then alnum/./_/-).")],
    path: Annotated[str, Field(description="Path to the Linux generic SCSI device, e.g. '/dev/sg4'.")],
    eject_before_unload: Annotated[bool | None, Field(description="If True, tapes are ejected manually before unloading.")] = None,
    export_slots: Annotated[str | None, Field(description="Comma-separated slot numbers reserved for Import/Export (e.g. '1,2,3') — media in those slots is considered offline.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PBS tape changer config.

    RISK_MEDIUM: maps 'name' onto real host hardware at 'path' — a wrong path means a future
    tape job silently targets the wrong physical changer/robot. Dry-run by default (returns a
    PLAN); confirm=True executes (POST /config/changer, synchronous — PBS returns null) and
    returns {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/changer/{name}"
    return run_governed(
        "pbs_tape_changer_create", tgt,
        plan=lambda: plan_tape_changer_create(name, path, eject_before_unload, export_slots),
        execute=lambda: tape_changer_create(pbs, name, path, eject_before_unload, export_slots),
        confirm=confirm)


@tool()
def pbs_tape_changer_update(
    name: Annotated[str, Field(description="Name of the existing tape changer to update.")],
    path: Annotated[str | None, Field(description="New device path, e.g. '/dev/sg4'.")] = None,
    eject_before_unload: Annotated[bool | None, Field(description="If True, tapes are ejected manually before unloading.")] = None,
    export_slots: Annotated[str | None, Field(description="Comma-separated slot numbers reserved for Import/Export.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned. If set and stale, PBS rejects the update.")] = None,
    delete: Annotated[list[str] | None, Field(description="Property names to clear: 'export-slots' and/or 'eject-before-unload'.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: update a PBS tape changer config.

    RISK_MEDIUM: repoints 'name' at (potentially) different physical hardware — a scheduled tape
    job using an associated drive next targets whatever changer the new config names. Dry-run by
    default (captures current config into the PLAN); confirm=True executes (PUT
    /config/changer/{name}, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. No snapshot primitive; re-apply the captured config to
    revert. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/changer/{name}"
    return run_governed(
        "pbs_tape_changer_update", tgt,
        plan=lambda: plan_tape_changer_update(pbs, name, path, eject_before_unload, export_slots, digest, delete),
        execute=lambda: tape_changer_update(pbs, name, path, eject_before_unload, export_slots, digest, delete),
        confirm=confirm)


@tool()
def pbs_tape_changer_delete(
    name: Annotated[str, Field(description="Name of the tape changer to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PBS tape changer config.

    RISK_LOW: config-only — does not touch tape media or changer hardware, re-creatable. Dry-run
    by default (captures current config); confirm=True executes (DELETE
    /config/changer/{name}, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. No UNDO primitive — drives associated with this changer
    fail to load/unload until it is re-created with pbs_tape_changer_create. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/changer/{name}"
    return run_governed(
        "pbs_tape_changer_delete", tgt,
        plan=lambda: plan_tape_changer_delete(pbs, name),
        execute=lambda: tape_changer_delete(pbs, name),
        confirm=confirm)
