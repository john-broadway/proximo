"""PBS tape drive + changer OPERATIONS wrappers (Wave 4c, full-surface campaign) —
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 4 decomposition (PBS tape)", "4c — drive +
changer operations". See `proximo.pbs_tape_ops` module docstring for the full endpoint table, the
schema-verified facts, and the risk-rating reasoning.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_tape_ops import (
    plan_tape_changer_transfer,
    plan_tape_drive_barcode_label_media,
    plan_tape_drive_catalog,
    plan_tape_drive_clean,
    plan_tape_drive_eject,
    plan_tape_drive_format,
    plan_tape_drive_inventory_update,
    plan_tape_drive_label_media,
    plan_tape_drive_load_media,
    plan_tape_drive_load_slot,
    plan_tape_drive_restore_key,
    plan_tape_drive_rewind,
    plan_tape_drive_unload,
    tape_changer_status,
    tape_changer_transfer,
    tape_drive_barcode_label_media,
    tape_drive_cartridge_memory,
    tape_drive_catalog,
    tape_drive_clean,
    tape_drive_eject,
    tape_drive_format,
    tape_drive_inventory,
    tape_drive_inventory_update,
    tape_drive_label_media,
    tape_drive_load_media,
    tape_drive_load_slot,
    tape_drive_read_label,
    tape_drive_restore_key,
    tape_drive_rewind,
    tape_drive_status,
    tape_drive_unload,
    tape_drive_volume_statistics,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Reads: Drive ---

@tool()
def pbs_tape_drive_status(
    drive: Annotated[str, Field(description="Drive identifier (3-32 chars, alnum/underscore start, then alnum/./_/-).")],
) -> dict:
    """READ-ONLY: get one PBS tape drive's status (media-related fields only present if a medium
    is loaded). Pure device telemetry — no label-text field exists in this response at all. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_drive_status", f"pbs/tape/drive/{drive}/status",
                    lambda: tape_drive_status(pbs, drive))


@tool()
def pbs_tape_drive_read_label(
    drive: Annotated[str, Field(description="Drive identifier.")],
    inventorize: Annotated[bool | None, Field(description="If True, also record this media into the inventory/media database.")] = None,
) -> dict:
    """READ-ONLY: read the mounted media's label (label-text, media-set uuid/pool/ctime, encryption
    key fingerprint if any). ADVERSARIAL: label-text is physical-media-authored free text (whoever
    labeled the cartridge controls these bytes) — no return-side pattern constraint in the schema.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_drive_read_label", f"pbs/tape/drive/{drive}/read-label",
                    lambda: tape_drive_read_label(pbs, drive, inventorize))


@tool()
def pbs_tape_drive_cartridge_memory(
    drive: Annotated[str, Field(description="Drive identifier.")],
) -> list[dict]:
    """READ-ONLY: read the mounted media's LTO cartridge memory (MAM) attributes — id/name/value
    triples. ADVERSARIAL: read directly off the physical medium's own onboard memory chip, no
    pattern/enum constraint anywhere in the schema. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_drive_cartridge_memory", f"pbs/tape/drive/{drive}/cartridge-memory",
                    lambda: tape_drive_cartridge_memory(pbs, drive))


@tool()
def pbs_tape_drive_volume_statistics(
    drive: Annotated[str, Field(description="Drive identifier.")],
) -> dict:
    """READ-ONLY: read the mounted media's SCSI log-page-17h volume statistics (byte counters,
    error counters, a hardware-assigned serial). Device telemetry — no label-text field. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_drive_volume_statistics", f"pbs/tape/drive/{drive}/volume-statistics",
                    lambda: tape_drive_volume_statistics(pbs, drive))


@tool()
def pbs_tape_drive_inventory(
    drive: Annotated[str, Field(description="Drive identifier.")],
) -> list[dict]:
    """READ-ONLY: list known media labels via the drive's associated changer (this read ALSO
    updates PBS's media online-status bookkeeping, per the schema's own note — still a GET, no
    confirm gate). ADVERSARIAL: carries physical media label-text, no return-side pattern
    constraint. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_drive_inventory", f"pbs/tape/drive/{drive}/inventory",
                    lambda: tape_drive_inventory(pbs, drive))


# --- Reads: Changer ---

@tool()
def pbs_tape_changer_status(
    name: Annotated[str, Field(description="Tape changer identifier.")],
    cache: Annotated[bool | None, Field(description="Use a cached value (default True per PBS) instead of re-querying the changer hardware.")] = None,
) -> list[dict]:
    """READ-ONLY: one status entry per drive/slot/import-export bay on the changer. ADVERSARIAL:
    occupied-slot entries carry a label-text field — the same media-label content class as
    read-label/inventory (see module docstring's Taint section for why this diverges from a naive
    "status=trusted" reading). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_changer_status", f"pbs/tape/changer/{name}/status",
                    lambda: tape_changer_status(pbs, name, cache))


# --- Mutations: Drive ---

@tool()
def pbs_tape_drive_load_media(
    drive: Annotated[str, Field(description="Drive identifier.")],
    label_text: Annotated[str, Field(description="Media Label/Barcode of the cartridge to mount (2-32 chars, alnum/underscore start, then alnum/./_/-).")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the load.")] = False,
) -> dict:
    """MUTATION: mount the cartridge carrying `label_text` into a drive via its associated changer.

    RISK_MEDIUM: real robotic action — the drive is busy for the duration, any previously-mounted
    cartridge is displaced. No data is touched. Dry-run by default (returns a PLAN); confirm=True
    executes (POST /tape/drive/{drive}/load-media) and returns
    {"status": "submitted", "result": "<UPID>"}. No undo primitive — reverse with
    pbs_tape_drive_unload. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/drive/{drive}/load-media"
    return run_governed(
        "pbs_tape_drive_load_media", tgt,
        plan=lambda: plan_tape_drive_load_media(drive, label_text),
        execute=lambda: tape_drive_load_media(pbs, drive, label_text),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_tape_drive_load_slot(
    drive: Annotated[str, Field(description="Drive identifier.")],
    source_slot: Annotated[int, Field(description="Source changer slot number (>= 1).")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the load.")] = False,
) -> dict:
    """MUTATION: mount the cartridge in `source_slot` into a drive via its associated changer.

    RISK_MEDIUM: real robotic action — same physical effect as pbs_tape_drive_load_media. Dry-run
    by default (returns a PLAN); confirm=True executes (POST /tape/drive/{drive}/load-slot,
    SYNCHRONOUS — the one load/mount-shaped op on this plane that returns null, not a UPID) and
    returns {"status": "ok", "result": None}. No undo primitive — reverse with
    pbs_tape_drive_unload. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/drive/{drive}/load-slot"
    return run_governed(
        "pbs_tape_drive_load_slot", tgt,
        plan=lambda: plan_tape_drive_load_slot(drive, source_slot),
        execute=lambda: tape_drive_load_slot(pbs, drive, source_slot),
        confirm=confirm)


@tool()
def pbs_tape_drive_unload(
    drive: Annotated[str, Field(description="Drive identifier.")],
    target_slot: Annotated[int | None, Field(description="Target changer slot number (>= 1). If omitted, PBS defaults to the slot the drive was loaded from.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the unload.")] = False,
) -> dict:
    """MUTATION: return a drive's mounted media to a changer slot.

    RISK_MEDIUM: real robotic action — no data touched. Dry-run by default (returns a PLAN);
    confirm=True executes (POST /tape/drive/{drive}/unload) and returns
    {"status": "submitted", "result": "<UPID>"}. No undo primitive — reverse with
    pbs_tape_drive_load_slot. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/drive/{drive}/unload"
    return run_governed(
        "pbs_tape_drive_unload", tgt,
        plan=lambda: plan_tape_drive_unload(drive, target_slot),
        execute=lambda: tape_drive_unload(pbs, drive, target_slot),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_tape_drive_eject(
    drive: Annotated[str, Field(description="Drive identifier.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the eject.")] = False,
) -> dict:
    """MUTATION: eject/unload a drive's mounted media.

    RISK_MEDIUM: on a standalone (non-changer) drive this PHYSICALLY EJECTS the cartridge —
    requires a HUMAN to retrieve/reinsert it, no robot arm to undo it. Dry-run by default (returns
    a PLAN); confirm=True executes (POST /tape/drive/{drive}/eject-media) and returns
    {"status": "submitted", "result": "<UPID>"}. No undo primitive. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/drive/{drive}/eject-media"
    return run_governed(
        "pbs_tape_drive_eject", tgt,
        plan=lambda: plan_tape_drive_eject(drive),
        execute=lambda: tape_drive_eject(pbs, drive),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_tape_drive_rewind(
    drive: Annotated[str, Field(description="Drive identifier.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the rewind.")] = False,
) -> dict:
    """MUTATION: rewind a drive's mounted tape to its beginning.

    RISK_LOW: repositions the tape head only — no mount/unmount, no data touched, the
    lowest-consequence physical action on this plane. Dry-run by default (returns a PLAN);
    confirm=True executes (POST /tape/drive/{drive}/rewind) and returns
    {"status": "submitted", "result": "<UPID>"}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/drive/{drive}/rewind"
    return run_governed(
        "pbs_tape_drive_rewind", tgt,
        plan=lambda: plan_tape_drive_rewind(drive),
        execute=lambda: tape_drive_rewind(pbs, drive),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_tape_drive_clean(
    drive: Annotated[str, Field(description="Drive identifier.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the cleaning cycle.")] = False,
) -> dict:
    """MUTATION: run a cleaning cycle on a drive.

    RISK_MEDIUM: consumes one use-cycle of the staged cleaning cartridge (a finite physical
    consumable) and takes the drive offline for the cycle's duration — no digital undo. Dry-run
    by default (returns a PLAN); confirm=True executes (PUT /tape/drive/{drive}/clean) and returns
    {"status": "submitted", "result": "<UPID>"}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/drive/{drive}/clean"
    return run_governed(
        "pbs_tape_drive_clean", tgt,
        plan=lambda: plan_tape_drive_clean(drive),
        execute=lambda: tape_drive_clean(pbs, drive),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_tape_drive_inventory_update(
    drive: Annotated[str, Field(description="Drive identifier.")],
    catalog: Annotated[bool | None, Field(description="If True, also try to restore the PBS catalog from tape for newly-inventoried media.")] = None,
    read_all_labels: Annotated[bool | None, Field(description="If True, load ALL tapes and re-read labels even if already inventoried.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the inventory update.")] = False,
) -> dict:
    """MUTATION: query the changer and load+read any unknown cartridge into this drive, storing
    results to the media database.

    RISK_MEDIUM: can physically cycle through EVERY not-yet-inventoried cartridge in the attached
    library, one at a time — duration scales with library size. Dry-run by default (returns a
    PLAN); confirm=True executes (PUT /tape/drive/{drive}/inventory) and returns
    {"status": "submitted", "result": "<UPID>"}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/drive/{drive}/inventory"
    return run_governed(
        "pbs_tape_drive_inventory_update", tgt,
        plan=lambda: plan_tape_drive_inventory_update(drive, catalog, read_all_labels),
        execute=lambda: tape_drive_inventory_update(pbs, drive, catalog, read_all_labels),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_tape_drive_label_media(
    drive: Annotated[str, Field(description="Drive identifier.")],
    label_text: Annotated[str, Field(description="The NEW label text to write (2-32 chars, alnum/underscore start, then alnum/./_/-).")],
    pool: Annotated[str | None, Field(description="Media pool to assign the newly-labeled media to. Omit to assign it to the free-media pool.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the label write.")] = False,
) -> dict:
    """MUTATION: write a NEW label to a drive's mounted media.

    RISK_HIGH: writing a new label makes any PRIOR content on the tape ORPHANED/unaddressable
    through normal PBS tooling — rated the same tier as pbs_tape_drive_format even though raw
    bytes aren't erased. UNLIKE format-media, this op has NO built-in check that the tape is
    actually empty — PBS's only guidance is a prose note ("the media need to be empty"), never
    enforced. Call pbs_tape_drive_read_label first if unsure what's mounted. Dry-run by default
    (returns a PLAN); confirm=True executes (POST /tape/drive/{drive}/label-media) and returns
    {"status": "submitted", "result": "<UPID>"}. No undo. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/drive/{drive}/label-media"
    return run_governed(
        "pbs_tape_drive_label_media", tgt,
        plan=lambda: plan_tape_drive_label_media(drive, label_text, pool),
        execute=lambda: tape_drive_label_media(pbs, drive, label_text, pool),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_tape_drive_barcode_label_media(
    drive: Annotated[str, Field(description="Drive identifier.")],
    pool: Annotated[str | None, Field(description="Media pool to assign the newly-labeled media to. Omit to assign it to the free-media pool.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the label write.")] = False,
) -> dict:
    """MUTATION: label a drive's mounted media using barcodes read from the changer device.

    RISK_HIGH: same "prior content becomes unaddressable" reasoning as pbs_tape_drive_label_media
    — the new label is sourced from the changer's barcode scan instead of a caller-supplied
    string. No built-in emptiness check. Dry-run by default (returns a PLAN); confirm=True
    executes (POST /tape/drive/{drive}/barcode-label-media) and returns
    {"status": "submitted", "result": "<UPID>"}. No undo. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/drive/{drive}/barcode-label-media"
    return run_governed(
        "pbs_tape_drive_barcode_label_media", tgt,
        plan=lambda: plan_tape_drive_barcode_label_media(drive, pool),
        execute=lambda: tape_drive_barcode_label_media(pbs, drive, pool),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_tape_drive_format(
    drive: Annotated[str, Field(description="Drive identifier.")],
    fast: Annotated[bool | None, Field(description="Use fast erase (PBS default: True if omitted).")] = None,
    label_text: Annotated[str | None, Field(description="If given, PBS cancels the format when the MOUNTED tape's own current label doesn't match this value — protects against formatting the wrong cartridge. Omit and PBS formats unconditionally.")] = None,
    load_barcode: Annotated[str | None, Field(description="If given, PBS first loads the cartridge carrying this barcode from the changer, THEN formats it (implicit load-then-format).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the format.")] = False,
) -> dict:
    """MUTATION: format (ERASE) a drive's mounted media.

    RISK_HIGH: DESTROYS ALL DATA on the mounted tape, no undo. If `label_text` is supplied, PBS
    cancels the format on a mismatch — real, but OPT-IN, protection. Omitting it formats whatever
    is loaded UNCONDITIONALLY. Dry-run by default (returns a PLAN); confirm=True executes (POST
    /tape/drive/{drive}/format-media) and returns {"status": "submitted", "result": "<UPID>"}.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/drive/{drive}/format-media"
    return run_governed(
        "pbs_tape_drive_format", tgt,
        plan=lambda: plan_tape_drive_format(drive, fast, label_text, load_barcode),
        execute=lambda: tape_drive_format(pbs, drive, fast, label_text, load_barcode),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_tape_drive_catalog(
    drive: Annotated[str, Field(description="Drive identifier.")],
    force: Annotated[bool | None, Field(description="Force overriding an existing catalog index for this media.")] = None,
    scan: Annotated[bool | None, Field(description="Re-read the whole tape to reconstruct the catalog, instead of restoring saved catalog versions.")] = None,
    verbose: Annotated[bool | None, Field(description="Verbose mode — log all found chunks.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the catalog scan.")] = False,
) -> dict:
    """MUTATION: scan a drive's mounted media and (re)record its content into the local PBS
    catalog database.

    RISK_MEDIUM: reads (does not modify) the tape; writes/updates local catalog metadata —
    force=True overrides an existing index, scan=True can tie up the drive for the full tape read.
    Dry-run by default (returns a PLAN); confirm=True executes (POST /tape/drive/{drive}/catalog)
    and returns {"status": "submitted", "result": "<UPID>"}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/drive/{drive}/catalog"
    return run_governed(
        "pbs_tape_drive_catalog", tgt,
        plan=lambda: plan_tape_drive_catalog(drive, force, scan, verbose),
        execute=lambda: tape_drive_catalog(pbs, drive, force, scan, verbose),
        confirm=confirm, outcome="submitted")


@tool()
def pbs_tape_drive_restore_key(
    drive: Annotated[str, Field(description="Drive identifier.")],
    password: Annotated[str, Field(description="The password the tape encryption key was protected with.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the restore attempt.")] = False,
) -> dict:
    """MUTATION: try to restore a tape encryption key from a drive's mounted media.

    RISK_MEDIUM: on success, changes what tape content becomes decryptable going forward — mirrors
    pbs_tape_key_create's rating. SECRET CONTRACT: `password` is NEVER written to the audit ledger
    or returned in the dry-run PLAN — forwarded RAW only to the real PBS API on confirm=True.
    confirm=True executes (POST /tape/drive/{drive}/restore-key, synchronous) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/drive/{drive}/restore-key"
    return run_governed(
        "pbs_tape_drive_restore_key", tgt,
        plan=lambda: plan_tape_drive_restore_key(drive, password),
        execute=lambda: tape_drive_restore_key(pbs, drive, password),
        confirm=confirm)


# --- Mutations: Changer ---

@tool()
def pbs_tape_changer_transfer(
    name: Annotated[str, Field(description="Tape changer identifier.")],
    from_slot: Annotated[int, Field(description="Source slot number (>= 1).")],
    to_slot: Annotated[int, Field(description="Destination slot number (>= 1).")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the transfer.")] = False,
) -> dict:
    """MUTATION: move media from one changer slot to another.

    RISK_LOW: pure storage-slot rearrangement via the changer robot — no drive interaction, no
    in-flight job interrupted, trivially reversible by transferring again with from/to swapped.
    Dry-run by default (returns a PLAN); confirm=True executes (POST
    /tape/changer/{name}/transfer, synchronous) and returns {"status": "ok", "result": None}.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/tape/changer/{name}/transfer"
    return run_governed(
        "pbs_tape_changer_transfer", tgt,
        plan=lambda: plan_tape_changer_transfer(name, from_slot, to_slot),
        execute=lambda: tape_changer_transfer(pbs, name, from_slot, to_slot),
        confirm=confirm)
