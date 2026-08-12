"""PBS tape drive + changer OPERATIONS plane (Wave 4c of the full-surface campaign,
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 4 decomposition (PBS tape)", "4c — drive +
changer operations"). Sibling to `pbs_tape_config.py` (Wave 4a — drive/changer hardware config)
and `pbs_tape_media.py` (Wave 4b — media pools + encryption keys): same no-PVE-sibling posture,
same idiom set. Media catalog/backup/restore (Wave 4d) is a separate later module — not built
here.

Schema truth: `.scratch/api-schemas-2026-07-15/wave4-pbs-tape-schema.json` (the live PBS
apidoc.js, pulled 2026-07-15).

**This module moves REAL robotics and tape** — every mutation here has a genuine physical-world
effect (a changer robot arm grabs a cartridge; a drive spins up, mounts, reads/writes, or erases a
physical tape). None of it is PVE-snapshottable and NONE of it has a digital undo primitive: the
only way to "revert" a load/unload/transfer is another physical load/unload/transfer call, and the
only way to "revert" a label/format is impossible (the old identity/content is gone). Every plan
below states the physical effect in plain language — never implies an undo that doesn't exist.

Endpoint table (19 tools total — 6 read, 13 mutation):

  GET    /tape/drive/{drive}/status              — pbs_tape_drive_status             (read)
  GET    /tape/drive/{drive}/read-label          — pbs_tape_drive_read_label         (read, ADVERSARIAL)
  GET    /tape/drive/{drive}/cartridge-memory    — pbs_tape_drive_cartridge_memory   (read, ADVERSARIAL)
  GET    /tape/drive/{drive}/volume-statistics   — pbs_tape_drive_volume_statistics  (read)
  GET    /tape/drive/{drive}/inventory           — pbs_tape_drive_inventory          (read, ADVERSARIAL)
  GET    /tape/changer/{name}/status             — pbs_tape_changer_status           (read, ADVERSARIAL)
  POST   /tape/drive/{drive}/load-media          — pbs_tape_drive_load_media         (MUTATION, MEDIUM)
  POST   /tape/drive/{drive}/load-slot           — pbs_tape_drive_load_slot          (MUTATION, MEDIUM)
  POST   /tape/drive/{drive}/unload              — pbs_tape_drive_unload             (MUTATION, MEDIUM)
  POST   /tape/drive/{drive}/eject-media         — pbs_tape_drive_eject              (MUTATION, MEDIUM)
  POST   /tape/drive/{drive}/rewind              — pbs_tape_drive_rewind             (MUTATION, LOW)
  PUT    /tape/drive/{drive}/clean               — pbs_tape_drive_clean              (MUTATION, MEDIUM)
  PUT    /tape/drive/{drive}/inventory           — pbs_tape_drive_inventory_update   (MUTATION, MEDIUM)
  POST   /tape/drive/{drive}/label-media         — pbs_tape_drive_label_media        (MUTATION, HIGH)
  POST   /tape/drive/{drive}/barcode-label-media — pbs_tape_drive_barcode_label_media (MUTATION, HIGH)
  POST   /tape/drive/{drive}/format-media        — pbs_tape_drive_format             (MUTATION, HIGH)
  POST   /tape/drive/{drive}/catalog             — pbs_tape_drive_catalog            (MUTATION, MEDIUM)
  POST   /tape/drive/{drive}/restore-key         — pbs_tape_drive_restore_key        (MUTATION, MEDIUM, SECRET)
  POST   /tape/changer/{name}/transfer           — pbs_tape_changer_transfer         (MUTATION, LOW)

SCHEMA-VERIFIED FACTS (binding on this build — from the live schema, not memory):

  1. **`drive`/`name` (changer) identifiers are the SAME identifier space as `pbs_tape_config.py`'s
     drive/changer config** — every path here operates on an already-configured drive/changer by
     that exact identifier (pattern `^[A-Za-z0-9_][A-Za-z0-9._\\-]*$`, 3-32 chars). This module
     IMPORTS `pbs_tape_config._check_tape_id` rather than duplicating it (unlike `pbs_tape_media.py`,
     which wrote a fresh validator because ITS length bound genuinely differed — here the shape is
     byte-for-byte identical, so reuse is the honest choice, not a shortcut).
  2. **Returns are NOT uniform — checked endpoint by endpoint, not assumed:**
     - UPID (async task) -> outcome="submitted": load-media, unload, eject-media, rewind, clean,
       inventory PUT, label-media, barcode-label-media, format-media, catalog (10 of 13 mutations).
     - `null` (synchronous) -> outcome="ok": **load-slot** (the one surprise — every OTHER
       load/mount-shaped op on this plane returns a UPID; load-slot alone returns null per the
       live schema, confirmed twice against the raw JSON), restore-key, changer transfer.
     No fixed/lambda-outcome hedging is used anywhere in this module (unlike `pve_apt_update_refresh`'s
     callable-outcome idiom) — every one of these 13 endpoints has an UNAMBIGUOUS, single-shape
     `returns` block in the schema, so a fixed `outcome=` literal per tool is the honest form.
  3. **`/tape/drive/{drive}/unload`'s `target-slot` is OPTIONAL** ("If omitted, defaults to the
     slot that the drive was loaded from") — Proximo does not invent a client-side default; `None`
     is forwarded as "omit the field", letting PBS apply its own return-to-origin default.
  4. **`/tape/changer/{name}/transfer`'s `from`/`to` are both REQUIRED ints, and `from` is a
     Python keyword** — the wrapper parameters are named `from_slot`/`to_slot` and mapped onto the
     wire's literal `"from"`/`"to"` keys inside the backend function, never exposed as Python
     identifiers.
  5. **THE TWO `label-text` PARAMS ON THIS PLANE MEAN DIFFERENT THINGS — do not conflate them**:
     - `format-media`'s `label-text` IS a protective, OPT-IN check: the schema's own description
       reads "Format media. Check for label-text if given (cancels if wrong media)." — if supplied,
       PBS CANCELS the format when the mounted tape's own current label doesn't match, protecting
       against erasing the wrong physical cartridge by mistake. If omitted, PBS formats whatever is
       loaded, UNCONDITIONALLY — there is no default protection, only an opt-in one.
     - `label-media`'s `label-text` is NOT a check at all — it is simply the NEW label being
       written. The schema's only related guidance is a prose NOTE, not an enforced precondition:
       "the media need to be empty (you may want to format it first)". PBS does not verify
       emptiness before writing; the caller's own honesty about what's mounted is the only
       safeguard. Conflating these two would be a real, dangerous documentation bug — kept
       explicitly separate here and in each tool's own docstring below.
  6. **`format-media`'s `load-barcode` behavior — NOT schema-verified (Smoke-confirm).** The
     schema declares the param but its description does not state whether PBS performs an
     implicit load-from-changer before formatting. Treated operationally as a possible compound
     action (load + destroy) out of caution; the plan wording says "may load", not "loads".
  7. **`clean` cartridge consumption — domain knowledge, NOT schema-verified (Smoke-confirm).**
     That a cleaning cycle consumes one use of a finite-rated cleaning cartridge is standard
     LTO behavior, not something the schema states. The plan keeps the caution but attributes
     it as standard tape practice, and there is no digital undo for a spent cycle either way.
  8. **`inventory` PUT's blast radius can span the WHOLE library, not just one drive**: per the
     schema's own description, it "loads any unknown media into the drive, reads the label, and
     store[s] the result to the media database" — potentially cycling through every not-yet-seen
     cartridge in the attached changer, one at a time, sequentially, over a duration proportional
     to library size. `catalog=True` additionally tries to restore the PBS media catalog FROM tape
     content for any newly-inventoried media.
  9. **`restore-key`'s `password` has NO length/format constraint in the schema** (plain
     `{"type": "string"}`, unlike `pbs_tape_media.py`'s own key-create/update passwords, which
     enforce `minLength: 5`) — Proximo does not invent a stricter client-side bound than PBS itself
     declares; the raw value is still masked in every plan/ledger surface regardless (fact #10).
  10. **THE SECRET CONTRACT — one secret shape on this plane**: `restore-key`'s `password` is
      masked to `"[redacted]"` before entering ANY Plan field, mirroring
      `pbs_tape_media.py`'s `_redact_secrets` idiom (a fresh single-key copy here, not imported —
      each PBS module keeps its own, established convention). The RAW value is still forwarded to
      the live PBS API on `confirm=True` (the restore attempt must actually work) — only the
      PLAN/PROVE surfaces are scrubbed. Mirrors 4b's raw-ledger-bytes sweep discipline exactly.
  11. **No `digest` optimistic-lock exists anywhere on this plane** — confirmed: none of the 13
      mutation endpoints' parameter schemas include a `digest` property. Unlike the CONFIG planes
      (4a/4b), these operate on live hardware/media state, not a versioned config file — there is
      nothing to optimistic-lock against.
  12. **Every plan factory on this plane is PURE (no live API read)** — unlike 4a/4b's
      update/delete plans, which CAPTURE the current config via a live GET, there is no meaningful
      "current config" to capture here: the target is an already-configured drive/changer
      identifier (not something this module edits), and drive/media STATUS changes continuously —
      capturing it into a plan would be stale the instant it's read, not a real revert anchor. A
      caller who wants to know what's currently mounted/loaded should call
      `pbs_tape_drive_status`/`pbs_tape_drive_read_label`/`pbs_tape_changer_status` themselves
      BEFORE planning a mutation here — the plan notes say so explicitly rather than silently
      fetching adversarial-classified content into a plan the caller didn't ask to taint (see
      Taint section below for why read-label/inventory/changer-status content is NOT folded into
      any of this module's plans).

RISK RATING (module-specific reasoning — every rating states the PHYSICAL effect, per the
campaign's physical-media-honesty instruction):

  - **load-media/load-slot = RISK_MEDIUM**: commands the changer robot to mount a specific
    cartridge into the drive — the drive is busy for the duration, and whatever was previously
    logically "the drive's tape" is now displaced. Fully reversible via another load/unload call;
    no data is destroyed; but it is a real physical action with no digital undo, and it can
    collide with another in-flight operation already using that drive.
  - **unload = RISK_MEDIUM**: symmetric to load — returns the currently-mounted tape to a changer
    slot (or its origin slot by default). Real robotic action, non-destructive, reversible by a
    subsequent load.
  - **eject-media = RISK_MEDIUM**: PBS's own description reads "Eject/Unload drive media" — on a
    changer-attached drive this behaves like unload; on a standalone drive it physically ejects
    the cartridge, which then requires a HUMAN to retrieve/reinsert it (no robot arm to undo it).
  - **rewind = RISK_LOW**: repositions the tape head to the beginning of the medium — no mount/
    unmount, no data touched, the lowest-consequence physical action on this plane.
  - **clean = RISK_MEDIUM**: consumes a finite cleaning-cartridge use-cycle (standard LTO
    practice — fact #7, Smoke-confirm) and takes the drive offline for the cycle's duration —
    a real, non-reversible resource cost even though it touches no backup data.
  - **inventory (PUT) = RISK_MEDIUM**: can physically cycle through every unrecognized cartridge in
    the attached library (fact #8) — a materially larger blast radius than a single load/unload,
    though still non-destructive to tape content; `catalog=True` writes into the local PBS catalog
    database from what it reads off tape.
  - **label-media/barcode-label-media = RISK_HIGH**: per the campaign brief's explicit binding
    fact, "writing a new label makes prior content unaddressable." This does not erase the tape's
    raw bytes the way `format-media` does, but it overwrites the tape's IDENTITY in PBS's own
    catalog/media-set bookkeeping — any backup data written under the OLD label becomes orphaned
    and effectively unreachable through normal PBS tooling. Rated at the same HIGH tier as
    `format-media` rather than a notional "medium-high" (this codebase's risk enum has exactly
    four levels — none/low/medium/high, `planning.py`; there is no fifth tier to reach for) because
    the PRACTICAL consequence — losing addressable access to whatever was on the tape before — is
    functionally equivalent to data loss for anyone who didn't intend it. Unlike `format-media`,
    THIS op has NO opt-in match-check at all (fact #5) — PBS's only guidance is a prose note that
    the media "need to be empty," never enforced — so label-media/barcode-label-media are actually
    the LESS-guarded of the two destructive-to-addressability ops on this plane, not the better-
    protected one.
  - **format-media = RISK_HIGH**: the campaign brief's own binding fact — DESTROYS ALL DATA on the
    mounted tape, no undo. The optional `label-text` check (fact #5) cancels the format if the
    MOUNTED tape's current label doesn't match what the caller expects — real protection against
    formatting the WRONG physical cartridge by mistake — but provides NO protection at all if the
    caller omits it (PBS formats whatever is loaded, unconditionally). `load-barcode` (fact #6,
    Smoke-confirm) may compound a load onto the same destructive call.
  - **catalog = RISK_MEDIUM**: reads (not writes) the tape's own data to reconstruct/verify the
    LOCAL PBS catalog database; `force=True` overrides an existing catalog index for that media
    (a real local-state change, though the tape's own content is untouched), and the full `scan`
    mode can tie up the drive for the time needed to read the entire tape.
  - **restore-key = RISK_MEDIUM**: mirrors `pbs_tape_media.py`'s `key_create` rating — attempts to
    recover/re-register an encryption key's usability from tape+password; on success it changes
    what's decryptable going forward, the same "creates/restores a credential" reasoning as
    key_create, without key_delete's irreversible-destruction severity.
  - **transfer (changer) = RISK_LOW**: purely rearranges cartridges between two changer STORAGE
    slots — no drive interaction, no in-flight job can be interrupted, and it is trivially
    reversible by calling transfer again with `from`/`to` swapped.

Taint (this module's read-only tools — see `taint.ADVERSARIAL_TOOLS` and
`tests/test_taint_classification_complete.py`'s `REVIEWED_TRUSTED`):

  - **`pbs_tape_drive_status` / `pbs_tape_drive_volume_statistics` = REVIEWED_TRUSTED**, matching
    the `pbs_node_disk_smart` precedent: pure device-reported telemetry (alert flags, block/file
    numbers, byte counters, compression state, density enum, SCSI log-page-17h counters, a
    hardware-assigned serial). Neither response carries a `label-text` field or any other
    operator/media-authored free text at all — confirmed against both schemas line by line.
  - **`pbs_tape_drive_read_label` / `pbs_tape_drive_inventory` = ADVERSARIAL**, matching the
    `pbs_snapshots_list` precedent per the campaign brief's explicit instruction: both carry
    `label-text` — the physical media's own label/barcode — with NO pattern constraint documented
    on the RETURN side of either schema (genuinely free text as read back, whatever the label-time
    write-side pattern requires). Whoever physically labeled/barcoded the cartridge (an operator,
    or a hostile actor with physical access to the tape library) controls these bytes.
  - **`pbs_tape_drive_cartridge_memory` = ADVERSARIAL**: the LTO cartridge memory (MAM) chip's
    `name`/`value` attribute pairs have NO pattern or enum constraint anywhere in the schema —
    genuinely arbitrary strings read directly off a physical medium's own onboard memory, the most
    directly "whatever is physically on the tape" channel on this entire plane.
  - **`pbs_tape_changer_status` = ADVERSARIAL — a deliberate divergence from the campaign brief's
    "status/statistics = device-authored -> REVIEWED_TRUSTED" default bucket, argued explicitly
    per the brief's own "argue any divergence, never silently decide" instruction**: unlike
    `pbs_tape_drive_status` (fact above — telemetry only, NO label-text field exists in that
    response at all), changer status returns a `label-text` field per slot/drive entry — the exact
    same media-label content class as read-label/inventory, just observed from the changer's
    perspective instead of the drive's. The schema DOES type this specific field with a stricter
    pattern (the same alnum/./_/- charset used for created identifiers) than read-label's/
    inventory's untyped label-text — but that pattern describes PBS's documented response CONTRACT,
    not a hardware-enforced guarantee: the actual bytes originate from whatever the changer's
    SCSI/mtx layer reports off a physical barcode sticker, a channel this module has no way to
    verify is actually validated against that pattern before being echoed back. Given genuine
    uncertainty and this codebase's own stated bias ("classify as adversarial when unsure",
    `taint.py` docstring), treating the one endpoint that structurally matches read-label/inventory
    (same field, same physical-media origin) as suddenly trusted — on the strength of a schema
    annotation alone — would be inconsistent with how the other two were classified. ADVERSARIAL.
  - **All 13 mutations = REVIEWED_TRUSTED**: every mutation on this plane returns either a UPID
    (an opaque task identifier string, PBS-generated, not attacker-shapeable content) or `null` —
    none of them echo back media-authored free text the way the four reads above do.

VERIFIED live shapes: None — all backend functions carry "Smoke-confirm:" comments; every shape
here is schema-derived, not live-proven against a running PBS with real tape hardware attached.
"""

from __future__ import annotations

import re

from ._validate import redact_secrets
from .backends import ProximoError
from .pbs import PbsBackend
from .pbs_tape_config import _check_tape_id  # reuse: identical drive/changer identifier shape
from .pbs_tape_media import _check_pool_name  # reuse: identical media-pool name shape
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# label-text (media label/barcode) — SAME charset as tape identifiers (no `|` alternation, module
# docstring: no alternation-precedence slip to correct here either), but minLength 2 not 3 (module
# docstring fact: shares pool-name's bound, not tape-id's) — a fresh copy per this module's own
# established convention (each PBS module keeps its own micro-validators).
_LABEL_TEXT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*\Z")


def _check_label_text(value: str) -> str:
    s = str(value)
    if not (2 <= len(s) <= 32) or not _LABEL_TEXT_RE.match(s):
        raise ProximoError(
            f"invalid label-text: {value!r} (must start with alnum or underscore, then "
            "alnum/./_/-, 2-32 chars)"
        )
    return s


def _check_slot(value: int, field: str) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid {field}: {value!r} (must be an integer)") from exc
    if n < 1:
        raise ProximoError(f"invalid {field}: {value!r} (must be >= 1)")
    return n


# Credential-shaped field on this plane (module docstring fact #10): restore-key's `password`.
_SECRET_KEYS = frozenset({"password"})


def _redact_secrets(d: dict) -> dict:
    """Mask credential-shaped fields before they enter a plan string — the shared
    `_validate.redact_secrets` mechanic over this plane's own `_SECRET_KEYS`."""
    return redact_secrets(d, _SECRET_KEYS)


# ---------------------------------------------------------------------------
# Backend functions — reads
# ---------------------------------------------------------------------------

def tape_drive_status(api: PbsBackend, drive: str) -> dict:
    """GET /tape/drive/{drive}/status — drive/media status (telemetry only — no label-text field
    exists in this response at all). Smoke-confirm: response shape."""
    drive = _check_tape_id(drive)
    return api._get(f"/tape/drive/{drive}/status") or {}


def tape_drive_read_label(api: PbsBackend, drive: str, inventorize: bool | None = None) -> dict:
    """GET /tape/drive/{drive}/read-label — read the mounted media's label (optionally
    inventorize it into the media database). ADVERSARIAL: carries the physical tape's own
    label-text, media-set uuid/pool, free text with no return-side pattern constraint.
    Smoke-confirm: response shape."""
    drive = _check_tape_id(drive)
    params: dict = {}
    if inventorize is not None:
        params["inventorize"] = bool(inventorize)
    return api._get(f"/tape/drive/{drive}/read-label", params=params) or {}


def tape_drive_cartridge_memory(api: PbsBackend, drive: str) -> list[dict]:
    """GET /tape/drive/{drive}/cartridge-memory — read the mounted media's LTO cartridge memory
    (MAM) attributes. ADVERSARIAL: name/value pairs read directly off the physical medium's own
    onboard memory, no pattern/enum constraint in the schema at all. Smoke-confirm: response
    shape."""
    drive = _check_tape_id(drive)
    return api._get(f"/tape/drive/{drive}/cartridge-memory") or []


def tape_drive_volume_statistics(api: PbsBackend, drive: str) -> dict:
    """GET /tape/drive/{drive}/volume-statistics — SCSI log page 17h volume statistics
    (telemetry counters + a hardware-assigned serial; no label-text). Smoke-confirm: response
    shape."""
    drive = _check_tape_id(drive)
    return api._get(f"/tape/drive/{drive}/volume-statistics") or {}


def tape_drive_inventory(api: PbsBackend, drive: str) -> list[dict]:
    """GET /tape/drive/{drive}/inventory — list known media labels via the associated changer
    (this READ also updates PBS's media online-status bookkeeping, per the schema's own note —
    still a GET, no confirm gate, listed here as a read like `pbs_snapshots_list`). ADVERSARIAL:
    carries physical media label-text, no return-side pattern constraint. Smoke-confirm: response
    shape."""
    drive = _check_tape_id(drive)
    return api._get(f"/tape/drive/{drive}/inventory") or []


def tape_changer_status(api: PbsBackend, name: str, cache: bool | None = None) -> list[dict]:
    """GET /tape/changer/{name}/status — one status entry per drive/slot/import-export bay.
    ADVERSARIAL: entries carry a `label-text` field for occupied slots — same media-label content
    class as read-label/inventory (module docstring's Taint section argues this divergence from a
    naive "status=trusted" reading explicitly). Smoke-confirm: response shape."""
    name = _check_tape_id(name)
    params: dict = {}
    if cache is not None:
        params["cache"] = bool(cache)
    return api._get(f"/tape/changer/{name}/status", params=params) or []


# ---------------------------------------------------------------------------
# Backend functions — mutations, Drive
# ---------------------------------------------------------------------------

def tape_drive_load_media(api: PbsBackend, drive: str, label_text: str) -> str:
    """POST /tape/drive/{drive}/load-media — mount the cartridge carrying `label_text` via the
    associated changer. Returns a UPID (async task). MUTATION — confirm-gated + audited at the
    server layer."""
    drive = _check_tape_id(drive)
    data = {"label-text": _check_label_text(label_text)}
    return api._post(f"/tape/drive/{drive}/load-media", data)


def tape_drive_load_slot(api: PbsBackend, drive: str, source_slot: int) -> None:
    """POST /tape/drive/{drive}/load-slot — mount whatever cartridge is in `source_slot` via the
    associated changer. Returns null (SYNCHRONOUS — the one exception on this plane; every other
    load/mount-shaped op returns a UPID, module docstring fact #2). MUTATION — confirm-gated +
    audited at the server layer."""
    drive = _check_tape_id(drive)
    data = {"source-slot": _check_slot(source_slot, "source-slot")}
    api._post(f"/tape/drive/{drive}/load-slot", data)


def tape_drive_unload(api: PbsBackend, drive: str, target_slot: int | None = None) -> str:
    """POST /tape/drive/{drive}/unload — return the mounted cartridge to `target_slot` (default:
    its origin slot, module docstring fact #3, if omitted). Returns a UPID. MUTATION —
    confirm-gated + audited at the server layer."""
    drive = _check_tape_id(drive)
    data: dict = {}
    if target_slot is not None:
        data["target-slot"] = _check_slot(target_slot, "target-slot")
    return api._post(f"/tape/drive/{drive}/unload", data)


def tape_drive_eject(api: PbsBackend, drive: str) -> str:
    """POST /tape/drive/{drive}/eject-media — eject/unload the drive's media. Returns a UPID.
    MUTATION — confirm-gated + audited at the server layer."""
    drive = _check_tape_id(drive)
    return api._post(f"/tape/drive/{drive}/eject-media", {})


def tape_drive_rewind(api: PbsBackend, drive: str) -> str:
    """POST /tape/drive/{drive}/rewind — rewind the mounted tape to its beginning. Returns a
    UPID. MUTATION — confirm-gated + audited at the server layer."""
    drive = _check_tape_id(drive)
    return api._post(f"/tape/drive/{drive}/rewind", {})


def tape_drive_clean(api: PbsBackend, drive: str) -> str:
    """PUT /tape/drive/{drive}/clean — run a drive cleaning cycle (consumes a limited
    cleaning-cartridge use-cycle — standard LTO practice, module docstring fact #7,
    Smoke-confirm). Returns a UPID. MUTATION — confirm-gated + audited at the server layer."""
    drive = _check_tape_id(drive)
    return api._put(f"/tape/drive/{drive}/clean", {})


def tape_drive_inventory_update(
    api: PbsBackend,
    drive: str,
    catalog: bool | None = None,
    read_all_labels: bool | None = None,
) -> str:
    """PUT /tape/drive/{drive}/inventory — query the changer's media labels, load+read any
    unknown cartridge, and store results to the media database (can span the whole attached
    library, module docstring fact #8). `catalog=True` also tries restoring the PBS catalog from
    tape. Returns a UPID. MUTATION — confirm-gated + audited at the server layer."""
    drive = _check_tape_id(drive)
    data: dict = {}
    if catalog is not None:
        data["catalog"] = bool(catalog)
    if read_all_labels is not None:
        data["read-all-labels"] = bool(read_all_labels)
    return api._put(f"/tape/drive/{drive}/inventory", data)


def tape_drive_label_media(
    api: PbsBackend, drive: str, label_text: str, pool: str | None = None,
) -> str:
    """POST /tape/drive/{drive}/label-media — write a NEW label to the mounted media (assigned to
    `pool`, or the free-media pool). PBS's own note: "the media need to be empty (you may want to
    format it first)" — writing a label makes any PRIOR content unaddressable (module docstring
    RISK RATING). Returns a UPID. MUTATION — confirm-gated + audited at the server layer."""
    drive = _check_tape_id(drive)
    data: dict = {"label-text": _check_label_text(label_text)}
    if pool is not None:
        data["pool"] = _check_pool_name(pool)
    return api._post(f"/tape/drive/{drive}/label-media", data)


def tape_drive_barcode_label_media(api: PbsBackend, drive: str, pool: str | None = None) -> str:
    """POST /tape/drive/{drive}/barcode-label-media — label media using barcodes read from the
    changer device (assigned to `pool`, or the free-media pool). Same "makes prior content
    unaddressable" risk as label-media. Returns a UPID. MUTATION — confirm-gated + audited at the
    server layer."""
    drive = _check_tape_id(drive)
    data: dict = {}
    if pool is not None:
        data["pool"] = _check_pool_name(pool)
    return api._post(f"/tape/drive/{drive}/barcode-label-media", data)


def tape_drive_format(
    api: PbsBackend,
    drive: str,
    fast: bool | None = None,
    label_text: str | None = None,
    load_barcode: str | None = None,
) -> str:
    """POST /tape/drive/{drive}/format-media — DESTROYS ALL DATA on the mounted tape, no undo. If
    `label_text` is given, PBS cancels the format when the mounted tape's own label doesn't match
    (protects against formatting the wrong cartridge) — OMITTING it formats whatever is loaded
    UNCONDITIONALLY (module docstring fact #5/RISK RATING — no default protection). `load_barcode`
    may perform a load-then-format (module docstring fact #6, Smoke-confirm — the schema does not
    state the load semantics). Returns a UPID. MUTATION — confirm-gated + audited at the server
    layer."""
    drive = _check_tape_id(drive)
    data: dict = {}
    if fast is not None:
        data["fast"] = bool(fast)
    if label_text is not None:
        data["label-text"] = _check_label_text(label_text)
    if load_barcode is not None:
        data["load-barcode"] = _check_label_text(load_barcode)
    return api._post(f"/tape/drive/{drive}/format-media", data)


def tape_drive_catalog(
    api: PbsBackend,
    drive: str,
    force: bool | None = None,
    scan: bool | None = None,
    verbose: bool | None = None,
) -> str:
    """POST /tape/drive/{drive}/catalog — scan the mounted media and (re)record its content into
    the local PBS catalog database. `force=True` overrides an existing catalog index for this
    media. `scan=True` re-reads the whole tape instead of restoring saved catalog versions (can
    tie up the drive for the full read duration). Returns a UPID. MUTATION — confirm-gated +
    audited at the server layer."""
    drive = _check_tape_id(drive)
    data: dict = {}
    if force is not None:
        data["force"] = bool(force)
    if scan is not None:
        data["scan"] = bool(scan)
    if verbose is not None:
        data["verbose"] = bool(verbose)
    return api._post(f"/tape/drive/{drive}/catalog", data)


def tape_drive_restore_key(api: PbsBackend, drive: str, password: str) -> None:
    """POST /tape/drive/{drive}/restore-key — try to restore a tape encryption key from the
    mounted media using `password`. Returns null (synchronous). MUTATION — confirm-gated +
    audited at the server layer. The RAW password is forwarded here (the restore must actually
    work) but never recorded to the ledger — see plan_tape_drive_restore_key's redaction."""
    drive = _check_tape_id(drive)
    data = {"password": str(password)}
    api._post(f"/tape/drive/{drive}/restore-key", data)


# ---------------------------------------------------------------------------
# Backend functions — mutations, Changer
# ---------------------------------------------------------------------------

def tape_changer_transfer(api: PbsBackend, name: str, from_slot: int, to_slot: int) -> None:
    """POST /tape/changer/{name}/transfer — move media from `from_slot` to `to_slot` via the
    changer robot (wire keys are the literal `from`/`to` — `from` is a Python keyword, module
    docstring fact #4). Returns null (synchronous). MUTATION — confirm-gated + audited at the
    server layer."""
    name = _check_tape_id(name)
    data = {
        "from": _check_slot(from_slot, "from"),
        "to": _check_slot(to_slot, "to"),
    }
    api._post(f"/tape/changer/{name}/transfer", data)


# ---------------------------------------------------------------------------
# Plan factories — Drive
# ---------------------------------------------------------------------------

def plan_tape_drive_load_media(drive: str, label_text: str) -> Plan:
    """Plan mounting a labeled cartridge into a drive. RISK_MEDIUM. PURE — no API read (module
    docstring fact #12)."""
    _check_tape_id(drive)
    _check_label_text(label_text)
    return Plan(
        action="pbs_tape_drive_load_media",
        target=f"pbs/tape/drive/{drive}/load-media",
        change=f"load media labeled {label_text!r} into drive {drive!r} via the associated changer",
        current={},
        blast_radius=[
            f"drive {drive!r} is busy for the duration of the mount; whatever cartridge (if any) "
            "was previously mounted is displaced — no data is touched, this is a physical mount "
            "action only",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "commands the changer robot to physically mount a cartridge — real hardware action, "
            "no digital undo (only another load/unload call reverses it)",
        ],
        note=(
            "No snapshot/undo primitive on this plane. Reversible via pbs_tape_drive_unload. "
            "Check pbs_tape_drive_status/pbs_tape_changer_status first if unsure what's currently "
            "mounted or where in the library the labeled cartridge sits."
        ),
    )


def plan_tape_drive_load_slot(drive: str, source_slot: int) -> Plan:
    """Plan mounting the cartridge in `source_slot` into a drive. RISK_MEDIUM. PURE — no API
    read."""
    _check_tape_id(drive)
    _check_slot(source_slot, "source-slot")
    return Plan(
        action="pbs_tape_drive_load_slot",
        target=f"pbs/tape/drive/{drive}/load-slot",
        change=f"load media from slot {source_slot} into drive {drive!r} via the associated changer",
        current={},
        blast_radius=[
            f"drive {drive!r} is busy for the duration of the mount; whatever cartridge (if any) "
            "was previously mounted is displaced — no data is touched, this is a physical mount "
            "action only",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "commands the changer robot to physically mount a cartridge — real hardware action, "
            "no digital undo (only another load/unload call reverses it)",
        ],
        note=(
            "No snapshot/undo primitive on this plane. Returns null (synchronous) — the one "
            "load/mount-shaped op on this plane that does NOT return a UPID (module docstring "
            "fact #2). Reversible via pbs_tape_drive_unload."
        ),
    )


def plan_tape_drive_unload(drive: str, target_slot: int | None = None) -> Plan:
    """Plan unloading a drive's mounted media to a changer slot. RISK_MEDIUM. PURE — no API
    read."""
    _check_tape_id(drive)
    if target_slot is not None:
        _check_slot(target_slot, "target-slot")
    slot_desc = f"slot {target_slot}" if target_slot is not None else "its origin slot (PBS default)"
    return Plan(
        action="pbs_tape_drive_unload",
        target=f"pbs/tape/drive/{drive}/unload",
        change=f"unload drive {drive!r}'s mounted media to {slot_desc} via the associated changer",
        current={},
        blast_radius=[
            f"drive {drive!r} becomes empty; the previously-mounted cartridge is physically "
            f"returned to {slot_desc} — no data is touched",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "commands the changer robot to physically unmount a cartridge — real hardware "
            "action, reversible only by another physical load",
        ],
        note="No snapshot/undo primitive on this plane. Reversible via pbs_tape_drive_load_slot.",
    )


def plan_tape_drive_eject(drive: str) -> Plan:
    """Plan ejecting/unloading a drive's media. RISK_MEDIUM. PURE — no API read."""
    _check_tape_id(drive)
    return Plan(
        action="pbs_tape_drive_eject",
        target=f"pbs/tape/drive/{drive}/eject-media",
        change=f"eject/unload drive {drive!r}'s mounted media",
        current={},
        blast_radius=[
            f"drive {drive!r} becomes empty; on a standalone (non-changer) drive the cartridge is "
            "physically ejected and requires a HUMAN to retrieve/reinsert it — no robot arm to "
            "undo this",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "real physical ejection — on a standalone drive this has no automated undo path at "
            "all, only manual operator intervention",
        ],
        note="No snapshot/undo primitive on this plane.",
    )


def plan_tape_drive_rewind(drive: str) -> Plan:
    """Plan rewinding a drive's mounted tape. RISK_LOW. PURE — no API read."""
    _check_tape_id(drive)
    return Plan(
        action="pbs_tape_drive_rewind",
        target=f"pbs/tape/drive/{drive}/rewind",
        change=f"rewind drive {drive!r}'s mounted tape to its beginning",
        current={},
        blast_radius=[
            f"drive {drive!r}'s tape head repositions to the start of the medium — no mount/"
            "unmount, no data touched",
        ],
        risk=RISK_LOW,
        risk_reasons=["repositions the tape head only — the lowest-consequence physical action "
                      "on this plane"],
        note="No snapshot/undo primitive on this plane (none needed — nothing state-changing "
             "happens).",
    )


def plan_tape_drive_clean(drive: str) -> Plan:
    """Plan running a drive cleaning cycle. RISK_MEDIUM. PURE — no API read."""
    _check_tape_id(drive)
    return Plan(
        action="pbs_tape_drive_clean",
        target=f"pbs/tape/drive/{drive}/clean",
        change=f"run a cleaning cycle on drive {drive!r}",
        current={},
        blast_radius=[
            f"drive {drive!r} is offline for the cleaning cycle's duration; consumes one "
            "use-cycle of whatever cleaning cartridge is staged for it (standard LTO practice — "
            "cleaning cartridges have a finite rated number of cleans), and the cycle is not "
            "reversible",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["consumes a finite physical consumable (cleaning-cartridge use-cycle) with "
                      "no digital undo"],
        note="No snapshot/undo primitive on this plane.",
    )


def plan_tape_drive_inventory_update(
    drive: str, catalog: bool | None = None, read_all_labels: bool | None = None,
) -> Plan:
    """Plan a changer inventory scan + label read from a drive. RISK_MEDIUM. PURE — no API
    read."""
    _check_tape_id(drive)
    extra = []
    if catalog is not None:
        extra.append(f"catalog={bool(catalog)}")
    if read_all_labels is not None:
        extra.append(f"read-all-labels={bool(read_all_labels)}")
    extra_note = f" ({', '.join(extra)})" if extra else ""
    return Plan(
        action="pbs_tape_drive_inventory_update",
        target=f"pbs/tape/drive/{drive}/inventory",
        change=f"update changer inventory via drive {drive!r}{extra_note}",
        current={},
        blast_radius=[
            f"can physically cycle drive {drive!r} through EVERY not-yet-inventoried cartridge in "
            "the attached library, one at a time, sequentially — duration scales with library "
            "size; media online-status is updated in the media database",
            "if catalog=True: also tries to restore the local PBS catalog database from what it "
            "reads off each newly-inventoried tape",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "materially larger blast radius than a single load/unload (can touch the whole "
            "library), though non-destructive to tape content itself",
        ],
        note="No snapshot/undo primitive on this plane.",
    )


def plan_tape_drive_label_media(drive: str, label_text: str, pool: str | None = None) -> Plan:
    """Plan writing a new label onto a drive's mounted media. RISK_HIGH — module docstring RISK
    RATING: writing a new label makes prior content unaddressable, rated at the same tier as
    format-media even though it doesn't erase raw bytes. PURE — no API read (module docstring
    fact #12: this module deliberately does NOT auto-CAPTURE the current label via the
    ADVERSARIAL-classified read-label tool into a plan the caller didn't ask to taint — check
    pbs_tape_drive_read_label yourself first)."""
    _check_tape_id(drive)
    _check_label_text(label_text)
    if pool is not None:
        _check_pool_name(pool)
    pool_desc = f" into pool {pool!r}" if pool is not None else " into the free-media pool"
    return Plan(
        action="pbs_tape_drive_label_media",
        target=f"pbs/tape/drive/{drive}/label-media",
        change=f"write label {label_text!r} to drive {drive!r}'s mounted media{pool_desc}",
        current={},
        blast_radius=[
            "OVERWRITES the mounted tape's identity in PBS's catalog/media-set bookkeeping. Any "
            "backup data previously written under the OLD label becomes ORPHANED and effectively "
            "unaddressable through normal PBS tooling — this does not erase raw bytes the way "
            "format-media does, but the practical effect for anyone who didn't intend it is the "
            "same as data loss. PBS's own guidance: the media should be empty (format it first).",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "relabeling makes any prior content on this tape unaddressable — no undo",
        ],
        note=(
            "No undo. This tool does NOT check what's currently on the tape before relabeling — "
            "call pbs_tape_drive_read_label/pbs_tape_drive_cartridge_memory first if you are not "
            "certain the mounted tape is actually empty/scratch."
        ),
    )


def plan_tape_drive_barcode_label_media(drive: str, pool: str | None = None) -> Plan:
    """Plan labeling a drive's mounted media using changer-read barcodes. RISK_HIGH — same
    reasoning as plan_tape_drive_label_media. PURE — no API read (same "don't auto-CAPTURE
    adversarial content" reasoning as the label-media plan above)."""
    _check_tape_id(drive)
    if pool is not None:
        _check_pool_name(pool)
    pool_desc = f" into pool {pool!r}" if pool is not None else " into the free-media pool"
    return Plan(
        action="pbs_tape_drive_barcode_label_media",
        target=f"pbs/tape/drive/{drive}/barcode-label-media",
        change=f"label drive {drive!r}'s mounted media using its changer-read barcode{pool_desc}",
        current={},
        blast_radius=[
            "OVERWRITES the mounted tape's identity in PBS's catalog/media-set bookkeeping. Any "
            "backup data previously written under the OLD label becomes ORPHANED and effectively "
            "unaddressable through normal PBS tooling — same consequence as pbs_tape_drive_"
            "label_media, sourced from the changer's barcode scan instead of a caller-supplied "
            "label-text.",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "relabeling makes any prior content on this tape unaddressable — no undo",
        ],
        note=(
            "No undo. This tool does NOT check what's currently on the tape before relabeling — "
            "call pbs_tape_drive_read_label/pbs_tape_drive_cartridge_memory first if you are not "
            "certain the mounted tape is actually empty/scratch."
        ),
    )


def plan_tape_drive_format(
    drive: str,
    fast: bool | None = None,
    label_text: str | None = None,
    load_barcode: str | None = None,
) -> Plan:
    """Plan formatting (destroying) a drive's mounted media. RISK_HIGH — the campaign brief's own
    binding fact, verbatim: DESTROYS ALL DATA, no undo. PURE — no API read."""
    _check_tape_id(drive)
    if label_text is not None:
        _check_label_text(label_text)
    if load_barcode is not None:
        _check_label_text(load_barcode)
    extra = []
    if fast is not None:
        extra.append(f"fast={bool(fast)}")
    if label_text is not None:
        extra.append(f"label-text={label_text!r} (format cancels if the mounted tape's own label "
                      "doesn't match)")
    if load_barcode is not None:
        extra.append(f"load-barcode={load_barcode!r} (may load-then-format — Smoke-confirm)")
    extra_note = f" ({', '.join(extra)})" if extra else ""
    return Plan(
        action="pbs_tape_drive_format",
        target=f"pbs/tape/drive/{drive}/format-media",
        change=f"format (ERASE) drive {drive!r}'s mounted media{extra_note}",
        current={},
        blast_radius=[
            f"DESTROYS ALL DATA on the tape currently mounted in drive {drive!r}. There is NO "
            "undo — this is a real, physical tape erase.",
            (
                "protection: if label-text is supplied, PBS cancels the format when the mounted "
                "tape's OWN label doesn't match — real protection against formatting the WRONG "
                "cartridge by mistake. NO protection if label-text is omitted: PBS erases "
                "whatever tape happens to be loaded, unconditionally."
                if label_text is not None
                else "NO label-text supplied: PBS erases whatever tape happens to be loaded in "
                     f"drive {drive!r}, UNCONDITIONALLY — there is no built-in default check "
                     "preventing the wrong cartridge from being formatted."
            ),
        ],
        risk=RISK_HIGH,
        risk_reasons=["irreversibly destroys all data on the mounted tape — no PBS-side undo"],
        note=(
            "NO UNDO. Double-check pbs_tape_drive_status/pbs_tape_drive_read_label for what's "
            "actually mounted before confirming, especially if label-text is omitted."
        ),
    )


def plan_tape_drive_catalog(
    drive: str,
    force: bool | None = None,
    scan: bool | None = None,
    verbose: bool | None = None,
) -> Plan:
    """Plan cataloging (scanning) a drive's mounted media. RISK_MEDIUM. PURE — no API read."""
    _check_tape_id(drive)
    extra = []
    if force is not None:
        extra.append(f"force={bool(force)}")
    if scan is not None:
        extra.append(f"scan={bool(scan)}")
    if verbose is not None:
        extra.append(f"verbose={bool(verbose)}")
    extra_note = f" ({', '.join(extra)})" if extra else ""
    return Plan(
        action="pbs_tape_drive_catalog",
        target=f"pbs/tape/drive/{drive}/catalog",
        change=f"catalog (scan) drive {drive!r}'s mounted media{extra_note}",
        current={},
        blast_radius=[
            f"reads (does not modify) the tape mounted in drive {drive!r}; writes/updates the "
            "LOCAL PBS catalog database entry for this media — force=True overrides an existing "
            "catalog index for it; scan=True re-reads the whole tape (can tie up the drive for the "
            "full read duration)",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "modifies local catalog metadata (force=True can override an existing index) and can "
            "occupy the drive for an extended, tape-length-dependent duration",
        ],
        note="No snapshot/undo primitive on this plane. Tape content itself is not modified.",
    )


def plan_tape_drive_restore_key(drive: str, password: str) -> Plan:
    """Plan attempting to restore a tape encryption key from mounted media. RISK_MEDIUM (mirrors
    pbs_tape_media.py's key_create rating). PURE — no API read. THE SECRET CONTRACT (module
    docstring fact #10): `password` is masked to '[redacted]' before entering the Plan; the RAW
    value is still forwarded to the live PBS API on confirm=True."""
    _check_tape_id(drive)
    return Plan(
        action="pbs_tape_drive_restore_key",
        target=f"pbs/tape/drive/{drive}/restore-key",
        change=(
            f"try to restore a tape encryption key from drive {drive!r}'s mounted media: "
            f"{_redact_secrets({'password': password})}"
        ),
        current={},
        blast_radius=[
            f"attempts to recover/re-register an encryption key's usability using the media "
            f"mounted in drive {drive!r} and the supplied password; on success, changes what tape "
            "content becomes decryptable going forward",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "creates/restores a credential controlling future tape access — mirrors "
            "pbs_tape_key_create's rating",
        ],
        note="No snapshot/undo primitive on this plane. The password is never recorded raw to "
             "the ledger or this plan.",
    )


# ---------------------------------------------------------------------------
# Plan factories — Changer
# ---------------------------------------------------------------------------

def plan_tape_changer_transfer(name: str, from_slot: int, to_slot: int) -> Plan:
    """Plan transferring media between two changer slots. RISK_LOW. PURE — no API read."""
    _check_tape_id(name)
    _check_slot(from_slot, "from")
    _check_slot(to_slot, "to")
    return Plan(
        action="pbs_tape_changer_transfer",
        target=f"pbs/tape/changer/{name}/transfer",
        change=f"transfer media from slot {from_slot} to slot {to_slot} on changer {name!r}",
        current={},
        blast_radius=[
            f"changer {name!r}'s robot arm physically moves whatever cartridge occupies slot "
            f"{from_slot} into slot {to_slot} — no drive interaction, no in-flight job is "
            "interrupted",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "pure storage-slot rearrangement — trivially reversible by transferring again with "
            "from/to swapped",
        ],
        note="No snapshot/undo primitive on this plane (none needed — reversible via a symmetric "
             "transfer call).",
    )
