"""PBS tape media CATALOG + tape-backup JOBS + backup/restore plane (Wave 4d of the
full-surface campaign, `.scratch/2026-07-15-full-surface-campaign.md`, "Wave 4 decomposition
(PBS tape)", "4d — media catalog + jobs + backup/restore"). Sibling to `pbs_tape_config.py`
(4a — drive/changer hardware config), `pbs_tape_media.py` (4b — media pools + encryption keys),
and `pbs_tape_ops.py` (4c — drive/changer OPERATIONS): same no-PVE-sibling posture, same idiom
set. This chunk CLOSES Wave 4 (PBS tape).

Schema truth: `.scratch/api-schemas-2026-07-15/wave4-pbs-tape-schema.json` (the live PBS
apidoc.js, pulled 2026-07-15).

Endpoint table (15 tools total — 6 read, 9 mutation):

  GET    /tape/media/list                    — pbs_tape_media_list        (read, ADVERSARIAL)
  GET    /tape/media/content                 — pbs_tape_media_content     (read, ADVERSARIAL)
  GET    /tape/media/media-sets              — pbs_tape_media_sets        (read, REVIEWED_TRUSTED)
  GET    /tape/media/list/{uuid}/status      — pbs_tape_media_status_get  (read, ADVERSARIAL)
  GET    /config/tape-backup-job             — pbs_tape_backup_job_list   (read, REVIEWED_TRUSTED)
  GET    /config/tape-backup-job/{id}        — pbs_tape_backup_job_get    (read, REVIEWED_TRUSTED)
  GET    /tape/media/destroy                 — pbs_tape_media_destroy    (MUTATION, HIGH — GET verb!)
  POST   /tape/media/list/{uuid}/status      — pbs_tape_media_status_set  (MUTATION, MEDIUM)
  POST   /tape/media/move                    — pbs_tape_media_move       (MUTATION, MEDIUM)
  POST   /config/tape-backup-job             — pbs_tape_backup_job_create (MUTATION, LOW)
  PUT    /config/tape-backup-job/{id}        — pbs_tape_backup_job_update (MUTATION, MEDIUM)
  DELETE /config/tape-backup-job/{id}        — pbs_tape_backup_job_delete (MUTATION, MEDIUM)
  POST   /tape/backup/{id}                   — pbs_tape_backup_job_run    (MUTATION, MEDIUM)
  POST   /tape/backup                        — pbs_tape_backup           (MUTATION, MEDIUM)
  POST   /tape/restore                       — pbs_tape_restore          (MUTATION, HIGH)

SCHEMA-VERIFIED FACTS (binding on this build — from the live schema, not memory):

  1. **`GET /tape/media/destroy` DESTROYS media — this is the wave's headline weld.** The
     campaign's own binding fact, re-verified against the live schema: description "Destroy
     media (completely remove from database)", `returns: null`. The HTTP verb is GET but the
     effect is a permanent, irreversible deletion from PBS's media catalog. This module treats
     the verb as NOT the safety signal — the wrapper (`tools/pbs_tape_jobs.py`) is PLAN-gated
     and confirm-gated EXACTLY like every POST/PUT/DELETE mutation on this plane, and is never
     listed as a bare read. The backend function still issues an actual HTTP GET (PBS's own
     wire contract, unchanged) — only the SAFETY GATING is verb-independent.
  2. **`/tape/backup/{id}` (manual job run) ALSO declares `returns: null`** — "Runs a tape
     backup job manually" reads like a real async operation (mirrors its sibling one-off
     `POST /tape/backup`, which DOES return a UPID), but the schema's own `returns` block for
     THIS specific endpoint is `{"type": "null"}`. Same quirk category as Wave 3b's ACME cert
     order/renew (`returns: null` despite doing real work) — outcome is recorded as "ok", NEVER
     "submitted", because that is what the schema states; Smoke-confirm whether the live
     endpoint is genuinely synchronous or the upstream schema annotation is simply incomplete.
  3. **`GET /tape/media/list/{uuid}/status` ALSO declares `returns: null`**, despite its
     description reading "Get current media status" (not a directory-index stub — those are
     separately typed `"Directory index."` with `additionalProperties: true`, e.g.
     `/tape/media/list/{uuid}` itself, which this module does NOT build a tool for). A genuine
     schema-authoring quirk on PBS's own side. `pbs_tape_media_status_get` passes the raw
     response through best-effort (`or {}`) rather than assuming the declared null is
     authoritative about real runtime behavior — Smoke-confirm.
  4. **`store` means TWO GENUINELY DIFFERENT WIRE SHAPES depending on the endpoint** — a real,
     schema-verified trap: on `/config/tape-backup-job[/{id}]` and the one-off `/tape/backup`,
     `store` is a SINGLE datastore identifier (the same 3-32 char tape-identifier shape as
     `drive`/`pool`/`id` on this whole plane). On `/tape/restore`, `store` is a
     COMMA-SEPARATED LIST of `(<source>=)?<target>` DATASTORE MAPPINGS (each entry 3-65 chars,
     `typetext: "[(<source>=)?<target>, ...]"`) — mapping each source datastore recorded on the
     tape to a (possibly different) target datastore to restore into. Same field name, two
     validators (`_check_tape_id` vs `_check_store_mapping`); conflating them would silently
     corrupt a restore call by rejecting (or worse, mis-forwarding) a legitimate mapping list.
     **A further self-contradiction inside this same field's schema**: the description's own
     illustrative example — "For example 'a=b,e' maps the source datastore 'a' to target 'b ...
     and all other sources to the default 'e'" — uses a 1-character target (`e`), which VIOLATES
     the item schema's own `minLength: 3` a few lines below it. `_check_store_mapping` follows
     the FORMAL, machine-checkable `minLength`/`maxLength`/`pattern` constraint, not the
     (self-contradictory) prose example — meaning PBS's own documented example string would be
     REJECTED by this validator. Smoke-confirm whether the live PBS server itself actually
     enforces the 3-65 bound, or whether the formal schema is simply as sloppy as its own
     example; erring toward the stricter, machine-declared constraint is the safer client-side
     default either way.
  5. **`/tape/restore`'s own `media-set` param has NO pattern constraint at all**
     (`{"description": "Media set UUID.", "type": "string"}`) — genuinely open, UNLIKE
     `/tape/media/content`'s `media-set` FILTER param (which DOES carry the standard UUID
     pattern `^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$`). A real, schema-verified asymmetry
     between two same-named fields on this same plane — `plan/tape_restore`'s `media_set`
     argument is validated only defensively (non-empty, no control chars, a 128-char cap this
     module imposes since the schema imposes none — same "stricter-than-schema by documented
     choice" posture `pbs_tape_media.py`'s `allocation`/`retention` fields already established),
     not against the UUID shape.
  6. **`POST /tape/media/list/{uuid}/status`'s enum lists 5 status values but the endpoint's own
     PROSE description forbids 2 of them**: "Update media status (None, 'full', 'damaged' or
     'retired') ... It is not allowed to set status to 'writable' or 'unknown' (those are
     internally managed states)." This module validates `status` (when given) against the
     PROSE-restricted 3-value closed set (`full`/`damaged`/`retired`), not the raw 5-value
     schema enum — matching the established "trust the prose restriction over a looser raw
     enum" discipline (mirrors `pbs_tape_media.py`'s `kdf` closed-enum validation). Omitting
     `status` entirely is PBS's own documented way to CLEAR the manual override (revert to the
     internally-managed writable/unknown state) — `tape_media_status_set`'s `status` parameter
     therefore defaults to `None` and is only included in the wire payload when explicitly
     given (never sent as the literal string `"None"`).
  7. **Media destroy/move both mark BOTH `label-text` and `uuid` fully OPTIONAL in the schema**
     — but calling either with NEITHER supplied leaves PBS with no way to know which physical
     medium to act on. This module adds a client-side "at least one of label_text/uuid is
     required" check on BOTH `plan_tape_media_destroy`/`tape_media_destroy` and
     `plan_tape_media_move`/`tape_media_move` — a DELIBERATE stricter-than-schema safety rail
     (not schema-mandated), justified because these are HIGH/MEDIUM-risk operations on physical
     media identity and an ambiguous, un-targeted call has no legitimate use case. Noted here
     rather than silently diverging from "pass optional fields straight through."
  8. **Restore's `namespaces`/`snapshots` (and job/backup's `group-filter`) are wire-typed
     `array` of plain STRINGS encoding a compound shape, not nested JSON objects or an array of
     dicts** — same PVE::JSONSchema convention as `pbs_tape_config.py`'s comma-separated
     `export-slots` (that module's fact #4), just array-of-compound-string here instead of
     single-comma-string. `namespaces` entries: `store=<string>[,max-depth=<integer>]
     [,source=<string>][,target=<string>]` (validated defensively — must start with `store=`,
     no control chars; the sub-key structure itself is NOT deeply parsed/validated client-side,
     matching `group-filter`'s own established pass-through posture). `snapshots` entries:
     `store:[ns/namespace/...]type/id/time` (validated against a mirrored regex — this one DOES
     get a real pattern match, since the schema supplies one).
  9. **No `digest` optimistic-lock param exists on ANY of the operational/live-state endpoints
     on this plane** (media list/content/media-sets/status-get/status-set/move/destroy, the two
     backup POSTs, restore, job-run) — confirmed field-by-field. Only the CONFIG-plane
     `/config/tape-backup-job[/{id}]` PUT/DELETE carry one. Matches `pbs_tape_ops.py`'s fact #11
     (operational/live-state endpoints never carry digest on this whole tape family; only
     versioned CONFIG does) — extended here to cover jobs + media catalog too.
  10. **Restore auto-creates namespaces** — the endpoint's own description, verbatim:
      "Restore data from media-set. Namespaces will be automatically created if necessary."
      PBS's description does NOT state what happens if a target snapshot with the same
      type/id/time already exists in the destination datastore/namespace when the restore
      writes into it — genuinely undocumented overwrite semantics. Treated as Smoke-confirm per
      the campaign's explicit instruction (do not assert an overwrite/skip behavior the schema
      never states); the tool docstring and plan note say so plainly rather than inventing
      either "safe, never overwrites" or "may silently overwrite" as a verified fact.
  11. **`id` (job identifier) shares the IDENTICAL char-class/length shape as `drive`/`pool`-
      adjacent tape identifiers** (`^[A-Za-z0-9_][A-Za-z0-9._\\-]*$`, 3-32 chars) — this module
      reuses `pbs_tape_config._check_tape_id` for the job id (Python param name `job_id`,
      avoiding a shadow of the `id` builtin) rather than writing a fresh copy, same reuse
      discipline `pbs_tape_ops.py` already established for `drive`/`name`. `store` (single-
      datastore shape, fact #4), `vault_name`, and `update_status_changer` share this exact
      shape too and reuse the same validator. `pool` (media pool filters) reuses
      `pbs_tape_media._check_pool_name` (2-32, a DIFFERENT bound). `label_text` reuses
      `pbs_tape_ops._check_label_text` (2-32, confirmed byte-identical pattern to the
      drive-operations plane's own label-text).
  12. **`GET /tape/media/list`'s `update-status` param defaults to `true` UPSTREAM** ("Try to
      update tape library status (check what tapes are online)" — this can mean re-querying a
      changer, real hardware/robotics-adjacent work, not a pure database read). Per the
      campaign's explicit instruction, Proximo's OWN tool default deliberately OVERRIDES this:
      `pbs_tape_media_list()` called with no arguments ALWAYS sends `update-status=false`
      explicitly (never omits the field and lets PBS's own `true` default apply) — so calling
      this READ tool bare never triggers a changer status refresh. Pass `update_status=True`
      to explicitly opt into PBS's own default behavior.

RISK RATING (module-specific reasoning):
  - **media_destroy = RISK_HIGH**: the campaign's own binding fact — "completely removes the
    media from the catalog/database," permanent, no undo, regardless of the GET verb.
  - **media_status_set = RISK_MEDIUM**: changes whether PBS considers this specific tape
    available for future writes (marking 'retired'/'damaged' takes usable capacity out of
    rotation, or correctly protects a bad tape from further writes; marking a GOOD tape
    'retired'/'damaged' by mistake reduces available media until reverted). Fully reversible —
    call this tool again with a different status, or omit `status` to clear the override — no
    tape content is touched either way.
  - **media_move = RISK_MEDIUM**: changes PBS's own location bookkeeping for a physical tape
    (`online-<changer>` / `vault-<name>` / `offline`) — does not itself move anything
    physically, but a scheduled job or inventory operation that expects this media to be
    online in a changer will fail to find it (or vice versa) until the bookkeeping is corrected
    to match reality. Omitting `vault_name` is NOT a no-op — per the endpoint's own description
    ("Change Tape location to vault (if given), or offline"), it actively sets the location to
    OFFLINE.
  - **backup_job_create = RISK_LOW**: additive config — mirrors
    `pbs_tape_pool_create`/`pbs_notification_endpoint_create`'s LOW rating (no existing
    drive/pool/job config is affected).
  - **backup_job_update = RISK_MEDIUM**: changes which drive/pool/store/schedule/filter a
    SCHEDULED job uses on its next automatic run — mirrors `pbs_tape_pool_update`'s reasoning
    (a behavioral change to already-relied-upon automation, not merely additive).
  - **backup_job_delete = RISK_MEDIUM** — a step up from `pbs_tape_config.py`'s drive/changer
    delete (config-only LOW) and matched to `pbs_tape_pool_delete`'s MEDIUM, for a reason
    specific to this endpoint: removing a SCHEDULED job's config makes future automatic tape
    backups for its guests STOP SILENTLY — no error, no alert, the job simply no longer runs.
    That is a materially worse failure mode for a data-protection control than a drive/changer
    identifier going stale (which surfaces loudly and immediately the next time anything tries
    to use it).
  - **backup_job_run = RISK_MEDIUM**: triggers a REAL tape backup right now, using whatever
    drive/pool/store/filters the named job was configured with — the drive is busy for the
    duration and writes real data to tape (same physical/operational weight as the one-off
    `pbs_tape_backup` below). Caller does not automatically see the job's own configured
    parameters in this plan — check `pbs_tape_backup_job_get` first if unsure what will run.
  - **tape_backup (one-off) = RISK_MEDIUM** — the campaign's own binding fact: writes datastore
    contents to tape, drive busy for the duration; does not itself destroy prior tape content
    the way `format-media`/`label-media` do (Wave 4c), so it does not reach HIGH.
  - **tape_restore = RISK_HIGH** — the campaign's own "MEDIUM-HIGH" resolved UP, matching Wave
    4c's own resolution rule verbatim (this codebase's risk enum has exactly 4 levels — none/
    low/medium/high, `planning.py` — there is no fifth tier to reach for): WRITES into an
    existing datastore, AUTO-CREATES namespaces (a structural change to the target datastore's
    namespace tree, not merely additive data), can restore an entire media-set's worth of
    snapshots across multiple namespaces in ONE call (a materially larger, less-inspectable
    blast radius than e.g. `pve_restore`'s single-vmid scope, which that tool's own plan
    factory bounds with a cheap live existence-check before deciding HIGH vs MEDIUM — no
    equivalent cheap precheck exists here across a whole media-set), and PBS's own schema is
    SILENT on overwrite-vs-skip semantics for a colliding existing snapshot (fact #10) — genuine
    uncertainty compounding an already-broad blast radius resolves to the higher tier, not the
    lower one.

Taint (this module's read-only tools):
  - **`pbs_tape_media_list` = ADVERSARIAL**: entries carry `label-text`
    (`{"description": "Media label text (or Barcode)", "type": "string"}`) with NO return-side
    pattern constraint at all — confirmed field-by-field against the live schema. This is an
    EVEN CLEARER call than Wave 4c's `pbs_tape_changer_status` (which at least had a typed
    pattern on its label-text field and still landed ADVERSARIAL): here there is no pattern
    nuance to weigh at all, so this diverges from the campaign brief's suggestion to weigh it
    against the changer_status precedent — it doesn't need that precedent's argued-divergence
    reasoning, it's structurally identical to `pbs_tape_drive_read_label`/
    `pbs_tape_drive_inventory` (untyped free text, no return-side pattern) from the start.
  - **`pbs_tape_media_content` = ADVERSARIAL**: carries both `label-text` (same content class as
    above) AND `snapshot` (a guest-influenced backup identifier/type/time string) — directly
    matches the `pbs_snapshots_list` precedent the campaign brief names explicitly.
  - **`pbs_tape_media_sets` = REVIEWED_TRUSTED — a deliberate DIVERGENCE from the campaign
    brief's own premise** ("media_list/media_sets carry media labels"), argued explicitly per
    the brief's "argue any divergence, never silently decide" instruction: checked field-by-
    field against the live schema, `/tape/media/media-sets`' response carries ONLY
    `media-set-ctime` (int), `media-set-name` (string — but PBS-GENERATED from the owning
    pool's OPERATOR-authored `template` field at media-set allocation time, not read off
    physical tape or attacker-influenced), `media-set-uuid` (PBS-generated uuid), and `pool`
    (an OPERATOR-CONFIGURED pool identifier). There is NO `label-text` field anywhere in this
    response — the brief's premise does not hold against the live schema for this specific
    endpoint, unlike `pbs_tape_media_list` (fact above) where it does.
  - **`pbs_tape_media_status_get` = ADVERSARIAL (conservative default under genuine
    uncertainty)**: the schema's own declared return type is `null` (fact #3) — what real
    content actually comes back is UNKNOWN from the schema alone. By direct analogy to
    `/tape/media/list` (whose per-media entries carry a `status` field ALONGSIDE `label-text`),
    a per-media status fetch plausibly returns similarly label-text-adjacent content. Given
    real ambiguity, this module follows `taint.py`'s own stated bias, the same one
    `pbs_tape_changer_status` (Wave 4c) invoked for its own argued divergence: "classify as
    adversarial when unsure." Reclassify to REVIEWED_TRUSTED only once a live PBS response is
    actually inspected and confirmed label-text-free.
  - **`pbs_tape_backup_job_list`/`pbs_tape_backup_job_get` = REVIEWED_TRUSTED**: operator-
    authored scheduled-job config (schedule/comment/group-filter/notify-user/pool/store/drive
    references, plus PBS-generated `last-run-*` status fields on the sibling `/tape/backup` GET
    this module does NOT build — see follow-up debt) — matches `pve_backup_job_list`/
    `pve_backup_job_create`'s existing REVIEWED_TRUSTED classification exactly, per the
    campaign's explicit instruction.
  - **All 9 mutations = REVIEWED_TRUSTED**: every one returns either an opaque UPID (task
    identifier, PBS-generated) or `null` — none echo back media-authored or guest-authored free
    text, matching Wave 4c's "taint classifies the RETURN channel, not the mutation's
    consequences" rule.

Design note — CAPTURE discipline mirrors Wave 4c: `plan_tape_media_destroy`/
`plan_tape_media_status_set`/`plan_tape_media_move`/`plan_tape_backup_job_run`/`plan_tape_backup`/
`plan_tape_restore` are all PURE (no live API read) — deliberately NOT auto-CAPTURING the
ADVERSARIAL-classified `pbs_tape_media_list`/`pbs_tape_media_content`/`pbs_tape_media_status_get`
content into a plan the caller didn't ask to taint (Wave 4c fact #12's same reasoning, extended
to this module's own physical/live-state mutations). Only the CONFIG-plane job update/delete
plans CAPTURE current config, via the REVIEWED_TRUSTED `tape_backup_job_get` — safe, matching
Wave 4a/4b's config-CRUD CAPTURE discipline.

Follow-up debt (surfaced during this build, NOT invented to pad the count): `GET /tape/backup`
("List all tape backup jobs" — but WITH last-run-state/last-run-upid/next-run status fields the
plain `/config/tape-backup-job` GET this module builds does not carry) is present in the live
schema but was not part of this wave's binding 15-tool list. A genuine gap, same shape as Wave
4c's unbuilt `/tape/drive/{drive}/export-media` — candidate for a future patch.

VERIFIED live shapes: None — all backend functions carry "Smoke-confirm:" comments; every shape
here is schema-derived, not live-proven against a running PBS with real tape hardware attached.
"""

from __future__ import annotations

import re

from ._validate import check_digest as _check_digest
from .backends import ProximoError
from .pbs import PbsBackend, _check_delete_list
from .pbs_tape_config import _check_tape_id  # reuse: identical drive/pool/id/store/vault shape
from .pbs_tape_media import (  # reuse: identical comment shape (128, no ctrl) + media-pool name
    _check_no_control,
    _check_pool_name,
)
from .pbs_tape_ops import _check_label_text  # reuse: identical media label-text shape
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# Media UUID — standard lowercase-hex UUID shape, shared by `media`/`media-set` filter params on
# /tape/media/content, `uuid` on destroy/move, and the {uuid} path segment on status get/set.
_MEDIA_UUID_RE = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")

# backup-id filter on /tape/media/content: schema pattern only, NO length bound at all (unlike
# pbs.py's own _check_backup_id, which caps at 64 and disallows a leading underscore — a fresh,
# genuinely different shape here, not reused).
_BACKUP_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*\Z")

_VALID_BACKUP_TYPES = frozenset({"vm", "ct", "host"})

# Media status: schema enum lists 5 values, but the endpoint's own prose forbids 2 of them
# (fact #6) — validated against the prose-restricted set, not the raw enum.
_VALID_MEDIA_STATUS = frozenset({"full", "damaged", "retired"})

_VALID_NOTIFICATION_MODE = frozenset({"legacy-sendmail", "notification-system"})

# notify-user (PBS userid: user@realm) and owner (PBS authid: user@realm or
# user@realm!token-name) — same charset shape as pbs_access.py's _check_userid/_check_authid,
# NOT imported (this tape-module family's own convention is fresh per-module copies — see
# pbs_tape_ops.py's identical statement); this endpoint's schema additionally states an explicit
# 3-64 length bound neither of pbs_access.py's versions enforces.
_USERID_RE = re.compile(r"^[^\s:/\x00-\x1f\x7f]+@[A-Za-z0-9_][A-Za-z0-9._-]*\Z")
_AUTHID_RE = re.compile(
    r"^[^\s:/\x00-\x1f\x7f]+@[A-Za-z0-9_][A-Za-z0-9._-]*(?:![A-Za-z0-9_][A-Za-z0-9._-]*)?\Z"
)

# group-filter entries (job create/update, one-off backup): defensive, non-exhaustive — PBS
# itself parses the exclude:/include:/type:/group:/regex: prefix structure server-side. Mirrors
# the established "pass compound strings through, let the live API enforce its own inner shape"
# posture already used for `delete` lists across this codebase.
_GROUP_FILTER_RE = re.compile(r"^[^\x00-\x1f\x7f]+\Z")

# namespaces entries (restore, fact #8): "store=<string>[,max-depth=<int>][,source=<string>]
# [,target=<string>]" — validated only for the required leading "store=" + no control chars, the
# inner key structure is NOT deeply parsed (same posture as group-filter above).
_NAMESPACE_MAPPING_RE = re.compile(r"^store=[^\x00-\x1f\x7f]+\Z")

# snapshots entries (restore): "store:[ns/namespace/...]type/id/time" — the schema DOES supply a
# real pattern here, mirrored directly (re-anchored \Z per this codebase's convention).
_SNAPSHOT_RE = re.compile(
    r"^[A-Za-z0-9_][A-Za-z0-9._-]*:"
    r"(?:(?:ns/[A-Za-z0-9_][A-Za-z0-9._-]*/){0,7}ns/[A-Za-z0-9_][A-Za-z0-9._-]*/)?"
    r"(?:host|vm|ct)/[A-Za-z0-9_][A-Za-z0-9._-]*/"
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)

# store mapping entries (restore's OWN "store" shape — fact #4, genuinely different from the
# single-identifier "store" used by job create/update and the one-off backup).
_STORE_MAPPING_ENTRY_RE = re.compile(r"^(?:[A-Za-z0-9_][A-Za-z0-9._-]*=)?[A-Za-z0-9_][A-Za-z0-9._-]*\Z")

# Complete no-control-characters class — the module's ONE control-char truth (\x00-\x1f + \x7f),
# shared by _check_media_set_ref (Wave 4d review finding 3: never hand-roll a partial blocklist).
_NO_CONTROL_FULL_RE = re.compile(r"^[^\x00-\x1f\x7f]+\Z")

# ns (tape-backup-job create/update + one-off backup): the tape schema's own pattern —
# up to 8 /-separated identifier components (`(?:comp/){0,7}comp`, each component alnum/
# underscore-leading then alnum/./_/-), empty allowed (root namespace), maxLength 256. Mirrored
# directly + \Z-re-anchored. NOTE (Wave 4d review finding 2): deliberately NOT reusing
# pbs._check_namespace — verified against the live schema that it is materially LOOSER than this
# plane's ns shape (no charset restriction: accepts spaces/colons; no 256 cap; no 8-component
# depth cap), so a fresh, schema-faithful local validator is the honest choice here.
_TAPE_NS_RE = re.compile(
    r"^(?:(?:[A-Za-z0-9_][A-Za-z0-9._-]*/){0,7}[A-Za-z0-9_][A-Za-z0-9._-]*)?\Z"
)


def _check_tape_ns(value: str) -> str:
    """Validate a tape-plane namespace against the schema's OWN shape (see _TAPE_NS_RE above):
    up to 8 /-separated identifier components, empty = root, maxLength 256. Wave 4d review
    finding 2 — this field was previously forwarded via bare str() with zero validation."""
    s = str(value)
    if len(s) > 256 or not _TAPE_NS_RE.match(s):
        raise ProximoError(
            f"invalid ns: {value!r} — up to 8 /-separated components (each starting alnum/"
            "underscore, then alnum/./_/-), <=256 chars, no leading/trailing slash "
            "(empty = root namespace)"
        )
    return s


def _check_media_uuid(value: str) -> str:
    s = str(value)
    if not _MEDIA_UUID_RE.match(s):
        raise ProximoError(f"invalid media uuid: {value!r} (expected a lowercase-hex UUID)")
    return s


def _check_backup_id_filter(value: str) -> str:
    s = str(value)
    if not _BACKUP_ID_RE.match(s):
        raise ProximoError(
            f"invalid backup_id filter: {value!r} (alnum/underscore start, then alnum/./_/-)"
        )
    return s


def _check_backup_type(value: str) -> str:
    s = str(value)
    if s not in _VALID_BACKUP_TYPES:
        raise ProximoError(f"invalid backup_type: {value!r} (expected one of {sorted(_VALID_BACKUP_TYPES)})")
    return s


def _check_media_status(value: str) -> str:
    s = str(value)
    if s not in _VALID_MEDIA_STATUS:
        raise ProximoError(
            f"invalid media status: {value!r} — PBS's own description forbids 'writable'/"
            f"'unknown' here (internally managed); expected one of {sorted(_VALID_MEDIA_STATUS)}, "
            "or omit `status` entirely to clear the manual override"
        )
    return s


def _check_notification_mode(value: str) -> str:
    s = str(value)
    if s not in _VALID_NOTIFICATION_MODE:
        raise ProximoError(
            f"invalid notification-mode: {value!r} (expected one of {sorted(_VALID_NOTIFICATION_MODE)})"
        )
    return s


def _check_notify_user(value: str) -> str:
    s = str(value)
    if not (3 <= len(s) <= 64) or not _USERID_RE.match(s):
        raise ProximoError(f"invalid notify_user: {value!r} — expected 'user@realm', 3-64 chars")
    return s


def _check_owner(value: str) -> str:
    s = str(value)
    if not (3 <= len(s) <= 64) or not _AUTHID_RE.match(s):
        raise ProximoError(
            f"invalid owner: {value!r} — expected 'user@realm' or 'user@realm!token-name', 3-64 chars"
        )
    return s


def _check_max_depth(value: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid max_depth: {value!r} (must be an integer)") from exc
    if not (0 <= n <= 7):
        raise ProximoError(f"invalid max_depth: {value!r} (must be 0-7)")
    return n


def _check_worker_threads(value: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid worker_threads: {value!r} (must be an integer)") from exc
    if not (1 <= n <= 32):
        raise ProximoError(f"invalid worker_threads: {value!r} (must be 1-32)")
    return n


def _check_group_filter_list(values) -> list[str]:
    out = []
    for v in values:
        s = str(v)
        if not s or not _GROUP_FILTER_RE.match(s):
            raise ProximoError(
                f"invalid group-filter entry: {v!r} — non-empty, no control characters "
                "(PBS parses the exclude:/include:/type:/group:/regex: prefix server-side)"
            )
        out.append(s)
    return out


def _check_namespace_mapping_list(values) -> list[str]:
    out = []
    for v in values:
        s = str(v)
        if not _NAMESPACE_MAPPING_RE.match(s):
            raise ProximoError(
                f"invalid namespaces entry: {v!r} — expected 'store=<string>[,max-depth=<int>]"
                "[,source=<string>][,target=<string>]' (must start with 'store=', no control chars)"
            )
        out.append(s)
    return out


def _check_snapshot_list(values) -> list[str]:
    out = []
    for v in values:
        s = str(v)
        if not _SNAPSHOT_RE.match(s):
            raise ProximoError(
                f"invalid snapshot spec: {v!r} — expected 'store:[ns/namespace/...]type/id/time'"
            )
        out.append(s)
    return out


def _check_store_mapping(value: str) -> str:
    """Restore's OWN `store` shape (fact #4) — comma-separated (<source>=)?<target> entries,
    3-65 chars each. Genuinely different from the single-identifier `store` used by job
    create/update and the one-off backup (which reuse `_check_tape_id` instead)."""
    s = str(value)
    parts = s.split(",")
    if not parts or any(not p for p in parts):
        raise ProximoError(
            f"invalid store mapping list: {value!r} — comma-separated (<source>=)?<target> "
            "entries, no empty segments"
        )
    for p in parts:
        if not (3 <= len(p) <= 65) or not _STORE_MAPPING_ENTRY_RE.match(p):
            raise ProximoError(
                f"invalid store mapping entry: {p!r} — expected '(<source>=)?<target>', 3-65 "
                "chars, alnum/./_/- charset"
            )
    return s


def _check_media_set_ref(value: str) -> str:
    """Restore's own `media-set` param (fact #5) — NO pattern in the live schema at all, unlike
    /tape/media/content's UUID-patterned `media-set` filter. Validated defensively only (no
    control chars, a 128-char cap this module imposes since the schema imposes none — same
    stricter-than-schema-by-documented-choice posture as pbs_tape_media.py's
    allocation/retention fields). Control chars checked with the module's own complete
    [^\\x00-\\x1f\\x7f] class (Wave 4d review finding 3: an earlier hand-rolled blocklist covered
    only \\x00-\\x0d, letting \\x1b/ESC — the ANSI escape driver — through into
    Plan.target/ledger-display contexts)."""
    s = str(value)
    if not s or not _NO_CONTROL_FULL_RE.match(s) or len(s) > 128:
        raise ProximoError(
            f"invalid media_set: {value!r} — non-empty, no control characters, <=128 chars"
        )
    return s


# ---------------------------------------------------------------------------
# Backend functions — reads
# ---------------------------------------------------------------------------

def tape_media_list(
    api: PbsBackend,
    pool: str | None = None,
    update_status: bool = False,
    update_status_changer: str | None = None,
) -> list[dict]:
    """GET /tape/media/list — list registered backup media, optionally scoped to `pool`.
    `update_status` DEFAULTS TO FALSE here (module docstring fact #12) — PBS's own upstream
    default is `true`, which can trigger a real changer status refresh; this tool never does
    that unless explicitly asked. ADVERSARIAL: entries carry `label-text`, no return-side
    pattern constraint. Smoke-confirm: response shape."""
    params: dict = {"update-status": bool(update_status)}
    if pool is not None:
        params["pool"] = _check_pool_name(pool)
    if update_status_changer is not None:
        params["update-status-changer"] = _check_tape_id(update_status_changer)
    return api._get("/tape/media/list", params=params) or []


def tape_media_content(
    api: PbsBackend,
    backup_id: str | None = None,
    backup_type: str | None = None,
    label_text: str | None = None,
    media: str | None = None,
    media_set: str | None = None,
    pool: str | None = None,
) -> list[dict]:
    """GET /tape/media/content — list media content (snapshot inventory across tape), optionally
    filtered. ADVERSARIAL: carries `snapshot` (guest-influenced backup id/type/time) AND
    `label-text` — matches the pbs_snapshots_list precedent directly. Smoke-confirm: response
    shape."""
    params: dict = {}
    if backup_id is not None:
        params["backup-id"] = _check_backup_id_filter(backup_id)
    if backup_type is not None:
        params["backup-type"] = _check_backup_type(backup_type)
    if label_text is not None:
        params["label-text"] = _check_label_text(label_text)
    if media is not None:
        params["media"] = _check_media_uuid(media)
    if media_set is not None:
        params["media-set"] = _check_media_uuid(media_set)
    if pool is not None:
        params["pool"] = _check_pool_name(pool)
    return api._get("/tape/media/content", params=params) or []


def tape_media_sets(api: PbsBackend) -> list[dict]:
    """GET /tape/media/media-sets — list media sets. REVIEWED_TRUSTED (module docstring's Taint
    section: no label-text field exists in this response — media-set-name is PBS-generated from
    the pool's operator-authored template, not physical-media content). Smoke-confirm: response
    shape."""
    return api._get("/tape/media/media-sets") or []


def tape_media_status_get(api: PbsBackend, uuid: str) -> dict:
    """GET /tape/media/list/{uuid}/status — one medium's current status. The live schema declares
    `returns: null` (module docstring fact #3) despite the description implying real data —
    best-effort passthrough. ADVERSARIAL (conservative default, module docstring's Taint
    section — genuine ambiguity about the real return shape). Smoke-confirm: response shape."""
    uuid = _check_media_uuid(uuid)
    return api._get(f"/tape/media/list/{uuid}/status") or {}


def tape_backup_job_list(api: PbsBackend) -> list[dict]:
    """GET /config/tape-backup-job — list configured tape backup jobs. REVIEWED_TRUSTED:
    operator-authored scheduled-job config. Smoke-confirm: response shape."""
    return api._get("/config/tape-backup-job") or []


def tape_backup_job_get(api: PbsBackend, job_id: str) -> dict:
    """GET /config/tape-backup-job/{id} — one job's full config. REVIEWED_TRUSTED. Smoke-confirm:
    response shape."""
    job_id = _check_tape_id(job_id)
    return api._get(f"/config/tape-backup-job/{job_id}") or {}


# ---------------------------------------------------------------------------
# Backend functions — mutations, Media catalog
# ---------------------------------------------------------------------------

def tape_media_destroy(
    api: PbsBackend, label_text: str | None = None, uuid: str | None = None, force: bool | None = None,
) -> None:
    """GET /tape/media/destroy — COMPLETELY REMOVES the media from PBS's database. GET verb, real
    destructive effect (module docstring fact #1) — the safety gating in
    tools/pbs_tape_jobs.py's wrapper is verb-independent (PLAN + confirm, same as every other
    mutation). At least one of label_text/uuid is required (module docstring fact #7 — a
    deliberate stricter-than-schema safety rail; both are schema-optional but an unidentified
    target has no legitimate use here). Returns null (synchronous). MUTATION — confirm-gated +
    audited at the server layer."""
    if label_text is None and uuid is None:
        raise ProximoError(
            "pbs_tape_media_destroy requires at least one of label_text/uuid to identify which "
            "media to destroy — both are schema-optional, but an unidentified target has no "
            "legitimate use for a permanent, irreversible removal"
        )
    params: dict = {}
    if label_text is not None:
        params["label-text"] = _check_label_text(label_text)
    if uuid is not None:
        params["uuid"] = _check_media_uuid(uuid)
    if force is not None:
        params["force"] = bool(force)
    api._get("/tape/media/destroy", params=params)


def tape_media_status_set(api: PbsBackend, uuid: str, status: str | None = None) -> None:
    """POST /tape/media/list/{uuid}/status — set (or, if status is omitted, CLEAR) a medium's
    manual status override. `status`, when given, must be 'full'/'damaged'/'retired' (module
    docstring fact #6 — PBS's own prose forbids 'writable'/'unknown' even though they appear in
    the raw schema enum). Returns null (synchronous). MUTATION — confirm-gated + audited at the
    server layer."""
    uuid = _check_media_uuid(uuid)
    data: dict = {}
    if status is not None:
        data["status"] = _check_media_status(status)
    api._post(f"/tape/media/list/{uuid}/status", data)


def tape_media_move(
    api: PbsBackend, label_text: str | None = None, uuid: str | None = None, vault_name: str | None = None,
) -> None:
    """POST /tape/media/move — change a tape's LOCATION bookkeeping to a vault (if `vault_name`
    given) or to OFFLINE (if omitted — module docstring RISK RATING: NOT a no-op). At least one
    of label_text/uuid is required (module docstring fact #7, same rail as destroy). Returns
    null (synchronous). MUTATION — confirm-gated + audited at the server layer."""
    if label_text is None and uuid is None:
        raise ProximoError(
            "pbs_tape_media_move requires at least one of label_text/uuid to identify which "
            "media to move"
        )
    data: dict = {}
    if label_text is not None:
        data["label-text"] = _check_label_text(label_text)
    if uuid is not None:
        data["uuid"] = _check_media_uuid(uuid)
    if vault_name is not None:
        data["vault-name"] = _check_tape_id(vault_name)
    api._post("/tape/media/move", data)


# ---------------------------------------------------------------------------
# Backend functions — mutations, Tape backup jobs (config)
# ---------------------------------------------------------------------------

def _job_extra_fields(
    comment=None, eject_media=None, export_media_set=None, group_filter=None, latest_only=None,
    max_depth=None, notification_mode=None, notify_user=None, ns=None, schedule=None,
    worker_threads=None,
) -> dict:
    data: dict = {}
    if comment is not None:
        # Schema: maxLength 128, no control chars — reuses pbs_tape_media's identical-shape
        # validator (Wave 4d review finding 2: was a bare str() with zero validation).
        data["comment"] = _check_no_control(comment, "comment", max_len=128)
    if eject_media is not None:
        data["eject-media"] = bool(eject_media)
    if export_media_set is not None:
        data["export-media-set"] = bool(export_media_set)
    if group_filter is not None:
        data["group-filter"] = _check_group_filter_list(group_filter)
    if latest_only is not None:
        data["latest-only"] = bool(latest_only)
    if max_depth is not None:
        data["max-depth"] = _check_max_depth(max_depth)
    if notification_mode is not None:
        data["notification-mode"] = _check_notification_mode(notification_mode)
    if notify_user is not None:
        data["notify-user"] = _check_notify_user(notify_user)
    if ns is not None:
        # Schema-faithful local validator (Wave 4d review finding 2 — see _TAPE_NS_RE's note on
        # why pbs._check_namespace was NOT reused).
        data["ns"] = _check_tape_ns(ns)
    if schedule is not None:
        data["schedule"] = str(schedule)
    if worker_threads is not None:
        data["worker-threads"] = _check_worker_threads(worker_threads)
    return data


def tape_backup_job_create(
    api: PbsBackend,
    job_id: str,
    drive: str,
    pool: str,
    store: str,
    comment: str | None = None,
    eject_media: bool | None = None,
    export_media_set: bool | None = None,
    group_filter: list[str] | None = None,
    latest_only: bool | None = None,
    max_depth: int | None = None,
    notification_mode: str | None = None,
    notify_user: str | None = None,
    ns: str | None = None,
    schedule: str | None = None,
    worker_threads: int | None = None,
) -> None:
    """POST /config/tape-backup-job — id/drive/pool/store required, all else optional. Returns
    null (synchronous). MUTATION — confirm-gated + audited at the server layer."""
    data: dict = {
        "id": _check_tape_id(job_id),
        "drive": _check_tape_id(drive),
        "pool": _check_pool_name(pool),
        "store": _check_tape_id(store),
    }
    data.update(_job_extra_fields(
        comment, eject_media, export_media_set, group_filter, latest_only, max_depth,
        notification_mode, notify_user, ns, schedule, worker_threads,
    ))
    api._post("/config/tape-backup-job", data)


def tape_backup_job_update(
    api: PbsBackend,
    job_id: str,
    drive: str | None = None,
    pool: str | None = None,
    store: str | None = None,
    comment: str | None = None,
    eject_media: bool | None = None,
    export_media_set: bool | None = None,
    group_filter: list[str] | None = None,
    latest_only: bool | None = None,
    max_depth: int | None = None,
    notification_mode: str | None = None,
    notify_user: str | None = None,
    ns: str | None = None,
    schedule: str | None = None,
    worker_threads: int | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> None:
    """PUT /config/tape-backup-job/{id} — all fields but the path id optional. Returns null
    (synchronous). MUTATION — confirm-gated + audited at the server layer."""
    job_id = _check_tape_id(job_id)
    data: dict = {}
    if drive is not None:
        data["drive"] = _check_tape_id(drive)
    if pool is not None:
        data["pool"] = _check_pool_name(pool)
    if store is not None:
        data["store"] = _check_tape_id(store)
    data.update(_job_extra_fields(
        comment, eject_media, export_media_set, group_filter, latest_only, max_depth,
        notification_mode, notify_user, ns, schedule, worker_threads,
    ))
    if digest is not None:
        data["digest"] = _check_digest(digest)
    if delete is not None:
        data["delete"] = _check_delete_list(delete)
    api._put(f"/config/tape-backup-job/{job_id}", data)


def tape_backup_job_delete(api: PbsBackend, job_id: str, digest: str | None = None) -> None:
    """DELETE /config/tape-backup-job/{id}. Returns null (synchronous). MUTATION — confirm-gated
    + audited at the server layer."""
    job_id = _check_tape_id(job_id)
    params: dict = {}
    if digest is not None:
        params["digest"] = _check_digest(digest)
    api._delete(f"/config/tape-backup-job/{job_id}", params=params)


def tape_backup_job_run(api: PbsBackend, job_id: str) -> None:
    """POST /tape/backup/{id} — run a preconfigured tape backup job manually, right now. Returns
    null per the live schema (module docstring fact #2 — a real quirk; do NOT assume this is
    genuinely synchronous just because the schema says so). MUTATION — confirm-gated + audited at
    the server layer."""
    job_id = _check_tape_id(job_id)
    api._post(f"/tape/backup/{job_id}", {})


# ---------------------------------------------------------------------------
# Backend functions — mutations, One-off backup + restore
# ---------------------------------------------------------------------------

def tape_backup(
    api: PbsBackend,
    drive: str,
    pool: str,
    store: str,
    eject_media: bool | None = None,
    export_media_set: bool | None = None,
    force_media_set: bool | None = None,
    group_filter: list[str] | None = None,
    latest_only: bool | None = None,
    max_depth: int | None = None,
    notification_mode: str | None = None,
    notify_user: str | None = None,
    ns: str | None = None,
    worker_threads: int | None = None,
) -> str:
    """POST /tape/backup — one-off: back up `store` to `pool` via `drive`, right now (no
    schedule, no job id — unlike tape_backup_job_create). Returns a UPID (async task). MUTATION —
    confirm-gated + audited at the server layer."""
    data: dict = {
        "drive": _check_tape_id(drive),
        "pool": _check_pool_name(pool),
        "store": _check_tape_id(store),
    }
    if eject_media is not None:
        data["eject-media"] = bool(eject_media)
    if export_media_set is not None:
        data["export-media-set"] = bool(export_media_set)
    if force_media_set is not None:
        data["force-media-set"] = bool(force_media_set)
    if group_filter is not None:
        data["group-filter"] = _check_group_filter_list(group_filter)
    if latest_only is not None:
        data["latest-only"] = bool(latest_only)
    if max_depth is not None:
        data["max-depth"] = _check_max_depth(max_depth)
    if notification_mode is not None:
        data["notification-mode"] = _check_notification_mode(notification_mode)
    if notify_user is not None:
        data["notify-user"] = _check_notify_user(notify_user)
    if ns is not None:
        # Same schema-faithful ns validator as _job_extra_fields' (Wave 4d review finding 2).
        data["ns"] = _check_tape_ns(ns)
    if worker_threads is not None:
        data["worker-threads"] = _check_worker_threads(worker_threads)
    return api._post("/tape/backup", data)


def tape_restore(
    api: PbsBackend,
    drive: str,
    media_set: str,
    store: str,
    namespaces: list[str] | None = None,
    notification_mode: str | None = None,
    notify_user: str | None = None,
    owner: str | None = None,
    snapshots: list[str] | None = None,
) -> str:
    """POST /tape/restore — restore data from a media-set into `store` (a comma-separated
    datastore MAPPING list — module docstring fact #4, a DIFFERENT wire shape than the plain
    single-identifier `store` used elsewhere on this plane) via `drive`. Namespaces are
    auto-created as needed (fact #10). `snapshots` restricts the restore to specific snapshots
    (selective restore); omit for a full media-set restore. Returns a UPID (async task).
    MUTATION — confirm-gated + audited at the server layer."""
    data: dict = {
        "drive": _check_tape_id(drive),
        "media-set": _check_media_set_ref(media_set),
        "store": _check_store_mapping(store),
    }
    if namespaces is not None:
        data["namespaces"] = _check_namespace_mapping_list(namespaces)
    if notification_mode is not None:
        data["notification-mode"] = _check_notification_mode(notification_mode)
    if notify_user is not None:
        data["notify-user"] = _check_notify_user(notify_user)
    if owner is not None:
        data["owner"] = _check_owner(owner)
    if snapshots is not None:
        data["snapshots"] = _check_snapshot_list(snapshots)
    return api._post("/tape/restore", data)


# ---------------------------------------------------------------------------
# Plan factories — Media catalog mutations (all PURE — see module docstring's Design note)
# ---------------------------------------------------------------------------

def plan_tape_media_destroy(label_text: str | None = None, uuid: str | None = None, force: bool | None = None) -> Plan:
    """Plan destroying a tape medium. RISK_HIGH — permanent removal from PBS's database, no undo,
    regardless of the GET verb (module docstring fact #1). PURE — no API read (does not
    auto-CAPTURE the ADVERSARIAL pbs_tape_media_list/status_get content; check those tools
    yourself first)."""
    if label_text is None and uuid is None:
        raise ProximoError(
            "pbs_tape_media_destroy requires at least one of label_text/uuid to identify which "
            "media to destroy"
        )
    if label_text is not None:
        _check_label_text(label_text)
    if uuid is not None:
        _check_media_uuid(uuid)
    ident = f"label {label_text!r}" if label_text is not None else f"uuid {uuid!r}"
    force_note = f", force={bool(force)}" if force is not None else ""
    return Plan(
        action="pbs_tape_media_destroy",
        target=f"pbs/tape/media/destroy/{label_text or uuid}",
        change=f"DESTROY tape medium ({ident}{force_note}) — completely remove it from PBS's database",
        current={},
        blast_radius=[
            "PERMANENTLY removes this medium's record from PBS's media/media-set catalog — "
            "PBS's own description, verbatim: 'completely remove from database'. This does NOT "
            "erase the physical tape's bytes (unlike format-media), but PBS forgets the medium "
            "entirely: any backup/media-set bookkeeping referencing it is orphaned, and PBS will "
            "no longer recognize this physical cartridge unless it is re-inventoried from "
            "scratch. There is no undo.",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "irreversibly deletes a media catalog record — the HTTP verb is GET, but the effect "
            "is a permanent removal; verb is not the safety signal here",
        ],
        note=(
            "NO UNDO. Double-check pbs_tape_media_list/pbs_tape_media_content for what this "
            "medium currently holds before confirming — this tool does not check for you."
        ),
    )


def plan_tape_media_status_set(uuid: str, status: str | None = None) -> Plan:
    """Plan setting (or clearing) a medium's manual status override. RISK_MEDIUM. PURE — no API
    read (same reasoning as plan_tape_media_destroy)."""
    _check_media_uuid(uuid)
    if status is not None:
        _check_media_status(status)
    change_desc = f"set status to {status!r}" if status is not None else "CLEAR the manual status override"
    return Plan(
        action="pbs_tape_media_status_set",
        target=f"pbs/tape/media/list/{uuid}/status",
        change=f"{change_desc} for tape medium {uuid!r}",
        current={},
        blast_radius=[
            f"changes whether PBS considers medium {uuid!r} available for future writes — "
            "'retired'/'damaged' take it out of rotation (or correctly protect a bad tape); "
            "clearing the override (status omitted) reverts to PBS's own internally-managed "
            "writable/unknown state. Tape content is not touched either way.",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "changes future-write eligibility for a specific tape — reversible by calling this "
            "again, but a mistaken 'retired'/'damaged' reduces available media until corrected",
        ],
        note="No snapshot/undo primitive on this plane. Reversible via this same tool.",
    )


def plan_tape_media_move(label_text: str | None = None, uuid: str | None = None, vault_name: str | None = None) -> Plan:
    """Plan changing a tape's location bookkeeping. RISK_MEDIUM. PURE — no API read (same
    reasoning as plan_tape_media_destroy)."""
    if label_text is None and uuid is None:
        raise ProximoError(
            "pbs_tape_media_move requires at least one of label_text/uuid to identify which "
            "media to move"
        )
    if label_text is not None:
        _check_label_text(label_text)
    if uuid is not None:
        _check_media_uuid(uuid)
    if vault_name is not None:
        _check_tape_id(vault_name)
    ident = f"label {label_text!r}" if label_text is not None else f"uuid {uuid!r}"
    dest = f"vault {vault_name!r}" if vault_name is not None else "OFFLINE"
    return Plan(
        action="pbs_tape_media_move",
        target=f"pbs/tape/media/move/{label_text or uuid}",
        change=f"move tape medium ({ident}) location to {dest}",
        current={},
        blast_radius=[
            f"updates PBS's location bookkeeping for this medium to {dest} — does NOT physically "
            "move anything; a scheduled job or inventory operation expecting this medium to be "
            "online in a changer fails to find it (or vice versa) until the bookkeeping matches "
            "physical reality again. Omitting vault_name sets OFFLINE, NOT a no-op.",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "changes location metadata other tape operations rely on to find this medium",
        ],
        note="No snapshot/undo primitive on this plane. Reversible via this same tool.",
    )


# ---------------------------------------------------------------------------
# Plan factories — Tape backup jobs (config)
# ---------------------------------------------------------------------------

def plan_tape_backup_job_create(
    job_id: str,
    drive: str,
    pool: str,
    store: str,
    comment: str | None = None,
    eject_media: bool | None = None,
    export_media_set: bool | None = None,
    group_filter: list[str] | None = None,
    latest_only: bool | None = None,
    max_depth: int | None = None,
    notification_mode: str | None = None,
    notify_user: str | None = None,
    ns: str | None = None,
    schedule: str | None = None,
    worker_threads: int | None = None,
) -> Plan:
    """Plan creating a PBS tape backup job. RISK_LOW — additive config. PURE — no API read. Every
    optional field is validated here too (not just at execution) — plan-time validation parity."""
    _check_tape_id(job_id)
    _check_tape_id(drive)
    _check_pool_name(pool)
    _check_tape_id(store)
    extra_fields = _job_extra_fields(
        comment, eject_media, export_media_set, group_filter, latest_only, max_depth,
        notification_mode, notify_user, ns, schedule, worker_threads,
    )
    extra = [f"{k}={v!r}" for k, v in extra_fields.items()]
    extra_note = f" ({', '.join(extra)})" if extra else ""
    return Plan(
        action="pbs_tape_backup_job_create",
        target=f"pbs/config/tape-backup-job/{job_id}",
        change=(
            f"create PBS tape backup job {job_id!r} (drive={drive!r}, pool={pool!r}, "
            f"store={store!r}){extra_note}"
        ),
        current={},
        blast_radius=[
            f"adds a new scheduled tape backup job {job_id!r} — no existing job/pool/drive "
            "config is affected until its schedule (if any) fires or it is run manually",
        ],
        risk=RISK_LOW,
        risk_reasons=["additive config — creates a new tape backup job"],
        note=(
            "No snapshot primitive on this plane. Config is re-creatable — delete with "
            "pbs_tape_backup_job_delete and re-create to correct a mistake."
        ),
    )


def plan_tape_backup_job_update(
    api: PbsBackend,
    job_id: str,
    drive: str | None = None,
    pool: str | None = None,
    store: str | None = None,
    comment: str | None = None,
    eject_media: bool | None = None,
    export_media_set: bool | None = None,
    group_filter: list[str] | None = None,
    latest_only: bool | None = None,
    max_depth: int | None = None,
    notification_mode: str | None = None,
    notify_user: str | None = None,
    ns: str | None = None,
    schedule: str | None = None,
    worker_threads: int | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> Plan:
    """Plan updating a PBS tape backup job. CAPTURE: reads current config (REVIEWED_TRUSTED,
    operator-authored — safe to capture unredacted). Every optional field validated here too —
    plan-time validation parity."""
    job_id = _check_tape_id(job_id)
    if drive is not None:
        _check_tape_id(drive)
    if pool is not None:
        _check_pool_name(pool)
    if store is not None:
        _check_tape_id(store)
    extra_fields = _job_extra_fields(
        comment, eject_media, export_media_set, group_filter, latest_only, max_depth,
        notification_mode, notify_user, ns, schedule, worker_threads,
    )
    if digest is not None:
        _check_digest(digest)
    current = tape_backup_job_get(api, job_id)
    extra = [f"{k}={v!r}" for k, v in extra_fields.items()]
    if drive is not None:
        extra.append(f"drive={drive!r}")
    if pool is not None:
        extra.append(f"pool={pool!r}")
    if store is not None:
        extra.append(f"store={store!r}")
    # `is not None`, NOT truthiness — but delete=[] is REJECTED, not disclosed: httpx's form
    # encoding drops an empty-list value entirely, so a disclosed "delete=[]" would never match
    # what confirm=True actually sends (Wave 5b review finding 1, corrects the "established
    # convention" this comment previously described across this whole tape family).
    if delete is not None:
        extra.append(f"delete={_check_delete_list(delete)!r}")
    change_desc = ", ".join(extra) if extra else "no fields changed"
    return Plan(
        action="pbs_tape_backup_job_update",
        target=f"pbs/config/tape-backup-job/{job_id}",
        change=f"update PBS tape backup job {job_id!r}: {change_desc}",
        current=current,
        blast_radius=[
            f"tape backup job {job_id!r}: changes which drive/pool/store/schedule/filters this "
            "SCHEDULED job uses on its next automatic (or manual) run",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "changes behavior of an already-relied-upon scheduled automation, not merely additive",
        ],
        note=(
            "No snapshot primitive on this plane. Current config captured above — re-apply it "
            "manually (pbs_tape_backup_job_update) to revert."
        ),
    )


def plan_tape_backup_job_delete(api: PbsBackend, job_id: str) -> Plan:
    """Plan deleting a PBS tape backup job. CAPTURE: reads current config for honesty/restore
    material. RISK_MEDIUM — module docstring's RISK RATING: future automatic tape backups for
    this job's guests stop SILENTLY, no alert."""
    job_id = _check_tape_id(job_id)
    current = tape_backup_job_get(api, job_id)
    return Plan(
        action="pbs_tape_backup_job_delete",
        target=f"pbs/config/tape-backup-job/{job_id}",
        change=f"delete PBS tape backup job {job_id!r}",
        current=current,
        blast_radius=[
            f"removes tape backup job {job_id!r}'s config — future automatic tape backups for "
            "this job's schedule/guest-filter STOP running, silently (no error, no alert). "
            "Media/backup data already written to tape is untouched.",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "a scheduled job disappearing silently is a materially worse failure mode than a "
            "config identifier merely going stale — nothing surfaces the gap until someone "
            "notices backups stopped",
        ],
        note=(
            "No UNDO primitive on this plane. Config is re-creatable — re-create with "
            "pbs_tape_backup_job_create using the captured current config above to restore."
        ),
    )


def plan_tape_backup_job_run(job_id: str) -> Plan:
    """Plan manually running a preconfigured tape backup job. RISK_MEDIUM. PURE — no API read
    (does not auto-fetch the job's own config; check pbs_tape_backup_job_get yourself first)."""
    _check_tape_id(job_id)
    return Plan(
        action="pbs_tape_backup_job_run",
        target=f"pbs/tape/backup/{job_id}",
        change=f"run PBS tape backup job {job_id!r} manually, right now",
        current={},
        blast_radius=[
            f"triggers a real tape backup using job {job_id!r}'s CONFIGURED drive/pool/store/"
            "filters — the drive is busy for the duration and real data is written to tape",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["kicks off a real tape backup now, outside the normal schedule"],
        note=(
            "Schema oddity (module docstring fact #2): this endpoint returns null, unlike the "
            "one-off pbs_tape_backup which returns a UPID — outcome recorded as 'ok', not "
            "'submitted'. Check pbs_tape_backup_job_get first if unsure what this job will do."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — One-off backup + restore
# ---------------------------------------------------------------------------

def plan_tape_backup(
    drive: str,
    pool: str,
    store: str,
    eject_media: bool | None = None,
    export_media_set: bool | None = None,
    force_media_set: bool | None = None,
    group_filter: list[str] | None = None,
    latest_only: bool | None = None,
    max_depth: int | None = None,
    notification_mode: str | None = None,
    notify_user: str | None = None,
    ns: str | None = None,
    worker_threads: int | None = None,
) -> Plan:
    """Plan a one-off tape backup. RISK_MEDIUM — module docstring's binding fact: writes datastore
    contents to tape, drive busy. PURE — no API read. Every optional field validated here too —
    plan-time validation parity."""
    _check_tape_id(drive)
    _check_pool_name(pool)
    _check_tape_id(store)
    extra = []
    if eject_media is not None:
        extra.append(f"eject-media={bool(eject_media)}")
    if export_media_set is not None:
        extra.append(f"export-media-set={bool(export_media_set)}")
    if force_media_set is not None:
        extra.append(f"force-media-set={bool(force_media_set)}")
    if group_filter is not None:
        extra.append(f"group-filter={_check_group_filter_list(group_filter)!r}")
    if latest_only is not None:
        extra.append(f"latest-only={bool(latest_only)}")
    if max_depth is not None:
        extra.append(f"max-depth={_check_max_depth(max_depth)}")
    if notification_mode is not None:
        extra.append(f"notification-mode={_check_notification_mode(notification_mode)!r}")
    if notify_user is not None:
        extra.append(f"notify-user={_check_notify_user(notify_user)!r}")
    if ns is not None:
        extra.append(f"ns={_check_tape_ns(ns)!r}")
    if worker_threads is not None:
        extra.append(f"worker-threads={_check_worker_threads(worker_threads)}")
    extra_note = f" ({', '.join(extra)})" if extra else ""
    return Plan(
        action="pbs_tape_backup",
        target=f"pbs/tape/backup/{store}",
        change=f"back up datastore {store!r} to tape pool {pool!r} via drive {drive!r}{extra_note}",
        current={},
        blast_radius=[
            f"writes datastore {store!r}'s contents to tape via drive {drive!r} — the drive is "
            "busy for the duration; does not itself destroy any prior content on the target "
            "tape (that risk belongs to format-media/label-media, Wave 4c)",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["writes real data to tape and occupies the drive for the duration"],
        note=(
            "Async — returns a UPID. Use pbs_tasks_list to track completion. Check "
            "pbs_tape_pool_get/pbs_tape_drive_status first if unsure about pool policy or "
            "drive availability."
        ),
    )


def plan_tape_restore(
    drive: str,
    media_set: str,
    store: str,
    namespaces: list[str] | None = None,
    notification_mode: str | None = None,
    notify_user: str | None = None,
    owner: str | None = None,
    snapshots: list[str] | None = None,
) -> Plan:
    """Plan restoring data from a tape media-set. RISK_HIGH — module docstring's RISK RATING:
    the campaign's own 'MEDIUM-HIGH' resolved up (no 5th tier in this codebase's risk enum),
    writes into an existing datastore, auto-creates namespaces, undocumented overwrite semantics
    (Smoke-confirm). PURE — no API read. Every optional field validated here too — plan-time
    validation parity — AND every optional field is SURFACED in the change text (Wave 4d review
    finding 1: an earlier draft validated namespaces/owner/notify_user/notification_mode and then
    dropped them from the rendered plan — a namespace remap or ownership reassignment on the
    wave's own RISK_HIGH tool was invisible in the dry-run preview; mirrors plan_tape_backup's
    render-everything idiom, with namespaces and owner ALSO called out in blast_radius since they
    decide WHERE restored data lands and WHO owns it)."""
    _check_tape_id(drive)
    _check_media_set_ref(media_set)
    _check_store_mapping(store)
    extra = []
    if namespaces is not None:
        extra.append(f"namespaces={_check_namespace_mapping_list(namespaces)!r}")
    if notification_mode is not None:
        extra.append(f"notification-mode={_check_notification_mode(notification_mode)!r}")
    if notify_user is not None:
        extra.append(f"notify-user={_check_notify_user(notify_user)!r}")
    if owner is not None:
        extra.append(f"owner={_check_owner(owner)!r}")
    if snapshots is not None:
        _check_snapshot_list(snapshots)
    extra_note = f" ({', '.join(extra)})" if extra else ""
    scope = f"snapshots={snapshots!r}" if snapshots else "the WHOLE media-set"
    # WHERE the restored data lands: an explicit namespace remapping when given, otherwise PBS's
    # auto-created source-mirroring default — either way the plan says which one is in effect.
    where = (
        f"restored data lands per the EXPLICIT namespace remapping {namespaces!r} — each entry "
        "maps a source namespace recorded on tape onto a (possibly different) target namespace"
        if namespaces is not None
        else "no namespace remapping given — restored data lands in namespaces mirroring the "
             "source layout recorded on tape"
    )
    # WHO owns the restored snapshots afterward.
    who = (
        f"ownership of every restored snapshot is REASSIGNED to {owner!r}"
        if owner is not None
        else "no owner override given — restored snapshots keep PBS's default ownership behavior"
    )
    return Plan(
        action="pbs_tape_restore",
        # media_set is an open string (fact #5) — embedded via !r so an out-of-charset byte can
        # never ride raw into the target/ledger-display context (Wave 4d review finding 3).
        target=f"pbs/tape/restore/{media_set!r}",
        change=(
            f"restore {scope} from media-set {media_set!r} via drive {drive!r} into "
            f"{store!r}{extra_note}"
        ),
        current={},
        blast_radius=[
            f"WRITES into datastore mapping {store!r} — namespaces are AUTO-CREATED as needed "
            "(PBS's own description, verbatim: 'Namespaces will be automatically created if "
            "necessary'). PBS's schema does NOT state what happens if a target snapshot with "
            "the same type/id/time already exists at the destination — Smoke-confirm: this "
            "restore may overwrite, skip, or fail per-snapshot on a collision; verify against a "
            "live PBS before relying on either behavior.",
            where,
            who,
            "a media-set can span many snapshots across many namespaces — a single call's blast "
            "radius is not bounded to one guest/namespace the way a single-vmid PVE restore is",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "writes into an existing datastore, restructures its namespace tree, with "
            "undocumented overwrite semantics on a possibly-broad, multi-snapshot scope",
        ],
        note=(
            "Async — returns a UPID. Use pbs_tasks_list to track completion. Check "
            "pbs_tape_media_sets/pbs_tape_media_content first to see what this media-set "
            "actually contains before confirming."
        ),
    )
