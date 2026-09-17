"""PBS datastore-admin remainder — group management, datastore lifecycle, whole-datastore
prune, telemetry odds, and remote discovery (Wave 5d of the full-surface campaign).

ORIGIN: the Wave 5c adversarial review (`.scratch/sdd/wave-5c-review.md`, Findings 1+2) proved
Wave 5c's "PBS plane CLOSED" claim FALSE by diffing the live apidoc against every `(method,
path)` pair actually called across all pbs modules: 7 real mutations and 7+ real reads had zero
coverage and were on no exclusion list. This module builds that enumerated remainder — the
ACTUAL plane closer. Homed in its own module pair rather than `pbs.py` (`pbs.py` is ~1,475
lines and already carries the PbsBackend class + the core datastore ops; adding ~17 tools of
backend+plan code would push it past 2,200 — the same "already large" split reasoning Wave 2d
used to put `pbs_disks.py` beside `pbs_node.py`). Shared validators (`_check_store`,
`_check_namespace`, `_check_backup_type`, `_check_backup_id`, `_check_backup_time`) are
IMPORTED from `pbs.py` — the established shared-validator precedent (`pbs_admin.py` fact #8),
not fresh copies: these are the same fields on the same `/admin/datastore` plane, not
same-shaped fields on a different plane.

Schema truth: `.scratch/api-schemas-2026-07-15/wave5d-pbs-datastore-admin-schema.json`
(17 nodes extracted from the live PBS apidoc, pulled 2026-07-15).

Endpoint table (17 tools total — 9 read, 8 mutation):

  Group management:
    GET    /admin/datastore/{store}/groups       — pbs_groups_list        (read, ADVERSARIAL)
    DELETE /admin/datastore/{store}/groups       — pbs_group_delete       (MUTATION, HIGH)
    GET    /admin/datastore/{store}/group-notes  — pbs_group_notes_get    (read, ADVERSARIAL)
    PUT    /admin/datastore/{store}/group-notes  — pbs_group_notes_set    (MUTATION, LOW)
    POST   /admin/datastore/{store}/move-group   — pbs_group_move         (MUTATION, MEDIUM)
    GET    /admin/datastore/{store}/protected    — pbs_snapshot_protected_get (read)

  Datastore lifecycle + whole-datastore prune:
    POST /admin/datastore/{store}/mount            — pbs_datastore_mount      (MUTATION, MEDIUM)
    POST /admin/datastore/{store}/unmount          — pbs_datastore_unmount    (MUTATION, MEDIUM)
    POST /admin/datastore/{store}/move-namespace   — pbs_namespace_move       (MUTATION, HIGH)
    POST /admin/datastore/{store}/prune-datastore  — pbs_datastore_prune      (MUTATION, LOW dry-run / HIGH live)
    PUT  /admin/datastore/{store}/s3-refresh       — pbs_datastore_s3_refresh (MUTATION, MEDIUM)

  Telemetry odds:
    GET /admin/datastore/{store}/rrd               — pbs_datastore_rrd               (read)
    GET /admin/datastore/{store}/active-operations — pbs_datastore_active_operations (read)
    GET /status/datastore-usage                    — pbs_datastores_usage            (read)

  Remote discovery (the read-side of Wave 5c's pbs_pull/pbs_push — the review's own workflow
  point: pull/push required guessing remote-store/ns/group-filter blind):
    GET /config/remote/{name}/scan                       — pbs_remote_scan            (read, ADVERSARIAL)
    GET /config/remote/{name}/scan/{store}/groups        — pbs_remote_scan_groups     (read, ADVERSARIAL)
    GET /config/remote/{name}/scan/{store}/namespaces    — pbs_remote_scan_namespaces (read, ADVERSARIAL)

NOT BUILT: `GET /config/remote/{name}/scan/{store}` (bare, no further segment) is a
"Directory index." stub (`returns: null`) — the same shape as `/admin/prune/{id}` etc.
(pbs_admin.py NOT BUILT #3); a bare API-tree pointer to its `groups`/`namespaces` children.

SCHEMA-VERIFIED FACTS (binding on this build — from the live schema, not memory):

  1. **`DELETE /admin/datastore/{store}/groups` returns a synchronous STATS OBJECT** —
     `{removed-groups, removed-snapshots, protected-snapshots}` (all counters,
     `additionalProperties: false`) — NOT a UPID and NOT null. The bulk-destructive mutation on
     this plane is the one that completes synchronously and tells you exactly what died.
     Outcome is "ok"; the stats object rides back in `result` (a caller should read
     `removed-snapshots`/`protected-snapshots` to verify what actually happened).
  2. **`error-on-protected` (group delete) defaults TRUE upstream**: with the default, a group
     containing any protected snapshot makes the call FAIL (nothing about protection is
     bypassed). Setting it False changes the failure mode, not the protection: unprotected
     snapshots in the group are deleted, protected ones survive, and the call SUCCEEDS with
     `protected-snapshots > 0` — a partial delete a caller could easily misread as complete.
     Disclosed in the plan whenever False.
  3. **`POST .../mount`, `POST .../unmount`, `POST .../move-group`, `POST .../move-namespace`,
     `POST .../prune-datastore`, `PUT .../s3-refresh` ALL declare a UPID return** (full UPID
     pattern in the schema — genuinely async, unlike this campaign's many returns-null quirks).
     All six use the callable-outcome idiom anyway (`"submitted" if result else "ok"`) —
     schema-faithful when the UPID arrives, honest if a PBS version returns nothing.
  4. **`prune-datastore` is schema-distinct from the already-shipped single-group `prune`**
     (`pbs_prune`, `pbs.py`): the shipped endpoint scopes to ONE group (`backup-type` +
     `backup-id`, no recursion); `prune-datastore` has NO group scoping at all and instead takes
     `ns` + `max-depth` — it prunes EVERY group in the namespace tree per the retention policy,
     as an async task (UPID; the shipped group-form returns its decision list synchronously).
     It also accepts `keep-hourly`, which the group-form endpoint does not expose. The schema's
     own `dry-run` default is FALSE — **this tool deliberately flips the default to
     `dry_run=True`**, the exact safe-default flip the shipped `pbs_prune` already made (and
     Wave 4d's `update_status=False` flip): a caller must explicitly opt into deletion.
     When dry_run=False, `dry-run` is OMITTED from the wire payload (the schema default) rather
     than sent as an explicit 0 — one less param to mis-encode.
  5. **`move-namespace`'s `delete-source` defaults TRUE upstream** ("Remove the source namespace
     after moving all contents. Defaults to true.") — the source tree is REMOVED after the move
     unless the caller explicitly passes delete_source=False. Its `max-depth` also carries an
     upstream default of 7 (full recursion) — omitting it moves EVERYTHING under `ns`. Both
     defaults are disclosed in the plan even when unset. `ns` and `target-ns` are both REQUIRED;
     their shared pattern technically admits the empty string (root), but a ROOT-namespace move
     is meaningless — `ns` (the source) gets a stricter-than-schema non-empty rail mirroring
     `plan_namespace_delete`'s identical rail; `target-ns` MAY be empty (moving INTO the root is
     coherent).
  6. **`move-group`'s `merge-group` defaults TRUE upstream**: if the group already exists in the
     target namespace, snapshots are merged into it (requires matching ownership +
     non-overlapping snapshot times). Disclosed in the plan even when unset.
  7. **`GET .../protected` declares `returns: null`** despite "Query protection for a specific
     backup" — the familiar quirk. Classified REVIEWED_TRUSTED (NOT the media_status_get
     conservative-ADVERSARIAL default): unlike media-status (whose sibling media_list carries
     attacker-authored `label-text`, making free-text content plausible), this endpoint's OWN
     paired write-half (`PUT .../protected`, shipped as `pbs_snapshot_protected_set`) types the
     field it manages as a schema-typed BOOLEAN — the plausible return is that boolean, and no
     sibling on the protection plane carries free text. Argued, not defaulted.
  8. **`GET .../rrd` (datastore) mirrors `/nodes/{node}/rrd` exactly** (pbs_admin.py fact #13):
     `cf` ∈ {MAX, AVERAGE} + `timeframe` ∈ {hour, day, week, month, year, decade}, both
     REQUIRED, no server default, `returns: null` quirk — passed through best-effort as a dict.
  9. **`GET .../active-operations`'s schema description is "Read datastore stats"** — a
     copy-paste artifact from the rrd endpoint's description (same artifact class as pbs_s3.py
     fact #4's "Job ID."). Declares `returns: null`. Classified REVIEWED_TRUSTED, argued (not
     defaulted, per the media_status_get precedent's own bar): the endpoint's semantic domain is
     in-flight operation COUNTS, and every sibling on the datastore-status plane
     (`datastore_status`, `gc_status` — both long since REVIEWED_TRUSTED) is numeric
     server-authored telemetry; no plausible externally-authored free-text channel exists here,
     unlike media-status's label-text-carrying sibling.
 10. **The remote-scan family's namespace filter is spelled `namespace` on the wire — NOT
     `ns`** (`/config/remote/{name}/scan/{store}/groups`), diverging from every
     `/admin/datastore` sibling on this very plane. Forwarded under its schema name.
 11. **The remote-scan family returns REMOTE-authored content**: store names/comments/
     maintenance messages (scan), group ids + notes-derived comments (scan groups), namespace
     names + comments (scan namespaces) are all authored on the REMOTE PBS — whoever controls
     that remote controls these bytes. ADVERSARIAL per the `pbs_s3_list_buckets` precedent
     (externally-authored content over an operator-configured channel), which is itself the
     argued descendant of `pbs_snapshots_list`.
 12. **`GET /status/datastore-usage` is schema-typed** (`additionalProperties: false` items:
     avail/error/estimated-full-date/gc-status/…): server-computed capacity telemetry +
     operator-named stores. REVIEWED_TRUSTED, matching `pbs_datastores_list`/
     `pbs_datastore_status` exactly. Distinct from Wave 5b's `/status/metrics`
     (performance samples) — this is capacity + fill-date estimation.
 13. **`GET .../groups` (list) carries `backup-id` (no return-side charset guarantee beyond the
     request pattern), `owner`, and `comment` ("The first line from group notes" — free text)**
     — the same guest/operator-influenced content class as `pbs_snapshots_list` (ADVERSARIAL
     precedent, matched exactly). `group-notes` GET is the full free-text notes body — same
     class, ADVERSARIAL.

RISK RATING (module-specific reasoning):
  - **group_delete = RISK_HIGH** — bulk-destructive: one call deletes an entire backup group,
    i.e. EVERY snapshot in it (every recovery point for that guest/host in that namespace).
    Strictly more destructive than the shipped `pbs_snapshot_delete` (one snapshot) and the
    same class as `pbs_namespace_delete(delete_groups=True)` (RISK_HIGH, "equivalent to bulk
    snapshot deletion"). No undo.
  - **group_notes_set = RISK_LOW** — annotation metadata only; mirrors the shipped
    `pbs_snapshot_notes_set` (its direct single-snapshot sibling) including its
    CAPTURE-or-declare of the current notes.
  - **datastore_mount / datastore_unmount = RISK_MEDIUM** — availability-affecting, not
    data-destroying: unmount makes every job/backup targeting the datastore fail while it's
    unmounted (and aborts in-flight operations); mount is the reverse transition. Reversible by
    the inverse call.
  - **group_move = RISK_MEDIUM** — data-relocating, not destroying: the group's snapshots move
    to `target-ns` within the same datastore; sync/verify/prune jobs or ACL paths scoped to the
    OLD namespace silently stop seeing the group. merge-group (default true) can interleave the
    moved snapshots into an existing same-name group.
  - **namespace_move = RISK_HIGH** — a whole-TREE relocation: every child namespace and every
    group under `ns` (max-depth defaults to 7 = full recursion) moves, and the source namespace
    tree is then REMOVED (delete-source default true). Every job (sync/prune/verify/tape),
    ACL path, and pull/push target that references the old namespace path breaks or silently
    matches nothing afterward. Data itself survives at the target, but the blast radius is the
    widest of any non-deleting mutation on this plane.
  - **datastore_prune: dry_run=True → RISK_LOW, dry_run=False → RISK_HIGH** — mirrors the
    shipped `plan_prune` exactly (LOW = "no state change", NOT "safe"; a live run permanently
    deletes recovery points across the whole namespace tree per the policy — and with NO keep-*
    set, ALL prunable snapshots are candidates).
  - **datastore_s3_refresh = RISK_MEDIUM** — re-syncs the LOCAL cache store from the S3 backend:
    local cache contents are overwritten/reconciled from the remote object store; the datastore
    passes through an `s3-refresh` maintenance mode (the scan schema's own maintenance enum
    names it) while running, affecting availability.

Taint:
  - **pbs_groups_list / pbs_group_notes_get = ADVERSARIAL** (fact #13 — pbs_snapshots_list
    precedent: guest-influenced backup ids + notes free text).
  - **pbs_remote_scan / pbs_remote_scan_groups / pbs_remote_scan_namespaces = ADVERSARIAL**
    (fact #11 — remote-authored content, pbs_s3_list_buckets precedent).
  - **pbs_snapshot_protected_get = REVIEWED_TRUSTED** (fact #7 — argued via the paired
    write-half's schema-typed boolean, against the media_status_get conservative default).
  - **pbs_datastore_rrd / pbs_datastore_active_operations / pbs_datastores_usage =
    REVIEWED_TRUSTED** (facts #8/#9/#12 — numeric/typed server telemetry precedents).
  - **All 8 mutations = REVIEWED_TRUSTED**: group_delete returns a closed-shape counter object
    (fact #1); group_notes_set returns null; the other six return opaque UPIDs (fact #3) —
    no externally-authored content channel in any of them.

VERIFIED live shapes: None — all backend functions carry "Smoke-confirm:" comments; every
shape here is schema-derived, not live-proven.
"""

from __future__ import annotations

import re

from .backends import ProximoError
from .pbs import (
    PbsBackend,
    _check_backup_id,
    _check_backup_time,
    _check_backup_type,
    _check_namespace,
    _check_store,
)
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators (module-local; shared /admin/datastore field validators are imported from pbs.py)
# ---------------------------------------------------------------------------

# Remote ID (the remote-scan family's {name} path param): the live schema's own
# `^[A-Za-z0-9_][A-Za-z0-9._-]*$`, 3-32 chars — NOT pbs.py's `_check_store` shape (that one
# disallows dots/leading underscore and allows 64 chars; a genuinely different field). Kept as
# this module's own copy of the id shape per the per-module convention (pbs_admin.py/_ID_RE etc.).
_REMOTE_NAME_RE = re.compile(r"^(?:[A-Za-z0-9_][A-Za-z0-9._\-]*)\Z")

# RRD enums — byte-identical to pbs_admin.py's node-rrd enums (fact #8), kept as this module's
# own copy per the per-module convention (a datastore-telemetry field, not a node one).
_VALID_CF = frozenset({"MAX", "AVERAGE"})
_VALID_RRD_TIMEFRAMES = frozenset({"hour", "day", "week", "month", "year", "decade"})


def _check_remote_name(value: str) -> str:
    s = str(value)
    if not (3 <= len(s) <= 32) or not _REMOTE_NAME_RE.match(s):
        raise ProximoError(
            f"invalid remote name: {value!r} (must start alnum/underscore, then alnum/./_/-, "
            "3-32 chars)"
        )
    return s


def _check_cf(value: str) -> str:
    s = str(value)
    if s not in _VALID_CF:
        raise ProximoError(f"invalid cf: {value!r} (expected one of {sorted(_VALID_CF)})")
    return s


def _check_rrd_timeframe(value: str) -> str:
    s = str(value)
    if s not in _VALID_RRD_TIMEFRAMES:
        raise ProximoError(
            f"invalid timeframe: {value!r} (expected one of {sorted(_VALID_RRD_TIMEFRAMES)})"
        )
    return s


def _check_max_depth(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid max_depth: {value!r} (must be an integer)") from exc
    if not (0 <= n <= 7):
        raise ProximoError(f"invalid max_depth: {value!r} — must be 0-7")
    return n


def _check_keep(value, field: str) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid {field}: {value!r} (must be an integer)") from exc
    if n < 1:
        raise ProximoError(f"invalid {field}: {value!r} — must be >= 1 per the schema")
    return n


def _required_backup_type(backup_type: str) -> str:
    """`_check_backup_type` (pbs.py) admits None (optional-filter call sites); every endpoint in
    this module that takes backup_type REQUIRES it — enforce non-None here."""
    checked = _check_backup_type(backup_type)
    if checked is None:
        raise ProximoError("backup_type is required (vm, ct, or host)")
    return checked


def _required_backup_id(backup_id: str) -> str:
    checked = _check_backup_id(backup_id)
    if checked is None:
        raise ProximoError("backup_id is required")
    return checked


def _group_params(backup_type: str, backup_id: str, ns: str | None) -> dict:
    """The shared {backup-type, backup-id[, ns]} triple every group-scoped endpoint takes."""
    params: dict = {
        "backup-type": _required_backup_type(backup_type),
        "backup-id": _required_backup_id(backup_id),
    }
    ns = _check_namespace(ns)
    if ns is not None:
        params["ns"] = ns
    return params


# ---------------------------------------------------------------------------
# Backend functions — group reads
# ---------------------------------------------------------------------------

def groups_list(api: PbsBackend, store: str, ns: str | None = None) -> list[dict]:
    """GET /admin/datastore/{store}/groups — list backup groups (backup-type/backup-id/
    backup-count/last-backup/owner/files/comment). ADVERSARIAL (module docstring fact #13 —
    pbs_snapshots_list precedent). Smoke-confirm: response shape."""
    store = _check_store(store)
    params: dict = {}
    ns = _check_namespace(ns)
    if ns is not None:
        params["ns"] = ns
    return api._get(f"/admin/datastore/{store}/groups", params=params) or []


def groups_list_sighted(api: PbsBackend, store: str, ns: str | None = None) -> list[dict]:
    """`groups_list`, refusing an EMPTY view from an owner-filtered token (see
    pbs.datastore_blind_reason); non-empty returns as-is, sighted-empty returns []."""
    from .pbs import datastore_blind_reason
    groups = groups_list(api, store, ns)
    if groups:
        return groups
    reason = datastore_blind_reason(api, store, ns)
    if reason:
        raise ProximoError(reason)
    return []


def group_notes_get(
    api: PbsBackend, store: str, backup_type: str, backup_id: str, ns: str | None = None,
) -> str:
    """GET /admin/datastore/{store}/group-notes — the full free-text notes body for a backup
    GROUP (distinct from the shipped snapshot-level notes). ADVERSARIAL (free text).
    Schema declares returns:null — best-effort passthrough as a string. Smoke-confirm: shape."""
    store = _check_store(store)
    params = _group_params(backup_type, backup_id, ns)
    return api._get(f"/admin/datastore/{store}/group-notes", params=params) or ""


def snapshot_protected_get(
    api: PbsBackend,
    store: str,
    backup_type: str,
    backup_id: str,
    backup_time: int,
    ns: str | None = None,
) -> object:
    """GET /admin/datastore/{store}/protected — the READ half of the shipped
    pbs_snapshot_protected_set. Schema declares returns:null (fact #7) — the plausible return is
    the protection boolean; passed through as-is. Smoke-confirm: shape."""
    store = _check_store(store)
    params = _group_params(backup_type, backup_id, ns)
    params["backup-time"] = _check_backup_time(backup_time)
    # dict ordering for exact-payload tests: backup-type, backup-id, backup-time[, ns] — rebuild
    # so ns (if any) sorts after backup-time, matching the shipped protected_set's own ordering.
    ordered = {"backup-type": params["backup-type"], "backup-id": params["backup-id"],
               "backup-time": params["backup-time"]}
    if "ns" in params:
        ordered["ns"] = params["ns"]
    return api._get(f"/admin/datastore/{store}/protected", params=ordered)


def datastore_rrd(api: PbsBackend, store: str, cf: str, timeframe: str) -> dict:
    """GET /admin/datastore/{store}/rrd — datastore stats telemetry. cf/timeframe both REQUIRED
    (no server default — fact #8, mirrors pbs_node_rrd). returns:null quirk — best-effort dict.
    REVIEWED_TRUSTED (rrddata precedent). Smoke-confirm: real shape."""
    store = _check_store(store)
    params = {"cf": _check_cf(cf), "timeframe": _check_rrd_timeframe(timeframe)}
    return api._get(f"/admin/datastore/{store}/rrd", params=params) or {}


def datastore_active_operations(api: PbsBackend, store: str) -> dict:
    """GET /admin/datastore/{store}/active-operations — in-flight operation counts for a
    datastore. Schema declares returns:null AND its description is a copy-paste artifact
    ("Read datastore stats" — fact #9); best-effort dict. REVIEWED_TRUSTED (argued, fact #9).
    Smoke-confirm: real shape (expected read/write counters)."""
    store = _check_store(store)
    return api._get(f"/admin/datastore/{store}/active-operations") or {}


def datastores_usage(api: PbsBackend) -> list[dict]:
    """GET /status/datastore-usage — capacity usage + full-date estimates for every datastore
    (avail/error/estimated-full-date/gc-status per store). Distinct from /status/metrics
    (Wave 5b — performance samples). REVIEWED_TRUSTED (fact #12). Smoke-confirm: shape."""
    return api._get("/status/datastore-usage") or []


# ---------------------------------------------------------------------------
# Backend functions — remote discovery (the read-side of pbs_pull/pbs_push)
# ---------------------------------------------------------------------------

def remote_scan(api: PbsBackend, name: str) -> list[dict]:
    """GET /config/remote/{name}/scan — list the datastores accessible on a configured remote.
    ADVERSARIAL (fact #11 — remote-authored store names/comments/maintenance messages).
    Smoke-confirm: response shape."""
    name = _check_remote_name(name)
    return api._get(f"/config/remote/{name}/scan") or []


def remote_scan_groups(
    api: PbsBackend, name: str, store: str, namespace: str | None = None,
) -> list[dict]:
    """GET /config/remote/{name}/scan/{store}/groups — list backup groups on a remote's
    datastore, BEFORE pulling from / pushing to it. The namespace filter is spelled `namespace`
    on the wire, NOT `ns` (fact #10). ADVERSARIAL (fact #11). Smoke-confirm: response shape."""
    name = _check_remote_name(name)
    store = _check_store(store)
    params: dict = {}
    namespace = _check_namespace(namespace)
    if namespace is not None:
        params["namespace"] = namespace
    return api._get(f"/config/remote/{name}/scan/{store}/groups", params=params) or []


def remote_scan_namespaces(api: PbsBackend, name: str, store: str) -> list[dict]:
    """GET /config/remote/{name}/scan/{store}/namespaces — list namespaces on a remote's
    datastore. ADVERSARIAL (fact #11). Smoke-confirm: response shape."""
    name = _check_remote_name(name)
    store = _check_store(store)
    return api._get(f"/config/remote/{name}/scan/{store}/namespaces") or []


# ---------------------------------------------------------------------------
# Backend functions — mutations
# ---------------------------------------------------------------------------

def group_delete(
    api: PbsBackend,
    store: str,
    backup_type: str,
    backup_id: str,
    ns: str | None = None,
    error_on_protected: bool | None = None,
) -> dict:
    """DELETE /admin/datastore/{store}/groups — delete a backup group INCLUDING ALL SNAPSHOTS.
    Returns a synchronous stats object {removed-groups, removed-snapshots, protected-snapshots}
    (fact #1 — not a UPID, not null). error_on_protected default TRUE upstream (fact #2).
    MUTATION — confirm-gated + audited at the server layer."""
    store = _check_store(store)
    params = _group_params(backup_type, backup_id, ns)
    if error_on_protected is not None:
        params["error-on-protected"] = bool(error_on_protected)
    return api._delete(f"/admin/datastore/{store}/groups", params=params) or {}


def group_notes_set(
    api: PbsBackend,
    store: str,
    backup_type: str,
    backup_id: str,
    notes: str,
    ns: str | None = None,
) -> None:
    """PUT /admin/datastore/{store}/group-notes — set the notes body for a backup group
    ("A multiline text." per the schema — no charset constraint given; passed through).
    Returns null. MUTATION — confirm-gated + audited at the server layer."""
    store = _check_store(store)
    data = _group_params(backup_type, backup_id, ns)
    # re-order so notes sits after the group triple but before ns, matching the shipped
    # snapshot_notes_set's own dict-build order (backup fields, then notes, then ns).
    ns_val = data.pop("ns", None)
    data["notes"] = str(notes)
    if ns_val is not None:
        data["ns"] = ns_val
    api._put(f"/admin/datastore/{store}/group-notes", data)


def datastore_mount(api: PbsBackend, store: str) -> str:
    """POST /admin/datastore/{store}/mount — mount a removable datastore. Returns a UPID
    (fact #3). MUTATION — confirm-gated + audited at the server layer."""
    store = _check_store(store)
    return api._post(f"/admin/datastore/{store}/mount") or ""


def datastore_unmount(api: PbsBackend, store: str) -> str:
    """POST /admin/datastore/{store}/unmount — unmount the removable device backing a
    datastore. Returns a UPID (fact #3). MUTATION — confirm-gated + audited at the server
    layer."""
    store = _check_store(store)
    return api._post(f"/admin/datastore/{store}/unmount") or ""


def datastore_s3_refresh(api: PbsBackend, store: str) -> str:
    """PUT /admin/datastore/{store}/s3-refresh — refresh datastore contents from S3 into the
    local cache store. Returns a UPID (fact #3). MUTATION — confirm-gated + audited at the
    server layer."""
    store = _check_store(store)
    return api._put(f"/admin/datastore/{store}/s3-refresh") or ""


def group_move(
    api: PbsBackend,
    store: str,
    backup_type: str,
    backup_id: str,
    ns: str | None = None,
    target_ns: str | None = None,
    merge_group: bool | None = None,
) -> str:
    """POST /admin/datastore/{store}/move-group — move a backup group to a different namespace
    within the same datastore. merge-group defaults TRUE upstream (fact #6). Returns a UPID
    (fact #3). MUTATION — confirm-gated + audited at the server layer."""
    store = _check_store(store)
    data = _group_params(backup_type, backup_id, ns)
    target_checked = _check_namespace(target_ns)
    if target_checked is not None:
        data["target-ns"] = target_checked
    if merge_group is not None:
        data["merge-group"] = bool(merge_group)
    return api._post(f"/admin/datastore/{store}/move-group", data) or ""


def namespace_move(
    api: PbsBackend,
    store: str,
    ns: str,
    target_ns: str,
    delete_source: bool | None = None,
    max_depth: int | None = None,
    merge_groups: bool | None = None,
) -> str:
    """POST /admin/datastore/{store}/move-namespace — move a namespace INCLUDING ALL CHILD
    NAMESPACES AND GROUPS to a new location. delete-source defaults TRUE upstream, max-depth
    defaults 7 = full recursion (fact #5). Returns a UPID (fact #3). MUTATION — confirm-gated +
    audited at the server layer."""
    store = _check_store(store)
    ns_checked = _check_namespace(ns)
    if not ns_checked:
        # Stricter-than-schema rail mirroring plan_namespace_delete: the root namespace cannot
        # be relocated (module docstring fact #5).
        raise ProximoError("source namespace to move must not be empty (the root cannot move)")
    target_checked = _check_namespace(target_ns)
    if target_checked is None:
        raise ProximoError("target_ns is required (empty string = the root namespace)")
    data: dict = {"ns": ns_checked, "target-ns": target_checked}
    if delete_source is not None:
        data["delete-source"] = bool(delete_source)
    if max_depth is not None:
        data["max-depth"] = _check_max_depth(max_depth)
    if merge_groups is not None:
        data["merge-groups"] = bool(merge_groups)
    return api._post(f"/admin/datastore/{store}/move-namespace", data) or ""


def datastore_prune(
    api: PbsBackend,
    store: str,
    keep_last: int | None = None,
    keep_hourly: int | None = None,
    keep_daily: int | None = None,
    keep_weekly: int | None = None,
    keep_monthly: int | None = None,
    keep_yearly: int | None = None,
    ns: str | None = None,
    max_depth: int | None = None,
    dry_run: bool = True,
) -> str:
    """POST /admin/datastore/{store}/prune-datastore — prune EVERY group in the datastore/
    namespace tree per the retention policy (schema-distinct from the shipped single-group
    pbs_prune — fact #4). dry_run defaults TRUE here (deliberate safe-default flip; the
    schema's own default is false); when False, dry-run is OMITTED from the wire (the schema
    default), never sent as 0. Returns a UPID (fact #3). MUTATION — confirm-gated + audited at
    the server layer."""
    store = _check_store(store)
    data: dict = {}
    for py_val, wire in (
        (keep_last, "keep-last"), (keep_hourly, "keep-hourly"), (keep_daily, "keep-daily"),
        (keep_weekly, "keep-weekly"), (keep_monthly, "keep-monthly"),
        (keep_yearly, "keep-yearly"),
    ):
        if py_val is not None:
            data[wire] = _check_keep(py_val, wire.replace("-", "_"))
    ns_checked = _check_namespace(ns)
    if ns_checked is not None:
        data["ns"] = ns_checked
    if max_depth is not None:
        data["max-depth"] = _check_max_depth(max_depth)
    if dry_run:
        data["dry-run"] = True
    return api._post(f"/admin/datastore/{store}/prune-datastore", data) or ""


# ---------------------------------------------------------------------------
# Plan factories
# ---------------------------------------------------------------------------

def _group_desc(backup_type: str, backup_id: str, ns: str | None, store: str) -> str:
    ns_note = f" in namespace '{ns}'" if ns else ""
    return f"group {backup_type}/{backup_id}{ns_note} in datastore '{store}'"


def plan_group_delete(
    store: str,
    backup_type: str,
    backup_id: str,
    ns: str | None = None,
    error_on_protected: bool | None = None,
) -> Plan:
    """Plan deleting an ENTIRE backup group (all snapshots). RISK_HIGH — bulk-destructive, the
    same class as pbs_namespace_delete(delete_groups=True). PURE — deliberately does NOT
    auto-CAPTURE the ADVERSARIAL-classified groups/snapshots listing into the plan (the Wave 4c
    no-auto-taint precedent); the note directs the caller to check pbs_groups_list /
    pbs_snapshots_list themselves first."""
    store = _check_store(store)
    bt = _required_backup_type(backup_type)
    bid = _required_backup_id(backup_id)
    ns = _check_namespace(ns)
    desc = _group_desc(bt, bid, ns, store)

    blast = [
        f"PERMANENTLY DELETES {desc} — the WHOLE group: ALL snapshots (every recovery point "
        "for this guest/host in this namespace), not one snapshot; strictly more destructive "
        "than pbs_snapshot_delete",
        "no undo — deleted snapshots cannot be recovered",
    ]
    if error_on_protected is False:
        blast.append(
            "error_on_protected=False: protected snapshots survive but every UNPROTECTED "
            "snapshot in the group is deleted and the call SUCCEEDS as a PARTIAL delete — "
            "check the returned protected-snapshots counter, a nonzero value means the group "
            "still exists with only its protected snapshots left"
        )
    else:
        blast.append(
            "error_on_protected defaults true: the call FAILS (deleting nothing further) if "
            "the group contains any protected snapshot"
        )

    return Plan(
        action="pbs_group_delete",
        target=f"pbs/datastore/{store}/groups/{bt}/{bid}" + (f"/{ns}" if ns else ""),
        change=f"DELETE ENTIRE backup {desc} including ALL its snapshots",
        current={},
        blast_radius=blast,
        risk=RISK_HIGH,
        risk_reasons=[
            "bulk-destructive: one call deletes every snapshot in the group — the recovery "
            "points ARE the undo substrate; no rollback exists",
        ],
        note=(
            "Check pbs_groups_list (snapshot count per group) and pbs_snapshots_list (the "
            "individual snapshots) BEFORE confirming — this plan deliberately does not pull "
            "that content in itself. Returns a synchronous stats object "
            "{removed-groups, removed-snapshots, protected-snapshots} — verify it after."
        ),
    )


def plan_group_notes_set(
    api: PbsBackend,
    store: str,
    backup_type: str,
    backup_id: str,
    notes: str,
    ns: str | None = None,
) -> Plan:
    """Plan setting a backup GROUP's notes. RISK_LOW; CAPTURE-or-declare of the current notes —
    mirrors the shipped plan_snapshot_notes_set (its direct snapshot-level sibling) exactly."""
    store = _check_store(store)
    bt = _required_backup_type(backup_type)
    bid = _required_backup_id(backup_id)
    ns = _check_namespace(ns)
    desc = _group_desc(bt, bid, ns, store)

    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current_notes = group_notes_get(api, store, bt, bid, ns)
        if current_notes:
            current = {"notes": current_notes}
    except Exception:
        complete = False
        note_capture = " Could not capture current notes — no guided revert available."

    return Plan(
        action="pbs_group_notes_set",
        target=f"pbs/datastore/{store}/group-notes/{bt}/{bid}" + (f"/{ns}" if ns else ""),
        change=f"set notes on backup {desc}",
        current=current,
        blast_radius=[
            f"annotation on {desc} — does not affect backup data, retention, or protection "
            "(the first line becomes the group's 'comment' in listings)",
        ],
        risk=RISK_LOW,
        risk_reasons=["annotation only — no backup data, retention, or protection is changed"],
        complete=complete,
        note="Revert by re-applying the captured notes with pbs_group_notes_set." + note_capture,
    )


def plan_datastore_mount(store: str) -> Plan:
    """Plan mounting a removable datastore. RISK_MEDIUM — availability transition. PURE."""
    store = _check_store(store)
    return Plan(
        action="pbs_datastore_mount",
        target=f"pbs/datastore/{store}/mount",
        change=f"mount removable datastore '{store}'",
        current={},
        blast_radius=[
            f"datastore '{store}' becomes available — scheduled jobs with run-on-mount fire, "
            "and backups/syncs targeting it start succeeding again",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "availability transition on a whole datastore — requires Datastore.Modify AND "
            "Sys.Modify on system/disks per PBS's own permission model",
        ],
        note="Async — returns a UPID; track with pbs_tasks_list. Reverse with pbs_datastore_unmount.",
    )


def plan_datastore_unmount(store: str) -> Plan:
    """Plan unmounting a removable datastore's backing device. RISK_MEDIUM. PURE."""
    store = _check_store(store)
    return Plan(
        action="pbs_datastore_unmount",
        target=f"pbs/datastore/{store}/unmount",
        change=f"unmount the removable device backing datastore '{store}'",
        current={},
        blast_radius=[
            f"datastore '{store}' becomes UNAVAILABLE — in-flight operations are aborted and "
            "every backup/sync/verify/prune job targeting it fails until re-mounted",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "makes a whole datastore unavailable and aborts its in-flight operations — "
            "no data is destroyed, but every dependent job fails while unmounted",
        ],
        note=(
            "Async — returns a UPID; track with pbs_tasks_list. Check "
            "pbs_datastore_active_operations first for in-flight reads/writes. Reverse with "
            "pbs_datastore_mount."
        ),
    )


def plan_datastore_s3_refresh(store: str) -> Plan:
    """Plan refreshing a datastore's local cache from its S3 backend. RISK_MEDIUM. PURE."""
    store = _check_store(store)
    return Plan(
        action="pbs_datastore_s3_refresh",
        target=f"pbs/datastore/{store}/s3-refresh",
        change=f"refresh datastore '{store}' contents from S3 into the local cache store",
        current={},
        blast_radius=[
            f"the LOCAL cache store for '{store}' is overwritten/reconciled from the S3 "
            "backend; the datastore passes through 's3-refresh' maintenance mode while the "
            "task runs (PBS's own maintenance-mode enum names this state), affecting "
            "availability for the duration",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "rewrites the local cache from the remote object store and puts the datastore "
            "into a maintenance mode while running",
        ],
        note="Async — returns a UPID; track with pbs_tasks_list. No undo — the cache is rebuilt.",
    )


def plan_group_move(
    store: str,
    backup_type: str,
    backup_id: str,
    ns: str | None = None,
    target_ns: str | None = None,
    merge_group: bool | None = None,
) -> Plan:
    """Plan moving a backup group to a different namespace within the same datastore.
    RISK_MEDIUM — data-relocating, not destroying. PURE. Disclosure: EVERY where-data-lands
    param (source ns, target ns, merge behavior incl. the upstream default) is named."""
    store = _check_store(store)
    bt = _required_backup_type(backup_type)
    bid = _required_backup_id(backup_id)
    ns = _check_namespace(ns)
    target_checked = _check_namespace(target_ns)
    src_desc = f"'{ns}'" if ns else "the root namespace"
    dst_desc = f"'{target_checked}'" if target_checked else "the root namespace"

    merge_note = (
        "merge_group NOT set — upstream default TRUE: if the group already exists in the "
        "target namespace, snapshots are MERGED into it (requires matching ownership and "
        "non-overlapping snapshot times)"
        if merge_group is None else
        f"merge_group={merge_group}: "
        + ("existing same-name target group gets the moved snapshots merged in"
           if merge_group else "the move FAILS if the group already exists in the target")
    )

    return Plan(
        action="pbs_group_move",
        target=f"pbs/datastore/{store}/move-group/{bt}/{bid}",
        change=(
            f"move backup group {bt}/{bid} in datastore '{store}' from {src_desc} "
            f"to {dst_desc}"
        ),
        current={},
        blast_radius=[
            f"group {bt}/{bid} relocates from {src_desc} to {dst_desc} within '{store}' — "
            "sync/verify/prune jobs, ACL paths, and pull/push targets scoped to the OLD "
            "namespace silently stop seeing this group",
            merge_note,
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "data-relocating, not destroying — but namespace-scoped jobs and permissions "
            "referencing the old location silently stop matching",
        ],
        note=(
            "Async — returns a UPID; track with pbs_tasks_list. Reverse by moving the group "
            "back (a second pbs_group_move)."
        ),
    )


def plan_namespace_move(
    store: str,
    ns: str,
    target_ns: str,
    delete_source: bool | None = None,
    max_depth: int | None = None,
    merge_groups: bool | None = None,
) -> Plan:
    """Plan moving a WHOLE namespace tree. RISK_HIGH — the widest-blast-radius non-deleting
    mutation on this plane (module docstring's RISK RATING). PURE. Disclosure: delete-source
    (upstream default TRUE) and max-depth (upstream default 7 = full recursion) are named even
    when unset."""
    store = _check_store(store)
    ns_checked = _check_namespace(ns)
    if not ns_checked:
        raise ProximoError("source namespace to move must not be empty (the root cannot move)")
    target_checked = _check_namespace(target_ns)
    if target_checked is None:
        raise ProximoError("target_ns is required (empty string = the root namespace)")
    if max_depth is not None:
        _check_max_depth(max_depth)
    dst_desc = f"'{target_checked}'" if target_checked else "the root namespace"

    depth_note = (
        "max_depth NOT set — upstream default 7 (FULL recursion): every child namespace and "
        "group under the source moves"
        if max_depth is None else
        f"max_depth={max_depth}: namespaces/groups down to {max_depth} level(s) move"
    )
    if delete_source is None or delete_source:
        source_note = (
            "the SOURCE namespace tree is REMOVED after the move"
            + (" (delete_source NOT set — upstream default TRUE)" if delete_source is None else
               " (delete_source=True)")
        )
    else:
        source_note = "delete_source=False: the (now-empty) source namespace tree is kept, not removed"
    merge_note = (
        "merge_groups NOT set — upstream default TRUE: same-name groups already in the target "
        "get the moved snapshots merged in (requires matching ownership + non-overlapping "
        "snapshot times)"
        if merge_groups is None else
        f"merge_groups={merge_groups}"
    )

    return Plan(
        action="pbs_namespace_move",
        target=f"pbs/datastore/{store}/move-namespace/{ns_checked}",
        change=(
            f"move namespace '{ns_checked}' (including child namespaces and groups) in "
            f"datastore '{store}' to {dst_desc}"
        ),
        current={},
        blast_radius=[
            f"the WHOLE tree under '{ns_checked}' relocates to {dst_desc} — {depth_note}",
            source_note,
            merge_note,
            "every job (sync/prune/verify/tape-backup), ACL path, and pull/push target that "
            "references the old namespace path breaks or silently matches nothing afterward",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "whole-tree relocation with source removal by default — data survives at the "
            "target, but every namespace-scoped reference (jobs, permissions, sync targets) "
            "to the old path is silently invalidated",
        ],
        note=(
            "Async — returns a UPID; track with pbs_tasks_list. No single-call undo — "
            "reversing requires a second move plus re-pointing anything that referenced the "
            "old path in the interim."
        ),
    )


def plan_datastore_prune(
    store: str,
    keep_last: int | None = None,
    keep_hourly: int | None = None,
    keep_daily: int | None = None,
    keep_weekly: int | None = None,
    keep_monthly: int | None = None,
    keep_yearly: int | None = None,
    ns: str | None = None,
    max_depth: int | None = None,
    dry_run: bool = True,
) -> Plan:
    """Plan a WHOLE-DATASTORE prune (schema-distinct from the shipped single-group pbs_prune —
    module docstring fact #4). dry_run=True → RISK_LOW (preview); dry_run=False → RISK_HIGH
    (deletes recovery points across the whole namespace tree). PURE. Mirrors plan_prune's
    honesty framing verbatim in spirit."""
    store = _check_store(store)
    ns = _check_namespace(ns)
    if max_depth is not None:
        _check_max_depth(max_depth)

    policy_parts = []
    for label, val in (
        ("keep-last", keep_last), ("keep-hourly", keep_hourly), ("keep-daily", keep_daily),
        ("keep-weekly", keep_weekly), ("keep-monthly", keep_monthly),
        ("keep-yearly", keep_yearly),
    ):
        if val is not None:
            policy_parts.append(f"{label}={val}")
    policy_str = ", ".join(policy_parts) if policy_parts else "(no keep policy set — ALL may be pruned)"
    scope = f"datastore '{store}'" + (f" namespace '{ns}'" if ns else " (root namespace)")
    depth_str = (
        f"max_depth={max_depth}" if max_depth is not None
        else "max_depth not set (automatic full recursion)"
    )

    if dry_run:
        return Plan(
            action="pbs_datastore_prune",
            target=f"pbs/datastore/{store}/prune-datastore",
            change=(
                f"whole-datastore prune preview (dry-run) on {scope}, {depth_str} — "
                f"policy: {policy_str}"
            ),
            current={},
            blast_radius=[
                "DRY RUN — preview only; NO backups will be deleted",
                f"shows what WOULD be pruned across EVERY group in {scope} ({depth_str}) "
                f"under policy: {policy_str} — unlike pbs_prune, this is not scoped to one group",
                "to execute: re-call with dry_run=False (that is RISK_HIGH)",
            ],
            risk=RISK_LOW,
            risk_reasons=["dry_run=True — no state change; the task reports decisions without deleting"],
            note=(
                "LOW means 'does not change state', NOT 'safe'. Async — returns a UPID; the "
                "decisions land in the task log (pbs_tasks_list). This tool's dry_run defaults "
                "True — a deliberate flip of the schema's own false default."
            ),
        )
    return Plan(
        action="pbs_datastore_prune",
        target=f"pbs/datastore/{store}/prune-datastore",
        change=(
            f"EXECUTE whole-datastore prune on {scope}, {depth_str} — policy: {policy_str}"
        ),
        current={},
        blast_radius=[
            f"PERMANENTLY DELETES backup snapshots across EVERY group in {scope} "
            f"({depth_str}) — the whole namespace tree, not one group (that narrower "
            "operation is pbs_prune)",
            f"retention policy: {policy_str}",
            "deleted backups are RECOVERY POINTS — they cannot be recovered; no undo",
            "run with dry_run=True first to preview the decisions in the task log",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "prune with dry_run=False DELETES backup snapshots permanently, across every "
            "group in scope — the recovery points are the undo substrate itself",
        ],
        note=(
            "Async — returns a UPID; track with pbs_tasks_list. GC (pbs_gc_start) is needed "
            "afterward to actually reclaim the freed disk space."
        ),
    )
