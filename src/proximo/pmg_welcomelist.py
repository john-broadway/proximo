"""PMG global SMTP welcomelist plane (Wave 8b, full-surface campaign,
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 8 decomposition"). Separate module from
`proximo.pmg` — the plane-per-module precedent Wave 7 established (sdn_objects.py/sdn_routing.py/
sdn_fabrics.py/sdn_firewall.py alongside network.py) — this family has NO `ogroup` nesting concept
at all (Fact #4 below), a real structural divergence from every ruledb who/what/when family that
would otherwise have made it an awkward fit inside `pmg.py`'s own W-marker sequence.

Schema truth: `.scratch/api-schemas-2026-07-15/wave8-pmg-ruledb-schema.json` (the `/config/
welcomelist/*` subtree; 26 of the wave's 92 paths). Binding decomposition:
`.scratch/sdd/wave-8-draft-decomposition.md` §2 chunk 8b + §3 facts #4-#8, #12-#13, §6.5.
Coordinator rulings (`.scratch/2026-07-15-full-surface-campaign.md`, binding, SUPERSEDE the scout
draft where they differ):
  RULING 3 — risk: MEDIUM create/update (the "no bind/activate gate at all, plus cluster-wide
    scope" combination is a genuine tier above the per-user `pmg_quarantine_welcomelist_add`
    precedent's LOW), LOW delete (removing a bypass is protective — the direction argument), LOW
    reads. The divergence from `pmg_quarantine_welcomelist_add`'s LOW is argued on scope, never
    silently diverged.
  RULING 5 — naming stays `pmg_welcomelist_*` (the schema's own vocabulary, `/config/welcomelist/
    *`) despite sitting one word from the ALREADY-shipped, semantically DIFFERENT
    `pmg_quarantine_welcomelist_add/list/remove` (per-mailbox quarantine bypass vs this family's
    global admin policy object). Mandatory disambiguation line in both families' docstrings; the
    three shipped `pmg_quarantine_welcomelist_*` tools get the reverse cross-reference (doc-only
    diff in `tools/pmg_mail.py`, this wave).

Endpoint table (5 tools total — 2 read, 3 mutation):

  GET    /config/welcomelist/objects          — pmg_welcomelist_objects_list  (read, LOW)
  GET    /config/welcomelist/{type}/{id}       — pmg_welcomelist_object_get   (read, LOW)
  POST   /config/welcomelist/{type}            — pmg_welcomelist_object_add   (MUTATION, MEDIUM)
  PUT    /config/welcomelist/{type}/{id}       — pmg_welcomelist_object_update (MUTATION, MEDIUM)
  DELETE /config/welcomelist/objects/{id}      — pmg_welcomelist_object_delete (MUTATION, LOW)

`GET /config/welcomelist` (directory-index stub, menu of the 8 typed sub-collections) is one of
the wave's 7 no-governance-value stubs (draft §1.2) — not built.

SCHEMA-VERIFIED FACTS (binding on this build — from the live schema, not memory; numbering
follows the draft decomposition's own §3 for cross-reference):

  4. **NO `ogroup` concept anywhere on this plane** — verified across all 8 typed families' POST/
     PUT parameter schemas: none carry an `ogroup` field, no path segment nests under a group ID
     (unlike every ruledb who/what/when family, `/{ogroup}/{type}/...` three levels deep).
     Welcomelist is a flat, single global namespace with 8 typed sub-collections. Every function
     below takes `type_` + the typed field only — no `ogroup` parameter, full stop.

  5. **Object `id` is a plain positive integer** — matches `_check_ruledb_id`'s existing regex
     byte-for-byte (verified against `email`/`network` GET/PUT param schemas — both type `id` as
     `integer`). Whether this id-space is shared with any ruledb id-space is NOT stated anywhere
     in the schema; most plausible reading is an independent counter, with zero functional
     consequence either way (ids are already treated as opaque, URL-scoped integers by every
     validator on this plane). See §6.5 below for the `_check_welcomelist_id` alias this fact
     motivates.

  6/7. **Live-verified 2026-07-17 (lab PMG 9.1)**: the apidoc types every typed-object GET's
     `returns.properties`, and the aggregate `GET /config/welcomelist/objects` list-all, as bare
     `{id: <type>}` / `{id: int}` with no `type` field documented — but the real runtime response
     is richer on both counts. Typed GETs return the full type-specific field. The aggregate list
     items are RICH too — they carry the typed field plus `otype_text` etc. — so a caller CAN
     route straight from the aggregate list alone, resolving the routing question this fact
     originally raised.

  8. **Zero `digest` parameters exist anywhere on this plane** (verified programmatically, not
     spot-checked) — no create, update, or read carries a `digest` field. **No optimistic-lock
     support at any level.** `plan_welcomelist_object_update`'s CAPTURE renders the current state
     for operator review, but two concurrent updates can still race (last write wins) — documented
     plainly in the update plan's blast_radius, never silently assumed safe.

  12. **Likely upstream copy-paste description bug**: `POST /config/welcomelist/receiver_domain`'s
     `domain` field is described `"DNS domain name (Sender)."` — identical text to plain
     `/config/welcomelist/domain`'s own field description. Given the family-name convention
     (`receiver_*` = matches the recipient side, plain = matches the sender side), a receiver-side
     family's field being labeled "(Sender)" almost certainly carries the sibling's description
     over verbatim. Trust the field name/type/family name; this description string is NEVER
     copied into this module's docstrings or Plan text — flagged here once, not repeated as truth.

  13. **All typed fields are single-field, no `info`/`and`/`invert` metadata** — verified across
     all 8: `email` (email/receiver), `domain` (domain/receiver_domain), `regex` (regex/
     receiver_regex), `ip`, `cidr` (network). Simpler than ruledb who-objects (which at least
     share group-level `info`/`and`/`invert`, even if objects themselves don't carry it). Because
     every type has exactly ONE required field, `plan_welcomelist_object_add`/
     `plan_welcomelist_object_update` raise `ProximoError` when that field is missing (an
     "at-least-one-field" guard that, for a single-field family, collapses to "the field must be
     given") — a stricter guard than the multi-field ruledb who/what families use, deliberately,
     because there IS no ambiguity here about what "no fields" could mean.

Taint: `pmg_welcomelist_objects_list`/`pmg_welcomelist_object_get` are REVIEWED_TRUSTED —
operator-authored match criteria (email/domain/regex/ip/cidr), the same channel already
REVIEWED_TRUSTED for `pmg_who_object_get`/`pmg_what_object_get`. `pmg_welcomelist_object_add`/
`_update`/`_delete` are REVIEWED_TRUSTED too (mutations; no content channel to classify either way
— taint classifies the RETURN channel, not the mutation's consequences). None belong in
`taint.ADVERSARIAL_TOOLS`. See `tests/test_taint_classification_complete.py`'s Wave 8b block.

Live-verified 2026-07-17 (lab PMG 9.1): the PMG lab smoke (draft §5 Priority 2) ran the round-trip
this module's plan docstrings promised — email (add -> typed get -> update -> typed get ->
delete) and receiver_domain (add -> typed get -> delete), 20/20 PASS overall. Direction and the
per-type field shapes are confirmed live for those two families; the remaining 6 typed families
(receiver/regex/receiver_regex/ip/network) share the same body-builder/validator code path but
were not individually smoked.
"""
from __future__ import annotations

from proximo._secretfile import safe_exception_text

from .backends import ProximoError
from .planning import RISK_LOW, RISK_MEDIUM, Plan
from .pmg import PmgBackend, _check_ruledb_id

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# §6.5 (draft decomposition, follow-up debt item 5): the id-format regex is byte-identical to
# ruledb's own (`^\d+\Z`, a positive-integer string — "0" survives, matching PMG's own plain-
# integer id typing), but this plane's id-space is a conceptually distinct resource (Fact #5). A
# thin alias keeps call sites in THIS file readable ("_check_welcomelist_id") without duplicating
# the regex/logic or reaching into a file that has nothing to do with welcomelist by its
# ruledb-specific name. The underlying error text still says "ruledb rule ID" (a known, minor,
# not-escalated wart — see the draft's own framing of this as a naming-hygiene point, not a
# correctness one).
_check_welcomelist_id = _check_ruledb_id

# Welcomelist object type enum — 8 flat typed families, no ogroup nesting (Fact #4).
_WELCOMELIST_OBJECT_TYPES = frozenset({
    "email", "receiver", "domain", "receiver_domain",
    "regex", "receiver_regex", "ip", "network",
})

# Direction the family name encodes (stated in _welcomelist_object_body's own docstring): plain
# families (email/domain/regex/ip/network) match the message's SENDER side; receiver_* families
# match the RECIPIENT side instead. Used by the add/update PLAN factories to render a per-call
# direction line (wave-8b review Finding 2 — the previous blast text was direction-blind).
_RECIPIENT_SIDE_TYPES = frozenset({"receiver", "receiver_domain", "receiver_regex"})


def _check_welcomelist_object_type(type_: str) -> str:
    if type_ not in _WELCOMELIST_OBJECT_TYPES:
        raise ProximoError(
            f"invalid welcomelist object type: {type_!r}. "
            f"Must be one of: {', '.join(sorted(_WELCOMELIST_OBJECT_TYPES))}"
        )
    return type_


# ---------------------------------------------------------------------------
# READ operations
# ---------------------------------------------------------------------------


def welcomelist_objects_list(api: PmgBackend) -> list[dict]:
    """List every entry across all 8 welcomelist typed families (the flat, global aggregate).

    GET /config/welcomelist/objects

    Wave 8b, schema-verified path. Schema types only {id: int} per item, no 'type' field (Fact
    #7) — but Live-verified 2026-07-17 (lab PMG 9.1): the real list items are RICH, carrying the
    typed field plus `otype_text` etc., so a caller CAN route straight from this list without a
    separate typed GET per candidate id (resolves Fact #7's open routing question).
    """
    return api._get("/config/welcomelist/objects") or []


def welcomelist_object_get(api: PmgBackend, type_: str, id_: str) -> dict:
    """Get a PMG global welcomelist object's settings.

    GET /config/welcomelist/{type}/{id}

    Wave 8b, schema-verified path.
    type_: email|receiver|domain|receiver_domain|regex|receiver_regex|ip|network — controls the
    sub-path. NO ogroup — this plane is a flat global namespace (Fact #4).
    id_: object ID (numeric string) from pmg_welcomelist_objects_list.
    Schema types only {id: int} in the return (Fact #6) — but Live-verified 2026-07-17 (lab PMG
    9.1, email + receiver_domain variants): the real response carries the full type-specific
    field, richer than the apidoc's {id}-only declared shape.
    """
    type_ = _check_welcomelist_object_type(type_)
    id_ = _check_welcomelist_id(id_)
    return api._get(f"/config/welcomelist/{type_}/{id_}") or {}


# ---------------------------------------------------------------------------
# Body builder shared by add/update
# ---------------------------------------------------------------------------


def _welcomelist_object_body(
    type_: str,
    *,
    email: str | None = None,
    domain: str | None = None,
    regex: str | None = None,
    ip: str | None = None,
    cidr: str | None = None,
) -> dict:
    """Build the type-dispatched request body shared by welcomelist_object_add/update.

    Field mapping per family (schema-verified, draft Fact list): email/receiver -> email;
    domain/receiver_domain -> domain; regex/receiver_regex -> regex; ip -> ip; network -> cidr.
    Direction (sender- vs recipient-side) comes from the FAMILY NAME, not a body field — plain
    families (email/domain/regex/ip/network) match the sender side, receiver_* families match the
    recipient side. NOTE (Fact #12): receiver_domain's own upstream field description text
    mislabels this as "(Sender)" — a copy-paste artifact from plain domain's description, trusted
    nowhere in this codebase; the family name is the source of truth for direction.
    """
    body: dict = {}
    if type_ in ("email", "receiver"):
        if email is not None:
            body["email"] = email
    elif type_ in ("domain", "receiver_domain"):
        if domain is not None:
            body["domain"] = domain
    elif type_ in ("regex", "receiver_regex"):
        if regex is not None:
            body["regex"] = regex
    elif type_ == "ip":
        if ip is not None:
            body["ip"] = ip
    elif type_ == "network":
        if cidr is not None:
            body["cidr"] = cidr
    return body


# ---------------------------------------------------------------------------
# MUTATION operations
# ---------------------------------------------------------------------------


def welcomelist_object_add(
    api: PmgBackend,
    type_: str,
    *,
    email: str | None = None,
    domain: str | None = None,
    regex: str | None = None,
    ip: str | None = None,
    cidr: str | None = None,
) -> object:
    """Add an object to the PMG global welcomelist.

    POST /config/welcomelist/{type}

    MUTATION — confirm-gated + audited at the server layer.

    Wave 8b, schema-verified path. Live-verified 2026-07-17 (lab PMG 9.1, email + receiver_domain
    variants): add -> typed get round-trip confirmed against the real API.
    type_: email|receiver|domain|receiver_domain|regex|receiver_regex|ip|network.
    Type-specific field (send only the relevant one):
        email/receiver:            email (str)
        domain/receiver_domain:    domain (str)
        regex/receiver_regex:      regex (str)
        ip:                        ip (str)
        network:                   cidr (str)
    GLOBAL scope, unconditionally live cluster-wide the moment it lands — unlike a ruledb
    who-object, there is no owning group that must first be bound to a rule. Returns the new
    object's integer ID assigned by PMG.
    """
    type_ = _check_welcomelist_object_type(type_)
    body = _welcomelist_object_body(type_, email=email, domain=domain, regex=regex, ip=ip, cidr=cidr)
    return api._post(f"/config/welcomelist/{type_}", data=body)


def welcomelist_object_update(
    api: PmgBackend,
    type_: str,
    id_: str,
    *,
    email: str | None = None,
    domain: str | None = None,
    regex: str | None = None,
    ip: str | None = None,
    cidr: str | None = None,
) -> object:
    """Update an object in the PMG global welcomelist.

    PUT /config/welcomelist/{type}/{id}

    MUTATION — confirm-gated + audited at the server layer.

    Wave 8b, schema-verified path. Live-verified 2026-07-17 (lab PMG 9.1, email variant): update
    -> typed get round-trip confirmed against the real API.
    type_: email|receiver|domain|receiver_domain|regex|receiver_regex|ip|network — must match the
    object's existing type. id_: object ID (numeric string) from pmg_welcomelist_objects_list.
    NO digest exists on this plane (Fact #8) — no optimistic lock; a concurrent update from
    another caller can still race (last write wins).
    """
    type_ = _check_welcomelist_object_type(type_)
    id_ = _check_welcomelist_id(id_)
    body = _welcomelist_object_body(type_, email=email, domain=domain, regex=regex, ip=ip, cidr=cidr)
    return api._put(f"/config/welcomelist/{type_}/{id_}", data=body)


def welcomelist_object_delete(api: PmgBackend, id_: str) -> object:
    """Delete an object from the PMG global welcomelist (generic, untyped — no type_ needed).

    DELETE /config/welcomelist/objects/{id}

    MUTATION — confirm-gated + audited at the server layer.

    Wave 8b, schema-verified path. Live-verified 2026-07-17 (lab PMG 9.1, email + receiver_domain
    variants): delete confirmed against the real API as part of each fixture's cleanup.
    id_: object ID (numeric string) from pmg_welcomelist_objects_list. Unlike add/update, PMG's
    own DELETE endpoint is generic across all 8 typed families — one path, no type in the URL.
    Removes a scanning bypass (protective direction) — see plan_welcomelist_object_delete for the
    RISK_LOW reasoning vs. ruledb object delete's own RISK_MEDIUM.
    """
    id_ = _check_welcomelist_id(id_)
    return api._delete(f"/config/welcomelist/objects/{id_}")


# ---------------------------------------------------------------------------
# Update-plan CAPTURE helper — degrade-honestly-on-failure (mirrors pmg.py's own W6a
# `_ruledb_reset_capture_count` precedent: a trusted-plane capture read must never block a plan
# from rendering; a failed capture becomes an honest note instead).
# ---------------------------------------------------------------------------


def _welcomelist_capture_current(api: PmgBackend, type_: str, id_: str) -> tuple[dict, str | None]:
    """Best-effort typed-GET capture for plan_welcomelist_object_update: returns (current, note).

    Never raises — REVIEWED_TRUSTED source, so the plain try/except capture path is right (no
    taint-marking machinery needed, unlike ceph.py's capture_adversarial_current, reserved for
    ADVERSARIAL-classified capture sources). A capture failure degrades to an honest note; the
    plan still renders (current={}), it just can't show the pre-change state.
    """
    try:
        return welcomelist_object_get(api, type_, id_), None
    except Exception as e:  # noqa: BLE001 — deliberate: ANY capture-read failure degrades honestly
        return {}, f"current-state capture failed: {safe_exception_text(e)}"


# ---------------------------------------------------------------------------
# Direction line — per-call blast text for the add/update PLAN factories.
# ---------------------------------------------------------------------------


def _welcomelist_direction_blast_line(type_: str, value: object) -> str:
    """One blast_radius line stating which side of the message a specific call affects.

    Direction is inferred from the family-NAMING convention (Fact stated in
    _welcomelist_object_body's own docstring) — live-evidenced 2026-07-17 by PMG's own
    `receivertest` flag (see _DIRECTION_HEDGE_NOTE), but full mail-flow behavior was not
    exercised; that fuller hedge belongs in the plan's `note`, not here — this line states the
    direction as read off the family name, nothing more.
    """
    if type_ in _RECIPIENT_SIDE_TYPES:
        return (
            f"matches the RECIPIENT side: mail TO {value} bypasses spam/virus scanning for "
            "every mailbox, cluster-wide"
        )
    return (
        f"matches the SENDER side: mail FROM {value} bypasses spam/virus scanning for every "
        "mailbox, cluster-wide"
    )


_DIRECTION_HEDGE_NOTE = (
    "Direction (SENDER vs RECIPIENT) is inferred from the family-naming convention — "
    "live-evidenced 2026-07-17 (lab PMG 9.1): PMG's own `receivertest` flag came back 1 for "
    "receiver_domain and 0 for plain email in lab reads, matching the convention. Full mail-flow "
    "behavior was not exercised. Upstream's own receiver_domain field description carries a "
    "known copy-paste bug (Fact #12)."
)


# ---------------------------------------------------------------------------
# PLAN functions
# ---------------------------------------------------------------------------


def plan_welcomelist_object_add(
    type_: str,
    *,
    email: str | None = None,
    domain: str | None = None,
    regex: str | None = None,
    ip: str | None = None,
    cidr: str | None = None,
) -> Plan:
    """Preview adding an object to the PMG global welcomelist. PURE — no API call (nothing
    pre-existing to capture for a brand-new object).

    RISK_MEDIUM (coordinator RULING 3) — a deliberate tier ABOVE the per-user
    pmg_quarantine_welcomelist_add precedent's LOW: this entry has NO bind/activate gate at all
    (unlike a ruledb who-object, conditional on the owning group being bound to a rule) — it is
    unconditionally live, cluster-wide, for every mailbox, the moment it lands. A forged/
    compromised sender matching a bad entry bypasses spam/virus scanning entirely, for everyone.
    """
    type_ = _check_welcomelist_object_type(type_)
    changes = _welcomelist_object_body(type_, email=email, domain=domain, regex=regex, ip=ip, cidr=cidr)
    if not changes:
        raise ProximoError(
            f"welcomelist add requires the {type_!r} type's field to be set "
            "(every welcomelist type has exactly one required field — Fact #13)"
        )
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    direction_value = next(iter(changes.values()))
    return Plan(
        action="pmg_welcomelist_object_add",
        target=f"config/welcomelist/{type_}",
        change=f"add {type_} object to the global welcomelist: {change_summary}",
        current={},
        blast_radius=[
            f"adds one {type_} object to the GLOBAL welcomelist: {change_summary}",
            _welcomelist_direction_blast_line(type_, direction_value),
            "GLOBAL scope: unconditionally live cluster-wide the instant this lands — no owning "
            "group, no bind/activate step (unlike a ruledb who-object)",
            "matching mail BYPASSES spam/virus scanning entirely, for EVERY mailbox",
            "a tier above pmg_quarantine_welcomelist_add's LOW rating on purpose — that entry is "
            "scoped to one mailbox; this one is not",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: no bind/activate gate — immediately live cluster-wide, unlike ruledb "
            "who-objects (conditional on group-to-rule binding)",
            "a scanning bypass for every mailbox, not just one — the scope argument (RULING 3)",
        ],
        note="Schema-verified path (Smoke-confirm — not yet live-tested): "
             f"POST /config/welcomelist/{type_}. {_DIRECTION_HEDGE_NOTE}",
    )


def plan_welcomelist_object_update(
    api: PmgBackend,
    type_: str,
    id_: str,
    *,
    email: str | None = None,
    domain: str | None = None,
    regex: str | None = None,
    ip: str | None = None,
    cidr: str | None = None,
) -> Plan:
    """Preview updating an object in the PMG global welcomelist. CAPTURE: reads the object's
    current state via the typed GET (capture-then-show) — a failed capture degrades to an honest
    note rather than blocking the plan (see _welcomelist_capture_current).

    RISK_MEDIUM (coordinator RULING 3) — same scope argument as add: GLOBAL, unconditionally
    live, bypasses scanning for every mailbox. NO digest exists on this plane (Fact #8): no
    optimistic lock, so a concurrent update from another caller can still race with this one —
    stated plainly below, never silently assumed safe.
    """
    type_ = _check_welcomelist_object_type(type_)
    id_ = _check_welcomelist_id(id_)
    changes = _welcomelist_object_body(type_, email=email, domain=domain, regex=regex, ip=ip, cidr=cidr)
    if not changes:
        raise ProximoError(
            f"welcomelist_object_update needs the {type_!r} type's field provided "
            "(every welcomelist type has exactly one required field — Fact #13)"
        )
    current, fail_note = _welcomelist_capture_current(api, type_, id_)
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(changes.items()))
    direction_value = next(iter(changes.values()))
    blast = [
        f"modifies {type_} object {id_} in the GLOBAL welcomelist: {change_summary}",
        _welcomelist_direction_blast_line(type_, direction_value),
        "GLOBAL scope: the new value is live cluster-wide immediately, no bind/activate step",
        "matching mail BYPASSES spam/virus scanning entirely, for EVERY mailbox",
        "NO digest/optimistic-lock on this plane (Fact #8) — a concurrent update from another "
        "caller can still race with this one; last write wins",
    ]
    if fail_note:
        blast.append(fail_note)
    return Plan(
        action="pmg_welcomelist_object_update",
        target=f"config/welcomelist/{type_}/{id_}",
        change=f"update {type_} object {id_} in the global welcomelist: {change_summary}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[
            "MEDIUM: modifies a live, unconditionally-active global bypass entry",
            "a scanning bypass for every mailbox, not just one — the scope argument (RULING 3)",
        ],
        note="Schema-verified path (Smoke-confirm — not yet live-tested): "
             f"PUT /config/welcomelist/{type_}/{id_}. {_DIRECTION_HEDGE_NOTE}",
        complete=fail_note is None,
    )


def plan_welcomelist_object_delete(id_: str) -> Plan:
    """Preview deleting an object from the PMG global welcomelist. PURE — no API call.

    RISK_LOW (coordinator RULING 3) — a DELIBERATE divergence from ruledb who/what object
    delete's own RISK_MEDIUM, argued on direction, not silently diverged: a ruledb object DELETE
    removes a rule's matching criterion (a coverage LOSS); this DELETE removes a bypass (a
    coverage GAIN) — the deleted address/domain/network is simply re-subjected to normal
    spam/virus scanning, the protective direction.
    """
    id_ = _check_welcomelist_id(id_)
    return Plan(
        action="pmg_welcomelist_object_delete",
        target=f"config/welcomelist/objects/{id_}",
        change=f"delete object {id_} from the global welcomelist",
        current={},
        blast_radius=[
            f"permanently removes object {id_} from the GLOBAL welcomelist",
            "PROTECTIVE direction: the removed address/domain/network is re-subjected to normal "
            "spam/virus scanning cluster-wide, immediately",
            "if the entry was legitimately relied on, affected mail may now be quarantined/scanned "
            "until re-added with pmg_welcomelist_object_add",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "LOW: removes a scanning bypass — a coverage GAIN, not a loss (the direction argument, "
            "RULING 3) — asymmetric from ruledb who/what object delete's own RISK_MEDIUM on purpose",
        ],
        note="Schema-verified path (Smoke-confirm — not yet live-tested): "
             "DELETE /config/welcomelist/objects/{id}.",
    )
