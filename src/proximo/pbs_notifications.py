"""PBS notifications plane — endpoints (gotify/sendmail/smtp/webhook), matchers, matcher
metadata, and target test (Wave 3a of the full-surface campaign,
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 3 decomposition (PBS notifications +
ACME)"). Mirrors the shipped PVE `notifications.py` module (endpoint-type frozenset,
`_SECRET_KEYS` redaction, matcher upsert-with-one-read) — this docstring calls out every place
this module DIVERGES from that precedent, and why.

Schema truth: `.scratch/api-schemas-2026-07-15/wave3-pbs-notifications-acme-schema.json` (the live
PBS apidoc.js, pulled 2026-07-15). ACME (`/config/acme/...`) is Wave 3b, a separate module — not
built here.

Endpoint table (13 tools total — 7 read, 6 mutation):

  GET  /config/notifications/targets                       — notification_targets_list   (read)
  GET  /config/notifications/endpoints/{type}   (x4, agg.)  — notification_endpoint_list   (read)
  GET  /config/notifications/endpoints/{type}/{name}        — notification_endpoint_get    (read)
  GET  /config/notifications/matchers                       — notification_matchers_list   (read)
  GET  /config/notifications/matchers/{name}                — notification_matcher_get     (read)
  GET  /config/notifications/matcher-fields                 — notification_matcher_fields  (read)
  GET  /config/notifications/matcher-field-values            — notification_matcher_field_values (read)
  POST /config/notifications/endpoints/{type}               — notification_endpoint_create (MUTATION, LOW)
  PUT  /config/notifications/endpoints/{type}/{name}         — notification_endpoint_update (MUTATION, LOW)
  DELETE /config/notifications/endpoints/{type}/{name}       — notification_endpoint_delete (MUTATION, LOW)
  POST/PUT /config/notifications/matchers[/{name}]           — notification_matcher_set     (MUTATION, LOW, upsert)
  DELETE /config/notifications/matchers/{name}               — notification_matcher_delete  (MUTATION, LOW)
  POST /config/notifications/targets/{name}/test             — notification_target_test     (MUTATION, LOW, REAL send)

SCHEMA-VERIFIED FACTS (binding on this build — from the live schema, not memory):

  1. **`GET /config/notifications/endpoints` is a directory index, NOT a unified list** — its
     `returns` schema is `{"type": "null"}` (confirmed). Unlike PVE (`/cluster/notifications/
     endpoints` IS the unified list), PBS's unified list lives at a DIFFERENT path entirely:
     `/config/notifications/targets`. This module's `notification_endpoint_list` aggregates the
     4 per-type collection GETs instead (`/config/notifications/endpoints/{type}` for type in
     gotify/sendmail/smtp/webhook) — the directory-index path is never called.
  2. **The 4 per-type endpoint-list/get responses carry NO "type" field of their own** (confirmed:
     none of the 4 `properties` blocks for gotify/sendmail/smtp/webhook include "type"). A caller
     aggregating across all 4 types via `notification_endpoint_list()` would otherwise be unable
     to tell which type each returned dict came from — so this module tags each item with the
     type it was fetched under (`item["type"] = queried_type`, only if the key is absent) before
     returning. This is metadata we already know from which sub-collection we queried, not an
     invented field — `/config/notifications/targets` (the OTHER read, #1 above) already proves
     the API considers "type" a real property of a notification entity.
  3. **Secret-shaped params are a WIDER set than PVE's `_SECRET_KEYS`.** PBS documents FOUR
     credential-shaped fields at this plane: gotify `token`, smtp `password`, webhook `secret`
     (array of {name, value} pairs, base64-encoded value — schema's own words: "only the secret
     name but not the value will be returned" on reads), and webhook `header` (array of {name,
     value} pairs — NOT officially flagged secret by PBS's schema, but the value can carry an
     `Authorization: Bearer ...` header, so it is treated as secret-shaped here too, matching the
     campaign brief's explicit instruction). PVE's sibling `notifications.py` only redacts
     `{token, password}` — missing `secret`/`header` entirely. That is a real gap on the PVE side
     (not silently diverged from here — noted as PVE-side debt for a future PVE-touch wave, not
     invented/fixed there in this commit).
  4. **PVE's own `plan_notification_endpoint_delete` does NOT redact its `current` field at all**
     (`current = notification_endpoint_get(api, ep_type, name)`, unredacted — re-checked against
     the live `notifications.py` source, not assumed). For gotify/smtp this happens to be safe
     TODAY only because those two endpoint types' GET responses never include the secret field in
     the first place (schema-confirmed: gotify GET has no "token" property, smtp GET has no
     "password" property) — but webhook's GET response as documented in THIS schema DOES include
     "header" with its base64 `value` (the `secret` array is the one PBS explicitly strips the
     value from on read, per its own schema description — `header` carries no such guarantee).
     Given the campaign's HARD INVARIANT ("must NEVER appear raw in any Plan field — change/
     current/note"), this module's `plan_notification_endpoint_delete` redacts `current` too —
     a deliberate improvement over the PVE precedent, not a silent divergence.
  5. **`digest` optimistic-lock exists on every notification PUT** (endpoint update, matcher
     update) but NOT on any POST (create) — confirmed: the POST bodies for all 4 endpoint types
     and for matchers have no `digest` property at all. Forwarded only where the schema offers it.
  6. **Matcher `{name}` accepts only GET/PUT/DELETE; POST goes to the collection** (name in body)
     — identical upsert shape to PVE's own `notification_matcher_set`: one safe read of the
     collection decides which verb to use.
  7. **Endpoint/matcher/target `name` schema pattern is `/^(?:[A-Za-z0-9_][A-Za-z0-9._\\-]*)$/`,
     minLength 2, maxLength 32** (confirmed on every endpoint-type GET/POST/PUT and on
     matchers/targets). This is NOT `\\Z`-anchored (bare `$`, vulnerable to the trailing-newline
     bypass this codebase's validators always close — see `backends._check_disk`'s docstring) and
     its charset (leading `_` allowed, `.` allowed anywhere) is LOOSER than the sibling PVE
     `notifications.py` validator's own charset (alnum-only lead, no `.` ever, no length cap
     enforced beyond the implicit 64 from `{0,63}`). Per the campaign brief: use the STRICTER of
     the two. This module's `_NOTIFICATION_NAME_RE` combines PVE's tighter charset (alnum lead,
     alnum/`_`/`-` body, no dot) with PBS's own tighter length bound (2-32, not PVE's looser
     implicit 1-64), `\\Z`-anchored.
  8. **All 6 mutations here return `null` per the schema** (every POST/PUT/DELETE on this plane
     declares `"returns": {"type": "null"}`) — these are SYNCHRONOUS config ops, unlike a PVE
     guest/storage mutation that returns a task UPID. Every wrapper records outcome="ok", never
     "submitted" (mirrors how `pbs_disks.py`'s `disk_directory_delete` — the one synchronous
     mutation in that module — was handled).
  9. **`notification_target_test` sends a REAL notification** — POST with only `name` in the
     path, no body. Matches PVE's `notification_test` exactly in shape and honesty framing.

Security posture:
  - All path components validated with `\\Z`-anchored regexes (trailing-newline bypass rejected).
  - Endpoint type validated against a closed frozenset — no arbitrary string reaches the URL path.
  - Every credential-shaped kwarg (`token`, `password`, `secret`, `header`) is masked to
    `"[redacted]"` before it can enter `Plan.change`/`Plan.current`/anything recorded to the
    tamper-evident ledger. The RAW value is still forwarded to the live PBS API on `confirm=True`
    (the operation must actually work) — only the PLAN/PROVE surfaces are scrubbed.
  - No snapshot/UNDO primitive on this plane (config is re-creatable, not restorable) — every
    mutation plan says so explicitly, matching `notifications.py`'s own honesty convention.
  - RISK_LOW across all 6 mutations: config-plane only, no guest/data state touched (mirrors the
    PVE module's uniform-LOW rating for this same plane).

VERIFIED live shapes: None — all backend functions carry "Smoke-confirm:" comments; every shape
here is schema-derived, not live-proven against a running PBS.
"""

from __future__ import annotations

import re

from ._validate import check_digest as _check_digest
from ._validate import redact_secrets
from .backends import ProximoError
from .pbs import PbsBackend, _check_delete_list
from .planning import RISK_LOW, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# PBS notification endpoint types — the live schema exposes exactly these 4 collections under
# /config/notifications/endpoints/{type}. Same closed set as PVE's notifications.py.
_VALID_ENDPOINT_TYPES = frozenset({"gotify", "sendmail", "smtp", "webhook"})

# Endpoint/matcher/target name. See module docstring fact #7: combines PVE notifications.py's
# tighter charset (alnum-only lead, alnum/_/- body, NO dot) with PBS's own tighter length bound
# (2-32, confirmed via minLength/maxLength on the live schema) — the stricter of the two on every
# axis, \Z-anchored per this codebase's trailing-newline-bypass discipline. PBS's own schema
# pattern alone (`/^(?:[A-Za-z0-9_][A-Za-z0-9._\-]*)$/`, no length bound in the regex itself) is
# LOOSER on charset (allows leading `_`, allows `.` anywhere) — deliberately not mirrored as-is.
_NOTIFICATION_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,31}\Z")

_VALID_MATCHER_MODES = frozenset({"all", "any"})

# Credential-shaped fields on this plane (module docstring fact #3): gotify `token`, smtp
# `password`, webhook `secret` (array of {name,value} pairs) and webhook `header` (array of
# {name,value} pairs — not schema-flagged secret, but can carry an Authorization header value).
# WIDER than PVE notifications.py's `_SECRET_KEYS = {token, password}` — see fact #3 for why.
_SECRET_KEYS = frozenset({"token", "password", "secret", "header"})


def _redact_secrets(d: dict) -> dict:
    """Mask credential-shaped fields before they enter a plan string or Plan.current — the
    shared `_validate.redact_secrets` mechanic over this plane's own `_SECRET_KEYS`."""
    return redact_secrets(d, _SECRET_KEYS)


def _check_endpoint_type(ep_type: str) -> str:
    # Do NOT strip — stripping defeats \Z trailing-newline protection.
    if ep_type not in _VALID_ENDPOINT_TYPES:
        raise ProximoError(
            f"invalid PBS notification endpoint type: {ep_type!r} "
            f"(expected one of {sorted(_VALID_ENDPOINT_TYPES)})"
        )
    return ep_type


def _check_notification_name(name: str) -> str:
    s = str(name)
    if not _NOTIFICATION_NAME_RE.match(s):
        raise ProximoError(
            f"invalid PBS notification endpoint/matcher/target name: {name!r} "
            "(must start with alnum, then alnum/_/-, 2-32 chars, no dot, no slash)"
        )
    return s


def _check_matcher_mode(mode: str) -> str:
    s = str(mode)
    if s not in _VALID_MATCHER_MODES:
        raise ProximoError(
            f"invalid PBS matcher mode: {mode!r} (expected one of {sorted(_VALID_MATCHER_MODES)})"
        )
    return s


# ---------------------------------------------------------------------------
# Backend functions — reads
# ---------------------------------------------------------------------------

def notification_targets_list(api: PbsBackend) -> list[dict]:
    """GET /config/notifications/targets — the unified list across all endpoint types + matchers'
    routable targets. Returns {name, type, comment?, disable?, origin} per entry (lighter than
    notification_endpoint_get's full type-specific config). Smoke-confirm: response shape."""
    return api._get("/config/notifications/targets") or []


def notification_endpoint_list(api: PbsBackend, ep_type: str | None = None) -> list[dict]:
    """Aggregates GET /config/notifications/endpoints/{type} across all 4 types (or just one if
    ep_type is given). NOTE: GET /config/notifications/endpoints itself is a directory index that
    returns null on live PBS — never called (module docstring fact #1). Each returned item is
    tagged with its 'type' (module docstring fact #2 — the per-type responses don't carry one).
    Smoke-confirm: response shape per type."""
    if ep_type is not None:
        types = [_check_endpoint_type(ep_type)]
    else:
        types = sorted(_VALID_ENDPOINT_TYPES)
    out: list[dict] = []
    for t in types:
        items = api._get(f"/config/notifications/endpoints/{t}") or []
        for item in items:
            if isinstance(item, dict):
                item = dict(item)
                item.setdefault("type", t)
            out.append(item)
    return out


def notification_endpoint_get(api: PbsBackend, ep_type: str, name: str) -> dict:
    """GET /config/notifications/endpoints/{type}/{name} — one endpoint's full type-specific
    config. Smoke-confirm: exact response shape per endpoint type."""
    ep_type = _check_endpoint_type(ep_type)
    name = _check_notification_name(name)
    return api._get(f"/config/notifications/endpoints/{ep_type}/{name}") or {}


def notification_matchers_list(api: PbsBackend) -> list[dict]:
    """GET /config/notifications/matchers — all routing rules. Smoke-confirm: response shape."""
    return api._get("/config/notifications/matchers") or []


def notification_matcher_get(api: PbsBackend, name: str) -> dict:
    """GET /config/notifications/matchers/{name} — one routing rule's full config.
    Smoke-confirm: response shape."""
    name = _check_notification_name(name)
    return api._get(f"/config/notifications/matchers/{name}") or {}


def notification_matcher_fields(api: PbsBackend) -> list[dict]:
    """GET /config/notifications/matcher-fields — all known metadata field NAMES matchable in a
    matcher's match-field rule. No params. Smoke-confirm: response shape."""
    return api._get("/config/notifications/matcher-fields") or []


def notification_matcher_field_values(api: PbsBackend) -> list[dict]:
    """GET /config/notifications/matcher-field-values — all known (field, value) pairs the system
    currently recognizes (e.g. which datastore/job values a matcher rule can target). No params.
    Smoke-confirm: response shape."""
    return api._get("/config/notifications/matcher-field-values") or []


# ---------------------------------------------------------------------------
# Backend functions — mutations, Endpoints
# ---------------------------------------------------------------------------

def notification_endpoint_create(api: PbsBackend, ep_type: str, name: str, **kw) -> None:
    """POST /config/notifications/endpoints/{type} — name goes in the BODY, not the path (matches
    PVE's own live-confirmed convention for the sibling plane). Returns null (synchronous).
    MUTATION — confirm-gated + audited at the server layer."""
    ep_type = _check_endpoint_type(ep_type)
    name = _check_notification_name(name)
    data = {"name": name, **{k: v for k, v in kw.items() if v is not None}}
    api._post(f"/config/notifications/endpoints/{ep_type}", data)


def notification_endpoint_update(api: PbsBackend, ep_type: str, name: str, **kw) -> None:
    """PUT /config/notifications/endpoints/{type}/{name} — accepts a `digest` optimistic-lock
    (module docstring fact #5). Returns null (synchronous).
    MUTATION — confirm-gated + audited at the server layer."""
    ep_type = _check_endpoint_type(ep_type)
    name = _check_notification_name(name)
    data = {k: v for k, v in kw.items() if v is not None}
    if "digest" in data:
        data["digest"] = _check_digest(data["digest"])
    api._put(f"/config/notifications/endpoints/{ep_type}/{name}", data)


def notification_endpoint_delete(api: PbsBackend, ep_type: str, name: str) -> None:
    """DELETE /config/notifications/endpoints/{type}/{name}. Config is re-creatable; matchers
    routing to this endpoint silently fail to deliver until it is re-created. Returns null
    (synchronous). MUTATION — confirm-gated + audited at the server layer."""
    ep_type = _check_endpoint_type(ep_type)
    name = _check_notification_name(name)
    api._delete(f"/config/notifications/endpoints/{ep_type}/{name}")


# ---------------------------------------------------------------------------
# Backend functions — mutations, Matchers
# ---------------------------------------------------------------------------

def notification_matcher_set(
    api: PbsBackend,
    name: str,
    comment: str | None = None,
    mode: str | None = None,
    match_severity: list[str] | None = None,
    match_field: list[str] | None = None,
    match_calendar: list[str] | None = None,
    invert_match: bool | None = None,
    target: list[str] | None = None,
    disable: bool | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> None:
    """Create-or-update a PBS notification matcher (routing rule).

    Create: POST /config/notifications/matchers        {name, ...}
    Update: PUT  /config/notifications/matchers/{name}  {...}
    Module docstring fact #6: the {name} path accepts only GET/PUT/DELETE — POST goes to the
    collection with the name in the body, so the upsert needs one safe read to pick the verb
    (identical shape to PVE's own notification_matcher_set). `digest`/`delete` are PUT-only per
    the live schema (no such properties on the POST body) — dropped on the create branch even if
    supplied, rather than sent and rejected by a real server.
    MUTATION — confirm-gated + audited at the server layer."""
    name = _check_notification_name(name)
    data: dict = {}
    if comment is not None:
        data["comment"] = comment
    if mode is not None:
        data["mode"] = _check_matcher_mode(mode)
    if match_severity is not None:
        data["match-severity"] = list(match_severity)
    if match_field is not None:
        data["match-field"] = list(match_field)
    if match_calendar is not None:
        data["match-calendar"] = list(match_calendar)
    if invert_match is not None:
        data["invert-match"] = bool(invert_match)
    if target is not None:
        data["target"] = [_check_notification_name(t) for t in target]
    if disable is not None:
        data["disable"] = bool(disable)

    existing = api._get("/config/notifications/matchers") or []
    names = {m.get("name") for m in existing if isinstance(m, dict)}
    if name in names:
        if digest is not None:
            data["digest"] = _check_digest(digest)
        if delete is not None:
            data["delete"] = _check_delete_list(delete)
        api._put(f"/config/notifications/matchers/{name}", data)
    else:
        api._post("/config/notifications/matchers", {"name": name, **data})


def notification_matcher_delete(api: PbsBackend, name: str) -> None:
    """DELETE /config/notifications/matchers/{name}. Alerts matching this rule go un-routed.
    Returns null (synchronous). MUTATION — confirm-gated + audited at the server layer."""
    name = _check_notification_name(name)
    api._delete(f"/config/notifications/matchers/{name}")


# ---------------------------------------------------------------------------
# Backend functions — mutation, Target Test
# ---------------------------------------------------------------------------

def notification_target_test(api: PbsBackend, name: str) -> None:
    """POST /config/notifications/targets/{name}/test — send a REAL test notification to an
    endpoint or matcher target. No body (only `name` is a path param per the live schema).
    Returns null (synchronous). MUTATION — confirm-gated + audited at the server layer (real
    notification sent)."""
    name = _check_notification_name(name)
    api._post(f"/config/notifications/targets/{name}/test")


# ---------------------------------------------------------------------------
# Plan factories — Endpoints
# ---------------------------------------------------------------------------

def plan_notification_endpoint_create(ep_type: str, name: str, **kw) -> Plan:
    """Plan creating a PBS notification endpoint (additive, LOW risk). PURE — no API read."""
    _check_endpoint_type(ep_type)
    _check_notification_name(name)
    return Plan(
        action="pbs_notification_endpoint_create",
        target=f"pbs/config/notifications/endpoints/{ep_type}/{name}",
        change=f"create PBS {ep_type!r} notification endpoint {name!r}: {_redact_secrets(kw)}",
        current={},
        blast_radius=["adds a new PBS notification delivery channel (no existing alerts/matchers affected)"],
        risk=RISK_LOW,
        risk_reasons=["additive config — creates a new notification endpoint"],
        note=(
            "No snapshot primitive on this plane. Deleting the endpoint removes the config and "
            "silently stops alert delivery via this channel. Re-create with "
            "pbs_notification_endpoint_create to restore."
        ),
    )


def plan_notification_endpoint_update(api: PbsBackend, ep_type: str, name: str, **kw) -> Plan:
    """Plan updating a PBS notification endpoint. CAPTURE: reads current config for honesty
    (redacted before it ever enters the Plan — see module docstring fact #4). `digest` is
    validated here too (not just at execution) so a bad value is caught at PLAN time — same
    contract as plan_notification_matcher_set."""
    _check_endpoint_type(ep_type)
    _check_notification_name(name)
    if kw.get("digest") is not None:
        _check_digest(kw["digest"])
    current = _redact_secrets(notification_endpoint_get(api, ep_type, name))
    return Plan(
        action="pbs_notification_endpoint_update",
        target=f"pbs/config/notifications/endpoints/{ep_type}/{name}",
        change=f"update PBS {ep_type!r} notification endpoint {name!r}: {_redact_secrets(kw)}",
        current=current,
        blast_radius=["modifies delivery settings for an existing PBS notification endpoint"],
        risk=RISK_LOW,
        risk_reasons=["config-only change — affects future notifications for this endpoint"],
        note=(
            "No snapshot primitive on this plane. Current config captured above (secrets "
            "redacted) — re-apply it manually to revert."
        ),
    )


def plan_notification_endpoint_delete(api: PbsBackend, ep_type: str, name: str) -> Plan:
    """Plan deleting a PBS notification endpoint. CAPTURE: reads current config for honesty,
    redacted (module docstring fact #4 — a deliberate improvement over the PVE precedent, which
    does not redact this field)."""
    _check_endpoint_type(ep_type)
    _check_notification_name(name)
    current = _redact_secrets(notification_endpoint_get(api, ep_type, name))
    return Plan(
        action="pbs_notification_endpoint_delete",
        target=f"pbs/config/notifications/endpoints/{ep_type}/{name}",
        change=f"delete PBS {ep_type!r} notification endpoint {name!r}",
        current=current,
        blast_radius=[
            "removes the notification endpoint config",
            "matchers referencing this endpoint will silently fail to deliver",
        ],
        risk=RISK_LOW,
        risk_reasons=["config-only change — may cause silent alert delivery failures"],
        note=(
            "No UNDO primitive on this plane. Current config captured above (secrets redacted) — "
            "re-create with pbs_notification_endpoint_create to restore. WARN: matchers "
            "referencing this endpoint will silently fail until restored."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — Matchers
# ---------------------------------------------------------------------------

def plan_notification_matcher_set(
    name: str,
    comment: str | None = None,
    mode: str | None = None,
    match_severity: list[str] | None = None,
    match_field: list[str] | None = None,
    match_calendar: list[str] | None = None,
    invert_match: bool | None = None,
    target: list[str] | None = None,
    disable: bool | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> Plan:
    """Plan creating-or-updating a PBS notification matcher. PURE — no API read (mirrors PVE's
    own plan_notification_matcher_set; the backend's upsert read happens only on confirm=True).
    No secret-shaped fields exist on a matcher, so nothing here needs redaction. `mode`/`digest`/
    `delete` are validated here too (not just at execution) so a bad value is caught at PLAN
    time. `delete` in particular: empty-list is REJECTED, not disclosed — httpx's form encoding
    drops an empty-list value entirely on the update branch, so a disclosed "delete=[]" would
    never match what confirm=True actually sends (Wave 5b review finding 1); rejected here even
    though this PURE factory can't yet know create-vs-update, since a race between plan-preview
    and confirm=True could flip which branch executes."""
    _check_notification_name(name)
    if mode is not None:
        mode = _check_matcher_mode(mode)
    if digest is not None:
        digest = _check_digest(digest)
    if delete is not None:
        delete = _check_delete_list(delete)
    kw = {
        "comment": comment, "mode": mode, "match-severity": match_severity,
        "match-field": match_field, "match-calendar": match_calendar,
        "invert-match": invert_match, "target": target, "disable": disable,
        "digest": digest, "delete": delete,
    }
    kw = {k: v for k, v in kw.items() if v is not None}
    return Plan(
        action="pbs_notification_matcher_set",
        target=f"pbs/config/notifications/matchers/{name}",
        change=f"create-or-update PBS notification matcher {name!r}: {kw}",
        current={},
        blast_radius=["creates or updates PBS alert routing rules (which endpoints receive which alerts)"],
        risk=RISK_LOW,
        risk_reasons=["config-only change — routes which endpoints receive which alerts"],
        note=(
            "No snapshot primitive on this plane. Re-create with pbs_notification_matcher_set to "
            "restore after deletion. Create goes to POST .../matchers (name in body); update goes "
            "to PUT .../matchers/{name} — the live upsert read (not this plan) decides which."
        ),
    )


def plan_notification_matcher_delete(name: str) -> Plan:
    """Plan deleting a PBS notification matcher. PURE — no API read (mirrors PVE)."""
    _check_notification_name(name)
    return Plan(
        action="pbs_notification_matcher_delete",
        target=f"pbs/config/notifications/matchers/{name}",
        change=f"delete PBS notification matcher {name!r}",
        current={},
        blast_radius=[
            "removes the alert routing rule",
            "alerts matching this filter will no longer be routed to its endpoints",
        ],
        risk=RISK_LOW,
        risk_reasons=["config-only change — alerts may go undelivered after deletion"],
        note=(
            "No UNDO primitive on this plane. Re-create with pbs_notification_matcher_set to "
            "restore. WARN: alerts will be silently un-routed until restored."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factory — Target Test
# ---------------------------------------------------------------------------

def plan_notification_target_test(name: str) -> Plan:
    """Plan sending a REAL test notification to a PBS target. PURE — no API read (mirrors PVE)."""
    _check_notification_name(name)
    return Plan(
        action="pbs_notification_target_test",
        target=f"pbs/config/notifications/targets/{name}",
        change=f"send a REAL test notification to PBS target {name!r}",
        current={},
        blast_radius=["sends a REAL test notification — recipients/webhook/gotify server will receive it"],
        risk=RISK_LOW,
        risk_reasons=["side-effect only — no config state is changed, but a live notification IS sent"],
        note=(
            "Sends a REAL notification; confirm=True triggers delivery to whatever endpoint(s) "
            "this target routes to. No config change — only the notification channel is exercised."
        ),
    )
