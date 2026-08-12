"""PBS ACME plane — accounts, DNS challenge plugins, and node cert order/renew (Wave 3b of the
full-surface campaign, `.scratch/2026-07-15-full-surface-campaign.md`, "Wave 3 decomposition
(PBS notifications + ACME)"). Mirrors the shipped PVE `acme_certs.py` module (`_redact_plugin_kw`,
plan-factory risk ratings, docstring style) — this docstring calls out every place this module
DIVERGES from that precedent, and why.

Schema truth: `.scratch/api-schemas-2026-07-15/wave3-pbs-notifications-acme-schema.json` (the live
PBS apidoc.js, pulled 2026-07-15). Notifications (`/config/notifications/...`) is Wave 3a, a
separate module — not built here.

Endpoint table (15 tools total — 7 read, 8 mutation):

  GET    /config/acme/account                              — acme_account_list      (read)
  GET    /config/acme/account/{name}                        — acme_account_get       (read)
  GET    /config/acme/directories                           — acme_directories       (read)
  GET    /config/acme/tos                                   — acme_tos               (read)
  GET    /config/acme/challenge-schema                      — acme_challenge_schema  (read)
  GET    /config/acme/plugins                                — acme_plugins_list      (read)
  GET    /config/acme/plugins/{id}                           — acme_plugin_get        (read)
  POST   /config/acme/account                                — acme_account_create    (MUTATION, MEDIUM)
  PUT    /config/acme/account/{name}                         — acme_account_update    (MUTATION, LOW)
  DELETE /config/acme/account/{name}                         — acme_account_delete    (MUTATION, HIGH)
  POST   /config/acme/plugins                                — acme_plugin_create     (MUTATION, MEDIUM)
  PUT    /config/acme/plugins/{id}                            — acme_plugin_update     (MUTATION, MEDIUM)
  DELETE /config/acme/plugins/{id}                            — acme_plugin_delete     (MUTATION, HIGH)
  POST   /nodes/{node}/certificates/acme/certificate          — acme_cert_order        (MUTATION, MEDIUM)
  PUT    /nodes/{node}/certificates/acme/certificate          — acme_cert_renew        (MUTATION, MEDIUM)

SCHEMA-VERIFIED FACTS (binding on this build — from the live schema, not memory):

  1. **PBS has NO ACME cert revoke.** PVE exposes DELETE /nodes/{node}/certificates/acme/
     certificate (`pve_acme_cert_revoke`); the live PBS schema has no DELETE at all on
     `/nodes/{node}/certificates/acme/certificate` — only POST (order) and PUT (renew). No
     `pbs_acme_cert_revoke` tool exists here because there is nothing on PBS's own API to call.
  2. **PBS cert order (POST) and renew (PUT) both declare `returns: {"type": "null"}`** —
     unlike PVE's identically-shaped endpoints, which return a task UPID (confirmed against
     `acme_certs.py`'s own `acme_cert_order`/`acme_cert_renew`, and against the live PVE
     schema). Both wrappers here record outcome="ok" (never "submitted") and their docstrings
     say explicitly: PBS's declared null return does NOT mean the ACME order/renewal is
     synchronous or already complete — cert issuance still happens asynchronously on the PBS
     side (an ACME challenge round-trip with the CA takes real time) — this tool call simply has
     nothing to poll. There is no UPID to wait on; inventing a wait would be dishonest. This may
     be a schema-authoring slip on PBS's part (PVE's equivalent DOES return a UPID for the exact
     same kind of operation) but the live schema is what a caller actually gets back, and this
     module reports that truthfully rather than assuming PVE's shape applies.
  3. **All 9 `/config/acme/*` reads are entirely new coverage — PVE has ZERO of them.**
     Proximo's shipped `tools/pve_certs.py` exposes only 9 ACME tools, all mutations (account
     create/update/delete, plugin create/update/delete, node-domains-set, cert order/renew/
     revoke) — verified by reading that file: no `pve_acme_account_list`, `pve_acme_account_get`,
     `pve_acme_directories`, `pve_acme_tos`, `pve_acme_challenge_schema`, `pve_acme_plugins_list`,
     or `pve_acme_plugin_get` tool exists on the PVE side, even though `acme_certs.py`'s backend
     module has internal `acme_account_get`/`acme_plugin_get` functions (used ONLY for a plan
     factory's CAPTURE read, never exposed as their own MCP tool). This is real PVE-side debt —
     an agent can create/update/delete a PVE ACME account or plugin but can never simply list or
     inspect one — noted here, not silently fixed on the PVE side in this commit (out of scope
     for a PBS wave).
  4. **Secret-shaped params: account `eab_hmac_key` (create only) and plugin `data` (create +
     update).** `eab_hmac_key` exists ONLY on POST /config/acme/account's body — PUT (update)
     accepts only `contact`, and GET /config/acme/account/{name}'s response schema does NOT
     include an `eab_hmac_key` property anywhere (checked: the `account` sub-object exposes
     `contact`, `externalAccountBinding` {payload, protected, signature}, `onlyReturnExisting`,
     `orders`, `status`, `termsOfServiceAgreed} — no raw HMAC key). So account read/CAPTURE paths
     never see this credential on a live PBS. This module redacts it defensively anyway
     everywhere an account kwarg dict is stringified (`_redact_account_kw`, applied to both
     `Plan.change` and any CAPTURE `Plan.current`) — costs nothing and guards against a future
     schema change, same defensive posture `acme_certs.py`'s own `plan_acme_plugin_delete` note
     already takes ("whether stored secrets are returned by the GET endpoint is unverified... so
     this plan redacts defensively rather than assuming"). Plugin `data` (DNS-API credential
     blob) DOES come back on `GET /config/acme/plugins` and `GET .../plugins/{id}` (both response
     schemas list `data` as a returned property) — so `acme_plugin_update`/`_delete`'s CAPTURE
     reads MUST redact it, not just defensively; this module does (`_redact_plugin_kw`, mirrors
     `acme_certs.py`'s function of the same name exactly).
  5. **`digest` optimistic-lock exists on plugin PUT only** (not on plugin POST, not on any
     account verb) — confirmed: plugin POST has no `digest` property; plugin PUT does
     (`/^[a-f0-9]{64}$/`, non-`\\Z`-anchored in PBS's own pattern — this module re-anchors with
     `\\Z` per this codebase's trailing-newline-bypass discipline). Forwarded only where the
     schema offers it, validated at PLAN time (not just at execution) — same early-validation
     contract `pbs_notifications.py`'s `plan_notification_endpoint_update` already established.
  6. **Account name: use the schema's own pattern directly** (per the campaign brief) —
     `/^(?:[A-Za-z0-9_][A-Za-z0-9._\\-]*)$/`, allowing a leading underscore and dots (looser than
     `acme_certs.py`'s PVE-side account-name regex, which requires an alnum lead and rejects
     dots) — deliberately NOT tightened to PVE's charset here, since the brief calls for the
     PBS schema's own pattern, not the cross-plane "stricter of the two" rule `pbs_notifications.
     py` used for its name field. PBS declares no length bound on this field at all (no
     `minLength`/`maxLength` anywhere `name` appears under `/config/acme/account`); this module
     adds a defensive 256-char cap (documented, not schema-derived) to block unbounded input.
  7. **Plugin ID: schema's own pattern + explicit bounds** — `maxLength: 32`, `minLength: 1`,
     same underscore/dot-permissive pattern as account name. Used directly, `\\Z`-anchored.
  8. **Plugin `type` has NO enum in the schema** — `POST /config/acme/plugins`' `type` property
     is a bare `"type": "string"`, no `enum` list (unlike, say, `smtp`'s `mode` enum in the
     notifications plane). `GET /config/acme/challenge-schema` returns a catalog of KNOWN plugin
     types (id/name/schema/type per entry) but that is informational metadata from a separate
     live API call, not a client-side validation set this module can bake in without either
     hardcoding PBS's current catalog (which can grow) or making a network call from inside a
     pure validator. Per the campaign brief ("if the schema leaves type open, validate charset
     defensively and say so in a comment") — `_check_plugin_type` enforces a conservative
     lowercase-alnum/hyphen/underscore charset with a defensive 64-char bound instead of an enum;
     see that function's docstring.
  9. **All 8 mutations on this plane return `null` per the schema** — every POST/PUT/DELETE
     under `/config/acme/...` AND both node cert-order/renew endpoints declare
     `"returns": {"type": "null"}`. Every wrapper records outcome="ok", never "submitted" (mirrors
     `pbs_notifications.py`'s fact #8 and `pbs_disks.py`'s synchronous `disk_directory_delete`).
  10. **Account DELETE accepts an extra `force` param PVE's delete does not have** — PBS's
      `DELETE /config/acme/account/{name}` schema includes `force` (bool, default false:
      "Delete account data even if the server refuses to deactivate the account"), a PBS-only
      escape hatch for a CA that won't cooperate with deactivation. PVE's `DELETE /cluster/acme/
      account/{name}` (per `acme_certs.py`) takes no such parameter. Forwarded only when true
      (mirrors this codebase's established truthy-only-send convention for optional flags, e.g.
      `acme_certs.py`'s own `{"force": 1} if force else {}` for cert order/renew).

Security posture:
  - All path components validated with `\\Z`-anchored regexes (trailing-newline bypass rejected).
  - `eab_hmac_key` (account) and `data` (plugin) are masked to `"[redacted]"` before they can
    enter `Plan.change`/`Plan.current`/anything recorded to the tamper-evident ledger. The RAW
    value is still forwarded to the live PBS API on `confirm=True` (the operation must actually
    work) — only the PLAN/PROVE surfaces are scrubbed.
  - `pbs_acme_account_delete`: HIGH risk — DEACTIVATES the account AT THE CA, not just a local
    config removal (mirrors `acme_certs.py`'s own account-delete rating exactly: "the account key
    is gone; only a NEW registration can be made, not a restore").
  - `pbs_acme_plugin_delete`: HIGH risk — breaks auto-renewal for every domain using that
    challenge method (mirrors `acme_certs.py`'s plugin-delete rating).
  - `pbs_acme_cert_order`/`pbs_acme_cert_renew`: MEDIUM — same rating as `acme_certs.py`'s
    `plan_acme_cert_order`/`plan_acme_cert_renew` (CA-validated; a failed challenge cannot lock
    you out, unlike a direct cert upload).
  - No snapshot/UNDO primitive on this plane (config is re-creatable, not restorable) — every
    mutation plan says so explicitly, matching `acme_certs.py`'s own honesty convention.

VERIFIED live shapes: None — all backend functions carry "Smoke-confirm:" comments; every shape
here is schema-derived, not live-proven against a running PBS.
"""

from __future__ import annotations

import re

from ._validate import check_digest as _check_digest
from ._validate import redact_secrets
from .backends import ProximoError
from .pbs import PbsBackend, _check_delete_list, _check_pbs_node
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# Account name: schema's own pattern (module docstring fact #6), used directly (not tightened to
# PVE's stricter charset — the campaign brief calls for the PBS schema's own pattern here). No
# length bound in the live schema; 256 is a defensive cap only, not schema-derived.
_ACME_ACCOUNT_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,255}\Z")

# Plugin ID: schema's own pattern + explicit bounds (fact #7): minLength 1, maxLength 32.
_ACME_PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,31}\Z")

# Plugin type: the live schema leaves this an open string (no enum) — fact #8. Conservative
# defensive charset (lowercase-friendly identifier shape), NOT drawn from an enum PBS doesn't
# declare; challenge-schema's own catalog of known types is informational, fetched via a separate
# live call, not baked in here.
_PLUGIN_TYPE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}\Z")

# validation-delay bound per the live schema's WRITE-path properties (POST/PUT), 0..172800.
_MAX_VALIDATION_DELAY = 172800

# Defensive bound for ACME directory/ToS URLs (schema declares no maxLength; real CA
# directory URLs are well under this).
_MAX_ACME_URL_LEN = 512

# Deletable plugin-update properties per the live schema's `delete` array enum.
_VALID_PLUGIN_DELETE_PROPS = frozenset({"disable", "validation-delay"})

# Secret-shaped kwargs (module docstring fact #4).
_ACCOUNT_SECRET_KEYS = frozenset({"eab_hmac_key"})
_PLUGIN_SECRET_KEYS = frozenset({"data"})


def _redact_account_kw(kw: dict) -> dict:
    """Mask `eab_hmac_key` before it enters a plan string or Plan.current. Defensive on the
    CAPTURE-read side (module docstring fact #4 — GET never actually returns this field on a live
    PBS, but redact anyway rather than assume that never changes)."""
    return redact_secrets(kw, _ACCOUNT_SECRET_KEYS)


def _redact_plugin_kw(kw: dict) -> dict:
    """Mask the DNS-provider credential blob (`data`) before it enters a plan string or
    Plan.current. Mirrors `acme_certs.py`'s function of the same name exactly — `data` DOES come
    back on a live plugin GET (module docstring fact #4), so this redaction is load-bearing, not
    just defensive."""
    return redact_secrets(kw, _PLUGIN_SECRET_KEYS)


def _check_acme_account_name(name: str) -> str:
    # Do NOT strip — stripping defeats \Z trailing-newline protection.
    s = str(name)
    if not _ACME_ACCOUNT_NAME_RE.match(s):
        raise ProximoError(
            f"invalid PBS ACME account name: {name!r} "
            "(must start with alnum/_, then alnum/./_/-, <=256 chars, no slash)"
        )
    return s


def _check_acme_plugin_id(plugin_id: str) -> str:
    s = str(plugin_id)
    if not _ACME_PLUGIN_ID_RE.match(s):
        raise ProximoError(
            f"invalid PBS ACME plugin ID: {plugin_id!r} "
            "(must start with alnum/_, then alnum/./_/-, 1-32 chars, no slash)"
        )
    return s


def _check_plugin_type(plugin_type: str) -> str:
    s = str(plugin_type)
    if not _PLUGIN_TYPE_RE.match(s):
        raise ProximoError(
            f"invalid PBS ACME plugin type: {plugin_type!r} "
            "(expected alnum/_/-, 1-64 chars — the live schema declares no enum; this is a "
            "defensive charset bound, not PBS's own validation set)"
        )
    return s


def _check_acme_url(url: str, field: str) -> str:
    """Restrict ACME directory/ToS URLs to https:// with no whitespace/control chars.

    STRICTER THAN SCHEMA BY CHOICE (the live schema declares a bare untyped string): the
    `directory` value makes the PBS HOST issue an outbound fetch to it, so this validator
    refuses non-https schemes (RFC 8555 §7.1 requires https for directory URLs anyway) and
    anything that could smuggle header/path tricks. Review finding, Wave 3b.
    """
    s = str(url)
    if (
        not s.startswith("https://")
        or len(s) > _MAX_ACME_URL_LEN
        or any(c.isspace() or ord(c) < 0x20 for c in s)
    ):
        raise ProximoError(
            f"invalid {field}: {url!r} (must be an https:// URL, no whitespace/control "
            f"characters, <={_MAX_ACME_URL_LEN} chars)"
        )
    return s


def _check_validation_delay(value: int) -> int:
    # Reject non-int types outright (a float like 12.9 must not silently truncate to 12 —
    # review finding, Wave 3b). bool is an int subclass — reject it too.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProximoError(f"invalid validation-delay: {value!r} (must be an integer)")
    try:
        v = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid validation-delay: {value!r} (must be an integer)") from exc
    if not (0 <= v <= _MAX_VALIDATION_DELAY):
        raise ProximoError(
            f"invalid validation-delay: {v} (must be 0-{_MAX_VALIDATION_DELAY} per the live schema)"
        )
    return v


def _check_plugin_delete_props(delete: list[str]) -> list[str]:
    # `_check_delete_list` rejects `[]` outright (Wave 5b review finding 1 — httpx's form
    # encoding drops an empty-list `delete` value entirely, so it never reaches the wire; the
    # enum check below then further narrows a non-empty list to this plane's closed property
    # set). `delete` is already `list[str]` here (never None — every caller guards `is not
    # None` first), so the validated return is discarded rather than reassigned.
    _check_delete_list(delete)
    out = []
    for item in delete:
        s = str(item)
        if s not in _VALID_PLUGIN_DELETE_PROPS:
            raise ProximoError(
                f"invalid PBS ACME plugin delete property: {s!r} "
                f"(expected one of {sorted(_VALID_PLUGIN_DELETE_PROPS)})"
            )
        out.append(s)
    return out


# ---------------------------------------------------------------------------
# Backend functions — reads
# ---------------------------------------------------------------------------

def acme_account_list(api: PbsBackend) -> list[dict]:
    """GET /config/acme/account — list registered ACME account NAMES only (the schema's own
    response item is `{"name": str}`, nothing else — use acme_account_get for full detail).
    Smoke-confirm: response shape."""
    return api._get("/config/acme/account") or []


def acme_account_get(api: PbsBackend, name: str) -> dict:
    """GET /config/acme/account/{name} — full ACME account detail (account/directory/location/
    tos). Does NOT include `eab_hmac_key` (module docstring fact #4 — never returned by a live
    PBS). Smoke-confirm: exact response shape."""
    name = _check_acme_account_name(name)
    return api._get(f"/config/acme/account/{name}") or {}


def acme_directories(api: PbsBackend) -> list[dict]:
    """GET /config/acme/directories — PBS's built-in catalog of known ACME CA directory
    endpoints (name + URL pairs, e.g. Let's Encrypt production/staging). No params.
    Smoke-confirm: response shape."""
    return api._get("/config/acme/directories") or []


def acme_tos(api: PbsBackend, directory: str | None = None) -> str | None:
    """GET /config/acme/tos — the Terms-of-Service URL for an ACME directory (optional; omit for
    PBS's default CA). Returns a bare string (or None if the CA advertises no ToS) — NOT wrapped
    in a dict, per the schema's own `returns` shape (`{"type": "string", "optional": 1}`).
    Smoke-confirm: response shape."""
    if directory is not None:
        directory = _check_acme_url(directory, "directory")
    params = {"directory": directory} if directory is not None else None
    return api._get("/config/acme/tos", params=params)


def acme_challenge_schema(api: PbsBackend) -> list[dict]:
    """GET /config/acme/challenge-schema — the catalog of known ACME challenge plugin types
    (id/name/schema/type per entry) that a real `type`+`data` pairing must satisfy on plugin
    create/update. No params. Smoke-confirm: response shape."""
    return api._get("/config/acme/challenge-schema") or []


def acme_plugins_list(api: PbsBackend) -> list[dict]:
    """GET /config/acme/plugins — list all configured ACME DNS challenge plugins, INCLUDING the
    raw `data` credential blob (module docstring fact #4 — PBS does not strip it on read). This
    backend function does NOT redact; only the PLAN factories for update/delete redact before
    anything reaches a plan string or the ledger (mirrors pbs_notifications.py's own
    read-vs-plan redaction split). Smoke-confirm: response shape."""
    return api._get("/config/acme/plugins") or []


def acme_plugin_get(api: PbsBackend, plugin_id: str) -> dict:
    """GET /config/acme/plugins/{id} — one plugin's full config, INCLUDING the raw `data`
    credential blob (fact #4). Same no-redaction-here posture as acme_plugins_list.
    Smoke-confirm: response shape."""
    plugin_id = _check_acme_plugin_id(plugin_id)
    return api._get(f"/config/acme/plugins/{plugin_id}") or {}


# ---------------------------------------------------------------------------
# Backend functions — mutations, Accounts
# ---------------------------------------------------------------------------

def acme_account_create(
    api: PbsBackend,
    contact: str,
    name: str | None = None,
    directory: str | None = None,
    eab_hmac_key: str | None = None,
    eab_kid: str | None = None,
    tos_url: str | None = None,
) -> None:
    """POST /config/acme/account — register a new ACME account at the CA. `name` is OPTIONAL per
    the live schema (PBS assigns a default if omitted). Returns null (synchronous, fact #9).
    MUTATION — confirm-gated + audited at the server layer."""
    data: dict = {"contact": contact}
    if name is not None:
        data["name"] = _check_acme_account_name(name)
    if directory is not None:
        data["directory"] = _check_acme_url(directory, "directory")
    if eab_hmac_key is not None:
        data["eab_hmac_key"] = eab_hmac_key
    if eab_kid is not None:
        data["eab_kid"] = eab_kid
    if tos_url is not None:
        data["tos_url"] = _check_acme_url(tos_url, "tos_url")
    api._post("/config/acme/account", data)


def acme_account_update(api: PbsBackend, name: str, contact: str | None = None) -> None:
    """PUT /config/acme/account/{name} — update ACME account contact info. Schema accepts ONLY
    `contact` on this verb (no eab/tos fields — those are create-only). Returns null (synchronous).
    MUTATION — confirm-gated + audited at the server layer."""
    name = _check_acme_account_name(name)
    data: dict = {}
    if contact is not None:
        data["contact"] = contact
    api._put(f"/config/acme/account/{name}", data)


def acme_account_delete(api: PbsBackend, name: str, force: bool = False) -> None:
    """DELETE /config/acme/account/{name} — DEACTIVATES the account at the CA (not just local
    config removal) and deletes the local record. `force` (module docstring fact #10, PBS-only):
    delete local data even if the CA refuses to deactivate the account. Returns null (synchronous).
    MUTATION — confirm-gated + audited at the server layer."""
    name = _check_acme_account_name(name)
    params = {"force": 1} if force else {}
    api._delete(f"/config/acme/account/{name}", params=params or None)


# ---------------------------------------------------------------------------
# Backend functions — mutations, Plugins
# ---------------------------------------------------------------------------

def acme_plugin_create(
    backend: PbsBackend,
    plugin_id: str,
    plugin_type: str,
    api: str | None = None,
    data: str | None = None,
    disable: bool | None = None,
    validation_delay: int | None = None,
) -> None:
    """POST /config/acme/plugins — create an ACME DNS challenge plugin. `backend` (not `api`) is
    the HTTP client parameter name here — PBS's own body field is literally called `api` (the DNS
    provider name), so the client param is renamed to dodge the collision, exactly like
    `acme_certs.py`'s own `acme_plugin_create(backend, ...)`. `data` = base64-encoded DNS
    provider credential blob. Returns null (synchronous).
    MUTATION — confirm-gated + audited at the server layer."""
    plugin_id = _check_acme_plugin_id(plugin_id)
    plugin_type = _check_plugin_type(plugin_type)
    body: dict = {"id": plugin_id, "type": plugin_type}
    if api is not None:
        body["api"] = api
    if data is not None:
        body["data"] = data
    if disable is not None:
        body["disable"] = bool(disable)
    if validation_delay is not None:
        body["validation-delay"] = _check_validation_delay(validation_delay)
    backend._post("/config/acme/plugins", body)


def acme_plugin_update(
    backend: PbsBackend,
    plugin_id: str,
    api: str | None = None,
    data: str | None = None,
    disable: bool | None = None,
    validation_delay: int | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> None:
    """PUT /config/acme/plugins/{id} — update an ACME DNS challenge plugin. `backend` for the same
    naming-collision reason as acme_plugin_create. `digest` is the ONLY optimistic-lock on this
    plane (fact #5); `delete` is a closed enum {disable, validation-delay} (fact — schema `delete`
    items enum). Returns null (synchronous).
    MUTATION — confirm-gated + audited at the server layer."""
    plugin_id = _check_acme_plugin_id(plugin_id)
    body: dict = {}
    if api is not None:
        body["api"] = api
    if data is not None:
        body["data"] = data
    if disable is not None:
        body["disable"] = bool(disable)
    if validation_delay is not None:
        body["validation-delay"] = _check_validation_delay(validation_delay)
    if digest is not None:
        body["digest"] = _check_digest(digest)
    if delete is not None:
        body["delete"] = _check_plugin_delete_props(delete)
    backend._put(f"/config/acme/plugins/{plugin_id}", body)


def acme_plugin_delete(api: PbsBackend, plugin_id: str) -> None:
    """DELETE /config/acme/plugins/{id} — delete an ACME DNS challenge plugin. Returns null
    (synchronous). No naming collision on delete (no `api` kwarg here) — uses `api` for the
    client param, matching `acme_certs.py`'s own `acme_plugin_delete(api, plugin_id)`.
    MUTATION — confirm-gated + audited at the server layer."""
    plugin_id = _check_acme_plugin_id(plugin_id)
    api._delete(f"/config/acme/plugins/{plugin_id}")


# ---------------------------------------------------------------------------
# Backend functions — mutations, node cert order/renew
# ---------------------------------------------------------------------------

def acme_cert_order(api: PbsBackend, node: str = "localhost", force: bool = False) -> None:
    """POST /nodes/{node}/certificates/acme/certificate — order a NEW ACME cert for the node.
    Returns null per the live schema (module docstring fact #2 — unlike PVE's UPID). Cert
    issuance still happens asynchronously on the PBS side; this call does not wait for it and
    there is no UPID to poll. Smoke-confirm: exact live behavior around the null return.
    MUTATION — confirm-gated + audited at the server layer."""
    node = _check_pbs_node(node)
    data = {"force": 1} if force else {}
    api._post(f"/nodes/{node}/certificates/acme/certificate", data)


def acme_cert_renew(api: PbsBackend, node: str = "localhost", force: bool = False) -> None:
    """PUT /nodes/{node}/certificates/acme/certificate — renew the node's existing ACME cert if
    within its renewal lead time (or always, if force). Returns null per the live schema (fact
    #2). Same "no UPID to wait on" honesty as acme_cert_order.
    MUTATION — confirm-gated + audited at the server layer."""
    node = _check_pbs_node(node)
    data = {"force": 1} if force else {}
    api._put(f"/nodes/{node}/certificates/acme/certificate", data)


# ---------------------------------------------------------------------------
# Plan factories — Accounts
# ---------------------------------------------------------------------------

def plan_acme_account_create(
    contact: str,
    name: str | None = None,
    directory: str | None = None,
    eab_hmac_key: str | None = None,
    eab_kid: str | None = None,
    tos_url: str | None = None,
) -> Plan:
    """Plan an ACME account registration (additive, MEDIUM risk). PURE — no API read (PBS may
    assign the account name itself if `name` is omitted, so there is nothing existing to read)."""
    kw = {
        "name": _check_acme_account_name(name) if name is not None else None,
        "directory": _check_acme_url(directory, "directory") if directory is not None else None,
        "eab_hmac_key": eab_hmac_key, "eab_kid": eab_kid,
        "tos_url": _check_acme_url(tos_url, "tos_url") if tos_url is not None else None,
    }
    kw = {k: v for k, v in kw.items() if v is not None}
    tgt = f"pbs/config/acme/account/{name}" if name else "pbs/config/acme/account"
    return Plan(
        action="pbs_acme_account_create",
        target=tgt,
        change=f"register PBS ACME account (contact: {contact!r}): {_redact_account_kw(kw)}",
        current={},
        blast_radius=["registers a new ACME account with the CA (no existing config affected)"],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "sends account registration to the ACME CA directory",
            "depends on correct contact email + TOS acceptance",
        ],
        note=(
            "Additive config. Delete with pbs_acme_account_delete to deactivate. "
            "Smoke-confirm: exact POST body shape against a live PBS instance."
        ),
    )


def plan_acme_account_update(api: PbsBackend, name: str, contact: str | None = None) -> Plan:
    """Plan an ACME account contact update. CAPTURE: reads current config for honesty (redacted
    defensively — module docstring fact #4)."""
    name = _check_acme_account_name(name)
    current = _redact_account_kw(acme_account_get(api, name))
    return Plan(
        action="pbs_acme_account_update",
        target=f"pbs/config/acme/account/{name}",
        change=f"update PBS ACME account {name!r}: {_redact_account_kw({'contact': contact})}",
        current=current,
        blast_radius=["updates contact info on the CA side (no cert impact)"],
        risk=RISK_LOW,
        risk_reasons=["contact metadata update — does not affect cert issuance or renewal"],
        note=(
            "No snapshot primitive on this plane. Current config captured above — "
            "re-apply contact via pbs_acme_account_update to revert."
        ),
    )


def plan_acme_account_delete(api: PbsBackend, name: str, force: bool = False) -> Plan:
    """Plan an ACME account deletion. IRREVERSIBLE — see honesty note. HIGH risk (mirrors
    acme_certs.py's account-delete rating exactly). Captures current config as EVIDENCE ONLY —
    this does NOT enable restore. The account key is gone; only a NEW CA registration can be
    made."""
    name = _check_acme_account_name(name)
    current = _redact_account_kw(acme_account_get(api, name))
    force_note = " (force: delete local data even if the CA refuses to deactivate)" if force else ""
    return Plan(
        action="pbs_acme_account_delete",
        target=f"pbs/config/acme/account/{name}",
        change=f"IRREVERSIBLE: deactivate and delete PBS ACME account {name!r} from the CA{force_note}",
        current=current,
        blast_radius=[
            "ACME account deactivated at the CA — no new cert orders or renewals possible",
            "any TLS cert using this account will NOT renew — TLS lockout at expiry",
            "domains depending on this account require re-registration with a new account",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "IRREVERSIBLE: account key is destroyed; re-registration creates a NEW account, "
            "not a restore of this one",
            "TLS lockout risk: if this is the only ACME account, all auto-renewal stops",
        ],
        note=(
            "IRREVERSIBLE. Current config captured above is for EVIDENCE ONLY — "
            "it does NOT enable restore. The account key is not recoverable. "
            "A new account can be registered with pbs_acme_account_create, "
            "but it will be a different CA account, not this one."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — Plugins
# ---------------------------------------------------------------------------

def plan_acme_plugin_create(plugin_id: str, plugin_type: str, **kw) -> Plan:
    """Plan an ACME plugin creation (additive, MEDIUM risk). PURE — no API read.
    `validation_delay` validated here too (not just at execution) so a bad value is caught at
    PLAN time — review finding, Wave 3b."""
    plugin_id = _check_acme_plugin_id(plugin_id)
    _check_plugin_type(plugin_type)
    if kw.get("validation_delay") is not None:
        _check_validation_delay(kw["validation_delay"])
    return Plan(
        action="pbs_acme_plugin_create",
        target=f"pbs/config/acme/plugins/{plugin_id}",
        change=f"create PBS ACME plugin {plugin_id!r} (type={plugin_type!r}): {_redact_plugin_kw(kw)}",
        current={},
        blast_radius=["adds a new ACME DNS challenge plugin (no existing config affected)"],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "DNS challenge plugin stores API credentials for the DNS provider",
            "incorrect credentials silently break cert issuance until renewal is attempted",
        ],
        note=(
            "Additive config. Delete with pbs_acme_plugin_delete to remove. "
            "Smoke-confirm: exact POST body shape against a live PBS instance."
        ),
    )


def plan_acme_plugin_update(backend: PbsBackend, plugin_id: str, **kw) -> Plan:
    """Plan an ACME plugin update. CAPTURE: reads current config for honesty (redacted — module
    docstring fact #4, load-bearing here since GET DOES return `data`). `digest` validated here
    too (not just at execution) — same early-validation contract
    pbs_notifications.plan_notification_endpoint_update already established."""
    plugin_id = _check_acme_plugin_id(plugin_id)
    if kw.get("digest") is not None:
        _check_digest(kw["digest"])
    if kw.get("delete") is not None:
        _check_plugin_delete_props(kw["delete"])
    if kw.get("validation_delay") is not None:
        _check_validation_delay(kw["validation_delay"])
    current = _redact_plugin_kw(acme_plugin_get(backend, plugin_id))
    return Plan(
        action="pbs_acme_plugin_update",
        target=f"pbs/config/acme/plugins/{plugin_id}",
        change=f"update PBS ACME plugin {plugin_id!r}: {_redact_plugin_kw(kw)}",
        current=current,
        blast_radius=[
            "changes challenge credentials for all domains using this plugin",
            "incorrect new credentials break cert renewal for those domains",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "modifies DNS provider credentials — invalid update breaks challenge at next renewal",
        ],
        note=(
            "No snapshot primitive on this plane. Current config captured above (credential "
            "redacted) — re-apply it manually to revert."
        ),
    )


def plan_acme_plugin_delete(api: PbsBackend, plugin_id: str) -> Plan:
    """Plan an ACME plugin deletion. HIGH risk — cert renewal breaks. CAPTURE: reads current
    config, redacted (load-bearing — GET DOES return `data`, module docstring fact #4)."""
    plugin_id = _check_acme_plugin_id(plugin_id)
    current = _redact_plugin_kw(acme_plugin_get(api, plugin_id))
    return Plan(
        action="pbs_acme_plugin_delete",
        target=f"pbs/config/acme/plugins/{plugin_id}",
        change=f"delete PBS ACME plugin {plugin_id!r}",
        current=current,
        blast_radius=[
            "all domains using this plugin can no longer complete DNS challenges",
            "cert renewal fails at next renewal attempt — TLS lockout at cert expiry",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "auto-renewal breaks for all domains referencing this plugin",
            "TLS lockout risk if no fallback challenge method is configured",
        ],
        note=(
            "No UNDO primitive on this plane. Current config captured above (credential "
            "redacted) — re-create with pbs_acme_plugin_create to restore, but credentials must "
            "be re-supplied by the caller (the raw value is never returned in a usable form here)."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — node cert order/renew
# ---------------------------------------------------------------------------

def plan_acme_cert_order(node: str = "localhost", force: bool = False) -> Plan:
    """Plan an ACME cert order (MEDIUM — mirrors acme_certs.py's plan_acme_cert_order rating).
    PURE — no API read."""
    node = _check_pbs_node(node)
    return Plan(
        action="pbs_acme_cert_order",
        target=f"pbs/node/{node}/certificates/acme/certificate",
        change=(
            f"order a new ACME TLS certificate for PBS node {node!r}"
            + (" (force: overwrite existing files)" if force else "")
        ),
        current={},
        blast_radius=[
            "requests a cert from the configured ACME CA for this PBS node",
            "on SUCCESS, PBS installs the cert; on a failed DNS/HTTP challenge, the existing "
            "cert is left untouched",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "CA-validated: the cert is installed ONLY on a successful challenge — a failure "
            "cannot lock you out",
            "talks to the public CA — repeated orders can hit CA rate limits",
        ],
        note=(
            "The live PBS schema declares a null return for this call (module docstring fact "
            "#2) — unlike PVE, which returns a task UPID. That does NOT mean issuance is "
            "synchronous: the ACME challenge round-trip with the CA still happens after this "
            "call returns, on the PBS side. There is no UPID to poll here; this tool does not "
            "wait for cert issuance. PBS has no ACME cert revoke (module docstring fact #1)."
        ),
    )


def plan_acme_cert_renew(node: str = "localhost", force: bool = False) -> Plan:
    """Plan an ACME cert renew (MEDIUM — same install-on-success guarantee as order)."""
    node = _check_pbs_node(node)
    return Plan(
        action="pbs_acme_cert_renew",
        target=f"pbs/node/{node}/certificates/acme/certificate",
        change=(
            f"renew the existing ACME TLS certificate for PBS node {node!r}"
            + (" (force: renew even if not within the renewal lead time)" if force else "")
        ),
        current={},
        blast_radius=[
            "renews the node's existing ACME cert from the configured CA",
            "on SUCCESS, PBS installs the renewed cert; on a failed challenge, the existing "
            "cert is left untouched",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "CA-validated renew, installed only on success; a failure cannot lock you out",
            "talks to the public CA — repeated renews can hit CA rate limits",
        ],
        note=(
            "Same null-return honesty as pbs_acme_cert_order (module docstring fact #2): no "
            "UPID to poll, issuance still happens asynchronously on the PBS side. PBS has no "
            "ACME cert revoke (fact #1) — there is no way to undo an installed renewal through "
            "this API short of ordering again with a different account/plugin."
        ),
    )
