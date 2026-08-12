"""PBS tape media-pool + encryption-key config plane (Wave 4b of the full-surface campaign,
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 4 decomposition (PBS tape)", "4b — media
pools + encryption keys"). Sibling to `pbs_tape_config.py` (Wave 4a — drive/changer hardware
config): same no-PVE-sibling posture, same idiom set. The operational tape surface (drive/changer
status, load/unload/label/format/catalog, media catalog/backup/restore) is Waves 4c/4d, separate
modules — not built here.

Schema truth: `.scratch/api-schemas-2026-07-15/wave4-pbs-tape-schema.json` (the live PBS
apidoc.js, pulled 2026-07-15).

Endpoint table (10 tools total — 4 read, 6 mutation):

  GET    /config/media-pool                        — pbs_tape_pool_list           (read)
  GET    /config/media-pool/{name}                  — pbs_tape_pool_get            (read)
  GET    /config/tape-encryption-keys               — pbs_tape_key_list            (read)
  GET    /config/tape-encryption-keys/{fingerprint} — pbs_tape_key_get             (read, PUBLIC part only)
  POST   /config/media-pool                         — pbs_tape_pool_create         (MUTATION, LOW)
  PUT    /config/media-pool/{name}                  — pbs_tape_pool_update         (MUTATION, MEDIUM)
  DELETE /config/media-pool/{name}                  — pbs_tape_pool_delete         (MUTATION, MEDIUM)
  POST   /config/tape-encryption-keys               — pbs_tape_key_create          (MUTATION, MEDIUM)
  PUT    /config/tape-encryption-keys/{fingerprint} — pbs_tape_key_update_password (MUTATION, MEDIUM)
  DELETE /config/tape-encryption-keys/{fingerprint} — pbs_tape_key_delete          (MUTATION, HIGH)

SCHEMA-VERIFIED FACTS (binding on this build — from the live schema, not memory):

  1. **Media pool `name` shares pbs_tape_config.py's drive/changer char-class**
     (`^[A-Za-z0-9_][A-Za-z0-9._\\-]*$`) but `minLength` is **2**, not 3 (confirmed on every
     pool list-item/GET/POST/PUT/DELETE) — a fresh validator here, not reused, since the length
     bound differs from `pbs_tape_config._check_tape_id`.
  2. **Media-pool endpoints have NO `digest` optimistic-lock anywhere** — confirmed: neither the
     PUT nor the DELETE body/params schema for `/config/media-pool/{name}` includes a `digest`
     property at all (unlike `pbs_tape_config.py`'s drive/changer PUTs, which do carry one —
     Wave 4a fact #3). This is a genuine absence in the schema, not merely unforwarded by this
     module; a `_check_digest` validator is kept here anyway (see fact below) purely for parity
     with the encryption-keys side of this same module, which DOES have digest support.
  3. **Media-pool PUT's `delete` enum**: `["allocation", "retention", "template", "encrypt",
     "comment"]` — confirmed against the live schema. Not validated against its closed enum
     client-side, matching the established "pass the list through, let the live API enforce its
     own enum" convention (`pbs_tape_config.py` fact #8, `pbs_notifications.py` fact #6).
  4. **`encrypt` (media-pool) and `fingerprint` (encryption-keys path param, and the `fingerprint`
     field in both keys' list/get responses) share the IDENTICAL pattern**: 32 colon-separated
     hex byte-pairs — `^(?:[0-9a-fA-F][0-9a-fA-F])(?::[0-9a-fA-F][0-9a-fA-F]){31}$`, i.e. a
     formatted SHA-256. One shared validator (`_check_fingerprint`) covers both uses. `encrypt`
     is a REFERENCE/pointer to a key, not key material itself — safe to show unredacted in a
     plan/ledger (unlike `key`/`password`/`new-password`, see fact #7).
  5. **`allocation`/`retention` are genuinely open `string` fields** — no `pattern`, no `enum` in
     the schema at all, only prose describing accepted shapes (allocation ∈ {'continue',
     'always', a calendar event}; retention ∈ {'overwrite', 'keep', a time span}). This module
     validates them defensively — reject control characters, and impose a 256-char cap the
     schema itself does NOT impose — a deliberate STRICTER-THAN-SCHEMA choice, noted here rather
     than silently diverged.
  6. **`comment`/`template`/`hint` share the POSIX `[[:^cntrl:]]*` ("no control characters")
     pattern** — mirrored as a plain not-control-char regex (`_check_no_control`), with the
     schema's own length bounds: comment maxLength 128 (no minLength); template minLength 2/
     maxLength 64; hint minLength 1/maxLength 64 on POST — but see fact #8 for the PUT shape,
     where `hint` is REQUIRED, not optional.
  7. **THE SECRET CONTRACT — two secret shapes on this plane**: POST /config/tape-encryption-keys
     accepts `key` (optional — imported/restore key material, a 300-600 char JSON string) and
     `password` (REQUIRED — minLength 5); PUT /config/tape-encryption-keys/{fingerprint} accepts
     `new-password` (REQUIRED — minLength 5) and `password` (optional — the CURRENT password).
     `key`/`password`/`new-password` are masked to `"[redacted]"` before entering ANY Plan field
     — mirrors `pbs_notifications.py`'s `_redact_secrets` idiom, widened to this plane's 3-key
     set. The RAW values are still forwarded to the live PBS API on `confirm=True` (the mutation
     must actually work) — only the PLAN/PROVE surfaces are scrubbed.
  8. **PUT /config/tape-encryption-keys/{fingerprint} is NOT a partial-update shape** like every
     other PUT in this codebase: `hint` and `new-password` are REQUIRED (no `optional:1` flag on
     either in the live schema) even though the endpoint's own description reads "Change the
     encryption key's password (and password hint)" — a caller cannot change just the password
     without resending the hint (or vice versa). `password` (the CURRENT password) is optional —
     meaningful only when `force` is not set (per the schema's own description, `force=True`
     resets the passphrase "using the root-only accessible copy", bypassing the current-password
     check). `digest`/`kdf`/`force` are the only genuinely optional fields on this PUT.
  9. **GET /config/tape-encryption-keys[/{fingerprint}] returns PUBLIC KEY METADATA ONLY**
     (`created`, `fingerprint`, `hint`, `kdf`, `modified`, `path`) — confirmed: neither `key` nor
     `password` appears anywhere in either GET response schema (list or single) — "Get key config
     (public key part)" is the live schema's own description for the single-key GET. The CAPTURE
     reads in `plan_tape_key_update_password`/`plan_tape_key_delete` therefore have nothing
     secret to redact per the schema TODAY — but `_redact_secrets` is applied to the captured
     dict regardless (defensive-in-depth, cheap), and the confirm-sweep test proves the sweep by
     wiring the fake GET to return secret-bearing fields anyway, per the campaign brief's
     explicit instruction.
  10. **POST /config/tape-encryption-keys returns the new key's SHA-256 FINGERPRINT as a bare
      string** (schema: `{"type": "string", "pattern": "...", "description": "Tape encryption
      key fingerprint (sha256)."}`) — NOT secret material, safe to return to the caller AND
      record in the ledger. Mirrors `pve_token_create`'s "secret in the RETURN, redacted from the
      ledger DETAIL" contract, except here the RETURN value itself (the fingerprint) is not the
      secret at all — `key`/`password` never appear in the response in the first place.
  11. **`kdf` is a CLOSED enum** (`none`, `scrypt`, `pbkdf2`; default `scrypt`) on both POST and
      PUT — validated client-side against the closed set (unlike the `delete` list enums on this
      same plane and on `pbs_tape_config.py`, which the established convention leaves to the live
      API to enforce).
  12. **Every mutation on this plane returns `null` EXCEPT `pbs_tape_key_create`**, whose POST
      returns the fingerprint string (fact #10). Every wrapper except `pbs_tape_key_create`
      records `outcome="ok"` with `result: None`; `pbs_tape_key_create` records `outcome="ok"`
      with `result: <fingerprint>`. Nothing on this plane is asynchronous — never "submitted".

RISK RATING (module-specific reasoning):
  - **pool_create = RISK_LOW**: additive — no existing pool/drive/changer/job config is affected
    (mirrors `pbs_notifications.py`'s `endpoint_create`).
  - **pool_update = RISK_MEDIUM**: changes allocation/retention policy and/or the encryption-key
    association for a pool that FUTURE tape-backup jobs write into — a behavioral change to which
    tapes get reused/overwritten and how, not merely additive.
  - **pool_delete = RISK_MEDIUM** (the campaign brief's own instruction, verified against the
    schema's DELETE description — "Delete a media pool configuration", no mention either way of
    media/tape survival): media/backup data already written to tape is untouched, but the pool's
    retention/allocation policy AND its encryption-key association are gone — a materially bigger
    behavioral loss than `pbs_tape_config.py`'s drive/changer delete (config-only LOW): a
    scheduled tape-backup-job referencing this pool fails, and the retention policy that decided
    which tapes were safe to overwrite is gone with it.
  - **key_create = RISK_MEDIUM**: creates a credential controlling future tape access — mirrors
    `pve_token_create`'s privsep=True MEDIUM rating ("creates a credential — cannot be retrieved
    after creation").
  - **key_update_password = RISK_MEDIUM**: rotates the password protecting an existing key; PBS
    itself provides a `force` recovery path via the root-only copy, so this is not an immediate
    one-way lockout the way key_delete is — but a caller who loses track of the new password
    before invoking `force` risks losing normal-user access to that key.
  - **key_delete = RISK_HIGH**, verbatim per the campaign's HARD INVARIANT: "tapes encrypted with
    this key become UNREADABLE without it" — matches PBS's own DELETE description word for word
    ("Please note that you can no longer access tapes using this key.") — no softening language
    anywhere in the plan or the tool docstring.

Taint: all 10 tools REVIEWED_TRUSTED — same reasoning as Wave 4a's 12 tools (structured,
operator-authored config; no attacker-shapeable free-text channel). `comment`/`hint`/`template`
are operator-authored free-text fields, same category as `pbs_notifications.py`'s own `comment`
fields (already REVIEWED_TRUSTED), not an external/guest-authored channel.

VERIFIED live shapes: None — all backend functions carry "Smoke-confirm:" comments; every shape
here is schema-derived, not live-proven against a running PBS.
"""

from __future__ import annotations

import re

from ._validate import check_digest as _check_digest
from ._validate import redact_secrets
from .backends import ProximoError
from .pbs import PbsBackend, _check_delete_list
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# Media pool name — same char-class as pbs_tape_config's drive/changer identifier, but minLength
# 2 (not 3) per the live schema (module docstring fact #1) — a fresh validator, not reused, since
# the length bound differs.
_POOL_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*\Z")

# Tape-encryption-key fingerprint — 32 colon-separated hex byte-pairs (a formatted SHA-256).
# Shared by media-pool's `encrypt` field and tape-encryption-keys' own `fingerprint` path param /
# response field (module docstring fact #4) — the SAME pattern in both places, one validator.
_FINGERPRINT_RE = re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){31}\Z")

# comment / template / hint — POSIX [[:^cntrl:]]* ("no control characters"), mirrored as a plain
# not-control-char check (module docstring fact #6).
_NO_CONTROL_RE = re.compile(r"^[^\x00-\x1f\x7f]*\Z")

_VALID_KDF = frozenset({"none", "scrypt", "pbkdf2"})


def _check_pool_name(name: str) -> str:
    s = str(name)
    if not (2 <= len(s) <= 32) or not _POOL_NAME_RE.match(s):
        raise ProximoError(
            f"invalid PBS media pool name: {name!r} (must start with alnum or underscore, "
            "then alnum/./_/-, 2-32 chars)"
        )
    return s


def _check_fingerprint(value: str) -> str:
    s = str(value)
    if not _FINGERPRINT_RE.match(s):
        raise ProximoError(
            f"invalid tape encryption key fingerprint: {value!r} (expected 32 colon-separated "
            "hex byte-pairs, e.g. 'AA:BB:...:FF' — a formatted SHA-256)"
        )
    return s


def _check_no_control(value: str, field: str, min_len: int = 0, max_len: int | None = None) -> str:
    s = str(value)
    if not _NO_CONTROL_RE.match(s):
        raise ProximoError(f"invalid {field}: {value!r} — control characters not allowed")
    if len(s) < min_len or (max_len is not None and len(s) > max_len):
        bound = f"{min_len}-{max_len}" if max_len is not None else f">= {min_len}"
        raise ProximoError(f"invalid {field}: {value!r} — length must be {bound} chars")
    return s


def _check_policy_string(value: str, field: str) -> str:
    """allocation/retention: genuinely open strings per the schema — no pattern, no enum (module
    docstring fact #5). Validated defensively: no control chars, plus a 256-char cap the schema
    itself does not impose — a deliberate stricter-than-schema choice, not a silent gap."""
    return _check_no_control(value, field, min_len=1, max_len=256)


def _check_kdf(value: str) -> str:
    s = str(value)
    if s not in _VALID_KDF:
        raise ProximoError(f"invalid kdf: {value!r} (expected one of {sorted(_VALID_KDF)})")
    return s


# Credential-shaped fields on this plane (module docstring fact #7): `key` (imported key
# material), `password` (create's required secret / update's CURRENT password), and
# `new-password` (update's new secret). Both the wire-hyphenated and Python-underscored spelling
# of new-password are covered so a caller can pass either shape through _redact_secrets.
_SECRET_KEYS = frozenset({"key", "password", "new-password", "new_password"})


def _redact_secrets(d: dict) -> dict:
    """Mask credential-shaped fields before they enter a plan string or Plan.current — the
    shared `_validate.redact_secrets` mechanic over this plane's own `_SECRET_KEYS`."""
    return redact_secrets(d, _SECRET_KEYS)


# ---------------------------------------------------------------------------
# Backend functions — reads
# ---------------------------------------------------------------------------

def tape_pool_list(api: PbsBackend) -> list[dict]:
    """GET /config/media-pool — list configured tape media pools (with config digest, per the
    schema's list description — but see module docstring fact #2: this plane has no digest FIELD
    anywhere in the actual per-endpoint schemas). Smoke-confirm: response shape."""
    return api._get("/config/media-pool") or []


def tape_pool_get(api: PbsBackend, name: str) -> dict:
    """GET /config/media-pool/{name} — one pool's full config. Smoke-confirm: response shape."""
    name = _check_pool_name(name)
    return api._get(f"/config/media-pool/{name}") or {}


def tape_key_list(api: PbsBackend) -> list[dict]:
    """GET /config/tape-encryption-keys — list existing encryption keys, PUBLIC metadata only
    (created/fingerprint/hint/kdf/modified/path — module docstring fact #9). Stripped
    defensively anyway (Wave 5a review parity — pbs_config.remote_get idiom). Smoke-confirm:
    response shape."""
    items = api._get("/config/tape-encryption-keys") or []
    return [{k: v for k, v in it.items() if k not in _SECRET_KEYS}
            for it in items if isinstance(it, dict)]


def tape_key_get(api: PbsBackend, fingerprint: str) -> dict:
    """GET /config/tape-encryption-keys/{fingerprint} — one key's PUBLIC metadata only (module
    docstring fact #9: neither `key` nor `password` appears in this response, confirmed against
    the live schema — "Get key config (public key part)"). Stripped defensively anyway (Wave 5a
    review parity). Smoke-confirm: response shape."""
    fingerprint = _check_fingerprint(fingerprint)
    data = api._get(f"/config/tape-encryption-keys/{fingerprint}") or {}
    return {k: v for k, v in data.items() if k not in _SECRET_KEYS}


# ---------------------------------------------------------------------------
# Backend functions — mutations, Media pools
# ---------------------------------------------------------------------------

def tape_pool_create(
    api: PbsBackend,
    name: str,
    allocation: str | None = None,
    comment: str | None = None,
    encrypt: str | None = None,
    retention: str | None = None,
    template: str | None = None,
) -> None:
    """POST /config/media-pool — name required, all else optional. Returns null (synchronous).
    MUTATION — confirm-gated + audited at the server layer."""
    name = _check_pool_name(name)
    data: dict = {"name": name}
    if allocation is not None:
        data["allocation"] = _check_policy_string(allocation, "allocation")
    if comment is not None:
        data["comment"] = _check_no_control(comment, "comment", max_len=128)
    if encrypt is not None:
        data["encrypt"] = _check_fingerprint(encrypt)
    if retention is not None:
        data["retention"] = _check_policy_string(retention, "retention")
    if template is not None:
        data["template"] = _check_no_control(template, "template", min_len=2, max_len=64)
    api._post("/config/media-pool", data)


def tape_pool_update(
    api: PbsBackend,
    name: str,
    allocation: str | None = None,
    comment: str | None = None,
    encrypt: str | None = None,
    retention: str | None = None,
    template: str | None = None,
    delete: list[str] | None = None,
) -> None:
    """PUT /config/media-pool/{name} — all fields optional. NO digest param exists on this
    endpoint (module docstring fact #2) — nothing to forward even if a caller wanted optimistic
    concurrency here. Returns null (synchronous). MUTATION — confirm-gated + audited at the
    server layer."""
    name = _check_pool_name(name)
    data: dict = {}
    if allocation is not None:
        data["allocation"] = _check_policy_string(allocation, "allocation")
    if comment is not None:
        data["comment"] = _check_no_control(comment, "comment", max_len=128)
    if encrypt is not None:
        data["encrypt"] = _check_fingerprint(encrypt)
    if retention is not None:
        data["retention"] = _check_policy_string(retention, "retention")
    if template is not None:
        data["template"] = _check_no_control(template, "template", min_len=2, max_len=64)
    if delete is not None:
        data["delete"] = _check_delete_list(delete)
    api._put(f"/config/media-pool/{name}", data)


def tape_pool_delete(api: PbsBackend, name: str) -> None:
    """DELETE /config/media-pool/{name}. No digest param exists on this endpoint either (module
    docstring fact #2). Returns null (synchronous). MUTATION — confirm-gated + audited at the
    server layer."""
    name = _check_pool_name(name)
    api._delete(f"/config/media-pool/{name}")


# ---------------------------------------------------------------------------
# Backend functions — mutations, Encryption keys
# ---------------------------------------------------------------------------

def tape_key_create(
    api: PbsBackend,
    password: str,
    hint: str | None = None,
    kdf: str | None = None,
    key: str | None = None,
) -> str:
    """POST /config/tape-encryption-keys — `password` REQUIRED; hint/kdf/key optional. Returns
    the new key's SHA-256 fingerprint as a bare string (module docstring fact #10) — NOT secret
    material, safe to return/record. MUTATION — confirm-gated + audited at the server layer. The
    RAW password/key values are forwarded here (the operation must actually work) but never
    recorded to the ledger — see plan_tape_key_create's redaction."""
    data: dict = {"password": str(password)}
    if hint is not None:
        data["hint"] = _check_no_control(hint, "hint", min_len=1, max_len=64)
    if kdf is not None:
        data["kdf"] = _check_kdf(kdf)
    if key is not None:
        k = str(key)
        if not (300 <= len(k) <= 600):
            raise ProximoError(
                f"invalid key: length {len(k)} chars — PBS requires a 300-600 char JSON string "
                "(the exported key material)"
            )
        data["key"] = k
    return api._post("/config/tape-encryption-keys", data)


def tape_key_update_password(
    api: PbsBackend,
    fingerprint: str,
    hint: str,
    new_password: str,
    password: str | None = None,
    kdf: str | None = None,
    force: bool | None = None,
    digest: str | None = None,
) -> None:
    """PUT /config/tape-encryption-keys/{fingerprint} — `hint` and `new_password` are REQUIRED
    (module docstring fact #8: NOT a partial-update shape like every other PUT in this codebase
    — the live schema has no `optional:1` on either). `password` (current) is optional,
    meaningful only when `force` is not set. Returns null (synchronous). MUTATION —
    confirm-gated + audited at the server layer. The RAW password values are forwarded here (the
    operation must actually work) but never recorded to the ledger — see
    plan_tape_key_update_password's redaction."""
    fingerprint = _check_fingerprint(fingerprint)
    data: dict = {
        "hint": _check_no_control(hint, "hint", min_len=1, max_len=64),
        "new-password": str(new_password),
    }
    if password is not None:
        data["password"] = str(password)
    if kdf is not None:
        data["kdf"] = _check_kdf(kdf)
    if force is not None:
        data["force"] = bool(force)
    if digest is not None:
        data["digest"] = _check_digest(digest)
    api._put(f"/config/tape-encryption-keys/{fingerprint}", data)


def tape_key_delete(api: PbsBackend, fingerprint: str, digest: str | None = None) -> None:
    """DELETE /config/tape-encryption-keys/{fingerprint}. PBS's own description, verbatim:
    'Please note that you can no longer access tapes using this key.' Returns null (synchronous).
    MUTATION — confirm-gated + audited at the server layer."""
    fingerprint = _check_fingerprint(fingerprint)
    params: dict = {}
    if digest is not None:
        params["digest"] = _check_digest(digest)
    api._delete(f"/config/tape-encryption-keys/{fingerprint}", params=params)


# ---------------------------------------------------------------------------
# Plan factories — Media pools
# ---------------------------------------------------------------------------

def plan_tape_pool_create(
    name: str,
    allocation: str | None = None,
    comment: str | None = None,
    encrypt: str | None = None,
    retention: str | None = None,
    template: str | None = None,
) -> Plan:
    """Plan creating a PBS tape media pool. RISK_LOW (module docstring's RISK RATING note —
    additive, no existing state touched). PURE — no API read."""
    _check_pool_name(name)
    if allocation is not None:
        _check_policy_string(allocation, "allocation")
    if comment is not None:
        _check_no_control(comment, "comment", max_len=128)
    if encrypt is not None:
        _check_fingerprint(encrypt)
    if retention is not None:
        _check_policy_string(retention, "retention")
    if template is not None:
        _check_no_control(template, "template", min_len=2, max_len=64)
    extra = []
    if allocation is not None:
        extra.append(f"allocation={allocation!r}")
    if retention is not None:
        extra.append(f"retention={retention!r}")
    if template is not None:
        extra.append(f"template={template!r}")
    if encrypt is not None:
        extra.append(f"encrypt={encrypt!r}")
    if comment is not None:
        extra.append(f"comment={comment!r}")
    extra_note = f" ({', '.join(extra)})" if extra else ""
    return Plan(
        action="pbs_tape_pool_create",
        target=f"pbs/config/media-pool/{name}",
        change=f"create PBS tape media pool {name!r}{extra_note}",
        current={},
        blast_radius=[
            f"adds a new media pool {name!r} — no existing pool/drive/changer/job config is "
            "affected",
        ],
        risk=RISK_LOW,
        risk_reasons=["additive config — creates a new tape media pool"],
        note=(
            "No snapshot primitive on this plane. Config is re-creatable — delete with "
            "pbs_tape_pool_delete and re-create to correct a mistake."
        ),
    )


def plan_tape_pool_update(
    api: PbsBackend,
    name: str,
    allocation: str | None = None,
    comment: str | None = None,
    encrypt: str | None = None,
    retention: str | None = None,
    template: str | None = None,
    delete: list[str] | None = None,
) -> Plan:
    """Plan updating a PBS tape media pool. CAPTURE: reads current config (`encrypt` is a
    fingerprint REFERENCE, not key material — safe to show unredacted, module docstring fact
    #4). No `digest` param exists on this endpoint at all (module docstring fact #2) — nothing
    to validate there."""
    _check_pool_name(name)
    if allocation is not None:
        _check_policy_string(allocation, "allocation")
    if comment is not None:
        _check_no_control(comment, "comment", max_len=128)
    if encrypt is not None:
        _check_fingerprint(encrypt)
    if retention is not None:
        _check_policy_string(retention, "retention")
    if template is not None:
        _check_no_control(template, "template", min_len=2, max_len=64)
    # Defense-in-depth redaction on the CAPTURE, same as the key-plane factories below —
    # media-pool GET is public-only per today's schema, but an out-of-schema secret-shaped
    # field must never reach Plan.current raw (review finding, Wave 4b).
    current = _redact_secrets(tape_pool_get(api, name))
    extra = []
    if allocation is not None:
        extra.append(f"allocation={allocation!r}")
    if comment is not None:
        extra.append(f"comment={comment!r}")
    if encrypt is not None:
        extra.append(f"encrypt={encrypt!r}")
    if retention is not None:
        extra.append(f"retention={retention!r}")
    if template is not None:
        extra.append(f"template={template!r}")
    # `is not None`, NOT truthiness — but delete=[] is REJECTED, not disclosed: httpx's form
    # encoding drops an empty-list value entirely, so a disclosed "delete=[]" would never match
    # what confirm=True actually sends (Wave 5b review finding 1, corrects the Wave 4a comment
    # this replaced).
    if delete is not None:
        extra.append(f"delete={_check_delete_list(delete)!r}")
    change_desc = ", ".join(extra) if extra else "no fields changed"
    return Plan(
        action="pbs_tape_pool_update",
        target=f"pbs/config/media-pool/{name}",
        change=f"update PBS tape media pool {name!r}: {change_desc}",
        current=current,
        blast_radius=[
            f"media pool {name!r}: changes allocation/retention policy and/or the "
            "encryption-key association — future tape-backup jobs writing into this pool "
            "target/reuse tapes under the new policy on their next run",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "changes policy governing which tapes are reused/overwritten and (if `encrypt` "
            "changes) which key future writes into this pool use",
        ],
        note=(
            "No snapshot primitive on this plane. Current config captured above — re-apply it "
            "manually (pbs_tape_pool_update) to revert."
        ),
    )


def plan_tape_pool_delete(api: PbsBackend, name: str) -> Plan:
    """Plan deleting a PBS tape media pool. CAPTURE: reads current config for honesty/restore
    material. RISK_MEDIUM (module docstring's RISK RATING note — a step up from
    pbs_tape_config.py's drive/changer delete=LOW: losing the pool config also loses its
    retention/allocation policy and encryption-key association, not just an identifier)."""
    _check_pool_name(name)
    # Defense-in-depth redaction on the CAPTURE (review finding, Wave 4b) — see update above.
    current = _redact_secrets(tape_pool_get(api, name))
    return Plan(
        action="pbs_tape_pool_delete",
        target=f"pbs/config/media-pool/{name}",
        change=f"delete PBS tape media pool {name!r}",
        current=current,
        blast_radius=[
            f"removes media pool {name!r}'s config — tape-backup jobs referencing this pool "
            "fail until it is re-created; media/backup data already written to tapes that "
            "belonged to this pool is untouched, but the retention/allocation policy and any "
            "encryption-key association governing future writes is gone",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "removes routing/retention policy a scheduled tape-backup job depends on — a "
            "bigger behavioral loss than a config-only identifier going stale",
        ],
        note=(
            "No UNDO primitive on this plane. Config is re-creatable — re-create with "
            "pbs_tape_pool_create using the captured current config above (allocation/"
            "retention/template/encrypt/comment) to restore. WARN: tape-backup jobs "
            "referencing this pool fail until it is restored."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — Encryption keys
# ---------------------------------------------------------------------------

def plan_tape_key_create(
    password: str,
    hint: str | None = None,
    kdf: str | None = None,
    key: str | None = None,
) -> Plan:
    """Plan creating a PBS tape encryption key. RISK_MEDIUM (module docstring's RISK RATING note
    — mirrors pve_token_create's privsep=True MEDIUM rating). PURE — no API read (the key
    doesn't exist yet). THE SECRET CONTRACT (module docstring fact #7): `key`/`password` are
    masked to '[redacted]' before entering the Plan; the RAW values are still forwarded to the
    live PBS API on confirm=True (the create must actually work) — only this PLAN/PROVE surface
    is scrubbed."""
    if hint is not None:
        _check_no_control(hint, "hint", min_len=1, max_len=64)
    if kdf is not None:
        _check_kdf(kdf)
    if key is not None:
        k = str(key)
        if not (300 <= len(k) <= 600):
            raise ProximoError(
                f"invalid key: length {len(k)} chars — PBS requires a 300-600 char JSON string"
            )
    kw = {"password": password, "hint": hint, "kdf": kdf, "key": key}
    kw = {k_: v for k_, v in kw.items() if v is not None}
    return Plan(
        action="pbs_tape_key_create",
        target="pbs/config/tape-encryption-keys",
        change=f"create PBS tape encryption key: {_redact_secrets(kw)}",
        current={},
        blast_radius=[
            "adds a new tape encryption key (additive — no existing key/pool/job config is "
            "affected); the new key's fingerprint is returned on confirm=True",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "creates a credential controlling future tape access — the password/imported key "
            "material cannot be retrieved again after creation",
        ],
        note=(
            "The RETURN on confirm=True carries the new key's sha256 FINGERPRINT (not secret — "
            "safe to record). Assign it to a media pool's `encrypt` field with "
            "pbs_tape_pool_create/pbs_tape_pool_update to actually encrypt future tape writes."
        ),
    )


def plan_tape_key_update_password(
    api: PbsBackend,
    fingerprint: str,
    hint: str,
    new_password: str,
    password: str | None = None,
    kdf: str | None = None,
    force: bool | None = None,
    digest: str | None = None,
) -> Plan:
    """Plan changing a PBS tape encryption key's password (+ hint). CAPTURE: reads current key
    metadata (PUBLIC part only per the live schema — module docstring fact #9 — but redacted
    regardless, defensive-in-depth). `hint`/`new_password` are REQUIRED per the live schema
    (module docstring fact #8) — validated here too (not just at execution) so a bad value is
    caught at PLAN time."""
    fingerprint = _check_fingerprint(fingerprint)
    _check_no_control(hint, "hint", min_len=1, max_len=64)
    if kdf is not None:
        _check_kdf(kdf)
    if digest is not None:
        _check_digest(digest)
    current = _redact_secrets(tape_key_get(api, fingerprint))
    kw = {
        "hint": hint, "new-password": new_password, "password": password,
        "kdf": kdf, "force": force, "digest": digest,
    }
    kw = {k_: v for k_, v in kw.items() if v is not None}
    return Plan(
        action="pbs_tape_key_update_password",
        target=f"pbs/config/tape-encryption-keys/{fingerprint}",
        change=(
            f"change password for PBS tape encryption key {fingerprint!r}: "
            f"{_redact_secrets(kw)}"
        ),
        current=current,
        blast_radius=[
            f"rotates the password (and hint) protecting key {fingerprint!r} — anyone/anything "
            "using the OLD password to unlock this key loses access until updated with the new "
            "one",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "rotates a credential protecting tape data — PBS retains a root-only recovery copy "
            "(force=True bypasses the current-password check via it), so this is not an "
            "immediate one-way lockout, but losing track of the new password before using "
            "force still risks losing normal-user access to this key",
        ],
        note=(
            "No snapshot primitive on this plane. Current metadata captured above (public "
            "fields only, redacted regardless). Re-apply the OLD password/hint with this same "
            "tool to revert, if still known."
        ),
    )


def plan_tape_key_delete(api: PbsBackend, fingerprint: str, digest: str | None = None) -> Plan:
    """Plan deleting a PBS tape encryption key. CAPTURE: reads current key metadata (public part
    only, redacted regardless — defensive-in-depth, module docstring fact #9). RISK_HIGH — PBS's
    own description, verbatim, is not softened here: 'you can no longer access tapes using this
    key.' Every tape written with this key becomes permanently unreadable once it is gone unless
    the key material was separately exported/backed up outside PBS."""
    fingerprint = _check_fingerprint(fingerprint)
    if digest is not None:
        _check_digest(digest)
    current = _redact_secrets(tape_key_get(api, fingerprint))
    return Plan(
        action="pbs_tape_key_delete",
        target=f"pbs/config/tape-encryption-keys/{fingerprint}",
        change=f"delete PBS tape encryption key {fingerprint!r}",
        current=current,
        blast_radius=[
            f"PERMANENTLY removes encryption key {fingerprint!r} from PBS's database — TAPES "
            "ENCRYPTED WITH THIS KEY BECOME UNREADABLE WITHOUT IT. This is PBS's own "
            "description, verbatim: 'you can no longer access tapes using this key.' There is "
            "no undo unless the key material was separately exported/backed up outside PBS.",
            f"any media pool whose `encrypt` field still references {fingerprint!r} keeps "
            "pointing at a now-nonexistent key — future writes into that pool will fail until "
            "the pool is updated to a different key or its encrypt field is cleared",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "irreversibly destroys the ONLY means of decrypting every tape written with this "
            "key — no PBS-side undo",
        ],
        note=(
            "NO UNDO. If you have not separately exported/backed up this key's material "
            "outside PBS, deleting it is permanent data loss for every tape it encrypted. "
            "Double-check pbs_tape_pool_list/pbs_tape_pool_get for any pool still referencing "
            "this fingerprint before confirming."
        ),
    )
