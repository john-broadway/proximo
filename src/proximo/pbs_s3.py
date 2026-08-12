"""PBS S3 client configs + client encryption keys plane (Wave 5a of the full-surface campaign,
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 5 decomposition (PBS s3 + remainder —
CLOSES THE PBS PLANE)", "5a — S3 + client encryption keys"). No PVE sibling exists for either
sub-plane. This chunk starts Wave 5, which closes the PBS plane after 5c.

Schema truth: `.scratch/api-schemas-2026-07-15/wave5a-pbs-s3-keys-schema.json` (extracted from
the live PBS apidoc, pulled 2026-07-15, 9 nodes under /config/s3*, /admin/s3*,
/config/encryption-keys*).

Endpoint table (12 tools total — 4 read, 8 mutation):

  GET    /config/s3                              — pbs_s3_client_list       (read)
  GET    /config/s3/{id}                         — pbs_s3_client_get        (read)
  GET    /config/s3/{id}/list-buckets            — pbs_s3_list_buckets      (read, ADVERSARIAL)
  GET    /config/encryption-keys                 — pbs_encryption_key_list  (read)
  POST   /config/s3                              — pbs_s3_client_create     (MUTATION, MEDIUM)
  PUT    /config/s3/{id}                         — pbs_s3_client_update     (MUTATION, MEDIUM)
  DELETE /config/s3/{id}                         — pbs_s3_client_delete     (MUTATION, MEDIUM)
  PUT    /admin/s3/{s3-endpoint-id}/check        — pbs_s3_check             (MUTATION, LOW — PUT verb, non-mutating)
  PUT    /admin/s3/{s3-endpoint-id}/reset-counters — pbs_s3_reset_counters  (MUTATION, LOW)
  POST   /config/encryption-keys                 — pbs_encryption_key_create (MUTATION, MEDIUM)
  DELETE /config/encryption-keys/{id}            — pbs_encryption_key_delete (MUTATION, HIGH)
  POST   /config/encryption-keys/{id}            — pbs_encryption_key_toggle_archive (MUTATION, MEDIUM)

NOT BUILT: `GET /admin/s3/{s3-endpoint-id}` (no further path segment) is a "Directory index."
stub (`returns: null`, `additionalProperties: true`) — the SAME shape as `/tape/media/list/{uuid}`
(Wave 4d): a bare API-tree pointer to its own children (`check`, `reset-counters`), not a real
data endpoint. Matches that precedent; not built as a tool here.

SCHEMA-VERIFIED FACTS (binding on this build — from the live schema, not memory):

  1. **GET /config/s3[/{id}] responses are explicitly typed "S3 client configuration properties
     without secret."** `secret-key` NEVER appears in ANY read response (list or single) —
     confirmed field-by-field against both response shapes. `access-key` DOES appear UNREDACTED
     in every read response — schema evidence that PBS itself treats access-key as a non-secret
     identifier (AWS convention: the access-key ID identifies an account/credential-pair, the
     secret-key is the actual credential). **Decision (per the task's explicit "decide and
     document" instruction): `access-key` is NOT redacted anywhere in this module's Plan/ledger
     surfaces; `secret-key` is ALWAYS redacted** (masked `"[redacted]"` before entering ANY Plan
     field), forwarded RAW to the live PBS API only on `confirm=True` (the mutation must actually
     work) — only the PLAN/PROVE surfaces are scrubbed.
  2. **`put-rate-limit` appears in EVERY read response's item shape but is NOT a settable
     parameter on either POST or PUT /config/s3[/{id}]** — confirmed missing from both parameter
     schemas (only present under `returns`). This module does not expose a `put_rate_limit` tool
     parameter on create/update since the schema offers no way to set it here (likely
     read-only/computed, or set via an endpoint this wave does not build) — not invented.
  3. **PUT /config/s3/{id} carries BOTH a `digest` (SHA256 hex) optimistic-lock AND a `delete`
     enum** (`port`, `region`, `fingerprint`, `path-style`, `rate-in`, `burst-in`, `rate-out`,
     `burst-out`, `provider-quirks`) — `access-key`/`secret-key`/`endpoint`/`id` are notably NOT
     in the deletable set (rotate them by supplying a new value; they can never be cleared to
     empty via `delete`). `delete` is passed through un-validated against its own enum, matching
     the established "pass the list through, let the live API enforce its own enum" convention
     (`pbs_tape_media.py`/`pbs_tape_config.py`).
  4. **The `{id}` PATH PARAMETER on GET/PUT/DELETE /config/s3/{id} is described as "Job ID." in
     the live schema** — a copy-paste artifact from PBS's own job-id schema fragment, confirmed
     on all three verbs. The FORMAT (3-32 chars, `^[A-Za-z0-9_][A-Za-z0-9._-]*$`) is unaffected —
     purely a cosmetic schema-authoring quirk, noted for completeness (same "genuine artifact,
     not consequential" category as prior waves' returns-null-despite-real-data quirks).
  5. **`PUT /admin/s3/{s3-endpoint-id}/check` and `PUT .../reset-counters` share an IDENTICAL
     parameter shape**: `bucket` (REQUIRED, 3-63 chars, no pattern given — only length bounds),
     `s3-endpoint-id` (path, REQUIRED, same id shape as /config/s3), `store-prefix` (optional,
     NO length bound stated at all). BOTH declare `returns: null`. NEITHER carries a `digest`
     param — confirmed absent from both (unlike the CONFIG-plane PUT, which does carry one).
     `check` requires `Sys.Modify` privilege (not `Sys.Audit`, despite reading like a pure sanity
     probe) — PBS's OWN permission model treats it as privileged, reinforcing fact #6 below.
  6. **`check`'s own description — "Perform basic sanity check for given s3 client
     configuration" — makes a REAL outbound network call to the configured S3 endpoint using its
     stored credentials.** Genuinely non-mutating from PBS's OWN config-state perspective
     (nothing in `/config/s3` changes, and the schema's `returns: null` confirms nothing comes
     back), but NOT side-effect-free: it exercises live S3 credentials against a third-party
     target (Smoke-confirm whether it also attempts a write probe — the `Sys.Modify` requirement
     in fact #5 is circumstantial evidence it may). **Design decision, argued against BOTH
     candidate precedents rather than silently picked (per the task's explicit instruction):**
     (a) `pbs_tape_media_list`'s `update_status` default-flip (Wave 4d) — that tool stayed a
     bare, UNGATED read because it has a genuinely SAFE DEFAULT (`update_status=False`) that
     avoids its own side effect on a call-by-call basis; `check` has NO such safe mode — every
     invocation's entire purpose IS the live probe, so there is no default to flip toward safety.
     (b) `pbs_notification_target_test` (Wave 3a) — a tool that ALSO performs a real, non-PBS-
     config-mutating EXTERNAL action (sends a real notification) and IS confirm-gated as a
     MUTATION despite leaving no trace in PBS's own persisted config. `check` matches (b), not
     (a): it is **PLAN-gated + confirm-gated exactly like every mutation on this server** —
     NOT listed in `_READ_ONLY_TOOLS` — RISK_LOW (no PBS state changes, but a real external
     network operation using credentials PBS holds).
  7. **`reset-counters`'s own description states plainly what it does**: "Reset the S3 request
     counters for matching endpoint, bucket or datastore (if prefix is given)." A REAL mutation
     of observability-only state (request counters), not of any data or durable config — RISK_LOW,
     PLAN-gated + confirm-gated like every mutation. Honest framing, verbatim per the campaign's
     own instruction: "resets observability counters, not data."
  8. **`/config/encryption-keys` (client-side encryption key REGISTRY) is a MATERIALLY SIMPLER
     plane than the tape-encryption-keys plane (Wave 4b) despite the similar name** — confirmed
     field-by-field against the live schema, not assumed from the tape precedent: `POST` accepts
     ONLY `id` (CALLER-CHOSEN, NOT server-generated — a real divergence from tape's
     server-generated-fingerprint identity model) and an OPTIONAL `key` (an already-formed key
     blob to import — "Use provided key instead of creating new one" — with NO length bound
     stated at all, unlike tape's declared 300-600 char bound). **There is NO `password`/`hint`/
     `kdf` parameter on this endpoint AT ALL** — `hint`/`kdf`/`fingerprint` appear only in READ
     responses (all marked `optional`), presumably populated from metadata embedded within an
     imported `key` blob, or left absent for a freshly server-generated key. This module does not
     invent settable parameters the schema doesn't offer.
  9. **POST /config/encryption-keys declares `returns: null`** — genuinely NO fingerprint or key
     material comes back. This is a real divergence from BOTH the task brief's own framing
     ("what does it RETURN per schema — fingerprint? key?") AND the tape plane's create (which
     DOES return a bare fingerprint string, Wave 4b fact #10). Since the `id` was caller-chosen
     in the request, nothing new needs to be surfaced to identify the created key;
     `pbs_encryption_key_list` is how a caller inspects the resulting `fingerprint`/`hint`/`kdf`
     afterward (which may itself be absent — `fingerprint` is `optional` even in the read shape).
  10. **There is NO individual GET for a single encryption key** — `/config/encryption-keys/{id}`
      supports only `DELETE` and `POST` (toggle-archive); confirmed no `GET` method is registered
      at that path. Only the collection LIST exists. `plan_encryption_key_delete`/
      `plan_encryption_key_toggle_archive` are therefore deliberately PURE (no CAPTURE) rather
      than fetching+filtering the full list for one entry — the same "don't pull a bigger read
      than the mutation needs" reasoning already established (Wave 4d design note); both tool
      docstrings direct the caller to check `pbs_encryption_key_list` themselves first.
  11. **`DELETE /config/encryption-keys/{id}`'s own description is bare — "Remove encryption
      key." — with NO explicit consequence language**, unlike the tape-encryption-keys plane's
      verbatim PBS warning ("you can no longer access tapes using this key.", Wave 4b) reused
      there. This module does NOT invent PBS-stated wording it never gave — see the RISK RATING
      section for the full honesty framing, matching the campaign's Wave 4c "never claim
      schema-verified what the schema doesn't say" discipline.
  12. **`POST /config/encryption-keys/{id}` ("toggle the archive state ... archived keys are no
      longer usable to encrypt contents") DOES state a real, specific consequence**: archiving
      blocks the key from being used to encrypt NEW content going forward. The schema's own
      wording says nothing about DEcryption of already-encrypted data — this module does not
      claim (nor deny) that archived keys remain usable to decrypt, since PBS's own description
      is silent on that question.
  13. **Both `/config/encryption-keys/{id}` mutations (DELETE, POST-toggle) carry an optional
      `digest` (SHA256 hex) optimistic-lock** — confirmed on both. `/config/encryption-keys`
      (collection POST) carries NO digest (a fresh resource being created, nothing to lock
      against yet) — same absence-is-expected reasoning as every CREATE across this codebase.

RISK RATING (module-specific reasoning):
  - **s3_client_create = RISK_MEDIUM** — NOT the LOW rating a naive "additive config" reading
    might suggest (mirrors `pbs_tape_pool_create`'s LOW). Instead this mirrors
    `pbs_remote_create`'s MEDIUM rating (`pbs_config.py`): both create a PERSISTENT
    CREDENTIAL-BEARING entry (access-key + secret-key here; auth-id + password there) — a
    materially different risk class than pure policy/identifier config.
  - **s3_client_update = RISK_MEDIUM**: rotating credentials/endpoint/region can silently break
    whatever datastore/sync configuration already depends on this s3-endpoint-id — mirrors
    `pbs_remote_update`'s MEDIUM reasoning ("updating credentials or host can break sync jobs").
  - **s3_client_delete = RISK_MEDIUM**: mirrors `pbs_remote_delete` exactly — removes a
    credential-bearing config entry; anything referencing this s3-endpoint-id (a datastore's S3
    tier, a sync target) breaks until re-pointed; the credential itself cannot be retrieved once
    deleted.
  - **s3_check = RISK_LOW**: see fact #6 — no PBS state changes; a real but low-consequence
    external network probe.
  - **s3_reset_counters = RISK_LOW**: see fact #7 — resets observability counters only.
  - **encryption_key_create = RISK_MEDIUM**: creates a credential controlling future client-side
    encryption capability — mirrors `pve_token_create`/`plan_tape_key_create`'s MEDIUM rating
    ("creates a credential — cannot be retrieved after creation" in spirit; here nothing is
    RETURNED at all per fact #9, so there is doubly nothing to retrieve later).
  - **encryption_key_delete = RISK_HIGH — INFERRED, not schema-stated** (fact #11): PBS's own
    description here is bare, unlike tape's explicit warning. Rated HIGH anyway because losing
    an encryption-key registration's only tracked copy is categorically severe IF no independent
    copy of the key material survives elsewhere (the client machine that used it, an exported
    backup of the key blob, etc.) — the WORST-CASE consequence (irrecoverable data) is severe
    even though PBS's schema does not confirm this consequence the way tape's did. Smoke-confirm
    before treating "backups become unreadable" as a PBS-side-verified fact for THIS plane the
    way it is for tape's.
  - **encryption_key_toggle_archive = RISK_MEDIUM**: reversible (toggle again to un-archive) but
    can silently break automation that expects to keep encrypting NEW content with this key until
    someone notices — mirrors `pbs_tape_media_status_set`'s MEDIUM reasoning (fully reversible,
    still a real operational risk via silent failure).

Taint:
  - **`pbs_s3_client_list`/`pbs_s3_client_get` = REVIEWED_TRUSTED**: operator-authored config;
    `access-key` is an identifier, not attacker-shapeable free text (fact #1); `secret-key` never
    appears in any read response.
  - **`pbs_s3_list_buckets` = ADVERSARIAL — argued explicitly against the `pbs_acme_tos`
    precedent per the task's instruction, not silently decided.** Unlike `pbs_acme_tos` (which
    fetches a CALLER-CHOSEN arbitrary directory URL), the TARGET here is OPERATOR-CONFIGURED — an
    existing `s3-endpoint-id` the operator already trusted enough to register (requiring
    `Sys.Modify` to create). However, `taint.py`'s own stated rule is that **classification is by
    CONTENT CHANNEL, not by who chose the target** ("Classification is by CHANNEL, not
    read-vs-mutation"): the RETURNED bucket names are authored by whoever controls that EXTERNAL
    S3 account at read-time — not by Proxmox, not by the local operator's config, but by the
    remote provider/account. This is the same class of externally-authored content that lands
    `pve_storage_content`/`pbs_snapshots_list` in `ADVERSARIAL_TOOLS` despite THEIR OWN targets
    also being operator-configured storage, not caller-chosen. A compromised or malicious
    S3-compatible endpoint could return adversarial bucket names in the response. This diverges
    from `pbs_acme_tos`'s own rationale (caller-controlled TARGET) but lands at the SAME
    ADVERSARIAL classification via a different, argued path (externally-authored CONTENT) — bias
    conservative per `taint.py`'s stated policy ("classify as adversarial when unsure").
  - **`pbs_s3_check`/`pbs_s3_reset_counters` = REVIEWED_TRUSTED**: both declare `returns: null`
    (fact #5) — no content channel exists to classify at all.
  - **`pbs_s3_client_create`/`update`/`delete` = REVIEWED_TRUSTED**: opaque `null` returns, no
    content.
  - **`pbs_encryption_key_list` = REVIEWED_TRUSTED**: operator/import-authored metadata
    (id/hint/kdf/fingerprint/created/modified/path/archived-at) — no guest/attacker channel.
  - **`pbs_encryption_key_create`/`delete`/`toggle_archive` = REVIEWED_TRUSTED**: `null` returns.

VERIFIED live shapes: None — all backend functions carry "Smoke-confirm:" comments; every shape
here is schema-derived, not live-proven against a running PBS with real S3/encryption-key
config.
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

# S3 client config id AND encryption key id — BYTE-IDENTICAL shape per the live schema
# (`^[A-Za-z0-9_][A-Za-z0-9._-]*$`, 3-32 chars) — one shared validator within this module (both
# fields live in this same module, unlike a cross-module-family reuse decision).
_ID_RE = re.compile(r"^(?:[A-Za-z0-9_][A-Za-z0-9._-]*)\Z")

# S3 endpoint hostname/IPv4/IPv6, optionally templated with {{bucket}}./{{region}} — copied
# VERBATIM from the live schema's own pattern (not hand-derived), re-anchored to \Z per this
# codebase's convention. Preserves a genuine schema quirk faithfully rather than "fixing" it: the
# leading alternative `(^\{\{bucket\}\}\.)*` contains an internal `^` mid-pattern, which (no
# re.MULTILINE) behaves as "start-of-string" even mid-alternation in both the JS source schema
# and this Python re — same "preserve the schema's own quirk" practice as Wave 4d's store-mapping
# validator, which followed the schema's formal constraint over its own self-contradictory prose.
_ENDPOINT_RE = re.compile(
    r"^(?:(^\{\{bucket\}\}\.)*(?:(?:((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?)|\{\{region\}\})\.)*(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?))|(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){6})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:::(?:(?:[0-9a-fA-F]{1,4}):){5})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){4})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,1}(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){3})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,2}(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){2})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,3}(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){1})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,4}(?:[0-9a-fA-F]{1,4}))?::)(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,5}(?:[0-9a-fA-F]{1,4}))?::)(?:[0-9a-fA-F]{1,4}))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,6}(?:[0-9a-fA-F]{1,4}))?::)))))\Z"
)

# region: pattern copied verbatim from the schema (lowercase alnum/underscore/hyphen, min 2
# chars implied by the pattern itself); maxLength 32 is a SEPARATE schema attribute, enforced here
# explicitly since the pattern alone doesn't bound the upper length.
_REGION_RE = re.compile(r"^[_a-z\d][-_a-z\d]+\Z")

# X509 certificate fingerprint (sha256) — 32 colon-separated hex byte-pairs. Byte-identical shape
# to the tape-encryption-keys plane's own fingerprint (Wave 4b), but a genuinely different field
# (a TLS cert pin here, a key identity there) — a fresh copy per this module's own convention,
# matching every other PBS module's "keep your own copy" practice even for identical shapes.
_FINGERPRINT_RE = re.compile(r"^(?:[0-9a-fA-F][0-9a-fA-F])(?::[0-9a-fA-F][0-9a-fA-F]){31}\Z")

# Complete no-control-characters class, shared by every free-text-ish field on this plane that the
# schema gives no pattern for (bucket, store-prefix, rate/burst byte-size strings).
_NO_CONTROL_RE = re.compile(r"^[^\x00-\x1f\x7f]*\Z")

_VALID_PROVIDER_QUIRKS = frozenset({"skip-if-none-match-header", "delete-objects-via-delete-object"})


def _check_id(value: str) -> str:
    s = str(value)
    if not (3 <= len(s) <= 32) or not _ID_RE.match(s):
        raise ProximoError(
            f"invalid id: {value!r} (must start alnum/underscore, then alnum/./_/-, 3-32 chars)"
        )
    return s


def _check_endpoint(value: str) -> str:
    s = str(value)
    if not _ENDPOINT_RE.match(s):
        raise ProximoError(
            f"invalid endpoint: {value!r} — expected a hostname, IPv4, IPv6, or a "
            "{{bucket}}./{{region}} templated hostname per the live PBS schema"
        )
    return s


def _check_region(value: str) -> str:
    s = str(value)
    if len(s) > 32 or not _REGION_RE.match(s):
        raise ProximoError(
            f"invalid region: {value!r} — lowercase alnum/underscore/hyphen, min 2 chars, "
            "<=32 chars"
        )
    return s


def _check_fingerprint(value: str) -> str:
    s = str(value)
    if not _FINGERPRINT_RE.match(s):
        raise ProximoError(
            f"invalid X509 fingerprint: {value!r} (expected 32 colon-separated hex byte-pairs — "
            "a formatted SHA-256)"
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


def _check_bucket(value: str) -> str:
    """3-63 chars per the schema's own length bounds; the schema gives NO character pattern at
    all for this field, so only the length bound + a defensive no-control-chars check apply
    (not an invented AWS-bucket-naming charset the schema doesn't state)."""
    return _check_no_control(value, "bucket", min_len=3, max_len=63)


def _check_store_prefix(value: str) -> str:
    """The schema imposes NO length bound on store-prefix at all — a deliberate
    stricter-than-schema 256-char cap is imposed here anyway (matches the established
    `pbs_tape_media.py` allocation/retention precedent for genuinely open schema strings), plus
    the standard no-control-chars check."""
    return _check_no_control(value, "store_prefix", min_len=0, max_len=256)


def _check_byte_size(value: str, field: str) -> str:
    """rate-in/rate-out/burst-in/burst-out: schema gives length bounds (1-64) but no character
    pattern ("Byte size with optional unit (B, KB, ..., KiB, ...)") — validated defensively
    (length + no control chars), not against an invented numeric-with-unit regex the schema
    doesn't provide."""
    return _check_no_control(value, field, min_len=1, max_len=64)


def _check_port(value: int) -> int:
    """The schema types `port` as a bare integer with NO bound at all. The 1-65535 bound here is
    the standard TCP port range — a defensive default, NOT a schema-stated constraint."""
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid port: {value!r} (must be an integer)") from exc
    if not (1 <= n <= 65535):
        raise ProximoError(f"invalid port: {value!r} — must be 1-65535 (standard TCP port range)")
    return n


def _check_provider_quirks(values) -> list[str]:
    """Validated against the closed enum (unlike the pass-through `delete` list on this same
    plane) — `provider-quirks` is a small, fully-documented closed set of STORED CONFIG VALUES
    worth catching a typo on, matching the `kdf`-style validated-closed-enum precedent rather
    than the `delete`-style pass-through-let-the-API-enforce-it precedent."""
    out = []
    for v in values:
        s = str(v)
        if s not in _VALID_PROVIDER_QUIRKS:
            raise ProximoError(
                f"invalid provider quirk: {v!r} (expected one of {sorted(_VALID_PROVIDER_QUIRKS)})"
            )
        out.append(s)
    return out


def _check_key_material(value: str) -> str:
    """encryption-keys' `key` param: schema gives NO length bound at all (a real divergence from
    the tape plane's declared 300-600 char bound, module docstring fact #8) — only a non-empty +
    no-control-chars check is applied; no bound is invented."""
    s = str(value)
    if not s or not _NO_CONTROL_RE.match(s):
        raise ProximoError("invalid key material: non-empty, no control characters required")
    return s


# Credential-shaped fields on this plane (module docstring fact #1, #8): `secret-key` (S3) and
# `key` (encryption-key import material). `access-key` is DELIBERATELY NOT here — see fact #1's
# decision.
_SECRET_KEYS = frozenset({"secret-key", "key"})


def _redact_secrets(d: dict) -> dict:
    """Mask credential-shaped fields before they enter a plan string or Plan.current — the
    shared `_validate.redact_secrets` mechanic over this plane's own `_SECRET_KEYS`."""
    return redact_secrets(d, _SECRET_KEYS)


def _s3_fields(
    access_key: str | None = None,
    secret_key: str | None = None,
    endpoint: str | None = None,
    region: str | None = None,
    fingerprint: str | None = None,
    port: int | None = None,
    path_style: bool | None = None,
    provider_quirks: list[str] | None = None,
    rate_in: str | None = None,
    rate_out: str | None = None,
    burst_in: str | None = None,
    burst_out: str | None = None,
) -> dict:
    """Shared field-assembly + validation for BOTH s3_client_create (where access_key/
    secret_key/endpoint are required — enforced by the caller's own signature, not here) and
    s3_client_update (where every field is optional). Builds a WIRE-hyphenated dict of whichever
    fields are not None. Mirrors `pbs_tape_jobs.py`'s `_job_extra_fields` sharing idiom."""
    data: dict = {}
    # Hygiene parity with every sibling free-text field (review finding, Wave 5a): control
    # chars rejected. Error messages for these two NEVER embed the value (secret-shaped).
    if access_key is not None:
        if not _NO_CONTROL_RE.match(str(access_key)):
            raise ProximoError("invalid access-key: contains control characters")
        data["access-key"] = str(access_key)
    if secret_key is not None:
        if not _NO_CONTROL_RE.match(str(secret_key)):
            raise ProximoError("invalid secret-key: contains control characters")
        data["secret-key"] = str(secret_key)
    if endpoint is not None:
        data["endpoint"] = _check_endpoint(endpoint)
    if region is not None:
        data["region"] = _check_region(region)
    if fingerprint is not None:
        data["fingerprint"] = _check_fingerprint(fingerprint)
    if port is not None:
        data["port"] = _check_port(port)
    if path_style is not None:
        data["path-style"] = bool(path_style)
    if provider_quirks is not None:
        data["provider-quirks"] = _check_provider_quirks(provider_quirks)
    if rate_in is not None:
        data["rate-in"] = _check_byte_size(rate_in, "rate_in")
    if rate_out is not None:
        data["rate-out"] = _check_byte_size(rate_out, "rate_out")
    if burst_in is not None:
        data["burst-in"] = _check_byte_size(burst_in, "burst_in")
    if burst_out is not None:
        data["burst-out"] = _check_byte_size(burst_out, "burst_out")
    return data


# ---------------------------------------------------------------------------
# Backend functions — reads, S3 client configs
# ---------------------------------------------------------------------------

def s3_client_list(api: PbsBackend) -> list[dict]:
    """GET /config/s3 — list all S3 client configurations. Response items are "without secret"
    (module docstring fact #1) — access-key present unredacted, secret-key never present.
    Stripped defensively anyway (pbs_config.remote_get idiom — never trust the documented
    shape blindly; review finding, Wave 5a). Smoke-confirm: response shape."""
    items = api._get("/config/s3") or []
    return [{k: v for k, v in it.items() if k != "secret-key"}
            for it in items if isinstance(it, dict)]


def s3_client_get(api: PbsBackend, s3_id: str) -> dict:
    """GET /config/s3/{id} — one S3 client config's full (secret-free) shape, stripped
    defensively anyway (review finding, Wave 5a). Smoke-confirm: response shape."""
    s3_id = _check_id(s3_id)
    data = api._get(f"/config/s3/{s3_id}") or {}
    return {k: v for k, v in data.items() if k != "secret-key"}


def s3_list_buckets(api: PbsBackend, s3_id: str) -> list:
    """GET /config/s3/{id}/list-buckets — LIVE outbound call to the configured S3 endpoint;
    returns the bucket names it can see. ADVERSARIAL (module docstring's Taint section — argued
    against the pbs_acme_tos precedent). Schema declares `returns: null` despite the description
    implying real data — best-effort passthrough. Smoke-confirm: response shape."""
    s3_id = _check_id(s3_id)
    return api._get(f"/config/s3/{s3_id}/list-buckets") or []


# ---------------------------------------------------------------------------
# Backend functions — mutations, S3 client configs
# ---------------------------------------------------------------------------

def s3_client_create(
    api: PbsBackend,
    s3_id: str,
    endpoint: str,
    access_key: str,
    secret_key: str,
    region: str | None = None,
    fingerprint: str | None = None,
    port: int | None = None,
    path_style: bool | None = None,
    provider_quirks: list[str] | None = None,
    rate_in: str | None = None,
    rate_out: str | None = None,
    burst_in: str | None = None,
    burst_out: str | None = None,
) -> None:
    """POST /config/s3 — id/endpoint/access-key/secret-key REQUIRED, all else optional. Returns
    null (synchronous). MUTATION — confirm-gated + audited at the server layer. secret-key is
    forwarded RAW here (the create must actually work) but never recorded to the ledger — see
    plan_s3_client_create's redaction."""
    s3_id = _check_id(s3_id)
    data: dict = {"id": s3_id, "endpoint": _check_endpoint(endpoint),
                  "access-key": str(access_key), "secret-key": str(secret_key)}
    data.update(_s3_fields(
        region=region, fingerprint=fingerprint, port=port, path_style=path_style,
        provider_quirks=provider_quirks, rate_in=rate_in, rate_out=rate_out,
        burst_in=burst_in, burst_out=burst_out,
    ))
    api._post("/config/s3", data)


def s3_client_update(
    api: PbsBackend,
    s3_id: str,
    access_key: str | None = None,
    secret_key: str | None = None,
    endpoint: str | None = None,
    region: str | None = None,
    fingerprint: str | None = None,
    port: int | None = None,
    path_style: bool | None = None,
    provider_quirks: list[str] | None = None,
    rate_in: str | None = None,
    rate_out: str | None = None,
    burst_in: str | None = None,
    burst_out: str | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> None:
    """PUT /config/s3/{id} — all body fields optional. Returns null (synchronous). MUTATION —
    confirm-gated + audited at the server layer. secret-key (if given) is forwarded RAW here but
    never recorded to the ledger — see plan_s3_client_update's redaction."""
    s3_id = _check_id(s3_id)
    data = _s3_fields(
        access_key=access_key, secret_key=secret_key, endpoint=endpoint, region=region,
        fingerprint=fingerprint, port=port, path_style=path_style,
        provider_quirks=provider_quirks, rate_in=rate_in, rate_out=rate_out,
        burst_in=burst_in, burst_out=burst_out,
    )
    if digest is not None:
        data["digest"] = _check_digest(digest)
    if delete is not None:
        data["delete"] = _check_delete_list(delete)
    api._put(f"/config/s3/{s3_id}", data)


def s3_client_delete(api: PbsBackend, s3_id: str, digest: str | None = None) -> None:
    """DELETE /config/s3/{id}. Returns null (synchronous). MUTATION — confirm-gated + audited at
    the server layer."""
    s3_id = _check_id(s3_id)
    params: dict = {}
    if digest is not None:
        params["digest"] = _check_digest(digest)
    api._delete(f"/config/s3/{s3_id}", params=params)


def s3_check(api: PbsBackend, s3_id: str, bucket: str, store_prefix: str | None = None) -> None:
    """PUT /admin/s3/{s3-endpoint-id}/check — a read-shaped sanity probe behind a PUT verb
    (module docstring fact #6). No digest param exists on this endpoint. Returns null. MUTATION —
    confirm-gated + audited at the server layer despite touching NO PBS config (verb/effect
    reasoning in the module docstring)."""
    s3_id = _check_id(s3_id)
    data: dict = {"bucket": _check_bucket(bucket)}
    if store_prefix is not None:
        data["store-prefix"] = _check_store_prefix(store_prefix)
    api._put(f"/admin/s3/{s3_id}/check", data)


def s3_reset_counters(api: PbsBackend, s3_id: str, bucket: str, store_prefix: str | None = None) -> None:
    """PUT /admin/s3/{s3-endpoint-id}/reset-counters — resets S3 request counters for the
    matching endpoint/bucket/prefix. No digest param exists on this endpoint. Returns null.
    MUTATION — confirm-gated + audited at the server layer."""
    s3_id = _check_id(s3_id)
    data: dict = {"bucket": _check_bucket(bucket)}
    if store_prefix is not None:
        data["store-prefix"] = _check_store_prefix(store_prefix)
    api._put(f"/admin/s3/{s3_id}/reset-counters", data)


# ---------------------------------------------------------------------------
# Backend functions — reads + mutations, Client encryption keys
# ---------------------------------------------------------------------------

def encryption_key_list(api: PbsBackend, include_archived: bool = False) -> list[dict]:
    """GET /config/encryption-keys — list registered client encryption keys. `include_archived`
    defaults False, matching PBS's own upstream default. REVIEWED_TRUSTED: operator/import-
    authored metadata, no key material or password ever returned (module docstring fact #8).
    Smoke-confirm: response shape."""
    params = {"include-archived": bool(include_archived)}
    return api._get("/config/encryption-keys", params=params) or []


def encryption_key_create(api: PbsBackend, key_id: str, key: str | None = None) -> None:
    """POST /config/encryption-keys — `id` (caller-chosen) REQUIRED; `key` (import material)
    OPTIONAL — omit to have PBS generate a fresh key. Returns null (module docstring fact #9 — a
    real divergence from the tape plane's fingerprint-returning create). MUTATION — confirm-gated
    + audited at the server layer. `key` is forwarded RAW here (the create must actually work)
    but never recorded to the ledger — see plan_encryption_key_create's redaction."""
    key_id = _check_id(key_id)
    data: dict = {"id": key_id}
    if key is not None:
        data["key"] = _check_key_material(key)
    api._post("/config/encryption-keys", data)


def encryption_key_delete(api: PbsBackend, key_id: str, digest: str | None = None) -> None:
    """DELETE /config/encryption-keys/{id}. PBS's own description is bare — "Remove encryption
    key." — no explicit consequence language (module docstring fact #11). Returns null. MUTATION
    — confirm-gated + audited at the server layer."""
    key_id = _check_id(key_id)
    params: dict = {}
    if digest is not None:
        params["digest"] = _check_digest(digest)
    api._delete(f"/config/encryption-keys/{key_id}", params=params)


def encryption_key_toggle_archive(api: PbsBackend, key_id: str, digest: str | None = None) -> None:
    """POST /config/encryption-keys/{id} — toggle the archive flag; archived keys can no longer
    encrypt NEW content (module docstring fact #12 — PBS's own stated consequence, verbatim in
    spirit). Returns null. MUTATION — confirm-gated + audited at the server layer."""
    key_id = _check_id(key_id)
    data: dict = {}
    if digest is not None:
        data["digest"] = _check_digest(digest)
    api._post(f"/config/encryption-keys/{key_id}", data)


# ---------------------------------------------------------------------------
# Plan factories — S3 client configs
# ---------------------------------------------------------------------------

def plan_s3_client_create(
    s3_id: str,
    endpoint: str,
    access_key: str,
    secret_key: str,
    region: str | None = None,
    fingerprint: str | None = None,
    port: int | None = None,
    path_style: bool | None = None,
    provider_quirks: list[str] | None = None,
    rate_in: str | None = None,
    rate_out: str | None = None,
    burst_in: str | None = None,
    burst_out: str | None = None,
) -> Plan:
    """Plan creating a PBS S3 client configuration. RISK_MEDIUM (module docstring's RISK RATING
    note — mirrors pbs_remote_create, NOT pbs_tape_pool_create: this creates a PERSISTENT
    CREDENTIAL-BEARING entry). PURE — no API read. SECRET CONTRACT: secret-key is masked to
    '[redacted]' before entering the Plan; access-key is DELIBERATELY NOT redacted (module
    docstring fact #1's decision — AWS convention, schema-confirmed non-secret)."""
    s3_id = _check_id(s3_id)
    _check_endpoint(endpoint)
    extra = _s3_fields(
        region=region, fingerprint=fingerprint, port=port, path_style=path_style,
        provider_quirks=provider_quirks, rate_in=rate_in, rate_out=rate_out,
        burst_in=burst_in, burst_out=burst_out,
    )
    kw = {"id": s3_id, "endpoint": endpoint, "access-key": access_key,
          "secret-key": secret_key, **extra}
    return Plan(
        action="pbs_s3_client_create",
        target=f"pbs/config/s3/{s3_id}",
        change=f"create PBS S3 client config {s3_id!r}: {_redact_secrets(kw)}",
        current={},
        blast_radius=[
            f"creates a new S3 client config {s3_id!r} with a stored access-key/secret-key "
            "pair — a persistent credential entry PBS can use to authenticate to the "
            "configured endpoint; no existing config is affected",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "creates a persistent credential-bearing entry — grants PBS the ability to "
            "authenticate to the specified S3 endpoint with the given access/secret key pair",
        ],
        note=(
            "secret-key is UNCONDITIONALLY redacted — only \"[redacted]\" appears in plans and "
            "the audit ledger; access-key is NOT redacted (schema-confirmed non-secret "
            "identifier). No snapshot primitive on this plane. Config is re-creatable — delete "
            "with pbs_s3_client_delete and re-create to correct a mistake."
        ),
    )


def plan_s3_client_update(
    api: PbsBackend,
    s3_id: str,
    access_key: str | None = None,
    secret_key: str | None = None,
    endpoint: str | None = None,
    region: str | None = None,
    fingerprint: str | None = None,
    port: int | None = None,
    path_style: bool | None = None,
    provider_quirks: list[str] | None = None,
    rate_in: str | None = None,
    rate_out: str | None = None,
    burst_in: str | None = None,
    burst_out: str | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> Plan:
    """Plan updating a PBS S3 client configuration. CAPTURE: reads current config (secret-free
    per the schema — module docstring fact #1 — redacted defensively regardless, same
    defense-in-depth idiom as pbs_tape_media.py's CAPTURE reads)."""
    s3_id = _check_id(s3_id)
    kw = _s3_fields(
        access_key=access_key, secret_key=secret_key, endpoint=endpoint, region=region,
        fingerprint=fingerprint, port=port, path_style=path_style,
        provider_quirks=provider_quirks, rate_in=rate_in, rate_out=rate_out,
        burst_in=burst_in, burst_out=burst_out,
    )
    if digest is not None:
        _check_digest(digest)
    current = _redact_secrets(s3_client_get(api, s3_id))
    # `is not None`, NOT truthiness — but delete=[] is REJECTED, not disclosed: httpx's form
    # encoding drops an empty-list value entirely, so a disclosed "delete=[]" would never match
    # what confirm=True actually sends (Wave 5b review finding 1; this was the site the finding
    # traced the bug against directly).
    display = dict(_redact_secrets(kw))
    if delete is not None:
        display["delete"] = _check_delete_list(delete)
    change_desc = ", ".join(f"{k}={v!r}" for k, v in display.items()) if display else "no fields changed"
    return Plan(
        action="pbs_s3_client_update",
        target=f"pbs/config/s3/{s3_id}",
        change=f"update PBS S3 client config {s3_id!r}: {change_desc}",
        current=current,
        blast_radius=[
            f"S3 client config {s3_id!r}: rotating credentials/endpoint/region can silently "
            "break whatever datastore or sync configuration already depends on this "
            "s3-endpoint-id until the change is verified with pbs_s3_check",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "updating credentials or endpoint/region can break dependent datastore/sync "
            "configuration — mirrors pbs_remote_update's reasoning",
        ],
        note=(
            "secret-key (if given) is UNCONDITIONALLY redacted here; access-key is not "
            "(schema-confirmed non-secret). No snapshot primitive on this plane. Current "
            "config captured above (secret-free) — re-apply it to revert."
        ),
    )


def plan_s3_client_delete(api: PbsBackend, s3_id: str, digest: str | None = None) -> Plan:
    """Plan deleting a PBS S3 client configuration. CAPTURE: reads current config (secret-free).
    RISK_MEDIUM — mirrors pbs_remote_delete exactly."""
    s3_id = _check_id(s3_id)
    if digest is not None:
        _check_digest(digest)
    current = _redact_secrets(s3_client_get(api, s3_id))
    return Plan(
        action="pbs_s3_client_delete",
        target=f"pbs/config/s3/{s3_id}",
        change=f"delete PBS S3 client config {s3_id!r}",
        current=current,
        blast_radius=[
            f"removes S3 client config {s3_id!r} and its stored access-key/secret-key pair — "
            "the credential entry cannot be retrieved after deletion",
            "any datastore or sync configuration referencing this s3-endpoint-id breaks "
            "immediately",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "removes a credential-bearing config entry — dependent datastore/sync "
            "configuration breaks until re-pointed",
        ],
        note=(
            "No snapshot primitive on this plane. Config is re-creatable — re-create with "
            "pbs_s3_client_create using the captured non-secret fields above (a fresh "
            "secret-key must be supplied; the old one cannot be recovered)."
        ),
    )


def plan_s3_check(s3_id: str, bucket: str, store_prefix: str | None = None) -> Plan:
    """Plan running a live S3 sanity check. RISK_LOW (module docstring fact #6 — no PBS state
    changes, but a real external network operation). PURE — no API read."""
    s3_id = _check_id(s3_id)
    _check_bucket(bucket)
    if store_prefix is not None:
        _check_store_prefix(store_prefix)
    prefix_note = f", store_prefix={store_prefix!r}" if store_prefix is not None else ""
    return Plan(
        action="pbs_s3_check",
        target=f"pbs/admin/s3/{s3_id}/check/{bucket}",
        change=(
            f"perform a live sanity check of S3 client config {s3_id!r} against bucket "
            f"{bucket!r}{prefix_note}"
        ),
        current={},
        blast_radius=[
            f"makes a REAL outbound network call from PBS to the endpoint configured for "
            f"{s3_id!r}, using its stored access-key/secret-key — does NOT change any PBS "
            "config (returns null); PBS requires Sys.Modify privilege for this call, "
            "suggesting it may exercise write-capable operations against the bucket "
            "(Smoke-confirm — the schema does not say)",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "no PBS-side config or data is changed — the effect (if any) lands on the "
            "third-party S3 target, not on PBS itself",
        ],
        note=(
            "Confirm-gated despite being non-config-mutating (module docstring fact #6): this "
            "endpoint has NO safe default to fall back on the way pbs_tape_media_list's "
            "update_status=False does — every call's entire purpose is the live probe. No "
            "undo needed — nothing persists."
        ),
    )


def plan_s3_reset_counters(s3_id: str, bucket: str, store_prefix: str | None = None) -> Plan:
    """Plan resetting S3 request counters. RISK_LOW — resets observability counters, not data
    (module docstring fact #7, verbatim per the campaign's own instruction). PURE — no API read."""
    s3_id = _check_id(s3_id)
    _check_bucket(bucket)
    if store_prefix is not None:
        _check_store_prefix(store_prefix)
    prefix_note = f", store_prefix={store_prefix!r}" if store_prefix is not None else ""
    return Plan(
        action="pbs_s3_reset_counters",
        target=f"pbs/admin/s3/{s3_id}/reset-counters/{bucket}",
        change=f"reset S3 request counters for {s3_id!r} bucket {bucket!r}{prefix_note}",
        current={},
        blast_radius=[
            "resets observability counters (S3 request counts) for the matching endpoint/"
            "bucket/prefix — NOT data; no backup/config content is touched",
        ],
        risk=RISK_LOW,
        risk_reasons=["resets observability counters only — no data or config state changes"],
        note="No undo needed — counters simply resume accumulating from zero; harmless.",
    )


# ---------------------------------------------------------------------------
# Plan factories — Client encryption keys
# ---------------------------------------------------------------------------

def plan_encryption_key_create(key_id: str, key: str | None = None) -> Plan:
    """Plan creating a PBS client encryption key. RISK_MEDIUM (module docstring's RISK RATING
    note). PURE — no API read (the key doesn't exist yet; `id` is caller-chosen). SECRET
    CONTRACT: `key` is masked to '[redacted]' before entering the Plan; the RAW value is still
    forwarded to the live PBS API on confirm=True."""
    key_id = _check_id(key_id)
    if key is not None:
        _check_key_material(key)
    kw = {"id": key_id}
    if key is not None:
        kw["key"] = key
    return Plan(
        action="pbs_encryption_key_create",
        target=f"pbs/config/encryption-keys/{key_id}",
        change=f"create PBS client encryption key {key_id!r}: {_redact_secrets(kw)}",
        current={},
        blast_radius=[
            f"adds a new client encryption key {key_id!r} (additive — no existing key config "
            "is affected). Schema-verified: the create RETURNS NOTHING (module docstring fact "
            "#9) — check pbs_encryption_key_list afterward to see the assigned "
            "fingerprint/hint/kdf, if any.",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "creates a credential controlling future client-side encryption capability",
        ],
        note=(
            "key material (if supplied) is UNCONDITIONALLY redacted — only \"[redacted]\" "
            "appears in plans and the audit ledger. No rollback primitive — delete with "
            "pbs_encryption_key_delete to correct a mistake."
        ),
    )


def plan_encryption_key_delete(key_id: str, digest: str | None = None) -> Plan:
    """Plan deleting a PBS client encryption key. PURE — no individual GET exists on this plane
    (module docstring fact #10); check pbs_encryption_key_list yourself first. RISK_HIGH —
    INFERRED, not schema-stated (module docstring fact #11 / RISK RATING section): PBS's own
    description here is bare ('Remove encryption key.'), unlike the tape plane's explicit
    warning. Rated HIGH anyway given the worst-case severity of losing an encryption-key
    registration's only tracked copy."""
    key_id = _check_id(key_id)
    if digest is not None:
        _check_digest(digest)
    return Plan(
        action="pbs_encryption_key_delete",
        target=f"pbs/config/encryption-keys/{key_id}",
        change=f"delete PBS client encryption key {key_id!r}",
        current={},
        blast_radius=[
            f"removes encryption key {key_id!r}'s registration from PBS. PBS's OWN "
            "description here is bare ('Remove encryption key.') — it does NOT state that "
            "encrypted content becomes unreadable (unlike the tape-encryption-keys plane, "
            "which says so explicitly). INFERRED, not schema-verified: if this was the only "
            "tracked copy of the key material, content encrypted with it may become "
            "unrecoverable via tooling that looks the key up by this id — Smoke-confirm "
            "before treating this as PBS-confirmed the way tape's warning is.",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "irreversible removal of a credential registration whose worst-case consequence "
            "(unrecoverable encrypted data) is severe even though PBS's own schema does not "
            "confirm that consequence for this specific plane",
        ],
        note=(
            "NO UNDO. Double-check pbs_encryption_key_list for this key's current "
            "fingerprint/hint/kdf and confirm any independently-held copy of the key material "
            "before confirming this delete."
        ),
    )


def plan_encryption_key_toggle_archive(key_id: str, digest: str | None = None) -> Plan:
    """Plan toggling a PBS client encryption key's archive flag. PURE — no individual GET exists
    on this plane (module docstring fact #10); check pbs_encryption_key_list yourself first for
    the CURRENT archived state (toggling flips whatever it currently is). RISK_MEDIUM — reversible
    (toggle again), but automation relying on continued encryption with this key can silently
    start failing until noticed (module docstring's RISK RATING section)."""
    key_id = _check_id(key_id)
    if digest is not None:
        _check_digest(digest)
    return Plan(
        action="pbs_encryption_key_toggle_archive",
        target=f"pbs/config/encryption-keys/{key_id}",
        change=f"toggle archive state for PBS client encryption key {key_id!r}",
        current={},
        blast_radius=[
            f"flips key {key_id!r}'s archived flag — PBS's own wording: archived keys 'are no "
            "longer usable to encrypt contents' (new content only; PBS's description says "
            "nothing about decrypting existing content either way). Check "
            "pbs_encryption_key_list first to know which direction this toggle moves — "
            "archiving an ACTIVE key or un-archiving an ARCHIVED one.",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "reversible via calling this again, but automation expecting to keep encrypting "
            "NEW content with this key can silently start failing until someone notices",
        ],
        note="Reversible — call this tool again to flip the flag back.",
    )
