"""PBS S3 client configs + client encryption keys wrappers (Wave 5a, full-surface campaign) —
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 5 decomposition (PBS s3 + remainder)",
"5a — S3 + client encryption keys". See `proximo.pbs_s3` module docstring for the full endpoint
table, the schema-verified facts, and the risk-rating reasoning.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_s3 import (
    encryption_key_create,
    encryption_key_delete,
    encryption_key_list,
    encryption_key_toggle_archive,
    plan_encryption_key_create,
    plan_encryption_key_delete,
    plan_encryption_key_toggle_archive,
    plan_s3_check,
    plan_s3_client_create,
    plan_s3_client_delete,
    plan_s3_client_update,
    plan_s3_reset_counters,
    s3_check,
    s3_client_create,
    s3_client_delete,
    s3_client_get,
    s3_client_list,
    s3_client_update,
    s3_list_buckets,
    s3_reset_counters,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Reads: S3 client configs ---

@tool()
def pbs_s3_client_list() -> list[dict]:
    """READ-ONLY: list all PBS S3 client configurations. Responses are "without secret" per the
    live schema — access-key present unredacted, secret-key never returned. Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_s3_client_list", "pbs/config/s3", lambda: s3_client_list(pbs))


@tool()
def pbs_s3_client_get(
    s3_id: Annotated[str, Field(description="S3 client config id (3-32 chars, alnum/underscore start, then alnum/./_/-).")],
) -> dict:
    """READ-ONLY: get one PBS S3 client config's full (secret-free) shape. Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_s3_client_get", f"pbs/config/s3/{s3_id}",
                    lambda: s3_client_get(pbs, s3_id))


@tool()
def pbs_s3_list_buckets(
    s3_id: Annotated[str, Field(description="S3 client config id to probe.")],
) -> list:
    """READ-ONLY: list buckets accessible by the given S3 client configuration. Makes a LIVE
    outbound call from PBS to the configured S3 endpoint. ADVERSARIAL: the returned bucket names
    are authored by whoever controls the remote S3 account — the target is operator-configured,
    but the CONTENT is external (see proximo.pbs_s3 module docstring's Taint section for the full
    argument against the pbs_acme_tos precedent). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_s3_list_buckets", f"pbs/config/s3/{s3_id}/list-buckets",
                    lambda: s3_list_buckets(pbs, s3_id))


# --- Reads: Client encryption keys ---

@tool()
def pbs_encryption_key_list(
    include_archived: Annotated[bool, Field(description="Also list archived keys. Defaults False, matching PBS's own upstream default.")] = False,
) -> list[dict]:
    """READ-ONLY: list registered PBS client encryption keys. REVIEWED_TRUSTED: operator/import-
    authored metadata only (id/fingerprint/hint/kdf/created/modified/path/archived-at) — key
    material and any password are NEVER returned by this endpoint. There is NO individual GET on
    this plane — this list is the only read. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_encryption_key_list", "pbs/config/encryption-keys",
                    lambda: encryption_key_list(pbs, include_archived))


# --- Mutations: S3 client configs ---

@tool()
def pbs_s3_client_create(
    s3_id: Annotated[str, Field(description="New S3 client config id (3-32 chars, alnum/underscore start, then alnum/./_/-).")],
    endpoint: Annotated[str, Field(description="Endpoint hostname/IPv4/IPv6 to access the S3 object store (may use {{bucket}}./{{region}} templating).")],
    access_key: Annotated[str, Field(description="Access key for the S3 object store. NOT treated as secret — PBS itself returns this unredacted on every read (AWS convention: identifies the credential pair, is not itself the credential).")],
    secret_key: Annotated[str, Field(description="Secret key for the S3 object store. SECRET — never written to the audit ledger or the dry-run PLAN.")],
    region: Annotated[str | None, Field(description="Region to access the S3 object store (lowercase alnum/underscore/hyphen, <=32 chars).")] = None,
    fingerprint: Annotated[str | None, Field(description="X509 certificate fingerprint (sha256, 32 colon-separated hex byte-pairs) to pin the endpoint's TLS cert.")] = None,
    port: Annotated[int | None, Field(description="Port to access the S3 object store (1-65535).")] = None,
    path_style: Annotated[bool | None, Field(description="Use path-style bucket addressing instead of vhost-style.")] = None,
    provider_quirks: Annotated[list[str] | None, Field(description="Provider-specific implementation quirks: 'skip-if-none-match-header' and/or 'delete-objects-via-delete-object'.")] = None,
    rate_in: Annotated[str | None, Field(description="Inbound rate limit as a byte size with unit, e.g. '10MB' (1-64 chars).")] = None,
    rate_out: Annotated[str | None, Field(description="Outbound rate limit as a byte size with unit (1-64 chars).")] = None,
    burst_in: Annotated[str | None, Field(description="Inbound burst limit as a byte size with unit (1-64 chars).")] = None,
    burst_out: Annotated[str | None, Field(description="Outbound burst limit as a byte size with unit (1-64 chars).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PBS S3 client configuration.

    RISK_MEDIUM: creates a PERSISTENT CREDENTIAL-BEARING entry (mirrors pbs_remote_create, not
    the LOW-rated additive-config pattern of e.g. pbs_tape_pool_create). SECRET CONTRACT:
    secret-key is NEVER written to the audit ledger or the dry-run PLAN — it is forwarded RAW
    only to the real PBS API on confirm=True (the create must actually work). access-key is NOT
    redacted (schema-confirmed non-secret). Dry-run by default (returns a PLAN); confirm=True
    executes (POST /config/s3, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/s3/{s3_id}"
    # SECRET HANDLING: detail must NEVER contain secret-key — only non-secret params.
    return run_governed(
        "pbs_s3_client_create", tgt,
        plan=lambda: plan_s3_client_create(
        s3_id, endpoint, access_key, secret_key, region, fingerprint, port, path_style,
        provider_quirks, rate_in, rate_out, burst_in, burst_out,
    ),
        execute=lambda: s3_client_create(
            pbs, s3_id, endpoint, access_key, secret_key, region, fingerprint, port, path_style,
            provider_quirks, rate_in, rate_out, burst_in, burst_out,
        ),
        confirm=confirm, detail={"access_key": access_key, "endpoint": endpoint})


@tool()
def pbs_s3_client_update(
    s3_id: Annotated[str, Field(description="Id of the existing S3 client config to update.")],
    access_key: Annotated[str | None, Field(description="New access key. NOT treated as secret.")] = None,
    secret_key: Annotated[str | None, Field(description="New secret key. SECRET — never written to the audit ledger or the dry-run PLAN.")] = None,
    endpoint: Annotated[str | None, Field(description="New endpoint hostname/IPv4/IPv6.")] = None,
    region: Annotated[str | None, Field(description="New region.")] = None,
    fingerprint: Annotated[str | None, Field(description="New X509 certificate fingerprint.")] = None,
    port: Annotated[int | None, Field(description="New port (1-65535).")] = None,
    path_style: Annotated[bool | None, Field(description="Use path-style bucket addressing.")] = None,
    provider_quirks: Annotated[list[str] | None, Field(description="New provider-specific implementation quirks.")] = None,
    rate_in: Annotated[str | None, Field(description="New inbound rate limit (byte size with unit).")] = None,
    rate_out: Annotated[str | None, Field(description="New outbound rate limit (byte size with unit).")] = None,
    burst_in: Annotated[str | None, Field(description="New inbound burst limit (byte size with unit).")] = None,
    burst_out: Annotated[str | None, Field(description="New outbound burst limit (byte size with unit).")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned.")] = None,
    delete: Annotated[list[str] | None, Field(description="Property names to clear: any of port/region/fingerprint/path-style/rate-in/burst-in/rate-out/burst-out/provider-quirks. access-key/secret-key/endpoint/id are NOT deletable — rotate them with a new value instead.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: update a PBS S3 client configuration.

    RISK_MEDIUM: rotating credentials/endpoint/region can silently break dependent datastore/
    sync configuration — mirrors pbs_remote_update. SECRET CONTRACT: secret-key (if given) is
    NEVER written to the audit ledger or the dry-run PLAN. Dry-run by default (captures current
    secret-free config into the PLAN); confirm=True executes (PUT /config/s3/{id}, synchronous —
    PBS returns null) and returns {"status": "ok", "result": None}. No snapshot primitive; verify
    with pbs_s3_check after rotating credentials. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/s3/{s3_id}"
    return run_governed(
        "pbs_s3_client_update", tgt,
        plan=lambda: plan_s3_client_update(
        pbs, s3_id, access_key, secret_key, endpoint, region, fingerprint, port, path_style,
        provider_quirks, rate_in, rate_out, burst_in, burst_out, digest, delete,
    ),
        execute=lambda: s3_client_update(
            pbs, s3_id, access_key, secret_key, endpoint, region, fingerprint, port, path_style,
            provider_quirks, rate_in, rate_out, burst_in, burst_out, digest, delete,
        ),
        confirm=confirm)


@tool()
def pbs_s3_client_delete(
    s3_id: Annotated[str, Field(description="Id of the S3 client config to delete.")],
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PBS S3 client configuration.

    RISK_MEDIUM: removes a credential-bearing config entry — mirrors pbs_remote_delete. Any
    datastore or sync configuration referencing this s3-endpoint-id breaks immediately; the
    credential cannot be retrieved after deletion. Dry-run by default (captures current
    secret-free config); confirm=True executes (DELETE /config/s3/{id}, synchronous — PBS
    returns null) and returns {"status": "ok", "result": None}. No UNDO primitive — re-create
    with pbs_s3_client_create (a fresh secret-key is required). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/s3/{s3_id}"
    return run_governed(
        "pbs_s3_client_delete", tgt,
        plan=lambda: plan_s3_client_delete(pbs, s3_id, digest),
        execute=lambda: s3_client_delete(pbs, s3_id, digest),
        confirm=confirm)


@tool()
def pbs_s3_check(
    s3_id: Annotated[str, Field(description="S3 client config id to check.")],
    bucket: Annotated[str, Field(description="Bucket name for the S3 object store (3-63 chars). REQUIRED.")],
    store_prefix: Annotated[str | None, Field(description="Store prefix within the bucket for S3 object keys (commonly a datastore name).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True runs the live check.")] = False,
) -> dict:
    """MUTATION: perform a basic sanity check for a PBS S3 client configuration.

    RISK_LOW: PUT verb, but genuinely non-config-mutating (schema-confirmed: PBS's own state
    never changes, returns null) — this is a read-shaped probe that makes a REAL outbound
    network call to the configured S3 endpoint using its stored credentials. Confirm-gated
    anyway (verb is not the safety signal): this endpoint has no safe default to fall back on
    (unlike pbs_tape_media_list's update_status=False) — every invocation's whole purpose is the
    live probe; see proximo.pbs_s3 module docstring fact #6 for the full argued reasoning
    (weighed against both the pbs_tape_media_destroy and pbs_notification_target_test
    precedents). Dry-run by default (returns a PLAN, nothing is called); confirm=True executes
    (PUT /admin/s3/{s3-endpoint-id}/check) and returns {"status": "ok", "result": None}. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/admin/s3/{s3_id}/check/{bucket}"
    return run_governed(
        "pbs_s3_check", tgt,
        plan=lambda: plan_s3_check(s3_id, bucket, store_prefix),
        execute=lambda: s3_check(pbs, s3_id, bucket, store_prefix),
        confirm=confirm)


@tool()
def pbs_s3_reset_counters(
    s3_id: Annotated[str, Field(description="S3 client config id whose counters to reset.")],
    bucket: Annotated[str, Field(description="Bucket name for the S3 object store (3-63 chars). REQUIRED.")],
    store_prefix: Annotated[str | None, Field(description="Store prefix within the bucket (commonly a datastore name) to scope the reset.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the reset.")] = False,
) -> dict:
    """MUTATION: reset S3 request counters for a matching endpoint/bucket/prefix.

    RISK_LOW: resets observability counters, not data — no backup/config content is touched.
    Dry-run by default (returns a PLAN); confirm=True executes
    (PUT /admin/s3/{s3-endpoint-id}/reset-counters, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/admin/s3/{s3_id}/reset-counters/{bucket}"
    return run_governed(
        "pbs_s3_reset_counters", tgt,
        plan=lambda: plan_s3_reset_counters(s3_id, bucket, store_prefix),
        execute=lambda: s3_reset_counters(pbs, s3_id, bucket, store_prefix),
        confirm=confirm)


# --- Mutations: Client encryption keys ---

@tool()
def pbs_encryption_key_create(
    key_id: Annotated[str, Field(description="New encryption key id (3-32 chars, alnum/underscore start, then alnum/./_/-). CALLER-CHOSEN — PBS does not generate it.")],
    key: Annotated[str | None, Field(description="Optional: import this key material instead of having PBS generate a fresh one. No length bound (unlike the tape-encryption-keys plane's 300-600 char requirement).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PBS client encryption key.

    RISK_MEDIUM: creates a credential controlling future client-side encryption capability.
    SECRET CONTRACT: `key` (if given) is NEVER written to the audit ledger or the dry-run PLAN —
    forwarded RAW only to the real PBS API on confirm=True. SCHEMA QUIRK: this endpoint returns
    null — unlike the tape-encryption-keys plane, NO fingerprint comes back; check
    pbs_encryption_key_list afterward for the assigned fingerprint/hint/kdf, if any. confirm=True
    executes (POST /config/encryption-keys, synchronous) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/encryption-keys/{key_id}"
    return run_governed(
        "pbs_encryption_key_create", tgt,
        plan=lambda: plan_encryption_key_create(key_id, key),
        execute=lambda: encryption_key_create(pbs, key_id, key),
        confirm=confirm, detail={"key_supplied": key is not None})


@tool()
def pbs_encryption_key_delete(
    key_id: Annotated[str, Field(description="Id of the encryption key to delete.")],
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PBS client encryption key.

    RISK_HIGH — INFERRED, NOT SCHEMA-STATED: PBS's own description here is bare ("Remove
    encryption key.") — unlike the tape-encryption-keys plane, it does NOT explicitly say
    content becomes unreadable. Rated HIGH anyway given the worst-case severity if this was the
    only tracked copy of the key material (Smoke-confirm before treating this as PBS-confirmed).
    Dry-run by default (no CAPTURE — no individual GET exists on this plane; check
    pbs_encryption_key_list yourself first); confirm=True executes (DELETE
    /config/encryption-keys/{id}, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/encryption-keys/{key_id}"
    return run_governed(
        "pbs_encryption_key_delete", tgt,
        plan=lambda: plan_encryption_key_delete(key_id, digest),
        execute=lambda: encryption_key_delete(pbs, key_id, digest),
        confirm=confirm)


@tool()
def pbs_encryption_key_toggle_archive(
    key_id: Annotated[str, Field(description="Id of the encryption key to toggle.")],
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the toggle.")] = False,
) -> dict:
    """MUTATION: toggle a PBS client encryption key's archive flag.

    RISK_MEDIUM: archived keys can no longer encrypt NEW content (PBS's own stated
    consequence) — reversible by toggling again, but automation relying on continued encryption
    with this key can silently start failing until noticed. Check pbs_encryption_key_list first
    to know the CURRENT archived state (this toggle flips whatever it currently is). Dry-run by
    default (returns a PLAN); confirm=True executes (POST /config/encryption-keys/{id},
    synchronous — PBS returns null) and returns {"status": "ok", "result": None}. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/encryption-keys/{key_id}"
    return run_governed(
        "pbs_encryption_key_toggle_archive", tgt,
        plan=lambda: plan_encryption_key_toggle_archive(key_id, digest),
        execute=lambda: encryption_key_toggle_archive(pbs, key_id, digest),
        confirm=confirm)
