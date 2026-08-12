"""PBS tape media-pool + encryption-key wrappers (Wave 4b, full-surface campaign) —
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 4 decomposition (PBS tape)", "4b — media
pools + encryption keys". See `proximo.pbs_tape_media` module docstring for the full endpoint
table, the schema-verified facts, and the risk-rating reasoning.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_tape_media import (
    plan_tape_key_create,
    plan_tape_key_delete,
    plan_tape_key_update_password,
    plan_tape_pool_create,
    plan_tape_pool_delete,
    plan_tape_pool_update,
    tape_key_create,
    tape_key_delete,
    tape_key_get,
    tape_key_list,
    tape_key_update_password,
    tape_pool_create,
    tape_pool_delete,
    tape_pool_get,
    tape_pool_list,
    tape_pool_update,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Reads: Media pools ---

@tool()
def pbs_tape_pool_list() -> list[dict]:
    """READ-ONLY: list configured PBS tape media pools. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_pool_list", "pbs/config/media-pool", lambda: tape_pool_list(pbs))


@tool()
def pbs_tape_pool_get(
    name: Annotated[str, Field(description="Media pool name (2-32 chars, alnum/underscore start, then alnum/./_/-).")],
) -> dict:
    """READ-ONLY: get one PBS tape media pool's config. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_pool_get", f"pbs/config/media-pool/{name}",
                    lambda: tape_pool_get(pbs, name))


# --- Reads: Encryption keys ---

@tool()
def pbs_tape_key_list() -> list[dict]:
    """READ-ONLY: list existing PBS tape encryption keys — PUBLIC metadata only (created/
    fingerprint/hint/kdf/modified/path; PBS never returns the key material or password on this
    endpoint). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_key_list", "pbs/config/tape-encryption-keys",
                    lambda: tape_key_list(pbs))


@tool()
def pbs_tape_key_get(
    fingerprint: Annotated[str, Field(description="Tape encryption key fingerprint — 32 colon-separated hex byte-pairs (a formatted SHA-256), e.g. from pbs_tape_key_list.")],
) -> dict:
    """READ-ONLY: get one PBS tape encryption key's config — PUBLIC part only (created/
    fingerprint/hint/kdf/modified/path; PBS never returns the key material or password on this
    endpoint). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tape_key_get", f"pbs/config/tape-encryption-keys/{fingerprint}",
                    lambda: tape_key_get(pbs, fingerprint))


# --- Mutations: Media pools ---

@tool()
def pbs_tape_pool_create(
    name: Annotated[str, Field(description="New media pool name (2-32 chars, alnum/underscore start, then alnum/./_/-).")],
    allocation: Annotated[str | None, Field(description="Media set allocation policy: 'continue', 'always', or a calendar event.")] = None,
    comment: Annotated[str | None, Field(description="Optional comment (no control characters, <=128 chars).")] = None,
    encrypt: Annotated[str | None, Field(description="Optional tape encryption key fingerprint (32 colon-separated hex byte-pairs) — future writes into this pool are encrypted with it.")] = None,
    retention: Annotated[str | None, Field(description="Media retention policy: 'overwrite', 'keep', or a time span.")] = None,
    template: Annotated[str | None, Field(description="Media set naming template (may contain strftime() specs, 2-64 chars).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PBS tape media pool.

    RISK_LOW: additive — no existing pool/drive/changer/job config is affected. Dry-run by
    default (returns a PLAN); confirm=True executes (POST /config/media-pool, synchronous — PBS
    returns null) and returns {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/media-pool/{name}"
    return run_governed(
        "pbs_tape_pool_create", tgt,
        plan=lambda: plan_tape_pool_create(name, allocation, comment, encrypt, retention, template),
        execute=lambda: tape_pool_create(pbs, name, allocation, comment, encrypt, retention, template),
        confirm=confirm)


@tool()
def pbs_tape_pool_update(
    name: Annotated[str, Field(description="Name of the existing media pool to update.")],
    allocation: Annotated[str | None, Field(description="New allocation policy: 'continue', 'always', or a calendar event.")] = None,
    comment: Annotated[str | None, Field(description="New comment (no control characters, <=128 chars).")] = None,
    encrypt: Annotated[str | None, Field(description="New tape encryption key fingerprint association.")] = None,
    retention: Annotated[str | None, Field(description="New retention policy: 'overwrite', 'keep', or a time span.")] = None,
    template: Annotated[str | None, Field(description="New media set naming template.")] = None,
    delete: Annotated[list[str] | None, Field(description="Property names to clear: any of allocation/retention/template/encrypt/comment.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: update a PBS tape media pool.

    RISK_MEDIUM: changes allocation/retention policy and/or the encryption-key association —
    future tape-backup jobs writing into this pool target/reuse tapes under the new policy on
    their next run. NO digest/optimistic-lock param exists on this endpoint at all (schema-
    verified — see module docstring). Dry-run by default (captures current config into the
    PLAN); confirm=True executes (PUT /config/media-pool/{name}, synchronous — PBS returns null)
    and returns {"status": "ok", "result": None}. No snapshot primitive; re-apply the captured
    config to revert. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/media-pool/{name}"
    return run_governed(
        "pbs_tape_pool_update", tgt,
        plan=lambda: plan_tape_pool_update(pbs, name, allocation, comment, encrypt, retention, template, delete),
        execute=lambda: tape_pool_update(pbs, name, allocation, comment, encrypt, retention, template, delete),
        confirm=confirm)


@tool()
def pbs_tape_pool_delete(
    name: Annotated[str, Field(description="Name of the media pool to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PBS tape media pool.

    RISK_MEDIUM: media/backup data already written to tapes that belonged to this pool is
    untouched, but the pool's retention/allocation policy and encryption-key association is
    gone — tape-backup jobs referencing this pool fail until it is re-created. Dry-run by
    default (captures current config); confirm=True executes (DELETE /config/media-pool/{name},
    synchronous — PBS returns null) and returns {"status": "ok", "result": None}. No UNDO
    primitive — re-create with pbs_tape_pool_create. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/media-pool/{name}"
    return run_governed(
        "pbs_tape_pool_delete", tgt,
        plan=lambda: plan_tape_pool_delete(pbs, name),
        execute=lambda: tape_pool_delete(pbs, name),
        confirm=confirm)


# --- Mutations: Encryption keys ---

@tool()
def pbs_tape_key_create(
    password: Annotated[str, Field(description="A secret password protecting the new key (min 5 chars). REQUIRED.")],
    hint: Annotated[str | None, Field(description="Optional password hint (no control characters, 1-64 chars).")] = None,
    kdf: Annotated[str | None, Field(description="Key derivation function: 'none', 'scrypt' (default), or 'pbkdf2'.")] = None,
    key: Annotated[str | None, Field(description="Optional: restore/re-create a key from this exported JSON string (300-600 chars) instead of generating a new one.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PBS tape encryption key.

    RISK_MEDIUM: creates a credential controlling future tape access. SECRET CONTRACT: `key`/
    `password` are NEVER written to the audit ledger or returned in the dry-run PLAN — they are
    forwarded RAW only to the real PBS API on confirm=True (the create must actually work).
    confirm=True executes (POST /config/tape-encryption-keys, synchronous) and returns
    {"status": "ok", "result": "<sha256 fingerprint>"} — the fingerprint is NOT secret, safe to
    record; assign it to a pool's `encrypt` field with pbs_tape_pool_create/pbs_tape_pool_update
    to actually encrypt future tape writes. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = "pbs/config/tape-encryption-keys"
    # SECRET HANDLING: the raw op result (the fingerprint — not secret) passes straight through;
    # detail must NEVER contain key/password — only non-secret params, mirroring
    # pve_token_create's contract.
    return run_governed(
        "pbs_tape_key_create", tgt,
        plan=lambda: plan_tape_key_create(password, hint, kdf, key),
        execute=lambda: tape_key_create(pbs, password, hint, kdf, key),
        confirm=confirm, detail={"hint": hint, "kdf": kdf, "key_supplied": key is not None})


@tool()
def pbs_tape_key_update_password(
    fingerprint: Annotated[str, Field(description="Fingerprint of the existing tape encryption key to update.")],
    hint: Annotated[str, Field(description="New password hint (no control characters, 1-64 chars). REQUIRED by PBS — cannot change the password alone.")],
    new_password: Annotated[str, Field(description="The new password (min 5 chars). REQUIRED.")],
    password: Annotated[str | None, Field(description="The CURRENT password — required unless force=True (which resets via PBS's root-only accessible copy).")] = None,
    kdf: Annotated[str | None, Field(description="Key derivation function: 'none', 'scrypt' (default), or 'pbkdf2'.")] = None,
    force: Annotated[bool | None, Field(description="Reset the passphrase using the root-only accessible copy, bypassing the current-password check.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: change a PBS tape encryption key's password (and hint).

    RISK_MEDIUM: rotates the credential protecting tape data; PBS retains a root-only recovery
    copy (force=True bypasses the current-password check via it), so this is not an immediate
    one-way lockout — but losing track of the new password before force is available risks
    losing normal-user access to this key. SECRET CONTRACT: `password`/`new_password` are NEVER
    written to the audit ledger or the dry-run PLAN. confirm=True executes (PUT
    /config/tape-encryption-keys/{fingerprint}, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/tape-encryption-keys/{fingerprint}"
    return run_governed(
        "pbs_tape_key_update_password", tgt,
        plan=lambda: plan_tape_key_update_password(pbs, fingerprint, hint, new_password, password, kdf, force, digest),
        execute=lambda: tape_key_update_password(pbs, fingerprint, hint, new_password, password, kdf, force, digest),
        confirm=confirm, detail={"hint": hint, "kdf": kdf, "force": force})


@tool()
def pbs_tape_key_delete(
    fingerprint: Annotated[str, Field(description="Fingerprint of the tape encryption key to delete.")],
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PBS tape encryption key.

    RISK_HIGH: TAPES ENCRYPTED WITH THIS KEY BECOME UNREADABLE WITHOUT IT — PBS's own
    description, verbatim: "you can no longer access tapes using this key." No undo unless the
    key material was separately exported/backed up outside PBS. Dry-run by default (captures
    current public metadata); confirm=True executes (DELETE
    /config/tape-encryption-keys/{fingerprint}, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/tape-encryption-keys/{fingerprint}"
    return run_governed(
        "pbs_tape_key_delete", tgt,
        plan=lambda: plan_tape_key_delete(pbs, fingerprint, digest),
        execute=lambda: tape_key_delete(pbs, fingerprint, digest),
        confirm=confirm)
