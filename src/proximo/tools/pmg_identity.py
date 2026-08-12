"""PMG identity wrappers (Wave 9h AND 9i, full-surface campaign) —
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 9 decomposition", chunks 9h + 9i.

New tools module (RULING 5, campaign coordinator) — the backend/plan logic lives in its own
dedicated `proximo.pmg_identity` module (mirroring `pmg_node.py`'s split from `pmg.py`); see that
module's docstring for the endpoint table, the schema-verified facts (PMG-vs-PBS divergences),
and the secret contract. Chunk 9i (this addition, below the 9h section) covers global
single-object appliance config (admin/clamav/mail/spamquar/virusquar/tfa-webauthn) plus the wave's
one DANGER item — PMG cluster bootstrap/join (RULING 1, binding).
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pmg_identity import (
    _client_key_redacted_detail,
    _join_password_redacted_detail,
    _tfa_password_redacted_detail,
    _user_secret_redacted_detail,
    admin_config_get,
    admin_config_update,
    clamav_config_get,
    clamav_config_update,
    cluster_create,
    cluster_join,
    cluster_join_info,
    cluster_node_add,
    cluster_nodes_list,
    cluster_status,
    cluster_update_fingerprints,
    mail_config_update,
    plan_admin_config_update,
    plan_clamav_config_update,
    plan_cluster_create,
    plan_cluster_join,
    plan_cluster_node_add,
    plan_cluster_update_fingerprints,
    plan_mail_config_update,
    plan_realm_create,
    plan_realm_delete,
    plan_realm_update,
    plan_spamquar_config_update,
    plan_tfa_add,
    plan_tfa_delete,
    plan_tfa_update,
    plan_tfa_webauthn_config_update,
    plan_user_create,
    plan_user_delete,
    plan_user_unlock_tfa,
    plan_user_update,
    plan_virusquar_config_update,
    realm_create,
    realm_delete,
    realm_get,
    realm_list,
    realm_update,
    spamquar_config_get,
    spamquar_config_update,
    tfa_add,
    tfa_delete,
    tfa_entry_get,
    tfa_list,
    tfa_update,
    tfa_user_list,
    tfa_webauthn_config_get,
    tfa_webauthn_config_update,
    user_create,
    user_delete,
    user_get,
    user_unlock_tfa,
    user_update,
    virusquar_config_get,
    virusquar_config_update,
)
from proximo.server import (
    _audited,
    _plan,
    run_governed,
    tool,
)

# ---------------------------------------------------------------------------
# Auth realms
# ---------------------------------------------------------------------------

@tool()
def pmg_access_realm_list() -> list[dict]:
    """READ-ONLY: list configured PMG auth realms. Returns each realm's comment/realm/type — no
    client-key (schema-confirmed absent from this list). Use pmg_access_realm_get for one realm's
    full config. Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_access_realm_list", "pmg/access/auth-realm", lambda: realm_list(pmg))


@tool()
def pmg_access_realm_get(
    realm: Annotated[str, Field(description="Realm name to look up.")],
) -> dict:
    """READ-ONLY: get one PMG auth realm's config. client-key is defensively stripped (the
    single-realm read is schema-thin — unconfirmed whether PMG ever echoes it). Needs
    PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_access_realm_get", f"pmg/access/auth-realm/{realm}", lambda: realm_get(pmg, realm))


@tool()
def pmg_access_realm_create(
    realm: Annotated[str, Field(description="New realm name.")],
    realm_type: Annotated[str, Field(description="Realm type: 'oidc', 'pam', or 'pmg'. PMG has NO 'ad'/'ldap' realm types (those are a separate, already-shipped LDAP-profile family) — unlike PBS.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment.")] = None,
    default: Annotated[bool | None, Field(description="True to make this the default realm preselected on login.")] = None,
    issuer_url: Annotated[str | None, Field(description="OIDC issuer URL (required by PMG for type='oidc').")] = None,
    client_id: Annotated[str | None, Field(description="OIDC client id (required by PMG for type='oidc').")] = None,
    client_key: Annotated[str | None, Field(description="OIDC client secret; redacted from all plans/logs/ledger.")] = None,
    autocreate: Annotated[bool | None, Field(description="Automatically create PMG users on first login if they don't exist.")] = None,
    autocreate_role: Annotated[str | None, Field(description="DEPRECATED (favor autocreate_role_assignment): auto-create users at this role — one of admin/qmanager/audit/helpdesk. Can auto-provision admin-equivalent users on a FUTURE login.")] = None,
    autocreate_role_assignment: Annotated[str | None, Field(description="Role assignment expression for auto-created users (replaces autocreate_role).")] = None,
    acr_values: Annotated[str | None, Field(description="OIDC Authentication Context Class Reference values, forwarded verbatim.")] = None,
    audiences: Annotated[str | None, Field(description="OIDC accepted audiences list, forwarded verbatim.")] = None,
    prompt: Annotated[str | None, Field(description="OIDC prompt parameter.")] = None,
    scopes: Annotated[str | None, Field(description="OIDC scopes to request, forwarded verbatim.")] = None,
    username_claim: Annotated[str | None, Field(description="OIDC claim used to generate the unique username. CREATE-ONLY (not accepted by pmg_access_realm_update).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): create a PMG auth realm. Dry-run by default.

    CLIENT-KEY REDACTION: `client_key` (the OIDC client secret), when supplied, is
    UNCONDITIONALLY redacted from the plan, detail, and audit ledger (only
    {"client-key": "[redacted]"} is recorded). `autocreate_role`/`autocreate_role_assignment` can
    auto-provision admin-equivalent users on a FUTURE login — a realm-level authority vector,
    distinct from pmg_access_user_create's direct RULING-3 grant, flagged in the plan when it
    applies. confirm=True executes and returns a dict; the return shape is `null` per PMG's
    schema. Use pmg_access_realm_update to change it afterward, or pmg_access_realm_delete to
    remove it. Needs PROXIMO_PMG_* config.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/access/auth-realm/{realm}"
    ck_detail = _client_key_redacted_detail(client_key)
    fields = dict(
        comment=comment, default=default, issuer_url=issuer_url, client_id=client_id,
        autocreate=autocreate, autocreate_role=autocreate_role,
        autocreate_role_assignment=autocreate_role_assignment, acr_values=acr_values,
        audiences=audiences, prompt=prompt, scopes=scopes, username_claim=username_claim,
    )
    return run_governed(
        "pmg_access_realm_create", tgt,
        plan=lambda: plan_realm_create(realm, realm_type, **fields),
        execute=lambda: realm_create(pmg, realm, realm_type, comment, default, issuer_url,
                                        client_id, client_key, autocreate, autocreate_role,
                                        autocreate_role_assignment, acr_values, audiences,
                                        prompt, scopes, username_claim),
        confirm=confirm, surface=ck_detail)


@tool()
def pmg_access_realm_update(
    realm: Annotated[str, Field(description="Realm name to update.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment; omit to leave unchanged.")] = None,
    default: Annotated[bool | None, Field(description="Default-realm-on-login flag; omit to leave unchanged.")] = None,
    issuer_url: Annotated[str | None, Field(description="OIDC issuer URL; omit to leave unchanged.")] = None,
    client_id: Annotated[str | None, Field(description="OIDC client id; omit to leave unchanged.")] = None,
    client_key: Annotated[str | None, Field(description="New OIDC client secret; redacted from all plans/logs/ledger.")] = None,
    autocreate: Annotated[bool | None, Field(description="Autocreate-on-login flag; omit to leave unchanged.")] = None,
    autocreate_role: Annotated[str | None, Field(description="DEPRECATED autocreate role; omit to leave unchanged.")] = None,
    autocreate_role_assignment: Annotated[str | None, Field(description="Autocreate role-assignment expression; omit to leave unchanged.")] = None,
    acr_values: Annotated[str | None, Field(description="OIDC ACR values; omit to leave unchanged.")] = None,
    audiences: Annotated[str | None, Field(description="OIDC audiences list; omit to leave unchanged.")] = None,
    prompt: Annotated[str | None, Field(description="OIDC prompt parameter; omit to leave unchanged.")] = None,
    scopes: Annotated[str | None, Field(description="OIDC scopes; omit to leave unchanged.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear.")] = None,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a PMG auth realm's config. Dry-run by default — the PLAN reads
    the realm's current config first.

    NOTE: no `realm_type`/`username_claim` params — both are CREATE-ONLY per PMG's schema
    (sending them here would hard-fail the whole request server-side). `client_key`, if supplied,
    is redacted identically to pmg_access_realm_create's. confirm=True executes and returns a
    dict (`null` per schema). Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/access/auth-realm/{realm}"
    ck_detail = _client_key_redacted_detail(client_key)
    fields = dict(
        comment=comment, default=default, issuer_url=issuer_url, client_id=client_id,
        autocreate=autocreate, autocreate_role=autocreate_role,
        autocreate_role_assignment=autocreate_role_assignment, acr_values=acr_values,
        audiences=audiences, prompt=prompt, scopes=scopes,
    )
    return run_governed(
        "pmg_access_realm_update", tgt,
        plan=lambda: plan_realm_update(pmg, realm, **fields),
        execute=lambda: realm_update(pmg, realm, comment, default, issuer_url, client_id,
                                        client_key, autocreate, autocreate_role,
                                        autocreate_role_assignment, acr_values, audiences,
                                        prompt, scopes, delete_props, digest),
        confirm=confirm, surface=ck_detail)


@tool()
def pmg_access_realm_delete(
    realm: Annotated[str, Field(description="Realm name to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): permanently delete a PMG auth realm. Dry-run by default — the PLAN reads
    the realm's current config and flags that any users authenticating via it lose login access.
    NO digest param exists on this endpoint (schema-verified — only `realm` in its parameter
    block). confirm=True executes and returns a dict (`null` per schema). Needs PROXIMO_PMG_*
    config."""
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/access/auth-realm/{realm}"
    return run_governed(
        "pmg_access_realm_delete", tgt,
        plan=lambda: plan_realm_delete(pmg, realm),
        execute=lambda: realm_delete(pmg, realm),
        confirm=confirm)


# ---------------------------------------------------------------------------
# Local users
# ---------------------------------------------------------------------------

@tool()
def pmg_access_user_get(
    userid: Annotated[str, Field(description="PMG user id to look up, format 'user@realm'.")],
) -> dict:
    """READ-ONLY: get a PMG user's config. `password`/`crypt_pass`/`keys` are defensively
    stripped (the single-user read is schema-thin — unconfirmed whether PMG ever echoes any of
    the three). Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_access_user_get", f"pmg/access/users/{userid}", lambda: user_get(pmg, userid))


@tool()
def pmg_access_user_create(
    userid: Annotated[str, Field(description="New PMG user id, format 'user@realm'.")],
    role: Annotated[str, Field(description="REQUIRED. One of 'root' (reserved for the Unix Superuser), 'admin', 'helpdesk', 'qmanager', 'audit'. 'root'/'admin' are ADMIN-EQUIVALENT — see the risk note.")],
    realm: Annotated[str | None, Field(description="Authentication realm; PMG defaults to its own 'pmg' realm when omitted.")] = None,
    comment: Annotated[str | None, Field(description="Optional free-text comment.")] = None,
    email: Annotated[str | None, Field(description="Optional email address.")] = None,
    enable: Annotated[bool | None, Field(description="Whether the account can log in; None defers to PMG's default (enabled).")] = None,
    expire: Annotated[int | None, Field(description="Optional account expiry as a Unix timestamp; None/0 means no expiry.")] = None,
    firstname: Annotated[str | None, Field(description="Optional first name.")] = None,
    lastname: Annotated[str | None, Field(description="Optional last name.")] = None,
    password: Annotated[str | None, Field(description="Optional initial password (8-64 chars per PMG); redacted from all plans/logs/ledger.")] = None,
    crypt_pass: Annotated[str | None, Field(description="Optional pre-encrypted password (crypt(3) hash shape, e.g. '$6$salt$hash'); forwarded verbatim, not locally shape-validated; redacted from all plans/logs/ledger.")] = None,
    keys: Annotated[str | None, Field(description="Optional Yubico two-factor key material (a THIRD secret this build found on this endpoint, beyond password/crypt_pass); redacted from all plans/logs/ledger.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (RULING 3 — CONDITIONAL MEDIUM/HIGH): create a PMG local user. Dry-run by default.

    RISK IS CONDITIONAL ON `role`: RISK_HIGH when role is admin-equivalent ('root'/'admin' — PMG
    grants role directly in THIS create call, unlike PVE/PBS's separate ACL-grant step, so a
    single call both creates the identity AND grants full appliance control); RISK_MEDIUM
    otherwise ('helpdesk'/'qmanager'/'audit'). No invented fifth tier.

    SECRET REDACTION: `password`/`crypt_pass`/`keys`, when supplied, are ALL UNCONDITIONALLY
    redacted from the plan, detail, and audit ledger (only their `"[redacted]"` markers are
    recorded, omitted entirely when not given). confirm=True executes and returns a dict (`null`
    per schema); synchronous. Use pmg_access_user_update to change it afterward, or
    pmg_access_user_delete to remove it. Needs PROXIMO_PMG_* config.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/access/users/{userid}"
    secret_detail = _user_secret_redacted_detail(password, crypt_pass, keys)
    fields = dict(realm=realm, comment=comment, email=email, enable=enable, expire=expire,
                  firstname=firstname, lastname=lastname)
    return run_governed(
        "pmg_access_user_create", tgt,
        plan=lambda: plan_user_create(userid, role, **fields),
        execute=lambda: user_create(pmg, userid, role, realm, comment, email, enable,
                                       expire, firstname, lastname, password, crypt_pass, keys),
        confirm=confirm, detail={"role": role}, surface=secret_detail)


@tool()
def pmg_access_user_update(
    userid: Annotated[str, Field(description="PMG user id to update, format 'user@realm'.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment; omit to leave unchanged.")] = None,
    email: Annotated[str | None, Field(description="Optional email address; omit to leave unchanged.")] = None,
    enable: Annotated[bool | None, Field(description="Whether the account can log in; False stops login. Omit to leave unchanged.")] = None,
    expire: Annotated[int | None, Field(description="Account expiry as a Unix timestamp; omit to leave unchanged.")] = None,
    firstname: Annotated[str | None, Field(description="Optional first name; omit to leave unchanged.")] = None,
    lastname: Annotated[str | None, Field(description="Optional last name; omit to leave unchanged.")] = None,
    realm: Annotated[str | None, Field(description="Authentication realm; omit to leave unchanged.")] = None,
    role: Annotated[str | None, Field(description="New role; omit to leave unchanged. Same admin-equivalent semantics as pmg_access_user_create's — see the risk note.")] = None,
    password: Annotated[str | None, Field(description="New password; redacted from all plans/logs/ledger.")] = None,
    crypt_pass: Annotated[str | None, Field(description="New pre-encrypted password (crypt(3) hash shape); forwarded verbatim; redacted from all plans/logs/ledger.")] = None,
    keys: Annotated[str | None, Field(description="New Yubico two-factor key material; redacted from all plans/logs/ledger.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (RULING 3 — CONDITIONAL MEDIUM/HIGH): update a PMG user. Dry-run by default — the
    PLAN reads the user's CURRENT config first (needed to resolve the EFFECTIVE role: if `role`
    is omitted here, the existing role still governs the risk tier).

    RISK IS CONDITIONAL on the RESOLVED effective role (supplied `role`, else the captured current
    role) being admin-equivalent ('root'/'admin') -> RISK_HIGH, otherwise RISK_MEDIUM — same
    RULING 3 logic as pmg_access_user_create's. If the current-config capture fails, this fails
    OPEN to HIGH (the honest choice — never silently under-rate a possibly-admin account).

    NOTE: this tool does NOT accept a `digest` parameter — PMG's own PUT /access/users/{userid}
    schema declares no such field at all (a genuine divergence from PBS, whose equivalent DOES
    accept one). `password`/`crypt_pass`/`keys`, if supplied, are redacted identically to
    pmg_access_user_create's. confirm=True executes and returns a dict (`null` per schema). Needs
    PROXIMO_PMG_* config.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/access/users/{userid}"
    secret_detail = _user_secret_redacted_detail(password, crypt_pass, keys)
    fields = dict(comment=comment, email=email, enable=enable, expire=expire,
                  firstname=firstname, lastname=lastname, realm=realm)
    return run_governed(
        "pmg_access_user_update", tgt,
        plan=lambda: plan_user_update(pmg, userid, role, **fields),
        execute=lambda: user_update(pmg, userid, comment, email, enable, expire, firstname,
                                       lastname, realm, role, password, crypt_pass, keys,
                                       delete_props),
        confirm=confirm, surface=secret_detail)


@tool()
def pmg_access_user_delete(
    userid: Annotated[str, Field(description="PMG user id to delete, format 'user@realm'.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): delete a PMG user. Dry-run by default — the PLAN reads the user's
    current config and, if this user is admin-equivalent, checks whether it is the LAST such
    account on the appliance (reusing the already-shipped access-list read) and loudly warns if
    so — a real lockout footgun. Permanent, no undo. NO digest param exists on this endpoint
    (schema-verified). confirm=True executes and returns a dict (`null` per schema). To disable
    login without deleting, use pmg_access_user_update (enable=False) instead. Needs
    PROXIMO_PMG_* config.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/access/users/{userid}"
    return run_governed(
        "pmg_access_user_delete", tgt,
        plan=lambda: plan_user_delete(pmg, userid),
        execute=lambda: user_delete(pmg, userid),
        confirm=confirm)


@tool()
def pmg_access_user_unlock_tfa(
    userid: Annotated[str, Field(description="PMG user id to clear a TOTP lockout for, format 'user@realm'.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (HIGH): clear a PMG user's TOTP lockout (PUT /access/users/{userid}/unlock-tfa).

    Escalated to HIGH (Wave 9h review, Major 1) to match the shipped PBS twin (pbs_tfa_unlock),
    which rates the IDENTICAL wire endpoint and semantics RISK_HIGH ("clears the anti-brute-force
    throttle guarding a 6-digit TOTP keyspace") — re-unlocking a locked-out account is an
    attack-recovery vector, and no PMG-specific reasoning makes it less dangerous than the PBS
    twin; this build originally shipped at MEDIUM per this chunk's own dispatch instruction, but
    that was a process artifact, not an argued technical difference. Dry-run by default.
    confirm=True executes and returns a dict whose result is a bool: whether the user was
    previously locked out. Synchronous. Needs PROXIMO_PMG_* config.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/access/users/{userid}/unlock-tfa"
    return run_governed(
        "pmg_access_user_unlock_tfa", tgt,
        plan=lambda: plan_user_unlock_tfa(userid),
        execute=lambda: user_unlock_tfa(pmg, userid),
        confirm=confirm)


# ---------------------------------------------------------------------------
# TFA
# ---------------------------------------------------------------------------

@tool()
def pmg_access_tfa_list() -> list[dict]:
    """READ-ONLY: list ALL users' TFA configuration. Use pmg_access_tfa_user_list to scope to one
    user. Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_access_tfa_list", "pmg/access/tfa", lambda: tfa_list(pmg))


@tool()
def pmg_access_tfa_user_list(
    userid: Annotated[str, Field(description="PMG user id, format 'user@realm'.")],
) -> list[dict]:
    """READ-ONLY: list one user's TFA entries (created/description/enable/id/type — no secret;
    richly typed on this plane). Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_access_tfa_user_list", f"pmg/access/tfa/{userid}", lambda: tfa_user_list(pmg, userid))


@tool()
def pmg_access_tfa_get(
    userid: Annotated[str, Field(description="PMG user id, format 'user@realm'.")],
    tfa_id: Annotated[str, Field(description="TFA entry id (from pmg_access_tfa_user_list).")],
) -> dict:
    """READ-ONLY: get one TFA entry (created/description/enable/id/type — no secret; richly
    typed on this plane, a divergence from the shipped PBS twin's `null`-typed equivalent). Needs
    PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_access_tfa_get", f"pmg/access/tfa/{userid}/{tfa_id}",
                    lambda: tfa_entry_get(pmg, userid, tfa_id))


@tool()
def pmg_access_tfa_add(
    userid: Annotated[str, Field(description="PMG user id to add a TFA entry for, format 'user@realm'.")],
    tfa_type: Annotated[str, Field(description="TFA entry type: 'totp', 'u2f', 'webauthn', or 'recovery'. PMG has NO 'yubico' TFA type (unlike PBS).")],
    description: Annotated[str | None, Field(description="Optional description to distinguish this entry from the user's others.")] = None,
    password: Annotated[str | None, Field(description="The ACTING user's own current password (step-up re-auth); redacted from all plans/logs/ledger.")] = None,
    totp: Annotated[str | None, Field(description="For type='totp': the totp: URI the caller generated (PMG does not generate this).")] = None,
    value: Annotated[str | None, Field(description="Registration/verification value (e.g. the current TOTP code, or a WebAuthn/U2F challenge response).")] = None,
    challenge: Annotated[str | None, Field(description="For u2f: the original challenge string being responded to.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): add a TFA entry for a user. Dry-run by default.

    SECRET-BEARING RESPONSE for tfa_type='recovery': confirm=True's result carries
    {"recovery": [<one-time codes>], "id": ...} — SERVER-GENERATED secret material, shown ONCE
    and never retrievable again — never written to the audit ledger (the `detail=` dict below
    never includes 'recovery'/'id'/'challenge'). `password`, if supplied, is UNCONDITIONALLY
    redacted identically to pmg_access_user_create's. confirm=True executes and returns a dict;
    synchronous. Needs PROXIMO_PMG_* config.
    """
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/access/tfa/{userid}"
    pw_detail = _tfa_password_redacted_detail(password)
    # SECRET HANDLING: type='recovery' results carry one-time codes in 'recovery' — detail must
    # NEVER contain the op result. Non-secret params only.
    return run_governed(
        "pmg_access_tfa_add", tgt,
        plan=lambda: plan_tfa_add(userid, tfa_type, description),
        execute=lambda: tfa_add(pmg, userid, tfa_type, description, password, totp, value, challenge),
        confirm=confirm, detail={"type": tfa_type}, surface=pw_detail)


@tool()
def pmg_access_tfa_update(
    userid: Annotated[str, Field(description="PMG user id, format 'user@realm'.")],
    tfa_id: Annotated[str, Field(description="TFA entry id to update.")],
    description: Annotated[str | None, Field(description="New description; omit to leave unchanged.")] = None,
    enable: Annotated[bool | None, Field(description="Whether the entry is enabled; False disables it immediately. Omit to leave unchanged.")] = None,
    password: Annotated[str | None, Field(description="The ACTING user's own current password (step-up re-auth); redacted from all plans/logs/ledger.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a TFA entry's description/enabled flag. Dry-run by default — the
    PLAN reads the current entry first. `password`, if supplied, is redacted identically to
    pmg_access_tfa_add's. confirm=True executes and returns a dict (`null` per schema). Needs
    PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/access/tfa/{userid}/{tfa_id}"
    pw_detail = _tfa_password_redacted_detail(password)
    return run_governed(
        "pmg_access_tfa_update", tgt,
        plan=lambda: plan_tfa_update(pmg, userid, tfa_id, description, enable),
        execute=lambda: tfa_update(pmg, userid, tfa_id, description, enable, password),
        confirm=confirm, surface=pw_detail)


@tool()
def pmg_access_tfa_delete(
    userid: Annotated[str, Field(description="PMG user id, format 'user@realm'.")],
    tfa_id: Annotated[str, Field(description="TFA entry id to remove.")],
    password: Annotated[str | None, Field(description="The ACTING user's own current password (step-up re-auth); redacted from all plans/logs/ledger.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (HIGH, IRREVERSIBLE): permanently remove one TFA factor from a user. HIGH because
    it WEAKENS authentication unconditionally — an account-takeover enabler, and a possible
    lockout if it's the user's last factor (matches the shipped PBS twin's identical RISK_HIGH
    rating; a reasoned upward divergence from the draft's own un-argued MEDIUM guess). Dry-run by
    default — the PLAN flags the permanence and the takeover/lockout risk. `password`, if
    supplied, is redacted identically to pmg_access_tfa_add's. confirm=True executes and returns a
    dict (`null` per schema). Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    tgt = f"pmg/access/tfa/{userid}/{tfa_id}"
    pw_detail = _tfa_password_redacted_detail(password)
    return run_governed(
        "pmg_access_tfa_delete", tgt,
        plan=lambda: plan_tfa_delete(pmg, userid, tfa_id),
        execute=lambda: tfa_delete(pmg, userid, tfa_id, password),
        confirm=confirm, surface=pw_detail)


# ===========================================================================
# CHUNK 9i — Global appliance config + cluster bootstrap/join
# ===========================================================================

# ---------------------------------------------------------------------------
# Global config — admin
# ---------------------------------------------------------------------------

@tool()
def pmg_config_admin_get() -> dict:
    """READ-ONLY: read PMG admin/appliance-wide config (mail-from banner, virus-scanner toggles,
    DKIM defaults, consent text, http_proxy, stats lifetime). Schema-thin on this plane — passed
    through best-effort. `http_proxy`, if present, is defensively masked for any embedded
    userinfo credential. Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_config_admin_get", "pmg/config/admin", lambda: admin_config_get(pmg))


@tool()
def pmg_config_admin_update(
    admin_mail_from: Annotated[str | None, Field(description="'From' header text for admin mails/bounces. Omit to leave unchanged.")] = None,
    advfilter: Annotated[bool | None, Field(description="Enable advanced filters for statistics. Omit to leave unchanged.")] = None,
    avast: Annotated[bool | None, Field(description="Use Avast Virus Scanner (requires a separate license). Omit to leave unchanged.")] = None,
    clamav: Annotated[bool | None, Field(description="Use ClamAV Virus Scanner (default on). False DISABLES ClamAV scanning — flagged in the plan. Omit to leave unchanged.")] = None,
    consent_text: Annotated[str | None, Field(description="Consent text displayed before login. Omit to leave unchanged.")] = None,
    custom_check: Annotated[bool | None, Field(description="Use a custom check script. Omit to leave unchanged.")] = None,
    custom_check_path: Annotated[str | None, Field(description="Absolute path to the custom check script. Omit to leave unchanged.")] = None,
    dailyreport: Annotated[bool | None, Field(description="Send daily reports. Omit to leave unchanged.")] = None,
    demo: Annotated[bool | None, Field(description="Demo mode — STOPS the SMTP filter entirely when True. Flagged loudly in the plan. Omit to leave unchanged.")] = None,
    dkim_use_domain: Annotated[str | None, Field(description="'header' or 'envelope' — which domain DKIM signing uses. Omit to leave unchanged.")] = None,
    dkim_selector: Annotated[str | None, Field(description="Default DKIM selector. Omit to leave unchanged.")] = None,
    dkim_sign: Annotated[bool | None, Field(description="DKIM-sign outbound mail with the configured selector. Omit to leave unchanged.")] = None,
    dkim_sign_all_mail: Annotated[bool | None, Field(description="DKIM-sign ALL outgoing mail regardless of envelope-from domain. Omit to leave unchanged.")] = None,
    email: Annotated[str | None, Field(description="Administrator e-mail address. Omit to leave unchanged.")] = None,
    http_proxy: Annotated[str | None, Field(description="External HTTP proxy for downloads, e.g. 'http://user:pass@host:port/'; redacted from all plans/logs/ledger DISPLAY (still forwarded raw on write). Omit to leave unchanged.")] = None,
    statlifetime: Annotated[int | None, Field(description="User statistics lifetime, in days (>=1). Omit to leave unchanged.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear (reset to default).")] = None,
    digest: Annotated[str | None, Field(description="Optional 64-char SHA-256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM, digest-gated): update PMG admin/appliance-wide config. Dry-run by
    default — the PLAN reads the current config first and flags `demo=True` (stops the SMTP
    filter entirely) and `clamav=False` (disables virus scanning) loudly if either is set.
    `delete_props`, if given, is disclosed explicitly in the PLAN (one line per cleared
    property) before confirm=True executes it. `http_proxy` is masked in the plan/ledger DISPLAY
    only — the raw value is still forwarded on confirm=True (the update must actually work).
    confirm=True executes (PUT /config/admin) and returns {"status": "ok", "result": None}. Needs
    PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/admin"
    fields = dict(
        admin_mail_from=admin_mail_from, advfilter=advfilter, avast=avast, clamav=clamav,
        consent_text=consent_text, custom_check=custom_check, custom_check_path=custom_check_path,
        dailyreport=dailyreport, demo=demo, dkim_use_domain=dkim_use_domain,
        dkim_selector=dkim_selector, dkim_sign=dkim_sign, dkim_sign_all_mail=dkim_sign_all_mail,
        email=email, http_proxy=http_proxy, statlifetime=statlifetime,
    )
    return run_governed(
        "pmg_config_admin_update", tgt,
        plan=lambda: plan_admin_config_update(pmg, delete_props=delete_props, **fields),
        execute=lambda: admin_config_update(
                        pmg, admin_mail_from=admin_mail_from, advfilter=advfilter, avast=avast,
                        clamav=clamav, consent_text=consent_text, custom_check=custom_check,
                        custom_check_path=custom_check_path, dailyreport=dailyreport, demo=demo,
                        dkim_use_domain=dkim_use_domain, dkim_selector=dkim_selector,
                        dkim_sign=dkim_sign, dkim_sign_all_mail=dkim_sign_all_mail, email=email,
                        http_proxy=http_proxy, statlifetime=statlifetime,
                        delete_props=delete_props, digest=digest,
                    ),
        confirm=confirm)


# ---------------------------------------------------------------------------
# Global config — clamav
# ---------------------------------------------------------------------------

@tool()
def pmg_config_clamav_get() -> dict:
    """READ-ONLY: read PMG ClamAV config (archive-scan limits, DB mirror, scripted-updates
    toggle). Schema-thin — passed through best-effort. Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_config_clamav_get", "pmg/config/clamav", lambda: clamav_config_get(pmg))


@tool()
def pmg_config_clamav_update(
    archiveblockencrypted: Annotated[bool | None, Field(description="Flag encrypted archives/documents as a heuristic virus match. Transitioning True->False is flagged in the plan. Omit to leave unchanged.")] = None,
    archivemaxfiles: Annotated[int | None, Field(description="Number of files scanned within an archive/container (>=0). Lowering below the current value is flagged. Omit to leave unchanged.")] = None,
    archivemaxrec: Annotated[int | None, Field(description="Nested-archive scan recursion depth (>=1). Lowering below the current value is flagged. Omit to leave unchanged.")] = None,
    archivemaxsize: Annotated[int | None, Field(description="Max archive size (bytes, >=1000000) to scan. Lowering below the current value is flagged. Omit to leave unchanged.")] = None,
    dbmirror: Annotated[str | None, Field(description="ClamAV database mirror server. Omit to leave unchanged.")] = None,
    maxcccount: Annotated[int | None, Field(description="Lowest number of credit-card/SSN matches to flag a file (>=0). Omit to leave unchanged.")] = None,
    maxscansize: Annotated[int | None, Field(description="Max data (bytes, >=1000000) scanned per input file. Lowering below the current value is flagged. Omit to leave unchanged.")] = None,
    scriptedupdates: Annotated[bool | None, Field(description="Enable incremental (scripted) signature-database updates. Omit to leave unchanged.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear (reset to default).")] = None,
    digest: Annotated[str | None, Field(description="Optional 64-char SHA-256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM, digest-gated): update PMG ClamAV config. Dry-run by default — the PLAN
    reads the current config first and flags `archiveblockencrypted` weakening and any of the 4
    scan-limit fields narrowing below their current value. `delete_props`, if given, is disclosed
    explicitly. confirm=True executes (PUT /config/clamav) and returns {"status": "ok", "result":
    None}. Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/clamav"
    fields = dict(
        archiveblockencrypted=archiveblockencrypted, archivemaxfiles=archivemaxfiles,
        archivemaxrec=archivemaxrec, archivemaxsize=archivemaxsize, dbmirror=dbmirror,
        maxcccount=maxcccount, maxscansize=maxscansize, scriptedupdates=scriptedupdates,
    )
    return run_governed(
        "pmg_config_clamav_update", tgt,
        plan=lambda: plan_clamav_config_update(pmg, delete_props=delete_props, **fields),
        execute=lambda: clamav_config_update(
                        pmg, archiveblockencrypted=archiveblockencrypted,
                        archivemaxfiles=archivemaxfiles, archivemaxrec=archivemaxrec,
                        archivemaxsize=archivemaxsize, dbmirror=dbmirror, maxcccount=maxcccount,
                        maxscansize=maxscansize, scriptedupdates=scriptedupdates,
                        delete_props=delete_props, digest=digest,
                    ),
        confirm=confirm)


# ---------------------------------------------------------------------------
# Global config — mail (GET already shipped as pmg_relay_config)
# ---------------------------------------------------------------------------

@tool()
def pmg_config_mail_update(
    accept_broken_mime: Annotated[bool | None, Field(description="Accept mail with broken MIME structure (insecure; adds an X-Proxmox-Broken-Message header). Omit to leave unchanged.")] = None,
    banner: Annotated[str | None, Field(description="ESMTP banner text. Omit to leave unchanged.")] = None,
    before_queue_filtering: Annotated[bool | None, Field(description="Enable before-queue filtering by pmg-smtp-filter. Omit to leave unchanged.")] = None,
    conn_count_limit: Annotated[int | None, Field(description="Max simultaneous connections per client (0=unlimited). Omit to leave unchanged.")] = None,
    conn_rate_limit: Annotated[int | None, Field(description="Max connection attempts per client per minute (0=unlimited). Omit to leave unchanged.")] = None,
    dnsbl_sites: Annotated[str | None, Field(description="DNS block/welcome-list domains (postfix postscreen_dnsbl_sites). Omit to leave unchanged.")] = None,
    dnsbl_threshold: Annotated[int | None, Field(description="DNSBL score threshold to block a client. Omit to leave unchanged.")] = None,
    dwarning: Annotated[int | None, Field(description="SMTP delay-warning time, in hours. Omit to leave unchanged.")] = None,
    ext_port: Annotated[int | None, Field(description="SMTP port for incoming (untrusted) mail. Omit to leave unchanged.")] = None,
    filter_timeout: Annotated[int | None, Field(description="Timeout (seconds, 2-86400) for processing one mail. Omit to leave unchanged.")] = None,
    greylist: Annotated[bool | None, Field(description="Use greylisting for IPv4. Omit to leave unchanged.")] = None,
    greylist6: Annotated[bool | None, Field(description="Use greylisting for IPv6. Omit to leave unchanged.")] = None,
    greylistmask4: Annotated[int | None, Field(description="Netmask applied for greylisting IPv4 hosts (0-32). Omit to leave unchanged.")] = None,
    greylistmask6: Annotated[int | None, Field(description="Netmask applied for greylisting IPv6 hosts (0-128). Omit to leave unchanged.")] = None,
    helotests: Annotated[bool | None, Field(description="Use SMTP HELO tests. Omit to leave unchanged.")] = None,
    hide_received: Annotated[bool | None, Field(description="Hide the Received header in outgoing mail. Omit to leave unchanged.")] = None,
    int_port: Annotated[int | None, Field(description="SMTP port for outgoing (trusted) mail. Omit to leave unchanged.")] = None,
    log_headers: Annotated[bool | None, Field(description="Log envelope sender/recipient + decoded From/To/Subject to the mail log (writes personal data — check data-protection obligations). Omit to leave unchanged.")] = None,
    max_filters: Annotated[int | None, Field(description="Max pmg-smtp-filter processes (3-40). Omit to leave unchanged.")] = None,
    max_policy: Annotated[int | None, Field(description="Max pmgpolicy processes (2-10). Omit to leave unchanged.")] = None,
    max_smtpd_in: Annotated[int | None, Field(description="Max inbound SMTP daemon processes (3-100). Omit to leave unchanged.")] = None,
    max_smtpd_out: Annotated[int | None, Field(description="Max outbound SMTP daemon processes (3-100). Omit to leave unchanged.")] = None,
    maxsize: Annotated[int | None, Field(description="Max email size in bytes (>=1024); larger mail is rejected. Omit to leave unchanged.")] = None,
    message_rate_limit: Annotated[int | None, Field(description="Max message-delivery requests per client per minute (0=unlimited). Omit to leave unchanged.")] = None,
    ndr_on_block: Annotated[bool | None, Field(description="Send an NDR (bounce) when mail is blocked. Omit to leave unchanged.")] = None,
    queue_lifetime: Annotated[int | None, Field(description="Max days (1-100) a deferred/bounce message stays queued before returning to sender. Omit to leave unchanged.")] = None,
    rejectunknown: Annotated[bool | None, Field(description="Reject unknown clients (unresolvable hostname). Omit to leave unchanged.")] = None,
    rejectunknownsender: Annotated[bool | None, Field(description="Reject unknown senders (unresolvable sender domain). Omit to leave unchanged.")] = None,
    relay: Annotated[str | None, Field(description="Default mail delivery transport for incoming mail. Changing this reroutes ALL matching mail — flagged in the plan. Omit to leave unchanged.")] = None,
    relaynomx: Annotated[bool | None, Field(description="Disable MX lookups for the default relay (SMTP only). Omit to leave unchanged.")] = None,
    relayport: Annotated[int | None, Field(description="SMTP/LMTP port for the relay host. Omit to leave unchanged.")] = None,
    relayprotocol: Annotated[str | None, Field(description="Transport protocol for the relay host: 'smtp' or 'lmtp'. Omit to leave unchanged.")] = None,
    smarthost: Annotated[str | None, Field(description="Smarthost for ALL outgoing mail. Changing this reroutes ALL outbound mail — flagged in the plan. Omit to leave unchanged.")] = None,
    smarthostport: Annotated[int | None, Field(description="SMTP port for the smarthost. Omit to leave unchanged.")] = None,
    smtputf8: Annotated[bool | None, Field(description="Enable SMTPUTF8 support. Omit to leave unchanged.")] = None,
    spf: Annotated[bool | None, Field(description="Use Sender Policy Framework checks. False disables SPF — flagged in the plan. Omit to leave unchanged.")] = None,
    tls: Annotated[bool | None, Field(description="Enable TLS. False disables TLS (SECURITY-LOOSENING) — flagged in the plan. Omit to leave unchanged.")] = None,
    tlsheader: Annotated[bool | None, Field(description="Add a TLS-received header. Omit to leave unchanged.")] = None,
    tlslog: Annotated[bool | None, Field(description="Enable TLS logging. Omit to leave unchanged.")] = None,
    verifyreceivers: Annotated[str | None, Field(description="Enable receiver verification; the reply code on rejection: '450' or '550'. Omit to leave unchanged.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear (reset to default).")] = None,
    digest: Annotated[str | None, Field(description="Optional 64-char SHA-256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM, digest-gated): update PMG mail/SMTP/relay/greylist/DNSBL config — the
    single richest config surface on the whole PMG plane (39 fields). Dry-run by default — the
    PLAN reuses the already-shipped `pmg_relay_config` read for CAPTURE, and flags `tls=False`/
    `spf=False` (explicit disable) and a `relay`/`smarthost` change (reroutes ALL matching mail)
    loudly. `delete_props`, if given, is disclosed explicitly. Use `pmg_relay_config` (already
    shipped) to read the current config. confirm=True executes (PUT /config/mail) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/mail"
    fields = dict(
        accept_broken_mime=accept_broken_mime, banner=banner,
        before_queue_filtering=before_queue_filtering, conn_count_limit=conn_count_limit,
        conn_rate_limit=conn_rate_limit, dnsbl_sites=dnsbl_sites, dnsbl_threshold=dnsbl_threshold,
        dwarning=dwarning, ext_port=ext_port, filter_timeout=filter_timeout, greylist=greylist,
        greylist6=greylist6, greylistmask4=greylistmask4, greylistmask6=greylistmask6,
        helotests=helotests, hide_received=hide_received, int_port=int_port,
        log_headers=log_headers, max_filters=max_filters, max_policy=max_policy,
        max_smtpd_in=max_smtpd_in, max_smtpd_out=max_smtpd_out, maxsize=maxsize,
        message_rate_limit=message_rate_limit, ndr_on_block=ndr_on_block,
        queue_lifetime=queue_lifetime, rejectunknown=rejectunknown,
        rejectunknownsender=rejectunknownsender, relay=relay, relaynomx=relaynomx,
        relayport=relayport, relayprotocol=relayprotocol, smarthost=smarthost,
        smarthostport=smarthostport, smtputf8=smtputf8, spf=spf, tls=tls, tlsheader=tlsheader,
        tlslog=tlslog, verifyreceivers=verifyreceivers,
    )
    return run_governed(
        "pmg_config_mail_update", tgt,
        plan=lambda: plan_mail_config_update(pmg, delete_props=delete_props, **fields),
        execute=lambda: mail_config_update(
                        pmg, accept_broken_mime=accept_broken_mime, banner=banner,
                        before_queue_filtering=before_queue_filtering,
                        conn_count_limit=conn_count_limit, conn_rate_limit=conn_rate_limit,
                        dnsbl_sites=dnsbl_sites, dnsbl_threshold=dnsbl_threshold,
                        dwarning=dwarning, ext_port=ext_port, filter_timeout=filter_timeout,
                        greylist=greylist, greylist6=greylist6, greylistmask4=greylistmask4,
                        greylistmask6=greylistmask6, helotests=helotests,
                        hide_received=hide_received, int_port=int_port, log_headers=log_headers,
                        max_filters=max_filters, max_policy=max_policy,
                        max_smtpd_in=max_smtpd_in, max_smtpd_out=max_smtpd_out, maxsize=maxsize,
                        message_rate_limit=message_rate_limit, ndr_on_block=ndr_on_block,
                        queue_lifetime=queue_lifetime, rejectunknown=rejectunknown,
                        rejectunknownsender=rejectunknownsender, relay=relay,
                        relaynomx=relaynomx, relayport=relayport, relayprotocol=relayprotocol,
                        smarthost=smarthost, smarthostport=smarthostport, smtputf8=smtputf8,
                        spf=spf, tls=tls, tlsheader=tlsheader, tlslog=tlslog,
                        verifyreceivers=verifyreceivers, delete_props=delete_props, digest=digest,
                    ),
        confirm=confirm)


# ---------------------------------------------------------------------------
# Global config — spamquar
# ---------------------------------------------------------------------------

@tool()
def pmg_config_spamquar_get() -> dict:
    """READ-ONLY: read PMG spam-quarantine config (auth mode, lifetime, quarantine-link
    self-service toggle, report style). Schema-thin — passed through best-effort. Needs
    PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_config_spamquar_get", "pmg/config/spamquar", lambda: spamquar_config_get(pmg))


@tool()
def pmg_config_spamquar_update(
    allowhrefs: Annotated[bool | None, Field(description="Allow viewing hyperlinks in quarantined spam mail (else shown as plain text). Omit to leave unchanged.")] = None,
    authmode: Annotated[str | None, Field(description="Quarantine-interface auth mode: 'ticket' (email-ticket login), 'ldap' (LDAP account required), or 'ldapticket' (both). Weakening toward 'ticket' from 'ldap'/'ldapticket' is flagged. Omit to leave unchanged.")] = None,
    hostname: Annotated[str | None, Field(description="Quarantine host — useful in a cluster to direct users to a specific host. Omit to leave unchanged.")] = None,
    lifetime: Annotated[int | None, Field(description="Quarantine lifetime, in days (>=1). Omit to leave unchanged.")] = None,
    mailfrom: Annotated[str | None, Field(description="'From' header text for daily spam-report mail. Omit to leave unchanged.")] = None,
    port: Annotated[int | None, Field(description="Quarantine port, for a reverse proxy/port-forward — only used in the generated spam report. Omit to leave unchanged.")] = None,
    protocol: Annotated[str | None, Field(description="Quarantine web-interface protocol for the spam report: 'http' or 'https'. Omit to leave unchanged.")] = None,
    quarantinelink: Annotated[bool | None, Field(description="Enable user self-service Quarantine Links. UPSTREAM CAUTION: 'accessible without authentication'. Setting True is flagged loudly. Omit to leave unchanged.")] = None,
    reportstyle: Annotated[str | None, Field(description="Spam-report style: 'none', 'short', 'verbose', or 'custom'. Omit to leave unchanged.")] = None,
    viewimages: Annotated[str | None, Field(description="Image display in quarantined mail: '1' (all, incl. externally-hosted), '0' (hidden), or 'on-demand'. Omit to leave unchanged.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear (reset to default).")] = None,
    digest: Annotated[str | None, Field(description="Optional 64-char SHA-256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM, digest-gated): update PMG spam-quarantine config. Dry-run by default —
    the PLAN reads the current config first and flags `quarantinelink=True` (upstream's own
    unauthenticated-access caution) and `authmode` weakening toward 'ticket'. `delete_props`, if
    given, is disclosed explicitly. confirm=True executes (PUT /config/spamquar) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/spamquar"
    fields = dict(
        allowhrefs=allowhrefs, authmode=authmode, hostname=hostname, lifetime=lifetime,
        mailfrom=mailfrom, port=port, protocol=protocol, quarantinelink=quarantinelink,
        reportstyle=reportstyle, viewimages=viewimages,
    )
    return run_governed(
        "pmg_config_spamquar_update", tgt,
        plan=lambda: plan_spamquar_config_update(pmg, delete_props=delete_props, **fields),
        execute=lambda: spamquar_config_update(
                        pmg, allowhrefs=allowhrefs, authmode=authmode, hostname=hostname,
                        lifetime=lifetime, mailfrom=mailfrom, port=port, protocol=protocol,
                        quarantinelink=quarantinelink, reportstyle=reportstyle,
                        viewimages=viewimages, delete_props=delete_props, digest=digest,
                    ),
        confirm=confirm)


# ---------------------------------------------------------------------------
# Global config — virusquar
# ---------------------------------------------------------------------------

@tool()
def pmg_config_virusquar_get() -> dict:
    """READ-ONLY: read PMG virus-quarantine config (hyperlink display, lifetime, image display).
    Schema-thin — passed through best-effort. Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_config_virusquar_get", "pmg/config/virusquar", lambda: virusquar_config_get(pmg))


@tool()
def pmg_config_virusquar_update(
    allowhrefs: Annotated[bool | None, Field(description="Allow viewing hyperlinks in quarantined virus mail (else shown as plain text). Quarantined mail is attacker-authored — setting True is flagged as a phishing-link caution. Omit to leave unchanged.")] = None,
    lifetime: Annotated[int | None, Field(description="Quarantine lifetime, in days (>=1). Omit to leave unchanged.")] = None,
    viewimages: Annotated[str | None, Field(description="Image display in quarantined mail: '1' (all, incl. externally-hosted), '0' (hidden), or 'on-demand'. Omit to leave unchanged.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear (reset to default).")] = None,
    digest: Annotated[str | None, Field(description="Optional 64-char SHA-256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM, digest-gated): update PMG virus-quarantine config. Dry-run by default —
    the PLAN reads the current config first and flags `allowhrefs=True` (quarantined virus mail
    is attacker-authored; clickable links are a phishing risk). `delete_props`, if given, is
    disclosed explicitly. confirm=True executes (PUT /config/virusquar) and returns {"status":
    "ok", "result": None}. Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/virusquar"
    fields = dict(allowhrefs=allowhrefs, lifetime=lifetime, viewimages=viewimages)
    return run_governed(
        "pmg_config_virusquar_update", tgt,
        plan=lambda: plan_virusquar_config_update(pmg, delete_props=delete_props, **fields),
        execute=lambda: virusquar_config_update(
                        pmg, allowhrefs=allowhrefs, lifetime=lifetime, viewimages=viewimages,
                        delete_props=delete_props, digest=digest,
                    ),
        confirm=confirm)


# ---------------------------------------------------------------------------
# Global config — tfa/webauthn
# ---------------------------------------------------------------------------

@tool()
def pmg_config_tfa_webauthn_get() -> dict:
    """READ-ONLY: read PMG webauthn config (relying-party id/origin/name, subdomain-allow flag).
    Richly typed on this plane (the one exception among the 5 GET-verbed global-config reads in
    this chunk, which are all schema-thin). Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_config_tfa_webauthn_get", "pmg/config/tfa/webauthn",
                    lambda: tfa_webauthn_config_get(pmg))


@tool()
def pmg_config_tfa_webauthn_update(
    allow_subdomains: Annotated[bool | None, Field(description="Allow the origin to be a subdomain rather than the exact URL. Omit to leave unchanged.")] = None,
    id_: Annotated[str | None, Field(description="Relying-party ID — the domain name, without protocol/port/location. Changing this WILL break existing WebAuthn credentials (upstream wording verbatim) — flagged loudly. Omit to leave unchanged.")] = None,
    origin: Annotated[str | None, Field(description="Site origin — an https:// URL (or http://localhost). Changing this MAY break existing WebAuthn credentials (upstream wording verbatim). Omit to leave unchanged.")] = None,
    rp: Annotated[str | None, Field(description="Relying-party name — any text identifier. Changing this MAY break existing WebAuthn credentials (upstream wording verbatim). Omit to leave unchanged.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear: 'allow-subdomains', 'id', 'origin', or 'rp'.")] = None,
    digest: Annotated[str | None, Field(description="Optional 40-char SHA-1 config digest to prevent concurrent modifications — a genuine divergence from this chunk's other 5 config families, which use a 64-char SHA-256 digest.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM, digest-gated — SHA1/40-char, NOT this chunk's usual SHA256/64-char):
    update PMG webauthn config. Dry-run by default — the PLAN reads the current config first and
    flags `id_`/`origin`/`rp` changes with upstream's own "will"/"may" break existing credentials
    wording. `delete_props`, if given, is disclosed explicitly. NOTE: PMG's own PUT description
    text is byte-identical to its GET's ("Read the webauthn configuration.") — a documented
    upstream copy-paste label bug; this tool's own verb/param/return shape is a genuine write.
    confirm=True executes (PUT /config/tfa/webauthn) and returns {"status": "ok", "result": None}.
    Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/tfa/webauthn"
    fields = dict(allow_subdomains=allow_subdomains, id_=id_, origin=origin, rp=rp)
    return run_governed(
        "pmg_config_tfa_webauthn_update", tgt,
        plan=lambda: plan_tfa_webauthn_config_update(pmg, delete_props=delete_props, **fields),
        execute=lambda: tfa_webauthn_config_update(
                        pmg, allow_subdomains=allow_subdomains, id_=id_, origin=origin, rp=rp,
                        delete_props=delete_props, digest=digest,
                    ),
        confirm=confirm)


# ---------------------------------------------------------------------------
# Cluster — reads
# ---------------------------------------------------------------------------

@tool()
def pmg_cluster_join_info() -> dict:
    """READ-ONLY: get the information a NEW node needs to join THIS cluster — the master's own
    address + certificate fingerprint (meant to be base64-encoded and pasted into the new node's
    own join dialog). PUBLIC verification material only — no secret. Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_cluster_join_info", "pmg/config/cluster/join", lambda: cluster_join_info(pmg))


@tool()
def pmg_cluster_nodes_list() -> list[dict]:
    """READ-ONLY: list this PMG cluster's member nodes (cid/fingerprint/hostrsapubkey/ip/name/
    rootrsapubkey/type). PUBLIC verification material only — fingerprint and SSH host/root
    PUBLIC keys, not secrets. Needs PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_cluster_nodes_list", "pmg/config/cluster/nodes", lambda: cluster_nodes_list(pmg))


@tool()
def pmg_cluster_status(
    list_single_node: Annotated[bool | None, Field(description="Also list the local node when no cluster is defined. Upstream note: RSA keys/fingerprint are not valid in that case.")] = None,
) -> list[dict]:
    """READ-ONLY: get PMG cluster node status. PUBLIC verification material only. Needs
    PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    return _audited("pmg_cluster_status", "pmg/config/cluster/status",
                    lambda: cluster_status(pmg, list_single_node))


# ---------------------------------------------------------------------------
# Cluster — mutations (RULING 1, campaign coordinator, binding)
# ---------------------------------------------------------------------------

@tool()
def pmg_cluster_create(
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (RISK_HIGH, NO UNDO): bootstrap THIS PMG node as a NEW cluster's master (POST
    /config/cluster/create, no parameters). Dry-run by default — the PLAN's FIRST blast_radius
    line states plainly: Proximo has NO undo for this, and NO visibility into un-clustering once
    complete (RULING 1) — unlike pmg_ruledb_reset, there is NO backup-and-restore escape hatch
    here at all. The PLAN also reads current cluster status for context (whether this node may
    already be part of a cluster).

    Returns a schema-ambiguous string (UPID vs. plain status, unresolved from schema alone) —
    confirm=True records outcome="submitted" (mirrors pmg_node_network_reload's identical-
    ambiguity precedent), the raw string recorded BOTH in the response's "result" AND in the
    ledger's own detail.raw_result. Needs PROXIMO_PMG_* config.
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/cluster/create"
    plan = _plan("pmg_cluster_create", tgt, lambda: plan_cluster_create(pmg))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    detail: dict = {"confirmed": True}

    def _do_create():
        raw = cluster_create(pmg)
        detail["raw_result"] = raw
        return raw

    return _audited("pmg_cluster_create", tgt, _do_create, mutation=True, outcome="submitted", detail=detail)


@tool()
def pmg_cluster_join(
    fingerprint: Annotated[str, Field(description="Certificate SHA-256 fingerprint of the target cluster's master node (from that master's own pmg_cluster_join_info).")],
    master_ip: Annotated[str, Field(description="IP address of the target cluster's master node to join.")],
    password: Annotated[str, Field(description="The TARGET MASTER's OWN root/superuser password (a THIRD-PARTY credential, not the caller's own secret) — transmitted in transit to authenticate the join; redacted from all plans/logs/ledger.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (RISK_HIGH, NO UNDO, THIRD-PARTY CREDENTIAL): join THIS PMG node to an EXISTING
    cluster identified by `master_ip`/`fingerprint`. Dry-run by default — the PLAN's FIRST
    blast_radius line states plainly: Proximo has NO undo for this, and NO visibility into
    un-clustering once complete (RULING 1) — unlike pmg_ruledb_reset, there is NO backup-and-
    restore escape hatch here at all. The PLAN's SECOND line states plainly that this transmits
    the TARGET MASTER's OWN superuser password through Proximo IN TRANSIT — a genuinely different
    secret-handling shape than every other secret this codebase handles (which all belong to the
    CALLER's own configured target, not a third party). `password` is UNCONDITIONALLY redacted
    from the plan/detail/ledger — the plan factory itself never receives it at all. The PLAN also
    reads current cluster status for context (whether this node may already be part of a
    different cluster).

    Returns a schema-ambiguous string (UPID vs. plain status) — confirm=True records
    outcome="submitted" (mirrors pmg_node_network_reload's identical-ambiguity precedent). UNLIKE
    pmg_cluster_create, the raw string is NEVER recorded to the ledger's detail.raw_result: this
    endpoint's return is schema-typed ONLY as a bare string with no further constraint, so its
    CONTENT is not schema-guaranteed safe — a hostile or auth-failure-shaped response could echo
    the just-submitted third-party `password` straight back (Wave 9i review CRITICAL finding).
    RULING 1 is unconditional here: never-in-ledger, never-echoed. The response's "result" field
    still carries the raw string (so the caller can see the real outcome), but with the exact
    submitted `password` substring scrubbed out first — defense in depth, since a scrubbed value
    can't leak further even if the caller's own tooling logs the response downstream. Needs
    PROXIMO_PMG_* config.
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/cluster/join"
    pw_detail = _join_password_redacted_detail(password)
    plan = _plan("pmg_cluster_join", tgt, lambda: plan_cluster_join(pmg, fingerprint, master_ip))
    if not confirm:
        return {"status": "plan", **plan.as_dict(), **pw_detail}
    detail: dict = {**pw_detail, "confirmed": True}

    def _do_join():
        raw = cluster_join(pmg, fingerprint, master_ip, password)
        # Wave 9i review CRITICAL fix: `raw` is UNTRUSTED, possibly-secret-bearing content (see
        # the docstring above) — do NOT forward it into the ledger detail at all, under
        # "raw_result" or any other key (the Wave 9f minimal-detail-wrapper precedent: omit
        # rather than trust an unconstrained string). `detail` records only a fixed, safe marker
        # — no runtime-derived content, so it cannot possibly leak anything regardless of what
        # PMG's own response said. Deliberately NOT the "raw_result" key name (used by
        # pmg_cluster_create, whose raw_result IS safe to keep verbatim — that endpoint takes no
        # secret parameter) — a different key name makes the two shapes unmistakable.
        detail["raw_result_omitted"] = (
            "cluster-join's response is untrusted content and may echo the submitted password — "
            "RULING 1 forbids storing it in the ledger; see this call's returned 'result' for a "
            "password-scrubbed copy"
        )
        # Defense in depth: scrub the exact submitted password out of the CALLER-facing string
        # too. The caller already supplied this password, so seeing it back isn't a NEW
        # disclosure to them — but a scrubbed value can't propagate further downstream.
        if isinstance(raw, str) and password:
            raw = raw.replace(password, "[redacted]")
        return raw

    return _audited("pmg_cluster_join", tgt, _do_join, mutation=True, outcome="submitted", detail=detail)


@tool()
def pmg_cluster_node_add(
    fingerprint: Annotated[str, Field(description="Certificate SHA-256 fingerprint of the node being registered.")],
    hostrsapubkey: Annotated[str, Field(description="Public SSH RSA key for the node's host.")],
    ip: Annotated[str, Field(description="IP address of the node being registered.")],
    name: Annotated[str, Field(description="Node name.")],
    rootrsapubkey: Annotated[str, Field(description="Public SSH RSA key for the node's root user.")],
    max_cid: Annotated[int | None, Field(description="Maximum used cluster node ID — upstream's own field description: 'used internally, do not modify' unless you know what you're doing.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (RISK_MEDIUM, bookkeeping): register a node into THIS cluster's config (POST
    /config/cluster/nodes) — RULING 1's MEDIUM branch: cluster-membership bookkeeping, NOT
    identity fusion (the actual fusion already happened via a prior pmg_cluster_create/
    pmg_cluster_join on the node being registered). `fingerprint`/`hostrsapubkey`/`rootrsapubkey`
    are PUBLIC verification material, not secrets. Dry-run by default. confirm=True executes and
    returns {"status": "ok", "result": <the resulting node list — real, if thin: {cid} per
    item>}. Needs PROXIMO_PMG_* config.
    """
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/cluster/nodes"
    return run_governed(
        "pmg_cluster_node_add", tgt,
        plan=lambda: plan_cluster_node_add(fingerprint, hostrsapubkey, ip, name, rootrsapubkey, max_cid),
        execute=lambda: cluster_node_add(pmg, fingerprint, hostrsapubkey, ip, name, rootrsapubkey, max_cid),
        confirm=confirm)


@tool()
def pmg_cluster_update_fingerprints(
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (RISK_MEDIUM, bookkeeping): refresh API certificate fingerprints for every cluster
    node, fetched via ssh (POST /config/cluster/update-fingerprints, no parameters) — RULING 1's
    MEDIUM branch: fingerprint bookkeeping, not identity fusion. Dry-run by default. confirm=True
    executes and returns {"status": "ok", "result": None} (schema: null, synchronous). Needs
    PROXIMO_PMG_* config."""
    _, pmg = _proximo_server._pmg()
    tgt = "pmg/config/cluster/update-fingerprints"
    return run_governed(
        "pmg_cluster_update_fingerprints", tgt,
        plan=lambda: plan_cluster_update_fingerprints(),
        execute=lambda: cluster_update_fingerprints(pmg),
        confirm=confirm)
