"""PBS access governance: users, API tokens, ACL, roles, permissions (Wave 2a), realms + TFA
(Wave 2b) — full-surface campaign, `.scratch/2026-07-15-full-surface-campaign.md`, "2a — PBS
identity core" / "2b — PBS realms".

Split out as its own tools module (mirroring tools/pve_access.py's split from tools/pbs.py's
flat layout) because the backend/plan logic lives in its own dedicated proximo.pbs_access module
— see that module's docstring for the endpoint table, the secret classes, and the EXCLUSIONs
these two waves close (pbs_config.py named PBS access as deliberately out of its own scope; 2a
itself named realms/TFA as its own carried-forward exclusion, closed here by 2b).
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_access import (
    _client_key_redacted_detail,
    _password_redacted_detail,
    acl_get,
    acl_update,
    permissions_get,
    plan_acl_update,
    plan_realm_ad_create,
    plan_realm_ad_delete,
    plan_realm_ad_update,
    plan_realm_ldap_create,
    plan_realm_ldap_delete,
    plan_realm_ldap_update,
    plan_realm_openid_create,
    plan_realm_openid_delete,
    plan_realm_openid_update,
    plan_realm_pam_set,
    plan_realm_pbs_set,
    plan_tfa_add,
    plan_tfa_delete,
    plan_tfa_unlock,
    plan_tfa_update,
    plan_tfa_webauthn_set,
    plan_token_create,
    plan_token_delete,
    plan_token_update,
    plan_user_create,
    plan_user_delete,
    plan_user_update,
    realm_ad_create,
    realm_ad_delete,
    realm_ad_get,
    realm_ad_list,
    realm_ad_update,
    realm_ldap_create,
    realm_ldap_delete,
    realm_ldap_get,
    realm_ldap_list,
    realm_ldap_update,
    realm_openid_create,
    realm_openid_delete,
    realm_openid_get,
    realm_openid_list,
    realm_openid_update,
    realm_pam_get,
    realm_pam_set,
    realm_pbs_get,
    realm_pbs_set,
    roles_list,
    tfa_add,
    tfa_delete,
    tfa_entry_get,
    tfa_list,
    tfa_unlock,
    tfa_update,
    tfa_user_get,
    tfa_webauthn_get,
    tfa_webauthn_set,
    token_create,
    token_delete,
    token_update,
    user_create,
    user_delete,
    user_get,
    user_token_get,
    user_tokens_list,
    user_update,
    users_list,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Users (read) ---

@tool()
def pbs_users_list(
    include_tokens: Annotated[
        bool, Field(description="If True, embed each user's API tokens (metadata only, no secrets) in the result."),
    ] = False,
) -> list[dict]:
    """READ-ONLY: list all PBS users. Returns each user's userid, enabled flag, expiry, email,
    comment, and firstname/lastname; include_tokens=True also embeds token metadata (never
    secrets). Use pbs_user_get for one user's full config or pbs_user_tokens_list for a
    dedicated token listing. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_users_list", "pbs/access/users",
                    lambda: users_list(pbs, include_tokens))


@tool()
def pbs_user_get(
    userid: Annotated[str, Field(description="PBS user id to look up, format 'user@realm'.")],
) -> dict:
    """READ-ONLY: get a PBS user's config. Returns userid, enabled flag, expiry, email, comment,
    firstname/lastname (no tokens, no secrets). Use pbs_user_tokens_list for the user's API
    tokens, or pbs_user_create/update/delete to manage the user. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_user_get", f"pbs/access/users/{userid}", lambda: user_get(pbs, userid))


# --- Users (mutation) ---

@tool()
def pbs_user_create(
    userid: Annotated[str, Field(description="New PBS user id, format 'user@realm'.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment.")] = None,
    email: Annotated[str | None, Field(description="Optional email address.")] = None,
    enable: Annotated[bool | None, Field(description="Whether the account can log in; None defers to PBS's default (enabled).")] = None,
    expire: Annotated[int | None, Field(description="Optional account expiry as a Unix timestamp; None/0 means no expiry.")] = None,
    firstname: Annotated[str | None, Field(description="Optional first name.")] = None,
    lastname: Annotated[str | None, Field(description="Optional last name.")] = None,
    password: Annotated[
        str | None, Field(description="Optional initial password (min 8 chars per PBS); redacted from all plans/logs/ledger. Can also be set later via a separate password-change flow."),
    ] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): create a PBS user. Dry-run by default.

    PASSWORD REDACTION: `password` is OPTIONAL and, when supplied, a real credential — it is
    UNCONDITIONALLY redacted from the plan, detail, and audit ledger (only
    {"password": "[redacted]"} is recorded; omitted entirely when no password was given).

    confirm=True executes and returns a dict; synchronous, no UPID. Use pbs_user_update to
    change it afterward, or pbs_user_delete to remove it. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/access/users/{userid}"
    pw_detail = _password_redacted_detail(password)
    return run_governed(
        "pbs_user_create", tgt,
        plan=lambda: plan_user_create(userid, comment, email, enable, expire, firstname, lastname),
        execute=lambda: user_create(pbs, userid, comment, email, enable, expire,
                                       firstname, lastname, password),
        confirm=confirm, surface=pw_detail)


@tool()
def pbs_user_update(
    userid: Annotated[str, Field(description="PBS user id to update, format 'user@realm'.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment; omit to leave unchanged.")] = None,
    email: Annotated[str | None, Field(description="Optional email address; omit to leave unchanged.")] = None,
    enable: Annotated[bool | None, Field(description="Whether the account can log in; False stops login. Omit to leave unchanged.")] = None,
    expire: Annotated[int | None, Field(description="Account expiry as a Unix timestamp; omit to leave unchanged.")] = None,
    firstname: Annotated[str | None, Field(description="Optional first name; omit to leave unchanged.")] = None,
    lastname: Annotated[str | None, Field(description="Optional last name; omit to leave unchanged.")] = None,
    delete_props: Annotated[
        list[str] | None, Field(description="Property names to clear: any of 'comment', 'firstname', 'lastname', 'email'."),
    ] = None,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a PBS user (enable=False stops login immediately). Dry-run by
    default — the PLAN reads the user's current config first.

    NOTE: this tool does NOT accept a password parameter — PBS's own PUT /access/users
    'password' field is documented as ignored ("use PUT /access/password instead"); exposing a
    working-looking no-op parameter here would mislead a caller into thinking it changed the
    password.

    confirm=True executes and returns a dict; synchronous, no UPID. Use pbs_user_get to see
    current state first, or pbs_user_delete to remove the user instead. Needs PROXIMO_PBS_*
    config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/access/users/{userid}"
    return run_governed(
        "pbs_user_update", tgt,
        plan=lambda: plan_user_update(pbs, userid, comment, email, enable, expire,
                                          firstname, lastname, delete_props),
        execute=lambda: user_update(pbs, userid, comment, email, enable, expire,
                                       firstname, lastname, delete_props, digest),
        confirm=confirm)


@tool()
def pbs_user_delete(
    userid: Annotated[str, Field(description="PBS user id to delete, format 'user@realm'.")],
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): delete a PBS user. Dry-run by default — the PLAN reads the user's
    current config and tokens to show what vanishes with it (permanent, no undo — any tokens
    owned by this user are removed with it, and ACL entries granted directly to this userid
    become orphaned). confirm=True executes and returns a dict; synchronous, no UPID. To disable
    login without deleting, use pbs_user_update (enable=False) instead. Needs PROXIMO_PBS_*
    config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/access/users/{userid}"
    return run_governed(
        "pbs_user_delete", tgt,
        plan=lambda: plan_user_delete(pbs, userid),
        execute=lambda: user_delete(pbs, userid, digest),
        confirm=confirm)


# --- API tokens (read) ---

@tool()
def pbs_user_tokens_list(
    userid: Annotated[str, Field(description="Owning PBS user, format 'user@realm'.")],
) -> list[dict]:
    """READ-ONLY: list API tokens for a PBS user. Returns each token's token-name, tokenid,
    comment, expiry, and enabled flag — NOT the secret (shown only once, at creation or
    regeneration). Use pbs_token_create/update/delete to manage tokens. Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_user_tokens_list", f"pbs/access/users/{userid}/token",
                    lambda: user_tokens_list(pbs, userid))


@tool()
def pbs_user_token_get(
    userid: Annotated[str, Field(description="Owning PBS user, format 'user@realm'.")],
    token_name: Annotated[str, Field(description="Token name (the part after '!' in the full tokenid).")],
) -> dict:
    """READ-ONLY: get one PBS API token's metadata. Returns comment, expiry, enabled flag,
    token-name, and tokenid — NOT the secret. Use pbs_user_tokens_list to enumerate a user's
    tokens first. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_user_token_get", f"pbs/access/users/{userid}/token/{token_name}",
                    lambda: user_token_get(pbs, userid, token_name))


# --- API tokens (mutation) ---

@tool()
def pbs_token_create(
    userid: Annotated[str, Field(description="Owning PBS user, format 'user@realm'.")],
    token_name: Annotated[str, Field(description="Name for the new API token, unique per user.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment describing the token's purpose.")] = None,
    enable: Annotated[bool | None, Field(description="Whether the token is usable immediately; None defers to PBS's default (enabled).")] = None,
    expire: Annotated[int | None, Field(description="Optional token expiry as a Unix timestamp; None/0 means no expiry.")] = None,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): create an API token for a PBS user.

    Dry-run by default. PBS has NO privsep concept (unlike PVE) — the new token has NO
    privileges until an ACL entry grants it some (pbs_acl_update with
    auth_id='{userid}!{token_name}'). confirm=True executes and returns a dict whose result
    carries the token secret (value) ONCE — it is never written to the audit ledger and cannot
    be retrieved again (only regenerated via pbs_token_update, which invalidates it).
    Synchronous. Use pbs_user_tokens_list to see a user's existing tokens, or pbs_token_delete to
    remove one. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/access/users/{userid}/token/{token_name}"
    # SECRET HANDLING: return op result directly (carries the token value to caller);
    # detail dict must NEVER contain the secret — only {"confirmed": True} + non-secret params.
    return run_governed(
        "pbs_token_create", tgt,
        plan=lambda: plan_token_create(userid, token_name, comment, enable, expire),
        execute=lambda: token_create(pbs, userid, token_name, comment, enable, expire, digest),
        confirm=confirm, detail={"enable": enable, "expire": expire})


@tool()
def pbs_token_update(
    userid: Annotated[str, Field(description="Owning PBS user, format 'user@realm'.")],
    token_name: Annotated[str, Field(description="Name of the API token to update.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment; omit to leave unchanged.")] = None,
    enable: Annotated[bool | None, Field(description="Whether the token is usable; False disables it immediately. Omit to leave unchanged.")] = None,
    expire: Annotated[int | None, Field(description="Token expiry as a Unix timestamp; omit to leave unchanged.")] = None,
    regenerate: Annotated[
        bool, Field(description="If True, issue a BRAND-NEW secret and invalidate the old one immediately (RISK_HIGH — any system using the old token loses access instantly)."),
    ] = False,
    delete_props: Annotated[
        list[str] | None, Field(description="Property names to clear: only 'comment' is supported by PBS on this endpoint."),
    ] = None,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION: update a PBS API token's metadata. Dry-run by default.

    RISK IS CONDITIONAL: regenerate=False is MEDIUM (metadata-only); regenerate=True is HIGH —
    it issues a brand-new secret and invalidates the OLD one IMMEDIATELY, with no grace period,
    breaking any integration still using it. When regenerate=True, confirm=True's result carries
    the NEW secret ONCE (key 'secret') — same never-in-ledger contract as pbs_token_create: the
    detail dict passed to the audit ledger never contains it.

    confirm=True executes and returns a dict; synchronous, no UPID. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/access/users/{userid}/token/{token_name}"
    # SECRET HANDLING: regenerate=True's result may carry a NEW secret ('secret' key) — never
    # put it in detail=. Non-secret params only.
    return run_governed(
        "pbs_token_update", tgt,
        plan=lambda: plan_token_update(userid, token_name, comment, enable, expire,
                                           regenerate, delete_props),
        execute=lambda: token_update(pbs, userid, token_name, comment, enable, expire,
                                        regenerate, delete_props, digest),
        confirm=confirm, detail={"regenerate": regenerate, "enable": enable})


@tool()
def pbs_token_delete(
    userid: Annotated[str, Field(description="Owning PBS user, format 'user@realm'.")],
    token_name: Annotated[str, Field(description="Name of the API token to revoke.")],
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM, IRREVERSIBLE): permanently revoke a PBS API token. Dry-run by default —
    the PLAN flags that revocation is permanent, the secret is gone forever, and any integration
    using it loses PBS API access immediately. confirm=True executes and returns a dict;
    synchronous, no UPID. Use pbs_user_tokens_list to see a user's tokens first, or
    pbs_token_create to issue a new one instead. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/access/users/{userid}/token/{token_name}"
    return run_governed(
        "pbs_token_delete", tgt,
        plan=lambda: plan_token_delete(userid, token_name),
        execute=lambda: token_delete(pbs, userid, token_name, digest),
        confirm=confirm)


# --- ACL (read + mutation) ---

@tool()
def pbs_acl_get(
    path: Annotated[str | None, Field(description="ACL path to filter by; omit to return every entry on the server.")] = None,
    exact: Annotated[bool | None, Field(description="If True (with path set), return only entries at the exact path, not the subtree.")] = None,
) -> list[dict]:
    """READ-ONLY: list PBS ACL entries. Returns each entry's path, roleid, ugid (the
    user/token/group id), ugid_type ('user' or 'group'), and propagate flag. Use pbs_acl_update
    to grant/revoke, or pbs_roles_list to see PBS's fixed set of built-in roles. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_acl_get", "pbs/access/acl", lambda: acl_get(pbs, path, exact))


@tool()
def pbs_acl_update(
    path: Annotated[str, Field(description="ACL path the entry applies to, e.g. '/datastore/ds1' or '/'.")],
    role: Annotated[str, Field(description="A single PBS role id to grant or revoke, e.g. 'DatastoreAdmin'.")],
    auth_id: Annotated[
        str | None, Field(description="User or token principal ('user@realm' or 'user@realm!token-name'). Exactly one of auth_id/group is required."),
    ] = None,
    group: Annotated[str | None, Field(description="Group principal. Exactly one of auth_id/group is required.")] = None,
    propagate: Annotated[bool | None, Field(description="Whether the grant propagates to child paths below `path`; omit for PBS's default (true).")] = None,
    delete: Annotated[bool, Field(description="False to grant the role, True to revoke it.")] = False,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (HIGH): grant or revoke a PBS ACL entry (PUT /access/acl) — this GRANTS or
    REVOKES AUTHORITY, so it is treated as HIGH risk unconditionally on this plane (PBS's
    ACL-inheritance/shadow semantics are not schema-documented or live-verified here, unlike
    PVE's plan_acl_modify which computes a shadow/widen preview — every change here is flagged
    HIGH rather than risk under-flagging one this module cannot yet analyze).

    Dry-run by default (reads the current entries at this exact path for context). Exactly one
    of auth_id (a user or token principal) / group is required — PBS's PUT /access/acl carries
    a single 'role' (not PVE's comma-separated multi-role list) and folds user+token identity
    into one 'auth-id' field. delete=False = grant; delete=True = revoke. confirm=True executes
    and returns a dict; synchronous, no UPID. Use pbs_acl_get to see current entries or
    pbs_roles_list to see PBS's fixed set of built-in roles. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    principal = auth_id if auth_id is not None else f"group:{group}"
    tgt = f"pbs/access/acl:{path}:{principal}"
    return run_governed(
        "pbs_acl_update", tgt,
        plan=lambda: plan_acl_update(pbs, path, role, auth_id, group, propagate, delete),
        execute=lambda: acl_update(pbs, path, role, auth_id, group, propagate, delete, digest),
        confirm=confirm)


# --- Roles (read-only — PBS roles are a fixed built-in enum, no CRUD) ---

@tool()
def pbs_roles_list() -> list[dict]:
    """READ-ONLY: list PBS's built-in roles. Returns each role's id, privilege list, and
    comment. PBS roles are a FIXED enum (Admin, Audit, NoAccess, Datastore*/Remote*/Tape* roles)
    — unlike PVE, there is no create/update/delete endpoint for PBS roles. Use pbs_acl_update to
    assign a role to a principal. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_roles_list", "pbs/access/roles", lambda: roles_list(pbs))


# --- Permissions (read-only) ---

@tool()
def pbs_permissions_get(
    auth_id: Annotated[
        str | None, Field(description="User or token to resolve permissions for ('user@realm' or 'user@realm!token-name'); omit for the calling credential's own permissions."),
    ] = None,
    path: Annotated[str | None, Field(description="ACL path to scope the result to; omit for every path the principal has any privilege on.")] = None,
) -> dict:
    """READ-ONLY: resolve effective privileges for a PBS user/token. Returns a map of ACL path
    to a map of privilege name to propagate-bit — the RESOLVED (inherited + direct) view, unlike
    pbs_acl_get's raw entry list. Use pbs_acl_get to see the raw ACL entries this resolves from.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/access/permissions/{auth_id}" if auth_id else "pbs/access/permissions"
    return _audited("pbs_permissions_get", tgt, lambda: permissions_get(pbs, auth_id, path))


# ---------------------------------------------------------------------------
# Realms: AD (Wave 2b)
# ---------------------------------------------------------------------------

@tool()
def pbs_realm_ad_list() -> list[dict]:
    """READ-ONLY: list configured AD realms. Use pbs_realm_ad_get for one realm's full config.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_realm_ad_list", "pbs/config/access/ad", lambda: realm_ad_list(pbs))


@tool()
def pbs_realm_ad_get(
    realm: Annotated[str, Field(description="AD realm name to look up.")],
) -> dict:
    """READ-ONLY: get one AD realm's config. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_realm_ad_get", f"pbs/config/access/ad/{realm}", lambda: realm_ad_get(pbs, realm))


@tool()
def pbs_realm_ad_create(
    realm: Annotated[str, Field(description="New AD realm name.")],
    server1: Annotated[str, Field(description="Primary AD server address.")],
    base_dn: Annotated[str | None, Field(description="LDAP base DN to search under; optional for AD.")] = None,
    bind_dn: Annotated[str | None, Field(description="LDAP bind DN for the service account.")] = None,
    capath: Annotated[str | None, Field(description="Path to a CA certificate file or directory to trust for TLS.")] = None,
    comment: Annotated[str | None, Field(description="Optional free-text comment.")] = None,
    default: Annotated[bool | None, Field(description="True to make this the default realm preselected on login.")] = None,
    filter: Annotated[str | None, Field(description="Custom LDAP search filter for user sync.")] = None,
    mode: Annotated[str | None, Field(description="LDAP connection type: 'ldap', 'ldap+starttls', or 'ldaps'.")] = None,
    password: Annotated[str | None, Field(description="AD bind password for the service account; redacted from all plans/logs/ledger.")] = None,
    port: Annotated[int | None, Field(description="AD server port.")] = None,
    server2: Annotated[str | None, Field(description="Fallback AD server address.")] = None,
    sync_attributes: Annotated[str | None, Field(description="Comma-separated key=value LDAP-attribute-to-PBS-field sync map, forwarded verbatim.")] = None,
    sync_defaults_options: Annotated[str | None, Field(description="Default sync-run options string, forwarded verbatim (exact syntax not live-verified).")] = None,
    user_classes: Annotated[str | None, Field(description="Comma-separated allowed objectClass values for user sync.")] = None,
    verify: Annotated[bool | None, Field(description="Whether to verify the AD server's TLS certificate.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): create an AD authentication realm. Dry-run by default.

    PASSWORD REDACTION: `password` (the AD bind password), when supplied, is UNCONDITIONALLY
    redacted from the plan, detail, and audit ledger (only {"password": "[redacted]"} is
    recorded). confirm=True executes and returns a dict; synchronous, no UPID. Use
    pbs_realm_ad_update to change it afterward, or pbs_realm_ad_delete to remove it. Needs
    PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/access/ad/{realm}"
    pw_detail = _password_redacted_detail(password)
    fields = dict(base_dn=base_dn, bind_dn=bind_dn, capath=capath, comment=comment,
                  default=default, filter=filter, mode=mode, port=port, server2=server2,
                  sync_attributes=sync_attributes, sync_defaults_options=sync_defaults_options,
                  user_classes=user_classes, verify=verify)
    fields = {k: v for k, v in fields.items() if v is not None}
    return run_governed(
        "pbs_realm_ad_create", tgt,
        plan=lambda: plan_realm_ad_create(realm, server1, **fields),
        execute=lambda: realm_ad_create(pbs, realm, server1, base_dn, bind_dn, capath,
                                            comment, default, filter, mode, password, port,
                                            server2, sync_attributes, sync_defaults_options,
                                            user_classes, verify),
        confirm=confirm, surface=pw_detail)


@tool()
def pbs_realm_ad_update(
    realm: Annotated[str, Field(description="AD realm name to update.")],
    base_dn: Annotated[str | None, Field(description="LDAP base DN; omit to leave unchanged.")] = None,
    bind_dn: Annotated[str | None, Field(description="LDAP bind DN; omit to leave unchanged.")] = None,
    capath: Annotated[str | None, Field(description="CA certificate path; omit to leave unchanged.")] = None,
    comment: Annotated[str | None, Field(description="Optional free-text comment; omit to leave unchanged.")] = None,
    default: Annotated[bool | None, Field(description="Default-realm-on-login flag; omit to leave unchanged.")] = None,
    filter: Annotated[str | None, Field(description="Custom LDAP search filter; omit to leave unchanged.")] = None,
    mode: Annotated[str | None, Field(description="LDAP connection type; omit to leave unchanged.")] = None,
    password: Annotated[str | None, Field(description="New AD bind password; redacted from all plans/logs/ledger.")] = None,
    port: Annotated[int | None, Field(description="AD server port; omit to leave unchanged.")] = None,
    server1: Annotated[str | None, Field(description="Primary AD server address; omit to leave unchanged.")] = None,
    server2: Annotated[str | None, Field(description="Fallback AD server address; omit to leave unchanged.")] = None,
    sync_attributes: Annotated[str | None, Field(description="Sync-attribute map string; omit to leave unchanged.")] = None,
    sync_defaults_options: Annotated[str | None, Field(description="Sync-defaults options string; omit to leave unchanged.")] = None,
    user_classes: Annotated[str | None, Field(description="Allowed objectClass values; omit to leave unchanged.")] = None,
    verify: Annotated[bool | None, Field(description="TLS verification flag; omit to leave unchanged.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear.")] = None,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update an AD realm's config. Dry-run by default — the PLAN reads the
    realm's current config first. `password`, if supplied, is redacted identically to
    pbs_realm_ad_create's. confirm=True executes and returns a dict; synchronous, no UPID. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/access/ad/{realm}"
    pw_detail = _password_redacted_detail(password)
    fields = dict(base_dn=base_dn, bind_dn=bind_dn, capath=capath, comment=comment,
                  default=default, filter=filter, mode=mode, port=port, server1=server1,
                  server2=server2, sync_attributes=sync_attributes,
                  sync_defaults_options=sync_defaults_options, user_classes=user_classes,
                  verify=verify)
    fields = {k: v for k, v in fields.items() if v is not None}
    return run_governed(
        "pbs_realm_ad_update", tgt,
        plan=lambda: plan_realm_ad_update(pbs, realm, **fields),
        execute=lambda: realm_ad_update(pbs, realm, base_dn, bind_dn, capath, comment,
                                            default, filter, mode, password, port, server1,
                                            server2, sync_attributes, sync_defaults_options,
                                            user_classes, verify, delete_props, digest),
        confirm=confirm, surface=pw_detail)


@tool()
def pbs_realm_ad_delete(
    realm: Annotated[str, Field(description="AD realm name to delete.")],
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): permanently delete an AD realm. Dry-run by default — the PLAN reads the
    realm's current config and flags that any users authenticating via it lose login access.
    confirm=True executes and returns a dict; synchronous, no UPID. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/access/ad/{realm}"
    return run_governed(
        "pbs_realm_ad_delete", tgt,
        plan=lambda: plan_realm_ad_delete(pbs, realm),
        execute=lambda: realm_ad_delete(pbs, realm, digest),
        confirm=confirm)


# ---------------------------------------------------------------------------
# Realms: LDAP (Wave 2b) — same shape as AD; base_dn/user_attr REQUIRED on create.
# ---------------------------------------------------------------------------

@tool()
def pbs_realm_ldap_list() -> list[dict]:
    """READ-ONLY: list configured LDAP realms. Use pbs_realm_ldap_get for one realm's full
    config. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_realm_ldap_list", "pbs/config/access/ldap", lambda: realm_ldap_list(pbs))


@tool()
def pbs_realm_ldap_get(
    realm: Annotated[str, Field(description="LDAP realm name to look up.")],
) -> dict:
    """READ-ONLY: get one LDAP realm's config. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_realm_ldap_get", f"pbs/config/access/ldap/{realm}", lambda: realm_ldap_get(pbs, realm))


@tool()
def pbs_realm_ldap_create(
    realm: Annotated[str, Field(description="New LDAP realm name.")],
    server1: Annotated[str, Field(description="Primary LDAP server address.")],
    base_dn: Annotated[str, Field(description="LDAP base DN to search under (required for LDAP, unlike AD).")],
    user_attr: Annotated[str, Field(description="Username attribute used to map a userid to an LDAP dn (required for LDAP).")],
    bind_dn: Annotated[str | None, Field(description="LDAP bind DN for the service account.")] = None,
    capath: Annotated[str | None, Field(description="Path to a CA certificate file or directory to trust for TLS.")] = None,
    comment: Annotated[str | None, Field(description="Optional free-text comment.")] = None,
    default: Annotated[bool | None, Field(description="True to make this the default realm preselected on login.")] = None,
    filter: Annotated[str | None, Field(description="Custom LDAP search filter for user sync.")] = None,
    mode: Annotated[str | None, Field(description="LDAP connection type: 'ldap', 'ldap+starttls', or 'ldaps'.")] = None,
    password: Annotated[str | None, Field(description="LDAP bind password for the service account; redacted from all plans/logs/ledger.")] = None,
    port: Annotated[int | None, Field(description="LDAP server port.")] = None,
    server2: Annotated[str | None, Field(description="Fallback LDAP server address.")] = None,
    sync_attributes: Annotated[str | None, Field(description="Comma-separated key=value LDAP-attribute-to-PBS-field sync map, forwarded verbatim.")] = None,
    sync_defaults_options: Annotated[str | None, Field(description="Default sync-run options string, forwarded verbatim (exact syntax not live-verified).")] = None,
    user_classes: Annotated[str | None, Field(description="Comma-separated allowed objectClass values for user sync.")] = None,
    verify: Annotated[bool | None, Field(description="Whether to verify the LDAP server's TLS certificate.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): create an LDAP authentication realm. Dry-run by default. `base_dn` and
    `user_attr` are REQUIRED (unlike AD, which needs neither on create).

    PASSWORD REDACTION: `password` is UNCONDITIONALLY redacted identically to
    pbs_realm_ad_create's. confirm=True executes and returns a dict; synchronous, no UPID. Needs
    PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/access/ldap/{realm}"
    pw_detail = _password_redacted_detail(password)
    fields = dict(bind_dn=bind_dn, capath=capath, comment=comment, default=default,
                  filter=filter, mode=mode, port=port, server2=server2,
                  sync_attributes=sync_attributes, sync_defaults_options=sync_defaults_options,
                  user_classes=user_classes, verify=verify)
    fields = {k: v for k, v in fields.items() if v is not None}
    return run_governed(
        "pbs_realm_ldap_create", tgt,
        plan=lambda: plan_realm_ldap_create(realm, server1, base_dn, user_attr, **fields),
        execute=lambda: realm_ldap_create(pbs, realm, server1, base_dn, user_attr, bind_dn,
                                              capath, comment, default, filter, mode, password,
                                              port, server2, sync_attributes,
                                              sync_defaults_options, user_classes, verify),
        confirm=confirm, surface=pw_detail)


@tool()
def pbs_realm_ldap_update(
    realm: Annotated[str, Field(description="LDAP realm name to update.")],
    base_dn: Annotated[str | None, Field(description="LDAP base DN; omit to leave unchanged.")] = None,
    bind_dn: Annotated[str | None, Field(description="LDAP bind DN; omit to leave unchanged.")] = None,
    capath: Annotated[str | None, Field(description="CA certificate path; omit to leave unchanged.")] = None,
    comment: Annotated[str | None, Field(description="Optional free-text comment; omit to leave unchanged.")] = None,
    default: Annotated[bool | None, Field(description="Default-realm-on-login flag; omit to leave unchanged.")] = None,
    filter: Annotated[str | None, Field(description="Custom LDAP search filter; omit to leave unchanged.")] = None,
    mode: Annotated[str | None, Field(description="LDAP connection type; omit to leave unchanged.")] = None,
    password: Annotated[str | None, Field(description="New LDAP bind password; redacted from all plans/logs/ledger.")] = None,
    port: Annotated[int | None, Field(description="LDAP server port; omit to leave unchanged.")] = None,
    server1: Annotated[str | None, Field(description="Primary LDAP server address; omit to leave unchanged.")] = None,
    server2: Annotated[str | None, Field(description="Fallback LDAP server address; omit to leave unchanged.")] = None,
    sync_attributes: Annotated[str | None, Field(description="Sync-attribute map string; omit to leave unchanged.")] = None,
    sync_defaults_options: Annotated[str | None, Field(description="Sync-defaults options string; omit to leave unchanged.")] = None,
    user_attr: Annotated[str | None, Field(description="Username attribute; omit to leave unchanged.")] = None,
    user_classes: Annotated[str | None, Field(description="Allowed objectClass values; omit to leave unchanged.")] = None,
    verify: Annotated[bool | None, Field(description="TLS verification flag; omit to leave unchanged.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear.")] = None,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update an LDAP realm's config. Dry-run by default — the PLAN reads the
    realm's current config first. `password`, if supplied, is redacted identically to
    pbs_realm_ldap_create's. confirm=True executes and returns a dict; synchronous, no UPID.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/access/ldap/{realm}"
    pw_detail = _password_redacted_detail(password)
    fields = dict(base_dn=base_dn, bind_dn=bind_dn, capath=capath, comment=comment,
                  default=default, filter=filter, mode=mode, port=port, server1=server1,
                  server2=server2, sync_attributes=sync_attributes,
                  sync_defaults_options=sync_defaults_options, user_attr=user_attr,
                  user_classes=user_classes, verify=verify)
    fields = {k: v for k, v in fields.items() if v is not None}
    return run_governed(
        "pbs_realm_ldap_update", tgt,
        plan=lambda: plan_realm_ldap_update(pbs, realm, **fields),
        execute=lambda: realm_ldap_update(pbs, realm, base_dn, bind_dn, capath, comment,
                                              default, filter, mode, password, port, server1,
                                              server2, sync_attributes, sync_defaults_options,
                                              user_attr, user_classes, verify, delete_props,
                                              digest),
        confirm=confirm, surface=pw_detail)


@tool()
def pbs_realm_ldap_delete(
    realm: Annotated[str, Field(description="LDAP realm name to delete.")],
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): permanently delete an LDAP realm. Dry-run by default — the PLAN reads
    the realm's current config and flags that any users authenticating via it lose login access.
    confirm=True executes and returns a dict; synchronous, no UPID. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/access/ldap/{realm}"
    return run_governed(
        "pbs_realm_ldap_delete", tgt,
        plan=lambda: plan_realm_ldap_delete(pbs, realm),
        execute=lambda: realm_ldap_delete(pbs, realm, digest),
        confirm=confirm)


# ---------------------------------------------------------------------------
# Realms: OpenID (Wave 2b)
# ---------------------------------------------------------------------------

@tool()
def pbs_realm_openid_list() -> list[dict]:
    """READ-ONLY: list configured OpenID realms. Use pbs_realm_openid_get for one realm's full
    config. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_realm_openid_list", "pbs/config/access/openid", lambda: realm_openid_list(pbs))


@tool()
def pbs_realm_openid_get(
    realm: Annotated[str, Field(description="OpenID realm name to look up.")],
) -> dict:
    """READ-ONLY: get one OpenID realm's config (never includes client_key). Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_realm_openid_get", f"pbs/config/access/openid/{realm}",
                    lambda: realm_openid_get(pbs, realm))


@tool()
def pbs_realm_openid_create(
    realm: Annotated[str, Field(description="New OpenID realm name.")],
    issuer_url: Annotated[str, Field(description="OpenID issuer URL.")],
    client_id: Annotated[str, Field(description="OpenID client id.")],
    client_key: Annotated[str | None, Field(description="OpenID client secret; redacted from all plans/logs/ledger.")] = None,
    comment: Annotated[str | None, Field(description="Optional free-text comment.")] = None,
    default: Annotated[bool | None, Field(description="True to make this the default realm preselected on login.")] = None,
    acr_values: Annotated[str | None, Field(description="OpenID ACR list string, forwarded verbatim.")] = None,
    audiences: Annotated[str | None, Field(description="OpenID audience list string, forwarded verbatim.")] = None,
    autocreate: Annotated[bool | None, Field(description="Automatically create PBS users on first login if they don't exist.")] = None,
    prompt: Annotated[str | None, Field(description="OpenID prompt parameter.")] = None,
    scopes: Annotated[str | None, Field(description="OpenID scope list, SPACE-separated (schema default: 'email profile').")] = None,
    username_claim: Annotated[str | None, Field(description="Claim to use as the unique username; the identity provider must guarantee uniqueness.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): create an OpenID authentication realm. Dry-run by default.

    CLIENT-KEY REDACTION: `client_key` (the OAuth client secret), when supplied, is
    UNCONDITIONALLY redacted from the plan, detail, and audit ledger (only
    {"client-key": "[redacted]"} is recorded). confirm=True executes and returns a dict;
    synchronous, no UPID. NOTE: the browser-based auth-url/login handshake is out of scope for
    this plane (token-auth-shaped tools only) — see module docstring. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/access/openid/{realm}"
    ck_detail = _client_key_redacted_detail(client_key)
    fields = dict(comment=comment, default=default, acr_values=acr_values, audiences=audiences,
                  autocreate=autocreate, prompt=prompt, scopes=scopes,
                  username_claim=username_claim)
    fields = {k: v for k, v in fields.items() if v is not None}
    return run_governed(
        "pbs_realm_openid_create", tgt,
        plan=lambda: plan_realm_openid_create(realm, issuer_url, client_id, **fields),
        execute=lambda: realm_openid_create(pbs, realm, issuer_url, client_id, client_key,
                                                comment, default, acr_values, audiences,
                                                autocreate, prompt, scopes, username_claim),
        confirm=confirm, surface=ck_detail)


@tool()
def pbs_realm_openid_update(
    realm: Annotated[str, Field(description="OpenID realm name to update.")],
    issuer_url: Annotated[str | None, Field(description="OpenID issuer URL; omit to leave unchanged.")] = None,
    client_id: Annotated[str | None, Field(description="OpenID client id; omit to leave unchanged.")] = None,
    client_key: Annotated[str | None, Field(description="New OpenID client secret; redacted from all plans/logs/ledger.")] = None,
    comment: Annotated[str | None, Field(description="Optional free-text comment; omit to leave unchanged.")] = None,
    default: Annotated[bool | None, Field(description="Default-realm-on-login flag; omit to leave unchanged.")] = None,
    acr_values: Annotated[str | None, Field(description="OpenID ACR list string; omit to leave unchanged.")] = None,
    audiences: Annotated[str | None, Field(description="OpenID audience list string; omit to leave unchanged.")] = None,
    autocreate: Annotated[bool | None, Field(description="Autocreate-on-login flag; omit to leave unchanged.")] = None,
    prompt: Annotated[str | None, Field(description="OpenID prompt parameter; omit to leave unchanged.")] = None,
    scopes: Annotated[str | None, Field(description="OpenID scope list, SPACE-separated; omit to leave unchanged.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear.")] = None,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update an OpenID realm's config. Dry-run by default — the PLAN reads
    the realm's current config first. `client_key`, if supplied, is redacted identically to
    pbs_realm_openid_create's. confirm=True executes and returns a dict; synchronous, no UPID.

    NOTE: there is NO username_claim parameter here — the live PBS schema makes it create-only
    (set it at pbs_realm_openid_create time); PUT is additionalProperties:false, so accepting it
    here would only hard-fail the whole update server-side. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/access/openid/{realm}"
    ck_detail = _client_key_redacted_detail(client_key)
    fields = dict(comment=comment, default=default, acr_values=acr_values, audiences=audiences,
                  autocreate=autocreate, prompt=prompt, scopes=scopes)
    fields = {k: v for k, v in fields.items() if v is not None}
    return run_governed(
        "pbs_realm_openid_update", tgt,
        plan=lambda: plan_realm_openid_update(pbs, realm, **fields),
        execute=lambda: realm_openid_update(pbs, realm, issuer_url, client_id, client_key,
                                                comment, default, acr_values, audiences,
                                                autocreate, prompt, scopes,
                                                delete_props, digest),
        confirm=confirm, surface=ck_detail)


@tool()
def pbs_realm_openid_delete(
    realm: Annotated[str, Field(description="OpenID realm name to delete.")],
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): permanently delete an OpenID realm. Dry-run by default — the PLAN reads
    the realm's current config and flags that any users authenticating via it lose login access.
    confirm=True executes and returns a dict; synchronous, no UPID. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/access/openid/{realm}"
    return run_governed(
        "pbs_realm_openid_delete", tgt,
        plan=lambda: plan_realm_openid_delete(pbs, realm),
        execute=lambda: realm_openid_delete(pbs, realm, digest),
        confirm=confirm)


# ---------------------------------------------------------------------------
# Realms: PAM / PBS built-in (Wave 2b) — GET/PUT only, no create/delete.
# ---------------------------------------------------------------------------

@tool()
def pbs_realm_pam_get() -> dict:
    """READ-ONLY: get the built-in PAM realm's config (comment/default only). Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_realm_pam_get", "pbs/config/access/pam", lambda: realm_pam_get(pbs))


@tool()
def pbs_realm_pam_set(
    comment: Annotated[str | None, Field(description="Optional free-text comment; omit to leave unchanged.")] = None,
    default: Annotated[bool | None, Field(description="Default-realm-on-login flag; omit to leave unchanged.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear.")] = None,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update the built-in PAM realm's comment/default-preselect flag. Dry-run
    by default. PAM has NO delete endpoint — the worst case here is a comment/default change, not
    a lockout. confirm=True executes and returns a dict; synchronous, no UPID. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = "pbs/config/access/pam"
    return run_governed(
        "pbs_realm_pam_set", tgt,
        plan=lambda: plan_realm_pam_set(pbs, comment, default),
        execute=lambda: realm_pam_set(pbs, comment, default, delete_props, digest),
        confirm=confirm)


@tool()
def pbs_realm_pbs_get() -> dict:
    """READ-ONLY: get the built-in PBS-auth realm's config (comment/default only). Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_realm_pbs_get", "pbs/config/access/pbs", lambda: realm_pbs_get(pbs))


@tool()
def pbs_realm_pbs_set(
    comment: Annotated[str | None, Field(description="Optional free-text comment; omit to leave unchanged.")] = None,
    default: Annotated[bool | None, Field(description="Default-realm-on-login flag; omit to leave unchanged.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear.")] = None,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update the built-in PBS-auth realm's comment/default-preselect flag.
    Dry-run by default. This realm has NO delete endpoint — the worst case here is a
    comment/default change, not a lockout. confirm=True executes and returns a dict;
    synchronous, no UPID. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = "pbs/config/access/pbs"
    return run_governed(
        "pbs_realm_pbs_set", tgt,
        plan=lambda: plan_realm_pbs_set(pbs, comment, default),
        execute=lambda: realm_pbs_set(pbs, comment, default, delete_props, digest),
        confirm=confirm)


# ---------------------------------------------------------------------------
# TFA (Wave 2b)
# ---------------------------------------------------------------------------

@tool()
def pbs_tfa_list() -> list[dict]:
    """READ-ONLY: list ALL users' TFA configuration (per-user entries + lock state). Use
    pbs_tfa_user_get to scope to one user. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tfa_list", "pbs/access/tfa", lambda: tfa_list(pbs))


@tool()
def pbs_tfa_user_get(
    userid: Annotated[str, Field(description="PBS user id, format 'user@realm'.")],
) -> list[dict]:
    """READ-ONLY: list one user's TFA entries. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tfa_user_get", f"pbs/access/tfa/{userid}", lambda: tfa_user_get(pbs, userid))


@tool()
def pbs_tfa_entry_get(
    userid: Annotated[str, Field(description="PBS user id, format 'user@realm'.")],
    tfa_id: Annotated[str, Field(description="TFA entry id (from pbs_tfa_user_get).")],
) -> object:
    """READ-ONLY: get one TFA entry. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tfa_entry_get", f"pbs/access/tfa/{userid}/{tfa_id}",
                    lambda: tfa_entry_get(pbs, userid, tfa_id))


@tool()
def pbs_tfa_add(
    userid: Annotated[str, Field(description="PBS user id to add a TFA entry for, format 'user@realm'.")],
    tfa_type: Annotated[str, Field(description="TFA entry type: 'totp', 'u2f', 'webauthn', 'recovery', or 'yubico'.")],
    description: Annotated[str | None, Field(description="Optional description to distinguish this entry from the user's others.")] = None,
    password: Annotated[str | None, Field(description="The ACTING user's own current password (re-authenticates the change); redacted from all plans/logs/ledger.")] = None,
    totp: Annotated[str | None, Field(description="For type='totp': the totp: URI the caller generated (PBS does not generate this).")] = None,
    value: Annotated[str | None, Field(description="Registration/verification value (e.g. the current TOTP code, or a WebAuthn/U2F challenge response).")] = None,
    challenge: Annotated[str | None, Field(description="For u2f: the original challenge string being responded to.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): add a TFA entry for a user. Dry-run by default.

    SECRET-BEARING RESPONSE for type='recovery': confirm=True's result carries
    {"recovery": [<one-time codes>], ...} — SERVER-GENERATED secret material, shown ONCE and
    never retrievable again. It is never written to the audit ledger (the `detail=` dict below
    never includes 'recovery'/'challenge'/'id'). `password`, if supplied, is UNCONDITIONALLY
    redacted identically to pbs_user_create's. For type='totp', the caller supplies the secret
    (via `totp`) — PBS does not generate one server-side for that type. confirm=True executes and
    returns a dict; synchronous, no UPID. Needs PROXIMO_PBS_* config.
    """
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/access/tfa/{userid}"
    pw_detail = _password_redacted_detail(password)
    # SECRET HANDLING: type='recovery' results carry one-time codes in 'recovery' — detail must
    # NEVER contain the op result. Non-secret params only.
    return run_governed(
        "pbs_tfa_add", tgt,
        plan=lambda: plan_tfa_add(userid, tfa_type, description),
        execute=lambda: tfa_add(pbs, userid, tfa_type, description, password, totp, value, challenge),
        confirm=confirm, detail={"type": tfa_type}, surface=pw_detail)


@tool()
def pbs_tfa_update(
    userid: Annotated[str, Field(description="PBS user id, format 'user@realm'.")],
    tfa_id: Annotated[str, Field(description="TFA entry id to update.")],
    description: Annotated[str | None, Field(description="New description; omit to leave unchanged.")] = None,
    enable: Annotated[bool | None, Field(description="Whether the entry is currently enabled; False disables it immediately. Omit to leave unchanged.")] = None,
    password: Annotated[str | None, Field(description="The ACTING user's own current password; redacted from all plans/logs/ledger.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a TFA entry's description/enabled flag. Dry-run by default —
    the PLAN reads the current entry first. `password`, if supplied, is redacted identically to
    pbs_tfa_add's. confirm=True executes and returns a dict; synchronous, no UPID. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/access/tfa/{userid}/{tfa_id}"
    pw_detail = _password_redacted_detail(password)
    return run_governed(
        "pbs_tfa_update", tgt,
        plan=lambda: plan_tfa_update(pbs, userid, tfa_id, description, enable),
        execute=lambda: tfa_update(pbs, userid, tfa_id, description, enable, password),
        confirm=confirm, surface=pw_detail)


@tool()
def pbs_tfa_delete(
    userid: Annotated[str, Field(description="PBS user id, format 'user@realm'.")],
    tfa_id: Annotated[str, Field(description="TFA entry id to remove.")],
    password: Annotated[str | None, Field(description="The ACTING user's own current password; redacted from all plans/logs/ledger.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (HIGH, IRREVERSIBLE): permanently remove one TFA factor from a user. HIGH because
    it WEAKENS authentication — an account-takeover enabler, and a lockout if it's the user's last
    factor on a TFA-required realm. Dry-run by default — the PLAN flags the permanence and the
    takeover/lockout risk. `password`, if supplied, is redacted identically to pbs_tfa_add's.
    confirm=True executes and returns a dict; synchronous, no UPID. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/access/tfa/{userid}/{tfa_id}"
    pw_detail = _password_redacted_detail(password)
    return run_governed(
        "pbs_tfa_delete", tgt,
        plan=lambda: plan_tfa_delete(pbs, userid, tfa_id),
        execute=lambda: tfa_delete(pbs, userid, tfa_id, password),
        confirm=confirm, surface=pw_detail)


@tool()
def pbs_tfa_unlock(
    userid: Annotated[str, Field(description="PBS user id to clear a TOTP lockout for, format 'user@realm'.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (HIGH): clear a user's TOTP lockout (PUT /access/users/{userid}/unlock-tfa — note
    the path lives under /access/users/, not /access/tfa/{userid}/). HIGH because it removes the
    anti-brute-force throttle guarding a 6-digit TOTP keyspace — an account-takeover enabler if
    the lockout was triggered by a real guessing attack. Dry-run by default. confirm=True executes
    and returns a dict whose result is a bool: whether the user was previously locked out.
    Synchronous. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/access/users/{userid}/unlock-tfa"
    return run_governed(
        "pbs_tfa_unlock", tgt,
        plan=lambda: plan_tfa_unlock(userid),
        execute=lambda: tfa_unlock(pbs, userid),
        confirm=confirm)


@tool()
def pbs_tfa_webauthn_get() -> dict:
    """READ-ONLY: get the server-wide WebAuthn relying-party config (id/origin/rp/
    allow-subdomains). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_tfa_webauthn_get", "pbs/config/access/tfa/webauthn", lambda: tfa_webauthn_get(pbs))


@tool()
def pbs_tfa_webauthn_set(
    rp_id: Annotated[str | None, Field(description="Relying party ID (the domain name, no protocol/port/path). Changing this WILL break every existing WebAuthn credential on the server.")] = None,
    origin: Annotated[str | None, Field(description="Site origin (https:// URL, or http://localhost). Changing this MAY break existing WebAuthn credentials.")] = None,
    rp_name: Annotated[str | None, Field(description="Relying party display name (any text identifier). Changing this MAY break existing credentials.")] = None,
    allow_subdomains: Annotated[bool | None, Field(description="Whether subdomains of origin are considered valid too. Defaults to true per PBS.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear.")] = None,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update the server-wide WebAuthn config. Dry-run by default — the PLAN
    reads the current config and calls out that changing `rp_id` WILL break every existing
    WebAuthn credential on the server, and `origin` MAY. confirm=True executes and returns a
    dict; synchronous, no UPID. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = "pbs/config/access/tfa/webauthn"
    return run_governed(
        "pbs_tfa_webauthn_set", tgt,
        plan=lambda: plan_tfa_webauthn_set(pbs, rp_id, origin, rp_name, allow_subdomains),
        execute=lambda: tfa_webauthn_set(pbs, rp_id, origin, rp_name, allow_subdomains,
                                             delete_props, digest),
        confirm=confirm)
