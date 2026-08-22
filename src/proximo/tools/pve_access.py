"""PVE access governance: ACLs/roles/tokens (read+mutation), users & groups, and roles/realms/TFA CRUD.

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.access import (
    access_acl_list,
    access_overbroad_grants,
    access_roles_list,
    access_tokens_list,
    access_users_list,
    acl_modify,
    acl_prune,
    plan_acl_modify,
    plan_prune_grant,
    plan_token_create,
    plan_token_revoke,
    token_create,
    token_revoke,
)
from proximo.access_governance import (
    plan_realm_create,
    plan_realm_delete,
    plan_realm_update,
    plan_role_create,
    plan_role_delete,
    plan_role_update,
    plan_tfa_delete,
    realm_create,
    realm_delete,
    realm_get,
    realm_update,
    realms_list,
    role_create,
    role_delete,
    role_update,
    tfa_delete,
    tfa_get,
    tfa_list,
)
from proximo.access_users import (
    group_create,
    group_delete,
    group_get,
    group_update,
    groups_list,
    plan_group_create,
    plan_group_delete,
    plan_group_update,
    plan_user_create,
    plan_user_delete,
    plan_user_update,
    user_create,
    user_delete,
    user_get,
    user_update,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Access governance (REST API, read) ---

@tool()
def pve_users_list() -> list[dict]:
    """READ-ONLY: List all Proxmox users across every realm. Returns each user's id (user@realm),
    enabled flag, expiry, group membership, email, and comment. Use pve_user_get for one user's
    full config, tokens, and effective ACL."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_users_list", "access/users", lambda: access_users_list(api))


@tool()
def pve_roles_list() -> list[dict]:
    """READ-ONLY: List all Proxmox roles and their privileges. Returns each role's id, privilege
    set, and whether it is built-in. Use pve_role_create/update/delete to modify roles; use
    pve_acl_list to see which principals hold which roles at which paths."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_roles_list", "access/roles", lambda: access_roles_list(api))


@tool()
def pve_acl_list() -> list[dict]:
    """READ-ONLY: List all ACL entries on the Proxmox cluster. Returns each entry's path (resource
    scope), roleid (privilege set), principal (user/group/token), type, and propagate flag. Use
    pve_acl_modify to grant/revoke; use pve_overbroad_grants to flag Administrator or root-path
    grants."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_acl_list", "access/acl", lambda: access_acl_list(api))


@tool()
def pve_tokens_list(
    userid: Annotated[str, Field(description="Owning user, format 'user@realm'.")],
) -> list[dict]:
    """READ-ONLY: List API tokens for a specific user. Returns each token's id, comment, expiry,
    and privsep (privilege separation) flag — NOT the secret (shown only at creation). userid
    format: 'user@realm'. Use pve_token_create/revoke to manage tokens."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_tokens_list", f"access/users/{userid}/token",
                    lambda: access_tokens_list(api, userid))


@tool()
def pve_overbroad_grants() -> list[dict]:
    """READ-ONLY: surface over-broad ACL grants — Administrator-role assignments or grants on the
    root '/' path — as a least-privilege diagnostic.

    No state change; this only reports, it does not revoke anything. Returns a list of the flagged ACL
    entries (empty when none). Use pve_acl_list for the full ACL and pve_acl_modify to tighten a finding."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_overbroad_grants", "access/acl",
                    lambda: access_overbroad_grants(api))


# --- Access governance (REST API, MUTATION — confirm-gated) ---

@tool()
def pve_acl_modify(
    path: Annotated[str, Field(description="Resource path the ACL entry applies to, e.g. '/vms/100' or '/'.")],
    roles: Annotated[str, Field(description="Comma-separated role id(s) to grant or revoke, e.g. 'PVEVMAdmin'.")],
    target: Annotated[str, Field(description="Principal the ACL entry applies to: userid, groupid, or tokenid depending on kind.")],
    kind: Annotated[str, Field(description="Principal type of target: 'user', 'group', or 'token'.")] = "user",
    propagate: Annotated[bool, Field(description="Whether the grant propagates to child paths below `path`.")] = True,
    delete: Annotated[bool, Field(description="False to grant the roles, True to revoke them.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION: grant or revoke an ACL entry (PUT /access/acl).

    Dry-run by default (returns a PLAN) — it surfaces the critical Proxmox gotcha: a specific-path
    ACL REPLACES inherited grants (SHADOW) and revoking can RESTORE them (WIDEN). confirm=True
    executes and returns a dict; synchronous, no UPID. Use pve_acl_list to see current entries,
    pve_overbroad_grants to find over-broad ones, or pve_acl_prune to narrow/remove one.

    kind='user' (default), 'group', or 'token'. delete=False = grant; delete=True = revoke.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"acl:{path}:{target}"
    return run_governed(
        "pve_acl_modify", tgt,
        plan=lambda: plan_acl_modify(api, path, roles, target, kind, propagate, delete),
        execute=lambda: acl_modify(api, path, roles, target, kind, propagate, delete),
        confirm=confirm)


@tool()
def pve_acl_prune(
    path: Annotated[str, Field(description="Resource path of the over-broad ACL entry to prune, e.g. '/'.")],
    target: Annotated[str, Field(description="Principal the over-broad grant belongs to: userid, groupid, or tokenid depending on kind.")],
    kind: Annotated[str, Field(description="Principal type of target: 'user', 'group', or 'token'.")] = "user",
    roleid: Annotated[str, Field(description="The over-broad role id to remove, as identified by pve_overbroad_grants.")] = "",
    narrow_role: Annotated[str | None, Field(description="Optional narrower role id to re-grant in place of the removed one.")] = None,
    narrow_path: Annotated[str | None, Field(description="Optional narrower path to scope the re-grant to, instead of the original path.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION: prune (remove/narrow) an over-broad ACL grant flagged by pve_overbroad_grants.

    Dry-run by default (returns a PLAN naming every principal losing/gaining what, and flagging
    shadow/widen gotchas); confirm=True executes and returns a dict. Non-atomic — a revoke PUT
    then an optional narrower re-grant PUT — but safe-direction: a partial failure only narrows
    access, never widens it. Synchronous. roleid = the over-broad role to remove (from detection).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"acl:prune:{path}:{target}"
    return run_governed(
        "pve_acl_prune", tgt,
        plan=lambda: plan_prune_grant(api, path, target, kind, roleid, narrow_role, narrow_path),
        execute=lambda: acl_prune(api, path, target, kind, roleid, narrow_role, narrow_path),
        confirm=confirm, detail={"roleid": roleid, "narrow_role": narrow_role, "narrow_path": narrow_path})


@tool()
def pve_token_create(
    userid: Annotated[str, Field(description="Owning user, format 'user@realm'.")],
    tokenid: Annotated[str, Field(description="Name for the new API token, unique per user.")],
    privsep: Annotated[bool, Field(description="Privilege separation: True (default) restricts the token to its own ACL grants; False lets it inherit ALL owner permissions.")] = True,
    comment: Annotated[str | None, Field(description="Optional free-text comment describing the token's purpose.")] = None,
    expire: Annotated[int | None, Field(description="Optional token expiry as a Unix timestamp; None means no expiry.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION: create an API token for a user.

    Dry-run by default — the PLAN shows risk (privsep=False is HIGH: token inherits ALL owner perms).
    confirm=True executes and returns a dict whose result carries the token secret (value) ONCE —
    it is never written to the audit ledger and cannot be retrieved again. Synchronous. Use
    pve_tokens_list to see a user's existing tokens, or pve_token_revoke to remove one.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"token:{userid}!{tokenid}"
    # L03: pass expire+comment so the PLAN surface reflects what will actually be created
    # SECRET HANDLING: return op result directly (carries the token value to caller);
    # detail dict must NEVER contain the secret — only {"confirmed": True} + non-secret params.
    return run_governed(
        "pve_token_create", tgt,
        plan=lambda: plan_token_create(userid, tokenid, privsep, expire=expire, comment=comment),
        execute=lambda: token_create(api, userid, tokenid, privsep, comment, expire),
        confirm=confirm, detail={"expire": expire, "privsep": privsep})


@tool()
def pve_token_revoke(
    userid: Annotated[str, Field(description="Owning user, format 'user@realm'.")],
    tokenid: Annotated[str, Field(description="Name of the API token to revoke.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (IRREVERSIBLE): permanently revoke an API token.

    Dry-run by default — the PLAN flags HIGH: revocation is permanent, the secret is gone forever.
    confirm=True executes and returns a dict; synchronous, no UPID. Use pve_tokens_list to see a
    user's tokens first, or pve_token_create to issue a new one instead.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"token:{userid}!{tokenid}"
    return run_governed(
        "pve_token_revoke", tgt,
        plan=lambda: plan_token_revoke(userid, tokenid),
        execute=lambda: token_revoke(api, userid, tokenid),
        confirm=confirm)


# --- Access governance: users & groups ---

@tool()
def pve_user_get(
    userid: Annotated[str, Field(description="User id to look up, format 'user@realm'.")],
) -> dict:
    """READ-ONLY: Get a user's full config. Returns userid, enabled flag, expiry, email, comment,
    group membership, API tokens, and firstname/lastname. Use pve_user_create/update/delete to
    modify the user; use pve_acl_list to see the cluster's raw ACL entries (not a resolved
    per-user effective-permission view)."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_user_get", f"user/{userid}", lambda: user_get(api, userid))


@tool()
def pve_groups_list() -> list[dict]:
    """READ-ONLY: List all Proxmox groups. Returns each group's id, comment, and member count.
    Use pve_group_get for full member list; use pve_group_create/update/delete to manage groups."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_groups_list", "access/groups", lambda: groups_list(api))


@tool()
def pve_group_get(
    groupid: Annotated[str, Field(description="Group id to look up.")],
) -> dict:
    """READ-ONLY: Get a group's full config. Returns groupid, comment, and member list (users in
    the group). Use pve_group_create/update/delete to manage the group; use pve_acl_list to see
    ACL entries referencing this group."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_group_get", f"group/{groupid}", lambda: group_get(api, groupid))


@tool()
def pve_user_create(
    userid: Annotated[str, Field(description="New user id, format 'user@realm'.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment.")] = None,
    email: Annotated[str | None, Field(description="Optional email address.")] = None,
    enable: Annotated[bool | None, Field(description="Whether the account can log in; None defers to PVE's default (enabled).")] = None,
    expire: Annotated[int | None, Field(description="Optional account expiry as a Unix timestamp; None means no expiry.")] = None,
    groups: Annotated[str | None, Field(description="Comma-separated list of group ids to add the user to.")] = None,
    firstname: Annotated[str | None, Field(description="Optional first name.")] = None,
    lastname: Annotated[str | None, Field(description="Optional last name.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION: create a user. Dry-run by default (note: password is set separately — the user
    cannot log in until then). confirm=True executes and returns a dict; synchronous, no UPID.
    Use pve_user_update to change it afterward, or pve_user_delete to remove it."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"user/{userid}"
    return run_governed(
        "pve_user_create", tgt,
        plan=lambda: plan_user_create(userid, comment, email, enable, expire, groups,
                                          firstname, lastname),
        execute=lambda: user_create(api, userid, comment, email, enable, expire,
                                       groups, firstname, lastname),
        confirm=confirm)


@tool()
def pve_user_update(
    userid: Annotated[str, Field(description="User id to update, format 'user@realm'.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment; omit to leave unchanged.")] = None,
    email: Annotated[str | None, Field(description="Optional email address; omit to leave unchanged.")] = None,
    enable: Annotated[bool | None, Field(description="Whether the account can log in; False stops login. Omit to leave unchanged.")] = None,
    expire: Annotated[int | None, Field(description="Account expiry as a Unix timestamp; omit to leave unchanged.")] = None,
    groups: Annotated[str | None, Field(description="Comma-separated list of group ids; replaces membership unless append=True.")] = None,
    firstname: Annotated[str | None, Field(description="Optional first name; omit to leave unchanged.")] = None,
    lastname: Annotated[str | None, Field(description="Optional last name; omit to leave unchanged.")] = None,
    append: Annotated[bool | None, Field(description="If True, add `groups` to existing membership instead of replacing it.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION: update a user (enable=False stops login; group changes re-scope access).
    Dry-run by default. confirm=True executes and returns a dict; synchronous, no UPID. Use
    pve_user_get to see current state first, or pve_user_delete to remove the user instead."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"user/{userid}"
    return run_governed(
        "pve_user_update", tgt,
        plan=lambda: plan_user_update(userid, comment, email, enable, expire, groups,
                                          firstname, lastname, append),
        execute=lambda: user_update(api, userid, comment, email, enable, expire,
                                       groups, firstname, lastname, append),
        confirm=confirm)


@tool()
def pve_user_delete(
    userid: Annotated[str, Field(description="User id to delete, format 'user@realm'.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (HIGH): delete a user. Dry-run by default — the PLAN reads the user's ACLs/tokens
    to show what access vanishes (permanent, no undo; admin = lockout risk). confirm=True executes
    and returns a dict; synchronous, no UPID. To disable login without deleting, use
    pve_user_update (enable=False) instead."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"user/{userid}"
    return run_governed(
        "pve_user_delete", tgt,
        plan=lambda: plan_user_delete(api, userid),
        execute=lambda: user_delete(api, userid),
        confirm=confirm)


@tool()
def pve_group_create(
    groupid: Annotated[str, Field(description="New group id.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION: create an (empty) group. Dry-run by default (additive, LOW risk); confirm=True
    executes and returns a dict, synchronous with no UPID. The group is inert until users are
    added (pve_user_update/pve_user_create with groups=) or pve_acl_modify grants it privileges."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"group/{groupid}"
    return run_governed(
        "pve_group_create", tgt,
        plan=lambda: plan_group_create(groupid, comment),
        execute=lambda: group_create(api, groupid, comment),
        confirm=confirm)


@tool()
def pve_group_update(
    groupid: Annotated[str, Field(description="Group id to update.")],
    comment: Annotated[str | None, Field(description="New free-text comment.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION: update a group's comment. Dry-run by default (comment-only replace, LOW risk); confirm=True
    executes and returns a dict, synchronous with no UPID. Does not modify group membership — use
    pve_user_update (groups=) to add/remove members, or pve_group_get to see current members."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"group/{groupid}"
    return run_governed(
        "pve_group_update", tgt,
        plan=lambda: plan_group_update(groupid, comment),
        execute=lambda: group_update(api, groupid, comment),
        confirm=confirm)


@tool()
def pve_group_delete(
    groupid: Annotated[str, Field(description="Group id to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (HIGH): delete a group. Dry-run by default — the PLAN reads members and warns ACLs
    granted to/on the group are orphaned (permanent, no undo). confirm=True executes and returns a
    dict; synchronous, no UPID. Use pve_group_get first to see current members."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"group/{groupid}"
    return run_governed(
        "pve_group_delete", tgt,
        plan=lambda: plan_group_delete(api, groupid),
        execute=lambda: group_delete(api, groupid),
        confirm=confirm)


# --- Access governance: roles, realms, TFA ---

@tool()
def pve_realms_list() -> list[dict]:
    """READ-ONLY: List authentication realms/domains configured in Proxmox. Returns each realm's
    type (pam/pve/ldap/ad/openid), comment, TFA setting, and default flag. Use pve_realm_get for
    type-specific config; use pve_realm_create/update/delete to manage realms."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_realms_list", "access/domains", lambda: realms_list(api))


@tool()
def pve_realm_get(
    realm: Annotated[str, Field(description="Realm id to look up, e.g. 'pam', 'pve', or a configured ldap/ad/openid realm name.")],
) -> dict:
    """READ-ONLY: Get a realm's full config. Returns realm type, comment, TFA requirement, and
    type-specific settings (server1/base_dn for ldap; domain/server1 for ad; issuer-url/client-id
    for openid). Use pve_realm_create/update/delete to manage realms."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_realm_get", f"realm/{realm}", lambda: realm_get(api, realm))


@tool()
def pve_tfa_list() -> list[dict]:
    """READ-ONLY: List all per-user TFA (two-factor) entries across the cluster. Returns the
    configured TFA entries; the exact shape varies by PVE version (typically per-user with a
    nested `entries` list of factor type/id). Use pve_tfa_get
    for one user's entries; use pve_tfa_delete (confirm=True) to remove a factor (RISK_HIGH)."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_tfa_list", "access/tfa", lambda: tfa_list(api))


@tool()
def pve_tfa_get(
    userid: Annotated[str, Field(description="User id whose TFA entries to read, format 'user@realm'.")],
    tfa_id: Annotated[str | None, Field(description="Specific TFA entry id to return; omit to return all of the user's entries.")] = None,
) -> object:
    """READ-ONLY: Read a user's TFA entries. Returns list of entries if tfa_id is omitted; a
    single entry dict if tfa_id is specified. Each entry includes factor type, id, and metadata.
    Use pve_tfa_delete (confirm=True) to remove a factor (RISK_HIGH — can lock the user out)."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_tfa_get", f"access/tfa/{userid}", lambda: tfa_get(api, userid, tfa_id))


@tool()
def pve_tfa_delete(
    userid: Annotated[str, Field(description="User id whose TFA factor to delete, format 'user@realm'.")],
    tfa_id: Annotated[str, Field(description="Id of the TFA factor to delete.")],
    password: Annotated[str | None, Field(description="The user's current password, if PVE requires re-authentication for this mutation; never logged.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (HIGH RISK): delete a user's TFA factor. Dry-run by default — the PLAN shows how many
    factors remain and warns this WEAKENS the account (and can lock the user out if it's the last
    factor on a TFA-required realm). `password` (if PVE requires it) is passed through but never
    logged. confirm=True executes and returns a dict; no UNDO (the factor must be re-enrolled).

    NOTE (live-verified PVE 9.1.7): PVE requires a ticket-based login session — NOT an API token —
    to mutate TFA, returning `403 ... need proper ticket` under token auth. Proximo is token-authed,
    so this delete will 403 on PVE; the read tools (pve_tfa_get/pve_tfa_list) work normally.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"access/tfa/{userid}/{tfa_id}"
    return run_governed(
        "pve_tfa_delete", tgt,
        plan=lambda: plan_tfa_delete(api, userid, tfa_id),
        execute=lambda: tfa_delete(api, userid, tfa_id, password),
        confirm=confirm)


@tool()
def pve_role_create(
    roleid: Annotated[str, Field(description="New role id.")],
    privs: Annotated[str | None, Field(description="Comma-separated privilege names for the role, e.g. 'VM.PowerMgmt,VM.Config.Disk'.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION: create a custom role with an optional privilege set. Dry-run by default (MEDIUM
    risk — inert until an ACL entry references it). confirm=True executes and returns a dict,
    synchronous with no UPID. privs format: comma-separated privilege names (e.g.
    'VM.PowerMgmt,VM.Config.Disk'). Use pve_acl_modify to assign the new role to a principal."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"role/{roleid}"
    return run_governed(
        "pve_role_create", tgt,
        plan=lambda: plan_role_create(roleid, privs),
        execute=lambda: role_create(api, roleid, privs),
        confirm=confirm)


@tool()
def pve_role_update(
    roleid: Annotated[str, Field(description="Role id to update.")],
    privs: Annotated[str | None, Field(description="Comma-separated privilege names to set (or add, if append=True).")] = None,
    append: Annotated[bool | None, Field(description="If True, add `privs` to the role's existing privileges instead of replacing them.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION: change a role's privileges. Dry-run by default — built-in roles (Administrator,
    PVEAdmin, …) are flagged HIGH (changing them re-scopes every ACL using them). confirm=True
    executes and returns a dict; synchronous, no UPID. Use pve_roles_list to see current roles
    and privileges first."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"role/{roleid}"
    return run_governed(
        "pve_role_update", tgt,
        plan=lambda: plan_role_update(api, roleid, privs, append),
        execute=lambda: role_update(api, roleid, privs, append),
        confirm=confirm)


@tool()
def pve_role_delete(
    roleid: Annotated[str, Field(description="Role id to delete (built-in roles are refused).")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (HIGH): delete a role. Dry-run by default — the PLAN reads ACLs to count grants
    that will break, and refuses built-in roles (permanent, no undo). confirm=True executes and
    returns a dict; synchronous, no UPID. Use pve_acl_list to see which grants reference the role first."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"role/{roleid}"
    return run_governed(
        "pve_role_delete", tgt,
        plan=lambda: plan_role_delete(api, roleid),
        execute=lambda: role_delete(api, roleid),
        confirm=confirm)


@tool()
def pve_realm_create(
    realm: Annotated[str, Field(description="New realm id/name.")],
    realm_type: Annotated[str, Field(description="Realm type: 'pam', 'pve', 'ldap', 'ad', or 'openid'.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment.")] = None,
    options: Annotated[dict | None, Field(description="Type-specific config fields passed verbatim to PVE (e.g. ldap: server1/base_dn/user_attr; ad: domain/server1; openid: issuer-url/client-id).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION: create an auth realm. Dry-run by default; confirm=True executes and returns a
    dict, synchronous with no UPID. `options` carries the type-specific fields PVE requires (ldap:
    server1/base_dn/user_attr; ad: domain/server1; openid: issuer-url/client-id) — passed verbatim;
    PVE validates them. Use pve_realms_list to see configured realms first."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"realm/{realm}"
    return run_governed(
        "pve_realm_create", tgt,
        plan=lambda: plan_realm_create(realm, realm_type, comment, options),
        execute=lambda: realm_create(api, realm, realm_type, comment, options),
        confirm=confirm)


@tool()
def pve_realm_update(
    realm: Annotated[str, Field(description="Realm id to update.")],
    comment: Annotated[str | None, Field(description="New free-text comment; omit to leave unchanged.")] = None,
    options: Annotated[dict | None, Field(description="Type-specific config fields to update, passed verbatim to PVE (e.g. server1/base_dn/etc.).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION: update a realm. Dry-run by default — built-in pam/pve realms are flagged HIGH
    (changing them risks breaking logins). confirm=True executes and returns a dict; synchronous,
    no UPID. `options` carries type-specific fields (server1/base_dn/etc.) passed verbatim; PVE
    validates them. Use pve_realm_get to see current config first."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"realm/{realm}"
    return run_governed(
        "pve_realm_update", tgt,
        plan=lambda: plan_realm_update(api, realm, comment, options),
        execute=lambda: realm_update(api, realm, comment, options),
        confirm=confirm)


@tool()
def pve_realm_delete(
    realm: Annotated[str, Field(description="Realm id to delete (built-in 'pam'/'pve' are refused).")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")] = False,
) -> dict:
    """MUTATION (HIGH, lockout-class): delete an auth realm. Dry-run by default — the PLAN reads
    users to count who can no longer log in, and refuses built-in pam/pve (permanent, no undo).
    confirm=True executes and returns a dict; synchronous, no UPID. Use pve_users_list to see who
    authenticates through the realm first."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"realm/{realm}"
    return run_governed(
        "pve_realm_delete", tgt,
        plan=lambda: plan_realm_delete(api, realm),
        execute=lambda: realm_delete(api, realm),
        confirm=confirm)
