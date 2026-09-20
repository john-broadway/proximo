"""PDM access governance: users, API tokens, ACL, permissions — the first native PDM mutations.

PDM's access API is PBS's (the same proxmox-access crate: users with tokens, one `auth-id`,
one `role` per ACL entry), so the backend and plan helpers are proximo.pbs_access driven with a
PdmBackend; `_plane(api)` and `plane="pdm"` put this plane's name on actions and PLAN targets.
Reads that already existed stay in tools/pdm.py (pdm_users_list, pdm_acl_list, pdm_roles_list).
Live-proven 2026-09-19 on pdm-test (PDM 1.1.4): user create/update(delete_props)/delete, token
create (secret returned once, never ledgered)/delete, ACL grant/revoke, permissions.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_access import (
    _password_redacted_detail,
    acl_update,
    permissions_get,
    plan_acl_update,
    plan_token_create,
    plan_token_delete,
    plan_token_update,
    plan_user_create,
    plan_user_delete,
    plan_user_update,
    token_create,
    token_delete,
    token_update,
    user_create,
    user_delete,
    user_get,
    user_token_get,
    user_tokens_list,
    user_update,
)
from proximo.server import _audited, run_governed, tool


@tool()
def pdm_user_get(
    userid: Annotated[str, Field(description="PDM user id to look up, format 'user@realm'.")],
) -> dict:
    """READ-ONLY: get a PDM user's config (userid, enabled flag, expiry, email, comment,
    firstname/lastname; no tokens, no secrets). Use pdm_user_tokens_list for the user's API
    tokens, or pdm_user_create/update/delete to manage the user. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_user_get", f"pdm/access/users/{userid}", lambda: user_get(pdm, userid))


@tool()
def pdm_user_create(
    userid: Annotated[str, Field(description="New PDM user id, format 'user@realm'.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment.")] = None,
    email: Annotated[str | None, Field(description="Optional email address.")] = None,
    enable: Annotated[
        bool | None, Field(description="Whether the account can log in; None defers to PDM's default (enabled).")
    ] = None,
    expire: Annotated[
        int | None, Field(description="Optional account expiry as a Unix timestamp; None/0 means no expiry.")
    ] = None,
    firstname: Annotated[str | None, Field(description="Optional first name.")] = None,
    lastname: Annotated[str | None, Field(description="Optional last name.")] = None,
    password: Annotated[
        str | None, Field(description="Optional initial password; redacted from all plans/logs/ledger.")
    ] = None,
    confirm: Annotated[
        bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")
    ] = False,
) -> dict:
    """MUTATION (MEDIUM): create a PDM user. Dry-run by default. `password` is optional and,
    when supplied, unconditionally redacted from the plan, detail and ledger. confirm=True
    executes and returns a dict; synchronous. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return run_governed(
        "pdm_user_create",
        f"pdm/access/users/{userid}",
        plan=lambda: plan_user_create(userid, comment, email, enable, expire, firstname, lastname, plane="pdm"),
        execute=lambda: user_create(pdm, userid, comment, email, enable, expire, firstname, lastname, password),
        confirm=confirm,
        surface=_password_redacted_detail(password),
    )


@tool()
def pdm_user_update(
    userid: Annotated[str, Field(description="PDM user id to update, format 'user@realm'.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment; omit to leave unchanged.")] = None,
    email: Annotated[str | None, Field(description="Optional email address; omit to leave unchanged.")] = None,
    enable: Annotated[
        bool | None, Field(description="Whether the account can log in; False stops login. Omit to leave unchanged.")
    ] = None,
    expire: Annotated[
        int | None, Field(description="Account expiry as a Unix timestamp; omit to leave unchanged.")
    ] = None,
    firstname: Annotated[str | None, Field(description="Optional first name; omit to leave unchanged.")] = None,
    lastname: Annotated[str | None, Field(description="Optional last name; omit to leave unchanged.")] = None,
    delete_props: Annotated[
        list[str] | None,
        Field(description="Property names to clear: any of 'comment', 'firstname', 'lastname', 'email'."),
    ] = None,
    digest: Annotated[
        str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")
    ] = None,
    confirm: Annotated[
        bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")
    ] = False,
) -> dict:
    """MUTATION (MEDIUM): update a PDM user (enable=False stops login immediately). Dry-run by
    default; the PLAN reads the current config first. No password parameter: the user
    endpoint's password field is not the way to set one. confirm=True executes and returns a
    dict; synchronous. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return run_governed(
        "pdm_user_update",
        f"pdm/access/users/{userid}",
        plan=lambda: plan_user_update(pdm, userid, comment, email, enable, expire, firstname, lastname, delete_props),
        execute=lambda: user_update(
            pdm, userid, comment, email, enable, expire, firstname, lastname, delete_props, digest
        ),
        confirm=confirm,
    )


@tool()
def pdm_user_delete(
    userid: Annotated[str, Field(description="PDM user id to delete, format 'user@realm'.")],
    digest: Annotated[
        str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")
    ] = None,
    confirm: Annotated[
        bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")
    ] = False,
) -> dict:
    """MUTATION (MEDIUM): delete a PDM user. Dry-run by default; the PLAN reads the user's config
    and tokens to show what vanishes (permanent, no undo: the user's tokens go with it and ACL
    entries naming it are orphaned). To stop login without deleting, use pdm_user_update
    (enable=False). confirm=True executes and returns a dict. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return run_governed(
        "pdm_user_delete",
        f"pdm/access/users/{userid}",
        plan=lambda: plan_user_delete(pdm, userid),
        execute=lambda: user_delete(pdm, userid, digest),
        confirm=confirm,
    )


@tool()
def pdm_user_tokens_list(
    userid: Annotated[str, Field(description="Owning PDM user, format 'user@realm'.")],
) -> list[dict]:
    """READ-ONLY: list a PDM user's API tokens (token-name, tokenid, comment, expiry, enabled
    flag; never the secret). Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited("pdm_user_tokens_list", f"pdm/access/users/{userid}/token", lambda: user_tokens_list(pdm, userid))


@tool()
def pdm_user_token_get(
    userid: Annotated[str, Field(description="Owning PDM user, format 'user@realm'.")],
    token_name: Annotated[str, Field(description="Token name (the part after '!' in the full tokenid).")],
) -> dict:
    """READ-ONLY: one PDM API token's metadata (comment, expiry, enabled flag, token-name,
    tokenid; never the secret). Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return _audited(
        "pdm_user_token_get",
        f"pdm/access/users/{userid}/token/{token_name}",
        lambda: user_token_get(pdm, userid, token_name),
    )


@tool()
def pdm_token_create(
    userid: Annotated[str, Field(description="Owning PDM user, format 'user@realm'.")],
    token_name: Annotated[str, Field(description="Name for the new API token, unique per user.")],
    comment: Annotated[
        str | None, Field(description="Optional free-text comment describing the token's purpose.")
    ] = None,
    enable: Annotated[
        bool | None,
        Field(description="Whether the token is usable immediately; None defers to PDM's default (enabled)."),
    ] = None,
    expire: Annotated[
        int | None, Field(description="Optional token expiry as a Unix timestamp; None/0 means no expiry.")
    ] = None,
    digest: Annotated[
        str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")
    ] = None,
    confirm: Annotated[
        bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")
    ] = False,
) -> dict:
    """MUTATION (MEDIUM): create an API token for a PDM user. Dry-run by default. The new token
    has no privileges until pdm_acl_update grants it some (auth_id='user@realm!token_name'), and
    never more than its owning user holds on that path (grant the user first).
    confirm=True returns the token secret ONCE in the result; it is never written to the ledger
    and cannot be retrieved again (only regenerated). Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return run_governed(
        "pdm_token_create",
        f"pdm/access/users/{userid}/token/{token_name}",
        plan=lambda: plan_token_create(userid, token_name, comment, enable, expire, plane="pdm"),
        execute=lambda: token_create(pdm, userid, token_name, comment, enable, expire, digest),
        confirm=confirm,
        detail={"enable": enable, "expire": expire},
    )


@tool()
def pdm_token_update(
    userid: Annotated[str, Field(description="Owning PDM user, format 'user@realm'.")],
    token_name: Annotated[str, Field(description="Name of the API token to update.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment; omit to leave unchanged.")] = None,
    enable: Annotated[
        bool | None,
        Field(description="Whether the token is usable; False disables it immediately. Omit to leave unchanged."),
    ] = None,
    expire: Annotated[
        int | None, Field(description="Token expiry as a Unix timestamp; omit to leave unchanged.")
    ] = None,
    regenerate: Annotated[
        bool, Field(description="If True, issue a BRAND-NEW secret and invalidate the old one immediately (HIGH).")
    ] = False,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear ('comment').")] = None,
    digest: Annotated[
        str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")
    ] = None,
    confirm: Annotated[
        bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")
    ] = False,
) -> dict:
    """MUTATION: update a PDM API token's metadata; regenerate=True is HIGH (a new secret, the
    old one invalid at once, returned ONCE and never ledgered). Dry-run by default. Needs
    PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return run_governed(
        "pdm_token_update",
        f"pdm/access/users/{userid}/token/{token_name}",
        plan=lambda: plan_token_update(
            userid, token_name, comment, enable, expire, regenerate, delete_props, plane="pdm"
        ),
        execute=lambda: token_update(
            pdm, userid, token_name, comment, enable, expire, regenerate, delete_props, digest
        ),
        confirm=confirm,
        detail={"regenerate": regenerate, "enable": enable},
    )


@tool()
def pdm_token_delete(
    userid: Annotated[str, Field(description="Owning PDM user, format 'user@realm'.")],
    token_name: Annotated[str, Field(description="Name of the API token to revoke.")],
    digest: Annotated[
        str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")
    ] = None,
    confirm: Annotated[
        bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")
    ] = False,
) -> dict:
    """MUTATION (MEDIUM, IRREVERSIBLE): permanently revoke a PDM API token; any integration using
    it loses access at once. Dry-run by default. Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    return run_governed(
        "pdm_token_delete",
        f"pdm/access/users/{userid}/token/{token_name}",
        plan=lambda: plan_token_delete(userid, token_name, plane="pdm"),
        execute=lambda: token_delete(pdm, userid, token_name, digest),
        confirm=confirm,
    )


@tool()
def pdm_acl_update(
    path: Annotated[str, Field(description="ACL path the entry applies to, e.g. '/resource/lab' or '/'.")],
    role: Annotated[str, Field(description="A single PDM role id to grant or revoke, e.g. 'Auditor'.")],
    auth_id: Annotated[
        str | None,
        Field(
            description="User or token principal ('user@realm' or 'user@realm!token-name'). Exactly one of auth_id/group is required."
        ),
    ] = None,
    group: Annotated[
        str | None, Field(description="Group principal. Exactly one of auth_id/group is required.")
    ] = None,
    propagate: Annotated[
        bool | None, Field(description="Whether the grant propagates below `path`; omit for PDM's default (true).")
    ] = None,
    delete: Annotated[bool, Field(description="False to grant the role, True to revoke it.")] = False,
    digest: Annotated[
        str | None, Field(description="Optional SHA256 config digest to prevent concurrent modifications.")
    ] = None,
    confirm: Annotated[
        bool, Field(description="False (default) returns a dry-run PLAN preview; True executes the mutation.")
    ] = False,
) -> dict:
    """MUTATION (HIGH): grant or revoke a PDM ACL entry (PUT /access/acl). Every ACL change
    grants or revokes authority, so it is HIGH unconditionally. Dry-run by default (reads the
    entries at this exact path for context). Exactly one of auth_id/group. Revert with a second
    call (grant<->revoke). Use pdm_acl_list to see entries, pdm_roles_list for the roles. Needs
    PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    principal = auth_id if auth_id is not None else f"group:{group}"
    return run_governed(
        "pdm_acl_update",
        f"pdm/access/acl:{path}:{principal}",
        plan=lambda: plan_acl_update(pdm, path, role, auth_id, group, propagate, delete),
        execute=lambda: acl_update(pdm, path, role, auth_id, group, propagate, delete, digest),
        confirm=confirm,
    )


@tool()
def pdm_permissions_get(
    auth_id: Annotated[
        str | None,
        Field(
            description="User or token to resolve ('user@realm' or 'user@realm!token-name'); omit for the calling credential."
        ),
    ] = None,
    path: Annotated[str | None, Field(description="ACL path to scope the result to; omit for every path.")] = None,
) -> dict:
    """READ-ONLY: resolved effective privileges for a PDM user/token (path -> privilege ->
    propagate bit), the inherited plus direct view that pdm_acl_list's raw entries resolve to.
    Needs PROXIMO_PDM_* config."""
    _, pdm = _proximo_server._pdm()
    tgt = f"pdm/access/permissions/{auth_id}" if auth_id else "pdm/access/permissions"
    return _audited("pdm_permissions_get", tgt, lambda: permissions_get(pdm, auth_id, path))
