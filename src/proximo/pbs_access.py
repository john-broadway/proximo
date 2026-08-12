"""PBS access governance — users, API tokens, ACL, roles, permissions.

Wave 2a of the full-surface campaign (`.scratch/2026-07-15-full-surface-campaign.md`, "2a — PBS
identity core"). Mirrors the PVE access plane's own split into dedicated modules (access.py /
access_users.py / access_governance.py) but for PBS's distinct auth/ACL model — this closes the
EXCLUSION named in pbs_config.py's module docstring: "PBS access management (acl / users /
tokens) is deliberately NOT in this wave. ... belongs in its own focused PBS-access wave —
mirroring how PVE access management lives in dedicated access.py / access_users.py /
access_governance.py modules." That wave is this module.

Endpoints used (schema truth: the LIVE api-viewer schema, https://pbs.proxmox.com/docs/
api-viewer/apidoc.js, pulled 2026-07-15 — the `.scratch/api-schemas-2026-07-15/methods-pbs.json`
snapshot carries path+verb only, no param-level detail, so every param list below was read
directly from the live JSON-Schema `parameters` blocks, not invented or guessed):

  Users (/access/users):
    GET    /access/users                    — list users (include_tokens: bool filter)
    POST   /access/users                    — create user (password is OPTIONAL — a real secret)
    GET    /access/users/{userid}           — read one user (no tokens/secrets in this shape)
    PUT    /access/users/{userid}           — update user config. PBS's own 'password' PUT param
                                               is documented "This parameter is ignored, please
                                               use 'PUT /access/password'" — deliberately NOT
                                               exposed here (a working-looking no-op param would
                                               be a lie).
    DELETE /access/users/{userid}           — remove user (permanent)

  API tokens (/access/users/{userid}/token[/…]):
    GET    /access/users/{userid}/token                  — list a user's tokens (no secret)
    GET    /access/users/{userid}/token/{token-name}      — read one token's metadata (no secret)
    POST   /access/users/{userid}/token/{token-name}      — create → {"tokenid","value"}
                                                              ('value' = the secret, shown ONCE)
    PUT    /access/users/{userid}/token/{token-name}      — update metadata; regenerate=True →
                                                              {"secret": ...} — a SECOND
                                                              secret-bearing shape on this plane,
                                                              issuing a brand-new secret and
                                                              invalidating the old one immediately
    DELETE /access/users/{userid}/token/{token-name}      — revoke (permanent)

  ACL (/access/acl):
    GET  /access/acl   — read ACL entries (optional exact-path filter)
    PUT  /access/acl   — grant/revoke ONE role for ONE principal (auth-id XOR group) at a path.
                          Unlike PVE's comma-separated multi-role 'roles' + kind='user'/'group'/
                          'token' discriminator, PBS's schema carries a single 'role' string and
                          folds user+token identity into one 'auth-id' field (pattern matches
                          either 'user@realm' or 'user@realm!token-name'); 'group' is separate.

  Roles (/access/roles):
    GET  /access/roles   — list roles. PBS roles are a FIXED built-in enum (Admin, Audit,
                            NoAccess, DatastoreAdmin, DatastoreReader, DatastoreBackup,
                            DatastorePowerUser, DatastoreAudit, RemoteAudit, RemoteAdmin,
                            RemoteSyncOperator, RemoteSyncPushOperator, RemoteDatastorePowerUser,
                            RemoteDatastoreAdmin, TapeAudit, TapeAdmin, TapeOperator, TapeReader)
                            — there is NO create/update/delete role endpoint in the PBS API,
                            unlike PVE's custom roles. This module exposes read-only accordingly.

  Permissions (/access/permissions):
    GET  /access/permissions   — resolved effective privileges for a user/token (or the caller
                                  if auth-id is omitted), optionally scoped to one ACL path.

  Realms (config/access/{ad,ldap,openid,pam,pbs}) — Wave 2b, `.scratch/2026-07-15-full-surface-
  campaign.md` "2b — PBS realms". Endpoint table (params read directly from the live api-viewer
  'parameters' blocks, 2026-07-15 — NOT from the `.scratch` path+verb-only snapshot):
    GET    /config/access/ad                — list configured AD realms
    POST   /config/access/ad                — create (required: realm, server1)
    GET    /config/access/ad/{realm}        — read one AD realm
    PUT    /config/access/ad/{realm}        — update (delete[], digest supported)
    DELETE /config/access/ad/{realm}        — remove
    GET/POST/GET/PUT/DELETE /config/access/ldap[/{realm}] — same 5 ops; LDAP additionally
      REQUIRES base-dn + user-attr on create (both optional on update) — AD does not.
    GET/POST/GET/PUT/DELETE /config/access/openid[/{realm}] — same 5 ops; create requires
      realm, issuer-url, client-id. NO delete/update auth-url/login/browser-handshake endpoints
      are exposed here (excluded by design, see EXCLUSION below).
    GET  /config/access/pam   — read the built-in PAM realm config (comment/default only)
    PUT  /config/access/pam   — update it
    GET  /config/access/pbs   — read the built-in PBS-auth realm config (comment/default only)
    PUT  /config/access/pbs   — update it
    PAM/PBS have NO create/delete endpoint — they are fixed built-in realms, GET/PUT only
    (mirrors roles_list's read-only posture for PBS's fixed role enum). Because neither can be
    deleted (no lockout-by-removal path exists on this plane), their PUT is rated the SAME
    RISK_MEDIUM as every other realm mutation here — deliberately NOT escalated to HIGH the way
    PVE's plan_realm_update escalates built-in realms, because the only thing PUT can change here
    is 'comment'/'default' (which realm is preselected on the login screen), not whether the
    realm is enabled at all.
    Realm mutations (create/update/delete, all types) = RISK_MEDIUM — auth config, but not the
    unconditional-authority-grant class that makes ACL updates flat HIGH.

  TFA (access/tfa, access/users/{userid}/unlock-tfa, config/access/tfa/webauthn):
    GET    /access/tfa                       — list ALL users' TFA configuration
    GET    /access/tfa/{userid}              — list ONE user's TFA entries. Smoke-confirm: PBS's
                                                own apidoc labels this GET's description "Add a
                                                TOTP secret to the user" (identical wording to the
                                                sibling POST on the same path) — almost certainly a
                                                copy/paste doc bug upstream, since its RETURN shape
                                                is documented as "the list of TFA entries" and the
                                                GET verb itself is a read; treated here as a list
                                                read, matching the return shape, not the label.
    POST   /access/tfa/{userid}              — add a TFA entry (type: totp/u2f/webauthn/recovery/
                                                yubico). SECRET-BEARING: see below.
    GET    /access/tfa/{userid}/{id}         — one TFA entry. Smoke-confirm: PBS's own apidoc
                                                documents this GET's return type as literally
                                                `null` — a schema-generation quirk, not this
                                                module's invention; treated as an untyped read.
    PUT    /access/tfa/{userid}/{id}         — update description/enable
    DELETE /access/tfa/{userid}/{id}         — remove one TFA factor (permanent)
    PUT    /access/users/{userid}/unlock-tfa — clear a TOTP lockout. NOTE: this lives under
                                                /access/users/, NOT /access/tfa/{userid}/ as an
                                                initial guess assumed — confirmed from the live
                                                schema, not invented.
    GET/PUT /config/access/tfa/webauthn      — server-wide WebAuthn relying-party config (id/
                                                origin/rp) — changing 'id'/'origin' MAY break
                                                EVERY existing WebAuthn credential on the server
                                                (per the schema's own field descriptions).

  TFA mutation risk: the two AUTHENTICATION-WEAKENING mutations are RISK_HIGH — tfa_delete
  (removes a 2FA factor → account-takeover enabler / lockout, the same semantics PVE's own
  plan_tfa_delete rates HIGH) and tfa_unlock (clears the anti-brute-force throttle guarding a
  6-digit TOTP keyspace). The other three (tfa_add — creates a factor; tfa_update — description/
  enable metadata; webauthn_set — server-wide relying-party config) stay RISK_MEDIUM. This plane
  guards backups, so under-flagging an auth-weakening act would be dishonest.

NONE of this module is live-verified yet (no PBS-access smoke has run against a real server) —
every backend function below is schema-derived only. "Smoke-confirm:" comments name the specific
unverified detail (mirrors the discipline already established in pbs.py / pbs_config.py).

Security posture — secret classes on this plane:
  1. User 'password' (POST /access/users create only — PUT's 'password' param is a documented
     no-op). Mirrors pbs_config.py's remote-password pattern: UNCONDITIONALLY redacted from the
     plan/detail/ledger surfaces — {"password": "[redacted]"} when supplied, {} when not (unlike
     pbs_config's remote password, PBS user passwords are OPTIONAL, so the redaction marker only
     appears when one was actually set — claiming a password was redacted when none was given
     would be its own small dishonesty). plan_user_create takes NO password parameter at all —
     the plan factory never receives it, same discipline as plan_remote_create.
  2. API token secret ('value' on create, 'secret' on a regenerate=True update): mirrors
     pve_token_create's contract EXACTLY (proximo/access.py token_create / plan_token_create) —
     the secret surfaces ONCE in the tool's return value and is NEVER written to the audit
     ledger. Neither plan_token_create nor plan_token_update accepts a secret-bearing parameter
     (PURE, no API call — the secret doesn't exist yet at plan time). The server-layer wrapper
     enforces the never-in-ledger promise by simply never putting 'value'/'secret' in the
     `detail=` dict passed to `_audited()` — see tools/pbs_access.py.
  3. (Wave 2b) AD/LDAP bind 'password' and OpenID 'client-key' (POST/PUT create+update): the
     SAME `_password_redacted_detail` helper is reused verbatim for AD/LDAP (identical field
     name and semantics — a persistent service-account credential, not one-time-shown); a
     sibling `_client_key_redacted_detail` covers OpenID's differently-named field.
  4. (Wave 2b) TFA's 'password' request param (the ACTING user's own current password, sent on
     add/update/delete to re-authenticate a sensitive change) — also redacted via
     `_password_redacted_detail`, same field name, same discipline.
  5. (Wave 2b) TFA add's 'recovery' response field: POST /access/tfa/{userid} with type='recovery'
     returns `{"recovery": [<one-time codes>], ...}` — SERVER-GENERATED secret material, usable
     as backup 2FA credentials. Mirrors pbs_token_create's contract EXACTLY: surfaces ONCE in the
     tool's return value, NEVER written to the audit ledger (the wrapper's `detail=` dict never
     includes 'recovery'/'challenge'/'id'). For type='totp', the caller supplies the secret
     (a totp: URI) rather than PBS generating one — no secret flows back to the caller in that
     case, but the SAME never-in-ledger discipline is applied to the whole POST response
     unconditionally, since the response shape is secret-bearing for at least one accepted type.

EXCLUSION (historical — closed 2026-07-15, Wave 2b): realms (config/access/{ad,ldap,openid,pam,
pbs}) and TFA (access/tfa, config/access/tfa/webauthn, unlock-tfa) were carried forward from
pbs_config.py's own EXCLUSION note as NOT yet built — that wave is now built, in this same module
(the endpoint tables above). Still excluded, by design, not oversight: the openid browser
handshake (auth-url/login — a ticket/redirect flow, not a token-auth-shaped operation), realm
sync (already built — see backup_schedules.py's pbs_realm_sync, not rebuilt here), and password
self-change (PUT /access/password — a different auth-flow shape entirely).
"""

from __future__ import annotations

import re

from ._validate import check_digest as _check_digest
from .backends import ProximoError
from .backup_schedules import _check_realm
from .pbs import PbsBackend
from .planning import RISK_HIGH, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators (module-local — PBS's own charset is NOT identical to PVE's; read from the live
# api-viewer 'pattern' fields, not copied from access.py).
# ---------------------------------------------------------------------------

# userid: PBS's own regex is far more permissive on the user-part than PVE's — anything except
# whitespace/colon/slash/control chars — then '@' then a realm (alnum/underscore start,
# alnum/./_/- body). Source: POST /access/users 'userid' property pattern (live api-viewer,
# 2026-07-15): /^(?:[^\s:/[:cntrl:]]+)@(?:[A-Za-z0-9_][A-Za-z0-9._\-]*)$/
_USERID_RE = re.compile(r"^[^\s:/\x00-\x1f\x7f]+@[A-Za-z0-9_][A-Za-z0-9._-]*\Z")

# token-name: the bare token-name part only (not the full 'user@realm!name' tokenid).
# Source: POST token 'token-name' property pattern: /^(?:[A-Za-z0-9_][A-Za-z0-9._\-]*)$/
_TOKENNAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*\Z")

# auth-id: accepted by PUT /access/acl and GET /access/permissions — either a bare userid or a
# full tokenid ('user@realm!token-name'). Source: PUT /access/acl 'auth-id' property pattern.
_AUTHID_RE = re.compile(
    r"^[^\s:/\x00-\x1f\x7f]+@[A-Za-z0-9_][A-Za-z0-9._-]*"
    r"(?:![A-Za-z0-9_][A-Za-z0-9._-]*)?\Z"
)

# group id (ACL 'group' target): PBS's api-viewer documents this only as "Group ID" with the
# same charset restriction as the userid user-part (no dedicated stricter pattern is published).
# Smoke-confirm: exact accepted charset against a live PBS group.
_GROUPID_RE = re.compile(r"^[^\s:/\x00-\x1f\x7f]+\Z")

# ACL path: PBS's own pattern is '/' alone, or one-or-more '/segment' where each segment starts
# alnum/underscore then continues alnum/./_/- (slightly stricter than PVE's: a segment may not
# START with '.' or '-'). Source: GET/PUT /access/acl 'path' property pattern:
# /^(?:/|(?:/(?:[A-Za-z0-9_][A-Za-z0-9._\-]*))+)$/
_ACL_PATH_RE = re.compile(r"^(?:/|(?:/[A-Za-z0-9_][A-Za-z0-9._-]*)+)\Z")

# role id: PBS roles are a FIXED built-in enum (see module docstring) — no custom-role CRUD
# exists in the PBS API. Validate charset only (letters/digits, matching every listed role name)
# rather than hard-coding the exact enum, so a future PBS release adding a role doesn't need a
# Proximo code change; PBS itself is the final authority and 400s on an unknown role.
_ROLEID_RE = re.compile(r"^[A-Za-z0-9]+\Z")

# TFA entry id: PBS's own schema documents 'id' only as "the tfa entry id" — no pattern, no
# length limit. Guarded defensively (it flows into the URL path) by mirroring PVE's own TFA-id
# charset (access_governance.py's _TFA_ID_RE) — PVE and PBS share the same underlying
# proxmox-tfa Rust crate, so the id shapes are very likely identical, but this is NOT
# live-verified on PBS specifically.
_TFA_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]*\Z")

# TFA entry type enum. Source: POST /access/tfa/{userid} 'type' property enum.
_TFA_TYPES = frozenset({"totp", "u2f", "webauthn", "recovery", "yubico"})


def _reject_dot_traversal(s: str, label: str) -> None:
    """Reject a '.'/'..'-containing identifier — it flows into the URL path and the HTTP client
    normalizes dot-segments BEFORE sending, so a crafted value can retarget the request onto a
    different endpoint entirely. Mirrors access.py's identical guard on the PVE plane."""
    if s == "." or ".." in s:
        raise ProximoError(f"invalid {label}: {s!r} — path-traversal segment rejected")


def _check_userid(userid: str) -> str:
    s = str(userid).strip()
    if not _USERID_RE.match(s):
        raise ProximoError(
            f"invalid PBS userid: {userid!r} — expected 'user@realm' "
            "(user part: no whitespace/colon/slash/control chars; "
            "realm: letters/digits/._- only, starting with a letter/digit/underscore)"
        )
    _reject_dot_traversal(s, "userid")
    return s


def _check_tokenname(name: str) -> str:
    s = str(name).strip()
    if not _TOKENNAME_RE.match(s):
        raise ProximoError(
            f"invalid PBS token-name: {name!r} — expected letters/digits/._- only, "
            "starting with a letter/digit/underscore"
        )
    _reject_dot_traversal(s, "token-name")
    return s


def _check_authid(auth_id: str) -> str:
    s = str(auth_id).strip()
    if not _AUTHID_RE.match(s):
        raise ProximoError(
            f"invalid PBS auth-id: {auth_id!r} — expected 'user@realm' or "
            "'user@realm!token-name'"
        )
    _reject_dot_traversal(s, "auth-id")
    return s


def _check_groupid(groupid: str) -> str:
    s = str(groupid).strip()
    if not _GROUPID_RE.match(s):
        raise ProximoError(
            f"invalid PBS group id: {groupid!r} — no whitespace/colon/slash/control chars"
        )
    _reject_dot_traversal(s, "group id")
    return s


def _check_acl_path(path: str) -> str:
    s = str(path).strip()
    if ".." in s:
        raise ProximoError(f"invalid PBS ACL path: {path!r} (path traversal rejected)")
    if not _ACL_PATH_RE.match(s):
        raise ProximoError(
            f"invalid PBS ACL path: {path!r} — expected '/' or '/segment/…/segment' "
            "(each segment: letters/digits/underscore first char, then letters/digits/._-)"
        )
    return s


def _check_roleid(roleid: str) -> str:
    s = str(roleid).strip()
    if not _ROLEID_RE.match(s):
        raise ProximoError(f"invalid PBS role id: {roleid!r} — expected letters/digits only")
    return s


def _check_tfa_id(tfa_id: str) -> str:
    s = str(tfa_id).strip()
    if not _TFA_ID_RE.match(s):
        raise ProximoError(
            f"invalid PBS TFA entry id: {tfa_id!r} — expected alnum/:._- only, "
            "starting with a letter/digit"
        )
    _reject_dot_traversal(s, "TFA entry id")
    return s


def _check_tfa_type(tfa_type: str) -> str:
    s = str(tfa_type).strip()
    if s not in _TFA_TYPES:
        raise ProximoError(f"invalid TFA type: {tfa_type!r} — expected one of {sorted(_TFA_TYPES)}")
    return s


def _check_acl_principal(auth_id: str | None, group: str | None) -> tuple[str | None, str | None]:
    """PBS's PUT /access/acl takes auth-id and group as two independent optional body fields,
    but exactly one identifies the principal being granted/revoked. Fail loud rather than send
    an ambiguous or empty-principal request — the honest failure mode is a clear local error,
    not a PBS 400 the caller has to decode."""
    if (auth_id is None) == (group is None):
        raise ProximoError(
            "pbs_acl_update requires exactly one of auth_id or group (PBS's ACL entry names "
            "either a user/token principal via auth_id, or a group via group — never both, "
            "never neither)"
        )
    if auth_id is not None:
        return _check_authid(auth_id), None
    return None, _check_groupid(group)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Secret redaction helper
# ---------------------------------------------------------------------------

def _password_redacted_detail(password: str | None) -> dict:
    """Unconditional redaction for the optional PBS user-create password — never store even a
    hash. Returns {} when no password was supplied (honest: nothing to redact), or
    {"password": "[redacted]"} when one was. Used by the server layer only — plan_user_create
    never receives the password at all (same discipline as pbs_config.py's plan_remote_create)."""
    return {"password": "[redacted]"} if password is not None else {}


def _client_key_redacted_detail(client_key: str | None) -> dict:
    """Same discipline as _password_redacted_detail, for OpenID's differently-named credential
    field ('client-key' — the OAuth client secret). Wire key uses the hyphenated wire name so a
    reader of the ledger detail sees the same field name the API itself uses."""
    return {"client-key": "[redacted]"} if client_key is not None else {}


# ---------------------------------------------------------------------------
# Field-building helpers — realm directory config (AD/LDAP share nearly all fields; OpenID and
# the PAM/PBS singleton realms get their own). Mirrors _user_fields's discipline: the create/
# update ops and their plan-factory previews call the SAME builder so the field list can't
# silently diverge between the two.
# ---------------------------------------------------------------------------

def _realm_directory_fields(
    *,
    comment: str | None = None,
    default: bool | None = None,
    filter: str | None = None,  # noqa: A002 — matches PBS's own wire field name 'filter'
    mode: str | None = None,
    port: int | None = None,
    server2: str | None = None,
    sync_attributes: str | None = None,
    sync_defaults_options: str | None = None,
    user_classes: str | None = None,
    verify: bool | None = None,
    base_dn: str | None = None,
    bind_dn: str | None = None,
    capath: str | None = None,
) -> dict:
    """Shared by AD + LDAP create/update (their schemas are near-identical). LDAP additionally
    REQUIRES base-dn + user-attr on create — those are handled by the caller directly (user-attr
    has no AD equivalent at all, so it isn't a param here); base_dn/bind_dn/capath ARE common to
    both and so live in this shared builder, optional either way (LDAP's caller always supplies
    base_dn since it's required there, but the field name is identical).

    Compound string-shaped fields (sync-attributes, sync-defaults-options, user-classes) are
    forwarded VERBATIM as PBS-formatted strings — Proximo does NOT re-encode a Python list into
    them. Smoke-confirm: the exact expected separator per field is not uniformly documented —
    user-classes' own schema default ("inetorgperson,posixaccount,person,user") confirms
    comma-separated for that one field, but sync-defaults-options' exact syntax
    (semicolon/equals-shaped per its description) is not live-verified here.
    """
    fields: dict = {}
    if comment is not None:
        fields["comment"] = comment
    if default is not None:
        fields["default"] = default
    if filter is not None:
        fields["filter"] = filter
    if mode is not None:
        fields["mode"] = mode
    if port is not None:
        fields["port"] = int(port)
    if server2 is not None:
        fields["server2"] = server2
    if sync_attributes is not None:
        fields["sync-attributes"] = sync_attributes
    if sync_defaults_options is not None:
        fields["sync-defaults-options"] = sync_defaults_options
    if user_classes is not None:
        fields["user-classes"] = user_classes
    if verify is not None:
        fields["verify"] = verify
    if base_dn is not None:
        fields["base-dn"] = base_dn
    if bind_dn is not None:
        fields["bind-dn"] = bind_dn
    if capath is not None:
        fields["capath"] = capath
    return fields


def _openid_fields(
    *,
    comment: str | None = None,
    default: bool | None = None,
    acr_values: str | None = None,
    audiences: str | None = None,
    autocreate: bool | None = None,
    prompt: str | None = None,
    scopes: str | None = None,
) -> dict:
    """Shared by OpenID create/update. `client-id`/`issuer-url`/`client-key` are handled by the
    caller directly (client-id/issuer-url are REQUIRED on create but optional on update; client-key
    is a secret needing its own redaction path — see _client_key_redacted_detail).

    NOTE `username-claim` is deliberately NOT in this shared builder — the live schema shows it is
    a CREATE-ONLY field (absent from PUT /config/access/openid/{realm}'s properties, which is
    additionalProperties:false), so sending it on an update hard-fails the WHOLE request
    server-side. realm_openid_create adds it directly (create-specific), mirroring how LDAP's
    create-required base_dn/user_attr are added by realm_ldap_create rather than routed through
    the shared _realm_directory_fields builder.

    scopes/acr-values/audiences are also compound string-shaped fields forwarded verbatim —
    scopes' own schema default ("email profile", a SPACE, not comma) confirms space-separated for
    that field; acr-values/audiences' exact separator is not live-verified here.
    """
    fields: dict = {}
    if comment is not None:
        fields["comment"] = comment
    if default is not None:
        fields["default"] = default
    if acr_values is not None:
        fields["acr-values"] = acr_values
    if audiences is not None:
        fields["audiences"] = audiences
    if autocreate is not None:
        fields["autocreate"] = autocreate
    if prompt is not None:
        fields["prompt"] = prompt
    if scopes is not None:
        fields["scopes"] = scopes
    return fields


def _realm_singleton_fields(comment: str | None = None, default: bool | None = None) -> dict:
    """Shared by the PAM/PBS built-in realms' PUT — the only two mutable fields either exposes."""
    fields: dict = {}
    if comment is not None:
        fields["comment"] = comment
    if default is not None:
        fields["default"] = default
    return fields


# ---------------------------------------------------------------------------
# Field-building helper — shared by user_create/user_update and their plan-factory previews so
# the field list can't silently diverge (mirrors pbs_config.py's _datastore_schedule_fields).
# ---------------------------------------------------------------------------

def _user_fields(
    comment: str | None = None,
    email: str | None = None,
    enable: bool | None = None,
    expire: int | None = None,
    firstname: str | None = None,
    lastname: str | None = None,
) -> dict:
    fields: dict = {}
    if comment is not None:
        fields["comment"] = comment
    if email is not None:
        fields["email"] = email
    if enable is not None:
        fields["enable"] = enable
    if expire is not None:
        fields["expire"] = int(expire)
    if firstname is not None:
        fields["firstname"] = firstname
    if lastname is not None:
        fields["lastname"] = lastname
    return fields


def _join_delete_props(delete_props) -> str:
    # Smoke-confirm: PBS's accepted array encoding for the 'delete' property-list param (comma-
    # joined here, matching this codebase's existing PVE-list convention for array-shaped form
    # params — e.g. access_users.py's 'groups' — since PBS's api-viewer only documents the JSON
    # array shape, not the HTTP form-encoding PBS expects for it).
    if isinstance(delete_props, (list, tuple)):
        return ",".join(delete_props)
    return str(delete_props)


# ---------------------------------------------------------------------------
# Backend functions — users (read)
# ---------------------------------------------------------------------------

def users_list(api: PbsBackend, include_tokens: bool = False) -> list[dict]:
    """GET /access/users — list all PBS users.

    include_tokens=True embeds each user's API tokens in the returned list (no secrets — token
    metadata only). Smoke-confirm: whether 'include_tokens' is accepted as a raw boolean query
    param (mirrors the same open question already carried by pbs.py's tasks_list for
    'running'/'errors' — PBS's GET-param boolean convention is unconfirmed here).
    """
    params = {"include_tokens": include_tokens} if include_tokens else None
    return api._get("/access/users", params=params) or []


def user_get(api: PbsBackend, userid: str) -> dict:
    """GET /access/users/{userid} — read one user's config (comment/email/enable/expire/
    firstname/lastname/userid; no tokens, no secrets)."""
    userid = _check_userid(userid)
    return api._get(f"/access/users/{userid}") or {}


# ---------------------------------------------------------------------------
# Backend functions — users (mutation). Do NOT self-gate — the server layer adds confirm-gating
# + audit, mirroring every other plane in this codebase.
# ---------------------------------------------------------------------------

def user_create(
    api: PbsBackend,
    userid: str,
    comment: str | None = None,
    email: str | None = None,
    enable: bool | None = None,
    expire: int | None = None,
    firstname: str | None = None,
    lastname: str | None = None,
    password: str | None = None,
) -> object:
    """POST /access/users — create a user.

    `password` is OPTIONAL (PBS also lets you set one later via PUT /access/password) — a real
    credential when supplied; UNCONDITIONALLY redacted at the server layer, never written to any
    plan/ledger surface. Returns None on success.

    Smoke-confirm: the minimum password length PBS actually enforces server-side (schema says 8).
    """
    userid = _check_userid(userid)
    data: dict = {
        "userid": userid,
        **_user_fields(comment, email, enable, expire, firstname, lastname),
    }
    if password is not None:
        data["password"] = str(password)
    return api._post("/access/users", data)


def user_update(
    api: PbsBackend,
    userid: str,
    comment: str | None = None,
    email: str | None = None,
    enable: bool | None = None,
    expire: int | None = None,
    firstname: str | None = None,
    lastname: str | None = None,
    delete_props: list[str] | None = None,
    digest: str | None = None,
) -> object:
    """PUT /access/users/{userid} — update user config.

    NOTE: PBS's own 'password' PUT param is documented as IGNORED ("This parameter is ignored,
    please use 'PUT /access/password' to change a user's password") — deliberately NOT exposed
    here; a working-looking no-op parameter would mislead a caller into thinking it changed the
    password. `delete_props`: property names to clear (comment/firstname/lastname/email).
    """
    userid = _check_userid(userid)
    data: dict = _user_fields(comment, email, enable, expire, firstname, lastname)
    if delete_props is not None:
        data["delete"] = _join_delete_props(delete_props)
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/access/users/{userid}", data or None)


def user_delete(api: PbsBackend, userid: str, digest: str | None = None) -> object:
    """DELETE /access/users/{userid} — remove a user. Permanent — no undo."""
    userid = _check_userid(userid)
    params: dict = {}
    digest = _check_digest(digest)
    if digest is not None:
        params["digest"] = digest
    return api._delete(f"/access/users/{userid}", params=params or None)


# ---------------------------------------------------------------------------
# Backend functions — API tokens (read)
# ---------------------------------------------------------------------------

def user_tokens_list(api: PbsBackend, userid: str) -> list[dict]:
    """GET /access/users/{userid}/token — list a user's API tokens. No secret is ever returned
    by this endpoint — shown ONCE at creation (token_create) or regeneration (token_update)."""
    userid = _check_userid(userid)
    return api._get(f"/access/users/{userid}/token") or []


def user_token_get(api: PbsBackend, userid: str, token_name: str) -> dict:
    """GET /access/users/{userid}/token/{token-name} — one token's metadata (comment/enable/
    expire/token-name/tokenid; no secret)."""
    userid = _check_userid(userid)
    token_name = _check_tokenname(token_name)
    return api._get(f"/access/users/{userid}/token/{token_name}") or {}


# ---------------------------------------------------------------------------
# Backend functions — API tokens (mutation)
# ---------------------------------------------------------------------------

def token_create(
    api: PbsBackend,
    userid: str,
    token_name: str,
    comment: str | None = None,
    enable: bool | None = None,
    expire: int | None = None,
    digest: str | None = None,
) -> dict:
    """POST /access/users/{userid}/token/{token-name} — create an API token.

    Returns {"tokenid": str, "value": str} — 'value' is the SECRET, shown ONCE and never
    retrievable again. MUST NEVER be written to the audit ledger; the server-layer wrapper
    enforces this by never putting it in the `detail=` dict passed to `_audited()`.

    PBS has NO privsep-equivalent parameter on this endpoint (unlike PVE's token_create) — a
    PBS API token's privileges come entirely from its OWN ACL grants (pbs_acl_update with
    auth_id='user@realm!token-name'); there is no "inherit all owner permissions" toggle to
    invent here.
    """
    userid = _check_userid(userid)
    token_name = _check_tokenname(token_name)
    data: dict = {}
    if comment is not None:
        data["comment"] = comment
    if enable is not None:
        data["enable"] = enable
    if expire is not None:
        data["expire"] = int(expire)
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    result = api._post(f"/access/users/{userid}/token/{token_name}", data or None)
    return result or {}


def token_update(
    api: PbsBackend,
    userid: str,
    token_name: str,
    comment: str | None = None,
    enable: bool | None = None,
    expire: int | None = None,
    regenerate: bool = False,
    delete_props: list[str] | None = None,
    digest: str | None = None,
) -> object:
    """PUT /access/users/{userid}/token/{token-name} — update token metadata.

    regenerate=True issues a BRAND-NEW secret and invalidates the old one immediately — the
    return then carries {"secret": str}, a SECOND secret-bearing shape on this plane (same
    never-in-ledger contract as token_create's 'value'). Returns None when regenerate=False.
    """
    userid = _check_userid(userid)
    token_name = _check_tokenname(token_name)
    data: dict = {}
    if comment is not None:
        data["comment"] = comment
    if enable is not None:
        data["enable"] = enable
    if expire is not None:
        data["expire"] = int(expire)
    if regenerate:
        data["regenerate"] = True
    if delete_props is not None:
        data["delete"] = _join_delete_props(delete_props)
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/access/users/{userid}/token/{token_name}", data or None)


def token_delete(api: PbsBackend, userid: str, token_name: str, digest: str | None = None) -> object:
    """DELETE /access/users/{userid}/token/{token-name} — revoke (permanently delete) a token.
    IRREVERSIBLE: the secret is gone forever; any integration using it loses access immediately.
    """
    userid = _check_userid(userid)
    token_name = _check_tokenname(token_name)
    params: dict = {}
    digest = _check_digest(digest)
    if digest is not None:
        params["digest"] = digest
    return api._delete(f"/access/users/{userid}/token/{token_name}", params=params or None)


# ---------------------------------------------------------------------------
# Backend functions — ACL / roles / permissions
# ---------------------------------------------------------------------------

def acl_get(api: PbsBackend, path: str | None = None, exact: bool | None = None) -> list[dict]:
    """GET /access/acl — read ACL entries (path/propagate/roleid/ugid/ugid_type), optionally
    filtered to one path (exact=True restricts to an exact-path match, not the subtree)."""
    params: dict = {}
    if path is not None:
        params["path"] = _check_acl_path(path)
    if exact is not None:
        params["exact"] = exact
    return api._get("/access/acl", params=params or None) or []


def acl_update(
    api: PbsBackend,
    path: str,
    role: str,
    auth_id: str | None = None,
    group: str | None = None,
    propagate: bool | None = None,
    delete: bool = False,
    digest: str | None = None,
) -> object:
    """PUT /access/acl — grant (delete=False) or revoke (delete=True) ONE role for ONE
    principal at `path`. Exactly one of auth_id/group must be given (PBS's ACL entry names
    either a user/token principal via auth_id — including 'user@realm!token-name' for a token
    principal — or a group via group).

    Returns None (synchronous — no UPID). MUTATION — confirm-gated + audited at the server layer.
    """
    path = _check_acl_path(path)
    role = _check_roleid(role)
    auth_id, group = _check_acl_principal(auth_id, group)
    data: dict = {"path": path, "role": role}
    if auth_id is not None:
        data["auth-id"] = auth_id
    if group is not None:
        data["group"] = group
    if propagate is not None:
        data["propagate"] = propagate
    if delete:
        data["delete"] = True
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put("/access/acl", data)


def roles_list(api: PbsBackend) -> list[dict]:
    """GET /access/roles — list PBS's built-in roles (roleid, privs, comment). PBS roles are a
    FIXED enum — no create/update/delete endpoint exists in the PBS API (unlike PVE's custom
    roles), so this plane exposes read-only."""
    return api._get("/access/roles") or []


def permissions_get(
    api: PbsBackend, auth_id: str | None = None, path: str | None = None,
) -> dict:
    """GET /access/permissions — resolved effective privileges for `auth_id` (or the calling
    token/user if omitted), optionally scoped to one ACL path. Returns a map of ACL path to a
    map of privilege to propagate-bit."""
    params: dict = {}
    if auth_id is not None:
        params["auth-id"] = _check_authid(auth_id)
    if path is not None:
        params["path"] = _check_acl_path(path)
    return api._get("/access/permissions", params=params or None) or {}


# ---------------------------------------------------------------------------
# Plan functions — pure analysis (or CAPTURE-or-declare where a cheap safe read adds honest
# context); return a Plan the caller can inspect. Never self-gate.
# ---------------------------------------------------------------------------

def plan_user_create(
    userid: str,
    comment: str | None = None,
    email: str | None = None,
    enable: bool | None = None,
    expire: int | None = None,
    firstname: str | None = None,
    lastname: str | None = None,
) -> Plan:
    """Preview creating a PBS user. PURE — no API call.

    Deliberately takes NO password parameter — the plan factory never receives the secret at
    all (same discipline as pbs_config.py's plan_remote_create). The server-layer wrapper adds
    the redacted {"password": "[redacted]"} marker itself, from the caller's own knowledge of
    whether a password was passed, without ever routing the real value through this function.

    RISK_MEDIUM: creates a new credential-holder in the access-control system.
    """
    userid = _check_userid(userid)
    fields = _user_fields(comment, email, enable, expire, firstname, lastname)
    blast = [f"creates PBS user {userid!r}" + (f" with {fields}" if fields else " (no optional fields set)")]
    if enable is False:
        blast.append(f"user {userid!r} is created DISABLED (enable=False) — cannot log in until enabled")
    return Plan(
        action="pbs_user_create",
        target=f"pbs/access/users/{userid}",
        change=f"create PBS user {userid!r}: {fields}",
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["creates a new principal in the PBS access-control system"],
        note="an optional password, if supplied, is redacted from every plan/ledger surface — it never appears here",
    )


def plan_user_update(
    api: PbsBackend,
    userid: str,
    comment: str | None = None,
    email: str | None = None,
    enable: bool | None = None,
    expire: int | None = None,
    firstname: str | None = None,
    lastname: str | None = None,
    delete_props: list[str] | None = None,
) -> Plan:
    """Preview updating a PBS user config. CAPTURE-or-declare.

    CAPTURE: reads GET /access/users/{userid} -> plan.current; on failure -> complete=False.
    RISK_MEDIUM. enable=False is called out explicitly in the blast radius (stops login).
    """
    userid = _check_userid(userid)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = user_get(api, userid)
    except Exception:
        complete = False
        note_capture = " Could not capture current user config — no guided revert available."

    fields = _user_fields(comment, email, enable, expire, firstname, lastname)
    blast = [f"updates PBS user {userid!r}: {fields}"]
    if enable is False:
        blast.append(f"enable=False STOPS LOGIN for {userid!r} immediately")
    if delete_props:
        blast.append(f"clears properties {list(delete_props)!r} from {userid!r}")

    return Plan(
        action="pbs_user_update",
        target=f"pbs/access/users/{userid}",
        change=f"update PBS user {userid!r}: {fields}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["changes an existing principal's account state (login, contact, expiry)"],
        complete=complete,
        note="revert by re-applying the captured config with pbs_user_update." + note_capture,
    )


def plan_user_delete(api: PbsBackend, userid: str) -> Plan:
    """Preview deleting a PBS user. CAPTURE-or-declare.

    CAPTURE: reads GET /access/users/{userid} -> plan.current (best-effort — a failed read
    still lets the delete plan proceed, just less informative); best-effort reads the user's
    tokens too, so the blast radius names what else vanishes with the account.

    RISK_MEDIUM. Permanent — no undo. Any tokens owned by this user are removed with it, and any
    ACL entries granted directly to this userid become orphaned (they no longer resolve to
    anyone).
    """
    userid = _check_userid(userid)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = user_get(api, userid)
    except Exception:
        complete = False
        note_capture = " Could not read current user config."

    token_count_note = ""
    try:
        tokens = user_tokens_list(api, userid)
        if tokens:
            token_count_note = f" — {len(tokens)} API token(s) owned by this user are removed with it"
    except Exception:
        complete = False
        note_capture += " Could not read the user's tokens — token-loss extent unknown."

    return Plan(
        action="pbs_user_delete",
        target=f"pbs/access/users/{userid}",
        change=f"delete PBS user {userid!r}",
        current=current,
        blast_radius=[
            f"PERMANENTLY removes PBS user {userid!r} — no undo" + token_count_note,
            f"any ACL entries granted directly to {userid!r} become orphaned",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            f"permanent removal of principal {userid!r} and its owned API tokens",
            "no rollback primitive — recreate with pbs_user_create to recover (tokens cannot be "
            "recovered; new ones must be reissued)",
        ],
        complete=complete,
        note="irreversible; no PBS snapshot primitive applies to access-control state." + note_capture,
    )


def plan_token_create(
    userid: str,
    token_name: str,
    comment: str | None = None,
    enable: bool | None = None,
    expire: int | None = None,
) -> Plan:
    """Preview creating a PBS API token. PURE — no API call.

    PBS has no privsep toggle (see token_create's docstring) — a created token's privileges
    come entirely from ACL grants made to it afterward (pbs_acl_update). RISK_MEDIUM: creates a
    credential; the secret cannot be retrieved after creation (only regenerated, which
    invalidates it — pbs_token_update with regenerate=True).

    expire is an ABSOLUTE UNIX timestamp (seconds since epoch), NOT a TTL/duration — mirrors the
    same honesty check already proven for pve_token_create (a duration-shaped value like 86400
    is a date in Jan 1970, already expired).
    """
    userid = _check_userid(userid)
    token_name = _check_tokenname(token_name)

    blast = [
        f"creates token {userid}!{token_name}",
        "the token secret value will be shown ONCE at creation; it cannot be retrieved again "
        "(only regenerated via pbs_token_update, which invalidates the old secret)",
        "the new token has NO privileges until an ACL entry grants it some "
        "(pbs_acl_update with auth_id=f'{userid}!{token_name}')",
    ]

    if not expire:
        blast.append(
            f"token {userid}!{token_name} has NO expiration (expire={expire!r}) — it never "
            "expires; set expire to an absolute UNIX timestamp (seconds since epoch) in the "
            "future for a limited lifetime — it is a DATE, not a duration/TTL"
        )
        expire_desc = "never"
    else:
        expire_desc = str(expire)
        try:
            _e = int(expire)
        except (TypeError, ValueError):
            _e = None
        if _e is not None and 0 < _e < 1_000_000_000:
            blast.append(
                f"WARNING: expire={expire!r} looks like a TTL/duration, but PBS treats it as an "
                "ABSOLUTE UNIX timestamp (seconds since epoch) — this token would be created "
                "ALREADY EXPIRED (a date in the past). Use a future epoch timestamp instead."
            )

    change = f"create token {userid}!{token_name} (expire={expire_desc})"
    if comment:
        change += f", comment={comment!r}"

    return Plan(
        action="pbs_token_create",
        target=f"pbs/access/users/{userid}/token/{token_name}",
        change=change,
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["creates a credential — token secrets cannot be retrieved after creation"],
        note="the token secret is NOT in this plan (it doesn't exist yet) — it surfaces once in the creation result",
    )


def plan_token_update(
    userid: str,
    token_name: str,
    comment: str | None = None,
    enable: bool | None = None,
    expire: int | None = None,
    regenerate: bool = False,
    delete_props: list[str] | None = None,
) -> Plan:
    """Preview updating a PBS API token. PURE — no API call.

    RISK IS CONDITIONAL ON regenerate:
      regenerate=False -> RISK_MEDIUM: metadata-only change (comment/enable/expire/delete_props).
      regenerate=True  -> RISK_HIGH: issues a BRAND-NEW secret and invalidates the OLD one
        immediately — any system using the current token loses access the moment this executes,
        with no warning beyond this plan. The new secret then surfaces ONCE in the result (same
        never-in-ledger contract as token_create).
    """
    userid = _check_userid(userid)
    token_name = _check_tokenname(token_name)

    blast = [f"updates token {userid}!{token_name} metadata"]
    if enable is False:
        blast.append(f"enable=False disables token {userid}!{token_name} immediately")
    if delete_props:
        blast.append(f"clears properties {list(delete_props)!r} from the token")

    if regenerate:
        risk = RISK_HIGH
        blast.append(
            f"regenerate=True issues a BRAND-NEW secret for {userid}!{token_name} and "
            "invalidates the OLD secret IMMEDIATELY — any system currently using this token "
            "loses access the instant this executes; the new secret surfaces ONCE in the result "
            "and is never written to the audit ledger"
        )
        reasons = [
            "regenerate=True invalidates the current secret immediately — a real outage for any "
            "integration still using it, with no grace period",
        ]
    else:
        risk = RISK_MEDIUM
        reasons = ["metadata-only change (comment/enable/expire/properties) — the secret is unchanged"]

    return Plan(
        action="pbs_token_update",
        target=f"pbs/access/users/{userid}/token/{token_name}",
        change=f"update token {userid}!{token_name} (regenerate={regenerate})",
        current={},
        blast_radius=blast,
        risk=risk,
        risk_reasons=reasons,
        note="a regenerated secret (if any) is NOT in this plan — it surfaces once in the execute result",
    )


def plan_token_delete(userid: str, token_name: str) -> Plan:
    """Preview revoking (deleting) a PBS API token. PURE — no API call.

    RISK_MEDIUM: revocation is IRREVERSIBLE — the secret is permanently gone and any system or
    integration using this token loses PBS API access immediately. No undo; issue a new token
    (pbs_token_create) to replace it.
    """
    userid = _check_userid(userid)
    token_name = _check_tokenname(token_name)
    return Plan(
        action="pbs_token_delete",
        target=f"pbs/access/users/{userid}/token/{token_name}",
        change=f"revoke (permanently delete) token {userid}!{token_name}",
        current={},
        blast_radius=[
            f"PERMANENTLY revokes token {userid}!{token_name} — the secret is gone forever, no undo",
            "any service or integration using this token loses PBS API access immediately",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "token revocation is permanent — the secret cannot be recovered or reissued",
            "downstream systems using this token lose access immediately and irrecoverably",
        ],
    )


def plan_acl_update(
    api: PbsBackend,
    path: str,
    role: str,
    auth_id: str | None = None,
    group: str | None = None,
    propagate: bool | None = None,
    delete: bool = False,
) -> Plan:
    """Preview granting or revoking a PBS ACL entry. CAPTURE-or-declare.

    RISK IS ALWAYS HIGH: an ACL change grants or revokes authority — the campaign's own Wave 2a
    risk table pins this flat (unlike PVE's plan_acl_modify, which only escalates HIGH on
    Administrator/root-path/shadow — PBS's shadow/widen inheritance behavior is NOT
    schema-documented and has not been live-verified on this plane, so this module does not
    attempt PVE's shadow/widen resolver; every ACL change here is HIGH, full stop, rather than
    silently under-flagging one PBS doesn't document the same way).

    CAPTURE: best-effort reads GET /access/acl?path=<path>&exact=true -> plan.current (the
    entries currently AT this exact path, for context); a failed read does not block the plan
    but sets complete=False.
    """
    path = _check_acl_path(path)
    role = _check_roleid(role)
    auth_id, group = _check_acl_principal(auth_id, group)
    principal = auth_id if auth_id is not None else f"group:{group}"

    current: list[dict] = []
    complete = True
    note_capture = ""
    try:
        current = acl_get(api, path=path, exact=True)
    except Exception:
        complete = False
        note_capture = " Could not read current ACL entries at this path."

    verb = "revokes" if delete else "grants"
    change = f"{verb} role {role!r} {'from' if delete else 'to'} {principal!r} at path {path!r}"

    return Plan(
        action="pbs_acl_update",
        target=f"pbs/access/acl:{path}:{principal}",
        change=change,
        current={"entries_at_path": current},
        blast_radius=[
            f"{'REVOKES' if delete else 'GRANTS'} role {role!r} {'from' if delete else 'to'} "
            f"{principal!r} at {path!r} — this changes what {principal!r} is authorized to do "
            "on the PBS server",
            "propagate="
            + (str(propagate) if propagate is not None else "PBS default (true)")
            + " controls whether the change also applies to everything under this path",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "every ACL change grants or revokes authority — treated as HIGH unconditionally on "
            "this plane (PBS's inheritance/shadow semantics are not live-verified here)",
        ],
        complete=complete,
        note="no rollback primitive — revert with a second pbs_acl_update call (grant<->revoke)." + note_capture,
    )


# ---------------------------------------------------------------------------
# Backend functions — realms: AD (Wave 2b)
# ---------------------------------------------------------------------------

def realm_ad_list(api: PbsBackend) -> list[dict]:
    """GET /config/access/ad — list configured AD realms."""
    return api._get("/config/access/ad") or []


def realm_ad_get(api: PbsBackend, realm: str) -> dict:
    """GET /config/access/ad/{realm} — read one AD realm's config."""
    realm = _check_realm(realm)
    return api._get(f"/config/access/ad/{realm}") or {}


def realm_ad_create(
    api: PbsBackend,
    realm: str,
    server1: str,
    base_dn: str | None = None,
    bind_dn: str | None = None,
    capath: str | None = None,
    comment: str | None = None,
    default: bool | None = None,
    filter: str | None = None,  # noqa: A002
    mode: str | None = None,
    password: str | None = None,
    port: int | None = None,
    server2: str | None = None,
    sync_attributes: str | None = None,
    sync_defaults_options: str | None = None,
    user_classes: str | None = None,
    verify: bool | None = None,
) -> object:
    """POST /config/access/ad — create an AD realm. `realm` and `server1` are required (per the
    live schema — AD, unlike LDAP, does NOT require base_dn/bind_dn on create). `password` (the
    AD bind password) is a persistent credential — UNCONDITIONALLY redacted at the server layer
    (see _password_redacted_detail), never written to any plan/ledger surface."""
    realm = _check_realm(realm)
    data: dict = {
        "realm": realm,
        "server1": server1,
        **_realm_directory_fields(
            comment=comment, default=default, filter=filter, mode=mode, port=port,
            server2=server2, sync_attributes=sync_attributes,
            sync_defaults_options=sync_defaults_options, user_classes=user_classes,
            verify=verify, base_dn=base_dn, bind_dn=bind_dn, capath=capath,
        ),
    }
    if password is not None:
        data["password"] = str(password)
    return api._post("/config/access/ad", data)


def realm_ad_update(
    api: PbsBackend,
    realm: str,
    base_dn: str | None = None,
    bind_dn: str | None = None,
    capath: str | None = None,
    comment: str | None = None,
    default: bool | None = None,
    filter: str | None = None,  # noqa: A002
    mode: str | None = None,
    password: str | None = None,
    port: int | None = None,
    server1: str | None = None,
    server2: str | None = None,
    sync_attributes: str | None = None,
    sync_defaults_options: str | None = None,
    user_classes: str | None = None,
    verify: bool | None = None,
    delete_props: list[str] | None = None,
    digest: str | None = None,
) -> object:
    """PUT /config/access/ad/{realm} — update an AD realm's config."""
    realm = _check_realm(realm)
    data: dict = _realm_directory_fields(
        comment=comment, default=default, filter=filter, mode=mode, port=port,
        server2=server2, sync_attributes=sync_attributes,
        sync_defaults_options=sync_defaults_options, user_classes=user_classes,
        verify=verify, base_dn=base_dn, bind_dn=bind_dn, capath=capath,
    )
    if server1 is not None:
        data["server1"] = server1
    if password is not None:
        data["password"] = str(password)
    if delete_props is not None:
        data["delete"] = _join_delete_props(delete_props)
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/config/access/ad/{realm}", data or None)


def realm_ad_delete(api: PbsBackend, realm: str, digest: str | None = None) -> object:
    """DELETE /config/access/ad/{realm} — remove an AD realm. Permanent."""
    realm = _check_realm(realm)
    params: dict = {}
    digest = _check_digest(digest)
    if digest is not None:
        params["digest"] = digest
    return api._delete(f"/config/access/ad/{realm}", params=params or None)


# ---------------------------------------------------------------------------
# Backend functions — realms: LDAP (Wave 2b). Same shape as AD, but base_dn + user_attr are
# REQUIRED on create (AD requires neither).
# ---------------------------------------------------------------------------

def realm_ldap_list(api: PbsBackend) -> list[dict]:
    """GET /config/access/ldap — list configured LDAP realms."""
    return api._get("/config/access/ldap") or []


def realm_ldap_get(api: PbsBackend, realm: str) -> dict:
    """GET /config/access/ldap/{realm} — read one LDAP realm's config."""
    realm = _check_realm(realm)
    return api._get(f"/config/access/ldap/{realm}") or {}


def realm_ldap_create(
    api: PbsBackend,
    realm: str,
    server1: str,
    base_dn: str,
    user_attr: str,
    bind_dn: str | None = None,
    capath: str | None = None,
    comment: str | None = None,
    default: bool | None = None,
    filter: str | None = None,  # noqa: A002
    mode: str | None = None,
    password: str | None = None,
    port: int | None = None,
    server2: str | None = None,
    sync_attributes: str | None = None,
    sync_defaults_options: str | None = None,
    user_classes: str | None = None,
    verify: bool | None = None,
) -> object:
    """POST /config/access/ldap — create an LDAP realm. `realm`, `server1`, `base_dn`, and
    `user_attr` are ALL required (per the live schema — LDAP, unlike AD, requires both directory
    fields up front). `password` (the LDAP bind password) is redacted identically to AD's."""
    realm = _check_realm(realm)
    data: dict = {
        "realm": realm,
        "server1": server1,
        "user-attr": user_attr,
        **_realm_directory_fields(
            comment=comment, default=default, filter=filter, mode=mode, port=port,
            server2=server2, sync_attributes=sync_attributes,
            sync_defaults_options=sync_defaults_options, user_classes=user_classes,
            verify=verify, base_dn=base_dn, bind_dn=bind_dn, capath=capath,
        ),
    }
    if password is not None:
        data["password"] = str(password)
    return api._post("/config/access/ldap", data)


def realm_ldap_update(
    api: PbsBackend,
    realm: str,
    base_dn: str | None = None,
    bind_dn: str | None = None,
    capath: str | None = None,
    comment: str | None = None,
    default: bool | None = None,
    filter: str | None = None,  # noqa: A002
    mode: str | None = None,
    password: str | None = None,
    port: int | None = None,
    server1: str | None = None,
    server2: str | None = None,
    sync_attributes: str | None = None,
    sync_defaults_options: str | None = None,
    user_attr: str | None = None,
    user_classes: str | None = None,
    verify: bool | None = None,
    delete_props: list[str] | None = None,
    digest: str | None = None,
) -> object:
    """PUT /config/access/ldap/{realm} — update an LDAP realm's config. base_dn/user_attr are
    OPTIONAL here (unlike create) — omit to leave unchanged."""
    realm = _check_realm(realm)
    data: dict = _realm_directory_fields(
        comment=comment, default=default, filter=filter, mode=mode, port=port,
        server2=server2, sync_attributes=sync_attributes,
        sync_defaults_options=sync_defaults_options, user_classes=user_classes,
        verify=verify, base_dn=base_dn, bind_dn=bind_dn, capath=capath,
    )
    if server1 is not None:
        data["server1"] = server1
    if user_attr is not None:
        data["user-attr"] = user_attr
    if password is not None:
        data["password"] = str(password)
    if delete_props is not None:
        data["delete"] = _join_delete_props(delete_props)
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/config/access/ldap/{realm}", data or None)


def realm_ldap_delete(api: PbsBackend, realm: str, digest: str | None = None) -> object:
    """DELETE /config/access/ldap/{realm} — remove an LDAP realm. Permanent."""
    realm = _check_realm(realm)
    params: dict = {}
    digest = _check_digest(digest)
    if digest is not None:
        params["digest"] = digest
    return api._delete(f"/config/access/ldap/{realm}", params=params or None)


# ---------------------------------------------------------------------------
# Backend functions — realms: OpenID (Wave 2b)
# ---------------------------------------------------------------------------

def realm_openid_list(api: PbsBackend) -> list[dict]:
    """GET /config/access/openid — list configured OpenID realms."""
    return api._get("/config/access/openid") or []


def realm_openid_get(api: PbsBackend, realm: str) -> dict:
    """GET /config/access/openid/{realm} — read one OpenID realm's config."""
    realm = _check_realm(realm)
    return api._get(f"/config/access/openid/{realm}") or {}


def realm_openid_create(
    api: PbsBackend,
    realm: str,
    issuer_url: str,
    client_id: str,
    client_key: str | None = None,
    comment: str | None = None,
    default: bool | None = None,
    acr_values: str | None = None,
    audiences: str | None = None,
    autocreate: bool | None = None,
    prompt: str | None = None,
    scopes: str | None = None,
    username_claim: str | None = None,
) -> object:
    """POST /config/access/openid — create an OpenID realm. `realm`, `issuer_url`, `client_id`
    are required. `client_key` (the OAuth client secret) is redacted at the server layer via
    _client_key_redacted_detail — never written to any plan/ledger surface."""
    realm = _check_realm(realm)
    data: dict = {
        "realm": realm,
        "issuer-url": issuer_url,
        "client-id": client_id,
        **_openid_fields(
            comment=comment, default=default, acr_values=acr_values, audiences=audiences,
            autocreate=autocreate, prompt=prompt, scopes=scopes,
        ),
    }
    # username-claim is CREATE-ONLY (see _openid_fields' note) — added here, not on the update path.
    if username_claim is not None:
        data["username-claim"] = username_claim
    if client_key is not None:
        data["client-key"] = str(client_key)
    return api._post("/config/access/openid", data)


def realm_openid_update(
    api: PbsBackend,
    realm: str,
    issuer_url: str | None = None,
    client_id: str | None = None,
    client_key: str | None = None,
    comment: str | None = None,
    default: bool | None = None,
    acr_values: str | None = None,
    audiences: str | None = None,
    autocreate: bool | None = None,
    prompt: str | None = None,
    scopes: str | None = None,
    delete_props: list[str] | None = None,
    digest: str | None = None,
) -> object:
    """PUT /config/access/openid/{realm} — update an OpenID realm's config. issuer_url/client_id
    are OPTIONAL here (unlike create) — omit to leave unchanged. NOTE: `username_claim` is NOT
    accepted here — the live schema makes it create-only, and PUT is additionalProperties:false,
    so sending it would hard-fail the whole request (see _openid_fields' note)."""
    realm = _check_realm(realm)
    data: dict = _openid_fields(
        comment=comment, default=default, acr_values=acr_values, audiences=audiences,
        autocreate=autocreate, prompt=prompt, scopes=scopes,
    )
    if issuer_url is not None:
        data["issuer-url"] = issuer_url
    if client_id is not None:
        data["client-id"] = client_id
    if client_key is not None:
        data["client-key"] = str(client_key)
    if delete_props is not None:
        data["delete"] = _join_delete_props(delete_props)
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/config/access/openid/{realm}", data or None)


def realm_openid_delete(api: PbsBackend, realm: str, digest: str | None = None) -> object:
    """DELETE /config/access/openid/{realm} — remove an OpenID realm. Permanent."""
    realm = _check_realm(realm)
    params: dict = {}
    digest = _check_digest(digest)
    if digest is not None:
        params["digest"] = digest
    return api._delete(f"/config/access/openid/{realm}", params=params or None)


# ---------------------------------------------------------------------------
# Backend functions — realms: PAM / PBS built-in (Wave 2b). GET/PUT only — no create/delete
# endpoint exists for either (fixed built-in realms).
# ---------------------------------------------------------------------------

def realm_pam_get(api: PbsBackend) -> dict:
    """GET /config/access/pam — read the built-in PAM realm config (comment/default only)."""
    return api._get("/config/access/pam") or {}


def realm_pam_set(
    api: PbsBackend,
    comment: str | None = None,
    default: bool | None = None,
    delete_props: list[str] | None = None,
    digest: str | None = None,
) -> object:
    """PUT /config/access/pam — update the built-in PAM realm's comment/default flag."""
    data: dict = _realm_singleton_fields(comment, default)
    if delete_props is not None:
        data["delete"] = _join_delete_props(delete_props)
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put("/config/access/pam", data or None)


def realm_pbs_get(api: PbsBackend) -> dict:
    """GET /config/access/pbs — read the built-in PBS-auth realm config (comment/default only)."""
    return api._get("/config/access/pbs") or {}


def realm_pbs_set(
    api: PbsBackend,
    comment: str | None = None,
    default: bool | None = None,
    delete_props: list[str] | None = None,
    digest: str | None = None,
) -> object:
    """PUT /config/access/pbs — update the built-in PBS-auth realm's comment/default flag."""
    data: dict = _realm_singleton_fields(comment, default)
    if delete_props is not None:
        data["delete"] = _join_delete_props(delete_props)
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put("/config/access/pbs", data or None)


# ---------------------------------------------------------------------------
# Backend functions — TFA (Wave 2b)
# ---------------------------------------------------------------------------

def tfa_list(api: PbsBackend) -> list[dict]:
    """GET /access/tfa — list ALL users' TFA configuration (per-user entries + lock state)."""
    return api._get("/access/tfa") or []


def tfa_user_get(api: PbsBackend, userid: str) -> list[dict]:
    """GET /access/tfa/{userid} — list ONE user's TFA entries.

    Smoke-confirm: PBS's own apidoc labels this GET's description "Add a TOTP secret to the
    user" (see module docstring) — treated here as a list read, matching the documented return
    shape ("the list of TFA entries"), not the (almost certainly copy/pasted) label.
    """
    userid = _check_userid(userid)
    return api._get(f"/access/tfa/{userid}") or []


def tfa_add(
    api: PbsBackend,
    userid: str,
    tfa_type: str,
    description: str | None = None,
    password: str | None = None,
    totp: str | None = None,
    value: str | None = None,
    challenge: str | None = None,
) -> dict:
    """POST /access/tfa/{userid} — add a TFA entry.

    `tfa_type`: one of totp/u2f/webauthn/recovery/yubico. `totp`/`value`/`challenge` carry the
    type-specific registration payload (e.g. for totp: `totp` is the URI the CALLER generated,
    `value` is the current code proving it's correctly configured; PBS does not generate the
    TOTP secret server-side on this endpoint — the caller already holds it).

    SECRET-BEARING RESPONSE: for tfa_type='recovery', the result carries
    `{"recovery": [<one-time codes>], ...}` — SERVER-GENERATED secret material, shown ONCE and
    never retrievable again. `password` (the acting user's own current password, used to
    re-authenticate this change) is UNCONDITIONALLY redacted at the server layer via
    _password_redacted_detail; the response's 'recovery'/'challenge'/'id' fields are never
    written to the audit ledger — see tools/pbs_access.py's SECRET HANDLING comment.
    """
    userid = _check_userid(userid)
    tfa_type = _check_tfa_type(tfa_type)
    data: dict = {"type": tfa_type}
    if description is not None:
        data["description"] = description
    if password is not None:
        data["password"] = str(password)
    if totp is not None:
        data["totp"] = totp
    if value is not None:
        data["value"] = value
    if challenge is not None:
        data["challenge"] = challenge
    result = api._post(f"/access/tfa/{userid}", data)
    return result or {}


def tfa_entry_get(api: PbsBackend, userid: str, tfa_id: str) -> object:
    """GET /access/tfa/{userid}/{id} — read a single TFA entry.

    Smoke-confirm: PBS's own apidoc documents this GET's return type as literally `null` (see
    module docstring) — an untyped passthrough of whatever PBS actually returns.
    """
    userid = _check_userid(userid)
    tfa_id = _check_tfa_id(tfa_id)
    return api._get(f"/access/tfa/{userid}/{tfa_id}")


def tfa_update(
    api: PbsBackend,
    userid: str,
    tfa_id: str,
    description: str | None = None,
    enable: bool | None = None,
    password: str | None = None,
) -> object:
    """PUT /access/tfa/{userid}/{id} — update a TFA entry's description/enabled flag.
    `password` is redacted identically to tfa_add's (the acting user's own current password)."""
    userid = _check_userid(userid)
    tfa_id = _check_tfa_id(tfa_id)
    data: dict = {}
    if description is not None:
        data["description"] = description
    if enable is not None:
        data["enable"] = enable
    if password is not None:
        data["password"] = str(password)
    return api._put(f"/access/tfa/{userid}/{tfa_id}", data or None)


def tfa_delete(api: PbsBackend, userid: str, tfa_id: str, password: str | None = None) -> object:
    """DELETE /access/tfa/{userid}/{id} — permanently remove one TFA factor.
    `password` is redacted identically to tfa_add's."""
    userid = _check_userid(userid)
    tfa_id = _check_tfa_id(tfa_id)
    params: dict = {}
    if password is not None:
        params["password"] = str(password)
    return api._delete(f"/access/tfa/{userid}/{tfa_id}", params=params or None)


def tfa_unlock(api: PbsBackend, userid: str) -> bool:
    """PUT /access/users/{userid}/unlock-tfa — clear a TOTP lockout for `userid`.

    NOTE the path: this lives under /access/users/, NOT /access/tfa/{userid}/ — confirmed from
    the live schema (see module docstring). Returns whether the user was previously locked out.
    """
    userid = _check_userid(userid)
    return bool(api._put(f"/access/users/{userid}/unlock-tfa"))


def tfa_webauthn_get(api: PbsBackend) -> dict:
    """GET /config/access/tfa/webauthn — read the server-wide WebAuthn relying-party config."""
    return api._get("/config/access/tfa/webauthn") or {}


def tfa_webauthn_set(
    api: PbsBackend,
    rp_id: str | None = None,
    origin: str | None = None,
    rp_name: str | None = None,
    allow_subdomains: bool | None = None,
    delete_props: list[str] | None = None,
    digest: str | None = None,
) -> object:
    """PUT /config/access/tfa/webauthn — update the server-wide WebAuthn config.

    `rp_id` (wire 'id') and `origin` changes MAY break EVERY existing WebAuthn credential on the
    server (per the schema's own field descriptions) — see plan_tfa_webauthn_set's blast radius.
    """
    data: dict = {}
    if rp_id is not None:
        data["id"] = rp_id
    if origin is not None:
        data["origin"] = origin
    if rp_name is not None:
        data["rp"] = rp_name
    if allow_subdomains is not None:
        data["allow-subdomains"] = allow_subdomains
    if delete_props is not None:
        data["delete"] = _join_delete_props(delete_props)
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put("/config/access/tfa/webauthn", data or None)


# ---------------------------------------------------------------------------
# Plan functions — realms: AD (Wave 2b)
# ---------------------------------------------------------------------------

def plan_realm_ad_create(realm: str, server1: str, **fields) -> Plan:
    """Preview creating an AD realm. PURE — no API call. RISK_MEDIUM: adds a new auth source; a
    misconfigured realm can let unintended principals authenticate, or none at all if broken.
    Deliberately takes NO password parameter (see plan_user_create's identical discipline)."""
    realm = _check_realm(realm)
    return Plan(
        action="pbs_realm_ad_create",
        target=f"pbs/config/access/ad/{realm}",
        change=f"create AD realm {realm!r} (server1={server1!r}){f' with {fields}' if fields else ''}",
        current={},
        blast_radius=[
            f"adds AD auth realm {realm!r} (server1={server1!r}) to the PBS server",
            "a misconfigured realm can let unintended principals authenticate, or simply fail "
            "to authenticate anyone until fixed",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["adds a new auth source — auth config, not an authority grant by itself"],
        note="an optional bind password, if supplied, is redacted from every plan/ledger "
             "surface — it never appears here",
    )


def plan_realm_ad_update(api: PbsBackend, realm: str, **fields) -> Plan:
    """Preview updating an AD realm. CAPTURE-or-declare. RISK_MEDIUM."""
    realm = _check_realm(realm)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = realm_ad_get(api, realm)
    except Exception:
        complete = False
        note_capture = " Could not capture current AD realm config — no guided revert available."
    return Plan(
        action="pbs_realm_ad_update",
        target=f"pbs/config/access/ad/{realm}",
        change=f"update AD realm {realm!r}: {fields}",
        current=current,
        blast_radius=[f"updates AD realm {realm!r} connection/sync settings"],
        risk=RISK_MEDIUM,
        risk_reasons=["changes an existing auth source's connection/sync settings"],
        complete=complete,
        note="an optional bind password, if supplied, is redacted from every plan/ledger surface." + note_capture,
    )


def plan_realm_ad_delete(api: PbsBackend, realm: str) -> Plan:
    """Preview deleting an AD realm. CAPTURE-or-declare. RISK_MEDIUM: any users who authenticate
    via this realm can no longer log in once it's removed."""
    realm = _check_realm(realm)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = realm_ad_get(api, realm)
    except Exception:
        complete = False
        note_capture = " Could not read current AD realm config."
    return Plan(
        action="pbs_realm_ad_delete",
        target=f"pbs/config/access/ad/{realm}",
        change=f"delete AD realm {realm!r}",
        current=current,
        blast_radius=[
            f"PERMANENTLY removes AD realm {realm!r} — no undo",
            f"any users who authenticate via {realm!r} can no longer log in",
            "Smoke-confirm: whether PBS user records under this realm's namespace "
            f"(userid ending '@{realm}') are also removed or left orphaned",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            f"permanent removal of auth source {realm!r} — users authenticating via it lose login",
            "no rollback primitive — recreate with pbs_realm_ad_create to recover the connection",
        ],
        complete=complete,
        note="irreversible; no PBS snapshot primitive applies to realm config." + note_capture,
    )


# ---------------------------------------------------------------------------
# Plan functions — realms: LDAP (Wave 2b) — same shape as AD.
# ---------------------------------------------------------------------------

def plan_realm_ldap_create(realm: str, server1: str, base_dn: str, user_attr: str, **fields) -> Plan:
    """Preview creating an LDAP realm. PURE — no API call. RISK_MEDIUM."""
    realm = _check_realm(realm)
    return Plan(
        action="pbs_realm_ldap_create",
        target=f"pbs/config/access/ldap/{realm}",
        change=(f"create LDAP realm {realm!r} (server1={server1!r}, base_dn={base_dn!r}, "
                f"user_attr={user_attr!r}){f' with {fields}' if fields else ''}"),
        current={},
        blast_radius=[
            f"adds LDAP auth realm {realm!r} (server1={server1!r}) to the PBS server",
            "a misconfigured realm can let unintended principals authenticate, or simply fail "
            "to authenticate anyone until fixed",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["adds a new auth source — auth config, not an authority grant by itself"],
        note="an optional bind password, if supplied, is redacted from every plan/ledger "
             "surface — it never appears here",
    )


def plan_realm_ldap_update(api: PbsBackend, realm: str, **fields) -> Plan:
    """Preview updating an LDAP realm. CAPTURE-or-declare. RISK_MEDIUM."""
    realm = _check_realm(realm)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = realm_ldap_get(api, realm)
    except Exception:
        complete = False
        note_capture = " Could not capture current LDAP realm config — no guided revert available."
    return Plan(
        action="pbs_realm_ldap_update",
        target=f"pbs/config/access/ldap/{realm}",
        change=f"update LDAP realm {realm!r}: {fields}",
        current=current,
        blast_radius=[f"updates LDAP realm {realm!r} connection/sync settings"],
        risk=RISK_MEDIUM,
        risk_reasons=["changes an existing auth source's connection/sync settings"],
        complete=complete,
        note="an optional bind password, if supplied, is redacted from every plan/ledger surface." + note_capture,
    )


def plan_realm_ldap_delete(api: PbsBackend, realm: str) -> Plan:
    """Preview deleting an LDAP realm. CAPTURE-or-declare. RISK_MEDIUM."""
    realm = _check_realm(realm)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = realm_ldap_get(api, realm)
    except Exception:
        complete = False
        note_capture = " Could not read current LDAP realm config."
    return Plan(
        action="pbs_realm_ldap_delete",
        target=f"pbs/config/access/ldap/{realm}",
        change=f"delete LDAP realm {realm!r}",
        current=current,
        blast_radius=[
            f"PERMANENTLY removes LDAP realm {realm!r} — no undo",
            f"any users who authenticate via {realm!r} can no longer log in",
            "Smoke-confirm: whether PBS user records under this realm's namespace "
            f"(userid ending '@{realm}') are also removed or left orphaned",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            f"permanent removal of auth source {realm!r} — users authenticating via it lose login",
            "no rollback primitive — recreate with pbs_realm_ldap_create to recover the connection",
        ],
        complete=complete,
        note="irreversible; no PBS snapshot primitive applies to realm config." + note_capture,
    )


# ---------------------------------------------------------------------------
# Plan functions — realms: OpenID (Wave 2b)
# ---------------------------------------------------------------------------

def plan_realm_openid_create(realm: str, issuer_url: str, client_id: str, **fields) -> Plan:
    """Preview creating an OpenID realm. PURE — no API call. RISK_MEDIUM. Deliberately takes NO
    client_key parameter (same discipline as plan_user_create's password exclusion)."""
    realm = _check_realm(realm)
    return Plan(
        action="pbs_realm_openid_create",
        target=f"pbs/config/access/openid/{realm}",
        change=(f"create OpenID realm {realm!r} (issuer_url={issuer_url!r}, client_id={client_id!r})"
                f"{f' with {fields}' if fields else ''}"),
        current={},
        blast_radius=[
            f"adds OpenID auth realm {realm!r} (issuer={issuer_url!r}) to the PBS server",
            "a misconfigured realm can let unintended principals authenticate, or simply fail "
            "to authenticate anyone until fixed",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["adds a new auth source — auth config, not an authority grant by itself"],
        note="an optional client_key, if supplied, is redacted from every plan/ledger surface — it never appears here",
    )


def plan_realm_openid_update(api: PbsBackend, realm: str, **fields) -> Plan:
    """Preview updating an OpenID realm. CAPTURE-or-declare. RISK_MEDIUM."""
    realm = _check_realm(realm)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = realm_openid_get(api, realm)
    except Exception:
        complete = False
        note_capture = " Could not capture current OpenID realm config — no guided revert available."
    return Plan(
        action="pbs_realm_openid_update",
        target=f"pbs/config/access/openid/{realm}",
        change=f"update OpenID realm {realm!r}: {fields}",
        current=current,
        blast_radius=[f"updates OpenID realm {realm!r} connection settings"],
        risk=RISK_MEDIUM,
        risk_reasons=["changes an existing auth source's connection settings"],
        complete=complete,
        note="an optional client_key, if supplied, is redacted from every plan/ledger surface." + note_capture,
    )


def plan_realm_openid_delete(api: PbsBackend, realm: str) -> Plan:
    """Preview deleting an OpenID realm. CAPTURE-or-declare. RISK_MEDIUM."""
    realm = _check_realm(realm)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = realm_openid_get(api, realm)
    except Exception:
        complete = False
        note_capture = " Could not read current OpenID realm config."
    return Plan(
        action="pbs_realm_openid_delete",
        target=f"pbs/config/access/openid/{realm}",
        change=f"delete OpenID realm {realm!r}",
        current=current,
        blast_radius=[
            f"PERMANENTLY removes OpenID realm {realm!r} — no undo",
            f"any users who authenticate via {realm!r} can no longer log in",
            "Smoke-confirm: whether PBS user records under this realm's namespace "
            f"(userid ending '@{realm}') are also removed or left orphaned",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            f"permanent removal of auth source {realm!r} — users authenticating via it lose login",
            "no rollback primitive — recreate with pbs_realm_openid_create to recover the connection",
        ],
        complete=complete,
        note="irreversible; no PBS snapshot primitive applies to realm config." + note_capture,
    )


# ---------------------------------------------------------------------------
# Plan functions — realms: PAM / PBS built-in (Wave 2b)
# ---------------------------------------------------------------------------

def plan_realm_pam_set(api: PbsBackend, comment: str | None = None, default: bool | None = None) -> Plan:
    """Preview updating the built-in PAM realm. CAPTURE-or-declare. RISK_MEDIUM — but PAM has no
    delete endpoint, so the worst case here is a comment/default-preselect change, not a lockout."""
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = realm_pam_get(api)
    except Exception:
        complete = False
        note_capture = " Could not capture current PAM realm config."
    return Plan(
        action="pbs_realm_pam_set",
        target="pbs/config/access/pam",
        change=f"update PAM realm: comment={comment!r}, default={default!r}",
        current=current,
        blast_radius=[
            "updates the built-in PAM realm's comment/default-preselect flag",
            "PAM cannot be deleted or disabled via this endpoint — no lockout path here",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["auth config change on a built-in realm — limited to comment/default"],
        complete=complete,
        note="revert by re-applying the captured config with pbs_realm_pam_set." + note_capture,
    )


def plan_realm_pbs_set(api: PbsBackend, comment: str | None = None, default: bool | None = None) -> Plan:
    """Preview updating the built-in PBS-auth realm. CAPTURE-or-declare. RISK_MEDIUM — same
    reasoning as plan_realm_pam_set: no delete endpoint exists, so no lockout-by-removal path."""
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = realm_pbs_get(api)
    except Exception:
        complete = False
        note_capture = " Could not capture current PBS-auth realm config."
    return Plan(
        action="pbs_realm_pbs_set",
        target="pbs/config/access/pbs",
        change=f"update PBS-auth realm: comment={comment!r}, default={default!r}",
        current=current,
        blast_radius=[
            "updates the built-in PBS-auth realm's comment/default-preselect flag",
            "this realm cannot be deleted or disabled via this endpoint — no lockout path here",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["auth config change on a built-in realm — limited to comment/default"],
        complete=complete,
        note="revert by re-applying the captured config with pbs_realm_pbs_set." + note_capture,
    )


# ---------------------------------------------------------------------------
# Plan functions — TFA (Wave 2b)
# ---------------------------------------------------------------------------

def plan_tfa_add(userid: str, tfa_type: str, description: str | None = None) -> Plan:
    """Preview adding a TFA entry. PURE — no API call. RISK_MEDIUM: creates a new 2FA factor for
    the user (same "creates a credential" class as plan_token_create). Deliberately takes NO
    password/totp/value/challenge parameter (same discipline as plan_user_create/
    plan_token_create — the secret-bearing/re-auth material never touches the plan)."""
    userid = _check_userid(userid)
    tfa_type = _check_tfa_type(tfa_type)
    blast = [f"adds a {tfa_type!r} TFA entry for user {userid!r}"]
    if tfa_type == "recovery":
        blast.append(
            "type='recovery' generates a BATCH of one-time recovery codes SERVER-SIDE — they "
            "surface ONCE in the result and are never written to the audit ledger"
        )
    else:
        blast.append(
            f"type={tfa_type!r}: the caller supplies the registration material "
            "(totp/value/challenge) — PBS does not generate a new secret for this type"
        )
    return Plan(
        action="pbs_tfa_add",
        target=f"pbs/access/tfa/{userid}",
        change=f"add {tfa_type!r} TFA entry for {userid!r}" + (f" ({description!r})" if description else ""),
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["adds a new 2FA credential for the user"],
        note="any acting-user password and any recovery codes generated are NOT in this "
             "plan — they surface once in the execute result",
    )


def plan_tfa_update(api: PbsBackend, userid: str, tfa_id: str, description: str | None = None,
                    enable: bool | None = None) -> Plan:
    """Preview updating a TFA entry. CAPTURE-or-declare (best-effort read of this one entry).
    RISK_MEDIUM."""
    userid = _check_userid(userid)
    tfa_id = _check_tfa_id(tfa_id)
    current: object = {}
    complete = True
    note_capture = ""
    try:
        current = tfa_entry_get(api, userid, tfa_id)
    except Exception:
        complete = False
        note_capture = " Could not read the current TFA entry."
    blast = [f"updates TFA entry {tfa_id!r} for user {userid!r}"]
    if enable is False:
        blast.append(f"enable=False disables this factor for {userid!r} immediately")
    return Plan(
        action="pbs_tfa_update",
        target=f"pbs/access/tfa/{userid}/{tfa_id}",
        change=f"update TFA entry {tfa_id!r} for {userid!r}: description={description!r}, enable={enable!r}",
        current=current if isinstance(current, dict) else {"raw": current},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["changes an existing 2FA factor's description/enabled state"],
        complete=complete,
        note="the acting-user password, if supplied, is redacted from every plan/ledger surface." + note_capture,
    )


def plan_tfa_delete(api: PbsBackend, userid: str, tfa_id: str) -> Plan:
    """Preview deleting a TFA factor. CAPTURE-or-declare (best-effort reads how many factors this
    user has, for context). RISK_HIGH: removing a 2FA factor WEAKENS authentication — it is a
    lockout AND an account-takeover enabler, the same security-weakening semantics PVE's own
    plan_tfa_delete rates HIGH, and this plane guards backups."""
    userid = _check_userid(userid)
    tfa_id = _check_tfa_id(tfa_id)
    total: int | None = None
    note_capture = ""
    complete = True
    try:
        entries = tfa_user_get(api, userid)
        total = len(entries)
    except Exception:
        complete = False
        note_capture = " Could not read the user's TFA entries — remaining-factor count unknown."
    blast = [
        f"PERMANENTLY removes TFA entry {tfa_id!r} from user {userid!r} — no undo, "
        "the factor must be re-enrolled to restore it",
        "WEAKENS the account's authentication: one fewer 2FA factor lowers the bar for account "
        "TAKEOVER, and on a TFA-required realm can lock the user out",
    ]
    if total is not None:
        blast.insert(1, f"user currently has {total} TFA entry/entries")
        if total <= 1:
            blast.append(
                f"if this is {userid!r}'s LAST factor and the realm REQUIRES TFA, the user may "
                "be unable to log in"
            )
    return Plan(
        action="pbs_tfa_delete",
        target=f"pbs/access/tfa/{userid}/{tfa_id}",
        change=f"delete TFA entry {tfa_id!r} for {userid!r}",
        current={},
        blast_radius=blast,
        risk=RISK_HIGH,
        risk_reasons=[
            "removes a 2FA factor — weakens authentication (account-takeover enabler / lockout); "
            "no rollback primitive",
        ],
        complete=complete,
        note="irreversible; re-enroll a new factor with pbs_tfa_add to restore 2FA coverage." + note_capture,
    )


def plan_tfa_unlock(userid: str) -> Plan:
    """Preview clearing a user's TOTP lockout. PURE — no API call. RISK_HIGH: clearing the lockout
    removes the anti-brute-force throttle guarding a 6-digit TOTP keyspace — an authentication-
    weakening act. (If the user was not actually locked out, PBS treats it as a no-op — its own
    return value says which happened.)"""
    userid = _check_userid(userid)
    return Plan(
        action="pbs_tfa_unlock",
        target=f"pbs/access/users/{userid}/unlock-tfa",
        change=f"clear TOTP lockout for {userid!r}",
        current={},
        blast_radius=[
            f"clears any TOTP lockout for {userid!r}, allowing further login attempts",
            "REMOVES the anti-brute-force throttle protecting a 6-digit TOTP keyspace — an "
            "account-takeover enabler if the lockout was triggered by a real guessing attack",
            "a no-op if the user was not actually locked out",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "clears the brute-force lockout on a 6-digit TOTP code — weakens authentication",
        ],
    )


def plan_tfa_webauthn_set(api: PbsBackend, rp_id: str | None = None, origin: str | None = None,
                          rp_name: str | None = None, allow_subdomains: bool | None = None) -> Plan:
    """Preview updating the server-wide WebAuthn config. CAPTURE-or-declare. RISK_MEDIUM — but the
    blast radius calls out the schema's own break-existing-credentials warnings explicitly."""
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = tfa_webauthn_get(api)
    except Exception:
        complete = False
        note_capture = " Could not capture current WebAuthn config."
    blast = ["updates the server-wide WebAuthn relying-party config"]
    if rp_id is not None:
        blast.append(
            f"rp_id={rp_id!r}: changing the relying-party id WILL break EVERY existing "
            "WebAuthn credential on the server"
        )
    if origin is not None:
        blast.append(f"origin={origin!r}: changing the origin MAY break existing WebAuthn credentials")
    return Plan(
        action="pbs_tfa_webauthn_set",
        target="pbs/config/access/tfa/webauthn",
        change=f"update WebAuthn config: rp_id={rp_id!r}, origin={origin!r}, rp_name={rp_name!r}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[
            "server-wide WebAuthn config change — id/origin changes can break every "
            "user's existing credential",
        ],
        complete=complete,
        note="revert by re-applying the captured config with pbs_tfa_webauthn_set." + note_capture,
    )
