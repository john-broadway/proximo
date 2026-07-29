"""ACCESS GOVERNANCE pillar — ACL, roles, users, and API tokens.

The trust-layer differentiator: Proxmox ACL semantics are non-obvious in one
critical way — a specific-path ACL entry REPLACES any inherited (propagated) grant
from an ancestor path; it does NOT union with it. Granting can silently narrow
access; revoking a specific entry can silently widen it. plan_acl_modify surfaces
both the SHADOW (loss of inherited privileges) and WIDEN effects BEFORE any
mutation is made — the gotcha that cost a real production cycle.

Hard rules mirrored from the codebase:
- Validators fire on every path/id component before it enters a URL.
- Plans are HONEST — HIGH is maintained even when the op would fail; no false-safety claims.
- The absence of a HIGH flag is NOT a safety signal (curated, not exhaustive).
- No self-gating: the server layer adds confirm-gating + audit; these functions are pure ops.
- Secrets: token values are NEVER written to any plan or ledger detail dict.
  A created token's value surfaces ONCE in the create result and nowhere else.
- UNDO: token_revoke is irreversible; snapshot-based undo does NOT apply to ACL/token ops.
  Never claim undo capability that the platform cannot deliver.
- ACL modify (both grant and revoke) uses PUT /access/acl — there is no per-entry
  DELETE endpoint in Proxmox. Revoke sets delete=1 in the PUT body.
- These ops are SYNCHRONOUS — no UPID; outcome is "ok", not "submitted".

Endpoint shape note:
  ApiBackend exposes _get/_post/_delete/_put. acl_modify uses api._put() for
  the PUT /access/acl call. Confirm the PUT path and body params at live smoke
  (see docstring on acl_modify).
"""

from __future__ import annotations

import re

from . import blast
from .backends import ProximoError
from .planning import RISK_HIGH, RISK_MEDIUM, Plan, _max_risk

# ---------------------------------------------------------------------------
# Validators (module-local)
# ---------------------------------------------------------------------------

# userid: "user@realm" or just "user" (realm is optional for some forms).
# Characters: alnum, dot, underscore, hyphen. No traversal, no newlines.
# \Z anchors past any trailing newline.
_USERID_RE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+\Z")

# tokenid: alphanumeric + hyphen/underscore (PVE's own naming rule for tokens).
_TOKENID_RE = re.compile(r"^[A-Za-z0-9._-]+\Z")

# roleid: e.g. "PVEVMAdmin", "Administrator", custom names.
_ROLEID_RE = re.compile(r"^[A-Za-z0-9._-]+\Z")

# groupid: PVE group names — alnum, dot, underscore, hyphen. No "@" (that's a userid),
# no "/" (that's a path separator). \Z anchors past any trailing newline.
_GROUPID_RE = re.compile(r"^[A-Za-z0-9._-]+\Z")

# ACL path: "/"  or  "/" + slash-separated segments (no "..", no trailing slash, no spaces).
# An ACL path of "/" alone is the root (highest blast — all resources).
_ACL_PATH_RE = re.compile(r"^/([A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*)?\Z")


def _check_userid(userid: str) -> str:
    s = str(userid).strip()
    if not _USERID_RE.match(s):
        raise ProximoError(
            f"invalid userid: {userid!r} — expected user@realm "
            "(letters/digits/._- only; no path separators or whitespace)"
        )
    _reject_dot_traversal(s, "userid")
    return s


def _reject_dot_traversal(s: str, label: str) -> None:
    """Reject a '.'/'..' (or any '..'-containing) identifier. It flows into the URL path and the HTTP
    client normalizes dot-segments BEFORE sending — e.g. `.../token/..` collapses onto the
    user-delete endpoint — turning a scoped op into a wrong-target destructive one. Same class of
    guard `_check_acl_path` / `_check_tfa_id` already apply; the bare regex permits all-dots."""
    if s == "." or ".." in s:
        raise ProximoError(f"invalid {label}: {s!r} — path-traversal segment rejected")


def _check_tokenid(tokenid: str) -> str:
    s = str(tokenid).strip()
    if not _TOKENID_RE.match(s):
        raise ProximoError(
            f"invalid tokenid: {tokenid!r} — expected letters/digits/._- only"
        )
    _reject_dot_traversal(s, "tokenid")
    return s


def _check_groupid(groupid: str) -> str:
    """Validate a PVE group name for use as an ACL 'groups' target.

    Note: `access_users.py` has its OWN `_check_groupid` (a stricter regex used for
    /access/groups CRUD). This is a separate, module-local validator for the ACL surface
    (mirrors `_check_roleid`'s style) — the two are deliberately not shared to avoid a
    circular import (access_users.py already imports `_check_userid` from this module).
    """
    s = str(groupid).strip()
    if not _GROUPID_RE.match(s):
        raise ProximoError(
            f"invalid groupid: {groupid!r} — expected letters/digits/._- only"
        )
    _reject_dot_traversal(s, "groupid")
    return s


def _check_roleid(roleid: str) -> str:
    s = str(roleid).strip()
    if not _ROLEID_RE.match(s):
        raise ProximoError(
            f"invalid roleid: {roleid!r} — expected letters/digits/._- only"
        )
    _reject_dot_traversal(s, "roleid")
    return s


def _check_roles(roles: str) -> str:
    """Validate a comma-separated role list (at least one valid roleid)."""
    s = str(roles).strip()
    if not s:
        raise ProximoError("roles must not be empty")
    for r in s.split(","):
        _check_roleid(r.strip())
    return s


def _check_acl_path(path: str) -> str:
    s = str(path).strip()
    if ".." in s:
        raise ProximoError(f"invalid ACL path: {path!r} (path traversal rejected)")
    if not _ACL_PATH_RE.match(s):
        raise ProximoError(
            f"invalid ACL path: {path!r} — expected '/' or '/segment/…/segment' "
            "(letters/digits/._- only; no trailing slash; no spaces)"
        )
    return s


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_root_or_broad(acl_path: str) -> bool:
    """True for the two highest-blast ACL scopes: / (root) and /storage (all datastores)."""
    return acl_path in ("/", "/storage")


def _is_administrator_role(roles: str) -> bool:
    """True if the comma-separated roles list includes 'Administrator' (PVE's super-role)."""
    return "Administrator" in {r.strip() for r in roles.split(",")}


def _check_acl_target(target: str, kind: str) -> str:
    """Validate + normalize an ACL target for the given kind ('user'/'group'/'token')."""
    if kind == "user":
        return _check_userid(target)
    if kind == "group":
        return _check_groupid(target)
    if kind == "token":
        if "!" not in target:
            raise ProximoError(
                f"invalid token target: {target!r} — expected 'user@realm!tokenid'"
            )
        user_part, _, token_part = target.partition("!")
        return f"{_check_userid(user_part)}!{_check_tokenid(token_part)}"
    raise ProximoError(f"invalid kind: {kind!r} (expected 'user', 'token', or 'group')")


# ---------------------------------------------------------------------------
# Read operations — audited but not confirm-gated
# ---------------------------------------------------------------------------

def access_users_list(api) -> list[dict]:
    """List all Proxmox users.

    GET /access/users

    Returns a list of user objects (userid, comment, email, enable, expire, groups, …).
    Audited at the server layer.
    """
    return api._get("/access/users") or []


def access_roles_list(api) -> list[dict]:
    """List all Proxmox roles and their privileges.

    GET /access/roles

    Returns a list of role objects (roleid, privs map, …).
    Audited at the server layer.
    """
    return api._get("/access/roles") or []


def access_acl_list(api) -> list[dict]:
    """List all ACL entries on the Proxmox cluster.

    GET /access/acl

    Returns a list of ACL entry objects (path, roleid, ugid (user/group/token),
    type (user|group|token), propagate).
    Audited at the server layer.
    """
    return api._get("/access/acl") or []


def access_tokens_list(api, userid: str) -> list[dict]:
    """List API tokens for a specific user.

    GET /access/users/{userid}/token

    Returns a list of token objects (tokenid, comment, expire, privsep).
    NOTE: the token secret (value) is never returned by this endpoint — it is
    shown ONLY once at token creation time.

    Shape note: {userid} is URL-encoded by PVE on its side; we validate the
    userid here (character set + realm format) but do NOT additionally URL-encode
    it before inserting into the path — Proxmox's own implementation uses the
    raw user@realm string in the path. Confirm at live smoke.
    """
    userid = _check_userid(userid)
    return api._get(f"/access/users/{userid}/token") or []


# ---------------------------------------------------------------------------
# Diagnostic: over-broad grants
# ---------------------------------------------------------------------------

def access_overbroad_grants(api) -> list[dict]:
    """Surface over-broad ACL grants as a first-class diagnostic.

    An 'over-broad' grant is one where:
      - The roleid is 'Administrator' (the PVE super-role with all privileges), OR
      - The ACL path is '/' (root — affects every resource on the cluster).

    These are not necessarily wrong, but they warrant explicit review.

    READ — no mutation, no confirm required. Audited at the server layer.

    Returns a list of dicts with keys: path, ugid, roleid, type, propagate,
    reason (why it's flagged).
    """
    acl_entries = access_acl_list(api)
    flagged = []
    for entry in acl_entries:
        path = entry.get("path", "")
        roleid = entry.get("roleid", "")
        reasons = []
        if roleid == "Administrator":
            reasons.append(
                "Administrator role grants ALL privileges (super-role); "
                "prefer a least-privilege role scoped to the specific task"
            )
        if path == "/":
            reasons.append(
                "ACL at '/' affects EVERY resource on the cluster — widest possible scope"
            )
        if reasons:
            flagged.append({
                "path": path,
                "ugid": entry.get("ugid", ""),
                "roleid": roleid,
                "type": entry.get("type", ""),
                "propagate": entry.get("propagate", True),
                "reasons": reasons,
            })
    return flagged


# ---------------------------------------------------------------------------
# Mutation operations — validate params, build exact PVE URL, return result.
# These do NOT self-gate. The server layer adds confirm-gating + audit.
# ---------------------------------------------------------------------------

def acl_modify(
    api,
    path: str,
    roles: str,
    target: str,
    kind: str = "user",
    propagate: bool = True,
    delete: bool = False,
) -> None:
    """Grant or revoke an ACL entry.

    PUT /access/acl
    Body: {path, roles, users|groups|tokens, propagate, delete}

    kind must be 'user', 'group', or 'token'.
    delete=False: grant; delete=True: revoke the entry.

    Proxmox uses a single PUT /access/acl for BOTH grant and revoke — there is
    no per-entry DELETE endpoint. Revoke is indicated by delete=1 in the body.

    Returns None (synchronous — no UPID).

    Endpoint shape notes (confirm at live smoke):
    - PUT /access/acl is the documented PVE API endpoint for all ACL writes.
    - The 'users' body param accepts a comma-separated list of user@realm strings.
    - The 'groups' body param accepts a comma-separated list of group names.
    - The 'tokens' body param accepts a comma-separated list of user@realm!tokenid strings.
    - 'propagate' applies the entry recursively down the path hierarchy if True.

    MUTATION — confirm-gated + audited at the server layer.
    """
    path = _check_acl_path(path)
    roles = _check_roles(roles)
    target = _check_acl_target(target, kind)

    data: dict = {
        "path": path,
        "roles": roles,
        "propagate": int(propagate),
        "delete": int(delete),
    }
    if kind == "user":
        data["users"] = target
    elif kind == "group":
        data["groups"] = target
    else:
        data["tokens"] = target

    # MUTATION — confirm-gated + audited at the server layer.
    return api._put("/access/acl", data)


def acl_prune(
    api,
    path: str,
    target: str,
    kind: str,
    roleid: str,
    narrow_role: str | None = None,
    narrow_path: str | None = None,
) -> None:
    """Revoke an over-broad ACL grant, then optionally re-grant a narrower one.

    Two synchronous PUT /access/acl calls (revoke, then re-grant). Returns None.

    Revoke FIRST, re-grant SECOND: a revoke-then-grant sequence briefly narrows access
    (the safe direction) rather than briefly widening it. Each call is validated and
    executed by `acl_modify` — no bulk here: exactly one principal, one roleid, per call.

    NON-ATOMIC (documented limit, safe-direction — mirrors the L16 audit-window NOTE in
    server._audited): these are two separate PUTs. If the revoke succeeds and the re-grant
    then raises, the ledger records one outcome="error" for the whole pve_acl_prune action —
    it does NOT distinguish "nothing happened" from "revoke landed, re-grant failed". The
    direction is safe (revoke-first leaves the target MORE restricted, never wider), so a
    partial failure never widens access; but an auditor reading only the ledger cannot tell
    the revoke already applied. A distinct partial-outcome state (a named
    PruneRegrantFailedError, or a "partial:revoke_only" outcome) is a deliberate follow-up —
    it ripples into audit_verify + the ledger outcome-state suite; tracked as a known limit,
    not a stop-ship.

    (This used to cite "the same reason the L16 window fix was deferred". That fix has since
    LANDED — a new `executing` outcome plus a derived intent id, see server._audited and
    audit.in_flight — so the deferral no longer has that precedent behind it. The limit here
    is still real and still open; only the justification changed. The pattern that closed L16
    is also the shape that would close this one: record the interval, not just the result.)

    MUTATION — confirm-gated + audited at the server layer (see plan_prune_grant for the
    matching dry-run preview).
    """
    acl_modify(api, path, roleid, target, kind, delete=True)
    if narrow_role is not None or narrow_path is not None:
        acl_modify(api, narrow_path or path, narrow_role or roleid, target, kind, delete=False)
    return None


def token_create(
    api,
    userid: str,
    tokenid: str,
    privsep: bool = True,
    comment: str | None = None,
    expire: int | None = None,
) -> dict:
    """Create an API token for a user.

    POST /access/users/{userid}/token/{tokenid}

    privsep=True (default, SAFER): the token's privileges are limited to the
    roles/ACLs assigned DIRECTLY to it. privsep=False: the token inherits all
    of the owner user's permissions — effectively granting the owner's full privilege set.

    Returns a dict with keys: value (the token secret — shown ONCE), info (metadata).
    Callers must show the 'value' to the user and warn it cannot be retrieved again.
    The value must NEVER be written to the audit ledger.

    Returns result immediately (synchronous — no UPID).

    MUTATION — confirm-gated + audited at the server layer.
    The audit record must NOT include the token value in its detail dict.
    """
    userid = _check_userid(userid)
    tokenid = _check_tokenid(tokenid)
    data: dict = {"privsep": int(privsep)}
    if comment is not None:
        data["comment"] = str(comment)
    if expire is not None:
        data["expire"] = int(expire)
    # POST /access/users/{userid}/token/{tokenid}
    # userid contains '@' which is safe in URL path per RFC 3986; PVE handles it natively.
    result = api._post(f"/access/users/{userid}/token/{tokenid}", data)
    # result is expected to be {"value": "<secret>", "info": {...}}
    return result or {}


def token_revoke(api, userid: str, tokenid: str) -> None:
    """Revoke (permanently delete) an API token.

    DELETE /access/users/{userid}/token/{tokenid}

    IRREVERSIBLE: the token secret is gone forever. There is no undo.
    Do NOT call this with the intent to undo — it cannot be undone.

    Returns None (synchronous — no UPID).

    MUTATION — confirm-gated + audited at the server layer.
    """
    userid = _check_userid(userid)
    tokenid = _check_tokenid(tokenid)
    return api._delete(f"/access/users/{userid}/token/{tokenid}")


# ---------------------------------------------------------------------------
# Plan functions — pure analysis; return a Plan the caller can inspect.
# ---------------------------------------------------------------------------

def plan_acl_modify(
    api,
    path: str,
    roles: str,
    target: str,
    kind: str = "user",
    propagate: bool = True,
    delete: bool = False,
) -> Plan:
    """Preview what an ACL change does — the killer feature.

    THE CRITICAL PROXMOX GOTCHA: a specific-path ACL entry REPLACES any
    inherited (propagated) grant from an ancestor path. It does NOT union with it.
    This means:
      - GRANTING can NARROW access: if the target currently has broad inherited
        privileges (e.g. Administrator at /), a new specific entry at /vms/100
        with fewer privileges SHADOWS the inherited grant — the inherited grant no
        longer applies at /vms/100.
      - REVOKING a specific entry can WIDEN access: if you remove a specific entry,
        the target falls back to a broader inherited grant that was being shadowed.

    This plan:
      1. Reads the current ACL (one safe read; errors are disclosed, not swallowed).
      2. Computes SHADOW: inherited privileges that would be LOST at `path` due to
         the new specific entry replacing the inherited grant (grant path).
         For revoke path: inherited grants that would be RESTORED (i.e., WIDENED).
      3. Computes WIDEN: privileges the new entry adds that the target didn't have.
      4. Flags HIGH risk for: Administrator role, root path (/), or any detected shadow.
      5. Flags HIGH risk when revoke widens access (restores a broader inherited grant).

    Validates inputs even on the plan path — same as all other plan functions.
    """
    path = _check_acl_path(path)
    roles = _check_roles(roles)
    target = _check_acl_target(target, kind)

    # ONE SAFE READ: current ACL state (fail-closed — None signals the read failed).
    acl_entries: list[dict] | None
    acl_error: str | None = None
    try:
        acl_entries = access_acl_list(api) or []
    except Exception as e:
        acl_entries = None
        acl_error = type(e).__name__

    # #1: resolve the target's OWN group memberships so the shadow analysis is complete.
    # Local import — access_users imports access (._check_userid), so a top-level import would cycle.
    from .access_users import group_get, user_get
    target_groups: list[str] | None = None
    extra_inherited: dict[str, str] | None = None
    if acl_entries is not None:
        if kind == "user":
            try:
                target_groups = list(user_get(api, target).get("groups") or [])
            except Exception:
                target_groups = None
        elif kind == "group":
            # A group has no own-memberships to inherit through; [] (not None) makes
            # groups_resolved=True in the engine, so it does NOT emit the misleading
            # "target's group membership could not be resolved" line for a group target.
            target_groups = []
        else:  # token "owner@realm!tokenid" inherits owner groups ONLY if privsep == 0
            owner = target.split("!", 1)[0]
            try:
                tid = target.split("!", 1)[1]
                tok = next((t for t in access_tokens_list(api, owner) if t.get("tokenid") == tid), None)
                privsep = tok.get("privsep", 1) if tok else 1   # default privsep=1 (least inheritance)
                if str(privsep) in ("0", "False"):
                    target_groups = list(user_get(api, owner).get("groups") or [])
                    # privsep=0 token IS the owner: also fold owner's DIRECT propagated user grants
                    # from ancestor paths (group grants are covered by target_groups above).
                    extra_inherited = {
                        e.get("roleid", ""): f"token owner {owner} (direct)"
                        for e in acl_entries
                        if e.get("type") == "user" and e.get("ugid") == owner
                        and path.startswith(e.get("path", "").rstrip("/") + "/")
                        and e.get("propagate", True)
                    }
                else:
                    target_groups = None  # privsep token: no owner-group inheritance -> stay honest
            except Exception:
                target_groups = None

    # #2: members of group-type ACL entries at/above the path (who-else-can-reach context).
    group_members: dict[str, list | None] = {}
    if acl_entries is not None:
        in_scope_groups = {
            e.get("ugid", "") for e in acl_entries
            if e.get("type") == "group" and (
                e.get("path") == path or path.startswith(e.get("path", "").rstrip("/") + "/")
            )
        }
        for grp in sorted(g for g in in_scope_groups if g):
            try:
                group_members[grp] = list(group_get(api, grp).get("members") or [])
            except Exception:
                group_members[grp] = None

    result = blast.compute_acl_blast(path, roles, target, kind, delete, acl_entries, acl_error,
                                     target_groups=target_groups, group_members=group_members or None,
                                     extra_inherited=extra_inherited)

    return Plan(
        action="pve_acl_modify",
        target=f"acl:{path}:{target}",
        change=(
            f"{'revoke' if delete else 'grant'} role(s) {roles!r} {'from' if delete else 'to'} "
            f"{target!r} at path {path!r} (propagate={propagate})"
        ),
        current=result.current,
        blast_radius=result.summary_lines,
        affected=result.affected,
        risk=result.risk,
        risk_reasons=result.risk_reasons,
        complete=result.complete,
    )


def plan_prune_grant(
    api,
    path: str,
    target: str,
    kind: str,
    roleid: str,
    narrow_role: str | None = None,
    narrow_path: str | None = None,
) -> Plan:
    """Preview pruning (revoking, and optionally re-granting narrower) an over-broad ACL grant.

    Least-privilege companion to `plan_acl_modify`: `access_overbroad_grants` flags a grant,
    this previews REMOVING it. Two legs, merged into one honest plan:
      - REVOKE leg: `roleid` is removed from `target` at `path` (via `compute_acl_blast(delete=True)`).
      - RE-GRANT leg (only if `narrow_role` and/or `narrow_path` is given): a narrower
        replacement is granted — effective role `narrow_role or roleid`, effective path
        `narrow_path or path`. Neither given => PURE REVOKE, no re-grant leg.

    `compute_acl_blast(delete=True)` never names the primary revoked grant as a "loses" entry
    (it only reports restored/widened inherited grants) — pruning's whole point is naming the
    removal, so this function SYNTHESIZES an explicit primary-loss entry and prepends it.

    The re-grant leg's blast is computed against a POST-revoke view of the ACL (the just-revoked
    entry filtered out) so it never spuriously warns about shadowing the role being deleted in
    the same operation.

    Risk never goes down across the merge: `risk = max(revoke.risk, regrant.risk)`.

    Validates inputs even on the plan path — same as all other plan functions.
    """
    path = _check_acl_path(path)
    target = _check_acl_target(target, kind)
    roleid = _check_roleid(roleid)
    if narrow_role is not None:
        narrow_role = _check_roleid(narrow_role)
    if narrow_path is not None:
        narrow_path = _check_acl_path(narrow_path)

    # ONE SAFE READ + group resolution — copy of plan_acl_modify's block (lines ~460–515),
    # with ONE change for kind=="group": target_groups=[] (see docstring above).
    # Local import — access_users imports access (._check_userid), so a top-level import would cycle.
    from .access_users import group_get, user_get
    acl_entries: list[dict] | None
    acl_error: str | None = None
    try:
        acl_entries = access_acl_list(api) or []
    except Exception as e:
        acl_entries = None
        acl_error = type(e).__name__

    # Path-INDEPENDENT resolution — computed ONCE and shared by both legs: target_groups, and
    # (token kind only) the owner id + whether the token is privsep=0. compute_acl_blast
    # re-derives group-inheritance-AT-PATH itself from target_groups, so this part carries no
    # path dependency.
    target_groups: list[str] | None = None
    owner: str | None = None
    is_privsep0 = False
    if acl_entries is not None:
        if kind == "user":
            try:
                target_groups = list(user_get(api, target).get("groups") or [])
            except Exception:
                target_groups = None
        elif kind == "group":
            target_groups = []
        else:  # token "owner@realm!tokenid" inherits owner groups ONLY if privsep == 0
            owner = target.split("!", 1)[0]
            try:
                tid = target.split("!", 1)[1]
                tok = next((t for t in access_tokens_list(api, owner) if t.get("tokenid") == tid), None)
                privsep = tok.get("privsep", 1) if tok else 1
                if str(privsep) in ("0", "False"):
                    # is_privsep0 flips True only AFTER user_get succeeds — mirrors the original
                    # coupling (a user_get failure here must leave BOTH legs' extra_inherited
                    # None, same as before the fix; see _leg_ctx docstring below).
                    target_groups = list(user_get(api, owner).get("groups") or [])
                    is_privsep0 = True
                else:
                    target_groups = None
            except Exception:
                target_groups = None

    def _leg_ctx(
        entries: list[dict] | None, leg_path: str,
    ) -> tuple[dict[str, str] | None, dict[str, list | None]]:
        """Path-DEPENDENT resolution for ONE leg, evaluated AT `leg_path` against `entries`:
        (extra_inherited, group_members) — mirrors plan_acl_modify's matching block. Both
        extra_inherited (a privsep=0 token owner's direct grants that propagate onto leg_path)
        and group_members (in-scope groups at/above leg_path) depend on the path being
        evaluated. FINDING 1 fix: the revoke leg (path) and the re-grant leg (effective_path,
        against a post-revoke `entries` view) MUST call this separately — sharing one stale
        result silently under-reports shadow/context at a re-grant path that differs from path.
        """
        ei: dict[str, str] | None = None
        if entries is not None and is_privsep0 and owner is not None:
            ei = {
                e.get("roleid", ""): f"token owner {owner} (direct)"
                for e in entries
                if e.get("type") == "user" and e.get("ugid") == owner
                and leg_path.startswith(e.get("path", "").rstrip("/") + "/")
                and e.get("propagate", True)
            }
        gm: dict[str, list | None] = {}
        if entries is not None:
            in_scope_groups = {
                e.get("ugid", "") for e in entries
                if e.get("type") == "group" and (
                    e.get("path") == leg_path
                    or leg_path.startswith(e.get("path", "").rstrip("/") + "/")
                )
            }
            for grp in sorted(g for g in in_scope_groups if g):
                try:
                    gm[grp] = list(group_get(api, grp).get("members") or [])
                except Exception:
                    gm[grp] = None
        return ei, gm

    # REVOKE leg's path-dependent context, evaluated at `path` — byte-identical to the
    # pre-fix single computation (which was also implicitly evaluated at `path`).
    ei_rev, gm_rev = _leg_ctx(acl_entries, path)

    # REVOKE leg.
    revoke = blast.compute_acl_blast(path, roleid, target, kind, True, acl_entries, acl_error,
                                     target_groups=target_groups, group_members=gm_rev or None,
                                     extra_inherited=ei_rev)

    # SYNTHESIZE THE PRIMARY LOSS ENTRY — compute_acl_blast(delete=True) forces
    # shadowed_inherited=set() (it only reports restored/widened inherited grants), so it never
    # names the grant actually being removed. Add it ALWAYS, even on ACL-read failure (the
    # primary revoke target is known regardless of whether the read succeeded).
    primary_sev = "high" if (_is_root_or_broad(path) or roleid == "Administrator"
                             or revoke.risk == RISK_HIGH) else "medium"
    primary_loss = {"principal": target, "kind": kind, "via": "direct grant removed",
                    "change": "loses", "roles": [roleid], "at": path, "severity": primary_sev}

    do_regrant = narrow_role is not None or narrow_path is not None
    if do_regrant:
        effective_role = narrow_role or roleid
        effective_path = narrow_path or path
        # ORDERING FIX: build a post-revoke view of the ACL so the re-grant leg does not emit
        # a spurious "shadows inherited {roleid}" warning for the role being deleted in this
        # same operation.
        regrant_entries = None if acl_entries is None else [
            e for e in acl_entries
            if not (e.get("path") == path and e.get("ugid") == target and e.get("roleid") == roleid)
        ]
        # RE-GRANT leg's path-dependent context, re-derived at `effective_path` against the
        # POST-revoke view (FINDING 1 fix — see _leg_ctx docstring above).
        ei_re, gm_re = _leg_ctx(regrant_entries, effective_path)
        regrant = blast.compute_acl_blast(effective_path, effective_role, target, kind, False,
                                          regrant_entries, acl_error,
                                          target_groups=target_groups, group_members=gm_re or None,
                                          extra_inherited=ei_re)
        risk = _max_risk(revoke.risk, regrant.risk)
        blast_radius = revoke.summary_lines + regrant.summary_lines
        affected = [primary_loss, *revoke.affected, *regrant.affected]
        risk_reasons = revoke.risk_reasons + regrant.risk_reasons
        complete = revoke.complete and regrant.complete
        change = (
            f"revoke {roleid!r} from {target!r} at {path!r}; "
            f"re-grant {effective_role!r} at {effective_path!r}"
        )
    else:
        risk = revoke.risk
        blast_radius = revoke.summary_lines
        affected = [primary_loss, *revoke.affected]
        risk_reasons = revoke.risk_reasons
        complete = revoke.complete
        change = f"revoke {roleid!r} from {target!r} at {path!r}"

    # Honesty escalation (plan_prune_grant's own, after the merge): pruning a group whose OWN
    # members we could not enumerate is uncertain about who loses what — force HIGH + incomplete.
    # Do NOT escalate for an incidental who-else group failing elsewhere (that stays best-effort
    # complete=False per the engine's existing restraint). The target group always has an entry
    # at `path` (that IS the grant being pruned), so `.get(target) is None` cleanly means its
    # own read failed, not "absent". Always checked against the REVOKE-leg's group_members
    # (gm_rev) — the pruned group's entry is at `path`, unchanged by the re-grant leg's context.
    if kind == "group" and gm_rev.get(target) is None:
        risk = _max_risk(risk, RISK_HIGH)
        complete = False

    return Plan(
        action="pve_acl_prune",
        target=f"acl:prune:{path}:{target}",
        change=change,
        current=revoke.current,
        blast_radius=blast_radius,
        affected=affected,
        risk=risk,
        risk_reasons=risk_reasons,
        complete=complete,
    )


def plan_token_create(
    userid: str,
    tokenid: str,
    privsep: bool = True,
    expire: int | None = None,
    comment: str | None = None,
) -> Plan:
    """Preview creating an API token.

    PURE — no API call needed.

    privsep=True (default): token is privilege-separated — its rights are limited
    to ACLs assigned directly to it. Lower blast.
    privsep=False: token inherits ALL of the owner's permissions. The token
    effectively IS the user — RISK_HIGH, flagged as over-broad.

    expire: ABSOLUTE UNIX timestamp (seconds since epoch) at which the token expires; 0 or
    absent = never. This is NOT a TTL/duration — a duration-shaped value like 86400 is a date
    in Jan 1970 (already expired). Absent/None and 0 both mean the token NEVER expires — surfaced
    explicitly in the plan so the operator can make an informed decision (L03 fix; 2026-07-10 L8).

    NOTE: the token secret value does NOT appear in the plan (it doesn't exist yet).
    The value surfaces once in the token_create result. Plans are safe to log.
    """
    userid = _check_userid(userid)
    tokenid = _check_tokenid(tokenid)

    if not privsep:
        risk = RISK_HIGH
        reasons = [
            "privsep=False: this token inherits ALL of the owner user's permissions — "
            "it is equivalent to the user credential itself; prefer privsep=True and "
            "assign only the permissions the token actually needs"
        ]
        blast = [
            f"creates token {userid}!{tokenid} with privsep=False — "
            "token has FULL owner privileges (not privilege-separated); "
            "a leaked token is as dangerous as a leaked user password"
        ]
    else:
        risk = RISK_MEDIUM
        reasons = ["creates a credential — token secrets cannot be retrieved after creation"]
        blast = [
            f"creates token {userid}!{tokenid} (privsep=True — restricted to token's own ACLs)",
            "the token secret value will be shown ONCE at creation; it cannot be retrieved again",
        ]

    # L03: surface expiry visibility — expire=None/0 both mean "never expires" in PVE
    if not expire:
        blast.append(
            f"token {userid}!{tokenid} has NO expiration (expire={expire!r}) — it never expires; "
            "set expire to an absolute UNIX timestamp (seconds since epoch) in the future for a "
            "limited lifetime — it is a DATE, not a duration/TTL"
        )
        expire_desc = "never"
    else:
        expire_desc = str(expire)
        # 2026-07-10 audit L8: PVE 'expire' is an absolute epoch, not a TTL. A duration-shaped value
        # (e.g. 3600 / 86400 / 2592000) is a date in the past -> the token is created ALREADY EXPIRED.
        # 1_000_000_000 = Sept 2001; any real future expiry is well above it. Pure/deterministic guard.
        try:
            _e = int(expire)
        except (TypeError, ValueError):
            _e = None
        if _e is not None and 0 < _e < 1_000_000_000:
            blast.append(
                f"WARNING: expire={expire!r} looks like a TTL/duration, but PVE treats it as an "
                "ABSOLUTE UNIX timestamp (seconds since epoch) — this token would be created ALREADY "
                "EXPIRED (a date in the past). Use a future epoch timestamp instead."
            )

    change = f"create token {userid}!{tokenid} (privsep={privsep}, expire={expire_desc})"
    if comment:
        change += f", comment={comment!r}"

    return Plan(
        action="pve_token_create",
        target=f"token:{userid}!{tokenid}",
        change=change,
        current={},
        blast_radius=blast,
        risk=risk,
        risk_reasons=reasons,
        note="token secret (value) is NOT in this plan — it surfaces once in the creation result",
    )


def plan_token_revoke(userid: str, tokenid: str) -> Plan:
    """Preview revoking (deleting) an API token.

    PURE — no API call needed.

    RISK_HIGH: revocation is IRREVERSIBLE. The token secret is permanently gone.
    Any systems or integrations using this token will immediately lose access.
    There is no undo — snapshot-based undo does NOT apply to token operations.
    """
    userid = _check_userid(userid)
    tokenid = _check_tokenid(tokenid)
    return Plan(
        action="pve_token_revoke",
        target=f"token:{userid}!{tokenid}",
        change=f"revoke (permanently delete) token {userid}!{tokenid}",
        current={},
        blast_radius=[
            f"PERMANENTLY revokes token {userid}!{tokenid} — the secret is gone forever",
            "any service or integration using this token will immediately lose Proxmox API access",
            "IRREVERSIBLE: snapshot-based undo does NOT apply to token operations",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "token revocation is permanent — the secret cannot be recovered or reissued",
            "downstream systems using this token lose access immediately and irrecoverably",
        ],
    )
