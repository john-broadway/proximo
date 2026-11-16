"""PMG'S SHAPE for the estate memory (`memory.PlaneShape`): relay domains, transports, trusted networks,
TLS policies, DKIM domains, the rule database (rules, and the who, what, when and action objects they
use), PBS remotes, nodes and users, each kept in the vendor's own words (the field names a PMG 9.1
answers) and answered by the vendor's own id. No edges: a rule names its objects, but no relation is
judged here. This module registers itself in `memory.SHAPES` when imported (`memory` imports it at
its end), so either import order works.

    read                              kind          key = ident     name
    /config/domains                   domain        domain          domain
    /config/transport                 transport     domain          domain
    /config/mynetworks                mynetwork     cidr            cidr
    /config/tlspolicy                 tlspolicy     destination     destination
    /config/dkim/domains              dkim-domain   domain          domain
    /config/ruledb/rules              rule          id              name   (priority, active, direction kept)
    /config/ruledb/action/objects     action        id              name
    /config/ruledb/who|what|when      who|what|when id              name
    /config/pbs                       pbs           remote          remote
    /nodes  /config/cluster/status    node          node | name     node | name
    /access/users                     user          userid          username

The kind words are taken from the vendor's paths, never from a live answer's values, so none is to be
read as the vendor's own answer. Seven ARE a live path segment: `transport`, `tlspolicy`, `action`,
`who`, `what`, `when`, `pbs`. Five are the singular of one: `domain` (of `/config/domains`, and the
vendor's own param name), `mynetwork`, `rule`, `user`, `node`. One is a composite: `dkim-domain`, of
`/config/dkim/domains`. `action` is beyond the plan's candidate list: `/config/ruledb/action/objects`
is the vendor's list of the action objects a rule names. The kinds are shown in THIS SHAPE'S OWN
ORDER, not the GUI's (which the API cannot show): mail proxy (domain, transport, mynetwork,
tlspolicy, dkim-domain), then mail filter (rule, action, who, what, when), then users, nodes and
backup. A relay domain, its transport and its DKIM domain share one spelling and all three answer
it, each with its own read, in that order.

A ROLE READS A CONFIG LIST WHOLE OR NOT AT ALL. PMG checks the caller's role and refuses a role it does
not let in with a 403 (a quarantine manager, live, on every list here); a role it lets in gets the
whole list (an auditor and a help desk user, live, got the same lists). So a whole read of a config
list owns it, when every row names itself by the list's field: absent is not proof, and a row memory
cannot key (a field renamed in another version, a garbled answer) may be the very thing a retire would
call gone, so such a list only adds, and a learn that read it says incomplete. The node list is every
role's and owns when it names a node and every row does; the users list keys the same way. The cluster
status lists nothing on a node with no cluster unless asked `list_single_node`, so it only adds.

THE USERS LIST FILTERS. A quarantine manager is shown only itself, live. So it owns only when the
box's last `learn` read the credential's OWN user record first and found a role that sees every user
(`_SEES_EVERY_USER`): `users_sight` is then `whole:<user@realm>`, the credential's public user (PMG
has no API tokens; `arm.served_id` reads the credential file's first line, never the password), and a
users read owns only when the credential that made it names the same user AND the answer's own row for
that user, there once, still shows a role that sees every user (a role is the box admin's to change
after a learn; a demoted user's read shows only itself and must retire no one). Learn writes the flag
"partial" first on every pass and raises it only when the user it read before the record and after it
agree. Unknown, unread, another user's, or a role not in the set: the users list adds and refreshes only.

Never kept: a comment or an object's `info` (free text), a rule's embedded object lists, a user's mail,
first and last names or keys (a user keeps its userid, its username, which `where` answers to, and its
role, realm and enable), a PBS remote's user, password or key, fetchmail and LDAP (their lists carry
account secrets and no id worth finding).
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Mapping
from typing import Any

from proximo.core import consult, memory

_PLANE = "pmg"
_USERS = "/access/users"
_ME = "/access/users/{userid}"
_NODES = "/nodes"
_CLUSTER = "/config/cluster/status"
_DOMAINS = "/config/domains"
#: Each config list: the kind it holds, and the field the vendor names each one by.
_LISTS: dict[str, tuple[str, str]] = {
    _DOMAINS: ("domain", "domain"),
    "/config/transport": ("transport", "domain"),
    "/config/mynetworks": ("mynetwork", "cidr"),
    "/config/tlspolicy": ("tlspolicy", "destination"),
    "/config/dkim/domains": ("dkim-domain", "domain"),
    "/config/ruledb/rules": ("rule", "id"),
    "/config/ruledb/action/objects": ("action", "id"),
    "/config/ruledb/who": ("who", "id"),
    "/config/ruledb/what": ("what", "id"),
    "/config/ruledb/when": ("when", "id"),
    "/config/pbs": ("pbs", "remote"),
}
#: The kinds named by an object's own `name`; the rest are named by their id.
_NAMED = frozenset({"rule", "action", "who", "what", "when"})
#: What each kind keeps beside its id: the vendor's own values, never free text or a secret.
_DETAIL: dict[str, tuple[str, ...]] = {
    "transport": ("host", "port", "protocol", "use_mx"), "tlspolicy": ("policy",),
    "rule": ("priority", "active", "direction"), "pbs": ("server", "datastore"),
}
FEEDS = frozenset({*_LISTS, _NODES, _CLUSTER, _USERS})
#: The meta key `learn` writes from the credential's own user record: `whole:<user@realm>` when its role
#: sees every user; anything else (or absent) is not sight.
_USERS_SIGHT = "users_sight"
#: The roles PMG shows every user to: audit and helpdesk seen whole live; admin and root above them.
_SEES_EVERY_USER = frozenset({"root", "admin", "audit", "helpdesk"})
#: The roles PMG has, the only ones a gap may name.
_ROLES = frozenset({*_SEES_EVERY_USER, "qmanager"})
#: A PMG user (`user@realm`): what the flag may name. No `!`: PMG has no tokens.
_WHO = re.compile(r"[^\s!=:@/]+@[^\s!=:@/]+")
#: The kinds find's exact lookup takes, in this shape's own order (mail proxy, mail filter, users, nodes,
#: backup), not the GUI's.
KIND_ORDER = ("domain", "transport", "mynetwork", "tlspolicy", "dkim-domain", "rule", "action", "who", "what",
              "when", "user", "node", "pbs")
VENDOR_KINDS = frozenset(KIND_ORDER)


def _text(v: Any) -> str | None:
    """A non-empty id the vendor gave: a string, or an integer (the rule database answers both), never
    a bool or a null."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return str(v)
    return v if isinstance(v, str) and v else None


#: The field each list's rows name themselves by: a config list's own field, a node, a cluster member, a
#: user. A list that is not here keys nothing.
_KEY: dict[str, str] = {**{t: field for t, (_, field) in _LISTS.items()}, _NODES: "node", _CLUSTER: "name",
                        _USERS: "userid"}


def _keyed(data: list[Any], field: str) -> bool:
    """Every row names itself by `field`. Absent is no proof: a row memory cannot key may be the very
    thing a retire would call gone (a field renamed in another version, a garbled answer)."""
    return all(isinstance(r, dict) and _text(r.get(field)) for r in data)


def _sighted(who: str | None) -> str | None:
    """The flag value a credential naming this user is seen by (`whole:<user@realm>`), or None when it
    is not one a flag may name: unknown is blind."""
    return f"whole:{who}" if isinstance(who, str) and len(who) <= memory.TEXT and _WHO.fullmatch(who) else None


# ---- feeding: one vendor answer at a time ------------------------------------------------------------

def _owner(template: str, args: Mapping[str, Any], fields: str | None, data: Any, box: str, evaluating: bool,
           db: sqlite3.Connection | None, who: str | None) -> str | None:
    """The list a WHOLE read of `template` owns, or None (a read that may only add or refresh): an
    argument, a field subset, a door's own look for a verdict, a box with no name, a non-list, or a list
    with a row that does not name itself by its field never owns; nor does an empty node list, the
    cluster status, or a users list without the sight of the credential that made this read (`who`)
    and its own row showing a role that sees every user."""
    if evaluating or fields is not None or not box or not isinstance(data, list) or args:
        return None
    if not _keyed(data, _KEY.get(template, "")):
        return None
    if template in _LISTS:
        return template
    if template == _NODES:
        return template if data else None
    if template == _USERS:
        seen = _sighted(who)
        if db is not None and seen is not None and memory._meta(db, _PLANE, box, _USERS_SIGHT) == seen:
            # A role is the box admin's to change after a learn: the answer's own row shows the role it
            # was read under, so it owns only while that row is there once and still sees every user.
            mine = [r for r in data if isinstance(r, dict) and r.get("userid") == who]
            role = mine[0].get("role") if len(mine) == 1 else None
            if isinstance(role, str) and role in _SEES_EVERY_USER:
                return template
    return None


def _ingest(f: memory._Feed, template: str, data: Any) -> None:
    rows = [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
    for r in rows:
        if template in _LISTS:
            kind, field = _LISTS[template]
            vid = _text(r.get(field))
            if vid:
                kept = {k.replace("-", "_"): r[k] for k in _DETAIL.get(kind, ()) if r.get(k) is not None}
                f.put(kind, vid, ident=vid, name=_text(r.get("name")) if kind in _NAMED else vid,
                      detail=kept or None)
        elif template in (_NODES, _CLUSTER):
            node = _text(r.get(_KEY[template]))
            if node:
                f.put("node", node, ident=node, name=node)
        elif template == _USERS:
            uid = _text(r.get("userid"))
            if uid:                     # never the mail, first and last names, the comment or the keys
                kept = {k: r[k] for k in ("role", "realm", "enable") if r.get(k) is not None}
                f.put("user", uid, ident=uid, name=_text(r.get("username")), detail=kept or None)


# ---- answering ---------------------------------------------------------------------------------------

def _ok(*ids: Any) -> bool:
    return all(isinstance(i, str) and memory._ID.fullmatch(i) for i in ids)


#: Each kind's own live read (`{}` its id) and its list: the own read when the id passes `_ID`, else the
#: list, which reads it too. A cidr's `/` and a userid's `@` are no path piece, an action object has no
#: read of its own, and a PBS remote's own read failed live: those hand out their list.
_READS: dict[str, tuple[str | None, str]] = {
    "domain": ("/config/domains/{}", _DOMAINS), "transport": ("/config/transport/{}", "/config/transport"),
    "dkim-domain": ("/config/dkim/domains/{}", "/config/dkim/domains"),
    "tlspolicy": ("/config/tlspolicy/{}", "/config/tlspolicy"),
    "rule": ("/config/ruledb/rules/{}/config", "/config/ruledb/rules"),
    "who": ("/config/ruledb/who/{}/objects", "/config/ruledb/who"),
    "what": ("/config/ruledb/what/{}/objects", "/config/ruledb/what"),
    "when": ("/config/ruledb/when/{}/objects", "/config/ruledb/when"),
    "node": ("/nodes/{}/status", _NODES), "mynetwork": (None, "/config/mynetworks"),
    "action": (None, "/config/ruledb/action/objects"), "pbs": (None, "/config/pbs"), "user": (None, _USERS),
}


def _paths(r: Mapping[str, Any]) -> list[str]:
    """The concrete GET that reads this thing live: its own read built from an id that passes `_ID`, else
    its list; memory checks each with `_published`."""
    read = _READS.get(r["kind"])
    if read is None:
        return []
    own, whole = read
    return [own.format(r["key"]) if own is not None and _ok(r["key"]) else whole]


def _show(r: Mapping[str, Any]) -> dict[str, Any]:
    """The entry's id is the vendor's (`ident`); a rule carries its priority, whether it is active and
    its direction, as the vendor gives them."""
    if r["kind"] == "rule":
        d = json.loads(r["detail"]) if r.get("detail") else {}
        return {"id": r["ident"], "priority": d.get("priority"), "active": d.get("active"),
                "direction": d.get("direction")}
    return {"id": r["ident"]}


# ---- learn: the one deliberate pass ------------------------------------------------------------------

def _learn(read: Callable[..., dict[str, Any] | None], db_at: Callable[[], sqlite3.Connection], box: str,
           start: float, gaps: list[str], who: Callable[[], str | None]) -> memory.LearnTally:
    """The credential's own user record first (its role decides whether the users list may own), then
    every config list, the node list, and the users list last. `read` stops at the budget by raising
    `memory._Spent` (the frame names it); what was gathered before still tallies."""
    plane = _PLANE
    skipped_before = int(memory._meta(db_at(), plane, box, "skipped_ids") or 0)
    sees: bool | None = None

    def sight(v: str) -> None:
        db = db_at()
        with db:
            memory._set(db, plane, box, _USERS_SIGHT, v)
    # Not sight until this pass's own record shows it: a "whole" from an earlier credential never outlives
    # a pass that stops (refused, failed, out of budget) before the record is read.
    sight("partial")
    try:
        before = who()
        if before is None or _sighted(before) is None or not _ok(*before.split("@")):
            gaps.append("the served credential names no user@realm a path may carry: the users list owns nothing")
        else:
            env = read(f"/access/users/{before}", _ME)
            whole, mine = consult._data_of(env) if env is not None else (False, None)
            role = mine.get("role") if whole and isinstance(mine, dict) and mine.get("userid") == before else None
            if who() != before:
                gaps.append("the served credential names no user this pass could hold steady (it changed while "
                            "its own record was read): the users list owns nothing")
            elif isinstance(role, str) and role in _SEES_EVERY_USER:
                sight(f"whole:{before}")    # before the lists feed, so this pass's users read owns its list
                sees = True
            else:
                sees = False if env is not None else None
                named = role if isinstance(role, str) and role in _ROLES else "unread or unknown"
                gaps.append(f"this credential's role ({named}) is not one PMG shows every user to: memory holds "
                            "the users it may see, which may not be all")
        for t in (*_LISTS, _NODES, _USERS):
            read(t, t)
    except memory._Spent:                   # the frame has named it; what was listed still tallies
        pass

    def this_pass(db: sqlite3.Connection, k: str) -> bool:
        v = memory._meta(db, plane, box, k)
        return v is not None and float(v) >= start
    # A list read on this pass that could not own (a row memory cannot key, an empty node list, a users
    # answer whose own row no longer sees every user) retired nothing: the pass is not whole, and a users
    # list that did not own leaves no whole sight.
    db = db_at()
    for t in (*_LISTS, _NODES, *((_USERS,) if sees else ())):
        if this_pass(db, f"read:{t}") and not this_pass(db, f"whole:{t}"):
            gaps.append(f"GET {t} was read but could not own its list: nothing it no longer lists was retired")
            if t == _USERS:
                sees = False
    kept = [(t, f"read:{t}") for t in (*_LISTS, _NODES, _USERS)]
    (count,) = db_at().execute("SELECT count(*) FROM entity WHERE plane=? AND box=? AND kind='domain' AND "
                               "gone_at IS NULL AND last_seen >= ?", (plane, box, start)).fetchone()

    def after_kept(db: sqlite3.Connection) -> list[str]:
        moved = int(memory._meta(db, plane, box, "skipped_ids") or 0) - skipped_before
        if moved > 0:
            return [f"{moved} thing(s) not kept on this pass: an id longer than memory keeps "
                    f"({memory.TEXT} characters)"]
        return []
    return memory.LearnTally(kept=tuple(kept), count_kind="domains", count=count, sees=sees, after_kept=after_kept)


class _Pmg:
    """PMG's `memory.PlaneShape`."""

    plane: str = _PLANE
    feeds: frozenset[str] = FEEDS
    vendor_kinds: frozenset[str] = VENDOR_KINDS
    kind_order: tuple[str, ...] = KIND_ORDER
    relating_owners: frozenset[str] = frozenset()
    answers_uses: bool = False          # nothing relates on PMG
    id_names: frozenset[str] = frozenset()
    no_ident_kinds: frozenset[str] = frozenset()
    no_name_kinds: frozenset[str] = frozenset()
    global_ids: frozenset[str] = frozenset()      # no kind is matched by its key
    next_live: tuple[str, ...] = (f"GET {_DOMAINS}",)
    whole_owner: str = _DOMAINS
    token_sight: bool = True            # the users list is filtered by the credential's role

    def owner(self, template: str, bound: Mapping[str, str], args: Mapping[str, Any], fields: str | None,
              data: Any, box: str, evaluating: bool, *, db: sqlite3.Connection | None = None,
              who: str | None = None) -> str | None:
        return _owner(template, args, fields, data, box, evaluating, db, who)

    def ingest(self, f: memory._Feed, template: str, bound: dict[str, str], args: Mapping[str, Any],
               data: Any) -> None:
        _ingest(f, template, data)

    def relate(self, db: sqlite3.Connection, box: str, t: float) -> None:
        """No relations are judged on PMG: nothing to relate."""

    def paths(self, r: Mapping[str, Any]) -> list[str]:
        return _paths(r)

    def show(self, r: Mapping[str, Any]) -> dict[str, Any]:
        return _show(r)

    def learn(self, read: Callable[..., dict[str, Any] | None], db_at: Callable[[], sqlite3.Connection],
              box: str, start: float, gaps: list[str], *,
              who: Callable[[], str | None] = lambda: None) -> memory.LearnTally:
        return _learn(read, db_at, box, start, gaps, who)


SHAPE: memory.PlaneShape = _Pmg()
memory.SHAPES[_PLANE] = SHAPE
