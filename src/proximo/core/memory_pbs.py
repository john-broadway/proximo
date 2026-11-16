"""PBS'S SHAPE for the estate memory (`memory.PlaneShape`): datastores, namespaces, backup groups,
remotes and the sync, verify and prune jobs, each kept in the vendor's own words (the field names of
the PBS api-viewer schema) and answered by the vendor's own id. No edges: PBS's relations are not
judged here. This module registers itself in `memory.SHAPES` when imported (`memory` imports it at
its end), so either import order works.

    read                                   kind        key                     ident        name
    /admin/datastore  /config/datastore    datastore   store                   store        store
    /admin/datastore/{store}/namespace     namespace   {store}/{ns}            ns           ns
    /admin/datastore/{store}/groups        group       {store}/{ns}/{type}/{id} {type}/{id}  backup-id
    /config/remote                         remote      name                    name         name
    /config/sync|verify|prune              *-job       id                      id           id

`/admin/datastore` spells a store `store`, `/config/datastore` spells it `name`.

ABSENT IS NOT PROOF. PBS filters every list here by the token's privileges and answers what it hides
as absent: a datastore, its namespaces and groups, and the verify and prune jobs on it by the
datastore privileges, a remote by Remote.Audit, a pull sync job by both, a push sync job by
Datastore.Audit and RemoteDatastore.Audit. So a list owns (may retire) only when the box's last
`learn` read a permission map showing that sight whole (`_NEEDS`): Datastore.Audit reaching every
datastore (`sees_every("Datastore.Audit", "/datastore")`, the meta flag `datastore_sight`),
Remote.Audit reaching every remote (`remote_sight`) and RemoteDatastore.Audit reaching every remote
datastore (`push_sight`), both judged at `/remote`.

SIGHT IS THE TOKEN'S, NOT THE BOX'S. Arming and disarming swap the served token behind one box URL,
so a flag is stored as `whole:<id>`, the token's public id (`user@realm!name`, `arm.served_id`; never
a secret byte), and a read owns only when the token that made it names the same id. Learn writes
every flag "partial" first on every pass, and raises one only when the id it read before the map and
after it agree. Unknown, unread, partial, another token's, or an id that cannot be read: a list adds
and refreshes only.

A ROW MUST BE THE VENDOR'S, AND NAME ITSELF. Absent is not proof for a row either. What a row carries
is the vendor's to say, and `memory.feed` holds every list to it first (the one JSON's `row` column).
Beside that stands memory's own need: a list with a row it cannot key (`_row_id`: an id sent empty,
not a record) owns nothing, because that row may be the very thing a retire would call gone.
`_ingest` keeps rows through the same reader.

SYNC JOBS HAVE A DIRECTION. A bare `/config/sync` lists the pull jobs only; push jobs answer only to
`sync-direction=push` or `all`. So learn reads it with `sync-direction=all`, and only that read, with
every sight whole, owns the list: a bare or one-direction read never retires a job.

The root namespace (`""`) is never an entity: a groups read with `ns` absent and with `ns=""` reads
the same list and owns it under one name. A group's `comment` (the first line of its notes) and
`owner` are never kept; its backup-id is the vendor's second id (`id_names`), so the bare `105`
finds `vm/105` and `ct/105`.
"""
from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Callable, Mapping
from typing import Any

from proximo.core import consult, estate, memory

_PLANE = "pbs"
_STORES = "/admin/datastore"
_STORE_CONFIG = "/config/datastore"
_NAMESPACES = "/admin/datastore/{store}/namespace"
_GROUPS = "/admin/datastore/{store}/groups"
_SYNC = "/config/sync"
_JOBS = {_SYNC: "sync-job", "/config/verify": "verify-job", "/config/prune": "prune-job"}
_CONFIG_LISTS = (_STORE_CONFIG, "/config/remote", *_JOBS)
#: The one way of asking for the sync list that lists every job: pull and push alike.
_SYNC_ALL = {"sync-direction": "all"}
#: The meta keys `learn` writes from the token's permission map: `whole:<id>` when it shows the
#: privilege reaching every datastore / remote / remote datastore for the token named `<id>`; anything
#: else (or absent) is not sight.
_DATASTORE_SIGHT = "datastore_sight"
_REMOTE_SIGHT = "remote_sight"
_PUSH_SIGHT = "push_sight"
#: A token's public id (`user@realm!name`), or a ticket's user (`user@realm`): what a flag may name.
_WHO = re.compile(r"[^\s!=:@]+@[^\s!=:@]+(?:![^\s!=:@]+)?")
FEEDS = frozenset({_STORES, _NAMESPACES, _GROUPS, *_CONFIG_LISTS})
#: The sights a whole read of each list needs before it may own (and so retire) what it lists: PBS
#: filters each by these privileges and answers what the token cannot see as absent.
_NEEDS: dict[str, tuple[str, ...]] = {
    _STORES: (_DATASTORE_SIGHT,), _STORE_CONFIG: (_DATASTORE_SIGHT,), _NAMESPACES: (_DATASTORE_SIGHT,),
    _GROUPS: (_DATASTORE_SIGHT,), "/config/verify": (_DATASTORE_SIGHT,), "/config/prune": (_DATASTORE_SIGHT,),
    "/config/remote": (_REMOTE_SIGHT,), _SYNC: (_REMOTE_SIGHT, _DATASTORE_SIGHT, _PUSH_SIGHT),
}
#: The kinds find's exact lookup takes: the vendor's nouns, a job by what it does.
VENDOR_KINDS = frozenset({"datastore", "namespace", "group", "remote", "sync-job", "verify-job", "prune-job"})
#: What is backed up first, then what holds it, then what moves it.
KIND_ORDER = ("group", "datastore", "namespace", "remote", "sync-job", "verify-job", "prune-job")
#: The vendor's backup types (`backup-type`): the only words a group's path may carry.
_TYPES = frozenset({"vm", "ct", "host"})


def _text(v: Any) -> str | None:
    """A non-empty string the vendor gave, or None (a number or a null is no id here)."""
    return v if isinstance(v, str) and v else None


def _sighted(who: str | None) -> str | None:
    """The flag value a token with this id is seen by (`whole:<id>`), or None when the id is not one a
    flag may name: unknown is blind."""
    return f"whole:{who}" if isinstance(who, str) and len(who) <= memory.TEXT and _WHO.fullmatch(who) else None


def _groups_read(store: str, ns: str) -> str:
    """The meta key a groups read of one namespace is kept under: learn's kept check reads it per
    (store, namespace), so one namespace's read never answers for another's."""
    return f"read:{_GROUPS}|{json.dumps({'ns': ns, 'store': store}, sort_keys=True)}"


def _ns(args: Mapping[str, Any]) -> str:
    """The namespace a groups read was asked for: absent and `""` are both the root."""
    v = args.get("ns")
    return "" if v is None else str(v)


#: The field a row of each one-id list names itself by.
_ID_FIELD: dict[str, str] = {_STORES: "store", _STORE_CONFIG: "name", "/config/remote": "name",
                             **dict.fromkeys(_JOBS, "id")}


def _row_id(template: str, r: Any) -> str | None:
    """The id a row of `template` names itself by, as `_ingest` keeps it and `_owner` judges it (one
    reader, so the two never disagree), or None for a row memory cannot key. A namespace row answers
    its `ns`: the root is the vendor's own `""`, a row of every namespace list, named and never kept.
    A group row needs both halves of its id and answers `type/id`."""
    if not isinstance(r, dict):
        return None
    if template == _NAMESPACES:
        ns = r.get("ns")
        return ns if isinstance(ns, str) else None
    if template == _GROUPS:
        kind, bid = _text(r.get("backup-type")), _text(r.get("backup-id"))
        return f"{kind}/{bid}" if kind and bid else None
    return _text(r.get(_ID_FIELD.get(template, "")))


def _sees(db: sqlite3.Connection, box: str, template: str, seen: str | None) -> bool:
    """The box's last learn judged every sight `template` needs whole for the token `seen` names."""
    return seen is not None and all(memory._meta(db, _PLANE, box, k) == seen for k in _NEEDS.get(template, ()))


# ---- feeding: one vendor answer at a time ------------------------------------------------------------

def _owner(template: str, bound: Mapping[str, str], args: Mapping[str, Any], fields: str | None,
           data: Any, box: str, evaluating: bool, db: sqlite3.Connection | None, who: str | None) -> str | None:
    """The list a WHOLE read of `template` owns, or None (a read that may only add or refresh): a
    field subset, a door's own look for a verdict, a box with no name, or a non-list never owns, nor
    does a list whose sights (`_NEEDS`) the box's last learn did not judge whole FOR THE TOKEN THAT
    MADE THIS READ (`who`): unknown is blind. Nor does a list with a row that does not name itself
    (`_row_id`). The sync list owns only when asked for every direction."""
    if evaluating or fields is not None or not box or not isinstance(data, list):
        return None
    if db is None or not _sees(db, box, template, _sighted(who)):
        return None
    if any(_row_id(template, r) is None for r in data):      # absent is no proof: such a list retires nothing
        return None
    if template == _SYNC:
        return template if dict(args) == _SYNC_ALL else None
    if template == _STORES:
        return None if args else "datastores"
    if template in _CONFIG_LISTS:
        return None if args else template
    if template == _NAMESPACES:
        return None if args else f"namespaces/{bound.get('store')}"
    if template == _GROUPS:
        return f"groups/{bound.get('store')}/{_ns(args)}" if set(args) <= {"ns"} else None
    return None


def _ingest(f: memory._Feed, template: str, bound: dict[str, str], args: Mapping[str, Any], data: Any) -> None:
    rows = [r for r in data if isinstance(r, dict)] if isinstance(data, list) else []
    store = _text(bound.get("store"))
    if template == _GROUPS and store:
        f.mark(_groups_read(store, _ns(args)))
    for r in rows:
        vid = _row_id(template, r)
        if not vid:                                 # a row with no id, or the root namespace: never kept
            continue
        if template in (_STORES, _STORE_CONFIG):
            m = r.get("maintenance" if template == _STORES else "maintenance-mode")
            f.put("datastore", vid, ident=vid, name=vid, detail={"maintenance": m} if m is not None else None)
        elif template == _NAMESPACES:
            if store:
                f.put("namespace", f"{store}/{vid}", ident=vid, name=vid, detail={"store": store})
        elif template == _GROUPS:
            kind, bid, ns = r["backup-type"], r["backup-id"], _ns(args)
            if store:                               # `comment` and `owner` are never kept
                f.put("group", f"{store}/{ns}/{vid}", ident=vid, name=bid,
                      detail={"store": store, "ns": ns, "type": kind, "id": bid,
                              "last_backup": r.get("last-backup"), "count": r.get("backup-count")})
        elif template == "/config/remote":          # what the withhold left: the host, never a secret
            f.put("remote", vid, ident=vid, name=vid, detail={"host": r.get("host")})
        elif template in _JOBS:
            fields = ("store", "remote", "remote-store", "ns") if template == "/config/sync" else ("store", "ns")
            f.put(_JOBS[template], vid, ident=vid, name=vid,
                  detail={k.replace("-", "_"): r[k] for k in fields if r.get(k) is not None})


# ---- answering ---------------------------------------------------------------------------------------

def _ok(*ids: Any) -> bool:
    return all(isinstance(i, str) and memory._ID.fullmatch(i) for i in ids)


def _group_args(d: Mapping[str, Any]) -> dict[str, str] | None:
    """A group's own snapshots read, as the vendor's published params (`backup-type`, `backup-id`,
    and `ns` when not the root), or None when any piece fails the check a path piece must pass: the
    store and backup-id through `_ID`, the type one the vendor publishes, each namespace level
    through `_ID`. The path alone reads the root namespace, so these ride beside it."""
    ns = d.get("ns")
    if not (_ok(d.get("store"), d.get("id")) and d.get("type") in _TYPES and isinstance(ns, str)
            and (ns == "" or _ok(*ns.split("/")))):
        return None
    return {"backup-type": d["type"], "backup-id": d["id"], **({"ns": ns} if ns else {})}


def _paths(r: Mapping[str, Any]) -> list[str]:
    """The concrete GETs that read this thing live, built only from pieces that pass `_ID` (and, for
    a group, a `backup-type` the vendor publishes); memory checks each with `_published`."""
    kind, key = r["kind"], r["key"]
    d = json.loads(r["detail"]) if r.get("detail") else {}
    if kind == "datastore" and _ok(key):
        return [f"/admin/datastore/{key}/status"]
    if kind == "namespace" and _ok(d.get("store")):
        return [f"/admin/datastore/{d['store']}/namespace"]
    if kind == "group" and _group_args(d) is not None:
        return [f"/admin/datastore/{d['store']}/snapshots"]
    if kind == "remote" and _ok(key):
        return [f"/config/remote/{key}"]
    if kind in ("sync-job", "verify-job", "prune-job") and _ok(key):
        return [f"/config/{kind.removesuffix('-job')}/{key}"]
    return []


def _show(r: Mapping[str, Any]) -> dict[str, Any]:
    """The entry's id is the vendor's (`ident`), never memory's composite key; a group carries its
    store and namespace and, when every piece passes the path check, `args`: the vendor's own params
    for its snapshots read (the path stays a plain string); a namespace carries its store."""
    d = json.loads(r["detail"]) if r.get("detail") else {}
    if r["kind"] == "group":
        args = _group_args(d)
        return {"id": r["ident"], "store": d.get("store"), "ns": d.get("ns"), **({"args": args} if args else {})}
    if r["kind"] == "namespace":
        return {"id": r["ident"], "store": d.get("store")}
    return {"id": r["ident"]}


# ---- learn: the one deliberate pass ------------------------------------------------------------------

def _learn(read: Callable[..., dict[str, Any] | None], db_at: Callable[[], sqlite3.Connection], box: str,
           start: float, gaps: list[str], who: Callable[[], str | None]) -> memory.LearnTally:
    """The token's permission map, the datastore list, the config lists (the sync list in every
    direction), then per datastore listed this pass its namespaces (the vendor's default depth lists
    nested ones too) and per namespace, the root included, its backup groups. `read` stops at the
    budget by raising `memory._Spent` (the frame names it); what was gathered before still tallies."""
    plane = _PLANE
    stores: list[str] = []
    asked: list[tuple[str, str]] = []           # (store, namespace) whose groups this pass asked for
    # An id past memory's bound is not kept (`_Feed.put` counts it under `skipped_ids`). A namespace's
    # key carries its whole path, so a deep one can pass the bound: it is then no entity and its groups
    # are never read. Counted before the pass and after it, the difference is a gap, never silence.
    skipped_before = int(memory._meta(db_at(), plane, box, "skipped_ids") or 0)
    sees: bool | None = None
    seen: str | None = None                     # the flag value of the token the permission map was read under

    def sight(k: str, v: str) -> None:
        db = db_at()
        with db:
            memory._set(db, plane, box, k, v)
    # Not sight until this pass's permission map shows it: a "whole" from an earlier token never outlives
    # a pass that stops (refused, failed, out of budget) before the map is read.
    sight(_DATASTORE_SIGHT, "partial")
    sight(_REMOTE_SIGHT, "partial")
    sight(_PUSH_SIGHT, "partial")

    def listed(kind: str, prefix: str = "") -> list[tuple[str, str]]:
        """What this pass's reads kept of `kind` (a read that owns nothing still refreshes `last_seen`):
        the datastores right after their list, a store's namespaces by its key prefix."""
        return db_at().execute(
            "SELECT key, ident FROM entity WHERE plane=? AND box=? AND kind=? AND last_seen >= ? AND "
            "gone_at IS NULL AND substr(key, 1, ?) = ? ORDER BY key",
            (plane, box, kind, start, len(prefix), prefix)).fetchall()
    try:
        # The map FIRST: each sight is judged before any list feeds, so this pass's lists own when the
        # token sees them whole (and the datastore list begins `changed`); a map that fails leaves every
        # sight "partial" and every list adds only. The map is the token's that read it: its id is read
        # before and after, and a sight is that id's only when the two agree.
        before = who()
        env = read("/access/permissions", "/access/permissions", "all")
        seen = _sighted(before) if who() == before else None
        whole, perms = consult._data_of(env) if env is not None else (False, None)
        held = estate.Estate(permissions=estate.permission_map(perms)) if whole else None
        if seen is None:
            gaps.append("the served token names no id this pass could hold steady (it is not a token, or it "
                        "changed while the permission map was read): no list owns what it lists")
            held = None
        sees = held.sees_every("Datastore.Audit", "/datastore") if held is not None else None
        if sees is True and seen is not None:   # before the lists feed, so this pass's reads own them
            sight(_DATASTORE_SIGHT, seen)
        else:
            gaps.append("this token's permission map does not show Datastore.Audit reaching every datastore (or "
                        "could not be read): memory holds the token's backups, which may not be all of them")
        remotes = held.sees_every("Remote.Audit", "/remote") if held is not None else None
        if remotes is True and seen is not None:
            sight(_REMOTE_SIGHT, seen)
        else:
            gaps.append("this token's permission map does not show Remote.Audit on /remote: remotes and sync jobs "
                        "may be hidden")
        push = held.sees_every("RemoteDatastore.Audit", "/remote") if held is not None else None
        if push is True and seen is not None:
            sight(_PUSH_SIGHT, seen)
        else:
            gaps.append("this token's permission map does not show RemoteDatastore.Audit on /remote: push sync "
                        "jobs may be hidden")
        if held is not None:
            sees = sees is True and remotes is True and push is True
        read(_STORES, _STORES)
        store_keys = listed("datastore")    # before `/config/datastore` feeds: the stores the list named
        for t in _CONFIG_LISTS:
            read(t, t, None, _SYNC_ALL if t == _SYNC else None)
        for key, _ in store_keys:
            if _ok(key):
                stores.append(key)
            else:
                gaps.append("a datastore name is not one a path may carry; its namespaces were not read")
        for s in stores:
            read(f"/admin/datastore/{s}/namespace", _NAMESPACES)
        for s in stores:
            for ns in ["", *(ident for _, ident in listed("namespace", f"{s}/"))]:
                asked.append((s, ns))
                read(f"/admin/datastore/{s}/groups", _GROUPS, None, {"ns": ns} if ns else None)
    except memory._Spent:                   # the frame has named it; what was listed still tallies
        pass
    # A list read on this pass under a sight judged whole that still could not own (a row memory cannot
    # key) retired nothing: the pass is not whole, and it says so. A list without its sight is already
    # named above, once per sight.
    # Judged by the token the map was read under (`seen`), not the one served now: a token swapped mid-pass
    # owns nothing from then on, and each list it read is named.
    db, token = db_at(), seen
    lists = [(_STORES, _STORES, f"read:{_STORES}", "datastores"),
             *((t, t, f"read:{t}", t) for t in _CONFIG_LISTS),
             *((f"/admin/datastore/{s}/namespace", _NAMESPACES, f"read:{_NAMESPACES}|{json.dumps({'store': s})}",
                f"namespaces/{s}") for s in stores),
             *((f"/admin/datastore/{s}/groups" + (f" (ns {ns})" if ns else ""), _GROUPS, _groups_read(s, ns),
                f"groups/{s}/{ns}") for s, ns in asked)]
    gaps.extend(memory._read_not_owned(db, plane, box, start, [
        (what, stamp, owner) for what, template, stamp, owner in lists if _sees(db, box, template, token)]))
    kept = [(t, f"read:{t}") for t in (_STORES, *_CONFIG_LISTS)]
    for s in stores:
        bound = json.dumps({"store": s})
        kept.append((f"/admin/datastore/{s}/namespace", f"read:{_NAMESPACES}|{bound}"))
    # every namespace's groups read, each its own (the root always, even when the budget stopped first)
    for s, ns in dict.fromkeys([*((s, "") for s in stores), *asked]):
        kept.append((f"/admin/datastore/{s}/groups" + (f" (ns {ns})" if ns else ""), _groups_read(s, ns)))
    (count,) = db_at().execute("SELECT count(*) FROM entity WHERE plane=? AND box=? AND kind='group' AND "
                               "gone_at IS NULL AND last_seen >= ?", (plane, box, start)).fetchone()

    def after_kept(db: sqlite3.Connection) -> list[str]:
        moved = int(memory._meta(db, plane, box, "skipped_ids") or 0) - skipped_before
        if moved > 0:
            return [f"{moved} datastore(s)/namespace(s)/group(s) not kept on this pass: an id longer than memory "
                    f"keeps ({memory.TEXT} characters with its store and namespace); a namespace not kept has "
                    "its groups unread"]
        return []
    return memory.LearnTally(kept=tuple(kept), count_kind="groups", count=count, sees=sees, after_kept=after_kept)


class _Pbs:
    """PBS's `memory.PlaneShape`."""

    plane: str = _PLANE
    feeds: frozenset[str] = FEEDS
    vendor_kinds: frozenset[str] = VENDOR_KINDS
    kind_order: tuple[str, ...] = KIND_ORDER
    relating_owners: frozenset[str] = frozenset()
    answers_uses: bool = False          # nothing relates on PBS
    id_names: frozenset[str] = frozenset({"group"})
    no_ident_kinds: frozenset[str] = frozenset()
    no_name_kinds: frozenset[str] = frozenset()
    global_ids: frozenset[str] = frozenset()      # no kind is matched by its key
    next_live: tuple[str, ...] = ("GET /admin/datastore",)
    whole_owner: str = "datastores"
    token_sight: bool = True            # every list is filtered by the token's privileges

    def owner(self, template: str, bound: Mapping[str, str], args: Mapping[str, Any], fields: str | None,
              data: Any, box: str, evaluating: bool, *, db: sqlite3.Connection | None = None,
              who: str | None = None) -> str | None:
        return _owner(template, bound, args, fields, data, box, evaluating, db, who)

    def ingest(self, f: memory._Feed, template: str, bound: dict[str, str], args: Mapping[str, Any],
               data: Any) -> None:
        _ingest(f, template, bound, args, data)

    def relate(self, db: sqlite3.Connection, box: str, t: float) -> None:
        """No relations are judged on PBS: nothing to relate."""

    def paths(self, r: Mapping[str, Any]) -> list[str]:
        return _paths(r)

    def show(self, r: Mapping[str, Any]) -> dict[str, Any]:
        return _show(r)

    def learn(self, read: Callable[..., dict[str, Any] | None], db_at: Callable[[], sqlite3.Connection],
              box: str, start: float, gaps: list[str], *,
              who: Callable[[], str | None] = lambda: None) -> memory.LearnTally:
        return _learn(read, db_at, box, start, gaps, who)


SHAPE: memory.PlaneShape = _Pbs()
memory.SHAPES[_PLANE] = SHAPE
