"""PDM'S SHAPE for the estate memory (`memory.PlaneShape`): the remotes a Proxmox Datacenter Manager
holds, and per remote its guests (qemu, lxc), nodes and storages, a PBS remote's datastores and node,
and PDM's own views, each kept in the vendor's own words (the field names a PDM 1.1 answered) and
answered by the vendor's own ids. No edges are made. This module registers itself in `memory.SHAPES`
when imported (`memory` imports it at its end), so either import order works.

    read                                   kind        key                              ident     name
    /remotes/remote                        remote      id                               id        id
    /pve/remotes/{remote}/resources        qemu|lxc    id (remote/<r>/guest/<vmid>)     vmid      name
                                           node        id (remote/<r>/node/<node>)      node      node
                                           storage     id (remote/<r>/storage/<n>/<s>)  storage   storage
    /pbs/remotes/{remote}/datastore        datastore   remote/<r>/datastore/<name>      name      name
    /resources/list (`pbs-node` rows only) node        id (remote/<r>/node/<name>)      name      name
    /config/views                          view        id                               id        id

THE VENDOR'S ONE-STRING ID. PDM spells a guest, node, storage and datastore by one string that carries
its remote (`id`, the shape above, read live). Those kinds are keyed by that string UNCHANGED
(`global_ids`), so `where` answers it exactly beside the vmid or id within the remote (`ident`) and the
vendor's name; an id past memory's bound is not kept at all (counted, and learn says incomplete), never
cut. The per-remote datastore list carries only a datastore's `name`: its key is composed as
`remote/<r>/datastore/<name>` (`_datastore_id`), which is byte for byte the `id` the combined list gives
the same datastore (seen live, one datastore, read twice). A vmid is not unique across remotes:
`where 105` answers every remote's 105, each entry naming its remote (`show`) and carrying its own
read. A remote and a view are keyed by their own id.

THE KIND WORDS and their basis, none claimed as more: `qemu`, `lxc` (path segments of the vendor's
guest reads; `qemu`, `node` and `storage` are also live `type` values of the per-remote resources
list; `lxc` as a `type` was not seen live, the lab had no container), `node` (the singular of the
path segment `nodes`), `storage`, `datastore` and `remote` (path segments), `view` (the singular of
`views`). The kinds are shown in THIS SHAPE'S OWN ORDER, not the GUI's: remotes, then nodes, guests,
storages, datastores, views.

WHO OWNS WHAT, AT MOST ONE OWNER PER KIND PER REMOTE (a PBS remote's node has none). The two lists the
vendor filters by the token, the remotes and the views, own only inside a learn's own pass; a remote's
own list owns between learns too (THE TOKEN'S SIGHT, below). A list owns (may retire what it no longer
lists) only when it was asked with no argument and no field subset, answered a list in which EVERY row
yields its id (a row memory cannot key may be the very thing a retire would call gone), and the token
that made the read has whole sight (below):
- the remotes: `/remotes/remote`, when it lists at least one remote and every row has a string `id`;
- a PVE remote's guests, nodes and storages: `/pve/remotes/{remote}/resources`, scoped to that remote
  (one remote's retire never touches another's), when it lists at least one thing. Each row must carry
  a string `id` and a string `type`, and a guest its `vmid`, a node its `node`, a storage its `storage`.
  A row of a type this shape does not keep is not kept and, keyed, does not stop owning, but learn
  names its type and says incomplete;
- a PBS remote's datastores: `/pbs/remotes/{remote}/datastore`, scoped to that remote, when it lists
  at least one datastore and every row has a string `name`;
- the views: `/config/views`, when every row has a string `id` (PDM's own config: an empty list owns).
The combined `/resources/list` never owns and feeds ONLY a PBS remote's node (`pbs-node` rows), the one
thing no per-remote list reads, and only from the group of a remote memory holds and has not retired:
a kind a per-remote list owns is never fed from it, so a thing its owner retired does not come back from
the combined list. It can come back from a read of its own list that could not own (an argument, a
field subset, another token's read, a read without whole sight): that read adds it, and it stays shown
until its owner's next whole read, which retires it, dated by that read, if it does not list it (the
frame's rule: every owner that dropped it judges it again), or until its remote's removal takes it
first (below). A plain read of its own list by the token whose sight is whole owns: it lists it, so its
owner holds it until a whole read leaves it out.
The combined list filters by the token, carries a remote that did not answer as an `error` group
(which feeds nothing) and takes the vendor's `max-age`, so a group for a remote PDM no
longer lists may still come (it feeds nothing unless memory still holds that remote, and learn names it
either way). A group whose remote id no path may carry feeds nothing, held or not.
A REMOVED REMOTE TAKES ITS THINGS: right after every remotes read that owns (a learn's), every thing
still present whose remote memory holds as gone (retired by that read or an earlier one) is gone too
(the frame's `relate` hook, `relating_owners`; no edge is made), and nothing else: a thing of another
remote stays. So a remote removed from PDM takes its things at the next learn. A PBS remote's node,
which no list owns, is added and refreshed from the combined list while its remote is held and not
gone, retires only with its remote, and cannot come back from the combined list until its remote is
listed again.

A REMOTE THAT DOES NOT ANSWER (live: three powered-off remotes). Its own lists answer an error (a 400),
so they feed nothing and retire nothing; the combined list carries it as `{remote, error}` with no
rows, and an error group feeds nothing (its error text, which carries an address, is never kept);
the remotes list still lists it. A learn names every remote whose own read failed, every PBS
remote the combined list carried as an error or left out, and every group the combined list carried
for a remote this pass's remotes list does not (by its id only when a path may carry it). Not seen
live: a remote that answered and then stopped, which PDM may serve from its cache within `max-age`.
Memory stamps its own read time and claims no freshness; an owning read must list at least one thing
(views aside), so a degenerate empty answer retires nothing.

LEARN IS WHOLE only when it listed, on this pass, everything memory shows present for this box on this
plane. Otherwise it says incomplete and how many things it shows present that this pass did not list:
a thing nothing owns (one another token's read of a remote's own list added, for a remote this pass's
remotes list does not show, so learn reads no list of it), a thing a file written before the frame's
rule left shown after its owner retired it (no owner's whole read retires it until some read lists it
again, so one that has left the vendor stays shown and counted until its remote is removed, memory
evicts it at its size bound or the file is deleted), a PBS remote's node its group no
longer carries, the things of a remote that did not answer. It also names a listed remote whose type is
not one this shape reads (`pve`, `pbs`; or no type, or one that is not a string), whose things are then
not read, and a remote listed as one product while memory shows things it kept of it as the other (its id
came back under another product). This retires nothing: what it counts stays shown. The count is the
first gap, so the three a `why` shows always hold it.

THE TOKEN'S SIGHT. Live, with a throwaway token: the remotes list, the combined list and the views
list FILTER by the token's privileges (a remote out of reach is left out, with no error); the
per-remote lists were seen whole or refused (403), never filtered within a remote. The vendor's
published checks are Resource.Audit on `/resource/{remote}` and on `/view/{id}`, and its permission map
writes the propagate bit as a bool (a non-propagating grant answered `false`, live). So every owning
list owns only when the box's last `learn` read a permission map in which Resource.Audit reaches every
path under `/resource` (`resource_sight`; for the views, under `/view`, `view_sight`), stored as
`whole:<id>`, the token's public id (`user@realm!name`, `arm.served_id`; never a secret byte), and the
token that made the read names the same id. That is more than one remote needs: a token that sees one
remote whole owns nothing (the safe side). Learn writes both sights "partial" first and raises one only
when the id it read before the map and after it agree. Unknown, unread, partial, another token's: a
list adds and refreshes only. A remote's own list owns by that sight between learns too: it is never
filtered within the remote, so a token that has since lost a remote gets a 403, which retires nothing.
The remotes list and the views list are filtered, so a sight the token has since lost would retire
what it no longer sees: they own only inside the learn's own pass (`_OPEN`, held in the process that
runs the learn and never written to the file; it closes however the pass ends, a killed process takes
it with it, and a read by another process, or by a thread or task that did not start inside the learn,
never sees it). So a read between learns of the remotes or the views adds and refreshes only, and a
removed remote takes its things at the next learn.
`changed`'s `partial_sight` is not these keys: it is the frame's `learn_sight`, which the frame writes
from this pass's answer (`LearnTally.sees`).

THE READS HANDED OUT, each built from pieces that pass `_ID` and checked with `_published`: a guest's
`/pve/remotes/{remote}/{qemu|lxc}/{vmid}/status` (ONLY its status: the vendor's guest config read has a
required `state` argument, and the door refused the bare path live, so it is never handed out); a PVE
node's `/pve/remotes/{remote}/nodes/{node}/status`; a PBS remote's node, `/pbs/remotes/{remote}/status`;
a storage's `/pve/remotes/{remote}/nodes/{node}/storage/{storage}/status`; a datastore's
`/pbs/remotes/{remote}/datastore` (its own `/datastore/{store}` is an index, live); a remote's
`/remotes/remote/{id}/config`; a view's `/config/views/{id}`.

WHAT IS KEPT, beside the key, `ident` and name in the table and memory's own columns (seen, added and
gone times, a status's previous value and when it moved, the untrusted mark and the address that
wrote it): a remote, its `type` and `hosts`, the host of each of
its `nodes` entries (the text before the first `,`, so the fingerprint after it never reaches the file;
an entry whose host holds `=` is dropped; a host is cut at memory's TEXT bound); a guest, its `node`
and `status`; a node, its `status` (a PBS node row carried none live) and `on` (`pve` or `pbs`, which
picks its read); a storage, its `node` and `status`; every guest, node, storage and datastore, its
`remote`; a view, nothing more. Beside the things, memory's own notes on a read (meta keys) carry two
kinds of vendor word: a remote's id as a read named it (a combined list group's note says `?` for an id
no path may carry), and the type word of a per-remote resources row this shape does not keep (its
first 40 characters, so learn can name it). Never kept: a remote's `authid`, its token or any secret,
a datastore's `path`, a remote's error text, and any other field the vendor gives. Out of scope: ceph,
SDN, subscriptions and auto-install.
"""
from __future__ import annotations

import contextvars
import json
import re
import sqlite3
from collections.abc import Callable, Mapping
from typing import Any

from proximo.core import consult, estate, memory

_PLANE = "pdm"
_REMOTES = "/remotes/remote"
_COMBINED = "/resources/list"
_PVE = "/pve/remotes/{remote}/resources"
_PBS = "/pbs/remotes/{remote}/datastore"
_VIEWS = "/config/views"
_PERMS = "/access/permissions"
FEEDS = frozenset({_REMOTES, _COMBINED, _PVE, _PBS, _VIEWS})
#: The meta keys `learn` writes from the token's permission map: `whole:<id>` when Resource.Audit
#: reaches every path under `/resource` / `/view` for the token named `<id>`; anything else is not sight.
_RESOURCE_SIGHT = "resource_sight"
_VIEW_SIGHT = "view_sight"
#: The sight each owning list needs; a list not here never owns.
_NEEDS = {_REMOTES: _RESOURCE_SIGHT, _PVE: _RESOURCE_SIGHT, _PBS: _RESOURCE_SIGHT, _VIEWS: _VIEW_SIGHT}
#: The lists the vendor FILTERS by the token: they own only inside a learn's own pass (`_OPEN`), so a
#: sight the token lost since that learn never retires through them.
_LEARN_ONLY = frozenset({_REMOTES, _VIEWS})
#: The box whose learn pass is open in THIS context (this thread or task), or None. Process-local and
#: never written to the file: another process, or a thread or task that did not start inside the learn,
#: never sees it, and a killed process takes it with it.
_OPEN: contextvars.ContextVar[str | None] = contextvars.ContextVar("pdm_learn_open", default=None)
#: A token's public id (`user@realm!name`), or a ticket's user (`user@realm`): what a sight may name.
_WHO = re.compile(r"[^\s!=:@]+@[^\s!=:@]+(?:![^\s!=:@]+)?")
#: The kinds find's exact lookup takes, in this shape's own order (not the GUI's).
KIND_ORDER = ("remote", "node", "qemu", "lxc", "storage", "datastore", "view")
VENDOR_KINDS = frozenset(KIND_ORDER)
#: The kinds keyed by the vendor's one-string id, unchanged.
GLOBAL_IDS = frozenset({"node", "qemu", "lxc", "storage", "datastore"})
#: A resource row's `type`, per list, and the kind it is kept as; any other type is not kept. The combined
#: list feeds ONLY what no per-remote list reads (a PBS remote's node): a kind a per-remote list owns is
#: never fed from it, so a thing its owner retired does not come back from the combined list.
_PER_REMOTE = {"qemu": "qemu", "lxc": "lxc", "node": "node", "storage": "storage"}
_IN_COMBINED = {"pbs-node": "node"}
#: A type word a gap may name; anything else is named only as "a type this shape does not keep".
_TYPE_WORD = re.compile(r"[a-z][a-z0-9-]{0,31}")


def _text(v: Any) -> str | None:
    """A non-empty id the vendor gave: a string, or an integer (a vmid), never a bool or a null."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return str(v)
    return v if isinstance(v, str) and v else None


def _id(v: Any) -> str | None:
    """A non-empty string id the vendor gave (a remote's, a view's, a resource's one-string id)."""
    return v if isinstance(v, str) and v else None


def _datastore_id(remote: str, name: str) -> str:
    """A PBS datastore's one-string id as the vendor's combined list spells it (`remote/<r>/datastore/<name>`,
    byte for byte equal to the live combined list's `id` of the same datastore): the per-remote datastore
    list carries only `name`, and this is the key both reads agree on."""
    return f"remote/{remote}/datastore/{name}"


def _sighted(who: str | None) -> str | None:
    """The sight value a token with this id is seen by (`whole:<id>`), or None: unknown is blind."""
    return f"whole:{who}" if isinstance(who, str) and len(who) <= memory.TEXT and _WHO.fullmatch(who) else None


def _ok(*ids: Any) -> bool:
    return all(isinstance(i, str) and memory._ID.fullmatch(i) for i in ids)


def _resource(r: Any, types: Mapping[str, str]) -> tuple[str, str, str, str | None, str | None] | None:
    """(kind, key, ident, name, node) of a resource row this shape keeps, or None for one it does not
    (a type it does not keep, or a row it cannot key)."""
    if not isinstance(r, dict):
        return None
    t = r.get("type")
    kind, gid = types.get(t) if isinstance(t, str) else None, _id(r.get("id"))
    if kind is None or gid is None:
        return None
    if kind in ("qemu", "lxc"):
        vmid = _text(r.get("vmid"))
        return (kind, gid, vmid, _text(r.get("name")), _text(r.get("node"))) if vmid else None
    if kind == "node":
        node = _text(r.get("node" if r.get("type") in ("node", "pve-node") else "name"))
        return (kind, gid, node, node, node) if node else None
    sid = _text(r.get("storage"))                                 # a storage
    return (kind, gid, sid, sid, _text(r.get("node"))) if sid else None


def _keyed_resources(data: list[Any]) -> bool:
    """Every row of a per-remote resources answer names itself: a string `id` and `type`, and a row of a
    kind this shape keeps also its own id field. Absent is no proof."""
    return all(isinstance(r, dict) and _id(r.get("id")) and isinstance(r.get("type"), str)
               and (r["type"] not in _PER_REMOTE or _resource(r, _PER_REMOTE) is not None) for r in data)


def _keyed(data: list[Any], field: str) -> bool:
    """Every row names itself by a string `field`."""
    return all(isinstance(r, dict) and _id(r.get(field)) for r in data)


# ---- feeding: one vendor answer at a time ------------------------------------------------------------

def _owner(template: str, bound: Mapping[str, str], args: Mapping[str, Any], fields: str | None, data: Any,
           box: str, evaluating: bool, db: sqlite3.Connection | None, who: str | None) -> str | None:
    """The list a WHOLE read of `template` owns, or None (a read that may only add or refresh): an
    argument, a field subset, a door's own look for a verdict, a box with no name, a non-list, the
    combined list, a list with a row that does not name itself, an empty remotes or resources answer,
    or a read whose token's sight the box's last learn did not judge whole FOR THAT TOKEN never owns; and
    the remotes and views lists (filtered by the token) own only inside a learn's own pass (`_OPEN`)."""
    if evaluating or fields is not None or not box or not isinstance(data, list) or args:
        return None
    need = _NEEDS.get(template)
    seen = _sighted(who)
    if need is None or db is None or seen is None or memory._meta(db, _PLANE, box, need) != seen:
        return None
    if template in _LEARN_ONLY and _OPEN.get() != box:
        return None
    if template == _VIEWS:
        return "views" if _keyed(data, "id") else None
    if not data:
        return None
    if template == _REMOTES:
        return "remotes" if _keyed(data, "id") else None
    remote = bound.get("remote")
    if not isinstance(remote, str) or not remote:
        return None
    if template == _PBS:
        return f"pbs-datastores/{remote}" if _keyed(data, "name") else None
    return f"pve-resources/{remote}" if _keyed_resources(data) else None


def _host(entry: Any) -> str | None:
    """A remote's node entry (`host,fingerprint=...`) as its host alone, or None."""
    host = entry.split(",", 1)[0].strip() if isinstance(entry, str) else ""
    return host[:memory.TEXT] if host and "=" not in host else None


def _ingest(f: memory._Feed, template: str, bound: dict[str, str], data: Any) -> None:
    rows = data if isinstance(data, list) else []
    if template == _REMOTES:
        for r in rows:
            rid = _id(r.get("id")) if isinstance(r, dict) else None
            if rid:                         # never the authid, a token or a fingerprint
                hosts = [h for h in map(_host, r.get("nodes") or []) if h] if isinstance(r.get("nodes"), list) else []
                f.put("remote", rid, ident=rid, name=rid,
                      detail={"type": _id(r.get("type")), "hosts": hosts})
    elif template == _VIEWS:
        for r in rows:
            vid = _id(r.get("id")) if isinstance(r, dict) else None
            if vid:
                f.put("view", vid, ident=vid, name=vid)
    elif template == _PVE:
        remote = bound.get("remote")
        if isinstance(remote, str) and remote:
            for r in rows:
                t = r.get("type") if isinstance(r, dict) else None
                if isinstance(t, str) and t not in _PER_REMOTE:      # learn names it: not kept, not silent
                    f.mark(f"{_unknown(remote)}{t[:40]}")
                _put(f, r, _PER_REMOTE, remote, "pve")
    elif template == _PBS:
        remote = bound.get("remote")
        if isinstance(remote, str) and remote:
            for r in rows:
                name = _id(r.get("name")) if isinstance(r, dict) else None
                if name:                    # its `path` is never kept
                    f.put("datastore", _datastore_id(remote, name), ident=name, name=name, detail={"remote": remote})
    elif template == _COMBINED:
        _ingest_combined(f, rows)


def _ingest_combined(f: memory._Feed, rows: list[Any]) -> None:
    """The combined list's groups: each marks its remote for learn, and only a group with rows, for a remote
    memory holds and a path may carry, feeds (a PBS remote's node) and marks it answered."""
    for g in rows:
        remote = _id(g.get("remote")) if isinstance(g, dict) else None
        if remote is None:
            continue
        f.mark(_grouped(remote))            # learn checks each group's remote against this pass's remotes list
        if "error" in g or not isinstance(g.get("resources"), list):
            continue                        # a remote that did not answer: nothing of it, never its error text
        if not _present(f, remote) or not _ok(remote):
            continue                        # one memory does not hold, or whose id no path may carry: nothing
        f.mark(_answered(remote))
        for r in g["resources"]:
            if isinstance(r, dict):
                _put(f, r, _IN_COMBINED, remote, "pbs")


def _put(f: memory._Feed, r: Any, types: Mapping[str, str], remote: str, on: str) -> None:
    got = _resource(r, types)
    if got is None:
        return
    kind, gid, ident, name, node = got
    detail: dict[str, Any] = {"remote": remote, **({"on": on} if kind == "node" else {})}
    f.put(kind, gid, ident=ident, name=name, node=node, status=_text(r.get("status")), detail=detail)


def _unknown(remote: str) -> str:
    """The meta key prefix a per-remote resources read marks, then the type, for a row it does not keep."""
    return f"unkept:{_PVE}|{remote}|"


def _present(f: memory._Feed, remote: str) -> bool:
    """The remote is a `remote` memory holds and has not retired: the one a combined group may feed."""
    return f.db.execute("SELECT 1 FROM entity WHERE plane=? AND box=? AND kind='remote' AND key=? AND "
                        "gone_at IS NULL", (_PLANE, f.box, remote)).fetchone() is not None


def _grouped(remote: str) -> str:
    """The meta key the combined list marks for every group that names a remote, error or not. A remote id
    no path may carry is marked by one fixed key, so the vendor's text never reaches the file's keys."""
    return f"{_GROUPED}{remote}" if _ok(remote) else f"{_GROUPED}?"


_GROUPED = f"grouped:{_COMBINED}|"


def _answered(remote: str) -> str:
    """The meta key the combined list marks when it carried a remote's rows (no error)."""
    return f"answered:{_COMBINED}|{remote}"


# ---- answering ---------------------------------------------------------------------------------------

def _detail(r: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(r["detail"]) if r.get("detail") else {}


def _paths(r: Mapping[str, Any]) -> list[str]:
    """The concrete GET that reads this thing live, built only from pieces that pass `_ID` (a vmid from
    digits); memory checks each with `_published`."""
    kind, ident, d = r["kind"], r.get("ident"), _detail(r)
    if kind == "remote":
        return [f"/remotes/remote/{ident}/config"] if _ok(ident) else []
    if kind == "view":
        return [f"/config/views/{ident}"] if _ok(ident) else []
    remote = d.get("remote")
    if not _ok(remote):
        return []
    if kind in ("qemu", "lxc"):
        ok = isinstance(ident, str) and memory._VMID.fullmatch(ident)
        return [f"/pve/remotes/{remote}/{kind}/{ident}/status"] if ok else []
    if kind == "node":
        if d.get("on") == "pbs":
            return [f"/pbs/remotes/{remote}/status"]
        return [f"/pve/remotes/{remote}/nodes/{ident}/status"] if d.get("on") == "pve" and _ok(ident) else []
    if kind == "storage":
        node = r.get("node")
        return [f"/pve/remotes/{remote}/nodes/{node}/storage/{ident}/status"] if _ok(node, ident) else []
    if kind == "datastore":
        return [f"/pbs/remotes/{remote}/datastore"]
    return []


def _show(r: Mapping[str, Any]) -> dict[str, Any]:
    """The entry's id is the vendor's id within its remote (`ident`), and every kind but a remote and a
    view names its remote."""
    if r["kind"] in ("remote", "view"):
        return {"id": r["ident"]}
    return {"id": r["ident"], "remote": _detail(r).get("remote")}


# ---- learn: the one deliberate pass ------------------------------------------------------------------

def _unkept(db: sqlite3.Connection, box: str, remotes: list[str], start: float) -> list[str]:
    """A gap per type a per-remote resources read listed on this pass and this shape does not keep: named,
    never silent (a type word the vendor spells oddly is named only as such)."""
    out = []
    for r in remotes:
        for (k,) in db.execute("SELECT k FROM meta WHERE plane=? AND box=? AND substr(k, 1, ?) = ? AND "
                               "CAST(v AS REAL) >= ? ORDER BY k", (_PLANE, box, len(_unknown(r)), _unknown(r), start)):
            t = k[len(_unknown(r)):]
            named = f"type {t}" if _TYPE_WORD.fullmatch(t) else "a type this shape does not keep"
            out.append(f"GET /pve/remotes/{r}/resources listed {named}: those rows were not kept")
    return out


def _unread_type(key: str, kind: Any) -> str:
    """The gap for a listed remote whose type is not one this shape reads (`pve`, `pbs`): its things are
    not read on this pass. Named by its id only when a path may carry it, its type only when it is a plain word."""
    who = f"remote {key}" if _ok(key) else "a remote"
    if not isinstance(kind, str):
        return f"{who} names no type this shape reads (pve or pbs): its resources were not read"
    named = f"type {kind}, which" if _TYPE_WORD.fullmatch(kind) else "a type"
    return f"{who} is of {named} this shape does not read: its resources were not read"


def _sides(db: sqlite3.Connection, box: str) -> dict[tuple[str, str], int]:
    """How many things memory shows present per (remote, the product they were kept under): a guest,
    storage or PVE node is `pve`'s, a datastore or PBS node `pbs`'s. A remote listed as one product while
    memory shows things of the other under its id has returned as another product."""
    out: dict[tuple[str, str], int] = {}
    for kind, detail in db.execute("SELECT kind, detail FROM entity WHERE plane=? AND box=? AND gone_at IS NULL "
                                   "AND kind NOT IN ('remote', 'view')", (_PLANE, box)):
        d = json.loads(detail) if detail else {}
        side = d.get("on") if kind == "node" else ("pbs" if kind == "datastore" else "pve")
        if isinstance(d.get("remote"), str) and side in ("pve", "pbs"):
            out[(d["remote"], side)] = out.get((d["remote"], side), 0) + 1
    return out


def _combined_gaps(db: sqlite3.Connection, box: str, start: float, stores: list[str],
                   this_pass: Callable[[str], bool]) -> list[str]:
    """What this pass's combined list left undone: a PBS remote it did not carry (its node was not
    refreshed), and a group for a remote this pass's remotes list does not carry (it fed only when memory
    still holds that remote and the group carried rows, and the gap says which, by `_answered`; named by
    its id only when a path may carry it, and a group whose remote id no path may carry feeds nothing)."""
    out = [f"remote {r} did not answer GET {_COMBINED} (or was left out of it): its node was not refreshed"
           for r in stores if not this_pass(_answered(r))]       # where a PBS remote's node comes from
    listed = {k for (k,) in db.execute("SELECT key FROM entity WHERE plane=? AND box=? AND kind='remote' AND "
                                       "last_seen >= ?", (_PLANE, box, start))}
    held = {k for (k,) in db.execute("SELECT key FROM entity WHERE plane=? AND box=? AND kind='remote' AND "
                                     "gone_at IS NULL", (_PLANE, box))}
    for (k,) in db.execute("SELECT k FROM meta WHERE plane=? AND box=? AND substr(k, 1, ?) = ? AND "
                           "CAST(v AS REAL) >= ? ORDER BY k", (_PLANE, box, len(_GROUPED), _GROUPED, start)):
        r = k[len(_GROUPED):]
        if r == "?":
            out.append(f"GET {_COMBINED} carried a remote whose id no path may carry: nothing of it was kept")
        elif r not in listed:
            out.append(f"GET {_COMBINED} carried remote {r}, which this pass's remotes list does not: " + (
                "memory still holds that remote, so its group was kept from a list that may be stale"
                if r in held and this_pass(_answered(r)) else "nothing of it was kept"))
    return out


def _learn(read: Callable[..., dict[str, Any] | None], db_at: Callable[[], sqlite3.Connection], box: str,
           start: float, gaps: list[str], who: Callable[[], str | None]) -> memory.LearnTally:
    """The token's permission map first, then the remotes list, then each PVE remote's resources and each
    PBS remote's datastores, the combined list (a PBS remote's node) and the views. `read` stops at the
    budget by raising `memory._Spent` (the frame names it); what was gathered before still tallies.
    The pass (`_OPEN`, the remotes and views lists' owning) opens before the map and closes when the pass
    ends, however it ends; the sights it raises stay for a remote's own list."""
    plane = _PLANE
    skipped_before = int(memory._meta(db_at(), plane, box, "skipped_ids") or 0)
    sees: bool | None = None
    asked: list[str] = []                       # the PVE remotes whose resources this pass asked for
    stores: list[str] = []                      # the PBS remotes whose datastores this pass asked for

    def sight(k: str, v: str) -> None:
        db = db_at()
        with db:
            memory._set(db, plane, box, k, v)
    # Not sight until this pass's permission map shows it: a "whole" from an earlier token never outlives
    # a pass that stops (refused, failed, out of budget) before the map is read.
    sight(_RESOURCE_SIGHT, "partial")
    sight(_VIEW_SIGHT, "partial")
    opened = _OPEN.set(box)                     # this pass's own reads of the remotes and views lists may own
    try:
        before = who()
        env = read(_PERMS, _PERMS, "all")
        seen = _sighted(before) if who() == before else None
        whole, perms = consult._data_of(env) if env is not None else (False, None)
        held = estate.Estate(permissions=estate.permission_map(perms)) if whole else None
        if seen is None:
            gaps.append("the served token names no id this pass could hold steady (it is not a token, or it "
                        "changed while the permission map was read): no list owns what it lists")
            held = None
        res = held.sees_every("Resource.Audit", "/resource") if held is not None else None
        if res is True and seen is not None:    # before the lists feed, so this pass's reads own them
            sight(_RESOURCE_SIGHT, seen)
        else:
            gaps.append("this token's permission map does not show Resource.Audit reaching every remote (or could "
                        "not be read): memory holds the remotes and resources it may see, which may not be all")
        views = held.sees_every("Resource.Audit", "/view") if held is not None else None
        if views is True and seen is not None:
            sight(_VIEW_SIGHT, seen)
        else:
            gaps.append("this token's permission map does not show Resource.Audit reaching every view (or could "
                        "not be read): views may be hidden")
        if held is not None:
            sees = res is True and views is True
        read(_REMOTES, _REMOTES)
        sides = _sides(db_at(), box)
        for key, detail in db_at().execute(
                "SELECT key, detail FROM entity WHERE plane=? AND box=? AND kind='remote' AND last_seen >= ? AND "
                "gone_at IS NULL ORDER BY key", (plane, box, start)).fetchall():
            kind = (json.loads(detail) if detail else {}).get("type")
            if kind not in ("pve", "pbs"):      # named, never skipped silently: its things are not read
                gaps.append(_unread_type(key, kind))
                continue
            if _ok(key):
                (asked if kind == "pve" else stores).append(key)
                other = "pbs" if kind == "pve" else "pve"
                if sides.get((key, other)):
                    gaps.append(f"remote {key} is listed as {kind} now, and memory still shows "
                                f"{sides[(key, other)]} thing(s) it kept of it as {other}: this pass did not read them")
            else:
                gaps.append("a remote id is not one a path may carry; its resources were not read")
        for r in asked:
            read(f"/pve/remotes/{r}/resources", _PVE)
        for r in stores:
            read(f"/pbs/remotes/{r}/datastore", _PBS)
        read(_COMBINED, _COMBINED)
        read(_VIEWS, _VIEWS)
    except memory._Spent:                       # the frame has named it; what was listed still tallies
        pass
    finally:
        # The pass closes however it ends (whole, out of budget, an exception): between learns the remotes
        # and views lists add and refresh only. The sights stay: a remote's own list still owns by them.
        _OPEN.reset(opened)

    db = db_at()

    def this_pass(k: str) -> bool:
        v = memory._meta(db, plane, box, k)
        return v is not None and float(v) >= start
    if this_pass(f"read:{_COMBINED}"):
        gaps.extend(_combined_gaps(db, box, start, stores, this_pass))
    gaps.extend(_unkept(db, box, asked, start))
    # A list read on this pass that could not own (a row memory cannot key, an empty answer, sight that is
    # not whole) retired nothing: the pass is not whole.
    owning = [(_REMOTES, f"read:{_REMOTES}", "remotes"), (_VIEWS, f"read:{_VIEWS}", "views"),
              *((f"/pve/remotes/{r}/resources", f"read:{_PVE}|{json.dumps({'remote': r}, sort_keys=True)}",
                 f"pve-resources/{r}") for r in asked),
              *((f"/pbs/remotes/{r}/datastore", f"read:{_PBS}|{json.dumps({'remote': r}, sort_keys=True)}",
                 f"pbs-datastores/{r}") for r in stores)]
    for what, k, owner in owning:
        if this_pass(k) and not this_pass(f"whole:{owner}"):
            gaps.append(f"GET {what} was read but could not own its list: nothing it no longer lists was retired")
    # Whole means everything memory shows present was listed on this pass. A thing no read of this pass
    # listed and no owner retired (added for a remote this pass's remotes list does not show, left shown by
    # a file written before the frame's rule after its owner retired it, a remote whose type this pass does
    # not read) is shown on an older read's word. This retires nothing; it says so.
    (unseen,) = db.execute("SELECT count(*) FROM entity WHERE plane=? AND box=? AND gone_at IS NULL AND "
                           "last_seen < ?", (plane, box, start)).fetchone()
    # The count goes first, so the three gaps a `why` shows always hold it.
    if unseen:
        gaps.insert(0, f"{unseen} thing(s) memory shows present were not listed on this pass")
    kept =[(_REMOTES, f"read:{_REMOTES}"), (_COMBINED, f"read:{_COMBINED}"), (_VIEWS, f"read:{_VIEWS}"),
            *((what, k) for what, k, _ in owning[2:])]
    (count,) = db.execute("SELECT count(*) FROM entity WHERE plane=? AND box=? AND kind IN ('qemu', 'lxc') AND "
                          "gone_at IS NULL AND last_seen >= ?", (plane, box, start)).fetchone()

    def after_kept(db: sqlite3.Connection) -> list[str]:
        moved = int(memory._meta(db, plane, box, "skipped_ids") or 0) - skipped_before
        if moved > 0:
            return [f"{moved} thing(s) not kept on this pass: an id longer than memory keeps "
                    f"({memory.TEXT} characters); a one-string vendor id is never cut"]
        return []
    return memory.LearnTally(kept=tuple(kept), count_kind="guests", count=count, sees=sees, after_kept=after_kept)


def _retire_with_their_remote(db: sqlite3.Connection, box: str, t: float) -> None:
    """Run by the frame right after a WHOLE remotes read (the owner `remotes`) retired what it no longer
    lists: every thing still present whose remote is gone is gone too, dated by this read.
    No edges are made: this is the shape's own cascade, not a relation."""
    gone = {k for (k,) in db.execute("SELECT key FROM entity WHERE plane=? AND box=? AND kind='remote' AND "
                                     "gone_at IS NOT NULL", (_PLANE, box))}
    if not gone:
        return
    orphans = [nid for nid, detail in db.execute(
        "SELECT nid, detail FROM entity WHERE plane=? AND box=? AND kind NOT IN ('remote', 'view') AND "
        "gone_at IS NULL", (_PLANE, box)) if (json.loads(detail) if detail else {}).get("remote") in gone]
    db.executemany("UPDATE entity SET gone_at=? WHERE plane=? AND box=? AND nid=?",
                   [(t, _PLANE, box, n) for n in orphans])


class _Pdm:
    """PDM's `memory.PlaneShape`."""

    plane: str = _PLANE
    feeds: frozenset[str] = FEEDS
    vendor_kinds: frozenset[str] = VENDOR_KINDS
    kind_order: tuple[str, ...] = KIND_ORDER
    relating_owners: frozenset[str] = frozenset({"remotes"})    # a removed remote takes its things (`relate`)
    answers_uses: bool = False          # no edges on PDM: `uses` is not answered
    id_names: frozenset[str] = frozenset()
    no_ident_kinds: frozenset[str] = frozenset()
    no_name_kinds: frozenset[str] = frozenset()
    global_ids: frozenset[str] = GLOBAL_IDS
    next_live: tuple[str, ...] = (f"GET {_REMOTES}",)
    whole_owner: str = "remotes"
    token_sight: bool = True            # the remotes, combined and views lists filter by the token

    def owner(self, template: str, bound: Mapping[str, str], args: Mapping[str, Any], fields: str | None,
              data: Any, box: str, evaluating: bool, *, db: sqlite3.Connection | None = None,
              who: str | None = None) -> str | None:
        return _owner(template, bound, args, fields, data, box, evaluating, db, who)

    def ingest(self, f: memory._Feed, template: str, bound: dict[str, str], args: Mapping[str, Any],
               data: Any) -> None:
        _ingest(f, template, bound, data)

    def relate(self, db: sqlite3.Connection, box: str, t: float) -> None:
        _retire_with_their_remote(db, box, t)

    def paths(self, r: Mapping[str, Any]) -> list[str]:
        return _paths(r)

    def show(self, r: Mapping[str, Any]) -> dict[str, Any]:
        return _show(r)

    def learn(self, read: Callable[..., dict[str, Any] | None], db_at: Callable[[], sqlite3.Connection],
              box: str, start: float, gaps: list[str], *,
              who: Callable[[], str | None] = lambda: None) -> memory.LearnTally:
        return _learn(read, db_at, box, start, gaps, who)


SHAPE: memory.PlaneShape = _Pdm()
memory.SHAPES[_PLANE] = SHAPE
