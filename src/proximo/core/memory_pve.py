"""PVE'S SHAPE for the estate memory (`memory.PlaneShape`): which PVE reads feed it, which own a whole
list, how a PVE answer becomes entities and edges, which paths read a thing live, and what `learn`
reads. Moved here verbatim from `memory.py` (2026-11-09) so a second plane is a second module, not a
branch in every function; `memory.py` keeps the file, the bounds and the answers, and dispatches
through `memory.shape("pve")`. This module registers itself in `memory.SHAPES` when imported
(`memory` imports it at its end), so either import order works.
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Mapping
from typing import Any

from proximo.core import consult, estate, memory

_PLANE = "pve"
#: The guest config learn reads per guest: consult's fan-out, so learn and a consult read the same.
FANOUT = tuple(consult.FANOUT["guest_config"].templates.values())

_GUESTS = ("qemu", "lxc")
_NODE_LISTS = frozenset({"/nodes/{node}/qemu", "/nodes/{node}/lxc"})
_CONTENT = "/nodes/{node}/storage/{storage}/content"
#: What memory takes: the estate's sources but the permission map (the token's, not the estate's),
#: and the per-node guest lists (refresh only: they see one node).
FEEDS = frozenset(set(estate.SOURCES) - {"/access/permissions"}) | _NODE_LISTS
_KIND_WORDS = frozenset({"qemu", "lxc", "node", "storage", "pool", "bridge", "job"})
#: The kinds find's exact lookup takes, by the vendor's own words only: the `type` values of
#: `/cluster/resources`, a network interface's `type` (`bridge`) and a storage content type
#: (`backup`). `job` and `acl` are this module's labels, not the vendor's; `container` and `vm` are
#: find's vocabulary. Mapping the operator's words onto these is the model's work, not the metal's.
VENDOR_KINDS = frozenset({"qemu", "lxc", "node", "storage", "pool", "bridge", "backup"})
#: The order kinds are shown in: the vendor's own (guests, then what holds them), never the alphabet,
#: so seven bridges named `pve3` never push node pve3 past WHERE_SHOWN (lens 2026-11-07). `lxc` before
#: `qemu`: the two once tied and `kind` broke the tie, so this is that order exactly.
KIND_ORDER = ("lxc", "qemu", "node", "storage", "pool", "job", "bridge", "backup")
#: The owners whose whole read moves pool membership and backup coverage (`_relate`).
_RELATING = frozenset({"resources", "/cluster/backup", "/pools"})
#: The reads a whole answer of which owns a list.
_OWNING = frozenset({"/cluster/resources", "/storage", "/access/acl", "/cluster/backup", "/pools",
                     "/nodes/{node}/network", _CONTENT})


# ---- feeding: one vendor answer at a time ------------------------------------------------------------

#: The `/cluster/resources` row types this shape keeps; a row of any other type (a pool, an sdn zone, a
#: network) is the vendor's and not kept, and does not stop the read owning.
_KEPT_TYPES = frozenset({*_GUESTS, "node", "storage"})


def _keyed(template: str, data: list[Any]) -> bool:
    """MEMORY'S OWN NEED, not the vendor's rule: every row this shape would keep can be keyed, judged by the
    estate's own constructors (the ones `_ingest` keeps rows through), so the two can never disagree. What
    a row must carry is the vendor's to say and is held first, for every plane, by `memory.feed` (the one
    JSON's `row` column). This is what that cannot cover: the vendor marks `vmid`, `node` and `storage`
    optional on a `/cluster/resources` row and memory keys a guest, a node and a storage by them, and an
    id the vendor sent empty names nothing. Absent is no proof: a row memory cannot key may be the very
    thing a retire would call gone."""
    if not all(isinstance(r, dict) for r in data):
        return False
    if template == "/cluster/resources":
        if not all(isinstance(r.get("type"), str) for r in data):
            return False
        kept = sum(1 for r in data if r["type"] in _KEPT_TYPES)
        return kept == (len(estate.guests_from_resources(data)) + len(estate.nodes_from_resources(data))
                        + len(estate.storages_from_resources(data)))
    if template == "/access/acl":
        return len(_grants(estate.acls_from_acl(data))) == len(data)
    if template == "/nodes/{node}/network":
        return len(estate.ifaces_from_network("", data)) == len(data)
    if template == _CONTENT:
        return len(estate.volumes_from_content("", data)) == len(data)
    count = {"/storage": estate.storages_from_config, "/cluster/backup": estate.jobs_from_backup,
             "/pools": estate.pools_from_pools}[template]
    return len(count(data)) == len(data)


def _owner(template: str, bound: Mapping[str, str], args: Mapping[str, Any], fields: str | None,
           data: Any, box: str, evaluating: bool) -> str | None:
    """The list a WHOLE read of `template` owns, or None (a read that may only add or refresh): a
    field subset, a door's own look for a verdict, a box with no name, a non-list, or a list with a row
    that does not name itself (`_keyed`) never owns."""
    if evaluating or fields is not None or not box or not isinstance(data, list):
        return None
    if template not in _OWNING or not _keyed(template, data):
        return None
    if template == "/cluster/resources":
        return "resources" if not args and data else None
    if template in ("/storage", "/access/acl", "/cluster/backup", "/pools"):
        return None if args else template
    if template == "/nodes/{node}/network":
        return None if args else f"network/{bound.get('node')}"
    whole = not set(args) - {"content"} and args.get("content") in (None, "backup")
    return f"content/{bound.get('node')}/{bound.get('storage')}" if whole else None


def resources(f: memory._Feed, est: estate.Estate) -> None:
    runs = {e.src: e for e in est.edges() if e.rel == "runs_on"}
    for g in est.guests:
        f.put(g.kind, g.vmid, ident=g.vmid, name=g.name, node=g.node, status=g.status,
              tags=";".join(g.tags) if g.tags is not None else None,
              detail={"pool": g.pool} if g.pool else None)
        memory._replace(f.db, f.plane, f.box, g.key, ("runs_on",), [runs[g.key]] if g.key in runs else [], f.t)
    for n in est.nodes:
        f.put("node", n.name, ident=n.name, name=n.name, node=n.name, status=n.status)
    per: dict[str, list[estate.Storage]] = {}
    for st in est.storages:
        per.setdefault(st.id, []).append(st)
    for sid, rows in per.items():       # one row per node: one storage, its nodes in detail
        nodes = sorted({x.node for x in rows if x.node})
        statuses = {x.status for x in rows if x.status}
        f.put("storage", sid, ident=sid, name=sid,
              node=",".join(nodes[:3]) + (f",+{len(nodes) - 3}" if len(nodes) > 3 else "") or None,
              status=(statuses.pop() if len(statuses) == 1 else "mixed") if statuses else None,
              detail={"nodes": [n for n in nodes if memory._ID.fullmatch(n)][:16]})
    if f.owner is None:
        _relate(f.db, f.plane, f.box, f.t)


def config(f: memory._Feed, est: estate.Estate) -> None:
    g = est.guests[0] if est.guests else None
    if g is None or g.key in est.unread:      # an empty config is a failed read, never "no disks"
        return
    f.put(g.kind, g.vmid, ident=g.vmid, name=g.name, node=g.node, config=True)
    slots: dict[estate.Edge, set[str]] = {}
    for d in est.disks:
        if d.storage and not d.cdrom:
            slots.setdefault(estate.Edge(g.key, "disk_on", f"storage/{d.storage}"), set()).add(d.slot)
    for n in est.nics:
        if n.bridge:
            slots.setdefault(estate.Edge(g.key, "nic_on", f"bridge/{n.bridge}"), set()).add(n.slot)
    edges = [e for e in est.edges() if e.rel in ("disk_on", "nic_on")]
    memory._replace(f.db, f.plane, f.box, g.key, ("disk_on", "nic_on"), edges, f.t,
                    via={e: ",".join(sorted(slots.get(e, ()))) for e in edges})


def storage(f: memory._Feed, est: estate.Estate) -> None:
    for st in est.storages:
        f.put("storage", st.id, ident=st.id, name=st.id, detail={k: v for k, v in (
            ("type", st.type), ("shared", st.shared), ("disabled", st.disabled)) if v is not None})


def backup(f: memory._Feed, est: estate.Estate) -> None:
    for j in est.jobs:
        f.put("job", j.id, ident=j.id, name=j.id,
              status=None if j.enabled is None else "enabled" if j.enabled else "disabled",
              detail={"all": j.all, "vmids": list(j.vmids) if j.vmids is not None else None, "pool": j.pool,
                      "exclude": list(j.exclude) if j.exclude is not None else None})
    if f.owner is None:
        _relate(f.db, f.plane, f.box, f.t)


def pools(f: memory._Feed, est: estate.Estate) -> None:
    for pool in est.pools:
        f.put("pool", pool.id, ident=pool.id, name=pool.id,
              detail={"members": list(pool.members) if pool.members is not None else None})
    if f.owner is None:
        _relate(f.db, f.plane, f.box, f.t)


def _grants(acls: tuple[estate.Acl, ...]) -> list[estate.Acl]:
    """The grants memory can key: an entry is named from its path, subject, type and role together, so a
    row short of any is not kept (kept, it would sit under a name no whole read lists again, and never
    leave). `_keyed` counts through this too."""
    return [a for a in acls if a.type and a.role]


def acl(f: memory._Feed, est: estate.Estate) -> None:
    for a in _grants(est.acls):
        f.put("acl", f"{a.path} {a.type or 'subject'}/{a.ugid} {a.role or ''}".strip(), ident=a.ugid,
              name=a.ugid, tags=a.role, detail={"path": a.path, "propagate": a.propagate})
    if f.owner is not None:        # a whole list is every grant: its edges are exactly these
        f.db.execute("DELETE FROM edge WHERE plane=? AND box=? AND rel='granted_on'", (f.plane, f.box))
    kept = {(f"{a.type}/{a.ugid}", f"path{a.path}") for a in _grants(est.acls)}     # no edge for a grant not kept
    f.edges(e for e in est.edges() if e.rel == "granted_on" and (e.src, e.dst) in kept)


def network(f: memory._Feed, est: estate.Estate) -> None:
    for i in est.ifaces:
        if i.type and "bridge" in i.type.lower():
            f.put("bridge", f"{i.node}/{i.iface}", ident=i.iface, name=i.iface, node=i.node,
                  status=None if i.active is None else "active" if i.active else "inactive")


def content(f: memory._Feed, est: estate.Estate, node: str | None) -> None:
    for v in est.volumes:
        if v.content == "backup":
            f.put("backup", v.volid, ident=v.volid, name=v.volid.rpartition("/")[2], node=node,
                  detail={"storage": v.storage, "vmid": v.vmid, "ctime": v.ctime})
    f.edges(e for e in est.edges() if e.rel == "backup_of")


def _ingest(f: memory._Feed, template: str, bound: dict[str, str], args: Mapping[str, Any], data: Any) -> None:
    if template in _NODE_LISTS:          # one node's guests: kept like resources rows, never a whole read
        kind = template.split("/")[3]
        data = [{**r, "type": kind, "node": bound.get("node")} for r in data if isinstance(r, dict)] \
            if isinstance(data, list) else []
        template, bound = "/cluster/resources", {}
    est = estate.build([estate.Answer(template, bound, data)])
    if template == "/cluster/resources":
        resources(f, est)
    elif template.endswith(("/config", "/pending")):
        config(f, est)
    elif template.endswith("/network"):
        network(f, est)
    elif template == _CONTENT:
        content(f, est, bound.get("node"))
    elif template == "/storage" and f.owner is None:
        # A `/storage` read feeds storage only when it owns (an argument, a field subset, the door's own look
        # or a box with no name never does: `_owner`). `/cluster/resources` owns storage too, and is thought
        # to leave out a storage disabled in the definitions that `/storage` still lists; that is unverified
        # (recalled, no capture shows it). A read that cannot own would bring back what `resources` dropped,
        # and each `resources` read would drop it again.
        return
    else:
        {"/storage": storage, "/cluster/backup": backup, "/pools": pools, "/access/acl": acl}[template](f, est)


def _relate(db: sqlite3.Connection, plane: str, box: str, t: float) -> None:
    """Pool membership and backup coverage, from the guests, pools and jobs the file holds and are not
    gone, through `Estate.edges` (the judges' own `guests_in_pool` and `jobs_covering`)."""
    guests, jobs, pools = [], [], []
    for kind, key, node, detail in db.execute(
            "SELECT kind, key, node, detail FROM entity WHERE plane=? AND box=? AND gone_at IS NULL AND kind IN "
            "('qemu','lxc','job','pool')", (plane, box)):
        d = json.loads(detail) if detail else {}
        if kind in _GUESTS:
            guests.append(estate.Guest(kind=kind, vmid=key, node=node, pool=d.get("pool")))
        elif kind == "job":
            jobs.append(estate.BackupJob(id=key, all=d.get("all"), pool=d.get("pool"),
                                         vmids=tuple(d["vmids"]) if d.get("vmids") is not None else None,
                                         exclude=tuple(d["exclude"]) if d.get("exclude") is not None else None))
        else:
            pools.append(estate.Pool(id=key, members=tuple(d["members"]) if d.get("members") is not None else None))
    est = estate.Estate(guests=tuple(guests), jobs=tuple(jobs), pools=tuple(pools))
    # A pool or job the file knows is GONE (a whole /pools or /cluster/backup read dropped it) takes no
    # edge: a guest's own `pool` field still spells the pool it was in, and the judge would relate the
    # two from that word alone, so the stale row came back on every read until the next resources read.
    # A pool never read at all stays related by the guest's word, as the judge relates it.
    gone = {nid for (nid,) in db.execute(
        "SELECT nid FROM entity WHERE plane=? AND box=? AND gone_at IS NOT NULL AND kind IN ('pool','job')",
        (plane, box))}
    db.execute("DELETE FROM edge WHERE plane=? AND box=? AND rel IN ('in_pool','covered_by')", (plane, box))
    memory._insert(db, plane, box,
                   [e for e in est.edges() if e.rel in ("in_pool", "covered_by") and e.dst not in gone], t)


# ---- answering ---------------------------------------------------------------------------------------

def _paths(r: Mapping[str, Any]) -> list[str]:
    """The concrete GETs that read this thing live, built only from vendor ids that pass `_ID`/`_VMID`
    and from the feeding read's own path parameters; memory checks each with `_published` and drops a
    gone thing's."""
    kind, key, node = r["kind"], r["key"], r["node"]
    d = json.loads(r["detail"]) if r.get("detail") else {}

    def ok(*ids: Any) -> bool:
        return all(isinstance(i, str) and memory._ID.fullmatch(i) for i in ids)
    out: list[str] = []
    if kind in _GUESTS and node and ok(node) and memory._VMID.fullmatch(key):
        out = [f"/nodes/{node}/{kind}/{key}/status/current", f"/nodes/{node}/{kind}/{key}/config"]
    elif kind == "node" and ok(key):
        out = [f"/nodes/{key}/status"]
    elif kind == "storage" and ok(key):
        out = [f"/nodes/{n}/storage/{key}/status" for n in d.get("nodes", [])[:3] if ok(n)]
    elif kind == "pool" and ok(key):
        out = [f"/pools/{key}"]
    elif kind == "job" and ok(key):
        out = [f"/cluster/backup/{key}"]
    elif kind == "bridge" and ok(node, r["ident"]):
        out = [f"/nodes/{node}/network/{r['ident']}"]
    elif kind == "acl":
        out = ["/access/acl"]
    elif kind == "backup" and ok(node, d.get("storage")):
        out = [f"/nodes/{node}/storage/{d['storage']}/content"]
    return out


def _show(r: Mapping[str, Any]) -> dict[str, Any]:
    """The entry's id: memory's key (a bridge shows `node/iface`), as it always has."""
    return {"id": r["key"]}


# ---- learn: the one deliberate pass ------------------------------------------------------------------

def _learn(read: Callable[..., dict[str, Any] | None], db_at: Callable[[], sqlite3.Connection], box: str,
           start: float, gaps: list[str]) -> memory.LearnTally:
    """Cluster resources (whole), the token's permission map, storage, backup jobs, pools, ACLs, each
    node's network and each guest it listed (consult's own pending read). `read` stops at the budget
    by raising `memory._Spent` (the frame names it); what was gathered before still tallies."""
    from proximo.core import engine  # noqa: PLC0415 -- call time: engine imports memory

    plane = _PLANE
    guests: list[tuple[str, str, str | None]] = []
    nodes: list[str] = []
    sees: bool | None = None
    try:
        read("/cluster/resources", "/cluster/resources")
        env = read("/access/permissions", "/access/permissions", "all")
        whole, perms = consult._data_of(env) if env is not None else (False, None)
        sees = estate.build([estate.Answer("/access/permissions", {}, perms)]).sees_every("VM.Audit", "/vms") \
            if whole else None
        if sees is not True:
            gaps.append("this token's permission map does not show VM.Audit reaching every guest (or could not be "
                        "read): memory holds the token's estate, which may not be the whole one")
        for t in ("/storage", "/cluster/backup", "/pools", "/access/acl"):
            read(t, t)
        db = db_at()
        # what this pass's resources read kept, whether or not it could own its list: a read that retires
        # nothing still names the nodes and guests whose network and config are read next
        listed = "SELECT e.kind, e.key, e.node FROM entity e WHERE e.plane=? AND e.box=? AND e.last_seen >= ? AND " \
                 "e.gone_at IS NULL AND e.kind IN "
        nodes = [k for _, k, _ in db.execute(listed + "('node') ORDER BY e.key", (plane, box, start))]
        guests = [(k, kind, node) for kind, k, node in db.execute(
            listed + "('qemu','lxc') ORDER BY CAST(e.key AS INTEGER), e.kind", (plane, box, start))]
        for n in nodes:
            read(f"/nodes/{n}/network", "/nodes/{node}/network")
        for vmid, kind, node in guests:
            template = next(t for t in FANOUT if t.split("/")[3] == kind)
            if node is None:
                gaps.append(f"{kind}/{vmid} names no node to read its config at")
                continue
            read(engine.fill(template, {"node": node, "vmid": vmid}), template)
    except memory._Spent:                   # the frame has named it; what was listed still tallies
        pass
    # A list read on this pass that could not own (a row memory cannot key, an empty resources answer)
    # retired nothing: the pass is not whole, and it says so.
    gaps.extend(memory._read_not_owned(db_at(), plane, box, start, [
        ("/cluster/resources", "read:/cluster/resources", "resources"),
        *((t, f"read:{t}", t) for t in ("/storage", "/cluster/backup", "/pools", "/access/acl")),
        *((f"/nodes/{n}/network", f"read:/nodes/{{node}}/network|{json.dumps({'node': n})}", f"network/{n}")
          for n in nodes)]))
    kept = [(t, f"read:{t}") for t in ("/cluster/resources", "/storage", "/cluster/backup", "/pools",
                                       "/access/acl")]
    kept += [(f"/nodes/{n}/network", f"read:/nodes/{{node}}/network|{json.dumps({'node': n})}") for n in nodes]

    def after_kept(db: sqlite3.Connection) -> list[str]:
        read_at = dict(db.execute("SELECT nid, config_as_of FROM entity WHERE plane=? AND box=? AND kind IN "
                                  "('qemu','lxc')", (plane, box)))
        unread = sorted(nid for vmid, kind, _ in guests if (read_at.get(nid := f"{kind}/{vmid}") or 0) < start)
        if unread:
            return [f"{len(unread)} guest config(s) not kept on this pass: {', '.join(unread[:5])}"
                    + (" ..." if len(unread) > 5 else "")]
        return []
    return memory.LearnTally(kept=tuple(kept), count_kind="guests", count=len(guests), sees=sees,
                             after_kept=after_kept)


class _Pve:
    """PVE's `memory.PlaneShape`: the module's functions under the seam's names."""

    plane: str = _PLANE
    feeds: frozenset[str] = FEEDS
    vendor_kinds: frozenset[str] = VENDOR_KINDS
    kind_order: tuple[str, ...] = KIND_ORDER
    relating_owners: frozenset[str] = _RELATING
    answers_uses: bool = True           # disks and NICs: guests relate to storage and bridges
    id_names: frozenset[str] = frozenset()
    no_ident_kinds: frozenset[str] = frozenset({"acl"})            # an ACL row's ident is its subject
    no_name_kinds: frozenset[str] = frozenset({"acl", "backup"})   # a backup's name is derived from its volid
    global_ids: frozenset[str] = frozenset()      # no kind is matched by its key
    next_live: tuple[str, ...] = ("GET /cluster/resources",)
    whole_owner: str = "resources"
    token_sight: bool = False           # a whole read owns by what it is, whoever asked

    def owner(self, template: str, bound: Mapping[str, str], args: Mapping[str, Any], fields: str | None,
              data: Any, box: str, evaluating: bool, *, db: sqlite3.Connection | None = None,
              who: str | None = None) -> str | None:
        return _owner(template, bound, args, fields, data, box, evaluating)

    def ingest(self, f: memory._Feed, template: str, bound: dict[str, str], args: Mapping[str, Any],
               data: Any) -> None:
        _ingest(f, template, bound, args, data)

    def relate(self, db: sqlite3.Connection, box: str, t: float) -> None:
        _relate(db, self.plane, box, t)

    def paths(self, r: Mapping[str, Any]) -> list[str]:
        return _paths(r)

    def show(self, r: Mapping[str, Any]) -> dict[str, Any]:
        return _show(r)

    def learn(self, read: Callable[..., dict[str, Any] | None], db_at: Callable[[], sqlite3.Connection],
              box: str, start: float, gaps: list[str], *,
              who: Callable[[], str | None] = lambda: None) -> memory.LearnTally:
        return _learn(read, db_at, box, start, gaps)


SHAPE: memory.PlaneShape = _Pve()
memory.SHAPES[_PLANE] = SHAPE
# memory's back-compat names are PVE's (engine's read hook and doctor read `memory.FEEDS`)
memory.FEEDS, memory.VENDOR_KINDS, memory.FANOUT = FEEDS, VENDOR_KINDS, FANOUT
