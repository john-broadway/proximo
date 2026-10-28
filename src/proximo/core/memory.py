"""THE ESTATE MEMORY: what the door has seen of the estate, in ONE SQLite file beside the ledger, so
"where is 105", "who uses this storage" and "what changed" are a query, with no model and no
network. The design: "What the cut took" (2026-10-25), piece 3 and the terminal verbs of piece 4.

    a read the engine served (engine._keep, after the withhold)  -> feed()  -> the file
    learn(): the one deliberate pass, every read engine.execute  -> feed()  -> the file
    the file -> where / uses / changed / resolve                  (no vendor call, no model)

WHAT IS KEPT. The estate graph: entities (kind, key, name, node, status, tags, first and last seen,
added and gone, when a guest's config was read, `untrusted`, the address that wrote them) and edges
(src, rel, dst, as_of, and the slots a disk or NIC sits in), built by `estate.build` from the
vendor's answer with the relations `estate.Edge` names, so a terminal answer and a consult agree by
construction. An FTS5 index over ids, names and tags; without FTS5, LIKE over the same columns
(doctor says so; nothing refuses).

WHAT MAY JUDGE ABSENCE. Every fed read adds or refreshes. Only a WHOLE read of a list may retire what
it no longer holds, or begin memory for what it holds (so a later first sighting is "added"):

    an unfiltered GET (no argument narrows it, no field subset), on a named box, of a list:
      /cluster/resources (and not empty)   guests, nodes, storage
      /storage                             storage definitions (a disabled storage stays)
      /access/acl  /cluster/backup  /pools grants, backup jobs, pools
      /nodes/{node}/network                that node's bridges
      /nodes/{node}/storage/{storage}/content (or content=backup)   that storage's backups

Each such read OWNS what it lists; a thing is gone only when every owner that listed it has since
read whole without it (`sighting`), so a storage the definitions still hold does not flap when the
cluster view drops it. The engine's own reads (a consult's `type=vm` resources read with its field
subset, a plan's look at its target, which the engine marks `evaluating`) are real governed reads:
they feed entities and retire nothing. The door's answer cap does not make a read partial here: the
hook is fed the vendor's answer before the cap bounds what a model is handed.

THE RULES (the design's "Rules every piece keeps"): derived, never truth (deleting the file loses
convenience, never proof); fed opportunistically, never dialing (`learn` is the one deliberate pass,
under LEARN_MAX_READS); fail toward the worst case (`not_in_memory` + `absent_is_not_proof`, an empty
memory answers with no count, `uses` is complete only when it is); taint survives storage (an answer
built from an untrusted read's rows marks the session, refuses when the marker cannot be written, and
is fenced under PROXIMO_TAINT_FENCE); per plane and box; bounded (TEXT, and an id longer than it is
not kept at all, MAX_ROWS, MAX_ENTITIES, MAX_EDGES, and every answer's FINAL bytes, after its paths and
its fence, under ANSWER_BYTES, a path never cut); answers
are data, a verdict, short fixed codes and concrete next paths, never prose and never the caller's
words; every answer is a `core.recall` row on the ledger. Owner-only: created 0600 with O_EXCL and
O_NOFOLLOW before sqlite opens it read-write (never creating); a symlink (file or sidecar), a hard
link, another owner, a group or other bit, a file swapped between the check and the open, or an empty
file memory did not create is refused, never tightened. The directory is taken as given, like the
ledger's.

`PROXIMO_MEMORY` unset or 1/true/yes/on: on; 0/false/no/off: off, nothing created; any other word:
off, and doctor names it. `PROXIMO_MEMORY_PATH` moves the file (the same rules). PHASE B SEAM:
`resolve(words)` is the one function the MCP find calls for concrete paths.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from functools import cache, lru_cache
from threading import local as _thread_state
from typing import Any
from urllib.parse import quote

from proximo.core import consult, estate, spine, store
from proximo.core.errors import ProximoError

#: A name, a tag, a node list or a status, cut to this (the consult's cut for guest-authored text).
TEXT = 120
#: Rows a list shows; the total rides beside it.
SHOWN = 20
#: Matches `where` shows.
WHERE_SHOWN = 5
#: Every answer's ceiling in bytes of JSON, measured on the FINAL answer (paths and fence included).
ANSWER_BYTES = 4096
#: A read with more rows than this is not kept at all.
MAX_ROWS = 20_000
#: Per plane and box. Past it, the entities seen longest ago go first (counted, and remembered as
#: known so a reseen one is never "added").
MAX_ENTITIES = 50_000
MAX_EDGES = 200_000
#: LEARN'S BUDGET, the way consult budgets its reads: counted before a read starts, none past it.
LEARN_MAX_READS = 256
#: The guest config learn reads per guest: consult's fan-out, so learn and a consult read the same.
FANOUT = tuple(consult.FANOUT["guest_config"].templates.values())

_GUESTS = ("qemu", "lxc")
#: An entity id (`kind/key`) with the key at its bound; an edge end past it is not kept.
_NID = TEXT + 16
_NODE_LISTS = frozenset({"/nodes/{node}/qemu", "/nodes/{node}/lxc"})
_CONTENT = "/nodes/{node}/storage/{storage}/content"
#: What memory takes: the estate's sources but the permission map (the token's, not the estate's),
#: and the per-node guest lists (refresh only: they see one node).
FEEDS = frozenset(set(estate.SOURCES) - {"/access/permissions"}) | _NODE_LISTS
_KIND_WORDS = frozenset({"qemu", "lxc", "node", "storage", "pool", "bridge", "job"})
_ON, _OFF = frozenset({"", "1", "true", "yes", "on"}), frozenset({"0", "false", "no", "off"})
_FILE = "memory.db"
_SCHEMA_VERSION = 2
_NEXT_LIVE = ["GET /cluster/resources"]
#: A vendor id a path may carry: a node, storage, pool, job or bridge name, a vmid.
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_VMID = re.compile(r"[0-9]{1,10}")

_SCHEMA = """
CREATE TABLE entity (
    id INTEGER PRIMARY KEY,
    plane TEXT NOT NULL, box TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL, nid TEXT NOT NULL,
    ident TEXT, name TEXT, node TEXT, status TEXT, tags TEXT, detail TEXT,
    prev_status TEXT, status_changed_at REAL, first_seen REAL NOT NULL, last_seen REAL NOT NULL,
    added_at REAL, gone_at REAL, config_as_of REAL, untrusted INTEGER NOT NULL DEFAULT 0, source TEXT,
    UNIQUE (plane, box, nid));
CREATE INDEX entity_ident ON entity (plane, box, ident COLLATE NOCASE);
CREATE INDEX entity_name ON entity (plane, box, name COLLATE NOCASE);
CREATE INDEX entity_seen ON entity (plane, box, last_seen);
CREATE TABLE edge (
    plane TEXT NOT NULL, box TEXT NOT NULL, src TEXT NOT NULL, rel TEXT NOT NULL, dst TEXT NOT NULL,
    as_of REAL NOT NULL, via TEXT, PRIMARY KEY (plane, box, src, rel, dst)) WITHOUT ROWID;
CREATE INDEX edge_dst ON edge (plane, box, rel, dst);
CREATE TABLE sighting (
    plane TEXT NOT NULL, box TEXT NOT NULL, nid TEXT NOT NULL, owner TEXT NOT NULL, seen REAL NOT NULL,
    dropped REAL, PRIMARY KEY (plane, box, nid, owner)) WITHOUT ROWID;
CREATE INDEX sighting_owner ON sighting (plane, box, owner, dropped);
CREATE TABLE tomb (
    plane TEXT NOT NULL, box TEXT NOT NULL, nid TEXT NOT NULL, ts REAL NOT NULL,
    PRIMARY KEY (plane, box, nid)) WITHOUT ROWID;
CREATE TABLE meta (
    plane TEXT NOT NULL, box TEXT NOT NULL, k TEXT NOT NULL, v TEXT, PRIMARY KEY (plane, box, k)) WITHOUT ROWID;
"""


class Unusable(ProximoError):
    """The memory cannot be used on this box (off, or a file it must refuse): the operator's
    configuration, never a verdict of the spine."""


def _now() -> float:
    return time.time()


def _euid() -> int:
    return os.geteuid()


def _is_link(p: str) -> bool:
    return os.path.islink(p)


def setting() -> str:
    """`on`, `off`, or `unrecognised` (a word memory does not read: off, and doctor names it)."""
    word = os.environ.get("PROXIMO_MEMORY", "").strip().lower()
    return "on" if word in _ON else "off" if word in _OFF else "unrecognised"


def enabled() -> bool:
    return setting() == "on"


def path(ledger_path: str) -> str:
    """`PROXIMO_MEMORY_PATH`, else `memory.db` beside the ledger (the store's own placement)."""
    return os.environ.get("PROXIMO_MEMORY_PATH", "").strip() or os.path.join(os.path.dirname(ledger_path) or ".", _FILE)


@cache
def _fts5() -> bool:
    """Whether this sqlite was built with FTS5 (most are; some distributions' are not)."""
    try:
        with sqlite3.connect(":memory:") as probe:
            probe.execute("CREATE VIRTUAL TABLE t USING fts5(x)")
        return True
    except sqlite3.Error:
        return False


def _cut(v: Any, n: int = TEXT) -> str | None:
    return None if v is None else str(v)[:n]


def _echo(text: str, n: int = 40) -> str:
    """The caller's words for a receipt: whole when short, else a prefix, the length and a fingerprint."""
    if len(text) <= n:
        return text
    return f"{text[:n]}... ({len(text)} chars, sha256:{hashlib.sha256(text.encode()).hexdigest()[:12]})"


# ---- the file: owner-only before sqlite opens it, and the same file after --------------------------

def _guard(p: str, create: bool) -> tuple[os.stat_result, bool] | None:
    """The file's stat, and whether this call made it, when it is there and usable; None when absent
    and not to be created. Refuses a symlink (at the file or a sidecar sqlite would open), a
    non-regular file, a second name (a hard link: the inventory would sit wherever that name is),
    another user's file, a group or other bit, and an empty file this call did not make (sqlite would
    silently turn a ledger not yet written, pointed at by mistake, into a database): estate inventory
    in plaintext is the operator's alone."""
    for f in (p, p + "-journal", p + "-wal", p + "-shm"):
        if _is_link(f):
            raise Unusable("the memory file (or its journal) is a symlink: refusing to open estate state through it")
    made = False
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        if not create:
            return None
        os.makedirs(os.path.dirname(p) or ".", mode=0o700, exist_ok=True)
        try:
            os.close(os.open(p, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600))
            made = True
        except FileExistsError:       # made first by another process, or a link planted since: judged below
            pass
        st = os.lstat(p)
    if not stat.S_ISREG(st.st_mode):
        raise Unusable("the memory file is not a regular file")
    if st.st_nlink > 1:
        raise Unusable("the memory file has a second name (a hard link): refusing; remove the other name")
    if st.st_uid != _euid():
        raise Unusable("the memory file is owned by another user: refusing to read or write it")
    if st.st_mode & 0o077:
        raise Unusable(f"the memory file is group/other-accessible (mode {stat.S_IMODE(st.st_mode):03o}): "
                       "refusing; chmod 600 it, or delete it (it is derived)")
    if st.st_size == 0 and not made:
        raise Unusable("the memory file is an empty file memory did not create: refusing to write a database "
                       "into it; delete it if it is meant to be the memory (it is derived)")
    return st, made


#: A connection per thread per file while the file is the same one (device, inode and change time:
#: another process's checkpoint, or a file deleted and made again under a reused inode, opens it
#: afresh); judged by `_guard` on EVERY use. At most _CACHED files per thread.
_local = _thread_state()
_CACHED = 4


def _ident(st: os.stat_result) -> tuple[int, int, int]:
    return st.st_dev, st.st_ino, st.st_ctime_ns


def _open(ledger_path: str, *, create: bool) -> sqlite3.Connection | None:
    p = path(ledger_path)
    judged = _guard(p, create)
    if judged is None:
        return None
    st, _ = judged
    conns: dict[str, tuple[sqlite3.Connection, tuple[int, int, int]]] = _local.__dict__.setdefault("conns", {})
    held = conns.pop(p, None)
    if held is not None and held[1] == _ident(st):
        conns[p] = held
        return held[0]
    if held is not None:
        held[0].close()
    try:    # read-write, NEVER creating (`_guard` made the file with O_EXCL): a name swapped to a
            # dangling link between the check and the open creates nothing at its target
        db = sqlite3.connect(f"file:{quote(p, safe='/')}?mode=rw&nofollow=1", uri=True, timeout=0.5)
    except sqlite3.Error as exc:
        raise Unusable(f"the memory file could not be opened ({type(exc).__name__}): refusing") from exc
    try:
        after = os.lstat(p)           # the file sqlite opened is the file `_guard` judged
        if stat.S_ISLNK(after.st_mode) or (after.st_dev, after.st_ino) != (st.st_dev, st.st_ino):
            raise Unusable("the memory file changed between its check and its open: refusing")
        if db.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA_VERSION:
            # derived data: an older shape is dropped whole and rebuilt by the next reads
            for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE "
                                      "'sqlite_%' AND name NOT LIKE 'words_%'").fetchall():
                db.execute(f'DROP TABLE IF EXISTS "{name}"')
            db.executescript(_SCHEMA)
            db.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            db.execute("PRAGMA journal_mode=WAL")       # derived data: no fsync per read it rides on
            db.commit()
        db.execute("PRAGMA synchronous=NORMAL")
        if create and _fts5() and _meta(db, "", "", "fts_synced") != "1":
            db.execute("CREATE VIRTUAL TABLE IF NOT EXISTS words USING fts5(key, name, tags)")
            db.execute("DELETE FROM words")
            db.execute("INSERT INTO words (rowid, key, name, tags) SELECT id, key, name, "
                       "replace(replace(tags, ';', ' '), ',', ' ') FROM entity")
            _set(db, "", "", "fts_synced", "1")
            db.commit()
    except BaseException:
        db.close()
        raise
    conns[p] = (db, _ident(os.lstat(p)))
    while len(conns) > _CACHED:
        conns.pop(next(iter(conns)))[0].close()
    return db


def _settle(ledger_path: str) -> None:
    """After this process wrote: the change time it moved is its own, so the held connection stays."""
    p = path(ledger_path)
    conns = _local.__dict__.get("conns", {})
    if p in conns:
        try:
            conns[p] = (conns[p][0], _ident(os.lstat(p)))
        except OSError:
            conns.pop(p)[0].close()


def _meta(db: sqlite3.Connection, plane: str, box: str, k: str) -> str | None:
    row = db.execute("SELECT v FROM meta WHERE plane=? AND box=? AND k=?", (plane, box, k)).fetchone()
    return row[0] if row else None


def _set(db: sqlite3.Connection, plane: str, box: str, k: str, v: Any) -> None:
    db.execute("INSERT INTO meta (plane, box, k, v) VALUES (?,?,?,?) "
               "ON CONFLICT (plane, box, k) DO UPDATE SET v=excluded.v", (plane, box, k, str(v)))


def _bump(db: sqlite3.Connection, plane: str, box: str, k: str, n: int = 1) -> None:
    _set(db, plane, box, k, int(_meta(db, plane, box, k) or 0) + n)


def _searchable(db: sqlite3.Connection) -> bool:
    return _fts5() and _meta(db, "", "", "fts_synced") == "1"


# ---- feeding: one vendor answer at a time ------------------------------------------------------------

def _owner(template: str, bound: Mapping[str, str], args: Mapping[str, Any], fields: str | None,
           data: Any, box: str, evaluating: bool) -> str | None:
    """The list a WHOLE read of `template` owns, or None (a read that may only add or refresh): a
    field subset, a door's own look for a verdict, a box with no name, or a non-list never owns."""
    if evaluating or fields is not None or not box or not isinstance(data, list):
        return None
    if template == "/cluster/resources":
        return "resources" if not args and data else None
    if template in ("/storage", "/access/acl", "/cluster/backup", "/pools"):
        return None if args else template
    if template == "/nodes/{node}/network":
        return None if args else f"network/{bound.get('node')}"
    if template == _CONTENT:
        whole = not set(args) - {"content"} and args.get("content") in (None, "backup")
        return f"content/{bound.get('node')}/{bound.get('storage')}" if whole else None
    return None


def feed(ledger_path: str, plane: str, box: str, template: str, bound: Mapping[str, str],
         args: Mapping[str, Any], data: Any, *, source: str, untrusted: bool, fields: str | None = None,
         evaluating: bool = False, now: float | None = None) -> None:
    """Keep what one read answered (`template` the published address it was served on, `bound` the
    values its path filled, `args` and `fields` how it was asked, `evaluating` when it was the door's
    own look for a verdict, `data` the vendor's answer after the withhold). Raises on a failure of its
    own; the engine swallows it, because a convenience must never fail the read it rides on."""
    if plane != "pve" or template not in FEEDS or not enabled():
        return
    t = _now() if now is None else now
    db = _open(ledger_path, create=True)
    assert db is not None                                   # noqa: S101 -- create=True never answers None
    try:
        with db:
            if isinstance(data, list) and len(data) > MAX_ROWS:
                _bump(db, plane, box, "skipped")
                return
            owner = _owner(template, bound, args, fields, data, box, evaluating)
            f = _Feed(db, plane, box, source, untrusted, t, owner)
            _ingest(f, template, dict(bound), args, data)
            if owner is not None:
                f.retire()
                if _meta(db, plane, box, f"first_whole:{owner}") is None:
                    _set(db, plane, box, f"first_whole:{owner}", t)
                _set(db, plane, box, f"whole:{owner}", t)
            if _meta(db, plane, box, "first_fed") is None:
                _set(db, plane, box, "first_fed", t)
            _set(db, plane, box, "last_fed", t)
            _set(db, plane, box, f"read:{template}", t)
            _set(db, plane, box, f"read:{template}|{json.dumps(dict(bound), sort_keys=True)}", t)
            _evict(db, plane, box, t)
    finally:
        _settle(ledger_path)


class _Feed:
    """One answer going into the file: `put` an entity (and, for a whole read, its owner's sighting),
    the edges its template carries, then `retire` what the owner no longer lists."""

    def __init__(self, db: sqlite3.Connection, plane: str, box: str, source: str, untrusted: bool, t: float,
                 owner: str | None) -> None:
        self.db, self.plane, self.box, self.t = db, plane, box, t
        self.source, self.untrusted, self.owner = source, untrusted, owner
        prev = _meta(db, plane, box, f"whole:{owner}") if owner else None
        self.prev_whole = float(prev) if prev else None

    def put(self, kind: str, key: str, **kw: Any) -> None:
        if len(key) > TEXT:       # an id past the bound is not kept (a cut one would collide and orphan its edges)
            _bump(self.db, self.plane, self.box, "skipped_ids")
            return
        nid = _upsert(self.db, self.plane, self.box, kind, key, t=self.t, source=self.source,
                      untrusted=self.untrusted, **kw)
        if self.owner is None:
            return
        known = self.db.execute("SELECT 1 FROM sighting WHERE plane=? AND box=? AND nid=? AND owner=?",
                                (self.plane, self.box, nid, self.owner)).fetchone()
        if known is None and self.prev_whole is not None and not self.db.execute(
                "SELECT 1 FROM tomb WHERE plane=? AND box=? AND nid=?", (self.plane, self.box, nid)).fetchone():
            # first listed by an owner that has read whole before, and not there at that read: added,
            # dated when memory first saw it
            self.db.execute("UPDATE entity SET added_at=first_seen WHERE plane=? AND box=? AND nid=? AND "
                            "first_seen > ? AND added_at IS NULL", (self.plane, self.box, nid, self.prev_whole))
        self.db.execute("INSERT INTO sighting VALUES (?,?,?,?,?,NULL) ON CONFLICT (plane, box, nid, owner) "
                        "DO UPDATE SET seen=excluded.seen, dropped=NULL",
                        (self.plane, self.box, nid, self.owner, self.t))

    def retire(self) -> None:
        """What this owner listed before and not now is dropped by it; a thing every owner has dropped
        is gone, dated by this read."""
        db, args = self.db, (self.plane, self.box, self.owner)
        db.execute("UPDATE sighting SET dropped=? WHERE plane=? AND box=? AND owner=? AND dropped IS NULL "
                   "AND seen < ?", (self.t, *args, self.t))
        db.execute("UPDATE entity SET gone_at=? WHERE plane=? AND box=? AND gone_at IS NULL AND nid IN "
                   "(SELECT nid FROM sighting WHERE plane=? AND box=? AND owner=? AND dropped=?) AND NOT EXISTS "
                   "(SELECT 1 FROM sighting s WHERE s.plane=entity.plane AND s.box=entity.box AND s.nid=entity.nid "
                   "AND s.dropped IS NULL)", (self.t, self.plane, self.box, *args, self.t))
        if self.owner in ("resources", "/cluster/backup", "/pools"):
            _relate(db, self.plane, self.box, self.t)

    def edges(self, edges: Iterable[estate.Edge], via: Mapping[estate.Edge, str] | None = None) -> None:
        _insert(self.db, self.plane, self.box, edges, self.t, via)

    def resources(self, est: estate.Estate) -> None:
        runs = {e.src: e for e in est.edges() if e.rel == "runs_on"}
        for g in est.guests:
            self.put(g.kind, g.vmid, ident=g.vmid, name=g.name, node=g.node, status=g.status,
                     tags=";".join(g.tags) if g.tags is not None else None,
                     detail={"pool": g.pool} if g.pool else None)
            _replace(self.db, self.plane, self.box, g.key, ("runs_on",), [runs[g.key]] if g.key in runs else [],
                     self.t)
        for n in est.nodes:
            self.put("node", n.name, ident=n.name, name=n.name, node=n.name, status=n.status)
        per: dict[str, list[estate.Storage]] = {}
        for st in est.storages:
            per.setdefault(st.id, []).append(st)
        for sid, rows in per.items():       # one row per node: one storage, its nodes in detail
            nodes = sorted({x.node for x in rows if x.node})
            statuses = {x.status for x in rows if x.status}
            self.put("storage", sid, ident=sid, name=sid,
                     node=",".join(nodes[:3]) + (f",+{len(nodes) - 3}" if len(nodes) > 3 else "") or None,
                     status=(statuses.pop() if len(statuses) == 1 else "mixed") if statuses else None,
                     detail={"nodes": [n for n in nodes if _ID.fullmatch(n)][:16]})
        if self.owner is None:
            _relate(self.db, self.plane, self.box, self.t)

    def config(self, est: estate.Estate) -> None:
        g = est.guests[0] if est.guests else None
        if g is None or g.key in est.unread:      # an empty config is a failed read, never "no disks"
            return
        self.put(g.kind, g.vmid, ident=g.vmid, name=g.name, node=g.node, config=True)
        slots: dict[estate.Edge, set[str]] = {}
        for d in est.disks:
            if d.storage and not d.cdrom:
                slots.setdefault(estate.Edge(g.key, "disk_on", f"storage/{d.storage}"), set()).add(d.slot)
        for n in est.nics:
            if n.bridge:
                slots.setdefault(estate.Edge(g.key, "nic_on", f"bridge/{n.bridge}"), set()).add(n.slot)
        edges = [e for e in est.edges() if e.rel in ("disk_on", "nic_on")]
        _replace(self.db, self.plane, self.box, g.key, ("disk_on", "nic_on"), edges, self.t,
                 via={e: ",".join(sorted(slots.get(e, ()))) for e in edges})

    def storage(self, est: estate.Estate) -> None:
        for st in est.storages:
            self.put("storage", st.id, ident=st.id, name=st.id, detail={k: v for k, v in (
                ("type", st.type), ("shared", st.shared), ("disabled", st.disabled)) if v is not None})

    def backup(self, est: estate.Estate) -> None:
        for j in est.jobs:
            self.put("job", j.id, ident=j.id, name=j.id,
                     status=None if j.enabled is None else "enabled" if j.enabled else "disabled",
                     detail={"all": j.all, "vmids": list(j.vmids) if j.vmids is not None else None, "pool": j.pool,
                             "exclude": list(j.exclude) if j.exclude is not None else None})
        if self.owner is None:
            _relate(self.db, self.plane, self.box, self.t)

    def pools(self, est: estate.Estate) -> None:
        for pool in est.pools:
            self.put("pool", pool.id, ident=pool.id, name=pool.id,
                     detail={"members": list(pool.members) if pool.members is not None else None})
        if self.owner is None:
            _relate(self.db, self.plane, self.box, self.t)

    def acl(self, est: estate.Estate) -> None:
        for a in est.acls:
            self.put("acl", f"{a.path} {a.type or 'subject'}/{a.ugid} {a.role or ''}".strip(), ident=a.ugid,
                     name=a.ugid, tags=a.role, detail={"path": a.path, "propagate": a.propagate})
        if self.owner is not None:        # a whole list is every grant: its edges are exactly these
            self.db.execute("DELETE FROM edge WHERE plane=? AND box=? AND rel='granted_on'", (self.plane, self.box))
        self.edges(e for e in est.edges() if e.rel == "granted_on")

    def network(self, est: estate.Estate) -> None:
        for i in est.ifaces:
            if i.type and "bridge" in i.type.lower():
                self.put("bridge", f"{i.node}/{i.iface}", ident=i.iface, name=i.iface, node=i.node,
                         status=None if i.active is None else "active" if i.active else "inactive")

    def content(self, est: estate.Estate, node: str | None) -> None:
        for v in est.volumes:
            if v.content == "backup":
                self.put("backup", v.volid, ident=v.volid, name=v.volid.rpartition("/")[2], node=node,
                         detail={"storage": v.storage, "vmid": v.vmid, "ctime": v.ctime})
        self.edges(e for e in est.edges() if e.rel == "backup_of")


def _ingest(f: _Feed, template: str, bound: dict[str, str], args: Mapping[str, Any], data: Any) -> None:
    if template in _NODE_LISTS:          # one node's guests: kept like resources rows, never a whole read
        kind = template.split("/")[3]
        data = [{**r, "type": kind, "node": bound.get("node")} for r in data if isinstance(r, dict)] \
            if isinstance(data, list) else []
        template, bound = "/cluster/resources", {}
    est = estate.build([estate.Answer(template, bound, data)])
    if template == "/cluster/resources":
        f.resources(est)
    elif template.endswith(("/config", "/pending")):
        f.config(est)
    elif template.endswith("/network"):
        f.network(est)
    elif template == _CONTENT:
        f.content(est, bound.get("node"))
    else:
        {"/storage": f.storage, "/cluster/backup": f.backup, "/pools": f.pools, "/access/acl": f.acl}[template](est)


def _upsert(db: sqlite3.Connection, plane: str, box: str, kind: str, key: str, *, t: float, source: str,
            untrusted: bool, ident: Any = None, name: Any = None, node: Any = None, status: Any = None,
            tags: Any = None, detail: Mapping[str, Any] | None = None, config: bool = False) -> str:
    """One entity; its nid back. A field the vendor did not give keeps what was known (unknown is not
    empty); detail merges key by key; a new status moves the old one to `prev_status` with the time;
    seen again, it is not gone; the untrusted mark is sticky, and so is the address that wrote it."""
    nid = f"{kind}/{key}"
    name, tags, node, status, ident = _cut(name), _cut(tags), _cut(node), _cut(status), _cut(ident)
    row = db.execute("SELECT id, status, untrusted, source, detail FROM entity WHERE plane=? AND box=? AND nid=?",
                     (plane, box, nid)).fetchone()
    if row is None:
        blob = json.dumps(dict(detail), sort_keys=True, default=str) if detail else None
        cur = db.execute(
            "INSERT INTO entity (plane, box, kind, key, nid, ident, name, node, status, tags, detail, first_seen, "
            "last_seen, config_as_of, untrusted, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (plane, box, kind, key, nid, ident, name, node, status, tags, blob, t, t,
             t if config else None, int(untrusted), source))
        eid = cur.lastrowid
    else:
        eid, old, was, had, blob = row
        merged = {**(json.loads(blob) if blob else {}), **(detail or {})}
        moved = status is not None and old is not None and status != old
        keep_mark = bool(was) and not untrusted          # a trusted read never clears the mark or its source
        db.execute(
            "UPDATE entity SET ident=COALESCE(?, ident), name=COALESCE(?, name), node=COALESCE(?, node), "
            "tags=COALESCE(?, tags), detail=?, status=COALESCE(?, status), last_seen=?, gone_at=NULL, "
            "prev_status=CASE WHEN ? THEN ? ELSE prev_status END, "
            "status_changed_at=CASE WHEN ? THEN ? ELSE status_changed_at END, "
            "config_as_of=CASE WHEN ? THEN ? ELSE config_as_of END, untrusted=?, source=? WHERE id=?",
            (ident, name, node, tags, json.dumps(merged, sort_keys=True, default=str) if merged else None, status, t,
             moved, old, moved, t, config, t, int(bool(was) or untrusted), had if keep_mark else source, eid))
    if _searchable(db):
        db.execute("DELETE FROM words WHERE rowid=?", (eid,))
        db.execute("INSERT INTO words (rowid, key, name, tags) SELECT id, key, name, "
                   "replace(replace(tags, ';', ' '), ',', ' ') FROM entity WHERE id=?", (eid,))
    elif not _fts5():
        _set(db, "", "", "fts_synced", "0")       # written without the index: rebuilt when FTS5 is back
    return nid


def _insert(db: sqlite3.Connection, plane: str, box: str, edges: Iterable[estate.Edge], t: float,
            via: Mapping[estate.Edge, str] | None = None) -> None:
    db.executemany("INSERT INTO edge VALUES (?,?,?,?,?,?,?) ON CONFLICT (plane, box, src, rel, dst) "
                   "DO UPDATE SET as_of=excluded.as_of, via=excluded.via",
                   [(plane, box, e.src, e.rel, e.dst, t, (via or {}).get(e)) for e in edges
                    if len(e.src) <= _NID and len(e.dst) <= _NID])


def _replace(db: sqlite3.Connection, plane: str, box: str, src: str, rels: tuple[str, ...],
             edges: Iterable[estate.Edge], t: float, via: Mapping[estate.Edge, str] | None = None) -> None:
    """A source's edges of these relations are what this read says, wholesale: a detached disk or a
    migrated guest leaves the old edge behind it."""
    db.execute(f"DELETE FROM edge WHERE plane=? AND box=? AND src=? AND rel IN ({','.join('?' * len(rels))})",  # noqa: S608 -- placeholders only
               (plane, box, src, *rels))
    _insert(db, plane, box, edges, t, via)


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
    _insert(db, plane, box, [e for e in est.edges() if e.rel in ("in_pool", "covered_by") and e.dst not in gone], t)


def _evict(db: sqlite3.Connection, plane: str, box: str, t: float) -> None:
    (n,) = db.execute("SELECT count(*) FROM entity WHERE plane=? AND box=?", (plane, box)).fetchone()
    if n > MAX_ENTITIES:
        gone = db.execute("SELECT id, nid FROM entity WHERE plane=? AND box=? ORDER BY last_seen, id LIMIT ?",
                          (plane, box, n - MAX_ENTITIES)).fetchall()
        db.executemany("DELETE FROM entity WHERE id=?", [(i,) for i, _ in gone])
        db.executemany("DELETE FROM edge WHERE plane=? AND box=? AND (src=? OR dst=?)",
                       [(plane, box, nid, nid) for _, nid in gone])
        db.executemany("DELETE FROM sighting WHERE plane=? AND box=? AND nid=?", [(plane, box, nid) for _, nid in gone])
        db.executemany("INSERT INTO tomb VALUES (?,?,?,?) ON CONFLICT (plane, box, nid) DO UPDATE SET ts=excluded.ts",
                       [(plane, box, nid, t) for _, nid in gone])
        db.execute("DELETE FROM tomb WHERE plane=? AND box=? AND nid IN (SELECT nid FROM tomb WHERE plane=? AND "
                   "box=? ORDER BY ts DESC LIMIT -1 OFFSET ?)", (plane, box, plane, box, MAX_ENTITIES))
        if _searchable(db):
            db.executemany("DELETE FROM words WHERE rowid=?", [(i,) for i, _ in gone])
        _bump(db, plane, box, "evicted", len(gone))
        _set(db, plane, box, "edges_evicted_at", t)   # its edges went with it, and so did its place in every count
    (m,) = db.execute("SELECT count(*) FROM edge WHERE plane=? AND box=?", (plane, box)).fetchone()
    if m > MAX_EDGES:
        old = db.execute("SELECT src, rel, dst FROM edge WHERE plane=? AND box=? ORDER BY as_of LIMIT ?",
                         (plane, box, m - MAX_EDGES)).fetchall()
        db.executemany("DELETE FROM edge WHERE plane=? AND box=? AND src=? AND rel=? AND dst=?",
                       [(plane, box, *k) for k in old])
        _bump(db, plane, box, "evicted_edges", len(old))
        _set(db, plane, box, "edges_evicted_at", t)


# ---- answering ---------------------------------------------------------------------------------------

def _iso(ts: float | None) -> str | None:
    return None if ts is None else datetime.datetime.fromtimestamp(ts, datetime.UTC).isoformat(timespec="seconds")


def _age(ts: float | None, now: float) -> int | None:
    return None if ts is None else int(round(now - ts))


def _stamp(ts: float | None, now: float) -> dict[str, Any]:
    return {"as_of": _iso(ts), "age_seconds": _age(ts, now)}


def _usable(ledger_path: str) -> sqlite3.Connection | None:
    if not enabled():
        raise Unusable("the estate memory is off on this box (PROXIMO_MEMORY); unset it to keep one")
    return _open(ledger_path, create=False)


def _empty(now: float) -> dict[str, Any]:
    """Nothing kept for this box: NO count, not even an empty list ("nothing observed" is not "nothing
    there", and a small model reads the number)."""
    return {"source": "memory", "verdict": "not_in_memory", "codes": ["memory_empty", "absent_is_not_proof"],
            "next": list(_NEXT_LIVE), **_stamp(None, now)}


_COLS = ("kind", "key", "ident", "name", "node", "status", "detail", "last_seen", "untrusted", "source",
         "config_as_of", "prev_status", "status_changed_at", "first_seen", "added_at", "gone_at")
_SELECT = ", ".join(_COLS)


def _rows(cur: Iterable[tuple]) -> list[dict[str, Any]]:
    return [dict(zip(_COLS, r, strict=True)) for r in cur]


@lru_cache(maxsize=4096)
def _published(p: str) -> bool:
    """Whether `GET <p>` is a concrete path the table serves as a read: checked at runtime, so a path
    memory hands out is never one the door would refuse as unpublished."""
    from proximo.core import engine  # noqa: PLC0415 -- call time: engine imports this module

    try:
        return "{" not in p and engine.resolve("pve", "GET", p).access == "read"
    except Exception:  # noqa: BLE001 -- unpublished or malformed: not a path to hand out
        return False


def _paths(r: Mapping[str, Any]) -> list[str]:
    """The concrete published GETs that read this thing live, built only from vendor ids that pass
    `_ID`/`_VMID` and from the feeding read's own path parameters, each checked by `_published`. A
    gone thing has none."""
    if r.get("gone_at") is not None:
        return []
    kind, key, node = r["kind"], r["key"], r["node"]
    d = json.loads(r["detail"]) if r.get("detail") else {}

    def ok(*ids: Any) -> bool:
        return all(isinstance(i, str) and _ID.fullmatch(i) for i in ids)
    out: list[str] = []
    if kind in _GUESTS and node and ok(node) and _VMID.fullmatch(key):
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
    return [f"GET {p}" for p in out if _published(p)]


def _mark(rows: Iterable[Mapping[str, Any]], ledger_path: str) -> bool:
    """TAINT SURVIVES STORAGE: an answer carrying rows an untrusted address wrote marks the session with
    that address, as the read did, and is refused when the marker cannot be written. True: untrusted."""
    sources = sorted({r["source"] or "pve:memory" for r in rows if r["untrusted"]})
    if sources and spine.taint_tracking_on():
        audit_dir = os.path.dirname(ledger_path)
        for s in sources:
            try:
                if not audit_dir:
                    raise OSError("the ledger has no directory to hold the taint marker")
                spine.mark_tainted(audit_dir, s)
            except Exception as exc:  # noqa: BLE001 -- any failure to mark is a refusal to serve
                raise ProximoError(f"memory holds text an untrusted read ({s}) wrote and the taint marker could "
                                   f"not be written ({type(exc).__name__}); the answer was not served "
                                   "(fail-closed)") from exc
    return bool(sources)


def _shrink(item: Any) -> Any:
    """A lone row too big for the answer: its lists to two, its strings to 40 characters, its `paths`
    untouched (each is a published GET built from bounded ids; a cut path was a different guest's)."""
    if isinstance(item, dict):
        return {k: (v if k == "paths" else _shrink(v)) for k, v in item.items()}
    if isinstance(item, list):
        return [_shrink(v) for v in item[:2]]
    return item[:40] if isinstance(item, str) else item


def _final(answer: dict[str, Any], rows: Sequence[Mapping[str, Any]], ledger_path: str, lists: tuple[str, ...],
           derive: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
    """Mark, then render (derived keys, the fence) and MEASURE the final bytes; over ANSWER_BYTES, the
    longest list gives up a row from its end (and says `<key>_shown`), and a lone row too big is cut
    shorter, never dropped."""
    untrusted = _mark(rows, ledger_path)
    fence = untrusted and spine.fence_on()

    def render() -> dict[str, Any]:
        out = dict(answer)
        if derive is not None:
            derive(out)
        if untrusted:
            out["untrusted"] = True
        if fence:
            for k in lists:
                if k in out:
                    out[k] = spine.fence("pve:memory", out[k])
        return out
    shrunk: set[str] = set()
    while True:
        out = render()
        if len(json.dumps(out, default=str)) <= ANSWER_BYTES:
            return out
        k = max((k for k in lists if answer.get(k) and k not in shrunk),
                key=lambda k: len(json.dumps(answer[k], default=str)), default=None)
        if k is None:
            return out
        if len(answer[k]) > 1:
            answer[k] = answer[k][:-1]
            answer[f"{k}_shown"] = len(answer[k])
        else:
            answer[k] = [_shrink(answer[k][0])]
            shrunk.add(k)


def _receipt(ledger_path: str, verb: str, asked: str, out: Mapping[str, Any]) -> None:
    """A `core.recall` row, like `since=`: what memory told the caller (verdict, counts, the taint
    label), never a guest's text. Best-effort, like every read's row."""
    from proximo.core.ledger import LedgerConfig, open_ledger  # noqa: PLC0415
    from proximo.core.principal import ledger_principal  # noqa: PLC0415

    detail = {"source": "memory", "verb": verb, "asked": _echo(asked), "verdict": out.get("verdict"),
              "untrusted": bool(out.get("untrusted")),
              **{k: out[k] for k in ("total", "counts", "complete", "why") if k in out}}
    try:
        open_ledger(LedgerConfig(audit_log_path=ledger_path,
                                 audit_key_path=os.environ.get("PROXIMO_AUDIT_KEY_PATH") or None)).record(
            "core.recall", target=f"memory {verb}", detail=detail, principal=ledger_principal())
    except Exception:  # noqa: BLE001, S110 -- a receipt is a read's: it never fails the answer
        pass


def _kinds(words: list[str]) -> tuple[set[str], list[str]]:
    """The kind words of a question (find's own vocabulary, `records/vocab.toml`: a container is
    `lxc`, a vm `qemu`), and the words left to match. The vocabulary loads only when a word may be one."""
    kinds: set[str] = set()
    rest = []
    syn: Mapping[str, frozenset[str]] | None = None
    for w in words:
        if w in _KIND_WORDS:
            kinds.add(w)
            continue
        if w.isalpha():
            if syn is None:
                from proximo.core import search  # noqa: PLC0415 -- call time: search builds the address index
                syn = search.synonyms()
            if w in syn and syn[w] <= set(_GUESTS):
                kinds |= syn[w]
                continue
        rest.append(w)
    return kinds, rest


def _like(w: str) -> str:
    return "%" + w.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _match(db: sqlite3.Connection, plane: str, box: str, words: str) -> list[dict[str, Any]]:
    toks = re.findall(r"[^\s\"']+", words.lower())[:8]
    if len(toks) == 1:                    # an id or a name said alone: no vocabulary needed
        kinds, rest = set(), toks
        exact = _exact(db, plane, box, kinds, rest[0])
        if exact:
            return exact
        kinds, rest = _kinds(toks)
    else:
        kinds, rest = _kinds(toks)
    scope = " AND kind IN (%s)" % ",".join("?" * len(kinds)) if kinds else ""    # noqa: UP031 -- placeholders only
    base = (plane, box, *sorted(kinds))
    order = " ORDER BY gone_at IS NOT NULL, CASE WHEN kind IN ('qemu','lxc') THEN 0 ELSE 1 END, kind, length(key), key"
    q = f"SELECT {_SELECT} FROM entity WHERE plane=? AND box=?{scope}"                 # noqa: S608
    if not rest:
        return _rows(db.execute(q + order, base)) if kinds else []
    if len(rest) == 1 and (exact := _exact(db, plane, box, kinds, rest[0])):
        return exact
    if _searchable(db):
        fts = " AND ".join('"%s"*' % w.replace('"', '""') for w in rest)          # noqa: UP031
        return _rows(db.execute(q + " AND id IN (SELECT rowid FROM words WHERE words MATCH ?)" + order,   # noqa: S608 -- placeholders only
                                (*base, fts)))
    like = " AND ".join("(lower(key) LIKE ? ESCAPE '\\' OR lower(name) LIKE ? ESCAPE '\\' OR lower(tags) LIKE ? "
                        "ESCAPE '\\')" for _ in rest)
    return _rows(db.execute(q + f" AND {like}" + order,                                  # noqa: S608 -- placeholders only
                            (*base, *[x for w in rest for x in (_like(w),) * 3])))


def _exact(db: sqlite3.Connection, plane: str, box: str, kinds: set[str], word: str) -> list[dict[str, Any]]:
    """An exact id, key or name. A vendor id outranks a name that spells it: a guest named `105` or
    `pve1` never takes the first path from guest 105 or node pve1."""
    scope = " AND kind IN (%s)" % ",".join("?" * len(kinds)) if kinds else ""    # noqa: UP031 -- placeholders only
    return _rows(db.execute(
        f"SELECT {_SELECT} FROM entity WHERE plane=? AND box=?{scope} AND (lower(ident)=? OR lower(key)=? OR "  # noqa: S608
        "lower(name)=?) ORDER BY CASE WHEN lower(ident)=? OR lower(key)=? THEN 0 ELSE 1 END, gone_at IS NOT NULL, "
        "CASE WHEN kind IN ('qemu','lxc') THEN 0 ELSE 1 END, kind, key",
        (plane, box, *sorted(kinds), word, word, word, word, word)))


def where(ledger_path: str, plane: str, box: str, words: str, *, now: float | None = None,
          receipt: bool = True) -> dict[str, Any]:
    """A guest, node, storage, pool, job, bridge, grant or backup by its id, name, tag or the
    operator's words: kind, node, status (or `gone` with `gone_at`), and the concrete published GETs
    that read it live. The caller's words are never echoed."""
    now = _now() if now is None else now
    db = _usable(ledger_path)
    out: dict[str, Any]
    if db is None or _meta(db, plane, box, "last_fed") is None:
        out = {**_empty(now), "found": False}
    else:
        found = _match(db, plane, box, words)
        if not found:
            fed, learned = _meta(db, plane, box, "last_fed"), _meta(db, plane, box, "learned_at")
            out = {"source": "memory", "verdict": "not_in_memory", "found": False,
                   "codes": ["absent_is_not_proof"] + ([] if learned else ["never_learned"]),
                   "learned_age_seconds": _age(float(learned), now) if learned else None,
                   "next": list(_NEXT_LIVE), **_stamp(float(fed) if fed else None, now)}
        else:
            shown = found[:WHERE_SHOWN]

            def entry(r: Mapping[str, Any]) -> dict[str, Any]:
                e = {"kind": r["kind"], "id": r["key"], "name": r["name"], "node": r["node"], "status": r["status"],
                     "paths": _paths(r), "age_seconds": _age(r["last_seen"], now)}
                if r["gone_at"] is not None:
                    e.update(status="gone", last_status=r["status"], gone_at=_iso(r["gone_at"]))
                return e
            out = {"source": "memory", "verdict": "found", "found": True,
                   **_stamp(min(r["last_seen"] for r in shown), now), "matches": [entry(r) for r in shown]}
            if len(found) > len(shown):
                out["total"] = len(found)

            def paths(o: dict[str, Any]) -> None:    # outside the fence: vendor ids only, find's seam reads them
                o["paths"] = [p for m in out["matches"] for p in m["paths"]]
            out = _final(out, shown, ledger_path, ("matches",), paths)
    if receipt:
        _receipt(ledger_path, "where", words, out)
    return out


def resolve(words: str, *, plane: str = "pve", box: str | None = None, ledger_path: str | None = None,
            now: float | None = None) -> dict[str, Any]:
    """THE SEAM FIND CALLS (phase B): words -> the concrete published paths memory knows for them, in
    rank order (`paths`), with `where`'s answer. `box` and `ledger_path` default to the env's."""
    from proximo.core import wire  # noqa: PLC0415
    from proximo.core.ledger import LedgerConfig  # noqa: PLC0415

    box = box if box is not None else (wire.env_base_url(plane) or "")
    out = where(ledger_path or LedgerConfig.from_env().audit_log_path, plane, box, words, now=now)
    out.setdefault("paths", [])
    return out


def uses(ledger_path: str, plane: str, box: str, thing: str, *, now: float | None = None,
         receipt: bool = True) -> dict[str, Any]:
    """The guests (not gone) with a disk on a storage or a NIC on a bridge, by slot. Complete only when
    a whole resources read is in memory, every guest present has its config kept, nothing (an edge, or
    an entity with its edges and its place in the counts) was evicted since those configs, and the
    last learn saw every guest; otherwise `why` says which, in codes."""
    now = _now() if now is None else now
    db = _usable(ledger_path)
    if db is None or _meta(db, plane, box, "last_fed") is None:
        out = _empty(now)
    else:
        on = ("FROM edge e JOIN entity n ON n.plane=e.plane AND n.box=e.box AND n.nid=e.src WHERE e.plane=? "
              "AND e.box=? AND n.gone_at IS NULL AND ((e.rel='disk_on' AND e.dst=?) OR (e.rel='nic_on' AND e.dst=?))")
        args = (plane, box, f"storage/{thing}", f"bridge/{thing}")
        (total,) = db.execute(f"SELECT count(DISTINCT e.src) {on}", args).fetchone()      # noqa: S608
        shown, rows = [], []
        for src, via, name, node, st, u, sc in db.execute(
                f"SELECT e.src, group_concat(e.via), n.name, n.node, n.status, n.untrusted, n.source {on} "  # noqa: S608
                "GROUP BY e.src ORDER BY e.src LIMIT ?", (*args, SHOWN)):
            shown.append({"guest": src, "name": name, "node": node, "status": st,
                          "via": sorted(set(filter(None, (via or "").split(","))))})
            rows.append({"untrusted": u, "source": sc})
        guests = "FROM entity WHERE plane=? AND box=? AND kind IN ('qemu','lxc') AND gone_at IS NULL"
        (missing, oldest) = db.execute(f"SELECT sum(config_as_of IS NULL), min(config_as_of) {guests}",  # noqa: S608
                                       (plane, box)).fetchone()
        unread = _rows(db.execute(f"SELECT {_SELECT} {guests} AND config_as_of IS NULL ORDER BY nid LIMIT ?",  # noqa: S608
                                  (plane, box, SHOWN)))
        evicted = _meta(db, plane, box, "edges_evicted_at")
        why = [code for code, bad in (
            ("no_whole_read", _meta(db, plane, box, "whole:resources") is None),
            ("configs_unread", bool(missing)),
            ("edges_evicted", evicted is not None and (oldest is None or float(evicted) > oldest)),
            ("partial_sight", _meta(db, plane, box, "learn_sight") == "partial")) if bad]
        nxt = (list(_NEXT_LIVE) if "no_whole_read" in why else []) + [
            f"GET /nodes/{r['node']}/{r['kind']}/{r['key']}/pending" for r in unread
            if r["node"] and _ID.fullmatch(r["node"])
            and _published(f"/nodes/{r['node']}/{r['kind']}/{r['key']}/pending")][:5]
        if oldest is None:
            fed = _meta(db, plane, box, "last_fed")
            oldest = float(fed) if fed else None
        out = {"source": "memory", "verdict": "incomplete" if why else "complete", "complete": not why,
               **({"why": why} if why else {}), **_stamp(oldest, now), "guests": shown, "total": total,
               "unread": [f"{r['kind']}/{r['key']}" for r in unread], **({"next": nxt} if nxt else {})}
        if (missing or 0) > len(unread):
            out["unread_total"] = missing
        out = _final(out, rows, ledger_path, ("guests", "unread"))
    if receipt:
        _receipt(ledger_path, "uses", thing, out)
    return out


def changed(ledger_path: str, plane: str, box: str, window: str, *, now: float | None = None,
            receipt: bool = True) -> dict[str, Any]:
    """Added (first listed by a whole read after the one that began memory, and never known before),
    gone (dropped by every whole read that owned it) and status changes, over the window (30m, 24h, 7d)."""
    seconds = store.parse_since(window)
    now = _now() if now is None else now
    db = _usable(ledger_path)
    if db is None or _meta(db, plane, box, "first_fed") is None:
        out = _empty(now)
    else:
        cutoff = now - seconds
        q = f"SELECT {_SELECT} FROM entity WHERE plane=? AND box=? AND "      # noqa: S608
        added = _rows(db.execute(q + "added_at > ? ORDER BY added_at", (plane, box, cutoff)))
        moved = _rows(db.execute(q + "status_changed_at > ? ORDER BY status_changed_at", (plane, box, cutoff)))
        gone = _rows(db.execute(q + "gone_at > ? ORDER BY gone_at", (plane, box, cutoff)))

        def brief(r: Mapping[str, Any], **extra: Any) -> dict[str, Any]:
            return {"kind": r["kind"], "id": r["key"], "name": r["name"], "node": r["node"], **extra}
        fed, began = _meta(db, plane, box, "last_fed"), _meta(db, plane, box, "first_whole:resources")
        out = {"source": "memory", "window_s": seconds, "began": _iso(float(began)) if began else None,
               **_stamp(float(fed) if fed else None, now),
               "added": [brief(r, status=r["status"]) for r in added[:SHOWN]],
               "gone": [brief(r, gone_at=_iso(r["gone_at"]), last_seen=_iso(r["last_seen"])) for r in gone[:SHOWN]],
               "changed": [brief(r, **{"from": r["prev_status"], "to": r["status"], "at": _iso(r["status_changed_at"])})
                           for r in moved[:SHOWN]],
               "counts": {"added": len(added), "gone": len(gone), "changed": len(moved)},
               "codes": ["gone_by_whole_read", "added_after_first_whole_read"] + ([] if began else ["no_whole_read"])}
        out = _final(out, added[:SHOWN] + gone[:SHOWN] + moved[:SHOWN], ledger_path, ("added", "gone", "changed"))
    if receipt:
        _receipt(ledger_path, "changed", window, out)
    return out


#: The doctor flags `station` writes that are advice (`doctor._ADVISORY`): they move no exit code.
ADVISORY = ("memory search runs on LIKE",)


def station(lcfg: Any, flags: list[str]) -> dict[str, Any]:
    """Doctor's memory section: `status`, and its flags. Without FTS5, search runs on LIKE (advice); a
    word PROXIMO_MEMORY does not read (off, and the operator meant something), or a file memory must
    refuse or cannot read, is a flag that makes the report incomplete. Never a path."""
    from proximo.core.secretfile import safe_text  # noqa: PLC0415

    section = status(lcfg.audit_log_path)
    if section["setting"] == "unrecognised":
        flags.append("PROXIMO_MEMORY is set to a word memory does not read, so memory is off: unset it or 1 for on, "
                     "0 for off")
    if section["on"] and section["search"] == "like":
        flags.append("memory search runs on LIKE: this sqlite build has no FTS5 (or the index waits for the "
                     "next read to rebuild it); answers are the same, only slower on a big estate")
    if section.get("file") in ("refused", "unreadable"):
        flags.append(f"the estate memory file is {section['file']}: {safe_text(section.get('why', ''), paths=True)}")
    return section


def status(ledger_path: str) -> dict[str, Any]:
    """For doctor: state and counts, never a path. Never raises."""
    out: dict[str, Any] = {"on": enabled(), "setting": setting(), "fts5": _fts5(),
                           "search": "fts5" if _fts5() else "like"}
    if not out["on"]:
        return out
    try:
        db = _open(ledger_path, create=False)
    except (Unusable, OSError, sqlite3.Error) as exc:
        return {**out, "file": "refused", "why": str(exc) if isinstance(exc, Unusable) else type(exc).__name__}
    if db is None:
        return {**out, "file": "absent", "learned": "never"}
    try:
        (n,) = db.execute("SELECT count(*) FROM entity").fetchone()
        (boxes,) = db.execute("SELECT count(DISTINCT box) FROM entity").fetchone()
        totals = dict(db.execute("SELECT k, sum(CAST(v AS INTEGER)) FROM meta WHERE k IN "
                                 "('evicted', 'evicted_edges', 'skipped', 'skipped_ids') GROUP BY k"))
        learned = {v for (v,) in db.execute("SELECT v FROM meta WHERE k='learned'")}
        searchable = _searchable(db)
    except sqlite3.Error as exc:
        return {**out, "file": "unreadable", "why": type(exc).__name__}
    if not searchable:
        out["search"] = "like"          # no FTS5, or the index waits for the next write to rebuild it
    return {**out, "file": "present", "entities": n, "boxes": boxes, "evicted": totals.get("evicted") or 0,
            "evicted_edges": totals.get("evicted_edges") or 0, "skipped": totals.get("skipped") or 0,
            "skipped_ids": totals.get("skipped_ids") or 0,
            "learned": "never" if not learned else "complete" if learned == {"complete"} else "incomplete"}


# ---- learn: the one deliberate pass ------------------------------------------------------------------

class _Spent(Exception):
    pass


def learn(plane: str = "pve", *, cfg: Any = None, ledger_cfg: Any = None) -> dict[str, Any]:
    """Read the estate once, on the operator's word: cluster resources (whole), the token's permission
    map, storage, backup jobs, pools, ACLs, each node's network and each guest it listed (consult's own
    pending read). Every read is `engine.execute` (receipted, withheld, taint-marked, bounded) and the
    engine's read hook keeps it; this function keeps nothing itself and only tallies. Under
    LEARN_MAX_READS; anything that stops a whole picture (a read refused, failed, over budget, not kept
    on this pass, a token that cannot see every guest) is `complete: false` with the reason."""
    from proximo.core import engine, wire  # noqa: PLC0415 -- call time: engine imports this module
    from proximo.core.ledger import LedgerConfig  # noqa: PLC0415

    if not enabled():
        raise Unusable("the estate memory is off on this box (PROXIMO_MEMORY): learn has nowhere to keep what it reads")
    if plane != "pve":
        raise Unusable(f"the estate memory is PVE's; {plane} has no estate to learn")
    lcfg = ledger_cfg or LedgerConfig.from_env()
    box = (cfg.base_url if cfg is not None else wire.env_base_url(plane)) or ""
    _open(lcfg.audit_log_path, create=True)               # refused here, before any read, when unusable
    start = _now()
    gaps: list[str] = []
    spent: list[str] = []
    reads = 0
    table = engine.table()

    def read(concrete: str, template: str, fields: str | None = None) -> dict[str, Any] | None:
        nonlocal reads
        if reads >= LEARN_MAX_READS:
            raise _Spent(f"the read budget ({LEARN_MAX_READS}) ran out")
        reads += 1
        try:
            return engine.execute(table[(plane, "GET", template)], {}, cfg=cfg, path=concrete,
                                  ledger_cfg=ledger_cfg, fields=fields)
        except ProximoError as exc:
            gaps.append(f"GET {concrete} was refused: {exc}")
        except Exception as exc:  # noqa: BLE001 -- the vendor failed or is unreachable; receipted by execute
            gaps.append(f"GET {concrete} failed ({spine.wire_error(exc).get('status') or type(exc).__name__})")
        return None

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
        db = _open(lcfg.audit_log_path, create=False)
        if db is None:
            raise Unusable("the memory file went away during learn")
        listed = "SELECT e.kind, e.key, e.node FROM entity e JOIN sighting s ON s.plane=e.plane AND s.box=e.box AND " \
                 "s.nid=e.nid AND s.owner='resources' WHERE e.plane=? AND e.box=? AND s.seen >= ? AND e.kind IN "
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
    except _Spent as exc:
        spent.append(f"{exc}; the estate was not read whole")
    db = _open(lcfg.audit_log_path, create=True)
    assert db is not None                                  # noqa: S101
    try:
        with db:
            kept = [(t, f"read:{t}") for t in ("/cluster/resources", "/storage", "/cluster/backup", "/pools",
                                               "/access/acl")]
            kept += [(f"/nodes/{n}/network", f"read:/nodes/{{node}}/network|{json.dumps({'node': n})}") for n in nodes]
            for what, k in kept:
                v = _meta(db, plane, box, k)
                if v is None or float(v) < start:
                    gaps.append(f"memory did not keep GET {what} on this pass")
            read_at = dict(db.execute("SELECT nid, config_as_of FROM entity WHERE plane=? AND box=? AND kind IN "
                                      "('qemu','lxc')", (plane, box)))
            unread = sorted(nid for vmid, kind, _ in guests if (read_at.get(nid := f"{kind}/{vmid}") or 0) < start)
            if unread:
                gaps.append(f"{len(unread)} guest config(s) not kept on this pass: {', '.join(unread[:5])}"
                            + (" ..." if len(unread) > 5 else ""))
            gaps = spent + gaps
            done = _now()
            _set(db, plane, box, "learned_at", done)
            _set(db, plane, box, "learned", "complete" if not gaps else "incomplete")
            _set(db, plane, box, "learn_sight", "whole" if sees is True else "partial")
    finally:
        _settle(lcfg.audit_log_path)
    out: dict[str, Any] = {"source": "live", "complete": not gaps, "reads": reads, "guests": len(guests),
                           **_stamp(done, done)}
    if gaps:
        out["why"] = "; ".join(gaps[:3]) + (f" (+{len(gaps) - 3} more)" if len(gaps) > 3 else "")
    return out
