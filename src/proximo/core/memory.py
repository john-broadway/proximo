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
construction. Every answer matches the caller's words to the vendor's values EXACTLY (`_vendor_exact`:
an id, key or name byte for byte, optionally after one of the vendor's type words); no index, no
prefix, no vocabulary. Mapping a person's words onto the vendor's is the model's work, or the
person's at the shell; a miss points at the vendor's own read (John, 2026-11-07).

WHAT MAY JUDGE ABSENCE. Every fed read adds or refreshes (one exception, on PVE, below). Only a WHOLE
read of a list may retire what it no longer holds, or begin memory for what it holds (so a later first
sighting is "added"):

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
they feed entities and retire nothing, like every read that cannot own (an argument, a field subset,
a box with no name, a token whose sight the plane's shape does not judge whole). The exception: on PVE
a `/storage` read that cannot own feeds no storage, so it cannot bring back a storage
`/cluster/resources` dropped; the reason, that `/cluster/resources` leaves out a storage disabled in
the definitions, is unverified (recalled, no capture shows it). The door's answer cap does not make a
read partial here: the hook is fed the vendor's answer before the cap bounds what a model is handed.

SEEN AGAIN, A THING IS NOT GONE. Brought back by a read that cannot own, every owner that dropped it
judges it again at its next whole read: it lists it and holds it, or drops it again; once every owner
has dropped it, it is gone, dated by the read that dropped it last. So two lists that disagree for
good about one thing, an owner that no longer lists it and a read that cannot own that still does,
alternate: gone at the owner's read, present at the other's; the latest read wins. One such pair is
possible and not closed: on PMG, `/config/cluster/status` beside `/nodes`, if a cluster's status lists
a node its node list does not (not seen: the captures are single-node). A file of this schema written
before this rule (an older schema is rebuilt whole when opened) may hold a thing shown with every
owner's drop standing (brought back, nothing reopened): no owner's whole read retires it until some
read lists it again and it is judged as above, so one that has left the vendor stays shown until it
is evicted (MAX_ENTITIES), a shape's own cascade retires it (PDM's removed remote) or the file is deleted.

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
from dataclasses import dataclass, field
from functools import lru_cache
from threading import local as _thread_state
from typing import Any, Protocol
from urllib.parse import quote

from proximo.core import estate, spine, store
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

#: An entity id (`kind/key`) with the key at its bound; an edge end past it is not kept.
_NID = TEXT + 16
_ON, _OFF = frozenset({"", "1", "true", "yes", "on"}), frozenset({"0", "false", "no", "off"})
_FILE = "memory.db"
_SCHEMA_VERSION = 3                 # 3: the FTS index went with fuzzy matching (2026-11-07)
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


# ---- the per-plane seam: what memory knows of one plane's shape ----------------------------------------

@dataclass(frozen=True)
class LearnTally:
    """What a plane's `learn` hands back to the frame: the (what, meta key) pairs whose read must have
    been kept on this pass, the count the answer carries under `count_kind`, the token's sight check
    (None: it could not be read), and `after_kept`, the plane's own checks, run right after the kept
    check inside the same transaction, its gaps appended in that order."""

    kept: tuple[tuple[str, str], ...]
    count_kind: str
    count: int
    sees: bool | None
    after_kept: Callable[[sqlite3.Connection], list[str]] = field(default=lambda db: [])


class PlaneShape(Protocol):
    """One plane's shape: which reads feed memory (`feeds`), which own a whole list (`owner`), how an
    answer becomes entities and edges (`ingest`, `relate`), the vendor's type words and their display
    order, the kinds whose name is a second vendor id, the kinds `where` never matches by id
    (`no_ident_kinds`) or by name (`no_name_kinds`), whether it answers `uses` (`answers_uses`; whose
    whole reads trigger `relate` is `relating_owners`), the bare paths that read a thing live (`paths`;
    memory adds "GET " and checks each with `_published`), what an answer shows as its id (`show`),
    what `learn` reads (`learn`), the read a miss points at (`next_live`), the owner whose first
    whole read begins `changed` (`whole_owner`), and whether what a whole read may retire hangs on the
    served token's sight (`token_sight`: the engine then reads the token's public id and hands it to
    `owner`, and `changed` says `partial_sight` after a learn that could not see everything), and the
    kinds whose stored `key` IS the vendor's own one-string id, byte for byte (`global_ids`: `where`
    then also matches that key exactly; a shape that keys by its own composite declares none). `memory.py`
    keeps the file, the bounds and the answers."""

    plane: str
    feeds: frozenset[str]
    vendor_kinds: frozenset[str]
    kind_order: tuple[str, ...]
    relating_owners: frozenset[str]
    answers_uses: bool
    id_names: frozenset[str]
    no_ident_kinds: frozenset[str]
    no_name_kinds: frozenset[str]
    global_ids: frozenset[str]
    next_live: tuple[str, ...]
    whole_owner: str
    token_sight: bool

    def owner(self, template: str, bound: Mapping[str, str], args: Mapping[str, Any], fields: str | None,
              data: Any, box: str, evaluating: bool, *, db: sqlite3.Connection | None = None,
              who: str | None = None) -> str | None:
        """`db` is the file this read is going into (its `meta` holds what the plane's last learn judged
        of the token's sight); `who` the public id of the token that made this read (`arm.served_id`).
        None for either reads as nothing known."""
        ...

    def ingest(self, f: _Feed, template: str, bound: dict[str, str], args: Mapping[str, Any],
               data: Any) -> None: ...

    def relate(self, db: sqlite3.Connection, box: str, t: float) -> None: ...

    def paths(self, r: Mapping[str, Any]) -> list[str]: ...

    def show(self, r: Mapping[str, Any]) -> dict[str, Any]: ...

    def learn(self, read: Callable[..., dict[str, Any] | None], db_at: Callable[[], sqlite3.Connection],
              box: str, start: float, gaps: list[str], *,
              who: Callable[[], str | None] = lambda: None) -> LearnTally:
        """Must catch `memory._Spent` (the budget's stop, which `read` raises) and still return its tally.
        `who` reads the served token's public id now (None: unknown)."""
        ...


#: Every plane memory has a shape for; each shape's module registers itself (`memory_pve`, imported at
#: this module's end).
SHAPES: dict[str, PlaneShape] = {}
#: Back-compat names, PVE's (set by `memory_pve` when it registers).
FEEDS: frozenset[str]
VENDOR_KINDS: frozenset[str]
FANOUT: tuple[str, ...]


def shape(plane: str) -> PlaneShape | None:
    return SHAPES.get(plane)


def _next_live(plane: str) -> list[str]:
    """The live read a miss on `plane` points at; nothing for a plane with no shape."""
    s = shape(plane)
    return list(s.next_live) if s is not None else []


def feeds(plane: str) -> frozenset[str]:
    """The templates whose answer feeds memory on `plane`; nothing for a plane with no shape."""
    s = shape(plane)
    return s.feeds if s is not None else frozenset()


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
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version > _SCHEMA_VERSION:      # a newer Proximo's file: refused, never wiped (lens 2026-11-07)
            raise Unusable(f"the memory file is schema {version}, newer than this Proximo's {_SCHEMA_VERSION}: "
                           "upgrade this Proximo, or move the file")
        if version < _SCHEMA_VERSION:
            # derived data: an older shape is dropped whole and rebuilt by the next reads
            for (name,) in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE "
                                      "'sqlite_%' AND name NOT LIKE 'words_%'").fetchall():
                try:                                    # a v2 `words` (FTS5) drops its own shadow tables
                    db.execute(f'DROP TABLE IF EXISTS "{name}"')
                except sqlite3.OperationalError:
                    if name != "words":                 # FTS5's table, on a build without FTS5: see below
                        raise
            for t in ("words_data", "words_idx", "words_content", "words_docsize", "words_config"):
                db.execute(f'DROP TABLE IF EXISTS "{t}"')   # plain: they drop without FTS5, guest text too
            db.executescript(_SCHEMA)
            db.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            db.execute("PRAGMA journal_mode=WAL").fetchone()   # read: an open statement blocks VACUUM
            db.commit()
            try:                                        # once per rebuild: freed pages keep no old guest text
                db.execute("VACUUM")
                db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            except sqlite3.Error:                       # best-effort: a file that cannot vacuum still serves
                pass
        db.execute("PRAGMA synchronous=NORMAL")
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


# ---- feeding: one vendor answer at a time ------------------------------------------------------------

def _vendor_row(plane: str, template: str) -> tuple[str, ...] | None:
    """The fields the vendor publishes as present on every row of this list read (the one JSON's `row`
    column, from the api-viewer's `returns`), less any Proximo itself withholds before memory is fed (a
    remote's `token`); None when the vendor names none."""
    from proximo.core import engine  # noqa: PLC0415 -- call time: engine imports this module

    row = engine.table().get((plane, "GET", template))
    if row is None or row.row is None:
        return None
    return tuple(f for f in row.row if f not in row.secret[0])


def _rows_as_published(plane: str, template: str, data: Any) -> bool:
    """Every row of the answer carries what the vendor says every row carries: the field is there and
    not null (an empty string is a value: PBS names the root namespace `""`). The rule is the vendor's;
    nothing here says what a row should hold. A list the vendor publishes no row for is not judged."""
    need = _vendor_row(plane, template)
    if need is None or not isinstance(data, list):
        return True
    return all(isinstance(r, dict) and all(r.get(f) is not None for f in need) for r in data)


def _read_not_owned(db: sqlite3.Connection, plane: str, box: str, start: float,
                    lists: Iterable[tuple[str, str, str]]) -> list[str]:
    """A learn's gaps for the lists (`what` it shows, its `read:` stamp, its owner) read since `start`
    that did not own on that pass: such a read retired nothing, so the pass is not whole."""
    def since(k: str) -> bool:
        v = _meta(db, plane, box, k)
        return v is not None and float(v) >= start
    return [f"GET {what} was read but could not own its list: nothing it no longer lists was retired"
            for what, stamp, owner in lists if since(stamp) and not since(f"whole:{owner}")]


def feed(ledger_path: str, plane: str, box: str, template: str, bound: Mapping[str, str],
         args: Mapping[str, Any], data: Any, *, source: str, untrusted: bool, fields: str | None = None,
         evaluating: bool = False, now: float | None = None, who: str | None = None) -> None:
    """Keep what one read answered (`template` the published address it was served on, `bound` the
    values its path filled, `args` and `fields` how it was asked, `evaluating` when it was the door's
    own look for a verdict, `data` the vendor's answer after the withhold, `who` the public id of the
    token that asked, when the shape's owning hangs on it). Raises on a failure of its own; the engine
    swallows it, because a convenience must never fail the read it rides on."""
    s = shape(plane)
    if s is None or template not in s.feeds or not enabled():
        return
    t = _now() if now is None else now
    db = _open(ledger_path, create=True)
    assert db is not None                                   # noqa: S101 -- create=True never answers None
    try:
        with db:
            if isinstance(data, list) and len(data) > MAX_ROWS:
                _bump(db, plane, box, "skipped")
                return
            owner = s.owner(template, bound, args, fields, data, box, evaluating, db=db, who=who)
            if owner is not None and not _rows_as_published(plane, template, data):
                # ABSENT IS NO PROOF: a row that is not the row the vendor publishes (a field it says every
                # row carries is missing) may be the very thing a retire would call gone. Such a read adds
                # and refreshes what the shape can key and retires nothing.
                owner = None
            f = _Feed(db, plane, box, source, untrusted, t, owner)
            s.ingest(f, template, dict(bound), args, data)
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
    the edges its template carries, then `retire` what the owner no longer lists. A `put` by a read that
    cannot own reopens every owner's drop of the thing (its `seen` left as it was) when the thing was
    gone before the put or no owner holds it, so each of those owners judges it again at its next whole
    read; an owning `put` reopens only its own. What the answer holds is the plane's shape's to say
    (`PlaneShape.ingest`); this is how it is kept."""

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
        nid, was_gone = _upsert(self.db, self.plane, self.box, kind, key, t=self.t, source=self.source,
                                untrusted=self.untrusted, **kw)
        if self.owner is None:
            # back through a read that cannot own: every owner that dropped it judges it again at its next
            # whole read (`seen` kept, so that read drops it unless it lists it). Gone before this put, or
            # held by no owner (every sighting dropped: a file an older version left with the thing shown).
            self.db.execute("UPDATE sighting SET dropped=NULL WHERE plane=? AND box=? AND nid=? AND dropped IS NOT "
                            "NULL AND (? OR NOT EXISTS (SELECT 1 FROM sighting s WHERE s.plane=sighting.plane AND "
                            "s.box=sighting.box AND s.nid=sighting.nid AND s.dropped IS NULL))",
                            (self.plane, self.box, nid, was_gone))
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
        s = shape(self.plane)
        if s is not None and self.owner in s.relating_owners:
            s.relate(db, self.box, self.t)

    def edges(self, edges: Iterable[estate.Edge], via: Mapping[estate.Edge, str] | None = None) -> None:
        _insert(self.db, self.plane, self.box, edges, self.t, via)

    def mark(self, k: str) -> None:
        """Stamp a meta key with this read's time: a shape's own record that a read was kept, finer than
        the `read:<template>|<bound>` the feed writes (a groups read per namespace, say)."""
        _set(self.db, self.plane, self.box, k, self.t)


def _upsert(db: sqlite3.Connection, plane: str, box: str, kind: str, key: str, *, t: float, source: str,
            untrusted: bool, ident: Any = None, name: Any = None, node: Any = None, status: Any = None,
            tags: Any = None, detail: Mapping[str, Any] | None = None, config: bool = False) -> tuple[str, bool]:
    """One entity; its nid back, and whether it was gone before this put. A field the vendor did not give
    keeps what was known (unknown is not empty); detail merges key by key; a new status moves the old one
    to `prev_status` with the time; seen again, it is not gone; the untrusted mark is sticky, and so is
    the address that wrote it."""
    nid = f"{kind}/{key}"
    name, tags, node, status, ident = _cut(name), _cut(tags), _cut(node), _cut(status), _cut(ident)
    row = db.execute("SELECT id, status, untrusted, source, detail, gone_at FROM entity WHERE plane=? AND box=? "
                     "AND nid=?", (plane, box, nid)).fetchone()
    if row is None:
        blob = json.dumps(dict(detail), sort_keys=True, default=str) if detail else None
        cur = db.execute(
            "INSERT INTO entity (plane, box, kind, key, nid, ident, name, node, status, tags, detail, first_seen, "
            "last_seen, config_as_of, untrusted, source) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (plane, box, kind, key, nid, ident, name, node, status, tags, blob, t, t,
             t if config else None, int(untrusted), source))
        eid, gone = cur.lastrowid, None
    else:
        eid, old, was, had, blob, gone = row
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
    return nid, gone is not None


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


def _empty(now: float, plane: str) -> dict[str, Any]:
    """Nothing kept for this box: NO count, not even an empty list ("nothing observed" is not "nothing
    there", and a small model reads the number)."""
    return {"source": "memory", "verdict": "not_in_memory", "codes": ["memory_empty", "absent_is_not_proof"],
            "next": _next_live(plane), **_stamp(None, now)}


_COLS = ("plane", "kind", "key", "ident", "name", "node", "status", "detail", "last_seen", "untrusted", "source",
         "config_as_of", "prev_status", "status_changed_at", "first_seen", "added_at", "gone_at")
_SELECT = ", ".join(_COLS)


def _rows(cur: Iterable[tuple]) -> list[dict[str, Any]]:
    return [dict(zip(_COLS, r, strict=True)) for r in cur]


@lru_cache(maxsize=4096)
def _published(plane: str, p: str) -> bool:
    """Whether `GET <p>` is a concrete path the table serves as a read on `plane`: checked at runtime,
    so a path memory hands out is never one the door would refuse as unpublished."""
    from proximo.core import engine  # noqa: PLC0415 -- call time: engine imports this module

    try:
        return "{" not in p and engine.resolve(plane, "GET", p).access == "read"
    except Exception:  # noqa: BLE001 -- unpublished or malformed: not a path to hand out
        return False


def _paths(plane: str, r: Mapping[str, Any]) -> list[str]:
    """The concrete published GETs that read this thing live: the plane's shape builds them (only from
    vendor ids its own checks pass, and the feeding read's own path parameters), each checked by
    `_published`. A gone thing has none."""
    s = shape(plane)
    if s is None or r.get("gone_at") is not None:
        return []
    return [f"GET {p}" for p in s.paths(r) if _published(plane, p)]


def _mark(rows: Iterable[Mapping[str, Any]], ledger_path: str) -> bool:
    """TAINT SURVIVES STORAGE: an answer carrying rows an untrusted address wrote marks the session with
    that address, as the read did, and is refused when the marker cannot be written. True: untrusted."""
    sources = sorted({r["source"] or f"{r['plane']}:memory" for r in rows if r["untrusted"]})
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
           derive: Callable[[dict[str, Any]], None] | None = None, *, plane: str) -> dict[str, Any]:
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
                    out[k] = spine.fence(f"{plane}:memory", out[k])
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


_KIND = re.compile(r"[a-z][a-z-]{0,31}")


@lru_cache(maxsize=16)
def _vendor_order(kinds: tuple[str, ...]) -> str:
    """The order kinds are shown in, from the plane's `kind_order`: the vendor's own (for PVE, guests,
    then what holds them), never the alphabet, so seven bridges named `pve3` never push node pve3 past
    WHERE_SHOWN (lens 2026-11-07); a kind the order does not name comes last, then `kind`. The kinds are
    the shape's own constants, each held to `_KIND` before it is spelled into SQL."""
    if not all(_KIND.fullmatch(k) for k in kinds):
        raise ValueError("a shape's kind_order holds a kind that is not a plain word")
    whens = " ".join(f"WHEN '{k}' THEN {i}" for i, k in enumerate(kinds))
    return f"CASE kind {whens} ELSE {len(kinds)} END, kind"


def _vendor_exact(db: sqlite3.Connection, plane: str, box: str, words: str) -> list[dict[str, Any]]:
    """Find's lookup, EXACT and in the vendor's words (John, 2026-11-07: "we say exactly what the
    vendor gave"; fuzzy belongs to the model, not the metal). One token, the target, or two, a word of
    the plane's `vendor_kinds` then the target; anything else is no answer. The target is compared to
    the vendor's own values byte for byte, case included, and only the vendor's: the id the vendor gave
    each kind (`ident`: a vmid, a node, storage, pool or job id, a bridge's iface, a backup's volid)
    first, then the vendor's exact name, both shown (a name that spells an id ranks after it, never
    hidden: a gone or pathless id must not hide a live guest, lens 2026-11-07); a target of digits
    (`_VMID`) is an id or nothing (or the name of a kind the shape names in `id_names`, a second vendor
    id). A kind in the shape's `global_ids` is keyed by the vendor's own one-string id, so its `key`
    answers too, exactly, ranked first; a thing is shown once whichever of its values matched. Never
    memory's own labels: a composite `key` (`node/iface`, an ACL row's), a backup's short
    name (derived from the volid), a tag: the shape names the kinds whose `ident` is no vendor id
    (`no_ident_kinds`) and whose `name` is no vendor name (`no_name_kinds`). On PVE an ACL row has no
    single vendor id (its `ident` is the subject, which would hide a guest named like a group) and
    answers to nothing here: `GET /access/acl` is the vendor's. Gone rows are kept here and fall to
    `where`'s path check (lens 2026-11-07)."""
    s = shape(plane)
    if s is None:
        return []
    toks = words.split(" ")      # one plain space, strictly: a tab, a double or edge space fits no shape below
    if len(toks) == 2 and toks[0] in s.vendor_kinds:
        kinds, target = (toks[0],), toks[1]
    elif len(toks) == 1:
        kinds, target = (), toks[0]
    else:
        return []
    scope = " AND kind IN (%s)" % ",".join("?" * len(kinds)) if kinds else ""    # noqa: UP031 -- placeholders only
    q = f"SELECT {_SELECT} FROM entity WHERE plane=? AND box=?{scope}"                 # noqa: S608
    order = f" ORDER BY gone_at IS NOT NULL, {_vendor_order(s.kind_order)}, key"
    base = (plane, box, *kinds)
    no_id, no_name = tuple(sorted(s.no_ident_kinds)), tuple(sorted(s.no_name_kinds))
    # a kind keyed by the vendor's own one-string id (`global_ids`) answers to that key exactly, first
    gids = tuple(sorted(k for k in s.global_ids if not kinds or k in kinds))
    rows = _rows(db.execute(q + " AND key=?" + _in(gids) + order, (*base, target, *gids))) if gids else []
    keyed = {(r["kind"], r["key"]) for r in rows}
    rows += [r for r in _rows(db.execute(q + " AND ident=?" + _not_in(no_id) + order, (*base, target, *no_id)))
             if (r["kind"], r["key"]) not in keyed]
    names = q + " AND name=?" + _not_in(no_name)
    extra: tuple[str, ...] = ()
    if _VMID.fullmatch(target):
        if not s.id_names:
            return rows
        # a kind whose name is a second vendor id (`id_names`) answers a digits target by that name too
        extra = tuple(sorted(s.id_names))
        names += " AND kind IN (%s)" % ",".join("?" * len(extra))    # noqa: UP031 -- placeholders only
    seen = {(r["kind"], r["key"]) for r in rows}
    return rows + [r for r in _rows(db.execute(names + order, (*base, target, *no_name, *extra)))
                   if (r["kind"], r["key"]) not in seen]


def _in(kinds: tuple[str, ...]) -> str:
    """The placeholders that hold a match to `kinds`."""
    return " AND kind IN (%s)" % ",".join("?" * len(kinds))    # noqa: UP031 -- placeholders only


def _not_in(kinds: tuple[str, ...]) -> str:
    """The placeholders that keep `kinds` out of a match; nothing for none."""
    return " AND kind NOT IN (%s)" % ",".join("?" * len(kinds)) if kinds else ""    # noqa: UP031 -- placeholders only


def where(ledger_path: str, plane: str, box: str, words: str, *, now: float | None = None,
          receipt: bool = True, need_paths: bool = False) -> dict[str, Any]:
    """A guest, node, storage, pool, job, bridge or backup by the vendor's id or exact name, alone or
    after one of the vendor's type words (the shape's `vendor_kinds`): kind, node, status (or `gone` with
    `gone_at`), and the concrete published GETs
    that read it live, matched exactly in the vendor's words (`_vendor_exact`). The caller's words
    are never echoed. `need_paths` is find's seam (`resolve`): matches none of which has a path to
    read are dropped before the answer is built, so find shows, marks and receipts only what it can
    hand a path for and its first path is its first match's; the shell keeps a gone thing, and says
    it is gone."""
    now = _now() if now is None else now
    db = _usable(ledger_path)
    out: dict[str, Any]
    if db is None or _meta(db, plane, box, "last_fed") is None:
        out = {**_empty(now, plane), "found": False}
    else:
        found = _vendor_exact(db, plane, box, words)
        if need_paths:                     # find shows only what it can hand a path for (lens 2026-11-07):
            found = [r for r in found if _paths(plane, r)]   # a gone or pathless row is never rendered, so never marks
        if not found:
            fed, learned = _meta(db, plane, box, "last_fed"), _meta(db, plane, box, "learned_at")
            out = {"source": "memory", "verdict": "not_in_memory", "found": False,
                   "codes": ["absent_is_not_proof"] + ([] if learned else ["never_learned"]),
                   "learned_age_seconds": _age(float(learned), now) if learned else None,
                   "next": _next_live(plane), **_stamp(float(fed) if fed else None, now)}
        else:
            shown = found[:WHERE_SHOWN]
            s = shape(plane)
            assert s is not None                    # noqa: S101 -- `_vendor_exact` finds nothing without one

            def entry(r: Mapping[str, Any]) -> dict[str, Any]:
                e = {"kind": r["kind"], **s.show(r), "name": r["name"], "node": r["node"], "status": r["status"],
                     "paths": _paths(plane, r), "age_seconds": _age(r["last_seen"], now)}
                if r["gone_at"] is not None:
                    e.update(status="gone", last_status=r["status"], gone_at=_iso(r["gone_at"]))
                return e
            out = {"source": "memory", "verdict": "found", "found": True,
                   **_stamp(min(r["last_seen"] for r in shown), now), "matches": [entry(r) for r in shown]}
            if len(found) > len(shown):
                out["total"] = len(found)

            def paths(o: dict[str, Any]) -> None:    # outside the fence: vendor ids only, find's seam reads them
                o["paths"] = [p for m in out["matches"] for p in m["paths"]]
            out = _final(out, shown, ledger_path, ("matches",), paths, plane=plane)
    if receipt:
        _receipt(ledger_path, "where", words, out)
    return out


def resolve(words: str, *, plane: str = "pve", box: str | None = None, ledger_path: str | None = None,
            now: float | None = None) -> dict[str, Any]:
    """THE SEAM FIND CALLS (phase B): the vendor's words -> the concrete published paths memory knows
    for them, in rank order (`paths`), with `where`'s answer, matched EXACTLY (`_vendor_exact`). `box`
    and `ledger_path` default to the env's. A plane with no shape has no estate here: not found,
    nothing opened. A `core.recall` row (verb `find`) is written only for an answer with a path:
    find hands the model nothing from memory otherwise, so no recall happened."""
    from proximo.core import wire  # noqa: PLC0415
    from proximo.core.ledger import LedgerConfig  # noqa: PLC0415

    if shape(plane) is None:
        return {"source": "memory", "verdict": "not_in_memory", "found": False, "paths": []}
    box = box if box is not None else (wire.env_base_url(plane) or "")
    ledger_path = ledger_path or LedgerConfig.from_env().audit_log_path
    out = where(ledger_path, plane, box, words, now=now, receipt=False, need_paths=True)
    out.setdefault("paths", [])
    if out.get("found") and out["paths"]:
        _receipt(ledger_path, "find", words, out)
    return out


def uses(ledger_path: str, plane: str, box: str, thing: str, *, now: float | None = None,
         receipt: bool = True) -> dict[str, Any]:
    """The guests (not gone) with a disk on a storage or a NIC on a bridge, by slot. Complete only when
    a whole resources read is in memory, every guest present has its config kept, nothing (an edge, or
    an entity with its edges and its place in the counts) was evicted since those configs, and the
    last learn saw every guest; otherwise `why` says which, in codes. A plane whose shape does not
    answer `uses` (`answers_uses`, or has no shape) is refused before any answer or receipt: an empty
    list there would read as "nothing uses it"."""
    s = shape(plane)
    if s is None or not s.answers_uses:
        raise Unusable(f"the estate memory relates nothing on {plane}: uses is PVE's (disks and NICs)")
    now = _now() if now is None else now
    db = _usable(ledger_path)
    if db is None or _meta(db, plane, box, "last_fed") is None:
        out = _empty(now, plane)
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
            rows.append({"plane": plane, "untrusted": u, "source": sc})
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
        nxt = (_next_live(plane) if "no_whole_read" in why else []) + [
            f"GET /nodes/{r['node']}/{r['kind']}/{r['key']}/pending" for r in unread
            if r["node"] and _ID.fullmatch(r["node"])
            and _published(plane, f"/nodes/{r['node']}/{r['kind']}/{r['key']}/pending")][:5]
        if oldest is None:
            fed = _meta(db, plane, box, "last_fed")
            oldest = float(fed) if fed else None
        out = {"source": "memory", "verdict": "incomplete" if why else "complete", "complete": not why,
               **({"why": why} if why else {}), **_stamp(oldest, now), "guests": shown, "total": total,
               "unread": [f"{r['kind']}/{r['key']}" for r in unread], **({"next": nxt} if nxt else {})}
        if (missing or 0) > len(unread):
            out["unread_total"] = missing
        out = _final(out, rows, ledger_path, ("guests", "unread"), plane=plane)
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
        out = _empty(now, plane)
    else:
        cutoff = now - seconds
        q = f"SELECT {_SELECT} FROM entity WHERE plane=? AND box=? AND "      # noqa: S608
        added = _rows(db.execute(q + "added_at > ? ORDER BY added_at", (plane, box, cutoff)))
        moved = _rows(db.execute(q + "status_changed_at > ? ORDER BY status_changed_at", (plane, box, cutoff)))
        gone = _rows(db.execute(q + "gone_at > ? ORDER BY gone_at", (plane, box, cutoff)))

        s = shape(plane)

        def brief(r: Mapping[str, Any], **extra: Any) -> dict[str, Any]:
            # the shape's own id (the vendor's, and for a group its store and namespace), never memory's
            # composite key; `args` is a read's params, not an id, and stays with `where`
            ids = {k: v for k, v in s.show(r).items() if k != "args"} if s is not None else {"id": r["key"]}
            return {"kind": r["kind"], **ids, "name": r["name"], "node": r["node"], **extra}
        fed = _meta(db, plane, box, "last_fed")
        began = _meta(db, plane, box, f"first_whole:{s.whole_owner}") if s is not None else None
        out = {"source": "memory", "window_s": seconds, "began": _iso(float(began)) if began else None,
               **_stamp(float(fed) if fed else None, now),
               "added": [brief(r, status=r["status"]) for r in added[:SHOWN]],
               "gone": [brief(r, gone_at=_iso(r["gone_at"]), last_seen=_iso(r["last_seen"])) for r in gone[:SHOWN]],
               "changed": [brief(r, **{"from": r["prev_status"], "to": r["status"], "at": _iso(r["status_changed_at"])})
                           for r in moved[:SHOWN]],
               "counts": {"added": len(added), "gone": len(gone), "changed": len(moved)},
               "codes": ["gone_by_whole_read", "added_after_first_whole_read"] + ([] if began else ["no_whole_read"])
               + (["partial_sight"] if s is not None and s.token_sight
                  and _meta(db, plane, box, "learn_sight") == "partial" else [])}
        out = _final(out, added[:SHOWN] + gone[:SHOWN] + moved[:SHOWN], ledger_path, ("added", "gone", "changed"),
                     plane=plane)
    if receipt:
        _receipt(ledger_path, "changed", window, out)
    return out


#: The doctor flags `station` writes that are advice (`doctor._ADVISORY`): they move no exit code.
ADVISORY: tuple[str, ...] = ()


def station(lcfg: Any, flags: list[str]) -> dict[str, Any]:
    """Doctor's memory section: `status`, and its flags. A
    word PROXIMO_MEMORY does not read (off, and the operator meant something), or a file memory must
    refuse or cannot read, is a flag that makes the report incomplete. Never a path."""
    from proximo.core.secretfile import safe_text  # noqa: PLC0415

    section = status(lcfg.audit_log_path)
    if section["setting"] == "unrecognised":
        flags.append("PROXIMO_MEMORY is set to a word memory does not read, so memory is off: unset it or 1 for on, "
                     "0 for off")
    if section.get("file") in ("refused", "unreadable"):
        flags.append(f"the estate memory file is {section['file']}: {safe_text(section.get('why', ''), paths=True)}")
    return section


def status(ledger_path: str) -> dict[str, Any]:
    """For doctor: state and counts, never a path. Never raises. `learned` is per plane (`{"pve":
    "complete", "pbs": "incomplete"}`: a plane is complete only when every box of it learned complete,
    and a plane never learned is not listed), or "never" when no plane has learned."""
    out: dict[str, Any] = {"on": enabled(), "setting": setting()}
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
        learned: dict[str, set[str]] = {}
        for plane, v in db.execute("SELECT plane, v FROM meta WHERE k='learned'"):
            learned.setdefault(plane, set()).add(v)
    except sqlite3.Error as exc:
        return {**out, "file": "unreadable", "why": type(exc).__name__}
    by_plane = {p: "complete" if vs == {"complete"} else "incomplete" for p, vs in sorted(learned.items())}
    return {**out, "file": "present", "entities": n, "boxes": boxes, "evicted": totals.get("evicted") or 0,
            "evicted_edges": totals.get("evicted_edges") or 0, "skipped": totals.get("skipped") or 0,
            "skipped_ids": totals.get("skipped_ids") or 0,
            "learned": by_plane or "never"}


# ---- learn: the one deliberate pass ------------------------------------------------------------------

class _Spent(Exception):
    pass


def learn(plane: str = "pve", *, cfg: Any = None, ledger_cfg: Any = None) -> dict[str, Any]:
    """Read the estate once, on the operator's word: what the plane's shape reads (`PlaneShape.learn`;
    PVE's: cluster resources whole, the token's permission map, storage, backup jobs, pools, ACLs,
    each node's network and each guest it listed). Every read is `engine.execute` (receipted,
    withheld, taint-marked, bounded) and the engine's read hook keeps it; this function keeps nothing
    itself and only tallies. Under LEARN_MAX_READS; anything that stops a whole picture (a read
    refused, failed, over budget, not kept on this pass, a token that cannot see everything) is
    `complete: false` with the reason."""
    from proximo.core import arm, engine, wire  # noqa: PLC0415 -- call time: engine imports this module
    from proximo.core.ledger import LedgerConfig  # noqa: PLC0415

    if not enabled():
        raise Unusable("the estate memory is off on this box (PROXIMO_MEMORY): learn has nowhere to keep what it reads")
    s = shape(plane)
    if s is None:
        raise Unusable(f"the estate memory has no shape for {plane}")
    lcfg = ledger_cfg or LedgerConfig.from_env()
    box = (cfg.base_url if cfg is not None else wire.env_base_url(plane)) or ""
    view = cfg if cfg is not None else wire.env_arm_view(plane)

    def who() -> str | None:
        """The served token's public id now; the shape reads it around the reads it judges sight from."""
        try:
            return arm.served_id(view)
        except Exception:  # noqa: BLE001 -- an id that cannot be read is unknown: blind, never a failure
            return None
    first = _open(lcfg.audit_log_path, create=True)       # refused here, before any read, when unusable
    assert first is not None                               # noqa: S101
    try:
        with first:                     # partial until this pass ends whole: a learn that dies leaves no stale whole
            _set(first, plane, box, "learn_sight", "partial")
    finally:
        _settle(lcfg.audit_log_path)
    start = _now()
    gaps: list[str] = []
    spent: list[str] = []
    reads = 0
    table = engine.table()

    def read(concrete: str, template: str, fields: str | None = None,
             args: Mapping[str, Any] | None = None) -> dict[str, Any] | None:
        nonlocal reads
        if reads >= LEARN_MAX_READS:
            # the frame names the stop; the shape catches `_Spent` so what it gathered still tallies
            spent.append(f"the read budget ({LEARN_MAX_READS}) ran out; the estate was not read whole")
            raise _Spent(spent[-1])
        reads += 1
        try:
            return engine.execute(table[(plane, "GET", template)], dict(args or {}), cfg=cfg, path=concrete,
                                  ledger_cfg=ledger_cfg, fields=fields)
        except ProximoError as exc:
            gaps.append(f"GET {concrete} was refused: {exc}")
        except Exception as exc:  # noqa: BLE001 -- the vendor failed or is unreachable; receipted by execute
            gaps.append(f"GET {concrete} failed ({spine.wire_error(exc).get('status') or type(exc).__name__})")
        return None

    def db_at() -> sqlite3.Connection:
        db = _open(lcfg.audit_log_path, create=False)
        if db is None:
            raise Unusable("the memory file went away during learn")
        return db

    tally = s.learn(read, db_at, box, start, gaps, who=who)
    db = _open(lcfg.audit_log_path, create=True)
    assert db is not None                                  # noqa: S101
    try:
        with db:
            for what, k in tally.kept:
                v = _meta(db, plane, box, k)
                if v is None or float(v) < start:
                    gaps.append(f"memory did not keep GET {what} on this pass")
            gaps.extend(tally.after_kept(db))
            gaps = spent[:1] + gaps
            done = _now()
            _set(db, plane, box, "learned_at", done)
            _set(db, plane, box, "learned", "complete" if not gaps else "incomplete")
            _set(db, plane, box, "learn_sight", "whole" if tally.sees is True else "partial")
    finally:
        _settle(lcfg.audit_log_path)
    out: dict[str, Any] = {"source": "live", "complete": not gaps, "reads": reads, tally.count_kind: tally.count,
                           **_stamp(done, done)}
    if gaps:
        out["why"] = "; ".join(gaps[:3]) + (f" (+{len(gaps) - 3} more)" if len(gaps) > 3 else "")
    return out


# The shapes register themselves when imported (each imports this module, so either order works).
from proximo.core import memory_pbs, memory_pdm, memory_pmg, memory_pve  # noqa: E402, F401
