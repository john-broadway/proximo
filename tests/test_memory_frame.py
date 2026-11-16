"""The frame's retire (`memory._Feed.put` / `retire` / `_upsert`), across every plane's shape.

A thing an owner's whole read retired can come back through a read that cannot own (an argument, a
door's own look, another token's read, a read without whole sight): `_upsert` clears `gone_at`
("seen again, it is not gone"). When it leaves the vendor again, the owner's next whole read must
retire it again, dated by that read: "absent is not proof" still holds, because nothing is retired
except by an owner's whole read. These tests hold that on each plane (each through a route that
cannot own), on a small fake shape with two owners, and through the real shapes on PMG's named pair
and PVE's two-owner storage. Every value here is invented; no box is reached.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from proximo.core import memory


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.delenv("PROXIMO_MEMORY_PATH", raising=False)
    return str(tmp_path / "audit.log")


def _gone_at(ledger: str, plane: str, box: str, nid: str) -> float | None:
    db = sqlite3.connect(memory.path(ledger))
    try:
        row = db.execute("SELECT gone_at FROM entity WHERE plane=? AND box=? AND nid=?", (plane, box, nid)).fetchone()
    finally:
        db.close()
    assert row is not None, f"{nid} is not in memory at all"
    return row[0]


def _sight(ledger: str, plane: str, box: str, keys: tuple[str, ...], who: str) -> None:
    """Write a token's whole sight, as a learn that read its permission map would have."""
    db = memory._open(ledger, create=True)
    assert db is not None
    with db:
        for k in keys:
            memory._set(db, plane, box, k, f"whole:{who}")
    memory._settle(ledger)


# ---- the four planes: the owner retires it, a read that cannot own brings it back, it leaves again ----

def _q(vmid: int) -> dict[str, Any]:
    return {"id": f"qemu/{vmid}", "type": "qemu", "vmid": vmid, "name": f"g{vmid}", "node": "n1", "status": "running"}


_PVE_NODE = {"id": "node/n1", "type": "node", "node": "n1", "status": "online"}
_PDM_REMOTE = "r1"


def _pdm_guest(vmid: int) -> dict[str, Any]:
    return {"id": f"remote/{_PDM_REMOTE}/guest/{vmid}", "type": "qemu", "vmid": vmid, "name": f"g{vmid}",
            "node": "n1", "status": "running"}


_PDM_NODE = {"id": f"remote/{_PDM_REMOTE}/node/n1", "type": "node", "node": "n1", "status": "online"}


def _store(name):
    """A PBS datastore row as the vendor publishes it: `store`, `backend-type` and `mount-status` on every row."""
    return {"store": name, "backend-type": "filesystem", "mount-status": "nonremovable"}


#: plane -> (box, template, bound, whole list, the list without the thing, the read that cannot own, its nid,
#: the word `where` finds it by, the owner's token and the sight keys it needs (None: owning is the read's own),
#: the path `where` hands out while it is present)
_PLANES: dict[str, tuple] = {
    # an argument read of the owner's own list (the vendor's `type` filter)
    "pve": ("https://pve.invalid:8006", "/cluster/resources", {}, [_PVE_NODE, _q(100), _q(105)],
            [_PVE_NODE, _q(100)], {"args": {"type": "vm"}}, "qemu/105", "105", None, (),
            "GET /nodes/n1/qemu/105/status/current"),
    # a read by a token whose sight memory does not know (no id): adds and refreshes only
    "pbs": ("https://pbs.invalid:8007", "/admin/datastore", {}, [_store("s1"), _store("s2")],
            [_store("s1")], {"who": None}, "datastore/s2", "s2", "invented@pbs!wide", ("datastore_sight",),
            "GET /admin/datastore/s2/status"),
    # the door's own look for a verdict (`evaluating`)
    "pmg": ("https://pmg.invalid:8006", "/config/domains", {},
            [{"domain": "a.example", "comment": ""}, {"domain": "b.example", "comment": ""}],
            [{"domain": "a.example", "comment": ""}], {"evaluating": True}, "domain/b.example", "b.example", None, (),
            "GET /config/domains/b.example"),
    # an argument read of a remote's own list (the vendor's `kind` filter); a plain same-token read re-owns
    "pdm": ("https://pdm.invalid:8443", "/pve/remotes/{remote}/resources", {"remote": _PDM_REMOTE},
            [_PDM_NODE, _pdm_guest(100), _pdm_guest(105)], [_PDM_NODE, _pdm_guest(100)], {"args": {"kind": "vm"}},
            f"qemu/remote/{_PDM_REMOTE}/guest/105", "105", "invented@pdm!wide", ("resource_sight", "view_sight"),
            f"GET /pve/remotes/{_PDM_REMOTE}/qemu/105/status"),
}


@pytest.mark.parametrize("plane", list(_PLANES))
def test_a_thing_brought_back_by_a_read_that_cannot_own_retires_again(ledger, plane):
    box, template, bound, whole, without, cannot_own, nid, word, who, sight, path = _PLANES[plane]
    if plane == "pdm":       # the remote the resources list belongs to, as a learn's remotes read keeps it
        memory.feed(ledger, plane, box, "/remotes/remote", {}, {}, [{"id": _PDM_REMOTE, "type": "pve", "nodes": []}],
                    source=f"{plane}:t", untrusted=False, now=1, who=who)
    if sight:
        _sight(ledger, plane, box, sight, who)

    def read(t: float, data: list[Any], **kw: Any) -> None:
        memory.feed(ledger, plane, box, template, bound, kw.pop("args", {}), data, source=f"{plane}:t",
                    untrusted=False, now=t, who=kw.pop("who", who), **kw)

    read(10, whole)
    read(20, without)
    assert _gone_at(ledger, plane, box, nid) == 20                       # the owner retired it
    read(30, whole, **cannot_own)                                         # back at the vendor; a read that cannot own
    assert _gone_at(ledger, plane, box, nid) is None
    [m] = memory.where(ledger, plane, box, word, now=31, receipt=False)["matches"]
    assert m["status"] != "gone" and path in m["paths"]
    read(40, without)                                     # gone at the vendor again; the owner reads whole
    assert _gone_at(ledger, plane, box, nid) == 40
    [m] = memory.where(ledger, plane, box, word, now=41, receipt=False)["matches"]
    assert (m["status"], m["paths"]) == ("gone", [])
    out = memory.changed(ledger, plane, box, "1m", now=50, receipt=False)
    assert out["counts"]["gone"] == 1 and [g["gone_at"] for g in out["gone"]] == [memory._iso(40)]


# ---- a fake shape with two owners: list `/a` is owner A's, list `/b` owner B's ------------------------------

_BOX = "box"


class _TwoOwners:
    """Two lists that each own the same kind whole; an argument or a door's look never owns."""

    plane = "zz"
    feeds = frozenset({"/a", "/b"})
    vendor_kinds = frozenset({"thing"})
    kind_order = ("thing",)
    relating_owners: frozenset[str] = frozenset()
    answers_uses = False
    id_names: frozenset[str] = frozenset()
    no_ident_kinds: frozenset[str] = frozenset()
    no_name_kinds: frozenset[str] = frozenset()
    global_ids: frozenset[str] = frozenset()
    next_live = ("GET /a",)
    whole_owner = "A"
    token_sight = False

    def owner(self, template: str, bound: Mapping[str, str], args: Mapping[str, Any], fields: str | None,
              data: Any, box: str, evaluating: bool, *, db: sqlite3.Connection | None = None,
              who: str | None = None) -> str | None:
        if evaluating or args or fields is not None or not isinstance(data, list):
            return None
        return {"/a": "A", "/b": "B"}[template]

    def ingest(self, f: memory._Feed, template: str, bound: dict[str, str], args: Mapping[str, Any],
               data: Any) -> None:
        for r in data:
            f.put("thing", r["id"], ident=r["id"], name=r["id"], status=r.get("status"))

    def relate(self, db: sqlite3.Connection, box: str, t: float) -> None:
        return None

    def paths(self, r: Mapping[str, Any]) -> list[str]:
        return []

    def show(self, r: Mapping[str, Any]) -> dict[str, Any]:
        return {"id": r["key"]}

    def learn(self, read: Callable[..., dict[str, Any] | None], db_at: Callable[[], sqlite3.Connection],
              box: str, start: float, gaps: list[str], *,
              who: Callable[[], str | None] = lambda: None) -> memory.LearnTally:
        raise NotImplementedError


@pytest.fixture
def zz(ledger, monkeypatch):
    monkeypatch.setitem(memory.SHAPES, "zz", _TwoOwners())

    def read(template: str, t: float, *ids: str, status: str | None = None, **kw: Any) -> None:
        rows = [{"id": i, **({"status": status} if status else {})} for i in ids]
        memory.feed(ledger, "zz", _BOX, template, {}, kw.pop("args", {}), rows, source="zz:t", untrusted=False,
                    now=t, **kw)

    def gone_at(key: str = "x") -> float | None:
        return _gone_at(ledger, "zz", _BOX, f"thing/{key}")

    def changed(now: float = 100) -> dict[str, Any]:
        return memory.changed(ledger, "zz", _BOX, "1h", now=now, receipt=False)
    return read, gone_at, changed


def _gone_listed(out: Mapping[str, Any], key: str = "x") -> list[str | None]:
    return [g["gone_at"] for g in out["gone"] if g["id"] == key]


def _dropped_by_both_then_back(read: Callable[..., None]) -> None:
    """Owners A and B list x at 10; A drops it at 20, B at 25 (B's drop makes it gone); a read that
    cannot own brings it back at 30."""
    read("/a", 10, "x", "y")
    read("/b", 10, "x", "y")
    read("/a", 20, "y")
    read("/b", 25, "y")
    read("/a", 30, "x", "y", args={"filter": "all"})


@pytest.mark.parametrize("first, last", [("/a", "/b"), ("/b", "/a")], ids=["first-dropper-first", "last-dropper-first"])
def test_two_owners_must_both_drop_it_again(zz, first, last):                                 # RF1
    """Both orders after the revival: whichever owner reads whole first, the thing stays shown (the
    other still holds it); the second owner's whole read makes it gone, dated by that read. The order
    `last-dropper-first` is the one a cure that opened only the sighting whose drop made it gone fails."""
    read, gone_at, _ = zz
    read("/a", 10, "x", "y")
    read("/b", 10, "x", "y")
    read("/a", 20, "y")
    assert gone_at() is None                                           # B still holds it
    read("/b", 25, "y")
    assert gone_at() == 25                                             # every owner dropped it
    read("/a", 30, "x", "y", args={"filter": "all"})                   # back, through a read that cannot own
    assert gone_at() is None
    read(first, 40, "y")
    assert gone_at() is None                                           # one owner dropped it again; the other holds it
    read(last, 50, "y")
    assert gone_at() == 50                                             # the other dropped it again: gone, dated by it


def test_a_revival_opens_every_dropped_sighting_and_leaves_seen_as_it_was(zz, ledger):
    """After the revival every owner's sighting is open and its `seen` is what it was before (10): a
    revival is no owner's listing, and PVE's learn reads `seen` to choose what its whole read listed."""
    read, _, _ = zz
    _dropped_by_both_then_back(read)
    db = sqlite3.connect(memory.path(ledger))
    try:
        rows = db.execute("SELECT owner, seen, dropped FROM sighting WHERE plane='zz' AND nid='thing/x' "
                          "ORDER BY owner").fetchall()
    finally:
        db.close()
    assert rows == [("A", 10, None), ("B", 10, None)]


def test_an_owner_that_lists_it_again_keeps_it_and_does_not_date_it_added_twice(zz, ledger):  # RF2
    read, gone_at, changed = zz
    read("/a", 1, "y")
    read("/b", 1, "y")
    read("/a", 10, "x", "y")                                           # x is new to an owner that read whole before
    read("/b", 10, "x", "y")
    read("/a", 20, "y")
    read("/b", 20, "y")
    assert gone_at() == 20
    read("/a", 30, "x", "y", evaluating=True)                          # back, through a read that cannot own
    read("/a", 40, "x", "y")                                           # A lists it again
    assert gone_at() is None
    read("/b", 50, "y")                                                # B does not; A holds it
    assert gone_at() is None
    out = changed()
    assert [a["id"] for a in out["added"]] == ["x"] and out["counts"]["added"] == 1
    db = sqlite3.connect(memory.path(ledger))
    try:
        assert db.execute("SELECT added_at FROM entity WHERE nid='thing/x'").fetchone() == (10,)
    finally:
        db.close()


def test_a_put_on_a_thing_that_is_present_opens_nothing(zz):                                  # RF3
    read, gone_at, _ = zz
    read("/a", 10, "x", "y")
    read("/b", 10, "x", "y")
    read("/a", 20, "y")                                                # A dropped it; B holds it: present
    assert gone_at() is None
    read("/a", 30, "x", "y", args={"filter": "all"})                   # a read that cannot own, on a present thing
    read("/b", 40, "y")                                                # B drops it: A's old drop still counts
    assert gone_at() == 40


def test_the_second_retire_is_dated_by_its_own_read(zz):                                      # RF4
    read, gone_at, changed = zz
    read("/a", 10, "x", "y", status="running")
    read("/a", 20, "y", status="running")
    assert gone_at() == 20
    read("/a", 30, "x", "y", status="stopped", evaluating=True)       # back, its status moved at the revival
    assert gone_at() is None
    read("/a", 40, "y", status="stopped")
    assert gone_at() == 40
    read("/a", 45, "y", status="stopped")                              # a later whole read does not re-date it
    assert gone_at() == 40
    out = changed()
    assert _gone_listed(out) == [memory._iso(40)] and out["counts"]["gone"] == 1
    assert [(c["from"], c["to"], c["at"]) for c in out["changed"] if c["id"] == "x"] == [
        ("running", "stopped", memory._iso(30))]


def test_an_owning_put_opens_no_other_owners_drop(zz, ledger):
    """Only a read that cannot own opens a drop: an owner listing a gone thing reopens its own sighting
    and no other. A and B both dropped x (gone); A lists it again, then drops it: B's drop still counts,
    so it is gone, dated by A's read."""
    read, gone_at, _ = zz
    read("/a", 10, "x", "y")
    read("/b", 10, "x", "y")
    read("/a", 20, "y")
    read("/b", 25, "y")
    assert gone_at() == 25
    read("/a", 30, "x", "y")                                           # A lists it again (an owning put)
    assert gone_at() is None and _sightings(ledger) == [("A", 30, None), ("B", 10, 25)]
    read("/a", 40, "y")                                                # A drops it: no owner holds it
    assert gone_at() == 40


def _sightings(ledger: str, key: str = "x") -> list[tuple[str, float, float | None]]:
    db = sqlite3.connect(memory.path(ledger))
    try:
        return db.execute("SELECT owner, seen, dropped FROM sighting WHERE plane='zz' AND nid=? ORDER BY owner",
                          (f"thing/{key}",)).fetchall()
    finally:
        db.close()


def _by_hand(ledger: str, sql: str) -> None:
    db = sqlite3.connect(memory.path(ledger))
    try:
        with db:
            db.execute(sql)
    finally:
        db.close()


def test_a_gone_thing_a_shape_retired_itself_opens_every_drop_when_it_comes_back(zz, ledger):
    """A shape's own cascade (PDM retires a removed remote's things with it) makes a thing gone while an
    owner's sighting of it is still open. Brought back by a read that cannot own, it was gone, so every
    dropped sighting opens too: each owner that dropped it judges it again."""
    read, gone_at, _ = zz
    read("/a", 10, "x", "y")
    read("/b", 10, "x", "y")
    read("/b", 20, "y")                                                # B dropped it; A holds it
    _by_hand(ledger, "UPDATE entity SET gone_at=25 WHERE plane='zz' AND nid='thing/x'")   # the cascade
    read("/a", 30, "x", "y", evaluating=True)                          # back, through a read that cannot own
    assert gone_at() is None
    assert _sightings(ledger) == [("A", 10, None), ("B", 10, None)]
    read("/a", 40, "y")
    assert gone_at() is None                                           # B, reopened, still holds it
    read("/b", 50, "y")
    assert gone_at() == 50


def _stuck(read: Callable[..., None], ledger: str) -> None:
    """The state an older version left: A retired x at 20; a read that cannot own brought it back at 30
    (`gone_at` cleared, `last_seen` 30) and opened nothing, so x is shown and A's one sighting stays
    dropped."""
    read("/a", 10, "x", "y")
    read("/a", 20, "y")
    _by_hand(ledger, "UPDATE entity SET gone_at=NULL, last_seen=30 WHERE plane='zz' AND nid='thing/x'")


def test_a_thing_stuck_before_the_change(zz, ledger):
    """(a) The owner's whole read without it changes nothing: its sighting is already dropped, so this
    read drops nothing, and a thing is retired only by a read that drops it. It stays shown. (b) Any read
    that lists it again cures it: one that cannot own finds no owner holding it and opens the drop, and
    the owner's next whole read without it retires it, dated by that read."""
    read, gone_at, changed = zz
    _stuck(read, ledger)
    assert _sightings(ledger) == [("A", 10, 20)]
    read("/a", 40, "y")                                                # (a)
    assert gone_at() is None and _sightings(ledger) == [("A", 10, 20)]
    read("/a", 50, "x", "y", args={"filter": "all"})                   # (b) a read that cannot own lists it
    assert gone_at() is None and _sightings(ledger) == [("A", 10, None)]
    read("/a", 60, "y")
    assert gone_at() == 60
    assert _gone_listed(changed()) == [memory._iso(60)]


def test_a_thing_stuck_before_the_change_is_cured_by_its_owner_listing_it(zz, ledger):
    """The other cure of (b): the owner lists it again, then leaves it out: gone, dated by that read."""
    read, gone_at, _ = zz
    _stuck(read, ledger)
    read("/a", 40, "x", "y")
    read("/a", 50, "y")
    assert gone_at() == 50


# ---- the opening is scoped to its own plane and box -------------------------------------------------------------

class _TwoOwnersElsewhere(_TwoOwners):
    """The same two lists on a second plane."""

    plane = "yy"


#: where -> (the plane and box the revival happens on, the other plane and box that holds the same nid)
_SCOPES = {
    "box": (("zz", "box-p"), ("zz", "box-q")),
    "plane": (("zz", _BOX), ("yy", _BOX)),
}


@pytest.fixture
def two_places(ledger, monkeypatch):
    monkeypatch.setitem(memory.SHAPES, "zz", _TwoOwners())
    monkeypatch.setitem(memory.SHAPES, "yy", _TwoOwnersElsewhere())

    def read(at: tuple[str, str], template: str, t: float, *ids: str, **kw: Any) -> None:
        plane, box = at
        memory.feed(ledger, plane, box, template, {}, kw.pop("args", {}), [{"id": i} for i in ids],
                    source=f"{plane}:t", untrusted=False, now=t, **kw)

    def rows(at: tuple[str, str]) -> list[tuple[str, float, float | None]]:
        db = sqlite3.connect(memory.path(ledger))
        try:
            return db.execute("SELECT owner, seen, dropped FROM sighting WHERE plane=? AND box=? AND nid='thing/x'",
                              at).fetchall()
        finally:
            db.close()

    def gone_at(at: tuple[str, str]) -> float | None:
        return _gone_at(ledger, *at, "thing/x")
    return read, rows, gone_at


@pytest.mark.parametrize("where", list(_SCOPES))
def test_a_revival_opens_no_drop_of_the_same_thing_on_another_plane_or_box(two_places, where):
    """The same nid is gone on two boxes (or two planes). Brought back on one of them by a read that cannot
    own, only that one's drop opens: the other's sighting stays dropped and its thing stays gone."""
    read, rows, gone_at = two_places
    here, there = _SCOPES[where]
    for at in (here, there):
        read(at, "/a", 10, "x", "y")
        read(at, "/a", 20, "y")
        assert gone_at(at) == 20
    read(here, "/a", 30, "x", "y", args={"filter": "all"})            # back here, through a read that cannot own
    assert rows(here) == [("A", 10, None)] and gone_at(here) is None
    assert rows(there) == [("A", 10, 20)] and gone_at(there) == 20


@pytest.mark.parametrize("where", list(_SCOPES))
def test_an_owner_holding_the_same_thing_on_another_plane_or_box_does_not_hold_it_here(two_places, ledger, where):
    """Here the thing is stuck as an older version left it (shown, its one sighting dropped); there an owner
    holds the same nid open. A read that cannot own lists it here: no owner holds it HERE, so its drop
    opens, and the owner's next whole read here retires it."""
    read, rows, gone_at = two_places
    here, there = _SCOPES[where]
    read(there, "/a", 10, "x", "y")                                     # held open there
    read(here, "/a", 10, "x", "y")
    read(here, "/a", 20, "y")
    db = sqlite3.connect(memory.path(ledger))                           # the stuck state an older version left
    try:
        with db:
            db.execute("UPDATE entity SET gone_at=NULL, last_seen=30 WHERE plane=? AND box=? AND nid='thing/x'", here)
    finally:
        db.close()
    read(here, "/a", 40, "x", "y", args={"filter": "all"})              # a read that cannot own lists it here
    assert rows(here) == [("A", 10, None)]
    read(here, "/a", 50, "y")
    assert gone_at(here) == 50
    assert rows(there) == [("A", 10, None)] and gone_at(there) is None


# ---- through the real shapes: the PMG pair the frame names, and a real two-owner kind ------------------------

_PMG = "https://pmg.invalid:8006"


def test_the_pmg_pair_alternates_and_the_latest_read_wins(ledger):
    """The pair the frame's docstring names: on PMG `/nodes` owns the nodes, `/config/cluster/status` lists
    them and cannot own. IF a cluster's status lists a node its node list does not (not seen: the captures
    are single-node), the two disagree for good and the docstring says they alternate, the latest read
    winning: gone at the node list's read, present again at the status read's. Pinned, so that cannot drift
    unsaid."""
    def nodes(t: float, *names: str) -> None:
        memory.feed(ledger, "pmg", _PMG, "/nodes", {}, {}, [{"node": n} for n in names], source="pmg:t",
                    untrusted=False, now=t)

    def status(t: float, *names: str) -> None:
        memory.feed(ledger, "pmg", _PMG, "/config/cluster/status", {}, {}, [{"name": n} for n in names],
                    source="pmg:t", untrusted=False, now=t)

    nodes(10, "m1", "m2")
    nodes(20, "m1")
    assert _gone_at(ledger, "pmg", _PMG, "node/m2") == 20                # the owner left it out
    for t in (30, 50):
        status(t, "m1", "m2")                                            # the status still lists it: present
        assert _gone_at(ledger, "pmg", _PMG, "node/m2") is None
        [m] = memory.where(ledger, "pmg", _PMG, "m2", now=t + 1, receipt=False)["matches"]
        assert m["status"] != "gone"
        nodes(t + 10, "m1")                                              # the node list still does not: gone
        assert _gone_at(ledger, "pmg", _PMG, "node/m2") == t + 10        # dated by this read, not the first
        [m] = memory.where(ledger, "pmg", _PMG, "m2", now=t + 11, receipt=False)["matches"]
        assert (m["status"], m["paths"]) == ("gone", [])


_PVE = "https://pve.invalid:8006"


def test_a_pve_storage_both_owners_dropped_is_gone_again_only_when_both_read_whole_without_it(ledger):
    """A real two-owner kind: on PVE a storage is owned by `/cluster/resources` and by a whole `/storage`
    read. Both drop x; an argument read of the resources list (which cannot own) brings it back; one
    owner's whole read without it does not retire it, the other's does, dated by that read."""
    def resources(t: float, *ids: str, **kw: Any) -> None:
        rows = [_PVE_NODE, *({"id": f"storage/n1/{s}", "type": "storage", "storage": s, "node": "n1",
                               "status": "available"} for s in ids)]
        memory.feed(ledger, "pve", _PVE, "/cluster/resources", {}, kw.pop("args", {}), rows, source="pve:t",
                    untrusted=False, now=t)

    def storage(t: float, *ids: str) -> None:
        memory.feed(ledger, "pve", _PVE, "/storage", {}, {}, [{"storage": s, "type": "dir"} for s in ids],
                    source="pve:t", untrusted=False, now=t)

    resources(10, "s1", "x")
    storage(11, "s1", "x")
    resources(20, "s1")
    assert _gone_at(ledger, "pve", _PVE, "storage/x") is None            # `/storage` still holds it
    storage(21, "s1")
    assert _gone_at(ledger, "pve", _PVE, "storage/x") == 21              # both dropped it
    resources(30, "s1", "x", args={"type": "storage"})                   # back, through a read that cannot own
    assert _gone_at(ledger, "pve", _PVE, "storage/x") is None
    storage(40, "s1")
    assert _gone_at(ledger, "pve", _PVE, "storage/x") is None            # one owner alone does not retire it
    resources(50, "s1")
    assert _gone_at(ledger, "pve", _PVE, "storage/x") == 50              # the second owner's whole read does
    [m] = memory.where(ledger, "pve", _PVE, "x", now=51, receipt=False)["matches"]
    assert (m["status"], m["paths"]) == ("gone", [])
