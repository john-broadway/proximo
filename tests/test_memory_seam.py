"""The estate memory's per-plane seam: what memory knows of a plane's shape lives behind
`memory.shape(plane)`, one implementation per plane (`memory_pve` today). A plane with no shape
feeds nothing, resolves nothing and learns nothing, and says which plane it was."""
from __future__ import annotations

import sqlite3

import pytest

from proximo.core import engine, memory, memory_pve


class _ReadRow:
    access = "read"


def test_pve_is_registered_and_its_feeds_are_todays():
    assert memory.shape("pve") is memory_pve.SHAPE
    assert memory.feeds("pve") == memory.FEEDS


def test_a_plane_with_no_shape_feeds_nothing_and_resolves_nothing():
    assert memory.feeds("nope") == frozenset()
    assert memory.resolve("x", plane="nope") == {"source": "memory", "verdict": "not_in_memory",
                                                "found": False, "paths": []}


def test_learn_on_a_plane_with_no_shape_names_the_plane():
    with pytest.raises(memory.Unusable, match="nope"):
        memory.learn("nope")


def test_published_checks_the_plane_it_is_asked_about(monkeypatch):
    memory._published.cache_clear()
    asked = []
    monkeypatch.setattr(engine, "resolve", lambda p, m, path: asked.append(p) or _ReadRow())
    try:
        memory._published("pbs", "/admin/datastore")
    finally:
        memory._published.cache_clear()          # the fake's answer never outlives this test
    assert asked == ["pbs"]


# Today's literal, before the seam: qemu and lxc tie at 0 and `kind` breaks the tie.
_TODAY = ("CASE kind WHEN 'qemu' THEN 0 WHEN 'lxc' THEN 0 WHEN 'node' THEN 1 WHEN 'storage' THEN 2 "
          "WHEN 'pool' THEN 3 WHEN 'job' THEN 4 WHEN 'bridge' THEN 5 WHEN 'backup' THEN 6 ELSE 7 END, kind")


def test_pves_kind_order_sorts_exactly_as_today():
    kinds = ["backup", "acl", "bridge", "qemu", "job", "lxc", "pool", "storage", "node", "other"]
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE t (kind TEXT)")
    db.executemany("INSERT INTO t VALUES (?)", [(k,) for k in kinds])
    today = [k for (k,) in db.execute(f"SELECT kind FROM t ORDER BY {_TODAY}")]   # noqa: S608
    now = [k for (k,) in db.execute(
        f"SELECT kind FROM t ORDER BY {memory._vendor_order(memory_pve.SHAPE.kind_order)}")]  # noqa: S608
    assert now == today


def test_pve_shows_its_key_as_the_id_and_has_no_second_id():
    assert memory_pve.SHAPE.show({"kind": "bridge", "key": "pve1/vmbr0", "ident": "vmbr0"}) == {"id": "pve1/vmbr0"}
    assert memory_pve.SHAPE.id_names == frozenset()


def test_a_shape_that_omits_after_kept_adds_no_gaps():
    tally = memory.LearnTally(kept=(), count_kind="groups", count=0, sees=True)
    assert tally.after_kept(sqlite3.connect(":memory:")) == []


class _Twin:
    """A shape whose `group` kind carries a second vendor id in its name (`id_names`)."""

    plane = "zz"
    vendor_kinds = frozenset({"group", "store"})
    kind_order = ("group", "store")
    id_names = frozenset({"group"})
    no_ident_kinds: frozenset[str] = frozenset()
    no_name_kinds: frozenset[str] = frozenset()
    global_ids: frozenset[str] = frozenset()


def _held(rows):
    db = sqlite3.connect(":memory:")
    db.executescript(memory._SCHEMA)
    for kind, key, ident, name in rows:
        memory._upsert(db, "zz", "box", kind, key, t=1.0, source="s", untrusted=False, ident=ident, name=name)
    return db


def test_a_digits_word_matches_the_name_of_an_id_names_kind_only(monkeypatch):
    monkeypatch.setitem(memory.SHAPES, "zz", _Twin())
    db = _held([("group", "a/vm/105", "vm/105", "105"), ("store", "105x", "s1", "105")])
    found = memory._vendor_exact(db, "zz", "box", "105")
    assert [(r["kind"], r["key"]) for r in found] == [("group", "a/vm/105")]     # never the store named 105
    assert memory._vendor_exact(db, "zz", "box", "10") == []                       # exact, never a prefix


def test_with_no_id_names_a_digits_word_is_an_id_or_nothing(monkeypatch):
    monkeypatch.setitem(memory.SHAPES, "zz", type("_Plain", (_Twin,), {"id_names": frozenset()})())
    db = _held([("group", "a/vm/105", "vm/105", "105")])
    assert memory._vendor_exact(db, "zz", "box", "105") == []


# --- a shape declares its uses and its unmatched kinds (nothing PVE-literal left in memory.py) ------

def test_pve_and_pbs_declare_their_uses_and_their_unmatched_kinds():
    from proximo.core import memory_pbs  # noqa: PLC0415
    pve, pbs = memory_pve.SHAPE, memory_pbs.SHAPE
    assert (pve.answers_uses, pve.no_ident_kinds, pve.no_name_kinds) == (
        True, frozenset({"acl"}), frozenset({"acl", "backup"}))
    assert (pbs.answers_uses, pbs.no_ident_kinds, pbs.no_name_kinds) == (False, frozenset(), frozenset())


class _Kinds(_Twin):
    """A shape that keeps a `store`'s name and a `group`'s id out of `where`'s exact match."""

    id_names = frozenset()
    no_ident_kinds = frozenset({"group"})
    no_name_kinds = frozenset({"store"})


def test_a_shapes_no_name_kinds_answer_to_no_name(monkeypatch):
    monkeypatch.setitem(memory.SHAPES, "zz", _Kinds())
    db = _held([("group", "g1", "gid", "same"), ("store", "s1", "sid", "same")])
    assert [(r["kind"], r["key"]) for r in memory._vendor_exact(db, "zz", "box", "same")] == [("group", "g1")]
    assert [r["key"] for r in memory._vendor_exact(db, "zz", "box", "sid")] == ["s1"]   # its id still answers


def test_a_shapes_no_ident_kinds_answer_to_no_id(monkeypatch):
    monkeypatch.setitem(memory.SHAPES, "zz", _Kinds())
    db = _held([("group", "g1", "gid", "gname")])
    assert memory._vendor_exact(db, "zz", "box", "gid") == []
    assert [r["key"] for r in memory._vendor_exact(db, "zz", "box", "gname")] == ["g1"]   # its name still answers


# --- a shape's global ids: kinds whose stored key IS the vendor's one-string id -----------------------

class _Global(_Twin):
    """A shape whose `group` kind is keyed by the vendor's own one-string id."""

    id_names = frozenset()
    global_ids = frozenset({"group"})


def test_a_global_id_kind_is_found_by_its_key_and_a_shape_without_it_is_not(monkeypatch):
    db = _held([("group", "remote/a/guest/105", "105", "web"), ("store", "remote/a/store/s1", "s1", "s1")])
    monkeypatch.setitem(memory.SHAPES, "zz", _Global())
    assert [r["key"] for r in memory._vendor_exact(db, "zz", "box", "remote/a/guest/105")] == ["remote/a/guest/105"]
    assert [r["key"] for r in memory._vendor_exact(db, "zz", "box", "group remote/a/guest/105")] == [
        "remote/a/guest/105"]                                                        # after its type word too
    assert memory._vendor_exact(db, "zz", "box", "store remote/a/guest/105") == []   # another type word: no
    assert memory._vendor_exact(db, "zz", "box", "remote/a/store/s1") == []          # a kind not declared
    assert memory._vendor_exact(db, "zz", "box", "remote/a/guest/10") == []          # exact, never a prefix
    assert memory._vendor_exact(db, "zz", "box", "REMOTE/a/guest/105") == []         # case is the vendor's
    monkeypatch.setitem(memory.SHAPES, "zz", _Twin())                                # the control: no global ids
    assert memory._vendor_exact(db, "zz", "box", "remote/a/guest/105") == []


def test_a_target_that_is_a_key_and_an_ident_comes_back_once_key_matches_first(monkeypatch):
    monkeypatch.setitem(memory.SHAPES, "zz", _Global())
    db = _held([("group", "same", "same", "same"), ("group", "g2", "same", "x"), ("store", "s3", "y", "same")])
    found = [(r["kind"], r["key"]) for r in memory._vendor_exact(db, "zz", "box", "same")]
    assert found == [("group", "same"), ("group", "g2"), ("store", "s3")]   # key, then ident, then name; once each


class _Relates(_Twin):
    """A shape that relates (its `retire` triggers `relate`) and may or may not answer `uses`."""

    relating_owners = frozenset({"whole"})
    next_live = ("GET /zz",)
    token_sight = False
    answers_uses = False


def _fed(tmp_path, **meta):
    ledger = str(tmp_path / "audit.log")
    db = memory._open(ledger, create=True)
    assert db is not None
    with db:
        for k, v in {"last_fed": 1.0, **meta}.items():
            memory._set(db, "zz", "box", k, v)
    memory._settle(ledger)
    return ledger


def test_a_shape_that_relates_but_does_not_answer_uses_refuses_it(tmp_path, monkeypatch):
    monkeypatch.setitem(memory.SHAPES, "zz", _Relates())
    ledger = _fed(tmp_path)
    with pytest.raises(memory.Unusable, match="relates nothing on zz"):
        memory.uses(ledger, "zz", "box", "tank", receipt=False)


@pytest.mark.parametrize("token_sight", [False, True])
def test_a_shape_that_answers_uses_says_partial_sight_whatever_its_token_sight(tmp_path, monkeypatch, token_sight):
    monkeypatch.setitem(memory.SHAPES, "zz", type("_Uses", (_Relates,), {
        "answers_uses": True, "relating_owners": frozenset(), "token_sight": token_sight})())
    ledger = _fed(tmp_path, learn_sight="partial")
    out = memory.uses(ledger, "zz", "box", "tank", receipt=False)
    assert out["complete"] is False and "partial_sight" in out["why"]
    ledger = _fed(tmp_path, learn_sight="whole")
    assert "partial_sight" not in memory.uses(ledger, "zz", "box", "tank", receipt=False)["why"]
