"""Phase B of the estate memory: `proximo_find` answers with the concrete paths memory knows for the
target ("lxc 105" -> `GET /nodes/pve1/lxc/105/status/current`) and keeps the addresses for the
words. The design: "What the cut took" (2026-10-25), piece 4. The seam is `memory.resolve`.

The rules this file holds the door to: the block rides under ONE key, `memory`, and only when memory
found the target (find makes no claim about a target it does not know); each plane with a memory
shape and a box this caller holds a token for (PVE, PBS, PMG) gives its own block; a
memory failure never fails the find (the answer is the one memory-off gives); a recall row is written
for an answer memory gave and for nothing else; the whole answer, block included, fits the door's cap,
and a path is dropped whole, never cut.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from proximo.core import apitree, engine, memory, rawdoor, spine, wire
from proximo.core.doors import mcp
from proximo.core.errors import ProximoError
from proximo.core.ledger import LedgerConfig
from test_memory import BOX, LISTS, _Wire
from test_memory_pbs import BOX as PBS_BOX
from test_memory_pbs import PBS
from test_memory_pbs import _Wire as _PbsWire
from test_memory_pdm import BOX as PDM_BOX
from test_memory_pdm import PDM
from test_memory_pdm import _Wire as _PdmWire
from test_memory_pmg import BOX as PMG_BOX
from test_memory_pmg import PMG
from test_memory_pmg import _Wire as _PmgWire

FEEDS = ("/cluster/resources", "/nodes/pve1/lxc/105/pending", "/nodes/pve1/qemu/100/pending",
         "/storage", "/cluster/backup", "/pools", "/access/acl", "/nodes/pve1/network")


@pytest.fixture
def box(monkeypatch):
    """The env box find consults: the same base URL the engine feeds memory under."""
    monkeypatch.setenv("PROXIMO_API_BASE_URL", BOX)
    return BOX


@pytest.fixture
def vendor(monkeypatch):
    w = _Wire(LISTS)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    return w


@pytest.fixture
def pbs_box(monkeypatch):
    """The env PBS box: a token this caller holds for PBS (its base URL set)."""
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", PBS_BOX)
    return PBS_BOX


@pytest.fixture
def pbs_vendor(monkeypatch):
    """PBS's wire beside whichever wire the other planes already have."""
    w = _PbsWire(PBS)
    other = engine._client
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w if product == "pbs" else other(product, c))
    return w


@pytest.fixture
def pmg_box(monkeypatch):
    """The env PMG box: a credential this caller holds for PMG (its base URL set)."""
    monkeypatch.setenv("PROXIMO_PMG_BASE_URL", PMG_BOX)
    return PMG_BOX


def _pmg_vendor(monkeypatch, bodies):
    w = _PmgWire(bodies)
    other = engine._client
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w if product == "pmg" else other(product, c))
    return w


@pytest.fixture
def pmg_vendor(monkeypatch):
    """PMG's wire beside whichever wire the other planes already have."""
    return _pmg_vendor(monkeypatch, PMG)


@pytest.fixture
def pdm_box(monkeypatch):
    """The env PDM box: a token this caller holds for PDM (its base URL set)."""
    monkeypatch.setenv("PROXIMO_PDM_BASE_URL", PDM_BOX)
    return PDM_BOX


def _pdm_vendor(monkeypatch, bodies):
    w = _PdmWire(bodies)
    other = engine._client
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w if product == "pdm" else other(product, c))
    return w


@pytest.fixture
def pdm_vendor(monkeypatch):
    """PDM's wire beside whichever wire the other planes already have."""
    return _pdm_vendor(monkeypatch, PDM)


#: The PDM lists find is proven on: the remotes, each PVE remote's resources, and the combined list (a PBS
#: remote's node). No sight is needed to add: find reads what memory holds, owned or not.
PDM_FEEDS = ("/remotes/remote", "/pve/remotes/alpha/resources", "/pve/remotes/beta/resources", "/resources/list")


def _feed_pdm(paths=PDM_FEEDS):
    for p in paths:
        engine.execute(engine.resolve("pdm", "GET", p), {}, path=p)


#: The PMG lists find is proven on: a relay domain, its transport and its DKIM domain share one spelling.
PMG_FEEDS = ("/config/domains", "/config/transport", "/config/dkim/domains", "/config/pbs")


def _feed_pmg(paths=PMG_FEEDS):
    for p in paths:
        engine.execute(engine.resolve("pmg", "GET", p), {}, path=p)


def _feed_pbs():
    for p in ("/admin/datastore", "/admin/datastore/tank/groups"):
        engine.execute(engine.resolve("pbs", "GET", p), {}, path=p)


def _feed(paths=FEEDS):
    for p in paths:
        engine.execute(engine.resolve("pve", "GET", p), {}, path=p)


def _ledger():
    return LedgerConfig.from_env().audit_log_path


def _recalls():
    try:
        with open(_ledger()) as fh:
            return [json.loads(line) for line in fh if '"core.recall"' in line]
    except FileNotFoundError:
        return []


def _size(answer):
    body = json.dumps(answer, separators=(",", ":"), default=str)
    return len(body.encode()), body


def _within(answer, cap=None):
    """The door's own measure (`_shape`'s `fits_with`): compact JSON bytes and tokens, `rawdoor.fits`."""
    n, body = _size(answer)
    return rawdoor.fits(n, body, cap=cap or rawdoor.answer_cap())


# --- the block: concrete paths for a target memory knows ------------------------------------------

def test_find_names_the_concrete_path_memory_knows(box, vendor):
    _feed()
    out = mcp.find("lxc 105")
    block = out["memory"][0]
    assert block["verdict"] == "found" and block["source"] == "memory"
    assert block["paths"][0] == "GET /nodes/pve1/lxc/105/status/current"
    assert "age_seconds" in block and "as_of" in block
    assert out["matches"], "the addresses for the words are kept beside the target"


def test_find_by_a_name_finds_the_guest(box, vendor):
    _feed()
    assert mcp.find("web")["memory"][0]["paths"][0] == "GET /nodes/pve1/lxc/105/status/current"


def test_every_path_in_the_block_is_a_published_read(box, vendor):
    _feed()
    for words in ("lxc 105", "web", "db", "nas", "pve1"):
        block = (mcp.find(words).get("memory") or [None])[0]
        assert block, words
        for p in block["paths"]:
            method, path = p.split(" ", 1)
            assert method == "GET" and "{" not in path
            assert engine.resolve("pve", "GET", path).access == "read"


def test_words_memory_does_not_know_add_no_block(box, vendor):
    """find makes no claim about a target it does not know: no block, not an empty one."""
    _feed()
    assert "memory" not in mcp.find("list datastores")


def test_an_empty_memory_adds_no_block(box, vendor):
    assert "memory" not in mcp.find("lxc 105")


# --- PVE only ---------------------------------------------------------------------------------------

def test_a_plane_with_no_shape_is_never_asked_even_with_a_box(box, vendor, monkeypatch):
    """Every product has a shape now, so a made-up plane stands for one that has none: the door would
    refuse its name (`find` knows only `apitree.PRODUCTS`), so the seam `_recall` is driven directly,
    with a box this caller holds for it. Nothing is asked and no block comes back."""
    assert memory.shape("nope") is None
    real_url = wire.env_base_url
    monkeypatch.setattr(wire, "env_base_url", lambda p: BOX if p == "nope" else real_url(p))
    _feed()
    asked = []
    real_resolve, real_where = memory.resolve, memory.where
    monkeypatch.setattr(memory, "resolve",
                        lambda w, plane, **k: asked.append(plane) or real_resolve(w, plane=plane, **k))
    monkeypatch.setattr(memory, "where", lambda *a, **k: asked.append(a[1]) or real_where(*a, **k))
    assert mcp._recall("web", "nope") is None and asked == []
    assert mcp._recall("web", "pve") and asked == ["pve", "pve"]    # the control: a plane with a shape is asked


def test_resolve_on_a_plane_with_no_shape_opens_nothing(box, vendor, monkeypatch):
    """`resolve`'s own guard, below the door's: a plane with no shape is not found, `where` is never called."""
    _feed()
    asked = []
    monkeypatch.setattr(memory, "where", lambda *a, **k: asked.append(a) or {"found": True, "paths": ["x"]})
    assert memory.resolve("web", plane="nope") == {"source": "memory", "verdict": "not_in_memory", "found": False,
                                                    "paths": []}
    assert asked == []
    memory.resolve("web", plane="pve")
    assert len(asked) == 1                                            # the control: a plane with a shape asks


_BASE_URL = {p: "PROXIMO_API_BASE_URL" if p == "pve" else f"PROXIMO_{p.upper()}_BASE_URL" for p in apitree.PRODUCTS}


@pytest.mark.parametrize("plane", apitree.PRODUCTS)
def test_a_named_plane_with_no_box_is_never_asked(monkeypatch, plane):
    """A plane is asked only when the caller holds a credential for it (`wire.env_base_url`), named or
    not: no box, no `resolve`, no `where`, and no block (the answer memory-off gives)."""
    for var in _BASE_URL.values():
        monkeypatch.delenv(var, raising=False)
    assert wire.env_base_url(plane) is None
    asked = []
    real_resolve, real_where = memory.resolve, memory.where
    monkeypatch.setattr(memory, "resolve", lambda w, plane, **k: asked.append(("resolve", plane))
                        or real_resolve(w, plane=plane, **k))
    monkeypatch.setattr(memory, "where", lambda *a, **k: asked.append(("where", a[1])) or real_where(*a, **k))
    out = mcp.find("105", plane=plane)
    assert asked == [] and "memory" not in out
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    assert out == mcp.find("105", plane=plane)                       # what memory-off answers, word for word


@pytest.mark.parametrize("plane", apitree.PRODUCTS)
def test_a_named_plane_with_its_box_is_asked(monkeypatch, plane):
    """The control for the test above: the same find, that plane's base URL set, asks memory on it."""
    for var in _BASE_URL.values():
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(_BASE_URL[plane], "https://unreachable.invalid:8006/api2/json")
    assert wire.env_base_url(plane)
    asked = []
    real = memory.resolve
    monkeypatch.setattr(memory, "resolve", lambda w, plane, **k: asked.append(plane) or real(w, plane=plane, **k))
    mcp.find("105", plane=plane)
    assert asked == [plane]


def test_the_pve_plane_consults_memory(box, vendor):
    """The control for the test above: the same words on pve do answer from memory."""
    _feed()
    assert mcp.find("web", plane="pve")["memory"][0]["verdict"] == "found"


# --- PBS, and every plane this caller holds a token for (John 2026-11-09) ---------------------------

def test_the_pbs_plane_consults_pbs_memory(pbs_box, pbs_vendor):
    _feed_pbs()
    [block] = mcp.find("tank", plane="pbs")["memory"]
    assert block["plane"] == "pbs" and block["verdict"] == "found"
    assert block["paths"] == ["GET /admin/datastore/tank/status"]
    assert all(m["plane"] == "pbs" for m in block["matches"])


def test_no_plane_asks_every_plane_this_caller_holds_a_token_for(box, vendor, pbs_box, pbs_vendor):
    _feed()                                           # guest 105 on pve
    _feed_pbs()                                       # group vm/105 on pbs
    blocks = mcp.find("105")["memory"]
    assert [b["plane"] for b in blocks] == ["pve", "pbs"]
    assert all(m["plane"] == b["plane"] for b in blocks for m in b["matches"])


def test_a_plane_without_a_token_is_never_asked(box, vendor, monkeypatch):
    real_url = wire.env_base_url
    monkeypatch.setattr(wire, "env_base_url", lambda p: None if p == "pbs" else real_url(p))   # no PBS token here
    asked = []
    real = memory.resolve
    monkeypatch.setattr(memory, "resolve", lambda w, plane, **k: asked.append(plane) or real(w, plane=plane, **k))
    _feed()
    mcp.find("105")
    assert asked == ["pve"]


def test_with_both_tokens_both_planes_are_asked(box, vendor, pbs_box, monkeypatch):
    """The control for the test above: the same seam, PBS's base URL set, asks both in order."""
    asked = []
    real = memory.resolve
    monkeypatch.setattr(memory, "resolve", lambda w, plane, **k: asked.append(plane) or real(w, plane=plane, **k))
    mcp.find("105")
    assert asked == ["pve", "pbs"]


def test_one_planes_failure_drops_only_its_block(box, vendor, pbs_box, pbs_vendor, monkeypatch):
    _feed()
    _feed_pbs()
    real = memory.resolve
    def flaky(w, plane, **k):
        if plane == "pbs":
            raise OSError("disk")
        return real(w, plane=plane, **k)
    monkeypatch.setattr(memory, "resolve", flaky)
    assert [b["plane"] for b in mcp.find("105")["memory"]] == ["pve"]


def test_a_pbs_group_whose_taint_marker_cannot_be_written_drops_the_block_not_the_find(pbs_box, pbs_vendor,
                                                                                      monkeypatch):
    """A group is guest text; no marker, no block, the addresses stay."""
    _feed_pbs()
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    off = mcp.find("105", plane="pbs")
    monkeypatch.delenv("PROXIMO_MEMORY")
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    assert mcp.find("105", plane="pbs")["memory"][0]["plane"] == "pbs"     # the control: it answers when marked

    def cannot(*a, **k):
        raise OSError("read-only")
    monkeypatch.setattr(spine, "mark_tainted", cannot)
    assert mcp.find("105", plane="pbs") == off                            # the find answers, as memory-off does


# --- PMG: find answers from PMG's memory in the vendor's words ------------------------------------

def test_the_pmg_plane_consults_pmg_memory(pmg_box, pmg_vendor, monkeypatch):
    """The pin for find on plane=pmg: memory is ASKED on pmg and its block comes back. A find that
    stopped consulting memory on pmg (no shape, or the plane left out) answers with no block."""
    _feed_pmg()
    asked = []
    real = memory.resolve
    monkeypatch.setattr(memory, "resolve", lambda w, plane, **k: asked.append(plane) or real(w, plane=plane, **k))
    [block] = mcp.find("example.com", plane="pmg")["memory"]
    assert asked == ["pmg"]
    assert block["plane"] == "pmg" and block["verdict"] == "found" and block["source"] == "memory"
    assert [(m["plane"], m["kind"], m["id"]) for m in block["matches"]] == [
        ("pmg", "domain", "example.com"), ("pmg", "transport", "example.com"), ("pmg", "dkim-domain", "example.com")]
    assert block["paths"] == ["GET /config/domains/example.com", "GET /config/transport/example.com",
                              "GET /config/dkim/domains/example.com"]


def test_a_pmg_type_word_narrows_the_block_to_that_kind(pmg_box, pmg_vendor):
    _feed_pmg()
    [block] = mcp.find("dkim-domain example.com", plane="pmg")["memory"]
    assert [m["kind"] for m in block["matches"]] == ["dkim-domain"]
    assert block["paths"] == ["GET /config/dkim/domains/example.com"]


def test_every_path_in_a_pmg_block_is_a_published_read(pmg_box, pmg_vendor):
    _feed_pmg()
    for words in ("example.com", "example.org", "offsite"):
        [block] = mcp.find(words, plane="pmg")["memory"]
        for p in block["paths"]:
            method, path = p.split(" ", 1)
            assert method == "GET" and engine.resolve("pmg", method, path).access == "read", p


@pytest.mark.parametrize("words", ["nowhere.example", "example", "example.co", "domain nowhere.example",
                                   "transport example.org"])
def test_a_word_not_in_pmg_memory_adds_no_block_and_no_recall_row(pmg_box, pmg_vendor, words):
    """Exact or nothing: a word the box never answered, a prefix, a near miss, or a type word on the
    wrong kind gives the answer memory-off gives."""
    _feed_pmg()
    assert mcp.find("example.com", plane="pmg")["memory"]          # the control: the box's own word answers
    n = len(_recalls())
    assert "memory" not in mcp.find(words, plane="pmg")
    assert len(_recalls()) == n


def test_a_found_pmg_block_writes_one_recall_row(pmg_box, pmg_vendor):
    _feed_pmg()
    n = len(_recalls())
    mcp.find("example.org", plane="pmg")
    rows = _recalls()[n:]
    assert len(rows) == 1 and rows[0]["target"] == "memory find"


def test_pmg_memory_off_gives_todays_answer(pmg_box, pmg_vendor, monkeypatch):
    before = mcp.find("example.com", plane="pmg")
    _feed_pmg()
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    assert mcp.find("example.com", plane="pmg") == before


def test_no_plane_asks_pmg_after_pbs_in_the_products_order(box, vendor, pbs_box, pbs_vendor, pmg_box, monkeypatch):
    """PMG and PBS boxes configured, no plane named: one block per plane that knows the word, in
    `apitree.PRODUCTS` order. `tank` is a PBS datastore and, here, a PMG PBS remote of that name."""
    _pmg_vendor(monkeypatch, {**PMG, "/config/pbs": [{"remote": "tank", "server": "192.0.2.20",
                                                      "datastore": "store1"}]})
    _feed_pbs()
    _feed_pmg(("/config/pbs",))
    blocks = mcp.find("tank")["memory"]
    planes = [b["plane"] for b in blocks]
    assert planes == ["pbs", "pmg"] == [p for p in apitree.PRODUCTS if p in planes]
    assert all(m["plane"] == b["plane"] for b in blocks for m in b["matches"])
    assert blocks[1]["paths"] == ["GET /config/pbs"]


def test_with_pve_pbs_and_pmg_credentials_each_plane_is_asked_in_the_products_order(box, vendor, pbs_box, pmg_box,
                                                                                    monkeypatch):
    asked = []
    real = memory.resolve
    monkeypatch.setattr(memory, "resolve", lambda w, plane, **k: asked.append(plane) or real(w, plane=plane, **k))
    mcp.find("105")
    assert asked == [p for p in apitree.PRODUCTS if memory.shape(p) is not None and wire.env_base_url(p)] == [
        "pve", "pbs", "pmg"]
    assert memory.shape("pdm") is not None and wire.env_base_url("pdm") is None   # a shape, no box: never asked


def test_without_a_pmg_box_pmg_is_never_asked(box, vendor, pbs_box, monkeypatch):
    """The control for the test above: PMG's base URL unset, the same find never asks PMG."""
    asked = []
    real = memory.resolve
    monkeypatch.setattr(memory, "resolve", lambda w, plane, **k: asked.append(plane) or real(w, plane=plane, **k))
    mcp.find("105")
    assert asked == ["pve", "pbs"]


def test_a_pmg_failure_drops_only_its_block(pbs_box, pbs_vendor, pmg_box, monkeypatch):
    _pmg_vendor(monkeypatch, {**PMG, "/config/pbs": [{"remote": "tank", "server": "192.0.2.20",
                                                      "datastore": "store1"}]})
    _feed_pbs()
    _feed_pmg(("/config/pbs",))
    real = memory.resolve

    def flaky(w, plane, **k):
        if plane == "pmg":
            raise sqlite3.OperationalError("disk I/O error")
        return real(w, plane=plane, **k)
    monkeypatch.setattr(memory, "resolve", flaky)
    assert [b["plane"] for b in mcp.find("tank")["memory"]] == ["pbs"]


# --- a memory failure never fails the find ----------------------------------------------------------

def test_memory_off_gives_todays_answer(box, vendor, monkeypatch):
    before = mcp.find("lxc 105")                     # nothing fed yet: today's answer
    _feed()
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    assert mcp.find("lxc 105") == before


@pytest.mark.parametrize("exc", [sqlite3.OperationalError("disk I/O error"), OSError("gone"),
                                 memory.Unusable("refused"), RuntimeError("anything")])
def test_a_memory_that_raises_gives_the_answer_memory_off_gives(box, vendor, monkeypatch, exc):
    _feed()
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    off = mcp.find("lxc 105")
    monkeypatch.delenv("PROXIMO_MEMORY")

    def boom(*a, **k):
        raise exc
    monkeypatch.setattr(memory, "where", boom)
    assert mcp.find("lxc 105") == off


def test_a_taint_marker_that_cannot_be_written_drops_the_block_not_the_find(box, vendor, monkeypatch):
    """The marker refusal protects the model from guest text it was not marked for: the block goes,
    the addresses stay."""
    _feed()
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")

    def cannot(*a, **k):
        raise OSError("read-only")
    monkeypatch.setattr(spine, "mark_tainted", cannot)
    out = mcp.find("lxc 105")                        # lxc 105 came from /cluster/resources: guest text
    assert "memory" not in out and out["matches"]


# --- receipts: a row for an answer memory gave, nothing else ---------------------------------------

def test_a_found_block_writes_one_recall_row(box, vendor):
    _feed()
    n = len(_recalls())
    mcp.find("lxc 105")
    rows = _recalls()[n:]
    assert len(rows) == 1 and rows[0]["target"] == "memory find"


def test_words_memory_does_not_know_write_no_recall_row(box, vendor):
    _feed()
    n = len(_recalls())
    mcp.find("list datastores")
    mcp.find("container 999")
    assert len(_recalls()) == n


# --- taint and the fence ----------------------------------------------------------------------------

def test_a_block_from_guest_text_marks_the_session(box, vendor, monkeypatch):
    _feed(("/cluster/resources",))
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    audit_dir = __import__("os").path.dirname(_ledger())
    assert not spine.is_tainted(audit_dir)
    out = mcp.find("web")
    assert out["memory"][0]["untrusted"] is True and spine.is_tainted(audit_dir)


def test_a_fenced_block_keeps_its_paths_readable(box, vendor, monkeypatch):
    _feed(("/cluster/resources",))
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", "1")
    block = mcp.find("web")["memory"][0]
    assert block["paths"][0] == "GET /nodes/pve1/lxc/105/status/current"
    assert block["matches"]["proximo_untrusted"] is True


# --- the cap: the whole answer fits, a path is dropped whole ---------------------------------------

BIG = "web-" + "x" * 60


def _big_estate(monkeypatch, n=40):
    rows = [{"id": "node/pve1", "type": "node", "node": "pve1", "status": "online"}]
    rows += [{"id": f"lxc/{200 + i}", "type": "lxc", "vmid": 200 + i, "node": "pve1", "status": "running",
              "name": BIG} for i in range(n)]
    w = _Wire({**LISTS, "/cluster/resources": rows})
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    _feed(("/cluster/resources",))


def test_the_whole_answer_fits_the_default_cap(box, monkeypatch):
    _big_estate(monkeypatch)
    out = mcp.find(BIG, limit=25)
    n, body = _size(out)
    assert rawdoor.fits(n, body), f"{n} bytes"
    block = out["memory"][0]
    assert block["paths"], "the path is what the block is for: one stays"
    for p in block["paths"]:
        assert p.startswith("GET /nodes/pve1/lxc/") and p.endswith(("/status/current", "/config"))
    assert out.get("truncated") is True


def test_a_cut_block_says_how_much_it_shows(box, monkeypatch):
    _big_estate(monkeypatch)
    out = mcp.find(BIG, limit=25)
    assert _within(out)
    block = out["memory"][0]
    shown = block.get("matches_shown", len(block.get("matches", [])))
    assert shown < memory.WHERE_SHOWN or "paths_shown" in block


# --- lens 1 (2026-11-06): a gone target, the shed branches pinned ---------------------------------

def _gone_105(monkeypatch):
    """lxc 105 listed, then a whole read without it: memory knows it, gone, with no path to read."""
    first = _Wire(LISTS)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: first)
    _feed(("/cluster/resources",))
    rows = [r for r in LISTS["/cluster/resources"] if r.get("vmid") != 105]
    w = _Wire({**LISTS, "/cluster/resources": rows})
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    _feed(("/cluster/resources",))


def test_a_gone_target_gives_no_block_and_writes_no_recall_row(box, monkeypatch):
    _gone_105(monkeypatch)
    n = len(_recalls())
    out = mcp.find("lxc 105")
    assert "memory" not in out
    assert len(_recalls()) == n, "a recall row for a block find never gave"


def test_a_gone_target_never_marks_the_session(box, monkeypatch):
    _gone_105(monkeypatch)
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    audit_dir = __import__("os").path.dirname(_ledger())
    out = mcp.find("lxc 105")
    assert "memory" not in out
    assert not spine.is_tainted(audit_dir), "marked by a find that showed no guest text"


def test_no_match_in_the_block_carries_its_own_paths(box, vendor):
    _feed()
    block = mcp.find("pve1")["memory"][0]
    assert block["matches"] and all("paths" not in m for m in block["matches"])


def _digit_estate(monkeypatch):
    """Digits are a token each: eight guests named `migrate`, each on a node with a 64-digit name, so
    the token cap binds and the paths themselves must be shed (the branch the first cut never ran)."""
    nodes = [str(k) * 64 for k in range(1, 9)]
    rows = [{"id": f"node/{n}", "type": "node", "node": n, "status": "online"} for n in nodes]
    rows += [{"id": f"lxc/{9999999990 + i}", "type": "lxc", "vmid": 9999999990 + i, "node": nodes[i],
              "status": "running", "name": "migrate"} for i in range(8)]
    w = _Wire({**LISTS, "/cluster/resources": rows})
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    _feed(("/cluster/resources",))


@pytest.mark.parametrize("fence", ["0", "1"])
def test_a_block_sheds_its_paths_whole_to_fit(box, monkeypatch, fence):
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", fence)
    _digit_estate(monkeypatch)
    out = mcp.find("lxc migrate", limit=25)
    n, body = _size(out)
    assert rawdoor.fits(n, body), f"{n} bytes, {rawdoor.estimate_tokens(body)} tokens"
    block = out["memory"][0]
    assert block["matches_shown"] == 0 and "matches" not in block
    assert block["paths_shown"] == len(block["paths"]) >= 1
    for p in block["paths"]:
        assert engine.resolve("pve", "GET", p.split(" ", 1)[1]).access == "read"


def test_the_door_serves_no_block_without_a_path_whatever_the_seam_says(box, vendor, monkeypatch):
    """`resolve` finds nothing pathless now; the door's own guard is pinned in case it ever does."""
    monkeypatch.setattr(memory, "resolve", lambda *a, **k: {"source": "memory", "verdict": "found",
                                                             "found": True, "paths": [], "matches": []})
    assert "memory" not in mcp.find("lxc 105")


def test_under_a_cap_too_small_for_one_path_the_block_goes_whole():
    """The last resort (unreachable at the cap floors): a block still over the cap with one path left
    is dropped whole (it was kept at one path before), never cut, and the
    answer is the one memory-off gives."""
    found = {"matches": [{"plane": "pve", "method": "GET", "path": "/version", "access": "read"}]}
    block = {"source": "memory", "verdict": "found", "paths": ["GET /nodes/pve1/lxc/105/status/current",
                                                               "GET /nodes/pve1/lxc/105/config"],
             "matches": [{"kind": "lxc", "id": "105"}]}
    out = mcp._shape(found, cap=rawdoor.Cap(64, None), recalled=[block])
    assert "memory" not in out and out == mcp._shape(found, cap=rawdoor.Cap(64, None))


# --- lens 2 (2026-11-06): an id is never answered by a name; one query decides --------------------

def _estate(monkeypatch, *readings):
    """Feed `/cluster/resources` once per reading, in order: what memory holds after the last."""
    for rows in readings:
        w = _Wire({**LISTS, "/cluster/resources": rows})
        monkeypatch.setattr(engine, "_client", lambda product, c=None, w=w: w)
        _feed(("/cluster/resources",))


NODE = {"id": "node/pve1", "type": "node", "node": "pve1", "status": "online"}
WEB = {"id": "lxc/105", "type": "lxc", "vmid": 105, "node": "pve1", "name": "web", "status": "running"}


def test_a_guest_named_after_a_gone_id_never_takes_its_path(box, monkeypatch):
    squat = {"id": "lxc/300", "type": "lxc", "vmid": 300, "node": "pve1", "name": "105", "status": "running"}
    _estate(monkeypatch, [NODE, WEB], [NODE, squat])
    out = mcp.find("lxc 105")
    assert "memory" not in out, out.get("memory")
    assert memory.where(_ledger(), "pve", BOX, "105", receipt=False)["matches"][0]["id"] == "105"


def test_find_matches_the_vendor_name_exactly_never_a_prefix(box, monkeypatch):
    two = {"id": "lxc/106", "type": "lxc", "vmid": 106, "node": "pve1", "name": "web-two", "status": "running"}
    _estate(monkeypatch, [NODE, WEB, two], [NODE, two])
    assert mcp.find("web-two")["memory"][0]["paths"][0] == "GET /nodes/pve1/lxc/106/status/current"
    for words in ("web", "we", "web-tw", "Web-two", "WEB-TWO"):       # web is gone; the rest are not the vendor's
        assert "memory" not in mcp.find(words), words


def test_a_live_row_beside_a_gone_one_of_the_same_name_is_served(box, monkeypatch):
    again = {"id": "lxc/106", "type": "lxc", "vmid": 106, "node": "pve1", "name": "web", "status": "running"}
    _estate(monkeypatch, [NODE, WEB], [NODE, again])
    block = mcp.find("lxc web")["memory"][0]
    assert block["paths"] == ["GET /nodes/pve1/lxc/106/status/current", "GET /nodes/pve1/lxc/106/config"]


def test_a_feed_racing_the_find_never_marks_or_receipts_an_unserved_block(box, monkeypatch):
    """A whole read that makes 105 gone lands between find's question and memory's answer."""
    _estate(monkeypatch, [NODE, WEB])
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    audit_dir = __import__("os").path.dirname(_ledger())
    real = memory._vendor_exact

    def racing(*a, **k):
        rows = real(*a, **k)                              # memory answered from what it held...
        monkeypatch.setattr(memory, "_vendor_exact", real)
        monkeypatch.delenv("PROXIMO_TAINT_TRACK")         # ...then the vendor's whole read lands (not find's)
        _estate(monkeypatch, [NODE])
        monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
        return rows
    monkeypatch.setattr(memory, "_vendor_exact", racing)
    n = len(_recalls())
    out = mcp.find("lxc 105")
    served = "memory" in out
    assert served == spine.is_tainted(audit_dir), "marked iff served"
    assert len(_recalls()) - n == int(served), "a recall row iff served"


def test_shedding_keeps_the_best_match_first(box, monkeypatch):
    _big_estate(monkeypatch)
    whole = memory.where(_ledger(), "pve", BOX, BIG, receipt=False)["matches"]
    out = mcp.find(BIG, limit=25)
    assert _within(out)
    block = out["memory"][0]
    if block.get("matches"):
        assert block["matches"][0]["id"] == whole[0]["id"]
    assert block["paths"][0] == whole[0]["paths"][0]


def test_shed_descriptions_leave_from_the_end(box, vendor):
    found = {"matches": [{"plane": "pve", "method": "GET", "path": "/version", "access": "read"}]}
    block = {"source": "memory", "verdict": "found", "paths": ["GET /nodes/pve1/lxc/105/status/current"],
             "matches": [{"kind": "lxc", "id": str(i), "name": "n" * 150} for i in range(5)]}
    out = mcp._shape(found, recalled=[block])
    assert _within(out)
    kept = out["memory"][0].get("matches", [])
    assert [m["id"] for m in kept] == [str(i) for i in range(len(kept))]


# --- lens 3 (2026-11-07): a word of digits is an id ------------------------------------------------

def test_find_never_hands_a_longer_id_for_an_id_memory_lacks(box, monkeypatch):
    _estate(monkeypatch, [NODE, {"id": "lxc/1050", "type": "lxc", "vmid": 1050, "node": "pve1", "name": "app",
                                 "status": "running"}])
    for words in ("105", "lxc 105"):
        assert "memory" not in mcp.find(words), words
    assert mcp.find("lxc 1050")["memory"][0]["paths"][0] == "GET /nodes/pve1/lxc/1050/status/current"


def test_find_never_hands_a_guest_named_after_an_id_memory_never_held(box, monkeypatch):
    _estate(monkeypatch, [NODE, {"id": "lxc/300", "type": "lxc", "vmid": 300, "node": "pve1", "name": "105",
                                 "status": "running"}])
    assert "memory" not in mcp.find("lxc 105")


# --- vendor words only (John, 2026-11-07): the metal answers exactly; fuzzy is the model's ----------

def test_only_the_vendors_kind_words_open_memory(box, vendor):
    _feed()
    assert mcp.find("lxc 105")["memory"][0]["paths"][0] == "GET /nodes/pve1/lxc/105/status/current"
    assert mcp.find("qemu 100")["memory"][0]["paths"][0] == "GET /nodes/pve1/qemu/100/status/current"
    assert mcp.find("storage nas")["memory"][0]["paths"]
    assert mcp.find("pool core")["memory"][0]["paths"] == ["GET /pools/core"]
    for words in ("container 105", "ct 105", "vm 100", "LXC 105", "job backup-nightly", "guest 105"):
        assert "memory" not in mcp.find(words), words


@pytest.mark.parametrize("words", ["lxc 105?", "105.", "#105", "(105)", "lxc 105 status", "snapshot lxc 105",
                                   "lxc lxc 105", "１０５", "10", "1050"])
def test_anything_but_kind_and_target_exactly_is_no_block(box, vendor, words):
    """No block; a few of these find itself refuses as having no words to search (its own rule)."""
    _feed()
    try:
        out = mcp.find(words)
    except ProximoError as exc:
        assert "one or more words" in str(exc)
        return
    assert "memory" not in out


def test_a_vendor_id_ranks_before_a_name_that_spells_it(box, monkeypatch):
    """Both are the vendor's facts: the node's id first, the guest that took its name after (lens 6:
    hiding the name let a gone or pathless id hide a live guest)."""
    squat = {"id": "lxc/300", "type": "lxc", "vmid": 300, "node": "pve1", "name": "pve1", "status": "running"}
    _estate(monkeypatch, [NODE, squat])
    block = mcp.find("pve1")["memory"][0]
    assert block["paths"][0] == "GET /nodes/pve1/status"
    assert "GET /nodes/pve1/lxc/300/status/current" in block["paths"]
    assert mcp.find("lxc pve1")["memory"][0]["paths"][0] == "GET /nodes/pve1/lxc/300/status/current"


def test_a_gone_id_never_hides_a_live_name(box, monkeypatch):
    app = {"id": "lxc/107", "type": "lxc", "vmid": 107, "node": "pve1", "name": "app", "status": "running"}
    _estate(monkeypatch, [NODE, app])
    w = _Wire({**LISTS, "/cluster/resources": [NODE, app], "/pools": [{"poolid": "app"}]})
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    _feed(("/pools",))
    w2 = _Wire({**LISTS, "/cluster/resources": [NODE, app], "/pools": []})
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w2)
    _feed(("/pools",))                                        # pool app is gone
    assert mcp.find("app")["memory"][0]["paths"][0] == "GET /nodes/pve1/lxc/107/status/current"


def test_digits_are_an_id_or_nothing(box, monkeypatch):
    _estate(monkeypatch, [NODE, {"id": "lxc/300", "type": "lxc", "vmid": 300, "node": "pve1", "name": "105",
                                 "status": "running"},
                          {"id": "lxc/1050", "type": "lxc", "vmid": 1050, "node": "pve1", "name": "app",
                           "status": "running"}])
    for words in ("105", "lxc 105"):
        assert "memory" not in mcp.find(words), words
    assert mcp.find("lxc 300")["memory"][0]["paths"][0] == "GET /nodes/pve1/lxc/300/status/current"


# --- lens 7 (2026-11-07): find shows only what it can hand a path for --------------------------------

def test_find_shows_only_rows_with_a_path_and_the_first_path_is_the_first_match(box, monkeypatch):
    media = {"id": "lxc/108", "type": "lxc", "vmid": 108, "node": "pve1", "name": "media", "status": "running"}
    w = _Wire({**LISTS, "/cluster/resources": [NODE, media], "/storage": [{"storage": "media", "type": "dir"}]})
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    _feed(("/cluster/resources", "/storage"))                 # storage media: known, no node, no path
    block = mcp.find("media")["memory"][0]
    assert [(m["kind"], m["id"]) for m in block["matches"]] == [("lxc", "108")]
    assert block["paths"][0] == "GET /nodes/pve1/lxc/108/status/current"


def test_a_pathless_row_never_marks_the_session(box, monkeypatch):
    """Only rows find can serve are rendered, so only they can mark (lens 7: the cap cut the one row
    with a path after gone rows had marked the session)."""
    w = _Wire({**LISTS, "/cluster/resources": [NODE], "/storage": [{"storage": "media", "type": "dir"}]})
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    _feed(("/cluster/resources", "/storage"))
    monkeypatch.setattr(memory, "_mark", lambda rows, lp: bool(rows) and (_ for _ in ()).throw(AssertionError(rows)))
    assert "memory" not in mcp.find("media")


# --- a match with args leaves only with the paths it explains; the cross-block cut pinned ------------

TWO_GROUPS = {**PBS,
              "/admin/datastore/tank/groups": [{"backup-type": "vm", "backup-id": "105"},
                                               {"backup-type": "ct", "backup-id": "105"}],
              "/admin/datastore/tank/groups?ns=prod": [{"backup-type": "vm", "backup-id": "105"}]}


def _store_of(path):
    """`GET /admin/datastore/<store>/snapshots` -> store; None for any other path."""
    parts = path.split(" ", 1)[1].strip("/").split("/")
    return parts[2] if len(parts) == 4 and parts[:2] == ["admin", "datastore"] and parts[3] == "snapshots" else None


def _served_matches(block):
    told = block.get("matches", [])
    return json.loads(told["data"]) if isinstance(told, dict) else told


@pytest.mark.parametrize("fence", ["0", "1"])
def test_a_capped_pbs_block_never_hands_a_snapshots_path_without_its_args(pbs_box, monkeypatch, fence):
    """Two groups in one store share one snapshots path. The block names it once, and
    never hands it out without the `args`-carrying match that says which group it reads."""
    w = _PbsWire(TWO_GROUPS)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    for p, args in (("/admin/datastore/tank/groups", {}), ("/admin/datastore/tank/groups", {"ns": "prod"}),
                    ("/admin/datastore/cold/groups", {})):
        engine.execute(engine.resolve("pbs", "GET", p), dict(args), path=p)
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", fence)
    whole = mcp._recall("105", "pbs")
    assert whole and [b["plane"] for b in whole] == ["pbs"]
    assert whole[0]["paths"] == ["GET /admin/datastore/cold/snapshots", "GET /admin/datastore/tank/snapshots"]
    full = len(json.dumps(mcp._shape({"matches": []}, recalled=mcp._recall("105", "pbs")), separators=(",", ":")))
    shrank = False
    for n in range(full, 63, -16):
        out = mcp._shape({"matches": []}, cap=rawdoor.Cap(n, None), recalled=mcp._recall("105", "pbs"))
        assert _within(out, rawdoor.Cap(n, None)), n
        if "memory" not in out:                                          # dropped whole
            continue
        [block] = out["memory"]
        paths = block["paths"]
        assert paths and len(paths) == len(set(paths)), (n, paths)
        served = _served_matches(block)
        for p in paths:
            store = _store_of(p)
            assert store is not None, p
            assert any(m.get("args") and m.get("store") == store for m in served), (n, p, served)
        shrank = shrank or len(paths) < 2
    assert shrank or fence == "1", "the sweep never cut the block: the test looked at nothing"


def _plain_block(plane, paths, names):
    return {"plane": plane, "source": "memory", "verdict": "found", "paths": list(paths),
            "matches": [{"plane": plane, "kind": "thing", "id": n, "name": n * 30} for n in names]}


def test_two_blocks_shed_descriptions_last_block_first_then_paths_and_each_keeps_one():
    """The cross-block order as built: every plain description (last block first) before any path,
    paths from the last block first, and every block keeps one path."""
    found = {"matches": [{"plane": "pve", "method": "GET", "path": "/version", "access": "read"}]}
    pve_paths = [f"GET /nodes/pve1/lxc/{i}/status/current" for i in (101, 102, 103)]
    pbs_paths = [f"GET /admin/datastore/{s}/status" for s in ("aa", "bb", "cc")]

    def shaped(n):
        blocks = [_plain_block("pve", pve_paths, "abc"), _plain_block("pbs", pbs_paths, "xyz")]
        out = mcp._shape(found, cap=rawdoor.Cap(n, None), recalled=blocks)
        assert "memory" not in out or _within(out, rawdoor.Cap(n, None)), n
        return out.get("memory", [])

    full = len(json.dumps(mcp._shape(found, recalled=[_plain_block("pve", pve_paths, "abc"),
                                                      _plain_block("pbs", pbs_paths, "xyz")]),
                          separators=(",", ":")))
    seen = set()
    for n in range(full, 31, -8):
        blocks = shaped(n)
        assert [b["plane"] for b in blocks] in (["pve", "pbs"], ["pve"], []), n   # dropped whole, last first
        seen.add(("dropped", len(blocks)))
        if len(blocks) < 2:
            continue
        pve, pbs = blocks
        assert pve["plane"] == "pve" and pbs["plane"] == "pbs"
        assert len(pve["paths"]) >= 1 and len(pbs["paths"]) >= 1, (n, pve["paths"], pbs["paths"])
        if "paths_shown" in pve or "paths_shown" in pbs:
            assert "matches" not in pve and "matches" not in pbs, n          # descriptions all went first
        if "matches_shown" in pve:
            assert "matches" not in pbs, n                                  # the last block's went before
        if "paths_shown" in pve:
            assert pbs["paths"] == pbs_paths[:1], n                         # the last block's paths went before
        seen.add(("pbs-desc-cut", "matches_shown" in pbs and "matches_shown" not in pve))
        seen.add(("pbs-path-cut", "paths_shown" in pbs and "paths_shown" not in pve))
        seen.add(("floor", pve["paths"] == pve_paths[:1] and pbs["paths"] == pbs_paths[:1]))
    assert {("pbs-desc-cut", True), ("pbs-path-cut", True), ("floor", True), ("dropped", 1),
            ("dropped", 0)} <= seen, seen


def test_one_recall_row_per_plane_block(box, vendor, pbs_box, pbs_vendor):
    _feed()
    _feed_pbs()
    n = len(_recalls())
    assert [b["plane"] for b in mcp.find("105")["memory"]] == ["pve", "pbs"]
    rows = _recalls()[n:]
    assert len(rows) == 2 and all(r["target"] == "memory find" for r in rows)
    n = len(_recalls())
    mcp.find("105", plane="pbs")
    assert len(_recalls()) - n == 1


# --- the cap is hard: a block that cannot fit at its floor goes whole ---------------------------------

FOUND = {"matches": [{"plane": "pve", "method": "GET", "path": "/version", "access": "read"}]}


def _group_block(n_groups=2):
    """The live shape: groups in one store, one snapshots path, each group's args beside it."""
    path = "GET /admin/datastore/tank/snapshots"
    ms = [{"plane": "pbs", "kind": "group", "id": f"{t}/105", "store": "tank", "ns": ns, "paths": [path],
           "args": {"backup-type": t, "backup-id": "105", **({"ns": ns} if ns else {})}}
          for t, ns in (("ct", ""), ("vm", "prod"), ("vm", "prod/web"), ("ct", "prod"))[:n_groups]]
    return {"plane": "pbs", "source": "memory", "verdict": "found", "paths": [path], "matches": ms}


def _pve_block():
    return {"plane": "pve", "source": "memory", "verdict": "found",
            "paths": ["GET /nodes/pve1/lxc/105/status/current"],
            "matches": [{"plane": "pve", "kind": "lxc", "id": "105"}]}


def _floor_bytes(blocks):
    return _size(mcp._shape(FOUND, recalled=blocks))[0]


def test_a_block_over_the_cap_at_its_floor_goes_whole():
    """(a) The live shape under a cap smaller than its floor: no partial PBS block, within the cap,
    and the answer memory-off gives."""
    cap = rawdoor.Cap(_floor_bytes([_group_block()]) - 40, None)
    assert _within(mcp._shape(FOUND, cap=cap)), "the control: the addresses alone fit this cap"
    out = mcp._shape(FOUND, cap=cap, recalled=[_group_block()])
    assert "memory" not in out and _within(out, cap)
    assert out == mcp._shape(FOUND, cap=cap)


def test_only_the_block_too_big_at_its_floor_goes():
    """(b) PVE fits, PBS's floor does not: PVE stays, PBS goes whole, the answer is within the cap."""
    big = _group_block(4)
    cap = rawdoor.Cap(_floor_bytes([_pve_block()]) + 60, None)
    assert _floor_bytes([_pve_block(), big]) > cap.bytes, "the PBS floor must not fit beside PVE"
    out = mcp._shape(FOUND, cap=cap, recalled=[_pve_block(), big])
    assert [b["plane"] for b in out["memory"]] == ["pve"] and _within(out, cap)
    assert out["memory"][0]["paths"] == ["GET /nodes/pve1/lxc/105/status/current"]


def test_an_answer_that_fits_keeps_its_blocks():
    """(c) The control: a cap the whole answer fits keeps both blocks, nothing cut."""
    blocks = [_pve_block(), _group_block(4)]
    cap = rawdoor.Cap(_floor_bytes(blocks) + 16, None)
    out = mcp._shape(FOUND, cap=cap, recalled=blocks)
    assert [b["plane"] for b in out["memory"]] == ["pve", "pbs"] and _within(out, cap)
    assert len(out["memory"][1]["matches"]) == 4 and "truncated" not in out


# --- PDM: every match names its remote, and every path carries it ----------------------------------

def test_the_pdm_plane_answers_a_vmid_with_one_block_whose_matches_name_their_remotes(pdm_box, pdm_vendor):
    _feed_pdm()
    [block] = mcp.find("105", plane="pdm")["memory"]
    assert block["plane"] == "pdm" and block["verdict"] == "found"
    assert [(m["plane"], m["kind"], m["id"], m["remote"]) for m in block["matches"]] == [
        ("pdm", "qemu", "105", "alpha"), ("pdm", "lxc", "105", "beta")]
    assert block["paths"] == ["GET /pve/remotes/alpha/qemu/105/status", "GET /pve/remotes/beta/lxc/105/status"]
    assert all("paths" not in m for m in block["matches"])          # the block's paths carry them, in rank order


def test_the_pdm_plane_answers_the_vendors_one_string_id_with_that_one_thing(pdm_box, pdm_vendor):
    _feed_pdm()
    [block] = mcp.find("remote/beta/guest/105", plane="pdm")["memory"]
    assert [(m["kind"], m["id"], m["remote"]) for m in block["matches"]] == [("lxc", "105", "beta")]
    assert block["paths"] == ["GET /pve/remotes/beta/lxc/105/status"]


@pytest.mark.parametrize("words", ["106", "remote/alpha/guest/10", "remote/gamma/guest/105",
                                   "qemu remote/beta/guest/105", "remote/alpha/guest/105/", "Web", "we"])
def test_a_word_not_in_pdm_memory_adds_no_block_and_no_recall_row(pdm_box, pdm_vendor, words):
    _feed_pdm()
    assert mcp.find("105", plane="pdm")["memory"]                   # the control: the box's own word answers
    n = len(_recalls())
    assert "memory" not in mcp.find(words, plane="pdm")
    assert len(_recalls()) == n


def test_every_path_in_a_pdm_block_is_a_published_read(pdm_box, pdm_vendor):
    _feed_pdm()
    for words in ("105", "web", "n1", "local", "localhost", "alpha", "remote/alpha/storage/n1/local"):
        [block] = mcp.find(words, plane="pdm")["memory"]
        for p in block["paths"]:
            method, path = p.split(" ", 1)
            assert method == "GET" and "{" not in path and engine.resolve("pdm", "GET", path).access == "read", p


def test_with_every_box_each_plane_is_asked_in_the_products_order_and_blocks_follow_it(
        box, vendor, pbs_box, pbs_vendor, pmg_box, pdm_box, pdm_vendor, monkeypatch):
    _feed()                                                           # guest 105 on pve
    _feed_pbs()                                                       # group vm/105 on pbs
    _feed_pdm()                                                       # 105 on two PDM remotes
    asked = []
    real = memory.resolve
    monkeypatch.setattr(memory, "resolve", lambda w, plane, **k: asked.append(plane) or real(w, plane=plane, **k))
    blocks = mcp.find("105")["memory"]
    assert asked == list(apitree.PRODUCTS) == ["pve", "pbs", "pmg", "pdm"]
    assert [b["plane"] for b in blocks] == ["pve", "pbs", "pdm"]       # pmg holds no 105: no block
    whole = mcp._recall("105", None)                                  # before the door's cap sheds descriptions
    assert whole and [b["plane"] for b in whole] == ["pve", "pbs", "pdm"]
    assert all(m["plane"] == b["plane"] for b in whole for m in b["matches"])


def test_with_pbs_pmg_and_pdm_boxes_and_no_pve_box_pve_is_never_asked(pbs_box, pbs_vendor, pmg_box, pdm_box,
                                                                      pdm_vendor, monkeypatch):
    monkeypatch.delenv("PROXIMO_API_BASE_URL", raising=False)
    _feed_pbs()
    _feed_pdm()
    asked = []
    real = memory.resolve
    monkeypatch.setattr(memory, "resolve", lambda w, plane, **k: asked.append(plane) or real(w, plane=plane, **k))
    blocks = mcp.find("105")["memory"]
    assert asked == ["pbs", "pmg", "pdm"]
    assert [b["plane"] for b in blocks] == ["pbs", "pdm"]


def test_without_a_pdm_box_pdm_is_never_asked(box, vendor, pbs_box, pbs_vendor, pmg_box, monkeypatch):
    """The control for the two above: PDM's base URL unset, the same find never asks PDM."""
    monkeypatch.delenv("PROXIMO_PDM_BASE_URL", raising=False)
    asked = []
    real = memory.resolve
    monkeypatch.setattr(memory, "resolve", lambda w, plane, **k: asked.append(plane) or real(w, plane=plane, **k))
    mcp.find("105")
    assert asked == ["pve", "pbs", "pmg"]


@pytest.mark.parametrize("broken", ["pve", "pbs", "pdm"])
def test_one_planes_failure_drops_only_its_block_pdm_among_them(box, vendor, pbs_box, pbs_vendor, pdm_box,
                                                                 pdm_vendor, monkeypatch, broken):
    _feed()
    _feed_pbs()
    _feed_pdm()
    assert [b["plane"] for b in mcp.find("105")["memory"]] == ["pve", "pbs", "pdm"]    # the control
    real = memory.resolve

    def flaky(w, plane, **k):
        if plane == broken:
            raise sqlite3.OperationalError("disk I/O error")
        return real(w, plane=plane, **k)
    monkeypatch.setattr(memory, "resolve", flaky)
    assert [b["plane"] for b in mcp.find("105")["memory"]] == [p for p in ("pve", "pbs", "pdm") if p != broken]


def _many_remotes(n=6):
    """`n` PVE remotes, each with a guest 105: one find of 105 on pdm answers `n` matches, each its own remote."""
    names = [f"r{i}" for i in range(n)]
    bodies = {**PDM, "/remotes/remote": [{"id": r, "type": "pve", "nodes": [f"{r}.example.invalid"]} for r in names]}
    for r in names:
        bodies[f"/pve/remotes/{r}/resources"] = [
            {"id": f"remote/{r}/guest/105", "type": "qemu", "vmid": 105, "name": f"guest-of-{r}" * 3, "node": "n1",
             "status": "running"}]
    return names, bodies


@pytest.mark.parametrize("fence", ["0", "1"])
def test_a_capped_pdm_block_sheds_whole_matches_and_never_a_path_without_its_remote(pdm_box, monkeypatch, fence):
    """Every match names its remote and every path carries it (`/pve/remotes/<remote>/...`). Under every cap
    the block sheds whole matches (each one served is one memory gave, its remote with it), and every
    path it still hands out is one memory gave, naming a remote memory gave."""
    names, bodies = _many_remotes()
    _pdm_vendor(monkeypatch, bodies)
    _feed_pdm(("/remotes/remote", *(f"/pve/remotes/{r}/resources" for r in names)))
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", fence)
    whole = mcp._recall("105", "pdm")
    assert whole and [b["plane"] for b in whole] == ["pdm"]
    full_paths = whole[0]["paths"]
    assert len(full_paths) >= 2 and all(any(f"/pve/remotes/{r}/" in p for r in names) for p in full_paths)
    full_matches = whole[0]["matches"] if isinstance(whole[0]["matches"], list) else None
    if fence == "0":
        assert full_matches and all(m["remote"] in names for m in full_matches)
        served_full = [{k: v for k, v in m.items() if k != "paths"} for m in full_matches]
    found = {"matches": []}
    full = len(json.dumps(mcp._shape(found, recalled=mcp._recall("105", "pdm")), separators=(",", ":")))
    cut_matches = cut_paths = False
    for n in range(full, 63, -8):
        out = mcp._shape(found, cap=rawdoor.Cap(n, None), recalled=mcp._recall("105", "pdm"))
        assert _within(out, rawdoor.Cap(n, None)), n
        if "memory" not in out:                                       # dropped whole
            assert out == mcp._shape(found, cap=rawdoor.Cap(n, None)), n
            continue
        [block] = out["memory"]
        paths = block["paths"]
        assert paths and set(paths) <= set(full_paths) and len(paths) == len(set(paths)), (n, paths)
        assert paths == full_paths[:len(paths)], (n, paths)                   # from the end, rank order kept
        if fence == "0" and isinstance(block.get("matches"), list):
            assert all(m in served_full for m in block["matches"]), n         # each match whole, its remote with it
            cut_matches = cut_matches or len(block["matches"]) < len(served_full)
        cut_paths = cut_paths or len(paths) < len(full_paths)
    assert cut_paths and (cut_matches or fence == "1"), "the sweep never cut the block: the test looked at nothing"
