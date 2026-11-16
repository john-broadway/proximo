"""PDM's shape for the estate memory (core/memory_pdm.py): the remotes, and per remote its guests (qemu,
lxc), nodes and storages, a PBS remote's datastores and nodes, and PDM's own views, kept in the vendor's
own words and answered by the vendor's own ids. Field names are the ones a live PDM 1.1 answered
(`id`, `type`, `nodes`, `authid`, `remote`, `resources`, `error`, `vmid`, `name`, `node`, `storage`,
`status`, `include-all`); every value here is invented and the box is unreachable by construction.

What the live box showed, which these tests hold:
- a remote that does not answer is a 400 on its own lists (nothing to feed) and an `error` group in the
  combined list (never its rows);
- the remotes list, the combined list and the views list FILTER by the token's privileges; the
  per-remote lists were seen whole or refused, never filtered, and own only with whole sight anyway;
- the vendor spells a one-string id for a guest, node, storage and datastore (`remote/<r>/guest/<vmid>`),
  and that exact string answers `where` beside the vmid and the name;
- `/access/permissions` writes the propagate bit as a bool, as PVE does.
"""
from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass

import pytest

from proximo.core import apitree, arm, engine, memory, memory_pdm, wire
from proximo.core.doors import cli

BOX = "https://unreachable.invalid:8443/api2/json"
TOKEN_A, TOKEN_B = "invented@pdm!wide", "invented@pdm!other"
SECRET_A, SECRET_B = "PLANTED-SECRET-AAAA-0000", "PLANTED-SECRET-BBBB-1111"
WHOLE = {"Access.Audit": True, "Resource.Audit": True, "System.Audit": True}


def _gid(remote: str, *rest: str) -> str:
    return "/".join(("remote", remote, *rest))


ALPHA = [
    {"id": _gid("alpha", "guest", "105"), "type": "qemu", "vmid": 105, "name": "web", "node": "n1",
     "status": "running", "pool": "", "template": False},
    {"id": _gid("alpha", "node", "n1"), "type": "node", "node": "n1", "status": "online", "level": ""},
    {"id": _gid("alpha", "storage", "n1", "local"), "type": "storage", "storage": "local", "node": "n1",
     "status": "available", "shared": False},
]
BETA = [
    {"id": _gid("beta", "guest", "105"), "type": "lxc", "vmid": 105, "name": "db", "node": "m1",
     "status": "stopped", "pool": "", "template": False},
    {"id": _gid("beta", "node", "m1"), "type": "node", "node": "m1", "status": "online", "level": ""},
]
GAMMA = [
    {"id": _gid("gamma", "node", "localhost"), "type": "pbs-node", "name": "localhost"},
    {"id": _gid("gamma", "datastore", "tank"), "type": "pbs-datastore", "name": "tank"},
]


#: A row the live combined list carried and this shape does not keep (an SDN zone, `pve-network`).
NETWORK = {"id": _gid("alpha", "network", "n1", "zone", "z1"), "type": "pve-network", "network": "z1",
           "network_type": "zone", "node": "n1", "status": "available"}


def _combined(rows):
    """A per-remote row as the combined list spells it: the type word carries the remote's product."""
    return [{**r, "type": r["type"] if r["type"].startswith("pbs-") else f"pve-{r['type']}"} for r in rows]


PDM = {
    "/remotes/remote": [
        {"authid": "invented@pam!pdm", "id": "alpha", "type": "pve",
         "nodes": ["alpha.example.invalid,fingerprint=AA:BB:CC"]},
        {"authid": "invented@pam!pdm", "id": "beta", "type": "pve", "nodes": ["beta.example.invalid"]},
        {"authid": "invented@pam!pdm", "id": "gamma", "type": "pbs",
         "nodes": ["gamma.example.invalid,fingerprint=DD:EE:FF"]},
    ],
    "/pve/remotes/alpha/resources": ALPHA,
    "/pve/remotes/beta/resources": BETA,
    "/pbs/remotes/gamma/datastore": [{"name": "tank", "path": "/datastore/tank"}],      # the live row's shape
    "/resources/list": [{"remote": "alpha", "resources": [*_combined(ALPHA), NETWORK]},
                        {"remote": "beta", "resources": _combined(BETA)},
                        {"remote": "gamma", "resources": GAMMA}],
    "/config/views": [{"id": "ops", "include-all": True}],
    "/access/permissions": {"/": WHOLE, "/access": WHOLE, "/resource": WHOLE, "/system": WHOLE},
}


class _Wire:
    """The vendor, by path. A path it does not hold answers a failure, as a remote that does not answer
    does on its own lists (the live box: a 400)."""

    def __init__(self, bodies):
        self.bodies, self.calls = json.loads(json.dumps(bodies)), []

    def call(self, method, path, params=None):
        self.calls.append(path)
        if path not in self.bodies:
            raise RuntimeError(f"vendor down for {path}")
        return self.bodies[path]


@dataclass(frozen=True)
class _Cfg(wire.Plane):
    audit_log_path: str = ""
    audit_key_path: str | None = None


def _serve(cfg, token_id, secret):
    """Swap the served token behind the one box URL, as arm and disarm do."""
    with open(cfg.token_path, "w") as f:
        f.write(f"{token_id}:{secret}\n")


@pytest.fixture
def cfg(tmp_path):
    token = tmp_path / "pdm.served"
    token.write_text(f"{TOKEN_A}:{SECRET_A}\n")
    token.chmod(0o600)
    return _Cfg("pdm", BOX, str(token), audit_log_path=str(tmp_path / "audit.log"))


@pytest.fixture(autouse=True)
def _closed():
    """No learn pass is open when a test starts, and none outlives it (`_see` opens one)."""
    var = getattr(memory_pdm, "_OPEN", None)
    tok = var.set(None) if var is not None else None
    yield
    if var is not None and tok is not None:
        var.reset(tok)


@pytest.fixture
def vendor(monkeypatch):
    w = _Wire(PDM)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    return w


def _remote(vendor, remote, rows):
    """A PVE remote now lists `rows` in its own resources read and in its group in the combined list."""
    vendor.bodies[f"/pve/remotes/{remote}/resources"] = rows
    vendor.bodies["/resources/list"] = [{"remote": remote, "resources": _combined(rows)} if g["remote"] == remote
                                        else g for g in vendor.bodies["/resources/list"]]


def _read(cfg, path, args=None, **kw):
    return engine.execute(engine.resolve("pdm", "GET", path), dict(args or {}), cfg=cfg, ledger_cfg=cfg,
                          path=path, **kw)


def _learn(cfg):
    return memory.learn("pdm", cfg=cfg, ledger_cfg=cfg)


def _where(cfg, words, **kw):
    return memory.where(cfg.audit_log_path, "pdm", BOX, words, **kw)


def _db(cfg):
    return sqlite3.connect(memory.path(cfg.audit_log_path))


def _held(cfg) -> bytes:
    """Every byte the memory file and its sidecars hold."""
    p = memory.path(cfg.audit_log_path)
    return b"".join(open(f, "rb").read() for f in (p, p + "-wal", p + "-shm", p + "-journal") if os.path.exists(f))


def _status(cfg, words, remote=None):
    [m] = [m for m in _where(cfg, words)["matches"] if remote is None or m.get("remote") == remote]
    return m["status"]


def _see(cfg, who=None):
    """The state INSIDE a learn by a token that sees every remote and view, after its permission map: both
    sights, for the served token, and the learn's pass open, so the reads that follow own (the remotes
    and views lists only while a pass is open; `_closed` closes it after each test). The id is the
    production reader's, never spelled here. A between-learn test never calls this."""
    memory_pdm._OPEN.set(BOX)                                  # a learn pass is open (closed after each test)
    db = memory._open(cfg.audit_log_path, create=True)
    assert db is not None
    with db:
        for k in ("resource_sight", "view_sight"):
            memory._set(db, "pdm", BOX, k, f"whole:{who or arm.served_id(cfg)}")
    memory._settle(cfg.audit_log_path)


def _learn_sight(cfg):
    with _db(cfg) as db:
        return db.execute("SELECT v FROM meta WHERE plane='pdm' AND k='learn_sight'").fetchone()[0]


# --- the seam -------------------------------------------------------------------------------------

def test_pdm_is_registered_with_its_own_feeds():
    s = memory.shape("pdm")
    assert s is memory_pdm.SHAPE and memory.SHAPES["pdm"] is memory_pdm.SHAPE
    assert memory.feeds("pdm") == memory_pdm.FEEDS == frozenset(
        {"/remotes/remote", "/resources/list", "/pve/remotes/{remote}/resources", "/pbs/remotes/{remote}/datastore",
         "/config/views"})
    assert (s.answers_uses, s.relating_owners, s.token_sight) == (False, frozenset({"remotes"}), True)
    assert (s.no_ident_kinds, s.no_name_kinds, s.id_names) == (frozenset(), frozenset(), frozenset())
    assert s.global_ids == frozenset({"node", "qemu", "lxc", "storage", "datastore"})
    assert s.next_live == ("GET /remotes/remote",) and s.whole_owner == "remotes"


def test_every_kind_is_a_vendor_word_in_this_shapes_order():
    assert memory_pdm.KIND_ORDER == ("remote", "node", "qemu", "lxc", "storage", "datastore", "view")
    assert memory_pdm.VENDOR_KINDS == frozenset(memory_pdm.KIND_ORDER)


def test_uses_refuses_on_pdm(cfg, vendor):
    _learn(cfg)
    with pytest.raises(memory.Unusable, match="relates nothing on pdm"):
        memory.uses(cfg.audit_log_path, "pdm", BOX, "local")


def test_a_miss_points_at_the_remotes_list(cfg, vendor):
    _read(cfg, "/config/views")
    assert _where(cfg, "nothing-here")["next"] == ["GET /remotes/remote"]
    assert memory.where(cfg.audit_log_path, "pdm", "https://never.invalid:8443/api2/json", "x")["next"] == \
        ["GET /remotes/remote"]                                   # an empty memory too


def test_changed_begins_at_the_remotes_list(cfg, vendor):
    _see(cfg)
    _read(cfg, "/config/views")                                   # fed and owned, but not the remotes list
    out = memory.changed(cfg.audit_log_path, "pdm", BOX, "1h")
    assert out["began"] is None and "no_whole_read" in out["codes"]
    _read(cfg, "/remotes/remote")
    out = memory.changed(cfg.audit_log_path, "pdm", BOX, "1h")
    assert out["began"] is not None and "no_whole_read" not in out["codes"]


# --- each kind, fed and found by its vendor id, alone and after its type word ----------------------

KINDS = [
    # (words alone, kind, remote, id, its read)
    ("alpha", "remote", None, "alpha", ["GET /remotes/remote/alpha/config"]),
    ("n1", "node", "alpha", "n1", ["GET /pve/remotes/alpha/nodes/n1/status"]),
    ("localhost", "node", "gamma", "localhost", ["GET /pbs/remotes/gamma/status"]),
    ("web", "qemu", "alpha", "105", ["GET /pve/remotes/alpha/qemu/105/status"]),
    ("db", "lxc", "beta", "105", ["GET /pve/remotes/beta/lxc/105/status"]),
    ("local", "storage", "alpha", "local", ["GET /pve/remotes/alpha/nodes/n1/storage/local/status"]),
    ("tank", "datastore", "gamma", "tank", ["GET /pbs/remotes/gamma/datastore"]),
    ("ops", "view", None, "ops", ["GET /config/views/ops"]),
]


@pytest.mark.parametrize("words,kind,remote,vid,paths", KINDS, ids=[k for _, k, _, _, _ in KINDS])
def test_each_kind_is_fed_and_found_by_its_vendor_id(cfg, vendor, words, kind, remote, vid, paths):
    assert _learn(cfg)["complete"] is True
    for asked in (words, f"{kind} {words}", vid, f"{kind} {vid}"):
        out = _where(cfg, asked)
        assert out["verdict"] == "found", asked
        [m] = [m for m in out["matches"] if m["kind"] == kind and m.get("remote") == remote]
        assert (m["id"], m["paths"]) == (vid, paths), asked
        assert ("remote" in m) is (remote is not None)


def test_every_path_handed_out_is_published():
    for *_, paths in KINDS:
        for p in paths:
            assert memory._published("pdm", p.removeprefix("GET ")), p


def test_a_guest_hands_out_its_status_read_only(cfg, vendor):
    """The guest's config read needs the vendor's required `state` argument: a bare path would be
    refused, so it is never handed out."""
    _learn(cfg)
    [m] = _where(cfg, "qemu web")["matches"]
    assert m["paths"] == ["GET /pve/remotes/alpha/qemu/105/status"]
    assert all("/config" not in p for p in m["paths"])


def test_a_type_word_of_another_kind_finds_nothing(cfg, vendor):
    _learn(cfg)
    assert _where(cfg, "lxc web")["verdict"] == "not_in_memory"
    assert _where(cfg, "guest 105")["verdict"] == "not_in_memory"         # `guest` is no type word here
    assert _where(cfg, "Web")["verdict"] == "not_in_memory"               # case is the vendor's
    assert _where(cfg, "we")["verdict"] == "not_in_memory"                # no prefix


# --- Review Focus 4: the same id on two remotes and two kinds; the vendor's one-string id ----------

def test_a_guest_answers_to_its_vmid_its_name_and_its_global_id(cfg, vendor):                       # RF4
    _learn(cfg)
    for words in ("105", "web", _gid("alpha", "guest", "105"), f"qemu {_gid('alpha', 'guest', '105')}"):
        found = [(m["kind"], m["remote"]) for m in _where(cfg, words)["matches"] if m["kind"] == "qemu"]
        assert found == [("qemu", "alpha")], words
    [m] = _where(cfg, _gid("alpha", "guest", "105"))["matches"]           # exactly one, never twice
    assert (m["id"], m["name"]) == ("105", "web")
    assert _where(cfg, _gid("alpha", "guest", "10"))["verdict"] == "not_in_memory"      # never a prefix
    assert _where(cfg, f"lxc {_gid('alpha', 'guest', '105')}")["verdict"] == "not_in_memory"


def test_the_same_vmid_on_two_remotes_returns_both_by_vmid_and_one_by_global_id(cfg, vendor):        # RF4
    _remote(vendor, "beta", [{**BETA[0], "type": "qemu", "name": "web"}, BETA[1]])
    _learn(cfg)
    out = _where(cfg, "qemu 105")
    assert [(m["remote"], m["paths"]) for m in out["matches"]] == [
        ("alpha", ["GET /pve/remotes/alpha/qemu/105/status"]),
        ("beta", ["GET /pve/remotes/beta/qemu/105/status"])]
    assert [m["remote"] for m in _where(cfg, "web")["matches"]] == ["alpha", "beta"]
    [m] = _where(cfg, _gid("beta", "guest", "105"))["matches"]
    assert (m["remote"], m["paths"]) == ("beta", ["GET /pve/remotes/beta/qemu/105/status"])


def test_the_same_id_as_a_qemu_and_an_lxc_comes_back_in_this_shapes_kind_order(cfg, vendor):          # RF4
    _learn(cfg)
    out = _where(cfg, "105")
    assert [(m["kind"], m["remote"]) for m in out["matches"]] == [("qemu", "alpha"), ("lxc", "beta")]
    assert [m["kind"] for m in _where(cfg, "lxc 105")["matches"]] == ["lxc"]


def test_retiring_a_guest_on_one_remote_leaves_the_same_id_on_another(cfg, vendor):                  # RF4
    _remote(vendor, "beta", [{**BETA[0], "type": "qemu"}, BETA[1]])
    assert _learn(cfg)["complete"] is True
    _remote(vendor, "alpha", ALPHA[1:])                                 # alpha's 105 is gone
    assert _learn(cfg)["complete"] is True
    assert _status(cfg, "qemu 105", "alpha") == "gone"
    assert _status(cfg, "qemu 105", "beta") == "stopped"


def test_a_node_named_like_its_remote_is_both_remote_first(cfg, vendor):
    _remote(vendor, "alpha", [
        *ALPHA, {"id": _gid("alpha", "node", "alpha"), "type": "node", "node": "alpha", "status": "online"}])
    _learn(cfg)
    assert [(m["kind"], m.get("remote")) for m in _where(cfg, "alpha")["matches"]] == [
        ("remote", None), ("node", "alpha")]


# --- Review Focus 1: a remote that does not answer ------------------------------------------------

def test_a_remote_that_does_not_answer_retires_nothing_of_it_and_learn_names_it(cfg, vendor):        # RF1
    assert _learn(cfg)["complete"] is True
    del vendor.bodies["/pve/remotes/alpha/resources"]                 # the live box: a 400
    vendor.bodies["/resources/list"] = [
        {"remote": "alpha", "error": "error connecting to https://192.0.2.1:8006/ - no route to host"},
        *PDM["/resources/list"][1:]]
    out = _learn(cfg)
    assert out["complete"] is False
    assert "GET /pve/remotes/alpha/resources failed" in out["why"]
    assert "192.0.2.1" not in out["why"]                              # the vendor's error text is never echoed
    for words in ("web", "n1", "local"):
        assert _status(cfg, words, "alpha") != "gone", words
    assert _status(cfg, "db", "beta") == "stopped"                    # the other remote still answered
    assert b"192.0.2.1" not in _held(cfg)


def test_a_remote_left_out_of_the_combined_list_is_named(cfg, vendor):                               # RF1
    vendor.bodies["/resources/list"] = PDM["/resources/list"][:2]     # gamma left out
    out = _learn(cfg)
    assert out["complete"] is False and "remote gamma did not answer" in out["why"]


def test_an_error_group_in_the_combined_list_feeds_nothing_of_that_remote(cfg, vendor):              # RF1
    _read(cfg, "/remotes/remote")                                       # a combined group feeds a remote memory holds
    _read(cfg, "/resources/list")
    vendor.bodies["/resources/list"] = [{"remote": "gamma", "error": "down", "resources": GAMMA[:1]}]
    with _db(cfg) as db:
        before = db.execute("SELECT last_seen FROM entity WHERE plane='pdm' AND kind='node' AND key=?",
                            (_gid("gamma", "node", "localhost"),)).fetchone()
    assert before is not None                                         # the control: the first read fed it
    _read(cfg, "/resources/list")
    with _db(cfg) as db:
        after = db.execute("SELECT last_seen FROM entity WHERE plane='pdm' AND kind='node' AND key=?",
                           (_gid("gamma", "node", "localhost"),)).fetchone()
    assert before == after                                            # an error group refreshes nothing


def test_the_combined_list_never_retires_even_with_whole_sight(cfg, vendor):
    _see(cfg)
    _read(cfg, "/remotes/remote")                                       # a combined group feeds a remote memory holds
    _read(cfg, "/resources/list")
    vendor.bodies["/resources/list"] = [{"remote": "gamma", "resources": []}]
    _read(cfg, "/resources/list")
    assert _status(cfg, "localhost", "gamma") != "gone"


def test_a_pbs_remotes_datastores_are_owned_by_its_own_list(cfg, vendor):                          # I3
    assert _learn(cfg)["complete"] is True
    vendor.bodies["/pbs/remotes/gamma/datastore"] = [{"name": "cold", "path": "/datastore/cold"}]
    assert _learn(cfg)["complete"] is True
    assert _status(cfg, "tank", "gamma") == "gone" and _status(cfg, "cold", "gamma") is None


def test_a_datastore_list_retires_only_its_own_remotes_datastores(cfg, vendor):                     # C4
    """Two PBS remotes, each with a datastore named `tank`: one remote's list no longer listing its tank
    retires that tank only (the owner is per remote, `pbs-datastores/<remote>`)."""
    vendor.bodies["/pbs/remotes/delta/datastore"] = [{"name": "tank", "path": "/datastore/tank"}]
    _see(cfg)
    _read(cfg, "/pbs/remotes/gamma/datastore")
    _read(cfg, "/pbs/remotes/delta/datastore")
    assert _status(cfg, "tank", "gamma") is None and _status(cfg, "tank", "delta") is None   # both held
    vendor.bodies["/pbs/remotes/gamma/datastore"] = [{"name": "cold", "path": "/datastore/cold"}]
    _read(cfg, "/pbs/remotes/gamma/datastore")
    assert _status(cfg, "tank", "gamma") == "gone"
    assert _status(cfg, "tank", "delta") is None                        # another remote's tank stays


def test_a_datastore_is_keyed_exactly_as_the_combined_list_spells_its_id(cfg, vendor):               # I3
    """The key is composed from the per-remote list's `name`; it is the vendor's own id only because the
    combined list spells the same datastore so (live: byte for byte equal). Pinned on the live shapes."""
    _learn(cfg)
    with _db(cfg) as db:
        keys = [k for (k,) in db.execute("SELECT key FROM entity WHERE plane='pdm' AND kind='datastore'")]
    assert keys == [GAMMA[1]["id"]] == [memory_pdm._datastore_id("gamma", "tank")]
    [m] = _where(cfg, GAMMA[1]["id"])["matches"]
    assert (m["kind"], m["id"], m["remote"], m["paths"]) == ("datastore", "tank", "gamma",
                                                             ["GET /pbs/remotes/gamma/datastore"])


def test_a_pbs_node_is_added_from_the_combined_list_and_retires_with_its_remote(cfg, vendor):        # I3
    """A PBS node its group no longer carries is not retired (the combined list only adds) and is still
    shown, so learn says incomplete and says how many it shows that it did not list (C1)."""
    assert _learn(cfg)["complete"] is True
    vendor.bodies["/resources/list"] = [g if g["remote"] != "gamma" else {"remote": "gamma", "resources": GAMMA[1:]}
                                        for g in PDM["/resources/list"]]
    out = _learn(cfg)
    assert out["complete"] is False
    assert "1 thing(s) memory shows present were not listed on this pass" in out["why"], out["why"]
    assert _status(cfg, "localhost", "gamma") != "gone"                 # the combined list only adds
    vendor.bodies["/remotes/remote"] = PDM["/remotes/remote"][:2]       # gamma removed from PDM
    vendor.bodies["/resources/list"] = PDM["/resources/list"][:2]       # and from the combined list
    assert _learn(cfg)["complete"] is True
    assert _status(cfg, "localhost", "gamma") == "gone" and _status(cfg, "tank", "gamma") == "gone"


def test_a_removed_pbs_remotes_node_never_comes_back_from_a_stale_combined_list(cfg, vendor):        # C3
    """The remotes list no longer lists gamma; the combined list (which may answer from PDM's cache) still
    carries gamma's group. The node the cascade retired stays gone, and learn says the pass is not whole,
    naming the group's remote."""
    assert _learn(cfg)["complete"] is True
    vendor.bodies["/remotes/remote"] = PDM["/remotes/remote"][:2]       # gamma removed from PDM
    del vendor.bodies["/pbs/remotes/gamma/datastore"]
    out = _learn(cfg)
    assert _status(cfg, "remote gamma") == "gone"
    assert _status(cfg, "localhost", "gamma") == "gone"                 # the stale group fed nothing
    assert out["complete"] is False
    assert "GET /resources/list carried remote gamma, which this pass's remotes list does not" in out["why"]


def test_a_group_for_an_unlisted_remote_memory_still_holds_is_kept_and_learn_says_so(cfg, vendor):     # C3
    """A remotes read that cannot own (a row it cannot key) retires nothing, so gamma is still held; its combined
    group then feeds its node, and learn's gap says so, never that nothing was kept."""
    assert _learn(cfg)["complete"] is True
    with _db(cfg) as db:
        (before,) = db.execute("SELECT last_seen FROM entity WHERE plane='pdm' AND kind='node' AND key=?",
                               (_gid("gamma", "node", "localhost"),)).fetchone()
    vendor.bodies["/remotes/remote"] = [*PDM["/remotes/remote"][:2], {"type": "pve"}]   # a row with no id:
    #                                                                   the remotes list cannot own, so gamma is held
    out = _learn(cfg)
    assert _status(cfg, "remote gamma") != "gone"
    with _db(cfg) as db:
        (after,) = db.execute("SELECT last_seen FROM entity WHERE plane='pdm' AND kind='node' AND key=?",
                              (_gid("gamma", "node", "localhost"),)).fetchone()
    assert after > before                                               # held, so its group fed the node
    assert out["complete"] is False
    assert ("GET /resources/list carried remote gamma, which this pass's remotes list does not: memory still "
            "holds that remote") in out["why"]
    assert "remote gamma, which this pass's remotes list does not: nothing of it was kept" not in out["why"]


@pytest.mark.parametrize("group", [{"remote": "gamma", "error": "down"},
                                   {"remote": "gamma", "resources": {"not": "a list"}}])
def test_a_group_for_an_unlisted_held_remote_that_fed_nothing_is_never_called_kept(cfg, vendor, group):   # R1
    """The held-and-unlisted case, but the group itself feeds nothing (an error group, or rows that are not a
    list): learn says nothing of it was kept, never that it was kept."""
    assert _learn(cfg)["complete"] is True
    with _db(cfg) as db:
        (before,) = db.execute("SELECT last_seen FROM entity WHERE plane='pdm' AND kind='node' AND key=?",
                               (_gid("gamma", "node", "localhost"),)).fetchone()
    vendor.bodies["/remotes/remote"] = [*PDM["/remotes/remote"][:2], {"type": "pve"}]   # a row with no id:
    #                                                                   the remotes list cannot own, so gamma is held
    vendor.bodies["/resources/list"] = [*PDM["/resources/list"][:2], group]
    out = _learn(cfg)
    assert _status(cfg, "remote gamma") != "gone"                       # held
    with _db(cfg) as db:
        (after,) = db.execute("SELECT last_seen FROM entity WHERE plane='pdm' AND kind='node' AND key=?",
                              (_gid("gamma", "node", "localhost"),)).fetchone()
    assert after == before                                              # the group fed nothing
    assert out["complete"] is False
    assert "remote gamma, which this pass's remotes list does not: nothing of it was kept" in out["why"], out
    assert "its group was kept" not in out["why"]


def test_a_group_for_a_held_remote_whose_id_no_path_may_carry_feeds_nothing(cfg, vendor):          # Ra
    """A remote whose id fails the path check is still kept by the remotes list (its id is a non-empty
    string), so it is held; its combined group still feeds nothing, which is what learn's gap says."""
    odd = "a b"
    vendor.bodies["/remotes/remote"] = [*PDM["/remotes/remote"], {"id": odd, "type": "pbs", "nodes": ["h"]}]
    vendor.bodies["/resources/list"] = [*PDM["/resources/list"], {"remote": odd, "resources": [
        {"id": f"remote/{odd}/node/localhost", "type": "pbs-node", "name": "localhost"}]}]
    out = _learn(cfg)
    with _db(cfg) as db:
        assert db.execute("SELECT gone_at FROM entity WHERE plane='pdm' AND kind='remote' AND key=?",
                          (odd,)).fetchone() == (None,)                 # held (`where` cannot take a spaced id)
        assert db.execute("SELECT count(*) FROM entity WHERE plane='pdm' AND key=?",
                          (f"remote/{odd}/node/localhost",)).fetchone() == (0,)
    assert "GET /resources/list carried a remote whose id no path may carry: nothing of it was kept" in out["why"]
    assert odd not in out["why"].replace("a remote whose id", "")


def test_a_combined_group_feeds_only_a_remote_memory_holds(cfg, vendor):                              # C3
    """Outside learn too: a combined list read before any remotes read feeds nothing; once the remotes
    list has put gamma in memory, the same read feeds gamma's node."""
    _see(cfg)
    _read(cfg, "/resources/list")
    assert _where(cfg, "localhost")["verdict"] == "not_in_memory"
    _read(cfg, "/remotes/remote")
    _read(cfg, "/resources/list")
    assert _status(cfg, "localhost", "gamma") is None                   # found: a PBS node carries no status


def test_a_combined_group_for_a_remote_no_path_may_carry_is_named_without_its_id(cfg, vendor):        # C3
    vendor.bodies["/resources/list"] = [*PDM["/resources/list"], {"remote": "a b/../x", "resources": GAMMA}]
    out = _learn(cfg)
    assert out["complete"] is False and "a b/../x" not in out["why"]
    assert "GET /resources/list carried a remote whose id no path may carry" in out["why"]


def test_the_combined_list_feeds_no_kind_a_per_remote_read_owns(cfg, vendor):                      # I1
    _read(cfg, "/remotes/remote")                                       # a combined group feeds a remote memory holds
    _read(cfg, "/resources/list")
    for words in ("web", "n1", "local", "db", "tank", "z1"):
        assert _where(cfg, words)["verdict"] == "not_in_memory", words
    assert _where(cfg, "localhost")["verdict"] == "found"               # nothing else reads a PBS node


def test_a_retired_guest_never_comes_back_from_a_stale_combined_list(cfg, vendor):                  # I1
    """The two lists DISAGREE: the per-remote read no longer lists alpha's 105, the combined list (which
    may answer from PDM's cache) still does."""
    assert _learn(cfg)["complete"] is True
    vendor.bodies["/pve/remotes/alpha/resources"] = ALPHA[1:]           # the combined list is stale
    _learn(cfg)
    assert _status(cfg, "web", "alpha") == "gone"
    vendor.bodies["/resources/list"] = [{"remote": "alpha", "resources": _combined(ALPHA[1:])},
                                        *PDM["/resources/list"][1:]]     # caught up
    _learn(cfg)
    _learn(cfg)
    assert _status(cfg, "web", "alpha") == "gone"


def test_a_removed_remote_takes_its_things_with_it(cfg, vendor):                                    # I2
    assert _learn(cfg)["complete"] is True
    vendor.bodies["/remotes/remote"] = PDM["/remotes/remote"][1:]       # alpha removed from PDM
    del vendor.bodies["/pve/remotes/alpha/resources"]
    vendor.bodies["/resources/list"] = PDM["/resources/list"][1:]
    out = _learn(cfg)
    assert out["complete"] is True, out.get("why")
    assert _status(cfg, "remote alpha") == "gone"
    for words in ("web", "n1", "local"):
        [m] = [m for m in _where(cfg, words)["matches"] if m.get("remote") == "alpha"]
        assert m["status"] == "gone" and m["paths"] == [], words
    assert _status(cfg, "db", "beta") == "stopped"                      # another remote's things stay
    gone = memory.changed(cfg.audit_log_path, "pdm", BOX, "1h")["gone"]
    assert {(g["kind"], g.get("remote")) for g in gone} >= {("remote", None), ("qemu", "alpha"), ("node", "alpha")}


def test_a_remotes_read_that_does_not_own_retires_nothing_of_a_removed_remote(cfg, vendor):         # I2
    assert _learn(cfg)["complete"] is True
    vendor.bodies["/access/permissions"] = {"/resource/beta": WHOLE}     # no whole sight
    vendor.bodies["/remotes/remote"] = PDM["/remotes/remote"][1:]
    assert _learn(cfg)["complete"] is False
    assert _status(cfg, "remote alpha") != "gone" and _status(cfg, "web", "alpha") != "gone"


def test_a_remote_back_in_the_list_brings_its_things_back_with_its_own_read(cfg, vendor):            # I2
    _learn(cfg)
    vendor.bodies["/remotes/remote"] = PDM["/remotes/remote"][1:]
    _learn(cfg)
    vendor.bodies["/remotes/remote"] = PDM["/remotes/remote"]
    assert _learn(cfg)["complete"] is True
    assert _status(cfg, "remote alpha") != "gone" and _status(cfg, "web", "alpha") == "running"


def test_an_empty_answer_retires_nothing(cfg, vendor):
    _see(cfg)
    _read(cfg, "/remotes/remote")
    _read(cfg, "/pve/remotes/alpha/resources")
    vendor.bodies["/remotes/remote"] = []
    vendor.bodies["/pve/remotes/alpha/resources"] = []
    _read(cfg, "/remotes/remote")
    _read(cfg, "/pve/remotes/alpha/resources")
    assert _status(cfg, "remote alpha") != "gone" and _status(cfg, "web", "alpha") != "gone"


# --- Review Focus 3: the token's sight ------------------------------------------------------------

def test_without_whole_sight_a_whole_read_adds_and_refreshes_only(cfg, vendor):                     # RF3
    _read(cfg, "/pve/remotes/alpha/resources")
    _read(cfg, "/remotes/remote")
    vendor.bodies["/pve/remotes/alpha/resources"] = ALPHA[1:]
    vendor.bodies["/remotes/remote"] = PDM["/remotes/remote"][1:]
    _read(cfg, "/pve/remotes/alpha/resources")
    _read(cfg, "/remotes/remote")
    assert _status(cfg, "web", "alpha") != "gone" and _status(cfg, "remote alpha") != "gone"


@pytest.mark.parametrize("template,changed,words,remote", [
    ("/pve/remotes/alpha/resources", ALPHA[1:], "web", "alpha"),
    ("/remotes/remote", PDM["/remotes/remote"][1:], "remote alpha", None),
    ("/config/views", [{"id": "other"}], "ops", None),
])
def test_with_the_same_tokens_sight_a_whole_read_owns_and_another_tokens_does_not(
        cfg, vendor, template, changed, words, remote):                                          # RF3
    _see(cfg)
    _read(cfg, template)                                               # owned: listed by its owner
    _see(cfg, who=TOKEN_B)                                             # another token's sight
    vendor.bodies[template] = changed
    _read(cfg, template)
    assert _status(cfg, words, remote) != "gone"
    _see(cfg)                                                          # the served token's own sight
    _read(cfg, template)
    assert _status(cfg, words, remote) == "gone"


@pytest.mark.parametrize("swap", [False, True])
def test_a_sight_learned_by_one_token_never_owns_for_another(cfg, vendor, monkeypatch, swap):       # RF3
    """Inside one learn: the map was read under token A, then the served token becomes B before alpha's
    own list is read. B's read owns nothing; the control (no swap) retires."""
    assert _learn(cfg)["complete"] is True
    _remote(vendor, "alpha", ALPHA[1:])
    real = vendor.call

    def call(method, path, params=None):
        out = real(method, path, params)
        if swap and path == "/remotes/remote":
            _serve(cfg, TOKEN_B, SECRET_B)
        return out
    monkeypatch.setattr(vendor, "call", call)
    _learn(cfg)
    assert (_status(cfg, "web", "alpha") == "gone") is (not swap)


@pytest.mark.parametrize("perms", [
    {"/resource/alpha": WHOLE},                                        # one remote only (the live narrow token)
    {"/resource": {**WHOLE, "Resource.Audit": False}},                 # held, not propagating (seen live)
    {"/": WHOLE, "/resource/beta": {"System.Audit": True}},            # one remote without the privilege
    {"/": WHOLE, "/view": {"System.Audit": True}},                     # every remote, no view
])
def test_a_learn_without_whole_sight_owns_nothing_and_says_partial(cfg, vendor, perms):            # RF3
    vendor.bodies["/access/permissions"] = perms
    out = _learn(cfg)
    assert out["complete"] is False and "Resource.Audit" in out["why"]
    assert _learn_sight(cfg) == "partial"
    assert "partial_sight" in memory.changed(cfg.audit_log_path, "pdm", BOX, "1h")["codes"]


def test_a_learn_with_whole_sight_owns_and_retires(cfg, vendor):                                    # RF3
    assert _learn(cfg)["complete"] is True
    assert _learn_sight(cfg) == "whole"
    _remote(vendor, "alpha", ALPHA[1:])
    vendor.bodies["/config/views"] = []
    vendor.bodies["/remotes/remote"] = PDM["/remotes/remote"][:2]
    vendor.bodies["/resources/list"] = [g for g in vendor.bodies["/resources/list"] if g["remote"] != "gamma"]
    assert _learn(cfg)["complete"] is True
    assert _status(cfg, "web", "alpha") == "gone" and _status(cfg, "ops") == "gone"
    assert _status(cfg, "remote gamma") == "gone"


def test_a_later_learn_without_sight_stops_the_retiring(cfg, vendor):
    assert _learn(cfg)["complete"] is True
    vendor.bodies["/access/permissions"] = {"/resource/alpha": WHOLE}
    _remote(vendor, "alpha", ALPHA[1:])
    assert _learn(cfg)["complete"] is False
    assert _status(cfg, "web", "alpha") != "gone"


def test_between_learns_a_plain_remotes_read_retires_nothing(cfg, vendor):                          # C3
    """Learn complete under a token that sees everything; the admin then narrows the SAME token, so PDM
    filters the remotes list down to beta. One plain read, no learn: nothing is retired and nothing
    cascades, since the remotes list (which the vendor filters by the token) owns only inside a learn."""
    assert _learn(cfg)["complete"] is True
    vendor.bodies["/access/permissions"] = {"/resource/beta": WHOLE}
    vendor.bodies["/remotes/remote"] = PDM["/remotes/remote"][1:2]
    _read(cfg, "/remotes/remote")
    for words, remote in (("remote alpha", None), ("remote gamma", None), ("web", "alpha"), ("n1", "alpha"),
                          ("tank", "gamma"), ("localhost", "gamma"), ("db", "beta"), ("ops", None)):
        assert _status(cfg, words, remote) != "gone", words
    assert memory.changed(cfg.audit_log_path, "pdm", BOX, "1h")["gone"] == []


@pytest.mark.parametrize("template,changed,words,remote", [
    ("/remotes/remote", PDM["/remotes/remote"][1:], "remote alpha", None),
    ("/config/views", [{"id": "other"}], "ops", None),
])
def test_between_learns_the_lists_the_vendor_filters_retire_nothing(cfg, vendor, template, changed, words,
                                                                    remote):                   # C3, 12b
    assert _learn(cfg)["complete"] is True
    vendor.bodies[template] = changed
    _read(cfg, template)
    assert _status(cfg, words, remote) != "gone"
    _learn(cfg)                                                         # the next learn's own read retires it
    assert _status(cfg, words, remote) == "gone"


@pytest.mark.parametrize("template,changed,words,remote", [
    ("/pve/remotes/alpha/resources", ALPHA[1:], "web", "alpha"),
    ("/pbs/remotes/gamma/datastore", [{"name": "cold", "path": "/datastore/cold"}], "tank", "gamma"),
])
def test_between_learns_a_remotes_own_list_retires_under_the_last_learns_sight(cfg, vendor, template, changed,
                                                                               words, remote):     # 12b
    """A remote's own list is never filtered within the remote (whole or a 403), so it owns between learns
    when the box's last learn read a whole map under the same token."""
    assert _learn(cfg)["complete"] is True
    vendor.bodies[template] = changed
    _read(cfg, template)
    assert _status(cfg, words, remote) == "gone"


@pytest.mark.parametrize("how", ["a-narrowed-learn", "another-token"])
def test_between_learns_a_remotes_own_list_without_this_tokens_whole_sight_adds_only(cfg, vendor, how):  # 12b
    if how == "a-narrowed-learn":
        vendor.bodies["/access/permissions"] = {"/resource/alpha": WHOLE}
        assert _learn(cfg)["complete"] is False                         # sight partial
    else:
        assert _learn(cfg)["complete"] is True
        _serve(cfg, TOKEN_B, SECRET_B)                                  # the sight is token A's
    vendor.bodies["/pve/remotes/alpha/resources"] = ALPHA[1:]
    _read(cfg, "/pve/remotes/alpha/resources")
    assert _status(cfg, "web", "alpha") != "gone"


def _sights(cfg):
    with _db(cfg) as db:
        return {k: v for k, v in db.execute("SELECT k, v FROM meta WHERE plane='pdm' AND k IN "
                                            "('resource_sight', 'view_sight')")}


def test_a_whole_learn_keeps_its_sight_for_a_remotes_own_list_and_says_whole(cfg, vendor):          # 12b
    """After a whole learn: it says complete, `changed` says no `partial_sight` (the frame's `learn_sight`),
    both sights stay raised for this token (a remote's own list owns between learns), and the pass is
    closed (a plain remotes read retires nothing)."""
    assert _learn(cfg)["complete"] is True
    _remote(vendor, "alpha", ALPHA[1:])
    out = _learn(cfg)
    assert out["complete"] is True and _status(cfg, "web", "alpha") == "gone"
    assert _learn_sight(cfg) == "whole"
    assert "partial_sight" not in memory.changed(cfg.audit_log_path, "pdm", BOX, "1h")["codes"]
    assert _sights(cfg) == {"resource_sight": f"whole:{TOKEN_A}", "view_sight": f"whole:{TOKEN_A}"}
    assert memory_pdm._OPEN.get() is None


def _remotes_read_after(cfg, vendor):
    """A plain remotes read with alpha removed: retires alpha only if a learn pass is still open."""
    vendor.bodies["/remotes/remote"] = PDM["/remotes/remote"][1:]
    _read(cfg, "/remotes/remote")
    return _status(cfg, "remote alpha")


def test_learn_closes_its_pass_when_it_stops_at_its_budget(cfg, vendor, monkeypatch):                # C3
    monkeypatch.setattr(memory, "LEARN_MAX_READS", 2)       # the map (sight raised), the remotes list
    assert _learn(cfg)["complete"] is False
    monkeypatch.setattr(memory, "LEARN_MAX_READS", 256)
    assert _remotes_read_after(cfg, vendor) != "gone"


def test_learn_closes_its_pass_when_it_dies(cfg, vendor, monkeypatch):                               # C3
    real = vendor.call

    def die(method, path, params=None):
        if path == "/pve/remotes/alpha/resources":          # after the map raised the sight and the remotes read
            raise KeyboardInterrupt
        return real(method, path, params)
    monkeypatch.setattr(vendor, "call", die)
    with pytest.raises(KeyboardInterrupt):
        _learn(cfg)
    monkeypatch.setattr(vendor, "call", real)
    assert _remotes_read_after(cfg, vendor) != "gone"


def test_inside_a_learn_a_removed_remote_takes_only_its_own_things(cfg, vendor, monkeypatch):        # I2
    """The cascade is scoped to the removed remote: a learn that stops right after the remotes read (so
    nothing re-reads beta or gamma after the cascade) leaves every other remote's things and the view."""
    assert _learn(cfg)["complete"] is True
    vendor.bodies["/remotes/remote"] = PDM["/remotes/remote"][1:]       # alpha removed from PDM
    monkeypatch.setattr(memory, "LEARN_MAX_READS", 2)                   # the map, the remotes list
    _learn(cfg)
    assert _status(cfg, "remote alpha") == "gone" and _status(cfg, "web", "alpha") == "gone"
    assert _status(cfg, "db", "beta") == "stopped" and _status(cfg, "m1", "beta") == "online"
    assert _status(cfg, "tank", "gamma") is None and _status(cfg, "localhost", "gamma") is None
    assert _status(cfg, "ops") is None                                  # a view has no remote


def test_learn_reads_the_permission_map_before_any_list(cfg, vendor):
    _learn(cfg)
    assert vendor.calls[0] == "/access/permissions" and vendor.calls[1] == "/remotes/remote"


@pytest.mark.parametrize("swap", [False, True])
def test_a_token_swapped_while_learn_reads_the_map_raises_no_sight(cfg, vendor, monkeypatch, swap):
    """The sights as they stand DURING the pass, when the first list is read: raised for the token that
    read the map (the control), never when the token changed while the map was read."""
    real = vendor.call
    during: list[dict[str, str]] = []

    def call(method, path, params=None):
        if path == "/remotes/remote":
            during.append(_sights(cfg))
        out = real(method, path, params)
        if swap and path == "/access/permissions":
            _serve(cfg, TOKEN_B, SECRET_B)
        return out
    monkeypatch.setattr(vendor, "call", call)
    out = _learn(cfg)
    if swap:
        assert out["complete"] is False and "could hold steady" in out["why"]
        assert during == [{"resource_sight": "partial", "view_sight": "partial"}]
    else:
        assert out["complete"] is True
        assert during == [{"resource_sight": f"whole:{TOKEN_A}", "view_sight": f"whole:{TOKEN_A}"}]


@pytest.mark.parametrize("template,bound,args,fields,box,evaluating,owner", [
    ("/pve/remotes/{remote}/resources", {"remote": "alpha"}, {}, None, BOX, False, "pve-resources/alpha"),
    ("/pve/remotes/{remote}/resources", {"remote": "alpha"}, {"kind": "vm"}, None, BOX, False, None),
    ("/pve/remotes/{remote}/resources", {"remote": "alpha"}, {}, "id,type", BOX, False, None),
    ("/pve/remotes/{remote}/resources", {"remote": "alpha"}, {}, None, "", False, None),
    ("/pve/remotes/{remote}/resources", {"remote": "alpha"}, {}, None, BOX, True, None),
    ("/remotes/remote", {}, {}, None, BOX, False, "remotes"),
    ("/config/views", {}, {}, None, BOX, False, "views"),
    ("/resources/list", {}, {}, None, BOX, False, None),          # the combined list never owns
])
def test_only_a_whole_read_with_sight_owns_its_list(cfg, template, bound, args, fields, box, evaluating, owner):
    _see(cfg)
    data = {"/pve/remotes/{remote}/resources": ALPHA, "/remotes/remote": PDM["/remotes/remote"],
            "/config/views": PDM["/config/views"], "/resources/list": PDM["/resources/list"]}[template]
    db = memory._open(cfg.audit_log_path, create=False)
    assert memory_pdm.SHAPE.owner(template, bound, args, fields, data, box, evaluating, db=db,
                                  who=arm.served_id(cfg)) == owner


def test_with_no_learn_no_list_owns(cfg):
    for template, bound in (("/remotes/remote", {}), ("/pve/remotes/{remote}/resources", {"remote": "alpha"}),
                            ("/config/views", {}), ("/resources/list", {})):
        assert memory_pdm.SHAPE.owner(template, bound, {}, None, [{"id": "x", "type": "qemu", "vmid": 1}],
                                      BOX, False, db=None, who=TOKEN_A) is None


# --- a list owns only when every row yields its id ------------------------------------------------

@pytest.mark.parametrize("template,body,words,remote", [
    ("/remotes/remote", [*PDM["/remotes/remote"][1:], {"type": "pve"}], "remote alpha", None),
    ("/pve/remotes/alpha/resources", [*ALPHA[1:], {"type": "qemu", "vmid": 7}], "web", "alpha"),          # no id
    ("/pve/remotes/alpha/resources", [*ALPHA[1:], {"id": _gid("alpha", "guest", "7"), "type": "qemu"}],
     "web", "alpha"),                                                                                     # no vmid
    ("/pve/remotes/alpha/resources", [*ALPHA[1:], {"id": _gid("alpha", "guest", "7"), "vmid": 7}],
     "web", "alpha"),                                                                                     # no type
    ("/pve/remotes/alpha/resources", [*ALPHA[1:], "garbled"], "web", "alpha"),
    # An id the vendor SENT, empty: the vendor's own row holds (the field is there and not null), so only
    # this shape's own need stands between the read and a retire. An id sent empty names nothing.
    ("/remotes/remote", [*PDM["/remotes/remote"][1:], {**PDM["/remotes/remote"][0], "id": ""}], "remote alpha", None),
    ("/pve/remotes/alpha/resources", [*ALPHA[1:], {**ALPHA[0], "id": ""}], "web", "alpha"),
    ("/pbs/remotes/gamma/datastore", [{"name": "", "path": "/datastore/tank"}], "tank", "gamma"),
    ("/config/views", [{"id": "", "include-all": True}], "ops", None),
    ("/config/views", [{"include-all": True}], "ops", None),
    ("/config/views", [{"id": 7}], "ops", None),                                         # no string id
    ("/pbs/remotes/gamma/datastore", [{"path": "/datastore/cold"}], "tank", "gamma"),                       # no name
])
def test_a_list_with_a_row_that_yields_no_id_owns_nothing_and_learn_names_it(cfg, vendor, template, body,
                                                                            words, remote):
    assert _learn(cfg)["complete"] is True
    vendor.bodies[template] = body
    out = _learn(cfg)
    assert out["complete"] is False
    assert f"GET {template} was read but could not own its list" in out["why"]
    assert _status(cfg, words, remote) != "gone"


def test_a_type_this_shape_does_not_keep_is_not_kept_and_learn_names_it(cfg, vendor):
    """A per-remote row of a type this shape does not keep (made up here: none was seen live in that list)
    is not kept; carrying what the vendor publishes on every row there (id, node, status), it does not stop
    the list owning what it does keep, and learn says incomplete, naming the type."""
    assert _learn(cfg)["complete"] is True
    vendor.bodies["/pve/remotes/alpha/resources"] = [
        *ALPHA[1:], {"id": _gid("alpha", "sdn", "z9"), "type": "sdn", "node": "pve1", "status": "ok"}]
    out = _learn(cfg)
    assert out["complete"] is False and "type sdn" in out["why"] and "/pve/remotes/alpha/resources" in out["why"]
    assert _status(cfg, "web", "alpha") == "gone"
    assert _where(cfg, "z9")["verdict"] == "not_in_memory"
    vendor.bodies["/pve/remotes/alpha/resources"] = [*ALPHA[1:], {"id": "x", "type": "a b\nc"}]
    assert "a type this shape does not keep" in _learn(cfg)["why"]           # never the vendor's odd word


def test_the_combined_lists_network_row_is_not_kept(cfg, vendor):
    """The live combined list carried an SDN zone (`pve-network`): not kept, and no reason to doubt a pass."""
    assert _learn(cfg)["complete"] is True
    assert _where(cfg, "z1")["verdict"] == "not_in_memory"


def test_a_global_id_longer_than_memory_keeps_is_never_kept_cut_and_learn_says_so(cfg, vendor):
    long = _gid("alpha", "guest", "1" + "0" * 130)
    _remote(vendor, "alpha", [*ALPHA, {**ALPHA[0], "id": long, "vmid": 106}])
    out = _learn(cfg)
    assert out["complete"] is False and "longer than memory keeps" in out["why"]
    with _db(cfg) as db:
        keys = [k for (k,) in db.execute("SELECT key FROM entity WHERE plane='pdm' AND kind='qemu'")]
    assert keys == [ALPHA[0]["id"]]                                      # the long one is not there at all
    assert _where(cfg, "106")["verdict"] == "not_in_memory"


# --- Review Focus 5: secrets ----------------------------------------------------------------------

PLANTED = {"token": "PLANTED-TOKEN-SECRET", "password": "PLANTED-PASSWORD",
           "fingerprint": "PLANTED-FINGERPRINT"}


def test_no_planted_secret_reaches_the_file_an_answer_or_a_recall_row(cfg, vendor):                  # RF5
    remotes = [{**r, **PLANTED, "nodes": [f"{r['id']}.example.invalid,fingerprint=PLANTED-NODE-FP"]}
               for r in PDM["/remotes/remote"]]
    _see(cfg)
    memory.feed(cfg.audit_log_path, "pdm", BOX, "/remotes/remote", {}, {}, remotes, source="pdm:test",
                untrusted=False, who=arm.served_id(cfg))      # straight to the feed: the allow-list is what holds
    answer = json.dumps(_where(cfg, "alpha")) + json.dumps(memory.changed(cfg.audit_log_path, "pdm", BOX, "1h"))
    held = _held(cfg)
    ledger = open(cfg.audit_log_path, "rb").read()
    assert b"alpha" in held and b"alpha.example.invalid" in held          # the control: the public id IS kept
    for planted in ("PLANTED", "invented@pam!pdm", "fingerprint"):
        assert planted.encode() not in held, planted
        assert planted not in answer, planted
        assert planted.encode() not in ledger, planted


def test_a_remote_keeps_its_type_and_hosts_never_its_authid(cfg, vendor):
    _read(cfg, "/remotes/remote")
    with _db(cfg) as db:
        rows = {k: json.loads(d) for k, d in db.execute(
            "SELECT key, detail FROM entity WHERE plane='pdm' AND kind='remote'")}
    assert rows == {"alpha": {"type": "pve", "hosts": ["alpha.example.invalid"]},
                    "beta": {"type": "pve", "hosts": ["beta.example.invalid"]},
                    "gamma": {"type": "pbs", "hosts": ["gamma.example.invalid"]}}


def test_learn_through_the_engine_keeps_no_secret(cfg, vendor):                                     # RF5
    vendor.bodies["/remotes/remote"] = [{**r, **PLANTED} for r in PDM["/remotes/remote"]]
    assert _learn(cfg)["complete"] is True
    held = _held(cfg)
    assert SECRET_A.encode() not in held and b"PLANTED" not in held
    assert TOKEN_A.encode() in held                                        # the token's public id, as sight


# --- a path is built only from ids a path may carry ------------------------------------------------

BAD = ["a/b", "..", "a%2fb", "a b", "a\nb", "_x"]


@pytest.mark.parametrize("bad", BAD)
def test_a_path_with_an_id_the_check_refuses_is_not_handed_out(cfg, bad):
    def row(kind, **d):
        return {"kind": kind, "key": "k", "ident": bad if kind != "storage" else "local", "node": d.pop("node", "n1"),
                "detail": json.dumps(d), "gone_at": None}
    for r in (row("qemu", remote=bad), row("node", remote=bad, on="pve"), row("storage", remote=bad),
              row("datastore", remote=bad), row("node", remote="alpha", on="pve"), row("remote"), row("view"),
              row("storage", remote="alpha", node=bad), row("qemu", remote="alpha")):
        assert memory._paths("pdm", r) == [], (r["kind"], r["detail"])


#: Ids `_ID` refuses that the published table would still serve inside a path: only the id check stops them.
SERVED_BAD = ["a%2fb", "_x", ".", "-x"]


def _row(kind, ident, node="n1", **d):
    return {"kind": kind, "key": "k", "ident": ident, "node": node, "detail": json.dumps(d), "gone_at": None}


#: (kind, a row whose one id is `bad`, the same row with a clean id, the path the clean one hands out)
ONE_ID = [
    ("storage", lambda b: _row("storage", b, remote="alpha"), lambda: _row("storage", "local", remote="alpha"),
     ["GET /pve/remotes/alpha/nodes/n1/storage/local/status"]),
    ("node", lambda b: _row("node", b, remote="alpha", on="pve"), lambda: _row("node", "n1", remote="alpha", on="pve"),
     ["GET /pve/remotes/alpha/nodes/n1/status"]),
    ("datastore", lambda b: _row("datastore", "tank", remote=b), lambda: _row("datastore", "tank", remote="gamma"),
     ["GET /pbs/remotes/gamma/datastore"]),               # its path carries its remote, not its name
    ("remote", lambda b: _row("remote", b), lambda: _row("remote", "alpha"), ["GET /remotes/remote/alpha/config"]),
    ("view", lambda b: _row("view", b), lambda: _row("view", "ops"), ["GET /config/views/ops"]),
]


@pytest.mark.parametrize("bad", SERVED_BAD)
@pytest.mark.parametrize("kind,bad_row,clean_row,clean_paths", ONE_ID, ids=[k for k, *_ in ONE_ID])
def test_an_id_the_check_refuses_hands_out_no_path_though_the_table_would_serve_it(kind, bad_row, clean_row,
                                                                                  clean_paths, bad):   # I3
    assert memory._paths("pdm", clean_row()) == clean_paths                 # the control
    assert memory._paths("pdm", bad_row(bad)) == [], (kind, bad)


def test_the_bad_ids_are_ones_the_table_would_serve():
    """Why the cases above test the id check and not the table: each bad id passes `_published`."""
    for bad in SERVED_BAD:
        assert not memory._ID.fullmatch(bad)
        for p in (f"/pve/remotes/alpha/nodes/n1/storage/{bad}/status", f"/pve/remotes/alpha/nodes/{bad}/status",
                  f"/pbs/remotes/{bad}/datastore", f"/remotes/remote/{bad}/config", f"/config/views/{bad}"):
            assert memory._published("pdm", p), p


def test_the_control_paths_are_handed_out(cfg):
    r = {"kind": "qemu", "key": "k", "ident": "105", "node": "n1", "detail": json.dumps({"remote": "alpha"}),
         "gone_at": None}
    assert memory._paths("pdm", r) == ["GET /pve/remotes/alpha/qemu/105/status"]


# --- learn honesty --------------------------------------------------------------------------------

def test_learn_reads_every_list_and_counts_the_guests(cfg, vendor):
    out = _learn(cfg)
    assert out["complete"] is True and out["guests"] == 2, out.get("why")
    assert vendor.calls == ["/access/permissions", "/remotes/remote", "/pve/remotes/alpha/resources",
                            "/pve/remotes/beta/resources", "/pbs/remotes/gamma/datastore", "/resources/list",
                            "/config/views"]
    assert _learn_sight(cfg) == "whole"


def test_learn_names_a_list_it_could_not_read(cfg, vendor):
    del vendor.bodies["/config/views"]
    out = _learn(cfg)
    assert out["complete"] is False and "/config/views" in out["why"]


def test_learn_stops_at_its_budget_and_still_tallies(cfg, vendor, monkeypatch):
    monkeypatch.setattr(memory, "LEARN_MAX_READS", 3)      # the map, the remotes, alpha's resources
    out = _learn(cfg)
    assert out["complete"] is False and "read budget" in out["why"] and out["reads"] == 3
    assert out["guests"] == 1


@pytest.mark.parametrize("how", ["an-argument", "another-token"])
def test_a_thing_a_read_that_cannot_own_brought_back_is_retired_by_its_owners_next_learn(cfg, vendor, how):  # C1
    """The owner retires 105; 105 comes back and a read that may not own (the vendor's own `kind`
    argument, or another token's read) lists it; 105 leaves again. The revival opened the owner's
    dropped sighting, so the owner's next whole read (the learn's) drops it again: 105 is gone, and
    learn says complete, twice."""
    assert _learn(cfg)["complete"] is True
    _remote(vendor, "alpha", ALPHA[1:])
    assert _learn(cfg)["complete"] is True
    assert _status(cfg, "web", "alpha") == "gone"                       # the owner retired it
    _remote(vendor, "alpha", ALPHA)
    if how == "another-token":
        _serve(cfg, TOKEN_B, SECRET_B)
    _read(cfg, "/pve/remotes/alpha/resources", {"kind": "vm"} if how == "an-argument" else {})
    _serve(cfg, TOKEN_A, SECRET_A)                                      # a read that could not own, then A again
    assert _status(cfg, "web", "alpha") == "running"
    _remote(vendor, "alpha", ALPHA[1:])                                 # gone at the vendor again
    for _ in range(2):
        out = _learn(cfg)
        assert out["complete"] is True, out.get("why")
    [m] = [m for m in _where(cfg, "web")["matches"] if m["remote"] == "alpha"]
    assert (m["status"], m["paths"]) == ("gone", [])


def test_a_guest_seen_again_between_learns_then_removed_again_retires(cfg, vendor):                # 12b
    """The ordinary lifecycle is not stuck: the owner retired 105, a plain read of alpha's own list by the
    same token sees it again (and owns, under the last learn's sight), 105 is removed again: the next
    owning read retires it, and learn says complete."""
    assert _learn(cfg)["complete"] is True
    _remote(vendor, "alpha", ALPHA[1:])
    assert _learn(cfg)["complete"] is True
    _remote(vendor, "alpha", ALPHA)
    _read(cfg, "/pve/remotes/alpha/resources")
    assert _status(cfg, "web", "alpha") == "running"
    _remote(vendor, "alpha", ALPHA[1:])
    out = _learn(cfg)
    assert out["complete"] is True, out.get("why")
    assert _status(cfg, "web", "alpha") == "gone"


def test_the_unseen_count_is_shown_however_many_gaps_come_before_it(cfg, vendor):                   # 12b
    """`why` shows three gaps; the count of things shown and not listed is always among them."""
    assert _learn(cfg)["complete"] is True
    for path in ("/pve/remotes/beta/resources", "/pbs/remotes/gamma/datastore", "/config/views"):
        del vendor.bodies[path]                                         # three failed reads first
    out = _learn(cfg)
    assert "(+" in out["why"]                                           # more than three gaps
    assert "thing(s) memory shows present were not listed on this pass" in out["why"], out["why"]


def test_a_whole_learn_lists_everything_it_shows_present(cfg, vendor):                              # C1
    """The control: a pass that lists everything says complete, twice."""
    assert _learn(cfg)["complete"] is True
    assert _learn(cfg)["complete"] is True


def test_a_remote_id_that_returns_as_another_product_is_named(cfg, vendor):                         # C2
    """Remote alpha (PVE) is replaced by a PBS remote with the same id. Its PVE things are no longer read by
    anything: learn names the remote and says how many, and says incomplete. They stay shown (the limit)."""
    assert _learn(cfg)["complete"] is True
    vendor.bodies["/remotes/remote"] = [{**PDM["/remotes/remote"][0], "type": "pbs"}, *PDM["/remotes/remote"][1:]]
    vendor.bodies["/pbs/remotes/alpha/datastore"] = [{"name": "x", "path": "/datastore/x"}]
    del vendor.bodies["/pve/remotes/alpha/resources"]
    vendor.bodies["/resources/list"] = [
        {"remote": "alpha", "resources": [{"id": _gid("alpha", "node", "localhost"), "type": "pbs-node",
                                           "name": "localhost"}]}, *PDM["/resources/list"][1:]]
    calls = len(vendor.calls)
    out = _learn(cfg)
    assert out["complete"] is False
    assert ("remote alpha is listed as pbs now, and memory still shows 3 thing(s) it kept of it as pve: "
            "this pass did not read them") in out["why"], out["why"]
    assert "/pve/remotes/alpha/resources" not in vendor.calls[calls:]
    for words in ("web", "n1", "local"):
        assert _status(cfg, words, "alpha") != "gone", words


@pytest.mark.parametrize("typ,said", [
    (None, "remote alpha names no type this shape reads (pve or pbs): its resources were not read"),
    (7, "remote alpha names no type this shape reads (pve or pbs): its resources were not read"),
    ("pmg", "remote alpha is of type pmg, which this shape does not read: its resources were not read"),
    ("A b", "remote alpha is of a type this shape does not read: its resources were not read"),
])
def test_a_remote_with_no_type_or_one_this_shape_does_not_read_is_named(cfg, vendor, typ, said):  # C2
    assert _learn(cfg)["complete"] is True
    row = {k: v for k, v in PDM["/remotes/remote"][0].items() if k != "type"}
    if typ is not None:
        row["type"] = typ
    vendor.bodies["/remotes/remote"] = [row, *PDM["/remotes/remote"][1:]]
    _remote(vendor, "alpha", ALPHA[1:])                                 # 105 gone at the vendor
    calls = len(vendor.calls)
    out = _learn(cfg)
    assert out["complete"] is False and said in out["why"], out["why"]
    assert "/pve/remotes/alpha/resources" not in vendor.calls[calls:]
    assert _status(cfg, "web", "alpha") == "running"                    # not read, so not retired


def test_a_remote_whose_id_no_path_may_carry_and_whose_type_is_not_read_is_named_without_its_id(cfg, vendor):
    vendor.bodies["/remotes/remote"] = [*PDM["/remotes/remote"], {"id": "a b", "type": "pmg"}]
    out = _learn(cfg)
    assert out["complete"] is False
    assert "a remote is of type pmg, which this shape does not read" in out["why"], out["why"]
    assert "a b" not in out["why"]


def test_learn_with_a_token_that_names_no_id_is_not_complete(cfg, vendor):
    _serve(cfg, "no-realm", SECRET_A)
    out = _learn(cfg)
    assert out["complete"] is False and "names no id" in out["why"]


def test_a_remote_id_no_path_may_carry_is_named_and_not_read(cfg, vendor):
    vendor.bodies["/remotes/remote"] = [*PDM["/remotes/remote"], {"id": "a b", "type": "pve"}]
    out = _learn(cfg)
    assert out["complete"] is False and "not one a path may carry" in out["why"]


# --- one file, four planes ------------------------------------------------------------------------

def test_pdm_rows_never_answer_another_plane(cfg, vendor):
    _learn(cfg)
    for plane in ("pve", "pbs", "pmg"):
        assert memory.where(cfg.audit_log_path, plane, BOX, "web")["verdict"] == "not_in_memory"


# --- the shell door -------------------------------------------------------------------------------

@pytest.fixture
def pdm_env(cfg, monkeypatch):
    monkeypatch.setenv("PROXIMO_PDM_BASE_URL", BOX)
    monkeypatch.setenv("PROXIMO_PDM_TOKEN_PATH", cfg.token_path)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", cfg.audit_log_path)
    return cfg


def test_the_shell_learns_and_finds_on_pdm(capsys, pdm_env, vendor):
    assert cli.main(["learn", "--plane", "pdm"]) == cli.EXIT_OK
    learned = json.loads(capsys.readouterr().out)
    assert learned["complete"] is True and learned["guests"] == 2, learned.get("why")
    assert cli.main(["where", "--plane", "pdm", "105"]) == cli.EXIT_OK
    assert [(m["kind"], m["remote"]) for m in json.loads(capsys.readouterr().out)["matches"]] == [
        ("qemu", "alpha"), ("lxc", "beta")]
    assert cli.main(["changed", "--plane", "pdm", "1h"]) == cli.EXIT_OK
    changed = json.loads(capsys.readouterr().out)
    assert changed["began"] is not None and "no_whole_read" not in changed["codes"]
    assert cli.main(["where", "--plane", "pdm", "nowhere-on-the-box"]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["verdict"] == "not_in_memory"


def test_uses_on_pdm_exits_3_and_says_why(capsys, pdm_env):
    assert cli.main(["uses", "--plane", "pdm", "x"]) == cli.EXIT_USAGE
    assert "relates nothing on pdm" in capsys.readouterr().err


def _help(capsys, verb):
    assert cli.main([verb, "--help"]) == cli.EXIT_OK
    return " ".join(capsys.readouterr().out.split())


@pytest.mark.parametrize("verb", cli.MEMORY_VERBS)
def test_the_plane_help_names_pdm(capsys, verb):
    out = _help(capsys, verb)
    plane_help = out.rsplit("--plane PLANE", 1)[1].split("--target", 1)[0]
    assert "pdm" in plane_help.replace(",", " ").split(), out


@pytest.mark.parametrize("verb", cli.MEMORY_VERBS)
def test_the_plane_help_names_every_plane(capsys, verb):                                             # Rb
    out = _help(capsys, verb)
    words = out.rsplit("--plane PLANE", 1)[1].split("--target", 1)[0].replace(",", " ").split()
    assert [p for p in apitree.PRODUCTS if p not in words] == [], out


@pytest.mark.parametrize("plane", ["pve", "pbs", "pmg", "pdm"])
def test_the_shell_with_no_box_names_the_variable_that_plane_reads(capsys, monkeypatch, plane):     # Rc
    for v in ("PROXIMO_API_BASE_URL", "PROXIMO_PBS_BASE_URL", "PROXIMO_PMG_BASE_URL", "PROXIMO_PDM_BASE_URL"):
        monkeypatch.delenv(v, raising=False)
    assert cli.main(["where", "--plane", plane, "x"]) == cli.EXIT_USAGE
    err = capsys.readouterr().err
    var = "PROXIMO_API_BASE_URL" if plane == "pve" else f"PROXIMO_{plane.upper()}_BASE_URL"
    assert f"no box to answer for: set {var} or name a --target" in err, err
    if plane == "pve":                                                  # PVE's line, byte for byte
        assert err == "unconfigured: no box to answer for: set PROXIMO_API_BASE_URL or name a --target\n"


def test_the_where_words_help_says_the_type_words_are_each_planes_own(capsys):
    """PVE's type words are named as PVE's, never as if every plane had them (PDM's are its own)."""
    words = _help(capsys, "where").split("positional arguments: words", 1)[1].split("options:", 1)[0]
    assert "that plane's own type words" in words, words
    assert "on pve: qemu|lxc" in words, words
    assert "after qemu|lxc" not in words, words
