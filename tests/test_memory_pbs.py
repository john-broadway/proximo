"""PBS's shape for the estate memory (core/memory_pbs.py): datastores, namespaces, backup groups,
remotes and sync/verify/prune jobs, kept in the vendor's own words and answered by its own ids. Field
names are the vendor's documented ones (the PBS api-viewer schema: `store`, `name`, `ns`,
`backup-type`, `backup-id`, `last-backup`, `backup-count`, `host`, `remote`, `remote-store`, `id`).
Every value here is invented; the box is unreachable by construction.
"""
from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass

import pytest

from proximo.core import arm, engine, memory, memory_pbs, memory_pve, spine, wire
from proximo.core.doors import cli

BOX = "https://unreachable.invalid:8007/api2/json"
PVE_BOX = "https://unreachable.invalid:8006/api2/json"

PBS = {
    "/admin/datastore": [{"store": "tank", "backend-type": "filesystem", "comment": None,
                          "mount-status": "nonremovable"},
                         {"store": "cold", "backend-type": "filesystem", "mount-status": "nonremovable",
                          "maintenance": "read-only"}],
    "/config/datastore": [{"name": "tank", "path": "/invented/tank"}, {"name": "cold", "path": "/invented/cold"}],
    "/admin/datastore/tank/namespace": [{"ns": ""}, {"ns": "prod"}, {"ns": "prod/web"}],
    "/admin/datastore/cold/namespace": [{"ns": ""}],
    "/admin/datastore/tank/groups": [{"backup-type": "vm", "backup-id": "105", "last-backup": 1_700_000_000,
                                      "backup-count": 3, "files": ["index.json.blob"], "owner": "ops@pbs"}],
    "/admin/datastore/tank/groups?ns=prod": [{"backup-type": "ct", "backup-id": "200", "last-backup": 1_700_000_100,
                                              "backup-count": 1, "files": [], "owner": "ops@pbs"}],
    "/admin/datastore/tank/groups?ns=prod/web": [],
    "/admin/datastore/cold/groups": [{"backup-type": "vm", "backup-id": "105", "last-backup": 1_690_000_000,
                                      "backup-count": 9, "files": []}],
    "/config/remote": [{"name": "offsite", "host": "backup.example", "auth-id": "sync@pbs"}],
    "/config/sync": [{"id": "s-offsite", "store": "cold", "remote": "offsite", "remote-store": "far",
                      "ns": "", "schedule": "daily"}],
    "/config/verify": [{"id": "v-tank", "store": "tank", "ns": "prod"}],
    "/config/prune": [{"id": "p-cold", "store": "cold", "schedule": "daily"}],
    # PBS writes the propagate bit as a bool, where PVE writes 1 or 0
    "/access/permissions": {"/": {"Datastore.Audit": True, "Remote.Audit": True, "RemoteDatastore.Audit": True,
                                  "Sys.Audit": True}},
}

#: The served token: its public id, and a secret no file memory writes may ever hold.
TOKEN_A, TOKEN_B = "invented@pbs!wide", "invented@pbs!narrow"
SECRET_A, SECRET_B = "PLANTED-SECRET-AAAA-0000", "PLANTED-SECRET-BBBB-1111"

PVE = {
    "/cluster/resources": [
        {"id": "node/pve1", "type": "node", "node": "pve1", "status": "online"},
        {"id": "lxc/105", "type": "lxc", "vmid": 105, "node": "pve1", "name": "web", "status": "running"},
        {"id": "qemu/100", "type": "qemu", "vmid": 100, "node": "pve1", "name": "105", "status": "stopped"},
    ],
}


class _Wire:
    """The vendor, by path (and `ns`, which a groups read carries as a parameter). A path it does not
    hold answers a 500-shaped failure."""

    def __init__(self, bodies):
        self.bodies, self.calls, self.params = dict(bodies), [], []

    def call(self, method, path, params=None):
        ns = (params or {}).get("ns")
        at = f"{path}?ns={ns}" if ns else path
        self.calls.append(at)
        self.params.append((path, dict(params or {})))
        if at not in self.bodies:
            raise RuntimeError(f"vendor down for {at}")
        return self.bodies[at]


@dataclass(frozen=True)
class _Cfg(wire.Plane):
    audit_log_path: str = ""
    audit_key_path: str | None = None


@pytest.fixture
def _wires(monkeypatch):
    held: dict[str, _Wire] = {}
    monkeypatch.setattr(engine, "_client", lambda product, c=None: held[product])
    return held


def _serve(cfg, token_id, secret):
    """Swap the served token behind the one box URL, as arm and disarm do."""
    with open(cfg.token_path, "w") as f:
        f.write(f"{token_id}:{secret}\n")


@pytest.fixture
def cfg(tmp_path):
    token = tmp_path / "pbs.served"
    token.write_text(f"{TOKEN_A}:{SECRET_A}\n")
    token.chmod(0o600)
    return _Cfg("pbs", BOX, str(token), audit_log_path=str(tmp_path / "audit.log"))


@pytest.fixture
def pve_cfg(tmp_path):
    return _Cfg("pve", PVE_BOX, "/dev/null", audit_log_path=str(tmp_path / "audit.log"))


@pytest.fixture
def vendor(_wires):
    _wires["pbs"] = _Wire(PBS)
    return _wires["pbs"]


@pytest.fixture
def pve_vendor(_wires):
    _wires["pve"] = _Wire(PVE)
    return _wires["pve"]


def _read(cfg, path, args=None, **kw):
    return engine.execute(engine.resolve("pbs", "GET", path), dict(args or {}), cfg=cfg, ledger_cfg=cfg,
                          path=path, **kw)


def _feed_all(cfg):
    for p in ("/admin/datastore", "/config/datastore", "/admin/datastore/tank/namespace",
              "/admin/datastore/cold/namespace", "/config/remote", "/config/sync", "/config/verify",
              "/config/prune"):
        _read(cfg, p)
    _read(cfg, "/admin/datastore/tank/groups")
    _read(cfg, "/admin/datastore/tank/groups", args={"ns": "prod"})
    _read(cfg, "/admin/datastore/cold/groups")


def _feed_all_pve(cfg):
    engine.execute(engine.resolve("pve", "GET", "/cluster/resources"), {}, cfg=cfg, ledger_cfg=cfg,
                   path="/cluster/resources")


def _where(cfg, words, **kw):
    return memory.where(cfg.audit_log_path, "pbs", BOX, words, **kw)


def _db(cfg):
    return sqlite3.connect(memory.path(cfg.audit_log_path))


def _owners(cfg):
    with _db(cfg) as db:
        return sorted(o for (o,) in db.execute("SELECT DISTINCT owner FROM sighting WHERE plane='pbs'"))


def _kinds_with_ident(cfg, kind, ident):
    with _db(cfg) as db:
        return [k for (k,) in db.execute("SELECT key FROM entity WHERE plane='pbs' AND kind=? AND ident=?",
                                         (kind, ident))]


def _see_all(cfg):
    """What a learn with every sight leaves: every flag whole for the served token, so a whole read by
    that token owns its list. The id is the production reader's, never spelled here."""
    db = memory._open(cfg.audit_log_path, create=True)
    assert db is not None
    with db:
        for k in ("datastore_sight", "remote_sight", "push_sight"):
            memory._set(db, "pbs", BOX, k, f"whole:{arm.served_id(cfg)}")
    memory._settle(cfg.audit_log_path)


def _sync_all(template):
    """The args a read of `template` owns its list with: every direction for the sync list."""
    return {"sync-direction": "all"} if template == "/config/sync" else None


def _taint_marked(cfg, plane):
    audit_dir = os.path.dirname(cfg.audit_log_path)
    return spine.is_tainted(audit_dir) and any(s.startswith(f"{plane}:") for s in spine.taint_sources(audit_dir))


def _raise_oserror(*a, **k):
    raise OSError("read-only")


# --- the seam -------------------------------------------------------------------------------------

def test_pbs_is_registered_beside_pve():
    assert memory.shape("pbs") is memory_pbs.SHAPE
    assert memory.feeds("pbs") == memory_pbs.FEEDS
    assert memory.FEEDS is memory_pve.FEEDS                  # the back-compat names stay PVE's


def test_each_plane_points_a_miss_at_its_own_live_read(cfg, vendor, pve_cfg, pve_vendor):
    _read(cfg, "/admin/datastore")
    _feed_all_pve(pve_cfg)
    assert _where(cfg, "nothing-here")["next"] == ["GET /admin/datastore"]
    assert memory.where(pve_cfg.audit_log_path, "pve", PVE_BOX, "nothing-here")["next"] == \
        ["GET /cluster/resources"]
    assert memory.where(cfg.audit_log_path, "pbs", "https://never.invalid:8007/api2/json", "x")["next"] == \
        ["GET /admin/datastore"]                               # an empty memory too


def test_changed_begins_at_the_planes_whole_list(cfg, vendor):
    _see_all(cfg)
    _read(cfg, "/config/remote")                                 # fed, but not the datastore list
    out = memory.changed(cfg.audit_log_path, "pbs", BOX, "1h")
    assert out["began"] is None and "no_whole_read" in out["codes"]
    _read(cfg, "/admin/datastore")
    out = memory.changed(cfg.audit_log_path, "pbs", BOX, "1h")
    assert out["began"] is not None and "no_whole_read" not in out["codes"]


# --- finding things in the vendor's words ---------------------------------------------------------

def test_a_datastore_read_feeds_memory_and_where_finds_it(cfg, vendor):
    _read(cfg, "/admin/datastore")
    out = _where(cfg, "tank")
    assert out["verdict"] == "found"
    assert out["matches"][0] == {**out["matches"][0], "kind": "datastore", "id": "tank"}
    assert out["matches"][0]["paths"] == ["GET /admin/datastore/tank/status"]


def test_a_read_through_the_engine_feeds_memory(cfg, vendor):
    """The engine's own seam (`_keep`, `memory.feeds(row.product)`): a PBS read through
    `engine.execute` is what feeds, not a direct `memory.feed`."""
    engine.execute(engine.resolve("pbs", "GET", "/admin/datastore"), {}, cfg=cfg, ledger_cfg=cfg,
                   path="/admin/datastore")
    assert _where(cfg, "tank")["verdict"] == "found"


def test_the_engines_own_evaluating_read_retires_nothing(cfg, vendor):
    _see_all(cfg)
    _read(cfg, "/admin/datastore")                                       # the one list that names tank here
    vendor.bodies["/admin/datastore"] = []
    _read(cfg, "/admin/datastore", evaluating=True)                      # the door's own look, not a whole read
    assert [m["status"] for m in _where(cfg, "tank")["matches"] if m["kind"] == "datastore"] != ["gone"]
    _read(cfg, "/admin/datastore")                                       # the control: a whole read does retire it
    assert [m["status"] for m in _where(cfg, "tank")["matches"] if m["kind"] == "datastore"] == ["gone"]


def test_the_config_list_names_a_store_by_name(cfg, vendor):
    """`/config/datastore` spells the store `name` (the vendor's schema), `/admin/datastore` `store`."""
    _read(cfg, "/config/datastore")
    out = _where(cfg, "datastore cold")
    assert [(m["kind"], m["id"]) for m in out["matches"]] == [("datastore", "cold")]


def test_a_group_matches_by_its_vendor_spelling_only(cfg, vendor):
    _feed_all(cfg)
    assert _where(cfg, "vm/105")["verdict"] == "found"
    assert {x["id"] for x in _where(cfg, "105")["matches"]} == {"vm/105"}   # the bare backup-id, John 11-09
    assert _where(cfg, "VM/105")["verdict"] == "not_in_memory"           # case is the vendor's
    assert _where(cfg, "10")["verdict"] == "not_in_memory"               # exact, never a prefix


def test_the_bare_id_never_widens_pve(pve_cfg, pve_vendor):
    """PVE's id_names is empty: a digits word still matches only a vmid there (today's behaviour), never
    the guest whose NAME is those digits."""
    _feed_all_pve(pve_cfg)
    out = memory.where(pve_cfg.audit_log_path, "pve", PVE_BOX, "105")
    assert [(m["kind"], m["id"]) for m in out["matches"]] == [("lxc", "105")]


def test_the_same_group_in_two_stores_is_two_matches_in_store_order(cfg, vendor):     # RF3
    _feed_all(cfg)
    m = _where(cfg, "group vm/105")["matches"]
    assert [(x["id"], x["store"]) for x in m] == [("vm/105", "cold"), ("vm/105", "tank")]


def test_the_answer_shows_the_vendor_id_never_memorys_key(cfg, vendor):
    _feed_all(cfg)
    ids = [x["id"] for x in _where(cfg, "ct/200")["matches"]] + [x["id"] for x in _where(cfg, "prod/web")["matches"]]
    assert ids == ["ct/200", "prod/web"]                                 # never "tank/prod/ct/200"
    [group] = _where(cfg, "ct/200")["matches"]
    assert (group["store"], group["ns"], group["name"]) == ("tank", "prod", "200")
    [ns] = _where(cfg, "prod/web")["matches"]
    assert ns["store"] == "tank" and "ns" not in ns


def test_remotes_and_jobs_answer_by_their_vendor_id_with_their_own_read(cfg, vendor):
    _feed_all(cfg)
    for words, kind, path in (("offsite", "remote", "GET /config/remote/offsite"),
                              ("s-offsite", "sync-job", "GET /config/sync/s-offsite"),
                              ("v-tank", "verify-job", "GET /config/verify/v-tank"),
                              ("p-cold", "prune-job", "GET /config/prune/p-cold")):
        [m] = _where(cfg, words)["matches"]
        assert (m["kind"], m["id"], m["paths"]) == (kind, words, [path])


def test_a_found_group_marks_the_session_untrusted(cfg, vendor, monkeypatch):
    _feed_all(cfg)                                                       # tracking off: fed, nothing marked
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    assert not _taint_marked(cfg, "pbs")
    out = _where(cfg, "ct/200")
    assert out["untrusted"] is True
    assert _taint_marked(cfg, "pbs")                                     # same helper shape as the PVE test


def test_a_datastore_answer_alone_marks_nothing(cfg, vendor, monkeypatch):
    """The control: `/admin/datastore` is not an untrusted address."""
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    _read(cfg, "/admin/datastore")
    out = _where(cfg, "tank")
    assert out["found"] is True and "untrusted" not in out
    assert not spine.is_tainted(os.path.dirname(cfg.audit_log_path))


def test_an_unwritable_marker_refuses_the_group_answer_at_where(cfg, vendor, monkeypatch):
    _feed_all(cfg)
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    monkeypatch.setattr(spine, "mark_tainted", _raise_oserror)
    with pytest.raises(memory.ProximoError, match="taint marker"):
        _where(cfg, "ct/200")


# --- paths only from validated pieces -------------------------------------------------------------

def test_a_group_path_is_built_from_validated_pieces_only(cfg, vendor):                # RF1
    vendor.bodies["/admin/datastore/tank/groups"] = [{"backup-type": "vm", "backup-id": "../x"},
                                                      {"backup-type": "evil", "backup-id": "1"}]
    _read(cfg, "/admin/datastore/tank/groups")
    for words in ("vm/../x", "evil/1"):
        assert memory.resolve(words, plane="pbs", box=BOX, ledger_path=cfg.audit_log_path)["paths"] == []
    assert _where(cfg, "evil/1")["matches"][0]["paths"] == []           # kept as the vendor said, never a path


@pytest.mark.parametrize("kind,key,ident,detail", [
    ("datastore", "../x", "../x", None),
    ("remote", "a/b", "a/b", None),
    ("sync-job", "-x", "-x", None),
    ("namespace", "../x/prod", "prod", {"store": "../x"}),
    ("group", "../x//vm/1", "vm/1", {"store": "../x", "ns": "", "type": "vm", "id": "1"}),
])
def test_no_path_carries_an_id_that_fails_the_check(kind, key, ident, detail):
    import json
    r = {"kind": kind, "key": key, "ident": ident, "node": None, "detail": json.dumps(detail) if detail else None}
    assert memory_pbs.SHAPE.paths(r) == []


# --- a group's own read: the path, and the vendor's params beside it ------------------------------

def test_a_namespaced_group_shows_the_args_its_snapshots_read_needs(cfg, vendor):
    _feed_all(cfg)
    [m] = _where(cfg, "ct/200")["matches"]
    assert m["paths"] == ["GET /admin/datastore/tank/snapshots"]          # a plain string, find's contract
    assert m["args"] == {"backup-type": "ct", "backup-id": "200", "ns": "prod"}


def test_a_root_group_shows_args_with_no_namespace(cfg, vendor):
    _feed_all(cfg)
    m = _where(cfg, "group vm/105")["matches"]
    assert [x["args"] for x in m] == [{"backup-type": "vm", "backup-id": "105"}] * 2


def test_the_args_are_the_vendors_published_params_for_the_snapshots_read():
    params = set(engine.table()[("pbs", "GET", "/admin/datastore/{store}/snapshots")].params)
    assert {"backup-type", "backup-id", "ns"} <= params


@pytest.mark.parametrize("detail", [
    {"store": "tank", "ns": "", "type": "evil", "id": "1"},            # a type the vendor does not publish
    {"store": "tank", "ns": "", "type": "vm", "id": "../x"},           # an id that fails _ID
    {"store": "../x", "ns": "", "type": "vm", "id": "1"},              # a store that fails _ID
    {"store": "tank", "ns": "prod/../x", "type": "vm", "id": "1"},     # a namespace level that fails _ID
    {"store": "tank", "ns": None, "type": "vm", "id": "1"},            # no namespace at all
])
def test_a_group_failing_the_check_shows_no_args_and_no_path(detail):
    import json
    r = {"kind": "group", "key": "k", "ident": f"{detail['type']}/{detail['id']}", "node": None,
         "detail": json.dumps(detail)}
    assert "args" not in memory_pbs.SHAPE.show(r)
    assert memory_pbs.SHAPE.paths(r) == []


def test_a_group_failing_the_check_through_a_read_shows_no_args(cfg, vendor):
    vendor.bodies["/admin/datastore/tank/groups"] = [{"backup-type": "evil", "backup-id": "1"}]
    _read(cfg, "/admin/datastore/tank/groups")
    [m] = _where(cfg, "evil/1")["matches"]
    assert "args" not in m and m["paths"] == []


# --- owners: only a whole read retires ------------------------------------------------------------

def test_root_namespace_unset_and_empty_are_one_owner(cfg, vendor):                    # RF2
    _see_all(cfg)
    _read(cfg, "/admin/datastore/tank/groups")
    _read(cfg, "/admin/datastore/tank/groups", args={"ns": ""})
    owners = _owners(cfg)
    assert [o for o in owners if o.startswith("groups/tank/")] == ["groups/tank/"]
    _read(cfg, "/admin/datastore/tank/namespace")                       # the vendor lists root as ns ""
    assert _kinds_with_ident(cfg, "namespace", "") == []                 # root is never an entity


def test_a_whole_group_read_without_a_group_marks_it_gone(cfg, vendor):
    _see_all(cfg)
    _feed_all(cfg)                                                       # vm/105 in tank AND cold
    vendor.bodies["/admin/datastore/tank/groups"] = []
    _read(cfg, "/admin/datastore/tank/groups")
    m = _where(cfg, "vm/105")["matches"]                                 # the shell keeps a gone thing
    assert [x["status"] for x in m if x["store"] == "tank"] == ["gone"]
    assert memory.resolve("vm/105", plane="pbs", box=BOX, ledger_path=cfg.audit_log_path)["paths"] \
        == ["GET /admin/datastore/cold/snapshots"]                       # find hands out only the live one


def test_one_namespaces_group_read_never_retires_anothers(cfg, vendor):
    _see_all(cfg)
    _feed_all(cfg)
    vendor.bodies["/admin/datastore/tank/groups"] = []                   # root emptied, prod untouched
    _read(cfg, "/admin/datastore/tank/groups")
    [m] = _where(cfg, "ct/200")["matches"]
    assert m["status"] != "gone"


@pytest.mark.parametrize("template,bound,args,fields,box,evaluating,data,owner", [
    ("/admin/datastore", {}, {}, None, BOX, False, [], "datastores"),
    ("/config/datastore", {}, {}, None, BOX, False, [], "/config/datastore"),
    ("/config/remote", {}, {}, None, BOX, False, [], "/config/remote"),
    ("/config/sync", {}, {"sync-direction": "all"}, None, BOX, False, [], "/config/sync"),
    ("/config/sync", {}, {}, None, BOX, False, [], None),                # bare: the pull jobs only
    ("/config/sync", {}, {"sync-direction": "push"}, None, BOX, False, [], None),
    ("/config/verify", {}, {}, None, BOX, False, [], "/config/verify"),
    ("/config/prune", {}, {}, None, BOX, False, [], "/config/prune"),
    ("/admin/datastore/{store}/namespace", {"store": "tank"}, {}, None, BOX, False, [], "namespaces/tank"),
    ("/admin/datastore/{store}/namespace", {"store": "tank"}, {"max-depth": 0}, None, BOX, False, [], None),
    ("/admin/datastore/{store}/namespace", {"store": "tank"}, {"parent": "prod"}, None, BOX, False, [], None),
    ("/admin/datastore/{store}/groups", {"store": "tank"}, {}, None, BOX, False, [], "groups/tank/"),
    ("/admin/datastore/{store}/groups", {"store": "tank"}, {"ns": ""}, None, BOX, False, [], "groups/tank/"),
    ("/admin/datastore/{store}/groups", {"store": "tank"}, {"ns": "prod"}, None, BOX, False, [], "groups/tank/prod"),
    ("/admin/datastore", {}, {}, "store", BOX, False, [], None),          # a field subset
    ("/admin/datastore", {}, {}, None, BOX, True, [], None),             # the door's own look
    ("/admin/datastore", {}, {}, None, "", False, [], None),             # a box with no name
    ("/admin/datastore", {}, {}, None, BOX, False, {"x": 1}, None),      # not a list
])
def test_only_a_whole_read_owns_its_list(cfg, template, bound, args, fields, box, evaluating, data, owner):
    _see_all(cfg)                                                       # every sight: only the read decides
    with _db(cfg) as db:
        assert memory_pbs.SHAPE.owner(template, bound, args, fields, data, box, evaluating, db=db,
                                      who=arm.served_id(cfg)) == owner


# --- remotes and sync jobs: the vendor hides them from a token without Remote.Audit ---------------

NO_REMOTE_AUDIT = {"/datastore": {"Datastore.Audit": True}}      # the lab token's shape: no Remote.Audit anywhere


def _gone(cfg, words):
    [m] = _where(cfg, words)["matches"]
    return m["status"] == "gone"


@pytest.mark.parametrize("template,words", [("/config/remote", "offsite"), ("/config/sync", "s-offsite")])
def test_without_remote_audit_an_empty_list_retires_nothing(cfg, vendor, template, words):
    """PBS filters `/config/remote` and `/config/sync` by Remote.Audit and answers `[]` for what the
    token cannot see: absent is not proof, so that read adds and refreshes only."""
    vendor.bodies["/access/permissions"] = NO_REMOTE_AUDIT
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False
    assert ("this token's permission map does not show Remote.Audit on /remote: remotes and sync jobs may be "
            "hidden") in out["why"]
    assert not _gone(cfg, words)                                         # learned while still listed
    vendor.bodies[template] = []
    _read(cfg, template, _sync_all(template))
    assert not _gone(cfg, words)


@pytest.mark.parametrize("template,words", [("/config/remote", "offsite"), ("/config/sync", "s-offsite")])
def test_with_remote_audit_an_empty_list_retires_it(cfg, vendor, template, words):
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)                     # Remote.Audit on `/`, propagating
    assert out["complete"] is True, out.get("why")
    vendor.bodies[template] = []
    _read(cfg, template, _sync_all(template))
    assert _gone(cfg, words)


def test_remote_audit_not_propagating_from_the_root_is_not_sight(cfg, vendor):
    vendor.bodies["/access/permissions"] = {"/": {"Datastore.Audit": True, "Remote.Audit": False}}
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert "Remote.Audit" in out["why"]
    vendor.bodies["/config/remote"] = []
    _read(cfg, "/config/remote")
    assert not _gone(cfg, "offsite")


def test_a_later_learn_that_loses_the_sight_stops_the_retiring(cfg, vendor):
    """The judgement is the latest learn's: a stale "sees" from an earlier token never survives."""
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    vendor.bodies["/access/permissions"] = NO_REMOTE_AUDIT
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    vendor.bodies["/config/remote"] = []
    _read(cfg, "/config/remote")
    assert not _gone(cfg, "offsite")


def test_an_unreadable_permission_map_is_no_sight(cfg, vendor):
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    del vendor.bodies["/access/permissions"]
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert "Remote.Audit" in out["why"]
    vendor.bodies["/config/sync"] = []
    _read(cfg, "/config/sync", _sync_all("/config/sync"))
    assert not _gone(cfg, "s-offsite")


def test_a_learn_stopped_before_the_map_drops_an_earlier_sight(cfg, vendor, monkeypatch):
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    monkeypatch.setattr(memory, "LEARN_MAX_READS", 0)                    # stopped before the map (read first)
    assert memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)["complete"] is False
    vendor.bodies["/config/remote"] = []
    _read(cfg, "/config/remote")
    assert not _gone(cfg, "offsite")


def test_with_sight_judged_the_config_lists_own_their_list(cfg, vendor):
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    me = arm.served_id(cfg)
    with _db(cfg) as db:
        owner = memory_pbs.SHAPE.owner
        assert owner("/config/remote", {}, {}, None, [], BOX, False, db=db, who=me) == "/config/remote"
        assert owner("/config/remote", {}, {"x": 1}, None, [], BOX, False, db=db, who=me) is None
        assert owner("/config/sync", {}, {"sync-direction": "all"}, None, [], BOX, False, db=db,
                     who=me) == "/config/sync"
        for args in ({}, {"sync-direction": "pull"}, {"sync-direction": "push"},
                     {"sync-direction": "all", "x": 1}):
            assert owner("/config/sync", {}, args, None, [], BOX, False, db=db, who=me) is None


# --- every PBS list is filtered by privilege: none owns without the sight it needs ------------------

# Sees `tank` (so the engine's own sight check serves its empty lists) but not every datastore.
NO_DATASTORE_AUDIT = {"/": {"Remote.Audit": True}, "/datastore/tank": {"Datastore.Audit": True}}
ALL_SIGHT = PBS["/access/permissions"]

#: (what whole reads list, the reads that empty them, the word that finds the thing they listed). A
#: datastore is held by both datastore lists, so both go empty: emptying one could never retire it,
#: with or without the rule.
LISTS = [
    ("/admin/datastore+/config/datastore", ["/admin/datastore", "/config/datastore"], "cold"),
    ("/admin/datastore/{store}/namespace", ["/admin/datastore/tank/namespace"], "prod"),
    ("/admin/datastore/{store}/groups", ["/admin/datastore/tank/groups?ns=prod"], "ct/200"),
    ("/config/verify", ["/config/verify"], "v-tank"),
    ("/config/prune", ["/config/prune"], "p-cold"),
]


def _empty_and_read(cfg, vendor, reads):
    for at in reads:
        vendor.bodies[at] = []
        path, _, ns = at.partition("?ns=")
        _read(cfg, path, args={"ns": ns} if ns else _sync_all(path))


def test_every_fed_list_names_the_sights_it_needs():
    assert set(memory_pbs._NEEDS) == memory_pbs.FEEDS


@pytest.mark.parametrize("template,reads,words", LISTS, ids=[c[0] for c in LISTS])
def test_without_datastore_sight_an_empty_list_retires_nothing(cfg, vendor, template, reads, words):   # (a)
    vendor.bodies["/access/permissions"] = NO_DATASTORE_AUDIT
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "Datastore.Audit reaching every datastore" in out["why"]
    assert out["groups"] == 3                                            # learn still reads what it may see
    assert not _gone(cfg, words)
    _empty_and_read(cfg, vendor, reads)
    assert not _gone(cfg, words)


@pytest.mark.parametrize("template,reads,words", LISTS, ids=[c[0] for c in LISTS])
def test_with_every_sight_an_empty_list_retires_it(cfg, vendor, template, reads, words):             # (b)
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is True, out.get("why")
    _empty_and_read(cfg, vendor, reads)
    assert _gone(cfg, words)


@pytest.mark.parametrize("perms,retires", [
    (ALL_SIGHT, True),
    ({"/": {"Datastore.Audit": True, "RemoteDatastore.Audit": True}}, False),           # no Remote.Audit
    ({"/": {"Remote.Audit": True, "RemoteDatastore.Audit": True},                       # no Datastore.Audit on
      "/datastore/tank": {"Datastore.Audit": True}}, False),                            # every store
    ({"/": {"Datastore.Audit": True, "Remote.Audit": True}}, False),                     # no RemoteDatastore.Audit
], ids=["every", "no-remote-sight", "no-datastore-sight", "no-push-sight"])
def test_a_sync_list_retires_only_with_every_sight(cfg, vendor, perms, retires):                      # (c)
    vendor.bodies["/access/permissions"] = perms
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    _empty_and_read(cfg, vendor, ["/config/sync"])
    assert _gone(cfg, "s-offsite") is retires


@pytest.mark.parametrize("template,reads,words", LISTS, ids=[c[0] for c in LISTS])
def test_a_later_learn_that_loses_datastore_sight_stops_the_retiring(cfg, vendor, template, reads, words):  # (d)
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    vendor.bodies["/access/permissions"] = NO_DATASTORE_AUDIT
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    _empty_and_read(cfg, vendor, reads)
    assert not _gone(cfg, words)


def test_a_fully_sighted_learn_alone_begins_changed(cfg, vendor):                         # fix round 1 (a)
    """The map is read before any list, so learn's own datastore list owns and anchors `changed`."""
    assert memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)["complete"] is True
    out = memory.changed(cfg.audit_log_path, "pbs", BOX, "1h")
    assert out["began"] is not None and "no_whole_read" not in out["codes"]


def test_a_partial_sight_learn_alone_has_no_whole_read(cfg, vendor):                     # fix round 1 (b)
    vendor.bodies["/access/permissions"] = NO_DATASTORE_AUDIT
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    out = memory.changed(cfg.audit_log_path, "pbs", BOX, "1h")
    assert out["began"] is None and "no_whole_read" in out["codes"]


def test_learn_reads_the_map_before_any_list(cfg, vendor):
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert vendor.calls[0] == "/access/permissions"


def test_with_no_learn_no_list_owns(cfg):
    """Unknown is blind: with no file judged, no PBS list owns, whatever it read."""
    for t in sorted(memory_pbs.FEEDS):
        assert memory_pbs.SHAPE.owner(t, {"store": "tank"}, {}, None, [], BOX, False) is None


# --- sight is the token's, not the box's: arm and disarm swap the token behind one URL ------------

NARROW = {"/datastore/tank": {"Datastore.Audit": True}}            # sees one store, no remote at all
EVERY_LIST = [("/config/remote", "offsite"), ("/config/sync", "s-offsite"), ("/config/verify", "v-tank"),
              ("/admin/datastore/{store}/groups", "ct/200")]
READS = {"/config/remote": ["/config/remote"], "/config/sync": ["/config/sync"], "/config/verify": ["/config/verify"],
         "/admin/datastore/{store}/groups": ["/admin/datastore/tank/groups?ns=prod"]}


@pytest.mark.parametrize("template,words", EVERY_LIST, ids=[t for t, _ in EVERY_LIST])
def test_a_sight_learned_by_one_token_never_owns_for_another(cfg, vendor, template, words):          # (a)
    """Learned with full sight under token A, then token B is served (a disarm): B's empty whole read
    is a filtered answer from a token never judged, and retires nothing."""
    assert memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)["complete"] is True
    _serve(cfg, TOKEN_B, SECRET_B)
    vendor.bodies["/access/permissions"] = NARROW
    _empty_and_read(cfg, vendor, READS[template])
    assert not _gone(cfg, words)


@pytest.mark.parametrize("template,words", EVERY_LIST, ids=[t for t, _ in EVERY_LIST])
def test_the_reverse_swap_owns_nothing_either_until_its_own_learn(cfg, vendor, template, words):       # (b)
    """Learned under the narrow token B, then the wide token A is served (an arm): A was never judged
    on this box, so its empty read retires nothing; A's own learn then makes it own."""
    _serve(cfg, TOKEN_B, SECRET_B)
    vendor.bodies["/access/permissions"] = NARROW
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    _serve(cfg, TOKEN_A, SECRET_A)
    vendor.bodies["/access/permissions"] = ALL_SIGHT
    _empty_and_read(cfg, vendor, READS[template])
    assert not _gone(cfg, words)
    vendor.bodies.update({k: v for k, v in PBS.items() if k not in vendor.bodies or not vendor.bodies[k]})
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    _empty_and_read(cfg, vendor, READS[template])
    assert _gone(cfg, words)


@pytest.mark.parametrize("template,words", EVERY_LIST, ids=[t for t, _ in EVERY_LIST])
def test_the_same_token_keeps_its_sight(cfg, vendor, template, words):                               # (c)
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    _serve(cfg, TOKEN_A, SECRET_A + "-rotated")                          # the same id, a new secret
    _empty_and_read(cfg, vendor, READS[template])
    assert _gone(cfg, words)


@pytest.mark.parametrize("line", ["not-a-token-line", "user-without-realm!t:s", "invented@pbs:secret-only",
                                  "invented@pbs!t name:secret", ""])
def test_a_token_that_names_no_id_is_blind(cfg, vendor, line):                                       # (d)
    with open(cfg.token_path, "w") as f:
        f.write(line + "\n")
    assert arm.served_id(cfg) is None
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "names no id this pass could hold steady" in out["why"]
    _empty_and_read(cfg, vendor, ["/config/remote", "/config/sync"])
    assert not _gone(cfg, "offsite") and not _gone(cfg, "s-offsite")


@pytest.mark.parametrize("who", [None, "", "garbage", "a@b!c d", "x" * 200 + "@pbs!t"])
def test_an_unknown_or_unparseable_id_owns_nothing(cfg, who):                                         # (d)
    _see_all(cfg)
    with _db(cfg) as db:
        for t in sorted(memory_pbs.FEEDS):
            assert memory_pbs.SHAPE.owner(t, {"store": "tank"}, _sync_all(t) or {}, None, [], BOX, False,
                                          db=db, who=who) is None


def test_no_secret_byte_ever_reaches_the_memory_file(cfg, vendor):                                  # (e)
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    _serve(cfg, TOKEN_B, SECRET_B)
    _feed_all(cfg)
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    held = b"".join(open(p, "rb").read() for p in (memory.path(cfg.audit_log_path),
                                                    memory.path(cfg.audit_log_path) + "-wal")
                    if os.path.exists(p))
    assert TOKEN_A.encode() in held or TOKEN_B.encode() in held        # the public id IS kept: the grep can see
    for secret in (SECRET_A, SECRET_B, "PLANTED-SECRET"):
        assert secret.encode() not in held


@pytest.mark.parametrize("first,then", [((TOKEN_A, SECRET_A), (TOKEN_B, SECRET_B)),
                                        ((TOKEN_B, SECRET_B), (TOKEN_A, SECRET_A))], ids=["disarm", "arm"])
def test_a_token_swapped_during_the_read_owns_nothing(cfg, vendor, monkeypatch, first, then):         # (f)
    """The engine reads the id before the wire and again after: a swap between them (an arm or a
    disarm during the read) leaves the read unattributed, so it retires nothing."""
    for tok, sec in (then, first):                                      # both tokens learned, full sight
        _serve(cfg, tok, sec)
        memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    real = vendor.call

    def swapping(method, path, params=None):
        out = real(method, path, params)
        _serve(cfg, *then)
        return out
    monkeypatch.setattr(vendor, "call", swapping)
    vendor.bodies["/config/remote"] = []
    _read(cfg, "/config/remote")
    assert not _gone(cfg, "offsite")


def test_a_token_swapped_while_learn_reads_the_map_raises_no_sight(cfg, vendor, monkeypatch):
    real = vendor.call

    def swapping(method, path, params=None):
        out = real(method, path, params)
        if path == "/access/permissions":
            _serve(cfg, TOKEN_B, SECRET_B)
        return out
    monkeypatch.setattr(vendor, "call", swapping)
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "names no id this pass could hold steady" in out["why"]
    with _db(cfg) as db:
        assert {v for (v,) in db.execute("SELECT v FROM meta WHERE k LIKE '%_sight' AND plane='pbs'")} == {"partial"}


def test_a_live_ticket_is_its_users_id_and_a_dead_one_is_blind(cfg):
    import time as _t
    issued = int(_t.time())
    doc = {"ticket": f"PBS:invented@pbs:{issued:08X}::c2lnbmF0dXJl", "csrf": "abc:def", "box": BOX}
    with open(cfg.token_path, "w") as f:
        json.dump(doc, f)
    assert arm.served_id(cfg) == "invented@pbs"
    doc["ticket"] = f"PBS:invented@pbs:{issued - 3 * 3600:08X}::c2lnbmF0dXJl"
    with open(cfg.token_path, "w") as f:
        json.dump(doc, f)
    assert arm.served_id(cfg) is None                                    # the wire would not send it
    doc["ticket"], doc["box"] = f"PBS:invented@pbs:{issued:08X}::c2lnbmF0dXJl", "https://elsewhere.invalid:8007"
    with open(cfg.token_path, "w") as f:
        json.dump(doc, f)
    assert arm.served_id(cfg) is None                                    # another box's ticket


# --- sync jobs have a direction: a bare read lists pull jobs only ---------------------------------

def test_learn_reads_the_sync_list_in_every_direction(cfg, vendor):
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert [a for p, a in vendor.params if p == "/config/sync"] == [{"sync-direction": "all"}]


@pytest.mark.parametrize("args", [None, {"sync-direction": "pull"}, {"sync-direction": "push"}],
                         ids=["bare", "pull", "push"])
def test_a_sync_read_not_asked_for_every_direction_never_retires(cfg, vendor, args):
    assert memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)["complete"] is True      # every sight
    vendor.bodies["/config/sync"] = []
    _read(cfg, "/config/sync", args)
    assert not _gone(cfg, "s-offsite")


def test_an_every_direction_sync_read_with_every_sight_retires(cfg, vendor):                         # control
    assert memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)["complete"] is True
    vendor.bodies["/config/sync"] = []
    _read(cfg, "/config/sync", {"sync-direction": "all"})
    assert _gone(cfg, "s-offsite")


def test_without_remote_datastore_audit_push_jobs_may_be_hidden(cfg, vendor):
    vendor.bodies["/access/permissions"] = {"/": {"Datastore.Audit": True, "Remote.Audit": True}}
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False
    assert ("this token's permission map does not show RemoteDatastore.Audit on /remote: push sync jobs may be "
            "hidden") in out["why"]
    vendor.bodies["/config/sync"] = []
    _read(cfg, "/config/sync", {"sync-direction": "all"})
    assert not _gone(cfg, "s-offsite")
    vendor.bodies["/config/remote"] = []                                  # Remote.Audit alone still owns remotes
    _read(cfg, "/config/remote")
    assert _gone(cfg, "offsite")


def test_a_later_learn_that_loses_push_sight_stops_the_sync_retiring(cfg, vendor):
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    vendor.bodies["/access/permissions"] = {"/": {"Datastore.Audit": True, "Remote.Audit": True}}
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    vendor.bodies["/config/sync"] = []
    _read(cfg, "/config/sync", {"sync-direction": "all"})
    assert not _gone(cfg, "s-offsite")


# --- changed names things by the vendor's ids; a partial learn says so ----------------------------

def test_changed_names_a_group_by_its_vendor_id_store_and_namespace(cfg, vendor):
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    vendor.bodies["/admin/datastore/tank/groups?ns=prod"] = []
    _read(cfg, "/admin/datastore/tank/groups", {"ns": "prod"})
    [g] = memory.changed(cfg.audit_log_path, "pbs", BOX, "1h")["gone"]
    assert (g["kind"], g["id"], g["store"], g["ns"]) == ("group", "ct/200", "tank", "prod")
    assert "args" not in g and "tank/prod/ct/200" not in json.dumps(g)


def test_changed_says_partial_sight_after_a_partial_learn(cfg, vendor):
    vendor.bodies["/access/permissions"] = NARROW
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert "partial_sight" in memory.changed(cfg.audit_log_path, "pbs", BOX, "1h")["codes"]


def test_changed_says_no_partial_sight_after_a_whole_learn(cfg, vendor):
    memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert "partial_sight" not in memory.changed(cfg.audit_log_path, "pbs", BOX, "1h")["codes"]


def test_learn_checks_each_namespaces_groups_read_on_its_own(cfg, vendor, monkeypatch):
    """One namespace's groups read kept never answers for another's: a namespace whose read was not
    kept is a gap even when the store's other namespaces were."""
    real = memory.feed

    def dropping(*a, **k):
        if a[3] == "/admin/datastore/{store}/groups" and (a[5] or {}).get("ns") == "prod":
            return None                                                   # this one read is not kept
        return real(*a, **k)
    monkeypatch.setattr(memory, "feed", dropping)
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False
    assert "memory did not keep GET /admin/datastore/tank/groups (ns prod) on this pass" in out["why"]


# --- doctor reads learn per plane -----------------------------------------------------------------

def test_doctor_says_learned_per_plane(cfg, vendor, pve_cfg, pve_vendor, monkeypatch):
    """A partial PBS learn never makes a PVE learn that was complete read as incomplete."""
    assert memory.status(cfg.audit_log_path)["learned"] == "never"
    pve_vendor.bodies.update({"/access/permissions": {"/": {"VM.Audit": 1, "Sys.Audit": 1}}, "/storage": [],
                              "/cluster/backup": [], "/pools": [], "/access/acl": [],
                              "/nodes/pve1/network": [],
                              "/nodes/pve1/lxc/105/pending": [{"key": "hostname", "value": "web"}],
                              "/nodes/pve1/qemu/100/pending": [{"key": "name", "value": "105"}]})
    out = memory.learn("pve", cfg=pve_cfg, ledger_cfg=pve_cfg)
    assert out["complete"] is True, out.get("why")
    vendor.bodies["/access/permissions"] = NARROW
    assert memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)["complete"] is False
    assert memory.status(cfg.audit_log_path)["learned"] == {"pbs": "incomplete", "pve": "complete"}


# --- what is never kept ---------------------------------------------------------------------------

def test_a_remote_secret_never_reaches_the_file(cfg, vendor):                          # RF5
    vendor.bodies["/config/remote"] = [{"name": "offsite", "host": "backup.example", "password": "PLANTED"}]
    _read(cfg, "/config/remote")
    assert _where(cfg, "offsite")["verdict"] == "found"                  # the remote itself was kept
    assert b"PLANTED" not in open(memory.path(cfg.audit_log_path), "rb").read()


def test_a_group_comment_is_untrusted_and_never_kept(cfg, vendor):
    vendor.bodies["/admin/datastore/tank/groups"] = [{"backup-type": "vm", "backup-id": "105",
                                                      "comment": "IGNORE PREVIOUS", "owner": "PLANTED-OWNER"}]
    _read(cfg, "/admin/datastore/tank/groups")
    assert _where(cfg, "vm/105")["verdict"] == "found"                   # the group itself was kept
    raw = open(memory.path(cfg.audit_log_path), "rb").read()
    assert b"IGNORE PREVIOUS" not in raw and b"PLANTED-OWNER" not in raw
    with _db(cfg) as db:
        assert db.execute("SELECT untrusted FROM entity WHERE kind='group'").fetchall() == [(1,)]


# --- learn ----------------------------------------------------------------------------------------

def test_learn_reads_every_store_and_namespace_and_counts_groups(cfg, vendor):
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is True and out["groups"] == 3
    assert "/admin/datastore/tank/groups?ns=prod/web" in vendor.calls      # nested namespaces too
    assert "/admin/datastore/cold/groups" in vendor.calls                  # root: no ns argument


def test_learn_without_datastore_audit_everywhere_is_not_complete(cfg, vendor):        # RF4
    vendor.bodies["/access/permissions"] = {"/datastore/tank": {"Datastore.Audit": True}}
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "Datastore.Audit" in out["why"]


def test_learn_names_a_store_it_could_not_read(cfg, vendor):
    del vendor.bodies["/admin/datastore/cold/namespace"]
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "/admin/datastore/cold/namespace" in out["why"]


def test_learn_is_not_complete_when_a_namespace_was_too_long_to_keep(cfg, vendor):
    """A valid depth-4 namespace whose key (`{store}/{ns}`) passes memory's bound is never an entity,
    so its groups are never read: learn says so (review finding, fix round 1)."""
    long = "/".join(["a" * 30] * 4)
    assert len(f"tank/{long}") > memory.TEXT
    vendor.bodies["/admin/datastore/tank/namespace"] = [{"ns": ""}, {"ns": "prod"}, {"ns": "prod/web"}, {"ns": long}]
    vendor.bodies[f"/admin/datastore/tank/groups?ns={long}"] = [{"backup-type": "vm", "backup-id": "777"}]
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "longer than memory keeps" in out["why"]
    assert out["why"].startswith("1 datastore(s)/namespace(s)/group(s) not kept")


def test_learn_ignores_ids_skipped_before_its_pass(cfg, vendor):
    """Only this pass's skips are its gap: an earlier read's skipped id never fails a later learn."""
    vendor.bodies["/access/permissions"] = PBS["/access/permissions"]
    vendor.bodies["/admin/datastore/tank/groups"] = [{"backup-type": "vm", "backup-id": "9" * 130}]
    _read(cfg, "/admin/datastore/tank/groups")                           # skipped before the pass
    vendor.bodies["/admin/datastore/tank/groups"] = PBS["/admin/datastore/tank/groups"]
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is True, out.get("why")


def test_learn_stops_at_its_budget_and_still_tallies(cfg, vendor, monkeypatch):
    monkeypatch.setattr(memory, "LEARN_MAX_READS", 9)     # the map, the 6 lists, both stores' namespaces
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "read budget" in out["why"] and out["reads"] == 9


# --- one file, two planes -------------------------------------------------------------------------

def test_pve_and_pbs_rows_never_mix_on_one_file(cfg, vendor, pve_cfg, pve_vendor):
    """The same ledger, both planes fed: a PVE word finds only PVE, a PBS word only PBS."""
    _feed_all(cfg)
    _feed_all_pve(pve_cfg)
    assert memory.where(cfg.audit_log_path, "pbs", BOX, "web")["verdict"] == "not_in_memory"   # a PVE guest name
    assert memory.where(cfg.audit_log_path, "pve", PVE_BOX, "tank")["verdict"] == "not_in_memory"
    assert memory.where(cfg.audit_log_path, "pbs", BOX, "tank")["verdict"] == "found"
    assert memory.where(cfg.audit_log_path, "pve", PVE_BOX, "web")["verdict"] == "found"


# --- the shell door -------------------------------------------------------------------------------

@pytest.fixture
def pbs_env(cfg, monkeypatch, tmp_path):
    """The env PBS box at the shell door, its ledger the test's."""
    token = tmp_path / "pbs.token"
    token.write_text("invented@pbs!t:00000000-0000-0000-0000-000000000000\n")
    token.chmod(0o600)
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", BOX)
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", str(token))
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", cfg.audit_log_path)
    return cfg


def test_the_shell_learns_and_finds_on_pbs(capsys, pbs_env, vendor):
    assert cli.main(["learn", "--plane", "pbs"]) == cli.EXIT_OK
    learned = json.loads(capsys.readouterr().out)
    assert learned["complete"] is True and learned["groups"] == 3, learned.get("why")
    assert cli.main(["where", "--plane", "pbs", "vm/105"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert '"verdict": "found"' in out
    assert cli.main(["changed", "--plane", "pbs", "1h"]) == cli.EXIT_OK
    changed = json.loads(capsys.readouterr().out)                       # a token with every sight: learn began it
    assert changed["source"] == "memory" and changed["began"] is not None and "no_whole_read" not in changed["codes"]
    assert cli.main(["where", "--plane", "pbs", "nowhere-on-the-box"]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["verdict"] == "not_in_memory"


def test_uses_on_pbs_says_why_and_exits_3(capsys, pbs_env):
    assert cli.main(["uses", "--plane", "pbs", "tank"]) == cli.EXIT_USAGE
    assert ("unconfigured: the estate memory relates nothing on pbs: uses is PVE's (disks and NICs)"
            in capsys.readouterr().err)


def test_uses_on_a_plane_that_relates_nothing_writes_no_receipt(pbs_env, vendor):
    _feed_all(pbs_env)
    before = open(pbs_env.audit_log_path).read().count('"core.recall"')
    with pytest.raises(memory.Unusable, match="relates nothing on pbs"):
        memory.uses(pbs_env.audit_log_path, "pbs", BOX, "tank")
    assert open(pbs_env.audit_log_path).read().count('"core.recall"') == before   # refused, never answered


def test_the_shell_on_a_plane_with_no_shape_refuses_with_its_plane(capsys):
    assert cli.main(["where", "--plane", "nope", "x"]) == cli.EXIT_USAGE
    assert "the estate memory has no shape for nope" in capsys.readouterr().err


# ======================== the keyed-row rule: absent is not proof ==================================
# A whole list with a row memory cannot key retires nothing: that row may be the very thing a retire
# would call gone (a field renamed in another version, a garbled answer).

_G105 = PBS["/admin/datastore/tank/groups"][0]
#: the read (path, or path?ns=), its owner, a later whole answer that lists less than the first
KEYED = [
    ("/admin/datastore", "datastores", [PBS["/admin/datastore"][0]]),
    ("/config/datastore", "/config/datastore", [PBS["/config/datastore"][0]]),
    ("/admin/datastore/tank/namespace", "namespaces/tank", [{"ns": ""}, {"ns": "prod"}]),
    ("/admin/datastore/tank/groups", "groups/tank/", []),
    ("/admin/datastore/tank/groups?ns=prod", "groups/tank/prod", []),
    ("/config/remote", "/config/remote", [{"name": "other", "host": "other.example", "auth-id": "sync@pbs"}]),
    ("/config/sync", "/config/sync", [{"id": "s-other", "store": "cold", "remote-store": "far"}]),
    ("/config/verify", "/config/verify", [{"id": "v-other", "store": "tank"}]),
    ("/config/prune", "/config/prune", [{"id": "p-other", "store": "cold", "schedule": "daily"}]),
]
UNKEYABLE = ["x", None, 7, {"bogus": 1}, ["vm/105"]]
UNKEYABLE_BY = {
    "/admin/datastore": [{"name": "tank"}, {"store": ""}, {"store": 5},           # `name` is the config list's word
                         {"store": "bare"},                                        # no `backend-type`, `mount-status`
                         {"store": "", "backend-type": "filesystem", "mount-status": "nonremovable"}],
    "/config/datastore": [{"store": "tank"}, {"name": None}, {"name": "bare"}, {"name": "", "path": "/invented"}],
    "/admin/datastore/tank/namespace": [{"ns": None}, {"ns": 5}, {"name": "prod"}],
    "/admin/datastore/tank/groups": [{"backup-type": "vm"}, {"backup-id": "105"},
                                     {"backup-type": "vm", "backup-id": "9"},     # the vendor's other fields missing
                                     {**_G105, "backup-id": ""},
                                     {"backup-type": "vm", "backup-id": ""}, {"backup-type": None, "backup-id": "105"}],
    "/admin/datastore/tank/groups?ns=prod": [{"backup-type": "ct"}, {"backup-id": 200}],
    "/config/remote": [{"host": "backup.example"}, {"name": ""}, {"name": "bare", "host": "bare.example"},
                       {"name": "", "host": "x.example", "auth-id": "sync@pbs"}],
    "/config/sync": [{"store": "cold"}, {"id": None}, {"id": "s-bare", "store": "cold"},
                     {"id": "", "store": "cold", "remote-store": "far"}],
    "/config/verify": [{"store": "tank"}, {"id": 5}, {"id": "v-bare"}, {"id": "", "store": "tank"}],
    "/config/prune": [{"store": "cold"}, {"id": ""}, {"id": "p-bare", "store": "cold"},
                      {"id": "", "store": "cold", "schedule": "daily"}],
}
_KEYED_CASES = [(*c, bad) for c in KEYED for bad in (*UNKEYABLE, *UNKEYABLE_BY[c[0]])]


def _drops(cfg, owner):
    with _db(cfg) as db:
        return db.execute("SELECT count(*) FROM sighting WHERE plane='pbs' AND owner=? AND dropped IS NOT NULL",
                          (owner,)).fetchone()[0]


def _whole_at(cfg, owner):
    with _db(cfg) as db:
        return float(db.execute("SELECT v FROM meta WHERE plane='pbs' AND k=?", (f"whole:{owner}",)).fetchone()[0])


def _read_at(cfg, at):
    path, _, ns = at.partition("?ns=")
    _read(cfg, path, args={"ns": ns} if ns else _sync_all(path))


@pytest.mark.parametrize("at,owner,later,bad", _KEYED_CASES, ids=[f"{c[0]} {json.dumps(c[3])}" for c in _KEYED_CASES])
def test_a_pbs_list_with_a_row_it_cannot_key_retires_nothing(cfg, vendor, monkeypatch, at, owner, later, bad):
    _see_all(cfg)
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _feed_all(cfg)
    _read(cfg, "/config/sync", _sync_all("/config/sync"))                # the one way of asking that owns it
    assert _whole_at(cfg, owner) == 1_000_000.0                          # the first answer owned
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    vendor.bodies[at] = [*later, bad]
    _read_at(cfg, at)
    assert _drops(cfg, owner) == 0
    assert _whole_at(cfg, owner) == 1_000_000.0                          # and this one did not
    monkeypatch.setattr(memory, "_now", lambda: 1_000_120.0)
    vendor.bodies[at] = later                                            # the control: every row keyed
    _read_at(cfg, at)
    assert _drops(cfg, owner) >= 1 and _whole_at(cfg, owner) == 1_000_120.0


def test_the_root_namespace_row_never_stops_the_retiring(cfg, vendor):
    """Every namespace list carries the root as the vendor's own `""`: named, never kept, and no reason
    to stop owning, or a healthy datastore's namespaces would never retire again."""
    _see_all(cfg)
    _feed_all(cfg)
    vendor.bodies["/admin/datastore/tank/namespace"] = [{"ns": ""}, {"ns": "prod"}]
    _read(cfg, "/admin/datastore/tank/namespace")
    assert _gone(cfg, "prod/web") and not _gone(cfg, "namespace prod")


def test_a_keyable_row_beside_an_unkeyable_one_is_still_kept(cfg, vendor):
    _see_all(cfg)
    _feed_all(cfg)
    vendor.bodies["/config/remote"] = [{"name": "fresh", "host": "fresh.example", "auth-id": "sync@pbs"},
                                       {"bogus": 1}]
    _read(cfg, "/config/remote")
    assert _where(cfg, "fresh")["verdict"] == "found" and not _gone(cfg, "offsite")


@pytest.mark.parametrize("at,bad", [
    ("/admin/datastore", {"bogus": 1}), ("/config/datastore", {"store": "tank"}),
    ("/admin/datastore/tank/namespace", {"ns": None}), ("/admin/datastore/tank/groups", {"backup-type": "vm"}),
    ("/admin/datastore/tank/groups?ns=prod", {"backup-id": "200"}), ("/config/remote", {"host": "x.example"}),
    ("/config/sync", {"store": "cold"}), ("/config/verify", {"bogus": 1}), ("/config/prune", {"bogus": 1})])
def test_a_pbs_learn_is_incomplete_when_a_list_it_read_could_not_own(cfg, vendor, at, bad):
    """Such a list retires nothing; learn must not then say complete, or a thing truly removed stays found
    and nothing says so."""
    assert memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)["complete"] is True
    clean = vendor.bodies[at]
    vendor.bodies[at] = [*clean, bad]
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    what = at.replace("?ns=prod", " (ns prod)")
    assert out["complete"] is False and f"GET {what} was read but could not own its list" in out["why"], out
    vendor.bodies[at] = clean                                            # the control: every row keyed
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is True, out.get("why")


def test_a_pbs_list_without_its_sight_is_named_once_by_its_sight(cfg, vendor):
    """A list the token does not see whole owns nothing whatever its rows hold: the sight gap already says
    so, and the could-not-own line is for a list that had its sight."""
    vendor.bodies["/access/permissions"] = NO_REMOTE_AUDIT
    vendor.bodies["/config/remote"] = [{"bogus": 1}]
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "Remote.Audit" in out["why"]
    assert "could not own" not in out["why"] and "more)" not in out["why"], out


@pytest.mark.parametrize("row", ["x", None, 7, ["vm/105"]])
def test_a_row_that_is_no_record_names_nothing(row):
    for template in memory_pbs.FEEDS:
        assert memory_pbs._row_id(template, row) is None


def test_a_token_swapped_after_the_permission_map_leaves_no_complete_learn(cfg, vendor):
    """Lens on a79bb9a (older than the branch): the gap was judged by the token served at the END of the
    pass, so a swap after the map left every list unowned and learn complete."""
    assert memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)["complete"] is True
    real = vendor.call

    def swapping(method, path, params=None):
        if path == "/admin/datastore":
            _serve(cfg, TOKEN_B, SECRET_B)
        return real(method, path, params)
    vendor.call = swapping
    vendor.bodies["/config/remote"] = []
    out = memory.learn("pbs", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "could not own its list" in out["why"], out
    assert not _gone(cfg, "offsite")
