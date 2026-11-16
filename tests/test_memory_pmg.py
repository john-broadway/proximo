"""PMG's shape for the estate memory (core/memory_pmg.py): relay domains, transports, trusted
networks, TLS policies, DKIM domains, rules and their who/what/when/action objects, PBS remotes,
nodes and users, kept in the vendor's own words and answered by its own ids. Field names are the
ones a live PMG 9.1 answered (`domain`, `cidr`, `destination`, `policy`, `id`, `name`, `priority`,
`active`, `direction`, `otype_text`, `remote`, `server`, `datastore`, `node`, `userid`, `username`,
`role`, `realm`, `enable`); every value here is invented and the box is unreachable by construction.

What the live box showed, which these tests hold: every config list answers a role it lets in whole
and refuses the rest with a 403, so a whole read owns its list; the users list FILTERS (a quarantine
manager sees only itself), so it owns only after a learn that read the credential's own role.
"""
from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass

import pytest

from proximo.core import arm, engine, memory, memory_pmg, wire
from proximo.core.doors import cli

BOX = "https://unreachable.invalid:8006/api2/json"
ME = "invented@pmg"
PASSWORD = "PLANTED-PASSWORD-PMG-0000"

PMG = {
    # the vendor publishes `comment` on every row of this list (the one JSON's `row`); a domain with no comment
    # answers it empty: PMG's own reader builds each row as `{ domain, comment }` from `my $comment = ''`
    # (PMG/Config.pm on the lab's PMG 9.1, read 2026-11-13)
    "/config/domains": [{"domain": "example.com", "comment": "PLANTED-COMMENT"},
                        {"domain": "example.org", "comment": ""}],
    "/config/transport": [{"domain": "example.com", "host": "192.0.2.10", "port": "25", "protocol": "smtp",
                           "use_mx": 0, "comment": "PLANTED-COMMENT"}],
    "/config/mynetworks": [{"cidr": "192.0.2.0/24", "comment": "PLANTED-COMMENT"}],
    "/config/tlspolicy": [{"destination": "example.net", "policy": "encrypt"}],
    "/config/dkim/domains": [{"domain": "example.com", "comment": "PLANTED-COMMENT"}],
    "/config/ruledb/rules": [
        {"id": "4", "name": "Blocklist", "priority": 98, "active": 1, "direction": 0,
         "from": [{"id": 2, "info": "Global blocklist", "name": "Blocklist"}], "to": [], "what": [], "when": [],
         "action": [{"id": 18, "info": "Block mail", "name": "Block"}]},
        {"id": "2", "name": "Block Viruses", "priority": 96, "active": 1, "direction": 0, "from": [], "to": [],
         "what": [{"id": 9, "info": "Matches virus infected mail", "name": "Virus"}], "when": [], "action": []},
    ],
    "/config/ruledb/action/objects": [{"id": "17_30", "name": "Accept", "ogroup": "17", "otype": 4000,
                                       "otype_text": "Accept", "descr": "accept message", "editable": 0,
                                       "info": "Accept mail for Delivery"}],
    "/config/ruledb/who": [{"id": "2", "name": "Blocklist", "info": "Global blocklist"},
                           {"id": "219", "name": "senders", "info": "PLANTED-INFO"}],
    "/config/ruledb/what": [{"id": "9", "name": "Virus", "info": "Matches virus infected mail"}],
    "/config/ruledb/when": [{"id": "4", "name": "Office Hours", "info": "Usual office hours"}],
    "/config/pbs": [{"remote": "offsite", "server": "192.0.2.20", "datastore": "store1", "username": "sync@pbs",
                     "disable": 1}],
    "/nodes": [{"node": "mx1"}],
    "/config/cluster/status": [],                 # the vendor's default on a node with no cluster
    "/config/cluster/status?list_single_node=1": [{"cid": "0", "name": "mx1", "type": "-", "ip": "192.0.2.5",
                                                   "insync": 1, "fingerprint": "-", "hostrsapubkey": "-"}],
    "/access/users": [{"userid": ME, "username": "invented", "realm": "pmg", "role": "audit", "enable": "1",
                       "expire": 0},
                      {"userid": "root@pam", "username": "root", "realm": "pam", "role": "root", "enable": 1,
                       "expire": 0, "comment": "Unix Superuser"}],
    f"/access/users/{ME}": {"userid": ME, "username": "invented", "realm": "pmg", "role": "audit", "enable": "1",
                            "expire": 0},
}

#: Every list the shape feeds, each with a word of what it lists and the kind it is kept as.
LISTS = [
    ("/config/domains", "example.org", "domain"),
    ("/config/transport", "transport example.com", "transport"),
    ("/config/mynetworks", "192.0.2.0/24", "mynetwork"),
    ("/config/tlspolicy", "example.net", "tlspolicy"),
    ("/config/dkim/domains", "dkim-domain example.com", "dkim-domain"),
    ("/config/ruledb/rules", "rule 4", "rule"),
    ("/config/ruledb/action/objects", "17_30", "action"),
    ("/config/ruledb/who", "219", "who"),
    ("/config/ruledb/what", "what 9", "what"),
    ("/config/ruledb/when", "when 4", "when"),
    ("/config/pbs", "offsite", "pbs"),
    ("/nodes", "mx1", "node"),
    ("/access/users", "root@pam", "user"),
]


class _Wire:
    """The vendor, by path (and any parameter, spelled `?k=v`). A path it does not hold answers a
    500-shaped failure."""

    def __init__(self, bodies):
        self.bodies, self.calls = dict(bodies), []

    def call(self, method, path, params=None):
        at = path + "".join(f"?{k}={v}" for k, v in sorted((params or {}).items()))
        self.calls.append(at)
        if at not in self.bodies:
            raise RuntimeError(f"vendor down for {at}")
        return self.bodies[at]


@dataclass(frozen=True)
class _Cfg(wire.Plane):
    audit_log_path: str = ""
    audit_key_path: str | None = None


def _serve(cfg, user, password=PASSWORD):
    """Swap the served credential file (user@realm, then the password), as arm and disarm do."""
    with open(cfg.token_path, "w") as f:
        f.write(f"{user}\n{password}\n")


@pytest.fixture
def cfg(tmp_path):
    cred = tmp_path / "pmg.credential"
    cred.write_text(f"{ME}\n{PASSWORD}\n")
    cred.chmod(0o600)
    return _Cfg("pmg", BOX, str(cred), credential=True, audit_log_path=str(tmp_path / "audit.log"))


@pytest.fixture
def vendor(monkeypatch):
    w = _Wire(PMG)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    return w


def _read(cfg, path, args=None, **kw):
    return engine.execute(engine.resolve("pmg", "GET", path), dict(args or {}), cfg=cfg, ledger_cfg=cfg,
                          path=path, **kw)


def _where(cfg, words, **kw):
    return memory.where(cfg.audit_log_path, "pmg", BOX, words, **kw)


def _db(cfg):
    return sqlite3.connect(memory.path(cfg.audit_log_path))


def _held(cfg) -> bytes:
    """Every byte the memory file and its sidecars hold."""
    p = memory.path(cfg.audit_log_path)
    return b"".join(open(f, "rb").read() for f in (p, p + "-wal", p + "-journal") if os.path.exists(f))


def _gone(cfg, words):
    [m] = _where(cfg, words)["matches"]
    return m["status"] == "gone"


def _see_users(cfg):
    """What a learn by a credential whose role sees every user leaves: the users sight, for the served
    user. The id is the production reader's, never spelled here."""
    db = memory._open(cfg.audit_log_path, create=True)
    assert db is not None
    with db:
        memory._set(db, "pmg", BOX, "users_sight", f"whole:{arm.served_id(cfg)}")
    memory._settle(cfg.audit_log_path)


# --- the seam -------------------------------------------------------------------------------------

def test_pmg_is_registered_with_its_own_feeds():
    assert memory.shape("pmg") is memory_pmg.SHAPE
    assert memory.feeds("pmg") == memory_pmg.FEEDS
    assert memory_pmg.SHAPE.answers_uses is False
    assert memory_pmg.SHAPE.no_ident_kinds == frozenset() and memory_pmg.SHAPE.no_name_kinds == frozenset()


def test_every_kind_is_a_vendor_word_in_the_order_shown():
    assert memory_pmg.VENDOR_KINDS == frozenset(memory_pmg.KIND_ORDER) == {k for _, _, k in LISTS}


def test_a_miss_points_at_the_relay_domains(cfg, vendor):
    _read(cfg, "/config/domains")
    assert _where(cfg, "nothing-here")["next"] == ["GET /config/domains"]
    assert memory.where(cfg.audit_log_path, "pmg", "https://never.invalid:8006/api2/json", "x")["next"] == \
        ["GET /config/domains"]                                  # an empty memory too


def test_changed_begins_at_the_relay_domain_list(cfg, vendor):
    _read(cfg, "/config/transport")                              # fed, but not the domain list
    out = memory.changed(cfg.audit_log_path, "pmg", BOX, "1h")
    assert out["began"] is None and "no_whole_read" in out["codes"]
    _read(cfg, "/config/domains")
    out = memory.changed(cfg.audit_log_path, "pmg", BOX, "1h")
    assert out["began"] is not None and "no_whole_read" not in out["codes"]


# --- each kind, fed and found by its vendor id ----------------------------------------------------

PATHS = {
    "example.org": ["GET /config/domains/example.org"],
    "transport example.com": ["GET /config/transport/example.com"],
    "192.0.2.0/24": ["GET /config/mynetworks"],                  # a cidr's `/` is no path piece: its list
    "example.net": ["GET /config/tlspolicy/example.net"],
    "dkim-domain example.com": ["GET /config/dkim/domains/example.com"],
    "rule 4": ["GET /config/ruledb/rules/4/config"],
    "17_30": ["GET /config/ruledb/action/objects"],
    "219": ["GET /config/ruledb/who/219/objects"],
    "what 9": ["GET /config/ruledb/what/9/objects"],
    "when 4": ["GET /config/ruledb/when/4/objects"],
    "offsite": ["GET /config/pbs"],                              # the per-remote read failed live: its list
    "mx1": ["GET /nodes/mx1/status"],
    "root@pam": ["GET /access/users"],                           # a userid's `@` is no path piece: its list
}


@pytest.mark.parametrize("template,words,kind", LISTS, ids=[t for t, _, _ in LISTS])
def test_each_kind_is_fed_and_found_by_its_vendor_id(cfg, vendor, template, words, kind):
    _read(cfg, template)
    out = _where(cfg, words)
    assert out["verdict"] == "found", out
    [m] = [m for m in out["matches"] if m["kind"] == kind]
    assert m["id"] == words.split(" ")[-1]
    assert m["paths"] == PATHS[words]


def test_every_path_handed_out_is_published():
    for paths in PATHS.values():
        for p in paths:
            assert memory._published("pmg", p.removeprefix("GET ")), p


def test_an_id_no_path_piece_may_carry_hands_out_its_list(cfg, vendor):
    vendor.bodies["/config/tlspolicy"] = [{"destination": "[192.0.2.1]:25", "policy": "encrypt"}]
    _read(cfg, "/config/tlspolicy")
    [m] = _where(cfg, "[192.0.2.1]:25")["matches"]
    assert m["paths"] == ["GET /config/tlspolicy"]


def test_a_name_finds_rules_and_objects_in_the_vendors_kind_order(cfg, vendor):
    _read(cfg, "/config/ruledb/rules")
    _read(cfg, "/config/ruledb/who")
    out = _where(cfg, "Blocklist")
    assert [(m["kind"], m["id"]) for m in out["matches"]] == [("rule", "4"), ("who", "2")]


def test_a_bare_id_shared_by_a_rule_and_a_when_group_is_both_in_kind_order(cfg, vendor):
    _read(cfg, "/config/ruledb/when")
    _read(cfg, "/config/ruledb/rules")
    assert [(m["kind"], m["id"]) for m in _where(cfg, "4")["matches"]] == [("rule", "4"), ("when", "4")]
    assert [m["kind"] for m in _where(cfg, "when 4")["matches"]] == ["when"]


def test_a_user_answers_to_its_userid_and_its_username(cfg, vendor):
    _read(cfg, "/access/users")
    assert [m["id"] for m in _where(cfg, "root")["matches"]] == ["root@pam"]
    assert [m["id"] for m in _where(cfg, "user root@pam")["matches"]] == ["root@pam"]


def test_a_name_of_two_words_is_found_by_its_id_only(cfg, vendor):
    """`where` takes one token, or a type word then one: a name with a space is no shape it answers,
    so the vendor's id finds the rule, and its name rides in the answer."""
    _read(cfg, "/config/ruledb/rules")
    assert _where(cfg, "Block Viruses")["verdict"] == "not_in_memory"
    [m] = _where(cfg, "rule 2")["matches"]
    assert m["name"] == "Block Viruses"


def test_a_word_that_is_not_a_vendor_type_finds_nothing(cfg, vendor):
    _read(cfg, "/config/domains")
    assert _where(cfg, "relay example.org")["verdict"] == "not_in_memory"
    assert _where(cfg, "Example.org")["verdict"] == "not_in_memory"      # case is the vendor's
    assert _where(cfg, "example")["verdict"] == "not_in_memory"          # no prefix


# --- Review Focus 3: a domain and a transport share a spelling -----------------------------------

def test_a_domain_and_its_transport_both_match_in_the_vendors_order_each_with_its_path(cfg, vendor):  # RF3
    _read(cfg, "/config/dkim/domains")
    _read(cfg, "/config/transport")
    _read(cfg, "/config/domains")
    out = _where(cfg, "example.com")
    assert [(m["kind"], m["paths"]) for m in out["matches"]] == [
        ("domain", ["GET /config/domains/example.com"]),
        ("transport", ["GET /config/transport/example.com"]),
        ("dkim-domain", ["GET /config/dkim/domains/example.com"])]
    assert [m["kind"] for m in _where(cfg, "transport example.com")["matches"]] == ["transport"]


# --- Review Focus 2: a rule shows its name and priority, no edge invented -------------------------

def test_a_rule_shows_its_name_and_priority_as_the_vendor_gives_them(cfg, vendor):                     # RF2
    _read(cfg, "/config/ruledb/rules")
    [m] = _where(cfg, "rule 4")["matches"]
    assert (m["id"], m["name"], m["priority"], m["active"], m["direction"]) == ("4", "Blocklist", 98, 1, 0)


def test_a_rule_relates_nothing(cfg, vendor):
    _read(cfg, "/config/ruledb/rules")
    _read(cfg, "/config/ruledb/who")
    with _db(cfg) as db:
        assert db.execute("SELECT count(*) FROM edge WHERE plane='pmg'").fetchone() == (0,)
    with pytest.raises(memory.Unusable, match="relates nothing on pmg"):
        memory.uses(cfg.audit_log_path, "pmg", BOX, "Blocklist")


def test_changed_names_a_rule_by_its_vendor_id_and_priority(cfg, vendor):
    _read(cfg, "/config/ruledb/rules")
    vendor.bodies["/config/ruledb/rules"] = PMG["/config/ruledb/rules"][1:]
    _read(cfg, "/config/ruledb/rules")
    [g] = memory.changed(cfg.audit_log_path, "pmg", BOX, "1h")["gone"]
    assert (g["kind"], g["id"], g["name"], g["priority"]) == ("rule", "4", "Blocklist", 98)


# --- Review Focus 4: the single node --------------------------------------------------------------

def test_the_single_node_is_kept_from_the_node_list(cfg, vendor):                                     # RF4
    _read(cfg, "/nodes")
    [m] = _where(cfg, "node mx1")["matches"]
    assert m["paths"] == ["GET /nodes/mx1/status"]


def test_the_cluster_status_lists_the_single_node_only_when_asked(cfg, vendor):                      # RF4
    _read(cfg, "/config/cluster/status")
    assert _where(cfg, "mx1")["verdict"] == "not_in_memory"           # the vendor's default lists nothing
    _read(cfg, "/config/cluster/status", {"list_single_node": 1})
    assert _where(cfg, "mx1")["verdict"] == "found"


def test_an_empty_cluster_status_never_retires_the_node(cfg, vendor):                                # RF4
    _read(cfg, "/nodes")
    _read(cfg, "/config/cluster/status", {"list_single_node": 1})
    _read(cfg, "/config/cluster/status")                               # [] on a node with no cluster
    assert not _gone(cfg, "mx1")


def test_an_empty_node_list_never_retires_the_node(cfg, vendor):
    _read(cfg, "/nodes")
    vendor.bodies["/nodes"] = []
    _read(cfg, "/nodes")
    assert not _gone(cfg, "mx1")


def test_a_node_list_without_the_node_retires_it(cfg, vendor):                                        # control
    _read(cfg, "/nodes")
    vendor.bodies["/nodes"] = [{"node": "mx2"}]
    _read(cfg, "/nodes")
    assert _gone(cfg, "mx1")


# --- owning: a config list a role reads at all, it reads whole ------------------------------------

@pytest.mark.parametrize("template,words,kind", [c for c in LISTS if c[0] not in ("/nodes", "/access/users")],
                         ids=[t for t, _, _ in LISTS if t not in ("/nodes", "/access/users")])
def test_a_whole_config_read_without_a_thing_retires_it(cfg, vendor, template, words, kind):
    _read(cfg, template)
    vendor.bodies[template] = []
    _read(cfg, template)
    assert _gone(cfg, words)


# --- I1: absent is not proof; a list with a row memory cannot key retires nothing -----------------

UNKEYABLE = [[{"bogus": 1}], ["x"], [None], [{"domain": None}], [{"domain": ""}], [{"domain": 5.5}],
             [{"domain": True}], [{"domain": ["example.org"]}]]


@pytest.mark.parametrize("body", UNKEYABLE, ids=[json.dumps(b) for b in UNKEYABLE])
def test_a_config_list_with_a_row_it_cannot_key_retires_nothing(cfg, vendor, body):
    _read(cfg, "/config/domains")
    vendor.bodies["/config/domains"] = body
    _read(cfg, "/config/domains")
    assert not _gone(cfg, "example.org") and not _gone(cfg, "domain example.com")


@pytest.mark.parametrize("template,fresh,words", [                    # `fresh`: a row as the vendor publishes it
    ("/config/domains", {"domain": "fresh-1", "comment": ""}, "example.org"),
    ("/config/ruledb/rules", {"id": "fresh-1"}, "rule 4"),
    ("/config/pbs", {"remote": "fresh-1", "server": "192.0.2.21", "datastore": "store2"}, "offsite"),
    ("/nodes", {"node": "fresh-1"}, "mx1")])
def test_one_unkeyable_row_beside_a_good_one_retires_nothing_and_the_good_one_is_kept(cfg, vendor, template,
                                                                                      fresh, words):
    _read(cfg, template)
    vendor.bodies[template] = [fresh, {"bogus": 1}]
    _read(cfg, template)
    assert not _gone(cfg, words)
    assert _where(cfg, "fresh-1")["verdict"] == "found"                 # the keyable row still adds
    vendor.bodies[template] = [fresh]                                   # the control: every row keyed
    _read(cfg, template)
    assert _gone(cfg, words)


@pytest.mark.parametrize("body", [[{"bogus": 1}], ["mx1"], [{"node": None}], [{"node": True}]])
def test_a_node_list_with_a_row_it_cannot_key_retires_nothing(cfg, vendor, body):
    _read(cfg, "/nodes")
    vendor.bodies["/nodes"] = body
    _read(cfg, "/nodes")
    assert not _gone(cfg, "mx1")


def test_a_users_list_with_a_row_it_cannot_key_retires_nothing(cfg, vendor):
    _see_users(cfg)
    _read(cfg, "/access/users")
    vendor.bodies["/access/users"] = [PMG["/access/users"][0], {"bogus": 1}]
    _read(cfg, "/access/users")
    assert not _gone(cfg, "root@pam")
    vendor.bodies["/access/users"] = [PMG["/access/users"][0]]           # the control
    _read(cfg, "/access/users")
    assert _gone(cfg, "root@pam")


@pytest.mark.parametrize("template,args,fields,box,evaluating,data,owner", [
    ("/config/domains", {}, None, BOX, False, [], "/config/domains"),
    ("/config/ruledb/rules", {}, None, BOX, False, [], "/config/ruledb/rules"),
    ("/config/pbs", {}, None, BOX, False, [], "/config/pbs"),
    ("/nodes", {}, None, BOX, False, [{"node": "mx1"}], "/nodes"),
    ("/nodes", {}, None, BOX, False, [], None),                         # never empty on a live box
    ("/config/cluster/status", {}, None, BOX, False, [{"name": "mx1"}], None),   # adds only
    ("/config/cluster/status", {"list_single_node": 1}, None, BOX, False, [{"name": "mx1"}], None),
    ("/config/domains", {"x": 1}, None, BOX, False, [], None),           # an argument narrows it
    ("/config/domains", {}, "domain", BOX, False, [], None),             # a field subset
    ("/config/domains", {}, None, BOX, True, [], None),                  # the door's own look
    ("/config/domains", {}, None, "", False, [], None),                  # a box with no name
    ("/config/domains", {}, None, BOX, False, {"x": 1}, None),           # not a list
])
def test_only_a_whole_read_owns_its_list(cfg, template, args, fields, box, evaluating, data, owner):
    with _db(cfg) as db:
        assert memory_pmg.SHAPE.owner(template, {}, args, fields, data, box, evaluating, db=db,
                                      who=arm.served_id(cfg)) == owner


def test_the_engines_own_evaluating_read_retires_nothing(cfg, vendor):
    _read(cfg, "/config/domains")
    vendor.bodies["/config/domains"] = []
    _read(cfg, "/config/domains", evaluating=True)
    assert not _gone(cfg, "example.org")
    _read(cfg, "/config/domains")                                        # the control
    assert _gone(cfg, "example.org")


# --- the users list filters: it owns only with the credential's sight -----------------------------

def test_without_a_learn_the_users_list_retires_nothing(cfg, vendor):
    _read(cfg, "/access/users")
    vendor.bodies["/access/users"] = [PMG["/access/users"][0]]           # what a quarantine manager sees
    _read(cfg, "/access/users")
    assert not _gone(cfg, "root@pam")


def test_with_the_users_sight_a_whole_users_read_retires(cfg, vendor):
    _see_users(cfg)
    _read(cfg, "/access/users")
    vendor.bodies["/access/users"] = [PMG["/access/users"][0]]
    _read(cfg, "/access/users")
    assert _gone(cfg, "root@pam")


@pytest.mark.parametrize("role", ["audit", "admin", "root", "helpdesk"])
def test_a_learn_by_a_role_that_sees_every_user_owns_the_users_list(cfg, vendor, role):
    vendor.bodies[f"/access/users/{ME}"] = {**PMG[f"/access/users/{ME}"], "role": role}
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is True, out.get("why")
    vendor.bodies["/access/users"] = [PMG["/access/users"][0]]
    _read(cfg, "/access/users")
    assert _gone(cfg, "root@pam")


@pytest.mark.parametrize("role", ["qmanager", "Audit", "", None, 1, "operator", ["admin"], {"admin": 1}])
def test_a_learn_by_any_other_role_owns_no_users_and_says_so(cfg, vendor, role):
    vendor.bodies[f"/access/users/{ME}"] = {**PMG[f"/access/users/{ME}"], "role": role}
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "every user" in out["why"]
    vendor.bodies["/access/users"] = [PMG["/access/users"][0]]
    _read(cfg, "/access/users")
    assert not _gone(cfg, "root@pam")
    assert "partial_sight" in memory.changed(cfg.audit_log_path, "pmg", BOX, "1h")["codes"]


def test_a_role_from_another_users_record_is_no_sight(cfg, vendor):
    vendor.bodies[f"/access/users/{ME}"] = {**PMG[f"/access/users/{ME}"], "userid": "root@pam"}
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False
    with _db(cfg) as db:
        assert db.execute("SELECT v FROM meta WHERE k='users_sight'").fetchall() == [("partial",)]


def test_an_unreadable_own_record_is_no_sight(cfg, vendor):
    del vendor.bodies[f"/access/users/{ME}"]
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and f"/access/users/{ME}" in out["why"]
    with _db(cfg) as db:
        assert db.execute("SELECT v FROM meta WHERE k='users_sight'").fetchall() == [("partial",)]


def test_a_later_learn_that_cannot_read_the_own_record_stops_the_retiring(cfg, vendor):
    memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    del vendor.bodies[f"/access/users/{ME}"]
    assert memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)["complete"] is False
    vendor.bodies["/access/users"] = [PMG["/access/users"][0]]
    _read(cfg, "/access/users")
    assert not _gone(cfg, "root@pam")


def test_learn_reads_the_callers_own_record_before_any_list(cfg, vendor):
    memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert vendor.calls[0] == f"/access/users/{ME}"
    assert vendor.calls.index("/access/users") > 0


def test_a_sighted_learn_alone_begins_changed_and_says_no_partial_sight(cfg, vendor):
    memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    out = memory.changed(cfg.audit_log_path, "pmg", BOX, "1h")
    assert out["began"] is not None and "no_whole_read" not in out["codes"] and "partial_sight" not in out["codes"]


def test_a_sight_learned_by_one_user_never_owns_for_another(cfg, vendor):
    memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    _serve(cfg, "other@pmg")
    vendor.bodies["/access/users"] = [PMG["/access/users"][0]]
    _read(cfg, "/access/users")
    assert not _gone(cfg, "root@pam")


def test_a_credential_swapped_while_learn_reads_the_own_record_raises_no_sight(cfg, vendor, monkeypatch):
    real = vendor.call

    def swapping(method, path, params=None):
        out = real(method, path, params)
        if path == f"/access/users/{ME}":
            _serve(cfg, "other@pmg")
        return out
    monkeypatch.setattr(vendor, "call", swapping)
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "hold steady" in out["why"]
    with _db(cfg) as db:
        assert db.execute("SELECT v FROM meta WHERE k='users_sight'").fetchall() == [("partial",)]


@pytest.mark.parametrize("who", [None, "", "garbage", "a@b!c", "a b@pmg", "x" * 200 + "@pmg"])
def test_an_unknown_or_unparseable_user_owns_no_users(cfg, who):
    """The flag names this very user and the answer shows its own row with a role that sees every user:
    only the user's own shape can refuse it."""
    _see_users(cfg)
    with _db(cfg) as db:
        with db:
            memory._set(db, "pmg", BOX, "users_sight", f"whole:{who}")
        data = [{"userid": who, "role": "audit"}]
        assert memory_pmg.SHAPE.owner("/access/users", {}, {}, None, data, BOX, False, db=db, who=who) is None


# --- C1: a role is the box admin's to change after a learn; the answer shows the role it was read under

def test_a_user_demoted_since_the_learn_retires_no_one(cfg, vendor):
    assert memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)["complete"] is True
    vendor.bodies["/access/users"] = [{**PMG["/access/users"][0], "role": "qmanager"}]   # what it sees now
    _read(cfg, "/access/users")
    assert not _gone(cfg, "root@pam")


@pytest.mark.parametrize("data", [
    [],                                                                       # no own row
    [{"userid": "root@pam", "role": "root"}],                                 # another user's row only
    [{"userid": ME, "role": "qmanager"}],
    [{"userid": ME}],                                                         # no role
    [{"userid": ME, "role": None}],
    [{"userid": ME, "role": "Audit"}],
    [{"userid": ME, "role": ["admin"]}],                                      # not a word: never raises
    [{"userid": ME, "role": {"admin": 1}}],
    [{"userid": ME, "role": "audit"}, {"userid": ME, "role": "audit"}],       # two own rows: no one row
])
def test_a_users_answer_owns_only_when_its_own_row_shows_a_role_that_sees_every_user(cfg, data):
    _see_users(cfg)
    with _db(cfg) as db:
        assert memory_pmg.SHAPE.owner("/access/users", {}, {}, None, data, BOX, False, db=db, who=ME) is None
        assert memory_pmg.SHAPE.owner("/access/users", {}, {}, None, [{"userid": ME, "role": "audit"}], BOX,
                                      False, db=db, who=ME) == "/access/users"          # the control


def test_a_learn_by_the_demoted_user_retires_no_one_and_a_whole_learn_lists_the_gone_again(cfg, vendor):
    """What memory holds after a demotion: a user retired by a true whole read stays gone; a learn by the
    demoted user is incomplete and retires no one more; a read that lists the gone user (a whole learn's,
    or any read at all) brings it back."""
    keep = {"userid": "keep@pmg", "username": "keep", "realm": "pmg", "role": "helpdesk", "enable": 1}
    vendor.bodies["/access/users"] = [*PMG["/access/users"], keep]
    assert memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)["complete"] is True
    vendor.bodies["/access/users"] = [PMG["/access/users"][0], keep]             # root@pam truly removed
    _read(cfg, "/access/users")
    assert _gone(cfg, "root@pam") and not _gone(cfg, "keep@pmg")
    demoted = {**PMG[f"/access/users/{ME}"], "role": "qmanager"}
    vendor.bodies[f"/access/users/{ME}"], vendor.bodies["/access/users"] = demoted, [demoted]
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "(qmanager)" in out["why"]
    assert _gone(cfg, "root@pam") and not _gone(cfg, "keep@pmg")                # no one more retired
    vendor.bodies[f"/access/users/{ME}"] = PMG[f"/access/users/{ME}"]          # an auditor again
    vendor.bodies["/access/users"] = [*PMG["/access/users"], keep]
    assert memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)["complete"] is True
    assert not _gone(cfg, "root@pam") and not _gone(cfg, "keep@pmg")


def test_any_read_that_lists_a_gone_user_brings_it_back(cfg, vendor):
    _see_users(cfg)
    _read(cfg, "/access/users")
    vendor.bodies["/access/users"] = [PMG["/access/users"][0]]
    _read(cfg, "/access/users")
    assert _gone(cfg, "root@pam")
    _serve(cfg, "other@pmg")                                                     # no sight: it only adds
    vendor.bodies["/access/users"] = PMG["/access/users"]
    _read(cfg, "/access/users")
    assert not _gone(cfg, "root@pam")


# --- the sight id: the credential file's user, never a secret byte --------------------------------

def test_a_credential_file_is_its_users_id(cfg):
    assert arm.served_id(cfg) == ME


@pytest.mark.parametrize("text", [
    f"{PASSWORD}\n",                               # one line: no user, the password alone
    f"{ME}\n",                                     # no password: not a credential the wire would send
    f"not-a-user\n{PASSWORD}\n",                   # no realm
    f"{ME}!tok\n{PASSWORD}\n",                     # a token id is no PMG user
    f"a b@pmg\n{PASSWORD}\n",
])
def test_a_credential_file_that_names_no_user_is_blind(cfg, text):
    with open(cfg.token_path, "w") as f:
        f.write(text)
    assert arm.served_id(cfg) is None


def test_a_password_file_names_no_one_even_when_it_looks_like_an_id(tmp_path):
    """Password mode: the file IS the password. Whatever it spells, it is never handed out as an id."""
    pw = tmp_path / "pmg.password"
    pw.write_text("looks@like!an-id:or-a-user@pmg\n")
    assert arm.served_id(_Cfg("pmg", BOX, str(pw), credential=False)) is None
    pw.write_text("looks@pmg\n")
    assert arm.served_id(_Cfg("pmg", BOX, str(pw), credential=False)) is None
    pw.write_text("looks@pmg\nand-a-second-line\n")                   # the credential file's shape, not its mode
    assert arm.served_id(_Cfg("pmg", BOX, str(pw), credential=False)) is None
    assert arm.served_id(_Cfg("pmg", BOX, str(pw), credential=True)) == "looks@pmg"     # the control


# --- Review Focus 5: secrets and free text never reach the file -----------------------------------

def test_no_planted_secret_or_comment_reaches_the_memory_file(cfg, vendor):                          # RF5
    vendor.bodies["/config/pbs"] = [{**PMG["/config/pbs"][0], "password": "PLANTED-PBS-SECRET",
                                     "encryption-key": "PLANTED-PBS-KEY", "fingerprint": "PLANTED-FP"}]
    vendor.bodies["/access/users"] = [{**u, "crypt_pass": "PLANTED-CRYPT", "keys": "PLANTED-KEYS",
                                       "email": "planted@example.com", "firstname": "PLANTED-FIRST"}
                                      for u in PMG["/access/users"]]
    vendor.bodies[f"/access/users/{ME}"] = {**PMG[f"/access/users/{ME}"], "password": "PLANTED-USER-PW",
                                            "crypt_pass": "PLANTED-CRYPT", "keys": "PLANTED-KEYS"}
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is True, out.get("why")
    assert _where(cfg, "offsite")["verdict"] == "found"                  # the remote itself was kept
    held = _held(cfg)
    assert ME.encode() in held                                           # the public id IS kept: the grep can see
    for planted in (PASSWORD, "PLANTED"):
        assert planted.encode() not in held, planted


def test_a_user_keeps_its_ids_role_realm_and_enable_and_a_remote_keeps_no_user(cfg, vendor):
    """What the public sentence says is kept, and no more: a user's userid and username (both answer
    `where`), its role, realm and enable; a PBS remote's user is never kept."""
    _read(cfg, "/access/users")
    _read(cfg, "/config/pbs")
    with _db(cfg) as db:
        rows = db.execute("SELECT key, name, detail FROM entity WHERE plane='pmg' AND kind='user' AND key=?",
                          (ME,)).fetchall()
    assert [(k, n, sorted(json.loads(d))) for k, n, d in rows] == [(ME, "invented", ["enable", "realm", "role"])]
    assert [m["id"] for m in _where(cfg, "invented")["matches"]] == [ME]
    assert b"sync@pbs" not in _held(cfg)


def test_fetchmail_and_ldap_are_never_fed():
    assert "/config/fetchmail" not in memory_pmg.FEEDS and "/config/ldap" not in memory_pmg.FEEDS


# --- learn ----------------------------------------------------------------------------------------

def test_learn_reads_every_list_and_counts_the_relay_domains(cfg, vendor):
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is True and out["domains"] == 2, out.get("why")
    for template, words, _ in LISTS:
        assert template in vendor.calls
        assert _where(cfg, words)["verdict"] == "found", words


def _learn_sight(cfg):
    with _db(cfg) as db:
        return db.execute("SELECT v FROM meta WHERE plane='pmg' AND k='learn_sight'").fetchone()[0]


@pytest.mark.parametrize("template,body,words,clean", [
    ("/config/domains", [{"domain": "fresh", "comment": ""}, {"bogus": 1}], "example.org",
     [{"domain": "fresh", "comment": ""}]),
    ("/nodes", [{"node": "mx2"}, {"bogus": 1}], "mx1", [{"node": "mx2"}]),
    ("/access/users", [*PMG["/access/users"][:1], {"bogus": 1}], "root@pam", PMG["/access/users"][:1]),
])
def test_a_learn_is_incomplete_when_a_list_it_read_could_not_own(cfg, vendor, template, body, words, clean):
    """Absent is not proof, so such a list retires nothing; learn must not then say complete, or a thing
    truly removed stays found and nothing says so."""
    assert memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)["complete"] is True
    vendor.bodies[template] = body
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and f"GET {template} was read but could not own its list" in out["why"]
    assert not _gone(cfg, words)
    vendor.bodies[template] = clean                                      # the control: every row keyed
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is True, out.get("why")
    assert _gone(cfg, words) and _learn_sight(cfg) == "whole"


def test_a_role_changed_between_the_own_record_and_the_users_list_leaves_no_whole_sight(cfg, vendor):
    vendor.bodies["/access/users"] = [{**PMG["/access/users"][0], "role": "qmanager"}]   # the record says audit
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "GET /access/users was read but could not own its list" in out["why"]
    assert _learn_sight(cfg) == "partial"
    assert "partial_sight" in memory.changed(cfg.audit_log_path, "pmg", BOX, "1h")["codes"]


def test_learn_names_a_list_it_could_not_read(cfg, vendor):
    del vendor.bodies["/config/ruledb/what"]
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "/config/ruledb/what" in out["why"]


def test_learn_with_a_credential_that_names_no_user_is_not_complete(cfg, vendor):
    _serve(cfg, "no-realm")
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "names no user" in out["why"]
    assert f"/access/users/{ME}" not in vendor.calls                     # nothing read under a bad name


def test_learn_is_not_complete_when_an_id_was_too_long_to_keep(cfg, vendor):
    vendor.bodies["/config/domains"] = [*PMG["/config/domains"], {"domain": "a" * 130 + ".example"}]
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "longer than memory keeps" in out["why"]


def test_learn_stops_at_its_budget_and_still_tallies(cfg, vendor, monkeypatch):
    monkeypatch.setattr(memory, "LEARN_MAX_READS", 2)     # the own record, the domains
    out = memory.learn("pmg", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "read budget" in out["why"] and out["reads"] == 2
    assert out["domains"] == 2


# --- one file, three planes -----------------------------------------------------------------------

def test_pmg_rows_never_answer_another_plane(cfg, vendor):
    _read(cfg, "/config/domains")
    assert memory.where(cfg.audit_log_path, "pbs", BOX, "example.org")["verdict"] == "not_in_memory"
    assert memory.where(cfg.audit_log_path, "pve", BOX, "example.org")["verdict"] == "not_in_memory"


# --- the shell door -------------------------------------------------------------------------------

@pytest.fixture
def pmg_env(cfg, monkeypatch):
    monkeypatch.setenv("PROXIMO_PMG_BASE_URL", BOX)
    monkeypatch.setenv("PROXIMO_PMG_CREDENTIAL_PATH", cfg.token_path)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", cfg.audit_log_path)
    return cfg


def test_the_shell_learns_and_finds_on_pmg(capsys, pmg_env, vendor):
    assert cli.main(["learn", "--plane", "pmg"]) == cli.EXIT_OK
    learned = json.loads(capsys.readouterr().out)
    assert learned["complete"] is True and learned["domains"] == 2, learned.get("why")
    assert cli.main(["where", "--plane", "pmg", "example.com"]) == cli.EXIT_OK
    assert [m["kind"] for m in json.loads(capsys.readouterr().out)["matches"]] == ["domain", "transport",
                                                                                 "dkim-domain"]
    assert cli.main(["changed", "--plane", "pmg", "1h"]) == cli.EXIT_OK
    changed = json.loads(capsys.readouterr().out)
    assert changed["began"] is not None and "no_whole_read" not in changed["codes"]
    assert cli.main(["where", "--plane", "pmg", "nowhere-on-the-box"]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["verdict"] == "not_in_memory"


def test_uses_on_pmg_exits_3_and_says_why(capsys, pmg_env):
    assert cli.main(["uses", "--plane", "pmg", "example.com"]) == cli.EXIT_USAGE
    assert "relates nothing on pmg" in capsys.readouterr().err


@pytest.mark.parametrize("verb", cli.MEMORY_VERBS)
def test_the_plane_help_names_pmg(capsys, verb):
    assert cli.main([verb, "--help"]) == cli.EXIT_OK
    out = " ".join(capsys.readouterr().out.split())
    plane_help = out.rsplit("--plane PLANE", 1)[1].split("--target", 1)[0]
    assert "pmg" in plane_help.replace(",", " ").split() and "(default pve)" in plane_help, out


def test_the_shell_finds_a_typed_word_and_hands_out_a_published_read(capsys, pmg_env, vendor):
    assert cli.main(["learn", "--plane", "pmg"]) == cli.EXIT_OK
    capsys.readouterr()
    assert cli.main(["where", "--plane", "pmg", "dkim-domain", "example.com"]) == cli.EXIT_OK
    [m] = json.loads(capsys.readouterr().out)["matches"]
    assert (m["kind"], m["id"], m["paths"]) == ("dkim-domain", "example.com", ["GET /config/dkim/domains/example.com"])
