"""The may/never map, step 2: the vendor's rule read against what a token holds (core/maynever.py).

Synthetic holdings only: this repo is public, and the evaluator's truth is the vendor's rule plus a
per-path answer, which a dict stands in for exactly.
"""
from __future__ import annotations

import ast
import collections.abc
import dataclasses
import itertools
import os
import pathlib

import pytest

from proximo.core import apitree, maynever
from proximo.core.maynever import FILTERED, MAY, NEVER, UNKNOWN, WORDS

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _answer(*a, wire="http", **k):
    """`wire` is required by the module (lens 2); the vendor's lane unless a test says otherwise."""
    return maynever.answer(*a, wire=wire, **k)


def _at(table):
    """`at` from {path: privileges}; a path mapped to None could not be read."""
    def at(path):
        v = table.get(path, frozenset())
        return None if v is None else frozenset(v)
    return at


# one leaf per answer, each on its own path so the cells never share a holding
LEAF = {
    MAY: ["perm", "/may", ["Sys.Audit"]],
    NEVER: ["perm", "/never", ["Sys.Audit"]],
    WORDS: ["userid-param", "self"],
    UNKNOWN: ["perm", "/unknown", ["Sys.Audit"]],
}
HELD = _at({"/may": {"Sys.Audit"}, "/never": set(), "/unknown": None})

AND = {NEVER: 0, UNKNOWN: 1, WORDS: 2, MAY: 3}      # the lower wins
OR = {MAY: 0, UNKNOWN: 1, WORDS: 2, NEVER: 3}


@pytest.mark.parametrize("head, rank", [("and", AND), ("or", OR)])
@pytest.mark.parametrize("a, b", list(itertools.product(LEAF, repeat=2)))
def test_every_cell_of_the_three_valued_tables(head, rank, a, b):
    """Lens-proofing the prototype's flaw: it read an unknown head as None and then ran all()/any()
    over it, so and(may, words) came out never."""
    got = _answer({"check": [head, LEAF[a], LEAF[b]]}, "pve", "GET", {}, HELD)
    # Lens 5: the vendor reads `or` left to right, and its own rule (LEAF[WORDS] is userid-param) can
    # refuse outright before a later part runs: nothing after it may lift the answer to MAY.
    want = WORDS if (head, a, b) == ("or", WORDS, MAY) else min((a, b), key=rank.get)
    assert got.verdict == want, got


def test_an_or_of_three_with_one_may_is_may_and_an_and_names_every_missing_grant():
    assert _answer({"check": ["or", LEAF[NEVER], LEAF[NEVER], LEAF[MAY]]}, "pve", "GET", {},
                           HELD).verdict == MAY
    two = ["and", ["perm", "/a", ["X.One"]], ["perm", "/b", ["X.Two"]]]
    got = _answer({"check": two}, "pve", "GET", {}, _at({}))
    assert got.verdict == NEVER and "X.One on /a" in got.why and "X.Two on /b" in got.why, got


# ---- the door's order: user first, then check, then no rule --------------------------------------

@pytest.mark.parametrize("rule, method, verdict", [
    ({"user": "all"}, "GET", MAY),
    ({"user": "world"}, "POST", WORDS),                            # a login door: no login, not a token
    ({"user": "world"}, "GET", WORDS),
    ({"user": "all", "description": "Only lists what you may see."}, "GET", FILTERED),
    ({"user": "all", "description": "Only lists what you may see."}, "POST", WORDS),
    ({"user": "all", "description": "Requires the VM.Audit permission on /vms/<vmid>."}, "GET", WORDS),
    ({"user": "all", "description": "You need read access for the volume."}, "GET", WORDS),
    ({"user": "all", "check": LEAF[NEVER]}, "GET", MAY),          # PVE admits `all` before any check
    (None, "GET", NEVER),                                          # no rule: root@pam itself only
    ({"check": LEAF[MAY]}, "PUT", MAY),
    ({"check": LEAF[MAY], "description": "You also need a ticket."}, "GET", WORDS),
    ({"check": LEAF[MAY], "description": "You also need a ticket."}, "DELETE", WORDS),
    ({"check": LEAF[NEVER], "description": "You also need a ticket."}, "GET", NEVER),
    ({"check": LEAF[UNKNOWN]}, "GET", UNKNOWN),
    ({"check": ["perm-modify", "{path}"]}, "PUT", WORDS),
    ({"check": ["userid-group", ["User.Modify"]]}, "PUT", WORDS),
])
def test_the_door_order_and_the_words(rule, method, verdict):
    assert _answer(rule, "pve", method, {}, HELD).verdict == verdict


def test_no_rule_says_why():
    got = _answer(None, "pve", "POST", {}, HELD)
    assert "root@pam" in got.why and "token" in got.why


@pytest.mark.parametrize("product", ["pbs", "pdm", "pmg"])
def test_every_product_admits_every_user_on_user_all(product):
    assert _answer({"user": "all"}, product, "GET", {}, HELD).verdict == MAY


def test_a_pmg_role_rule_is_words_naming_the_roles_until_the_users_role_is_read():
    got = _answer({"check": ["admin", "qmanager"]}, "pmg", "POST", {}, HELD)
    assert got.verdict == WORDS and "admin" in got.why and "qmanager" in got.why and "role" in got.why


# ---- perm, read to its operands ------------------------------------------------------------------

def test_all_privileges_are_needed_and_the_missing_ones_are_named():
    rule = {"check": ["perm", "/vms/{vmid}", ["VM.Audit", "VM.Console"]]}
    got = _answer(rule, "pve", "GET", {"vmid": 100}, _at({"/vms/100": {"VM.Audit"}}))
    assert got.verdict == NEVER and got.why == "VM.Console on /vms/100", got
    assert _answer(rule, "pve", "GET", {"vmid": "100"},
                           _at({"/vms/100": {"VM.Audit", "VM.Console"}})).verdict == MAY


def test_any_one_is_enough_with_the_any_option():
    rule = {"check": ["perm", "/storage/{storage}", ["A.One", "A.Two"], "any", 1]}
    assert _answer(rule, "pve", "GET", {"storage": "s"}, _at({"/storage/s": {"A.Two"}})).verdict == MAY
    got = _answer(rule, "pve", "GET", {"storage": "s"}, _at({}))
    assert got.verdict == NEVER and got.why.startswith("one of A.One, A.Two on /storage/s"), got
    # and without the option, one is not enough
    plain = {"check": ["perm", "/storage/{storage}", ["A.One", "A.Two"]]}
    assert _answer(plain, "pve", "GET", {"storage": "s"}, _at({"/storage/s": {"A.Two"}})).verdict == NEVER


def test_a_privilege_the_vendor_names_twice_is_named_once():
    rule = {"check": ["perm", "/", ["VM.GuestAgent.Unrestricted", "VM.GuestAgent.Unrestricted"]]}
    assert _answer(rule, "pve", "POST", {}, _at({})).why == "VM.GuestAgent.Unrestricted on /"


def test_require_param_is_words():
    rule = {"check": ["perm", "/pool/{pool}", ["Pool.Allocate"], "require_param", "pool"]}
    got = _answer(rule, "pve", "POST", {"pool": "p"}, _at({"/pool/p": {"Pool.Allocate"}}))
    assert got.verdict == WORDS and "pool" in got.why


def test_a_placeholder_no_value_fills_is_words_naming_it_never_the_parents_grant():
    """A parent's grant is no answer for a child a deeper ACL can take it from."""
    rule = {"check": ["perm", "/vms/{vmid}", ["VM.Audit"]]}
    everything = _at({"/": {"VM.Audit"}, "/vms": {"VM.Audit"}})
    for fill in ({}, {"vmid": ""}, {"vmid": None}, {"vmid": 0}, {"vmid": "0"}):      # the vendor fills 0 as -
        got = _answer(rule, "pve", "GET", fill, everything)
        assert got.verdict == WORDS and got.why == "depends on {vmid}: give it", (fill, got)


@pytest.mark.parametrize("value", ["..", "a/../b", "a//b", ".", True, 1.5, ["x"],
                                   "a b", "a:b", "a@b", "\u2603", "a\nb"])
def test_a_value_that_is_no_clean_path_is_words(value):
    rule = {"check": ["perm", "/pool/{pool}", ["Pool.Audit"]]}
    got = _answer(rule, "pve", "GET", {"pool": value}, _at({}))
    assert got.verdict == WORDS and got.why == "{pool} is not a path the vendor's door reads", got


def test_the_root_template_is_the_root_path():
    asked = []
    _answer({"check": ["perm", "/", ["Sys.Audit"]]}, "pve", "GET", {},
                    lambda p: asked.append(p) or frozenset())
    assert asked == ["/"]


def test_a_deeper_acl_that_takes_a_grant_away_is_never():
    """The lab's shape, synthetic names: `/` holds Pool.Audit, the pool's own ACL does not carry it,
    and the vendor answers 403. The per-path answer is the vendor's walk; the map follows it."""
    rule = next(r["permissions"] for r in apitree.published()["rows"]
                if (r["product"], r["method"], r["path"]) == ("pve", "GET", "/pools/{poolid}"))
    held = _at({"/": {"Pool.Audit", "VM.Audit"}, "/pool/lab": {"VM.Audit", "Datastore.Audit"}})
    got = _answer(rule, "pve", "GET", {"poolid": "lab"}, held)
    assert got.verdict == NEVER and got.why == "Pool.Audit on /pool/lab", got


# ---- bounded, as everything a door echoes --------------------------------------------------------

def test_the_why_is_bounded_in_bytes_whatever_the_vendor_or_the_caller_says():
    long = "é" * 5_000
    got = _answer({"user": "all", "description": long}, "pve", "GET", {}, HELD)
    assert len(got.why.encode()) <= maynever.WHY_BYTES
    rule = {"check": ["and"] + [["perm", "/pool/{pool}", [f"P.{i}" * 30]] for i in range(20)]}
    got = _answer(rule, "pve", "GET", {"pool": "p" * 400}, _at({}))
    assert got.verdict == NEVER and len(got.why.encode()) <= maynever.WHY_BYTES


def test_the_bounds_are_pinned_and_one_piece_is_bounded_alone():
    """Lens 1: the byte test compared against WHY_BYTES itself, and no test bound a single piece."""
    assert (maynever.PIECE_BYTES, maynever.WHY_BYTES) == (64, 480)
    got = _answer({"check": ["perm", "/", ["P" * 1000]]}, "pve", "GET", {}, _at({}))
    priv, _, where = got.why.rpartition(" on ")
    assert where == "/" and len(priv.encode()) <= 64 and priv.startswith("PPP"), got


# ---- the whole shipped PVE table -----------------------------------------------------------------

def _pve_rows():
    return [r for r in apitree.published()["rows"] if r["product"] == "pve" and r["wire"] != "ssh"]


def _fill(path):
    return {n: "x" for n in maynever._SLOT.findall(path)}


def _rule_fill(r):
    names = set(maynever._SLOT.findall(r["path"]))
    for t in _templates(r["permissions"]):
        names |= set(maynever._SLOT.findall(t))
    return {n: "x" for n in names}


def _templates(rule):
    out = []

    def walk(c):
        if c[0] in ("and", "or"):
            for x in c[1:]:
                walk(x)
        elif c[0] == "perm":
            out.append(c[1])
    if rule and "check" in rule:
        walk(rule["check"])
    return out


def _privs():
    out = set()

    def walk(c):
        if c[0] in ("and", "or"):
            for x in c[1:]:
                walk(x)
        elif c[0] == "perm":
            out.update(c[2])
    for r in _pve_rows():
        if r["permissions"] and "check" in r["permissions"]:
            walk(r["permissions"]["check"])
    return out


def test_holding_everything_everywhere_leaves_no_never_but_the_root_only_calls():
    every = _privs()
    for r in _pve_rows():
        got = _answer(r["permissions"], "pve", r["method"], _rule_fill(r), lambda p: frozenset(every))
        assert got.verdict != NEVER or r["permissions"] is None, (r["method"], r["path"], got)
        assert got.verdict != UNKNOWN


def test_holding_nothing_makes_every_plain_perm_check_never():
    seen = 0
    for r in _pve_rows():
        rule = r["permissions"]
        plain = rule and set(rule) == {"check"} and rule["check"][0] == "perm" and len(rule["check"]) == 3
        if not plain:
            continue
        seen += 1
        got = _answer(rule, "pve", r["method"], _rule_fill(r), _at({}))
        assert got.verdict == NEVER, (r["method"], r["path"], got)
    assert seen > 300, seen       # measured 2026-11-02: most PVE calls are one plain perm check


def test_every_shipped_pve_rule_answers_one_of_the_five_without_raising():
    for holdings in (_at({}), lambda p: None, lambda p: frozenset(_privs())):
        for r in _pve_rows():
            got = _answer(r["permissions"], "pve", r["method"], _fill(r["path"]), holdings)
            assert got.verdict in maynever.ANSWERS


# ---- the holdings reader -------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class _Plane:
    token_path: str


def _holdings(tmp_path, answers, token=b"t1"):
    tok = tmp_path / "token"
    tok.write_bytes(token)
    calls = []

    def read(path, token):
        calls.append(path)
        v = answers(path)
        if isinstance(v, Exception):
            raise v
        return v
    return maynever.Holdings(_Plane(str(tok)), read=read), calls, tok


def test_one_read_per_path_per_token_and_a_new_token_reads_again(tmp_path):
    h, calls, tok = _holdings(tmp_path, lambda p: {p: {"Sys.Audit": 1}})
    assert h.at("/") == frozenset({"Sys.Audit"})
    assert h.at("/") == frozenset({"Sys.Audit"})
    assert calls == ["/"]
    tok.write_bytes(b"t2")                       # an arm or a renew: the holdings were another token's
    h.at("/")
    assert calls == ["/", "/"]


def test_an_unreadable_token_holds_nothing_known(tmp_path):
    h, calls, tok = _holdings(tmp_path, lambda p: {p: {}})
    tok.unlink()
    assert h.at("/") is None and calls == []


@pytest.mark.parametrize("data", [
    None, [], {}, "x",
    {"/other": {"Sys.Audit": 1}},                       # another key: not the answer for this path
    {"/": {"Sys.Audit": 1}, "/x": {}},
    {"/": ["Sys.Audit"]},
    {"/": {"Sys.Audit": 2}},
    {"/": {"Sys.Audit": True}},
    {"/": {"Sys.Audit": "1"}},
    RuntimeError("403"),
])
def test_anything_but_the_vendors_per_path_answer_is_unknown(tmp_path, data):
    h, _, _ = _holdings(tmp_path, lambda p: data)
    assert h.at("/") is None


def test_the_vendors_answer_is_read_whatever_the_propagate_flag(tmp_path):
    h, _, _ = _holdings(tmp_path, lambda p: {p: {"A": 1, "B": 0}})
    assert h.at("/") == frozenset({"A", "B"})
    h2, _, _ = _holdings(tmp_path, lambda p: {p: {}})
    assert h2.at("/") == frozenset()            # holds nothing there: known, not unknown


def test_the_reader_goes_through_the_engine_receipted(monkeypatch, tmp_path):
    """The default read is one governed `GET /access/permissions?path=` (evaluating, fields=all)."""
    from proximo.core import engine
    seen = {}

    def execute(row, args, **kw):
        seen.update(row=(row.method, row.path), args=args, **kw)
        return {"data": {args["path"]: {"Pool.Audit": 1}}}
    monkeypatch.setattr(engine, "execute", execute)
    tok = tmp_path / "t"
    tok.write_bytes(b"x")
    h = maynever.Holdings(_Plane(str(tok)), ledger_cfg="L")
    assert h.at("/pool/p") == frozenset({"Pool.Audit"})
    assert seen["row"] == ("GET", "/access/permissions") and seen["args"] == {"path": "/pool/p"}
    assert seen["evaluating"] is True and seen["fields"] == "all" and seen["ledger_cfg"] == "L"


# ---- the map governs nothing ---------------------------------------------------------------------

def test_the_map_imports_no_gate():
    """A NEVER still sends: the vendor's 403 is the lock. The module may reach the wire only through
    the engine's read, never a gate or a door."""
    tree = ast.parse((ROOT / "src" / "proximo" / "core" / "maynever.py").read_text())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("proximo"):
            names |= {f"{node.module}.{a.name}" for a in node.names}
        elif isinstance(node, ast.Import):
            names |= {a.name for a in node.names if a.name.startswith("proximo")}
    assert names == {"proximo.core.rawdoor", "proximo.core.engine", "proximo.core.apitree"}, names


# ---- lens 1 on 21eefb7 ---------------------------------------------------------------------------

def test_the_why_of_a_mixed_and_or_names_only_the_deciding_parts():
    got = _answer({"check": ["and", LEAF[WORDS], LEAF[NEVER]]}, "pve", "GET", {}, HELD)
    assert got.verdict == NEVER and got.why == "Sys.Audit on /never", got
    got = _answer({"check": ["or", LEAF[NEVER], LEAF[WORDS]]}, "pve", "GET", {}, HELD)
    assert got.verdict == WORDS and got.why == "the vendor checks userid-param by a rule of its own", got


def test_a_value_with_slashes_is_filled_as_its_segments():
    asked = []
    _answer({"check": ["perm", "/pool/{pool}", ["Pool.Audit"]]}, "pve", "GET", {"pool": "/a/b/"},
                    lambda p: asked.append(p) or frozenset())
    assert asked == ["/pool/a/b"]


def test_a_row_on_proximos_own_lane_is_words_not_the_vendors_never():
    """Lens 1: the ssh-lane rows carry no vendor rule, which read as "root@pam only"."""
    got = _answer(None, "pve", "POST", {}, HELD, wire="ssh")
    assert got.verdict == WORDS and "own lane" in got.why, got


def test_every_ssh_lane_row_is_words():
    rows = [r for r in apitree.published()["rows"] if r["product"] == "pve" and r["wire"] == "ssh"]
    assert rows
    for r in rows:
        assert _answer(r["permissions"], "pve", r["method"], {}, HELD, wire=r["wire"]).verdict == WORDS


@pytest.mark.parametrize("rule", [
    {"check": ["and"]}, {"check": ["or"]}, {"check": []}, "x", 7,
    {"check": ["perm", "/", ["A"], "require_param"]}, {"description": "words alone"},
])
def test_a_malformed_rule_is_words_never_a_raise(rule):
    got = _answer(rule, "pve", "GET", {}, HELD)
    assert got.verdict == WORDS and got.why.startswith("a rule the map cannot read"), got


def test_filtered_is_the_vendors_cut_list_wording_only():
    """Lens 1: 22 reads whose words state a requirement (and 403) were filtered. Measured 2026-11-02."""
    rows = [r for r in _pve_rows() if r["method"] == "GET" and r["permissions"]
            and r["permissions"].get("user") == "all" and r["permissions"].get("description")]
    got = {r["path"]: _answer(r["permissions"], "pve", "GET", _rule_fill(r), HELD).verdict for r in rows}
    assert sum(v == FILTERED for v in got.values()) == 29, sorted(p for p, v in got.items() if v == FILTERED)
    for p in ("/cluster/replication/{id}", "/nodes/{node}/tasks/{upid}/log", "/cluster/sdn/vnets/{vnet}",
              "/nodes/{node}/storage/{storage}/content/{volume}", "/nodes/{node}/qemu/{vmid}/mtunnelwebsocket"):
        assert got[p] == WORDS, p
    for p in ("/nodes/{node}/qemu", "/storage", "/pools", "/access/acl", "/nodes/{node}/tasks"):
        assert got[p] == FILTERED, p


def test_the_whole_table_asks_only_filled_clean_paths():
    """Lens 1: every whole-table holdings ignored its argument; `{route-map-id}` must fill too."""
    asked = set()
    for r in _pve_rows():
        _answer(r["permissions"], "pve", r["method"], _rule_fill(r), lambda p: asked.add(p) or frozenset())
    assert len(asked) > 20 and all("{" not in p and "}" not in p and p.startswith("/") for p in asked), asked


def test_an_answer_is_reused_only_until_it_is_old(tmp_path):
    now = [0.0]
    h, calls, _ = _holdings(tmp_path, lambda p: {p: {"A": 1}})
    h._clock, h._max_age = (lambda: now[0]), 60
    h.at("/")
    now[0] = 59
    h.at("/")
    assert calls == ["/"]
    now[0] = 61
    h.at("/")
    assert calls == ["/", "/"]           # an ACL change leaves the token alone: the age bounds a stale answer


def test_a_failed_read_is_never_an_answer_and_stops_this_holdings(tmp_path):
    """Lens 3s1: a box that is down cost one timeout per path, and the same path twice. After one failure
    this Holdings asks nothing more (every path unknown); the failure is never kept as an answer, so the
    next question (a new Holdings) asks again."""
    answers = [RuntimeError("timeout"), {"/": {"A": 1}}]
    h, calls, _ = _holdings(tmp_path, lambda p: answers.pop(0))
    assert h.at("/") is None
    assert h.at("/") is None and h.at("/vms/1") is None and calls == ["/"]
    again = maynever.Holdings(h._cfg, read=lambda p, t: (calls.append(p), {"/": {"A": 1}})[1])
    assert again.at("/") == frozenset({"A"}) and calls == ["/", "/"]


def test_an_answer_that_is_not_the_vendors_shape_does_not_stop_the_holdings(tmp_path):
    """Only a read that RAISES stops it: an odd answer for one path is unknown for that path alone."""
    answers = [{"other": {}}, {"/vms/1": {"A": 1}}]
    h, calls, _ = _holdings(tmp_path, lambda p: answers.pop(0))
    assert h.at("/") is None and h.at("/vms/1") == frozenset({"A"}) and calls == ["/", "/vms/1"]


def test_the_map_never_changes_a_rule_it_reads():
    """Lens 3s1: the table's rule is a plain mutable value on a cached Row; the map, its only reader,
    must leave every one of them as it found it."""
    import copy
    for r in _pve_rows():
        before = copy.deepcopy(r["permissions"])
        _answer(r["permissions"], "pve", r["method"], _rule_fill(r), lambda p: frozenset())
        assert r["permissions"] == before, r["path"]


def test_the_bytes_asked_about_are_the_bytes_sent_whatever_the_file_does_meanwhile(tmp_path):
    """Lens 1 and 2: an arm (A->B) or an arm and a disarm (A->B->A) inside one read cached the write
    token's holdings under the read token's key, because the wire re-reads its file per request. The
    read now sends the bytes the answer is keyed on."""
    tok = tmp_path / "token"
    tok.write_bytes(b"read")
    sent = []

    def read(path, token):
        sent.append(token)
        tok.write_bytes(b"armed")
        tok.write_bytes(b"read")              # A -> B -> A: the file ends where it began
        return {path: {"VM.Audit": 1} if token == b"read" else {"VM.Allocate": 1}}
    h = maynever.Holdings(_Plane(str(tok)), read=read)
    assert h.at("/") == frozenset({"VM.Audit"}) and sent == [b"read"]
    assert h.at("/") == frozenset({"VM.Audit"}) and sent == [b"read"]       # reused: the same bytes
    tok.write_bytes(b"armed")
    assert h.at("/") == frozenset({"VM.Allocate"}) and sent == [b"read", b"armed"]


def test_the_default_read_sends_a_private_copy_of_the_bytes_and_removes_it(monkeypatch, tmp_path):
    from proximo.core import engine
    seen = {}

    def execute(row, args, **kw):
        staged = kw["cfg"].token_path
        seen.update(staged=staged, bytes=pathlib.Path(staged).read_bytes(), mode=oct(os.stat(staged).st_mode & 0o777))
        return {"data": {args["path"]: {}}}
    monkeypatch.setattr(engine, "execute", execute)
    tok = tmp_path / "t"
    tok.write_bytes(b"secret-bytes")
    assert maynever.Holdings(_Plane(str(tok))).at("/") == frozenset()
    assert seen["bytes"] == b"secret-bytes" and seen["mode"] == "0o600" and seen["staged"] != str(tok)
    assert not os.path.exists(seen["staged"])


def test_the_age_counts_from_the_reads_start_and_is_strict(tmp_path):
    now = [0.0]

    def answers(p):
        now[0] += 50                          # the read itself takes 50 s
        return {p: {"A": 1}}
    h, calls, _ = _holdings(tmp_path, answers)
    h._clock, h._max_age = (lambda: now[0]), 60
    h.at("/")                                 # started at 0, returned at 50
    now[0] = 59.9
    h.at("/")
    assert calls == ["/"]
    now[0] = 60.0                             # exactly max_age after the start: not reused
    h.at("/")
    assert calls == ["/", "/"]


def test_one_tokens_answers_are_kept_at_a_time(tmp_path):
    h, calls, tok = _holdings(tmp_path, lambda p: {p: {"A": 1}})
    h.at("/a")
    tok.write_bytes(b"other")
    h.at("/b")
    assert len(h._seen) == 1                   # the first token's answer is gone
    tok.write_bytes(b"t1")
    h.at("/a")
    assert calls == ["/a", "/b", "/a"]


@pytest.mark.parametrize("token_path", [None, "/x\0y"])
def test_a_token_path_that_is_no_path_holds_nothing_known(token_path):
    h = maynever.Holdings(_Plane(token_path), read=lambda p, t: {p: {"A": 1}})
    assert h.at("/") is None


def test_wire_is_required():
    with pytest.raises(TypeError):
        maynever.answer(None, "pve", "GET", {}, HELD)       # type: ignore[call-arg]


def test_a_rule_whose_own_text_the_vendor_would_not_read_is_words():
    got = _answer({"check": ["perm", "/vms/{vmid}/x y", ["VM.Audit"]]}, "pve", "GET", {"vmid": 100}, HELD)
    assert got.verdict == WORDS and "rule's path" in got.why, got


def test_a_huge_integer_is_words_not_a_raise():
    got = _answer({"check": ["perm", "/vms/{vmid}", ["VM.Audit"]]}, "pve", "GET", {"vmid": 10 ** 5000}, HELD)
    assert got.verdict == WORDS, got


def test_a_plane_with_no_token_path_holds_nothing_known():
    h = maynever.Holdings(object(), read=lambda p, t: {p: {"A": 1}})
    assert h.at("/") is None


def test_the_read_sends_the_bytes_the_key_was_made_of_not_the_files_bytes_now(tmp_path):
    """Lens 2 mutant: reading the file again for the send passed every test; the file is made to
    differ from the bytes `at` read, and the send must be the bytes read."""
    tok = tmp_path / "token"
    tok.write_bytes(b"armed")
    sent = []
    h = maynever.Holdings(_Plane(str(tok)), read=lambda p, t: sent.append(t) or {p: {}})
    h._token = lambda: b"read"
    h.at("/")
    assert sent == [b"read"]


# ---- lens 3 on ba30720: the real reader, guarded ------------------------------------------------

def _staging_execute(monkeypatch, effect=None):
    """engine.execute replaced: records the staged copy's bytes and where it was, then `effect`."""
    from proximo.core import engine
    seen = {}

    def execute(row, args, **kw):
        staged = kw["cfg"].token_path
        seen.update(staged=staged, bytes=pathlib.Path(staged).read_bytes())
        if effect is not None:
            raise effect
        return {"data": {args["path"]: {}}}
    monkeypatch.setattr(engine, "execute", execute)
    return seen


def test_the_real_reader_sends_the_bytes_read_not_the_files_bytes_now(monkeypatch, tmp_path):
    """Lens 3: the headline fix of lens 2 was guarded only through an injected reader; writing the
    file's bytes into the copy passed every test."""
    seen = _staging_execute(monkeypatch)
    tok = tmp_path / "token"
    tok.write_bytes(b"armed")
    h = maynever.Holdings(_Plane(str(tok)))
    h._token = lambda: b"read"
    assert h.at("/") == frozenset()
    assert seen["bytes"] == b"read"


def test_the_key_is_the_one_read_not_a_second(tmp_path):
    """Lens 3: a key taken from a second read of the file filed one token's answer under another's."""
    import hashlib
    reads = iter([b"read", b"armed", b"armed"])
    h = maynever.Holdings(_Plane(str(tmp_path / "t")), read=lambda p, t: {p: {}})
    h._token = lambda: next(reads)
    h.at("/")
    assert list(h._seen) == [(hashlib.sha256(b"read").hexdigest(), "/")]


@pytest.mark.parametrize("effect", [RuntimeError("x"), KeyboardInterrupt()])
def test_the_copy_is_removed_whatever_the_read_raises(monkeypatch, tmp_path, effect):
    seen = _staging_execute(monkeypatch, effect)
    tok = tmp_path / "token"
    tok.write_bytes(b"secret-bytes")
    h = maynever.Holdings(_Plane(str(tok)))
    if isinstance(effect, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt):
            h.at("/")
    else:
        assert h.at("/") is None
    assert seen["bytes"] == b"secret-bytes" and not os.path.exists(seen["staged"])
    assert sorted(x.name for x in tmp_path.iterdir()) == ["token"]


def test_the_copy_is_staged_beside_the_served_token(monkeypatch, tmp_path):
    """Lens 3: a SIGKILL mid-read leaves the copy where the token already lives (a writable dir)."""
    seen = _staging_execute(monkeypatch)
    tok = tmp_path / "served" / "token"
    tok.parent.mkdir()
    tok.write_bytes(b"x")
    maynever.Holdings(_Plane(str(tok))).at("/")
    assert os.path.dirname(seen["staged"]) == str(tok.parent)


def test_a_vendor_refusal_of_any_kind_is_unknown(tmp_path):
    """Lens 3: only RuntimeError was tested; an httpx 403 is not one."""
    import httpx
    req = httpx.Request("GET", "https://pve.invalid/api2/json/access/permissions")
    for exc in (httpx.HTTPStatusError("403", request=req, response=httpx.Response(403, request=req)),
                httpx.ConnectError("refused", request=req), ValueError("x")):
        h, _, _ = _holdings(tmp_path, lambda p, e=exc: e)
        assert h.at("/") is None, exc


def test_a_value_over_1024_characters_is_words():
    rule = {"check": ["perm", "/pool/{pool}", ["Pool.Audit"]]}
    assert _answer(rule, "pve", "GET", {"pool": "a" * 1024}, HELD).verdict == NEVER
    got = _answer(rule, "pve", "GET", {"pool": "a" * 1025}, HELD)
    assert got.verdict == WORDS, got


def test_one_holdings_keeps_two_paths_apart(tmp_path):
    """Lens 4: a lookup keyed on the token alone passed all 126 tests and gave the module's own lab
    case a wrong MAY (/ holds Pool.Audit, a deeper ACL takes it away on the pool)."""
    held = {"/": {"Pool.Audit": 1}, "/pool/lab": {}}
    h, calls, _ = _holdings(tmp_path, lambda p: {p: held[p]})
    assert h.at("/") == frozenset({"Pool.Audit"})
    assert h.at("/pool/lab") == frozenset()
    rule = {"check": ["perm", "/pool/{pool}", ["Pool.Audit"]]}
    got = maynever.answer(rule, "pve", "GET", {"pool": "lab"}, h.at, wire="http")
    assert got.verdict == NEVER and got.why == "Pool.Audit on /pool/lab", got
    assert calls == ["/", "/pool/lab"]


def test_a_letter_outside_ascii_in_a_value_is_words():
    """Lens 4: the docstring promised it and nothing held it (a Unicode \\w survived)."""
    rule = {"check": ["perm", "/pool/{pool}", ["Pool.Audit"]]}
    for value in ("café", "١٢", "laб"):
        got = _answer(rule, "pve", "GET", {"pool": value}, HELD)
        assert got.verdict == WORDS, (value, got)


def test_a_read_only_token_directory_stages_in_the_private_temp_dir(monkeypatch, tmp_path):
    """Lens 4: the shipped LXC unit runs ProtectSystem=strict, so /etc/proximo is read-only, and a
    secret mount is too. Staging only beside the token made every answer unknown there."""
    import tempfile
    seen = _staging_execute(monkeypatch)
    tok = tmp_path / "ro" / "token"
    tok.parent.mkdir()
    tok.write_bytes(b"x")
    private = tmp_path / "private"
    private.mkdir()
    real = tempfile.mkstemp

    def mkstemp(*a, dir=None, **k):
        if dir == str(tok.parent):
            raise OSError(30, "Read-only file system")
        return real(*a, dir=dir, **k)
    monkeypatch.setattr(tempfile, "mkstemp", mkstemp)
    monkeypatch.setattr(tempfile, "tempdir", str(private))
    assert maynever.Holdings(_Plane(str(tok))).at("/") == frozenset()
    assert os.path.dirname(seen["staged"]) == str(private) and seen["bytes"] == b"x"
    assert os.listdir(private) == [] and sorted(os.listdir(tok.parent)) == ["token"]


def test_no_place_to_stage_is_unknown_not_a_traceback(monkeypatch, tmp_path):
    import tempfile
    _staging_execute(monkeypatch)
    tok = tmp_path / "token"
    tok.write_bytes(b"x")

    def mkstemp(*a, **k):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(tempfile, "mkstemp", mkstemp)
    assert maynever.Holdings(_Plane(str(tok))).at("/") is None


def test_an_interrupt_while_staging_is_not_retried(monkeypatch, tmp_path):
    import tempfile
    _staging_execute(monkeypatch)
    tok = tmp_path / "token"
    tok.write_bytes(b"x")
    tries = []

    def mkstemp(*a, **k):
        tries.append(k.get("dir"))
        raise KeyboardInterrupt
    monkeypatch.setattr(tempfile, "mkstemp", mkstemp)
    with pytest.raises(KeyboardInterrupt):
        maynever.Holdings(_Plane(str(tok))).at("/")
    assert tries == [str(tmp_path)]


# ---- lens 5: `or` is read left to right, and a part can refuse outright ---------------------------

ACCESS = _at({"/access": {"User.Modify"}, "/x": set()})


@pytest.mark.parametrize("first", [
    ["userid-group", ["User.Modify"], "groups_param", "create"],   # raise_perm_exc, noerr or not
    ["userid-param", "self"],                                       # verify_username dies on a bad userid
    ["and", ["userid-param", "self"], ["perm", "/access", ["User.Modify"]]],   # an `and` asks without noerr
    ["or", ["perm", "/x", ["Sys.Audit"]], ["userid-param", "self"]],  # an `or` holding one, inside
    ["or", ["userid-param", "self"], ["perm", "/x", ["Sys.Audit"]]],   # lens 6: the FIRST inner part
    ["perm", "0", ["Sys.Audit"]],                   # lens 6: `die "missing parameters"`, noerr or not
])
def test_a_part_that_can_refuse_outright_stops_a_later_may(first):
    rule = {"check": ["or", first, ["perm", "/access", ["User.Modify"]]]}
    got = _answer(rule, "pve", "PUT", {"groups": "g"}, ACCESS)
    assert got.verdict == WORDS, got


def test_a_part_that_answers_0_under_noerr_never_stops_the_walk():
    """A perm (a filled path, valid privilege names), an `or` of such, and perm-modify (lens 6: no path
    returns 0, else check_any with noerr over names the vendor itself wrote) answer 0, never raise."""
    later = ["perm", "/access", ["User.Modify"]]
    for first in (["perm-modify", "/x"], ["perm-modify", "/x/{vmid}"],
                  ["perm", "/x", ["Sys.Audit"]], ["or", ["perm", "/x", ["Sys.Audit"]], ["perm", "/x", ["Sys.Audit"]]],
                  ["perm", "/x/{vmid}", ["Sys.Audit"]], ["perm", "/x", ["Sys.Audit"], "require_param", "y"]):
        got = _answer({"check": ["or", first, later]}, "pve", "GET", {}, ACCESS)
        assert got.verdict == MAY, (first, got)


def test_after_a_part_that_can_refuse_only_nevers_stay_never_and_an_earlier_may_still_wins():
    first = ["userid-param", "self"]
    never = ["perm", "/x", ["Sys.Audit"]]
    assert _answer({"check": ["or", first, never]}, "pve", "GET", {}, ACCESS).verdict == WORDS
    assert _answer({"check": ["or", ["perm", "/access", ["User.Modify"]], first]}, "pve", "GET", {},
                   ACCESS).verdict == MAY
    got = _answer({"check": ["or", never, ["and", never, never], never]}, "pve", "GET", {}, ACCESS)
    assert got.verdict == NEVER and got.why == "Sys.Audit on /x; or Sys.Audit on /x; and Sys.Audit on /x", got


def test_a_template_the_vendor_reads_as_no_path_is_words():
    """Lens 5/6: for a `perm` the vendor dies "missing parameters" on a falsy path before it normalises
    anything (lens 9: the credit was wrong); "0" was asked at /0."""
    for t in ("0",):
        got = _answer({"check": ["perm", t, ["Sys.Audit"]]}, "pve", "GET", {}, _at({"/0": {"Sys.Audit"}}))
        assert got.verdict == WORDS, (t, got)


class _Lying(str):
    def __str__(self):
        return "100"


class _Hostile:
    def __bool__(self):
        raise ValueError("no")


def test_only_a_plain_str_or_int_fills_a_path():
    """Lens 5: a str subclass whose text is not its value asked /vms/100 for "200"; a value whose
    truth raises, or a fill that is no mapping, raised out of answer()."""
    rule = {"check": ["perm", "/vms/{vmid}", ["VM.Audit"]]}
    held = _at({"/vms/100": {"VM.Audit"}})
    for value in (_Lying("200"), _Hostile(), 1.0, b"100"):
        assert _answer(rule, "pve", "GET", {"vmid": value}, held).verdict == WORDS, value
    for fill in (None, ["vmid"], "vmid"):
        assert _answer(rule, "pve", "GET", fill, held).verdict == WORDS, fill
    assert _answer(rule, "pve", "GET", {"vmid": 100}, held).verdict == MAY
    assert _answer(rule, "pve", "GET", {"vmid": False}, held).why == "depends on {vmid}: give it"


def test_a_path_that_is_no_string_is_unknown_not_a_traceback(tmp_path):
    h, calls, _ = _holdings(tmp_path, lambda p: {p: {}})
    for bad in (["/"], None, 3):
        assert h.at(bad) is None
    assert calls == []


@pytest.mark.parametrize("wire", ["ssh", "HTTP", None, ""])
def test_only_the_http_wire_is_the_vendors_door(wire):
    got = _answer({"user": "all"}, "pve", "GET", {}, HELD, wire=wire)
    assert got.verdict == WORDS and "own lane" in got.why, got


def test_the_holdings_defaults_are_a_minute_on_a_clock_that_never_steps_back(tmp_path):
    import time
    h = maynever.Holdings(_Plane(str(tmp_path / "token")))
    assert h._max_age == 60.0 and h._clock is time.monotonic


def test_the_joiners_say_and_and_or():
    a, b = ["perm", "/a", ["X.One"]], ["perm", "/b", ["X.Two"]]
    assert _answer({"check": ["and", a, b]}, "pve", "GET", {}, _at({})).why == "X.One on /a; and X.Two on /b"
    assert _answer({"check": ["or", a, b]}, "pve", "GET", {}, _at({})).why == "X.One on /a; or X.Two on /b"


def test_the_lens_5_fixtures_are_rules_the_grammar_admits():
    """A one-part `and` is refused as malformed (WORDS) before it is evaluated: such a fixture passes
    for the wrong reason."""
    from proximo.core import apitree
    later = ["perm", "/access", ["User.Modify"]]
    for first in test_a_part_that_can_refuse_outright_stops_a_later_may.pytestmark[0].args[1]:
        assert apitree.rule_problem({"check": ["or", first, later]}, "pve") is None, first



def test_a_stopping_part_that_refuses_makes_the_or_never_whatever_follows():
    """Lens 6: an `and` that is NEVER raises (it asks without noerr); a later MAY is never reached."""
    never = ["perm", "/x", ["Sys.Audit"]]
    rule = {"check": ["or", ["and", never, never], ["perm", "/access", ["User.Modify"]]]}
    got = _answer(rule, "pve", "GET", {}, ACCESS)
    assert got.verdict == NEVER and got.why == "Sys.Audit on /x; and Sys.Audit on /x", got


def test_every_part_after_the_stop_is_weighed_not_only_the_next():
    """Lens 6: `later` read after[0] only; a NEVER then a MAY behind a stop lost the MAY's words."""
    rule = {"check": ["or", ["userid-param", "self"], ["perm", "/x", ["Sys.Audit"]],
                      ["perm", "/access", ["User.Modify"]]]}
    got = _answer(rule, "pve", "GET", {}, ACCESS)
    assert got.verdict == WORDS and "a later part counts only if" in got.why, got


def test_a_stray_brace_in_the_rules_own_text_is_words():
    for t in ("/a{", "/a}", "/a{}"):
        got = _answer({"check": ["perm", t, ["Sys.Audit"]]}, "pve", "GET", {}, _at({}))
        assert got.verdict == WORDS, (t, got)


def test_a_literal_chunk_of_exactly_0_is_words():
    """Lens 7: the vendor's template_replace keeps a literal chunk only `if $1`, so a chunk "0" is
    dropped there (`/v/{vmid}0` is asked at /v/1) and kept here: a wrong MAY and a wrong NEVER."""
    for t in ("/v/{vmid}0", "0{vmid}", "/v/{vmid}0{vmid}"):
        got = _answer({"check": ["perm", t, ["Sys.Audit"]]}, "pve", "GET", {"vmid": "1"},
                      _at({"/v/10": {"Sys.Audit"}, "/01": {"Sys.Audit"}, "/v/101": {"Sys.Audit"}}))
        assert got.verdict == WORDS, (t, got)
    asked = []
    _answer({"check": ["perm", "/v/{vmid}00", ["Sys.Audit"]]}, "pve", "GET", {"vmid": "1"},
            lambda p: asked.append(p) or frozenset())
    assert asked == ["/v/100"]                      # "00" is truthy in perl: kept, as here


def test_any_needs_one_of_the_named_privileges_not_any_privilege():
    """Lens 7: `held & want` -> `held` survived; no test held an unrelated privilege."""
    got = _answer({"check": ["perm", "/x", ["A.One"], "any", 1]}, "pve", "GET", {}, _at({"/x": {"B.Two"}}))
    assert got.verdict == NEVER and got.why == "one of A.One on /x", got


def test_every_placeholder_is_checked_for_a_value_not_only_the_first():
    rule = {"check": ["perm", "/a/{x}/{y}", ["Sys.Audit"]]}
    for fill in ({"x": "1"}, {"x": "1", "y": 0}, {"x": "1", "y": "0"}):
        got = _answer(rule, "pve", "GET", fill, _at({"/a/1/0": {"Sys.Audit"}, "/a/1": {"Sys.Audit"}}))
        assert got.why == "depends on {y}: give it", (fill, got)


@pytest.mark.parametrize("template, fill", [
    ("0/", {}), ("0//", {}), ("{vmid}", {"vmid": "0/"}), ("{vmid}/", {"vmid": "0/"}),
])
def test_a_path_the_vendor_normalises_elsewhere_is_words(template, fill):
    """Lens 8: `normalize_path` rewrites a path that collapses to "0" (perl false) to `/`; the map
    asked /0. Any path the map would ask that is not the vendor's own normalised path is WORDS."""
    asked = []
    got = _answer({"check": ["perm", template, ["VM.Audit"]]}, "pve", "GET", fill,
                  lambda p: asked.append(p) or frozenset({"VM.Audit"}))
    assert got.verdict == WORDS and asked == [], (got, asked)


def test_the_ported_normalize_path_matches_the_vendors_on_its_own_cases():
    """Each pair run through the vendor's sub in perl (s|/+|/|g; s|/$||; '/' if !$path; "/$path")."""
    for raw, want in (("0/", "/"), ("0//", "/"), ("/0", "/0"), ("a//b/", "/a/b"), ("/", "/"), ("//", "/"),
                      ("a", "/a"), ("00/", "/00"), ("/vms/100", "/vms/100")):
        assert maynever._normalized(raw) == want, raw
    assert maynever._normalized("") is None and maynever._normalized("0") is None


def test_a_value_of_00_fills_it_is_truthy_in_perl():
    asked = []
    _answer({"check": ["perm", "/v/{vmid}", ["Sys.Audit"]]}, "pve", "GET", {"vmid": "00"},
            lambda p: asked.append(p) or frozenset())
    assert asked == ["/v/00"]


def test_a_rule_too_wide_to_walk_is_words_not_a_traceback():
    """Lens 8: the grammar caps depth, not width; 1,500 refusing parts recursed past the stack."""
    rule = {"check": ["or"] + [["userid-param", "self"]] * 1500}
    assert _answer(rule, "pve", "GET", {}, HELD).verdict == WORDS


class _Shifty(dict):
    """A mapping that answers one value, then another (lens 8: a value read twice)."""
    def __init__(self):
        super().__init__(vmid="100")
        self.reads = 0

    def __getitem__(self, k):
        self.reads += 1
        return "100" if self.reads == 1 else 0

    def get(self, k, d=None):
        return self[k]


class _Raising(collections.abc.Mapping):
    """Not a dict: `dict()` of a dict subclass copies its stored values and never calls these."""
    def __getitem__(self, k):
        raise TypeError("no")

    def __iter__(self):
        return iter(["vmid"])

    def __len__(self):
        return 1


def test_each_value_is_read_once_and_a_mapping_that_raises_is_words():
    rule = {"check": ["perm", "/vms/{vmid}", ["VM.Audit"]]}
    asked = []
    got = _answer(rule, "pve", "GET", _Shifty(), lambda p: asked.append(p) or frozenset({"VM.Audit"}))
    assert asked in ([], ["/vms/100"]) and (got.verdict == MAY) == (asked == ["/vms/100"]), (got, asked)
    r = _Raising()
    assert _answer(rule, "pve", "GET", r, _at({})).verdict == WORDS



def test_a_later_unknown_after_a_stop_stays_unknown():
    """Lens 9: the docstring said WORDS; the code keeps the later UNKNOWN (safe: never MAY)."""
    rule = {"check": ["or", ["and", ["perm", "/a", ["A"]], ["perm", "/x/{v}", ["A"]]], ["perm", "/b", ["A"]]]}
    got = _answer(rule, "pve", "GET", {}, lambda p: {"/a": frozenset({"A"}), "/b": None}.get(p, frozenset()))
    assert got.verdict == UNKNOWN and got.why == "what this token holds on /b could not be read", got


def test_a_later_words_after_a_stop_keeps_its_own_words():
    rule = {"check": ["or", ["userid-param", "self"], ["userid-group", ["User.Modify"]]]}
    got = _answer(rule, "pve", "GET", {}, _at({}))
    assert got.why == ("the vendor checks userid-param by a rule of its own; "
                       "or the vendor checks userid-group by a rule of its own"), got


class _PathLike(str):
    pass


def test_a_path_that_is_a_str_subclass_is_unknown(tmp_path):
    h, calls, _ = _holdings(tmp_path, lambda p: {p: {}})
    assert h.at(_PathLike("/")) is None and calls == []



def test_an_empty_token_file_is_no_credential_nothing_staged_nothing_sent(monkeypatch, tmp_path):
    """Step 3: a plane whose token is /dev/null (or an empty file) staged a copy beside it and dialled
    the vendor for every plan; it is unknown without either."""
    from proximo.core import engine
    sent = []
    monkeypatch.setattr(engine, "execute", lambda *a, **k: sent.append(a) or {"data": {}})
    for body in (b"", b"\n", b"  \n"):
        tok = tmp_path / "token"
        tok.write_bytes(body)
        assert maynever.Holdings(_Plane(str(tok))).at("/") is None
    assert maynever.Holdings(_Plane(os.devnull)).at("/") is None
    assert sent == [] and sorted(os.listdir(tmp_path)) == ["token"]


# ---- the PBS/PDM door (proxmox-router's Permission) -----------------------------------------------

def _check(path, privs, partial=False):
    return {"check": {"path": path, "privs": privs, "partial": partial}}


@pytest.mark.parametrize("product", ["pbs", "pdm"])
def test_every_privilege_is_needed_unless_partial_and_the_missing_are_named(product):
    rule = _check(["datastore", "{store}"], ["Datastore.Audit", "Datastore.Modify"])
    held = _at({"/datastore/d1": {"Datastore.Audit"}})
    got = _answer(rule, product, "PUT", {"store": "d1"}, held)
    assert got.verdict == NEVER and got.why == "Datastore.Modify on /datastore/d1", got
    assert _answer(rule, product, "PUT", {"store": "d1"},
                   _at({"/datastore/d1": {"Datastore.Audit", "Datastore.Modify"}})).verdict == MAY
    partial = _check(["datastore", "{store}"], ["Datastore.Audit", "Datastore.Modify"], partial=True)
    assert _answer(partial, product, "PUT", {"store": "d1"}, held).verdict == MAY
    got = _answer(partial, product, "PUT", {"store": "d1"}, _at({"/datastore/d1": set()}))
    assert got.verdict == NEVER and got.why == "one of Datastore.Audit, Datastore.Modify on /datastore/d1", got


def test_the_root_is_an_empty_path_and_a_placeholder_no_value_fills_is_words():
    assert _answer(_check([], ["Sys.Audit"]), "pbs", "GET", {}, _at({"/": {"Sys.Audit"}})).verdict == MAY
    got = _answer(_check(["datastore", "{store}"], ["Datastore.Audit"]), "pbs", "GET", {}, _at({}))
    assert got.verdict == WORDS and "{store}" in got.why


def test_what_the_token_holds_unread_is_unknown_on_pbs():
    got = _answer(_check(["access", "users"], ["Permissions.Modify"]), "pbs", "POST", {}, _at({"/access/users": None}))
    assert got.verdict == UNKNOWN and "/access/users" in got.why


SELF = {"or": [{"check": {"path": ["access", "users"], "privs": ["Permissions.Modify"], "partial": False}},
               {"userParam": "userid"}]}


def test_the_self_rule_is_the_served_credentials_whole_auth_id():
    """proxmox-auth-api sets the auth id to the USER for a ticket and to the TOKEN ID for a token;
    `Permission::UserParam` compares the argument to that string (lens on 325b37e, M1)."""
    none = _at({"/access/users": set()})
    assert _answer(SELF, "pbs", "POST", {"userid": "proximo@pbs"}, none, who="proximo@pbs").verdict == MAY
    got = _answer(SELF, "pbs", "POST", {"userid": "other@pbs"}, none, who="proximo@pbs")
    assert got.verdict == NEVER and "Permissions.Modify on /access/users" in got.why \
        and "not the caller's own user" in got.why, got
    assert _answer(SELF, "pbs", "POST", {"userid": "proximo@pbs"}, none).verdict == UNKNOWN
    got = _answer(SELF, "pbs", "POST", {}, none)
    assert got.verdict == WORDS and "{userid}" in got.why
    # the check alone decides when it is met, whoever is named
    assert _answer(SELF, "pbs", "POST", {"userid": "other@pbs"},
                   _at({"/access/users": {"Permissions.Modify"}}), who="proximo@pbs").verdict == MAY


def test_a_token_never_passes_the_self_rule_the_vendor_compares_the_token_id(tmp_path):
    """A token `proximo@pbs!read` calling POST /access/users/proximo@pbs/token/x: the vendor compares
    "proximo@pbs!read" to "proximo@pbs": false; without Permissions.Modify the `or` is a 403."""
    tok = tmp_path / "token"
    tok.write_bytes(b"proximo@pbs!read:SECRET")
    who = maynever.Holdings(_Box(str(tok))).user
    assert who == "proximo@pbs!read"
    got = _answer(SELF, "pbs", "POST", {"userid": "proximo@pbs"}, _at({"/access/users": set()}), who=who)
    assert got.verdict == NEVER and "token" in got.why and "proximo@pbs" in got.why and "SECRET" not in got.why
    assert _answer(SELF, "pbs", "POST", {"userid": "proximo@pbs!read"}, _at({"/access/users": set()}),
                   who=who).verdict == MAY           # the vendor's own compare, whatever the argument names


def test_a_rule_slot_the_rows_path_does_not_bind_is_refused_for_every_caller_but_root():
    """PBS/PDM `POST /nodes/{node}/network` carries {iface} in its rule and takes iface in the BODY; the
    vendor fills a rule's slot from the routed path only (`uri_param`), so the check is false (lens M4)."""
    rule = _check(["system", "network", "interfaces", "{iface}"], ["Sys.Modify"])
    everything = lambda p: frozenset({"Sys.Modify"})  # noqa: E731
    got = _answer(rule, "pbs", "POST", {"node": "pbs1", "iface": "eth0"}, everything, who="x@pbs",
                  path_slots=frozenset({"node"}))
    assert got.verdict == NEVER and "{iface}" in got.why and "root@pam" in got.why, got
    # the same slot bound by the path (the item router) is the ordinary check
    assert _answer(rule, "pbs", "PUT", {"node": "pbs1", "iface": "eth0"}, everything, who="x@pbs",
                   path_slots=frozenset({"node", "iface"})).verdict == MAY
    assert _answer(rule, "pbs", "PUT", {"node": "pbs1", "iface": "eth0"}, everything).verdict == MAY   # unchecked


@pytest.mark.parametrize("product", ["pve", "pbs", "pdm", "pmg"])
def test_no_rule_admits_the_user_root_itself_and_never_a_token(product):
    got = _answer(None, product, "POST", {}, HELD, who="root@pam")
    assert got.verdict == MAY and "root@pam" in got.why
    assert _answer(None, product, "POST", {}, HELD, who="root@pam!admin").verdict == NEVER
    assert _answer(None, product, "POST", {}, HELD, who="proximo@pve").verdict == NEVER


def test_an_and_needs_every_part_and_names_each_missing_grant():
    rule = {"and": [_check(["datastore", "{store}"], ["Datastore.Modify"]),
                    _check(["system", "disks"], ["Sys.Modify"])]}
    got = _answer(rule, "pbs", "POST", {"store": "d1"}, _at({"/datastore/d1": set(), "/system/disks": set()}))
    assert got.verdict == NEVER and got.why == "Datastore.Modify on /datastore/d1; and Sys.Modify on /system/disks"
    assert _answer(rule, "pbs", "POST", {"store": "d1"},
                   _at({"/datastore/d1": {"Datastore.Modify"}, "/system/disks": {"Sys.Modify"}})).verdict == MAY


@pytest.mark.parametrize("product", ["pbs", "pdm", "pmg"])
def test_no_rule_is_root_only_on_every_product(product):
    got = _answer(None, product, "POST", {}, HELD)
    assert got.verdict == NEVER and "root@pam" in got.why


def test_pves_cut_list_wording_is_not_read_as_filtered_on_another_product():
    rule = {"user": "all", "description": "Only list entries where you have rights."}
    assert _answer(rule, "pve", "GET", {}, HELD).verdict == FILTERED
    assert _answer(rule, "pbs", "GET", {}, HELD).verdict == WORDS


def _rows(product):
    return [r for r in apitree.published()["rows"] if r["product"] == product and r["wire"] != "ssh"]


def _other_fill(r):
    """Every placeholder the row's path or its rule names (PBS/PDM paths are lists of parts), filled."""
    import json
    names = set(maynever._SLOT.findall(r["path"])) | set(maynever._SLOT.findall(json.dumps(r["permissions"])))
    return {n: "x" for n in names}


@pytest.mark.parametrize("product", ["pbs", "pdm", "pmg"])
def test_every_shipped_rule_of_the_other_products_answers_one_of_the_five_without_raising(product):
    for holdings in (_at({}), lambda p: None, lambda p: frozenset(_privs())):
        for who in (None, "x@pam"):
            for r in _rows(product):
                got = _answer(r["permissions"], product, r["method"], _other_fill(r), holdings, who=who)
                assert got.verdict in maynever.ANSWERS, (r["method"], r["path"], got)


# ---- the holdings on PBS/PDM: the caller's own tree ----------------------------------------------

@dataclasses.dataclass(frozen=True)
class _Box:
    token_path: str
    product: str = "pbs"


TREE = {"/": {"Datastore.Audit": True, "Sys.Audit": True},
        "/datastore/d1": {"Datastore.Audit": True, "Datastore.Modify": False},
        "/remote": {"Remote.Audit": False}}


def _tree_holdings(tmp_path, answer, token=b"t1", product="pbs"):
    tok = tmp_path / "token"
    tok.write_bytes(token)
    calls = []

    def read(path, token):
        calls.append(path)
        if isinstance(answer, Exception):
            raise answer
        return answer
    return maynever.Holdings(_Box(str(tok), product), read=read), calls, tok


@pytest.mark.parametrize("product", ["pbs", "pdm"])
def test_a_listed_node_holds_all_its_privileges_and_an_unlisted_path_is_unknown(tmp_path, product):
    """The vendor's walk (`AclTree::roles`) is not inferred from the tree: a NoAccess fence is dropped from
    it (privileges none), and a node holding only non-propagating roles does not stop its parent's
    propagation below it (lens on 325b37e, M2). What is listed is held; the rest is unknown."""
    h, calls, _ = _tree_holdings(tmp_path, TREE, product=product)
    assert h.at("/datastore/d1") == frozenset({"Datastore.Audit", "Datastore.Modify"})
    assert h.at("/") == frozenset({"Datastore.Audit", "Sys.Audit"})
    assert h.at("/remote") == frozenset({"Remote.Audit"})          # listed, whatever the flag
    assert h.at("/datastore/d1/ns/x") is None                       # below a listed node: not inferred
    assert h.at("/datastore") is None                               # between two listed nodes: not inferred
    assert h.at("/system") is None
    assert calls == [None]                                          # one read of the tree


def test_an_empty_tree_is_the_vendor_saying_nothing_anywhere(tmp_path):
    h, calls, _ = _tree_holdings(tmp_path, {})
    assert h.at("/") == frozenset() and h.at("/datastore/d1") == frozenset() and calls == [None]


def test_an_answer_that_is_not_the_tree_is_remembered_not_re_read_per_path(tmp_path):
    h, calls, _ = _tree_holdings(tmp_path, {"/": ["A"]})
    assert h.at("/") is None and h.at("/x") is None and calls == [None]


@pytest.mark.parametrize("data", [
    None, [], "x",
    {"datastore": {"A": True}},                 # a key that is no path
    {"/": ["A"]},
    {"/": {"A": 1}},                            # PVE's int flag is not this product's bool
    {"/": {"A": "true"}},
    {"/": {"": True}},
    RuntimeError("403"),
])
def test_anything_but_the_vendors_tree_is_unknown(tmp_path, data):
    h, _, _ = _tree_holdings(tmp_path, data)
    assert h.at("/") is None


def test_the_tree_is_read_once_per_token_and_again_for_a_new_token(tmp_path):
    h, calls, tok = _tree_holdings(tmp_path, TREE)
    for path in ("/", "/datastore/d1", "/x"):
        h.at(path)
    assert calls == [None]
    tok.write_bytes(b"t2")
    h.at("/")
    assert calls == [None, None]


def test_a_failed_tree_read_stops_this_holdings(tmp_path):
    h, calls, _ = _tree_holdings(tmp_path, RuntimeError("down"))
    assert h.at("/") is None and h.at("/x") is None and calls == [None]


def test_pmg_holds_nothing_known_at_any_path(tmp_path):
    h, calls, _ = _tree_holdings(tmp_path, TREE, product="pmg")
    assert h.at("/") is None and calls == []


def test_the_pbs_reader_asks_the_callers_whole_tree_through_the_engine_receipted(monkeypatch, tmp_path):
    from proximo.core import engine
    seen = {}

    def execute(row, args, **kw):
        seen.update(row=(row.product, row.method, row.path), args=args, **kw)
        return {"data": {"/datastore/d1": {"Datastore.Audit": True}}}
    monkeypatch.setattr(engine, "execute", execute)
    tok = tmp_path / "t"
    tok.write_bytes(b"x")
    h = maynever.Holdings(_Box(str(tok), "pdm"), ledger_cfg="L")
    assert h.at("/datastore/d1") == frozenset({"Datastore.Audit"})
    assert seen["row"] == ("pdm", "GET", "/access/permissions") and seen["args"] == {}
    assert seen["evaluating"] is True and seen["fields"] == "all" and seen["ledger_cfg"] == "L"


def test_a_cut_tree_is_unknown(monkeypatch, tmp_path):
    """A tree the evaluation cap cut is not the caller's whole tree: a node missing from it is not "nothing"."""
    from proximo.core import engine
    monkeypatch.setattr(engine, "execute",
                        lambda row, args, **kw: {"data": {"/": {"Datastore.Audit": True}}, "truncated": True})
    tok = tmp_path / "t"
    tok.write_bytes(b"x")
    assert maynever.Holdings(_Box(str(tok), "pbs")).at("/") is None


@pytest.mark.parametrize("text, who", [
    (b"proximo@pve!read=SECRET", "proximo@pve!read"),           # a token: the token id is the auth id
    (b"proximo@pbs!write:SECRET\n", "proximo@pbs!write"),
    (b'{"ticket": "PBS:proximo@pbs:6AED0000::sig", "csrf": "c", "box": "https://b:8007"}', "proximo@pbs"),
    (b'{"ticket": "PVE:root@pam:6AED0000::sig", "csrf": "c", "box": "https://b:8006"}', "root@pam"),
    (b'{"ticket": "PBS:!tfa!proximo@pbs:6AED0000::sig", "csrf": "c", "box": "b"}', None),
    (b"proximo@pve=SECRET", None),                              # a token line names a token
    (b"SECRET", None),
    (b"p@ssw0rd", None),                                        # a secret with an @ is no token id
    (b"no-realm!read=SECRET", None),
    (b"PBSAPIToken=proximo@pbs!x:s", None),
    (b'{"csrf": "c"}', None),
    (b"{not json", None),
    (b"", None),
])
def test_the_served_credentials_auth_id_is_read_as_the_vendor_compares_it(tmp_path, text, who):
    tok = tmp_path / "t"
    tok.write_bytes(text)
    assert maynever.Holdings(_Box(str(tok))).user == who


@dataclasses.dataclass(frozen=True)
class _Pmg:
    token_path: str
    product: str = "pmg"
    credential: bool = False
    username: str = "root@pam"


def test_pmg_in_password_mode_is_its_configured_user_never_the_files_bytes(tmp_path):
    pw = tmp_path / "pw"
    pw.write_bytes(b"p@ssw0rd\n")
    assert maynever.Holdings(_Pmg(str(pw))).user == "root@pam"
    cred = tmp_path / "cred"
    cred.write_bytes(b"\xef\xbb\xbfadmin@pmg\npassword")
    assert maynever.Holdings(_Pmg(str(cred), credential=True)).user == "admin@pmg"
    bad = tmp_path / "bad"
    bad.write_bytes(b"password-only")
    assert maynever.Holdings(_Pmg(str(bad), credential=True)).user is None


def test_an_unreadable_credential_has_no_user(tmp_path):
    assert maynever.Holdings(_Box(str(tmp_path / "absent"))).user is None
