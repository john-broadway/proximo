"""The may/never map, step 1: the vendor's permission rule, brought in verbatim.

Each api-viewer publishes, per call, the rule Proxmox enforces: a privilege on a path (PVE's list
form, PBS and PDM's dict form, either under an `or`/`and`), a role (PMG), or `user: all|world`, with
a description where the vendor says more in words. Proximo dropped it; the map lines it up with
what a token holds. Step 1 carries it into `records/vendor.json.gz` and the shipped JSON and
changes no behaviour. The build refuses a rule whose shape it does not know, with its words.
"""
from __future__ import annotations

import gzip
import json
import pathlib

import pytest

from proximo.core import apitree

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _vendor() -> list[dict]:
    return json.loads(gzip.decompress((ROOT / "records" / "vendor.json.gz").read_bytes()))


def test_every_vendor_row_carries_the_rule_column():
    rows = _vendor()
    assert rows and all("permissions" in r for r in rows)


def test_the_rule_is_published_on_1729_of_1799_calls_as_measured():
    """Measured 2026-11-01 from the four api-viewers (the map's plan, docs/plans/internal)."""
    have: dict[str, list[int]] = {}
    for r in _vendor():
        have.setdefault(r["product"], [0, 0])
        have[r["product"]][0] += 1
        have[r["product"]][1] += bool(r["permissions"])
    assert have == {"pve": [680, 665], "pbs": [367, 346], "pmg": [425, 404], "pdm": [327, 314]}


def test_every_rule_carried_has_a_shape_the_build_knows():
    for r in _vendor():
        assert apitree.rule_problem(r["permissions"], r["product"]) is None, (r["product"], r["method"], r["path"])


def test_the_shipped_json_carries_the_same_rule():
    shipped = json.loads(gzip.decompress((ROOT / "src" / "proximo" / "core" / "proximo.json.gz").read_bytes()))
    by = {(r["product"], r["method"], r["path"]): r.get("permissions", "MISSING") for r in shipped["rows"]}
    for r in _vendor():
        assert by[(r["product"], r["method"], r["path"])] == r["permissions"]


_PERM = ["perm", "/", ["Sys.Audit"]]
_DICT = {"path": [], "privs": ["Sys.Audit"], "partial": False}


# ONE DEFECT PER CASE (lens 2 on 5684e6f: a case with two defects let the second guard hide the first,
# and 13 mutants survived). Each case is a known-good rule with exactly one thing wrong.
@pytest.mark.parametrize("rule, product, says", [
    ("all", "pve", "a mapping"),
    ({}, "pve", "empty"),
    ({"check": _PERM, "surprise": 1}, "pve", "surprise"),
    ({"user": "everyone"}, "pve", "user"),
    ({"description": 7, "user": "all"}, "pve", "description"),
    ({"user": "all"}, "pxx", "no rule grammar"),
    # the product split: each product writes its own form
    ({"check": _DICT}, "pve", "writes a list"),
    ({"check": _PERM}, "pbs", "writes {path"),
    ({"check": ["admin"]}, "pve", "head the map does not know"),
    ({"check": ["new-pve-head", "/vms/{vmid}"]}, "pve", "head the map does not know"),
    ({"check": _PERM}, "pmg", "PMG roles"),
    ({"check": ["admin", "superuser"]}, "pmg", "PMG roles"),
    ({"check": []}, "pmg", "PMG roles"),
    ({"or": [{"check": _DICT}]}, "pve", "unknown key"),
    # PVE perm, one defect each
    ({"check": ["perm", "/"]}, "pve", "perm is not"),
    ({"check": ["perm", "/", []]}, "pve", "perm is not"),
    ({"check": ["perm", "/", [7]]}, "pve", "perm is not"),
    ({"check": ["perm", "", ["Sys.Audit"]]}, "pve", "perm is not"),
    ({"check": ["perm", 7, ["Sys.Audit"]]}, "pve", "perm is not"),
    ({"check": ["perm", "/", ["Sys.Audit"], "any", 0]}, "pve", "option the map does not know"),
    ({"check": ["perm", "/", ["Sys.Audit"], "bogus", None, {}]}, "pve", "option the map does not know"),
    # PVE or / and, one defect each
    ({"check": ["or"]}, "pve", "does not hold checks"),
    ({"check": ["or", _PERM, "x"]}, "pve", "does not hold checks"),
    ({"check": ["or", ["perm", 7, ["A"]], _PERM]}, "pve", "or: perm is not"),
    ({"check": ["and", ["or", ["perm", "/", []], _PERM], _PERM]}, "pve", "and: or: perm is not"),
    ({"check": ["or", ["admin"], _PERM]}, "pve", "or: has a head"),
    # PVE's other heads, one defect each
    ({"check": ["userid-param"]}, "pve", "userid-param is not"),
    ({"check": ["userid-param", 7]}, "pve", "userid-param is not"),
    ({"check": ["userid-group", "x"]}, "pve", "userid-group is not"),
    ({"check": ["userid-group", ["User.Modify"], "groups_param", "delete"]}, "pve", "option the map does not know"),
    ({"check": ["perm-modify", 7]}, "pve", "perm-modify is not"),
    ({"check": ["perm-modify"]}, "pve", "perm-modify is not"),
    # PBS / PDM dict, one defect each
    ({"check": {**_DICT, "privs": []}}, "pbs", "privs"),
    ({"check": {**_DICT, "path": 7}}, "pbs", "path"),
    ({"check": {**_DICT, "path": ["x", ""]}}, "pbs", "path"),
    ({"check": {**_DICT, "partial": "no"}}, "pbs", "partial"),
    ({"check": {"path": [], "privs": ["Sys.Audit"]}}, "pdm", "exactly"),
    ({"check": {**_DICT, "x": 1}}, "pdm", "exactly"),
    ({"check": {}}, "pdm", "exactly"),
    # PBS / PDM top-level or / and, one defect each
    ({"or": []}, "pbs", "or is not a list"),
    ({"and": "x"}, "pbs", "and is not a list"),
    ({"or": [{"user": "nobody"}, {"userParam": "userid"}]}, "pbs", "or: a part"),
    ({"or": [{"check": _DICT, "userParam": "userid"}, {"userParam": "userid"}]}, "pbs", "or: a part"),
    ({"and": [{"check": _DICT}, {"user": "all"}]}, "pdm", "and: a part"),
    ({"or": [{"check": _DICT}, {"userParam": 5}]}, "pbs", "or: userParam"),
    ({"or": [{"check": _DICT}, {"userParam": ""}]}, "pbs", "or: userParam"),
    ({"or": [{"check": {**_DICT, "privs": []}}, {"userParam": "userid"}]}, "pdm", "or: check privs"),
    # lens 3 on 3968904: unbound cases, and the grammar tightened to exactly the data
    ({"check": ["perm", "/", ["Sys.Audit"], "require_param", ""]}, "pve", "option the map does not know"),
    ({"check": ["perm", "/", ["Sys.Audit"], "any", True]}, "pve", "option the map does not know"),
    ({"check": ["perm", "/", ["Sys.Audit"], "any", 1.0]}, "pve", "option the map does not know"),
    ({"check": ["perm", "/", [""]]}, "pve", "perm is not"),
    ({"check": ["admin", "admin"]}, "pmg", "PMG roles"),
    ({"check": ["or", _PERM]}, "pve", "does not hold checks"),                # data: or/and hold 2+
    ({"description": "words alone"}, "pve", "description alone"),
    ({"description": "", "user": "all"}, "pve", "description"),
    ({"check": ["admin"], "user": "all"}, "pmg", "check and user"),            # only PVE pairs them
    ({"check": _DICT, "user": "all"}, "pbs", "check and user"),
    ({"or": [{"check": _DICT}, {"userParam": "userid"}], "user": "all"}, "pbs", "stands alone"),
    ({"or": [{"check": _DICT}, {"userParam": "userid"}], "and": [{"check": _DICT}, {"check": _DICT}]}, "pdm",
     "stands alone"),
    ({"or": [{"check": _DICT}]}, "pbs", "or is one check and one userParam"),
    ({"or": [{"check": _DICT}, {"check": _DICT}]}, "pbs", "or is one check and one userParam"),
    ({"or": [{"userParam": "userid"}, {"userParam": "userid"}]}, "pbs", "or is one check and one userParam"),
    ({"and": [{"check": _DICT}, {"userParam": "userid"}]}, "pdm", "and: a part"),
    # lens 4 on c31a318: tightenings the suite did not bind
    ({"or": [{"check": _DICT}, {"check": _DICT}, {"userParam": "userid"}]}, "pbs", "or is one check and one userParam"),
    ({"check": ["userid-group", [7]]}, "pve", "userid-group is not"),
    ({"check": ["userid-group", [""]]}, "pve", "userid-group is not"),
    ({"check": ["perm-modify", ""]}, "pve", "perm-modify is not"),
    ({"check": ["userid-param", ""]}, "pve", "userid-param is not"),
    ({"check": ["userid-param", "self", "x"]}, "pve", "userid-param is not"),
])
def test_a_rule_of_an_unknown_shape_is_refused_with_its_words(rule, product, says):
    problem = apitree.rule_problem(rule, product)
    assert problem and says in problem, problem


@pytest.mark.parametrize("rule, product", [
    (None, "pve"),
    ({"user": "all"}, "pbs"),
    ({"user": "world"}, "pmg"),
    ({"description": "Only list VMs where you have VM.Audit permissions on /vms/<vmid>.", "user": "all"}, "pve"),
    ({"check": _PERM}, "pve"),
    ({"check": _PERM, "user": "all"}, "pve"),
    ({"check": ["perm", "/storage/{storage}", ["Datastore.Allocate"], "any", 1]}, "pve"),
    ({"check": ["perm", "/pool/{pool}", ["Pool.Allocate"], "require_param", "pool"]}, "pve"),
    ({"check": ["or", _PERM, ["userid-param", "self"]]}, "pve"),
    ({"check": ["and", ["perm", "/vms/{vmid}", ["VM.Audit"]], ["or", _PERM, ["userid-param", "self"]]]}, "pve"),
    ({"check": ["userid-param", "Realm.AllocateUser"]}, "pve"),
    ({"check": ["userid-group", ["User.Modify"]]}, "pve"),
    ({"check": ["userid-group", ["User.Modify"], "groups_param", "update"]}, "pve"),
    ({"check": ["perm-modify", "{path}"]}, "pve"),
    ({"check": ["admin", "qmanager", "audit", "quser"]}, "pmg"),
    ({"check": _DICT}, "pbs"),                                                  # path [] = the root
    ({"check": {"path": ["datastore", "{store}"], "privs": ["Datastore.Audit"], "partial": True}}, "pdm"),
    ({"or": [{"check": _DICT}, {"userParam": "userid"}]}, "pbs"),
    ({"and": [{"check": _DICT}, {"check": _DICT}]}, "pdm"),
])
def test_every_known_shape_passes(rule, product):
    assert apitree.rule_problem(rule, product) is None


def test_the_shipped_build_refuses_a_vendor_stage_with_a_bad_rule():
    """Lens on 85eb5fe: the build's own refusal was never exercised (deleting it passed the suite)."""
    from proximo.core.errors import ProximoError
    from test_tiers_harvest import bj

    vendor = _vendor()
    vendor[0] = {**vendor[0], "permissions": {"check": "Sys.Audit"}}
    with pytest.raises(ProximoError, match=rf"vendor.json.gz: the rule on {vendor[0]['product']}:"):
        bj.build(vendor, {})                       # the rule is checked before any authored record is read


def test_the_vendor_stage_build_refuses_an_api_viewer_with_a_bad_rule(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location("bgt", ROOT / "scripts" / "build_governance_table.py")
    bgt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bgt)
    tree = [{"path": "/version", "text": "version", "info": {"GET": {"permissions": {"user": "nobody"}}}}]
    for product in apitree.PRODUCTS:
        (tmp_path / f"{product}-apidoc.js").write_text("const apiSchema = " + json.dumps(tree) + ";")
    monkeypatch.setattr(bgt, "gates", lambda: {})
    with pytest.raises(SystemExit, match=r"GET /version: the vendor's permission rule: user"):
        bgt.build(tmp_path)


def test_an_empty_rule_from_the_vendor_is_refused_not_read_as_none(tmp_path, monkeypatch):
    """Lens on 85eb5fe: `permissions or None` turned a published {} into "no rule", a guess."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("bgt2", ROOT / "scripts" / "build_governance_table.py")
    bgt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bgt)
    tree = [{"path": "/version", "text": "version", "info": {"GET": {"permissions": {}}}}]
    for product in apitree.PRODUCTS:
        (tmp_path / f"{product}-apidoc.js").write_text("const apiSchema = " + json.dumps(tree) + ";")
    monkeypatch.setattr(bgt, "gates", lambda: {})
    with pytest.raises(SystemExit, match="empty rule"):
        bgt.build(tmp_path)


@pytest.mark.parametrize("product, rule", [
    (None, {"check": "Sys.Audit"}),                      # a shape no product writes
    ("pbs", {"check": ["perm", "/", ["Sys.Audit"]]}),     # a real PVE rule on a PBS row
    ("pve", {}),                                          # lens 4: `permissions or None` would load it
])
def test_the_loader_refuses_a_shipped_rule_of_an_unknown_shape(monkeypatch, product, rule):
    """The rule is checked twice at build (vendor stage, shipped table) and once more on load, like
    every column: a damaged shipped file refuses every address, never a half-read rule. (Lens 3 on
    3968904: this test was deleted by the rewrite of the cases above it, so the load check went
    unproven; restored with the per-product case.)"""
    from proximo.core.errors import ProximoError

    doc = json.loads(gzip.decompress((ROOT / "src" / "proximo" / "core" / "proximo.json.gz").read_bytes()))
    i = next(i for i, r in enumerate(doc["rows"]) if product is None or r["product"] == product)
    doc["rows"][i]["permissions"] = rule
    blob = gzip.compress(json.dumps(doc).encode())

    class _Files:
        def joinpath(self, name):
            return self

        def read_bytes(self):
            return blob
    monkeypatch.setattr(apitree.resources, "files", lambda pkg: _Files())
    with pytest.raises(ProximoError, match="not the shape the engine governs"):
        apitree.published.__wrapped__()        # the loader itself: published() is cached across the suite


def test_the_pmg_roles_are_exactly_the_four_pmg_publishes():
    """Lens 3: adding a role (say "root") went unseen. PMG's api-viewer names four, measured."""
    assert apitree._PMG_ROLES == frozenset({"admin", "audit", "qmanager", "quser"})


def test_a_rule_nested_past_any_real_depth_is_refused_not_a_recursion_error():
    """Lens 3: a tampered file nesting PVE or 2,000 deep overflowed the stack (RecursionError, not
    the loader's refusal). The data nests 2 deep; the grammar stops at 8."""
    c = _PERM
    for _ in range(2_000):
        c = ["or", c, _PERM]
    problem = apitree.rule_problem({"check": c}, "pve")
    assert problem and "deeper" in problem, problem


def test_a_shell_lane_row_carries_no_rule_or_the_loader_refuses(monkeypatch):
    """Lens 3: nothing at load tied "no rule" to the shell lane (Proximo's rows, not the vendor's)."""
    from proximo.core.errors import ProximoError

    doc = json.loads(gzip.decompress((ROOT / "src" / "proximo" / "core" / "proximo.json.gz").read_bytes()))
    i = next(i for i, r in enumerate(doc["rows"]) if r["wire"] == "ssh")
    doc["rows"][i]["permissions"] = {"user": "all"}
    blob = gzip.compress(json.dumps(doc).encode())

    class _Files:
        def joinpath(self, name):
            return self

        def read_bytes(self):
            return blob
    monkeypatch.setattr(apitree.resources, "files", lambda pkg: _Files())
    with pytest.raises(ProximoError, match="not the shape the engine governs"):
        apitree.published.__wrapped__()


def _nested(levels):
    c = _PERM
    for _ in range(levels):
        c = ["or", c, _PERM]
    return {"check": c}


def test_the_depth_cap_is_eight_exactly():
    """Lens 4 on c31a318: only the 2,000-deep case existed, so a cap of 2, of 100, or `>=` all
    passed. The innermost check of n nested ors sits at depth n."""
    assert apitree.rule_problem(_nested(8), "pve") is None
    problem = apitree.rule_problem(_nested(9), "pve")
    assert problem and "deeper than 8" in problem, problem


def test_a_shipped_file_nested_past_the_parsers_stack_is_refused_not_a_traceback(monkeypatch):
    """Lens 4 on c31a318: json.loads itself raised RecursionError on a 10,000-deep value, before
    any column was read, and the loader caught only (OSError, EOFError, ValueError, zlib.error)."""
    from proximo.core.errors import ProximoError

    blob = gzip.compress(b"[" * 100_000 + b"]" * 100_000)

    class _Files:
        def joinpath(self, name):
            return self

        def read_bytes(self):
            return blob
    monkeypatch.setattr(apitree.resources, "files", lambda pkg: _Files())
    with pytest.raises(ProximoError, match=r"cannot be read \(RecursionError\)"):
        apitree.published.__wrapped__()
