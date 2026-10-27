"""PROXIMO_NODE fills `{node}` when the caller leaves it out (capability `default-node`).

0.44's backend resolved a missing node to the configured one; the cut's path always names the
node. A caller (a small model, a person at a terminal) that knows one node and writes the
published spelling, `/nodes/{node}/status`, now gets it filled from `PROXIMO_NODE`, and the plan
says it did, because a plan that hid where its node came from would be the engine guessing.

The law this keeps: env unset is inert, exactly today's behaviour. Once set it fills only the
slot the caller left as the placeholder, only on the env box's own PVE (a registry target's node
is not this box's, and PBS, PMG and PDM name their nodes their own way), and a value that is not
a node name refuses rather than reaching a path.
"""
from __future__ import annotations

import json
import os

import pytest

from proximo.core import engine, wire
from proximo.core.errors import ProximoError

TEMPLATE, CONCRETE = "/nodes/{node}/status", "/nodes/pve1/status"
START_T, START_C = "/nodes/{node}/qemu/100/status/start", "/nodes/pve1/qemu/100/status/start"


class Wire:
    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        return {"status": "stopped"} if method == "GET" else None


def _rows() -> list[dict]:
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


@pytest.fixture
def w(monkeypatch):
    w = Wire()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    monkeypatch.delenv("PROXIMO_NODE", raising=False)
    return w


# --- inert unset ---------------------------------------------------------------------------

def test_unset_a_template_read_is_refused_at_the_wire_as_before(armed_plane, w):
    with pytest.raises(ProximoError, match=r"needs real values for node"):
        engine.execute(engine.resolve("pve", "GET", "/nodes/{node}/status"), {}, cfg=armed_plane, path=TEMPLATE)
    assert w.calls == []


@pytest.mark.parametrize("value", [None, "", "   "])
def test_unset_or_blank_the_plan_is_exactly_the_plan_without_the_variable(armed_plane, w, monkeypatch, value):
    row = engine.resolve("pve", "POST", START_T)
    before = engine.plan(row, {}, START_T, cfg=armed_plane)
    if value is not None:
        monkeypatch.setenv("PROXIMO_NODE", value)
    after = engine.plan(row, {}, START_T, cfg=armed_plane)
    assert after == before and "default_node" not in after
    assert w.calls == []                                           # a template path reads nothing


def test_set_but_the_caller_named_a_node_nothing_changes(armed_plane, w, monkeypatch):
    monkeypatch.setenv("PROXIMO_NODE", "pve2")
    row = engine.resolve("pve", "GET", "/nodes/{node}/status")
    out = engine.execute(row, {}, cfg=armed_plane, path=CONCRETE)
    assert w.calls == [("GET", CONCRETE, {})] and "default_node" not in out
    assert "default_node" not in engine.plan(engine.resolve("pve", "POST", START_T), {}, START_C, cfg=armed_plane)


# --- set: filled, and said -----------------------------------------------------------------

def test_set_a_template_read_goes_to_the_configured_node(armed_plane, w, monkeypatch):
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    out = engine.execute(engine.resolve("pve", "GET", "/nodes/{node}/status"), {}, cfg=armed_plane, path=TEMPLATE)
    assert w.calls == [("GET", CONCRETE, {})]
    assert out["default_node"] == {"node": "pve1", "from": "PROXIMO_NODE"}
    row = [r for r in _rows() if r["action"] == "core.execute"][-1]
    assert row["target"] == CONCRETE and row["detail"]["default_node"] == "pve1"       # the receipt says it too


def test_set_the_plan_says_the_node_came_from_the_environment(armed_plane, w, monkeypatch):
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    row = engine.resolve("pve", "POST", START_T)
    out = engine.plan(row, {}, START_T, cfg=armed_plane)
    assert out["default_node"] == {"node": "pve1", "from": "PROXIMO_NODE", "path": START_C}
    assert out["allowed"] is True
    assert w.calls and all(c[1].startswith("/nodes/pve1/") for c in w.calls)      # the live read went there too
    # the grant the operator places is for the call as it runs: the same id as the concrete spelling
    concrete = engine.plan(row, {}, START_C, cfg=armed_plane)
    assert out["consent_id"] == concrete["consent_id"]


def test_set_a_template_mutation_runs_on_the_configured_node_and_the_receipt_says_so(armed_plane, w, monkeypatch):
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    row = engine.resolve("pve", "POST", START_T)
    engine.execute(row, {}, cfg=armed_plane, path=START_T)
    assert [c for c in w.calls if c[0] == "POST"] == [("POST", START_C, {})]
    executing = [r for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "executing"]
    assert executing[-1]["target"] == START_C and executing[-1]["detail"]["default_node"] == "pve1"


def test_set_a_node_given_in_the_arguments_is_the_caller_naming_it_not_a_fill(armed_plane, w, monkeypatch):
    """The placeholder left in the path beside a node in the arguments is the caller giving it
    twice with different values, which the engine has always refused. The environment does not
    quietly pick a side."""
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    row = engine.resolve("pve", "GET", "/nodes/{node}/status")
    with pytest.raises(ProximoError, match="given twice"):
        engine.execute(row, {"node": "pve2"}, cfg=armed_plane, path=TEMPLATE)
    assert w.calls == []


# --- the boundaries ---------------------------------------------------------------------------

def test_a_registry_targets_node_is_not_the_env_boxs(w, monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    tok = tmp_path / "t"
    tok.write_text("u@pam!t=00000000-0000-0000-0000-000000000000")
    tok.chmod(0o600)
    east = wire.Plane("pve", "https://east.invalid:8006/api2/json", str(tok), name="east")
    row = engine.resolve("pve", "GET", "/nodes/{node}/status")
    with pytest.raises(ProximoError, match=r"needs real values for node"):
        engine.execute(row, {}, cfg=east, path=TEMPLATE)
    assert w.calls == []
    assert "default_node" not in engine.plan(row, {}, TEMPLATE, cfg=east)


@pytest.mark.parametrize("product", ["pbs", "pmg", "pdm"])
def test_the_other_products_name_their_nodes_their_own_way(w, monkeypatch, product):
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    row = engine.resolve(product, "GET", "/nodes/{node}/status")
    out = engine.plan(row, {}, TEMPLATE)
    assert "default_node" not in out


@pytest.mark.parametrize("bad", ["pve1/../x", "a b", "pve1?x=1", "{node}", "pve1\n", "-pve1", "../pve1", "é1"])
def test_a_value_that_is_not_a_node_name_refuses_and_is_receipted(armed_plane, w, monkeypatch, bad):
    monkeypatch.setenv("PROXIMO_NODE", bad)
    row = engine.resolve("pve", "GET", "/nodes/{node}/status")
    with pytest.raises(ProximoError, match="PROXIMO_NODE"):
        engine.execute(row, {}, cfg=armed_plane, path=TEMPLATE)
    assert w.calls == []
    refused = [r for r in _rows() if r["action"] == "core.refuse"]
    assert refused and refused[-1]["detail"]["needs"] == "config"
    plan = engine.plan(engine.resolve("pve", "POST", START_T), {}, START_T, cfg=armed_plane)
    assert plan["allowed"] is False and plan["needs"] == "config" and "PROXIMO_NODE" in plan["reason"]


def test_a_path_with_no_node_slot_is_left_alone(armed_plane, w, monkeypatch):
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    out = engine.execute(engine.resolve("pve", "GET", "/version"), {}, cfg=armed_plane, path="/version")
    assert w.calls == [("GET", "/version", {})] and "default_node" not in out


# --- where the fill may go: the node-of-this-box slot, and no other (lens: cluster membership) ---------

def test_no_row_is_filled_that_does_not_begin_at_nodes_node(monkeypatch):
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    filled, left = [], []
    for row in engine.table().values():
        if "{node}" not in row.path or row.product != "pve":
            continue
        path, node = engine.default_node(row, row.path, {}, None)
        (filled if node else left).append(row.path)
        assert (node is not None) == (row.path.startswith("/nodes/{node}"))
    assert any(p.startswith("/nodes/{node}") for p in filled) and left
    assert "/cluster/config/nodes/{node}" in left
    assert all(p.startswith("/nodes/{node}") for p in filled)


@pytest.mark.parametrize("method", ["POST", "DELETE"])
def test_the_cluster_membership_rows_are_not_filled_in_a_read_or_a_plan(armed_plane, w, monkeypatch, method):
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    path = "/cluster/config/nodes/{node}"
    key = ("pve", method, path)
    if key not in engine.table():
        pytest.skip("not published")
    out = engine.plan(engine.table()[key], {}, path, cfg=armed_plane)
    assert "default_node" not in out
    with pytest.raises(ProximoError, match="needs real values for node|is held"):
        engine.execute(engine.table()[key], {}, cfg=armed_plane, path=path)


def test_each_reason_not_to_fill_is_its_own_reason(armed_plane, monkeypatch):
    """One unit per clause of the guard, so none of them can be dropped unseen."""
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    row = engine.resolve("pve", "GET", "/nodes/{node}/status")
    asked = "/nodes/{node}/status"
    assert engine.default_node(row, asked, {}, None) == ("/nodes/pve1/status", "pve1")
    assert engine.default_node(row, None, {}, None) == (None, None)                       # no path
    assert engine.default_node(row, asked, {"node": "x"}, None) == (asked, None)          # the caller named it
    east = wire.Plane("pve", "https://e.invalid", "t", name="east")
    assert engine.default_node(row, asked, {}, east) == (asked, None)
    assert engine.default_node(engine.resolve("pbs", "GET", "/nodes/{node}/status"), asked, {}, None) == (asked, None)
    monkeypatch.setenv("PROXIMO_NODE", "  ")
    assert engine.default_node(row, asked, {}, None) == (asked, None)                     # blank is unset


@pytest.mark.parametrize("odd", ["/nodes/{node}/status/extra", "/nodes/{node}", "/nodes//status",
                                 "/nodes/{node}/status/{node}"])
def test_a_path_that_is_not_the_rows_own_shape_is_left_alone_not_zipped(monkeypatch, odd):
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    row = engine.resolve("pve", "GET", "/nodes/{node}/status")
    assert engine.default_node(row, odd, {}, None) == (odd, None)


def test_the_mutation_answer_says_the_node_came_from_the_environment(armed_plane, w, monkeypatch):
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    out = engine.execute(engine.resolve("pve", "POST", START_T), {}, cfg=armed_plane, path=START_T)
    assert out["default_node"] == {"node": "pve1", "from": "PROXIMO_NODE"}
    plain = engine.execute(engine.resolve("pve", "POST", START_C), {}, cfg=armed_plane, path=START_C)
    assert "default_node" not in plain
