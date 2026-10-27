"""LENS findings on 7e0f55a, each a failing assertion until fixed."""
from __future__ import annotations

import time

import pytest

from proximo.core import engine, risk
from proximo.core.errors import ProximoError


class _W:
    def __init__(self):
        self.calls = []

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        return None


@pytest.mark.parametrize("method,path", [("DELETE", "/cluster/config/nodes/{node}"),
                                         ("POST", "/cluster/config/nodes/{node}")])
def test_default_node_does_not_fill_a_node_that_is_not_this_boxs_own(armed_plane, monkeypatch, method, path):
    """`{node}` here names the node being ADDED to or REMOVED from the cluster, not the box's node."""
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    out = engine.plan(engine.resolve("pve", method, path), {}, path, cfg=armed_plane)
    assert "default_node" not in out


@pytest.mark.parametrize("empty", [[], {}])
def test_ceph_flags_guard_is_not_defeated_by_a_value_the_wire_drops(armed_plane, monkeypatch, empty):
    """httpx encodes `noout=[]` as an empty body: the vendor gets a call naming no flag."""
    w = _W()
    monkeypatch.setattr(engine, "_client", lambda p, c=None: w)
    row = engine.resolve("pve", "PUT", "/cluster/ceph/flags")
    assert engine.plan(row, {"noout": empty}, "/cluster/ceph/flags", cfg=armed_plane)["allowed"] is False
    with pytest.raises(ProximoError):
        engine.execute(row, {"noout": empty}, cfg=armed_plane, path="/cluster/ceph/flags")
    assert not [c for c in w.calls if c[0] == "PUT"]


@pytest.mark.parametrize("kind", ["copy", "chmod"])
def test_the_classifier_is_linear_in_what_it_reads(kind):
    """40KB of a repeated keyword takes seconds-to-minutes today (quadratic regexes); plan has no input cap."""
    start = time.monotonic()
    if kind == "copy":
        risk.classify_sql("COPY " * 8000)
    else:
        risk.classify_command(["sh", "-c", "chmod " * 8000])
    assert time.monotonic() - start < 0.5
