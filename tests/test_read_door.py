"""proximo_read — the read-only twin of the escape hatch: an ENFORCED promise, not a label.

Why it exists (2026-08-20 external report): in the default lean door every call rides
proximo_call, whose only honest static hint is readOnlyHint=False — so a client's
permission policy cannot tell a status read from a power cycle. A hint cannot vary per
dispatched call (annotations ride tools/list, which is static), so the fix is a second
door whose True hint is backed by refusal: classification comes from the SAME
READ-ONLY/MUTATION docstring marker that emits every readOnlyHint (lean.read_only_marker),
so the promise and the enforcement cannot diverge.

Fail-closed both ways: a MUTATION tool refuses, and an UNMARKED tool refuses too — including
proximo_call itself, which would otherwise be the loophole (dispatch the dispatcher through
the read door and mutate under a True hint).
"""
from __future__ import annotations

import anyio
import pytest

from proximo import door, lean, server
from proximo._mcpcompat import ServerClass
from proximo.backends import ProximoError


def _fresh_mcp():
    m = ServerClass("proximo-test-read-door")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    return m


def _read_door(monkeypatch, catalog: dict | None = None):
    """apply_lean on a throwaway server; optionally point the escape catalog at probe tools."""
    m = _fresh_mcp()
    door.apply_lean(m)
    if catalog is not None:
        monkeypatch.setattr(door, "FULL_CATALOG", catalog)
    return m, m._tool_manager._tools["proximo_read"].fn


def _probe_catalog(m) -> dict:
    """Three probe tools registered on a throwaway server, one per marker state."""
    probes = ServerClass("proximo-test-read-door-probes")

    @probes.tool()
    def probe_read() -> dict:
        """READ-ONLY: a probe that only reads."""
        return {"probe": "read"}

    @probes.tool()
    def probe_mut() -> dict:
        """MUTATION: a probe that would mutate."""
        return {"probe": "mut"}

    @probes.tool()
    def probe_unmarked() -> dict:
        """A probe with no marker at all."""
        return {"probe": "unmarked"}

    return dict(probes._tool_manager._tools)


def test_read_door_dispatches_a_read_only_tool(monkeypatch):
    m, read = _read_door(monkeypatch)
    monkeypatch.setattr(door, "FULL_CATALOG", _probe_catalog(m))

    async def go():
        return await read("probe_read", None)

    out = anyio.run(go)
    # dispatch_tool returns through ToolManager.call_tool; unwrap either a raw dict or a
    # wrapped content result by just asserting our sentinel is in its repr.
    assert "read" in repr(out)


def test_read_door_refuses_a_mutation_tool_before_dispatch(monkeypatch):
    """The teeth direction that matters: refusal must PRECEDE dispatch, not follow it.

    A refusal raised after the call went through would pass a naive raises-ProximoError
    assertion while being a real bypass. dispatch_tool is patched to explode, so the only
    way this test passes is enforcement firing first."""
    m, read = _read_door(monkeypatch)
    monkeypatch.setattr(door, "FULL_CATALOG", _probe_catalog(m))

    async def _boom(**kw):
        raise AssertionError("dispatch_tool was reached — enforcement did not precede dispatch")

    monkeypatch.setattr(door, "dispatch_tool", _boom)

    async def go():
        return await read("probe_mut", None)

    with pytest.raises(ProximoError, match="proximo_call"):
        anyio.run(go)


def test_read_door_refuses_an_unmarked_tool_fail_closed(monkeypatch):
    m, read = _read_door(monkeypatch)
    monkeypatch.setattr(door, "FULL_CATALOG", _probe_catalog(m))

    async def go():
        return await read("probe_unmarked", None)

    with pytest.raises(ProximoError, match="fail-closed"):
        anyio.run(go)


def test_read_door_refuses_proximo_call_the_loophole(monkeypatch):
    """proximo_read(tool='proximo_call', arguments={...a mutation...}) must refuse: the
    dispatcher is unmarked by design, and fail-closed is what keeps it from laundering a
    mutation through the read door's True hint."""
    m, read = _read_door(monkeypatch)

    async def go():
        return await read("proximo_call", {"tool": "pve_guest_power",
                                           "arguments": {"vmid": "100", "action": "stop"}})

    with pytest.raises(ProximoError, match="refuses"):
        anyio.run(go)


def test_read_door_resolves_aliases_before_classifying(monkeypatch):
    """A fabricated mutating name must classify as its REAL tool, not slip through as
    unknown-then-dispatched; and the refusal names the resolved tool."""
    m, read = _read_door(monkeypatch)

    async def go():
        return await read("pve_vm_create", None)  # alias of pve_create_vm, a MUTATION

    with pytest.raises(ProximoError, match="pve_create_vm"):
        anyio.run(go)


def test_read_door_lets_a_read_alias_through_to_dispatch(monkeypatch):
    """The clean direction: a read-only tool's alias passes enforcement and reaches dispatch."""
    m, read = _read_door(monkeypatch)
    reached = {}

    async def _spy(**kw):
        reached.update(kw)
        return {"ok": True}

    monkeypatch.setattr(door, "dispatch_tool", _spy)

    async def go():
        return await read("pve_guests_list", None)  # alias of pve_list_guests, READ-ONLY

    anyio.run(go)
    assert reached, "a READ-ONLY alias never reached dispatch"


def test_read_door_unknown_name_gets_the_fail_closed_error(monkeypatch):
    m, read = _read_door(monkeypatch)

    async def go():
        return await read("pve_no_such_thing", None)

    with pytest.raises(ProximoError, match="pve_no_such_thing"):
        anyio.run(go)


def test_read_only_marker_matches_the_annotation_derivation():
    """One source of truth: the door's classifier and the hint derivation must agree on every
    marker shape the existing derivation test pins."""
    assert lean.read_only_marker("READ-ONLY: list things.") is True
    assert lean.read_only_marker("MUTATION: change things.") is False
    assert lean.read_only_marker("MUTATION-CAPABLE: maybe.") is False
    assert lean.read_only_marker("Does a thing, no marker.") is None
    assert lean.read_only_marker(None) is None
