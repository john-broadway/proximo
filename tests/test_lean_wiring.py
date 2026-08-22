"""Lean/dynamic mode wiring + the four-layer scoping precedence.

The layers, most specific first:

    PROXIMO_TOOLS      exact tool names
    PROXIMO_TOOLSETS   domain groups, or the literal `dynamic` for the search facade
    PROXIMO_SURFACES   planes
    autoscope          configured planes (default-on)

THE INVARIANT UNDER TEST, and the reason this file is separate from test_lean.py: dispatch must
route through ToolManager.call_tool, the same path the MCP protocol handler uses, so every
decorator still fires — `target_aware`, the PLAN gate, the PROVE ledger write. A dispatcher that
reached the undecorated function would be a second mutate path, silently ungoverned, and would
look identical from the outside. `test_dispatch_runs_the_decorated_function` is the one that
would catch it.
"""
from __future__ import annotations

import anyio
import pytest

from proximo import door, server
from proximo.backends import ProximoError


def _fresh_mcp():
    """A server whose registry mirrors the real one, safe to prune in a test."""
    from proximo._mcpcompat import ServerClass

    m = ServerClass("proximo-test")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    return m


# --- per-tool selection --------------------------------------------------------------------

def test_exact_tool_selection_keeps_only_those():
    kept = door.tool_keep(server.mcp._tool_manager._tools, "pve_list_guests,pve_cluster_status")
    assert kept == {"pve_list_guests", "pve_cluster_status"} | set(door._ALWAYS_REGISTERED), (
        "tool_keep must return the named tools PLUS everything never scopeable away — read\n"
        "the set from the code, never restate it here")


def test_unknown_tool_name_refuses_startup():
    with pytest.raises(ValueError, match="unknown tool"):
        door.tool_keep(server.mcp._tool_manager._tools, "pve_list_guests,pve_no_such_thing")


def test_blank_tool_spec_is_inert():
    reg = server.mcp._tool_manager._tools
    assert door.tool_keep(reg, "") == set(reg)


# --- the dynamic facade --------------------------------------------------------------------

def test_lean_mode_registers_only_the_facade():
    # proximo_recall is part of the default facade since the 0.30 flip (memory default-on).
    m = _fresh_mcp()
    door.apply_lean(m)
    assert set(m._tool_manager._tools) == {
        "proximo_find_tools", "proximo_tool_schema", "proximo_call", "proximo_read",
        "proximo_recall", "audit_verify", "audit_entries",
    }


def test_lean_mode_keeps_the_full_catalog_for_dispatch():
    """Pruning the registry must not destroy what the facade dispatches into."""
    m = _fresh_mcp()
    before = len(m._tool_manager._tools)
    catalog = door.apply_lean(m)
    assert len(catalog) >= before - 4, "catalog lost tools when the registry was pruned"
    assert "pve_list_guests" in catalog


def test_lean_payload_is_a_fraction_of_the_full_surface():
    """The number this whole mode exists for."""
    import json

    m = _fresh_mcp()
    door.apply_lean(m)
    reg = m._tool_manager._tools
    payload = len(json.dumps([
        {"name": n, "description": getattr(t, "description", "") or "",
         "inputSchema": getattr(t, "parameters", {}) or {}}
        for n, t in reg.items()
    ]))
    # 6_000 -> 6_500 on 2026-08-20: proximo_read joined the facade (the enforced read-only
    # door), measured 6,294 B by this rebuild. A deliberate, stated cost — the wire-true
    # figures live in test_schema_budget; this cap only guards against silent facade growth.
    assert payload <= 6_500, f"lean surface is {payload:,} B (~{payload // 4:,} tokens)"


# --- THE SAFETY INVARIANT ------------------------------------------------------------------

def test_dispatch_runs_the_decorated_function():
    """proximo_call must reach the tool THROUGH its decorators, not around them.

    `target_aware` sets the active-target contextvar before calling the wrapped body. If dispatch
    called the raw function, the contextvar would stay None and the call would silently run
    against the default box while claiming otherwise — and every other decorator (PLAN, PROVE)
    would be skipped the same way. Observing the contextvar proves the wrapper ran.
    """
    from proximo import targets

    seen = {}

    def _probe_target_aware() -> dict:
        seen["target"] = targets.active_target()
        return {"ok": True}

    # Registered on the THROWAWAY server, never on server.mcp. The first draft used
    # @server.tool(), which registers globally and permanently — it survived the test and broke
    # the pinned tool count and the taint-classification completeness guard with a 901st tool.
    # Those guards were right; the test was leaking.
    m = _fresh_mcp()
    m.tool()(targets.target_aware(_probe_target_aware))
    catalog = dict(m._tool_manager._tools)

    async def go():
        return await door.dispatch_tool(
            m, catalog, "_probe_target_aware", {"proximo_target": "box-b"}
        )

    anyio.run(go)
    assert seen["target"] == "box-b", (
        "dispatch bypassed target_aware — the decorated wrapper never ran, which means "
        "PLAN/PROVE would be bypassed the same way"
    )


def test_dispatch_refuses_an_unknown_tool():
    m = _fresh_mcp()
    catalog = dict(m._tool_manager._tools)

    async def go():
        return await door.dispatch_tool(m, catalog, "no_such_tool", {})

    # ProximoError with a did-you-mean, not a bare KeyError: in dynamic mode a small model
    # calls directly without the schema step, and a dead-end KeyError was its whole answer
    # (arena verdict 1.12, 2026-07-30).
    with pytest.raises(ProximoError, match="no_such_tool"):
        anyio.run(go)


def test_dispatch_reaches_tools_pruned_from_the_registry():
    """The point of lean mode: a tool absent from tools/list must still be callable."""
    m = _fresh_mcp()
    catalog = door.apply_lean(m)
    assert "pve_list_guests" not in m._tool_manager._tools
    assert "pve_list_guests" in catalog


# --- found by DOGFOODING against a real single-plane box, not by any test above -------------

def test_lean_catalog_respects_configured_planes(monkeypatch):
    """Lean mode must not offer tools for planes this deployment does not have.

    Caught on a live PVE-only box: `proximo_find_tools("cluster status")` returned
    `pdm_pve_cluster_status` and `pmg_cluster_status` ahead of the real answer, on a host with
    no PMG and no PDM configured. Calling either can only fail (`Missing PROXIMO_PMG_BASE_URL`),
    so the facade was advertising capability the deployment does not have and burning the small
    model's turns to discover that.

    Cause: PROXIMO_TOOLSETS wins precedence over autoscope, so the lean branch snapshotted the
    registry BEFORE any plane scoping ran. Every test above either disabled autoscope or used a
    fake registry — they all shared the assumption that every plane is configured.
    """
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.example.lan:8006/api2/json")
    for var in ("PROXIMO_PBS_BASE_URL", "PROXIMO_PMG_BASE_URL", "PROXIMO_PDM_BASE_URL",
                "PROXIMO_TARGETS", "PROXIMO_AUTOSCOPE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_TOOLSETS", "dynamic")

    m = _fresh_mcp()
    door._apply_surfaces(m)
    catalog = door.LEAN_CATALOG

    offered = {n.split("_")[0] for n in catalog}
    assert "pmg" not in offered and "pbs" not in offered and "pdm" not in offered, (
        f"lean catalog offers unconfigured planes: "
        f"{sorted(n for n in catalog if n.startswith(('pmg_', 'pbs_', 'pdm_')))[:5]}"
    )
    assert "pve_cluster_status" in catalog, "the configured plane must still be reachable"


# --- increment 5: memory-first answering -----------------------------------------------------
#
# The facade's cost is ROUND TRIPS, not bytes. A small model must drive find_tools ->
# tool_schema -> call for every question; a 9B stalled empty doing it at 8k ctx. The dominant
# question class ("what exists / how many / what changed") is one memory already holds, counted
# server-side and age-stamped. When memory is on, proximo_recall becomes resident so that class
# costs ONE zero-argument call instead of three hops.
#
# It is KEPT, never redefined. A facade-local wrapper around recall_state would be a second path
# to the same body with none of the decorators — the property this whole mode must not lose.

def test_memory_on_makes_recall_resident_in_the_facade(monkeypatch):
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    m = _fresh_mcp()
    door.apply_lean(m)
    assert set(m._tool_manager._tools) == {
        "proximo_find_tools", "proximo_tool_schema", "proximo_call", "proximo_read",
        "proximo_recall", "audit_verify", "audit_entries",
    }


def test_memory_off_leaves_the_facade_at_four(monkeypatch):
    """No dead tool burning resident tokens on a first call that could only fail."""
    monkeypatch.setenv("PROXIMO_MEMORY", "0")   # memory is default-on since the 0.30 flip
    m = _fresh_mcp()
    door.apply_lean(m)
    assert "proximo_recall" not in m._tool_manager._tools


def test_resident_recall_is_the_governed_tool_itself_not_a_copy(monkeypatch):
    """The invariant: no second path to the same body.

    Would fail if apply_lean defined its own @tool wrapper calling recall_state — that function
    would carry no target_aware, no PLAN gate, no PROVE ledger write, and would look identical
    from the outside.
    """
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    m = _fresh_mcp()
    catalog = door.apply_lean(m)
    assert m._tool_manager._tools["proximo_recall"] is catalog["proximo_recall"]


def test_recall_scoped_away_is_not_resurrected_by_memory_being_on(monkeypatch):
    """PROXIMO_SURFACES excluding memory was a choice; the facade does not overrule it."""
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    m = _fresh_mcp()
    m._tool_manager._tools.pop("proximo_recall", None)
    door.apply_lean(m)
    assert "proximo_recall" not in m._tool_manager._tools


def test_find_tools_sends_estate_questions_to_recall_when_memory_is_on(monkeypatch):
    """A resident tool the model never reaches for is only a token cost.

    find_tools' description IS the small model's map. It must name recall as the one-call answer
    for the estate question class, and must not still claim three tools are loaded.
    """
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    m = _fresh_mcp()
    door.apply_lean(m)
    desc = m._tool_manager._tools["proximo_find_tools"].description
    assert "proximo_recall" in desc
    assert "three tools" not in desc.lower()


def test_find_tools_does_not_advertise_recall_when_memory_is_off(monkeypatch):
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    m = _fresh_mcp()
    door.apply_lean(m)
    desc = m._tool_manager._tools["proximo_find_tools"].description
    assert "proximo_recall" not in desc
