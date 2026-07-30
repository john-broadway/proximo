"""PROXIMO_SURFACES — opt-in registration scoping (context hygiene + surface reduction).

Unset/empty => all tools registered, zero behavior change (the house opt-in contract).
Set => only the named surfaces' tools stay in the MCP registry; everything else is
removed BEFORE serving, so unpicked planes never reach the client's context at all
(a structural gate, not a runtime refusal). `audit_verify` is always kept — PROVE is
never scopeable away. An unknown surface name refuses startup loudly (fail-closed:
a typo must never silently serve a different surface than the operator believes).
"""
from __future__ import annotations

import pytest

from proximo import server
from proximo.server import SURFACES, surface_keep

REGISTRY = set(server.mcp._tool_manager._tools)  # read-only snapshot of the live registry


def test_unset_and_blank_are_inert():
    assert surface_keep(REGISTRY, None) == REGISTRY
    assert surface_keep(REGISTRY, "") == REGISTRY
    assert surface_keep(REGISTRY, "   ") == REGISTRY


def test_single_surface_keeps_only_that_plane_plus_audit():
    keep = surface_keep(REGISTRY, "pbs")
    assert keep == {n for n in REGISTRY if n.startswith("pbs_")} | {"audit_verify"}


def test_multi_surface_union():
    keep = surface_keep(REGISTRY, "pbs, pmg")
    assert {n for n in keep if n != "audit_verify"} == {
        n for n in REGISTRY if n.startswith(("pbs_", "pmg_"))
    }


def test_exec_surface_is_the_ct_tools():
    keep = surface_keep(REGISTRY, "exec")
    assert keep == {"ct_exec", "ct_psql", "ct_logs", "ct_diagnose", "audit_verify"}


def test_audit_verify_always_kept():
    for spec in ("pve", "pbs", "exec", "pve,pbs,pmg,pdm,exec"):
        assert "audit_verify" in surface_keep(REGISTRY, spec)


def test_unknown_surface_refuses_loudly():
    with pytest.raises(ValueError, match="PROXIMO_SURFACES"):
        surface_keep(REGISTRY, "pve,exce")  # the typo that must never pass silently


def test_spec_is_case_insensitive_and_whitespace_tolerant():
    assert surface_keep(REGISTRY, " PVE ,Exec") == surface_keep(REGISTRY, "pve,exec")


def test_every_registered_tool_belongs_to_exactly_one_surface():
    """Completeness guard (same pattern as the TAINT classification test): a new tool
    whose prefix matches no surface would silently survive every filter — fail CI instead."""
    prefixes = tuple(p for pl in SURFACES.values() for p in pl)
    orphans = [n for n in REGISTRY if not n.startswith(prefixes) and n != "audit_verify"]
    assert not orphans, f"tools outside every surface (extend SURFACES or _ALWAYS): {orphans}"
    multi = [n for n in REGISTRY if sum(n.startswith(p) for p in prefixes) > 1]
    assert not multi, f"tools matching more than one surface: {multi}"


def test_apply_surfaces_prunes_a_registry(monkeypatch):
    """_apply_surfaces drives mcp.remove_tool from the env spec — proven on a fake."""
    removed: list[str] = []

    class _FakeTM:
        _tools = {n: None for n in ("pve_doctor", "pbs_prune", "ct_exec", "audit_verify")}

    class _FakeMCP:
        _tool_manager = _FakeTM()

        def remove_tool(self, name: str) -> None:
            removed.append(name)

    monkeypatch.setenv("PROXIMO_SURFACES", "pve")
    server._apply_surfaces(_FakeMCP())
    assert sorted(removed) == ["ct_exec", "pbs_prune"]


def test_apply_surfaces_nothing_configured_touches_nothing(monkeypatch):
    """No PROXIMO_SURFACES and no plane configured → serve the full surface, touch nothing."""
    for var in ("PROXIMO_SURFACES", "PROXIMO_API_BASE_URL", "PROXIMO_PBS_BASE_URL",
                "PROXIMO_PMG_BASE_URL", "PROXIMO_PDM_BASE_URL", "PROXIMO_ENABLE_EXEC",
                "PROXIMO_TARGETS"):
        monkeypatch.delenv(var, raising=False)

    class _FakeMCP:
        def remove_tool(self, name: str) -> None:  # pragma: no cover — must not be called
            raise AssertionError("remove_tool called with nothing configured")

    server._apply_surfaces(_FakeMCP())


def test_apply_surfaces_autoscope_off_touches_nothing(monkeypatch):
    """PROXIMO_AUTOSCOPE=off serves the full surface even with a plane configured."""
    monkeypatch.delenv("PROXIMO_SURFACES", raising=False)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.example.lan:8006/api2/json")
    monkeypatch.setenv("PROXIMO_AUTOSCOPE", "off")

    class _FakeMCP:
        def remove_tool(self, name: str) -> None:  # pragma: no cover — must not be called
            raise AssertionError("remove_tool called with PROXIMO_AUTOSCOPE=off")

    server._apply_surfaces(_FakeMCP())


def test_autoscope_prunes_to_configured_planes(monkeypatch):
    """A PVE+PBS-only box auto-serves just those planes' tools — no PROXIMO_SURFACES flag."""
    from mcp.server.fastmcp import FastMCP
    for var in ("PROXIMO_SURFACES", "PROXIMO_AUTOSCOPE", "PROXIMO_PMG_BASE_URL",
                "PROXIMO_PDM_BASE_URL", "PROXIMO_ENABLE_EXEC", "PROXIMO_TARGETS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.example.lan:8006/api2/json")
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs.example.lan:8007/api2/json")

    m = FastMCP("probe")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)  # mirror the full surface
    full = len(m._tool_manager._tools)
    server._apply_surfaces(m)
    kept = set(m._tool_manager._tools)

    assert len(kept) < full                                   # it narrowed
    assert not any(n.startswith(("pmg_", "pdm_")) for n in kept)   # unconfigured planes gone
    assert any(n.startswith("pve_") for n in kept)            # configured planes stay
    assert any(n.startswith("pbs_") for n in kept)
    assert "audit_verify" in kept                             # always-registered survives


# --- cross-plane utility surfaces vs autoscope ----------------------------------------------
#
# LIVE-CAUGHT 2026-07-29, on the real box, by driving the real config: autoscope silently
# pruned proximo_recall, proximo_baseline, proximo_wiki and proximo_wiki_read — four tools,
# two increments plus the wiki seam, unreachable in the DEFAULT configuration while every unit
# test above stayed green.
#
# Cause: configured_surfaces() detects DATA PLANES from a base URL, and `memory`/`wiki` are not
# planes. They are cross-plane utility surfaces whose configuration signal is their own opt-in
# env var — exactly the shape `exec` already has in that function, and exec was already handled.
# The test doubles never saw it because they mirror the full registry or disable autoscope.

def _probe_registry(monkeypatch, **env):
    from mcp.server.fastmcp import FastMCP
    for var in ("PROXIMO_SURFACES", "PROXIMO_TOOLSETS", "PROXIMO_AUTOSCOPE", "PROXIMO_TARGETS",
                "PROXIMO_PBS_BASE_URL", "PROXIMO_PMG_BASE_URL", "PROXIMO_PDM_BASE_URL",
                "PROXIMO_ENABLE_EXEC", "PROXIMO_MEMORY", "PROXIMO_WIKI"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.example.lan:8006/api2/json")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    m = FastMCP("probe")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    server._apply_surfaces(m)
    return set(m._tool_manager._tools)


def test_autoscope_keeps_memory_tools_when_memory_is_enabled(monkeypatch):
    kept = _probe_registry(monkeypatch, PROXIMO_MEMORY="1")
    assert {"proximo_recall", "proximo_baseline"} <= kept


def test_autoscope_prunes_memory_tools_when_memory_is_off(monkeypatch):
    """Inert stays inert — an opt-in layer nobody enabled must not cost resident schema."""
    kept = _probe_registry(monkeypatch)
    assert "proximo_recall" not in kept and "proximo_baseline" not in kept


def test_autoscope_keeps_wiki_tools_when_the_index_is_enabled(monkeypatch):
    kept = _probe_registry(monkeypatch, PROXIMO_WIKI="1")
    assert {"proximo_wiki", "proximo_wiki_read"} <= kept


def test_autoscope_prunes_wiki_tools_when_the_index_is_off(monkeypatch):
    kept = _probe_registry(monkeypatch)
    assert "proximo_wiki" not in kept and "proximo_wiki_read" not in kept


def test_a_utility_surface_alone_is_not_a_data_plane(monkeypatch):
    """PROXIMO_MEMORY=1 on a box with no plane configured must not narrow to memory only.

    The existing guard — no data plane detectable => leave the registry alone — exists so an
    ambiguous config never yields a near-empty server. A utility surface must not satisfy it.
    """
    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_PBS_BASE_URL", "PROXIMO_PMG_BASE_URL",
                "PROXIMO_PDM_BASE_URL", "PROXIMO_TARGETS", "PROXIMO_AUTOSCOPE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_WIKI", "1")
    assert server._autoscope_keep(set(server.mcp._tool_manager._tools)) is None


def test_a_utility_surface_alone_does_not_narrow_the_SERVED_registry(monkeypatch):
    """The same property, asserted at the door an operator actually comes through.

    The test above pins _autoscope_keep, which only the LEAN branch of _apply_surfaces calls.
    The default branch re-implemented the guard as `planes - {"exec"}` and so treated `memory`
    alone as a configured plane: 904 tools narrowed to 5 (the two memory tools, the two wiki
    tools, always-registered audit_verify) on any box whose data plane is undetectable — an
    unreadable PROXIMO_TARGETS file, a target `kind` outside SURFACES, or the opt-in set before
    the plane. It announces the narrowing on stderr only, which MCP clients do not surface, so
    the operator sees a 5-tool server and no reason for it.

    Guard the OUTCOME, not the helper: a near-empty server is the thing we promised never to ship.
    """
    from mcp.server.fastmcp import FastMCP
    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_PBS_BASE_URL", "PROXIMO_PMG_BASE_URL",
                "PROXIMO_PDM_BASE_URL", "PROXIMO_TARGETS", "PROXIMO_AUTOSCOPE",
                "PROXIMO_SURFACES", "PROXIMO_TOOLSETS", "PROXIMO_TOOLS",
                "PROXIMO_ENABLE_EXEC"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_WIKI", "1")

    full = dict(server.mcp._tool_manager._tools)
    m = FastMCP("probe")
    m._tool_manager._tools = dict(full)
    server._apply_surfaces(m)

    assert set(m._tool_manager._tools) == set(full), (
        f"ambiguous config narrowed the served registry {len(full)} -> "
        f"{len(m._tool_manager._tools)}; a utility surface is not a data plane")
