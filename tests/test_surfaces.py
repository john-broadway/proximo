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


# The always-registered set, read from the code rather than restated. These assertions used to
# spell "audit_verify" as a literal in six places, so adding a second always-registered tool
# (proximo_call, the by-name escape hatch) meant six edits and six chances to miss one. The
# property under test is "this filter keeps its plane PLUS whatever is never scopeable", and
# that is what this now says.
ALWAYS = set(server._ALWAYS_REGISTERED)

def test_unset_and_blank_are_inert():
    assert surface_keep(REGISTRY, None) == REGISTRY
    assert surface_keep(REGISTRY, "") == REGISTRY
    assert surface_keep(REGISTRY, "   ") == REGISTRY


def test_single_surface_keeps_only_that_plane_plus_audit():
    keep = surface_keep(REGISTRY, "pbs")
    assert keep == {n for n in REGISTRY if n.startswith("pbs_")} | ALWAYS


def test_multi_surface_union():
    keep = surface_keep(REGISTRY, "pbs, pmg")
    assert {n for n in keep if n not in ALWAYS} == {
        n for n in REGISTRY if n.startswith(("pbs_", "pmg_"))
    }


def test_exec_surface_is_the_ct_tools():
    keep = surface_keep(REGISTRY, "exec")
    assert keep == {"ct_exec", "ct_psql", "ct_logs", "ct_diagnose"} | ALWAYS


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
    orphans = [n for n in REGISTRY if not n.startswith(prefixes) and n not in ALWAYS]
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


def test_nothing_configured_defaults_to_the_dynamic_facade(monkeypatch):
    """The 0.30 flip: a bare default install serves the lean facade, not a catalog.

    Before 0.30 this test asserted the opposite (nothing configured → touch nothing → full
    surface). The measured reason for the flip: the full catalog is ~97k tokens on the wire,
    12x over ollama's default 8,192 window — dead on connect for a local model. The facade
    keeps every tool reachable (proximo_find_tools → proximo_tool_schema → proximo_call);
    PROXIMO_TOOLSETS=catalog or =all restores the old doors by name.
    """
    kept = _probe_registry(monkeypatch, pve=False)
    assert {"proximo_find_tools", "proximo_tool_schema", "proximo_call"} <= kept
    assert "proximo_recall" in kept       # memory rides the default flip too
    assert "pve_doctor" not in kept       # the catalog is searchable, not resident


def test_autoscope_off_still_serves_the_facade_unnarrowed(monkeypatch):
    """PROXIMO_AUTOSCOPE=off no longer means 'full catalog' — the default door is the facade.

    What `off` still controls: the searchable set behind the facade is NOT plane-narrowed,
    so an operator who turns autoscope off can search and reach every plane's tools.
    """
    kept = _probe_registry(monkeypatch, PROXIMO_AUTOSCOPE="off")
    assert "proximo_find_tools" in kept
    assert "pve_doctor" not in kept
    assert any(n.startswith("pmg_") for n in server.LEAN_CATALOG)  # off → searchable set unpruned


def test_apply_surfaces_twice_does_not_narrow_the_searchable_world(monkeypatch):
    """Redteam catch (2026-08-01): pre-flip, a double _apply_surfaces was an idempotent prune.
    Post-flip, a second pass would re-run apply_lean over the FACADE and snapshot those 6 tools
    as LEAN_CATALOG — collapsing the searchable catalog from ~906 to 6 with no error. No
    production path calls it twice today; this pins that an embedder who does is safe."""
    from mcp.server.fastmcp import FastMCP
    for var in ("PROXIMO_SURFACES", "PROXIMO_TOOLSETS", "PROXIMO_TOOLS", "PROXIMO_AUTOSCOPE",
                "PROXIMO_TARGETS", "PROXIMO_API_BASE_URL", "PROXIMO_PBS_BASE_URL",
                "PROXIMO_PMG_BASE_URL", "PROXIMO_PDM_BASE_URL", "PROXIMO_ENABLE_EXEC",
                "PROXIMO_MEMORY", "PROXIMO_WIKI"):
        monkeypatch.delenv(var, raising=False)
    m = FastMCP("probe")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    full = len(m._tool_manager._tools)
    server._apply_surfaces(m)
    once = dict(server.LEAN_CATALOG)
    server._apply_surfaces(m)
    assert len(server.LEAN_CATALOG) == len(once) == full, (
        f"double apply narrowed the searchable catalog {full} -> {len(server.LEAN_CATALOG)}")
    assert "proximo_find_tools" in m._tool_manager._tools


def test_empty_string_scoping_envs_mean_the_default_door(monkeypatch):
    """Redteam probe (2026-08-01), pinned as fact: PROXIMO_SURFACES=\"\" (set but empty) is
    inert — it falls through to the dynamic default, and doctor's scoping line names the
    default rather than rendering 'PROXIMO_SURFACES= — explicit'."""
    from proximo import doctor
    kept = _probe_registry(monkeypatch, PROXIMO_SURFACES="")
    assert "proximo_find_tools" in kept
    monkeypatch.setenv("PROXIMO_SURFACES", "")
    rep = doctor._surfaces_report()
    assert rep["scoping"].startswith("dynamic facade (the default)"), rep["scoping"]


def test_toolsets_catalog_restores_the_preflip_door(monkeypatch):
    """PROXIMO_TOOLSETS=catalog is the pre-0.30 default by name: auto-scoped plane catalog."""
    kept = _probe_registry(monkeypatch, PROXIMO_TOOLSETS="catalog")
    assert any(n.startswith("pve_") for n in kept)
    assert not any(n.startswith(("pmg_", "pdm_")) for n in kept)
    assert "proximo_find_tools" not in kept


def test_autoscope_prunes_to_configured_planes(monkeypatch):
    """In catalog mode, a PVE+PBS-only box auto-serves just those planes' tools."""
    from mcp.server.fastmcp import FastMCP
    for var in ("PROXIMO_SURFACES", "PROXIMO_AUTOSCOPE", "PROXIMO_PMG_BASE_URL",
                "PROXIMO_PDM_BASE_URL", "PROXIMO_ENABLE_EXEC", "PROXIMO_TARGETS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_TOOLSETS", "catalog")
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

def _probe_registry(monkeypatch, pve=True, **env):
    from mcp.server.fastmcp import FastMCP
    for var in ("PROXIMO_SURFACES", "PROXIMO_TOOLSETS", "PROXIMO_TOOLS", "PROXIMO_AUTOSCOPE",
                "PROXIMO_TARGETS", "PROXIMO_API_BASE_URL",
                "PROXIMO_PBS_BASE_URL", "PROXIMO_PMG_BASE_URL", "PROXIMO_PDM_BASE_URL",
                "PROXIMO_ENABLE_EXEC", "PROXIMO_MEMORY", "PROXIMO_WIKI"):
        monkeypatch.delenv(var, raising=False)
    if pve:
        monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.example.lan:8006/api2/json")
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    m = FastMCP("probe")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    server._apply_surfaces(m)
    return set(m._tool_manager._tools)


def test_catalog_autoscope_keeps_memory_tools_by_default(monkeypatch):
    """Memory rides the 0.30 default flip: unset means on, in catalog mode too."""
    kept = _probe_registry(monkeypatch, PROXIMO_TOOLSETS="catalog")
    assert {"proximo_recall", "proximo_baseline"} <= kept


def test_catalog_autoscope_prunes_memory_tools_when_opted_out(monkeypatch):
    """Opted out stays inert — a layer the operator disabled must not cost resident schema."""
    kept = _probe_registry(monkeypatch, PROXIMO_TOOLSETS="catalog", PROXIMO_MEMORY="0")
    assert "proximo_recall" not in kept and "proximo_baseline" not in kept


def test_catalog_autoscope_keeps_wiki_tools_when_the_index_is_enabled(monkeypatch):
    kept = _probe_registry(monkeypatch, PROXIMO_TOOLSETS="catalog", PROXIMO_WIKI="1")
    assert {"proximo_wiki", "proximo_wiki_read"} <= kept


def test_catalog_autoscope_prunes_wiki_tools_when_the_index_is_off(monkeypatch):
    kept = _probe_registry(monkeypatch, PROXIMO_TOOLSETS="catalog")
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


def test_a_utility_surface_alone_does_not_narrow_the_SEARCHABLE_world(monkeypatch):
    """The same property, asserted at the door an operator actually comes through.

    The test above pins _autoscope_keep, which the dynamic path of _apply_surfaces calls.
    Pre-0.30 history: the then-default catalog branch re-implemented the guard as
    `planes - {"exec"}` and treated `memory` alone as a configured plane, narrowing 904 tools
    to 5 with only a stderr note. The 0.30 promise is the updated form of the same law: the
    default door is the facade BY DESIGN (loud, self-describing), but a utility surface alone
    must never narrow the SEARCHABLE world behind it — an ambiguous config gets the same full
    catalog through proximo_find_tools as any other box.
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

    assert set(server.LEAN_CATALOG) == set(full), (
        f"ambiguous config narrowed the searchable catalog {len(full)} -> "
        f"{len(server.LEAN_CATALOG)}; a utility surface is not a data plane")
    assert "proximo_find_tools" in m._tool_manager._tools
