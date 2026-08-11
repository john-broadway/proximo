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
    """_apply_surfaces drives mcp.remove_tool from the env spec — proven on a fake.

    The double gained a `tool()` decorator when SURFACES stopped being a door (2026-08-02): the
    facade is installed AFTER the plane prune, so a double that cannot register a tool can no
    longer stand in for the server. Both halves are asserted separately below, because the
    ordering is the load-bearing part — pruning after the swap would snapshot the wrong catalog.
    """
    removed: list[str] = []

    class _FakeTM:
        def __init__(self):
            self._tools = {n: None for n in ("pve_doctor", "pbs_prune", "ct_exec", "audit_verify")}

    class _FakeMCP:
        def __init__(self):
            self._tool_manager = _FakeTM()

        def remove_tool(self, name: str) -> None:
            # Mirrors FastMCP: removing an unregistered name RAISES. A double that silently
            # pop()s and still records the name would feed `removed` with calls that would
            # crash a real server at startup (mutation review, 2026-08-02).
            if name not in self._tool_manager._tools:
                raise KeyError(f"Unknown tool: {name}")
            removed.append(name)
            del self._tool_manager._tools[name]

        def tool(self, *a, **kw):   # FastMCP's decorator: registers by function name
            def deco(fn):
                self._tool_manager._tools.setdefault(fn.__name__, fn)   # real one keeps existing
                return fn
            return deco

    monkeypatch.setattr(server, "LEAN_CATALOG", dict(server.LEAN_CATALOG))
    monkeypatch.setenv("PROXIMO_SURFACES", "pve")
    monkeypatch.delenv("PROXIMO_TOOLS", raising=False)
    monkeypatch.delenv("PROXIMO_TOOLSETS", raising=False)
    fake = _FakeMCP()
    server._apply_surfaces(fake)

    # 1. THE PRUNE RAN, AND RAN FIRST. Asserted on the snapshot, not on `removed`: apply_lean
    #    also removes every non-facade tool, so `removed` contains ct_exec/pbs_prune whether or
    #    not the surface prune happened — deleting the prune entirely left this test green
    #    (mutation M01). What only the prune can produce is a CATALOG that never saw them.
    assert "pve_doctor" in server.LEAN_CATALOG          # the named plane survived into the catalog
    assert "ct_exec" not in server.LEAN_CATALOG         # off-plane: pruned BEFORE the snapshot
    assert "pbs_prune" not in server.LEAN_CATALOG
    # 2. the removals really were driven by name...
    assert {"ct_exec", "pbs_prune"} <= set(removed)
    # 3. ...and the door stayed the default facade, which is what makes SURFACES scope-only.
    assert "proximo_find_tools" in fake._tool_manager._tools


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


def test_surfaces_scopes_the_plane_without_picking_the_door(monkeypatch):
    """PROXIMO_SURFACES answers WHICH PLANES, never WHICH DOOR. Regression, external vet 2026-08-02.

    Shipped 0.30.0 collapsed two orthogonal axes into one precedence ladder: _apply_surfaces
    returned on the SURFACES layer, so the layer below it — the dynamic facade, the whole point
    of the 0.30 flip — was unreachable for anyone who had scoped their planes. An adopter who
    followed the setup docs (which encourage PROXIMO_SURFACES) and then removed their catalog
    pin expecting the new default got 569 resident tools instead of 6, with no error and no
    signal. Measured on a live PVE+PBS box by driving the real binary over stdio JSON-RPC:
    unpinning bought 2 tools (571 -> 569), not the facade.

    apply_lean's own docstring already promised this composition ("any scoping applied first
    (auto-scope to configured planes, PROXIMO_SURFACES) narrows the catalog too") — the ladder
    simply never routed SURFACES into it. This pins the promise.
    """
    kept = _probe_registry(monkeypatch, PROXIMO_SURFACES="pve,pbs")
    assert {"proximo_find_tools", "proximo_tool_schema", "proximo_call"} <= kept
    assert "pve_doctor" not in kept          # the catalog is searchable, not resident
    # ...and the operator's plane choice still scopes the SEARCHABLE world behind the facade.
    assert any(n.startswith("pve_") for n in server.LEAN_CATALOG)
    assert any(n.startswith("pbs_") for n in server.LEAN_CATALOG)
    assert not any(n.startswith(("pmg_", "pdm_")) for n in server.LEAN_CATALOG)


def test_surfaces_all_is_a_scope_not_a_door(monkeypatch):
    """PROXIMO_SURFACES=all widens the SEARCHABLE world; it does not make the catalog resident.

    Same shape already shipped for PROXIMO_AUTOSCOPE=off (see
    test_autoscope_off_still_serves_the_facade_unnarrowed): turning OFF narrowing does not
    change which door you came in. `all` means every plane is reachable, not every schema is
    resident. The named door escapes stay PROXIMO_TOOLSETS=catalog / =all.
    """
    kept = _probe_registry(monkeypatch, PROXIMO_SURFACES="all")
    assert "proximo_find_tools" in kept
    assert "pve_doctor" not in kept
    assert any(n.startswith("pmg_") for n in server.LEAN_CATALOG)   # nothing narrowed away
    assert any(n.startswith("pdm_") for n in server.LEAN_CATALOG)


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


# --- external re-vet, 2026-08-02: three gaps an independent lens + a mutation run found -------

def test_double_apply_on_a_CONFIGURED_box_does_not_collapse_the_catalog(monkeypatch):
    """The sibling of test_apply_surfaces_twice_..., in the config where the bug actually fires.

    That test deletes every base-URL var, so autoscope declines to narrow and NO prune runs —
    the one configuration in which a double apply is harmless. On a box with a plane configured,
    the prune removes proximo_find_tools (no surface prefix, not in _ALWAYS_REGISTERED), which
    defeats apply_lean's idempotence guard, and the second pass snapshots the 3-tool facade as
    the searchable world. Measured before the fix: 314 -> 4 on the default door, 312 -> 3 under
    PROXIMO_SURFACES. Embedder-facing only; every shipped entry point applies surfaces once.
    """
    from mcp.server.fastmcp import FastMCP
    for door in ({}, {"PROXIMO_SURFACES": "pve"}):
        for var in ("PROXIMO_SURFACES", "PROXIMO_TOOLSETS", "PROXIMO_TOOLS", "PROXIMO_AUTOSCOPE",
                    "PROXIMO_TARGETS", "PROXIMO_PBS_BASE_URL", "PROXIMO_PMG_BASE_URL",
                    "PROXIMO_PDM_BASE_URL", "PROXIMO_ENABLE_EXEC"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.example.lan:8006/api2/json")
        for k, v in door.items():
            monkeypatch.setenv(k, v)

        m = FastMCP("probe")
        m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
        server._apply_surfaces(m)
        once = len(server.LEAN_CATALOG)
        assert once > 100, f"precondition: a real catalog was snapshotted, got {once}"
        server._apply_surfaces(m)
        assert len(server.LEAN_CATALOG) == once, (
            f"door={door or 'default'}: double apply collapsed the searchable catalog "
            f"{once} -> {len(server.LEAN_CATALOG)}")
        assert "proximo_find_tools" in m._tool_manager._tools


def test_a_utility_only_surface_is_served_plainly_not_behind_a_facade(monkeypatch):
    """`memory`/`wiki`/`exec` are cross-plane utilities, not planes.

    Scoped to those alone the searchable world is a handful of tools, and the facade's own
    description tells the model "the other ~900 are searchable but not resident" — a tool
    description is a prompt, so that is a claim the model acts on. `_autoscope_planes` already
    refuses to narrow on this exact condition; the door layer now refuses too, and the operator
    who asked for a few tools is served those few directly.
    """
    kept = _probe_registry(monkeypatch, PROXIMO_SURFACES="memory", PROXIMO_MEMORY="1")
    assert "proximo_find_tools" not in kept, "a facade over a five-tool world is a false map"
    assert "proximo_recall" in kept          # what they actually asked for is served
    # ...and a REAL plane alongside the utility surface still gets the facade.
    kept = _probe_registry(monkeypatch, PROXIMO_SURFACES="pve,memory", PROXIMO_MEMORY="1")
    assert "proximo_find_tools" in kept
    assert "proximo_recall" in kept          # naming `memory` keeps the one-call estate answer


def test_the_all_escape_is_case_insensitive(monkeypatch):
    """`PROXIMO_SURFACES=ALL` must mean the same as `all` — surviving mutant, mutation run 2026-08-02.

    Dropping `.lower()` sent `ALL` down the prune path, where `surface_keep` refuses an unknown
    surface named "ALL" and the server exits 1. A config that works lowercase and refuses
    uppercase is the "typo'd surface refuses startup" promise firing on a VALID value.
    """
    for spec in ("ALL", " All "):
        kept = _probe_registry(monkeypatch, PROXIMO_SURFACES=spec)
        assert "proximo_find_tools" in kept, spec
        assert any(n.startswith(("pmg_", "pdm_")) for n in server.LEAN_CATALOG), spec


def test_catalog_door_stays_silent_when_it_narrows_nothing(monkeypatch, capsys):
    """_apply_catalog announces ONLY when it actually prunes — mutant M08, 2026-08-02.

    The guard is `len(keep) < len(registry)`; relaxing it to `<=` survived the entire suite,
    because the only observable difference is a stderr line. That line matters: on a box where
    every plane is configured, `<=` prints "auto-scoped to configured planes (...)" having
    removed nothing, which is a doctor-grade lie about what the server just did to itself.
    """
    from mcp.server.fastmcp import FastMCP
    for var in ("PROXIMO_SURFACES", "PROXIMO_TOOLS", "PROXIMO_AUTOSCOPE", "PROXIMO_TARGETS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_TOOLSETS", "catalog")
    # every plane configured => keep == registry => nothing to narrow
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.example.lan:8006/api2/json")
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs.example.lan:8007/api2/json")
    monkeypatch.setenv("PROXIMO_PMG_BASE_URL", "https://pmg.example.lan:8006/api2/json")
    monkeypatch.setenv("PROXIMO_PDM_BASE_URL", "https://pdm.example.lan:8443/api2/json")
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_WIKI", "1")

    m = FastMCP("probe")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    before = len(m._tool_manager._tools)
    capsys.readouterr()                      # drop anything buffered before the call
    server._apply_surfaces(m)
    err = capsys.readouterr().err

    assert len(m._tool_manager._tools) == before, "precondition: nothing should have been pruned"
    assert "auto-scoped" not in err, (
        f"announced a narrowing that did not happen: {err!r}")


# --- L5: proximo_find_tools gives a "no tool does this" signal instead of a bare [] on no match --
def test_find_tools_no_match_returns_a_recoverable_note():
    """A bare [] on a no-match query reads as a dead end and invites a fabricated/near-miss call.
    On no match, proximo_find_tools returns an explicit note pointing at broader terms / proximo_call;
    a real match still returns the plain list of {name, summary}."""
    from mcp.server.fastmcp import FastMCP

    from proximo import server

    m = FastMCP("l5-test")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    server.apply_lean(m)
    find = m._tool_manager._tools["proximo_find_tools"].fn

    miss = find(query="zzzznotarealcapability")
    assert isinstance(miss, dict)
    assert miss["matches"] == []
    assert "proximo_call" in miss["note"]

    hit = find(query="guest power")
    assert isinstance(hit, list) and hit  # a real match is still the plain list
