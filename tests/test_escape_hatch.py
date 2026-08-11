"""The by-name escape hatch: narrowing the resident surface must never narrow REACHABILITY.

RED-FIRST. Every test in this file fails today, and the failures ARE the finding.

Why this file exists. Proximo has four scoping layers (PROXIMO_TOOLS, PROXIMO_TOOLSETS,
PROXIMO_SURFACES, autoscope) and autoscope is ON BY DEFAULT, so the ordinary deployment already
serves a pruned registry: 310 of 904 on a PVE-only box. The only by-name dispatcher in the
codebase, `proximo_call`, is a closure registered inside `apply_lean` (server.py:1500), whose
sole caller is the `PROXIMO_TOOLSETS=dynamic` branch (server.py:1253-1263). So in every other
mode a pruned tool is not merely unadvertised, it is UNREACHABLE — `ToolManager.call_tool`
raises `Unknown tool`, and `call_governed` 404s on the A2A/HTTP faces.

That is tolerable while pruning tracks whole unconfigured PLANES (a `pmg_*` call on a box with
no PMG could only ever fail). It stops being tolerable the moment anything prunes a family of a
CONFIGURED plane for context reasons, because then a working tool has been made unreachable to
save tokens, with no way back inside the session.

So the discriminating case is deliberately NOT an unconfigured plane. It is a tool of a
configured plane, pruned purely for context. `PROXIMO_TOOLSETS=pve.guests` builds exactly that
state with today's code: PVE is configured and reachable, and `pve_ceph_status` is gone.

What these tests would catch that the existing suite cannot: `tests/test_lean_wiring.py` proves
reachability only inside dynamic mode, where the dispatcher happens to exist. Its own module
docstring records the blind spot in this exact area — "Every test above either disabled
autoscope or used a fake registry" — which is how four tools came to be pruned on every real
deployment with the whole suite green. These tests assert the property in the modes that ship.
"""
from __future__ import annotations

import contextlib
from unittest import mock

import anyio
import pytest

from proximo import server
from proximo.audit import AuditLedger


def _fresh_mcp():
    """A server whose registry mirrors the real one, safe to prune in a test.

    Same helper as test_lean_wiring; duplicated deliberately so this file states its own
    assumptions rather than inheriting them from the file whose blind spot it exists to cover.
    """
    from mcp.server.fastmcp import FastMCP

    m = FastMCP("proximo-test")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    return m


def _pve_only(monkeypatch) -> None:
    """A single-plane PVE box with no scoping overrides — the default real deployment."""
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.example.lan:8006/api2/json")
    for var in ("PROXIMO_PBS_BASE_URL", "PROXIMO_PMG_BASE_URL", "PROXIMO_PDM_BASE_URL",
                "PROXIMO_TARGETS", "PROXIMO_AUTOSCOPE", "PROXIMO_TOOLS",
                "PROXIMO_TOOLSETS", "PROXIMO_SURFACES"):
        monkeypatch.delenv(var, raising=False)


def test_a_by_name_dispatcher_is_resident_in_the_default_mode(monkeypatch):
    """Catches: the escape hatch existing only in dynamic mode.

    Mutant it kills: registering the dispatcher inside `apply_lean` only (i.e. today's code).
    Not vacuous — it asserts on the registry produced by the real `_apply_surfaces` under the
    default configuration, not on a mirrored or hand-built one.
    """
    _pve_only(monkeypatch)
    m = _fresh_mcp()
    server._apply_surfaces(m)
    registry = m._tool_manager._tools

    assert len(registry) < len(server.mcp._tool_manager._tools), (
        "precondition failed: autoscope did not prune anything, so this test proves nothing "
        "about reachability under pruning"
    )
    assert "proximo_call" in registry, (
        "no by-name dispatcher is resident in the default (non-dynamic) mode, so every tool "
        f"autoscope pruned is unreachable: {len(registry)} of "
        f"{len(server.mcp._tool_manager._tools)} tools are callable at all"
    )


def test_a_context_pruned_tool_of_a_configured_plane_stays_reachable(monkeypatch):
    """Catches: any narrowing that removes reachability rather than just residency.

    The victim is `pve_ceph_status` on a box whose PVE plane IS configured, pruned only because
    a domain toolset was selected. That is the exact shape an environment-derived fit produces.

    Mutant it kills: snapshotting the dispatch catalog AFTER pruning (today's ordering at
    server.py:1260-1263). Not vacuous — it first asserts the victim really was pruned, so it
    cannot pass by the tool simply still being resident.
    """
    _pve_only(monkeypatch)
    monkeypatch.setenv("PROXIMO_TOOLSETS", "pve.guests")

    m = _fresh_mcp()
    server._apply_surfaces(m)
    registry = m._tool_manager._tools

    assert "pve_ceph_status" not in registry, (
        "precondition failed: the victim was not pruned, so reachability is not under test"
    )

    catalog = getattr(server, "escape_catalog", None)
    assert catalog is not None, (
        "no pre-prune dispatch snapshot exists; a tool pruned for CONTEXT is indistinguishable "
        "from a tool that was never built"
    )
    assert "pve_ceph_status" in catalog(m), (
        "the dispatch snapshot was taken after pruning, so context scoping silently removed "
        "capability instead of removing advertising"
    )


def test_the_dispatcher_routes_through_the_decorated_function(monkeypatch):
    """Catches: an escape hatch that becomes a SECOND, UNGOVERNED mutation path.

    The hatch must reach tools through `ToolManager.call_tool`, the same path the MCP protocol
    handler uses, so `target_aware` and pydantic argument validation still fire.

    CORRECTION, recorded because the first draft of this docstring said otherwise and was wrong.
    PLAN and PROVE are NOT carried by the decorator — `confirm` is a plain parameter and the
    dry-run branch plus the `_audited()` call are inline in each tool's BODY (see
    tools/pve_guest.py:129-149). That is strictly stronger than decorator-carried gates: no
    dispatch path that calls the function at all can skip them, which is why the mutation drill
    for this file could not kill the PLAN/taint tests with a decorator bypass. What the decorator
    genuinely carries is multi-target routing, so THAT is what this test guards.

    Mutant it kills: dispatching to `catalog[name].fn(...)` instead of through the manager —
    which skips `target_aware`, so a `proximo_target` in `arguments` is silently ignored and the
    call lands on the DEFAULT box. On a multi-target deployment that is a wrong-cluster write.
    """
    _pve_only(monkeypatch)

    seen = {}

    def _probe() -> dict:
        from proximo import targets
        seen["target"] = targets.active_target()
        return {"ok": True}

    # Registered on a THROWAWAY server only. @server.tool() would register globally and
    # permanently, breaking the pinned tool count and the taint-completeness guard with a 906th
    # tool — the leak test_lean_wiring.py:105-109 records paying for once already.
    from proximo import targets
    m = _fresh_mcp()
    m.tool()(targets.target_aware(_probe))
    catalog = dict(m._tool_manager._tools)

    async def go():
        return await server.dispatch_tool(m, catalog, "_probe", {"proximo_target": "box-b"})

    anyio.run(go)

    assert seen["target"] == "box-b", (
        "dispatch bypassed target_aware — the decorated wrapper never ran, so a by-name call "
        "carrying proximo_target would silently hit the DEFAULT box instead")


def test_the_network_faces_reach_a_context_pruned_tool(monkeypatch):
    """Catches: an escape hatch built for stdio only.

    `call_governed` (governed.py) is the ONE path all three network faces (A2A, HTTP, MCP-HTTP)
    take, and it resolves names against the live registry — so a pruned tool is a hard 404 there.
    The hatch covers them without any face-specific code, because `proximo_call` is resident on
    every transport and dispatches from the pre-prune snapshot.

    NOTE — the first draft of this test asserted a `server.resolve_for_face()` API. That was an
    invented mechanism, not the real one, and it was red for the wrong reason. Proved by running
    the real face path: the correct property is that the hatch is REACHABLE through
    `call_governed`, not that a second resolver exists. Kept visible because a test that fails
    for a reason its author made up is worth exactly as little as one that passes for a reason
    its author made up.

    Mutant it kills: dropping `proximo_call` from `_ALWAYS_REGISTERED`, which leaves stdio's
    lean-mode facade working while every network face 404s — a surface that differs by transport,
    which SECURITY.md promises it does not.
    """
    import anyio

    from proximo import governed

    _pve_only(monkeypatch)
    monkeypatch.setenv("PROXIMO_TOOLSETS", "pve.guests")

    # `call_governed` reads the module-global `server.mcp` directly, so this test cannot use a
    # throwaway server — it has to prune the real registry. Save and restore the dict CONTENTS
    # (not the dict object: _prune_registry mutates in place via remove_tool). Without this the
    # test permanently strands 877 tools for every test that runs after it, which is the same
    # global-registry leak test_lean_wiring.py:105-109 records paying for once already.
    saved = dict(server.mcp._tool_manager._tools)
    try:
        server._apply_surfaces()
        assert "pve_ceph_status" not in server.mcp._tool_manager._tools, (
            "precondition failed: the victim was not pruned")

        async def go(name, args):
            try:
                await governed.call_governed(name, args)
                return "ok"
            except governed.GovernedError as e:
                return f"{e.status}:{e!s}"

        direct = anyio.run(go, "pve_ceph_status", {})
        assert direct.startswith("404"), (
            f"expected the direct face call to 404 on a pruned tool, got {direct!r}")

        hatched = anyio.run(go, "proximo_call", {"tool": "pve_ceph_status", "arguments": {}})
        assert not hatched.startswith("404"), (
            "the face could not reach a pruned tool through the hatch — the escape hatch is "
            f"stdio-only and the surface differs by transport ({hatched!r})")
        # 502 here means the tool was RESOLVED and RAN (and then failed on an unreachable test
        # API, which is the expected end of the road in a unit test). Reaching it is the
        # property; succeeding against a fake host is not.
        assert "ToolError" in hatched or hatched == "ok", (
            f"expected the tool to run and fail on connectivity, got {hatched!r} — a "
            "ProximoError here would mean the hatch itself refused the name")
    finally:
        server.mcp._tool_manager._tools.clear()
        server.mcp._tool_manager._tools.update(saved)


def test_taint_fires_with_the_INNER_tool_name_through_the_hatch(tmp_path, monkeypatch):
    """Catches: the hatch becoming a taint-laundering path.

    `proximo_call` is NOT classified adversarial, and that is only correct if dispatching an
    adversarial tool through it still marks. The marker is set in `_audited` (server.py:368) on
    the tool name it is called with — through the hatch that is the INNER tool's name, because
    dispatch runs the decorated wrapper. If it were ever the hatch's own name, every adversarial
    read reached by name would launder its guest-authored bytes into the model clean.

    Mutant it kills: making `dispatch_tool` reach `tool.fn.__wrapped__` (or the module-level
    function) instead of going through `ToolManager.call_tool` — the decorators would not fire,
    and this test would see no marker at all.
    """
    from proximo import taint

    monkeypatch.setenv(taint.TAINT_TRACK_ENV, "1")
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))

    victim = "pve_list_guests"
    assert taint.is_adversarial(victim), "precondition: the inner tool must be adversarial"
    assert not taint.is_adversarial("proximo_call"), (
        "precondition: the hatch itself is deliberately NOT adversarial — it carries no bytes "
        "of its own, so classifying it would taint every by-name call including pure reads")
    assert not taint.is_tainted(str(tmp_path)), "precondition: not tainted yet"

    # `_svc()` runs BEFORE `_audited` in every plane wrapper, so an unconfigured box raises at
    # config time and never reaches the taint gate at all. That is correct (no bytes came back,
    # so there is nothing to taint) and it is also why a naive probe here reports a false clean:
    # the direct call behaves identically. Stub the backend so the body actually reaches
    # `_audited`, which is the code under test.
    # The ledger comes from _svc()[3] (server.py:139), and the taint marker is written beside
    # THAT path — so the injected ledger, not PROXIMO_AUDIT_LOG, is what puts the marker in
    # tmp_path. Passing None here silently produced a false clean on my first two attempts.
    cfg = mock.MagicMock()
    cfg.node = "testnode"
    fake = mock.MagicMock()
    fake.list_guests.return_value = [{"vmid": "100", "name": "g", "type": "lxc",
                                      "status": "running"}]
    ledger = AuditLedger(str(tmp_path / "audit.log"))
    monkeypatch.setattr(server, "_svc", lambda *a, **k: (cfg, fake, None, ledger))

    async def call(name):
        return await server.proximo_call(tool=name, arguments={})

    anyio.run(call, victim)

    assert taint.is_tainted(str(tmp_path)), (
        "dispatching an adversarial tool by name left NO taint marker — the hatch is a "
        "laundering path")
    assert victim in taint.taint_sources(str(tmp_path)), (
        f"the marker names {taint.taint_sources(str(tmp_path))}, not the inner tool {victim!r} — "
        "attributing the read to the dispatcher hides which tool carried the untrusted bytes")


def test_the_PLAN_gate_holds_through_the_hatch(tmp_path, monkeypatch):
    """Catches: the escape hatch becoming a mutation bypass — the worst thing it could be.

    `proximo_call` takes no `confirm` parameter of its own and is exempt from
    test_server_plan.py's confirm-gate sweep. That exemption is only defensible if the INNER
    tool's dry-run gate still fires, so this proves it rather than asserting it: a mutation
    reached BY NAME with no confirm must come back as a plan and must not touch the backend.

    Mutant it kills: any dispatch that reaches the undecorated function (the PLAN gate lives in
    the wrapper), and any future `confirm`-shaped parameter on the hatch that could satisfy the
    gate without the inner tool seeing it.
    """
    cfg = mock.MagicMock()
    cfg.node = "testnode"
    api = mock.MagicMock()
    api.guest_status.return_value = {"status": "running", "name": "g", "uptime": 1}
    ledger = AuditLedger(str(tmp_path / "audit.log"))
    monkeypatch.setattr(server, "_svc", lambda *a, **k: (cfg, api, None, ledger))

    async def call(args):
        return await server.proximo_call(tool="pve_guest_power", arguments=args)

    result = anyio.run(call, {"vmid": "100", "action": "stop"})

    assert isinstance(result, dict) and result.get("status") == "plan", (
        f"a mutation reached by name did NOT dry-run: got {result!r} — the escape hatch is a "
        "mutation bypass")
    assert not api.guest_power.called, (
        "the backend mutation ran on an unconfirmed by-name call — PLAN was bypassed entirely")


def test_the_hatch_does_not_defeat_a_SECURITY_gate(tmp_path, monkeypatch):
    """Catches: the escape hatch turning a security control into a suggestion.

    This is the sharpest question the hatch raises, and it has a good answer only because the
    controls were built in the right place. Autoscope drops the `ct_*` tools entirely when
    PROXIMO_ENABLE_EXEC is unset (`configured_surfaces`, server.py:1171), so on a default box
    they are not registered — and the hatch can now reach anything that was ever registered.
    If non-registration were the enforcement, this commit would have handed an agent in-container
    exec on every box that deliberately disabled it.

    It is not. `enable_exec` and the CTID allowlist are checked in the tool BODY
    (server.py:659-663, 717-721), so they fire on any path that calls the function at all.
    Proven here, both gates, rather than argued from where the code sits.

    Mutant it kills: moving either gate out of the body and relying on registration — and, more
    plausibly, a future scoping layer that assumes "pruned" means "cannot be called".
    """
    cfg = mock.MagicMock()
    cfg.enable_exec = False
    cfg.redact_ledger = True
    cfg.node = "n"
    cfg.ct_permitted.return_value = False
    api, exec_backend = mock.MagicMock(), mock.MagicMock()
    ledger = AuditLedger(str(tmp_path / "audit.log"))
    monkeypatch.setattr(server, "_svc", lambda *a, **k: (cfg, api, exec_backend, ledger))

    async def call(tool, args):
        return await server.proximo_call(tool=tool, arguments=args)

    for tool, args in (("ct_exec", {"ctid": "100", "command": ["id"], "confirm": True}),
                       ("ct_psql", {"ctid": "100", "sql": "select 1", "confirm": True})):
        result = anyio.run(call, tool, args)
        assert result.get("status") == "blocked:exec_disabled", (
            f"{tool} reached by name RAN with PROXIMO_ENABLE_EXEC unset: {result!r} — the hatch "
            "defeated a security control that registration was carrying")
    assert not exec_backend.called, "the exec backend was touched despite exec being disabled"

    # Second gate, independently: exec on, CTID not on the allowlist.
    cfg.enable_exec = True
    result = anyio.run(call, "ct_exec", {"ctid": "999", "command": ["id"], "confirm": True})
    assert result.get("status") == "blocked:allowlist", (
        f"a CTID off the allowlist was reachable by name: {result!r}")
    assert not exec_backend.called


def test_arguments_are_validated_not_passed_raw(tmp_path, monkeypatch):
    """Catches: the hatch becoming an unvalidated argument channel.

    `arguments` is a free-form dict on the wire. Because dispatch goes through
    ToolManager.call_tool, each tool's own pydantic model still validates it — a wrong-typed
    argument is rejected before the body runs, exactly as it would be on a direct call.

    Mutant it kills: dispatching to the function with `**arguments` and skipping validation,
    which would let a by-name call hand a tool a shape a direct call could never produce.
    """
    cfg = mock.MagicMock()
    cfg.enable_exec = True
    cfg.redact_ledger = True
    cfg.node = "n"
    ledger = AuditLedger(str(tmp_path / "audit.log"))
    monkeypatch.setattr(server, "_svc",
                        lambda *a, **k: (cfg, mock.MagicMock(), mock.MagicMock(), ledger))

    async def call():
        # `command` is a list[str]; a bare string must be refused by the tool's own model.
        return await server.proximo_call(tool="ct_exec",
                                         arguments={"ctid": "100", "command": "id"})

    with pytest.raises(Exception, match="validation error"):
        anyio.run(call)


def test_the_snapshot_is_the_COMPLETE_registry_not_a_subset():
    """Catches: a snapshot that silently holds only part of the surface.

    Every other test in this file names a `pve_*` victim, so a snapshot that dropped every
    pbs_/pmg_/pdm_ tool would satisfy all of them and the whole suite stayed green — a reviewer
    demonstrated exactly that mutant surviving 11,575 tests. "Missing a tool" and "missing a
    PLANE" are different instruments and only the first was pointed at.

    This asserts the property directly: the escape catalog IS the registry as it stood before
    any scoping ran, name for name.

    Mutant it kills: any filter applied to FULL_CATALOG at snapshot time, including one that
    drops a whole plane.
    """
    catalog = server.escape_catalog()
    registry = server.mcp._tool_manager._tools

    missing = set(registry) - set(catalog)
    assert not missing, f"the escape catalog is missing {len(missing)} registered tools: {sorted(missing)[:8]}"
    assert set(catalog) == set(registry), (
        f"escape catalog ({len(catalog)}) != live registry ({len(registry)}) — the hatch reaches "
        "a different set than the server has")

    # And it must span every plane, stated per-prefix so a plane-shaped hole names itself.
    for prefix in ("pve_", "pbs_", "pmg_", "pdm_", "ct_"):
        assert any(n.startswith(prefix) for n in catalog), (
            f"no {prefix}* tool in the escape catalog — a whole plane is unreachable by name")


def test_dynamic_mode_reaches_a_tool_outside_the_LEAN_CATALOG(monkeypatch):
    """Catches: the hatch re-narrowed to the lean catalog in the mode it is most advertised for.

    In dynamic mode `LEAN_CATALOG` is the POST-autoscope set (311 on a PVE-only box) while the
    escape catalog is the full 905 — `_apply_surfaces` autoscopes before `apply_lean` snapshots.
    A reviewer's mutant made `escape_catalog()` prefer `LEAN_CATALOG`, reinstating the exact
    pre-commit bug, and nothing noticed because no test drove the hatch at a tool outside the
    lean catalog while dynamic mode was active.

    Mutant it kills: `escape_catalog` returning LEAN_CATALOG (or any post-prune set) first.
    """
    _pve_only(monkeypatch)
    monkeypatch.setenv("PROXIMO_TOOLSETS", "dynamic")

    saved = dict(server.mcp._tool_manager._tools)
    try:
        server._apply_surfaces()
        victim = "pmg_cluster_status"   # a plane this box has NOT configured
        assert victim not in server.LEAN_CATALOG, (
            "precondition failed: the victim is inside the lean catalog, so reaching it proves "
            "nothing about the hatch seeing past it")
        assert victim in server.escape_catalog(), (
            "dynamic mode's hatch cannot see past the lean catalog — a by-name call to a tool "
            "outside it is unreachable, which is the bug this feature exists to fix")
    finally:
        server.mcp._tool_manager._tools.clear()
        server.mcp._tool_manager._tools.update(saved)


def test_dispatch_leaves_the_registry_unchanged(monkeypatch):
    """Catches: the temporary re-attach in dispatch_tool never being undone.

    `dispatch_tool` briefly puts the target back in the registry so `call_tool` can resolve it,
    then removes it (server.py:1437-1439). A reviewer's mutant replaced that `finally` with
    `pass` — permanently re-registering every scoped-away tool on first by-name use, so the
    advertised surface grows silently as an agent works — and 11,575 tests stayed green.

    Mutant it kills: `finally: pass` in dispatch_tool.
    """
    _pve_only(monkeypatch)
    monkeypatch.setenv("PROXIMO_TOOLSETS", "pve.guests")

    saved = dict(server.mcp._tool_manager._tools)
    try:
        server._apply_surfaces()
        before = set(server.mcp._tool_manager._tools)
        assert "pve_ceph_status" not in before, "precondition failed: victim not pruned"

        async def call():
            with contextlib.suppress(Exception):
                await server.proximo_call(tool="pve_ceph_status", arguments={})

        anyio.run(call)

        after = set(server.mcp._tool_manager._tools)
        assert after == before, (
            f"dispatch changed the advertised registry: added {sorted(after - before)}, "
            f"removed {sorted(before - after)} — a by-name call must not grow tools/list")
    finally:
        server.mcp._tool_manager._tools.clear()
        server.mcp._tool_manager._tools.update(saved)


# === M2: verb-first legacy names — the fabricated noun_verb guess routes to the real tool ========
def test_resolve_alias_maps_guesses_and_passes_others_through():
    from proximo import lean
    assert lean.resolve_alias("pve_vm_create") == "pve_create_vm"
    assert lean.resolve_alias("pve_guests_list") == "pve_list_guests"
    assert lean.resolve_alias("pve_guest_status") == "pve_guest_status"  # real name unchanged
    assert lean.resolve_alias("nonsense") == "nonsense"


def _empty_mcp():
    from mcp.server.fastmcp import FastMCP
    return FastMCP("proximo-alias-test")


def test_dispatch_routes_an_alias_guess_to_the_real_tool():
    """proximo_call(tool='pve_vm_create') must reach the REAL tool pve_create_vm, not dead-end.
    The verb-first legacy names are the only ones where did-you-mean mis-ranks the natural guess."""
    ran = {}

    def pve_create_vm() -> dict:
        ran["hit"] = True
        return {"ok": True}

    m = _empty_mcp()
    m.tool(name="pve_create_vm")(pve_create_vm)
    catalog = dict(m._tool_manager._tools)

    async def go():
        return await server.dispatch_tool(m, catalog, "pve_vm_create", {})

    anyio.run(go)
    assert ran.get("hit") is True


def test_tool_schema_resolves_an_alias_guess():
    from proximo import lean

    def pve_create_vm() -> dict:
        return {"ok": True}

    m = _empty_mcp()
    m.tool(name="pve_create_vm", description="MUTATION: make a VM")(pve_create_vm)
    catalog = dict(m._tool_manager._tools)
    got = lean.tool_schema(catalog, "pve_vm_create")
    assert got["name"] == "pve_create_vm"


# === H1: a direct call for a non-resident/unknown name gets a proximo_call pointer, not a dead end =
def test_unknown_tool_error_points_a_nonresident_real_name_at_proximo_call():
    # A real catalog tool named directly on the dynamic door (where it isn't resident) -> pointer.
    real = next(iter(server.FULL_CATALOG))  # any real tool name
    msg = server._unknown_tool_error(real)
    assert "proximo_call" in msg
    assert real in msg


def test_unknown_tool_error_resolves_an_alias_guess_in_the_pointer():
    msg = server._unknown_tool_error("pve_vm_create")
    assert "pve_create_vm" in msg  # the pointer names the REAL tool, not the guess
    assert "proximo_call" in msg


def test_unknown_tool_error_gives_did_you_mean_and_keeps_the_substring():
    msg = server._unknown_tool_error("totally_made_up_xyz")
    assert "unknown tool" in msg  # lowercase substring the governed/lean faces already return
    assert "proximo_call" in msg


def test_interceptor_returns_a_helpful_error_over_the_protocol():
    """The re-registered CallToolRequest handler turns a non-resident name into an isError result
    carrying the proximo_call pointer — not FastMCP's bare 'Unknown tool: X' dead end."""
    import mcp.types as mt
    handler = server.mcp._mcp_server.request_handlers[mt.CallToolRequest]

    async def call(name):
        req = mt.CallToolRequest(method="tools/call",
                                 params=mt.CallToolRequestParams(name=name, arguments={}))
        return (await handler(req)).root

    res = anyio.run(call, "pve_vm_create")
    assert res.isError
    assert "proximo_call" in res.content[0].text
