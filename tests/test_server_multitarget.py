"""Multi-target wiring: the plane resolvers route by the active target contextvar."""
import textwrap

import pytest

from proximo import server, targets
from proximo.backends import ProximoError


@pytest.fixture(autouse=True)
def _clear_svc_cache():
    # Backends/ledger are cached per target; env varies per test, so reset around each.
    def _clear():
        for fn in (server._svc, server._pbs, server._pmg, server._pdm):
            fn.cache_clear()
    _clear()
    yield
    _clear()


def _registry(monkeypatch, tmp_path, body):
    p = tmp_path / "targets.toml"
    p.write_text(textwrap.dedent(body))
    monkeypatch.setenv("PROXIMO_TARGETS", str(p))


def _env_default(monkeypatch):
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://192.0.2.10:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "home")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/etc/proximo/home.token")


def test_svc_default_uses_from_env(monkeypatch):
    _env_default(monkeypatch)
    token = targets._active_target.set(None)
    try:
        cfg, _api, _exec, _led = server._svc()
        assert cfg.node == "home"
    finally:
        targets._active_target.reset(token)


def test_svc_named_target_uses_registry(monkeypatch, tmp_path):
    _env_default(monkeypatch)
    _registry(monkeypatch, tmp_path, """
        [targets.edge]
        kind = "pve"
        base_url = "https://198.51.100.20:8006/api2/json"
        node = "edge"
        token_path = "/etc/proximo/edge.token"
    """)
    token = targets._active_target.set("edge")
    try:
        cfg, _api, _exec, _led = server._svc()
        assert cfg.node == "edge"
        assert cfg.api_base_url.startswith("https://198.51.100.20")
    finally:
        targets._active_target.reset(token)


def test_svc_targets_only_needs_no_single_target_env(monkeypatch, tmp_path):
    # Real multi-target install, 2026-07-06: `proximo doctor --target edge` with a valid
    # PROXIMO_TARGETS but NO single-target env vars raised "Missing required Proximo env var:
    # PROXIMO_API_BASE_URL" — because the instance ledger was built from_env(), which hard-requires
    # the API triple. The ledger reads only audit_* fields, so a pure-targets deployment must stand
    # up its ledger without them. NO _env_default() here — that is the whole point.
    monkeypatch.delenv("PROXIMO_API_BASE_URL", raising=False)
    monkeypatch.delenv("PROXIMO_NODE", raising=False)
    monkeypatch.delenv("PROXIMO_TOKEN_PATH", raising=False)
    server._svc_cache_clear()  # drop any instance ledger a prior test built from_env
    _registry(monkeypatch, tmp_path, """
        [targets.edge]
        kind = "pve"
        base_url = "https://198.51.100.20:8006/api2/json"
        node = "edge"
        token_path = "/etc/proximo/edge.token"
    """)
    token = targets._active_target.set("edge")
    try:
        cfg, _api, _exec, led = server._svc()
        assert cfg.node == "edge"
        assert led is not None          # the instance ledger stood up without the API triple
    finally:
        targets._active_target.reset(token)
        server._svc_cache_clear()


def test_svc_pbs_target_on_pve_resolver_raises(monkeypatch, tmp_path):
    _env_default(monkeypatch)
    _registry(monkeypatch, tmp_path, """
        [targets.backup]
        kind = "pbs"
        base_url = "https://192.0.2.7:8007"
        token_path = "/etc/proximo/pbs.token"
    """)
    token = targets._active_target.set("backup")
    try:
        with pytest.raises(ProximoError, match="not usable by a PVE tool"):
            server._svc()
    finally:
        targets._active_target.reset(token)


def test_audited_records_active_target_as_remote(monkeypatch, tmp_path):
    """A targeted, audited mutation must record remote=<target> — proving PROVE saw the right box.
    This is the wrong-box regression guard from the design.

    `edge` is registered in PROXIMO_TARGETS so the mutation clears the per-surface envelope: an
    active target that is NOT in the registry now fails closed (forbid-all) — the stale-cache
    guard from the envelope spec §11.A. In production an active target only reaches `_audited`
    when it IS registered (else `_svc()`/`resolve_target_fields` raises first), so registering it
    here makes the fixture faithful to production rather than relying on the old permissive path."""
    _registry(monkeypatch, tmp_path, """
        [targets.edge]
        kind = "pve"
        base_url = "https://198.51.100.20:8006/api2/json"
        node = "edge"
        token_path = "/etc/proximo/edge.token"
    """)
    recorded = {}

    class _FakeLedger:
        def record(self, action, *, target, mutation=False, outcome="ok", detail=None,
                   remote=None, principal=None):
            recorded.update(action=action, remote=remote, outcome=outcome)
            return {}

    monkeypatch.setattr(server, "_svc", lambda: (None, None, None, _FakeLedger()))
    token = targets._active_target.set("edge")
    try:
        server._audited("pve_guest_power", "131", lambda: {"ok": True}, mutation=True)
    finally:
        targets._active_target.reset(token)
    assert recorded["remote"] == "edge"


def test_audited_default_records_no_remote(monkeypatch):
    recorded = {}

    class _FakeLedger:
        def record(self, action, *, target, mutation=False, outcome="ok", detail=None,
                   remote=None, principal=None):
            recorded.update(remote=remote)
            return {}

    monkeypatch.setattr(server, "_svc", lambda: (None, None, None, _FakeLedger()))
    token = targets._active_target.set(None)
    try:
        server._audited("pve_guest_power", "131", lambda: {"ok": True}, mutation=True)
    finally:
        targets._active_target.reset(token)
    assert recorded["remote"] is None


def test_ledger_tolerates_non_pve_active_target(monkeypatch, tmp_path):
    """_ledger() must return the instance ledger even when the active target is non-pve
    (a pbs_*/pmg_*/pdm_* tool's ledger call) — without raising. Cross-plane fix.
    _svc() itself stays strict (kind safety for pve tool bodies)."""
    _env_default(monkeypatch)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    _registry(monkeypatch, tmp_path, """
        [targets.backup]
        kind = "pbs"
        base_url = "https://192.0.2.7:8007"
        token_path = "/etc/proximo/pbs.token"
    """)
    token = targets._active_target.set("backup")
    try:
        led = server._ledger()        # must NOT raise (pbs target, pve resolver would)
        assert led is not None
        with pytest.raises(ProximoError, match="not usable by a PVE tool"):
            server._svc()             # strict: a pve tool body aimed at a pbs target still errors
    finally:
        targets._active_target.reset(token)


# --- PBS / PMG / PDM resolvers route by the active target too ---

def test_pbs_default_and_named_and_kindmismatch(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://192.0.2.7:8007")
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", "/etc/proximo/pbs.token")
    # default -> env
    tok = targets._active_target.set(None)
    try:
        cfg, _ = server._pbs()
        assert cfg.base_url.startswith("https://192.0.2.7")
    finally:
        targets._active_target.reset(tok)
    # named -> registry
    _registry(monkeypatch, tmp_path, """
        [targets.offsite]
        kind = "pbs"
        base_url = "https://198.51.100.7:8007"
        token_path = "/etc/proximo/offsite.token"
        [targets.edge]
        kind = "pve"
        base_url = "https://198.51.100.20:8006/api2/json"
        node = "edge"
        token_path = "/etc/proximo/edge.token"
    """)
    tok = targets._active_target.set("offsite")
    try:
        cfg, _ = server._pbs()
        assert cfg.base_url.startswith("https://198.51.100.7")
    finally:
        targets._active_target.reset(tok)
    # a pve target on the pbs resolver -> kind mismatch
    tok = targets._active_target.set("edge")
    try:
        with pytest.raises(ProximoError, match="not usable by a PBS tool"):
            server._pbs()
    finally:
        targets._active_target.reset(tok)


def test_pmg_named_target_uses_registry(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_PMG_BASE_URL", "https://192.0.2.9:8006")
    monkeypatch.setenv("PROXIMO_PMG_PASSWORD_PATH", "/etc/proximo/pmg.pw")
    _registry(monkeypatch, tmp_path, """
        [targets.mail2]
        kind = "pmg"
        base_url = "https://198.51.100.9:8006"
        password_path = "/etc/proximo/mail2.pw"
        node = "mail2"
    """)
    tok = targets._active_target.set("mail2")
    try:
        cfg, _ = server._pmg()
        assert cfg.base_url.startswith("https://198.51.100.9")
        assert cfg.node == "mail2"
    finally:
        targets._active_target.reset(tok)


def test_pdm_named_target_uses_registry(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_PDM_BASE_URL", "https://192.0.2.11:8443")
    monkeypatch.setenv("PROXIMO_PDM_TOKEN_PATH", "/etc/proximo/pdm.token")
    _registry(monkeypatch, tmp_path, """
        [targets.dc2]
        kind = "pdm"
        base_url = "https://198.51.100.11:8443"
        token_path = "/etc/proximo/dc2.token"
    """)
    tok = targets._active_target.set("dc2")
    try:
        cfg, _ = server._pdm()
        assert cfg.base_url.startswith("https://198.51.100.11")
        assert cfg.base_url.endswith("/api2/json")  # PDM normalization applied to target too
    finally:
        targets._active_target.reset(tok)


# --- ct_* exec/diagnose tools must be target-aware (redteam MEDIUM: sweep missed ct_ prefix) ---

def _accepts_target(name: str) -> bool:
    """Does this tool's callable actually ACCEPT proximo_target?

    The advertised schema is downstream of this: `target_aware` injects the kwarg into the
    wrapper and the schema is generated from that signature. Asserting on the schema was a
    PROXY for the injection working — and the proxy broke the moment the schema was allowed to
    omit an unusable parameter (a box with no PROXIMO_TARGETS registry). Routing has always run
    off the signature, so assert the signature.
    """
    import inspect

    fn = server.mcp._tool_manager._tools[name].fn
    return "proximo_target" in inspect.signature(fn).parameters


def test_exec_tools_are_target_aware_and_the_ledger_tools_are_not():
    """ct_exec/ct_psql/ct_logs/ct_diagnose operate on a PVE box → must be target-aware.
    audit_verify and audit_entries are instance-level (THIS box's one local ledger, which
    has no remote to aim at) → must NOT be."""
    for name in ("ct_exec", "ct_psql", "ct_logs", "ct_diagnose"):
        assert _accepts_target(name), f"{name} not target-aware"
    for name in ("audit_verify", "audit_entries"):
        assert not _accepts_target(name), f"{name} is instance-level and must not take a target"


def test_ct_logs_wrong_kind_target_raises(monkeypatch, tmp_path):
    """A ct_* tool aimed at a non-pve target must error (kind safety), not silently hit env."""
    _env_default(monkeypatch)
    _registry(monkeypatch, tmp_path, """
        [targets.backup]
        kind = "pbs"
        base_url = "https://192.0.2.7:8007"
        token_path = "/etc/proximo/pbs.token"
    """)
    tok = targets._active_target.set("backup")
    try:
        with pytest.raises(ProximoError, match="not usable by a PVE tool"):
            server._svc()   # ct_* bodies resolve their backend via _svc(); proves kind-gate fires
    finally:
        targets._active_target.reset(tok)


def test_every_remote_tool_advertises_proximo_target():
    """Structural guarantee behind 'tools route by proximo_target': EVERY tool that acts on a
    remote box advertises proximo_target; only instance-level tools (which verify THIS Proximo's
    own ledger chain) are exempt. Generalizes the spot-checks to all ~350 tools and catches any
    tool whose signature silently defeated the __signature__ injection."""
    import anyio
    # audit_verify is instance-level (it verifies THIS Proximo's ledger chain).
    # proximo_call is a DISPATCHER: it acts on no box of its own, and the inner tool's
    # proximo_target rides inside `arguments` and is honoured because dispatch runs the
    # decorated wrapper (pinned by test_lean_wiring.py::test_dispatch_runs_the_decorated_
    # function, which asserts target_aware saw the target). Advertising a second, outer
    # proximo_target would create two places to say the same thing with no rule for which wins.
    INSTANCE_LEVEL = {"audit_verify", "audit_entries", "proximo_call"}
    tools = anyio.run(server.mcp.list_tools)
    assert len(tools) > 300, f"expected the full surface, got {len(tools)}"
    for t in tools:
        has = _accepts_target(t.name)
        if t.name in INSTANCE_LEVEL:
            assert not has, f"{t.name} is instance-level but accepts proximo_target"
        else:
            assert has, f"{t.name} acts on a remote box but does NOT accept proximo_target"


def test_advertised_schema_carries_the_target_param_when_a_registry_exists(monkeypatch, tmp_path):
    """The other half: when a registry IS configured the parameter must reach the wire, or a
    multi-target operator cannot select a box.

    Drives the real `_slim_registry_schemas` over a stand-in registry holding UNPRUNED schemas.
    The first version of this test deep-copied the LIVE schemas — which the import-time pass had
    already pruned, since this test env has no PROXIMO_TARGETS — so it re-ran a no-op over an
    empty result and could never have observed the thing it named.
    """
    reg = tmp_path / "targets.toml"
    reg.write_text('[targets.other]\nkind = "pve"\n'
                   'base_url = "https://192.0.2.9:8006/api2/json"\n'
                   'token_path = "/etc/proximo/other.token"\n')
    monkeypatch.setenv("PROXIMO_TARGETS", str(reg))

    def _unpruned():
        return {"properties": {"vmid": {"type": "string"},
                               "proximo_target": {"type": "string", "description": "d"}}}

    class _Tool:
        def __init__(self): self.parameters = _unpruned()

    class _Stand:
        def __init__(self): self._tool_manager = type("M", (), {"_tools": {"t": _Tool()}})()

    stand = _Stand()
    server._slim_registry_schemas(stand)
    kept = stand._tool_manager._tools["t"].parameters["properties"]
    assert "proximo_target" in kept, (
        "with a registry configured the slimming pass dropped the parameter a multi-target "
        "operator needs to select a box")

    # ...and the negative control, same pass, registry removed: it must actually prune.
    monkeypatch.delenv("PROXIMO_TARGETS", raising=False)
    stand2 = _Stand()
    server._slim_registry_schemas(stand2)
    assert "proximo_target" not in stand2._tool_manager._tools["t"].parameters["properties"], (
        "negative control failed — the prune never fires, so the positive case proves nothing")
