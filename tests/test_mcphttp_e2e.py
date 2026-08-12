"""End-to-end: the OFFICIAL MCP streamable-HTTP client drives the Proximo MCP-HTTP app.

The perimeter tests prove hostile requests are refused; this proves the legit path WORKS — the
whole point of the face (upstream FR #25: no third-party stdio→HTTP bridge). The SDK's real client
speaks the full Streamable HTTP protocol (initialize handshake, session header, SSE-or-JSON
responses) through the complete middleware stack (TrustedHost → CSRF guard → bearer) into the SAME
FastMCP instance the stdio server runs — list_tools returns the full governed surface and a real
tool (audit_verify) executes through the spine. Uses httpx ASGITransport (in-process, no socket)
with the app lifespan run explicitly, since the SDK app's session manager lives in the lifespan.
No live Proxmox (audit_verify reads a temp ledger).

On mcp 2.x the SSE-mode drives run against the single-PVE-plane scope (the _sse_sized_registry
fixture) because the 2.x CLIENT caps a single SSE event at 1MB — httpx2's EventSource default,
which mcp 2.0.0 constructs without exposing the knob — and the full unscoped catalog is
1,099,438 bytes on the SSE data line, ~4.9% over the cap. That kills not just list_tools
but every call_tool too: the 2.x client implicitly
refreshes its output-schema cache via list_tools inside validate_tool_result. The ceiling itself
is pinned by test_the_2x_client_caps_a_full_catalog_sse_event, so an SDK release lifting it
turns up loud; json_response mode is unaffected and keeps full-catalog coverage on both majors.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from proximo._mcpcompat import MCP_MAJOR, result_is_error
from proximo.mcphttp import build_app

BASE = "http://localhost"


@pytest.fixture
def _sse_sized_registry():
    """On mcp 2.x, shrink the served registry to the pve_/audit_/proximo_ PREFIX FILTER —
    316 tools, 391,203 bytes on the SSE data line (measured 2026-08-12 via an ASGI drive),
    comfortably under the 2.x client's 1MiB single-event cap (see the module docstring).
    A prefix filter, deliberately NOT door's
    autoscope (whose measured single-PVE-plane count is 310): these tests need a fixed,
    cheap, restorable slice, not the scoping ladder's behavior — that has its own tests. On
    1.x this yields untouched, keeping the original full-catalog coverage. Registry
    save/restore is the same pattern test_escape_hatch uses."""
    if MCP_MAJOR == 1:
        yield
        return
    import proximo.server as server
    tm = server.mcp._tool_manager
    saved = dict(tm._tools)
    tm._tools.clear()
    tm._tools.update({n: t for n, t in saved.items()
                      if n.startswith(("pve_", "audit_", "proximo_"))})
    try:
        yield
    finally:
        tm._tools.clear()
        tm._tools.update(saved)


def _configure_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://127.0.0.1:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "e2e-node")
    tok = tmp_path / "e2e.tok"
    tok.write_text("e2e@pam!t=00000000-0000-0000-0000-000000000000")
    tok.chmod(0o600)  # the config guard refuses group/other-readable tokens
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(tok))
    monkeypatch.setenv("PROXIMO_VERIFY_TLS", "true")
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "e2e-audit.log"))


async def _drive(app, headers=None):
    """Full client session against *app*: initialize → list_tools → call audit_verify."""
    hx = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                           headers=headers, timeout=30)
    async with app.router.lifespan_context(app):  # the SDK session manager runs in the lifespan
        async with streamable_http_client(f"{BASE}/mcp", http_client=hx) as _streams:
            read, write = _streams[0], _streams[1]  # 1.x yields (read, write, get_sid); 2.x (read, write)
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = {t.name for t in tools.tools}
                assert len(names) > 300, ("a real estate-scale surface: the full catalog on 1.x; "
                              "the 316-tool prefix scope under _sse_sized_registry on 2.x")
                assert "audit_verify" in names
                result = await session.call_tool("audit_verify", {})
                assert result_is_error(result) is False
                # Proximo tools return their JSON as text content — same as over stdio.
                verdict = json.loads(result.content[0].text)
                assert verdict["ok"] is True


async def test_mcp_client_end_to_end_no_token(tmp_path, monkeypatch, _sse_sized_registry):
    # Defaults — which means STATELESS (`stateless_http=True`, the FR #25 maintainer decision:
    # multi-client behind a proxy is the deployment model; the governed surface needs no session).
    _configure_env(tmp_path, monkeypatch)
    await _drive(build_app())


async def test_mcp_client_end_to_end_with_bearer(tmp_path, monkeypatch, _sse_sized_registry):
    # The same full protocol run with the bearer guard armed: the official client carries the
    # token on EVERY request (POST message, GET stream, DELETE session), so nothing 401s.
    _configure_env(tmp_path, monkeypatch)
    await _drive(build_app(token="s3cret"), headers={"Authorization": "Bearer s3cret"})


async def test_stateful_opt_out_end_to_end(tmp_path, monkeypatch, _sse_sized_registry):
    # The opt-out posture (PROXIMO_MCP_HTTP_STATELESS=0): real per-session state still works.
    _configure_env(tmp_path, monkeypatch)
    await _drive(build_app(stateless=False))


async def test_json_response_mode_end_to_end(tmp_path, monkeypatch):
    # Plain-JSON responses instead of SSE, for clients that prefer it.
    _configure_env(tmp_path, monkeypatch)
    await _drive(build_app(json_response=True))


class _PlanOnlyApi:
    """The minimal Proxmox fake a pve_guest_power PLAN needs — and a tripwire for EXECUTE."""

    def __init__(self):
        self.config = SimpleNamespace(node="e2e-node")
        self.powered: list[tuple] = []

    def guest_status(self, vmid, kind="lxc", node=None):
        return {"status": "running", "name": "web", "uptime": 500}

    def guest_power(self, vmid, action, kind="lxc", node=None):
        self.powered.append((vmid, action))  # reaching here means the PLAN gate failed
        return {"ok": True}


async def test_mutating_tool_through_the_face_is_plan_gated(tmp_path, monkeypatch, _sse_sized_registry):
    """The spine, proven through the new mouth (0.24 post-merge review nit): the OFFICIAL client
    calls a MUTATING tool without confirm and gets a recorded PLAN back — never a change. The
    read-only e2e above can't prove the PLAN gate; this asserts both halves of the PLAN→PROVE
    weld from outside the process boundary: status=="plan" in the MCP response, a "planned"
    entry in the real ledger, and the fake API's power method never reached. Backend faked at
    the same `server._svc` seam the server-level plan tests use — the face is in-process, so
    the seam works while the real client drives the full HTTP protocol.
    """
    import proximo.server as server  # noqa: PLC0415
    from proximo.audit import AuditLedger  # noqa: PLC0415
    from proximo.config import ProximoConfig  # noqa: PLC0415

    _configure_env(tmp_path, monkeypatch)
    log = str(tmp_path / "e2e-audit.log")
    cfg = ProximoConfig(api_base_url="https://127.0.0.1:8006/api2/json", node="e2e-node",
                        token_path=str(tmp_path / "e2e.tok"), audit_log_path=log)
    api = _PlanOnlyApi()
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, None, AuditLedger(log)))

    app = build_app()
    hx = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE, timeout=30)
    async with app.router.lifespan_context(app):
        async with streamable_http_client(f"{BASE}/mcp", http_client=hx) as _streams:
            read, write = _streams[0], _streams[1]  # 1.x yields (read, write, get_sid); 2.x (read, write)
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "pve_guest_power", {"vmid": "1975", "action": "stop"})  # no confirm
                assert result_is_error(result) is False
                out = json.loads(result.content[0].text)
                assert out["status"] == "plan", "an unconfirmed mutation must return a PLAN"
                assert api.powered == [], "the PLAN gate let a mutation through the face"

    with open(log, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    planned = [e for e in entries if e.get("outcome") == "planned"]
    assert planned and planned[0]["mutation"] is True, "the plan must land on the PROVE ledger"


# --- the face must not lie about WHICH face it is -------------------------------------------
#
# `set_serving_face` is a serve-time fact set by each face's main(); the module default is
# "stdio". httpface.main() and a2a/app.main() both set it and both wrap uvicorn.run in a
# try/finally recording session_start/session_end. mcphttp.main() did neither, because this face
# landed AFTER the principal work was written. The cost is not a missing nicety: every ledger
# entry from this NETWORK face was tagged face:"stdio" -- the local, trusted channel -- so the
# tamper-evident log misattributed the access path of a remote request.

def test_main_sets_the_serving_face_and_records_sessions(tmp_path, monkeypatch):
    import uvicorn  # noqa: PLC0415

    from proximo import mcphttp, principal, server  # noqa: PLC0415
    from proximo.audit import AuditLedger  # noqa: PLC0415

    log = tmp_path / "audit.log"
    ledger = AuditLedger(str(log))
    monkeypatch.setattr(server, "_svc", lambda: (None, None, None, ledger))
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "svc-account")
    monkeypatch.delenv("PROXIMO_CALLER_KEYS_DIR", raising=False)
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)  # no real bind

    try:
        mcphttp.main()
    finally:
        principal.set_serving_face("stdio")

    lines = [json.loads(x) for x in log.read_text().splitlines() if x.strip()]
    starts = [e for e in lines if e["action"] == "session_start"]
    ends = [e for e in lines if e["action"] == "session_end"]
    assert len(starts) == 1 and len(ends) == 1, "the face recorded no session arrival/departure"
    assert starts[0]["detail"]["face"] == "mcp-http"
    assert starts[0]["principal"] == {"id": "svc-account", "via": "spawn", "face": "mcp-http"}
    assert ends[0]["detail"]["face"] == "mcp-http"


@pytest.mark.skipif(MCP_MAJOR != 2, reason="pins a ceiling only the 2.x client has")
async def test_the_2x_client_caps_a_full_catalog_sse_event(tmp_path, monkeypatch):
    """PINNED SDK CEILING, not a proximo defect: the 2.x client's SSE decoder (httpx2
    EventSource, constructed by mcp 2.0.0 without exposing its max_event_size knob) refuses
    any single event over 1048576 bytes, and the full unscoped catalog serializes past that.
    The client surfaces it as MCPError("SSE stream ended without a response") — httpx2's
    SSEError is swallowed inside the task group.

    If this test ever FAILS, the SDK lifted the cap: delete _sse_sized_registry, rerun the
    SSE drives unscoped, and drop this pin in the same commit.
    """
    from mcp.shared.exceptions import MCPError  # noqa: PLC0415 — 2.x-only import, guarded by the skipif

    _configure_env(tmp_path, monkeypatch)

    def _leaves(eg):
        for e in eg.exceptions:
            if isinstance(e, BaseExceptionGroup):
                yield from _leaves(e)
            else:
                yield e

    with pytest.raises(BaseExceptionGroup) as ei:
        await _drive(build_app())
    assert any(isinstance(e, MCPError) and "SSE stream ended" in str(e)
               for e in _leaves(ei.value)), "expected the 1MB-cap failure shape"


@pytest.mark.skipif(MCP_MAJOR != 2, reason="the cap lives in the 2.x client's SSE decoder")
async def test_the_sse_cap_is_the_documented_byte_boundary():
    """Pins the CAUSE the wall test above can only see the symptom of. The full-catalog test
    fails with "SSE stream ended" — a shape ANY mid-stream death produces. Here two synthetic
    catalogs straddle the documented constant with everything else identical: the under-cap
    drive succeeds and the over-cap drive dies with the same shape, so the boundary itself is
    what kills the stream. Also asserts the constant is still the value the CHANGELOG
    documents — if the SDK raises it or mcp starts passing the knob, THIS fails first and
    names the real reason."""
    from httpx2._config import DEFAULT_MAX_EVENT_SIZE_BYTES  # noqa: PLC0415 — 2.x-only, guarded by skipif
    from mcp.server.transport_security import TransportSecuritySettings  # noqa: PLC0415
    from mcp.shared.exceptions import MCPError  # noqa: PLC0415

    from proximo import _mcpcompat as compat  # noqa: PLC0415

    assert DEFAULT_MAX_EVENT_SIZE_BYTES == 1024 * 1024, (
        "the SDK moved the SSE event cap — update the CHANGELOG's Known-SDK-ceiling note "
        "and re-measure which catalog scopes fit")

    margin = 64 * 1024  # swamps SSE/JSONRPC framing overhead on both sides

    def build(desc_bytes):
        srv = compat.make_server("cap-probe", version="0.0.0")

        def probe() -> dict:
            return {"ok": True}

        probe.__doc__ = "READ-ONLY. " + ("d" * desc_bytes)
        srv.add_tool(probe, name="probe")
        return compat.streamable_http_app(
            srv, path="/mcp", stateless=True, json_response=False,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))

    async def drive(app):
        hx = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                               timeout=30)
        async with app.router.lifespan_context(app):
            async with streamable_http_client(f"{BASE}/mcp", http_client=hx) as st:
                async with ClientSession(st[0], st[1]) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    return len(tools.tools)

    assert await drive(build(DEFAULT_MAX_EVENT_SIZE_BYTES - margin)) == 1  # under: clean

    def _leaves(eg):
        for e in eg.exceptions:
            if isinstance(e, BaseExceptionGroup):
                yield from _leaves(e)
            else:
                yield e

    with pytest.raises(BaseExceptionGroup) as ei:
        await drive(build(DEFAULT_MAX_EVENT_SIZE_BYTES + margin))  # over: the wall's shape
    assert any(isinstance(e, MCPError) and "SSE stream ended" in str(e)
               for e in _leaves(ei.value))
