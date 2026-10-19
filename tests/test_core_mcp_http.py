"""The core door over the network: the six tools, the ONE perimeter, and who asked on every row.

The topology this exists for: Proximo in its own container holding the credentials, agents given
the endpoint and nothing else. The stdio door cannot be that (it runs where the agent runs, beside
the token); this face can. It serves `proximo.core.doors.mcp.build_server()` through the same
`proximo.core.perimeter.mcp_http.build_app` perimeter every network face mounts, so there is no second copy of the
host guard, the CSRF guard or the bearer check to drift.

The official MCP client drives it in process (httpx ASGITransport, lifespan run by hand), the way
test_mcphttp_e2e drives the 0.44 face.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import httpx
import pytest

pytest.importorskip("mcp", reason="the [mcp] extra is not installed")
pytest.importorskip("starlette", reason="the [mcp-http] extra is not installed")

from mcp import ClientSession  # noqa: E402
from mcp.client.streamable_http import streamable_http_client  # noqa: E402

from proximo.core import principal  # noqa: E402
from proximo.core.doors import mcp as door  # noqa: E402
from proximo.core.doors import mcphttp as face  # noqa: E402
from proximo.core.mcpcompat import result_is_error  # noqa: E402

BASE = "http://localhost"
SIX = ["audit_entries", "audit_verify", "proximo_call", "proximo_find", "proximo_plan", "proximo_read"]
MUTATE = {"plane": "pve", "method": "DELETE", "path": "/nodes/x/qemu/1", "confirm": True}


@pytest.fixture
def env(monkeypatch, tmp_path):
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":   # the pin on the real file stays
            monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    yield tmp_path
    principal.set_serving_face("stdio")


def _rows(tmp_path):
    log = tmp_path / "audit.log"
    return [json.loads(x) for x in log.read_text().splitlines() if x.strip()] if log.exists() else []


async def _session(app, headers=None):
    hx = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                           headers=headers, timeout=30)
    async with app.router.lifespan_context(app):
        async with streamable_http_client(f"{BASE}/mcp", http_client=hx) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                tools = sorted(t.name for t in (await session.list_tools()).tools)
                prompts = sorted(p.name for p in (await session.list_prompts()).prompts)
                refused = await session.call_tool("proximo_call", MUTATE)
                return tools, prompts, refused


# --- who asked ------------------------------------------------------------------------------

def test_a_core_row_carries_the_name_tag_the_operator_declared(env, monkeypatch):
    """0.44 rows carry PROXIMO_PRINCIPAL; the core's rows dropped it, so the same box's ledger
    said who asked on one door and not the other. Watched red before `_record` stamped it."""
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "agent-a")
    with pytest.raises(Exception, match="not armed"):
        door.call(**MUTATE)
    row = _rows(env)[-1]
    assert row["action"] == "core.refuse"
    assert row["principal"] == {"id": "agent-a", "via": "spawn", "face": "stdio"}


def test_no_name_tag_means_no_principal_key(env):
    """Byte-compat: a box that never declared a principal writes the rows it always wrote."""
    with pytest.raises(Exception, match="not armed"):
        door.call(**MUTATE)
    assert "principal" not in _rows(env)[-1]


# --- the face -------------------------------------------------------------------------------

async def test_the_network_face_serves_the_six_core_tools_and_governs(env, monkeypatch):
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "agent-a")
    principal.set_serving_face(face.FACE)
    tools, prompts, refused = await _session(face.build_app(token="t0k"), {"Authorization": "Bearer t0k"})
    assert tools == SIX
    # The five runbooks ride the same instance (B15): one registration, every door.
    assert prompts == []            # the five 0.44 runbooks went at the cut (2026-10-18): six tools, nothing else
    assert result_is_error(refused) is True and "not armed" in refused.content[0].text
    row = _rows(env)[-1]
    assert row["action"] == "core.refuse" and row["principal"]["face"] == "mcp-http"


async def test_the_bearer_is_the_shared_perimeter(env):
    app = face.build_app(token="t0k")
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as hx:
            body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            hdr = {"Accept": "application/json, text/event-stream"}
            wrong = await hx.post("/mcp", json=body, headers={**hdr, "Authorization": "Bearer nope"})
            none = await hx.post("/mcp", json=body, headers=hdr)
            health = await hx.get("/healthz")
    assert (wrong.status_code, none.status_code, health.status_code) == (401, 401, 200)
    assert [m.cls.__name__ for m in app.user_middleware] == [
        "TrustedHostMiddleware", "CrossOriginGuardMiddleware", "BearerAuthMiddleware"]


def test_a_public_bind_with_no_token_never_starts(env, monkeypatch, capsys):
    import uvicorn
    ran = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: ran.append(1))
    monkeypatch.setenv("PROXIMO_MCP_HTTP_HOST", "0.0.0.0")  # noqa: S104 -- the refusal under test
    assert face.main([]) == 3
    assert ran == [] and "no auth token" in capsys.readouterr().err


def test_session_rows_land_even_when_serving_crashes(env, monkeypatch):
    import uvicorn

    def boom(*a, **k):
        raise RuntimeError("bind failed")

    monkeypatch.setattr(uvicorn, "run", boom)
    with pytest.raises(RuntimeError, match="bind failed"):
        face.main([])
    kinds = [(r["action"], r["detail"].get("face")) for r in _rows(env)]
    assert kinds == [("session_start", "mcp-http"), ("session_end", "mcp-http")]


def test_an_unknown_argument_refuses(env, capsys):
    assert face.main(["--port", "1"]) == 3


# --- a stop is an exit, on every face -------------------------------------------------------

FACES = [("proximo-mcp-http", "MCP_HTTP", ["session_start", "session_end"]),
         ("proximo-http", "HTTP", ["session_start", "session_end"]),
         ("proximo-a2a", "A2A", ["session_start", "session_end"])]


@pytest.mark.parametrize(("script", "prefix", "want"), FACES, ids=[f[0] for f in FACES])
def test_a_systemd_stop_still_records_session_end(env, script, prefix, want):
    """SIGTERM is how systemd stops a service. uvicorn 0.49 catches it, shuts down, then
    re-raises it under the default handler, which killed every face before its `finally`: the
    crash test in test_face_contract (an exception) was green while every real stop lost its
    departure row. Found driving the core door live, 2026-09-27. A real process, a real signal,
    the console script an adopter's unit runs; HOME and the env file are pinned to the test's
    own directory so the 0.44 entry points cannot load this box's proximo.env."""
    import shutil
    import signal
    import socket
    import time

    exe = shutil.which(script, path=os.path.dirname(sys.executable))
    if exe is None:
        pytest.skip(f"{script} is not installed beside this interpreter")
    if prefix == "A2A":
        pytest.importorskip("a2a", reason="the [a2a] extra is not installed")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    child = {**os.environ, "HOME": str(env), "PROXIMO_ENV_FILE": str(env / "absent.env"),
             f"PROXIMO_{prefix}_PORT": str(port), "PROXIMO_PRINCIPAL": "stop-test",
             "PROXIMO_API_BASE_URL": "https://127.0.0.1:8006/api2/json", "PROXIMO_NODE": "n"}
    tok = env / "pve.tok"
    tok.write_text("t@pam!t=00000000-0000-0000-0000-000000000000")
    tok.chmod(0o600)
    child["PROXIMO_TOKEN_PATH"] = str(tok)
    proc = subprocess.Popen([exe], env=child, stdout=subprocess.DEVNULL,  # noqa: S603
                            stderr=subprocess.PIPE)
    try:
        for _ in range(200):
            if proc.poll() is not None:
                pytest.fail(f"{script} exited before serving: {proc.stderr.read().decode()[-400:]}")
            try:
                httpx.get(f"http://127.0.0.1:{port}/", timeout=0.5)
                break
            except httpx.TransportError:
                time.sleep(0.1)
        else:
            pytest.fail(f"{script} never answered")
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=30) == 0, "a requested stop is a clean stop"
    finally:
        if proc.poll() is None:
            proc.kill()
    kinds = [r["action"] for r in _rows(env) if r["action"].startswith("session_")]
    assert kinds == want


def test_serve_leaves_the_signal_handler_as_it_found_it(monkeypatch):
    """In process, a face's main runs inside pytest: a SIGTERM->exit(0) handler left behind
    would turn a cancelled run into a clean exit, which reads as a pass."""
    import signal

    import uvicorn

    from proximo.core.perimeter.guard import serve
    before = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    serve(object(), "127.0.0.1", 1)
    assert signal.getsignal(signal.SIGTERM) is before


def test_serving_a_badge_writes_the_cores_chain_and_never_loads_the_044_server(env):
    """Lens, 2026-09-27 (BLOCKING): with PROXIMO_CALLER_KEYS_DIR set, the shared perimeter's
    camera wrote `caller_arrived` through `server._ledger()`, so the FIRST protected request
    loaded the 0.44 server while this door's docstring said it never would; building the app was
    all the old closure test ever looked at. Now a real badge, a real request, a fresh
    interpreter: the rows land through the core's ledger and the 0.44 server stays unloaded."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from proximo.core.perimeter.badge import public_jwk

    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pins = env / "pins"
    pins.mkdir()
    (pins / "agent-x.jwk").write_text(json.dumps(public_jwk(pem, "agent-x")))
    (env / "caller.pem").write_bytes(pem)
    code = f"""
import asyncio, json, sys, httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from proximo.core.doors import mcphttp as f
from proximo.core.perimeter.badge import mint_badge
async def go():
    app = f.build_app(token="t0k")
    hdr = {{"Authorization": "Bearer t0k",
           "Proximo-Principal": mint_badge(open({str(env / "caller.pem")!r}, "rb").read(), "agent-x")}}
    hx = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost",
                           headers=hdr, timeout=30)
    async with app.router.lifespan_context(app):
        async with streamable_http_client("http://localhost/mcp", http_client=hx) as s:
            async with ClientSession(s[0], s[1]) as c:
                await c.initialize()
                await c.call_tool("proximo_call", {MUTATE!r})
asyncio.run(go())
print("done")
"""
    child = {**os.environ, "PROXIMO_CALLER_KEYS_DIR": str(pins)}
    out = subprocess.run([sys.executable, "-c", code], env=child,  # noqa: S603 -- our own literal
                         capture_output=True, text=True, check=True).stdout.strip()
    assert out.splitlines()[-1] == "done"
    rows = {r["action"]: r for r in _rows(env)}
    assert rows["caller_arrived"]["detail"] == {"caller": "agent-x"}
    assert rows["core.refuse"]["principal"] == {"id": "agent-x", "via": "verified", "face": "stdio"}
