"""The core door as an A2A agent: the six tools as the card's skills behind the 0.44 A2A perimeter,
the core's engine behind them, the 0.44 server never loaded, and who asked on every row.

The official a2a-sdk client drives it in process (httpx ASGITransport), the way test_a2a_e2e drives
the 0.44 face: resolve the card, send a DataPart message, read the task back. A refused mutation
fails the task with the spine's own sentence; a message with no tool, or an unknown one, fails the
task and leaves an `a2a_rejected` row in the CORE ledger. The control for the "never loaded" probe
is the 0.44 face itself.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import httpx
import pytest

pytest.importorskip("a2a", reason="the [a2a] extra is not installed")

from a2a.client import A2ACardResolver, ClientConfig, ClientFactory  # noqa: E402
from a2a.helpers.proto_helpers import get_data_parts, get_text_parts, new_data_message  # noqa: E402
from a2a.types.a2a_pb2 import SendMessageRequest, TaskState  # noqa: E402

from proximo.core import principal  # noqa: E402
from proximo.core.doors import a2a as face  # noqa: E402

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


async def _send(app, payload, headers=None):
    """Resolve the card, send one data message, return (card, final state, status text, artifacts)."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                                 headers=headers, timeout=20) as hx:
        card = await A2ACardResolver(hx, BASE).get_agent_card()
        client = ClientFactory(ClientConfig(httpx_client=hx, streaming=False, polling=False)).create(card)
        req = SendMessageRequest(message=new_data_message(payload))
        task, artifacts, state, text = None, [], None, ""
        async for resp in client.send_message(req):
            if resp.HasField("task"):
                task = resp.task
            if resp.HasField("artifact_update"):
                artifacts.append(resp.artifact_update.artifact)
            if resp.HasField("status_update"):
                state = resp.status_update.status.state
                text += "".join(get_text_parts(resp.status_update.status.message.parts))
        if task is not None:
            artifacts = list(task.artifacts) + artifacts
            if state is None:
                state = task.status.state
                text += "".join(get_text_parts(task.status.message.parts))
        return card, state, text, artifacts


async def test_the_card_advertises_the_six_core_tools(env):
    card, state, _, artifacts = await _send(face.build_app(token="t0k"), {"tool": "audit_verify", "params": {}},
                                            {"Authorization": "Bearer t0k"})
    assert card.name == "Proximo"
    assert sorted(s.id for s in card.skills) == SIX
    assert "bearerAuth" in card.security_schemes
    assert state == TaskState.TASK_STATE_COMPLETED
    result = next(a for a in artifacts if a.name == "result")
    assert get_data_parts(result.parts)[0]["ok"] is True


async def test_a_refused_mutation_fails_the_task_with_the_spines_sentence(env, monkeypatch):
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "agent-a")
    principal.set_serving_face(face.FACE)
    _, state, text, _ = await _send(face.build_app(), {"tool": "proximo_call", "params": MUTATE})
    assert state == TaskState.TASK_STATE_FAILED
    assert "not armed" in text and "ProximoError" not in text
    row = _rows(env)[-1]
    assert row["action"] == "core.refuse"
    assert row["principal"] == {"id": "agent-a", "via": "spawn", "face": "a2a"}


async def test_rejections_land_in_the_core_ledger(env):
    app = face.build_app()
    _, s1, t1, _ = await _send(app, {"tool": "pve_list_guests", "params": {}})
    _, s2, t2, _ = await _send(app, {"nothing": "here"})
    assert (s1, s2) == (TaskState.TASK_STATE_FAILED, TaskState.TASK_STATE_FAILED)
    assert "unknown tool" in t1 and "DataPart" in t2
    rows = [(r["action"], r["target"], r["outcome"]) for r in _rows(env)]
    assert rows == [("a2a_rejected", "pve_list_guests", "rejected"), ("a2a_rejected", "<none>", "rejected")]


async def test_the_bearer_is_the_shared_perimeter(env):
    app = face.build_app(token="t0k")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as hx:
        body = {"jsonrpc": "2.0", "id": 1, "method": "tasks/get", "params": {"id": "x"}}
        wrong = await hx.post("/", json=body, headers={"Authorization": "Bearer nope"})
        none = await hx.post("/", json=body)
        card = await hx.get("/.well-known/agent-card.json")
    assert (wrong.status_code, none.status_code, card.status_code) == (401, 401, 200)
    assert [m.cls.__name__ for m in app.user_middleware] == [
        "TrustedHostMiddleware", "CrossOriginGuardMiddleware", "BearerAuthMiddleware"]


def test_a_public_bind_with_no_token_never_starts(env, monkeypatch, capsys):
    import uvicorn
    ran = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: ran.append(1))
    monkeypatch.setenv("PROXIMO_A2A_HOST", "0.0.0.0")  # noqa: S104 -- the refusal under test
    assert face.main([]) == 3
    assert ran == [] and "no auth token" in capsys.readouterr().err


def test_a_signing_key_that_is_set_but_unreadable_refuses_to_start(env, monkeypatch, capsys):
    """The 0.44 loader's rule, carried: never serve unsigned when signing was intended."""
    import uvicorn
    ran = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: ran.append(1))
    monkeypatch.setenv("PROXIMO_A2A_SIGNING_KEY_FILE", str(env / "absent.pem"))
    assert face.main([]) == 3
    assert ran == [] and "SIGNING_KEY" in capsys.readouterr().err


def test_session_rows_land_even_when_serving_crashes(env, monkeypatch):
    import uvicorn

    def boom(*a, **k):
        raise RuntimeError("bind failed")

    monkeypatch.setattr(uvicorn, "run", boom)
    with pytest.raises(RuntimeError, match="bind failed"):
        face.main([])
    kinds = [(r["action"], r["detail"].get("face"), r["target"]) for r in _rows(env)]
    assert kinds == [("session_start", "a2a", "face/a2a"), ("session_end", "a2a", "face/a2a")]


def test_an_unknown_argument_refuses_and_help_exits_clean(env, capsys):
    assert face.main(["--port", "1"]) == 3
    assert face.main(["--help"]) == 0
    assert "PROXIMO_A2A_SIGNING_KEY_FILE" in capsys.readouterr().out


_PROBE = """
import asyncio, sys, httpx
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.helpers.proto_helpers import new_data_message
from a2a.types.a2a_pb2 import SendMessageRequest
{build}
async def go(payload):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as hx:
        card = await A2ACardResolver(hx, "http://localhost").get_agent_card()
        client = ClientFactory(ClientConfig(httpx_client=hx, streaming=False, polling=False)).create(card)
        async for _ in client.send_message(SendMessageRequest(message=new_data_message(payload))):
            pass
asyncio.run(go({{"tool": "proximo_call", "params": {mutate!r}}}))
asyncio.run(go({{"tool": "no_such_tool", "params": {{}}}}))
print("done")
"""


def _probe(env, build: str) -> str:
    code = _PROBE.format(build=build, mutate=MUTATE)
    out = subprocess.run([sys.executable, "-c", code],  # noqa: S603 -- our own interpreter, our literal
                         env={**os.environ, "PROXIMO_AUDIT_LOG": str(env / "audit.log")},
                         capture_output=True, text=True, check=True).stdout.strip()
    return out.splitlines()[-1]


def test_the_door_serves_refuses_and_rejects_in_a_fresh_interpreter(env):
    assert _probe(env, "from proximo.core.doors import a2a as f; app = f.build_app()") == "done"
    assert {r["action"] for r in _rows(env)} == {"core.refuse", "a2a_rejected"}


def _badge(env):
    """A real caller key pinned for the camera, and a badge minted with it."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from proximo.core.perimeter.badge import mint_badge, public_jwk

    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pins = env / "pins"
    pins.mkdir()
    (pins / "agent-x.jwk").write_text(json.dumps(public_jwk(pem, "agent-x")))
    return pins, mint_badge(pem, "agent-x")


async def test_a_badge_is_verified_by_the_camera_and_its_rows_land_in_the_core_ledger(env, monkeypatch):
    pins, badge = _badge(env)
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pins))
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "name-tag")
    _, state, text, _ = await _send(face.build_app(), {"tool": "proximo_call", "params": MUTATE},
                                    {"Proximo-Principal": badge})
    assert state == TaskState.TASK_STATE_FAILED and "not armed" in text
    rows = {r["action"]: r for r in _rows(env)}
    assert rows["caller_arrived"]["detail"] == {"caller": "agent-x"}
    assert rows["core.refuse"]["principal"]["id"] == "agent-x"
    assert rows["core.refuse"]["principal"]["via"] == "verified"
