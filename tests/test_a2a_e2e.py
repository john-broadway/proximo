"""End-to-end: a real a2a-sdk client drives the Proximo A2A app over the full HTTP/JSON-RPC stack.

Existing A2A tests cover the executor in isolation and the card-over-HTTP; this is the only one that
drives the whole protocol with the OFFICIAL a2a-sdk *client* — resolve the agent card, send a real A2A
message, read the completed task's artifact back. Uses httpx ASGITransport (in-process, no socket) for
reliability while still exercising: client -> JSON-RPC -> Starlette routes -> DefaultRequestHandler ->
ProximoAgentExecutor -> governed.call_governed (spine) -> audit_verify tool -> artifact -> back.
(A real-socket variant of this flow was also proven against a live uvicorn during development.)
No live Proxmox (audit_verify reads a temp ledger).
"""
import json

import httpx
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.helpers.proto_helpers import get_data_parts, new_data_message
from a2a.types.a2a_pb2 import SendMessageRequest, TaskState

import proximo
from proximo import principal
from proximo.a2a.app import build_app
from proximo.principal import mint_badge

BASE = "http://localhost"  # loopback: in-process ASGI transport; A2A auth path is covered by test_a2a_auth.py


async def test_a2a_client_to_server_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://127.0.0.1:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "e2e-node")
    tok = tmp_path / "e2e.tok"
    tok.write_text("e2e@pam!t=00000000-0000-0000-0000-000000000000")
    tok.chmod(0o600)  # the config guard refuses group/other-readable tokens
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(tok))
    monkeypatch.setenv("PROXIMO_VERIFY_TLS", "true")  # construct over verified TLS (H-2); no real PVE call is made here
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "e2e-audit.log"))

    app = build_app(f"{BASE}/")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE, timeout=20) as hx:
        card = await A2ACardResolver(hx, BASE).get_agent_card()
        assert card.name == "Proximo"
        assert card.version == proximo.__version__  # the card advertises Proximo's own version
        assert len(card.skills) > 300  # the FULL governed surface, not a curated slice

        client = ClientFactory(ClientConfig(httpx_client=hx, streaming=False, polling=True)).create(card)
        req = SendMessageRequest(message=new_data_message({"skill": "audit_verify", "params": {}}))

        task = None
        artifacts = []
        final_state = None
        async for resp in client.send_message(req):
            if resp.HasField("task"):
                task = resp.task
            if resp.HasField("artifact_update"):
                artifacts.append(resp.artifact_update.artifact)
            if resp.HasField("status_update"):
                final_state = resp.status_update.status.state
        if task is not None:
            artifacts = list(task.artifacts) + artifacts
            if final_state is None:
                final_state = task.status.state

        assert final_state == TaskState.TASK_STATE_COMPLETED
        result = next((a for a in artifacts if a.name == "result"), None)
        assert result is not None, "no 'result' artifact returned over A2A"
        data = get_data_parts(result.parts)
        assert data and isinstance(data[0], dict) and data[0].get("ok") is True


# --- Task 6: verified-caller E2E, real A2A client -> real badge -> real governed dispatch --------
#
# a2a/app.main() is what calls principal.set_serving_face("a2a") for real; build_app() itself never
# does (a build-time factory used by embedders/tests that never serve must not stamp a serving-time
# fact). This test builds the REAL A2A app via build_app() directly, so it sets the serving face
# itself to stand in for what main() does at serve time — restored to "stdio" in `finally` so this
# test can't leak the face into any test that runs after it.


def _ledger_lines(log_path: str) -> list[dict]:
    with open(log_path) as f:
        return [json.loads(line) for line in f if line.strip()]


async def test_e2e_verified_caller_and_face_land_on_the_raw_ledger_line(tmp_path, monkeypatch):
    from test_a2a_executor import _wire  # noqa: PLC0415 -- shared fake-PVE-backend harness
    from test_webguard_principal import _pin  # noqa: PLC0415 -- shared badge-pinning helper

    _, _, _, _, log = _wire(tmp_path, monkeypatch)
    pin_dir = tmp_path / "pins"
    pin_dir.mkdir()
    pem = _pin(pin_dir, "fleet-7")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pin_dir))

    principal.set_serving_face("a2a")
    try:
        app = build_app(f"{BASE}/", token="tkn")  # noqa: S106 -- test sentinel, not a real credential
        transport = httpx.ASGITransport(app=app)
        badge = mint_badge(pem, "fleet-7")
        headers = {"Authorization": "Bearer tkn", "Proximo-Principal": badge}
        async with httpx.AsyncClient(transport=transport, base_url=BASE, timeout=20,
                                     headers=headers) as hx:
            card = await A2ACardResolver(hx, BASE).get_agent_card()
            client = ClientFactory(ClientConfig(httpx_client=hx, streaming=False, polling=True)).create(card)
            req = SendMessageRequest(message=new_data_message({"skill": "pve_node_status", "params": {}}))

            final_state = None
            async for resp in client.send_message(req):
                if resp.HasField("status_update"):
                    final_state = resp.status_update.status.state
                if resp.HasField("task"):
                    final_state = resp.task.status.state
            assert final_state == TaskState.TASK_STATE_COMPLETED
    finally:
        principal.set_serving_face("stdio")

    entries = [e for e in _ledger_lines(log) if e["action"] == "pve_node_status"]
    assert entries, "no pve_node_status ledger entry was recorded"
    assert entries[-1]["principal"] == {"id": "fleet-7", "via": "verified", "face": "a2a"}
