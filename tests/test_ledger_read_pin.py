"""PIN: no model-facing ledger read hands back a row's `detail` or a vendor's exitstatus.

The ledger keeps the full text on purpose (a refusal's reason, the arguments as ledgered, a failed
task's exitstatus, a proposal for the operator); `audit_entries` is the one tool that reads it back
to a model, on every door, and it answers who, what, when and the outcome, never the detail. A
vendor's exitstatus is guest- and vendor-authored text (a failed task's line), so it never rides back
either. The rows here are written by the engine's own writer, and the file is read to show it does
hold them whole."""
from __future__ import annotations

import asyncio
import json
import os
import pathlib

import pytest

from proximo.core import engine
from proximo.core.doors import dispatch
from proximo.core.doors import mcp as door

MARK = "LEDGER-ONLY-7f3a"


@pytest.fixture
def ledger(monkeypatch, tmp_path):
    for var in [v for v in os.environ if v.startswith("PROXIMO_") and v != "PROXIMO_ENV_FILE"]:
        monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    row = engine.resolve("pve", "POST", "/nodes/{node}/vzdump")
    called = "/nodes/pve1/vzdump"
    engine._record(None, "core.error", row, outcome="error", called=called,
                   detail={"tier": row.tier, "called_path": called, "status": 500,
                           "error": f"vendor said {MARK}", "delivery": "answered"})
    engine._record(None, "core.execute", row, outcome="failed", called=called,
                   detail={"tier": row.tier, "exitstatus": f"ERROR: {MARK}",
                           "task": {"status": "stopped", "exitstatus": f"ERROR: {MARK} backup failed"}})
    engine._record(None, "core.refuse", row, outcome="refused", called=called,
                   detail={"reason": f"not armed {MARK}", "needs": "arm",
                           "proposed": {"consent_id": "c" * 64, "args": {"notes": MARK}}})
    log = pathlib.Path(os.environ["PROXIMO_AUDIT_LOG"])
    held = log.read_text()
    assert held.count(MARK) >= 4 and '"exitstatus"' in held and '"detail"' in held   # the ledger keeps it whole
    return log


def _keys(value) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {k for v in value.values() for k in _keys(v)}
    if isinstance(value, list):
        return {k for v in value for k in _keys(v)}
    return set()


def _clean(answer: dict) -> None:
    assert answer.get("entries"), answer
    assert not _keys(answer) & {"detail", "exitstatus", "proposed"}, sorted(_keys(answer))
    assert MARK not in json.dumps(answer, ensure_ascii=False)


#: each row kind alone (the read cap may cut a mixed page to its newest rows), then mixed pages
ASK = [{"action": "core.error"}, {"action": "core.execute"}, {"action": "core.refuse"}, {}, {"mutations_only": True},
       {"target": "/nodes/pve1/vzdump"}]


@pytest.mark.parametrize("args", ASK)
def test_the_mcp_door_never_reads_back_detail_or_exitstatus(ledger, args):
    server = door.build_server()
    res = asyncio.run(server.call_tool("audit_entries", {"limit": 50, **args}))
    structured = res[1] if isinstance(res, tuple) else res.structured_content
    blocks = res[0] if isinstance(res, tuple) else res.content
    if "action" in args:
        assert [e["action"] for e in structured["entries"]] == [args["action"]]
    _clean(structured)
    assert MARK not in blocks[0].text and "exitstatus" not in blocks[0].text


@pytest.mark.parametrize("args", ASK)
def test_the_dispatch_and_rest_doors_never_read_back_detail_or_exitstatus(ledger, args):
    from starlette.testclient import TestClient

    from proximo.core.doors.http import build_app
    _clean(asyncio.run(dispatch.call_on(door.build_server(), "audit_entries", {"limit": 50, **args})))
    res = TestClient(build_app(), base_url="http://localhost").post("/tools/audit_entries", json={"limit": 50, **args})
    assert res.status_code == 200
    _clean(res.json())
    assert MARK not in res.text


@pytest.mark.parametrize("args", ASK)
def test_the_a2a_door_never_reads_back_detail_or_exitstatus(ledger, args):
    pytest.importorskip("a2a", reason="the [a2a] extra is not installed")
    import httpx
    from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
    from a2a.helpers.proto_helpers import get_data_parts, new_data_message
    from a2a.types.a2a_pb2 import SendMessageRequest

    from proximo.core import principal
    from proximo.core.doors import a2a as face

    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=face.build_app()), base_url="http://localhost",
                                     timeout=20) as hx:
            card = await A2ACardResolver(hx, "http://localhost").get_agent_card()
            client = ClientFactory(ClientConfig(httpx_client=hx, streaming=False, polling=False)).create(card)
            parts = []
            msg = new_data_message({"tool": "audit_entries", "params": {"limit": 50, **args}})
            async for resp in client.send_message(SendMessageRequest(message=msg)):
                if resp.HasField("task"):
                    parts += [p for a in resp.task.artifacts for p in get_data_parts(a.parts)]
                if resp.HasField("artifact_update"):
                    parts += get_data_parts(resp.artifact_update.artifact.parts)
            return parts
    try:
        parts = asyncio.run(go())
    finally:
        principal.set_serving_face("stdio")
    assert parts
    for answer in parts:
        _clean(answer)
