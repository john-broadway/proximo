"""The final lens over the exit (lens F): a refusal on every door goes through the one seal, the
refusal ceiling holds in BYTES whatever the characters, and the over-cap shape fits its own ceiling.

Each test was written against the defect and seen red first (the lens's probes, ported)."""
# ruff: noqa: E501 -- hostile fixtures are long literals on purpose
from __future__ import annotations

import asyncio
import json
import os

import pytest

from proximo.core import engine, rawdoor
from proximo.core.doors import dispatch
from proximo.core.doors import mcp as door

TAG = "\U000e0041"          # a tag character: hides text from a person, category Cf
CEIL = rawdoor.CEILINGS


def _bytes(text: str) -> int:
    return len(text.encode("utf-8", "backslashreplace"))


# --- 2. the refusal ceiling, in bytes ------------------------------------------------------------------

@pytest.mark.parametrize("text", ["w" * 5000, "日" * 5000, TAG * 5000, "‮" * 5000, "\x1b[31m" * 2000,
                                  ("ab" + TAG + "日‮") * 2000, "\udc80" * 3000])
def test_a_refusal_is_at_most_its_ceiling_in_bytes_suffix_included(text):
    out = rawdoor.refusal_text(text)
    assert _bytes(out) <= CEIL["refusal"], (_bytes(out), out[:60])
    assert f"({len(text)} chars, sha256:{rawdoor.fingerprint(text)})" in out
    assert TAG not in out and "‮" not in out and "\x1b" not in out


def test_a_short_refusal_is_whole_and_an_escape_is_never_cut_in_half():
    assert rawdoor.refusal_text("short") == "short"
    out = rawdoor.refusal_text("x" * 498 + TAG * 10)
    shown = out.split("... (")[0]
    assert _bytes(out) <= CEIL["refusal"] and not shown.endswith(("\\", "\\U", "\\U000")) and shown.count("\\U") == shown.count("\\U000e0041")


def test_echo_counts_what_it_shows_after_the_escapes():
    """An echo shows at most `limit` characters of what a person reads: the escapes count."""
    out = rawdoor.echo(TAG * 100, 80)
    assert out.split("... (")[0].count("\\U000e0041") <= 80 // len("\\U000e0041")
    assert out.endswith(f"(100 chars, sha256:{rawdoor.fingerprint(TAG * 100)})")
    assert rawdoor.echo("abc", 80) == "abc" and rawdoor.echo("a‮b", 80) == "a\\u202eb"


# --- 5. the over-cap shape fits its own ceiling -------------------------------------------------------

@pytest.mark.parametrize("ceiling", [CEIL["refusal"], CEIL["read"], CEIL["plan"]])
def test_the_over_cap_shape_never_exceeds_its_ceiling(ceiling):
    hostile = {k: TAG * 500 for k in rawdoor._KEEP} | {"reason": TAG * 500, "consent_id": TAG * 500,
                                                       "undo": {"id": TAG * 500}, "task": {"status": TAG * 500, "exitstatus": TAG * 500},
                                                       **{f"list{i}" * 40: [1] for i in range(20)}}
    out = rawdoor.over_cap("proximo_plan", hostile, 99999, ceiling)
    assert _bytes(json.dumps(out, separators=(",", ":"), ensure_ascii=False)) <= ceiling, out
    assert out["over_cap"] is True and "next" in out


def test_the_minimal_shape_keeps_the_verdict_and_the_operator_line():
    hostile = {"allowed": False, "needs": "consent", "consent_id": "c" * 64, "reason": TAG * 900,
               "status": TAG * 900, "intent": TAG * 900, "called_path": TAG * 900, "address": TAG * 900}
    out = rawdoor.over_cap("proximo_plan", hostile, 99999, CEIL["refusal"])
    assert _bytes(json.dumps(out, separators=(",", ":"), ensure_ascii=False)) <= CEIL["refusal"]
    assert out["allowed"] is False and out["needs"] == "consent" and out["consent_id"] == "c" * 64
    assert out["next"] == "the full plan is for the operator: proximo-core consent show " + "c" * 64


def test_finish_holds_the_lens_probe_under_the_plan_ceiling():
    oc = rawdoor.finish("proximo_plan", {"reason": TAG * 500, "status": TAG * 500, "intent": TAG * 500,
                                         "called_path": TAG * 500, "consent_id": TAG * 500, "arguments": {"a": "z" * 5000}})
    assert _bytes(json.dumps(oc, separators=(",", ":"), ensure_ascii=False)) <= CEIL["plan"]


# --- 1. a refusal on REST and A2A is sealed like one on MCP -------------------------------------------

class _Wire:
    def __init__(self, body):
        self.body = body

    def call(self, method, path, params=None):
        return self.body


@pytest.fixture
def estate(monkeypatch, tmp_path):
    for var in [v for v in os.environ if v.startswith("PROXIMO_") and v != "PROXIMO_ENV_FILE"]:
        monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.invalid:8006/api2/json")
    (tmp_path / "t").write_text("x")
    monkeypatch.setenv("PROXIMO_API_TOKEN_PATH", str(tmp_path / "t"))

    def serve(rows):
        monkeypatch.setattr(engine, "_client", lambda product, c=None: _Wire(rows))
    return serve


HOSTILE_ROWS = {"ascii": [{"k" * 5000 + str(i): 1 for i in range(15)}],
                "tags": [{TAG * 400 + str(i): 1 for i in range(15)}]}
READ = {"plane": "pve", "path": "/cluster/resources", "fields": "nope"}


def _clean(message: str) -> None:
    assert _bytes(message) <= CEIL["refusal"], _bytes(message)
    assert TAG not in message and "k" * 600 not in message


@pytest.mark.parametrize("rows", sorted(HOSTILE_ROWS))
def test_a_dispatch_refusal_is_sealed(estate, rows):
    estate(HOSTILE_ROWS[rows])
    with pytest.raises(dispatch.DispatchError) as e:
        asyncio.run(dispatch.call_on(door.build_server(), "proximo_read", READ))
    _clean(e.value.message)


@pytest.mark.parametrize("rows", sorted(HOSTILE_ROWS))
def test_a_rest_refusal_is_sealed(estate, rows):
    from starlette.testclient import TestClient

    from proximo.core.doors.http import build_app
    estate(HOSTILE_ROWS[rows])
    res = TestClient(build_app(), base_url="http://localhost").post("/tools/proximo_read", json=READ)
    assert res.status_code == 502
    _clean(res.json()["error"])


def test_every_dispatch_error_is_sealed_at_construction():
    assert _bytes(dispatch.DispatchError(502, TAG * 5000).message) <= CEIL["refusal"]
    assert dispatch.DispatchError(404, "unknown tool 'x'").message == "unknown tool 'x'"


@pytest.mark.parametrize("rows", sorted(HOSTILE_ROWS))
def test_an_a2a_refusal_is_sealed(estate, rows):
    pytest.importorskip("a2a", reason="the [a2a] extra is not installed")
    import httpx
    from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
    from a2a.helpers.proto_helpers import get_text_parts, new_data_message
    from a2a.types.a2a_pb2 import SendMessageRequest, TaskState

    from proximo.core import principal
    from proximo.core.doors import a2a as face
    estate(HOSTILE_ROWS[rows])

    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=face.build_app()), base_url="http://localhost",
                                     timeout=20) as hx:
            card = await A2ACardResolver(hx, "http://localhost").get_agent_card()
            client = ClientFactory(ClientConfig(httpx_client=hx, streaming=False, polling=False)).create(card)
            state, text = None, ""
            async for resp in client.send_message(SendMessageRequest(message=new_data_message({"tool": "proximo_read", "params": READ}))):
                if resp.HasField("task"):
                    state = resp.task.status.state
                    text += "".join(get_text_parts(resp.task.status.message.parts))
                if resp.HasField("status_update"):
                    state = resp.status_update.status.state
                    text += "".join(get_text_parts(resp.status_update.status.message.parts))
            return state, text
    try:
        state, text = asyncio.run(go())
    finally:
        principal.set_serving_face("stdio")
    assert state == TaskState.TASK_STATE_FAILED and text
    _clean(text)
