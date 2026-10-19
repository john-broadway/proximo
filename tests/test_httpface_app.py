"""The REST door's HTTP mapping of the dispatch: unknown tool 404, malformed request 400, a
refused or failed call 502 (sanitized), discovery open. The dispatch itself is pinned in
`test_core_http.py`; here only the mapping.
"""
from __future__ import annotations

from starlette.testclient import TestClient

from proximo.core.doors.http import build_app

LOCAL = "http://localhost"


def _client() -> TestClient:
    return TestClient(build_app(), base_url=LOCAL)


async def _ok(name, args):
    return {"tool": name, "args": args, "ok": True}


def test_unknown_tool_is_404():
    r = _client().post("/tools/definitely_not_a_tool", json={})
    assert r.status_code == 404
    assert "unknown tool" in r.json()["error"]


def test_missing_required_param_is_400():
    # proximo_read requires a plane and a path — an empty body is a malformed request.
    r = _client().post("/tools/proximo_read", json={})
    assert r.status_code == 400
    assert "required" in r.json()["error"]


def test_non_object_body_is_400():
    r = _client().post("/tools/proximo_find", json=[1, 2])
    assert r.status_code == 400


def test_invalid_json_body_is_400():
    r = _client().post("/tools/proximo_find", content=b"{not json",
                       headers={"content-type": "application/json"})
    assert r.status_code == 400


def test_valid_call_without_backend_is_502_sanitized():
    # A well-formed read with no PVE configured is refused inside the engine -> 502, the engine's
    # own sentence, never a traceback.
    r = _client().post("/tools/proximo_read", json={"plane": "pve", "path": "/nodes"})
    assert r.status_code == 502
    assert "traceback" not in r.text.lower()


def test_healthz():
    assert _client().get("/healthz").json() == {"ok": True}
