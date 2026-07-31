"""HTTP face dispatch — the full surface, over REST, through the spine.

Every POST /tools/{name} routes through governed.call_governed (the shared spine path), so:
unknown tool 404s, malformed requests 400, tool failures 502 (sanitized), and rejections land on
the PROVE ledger. Behavior parity with the governed core is covered in test_governed.py; here we
pin the HTTP mapping of it.
"""
from __future__ import annotations

import json

from starlette.testclient import TestClient

from proximo import governed, principal, server
from proximo.audit import AuditLedger
from proximo.httpface import build_app
from proximo.principal import mint_badge

LOCAL = "http://localhost"


def _client() -> TestClient:
    return TestClient(build_app(), base_url=LOCAL)


async def _ok(name, args):
    return {"tool": name, "args": args, "ok": True}


def test_tool_call_returns_result(monkeypatch):
    monkeypatch.setattr(governed, "call_governed", _ok)
    r = TestClient(build_app(), base_url=LOCAL).post("/tools/pve_node_status", json={})
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_unknown_tool_is_404():
    r = _client().post("/tools/definitely_not_a_tool", json={})
    assert r.status_code == 404
    assert "unknown tool" in r.json()["error"]


def test_missing_required_param_is_400():
    # pve_snapshot_list requires a vmid — an empty body is a malformed request.
    r = _client().post("/tools/pve_snapshot_list", json={})
    assert r.status_code == 400
    assert "required" in r.json()["error"]


def test_non_object_body_is_400():
    r = _client().post("/tools/pve_list_guests", json=[1, 2])
    assert r.status_code == 400


def test_invalid_json_body_is_400():
    r = _client().post("/tools/pve_list_guests", content=b"{not json",
                       headers={"content-type": "application/json"})
    assert r.status_code == 400


def test_valid_call_without_backend_is_502_sanitized():
    # A well-formed call to a real tool with no PVE env fails inside the tool -> 502, the tool's own
    # error, never a traceback.
    r = _client().post("/tools/pve_list_guests", json={})
    assert r.status_code == 502
    assert "traceback" not in r.text.lower()


def test_rejection_is_audited(monkeypatch):
    recorded: list = []

    class _Audit:
        def record(self, *a, **kw):
            recorded.append((a, kw))

    from proximo import server
    monkeypatch.setattr(server, "_ledger", lambda: _Audit())
    _client().post("/tools/definitely_not_a_tool", json={})
    assert recorded and recorded[0][0][0] == "http_rejected"


def test_healthz():
    assert _client().get("/healthz").json() == {"ok": True}


# --- Task 6: serving-face registration + session entries + verified-caller E2E ------------------
#
# The HTTP face's main() is what calls principal.set_serving_face("http") for real (see
# httpface.main()); build_app() itself never does (a build-time factory is used by embedders/tests
# that never serve, so the serving-face global must stay a serve-time-only fact). These E2E tests
# build the REAL face app via build_app() directly (not main()), so they set the serving face
# themselves to stand in for what main() does at serve time — restored to "stdio" in `finally` so
# this test can't leak the face into any test that runs after it.


def _ledger_lines(log_path) -> list[dict]:
    """Accepts either a ``Path`` or a plain str (``_wire``'s ``log`` return is a str)."""
    from pathlib import Path  # noqa: PLC0415

    p = Path(log_path)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]


def test_e2e_verified_caller_and_face_land_on_the_raw_ledger_line(monkeypatch, tmp_path):
    """A real badge, through the real guard_middleware stack, through a real governed dispatch
    (pve_node_status via the fake-backend `_wire` harness — no live PVE needed), must land a raw
    ledger line carrying via:verified, the verified caller id, and face:http together."""
    from test_a2a_executor import _wire  # noqa: PLC0415 -- shared fake-PVE-backend harness
    from test_webguard_principal import _pin  # noqa: PLC0415 -- shared badge-pinning helper

    _, _, _, _, log = _wire(tmp_path, monkeypatch)
    pin_dir = tmp_path / "pins"
    pin_dir.mkdir()
    pem = _pin(pin_dir, "fleet-7")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pin_dir))

    principal.set_serving_face("http")
    try:
        client = TestClient(build_app(token="tkn"), base_url=LOCAL)  # noqa: S106 -- test sentinel
        badge = mint_badge(pem, "fleet-7")
        r = client.post("/tools/pve_node_status", json={},
                        headers={"Authorization": "Bearer tkn", "Proximo-Principal": badge})
        assert r.status_code == 200
    finally:
        principal.set_serving_face("stdio")

    entries = [e for e in _ledger_lines(log) if e["action"] == "pve_node_status"]
    assert entries, "no pve_node_status ledger entry was recorded"
    assert entries[-1]["principal"] == {"id": "fleet-7", "via": "verified", "face": "http"}


def test_main_records_session_entries_with_face_http(monkeypatch, tmp_path):
    import uvicorn

    from proximo import httpface

    log = tmp_path / "audit.log"
    ledger = AuditLedger(str(log))
    monkeypatch.setattr(server, "_svc", lambda: (None, None, None, ledger))
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "svc-account")
    monkeypatch.delenv("PROXIMO_CALLER_KEYS_DIR", raising=False)
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)  # no real bind

    try:
        httpface.main()
    finally:
        principal.set_serving_face("stdio")

    lines = _ledger_lines(log)
    starts = [e for e in lines if e["action"] == "session_start"]
    ends = [e for e in lines if e["action"] == "session_end"]
    assert len(starts) == 1 and len(ends) == 1
    assert starts[0]["detail"]["face"] == "http"
    assert starts[0]["principal"] == {"id": "svc-account", "via": "spawn", "face": "http"}
    assert ends[0]["detail"]["face"] == "http"


def test_main_no_session_entries_when_principal_unconfigured(monkeypatch, tmp_path):
    """Byte-compat gate: an operator who hasn't opted into the principal feature sees NO session
    entries at all — same as before this feature existed."""
    import uvicorn

    from proximo import httpface

    log = tmp_path / "audit.log"
    ledger = AuditLedger(str(log))
    monkeypatch.setattr(server, "_svc", lambda: (None, None, None, ledger))
    monkeypatch.delenv("PROXIMO_PRINCIPAL", raising=False)
    monkeypatch.delenv("PROXIMO_CALLER_KEYS_DIR", raising=False)
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)  # no real bind

    try:
        httpface.main()
    finally:
        principal.set_serving_face("stdio")

    assert not log.exists()
