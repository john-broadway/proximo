"""HTTP face — localhost cross-origin (CSRF) defense on the full-surface mutating endpoint.

A loopback face with no token (the dev default) is reachable by any web page the operator loads.
A cross-origin page can POST with a CORS-safelisted Content-Type (text/plain) — no preflight — and
drive a real mutation, no credential. The shared CrossOriginGuardMiddleware refuses cross-origin
POSTs to /tools/*; these pin it and prove no legit client is caught. The guard runs BEFORE dispatch,
so a rejected request never reaches call_governed (asserted via a call-recording patch).
"""
from __future__ import annotations

from starlette.testclient import TestClient

FACE = "http"  # which perimeter this file tests: see conftest `build_app`
LOCAL = "http://localhost"


def _spy(monkeypatch) -> list:
    """Record what reaches dispatch: the core's `dispatch.Core.call`."""
    calls: list = []

    async def _rec(*a):
        calls.append(tuple(a[-2:]))          # (name, args); the method carries self first
        return {"ok": True}

    from proximo.core.doors import dispatch
    monkeypatch.setattr(dispatch.Core, "call", _rec)
    return calls


def _client(build_app) -> TestClient:
    return TestClient(build_app(), base_url=LOCAL)


# --- the attack is blocked, and the tool is NEVER reached --------------------------------------

def test_text_plain_mutation_is_refused_and_not_dispatched(build_app, monkeypatch):
    calls = _spy(monkeypatch)
    r = _client(build_app).post("/tools/proximo_call",
                       content=b'{"plane":"pve","method":"POST","path":"/nodes/x/qemu/1/status/stop","confirm":true}',
                       headers={"content-type": "text/plain"})
    assert r.status_code == 415
    assert calls == []


def test_form_urlencoded_body_is_refused(build_app, monkeypatch):
    calls = _spy(monkeypatch)
    r = _client(build_app).post("/tools/pve_snapshot_delete",
                       content=b'{"vmid":"102","snapname":"x","confirm":true}',
                       headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415
    assert calls == []


def test_sec_fetch_site_cross_site_is_refused_even_with_json(build_app, monkeypatch):
    calls = _spy(monkeypatch)
    r = _client(build_app).post("/tools/proximo_call",
                       json={"plane": "pve", "method": "POST", "path": "/nodes/x/qemu/1/status/stop", "confirm": True},
                       headers={"sec-fetch-site": "cross-site"})
    assert r.status_code == 403
    assert calls == []


def test_sec_fetch_site_same_site_is_refused(build_app, monkeypatch):
    calls = _spy(monkeypatch)
    r = _client(build_app).post("/tools/proximo_call",
                       json={"plane": "pve", "method": "POST", "path": "/nodes/x/qemu/1/status/stop", "confirm": True},
                       headers={"sec-fetch-site": "same-site"})
    assert r.status_code == 403
    assert calls == []


# --- legit clients are NOT caught --------------------------------------------------------------

def test_application_json_client_passes(build_app, monkeypatch):
    calls = _spy(monkeypatch)
    r = _client(build_app).post("/tools/proximo_call",
                       json={"plane": "pve", "method": "POST", "path": "/nodes/x/qemu/1/status/stop", "confirm": True})
    assert r.status_code == 200
    assert calls and calls[0][0] == "proximo_call"


def test_discovery_get_is_never_csrf_checked(build_app):
    c = _client(build_app)
    assert c.get("/openapi.json", headers={"sec-fetch-site": "cross-site"}).status_code == 200
    assert c.get("/healthz", headers={"sec-fetch-site": "cross-site"}).status_code == 200
