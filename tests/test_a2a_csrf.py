"""A2A face — same localhost cross-origin (CSRF) defense as the HTTP face.

The redteam found the A2A JSON-RPC endpoint shares the HTTP face's cross-origin vector
(a2a-sdk reads the body without enforcing Content-Type). The shared webguard CSRF middleware
is installed on the A2A app too, protecting the RPC path; discovery (card/jwks) stays open.
"""
from __future__ import annotations

from starlette.testclient import TestClient

FACE = "a2a"  # which perimeter this file tests: see conftest `build_app`
LOCAL = "http://localhost"
_RPC_BODY = {"jsonrpc": "2.0", "id": "1", "method": "message/send", "params": {}}


def test_text_plain_rpc_is_refused(build_app):
    client = TestClient(build_app(), base_url=LOCAL)
    r = client.post("/", content=b'{"jsonrpc":"2.0","id":"1","method":"message/send","params":{}}',
                    headers={"content-type": "text/plain"})
    assert r.status_code == 415


def test_cross_site_rpc_is_refused(build_app):
    client = TestClient(build_app(), base_url=LOCAL)
    r = client.post("/", json=_RPC_BODY, headers={"sec-fetch-site": "cross-site"})
    assert r.status_code == 403


def test_application_json_rpc_passes_csrf_guard(build_app):
    client = TestClient(build_app(), base_url=LOCAL)
    # Not 415/403 — the CSRF guard lets a proper JSON-RPC client through (it may still be a
    # well-formed-but-unsupported method downstream; we only assert the CSRF guard didn't fire).
    r = client.post("/", json=_RPC_BODY)
    assert r.status_code not in (403, 415)


def test_cross_origin_header_rpc_is_refused(build_app):
    # The shared Origin-fallback fires on the A2A face too (browser omits Sec-Fetch-Site, sends Origin).
    client = TestClient(build_app(), base_url=LOCAL)
    r = client.post("/", headers={"origin": "http://evil.example"})
    assert r.status_code == 403


def test_card_discovery_never_csrf_checked(build_app):
    from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH
    client = TestClient(build_app(), base_url=LOCAL)
    assert client.get(AGENT_CARD_WELL_KNOWN_PATH,
                      headers={"sec-fetch-site": "cross-site"}).status_code == 200
