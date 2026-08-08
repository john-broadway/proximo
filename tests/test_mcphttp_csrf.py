"""MCP-HTTP face — localhost cross-origin (CSRF) defense on the protocol endpoint.

A loopback face with no token (the dev default) is reachable by any web page the operator loads.
The shared CrossOriginGuardMiddleware refuses cross-origin POSTs to /mcp, exactly as it does for
/tools/* on the HTTP face and the RPC path on A2A. Rejections fire in middleware, BEFORE the SDK's
session manager — the app lifespan is never started in these tests, so a request that slipped the
guard would 500 on the unstarted manager, never the 4xx asserted here. (That legit MCP clients
pass the guard is proven end-to-end by test_mcphttp_e2e.py, which drives the official client
through this exact middleware stack.)
"""
from __future__ import annotations

from starlette.testclient import TestClient

from proximo.mcphttp import build_app

LOCAL = "http://localhost"

_RPC = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "pve_guest_power", "arguments": {"vmid": "102", "action": "stop"}}}


def _client() -> TestClient:
    return TestClient(build_app(), base_url=LOCAL)


def test_text_plain_post_is_refused():
    # The CORS-safelisted Content-Type a forged cross-origin fetch() can carry with no preflight.
    r = _client().post("/mcp", content=b"{}", headers={"content-type": "text/plain"})
    assert r.status_code == 415


def test_form_urlencoded_post_is_refused():
    r = _client().post("/mcp", content=b"{}",
                       headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 415


def test_sec_fetch_site_cross_site_is_refused_even_with_json():
    r = _client().post("/mcp", json=_RPC, headers={"sec-fetch-site": "cross-site"})
    assert r.status_code == 403


def test_sec_fetch_site_same_site_is_refused():
    r = _client().post("/mcp", json=_RPC, headers={"sec-fetch-site": "same-site"})
    assert r.status_code == 403


def test_cross_origin_header_without_sec_fetch_is_refused():
    # A browser that omits Fetch-Metadata still sends Origin on a cross-origin POST.
    r = _client().post("/mcp", headers={"origin": "http://evil.example"})
    assert r.status_code == 403


def test_origin_null_is_refused():
    # Sandboxed iframe / file:// pages send `Origin: null` — never same-origin, so refuse.
    r = _client().post("/mcp", headers={"origin": "null"})
    assert r.status_code == 403


def test_oversized_body_is_refused():
    big = b'{"x":"' + b"a" * 200_000 + b'"}'
    r = _client().post("/mcp", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_health_get_is_never_csrf_checked():
    assert _client().get("/healthz", headers={"sec-fetch-site": "cross-site"}).status_code == 200


def test_chunked_body_without_content_length_is_refused():
    # A Transfer-Encoding: chunked body carries no Content-Length, so the pre-buffer size cap
    # (MAX_BODY_BYTES) cannot fire. The guard must refuse it (411) rather than let the downstream
    # handler buffer it unbounded — the memory-DoS gap the size cap claims to close.
    def _gen():
        yield b"{}"

    r = _client().post("/mcp", content=_gen(), headers={"content-type": "application/json"})
    assert r.status_code == 411
