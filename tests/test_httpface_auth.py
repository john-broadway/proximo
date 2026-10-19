"""HTTP face perimeter hardening — fail-closed bind + bearer auth + Host (DNS-rebind) allowlist.

The HTTP face is a network control plane over Proxmox, exactly like the A2A face — and it
must obey the same fail-closed rules:
  - building a PUBLIC-bound app WITHOUT an auth token is REFUSED (not merely warned)
  - when a token is set: every /skills operation requires a correct Bearer token; discovery
    (/openapi.json) and liveness (/healthz) stay open, like the A2A agent card
  - localhost-default with no token still works for loopback Hosts (dev ergonomics preserved)
  - the Host guard is installed in ALL modes — non-loopback Hosts are rejected even tokenless
"""
from __future__ import annotations

import pytest
from starlette.testclient import TestClient

PUBLIC_URL = "http://10.1.2.3:41242/"
FACE = "http"  # which perimeter this file tests: see conftest `build_app`
LOCAL = "http://localhost"


# --- fail-closed bind -----------------------------------------------------------------------

def test_public_bind_without_token_is_refused(build_app):
    with pytest.raises(ValueError):
        build_app(PUBLIC_URL)


def test_public_bind_with_token_is_allowed(build_app):
    assert build_app(PUBLIC_URL, token="s3cret") is not None


def test_bind_all_interfaces_counts_as_public(build_app):
    with pytest.raises(ValueError):
        build_app("http://0.0.0.0:41242/")


def test_localhost_without_token_is_allowed(build_app):
    assert build_app() is not None


# --- bearer auth ----------------------------------------------------------------------------


def test_discovery_and_health_stay_open_with_token_set(build_app):
    client = TestClient(build_app(token="s3cret"), base_url=LOCAL)
    assert client.get("/healthz").status_code == 200
    r = client.get("/openapi.json")
    assert r.status_code == 200
    # And the doc DECLARES the bearer scheme, so clients learn how to authenticate.
    assert r.json()["security"] == [{"bearerAuth": []}]


def test_openapi_unsecured_when_no_token(build_app):
    client = TestClient(build_app(), base_url=LOCAL)
    assert "security" not in client.get("/openapi.json").json()


# --- Host (DNS-rebind) guard ----------------------------------------------------------------

def test_host_guard_rejects_non_loopback_host_even_tokenless(build_app):
    client = TestClient(build_app(), base_url=LOCAL)
    r = client.get("/healthz", headers={"Host": "evil.example"})
    assert r.status_code == 400


def test_host_guard_star_warns_loudly(build_app):
    with pytest.warns(UserWarning, match="DNS-rebind"):
        build_app(allowed_hosts=["*"])


# --- the control: the fixture hands back the door this file names ---------------------------------

def test_the_fixture_builds_the_core_door(build_app):
    """Six paths, the six core tools: the door behind every test here is the core's REST door.
    (Until the cut the fixture also built the 0.44 face, hundreds of paths; this control told the
    two apart. It stays so a fixture that handed back something else is red by its count.)"""
    paths = TestClient(build_app(), base_url=LOCAL).get("/openapi.json").json()["paths"]
    assert len(paths) == 6, len(paths)
