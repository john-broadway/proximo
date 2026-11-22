"""GHSA-pm7c-9g59-j62g (reported by Kamipiula, 2026-11-15): two ways the governed spelling and
the real one could part.

1. A lone `.` segment (or `%2e`) passed `rawdoor.reject_malformed`. The engine governed
   `PUT /nodes/localhost/network/.` on pbs as the row `PUT /nodes/{node}/network/{iface}`,
   while httpx removes the dot segment and sends `PUT /nodes/localhost/network`: a different
   address (on pbs, the network reload). Same class as the `//nodes/backup` tunnel the
   filter's docstring already names. The fix refuses a `.` segment beside `..`.

2. The perimeter guards asked `protect(request.url.path)`. An embedder that mounts a face
   under a Starlette `Mount` prefix gets the FULL path there (`/prefix/tools/...`), which no
   face's `protect` selects, so the bearer, the cross-origin guard and the badge camera all
   stood aside. The fix asks about the path the mounted app routes on, and about the full
   path too, so mounting can only add protection, never remove it.
"""

from __future__ import annotations

import os

import pytest

pytest.importorskip("starlette")

from starlette.applications import Starlette  # noqa: E402
from starlette.routing import Mount  # noqa: E402
from starlette.testclient import TestClient  # noqa: E402

from proximo.core import engine, principal, rawdoor  # noqa: E402
from proximo.core.doors import http as face  # noqa: E402
from proximo.core.errors import ProximoError  # noqa: E402

DOT_SHAPES = [
    "/nodes/localhost/network/.",          # the reporter's pbs shape
    "/nodes/localhost/network/%2e",
    "/nodes/localhost/network/%2E",
    "/remotes/remote/.",                   # pdm
    "/nodes/localhost/qemu/.",             # pve
    "/nodes/./qemu/100/status/current",    # a dot in the middle
    "/.",
]


@pytest.mark.parametrize("path", DOT_SHAPES)
def test_a_dot_segment_is_refused_at_the_spelling(path):
    with pytest.raises(ProximoError, match="malformed path"):
        rawdoor.reject_malformed(path)
    with pytest.raises(ProximoError, match="malformed path"):
        rawdoor.reject_malformed(path, allow_placeholders=True)


def test_the_reporters_pbs_put_never_reaches_a_row():
    with pytest.raises(ProximoError, match="malformed path"):
        engine.resolve("pbs", "PUT", "/nodes/localhost/network/.")


@pytest.mark.parametrize("path", [
    "/nodes/pve1/storage/local/content/local:iso/Windows 11 Pro.iso".replace(" ", "%20"),
    "/nodes/pve1/qemu/100/status/current",
    "/nodes/pve1/storage/local/content/local%3Aiso%2Fa..b.iso",   # dots inside a value stay legal
    "/nodes/pve1/network/.vmbr0",
])
def test_a_dot_inside_a_value_is_still_legal(path):
    rawdoor.reject_malformed(path)


# --- 2. a face mounted under a prefix keeps its guards ---------------------------------------

TOKEN = "t0k"  # noqa: S105 -- a test's own bearer


@pytest.fixture
def env(monkeypatch, tmp_path):
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":
            monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    yield tmp_path
    principal.set_serving_face("stdio")


def _mounted(prefix: str = "/proximo") -> TestClient:
    outer = Starlette(routes=[Mount(prefix, app=face.build_app(token=TOKEN))])
    return TestClient(outer, base_url="http://localhost")


def test_the_bearer_holds_under_a_mount_prefix(env):
    r = _mounted().post("/proximo/tools/proximo_find", json={"query": "datastore"})
    assert r.status_code == 401, r.text


def test_the_bearer_still_lets_the_right_caller_in_under_a_mount_prefix(env):
    r = _mounted().post("/proximo/tools/proximo_find", json={"query": "datastore"},
                        headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 200, r.text


def test_the_cross_origin_guard_holds_under_a_mount_prefix(env):
    r = _mounted().post("/proximo/tools/proximo_find", content=b'{"query":"x"}',
                        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "text/plain"})
    assert r.status_code == 415, r.text


def test_discovery_stays_open_under_a_mount_prefix(env):
    assert _mounted().get("/proximo/openapi.json").status_code == 200


def test_the_route_path_strips_only_a_whole_segment_prefix():
    from proximo.core.perimeter.guard import _guarded_paths
    assert _guarded_paths({"path": "/p/tools/x", "root_path": "/p"}) == ("/p/tools/x", "/tools/x")
    assert _guarded_paths({"path": "/px/tools", "root_path": "/p"}) == ("/px/tools",)
    assert _guarded_paths({"path": "/tools/x", "root_path": ""}) == ("/tools/x",)
    assert _guarded_paths({"path": "/tools/x"}) == ("/tools/x",)


def test_the_cross_origin_fetch_metadata_check_holds_under_a_mount_prefix(env):
    r = _mounted().post("/proximo/tools/proximo_find", json={"query": "x"},
                        headers={"Authorization": f"Bearer {TOKEN}", "Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403, r.text


def test_the_badge_camera_holds_under_a_mount_prefix(env, monkeypatch):
    pins = env / "pins"
    pins.mkdir()
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pins))
    r = _mounted().post("/proximo/tools/proximo_find", json={"query": "x"},
                        headers={"Authorization": f"Bearer {TOKEN}"})
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Proximo-Principal", r.text


def test_the_mcp_http_face_holds_under_a_mount_prefix(env):
    pytest.importorskip("mcp")
    from proximo.core.doors import mcphttp
    outer = Starlette(routes=[Mount("/proximo", app=mcphttp.build_app(token=TOKEN))])
    r = TestClient(outer, base_url="http://localhost").post("/proximo/mcp", json={})
    assert r.status_code == 401, r.text


def test_the_a2a_face_holds_under_a_mount_prefix(env):
    pytest.importorskip("a2a")
    from proximo.core.doors import a2a
    outer = Starlette(routes=[Mount("/proximo", app=a2a.build_app(token=TOKEN))])
    r = TestClient(outer, base_url="http://localhost").post("/proximo/", json={})
    assert r.status_code == 401, r.text


# --- the lens's minor: a brace that is not a whole segment ------------------------------------

@pytest.mark.parametrize("path", ["/nodes/localhost/network/{/x}", "/nodes/{/qemu/100}", "/nodes/a{b}/status",
                                  "/nodes/{node}x/status", "/nodes/{}/status"])
def test_a_brace_that_is_not_a_whole_segment_is_refused(path):
    with pytest.raises(ProximoError, match="malformed path"):
        rawdoor.reject_malformed(path, allow_placeholders=True)


def test_every_published_address_still_passes_the_spelling():
    for _product, _method, path in engine.table():
        rawdoor.reject_malformed(path, allow_placeholders=True)
