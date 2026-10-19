"""The core door as REST: the six tools behind the 0.44 HTTP perimeter, the core's engine behind
them, the 0.44 server never loaded, and who asked on every row.

`proximo.core.perimeter.rest.build_app` is handed a `dispatch.Core` and the core's row writer; this file pins
what that buys: the OpenAPI document lists the six and nothing else, a refused mutation answers
the spine's own sentence, a rejected request leaves its row in the CORE ledger, the perimeter is
the shared one, and a fresh interpreter can build the door, be refused by it and reject an unknown
tool in a fresh interpreter
itself, which must light the probe up.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

pytest.importorskip("starlette", reason="the [http] extra is not installed")

from starlette.testclient import TestClient  # noqa: E402

from proximo.core import principal  # noqa: E402
from proximo.core.doors import http as face  # noqa: E402

SIX = ["audit_entries", "audit_verify", "proximo_call", "proximo_find", "proximo_plan", "proximo_read"]
MUTATE = {"plane": "pve", "method": "DELETE", "path": "/nodes/x/qemu/1", "confirm": True}
TOKEN = "t0k"  # noqa: S105 -- a test's own bearer
BEARER = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def env(monkeypatch, tmp_path):
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":   # the pin on the real file stays
            monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    yield tmp_path
    principal.set_serving_face("stdio")


def _rows(tmp_path):
    log = tmp_path / "audit.log"
    return [json.loads(x) for x in log.read_text().splitlines() if x.strip()] if log.exists() else []


def _client(token=TOKEN) -> TestClient:
    return TestClient(face.build_app(token=token), base_url="http://localhost")


def test_the_document_lists_the_six_core_tools_and_speaks_for_the_core(env):
    doc = _client().get("/openapi.json").json()
    assert sorted(p.removeprefix("/tools/") for p in doc["paths"]) == SIX
    assert doc["info"]["description"] == face.DESCRIPTION
    assert "PROXIMO_SURFACES" not in doc["info"]["description"]
    assert doc["security"] == [{"bearerAuth": []}]
    schema = doc["paths"]["/tools/proximo_call"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    assert {"plane", "method", "path"} <= set(schema["required"])


def test_a_refused_mutation_answers_the_spines_sentence_and_its_row_says_the_face(env, monkeypatch):
    """Through `governed` a ProximoError came out as its type name: every refusal would have read
    "ProximoError". The dispatch shows the spine's own text, as the MCP doors always did."""
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "agent-a")
    principal.set_serving_face(face.FACE)
    r = _client().post("/tools/proximo_call", json=MUTATE, headers=BEARER)
    assert r.status_code == 502
    assert "not armed" in r.json()["error"]
    assert "ProximoError" not in r.json()["error"]
    row = _rows(env)[-1]
    assert row["action"] == "core.refuse"
    assert row["principal"] == {"id": "agent-a", "via": "spawn", "face": "http"}


def test_a_read_only_tool_answers_through_the_door(env):
    r = _client().post("/tools/proximo_find", json={"query": "list datastores", "limit": 2}, headers=BEARER)
    assert r.status_code == 200
    assert {"matches", "total", "planes"} <= set(r.json())


def test_rejections_land_in_the_core_ledger(env):
    c = _client()
    unknown = c.post("/tools/pve_list_guests", json={}, headers=BEARER)
    missing = c.post("/tools/proximo_read", json={}, headers=BEARER)
    broken = c.post("/tools/proximo_find", content=b"{not json", headers={**BEARER, "content-type": "application/json"})
    assert (unknown.status_code, missing.status_code, broken.status_code) == (404, 400, 400)
    assert "unknown tool" in unknown.json()["error"]
    assert "required" in missing.json()["error"]
    rows = [(r["action"], r["target"], r["outcome"]) for r in _rows(env)]
    assert rows == [("http_rejected", "pve_list_guests", "rejected"),
                    ("http_rejected", "proximo_read", "rejected"),
                    ("http_rejected", "proximo_find", "rejected")]


def test_the_bearer_is_the_shared_perimeter(env):
    c = _client()
    wrong = c.post("/tools/proximo_find", json={"query": "x"}, headers={"Authorization": "Bearer nope"})
    none = c.post("/tools/proximo_find", json={"query": "x"})
    assert (wrong.status_code, none.status_code) == (401, 401)
    assert (c.get("/healthz").status_code, c.get("/openapi.json").status_code) == (200, 200)
    assert [m.cls.__name__ for m in face.build_app(token="t0k").user_middleware] == [
        "TrustedHostMiddleware", "CrossOriginGuardMiddleware", "BearerAuthMiddleware"]


def test_a_public_bind_with_no_token_never_starts(env, monkeypatch, capsys):
    import uvicorn
    ran = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: ran.append(1))
    monkeypatch.setenv("PROXIMO_HTTP_HOST", "0.0.0.0")  # noqa: S104 -- the refusal under test
    assert face.main([]) == 3
    assert ran == [] and "no auth token" in capsys.readouterr().err


def test_session_rows_land_even_when_serving_crashes(env, monkeypatch):
    import uvicorn

    def boom(*a, **k):
        raise RuntimeError("bind failed")

    monkeypatch.setattr(uvicorn, "run", boom)
    with pytest.raises(RuntimeError, match="bind failed"):
        face.main([])
    kinds = [(r["action"], r["detail"].get("face"), r["target"]) for r in _rows(env)]
    assert kinds == [("session_start", "http", "face/http"), ("session_end", "http", "face/http")]


def test_an_unknown_argument_refuses_and_help_exits_clean(env, capsys):
    assert face.main(["--port", "1"]) == 3
    assert face.main(["--help"]) == 0
    assert "PROXIMO_HTTP_HOST" in capsys.readouterr().out


_PROBE = """
import sys
from starlette.testclient import TestClient
{build}
c = TestClient(app, base_url="http://localhost")
r1 = c.post("/tools/proximo_call", json={mutate!r}, headers={{"Authorization": "Bearer t0k"}})
r2 = c.post("/tools/no_such_tool", json={{}}, headers={{"Authorization": "Bearer t0k"}})
print(r1.status_code, r2.status_code)
"""


def _probe(env, build: str) -> list[str]:
    code = _PROBE.format(build=build, mutate=MUTATE)
    out = subprocess.run([sys.executable, "-c", code],  # noqa: S603 -- our own interpreter, our literal
                         env={**os.environ, "PROXIMO_AUDIT_LOG": str(env / "audit.log")},
                         capture_output=True, text=True, check=True).stdout.strip()
    return out.splitlines()


def test_the_door_serves_refuses_and_rejects_in_a_fresh_interpreter(env):
    """A fresh interpreter: build the door, be refused by it, reject an unknown tool; the badge
    camera and the rejection rows write through the core's ledger, the dispatch runs the core's
    own instance. (Until the cut of 2026-10-18 this probe also proved the 0.44 server was not
    loaded, against a control on the 0.44 face; there is no 0.44 server to load now.)"""
    (statuses,) = _probe(env, "from proximo.core.doors import http as f; app = f.build_app(token='t0k')")
    assert statuses == "502 404"
    assert {r["action"] for r in _rows(env)} == {"core.refuse", "http_rejected"}


def _badge(env):
    """A real caller key pinned for the camera, and a badge minted with it."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from proximo.core.perimeter.badge import mint_badge, public_jwk

    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pins = env / "pins"
    pins.mkdir()
    (pins / "agent-x.jwk").write_text(json.dumps(public_jwk(pem, "agent-x")))
    return pins, mint_badge(pem, "agent-x")


def test_a_badge_is_verified_by_the_camera_and_its_rows_land_in_the_core_ledger(env, monkeypatch):
    """Lens 2026-09-27 on the MCP-HTTP door: the shared perimeter's camera wrote `caller_arrived`
    through the 0.44 server's ledger. This door hands the camera its own writer; the row lands
    in the core's chain and the refusal names the verified caller, not the name tag."""
    pins, badge = _badge(env)
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(pins))
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "name-tag")
    r = _client().post("/tools/proximo_call", json=MUTATE, headers={**BEARER, "Proximo-Principal": badge})
    assert r.status_code == 502
    rows = {r["action"]: r for r in _rows(env)}
    assert rows["caller_arrived"]["detail"] == {"caller": "agent-x"}
    assert rows["core.refuse"]["principal"]["id"] == "agent-x"
    assert rows["core.refuse"]["principal"]["via"] == "verified"


def test_an_unconfigured_plane_says_so_through_the_door(env):
    """The door's own `_execute` raises its sentence `from` the env RuntimeError; a caller must
    read the sentence, not "RuntimeError" (lens 1)."""
    r = _client().post("/tools/proximo_read", json={"plane": "pve", "path": "/nodes"}, headers=BEARER)
    assert r.status_code == 502
    err = r.json()["error"]
    assert "pve is not configured" in err and "PROXIMO_API_BASE_URL" in err
    assert not err.endswith("failed: RuntimeError")


def test_surfaces_set_for_the_044_face_refuse_this_door(env, monkeypatch, capsys):
    """The 0.44 faces scope their tools by PROXIMO_SURFACES; the core has no surfaces. A host that
    set it is told, never silently served a set it did not ask for (lens 1, MAJOR)."""
    import uvicorn
    ran = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: ran.append(1))
    monkeypatch.setenv("PROXIMO_SURFACES", "pve")
    assert face.main([]) == 3
    assert ran == [] and "no surfaces" in capsys.readouterr().err
    assert _rows(env) == []
