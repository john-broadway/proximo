"""HTTP face — OpenAPI document over the FULL governed surface.

The doc is generated from the live tool registry (the same list an MCP client sees), so no-code
clients discover the whole governed estate — not a curated slice. One POST path per tool; the
request schema IS the tool's MCP inputSchema.
"""
from __future__ import annotations

import json

import anyio

import proximo
from proximo._mcpcompat import tool_input_schema
from proximo.governed import list_governed
from proximo.httpface import build_openapi


def _tools():
    return anyio.run(list_governed)


def test_one_post_path_per_tool_full_surface():
    tools = _tools()
    doc = build_openapi(tools)
    assert set(doc["paths"]) == {f"/tools/{t.name}" for t in tools}
    assert len(doc["paths"]) > 300  # the whole estate, not a 16-skill slice
    for path in doc["paths"].values():
        assert set(path) == {"post"}


def test_dangerous_plane_is_present_and_discoverable():
    doc = build_openapi(_tools())
    for name in ("pve_delete_guest", "ct_exec", "pve_token_create", "pve_acl_modify"):
        assert f"/tools/{name}" in doc["paths"]


def test_operation_id_and_schema_come_from_the_tool():
    tools = _tools()
    doc = build_openapi(tools)
    by_name = {t.name: t for t in tools}
    for path, spec in doc["paths"].items():
        name = path.removeprefix("/tools/")
        op = spec["post"]
        assert op["operationId"] == name
        assert op["requestBody"]["content"]["application/json"]["schema"] == tool_input_schema(by_name[name])


def test_version_matches_package():
    assert build_openapi(_tools())["info"]["version"] == proximo.__version__


def test_secured_declares_bearer_scheme():
    doc = build_openapi(_tools(), secured=True)
    assert doc["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"
    assert doc["security"] == [{"bearerAuth": []}]


def test_unsecured_omits_security():
    doc = build_openapi(_tools(), secured=False)
    assert "security" not in doc
    assert "securitySchemes" not in doc.get("components", {})


def test_doc_is_json_serializable():
    json.dumps(build_openapi(_tools()))
