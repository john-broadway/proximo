"""REST door — the OpenAPI document over the six tools.

The doc is generated from the door's live tool list (the same six an MCP client sees). One POST
path per tool; the request schema IS the tool's MCP inputSchema.
"""
from __future__ import annotations

import json

import anyio

import proximo
from proximo.core.doors.dispatch import Core
from proximo.core.mcpcompat import tool_input_schema
from proximo.core.perimeter.rest import build_openapi


def _tools():
    return anyio.run(Core().list)      # the wire's Tool objects, what the door hands build_openapi


def test_one_post_path_per_tool():
    tools = _tools()
    doc = build_openapi(tools)
    assert set(doc["paths"]) == {f"/tools/{t.name}" for t in tools}
    assert len(doc["paths"]) == 6
    for path in doc["paths"].values():
        assert set(path) == {"post"}


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
