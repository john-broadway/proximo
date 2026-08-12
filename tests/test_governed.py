"""The governed dispatch — the ONE transport-agnostic path both network faces route through.

The trust spine lives in the tools (every tool goes through _svc/_plan/_audited/the gates), and
`mcp.call_tool` runs a tool through that spine — exactly what an MCP client gets. So the A2A and
HTTP faces are thin adapters over `list_governed` + `call_governed`: full surface, one guard, no
transport-local curation and no second mutate path. These tests pin that contract.
"""
from __future__ import annotations

import anyio
import pytest

from proximo._mcpcompat import tool_input_schema
from proximo.governed import GovernedError, _normalize, call_governed, list_governed


def test_list_governed_is_the_full_surface():
    tools = anyio.run(list_governed)
    names = {t.name for t in tools}
    # The whole governed estate — NOT a 16-skill slice. The spine makes it safe to expose.
    assert len(names) > 300
    # The "dangerous plane" the old A2A slice excluded is present — governed, not hidden.
    assert "pve_delete_guest" in names
    assert "ct_exec" in names
    assert "pve_token_create" in names


def test_unknown_tool_is_404():
    with pytest.raises(GovernedError) as ei:
        anyio.run(call_governed, "definitely_not_a_tool", {})
    assert ei.value.status == 404
    assert "unknown tool" in ei.value.message.lower()


def test_missing_required_param_is_400():
    tools = anyio.run(list_governed)
    tool = next(t for t in tools if tool_input_schema(t).get("required"))
    with pytest.raises(GovernedError) as ei:
        anyio.run(call_governed, tool.name, {})
    assert ei.value.status == 400
    assert "required" in ei.value.message.lower()


def test_non_object_arguments_is_400():
    with pytest.raises(GovernedError) as ei:
        anyio.run(call_governed, "pve_list_guests", ["not", "a", "dict"])  # type: ignore[arg-type]
    assert ei.value.status == 400


def test_non_string_tool_name_is_400_not_a_crash():
    # A list/dict name (from a malformed inbound message) must be rejected, never an unhashable
    # dict-lookup TypeError that would bypass the audited rejection path.
    with pytest.raises(GovernedError) as ei:
        anyio.run(call_governed, ["not", "a", "string"], {})  # type: ignore[arg-type]
    assert ei.value.status == 400


def test_runtime_failure_is_502_and_sanitized():
    # No PVE env configured -> the tool raises inside call_tool -> 502, type-name only, no traceback.
    with pytest.raises(GovernedError) as ei:
        anyio.run(call_governed, "pve_list_guests", {})
    assert ei.value.status == 502


def test_tool_error_message_never_leaks_the_underlying_text(monkeypatch):
    # call_tool wraps a tool's exception (e.g. an exec TimeoutExpired whose message is the full
    # remote command + SSH host). call_governed must surface ONLY the exception TYPE, never that
    # text — a bearer-token caller must not read secrets/infra out of an error response.
    import subprocess

    from proximo import server
    from proximo._mcpcompat import ToolError

    secret_cmd = ["ssh", "root@host-sentinel", "pct exec 9 -- mysqldump --password=pw-sentinel db"]

    async def _boom(name, arguments):
        cause = subprocess.TimeoutExpired(cmd=secret_cmd, timeout=60)
        raise ToolError(f"Error executing tool {name}: {cause}") from cause

    monkeypatch.setattr(server.mcp, "call_tool", _boom)
    with pytest.raises(GovernedError) as ei:
        anyio.run(call_governed, "ct_exec", {"ctid": "9", "command": ["x"], "confirm": True})
    assert ei.value.status == 502
    assert "pw-sentinel" not in ei.value.message
    assert "host-sentinel" not in ei.value.message
    assert "TimeoutExpired" in ei.value.message  # the type is actionable; the text is not exposed


def test_validation_error_maps_to_400(monkeypatch):
    from pydantic import BaseModel, ValidationError

    from proximo import server
    from proximo._mcpcompat import ToolError

    class _M(BaseModel):
        n: int

    try:
        _M(n="not-an-int")
    except ValidationError as ve:
        cause = ve

    async def _boom(name, arguments):
        raise ToolError("Error executing tool x: validation") from cause

    monkeypatch.setattr(server.mcp, "call_tool", _boom)
    with pytest.raises(GovernedError) as ei:
        anyio.run(call_governed, "pve_list_guests", {})
    assert ei.value.status == 400


# --- result normalization (pure) ---------------------------------------------------------------

class _TC:
    """Minimal TextContent stand-in."""
    def __init__(self, text: str) -> None:
        self.text = text
        self.type = "text"


def test_normalize_call_tool_tuple_uses_structured_content():
    # THE shape FastMCP's call_tool actually returns: (content_blocks, structured_dict). Element 1
    # is the real data — a dict return passes through, a list return is wrapped under "result".
    dict_return = ([_TC('{"uptime": 123}')], {"uptime": 123})
    assert _normalize(dict_return) == {"uptime": 123}
    list_return = ([_TC('{"vmid": 100}')], {"result": [{"vmid": 100}]})
    assert _normalize(list_return) == {"result": [{"vmid": 100}]}


def test_normalize_dict_passthrough():
    assert _normalize({"x": 2, "ok": True}) == {"x": 2, "ok": True}


def test_normalize_single_json_textcontent():
    assert _normalize([_TC('{"a": 1, "b": "two"}')]) == {"a": 1, "b": "two"}


def test_normalize_non_json_text_wraps():
    out = _normalize([_TC("plain text, not json")])
    assert out == {"result": "plain text, not json"}


def test_normalize_multiple_parts_wraps():
    out = _normalize([_TC("one"), _TC("two")])
    assert out == {"result": ["one", "two"]}


def test_normalize_multiple_json_parts_are_parsed():
    # A bare-`list`-annotated tool with 2+ elements yields one content block per element; each must be
    # parsed to an object, not returned as a raw JSON string. (Regression: multi-disk pve_node_disks_list.)
    out = _normalize([_TC('{"devpath": "/dev/sda"}'), _TC('{"devpath": "/dev/sdb"}')])
    assert out == {"result": [{"devpath": "/dev/sda"}, {"devpath": "/dev/sdb"}]}


def test_normalize_scalar_text_parts_stay_strings():
    # Only structured JSON (dict/list) is substituted; a plain-text part, or one that parses to a bare
    # scalar ("123"/"true"/"null"), must NOT be silently retyped to int/bool/None.
    out = _normalize([_TC("123"), _TC("true"), _TC("null"), _TC("plain")])
    assert out == {"result": ["123", "true", "null", "plain"]}
