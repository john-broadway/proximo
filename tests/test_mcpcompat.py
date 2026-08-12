"""The mcp major seam (proximo._mcpcompat) — proven against the INSTALLED SDK, both stubs.

Every accessor test has teeth both ways: it passes on the running major's spelling AND
raises on the other spelling's stub. A major-aware accessor that quietly succeeded on both
would be the getattr-with-default vacuous-guard shape these tests exist to forbid.
"""

from __future__ import annotations

import importlib.metadata

import pytest
from packaging.version import Version

from proximo import _mcpcompat as compat


class _Stub:
    """An object carrying exactly the attributes given — nothing else."""

    def __init__(self, **attrs):
        for k, v in attrs.items():
            setattr(self, k, v)


SCHEMA = {"type": "object", "properties": {"x": {"type": "integer"}}}


def test_mcp_major_matches_the_installed_package():
    """The import-based detection and the installed metadata must agree — if they ever
    split, either the SDK changed its markers or our map is stale; both are loud news."""
    installed = Version(importlib.metadata.version("mcp")).major
    assert compat.MCP_MAJOR == installed


def test_supported_majors_is_a_closed_set():
    assert compat.MCP_MAJOR in {1, 2}


# --- accessors: right spelling answers, wrong spelling RAISES ---

def test_tool_input_schema_reads_the_running_majors_spelling():
    right = _Stub(inputSchema=SCHEMA) if compat.MCP_MAJOR == 1 else _Stub(input_schema=SCHEMA)
    assert compat.tool_input_schema(right) == SCHEMA


def test_tool_input_schema_refuses_the_other_majors_spelling():
    wrong = _Stub(input_schema=SCHEMA) if compat.MCP_MAJOR == 1 else _Stub(inputSchema=SCHEMA)
    with pytest.raises(AttributeError):
        compat.tool_input_schema(wrong)


def test_result_is_error_reads_the_running_majors_spelling():
    right = _Stub(isError=True) if compat.MCP_MAJOR == 1 else _Stub(is_error=True)
    assert compat.result_is_error(right) is True


def test_result_is_error_refuses_the_other_majors_spelling():
    wrong = _Stub(is_error=True) if compat.MCP_MAJOR == 1 else _Stub(isError=True)
    with pytest.raises(AttributeError):
        compat.result_is_error(wrong)


def test_annotations_read_only_reads_the_running_majors_spelling():
    right = (_Stub(readOnlyHint=False) if compat.MCP_MAJOR == 1
             else _Stub(read_only_hint=False))
    assert compat.annotations_read_only(right) is False


def test_annotations_read_only_refuses_the_other_majors_spelling():
    wrong = (_Stub(read_only_hint=True) if compat.MCP_MAJOR == 1
             else _Stub(readOnlyHint=True))
    with pytest.raises(AttributeError):
        compat.annotations_read_only(wrong)


def test_annotations_read_only_passes_none_through():
    assert compat.annotations_read_only(None) is None


# --- against the REAL installed SDK, not stubs ---

def test_tool_input_schema_reads_a_real_wire_tool():
    """mcp.types.Tool constructs by camelCase alias on both majors; the accessor must read
    the schema back off the real model on whichever major is installed."""
    from mcp.types import Tool

    t = Tool(name="t", inputSchema=SCHEMA)
    assert compat.tool_input_schema(t) == SCHEMA


def test_annotations_read_only_reads_a_real_annotations_model():
    from mcp.types import ToolAnnotations

    assert compat.annotations_read_only(ToolAnnotations(readOnlyHint=True)) is True


def test_tool_error_is_catchable_and_wraps_the_in_tool_exception():
    """The 1.x wrap contract governed.py leans on — 'Error executing tool {name}: {e}',
    __cause__ intact — holds on BOTH majors (probed on 2.0.0; pinned here so an SDK release
    changing it fails THIS test, not a governance sanitizer downstream)."""
    import anyio

    srv = compat.make_server("compat-probe", version="0.0.0")

    @srv.tool()
    def boom() -> dict:
        """READ-ONLY probe tool."""
        raise ValueError("inner-detail")

    async def go():
        with pytest.raises(compat.ToolError) as exc:
            await srv.call_tool("boom", {})
        assert "Error executing tool boom" in str(exc.value)
        assert isinstance(exc.value.__cause__, ValueError)

    anyio.run(go)


def test_make_server_advertises_proximos_version_not_the_sdks():
    srv = compat.make_server("compat-probe", version="9.9.9-probe")
    advertised = (srv._mcp_server.version if compat.MCP_MAJOR == 1  # noqa: SLF001
                  else srv.version)
    assert advertised == "9.9.9-probe"


def test_make_server_tool_decorator_accepts_annotations_kwarg():
    """server.py's feature-detect keys on this; both current majors have it."""
    import inspect

    srv = compat.make_server("compat-probe", version="0.0.0")
    assert "annotations" in inspect.signature(srv.tool).parameters


@pytest.mark.skipif(compat.MCP_MAJOR != 2, reason="the subclass H1 hook is the 2.x seam; "
                    "1.x H1 is the low-level re-registration pinned in test_escape_hatch")
def test_h1_on_2x_a_non_resident_name_gets_the_pointer_not_the_dead_end():
    import anyio

    from proximo.backends import ProximoError

    srv = compat.make_server("compat-probe", version="0.0.0")

    @srv.tool()
    def resident() -> dict:
        """READ-ONLY probe tool."""
        return {"ok": True}

    async def go():
        with pytest.raises(ProximoError) as exc:
            await srv.call_tool("pve_ghost_tool", {})
        msg = str(exc.value)
        assert "unknown tool" in msg  # lowercase — the uniformity contract door.py pins
        assert "proximo_call" in msg or "proximo_find_tools" in msg  # the recoverable pointer
        # and a resident tool still dispatches through the SDK unchanged
        r = await srv.call_tool("resident", {})
        assert r is not None

    anyio.run(go)


@pytest.mark.skipif(compat.MCP_MAJOR != 2, reason="wire-shape check for the 2.x override")
def test_h1_on_2x_reaches_the_wire_as_an_is_error_result():
    """_handle_call_tool turns a non-MCPError raise into CallToolResult(is_error=True) —
    the property that makes the subclass override equivalent to the 1.x handler swap."""
    import anyio
    from mcp.server.mcpserver.server import CallToolRequestParams

    srv = compat.make_server("compat-probe", version="0.0.0")

    async def go():
        params = CallToolRequestParams(name="pve_ghost_tool", arguments={})
        result = await srv._handle_call_tool.__func__(srv, None, params)  # noqa: SLF001
        assert compat.result_is_error(result) is True
        assert "unknown tool" in result.content[0].text

    anyio.run(go)


def test_the_in_process_unknown_tool_delta_is_the_documented_one():
    """The WIRE outcome for a non-resident name is the same pointer on both majors (pinned by
    test_escape_hatch's interceptor test); the IN-PROCESS outcome deliberately differs and
    this test pins WHICH WAY, so the delta can never drift silently: 1.x H1 rewires only the
    wire handler (in-process callers get the SDK's own ToolError), while the 2.x subclass
    intercepts every call (in-process callers get the ProximoError pointer). If this test
    fails, the seam's interception scope changed — update make_server's docstring in the
    same commit."""
    import anyio

    from proximo.backends import ProximoError

    srv = compat.make_server("compat-probe", version="0.0.0")

    @srv.tool()
    def resident() -> dict:
        """READ-ONLY probe tool."""
        return {"ok": True}

    async def go():
        expected = compat.ToolError if compat.MCP_MAJOR == 1 else ProximoError
        with pytest.raises(expected):
            await srv.call_tool("pve_ghost_tool", {})

    anyio.run(go)
