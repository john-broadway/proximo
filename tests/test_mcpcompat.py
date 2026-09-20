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
    """The wrap contract governed.py leans on: an in-tool exception comes back as a ToolError
    whose message starts 'Error executing tool {name}' with __cause__ intact, on BOTH majors.
    Only the PREFIX and the cause are common ground: 1.x appends '{e}' (the text), 2.x raises
    UnexpectedToolError with the text STRIPPED for anything that is not the SDK's ToolError
    (2026-09-20: this docstring used to claim the '{e}' part held on 2.x; it never did, and
    this test never asserted it — see test_proximo_error_text_reaches_the_caller_on_both_majors
    for the seam that restores it for ProximoError only)."""
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


# --- ProximoError text through the SDK boundary, both majors --------------------------------
# Found 2026-09-19 driving the dogfood server (mcp 2.2.0): a `blocked:lease_expired` refusal came
# back as a bare "Error executing tool proximo_call: Error executing tool pve_guest_power". On 1.x
# the SDK appends str(e) to every wrapped exception; on 2.x only its own ToolError carries text and
# every other exception is sanitized to the tool name. ProximoError is the caller-safe channel by
# design (backends.py: "never carries secrets"; _audited_run scrubs URLs into it; 1.x has shown its
# text verbatim since day one), so the 2.x seam translates exactly that class and nothing else.


def _probe_server():
    import anyio  # noqa: F401 — asserts the runner is present for the callers below

    from proximo.backends import ProximoError

    srv = compat.make_server("compat-probe", version="0.0.0")

    @srv.tool()
    def refuse() -> dict:
        """MUTATION probe: raises the caller-safe error class."""
        raise ProximoError("arm lease expired: 'refuse' refused — armed 7203s ago, TTL 3600s; re-arm to continue")

    @srv.tool()
    def crash() -> dict:
        """READ-ONLY probe: raises something that is NOT caller-safe."""
        raise ValueError("inner-detail-sentinel")

    return srv


def test_proximo_error_text_reaches_the_caller_on_both_majors():
    import anyio

    from proximo.backends import ProximoError

    srv = _probe_server()

    async def go():
        with pytest.raises(compat.ToolError) as exc:
            await srv.call_tool("refuse", {})
        assert "re-arm to continue" in str(exc.value), str(exc.value)
        assert "Error executing tool refuse" in str(exc.value)
        assert isinstance(exc.value.__cause__, ProximoError)

    anyio.run(go)


def test_a_non_proximo_error_stays_sanitized_on_2x_and_wrapped_on_1x():
    """The control: the seam must not widen exposure. A ValueError keeps the SDK's own contract
    per major (text on 1.x, name-only on 2.x); ONLY ProximoError is translated."""
    import anyio

    srv = _probe_server()

    async def go():
        with pytest.raises(compat.ToolError) as exc:
            await srv.call_tool("crash", {})
        assert "Error executing tool crash" in str(exc.value)
        assert isinstance(exc.value.__cause__, ValueError)
        if compat.MCP_MAJOR == 2:
            assert "inner-detail-sentinel" not in str(exc.value), str(exc.value)
        else:
            assert "inner-detail-sentinel" in str(exc.value)

    anyio.run(go)


def test_proximo_error_text_survives_the_nested_door():
    """proximo_call -> tool: the inner refusal rides through two SDK wraps. Pin the REASON, not
    the prefix shape (1.x carries both tool names, 2.x carries the outer one)."""
    import anyio

    from proximo import server
    from proximo.backends import ProximoError
    from proximo.door import dispatch_tool

    srv = _probe_server()

    @srv.tool()
    async def door(tool: str, arguments: dict | None = None) -> dict:
        """MUTATION probe: the escape hatch, minus the catalog."""
        catalog = {n: t for n, t in srv._tool_manager._tools.items()}  # noqa: SLF001
        return await dispatch_tool(server_mcp=srv, catalog=catalog, name=tool, arguments=arguments or {})

    async def go():
        with pytest.raises(compat.ToolError) as exc:
            await srv.call_tool("door", {"tool": "refuse"})
        assert "re-arm to continue" in str(exc.value), str(exc.value)
        cause = exc.value
        while isinstance(cause, compat.ToolError) and cause.__cause__ is not None:
            cause = cause.__cause__
        assert isinstance(cause, ProximoError), type(cause)
        assert server is not None  # keep the import honest: dispatch_tool is the real funnel

    anyio.run(go)


def test_the_cause_walk_follows_proximo_error_rewraps_and_stops_at_a_foreign_one():
    """The seam walks __cause__ through ToolError links only. A tool that re-raises
    `ProximoError(...) from ProximoError` (the two shapes in the tree: vectors.py, pmg_node.py)
    keeps its text on both majors. A tool that re-wraps a caught ProximoError as a NON-Proximo
    exception hands the SDK a foreign error and, on 2.x, loses the text by the SDK's own rule:
    that is the documented boundary (lens 2026-09-20), pinned so a future re-wrap is a visible
    choice, not a silent regression of this seam."""
    import anyio

    from proximo.backends import ProximoError

    srv = compat.make_server("compat-probe", version="0.0.0")

    @srv.tool()
    def rewrap_same() -> dict:
        """READ-ONLY probe."""
        try:
            raise ProximoError("inner reason: re-arm to continue")
        except ProximoError as e:
            raise ProximoError(f"outer: {e}") from e

    @srv.tool()
    def rewrap_foreign() -> dict:
        """READ-ONLY probe."""
        try:
            raise ProximoError("inner reason: re-arm to continue")
        except ProximoError as e:
            raise RuntimeError("foreign wrapper") from e

    async def go():
        with pytest.raises(compat.ToolError) as exc:
            await srv.call_tool("rewrap_same", {})
        assert "re-arm to continue" in str(exc.value)
        with pytest.raises(compat.ToolError) as exc:
            await srv.call_tool("rewrap_foreign", {})
        if compat.MCP_MAJOR == 2:
            assert "re-arm to continue" not in str(exc.value)
        else:
            assert "foreign wrapper" in str(exc.value)

    anyio.run(go)
