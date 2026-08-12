"""The mcp SDK major seam — resolved ONCE, at import, by the surface we actually use.

Proximo runs on mcp 1.x (FastMCP) and 2.x (MCPServer) from one build. Everything that is
spelled differently between the majors crosses through this module; no other proximo module
may import from `mcp.server.fastmcp` or `mcp.server.mcpserver` directly, and no proximo code
reads a spelled model attribute (`.inputSchema` / `.input_schema`, `.isError` / `.is_error`,
`.readOnlyHint` / `.read_only_hint`) off an SDK object outside the accessors below.

Detection is by IMPORT, not version parse: the 1.x branch imports the exact surface the 1.x
code path uses, so a package that merely CLAIMS a version can't mis-route us — we bind to
what is actually importable (probed against mcp 1.x and 2.0.0, 2026-08-12; the surface facts
live in .scratch/a13-mcp-dual-support-plan-2026-08-12.md).

What is deliberately NOT here: `_tool_manager._tools` access. The private registry survives
2.x with the same spelling and the same internal Tool shape (`.name`/`.parameters`/`.fn`),
so the scoping ladder in door.py stays single-spelled. If a future major renames it, the
loud import failure above is where that port starts.

The accessors are major-aware, never getattr-with-default: a fallback that quietly returns
a default on BOTH majors is the vacuous-guard shape — an AttributeError here means this
module's map is wrong, and it should be loud.
"""

from __future__ import annotations

from typing import Any

try:  # mcp 1.x — the fastmcp module IS the 1.x marker; 2.0.0 deleted it.
    from mcp.server.fastmcp import FastMCP as ServerClass
    from mcp.server.fastmcp.exceptions import ToolError

    MCP_MAJOR = 1
except ImportError:  # mcp 2.x — MCPServer is the FastMCP analog (same decorator/tool()/run surface).
    from mcp.server import MCPServer as ServerClass  # type: ignore[assignment]
    from mcp.server.mcpserver.exceptions import ToolError  # type: ignore[assignment]

    MCP_MAJOR = 2

__all__ = [
    "MCP_MAJOR",
    "ServerClass",
    "ToolError",
    "annotations_read_only",
    "in_process_result",
    "init_server_info",
    "make_server",
    "result_is_error",
    "streamable_http_app",
    "tool_input_schema",
]


def make_server(name: str, version: str) -> Any:
    """Construct the per-major server, advertising Proximo's OWN version in `initialize`.

    1.x FastMCP leaves the low-level Server.version=None (the handshake would advertise the
    SDK's version); setting the private attribute after construction is the only seam. 2.x
    takes `version=` as a constructor kwarg. On 2.x the returned instance is a subclass whose
    `call_tool` override is the H1 hook: `_handle_call_tool` (the wire) awaits the PUBLIC
    `call_tool`, and a non-MCPError raised there reaches the client as an is_error result —
    so a non-resident name gets the recoverable did-you-mean pointer instead of the SDK's
    dead-end "Unknown tool" (on 1.x, H1 is the low-level handler re-registration at the
    bottom of server.py; this subclass is its 2.x twin, sanctioned seam).

    Equivalence is WIRE-scoped, deliberately: a client sees the same pointer on both majors.
    The IN-PROCESS `server.call_tool()` differs for a non-resident name — 1.x H1 rewires only
    the wire handler, so in-process callers get the SDK's ToolError("Unknown tool: X"); the
    2.x override intercepts every call, so they get ProximoError(pointer). Embedders calling
    in-process should catch both; the delta is pinned by
    tests/test_mcpcompat.py::test_the_in_process_unknown_tool_delta_is_the_documented_one.
    (proximo's own faces are unaffected: governed 404s on non-residents before dispatching.)
    """
    if MCP_MAJOR == 1:
        server = ServerClass(name)
        server._mcp_server.version = version  # noqa: SLF001 — the only 1.x seam for this
        return server

    class _GovernedMCPServer(ServerClass):  # type: ignore[misc,valid-type]
        async def call_tool(self, name: str, arguments: dict, context: Any = None) -> Any:  # noqa: A002
            if name not in self._tool_manager._tools:  # noqa: SLF001
                from .backends import ProximoError  # noqa: PLC0415 — leaf, but lazy keeps compat import-clean
                from .door import _unknown_tool_error  # noqa: PLC0415 — door imports compat; break the cycle here

                raise ProximoError(_unknown_tool_error(name))
            return await super().call_tool(name, arguments, context)

    return _GovernedMCPServer(name, version=version)


def tool_input_schema(tool: Any) -> Any:
    """The JSON schema of a WIRE Tool (mcp.types.Tool) — 1.x `.inputSchema`, 2.x `.input_schema`.

    Not for the internal registry Tool (`_tool_manager._tools` values): that one spells its
    schema `.parameters` on BOTH majors and never crosses this seam.
    """
    return tool.inputSchema if MCP_MAJOR == 1 else tool.input_schema


def init_server_info(init_result: Any) -> Any:
    """InitializeResult's server-identity block — 1.x `.serverInfo`, 2.x `.server_info`."""
    return init_result.serverInfo if MCP_MAJOR == 1 else init_result.server_info


def result_is_error(result: Any) -> bool:
    """CallToolResult's error flag — 1.x `.isError`, 2.x `.is_error`."""
    return result.isError if MCP_MAJOR == 1 else result.is_error


def annotations_read_only(annotations: Any) -> bool | None:
    """ToolAnnotations' read-only hint — 1.x `.readOnlyHint`, 2.x `.read_only_hint`.

    CONSTRUCTION by camelCase kwargs stays alias-safe on both majors and does not cross this
    seam; only reads do.
    """
    if annotations is None:
        return None
    return annotations.readOnlyHint if MCP_MAJOR == 1 else annotations.read_only_hint


def in_process_result(result: Any) -> Any:
    """Normalize the IN-PROCESS `server.call_tool()` return for the faces' renderer.

    1.x FastMCP returns the `(content_blocks, structured_content)` tuple governed._normalize
    already understands — passed through untouched. 2.x returns a CallToolResult; hand back
    its structured dict when the SDK produced one, else the content-block list (a plain-dict
    tool return arrives as one JSON TextContent on 2.x — probed — and _normalize's existing
    parse path renders it identically to 1.x's structured dict).
    """
    if MCP_MAJOR == 1:
        return result
    structured = result.structured_content
    if isinstance(structured, dict):
        return structured
    return list(result.content)


def streamable_http_app(server: Any, *, path: str, stateless: bool, json_response: bool,
                        transport_security: Any) -> Any:
    """The Streamable-HTTP ASGI app, configured per major: 1.x mutates `server.settings`
    before calling (and needs its cached-manager quirk reset); 2.x has no settings object,
    takes the same knobs as kwargs, and builds a fresh manager per call (probed)."""
    if MCP_MAJOR == 1:
        server.settings.streamable_http_path = path
        server.settings.stateless_http = stateless
        server.settings.json_response = json_response
        server.settings.transport_security = transport_security
        # Fresh session manager per app: 1.x FastMCP caches its manager on first use, and a
        # manager's run() is once-per-instance — a second build (tests, embedders) would
        # otherwise crash at lifespan start, and the settings above would silently not apply.
        # Private-attr reach; the 1.x SDK exposes no reset. 2.x needs none of this.
        server._session_manager = None  # noqa: SLF001
        return server.streamable_http_app()
    return server.streamable_http_app(
        streamable_http_path=path,
        stateless_http=stateless,
        json_response=json_response,
        transport_security=transport_security,
    )
