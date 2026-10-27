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

import inspect
import json
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from . import rawdoor
from .errors import ProximoError
from .secretfile import redact

if TYPE_CHECKING:  # the checker reads the LOCKED major (2.x); the runtime picks below
    from mcp.server import MCPServer as ServerClass
    from mcp.server.mcpserver.exceptions import ToolError

    MCP_MAJOR = 2
else:
    try:  # mcp 1.x — the fastmcp module IS the 1.x marker; 2.0.0 deleted it.
        from mcp.server.fastmcp import FastMCP as ServerClass
        from mcp.server.fastmcp.exceptions import ToolError

        MCP_MAJOR = 1
    except ImportError:  # mcp 2.x — MCPServer is the FastMCP analog (same decorator/tool()/run surface).
        from mcp.server import MCPServer as ServerClass
        from mcp.server.mcpserver.exceptions import ToolError

        MCP_MAJOR = 2

__all__ = [
    "MCP_MAJOR",
    "compact_result",
    "compact_text_blocks",
    "seal_result",
    "slim_schemas",
    "ServerClass",
    "ToolError",
    "annotations_read_only",
    "in_process_result",
    "init_server_info",
    "make_server",
    "result_is_error",
    "streamable_http_app",
    "tool_annotations_kwargs",
    "tool_input_schema",
]

# Does this SDK's tool() decorator accept `annotations=`? The kwarg arrived well after the 1.24
# floor, so passing it unconditionally is a TypeError on the floor — and CI's 1.x leg runs the
# lock's pin, not the floor, so only this gate (not a green build) protects that path.
TOOL_SUPPORTS_ANNOTATIONS = "annotations" in inspect.signature(ServerClass.tool).parameters


def compact_text_blocks(blocks: Any) -> list[Any]:
    """The same blocks with every text block that holds a JSON object or array re-spelled COMPACT.

    Both SDK majors serialize a tool's dict with `indent=2`, and a model reads that text: measured
    with the Qwen3 tokenizer, the indentation was a third of the tokens of a lean read. The answer
    is unchanged (same keys, same order, same values; non-ASCII left whole, not `\\u`-escaped), and
    the structured copy a client reads beside it is not touched. Anything that is not an object or
    an array (a refusal's sentence, a bare number, plain text) is left exactly as it was."""
    out = []
    for block in blocks:
        text = getattr(block, "text", None)
        if isinstance(text, str) and getattr(block, "type", None) == "text":
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
            if isinstance(parsed, (dict, list)):
                squeezed = json.dumps(parsed, separators=(",", ":"), ensure_ascii=False)
                if squeezed != text:
                    block = block.model_copy(update={"text": squeezed})
        out.append(block)
    return out


def compact_result(result: Any) -> Any:
    """`compact_text_blocks` over what an in-process `call_tool` returns, per SDK major: 2.x a
    `CallToolResult`, 1.x the content list or the `(content, structured)` pair."""
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[0], (list, tuple)):
        return (compact_text_blocks(result[0]), result[1])
    if isinstance(result, (list, tuple)):
        return compact_text_blocks(result)
    content = getattr(result, "content", None)
    if isinstance(content, (list, tuple)):
        return result.model_copy(update={"content": compact_text_blocks(content)})
    return result


def seal_result(name: str, result: Any) -> Any:
    """THE EXIT: `compact_result`, then the answer held to its kind's ceiling (`rawdoor.finish`): terse, and
    REPLACED by the fixed-shape over-cap answer when its final bytes are over. The structured copy a client
    reads beside the text is the same object, so neither can carry what the other was cut of."""
    result = compact_result(result)
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        answer = result[1]
    elif isinstance(structured := getattr(result, "structured_content", None), dict):
        answer = structured
    else:
        return result
    final = rawdoor.finish(name, answer)
    from mcp.types import TextContent  # noqa: PLC0415 -- the SDK is an optional extra
    block = TextContent(type="text", text=json.dumps(final, separators=(",", ":"), ensure_ascii=False, default=str))
    if isinstance(result, tuple):
        return ([block], final)
    return result.model_copy(update={"content": [block], "structured_content": final})


def _invalid(tool: str, error: Any) -> str:
    """A validation failure as ONE fixed sentence and at most three argument names, each cut by echo. Pydantic's
    own text quotes the input (233 KB for a thousand undeclared keys); the names are all a caller needs."""
    found = error.errors(include_input=False, include_url=False)
    names = [".".join(str(p) for p in item.get("loc", ())) for item in found]
    more = f" (and {len(names) - 3} more)" if len(names) > 3 else ""
    shown = ", ".join(rawdoor.echo(n, 40) for n in names[:3]) + more
    extra = all(item.get("type") == "extra_forbidden" for item in found)
    what = "unexpected arguments" if extra else "invalid arguments"
    return f"Error executing tool {tool}: {what}: {shown}"


def tool_annotations_kwargs(read_only: bool) -> dict[str, Any]:
    """`annotations=` kwarg for ServerClass.tool(), or {} when this SDK predates the kwarg.

    Construction by camelCase kwargs is alias-safe on both majors (see annotations_read_only);
    on a pre-annotations SDK the hint degrades to absent, same as the derived-marker path."""
    if not TOOL_SUPPORTS_ANNOTATIONS:
        return {}
    from mcp.types import ToolAnnotations

    return {"annotations": ToolAnnotations(readOnlyHint=read_only)}  # pyright: ignore[reportCallIssue] -- alias kwarg


def make_server(name: str, version: str, unknown_tool: Callable[[str], str] | None = None) -> Any:
    """Construct the per-major server, advertising Proximo's OWN version in `initialize`.

    1.x FastMCP leaves the low-level Server.version=None (the handshake would advertise the
    SDK's version); setting the private attribute after construction is the only seam. 2.x
    takes `version=` as a constructor kwarg. On 2.x the returned instance is a subclass whose
    `call_tool` override is the H1 hook: `_handle_call_tool` (the wire) awaits the PUBLIC
    `call_tool`, and a non-MCPError raised there reaches the client as an is_error result —
    so a non-resident name gets the recoverable did-you-mean pointer instead of the SDK's
    dead-end "Unknown tool" (on 1.x, H1 is the low-level handler re-registration at the
    bottom of server.py; this subclass is its 2.x twin, sanctioned seam). `unknown_tool` is
    the door's own pointer text for a name it does not have; the default names the tools
    that ARE registered.

    Equivalence is WIRE-scoped, deliberately: a client sees the same pointer on both majors.
    The IN-PROCESS `server.call_tool()` differs for a non-resident name — 1.x H1 rewires only
    the wire handler, so in-process callers get the SDK's ToolError("Unknown tool: X"); the
    2.x override intercepts every call, so they get ProximoError(pointer). Embedders calling
    in-process should catch both; the delta is pinned by
    tests/test_mcpcompat.py::test_the_in_process_unknown_tool_delta_is_the_documented_one.
    (proximo's own faces are unaffected: governed 404s on non-residents before dispatching.)
    """
    if MCP_MAJOR == 1:
        class _CompactFastMCP(ServerClass):  # type: ignore[misc,valid-type]
            async def call_tool(self, *args: Any, **kwargs: Any) -> Any:
                return seal_result(str(args[0]) if args else "", await super().call_tool(*args, **kwargs))

        server = _CompactFastMCP(name)
        server._mcp_server.version = version  # noqa: SLF001  # pyright: ignore[reportAttributeAccessIssue] -- 1.x only
        return server

    class _GovernedMCPServer(ServerClass):  # type: ignore[misc,valid-type]
        async def call_tool(self, name: str, arguments: dict, context: Any = None) -> Any:  # noqa: A002
            if name not in self._tool_manager._tools:  # noqa: SLF001
                if unknown_tool is not None:
                    raise ProximoError(rawdoor.refusal_text(unknown_tool(rawdoor.echo(str(name), 40))))
                known = ", ".join(sorted(self._tool_manager._tools))  # noqa: SLF001
                raise ProximoError(f"unknown tool {rawdoor.quote(str(name), 40)}; this server has: {known}")
            try:
                return seal_result(name, await super().call_tool(name, arguments, context))
            except ToolError as e:
                # 2.x sanitizes every non-ToolError raised inside a tool to "Error executing tool
                # <name>" (UnexpectedToolError), so an adopter on this SDK read every refusal —
                # lease expired, consent missing, scope, did-you-mean, the read door — as a bare
                # tool name (2026-09-19, dogfood server on 2.2.0). ProximoError is the caller-safe
                # channel by design (backends.py: never carries secrets; _audited_run scrubs URLs
                # into it) and 1.x has shown its text verbatim since day one. Translate exactly
                # that class, keeping the SDK's prefix and the cause chain (governed.py reads
                # type(__cause__).__name__); everything else keeps the SDK's contract.
                cause = e
                while isinstance(cause, ToolError) and cause.__cause__ is not None:
                    cause = cause.__cause__
                if isinstance(cause, ProximoError):
                    head = f"Error executing tool {rawdoor.echo(str(name), 40)}: "     # the WHOLE text <= the ceiling
                    raise ToolError(head + rawdoor.echo_bytes(str(cause), rawdoor.CEILINGS["refusal"]
                                                              - len(head.encode()))) from cause
                # The last seam before str(e) reaches the model: argument validation runs in the
                # SDK before the tool body, so a caller value echoed by pydantic never met
                # target_aware (lens 2026-09-20). Scrub here; cause kept for governed.py.
                if type(cause).__name__ == "ValidationError":
                    raise ToolError(rawdoor.refusal_text(_invalid(name, cause))) from e.__cause__
                clean = redact(str(e))
                if clean != str(e):
                    raise ToolError(rawdoor.refusal_text(clean)) from e.__cause__
                raise ToolError(rawdoor.refusal_text(str(e))) from e.__cause__

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


_SCHEMA_MAPS = ("properties", "$defs", "definitions", "patternProperties")   # name -> schema
_VALUES = ("enum", "const", "default", "examples", "required")                    # data, not schema


def _slim(node: Any, names: bool = False) -> Any:
    """A schema as a model needs it: no `title` (pydantic repeats every name as one), no `default:
    null` and no `anyOf [X, null]` wrapper (an argument that may be left out is simply not required),
    no `additionalProperties`. Only SCHEMA KEYWORDS go: the keys of a `properties` map are argument
    NAMES (an argument called `title` or `default` stays), and an enum, a default or a required list
    is data. The ARGUMENT MODEL is untouched: validation and the undeclared-name refusal read that,
    not this."""
    if isinstance(node, list):
        return [_slim(x) for x in node]
    if not isinstance(node, dict):
        return node
    if names:                                   # a name -> schema map: every key is a name, kept
        return {k: _slim(v) for k, v in node.items()}
    out: dict[str, Any] = {}
    for k, v in node.items():
        if k in ("title", "additionalProperties") or (k == "default" and v is None):
            continue
        out[k] = v if k in _VALUES else _slim(v, names=k in _SCHEMA_MAPS)
    options = out.get("anyOf")
    if isinstance(options, list) and len(options) == 2 and {"type": "null"} in options:
        keep = next(o for o in options if o != {"type": "null"})
        out.pop("anyOf")
        out.update(keep if isinstance(keep, dict) else {})
    return out


def slim_schemas(server: Any) -> None:
    """Hand the model the slim schema of every registered tool (see `_slim`). The registry Tool's
    `.parameters` is what both majors put on the wire as the input schema."""
    for tool in server._tool_manager.list_tools():  # noqa: SLF001 -- the seam's sanctioned reach
        tool.parameters = _slim(tool.parameters)


def forbid_undeclared(server: Any) -> None:
    """Every registered tool REFUSES an argument its signature does not declare (both majors).

    The SDK's argument model ignores an unknown key by default, so a call carrying one ran as if
    the key were absent. Lens 3 (2026-10-05, BLOCKING): on a box where the core door does not
    advertise `target`, `proximo_call ... target=<box> confirm=true` dropped the target and ran on
    the ENV box under the env box's arm. The class is wider than that one name: a misspelt `wait`
    or `fields` vanished the same way. Applied after registration, so the published input schema
    is unchanged (no `additionalProperties` bytes in the 4K window); the refusal is pydantic's
    `extra_forbidden`, which the REST and A2A dispatch already maps to a 400.
    """
    for tool in server._tool_manager.list_tools():  # noqa: SLF001 -- the seam's sanctioned reach
        model = tool.fn_metadata.arg_model
        model.model_config["extra"] = "forbid"
        model.model_rebuild(force=True)
