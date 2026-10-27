"""ONE dispatch: a foreign protocol's call, run on an MCP server instance, answered as plain JSON.

The REST and A2A faces adapt a protocol that is not MCP onto a tool surface that is. 0.44 did
that 0.44 did over its own server; the core's doors do it over
`proximo.core.doors.mcp.build_server()`. The adapter is the same four steps whichever instance
stands behind it (a string name, an object of arguments, the tool exists, its required
arguments are present; then the SDK's own validation and the tool body; then the result as one
JSON object), so it is written once here and `governed` is this module applied to the 0.44
instance. A face handed a `Core` serves the six core tools through the identical bytes.

What a caller is told when a tool fails (`DispatchError`, status 502): a `ProximoError` is the
spine's own channel, scrubbed at construction (`core.errors`) and shown whole on the MCP doors
since day one, so its text is the answer: "not armed", the tier a mutation lacks, the consent
id, the did-you-mean pointer, "pve is not configured". The first ProximoError in the cause chain
is the one spoken, as on the MCP doors. A chain with none is a fault, and only the root's TYPE is
said: an exec timeout's message is the whole remote command line.

The SDK is imported inside the functions, never at module level: `tests/test_closure.py` holds
the doors' import closure to what `import httpx` alone loads.
"""
from __future__ import annotations

import json
from typing import Any

from proximo.core import rawdoor
from proximo.core.errors import ProximoError


class DispatchError(Exception):
    """A dispatch failure carrying the HTTP-ish status a transport maps it to.

    404 unknown tool · 400 malformed request · 502 the tool ran and failed. `message` is safe to
    return to the caller: our own structural sentence, a `ProximoError`'s text, or a type name, and
    SEALED HERE, at construction (`rawdoor.refusal_text`: escaped, at most the refusal ceiling in
    bytes), so the REST and A2A faces cannot hand back a refusal the MCP doors would have cut."""

    def __init__(self, status: int, message: str) -> None:
        message = rawdoor.refusal_text(str(message))
        super().__init__(message)
        self.status = status
        self.message = message


async def list_on(instance: Any) -> list[Any]:
    """The wire `Tool` objects of *instance* (`.name`, `.description`, the schema through
    `mcpcompat.tool_input_schema`, spelled per SDK major)."""
    return await instance.list_tools()


def list_sync_on(instance: Any) -> list[Any]:
    """The registry's tools, for a build path that may already be inside an event loop (the
    agent card). `.name` and `.description`; the schema is `.parameters` here, not the wire's."""
    return instance._tool_manager.list_tools()  # noqa: SLF001 -- the SDK's one sync listing


def _chain(exc: BaseException) -> list[BaseException]:
    out = [exc]
    while out[-1].__cause__ is not None:
        out.append(out[-1].__cause__)
    return out


async def call_on(instance: Any, name: Any, arguments: Any) -> dict[str, Any]:
    """Run one tool of *instance* and return plain JSON, or raise `DispatchError`."""
    from proximo.core.mcpcompat import in_process_result, tool_input_schema

    if not isinstance(name, str):
        # A list or dict name out of a malformed message would be an unhashable lookup: a 400 that
        # lands on the audited rejection path, never a crash.
        raise DispatchError(400, "tool name must be a string")
    if not isinstance(arguments, dict):
        raise DispatchError(400, "request params must be a JSON object")
    tool = next((t for t in await list_on(instance) if t.name == name), None)
    if tool is None:
        raise DispatchError(404, f"unknown tool {rawdoor.quote(name, 40)}")
    schema = tool_input_schema(tool)
    required = schema.get("required", []) if isinstance(schema, dict) else []
    missing = [r for r in required if r not in arguments]
    if missing:
        raise DispatchError(400, f"missing required param(s): {sorted(missing)}")
    try:
        result = await instance.call_tool(name, arguments)
    except Exception as e:  # noqa: BLE001 -- every escape is classified below, none re-raised
        from proximo.core.mcpcompat import ToolError
        if not isinstance(e, ToolError):
            raise DispatchError(502, f"internal error: {type(e).__name__}") from None
        chain = _chain(e)
        if type(chain[-1]).__name__ == "ValidationError":
            # The SDK's argument validation: the caller's fault, and pydantic's text echoes the
            # value it refused, so none of it is repeated.
            raise DispatchError(400, "invalid parameters (see this tool's schema)") from None
        # THE FIRST ProximoError, not the root: the spine raises its sentence `from` the vendor's
        # or the stdlib's exception ("pve is not configured on this Proximo (...)" from a
        # RuntimeError, 17 such sites), and walking to the root reduced every one of them to the
        # cause's type name (lens 1, 2026-10-04). The MCP doors stop at the first; so does this.
        spoken = next((c for c in chain if isinstance(c, ProximoError)), None)
        if spoken is not None:
            raise DispatchError(502, f"tool {rawdoor.quote(name, 40)} failed: {spoken}") from None
        raise DispatchError(502, f"tool {rawdoor.quote(name, 40)} failed: {type(chain[-1]).__name__}") from None
    return normalize(in_process_result(result))


def normalize(result: Any) -> dict[str, Any]:
    """One JSON object out of what an in-process `call_tool` returns, per SDK major.

    1.x answers `(content_blocks, structured_content)`: the structured dict IS what an MCP
    client's structured output carries, so it is what a REST or A2A caller gets, verbatim. 2.x has
    been unwrapped by `in_process_result` to that dict or to the content-block list; one JSON
    text block parses to the same object. A bare dict passes; anything else is wrapped under
    `result`. (Wrong, this answers an empty body for every read, and only driving the live face
    showed it: the tuple is what the real SDK returns.)
    """
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return result[1]
    if isinstance(result, dict):
        return result
    if isinstance(result, (list, tuple)):
        parts = [c.text for c in result if getattr(c, "text", None) is not None]
        if len(parts) == 1:
            try:
                parsed = json.loads(parts[0])
            except (ValueError, TypeError):
                return {"result": parts[0]}
            return parsed if isinstance(parsed, dict) else {"result": parsed}

        def _maybe(text: str) -> Any:
            # Several blocks (a bare-list tool with no output schema): structured JSON becomes
            # objects; plain text, or text that parses to a scalar, stays the string it was.
            try:
                parsed = json.loads(text)
            except (ValueError, TypeError):
                return text
            return parsed if isinstance(parsed, (dict, list)) else text
        return {"result": [_maybe(p) for p in parts]}
    return {"result": result}


class Core:
    """The six core tools as a dispatch: `build_server()` once, on first use, and the three
    operations a face needs. Handed to the perimeter's `rest.build_app` and `a2a.app.build_app`
    as `dispatch=`, so the core's REST and A2A doors are the 0.44 perimeters with this behind them."""

    def __init__(self) -> None:
        self._instance: Any = None

    @property
    def instance(self) -> Any:
        if self._instance is None:
            from proximo.core.doors.mcp import build_server
            self._instance = build_server()
        return self._instance

    async def list(self) -> list[Any]:
        return await list_on(self.instance)

    def list_sync(self) -> list[Any]:
        return list_sync_on(self.instance)

    async def call(self, name: Any, arguments: Any) -> dict[str, Any]:
        return await call_on(self.instance, name, arguments)
