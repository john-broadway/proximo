"""The governed dispatch — the ONE transport-agnostic path over Proximo's tool surface.

Proximo is a governed core with interchangeable transports. The core is the MCP tool surface, each
wrapped in the trust spine (PLAN-by-default, PROVE ledger, UNDO, the opt-in gates) and bounded by
the Proxmox token scope. `mcp.call_tool` runs a tool through that spine — exactly what an MCP
client gets. Every network face (A2A, HTTP) is a thin adapter over the two functions here:

  * ``list_governed()`` — the full surface the operator configured (auto-scoped / PROXIMO_SURFACES),
    the same list an MCP client would see.
  * ``call_governed(name, arguments)`` — run one tool through the spine and hand back plain JSON.

There is no transport-local curation and no second mutate path: a transport carries the surface,
it does not curate it. What is safe to expose is decided by the spine + the token scope + the
operator's surface config, uniformly, for every transport — never by a hand-picked per-transport
allowlist. (That
allowlist — the old 16-skill A2A slice — re-introduced the exact "safe inspector vs. loaded gun"
trade Proximo exists to refuse; the spine is the answer, so the whole surface rides it.)
"""

from __future__ import annotations

import json
from typing import Any

from mcp.server.fastmcp.exceptions import ToolError
from pydantic import ValidationError

from . import server


class GovernedError(Exception):
    """A dispatch failure carrying the HTTP-ish status a transport should map to.

    404 unknown tool · 400 malformed request · 502 the tool ran and failed. The ``message`` is
    safe to return to the caller: it is either our own structural message or the tool's own error
    string (which Proximo tools keep secret-free by invariant, and which MCP already surfaces).
    """

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


async def list_governed() -> list[Any]:
    """The governed tool surface — the operator's configured set, same as an MCP client sees.

    Returns MCP ``Tool`` objects (``.name`` / ``.description`` / ``.inputSchema``)."""
    return await server.mcp.list_tools()


def list_governed_sync() -> list[Any]:
    """Synchronous variant for build paths that may run inside a running event loop (e.g.
    ``build_agent_card`` called from an async server bootstrap, where ``anyio.run`` can't nest).

    Reads the FastMCP tool manager directly. The returned internal ``Tool`` objects expose
    ``.name`` and ``.description`` (their JSON schema is ``.parameters``, not ``.inputSchema``) —
    enough for the agent card, which advertises names + descriptions. For the request schema use
    the async ``list_governed`` (its ``.inputSchema``) from an async context."""
    return server.mcp._tool_manager.list_tools()


async def _tool_index() -> dict[str, Any]:
    """name -> Tool, for existence + required-param checks. The surface is fixed at process
    start (registration happens at import), so this is a cheap per-call rebuild of a small map."""
    return {t.name: t for t in await server.mcp.list_tools()}


async def call_governed(name: str, arguments: Any) -> dict[str, Any]:
    """Run one governed tool through the spine and return plain JSON.

    Raises GovernedError(404) for an unknown tool, (400) for a malformed request (non-object args
    or a missing required param), (502) for a tool that ran and failed (message sanitized to the
    tool's own error, never a traceback). Everything else is delegated to ``mcp.call_tool`` — the
    identical validation + spine path an MCP client takes, so the faces can't diverge from MCP.
    """
    if not isinstance(name, str):
        # A non-string name (list/dict from a malformed inbound message) would be an unhashable
        # dict-lookup crash; reject it as malformed so it lands in the audited rejection path.
        raise GovernedError(400, "tool name must be a string")
    if not isinstance(arguments, dict):
        raise GovernedError(400, "request params must be a JSON object")

    tool = (await _tool_index()).get(name)
    if tool is None:
        raise GovernedError(404, f"unknown tool '{name}'")

    # Structural pre-check (clean 400 for the common client mistake). Type validation stays with
    # the tool's own pydantic model via call_tool, so we never diverge from MCP's coercion.
    required = tool.inputSchema.get("required", []) if isinstance(tool.inputSchema, dict) else []
    missing = [r for r in required if r not in arguments]
    if missing:
        raise GovernedError(400, f"missing required param(s): {sorted(missing)}")

    try:
        result = await server.mcp.call_tool(name, arguments)
    except ToolError as e:
        # call_tool wraps EVERY in-tool exception as ToolError(f"Error executing tool {name}: {e}")
        # from e — so its str() carries the underlying exception's message verbatim, which for the
        # exec plane (ct_exec/ct_psql/pve_agent_exec) is the full remote command (secrets on the
        # argv) + the operator's SSH target. NEVER return that text. Surface only the underlying
        # exception TYPE (via __cause__), matching the old face's type-name-only sanitization.
        cause = e.__cause__
        if isinstance(cause, ValidationError):
            # A pydantic arg-validation failure is the caller's fault → 400, no echoed detail.
            raise GovernedError(400, "invalid parameters (see this tool's schema in /openapi.json)") from None
        tname = type(cause).__name__ if cause is not None else "ToolError"
        raise GovernedError(502, f"tool {name!r} failed: {tname}") from None
    except Exception as e:  # noqa: BLE001 — a non-ToolError escape is an internal fault; sanitize hard
        raise GovernedError(502, f"internal error: {type(e).__name__}") from None

    return _normalize(result)


def _normalize(result: Any) -> dict[str, Any]:
    """Normalize a call_tool result to a JSON object for the response body.

    FastMCP's ``call_tool`` returns a 2-tuple ``(content_blocks, structured_content)`` — element 1
    is the tool's structured output: a dict return passes through as itself, a non-dict (list/scalar)
    is wrapped by FastMCP under ``{"result": ...}``. That structured dict IS what an MCP client's
    structured output carries, so it is exactly what the REST/A2A caller should get — return it
    verbatim. Fallbacks cover a bare-dict return and the older single-content-block shape.

    (Getting this wrong returns an empty body for every read — caught only by driving the live face,
    not by the unit tests, because the tuple shape is what the real SDK returns.)
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
        # Multiple content blocks (a bare-`list`-annotated tool with no output schema): parse each
        # part so callers get objects, not raw JSON strings. Only structured JSON (dict/list) is
        # substituted — a plain-text part, or one that parses to a bare scalar ("123"/"true"), stays
        # the original string so we never silently retype text data.
        def _maybe(text: str) -> Any:
            try:
                parsed = json.loads(text)
            except (ValueError, TypeError):
                return text
            return parsed if isinstance(parsed, (dict, list)) else text
        return {"result": [_maybe(p) for p in parts]}
    return {"result": result}
