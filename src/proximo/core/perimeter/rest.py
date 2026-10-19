"""Proximo HTTP/OpenAPI face — a transport over the governed core.

The full governed tool surface as plain HTTP, for the apps/dashboards/no-code clients (Open WebUI
and the like) that speak REST, not MCP: ``POST /tools/{name}`` with a JSON body of arguments,
discoverable via a generated ``GET /openapi.json``, plus ``GET /healthz``. Every call routes through
the caller's ``dispatch`` (0.44: ``governed.Dispatch``; the core door: its own), the same spine path
(PLAN-by-default, PROVE, UNDO, the gates, the Proxmox token scope) an MCP client takes. No
transport-local curation, no second mutate path: the surface and its safety are the core's, uniform
for every transport. Scope with ``PROXIMO_SURFACES`` and the token ACL, exactly like the MCP face.

The face is an optional extra ([http]); the MCP core keeps zero extra deps. Fail-closed perimeter
(shared with A2A in ``proximo.core.perimeter.guard``): non-localhost binds refuse without a bearer token,
constant-time bearer on every ``/tools/*`` op (discovery stays open), a Host/DNS-rebind allowlist,
and a cross-origin (CSRF) guard on the mutating endpoint.
"""

from __future__ import annotations

import warnings
from typing import Any
from urllib.parse import urlparse

from proximo import __version__

from ..mcpcompat import tool_input_schema

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 41242  # A2A is 41241; the HTTP face sits beside it
_TOKEN_FILE_ENV = "PROXIMO_HTTP_TOKEN_FILE"  # noqa: S105 -- env var NAME, not a secret value
_TOOLS_PREFIX = "/tools/"


_DESCRIPTION = (
    "Proximo's governed Proxmox surface over HTTP — the same tools, spine, and token "
    "scope the MCP face exposes. Mutations are PLAN-by-default: without confirm=true you "
    "get a recorded dry-run plan, never a change. Scope with PROXIMO_SURFACES + the "
    "Proxmox token ACL."
)


def build_openapi(tools: list[Any], *, secured: bool = False,
                  description: str = _DESCRIPTION) -> dict[str, Any]:
    """Build the OpenAPI 3.1 document from the governed tool surface (pure — no I/O).

    One ``POST /tools/{name}`` per tool; the request body schema IS the tool's MCP input schema
    (already JSON Schema; read through ``core.mcpcompat.tool_input_schema``, since the field is
    spelled per mcp major). ``secured=True`` declares the bearer scheme globally so clients know to
    authenticate before they hit a 401. ``description`` is the document's own sentence: the
    0.44 surface's when ``_DESCRIPTION`` is taken, the core door's when it serves the six core tools.
    """
    paths: dict[str, Any] = {}
    for tool in tools:
        raw = tool_input_schema(tool)
        schema = raw if isinstance(raw, dict) else {"type": "object"}
        paths[f"/tools/{tool.name}"] = {
            "post": {
                "operationId": tool.name,
                "summary": tool.name,
                "description": tool.description or "",
                "requestBody": {
                    "required": bool(schema.get("required")),
                    "content": {"application/json": {"schema": schema}},
                },
                "responses": {
                    "200": {"description": "Result (a PLAN for an unconfirmed mutation)."},
                    "400": {"description": "Malformed request (non-object body / missing param)."},
                    "401": {"description": "Missing/invalid bearer token."},
                    "404": {"description": "Unknown tool."},
                    "413": {"description": "Request body too large."},
                    "415": {"description": "Content-Type must be application/json."},
                    "502": {"description": "The tool ran and failed (sanitized)."},
                },
            }
        }

    doc: dict[str, Any] = {
        "openapi": "3.1.0",
        "info": {
            "title": "Proximo",
            "version": __version__,
            "description": description,
        },
        "paths": paths,
    }
    if secured:
        doc["components"] = {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}}
        doc["security"] = [{"bearerAuth": []}]
    return doc


def _audit_rejection(tool_name: str | None, reason: str, record) -> None:
    """Best-effort PROVE trace for a REJECTED HTTP call (unknown tool / bad body / malformed).

    The 4xx response is the primary guarantee; this records the rejection to the same tamper-evident
    ledger the tools use, so hostile enumeration of the surface isn't invisible. ``record`` is the
    caller's row writer (the core door's ``network.recorder``, or an embedder's).
    Best-effort: a ledger write must never mask the rejection.
    """
    target = str(tool_name or "<none>")
    try:
        record("http_rejected", target=target, outcome="rejected", detail={"reason": reason})
    except Exception as exc:  # noqa: BLE001 — supplementary audit; never break the rejection path
        warnings.warn(f"HTTP rejection audit failed to record: {type(exc).__name__}", stacklevel=2)


def build_app(url: str | None = None, *, token: str | None = None,
              allowed_hosts: list[str] | None = None, dispatch, record,
              description: str = _DESCRIPTION):
    """Build the Proximo HTTP-face ASGI application.

    Args:
        url:   Advertised base URL (default ``http://127.0.0.1:41242/``). Its hostname feeds the
               fail-closed public-bind guard and the default Host allowlist.
        token: Inbound bearer token. When set, every ``/tools/*`` op requires it and the served
               OpenAPI doc declares the bearer scheme. When None and *url* advertises a non-localhost
               host, construction is REFUSED (fail-closed). This factory does NOT read the
               environment; the door (``doors.http`` through ``network.main_of``) loads the token and passes it in.
        allowed_hosts: Host allowlist for the DNS-rebind guard (all modes). Defaults to the served
               host + loopback forms. ``["*"]`` only behind a trusted reverse-proxy (warns).
        dispatch: What ``POST /tools/{name}`` runs on. Required: the governed core's
               REST door passes a ``proximo.core.doors.dispatch.Core``, so the
               OpenAPI document lists the six core tools and every call lands on the core's engine
               behind THIS perimeter.
        record: How the perimeter's badge camera and the rejection rows are written. Required:
               the core door's own (``network.recorder``), or an embedder's.
        description: the OpenAPI document's sentence (``build_openapi``).
    """
    import json as _json  # noqa: PLC0415

    import anyio.to_thread  # noqa: PLC0415, F401 -- [http]-extra deps present only with the extra
    from starlette.applications import Starlette  # noqa: PLC0415
    from starlette.responses import JSONResponse  # noqa: PLC0415
    from starlette.routing import Route  # noqa: PLC0415

    from ..doors.dispatch import DispatchError  # noqa: PLC0415
    from .guard import guard_middleware, require_auth_for_public  # noqa: PLC0415

    call_governed, list_governed = dispatch.call, dispatch.list

    if url is None:
        url = f"http://{_DEFAULT_HOST}:{_DEFAULT_PORT}/"

    # Defense-in-depth: refuse a public advertised URL without a token, whoever built the app.
    require_auth_for_public(urlparse(url).hostname, token, where="advertised URL",
                            face="HTTP", token_env=_TOKEN_FILE_ENV)

    _doc: list[dict | None] = [None]  # lazily built + cached on first discovery request

    async def _serve_openapi(_request):
        if _doc[0] is None:
            _doc[0] = build_openapi(await list_governed(), secured=bool(token),
                                    description=description)
        return JSONResponse(_doc[0])

    async def _healthz(_request):
        return JSONResponse({"ok": True})

    async def _tool(request):
        name = request.path_params["tool_name"]
        raw = await request.body()
        if raw:
            try:
                args = _json.loads(raw)
            except ValueError:
                _audit_rejection(name, "request body is not valid JSON", record)
                return JSONResponse({"error": "request body must be a JSON object"}, status_code=400)
        else:
            args = {}
        try:
            result = await call_governed(name, args)
        except DispatchError as exc:
            if exc.status in (400, 404):
                _audit_rejection(name, exc.message, record)
            return JSONResponse({"error": exc.message}, status_code=exc.status)
        return JSONResponse(result)

    routes = [
        Route("/openapi.json", _serve_openapi, methods=["GET"]),
        Route("/healthz", _healthz, methods=["GET"]),
        Route("/tools/{tool_name}", _tool, methods=["POST"]),
    ]

    # The shared perimeter stack (TrustedHost → CrossOriginGuard → Bearer-with-token) — one
    # contract for every face; this face only picks its protected paths and 401 body.
    middleware = guard_middleware(
        url, face="HTTP", token=token,
        protect=lambda path: path.startswith(_TOOLS_PREFIX),
        unauthorized_body={"error": "unauthorized"},
        allowed_hosts=allowed_hosts, record=record,
    )
    return Starlette(routes=routes, middleware=middleware)
