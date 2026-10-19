"""Proximo MCP-over-streamable-HTTP face — the MCP protocol itself, served over the network.

The stdio server IS MCP; this face serves the SAME FastMCP instance over the MCP Streamable HTTP
transport (the SDK's native ``streamable_http_app()``), for the distributed MCP clients (Claude
Desktop/Code on another machine, web clients) that would otherwise need a third-party stdio→HTTP
bridge. Those bridges sit OUTSIDE Proximo's perimeter: whatever auth/rebind/CSRF posture exists is
then the bridge's, not Proximo's (upstream FR #25). Here every call lands on the caller's FastMCP
``instance`` itself (the 0.44 entry hands in ``server.mcp``; the core door hands in its own): the
identical tool registry, trust spine (PLAN-by-default, PROVE, UNDO, the gates), and Proxmox token
scope a stdio client gets. There is no adapter layer at all, not even a dispatch, so this face
cannot diverge from MCP: it IS MCP. That includes error surfaces: a failing tool returns the same
MCP error text a stdio client sees; the REST face's sanitized ``tool failed: <Type>`` mapping is a
dispatch behavior and does not apply here. This module names no caller of its own: the instance
and the ledger writer are injected, so the perimeter reaches nothing of 0.44 (see
``tests/test_gate_mutations_inventory.py``).

The face is an optional extra ([mcp-http], which also pins the SDK floor for the streamable-HTTP
API); the MCP core keeps zero extra deps. Fail-closed perimeter shared with A2A + HTTP — the ONE
``guard.guard_middleware`` stack, in contract order: non-localhost binds refuse without a bearer
token, constant-time bearer on the ``/mcp`` endpoint (liveness stays open), a Host/DNS-rebind
allowlist, and the cross-origin (CSRF) guard on POST. The SDK ships its own DNS-rebind protection
(newer SDKs default it ON with a fixed loopback-only allowlist) — it is explicitly DISABLED here in
favor of the one authoritative perimeter guard, so the hardening contract cannot drift between
transports; see ``build_app``.
"""

from __future__ import annotations

from urllib.parse import urlparse

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 41243  # A2A is 41241, HTTP/OpenAPI 41242; the MCP-HTTP face sits beside them
_TOKEN_FILE_ENV = "PROXIMO_MCP_HTTP_TOKEN_FILE"  # noqa: S105 -- env var NAME, not a secret value
_MCP_PATH = "/mcp"  # the SDK's default streamable-HTTP path, pinned explicitly (the guards match it)

def build_app(url: str | None = None, *, token: str | None = None,
              allowed_hosts: list[str] | None = None,
              stateless: bool = True, json_response: bool = False, instance, record):
    """Build the Proximo MCP-over-streamable-HTTP ASGI application.

    Args:
        url:   Advertised base URL (default ``http://127.0.0.1:41243/``). Its hostname feeds the
               fail-closed public-bind guard and the default Host allowlist.
        token: Inbound bearer token. When set, every request to ``/mcp`` (POST message, GET SSE
               stream, DELETE session) requires it. When None and *url* advertises a non-localhost
               host, construction is REFUSED (fail-closed). This factory does NOT read the
               environment; the door (``doors.mcphttp`` through ``network.main_of``) loads the token and passes it in.
        allowed_hosts: Host allowlist for the DNS-rebind guard (all modes). Defaults to the served
               host + loopback forms. ``["*"]`` only behind a trusted reverse-proxy (warns).
        stateless: Serve in the SDK's stateless mode (no per-session state; each request is
               self-contained). Default TRUE — the maintainer's call on FR #25: multi-client
               behind a proxy is the deployment model this face exists for, and nothing in the
               governed surface needs a session. Pass False for session-stateful serving.
        json_response: Answer POSTs with plain JSON bodies instead of an SSE stream, for clients
               that prefer it.
        instance: The MCP server to serve. Required: the governed core's network door passes
               ``proximo.core.doors.mcp.build_server()`` so the core
               mounts THIS perimeter rather than a copy of it, and never loads the 0.44 server.
        record: How the perimeter's caller badge writes its rows (``guard_middleware``). Required:
               the core door's own (``network.recorder``), or an embedder's.

    NOTE: the returned app carries a lifespan (the SDK's session manager) — it must be served by a
    lifespan-running host (uvicorn does; a bare ``httpx.ASGITransport`` does not).
    """
    from mcp.server.transport_security import TransportSecuritySettings  # noqa: PLC0415
    from starlette.responses import JSONResponse  # noqa: PLC0415
    from starlette.routing import Route  # noqa: PLC0415

    from ..mcpcompat import streamable_http_app as compat_streamable_http_app  # noqa: PLC0415
    from .guard import guard_middleware, require_auth_for_public  # noqa: PLC0415

    if url is None:
        url = f"http://{_DEFAULT_HOST}:{_DEFAULT_PORT}/"

    # Defense-in-depth: refuse a public advertised URL without a token, whoever built the app.
    require_auth_for_public(urlparse(url).hostname, token, where="advertised URL",
                            face="MCP-HTTP", token_env=_TOKEN_FILE_ENV)

    # ONE authoritative perimeter, not two: newer SDKs default their own DNS-rebind guard ON with
    # a fixed loopback-only, port-suffixed allowlist — which would 421 every legitimate non-default
    # deployment (public bind with token, reverse-proxy Hosts, the operator's PROXIMO_MCP_HTTP_
    # ALLOWED_HOSTS) and cannot express the guard's list (no bare-host match, no "*"). The shared
    # guard_middleware stack below covers both of its checks — TrustedHost validates Host (rebind),
    # the CSRF guard validates Origin + Content-Type — so the SDK layer is disabled rather than fed
    # a second, driftable copy of the allowlist. (Its POST Content-Type check stays on either way.)
    # Per-major wiring (1.x settings mutation + its cached-manager reset / 2.x kwargs) lives in
    # mcpcompat.streamable_http_app.
    app = compat_streamable_http_app(
        instance, path=_MCP_PATH, stateless=stateless,
        json_response=json_response,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))

    async def _healthz(_request):
        return JSONResponse({"ok": True})

    app.router.routes.append(Route("/healthz", _healthz, methods=["GET"]))

    # The shared perimeter stack (TrustedHost → CrossOriginGuard → Bearer-with-token) — one
    # contract for every face; this face only picks its protected path and 401 body. The SDK
    # constructs the Starlette app itself, so the stack is mounted afterwards: add_middleware
    # PREPENDS, so adding in reverse yields exactly guard_middleware's contract order.
    # (/healthz stays open, like the other faces' discovery routes; /mcp itself is the whole
    # protected protocol endpoint — POST message, GET SSE stream, DELETE session.)
    stack = guard_middleware(
        url, face="MCP-HTTP", token=token,
        protect=lambda path: path.rstrip("/") == _MCP_PATH,
        # MCP streamable HTTP is JSON-RPC over HTTP — same 401 body shape as the A2A face.
        unauthorized_body={"jsonrpc": "2.0", "id": None,
                           "error": {"code": -32001, "message": "unauthorized"}},
        allowed_hosts=allowed_hosts, record=record,
    )
    for cls, args, kwargs in reversed(stack):
        app.add_middleware(cls, *args, **kwargs)
    return app
