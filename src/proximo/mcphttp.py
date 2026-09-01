"""Proximo MCP-over-streamable-HTTP face — the MCP protocol itself, served over the network.

The stdio server IS MCP; this face serves the SAME FastMCP instance over the MCP Streamable HTTP
transport (the SDK's native ``streamable_http_app()``), for the distributed MCP clients (Claude
Desktop/Code on another machine, web clients) that would otherwise need a third-party stdio→HTTP
bridge. Those bridges sit OUTSIDE Proximo's perimeter — whatever auth/rebind/CSRF posture exists is
then the bridge's, not Proximo's (upstream FR #25). Here every call lands on ``server.mcp`` itself:
the identical tool registry, trust spine (PLAN-by-default, PROVE, UNDO, the gates), and Proxmox
token scope a stdio client gets. There is no adapter layer at all — not even ``governed`` — so this
face cannot diverge from MCP: it IS MCP. That includes error surfaces: a failing tool returns the
same MCP error text a stdio client sees — the REST face's sanitized ``tool failed: <Type>`` mapping
is a ``governed`` behavior and does not apply here. (``server.mcp`` is this face's sanctioned seam, beside the
two every face gets — see ``tests/test_face_contract.py``: the other faces adapt a foreign protocol
onto the spine through ``governed``; this face serves the spine's native protocol, so the instance
itself is the only possible mouth.)

The face is an optional extra ([mcp-http], which also pins the SDK floor for the streamable-HTTP
API); the MCP core keeps zero extra deps. Fail-closed perimeter shared with A2A + HTTP — the ONE
``webguard.guard_middleware`` stack, in contract order: non-localhost binds refuse without a bearer
token, constant-time bearer on the ``/mcp`` endpoint (liveness stays open), a Host/DNS-rebind
allowlist, and the cross-origin (CSRF) guard on POST. The SDK ships its own DNS-rebind protection
(newer SDKs default it ON with a fixed loopback-only allowlist) — it is explicitly DISABLED here in
favor of the one authoritative webguard perimeter, so the hardening contract cannot drift between
transports; see ``build_app``.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 41243  # A2A is 41241, HTTP/OpenAPI 41242; the MCP-HTTP face sits beside them
_TOKEN_FILE_ENV = "PROXIMO_MCP_HTTP_TOKEN_FILE"  # noqa: S105 -- env var NAME, not a secret value
_MCP_PATH = "/mcp"  # the SDK's default streamable-HTTP path, pinned explicitly (the guards match it)

_TRUEISH = frozenset({"1", "true", "yes", "on"})
_FALSISH = frozenset({"0", "false", "no", "off"})


def build_app(url: str | None = None, *, token: str | None = None,
              allowed_hosts: list[str] | None = None,
              stateless: bool = True, json_response: bool = False):
    """Build the Proximo MCP-over-streamable-HTTP ASGI application.

    Args:
        url:   Advertised base URL (default ``http://127.0.0.1:41243/``). Its hostname feeds the
               fail-closed public-bind guard and the default Host allowlist.
        token: Inbound bearer token. When set, every request to ``/mcp`` (POST message, GET SSE
               stream, DELETE session) requires it. When None and *url* advertises a non-localhost
               host, construction is REFUSED (fail-closed). This factory does NOT read the
               environment — ``main`` loads the token and passes it in.
        allowed_hosts: Host allowlist for the DNS-rebind guard (all modes). Defaults to the served
               host + loopback forms. ``["*"]`` only behind a trusted reverse-proxy (warns).
        stateless: Serve in the SDK's stateless mode (no per-session state; each request is
               self-contained). Default TRUE — the maintainer's call on FR #25: multi-client
               behind a proxy is the deployment model this face exists for, and nothing in the
               governed surface needs a session. Pass False for session-stateful serving.
        json_response: Answer POSTs with plain JSON bodies instead of an SSE stream, for clients
               that prefer it.

    NOTE: the returned app carries a lifespan (the SDK's session manager) — it must be served by a
    lifespan-running host (uvicorn does; a bare ``httpx.ASGITransport`` does not).
    """
    from mcp.server.transport_security import TransportSecuritySettings  # noqa: PLC0415
    from starlette.responses import JSONResponse  # noqa: PLC0415
    from starlette.routing import Route  # noqa: PLC0415

    from . import server  # noqa: PLC0415
    from ._mcpcompat import streamable_http_app as compat_streamable_http_app  # noqa: PLC0415
    from .webguard import guard_middleware, require_auth_for_public  # noqa: PLC0415

    if url is None:
        url = f"http://{_DEFAULT_HOST}:{_DEFAULT_PORT}/"

    # Defense-in-depth: refuse a public advertised URL without a token (covers --factory paths).
    require_auth_for_public(urlparse(url).hostname, token, where="advertised URL",
                            face="MCP-HTTP", token_env=_TOKEN_FILE_ENV)

    # ONE authoritative perimeter, not two: newer SDKs default their own DNS-rebind guard ON with
    # a fixed loopback-only, port-suffixed allowlist — which would 421 every legitimate non-default
    # deployment (public bind with token, reverse-proxy Hosts, the operator's PROXIMO_MCP_HTTP_
    # ALLOWED_HOSTS) and cannot express webguard's list (no bare-host match, no "*"). The shared
    # guard_middleware stack below covers both of its checks — TrustedHost validates Host (rebind),
    # the CSRF guard validates Origin + Content-Type — so the SDK layer is disabled rather than fed
    # a second, driftable copy of the allowlist. (Its POST Content-Type check stays on either way.)
    # Per-major wiring (1.x settings mutation + its cached-manager reset / 2.x kwargs) lives in
    # _mcpcompat.streamable_http_app.
    app = compat_streamable_http_app(
        server.mcp, path=_MCP_PATH, stateless=stateless, json_response=json_response,
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
        allowed_hosts=allowed_hosts,
    )
    for cls, args, kwargs in reversed(stack):
        app.add_middleware(cls, *args, **kwargs)
    return app


def main() -> None:
    """``proximo-mcp-http`` entry point — run the MCP-HTTP face with uvicorn (fail-closed)."""
    import uvicorn  # noqa: PLC0415 -- only needed when actually serving

    from .principal import set_serving_face  # noqa: PLC0415
    from .webguard import (  # noqa: PLC0415
        apply_surfaces_or_exit,
        read_face_env,
        require_auth_for_public,
        url_authority,
    )

    # Which door this process serves — set before anything else so every ledger entry from this
    # process (incl. the session entries below) carries face="mcp-http", never the "stdio"
    # default. This face is network-exposed; inheriting the local-channel tag would make the
    # tamper-evident log misstate the access path of every remote request.
    set_serving_face("mcp-http")
    apply_surfaces_or_exit("proximo-mcp-http")
    host, port, token, allowed_hosts = read_face_env("MCP_HTTP", default_port=_DEFAULT_PORT)

    # FAIL-CLOSED: a public bind with no token never starts.
    require_auth_for_public(host, token, where="bind host", face="MCP-HTTP",
                            token_env=_TOKEN_FILE_ENV)

    # Stateless is the DEFAULT (FR #25 maintainer decision) — opt out with
    # PROXIMO_MCP_HTTP_STATELESS=0/false/no/off for session-stateful serving.
    stateless = os.environ.get("PROXIMO_MCP_HTTP_STATELESS", "").strip().lower() not in _FALSISH
    json_response = os.environ.get("PROXIMO_MCP_HTTP_JSON", "").strip().lower() in _TRUEISH

    app = build_app(f"http://{url_authority(host)}:{port}/", token=token,
                    allowed_hosts=allowed_hosts, stateless=stateless, json_response=json_response)
    # Arrival/departure PROVE entries — mirrors the HTTP and A2A faces exactly; a no-op unless
    # the operator configured the principal feature (PROXIMO_PRINCIPAL / PROXIMO_CALLER_KEYS_DIR),
    # so byte-compat for every deployment that hasn't opted in.
    from . import server  # noqa: PLC0415

    server._record_session("session_start")
    server._reach_grant_check()
    try:
        uvicorn.run(app, host=host, port=port)
    finally:
        server._record_session("session_end")
