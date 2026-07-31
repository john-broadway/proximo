"""Proximo A2A server application factory + ``proximo-a2a`` entrypoint.

Wires the A2A SDK's request-handler stack into a Starlette ASGI app. The executor
(``ProximoAgentExecutor``) is imported from the sibling ``.executor`` module; this module owns
the plumbing (routes, card, handler, auth) and the ``main`` entry point.

Security model (fail-closed, like the rest of Proximo):
  - Default bind is loopback (``127.0.0.1``) — not reachable off-box.
  - The A2A face is a network CONTROL PLANE over Proxmox. Binding it to any non-localhost address
    is REFUSED unless an auth token is configured (``PROXIMO_A2A_TOKEN_FILE``) — a hard error, not a
    warning. "Exposed by accident" is structurally impossible.
  - When a token is configured, the JSON-RPC control endpoint requires ``Authorization: Bearer
    <token>`` (constant-time compared). The agent card stays readable so A2A clients can discover
    how to authenticate.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes.agent_card_routes import create_agent_card_routes
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from .._secretfile import refuse_exposed_secret
from ..webguard import guard_middleware, require_auth_for_public
from .card import build_agent_card
from .executor import ProximoAgentExecutor
from .signing import OperatorKey, jwks, load_operator_key

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 41241
_TOKEN_FILE_ENV = "PROXIMO_A2A_TOKEN_FILE"  # noqa: S105 -- env var NAME, not a secret value
_SIGNING_KEY_ENV = "PROXIMO_A2A_SIGNING_KEY_FILE"  # noqa: S105 -- env var NAME, not a secret value
_JWKS_PATH = "/.well-known/jwks.json"

# The perimeter primitives (is_public / default_allowed_hosts / token loading / the bearer
# middleware / the public-bind refusal) live in ``proximo.webguard`` — shared with the HTTP
# face so the fail-closed contract cannot drift between transports.


def _load_signing_key() -> OperatorKey | None:
    """Load the operator's A2A signing key from ``PROXIMO_A2A_SIGNING_KEY_FILE`` (by path).

    Returns None when the env var is unset (the card is served unsigned — opt-in). Fails LOUD
    (RuntimeError) if the var is set but the key is missing/unreadable or not an EC P-256 key —
    never silently serve unsigned when signing was intended.
    """
    path = os.environ.get(_SIGNING_KEY_ENV)
    if not path:
        return None
    refuse_exposed_secret(path, f"{_SIGNING_KEY_ENV} signing-key file")
    try:
        return load_operator_key(path)
    except (OSError, ValueError) as e:
        raise RuntimeError(f"{_SIGNING_KEY_ENV}={path!r} could not be loaded: {e}") from e


def _jwks_url(rpc_url: str) -> str:
    """Absolute URL of the JWKS endpoint (root ``/.well-known/jwks.json``) for the signature's jku."""
    p = urlparse(rpc_url)
    return f"{p.scheme}://{p.netloc}{_JWKS_PATH}"


def _require_auth_for_public(host: str | None, token: str | None, *, where: str) -> None:
    """FAIL-CLOSED guard: refuse a non-localhost A2A control plane that has no auth token.

    Delegates to the shared webguard refusal (raises ValueError, never a warning). Fires from BOTH
    the bind path (``main``) and the application factory (``build_app``, on the advertised URL) so it
    can't be sidestepped via the uvicorn ``--factory`` path (defense-in-depth).
    """
    require_auth_for_public(host, token, where=where, face="A2A", token_env=_TOKEN_FILE_ENV)


def build_app(rpc_url: str | None = None, *, token: str | None = None,
              allowed_hosts: list[str] | None = None,
              signing_key: OperatorKey | None = None) -> Starlette:
    """Build the Proximo A2A ASGI application.

    Args:
        rpc_url: Fully-qualified JSON-RPC endpoint URL (default ``http://127.0.0.1:41241/``). Used
                 as the card's interface URL and (path-only) as the Starlette route path.
        token:   Inbound bearer token. When set, the JSON-RPC endpoint requires it, the card declares
                 the bearer scheme, and the bearer middleware is added to the stack. When None and
                 ``rpc_url`` advertises a non-localhost host, construction is REFUSED (fail-closed).
                 NOTE: this factory does NOT read the environment — the ``proximo-a2a`` entrypoint
                 (``main``) loads the token and passes it in. Embedders must pass ``token=`` explicitly.
        allowed_hosts: Host allowlist for the DNS-rebind guard (applied in ALL modes, with or without a
                 token). Defaults to the served host + loopback forms. Pass ``["*"]`` only behind a
                 trusted reverse-proxy that validates Host (emits a loud warning when ``"*"`` present).
    """
    if rpc_url is None:
        rpc_url = f"http://{_DEFAULT_HOST}:{_DEFAULT_PORT}/"

    # Defense-in-depth: refuse a public advertised URL without a token (covers the --factory path).
    _require_auth_for_public(urlparse(rpc_url).hostname, token, where="advertised URL")

    rpc_path = urlparse(rpc_url).path or "/"
    jwks_url = _jwks_url(rpc_url) if signing_key is not None else None
    card = build_agent_card(rpc_url, secured=bool(token), signing_key=signing_key, jwks_url=jwks_url)

    handler = DefaultRequestHandler(
        agent_executor=ProximoAgentExecutor(),
        task_store=InMemoryTaskStore(),
        agent_card=card,
    )
    routes = (
        create_jsonrpc_routes(request_handler=handler, rpc_url=rpc_path)
        + create_agent_card_routes(agent_card=card)
    )
    if signing_key is not None:
        # Publish the operator's public key so A2A clients can verify the seal (jku target).
        # Stays OUTSIDE the bearer guard — like the card, discovery must be readable pre-auth.
        async def _serve_jwks(_request):
            return JSONResponse(jwks(signing_key))

        routes = [*routes, Route(_JWKS_PATH, _serve_jwks, methods=["GET"])]

    # The shared perimeter stack (TrustedHost → CrossOriginGuard → Bearer-with-token) — one
    # contract for every face. This face protects the exact RPC path only; the agent-card /
    # well-known / jwks discovery routes stay open so A2A clients can read the card (and its
    # declared auth) before authenticating.
    rpc = rpc_path.rstrip("/")
    middleware = guard_middleware(
        rpc_url, face="A2A", token=token,
        protect=lambda path: path.rstrip("/") == rpc,
        unauthorized_body={"jsonrpc": "2.0", "id": None,
                           "error": {"code": -32001, "message": "unauthorized"}},
        allowed_hosts=allowed_hosts,
    )
    return Starlette(routes=routes, middleware=middleware)


def main() -> None:
    """``proximo-a2a`` entry point — run the A2A server with uvicorn (fail-closed)."""
    import uvicorn  # noqa: PLC0415 -- only needed when actually serving

    from .. import server  # noqa: PLC0415 -- late import; keeps the app-factory path import-light
    from ..principal import set_serving_face  # noqa: PLC0415
    from ..webguard import apply_surfaces_or_exit, read_face_env, url_authority  # noqa: PLC0415

    # Which door this process serves — set before anything else so every ledger entry from this
    # process (incl. the session entries below) carries face="a2a", never the "stdio" default.
    set_serving_face("a2a")
    apply_surfaces_or_exit("proximo-a2a")
    host, port, token, allowed_hosts = read_face_env("A2A", default_port=_DEFAULT_PORT)

    # FAIL-CLOSED: a public bind with no token never starts.
    _require_auth_for_public(host, token, where="bind host")

    app = build_app(
        f"http://{url_authority(host)}:{port}/",
        token=token,
        allowed_hosts=allowed_hosts,
        signing_key=_load_signing_key(),
    )
    # Arrival/departure PROVE entries — mirrors the stdio entrypoint's pattern exactly (Task 3.4);
    # a no-op unless the operator configured the principal feature (PROXIMO_PRINCIPAL /
    # PROXIMO_CALLER_KEYS_DIR), so byte-compat for every deployment that hasn't opted in.
    server._record_session("session_start")
    try:
        uvicorn.run(app, host=host, port=port)
    finally:
        server._record_session("session_end")
