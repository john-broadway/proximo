"""Shared fail-closed perimeter for Proximo's network faces (A2A, HTTP, MCP-over-streamable-HTTP).

The faces are network CONTROL PLANES over Proxmox, so they share one hardening contract —
extracted here (starlette-only, no a2a-sdk import) so it cannot drift between transports,
for the same reason ``governed.call_governed`` is shared:

  - Only explicit loopback binds are private; anything else — including bind-all — is PUBLIC
    and must refuse to start without a bearer token (a hard error, never a warning).
  - Tokens are loaded run-but-not-read, by file path from an env var; a configured-but-broken
    token file fails LOUD, never silently unauthenticated.
  - Bearer comparison is constant-time; protected paths are chosen per-face (A2A guards its
    RPC endpoint, HTTP guards /tools/*, MCP-HTTP guards /mcp) while discovery stays readable
    pre-auth.
"""

from __future__ import annotations

import hmac
import os
import sys
import warnings
from collections.abc import Callable
from urllib.parse import urlparse

from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse

from ._secretfile import refuse_exposed_secret

LOCALHOST_ADDRS = frozenset({"127.0.0.1", "localhost", "::1"})

# A cross-origin browser request that carries these Sec-Fetch-Site values is a forgery attempt
# against our loopback control plane — modern browsers set the header; non-browser clients (curl,
# the a2a-sdk, the OpenAPI client) never send it, so they are unaffected. "same-origin"/"none"
# (a legit same-origin XHR / a user-typed URL) are allowed.
_CROSS_ORIGIN_FETCH_SITES = frozenset({"cross-site", "same-site"})


def _origin_is_cross(origin: str, host: str | None) -> bool:
    """True when an ``Origin`` header is present and does NOT match the server's own host.

    Defense-in-depth beside the Sec-Fetch-Site check: a browser that omits Fetch-Metadata still
    sends ``Origin`` on a cross-origin POST — including a zero-body one that carries no Content-Type
    to catch. A non-browser client (curl, the a2a-sdk, the OpenAPI client) omits Origin entirely, so
    it is never reached here. ``Origin: null`` (sandboxed iframe / file://) is treated as cross.
    """
    parts = urlparse(origin)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return True  # "null", protocol-relative, or otherwise malformed → fail closed
    return parts.netloc.lower() != (host or "").strip().lower()

# Max request-body size for a skill/RPC call. Params are tiny; anything larger is a mistake or a
# memory-pressure probe. A cheap DoS floor (finding #4), enforced before the body is buffered.
MAX_BODY_BYTES = 128 * 1024


def is_public(host: str | None) -> bool:
    """True when *host* is reachable off-box — anything that is NOT an explicit localhost address.

    An empty/None/whitespace host means "bind all interfaces" (uvicorn/socket bind ``0.0.0.0``),
    which is the MOST reachable, so it is treated as PUBLIC (→ requires a token). Only the
    explicit loopback forms are private. (Regression guard: ``bool("")`` is False — a naive
    truthiness check once let ``HOST=""`` slip the fail-closed gate unauthenticated.)
    """
    return (host or "").strip() not in LOCALHOST_ADDRS


def default_allowed_hosts(url: str) -> list[str]:
    """Host allowlist for the DNS-rebind guard: the served host + loopback forms (deduped)."""
    hosts = set(LOCALHOST_ADDRS)
    host = urlparse(url).hostname
    if host:
        hosts.add(host)
    return sorted(hosts)


def load_token_file(env_var: str) -> str | None:
    """Load an inbound bearer token from the file named by *env_var* (run-but-not-read by path).

    Returns None when the env var is unset. Fails LOUD (RuntimeError) if the var is set but the
    file is missing/unreadable or empty — never silently run unauthenticated when auth was intended.
    """
    path = os.environ.get(env_var)
    if not path:
        return None
    refuse_exposed_secret(path, f"{env_var} bearer-token file")
    try:
        token = open(path, encoding="utf-8").read().strip()  # noqa: SIM115
    except OSError as e:
        raise RuntimeError(f"{env_var}={path!r} could not be read: {e}") from e
    if not token:
        raise RuntimeError(f"{env_var}={path!r} is empty — refusing to serve with a blank token.")
    return token


def require_auth_for_public(host: str | None, token: str | None, *, where: str,
                            face: str, token_env: str) -> None:
    """FAIL-CLOSED guard: refuse a non-localhost control plane that has no auth token.

    Raises ValueError (not a warning) so a public bind without a token cannot start. Call it
    from BOTH the bind path (``main``) and the application factory (on the advertised URL) so
    it can't be sidestepped via the uvicorn ``--factory`` path (defense-in-depth).
    """
    if is_public(host) and not token:
        raise ValueError(
            f"Refusing to expose the Proximo {face} control plane: {where} is {host!r} "
            f"(non-localhost) with no auth token. This face drives Proxmox — set {token_env} "
            "to a file containing a bearer token, or bind localhost only."
        )


def read_face_env(prefix: str, *, default_port: int,
                  default_host: str = "127.0.0.1") -> tuple[str, int, str | None, list[str] | None]:
    """Read a network face's bind/auth configuration from its ``PROXIMO_<prefix>_*`` env vars.

    Returns ``(host, port, token, allowed_hosts)`` from ``_HOST`` / ``_PORT`` / ``_TOKEN_FILE``
    (run-but-not-read, via :func:`load_token_file`) / ``_ALLOWED_HOSTS`` (comma-separated; empty →
    None → the face defaults to :func:`default_allowed_hosts`). One reader for every face so a new
    transport can't invent its own parsing quirks.
    """
    host = os.environ.get(f"PROXIMO_{prefix}_HOST", default_host)
    port = int(os.environ.get(f"PROXIMO_{prefix}_PORT", str(default_port)))
    token = load_token_file(f"PROXIMO_{prefix}_TOKEN_FILE")
    allowed = os.environ.get(f"PROXIMO_{prefix}_ALLOWED_HOSTS", "")
    allowed_hosts = [h.strip() for h in allowed.split(",") if h.strip()] or None
    return host, port, token, allowed_hosts


def url_authority(host: str) -> str:
    """RFC-3986 authority form of *host* — brackets a bare IPv6 address.

    Without brackets, ``urlparse("http://::1:41241/").hostname`` returns None, which the factories'
    public-bind guard misreads as bind-all (public) and refuses startup even for loopback ``::1``
    with no token. Skips double-bracketing when the caller already passed a bracketed host.
    """
    return f"[{host}]" if (":" in host and not host.startswith("[")) else host


def apply_surfaces_or_exit(face_cmd: str) -> None:
    """Scope the live tool registry to ``PROXIMO_SURFACES`` before a face serves — or refuse startup.

    Every network face reads the same global MCP registry the stdio server does; a face that skips
    this silently ignores the operator's surface config. A bad surface name exits 1 with a
    face-prefixed one-liner (refuse startup, never serve the wrong set — same contract as stdio).
    """
    from . import door  # noqa: PLC0415 -- late import; webguard stays server-independent

    try:
        door._apply_surfaces()
    except ValueError as e:
        print(f"{face_cmd}: {e}", file=sys.stderr)
        raise SystemExit(1) from None


def guard_middleware(url: str, *, face: str, token: str | None, protect: Callable[[str], bool],
                     unauthorized_body: dict, allowed_hosts: list[str] | None = None) -> list[Middleware]:
    """The ONE perimeter stack every network face mounts — the order is the contract.

    Outermost → innermost: ``TrustedHostMiddleware`` (DNS-rebind guard, ALWAYS on — a bad Host is
    refused before anything else runs) → :class:`CrossOriginGuardMiddleware` (loopback-CSRF defense,
    ALWAYS on) → :class:`BearerAuthMiddleware` (only when *token* is set; discovery paths stay open
    via *protect*) → :class:`PrincipalMiddleware` (only when ``PROXIMO_CALLER_KEYS_DIR`` is set;
    same *protect*). A face chooses only *protect* (which paths are its control endpoints) and the
    per-protocol 401 body — everything else is shared so the faces cannot drift.

    ``allowed_hosts=["*"]`` disables the Host guard and warns LOUDLY — legitimate only behind a
    trusted reverse-proxy that validates Host.
    """
    hosts = allowed_hosts or default_allowed_hosts(url)
    if "*" in hosts:
        warnings.warn(
            f"PROXIMO {face} host allowlist contains '*' — DNS-rebind/Host protection is DISABLED; "
            "any Host header is accepted. Only safe behind a trusted reverse-proxy that validates "
            "Host.", stacklevel=2,
        )
    middleware = [
        Middleware(TrustedHostMiddleware, allowed_hosts=hosts),
        Middleware(CrossOriginGuardMiddleware, protect=protect),
    ]
    if token:
        middleware.append(Middleware(
            BearerAuthMiddleware, token=token, protect=protect,
            unauthorized_body=unauthorized_body,
        ))
    pins_dir = os.environ.get("PROXIMO_CALLER_KEYS_DIR")
    if pins_dir:
        from .principal import load_pins  # noqa: PLC0415 -- lazy; needs the [http]/[a2a] extra
        pins = load_pins(pins_dir)  # fail-LOUD here: a bad dir must refuse startup
        middleware.append(Middleware(
            PrincipalMiddleware, pins=pins, pins_dir=pins_dir, protect=protect,
            face=face.strip().lower(), unauthorized_body=unauthorized_body,
        ))
    return middleware


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Require ``Authorization: Bearer <token>`` on the paths *protect* selects.

    Discovery routes (agent card / openapi.json / healthz) stay open so clients can learn how
    to authenticate before authenticating. The 401 body shape is per-face (*unauthorized_body*):
    JSON-RPC error for A2A, a plain error object for HTTP.
    """

    def __init__(self, app, *, token: str, protect: Callable[[str], bool],
                 unauthorized_body: dict) -> None:
        super().__init__(app)
        self._token = token
        self._protect = protect
        self._body = unauthorized_body

    async def dispatch(self, request, call_next):
        if self._protect(request.url.path):
            scheme, _, presented = request.headers.get("authorization", "").partition(" ")
            if scheme.lower() != "bearer" or not presented or not hmac.compare_digest(presented, self._token):
                return JSONResponse(self._body, status_code=401,
                                    headers={"WWW-Authenticate": "Bearer"})
        return await call_next(request)


class CrossOriginGuardMiddleware(BaseHTTPMiddleware):
    """Refuse browser cross-origin POSTs to a mutating endpoint — localhost-CSRF defense.

    Proximo's network faces bind loopback with no token by default (dev mode). A loopback HTTP
    server is reachable by any web page the operator loads: a cross-origin page can auto-submit a
    form or ``fetch`` with a CORS-*safelisted* Content-Type (text/plain, form-urlencoded,
    multipart) — which skips the CORS preflight — and drive a real mutation with no credential and
    no response-read (so the same-origin policy never blocks it). The bearer guard doesn't stop it
    in no-token mode, and the Host allowlist doesn't (the page hits 127.0.0.1 with the correct
    Host). Fail-closed checks on protected POSTs close it:

      1. ``Sec-Fetch-Site: cross-site``/``same-site`` → refuse (403). Modern browsers set this on
         the forged request; non-browser API clients never send it.
      1b. An ``Origin`` header that doesn't match the server's own host → refuse (403). A browser
         that omits Fetch-Metadata still sends Origin on a cross-origin POST — including a zero-body
         one that carries no Content-Type to catch (check 2 below). Non-browser clients omit Origin.
      2. A body-carrying request whose Content-Type is not ``application/json`` → refuse (415). A
         browser CANNOT set ``application/json`` cross-origin without triggering a preflight, and
         this app serves no CORS headers, so the preflight fails and the real request is never
         sent. Every legit client (the OpenAPI-generated client, curl with ``-H``, the a2a-sdk)
         sends ``application/json``. Empty-body requests (no Content-Type) are unaffected — they
         can't carry a mutation's params, so they're not a forgery vector.

    Also enforces a cheap body-size cap (413) before the body is buffered. GET discovery routes
    are never touched (only POST is guarded; reads can't mutate).
    """

    def __init__(self, app, *, protect: Callable[[str], bool]) -> None:
        super().__init__(app)
        self._protect = protect

    async def dispatch(self, request, call_next):
        if request.method == "POST" and self._protect(request.url.path):
            if request.headers.get("sec-fetch-site", "").lower() in _CROSS_ORIGIN_FETCH_SITES:
                return JSONResponse({"error": "cross-origin request refused"}, status_code=403)

            origin = request.headers.get("origin")
            if origin is not None and _origin_is_cross(origin, request.headers.get("host")):
                return JSONResponse({"error": "cross-origin request refused"}, status_code=403)

            cl = request.headers.get("content-length")
            has_body = (cl not in (None, "0")) or "transfer-encoding" in request.headers
            if has_body:
                media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
                if media_type != "application/json":
                    return JSONResponse(
                        {"error": "Content-Type must be application/json"}, status_code=415)
                # DoS floor: the body-size cap can only be enforced pre-buffer from a declared
                # Content-Length. A chunked body (Transfer-Encoding, no Content-Length) would
                # otherwise skip this check and buffer unbounded in the downstream handler, so
                # require a usable declared length for any body.
                if cl is None or not cl.isdigit():
                    return JSONResponse(
                        {"error": "Content-Length required (chunked request bodies are not accepted)"},
                        status_code=411)
                if int(cl) > MAX_BODY_BYTES:
                    return JSONResponse({"error": "request body too large"}, status_code=413)
        return await call_next(request)


_REFUSAL_WINDOW_S = 60.0
_refusal_state = {"window_start": 0.0, "folded": 0}     # module-level, process-wide by design


def _audit_caller_event(action: str, *, face: str, detail: dict) -> None:
    """PROVE entries from the perimeter — late server import (webguard stays server-independent)."""
    from . import server  # noqa: PLC0415 -- late import; webguard stays server-independent
    from .principal import ledger_principal  # noqa: PLC0415
    from .targets import ledger_remote  # noqa: PLC0415
    server._ledger().record(action, target=f"face/{face}", mutation=False,
                            outcome=detail.pop("outcome", "ok"), detail=detail,
                            principal=ledger_principal(), remote=ledger_remote())


def _audit_refusal_bounded(face: str) -> None:
    """≤1 refusal entry per window PROCESS-WIDE; the rest fold into a count. Never per-source —
    claimed subs / forwarded IPs are attacker-controlled, a per-source map is itself a target."""
    import time  # noqa: PLC0415
    now = time.monotonic()
    if now - _refusal_state["window_start"] >= _REFUSAL_WINDOW_S:
        # New window: read the PRIOR window's folded count before resetting, so the entry we're
        # about to record carries how much the last window suppressed.
        folded = _refusal_state["folded"]
        _refusal_state["window_start"] = now
        _refusal_state["folded"] = 0
        _audit_caller_event("caller_refused", face=face,
                            detail={"outcome": "blocked:unverified_caller",
                                    "folded_prior_window": folded})
    else:
        _refusal_state["folded"] += 1


class PrincipalMiddleware(BaseHTTPMiddleware):
    """The camera at the door: verify a ``Proximo-Principal`` ES256 badge against operator pins.

    Present only when ``PROXIMO_CALLER_KEYS_DIR`` is configured. Protected paths REQUIRE a valid
    badge (fail-closed); discovery stays open (same *protect* as bearer). Identity, not authority.
    """

    def __init__(self, app, *, pins: dict, protect: Callable[[str], bool],
                 face: str, unauthorized_body: dict, pins_dir: str | None = None) -> None:
        super().__init__(app)
        self._pins = pins
        self._pins_dir = pins_dir
        self._protect = protect
        self._face = face
        self._body = unauthorized_body
        self._seen: set[str] = set()

    async def dispatch(self, request, call_next):
        if not self._protect(request.url.path):
            return await call_next(request)
        from .principal import (  # noqa: PLC0415
            BadgeError,
            load_pins_live,
            reset_active_caller,
            set_active_caller,
            verify_badge,
        )
        badge = request.headers.get("proximo-principal", "")
        # Re-resolve the pin store per protected request (stat-gated, reloads only on change) so
        # deleting a pin file revokes that caller HERE, on the running process, exactly as
        # SECURITY.md promises. A store that has become unreadable refuses the request rather
        # than falling back to the last-known-good pins: zero trust by default.
        try:
            pins = load_pins_live(self._pins_dir) if self._pins_dir else self._pins
        except RuntimeError:
            _audit_refusal_bounded(self._face)
            return JSONResponse(self._body, status_code=401,
                                headers={"WWW-Authenticate": "Proximo-Principal"})
        try:
            sub = verify_badge(badge, pins)
        except BadgeError:
            _audit_refusal_bounded(self._face)
            return JSONResponse(self._body, status_code=401,
                                headers={"WWW-Authenticate": "Proximo-Principal"})
        token = set_active_caller(sub)
        try:
            if sub not in self._seen:
                self._seen.add(sub)
                _audit_caller_event("caller_arrived", face=self._face, detail={"caller": sub})
            return await call_next(request)
        finally:
            reset_active_caller(token)
