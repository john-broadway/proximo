"""The core door as plain HTTP: the six tools as `POST /tools/{name}`, discoverable at
`/openapi.json`, for the apps, dashboards and no-code clients that speak REST and not MCP.

    PROXIMO_HTTP_HOST=0.0.0.0 PROXIMO_HTTP_TOKEN_FILE=/etc/proximo/door.token proximo-http

One perimeter, not two: the app is `proximo.core.perimeter.rest.build_app` handed the core's dispatch
(`proximo.core.doors.dispatch.Core`, the six tools of `doors/mcp.py`) and the core's row writer, so
the Host guard, the cross-origin guard, the bearer check, the badge camera, the OpenAPI document and
the 400/404/502 mapping are the bytes the 0.44 REST face runs, with the core's engine behind them
and the 0.44 server never loaded. Same env names and port as that face, and the same face name on
the ledger, so a host configured for it serves this door with the same files and ports; what is not
carried (`PROXIMO_SURFACES`, refused; the reach-grant check; session rows always written) is
said in `doors/network.py`. A public bind with no token
never starts. A refused mutation answers 502 with the spine's own sentence ("not armed", the tier a
mutation lacks, the consent id); a rejected request (unknown tool, malformed body) answers 4xx and
leaves an `http_rejected` row.
"""
from __future__ import annotations

from typing import Any

from proximo.core.doors.dispatch import Core
from proximo.core.doors.network import main_of, recorder
from proximo.core.errors import ProximoError

FACE = "http"
PROG = "proximo-http"
_PORT = 41242
_TOKEN_ENV = "PROXIMO_HTTP_TOKEN_FILE"  # noqa: S105 -- env var NAME, not a secret value
_HELP = "the REST door needs the [http] extra: pip install 'proximo-proxmox[http]'"
DESCRIPTION = (
    "Proximo's governed core over HTTP: six tools that reach every address the planes publish "
    "(find, plan, read, call, and the ledger's entries and verify), the same engine, pillars and "
    "receipts the MCP doors serve. Mutations are PLAN-by-default: without confirm=true you get a "
    "recorded plan, never a change; with it, the call runs only armed AND tiered."
)


def build_app(url: str | None = None, *, token: str | None = None,
              allowed_hosts: list[str] | None = None) -> Any:
    """The ASGI app: the core's six tools behind the shared REST perimeter."""
    try:
        from proximo.core.perimeter.rest import build_app as perimeter
    except ImportError as e:
        raise ProximoError(_HELP) from e
    return perimeter(url, token=token, allowed_hosts=allowed_hosts, dispatch=Core(),
                     record=recorder(PROG), description=DESCRIPTION)


def main(argv: list[str] | None = None) -> int:
    return main_of(PROG, FACE, prefix="HTTP", default_port=_PORT, token_env=_TOKEN_ENV, help_=_HELP,
                   doc=__doc__ or "", extra_env="", argv=argv,
                   build=lambda url, token, allowed: build_app(url, token=token, allowed_hosts=allowed))


if __name__ == "__main__":
    raise SystemExit(main())
