"""The core door over the network: the six tools, served where the credentials are.

THIS IS THE DOOR THE TOPOLOGY NEEDS. The stdio door runs where the agent runs, so the token it
serves sits on the agent's box and every file-backed pillar (consent grants, the contain trip,
the rate reservations, the arm pair) is a speed bump the agent could write
around. Serve the same six tools from a host the agent cannot reach into and the agent holds an
endpoint and a bearer; the Proxmox token, the arm pair and the grants stay behind the door.

    PROXIMO_MCP_HTTP_HOST=0.0.0.0 PROXIMO_MCP_HTTP_TOKEN_FILE=/etc/proximo/door.token \\
        proximo-mcp-http

One perimeter, not two: the app is `proximo.core.perimeter.mcp_http.build_app` handed the core's server, so the
Host guard, the cross-origin guard, the bearer check and the caller badge are the bytes every
network face mounts. Same env names and port as the 0.44 MCP-HTTP face, and the same face name on
the ledger, so a host configured for that face serves this one with the same files
and ports (what is not carried is said in `doors/network.py`). A public bind with no
token never starts. Every row this process writes says `face: mcp-http`, and the name tag or the
verified badge says who asked. The REST and A2A doors (`doors/http.py`, `doors/a2a.py`) are this
door's shape over their own perimeters; `doors/network.py` is what the three share.
"""
from __future__ import annotations

import os
from typing import Any

from proximo.core.doors.network import main_of, recorder
from proximo.core.errors import ProximoError

FACE = "mcp-http"
PROG = "proximo-mcp-http"
_PORT = 41243
_TOKEN_ENV = "PROXIMO_MCP_HTTP_TOKEN_FILE"  # noqa: S105 -- env var NAME, not a secret value
_HELP = "the network door needs the [mcp-http] extra: pip install 'proximo-proxmox[mcp-http]'"


def build_app(url: str | None = None, *, token: str | None = None,
              allowed_hosts: list[str] | None = None, stateless: bool = True,
              json_response: bool = False) -> Any:
    """The ASGI app: the core's six tools behind the shared perimeter. Needs a lifespan host."""
    from proximo.core.doors.mcp import build_server
    try:
        from proximo.core.perimeter.mcp_http import build_app as perimeter
    except ImportError as e:
        raise ProximoError(_HELP) from e
    return perimeter(url, token=token, allowed_hosts=allowed_hosts, stateless=stateless,
                     json_response=json_response, instance=build_server(), record=recorder(PROG))


def _flag(name: str) -> str:
    return os.environ.get(f"PROXIMO_MCP_HTTP_{name}", "").strip().lower()


def _build(url: str, token: str | None, allowed: list[str] | None) -> Any:
    return build_app(url, token=token, allowed_hosts=allowed,
                     stateless=_flag("STATELESS") not in {"0", "false", "no", "off"},
                     json_response=_flag("JSON") in {"1", "true", "yes", "on"})


def main(argv: list[str] | None = None) -> int:
    return main_of(PROG, FACE, prefix="MCP_HTTP", default_port=_PORT, token_env=_TOKEN_ENV,
                   help_=_HELP, doc=__doc__ or "", extra_env=", _STATELESS, _JSON", argv=argv,
                   build=_build)


if __name__ == "__main__":
    raise SystemExit(main())
