"""The core door as an Agent2Agent participant: the six tools as the card's skills, one JSON-RPC
endpoint, for the agents that call other agents over A2A and not MCP.

    PROXIMO_A2A_HOST=0.0.0.0 PROXIMO_A2A_TOKEN_FILE=/etc/proximo/door.token proximo-a2a

One perimeter, not two: the app is `proximo.core.perimeter.a2a.app.build_app` handed the core's dispatch
(`proximo.core.doors.dispatch.Core`, the six tools of `doors/mcp.py`) and the core's row writer, so
the Host guard, the cross-origin guard, the bearer check, the badge camera, the agent card, the
operator's signature on it (`PROXIMO_A2A_SIGNING_KEY_FILE`, served at `/.well-known/jwks.json`) and
the message convention (`{"tool": "<name>", "params": {...}}` in a DataPart) are the bytes the 0.44
A2A face runs, with the core's engine behind them and the 0.44 server never loaded. Same env names
and port as that face, and the same face name on the ledger, so a host configured for it serves
this door with the same files and ports; what is not carried (`PROXIMO_SURFACES`, refused; the
reach-grant check; session rows always written) is said in `doors/network.py`. A public bind with no
token never starts. A refused mutation fails the task
with the spine's own sentence; a message with no tool, or an unknown one, fails the task and leaves
an `a2a_rejected` row.
"""
from __future__ import annotations

from typing import Any

from proximo.core.doors.dispatch import Core
from proximo.core.doors.network import main_of, recorder
from proximo.core.errors import ProximoError

FACE = "a2a"
PROG = "proximo-a2a"
_PORT = 41241
_TOKEN_ENV = "PROXIMO_A2A_TOKEN_FILE"  # noqa: S105 -- env var NAME, not a secret value
_HELP = "the A2A door needs the [a2a] extra: pip install 'proximo-proxmox[a2a]'"


def build_app(url: str | None = None, *, token: str | None = None,
              allowed_hosts: list[str] | None = None, signing_key: Any = None) -> Any:
    """The ASGI app: the core's six tools behind the shared A2A perimeter. `signing_key` is an
    `a2a.signing.OperatorKey` (the card is served unsigned without one)."""
    try:
        from proximo.core.perimeter.a2a.app import build_app as perimeter
    except ImportError as e:
        raise ProximoError(_HELP) from e
    return perimeter(url, token=token, allowed_hosts=allowed_hosts, signing_key=signing_key,
                     dispatch=Core(), record=recorder(PROG))


def _build(url: str, token: str | None, allowed: list[str] | None) -> Any:
    from proximo.core.perimeter.a2a.app import _load_signing_key  # the 0.44 loader: same env, same refusals
    return build_app(url, token=token, allowed_hosts=allowed, signing_key=_load_signing_key())


def main(argv: list[str] | None = None) -> int:
    return main_of(PROG, FACE, prefix="A2A", default_port=_PORT, token_env=_TOKEN_ENV, help_=_HELP,
                   doc=__doc__ or "", extra_env=", PROXIMO_A2A_SIGNING_KEY_FILE", argv=argv,
                   build=_build)


if __name__ == "__main__":
    raise SystemExit(main())
