"""Build the A2A AgentCard for Proximo.

This module provides a single factory function, ``build_agent_card``, that
assembles the machine-readable capability advertisement for Proximo's A2A face.
It maps the FULL governed tool surface (the same list an MCP client sees) 1-to-1
onto ``AgentSkill`` entries and exposes a single JSON-RPC 2.0 interface at the
caller-supplied URL — a transport over the governed core, not a curated slice.

Security note: auth is ENFORCED at the server layer (``app.py``) — a non-localhost bind is refused
without a token, and when a token is set the JSON-RPC control endpoint requires ``Authorization:
Bearer`` (plus Host-header validation as a DNS-rebind guard). When built with ``secured=True`` the
card DECLARES the bearer scheme (``security_schemes`` + a ``security_requirements`` entry) so A2A
clients self-configure from discovery rather than learning auth only from a 401. The card stays
readable so clients can fetch it before authenticating.
"""

from __future__ import annotations

import importlib.metadata
from typing import Any

from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    SecurityRequirement,
)
from a2a.utils.constants import PROTOCOL_VERSION_CURRENT, TransportProtocol

from proximo import __version__ as _FALLBACK_VERSION

from ..governed import list_governed_sync
from .signing import OperatorKey, sign_card


def build_agent_card(
    rpc_url: str,
    version: str | None = None,
    *,
    secured: bool = False,
    signing_key: OperatorKey | None = None,
    jwks_url: str | None = None,
    tools: list[Any] | None = None,
) -> AgentCard:
    """Build the Proximo AgentCard for a given JSON-RPC endpoint URL.

    Args:
        rpc_url:  The fully-qualified URL at which the A2A JSON-RPC endpoint is
                  served (e.g. ``http://localhost:8080/``).  Embedded in the card's
                  ``supported_interfaces`` so A2A clients know where to send requests.
        version:  Override the package version string.  Only used if
                  ``importlib.metadata`` cannot find the installed package.
        tools:    The governed tool surface to advertise as skills. Defaults to a
                  snapshot of ``list_governed()`` (the same set an MCP client sees).

    Returns:
        A fully populated ``AgentCard``.
    """
    try:
        pkg_version = importlib.metadata.version("proximo")
    except importlib.metadata.PackageNotFoundError:
        pkg_version = version or _FALLBACK_VERSION

    if tools is None:
        tools = list_governed_sync()  # snapshot the governed surface (nest-safe, no event loop)

    # One AgentSkill per governed tool — the full surface, discoverable. Tags carry the plane
    # prefix (pve/pbs/pmg/pdm/ct/audit) so a peer can filter without a naming convention.
    skills = [
        AgentSkill(
            id=t.name,
            name=t.name,
            description=t.description or "",
            tags=[t.name.split("_", 1)[0]],
        )
        for t in tools
    ]

    interface = AgentInterface(
        url=rpc_url,
        protocol_binding=TransportProtocol.JSONRPC,
        protocol_version=PROTOCOL_VERSION_CURRENT,
    )

    card = AgentCard(
        name="Proximo",
        description=(
            "The ethical Proxmox operator agent — one governed core, three faces (MCP, A2A, API). "
            "Every mutation is planned, audited, and reversible by construction."
        ),
        version=pkg_version,
        capabilities=AgentCapabilities(streaming=False, push_notifications=False),
        supported_interfaces=[interface],
        default_input_modes=["application/json", "text/plain"],
        default_output_modes=["application/json", "text/plain"],
        skills=skills,
    )

    if secured:
        # Declare the bearer scheme the server enforces (app.py), so A2A clients can self-configure
        # from discovery instead of learning it only from a 401. Scopeless requirement.
        card.security_schemes["bearerAuth"].http_auth_security_scheme.scheme = "bearer"
        req = SecurityRequirement()
        _ = req.schemes["bearerAuth"]  # auto-creates an empty StringList (no scopes)
        card.security_requirements.append(req)

    if signing_key is not None:
        # SIGNET: press the operator's ES256 seal onto the card (jku → the served JWKS).
        sign_card(card, signing_key, jku=jwks_url)

    return card
