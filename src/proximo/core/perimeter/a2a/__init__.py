"""Proximo's A2A (Agent2Agent) face — a transport on the governed core.

Proximo is a governed client; MCP over stdio is its first door (``proximo.core.doors.mcp``). This package
adds an OPTIONAL A2A face so Proximo can also be a first-class Agent2Agent participant — "the Proxmox
operator agent" other agents can call.

Design (one core, interchangeable transports):
    The A2A face exposes the FULL governed tool surface and routes every call through the
    caller's ``dispatch`` (0.44: ``proximo.governed.Dispatch``; the core door: its own), the same
    spine path (PLAN-by-default, PROVE, UNDO, the gates, the token scope) an MCP client takes. It
    reimplements no management or trust logic and curates no per-transport slice: a transport
    carries the surface, it does not curate it.

Layering (import-safe):
    - ``card``     — builds the ``AgentCard`` from the governed surface (needs a2a-sdk).
    - ``executor`` — the ``AgentExecutor`` that routes a call through the governed core (needs a2a-sdk).
    - ``app``      — the Starlette/JSON-RPC server + ``proximo-a2a`` entrypoint (needs a2a-sdk + uvicorn).

The a2a-sdk is an OPTIONAL dependency (``pip install 'proximo-proxmox[a2a]'``); the shared perimeter
(``proximo.core.perimeter.guard``) is dependency-light so the contract is always importable, and the dispatch
is the caller's to hand in.
"""
