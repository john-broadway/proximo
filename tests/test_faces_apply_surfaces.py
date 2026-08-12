"""All three network faces must scope the tool registry to PROXIMO_SURFACES at startup.

The A2A/HTTP faces read the same global MCP registry the stdio face does. `_apply_surfaces` is what
prunes it per PROXIMO_SURFACES / configured planes — and it was only ever called from the stdio
`server.main()`. A redteam (2026-07-13) found the network entrypoints never called it, so an operator
who set PROXIMO_SURFACES=pve still exposed the full surface (incl. exec/pbs/pmg/pdm) over the network.
These pin that all three faces (HTTP, A2A, MCP-HTTP) call it before serving. (Wiring-level,
via a recorder — actually pruning the global registry here would corrupt other tests; the
pruning logic itself is covered by the surface_keep / _apply_surfaces unit tests.)
"""
from __future__ import annotations

import pytest
import uvicorn

from proximo import door


def test_http_main_applies_surfaces_before_serving(monkeypatch):
    order: list[str] = []
    monkeypatch.setattr(door, "_apply_surfaces", lambda: order.append("scope"))
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: order.append("serve"))
    monkeypatch.delenv("PROXIMO_HTTP_TOKEN_FILE", raising=False)
    monkeypatch.delenv("PROXIMO_HTTP_HOST", raising=False)

    import proximo.httpface as hf
    hf.main()

    assert order == ["scope", "serve"], "surfaces must be applied before the server starts"


def test_a2a_main_applies_surfaces_before_serving(monkeypatch):
    order: list[str] = []
    monkeypatch.setattr(door, "_apply_surfaces", lambda: order.append("scope"))
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: order.append("serve"))
    monkeypatch.delenv("PROXIMO_A2A_TOKEN_FILE", raising=False)
    monkeypatch.delenv("PROXIMO_A2A_HOST", raising=False)
    monkeypatch.delenv("PROXIMO_A2A_SIGNING_KEY_FILE", raising=False)

    import proximo.a2a.app as a2a_app
    a2a_app.main()

    assert order == ["scope", "serve"], "surfaces must be applied before the server starts"


def test_mcphttp_main_applies_surfaces_before_serving(monkeypatch):
    # The third face was applying surfaces all along (mcphttp.main calls apply_surfaces_or_exit)
    # but only http/a2a had their scope-before-serve ORDER pinned — lens finding, 2026-08-11.
    order: list[str] = []
    monkeypatch.setattr(door, "_apply_surfaces", lambda: order.append("scope"))
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: order.append("serve"))
    monkeypatch.delenv("PROXIMO_MCP_HTTP_TOKEN_FILE", raising=False)
    monkeypatch.delenv("PROXIMO_MCP_HTTP_HOST", raising=False)

    import proximo.mcphttp as mcphttp
    mcphttp.main()

    assert order == ["scope", "serve"], "surfaces must be applied before the server starts"


def test_http_main_surface_error_exits_nonzero(monkeypatch):
    def _boom():
        raise ValueError("unknown surface 'bogus'")

    monkeypatch.setattr(door, "_apply_surfaces", _boom)
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    monkeypatch.delenv("PROXIMO_HTTP_TOKEN_FILE", raising=False)

    import proximo.httpface as hf
    with pytest.raises(SystemExit) as ei:
        hf.main()
    assert ei.value.code == 1
