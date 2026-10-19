"""The A2A perimeter over real HTTP: the agent card the core door serves. (The 0.44 executor's
async `execute()` path, which the rest of this file drove until the cut of 2026-10-18, went with the
0.44 server; the core door's executor is driven end to end in `test_a2a_e2e.py`.)"""
from __future__ import annotations

import pytest

FACE = "a2a"  # which perimeter this file tests: see conftest `build_app`

pytest.importorskip("a2a")


def test_agent_card_served_over_http(build_app):
    from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH
    from starlette.testclient import TestClient


    # The DNS-rebind Host guard (TrustedHostMiddleware) is now always installed, so the client must
    # present a loopback Host like a real client hitting the loopback-bound server — TestClient's
    # default "testserver" Host is correctly refused (400) by the guard.
    client = TestClient(build_app(), base_url="http://localhost")
    resp = client.get(AGENT_CARD_WELL_KNOWN_PATH)
    assert resp.status_code == 200, f"card endpoint returned {resp.status_code}"
    body = resp.json()
    assert "Proximo" in body.get("name", ""), f"unexpected card name: {body.get('name')!r}"
    # exactly the six core tools, as skills
    assert len(body.get("skills", [])) == 6, len(body.get("skills", []))
