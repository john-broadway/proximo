"""Tests for the Proximo A2A AgentCard factory (src/proximo/core/perimeter/a2a/card.py).

The card advertises the six tools as A2A skills — the same list an MCP client
sees, not a curated slice. Verifies: it builds; name/version/capabilities/interface/modes; every
governed tool appears once as a skill (id == tool name), including the "dangerous plane".
"""

from __future__ import annotations

from proximo.core.doors.dispatch import Core
from proximo.core.perimeter.a2a.card import build_agent_card


def _card(url, **kw):
    """The card as the 0.44 entry builds it: `tools` is required since step 1b, the governed surface here."""
    return build_agent_card(url, tools=Core().list_sync(), **kw)

_TEST_URL = "http://localhost:9000/rpc"


def _governed_names() -> set[str]:
    return {t.name for t in Core().list_sync()}


def test_card_builds() -> None:
    assert _card(_TEST_URL) is not None


def test_card_name() -> None:
    assert _card(_TEST_URL).name == "Proximo"


def test_card_version_is_set() -> None:
    card = _card(_TEST_URL)
    assert isinstance(card.version, str) and card.version


def test_card_version_fallback() -> None:
    card = _card(_TEST_URL, version="0.0.0-test")
    assert isinstance(card.version, str) and card.version


def test_card_capabilities_present() -> None:
    assert _card(_TEST_URL).HasField("capabilities")


def test_card_interface_url() -> None:
    card = _card(_TEST_URL)
    assert len(card.supported_interfaces) == 1
    assert card.supported_interfaces[0].url == _TEST_URL


def test_card_advertises_the_six_tools() -> None:
    card = _card(_TEST_URL)
    card_ids = {sk.id for sk in card.skills}
    assert card_ids == _governed_names()
    assert len(card_ids) == 6


def test_card_skill_id_equals_name() -> None:
    for sk in _card(_TEST_URL).skills:
        assert sk.id == sk.name


def test_card_explicit_tools_arg_is_honored() -> None:
    # build_app passes a snapshot; a caller can pass a subset and the card reflects exactly it.
    tools = Core().list_sync()[:3]
    card = build_agent_card(_TEST_URL, tools=tools)
    assert {sk.id for sk in card.skills} == {t.name for t in tools}


def test_card_default_modes() -> None:
    card = _card(_TEST_URL)
    assert "application/json" in list(card.default_input_modes)
    assert "application/json" in list(card.default_output_modes)
