"""Every door refuses a retired switch at start; the shell door too (lens of 2026-10-18: the stdio
and network doors refused at start and the engine refused mutations, so a shell READ on a box with
`PROXIMO_AUDIT_KEYED=off` and an unkeyed log quietly sealed it). Told at the door, before anything."""
from __future__ import annotations

import pytest

from proximo.core.doors import cli


@pytest.mark.parametrize("env,value", [
    ("PROXIMO_AUDIT_KEYED", "off"), ("PROXIMO_SCOPE_PATH", "/etc/proximo/scope.json"),
                                       ("PROXIMO_ARM_TTL", "3600")])
def test_a_read_at_the_shell_door_is_refused_while_a_retired_switch_is_set(monkeypatch, capsys, env, value):
    monkeypatch.setenv(env, value)
    assert cli.main(["pve", "GET", "/nodes/{node}/status", "--plan"]) == cli.EXIT_USAGE
    assert f"{env} is set, and the core no longer reads it" in capsys.readouterr().err


@pytest.mark.parametrize("env,value", [("PROXIMO_AUDIT_KEYED", "true"), ("PROXIMO_ARM_TTL", "0")])
def test_a_value_that_asks_for_what_the_core_does_refuses_nothing(monkeypatch, capsys, env, value):
    monkeypatch.setenv(env, value)
    assert cli.main(["pve", "GET", "/nodes/{node}/status", "--plan"]) == 0
    assert "no longer reads it" not in capsys.readouterr().err
