"""Every console entrypoint must answer --help by PRINTING USAGE and EXITING, never by binding a
socket or starting the stdin loop.

Regression for the 2026-08-07 footgun: `proximo-http --help` bound 127.0.0.1:41242 and served
until killed, because no entrypoint parsed argv. Since the default-command swap (2026-10-17) the
entries are the core doors: the three network doors parse through `main_of`, the stdio door
through its own `main`. The guard fires before any config read and before the optional-extra
probe, so these tests also stand on a wheel without the [http]/[a2a]/[mcp-http] extras.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_estate(monkeypatch):
    # No proximo config present: if the guard did NOT fire, the serve path would fail on missing
    # config or try to bind; it never returns 0 with usage. So rc 0 + usage proves the entrypoint
    # short-circuits before any config read or socket bind.
    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH"):
        monkeypatch.delenv(var, raising=False)


@pytest.mark.parametrize(("mod", "prog", "flag", "env", "port"), [
    ("proximo.core.doors.http", "proximo-http", "--help", "PROXIMO_HTTP_", "41242"),
    ("proximo.core.doors.mcphttp", "proximo-mcp-http", "-h", "PROXIMO_MCP_HTTP_", "41243"),
    ("proximo.core.doors.a2a", "proximo-a2a", "--help", "PROXIMO_A2A_", "41241"),
])
def test_a_network_door_answers_help_with_usage_and_returns_zero(mod, prog, flag, env, port, capsys):
    import importlib  # noqa: PLC0415
    rc = importlib.import_module(mod).main([flag])
    out = capsys.readouterr().out
    assert rc == 0
    assert prog in out and env in out and port in out


def test_the_stdio_door_answers_help_with_usage_and_returns_zero(capsys):
    from proximo.core.doors.mcp import main  # noqa: PLC0415
    rc = main(["--help"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "usage: proximo" in out and "mint|doctor|badge" in out and "PROXIMO_API_BASE_URL" in out


def test_the_stdio_door_refuses_an_unknown_argument_before_any_build(monkeypatch, capsys):
    from proximo.core.doors import mcp  # noqa: PLC0415
    monkeypatch.setattr(mcp, "build_server", lambda *a, **k: (_ for _ in ()).throw(AssertionError("built")))
    assert mcp.main(["--serve-please"]) == 3
    err = capsys.readouterr().err
    assert err.startswith("proximo: unknown argument") and "usage: proximo" in err


def test_the_stdio_door_hands_a_verb_to_the_shell_door(monkeypatch, capsys):
    """`proximo mint|doctor|badge` is the shell door's verb, never a server start."""
    from proximo.core.doors import cli, mcp  # noqa: PLC0415
    seen = {}
    monkeypatch.setattr(cli, "main", lambda argv: seen.setdefault("argv", argv) and 0)
    monkeypatch.setattr(mcp, "build_server", lambda *a, **k: (_ for _ in ()).throw(AssertionError("built")))
    assert mcp.main(["mint", "pve"]) == 0
    assert seen["argv"] == ["mint", "pve"]
