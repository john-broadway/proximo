"""Every console entrypoint must answer --help by PRINTING USAGE and EXITING, never by binding a
socket or starting the stdin loop.

Regression for the 2026-08-07 footgun: `proximo-http --help` bound 127.0.0.1:41242 and served
until killed, because no entrypoint parsed argv — they read env and served immediately. The guard
fires BEFORE load_env_file() and before the optional-extra probe, so these tests also stand on a
wheel without the [http]/[a2a]/[mcp-http] extras.
"""
from __future__ import annotations

import sys

import pytest


def _run_help(main, argv, monkeypatch, capsys):
    # No proximo config present: if the guard did NOT fire, the serve path would fail on missing
    # config or try to bind — never exit 0 with usage. So a clean SystemExit(0)+usage proves the
    # entrypoint short-circuits before any config read or socket bind.
    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exc:
        main()
    return exc.value.code, capsys.readouterr().out


def test_proximo_http_help_exits_zero_with_usage(monkeypatch, capsys):
    from proximo._http_entry import main
    code, out = _run_help(main, ["proximo-http", "--help"], monkeypatch, capsys)
    assert code == 0
    assert "proximo-http" in out
    assert "PROXIMO_HTTP_PORT" in out and "41242" in out


def test_proximo_mcp_http_help_exits_zero_with_usage(monkeypatch, capsys):
    from proximo._mcp_http_entry import main
    code, out = _run_help(main, ["proximo-mcp-http", "-h"], monkeypatch, capsys)
    assert code == 0
    assert "proximo-mcp-http" in out
    assert "PROXIMO_MCP_HTTP_PORT" in out and "41243" in out


def test_proximo_a2a_help_exits_zero_with_usage(monkeypatch, capsys):
    from proximo._a2a_entry import main
    code, out = _run_help(main, ["proximo-a2a", "--help"], monkeypatch, capsys)
    assert code == 0
    assert "proximo-a2a" in out
    assert "PROXIMO_A2A_PORT" in out and "41241" in out


def test_proximo_stdio_help_exits_zero_with_usage(monkeypatch, capsys):
    from proximo.server import main
    code, out = _run_help(main, ["proximo", "--help"], monkeypatch, capsys)
    assert code == 0
    assert "MCP stdio server" in out
    assert "proximo doctor" in out
