"""An unknown CLI verb must REFUSE — never fall through to serving.

Found by the harden lens (2026-08-26): `proximo <typo>` fell past every verb branch into the
stdio serve path — surfaces applied, banner printed, a session_start ledger entry written when
the principal feature is on, and mcp.run() blocking on the operator's terminal. A typo must be
a loud exit 2 naming the verb, not a server. The no-args path stays the stdio serve contract
(both MCP lanes and the container ENTRYPOINT launch bare `proximo`).
"""
from __future__ import annotations

import pytest

import proximo.server as srv


def _no_serve(monkeypatch):
    monkeypatch.setattr(srv.mcp, "run",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("SERVED")))


def test_unknown_verb_refuses_loud(monkeypatch, capsys):
    _no_serve(monkeypatch)
    monkeypatch.setattr(srv.sys, "argv", ["proximo", "hardn"])  # the typo class
    with pytest.raises(SystemExit) as ei:
        srv.main()
    assert ei.value.code == 2
    cap = capsys.readouterr()
    assert "hardn" in cap.err and "unknown" in cap.err.lower()
    assert "harden" in cap.out  # the usage block prints so the right verb is one glance away


def test_option_like_first_arg_also_refuses(monkeypatch, capsys):
    # `proximo --version` is not supported; serving on it was the same trap in a flag costume.
    _no_serve(monkeypatch)
    monkeypatch.setattr(srv.sys, "argv", ["proximo", "--version"])
    with pytest.raises(SystemExit) as ei:
        srv.main()
    assert ei.value.code == 2


def test_no_args_still_serves(monkeypatch):
    served = {}
    monkeypatch.setattr(srv.mcp, "run", lambda *a, **k: served.__setitem__("ran", True))
    monkeypatch.setattr(srv.sys, "argv", ["proximo"])
    srv.main()
    assert served.get("ran") is True  # the stdio contract is untouched


def test_known_verbs_still_dispatch(monkeypatch, capsys):
    # A verb that works today must not be caught by the refusal (harden as the probe).
    _no_serve(monkeypatch)
    for var in ("PROXIMO_CONSENT_DIR", "PROXIMO_CONTAIN_TRIP_PATH"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(srv.sys, "argv", ["proximo", "harden"])
    srv.main()
    assert "CONSENT" in capsys.readouterr().out
