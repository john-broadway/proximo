"""The operator's env file reaches every core door (the swap's security review, 2026-10-17).

The 0.44 commands sourced `~/.config/proximo/proximo.env` before reading any config; the core
doors did not, because the 0.44 shims did it for them. At the default-command swap that would
have made a gate set in the file (`PROXIMO_FORBID`, an arm source, the audit log) silently inert
on the default command: fail-dangerous. `proximo.core.envfile` is the core's loader, and every
door calls it before its first env read, with the process environment winning. Each door test
stubs the step after the load and asserts the file's key had arrived by then.
"""
from __future__ import annotations

import os

import pytest

from proximo.core import envfile, principal
from proximo.core.doors import cli, mcp, network


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The loader writes os.environ directly. Remove only the PROXIMO_* keys a test adds, and point
    the loader at a file under tmp_path so no real ~/.config is read."""
    monkeypatch.delenv("PROXIMO_SURFACES", raising=False)
    monkeypatch.setenv(envfile.PATH_ENV, str(tmp_path / "proximo.env"))
    before = {k for k in os.environ if k.startswith("PROXIMO_")}
    yield
    for k in [k for k in os.environ if k.startswith("PROXIMO_") and k not in before]:
        os.environ.pop(k, None)
    principal.set_serving_face("stdio")   # `main_of` sets a process global; put it back


def _file(tmp_path, text: str) -> None:
    (tmp_path / "proximo.env").write_text(text)


# --- the loader ------------------------------------------------------------------------------

def test_parse_takes_proximo_keys_strips_export_and_quotes_skips_the_rest():
    got = envfile.parse(["# c\n", "\n", "export PROXIMO_A='x y'\n", 'PROXIMO_B="q"\n', "PATH=/evil\n",
                         "LD_PRELOAD=x\n", "PROXIMO_C = bare \n", "noequals\n"])
    assert got == {"PROXIMO_A": "x y", "PROXIMO_B": "q", "PROXIMO_C": "bare"}


def test_load_fills_only_unset_keys_and_names_a_differing_shadow(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PROXIMO_FORBID", "from-env")
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", "same")
    _file(tmp_path, "PROXIMO_FORBID=from-file\nPROXIMO_AUDIT_LOG=same\nPROXIMO_TARGETS=/t\nPATH=/evil\n")
    loaded, shadowed = envfile.load(prog="p")
    assert loaded == ["PROXIMO_TARGETS"] and shadowed == ["PROXIMO_FORBID"]
    assert os.environ["PROXIMO_FORBID"] == "from-env"      # the process environment wins
    assert os.environ["PROXIMO_TARGETS"] == "/t"
    assert os.environ["PATH"] != "/evil"
    err = capsys.readouterr().err
    assert "p: loaded 1 setting(s)" in err and "PROXIMO_FORBID" in err and "from-file" not in err


def test_load_is_a_silent_noop_without_a_file_and_quiet_when_asked(tmp_path, capsys):
    assert envfile.load() == ([], [])
    _file(tmp_path, "PROXIMO_TARGETS=/t\n")
    assert envfile.load(announce=False) == (["PROXIMO_TARGETS"], [])
    assert capsys.readouterr().err == ""


def test_the_control_the_loader_sees_its_own_failure(tmp_path):
    """The file's key must NOT be in the environment before the load, or every door test below
    would pass on a key that was already there."""
    _file(tmp_path, "PROXIMO_TARGETS=/t\n")
    assert "PROXIMO_TARGETS" not in os.environ
    envfile.load(announce=False)
    assert os.environ["PROXIMO_TARGETS"] == "/t"


# --- every door sources it before its first env read -----------------------------------------

def test_the_stdio_door_sources_the_file_before_it_builds(tmp_path, monkeypatch):
    _file(tmp_path, "PROXIMO_TARGETS=/from-file\n")
    seen = {}

    def _build(*a, **k):
        seen["targets"] = os.environ.get("PROXIMO_TARGETS")
        raise mcp.ProximoError("stop here")
    monkeypatch.setattr(mcp, "build_server", _build)
    assert mcp.main([]) == 3
    assert seen["targets"] == "/from-file"


def test_the_stdio_door_sources_the_file_before_a_verb(tmp_path, monkeypatch):
    _file(tmp_path, "PROXIMO_TARGETS=/from-file\n")
    seen = {}
    monkeypatch.setattr(cli, "doctor_main",
                        lambda argv: seen.setdefault("targets", os.environ.get("PROXIMO_TARGETS")) and 0)
    assert mcp.main(["doctor"]) == 0
    assert seen["targets"] == "/from-file"


def test_the_stdio_door_refuses_surfaces_like_the_network_doors(monkeypatch, capsys):
    monkeypatch.setenv("PROXIMO_SURFACES", "pve")
    monkeypatch.setattr(mcp, "build_server", lambda *a, **k: (_ for _ in ()).throw(AssertionError("built")))
    assert mcp.main([]) == 3
    assert "PROXIMO_SURFACES" in capsys.readouterr().err


def test_a_network_door_sources_the_file_before_it_reads_its_env(tmp_path, monkeypatch):
    _file(tmp_path, "PROXIMO_HTTP_PORT=45999\n")
    seen = {}

    def _build(url, token, allowed):
        seen["url"] = url
        raise network.ProximoError("stop here")
    rc = network.main_of("proximo-http", "http", prefix="HTTP", default_port=41242, token_env="X",
                         help_="h", doc="d", extra_env="", argv=[], build=_build)
    assert rc == 3
    assert seen["url"] == "http://127.0.0.1:45999/"


def test_the_shell_door_sources_the_file_before_a_verb(tmp_path, monkeypatch):
    _file(tmp_path, "PROXIMO_TARGETS=/from-file\n")
    seen = {}
    monkeypatch.setattr(cli, "doctor_main",
                        lambda argv: seen.setdefault("targets", os.environ.get("PROXIMO_TARGETS")) and 0)
    assert cli.main(["doctor"]) == 0
    assert seen["targets"] == "/from-file"


# --- the order is the point: the file is read BEFORE the refusal reads the environment --------

def test_the_stdio_door_refuses_a_switch_set_only_in_the_file(tmp_path, monkeypatch, capsys):
    """Lens round 2 (2026-10-17): with the load moved after the refusal, every test stayed green and a
    PROXIMO_SURFACES in the file alone would have been served wide. This pins load-before-refuse."""
    _file(tmp_path, "PROXIMO_SURFACES=pve\n")
    monkeypatch.setattr(mcp, "build_server", lambda *a, **k: (_ for _ in ()).throw(AssertionError("built")))
    assert mcp.main([]) == 3
    assert "PROXIMO_SURFACES" in capsys.readouterr().err


def test_a_network_door_refuses_a_switch_set_only_in_the_file(tmp_path, monkeypatch, capsys):
    _file(tmp_path, "PROXIMO_SCOPE_PATH=/vms/100\n")
    rc = network.main_of("proximo-http", "http", prefix="HTTP", default_port=41242, token_env="X",
                         help_="h", doc="d", extra_env="", argv=[],
                         build=lambda *a: (_ for _ in ()).throw(AssertionError("built")))
    assert rc == 3
    assert "PROXIMO_SCOPE_PATH" in capsys.readouterr().err


# --- an allowlist is compared as the grant it is, and its refusal names its source --------------
# 0.44 lost two things at the cut (capability `allowlist-compares-grants`): a reordered allowlist
# holding the same ids was reported SHADOWED (the same 22 CTIDs, dogfood 2026-09), and a refusal
# never said which store fed the value or that only a restart applies an edit (hit live 2026-09-02).

@pytest.fixture
def _fresh_state(monkeypatch):
    monkeypatch.setattr(envfile, "_STATE", envfile._fresh_state())


@pytest.mark.parametrize("key", ["PROXIMO_CT_ALLOWLIST", "PROXIMO_AGENT_ALLOWLIST"])
@pytest.mark.parametrize("env,file", [("101,102,103", "103,101,102"), ("101,102", " 102 , 101 ,"),
                                       ("*", "7,*"), ("101,101", "101")])
def test_same_ids_in_another_order_or_spacing_are_one_grant_not_shadowed(
        tmp_path, monkeypatch, capsys, _fresh_state, key, env, file):
    monkeypatch.setenv(key, env)
    _file(tmp_path, f"{key}={file}\n")
    loaded, shadowed = envfile.load(prog="p")
    assert shadowed == [] and loaded == []
    assert "SHADOWED" not in capsys.readouterr().err


@pytest.mark.parametrize("key", ["PROXIMO_CT_ALLOWLIST", "PROXIMO_AGENT_ALLOWLIST"])
@pytest.mark.parametrize("env,file", [("101,102", "101,103"), ("101", "101,102"), ("101", "*"), ("", "101")])
def test_a_genuinely_different_grant_is_still_shadowed(tmp_path, monkeypatch, _fresh_state, key, env, file):
    monkeypatch.setenv(key, env)
    _file(tmp_path, f"{key}={file}\n")
    assert envfile.load(announce=False)[1] == [key]


def test_a_non_allowlist_key_still_compares_as_raw_text(tmp_path, monkeypatch, _fresh_state):
    monkeypatch.setenv("PROXIMO_FORBID", "a,b")
    monkeypatch.setenv("PROXIMO_TARGETS", "/t")
    _file(tmp_path, "PROXIMO_FORBID=b,a\nPROXIMO_TARGETS=/t\n")
    assert envfile.load(announce=False)[1] == ["PROXIMO_FORBID"]   # reordered text IS a difference here


def _refusal(lane: str, vmid: str) -> str:
    from proximo.core import spine
    r = spine.opt_in_refusal(lane, vmid)
    assert r is not None
    return r.reason


@pytest.mark.parametrize("lane,enable,allow", [("shell", "PROXIMO_ENABLE_EXEC", "PROXIMO_CT_ALLOWLIST"),
                                                ("agent", "PROXIMO_ENABLE_AGENT", "PROXIMO_AGENT_ALLOWLIST")])
def test_the_refusal_names_the_store_that_fed_the_allowlist_and_the_restart(
        tmp_path, monkeypatch, _fresh_state, lane, enable, allow):
    monkeypatch.setenv(enable, "1")
    secret = str(tmp_path)

    # fed by the env file
    monkeypatch.delenv(allow, raising=False)
    _file(tmp_path, f"{allow}=101\n")
    envfile.load(announce=False)
    msg = _refusal(lane, "999")
    assert "env file" in msg and "restart" in msg and secret not in msg and "proximo.env" not in msg

    # fed by the process environment alone
    monkeypatch.setattr(envfile, "_STATE", envfile._fresh_state())
    monkeypatch.setenv(allow, "101")
    _file(tmp_path, "")
    envfile.load(announce=False)
    msg = _refusal(lane, "999")
    assert "process environment" in msg and "env file" not in msg and "restart" in msg

    # both, the environment winning with a different grant: the file's copy is named dead
    monkeypatch.setattr(envfile, "_STATE", envfile._fresh_state())
    _file(tmp_path, f"{allow}=999\n")
    envfile.load(announce=False)
    msg = _refusal(lane, "999")
    assert "process environment" in msg and "env file" in msg and "SHADOWED" in msg and "restart" in msg
    assert secret not in msg

    # both, same grant: no shadow claim
    monkeypatch.setattr(envfile, "_STATE", envfile._fresh_state())
    monkeypatch.setenv(allow, "101,102")
    _file(tmp_path, f"{allow}=102,101\n")
    envfile.load(announce=False)
    assert "SHADOWED" not in _refusal(lane, "999")
