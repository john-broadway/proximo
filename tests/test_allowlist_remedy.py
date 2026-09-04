"""The allowlist refusal must name the store that actually fed it (2026-09-02 incident).

The incident: an operator added a CTID to the documented ``~/.config/proximo/proximo.env``,
verified the edit, reconnected, and ``ct_exec`` refused again with the identical text
("... not in PROXIMO_CT_ALLOWLIST — add it there to permit"). The allowlist also lived in the
MCP client's ``mcpServers.<name>.env`` block, and ``load_env_file`` fills only keys the process
environment has NOT already set, so the file's copy of that one key was dead, silently, by
design ("real/inline env always wins"). The refusal named a variable, not a store, and the
loader printed what it loaded, never what it skipped.

Three layers, each with a control that must fail:

- the loader names every file key the process environment SHADOWS (value differs / same value),
  never the values themselves;
- the config records where each allowlist came from (``ct_allowlist_source`` /
  ``agent_allowlist_source``), per constructor, never from module state a fixture-built config
  would not have;
- every allowlist refusal (server ct_exec/ct_psql/ct_logs/ct_diagnose and qemu-agent gates, and
  the backend defense-in-depth twins) names that source and says restart/reconnect, and never
  carries an expanded local path (the message reaches A2A/HTTP callers too).
"""

from __future__ import annotations

import os
import warnings

import pytest

import proximo.config as config
import proximo.server as server
from proximo.audit import AuditLedger
from proximo.backends import ApiBackend, ExecBackend, ProximoError
from proximo.config import ProximoConfig

MCP_BLOCK = "mcpServers"          # the client-side store, by the shape README/SETUP document
FILE_DISPLAY = "~/.config/proximo/proximo.env"   # the default file, UNEXPANDED (remote-safe)
FILE_BY_VAR = "PROXIMO_ENV_FILE"  # when the file is overridden, the message names the override, not the path


@pytest.fixture(autouse=True)
def _isolate_loader_state(monkeypatch):
    """The loader keeps a per-process record; it must not leak between tests. And load_env_file
    mutates os.environ directly (bypassing monkeypatch); strip only the PROXIMO_* keys it adds."""
    monkeypatch.setattr(config, "_ENV_FILE_STATE", config._fresh_env_file_state())
    before = {k for k in os.environ if k.startswith("PROXIMO_")}
    yield
    for k in [k for k in os.environ if k.startswith("PROXIMO_") and k not in before]:
        os.environ.pop(k, None)


def _write_env(tmp_path, content: str) -> str:
    p = tmp_path / "proximo.env"
    p.write_text(content)
    return str(p)


def _core_env(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/run/x")
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))


def _from_env() -> ProximoConfig:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ProximoConfig.from_env()


def _assert_remedy(msg: str, var: str, *, source_fragment: str):
    assert "add it there" not in msg, msg                     # the old text named no store
    assert var in msg
    assert source_fragment in msg
    assert "restart" in msg and "reconnect" in msg, msg       # the value is fixed at launch


# ─── the incident, verbatim shape ─────────────────────────────────────────────────────────────

def test_incident_2026_09_02_refusal_names_the_shadowed_file_and_the_restart(tmp_path, monkeypatch, capsys):
    _core_env(monkeypatch, tmp_path)
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "100,200")               # the MCP client's block
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_CT_ALLOWLIST=100,200,300\n"))
    config.load_env_file()
    err = capsys.readouterr().err
    assert "SHADOWED" in err and "PROXIMO_CT_ALLOWLIST (value differs)" in err, err
    assert "300" not in err and "100" not in err                        # keys, never values

    cfg = _from_env()
    ledger = AuditLedger(cfg.audit_log_path)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, ledger))  # gate fires before any backend
    out = server.ct_exec("300", ["echo", "hi"], confirm=True)
    assert out["status"] == "blocked:allowlist"                            # status untouched
    msg = out["message"]
    _assert_remedy(msg, "PROXIMO_CT_ALLOWLIST", source_fragment=MCP_BLOCK)
    assert "SHADOWED" in msg and FILE_BY_VAR in msg, msg
    assert str(tmp_path) not in msg                                        # no expanded path leaves the box


# ─── layer 1: the loader names what it skipped ───────────────────────────────────────────────

def test_loader_names_a_shadowed_key_whose_value_differs(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_CONSENT_DIR=/from/file\n"))
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", "/from/inline")
    config.load_env_file()
    err = capsys.readouterr().err
    assert "SHADOWED" in err and "PROXIMO_CONSENT_DIR (value differs)" in err, err
    assert os.environ["PROXIMO_CONSENT_DIR"] == "/from/inline"             # precedence unchanged


def test_loader_records_but_does_not_print_a_same_value_shadow(tmp_path, monkeypatch, capsys):
    """SETUP's own Step 4 sources the file into the shell and then runs `proximo doctor`: every key
    is then a same-value shadow, and a line on every CLI verb would be noise. Same value is not the
    hazard; it is recorded (doctor can see it) and stays off stderr. The control below proves the
    line fires for the differing key in the SAME load."""
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_CONSENT_DIR=/same\nPROXIMO_NODE=pve\n"))
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", "/same")
    monkeypatch.setenv("PROXIMO_NODE", "other")
    config.load_env_file()
    err = capsys.readouterr().err
    assert "PROXIMO_NODE (value differs)" in err, err
    assert "PROXIMO_CONSENT_DIR" not in err, err
    assert config.shadowed_keys() == {"PROXIMO_CONSENT_DIR": False, "PROXIMO_NODE": True}


def test_loader_is_silent_when_every_shadow_is_same_value(tmp_path, monkeypatch, capsys):
    """The documented flow: `set -a; . proximo.env; set +a; proximo doctor` must not print a shadow
    line at all."""
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_CONSENT_DIR=/same\nPROXIMO_NODE=pve\n"))
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", "/same")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    config.load_env_file()
    err = capsys.readouterr().err
    assert "SHADOWED" not in err, err
    assert config.shadowed_keys() == {"PROXIMO_CONSENT_DIR": False, "PROXIMO_NODE": False}


def test_loader_prints_no_shadow_line_when_nothing_overlaps(tmp_path, monkeypatch, capsys):
    """Control: the line must be absent, not merely empty, when the file and the env are disjoint."""
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_CONSENT_DIR=/from/file\n"))
    monkeypatch.delenv("PROXIMO_CONSENT_DIR", raising=False)
    config.load_env_file()
    err = capsys.readouterr().err
    assert "SHADOWED" not in err, err
    assert "loaded 1 setting(s)" in err                                    # the existing line survives


def test_loader_shadow_line_never_carries_values(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_TOKEN_PATH=/secret/from/file\n"))
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/secret/from/inline")
    config.load_env_file()
    err = capsys.readouterr().err
    assert "SHADOWED" in err
    assert "/secret/from/file" not in err and "/secret/from/inline" not in err


def test_shadowed_keys_is_a_fresh_record_per_load(tmp_path, monkeypatch):
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_CONSENT_DIR=/from/file\n"))
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", "/from/inline")
    config.load_env_file()
    assert config.shadowed_keys() == {"PROXIMO_CONSENT_DIR": True}
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_NODE=pve\n"))
    monkeypatch.delenv("PROXIMO_NODE", raising=False)
    config.load_env_file()
    assert config.shadowed_keys() == {}                                     # the old record did not linger


# ─── layer 2: the config records where each allowlist came from ──────────────────────────────

def test_env_source_names_the_file_when_the_file_fed_the_key(tmp_path, monkeypatch):
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_CT_ALLOWLIST=100\n"))
    monkeypatch.delenv("PROXIMO_CT_ALLOWLIST", raising=False)
    config.load_env_file()
    src = config.env_source("PROXIMO_CT_ALLOWLIST")
    assert FILE_BY_VAR in src and "SHADOWED" not in src
    assert str(tmp_path) not in src                                        # never the expanded path


def test_env_source_names_the_default_file_unexpanded(tmp_path, monkeypatch):
    monkeypatch.delenv(FILE_BY_VAR, raising=False)
    cfgdir = tmp_path / ".config" / "proximo"
    cfgdir.mkdir(parents=True)
    (cfgdir / "proximo.env").write_text("PROXIMO_CT_ALLOWLIST=100\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("PROXIMO_CT_ALLOWLIST", raising=False)
    config.load_env_file()
    src = config.env_source("PROXIMO_CT_ALLOWLIST")
    assert FILE_DISPLAY in src and str(tmp_path) not in src


def test_env_source_names_the_process_env_and_the_shadowed_file(tmp_path, monkeypatch):
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_CT_ALLOWLIST=100\n"))
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "200")
    config.load_env_file()
    src = config.env_source("PROXIMO_CT_ALLOWLIST")
    assert MCP_BLOCK in src and "SHADOWED" in src and FILE_BY_VAR in src


def test_env_source_names_the_process_env_alone_when_the_file_lacks_the_key(tmp_path, monkeypatch):
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_NODE=pve\n"))
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "200")
    config.load_env_file()
    src = config.env_source("PROXIMO_CT_ALLOWLIST")
    assert MCP_BLOCK in src and "SHADOWED" not in src


def test_env_source_says_unset_when_nothing_fed_the_key(tmp_path, monkeypatch):
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_NODE=pve\n"))
    monkeypatch.delenv("PROXIMO_CT_ALLOWLIST", raising=False)
    config.load_env_file()
    src = config.env_source("PROXIMO_CT_ALLOWLIST")
    assert "unset" in src and "deny" in src


def test_from_env_records_both_allowlist_sources(tmp_path, monkeypatch):
    _core_env(monkeypatch, tmp_path)
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_CT_ALLOWLIST=100\nPROXIMO_AGENT_ALLOWLIST=300\n"))
    monkeypatch.delenv("PROXIMO_CT_ALLOWLIST", raising=False)
    monkeypatch.setenv("PROXIMO_AGENT_ALLOWLIST", "400")
    config.load_env_file()
    cfg = _from_env()
    assert FILE_BY_VAR in cfg.ct_allowlist_source and "SHADOWED" not in cfg.ct_allowlist_source
    assert MCP_BLOCK in cfg.agent_allowlist_source and "SHADOWED" in cfg.agent_allowlist_source


def test_direct_construction_source_is_a_neutral_phrase_that_stays_true():
    """A fixture-built config never came from the env or the file; its source must not claim so."""
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x")
    assert cfg.ct_allowlist_source == "the server configuration"
    assert cfg.agent_allowlist_source == "the server configuration"
    assert MCP_BLOCK not in cfg.ct_allowlist_source and FILE_DISPLAY not in cfg.ct_allowlist_source


def test_from_target_source_names_the_registry_entry():
    cfg = ProximoConfig.from_target({"base_url": "https://y:8006/api2/json", "node": "pve",
                                     "token_path": "/run/y", "ct_allowlist": ["100"]})
    assert "target" in cfg.ct_allowlist_source and MCP_BLOCK not in cfg.ct_allowlist_source
    assert "target" in cfg.agent_allowlist_source


# ─── layer 3: every refusal site carries the remedy ─────────────────────────────────────────

def _wire_server(tmp_path, monkeypatch, **cfg_kw):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
                        audit_log_path=log, **cfg_kw)
    ledger = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, ledger))
    return cfg


SRC = "the process environment (planted)"


@pytest.mark.parametrize("call", [
    lambda: server.ct_exec("999", ["echo", "hi"], confirm=True),
    lambda: server.ct_psql("999", "SELECT 1", confirm=True),
    lambda: server.ct_logs("999", "nginx.service"),
    lambda: server.ct_diagnose("999"),
], ids=["ct_exec", "ct_psql", "ct_logs", "ct_diagnose"])
def test_every_ct_allowlist_refusal_names_the_source(tmp_path, monkeypatch, call):
    _wire_server(tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"100"}),
                 ct_allowlist_source=SRC)
    out = call()
    assert out["status"] == "blocked:allowlist"
    _assert_remedy(out["message"], "PROXIMO_CT_ALLOWLIST", source_fragment=SRC)


@pytest.mark.parametrize("call", [
    lambda: server.pve_agent_exec("999", ["echo"]),
    lambda: server.pve_agent_info("999"),
], ids=["pve_agent_exec", "pve_agent_info"])
def test_every_agent_allowlist_refusal_names_the_source(tmp_path, monkeypatch, call):
    _wire_server(tmp_path, monkeypatch, enable_agent=True, agent_allowlist=frozenset({"100"}),
                 agent_allowlist_source=SRC)
    out = call()
    assert out["status"] == "blocked:allowlist"
    _assert_remedy(out["message"], "PROXIMO_AGENT_ALLOWLIST", source_fragment=SRC)


def test_backend_exec_refusal_names_the_source():
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
                        enable_exec=True, ct_allowlist=frozenset({"100"}), ct_allowlist_source=SRC)
    with pytest.raises(ProximoError) as exc:
        ExecBackend(cfg).run("999", ["true"])
    _assert_remedy(str(exc.value), "PROXIMO_CT_ALLOWLIST", source_fragment=SRC)


def test_backend_agent_refusal_names_the_source():
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
                        enable_agent=True, agent_allowlist=frozenset({"100"}), agent_allowlist_source=SRC)
    with pytest.raises(ProximoError) as exc:
        ApiBackend(cfg).agent_exec("999", None, ["echo"])
    _assert_remedy(str(exc.value), "PROXIMO_AGENT_ALLOWLIST", source_fragment=SRC)


# ─── lens round A (2026-09-03): the stderr contracts, the daemon shape, three survivors ──────
#
# The lens reproduced two things the first round never looked at, and planted three mutants the
# suite could not see. Each gets a test that names it.

def _plant_shadow(tmp_path, monkeypatch, *, file_line: str, env_key: str, env_value: str):
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, file_line + "\n"))
    monkeypatch.setenv(env_key, env_value)


@pytest.mark.parametrize("argv, prefix", [
    (["proximo", "badge", "mint", "--key", "{tmp}/does-not-exist.pem", "--sub", "fleet-7"], "proximo badge: "),
    (["proximo", "reach-audit", "--ctids", "101"], "proximo reach-audit:"),
], ids=["badge", "reach-audit"])
def test_clean_stderr_verbs_stay_clean_with_a_differing_shadow(tmp_path, monkeypatch, capsys, argv, prefix):
    """`proximo badge` and `proximo reach-audit` pin `err.startswith(<prefix>)` (test_badge_cli,
    test_reach_audit). main() already keeps its own scoping noise off those verbs; the loader's
    lines (loaded N / SHADOWED) printed before that exemption and broke the contract on any box
    whose shell exports a PROXIMO_* key that differs from the file. Reproduced by the lens."""
    from proximo import reach_audit
    _plant_shadow(tmp_path, monkeypatch, file_line="PROXIMO_NODE=file-value",
                  env_key="PROXIMO_NODE", env_value="env-value")
    monkeypatch.setattr(reach_audit, "_api_and_token",
                        lambda token_path=None: (_ for _ in ()).throw(
                            RuntimeError("Missing required Proximo env var: X")))
    monkeypatch.setattr(server.sys, "argv", [a.replace("{tmp}", str(tmp_path)) for a in argv])
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith(prefix), err
    assert "SHADOWED" not in err and "loaded 1 setting" not in err


def test_the_server_path_still_announces_the_shadow(tmp_path, monkeypatch, capsys):
    """Control for the test above: quieting the CLI verbs must not quiet the loader itself. A
    direct load_env_file() (what the stdio server and the daemon entries do) still speaks."""
    _plant_shadow(tmp_path, monkeypatch, file_line="PROXIMO_NODE=file-value",
                  env_key="PROXIMO_NODE", env_value="env-value")
    config.load_env_file()
    assert "SHADOWED" in capsys.readouterr().err


def test_process_env_source_names_both_launch_shapes(tmp_path, monkeypatch):
    """The process environment is the MCP client's env block for a stdio server and the unit's
    EnvironmentFile for the daemon; a remedy that names only the client sends a daemon operator
    to a file their deployment does not have (lens D2)."""
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_NODE=pve\n"))
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "200")
    config.load_env_file()
    src = config.env_source("PROXIMO_CT_ALLOWLIST")
    assert MCP_BLOCK in src and "EnvironmentFile" in src, src


def test_loader_shadow_line_names_both_launch_shapes(tmp_path, monkeypatch, capsys):
    _plant_shadow(tmp_path, monkeypatch, file_line="PROXIMO_NODE=file-value",
                  env_key="PROXIMO_NODE", env_value="env-value")
    config.load_env_file()
    err = capsys.readouterr().err
    assert MCP_BLOCK in err and "EnvironmentFile" in err, err


def test_failed_reload_clears_the_previous_shadow_record(tmp_path, monkeypatch, capsys):
    """Survivor 1: a reset placed after the open would let a stale record outlive a later failed
    load. Load a shadowed file, then reload against a missing path: the record must be empty."""
    _plant_shadow(tmp_path, monkeypatch, file_line="PROXIMO_NODE=file-value",
                  env_key="PROXIMO_NODE", env_value="env-value")
    config.load_env_file()
    assert config.shadowed_keys() == {"PROXIMO_NODE": True}
    monkeypatch.setenv(FILE_BY_VAR, str(tmp_path / "gone.env"))
    assert config.load_env_file() == []
    assert config.shadowed_keys() == {}
    assert "SHADOWED" not in config.env_source("PROXIMO_NODE")


def test_loader_prints_differing_keys_in_alphabetical_order(tmp_path, monkeypatch, capsys):
    """Survivor 2's sibling one layer up: file order is NODE then CT_ALLOWLIST; the line sorts."""
    monkeypatch.setenv(FILE_BY_VAR, _write_env(tmp_path, "PROXIMO_NODE=file-value\nPROXIMO_CT_ALLOWLIST=1\n"))
    monkeypatch.setenv("PROXIMO_NODE", "env-value")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "2")
    config.load_env_file()
    err = capsys.readouterr().err
    assert err.index("PROXIMO_CT_ALLOWLIST (value differs)") < err.index("PROXIMO_NODE (value differs)"), err


def test_quoted_file_value_equal_to_the_env_value_is_a_same_value_shadow(tmp_path, monkeypatch, capsys):
    """Survivor 3: the diff must compare the file value AFTER quote-stripping, or `PROXIMO_NODE="pve"`
    in the file against `pve` in the env reports a false 'value differs'."""
    _plant_shadow(tmp_path, monkeypatch, file_line='PROXIMO_NODE="pve"', env_key="PROXIMO_NODE", env_value="pve")
    config.load_env_file()
    assert config.shadowed_keys() == {"PROXIMO_NODE": False}
    assert "SHADOWED" not in capsys.readouterr().err


# ─── lens round B (2026-09-03): help is a clean-stdout verb too ─────────────────────────────

def test_help_prints_no_loader_lines(tmp_path, monkeypatch, capsys):
    """`proximo --help` ran the loader before the help check, so a differing shadow (or any
    loaded key) printed to stderr in front of the usage text. Untested and unpinned until now
    (lens B): help is a clean verb like badge; the loader stays silent for it."""
    _plant_shadow(tmp_path, monkeypatch, file_line="PROXIMO_NODE=file-value",
                  env_key="PROXIMO_NODE", env_value="env-value")
    monkeypatch.setattr(server.sys, "argv", ["proximo", "--help"])
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 0
    out, err = capsys.readouterr()
    assert "MCP stdio server" in out
    assert err == "", err
