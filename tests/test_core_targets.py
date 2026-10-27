"""Multi-target on the core doors (parity row B16): one Proximo, the boxes PROXIMO_TARGETS names.

The engine already governed a `wire.Plane` (its own arm pair, its forbid, its rate, its name on
every receipt as `remote`); the doors never handed it one, so the core reached only the env box
while this host runs two live estates. These pin the door half: the selector resolves through
`proximo.core.registry`, the call dials the target's base_url and nothing else, the receipt names
the box, the target's arm pair (not the env's) decides a mutation, an unknown name is refused
without listing the registry, the shell lanes never dial the env host for a remote box, and the
selector is advertised only where a registry exists.
"""
from __future__ import annotations

import asyncio
import json
import os

import pytest

from proximo.core import engine, registry, wire
from proximo.core.doors import cli
from proximo.core.doors import mcp as door
from proximo.core.errors import ProximoError
from proximo.core.mcpcompat import tool_input_schema

ENV_URL = "https://env-box.invalid:8006/api2/json"
EAST_URL = "https://east-box.invalid:8006/api2/json"


@pytest.fixture
def estates(monkeypatch, tmp_path):
    """Two pve boxes: the env box and `east` in a registry; a backup box of another kind; a
    recorder standing where the wire is built, so a test sees which box every call dialed."""
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":   # the pin on the real file stays
            monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("PROXIMO_ENV_FILE", str(tmp_path / "absent.env"))
    env_tok, east_tok = tmp_path / "env.tok", tmp_path / "east.tok"
    for t in (env_tok, east_tok):
        t.write_text("u@pam!t=00000000-0000-0000-0000-000000000000")
        t.chmod(0o600)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", ENV_URL)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(env_tok))
    monkeypatch.setenv("PROXIMO_NODE", "pve1")
    reg = tmp_path / "targets.toml"
    reg.write_text(f'[targets.east]\nkind = "pve"\nbase_url = "{EAST_URL}"\ntoken_path = "{east_tok}"\n\n'
                   f'[targets.backup]\nkind = "pbs"\nbase_url = "https://pbs.invalid:8007"\n'
                   f'token_path = "{east_tok}"\n')
    monkeypatch.setenv("PROXIMO_TARGETS", str(reg))
    dialed: list[tuple[str, str, str]] = []

    class Recorder:
        def __init__(self, cfg):
            self.cfg = cfg

        def call(self, method, path, params=None):
            dialed.append((self.cfg.base_url, method, path))
            return [{"node": "n1", "status": "online", "type": "node"}]

    monkeypatch.setattr(engine, "_client", lambda product, cfg=None: Recorder(cfg or wire.Plane.from_env(product)))
    return {"dialed": dialed, "tmp": tmp_path, "east_tok": east_tok, "reg": reg}


def _rows(tmp):
    log = tmp / "audit.log"
    return [json.loads(x) for x in log.read_text().splitlines() if x.strip()] if log.exists() else []


# --- the resolution -------------------------------------------------------------------------

def test_no_target_is_the_env_box_and_a_name_is_its_plane(estates):
    assert registry.plane("pve", None) is None
    p = registry.plane("pve", "east")
    assert (p.name, p.base_url, p.product) == ("east", EAST_URL, "pve")


def test_an_unknown_name_is_refused_without_listing_the_registry(estates):
    with pytest.raises(ProximoError) as ei:
        registry.plane("pve", "nope")
    assert "unknown target 'nope'" in str(ei.value)
    assert "east" not in str(ei.value) and "backup" not in str(ei.value)


def test_a_target_of_another_kind_is_refused(estates):
    with pytest.raises(ProximoError, match="kind 'pbs', not usable by a PVE tool"):
        registry.plane("pve", "backup")


def test_a_readable_secret_is_refused_without_its_path(estates):
    """The path is the operator's; since the REST and A2A doors a ProximoError's text can reach a
    network caller, so the refusal says the fix, not where the file is."""
    estates["east_tok"].chmod(0o644)
    with pytest.raises(ProximoError) as ei:
        registry.plane("pve", "east")
    assert "readable by other users" in str(ei.value)
    assert str(estates["east_tok"]) not in str(ei.value)


def test_two_names_for_one_box_share_the_tightest_budget(estates):
    """0.44's name-swap evasion, closed in the core's copy: an alias with no cap of its own is not
    a second budget."""
    tok = estates["east_tok"]
    estates["reg"].write_text(
        f'[targets.east]\nkind = "pve"\nbase_url = "{EAST_URL}"\ntoken_path = "{tok}"\nrate_max = 5\n'
        f'rate_window = 60\n\n[targets.alias]\nkind = "pve"\nbase_url = "{EAST_URL}/"\ntoken_path = "{tok}"\n')
    p = registry.plane("pve", "alias")
    assert (p.rate_max, p.rate_window) == (5, 60)


# --- the doors ------------------------------------------------------------------------------

def test_a_read_with_a_target_dials_that_box_and_the_receipt_names_it(estates):
    door.read("pve", "/nodes", cfg=registry.plane("pve", "east"))
    door.read("pve", "/nodes")
    assert [d[0] for d in estates["dialed"]] == [EAST_URL, ENV_URL]
    reads = [r for r in _rows(estates["tmp"]) if r["action"].startswith("core.")]
    assert reads[0].get("remote") == "east" and "remote" not in reads[-1]


def _arm_env_box(estates, monkeypatch):
    """The env box ARMED for real: its served token is byte-identical to its arm source."""
    tmp = estates["tmp"]
    arm, ro = tmp / "arm.tok", tmp / "ro.tok"
    arm.write_text((tmp / "env.tok").read_text())
    ro.write_text("u@pam!ro=11111111-1111-1111-1111-111111111111")
    for f in (arm, ro):
        f.chmod(0o600)
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", str(arm))
    monkeypatch.setenv("PROXIMO_READONLY_SOURCE", str(ro))
    assert engine.arm.arm_state(None).armed, "the control: the env box must read ARMED"


def test_a_mutation_on_a_target_is_judged_by_the_targets_own_arm_pair(estates, monkeypatch):
    """The env box is ARMED; that says nothing about another estate. A target with no arm pair of
    its own is NOT armed, the refusal says which knob is missing, and nothing dials."""
    _arm_env_box(estates, monkeypatch)
    with pytest.raises(ProximoError, match="not armed") as ei:
        door.call("pve", "DELETE", "/nodes/n1/qemu/1", confirm=True, cfg=registry.plane("pve", "east"))
    assert "default box's arm never authorizes another box" in str(ei.value)
    assert estates["dialed"] == []
    assert _rows(estates["tmp"])[-1]["remote"] == "east"


def test_the_mcp_tools_take_target_and_route_it(estates):
    server = door.build_server()
    tools = {t.name: t for t in asyncio.run(server.list_tools())}
    schema = {n: set(tool_input_schema(t)["properties"]) for n, t in tools.items()}
    # audit_entries' own `target` is older and means a receipt's path: a filter, not a box.
    routed = {n for n, props in schema.items() if "target" in props} - {"audit_entries"}
    assert routed == {"proximo_plan", "proximo_read", "proximo_call"}
    asyncio.run(server.call_tool("proximo_read", {"plane": "pve", "path": "/nodes", "target": "east"}))
    assert estates["dialed"][-1][0] == EAST_URL


def test_without_a_registry_the_selector_is_not_advertised(estates, monkeypatch):
    """0.44's rule: a one-estate box pays nothing in the 4K window for a selector with nothing to
    select (tests/test_four_k_door.py measures that door)."""
    monkeypatch.delenv("PROXIMO_TARGETS")
    tools = asyncio.run(door.build_server().list_tools())
    assert all("target" not in tool_input_schema(t)["properties"]
               for t in tools if t.name != "audit_entries")


def test_an_unreadable_registry_keeps_the_selector_and_says_so(estates, monkeypatch, capsys):
    monkeypatch.setenv("PROXIMO_TARGETS", str(estates["tmp"] / "missing.toml"))
    tools = asyncio.run(door.build_server().list_tools())
    assert any("target" in tool_input_schema(t)["properties"]
               for t in tools if t.name == "proximo_call")
    assert "selector stays advertised" in capsys.readouterr().err


def test_the_shell_door_takes_target(estates, capsys):
    assert cli.main(["pve", "GET", "/nodes", "--target", "east"]) == cli.EXIT_OK
    assert estates["dialed"][-1][0] == EAST_URL
    assert cli.main(["pve", "GET", "/nodes", "--target", "nope"]) == cli.EXIT_USAGE
    assert "unknown target 'nope'" in capsys.readouterr().err


def test_a_diagnosis_on_a_target_never_dials_this_hosts_shell(estates, monkeypatch):
    """B5's split, class-checked for the diagnosis: with the node shell lane ON, a remote box's
    host probes must not run over this host's ssh. The lane is named closed, nothing dials ssh."""
    from proximo.core import shell
    monkeypatch.setenv("PROXIMO_ENABLE_NODE_SHELL", "1")
    monkeypatch.setenv("PROXIMO_SSH_TARGET", "root@env-box.invalid")
    dialed_ssh = []
    monkeypatch.setattr(shell, "_run", lambda *a, **k: dialed_ssh.append(a) or (0, "", ""))
    out = door.read("pve", "/nodes/n1", diagnose=True, cfg=registry.plane("pve", "east"))
    assert dialed_ssh == []
    assert out["incomplete"] is True and "east" in out["shell"]["skipped"]
    assert {d[0] for d in estates["dialed"]} == {EAST_URL}


# --- lens 3 (2026-10-05) ----------------------------------------------------------------------

@pytest.mark.parametrize("registry_set", [False, True], ids=["no-registry", "registry"])
def test_an_undeclared_argument_is_refused_and_nothing_dials(estates, monkeypatch, registry_set):
    """BLOCKING: where `target` was not advertised the SDK DROPPED it, and a call naming another
    box ran on the env box. Every tool now refuses an argument it does not declare: a target the
    door cannot route, or a misspelt one, dials nothing."""
    if not registry_set:
        monkeypatch.delenv("PROXIMO_TARGETS")
    server = door.build_server()
    bad = {"plane": "pve", "path": "/nodes", "target": "east"} if not registry_set else \
          {"plane": "pve", "path": "/nodes", "taget": "east"}
    with pytest.raises(Exception, match="unexpected arguments"):
        asyncio.run(server.call_tool("proximo_read", bad))
    assert estates["dialed"] == []


def test_the_rest_door_answers_an_undeclared_argument_with_a_400(estates, monkeypatch):
    """The same refusal through the dispatch the REST and A2A doors share: a caller error, 400."""
    from proximo.core.doors.dispatch import Core, DispatchError
    monkeypatch.delenv("PROXIMO_TARGETS")
    with pytest.raises(DispatchError) as ei:
        asyncio.run(Core().call("proximo_read", {"plane": "pve", "path": "/nodes", "target": "east"}))
    assert ei.value.status == 400
    assert estates["dialed"] == []


def test_a_container_diagnosis_on_a_target_never_dials_this_hosts_shell(estates, monkeypatch):
    """The container lane, alongside the node lane above: with exec opted in for every container,
    a remote box's container probes must not run over this host's ssh."""
    from proximo.core import shell
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "*")
    monkeypatch.setenv("PROXIMO_SSH_TARGET", "root@env-box.invalid")
    dialed_ssh = []
    monkeypatch.setattr(shell, "_run", lambda *a, **k: dialed_ssh.append(a) or (0, "", ""))
    out = door.read("pve", "/nodes/n1/lxc/101", diagnose=True, cfg=registry.plane("pve", "east"))
    assert dialed_ssh == []
    assert out["incomplete"] is True and "east" in out["shell"]["skipped"]


@pytest.mark.parametrize("shape", ["directory", "not-text"])
def test_an_unreadable_registry_is_a_refusal_without_its_path(estates, shape):
    """MAJOR: a directory or non-text bytes escaped as IsADirectoryError / UnicodeDecodeError, a
    traceback carrying the path, where the shell door promises exit 3."""
    reg = estates["reg"]
    reg.unlink()
    if shape == "directory":
        reg.mkdir()
    else:
        reg.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(ProximoError) as ei:
        registry.plane("pve", "east")
    assert str(reg) not in str(ei.value)
    assert cli.main(["pve", "GET", "/nodes", "--target", "east"]) == cli.EXIT_USAGE
