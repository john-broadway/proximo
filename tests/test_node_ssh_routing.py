"""Target-scoped PVE node routing through the existing governed SSH rows."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from proximo.core import diagnose, engine, registry, shell, spine, wire
from proximo.core.errors import ProximoError


@pytest.fixture
def target_registry(monkeypatch, tmp_path):
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":
            monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("PROXIMO_ENV_FILE", str(tmp_path / "absent.env"))
    token = tmp_path / "east.token"
    token.write_text("u@pam!t=11111111-1111-1111-1111-111111111111")
    token.chmod(0o600)
    reg = tmp_path / "targets.toml"
    reg.write_text(f'[targets.east]\nkind="pve"\nbase_url="https://east.invalid:8006/api2/json"\n'
                   f'token_path="{token}"\n[targets.east.nodes]\npve1="east-one"\npve2="east-two"\n')
    monkeypatch.setenv(registry.ENV, str(reg))
    return {"token": token, "registry": reg, "tmp": tmp_path}


def _enable_lanes(monkeypatch):
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "*")
    monkeypatch.setenv("PROXIMO_ENABLE_NODE_SHELL", "1")


def _refusal_rows(tmp_path):
    log = tmp_path / "audit.log"
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


@pytest.mark.parametrize(("method", "path", "args"), [
    ("GET", "/nodes/pve1/lxc/101/logs", {"unit": "ssh"}),
    ("GET", "/nodes/pve1/lxc/101/probe", {}),
    ("GET", "/nodes/pve1/probe", {}),
    ("POST", "/nodes/pve1/lxc/101/exec", {"command": ["id"]}),
    ("POST", "/nodes/pve1/lxc/101/psql", {"sql": "select 1"}),
])
def test_concrete_plans_preflight_every_ssh_row_without_live_api_calls(
    target_registry, monkeypatch, method, path, args
):
    _enable_lanes(monkeypatch)
    monkeypatch.setenv("PROXIMO_SSH_TARGET", "wrong-default")
    monkeypatch.setattr(engine.arm, "arm_state", lambda cfg=None: engine.arm.ArmGateState(True, True, "armed"))
    monkeypatch.setattr(engine, "_client", lambda *a, **k: pytest.fail("route refusal must precede live state"))
    monkeypatch.setattr(engine, "_live_state", lambda *a, **k: pytest.fail("route refusal must skip live state"))
    target_registry["registry"].write_text(target_registry["registry"].read_text().replace('pve1="east-one"\n', ""))
    registry._parse_registry.cache_clear()
    cfg = registry.plane("pve", "east")
    row = engine.resolve("pve", method, path)
    plan = engine.plan(row, args, path, cfg=cfg)
    assert plan["allowed"] is False and plan["needs"] == "config"
    assert "pve1" in plan["reason"] and "east" in plan["reason"]


@pytest.mark.parametrize(("method", "path", "args"), [
    ("GET", "/nodes/pve1/lxc/101/logs", {"unit": "ssh"}),
    ("GET", "/nodes/pve1/lxc/101/probe", {}),
    ("GET", "/nodes/pve1/probe", {}),
    ("POST", "/nodes/pve1/lxc/101/exec", {"command": ["id"]}),
    ("POST", "/nodes/pve1/lxc/101/psql", {"sql": "select 1"}),
])
def test_mapped_concrete_plans_accept_every_ssh_row(target_registry, monkeypatch, method, path, args):
    _enable_lanes(monkeypatch)
    monkeypatch.setattr(engine.arm, "arm_state", lambda cfg=None: engine.arm.ArmGateState(True, True, "armed"))
    monkeypatch.setattr(engine, "_live_state", lambda *a, **k: {})
    plan = engine.plan(engine.resolve("pve", method, path), args, path, cfg=registry.plane("pve", "east"))
    assert plan["allowed"] is True and plan["needs"] is None


def test_argument_conflict_keeps_priority_over_a_missing_route(target_registry, monkeypatch):
    _enable_lanes(monkeypatch)
    target_registry["registry"].write_text(target_registry["registry"].read_text().replace('pve1="east-one"\n', ""))
    registry._parse_registry.cache_clear()
    cfg = registry.plane("pve", "east")
    path = "/nodes/pve1/lxc/101/exec"
    plan = engine.plan(engine.resolve("pve", "POST", path),
                       {"command": ["id"], "node": "pve2"}, path, cfg=cfg)
    assert plan["allowed"] is False and plan["needs"] == "arguments"


def test_trailing_slash_plan_and_execution_use_the_same_concrete_route(target_registry, monkeypatch):
    _enable_lanes(monkeypatch)
    calls = []

    def run(argv, timeout):
        calls.append(argv)
        marker = re.search(r"proximo-ran-([0-9a-f]{32})", argv[-1]).group(1)
        return 0, "ok\n", f"proximo-ran-{marker}\n"

    monkeypatch.setattr(shell, "_run", run)
    cfg = registry.plane("pve", "east")
    path = "/nodes/pve1/lxc/101/logs/"
    row = engine.resolve("pve", "GET", path)
    preview = engine.plan(row, {"unit": "ssh"}, path, cfg=cfg)
    assert preview["allowed"] is True and preview["needs"] is None
    assert calls == []
    result = engine.execute(row, {"unit": "ssh"}, path=path, cfg=cfg)
    assert result["called_path"] == path.rstrip("/")
    assert len(calls) == 1 and calls[0][5] == "east-one"


def test_template_preview_and_closed_lane_keep_their_own_refusals(target_registry, monkeypatch):
    cfg = registry.plane("pve", "east")
    template = engine.resolve("pve", "GET", "/nodes/{node}/lxc/{vmid}/logs")
    preview = engine.plan(template, {"unit": "ssh"}, cfg=cfg)
    assert preview["needs"] == "shell"
    concrete = "/nodes/pve1/lxc/101/logs"
    closed = engine.plan(engine.resolve("pve", "GET", concrete), {"unit": "ssh"}, concrete, cfg=cfg)
    assert closed["needs"] == "shell"


def test_default_invalid_ssh_destination_is_a_config_refusal_in_plan_and_execute(monkeypatch):
    _enable_lanes(monkeypatch)
    monkeypatch.setenv("PROXIMO_SSH_TARGET", "-oProxyCommand=id")
    calls = []
    monkeypatch.setattr(shell, "_run", lambda *a, **k: calls.append(a))
    path = "/nodes/pve1/lxc/101/logs"
    row = engine.resolve("pve", "GET", path)
    plan = engine.plan(row, {"unit": "ssh"}, path)
    assert plan["allowed"] is False and plan["needs"] == "config"
    with pytest.raises(ProximoError, match="PROXIMO_SSH_TARGET"):
        engine.execute(row, {"unit": "ssh"}, path=path)
    rows = [json.loads(line) for line in Path(os.environ["PROXIMO_AUDIT_LOG"]).read_text().splitlines()]
    assert calls == [] and rows[-1]["action"] == "core.refuse" and rows[-1]["detail"]["needs"] == "config"


@pytest.mark.parametrize("destination", ["bad\ncommand", "bad\x00command", "bad;id"])
def test_control_characters_and_shell_fragments_never_enter_route_errors(target_registry, destination):
    token = target_registry["token"]
    encoded = json.dumps(destination)
    target_registry["registry"].write_text(f'[targets.bad]\nkind="pve"\nbase_url="https://bad.invalid"\n'
                                           f'token_path="{token}"\n[targets.bad.nodes]\npve1={encoded}\n')
    registry._parse_registry.cache_clear()
    with pytest.raises(ProximoError) as ei:
        registry.plane("pve", "bad")
    assert destination not in str(ei.value)


def test_missing_route_refuses_before_consent_rate_snapshot_or_api(target_registry, monkeypatch):
    target_registry["registry"].write_text(
        target_registry["registry"].read_text().replace('pve1="east-one"\n', ""))
    registry._parse_registry.cache_clear()
    _enable_lanes(monkeypatch)
    cfg = registry.plane("pve", "east")
    monkeypatch.setattr(engine.arm, "arm_state", lambda cfg=None: engine.arm.ArmGateState(True, True, "armed"))
    spends, rates, api, ssh = [], [], [], []
    monkeypatch.setattr(spine, "spend_consent", lambda *a: spends.append(a))
    monkeypatch.setattr(spine, "reserve_rate", lambda *a, **k: rates.append(a))

    class Api:
        def call(self, method, path, params=None):
            api.append((method, path))
            return {"data": "snapshot"}

    monkeypatch.setattr(engine, "_client", lambda *a, **k: Api())
    monkeypatch.setattr(shell, "_run", lambda *a, **k: ssh.append(a) or (0, "", ""))
    path = "/nodes/pve1/lxc/101/exec"
    with pytest.raises(ProximoError, match="no SSH destination mapped"):
        engine.execute(engine.resolve("pve", "POST", path), {"command": ["id"], "snapshot": True},
                       cfg=cfg, path=path)
    assert spends == rates == api == ssh == []
    row = _refusal_rows(target_registry["tmp"])[-1]
    assert (row["action"], row["outcome"], row["remote"]) == ("core.refuse", "refused", "east")
    assert row["detail"]["needs"] == "config" and row["detail"]["called_path"] == path


@pytest.mark.parametrize("snapshot_fails", [False, True])
def test_mapped_snapshot_and_ssh_use_the_same_target_node_and_guest(target_registry, monkeypatch, snapshot_fails):
    _enable_lanes(monkeypatch)
    monkeypatch.setattr(engine.arm, "arm_state", lambda cfg=None: engine.arm.ArmGateState(True, True, "armed"))
    monkeypatch.setattr(spine, "_SLEEP", lambda _: None)
    target = registry.plane("pve", "east")
    upid = "UPID:pve1:000A1B2C:0D3E4F50:68DA0000:vzsnapshot:101:root@pam!proximo:"

    class Api:
        def __init__(self, cfg):
            self.cfg = cfg
            self.calls = []

        def call(self, method, path, params=None):
            self.calls.append((self.cfg, method, path, dict(params or {})))
            if snapshot_fails and method == "POST":
                raise RuntimeError("snapshot unavailable")
            if method == "GET" and path.endswith("/status"):
                return {"status": "stopped", "exitstatus": "OK", "upid": upid}
            return upid

    apis = []

    def client(product, cfg=None):
        api = Api(cfg)
        apis.append(api)
        return api

    monkeypatch.setattr(engine, "_client", client)

    class Runner:
        def __init__(self):
            self.calls = []

        def __call__(self, argv, timeout):
            self.calls.append(argv)
            marker = re.search(r"proximo-ran-([0-9a-f]{32})", argv[-1]).group(1)
            return 0, "ok\n", f"proximo-ran-{marker}\n"

    runner = Runner()
    monkeypatch.setattr(shell, "_run", runner)
    path = "/nodes/pve1/lxc/101/exec"
    row = engine.resolve("pve", "POST", path)
    if snapshot_fails:
        with pytest.raises(ProximoError, match="snapshot"):
            engine.execute(row, {"command": ["id"], "snapshot": True}, cfg=target, path=path)
        assert runner.calls == []
    else:
        engine.execute(row, {"command": ["id"], "snapshot": True}, cfg=target, path=path)
        assert len(runner.calls) == 1
        argv = runner.calls[0]
        assert argv[5] == "east-one" and 'test "$(hostname)" = pve1' in argv[-1]
        assert "pct exec 101 -- id" in argv[-1]
    calls = [call for api in apis for call in api.calls]
    posts = [call for call in calls if call[1] == "POST"]
    assert posts and posts[0][0] is target
    assert posts[0][0].base_url == target.base_url and posts[0][2] == "/nodes/pve1/lxc/101/snapshot"
    assert all(call[0] is target for call in calls)


def test_two_concrete_nodes_select_distinct_destinations_and_keep_the_path(target_registry, monkeypatch):
    _enable_lanes(monkeypatch)
    monkeypatch.setenv("PROXIMO_SSH_TARGET", "wrong-default")
    class Runner:
        def __init__(self):
            self.calls = []

        def __call__(self, argv, timeout):
            self.calls.append((argv, timeout))
            marker = argv[-1].split("proximo-ran-", 1)[1].split()[0]
            return 0, "", f"proximo-ran-{marker}\n"

    runner = Runner()
    monkeypatch.setattr(shell, "_run", runner)
    cfg = registry.plane("pve", "east")
    for node in ("pve1", "pve2"):
        path = f"/nodes/{node}/lxc/101/logs"
        engine.execute(engine.resolve("pve", "GET", path), {"unit": "ssh"}, cfg=cfg, path=path)
    assert [call[0][5] for call in runner.calls] == ["east-one", "east-two"]
    assert ['test "$(hostname)" = pve1' in call[0][-1] for call in runner.calls] == [True, False]
    assert 'test "$(hostname)" = pve2' in runner.calls[1][0][-1]


def test_same_node_name_in_two_targets_uses_each_target_mapping(target_registry, monkeypatch):
    token = target_registry["token"]
    with target_registry["registry"].open("a") as f:
        f.write(f'\n[targets.west]\nkind="pve"\nbase_url="https://west.invalid:8006/api2/json"\n'
                f'token_path="{token}"\n[targets.west.nodes]\npve1="west-one"\n')
    registry._parse_registry.cache_clear()
    _enable_lanes(monkeypatch)
    class Runner:
        def __init__(self):
            self.calls = []

        def __call__(self, argv, timeout):
            self.calls.append(argv)
            marker = re.search(r"proximo-ran-([0-9a-f]{32})", argv[-1]).group(1)
            return 0, "", f"proximo-ran-{marker}\n"

    runner = Runner()
    monkeypatch.setattr(shell, "_run", runner)
    path = "/nodes/pve1/lxc/101/logs"
    row = engine.resolve("pve", "GET", path)
    for target in ("east", "west"):
        engine.execute(row, {"unit": "ssh"}, cfg=registry.plane("pve", target), path=path)
    assert [argv[5] for argv in runner.calls] == ["east-one", "west-one"]


def test_bad_target_node_map_does_not_disable_a_good_target(target_registry):
    token = target_registry["token"]
    with target_registry["registry"].open("a") as f:
        f.write(f'\n[targets.bad]\nkind="pve"\nbase_url="https://bad.invalid"\ntoken_path="{token}"\n'
                '[targets.bad.nodes]\npve1="-oProxyCommand=id"\n')
    registry._parse_registry.cache_clear()
    assert dict(registry.plane("pve", "east").nodes)["pve1"] == "east-one"
    with pytest.raises(ProximoError, match="SSH destinations"):
        registry.plane("pve", "bad")


def test_mapped_node_diagnosis_builds_its_shell_probes_for_the_target_route(target_registry, monkeypatch):
    from pathlib import Path

    fixture = json.loads((Path(__file__).parent / "fixtures" / "diagnose-pve.json").read_text())
    _enable_lanes(monkeypatch)
    monkeypatch.setenv("PROXIMO_SSH_TARGET", "wrong-default")

    class Api:
        def call(self, method, path, params=None):
            if path.endswith("/status"):
                return fixture["node_status"]
            if path.endswith("/storage"):
                return fixture["node_storage"]
            if path.endswith("/tasks"):
                return fixture["node_tasks"]
            raise AssertionError(path)

    monkeypatch.setattr(engine, "_client", lambda *a, **k: Api())

    class Runner:
        def __init__(self):
            self.calls = []

        def __call__(self, argv, timeout):
            self.calls.append(argv)
            marker = re.search(r"proximo-ran-([0-9a-f]{32})", argv[-1]).group(1)
            return 0, "", f"proximo-ran-{marker}\n"

    runner = Runner()
    monkeypatch.setattr(shell, "_run", runner)
    out = diagnose.run("pve", "/nodes/pve1", cfg=registry.plane("pve", "east"))
    assert out["incomplete"] is False and len(runner.calls) == 7
    assert all(argv[5] == "east-one" for argv in runner.calls)


def test_mapped_lxc_diagnosis_resolves_its_concrete_shell_probe(target_registry, monkeypatch):
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "*")
    cfg = registry.plane("pve", "east")
    subject = diagnose.subjects()["pve:GET /nodes/{node}/lxc/{vmid}"]
    closed = diagnose._closed_lanes("pve", subject, {"node": "pve1", "vmid": "101"}, cfg, None)
    assert closed == {}


@pytest.mark.parametrize("fields", [
    {"nodes": "bad"}, {"nodes": {"bad node": "east"}}, {"nodes": {"pve1": "-oProxyCommand=id"}},
    {"nodes": {"pve1": "east;id"}},
])
def test_malformed_node_maps_fail_closed_without_echoing_values(target_registry, fields):
    token = target_registry["token"]
    text = f'[targets.bad]\nkind="pve"\nbase_url="https://bad.invalid"\ntoken_path="{token}"\n'
    if isinstance(fields["nodes"], dict):
        node, destination = next(iter(fields["nodes"].items()))
        text += f'[targets.bad.nodes]\n{json.dumps(node)}={json.dumps(destination)}\n'
    else:
        text += 'nodes="bad"\n'
    target_registry["registry"].write_text(text)
    with pytest.raises(ProximoError) as ei:
        registry.plane("pve", "bad")
    assert not any(secret in str(ei.value) for secret in ("bad node", "ProxyCommand", "east;id"))


def test_nodes_are_target_local_and_require_a_real_target_arm_pair(target_registry, monkeypatch):
    token = target_registry["token"]
    arm = target_registry["tmp"] / "east.arm"
    readonly = target_registry["tmp"] / "east.readonly"
    arm.write_text(token.read_text())
    readonly.write_text("u@pam!r=22222222-2222-2222-2222-222222222222")
    for f in (arm, readonly):
        f.chmod(0o600)
    target_registry["registry"].write_text(target_registry["registry"].read_text().replace(
        "[targets.east.nodes]", f'arm_source="{arm}"\nreadonly_source="{readonly}"\n[targets.east.nodes]'))
    cfg = registry.plane("pve", "east")
    assert engine.arm.arm_state(cfg).armed
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", str(arm))
    # The registry target's own pair is read from its Plane; the default pair alone is not consulted.
    target_registry["registry"].write_text(target_registry["registry"].read_text().replace(
        f'arm_source="{arm}"', 'arm_source="/missing/target-arm"'))
    registry._parse_registry.cache_clear()
    default_token, default_arm, default_readonly = (target_registry["tmp"] / n
                                                    for n in ("default.token", "default.arm", "default.readonly"))
    default_token.write_text(token.read_text())
    default_arm.write_text(token.read_text())
    default_readonly.write_text("u@pam!r=33333333-3333-3333-3333-333333333333")
    for f in (default_token, default_arm, default_readonly):
        f.chmod(0o600)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://default.invalid:8006/api2/json")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(default_token))
    monkeypatch.setenv("PROXIMO_READONLY_SOURCE", str(default_readonly))
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", str(default_arm))
    assert engine.arm.arm_state(None).armed
    state = engine.arm.arm_state(registry.plane("pve", "east"))
    assert not state.armed


def test_nodes_are_rejected_for_non_pve_target(target_registry):
    token = target_registry["token"]
    target_registry["registry"].write_text(f'[targets.backup]\nkind="pbs"\nbase_url="https://pbs.invalid"\n'
                                           f'token_path="{token}"\n[targets.backup.nodes]\npbs1="pbs"\n')
    with pytest.raises(ProximoError, match="only for pve"):
        registry.plane("pbs", "backup")


def test_plane_keeps_an_immutable_copy_of_node_routes(target_registry):
    fields = {"base_url": "https://copy.invalid", "token_path": str(target_registry["token"]),
              "nodes": {"pve1": "copy-one"}}
    cfg = wire.plane_from_target("pve", "copy", fields)
    fields["nodes"]["pve1"] = "changed"
    assert cfg.nodes == (("pve1", "copy-one"),)
