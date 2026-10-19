"""B5 stage 2: a snapshot before a container command, fail-closed, and its rollback by receipt (2026-10-04).

0.44's `ct_exec(snapshot=True)` / `ct_psql(snapshot=True)` took a container snapshot first and
refused to run the command when the snapshot did not land (`blocked:undo_unavailable`). The core's
UNDO captured a GET twin before a mutation, and `pct exec` has none, so a shell call was receipted
`captured: false`. Now `snapshot=true` takes the snapshot as a governed mutation of its own (the
vendor's `POST .../lxc/{vmid}/snapshot`, armed, tiered, receipted, waited), records a capture that
names it, and `undo <id>` rolls back through the vendor's own rollback. B2's other half.
"""
from __future__ import annotations

import json
import os
import re

import pytest

from proximo.core import engine, shell, spine, undo
from proximo.core.errors import ProximoError

NODE, CT = "pve1", "101"
EXEC = f"/nodes/{NODE}/lxc/{CT}/exec"
UPID = f"UPID:{NODE}:000A1B2C:0D3E4F50:68DA0000:vzsnapshot:{CT}:root@pam!proximo:"


class Api:
    """The vendor's HTTP side: a snapshot POST answers a task id, the task's status answers
    `exitstatus` (OK unless told otherwise), a rollback POST answers a task id too."""

    def __init__(self, exitstatus="OK", fail=None):
        self.exitstatus, self.fail, self.calls = exitstatus, fail, []

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        if self.fail is not None and method == "POST":
            raise self.fail
        if method == "GET" and path.endswith("/status"):
            return {"status": "stopped", "exitstatus": self.exitstatus, "upid": UPID}
        return UPID


class Shell:
    """A host that reaches pct and runs the command (it echoes the per-call ran marker first)."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(argv[-1])
        ran = re.search(r"proximo-ran-([0-9a-f]{32})", argv[-1]).group(1)
        return 0, "ok\n", f"proximo-ran-{ran}\n"


def _rows() -> list[dict]:
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


@pytest.fixture
def box(armed_plane, monkeypatch):
    monkeypatch.setenv(shell.TARGET_ENV, "pve")
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", CT)
    monkeypatch.setattr(spine, "_SLEEP", lambda s: None)
    return armed_plane


def _wire(monkeypatch, **kw):
    api, sh = Api(**kw), Shell()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: api)
    monkeypatch.setattr(shell, "_run", sh)
    return api, sh


def _exec(box, **args):
    return engine.execute(engine.resolve("pve", "POST", EXEC), {"command": ["id"], **args}, cfg=box, path=EXEC)


def test_the_flag_is_published_on_both_mutations_and_not_on_the_read():
    t = engine.table()
    for op in ("exec", "psql"):
        assert t[("pve", "POST", f"/nodes/{{node}}/lxc/{{vmid}}/{op}")].params["snapshot"]["type"] == "boolean"
    assert "snapshot" not in t[("pve", "GET", "/nodes/{node}/lxc/{vmid}/logs")].params


def test_without_the_flag_nothing_is_snapshotted_and_the_receipt_says_so(box, monkeypatch):
    api, sh = _wire(monkeypatch)
    out = _exec(box)
    assert api.calls == [] and len(sh.calls) == 1
    assert out["undo"]["captured"] is False and "snapshot" in out["undo"]["why"]


def test_the_snapshot_lands_first_then_the_command_runs_and_the_capture_names_it(box, monkeypatch):
    api, sh = _wire(monkeypatch)
    out = _exec(box, snapshot=True)
    post = [c for c in api.calls if c[0] == "POST"]
    assert post and post[0][1] == f"/nodes/{NODE}/lxc/{CT}/snapshot"
    name = post[0][2]["snapname"]
    assert re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{2,39}", name)
    assert len(sh.calls) == 1                                          # the command ran, once, after
    u = out["undo"]
    assert u["captured"] is True and u["snapshot"] == name
    assert u["rollback"] == f"POST /nodes/{NODE}/lxc/{CT}/snapshot/{name}/rollback" and len(u["id"]) == 12
    acts = [(r["action"], r["outcome"]) for r in _rows()]
    # the snapshot is its own governed mutation (executing + submitted + task), then the capture,
    # then the command's executing and terminal rows
    assert acts.index(("core.undo_point", "undo_point")) < acts.index(("core.execute", "executing"), 3)
    snap = [r for r in _rows() if r["action"] == "core.undo_point"][-1]
    assert snap["detail"]["snapshot"] == name and snap["detail"]["plane"] == "pve"


def test_the_cli_spelling_true_is_the_flag(box, monkeypatch):
    api, _ = _wire(monkeypatch)
    _exec(box, snapshot="true")
    assert any(c[0] == "POST" and c[1].endswith("/snapshot") for c in api.calls)


@pytest.mark.parametrize("kw", [{"exitstatus": "snapshot feature is not available"},
                                {"fail": RuntimeError("HTTP 500")}])
def test_a_snapshot_that_does_not_land_refuses_the_command_fail_closed(box, monkeypatch, kw):
    api, sh = _wire(monkeypatch, **kw)
    with pytest.raises(ProximoError, match="snapshot"):
        _exec(box, snapshot=True)
    assert sh.calls == []                                              # NOTHING ran in the container
    refuse = [r for r in _rows() if r["action"] == "core.refuse"]
    assert refuse and refuse[-1]["detail"]["needs"] == "undo"
    assert not any(r["action"] == "core.execute" and r["target"].endswith("/exec") for r in _rows())


def test_a_snapshot_is_refused_when_the_container_is_not_allowlisted_before_anything(box, monkeypatch):
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "202")
    api, sh = _wire(monkeypatch)
    with pytest.raises(ProximoError):
        _exec(box, snapshot=True)
    assert api.calls == [] and sh.calls == []


def test_undo_by_receipt_plans_the_rollback_then_runs_it(box, monkeypatch):
    api, _ = _wire(monkeypatch)
    out = _exec(box, snapshot=True)
    ref, name = out["undo"]["id"], out["undo"]["snapshot"]
    rollback = f"/nodes/{NODE}/lxc/{CT}/snapshot/{name}/rollback"
    plan = undo.restore(ref, cfg=box)
    assert plan["status"] == "plan" and plan["restores"] == ref and plan["called_path"] == rollback
    assert plan["arguments"] == {"start": True}                      # the plan says it comes back up
    assert not any(c[1] == rollback for c in api.calls)                # a plan writes nothing
    done = undo.restore(ref, cfg=box, confirm=True)
    assert ("POST", rollback, {"start": True}) in api.calls and done["restores"] == ref   # back UP
    assert done.get("status") != "failed"


def test_a_rollback_whose_task_fails_says_failed_not_restored(box, monkeypatch):
    api, _ = _wire(monkeypatch)
    ref = _exec(box, snapshot=True)["undo"]["id"]
    api.exitstatus = "rollback failed: snapshot is locked"
    done = undo.restore(ref, cfg=box, confirm=True)
    assert done["status"] == "failed"


# ---- lens B5c (2026-10-04): two BLOCKING and six surviving mutants ----

@pytest.mark.parametrize("flag", [1, {"x": 1}, "maybe"])
def test_a_snapshot_flag_that_is_not_a_boolean_refuses_before_anything(box, monkeypatch, flag):
    api, sh = _wire(monkeypatch)                    # a JSON 1 used to skip the snapshot and RUN
    with pytest.raises(ProximoError, match="boolean"):
        _exec(box, snapshot=flag)
    assert api.calls == [] and sh.calls == []
    assert _rows()[-1]["action"] == "core.refuse" and _rows()[-1]["detail"]["needs"] == "arguments"


def test_a_registered_target_is_refused_the_shell_lane_so_the_net_and_the_act_share_a_box(box, monkeypatch):
    import dataclasses
    api, sh = _wire(monkeypatch)                    # snapshot on its API, command on the env box
    with pytest.raises(ProximoError, match="registered target"):
        _exec(dataclasses.replace(box, name="other-estate"), snapshot=True)
    assert api.calls == [] and sh.calls == []


def test_a_snapshot_task_not_seen_to_finish_refuses_the_command(box, monkeypatch):
    api, sh = _wire(monkeypatch)                    # submitted only: may land, is not a net yet
    monkeypatch.setattr(engine, "SNAPSHOT_WAIT", 0)
    with pytest.raises(ProximoError, match="snapshot"):
        _exec(box, snapshot=True)
    assert sh.calls == [] and any(c[1].endswith("/snapshot") for c in api.calls)


def _forged(detail: dict, target: str = EXEC) -> str:
    """A capture written through the ledger's own function (so its chain VERIFIES) whose detail
    is not what this door would write: the checks after PROVE must refuse it on their own."""
    row = engine.resolve("pve", "POST", target)
    point = engine._record(None, "core.undo_point", row, outcome="undo_point",
                           detail={"plane": "pve", **detail}, called=target, required=True)
    return point["entry_hash"][:12]


@pytest.mark.parametrize("detail,target", [
    ({"snapshot": "proximo_a", "rollback": f"POST /nodes/{NODE}/lxc/999/snapshot/proximo_a/rollback"}, EXEC),
    ({"snapshot": "../../x", "rollback": f"POST /nodes/{NODE}/lxc/{CT}/snapshot/../../x/rollback"}, EXEC),
    ({"snapshot": "p" * 41, "rollback": f"POST /nodes/{NODE}/lxc/{CT}/snapshot/{'p' * 41}/rollback"}, EXEC),
    ({"snapshot": "9proximo", "rollback": f"POST /nodes/{NODE}/lxc/{CT}/snapshot/9proximo/rollback"}, EXEC),
    ({"snapshot": "proximo_a", "rollback": f"POST /nodes/{NODE}/lxc/{CT}/snapshot/proximo_a/rollback"},
     f"/nodes/{NODE}/lxc/{CT}/status/start"),
])
def test_a_capture_this_door_would_not_write_rolls_nothing_back(box, monkeypatch, detail, target):
    api, _ = _wire(monkeypatch)
    ref = _forged(detail, target)
    with pytest.raises(ProximoError, match="roll back|refused"):
        undo.restore(ref, cfg=box, confirm=True)
    assert not any("rollback" in c[1] for c in api.calls)


def test_a_rollback_on_a_ledger_that_does_not_verify_is_refused(box, monkeypatch):
    api, _ = _wire(monkeypatch)
    ref = _exec(box, snapshot=True)["undo"]["id"]
    log = os.environ["PROXIMO_AUDIT_LOG"]
    with open(log, encoding="utf-8") as f:
        lines = f.readlines()
    first = json.loads(lines[0])
    first["ts"] = "2000-01-01T00:00:00+00:00"       # one earlier row edited: the chain breaks
    lines[0] = json.dumps(first) + "\n"
    with open(log, "w", encoding="utf-8") as f:
        f.writelines(lines)
    with pytest.raises(ProximoError):
        undo.restore(ref, cfg=box, confirm=True)
    assert not any("rollback" in c[1] for c in api.calls)


def test_a_gated_rollback_row_rolls_nothing_back(box, monkeypatch):
    import dataclasses
    api, _ = _wire(monkeypatch)
    ref = _exec(box, snapshot=True)["undo"]["id"]
    key = ("pve", "POST", "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/rollback")
    t = dict(engine.table())
    t[key] = dataclasses.replace(t[key], gate="held for the test")
    monkeypatch.setattr(engine, "table", lambda: t)
    with pytest.raises(ProximoError, match="not served"):
        undo.restore(ref, cfg=box, confirm=True)
    assert not any("rollback" in c[1] for c in api.calls)


# ---- his word 10-04: the snapshot rides the command's consent; undo brings the container back up ----

def _grants(monkeypatch, tmp_path):
    g = tmp_path / "grants"
    g.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(g))
    return g


def _grant_the_command(box, g, **args):
    row = engine.resolve("pve", "POST", EXEC)
    cid = engine.plan(row, {"command": ["id"], **args}, EXEC, cfg=box)["consent_id"]
    (g / os.path.basename(spine.grant_path(cid))).touch()
    return cid


def test_under_enforced_consent_one_grant_for_the_command_covers_its_snapshot(box, monkeypatch, tmp_path):
    g = _grants(monkeypatch, tmp_path)
    api, sh = _wire(monkeypatch)
    cid = _grant_the_command(box, g, snapshot=True)
    out = _exec(box, snapshot=True)
    assert out["undo"]["captured"] is True and len(sh.calls) == 1
    assert list(g.iterdir()) == []                                     # the ONE grant, spent once
    snap_exec = [r for r in _rows() if r["outcome"] == "executing" and r["target"].endswith("/snapshot")]
    assert snap_exec and snap_exec[0]["detail"]["consent_of"] == {"command": EXEC, "consent_id": cid}
    assert snap_exec[0]["detail"]["consent_id"] != cid                 # its own id was never granted


def test_under_enforced_consent_no_grant_for_the_command_snapshots_nothing(box, monkeypatch, tmp_path):
    _grants(monkeypatch, tmp_path)
    api, sh = _wire(monkeypatch)
    with pytest.raises(ProximoError, match="consent"):
        _exec(box, snapshot=True)
    assert api.calls == [] and sh.calls == []


@pytest.mark.parametrize("row_key,path", [
    (("pve", "POST", "/nodes/{node}/lxc/{vmid}/snapshot"), f"/nodes/{NODE}/lxc/202/snapshot"),       # another CT
    (("pve", "POST", "/nodes/{node}/lxc/{vmid}/snapshot"), f"/nodes/pve9/lxc/{CT}/snapshot"),        # another node
    (("pve", "POST", "/nodes/{node}/lxc/{vmid}/status/stop"), f"/nodes/{NODE}/lxc/{CT}/status/stop"),  # not a snapshot
    (("pve", "POST", "/nodes/{node}/qemu/{vmid}/snapshot"), f"/nodes/{NODE}/qemu/{CT}/snapshot"),    # a VM's
    (("pve", "POST", "/nodes/{node}/lxc/{vmid}/status/stop"), f"/nodes/{NODE}/lxc/{CT}/snapshot"),    # wrong row
])
def test_the_consent_exemption_covers_no_other_shape(box, monkeypatch, tmp_path, row_key, path):
    _grants(monkeypatch, tmp_path)
    api, _ = _wire(monkeypatch)
    with pytest.raises(ProximoError, match="consent exemption"):
        engine.execute(engine.table()[row_key], {"snapname": "proximo_x"}, cfg=box, path=path, net_of=(EXEC, None))
    assert api.calls == []


def test_a_net_of_that_is_not_a_container_command_covers_nothing(box, monkeypatch, tmp_path):
    _grants(monkeypatch, tmp_path)
    api, _ = _wire(monkeypatch)
    row = engine.table()[("pve", "POST", "/nodes/{node}/lxc/{vmid}/snapshot")]
    with pytest.raises(ProximoError, match="consent exemption"):
        engine.execute(row, {"snapname": "proximo_x"}, cfg=box, path=f"/nodes/{NODE}/lxc/{CT}/snapshot",
                       net_of=(f"/nodes/{NODE}/lxc/{CT}/status/stop", None))
    assert api.calls == []


@pytest.mark.parametrize("flag,announced", [(True, True), ("true", True), (False, False), (None, False), (1, False)])
def test_the_plan_names_the_snapshot_its_one_grant_also_authorises(box, monkeypatch, flag, announced):
    _wire(monkeypatch)
    args = {"command": ["id"], **({} if flag is None else {"snapshot": flag})}
    plan = engine.plan(engine.resolve("pve", "POST", EXEC), args, EXEC, cfg=box)
    assert ("also" in plan) is announced
    if announced:
        assert plan["also"]["address"] == "POST /nodes/{node}/lxc/{vmid}/snapshot"
        assert plan["also"]["tier"] and "covered" in plan["also"]["consent"]
