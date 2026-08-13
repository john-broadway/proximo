"""Tests for the PDM fleet-control increment — plan builders + confirm-gated tools.

Split from test_pdm.py (which covers the read plane + backend mutation methods).
Backend paths/bodies are proven in test_pdm.py; here we prove the trust spine:
dry-run-by-default plans (with no-op detection + honest risk), confirm-to-fire,
ledger outcome="submitted", and the auto safety-snapshot before a rollback.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.backends import ProximoError
from proximo.config import ProximoConfig
from proximo.planning import (
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_NONE,
    plan_pdm_migrate,
    plan_pdm_power,
    plan_pdm_snapshot_create,
    plan_pdm_snapshot_delete,
    plan_pdm_snapshot_rollback,
)


class _StubPdm:
    """Minimal PDM double: guest_status returns a fixed live state for the planner."""

    def __init__(self, status: str = "running"):
        self._status = status

    def guest_status(self, remote, kind, vmid):
        return {"status": self._status, "name": "web1", "uptime": 3600}


# --- power planner: no-op detection + risk by action ---

def test_plan_power_stop_running_is_high_and_flags_halt():
    plan = plan_pdm_power(_StubPdm("running"), "dc1", "qemu", "100", "stop")
    assert plan.risk == RISK_HIGH
    assert plan.current["status"] == "running"
    assert any("halt" in b.lower() for b in plan.blast_radius)


def test_plan_power_start_when_running_is_noop():
    plan = plan_pdm_power(_StubPdm("running"), "dc1", "qemu", "100", "start")
    assert plan.risk == RISK_NONE
    assert any("no-op" in b.lower() for b in plan.blast_radius)


def test_plan_power_shutdown_running_is_medium():
    plan = plan_pdm_power(_StubPdm("running"), "dc1", "lxc", "201", "shutdown")
    assert plan.risk == RISK_MEDIUM


# --- migrate planner: cross-remote + delete escalate risk ---

def test_plan_migrate_in_cluster_is_medium():
    plan = plan_pdm_migrate(_StubPdm(), "dc1", "qemu", "100", "node2")
    assert plan.risk == RISK_MEDIUM


def test_plan_remote_migrate_with_delete_is_high_and_warns():
    plan = plan_pdm_migrate(_StubPdm(), "dc1", "qemu", "100", "dc2",
                            cross_remote=True, delete=True)
    assert plan.risk == RISK_HIGH
    assert any("delet" in r.lower() for r in plan.risk_reasons)


# --- snapshot planners ---

def test_plan_snapshot_create_is_low_additive():
    plan = plan_pdm_snapshot_create(_StubPdm(), "dc1", "qemu", "100", "snap1")
    assert plan.risk == RISK_LOW


def test_plan_snapshot_delete_is_medium_irreversible():
    plan = plan_pdm_snapshot_delete(_StubPdm(), "dc1", "qemu", "100", "snap1")
    assert plan.risk == RISK_MEDIUM
    assert any("undo" in r.lower() or "cannot" in r.lower() for r in plan.risk_reasons)


def test_plan_snapshot_rollback_is_high_and_notes_safety_snapshot():
    plan = plan_pdm_snapshot_rollback(_StubPdm("running"), "dc1", "qemu", "100", "snap1")
    assert plan.risk == RISK_HIGH
    assert any("safety" in b.lower() for b in plan.blast_radius)


def test_plan_power_lxc_resume_is_flagged_not_low():
    # PDM does not proxy resume for lxc; the dry-run must NOT present it as a normal low-risk op
    # (redteam: confirm errors, so the preview must warn — not mislead).
    plan = plan_pdm_power(_StubPdm("running"), "dc1", "lxc", "201", "resume")
    assert plan.risk != RISK_LOW
    assert any("refus" in r.lower() or "not a power action" in r.lower()
               for r in plan.risk_reasons)


def test_plan_remote_migrate_delete_names_deletion_in_blast_radius():
    # The single most irreversible op: the source copy is destroyed. That belongs in blast_radius
    # (the 'what gets hit' field), not only in risk_reasons (redteam MEDIUM).
    plan = plan_pdm_migrate(_StubPdm(), "dc1", "qemu", "100", "dc2",
                            cross_remote=True, delete=True)
    assert any("delet" in b.lower() for b in plan.blast_radius)


def test_plan_migrate_lxc_online_warns_of_restart_downtime_in_blast_radius():
    # Audit-fixes plan Task 8 Fix A: pdm_pve_lxc_migrate's own docstring admits online=True is
    # a stop-move-start "restart-migration" with real downtime (there is no true live migration
    # for lxc) -- the dry-run PLAN a human approves before confirm=True must say so, not stay
    # silent about exactly the harm the tool's docs promise. Before the fix, plan_pdm_migrate had
    # no kind-specific branch at all: the only interruption warning fired for `running and not
    # online` (an offline migrate), which online=True never reaches.
    plan = plan_pdm_migrate(_StubPdm("running"), "dc1", "lxc", "201", "node2", online=True)
    assert any("restart" in b.lower() or "downtime" in b.lower() for b in plan.blast_radius), (
        f"lxc online=True migrate PLAN must warn of restart/downtime; got {plan.blast_radius}"
    )


def test_plan_migrate_qemu_online_does_not_get_the_lxc_restart_warning():
    # Regression guard: qemu online=True is a TRUE live migration (no downtime) -- the new
    # lxc-only warning must not leak onto its qemu sibling.
    plan = plan_pdm_migrate(_StubPdm("running"), "dc1", "qemu", "100", "node2", online=True)
    assert not any("restart" in b.lower() or "downtime" in b.lower() for b in plan.blast_radius)


# ---------------------------------------------------------------------------
# Tool wiring — dry-run-by-default, confirm-to-fire, ledger PROVE, auto-undo.
# ---------------------------------------------------------------------------

class _FakePdm:
    """Records mutation calls; guest_status feeds the planner, task_status the auto-undo wait."""

    def __init__(self, status: str = "running"):
        self._status = status
        self.calls: list = []

    def guest_status(self, remote, kind, vmid):
        return {"status": self._status, "name": "web1"}

    def guest_power(self, remote, kind, vmid, action):
        self.calls.append(("power", remote, kind, vmid, action))
        return "UPID:power"

    def guest_migrate(self, remote, kind, vmid, target, online=False, target_storage=None):
        self.calls.append(("migrate", remote, kind, vmid, target, online))
        return "UPID:migrate"

    def guest_remote_migrate(self, remote, kind, vmid, target_remote, target_bridge,
                             target_storage, target_vmid=None, online=False, delete=False):
        self.calls.append(("rmig", remote, kind, vmid, target_remote, delete))
        return "UPID:rmig"

    def snapshot_create(self, remote, kind, vmid, snapname, description=None, vmstate=False):
        self.calls.append(("snapc", remote, kind, vmid, snapname))
        return "UPID:snapc"

    def snapshot_delete(self, remote, kind, vmid, snapname):
        self.calls.append(("snapd", remote, kind, vmid, snapname))
        return "UPID:snapd"

    def snapshot_rollback(self, remote, kind, vmid, snapname):
        self.calls.append(("rollback", remote, kind, vmid, snapname))
        return "UPID:rollback"

    def task_status(self, remote, upid):
        return {"status": "stopped", "exitstatus": "OK"}


class _FailSnapPdm(_FakePdm):
    """snapshot_create raises — proves rollback fail-closes when the safety snapshot can't be taken."""

    def snapshot_create(self, *a, **k):
        raise RuntimeError("storage does not support snapshots")


def _wire(tmp_path, monkeypatch, pdm=None):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve",
                        token_path="/run/x", audit_log_path=log)
    ledger = AuditLedger(log)
    pdm = pdm or _FakePdm()
    monkeypatch.setattr(server, "_svc", lambda: (cfg, SimpleNamespace(), SimpleNamespace(), ledger))
    monkeypatch.setattr(server, "_pdm", lambda: (SimpleNamespace(), pdm))
    return pdm, ledger, log


def _outcomes(log, action):
    with open(log, encoding="utf-8") as f:
        return [json.loads(x)["outcome"] for x in f if x.strip()
                and json.loads(x)["action"] == action]


def test_power_dry_run_returns_plan_and_mutates_nothing(tmp_path, monkeypatch):
    pdm, _, _ = _wire(tmp_path, monkeypatch)
    out = server.pdm_pve_qemu_power("dc1", "100", "stop")
    assert out["status"] == "plan"
    assert pdm.calls == []  # dry-run must not touch the backend


def test_power_confirm_submits_and_records_planned_then_submitted(tmp_path, monkeypatch):
    pdm, _, log = _wire(tmp_path, monkeypatch)
    out = server.pdm_pve_qemu_power("dc1", "100", "stop", confirm=True)
    assert out["status"] == "submitted"  # task-backed: never "ok"
    assert pdm.calls == [("power", "dc1", "qemu", "100", "stop")]
    oc = _outcomes(log, "pdm_pve_qemu_power")
    assert "planned" in oc and "submitted" in oc
    assert oc.index("planned") < oc.index("submitted")
    assert "ok" not in oc


def test_lxc_power_targets_lxc(tmp_path, monkeypatch):
    pdm, _, _ = _wire(tmp_path, monkeypatch)
    server.pdm_pve_lxc_power("dc1", "201", "start", confirm=True)
    assert pdm.calls[0] == ("power", "dc1", "lxc", "201", "start")


def test_remote_migrate_confirm_reaches_backend(tmp_path, monkeypatch):
    pdm, _, _ = _wire(tmp_path, monkeypatch)
    out = server.pdm_pve_qemu_remote_migrate(
        "dc1", "100", target_remote="dc2", target_bridge="vmbr0:vmbr0",
        target_storage="local:local", confirm=True)
    assert out["status"] == "submitted"
    assert pdm.calls[0][0] == "rmig" and pdm.calls[0][4] == "dc2"


def test_snapshot_create_confirm(tmp_path, monkeypatch):
    pdm, _, _ = _wire(tmp_path, monkeypatch)
    server.pdm_pve_qemu_snapshot_create("dc1", "100", "snap1", confirm=True)
    assert pdm.calls[0] == ("snapc", "dc1", "qemu", "100", "snap1")


def test_rollback_takes_safety_snapshot_before_rolling_back(tmp_path, monkeypatch):
    pdm, _, log = _wire(tmp_path, monkeypatch)
    out = server.pdm_pve_qemu_snapshot_rollback("dc1", "100", "snap1", confirm=True)
    assert out["status"] == "submitted"
    kinds = [c[0] for c in pdm.calls]
    assert "snapc" in kinds and "rollback" in kinds
    assert kinds.index("snapc") < kinds.index("rollback")  # safety snapshot FIRST
    assert "undo_point" in _outcomes(log, "pdm_pve_qemu_snapshot_rollback")
    # The caller MUST get the safety-snapshot name back (not just in the ledger) — it is the
    # handle to revert a bad rollback. Live-prove 2026-07-06 caught it missing from the response.
    assert out.get("safety_snapshot"), f"rollback response must surface the safety snapshot: {out}"


def test_rollback_fail_closed_when_safety_snapshot_fails(tmp_path, monkeypatch):
    pdm, _, _ = _wire(tmp_path, monkeypatch, pdm=_FailSnapPdm())
    out = server.pdm_pve_qemu_snapshot_rollback("dc1", "100", "snap1", confirm=True)
    assert out["status"].startswith("blocked")
    assert "rollback" not in [c[0] for c in pdm.calls]  # NEVER rolled back unprotected


def test_rollback_dry_run_is_plan(tmp_path, monkeypatch):
    pdm, _, _ = _wire(tmp_path, monkeypatch)
    out = server.pdm_pve_qemu_snapshot_rollback("dc1", "100", "snap1")
    assert out["status"] == "plan"
    assert pdm.calls == []


def test_rollback_auto_undo_snapshot_is_refused_when_contained(tmp_path, monkeypatch):
    """CONTAIN must gate the auto-undo's OWN safety-snapshot mutation, not just the trailing
    rollback. Redteam HIGH (same bypass class already fixed for ct_exec): _pdm_auto_undo fired
    a real snapshot_create BEFORE any gate — so a tripped kill-switch still mutated the guest."""
    pdm, _, _ = _wire(tmp_path, monkeypatch)
    trip = tmp_path / "trip"
    trip.write_text("contained")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))
    with pytest.raises(ProximoError, match="contain"):
        server.pdm_pve_qemu_snapshot_rollback("dc1", "100", "snap1", confirm=True)
    # the safety snapshot must NEVER have fired under an active containment trip
    assert "snapc" not in [c[0] for c in pdm.calls]
    assert "rollback" not in [c[0] for c in pdm.calls]


@pytest.mark.parametrize("gate", [
    "enforce_scope", "enforce_lease", "enforce_envelope_forbid",
    "enforce_consent", "enforce_envelope_rate",
])
def test_rollback_auto_undo_snapshot_refused_when_any_gate_blocks(tmp_path, monkeypatch, gate):
    """M12 (2026-07-10 audit): _pdm_auto_undo clears SIX gates before its safety snapshot, but only
    CONTAIN was covered. Each of the other five must also refuse BEFORE the snapshot fires — prove it
    by making each gate refuse and asserting the real snapshot_create never happened."""
    import proximo.tools.pdm_fleet as pf

    pdm, _, _ = _wire(tmp_path, monkeypatch)

    def _refuse(*_a, **_k):
        raise ProximoError(f"{gate} refused")

    monkeypatch.setattr(pf, gate, _refuse)
    with pytest.raises(ProximoError, match="refused"):
        server.pdm_pve_qemu_snapshot_rollback("dc1", "100", "snap1", confirm=True)
    assert "snapc" not in [c[0] for c in pdm.calls]
    assert "rollback" not in [c[0] for c in pdm.calls]


# ---------------------------------------------------------------------------
# M4 option D — the opt-in newest-first cap plumbs through the wrapper seam
# ---------------------------------------------------------------------------

def test_pdm_pbs_snapshots_list_limit_is_opt_in_and_newest_first(tmp_path, monkeypatch):
    class _SnapPdm:
        def pbs_snapshots_list(self, remote, datastore, ns=None):
            return [
                {"backup-id": "old", "backup-time": 100},
                {"backup-id": "new", "backup-time": 300},
                {"backup-id": "mid", "backup-time": 200},
            ]
    _wire(tmp_path, monkeypatch, pdm=_SnapPdm())
    full = server.pdm_pbs_snapshots_list(remote="pbs-dc1", datastore="store")
    assert [r["backup-time"] for r in full] == [100, 300, 200]   # untouched without limit
    capped = server.pdm_pbs_snapshots_list(remote="pbs-dc1", datastore="store", limit=2)
    assert [r["backup-id"] for r in capped] == ["new", "mid"]


def test_pdm_tasks_list_limit_caps_newest_by_starttime(tmp_path, monkeypatch):
    class _TaskPdm:
        def tasks_list(self, params=None):
            return [{"upid": f"u{i}", "starttime": i} for i in (5, 1, 9)]
    _wire(tmp_path, monkeypatch, pdm=_TaskPdm())
    assert server.pdm_tasks_list()["returned"] == 3
    capped = server.pdm_tasks_list(limit=1)
    assert capped["tasks"][0]["upid"] == "u9"


def test_pdm_tasks_list_classifies_raw_error_text_as_failed(tmp_path, monkeypatch):
    """Rows are the live PDM shape (probed 2026-08-13 against the sealed lab).

    PDM puts the raw error TEXT in `status`, so bucketing on that string would hand a
    model a fresh key per failure — four failures, four keys, exactly when things break.
    by_outcome collapses them to one. The `upid` here is remote-qualified and the columns
    are worker_type/worker_id, both PDM shapes that differ from PVE.
    """
    class _TaskPdm:
        def tasks_list(self, params=None):
            base = {"node": "pve-test4", "pid": 1, "pstart": 2, "user": "root@pam",
                    "worker_type": "aptupdate", "worker_id": None, "starttime": 1, "endtime": 2}
            return [
                {**base, "upid": "pve:pve-test1!UPID:x:1", "status": "OK"},
                {**base, "upid": "pve:pve-test4!UPID:x:2",
                 "status": "command 'apt-get update' failed: received interrupt"},
                {**base, "upid": "pve:pve-test4!UPID:x:3",
                 "status": "snapshot name 'proximosmoke' already used"},
                {**base, "upid": "pve:pve-test4!UPID:x:4", "status": "Cluster join aborted!"},
                {**base, "upid": "pve:pve-test4!UPID:x:5",
                 "status": "snapshot feature is not available"},
            ]
    _wire(tmp_path, monkeypatch, pdm=_TaskPdm())
    out = server.pdm_tasks_list()
    assert out["by_outcome"] == {"ok": 1, "failed": 4}, "four distinct error texts, one class"
    assert set(out["tasks"][0]) == {"upid", "node", "worker_type", "worker_id", "user",
                                    "status", "starttime", "endtime"}
    assert out["tasks"][0]["node"] == "pve-test4", (
        "node is the only place the remote appears outside the prefixed upid"
    )
