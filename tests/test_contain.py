"""CONTAIN Slice 1 — the killable gate at Proximo's single mutation funnel.

Trip state is external: a file named by PROXIMO_CONTAIN_TRIP_PATH, read fresh on every call
(no caching, no contextvar — see contain.py). `_audited()` is the ONE seam every real mutation
passes through, so these tests exercise it directly, mirroring the `_wire_server` idiom used
elsewhere for ledger-backed server tests (see test_audit_harden_0_7_1.py).

The two sections below (BYPASS 1 / BYPASS 2) prove the two manual-audit-path tools that don't
run through `_audited()` — `pve_agent_exec` and `ct_exec`/`ct_psql`'s auto-undo snapshot — are
ALSO gated, by exercising them directly against fake backends and asserting the real backend
call (`api.agent_exec` / `api.snapshot_create`) never fires while contained.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import proximo.contain as contain
import proximo.server as server
from proximo.audit import AuditLedger
from proximo.backends import ExecResult, ProximoError
from proximo.config import ProximoConfig
from proximo.planning import RISK_NONE, Plan


def _wire_server(tmp_path, monkeypatch):
    """Wire proximo.server with a real ledger (tmp_path) and no live backends."""
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json",
        node="pve",
        token_path="/run/x",
        audit_log_path=log,
        audit_keyed=False,
    )
    led = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))
    return led, log


def _entries(log_path) -> list[dict]:
    return [json.loads(ln) for ln in Path(log_path).read_text().splitlines() if ln.strip()]


def test_mutation_refused_when_trip_file_present(tmp_path, monkeypatch):
    """A trip file present -> ProximoError, and the real mutation NEVER fires."""
    _wire_server(tmp_path, monkeypatch)
    trip = tmp_path / "trip"
    trip.write_text("operator pulled the cord")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))

    calls = []

    def _fn():
        calls.append(1)
        return {"ok": True}

    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/100", _fn, mutation=True)

    assert calls == []  # the wrapped fn was never called


def test_mutation_proceeds_when_trip_absent_env_unset(tmp_path, monkeypatch):
    """Backward compat: env unset -> mutation runs exactly as before."""
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.delenv("PROXIMO_CONTAIN_TRIP_PATH", raising=False)

    calls = []

    def _fn():
        calls.append(1)
        return {"ok": True}

    resp = server._audited("pve_guest_power", "lxc/100", _fn, mutation=True)
    assert calls == [1]
    assert resp == {"status": "ok", "result": {"ok": True}}


def test_mutation_proceeds_when_armed_but_trip_absent(tmp_path, monkeypatch):
    """The NORMAL standing state of a CONTAIN-armed box: PROXIMO_CONTAIN_TRIP_PATH is SET but no
    trip file exists yet -> mutations proceed. This is distinct from env-unset (tested above): a
    regression collapsing 'armed-but-not-tripped' into the fail-closed branch would refuse EVERY
    mutation on EVERY armed deployment, and would ship green without this test (contain.py:55)."""
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(tmp_path / "never-created"))

    calls = []
    resp = server._audited("pve_guest_power", "lxc/100",
                           lambda: (calls.append(1), {"ok": True})[1], mutation=True)
    assert calls == [1]
    assert resp == {"status": "ok", "result": {"ok": True}}
    # And the primitive itself reads not-contained for the armed-but-absent case.
    assert contain.contain_state().contained is False


def test_unreadable_trip_still_contains_reason_dropped(tmp_path, monkeypatch):
    """A trip that EXISTS but cannot be read (here: a directory, so the reason read raises) must
    stay CONTAINED with the reason simply dropped — a read failure must never un-contain
    (contain.py:64-65)."""
    trip = tmp_path / "trip-dir"
    trip.mkdir()  # exists (os.stat ok) but open()/_read_reason raises IsADirectoryError
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))
    state = contain.contain_state()
    assert state.contained is True
    assert state.reason is None


def test_reads_not_gated_while_contained(tmp_path, monkeypatch):
    """mutation=False calls (reads) are NOT gated — they still work while contained."""
    _wire_server(tmp_path, monkeypatch)
    trip = tmp_path / "trip"
    trip.write_text("")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))

    result = server._audited("pve_node_status", "pve", lambda: {"status": "running"})
    assert result == {"status": "running"}


def test_dry_run_plan_not_gated_while_contained(tmp_path, monkeypatch):
    """The dry-run PLAN path (_plan) still returns while contained — Slice 1 gates mutations only."""
    _wire_server(tmp_path, monkeypatch)
    trip = tmp_path / "trip"
    trip.write_text("")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))

    def _build():
        return Plan(
            action="x", target="lxc/100", change="would start", current={},
            blast_radius=[], risk=RISK_NONE, risk_reasons=[],
        )

    plan = server._plan("pve_guest_power", "lxc/100", _build)
    assert plan.change == "would start"


def test_contained_mutation_recorded_to_ledger(tmp_path, monkeypatch):
    """A refused mutation IS recorded to the PROVE ledger with outcome 'contained'."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    trip = tmp_path / "trip"
    trip.write_text("operator pulled the cord")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))

    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/100", lambda: {"ok": True}, mutation=True)

    entries = _entries(log)
    assert len(entries) == 1
    assert entries[0]["action"] == "pve_guest_power"
    assert entries[0]["target"] == "lxc/100"
    assert entries[0]["mutation"] is True
    assert entries[0]["outcome"] == "contained"


def test_fail_closed_when_trip_check_raises(tmp_path, monkeypatch):
    """Env set (operator opted in) + the check itself errors -> fail-closed: treated as contained.

    Fire a REAL stat error (no mock): point the trip path THROUGH a regular file, so os.stat
    raises NotADirectoryError (an OSError that is NOT FileNotFoundError). This proves the gate
    fails closed on a genuine unreadable/garbled path, not just a monkeypatched exception.
    """
    _wire_server(tmp_path, monkeypatch)
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(blocker / "trip"))

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)

    assert calls == []


# === BYPASS proofs: manual-audit-path tools that don't run through _audited() ===============


class _FakeApi:
    """Minimal backend spy for the bypass tests — records exactly which real Proxmox-mutating
    calls fired, so a refusal can be proven by an EMPTY call list, not just a raised error."""

    def __init__(self):
        self.config = SimpleNamespace(node="pve")
        self.agent_execs: list = []
        self.agent_exec_statuses: list = []
        self.snapshot_creates: list = []
        self.task_statuses: list = []

    def agent_exec(self, vmid, node, command):
        self.agent_execs.append((vmid, node, command))
        return {"pid": 1}

    def agent_exec_status(self, vmid, node, pid):
        self.agent_exec_statuses.append((vmid, node, pid))
        return {"exited": True, "exitcode": 0, "out-data": "", "err-data": ""}

    def snapshot_create(self, vmid, snapname, kind="lxc", node=None, description=None):
        self.snapshot_creates.append((vmid, snapname))
        return "UPID:create"

    def task_status(self, upid, node=None):
        self.task_statuses.append(upid)
        return {"status": "stopped", "exitstatus": "OK"}


class _FakeExec:
    """Minimal exec-backend spy — records whether the in-container command actually ran."""

    def __init__(self):
        self.ran: list = []

    def run(self, ctid, command, timeout=60):
        self.ran.append((ctid, command))
        return ExecResult(str(ctid), " ".join(command), 0, "out", "")

    def psql(self, ctid, sql, db="postgres", user="postgres", timeout=60):
        self.ran.append((ctid, sql))
        return ExecResult(str(ctid), sql, 0, "out", "")


def _wire_with_backends(tmp_path, monkeypatch, *, enable_agent=False,
                        agent_allowlist=frozenset(), enable_exec=False, ct_allowlist=frozenset()):
    """Wire proximo.server with FAKE api/exec backends (spies) + a real ledger, so a bypass
    test can prove a real mutating call never fired — not just that an error was raised."""
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
        audit_log_path=log, audit_keyed=False,
        enable_agent=enable_agent, agent_allowlist=agent_allowlist,
        enable_exec=enable_exec, ct_allowlist=ct_allowlist,
    )
    api = _FakeApi()
    exec_ = _FakeExec()
    led = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, exec_, led))
    return cfg, api, exec_, led, log


def test_bypass1_agent_exec_refused_when_contained(tmp_path, monkeypatch):
    """BYPASS 1 (F1, critical): pve_agent_exec has a manual audit path — it calls api.agent_exec
    directly and never runs through _audited(), so the inline gate there never sees it. Prove the
    fix: contained -> ProximoError, and api.agent_exec is NEVER called (the guest command must not
    fire, not even partially)."""
    _cfg, api, _exec, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_agent=True, agent_allowlist=frozenset({"101"}),
    )
    trip = tmp_path / "trip"
    trip.write_text("bypass1 proof")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))

    with pytest.raises(ProximoError, match="contained"):
        server.pve_agent_exec("101", ["echo", "hi"], confirm=True)

    assert api.agent_execs == []
    assert api.agent_exec_statuses == []
    entries = _entries(log)
    contained = [e for e in entries if e["outcome"] == "contained"]
    assert len(contained) == 1
    assert contained[0]["action"] == "pve_agent_exec"
    assert contained[0]["mutation"] is True


def test_bypass2_ct_exec_snapshot_refused_when_contained(tmp_path, monkeypatch):
    """BYPASS 2 (F2, high): ct_exec's auto-undo snapshot (_auto_undo -> api.snapshot_create) fires
    BEFORE the payload reaches _audited(mutation=True). Prove the fix: contained -> ProximoError,
    api.snapshot_create is NEVER called AND the command never runs — refuse the WHOLE operation,
    not just the exec half."""
    _cfg, api, exec_, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}),
    )
    trip = tmp_path / "trip"
    trip.write_text("bypass2 proof")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))

    with pytest.raises(ProximoError, match="contained"):
        server.ct_exec("105", ["rm", "-rf", "/x"], snapshot=True, confirm=True)

    assert api.snapshot_creates == []
    assert exec_.ran == []
    entries = _entries(log)
    contained = [e for e in entries if e["outcome"] == "contained"]
    assert len(contained) == 1
    assert contained[0]["action"] == "ct_exec"


def test_bypass2_ct_exec_without_snapshot_still_refused_when_contained(tmp_path, monkeypatch):
    """Same as above but snapshot=False: the gate must sit at the TOP of the execute path, before
    _auto_undo is even considered — not tucked inside the `if snapshot:` branch — so the plain
    exec (no undo requested) is refused too."""
    _cfg, api, exec_, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}),
    )
    trip = tmp_path / "trip"
    trip.write_text("bypass2 proof")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))

    with pytest.raises(ProximoError, match="contained"):
        server.ct_exec("105", ["echo", "hi"], confirm=True)

    assert exec_.ran == []
    assert api.snapshot_creates == []


def test_bypass2_ct_psql_snapshot_refused_when_contained(tmp_path, monkeypatch):
    """Same proof for ct_psql (shares _auto_undo with ct_exec)."""
    _cfg, api, exec_, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}),
    )
    trip = tmp_path / "trip"
    trip.write_text("bypass2 proof")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))

    with pytest.raises(ProximoError, match="contained"):
        server.ct_psql("105", "DELETE FROM t", snapshot=True, confirm=True)

    assert api.snapshot_creates == []
    assert exec_.ran == []
    entries = _entries(log)
    contained = [e for e in entries if e["outcome"] == "contained"]
    assert len(contained) == 1
    assert contained[0]["action"] == "ct_psql"
