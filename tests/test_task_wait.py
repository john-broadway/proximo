"""Native async-task wait — pve_task_wait over PVE UPIDs.

Spec: docs/specs/2026-06-19-async-task-wait.md (internal-only). The pure poll helper takes injected sleep/monotonic
so tests are deterministic and never actually sleep.
"""
from __future__ import annotations


def test_wait_for_task_succeeds_after_polling_to_terminal_ok():
    from proximo.tasks_pools import wait_for_task

    statuses = iter([
        {"status": "running"},
        {"status": "running"},
        {"status": "stopped", "exitstatus": "OK"},
    ])
    slept: list[int] = []
    clock = iter([0, 0, 0, 0])  # start + per-iteration checks, all well under the deadline

    r = wait_for_task(
        lambda: next(statuses),
        timeout=120,
        interval=2,
        sleep=slept.append,
        monotonic=lambda: next(clock),
    )

    assert r["finished"] is True
    assert r["succeeded"] is True
    assert r["status"] == "stopped"
    assert r["exitstatus"] == "OK"
    assert r["timed_out"] is False
    assert r["polls"] == 3
    assert slept == [2, 2]  # slept between the three polls


def test_wait_for_task_not_succeeded_on_nonok_exitstatus():
    from proximo.tasks_pools import wait_for_task

    r = wait_for_task(
        lambda: {"status": "stopped", "exitstatus": "command failed: exit code 1"},
        timeout=120,
        interval=2,
        sleep=lambda *_: None,
        monotonic=lambda: 0,
    )

    assert r["finished"] is True
    assert r["succeeded"] is False  # fail-closed: stopped != OK is not success
    assert r["exitstatus"] == "command failed: exit code 1"
    assert r["timed_out"] is False
    assert r["polls"] == 1


def test_wait_for_task_times_out_when_never_terminal():
    from proximo.tasks_pools import wait_for_task

    slept: list[int] = []
    clock = iter([0, 5, 15])  # start=0 (deadline=10); 5<10 → poll again; 15>=10 → time out

    r = wait_for_task(
        lambda: {"status": "running"},
        timeout=10,
        interval=2,
        sleep=slept.append,
        monotonic=lambda: next(clock),
    )

    assert r["timed_out"] is True
    assert r["finished"] is False
    assert r["succeeded"] is False
    assert r["status"] == "running"
    assert r["polls"] == 2


def test_wait_for_task_immediate_terminal_never_sleeps():
    from proximo.tasks_pools import wait_for_task

    slept: list[int] = []

    r = wait_for_task(
        lambda: {"status": "stopped", "exitstatus": "OK"},
        timeout=120,
        interval=2,
        sleep=slept.append,
        monotonic=lambda: 0,
    )

    assert r["polls"] == 1
    assert r["succeeded"] is True
    assert slept == []  # terminal on the first poll → no sleep


# --- the pve_task_wait tool (wiring) ---

import json  # noqa: E402
from types import SimpleNamespace  # noqa: E402

import proximo.server as server  # noqa: E402
from proximo.audit import AuditLedger  # noqa: E402
from proximo.config import ProximoConfig  # noqa: E402

_UPID = "UPID:pve:00001:0:0:0:vzdump:102:root@pam:"


class _FakeApi:
    """Returns a fixed task_status — immediate terminal, so the tool never actually sleeps."""

    def __init__(self, status):
        self.config = SimpleNamespace(node="pve")
        self._status = status
        self.calls = 0

    def task_status(self, upid, node=None):
        self.calls += 1
        return self._status


def _wire(tmp_path, monkeypatch, status):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve",
                        token_path="/run/x", audit_log_path=log)
    api = _FakeApi(status)
    ledger = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, SimpleNamespace(), ledger))
    return api, log


def _entries(log):
    with open(log, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_pve_task_wait_returns_succeeded_handle(tmp_path, monkeypatch):
    api, log = _wire(tmp_path, monkeypatch, {"status": "stopped", "exitstatus": "OK"})

    out = server.pve_task_wait(_UPID)

    assert out["upid"] == _UPID
    assert out["finished"] is True
    assert out["succeeded"] is True
    assert out["exitstatus"] == "OK"
    assert out["timed_out"] is False
    assert out["polls"] == 1  # immediate terminal → no real sleep
    assert api.calls == 1
    audited = [e for e in _entries(log) if e["action"] == "pve_task_wait"]
    assert audited and audited[-1]["mutation"] is False  # waiting is a read


def test_pve_task_wait_surfaces_task_failure(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch, {"status": "stopped", "exitstatus": "command failed: exit code 2"})

    out = server.pve_task_wait(_UPID)

    assert out["finished"] is True
    assert out["succeeded"] is False
    assert out["exitstatus"] == "command failed: exit code 2"
