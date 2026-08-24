"""DIAGNOSE pillar tests — read-only evidence gathering + advisory flags.

Fakes only. The battery is fixed read-only argv; flags are advisory. We assert the reliable
(API-structured) flags fire, the heuristic ones are surfaced, partial mode is disclosed, and a
single failing probe doesn't abort the rest.
"""

from __future__ import annotations

from proximo.backends import ExecResult
from proximo.diagnose import diagnose_container, diagnose_node


class _Api:
    def __init__(self, status=None, storage=None, tasks=None):
        self._status = status or {}
        self._storage = storage or []
        self._tasks = tasks or []

    def guest_status(self, vmid, kind="lxc", node=None):
        return self._status

    def node_status(self, node=None):
        return self._status

    def node_storage(self, node=None):
        return self._storage

    def node_tasks(self, node=None, limit=50):
        return self._tasks


class _Exec:
    def __init__(self, outputs=None, raise_on=None):
        self._outputs = outputs or {}
        self._raise_on = raise_on or set()
        self.ran: list = []

    def run(self, ctid, command, timeout=60):
        self.ran.append(command)
        key = command[0]
        if key in self._raise_on:
            raise RuntimeError("probe blew up")
        out = self._outputs.get(key, "ok")
        return ExecResult(str(ctid), " ".join(command), 0, out, "")

    def probe(self, ctid, key):
        """Mirrors ExecBackend.probe: a KEY, never argv. The battery is fixed in backends.py."""
        from proximo.backends import CONTAINER_PROBES
        return self.run(ctid, list(dict(CONTAINER_PROBES)[key]))


# --- container ---

def test_container_flags_not_running():
    api = _Api(status={"status": "stopped", "name": "web"})
    rep = diagnose_container(api, None, "105")
    assert any("not running" in f.lower() for f in rep["flags"])
    assert "probes_skipped" in rep  # exec=None -> partial mode disclosed


def test_container_flags_disk_over_90_from_api():
    api = _Api(status={"status": "running", "disk": 95, "maxdisk": 100})
    rep = diagnose_container(api, None, "105")
    assert any("disk" in f.lower() for f in rep["flags"])


def test_container_runs_battery_and_flags_failed_units():
    api = _Api(status={"status": "running", "disk": 1, "maxdisk": 100})
    ex = _Exec(outputs={"systemctl": "nginx.service loaded failed failed"})
    rep = diagnose_container(api, ex, "105")
    assert "probes" in rep
    assert "failed_units" in rep["probes"]
    assert any("failed unit" in f.lower() for f in rep["flags"])
    # the whole fixed read-only battery ran
    assert {c[0] for c in ex.ran} == {"systemctl", "df", "journalctl", "free", "ss"}


def test_container_no_failed_units_when_clean():
    # `systemctl --failed --no-legend` emits EMPTY output on a clean system (the dead "0 loaded
    # units" footer is suppressed by --no-legend), so the real clean case is "".
    api = _Api(status={"status": "running", "disk": 1, "maxdisk": 100})
    ex = _Exec(outputs={"systemctl": ""})
    rep = diagnose_container(api, ex, "105")
    assert not any("failed unit" in f.lower() for f in rep["flags"])


def test_container_probe_failure_is_recorded_not_fatal():
    api = _Api(status={"status": "running", "disk": 1, "maxdisk": 100})
    ex = _Exec(raise_on={"ss"})  # ss not installed, say (the "listening" probe)
    rep = diagnose_container(api, ex, "105")
    assert "error" in rep["probes"]["listening"]
    assert "output" in rep["probes"]["disk"]  # other probes still ran


def test_container_has_advisory_note():
    rep = diagnose_container(_Api(status={"status": "running"}), None, "105")
    assert "advisory" in rep["note"].lower() or "not a" in rep["note"].lower()


# --- node ---

def test_node_flags_storage_over_90():
    api = _Api(status={"memory": {"used": 1, "total": 100}},
               storage=[{"storage": "local-lvm", "used": 95, "total": 100}])
    rep = diagnose_node(api, "pve")
    assert any("local-lvm" in f for f in rep["flags"])


def test_node_flags_failed_tasks():
    api = _Api(status={}, tasks=[{"upid": "x", "status": "error: boom", "endtime": 2},
                                 {"upid": "y", "status": "OK", "endtime": 3}])
    rep = diagnose_node(api, "pve")
    assert any("failed task" in f.lower() for f in rep["flags"])
    assert len(rep["failed_tasks"]) == 1  # the OK one is excluded


def test_node_running_tasks_not_counted_failed():
    api = _Api(status={}, tasks=[{"upid": "z", "status": "running"}])
    rep = diagnose_node(api, "pve")
    assert rep["failed_tasks"] == []


# === DIAGNOSE redteam hardening (2026-06-07) =================================

def test_inactive_storage_not_flagged_as_full():
    # An offline storage with stale 99% usage must NOT raise a "storage at 99%" (full) alarm —
    # the real signal is that it's inactive, not that it's full.
    api = _Api(storage=[{"storage": "nas", "used": 99, "total": 100, "active": 0}])
    rep = diagnose_node(api, "pve")
    assert not any("at 99%" in f for f in rep["flags"])
    assert any("inactive" in f.lower() for f in rep["flags"])


def test_active_storage_over_90_still_flagged():
    api = _Api(storage=[{"storage": "local-lvm", "used": 95, "total": 100, "active": 1}])
    rep = diagnose_node(api, "pve")
    assert any("95%" in f for f in rep["flags"])


def test_partial_mode_flags_incompleteness():
    # exec off -> probes skipped -> flags must say so (empty flags can't read as "healthy").
    rep = diagnose_container(_Api(status={"status": "running"}), None, "105")
    assert any("incomplete" in f.lower() or "skipped" in f.lower() for f in rep["flags"])


def test_fully_failed_node_diagnosis_flags_incompleteness():
    class _Broken:
        def node_status(self, node=None): raise RuntimeError("down")
        def node_storage(self, node=None): raise RuntimeError("down")
        def node_tasks(self, node=None, limit=50): raise RuntimeError("down")
    rep = diagnose_node(_Broken(), "pve")
    assert rep["flags"], "an all-errored diagnosis must not present empty flags (looks healthy)"


def test_failed_guest_read_flags_incompleteness():
    class _Broken:
        def guest_status(self, vmid, kind="lxc", node=None): raise RuntimeError("down")
    rep = diagnose_container(_Broken(), None, "105")
    assert any("incomplete" in f.lower() or "failed" in f.lower() for f in rep["flags"])


def test_warnings_and_transient_tasks_not_counted_failed():
    # live-faithful shapes: finished rows carry endtime + exitstatus text; transient rows
    # have no endtime yet (2026-08-12 — one classifier repo-wide, classify_task_outcome)
    api = _Api(status={}, tasks=[
        {"upid": "a", "status": "WARNINGS: 1", "endtime": 4},
        {"upid": "b", "status": "stopping"},
        {"upid": "c", "status": "queued"},
        {"upid": "d", "status": "error: boom", "endtime": 5},
        # error PROSE beginning with the bare word is NOT the WARNINGS exitstatus shape
        {"upid": "e", "status": "WARNINGS were emitted then it died", "endtime": 6},
    ])
    rep = diagnose_node(api, "pve")
    assert len(rep["failed_tasks"]) == 2  # the real error + the WARNINGS-prose error
    assert {t["upid"] for t in rep["failed_tasks"]} == {"d", "e"}


def test_storage_infinite_fraction_does_not_crash_or_drop():
    api = _Api(storage=[{"storage": "weird", "used": float("inf"), "total": 100, "active": 1},
                        {"storage": "real", "used": 95, "total": 100, "active": 1}])
    rep = diagnose_node(api, "pve")
    # the inf entry must not OverflowError-crash and drop the real 95% entry's flag
    assert any("real" in f for f in rep["flags"])
