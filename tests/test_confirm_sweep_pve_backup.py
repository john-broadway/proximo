"""Confirm=True sweep — pve_backup wrapper welds (src/proximo/tools/pve_backup.py).

Closes the coverage-audit gap (`.scratch/2026-07-14-tool-coverage-audit-findings.json`, module
`src/proximo/tools/pve_backup.py`, "12 of the 13 mutation tools in this module ... never have
their confirm=True wrapper execute path invoked by any test"): every tool below has its
confirm=False PLAN branch tested elsewhere, but its confirm=True EXECUTE branch — the wrapper's
own `_audited(...)` call — was never invoked through the actual `server.<tool>` wrapper, only
through the underlying op functions (test_backup.py / test_backup_schedules.py), bypassing the
wrapper's own argument-forwarding and `_audited()` wiring. `pve_backup_job_create` is the ONE
tool in this module already covered with confirm=True (tests/test_server_plan.py) and is not
repeated here.

Mirrors the `_wire()` idiom in tests/test_server_plan.py:110-131 (already re-used and
review-approved in tests/test_confirm_sweep_pve_guest.py and
tests/test_confirm_sweep_pve_firewall_network.py): both `proximo.server._svc` (PVE plane) and
`proximo.server._pbs` (PBS plane — 5 of these 13 tools route through it) are monkeypatched to
fake backends + a REAL AuditLedger in tmp_path, so each confirm=True call proves three welds:
  1. return shape — status is the EXECUTED shape ("ok"/"submitted"), never "plan";
  2. the fake backend captured the underlying call (verb + path + data);
  3. the ledger recorded a confirmed mutation — structural asserts only (action, mutation,
     outcome, detail.confirmed), never exact prose.

Two dedicated tests beyond the generic sweep, called out by the audit-fixes plan (Task 5):
  - pve_backup_delete's confirm=True honesty fix (Fix A): backup_delete() may return None for a
    synchronous (dir-storage) delete rather than a task UPID (backup.py's own documented
    contract) — the wrapper must not claim "submitted" (still in-flight) when the delete has
    already completed synchronously.
  - plan_backup_job_create's guest-selection-kwargs echo (Fix B) is a backup_schedules.py-level
    fix — its dedicated tests live in tests/test_backup_schedules.py (TestPlanBackupJobCreate),
    since it's a PLAN-builder concern, not a confirm=True wrapper-execute concern.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import quote

import pytest

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.config import ProximoConfig

_VALID_VOLID = "local:backup/vzdump-lxc-102-2026_06_08.tar.zst"


class _Api:
    """Path-aware fake ApiBackend: records every _post/_put/_delete call, and answers _get /
    guest_status reads just enough for the PLAN builders (which always run first, even on
    confirm=True) to resolve without raising."""

    def __init__(self, node: str = "pve"):
        self.config = SimpleNamespace(node=node)
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict | None]] = []
        self.puts: list[tuple[str, dict | None]] = []
        self.deletes: list[tuple[str, dict | None]] = []

    def guest_status(self, vmid, kind="lxc", node=None):
        # plan_restore's one safe read -- any dict (existing guest) is enough for the plan to
        # build without raising; which risk branch it takes doesn't matter for these welds.
        return {"status": "stopped", "name": "restored-guest"}

    def _get(self, path):
        self.gets.append(path)
        # backup_job_get / replication_get (CAPTURE-or-declare honesty in the UPDATE/DELETE
        # plan builders) -- any dict works.
        return {"id": "daily", "schedule": "sat 02:00", "storage": "local"}

    def _post(self, path, data=None):
        self.posts.append((path, data))
        return "UPID:pve:00001:0:0:0:task:100:root@pam:"

    def _put(self, path, data=None):
        self.puts.append((path, data))
        return None

    def _delete(self, path, params=None):
        self.deletes.append((path, params))
        return "UPID:pve:00002:0:0:0:task:100:root@pam:"


class _Pbs:
    """Path-aware fake PbsBackend, mirroring _Api for the PBS-plane tools in this module."""

    def __init__(self):
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict | None]] = []
        self.puts: list[tuple[str, dict | None]] = []
        self.deletes: list[tuple[str, dict | None]] = []

    def _get(self, path, params=None):
        self.gets.append(path)
        return {"id": "nightly", "schedule": "sat 02:00", "store": "ds1"}

    def _post(self, path, data=None):
        self.posts.append((path, data))
        return "UPID:pbs:00001:0:0:0:task:100:root@pam:"

    def _put(self, path, data=None):
        self.puts.append((path, data))
        return None

    def _delete(self, path, params=None):
        self.deletes.append((path, params))
        return None


def _wire(tmp_path, monkeypatch):
    """The `_wire()` idiom from tests/test_server_plan.py:110-131, extended with the separate
    `_pbs()` seam (tests/test_server_new_wiring.py:78-89's pattern) for the 5 PBS-plane tools."""
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
        ct_allowlist=frozenset({"*"}), audit_log_path=log,
    )
    api = _Api()
    pbs = _Pbs()
    exec_ = SimpleNamespace()  # unused by pve_backup's non-exec wrappers
    ledger = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, exec_, ledger))
    monkeypatch.setattr(server, "_pbs", lambda: (SimpleNamespace(), pbs))
    return cfg, api, pbs, ledger, log


def _entries(log: str) -> list[dict]:
    with open(log, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _confirmed_entry(log: str, action: str, outcome: str) -> dict:
    entries = [e for e in _entries(log) if e["action"] == action and e["outcome"] == outcome]
    assert len(entries) == 1, f"expected exactly one {action!r}/{outcome!r} ledger entry, got {entries}"
    return entries[0]


# ---------------------------------------------------------------------------
# Homogeneous sweep — table-driven over all 13 tools: "confirm=True reaches the right
# verb/path/data on the right backend (PVE api or PBS) and records a confirmed mutation".
# ---------------------------------------------------------------------------

_SWEEP_CASES = [
    pytest.param(
        "pve_backup_delete",
        dict(storage="local", volid=_VALID_VOLID),
        "submitted", "api", "deletes",
        f"/nodes/pve/storage/local/content/{quote(_VALID_VOLID, safe='')}",
        None,
        id="backup_delete",
    ),
    pytest.param(
        "pve_restore",
        dict(vmid="150", archive=_VALID_VOLID, storage="local", kind="lxc"),
        "submitted", "api", "posts", "/nodes/pve/lxc",
        # unique=1: a restore to a NEW vmid (no force) asks PVE for a fresh MAC (issue #82).
        {"vmid": "150", "ostemplate": _VALID_VOLID, "storage": "local", "restore": 1, "unique": 1},
        id="restore",
    ),
    pytest.param(
        "pve_backup",
        dict(vmid="150", storage="local", mode="snapshot", kind="lxc"),
        "submitted", "api", "posts", "/nodes/pve/vzdump",
        # vzdump_backup() always builds data={vmid, storage, mode, compress} unconditionally —
        # compress defaults to "zstd" on the tool signature and is forwarded even though this
        # test never overrides it.
        {"vmid": "150", "storage": "local", "mode": "snapshot", "compress": "zstd"},
        id="backup",
    ),
    pytest.param(
        "pve_backup_job_update",
        dict(job_id="daily", schedule="sun 03:00"),
        "ok", "api", "puts", "/cluster/backup/daily",
        {"schedule": "sun 03:00"},
        id="backup_job_update",
    ),
    pytest.param(
        "pve_backup_job_delete",
        dict(job_id="daily"),
        "ok", "api", "deletes", "/cluster/backup/daily",
        None,
        id="backup_job_delete",
    ),
    pytest.param(
        "pve_replication_create",
        dict(rep_id="100-0", rep_type="local", target="node2"),
        "ok", "api", "posts", "/cluster/replication",
        {"id": "100-0", "type": "local", "target": "node2"},
        id="replication_create",
    ),
    pytest.param(
        "pve_replication_update",
        dict(rep_id="100-0", rate=50.0),
        "ok", "api", "puts", "/cluster/replication/100-0",
        {"rate": 50.0},
        id="replication_update",
    ),
    pytest.param(
        "pve_replication_delete",
        dict(rep_id="100-0"),
        "ok", "api", "deletes", "/cluster/replication/100-0",
        None,
        id="replication_delete",
    ),
    pytest.param(
        "pbs_job_create",
        dict(job_type="sync", job_id="nightly", store="ds1"),
        "ok", "pbs", "posts", "/config/sync",
        {"id": "nightly", "store": "ds1"},
        id="pbs_job_create",
    ),
    pytest.param(
        "pbs_job_update",
        dict(job_type="sync", job_id="nightly", comment="updated"),
        "ok", "pbs", "puts", "/config/sync/nightly",
        {"comment": "updated"},
        id="pbs_job_update",
    ),
    pytest.param(
        "pbs_job_delete",
        dict(job_type="sync", job_id="nightly"),
        "ok", "pbs", "deletes", "/config/sync/nightly",
        None,
        id="pbs_job_delete",
    ),
    pytest.param(
        "pbs_job_run",
        dict(job_type="prune", job_id="nightly"),
        "submitted", "pbs", "posts", "/admin/prune/nightly/run",
        None,
        id="pbs_job_run",
    ),
    pytest.param(
        "pbs_realm_sync",
        dict(realm="ldap1", remove_vanished=True),
        "submitted", "pbs", "posts", "/access/domains/ldap1/sync",
        {"remove-vanished": True},
        id="pbs_realm_sync",
    ),
]


@pytest.mark.parametrize(
    "tool_name,kwargs,expected_status,backend,capture,path,data_exact", _SWEEP_CASES,
)
def test_confirm_true_executes_forwards_and_records(
    tmp_path, monkeypatch, tool_name, kwargs, expected_status, backend, capture, path, data_exact,
):
    """confirm=True executes (never 'plan'), the fake backend captured the forwarded call, and
    the ledger recorded a confirmed mutation — the three welds the audit found untested."""
    _, api, pbs, _, log = _wire(tmp_path, monkeypatch)
    fn = getattr(server, tool_name)

    out = fn(confirm=True, **kwargs)

    # weld 1: return shape is the EXECUTED shape, never "plan"
    assert out["status"] == expected_status
    assert out["status"] != "plan"

    # weld 2: the fake backend captured the underlying call at the expected verb + path, with
    # the EXACT forwarded payload (full dict equality — an accidental extra field now fails).
    fake = api if backend == "api" else pbs
    calls = getattr(fake, capture)
    assert calls, f"{tool_name} confirm=True never reached {backend}.{capture}"
    call_path, call_data = calls[-1]
    assert call_path == path
    assert call_data == data_exact

    # weld 3: ledger structural asserts — never exact prose
    entry = _confirmed_entry(log, tool_name, expected_status)
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


# ---------------------------------------------------------------------------
# Fix A (test-first): pve_backup_delete must not claim "submitted" (still in-flight) when
# backup_delete() reports a synchronous, no-UPID delete (dir-backed storage). backup.py's own
# docstring (lines ~110-115) documents this contract; test_backup.py's
# test_backup_delete_returns_none_for_sync_delete proves the op's own return. Before the fix,
# pve_backup.py's wrapper hardcoded outcome="submitted" regardless of what backup_delete()
# actually reported.
#
# Task 5b closes the residual Task 5 left open: back then, the tool's RETURNED status was
# corrected but the raw LEDGER `outcome` field still literally read "submitted" (fixed at
# _audited()'s call site, before backup_delete() ran). Now that _audited() accepts a callable
# outcome resolved AFTER fn() succeeds (server.py), the ledger entry itself is honest too --
# these tests assert the ledger's outcome field directly, not just the envelope's status.
# ---------------------------------------------------------------------------


def test_backup_delete_confirm_sync_delete_reports_ok_not_submitted(tmp_path, monkeypatch):
    """A directory-backed storage delete completes SYNCHRONOUSLY -- backup_delete() returns
    None, not a task UPID. Both the tool's returned status AND the ledger's recorded outcome
    must reflect that (an operator/agent reading "submitted" -- or auditing the ledger after
    the fact -- would wrongly believe a delete of a disaster-recovery backup is still in-flight,
    when it has already finished)."""
    _, api, _, _, log = _wire(tmp_path, monkeypatch)
    monkeypatch.setattr(api, "_delete", lambda path, params=None: None)

    out = server.pve_backup_delete(storage="local", volid=_VALID_VOLID, confirm=True)

    assert out["status"] == "ok"
    assert out["status"] != "submitted"
    assert out["result"] is None

    # the ledger's raw outcome field is now honest too -- exactly one confirmed entry, "ok".
    entry = _confirmed_entry(log, "pve_backup_delete", "ok")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


def test_backup_delete_confirm_async_delete_still_reports_submitted(tmp_path, monkeypatch):
    """Regression guard for the fix above: when backup_delete() DOES return a task UPID
    (the async path — most storage backends), the honest label is still "submitted", not "ok" --
    both in the tool's returned status and in the ledger's recorded outcome."""
    _, api, _, _, log = _wire(tmp_path, monkeypatch)
    # default fake _delete already returns a UPID string (see _Api._delete above)

    out = server.pve_backup_delete(storage="local", volid=_VALID_VOLID, confirm=True)

    assert out["status"] == "submitted"
    assert out["result"] == "UPID:pve:00002:0:0:0:task:100:root@pam:"

    entry = _confirmed_entry(log, "pve_backup_delete", "submitted")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


# ---------------------------------------------------------------------------
# Wave 5c review Finding 4 (fixed in Wave 5d): pbs_job_run hardcoded outcome="submitted", but
# the LIVE schema declares POST /admin/{prune,sync,verify}/{id}/run ALL return null — the ledger
# recorded a synchronously-completed manual job trigger as still in-flight. Same fix shape as
# Fix A above (pve_backup_delete): the callable-outcome idiom resolves the honest label from the
# real return value. pbs_scheduled_job_run coerces a null response to "" (`... or ""`), so the
# resolver keys on falsy, not `is None`.
# ---------------------------------------------------------------------------

def test_pbs_job_run_null_result_reports_ok_not_submitted(tmp_path, monkeypatch):
    """The schema-declared case: /admin/{type}/{id}/run returns null. The wrapper must record
    "ok" (completed synchronously) in BOTH the returned status and the raw ledger outcome —
    never "submitted" (a UPID that never existed, unpollable)."""
    _, _, pbs, _, log = _wire(tmp_path, monkeypatch)
    monkeypatch.setattr(pbs, "_post", lambda path, data=None: None)

    out = server.pbs_job_run(job_type="prune", job_id="nightly", confirm=True)

    assert out["status"] == "ok"
    assert out["status"] != "submitted"

    entry = _confirmed_entry(log, "pbs_job_run", "ok")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


def test_pbs_job_run_upid_result_still_reports_submitted(tmp_path, monkeypatch):
    """Regression guard: if a live PBS DOES return a UPID (the schema may be under-documented —
    the now-familiar returns-null-despite-real-work quirk cuts both ways), the honest label is
    still "submitted". The default fake _post returns a UPID (see _Pbs._post above)."""
    _, _, _, _, log = _wire(tmp_path, monkeypatch)

    out = server.pbs_job_run(job_type="verify", job_id="nightly", confirm=True)

    assert out["status"] == "submitted"
    entry = _confirmed_entry(log, "pbs_job_run", "submitted")
    assert entry["mutation"] is True
