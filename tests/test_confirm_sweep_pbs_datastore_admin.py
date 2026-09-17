"""Confirm=True sweep — PBS datastore-admin remainder wrapper welds
(src/proximo/tools/pbs_datastore_admin.py, Wave 5d — the ACTUAL PBS plane closer).

Mirrors the `_wire()`/`_Pbs` idiom every confirm-sweep module in this repo follows
(self-contained, not imported).

Each homogeneous confirm=True call proves the three welds:
  1. return shape per the LIVE schema: group_delete → "ok" + a synchronous stats object (NOT a
     UPID); group_notes_set → "ok" (null); the six UPID-declared mutations → "submitted" via the
     callable-outcome resolver (with a dedicated null-return → "ok" honesty proof);
  2. the fake PbsBackend captured the underlying call (verb + path + EXACT payload, full dict
     equality — no subset matching);
  3. the ledger recorded a confirmed mutation — structural asserts only, never exact prose.

Headline welds:
  - pbs_group_delete (the bulk-destructive one): DELETE verb with query params, exact payload,
    stats object returned intact in `result`.
  - pbs_datastore_prune's DOUBLE gate: confirm=True with dry_run=True (the default) sends
    dry-run=true on the wire — an agent that confirms without reading still deletes nothing.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.backends import ProximoError
from proximo.config import ProximoConfig


class _Pbs:
    """Path-aware fake PbsBackend: records every _get/_post/_put/_delete call."""

    def __init__(self, get_return=None, post_return="UPID:pbs:1:0:0:0:t:x:root@pam:",
                 put_return=None, delete_return=None):
        self._get_return = get_return
        self._post_return = post_return
        self._put_return = put_return
        self._delete_return = delete_return
        self.gets: list[tuple[str, dict | None]] = []
        self.posts: list[tuple[str, dict | None]] = []
        self.puts: list[tuple[str, dict | None]] = []
        self.deletes: list[tuple[str, dict | None]] = []

    def _get(self, path, params=None):
        self.gets.append((path, params))
        return self._get_return

    def _post(self, path, data=None):
        self.posts.append((path, data))
        return self._post_return

    def _put(self, path, data=None):
        self.puts.append((path, data))
        return self._put_return

    def _delete(self, path, params=None):
        self.deletes.append((path, params))
        return self._delete_return


class _Api:
    """Minimal PVE API stub — only needed so server._svc() resolves (the ONE shared ledger
    lives behind it); pbs_datastore_admin.py's tools never touch this backend."""

    def __init__(self):
        self.config = SimpleNamespace(node="pve")


def _wire(tmp_path, monkeypatch, **pbs_kw):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
        audit_log_path=log,
    )
    api = _Api()
    pbs = _Pbs(**pbs_kw)
    exec_ = SimpleNamespace()
    ledger = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, exec_, ledger))
    monkeypatch.setattr(server, "_pbs", lambda: (SimpleNamespace(), pbs))
    return cfg, pbs, ledger, log


def _entries(log: str) -> list[dict]:
    with open(log, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _confirmed_entry(log: str, action: str, outcome: str) -> dict:
    entries = [e for e in _entries(log) if e["action"] == action and e["outcome"] == outcome]
    assert len(entries) == 1, f"expected exactly one {action!r}/{outcome!r} ledger entry, got {entries}"
    return entries[0]


_STATS = {"removed-groups": 1, "removed-snapshots": 9, "protected-snapshots": 0}

# ---------------------------------------------------------------------------
# Homogeneous sweep — the six UPID-declared mutations (fake _post/_put return a UPID) plus the
# two synchronous ones (group_delete: stats object; group_notes_set: null).
# ---------------------------------------------------------------------------

_SWEEP_CASES = [
    pytest.param(
        "pbs_group_delete",
        dict(store="ds1", backup_type="vm", backup_id="100"),
        "ok", "deletes", "/admin/datastore/ds1/groups",
        {"backup-type": "vm", "backup-id": "100"},
        id="group_delete",
    ),
    pytest.param(
        "pbs_group_notes_set",
        dict(store="ds1", backup_type="vm", backup_id="100", notes="line1\nline2"),
        "ok", "puts", "/admin/datastore/ds1/group-notes",
        {"backup-type": "vm", "backup-id": "100", "notes": "line1\nline2"},
        id="group_notes_set",
    ),
    pytest.param(
        "pbs_group_move",
        dict(store="ds1", backup_type="vm", backup_id="100", ns="src", target_ns="dst",
             merge_group=False),
        "submitted", "posts", "/admin/datastore/ds1/move-group",
        {"backup-type": "vm", "backup-id": "100", "ns": "src", "target-ns": "dst",
         "merge-group": False},
        id="group_move",
    ),
    pytest.param(
        "pbs_namespace_move",
        dict(store="ds1", ns="src", target_ns="dst", delete_source=False, max_depth=2),
        "submitted", "posts", "/admin/datastore/ds1/move-namespace",
        {"ns": "src", "target-ns": "dst", "delete-source": False, "max-depth": 2},
        id="namespace_move",
    ),
    pytest.param(
        "pbs_datastore_mount",
        dict(store="ds1"),
        "submitted", "posts", "/admin/datastore/ds1/mount",
        None,
        id="datastore_mount",
    ),
    pytest.param(
        "pbs_datastore_unmount",
        dict(store="ds1"),
        "submitted", "posts", "/admin/datastore/ds1/unmount",
        None,
        id="datastore_unmount",
    ),
    pytest.param(
        "pbs_datastore_prune",
        dict(store="ds1", keep_last=3, ns="a", max_depth=2, dry_run=False),
        "submitted", "posts", "/admin/datastore/ds1/prune-datastore",
        {"keep-last": 3, "ns": "a", "max-depth": 2},
        id="datastore_prune_live",
    ),
]


@pytest.mark.parametrize(
    "tool_name,kwargs,expected_status,capture,path,data_exact", _SWEEP_CASES,
)
def test_confirm_true_executes_forwards_and_records(
    tmp_path, monkeypatch, tool_name, kwargs, expected_status, capture, path, data_exact,
):
    """confirm=True executes (never 'plan'), the fake captured the forwarded call, and the
    ledger recorded a confirmed mutation — the three welds every confirm-sweep module proves."""
    _, pbs, _, log = _wire(tmp_path, monkeypatch, delete_return=_STATS)
    fn = getattr(server, tool_name)

    out = fn(confirm=True, **kwargs)

    assert out["status"] == expected_status
    assert out["status"] != "plan"

    calls = getattr(pbs, capture)
    assert calls, f"{tool_name} confirm=True never reached pbs.{capture}"
    call_path, call_data = calls[-1]
    assert call_path == path
    assert call_data == data_exact

    entry = _confirmed_entry(log, tool_name, expected_status)
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


def test_s3_refresh_confirm_is_put_and_submitted(tmp_path, monkeypatch):
    """s3-refresh is the one PUT-verb async mutation on this plane — proven separately since
    the fake's _put must return a UPID for it."""
    _, pbs, _, log = _wire(tmp_path, monkeypatch, put_return="UPID:pbs:1:0:0:0:s3:ds1:root@pam:")
    out = server.pbs_datastore_s3_refresh(store="ds1", confirm=True)
    assert out["status"] == "submitted"
    assert pbs.puts[-1] == ("/admin/datastore/ds1/s3-refresh", None)
    assert not pbs.posts
    entry = _confirmed_entry(log, "pbs_datastore_s3_refresh", "submitted")
    assert entry["mutation"] is True


# ---------------------------------------------------------------------------
# Callable-outcome honesty: a null return from any of the UPID-declared mutations records "ok"
# (completed/accepted synchronously), never a phantom "submitted".
# ---------------------------------------------------------------------------

def test_upid_mutation_null_return_records_ok(tmp_path, monkeypatch):
    _, pbs, _, log = _wire(tmp_path, monkeypatch, post_return=None)
    out = server.pbs_datastore_mount(store="ds1", confirm=True)
    assert out["status"] == "ok"
    assert out["status"] != "submitted"
    entry = _confirmed_entry(log, "pbs_datastore_mount", "ok")
    assert entry["mutation"] is True


# ---------------------------------------------------------------------------
# THE HEADLINE WELDS
# ---------------------------------------------------------------------------

def test_group_delete_returns_stats_object_intact(tmp_path, monkeypatch):
    """The bulk-destructive mutation returns a SYNCHRONOUS stats object (module docstring fact
    #1) — the caller's verification data ({removed,protected}-snapshots) must ride back intact
    in result, and the outcome must be 'ok' (never a phantom 'submitted')."""
    _, pbs, _, log = _wire(tmp_path, monkeypatch,
                           delete_return={"removed-groups": 1, "removed-snapshots": 9,
                                          "protected-snapshots": 2})
    out = server.pbs_group_delete(
        store="ds1", backup_type="vm", backup_id="100", error_on_protected=False, confirm=True,
    )
    assert out["status"] == "ok"
    assert out["result"] == {"removed-groups": 1, "removed-snapshots": 9,
                             "protected-snapshots": 2}
    _, call_params = pbs.deletes[-1]
    assert call_params == {"backup-type": "vm", "backup-id": "100",
                           "error-on-protected": False}
    _confirmed_entry(log, "pbs_group_delete", "ok")


def test_datastore_prune_confirm_with_default_dry_run_sends_dry_run_true(tmp_path, monkeypatch):
    """THE DOUBLE GATE: confirm=True with dry_run left at ITS default (True — this tool's
    deliberate flip of the schema's own false default) must send dry-run=true on the wire —
    an agent that confirms without reading still deletes nothing."""
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    out = server.pbs_datastore_prune(store="ds1", keep_last=3, confirm=True)
    assert out["status"] == "submitted"
    _, data = pbs.posts[-1]
    assert data == {"keep-last": 3, "dry-run": True}


def test_datastore_prune_live_run_omits_dry_run_from_wire(tmp_path, monkeypatch):
    """dry_run=False OMITS dry-run from the wire (the schema default) — never an explicit 0."""
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    server.pbs_datastore_prune(store="ds1", keep_last=3, dry_run=False, confirm=True)
    _, data = pbs.posts[-1]
    assert "dry-run" not in data


# ---------------------------------------------------------------------------
# Dry-run (confirm=False) — the PLAN path never touches the PbsBackend's write verbs.
# ---------------------------------------------------------------------------

def test_group_delete_dry_run_never_deletes_and_is_pure(tmp_path, monkeypatch):
    """plan_group_delete is deliberately PURE (no auto-CAPTURE of the ADVERSARIAL groups
    listing — the Wave 4c no-auto-taint precedent): no GET fires either."""
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    out = server.pbs_group_delete(store="ds1", backup_type="vm", backup_id="100", confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "high"
    assert not pbs.deletes
    assert not pbs.gets


def test_group_notes_set_dry_run_captures_but_never_puts(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch, get_return="old notes")
    out = server.pbs_group_notes_set(
        store="ds1", backup_type="vm", backup_id="100", notes="new", confirm=False,
    )
    assert out["status"] == "plan"
    assert out["current"] == {"notes": "old notes"}
    assert not pbs.puts


def test_namespace_move_dry_run_never_posts_and_risk_high(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    out = server.pbs_namespace_move(store="ds1", ns="src", target_ns="dst", confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "high"
    assert not pbs.posts


def test_namespace_move_empty_source_rejected_both_paths(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    with pytest.raises(ProximoError):
        server.pbs_namespace_move(store="ds1", ns="", target_ns="dst", confirm=False)
    with pytest.raises(ProximoError):
        server.pbs_namespace_move(store="ds1", ns="", target_ns="dst", confirm=True)
    assert not pbs.posts


def test_datastore_prune_dry_run_plan_risk_split(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    out = server.pbs_datastore_prune(store="ds1", keep_last=3, dry_run=True, confirm=False)
    assert out["risk"] == "low"
    out = server.pbs_datastore_prune(store="ds1", keep_last=3, dry_run=False, confirm=False)
    assert out["risk"] == "high"
    assert not pbs.posts


def test_mount_unmount_s3_refresh_dry_run_never_write(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    for fn, kw in ((server.pbs_datastore_mount, {}), (server.pbs_datastore_unmount, {}),
                   (server.pbs_datastore_s3_refresh, {})):
        out = fn(store="ds1", confirm=False, **kw)
        assert out["status"] == "plan"
    assert not pbs.posts
    assert not pbs.puts


def test_group_move_dry_run_never_posts(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    out = server.pbs_group_move(
        store="ds1", backup_type="vm", backup_id="100", target_ns="dst", confirm=False,
    )
    assert out["status"] == "plan"
    assert not pbs.posts


# ---------------------------------------------------------------------------
# Reads — the wrapper reaches the PbsBackend with the right path/params (no confirm= gate).
# ---------------------------------------------------------------------------

def test_groups_list_read_reaches_pbs(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch, get_return=[])
    server.pbs_groups_list(store="ds1", ns="a")
    # An EMPTY listing is followed by ONE permissions read (62878a6: an owner-filtered token's
    # empty view is refused, not repeated); this fake's [] there proves nothing, so [] returns.
    assert pbs.gets == [("/admin/datastore/ds1/groups", {"ns": "a"}), ("/access/permissions", None)]


def test_group_notes_get_read_reaches_pbs(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch, get_return="notes")
    out = server.pbs_group_notes_get(store="ds1", backup_type="vm", backup_id="100")
    assert out == "notes"
    assert pbs.gets[-1] == ("/admin/datastore/ds1/group-notes",
                            {"backup-type": "vm", "backup-id": "100"})


def test_snapshot_protected_get_read_reaches_pbs(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch, get_return=True)
    out = server.pbs_snapshot_protected_get(
        store="ds1", backup_type="vm", backup_id="100", backup_time=1700000000,
    )
    assert out is True
    assert pbs.gets[-1] == ("/admin/datastore/ds1/protected",
                            {"backup-type": "vm", "backup-id": "100",
                             "backup-time": 1700000000})


def test_datastore_rrd_read_reaches_pbs(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch, get_return=None)
    server.pbs_datastore_rrd(store="ds1", cf="MAX", timeframe="week")
    assert pbs.gets[-1] == ("/admin/datastore/ds1/rrd", {"cf": "MAX", "timeframe": "week"})


def test_active_operations_read_reaches_pbs(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch, get_return=None)
    server.pbs_datastore_active_operations(store="ds1")
    assert pbs.gets[-1] == ("/admin/datastore/ds1/active-operations", None)


def test_datastores_usage_read_reaches_pbs(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch, get_return=[])
    server.pbs_datastores_usage()
    assert pbs.gets[-1] == ("/status/datastore-usage", None)


def test_remote_scan_read_reaches_pbs(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch, get_return=[])
    server.pbs_remote_scan(name="myremote")
    assert pbs.gets[-1] == ("/config/remote/myremote/scan", None)


def test_remote_scan_groups_uses_namespace_wire_param(tmp_path, monkeypatch):
    """The wire param is `namespace`, NOT `ns` (module docstring fact #10) — pinned at the
    wrapper level too."""
    _, pbs, _, _ = _wire(tmp_path, monkeypatch, get_return=[])
    server.pbs_remote_scan_groups(name="myremote", store="rds", namespace="a/b")
    assert pbs.gets[-1] == ("/config/remote/myremote/scan/rds/groups", {"namespace": "a/b"})


def test_remote_scan_namespaces_read_reaches_pbs(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch, get_return=[])
    server.pbs_remote_scan_namespaces(name="myremote", store="rds")
    assert pbs.gets[-1] == ("/config/remote/myremote/scan/rds/namespaces", None)
