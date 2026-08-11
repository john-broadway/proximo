"""Confirm=True sweep — PMG node core wrapper welds (src/proximo/tools/pmg_node.py, Wave 9a + 9b).

Mirrors the `_wire()`/`_Pmg` idiom already established in
`tests/test_confirm_sweep_pmg_ruledb_objects.py` (itself mirroring
`tests/test_confirm_sweep_pbs_node.py`'s own `_Pbs` template): `_svc` is monkeypatched (the ONE
shared audit ledger lives behind it — `_ledger()` reads `_svc()[3]`) and `_pmg` is monkeypatched
to a fake PmgBackend. This file duplicates its own `_Pmg`/`_wire` rather than importing another
confirm-sweep module's — same self-contained convention every confirm-sweep module in this repo
follows. Starts the `test_confirm_sweep_pmg_node.py` file the Wave 9 draft's own §2 non-negotiable
calls for.

`_Pmg._get` is path-aware: the network_update CAPTURE-before-plan read (and the
type-injection read inside `network_update` itself, when `iface_type` is omitted) gets a fixed
truthy dict with a `type` field; a bare `/nodes/pmg/network` collision-check read (inside
`network_create`'s plan) gets an empty list so the plan always takes the no-collision branch.
`/nodes/pmg/backup` (chunk 9b's `plan_backup_restore` existence-check CAPTURE) returns one
matching backup-file entry; the 5 `/config/ruledb/*` paths (the SAME ruledb-count capture
`plan_ruledb_reset` uses, reused verbatim by `plan_backup_restore`) return empty lists — an
honest, zero-count capture, not a degrade.
`_Pmg._put` special-cases the bare `/nodes/pmg/network` path (network_reload) to return a
STRING (not None) — proving the wrapper passes PMG's schema-confirmed string return through
unchanged (module docstring fact #6), rather than assuming a null/UPID shape. `_Pmg._post`
special-cases the chunk 9b ambiguous-string-return paths (backup restore, clamav/spamassassin
DB update, the 4 service-lifecycle verbs) the same way, via `_SUBMITTED_STATUS_STRING`.

Each confirm=True call proves the three welds every confirm-sweep module proves:
  1. return shape — status is the EXECUTED shape ("ok"/"submitted"), never "plan";
  2. the fake PmgBackend captured the underlying call (verb + path + EXACT payload);
  3. the ledger recorded a confirmed mutation — structural asserts only, never exact prose.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.config import ProximoConfig

_RELOAD_STATUS_STRING = "TASK:localhost:reload-not-a-real-upid"
_SUBMITTED_STATUS_STRING = "TASK:localhost:submitted-not-a-real-upid"
_BACKUP_FILENAME = "pmg-backup_2026_07_17.tgz"

# Paths whose POST response is the chunk 9b ambiguous-string shape (fact #18) — everything
# except the bare '/nodes/pmg/network' PUT (network_reload, handled separately by `_put`).
_SUBMITTED_POST_PREFIXES = (
    "/nodes/pmg/clamav/database",
    "/nodes/pmg/spamassassin/rules",
    "/nodes/pmg/services/",
    f"/nodes/pmg/backup/{_BACKUP_FILENAME}",
)


class _Pmg:
    """Path-aware fake PmgBackend: records every _get/_post/_put/_delete call.

    `_get` returns [] for a bare '/nodes/pmg/network' read (network_create's collision-check
    CAPTURE), one matching backup-file entry for '/nodes/pmg/backup' (chunk 9b's
    `plan_backup_restore` existence check), [] for the 5 '/config/ruledb/*' ruledb-count-capture
    paths (an honest zero-count capture, not a degrade), and a fixed truthy dict (carrying a
    'type' field, for network_update's type-injection) for every other read. `_put` returns a
    STRING for the bare '/nodes/pmg/network' path (network_reload) and None for every other
    path. `_post` returns a STRING for the chunk 9b ambiguous-string-return paths
    (`_SUBMITTED_POST_PREFIXES`) and None for every other path.
    """

    _RULEDB_CAPTURE_PATHS = (
        "/config/ruledb/rules", "/config/ruledb/who", "/config/ruledb/what",
        "/config/ruledb/when", "/config/ruledb/action/objects",
    )

    def __init__(self):
        self.gets: list[tuple[str, dict | None]] = []
        self.posts: list[tuple[str, dict | None]] = []
        self.puts: list[tuple[str, dict | None]] = []
        self.deletes: list[tuple[str, dict | None]] = []

    def _get(self, path, params=None):
        self.gets.append((path, params))
        if path == "/nodes/pmg/network":
            return []
        if path == "/nodes/pmg/backup":
            return [{"filename": _BACKUP_FILENAME, "size": 1, "timestamp": 1}]
        if path in self._RULEDB_CAPTURE_PATHS:
            return []
        return {"method": "static", "type": "bridge", "comment": "pre-existing"}

    def _post(self, path, data=None):
        self.posts.append((path, data))
        if path.startswith(_SUBMITTED_POST_PREFIXES):
            return _SUBMITTED_STATUS_STRING
        return None

    def _put(self, path, data=None):
        self.puts.append((path, data))
        if path == "/nodes/pmg/network":
            return _RELOAD_STATUS_STRING
        return None

    def _delete(self, path, params=None):
        self.deletes.append((path, params))
        return None


class _Api:
    """Minimal PVE API stub — only needed so server._svc() resolves (the ONE shared ledger lives
    behind it); pmg_node.py's tools never touch this backend."""

    def __init__(self):
        self.config = SimpleNamespace(node="pve")


def _wire(tmp_path, monkeypatch):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
        audit_log_path=log,
    )
    api = _Api()
    pmg = _Pmg()
    exec_ = SimpleNamespace()
    ledger = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, exec_, ledger))
    monkeypatch.setattr(server, "_pmg", lambda: (SimpleNamespace(node="pmg"), pmg))
    return cfg, pmg, ledger, log


def _entries(log: str) -> list[dict]:
    with open(log, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _confirmed_entry(log: str, action: str, outcome: str) -> dict:
    entries = [e for e in _entries(log) if e["action"] == action and e["outcome"] == outcome]
    assert len(entries) == 1, f"expected exactly one {action!r}/{outcome!r} ledger entry, got {entries}"
    return entries[0]


# ---------------------------------------------------------------------------
# Homogeneous sweep — table-driven: "confirm=True reaches the right verb/path/data on the
# PmgBackend and records a confirmed mutation".
# ---------------------------------------------------------------------------

_SWEEP_CASES = [
    pytest.param(
        "pmg_node_dns_set",
        dict(search="new.example.test", dns1="9.9.9.9"),
        "ok", "puts", "/nodes/pmg/dns",
        {"search": "new.example.test", "dns1": "9.9.9.9"},
        id="dns_set",
    ),
    pytest.param(
        "pmg_node_time_set",
        dict(timezone="America/Chicago"),
        "ok", "puts", "/nodes/pmg/time",
        {"timezone": "America/Chicago"},
        id="time_set",
    ),
    pytest.param(
        "pmg_node_network_create",
        dict(iface="eth1", iface_type="bridge"),
        "ok", "posts", "/nodes/pmg/network",
        {"iface": "eth1", "type": "bridge"},
        id="network_create",
    ),
    pytest.param(
        "pmg_node_network_update",
        dict(iface="eth0", options={"mtu": 9000}),
        "ok", "puts", "/nodes/pmg/network/eth0",
        {"type": "bridge", "mtu": 9000},
        id="network_update_type_injected",
    ),
    pytest.param(
        "pmg_node_network_update",
        dict(iface="eth0", iface_type="vlan", options={"mtu": 1500}),
        "ok", "puts", "/nodes/pmg/network/eth0",
        {"type": "vlan", "mtu": 1500},
        id="network_update_type_explicit",
    ),
    pytest.param(
        "pmg_node_network_delete",
        dict(iface="eth1"),
        "ok", "deletes", "/nodes/pmg/network/eth1",
        None,
        id="network_delete",
    ),
    pytest.param(
        "pmg_node_network_revert",
        dict(),
        "ok", "deletes", "/nodes/pmg/network",
        None,
        id="network_revert",
    ),
    pytest.param(
        "pmg_node_config_set",
        dict(acme="account=default"),
        "ok", "puts", "/nodes/pmg/config",
        {"acme": "account=default"},
        id="config_set",
    ),
    pytest.param(
        "pmg_node_subscription_set",
        dict(key="pmgs-FAKE-KEY-sentinel-not-real"),
        "ok", "puts", "/nodes/pmg/subscription",
        {"key": "pmgs-FAKE-KEY-sentinel-not-real"},
        id="subscription_set",
    ),
    pytest.param(
        "pmg_node_subscription_check",
        dict(force=True),
        "ok", "posts", "/nodes/pmg/subscription",
        {"force": True},
        id="subscription_check",
    ),
    pytest.param(
        "pmg_node_subscription_delete",
        dict(),
        "ok", "deletes", "/nodes/pmg/subscription",
        None,
        id="subscription_delete",
    ),
    # --- Chunk 9b ---
    pytest.param(
        "pmg_node_task_stop",
        dict(upid="UPID:pmg:00001:0:0:0:test:0:root@pam:"),
        "ok", "deletes", "/nodes/pmg/tasks/UPID:pmg:00001:0:0:0:test:0:root@pam:",
        None,
        id="task_stop",
    ),
    pytest.param(
        "pmg_node_backup_delete",
        dict(filename=_BACKUP_FILENAME),
        "ok", "deletes", f"/nodes/pmg/backup/{_BACKUP_FILENAME}",
        None,
        id="backup_delete",
    ),
    pytest.param(
        "pmg_node_backup_restore",
        dict(filename=_BACKUP_FILENAME),
        "submitted", "posts", f"/nodes/pmg/backup/{_BACKUP_FILENAME}",
        {"config": False, "database": True, "statistic": False},
        id="backup_restore",
    ),
    pytest.param(
        "pmg_node_postfix_queue_action",
        dict(queue="deferred", action="delete", ids="ABC123"),
        "ok", "posts", "/nodes/pmg/postfix/queue/deferred",
        {"action": "delete", "ids": "ABC123"},
        id="postfix_queue_action",
    ),
    pytest.param(
        "pmg_node_postfix_queue_delete_all",
        dict(),
        "ok", "deletes", "/nodes/pmg/postfix/queue",
        None,
        id="postfix_queue_delete_all",
    ),
    pytest.param(
        "pmg_node_postfix_queue_delete_queue",
        dict(queue="hold"),
        "ok", "deletes", "/nodes/pmg/postfix/queue/hold",
        None,
        id="postfix_queue_delete_queue",
    ),
    pytest.param(
        "pmg_node_postfix_queue_message_delete",
        dict(queue="deferred", queue_id="ABC123"),
        "ok", "deletes", "/nodes/pmg/postfix/queue/deferred/ABC123",
        None,
        id="postfix_queue_message_delete",
    ),
    pytest.param(
        "pmg_node_postfix_queue_message_deliver",
        dict(queue="deferred", queue_id="ABC123"),
        "ok", "posts", "/nodes/pmg/postfix/queue/deferred/ABC123",
        None,
        id="postfix_queue_message_deliver",
    ),
    pytest.param(
        "pmg_node_postfix_discard_verify_cache",
        dict(),
        "ok", "posts", "/nodes/pmg/postfix/discard_verify_cache",
        None,
        id="postfix_discard_verify_cache",
    ),
    pytest.param(
        "pmg_node_clamav_database_update",
        dict(),
        "submitted", "posts", "/nodes/pmg/clamav/database",
        None,
        id="clamav_database_update",
    ),
    pytest.param(
        "pmg_node_spamassassin_rules_update",
        dict(),
        "submitted", "posts", "/nodes/pmg/spamassassin/rules",
        None,
        id="spamassassin_rules_update",
    ),
    pytest.param(
        "pmg_node_service_start",
        dict(service="postfix"),
        "submitted", "posts", "/nodes/pmg/services/postfix/start",
        None,
        id="service_start",
    ),
    pytest.param(
        "pmg_node_service_stop",
        dict(service="ssh"),
        "submitted", "posts", "/nodes/pmg/services/ssh/stop",
        None,
        id="service_stop",
    ),
    pytest.param(
        "pmg_node_service_restart",
        dict(service="postfix"),
        "submitted", "posts", "/nodes/pmg/services/postfix/restart",
        None,
        id="service_restart",
    ),
    pytest.param(
        "pmg_node_service_reload",
        dict(service="postfix"),
        "submitted", "posts", "/nodes/pmg/services/postfix/reload",
        None,
        id="service_reload",
    ),
]


@pytest.mark.parametrize(
    "tool_name,kwargs,expected_status,capture,path,data_exact", _SWEEP_CASES,
)
def test_confirm_true_executes_forwards_and_records(
    tmp_path, monkeypatch, tool_name, kwargs, expected_status, capture, path, data_exact,
):
    """confirm=True executes (never 'plan'), the fake captured the forwarded call, and the ledger
    recorded a confirmed mutation — the three welds every confirm-sweep module proves."""
    _, pmg, _, log = _wire(tmp_path, monkeypatch)
    fn = getattr(server, tool_name)

    out = fn(confirm=True, **kwargs)

    # weld 1: return shape is the EXECUTED shape, never "plan"
    assert out["status"] == expected_status
    assert out["status"] != "plan"

    # weld 2: the fake captured the underlying call at the expected verb + path, with the EXACT
    # forwarded payload (full dict equality — an accidental extra field now fails).
    calls = getattr(pmg, capture)
    assert calls, f"{tool_name} confirm=True never reached pmg.{capture}"
    call_path, call_data = calls[-1]
    assert call_path == path
    assert call_data == data_exact

    # weld 3: ledger structural asserts — never exact prose
    entry = _confirmed_entry(log, tool_name, expected_status)
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


def test_network_create_dry_run_never_posts(tmp_path, monkeypatch):
    _, pmg, _, _ = _wire(tmp_path, monkeypatch)
    out = server.pmg_node_network_create(iface="eth1", iface_type="bridge", confirm=False)
    assert out["status"] == "plan"
    assert not pmg.posts


# ---------------------------------------------------------------------------
# CRITICAL fix — the PLAN must disclose a real property deletion BEFORE confirm=True executes
# it, and the disclosed key(s) must be exactly what confirm=True then sends on the wire
# (regression-pin: dry-run disclosure and confirm-path payload can never drift apart again).
# ---------------------------------------------------------------------------

def test_config_set_dry_run_discloses_delete(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_config_set(delete=["acmedomain0"], confirm=False)
    assert out["status"] == "plan"
    joined = " ".join(out["blast_radius"])
    assert "acmedomain0" in joined
    assert "DELETES" in joined


def test_config_set_confirm_payload_matches_plan_disclosure(tmp_path, monkeypatch):
    _, pmg, _, _ = _wire(tmp_path, monkeypatch)
    plan_out = server.pmg_node_config_set(delete=["acmedomain0"], confirm=False)
    exec_out = server.pmg_node_config_set(delete=["acmedomain0"], confirm=True)

    assert exec_out["status"] != "plan"
    call_path, call_data = pmg.puts[-1]
    assert call_path == "/nodes/pmg/config"
    assert call_data == {"delete": "acmedomain0"}
    # regression pin: the key named in the wire payload's "delete" field is the SAME key the
    # dry-run plan disclosed — they can never silently drift apart again.
    assert "acmedomain0" in " ".join(plan_out["blast_radius"])
    assert call_data["delete"] == "acmedomain0"


def test_network_update_dry_run_discloses_delete_props(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_network_update(iface="eth0", delete_props=["comment"], confirm=False)
    assert out["status"] == "plan"
    joined = " ".join(out["blast_radius"])
    assert "comment" in joined
    assert "DELETES" in joined


def test_network_update_confirm_payload_matches_plan_disclosure(tmp_path, monkeypatch):
    _, pmg, _, _ = _wire(tmp_path, monkeypatch)
    plan_out = server.pmg_node_network_update(iface="eth0", delete_props=["comment"], confirm=False)
    exec_out = server.pmg_node_network_update(iface="eth0", delete_props=["comment"], confirm=True)

    assert exec_out["status"] != "plan"
    call_path, call_data = pmg.puts[-1]
    assert call_path == "/nodes/pmg/network/eth0"
    assert call_data["delete"] == "comment"
    assert "comment" in " ".join(plan_out["blast_radius"])


# ---------------------------------------------------------------------------
# MAJOR fix (c) — the confirmed-mutation ledger's detail.iface_type must record the RESOLVED
# type actually sent to PMG, not the raw (often None) caller-time argument.
# ---------------------------------------------------------------------------

def test_network_update_ledger_detail_records_resolved_type_when_injected(tmp_path, monkeypatch):
    _, pmg, _, log = _wire(tmp_path, monkeypatch)
    server.pmg_node_network_update(iface="eth0", options={"mtu": 9000}, confirm=True)

    call_path, call_data = pmg.puts[-1]
    entry = _confirmed_entry(log, "pmg_node_network_update", "ok")
    # the fake's _get returns {"type": "bridge", ...} — the wire payload's resolved type and the
    # ledger detail's recorded type must be the SAME value, not null/None.
    assert call_data["type"] == "bridge"
    assert entry["detail"]["iface_type"] == "bridge"
    assert entry["detail"]["iface_type"] == call_data["type"]


def test_network_update_ledger_detail_records_resolved_type_when_explicit(tmp_path, monkeypatch):
    _, pmg, _, log = _wire(tmp_path, monkeypatch)
    server.pmg_node_network_update(iface="eth0", iface_type="vlan", confirm=True)

    call_path, call_data = pmg.puts[-1]
    entry = _confirmed_entry(log, "pmg_node_network_update", "ok")
    assert call_data["type"] == "vlan"
    assert entry["detail"]["iface_type"] == "vlan"


# ---------------------------------------------------------------------------
# MAJOR fix (d) — plan_network_update flags an explicit iface_type that differs from the
# interface's current type as a TYPE CHANGE, at the wrapper/tool surface a caller actually sees.
# ---------------------------------------------------------------------------

def test_network_update_dry_run_flags_explicit_type_change(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    # the fake's _get returns {"type": "bridge", ...} for eth0 — an explicit "vlan" differs.
    out = server.pmg_node_network_update(iface="eth0", iface_type="vlan", confirm=False)
    joined = " ".join(out["blast_radius"])
    assert "TYPE CHANGE" in joined
    assert "bridge" in joined
    assert "vlan" in joined


def test_network_update_dry_run_does_not_flag_change_when_type_matches_current(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_network_update(iface="eth0", iface_type="bridge", confirm=False)
    joined = " ".join(out["blast_radius"])
    assert "TYPE CHANGE" not in joined


# ---------------------------------------------------------------------------
# MINOR fix (g) — an explicit "delete" key inside **opts (options=) must be rejected rather than
# silently overwritten by/overwriting a separate delete_props argument.
# ---------------------------------------------------------------------------

def test_network_update_reserved_delete_key_in_options_raises(tmp_path, monkeypatch):
    from proximo.backends import ProximoError as _ProximoError
    _wire(tmp_path, monkeypatch)
    with pytest.raises(_ProximoError):
        server.pmg_node_network_update(iface="eth0", options={"delete": "comment"}, confirm=True)


# ---------------------------------------------------------------------------
# pmg_node_network_reload — dedicated weld: PMG's schema-confirmed STRING return (not null) must
# pass through the wrapper's "result" field UNCHANGED — no invented UPID/None shape.
# ---------------------------------------------------------------------------

def test_network_reload_confirm_true_passes_through_the_string_return(tmp_path, monkeypatch):
    _, pmg, _, log = _wire(tmp_path, monkeypatch)

    out = server.pmg_node_network_reload(confirm=True)

    # MAJOR finding (b): the schema-confirmed ambiguous string return must record
    # outcome="submitted" (mirrors pve_network_apply's identical-ambiguity precedent), not "ok".
    assert out["status"] == "submitted"
    assert out["result"] == _RELOAD_STATUS_STRING
    call_path, call_data = pmg.puts[-1]
    assert call_path == "/nodes/pmg/network"
    assert call_data is None

    entry = _confirmed_entry(log, "pmg_node_network_reload", "submitted")
    assert entry["mutation"] is True
    # honest both ways: the raw string ALSO lands in the ledger's own detail, not just the
    # caller-facing envelope's "result" field.
    assert entry["detail"]["raw_result"] == _RELOAD_STATUS_STRING


def test_network_reload_dry_run_never_puts(tmp_path, monkeypatch):
    _, pmg, _, _ = _wire(tmp_path, monkeypatch)
    out = server.pmg_node_network_reload(confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "high"
    assert not pmg.puts


def test_network_revert_risk_is_low(tmp_path, monkeypatch):
    _, _, _, _ = _wire(tmp_path, monkeypatch)
    out = server.pmg_node_network_revert(confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "low"


# ---------------------------------------------------------------------------
# pmg_node_subscription_get — dedicated weld: 'key' must never survive the read, even though the
# fake simulates PMG echoing it back (the schema is too thin to confirm it never does).
# ---------------------------------------------------------------------------

def test_subscription_get_strips_key_defensively(tmp_path, monkeypatch):
    cfg, pmg, _, _ = _wire(tmp_path, monkeypatch)
    pmg._get = lambda path, params=None: {"key": "pmgs-SHOULD-NEVER-SURVIVE", "status": "active"}

    out = server.pmg_node_subscription_get()

    assert "key" not in out
    assert out["status"] == "active"


# ---------------------------------------------------------------------------
# Chunk 9b dedicated welds
# ---------------------------------------------------------------------------

# --- pmg_node_backup_restore — no-undo first line, ruledb-count CAPTURE reuse, submitted +
# raw_result (fact #17/#18) ---

def test_backup_restore_dry_run_states_no_undo_first(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_backup_restore(filename=_BACKUP_FILENAME, confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "high"
    assert "no undo" in out["blast_radius"][0].lower()
    assert "pmg_backup_create" in out["blast_radius"][0]


def test_backup_restore_dry_run_captures_ruledb_counts(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_backup_restore(filename=_BACKUP_FILENAME, confirm=False)
    # the fake's ruledb-family reads all return [] — an honest zero-count capture.
    assert out["current"] == {
        "rules": 0, "who_groups": 0, "what_groups": 0, "when_groups": 0, "action_objects": 0,
    }


def test_backup_restore_confirm_true_records_submitted_and_raw_result(tmp_path, monkeypatch):
    _, pmg, _, log = _wire(tmp_path, monkeypatch)

    out = server.pmg_node_backup_restore(filename=_BACKUP_FILENAME, confirm=True)

    assert out["status"] == "submitted"
    assert out["result"] == _SUBMITTED_STATUS_STRING
    call_path, call_data = pmg.posts[-1]
    assert call_path == f"/nodes/pmg/backup/{_BACKUP_FILENAME}"
    assert call_data == {"config": False, "database": True, "statistic": False}

    entry = _confirmed_entry(log, "pmg_node_backup_restore", "submitted")
    assert entry["mutation"] is True
    assert entry["detail"]["raw_result"] == _SUBMITTED_STATUS_STRING


def test_backup_restore_dry_run_never_posts(tmp_path, monkeypatch):
    _, pmg, _, _ = _wire(tmp_path, monkeypatch)
    out = server.pmg_node_backup_restore(filename=_BACKUP_FILENAME, confirm=False)
    assert out["status"] == "plan"
    assert not pmg.posts


# --- pmg_node_postfix_queue_action — conditional risk (fact #21) ---

def test_postfix_queue_action_delete_dry_run_risk_is_high(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_postfix_queue_action(queue="deferred", action="delete", ids="ABC123", confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "high"


def test_postfix_queue_action_deliver_dry_run_risk_is_medium(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_postfix_queue_action(queue="deferred", action="deliver", ids="ABC123", confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "medium"


# --- pmg_node_service_stop — conditional risk (fact #20), direction-aware blast_radius ---

def test_service_stop_mail_critical_dry_run_risk_is_high(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_service_stop(service="postfix", confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "high"
    assert "mail-flow-critical" in " ".join(out["blast_radius"])


def test_service_stop_other_service_dry_run_risk_is_medium(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_service_stop(service="ssh", confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "medium"
    assert "mail-flow-critical" not in " ".join(out["blast_radius"])


# --- pmg_node_postfix_queue_delete_all / _delete_queue — RISK_HIGH, no scoping ---

def test_postfix_queue_delete_all_dry_run_risk_is_high(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_postfix_queue_delete_all(confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "high"


def test_postfix_queue_delete_queue_dry_run_risk_is_high(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_postfix_queue_delete_queue(queue="hold", confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "high"


# --- pmg_node_postfix_queue_message_deliver — RISK_LOW (mirrors pmg_postfix_flush) ---

def test_postfix_queue_message_deliver_dry_run_risk_is_low(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_postfix_queue_message_deliver(queue="deferred", queue_id="ABC123", confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "low"


# --- pmg_node_task_stop — RISK_HIGH, matches pve_task_stop/pbs_node_task_stop ---

def test_task_stop_dry_run_risk_is_high(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    out = server.pmg_node_task_stop(upid="UPID:pmg:1:2:3:test:0:root@pam:", confirm=False)
    assert out["status"] == "plan"
    assert out["risk"] == "high"


# ---------------------------------------------------------------------------
# Reads — no confirm= gate; prove the wrapper reaches the PmgBackend at the exact expected path.
# ---------------------------------------------------------------------------

_READ_CASES = [
    pytest.param("pmg_node_network_list", dict(), "/nodes/pmg/network", id="network_list"),
    pytest.param("pmg_node_network_get", dict(iface="eth0"), "/nodes/pmg/network/eth0", id="network_get"),
    pytest.param("pmg_node_dns_get", dict(), "/nodes/pmg/dns", id="dns_get"),
    pytest.param("pmg_node_time_get", dict(), "/nodes/pmg/time", id="time_get"),
    pytest.param("pmg_node_config_get", dict(), "/nodes/pmg/config", id="config_get"),
    pytest.param("pmg_node_certificates_info", dict(), "/nodes/pmg/certificates/info", id="certificates_info"),
    pytest.param("pmg_node_services_list", dict(), "/nodes/pmg/services", id="services_list"),
    pytest.param("pmg_node_subscription_get", dict(), "/nodes/pmg/subscription", id="subscription_get"),
    # --- Chunk 9b ---
    pytest.param(
        "pmg_node_task_log", dict(upid="UPID:pmg:1:2:3:test:0:root@pam:"),
        "/nodes/pmg/tasks/UPID:pmg:1:2:3:test:0:root@pam:/log", id="task_log",
    ),
    pytest.param(
        "pmg_node_task_status", dict(upid="UPID:pmg:1:2:3:test:0:root@pam:"),
        "/nodes/pmg/tasks/UPID:pmg:1:2:3:test:0:root@pam:/status", id="task_status",
    ),
    pytest.param("pmg_node_report", dict(), "/nodes/pmg/report", id="report"),
    pytest.param("pmg_node_journal", dict(), "/nodes/pmg/journal", id="journal"),
    pytest.param("pmg_node_backup_list", dict(), "/nodes/pmg/backup", id="backup_list"),
    pytest.param(
        "pmg_node_postfix_queue_list", dict(queue="deferred"),
        "/nodes/pmg/postfix/queue/deferred", id="postfix_queue_list",
    ),
    pytest.param(
        "pmg_node_postfix_queue_message_get", dict(queue="deferred", queue_id="ABC123"),
        "/nodes/pmg/postfix/queue/deferred/ABC123", id="postfix_queue_message_get",
    ),
    pytest.param("pmg_node_clamav_database_get", dict(), "/nodes/pmg/clamav/database", id="clamav_database_get"),
    pytest.param(
        "pmg_node_spamassassin_rules_get", dict(),
        "/nodes/pmg/spamassassin/rules", id="spamassassin_rules_get",
    ),
]


@pytest.mark.parametrize("tool_name,kwargs,path", _READ_CASES)
def test_read_reaches_pmg_at_expected_path(tmp_path, monkeypatch, tool_name, kwargs, path):
    _, pmg, _, _ = _wire(tmp_path, monkeypatch)
    fn = getattr(server, tool_name)
    fn(**kwargs)
    call_path, _ = pmg.gets[-1]
    assert call_path == path
    assert not pmg.posts
    assert not pmg.puts
    assert not pmg.deletes


def test_read_is_audited_as_non_mutation(tmp_path, monkeypatch):
    _, _, _, log = _wire(tmp_path, monkeypatch)
    server.pmg_node_dns_get()
    entries = [e for e in _entries(log) if e["action"] == "pmg_node_dns_get"]
    assert len(entries) == 1
    assert entries[0]["mutation"] is False


def test_network_list_forwards_type_filter(tmp_path, monkeypatch):
    _, pmg, _, _ = _wire(tmp_path, monkeypatch)
    server.pmg_node_network_list(iface_type="bridge")
    call_path, call_params = pmg.gets[-1]
    assert call_path == "/nodes/pmg/network"
    assert call_params == {"type": "bridge"}


# ---------------------------------------------------------------------------
# Registration — this new module's own analogue of test_server_pmg_wiring.py's hardcoded set
# (which, per Wave 8b precedent, is NOT extended for a brand-new module — see wave-8b-report.md
# build decision #8).
# ---------------------------------------------------------------------------

async def test_node_tools_registered_with_fastmcp():
    names = {t.name for t in await server.mcp.list_tools()}
    expected = {
        # Wave 9a (19)
        "pmg_node_network_list", "pmg_node_network_get", "pmg_node_network_create",
        "pmg_node_network_update", "pmg_node_network_delete", "pmg_node_network_revert",
        "pmg_node_network_reload",
        "pmg_node_dns_get", "pmg_node_dns_set",
        "pmg_node_time_get", "pmg_node_time_set",
        "pmg_node_config_get", "pmg_node_config_set",
        "pmg_node_certificates_info",
        "pmg_node_services_list",
        "pmg_node_subscription_get", "pmg_node_subscription_set",
        "pmg_node_subscription_check", "pmg_node_subscription_delete",
        # Wave 9b (24)
        "pmg_node_task_stop", "pmg_node_task_log", "pmg_node_task_status",
        "pmg_node_report", "pmg_node_journal",
        "pmg_node_backup_list", "pmg_node_backup_delete", "pmg_node_backup_restore",
        "pmg_node_postfix_queue_list", "pmg_node_postfix_queue_message_get",
        "pmg_node_postfix_queue_action", "pmg_node_postfix_queue_delete_all",
        "pmg_node_postfix_queue_delete_queue", "pmg_node_postfix_queue_message_delete",
        "pmg_node_postfix_queue_message_deliver", "pmg_node_postfix_discard_verify_cache",
        "pmg_node_clamav_database_get", "pmg_node_clamav_database_update",
        "pmg_node_spamassassin_rules_get", "pmg_node_spamassassin_rules_update",
        "pmg_node_service_start", "pmg_node_service_stop",
        "pmg_node_service_restart", "pmg_node_service_reload",
    }
    assert len(expected) == 43
    assert expected <= names, f"missing from MCP surface: {expected - names}"


def test_journal_bare_call_carries_the_default_bound(tmp_path, monkeypatch):
    # 0.32.0 sibling-parity default bound — see the PBS twin for the rationale; the
    # discriminating assertion is at the request seam, not the return value.
    _, pmg, _, _ = _wire(tmp_path, monkeypatch)
    server.pmg_node_journal()
    call_path, call_params = pmg.gets[-1]
    assert call_path == "/nodes/pmg/journal"
    assert call_params == {"lastentries": 100}


def test_journal_time_range_suppresses_the_default_bound(tmp_path, monkeypatch):
    _, pmg, _, _ = _wire(tmp_path, monkeypatch)
    server.pmg_node_journal(since=1700000000, until=1700003600)
    _, call_params = pmg.gets[-1]
    assert call_params == {"since": 1700000000, "until": 1700003600}


def test_journal_cursor_suppresses_the_default_bound(tmp_path, monkeypatch):
    _, pmg, _, _ = _wire(tmp_path, monkeypatch)
    server.pmg_node_journal(startcursor="abc")
    _, call_params = pmg.gets[-1]
    assert call_params == {"startcursor": "abc"}
