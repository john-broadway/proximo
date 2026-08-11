"""Confirm=True sweep — PBS node OS admin wrapper welds (src/proximo/tools/pbs_node.py, Wave 2c).

Mirrors the `_wire()`/`_Pbs` idiom in tests/test_confirm_sweep_pbs.py (itself mirroring
tests/test_server_plan.py:110-131, re-used across every prior confirm-sweep module): `_svc` is
monkeypatched (the ONE shared audit ledger lives behind it — `_ledger()` reads `_svc()[3]`) and
`_pbs` is monkeypatched to a fake PbsBackend, matching how pbs_node.py's tools never touch the
PVE ApiBackend.

Each confirm=True call proves the three welds:
  1. return shape — status is the EXECUTED shape ("ok"/"submitted"), never "plan";
  2. the fake PbsBackend captured the underlying call (verb + path + EXACT payload);
  3. the ledger recorded a confirmed mutation — structural asserts only, never exact prose.

`_Pbs._get` is path-aware: CAPTURE-before-plan reads (dns_set's dns_get, time_set's time_get,
network_iface_update/delete's network_iface_get) get a fixed truthy dict; network_iface_create's
collision-check read (network_list) gets an empty list so its plan always takes the no-collision
branch — a dict here would break the `any(i.get(...) for i in ifaces)` iteration.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.config import ProximoConfig

_UPID = "UPID:localhost:00001234:0000ABCD:00000000:00000001:backup:ds1:root@pam:"


class _Pbs:
    """Path-aware fake PbsBackend: records every _get/_post/_put/_delete call. `_get` returns []
    for a bare '/nodes/{node}/network' read (network_iface_create's collision-check CAPTURE) and a
    fixed truthy dict for every other CAPTURE read (dns_set/time_set/network_iface_update/delete)."""

    def __init__(self):
        self.gets: list[tuple[str, dict | None]] = []
        self.posts: list[tuple[str, dict | None]] = []
        self.puts: list[tuple[str, dict | None]] = []
        self.deletes: list[tuple[str, dict | None]] = []

    def _get(self, path, params=None):
        self.gets.append((path, params))
        if path.endswith("/network"):
            return []
        return {"comment": "pre-existing", "timezone": "UTC", "search": "example.test"}

    def _post(self, path, data=None):
        self.posts.append((path, data))
        return None

    def _put(self, path, data=None):
        self.puts.append((path, data))
        return None

    def _delete(self, path, params=None):
        self.deletes.append((path, params))
        return None


class _Api:
    """Minimal PVE API stub — only needed so server._svc() resolves (the ONE shared ledger lives
    behind it); pbs_node.py's tools never touch this backend."""

    def __init__(self):
        self.config = SimpleNamespace(node="pve")


def _wire(tmp_path, monkeypatch):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
        audit_log_path=log,
    )
    api = _Api()
    pbs = _Pbs()
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


# ---------------------------------------------------------------------------
# Homogeneous sweep — table-driven: "confirm=True reaches the right verb/path/data on the
# PbsBackend and records a confirmed mutation".
# ---------------------------------------------------------------------------

_SWEEP_CASES = [
    pytest.param(
        "pbs_node_dns_set",
        dict(search="new.example.test", dns1="9.9.9.9"),
        "ok", "puts", "/nodes/localhost/dns",
        {"search": "new.example.test", "dns1": "9.9.9.9"},
        id="dns_set",
    ),
    pytest.param(
        "pbs_node_time_set",
        dict(timezone="America/Chicago"),
        "ok", "puts", "/nodes/localhost/time",
        {"timezone": "America/Chicago"},
        id="time_set",
    ),
    pytest.param(
        "pbs_node_network_iface_create",
        dict(iface="eth1", iface_type="bridge"),
        "submitted", "posts", "/nodes/localhost/network",
        {"iface": "eth1", "type": "bridge"},
        id="network_iface_create",
    ),
    pytest.param(
        "pbs_node_network_iface_update",
        dict(iface="eth0", options={"mtu": 9000}),
        "ok", "puts", "/nodes/localhost/network/eth0",
        {"mtu": 9000},
        id="network_iface_update",
    ),
    pytest.param(
        "pbs_node_network_iface_delete",
        dict(iface="eth1"),
        "ok", "deletes", "/nodes/localhost/network/eth1",
        None,
        id="network_iface_delete",
    ),
    pytest.param(
        "pbs_node_network_reload",
        dict(),
        "ok", "puts", "/nodes/localhost/network",
        None,
        id="network_reload",
    ),
    pytest.param(
        "pbs_node_network_revert",
        dict(),
        "ok", "deletes", "/nodes/localhost/network",
        None,
        id="network_revert",
    ),
    pytest.param(
        "pbs_node_cert_upload",
        dict(certificates="PEM-CERT-BODY-not-a-real-secret"),
        "ok", "posts", "/nodes/localhost/certificates/custom",
        {"certificates": "PEM-CERT-BODY-not-a-real-secret"},
        id="cert_upload",
    ),
    pytest.param(
        "pbs_node_cert_delete",
        dict(),
        "ok", "deletes", "/nodes/localhost/certificates/custom",
        None,
        id="cert_delete",
    ),
    pytest.param(
        "pbs_node_service_control",
        dict(service="cron", action="restart"),
        "ok", "posts", "/nodes/localhost/services/cron/restart",
        None,
        id="service_control",
    ),
    pytest.param(
        "pbs_node_subscription_set",
        dict(key="pbss-FAKE-KEY-sentinel-not-real"),
        "ok", "puts", "/nodes/localhost/subscription",
        {"key": "pbss-FAKE-KEY-sentinel-not-real"},
        id="subscription_set",
    ),
    pytest.param(
        "pbs_node_subscription_check",
        dict(force=True),
        "ok", "posts", "/nodes/localhost/subscription",
        {"force": True},
        id="subscription_check",
    ),
    pytest.param(
        "pbs_node_subscription_delete",
        dict(),
        "ok", "deletes", "/nodes/localhost/subscription",
        None,
        id="subscription_delete",
    ),
    pytest.param(
        "pbs_node_task_stop",
        dict(upid=_UPID),
        "ok", "deletes", f"/nodes/localhost/tasks/{_UPID}",
        None,
        id="task_stop",
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
    _, pbs, _, log = _wire(tmp_path, monkeypatch)
    fn = getattr(server, tool_name)

    out = fn(confirm=True, **kwargs)

    # weld 1: return shape is the EXECUTED shape, never "plan"
    assert out["status"] == expected_status
    assert out["status"] != "plan"

    # weld 2: the fake captured the underlying call at the expected verb + path, with the EXACT
    # forwarded payload (full dict equality — an accidental extra field now fails).
    calls = getattr(pbs, capture)
    assert calls, f"{tool_name} confirm=True never reached pbs.{capture}"
    call_path, call_data = calls[-1]
    assert call_path == path
    assert call_data == data_exact

    # weld 3: ledger structural asserts — never exact prose
    entry = _confirmed_entry(log, tool_name, expected_status)
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


# ---------------------------------------------------------------------------
# pbs_node_cert_upload — dedicated weld: the TLS private key is UNCONDITIONALLY redacted; it must
# never reach the ledger detail, even though it DOES reach the real PBS API call.
# ---------------------------------------------------------------------------

def test_cert_upload_confirm_forwards_key_to_api_but_redacts_from_ledger(tmp_path, monkeypatch):
    _, pbs, _, log = _wire(tmp_path, monkeypatch)

    out = server.pbs_node_cert_upload(
        certificates="PEM-CERT-BODY", key="PEM-KEY-BODY-not-a-real-secret", confirm=True,
    )

    assert out["status"] == "ok"
    call_path, call_data = pbs.posts[-1]
    assert call_path == "/nodes/localhost/certificates/custom"
    # the real API call DOES carry the key (PBS needs it to install the cert)
    assert call_data == {"certificates": "PEM-CERT-BODY", "key": "PEM-KEY-BODY-not-a-real-secret"}

    entry = _confirmed_entry(log, "pbs_node_cert_upload", "ok")
    assert entry["detail"]["key"] == "[redacted]"
    assert "PEM-KEY-BODY-not-a-real-secret" not in json.dumps(entry)


# ---------------------------------------------------------------------------
# pbs_node_task_log / pbs_node_journal / pbs_node_syslog — reads, not mutations, but confirm the
# wrapper reaches the PbsBackend with the right path (no confirm= gate on a read).
# ---------------------------------------------------------------------------

def test_task_log_read_reaches_pbs_with_pagination(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    server.pbs_node_task_log(upid=_UPID, start=5, limit=10)
    call_path, call_params = pbs.gets[-1]
    assert call_path == f"/nodes/localhost/tasks/{_UPID}/log"
    assert call_params == {"start": 5, "limit": 10}


def test_journal_read_reaches_pbs(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    server.pbs_node_journal(lastentries=50)
    call_path, call_params = pbs.gets[-1]
    assert call_path == "/nodes/localhost/journal"
    assert call_params == {"lastentries": 50}


def test_journal_bare_call_carries_the_default_bound(tmp_path, monkeypatch):
    # 0.32.0: PBS/PMG journals were unbounded-by-default while PVE's defaults
    # lastentries=100 — a sibling inconsistency. The bound must appear in the OUTGOING
    # request; a return-value test cannot see this failure.
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    server.pbs_node_journal()
    call_path, call_params = pbs.gets[-1]
    assert call_path == "/nodes/localhost/journal"
    assert call_params == {"lastentries": 100}


def test_journal_time_range_suppresses_the_default_bound(tmp_path, monkeypatch):
    # lastentries conflicts with a time range on PBS's own schema — the default must
    # never ride along with since/until.
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    server.pbs_node_journal(since=1700000000)
    _, call_params = pbs.gets[-1]
    assert call_params == {"since": 1700000000}


def test_journal_cursor_suppresses_the_default_bound(tmp_path, monkeypatch):
    _, pbs, _, _ = _wire(tmp_path, monkeypatch)
    server.pbs_node_journal(startcursor="abc")
    _, call_params = pbs.gets[-1]
    assert call_params == {"startcursor": "abc"}
