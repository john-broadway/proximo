"""GOLDEN per-wrapper request-shape sweep.

WHY this file exists (2026-07-01 review finding): server.py hand-writes 352 `@mcp.tool()`
wrappers. Two structural AST sweeps already prove every mutating wrapper HAS a confirm gate
(test_server_plan.py::test_every_mutating_tool_is_confirm_gated) and that its mutation path
reaches the containment gate (test_every_manual_audit_path_tool_reaches_containment_gate).
Neither proves the wrapper forwards the RIGHT target/args/literals. The highest-probability
real harm to a keys-holding user is a copy-paste wrapper bug: a wrapper that builds a plan for
the wrong action, forwards the wrong id/target, or passes a wrong mutation/outcome literal — a
fully-audited WRONG mutation. This sweep closes that specific gap.

APPROACH: enumerate every tool the same way test_server_plan.py / test_tool_count.py do (the
live FastMCP registry, `server.mcp.list_tools()`). For every MUTATING tool (has a `confirm`
param — the complement is the `_READ_ONLY_TOOLS` allowlist in test_server_plan.py), synthesize
minimal, deterministic, per-parameter-NAME sentinel values from `inspect.signature`, call it with
confirm=False (dry-run — never executes a real mutation), and assert the returned Plan is
INTERNALLY CONSISTENT with the call:
  - status == "plan" (never executed)
  - action == the tool's own name (the _plan() label; a copy-pasted wrapper that forwards the
    WRONG label would be caught here)
  - target is a non-empty string
  - risk is one of the known RISK_* levels
  - EVERY "identity-bearing" argument we passed (vmid, newid, storage, snapname, remote,
    datastore, ns, ogroup, id_, roleid, ...) is reflected as a substring somewhere in
    target+change — i.e. the preview is actually ABOUT the guest/object/target we asked about,
    not a different one. This is the check that catches a wrapper whose plan/target/action
    doesn't match its own name+args (wrong var forwarded, swapped params, hardcoded constant).

Backends are FAKE (no real network, no real mutation is possible even if a bug made confirm
matter). Most mutating tools' plan_*/build() functions are PURE (no backend I/O at all — the
whole "no-op unless building a preview" design surfaced by this sweep: only a handful of
plan_* builders read anything, see the module-level comment near _FakeApi for the exact list).

Coverage is reported honestly at the bottom via test_sweep_coverage_is_honest: every mutating
tool is either (a) shape-asserted here, or (b) on NOT_SHAPE_ASSERTED with a stated reason — no
tool is silently skipped.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
from types import SimpleNamespace
from typing import Any

import pytest

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.backends import ExecResult, _check_ceph_daemon_id, _check_node
from proximo.config import ProximoConfig

# ---------------------------------------------------------------------------
# Tool enumeration — same technique as test_server_plan.py / test_tool_count.py:
# the live FastMCP registry, not a hand-maintained list.
# ---------------------------------------------------------------------------


def _all_tool_names() -> list[str]:
    return [t.name for t in asyncio.run(server.mcp.list_tools())]


def _is_mutating(name: str) -> bool:
    fn = getattr(server, name)
    return "confirm" in inspect.signature(fn).parameters


_ALL_TOOLS = _all_tool_names()
MUTATING_TOOLS = sorted(n for n in _ALL_TOOLS if _is_mutating(n))
READ_TOOLS = sorted(n for n in _ALL_TOOLS if not _is_mutating(n))


# ---------------------------------------------------------------------------
# Fake backends. Only a NARROW backend surface is reachable on the confirm=False (dry-run)
# path we exercise here: the mutation-executing calls (api.snapshot_create, api.guest_power,
# node_disk_wipe, agent_*, ...) only run when confirm=True, which this sweep never sets. An
# AST sweep of every `plan_*` builder (the dry-run "build()" callable _plan() invokes) turned
# up exactly this set of backend reads:
#   PVE:  api._get, api.guest_status, api.snapshot_list, api.list_guests, api.node_time_get,
#         api.node_hosts_get   (+ the blast-radius engine's own api._get/guest_status/snapshot_list)
#   PBS:  pbs._get   (generic REST verb only)
#   PMG:  pmg._get   (generic REST verb only)
# Every one of those reads is wrapped in a try/except in the source (planning.py, blast.py,
# config_edit.py, ...) that degrades to an honesty disclaimer on failure rather than raising —
# so a minimal, permissive fake is sufficient and does not mask real behavior.


class _FakeApi:
    """Fake PVE backend. Records every call; returns plausible, sentinel-matching data."""

    def __init__(self) -> None:
        self.config = SimpleNamespace(node="node1", username="root@pam")
        self.calls: list[tuple[str, tuple, dict]] = []

    def _record(self, name: str, *a: Any, **kw: Any) -> None:
        self.calls.append((name, a, kw))

    def _get(self, path: str, params: dict | None = None) -> list:
        self._record("_get", path, params=params)
        return []  # falsy -> every caller's `or {}` / `or []` fallback kicks in safely

    def _post(self, path: str, data: dict | None = None) -> str:
        self._record("_post", path, data=data)
        return "UPID:node1:00000001:00000000:00000000:sentinel:100:root@pam:"

    def _put(self, path: str, data: dict | None = None) -> None:
        self._record("_put", path, data=data)
        return None

    def _delete(self, path: str, params: dict | None = None) -> None:
        self._record("_delete", path, params=params)
        return None

    def guest_status(self, vmid, kind="lxc", node=None) -> dict:
        self._record("guest_status", vmid, kind, node)
        return {"status": "running", "name": "sentinel-guest", "uptime": 500,
                "cpu": 0.1, "mem": 1, "maxmem": 2}

    def guest_power(self, vmid, action, kind="lxc", node=None) -> dict:
        self._record("guest_power", vmid, action, kind, node)
        return {"ok": True}

    def snapshot_list(self, vmid, kind="lxc", node=None) -> list[dict]:
        self._record("snapshot_list", vmid, kind, node)
        return [{"name": "snap1", "snaptime": 1700000000}]

    def snapshot_create(self, vmid, snapname, kind="lxc", node=None, description=None) -> str:
        self._record("snapshot_create", vmid, snapname, kind, node, description)
        return "UPID:node1:00000002:00000000:00000000:qmsnapshot:100:root@pam:"

    def snapshot_rollback(self, vmid, snapname, kind="lxc", node=None) -> str:
        self._record("snapshot_rollback", vmid, snapname, kind, node)
        return "UPID:node1:00000003:00000000:00000000:qmrollback:100:root@pam:"

    def snapshot_delete(self, vmid, snapname, kind="lxc", node=None, force=False) -> str:
        self._record("snapshot_delete", vmid, snapname, kind, node, force)
        return "UPID:node1:00000004:00000000:00000000:qmdelsnapshot:100:root@pam:"

    def task_status(self, upid, node=None) -> dict:
        self._record("task_status", upid, node)
        return {"status": "stopped", "exitstatus": "OK"}

    def list_guests(self, node=None) -> list[dict]:
        self._record("list_guests", node)
        return [{"vmid": "100", "type": "lxc", "name": "sentinel-guest"}]

    def node_status(self, node=None) -> dict:
        self._record("node_status", node)
        return {"uptime": 1000, "memory": {"used": 1, "total": 100}}

    def node_storage(self, node=None) -> list[dict]:
        self._record("node_storage", node)
        return [{"storage": "storage1", "used": 1, "total": 100}]

    def node_tasks(self, node=None, limit=50) -> list:
        self._record("node_tasks", node, limit)
        return []

    def node_time_get(self, node=None) -> dict:
        self._record("node_time_get", node)
        return {"timezone": "UTC", "time": 1700000000}

    def node_hosts_get(self, node=None) -> dict:
        self._record("node_hosts_get", node)
        return {"data": "127.0.0.1 localhost\n", "digest": "abc123"}

    def version(self) -> dict:
        self._record("version")
        return {"version": "9.0"}

    def access_permissions(self) -> dict:
        self._record("access_permissions")
        return {}

    def _ceph_daemon_target(self, node, explicit_id, label):
        # Mirrors ApiBackend._ceph_daemon_target — the mon/mgr/mds CREATE plan factories call
        # this shared resolution (Wave 6b review Nit); it must return a real (node, id) 2-tuple,
        # not the generic __getattr__ catch-all's bare {} (which isn't unpackable to 2 values).
        self._record("_ceph_daemon_target", node, explicit_id, label)
        _check_node(node)
        n = node or self.config.node
        ident = _check_ceph_daemon_id(explicit_id, label) if explicit_id is not None else n
        return n, ident

    # confirm=True-only execution calls — never reached by this sweep (dry-run only), but
    # implemented anyway so a future confirm=True sweep (or a stray real call) doesn't crash.
    def __getattr__(self, name: str):
        def _generic(*a: Any, **kw: Any) -> dict:
            self._record(name, *a, **kw)
            return {}
        return _generic


class _FakePbs:
    """Fake PBS backend — generic REST verbs only (confirmed by the plan_* AST sweep above)."""

    def __init__(self) -> None:
        self.config = SimpleNamespace(base_url="https://pbs1:8007/api2/json")
        self.calls: list[tuple[str, tuple, dict]] = []

    def _get(self, path: str, params: dict | None = None) -> list:
        self.calls.append(("_get", (path,), {"params": params}))
        return []

    def _post(self, path: str, data: dict | None = None) -> str:
        self.calls.append(("_post", (path,), {"data": data}))
        return "UPID:pbs1:00000001:00000000:00000000:sentinel:ds1:root@pam:"

    def _put(self, path: str, data: dict | None = None) -> None:
        self.calls.append(("_put", (path,), {"data": data}))
        return None

    def _delete(self, path: str, params: dict | None = None) -> None:
        self.calls.append(("_delete", (path,), {"params": params}))
        return None


class _FakePmg:
    """Fake PMG backend — generic REST verbs only (confirmed by the plan_* AST sweep above)."""

    def __init__(self) -> None:
        self.config = SimpleNamespace(node="pmg1", username="root@pam")
        self.calls: list[tuple[str, tuple, dict]] = []

    def _get(self, path: str, params: dict | None = None) -> list:
        self.calls.append(("_get", (path,), {"params": params}))
        return []

    def _post(self, path: str, data: dict | None = None) -> None:
        self.calls.append(("_post", (path,), {"data": data}))
        return None

    def _delete(self, path: str, params: dict | None = None) -> None:
        self.calls.append(("_delete", (path,), {"params": params}))
        return None

    def _put(self, path: str, data: dict | None = None) -> None:
        self.calls.append(("_put", (path,), {"data": data}))
        return None


class _FakeExec:
    """Fake in-container exec backend (ssh -> pct). Used by ct_exec/ct_psql/ct_logs."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple, dict]] = []

    def run(self, ctid: str, command: list[str], *, timeout: int = 60) -> ExecResult:
        self.calls.append(("run", (ctid, command), {"timeout": timeout}))
        return ExecResult(str(ctid), " ".join(command), 0, "sentinel-out", "")

    def psql(self, ctid: str, sql: str, *, db: str = "postgres", user: str = "postgres",
             timeout: int = 60) -> ExecResult:
        self.calls.append(("psql", (ctid, sql), {"db": db, "user": user, "timeout": timeout}))
        return ExecResult(str(ctid), sql, 0, "sentinel-out", "")

    def logs(self, ctid: str, unit: str, *, lines: int = 50) -> ExecResult:
        self.calls.append(("logs", (ctid, unit), {"lines": lines}))
        return ExecResult(str(ctid), unit, 0, "sentinel-out", "")


class _FakePdm:
    """Fake PDM (Proxmox Datacenter Manager) backend. Every pdm_* tool is READ-ONLY (no confirm
    param) — a generic recorder is enough; no plan/build path reaches it."""

    def __init__(self) -> None:
        self.config = SimpleNamespace(base_url="https://pdm1:8443/api2/json")
        self.calls: list[tuple[str, tuple, dict]] = []

    def __getattr__(self, name: str):
        def _generic(*a: Any, **kw: Any) -> dict:
            self.calls.append((name, a, kw))
            return {}
        return _generic


@pytest.fixture
def wired(tmp_path, monkeypatch):
    """Wire server._svc / _pbs / _pmg to the fakes above, with a REAL ledger (tmp_path) so the
    PLAN->PROVE weld still runs (mirrors test_server_plan.py / test_server_new_wiring.py)."""
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://pve1:8006/api2/json", node="node1", token_path="/run/x",
        audit_log_path=log,
        # ct_exec/ct_psql and the qemu-agent tools are OFF by default (safe default); flip them
        # on + allow every ctid/vmid so this sweep can reach their dry-run PLAN path too.
        enable_exec=True, ct_allowlist=frozenset({"*"}),
        enable_agent=True, agent_allowlist=frozenset({"*"}),
    )
    api = _FakeApi()
    pbs = _FakePbs()
    pmg = _FakePmg()
    pdm = _FakePdm()
    exec_ = _FakeExec()
    ledger = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, exec_, ledger))
    monkeypatch.setattr(server, "_pbs", lambda: (SimpleNamespace(), pbs))
    monkeypatch.setattr(server, "_pmg", lambda: (SimpleNamespace(node="pmg1"), pmg))
    monkeypatch.setattr(server, "_pdm", lambda: (SimpleNamespace(), pdm))
    return SimpleNamespace(cfg=cfg, api=api, pbs=pbs, pmg=pmg, pdm=pdm, exec_=exec_,
                           ledger=ledger, log=log)


# ---------------------------------------------------------------------------
# Sentinel synthesis — deterministic, distinguishable-by-name values keyed by parameter NAME,
# chosen to satisfy the src validators (backends._check_vmid wants digits, PMG ruledb ids want
# digits, ACME domains want a dotted FQDN, ...). Where a name is legitimately overloaded across
# tools with INCOMPATIBLE formats (e.g. "action": start/stop/.../ vs ACCEPT/DROP/REJECT vs
# deliver/delete/...), the default here satisfies the majority and CUSTOM_KWARGS below overrides
# the rest — this is expected and is not "cheating the test": every override is a real, cited
# format constraint (see the comment on each), not a workaround for a code bug.
# ---------------------------------------------------------------------------

SENTINELS: dict[str, Any] = {
    "vmid": "100",
    "newid": "101",
    # projection.project_rows: 'all' | comma list of fields actually present in the response —
    # 'all' is the one value valid against any backend payload
    "fields": "all",
    "ctid": "100",
    "node": "node1",
    "kind": "lxc",
    "storage": "storage1",
    "target_storage": "storage2",
    "snapname": "snap1",
    "action": "start",  # pve_guest_power / node_service_control / pmg_service_control default
    "mode": "snapshot",  # vzdump backup mode (snapshot|suspend|stop)
    "disk": "scsi0",
    "size": "+1G",
    "ostemplate": "local:vztmpl/sentinel.tar.zst",
    "filename": "sentinel.iso",
    "volid": "storage1:iso/sentinel.iso",
    "content": "iso",
    "url": "https://example.com/sentinel.iso",
    "upid": "UPID:node1:00000001:00000000:00000000:sentinel:100:root@pam:",
    "changes": {},
    "options": {},
    "prior_config": {},
    "password": "sentinel-placeholder-pass",  # noqa: S105 (test sentinel, not a real credential)
    "username": "sentineluser",
    "command": ["true"],
    "sql": "SELECT 1",
    "db": "postgres",
    "roles": "PVEAuditor",
    "roleid": "sentinelrole",
    "groupid": "sentinelgroup",
    "tokenid": "sentineltoken",
    "userid": "testuser@pve",
    "new_owner": "testuser@pbs",
    "realm": "sentinelrealm",
    "poolid": "sentinelpool",
    "pool": "sentinelpool",
    "path": "/sentinel",
    "narrow_path": "/sentinel-narrow",
    "narrow_role": "sentinelnarrowrole",
    "state": "started",  # HA resource state enum (backends._VALID_HA_STATES)
    "scope": "cluster",
    "pos": 7,
    "direction": "in",
    "source": "192.0.2.10",
    "dest": "192.0.2.20",
    "proto": "tcp",
    "dport": "22",
    "sport": "1024",
    "cidr": "192.0.2.0/24",
    "network": "192.0.2.0/24",
    "alias": "sentinelalias",
    "iface": "vmbr1",
    "iface_type": "bridge",
    "zone": "sentzone",
    "zone_type": "simple",
    "vnet": "sentvnet",
    "subnet": "192.0.2.0/24",
    "mapping_id": "sentinelmap",
    "hw_type": "pci",
    "metrics_id": "sentinelmetrics",
    "ep_type": "webhook",
    "job_id": "sentineljob",
    "job_type": "sync",
    "rep_id": "100/0",
    "rep_type": "local",
    "remote": "sentinelremote",
    "remote_id": "sentinelremote",
    "store": "ds1",
    "datastore": "ds1",
    "ns": "sentns",
    "namespace": "sentns",
    "backup_type": "vm",
    "backup_id": "100",
    "backup_time": 1700000000,
    "group": "vm/100",
    "ogroup": "100",
    "id_": "100",
    "type_": "email",
    # Epoch-int by default (PMG statistics_* reads, pve_task_log's line offset); the two PMG
    # when_object tools that want a "HH:MM" string get an explicit CUSTOM_KWARGS override below.
    "start": 1700000000,
    "end": 1700003600,
    "domain": "example.com",
    "domains": ["example.com"],
    "transport": "smtp",
    "protocol": "smtp",
    "mail_id": "100",
    "mail_ids": "100",
    "tracker_id": "sentineltracker",
    "quarantine_type": "spam",
    "address": "user@example.com",
    "email": "user@example.com",
    "pmail": "user@example.com",
    "mail": "user@example.com",
    "service": "pveproxy",
    "timeframe": "hour",
    "timespan": 3600,  # PMG tracker/statistics range must be in [3600, 31622400]
    "resource_type": "vm",  # pve_cluster_resources filter (node|sdn|storage|vm)
    "cf": "AVERAGE",
    "lastentries": 50,
    "field": "sentinelfield",
    "value": "sentinelvalue",
    "name": "sentinelname",
    "to": "user@example.com",
    "subject": "sentinel subject",
    "body_text": "sentinel body",
    "notify": "always",
    "disclaimer": "sentinel disclaimer",
    "position": "start",
    "text": "sentinel text",
    "storage_type": "dir",
    "backend": "directory",  # node_lifecycle._VALID_BACKENDS = {lvm,lvmthin,zfs,directory}
    "devices": "0000:01:00.0",
    "hw_id": "0000:01:00.0",
    "timezone": "UTC",
    "dns1": "192.0.2.1",
    "dns2": "192.0.2.2",
    "dns3": "192.0.2.3",
    "search": "example.com",
    "certificates": "sentinel-certificate-placeholder-not-real-pem-data",
    "key": "sentinel-key-placeholder-not-a-real-key",
    "file": "/etc/sentinel-file",
    "fingerprint": "AA:BB:CC:DD:EE:FF",
    "auth_id": "sentinelauth",
    "dns_api": "cf",
    "account": "sentinelaccount",
    "contact": "mailto:test@example.com",
    "plugin": "sentinelplugin",
    "plugin_id": "sentinelplugin",
    "priority": 50,
    "sid": "vm:100",
    "resources": "vm:100",
    "affinity": "positive",
    "rule": "sentinelrule",
    "rule_type": "node-affinity",
    "nodes": "node1",
    "vms": "100",
    "checksum": "0" * 64,
    "checksum_algorithm": "sha256",
    "gc_schedule": "daily",
    "prune_schedule": "daily",
    "notification_mode": "notification-system",
    "schedule": "daily",
    "expire": 30,
    "profile": "sentinelprofile",
    "regex": "^sentinel$",
}

_ALNUM_RE = re.compile(r"[^A-Za-z0-9]")


def _strip_annotated(ann: str) -> str:
    """Unwrap `Annotated[T, Field(...)]` -> `T` (as a source string, PEP 563) so the type
    sniffing below sees the real type, not the Field(description=...) text (which could contain
    words like 'list'/'int'). Plain annotations pass through unchanged."""
    if not ann.startswith("Annotated["):
        return ann
    inner = ann[len("Annotated[") : -1]  # drop leading "Annotated[" and trailing "]"
    depth = 0
    for i, c in enumerate(inner):
        if c in "[(":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "," and depth == 0:
            return inner[:i].strip()  # first top-level type arg
    return inner.strip()


def _fallback_value(pname: str, ann: str) -> Any:
    if "bool" in ann:
        return False
    if "dict" in ann:
        return {}
    if "list" in ann:
        return []
    if ann in ("int", "int | None") or ann.startswith("int"):
        return 100
    if "float" in ann:
        return 1.5
    # Generic alnum-only token — safe against every "[A-Za-z0-9][A-Za-z0-9._-]{0,N}"-style
    # validator we surveyed in the source (access.py, pbs.py, pmg.py, notifications.py, ...).
    token = _ALNUM_RE.sub("", pname) or "x"
    return f"sentinel{token}"[:40]


# Per-tool overrides where a param NAME is legitimately overloaded with an incompatible format
# for THAT specific tool (each cites the validator that forces it — see the research notes in
# the PR/commit, not reproduced here to keep this file focused).
CUSTOM_KWARGS: dict[str, dict[str, Any]] = {
    # firewall action is ACCEPT/DROP/REJECT, not a power verb; exercise the guest-scoped path
    # (scope="guest") so vmid/kind actually surface in the change/blast text (_scope_label).
    "pve_firewall_rule_add": {"action": "ACCEPT", "scope": "guest", "vmid": "100", "kind": "lxc"},
    "pve_firewall_rule_update": {"action": "ACCEPT", "scope": "guest", "vmid": "100", "kind": "lxc"},
    "pve_firewall_rule_remove": {"scope": "guest", "vmid": "100", "kind": "lxc"},
    "pve_firewall_options_set": {"scope": "guest", "vmid": "100", "kind": "lxc"},
    "pve_firewall_set_enabled": {"scope": "guest", "vmid": "100", "kind": "lxc"},
    "pve_firewall_alias_create": {"scope": "guest", "vmid": "100", "kind": "lxc"},
    "pve_firewall_alias_update": {"scope": "guest", "vmid": "100", "kind": "lxc"},
    "pve_firewall_alias_delete": {"scope": "guest", "vmid": "100", "kind": "lxc"},
    "pve_firewall_ipset_create": {"scope": "guest", "vmid": "100", "kind": "lxc"},
    "pve_firewall_ipset_delete": {"scope": "guest", "vmid": "100", "kind": "lxc"},
    "pve_firewall_ipset_entry_add": {"scope": "guest", "vmid": "100", "kind": "lxc"},
    "pve_firewall_ipset_entry_remove": {"scope": "guest", "vmid": "100", "kind": "lxc"},
    # Firewall security-group NAME is [A-Za-z][A-Za-z0-9-_]+ (_check_fw_name) — the global "group"
    # sentinel ("vm/100") is shaped for the HA/backup-group sense of "group", not this one.
    "pve_firewall_security_group_create": {"group": "sentinelgroup"},
    "pve_firewall_security_group_delete": {"group": "sentinelgroup"},
    # pmg_quarantine_action: _QUARANTINE_ACTIONS = {deliver, delete, mark-seen, mark-unseen,
    # blocklist, welcomelist} — not a service-control verb.
    "pmg_quarantine_action": {"action": "deliver"},
    # pmg ruledb rule create/update "direction" is an INT enum (0=in,1=out,2=both —
    # pmg._check_direction), unlike the firewall plane's string "in"/"out".
    "pmg_ruledb_rule_create": {"direction": 0},
    "pmg_ruledb_rule_update": {"direction": 0},
    # pmg_what_object_add/update: _WHAT_OBJECT_TYPES, not the who-object enum ("email" default is
    # a WHO type). (pmg_what_group_create/update take no "type_" param — group-level, not typed.)
    "pmg_what_object_add": {"type_": "contenttype"},
    "pmg_what_object_update": {"type_": "contenttype"},
    "pmg_what_object_get": {"type_": "contenttype"},
    # pmg_who_object_add/update take ONE value field matching `type_` — the others (domain, ip,
    # cidr, mode, profile, group, account) are alternates for OTHER who-object types and are
    # mutually irrelevant here; leave them unset so the plan reflects only the type_="email" +
    # email pair. `account` added Wave 8a (ldapuser extension) — same treatment.
    "pmg_who_object_add": {
        "domain": None, "regex": None, "ip": None, "cidr": None, "mode": None,
        "profile": None, "group": None, "account": None,
    },
    "pmg_who_object_update": {
        "domain": None, "regex": None, "ip": None, "cidr": None, "mode": None,
        "profile": None, "group": None, "account": None,
    },
    # Action-object update/delete/GET ids are compound "ogroup_objid" (e.g. "13_26"), NOT a bare
    # ruledb id — _check_action_object_id's own docstring example.
    "pmg_action_bcc_update": {"id_": "13_26"},
    "pmg_action_field_update": {"id_": "13_26"},
    "pmg_action_notification_update": {"id_": "13_26"},
    "pmg_action_disclaimer_update": {"id_": "13_26"},
    "pmg_action_removeattachments_update": {"id_": "13_26"},
    "pmg_action_delete": {"id_": "13_26"},
    # Wave 8a: the 5 new action-object GET reads take the same compound id.
    "pmg_action_bcc_get": {"id_": "13_26"},
    "pmg_action_field_get": {"id_": "13_26"},
    "pmg_action_notification_get": {"id_": "13_26"},
    "pmg_action_disclaimer_get": {"id_": "13_26"},
    "pmg_action_removeattachments_get": {"id_": "13_26"},
    # Replication id is "<vmid>-<n>" per _REPLICATION_ID_RE example in the source.
    "pve_replication_create": {"rep_id": "100-0"},
    "pve_replication_update": {"rep_id": "100-0"},
    "pve_replication_delete": {"rep_id": "100-0"},
    # SDN subnet identifiers are the CIDR itself (not an alnum id) for create; update/delete take
    # the PVE-derived "zone-cidr"-shaped path id — a CIDR string satisfies both regexes.
    "pve_sdn_subnet_create": {"subnet": "192.0.2.0/24"},
    "pve_sdn_subnet_delete": {"subnet": "192.0.2.0/24"},
    # SDN zone/vnet/subnet UPDATE additionally requires a non-empty options OR delete — the
    # blanket empty-dict default trips "requires at least one option to set or delete".
    "pve_sdn_zone_update": {"options": {"mtu": 1500}},
    "pve_sdn_vnet_update": {"options": {"mtu": 1500}},
    # node_disk_* "disk" is a HOST block device path (backends._check_disk, /dev/...), unlike the
    # guest-disk identifier (scsi0/virtio0/...) the global "disk" sentinel is shaped for.
    "pve_node_disk_initgpt": {"disk": "/dev/sdb"},
    "pve_node_disk_wipe": {"disk": "/dev/sdb"},
    # PBS disk admin (Wave 2d) "disk"/"devices" are BARE /sys/block/<name> basenames (pbs_disks.
    # _check_pbs_wholedisk / _check_pbs_disk_or_partition) — the OPPOSITE convention from PVE's
    # /dev/-prefixed form above, and unrelated to the guest-disk (scsi0) global sentinel too.
    "pbs_node_disk_smart": {"disk": "sda"},
    "pbs_node_disk_initgpt": {"disk": "sda"},
    "pbs_node_disk_wipe": {"disk": "sda1"},
    "pbs_node_disk_directory_create": {"disk": "sda", "filesystem": "ext4"},
    "pbs_node_disk_zfs_create": {
        "devices": "sda,sdb", "raidlevel": "mirror", "ashift": 12, "compression": "lz4",
    },
    # Guest backup-job selection (vmid/all_guests/pool) is mutually exclusive; leave only vmid set.
    "pve_backup_job_create": {"pool": None, "exclude": None, "all_guests": None},
    # cloud-init and template-convert are QEMU-only on Proxmox (kind="lxc" raises).
    "pve_template_convert": {"kind": "qemu"},
    # realm_type just needs to be one of the valid auth types; avoid "pam"/"pve" in case of any
    # future built-in-realm-type special-casing (the NAME "sentinelrealm" is already non-builtin).
    "pve_realm_create": {"realm_type": "ldap"},
    # node_storage_backend_create(backend="directory") additionally requires 'filesystem'
    # (_check_backend_create_params) — passed via **kw, not a named signature parameter.
    "pve_node_storage_backend_create": {"filesystem": "ext4"},
    # HA resource "group" is an HA GROUP name (_check_ha_group, alnum/_/-), not the
    # backup-group-descriptor sense ("vm/100") the global "group" sentinel is shaped for.
    "pve_ha_resource_add": {"group": "sentinelhagroup"},
    # ACL "kind" here means PRINCIPAL kind (user|token|group), NOT the guest kind (lxc|qemu) the
    # global "kind" sentinel is shaped for; "target" is the principal being granted/revoked —
    # with kind="user" it must be a userid (user@realm), not the generic alnum fallback.
    "pve_acl_modify": {"kind": "user", "target": "testuser@pve"},
    "pve_acl_prune": {"kind": "user", "target": "testuser@pve"},
    # SDN subnet UPDATE also requires a non-empty options/delete (same reason as zone/vnet above).
    "pve_sdn_subnet_update": {"subnet": "192.0.2.0/24", "options": {"mtu": 1500}},
    # cloudinit "changes" must be a non-empty dict of valid cloud-init keys (cloudinit._SCALAR_CI_KEYS);
    # both the read (get) and write (set) side are QEMU-only.
    "pve_cloudinit_set": {"kind": "qemu", "changes": {"nameserver": "192.0.2.53"}},
    "pve_cloudinit_get": {"kind": "qemu"},
    # pve_agent_fs's "command" is a fixed fs-op enum string (backends._VALID_AGENT_FS_CMDS),
    # NOT an argv list like ct_exec/pve_agent_exec's "command".
    "pve_agent_fs": {"command": "fstrim"},
    # pmg_when_object_add/update's start/end are "HH:MM" time-of-day strings, unlike the
    # epoch-int "start"/"end" the global sentinel is shaped for (PMG statistics_* reads).
    "pmg_when_object_add": {"start": "08:00", "end": "17:00"},
    "pmg_when_object_update": {"start": "08:00", "end": "17:00"},
    # pve_agent_info's "command" is a qemu-agent info-command enum (backends._VALID_AGENT_INFO_CMDS),
    # not an argv list like ct_exec's "command" — keep the tool's own default (already valid).
    "pve_agent_info": {"command": "info"},
    # apt "digest" is PVE's content-hash optimistic-lock field (backends._check_apt_digest wants
    # hex, <=80 chars) — unlike the generic alnum-token sentinel fallback ("sentineldigest").
    "pve_apt_repository_set": {"digest": "0" * 40},
    "pve_apt_repository_add": {"digest": "0" * 40},
    # PBS apt "digest" is stricter: pbs._check_pbs_apt_digest wants EXACTLY 64 lowercase hex
    # chars (a SHA-256 digest, per PBS's own upstream schema), unlike PVE/PMG's permissive
    # hex-up-to-80-chars validator.
    "pbs_apt_repository_set": {"digest": "0" * 64},
    "pbs_apt_repository_add": {"digest": "0" * 64},
    # PMG apt "digest" mirrors PVE's shape (hex, <=80 chars) — same override reason as PVE above.
    "pmg_apt_repository_set": {"digest": "0" * 40},
    "pmg_apt_repository_add": {"digest": "0" * 40},
    # PBS ACL "auth_id"/"group" are mutually exclusive on this endpoint (pbs_access._check_acl_
    # principal requires EXACTLY one) — the generic sweep synthesizes both, so pin auth_id to a
    # valid PBS 'user@realm' shape and explicitly null out group to avoid the "exactly one" error.
    # PBS's own auth-id pattern is unrelated to the global "userid" sentinel's PVE shape, so give
    # it its own value here too.
    "pbs_acl_update": {"auth_id": "testuser@pbs", "group": None},
    # pbs_permissions_get's "auth_id" needs the same PBS 'user@realm' shape as above — the
    # generic alnum fallback ("sentinelauth") fails pbs_access._check_authid.
    "pbs_permissions_get": {"auth_id": "testuser@pbs"},
    # pbs_tfa_add's "tfa_type" is a fixed enum (totp/u2f/webauthn/recovery/yubico —
    # pbs_access._check_tfa_type), not a free alnum token like the generic fallback synthesizes.
    "pbs_tfa_add": {"tfa_type": "totp"},
    # PBS notifications (Wave 3a) "digest" needs the same 64-char lowercase-hex SHA-256 shape as
    # pbs_apt's own digest override above (pbs_notifications._check_digest) — the generic alnum
    # fallback ("sentineldigest") fails it. matcher_set's "mode" is a closed {all,any} enum
    # (pbs_notifications._check_matcher_mode), unrelated to the global "mode" sentinel's vzdump
    # backup-mode shape ("snapshot").
    "pbs_notification_endpoint_update": {"digest": "0" * 64},
    # "delete" is a `list[str] | None` property-clear param — the generic list fallback ([])
    # is REJECTED (Wave 5b review finding 1: httpx's form encoding drops an empty-list `delete`
    # value entirely, so pbs.py's shared `_check_delete_list` now raises ProximoError rather
    # than disclosing a payload confirm=True would never actually send). Every tool below with
    # a `delete` param needs a non-empty override so this generic sweep can reach a real PLAN.
    "pbs_notification_matcher_set": {"mode": "all", "digest": "0" * 64, "delete": ["comment"]},
    # PBS ACME (Wave 3b) plugin update "digest" needs the same 64-char lowercase-hex SHA-256
    # shape as pbs_notifications' own digest override above (pbs_acme._check_digest) — the
    # generic alnum fallback ("sentineldigest") fails it. "delete" is a CLOSED enum
    # {disable, validation-delay} (pbs_acme._check_plugin_delete_props) — "comment" (the other
    # tools' un-validated-pass-through sentinel) would fail this one's own enum check.
    "pbs_acme_plugin_update": {"digest": "0" * 64, "delete": ["disable"]},
    # PBS ACME directory/ToS URLs are validated https-only (pbs_acme._check_acme_url,
    # Wave 3b review) — the generic alnum sentinel fails the scheme check.
    "pbs_acme_tos": {"directory": "https://sentinel-ca.example.com/directory"},
    "pbs_acme_account_create": {
        "directory": "https://sentinel-ca.example.com/directory",
        "tos_url": "https://sentinel-ca.example.com/tos",
    },
    # PMG ACME (Wave 9g) mirrors pbs_acme_account_create's own https-only directory/tos_url
    # override exactly (pmg._check_acme_directory_url, same review-finding-driven validator).
    "pmg_acme_account_create": {
        "directory": "https://sentinel-ca.example.com/directory",
        "tos_url": "https://sentinel-ca.example.com/tos",
    },
    # PMG ACME tos/meta (Wave 9g) also validate "directory" https-only — same override reason as
    # pbs_acme_tos/pmg_acme_account_create above (these are READ tools, exercised by the read
    # sweep too, not just the mutating one).
    "pmg_acme_tos": {"directory": "https://sentinel-ca.example.com/directory"},
    "pmg_acme_meta": {"directory": "https://sentinel-ca.example.com/directory"},
    # PMG ACME plugin "plugin_type" is a CLOSED enum {dns, standalone} (pmg._check_acme_
    # challenge_type) — the generic alnum fallback ("sentinelplugintype") fails it; no global
    # sentinel exists for this param name. pmg_acme_plugin_list's OWN "plugin_type" is the same
    # enum used as a list-filter (a READ tool, exercised by the read sweep).
    "pmg_acme_plugin_create": {"plugin_type": "dns"},
    "pmg_acme_plugin_list": {"plugin_type": "dns"},
    # PMG ACME plugin "delete" is a comma-joined STRING closed to THIS endpoint's own writable
    # optional properties (pmg._check_acme_plugin_delete_props) — a DIVERGENCE from PBS's own
    # list[str]-typed sibling (divergence #8, pmg.py's Wave 9g module section): the generic list
    # fallback ([]) is the wrong TYPE here (this field is a string, not a list) and would fail
    # validation regardless of content.
    "pmg_acme_plugin_update": {"delete": "disable"},
    # PMG node cert order/renew/revoke/custom-upload/custom-delete all take "cert_type", a
    # CLOSED enum {api, smtp} (pmg._check_pmg_cert_type — PMG's own dual-cert-slot model, a
    # divergence neither PVE nor PBS has) — the generic alnum fallback ("sentinelcerttype") fails
    # it; no global sentinel exists for this param name.
    "pmg_node_cert_acme_order": {"cert_type": "api"},
    "pmg_node_cert_acme_renew": {"cert_type": "api"},
    "pmg_node_cert_acme_revoke": {"cert_type": "api"},
    "pmg_node_cert_custom_upload": {"cert_type": "api"},
    "pmg_node_cert_custom_delete": {"cert_type": "api"},
    # PMG identity (Wave 9h). "role" is a CLOSED enum {root, admin, helpdesk, qmanager, audit}
    # (pmg_identity._check_role) — the generic alnum fallback ("sentinelrole") fails it; no global
    # sentinel exists for this bare param name (only "roles"/"roleid" do, for other planes'
    # differently-shaped role fields). "audit" is deliberately non-admin-equivalent here so the
    # generic sweep exercises RULING 3's MEDIUM branch by default (the dedicated HIGH-branch
    # coverage lives in tests/test_pmg_identity.py, which directly asserts role='admin'/'root'
    # resolve to RISK_HIGH).
    "pmg_access_user_create": {"role": "audit"},
    "pmg_access_user_update": {"role": "audit"},
    # "realm_type" is a CLOSED enum {oidc, pam, pmg} (pmg_identity._check_realm_type) — the
    # generic alnum fallback ("sentinelrealmtype") fails it; PUT has no such param (create-only,
    # Fact 10), so only realm_create needs the override.
    "pmg_access_realm_create": {"realm_type": "oidc"},
    # "tfa_type" is a CLOSED 4-member enum {totp, u2f, webauthn, recovery} — PMG has no 'yubico'
    # (Fact 5, a genuine divergence from the PBS sibling's own 5-member enum); mirrors the
    # existing "pbs_tfa_add": {"tfa_type": "totp"} override above for the identical param name.
    "pmg_access_tfa_add": {"tfa_type": "totp"},
    # PBS tape hardware config (Wave 4a) "digest" needs the same 64-char lowercase-hex SHA-256
    # shape as pbs_notifications'/pbs_acme's own digest overrides above
    # (pbs_tape_config._check_digest) — the generic alnum fallback ("sentineldigest") fails it.
    "pbs_tape_drive_update": {"digest": "0" * 64, "delete": ["comment"]},
    "pbs_tape_changer_update": {"digest": "0" * 64, "export_slots": "1,2,3", "delete": ["comment"]},
    # changer "export_slots" is a comma-separated positive-integer list
    # (pbs_tape_config._check_export_slots) — the generic alnum fallback ("sentinelexportslots")
    # fails it.
    "pbs_tape_changer_create": {"export_slots": "1,2,3"},
    # PBS tape media/keys (Wave 4b) "fingerprint"/"encrypt" need the SAME 32-colon-separated-hex-
    # byte-pair shape (pbs_tape_media._check_fingerprint) — the global "fingerprint" sentinel
    # above ("AA:BB:CC:DD:EE:FF", only 6 pairs — a MAC-address shape used elsewhere) is too short,
    # and "encrypt" has no global entry at all (falls back to a plain alnum token that carries no
    # colons whatsoever). Built as an expression (32 "ab" pairs) rather than typed out.
    "pbs_tape_pool_create": {"encrypt": ":".join(["ab"] * 32)},
    "pbs_tape_pool_update": {"encrypt": ":".join(["ab"] * 32), "delete": ["comment"]},
    "pbs_tape_key_get": {"fingerprint": ":".join(["ab"] * 32)},
    "pbs_tape_key_delete": {"fingerprint": ":".join(["ab"] * 32), "digest": "0" * 64},
    "pbs_tape_key_update_password": {
        "fingerprint": ":".join(["ab"] * 32), "digest": "0" * 64, "kdf": "scrypt",
    },
    # "kdf" is a CLOSED enum {none,scrypt,pbkdf2} (pbs_tape_media._check_kdf) — the generic alnum
    # fallback ("sentinelkdf") fails it. "key" (pbs_tape_key_create only) is a 300-600 char JSON
    # blob (pbs_tape_media.tape_key_create's own length check) — the global "key" sentinel above
    # (a ~40-char placeholder used by other tools' looser key-shaped params) is far too short.
    "pbs_tape_key_create": {"kdf": "scrypt", "key": "k" * 300},
    # PBS tape media catalog + jobs (Wave 4d) "uuid"/"media"/"media_set" need a real lowercase-hex
    # UUID shape (pbs_tape_jobs._check_media_uuid) — the generic alnum fallback ("sentineluuid")
    # fails it. media_content's own "media"/"media_set" filters share the same UUID validator.
    "pbs_tape_media_status_get": {"uuid": "12345678-1234-1234-1234-123456789abc"},
    "pbs_tape_media_destroy": {"uuid": "12345678-1234-1234-1234-123456789abc"},
    "pbs_tape_media_move": {"uuid": "12345678-1234-1234-1234-123456789abc"},
    "pbs_tape_media_content": {
        "media": "12345678-1234-1234-1234-123456789abc",
        "media_set": "12345678-1234-1234-1234-123456789abc",
    },
    # media_status_set's "uuid" needs the same UUID shape; "status" is a PROSE-restricted closed
    # set {full,damaged,retired} (pbs_tape_jobs._check_media_status — 'writable'/'unknown' are
    # rejected even though they appear in the raw schema enum) — the generic alnum fallback
    # ("sentinelstatus") fails it.
    "pbs_tape_media_status_set": {
        "uuid": "12345678-1234-1234-1234-123456789abc", "status": "retired",
    },
    # tape backup-job/one-off-backup "max_depth" (0-7) / "worker_threads" (1-32) are BOUNDED ints
    # (pbs_tape_jobs._check_max_depth/_check_worker_threads) — the generic int fallback (100)
    # fails both. "notify_user" needs a PBS userid shape (user@realm,
    # pbs_tape_jobs._check_notify_user) — the generic alnum fallback ("sentinelnotifyuser") fails
    # it; the global "userid" sentinel above is keyed to a DIFFERENT param name.
    "pbs_tape_backup_job_create": {
        "max_depth": 3, "worker_threads": 4, "notify_user": "testuser@pbs",
    },
    "pbs_tape_backup_job_update": {
        "max_depth": 3, "worker_threads": 4, "notify_user": "testuser@pbs", "digest": "0" * 64,
        "delete": ["comment"],
    },
    "pbs_tape_backup": {"max_depth": 3, "worker_threads": 4, "notify_user": "testuser@pbs"},
    # restore's "notify_user"/"owner" need PBS userid/authid shapes
    # (pbs_tape_jobs._check_notify_user/_check_owner) — same reasoning as above; "owner" also
    # additionally accepts a '!token-name' suffix but a bare userid is valid too.
    "pbs_tape_restore": {"notify_user": "testuser@pbs", "owner": "testuser@pbs"},
    # PBS S3 client configs (Wave 5a) "fingerprint" needs the SAME 32-colon-separated-hex-byte-
    # pair shape as pbs_tape_media's own fingerprint (pbs_s3._check_fingerprint) — the global
    # "fingerprint" sentinel above ("AA:BB:CC:DD:EE:FF", only 6 pairs) is too short. "digest"
    # needs the same 64-char lowercase-hex SHA-256 shape as every other digest-taking tool above
    # — the generic alnum fallback ("sentineldigest") fails it.
    "pbs_s3_client_create": {"fingerprint": ":".join(["ab"] * 32)},
    "pbs_s3_client_update": {"fingerprint": ":".join(["ab"] * 32), "digest": "0" * 64, "delete": ["comment"]},
    "pbs_s3_client_delete": {"digest": "0" * 64},
    "pbs_encryption_key_delete": {"digest": "0" * 64},
    "pbs_encryption_key_toggle_archive": {"digest": "0" * 64},
    # PBS metrics servers (Wave 5b) "digest" needs the same 64-char lowercase-hex SHA-256 shape
    # as every other digest-taking tool above (pbs_metrics._check_digest) — the generic alnum
    # fallback ("sentineldigest") fails it. influxdb-udp's "host" REQUIRES a trailing ":port"
    # (pbs_metrics._check_host, HOST_RE) — the generic alnum fallback ("sentinelhost") carries no
    # colon at all and fails the pattern; both create (required) and update (optional, but this
    # sweep always synthesizes a value for every signature param) need the override.
    "pbs_metrics_influxdb_http_update": {"digest": "0" * 64, "delete": ["comment"]},
    "pbs_metrics_influxdb_http_delete": {"digest": "0" * 64},
    "pbs_metrics_influxdb_udp_create": {"host": "192.0.2.10:8089"},
    "pbs_metrics_influxdb_udp_update": {
        "host": "192.0.2.10:8089", "digest": "0" * 64, "delete": ["comment"],
    },
    "pbs_metrics_influxdb_udp_delete": {"digest": "0" * 64},
    # PBS admin node config (Wave 5c) "digest" needs the same 64-char lowercase-hex SHA-256 shape
    # as every other digest-taking tool above (pbs_admin._check_digest). "delete" is a
    # list[str] — the global fallback ([]) is REJECTED by pbs.py's shared `_check_delete_list`
    # (an empty list is dropped by httpx's own form encoding, so it's rejected loudly rather than
    # disclosed misleadingly) — same override shape as pbs_s3_client_update/
    # pbs_metrics_influxdb_http_update above. "default_lang" is a CLOSED enum
    # (pbs_admin._check_default_lang) — the generic alnum fallback ("sentineldefaultlang") fails
    # it.
    "pbs_node_config_set": {"digest": "0" * 64, "delete": ["description"], "default_lang": "en"},
    # PBS pull/push (Wave 5c) "max_depth" (0-7) / "worker_threads" (1-32) are BOUNDED ints
    # (pbs_admin._check_max_depth/_check_worker_threads) — the generic int fallback (100) fails
    # both, same reasoning as the tape backup-job overrides above.
    "pbs_pull": {"max_depth": 3, "worker_threads": 4},
    "pbs_push": {"max_depth": 3, "worker_threads": 4},
    # pbs_admin_sync_jobs_list's "sync_direction" is a CLOSED 3-value enum
    # (pbs_admin._check_sync_direction) — the generic alnum fallback ("sentinelsyncdirection")
    # fails it. Applies to this READ tool too — _kwargs_for/CUSTOM_KWARGS cover both sweeps.
    "pbs_admin_sync_jobs_list": {"sync_direction": "push"},
    # PBS datastore-admin remainder (Wave 5d) "max_depth" is a BOUNDED int (0-7,
    # pbs_datastore_admin._check_max_depth) — the generic int fallback (100) fails it, same
    # reasoning as pbs_pull/pbs_push above.
    "pbs_datastore_prune": {"max_depth": 3},
    "pbs_namespace_move": {"max_depth": 3},
    # PVE Ceph core observability + flags (Wave 6a) "flag" is a CLOSED 11-value enum
    # (backends._check_ceph_flag, validated directly by plan_ceph_flag_set) — the generic alnum
    # fallback ("sentinelflag") fails it, same reasoning as pbs_admin_sync_jobs_list's
    # "sync_direction" override above.
    "pve_ceph_flag_set": {"flag": "noout"},
    # PVE Ceph services lifecycle (Wave 6b) "service" matches the CLOSED pattern
    # '(ceph|mon|mds|osd|mgr)(.<id>)?' (backends._check_ceph_service) — the generic alnum
    # fallback ("sentinelservice") isn't one of the 5 allowed kinds and fails it. "mon.pve1" also
    # exercises the mon/mds/osd-shaped id branch of plan_ceph_service_stop's conditional
    # cmd-safety citation (harmless on this dry-run sweep either way — the citation call is
    # wrapped in try/except and _FakeApi's __getattr__ catch-all answers it with {}).
    "pve_ceph_service_start": {"service": "mon.pve1"},
    "pve_ceph_service_stop": {"service": "mon.pve1"},
    "pve_ceph_service_restart": {"service": "mon.pve1"},
    # pve_ceph_init's min_size/size (1-7) and pg_bits (6-14) are BOUNDED ints
    # (backends._check_ceph_init_bound) — the generic int fallback (100) fails all three, same
    # reasoning as pbs_pull/pbs_push's max_depth/worker_threads overrides above.
    "pve_ceph_init": {"min_size": 2, "size": 3, "pg_bits": 8},
    # PVE Ceph OSD (Wave 6c) "lv_type" is a CLOSED 3-value enum (backends._check_ceph_osd_lv_type)
    # — the generic alnum fallback ("sentinellvtype") fails it, same reasoning as
    # pbs_admin_sync_jobs_list's "sync_direction" override above.
    "pve_ceph_osd_lv_info": {"lv_type": "block"},
    # pve_ceph_osd_create's "dev"/"db_dev"/"wal_dev" are validated with backends.
    # _check_ceph_osd_dev (requires a leading "/dev/" — the generic alnum fallback, e.g.
    # "sentineldev", fails it).
    # osds_per_device is explicitly forced to None: db_dev/wal_dev (populated here to exercise
    # their own "requires" pairing with db_dev_size/wal_dev_size) are schema-documented mutually
    # exclusive with osds_per_device (plan_ceph_osd_create enforces this client-side) — the
    # blanket per-param population this sweep does would otherwise trip that guard for every
    # single param the tool has, which is not what this override is testing.
    "pve_ceph_osd_create": {
        "dev": "/dev/sdb", "db_dev": "/dev/sdc", "wal_dev": "/dev/sdd", "osds_per_device": None,
    },
    # PVE Ceph pools (Wave 6d) "application"/"pg_autoscale_mode" are CLOSED enums
    # (backends._check_ceph_pool_application/_check_ceph_pool_autoscale_mode) — the generic
    # alnum fallback ("sentinelapplication"/"sentinelpgautoscalemode") fails both, same
    # reasoning as pve_ceph_flag_set's "flag" override above. "target_size" must match
    # backends._check_ceph_pool_target_size's pattern (number optionally suffixed K/M/G/T) — the
    # generic alnum fallback ("sentineltargetsize") fails it. "min_size"/"size" are BOUNDED ints
    # (1-7, backends._check_ceph_bounded_int) — the generic int fallback (100) fails both, same
    # reasoning as pve_ceph_init's override above ("pg_num"/"pg_num_min" stay unoverridden: the
    # generic int fallback of 100 is within both their ranges — 1-32768 and <=32768 respectively
    # — so no override is needed for either). "erasure_coding" must parse as PVE's own
    # propertyString (backends._check_ceph_pool_erasure_coding) — the generic alnum fallback
    # fails it (no "=").
    "pve_ceph_pool_create": {
        "application": "rbd", "pg_autoscale_mode": "warn", "target_size": "10G",
        "min_size": 2, "size": 3, "erasure_coding": "k=2,m=1",
    },
    "pve_ceph_pool_set": {
        "application": "rbd", "pg_autoscale_mode": "warn", "target_size": "10G",
        "min_size": 2, "size": 3,
    },
    # PVE SDN vnet-scoped firewall (Wave 7b) "action" is ACCEPT/DROP/REJECT
    # (firewall._check_action, imported) — the global "start" default (a power-verb sentinel)
    # fails it, same reasoning as pve_firewall_rule_add's own override above. "fw_type" is the
    # 4-value {in,out,forward,group} enum (sdn_firewall._check_vnet_fw_type) — the generic
    # alnum fallback ("sentinelfwtype") fails it; this param name is deliberately NOT "direction"
    # (see sdn_firewall.py's module docstring), so it does not pick up the global "direction":
    # "in" sentinel either.
    "pve_sdn_vnet_firewall_rule_add": {"action": "ACCEPT", "fw_type": "in"},
    "pve_sdn_vnet_firewall_rule_update": {"action": "ACCEPT", "fw_type": "in"},
    # PVE SDN vnet IP mappings (Wave 7b) "ip" is a single IP address
    # (sdn_firewall._check_vnet_ip, ipaddress.ip_address) — the generic alnum fallback
    # ("sentinelip") is not a valid address and fails it.
    "pve_sdn_vnet_ip_create": {"ip": "192.0.2.10"},
    "pve_sdn_vnet_ip_update": {"ip": "192.0.2.10"},
    "pve_sdn_vnet_ip_delete": {"ip": "192.0.2.10"},
    # PVE SDN controllers/DNS/IPAMs (Wave 7c). "controller_type"/"dns_type"/"ipam_type" are
    # each closed enums (sdn_objects._check_controller_type/_check_dns_type/_check_ipam_type)
    # — the generic alnum fallback ("sentinelcontrollertype" etc.) fails all three; note
    # "dns_type" carries a real default ("powerdns") in the wrapper signature, but this sweep
    # synthesizes a value for EVERY param regardless of its default, so it still needs an
    # explicit override. "fingerprint" is a STRICTER pattern than the global "fingerprint"
    # sentinel ("AA:BB:CC:DD:EE:FF", 6 byte-pairs) satisfies elsewhere: this schema's own
    # fingerprint is a full 32-byte-pair (SHA-256) cert fingerprint
    # (sdn_objects._check_fingerprint, copied verbatim from the live schema) — a 32-pair
    # override is supplied wherever this module's own "fingerprint" param appears.
    # Controller/dns/ipam UPDATE additionally requires >=1 set/unset for controller (generic
    # options dict, same "requires at least one option" reason as zone/vnet/subnet update
    # above); dns/ipam update use EXPLICIT named fields instead (url/key/token/... each get a
    # real sentinel from the global SENTINELS dict), so they never hit the empty-bag problem
    # and need no such override.
    "pve_sdn_controller_create": {"controller_type": "bgp"},
    "pve_sdn_controller_update": {"options": {"asn": 65000}},
    "pve_sdn_dns_create": {
        "dns_type": "powerdns", "fingerprint": ":".join(["ab"] * 32),
    },
    "pve_sdn_dns_update": {"fingerprint": ":".join(["ab"] * 32)},
    "pve_sdn_ipam_create": {
        "ipam_type": "netbox", "fingerprint": ":".join(["ab"] * 32),
    },
    "pve_sdn_ipam_update": {"fingerprint": ":".join(["ab"] * 32)},
    # PVE SDN controllers/DNS/IPAMs LIST reads (Wave 7c) — the optional `type` filter param
    # is the SAME closed enum as the create-side override above; the read sweep
    # (test_read_wrapper_request_shape) shares this same CUSTOM_KWARGS dict via _kwargs_for.
    "pve_sdn_controllers_list": {"controller_type": "bgp"},
    "pve_sdn_dns_list": {"dns_type": "powerdns"},
    "pve_sdn_ipams_list": {"ipam_type": "netbox"},
    # PVE SDN prefix-lists + route-maps (Wave 7e). "entries"/"match"/"set_clauses" are all
    # `list[dict] | None` — the generic _fallback_value checks "dict" in ann BEFORE "list", so
    # a `list[dict]` annotation string (which contains the substring "dict") wrongly falls into
    # the dict branch and synthesizes `{}` instead of `[]`, tripping sdn_routing.py's own
    # `_check_list_of_dicts` (which requires an actual list, not a dict) — this is the FIRST
    # `list[dict]`-typed tool param in the codebase, so no earlier override caught this fallback
    # gap. An empty list `[]` is a genuinely valid input for all three (an explicit "no
    # entries/clauses" set), so the override is not weakening what's tested. "action" is the
    # permit/deny 2-value enum (sdn_routing._check_action) — the global "action": "start"
    # power-verb sentinel fails it, same reasoning as pve_sdn_vnet_firewall_rule_add's own
    # override above. "prefix" (prefix-list entries only) must be a CIDR
    # (sdn_routing._check_prefix_cidr, ipaddress.ip_network) — the generic alnum fallback
    # ("sentinelprefix") is not a valid network and fails it.
    "pve_sdn_prefix_list_create": {"entries": []},
    "pve_sdn_prefix_list_update": {"entries": []},
    "pve_sdn_prefix_list_entry_create": {"action": "permit", "prefix": "10.99.99.0/24"},
    "pve_sdn_prefix_list_entry_update": {"action": "permit", "prefix": "10.99.99.0/24"},
    "pve_sdn_route_map_entry_create": {"action": "permit", "match": [], "set_clauses": []},
    "pve_sdn_route_map_entry_update": {"action": "permit", "match": [], "set_clauses": []},
    # PVE SDN fabrics (Wave 7d, the FINAL Wave 7 chunk). "protocol" is the fabric routing
    # protocol enum (openfabric/ospf/wireguard/bgp — sdn_fabrics._check_protocol) — the
    # global "protocol": "smtp" sentinel (shaped for PMG mail-transport tools) fails it.
    # fabric/fabric-node UPDATE additionally require >=1 option to set or delete (same
    # "requires at least one option" reason as zone/vnet/subnet/controller update above) —
    # the blanket empty-dict `options` default trips it, so both updates get a real option too.
    "pve_sdn_fabric_create": {"protocol": "bgp"},
    "pve_sdn_fabric_update": {"protocol": "bgp", "options": {"asn": 65000}},
    "pve_sdn_fabric_node_create": {"protocol": "bgp"},
    "pve_sdn_fabric_node_update": {"protocol": "bgp", "options": {"ip": "10.99.99.1/24"}},
    # PMG node ops odds (Wave 9b). "queue" is a 4-value enum (deferred/active/incoming/hold —
    # pmg_node._check_queue), not a free identifier — the generic "sentinelqueue" fallback fails
    # it on every postfix-queue tool. "action" on pmg_node_postfix_queue_action is the
    # delete/deliver 2-value enum (pmg_node._check_postfix_queue_action), not a service-control
    # verb (same reasoning as pmg_quarantine_action's own override above). "filename" on the
    # backup tools must match PMG's own schema pattern (pmg_node._check_backup_filename:
    # 'pmg-backup_[0-9A-Za-z_-]+.tgz') — the global "sentinel.iso" fallback (shaped for storage
    # ISO tools) fails it.
    "pmg_node_postfix_queue_list": {"queue": "deferred", "sortfield": "sender", "sortdir": "ASC"},
    "pmg_node_postfix_queue_message_get": {"queue": "deferred"},
    "pmg_node_postfix_queue_action": {"queue": "deferred", "action": "deliver"},
    "pmg_node_postfix_queue_delete_queue": {"queue": "deferred"},
    "pmg_node_postfix_queue_message_delete": {"queue": "deferred"},
    "pmg_node_postfix_queue_message_deliver": {"queue": "deferred"},
    "pmg_node_backup_delete": {"filename": "pmg-backup_sentinel.tgz"},
    "pmg_node_backup_restore": {"filename": "pmg-backup_sentinel.tgz"},
    # PMG LDAP profiles (Wave 9c). "mode" is the ldap/ldaps/ldap+starttls enum
    # (pmg._check_ldap_mode) — the global "mode" sentinel ("snapshot", shaped for vzdump backup
    # mode) fails it.
    "pmg_ldap_profile_create": {"mode": "ldap"},
    "pmg_ldap_profile_config_update": {"mode": "ldap"},
    # PMG fetchmail (Wave 9c). "protocol" is the pop3/imap enum (pmg._check_fetchmail_protocol) —
    # the global "protocol" sentinel ("smtp", shaped for the mail-transport plane) fails it.
    # "target" must be an email address (pmg._check_email_address) — no global sentinel exists
    # for this param name.
    "pmg_fetchmail_create": {"protocol": "pop3", "target": "user@example.com"},
    "pmg_fetchmail_update": {"protocol": "pop3", "target": "user@example.com"},
    # PMG DKIM (Wave 9e). "keysize" has a schema-verified floor of 1024 bits
    # (pmg._check_dkim_keysize) — there is no global "keysize" sentinel, and a generic
    # small-int fallback would fail the >=1024 floor.
    "pmg_dkim_selector_generate": {"keysize": 2048},
    # PMG PBS remote config (Wave 9f). "fingerprint" needs the SAME 32-colon-separated-hex-byte-
    # pair SHA-256 shape as pbs_s3/pbs_tape_media/sdn_objects's own fingerprint validators
    # (pmg._check_pbs_remote_fingerprint) — the global "fingerprint" sentinel above
    # ("AA:BB:CC:DD:EE:FF", only 6 pairs) is too short. "username" needs a `user@realm`/tokenid
    # shape (pmg._check_pbs_remote_username, PMG's own schema pattern requires a literal '@') —
    # the global "username" sentinel ("sentineluser", shaped for PVE/PBS's own userid-only fields)
    # carries no '@' and fails it.
    "pmg_pbs_remote_create": {"fingerprint": ":".join(["ab"] * 32), "username": "testuser@pbs"},
    "pmg_pbs_remote_update": {"fingerprint": ":".join(["ab"] * 32), "username": "testuser@pbs"},
    # PMG quarantine + statistics remainder (Wave 9j, THE FINAL CHUNK — closes the PMG plane).
    # "list_" is the BL/WL enum (pmg._check_quarusers_list) — the generic alnum fallback
    # ("sentinellist") fails it. "type_" on pmg_statistics_detail is the contact/sender/receiver
    # enum (pmg._check_statistics_detail_type) — the GLOBAL "type_": "email" sentinel (shaped for
    # an unrelated who-object type enum elsewhere in this file) fails it too. "day"/"month"/"year"
    # (pmg._day_month_year_params, schema bounds 1-31/1-12/1900-3000) are new param names this
    # sweep has never seen before — the generic int fallback (100) violates all three bounds
    # simultaneously, so every tool that carries them needs an explicit in-range override.
    # "hours"/"limit" on the two recent* reads (pmg._check_recent_hours/_check_recent_limit,
    # schema bounds 1-24/1-50) hit the identical problem — the generic int fallback (100) is
    # out of range for both.
    "pmg_quarantine_users_list": {"list_": "BL"},
    "pmg_statistics_contact": {"day": 15, "month": 6, "year": 2026},
    "pmg_statistics_detail": {"type_": "contact", "day": 15, "month": 6, "year": 2026},
    "pmg_statistics_maildistribution": {"day": 15, "month": 6, "year": 2026},
    "pmg_statistics_rejectcount": {"day": 15, "month": 6, "year": 2026},
    "pmg_statistics_recentreceivers": {"hours": 6, "limit": 10},
    "pmg_statistics_recentsenders": {"hours": 6, "limit": 10},
}

# Parameters excluded from synthesis entirely (handled specially, or would only broaden/weaken
# what we're proving if auto-filled).
_SKIP_PARAMS = frozenset({"confirm", "proximo_target"})


def _kwargs_for(name: str) -> dict[str, Any]:
    fn = getattr(server, name)
    sig = inspect.signature(fn)
    kwargs: dict[str, Any] = {}
    for pname, p in sig.parameters.items():
        if pname in _SKIP_PARAMS or p.kind is inspect.Parameter.VAR_KEYWORD:
            continue
        if pname in SENTINELS:
            kwargs[pname] = SENTINELS[pname]
        else:
            kwargs[pname] = _fallback_value(pname, _strip_annotated(str(p.annotation)))
    kwargs.update(CUSTOM_KWARGS.get(name, {}))
    return kwargs


# ---------------------------------------------------------------------------
# Identity-bearing parameter names: if a tool's signature carries one of these AND we passed a
# value for it, that value must show up somewhere in the returned plan. These are the "this
# argument IS (part of) what the operation targets" names — as opposed to free-text/property
# values (comment, description, password, contact, ...) that a plan is not obligated to echo
# back verbatim. NOTE: deliberately excludes "filename" — it is genuinely identity-bearing for
# pve_storage_download/pve_storage_content_delete (already covered via "storage"/"volid") but is
# an inert optional PMG "what-object" filter field for unrelated tools, so requiring it globally
# would produce false failures rather than catching a real bug.
# ---------------------------------------------------------------------------
IDENTITY_PARAMS = frozenset({
    "vmid", "newid", "ctid", "storage", "target_storage", "snapname", "disk", "volid",
    "upid", "remote", "remote_id", "store", "datastore", "ns", "namespace",
    "backup_id", "group", "ogroup", "id_", "roleid", "groupid", "tokenid", "userid",
    "new_owner", "realm", "poolid", "pool", "path", "pos", "iface", "zone", "vnet", "subnet",
    "mapping_id", "metrics_id", "ep_type", "job_id", "rep_id", "domain", "domains",
    "transport", "mail_id", "mail_ids", "tracker_id", "sid", "resources", "rule", "plugin_id",
    "auth_id", "account", "mail",
})

# Per-tool identity exemptions: a param IS identity-bearing in general, but for this specific
# tool the plan_* builder deliberately does not echo the raw value anywhere in its output. Each
# entry cites the source reason so this stays an honest, reviewable exception, not a quiet skip.
IDENTITY_EXEMPT: dict[str, frozenset[str]] = {
    # plan_restore(api, vmid, archive, kind, node, force) takes neither storage nor pool — the
    # preview only needs vmid/kind to describe create-vs-overwrite; where the restored guest
    # lands is orthogonal to that risk classification (storage/pool only matter to the REAL
    # restore_guest() call on the confirm=True path). backup.py, plan_restore().
    "pve_restore": frozenset({"storage", "pool"}),
    # plan_ha_rule_update() deliberately shows which field NAMES changed ("resources", "nodes",
    # ...), never the new VALUES — so a passed value never appears verbatim anywhere in the plan.
    # cluster_ops.py, plan_ha_rule_update().
    "pve_ha_rule_update": frozenset({"resources", "nodes", "rule_type", "affinity"}),
    # NOTE: plan_backup_job_create() used to be exempted here (its change text only reflected
    # job_id/schedule/storage — the guest-selection kwargs were validated but never echoed).
    # Fixed 2026-07-14 audit (backup_schedules.py: change now embeds `{kw}`, matching sibling
    # _create/_update plan factories) — vmid now DOES appear in the plan, so this tool no
    # longer over-exempts; the entry was removed rather than left stale/contradictory.
    # --- read-tool exemptions (test_read_wrapper_request_shape) ---
    # pve_tasks_list's ledger target is the NODE being queried (node or cfg.node); vmid/typefilter/
    # statusfilter are query-side filters passed to tasks_list(), never folded into the target.
    "pve_tasks_list": frozenset({"vmid"}),
    # pbs_snapshots_list / pdm_pbs_snapshots_list target the DATASTORE (f"pbs/{store}" /
    # f"pdm/pbs/{remote}/datastore/{datastore}/snapshots"); ns/backup_id are listing filters
    # passed through to the underlying op, not part of the ledger target.
    "pbs_snapshots_list": frozenset({"ns", "backup_id"}),
    "pdm_pbs_snapshots_list": frozenset({"ns"}),
    # pdm_acl_list's ledger target is the fixed "pdm/access/acl"; `path` is an optional filter
    # passed to pdm.acl_list(), not folded into the target.
    "pdm_acl_list": frozenset({"path"}),
    # pve_firewall_{alias_list,options_get,rules_list,ipset_list} target f"firewall/{scope}[...]"
    # ALWAYS — unlike their mutating create/update siblings (whose _scope_label lands vmid in
    # the Plan's change/blast text), these reads have no "change" narrative to carry it, so vmid
    # never appears regardless of scope. server.py, pve_firewall_{alias_list,options_get,
    # rules_list,ipset_list}; the underlying alias_list/firewall_options_get/firewall_rules_list/
    # ipset_list ops DO use vmid/kind to build the actual REST path — only the LEDGER target is
    # scope-only.
    "pve_firewall_alias_list": frozenset({"vmid"}),
    "pve_firewall_options_get": frozenset({"vmid"}),
    "pve_firewall_rules_list": frozenset({"vmid"}),
    "pve_ipset_list": frozenset({"vmid"}),
    # pbs_acl_get's ledger target is the fixed "pbs/access/acl" — mirrors pdm_acl_list exactly:
    # `path` is an optional exact-match filter passed to pbs_access.acl_get(), not folded into
    # the target.
    "pbs_acl_get": frozenset({"path"}),
    # pbs_permissions_get's ledger target embeds auth_id (f"pbs/access/permissions/{auth_id}")
    # but NOT path — path is an optional scoping filter passed to pbs_access.permissions_get(),
    # not folded into the target (same "list-filter, not identity" treatment as pbs_acl_get above).
    "pbs_permissions_get": frozenset({"path"}),
    # pbs_tape_media_list's ledger target is the fixed "pbs/tape/media/list" — mirrors
    # pbs_snapshots_list's own ns/backup_id exemption above: `pool` is an OPTIONAL narrowing
    # filter on a directory-style list, not the sole identity of what's being listed (there is no
    # single-resource target to embed it into the way pbs_tape_pool_get's f"pbs/config/
    # media-pool/{name}" does). pbs_tape_jobs.py, tape_media_list().
    "pbs_tape_media_list": frozenset({"pool"}),
    # pbs_tape_media_content's ledger target is the fixed "pbs/tape/media/content" — same
    # "list-filter, not identity" treatment as pbs_tape_media_list above; backup_id/pool are both
    # optional filters on the content listing, not a single resource this read targets.
    "pbs_tape_media_content": frozenset({"backup_id", "pool"}),
}


def _haystack(plan_dict: dict) -> str:
    """The whole plan, as text — target/change/blast_radius/current/risk_reasons/note/affected.
    Deliberately the FULL plan, not just target+change: several plan_* builders legitimately
    place an identifying value in blast_radius (e.g. plan_clone's storage-override warning,
    plan_storage_create's path/server/export detail line) rather than in change/target."""
    return json.dumps(plan_dict, default=str)


def _identity_kwargs(name: str, kwargs: dict[str, Any]) -> dict[str, Any]:
    exempt = IDENTITY_EXEMPT.get(name, frozenset())
    return {k: v for k, v in kwargs.items() if k in IDENTITY_PARAMS and k not in exempt}


def _value_missing(value: Any, hay: str) -> bool:
    """True if `value` is not reflected in `hay`. Lists (e.g. pve_node_acme_domains_set's
    `domains`) are checked element-wise — str(the_whole_list) would never match the plan's
    per-element rendering."""
    if isinstance(value, (list, tuple)):
        return any(str(v) not in hay for v in value)
    return str(value) not in hay


# ---------------------------------------------------------------------------
# Explicit, honest allowlist: mutating tools this generic sweep does NOT shape-assert, with the
# reason why. Nothing is silently skipped — test_sweep_coverage_is_honest below enforces that
# every mutating tool is in exactly one of {shape-asserted, this allowlist}.
# ---------------------------------------------------------------------------
NOT_SHAPE_ASSERTED: dict[str, str] = {}

# ---------------------------------------------------------------------------
# REAL BUGS this sweep found in src/ (task instructions: do not modify src/, do not paper over
# the assertion — report it). Each is xfail(strict=True): the tool IS shape-asserted (not
# silently skipped, not in NOT_SHAPE_ASSERTED), the failure is pinned and explained, and
# strict=True means this test starts FAILING again the moment the bug is fixed without this
# entry being removed — so the fix can't go unnoticed either.
# ---------------------------------------------------------------------------
# FIXED in this branch: the pve_acme_plugin_update / _create `dns_api` ↔ backend-`api` param
# collision this sweep found — the backend positional param was renamed to `backend` in
# acme_certs.py (see the confirm=True regressions in tests/test_certs.py, the path this dry-run
# sweep can't reach). The KNOWN_BUGS/xfail(strict=True) mechanism stays so a future finding can be
# pinned here again without weakening or deleting an assertion.
KNOWN_BUGS: dict[str, str] = {}


def _run_dry_run(name: str, kwargs: dict[str, Any]) -> dict:
    fn = getattr(server, name)
    return fn(confirm=False, **kwargs)


def _mutating_tool_params():
    for n in MUTATING_TOOLS:
        if n in KNOWN_BUGS:
            yield pytest.param(n, marks=pytest.mark.xfail(reason=KNOWN_BUGS[n], strict=True))
        else:
            yield n


@pytest.mark.parametrize("name", list(_mutating_tool_params()))
def test_mutating_wrapper_plan_shape(name, wired):
    """For every mutating wrapper: dry-run it with synthesized args and check the returned Plan
    is internally consistent with what we asked for. This is the core of the sweep — see the
    module docstring for exactly what "internally consistent" means and why it matters."""
    if name in NOT_SHAPE_ASSERTED:
        pytest.skip(NOT_SHAPE_ASSERTED[name])

    kwargs = _kwargs_for(name)
    resp = _run_dry_run(name, kwargs)

    assert isinstance(resp, dict), f"{name}: dry-run did not return a dict: {resp!r}"
    assert resp.get("status") == "plan", (
        f"{name}: dry-run (confirm=False) must return status='plan', got {resp.get('status')!r} "
        f"— a wrapper returning anything else on the dry-run path may be executing without "
        f"confirmation"
    )
    assert resp.get("action") == name, (
        f"{name}: plan.action is {resp.get('action')!r}, expected the tool's OWN name {name!r} — "
        f"this label is what _plan() stamps from the wrapper's first argument; a mismatch means "
        f"the wrapper is labelling its plan/ledger entry with a DIFFERENT tool's action (copy-paste bug)"
    )
    target = resp.get("target")
    assert isinstance(target, str) and target, (
        f"{name}: plan.target must be a non-empty string, got {target!r}"
    )
    assert resp.get("risk") in {"none", "low", "medium", "high"}, (
        f"{name}: plan.risk is {resp.get('risk')!r}, not a known RISK_* level"
    )
    assert isinstance(resp.get("change"), str) and resp.get("change"), (
        f"{name}: plan.change must be a non-empty human-readable summary, got {resp.get('change')!r}"
    )

    id_kwargs = _identity_kwargs(name, kwargs)
    if id_kwargs:
        hay = _haystack(resp)
        missing = [
            (pname, val) for pname, val in id_kwargs.items()
            if val is not None and _value_missing(val, hay)
        ]
        assert not missing, (
            f"{name}: identity argument(s) {missing} were passed but do NOT appear anywhere in "
            f"the returned plan's target/change ({hay!r}) — the wrapper may be building its plan "
            f"from the WRONG argument, a hardcoded constant, or another tool's target. "
            f"Full kwargs passed: {kwargs!r}"
        )


def test_sweep_coverage_is_honest():
    """No mutating tool is silently unassessed: every one of the 204(ish) mutating tools is
    either shape-asserted by test_mutating_wrapper_plan_shape above, or explicitly listed in
    NOT_SHAPE_ASSERTED with a reason. This test fails loudly if that ever drifts (a tool added
    to the allowlist that no longer exists, or a mutating tool that silently fell through)."""
    mutating_set = set(MUTATING_TOOLS)
    allowlisted = set(NOT_SHAPE_ASSERTED)
    stale = allowlisted - mutating_set
    assert not stale, f"NOT_SHAPE_ASSERTED references tool(s) no longer in the mutating set: {stale}"
    shape_asserted = mutating_set - allowlisted
    # Every mutating tool must be in exactly one bucket (trivially true by construction, but
    # pinned here so a future refactor that changes the parametrize source can't quietly change
    # the meaning of "covered" without this test noticing the counts).
    assert shape_asserted | allowlisted == mutating_set
    print(
        f"\nwrapper-shape sweep coverage: {len(shape_asserted)}/{len(mutating_set)} mutating "
        f"tools shape-asserted; {len(allowlisted)} on the honest allowlist."
    )


# ===========================================================================
# READ-tool sweep (best-effort secondary coverage — the task's primary ask is the mutating
# sweep above, since a wrong READ can't fully-audited-mutate a keys-holding user's infra the
# way a wrong MUTATION can). Read tools have no Plan/target field to inspect, but every one of
# them still calls `_audited(action, target, fn)` (server.py), and `_audited` records `target`
# EXACTLY as the wrapper built it — the read-side mirror of `_plan()`'s target. So the same
# "identity args must show up in what got recorded" check still catches a read wrapper that
# built its request from the wrong argument.
# ===========================================================================


def _entries(log: str) -> list[dict]:
    with open(log, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# Honest allowlist for read tools — same discipline as NOT_SHAPE_ASSERTED above, reasons cited.
NOT_SHAPE_ASSERTED_READ: dict[str, str] = {
    # Aggregate preflight/diagnostic reads: gather evidence from SEVERAL sub-reads under one
    # tool-level ledger entry with a fixed, non-identity target ("preflight" / node-only) by
    # design — there is no per-call identity argument to trace through a target string.
    "pve_doctor": "server.py pve_doctor(): fixed target='preflight', no identity-bearing params",
    "pmg_doctor": "server.py pmg_doctor(): connectivity/permission preflight, no identity params",
    "audit_verify": "server.py audit_verify(): verifies the ledger itself, not a per-object read",
}


@pytest.mark.parametrize("name", READ_TOOLS)
def test_read_wrapper_request_shape(name, wired):
    """For every read-only tool: call it with synthesized args and check the ledger entry
    _audited() recorded is internally consistent — action matches the tool's own name, is
    marked non-mutating, and every identity-bearing argument we passed is reflected somewhere
    in that entry (mirrors test_mutating_wrapper_plan_shape's target/change check, but against
    the PROVE ledger entry instead of a returned Plan, since reads have no Plan)."""
    if name in NOT_SHAPE_ASSERTED_READ:
        pytest.skip(NOT_SHAPE_ASSERTED_READ[name])

    kwargs = _kwargs_for(name)
    fn = getattr(server, name)
    fn(**kwargs)

    entries = [e for e in _entries(wired.log) if e.get("action") == name]
    assert entries, f"{name}: no ledger entry recorded under action={name!r} — _audited() wiring gap?"

    id_kwargs = _identity_kwargs(name, kwargs)
    if not id_kwargs:
        return

    hay = json.dumps(entries, default=str)
    missing = [
        (pname, val) for pname, val in id_kwargs.items()
        if val is not None and _value_missing(val, hay)
    ]
    assert not missing, (
        f"{name}: identity argument(s) {missing} were passed but do NOT appear anywhere in the "
        f"ledger entry/entries recorded for this call ({hay!r}) — the read wrapper may be "
        f"building its request from the WRONG argument. Full kwargs passed: {kwargs!r}"
    )
    assert all(not e.get("mutation") for e in entries), (
        f"{name}: a READ tool recorded a ledger entry with mutation=True: {entries!r}"
    )


def test_read_sweep_coverage_is_honest():
    """Same honesty pin as test_sweep_coverage_is_honest, for the read-tool sweep."""
    read_set = set(READ_TOOLS)
    allowlisted = set(NOT_SHAPE_ASSERTED_READ)
    stale = allowlisted - read_set
    assert not stale, f"NOT_SHAPE_ASSERTED_READ references tool(s) no longer read-only: {stale}"
    shape_asserted = read_set - allowlisted
    assert shape_asserted | allowlisted == read_set
    print(
        f"\nread-tool sweep coverage: {len(shape_asserted)}/{len(read_set)} read tools "
        f"shape-asserted; {len(allowlisted)} on the honest allowlist."
    )
