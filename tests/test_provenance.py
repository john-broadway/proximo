"""Provenance / scope gate (gap #3, slice 1) — arm-time declared TARGET scope.

Out-of-band file named by PROXIMO_SCOPE_PATH, read fresh on every call (no caching — see
provenance.py), enforced at Proximo's mutation funnel. Closes the headline scenario: an injected
instruction targeting a guest OUTSIDE the declared scope (`delete lxc/102` when scope is
`{lxc/900..lxc/910}`) is refused, fail-closed, before the backend call, and audited.

Mirrors tests/test_contain.py's harness exactly: `_wire_server`/`_entries` for the shared `_audited`
funnel, `_wire_with_backends`/`_FakeApi`/`_FakeExec` for the manual-audit-path seams
(`pve_agent_exec`, `ct_exec`/`ct_psql`'s pre-auto-undo gate) — proving the real backend call NEVER
fires when a target is refused, not just that an error was raised.

Build contract (single source of truth): .scratch/proximo-zerotrust/specs/02b-provenance-resolved-contract.md
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.backends import ExecResult, ProximoError
from proximo.config import ProximoConfig
from proximo.planning import (
    RISK_NONE,
    Plan,
    plan_power,
    plan_rollback,
    plan_snapshot_create,
    plan_snapshot_delete,
)
from proximo.provenance import enforce_scope, scope_key, scope_state


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
    # AuditLedger only creates the file lazily on the first record() — a scenario with zero
    # entries (e.g. an in-scope call that writes nothing) means the file may not exist yet.
    path = Path(log_path)
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def _write_scope(tmp_path, monkeypatch, payload: dict) -> Path:
    """Write a scope file and point PROXIMO_SCOPE_PATH at it."""
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps(payload))
    monkeypatch.setenv("PROXIMO_SCOPE_PATH", str(scope))
    return scope


# === Fail-closed core =========================================================================


def test_no_scope_env_means_unrestricted(tmp_path, monkeypatch):
    """PROXIMO_SCOPE_PATH unset -> zero behavior change: any mutation proceeds regardless of target."""
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.delenv("PROXIMO_SCOPE_PATH", raising=False)

    calls = []

    def _fn():
        calls.append(1)
        return {"ok": True}

    resp = server._audited("pve_delete_guest", "lxc/999", _fn, mutation=True)
    assert calls == [1]
    assert resp == {"status": "ok", "result": {"ok": True}}


def test_scope_file_absent_reads_as_unrestricted(tmp_path, monkeypatch):
    """Env set but the file simply doesn't exist yet (transitional armed-not-written window) ->
    reads as no-scope, exactly like an unset env — the mutation proceeds."""
    _wire_server(tmp_path, monkeypatch)
    missing = tmp_path / "scope.json"
    assert not missing.exists()
    monkeypatch.setenv("PROXIMO_SCOPE_PATH", str(missing))

    calls = []
    resp = server._audited("pve_delete_guest", "lxc/999", lambda: calls.append(1) or {"ok": True},
                           mutation=True)
    assert calls == [1]
    assert resp == {"status": "ok", "result": {"ok": True}}


def test_in_scope_target_proceeds(tmp_path, monkeypatch):
    """A target that IS on the declared scope proceeds; ledger records outcome='ok', not blocked."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/900"]})

    calls = []
    resp = server._audited("pve_delete_guest", "lxc/900", lambda: calls.append(1) or {"ok": True},
                           mutation=True)
    assert calls == [1]
    assert resp == {"status": "ok", "result": {"ok": True}}

    entries = _entries(log)
    # Two entries: the SCOPE gate passed, so the mutation actually ran, and a run now opens with
    # an `executing` record before fn() and closes with the outcome. The blocked-path tests above
    # stay at one entry precisely because a refusal never starts an interval.
    assert [e["outcome"] for e in entries] == ["executing", "ok"]
    assert not any(e["outcome"].startswith("blocked:") for e in entries)


def test_out_of_scope_refused_before_backend_call(tmp_path, monkeypatch):
    """HEADLINE (contract §1): scope {lxc/900}; delete lxc/102 -> ProximoError, the wrapped backend
    call NEVER fires, and exactly one ledger entry records outcome='blocked:out_of_scope'."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/900"]})

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_delete_guest", "lxc/102", lambda: calls.append(1), mutation=True)

    assert calls == []
    entries = _entries(log)
    assert len(entries) == 1
    assert entries[0]["action"] == "pve_delete_guest"
    assert entries[0]["target"] == "lxc/102"
    assert entries[0]["mutation"] is True
    assert entries[0]["outcome"] == "blocked:out_of_scope"
    assert entries[0]["detail"]["scope_key"] == "lxc/102"


def test_garbled_scope_file_fails_closed(tmp_path, monkeypatch):
    """Invalid JSON -> every mutation refused (never 'assume unrestricted')."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    scope = tmp_path / "scope.json"
    scope.write_text("{ this is not json")
    monkeypatch.setenv("PROXIMO_SCOPE_PATH", str(scope))

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_delete_guest", "lxc/900", lambda: calls.append(1), mutation=True)

    assert calls == []
    entries = _entries(log)
    assert len(entries) == 1
    assert entries[0]["outcome"] == "blocked:scope_unreadable"


def test_unreadable_scope_file_fails_closed(tmp_path, monkeypatch):
    """Env set (operator opted in) + the existence/read check itself errors -> fail-closed.

    Fire a REAL stat error (no mock): point the scope path THROUGH a regular file, so os.stat
    raises NotADirectoryError (an OSError that is NOT FileNotFoundError) — mirrors
    test_contain.py's test_fail_closed_when_trip_check_raises.
    """
    _wire_server(tmp_path, monkeypatch)
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x")
    monkeypatch.setenv("PROXIMO_SCOPE_PATH", str(blocker / "scope.json"))

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_delete_guest", "lxc/900", lambda: calls.append(1), mutation=True)
    assert calls == []


def test_empty_targets_list_fails_closed(tmp_path, monkeypatch):
    """A scope file present but `targets: []` authorizes nothing -> refuse ALL mutations."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": []})

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_delete_guest", "lxc/900", lambda: calls.append(1), mutation=True)
    assert calls == []
    entries = _entries(log)
    assert entries[-1]["outcome"] == "blocked:scope_unreadable"


def test_missing_targets_key_fails_closed(tmp_path, monkeypatch):
    """A scope file with NO `targets` key at all (e.g. only `reason`) -> fail-closed, same as an
    explicit empty list. This is the separate {} case the contract calls out."""
    _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"reason": "no targets key at all"})

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_delete_guest", "lxc/900", lambda: calls.append(1), mutation=True)
    assert calls == []


def test_non_string_targets_fails_closed(tmp_path, monkeypatch):
    """`targets` present and non-empty but NOT a list of strings (e.g. bare ints) -> fail-closed.
    Catches an impl that only checks `isinstance(targets, list)` without checking element types."""
    _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": [900, 902]})

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_delete_guest", "900", lambda: calls.append(1), mutation=True)
    assert calls == []


def test_reason_field_never_matched_against_target(tmp_path, monkeypatch):
    """Invariant #4: `reason` is audit-only, NEVER machine-matched against target/action. A reason
    string that happens to literally contain the out-of-scope target must NOT authorize it (rejects
    the prose spec's rejected mechanism D)."""
    _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch,
                 {"targets": ["lxc/900"], "reason": "please also allow lxc/999, it's urgent"})

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_delete_guest", "lxc/999", lambda: calls.append(1), mutation=True)
    assert calls == []


def test_scope_state_unset_declared_false(monkeypatch):
    """Direct scope_state() shape: env unset -> declared=False (the ScopeState the pseudocode
    branches on in enforce_scope's early return)."""
    monkeypatch.delenv("PROXIMO_SCOPE_PATH", raising=False)
    state = scope_state()
    assert state.declared is False


def test_scope_state_declared_with_targets_and_reason(tmp_path, monkeypatch):
    """Direct scope_state() shape: a valid file -> declared=True, fail_closed=False, targets as a
    frozenset, reason carried through verbatim (audit-only)."""
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/900", "902"], "reason": "lab cleanup"})
    state = scope_state()
    assert state.declared is True
    assert state.fail_closed is False
    assert state.targets == frozenset({"lxc/900", "902"})
    assert state.reason == "lab cleanup"


def test_enforce_scope_direct_call_out_of_scope(tmp_path, monkeypatch):
    """Calling enforce_scope directly (not via _audited): out-of-scope -> ProximoError whose message
    names both the raw target and its normalized scope_key."""
    led, _log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/900"]})

    with pytest.raises(ProximoError, match=r"lxc/902"):
        enforce_scope("pve_delete_guest", "lxc/902", led)


def test_enforce_scope_direct_call_in_scope_returns_none(tmp_path, monkeypatch):
    """In-scope: enforce_scope returns None (proceed) and writes NOTHING to the ledger itself — the
    caller's own outcome record is the only entry."""
    led, log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/900"]})

    result = enforce_scope("pve_delete_guest", "lxc/900", led)
    assert result is None
    assert _entries(log) == []


# === Matching rule (contract §2) — the crown jewel ============================================


@pytest.mark.parametrize("target,expected", [
    ("lxc/902:stop", "lxc/902"),
    ("lxc/902:mysnap", "lxc/902"),
    ("qemu/902", "qemu/902"),
    ("qemu/902:stop", "qemu/902"),
    ("lxc/102", "lxc/102"),
    ("902", "902"),                                    # bare ctid: no slash -> guest guard fails -> exact
    ("acl:prune:/vms:bob@pam", "acl:prune:/vms:bob@pam"),  # NOT collapsed to "acl"
    ("lxc/902->950", "lxc/902->950"),                  # "->" NOT stripped
])
def test_scope_key_matching_rule(target, expected):
    assert scope_key(target) == expected


def test_guest_power_action_suffix_stripped(tmp_path, monkeypatch):
    """scope {lxc/902} authorizes pve_guest_power's target lxc/902:stop (the :action suffix strips
    to the guest identity); a narrower scope {lxc/900} refuses the SAME target."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/902"]})

    calls = []
    resp = server._audited("pve_guest_power", "lxc/902:stop", lambda: calls.append(1) or {"ok": True},
                           mutation=True)
    assert calls == [1]
    assert resp == {"status": "ok", "result": {"ok": True}}

    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/900"]})
    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/902:stop", lambda: calls.append(2), mutation=True)
    assert calls == [1]  # the second call never fired


def test_snapshot_snapname_suffix_stripped(tmp_path, monkeypatch):
    """scope {lxc/902} authorizes a snapshot op's target lxc/902:<snapname> — the :snapname suffix
    strips the same way the :action suffix does."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/902"]})

    calls = []
    resp = server._audited("pve_snapshot_create", "lxc/902:nightly-2026-07-01",
                           lambda: calls.append(1) or {"ok": True}, mutation=True)
    assert calls == [1]
    assert resp == {"status": "ok", "result": {"ok": True}}
    entries = _entries(log)
    assert entries[-1]["outcome"] == "ok"


def test_no_kind_conflation(tmp_path, monkeypatch):
    """THE core safety assertion: scope {lxc/900} must REFUSE a qemu/900 target — same numeric
    vmid, different guest kind. Normalization may only merge suffixes of the SAME guest identity,
    never collapse kind."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/900"]})

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "qemu/900:stop", lambda: calls.append(1), mutation=True)

    assert calls == []
    entries = _entries(log)
    assert entries[-1]["outcome"] == "blocked:out_of_scope"
    assert entries[-1]["detail"]["scope_key"] == "qemu/900"


def test_clone_arrow_not_stripped_refused(tmp_path, monkeypatch):
    """pve_clone's target lxc/902->950 fails the guest-identity `^(lxc|qemu)/\\d+$` anchor (the `->`
    survives), so it is matched EXACT — refused under a narrow scope even though 902 is the source
    guest. Documented fast-follow limitation, decided fail-closed on purpose."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/902"]})

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_clone", "lxc/902->950", lambda: calls.append(1), mutation=True)

    assert calls == []
    entries = _entries(log)
    assert entries[-1]["outcome"] == "blocked:out_of_scope"
    assert entries[-1]["detail"]["scope_key"] == "lxc/902->950"


def test_acl_target_not_collapsed_to_plane(tmp_path, monkeypatch):
    """An ACL-plane mutation's target acl:prune:/vms:bob@pam must NOT collapse to the leading
    "acl" plane name — the guest-identity guard doesn't match, so the full string is the key, and a
    scope of {lxc/900} (a guest, not the ACL plane) refuses it."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/900"]})

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_acl_prune", "acl:prune:/vms:bob@pam", lambda: calls.append(1),
                        mutation=True)

    assert calls == []
    entries = _entries(log)
    assert entries[-1]["outcome"] == "blocked:out_of_scope"
    assert entries[-1]["detail"]["scope_key"] == "acl:prune:/vms:bob@pam"
    assert entries[-1]["detail"]["scope_key"] != "acl"


def test_bare_ctid_exact_match(tmp_path, monkeypatch):
    """ct_exec/ct_psql's scope target is a BARE ctid (no kind prefix) -> exact string match only.
    Documents the bare-vs-prefixed quirk: scope {"902"} authorizes ct_exec on ctid 902, but scope
    {"lxc/902"} (the guest-op form) does NOT — they are different scope-key strings."""
    cfg, api, exec_, led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"902"}),
    )
    _write_scope(tmp_path, monkeypatch, {"targets": ["902"]})

    resp = server.ct_exec("902", ["echo", "hi"], confirm=True)
    assert resp["status"] == "ok"
    assert exec_.ran == [("902", ["echo", "hi"])]

    # Re-scope with the guest-identity form "lxc/902" instead of the bare ctid -> must NOT match.
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/902"]})
    with pytest.raises(ProximoError):
        server.ct_exec("902", ["echo", "hi-again"], confirm=True)

    assert exec_.ran == [("902", ["echo", "hi"])]  # the second command never ran
    entries = _entries(log)
    assert entries[-1]["outcome"] == "blocked:out_of_scope"
    assert entries[-1]["detail"]["scope_key"] == "902"


# === Per-seam wiring (mirror test_contain.py's BYPASS 1/2) ====================================


class _FakeApi:
    """Minimal backend spy — records exactly which real Proxmox-mutating calls fired, so a refusal
    can be proven by an EMPTY call list, not just a raised error. Mirrors test_contain.py's _FakeApi."""

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
    """Wire proximo.server with FAKE api/exec backends (spies) + a real ledger, so a per-seam test
    can prove a real mutating call never fired — not just that an error was raised."""
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


def test_audited_mutation_gated(tmp_path, monkeypatch):
    """The primary funnel every plain REST-API mutation tool shares: _audited() refuses an
    out-of-scope target before the wrapped fn() (the real backend call) can fire."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/900"]})

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_delete_guest", "lxc/999", lambda: calls.append(1), mutation=True)

    assert calls == []
    entries = _entries(log)
    assert entries[-1]["action"] == "pve_delete_guest"
    assert entries[-1]["outcome"] == "blocked:out_of_scope"


def test_pve_agent_exec_gated_directly(tmp_path, monkeypatch):
    """pve_agent_exec has a manual audit path — it calls api.agent_exec directly and never runs
    through _audited(). Prove enforce_scope is called there too: out-of-scope -> ProximoError, and
    api.agent_exec is NEVER called (the guest command must not fire, not even partially)."""
    _cfg, api, _exec, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_agent=True, agent_allowlist=frozenset({"101"}),
    )
    _write_scope(tmp_path, monkeypatch, {"targets": ["qemu/900"]})

    with pytest.raises(ProximoError):
        server.pve_agent_exec("101", ["echo", "hi"], confirm=True)

    assert api.agent_execs == []
    assert api.agent_exec_statuses == []
    entries = _entries(log)
    blocked = [e for e in entries if e["outcome"] == "blocked:out_of_scope"]
    assert len(blocked) == 1
    assert blocked[0]["action"] == "pve_agent_exec"
    assert blocked[0]["target"] == "qemu/101"
    assert blocked[0]["mutation"] is True


def test_ct_exec_gated_before_auto_undo(tmp_path, monkeypatch):
    """ct_exec's auto-undo snapshot (_auto_undo -> api.snapshot_create) fires BEFORE the payload
    reaches _audited(mutation=True). Prove enforce_scope gates the WHOLE operation, not just the
    exec half: out-of-scope -> ProximoError, api.snapshot_create NEVER called, command never runs."""
    _cfg, api, exec_, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}),
    )
    _write_scope(tmp_path, monkeypatch, {"targets": ["999"]})

    with pytest.raises(ProximoError):
        server.ct_exec("105", ["rm", "-rf", "/x"], snapshot=True, confirm=True)

    assert api.snapshot_creates == []
    assert exec_.ran == []
    entries = _entries(log)
    blocked = [e for e in entries if e["outcome"] == "blocked:out_of_scope"]
    assert len(blocked) == 1
    assert blocked[0]["action"] == "ct_exec"
    assert blocked[0]["target"] == "105"


def test_ct_psql_gated_directly(tmp_path, monkeypatch):
    """Same proof for ct_psql (shares _auto_undo with ct_exec): out-of-scope -> refused, the SQL
    backend call NEVER fires."""
    _cfg, api, exec_, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}),
    )
    _write_scope(tmp_path, monkeypatch, {"targets": ["999"]})

    with pytest.raises(ProximoError):
        server.ct_psql("105", "DELETE FROM t", snapshot=True, confirm=True)

    assert api.snapshot_creates == []
    assert exec_.ran == []
    entries = _entries(log)
    blocked = [e for e in entries if e["outcome"] == "blocked:out_of_scope"]
    assert len(blocked) == 1
    assert blocked[0]["action"] == "ct_psql"
    assert blocked[0]["target"] == "105"


# === Ungated preview + structural guard ========================================================


def test_plan_dry_run_not_gated(tmp_path, monkeypatch):
    """The dry-run PLAN path (_plan) is NEVER gated by scope — a target outside the declared scope
    still gets its preview: no refusal, no blocked ledger entry. Only the mutation path is gated."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch, {"targets": ["lxc/900"]})

    def _build():
        return Plan(
            action="x", target="lxc/999", change="would delete", current={},
            blast_radius=[], risk=RISK_NONE, risk_reasons=[],
        )

    plan = server._plan("pve_delete_guest", "lxc/999", _build)
    assert plan.change == "would delete"

    entries = _entries(log)
    assert not any(e["outcome"].startswith("blocked:") for e in entries)
    assert any(e["outcome"] == "planned" for e in entries)


def test_plan_records_wrapper_target_not_factory_target(tmp_path, monkeypatch):
    # L15 (2026-07-10 audit): the wrapper's target is authoritative — the recorded 'planned' entry
    # must carry it, not the plan factory's internal (possibly different) target, so the planned and
    # executed ledger entries pair under ONE target (as the action already does).
    _led, log = _wire_server(tmp_path, monkeypatch)

    def _build():
        return Plan(action="factory_action", target="node/pve/factory-target", change="x",
                    current={}, blast_radius=[], risk=RISK_NONE, risk_reasons=[])

    plan = server._plan("pve_node_service_control", "svc/pve/sshd", _build)
    assert plan.target == "svc/pve/sshd"
    planned = [e for e in _entries(log) if e["outcome"] == "planned"]
    assert planned and planned[-1]["target"] == "svc/pve/sshd"


# Pre-existing tools ALREADY use a `scope` parameter for something unrelated to provenance: the
# Proxmox firewall plane's own "cluster/node/guest" domain selector (`scope: str = "cluster"`,
# e.g. pve_firewall_rules_list, pve_firewall_rule_add, pve_firewall_set_enabled, ...) and
# pbs_realm_sync's realm-sync scope. Verified by reading every definition in server.py — each one
# takes a plain scalar (`str` or `str | None`), never a list. That is a different SHAPE than a
# provenance target allowlist (a list of target strings) and predates this feature entirely, so
# it is not the self-authorization hole invariant #3 guards against. This is a fixed, named
# allowlist (not a loophole): any OTHER tool — new or old — is still forbidden a `scope` param,
# and even these exempted ones are pinned to stay scalar-shaped (never silently repurposed into a
# target-list kwarg).
_PRE_EXISTING_SCALAR_SCOPE_PARAMS = frozenset({
    "pve_firewall_rules_list", "pve_firewall_options_get", "pve_ipset_list",
    "pve_firewall_rule_add", "pve_firewall_rule_remove", "pve_firewall_rule_update",
    "pve_firewall_set_enabled", "pve_firewall_alias_list", "pve_firewall_alias_create",
    "pve_firewall_alias_update", "pve_firewall_alias_delete", "pve_firewall_ipset_create",
    "pve_firewall_ipset_delete", "pve_firewall_ipset_entry_add", "pve_firewall_ipset_entry_remove",
    "pve_firewall_options_set", "pbs_realm_sync",
    # Wave 6a (2026-07-16): pve_ceph_metadata's `scope` is the schema's own real Proxmox
    # vocabulary ("all"/"versions" — which metadata facet to return), a scalar enum string, not
    # a provenance target-list. Same category as the pre-existing entries above.
    "pve_ceph_metadata",
})


async def test_no_tool_accepts_a_scope_kwarg():
    """Structural invariant (contract §4.3): no @tool()-decorated function may accept a `scope`
    parameter shaped like a provenance target allowlist — scope is out-of-band ONLY. If a tool
    accepted a target-list scope=..., an agent could self-declare or override its own authorized
    target set, re-introducing the gap #1 self-authorization violation. Mirrors test_consent.py's
    structural guard for the analogous consent-id gap.

    Excludes the pre-existing, unrelated scalar `scope` params documented above (real Proxmox
    vocabulary, not a target list) — but still pins their default to a scalar shape, so this test
    would catch it if one were ever widened into a list.
    """
    import inspect

    tools = await server.mcp.list_tools()
    offenders = []
    for t in tools:
        fn = getattr(server, t.name, None)
        if fn is None or not callable(fn):
            continue
        sig = inspect.signature(fn)
        for pname, param in sig.parameters.items():
            if pname.lower() != "scope":
                continue
            if t.name in _PRE_EXISTING_SCALAR_SCOPE_PARAMS:
                assert param.default is inspect.Parameter.empty or isinstance(param.default, (str, type(None))), (
                    f"{t.name}(scope) default changed shape to {param.default!r} — this pre-existing "
                    "exemption assumed a scalar; re-audit as a possible provenance self-authorization path"
                )
                continue
            offenders.append(f"{t.name}({pname})")
    assert not offenders, f"tool(s) accept a caller-supplied provenance-shaped scope param: {offenders}"


# === Regression (FIX A): unvalidated vmid/kind colon-smuggles the scope gate ==================
#
# plan_snapshot_create/plan_snapshot_delete built Plan.target = f"{kind}/{vmid}:{snapname}" from
# RAW args with no validation. A colon-smuggled vmid like "900:1" produces target
# "lxc/900:1:x", and scope_key splits on the FIRST ":" -> "lxc/900" — false-matching a scope of
# {lxc/900} for a vmid that was never actually validated as numeric. _check_vmid/_check_kind at
# the top of both functions rejects the smuggle at plan-time, before the gate ever runs.


def test_plan_snapshot_create_rejects_colon_smuggled_vmid():
    with pytest.raises(ProximoError):
        plan_snapshot_create(vmid="900:1", snapname="x", kind="lxc")


def test_plan_snapshot_delete_rejects_colon_smuggled_vmid():
    with pytest.raises(ProximoError):
        plan_snapshot_delete(vmid="900:1", snapname="x", kind="lxc")


def test_plan_snapshot_create_rejects_invalid_kind():
    with pytest.raises(ProximoError):
        plan_snapshot_create(vmid="900", snapname="x", kind="bogus")


def test_plan_snapshot_delete_rejects_invalid_kind():
    with pytest.raises(ProximoError):
        plan_snapshot_delete(vmid="900", snapname="x", kind="bogus")


# The other TWO plan_* fns that build a suffixed guest target f"{kind}/{vmid}:..." — plan_power and
# plan_rollback — each do a plan-time API READ whose backend transitively validates the vmid
# (api.guest_status -> _check_vmid; api.snapshot_list -> _snap_base -> _check_vmid), so a smuggle is
# rejected TODAY, before the read even completes. This is NOT a live false-authorize. Adding the
# explicit _check_vmid/_check_kind at the top is defense-in-depth: the gate's correctness must not
# depend on a downstream read happening to validate (a future refactor dropping that read would
# silently reopen the hole). These tests pin that the check fires BEFORE the read — a spy api whose
# read method is NEVER called proves the validation is explicit, not merely transitive.


class _ReadSpy:
    """Records whether the plan-time READ backend call fired. If validation is explicit (fires
    first), the read method is never reached on a bad vmid."""

    def __init__(self):
        self.guest_status_calls: list = []
        self.snapshot_list_calls: list = []

    def guest_status(self, vmid, kind="lxc", node=None):
        self.guest_status_calls.append((vmid, kind, node))
        return {"status": "running"}

    def snapshot_list(self, vmid, kind="lxc", node=None):
        self.snapshot_list_calls.append((vmid, kind, node))
        return []


def test_plan_power_rejects_colon_smuggled_vmid():
    api = _ReadSpy()
    with pytest.raises(ProximoError):
        plan_power(api, "900:1", "stop", kind="lxc")
    assert api.guest_status_calls == []  # validation fired BEFORE the read (explicit, not transitive)


def test_plan_rollback_rejects_colon_smuggled_vmid():
    api = _ReadSpy()
    with pytest.raises(ProximoError):
        plan_rollback(api, "900:1", "before_x", kind="lxc")
    assert api.snapshot_list_calls == []  # validation fired BEFORE the read


def test_plan_power_rejects_invalid_kind():
    api = _ReadSpy()
    with pytest.raises(ProximoError):
        plan_power(api, "900", "stop", kind="bogus")
    assert api.guest_status_calls == []


def test_plan_rollback_rejects_invalid_kind():
    api = _ReadSpy()
    with pytest.raises(ProximoError):
        plan_rollback(api, "900", "before_x", kind="bogus")
    assert api.snapshot_list_calls == []


# === Regression (FIX B): scope_state's parse guard must fail-closed on ANY read/parse error =====
#
# `except (OSError, ValueError)` around json.load does NOT catch RecursionError (a deeply-nested
# scope file) — it propagates before the fail-closed ScopeState is returned, so enforce_scope
# raises a raw RecursionError with NO ledger record (record-before-raise violated). A size cap
# also guards against a MemoryError on a huge file before json.load ever runs.


def test_deeply_nested_scope_file_fails_closed_not_recursion_error(tmp_path, monkeypatch):
    """A pathologically deep JSON scope file must fail-closed via ProximoError + a recorded ledger
    entry — NOT propagate a raw RecursionError with an empty ledger."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    scope = tmp_path / "scope.json"
    scope.write_text("[" * 100000 + "]" * 100000)
    monkeypatch.setenv("PROXIMO_SCOPE_PATH", str(scope))

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_delete_guest", "lxc/900", lambda: calls.append(1), mutation=True)

    assert calls == []
    entries = _entries(log)
    assert entries, "the blocked attempt must be recorded to the ledger, not silently propagate"
    assert entries[-1]["outcome"] == "blocked:scope_unreadable"


def test_oversized_scope_file_fails_closed(tmp_path, monkeypatch):
    """A scope file larger than the sane size cap is refused fail-closed. A real scope file is
    tiny; this guards against a MemoryError on a huge file before json.load ever runs on it."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    scope = tmp_path / "scope.json"
    huge_targets = ", ".join(f'"lxc/{i}"' for i in range(1, 200000))
    payload = '{"targets": [' + huge_targets + "]}"
    scope.write_text(payload)
    assert scope.stat().st_size > (1 << 20)  # bigger than the 1 MiB cap
    monkeypatch.setenv("PROXIMO_SCOPE_PATH", str(scope))

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_delete_guest", "lxc/900", lambda: calls.append(1), mutation=True)

    assert calls == []
    entries = _entries(log)
    assert entries[-1]["outcome"] == "blocked:scope_unreadable"


# === Regression (FIX C): `reason` documented audit-only but never written to the ledger ========
#
# contain.py folds state.reason into its blocked ledger detail; enforce_scope never did, so the
# operator's scope justification was invisible in PROVE after a refusal. Still audit-only (never
# matched against target/action — see test_reason_field_never_matched_against_target above).


def test_reason_included_in_out_of_scope_blocked_detail(tmp_path, monkeypatch):
    _led, log = _wire_server(tmp_path, monkeypatch)
    _write_scope(tmp_path, monkeypatch,
                 {"targets": ["lxc/900"], "reason": "maintenance window for the 900 range"})

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_delete_guest", "lxc/999", lambda: calls.append(1), mutation=True)

    assert calls == []
    entries = _entries(log)
    assert entries[-1]["outcome"] == "blocked:out_of_scope"
    assert entries[-1]["detail"]["reason"] == "maintenance window for the 900 range"


# === Regression (FIX D): tighten _GUEST_RE (ASCII digits only, strict \Z end) ===================
#
# `\d` accepts Unicode/fullwidth digits and a bare `$` matches before a trailing `\n`. The bare
# (no colon-suffix) forms return their input unchanged either way — normalization only changes
# output when a colon suffix gets stripped — so the colon-suffixed forms are the cases that
# actually distinguish old (loose) vs. new (tightened) matching behavior.


def test_scope_key_rejects_unicode_and_trailing_newline_guest_forms():
    """Fail-safe direction: fullwidth-digit and trailing-newline guest-shaped targets are never
    treated as a normalizable guest identity — scope_key returns the FULL input EXACT."""
    fullwidth = "lxc/９００"  # "lxc/900" with fullwidth digits
    assert scope_key(fullwidth) == fullwidth

    trailing_newline = "lxc/900\n"
    assert scope_key(trailing_newline) == trailing_newline

    # Colon-suffixed forms are where the loose regex actually mis-normalizes (strips the suffix
    # instead of leaving the whole string exact) — this is the genuinely distinguishing case.
    fullwidth_suffixed = "lxc/９００:snap"
    assert scope_key(fullwidth_suffixed) == fullwidth_suffixed

    trailing_newline_suffixed = "lxc/900\n:snap"
    assert scope_key(trailing_newline_suffixed) == trailing_newline_suffixed
