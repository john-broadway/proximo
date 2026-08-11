"""Per-surface autonomy envelope — FORBID + RATE walls (Commit 1 + Commit 2). Mirrors
test_lease.py's harness discipline (`_wire_server`/`_wire_with_backends`, `_entries`, the
FakeApi/FakeExec bypass proofs). Real per-target mechanism: `targets._active_target.set(name)` /
`.reset(token)` (see tests/test_server_multitarget.py) — a raw ContextVar, not a helper function.

RATE tests call `envelope.begin_operation()` before a raw `server._audited(...)` call to simulate
what `server.py::_plan()` does for every real plan-then-mutate tool invocation — a FRESH operation,
so the per-operation `_rate_reserved` de-dup flag doesn't leak a reservation across unrelated test
mutations that never actually go through `_plan()`.

Build contract: .scratch/proximo-zerotrust/specs/05-per-surface-autonomy-envelope.md §11 (B=forbid,
C=rate, E=honest limits).
"""

from __future__ import annotations

import hashlib
import json
import textwrap
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import proximo.consent as consent
import proximo.server as server
from proximo import envelope, targets
from proximo.audit import AuditLedger
from proximo.backends import ExecResult, ProximoError
from proximo.config import ProximoConfig
from proximo.planning import RISK_NONE, Plan

# === Harness (mirrors test_lease.py) ===========================================================


def _wire_server(tmp_path, monkeypatch, *, token_path=None):
    """Wire proximo.server with a real ledger (tmp_path) and no live backends."""
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json",
        node="pve",
        token_path=token_path or str(tmp_path / "pve-token"),
        audit_log_path=log,
        audit_keyed=False,
    )
    led = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))
    return led, log


def _entries(log_path) -> list[dict]:
    return [json.loads(ln) for ln in Path(log_path).read_text().splitlines() if ln.strip()]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for var in ("PROXIMO_FORBID", "PROXIMO_TARGETS", "PROXIMO_API_BASE_URL",
                "PROXIMO_RATE_MAX", "PROXIMO_RATE_WINDOW"):
        monkeypatch.delenv(var, raising=False)
    token = targets._active_target.set(None)
    rate_token = envelope._rate_reserved.set(False)
    yield
    targets._active_target.reset(token)
    envelope._rate_reserved.reset(rate_token)


def _registry(monkeypatch, tmp_path, body):
    p = tmp_path / "targets.toml"
    p.write_text(textwrap.dedent(body))
    monkeypatch.setenv("PROXIMO_TARGETS", str(p))


def _rate_key(base_url: str) -> str:
    """Mirror envelope._box_key so tests can seed/inspect the reservation file directly."""
    return hashlib.sha256(base_url.encode("utf-8")).hexdigest()[:16]


def _rate_path(tmp_path, base_url: str) -> Path:
    return tmp_path / ".proximo-rate" / f"{_rate_key(base_url)}.rate"


# === Inert / backward-compat ====================================================================


def test_envelope_inert_when_unset(tmp_path, monkeypatch):
    """Nothing set -> mutation proceeds (backward compat, zero behavior change)."""
    _wire_server(tmp_path, monkeypatch)
    calls = []
    resp = server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1) or {"ok": True},
                            mutation=True)
    assert calls == [1]
    assert resp == {"status": "ok", "result": {"ok": True}}


# === Forbid-list =================================================================================


def test_forbidden_action_refused(tmp_path, monkeypatch):
    """HEADLINE: forbid `pve_delete_guest` (global env) -> ProximoError, fn NEVER called, ledger
    outcome="blocked:forbidden"."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_FORBID", "pve_delete_guest")

    calls = []
    with pytest.raises(ProximoError, match="forbidden"):
        server._audited("pve_delete_guest", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []

    entries = _entries(log)
    assert len(entries) == 1
    assert entries[0]["action"] == "pve_delete_guest"
    assert entries[0]["target"] == "lxc/100"
    assert entries[0]["mutation"] is True
    assert entries[0]["outcome"] == "blocked:forbidden"
    assert entries[0]["detail"]["forbid"] == ["pve_delete_guest"]


def test_forbid_substring_alias(tmp_path, monkeypatch):
    """A category alias (`delete`) expands to every matching action name, but leaves unrelated
    actions untouched."""
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_FORBID", "delete")

    for action in ("pbs_datastore_delete", "pve_delete_guest"):
        calls = []
        with pytest.raises(ProximoError, match="forbidden"):
            server._audited(action, "x", lambda calls=calls: calls.append(1), mutation=True)
        assert calls == []

    calls = []
    server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == [1]


def test_forbid_empty_entry_dropped(tmp_path, monkeypatch):
    """`PROXIMO_FORBID=" ,,"` parses to an empty set (dropped empties) -> inert, NOT forbid-all."""
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_FORBID", " ,,")

    calls = []
    server._audited("pve_delete_guest", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == [1]


# === Forbid — sub-action composite match (redteam regressions) =================================


def test_subaction_in_target_forbidden(tmp_path, monkeypatch):
    """The dangerous sub-action often lives in the TARGET string (`lxc/100:stop`,
    `pve/services/sshd:stop`), not the bare action name -> the composite match must catch it."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_FORBID", "stop")

    calls = []
    with pytest.raises(ProximoError, match="forbidden"):
        server._audited("pve_guest_power", "lxc/100:stop", lambda: calls.append(1),
                         mutation=True, detail={"confirmed": True})
    assert calls == []

    monkeypatch.setenv("PROXIMO_FORBID", "sshd")
    calls2 = []
    with pytest.raises(ProximoError, match="forbidden"):
        server._audited("pve_node_service_control", "pve/services/sshd:stop",
                         lambda: calls2.append(1), mutation=True)
    assert calls2 == []


def test_subaction_in_detail_forbidden(tmp_path, monkeypatch):
    """The dangerous sub-action can also live in `detail["action"]` (e.g. pmg_quarantine_action's
    delete/deliver/whitelist choice) -> the composite match must catch that too."""
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_FORBID", "delete")

    calls = []
    with pytest.raises(ProximoError, match="forbidden"):
        server._audited("pmg_quarantine_action", "pmg/quarantine/content", lambda: calls.append(1),
                         mutation=True, detail={"action": "delete"})
    assert calls == []


def test_subaction_match_does_not_overreach(tmp_path, monkeypatch):
    """A forbidden sub-action string must not blanket-match an unrelated call that merely shares
    the same action/plane but not the sub-action."""
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_FORBID", "stop")

    calls = []
    server._audited("pve_guest_power", "lxc/100:start", lambda: calls.append(1), mutation=True)
    assert calls == [1]


# === Forbid — global floor + fail-closed-unregistered (redteam regressions) ====================


def test_global_floor_applies_to_named_target(tmp_path, monkeypatch):
    """PROXIMO_FORBID (global floor) applies to EVERY mutation regardless of active target, even a
    registered target with no forbid list of its own -> inescapable."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _registry(monkeypatch, tmp_path, """
        [targets.alpha]
        kind = "pve"
        base_url = "https://198.51.100.10:8006/api2/json"
        node = "alpha"
        token_path = "/etc/proximo/alpha.token"
    """)
    monkeypatch.setenv("PROXIMO_FORBID", "pve_delete_guest")

    token = targets._active_target.set("alpha")
    try:
        calls = []
        with pytest.raises(ProximoError, match="forbidden"):
            server._audited("pve_delete_guest", "lxc/100", lambda: calls.append(1), mutation=True)
        assert calls == []
    finally:
        targets._active_target.reset(token)


def test_unregistered_active_target_fails_closed(tmp_path, monkeypatch):
    """An active target that isn't in the registry is an anomaly (stale-cache exposure) -> refuse
    EVERY mutation on it, fail-closed (forbid-all), not "no envelope configured"."""
    _wire_server(tmp_path, monkeypatch)

    token = targets._active_target.set("ghost")
    try:
        calls = []
        with pytest.raises(ProximoError, match="forbidden"):
            server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
        assert calls == []
    finally:
        targets._active_target.reset(token)


def test_per_target_forbid_unions_with_floor(tmp_path, monkeypatch):
    """The active target's own forbid list and the global floor both apply -> union, not
    either/or."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _registry(monkeypatch, tmp_path, """
        [targets.alpha]
        kind = "pve"
        base_url = "https://198.51.100.10:8006/api2/json"
        node = "alpha"
        token_path = "/etc/proximo/alpha.token"
        forbid = ["ct_exec"]
    """)
    monkeypatch.setenv("PROXIMO_FORBID", "pve_delete_guest")

    token = targets._active_target.set("alpha")
    try:
        calls = []
        with pytest.raises(ProximoError, match="forbidden"):
            server._audited("ct_exec", "ct/105", lambda: calls.append(1), mutation=True)
        assert calls == []

        calls2 = []
        with pytest.raises(ProximoError, match="forbidden"):
            server._audited("pve_delete_guest", "lxc/100", lambda: calls2.append(1), mutation=True)
        assert calls2 == []
    finally:
        targets._active_target.reset(token)


def test_forbid_garbled_shape_fails_closed(tmp_path, monkeypatch):
    """A per-target `forbid` that isn't a list-of-str/comma-string (e.g. a bare int) is a garbled
    shape -> fail-closed forbid-all, refusing even an unrelated, otherwise-benign action."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    _registry(monkeypatch, tmp_path, """
        [targets.gamma]
        kind = "pve"
        base_url = "https://198.51.100.30:8006/api2/json"
        node = "gamma"
        token_path = "/etc/proximo/gamma.token"
        forbid = 42
    """)

    token = targets._active_target.set("gamma")
    try:
        calls = []
        with pytest.raises(ProximoError, match="forbidden"):
            server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
        assert calls == []
    finally:
        targets._active_target.reset(token)

    entries = _entries(log)
    blocked = [e for e in entries if e["outcome"] == "blocked:forbidden"]
    assert len(blocked) == 1
    assert blocked[0]["action"] == "pve_guest_power"


# === Per-target resolution =======================================================================


def test_per_target_envelope_resolution(tmp_path, monkeypatch):
    """Two targets with different forbid lists; only the ACTIVE target's forbid applies."""
    led, _log = _wire_server(tmp_path, monkeypatch)
    _registry(monkeypatch, tmp_path, """
        [targets.alpha]
        kind = "pve"
        base_url = "https://198.51.100.10:8006/api2/json"
        node = "alpha"
        token_path = "/etc/proximo/alpha.token"
        forbid = ["pve_delete_guest"]

        [targets.beta]
        kind = "pve"
        base_url = "https://198.51.100.20:8006/api2/json"
        node = "beta"
        token_path = "/etc/proximo/beta.token"
        forbid = ["pve_guest_power"]
    """)

    token = targets._active_target.set("alpha")
    try:
        calls = []
        with pytest.raises(ProximoError, match="forbidden"):
            server._audited("pve_delete_guest", "lxc/100", lambda: calls.append(1), mutation=True)
        assert calls == []
        # beta's forbid (pve_guest_power) does NOT apply while alpha is active.
        calls2 = []
        server._audited("pve_guest_power", "lxc/100", lambda: calls2.append(1), mutation=True)
        assert calls2 == [1]
    finally:
        targets._active_target.reset(token)

    token = targets._active_target.set("beta")
    try:
        calls3 = []
        with pytest.raises(ProximoError, match="forbidden"):
            server._audited("pve_guest_power", "lxc/100", lambda: calls3.append(1), mutation=True)
        assert calls3 == []
        # alpha's forbid (pve_delete_guest) does NOT apply while beta is active.
        calls4 = []
        server._audited("pve_delete_guest", "lxc/100", lambda: calls4.append(1), mutation=True)
        assert calls4 == [1]
    finally:
        targets._active_target.reset(token)


def test_global_env_fallback_when_no_active_target(tmp_path, monkeypatch):
    """No active target -> global env forbid applies (single-target deployment)."""
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_FORBID", "pve_delete_guest")

    token = targets._active_target.set(None)
    try:
        calls = []
        with pytest.raises(ProximoError, match="forbidden"):
            server._audited("pve_delete_guest", "lxc/100", lambda: calls.append(1), mutation=True)
        assert calls == []
    finally:
        targets._active_target.reset(token)


# === Reads / PLAN not gated ======================================================================


def test_reads_and_plan_not_gated(tmp_path, monkeypatch):
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_FORBID", "pve_delete_guest")

    # A READ (mutation=False) using a forbidden action name still proceeds.
    result = server._audited("pve_delete_guest", "lxc/100", lambda: {"status": "would-be-read"})
    assert result == {"status": "would-be-read"}

    # The dry-run PLAN path (_plan) is not gated either.
    def _build():
        return Plan(
            action="x", target="lxc/100", change="would delete", current={},
            blast_radius=[], risk=RISK_NONE, risk_reasons=[],
        )

    plan = server._plan("pve_delete_guest", "lxc/100", _build)
    assert plan.change == "would delete"


# === BYPASS proofs: manual-audit-path tools that don't run through _audited() ==================


class _FakeApi:
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
    def __init__(self):
        self.ran: list = []

    def run(self, ctid, command, timeout=60):
        self.ran.append((ctid, command))
        return ExecResult(str(ctid), " ".join(command), 0, "out", "")

    def psql(self, ctid, sql, db="postgres", user="postgres", timeout=60):
        self.ran.append((ctid, sql))
        return ExecResult(str(ctid), sql, 0, "out", "")


def _wire_with_backends(tmp_path, monkeypatch, *, token_path=None, enable_agent=False,
                         agent_allowlist=frozenset(), enable_exec=False, ct_allowlist=frozenset()):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve",
        token_path=token_path or str(tmp_path / "pve-token"),
        audit_log_path=log, audit_keyed=False,
        enable_agent=enable_agent, agent_allowlist=agent_allowlist,
        enable_exec=enable_exec, ct_allowlist=ct_allowlist,
    )
    api = _FakeApi()
    exec_ = _FakeExec()
    led = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, exec_, led))
    return cfg, api, exec_, led, log


def test_pve_agent_exec_envelope_gated(tmp_path, monkeypatch):
    _cfg, api, _exec, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_agent=True, agent_allowlist=frozenset({"101"}),
    )
    monkeypatch.setenv("PROXIMO_FORBID", "pve_agent_exec")

    with pytest.raises(ProximoError, match="forbidden"):
        server.pve_agent_exec("101", ["echo", "hi"], confirm=True)

    assert api.agent_execs == []
    assert api.agent_exec_statuses == []
    entries = _entries(log)
    blocked = [e for e in entries if e["outcome"] == "blocked:forbidden"]
    assert len(blocked) == 1
    assert blocked[0]["action"] == "pve_agent_exec"
    assert blocked[0]["mutation"] is True


def test_ct_exec_envelope_gated(tmp_path, monkeypatch):
    _cfg, api, exec_, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}),
    )
    monkeypatch.setenv("PROXIMO_FORBID", "ct_exec")

    with pytest.raises(ProximoError, match="forbidden"):
        server.ct_exec("105", ["rm", "-rf", "/x"], snapshot=True, confirm=True)

    assert api.snapshot_creates == []
    assert exec_.ran == []
    entries = _entries(log)
    blocked = [e for e in entries if e["outcome"] == "blocked:forbidden"]
    assert len(blocked) == 1
    assert blocked[0]["action"] == "ct_exec"


def test_ct_psql_envelope_gated(tmp_path, monkeypatch):
    _cfg, api, exec_, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}),
    )
    monkeypatch.setenv("PROXIMO_FORBID", "ct_psql")

    with pytest.raises(ProximoError, match="forbidden"):
        server.ct_psql("105", "DELETE FROM t", snapshot=True, confirm=True)

    assert api.snapshot_creates == []
    assert exec_.ran == []
    entries = _entries(log)
    blocked = [e for e in entries if e["outcome"] == "blocked:forbidden"]
    assert len(blocked) == 1
    assert blocked[0]["action"] == "ct_psql"


# === Rate / budget wall (Commit 2, design spec §11.C) ============================================


def test_rate_under_budget_proceeds(tmp_path, monkeypatch):
    """HEADLINE (part 1): under the configured rate_max, every mutation proceeds."""
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_RATE_MAX", "2")

    calls = []
    for _ in range(2):
        envelope.begin_operation()
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == [1, 1]


def test_rate_at_budget_refused(tmp_path, monkeypatch):
    """HEADLINE (part 2): exactly rate_max succeed; the NEXT attempt is refused
    outcome="blocked:rate_budget", fn NEVER called, detail carries rate_max/rate_window/box."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_RATE_MAX", "2")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "60")

    calls = []
    for _ in range(2):
        envelope.begin_operation()
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == [1, 1]

    envelope.begin_operation()
    with pytest.raises(ProximoError, match="rate"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == [1, 1]  # fn never called on the refused attempt

    entries = _entries(log)
    blocked = [e for e in entries if e["outcome"] == "blocked:rate_budget"]
    assert len(blocked) == 1
    assert blocked[0]["detail"]["rate_max"] == 2
    assert blocked[0]["detail"]["rate_window"] == 60
    assert "box" in blocked[0]["detail"]


def test_rate_window_expiry(tmp_path, monkeypatch):
    """A slot older than the window has already expired -> doesn't count against the budget."""
    _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "60")

    rate_path = _rate_path(tmp_path, base_url)
    rate_path.parent.mkdir(parents=True, exist_ok=True)
    rate_path.write_text(f"{time.time() - 3600!r}\n")  # an hour old -> outside the 60s window

    calls = []
    envelope.begin_operation()
    server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == [1]


def test_rate_garbled_max_fails_closed(tmp_path, monkeypatch):
    """A garbled PROXIMO_RATE_MAX collapses the box's cap to 0 -> refuse every mutation."""
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_RATE_MAX", "abc")

    calls = []
    envelope.begin_operation()
    with pytest.raises(ProximoError, match="rate"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []


def test_rate_no_base_url_with_declared_cap_fails_closed(tmp_path, monkeypatch):
    """A rate cap is clearly declared (PROXIMO_RATE_MAX set) but the box's identity can't be
    resolved (PROXIMO_API_BASE_URL unset, no active target) -> fail-closed refuse rather than
    silently treating the unresolvable identity as "no envelope configured"."""
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "5")

    calls = []
    envelope.begin_operation()
    with pytest.raises(ProximoError, match="rate"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []


def test_corrupt_reservation_line_fails_closed(tmp_path, monkeypatch):
    """A non-float line in the reservation file counts as a USED slot (fail-closed, never
    dropped) -> with rate_max=1 the corrupt line alone exhausts the budget."""
    _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")

    rate_path = _rate_path(tmp_path, base_url)
    rate_path.parent.mkdir(parents=True, exist_ok=True)
    rate_path.write_text("not-a-float\n")

    calls = []
    envelope.begin_operation()
    with pytest.raises(ProximoError, match="rate"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []


def test_rate_per_box_isolation(tmp_path, monkeypatch):
    """Two distinct base_urls -> box A's reservations don't touch box B's budget (closes lens 2 F1
    contamination)."""
    _wire_server(tmp_path, monkeypatch)
    _registry(monkeypatch, tmp_path, """
        [targets.alpha]
        kind = "pve"
        base_url = "https://198.51.100.10:8006/api2/json"
        node = "alpha"
        token_path = "/etc/proximo/alpha.token"
        rate_max = 1

        [targets.beta]
        kind = "pve"
        base_url = "https://198.51.100.20:8006/api2/json"
        node = "beta"
        token_path = "/etc/proximo/beta.token"
        rate_max = 1
    """)

    token_a = targets._active_target.set("alpha")
    try:
        envelope.begin_operation()
        server._audited("pve_guest_power", "lxc/100", lambda: None, mutation=True)
    finally:
        targets._active_target.reset(token_a)

    # beta's own budget (also 1) is untouched by alpha's usage -> proceeds.
    token_b = targets._active_target.set("beta")
    try:
        envelope.begin_operation()
        server._audited("pve_guest_power", "lxc/100", lambda: None, mutation=True)
    finally:
        targets._active_target.reset(token_b)

    # alpha's budget (1) is now exhausted -> refused.
    token_a2 = targets._active_target.set("alpha")
    try:
        envelope.begin_operation()
        with pytest.raises(ProximoError, match="rate"):
            server._audited("pve_guest_power", "lxc/100", lambda: None, mutation=True)
    finally:
        targets._active_target.reset(token_a2)


def test_caller_cannot_evade_via_alias(tmp_path, monkeypatch):
    """Lens 2 F2: alpha{base_url=X, rate_max=1} + beta{base_url=X, no rate_max}. Addressing the
    SAME box via beta (which declares no cap of its own) still enforces alpha's tighter cap -> a
    caller cannot dodge a strict cap by picking a laxer/unnamed alias for the same physical box."""
    _wire_server(tmp_path, monkeypatch)
    _registry(monkeypatch, tmp_path, """
        [targets.alpha]
        kind = "pve"
        base_url = "https://198.51.100.10:8006/api2/json"
        node = "alpha"
        token_path = "/etc/proximo/alpha.token"
        rate_max = 1

        [targets.beta]
        kind = "pve"
        base_url = "https://198.51.100.10:8006/api2/json"
        node = "beta"
        token_path = "/etc/proximo/beta.token"
    """)

    token = targets._active_target.set("beta")
    try:
        envelope.begin_operation()
        server._audited("pve_guest_power", "lxc/100", lambda: None, mutation=True)

        envelope.begin_operation()
        with pytest.raises(ProximoError, match="rate"):
            server._audited("pve_guest_power", "lxc/100", lambda: None, mutation=True)
    finally:
        targets._active_target.reset(token)


def test_rate_concurrency_barrier(tmp_path, monkeypatch):
    """MAKE-OR-BREAK (lens 2 F3, design spec §11.E): rate_max=3; 20 threads block on a Barrier then
    simultaneously call enforce_envelope (via _audited) for the SAME box. EXACTLY 3 succeed, 17
    raise ProximoError. Threads don't inherit the parent's ContextVar context, so each thread's
    `_rate_reserved` starts fresh (False) — correctly modeling 20 independent concurrent attempts."""
    _wire_server(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_RATE_MAX", "3")

    n = 20
    barrier = threading.Barrier(n)
    results: list[str] = []
    results_lock = threading.Lock()

    def worker():
        barrier.wait()
        try:
            server._audited("pve_guest_power", "lxc/100", lambda: None, mutation=True)
            outcome = "ok"
        except ProximoError:
            outcome = "blocked"
        with results_lock:
            results.append(outcome)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == n  # every thread reported (no unexpected exception escaped)
    assert results.count("ok") == 3
    assert results.count("blocked") == 17


def test_ct_exec_single_reservation_across_seams(tmp_path, monkeypatch):
    """De-dup proof (multi-seam de-dup, design spec §11.C): with rate_max=1, ONE ct_exec(snapshot=
    True, confirm=True) call — which gates at its own body, `_auto_undo`'s snapshot, AND `_audited`
    (three enforce_envelope seams for one operation) — must consume exactly ONE reservation slot,
    not three. If de-dup were broken, the ct_exec call would itself exhaust budget=1 mid-flight (at
    its SECOND seam) and raise, rather than complete. A second, unrelated mutation afterward is
    then refused, proving the budget really was spent 1-not-3."""
    _cfg, api, exec_, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}),
    )
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")

    resp = server.ct_exec("105", ["echo", "hi"], snapshot=True, confirm=True)
    assert resp["status"] == "ok"
    assert exec_.ran  # the command actually ran -> the first call was NOT prematurely refused
    assert api.snapshot_creates  # the auto-undo snapshot ran too (the second of the 3 seams)

    blocked_before = [e for e in _entries(log) if e["outcome"] == "blocked:rate_budget"]
    assert blocked_before == []  # the ct_exec call itself never hit the exhausted-budget path

    # A second, unrelated mutation (its own fresh _plan()-driven operation) is refused: the sole
    # slot is already spent -> proves ct_exec consumed exactly 1, not 2 or 3.
    plan_build = lambda: Plan(  # noqa: E731
        action="pve_guest_power", target="lxc/100", change="power op", current={},
        blast_radius=[], risk=RISK_NONE, risk_reasons=[],
    )
    server._plan("pve_guest_power", "lxc/100", plan_build)  # resets _rate_reserved for this op
    with pytest.raises(ProximoError, match="rate"):
        server._audited("pve_guest_power", "lxc/100", lambda: None, mutation=True)


# === Hardening regressions (3-lens redteam, 7 findings closed) =================================


def test_rate_window_nonpositive_fails_closed(tmp_path, monkeypatch):
    """Fix 1 (HIGH): a rate_window that parses to <= 0 (env OR registry) must NOT fail open.
    cutoff = now - window >= now makes every slot read as already-expired, so the cap never
    engages — a non-positive window collapses that box to (0, default), fail-closed, exactly like
    a garbled rate_max."""
    _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")

    for window in ("0", "-50"):
        monkeypatch.setenv("PROXIMO_RATE_WINDOW", window)
        calls: list[int] = []
        for _ in range(15):
            envelope.begin_operation()
            with pytest.raises(ProximoError, match="rate"):
                server._audited("pve_guest_power", "lxc/100",
                                 lambda calls=calls: calls.append(1), mutation=True)
        assert calls == []

    monkeypatch.delenv("PROXIMO_RATE_MAX", raising=False)
    monkeypatch.delenv("PROXIMO_RATE_WINDOW", raising=False)
    monkeypatch.delenv("PROXIMO_API_BASE_URL", raising=False)

    # Same failure mode via a registry-declared rate_window, not just env.
    _registry(monkeypatch, tmp_path, """
        [targets.alpha]
        kind = "pve"
        base_url = "https://198.51.100.10:8006/api2/json"
        node = "alpha"
        token_path = "/etc/proximo/alpha.token"
        rate_max = 1
        rate_window = 0
    """)
    token = targets._active_target.set("alpha")
    try:
        calls2: list[int] = []
        for _ in range(15):
            envelope.begin_operation()
            with pytest.raises(ProximoError, match="rate"):
                server._audited("pve_guest_power", "lxc/100", lambda: calls2.append(1),
                                 mutation=True)
        assert calls2 == []
    finally:
        targets._active_target.reset(token)


def test_tie_break_prefers_tighter_window(tmp_path, monkeypatch):
    """Fix 2 (MED): on a rate_max TIE, the resolved window must be the LARGER/tighter one, not
    whichever candidate (env, always appended first) happens to win a stable-sort tie."""
    _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "5")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "1")
    _registry(monkeypatch, tmp_path, f"""
        [targets.alpha]
        kind = "pve"
        base_url = "{base_url}"
        node = "alpha"
        token_path = "/etc/proximo/alpha.token"
        rate_max = 5
        rate_window = 3600
    """)

    rate_max, rate_window = envelope._box_rate(base_url)
    assert rate_max == 5
    assert rate_window == 3600


def test_tightest_cap_compares_effective_rate_not_raw_count(tmp_path, monkeypatch):
    """The "tightest cap" selection must compare EFFECTIVE throughput (rate_max/window), not the
    raw rate_max count: a permissive env sanity ceiling (10/1s = 864,000/day) must NOT beat out a
    much stricter registry-declared per-box budget (500/86400s = 500/day) just because 10 < 500."""
    _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "10")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "1")
    _registry(monkeypatch, tmp_path, f"""
        [targets.prod]
        kind = "pve"
        base_url = "{base_url}"
        node = "prod"
        token_path = "/etc/proximo/prod.token"
        rate_max = 500
        rate_window = 86400
    """)

    rate_max, rate_window = envelope._box_rate(base_url)
    assert (rate_max, rate_window) == (500, 86400)


def test_base_url_whitespace_typo_still_caps(tmp_path, monkeypatch):
    """Fix 3 (MED): a leading/trailing-whitespace typo on the only cap-declaring alias must not
    make the cap invisible. `alpha` (the cap-declaring registry entry) has a trailing-space typo
    on its base_url; `beta` (the ACTIVE target) has the clean version of the same physical box.
    Built by string-concat, not typed into the TOML literally, so an editor/formatter can't
    silently eat the trailing space and turn this into a no-op test."""
    _wire_server(tmp_path, monkeypatch)
    clean = "https://198.51.100.10:8006/api2/json"
    typo = clean + " "
    _registry(monkeypatch, tmp_path, f"""
        [targets.alpha]
        kind = "pve"
        base_url = "{typo}"
        node = "alpha"
        token_path = "/etc/proximo/alpha.token"
        rate_max = 1

        [targets.beta]
        kind = "pve"
        base_url = "{clean}"
        node = "beta"
        token_path = "/etc/proximo/beta.token"
    """)
    # No env rate cap at all — alpha's registry entry is the ONLY cap source, so this genuinely
    # exercises the base_url-matching fix rather than an env-based candidate.

    token = targets._active_target.set("beta")
    try:
        envelope.begin_operation()
        server._audited("pve_guest_power", "lxc/100", lambda: None, mutation=True)  # 1st: ok

        envelope.begin_operation()
        with pytest.raises(ProximoError, match="rate"):
            server._audited("pve_guest_power", "lxc/100", lambda: None, mutation=True)  # 2nd: capped
    finally:
        targets._active_target.reset(token)


def test_nonfinite_reservation_line_fails_closed(tmp_path, monkeypatch):
    """Fix 4 (MED): nan/inf/-inf slots PARSE as floats (no ValueError), so they miss the
    corrupt-line fail-closed branch entirely; nan/-inf then read as < cutoff (silently dropped,
    under-count) and +inf as always >= cutoff (retained forever, self-DoS). Both must be treated
    exactly like an unparseable line: a USED slot."""
    _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")

    rate_path = _rate_path(tmp_path, base_url)
    rate_path.parent.mkdir(parents=True, exist_ok=True)
    rate_path.write_text("nan\n-inf\n")

    calls: list[int] = []
    envelope.begin_operation()
    with pytest.raises(ProximoError, match="rate"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []


def test_rate_file_capped_to_rate_max_slots(tmp_path, monkeypatch):
    """Fix 5 (LOW): corrupt/tampered lines becoming permanent `now` slots (or plain heavy usage)
    must not grow the reservation file without bound. After any rewrite, only the most-recent
    rate_max slots persist — fail-closed-safe, since keeping the newest frees budget no sooner
    than the true window would."""
    _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "3")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "3600")

    now = time.time()
    rate_path = _rate_path(tmp_path, base_url)
    rate_path.parent.mkdir(parents=True, exist_ok=True)
    rate_path.write_text("".join(f"{now - i}\n" for i in range(1000)))

    envelope.begin_operation()
    with pytest.raises(ProximoError, match="rate"):
        server._audited("pve_guest_power", "lxc/100", lambda: None, mutation=True)

    lines = [ln for ln in rate_path.read_text().splitlines() if ln.strip()]
    assert len(lines) <= 3


def test_symlinked_lock_refused_not_followed(tmp_path, monkeypatch):
    """Fix 6 (MED): the `.rate.lock` sidecar open must reject a symlinked lock path (O_NOFOLLOW)
    instead of silently following it — a co-located agent could otherwise redirect the flock (and,
    via O_CREAT, the file it creates) onto an arbitrary target path, a containment escape. This is
    genuinely coupled to Fix 7: without O_NOFOLLOW no OSError ever fires here at all."""
    _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "5")

    rate_dir = tmp_path / ".proximo-rate"
    rate_dir.mkdir(parents=True, exist_ok=True)
    lock_path = rate_dir / f"{_rate_key(base_url)}.rate.lock"
    evil_target = tmp_path / "evil-target"
    lock_path.symlink_to(evil_target)

    calls: list[int] = []
    envelope.begin_operation()
    with pytest.raises(ProximoError, match="rate"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []
    assert not evil_target.exists()  # never followed/created through the symlink


def test_symlinked_reservation_dir_refused_not_followed(tmp_path, monkeypatch):
    """Twin of the symlinked-LOCK refusal, for the reservation DIRECTORY itself (.proximo-rate). A
    planted symlink there could redirect every box's reservation writes onto an arbitrary path, so
    _rate_reserve refuses it (OSError) and enforce_envelope_rate turns that into a fail-closed
    blocked:rate_error — the real mutation never fires and the link is never followed/created."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "5")

    evil_target = tmp_path / "evil-rate-dir"  # deliberately NOT created
    (tmp_path / ".proximo-rate").symlink_to(evil_target, target_is_directory=True)

    calls: list[int] = []
    envelope.begin_operation()
    with pytest.raises(ProximoError, match="rate"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []
    assert not evil_target.exists()  # never created through the symlink
    assert any(e["outcome"] == "blocked:rate_error" for e in _entries(log))


def test_rate_reserve_error_audited_as_rate_error(tmp_path, monkeypatch):
    """Fix 7 (MED, the PROVE gap): ANY exception out of _rate_reserve — not just an over-budget
    refusal — must be caught, recorded to the PROVE ledger BEFORE raising (a DISTINCT outcome,
    blocked:rate_error, never confused with blocked:rate_budget), then turned into a fail-closed
    ProximoError. A directory sitting where the reservation FILE is expected forces IsADirectoryError
    regardless of uid (chmod-based permission errors are a no-op under root, which this suite runs
    as)."""
    _led, log = _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "5")

    rate_path = _rate_path(tmp_path, base_url)
    rate_path.parent.mkdir(parents=True, exist_ok=True)
    rate_path.mkdir()  # a directory, not a file -> IsADirectoryError on open(), not FileNotFoundError

    calls: list[int] = []
    envelope.begin_operation()
    with pytest.raises(ProximoError, match="rate"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []

    entries = _entries(log)
    rate_error = [e for e in entries if e["outcome"] == "blocked:rate_error"]
    budget = [e for e in entries if e["outcome"] == "blocked:rate_budget"]
    assert len(rate_error) == 1
    assert budget == []


def test_nonutf8_reservation_byte_self_heals(tmp_path, monkeypatch):
    """Fix 7a: a non-UTF8 byte in the reservation file must degrade to a replacement char (self-
    heal as a corrupt/used slot) rather than crash _rate_reserve with UnicodeDecodeError. Distinct
    from the Fix 7b test above: this exercises the tolerant READ, not the exception-wrapping seam.
    One non-UTF8 line counts as exactly ONE used slot (not a crash) — with rate_max=2 the call
    still has budget left and proceeds cleanly."""
    _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "2")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "3600")

    rate_path = _rate_path(tmp_path, base_url)
    rate_path.parent.mkdir(parents=True, exist_ok=True)
    rate_path.write_bytes(b"\xff\xfe not utf8 at all\n")

    envelope.begin_operation()
    server._audited("pve_guest_power", "lxc/100", lambda: None, mutation=True)  # doesn't raise


# === Seam order: RATE reservation moves to AFTER consent =========================================
# Origin: an agent that repeatedly plans+confirms actions CONSENT refuses would burn the box's
# entire rate budget on doomed attempts if rate were reserved BEFORE consent is checked -- turning
# the velocity wall built to bound a hijacked agent into a lever against the operator it defends.
# The fix: FORBID (cheap, no budget spent) stays an early hard wall before consent; the RATE
# reservation moves to AFTER consent passes, so a consent-refused attempt spends nothing.


def _consent_dir(tmp_path, monkeypatch):
    cdir = tmp_path / "consent"
    cdir.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(cdir))
    return cdir


def test_consent_refused_does_not_consume_rate_budget(tmp_path, monkeypatch):
    """HEADLINE (the fix): with rate_max=1, an attempt CONSENT refuses (no grant present) must
    spend ZERO rate budget -- a SUBSEQUENT, properly-consented attempt against the same box must
    still succeed. Under the OLD order (rate reserved before consent), the first attempt would have
    silently spent the sole slot and the second, legitimate attempt would be wrongly refused."""
    _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")
    _consent_dir(tmp_path, monkeypatch)

    # Attempt 1: no grant for this plan -> CONSENT refuses.
    consent.set_pending_consent("a" * 64)
    envelope.begin_operation()
    calls: list[int] = []
    with pytest.raises(ProximoError, match="(?i)consent"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []

    # Prove nothing was reserved: the rate file for this box doesn't even exist yet.
    assert not _rate_path(tmp_path, base_url).exists()

    # Attempt 2: a FRESH operation, this time WITH a matching grant -> must succeed, proving the
    # rate_max=1 budget for this box is still fully available after the refused attempt above.
    grant_id = "b" * 64
    (tmp_path / "consent" / grant_id).write_text("")
    consent.set_pending_consent(grant_id)
    envelope.begin_operation()
    resp = server._audited("pve_guest_power", "lxc/100",
                           lambda: calls.append(1) or {"ok": True}, mutation=True)
    assert calls == [1]
    assert resp == {"status": "ok", "result": {"ok": True}}


def test_forbid_blocks_before_consent_and_rate(tmp_path, monkeypatch):
    """FORBID stays an EARLY hard wall: even with a VALID consent grant present and rate budget
    available, a forbidden action never reaches consent or the rate reservation -- ledger records
    blocked:forbidden, the grant is left UNCONSUMED (consent never ran), and no rate slot is
    spent (rate never ran either)."""
    _wire_server(tmp_path, monkeypatch)
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_FORBID", "pve_delete_guest")
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "5")
    cdir = _consent_dir(tmp_path, monkeypatch)
    grant_id = "c" * 64
    grant_path = cdir / grant_id
    grant_path.write_text("")
    consent.set_pending_consent(grant_id)

    envelope.begin_operation()
    calls: list[int] = []
    with pytest.raises(ProximoError, match="(?i)forbidden"):
        server._audited("pve_delete_guest", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []
    assert grant_path.exists()  # consent never ran -> grant left untouched
    assert not _rate_path(tmp_path, base_url).exists()  # rate never ran -> nothing reserved


def test_ct_exec_single_reservation_across_seams_with_consent_enabled(tmp_path, monkeypatch):
    """De-dup still holds with CONSENT wired in: with rate_max=1 AND a valid consent grant, ONE
    ct_exec(snapshot=True, confirm=True) call -- which gates at its own body, `_auto_undo`, AND
    `_audited` (three consent + three rate seams) -- consumes exactly ONE rate slot and consumes
    the grant exactly ONCE (not thrice), proving the new consent-then-rate order doesn't reopen
    either multi-seam de-dup."""
    _cfg, api, exec_, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}),
    )
    base_url = "https://x:8006/api2/json"
    monkeypatch.setenv("PROXIMO_API_BASE_URL", base_url)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")
    cdir = _consent_dir(tmp_path, monkeypatch)

    # Dry-run first (as a real caller would) to learn the EXACT consent_id ct_exec's own _plan()
    # will compute for this ctid/command -- plan_exec() is pure/deterministic (no live reads), so
    # the confirm-path rebuild below hashes identically. Reading the contextvar _plan() just set
    # avoids hand-rolling a second Plan that could drift from the real one and false-refuse.
    server.ct_exec("105", ["echo", "hi"], snapshot=True, confirm=False)
    grant_path = cdir / consent._pending_consent_id.get()
    grant_path.write_text("")

    resp = server.ct_exec("105", ["echo", "hi"], snapshot=True, confirm=True)
    assert resp["status"] == "ok"
    assert exec_.ran  # the command ran -> not prematurely refused by either gate
    assert api.snapshot_creates  # the auto-undo snapshot ran too (the 2nd of 3 seams)
    assert not grant_path.exists()  # consumed exactly once

    blocked = [e for e in _entries(log)
               if e["outcome"].startswith(("blocked:rate", "blocked:consent"))]
    assert blocked == []  # the ct_exec call itself never hit either exhausted gate

    # A second, unrelated mutation (fresh _plan-driven operation) is refused on rate: the sole
    # slot is already spent -> proves ct_exec's 3 seams consumed exactly 1, not 2 or 3.
    plan_build = lambda: Plan(  # noqa: E731
        action="pve_guest_power", target="lxc/100", change="power op", current={},
        blast_radius=[], risk=RISK_NONE, risk_reasons=[],
    )
    plan2 = server._plan("pve_guest_power", "lxc/100", plan_build)
    (cdir / consent.consent_id_for(plan2)).write_text("")  # consent granted, only rate should block
    with pytest.raises(ProximoError, match="(?i)rate"):
        server._audited("pve_guest_power", "lxc/100", lambda: None, mutation=True)


# === Envelope resolution errors (record-before-raise) ===========================================


def test_forbid_wall_audits_envelope_resolution_error_before_raising(tmp_path, monkeypatch):
    """An exception raised while RESOLVING the envelope (e.g. a transiently-malformed
    PROXIMO_TARGETS file mid-write) must not leak out of enforce_envelope_forbid uncaught: every
    other refusal path in this gate family records to the PROVE ledger BEFORE raising, and this
    one must too — a distinct outcome (blocked:envelope_error), never confused with an ordinary
    blocked:forbidden."""
    led, log = _wire_server(tmp_path, monkeypatch)
    bad = tmp_path / "targets.toml"
    bad.write_text("this is not [valid toml")
    monkeypatch.setenv("PROXIMO_TARGETS", str(bad))

    with pytest.raises(ProximoError, match="(?i)envelope"):
        envelope.enforce_envelope_forbid("pve_guest_power", "lxc/100", led)

    entries = _entries(log)
    errors = [e for e in entries if e["outcome"] == "blocked:envelope_error"]
    assert len(errors) == 1
    assert [e for e in entries if e["outcome"] == "blocked:forbidden"] == []


def test_rate_wall_audits_envelope_resolution_error_before_raising(tmp_path, monkeypatch):
    """Same contract as above, for enforce_envelope_rate's own resolve_envelope() call."""
    led, log = _wire_server(tmp_path, monkeypatch)
    bad = tmp_path / "targets.toml"
    bad.write_text("this is not [valid toml")
    monkeypatch.setenv("PROXIMO_TARGETS", str(bad))

    with pytest.raises(ProximoError, match="(?i)envelope"):
        envelope.enforce_envelope_rate("pve_guest_power", "lxc/100", led)

    entries = _entries(log)
    errors = [e for e in entries if e["outcome"] == "blocked:envelope_error"]
    assert len(errors) == 1
    assert [e for e in entries if e["outcome"].startswith("blocked:rate")] == []


# === Structural guard ============================================================================


async def test_no_tool_accepts_a_forbid_or_rate_kwarg():
    """Structural invariant: no @tool()-decorated function may accept a forbid/rate_max/rate_window
    parameter — the envelope is out-of-band (env/registry) ONLY. Mirrors test_lease.py's
    test_no_tool_accepts_a_ttl_kwarg."""
    import inspect

    tools = await server.mcp.list_tools()
    offenders = []
    for t in tools:
        fn = getattr(server, t.name, None)
        if fn is None or not callable(fn):
            continue
        sig = inspect.signature(fn)
        for pname in sig.parameters:
            if pname.lower() in ("forbid", "rate_max", "rate_window"):
                offenders.append(f"{t.name}({pname})")
    assert not offenders, f"tool(s) accept a caller-supplied forbid/rate param: {offenders}"
