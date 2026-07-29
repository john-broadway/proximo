"""PRUNE leg (least-privilege ACL pruning) — unit tests for pve_acl_prune and its plan/executor.

Covers:
  - proximo.access.plan_prune_grant  (pure plan: revoke leg + optional re-grant leg, merged)
  - proximo.access.acl_prune         (executor: revoke PUT, then optional re-grant PUT)
  - proximo.server.pve_acl_prune     (MCP tool: dry-run plan / confirm=True audited execute)
  - proximo.access.acl_modify + proximo.access.plan_acl_modify extended for kind="group"

Style mirrors test_access.py (fake api records _get/_put) and test_blast_seam.py (server-seam
tool tests: monkeypatch server._svc, real AuditLedger in tmp_path, inspect the JSONL entries).
Every assertion targets a SPECIFIC value (exact role/path/severity/target string) — never a bare
"non-empty" check — so a plausible-but-wrong implementation fails, not just an empty stub.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import proximo.server as server
from proximo.access import (
    access_overbroad_grants,
    acl_modify,
    acl_prune,
    plan_prune_grant,
)
from proximo.audit import AuditLedger
from proximo.backends import ProximoError
from proximo.config import ProximoConfig

# ---------------------------------------------------------------------------
# Test fakes
# ---------------------------------------------------------------------------


def _prune_api(acl_entries, *, groups=None, members=None, tokens=None,
               raise_on_acl_get=False, raise_on_group_get=()):
    """Path-aware fake api for plan_prune_grant / acl_prune / acl_modify.

    Records every _get/_put call in .state so validator tests can assert fail-before-API
    (nothing issued to the wire) and executor tests can assert exact PUT bodies + call order.
    """
    state: dict = {"gets": [], "puts": []}

    def fake_get(path):
        state["gets"].append(path)
        if path == "/access/acl":
            if raise_on_acl_get:
                raise RuntimeError("acl read failed")
            return list(acl_entries)
        if path.startswith("/access/users/") and path.endswith("/token"):
            return list(tokens or [])
        if path.startswith("/access/groups/"):
            grp = path.rsplit("/", 1)[1]
            if grp in raise_on_group_get:
                raise RuntimeError("group read failed")
            return {"members": list((members or {}).get(grp, []))}
        if path.startswith("/access/users/"):
            return {"groups": list(groups or [])}
        return []

    def fake_put(path, data=None):
        state["puts"].append({"path": path, "data": dict(data or {})})
        return None

    return SimpleNamespace(config=SimpleNamespace(node="pve"), _get=fake_get, _put=fake_put, state=state)


def _wire_prune(tmp_path, monkeypatch, api):
    """Wire proximo.server._svc to the fake api + a real (unkeyed) ledger in tmp_path."""
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve1",
                        token_path="/run/x", audit_log_path=log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, SimpleNamespace(), AuditLedger(log)))
    return log


def _entries(log: str) -> list[dict]:
    with open(log, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ---------------------------------------------------------------------------
# Core invariants (contract §5)
# ---------------------------------------------------------------------------


def test_prune_pure_revoke_shows_losses():
    """narrow_role=None, narrow_path=None => pure revoke: affected shows the target LOSES
    roleid at path (an explicit loss entry, not merely a summary line) and no 'gains' entry."""
    acl = [{"path": "/vms", "ugid": "bob@pam", "roleid": "PVEVMAdmin", "type": "user", "propagate": True}]
    api = _prune_api(acl)
    plan = plan_prune_grant(api, "/vms", "bob@pam", "user", "PVEVMAdmin")
    losses = [a for a in plan.affected if a["change"] == "loses"]
    assert losses, "pure revoke must surface an explicit loss entry for the revoked grant"
    assert any(
        a["roles"] == ["PVEVMAdmin"] and a["at"] == "/vms" and a["principal"] == "bob@pam"
        for a in losses
    )
    assert not any(a["change"] == "gains" for a in plan.affected)


def test_prune_regrant_names_gains():
    """A re-grant leg must name an explicit GAIN of narrow_role at narrow_path."""
    api = _prune_api([])
    plan = plan_prune_grant(api, "/vms/100", "bob@pam", "user", "PVEVMUser",
                            narrow_role="PVEVMAdmin", narrow_path="/vms/100/disk0")
    gains = [a for a in plan.affected if a["change"] == "gains"]
    assert gains, "expected a gains entry for the narrower re-grant"
    assert any(
        a["roles"] == ["PVEVMAdmin"] and a["at"] == "/vms/100/disk0" and a["principal"] == "bob@pam"
        for a in gains
    )


def test_prune_acl_read_failure_forces_high():
    api = _prune_api([], raise_on_acl_get=True)
    plan = plan_prune_grant(api, "/vms/100", "bob@pam", "user", "PVEVMUser")
    assert plan.risk == "high"
    assert plan.complete is False


def test_prune_revoke_widen_flagged():
    """Revoking the specific entry restores a broader inherited grant — WIDEN WARNING naming it."""
    acl = [
        {"path": "/", "ugid": "bob@pam", "roleid": "Administrator", "type": "user", "propagate": True},
        {"path": "/vms/100", "ugid": "bob@pam", "roleid": "PVEVMUser", "type": "user", "propagate": True},
    ]
    api = _prune_api(acl)
    plan = plan_prune_grant(api, "/vms/100", "bob@pam", "user", "PVEVMUser")
    assert any("WIDEN WARNING" in line and "Administrator" in line for line in plan.blast_radius)
    assert plan.risk == "high"


def test_prune_root_path_always_high():
    acl = [{"path": "/", "ugid": "bob@pam", "roleid": "PVEVMUser", "type": "user", "propagate": True}]
    api = _prune_api(acl)
    plan = plan_prune_grant(api, "/", "bob@pam", "user", "PVEVMUser")
    assert plan.risk == "high"


def test_prune_administrator_revoke_high():
    acl = [{"path": "/vms", "ugid": "bob@pam", "roleid": "Administrator", "type": "user", "propagate": True}]
    api = _prune_api(acl)
    plan = plan_prune_grant(api, "/vms", "bob@pam", "user", "Administrator")
    assert plan.risk == "high"


def test_prune_regrant_administrator_high_with_disclosure():
    """Re-granting Administrator is HIGH + disclosed, NOT a hard refusal (no exception)."""
    api = _prune_api([])
    plan = plan_prune_grant(api, "/vms/100", "bob@pam", "user", "PVEVMUser",
                            narrow_role="Administrator")
    assert plan.risk == "high"
    combined = " ".join(plan.blast_radius + plan.risk_reasons)
    assert "Administrator" in combined


def test_prune_group_member_uncertainty_forces_high():
    """kind='group': the group's OWN member enumeration fails -> incomplete + HIGH, and the
    specific 'could not enumerate members' disclosure must actually be present (proves
    plan_prune_grant wired the group_members resolution for the group being pruned itself,
    not merely relying on an unrelated escalation elsewhere)."""
    acl = [{"path": "/vms", "ugid": "ops", "roleid": "PVEVMAdmin", "type": "group", "propagate": True}]
    api = _prune_api(acl, raise_on_group_get={"ops"})
    plan = plan_prune_grant(api, "/vms", "ops", "group", "PVEVMAdmin")
    assert plan.complete is False
    assert plan.risk == "high"
    assert any("could not enumerate members of group 'ops'" in line for line in plan.blast_radius)


def test_prune_blast_affected_has_severity():
    acl = [{"path": "/vms", "ugid": "bob@pam", "roleid": "PVEVMAdmin", "type": "user", "propagate": True}]
    api = _prune_api(acl)
    plan = plan_prune_grant(api, "/vms", "bob@pam", "user", "PVEVMAdmin", narrow_role="PVEVMUser")
    assert plan.affected, "expected at least one affected entry to check severity on"
    assert all(a["severity"] in ("high", "medium") for a in plan.affected)


def test_prune_invalid_path_rejected():
    api = _prune_api([])
    with pytest.raises(ProximoError):
        plan_prune_grant(api, "vms/100", "bob@pam", "user", "PVEVMUser")  # no leading slash
    assert api.state["gets"] == [] and api.state["puts"] == []


def test_prune_invalid_target_rejected():
    api = _prune_api([])
    with pytest.raises(ProximoError):
        plan_prune_grant(api, "/vms/100", "not-a-valid-target", "user", "PVEVMUser")  # no @realm
    assert api.state["gets"] == [] and api.state["puts"] == []


def test_prune_invalid_roleid_rejected():
    api = _prune_api([])
    with pytest.raises(ProximoError):
        plan_prune_grant(api, "/vms/100", "bob@pam", "user", "bad role!")
    assert api.state["gets"] == [] and api.state["puts"] == []


def test_prune_revoke_calls_acl_modify_delete():
    api = _prune_api([])
    acl_prune(api, "/vms/100", "bob@pam", "user", "PVEVMUser")
    assert api.state["puts"], "expected at least one PUT"
    first = api.state["puts"][0]
    assert first["path"] == "/access/acl"
    assert first["data"]["delete"] == 1
    assert first["data"]["roles"] == "PVEVMUser"
    assert first["data"]["path"] == "/vms/100"
    assert first["data"]["users"] == "bob@pam"


def test_prune_regrant_calls_acl_modify_grant():
    api = _prune_api([])
    acl_prune(api, "/vms/100", "bob@pam", "user", "PVEVMUser",
             narrow_role="PVEVMAdmin", narrow_path="/vms")
    assert len(api.state["puts"]) == 2
    second = api.state["puts"][1]
    assert second["data"]["delete"] == 0
    assert second["data"]["roles"] == "PVEVMAdmin"
    assert second["data"]["path"] == "/vms"
    assert second["data"]["users"] == "bob@pam"


def test_prune_pure_revoke_single_put():
    api = _prune_api([])
    acl_prune(api, "/vms/100", "bob@pam", "user", "PVEVMUser")
    assert len(api.state["puts"]) == 1


def test_prune_both_puts_on_regrant():
    api = _prune_api([])
    acl_prune(api, "/vms/100", "bob@pam", "user", "PVEVMUser", narrow_role="PVEVMAdmin")
    assert len(api.state["puts"]) == 2
    assert api.state["puts"][0]["data"]["delete"] == 1
    assert api.state["puts"][1]["data"]["delete"] == 0


def test_prune_synchronous_returns_none():
    api = _prune_api([])
    result = acl_prune(api, "/vms/100", "bob@pam", "user", "PVEVMUser")
    assert result is None


def test_prune_tool_dry_run_returns_plan(tmp_path, monkeypatch):
    acl = [{"path": "/", "ugid": "bob@pam", "roleid": "Administrator", "type": "user", "propagate": True}]
    api = _prune_api(acl)
    _wire_prune(tmp_path, monkeypatch, api)
    resp = server.pve_acl_prune("/", "bob@pam", kind="user", roleid="Administrator")  # confirm defaults False
    assert resp["status"] == "plan"
    assert resp["action"] == "pve_acl_prune"
    assert resp["risk"] == "high"
    assert api.state["puts"] == [], "dry-run must never issue a mutation"


def test_prune_tool_confirm_audited(tmp_path, monkeypatch):
    acl = [{"path": "/vms", "ugid": "bob@pam", "roleid": "PVEVMAdmin", "type": "user", "propagate": True}]
    api = _prune_api(acl)
    log = _wire_prune(tmp_path, monkeypatch, api)
    resp = server.pve_acl_prune("/vms", "bob@pam", kind="user", roleid="PVEVMAdmin", confirm=True)
    assert resp["status"] == "ok"
    ok_entries = [e for e in _entries(log) if e.get("action") == "pve_acl_prune" and e.get("outcome") == "ok"]
    assert ok_entries, "expected an 'ok'-outcome ledger entry for action=pve_acl_prune"
    assert ok_entries[-1]["target"] == "acl:prune:/vms:bob@pam"


def test_prune_audit_detail_no_secret(tmp_path, monkeypatch):
    acl = [{"path": "/vms", "ugid": "svc@pam!citoken", "roleid": "PVEVMAdmin", "type": "token", "propagate": True}]
    api = _prune_api(acl)
    log = _wire_prune(tmp_path, monkeypatch, api)
    server.pve_acl_prune("/vms", "svc@pam!citoken", kind="token", roleid="PVEVMAdmin", confirm=True)
    ok_entry = next(e for e in _entries(log) if e.get("action") == "pve_acl_prune" and e.get("outcome") == "ok")
    detail = ok_entry["detail"]
    # `intent` is the derived (action, target) grouping id — a truncated sha256 of two values the
    # entry already states in clear. It carries no secret, which is what this test guards.
    assert set(detail.keys()) == {"confirmed", "roleid", "narrow_role", "narrow_path", "intent"}
    assert detail["roleid"] == "PVEVMAdmin"
    assert detail["confirmed"] is True
    assert detail["narrow_role"] is None
    assert detail["narrow_path"] is None
    assert "citoken" not in json.dumps(detail)  # no secret/target-identifying value leaks into detail


def test_prune_consumes_detection_shape(tmp_path, monkeypatch):
    """Feed a finding straight from access_overbroad_grants() into pve_acl_prune — the shapes
    must interoperate (path/ugid/roleid/type)."""
    acl = [{"path": "/", "ugid": "bob@pam", "roleid": "Administrator", "type": "user", "propagate": True}]
    api = _prune_api(acl)
    _wire_prune(tmp_path, monkeypatch, api)
    detected = access_overbroad_grants(api)
    assert detected, "fixture must produce at least one over-broad grant to feed the tool"
    finding = detected[0]
    resp = server.pve_acl_prune(finding["path"], finding["ugid"], kind=finding["type"], roleid=finding["roleid"])
    assert resp["status"] == "plan"
    assert resp["risk"] == "high"


# ---------------------------------------------------------------------------
# Merge tests (advisor-added, REQUIRED — contract §5)
# ---------------------------------------------------------------------------


def test_prune_regrant_under_revoked_path_no_spurious_shadow():
    """Revoke Administrator at '/', re-grant PVEVMAdmin at the child path '/vms'. The re-grant
    leg's blast must be computed against a POST-revoke ACL view — it must NOT claim '/vms'
    shadows the role we are in the same operation deleting (the ordering-fix bug)."""
    acl = [{"path": "/", "ugid": "bob@pam", "roleid": "Administrator", "type": "user", "propagate": True}]
    api = _prune_api(acl)
    plan = plan_prune_grant(api, "/", "bob@pam", "user", "Administrator",
                            narrow_role="PVEVMAdmin", narrow_path="/vms")
    for line in plan.blast_radius:
        if "SHADOW WARNING" in line:
            assert "Administrator" not in line, (
                f"spurious shadow warning for the just-revoked role: {line!r}"
            )


def test_prune_merge_takes_max_risk():
    """revoke leg (PVEVMUser at a non-root path, no inherited grants) is MEDIUM; re-grant leg
    (narrow_role=Administrator at the same non-root path) is HIGH. Merged risk must be HIGH,
    and BOTH the revoke-leg loss entry and the re-grant-leg gain entry must survive the merge."""
    api = _prune_api([])
    plan = plan_prune_grant(api, "/vms/100", "bob@pam", "user", "PVEVMUser",
                            narrow_role="Administrator")
    assert plan.risk == "high"
    losses = [a for a in plan.affected if a["change"] == "loses" and a.get("roles") == ["PVEVMUser"]]
    assert losses, "revoke-leg loss entry (PVEVMUser) must survive the merge"
    assert losses[0]["at"] == "/vms/100"
    gains = [a for a in plan.affected if a["change"] == "gains" and a.get("roles") == ["Administrator"]]
    assert gains, "re-grant-leg gain entry (Administrator) must survive the merge"
    assert gains[0]["at"] == "/vms/100"


# ---------------------------------------------------------------------------
# FINDING 1 (HIGH, security review): the re-grant leg must re-resolve its path-dependent
# context (extra_inherited, group_members) AT effective_path — reusing the revoke leg's stale,
# path-scoped values silently under-reports shadow/context at a re-grant path that differs
# from the revoke path (risk under-classified, complete falsely True).
# ---------------------------------------------------------------------------


def test_prune_regrant_leg_uses_fresh_path_context_for_privsep0_token_shadow():
    """A privsep=0 token's owner has a DIRECT propagated grant (PVEAuditor) at /storage — an
    ancestor of the RE-GRANT path (/storage/mydisk) but NOT of the REVOKE path (/vms/100). The
    stale-reuse bug computes extra_inherited once at /vms/100 (where /storage is not an
    ancestor => empty) and reuses it unchanged for the re-grant leg at /storage/mydisk, so the
    genuine shadow of PVEAuditor there goes undetected: risk stays non-high and no loss is
    reported. Recomputed per-leg, the re-grant leg must catch it."""
    acl = [
        {"path": "/vms/100", "ugid": "svc@pam!tok1", "roleid": "PVEVMAdmin",
         "type": "token", "propagate": True},
        {"path": "/storage", "ugid": "svc@pam", "roleid": "PVEAuditor",
         "type": "user", "propagate": True},
    ]
    api = _prune_api(acl, tokens=[{"tokenid": "tok1", "privsep": 0}])
    plan = plan_prune_grant(api, "/vms/100", "svc@pam!tok1", "token", "PVEVMAdmin",
                            narrow_role="PVEVMUser", narrow_path="/storage/mydisk")
    assert plan.risk == "high"
    assert any("SHADOW WARNING" in line and "PVEAuditor" in line for line in plan.blast_radius)
    assert any(
        a["change"] == "loses" and a["roles"] == ["PVEAuditor"] and a["at"] == "/storage/mydisk"
        for a in plan.affected
    )


def test_prune_regrant_leg_uses_fresh_path_context_for_group_members():
    """Same root cause, lower severity. Revoke Administrator@/, re-grant PVEVMUser at the
    descendant path /vms/100/disk0. A group grant (PVEAuditor for group 'ops') sits at /vms —
    an ancestor of the RE-GRANT path but NOT of '/' (the revoke path), so the revoke leg
    correctly carries no context for it. The stale-reuse bug drops the who-else-reaches context
    at the re-grant path entirely; recomputed per-leg, it must appear there."""
    acl = [
        {"path": "/", "ugid": "bob@pam", "roleid": "Administrator", "type": "user", "propagate": True},
        {"path": "/vms", "ugid": "ops", "roleid": "PVEAuditor", "type": "group", "propagate": True},
    ]
    api = _prune_api(acl, members={"ops": ["bob@pam", "dave@pam"]})
    plan = plan_prune_grant(api, "/", "bob@pam", "user", "Administrator",
                            narrow_role="PVEVMUser", narrow_path="/vms/100/disk0")
    assert any(
        "also has access at this path — UNCHANGED" in line
        and "bob@pam" in line and "dave@pam" in line
        for line in plan.blast_radius
    )
    unchanged = [
        a for a in plan.affected
        if a["kind"] == "group-member" and a["change"] == "unchanged" and a["at"] == "/vms/100/disk0"
    ]
    assert {a["principal"] for a in unchanged} == {"bob@pam", "dave@pam"}
    assert all(a["via"] == "group ops" for a in unchanged)


# ---------------------------------------------------------------------------
# FINDING 2 (low/med, security review): the token branch validates user_part/token_part but
# must REASSIGN `target` to the validated (stripped) form before it reaches the wire / ledger —
# a whitespace/CRLF-padded token target must not leak the raw original.
# ---------------------------------------------------------------------------


def test_acl_modify_token_target_stripped_before_wire():
    api = _prune_api([])
    acl_modify(api, "/vms", "PVEVMAdmin", "\nsvc@pam!citoken\r\n", kind="token", delete=False)
    assert api.state["puts"][0]["data"]["tokens"] == "svc@pam!citoken"


def test_prune_plan_target_field_stripped_for_token():
    """plan_prune_grant's token branch must also reassign `target` — Plan.target (which flows
    into the audit ledger) must not carry a raw whitespace-padded token identifier."""
    api = _prune_api([])
    plan = plan_prune_grant(api, "/vms", "\nsvc@pam!citoken\r\n", "token", "PVEVMAdmin")
    assert plan.target == "acl:prune:/vms:svc@pam!citoken"


# ---------------------------------------------------------------------------
# Group support tests (acl_modify extended for kind="group" — contract §1)
# ---------------------------------------------------------------------------


def test_acl_modify_group_grant_builds_groups_body():
    api = _prune_api([])
    acl_modify(api, "/vms/100", "PVEVMUser", "ops", kind="group", delete=False)
    assert len(api.state["puts"]) == 1
    data = api.state["puts"][0]["data"]
    assert data["groups"] == "ops"
    assert data["delete"] == 0
    assert "users" not in data and "tokens" not in data


def test_acl_modify_group_revoke_builds_groups_body():
    api = _prune_api([])
    acl_modify(api, "/vms/100", "PVEVMUser", "ops", kind="group", delete=True)
    assert len(api.state["puts"]) == 1
    data = api.state["puts"][0]["data"]
    assert data["groups"] == "ops"
    assert data["delete"] == 1


def test_acl_modify_bad_group_name_rejected():
    api = _prune_api([])
    for bad in ("bad/name", ""):
        with pytest.raises(ProximoError):
            acl_modify(api, "/vms/100", "PVEVMUser", bad, kind="group")
    assert api.state["puts"] == []
