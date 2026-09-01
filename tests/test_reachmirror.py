"""reachmirror — the mirror's enforcement verdict (grant model, the junction closed).

Pins: (1) DORMANT without PROXIMO_REACH_PRIVILEGE — no API call is even made (the armgate
dormancy contract: unset means zero behavior change), (2) reach privilege present at the guest's path
=> allowed; absent => denied — asked of PVE PER PATH (the probe-proven primitive; the full map
cannot answer), (3) an API failure is UNAVAILABLE, never allowed (fail-closed: the checker must
not fail open into reach), (4) the ct_exec/ct_psql wiring refuses AFTER the allowlist and
BEFORE any plan/snapshot — the mirror INTERSECTS, it never widens — with ledger outcomes
blocked:mirror / blocked:mirror_unavailable, (5) setting/changing the reach privilege is a WITNESSED
reach-grant change (it joins the snapshot's env lane).
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import proximo.server as srv
from proximo import reachgrant, reachmirror
from proximo.audit import open_ledger


class _Api:
    def __init__(self, privs=None, raises=None):
        self.calls = []
        self._privs = privs or {}
        self._raises = raises

    def access_permissions(self, path=None):
        self.calls.append(path)
        if self._raises:
            raise self._raises
        return {path: self._privs} if self._privs else {}


def test_dormant_without_reach_privilege(monkeypatch):
    monkeypatch.delenv("PROXIMO_REACH_PRIVILEGE", raising=False)
    api = _Api(privs={"ProximoReach": 1})
    verdict, detail = reachmirror.mirror_verdict(api, "102")
    assert verdict == "off" and api.calls == []  # dormant = not even a query


def test_allowed_when_privilege_held_at_the_guest_path(monkeypatch):
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    api = _Api(privs={"ProximoReach": 1, "VM.Audit": 1})
    verdict, detail = reachmirror.mirror_verdict(api, "102")
    assert verdict == "allowed"
    assert api.calls == ["/vms/102"]  # per-path — never the full map
    assert detail["privilege"] == "ProximoReach"


def test_denied_when_privilege_absent(monkeypatch):
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    api = _Api(privs={"VM.Audit": 1})
    verdict, detail = reachmirror.mirror_verdict(api, "102")
    assert verdict == "denied" and detail["privilege"] == "ProximoReach"


def test_api_failure_is_unavailable_never_allowed(monkeypatch):
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    api = _Api(raises=ConnectionError("api down"))
    verdict, detail = reachmirror.mirror_verdict(api, "102")
    assert verdict == "unavailable"
    assert detail["error"] == "ConnectionError"


def _exec_svc(tmp_path, monkeypatch, api):
    cfg = SimpleNamespace(
        enable_exec=True, redact_ledger=False,
        ct_allowlist=frozenset({"102"}), agent_allowlist=frozenset(),
        ct_permitted=lambda ctid: str(ctid) == "102",
        audit_log_path=str(tmp_path / "audit.log"), audit_key_path=None, audit_keyed=True,
    )
    led = open_ledger(cfg)
    monkeypatch.setattr(srv, "_svc", lambda: (cfg, api, None, led))
    monkeypatch.setattr(srv, "_ledger", lambda: led)
    return led


def _grant_entries(tmp_path):
    with open(tmp_path / "audit.log", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_ct_exec_refuses_denied_after_allowlist_before_plan(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    api = _Api(privs={"VM.Audit": 1})  # reach privilege NOT held
    _exec_svc(tmp_path, monkeypatch, api)
    out = srv.ct_exec(ctid="102", command="id", confirm=False)
    assert out["status"] == "blocked:mirror"
    assert "ProximoReach" in out["message"]          # names the privilege it asked for
    ents = _grant_entries(tmp_path)
    assert ents and ents[-1]["outcome"] == "blocked:mirror"
    # intersection order: a CTID outside the allowlist refuses THERE, mirror never consulted
    api.calls.clear()
    out2 = srv.ct_exec(ctid="9999", command="id", confirm=False)
    assert out2["status"] == "blocked:allowlist" and api.calls == []


def test_ct_exec_unavailable_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    api = _Api(raises=TimeoutError("api down"))
    _exec_svc(tmp_path, monkeypatch, api)
    out = srv.ct_exec(ctid="102", command="id", confirm=False)
    assert out["status"] == "blocked:mirror_unavailable"
    assert "fail-closed" in out["message"].lower()


def test_ct_exec_allowed_proceeds_to_plan(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    api = _Api(privs={"ProximoReach": 1})
    _exec_svc(tmp_path, monkeypatch, api)
    out = srv.ct_exec(ctid="102", command="id", confirm=False)
    assert out["status"] == "plan"                    # mirror passed, plan returned


def test_privilege_change_is_a_witnessed_grant_change(monkeypatch, tmp_path):
    # The mirror's own switch is reach config — flipping it must move the snapshot digest.
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/run/x")
    monkeypatch.delenv("PROXIMO_TARGETS", raising=False)
    monkeypatch.delenv("PROXIMO_REACH_PRIVILEGE", raising=False)
    s1 = reachgrant.grant_snapshot()
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    s2 = reachgrant.grant_snapshot()
    assert reachgrant.grant_digest(s1) != reachgrant.grant_digest(s2)
    assert s2["mirror"] == {"privilege": "ProximoReach"}
    assert "mirror" not in s1                          # unset adds no key (no state churn)


def test_privilege_witnessed_even_on_pure_targets(monkeypatch):
    # Lens finding: enforcement reads the process env, so a pure-targets box (env lane
    # ABSENT) still mirrors — its flips must still move the digest AND show in the delta.
    for k in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH",
              "PROXIMO_TARGETS", "PROXIMO_REACH_PRIVILEGE"):
        monkeypatch.delenv(k, raising=False)
    s1 = reachgrant.grant_snapshot()
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    s2 = reachgrant.grant_snapshot()
    assert reachgrant.grant_digest(s1) != reachgrant.grant_digest(s2)
    delta = reachgrant._delta(s1, s2)
    assert delta["mirror"]["privilege"] == {"old": None, "new": "ProximoReach"}


def test_whitespace_privilege_is_refused_misconfiguration(monkeypatch):
    # Lens finding: '  ' silently read as dormant = fail-OPEN back to allowlist-only reach.
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "   ")
    api = _Api(privs={"ProximoReach": 1})
    verdict, detail = reachmirror.mirror_verdict(api, "102")
    assert verdict == "misconfigured" and api.calls == []
    _exec_svc_tmp = None  # (server-level check below)


def test_ct_exec_refuses_misconfigured_privilege(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", " ")
    api = _Api(privs={"ProximoReach": 1})
    _exec_svc(tmp_path, monkeypatch, api)
    out = srv.ct_exec(ctid="102", command="id", confirm=False)
    assert out["status"] == "blocked:mirror_misconfigured"


def test_keying_mismatch_fails_closed_never_open(monkeypatch):
    # The premise (PVE keys the answer under the queried path) was probed live 2026-08-26;
    # if PVE ever keyed differently (parent path, trailing slash), the mirror must DENY —
    # the safe direction — never allow. Pin the direction.
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")

    class _ParentKeyed(_Api):
        def access_permissions(self, path=None):
            self.calls.append(path)
            return {"/vms": {"ProximoReach": 1}}   # right priv, wrong key
    verdict, _ = reachmirror.mirror_verdict(_ParentKeyed(), "102")
    assert verdict == "denied"


def test_ct_logs_and_ct_diagnose_are_mirror_gated(monkeypatch, tmp_path):
    # Lens finding: the read-only shell siblings pulled journald/diagnostics at allowlist
    # breadth with no reach privilege — reach is reach. They stay ARM-free (the 08-24 ruling covers
    # authority); they are no longer mirror-free.
    import proximo.tools.pve_guest as pg
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    api = _Api(privs={"VM.Audit": 1})  # reach privilege NOT held
    _exec_svc(tmp_path, monkeypatch, api)  # pg._proximo_server IS srv — one patch serves both
    out = pg.ct_logs(ctid="102", unit="nginx.service")
    assert out["status"] == "blocked:mirror"
    out2 = pg.ct_diagnose(ctid="102")
    assert out2["status"] == "blocked:mirror"


# --- The node mirror: the same question at /nodes/<name> (host-shell battery) ---

def test_node_verdict_dormant_allowed_denied_at_node_path(monkeypatch):
    monkeypatch.delenv("PROXIMO_REACH_PRIVILEGE", raising=False)
    api = _Api(privs={"ProximoReach": 1})
    assert reachmirror.node_verdict(api, "pve")[0] == "off"
    assert api.calls == []                                    # dormant = no query
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    held = _Api(privs={"ProximoReach": 1})
    v, d = reachmirror.node_verdict(held, "pve")
    assert v == "allowed" and d["privilege"] == "ProximoReach"
    assert held.calls == ["/nodes/pve"]                       # the NODE path, one altitude up
    unheld = _Api(privs={"VM.Audit": 1})
    assert reachmirror.node_verdict(unheld, "pve")[0] == "denied"


def test_node_verdict_api_failure_is_unavailable_never_open(monkeypatch):
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    api = _Api(raises=RuntimeError("pve down"))
    v, d = reachmirror.node_verdict(api, "pve")
    assert v == "unavailable" and d["error"] == "RuntimeError"   # fail-closed, the recovery case


def test_node_and_guest_mirror_share_one_privilege(monkeypatch):
    # One privilege governs the whole shell channel; WHERE it is granted (a guest path or the
    # node) is the reach. A token holding it at the node but not a guest reaches one, not both.
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    class _NodeOnly:
        def __init__(self): self.calls = []
        def access_permissions(self, path=None):
            self.calls.append(path)
            return {path: {"ProximoReach": 1}} if path == "/nodes/pve" else {}
    api = _NodeOnly()
    assert reachmirror.node_verdict(api, "pve")[0] == "allowed"
    assert reachmirror.mirror_verdict(api, "102")[0] == "denied"


def test_node_logs_gated_by_own_flag_then_mirror(monkeypatch, tmp_path):
    # node_logs is off without its OWN flag (not enable_exec), then mirror-gated when on.
    from proximo.tools import pve_guest
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    monkeypatch.delenv("PROXIMO_ENABLE_NODE_SHELL", raising=False)
    led = open_ledger(SimpleNamespace(audit_log_path=str(tmp_path / "a.log"),
                                      audit_key_path=None, audit_keyed=True))
    cfg = SimpleNamespace(node="pve", enable_node_shell=False)
    monkeypatch.setattr(pve_guest._proximo_server, "_svc",
                        lambda: (cfg, _Api(privs={"VM.Audit": 1}), None, led))
    monkeypatch.setattr(srv, "_ledger", lambda: led)
    out = pve_guest.pve_node_logs("pveproxy.service")
    assert out["status"] == "blocked:node_shell_disabled"       # own flag first
    cfg.enable_node_shell = True
    out = pve_guest.pve_node_logs("pveproxy.service")
    assert out["status"] == "blocked:mirror"                     # then the node mirror refuses


def test_node_tools_take_no_caller_node_gate_matches_target(monkeypatch, tmp_path):
    # Authorization-decoupling fix (found by both the fierce lens and the automated security
    # review): the shell can only reach ssh_target's box, so a caller-supplied node would let
    # the mirror gate on node X's ACL while the ssh runs on cfg.node. The tools take NO node
    # arg — the gate path and the run target are the same box by construction.
    import inspect

    from proximo.tools import pve_guest
    assert "node" not in inspect.signature(pve_guest.pve_node_logs).parameters
    assert "node" not in inspect.signature(pve_guest.pve_node_diagnose).parameters
    # And the mirror is consulted with cfg.node, the box the battery will ssh to.
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    led = open_ledger(SimpleNamespace(audit_log_path=str(tmp_path / "a.log"),
                                      audit_key_path=None, audit_keyed=True))
    api = _Api(privs={"VM.Audit": 1})           # privilege NOT held at the node
    cfg = SimpleNamespace(node="pve", enable_node_shell=True)
    monkeypatch.setattr(pve_guest._proximo_server, "_svc", lambda: (cfg, api, None, led))
    monkeypatch.setattr(srv, "_ledger", lambda: led)
    out = pve_guest.pve_node_logs("pveproxy.service")
    assert out["status"] == "blocked:mirror"
    assert api.calls == ["/nodes/pve"]          # gated on cfg.node's path, nothing else


def test_pve_node_diagnose_skip_shape_carries_verdict_class(monkeypatch, tmp_path):
    # Lens finding: the blocked-battery disclosure must carry the machine-readable verdict
    # class (status), not a None from a nonexistent "outcome" key. And the API-only report
    # must still come back when the shell battery is gated off.
    from proximo.tools import pve_guest
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    led = open_ledger(SimpleNamespace(audit_log_path=str(tmp_path / "a.log"),
                                      audit_key_path=None, audit_keyed=True))
    class _NodeApi(_Api):
        def node_status(self, node=None): return {"uptime": 1, "cpu": 0.1}
        def node_storage(self, node=None): return []
        def cluster_tasks(self, *a, **k): return []
    api = _NodeApi(privs={"VM.Audit": 1})               # reach NOT held at the node
    cfg = SimpleNamespace(node="pve", enable_node_shell=True)
    monkeypatch.setattr(pve_guest._proximo_server, "_svc", lambda: (cfg, api, None, led))
    monkeypatch.setattr(srv, "_ledger", lambda: led)
    out = pve_guest.pve_node_diagnose()
    assert out["shell_battery"]["skipped"] == "blocked:mirror"   # the CLASS, not None
    assert "status" in out                                        # API-only half survived
    # disabled path discloses too
    cfg.enable_node_shell = False
    out2 = pve_guest.pve_node_diagnose()
    assert "PROXIMO_ENABLE_NODE_SHELL" in out2["shell_battery"]["skipped"]


def test_node_battery_probe_failure_is_contained_not_fatal(monkeypatch, tmp_path):
    # A hung/failing probe must not abort the whole battery and discard the API report — the
    # degraded-host case is exactly when this tool runs (lens finding).
    from proximo.tools import pve_guest
    monkeypatch.delenv("PROXIMO_REACH_PRIVILEGE", raising=False)   # mirror dormant, battery runs
    led = open_ledger(SimpleNamespace(audit_log_path=str(tmp_path / "a.log"),
                                      audit_key_path=None, audit_keyed=True))
    class _NodeApi(_Api):
        def node_status(self, node=None): return {"uptime": 1}
        def node_storage(self, node=None): return []
        def cluster_tasks(self, *a, **k): return []
    class _Exec:
        def node_probe(self, key):
            if key == "cluster":
                raise TimeoutError("ssh hung")     # the fatal case
            return SimpleNamespace(returncode=0, stdout=f"{key}-ok", stderr="")
    cfg = SimpleNamespace(node="pve", enable_node_shell=True)
    monkeypatch.setattr(pve_guest._proximo_server, "_svc",
                        lambda: (cfg, _NodeApi(), _Exec(), led))
    monkeypatch.setattr(srv, "_ledger", lambda: led)
    out = pve_guest.pve_node_diagnose()
    b = out["shell_battery"]
    assert b["cluster"] == {"error": "TimeoutError"}    # contained
    assert b["disk"]["stdout"] == "disk-ok"             # the rest still gathered
    assert "status" in out                              # API report survived the hang


def test_backend_node_probe_refuses_when_disabled():
    # Defense-in-depth: the backend re-checks enable_node_shell, so a future direct caller
    # cannot ride past the tool-seam gate.
    from proximo.backends import ExecBackend, ProximoError
    cfg = SimpleNamespace(enable_node_shell=False, is_local=True, ssh_target="pve")
    import pytest as _pytest
    with _pytest.raises(ProximoError):
        ExecBackend(cfg).node_probe("disk")
