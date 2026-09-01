"""reachgrant — the reach grant made observable (brick 1 of the grant model).

Pins: (1) resolved-lane canonicalization matches config's own allowlist parsing (parity, so the
two can never drift) and carries the behavior switches (exec/agent enable, ssh_target), (2) the
digest is stable and order-independent, (3) check_and_record PROVEs `initial` and `changed` —
records BEFORE the sidecar moves (crash-ordering pinned by an induced record failure) — and
deliberately NOT on an unchanged restart (no-spam, mutation-proofed by entry count), (4) a
corrupt sidecar is LOUD (`state_unreadable`) and a MISSING one with chain history is LOUD
(`state_missing`) — deletion is the cheaper clobber and neither may masquerade as first-run,
(5) a state-write failure is a SECOND entry, never a relabel of the delta entry, (6) a missing
env triple reports ABSENT while any other env failure reports an error (different facts), and a
registry target named "env" cannot shadow the env lane (namespaced flat), (7) every serve door
runs the check — pinned on the CALL, not the def line.
"""
from __future__ import annotations

import json
import os
import re
from types import SimpleNamespace

import pytest

from proximo import reachgrant
from proximo.audit import open_ledger
from proximo.config import ProximoConfig


def _svc_cfg(tmp_path, **kw):
    base = dict(audit_log_path=str(tmp_path / "audit.log"), audit_key_path=None, audit_keyed=True)
    base.update(kw)
    return SimpleNamespace(**base)


def _base_env(monkeypatch, **extra):
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/run/x")
    monkeypatch.delenv("PROXIMO_TARGETS", raising=False)
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def _entries(tmp_path):
    # Raw chain rows (read_entries is a summarizing reader — it deliberately drops `detail`,
    # and the delta payload is exactly what these tests must pin).
    with open(tmp_path / "audit.log", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _grant_entries(tmp_path):
    return [e for e in _entries(tmp_path) if e.get("action") == "reach_grant"]


# --- resolved lanes: parity with config's own parsing ---------------------------------------------

def test_resolved_lanes_parity_with_config_parsing():
    # The SAME raw string through ProximoConfig and through resolved_lanes must agree — the lanes
    # are read off the built config, so sloppy whitespace/dupes must land identically.
    cfg = ProximoConfig._build(
        api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
        ssh_target="pve", arm_source=None, readonly_source=None,
        ct_allow_raw=" 102, 101,,102 ,103", agent_allow_raw="",
        vtls_raw="true", ca_bundle=None, fingerprint=None,
        enable_exec=True, enable_agent=False,
        audit_key_path=None, audit_keyed_raw="true", redact_ledger=True,
        expected_head_raw="", audit_log_path="unused-audit.log",
        anchor_sink_raw="none", anchor_file_path=None, anchor_url=None,
        anchor_token_path=None, anchor_ca_bundle=None,
        anchor_syslog_address=None, anchor_journal_socket=None,
    )
    lanes = reachgrant.resolved_lanes(cfg)
    assert lanes["ct"] == ["101", "102", "103"]  # numeric sort, dupes collapsed
    assert lanes["agent"] == []                     # empty = deny-all, honestly empty
    assert set(lanes["ct"]) == set(cfg.ct_allowlist)
    # The switches ride along — enable flips and ssh re-points are behavior (lens F4).
    assert lanes["exec_enabled"] is True and lanes["agent_enabled"] is False
    assert lanes["ssh_target"] == "pve"


def test_resolved_lanes_star_canonicalizes():
    # "*, 101" and "*" are behaviorally identical grants (ct_permitted short-circuits on '*'),
    # so they must canonicalize to the same resolved lane — a snapshot records behavior.
    a = reachgrant.resolved_lanes(SimpleNamespace(ct_allowlist=frozenset({"*", "101"}),
                                                  agent_allowlist=frozenset()))
    b = reachgrant.resolved_lanes(SimpleNamespace(ct_allowlist=frozenset({"*"}),
                                                  agent_allowlist=frozenset()))
    assert a["ct"] == ["*"] and a == b


def test_enable_flip_changes_the_snapshot():
    # Same ids, exec flipped on: deny-all -> live is a behavior change and MUST move the digest.
    off = reachgrant.resolved_lanes(SimpleNamespace(ct_allowlist=frozenset({"102"}),
                                                    agent_allowlist=frozenset(),
                                                    enable_exec=False))
    on = reachgrant.resolved_lanes(SimpleNamespace(ct_allowlist=frozenset({"102"}),
                                                   agent_allowlist=frozenset(),
                                                   enable_exec=True))
    assert reachgrant.grant_digest(off) != reachgrant.grant_digest(on)


# --- digest ---------------------------------------------------------------------------------------

def test_digest_stable_and_change_sensitive():
    s1 = {"env": {"ct": ["101", "102"], "agent": []}}
    s2 = {"env": {"ct": ["101", "102"], "agent": []}}
    s3 = {"env": {"ct": ["101"], "agent": []}}
    assert reachgrant.grant_digest(s1) == reachgrant.grant_digest(s2)
    assert reachgrant.grant_digest(s1) != reachgrant.grant_digest(s3)
    assert len(reachgrant.grant_digest(s1)) == 16  # short head, hex


# --- snapshot: env lane + targets -----------------------------------------------------------------

def test_snapshot_env_lane_present(monkeypatch, tmp_path):
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102,101", PROXIMO_AGENT_ALLOWLIST="205")
    snap = reachgrant.grant_snapshot()
    assert snap["env"]["ct"] == ["101", "102"]
    assert snap["env"]["agent"] == ["205"]


def test_snapshot_env_lane_absent_when_triple_missing(monkeypatch):
    # A pure-targets deployment has no env API triple: the env lane must report ABSENT —
    # never crash, and never masquerade as an empty (deny-all) grant it does not hold.
    for k in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.delenv("PROXIMO_TARGETS", raising=False)
    snap = reachgrant.grant_snapshot()
    assert snap["env"] == {"absent": True}


def test_snapshot_env_failure_is_error_not_absent(monkeypatch):
    # Lens finding: with the triple PRESENT, a config-build failure (bad option, unreachable
    # anchor) must record an ERROR — calling it "absent" fakes a whole-grant REMOVED entry on
    # a transient failure and a re-ADDED one when it recovers.
    _base_env(monkeypatch, PROXIMO_AUDIT_EXPECTED_HEAD="not-a-valid-head!!")
    snap = reachgrant.grant_snapshot()
    assert "error" in snap["env"]
    assert snap["env"].get("absent") is not True


def test_snapshot_includes_pve_targets_and_flags_broken_ones(monkeypatch, tmp_path):
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102")
    reg = {
        "lab": {"kind": "pve", "base_url": "https://y:8006/api2/json", "node": "n2",
                "token_path": "/run/y", "ct_allowlist": ["31337", "31338"]},
        "backup": {"kind": "pbs", "base_url": "https://z:8007", "token_path": "/run/z"},
        "broken": {"kind": "pve"},  # missing required fields — must be RECORDED, not skipped
    }
    monkeypatch.setattr(reachgrant, "load_registry", lambda: reg)
    snap = reachgrant.grant_snapshot()
    assert snap["targets"]["lab"]["ct"] == ["31337", "31338"]
    assert "backup" not in snap["targets"]           # non-pve planes hold no exec grant
    assert "error" in snap["targets"]["broken"]      # loud, never silently dropped


def test_target_named_env_cannot_shadow_the_env_lane(monkeypatch, tmp_path):
    # Lens F3 (reproduced there): unprefixed flat keys let [targets.env] overwrite the env lane,
    # so an env widening recorded an EMPTY delta. The 'target:' namespace closes it.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102")
    reg = {"env": {"kind": "pve", "base_url": "https://y:8006/api2/json", "node": "n2",
                   "token_path": "/run/y", "ct_allowlist": ["555"]}}
    monkeypatch.setattr(reachgrant, "load_registry", lambda: reg)
    led = open_ledger(_svc_cfg(tmp_path))
    state = tmp_path / "reach-grant.state"
    reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "*")   # widen the ENV lane only
    out = reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    assert out["outcome"] == "changed"
    delta = _grant_entries(tmp_path)[-1]["detail"]["delta"]
    assert delta["env"]["ct"] == {"added": ["*"], "removed": ["102"]}   # NOT empty
    assert "target:env" not in delta                   # the target itself did not change


# --- check_and_record lifecycle -------------------------------------------------------------------

def test_initial_check_records_and_writes_state(monkeypatch, tmp_path):
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102,101")
    led = open_ledger(_svc_cfg(tmp_path))
    state = tmp_path / "reach-grant.state"
    out = reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    assert out["outcome"] == "initial"
    ents = _grant_entries(tmp_path)
    assert len(ents) == 1 and ents[0]["outcome"] == "initial"
    assert ents[0]["detail"]["door"] == "stdio"
    assert ents[0]["detail"]["summary"]["ct"] == 2
    saved = json.loads(state.read_text())
    assert saved["snapshot"]["env"]["ct"] == ["101", "102"]
    assert saved["digest"] == reachgrant.grant_digest(saved["snapshot"])


def test_initial_summary_reports_star_as_star(monkeypatch, tmp_path):
    # On `initial` the summary is the ONLY grant content in the entry — allow-all recorded as
    # ct:1 is the exact lie receipt_view refuses, and the ledger must refuse it too (lens F6).
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="*")
    led = open_ledger(_svc_cfg(tmp_path))
    out = reachgrant.check_and_record(led, state_file=str(tmp_path / "s"), door="stdio")
    assert out["outcome"] == "initial"
    assert _grant_entries(tmp_path)[0]["detail"]["summary"]["ct"] == "*"


def test_unchanged_restart_records_nothing(monkeypatch, tmp_path):
    # The no-spam contract: a restart with an identical grant adds ZERO ledger entries.
    # (Mutation-proof: delete the digest comparison and this fails on the entry count.)
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102,101")
    led = open_ledger(_svc_cfg(tmp_path))
    state = tmp_path / "reach-grant.state"
    reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    before = json.loads(state.read_text())
    out = reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    assert out["outcome"] == "unchanged"
    assert len(_grant_entries(tmp_path)) == 1  # still just the initial
    after = json.loads(state.read_text())
    assert after["last_checked"] >= before["last_checked"]  # liveness still moves


def test_change_records_added_and_removed(monkeypatch, tmp_path):
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102,101")
    led = open_ledger(_svc_cfg(tmp_path))
    state = tmp_path / "reach-grant.state"
    reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101,103")   # -102 +103
    out = reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    assert out["outcome"] == "changed"
    ents = _grant_entries(tmp_path)
    assert len(ents) == 2
    delta = ents[-1]["detail"]["delta"]
    assert delta["env"]["ct"] == {"added": ["103"], "removed": ["102"]}
    assert ents[-1]["detail"]["new_digest"] != ents[-1]["detail"]["old_digest"]


def test_star_widening_is_a_recorded_change(monkeypatch, tmp_path):
    # The single most consequential change: the grant widening to '*'.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102")
    led = open_ledger(_svc_cfg(tmp_path))
    state = tmp_path / "reach-grant.state"
    reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "*")
    out = reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    assert out["outcome"] == "changed"
    delta = _grant_entries(tmp_path)[-1]["detail"]["delta"]
    assert delta["env"]["ct"] == {"added": ["*"], "removed": ["102"]}


def test_record_lands_before_the_sidecar_moves(monkeypatch, tmp_path):
    # Lens F1 (reproduced there): write-state-first + a crash before record = the widened
    # snapshot on disk with no entry, and every later start reads `unchanged` — the permanent
    # swallow. Pin the order by making record raise: the sidecar must still hold the OLD state.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102")
    led = open_ledger(_svc_cfg(tmp_path))
    state = tmp_path / "reach-grant.state"
    reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    old_state = state.read_text()
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "*")

    class _Boom(RuntimeError):
        pass

    def _raise(*a, **k):
        raise _Boom("ledger append failed")
    monkeypatch.setattr(led, "record", _raise)
    with pytest.raises(_Boom):
        reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    assert state.read_text() == old_state  # crash window leaves the delta re-detectable
    monkeypatch.undo()  # restore led.record
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="*")
    out = reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    assert out["outcome"] == "changed"     # the widening is recorded on the next healthy start


def test_corrupt_state_is_loud_never_silent_initial(monkeypatch, tmp_path):
    # A present-but-unreadable state file must record `state_unreadable` — treating it as a
    # first run would let a clobbered sidecar swallow a grant change without a trace.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102")
    led = open_ledger(_svc_cfg(tmp_path))
    state = tmp_path / "reach-grant.state"
    state.write_text("{not json")
    out = reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    assert out["outcome"] == "state_unreadable"
    ents = _grant_entries(tmp_path)
    assert len(ents) == 1 and ents[0]["outcome"] == "state_unreadable"
    assert json.loads(state.read_text())["snapshot"]["env"]["ct"] == ["102"]  # rewritten fresh


def test_missing_state_with_chain_history_is_state_missing_not_initial(monkeypatch, tmp_path):
    # Reviewer finding 2: deletion is the CHEAPER clobber. A missing sidecar on a box whose
    # chain already holds reach_grant history must not reframe a widened grant as a benign
    # first run — the tamper-evident chain is the witness the trusted file can't be.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102")
    led = open_ledger(_svc_cfg(tmp_path))
    state = tmp_path / "reach-grant.state"
    first = reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    os.unlink(state)
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "*")   # the widening the rm would have hidden
    out = reachgrant.check_and_record(led, state_file=str(state), door="stdio")
    assert out["outcome"] == "state_missing"
    ent = _grant_entries(tmp_path)[-1]
    assert ent["outcome"] == "state_missing"
    assert ent["detail"]["last_recorded_digest"] == first["digest"]
    assert ent["detail"]["digest"] != first["digest"]  # the mismatch is visible in one entry


def test_true_first_run_is_still_initial(monkeypatch, tmp_path):
    # The state_missing hardening must not relabel a genuinely fresh box.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102")
    led = open_ledger(_svc_cfg(tmp_path))
    led.record("pve_guest_power", target="lxc/102", mutation=True)  # unrelated history only
    out = reachgrant.check_and_record(led, state_file=str(tmp_path / "s"), door="stdio")
    assert out["outcome"] == "initial"


def test_state_write_failure_is_a_second_entry_never_a_relabel(monkeypatch, tmp_path):
    # Root-safe unwritable target: the state path's PARENT is a regular file, so the atomic
    # rename fails for uid 0 too (chmod-based denial would pass silently on this root box).
    # Lens F9: the delta entry must land with outcome="changed" BEFORE the write failure is
    # reported as its own entry — a monitor filtering outcome=="changed" must not lose it.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102")
    led = open_ledger(_svc_cfg(tmp_path))
    blocker = tmp_path / "blocker"
    blocker.write_text("")
    out = reachgrant.check_and_record(led, state_file=str(blocker / "state"), door="stdio")
    assert out["outcome"] == "state_write_failed"
    ents = _grant_entries(tmp_path)
    assert [e["outcome"] for e in ents] == ["initial", "state_write_failed"]


def test_default_state_path_sits_beside_the_ledger(tmp_path):
    led = open_ledger(_svc_cfg(tmp_path))
    p = reachgrant.default_state_path(led)
    assert p == str(tmp_path / ".proximo-reach-grant")


# --- the server seam + the any-door law -----------------------------------------------------------

def test_server_reach_grant_check_records_with_serving_face(monkeypatch, tmp_path):
    # The helper every door calls: instance ledger + the face already set for this process.
    from proximo import server
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="102",
              PROXIMO_AUDIT_LOG=str(tmp_path / "audit.log"))
    server._instance_ledger.cache_clear()
    try:
        server._reach_grant_check()
    finally:
        server._instance_ledger.cache_clear()  # never leak a tmp ledger into other tests
    ents = _grant_entries(tmp_path)
    assert len(ents) == 1 and ents[0]["outcome"] == "initial"
    assert ents[0]["detail"]["door"] == "stdio"  # serving_face() default in tests


def test_every_door_runs_the_check():
    # ANY DOOR, ONE SPINE: a grant change observed only on stdio is the gate greeting one door.
    # Pinned on an actual CALL statement, not a substring — the def line itself contains
    # "_reach_grant_check()" and a stripped stdio call previously slipped this sweep (lens F5).
    import proximo
    src_dir = os.path.dirname(proximo.__file__)
    doors = {
        "server.py": (os.path.join(src_dir, "server.py"),
                      re.compile(r"^\s+_reach_grant_check\(\)\s*$", re.M)),
        "httpface.py": (os.path.join(src_dir, "httpface.py"),
                        re.compile(r"^\s+server\._reach_grant_check\(\)\s*$", re.M)),
        "mcphttp.py": (os.path.join(src_dir, "mcphttp.py"),
                       re.compile(r"^\s+server\._reach_grant_check\(\)\s*$", re.M)),
        "a2a/app.py": (os.path.join(src_dir, "a2a", "app.py"),
                       re.compile(r"^\s+server\._reach_grant_check\(\)\s*$", re.M)),
    }
    for name, (path, call) in doors.items():
        with open(path, encoding="utf-8") as f:
            text = f.read()
        assert '_record_session("session_start")' in text, \
            f"{name}: serve seam moved — update this sweep"
        assert call.search(text), \
            f"{name} serves the spine without an actual reach-grant check CALL"


def test_arm_source_flip_moves_the_digest(monkeypatch):
    # Lens finding (2026-08-26): unsetting PROXIMO_ARM_SOURCE between restarts silently
    # removes the exec write gate — a serve-start widening of exactly this perimeter — and
    # produced no reach_grant entry because arm_source was not in the snapshot. Now it is a
    # switch like ssh_target: set->unset and re-point must both move the digest.
    from types import SimpleNamespace as NS
    base = dict(ct_allowlist=frozenset({"102"}), agent_allowlist=frozenset(),
                enable_exec=True, enable_agent=False, ssh_target="pve")
    armed = reachgrant.resolved_lanes(NS(**base, arm_source="/etc/p/op-token"))
    unarmed = reachgrant.resolved_lanes(NS(**base, arm_source=None))
    repointed = reachgrant.resolved_lanes(NS(**base, arm_source="/etc/p/other-token"))
    d = reachgrant.grant_digest
    assert d(armed) != d(unarmed)        # the silent-widening case, now witnessed
    assert d(armed) != d(repointed)      # a re-pointed source is a different authority
    assert armed["arm_source"] == "/etc/p/op-token"


# --- Brick 3: the witness sees the PVE side (derived reach) ---

class _MirrorApi:
    """Double for the derive leg, REAL backend shape (lens finding: a fixture politer than
    the backend hides the defect): list_guests returns lxc AND qemu rows with INT vmids,
    exactly like ApiBackend.list_guests. Guests 101/103 hold the privilege, 102 does not;
    9001 is a QEMU VM that also "holds" it — the derive must never count it as ct reach."""
    def __init__(self, guests=(101, 102, 103), fail_on=None):
        self._guests = guests
        self._fail_on = fail_on
        self.queries = []

    def list_guests(self, node=None):
        rows = [{"vmid": g, "type": "lxc", "name": f"ct{g}"} for g in self._guests]
        rows.append({"vmid": 9001, "type": "qemu", "name": "vm9001"})
        return rows

    def access_permissions(self, path=None):
        self.queries.append(path)
        vmid = path.rsplit("/", 1)[-1]
        if self._fail_on and vmid == self._fail_on:
            raise RuntimeError("api down")
        held = {"ProximoReach": 1} if vmid in ("101", "103", "9001") else {}
        return {path: held} if held else {}


def test_derive_absent_without_factory_and_without_privilege(monkeypatch):
    # No factory = byte-identical snapshots to before this brick (zero digest churn for
    # estates not passing one); factory + dormant mirror = factory never called.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="101,102")
    monkeypatch.delenv("PROXIMO_REACH_PRIVILEGE", raising=False)
    def _boom():
        raise AssertionError("factory called while dormant")
    snap = reachgrant.grant_snapshot(_boom)
    assert "mirror" not in snap
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    snap = reachgrant.grant_snapshot()          # enforcing, no factory
    assert snap["mirror"] == {"privilege": "ProximoReach"}


def test_derived_ct_lists_only_reachable_guests(monkeypatch):
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="103,101,102")
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    api = _MirrorApi()
    snap = reachgrant.grant_snapshot(lambda: api)
    assert snap["mirror"]["derived_ct"] == ["101", "103"]   # 102 unreached; estate order
    assert api.queries == ["/vms/101", "/vms/102", "/vms/103"]  # allowlist scope, per path


def test_star_allowlist_enumerates_containers_only_never_vms(monkeypatch):
    # THE LENS'S HIGH: list_guests returns lxc AND qemu; a QEMU vmid in derived_ct would
    # witness "container reach" the mirror never governs — on exactly the flagship
    # allow-all config. The filter is type == "lxc", and int vmids must round-trip.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="*")
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    api = _MirrorApi(guests=(102, 101))
    snap = reachgrant.grant_snapshot(lambda: api)
    assert snap["mirror"]["derived_ct"] == ["101"]   # 9001 holds the privilege; qemu = excluded
    assert "/vms/102" in api.queries        # enumeration reached the unheld guest too
    assert "/vms/9001" not in api.queries   # and never wasted a query on the VM


def test_derive_failure_is_error_never_fake_reach(monkeypatch):
    # A factory failure or a mid-derive API failure records derived_error and OMITS the
    # list — the env-error precedent: churn in an entry carrying derived_error is unproven.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="101,102")
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    def _boom():
        raise RuntimeError("no backend")
    snap = reachgrant.grant_snapshot(_boom)
    assert snap["mirror"]["derived_error"] == "RuntimeError"
    assert "derived_ct" not in snap["mirror"]
    snap = reachgrant.grant_snapshot(lambda: _MirrorApi(fail_on="102"))
    assert snap["mirror"]["derived_error"] == "RuntimeError"
    assert "derived_ct" not in snap["mirror"]


def test_pveum_grant_lands_as_witnessed_delta(monkeypatch, tmp_path):
    # THE POINT OF THE BRICK: a PVE-side grant between serve starts — invisible to the env
    # side — now moves the digest and shows as a mirror.derived_ct delta.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="101,102,103")
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    led = open_ledger(_svc_cfg(tmp_path))
    state = str(tmp_path / "state")
    api = _MirrorApi()
    out1 = reachgrant.check_and_record(led, state_file=state, api_factory=lambda: api)
    assert out1["outcome"] == "initial"

    class _Widened(_MirrorApi):
        def access_permissions(self, path=None):
            self.queries.append(path)
            return {path: {"ProximoReach": 1}}   # pveum granted everywhere overnight

    out2 = reachgrant.check_and_record(led, state_file=state, api_factory=lambda: _Widened())
    assert out2["outcome"] == "changed"
    ents = _grant_entries(tmp_path)
    assert ents[-1]["detail"]["delta"]["mirror"]["derived_ct"] == {"added": ["102"], "removed": []}


def test_pure_targets_derive_is_absent_not_error(monkeypatch):
    # Absent, empty and broken are three different facts (module doctrine): an enforcing
    # pure-targets box has no env lane BY DESIGN — derived_absent, stable, factory unCALLED.
    for k in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.delenv("PROXIMO_TARGETS", raising=False)
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    def _boom():
        raise AssertionError("factory called on a pure-targets box")
    snap = reachgrant.grant_snapshot(_boom)
    assert snap["mirror"] == {"privilege": "ProximoReach", "derived_absent": True}


def test_env_error_derive_named_not_opaque(monkeypatch):
    # An env lane that failed to BUILD would raise the same error from the factory — the
    # derive names the fact (env_unavailable) instead of laundering it as an API exception.
    _base_env(monkeypatch, PROXIMO_AUDIT_EXPECTED_HEAD="not-a-valid-head!!")
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    def _boom():
        raise AssertionError("factory called while env lane is broken")
    snap = reachgrant.grant_snapshot(_boom)
    assert snap["mirror"]["derived_error"] == "env_unavailable"


def test_first_derive_is_annotated_baseline(monkeypatch, tmp_path):
    # The first post-upgrade enforcing start lands the whole map as "added" — a shape
    # identical to an overnight mass pveum grant. The entry must say which it is.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="101,102,103")
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    led = open_ledger(_svc_cfg(tmp_path))
    state = str(tmp_path / "state")
    reachgrant.check_and_record(led, state_file=state)                      # pre-brick sidecar
    out = reachgrant.check_and_record(led, state_file=state,
                                      api_factory=lambda: _MirrorApi())     # first derive
    assert out["outcome"] == "changed"
    ents = _grant_entries(tmp_path)
    assert ents[-1]["detail"]["derived_baseline"] is True
    class _Widened(_MirrorApi):
        def access_permissions(self, path=None):
            self.queries.append(path)
            return {path: {"ProximoReach": 1}}
    out2 = reachgrant.check_and_record(led, state_file=state,
                                       api_factory=lambda: _Widened())      # a REAL widening
    assert out2["outcome"] == "changed"
    assert "derived_baseline" not in _grant_entries(tmp_path)[-1]["detail"]


def test_derive_error_transition_shape_is_pinned(monkeypatch, tmp_path):
    # Documented contract, not an accident: list -> error shows the list emptying BESIDE
    # derived_error. Monitors key on derived_error's presence, not on `removed` alone.
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="101,103")
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    led = open_ledger(_svc_cfg(tmp_path))
    state = str(tmp_path / "state")
    reachgrant.check_and_record(led, state_file=state, api_factory=lambda: _MirrorApi())
    def _down():
        raise RuntimeError("pve down")
    reachgrant.check_and_record(led, state_file=state, api_factory=_down)
    d = _grant_entries(tmp_path)[-1]["detail"]["delta"]["mirror"]
    assert d["derived_ct"]["removed"] == ["101", "103"]
    assert d["derived_error"] == {"old": None, "new": "RuntimeError"}


def test_garbage_allowlist_entry_skipped_not_poisoning(monkeypatch):
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="101,abc")
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    api = _MirrorApi()
    snap = reachgrant.grant_snapshot(lambda: api)
    assert snap["mirror"]["derived_ct"] == ["101"]
    assert snap["mirror"]["derived_skipped"] == ["abc"]
    assert api.queries == ["/vms/101"]      # the garbage token never reached the API


def test_enumeration_unusable_guard(monkeypatch):
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="*")
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    class _Weird(_MirrorApi):
        def list_guests(self, node=None):
            return [{"vmid": "*", "type": "lxc"}]
    snap = reachgrant.grant_snapshot(lambda: _Weird())
    assert snap["mirror"]["derived_error"] == "enumeration_unusable"
    assert "derived_ct" not in snap["mirror"]


def test_env_api_factory_body_executes_through_the_real_seam(monkeypatch):
    # Lens finding: no test executed _env_api's body — a NameError/ImportError inside it
    # would ship as a perpetual opaque derived_error, the witness broken and self-reporting
    # only as an exception name. This drives the REAL serve seam with the mirror enforcing:
    # the factory must build (imports resolve), and the derive must fail on the fake token
    # path with a REAL exception name — proving the body ran past construction.
    import proximo.server as srv
    _base_env(monkeypatch, PROXIMO_CT_ALLOWLIST="101")
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    srv._reach_grant_check()
    state_path = reachgrant.default_state_path(srv._instance_ledger())
    saved = json.loads(open(state_path, encoding="utf-8").read())
    mirror = saved["snapshot"]["mirror"]
    assert mirror["privilege"] == "ProximoReach"
    # The factory body executed: the failure is the fake token file, not an import/name
    # error inside _env_api itself.
    assert mirror["derived_error"] in ("FileNotFoundError", "ProximoError", "RuntimeError")
    assert "derived_ct" not in mirror
