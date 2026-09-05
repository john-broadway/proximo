"""Unit tests for the live-smoke orchestrator's pure logic (registry integrity + phase planning).

The orchestrator (`scripts/live-smoke/run-all.py`) is live tooling, but its registry and planning are
pure and worth locking: a malformed registry (bad phase, dup name, missing script) or a broken phase
filter would silently mis-run the live tier. Loaded by path (the file name has a hyphen).
"""
import importlib.util
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).parent.parent / "scripts" / "live-smoke" / "run-all.py"
_spec = importlib.util.spec_from_file_location("run_all_orchestrator", _PATH)
run_all = importlib.util.module_from_spec(_spec)
# Register before exec: the module uses `from __future__ import annotations` + @dataclass, and
# dataclasses resolves the class's module via sys.modules during processing (None → crash otherwise).
sys.modules[_spec.name] = run_all
_spec.loader.exec_module(run_all)


@pytest.fixture(autouse=True)
def _isolate_file_env(monkeypatch):
    """The tier check reads env vars that name FILES, so an operator env leaking in (this box's
    own pbs-ci.env exports PROXIMO_PBS_CA_BUNDLE) would decide tests that are not about it.
    Clear them; each test sets exactly what it means to test."""
    for v in ("PROXIMO_CA_BUNDLE", "PROXIMO_PBS_CA_BUNDLE",
              "PROXIMO_TOKEN_PATH", "PROXIMO_TOKEN_FILE", "PROXIMO_PBS_TOKEN_PATH"):
        monkeypatch.delenv(v, raising=False)


def test_registry_self_validates():
    # phases valid, names unique, every referenced script file actually exists on disk
    assert run_all._validate_registry() == []


def test_every_smoke_has_a_known_phase():
    assert {s.phase for s in run_all.REGISTRY} <= set(run_all.PHASES)


def test_registry_names_are_unique():
    names = [s.name for s in run_all.REGISTRY]
    assert len(names) == len(set(names))


def test_selected_all_is_ordered_by_blast_radius():
    order = {p: i for i, p in enumerate(run_all.PHASES)}
    phases = [order[s.phase] for s in run_all._selected("all")]
    assert phases == sorted(phases)  # read → plan → mutate → destroy, non-decreasing


def test_selected_filters_to_named_phases():
    sel = run_all._selected("read,plan")
    assert {s.phase for s in sel} == {"read", "plan"}
    assert all(s.phase in ("read", "plan") for s in sel)


def test_selected_rejects_unknown_phase():
    with pytest.raises(SystemExit):
        run_all._selected("bogus")


def test_smoke_missing_env_reports_unset_requirements(monkeypatch):
    monkeypatch.delenv("PROXIMO_STORAGE", raising=False)
    blast = next(s for s in run_all.REGISTRY if s.name == "storage-blast")
    assert "PROXIMO_STORAGE" in run_all._smoke_missing_env(blast)


def test_destroy_smokes_flag_the_one_shot_regrant_constraint():
    # create→destroy smokes strip the guest's /vms/<id> ACL on purge; the registry must surface that
    # so the orchestrator/operator re-grants before each run (the load-bearing gotcha).
    destroy = [s for s in run_all.REGISTRY if s.phase == "destroy"]
    assert destroy and all(s.one_shot_regrant for s in destroy)


def test_template_convert_requires_source_vmid():
    # the smoke clones SMOKE_SRC_VMID -> a disposable id, so it REQUIRES the source; the registry must
    # list it or the orchestrator runs it (instead of cleanly SKIPping) and it hard-fails on a missing
    # env (the smoke→registry mismatch that bit the first live destroy run).
    tc = next(s for s in run_all.REGISTRY if s.name == "template-convert")
    assert "SMOKE_SRC_VMID" in tc.needs


def test_destroy_smokes_allocate_distinct_vmids():
    # each destroy smoke creates+purges a NEW guest, and purge STRIPS that /vms/<id> grant (one-shot,
    # confirmed live 2026-06-22). So two destroy smokes sharing a target-VMID env var collide in one
    # `--phase destroy` pass — the first strips the grant the second needs (clone vs template-convert
    # both on SMOKE_NEW_VMID was the live failure). The allocated (non-source) VMID vars must be distinct.
    destroy = [s for s in run_all.REGISTRY if s.phase == "destroy"]
    alloc_vars = [n for s in destroy for n in s.needs if "VMID" in n and "SRC" not in n]
    assert len(alloc_vars) == len(set(alloc_vars)), f"destroy smokes share a target VMID var: {alloc_vars}"


def test_read_and_plan_smokes_never_flagged_mutating():
    # the credential-free slice must not contain a one-shot-regrant (destroy) smoke
    safe = [s for s in run_all.REGISTRY if s.phase in ("read", "plan")]
    assert not any(s.one_shot_regrant for s in safe)


# --- env-tiering + PBS plane (continuous-CI wiring) ---------------------------

def test_pbs_is_a_phase_after_destroy():
    assert "pbs" in run_all.PHASES
    assert run_all.PHASES.index("pbs") > run_all.PHASES.index("destroy")


def test_pbs_smokes_registered_with_pbs_base():
    pbs = {s.name: s for s in run_all.REGISTRY if s.phase == "pbs"}
    assert {"pbs-namespace", "pbs-snapshot-delete", "pbs-prune", "pbs-gc", "pbs-verify"} <= set(pbs)
    assert all(s.base == "pbs" for s in pbs.values())
    assert not any(s.one_shot_regrant for s in pbs.values())  # PBS self-seeds; no ACL strip


def test_every_smoke_has_a_known_base():
    assert {s.base for s in run_all.REGISTRY} <= {"pve", "pbs"}


def test_base_env_ready_pve_tier(monkeypatch, tmp_path):
    tok = tmp_path / "pve.token"
    tok.write_text("t")
    for v in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE"):
        monkeypatch.setenv(v, "x")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(tok))
    assert run_all._base_env_ready("pve") == []


def test_base_env_ready_pbs_tier_reports_missing(monkeypatch):
    monkeypatch.delenv("PROXIMO_PBS_BASE_URL", raising=False)
    monkeypatch.delenv("PROXIMO_PBS_TOKEN_PATH", raising=False)
    missing = run_all._base_env_ready("pbs")
    assert "PROXIMO_PBS_BASE_URL" in missing and "PROXIMO_PBS_TOKEN_PATH" in missing


def test_pbs_smokes_require_the_pbs_host_allowlist():
    ns = next(s for s in run_all.REGISTRY if s.name == "pbs-namespace")
    assert "PROXIMO_SMOKE_PBS_HOSTS" in ns.needs


def test_guarded_mutate_smokes_require_the_vmid_allowlist():
    # the mutate smokes self-guard (default-deny); without the allowlist they'd hard-fail, so the
    # registry must require it -> the orchestrator SKIPs (not fails) when it isn't provisioned.
    gl = next(s for s in run_all.REGISTRY if s.name == "guest-lifecycle")
    assert "PROXIMO_SMOKE_TEST_VMIDS" in gl.needs


def test_skip_reason_combines_base_tier_and_needs(monkeypatch):
    for v in ("PROXIMO_PBS_BASE_URL", "PROXIMO_PBS_TOKEN_PATH", "PROXIMO_SMOKE_PBS_HOSTS"):
        monkeypatch.delenv(v, raising=False)
    ns = next(s for s in run_all.REGISTRY if s.name == "pbs-namespace")
    reasons = run_all._skip_reason(ns)
    assert any("PBS" in r.upper() for r in reasons)        # base-tier miss
    assert "PROXIMO_SMOKE_PBS_HOSTS" in reasons            # needs miss


def test_access_crud_registered_in_its_own_phase():
    assert "access" in run_all.PHASES
    ac = next(s for s in run_all.REGISTRY if s.name == "access-crud")
    assert ac.phase == "access" and ac.base == "pve"
    assert "PROXIMO_SMOKE_IDENTITY_PREFIXES" in ac.needs   # the identity guard's allowlist


def test_storage_admin_registered_in_its_own_phase():
    assert "storage" in run_all.PHASES
    sa = next(s for s in run_all.REGISTRY if s.name == "storage-admin")
    assert sa.phase == "storage" and sa.base == "pve"
    assert "PROXIMO_SMOKE_IDENTITY_PREFIXES" in sa.needs   # the name guard's allowlist


def test_coverage_blast_registered_in_plan_phase():
    # the 2026-06-19 blast-coverage PLAN smoke (op-classes #6-15) is read-only/plan-only, so it lives
    # in the plan phase and must SKIP (not red) when its sandbox fixtures aren't declared present.
    cb = next(s for s in run_all.REGISTRY if s.name == "coverage-blast")
    assert cb.phase == "plan" and cb.base == "pve"
    assert not cb.one_shot_regrant                        # read-only: no ACL strip
    # gated on the sandbox-IDENTITY fixtures (guessing one could name a prod object) so a cluster
    # without them skips instead of false-redding on fixture drift.
    for v in ("SMOKE_VMID", "PROXIMO_SMOKE_TEST_VMIDS", "SMOKE_STORE", "SMOKE_POOL"):
        assert v in cb.needs


def test_skip_reason_empty_when_fully_configured(monkeypatch, tmp_path):
    tok = tmp_path / "pbs.token"
    tok.write_text("t")
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://h:8007/api2/json")
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", str(tok))
    monkeypatch.setenv("PROXIMO_SMOKE_PBS_HOSTS", "pbs-test")
    ns = next(s for s in run_all.REGISTRY if s.name == "pbs-namespace")
    assert run_all._skip_reason(ns) == []


# --- a CA bundle that names no file (2026-09-04) -------------------------------
# Diagnosed from 65 straight nightly reds: the workflow's PBS precheck bails BEFORE writing
# ${RUNNER_TEMP}/pbs-ca.pem when the test box is down, and its own comment says the tier "must
# SKIP cleanly ... not red". But the bail is a bare `exit 0` in that step, so the smoke step still
# ran with PROXIMO_PBS_CA_BUNDLE pointing at a file that was never created, and all five PBS
# smokes FAILED where they should have skipped. The tier readiness check counted the VARIABLE as
# present and never asked whether the FILE was there.

def test_pbs_tier_is_not_ready_when_its_ca_bundle_names_no_file(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs.example:8007/api2/json")
    tok = tmp_path / "pbs.token"
    tok.write_text("t")
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", str(tok))
    monkeypatch.setenv("PROXIMO_PBS_CA_BUNDLE", str(tmp_path / "never-written.pem"))
    missing = run_all._base_env_ready("pbs")
    assert missing, "a CA bundle that names no file must not read as a ready tier"
    assert any("PROXIMO_PBS_CA_BUNDLE" in m for m in missing), missing


def test_pbs_tier_is_ready_when_its_ca_bundle_exists(monkeypatch, tmp_path):
    """CONTROL: the check must pass on a real file, or it is just a tier that never runs."""
    ca = tmp_path / "pbs-ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs.example:8007/api2/json")
    tok = tmp_path / "pbs.token"
    tok.write_text("t")
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", str(tok))
    monkeypatch.setenv("PROXIMO_PBS_CA_BUNDLE", str(ca))
    assert run_all._base_env_ready("pbs") == []


def test_pbs_tier_is_ready_when_no_ca_bundle_is_configured(monkeypatch, tmp_path):
    """CONTROL: an UNSET bundle is a deployment that verifies another way (fingerprint, system
    CAs). Only a bundle that is set and names nothing is the broken shape."""
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs.example:8007/api2/json")
    tok = tmp_path / "pbs.token"
    tok.write_text("t")
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", str(tok))
    monkeypatch.delenv("PROXIMO_PBS_CA_BUNDLE", raising=False)
    assert run_all._base_env_ready("pbs") == []


def test_pve_tier_ca_bundle_gets_the_same_check(monkeypatch, tmp_path):
    """The class, not the instance: the PVE tier takes a CA bundle too."""
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.example:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    tok = tmp_path / "pve.token"
    tok.write_text("t")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(tok))
    monkeypatch.setenv("PROXIMO_CA_BUNDLE", str(tmp_path / "never-written.pem"))
    missing = run_all._base_env_ready("pve")
    assert any("PROXIMO_CA_BUNDLE" in m for m in missing), missing


# --- the verdict: a run that ran nothing is not a pass (2026-09-04) -------------
# Found by an adversarial lens on the CA-bundle skip fix above. That fix was correct about
# readiness and WRONG about consequence: `cmd_run` ended `return 1 if failed else 0`, so a night
# where the lab is off and every smoke skips exited 0 and CI read GREEN. It converted a true red
# into a false green, which is the one outcome this workflow's own header forbids. `ran` was
# computed and never used.

def test_a_run_that_ran_nothing_is_not_a_pass():
    results = [(f"pbs-{n}", "SKIP", 0.0) for n in ("namespace", "prune", "gc")]
    rc, note = run_all._verdict(results)
    assert rc != 0, "0 run must never exit 0 — nothing was proven"
    assert "ran nothing" in note.lower() or "0 run" in note, note


def test_a_failure_still_exits_one():
    results = [("backup", "PASS", 1.0), ("prove", "FAIL(rc=1)", 1.0)]
    rc, _ = run_all._verdict(results)
    assert rc == 1


def test_a_partial_run_with_no_failures_passes():
    """CONTROL: the lab being off is NORMAL, not a nightly red. What ran, passed, and the skips
    stay visible in the summary. Only a run that proved NOTHING is refused."""
    results = [("backup", "PASS", 1.0), ("pbs-gc", "SKIP", 0.0)]
    rc, _ = run_all._verdict(results)
    assert rc == 0


def test_an_all_pass_run_passes():
    rc, _ = run_all._verdict([("backup", "PASS", 1.0)])
    assert rc == 0


def test_a_token_path_that_names_no_file_is_not_a_ready_tier(monkeypatch, tmp_path):
    """THE CLASS SWEEP the first cut missed. The workflow's Materialize step says
    "PROXIMO_CI_TOKEN unset — PVE (mutate) smokes will SKIP" and then does not write the token
    file, while the smoke step sets PROXIMO_TOKEN_PATH unconditionally. Same shape as the CA
    bundle, twenty lines away in the same YAML, and it was FAIL where the text says SKIP."""
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.example:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(tmp_path / "never-written.token"))
    missing = run_all._base_env_ready("pve")
    assert any("PROXIMO_TOKEN_PATH" in m for m in missing), missing


def test_a_directory_is_not_an_acceptable_bundle(monkeypatch, tmp_path):
    """`isfile`, not `exists`: httpx takes a cafile only, so a DIRECTORY of certs raises at
    connect time. Swapping isfile->exists survived the first test set — this closes that."""
    tok = tmp_path / "pbs.token"
    tok.write_text("t")
    d = tmp_path / "certs-dir"
    d.mkdir()
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs.example:8007/api2/json")
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", str(tok))
    monkeypatch.setenv("PROXIMO_PBS_CA_BUNDLE", str(d))
    missing = run_all._base_env_ready("pbs")
    assert any("PROXIMO_PBS_CA_BUNDLE" in m for m in missing), missing
