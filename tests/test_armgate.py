"""ARM gate — does the token the server serves actually carry WRITE authority?

The gap this closes (found 2026-08-24 on the dogfood estate): `arm`/`disarm` swap the PVE API
token, so the boundary is enforced by PVE's own permission check — which binds only the API
backend. ``ct_exec``/``ct_psql`` reach containers over ``ssh -> pct exec`` as root on the PVE
host, authority that never touches the token. A fully DISARMED session therefore ran arbitrary
in-container commands all evening with every existing gate satisfied.

``enforce_lease`` did not catch it and could not: it proves the served token is FRESH, never that
it is the WRITE one, and `disarm` stamps a fresh mtime too (arm.py deliberately does that so a new
arm does not read as already-expired). Freshness and authority are different questions.

Design mirrors lease.py exactly: env-read (no cfg-threading), opt-in by configuration presence
(``PROXIMO_ARM_SOURCE`` set => the operator uses the arm pattern => the arm binds everything),
fail-closed once opted in, record-before-raise, and never a token byte in a message or the ledger.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

import proximo.server as server
from proximo.armgate import ARM_SOURCE_ENV, TOKEN_PATH_ENV, arm_state, enforce_arm
from proximo.audit import AuditLedger
from proximo.backends import ExecResult, ProximoError
from proximo.config import ProximoConfig

WRITE_TOKEN = "root@pam!write=11111111-1111-1111-1111-111111111111"
RO_TOKEN = "proximo@pve!ro=22222222-2222-2222-2222-222222222222"


def _wire(tmp_path, monkeypatch, *, served: str | None = WRITE_TOKEN, arm_source: bool = True):
    """Lay down an arm source + a served token and point env at them."""
    src = tmp_path / "pve-operator-token"
    src.write_text(WRITE_TOKEN)
    ro = tmp_path / "pve-token.readonly"
    ro.write_text(RO_TOKEN)
    token = tmp_path / "pve-token"
    if served is not None:
        token.write_text(served)
    monkeypatch.setenv(TOKEN_PATH_ENV, str(token))
    if arm_source:
        monkeypatch.setenv(ARM_SOURCE_ENV, str(src))
    else:
        monkeypatch.delenv(ARM_SOURCE_ENV, raising=False)
    monkeypatch.setenv("PROXIMO_READONLY_SOURCE", str(ro))
    return src, ro, token


def _ledger(tmp_path):
    log = str(tmp_path / "audit.log")
    return AuditLedger(log), log


def _entries(log_path) -> list[dict]:
    p = Path(log_path)
    if not p.exists():
        return []
    return [json.loads(ln) for ln in p.read_text().splitlines() if ln.strip()]


# ---------------------------------------------------------------- opt-in invariant

def test_unset_arm_source_means_not_enforced_and_enforce_is_a_noop(tmp_path, monkeypatch):
    """Zero behavior change for deployments that do not use the arm pattern.

    Mint-and-revoke deployments have no write token at rest, so there is nothing to compare
    against; the gate must stay dormant rather than refuse everything.
    """
    _wire(tmp_path, monkeypatch, served=RO_TOKEN, arm_source=False)
    led, log = _ledger(tmp_path)

    assert arm_state().enforced is False
    enforce_arm("ct_exec", "5380", led)          # must not raise
    assert _entries(log) == []                    # and must not ledger anything


def test_an_empty_arm_source_env_is_also_not_enforced(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch, served=RO_TOKEN)
    monkeypatch.setenv(ARM_SOURCE_ENV, "   ")
    led, _ = _ledger(tmp_path)
    assert arm_state().enforced is False
    enforce_arm("ct_exec", "5380", led)


# ---------------------------------------------------------------- both directions

def test_armed_passes(tmp_path, monkeypatch):
    """The served token IS the write token -> write authority is live -> allow."""
    _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)
    led, log = _ledger(tmp_path)

    st = arm_state()
    assert st.enforced is True
    assert st.armed is True

    enforce_arm("ct_exec", "5380", led)           # must not raise
    assert _entries(log) == []                    # a pass is not a ledger event


def test_disarmed_refuses_and_records_before_raising(tmp_path, monkeypatch):
    """THE BUG: this is the case that ran unguarded all evening."""
    _wire(tmp_path, monkeypatch, served=RO_TOKEN)
    led, log = _ledger(tmp_path)

    assert arm_state().armed is False

    with pytest.raises(ProximoError, match="not armed"):
        enforce_arm("ct_exec", "5380", led, detail={"command": ["rm", "-rf", "/"]})

    entries = _entries(log)
    assert len(entries) == 1, "record BEFORE raise — a refusal that leaves no trace is not PROVE"
    assert entries[0]["outcome"] == "blocked:not_armed"
    assert entries[0]["action"] == "ct_exec"
    assert entries[0]["mutation"] is True


# ---------------------------------------------------------------- fail-closed directions

# NOTE: chmod(0o000) does NOT make a file unreadable for root, and this box runs tests as root
# while CI does not. A permission-based probe therefore proves different things in the two places
# — the exact blind spot `this-box-is-root-ci-is-not` warns about. The cases below are
# uid-INDEPENDENT (ENOENT / ENOTDIR / unlink), so they mean the same thing everywhere; the
# permission case is kept separately and skipped where it cannot hold.

@pytest.mark.parametrize("mutate", ["token_missing", "token_dangling_symlink",
                                    "source_missing", "source_under_a_non_directory"])
def test_every_ambiguity_reads_as_NOT_armed(tmp_path, monkeypatch, mutate):
    """Anything that prevents PROVING write authority must refuse, never assume."""
    src, _ro, token = _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)

    if mutate == "token_missing":
        token.unlink()
    elif mutate == "token_dangling_symlink":
        token.unlink()
        token.symlink_to(tmp_path / "nowhere")            # ENOENT for every uid
    elif mutate == "source_missing":
        src.unlink()
    elif mutate == "source_under_a_non_directory":
        monkeypatch.setenv(ARM_SOURCE_ENV, str(token / "child"))  # ENOTDIR for every uid

    assert arm_state().armed is False, f"{mutate} must NOT read as armed"
    led, log = _ledger(tmp_path)
    with pytest.raises(ProximoError):
        enforce_arm("ct_exec", "5380", led)
    assert _entries(log)[0]["outcome"] == "blocked:not_armed"


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses file modes; this can only hold as non-root")
@pytest.mark.parametrize("which", ["token", "source"])
def test_an_unreadable_file_reads_as_NOT_armed(tmp_path, monkeypatch, which):
    """The permission direction, kept for CI (non-root) where mode 000 actually denies."""
    src, _ro, token = _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)
    target = token if which == "token" else src
    target.chmod(0o000)
    try:
        assert arm_state().armed is False
    finally:
        target.chmod(0o600)


def test_unset_token_path_reads_as_not_armed(tmp_path, monkeypatch):
    """Guards the os.stat(None)/open(None) footgun the lease module also guards."""
    _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)
    monkeypatch.delenv(TOKEN_PATH_ENV, raising=False)
    assert arm_state().armed is False


def test_two_empty_files_are_NOT_armed(tmp_path, monkeypatch):
    """b'' == b'' is True. Equality alone would call an empty token 'armed'."""
    src, _ro, token = _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)
    src.write_text("")
    token.write_text("")
    assert arm_state().armed is False, "an empty served token is never write authority"


def test_a_token_matching_NEITHER_source_is_not_armed(tmp_path, monkeypatch):
    """Rotation/garble: unrecognized token -> refuse -> operator re-arms. Self-healing."""
    _wire(tmp_path, monkeypatch, served="somebody@pam!other=33333333-3333-3333-3333-333333333333")
    assert arm_state().armed is False


def test_a_directory_at_the_token_path_is_not_armed(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)
    d = tmp_path / "as-a-dir"
    d.mkdir()
    monkeypatch.setenv(TOKEN_PATH_ENV, str(d))
    assert arm_state().armed is False


def test_trailing_whitespace_does_not_defeat_the_match(tmp_path, monkeypatch):
    """`install`/`cp` round-trips and editors add newlines; that is still the same token."""
    src, _ro, token = _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)
    token.write_text(WRITE_TOKEN + "\n")
    assert arm_state().armed is True


# ---------------------------------------------------------------- no token material escapes

def test_no_token_material_in_the_refusal_or_the_ledger(tmp_path, monkeypatch):
    """A gate that leaks the credential it guards is worse than no gate."""
    _wire(tmp_path, monkeypatch, served=RO_TOKEN)
    led, log = _ledger(tmp_path)

    with pytest.raises(ProximoError) as ei:
        enforce_arm("ct_psql", "5432", led, detail={"db": "postgres"})

    blob = str(ei.value) + json.dumps(_entries(log))
    for secret in (WRITE_TOKEN, RO_TOKEN, "11111111", "22222222"):
        assert secret not in blob, f"token material leaked: {secret!r}"


def test_the_state_object_carries_no_token_bytes(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch, served=RO_TOKEN)
    blob = repr(arm_state())
    for secret in (WRITE_TOKEN, RO_TOKEN, "11111111", "22222222"):
        assert secret not in blob


def test_the_refusal_names_the_remedy(tmp_path, monkeypatch):
    """A tool description is a prompt; so is a refusal. Say what to do about it."""
    _wire(tmp_path, monkeypatch, served=RO_TOKEN)
    led, _ = _ledger(tmp_path)
    with pytest.raises(ProximoError, match="arm"):
        enforce_arm("ct_exec", "5380", led)


# ---------------------------------------------------------------- per-session token paths

def test_a_per_session_token_path_is_judged_on_its_own(tmp_path, monkeypatch):
    """arm --session installs to sessions/<key>.token; each session's authority is its own."""
    src, ro, _token = _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    mine = sessions / "aaaa.token"
    mine.write_text(RO_TOKEN)                     # this session disarmed
    monkeypatch.setenv(TOKEN_PATH_ENV, str(mine))
    assert arm_state().armed is False

    mine.write_text(WRITE_TOKEN)                  # this session armed
    assert arm_state().armed is True


# ================================================================ wiring: the seams



class _FakeExec:
    """Records what would have run. If the gate works, these lists stay empty."""

    def __init__(self):
        self.ran: list = []
        self.sqled: list = []

    def run(self, ctid, command, **kw):
        self.ran.append((ctid, command))
        return ExecResult(str(ctid), " ".join(command), 0, "out", "")

    def psql(self, ctid, sql, **kw):
        self.sqled.append((ctid, sql))
        return ExecResult(str(ctid), sql, 0, "out", "")


class _FakeApi:
    def __init__(self):
        self.snapshot_creates: list = []

    def snapshot_create(self, *a, **kw):
        self.snapshot_creates.append((a, kw))
        return {"ok": True}


def _wire_server_with_arm(tmp_path, monkeypatch, *, served):
    """Full server wiring plus an arm-pattern env whose served token is `served`."""
    src, ro, token = _wire(tmp_path, monkeypatch, served=served)
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve",
        token_path=str(token), audit_log_path=log, audit_keyed=False,
        enable_exec=True, ct_allowlist=frozenset({"105"}),
    )
    api, exec_ = _FakeApi(), _FakeExec()
    led = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, exec_, led))
    # _plan is NOT stubbed: the real planner is pure here, and stubbing it would hide a gate
    # that only works because planning was faked away.
    return api, exec_, log


def test_ct_exec_refuses_while_disarmed(tmp_path, monkeypatch):
    """THE REGRESSION: this is what ran unguarded on the estate."""
    api, exec_, log = _wire_server_with_arm(tmp_path, monkeypatch, served=RO_TOKEN)

    with pytest.raises(ProximoError, match="not armed"):
        server.ct_exec("105", ["rm", "-rf", "/x"], confirm=True)

    assert exec_.ran == [], "the command must NEVER have run"
    blocked = [e for e in _entries(log) if e["outcome"] == "blocked:not_armed"]
    assert len(blocked) == 1
    assert blocked[0]["action"] == "ct_exec"


def test_ct_exec_refuses_before_the_auto_undo_snapshot(tmp_path, monkeypatch):
    """The snapshot fires outside _audited — refuse the WHOLE operation, not just the exec half."""
    api, exec_, _log = _wire_server_with_arm(tmp_path, monkeypatch, served=RO_TOKEN)

    with pytest.raises(ProximoError, match="not armed"):
        server.ct_exec("105", ["rm", "-rf", "/x"], snapshot=True, confirm=True)

    assert api.snapshot_creates == []
    assert exec_.ran == []


def test_ct_psql_refuses_while_disarmed(tmp_path, monkeypatch):
    _api, exec_, log = _wire_server_with_arm(tmp_path, monkeypatch, served=RO_TOKEN)

    with pytest.raises(ProximoError, match="not armed"):
        server.ct_psql("105", "SELECT 1", confirm=True)

    assert exec_.sqled == []   # gate is statement-INDEPENDENT: it never inspects the SQL
    assert [e["action"] for e in _entries(log) if e["outcome"] == "blocked:not_armed"] == ["ct_psql"]


def test_ct_exec_runs_when_armed(tmp_path, monkeypatch):
    """Direction B: the gate must stay SILENT on the good path, not just fire on the bad one."""
    _api, exec_, log = _wire_server_with_arm(tmp_path, monkeypatch, served=WRITE_TOKEN)

    out = server.ct_exec("105", ["echo", "hi"], confirm=True)

    assert exec_.ran == [("105", ["echo", "hi"])]
    # mutations return the symmetric envelope {"status": <outcome>, "result": <raw>} — see _audited
    assert out["status"] == "ok"
    assert out["result"]["returncode"] == 0
    assert [e for e in _entries(log) if e["outcome"] == "blocked:not_armed"] == []


def test_a_dry_run_plan_is_not_gated(tmp_path, monkeypatch):
    """confirm=False executes nothing, so it stays available while disarmed — planning is a read."""
    _api, exec_, _log = _wire_server_with_arm(tmp_path, monkeypatch, served=RO_TOKEN)
    out = server.ct_exec("105", ["echo", "hi"], confirm=False)
    assert out["status"] == "plan"
    assert exec_.ran == []


def test_backend_refuses_directly_even_if_the_server_gate_is_bypassed(tmp_path, monkeypatch):
    """Defense in depth, mirroring the existing enable_exec check AT the backend.

    A future caller reaching ExecBackend.run() directly must not ride on the allowlist alone.
    """
    from proximo.backends import ExecBackend

    _wire(tmp_path, monkeypatch, served=RO_TOKEN)
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve",
        token_path=str(tmp_path / "pve-token"),
        enable_exec=True, ct_allowlist=frozenset({"105"}),
    )
    with pytest.raises(ProximoError, match="not armed"):
        ExecBackend(cfg).run("105", ["echo", "hi"])


# ================================================================ adversarial: what did the split break?

def _exec_backend(tmp_path, monkeypatch, *, served, enable_exec=True, allow=frozenset({"105"})):
    from proximo.backends import ExecBackend
    _wire(tmp_path, monkeypatch, served=served)
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve",
        token_path=str(tmp_path / "pve-token"),
        enable_exec=enable_exec, ct_allowlist=allow,
    )
    return ExecBackend(cfg)


def _capture(monkeypatch):
    """Intercept subprocess.run so nothing actually executes; return the recorded argv list."""
    import types
    calls: list = []
    monkeypatch.setattr(
        "proximo.backends.subprocess.run",
        lambda argv, **kw: calls.append(argv) or types.SimpleNamespace(
            returncode=0, stdout="", stderr=""))
    return calls


def test_logs_STILL_enforces_the_allowlist(tmp_path, monkeypatch):
    """REGRESSION GUARD for this change. `logs` used to call `run`, which carried the
    enable_exec + vmid + allowlist checks. Splitting `run` into gate + `_run_unchecked` drops all
    three from `logs` if the checks land in the wrong half — turning a read tool into an
    unallowlisted exec. This is the single most dangerous thing this change could have done."""
    be = _exec_backend(tmp_path, monkeypatch, served=WRITE_TOKEN, allow=frozenset({"105"}))
    with pytest.raises(ProximoError, match="allowlist"):
        be.logs("999", "ssh")


def test_logs_STILL_enforces_enable_exec(tmp_path, monkeypatch):
    be = _exec_backend(tmp_path, monkeypatch, served=WRITE_TOKEN, enable_exec=False)
    with pytest.raises(ProximoError, match="disabled"):
        be.logs("105", "ssh")


def test_logs_STILL_validates_the_ctid(tmp_path, monkeypatch):
    be = _exec_backend(tmp_path, monkeypatch, served=WRITE_TOKEN)
    with pytest.raises(ProximoError):
        be.logs("../../etc/passwd", "ssh")


def test_logs_is_allowed_while_disarmed_on_purpose(tmp_path, monkeypatch):
    """Reading logs is what an operator needs while disarmed — often to decide whether to arm."""
    be = _exec_backend(tmp_path, monkeypatch, served=RO_TOKEN)
    calls = _capture(monkeypatch)
    be.logs("105", "ssh")
    assert calls, "ct_logs must still work while disarmed"
    assert "journalctl" in " ".join(calls[0])


def test_a_hostile_unit_name_stays_one_argv_element(tmp_path, monkeypatch):
    """`logs` is the one ungated path, so its single caller-supplied field carries the weight."""
    be = _exec_backend(tmp_path, monkeypatch, served=RO_TOKEN)
    calls = _capture(monkeypatch)
    be.logs("105", "ssh; touch /tmp/pwned")
    remote = calls[0][-1]
    assert "'ssh; touch /tmp/pwned'" in remote, "must arrive as ONE quoted argv element"


def test_psql_IS_gated_because_it_goes_through_run(tmp_path, monkeypatch):
    """psql delegates to run(), so it inherits the gate — it must not take the logs path."""
    be = _exec_backend(tmp_path, monkeypatch, served=RO_TOKEN)
    with pytest.raises(ProximoError, match="not armed"):
        be.psql("105", "SELECT 1")


def test_the_gate_reads_env_fresh_every_call_and_never_caches(tmp_path, monkeypatch):
    """A cached verdict would keep authority alive across a disarm mid-session."""
    _src, _ro, token = _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)
    assert arm_state().armed is True
    token.write_text(RO_TOKEN)
    assert arm_state().armed is False, "the very next call must see the disarm"
    token.write_text(WRITE_TOKEN)
    assert arm_state().armed is True


def test_a_symlinked_token_is_judged_by_its_TARGET(tmp_path, monkeypatch):
    """Not a hole — anyone who can point the path at the arm source can already copy it, the same
    argument arm.py makes — but the behavior should be asserted, not accidental."""
    src, _ro, token = _wire(tmp_path, monkeypatch, served=RO_TOKEN)
    token.unlink()
    token.symlink_to(src)
    assert arm_state().armed is True


# --- ct_diagnose: DIAGNOSE is a trust-spine pillar, and it must survive being disarmed --------
#
# Found by the 2026-08-24 adversarial pass (lens 1 reachability, then confirmed by a refute pass).
# `diagnose_container`'s probe loop called the ARM-GATED `run()`, so while disarmed every probe
# raised and the loop's `except Exception` swallowed it into `{"error": "ProximoError"}` — the
# reason discarded, nothing ledgered, the call recorded outcome="ok". Two defects in one line.
#
# The fix follows the codebase's OWN precedent rather than adding a gate: `_CONTAINER_PROBES` is
# fixed read-only argv with no caller input, exactly the reasoning `logs()` already uses. You
# diagnose a box precisely when it is broken and you are NOT armed.

class _DiagApi:
    """Minimal API stand-in: guest_status only, which is all diagnose_container asks of it."""
    def guest_status(self, ctid, kind="lxc", node=None):
        return {"status": "running", "name": "c", "cpu": 0.0, "mem": 1, "maxmem": 2}


def test_diagnose_probes_RUN_while_disarmed(tmp_path, monkeypatch):
    """The whole point: DIAGNOSE is a pillar. It must not go dark exactly when it is needed."""
    from proximo.diagnose import diagnose_container
    be = _exec_backend(tmp_path, monkeypatch, served=RO_TOKEN)   # disarmed
    calls = _capture(monkeypatch)
    report = diagnose_container(_DiagApi(), be, "105")
    assert calls, "diagnose probes must still run while disarmed"
    assert "probes" in report
    for key, probe in report["probes"].items():
        assert "error" not in probe, f"probe {key} was refused while disarmed: {probe}"


def test_diagnose_STILL_enforces_the_allowlist_while_disarmed(tmp_path, monkeypatch):
    """REGRESSION GUARD: the exemption must drop the ARM check ONLY, never the allowlist."""
    from proximo.diagnose import diagnose_container
    be = _exec_backend(tmp_path, monkeypatch, served=RO_TOKEN, allow=frozenset({"999"}))
    calls = _capture(monkeypatch)
    report = diagnose_container(_DiagApi(), be, "105")   # 105 NOT allowlisted
    assert not calls, "an unallowlisted CTID must never reach subprocess"
    # Assert the REASON, not merely that something failed: before the exemption every probe
    # errored anyway (on the arm gate), so a bare "an error happened" assertion passed
    # vacuously and pinned nothing.
    assert all("allowlist" in p.get("error", "") for p in report["probes"].values()), \
        report["probes"]


def test_diagnose_STILL_enforces_enable_exec_while_disarmed(tmp_path, monkeypatch):
    """REGRESSION GUARD: the exemption must not ride past the PROXIMO_ENABLE_EXEC opt-in either."""
    from proximo.diagnose import diagnose_container
    be = _exec_backend(tmp_path, monkeypatch, served=RO_TOKEN, enable_exec=False)
    calls = _capture(monkeypatch)
    report = diagnose_container(_DiagApi(), be, "105")
    assert not calls, "exec disabled must still refuse"
    assert all("PROXIMO_ENABLE_EXEC" in p.get("error", "") for p in report["probes"].values()), \
        report["probes"]


def test_a_failing_probe_reports_WHY_not_just_the_exception_type(tmp_path, monkeypatch):
    """`{"error": "ProximoError"}` is not a diagnosis. A DIAGNOSE tool must carry the reason."""
    from proximo.diagnose import diagnose_container
    be = _exec_backend(tmp_path, monkeypatch, served=RO_TOKEN, enable_exec=False)
    report = diagnose_container(_DiagApi(), be, "105")
    probe = report["probes"]["disk"]
    assert "PROXIMO_ENABLE_EXEC" in probe.get("error", ""), (
        f"the operator must be told WHY the probe failed, got: {probe}")


# --- MULTI-TARGET: the gate must judge the box the command is aimed AT ------------------------
#
# Found by the 2026-08-24 adversarial pass (lens 2), and it SURVIVED a refute pass that made it
# worse: packaging/targets.example.toml already promises "arming stays out-of-band and per-target:
# it swaps the token at that target's token_path", and CHANGELOG 0.11.0 repeats it. arm_state()
# read process-global env only, so with a registry target the gate graded the DEFAULT box's token
# while ssh -> pct exec ran against a DIFFERENT one. Armed here meant armed everywhere.
#
# envelope.py already did this correctly (it resolves the active target), so the pattern existed.

def _cfg_for(tmp_path, *, token_name, arm_source=None, readonly_source=None):
    from proximo.config import ProximoConfig
    return ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve",
        token_path=str(tmp_path / token_name),
        enable_exec=True, ct_allowlist=frozenset({"105"}),
        arm_source=arm_source, readonly_source=readonly_source,
    )


def test_a_registry_target_is_NOT_armed_by_the_default_boxs_arm(tmp_path, monkeypatch):
    """THE FAIL-OPEN. Default box armed; the command is aimed at another box entirely."""
    _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)          # default box: ARMED
    other = tmp_path / "other-box.token"
    other.write_text("other@pve!ro=44444444-4444-4444-4444-444444444444")
    cfg = _cfg_for(tmp_path, token_name="other-box.token")     # a DIFFERENT box's token
    st = arm_state(cfg)
    assert not st.armed, f"the default box's arm must not authorize another box: {st.reason}"
    assert st.enforced


def test_a_target_with_its_OWN_arm_source_can_be_armed(tmp_path, monkeypatch):
    """Fail-closed must not mean 'registry targets can never be armed' — that is not a gate."""
    _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)
    tgt_tok = tmp_path / "tgt.token"
    tgt_arm = tmp_path / "tgt.arm"
    tgt_tok.write_text("t@pve!w=55555555-5555-5555-5555-555555555555")
    tgt_arm.write_text("t@pve!w=55555555-5555-5555-5555-555555555555")
    cfg = _cfg_for(tmp_path, token_name="tgt.token", arm_source=str(tgt_arm))
    st = arm_state(cfg)
    assert st.armed and st.enforced, st.reason


def test_a_target_whose_arm_source_is_unconfigured_fails_CLOSED(tmp_path, monkeypatch):
    """Silence must not read as permission. The reason has to say what to configure."""
    _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)
    tgt_tok = tmp_path / "tgt2.token"
    tgt_tok.write_text("t@pve!w=66666666-6666-6666-6666-666666666666")
    cfg = _cfg_for(tmp_path, token_name="tgt2.token")
    st = arm_state(cfg)
    assert st.enforced and not st.armed
    assert "arm_source" in st.reason, st.reason


def test_the_default_env_box_is_unaffected_by_the_cfg_parameter(tmp_path, monkeypatch):
    """Regression guard: passing no cfg must behave exactly as before this change."""
    _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)
    assert arm_state().armed
    _wire(tmp_path, monkeypatch, served=RO_TOKEN)
    assert not arm_state().armed


def test_the_backend_grades_ITS_OWN_target_not_the_process_env(tmp_path, monkeypatch):
    """ExecBackend.run had self.config in hand and asked arm_state() about the env instead."""
    from proximo.backends import ExecBackend
    _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)           # default box ARMED
    other = tmp_path / "other2.token"
    other.write_text("other@pve!ro=77777777-7777-7777-7777-777777777777")
    be = ExecBackend(_cfg_for(tmp_path, token_name="other2.token"))
    with pytest.raises(ProximoError, match="not armed"):
        be.run("105", ["echo", "hi"])


# --- the degenerate configuration that reports ARMED forever ---------------------------------

def test_arm_source_pointing_at_the_served_token_is_NOT_armed(tmp_path, monkeypatch):
    """If both env vars resolve to the same file the predicate becomes `x == x` — armed always,
    silently, permanently. Found by lens 2; no guard existed."""
    _wire(tmp_path, monkeypatch, served=WRITE_TOKEN)
    same = os.environ[TOKEN_PATH_ENV]
    monkeypatch.setenv(ARM_SOURCE_ENV, same)
    st = arm_state()
    assert not st.armed, "comparing a file to itself must never count as authority"
    assert "same file" in st.reason, st.reason


def test_arm_refusal_WINS_over_an_expired_lease(tmp_path, monkeypatch):
    """THE SURVIVING MUTANT (2026-08-24 mutation lens): swapping enforce_arm and enforce_lease in
    ct_exec left all 11,999 tests green. The order is documented at the call site and reasoned
    about in both modules, and nothing pinned it — no test in the suite ever configured a
    disarmed token and an expired lease at the same time, because test_lease.py's own helper
    never sets PROXIMO_ARM_SOURCE, so enforce_arm was a no-op in every lease test.

    Neither ordering executes the command, so this is not a bypass. It decides which REMEDY the
    operator and the ledger are told to reach for: re-arm, or renew. Being told the wrong one
    while both are true is how an incident gets chased in the wrong direction.
    """
    api, exec_, log = _wire_server_with_arm(tmp_path, monkeypatch, served=RO_TOKEN)  # DISARMED
    monkeypatch.setenv("PROXIMO_ARM_TTL", "3600")
    token = Path(os.environ[TOKEN_PATH_ENV])
    old = time.time() - 7200                       # ... and the lease is ALSO expired
    os.utime(token, (old, old))

    with pytest.raises(ProximoError, match="not armed"):
        server.ct_exec("105", ["echo", "hi"], confirm=True)

    assert exec_.ran == [], "neither gate may let the command through"
    outcomes = [json.loads(ln)["outcome"] for ln in Path(log).read_text().splitlines() if ln.strip()]
    assert "blocked:not_armed" in outcomes, outcomes
    assert "blocked:lease_expired" not in outcomes, outcomes
