"""Independent CONSENT — the single-use, out-of-band, per-plan authorization gate.

Grant state is external: a directory named by PROXIMO_CONSENT_DIR, holding a file per approved plan
named by consent_id_for(plan), read+consumed fresh on every call (no caching — see consent.py). The
consent_id is threaded from _plan() to the mutation seams via a contextvar; these tests simulate that
by calling set_pending_consent() directly (what _plan() does after recording the plan), then exercise
server._audited() — the shared mutation seam — mirroring the _wire_server idiom used in test_contain.py.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

import proximo.consent as consent
import proximo.server as server
from proximo.audit import AuditLedger
from proximo.backends import ExecResult, ProximoError
from proximo.config import ProximoConfig
from proximo.planning import RISK_LOW, Plan

_CID = "a" * 64  # a stand-in consent_id (any 64-hex is fine for the seam tests)


def _wire(tmp_path, monkeypatch):
    """Wire proximo.server with a real ledger and no live backends (as test_contain.py does)."""
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
        audit_log_path=log, audit_keyed=False,
    )
    led = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))
    return led, log


def _consent_dir(tmp_path, monkeypatch):
    cdir = tmp_path / "consent"
    cdir.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(cdir))
    return cdir


def _grant(cdir, consent_id) -> str:
    p = os.path.join(str(cdir), consent_id)
    with open(p, "w", encoding="utf-8") as f:
        f.write("")
    return p


def _entries(log_path) -> list[dict]:
    return [json.loads(ln) for ln in Path(log_path).read_text().splitlines() if ln.strip()]


# --- Backward compat: opt-in, inert when unset --------------------------------------------------


def test_mutation_proceeds_when_consent_dir_unset(tmp_path, monkeypatch):
    """Env unset => feature inert: mutation runs exactly as today, even with a pending consent_id."""
    _wire(tmp_path, monkeypatch)
    monkeypatch.delenv("PROXIMO_CONSENT_DIR", raising=False)
    consent.set_pending_consent(_CID)

    calls = []
    resp = server._audited("pve_guest_power", "lxc/100",
                           lambda: calls.append(1) or {"ok": True}, mutation=True)
    assert calls == [1]
    assert resp == {"status": "ok", "result": {"ok": True}}


# --- The core allow/deny gate -------------------------------------------------------------------


def test_mutation_refused_when_dir_set_and_no_grant(tmp_path, monkeypatch):
    """Dir set, no grant for this plan => ProximoError, and the real mutation NEVER fires."""
    _wire(tmp_path, monkeypatch)
    _consent_dir(tmp_path, monkeypatch)
    consent.set_pending_consent(_CID)

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []


def test_mutation_proceeds_with_matching_grant_and_consumes_it(tmp_path, monkeypatch):
    """A grant at <dir>/<consent_id> lets the mutation proceed once, and is CONSUMED (single-use)."""
    _wire(tmp_path, monkeypatch)
    cdir = _consent_dir(tmp_path, monkeypatch)
    consent.set_pending_consent(_CID)
    path = _grant(cdir, _CID)

    calls = []
    resp = server._audited("pve_guest_power", "lxc/100",
                           lambda: calls.append(1) or {"ok": True}, mutation=True)
    assert calls == [1]
    assert resp == {"status": "ok", "result": {"ok": True}}
    assert not os.path.exists(path)  # consumed


def test_grant_is_single_use_second_confirm_refused(tmp_path, monkeypatch):
    """Gap #2 closure: a grant authorizes ONE mutation, not a window. A replay of the identical
    confirm call (agent retry / hijack replay) finds no grant and is refused."""
    _wire(tmp_path, monkeypatch)
    cdir = _consent_dir(tmp_path, monkeypatch)
    consent.set_pending_consent(_CID)
    _grant(cdir, _CID)

    server._audited("pve_guest_power", "lxc/100", lambda: {"ok": True}, mutation=True)  # consumes

    consent.set_pending_consent(_CID)  # a fresh _plan for the retry (resets the satisfied flag)
    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []


def test_grant_for_a_different_plan_id_does_not_authorize(tmp_path, monkeypatch):
    """A grant present for one consent_id must not authorize a mutation whose plan hashes to another
    id — the binding is to THIS exact plan, not "some approval exists in the directory"."""
    _wire(tmp_path, monkeypatch)
    cdir = _consent_dir(tmp_path, monkeypatch)
    _grant(cdir, "b" * 64)                 # an approval for a DIFFERENT plan
    consent.set_pending_consent(_CID)      # but this mutation's plan hashes to _CID

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []


# --- consent_id_for: stable-field contract ------------------------------------------------------


def test_consent_id_excludes_volatile_current_but_binds_decision_fields():
    """consent_id ignores the volatile `current` telemetry (else a grant is unmatchable within
    seconds) but changes when a decision-relevant field (risk / blast_radius) changes."""
    p1 = Plan(action="pve_guest_power", target="lxc/100", change="halt",
              current={"uptime": 100}, blast_radius=[], risk=RISK_LOW, risk_reasons=[])
    p2 = Plan(action="pve_guest_power", target="lxc/100", change="halt",
              current={"uptime": 999999}, blast_radius=[], risk=RISK_LOW, risk_reasons=[])
    assert consent.consent_id_for(p1) == consent.consent_id_for(p2)  # `current` excluded

    p3 = Plan(action="pve_guest_power", target="lxc/100", change="halt",
              current={"uptime": 100}, blast_radius=["would evict guest 200"],
              risk=RISK_LOW, risk_reasons=[])
    p4 = Plan(action="pve_guest_power", target="lxc/100", change="halt",
              current={"uptime": 100}, blast_radius=[], risk="high", risk_reasons=[])
    assert consent.consent_id_for(p1) != consent.consent_id_for(p3)  # blast_radius binds
    assert consent.consent_id_for(p1) != consent.consent_id_for(p4)  # risk binds


# --- TTL + fail-closed --------------------------------------------------------------------------


def test_grant_refused_when_ttl_expired(tmp_path, monkeypatch):
    """A matching but stale grant (backdated past PROXIMO_CONSENT_TTL_SECONDS) is refused."""
    _wire(tmp_path, monkeypatch)
    cdir = _consent_dir(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_CONSENT_TTL_SECONDS", "1")
    consent.set_pending_consent(_CID)
    path = _grant(cdir, _CID)
    old = time.time() - 3600
    os.utime(path, (old, old))

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []
    assert os.path.exists(path)  # an expired grant is NOT consumed (only a valid consume removes it)


def test_ttl_falls_back_to_default_on_malformed_or_nonpositive(monkeypatch):
    """A misconfigured TTL must fall back to the default, never silently become 0 (= every grant
    instantly expired) or negative (= unbounded). Pins the malformed/<=0 branch of _ttl_seconds()."""
    for bad in ("abc", "  ", "0", "-5", "12x", "1_000_x"):
        monkeypatch.setenv("PROXIMO_CONSENT_TTL_SECONDS", bad)
        assert consent._ttl_seconds() == consent._DEFAULT_TTL_SECONDS, bad
    monkeypatch.delenv("PROXIMO_CONSENT_TTL_SECONDS", raising=False)
    assert consent._ttl_seconds() == consent._DEFAULT_TTL_SECONDS  # unset -> default
    monkeypatch.setenv("PROXIMO_CONSENT_TTL_SECONDS", "30")
    assert consent._ttl_seconds() == 30  # a valid positive value is honored


def test_grant_at_exactly_ttl_age_is_valid_boundary(tmp_path, monkeypatch):
    """A grant whose age is EXACTLY the TTL is still valid — the expiry check is strictly '>'. Pins
    the boundary so a '>' -> '>=' mutation (which would refuse a grant at the boundary) is caught.
    Time is pinned to the grant's own mtime + TTL so there is no filesystem-precision flake."""
    _wire(tmp_path, monkeypatch)
    cdir = _consent_dir(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_CONSENT_TTL_SECONDS", "1000")
    consent.set_pending_consent(_CID)
    path = _grant(cdir, _CID)
    mtime = os.stat(path).st_mtime

    monkeypatch.setattr(consent.time, "time", lambda: mtime + 1000.0)  # age == TTL exactly
    calls = []
    server._audited("pve_guest_power", "lxc/100",
                    lambda: (calls.append(1), {"ok": True})[1], mutation=True)
    assert calls == [1]
    assert not os.path.exists(path)  # a valid grant IS consumed

    # And one microsecond older is expired (the other side of the boundary).
    consent.set_pending_consent(_CID)
    path2 = _grant(cdir, _CID)
    mtime2 = os.stat(path2).st_mtime
    monkeypatch.setattr(consent.time, "time", lambda: mtime2 + 1000.001)
    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/101", lambda: calls.append(2), mutation=True)
    assert calls == [1]
    assert os.path.exists(path2)  # expired grant NOT consumed


def test_consent_no_plan_refused_when_dir_set_but_no_pending_id(tmp_path, monkeypatch):
    """Consent configured, but a mutation seam is reached with NO pending consent_id — no recorded
    plan to bind an approval to, so fail closed (blocked:consent_no_plan). Also exercises the A10
    end-of-operation clear: after clear_pending_consent(), a planless mutation fails closed here."""
    _, log = _wire(tmp_path, monkeypatch)
    _consent_dir(tmp_path, monkeypatch)
    consent.clear_pending_consent()  # no pending id (the state an op-end clear leaves behind)

    calls = []
    with pytest.raises(ProximoError, match="(?i)consent"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []
    assert any(e["outcome"] == "blocked:consent_no_plan" for e in _entries(log))


def test_taint_mandatory_but_no_consent_dir_fails_closed(tmp_path, monkeypatch):
    """Tainted session + PROXIMO_TAINT_REQUIRE_CONSENT set, but NO PROXIMO_CONSENT_DIR to verify a
    grant against: a silent no-op would let a tainted mutation through unconsented, so refuse
    (blocked:taint_consent_unconfigured) — the F7 fail-closed branch."""
    import proximo.taint as taint
    _, log = _wire(tmp_path, monkeypatch)
    monkeypatch.delenv("PROXIMO_CONSENT_DIR", raising=False)  # no consent dir configured
    monkeypatch.setenv("PROXIMO_TAINT_REQUIRE_CONSENT", "1")
    taint.mark_tainted(os.path.dirname(log), "ct_exec")  # taint the session out-of-band
    consent.set_pending_consent(_CID)  # a plan ran; the no-dir branch still fires first

    calls = []
    with pytest.raises(ProximoError, match="(?i)consent"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []
    assert any(e["outcome"] == "blocked:taint_consent_unconfigured" for e in _entries(log))


def _raise_for_grant(cdir, exc):
    real_remove = os.remove

    def fake_remove(p):
        if str(cdir) in str(p):
            raise exc
        return real_remove(p)
    return fake_remove


def test_consent_race_refused_when_grant_vanishes_before_consume(tmp_path, monkeypatch):
    """The os.remove IS the authoritative consume: if the grant vanishes between stat and remove (a
    concurrent single-use winner took it), the loser is refused (blocked:consent_race) and fn never
    runs. Mutating 'except FileNotFoundError: _refuse' -> 'pass' would let the loser proceed WITHOUT
    holding the grant — a genuine fail-open this pins (consent.py os.remove race arm)."""
    _, log = _wire(tmp_path, monkeypatch)
    cdir = _consent_dir(tmp_path, monkeypatch)
    consent.set_pending_consent(_CID)
    _grant(cdir, _CID)  # present at stat time
    monkeypatch.setattr(consent.os, "remove", _raise_for_grant(cdir, FileNotFoundError()))

    calls = []
    with pytest.raises(ProximoError, match="(?i)consent"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []
    assert consent._consent_satisfied.get() is False  # NOT authorized
    assert any(e["outcome"] == "blocked:consent_race" for e in _entries(log))


def test_consent_error_refused_when_grant_cannot_be_consumed(tmp_path, monkeypatch):
    """Grant present but the consume itself errors (perm denied on remove) => fail closed
    (blocked:consent_error), fn never runs (consent.py os.remove error arm)."""
    _, log = _wire(tmp_path, monkeypatch)
    cdir = _consent_dir(tmp_path, monkeypatch)
    consent.set_pending_consent(_CID)
    _grant(cdir, _CID)
    monkeypatch.setattr(consent.os, "remove", _raise_for_grant(cdir, PermissionError()))

    calls = []
    with pytest.raises(ProximoError, match="(?i)consent"):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []
    assert consent._consent_satisfied.get() is False
    assert any(e["outcome"] == "blocked:consent_error" for e in _entries(log))


def test_fail_closed_when_consent_dir_is_a_file(tmp_path, monkeypatch):
    """PROXIMO_CONSENT_DIR pointing at a real FILE (not a dir) => stat raises NotADirectoryError =>
    refuse (fail-closed on ambiguity), fn never called. A real OS error, not a mocked one."""
    _wire(tmp_path, monkeypatch)
    notdir = tmp_path / "not_a_dir"
    notdir.write_text("x")
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(notdir))
    consent.set_pending_consent(_CID)

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []


def test_no_pending_plan_fails_closed(tmp_path, monkeypatch):
    """Dir set but a mutation seam reached with NO consent_id in context (no _plan ran) => refuse
    (a mutation with no recorded plan can't be tied to an approval — fail-closed)."""
    _wire(tmp_path, monkeypatch)
    _consent_dir(tmp_path, monkeypatch)
    consent.set_pending_consent("")  # explicitly no pending consent_id

    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/100", lambda: calls.append(1), mutation=True)
    assert calls == []


# --- Reads / dry-run never gated ----------------------------------------------------------------


def test_reads_not_gated_by_consent(tmp_path, monkeypatch):
    """mutation=False calls (reads) proceed regardless of consent state — like CONTAIN."""
    _wire(tmp_path, monkeypatch)
    _consent_dir(tmp_path, monkeypatch)  # dir set, no grants anywhere
    consent.set_pending_consent(_CID)

    result = server._audited("pve_node_status", "pve", lambda: {"status": "running"})
    assert result == {"status": "running"}


# --- Forensics: blocked attempts recorded with the consent_id -----------------------------------


def test_blocked_consent_recorded_to_ledger_with_consent_id(tmp_path, monkeypatch):
    """A refused mutation IS recorded to the PROVE ledger with outcome blocked:consent_required and
    the consent_id in detail, so an operator can find and approve the exact plan."""
    led, log = _wire(tmp_path, monkeypatch)
    _consent_dir(tmp_path, monkeypatch)
    consent.set_pending_consent(_CID)

    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/100", lambda: {"ok": True}, mutation=True)

    entries = _entries(log)
    assert len(entries) == 1
    assert entries[0]["action"] == "pve_guest_power"
    assert entries[0]["outcome"] == "blocked:consent_required"
    assert entries[0]["mutation"] is True
    assert entries[0]["detail"]["consent_id"] == _CID


# --- Structural: the agent can never hand Proximo its own approval ------------------------------


async def test_no_registered_tool_accepts_a_caller_supplied_consent_id():
    """No MCP tool may take a consent/approval/grant parameter — else the agent could pass its own
    approval token instead of a human placing an out-of-band grant. Pinned at the API surface."""
    import inspect
    import re

    banned = re.compile(r"consent|approval|grant|authoriz", re.IGNORECASE)
    # pbs_node_config_set(consent_text): a REAL PBS API field (PUT /nodes/{node}/config's
    # `consent-text` — the login-page consent BANNER TEXT shown to PBS web-UI users, Wave 5c
    # full-surface campaign, pbs_admin.py). Coincidental substring match only — this is config
    # content the caller SUPPLIES to PBS, not a Proximo-level consent-grant token the caller could
    # use to bypass this server's own out-of-band CONSENT gate (consent.py). Narrowly exempted,
    # not silenced globally.
    # pmg_config_admin_update(consent_text): the IDENTICAL coincidental-collision shape, one
    # plane over — PMG's own PUT /config/admin `consent-text` field ("Consent text that is
    # displayed before logging in", Wave 9i full-surface campaign, pmg_identity.py). Same
    # reasoning as the PBS entry above: real appliance config content, not a consent-grant token.
    exempt = {
        "pbs_node_config_set": {"consent_text"},
        "pmg_config_admin_update": {"consent_text"},
    }
    tools = await server.mcp.list_tools()
    offenders = []
    for t in tools:
        fn = getattr(server, t.name, None)
        if fn is None or not callable(fn):
            continue
        for pname in inspect.signature(fn).parameters:
            if pname in exempt.get(t.name, ()):
                continue
            if banned.search(pname):
                offenders.append(f"{t.name}({pname})")
    assert not offenders, f"tool(s) accept a caller-supplied approval-shaped param: {offenders}"


def test_consent_module_exposes_no_grant_writer():
    """consent.py's public surface must contain NO function that writes a grant — minting a grant is
    reachable only from the out-of-band operator helper, never from Proximo code the agent can reach."""
    writer_like = [
        name for name in dir(consent)
        if not name.startswith("_")
        and callable(getattr(consent, name))
        and any(kw in name.lower() for kw in ("grant", "approve", "mint", "write", "place", "issue"))
    ]
    assert not writer_like, f"consent.py exposes a grant-writing-looking callable: {writer_like}"


# --- Contextvar isolation: the satisfied flag doesn't leak across operations --------------------


def test_satisfied_flag_reset_per_plan_no_leak(tmp_path, monkeypatch):
    """After one mutation consents (satisfied=True), a NEXT mutation whose _plan runs (resetting the
    flag) must still require its own grant — 'satisfied' must not leak from the prior operation."""
    _wire(tmp_path, monkeypatch)
    cdir = _consent_dir(tmp_path, monkeypatch)

    # Op A: grant present -> proceeds, sets satisfied.
    consent.set_pending_consent(_CID)
    _grant(cdir, _CID)
    server._audited("pve_guest_power", "lxc/100", lambda: {"ok": True}, mutation=True)

    # Op B: a fresh _plan (different id), NO grant -> must be refused (satisfied did not leak).
    other = "c" * 64
    consent.set_pending_consent(other)
    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/101", lambda: calls.append(1), mutation=True)
    assert calls == []


# --- A10: the de-dup markers are cleared at operation END, not only reset by the NEXT _plan -------
# The test above proves a fresh _plan resets the flag. This pair proves the complementary half: a
# mutation reaching the gates WITHOUT its own _plan (a future/unusual seam) cannot inherit a prior
# op's satisfied/reserved state, because the funnel clears it when the operation ends.
def test_stale_satisfied_does_not_leak_to_a_planless_mutation(tmp_path, monkeypatch):
    """Op A consents through the funnel and consumes its grant. Op B then reaches the funnel with
    NO _plan of its own — without the end-of-operation clear it would inherit satisfied=True and run
    ungated (fail-OPEN). It must fail closed instead."""
    _wire(tmp_path, monkeypatch)
    cdir = _consent_dir(tmp_path, monkeypatch)

    consent.set_pending_consent(_CID)
    _grant(cdir, _CID)
    server._audited("pve_guest_power", "lxc/100", lambda: {"ok": True}, mutation=True)

    # Op B: no set_pending_consent (the hole). Must NOT inherit Op A's satisfied flag.
    calls = []
    with pytest.raises(ProximoError):
        server._audited("pve_guest_power", "lxc/101", lambda: calls.append(1), mutation=True)
    assert calls == []


def test_audited_clears_gate_dedup_at_operation_end(tmp_path, monkeypatch):
    """The mechanism: after a mutation runs through the funnel, the CONSENT/ENVELOPE per-operation
    de-dup markers are cleared, so no gate state survives into the next call. Gates are inert here
    (nothing configured) — the clear must happen regardless of whether consent/rate were active."""
    import proximo.envelope as envelope
    _wire(tmp_path, monkeypatch)
    consent._consent_satisfied.set(True)
    consent._pending_consent_id.set("stale" * 12)
    envelope._rate_reserved.set(True)

    server._audited("pve_guest_power", "lxc/100", lambda: {"ok": True}, mutation=True)

    assert consent._consent_satisfied.get() is False
    assert consent._pending_consent_id.get() is None
    assert envelope._rate_reserved.get() is False


# === BYPASS proofs: the exec-family manual seams gate on consent too (seam-completeness) =========
# ct_exec / ct_psql / pve_agent_exec don't route their real mutating call through _audited(), so a
# consent gate only in _audited() would leave a hole. These drive the FULL tool path: the tool's own
# _plan() sets the real consent_id; with a consent dir set and NO grant present (and NO trip path, so
# the refusal is CONSENT's, not CONTAIN's), the real backend call must never fire.


class _FakeApi:
    """Backend spy — records exactly which real Proxmox-mutating calls fired (empty list = refused)."""

    def __init__(self):
        self.config = SimpleNamespace(node="pve")
        self.agent_execs: list = []
        self.snapshot_creates: list = []

    def agent_exec(self, vmid, node, command):
        self.agent_execs.append((vmid, node, command))
        return {"pid": 1}

    def agent_exec_status(self, vmid, node, pid):
        return {"exited": True, "exitcode": 0, "out-data": "", "err-data": ""}

    def snapshot_create(self, vmid, snapname, kind="lxc", node=None, description=None):
        self.snapshot_creates.append((vmid, snapname))
        return "UPID:create"

    def task_status(self, upid, node=None):
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


def _wire_with_backends(tmp_path, monkeypatch, *, enable_agent=False, agent_allowlist=frozenset(),
                        enable_exec=False, ct_allowlist=frozenset()):
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


def _blocked(log) -> list[dict]:
    return [e for e in _entries(log) if str(e["outcome"]).startswith("blocked:consent")]


def test_bypass_agent_exec_requires_consent(tmp_path, monkeypatch):
    """pve_agent_exec's manual audit path: no grant => refused, api.agent_exec NEVER fires."""
    _cfg, api, _exec, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_agent=True, agent_allowlist=frozenset({"101"}))
    _consent_dir(tmp_path, monkeypatch)  # dir set, NO grant
    with pytest.raises(ProximoError, match="(?i)consent"):
        server.pve_agent_exec("101", ["echo", "hi"], confirm=True)
    assert api.agent_execs == []
    assert _blocked(log)


def test_bypass_ct_exec_snapshot_requires_consent(tmp_path, monkeypatch):
    """ct_exec's auto-undo snapshot fires before _audited: no grant => refused, snapshot AND exec
    never run (the WHOLE operation refused, not just the exec half)."""
    _cfg, api, exec_, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}))
    _consent_dir(tmp_path, monkeypatch)
    with pytest.raises(ProximoError, match="(?i)consent"):
        server.ct_exec("105", ["rm", "-rf", "/x"], snapshot=True, confirm=True)
    assert api.snapshot_creates == []
    assert exec_.ran == []
    assert _blocked(log)


def test_bypass_ct_exec_without_snapshot_requires_consent(tmp_path, monkeypatch):
    """Same with snapshot=False: the gate is at the TOP of the execute path, so the plain exec is
    refused too (not tucked inside the `if snapshot:` branch)."""
    _cfg, api, exec_, _led, log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}))
    _consent_dir(tmp_path, monkeypatch)
    with pytest.raises(ProximoError, match="(?i)consent"):
        server.ct_exec("105", ["echo", "hi"], confirm=True)
    assert exec_.ran == []
    assert api.snapshot_creates == []


def test_bypass_ct_psql_requires_consent(tmp_path, monkeypatch):
    """ct_psql shares the same manual seam — no grant => refused, psql never runs."""
    _cfg, _api, exec_, _led, _log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}))
    _consent_dir(tmp_path, monkeypatch)
    with pytest.raises(ProximoError, match="(?i)consent"):
        server.ct_psql("105", "DROP TABLE x", confirm=True)
    assert exec_.ran == []


# --- A10: pve_agent_exec is the ONE mutation path that never routes through _audited, so its own
# finally must run the operation-end clear. ct_exec/ct_psql return _audited(...) and are covered by
# test_audited_clears_gate_dedup_at_operation_end; these pin the manual path.
def test_ct_exec_clears_gate_dedup_on_undo_unavailable_early_return(tmp_path, monkeypatch):
    """ct_exec(snapshot=True) runs its gate seams (consuming consent / reserving rate) and then, if
    the auto-undo snapshot can't be made, returns blocked:undo_unavailable BEFORE reaching _audited.
    The op-end clear must STILL fire on that early return — else a consumed-but-aborted op leaks its
    markers past itself. (Covers the branch _audited's finally never sees.)"""
    _cfg, api, exec_, _led, _log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}))
    monkeypatch.setattr(api, "snapshot_create",
                        lambda *a, **k: (_ for _ in ()).throw(ProximoError("no snapshots here")))
    calls = []
    monkeypatch.setattr(server, "_end_mutation_gates", lambda: calls.append(1))
    out = server.ct_exec("105", ["echo", "hi"], snapshot=True, confirm=True)
    assert out.get("status") == "blocked:undo_unavailable"
    assert exec_.ran == []          # command NOT run (fail-closed)
    assert calls == [1]             # cleared despite the early return


def test_ct_psql_clears_gate_dedup_on_undo_unavailable_early_return(tmp_path, monkeypatch):
    """Same early-return branch for ct_psql."""
    _cfg, api, exec_, _led, _log = _wire_with_backends(
        tmp_path, monkeypatch, enable_exec=True, ct_allowlist=frozenset({"105"}))
    monkeypatch.setattr(api, "snapshot_create",
                        lambda *a, **k: (_ for _ in ()).throw(ProximoError("no snapshots here")))
    calls = []
    monkeypatch.setattr(server, "_end_mutation_gates", lambda: calls.append(1))
    out = server.ct_psql("105", "DROP TABLE x", snapshot=True, confirm=True)
    assert out.get("status") == "blocked:undo_unavailable"
    assert exec_.ran == []
    assert calls == [1]


def test_pve_agent_exec_clears_gate_dedup_on_success(tmp_path, monkeypatch):
    """On the normal (successful) guest-exec path, the op-end clear fires exactly once."""
    _cfg, api, _exec, _led, _log = _wire_with_backends(
        tmp_path, monkeypatch, enable_agent=True, agent_allowlist=frozenset({"101"}))
    calls = []
    monkeypatch.setattr(server, "_end_mutation_gates", lambda: calls.append(1))
    out = server.pve_agent_exec("101", ["echo", "hi"], confirm=True)
    assert out["status"] == "ok"
    assert api.agent_execs == [("101", None, ["echo", "hi"])]
    assert calls == [1]


def test_pve_agent_exec_clears_gate_dedup_even_when_a_gate_refuses(tmp_path, monkeypatch):
    """The finally wraps the GATES, not just the exec — so a marker consumed by an earlier gate is
    cleared even when a LATER gate refuses (the rate-refused-after-consent-consumed leak). Here
    consent refuses (dir set, no grant); the clear must still run and the guest exec never fire."""
    _cfg, api, _exec, _led, _log = _wire_with_backends(
        tmp_path, monkeypatch, enable_agent=True, agent_allowlist=frozenset({"101"}))
    _consent_dir(tmp_path, monkeypatch)  # dir set, NO grant -> consent refuses
    calls = []
    monkeypatch.setattr(server, "_end_mutation_gates", lambda: calls.append(1))
    with pytest.raises(ProximoError, match="(?i)consent"):
        server.pve_agent_exec("101", ["echo", "hi"], confirm=True)
    assert api.agent_execs == []
    assert calls == [1]


# === Contextvar isolation: interleaved operations must not cross-wire consent ===================


def test_interleaved_operations_isolated_by_context(tmp_path, monkeypatch):
    """Two operations, each in its own contextvars.Context (as the MCP SDK's per-request
    copy_context() gives every call), must consume ONLY their own grant. If the consent_id/satisfied
    contextvars leaked across contexts, B's plan would clobber A's and A's confirm would look for the
    wrong grant. Interleave A.plan, B.plan, B.confirm, A.confirm and prove no cross-wire."""
    import contextvars

    _wire(tmp_path, monkeypatch)
    cdir = _consent_dir(tmp_path, monkeypatch)
    cid_a, cid_b = "a" * 64, "b" * 64
    _grant(cdir, cid_a)  # ONLY operation A is approved
    results: dict[str, str] = {}

    def _confirm(key):
        try:
            server._audited("pve_guest_power", f"lxc/{key}", lambda: None, mutation=True)
            results[key] = "ran"
        except ProximoError:
            results[key] = "refused"

    ctx_a = contextvars.copy_context()
    ctx_b = contextvars.copy_context()
    ctx_a.run(consent.set_pending_consent, cid_a)  # A plans
    ctx_b.run(consent.set_pending_consent, cid_b)  # B plans (would clobber A in a SHARED context)
    ctx_b.run(_confirm, "b")                        # B confirms: its own cid_b -> no grant -> refused
    ctx_a.run(_confirm, "a")                        # A confirms: its own cid_a (unclobbered) -> ran

    assert results == {"b": "refused", "a": "ran"}
