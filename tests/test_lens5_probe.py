# ruff: noqa: F811, I001  (fixtures are imported from the net and undo tests, then used as arguments)
"""Lens 5 against fe6b972: the spend step, the once-lock, `_attempts`, the fence; each finding fixed."""
from __future__ import annotations

import contextlib
import os

import pytest
from test_core_pdm_rollback_net import (  # noqa: F401
    GUESTS, Api, _paths, _plan, _posts, _rollback, _rows, _wire, plane,
)
from test_core_undo import (  # noqa: F401
    MINTED, TOKEN_PATH, TOKEN_ROW, _create_wire, _status_error, _tiered, box,
)
from test_core_undo import _wire as _undo_wire
from test_lens4_probe import _grant, _rollbacks, grants  # noqa: F401

from proximo.core import engine, ledger, spine, undo
from proximo.core.errors import ProximoError

PVE_QEMU = GUESTS[0][4]
CONFIG = "/nodes/pve1/qemu/100/config"
ROLLBACK_ROW = ("pve", "POST", "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback")


# --- L5-1: a mutation's read-back is taken before the spend ------------------------------------------

class ReadBackFails(Api):
    def call(self, method, path, params=None):
        if method == "GET" and path == CONFIG:
            self.calls.append((method, path, dict(params or {})))
            raise RuntimeError("HTTP 500")
        return super().call(method, path, params)


def test_a_mutation_whose_read_back_fails_spends_no_grant_and_no_slot(plane, monkeypatch, grants):
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    api = ReadBackFails()
    monkeypatch.setattr(engine, "_client", lambda p, c=None: api)
    row = engine.table()[("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config")]
    cid = engine.plan(row, {"cores": 4}, CONFIG, cfg=plane("pve"))["consent_id"]
    grant = _grant(grants, cid)
    with pytest.raises(ProximoError, match="read-back"):
        engine.execute(row, {"cores": 4}, cfg=plane("pve"), path=CONFIG)
    assert not [p for m, p, _ in api.calls if m == "PUT"]
    assert grant.exists() and not any(r["action"] == "core.consent_spent" for r in _rows())
    assert spine.reserve_rate(plane("pve").base_url, engine._audit_dir(None), count=1) is None   # the one slot is free


def test_the_read_back_is_already_taken_when_the_grant_is_spent(plane, monkeypatch, grants):
    api = _wire(monkeypatch)
    row = engine.table()[("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config")]
    cid = engine.plan(row, {"cores": 4}, CONFIG, cfg=plane("pve"))["consent_id"]
    _grant(grants, cid)
    real, at_spend = spine.spend_consent, []

    def spy(c, d):
        at_spend.append(("GET", CONFIG, {}) in api.calls)     # was the record already read when the grant went?
        return real(c, d)
    monkeypatch.setattr(spine, "spend_consent", spy)
    engine.execute(row, {"cores": 4}, cfg=plane("pve"), path=CONFIG)
    assert at_spend == [True]
    assert api.calls.index(("GET", CONFIG, {})) < api.calls.index(("PUT", CONFIG, {"cores": 4}))


# --- L5-2 / L5-3: what closes a capture -------------------------------------------------------------------

def _die_after_the_post(monkeypatch):
    real = engine._record

    def dying(cfg, action, row, *, outcome, detail, **kw):
        if action == "core.execute" and outcome != engine.EXECUTING and detail.get("restores"):
            raise KeyboardInterrupt
        return real(cfg, action, row, outcome=outcome, detail=detail, **kw)
    monkeypatch.setattr(engine, "_record", dying)
    return real


def test_an_unrelated_wire_error_at_the_same_path_does_not_reopen_a_maybe_landed_capture(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    real = _die_after_the_post(monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        undo.restore(ref, cfg=plane("pve"), confirm=True)       # the rollback was SENT; the process died
    monkeypatch.setattr(engine, "_record", real)
    assert len(_rollbacks(api, PVE_QEMU, snap)) == 1
    # an operator's direct rollback at the same path that the vendor refuses ("VM is locked")
    api.fail_on = "/rollback"
    with pytest.raises(Exception):  # noqa: B017,PT011
        engine.execute(engine.table()[ROLLBACK_ROW], {}, cfg=plane("pve"), path=_paths(PVE_QEMU, snap)[1])
    api.fail_on = None
    n = len(_rollbacks(api, PVE_QEMU, snap))
    with pytest.raises(ProximoError, match="does not show how it ended"):
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    assert len(_rollbacks(api, PVE_QEMU, snap)) == n


def test_an_undos_own_wire_error_row_names_the_capture_and_closes_only_that_attempt(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref = out["undo"]["id"]
    api.fail_on = "/rollback"
    with pytest.raises(Exception):  # noqa: B017,PT011
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    api.fail_on = None
    full = next(r["entry_hash"] for r in _rows() if str(r.get("entry_hash", "")).startswith(ref))
    errors = [r for r in _rows() if r["action"] == "core.error" and r["detail"].get("restores")]
    assert errors and errors[-1]["detail"]["restores"] == full
    assert undo.restore(ref, cfg=plane("pve"), confirm=True)["restores"] == ref        # failed: retryable


def test_a_direct_rollback_to_the_safety_snapshot_closes_the_capture(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    engine.execute(engine.table()[ROLLBACK_ROW], {}, cfg=plane("pve"), path=_paths(PVE_QEMU, snap)[1])
    n = len(_rollbacks(api, PVE_QEMU, snap))
    with pytest.raises(ProximoError, match="already rolled back"):
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    assert len(_rollbacks(api, PVE_QEMU, snap)) == n


def test_a_direct_rollback_that_failed_leaves_the_capture_open(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    api.fail_on = "/rollback"
    with pytest.raises(Exception):  # noqa: B017,PT011
        engine.execute(engine.table()[ROLLBACK_ROW], {}, cfg=plane("pve"), path=_paths(PVE_QEMU, snap)[1])
    api.fail_on = None
    assert undo.restore(ref, cfg=plane("pve"), confirm=True)["restores"] == ref


def test_the_unknown_refusal_says_only_what_the_operator_can_do(plane, monkeypatch):
    _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    real = _die_after_the_post(monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    monkeypatch.setattr(engine, "_record", real)
    with pytest.raises(ProximoError) as caught:
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    said = str(caught.value)
    assert "once the ledger shows" not in said                           # nothing writes that row
    assert "`undo` stays closed for this capture" in said
    assert f"proximo_call POST {_paths(PVE_QEMU, snap)[1]}" in said      # the one way on that works


def test_the_way_on_the_refusal_names_works_and_closes_the_capture_too(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    real = _die_after_the_post(monkeypatch)
    with pytest.raises(KeyboardInterrupt):
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    monkeypatch.setattr(engine, "_record", real)
    engine.execute(engine.table()[ROLLBACK_ROW], {}, cfg=plane("pve"), path=_paths(PVE_QEMU, snap)[1])
    with pytest.raises(ProximoError):
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    assert len(_rollbacks(api, PVE_QEMU, snap)) == 2          # the died one and the operator's; never a third


# --- L5-4 / 7: the order of the spend step ----------------------------------------------------------------------

def test_a_caller_whose_grant_is_gone_reserves_no_slot_at_all(plane, monkeypatch, grants):
    monkeypatch.setenv("PROXIMO_RATE_MAX", "2")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    _wire(monkeypatch)
    grant = _grant(grants, _plan(plane, "pve", "qemu", PVE_QEMU)["consent_id"])
    real, reserved = spine.spend_consent, []

    def racing(c, d):
        grant.unlink()                                   # the other racer spent it after our look
        return real(c, d)
    monkeypatch.setattr(spine, "spend_consent", racing)
    real_reserve = spine.reserve_rate
    monkeypatch.setattr(spine, "reserve_rate", lambda *a, **k: reserved.append(1) or real_reserve(*a, **k))
    with pytest.raises(ProximoError):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert reserved == []                                # a lost grant held no budget, not even for an instant


def test_a_rate_refusal_puts_the_grants_marker_back(plane, monkeypatch, grants):
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    _wire(monkeypatch)
    grant = _grant(grants, _plan(plane, "pve", "qemu", PVE_QEMU)["consent_id"])
    with pytest.raises(ProximoError, match="rate refused"):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert grant.exists()
    monkeypatch.setenv("PROXIMO_RATE_MAX", "5")
    assert _rollback(plane, "pve", "qemu", PVE_QEMU)["undo"]["captured"] is True   # the same grant, spendable once


def test_a_consent_spent_receipt_that_cannot_be_written_gives_back_the_marker_and_the_slots(
        plane, monkeypatch, grants):
    monkeypatch.setenv("PROXIMO_RATE_MAX", "2")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    api = _wire(monkeypatch)
    grant = _grant(grants, _plan(plane, "pve", "qemu", PVE_QEMU)["consent_id"])
    real = engine._record

    def refusing(cfg, action, row, **kw):
        if action == "core.consent_spent":
            raise ProximoError("the audit ledger could not be written")
        return real(cfg, action, row, **kw)
    monkeypatch.setattr(engine, "_record", refusing)
    with pytest.raises(ProximoError, match="could not be written"):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    monkeypatch.setattr(engine, "_record", real)
    assert grant.exists() and _posts(api) == []
    assert _rollback(plane, "pve", "qemu", PVE_QEMU)["undo"]["captured"] is True   # marker gone, both slots back


def test_release_gives_back_only_its_own_stamp(tmp_path):
    base = "https://pve.invalid:8006/api2/json"
    mine: list[float] = []
    os.environ["PROXIMO_RATE_MAX"], os.environ["PROXIMO_RATE_WINDOW"] = "5", "600"
    try:
        assert spine.reserve_rate(base, str(tmp_path), count=2) is None          # another caller's two
        assert spine.reserve_rate(base, str(tmp_path), count=2, stamp=mine) is None
        spine.release_rate(base, str(tmp_path), mine[0], 2)
        spine.release_rate(base, str(tmp_path), mine[0], 2)                     # twice: still only mine
        assert spine.reserve_rate(base, str(tmp_path), count=3) is None          # 2 + 3 = 5
        assert spine.reserve_rate(base, str(tmp_path), count=1) is not None
    finally:
        del os.environ["PROXIMO_RATE_MAX"], os.environ["PROXIMO_RATE_WINDOW"]


def test_a_tight_cap_does_not_drop_the_slots_a_looser_caller_reserved(tmp_path):
    """The reservation file is bounded for runaway growth, not by one caller's cap: a caller with a cap
    of 2 rewriting the file must not forget the 6 slots a caller with a cap of 10 holds."""
    base = "https://pve.invalid:8006/api2/json"
    os.environ["PROXIMO_RATE_WINDOW"] = "600"
    try:
        os.environ["PROXIMO_RATE_MAX"] = "10"
        assert spine.reserve_rate(base, str(tmp_path), count=6) is None
        os.environ["PROXIMO_RATE_MAX"] = "2"
        assert spine.reserve_rate(base, str(tmp_path), count=1) is not None        # over ITS cap: refused
        os.environ["PROXIMO_RATE_MAX"] = "10"
        assert spine.reserve_rate(base, str(tmp_path), count=4) is None            # 6 + 4: still exactly full
        assert spine.reserve_rate(base, str(tmp_path), count=1) is not None
    finally:
        del os.environ["PROXIMO_RATE_MAX"], os.environ["PROXIMO_RATE_WINDOW"]


# --- L5-6: an untrusted mutation's taint marker is written before anything is spent ----------------------------

def _mark_fails(monkeypatch):
    def cannot(*a, **k):
        raise OSError("read-only file system")
    monkeypatch.setattr(spine, "mark_tainted", cannot)


def test_a_shell_command_whose_taint_mark_fails_spent_nothing_and_left_nothing_open(
        monkeypatch, tmp_path, armed_plane):
    import test_core_shell_snapshot as ss
    from proximo.core import shell
    monkeypatch.setenv(shell.TARGET_ENV, "pve")
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", ss.CT)
    monkeypatch.setenv(spine.TAINT_TRACK_ENV, "1")
    monkeypatch.setattr(spine, "_SLEEP", lambda s: None)
    g = ss._grants(monkeypatch, tmp_path)
    api, sh = ss._wire(monkeypatch)
    ss._grant_the_command(armed_plane, g, snapshot=True)
    _mark_fails(monkeypatch)
    with pytest.raises(ProximoError, match="taint marker") as e:
        ss._exec(armed_plane, snapshot=True)
    assert "returns untrusted bytes" in str(e.value) and "the call was not run" in str(e.value)
    assert "read was not served" not in str(e.value)                                  # worded for a mutation
    assert sh.calls == [] and [p for m, p, _ in api.calls if m == "POST"] == []        # no net was taken
    assert list(g.iterdir())                                                           # the grant stands
    assert ledger.in_flight(_rows()) == []                                             # nothing left open


def test_a_guest_agent_command_whose_taint_mark_fails_is_refused_before_anything_is_spent(
        monkeypatch, tmp_path, armed_plane):
    monkeypatch.setenv("PROXIMO_ENABLE_AGENT", "1")
    monkeypatch.setenv("PROXIMO_AGENT_ALLOWLIST", "100")
    monkeypatch.setenv(spine.TAINT_TRACK_ENV, "1")
    g = tmp_path / "grants"
    g.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(g))
    api = Api()
    monkeypatch.setattr(engine, "_client", lambda p, c=None: api)
    path = "/nodes/pve1/qemu/100/agent"
    row = engine.table()[("pve", "POST", "/nodes/{node}/qemu/{vmid}/agent")]
    assert row.untrusted and row.lane == "agent"
    cid = engine.plan(row, {"command": "ping"}, path, cfg=armed_plane)["consent_id"]
    (g / os.path.basename(spine.grant_path(cid))).touch()
    _mark_fails(monkeypatch)
    with pytest.raises(ProximoError, match="the call was not run"):
        engine.execute(row, {"command": "ping"}, cfg=armed_plane, path=path)
    assert [p for m, p, _ in api.calls if m != "GET"] == [] and list(g.iterdir())
    assert ledger.in_flight(_rows()) == []


def test_a_reads_taint_refusal_keeps_its_own_words(plane, monkeypatch):
    monkeypatch.setenv(spine.TAINT_TRACK_ENV, "1")
    _wire(monkeypatch)
    _mark_fails(monkeypatch)
    row = engine.table()[("pve", "GET", "/nodes/{node}/qemu/{vmid}/config")]
    with pytest.raises(ProximoError, match="is an untrusted read and the taint marker could not be written"):
        engine.execute(row, {}, cfg=plane("pve"), path=CONFIG)


# --- the once-lock and the checks around it -----------------------------------------------------------------------

def test_a_plan_of_an_already_restored_capture_is_refused_before_it_is_planned(plane, monkeypatch):
    _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref = out["undo"]["id"]
    undo.restore(ref, cfg=plane("pve"), confirm=True)
    planned = []
    real = engine.plan
    monkeypatch.setattr(engine, "plan", lambda *a, **k: planned.append(1) or real(*a, **k))
    with pytest.raises(ProximoError, match="already rolled back"):
        undo.restore(ref, cfg=plane("pve"))
    assert planned == []                                  # refused on the ledger, before any plan was made


@contextlib.contextmanager
def _spying(monkeypatch, events):
    real_lock, real_check = undo._once_lock, undo._refuse_a_second

    @contextlib.contextmanager
    def lock(lcfg, key):
        events.append("lock")
        with real_lock(lcfg, key):
            yield
        events.append("unlock")

    def check(*a, **k):
        events.append("check")
        return real_check(*a, **k)
    monkeypatch.setattr(undo, "_once_lock", lock)
    monkeypatch.setattr(undo, "_refuse_a_second", check)
    yield


def test_the_rollbacks_check_is_repeated_inside_its_lock(plane, monkeypatch):
    _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    events: list[str] = []
    with _spying(monkeypatch, events):
        undo.restore(out["undo"]["id"], cfg=plane("pve"), confirm=True)
    assert events == ["check", "lock", "check", "unlock"]


def test_the_delete_backs_check_is_repeated_inside_its_lock(box, monkeypatch):
    _create_wire(monkeypatch, _status_error(404), answer=MINTED)
    out = engine.execute(_tiered(*TOKEN_ROW), {}, cfg=box, path=TOKEN_PATH)
    _undo_wire(monkeypatch, {"privsep": 1, "expire": 0})
    events: list[str] = []
    with _spying(monkeypatch, events):
        undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert events == ["check", "lock", "check", "unlock"]


def test_two_deletes_racing_for_one_create_delete_once(box, monkeypatch):
    import threading
    import time as _time
    _create_wire(monkeypatch, _status_error(404), answer=MINTED)
    out = engine.execute(_tiered(*TOKEN_ROW), {}, cfg=box, path=TOKEN_PATH)
    w = _undo_wire(monkeypatch, {"privsep": 1, "expire": 0})
    real = engine.execute

    def slow(row, args=None, **kw):
        if kw.get("restores"):
            _time.sleep(0.15)
        return real(row, args, **kw)
    monkeypatch.setattr(engine, "execute", slow)
    results = []

    def attempt():
        try:
            results.append(undo.restore(out["undo"]["id"], cfg=box, confirm=True) and "ran")
        except ProximoError:
            results.append("refused")
    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["ran", "refused"]
    assert len([m for m in w.mutations() if m[0] == "DELETE"]) == 1


def _lcfg(tmp_path):
    from proximo.core.ledger import LedgerConfig
    return LedgerConfig(audit_log_path=str(tmp_path / "audit.log"))


def test_the_lock_file_is_0600_in_a_0700_directory_per_capture(tmp_path):
    old = os.umask(0)
    try:
        with undo._once_lock(_lcfg(tmp_path), "ab" * 32):
            pass
    finally:
        os.umask(old)
    d = tmp_path / ".proximo-undo"
    assert oct(d.stat().st_mode & 0o777) == "0o700"
    assert oct((d / ("ab" * 32 + ".lock")).stat().st_mode & 0o777) == "0o600"


def test_a_symlinked_lock_file_refuses(tmp_path):
    (tmp_path / ".proximo-undo").mkdir()
    (tmp_path / "elsewhere").write_text("")
    os.symlink(tmp_path / "elsewhere", tmp_path / ".proximo-undo" / ("ab" * 32 + ".lock"))
    with pytest.raises(ProximoError, match="undo lock"), undo._once_lock(_lcfg(tmp_path), "ab" * 32):
        pass


def test_a_symlinked_lock_directory_refuses(tmp_path):
    (tmp_path / "elsewhere").mkdir()
    os.symlink(tmp_path / "elsewhere", tmp_path / ".proximo-undo")
    with pytest.raises(ProximoError, match="undo lock"), undo._once_lock(_lcfg(tmp_path), "ab" * 32):
        pass
    assert list((tmp_path / "elsewhere").iterdir()) == []         # nothing was made through the link


@pytest.mark.parametrize("bad", ["", "xyz", "AB" * 32, "../" + "a" * 30, "a" * 7, "a" * 65])
def test_a_lock_key_that_is_not_a_ledger_hash_refuses(tmp_path, bad):
    with pytest.raises(ProximoError, match="not a ledger hash"), undo._once_lock(_lcfg(tmp_path), bad):
        pass


def test_a_restore_waits_a_bounded_time_for_another_of_the_same_capture_then_refuses(tmp_path, monkeypatch):
    import fcntl
    monkeypatch.setattr(undo, "UNDO_LOCK_WAIT", 0.3)
    (tmp_path / ".proximo-undo").mkdir()
    fd = os.open(tmp_path / ".proximo-undo" / ("ab" * 32 + ".lock"), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        with pytest.raises(ProximoError, match="another restore of this capture is still running"), \
                undo._once_lock(_lcfg(tmp_path), "ab" * 32):
            pass
    finally:
        os.close(fd)


# --- an attempt whose task is not seen to end ----------------------------------------------------------------------

class RollbackRuns(Api):
    """The rollback's task is still running when the wait ends (timed out), or its poll fails."""
    mode = None

    def call(self, method, path, params=None):
        if method == "GET" and "/tasks/" in path and self.mode:
            posts = [p for m, p, _ in self.calls if m == "POST"]
            if posts and posts[-1].endswith("/rollback"):
                self.calls.append((method, path, dict(params or {})))
                if self.mode == "poll-error":
                    raise RuntimeError("HTTP 595")
                return {"status": "running", "upid": "x"}
        return super().call(method, path, params)


@pytest.mark.parametrize("mode", ["timed-out", "poll-error"])
def test_a_rollback_whose_task_is_not_seen_to_end_reads_unknown_and_closes_the_capture(plane, monkeypatch, mode):
    api = RollbackRuns()
    monkeypatch.setattr(engine, "_client", lambda p, c=None: api)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    api.mode = mode
    undo.restore(ref, cfg=plane("pve"), confirm=True, wait=1)
    api.mode = None
    n = len(_rollbacks(api, PVE_QEMU, snap))
    with pytest.raises(ProximoError, match="does not show how it ended"):
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    assert len(_rollbacks(api, PVE_QEMU, snap)) == n
    entries = ledger.parse_lines(ledger.read_log(os.environ["PROXIMO_AUDIT_LOG"]))
    full = next(r["entry_hash"] for r in entries if str(r.get("entry_hash", "")).startswith(ref))
    states = [a["state"] for a in undo._attempts(entries, full, _paths(PVE_QEMU, snap)[1])]
    assert states == ["unknown"]                                      # the task row said timed_out or error


def test_attempts_reads_each_kind_of_end_from_the_ledger_alone():
    full = "ab" * 32

    def row(action, outcome, **d):
        return {"action": action, "outcome": outcome, "target": "/x/rollback", "ts": "t", "detail": d}
    exe = row("core.execute", engine.EXECUTING, restores=full, intent="i")
    cases = {
        "ok": [exe, row("core.execute", "ok", restores=full, intent="i")],
        "failed-wire": [exe, row("core.error", "error", restores=full, intent="i", delivery="answered")],
        "failed-never-sent": [exe, row("core.error", "error", restores=full, intent="i", delivery="never-sent")],
        "lost-answer": [exe, row("core.error", "error", restores=full, intent="i", delivery="unknown")],
        "task-finished": [exe, row("core.execute", "submitted", restores=full, intent="i", upid="U"),
                          row("core.task", "finished", upid="U")],
        "task-failed": [exe, row("core.execute", "submitted", restores=full, intent="i", upid="U"),
                        row("core.task", "failed", upid="U")],
        "task-timed-out": [exe, row("core.execute", "submitted", restores=full, intent="i", upid="U"),
                           row("core.task", "timed_out", upid="U")],
        "task-poll-error": [exe, row("core.execute", "submitted", restores=full, intent="i", upid="U"),
                            row("core.task", "error", upid="U")],
        "no-terminal-row": [exe],
        "error-without-restores": [exe, row("core.error", "error", intent="i")],
    }
    want = {"ok": "done", "failed-wire": "failed", "failed-never-sent": "failed", "lost-answer": "unknown",
            "task-finished": "done", "task-failed": "failed", "task-timed-out": "unknown",
            "task-poll-error": "unknown", "no-terminal-row": "unknown", "error-without-restores": "unknown"}
    for name, entries in cases.items():
        assert [a["state"] for a in undo._attempts(entries, full)] == [want[name]], name
