# ruff: noqa: F811, I001  (the `plane` fixture is imported from the net tests, then used as an argument)
"""Lens 4 against 074a14d: probes of round 4 (judging reads, two rate slots, the once-only rollback).

Each finding is written as the behaviour that SHOULD hold; the held behaviours are plain tests."""
from __future__ import annotations

import json
import os

import pytest
from test_core_pdm_rollback_net import (  # noqa: F401
    GUESTS, STORAGES, Api, _paths, _plan, _posts, _rollback, _rows, _wire, plane,
)
from test_net_reads_taint_nothing import INJ, Hostile, _FIXED

from proximo.core import engine, safetynet, spine, undo
from proximo.core.errors import ProximoError

PVE_QEMU = GUESTS[0][4]
PVE_LXC = GUESTS[1][4]


@pytest.fixture
def grants(monkeypatch, tmp_path):
    g = tmp_path / "grants"
    g.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(g))
    return g


def _grant(g, cid):
    p = g / os.path.basename(spine.grant_path(cid))
    p.touch()
    return p


def _rollbacks(api, concrete, name="before"):
    return [p for p in _posts(api) if p.endswith(f"/snapshot/{name}/rollback")]


# --- L4-1: the once-only guard compares the id AS SPELLED ---------------------------------------------

@pytest.mark.parametrize("respell", ["full-hash", "eight-chars", "twelve-chars", "forty-chars"])
def test_a_capture_is_rolled_back_to_once_whatever_the_id_spelling(plane, monkeypatch, respell):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref = out["undo"]["id"]
    snap = out["undo"]["snapshot"]
    undo.restore(ref, cfg=plane("pve"), confirm=True)
    assert len(_rollbacks(api, PVE_QEMU, snap)) == 1
    full = next(r["entry_hash"] for r in _rows() if str(r.get("entry_hash", "")).startswith(ref))
    other = {"full-hash": full, "eight-chars": ref[:8], "twelve-chars": ref, "forty-chars": full[:40]}[respell]
    with pytest.raises(ProximoError, match="already rolled back"):
        undo.restore(other, cfg=plane("pve"), confirm=True)
    assert len(_rollbacks(api, PVE_QEMU, snap)) == 1
    # and the ledger names the capture by its resolved hash, whatever the caller typed
    restores = {r["detail"]["restores"] for r in _rows() if r["detail"].get("restores")}
    assert restores == {full}


def test_a_mixed_case_id_is_not_an_id_at_all(plane, monkeypatch):
    _wire(monkeypatch)
    ref = _rollback(plane, "pve", "qemu", PVE_QEMU)["undo"]["id"]
    with pytest.raises(ProximoError, match="at least 8 hex characters"):
        undo.restore(ref.upper() if ref.upper() != ref else "AbCdEf012345", cfg=plane("pve"), confirm=True)


def test_held_the_same_spelling_is_refused_a_second_time(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    undo.restore(ref, cfg=plane("pve"), confirm=True)
    with pytest.raises(ProximoError, match="already rolled back"):
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    assert len(_rollbacks(api, PVE_QEMU, snap)) == 1


class RollbackFails(Api):
    """A guest whose rollback task ends in an error while `fail_rollback` is set."""

    fail_rollback = False

    def call(self, method, path, params=None):
        if method == "GET" and "/tasks/" in path and self.fail_rollback:
            posts = [p for m, p, _ in self.calls if m == "POST"]
            if posts and posts[-1].endswith("/rollback"):
                self.calls.append((method, path, dict(params or {})))
                return {"status": "stopped", "exitstatus": "rollback failed: storage busy", "upid": "x"}
        return super().call(method, path, params)


def test_a_rollback_whose_task_failed_may_be_retried(plane, monkeypatch):
    """The capture is closed by a rollback that LANDED (or may have), not by one the vendor's task
    reported as failed: nothing was rolled back, so trying again discards no work."""
    api = RollbackFails()
    monkeypatch.setattr(engine, "_client", lambda p, c=None: api)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    api.fail_rollback = True
    first = undo.restore(ref, cfg=plane("pve"), confirm=True)
    assert first.get("status") == "failed"
    api.fail_rollback = False
    second = undo.restore(ref, cfg=plane("pve"), confirm=True)
    assert second.get("status") != "failed"
    assert len(_rollbacks(api, PVE_QEMU, snap)) == 2
    with pytest.raises(ProximoError, match="already rolled back"):          # and now it did land: once
        undo.restore(ref, cfg=plane("pve"), confirm=True)


def test_a_rollback_whose_wire_call_failed_may_be_retried(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref = out["undo"]["id"]
    api.fail_on = "/rollback"
    with pytest.raises(Exception):  # noqa: B017,PT011  (the vendor refused; the type is the wire's)
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    api.fail_on = None
    assert undo.restore(ref, cfg=plane("pve"), confirm=True)["restores"] == ref


@pytest.mark.parametrize("how", ["crash-after-the-executing-row", "task-never-seen-to-finish"])
def test_a_rollback_that_may_have_landed_closes_the_capture_and_says_how_to_go_on(plane, monkeypatch, how):
    """Unknown reads as done: a second rollback over work that may already have been rolled back is
    the harm. The refusal says so and says what to read."""
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    full = next(r["entry_hash"] for r in _rows() if str(r.get("entry_hash", "")).startswith(ref))
    if how == "crash-after-the-executing-row":
        real = engine._record

        def dying(cfg, action, row, *, outcome, detail, **kw):
            if action == "core.execute" and outcome != engine.EXECUTING and detail.get("restores"):
                raise KeyboardInterrupt                      # the process dies after the POST, before any terminal row
            return real(cfg, action, row, outcome=outcome, detail=detail, **kw)
        monkeypatch.setattr(engine, "_record", dying)
        with pytest.raises(KeyboardInterrupt):
            undo.restore(ref, cfg=plane("pve"), confirm=True)
        monkeypatch.setattr(engine, "_record", real)
    else:
        monkeypatch.setattr(engine, "TASK_WAIT_DEFAULT", 0)
        undo.restore(ref, cfg=plane("pve"), confirm=True, wait=0)           # submitted, never polled
    n = len(_rollbacks(api, PVE_QEMU, snap))
    with pytest.raises(ProximoError, match="does not show how it ended") as caught:
        undo.restore(full, cfg=plane("pve"), confirm=True)
    assert "Read the guest and the vendor's task log" in str(caught.value) and "proximo_call" in str(caught.value)
    assert len(_rollbacks(api, PVE_QEMU, snap)) == n


# --- L4-2: a doomed attempt burns the two slots it reserved before the grant -------------------------

def test_a_rollback_refused_at_the_spend_costs_no_rate_slot(plane, monkeypatch, grants):
    monkeypatch.setenv("PROXIMO_RATE_MAX", "2")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    api = _wire(monkeypatch)
    cid = _plan(plane, "pve", "qemu", PVE_QEMU)["consent_id"]
    grant = _grant(grants, cid)
    real = spine.spend_consent

    def racing(c, d):                           # another process spends the one grant right after our look
        grant.unlink()
        return real(c, d)
    monkeypatch.setattr(spine, "spend_consent", racing)
    with pytest.raises(ProximoError):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert _posts(api) == []
    monkeypatch.setattr(spine, "spend_consent", real)
    _grant(grants, cid)                         # the operator approves again: the budget must still hold two
    _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert _paths(PVE_QEMU)[1] in _posts(api)


# --- L4-3: the vocabulary test does not know the device sentence -------------------------------------

def test_the_device_sentence_is_in_the_pinned_vocabulary(plane, monkeypatch):
    config = {"rootfs": "local-lvm:vm-100-disk-0", "mp0": f"/srv/{INJ},mp=/{INJ}"}
    api = Hostile(config=config, snapcfg={"rootfs": "local-lvm:vm-100-disk-0"})
    monkeypatch.setattr(engine, "_client", lambda p, c=None: api)
    why = _plan(plane, "pve", "lxc", PVE_LXC)["safety_net"]["why"]
    assert INJ not in why and safetynet.DEVICE_REASON in why          # the premise holds ...
    assert any(rx.match(why) for rx in _FIXED)                        # ... the pin does not cover it


# --- L4-4: a storage type that is not a string crashes the net unreceipted ---------------------------

def test_an_unhashable_storage_type_is_unsettled_not_a_crash(plane, monkeypatch):
    api = _wire(monkeypatch, storages=[{"storage": "local-lvm", "type": ["lvmthin"]}])
    before = len(_rows())
    try:
        _rollback(plane, "pve", "qemu", PVE_QEMU)              # a TypeError escapes here today
    except ProximoError:
        pass
    assert _paths(PVE_QEMU)[1] in _posts(api) or any(r["action"] == "core.refuse" for r in _rows()[before:])


# --- held: judging skips taint and nothing else -------------------------------------------------------

def test_held_a_judging_read_still_receipts_ok(plane, monkeypatch):
    monkeypatch.setenv(spine.TAINT_TRACK_ENV, "1")
    _wire(monkeypatch)
    row = engine.table()[("pve", "GET", "/nodes/{node}/qemu/{vmid}/config")]
    engine.execute(row, {}, cfg=plane("pve"), path="/nodes/pve1/qemu/100/config", judging=safetynet.JUDGING)
    last = _rows()[-1]
    assert last["action"] == "core.execute" and last["outcome"] == "ok" and last["detail"].get("untrusted") is True


def test_held_judging_has_no_effect_on_a_mutation(plane, monkeypatch, grants):
    """A mutation's own untrusted mark is unconditional: judging is only on the READ branch."""
    _wire(monkeypatch)
    row = engine.table()[("pve", "POST", "/nodes/{node}/qemu/{vmid}/snapshot")]
    with pytest.raises(ProximoError):
        engine.execute(row, {"snapname": "x"}, cfg=plane("pve"), path="/nodes/pve1/qemu/100/snapshot",
                       judging=safetynet.JUDGING)


def test_held_a_vendor_error_on_a_net_read_carries_no_text(plane, monkeypatch):
    class Loud(Api):
        def call(self, method, path, params=None):
            if method == "GET" and path.endswith("/config"):
                raise RuntimeError(f"HTTP 500: {INJ}")
            return super().call(method, path, params)
    api = Loud()
    monkeypatch.setattr(engine, "_client", lambda p, c=None: api)
    planned = _plan(plane, "pve", "qemu", PVE_QEMU)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    with open(os.environ["PROXIMO_AUDIT_LOG"], encoding="utf-8") as f:
        ledger = f.read()
    assert INJ not in json.dumps([planned, out], default=str) and INJ not in ledger


def test_a_net_read_keeps_nothing_in_the_store(plane, monkeypatch, tmp_path):
    store_dir = tmp_path / "store"
    monkeypatch.setenv("PROXIMO_STORE", "1")
    monkeypatch.setenv("PROXIMO_STORE_DIR", str(store_dir))
    api = Hostile()
    monkeypatch.setattr(engine, "_client", lambda p, c=None: api)
    _rollback(plane, "pve", "qemu", PVE_QEMU)
    hits = []
    for d, _, files in os.walk(store_dir):
        for f in files:
            with open(os.path.join(d, f), "rb") as fh:
                raw = fh.read()
            if f.endswith(".gz"):
                import gzip
                raw = gzip.decompress(raw)
            if INJ.encode() in raw:
                hits.append(os.path.relpath(os.path.join(d, f), store_dir))
    assert hits == []


# --- L4-5: the shell lane's snapshot=true still takes its slots one at a time -------------------------

def test_shell_snapshot_on_the_last_slot_refuses_before_the_grant_is_spent(monkeypatch, tmp_path, armed_plane):
    import test_core_shell_snapshot as ss
    from proximo.core import shell
    monkeypatch.setenv(shell.TARGET_ENV, "pve")
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", ss.CT)
    monkeypatch.setattr(spine, "_SLEEP", lambda s: None)
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    g = ss._grants(monkeypatch, tmp_path)
    api, sh = ss._wire(monkeypatch)
    ss._grant_the_command(armed_plane, g, snapshot=True)
    with pytest.raises(ProximoError):
        ss._exec(armed_plane, snapshot=True)
    assert list(g.iterdir()), "the operator's one grant was burned by a call that could never run"
    assert sh.calls == [] and not [p for m, p, _ in api.calls if m == "POST"]


# --- L4-6: a wall that refuses only the net's snapshot is met after the grant is spent --------------

def test_a_forbid_only_the_net_meets_is_shown_by_the_plan_and_refuses_before_the_grant_is_spent(
        plane, monkeypatch, grants):
    api = _wire(monkeypatch)
    cid = _plan(plane, "pve", "qemu", PVE_QEMU)["consent_id"]          # approved on a plan that saw no wall
    grant = _grant(grants, cid)
    monkeypatch.setenv("PROXIMO_FORBID", "description=")
    planned = _plan(plane, "pve", "qemu", PVE_QEMU)
    assert planned["allowed"] is False and planned["needs"] == "forbid" and "safety snapshot" in planned["reason"]
    with pytest.raises(ProximoError, match="forbid"):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert _posts(api) == []
    assert grant.exists(), "the grant was spent on a rollback whose net could never be taken"
    assert not any(r["action"] == "core.consent_spent" for r in _rows())


def test_the_shell_lanes_snapshot_walls_are_shown_and_met_before_the_grant(monkeypatch, tmp_path, armed_plane):
    import test_core_shell_snapshot as ss
    from proximo.core import shell
    monkeypatch.setenv(shell.TARGET_ENV, "pve")
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", ss.CT)
    monkeypatch.setattr(spine, "_SLEEP", lambda s: None)
    g = ss._grants(monkeypatch, tmp_path)
    api, sh = ss._wire(monkeypatch)
    ss._grant_the_command(armed_plane, g, snapshot=True)
    monkeypatch.setenv("PROXIMO_FORBID", "description=")
    row = engine.resolve("pve", "POST", ss.EXEC)
    planned = engine.plan(row, {"command": ["id"], "snapshot": True}, ss.EXEC, cfg=armed_plane)
    assert planned["allowed"] is False and planned["needs"] == "forbid"
    with pytest.raises(ProximoError, match="forbid"):
        ss._exec(armed_plane, snapshot=True)
    assert list(g.iterdir()) and api.calls == [] and sh.calls == []


# --- round 5 nits --------------------------------------------------------------------------------------

def test_a_bind_mount_guest_does_not_also_list_the_names_no_storage_reason(plane, monkeypatch):
    """The path is the cause, named once; it is not a volume that 'names no storage'."""
    _wire(monkeypatch, config={"rootfs": "local-lvm:vm-100-disk-0", "mp0": "/srv/data,mp=/data"},
          snapcfg={"rootfs": "local-lvm:vm-100-disk-0"})
    net = _plan(plane, "pve", "lxc", PVE_LXC)["safety_net"]
    assert safetynet.DEVICE_REASON in net["why"]
    assert not any("names no storage" in u for u in net.get("unsettled", []))


def test_a_passthrough_cdrom_does_not_cost_the_guest_its_net(plane, monkeypatch):
    """PVE's has_feature skips a CD-ROM drive, a passthrough `/dev/sr0` included."""
    _wire(monkeypatch, config={"scsi0": "local-lvm:vm-100-disk-0", "ide2": "/dev/sr0,media=cdrom"})
    net = _plan(plane, "pve", "qemu", PVE_QEMU)["safety_net"]
    assert net["taken"] is True and not net.get("unsettled")


@pytest.mark.parametrize("bad", [["lvmthin"], {"a": 1}, 5, None, True, "", ["a", ["b"]]])
def test_a_storage_type_that_is_not_text_is_unsettled_and_the_net_is_taken(plane, monkeypatch, bad):
    api = _wire(monkeypatch, storages=[{"storage": "local-lvm", "type": bad}])
    net = _plan(plane, "pve", "qemu", PVE_QEMU)["safety_net"]
    assert net["taken"] is True and "unknown" in net["unsettled"]
    assert _rollback(plane, "pve", "qemu", PVE_QEMU)["undo"]["captured"] is True
    assert _paths(PVE_QEMU)[0] in _posts(api)


def test_a_judgement_that_cannot_finish_is_unsettled_and_receipted_never_a_crash(plane, monkeypatch):
    _wire(monkeypatch)

    def boom(*a, **k):
        raise TypeError("unhashable type: 'list'")
    monkeypatch.setattr(safetynet, "judge_blocking", boom)
    net = _plan(plane, "pve", "qemu", PVE_QEMU)["safety_net"]
    assert net["taken"] is True and safetynet.JUDGEMENT_FAILED in net["unsettled"]
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert out["undo"]["captured"] is True and safetynet.JUDGEMENT_FAILED in out["undo"]["note"]
    executing = [r for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "executing"][-1]
    assert safetynet.JUDGEMENT_FAILED in executing["detail"]["undo"]["note"]       # in the receipt


def test_a_judging_read_keeps_nothing_in_the_store_and_a_callers_read_does(plane, monkeypatch, tmp_path):
    from proximo.core import store
    kept = []
    monkeypatch.setenv("PROXIMO_STORE", "1")
    monkeypatch.setenv("PROXIMO_STORE_DIR", str(tmp_path / "s"))
    monkeypatch.setattr(store, "keep", lambda *a, **k: kept.append(a))
    _wire(monkeypatch)
    row = engine.table()[("pve", "GET", "/nodes/{node}/qemu/{vmid}/snapshot")]
    engine.execute(row, {}, cfg=plane("pve"), path="/nodes/pve1/qemu/100/snapshot", judging=safetynet.JUDGING)
    assert kept == []
    engine.execute(row, {}, cfg=plane("pve"), path="/nodes/pve1/qemu/100/snapshot")
    assert len(kept) == 1


def test_a_task_exit_status_never_reaches_the_caller_or_the_refusal_row(plane, monkeypatch):
    """The snapshot task's exit status can carry what a guest agent said; the refusal says a fixed
    word and the task's id (the id is what to read the real status by). The generic `core.task` row
    of any task, this one included, still carries the vendor's status for the operator's audit
    (reported, not changed: it is the ledger's long-standing record of every task)."""
    _wire(monkeypatch, exitstatus=f"guest-fsfreeze-freeze failed: {INJ}")
    with pytest.raises(ProximoError) as e:
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert INJ not in str(e.value) and "the vendor's task ended in an error" in str(e.value)
    refuse = [r for r in _rows() if r["action"] == "core.refuse"][-1]
    assert INJ not in json.dumps(refuse) and str(refuse["detail"]["upid"]).startswith("UPID:")


# --- two undos racing -------------------------------------------------------------------------------------

def test_two_undos_racing_roll_back_once(plane, monkeypatch):
    """Both see a clean ledger; the lock beside it holds the once-check and the rollback together,
    so the second sees the first's rows and is refused."""
    import threading
    import time as _time
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    real = engine.execute

    def slow(row, args=None, **kw):
        if kw.get("restores"):
            _time.sleep(0.15)                       # widen the window between the check and the write
        return real(row, args, **kw)
    monkeypatch.setattr(engine, "execute", slow)
    results = []

    def attempt():
        try:
            results.append(("ran", undo.restore(ref, cfg=plane("pve"), confirm=True)))
        except ProximoError as exc:
            results.append(("refused", str(exc)))
    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(k for k, _ in results) == ["ran", "refused"]
    assert len(_rollbacks(api, PVE_QEMU, snap)) == 1


CAPTURE = "ab" * 32


def test_the_undo_lock_excludes_another_process_on_the_same_capture_only(tmp_path):
    """A second process holds the lock file of THIS capture; the call waits for it. Another capture's
    lock is a different file and does not wait."""
    import subprocess
    import sys
    import time as _time

    from proximo.core.ledger import LedgerConfig
    lcfg = LedgerConfig(audit_log_path=str(tmp_path / "audit.log"))
    (tmp_path / ".proximo-undo").mkdir()
    script = "\n".join(["import fcntl, os, sys, time",
                        "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)",
                        "fcntl.flock(fd, fcntl.LOCK_EX)",
                        "print('held', flush=True)",
                        "time.sleep(1.2)"])
    holder = subprocess.Popen([sys.executable, "-c", script, str(tmp_path / ".proximo-undo" / f"{CAPTURE}.lock")],  # noqa: S603
                              stdout=subprocess.PIPE, text=True)
    try:
        assert holder.stdout.readline().strip() == "held"
        start = _time.monotonic()
        with undo._once_lock(lcfg, "cd" * 32):
            assert _time.monotonic() - start < 0.5            # another capture: no wait
        start = _time.monotonic()
        with undo._once_lock(lcfg, CAPTURE):
            assert _time.monotonic() - start > 0.5            # the same capture: it blocked until the other let go
    finally:
        holder.kill()
        holder.wait()


def test_a_restore_recorded_under_a_short_spelling_still_closes_the_capture(plane, monkeypatch):
    """Rows written before the canonical id (a 12-character `restores`) are still read: the capture's
    resolved hash starts with what they recorded."""
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    row = engine.table()[("pve", "POST", "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback")]
    old_style = _paths(PVE_QEMU, snap)[1]
    engine.execute(row, {"start": True}, cfg=plane("pve"), path=old_style, restores=ref)   # as an older build wrote it
    full = next(r["entry_hash"] for r in _rows() if str(r.get("entry_hash", "")).startswith(ref))
    n = len(_rollbacks(api, PVE_QEMU, snap))
    with pytest.raises(ProximoError, match="already rolled back"):
        undo.restore(full, cfg=plane("pve"), confirm=True)
    assert len(_rollbacks(api, PVE_QEMU, snap)) == n
