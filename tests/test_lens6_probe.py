# ruff: noqa: F811, I001  (fixtures are imported from the net and undo tests, then used as arguments)
"""Lens 6 against 40df3ec: what a failed request proves, what a failed safety snapshot costs, direct
rollbacks across planes, receipts for the once-guard's refusals, and the rate file's windows."""
from __future__ import annotations

import fcntl
import os
import threading
import time as _time

import httpx
import pytest
from test_core_pdm_rollback_net import (  # noqa: F401
    GUESTS, Api, _paths, _plan, _posts, _rollback, _rows, _wire, plane,
)
from test_lens4_probe import _grant, _rollbacks, grants  # noqa: F401

from proximo.core import engine, ledger, spine, undo
from proximo.core.errors import ProximoError

PVE_QEMU = GUESTS[0][4]
PDM_QEMU = GUESTS[2][4]
ROLLBACK_ROW = ("pve", "POST", "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback")


def _slots_free(plane_cfg) -> int:
    """How many slots the box's budget still has (probed by taking and giving back)."""
    free = 0
    for n in (1, 2, 3):
        stamp: list[float] = []
        if spine.reserve_rate(plane_cfg.base_url, engine._audit_dir(None), count=n, stamp=stamp) is None:
            spine.release_rate(plane_cfg.base_url, engine._audit_dir(None), stamp[0], n)
            free = n
    return free


# --- L6-2: an error after the request went out, with no answer, is unknown, not failed -----------------

def _lost_answer_api(monkeypatch):
    api = _wire(monkeypatch)
    api.lose_answer_on = "/rollback"
    return api


def test_an_undo_whose_answer_was_lost_is_unknown_and_never_retried(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    api.lose_answer_on = "/rollback"
    with pytest.raises(ProximoError):                      # the rollback was SENT; the answer never came back
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    api.lose_answer_on = None
    assert len(_rollbacks(api, PVE_QEMU, snap)) == 1
    err = [r for r in _rows() if r["action"] == "core.error" and r["detail"].get("restores")][-1]
    assert err["detail"]["delivery"] == "unknown" and err["detail"]["error"] == "ReadTimeout"
    with pytest.raises(ProximoError, match="does not show how it ended"):
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    assert len(_rollbacks(api, PVE_QEMU, snap)) == 1                              # never rolled back twice


class NeverConnects(Api):
    def call(self, method, path, params=None):
        if method == "POST" and path.endswith("/rollback") and self.refuse_connect:
            self.calls.append((method, path, dict(params or {})))
            raise httpx.ConnectError("connection refused")
        return super().call(method, path, params)

    refuse_connect = False


@pytest.mark.parametrize("how", ["never-sent", "answered"])
def test_an_attempt_that_provably_did_not_land_may_be_tried_again(plane, monkeypatch, how):
    api = NeverConnects()
    monkeypatch.setattr(engine, "_client", lambda p, c=None: api)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref = out["undo"]["id"]
    if how == "never-sent":
        api.refuse_connect = True
    else:
        api.fail_on = "/rollback"
    with pytest.raises(Exception):  # noqa: B017,PT011
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    err = [r for r in _rows() if r["action"] == "core.error" and r["detail"].get("restores")][-1]
    assert err["detail"]["delivery"] == how
    api.refuse_connect, api.fail_on = False, None
    assert undo.restore(ref, cfg=plane("pve"), confirm=True)["restores"] == ref


def test_delivery_is_read_from_the_exception_alone():
    d = engine._delivery
    req = httpx.Request("POST", "https://pve.invalid/x")
    assert d(httpx.HTTPStatusError("x", request=req, response=httpx.Response(500, request=req))) == "answered"
    assert d(httpx.ConnectError("x")) == d(httpx.ConnectTimeout("x")) == d(httpx.PoolTimeout("x")) == "never-sent"
    for unknown in (httpx.ReadTimeout("x"), httpx.WriteTimeout("x"), httpx.ReadError("x"),
                    httpx.RemoteProtocolError("x"), RuntimeError("x"), OSError("x"), httpx.TimeoutException("x")):
        assert d(unknown) == "unknown", type(unknown).__name__


# --- L6-1: a safety snapshot that fails after the spend ----------------------------------------------------

def test_a_failed_safety_snapshot_keeps_the_grant_spent_and_gives_the_rollbacks_slot_back(plane, monkeypatch, grants):
    monkeypatch.setenv("PROXIMO_RATE_MAX", "3")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    api = _wire(monkeypatch, exitstatus="ERROR")
    grant = _grant(grants, _plan(plane, "pve", "qemu", PVE_QEMU)["consent_id"])
    with pytest.raises(ProximoError, match="did not land") as caught:
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    said = str(caught.value)
    assert not _rollbacks(api, PVE_QEMU)                                            # the act was never dialled
    assert any(r["action"] == "core.consent_spent" for r in _rows()) and not grant.exists()   # something was sent
    assert "was SENT, named proximo_" in said and "may have" in said or "if the vendor created it anyway" in said
    assert "approval for this call is spent" in said and "Nothing was sent" not in said
    assert _slots_free(plane("pve")) == 2          # 3 - the snapshot's slot; the rollback's own went back
    assert ledger.in_flight(_rows()) == []


def test_a_sent_snapshot_whose_refusal_cannot_be_written_keeps_the_snapshots_slot(plane, monkeypatch, grants):
    """An error that does not SAY the snapshot was unsent keeps its slot: the request went out."""
    monkeypatch.setenv("PROXIMO_RATE_MAX", "3")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    _wire(monkeypatch, exitstatus="ERROR")
    _grant(grants, _plan(plane, "pve", "qemu", PVE_QEMU)["consent_id"])
    real = engine._record

    def unwritable(cfg, action, *a, **kw):
        if action == "core.refuse" and (kw.get("detail") or {}).get("needs") == "undo":
            raise OSError("ledger unwritable")
        return real(cfg, action, *a, **kw)
    monkeypatch.setattr(engine, "_record", unwritable)
    with pytest.raises(OSError):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert _slots_free(plane("pve")) == 2          # the sent snapshot's slot stays spent


def test_a_safety_snapshot_refused_before_the_wire_gives_both_slots_back_and_says_nothing_was_sent(
        plane, monkeypatch, grants):
    monkeypatch.setenv("PROXIMO_RATE_MAX", "3")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    api = _wire(monkeypatch)
    _grant(grants, _plan(plane, "pve", "qemu", PVE_QEMU)["consent_id"])
    real = engine.execute

    def wall(row, args=None, **kw):                 # a wall that appeared between the check and the snapshot's govern
        if kw.get("net_of") is not None:
            raise ProximoError("a wall in front of the snapshot")
        return real(row, args, **kw)
    monkeypatch.setattr(engine, "execute", wall)
    with pytest.raises(ProximoError) as caught:
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    said = str(caught.value)
    assert "Nothing was sent to the vendor" in said and "approval for this call is spent" in said
    assert _posts(api) == [] and _slots_free(plane("pve")) == 3


# --- L6-3: a direct rollback through another plane closes the capture too --------------------------------

def test_a_direct_pve_rollback_to_a_pdm_captures_snapshot_closes_it(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pdm", "qemu", PDM_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    engine.execute(engine.table()[ROLLBACK_ROW], {}, cfg=plane("pve"), path=_paths(PVE_QEMU, snap)[1])
    with pytest.raises(ProximoError, match="already rolled back"):
        undo.restore(ref, cfg=plane("pdm"), confirm=True)
    assert len([p for p in _posts(api) if p.endswith(f"/snapshot/{snap}/rollback")]) == 1


def test_a_rollback_to_another_guests_snapshot_of_the_same_name_does_not_close_it(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    other = "/nodes/pve1/qemu/101"
    api.snaps.append(snap)
    engine.execute(engine.table()[ROLLBACK_ROW], {}, cfg=plane("pve"), path=_paths(other, snap)[1])
    assert undo.restore(ref, cfg=plane("pve"), confirm=True)["restores"] == ref           # a different guest


# --- L6-4: refusals of the lock and the once-guard are receipted ------------------------------------------------

def _full(ref):
    return next(r["entry_hash"] for r in _rows() if str(r.get("entry_hash", "")).startswith(ref))


def test_a_lock_wait_refusal_is_receipted(plane, monkeypatch):
    _wire(monkeypatch)
    ref = _rollback(plane, "pve", "qemu", PVE_QEMU)["undo"]["id"]
    d = os.path.join(engine._audit_dir(None), ".proximo-undo")
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(d, f"{_full(ref)}.lock"), os.O_RDWR | os.O_CREAT)
    fcntl.flock(fd, fcntl.LOCK_EX)
    monkeypatch.setattr(undo, "UNDO_LOCK_WAIT", 0.1)
    before = len(_rows())
    try:
        with pytest.raises(ProximoError, match="still running"):
            undo.restore(ref, cfg=plane("pve"), confirm=True)
    finally:
        os.close(fd)
    refuse = [r for r in _rows()[before:] if r["action"] == "core.refuse"]
    assert refuse and refuse[-1]["detail"]["restores"] == _full(ref)
    assert "still running" in refuse[-1]["detail"]["reason"]


def test_a_once_refusal_is_receipted_in_the_plan_and_the_confirm(plane, monkeypatch):
    _wire(monkeypatch)
    ref = _rollback(plane, "pve", "qemu", PVE_QEMU)["undo"]["id"]
    undo.restore(ref, cfg=plane("pve"), confirm=True)
    for confirm in (False, True):
        before = len(_rows())
        with pytest.raises(ProximoError, match="already rolled back"):
            undo.restore(ref, cfg=plane("pve"), confirm=confirm)
        refuse = [r for r in _rows()[before:] if r["action"] == "core.refuse"]
        assert refuse and refuse[-1]["detail"]["needs"] == "undo" and refuse[-1]["detail"]["restores"] == _full(ref)


def test_an_unusable_lock_dir_refuses_with_a_receipt(plane, monkeypatch):
    _wire(monkeypatch)
    ref = _rollback(plane, "pve", "qemu", PVE_QEMU)["undo"]["id"]
    with open(os.path.join(engine._audit_dir(None), ".proximo-undo"), "w", encoding="utf-8") as f:
        f.write("x")                                  # a FILE where the directory goes
    before = len(_rows())
    with pytest.raises(ProximoError, match="undo lock"):
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    assert any(r["action"] == "core.refuse" for r in _rows()[before:])


@pytest.mark.parametrize("mode", [0o777, 0o770, 0o707, 0o722])
def test_a_lock_directory_others_can_write_is_refused_not_used(plane, monkeypatch, mode):
    _wire(monkeypatch)
    ref = _rollback(plane, "pve", "qemu", PVE_QEMU)["undo"]["id"]
    d = os.path.join(engine._audit_dir(None), ".proximo-undo")
    os.makedirs(d)
    os.chmod(d, mode)
    with pytest.raises(ProximoError, match="undo lock"):
        undo.restore(ref, cfg=plane("pve"), confirm=True)


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs a second owner (root can give one)")
def test_a_lock_directory_somebody_else_owns_is_refused(plane, monkeypatch):
    _wire(monkeypatch)
    ref = _rollback(plane, "pve", "qemu", PVE_QEMU)["undo"]["id"]
    d = os.path.join(engine._audit_dir(None), ".proximo-undo")
    os.makedirs(d, mode=0o700)
    os.chown(d, 12345, 12345)
    with pytest.raises(ProximoError, match="undo lock"):
        undo.restore(ref, cfg=plane("pve"), confirm=True)


# --- A7: a direct rollback lands while an undo waits for the lock ---------------------------------------------

def test_an_undo_waiting_for_the_lock_sees_a_direct_rollback_that_landed_meanwhile(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref, snap = out["undo"]["id"], out["undo"]["snapshot"]
    lcfg = ledger.LedgerConfig.from_env()
    seen: list[str] = []

    def attempt():
        try:
            undo.restore(ref, cfg=plane("pve"), confirm=True)
            seen.append("ran")
        except ProximoError as exc:
            seen.append("refused: " + str(exc)[:40])
    with undo._once_lock(lcfg, _full(ref)):
        waiter = threading.Thread(target=attempt)
        waiter.start()
        _time.sleep(0.3)                          # it passed the outer check and is now waiting at the lock
        engine.execute(engine.table()[ROLLBACK_ROW], {}, cfg=plane("pve"), path=_paths(PVE_QEMU, snap)[1])
    waiter.join()
    assert len(seen) == 1 and seen[0].startswith("refused: capture")
    assert len(_rollbacks(api, PVE_QEMU, snap)) == 1


# --- L6-6: a slot lives as long as ITS window --------------------------------------------------------------------

def test_a_shorter_window_caller_does_not_erase_a_longer_window_callers_slots(tmp_path, monkeypatch):
    base = "https://pve.invalid:8006/api2/json"
    t = [1_000_000.0]
    monkeypatch.setattr(spine.time, "time", lambda: t[0])
    monkeypatch.delenv("PROXIMO_RATE_MAX", raising=False)
    monkeypatch.delenv("PROXIMO_RATE_WINDOW", raising=False)
    hourly, minute = (3, 3600), (100, 60)
    for _ in range(3):
        assert spine.reserve_rate(base, str(tmp_path), cap=hourly) is None
    assert spine.reserve_rate(base, str(tmp_path), cap=hourly) is not None
    t[0] += 120
    assert spine.reserve_rate(base, str(tmp_path), cap=minute) is None          # the other caller writes the file
    t[0] += 1
    assert spine.reserve_rate(base, str(tmp_path), cap=hourly) is not None      # the hourly budget is still full
    t[0] += 3600
    assert spine.reserve_rate(base, str(tmp_path), cap=hourly) is None          # and expires with ITS window


def test_a_line_from_before_windows_were_stored_takes_the_readers_window(tmp_path, monkeypatch):
    base = "https://pve.invalid:8006/api2/json"
    monkeypatch.setattr(spine.time, "time", lambda: 5_000.0)
    d = tmp_path / spine._RESERVATION_SUBDIR
    d.mkdir()
    (d / f"{spine._box_key(base)}.rate").write_text("4990.0\n4995.0\n")
    assert spine.reserve_rate(base, str(tmp_path), cap=(2, 60)) is not None     # both old slots count, as before
    monkeypatch.setattr(spine.time, "time", lambda: 5_100.0)
    assert spine.reserve_rate(base, str(tmp_path), cap=(2, 60)) is None         # and age out in the reader's window
