"""REAP — putting the write key back for sessions that ENDED while armed.

The premise under test is that **the kernel is the liveness oracle**: a server process holds a
shared `flock` on a sidecar lock file for its whole life, so an exclusive non-blocking try
succeeds only once every holder is gone — and the kernel releases those on process death, crash
or kill alike. There is no age heuristic, no heartbeat, and nothing client-specific.

That premise is worth testing for real rather than by mocking `fcntl`, so
`test_a_dead_holders_arm_is_reaped_once_the_process_exits` spawns an actual subprocess, waits for
it to confirm the lock, proves the reaper calls it LIVE, kills it, and proves the same reaper now
reaps. A mocked lock would pass while the real one was inverted.

The fail direction is asymmetric on purpose and pinned below: reaping only ever REMOVES write
authority, so a wrong "dead" verdict costs one re-arm, while a wrong "live" verdict leaks the
write key for as long as the file sits there. Every ambiguous case therefore resolves toward
reaping — except a *fresh* arm, which is protected by the grace window because the gap between
`arm` and the server taking the lock is real.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from proximo.arm import (
    ARM_SOURCE_ENV,
    READONLY_SOURCE_ENV,
    REAP_GRACE_ENV,
    SESSION_DIR_ENV,
    TOKEN_PATH_ENV,
    do_arm,
    hold_session_lock,
    reap_stale_arms,
    release_session_locks,
    session_lock_path,
)

WRITE_TOKEN = "proximo@pve!arm=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"  # noqa: S105 -- test sentinel
RO_TOKEN = "proximo@pve!ro=11111111-2222-3333-4444-555555555555"  # noqa: S105 -- test sentinel

# A child that takes the shared lock, announces it, then waits to be killed.
_HOLDER = """
import os, sys, fcntl, time
lock, ready = sys.argv[1], sys.argv[2]
fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
fcntl.flock(fd, fcntl.LOCK_SH)
open(ready, "w").write("held")
time.sleep(120)
"""


def _wire(tmp_path, monkeypatch, *, grace="0"):
    src = tmp_path / "operator.token"
    src.write_text(WRITE_TOKEN)
    os.chmod(src, 0o600)
    ro = tmp_path / "readonly.token"
    ro.write_text(RO_TOKEN)
    os.chmod(ro, 0o600)
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    token_path = tmp_path / "pve-token"
    token_path.write_text(RO_TOKEN)
    monkeypatch.setenv(ARM_SOURCE_ENV, str(src))
    monkeypatch.setenv(READONLY_SOURCE_ENV, str(ro))
    monkeypatch.setenv(SESSION_DIR_ENV, str(sessions))
    monkeypatch.setenv(TOKEN_PATH_ENV, str(token_path))
    monkeypatch.setenv(REAP_GRACE_ENV, grace)  # 0 = no grace, so age never masks a real verdict
    return src, ro, sessions, token_path


def _age(path, seconds):
    old = time.time() - seconds
    os.utime(path, (old, old))


def _actions(decisions):
    return {d.session: d.action for d in decisions}


def _await_held(ready, timeout=10.0):
    """Block until a holder CONFIRMS its lock, and assert that it did.

    Asserting rather than falling through matters: an earlier version of the multi-holder test
    below merely polled and continued, so when the holders were (wrongly) exclusive the second one
    blocked forever, its confirmation never arrived, and the test still passed — proving nothing
    about the shared semantics it was named for.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ready.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"holder never confirmed its lock ({ready})")


@pytest.fixture(autouse=True)
def _drop_locks():
    """Never leak a held lock into the next test — a stale holder would fake LIVE."""
    yield
    release_session_locks()


# ---------------------------------------------------------------- the premise, for real

def test_a_dead_holders_arm_is_reaped_once_the_process_exits(tmp_path, monkeypatch):
    _src, _ro, sessions, _tp = _wire(tmp_path, monkeypatch)
    do_arm(session="held")
    target = sessions / "held.token"
    assert target.read_text() == WRITE_TOKEN

    ready = tmp_path / "ready"
    child = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", _HOLDER, session_lock_path("held"), str(ready)])
    try:
        _await_held(ready)
        assert _actions(reap_stale_arms())["held"] == "live"
        assert target.read_text() == WRITE_TOKEN   # a live session is NOT disarmed
    finally:
        child.kill()
        child.wait(timeout=10)

    # The holder is gone. Nothing told the reaper — the kernel released the lock on death.
    assert _actions(reap_stale_arms())["held"] == "reaped"
    assert target.read_text() == RO_TOKEN


def test_two_holders_keep_it_live_until_BOTH_are_gone(tmp_path, monkeypatch):
    """Holders take SHARED locks so several servers can serve one session key; the reaper's
    exclusive try must fail while ANY of them survives."""
    _src, _ro, sessions, _tp = _wire(tmp_path, monkeypatch)
    do_arm(session="two")
    lock = session_lock_path("two")
    kids = []
    try:
        for i in range(2):
            ready = tmp_path / f"ready{i}"
            kids.append((subprocess.Popen([sys.executable, "-c", _HOLDER, lock, str(ready)]),  # noqa: S603
                         ready))
        # BOTH must confirm. This is the assertion that makes the test about SHARED locks: if the
        # holders took LOCK_EX instead, the second would block here and never confirm.
        for _, ready in kids:
            _await_held(ready)
        assert _actions(reap_stale_arms())["two"] == "live"
        kids[0][0].kill()
        kids[0][0].wait(timeout=10)
        assert _actions(reap_stale_arms())["two"] == "live"     # one still holds
    finally:
        for kid, _ in kids:
            kid.kill()
            kid.wait(timeout=10)
    assert _actions(reap_stale_arms())["two"] == "reaped"
    assert (sessions / "two.token").read_text() == RO_TOKEN


def test_this_process_own_lock_makes_its_session_live_with_no_self_exclusion(tmp_path, monkeypatch):
    """The old transcript-based reaper needed an explicit `sid == self` special case. With flock
    the in-process holder is just another holder, so no self-exclusion branch exists to get wrong."""
    _src, _ro, _sessions, _tp = _wire(tmp_path, monkeypatch)
    do_arm(session="mine")
    assert hold_session_lock("mine") is not None
    assert _actions(reap_stale_arms())["mine"] == "live"
    release_session_locks()
    assert _actions(reap_stale_arms())["mine"] == "reaped"


# ---------------------------------------------------------------- what it must NOT touch

def test_a_read_only_session_is_left_alone(tmp_path, monkeypatch):
    _src, _ro, sessions, _tp = _wire(tmp_path, monkeypatch)
    (sessions / "cold.token").write_text(RO_TOKEN)
    decisions = reap_stale_arms()
    assert _actions(decisions)["cold"] == "read-only"
    assert (sessions / "cold.token").read_text() == RO_TOKEN


def test_the_global_token_is_never_touched(tmp_path, monkeypatch):
    """The reaper's blast radius is the session dir. A global arm is the operator's own doing
    and has no session to be dead."""
    _src, _ro, _sessions, token_path = _wire(tmp_path, monkeypatch)
    token_path.write_text(WRITE_TOKEN)
    reap_stale_arms()
    assert token_path.read_text() == WRITE_TOKEN


def test_no_session_dir_means_nothing_to_scan(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    monkeypatch.delenv(SESSION_DIR_ENV)
    assert reap_stale_arms() == []


def test_dry_run_decides_without_writing(tmp_path, monkeypatch):
    _src, _ro, sessions, _tp = _wire(tmp_path, monkeypatch)
    do_arm(session="dry")
    decisions = reap_stale_arms(dry_run=True)
    assert _actions(decisions)["dry"] == "reaped"          # the verdict it WOULD reach
    assert (sessions / "dry.token").read_text() == WRITE_TOKEN  # but nothing changed


# ---------------------------------------------------------------- the startup-race grace

def test_a_fresh_arm_is_protected_by_the_grace_window(tmp_path, monkeypatch):
    """Between `arm` and the server taking the lock, NOBODY holds it. Without a grace window the
    reaper would cut an arm that is seconds old and about to be picked up."""
    _src, _ro, sessions, _tp = _wire(tmp_path, monkeypatch, grace="300")
    do_arm(session="fresh")
    assert _actions(reap_stale_arms())["fresh"] == "grace"
    assert (sessions / "fresh.token").read_text() == WRITE_TOKEN


def test_past_the_grace_window_an_unheld_arm_is_reaped(tmp_path, monkeypatch):
    _src, _ro, sessions, _tp = _wire(tmp_path, monkeypatch, grace="300")
    do_arm(session="stale")
    _age(sessions / "stale.token", 3600)
    assert _actions(reap_stale_arms())["stale"] == "reaped"
    assert (sessions / "stale.token").read_text() == RO_TOKEN


def test_a_garbled_grace_falls_back_to_the_default_not_to_zero(tmp_path, monkeypatch):
    """A typo must not silently disable the race guard and start cutting fresh arms."""
    _src, _ro, sessions, _tp = _wire(tmp_path, monkeypatch, grace="not-a-number")
    do_arm(session="fresh")
    assert _actions(reap_stale_arms())["fresh"] == "grace"


# ---------------------------------------------------------------- a missing lock reads as dead

def test_an_armed_token_with_no_lock_file_at_all_is_reaped(tmp_path, monkeypatch):
    """The planted dead-armed session: an arm left by something that never registered a holder.
    This is the exact leak the reaper exists for, so 'no lock file' must read as dead — the
    alternative leaves the write key sitting there forever."""
    _src, _ro, sessions, _tp = _wire(tmp_path, monkeypatch)
    planted = sessions / "planted.token"
    planted.write_text(WRITE_TOKEN)
    _age(planted, 86400)
    assert not os.path.exists(session_lock_path("planted"))
    assert _actions(reap_stale_arms())["planted"] == "reaped"
    assert planted.read_text() == RO_TOKEN


def test_arm_creates_the_lock_file_so_its_absence_means_something(tmp_path, monkeypatch):
    _src, _ro, _sessions, _tp = _wire(tmp_path, monkeypatch)
    do_arm(session="withlock")
    assert os.path.exists(session_lock_path("withlock"))


def test_a_lock_file_is_not_mistaken_for_a_session_token(tmp_path, monkeypatch):
    _src, _ro, sessions, _tp = _wire(tmp_path, monkeypatch)
    do_arm(session="only")
    _age(sessions / "only.token", 3600)
    sessions_seen = {d.session for d in reap_stale_arms()}
    assert sessions_seen == {"only"}          # not {"only", "only.lock"} etc.


# ---------------------------------------------------------------- config failures

def test_reap_without_a_readonly_source_reports_error_and_changes_nothing(tmp_path, monkeypatch):
    """It cannot do the safe thing, so it must not claim to have done it."""
    _src, _ro, sessions, _tp = _wire(tmp_path, monkeypatch)
    do_arm(session="broken")
    _age(sessions / "broken.token", 3600)
    monkeypatch.setenv(READONLY_SOURCE_ENV, str(tmp_path / "absent.token"))
    decisions = reap_stale_arms()
    assert _actions(decisions)["broken"] == "error"
    assert (sessions / "broken.token").read_text() == WRITE_TOKEN


def test_reap_without_an_arm_source_cannot_tell_armed_from_not(tmp_path, monkeypatch):
    """Armed-ness is decided by comparing against the arm source; with none there is no verdict
    to reach, so it reports error rather than guessing in either direction."""
    _src, _ro, sessions, _tp = _wire(tmp_path, monkeypatch)
    do_arm(session="unknown")
    _age(sessions / "unknown.token", 3600)
    monkeypatch.delenv(ARM_SOURCE_ENV)
    decisions = reap_stale_arms()
    assert all(d.action == "error" for d in decisions)
    assert (sessions / "unknown.token").read_text() == WRITE_TOKEN


def test_hold_session_lock_never_raises_on_a_bad_path(tmp_path, monkeypatch):
    """Locking is a liveness HINT for the reaper, never a gate — it must not break startup."""
    _wire(tmp_path, monkeypatch)
    monkeypatch.setenv(SESSION_DIR_ENV, "/proc/nonexistent-dir-for-proximo")
    assert hold_session_lock("x") is None


def test_hold_session_lock_is_a_noop_without_a_session(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    assert hold_session_lock(None) is None


def test_hold_session_lock_refuses_a_malformed_key(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    assert hold_session_lock("../escape") is None
