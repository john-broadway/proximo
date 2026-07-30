"""ARM — the agnostic write-authority toggle (`proximo arm` / `proximo disarm`).

Mirrors the discipline of test_contain.py / test_lease.py: env-read fresh, no process state, and
the fail direction asserted explicitly at every ambiguous input. Two properties carry the security
weight here and each gets its own block below:

- **The session key is a path component, so it is a path-traversal surface.** `arm` must REFUSE a
  malformed key rather than build the path anyway (an invalid key is a caller bug, and guessing
  could write the write-token somewhere unintended). `disarm` must NOT refuse — it falls back to
  the global token, because refusing to disarm leaves write authority live, which is the one
  outcome the tool exists to prevent.
- **The disclosure must not overclaim.** `boundary_state` reads the arm source's ownership and
  mode; anything that lets a second uid read the write token makes the arm advisory, and the tool
  says so instead of printing a bare "ARMED".
"""

from __future__ import annotations

import os
import stat
import time

import pytest

from proximo.arm import (
    ARM_SOURCE_ENV,
    READONLY_SOURCE_ENV,
    SESSION_DIR_ENV,
    SESSION_KEY_ENV,
    TOKEN_PATH_ENV,
    ArmError,
    ArmResult,
    boundary_state,
    do_arm,
    do_disarm,
    resolve_target,
    valid_session_key,
)

WRITE_TOKEN = "proximo@pve!arm=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"  # noqa: S105 -- test sentinel
RO_TOKEN = "proximo@pve!ro=11111111-2222-3333-4444-555555555555"  # noqa: S105 -- test sentinel


def _stat_reports(monkeypatch, owners):
    """Make `os.stat` report a chosen owner uid for chosen paths; real stat everywhere else.

    `owners` maps a path to the uid stat should report for it. Everything else about the stat
    result stays real — mode, sticky bit, type.

    Why report instead of `os.chown`: chown to another uid needs root, so every ownership test
    below could only ever run privileged, and CI (uid 1001) either failed or would have to skip
    the security verdict entirely. What the code under test reads is `st_uid` and `st_mode`, so
    this double lacks nothing it looks at — the kernel's chown semantics are not what is being
    tested, our verdict logic is.
    """
    real_stat = os.stat
    table = {os.path.realpath(p): uid for p, uid in owners.items()}

    class _Reported:
        def __init__(self, st, uid):
            self._st = st
            self.st_uid = uid

        def __getattr__(self, name):
            return getattr(self._st, name)

    def fake_stat(p, *a, **kw):
        st = real_stat(p, *a, **kw)
        try:
            uid = table.get(os.path.realpath(p))
        except TypeError:          # a file descriptor, never one of our paths
            uid = None
        return _Reported(st, uid) if uid is not None else st

    monkeypatch.setattr(os, "stat", fake_stat)


def _as_root_owner(monkeypatch, path, *, dir_uid=0):
    """Present the REAL-boundary condition at any uid: run as root, over a root-owned file.

    boundary_state asserts a REAL boundary only when the euid is 0 AND the file and its
    directory belong to that euid. The euid-0 half is deliberate, not incidental — a non-root
    arm is a uid the server may share, so the boundary cannot be asserted (pinned by
    test_an_unprivileged_arm_is_advisory_even_at_600). A CI runner is uid 1001 and cannot
    create a root-owned file at all, so the scenario is reported rather than constructed.

    These tests used to just hardcode `geteuid -> 0` and leave ownership real. That passed on a
    root box, where the files happen to be root's too, and failed everywhere else — the code
    was right and the test was environment-dependent.
    """
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    _stat_reports(monkeypatch, {path: 0, os.path.dirname(str(path)): dir_uid})


def _wire(tmp_path, monkeypatch, *, mode=0o600):
    """A minimal agnostic arm environment: a write source, a read-only source, a session dir."""
    src = tmp_path / "operator.token"
    src.write_text(WRITE_TOKEN)
    os.chmod(src, mode)
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
    monkeypatch.delenv(SESSION_KEY_ENV, raising=False)
    return src, ro, sessions, token_path


# ---------------------------------------------------------------- the traversal guard

@pytest.mark.parametrize("key", [
    "../evil", "a/b", "..", ".", "", "  ", "a\x00b", "a\nb", "x" * 129, "/abs", "a/../b",
])
def test_valid_session_key_rejects_unsafe(key):
    assert valid_session_key(key) is False


@pytest.mark.parametrize("key", [
    "ci-7f2a", "e80c5b37-cba0-4bc2-b81d-dcac5e4d57c4", "a", "A_b.c-1", "x" * 128,
])
def test_valid_session_key_accepts_safe(key):
    assert valid_session_key(key) is True


def test_arm_refuses_an_invalid_session_key_and_touches_nothing(tmp_path, monkeypatch):
    _src, _ro, sessions, token_path = _wire(tmp_path, monkeypatch)
    before = token_path.read_text()
    with pytest.raises(ArmError, match="session key"):
        do_arm(session="../escape")
    assert token_path.read_text() == before          # global untouched
    assert list(sessions.iterdir()) == []            # nothing created


def test_disarm_with_an_invalid_key_falls_back_to_global_and_does_not_raise(tmp_path, monkeypatch):
    _src, _ro, _sessions, token_path = _wire(tmp_path, monkeypatch)
    token_path.write_text(WRITE_TOKEN)               # pretend a global arm is live
    result = do_disarm(session="../escape")          # must NOT raise: refusing would leave it armed
    assert result.armed is False
    assert token_path.read_text() == RO_TOKEN


def test_disarm_with_no_key_at_all_restores_the_global(tmp_path, monkeypatch):
    _src, _ro, _sessions, token_path = _wire(tmp_path, monkeypatch)
    token_path.write_text(WRITE_TOKEN)
    result = do_disarm(session=None)
    assert result.armed is False
    assert token_path.read_text() == RO_TOKEN


# ---------------------------------------------------------------- the swap itself

def test_arm_installs_the_write_token_for_one_session_at_600(tmp_path, monkeypatch):
    _src, _ro, sessions, token_path = _wire(tmp_path, monkeypatch)
    result = do_arm(session="ci-7f2a")
    target = sessions / "ci-7f2a.token"
    assert result.armed is True
    assert result.target == str(target)
    assert target.read_text() == WRITE_TOKEN
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert token_path.read_text() == RO_TOKEN        # the GLOBAL token is not collaterally armed


def test_arming_one_session_leaves_a_sibling_session_read_only(tmp_path, monkeypatch):
    _src, _ro, sessions, _token_path = _wire(tmp_path, monkeypatch)
    sibling = sessions / "other.token"
    sibling.write_text(RO_TOKEN)
    do_arm(session="ci-7f2a")
    assert sibling.read_text() == RO_TOKEN


def test_disarm_restores_the_read_only_token_for_that_session_only(tmp_path, monkeypatch):
    _src, _ro, sessions, _token_path = _wire(tmp_path, monkeypatch)
    do_arm(session="ci-7f2a")
    do_arm(session="keep-me")
    result = do_disarm(session="ci-7f2a")
    assert result.armed is False
    assert (sessions / "ci-7f2a.token").read_text() == RO_TOKEN
    assert (sessions / "keep-me.token").read_text() == WRITE_TOKEN


def test_session_key_comes_from_env_when_the_flag_is_absent(tmp_path, monkeypatch):
    _src, _ro, sessions, _token_path = _wire(tmp_path, monkeypatch)
    monkeypatch.setenv(SESSION_KEY_ENV, "from-env")
    result = do_arm(session=None)
    assert result.session == "from-env"
    assert (sessions / "from-env.token").read_text() == WRITE_TOKEN


def test_arm_refuses_a_session_scope_the_config_cannot_honor(tmp_path, monkeypatch):
    """`--session K` with no SESSION_DIR has only the shared token path to write, which would
    arm EVERY caller on the box — broader than what was asked for. Refuse instead of silently
    widening, the same way a PROXIMO_TOOLSETS typo refuses startup."""
    _src, _ro, _sessions, token_path = _wire(tmp_path, monkeypatch)
    monkeypatch.delenv(SESSION_DIR_ENV)
    before = token_path.read_text()
    with pytest.raises(ArmError, match=SESSION_DIR_ENV):
        do_arm(session="ci-7f2a")
    assert token_path.read_text() == before          # nothing armed


def test_arm_with_no_session_at_all_arms_the_global_on_purpose(tmp_path, monkeypatch):
    """Dropping --session is a deliberate global arm, so it proceeds."""
    _src, _ro, _sessions, token_path = _wire(tmp_path, monkeypatch)
    monkeypatch.delenv(SESSION_DIR_ENV)
    result = do_arm(session=None)
    assert result.target == str(token_path)
    assert token_path.read_text() == WRITE_TOKEN
    assert result.global_fallback is False            # intentional, not a fallback


def test_disarm_does_NOT_mirror_that_refusal(tmp_path, monkeypatch):
    """disarm's fallback only ever REMOVES authority, so widening is safe and it must not
    refuse — a refused disarm is the one outcome that leaves write power live."""
    _src, _ro, _sessions, token_path = _wire(tmp_path, monkeypatch)
    monkeypatch.delenv(SESSION_DIR_ENV)
    token_path.write_text(WRITE_TOKEN)
    result = do_disarm(session="ci-7f2a")
    assert result.armed is False
    assert token_path.read_text() == RO_TOKEN
    assert result.global_fallback is True             # and it says so


def test_resolve_target_is_pure_and_composes_dir_and_key(tmp_path, monkeypatch):
    _src, _ro, sessions, token_path = _wire(tmp_path, monkeypatch)
    assert resolve_target("abc") == str(sessions / "abc.token")
    assert resolve_target(None) == str(token_path)


# ---------------------------------------------------------------- fail-closed on bad config

def test_arm_with_a_missing_source_refuses_and_leaves_the_target_alone(tmp_path, monkeypatch):
    _src, _ro, _sessions, token_path = _wire(tmp_path, monkeypatch)
    monkeypatch.setenv(ARM_SOURCE_ENV, str(tmp_path / "nope.token"))
    before = token_path.read_text()
    with pytest.raises(ArmError, match="arm source"):
        do_arm(session=None)
    assert token_path.read_text() == before


def test_arm_with_an_unset_source_env_refuses(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    monkeypatch.delenv(ARM_SOURCE_ENV)
    with pytest.raises(ArmError, match=ARM_SOURCE_ENV):
        do_arm(session=None)


def test_disarm_with_a_missing_readonly_source_refuses_loudly(tmp_path, monkeypatch):
    """The one case disarm MAY refuse: there is no read-only token to restore, so it cannot
    do the safe thing silently. Better a loud error than a false 'DISARMED'."""
    _wire(tmp_path, monkeypatch)
    monkeypatch.setenv(READONLY_SOURCE_ENV, str(tmp_path / "nope.token"))
    with pytest.raises(ArmError, match="read-only source"):
        do_disarm(session=None)


# ---------------------------------------------------------------- the honest disclosure

def test_a_group_readable_arm_source_is_advisory(tmp_path, monkeypatch):
    src, _ro, _s, _t = _wire(tmp_path, monkeypatch, mode=0o640)
    b = boundary_state(str(src))
    assert b.advisory is True
    assert any("group" in r or "other" in r for r in b.reasons)


def test_a_world_readable_arm_source_is_advisory(tmp_path, monkeypatch):
    src, _ro, _s, _t = _wire(tmp_path, monkeypatch, mode=0o604)
    assert boundary_state(str(src)).advisory is True


def test_an_unprivileged_arm_is_advisory_even_at_600(tmp_path, monkeypatch):
    """Running arm as a non-root uid means the uid that can arm is a uid the server may share,
    so the boundary cannot be asserted."""
    src, _ro, _s, _t = _wire(tmp_path, monkeypatch, mode=0o600)
    monkeypatch.setattr(os, "geteuid", lambda: 1001)
    b = boundary_state(str(src))
    assert b.advisory is True
    assert any("uid" in r for r in b.reasons)


def test_an_owner_run_600_source_is_not_advisory(tmp_path, monkeypatch):
    src, _ro, _s, _t = _wire(tmp_path, monkeypatch, mode=0o600)
    _as_root_owner(monkeypatch, src)
    b = boundary_state(str(src))
    assert b.advisory is False
    # It must still name the condition it cannot verify rather than claim a flat guarantee.
    assert b.owner_uid is not None
    assert b.conditional_on is not None


def test_boundary_on_an_unreadable_source_is_advisory_not_a_crash(tmp_path, monkeypatch):
    b = boundary_state(str(tmp_path / "absent.token"))
    assert b.advisory is True


def test_arm_result_carries_the_boundary_so_the_cli_can_print_it(tmp_path, monkeypatch):
    _src, _ro, _s, _t = _wire(tmp_path, monkeypatch, mode=0o640)
    result = do_arm(session="ci-7f2a")
    assert result.boundary is not None
    assert result.boundary.advisory is True


# --- the read-only source is half the trust surface, and it was the unaudited half ---------
#
# boundary_state was called once, on the ARM source. disarm's correctness rests entirely on the
# READ-ONLY source holding read-only bytes, and nothing looked at it. The read-only token is the
# everyday credential — the one most likely to be loosely permissioned, precisely because it is
# "just read-only" — so the audited file was the guarded one and the ignored file was not.

def test_disarm_refuses_when_the_readonly_source_holds_the_write_token(tmp_path, monkeypatch):
    """A false "DISARMED" is the worst outcome this module can produce; refuse instead.

    Substituting the read-only source's bytes made disarm report armed=False while installing the
    WRITE token. Byte-identical sources are exactly detectable, so this is a refusal and not a
    warning: there is no read-only token to restore, the same condition READONLY_SOURCE-unset
    already refuses for.
    """
    src, ro, _s, token_path = _wire(tmp_path, monkeypatch)
    ro.write_text(src.read_text())          # the substitution

    with pytest.raises(ArmError, match="read-only source|write token"):
        do_disarm(session=None)

    # And it must not have installed anything on the way out.
    assert token_path.read_text() == RO_TOKEN


def test_the_refusal_does_not_claim_live_write_authority_when_there_is_none(tmp_path, monkeypatch):
    """REDTEAM: the refusal ended "Write authority is still live until you do." unconditionally.

    It is refused BEFORE installing anything, so what is live depends on what the served token
    already holds. With a genuine read-only token in place the sentence was simply false, and a
    false alarm about live write authority is the same class of lie as a false DISARMED.
    """
    src, ro, _s, token_path = _wire(tmp_path, monkeypatch)
    ro.write_text(src.read_text())          # substituted read-only source
    token_path.write_text(RO_TOKEN)         # ... but the SERVED token is genuinely read-only

    with pytest.raises(ArmError) as exc:
        do_disarm(session=None)
    assert "Write authority is live" not in str(exc.value), str(exc.value)


def test_the_refusal_does_say_write_authority_is_live_when_it_is(tmp_path, monkeypatch):
    src, ro, _s, token_path = _wire(tmp_path, monkeypatch)
    ro.write_text(src.read_text())
    token_path.write_text(WRITE_TOKEN)      # the served token IS the write token

    with pytest.raises(ArmError) as exc:
        do_disarm(session=None)
    assert "Write authority is live" in str(exc.value), str(exc.value)


def test_disarm_still_works_when_the_arm_source_is_unreadable(tmp_path, monkeypatch):
    """The identical-bytes check must never become a reason a disarm cannot happen.

    If the arm source cannot be read there is nothing to compare against, and refusing would
    leave write authority live — the one direction disarm never takes.
    """
    src, _ro, _s, token_path = _wire(tmp_path, monkeypatch)
    token_path.write_text(WRITE_TOKEN)      # currently armed
    src.unlink()                            # arm source gone

    result = do_disarm(session=None)
    assert result.armed is False
    assert token_path.read_text() == RO_TOKEN


def test_disarm_carries_a_boundary_for_the_readonly_source(tmp_path, monkeypatch):
    """The disclosure has to cover the file disarm actually depends on."""
    _src, ro, _s, _t = _wire(tmp_path, monkeypatch)
    os.chmod(ro, 0o646)  # noqa: S103 -- the insecure mode IS the fixture: group/other writable
    result = do_disarm(session=None)
    assert result.boundary is not None
    assert result.boundary.advisory is True
    assert any("writ" in r for r in result.boundary.reasons), result.boundary.reasons


def test_a_garbled_ttl_is_not_reported_as_no_expiry(tmp_path, monkeypatch):
    """arm's output must not contradict lease's enforcement.

    lease.lease_state() on a garbled PROXIMO_ARM_TTL returns enforced=True, expired=True — correct,
    fail-closed. arm's own parse returned None for BOTH unset and garbled, so the render said
    "PROXIMO_ARM_TTL unset — no auto-expiry" about an arm that is already dead. The operator then
    watches every mutation refuse as expired with nothing explaining why.
    """
    from proximo.arm import render_text
    _wire(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_ARM_TTL", "5 minutes")   # garbled: not an int

    out = render_text(do_arm(session=None))
    # Assert on the false CLAIM, not on the word "unset" — the corrected message says "or unset
    # it" as the remedy, so a bare substring check would fail on correct output.
    assert "unset — no auto-expiry" not in out, out
    assert "EXPIRED" in out, out


def test_an_unset_ttl_still_reports_no_auto_expiry(tmp_path, monkeypatch):
    """The honest case must keep saying the thing that makes a forgotten arm visible."""
    from proximo.arm import render_text
    _wire(tmp_path, monkeypatch)
    monkeypatch.delenv("PROXIMO_ARM_TTL", raising=False)

    out = render_text(do_arm(session=None))
    assert "no auto-expiry" in out


def test_a_merely_readable_readonly_source_is_not_advisory(tmp_path, monkeypatch):
    """The two sources have different threat models, so they must not share one reason set.

    For the WRITE source, readability is the whole problem: a second uid copies write authority.
    For the READ-ONLY source it is the normal case (it is the everyday credential) and grants
    nobody anything. Only SUBSTITUTABILITY matters there. Reporting ADVISORY on a 644 read-only
    token, with the reason "a second uid can copy the write token", is a false alarm about the
    wrong file — and false alarms are how a disclosure gets trained into background noise.
    """
    _src, ro, _s, _t = _wire(tmp_path, monkeypatch)
    _as_root_owner(monkeypatch, ro)
    os.chmod(ro, 0o644)  # noqa: S103 -- readable, NOT writable: the ordinary everyday credential

    result = do_disarm(session=None)
    assert result.boundary is not None
    assert result.boundary.advisory is False, result.boundary.reasons


def test_the_readonly_boundary_never_claims_the_write_token_can_be_copied(tmp_path, monkeypatch):
    _src, ro, _s, _t = _wire(tmp_path, monkeypatch)
    _as_root_owner(monkeypatch, ro)
    os.chmod(ro, 0o646)  # noqa: S103 -- writable: a real substitution surface

    b = do_disarm(session=None).boundary
    assert b is not None and b.advisory is True
    assert any("substitut" in r for r in b.reasons), b.reasons
    assert not any("copy the write token" in r for r in b.reasons), b.reasons


# --- ownership, not just permission bits ---------------------------------------------------
#
# REDTEAM 2026-07-29: boundary_state judged the mode bits and the euid and reported
# advisory=False for a mode-400 file OWNED BY uid 65534, inside a directory OWNED BY uid 65534.
# That uid can rewrite the file and can unlink/replace the directory entry, so the boundary was
# not real and the tool said it was. Permission bits do not bound the OWNER.

def test_a_source_owned_by_another_uid_is_advisory(tmp_path, monkeypatch):
    src, _ro, _s, _t = _wire(tmp_path, monkeypatch, mode=0o600)
    # stat REPORTS a foreign owner rather than os.chown giving it one: chown needs root, and
    # this property (foreign owner => advisory) holds at any uid.
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    _stat_reports(monkeypatch, {src: 65534, os.path.dirname(str(src)): 0})

    b = boundary_state(str(src))
    assert b.advisory is True, b
    assert any("own" in r for r in b.reasons), b.reasons


def test_a_directory_owned_by_another_uid_is_advisory(tmp_path, monkeypatch):
    """Whoever owns the directory can replace the entry, whatever the file's own mode says."""
    src, _ro, _s, _t = _wire(tmp_path, monkeypatch, mode=0o600)
    holder = tmp_path / "theirs"
    holder.mkdir()
    moved = holder / "operator.token"
    moved.write_text(src.read_text())
    os.chmod(moved, 0o600)
    # The FILE reports root's (so the file branch passes) and only the DIRECTORY is foreign,
    # which is what isolates this to the directory branch.
    _as_root_owner(monkeypatch, moved, dir_uid=65534)

    b = boundary_state(str(moved))
    assert b.advisory is True, b
    assert any("director" in r for r in b.reasons), b.reasons


def test_the_real_verdict_states_the_mode_it_actually_saw(tmp_path, monkeypatch):
    """The REAL sentence said "is 600" and "owned by this uid" without checking either."""
    from proximo.arm import render_text
    src, _ro, _s, token_path = _wire(tmp_path, monkeypatch, mode=0o400)
    _as_root_owner(monkeypatch, src)

    b = boundary_state(str(src))
    assert b.advisory is False, b.reasons          # 400 root-owned in a root dir IS real
    out = render_text(ArmResult(armed=True, target=str(token_path), session=None, boundary=b))
    assert "is 600" not in out, out
    assert "0o400" in out or "400" in out, out


def test_a_writable_directory_makes_the_boundary_advisory(tmp_path, monkeypatch):
    """Substitution, not just reading, is the threat: a 600 file in a 777 dir is replaceable.

    boundary_state checked the file's own mode and the euid, never the containing directory's, so
    it reported a real boundary for a source any second uid could unlink and rewrite.
    """
    src, _ro, _s, _t = _wire(tmp_path, monkeypatch, mode=0o600)
    _as_root_owner(monkeypatch, src)
    holder = tmp_path / "loose"
    holder.mkdir()
    os.chmod(holder, 0o777)  # noqa: S103 -- a world-writable dir is the substitution surface
    moved = holder / "operator.token"
    moved.write_text(src.read_text())
    os.chmod(moved, 0o600)

    b = boundary_state(str(moved))
    assert b.advisory is True
    assert any("director" in r for r in b.reasons), b.reasons


# ---------------------------------------------------------------- composition with LEASE

def test_arm_stamps_a_fresh_mtime_so_lease_reads_it_as_just_armed(tmp_path, monkeypatch):
    """lease.py measures arm-age from the token file's mtime, so the swap MUST stamp now --
    a preserved (older) mtime would make a fresh arm look already-expired."""
    _src, _ro, sessions, _t = _wire(tmp_path, monkeypatch)
    old = time.time() - 86400
    target = sessions / "ci-7f2a.token"
    target.write_text(RO_TOKEN)
    os.utime(target, (old, old))
    do_arm(session="ci-7f2a")
    assert time.time() - target.stat().st_mtime < 60


def test_arm_reports_the_lease_ttl_when_the_operator_set_one(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_ARM_TTL", "3600")
    result = do_arm(session="ci-7f2a")
    assert result.lease_ttl == 3600


def test_arm_reports_no_lease_when_unset(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    monkeypatch.delenv("PROXIMO_ARM_TTL", raising=False)
    result = do_arm(session="ci-7f2a")
    assert result.lease_ttl is None


# ---------------------------------------------------------------- the CLI dispatch

@pytest.mark.parametrize("verb", ["arm", "disarm"])
def test_main_dispatches_the_subcommand(tmp_path, monkeypatch, capsys, verb):
    """The dispatch block sits between `mint` and `hello` in main(); a reorder or a bad merge
    could drop it silently, leaving `proximo arm` to fall through and start the stdio server.
    PROXIMO_ENV_FILE is pointed at nothing so main()'s load_env_file cannot pull real config in.
    """
    import proximo.server as server
    _src, _ro, sessions, _token_path = _wire(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_ENV_FILE", str(tmp_path / "absent.env"))
    monkeypatch.setattr("sys.argv", ["proximo", verb, "--session", "ci-7f2a"])
    server.main()
    out = capsys.readouterr().out
    assert ("ARMED" if verb == "arm" else "DISARMED") in out
    assert (sessions / "ci-7f2a.token").exists()


def test_main_arm_exits_2_on_a_refusal(tmp_path, monkeypatch, capsys):
    import proximo.server as server
    _wire(tmp_path, monkeypatch)
    monkeypatch.setenv("PROXIMO_ENV_FILE", str(tmp_path / "absent.env"))
    monkeypatch.setattr("sys.argv", ["proximo", "arm", "--session", "../escape"])
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 2
    assert "session key" in capsys.readouterr().err


def test_as_dict_boundary_carries_dir_owner_uid_like_the_text_render(tmp_path, monkeypatch):
    """dir_owner_uid is part of the verdict, not decoration — the dataclass says so and
    render_text prints it — so the --json mirror must carry it too, not bury it in the
    reasons prose a consumer would have to regex (ultra review 2026-07-30)."""
    from proximo.arm import as_dict

    _src, _ro, _s, _t = _wire(tmp_path, monkeypatch, mode=0o640)
    result = do_arm(session="ci-7f2a")
    assert result.boundary is not None
    payload = as_dict(result)
    assert "dir_owner_uid" in payload["boundary"]
    assert payload["boundary"]["dir_owner_uid"] == result.boundary.dir_owner_uid
