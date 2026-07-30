"""ARM — the write-authority toggle: swap the token the server reads, optionally per session.

The everyday token is read-only; `arm` installs a pre-minted **write** token at the path the
server reads per call, and `disarm` puts the read-only one back. This is the mechanical half of
the arm pattern SECURITY.md documents ("Scoping the token", point 3). It is deliberately NOT the
mint-and-revoke half: in that stronger deployment no write token exists at rest, so there is
nothing here to swap and `proximo mint --write` prints the root-on-Proxmox recipe instead.

**Agnostic by construction.** The session key arrives as an explicit ``--session`` argument or
``PROXIMO_SESSION_KEY``, never by sniffing a client's environment. An earlier in-house version of
this tool keyed per-session state on one specific agent harness's session-id variable and proved
liveness by stat-ing that harness's transcript files; both are invisible to every other client, so
neither could ship. Everything here is stdlib-only and reads its whole world from env, on purpose:
this module imports nothing else from ``proximo`` so it stays cheap to import and to test.

**It grants no capability the caller did not already have.** Anyone who can run `arm` can already
read the arm source and `cp` it into place; this is ergonomics over that fact, not a new door. What
the tool adds is the *disclosure*: whether the arm is a real boundary or merely advisory is a
question of file ownership, so `boundary_state` reads the ownership and says which one you have,
the same honesty SECURITY.md applies to the CONTAIN breaker ("if it points inside the agent's own
writable home the breaker is advisory: a compromised agent clears it").

Three fail directions, each chosen deliberately:

- **`arm` fails CLOSED on a malformed session key.** The key becomes a path component, so a
  garbled one is a traversal surface; refusing beats guessing where to put a write token.
- **`disarm` NEVER refuses over a malformed key** — it falls back to the global token path.
  Refusing to disarm is the one outcome that leaves write authority live, so every ambiguous
  input resolves toward read-only. (It *does* refuse loudly when there is no read-only token to
  restore, because there it cannot do the safe thing at all and a false "DISARMED" would be worse.)
- **The swap stamps a fresh mtime.** ``lease.py`` measures arm-age from the token file's mtime, so
  a preserved (older) stamp would make a brand-new arm read as already-expired.
"""

from __future__ import annotations

import fcntl
import os
import stat
import string
import tempfile
import time
from dataclasses import dataclass

ARM_SOURCE_ENV = "PROXIMO_ARM_SOURCE"  # noqa: S105 -- env var NAME, not a secret value
READONLY_SOURCE_ENV = "PROXIMO_READONLY_SOURCE"  # noqa: S105 -- env var NAME
SESSION_DIR_ENV = "PROXIMO_SESSION_DIR"
SESSION_KEY_ENV = "PROXIMO_SESSION_KEY"
TOKEN_PATH_ENV = "PROXIMO_TOKEN_PATH"  # noqa: S105 -- env var NAME; shared with lease.py
LEASE_ENV = "PROXIMO_ARM_TTL"
REAP_GRACE_ENV = "PROXIMO_REAP_GRACE"

_KEY_MAX = 128
_KEY_ALLOWED = frozenset(string.ascii_letters + string.digits + "._-")

TOKEN_SUFFIX = ".token"  # noqa: S105 -- filename suffix, not a secret
LOCK_SUFFIX = ".lock"
#: Seconds an arm is protected from reaping purely because it is new. This is a STARTUP-RACE
#: guard, not a TTL: between `arm` and the server taking its lock nobody holds it, so without a
#: window the reaper would cut an arm that is seconds old and about to be picked up. It expires
#: nothing on its own — that is LEASE's job (`PROXIMO_ARM_TTL`).
REAP_GRACE_DEFAULT = 300

#: Lock fds held for this process's lifetime. Module-global so they are never garbage-collected:
#: closing an fd releases its flock, which would make a live session look dead to the reaper.
_HELD_LOCKS: list[int] = []


class ArmError(Exception):
    """A refusal from `arm`/`disarm`. Carries an operator-facing message, never a secret."""


@dataclass(frozen=True)
class Boundary:
    """Whether an arm at this source is a real boundary, and why not when it isn't.

    ``advisory`` — a second uid can read the write token, so the arm restrains nobody who already
    has shell in that uid. ``conditional_on`` is set only in the non-advisory case: the tool can
    verify the file's protection but cannot see what uid the *server* runs as, so it names that
    remaining condition rather than claiming a flat guarantee.
    """

    advisory: bool
    reasons: tuple[str, ...] = ()
    owner_uid: int | None = None
    mode: int | None = None
    #: Owner of the directory holding the source. Whoever owns it can unlink and replace the
    #: entry regardless of the file's own mode, so it is part of the verdict, not decoration.
    dir_owner_uid: int | None = None
    conditional_on: str | None = None


@dataclass(frozen=True)
class ArmResult:
    """The outcome of one arm/disarm, shaped for both `render_text` and `--json`."""

    armed: bool
    target: str
    session: str | None
    boundary: Boundary | None = None
    lease_ttl: int | None = None
    #: The operator set LEASE_ENV to something unparseable. lease.py fails CLOSED on that, so the
    #: arm is already expired; a bare `lease_ttl is None` cannot be told from "no lease wanted".
    lease_garbled: bool = False
    global_fallback: bool = False


def valid_session_key(key: object) -> bool:
    """True iff ``key`` is safe to use as a single filename component.

    Conservative allowlist (letters, digits, dot, underscore, hyphen; 1-128 chars) with ``.`` and
    ``..`` excluded outright. An allowlist rather than a blocklist because this value is
    concatenated into a filesystem path: the failure mode of a missed blocklist entry is writing
    the *write* token somewhere unintended.
    """
    if not isinstance(key, str) or not key or len(key) > _KEY_MAX:
        return False
    if key in (".", ".."):
        return False
    return all(c in _KEY_ALLOWED for c in key)


def boundary_state(source: str, *, role: str = "write") -> Boundary:
    """Read a token source's protection and report whether the boundary is real or advisory.

    ``role`` picks the threat model, because the two sources do NOT share one:

    - ``"write"`` (the arm source) — **readability** is the whole problem. A second uid that can
      read it copies write authority without arming.
    - ``"readonly"`` (the read-only source) — readability is the ordinary case and grants nobody
      anything; it IS the everyday credential. Only **substitutability** matters: whoever can
      rewrite it chooses what `disarm` installs, which is how a reported "DISARMED" leaves write
      authority live.

    Sharing one reason set across both meant a 644 read-only token reported ADVISORY because "a
    second uid can copy the write token" — a false alarm naming the wrong file. False alarms are
    how a disclosure gets trained into background noise, so the roles are kept apart.
    """
    is_write = role == "write"
    what = "arm source" if is_write else "read-only source"
    try:
        st = os.stat(source)
    except (OSError, ValueError):
        return Boundary(
            advisory=True,
            reasons=(f"the {what} cannot be read, so its protection cannot be verified",),
        )
    mode = stat.S_IMODE(st.st_mode)
    reasons: list[str] = []
    if is_write and mode & (stat.S_IRGRP | stat.S_IROTH):
        reasons.append(
            "the arm source is readable by group or other, so a second uid can copy the "
            "write token without arming"
        )
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        reasons.append(
            f"the {what} is writable by group or other, so a second uid can substitute the "
            "bytes this tool installs"
        )
    # SUBSTITUTION, not just reading, is a threat here: `arm`/`disarm` copy these bytes into the
    # path the server reads, so whoever can replace the file chooses what gets installed. A mode
    # 600 file in a group/other-writable directory is replaceable by unlink-and-recreate, and
    # checking only the file's own mode reported that as a real boundary. The sticky bit is the
    # exception that makes /tmp-shaped directories safe: with it set, only the file's owner (or the
    # directory's, or root) may unlink, so it is not a substitution surface.
    euid = os.geteuid()
    dir_owner: int | None = None
    # Permission bits do not bound the OWNER. A mode-400 file owned by another uid is fully
    # rewritable BY that uid, and whoever owns the directory can unlink and replace the entry
    # whatever the file's mode says. Judging bits alone reported a nobody-owned token in a
    # nobody-owned directory as a REAL boundary (redteam, 2026-07-29).
    if st.st_uid != euid:
        reasons.append(
            f"the {what} is owned by uid {st.st_uid}, not the uid running this command ({euid}), "
            "so that uid can rewrite it whatever its mode says"
        )
    try:
        dst = os.stat(os.path.dirname(os.path.abspath(source)) or ".")
    except (OSError, ValueError):
        reasons.append(
            f"the directory holding the {what} cannot be read, so it cannot be shown to "
            "prevent substitution"
        )
    else:
        dir_owner = dst.st_uid
        dmode = stat.S_IMODE(dst.st_mode)
        if dmode & (stat.S_IWGRP | stat.S_IWOTH) and not dmode & stat.S_ISVTX:
            reasons.append(
                f"the directory holding the {what} is writable by group or other and is not "
                "sticky, so a second uid can replace the file whatever its own mode says"
            )
        if dst.st_uid != euid:
            reasons.append(
                f"the directory holding the {what} is owned by uid {dst.st_uid}, not the uid "
                f"running this command ({euid}), so that uid can replace the file by unlinking it"
            )
    if euid != 0:
        if is_write:
            reasons.append(
                f"arm is running as uid {euid}, not root, so any process sharing that uid "
                "(possibly the server itself) can re-arm without an operator"
            )
        else:
            reasons.append(
                f"disarm is running as uid {euid}, not root, so any process sharing that uid "
                "can rewrite the read-only source and make a later disarm install write authority"
            )
    if reasons:
        return Boundary(advisory=True, reasons=tuple(reasons), owner_uid=st.st_uid, mode=mode,
                        dir_owner_uid=dir_owner)
    return Boundary(
        advisory=False,
        owner_uid=st.st_uid,
        mode=mode,
        dir_owner_uid=dir_owner,
        # Only the WRITE side carries an unverifiable residual: this tool cannot see what uid the
        # server runs as, and that uid is what decides whether an at-rest write token is reachable.
        # A disarm depends on no such thing — if the read-only source cannot be substituted, the
        # restore is trustworthy — so claiming a condition there would be inventing doubt.
        conditional_on=(f"the server not running as uid {st.st_uid}" if is_write else None),
    )


def resolve_target(session: str | None) -> str:
    """The token path this arm/disarm writes: per-session when both a key and a dir exist."""
    session_dir = os.environ.get(SESSION_DIR_ENV, "").strip()
    if session and session_dir:
        return os.path.join(session_dir, f"{session}.token")
    path = os.environ.get(TOKEN_PATH_ENV, "").strip()
    if not path:
        raise ArmError(
            f"{TOKEN_PATH_ENV} is unset, and no {SESSION_DIR_ENV} + session key was given: "
            "there is nowhere to install the token"
        )
    return path


def _effective_session(session: str | None) -> str | None:
    if session is not None:
        return session
    return os.environ.get(SESSION_KEY_ENV, "").strip() or None


def _lease_ttl() -> int | None:
    raw = os.environ.get(LEASE_ENV, "").strip()
    if not raw:
        return None
    try:
        ttl = int(raw)
    except ValueError:
        return None
    return ttl if ttl > 0 else None


def _lease_garbled() -> bool:
    """True when the operator opted into a lease with a value lease.py cannot parse.

    ``lease.lease_state()`` treats that as enforced-and-EXPIRED (fail-closed, correct). A single
    None from _lease_ttl could not tell that apart from "unset", so the render announced "no
    auto-expiry" about an arm that is already dead on arrival. Kept as a separate read rather than
    importing lease.py: this module deliberately imports nothing else from proximo.
    """
    raw = os.environ.get(LEASE_ENV, "").strip()
    if not raw:
        return False
    try:
        int(raw)
    except ValueError:
        return True
    return False


def _targets_global(session: str | None) -> bool:
    return bool(session) and not os.environ.get(SESSION_DIR_ENV, "").strip()


def _install_atomic(src: str, dst: str) -> None:
    """Copy ``src`` over ``dst`` via temp+rename, mode 600, stamping a fresh mtime.

    The source is read in full BEFORE the destination is touched, so an unreadable source cannot
    leave a truncated token behind. The temp file is created in the destination's own directory so
    ``os.replace`` is a same-filesystem atomic rename: a server reading the token per call sees
    either the old bytes or the new ones, never a partial write.
    """
    with open(src, "rb") as f:
        data = f.read()
    directory = os.path.dirname(os.path.abspath(dst)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tok.", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        os.replace(tmp, dst)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def do_arm(session: str | None = None) -> ArmResult:
    """Install the write token. Fails closed on a malformed key or an unusable arm source."""
    session = _effective_session(session)
    if session is not None and not valid_session_key(session):
        raise ArmError(
            f"refusing to arm: {session!r} is not a valid session key (1-{_KEY_MAX} characters "
            "of letters, digits, dot, underscore or hyphen, and never a path). Refusing rather "
            "than guessing where to put a write token."
        )
    source = os.environ.get(ARM_SOURCE_ENV, "").strip()
    if not source:
        raise ArmError(
            f"{ARM_SOURCE_ENV} is unset: there is no write token to arm from. Mint one with "
            "`proximo mint --write` (root on the Proxmox host), place it out-of-band, and point "
            f"{ARM_SOURCE_ENV} at it."
        )
    if not os.path.isfile(source):
        raise ArmError(f"arm source is missing or not a regular file: {source}")
    if session and not os.environ.get(SESSION_DIR_ENV, "").strip():
        # Asking for a session scope the config cannot honor. Falling back to the global token
        # would arm EVERY caller on this box — broader than what was requested — so refuse
        # instead. Same reasoning as a PROXIMO_TOOLSETS typo refusing startup rather than
        # quietly serving a different set than the operator picked. `disarm` deliberately does
        # NOT mirror this: its fallback only ever REMOVES authority, so broadening is safe there.
        raise ArmError(
            f"refusing to arm: session {session!r} was requested but {SESSION_DIR_ENV} is unset, "
            "so the only place to install the token is the shared "
            f"{TOKEN_PATH_ENV} — which would arm every caller on this box, not just this session. "
            f"Set {SESSION_DIR_ENV} for per-session arms, or drop --session to arm globally on "
            "purpose."
        )
    target = resolve_target(session)
    boundary = boundary_state(source)
    if session:
        # Create the sidecar lock BEFORE installing the token, so an armed session always has a
        # lock file to be judged by. Its ABSENCE is what tells `reap` nobody ever registered as a
        # holder, so the file has to exist for that signal to mean anything. Best-effort: if this
        # fails the arm still proceeds and simply reads as unheld, which is the safe direction.
        try:
            os.close(_open_lock(session_lock_path(session), create=True))
        except (OSError, ValueError, ArmError):
            pass
    _install_atomic(source, target)
    return ArmResult(
        armed=True,
        target=target,
        session=session,
        boundary=boundary,
        lease_ttl=_lease_ttl(),
        lease_garbled=_lease_garbled(),
        # Always False: the refusal above makes a global fallback unreachable when a session
        # was named, and an unnamed session is a deliberate global arm, not a fallback.
        global_fallback=False,
    )


def do_disarm(session: str | None = None) -> ArmResult:
    """Restore the read-only token. Every ambiguous input resolves toward read-only."""
    session = _effective_session(session)
    fell_back = False
    if session is not None and not valid_session_key(session):
        # The safe direction: a garbled key must not become a reason to leave write power live.
        session = None
        fell_back = True
    source = os.environ.get(READONLY_SOURCE_ENV, "").strip()
    if not source:
        raise ArmError(
            f"{READONLY_SOURCE_ENV} is unset: there is no read-only token to restore, so this "
            "cannot disarm. Point it at your everyday read-only credential."
        )
    if not os.path.isfile(source):
        raise ArmError(f"read-only source is missing or not a regular file: {source}")
    target = resolve_target(session)
    _refuse_if_readonly_source_is_the_write_token(source, target)
    _install_atomic(source, target)
    return ArmResult(
        armed=False,
        target=target,
        session=session,
        # The read-only source is the file THIS operation depends on, so it is the one to disclose.
        # Auditing only the arm source left the everyday credential unexamined, and that is the one
        # an operator is likeliest to leave loose, precisely because it is "just read-only".
        boundary=boundary_state(source, role="readonly"),
        global_fallback=fell_back or _targets_global(session),
    )


def _refuse_if_readonly_source_is_the_write_token(ro_source: str, target: str) -> None:
    """Refuse a disarm that would install the WRITE token and report success.

    A false "DISARMED" is the worst outcome this module can produce, and byte-identical sources are
    exactly detectable, so this is a refusal rather than a warning: there is genuinely no read-only
    token to restore, the same condition an unset READONLY_SOURCE already refuses for.

    Only a POSITIVE match refuses. If either file cannot be read there is nothing to compare, and
    refusing on that would leave write authority live — the one direction disarm never takes.
    """
    arm_source = os.environ.get(ARM_SOURCE_ENV, "").strip()
    if not arm_source:
        return
    try:
        with open(arm_source, "rb") as f:
            armed_bytes = f.read()
        with open(ro_source, "rb") as f:
            restore_bytes = f.read()
    except OSError:
        return
    if restore_bytes != armed_bytes:
        return
    # What is live depends on what the SERVED token already holds, because this refuses before
    # installing anything. Claiming live write authority unconditionally was false whenever a
    # genuine read-only token was in place, and a false alarm is the same class of lie as a false
    # all-clear. Unreadable target => say nothing about it rather than guess.
    try:
        with open(target, "rb") as f:
            served_is_armed = f.read() == armed_bytes
    except OSError:
        served_is_armed = False
    tail = (" Write authority is live right now: the served token at that path holds the write "
            "token's bytes." if served_is_armed else
            " Nothing was changed; the served token is whatever it already held.")
    raise ArmError(
        "refusing to disarm: the read-only source is byte-identical to the write token at "
        f"{ARM_SOURCE_ENV}, so restoring it would install write authority and report "
        f"'DISARMED'. Point {READONLY_SOURCE_ENV} at a genuinely read-only credential." + tail
    )


# --------------------------------------------------------------------------- REAP
#
# Liveness is the KERNEL's answer, not a heuristic. A serving process holds a SHARED flock on a
# sidecar lock file for its whole life; the reaper tries an EXCLUSIVE non-blocking lock, which can
# only succeed once every holder is gone — and the kernel releases those on exit, crash or kill
# alike. Nothing here knows or cares what client is driving.
#
# Shared rather than exclusive for the holders, so several servers may serve one session key while
# a single exclusive try still detects "all gone". A SIDECAR file rather than the token itself
# because `arm` installs by `os.replace` and flock binds to the *inode*, so a lock taken on the
# token would survive only until the next swap — the same reason audit.py locks `<log>.lock`
# instead of the log it is protecting.


@dataclass(frozen=True)
class ReapDecision:
    """One session's verdict. ``action`` is reaped | live | read-only | grace | error."""

    session: str
    target: str
    action: str
    reason: str = ""


def session_lock_path(session: str) -> str:
    """The sidecar lock path for a session key. Requires a session dir."""
    session_dir = os.environ.get(SESSION_DIR_ENV, "").strip()
    if not session_dir:
        raise ArmError(f"{SESSION_DIR_ENV} is unset: per-session locks have nowhere to live")
    return os.path.join(session_dir, f"{session}{LOCK_SUFFIX}")


def _open_lock(path: str, *, create: bool) -> int:
    """Open a lock path for flock. ``O_NOFOLLOW`` so a planted symlink cannot redirect the lock
    (and, with O_CREAT, cannot make us create an arbitrary file) — same guard as audit.py."""
    flags = os.O_RDWR | os.O_NOFOLLOW
    if create:
        flags |= os.O_CREAT
    return os.open(path, flags, 0o600)


def hold_session_lock(session: str | None = None) -> str | None:
    """Register this process as a live holder of ``session``'s arm. Returns the lock path, or None.

    Best-effort by contract: locking is a liveness HINT for the reaper, never a gate, so every
    failure returns None instead of raising. It must not be able to break server startup. The
    consequence is bounded and in the safe direction — an unheld arm eventually reads as dead and
    gets disarmed, which costs a re-arm and grants nothing.
    """
    session = _effective_session(session)
    if not session or not valid_session_key(session):
        return None
    try:
        path = session_lock_path(session)
    except ArmError:
        return None
    try:
        fd = _open_lock(path, create=True)
    except (OSError, ValueError):
        return None
    # Non-blocking, with a short bounded retry: a reaper holds the exclusive lock only for the
    # microseconds of its try-and-restore, and giving up on that instant would leave this process
    # unheld for its whole life (so every later reap would cut it).
    for attempt in range(5):
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            if attempt == 4:
                os.close(fd)
                return None
            time.sleep(0.02)
        else:
            _HELD_LOCKS.append(fd)
            return path
    os.close(fd)  # pragma: no cover -- the loop above returns on every path
    return None


def release_session_locks() -> None:
    """Drop every lock this process holds. Normally unnecessary (exit releases them); exists so a
    test or an embedding host can hand the session back without dying."""
    while _HELD_LOCKS:
        fd = _HELD_LOCKS.pop()
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass


def _reap_grace() -> int:
    raw = os.environ.get(REAP_GRACE_ENV, "").strip()
    if not raw:
        return REAP_GRACE_DEFAULT
    try:
        value = int(raw)
    except ValueError:
        # A typo must not silently DISABLE the race guard and start cutting fresh arms.
        return REAP_GRACE_DEFAULT
    return max(0, value)


def _has_live_holder(lock_path: str) -> bool:
    """True only when a holder demonstrably still has the lock.

    Every other outcome is False — including a missing lock file, a permission error, or a
    symlinked path. That direction is deliberate: reaping only ever REMOVES write authority, so a
    wrong "dead" verdict costs one re-arm, while a wrong "live" verdict leaves the write key in
    place indefinitely. It also means a planted symlink cannot be used to keep an arm alive.
    """
    try:
        fd = _open_lock(lock_path, create=False)
    except (OSError, ValueError):
        return False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return True  # somebody holds it
        fcntl.flock(fd, fcntl.LOCK_UN)
        return False
    finally:
        os.close(fd)


def reap_stale_arms(dry_run: bool = False) -> list[ReapDecision]:
    """Restore the read-only token for every session that ended while armed.

    Scans only the session dir — a global arm is the operator's own standing act and has no
    session that could be dead, so it is never touched.
    """
    session_dir = os.environ.get(SESSION_DIR_ENV, "").strip()
    if not session_dir or not os.path.isdir(session_dir):
        return []

    # Armed-ness is decided by comparing bytes against the arm source. Without it there is no
    # verdict to reach, so every session reports error rather than being guessed either way.
    arm_source = os.environ.get(ARM_SOURCE_ENV, "").strip()
    armed_bytes: bytes | None = None
    blocked = ""
    if not arm_source:
        blocked = f"{ARM_SOURCE_ENV} is unset, so armed cannot be told from read-only"
    else:
        try:
            with open(arm_source, "rb") as f:
                armed_bytes = f.read()
        except OSError as exc:
            blocked = f"arm source unreadable ({exc.strerror}), so armed cannot be told apart"

    ro_source = os.environ.get(READONLY_SOURCE_ENV, "").strip()
    grace = _reap_grace()
    now = time.time()
    decisions: list[ReapDecision] = []

    for name in sorted(os.listdir(session_dir)):
        if not name.endswith(TOKEN_SUFFIX):
            continue  # skips the sidecar .lock files, and anything else living here
        session = name[: -len(TOKEN_SUFFIX)]
        target = os.path.join(session_dir, name)
        if blocked:
            decisions.append(ReapDecision(session, target, "error", blocked))
            continue
        try:
            with open(target, "rb") as f:
                current = f.read()
        except OSError as exc:
            decisions.append(ReapDecision(session, target, "error", f"unreadable: {exc.strerror}"))
            continue
        if current != armed_bytes:
            decisions.append(ReapDecision(session, target, "read-only",
                                          "not holding the write token"))
            continue
        try:
            age = int(now - os.stat(target).st_mtime)
        except OSError:
            age = grace + 1  # cannot age it => do not let the grace window shelter it
        if grace and age < grace:
            decisions.append(ReapDecision(
                session, target, "grace",
                f"armed {age}s ago, inside the {grace}s startup-race grace"))
            continue
        try:
            lock_path = session_lock_path(session)
        except ArmError as exc:  # pragma: no cover -- a session dir exists by here
            decisions.append(ReapDecision(session, target, "error", str(exc)))
            continue
        if _has_live_holder(lock_path):
            decisions.append(ReapDecision(session, target, "live",
                                          "a holder still has the lock"))
            continue
        if not ro_source or not os.path.isfile(ro_source):
            decisions.append(ReapDecision(
                session, target, "error",
                f"{READONLY_SOURCE_ENV} is unset or unusable, so there is nothing to restore"))
            continue
        if dry_run:
            decisions.append(ReapDecision(session, target, "reaped",
                                          f"would restore (armed {age}s ago, no holder)"))
            continue
        try:
            _install_atomic(ro_source, target)
        except OSError as exc:
            decisions.append(ReapDecision(session, target, "error",
                                          f"restore failed: {exc.strerror}"))
            continue
        decisions.append(ReapDecision(session, target, "reaped",
                                      f"armed {age}s ago, no holder held the lock"))
    return decisions


def reap_as_dict(decisions: list[ReapDecision], *, dry_run: bool = False) -> dict:
    counts: dict[str, int] = {}
    for d in decisions:
        counts[d.action] = counts.get(d.action, 0) + 1
    return {
        "dry_run": dry_run,
        "scanned": len(decisions),
        "counts": counts,
        "sessions": [{"session": d.session, "action": d.action,
                      "target": d.target, "reason": d.reason} for d in decisions],
    }


def render_reap(decisions: list[ReapDecision], *, dry_run: bool = False) -> str:
    if not decisions:
        return ("proximo reap: no per-session arms to check "
                f"({SESSION_DIR_ENV} unset or empty)")
    icon = {"reaped": "🔒", "live": "▶", "read-only": "·", "grace": "⏳", "error": "⚠️"}
    lines = []
    for d in sorted(decisions, key=lambda x: (x.action != "error", x.action, x.session)):
        verb = "would disarm" if (dry_run and d.action == "reaped") else d.action
        lines.append(f"  {icon.get(d.action, '?')} {d.session}: {verb} — {d.reason}")
    counts: dict[str, int] = {}
    for d in decisions:
        counts[d.action] = counts.get(d.action, 0) + 1
    verb = "would disarm" if dry_run else "disarmed"
    reaped = counts.get("reaped", 0)
    summary = ", ".join(f"{n} {a}" for a, n in sorted(counts.items()))
    head = (f"proximo reap: {verb} {reaped} stale "
            f"{'arm' if reaped == 1 else 'arms'} across {len(decisions)} "
            f"{'session' if len(decisions) == 1 else 'sessions'} — {summary}")
    return "\n".join([head, *lines])


def as_dict(result: ArmResult) -> dict:
    """The `--json` shape. Carries paths and verdicts, never token bytes."""
    payload: dict = {
        "armed": result.armed,
        "target": result.target,
        "session": result.session,
        "lease_ttl_seconds": result.lease_ttl,
        # Without this a consumer sees lease_ttl_seconds: null and cannot tell "no lease wanted"
        # from "lease opted into but unparseable, so LEASE holds this arm expired".
        "lease_garbled": result.lease_garbled,
        "global_fallback": result.global_fallback,
    }
    if result.boundary is not None:
        payload["boundary"] = {
            "advisory": result.boundary.advisory,
            "reasons": list(result.boundary.reasons),
            "owner_uid": result.boundary.owner_uid,
            "dir_owner_uid": result.boundary.dir_owner_uid,
            "mode": None if result.boundary.mode is None else format(result.boundary.mode, "04o"),
            "conditional_on": result.boundary.conditional_on,
        }
    return payload


def render_text(result: ArmResult) -> str:
    """The operator-facing report. States the boundary honestly rather than a bare 'ARMED'."""
    where = f"session {result.session}" if result.session else "global token"
    lines: list[str] = []
    if result.armed:
        lines.append(f"🔓 ARMED  {where}  (write authority live)")
    else:
        lines.append(f"🔒 DISARMED  {where}  (read-only again)")
    lines.append(f"   token: {result.target}")

    if result.armed:
        if result.lease_garbled:
            # Say what the ENFORCING layer will do, not what this parse could not read. lease.py
            # fails closed on an unparseable opt-in, so this arm is expired the moment it lands.
            lines.append(
                f"   lease: {LEASE_ENV} is set to something unparseable, so LEASE treats this arm "
                "as already EXPIRED and mutations will refuse. Set it to a positive number of "
                "seconds, or unset it."
            )
        elif result.lease_ttl is None:
            lines.append(f"   lease: {LEASE_ENV} unset — no auto-expiry; disarm is manual")
        else:
            lines.append(f"   lease: expires in {result.lease_ttl}s ({LEASE_ENV})")

    if result.global_fallback and result.session:
        lines.append(
            f"   note: {SESSION_DIR_ENV} is unset, so this restored the shared "
            f"{TOKEN_PATH_ENV} — every caller on this box is read-only again, not just this session"
        )
    if result.global_fallback and not result.session and not result.armed:
        lines.append("   note: the session key was unusable, so the global token was restored")

    b = result.boundary
    if b is not None:
        # Both operations disclose, but about DIFFERENT files: arm assesses the write source it
        # installs, disarm assesses the read-only source it restores. Saying "arm source" on a
        # disarm would name the wrong file, and the whole point of this block is that the operator
        # can go look at the file being described.
        which = "arm source (the write token)" if result.armed else "read-only source"
        if b.advisory:
            lines.append("")
            lines.append(
                f"   boundary: ADVISORY — the {which} is not protected against a second uid:")
            lines.extend(f"     - {r}" for r in b.reasons)
            if result.armed:
                lines.append(
                    "   For a real boundary: make the arm source root-owned 600 in a directory "
                    "only root can write, and arm from a root context; or use mint-and-revoke "
                    "(`proximo mint --write`) so no write token exists at rest."
                )
            else:
                # The consequence differs, so say the consequence, not a generic warning: a
                # substitutable read-only source is what turns a future disarm into a reported
                # success that leaves write authority live.
                lines.append(
                    "   This one bites on the NEXT disarm: whoever can rewrite that file chooses "
                    "what 'disarm' installs. Make it root-owned 600 in a directory only root can "
                    "write."
                )
        else:
            lines.append("")
            # State the values actually observed, never a prose summary. The old sentence claimed
            # "is 600, owned by this uid, in a directory no second uid can write" without checking
            # any of the three: it printed that for a mode-400 file owned by uid 65534 in a
            # directory owned by uid 65534 (redteam, 2026-07-29).
            observed = f"mode {oct(b.mode)}" if b.mode is not None else "mode unknown"
            if b.owner_uid is not None:
                observed += f", owned by uid {b.owner_uid}"
            if b.dir_owner_uid is not None:
                observed += f", in a directory owned by uid {b.dir_owner_uid}"
            if b.conditional_on:
                lines.append(f"   boundary: REAL, conditional on {b.conditional_on}")
                lines.append(
                    f"   (the {which} is {observed}, and no other uid can read or replace it; this "
                    "tool cannot see what uid the server runs as, so that condition is yours to hold)"
                )
            else:
                lines.append("   boundary: REAL")
                lines.append(
                    f"   (the {which} is {observed}, and no other uid can replace it, so the bytes "
                    "just restored are the ones you put there)"
                )

    if result.armed:
        put_back = "proximo disarm"
        if result.session:
            put_back += f" --session {result.session}"
        lines.append("")
        lines.append(f"   put it back:  {put_back}")
    return "\n".join(lines)
