"""Secret-file permission floor, shared by every loader that reads a secret by path.

One helper, one rule (mirrors ``_tls.py``'s role for TLS parsing): a secret file that
group/other can touch is refused LOUD at config/load time, so a mis-deployed credential
fails before it is ever used. Callers: PVE token + audit HMAC key (``config.py``),
PBS/PMG/PDM credentials (``pbs.py`` / ``pmg.py`` / ``pdm.py``), and the network faces'
bearer tokens + A2A signing key (``webguard.py`` / ``a2a/app.py``).
"""

from __future__ import annotations

import os
import re
import threading

# --- The output scrubber ------------------------------------------------------------------------
# Every secret Proximo reads by path is registered here at read time (read_secret), and any text
# that leaves the process through an exception is passed through redact(): ProximoError scrubs
# its own message (backends.py) and targets.target_aware scrubs the args of whatever else a plane
# tool raises. Shapes cover the four auth headers Proximo itself sends, so a header that was
# never registered (an httpx error echoing a request) still scrubs. Floor: values shorter than
# _MIN_SECRET_LEN are not registered — a one-character secret would shred every message it
# happened to occur in (a rival's shipped incident, 2026); the header shapes still cover them.
_MIN_SECRET_LEN = 8
_REDACTED = "<redacted>"
_lock = threading.Lock()
_registered: set[str] = set()
_SHAPES = (
    re.compile(r"(PVEAPIToken=)\S+"),
    re.compile(r"(PBSAPIToken=)\S+"),
    re.compile(r"(PDMAPIToken )\S+"),
    re.compile(r"(Bearer )\S+"),
)


def register_secret(value: str | None) -> None:
    """Register a literal so redact() hides it. Empty and short values are ignored (see floor)."""
    if not value or len(value) < _MIN_SECRET_LEN:
        return
    with _lock:
        _registered.add(value)


def registered_count() -> int:
    return len(_registered)


def clear_registered_secrets() -> None:
    """Test seam only: the registry is process-wide and never cleared in production."""
    with _lock:
        _registered.clear()


def redact(text: str) -> str:
    """Hide every registered literal and every auth-header shape in `text`. Longest literal first,
    so a whole token line goes before the secret half it contains."""
    if not text:
        return text
    with _lock:
        literals = sorted(_registered, key=len, reverse=True)
    for lit in literals:
        if lit in text:
            text = text.replace(lit, _REDACTED)
    for shape in _SHAPES:
        text = shape.sub(lambda m: m.group(1) + _REDACTED, text)
    return text


def read_secret(path: str, what: str, *, floor: bool = False) -> str:
    """Read a secret file, strip it, and register it — the whole line and, for a
    `USER@REALM!ID=SECRET` / `ID:SECRET` token line, the secret half on its own, since an error can
    carry either. The one read path for every secret Proximo holds by file. The permission floor
    stays where it has always been, at config load (every loader calls refuse_exposed_secret
    before it ever constructs a client); `floor=True` re-runs it here for the callers that check
    per call by design (the audit anchor)."""
    if floor:
        refuse_exposed_secret(path, what)
    with open(path, encoding="utf-8") as f:
        value = f.read().strip()
    register_secret(value)
    for sep in ("=", ":"):
        if sep in value:
            register_secret(value.split(sep, 1)[1])
    return value


def refuse_exposed_secret(path: str, what: str) -> None:
    """Refuse a secret file that group/other can touch (mode & 0o077) — fail LOUD, not silent.

    READ-side floor for secrets referenced by path. Write-side hygiene is already
    0600+O_NOFOLLOW everywhere Proximo *creates* these; this catches the hand-deployed
    file that arrived 0644. Skips: empty path (secret not configured), missing file
    (the call-time read already fails loudly — don't change that), and non-POSIX
    (no meaningful mode bits).
    """
    if not path or os.name != "posix":
        return
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return  # missing/unreadable => the call-time open reports it; perms aren't the story
    if mode & 0o077:
        raise RuntimeError(
            f"{what} {path!r} is group/other-accessible (mode {mode & 0o777:03o}). "
            f"Refusing to start: anything on this box could read the secret. "
            f"Fix: chmod 600 {path}"
        )
