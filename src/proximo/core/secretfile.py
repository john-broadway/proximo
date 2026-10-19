"""Secret-file permission floor, shared by every loader that reads a secret by path.

One helper, one rule (mirrors ``_tls.py``'s role for TLS parsing): a secret file that
group/other can touch is refused LOUD at config/load time, so a mis-deployed credential
fails before it is ever used. Callers: PVE token + audit HMAC key (``config.py``),
PBS/PMG/PDM credentials (``pbs.py`` / ``pmg.py`` / ``pdm.py``), and the network faces'
bearer tokens + A2A signing key (``core/perimeter/guard.py`` / ``core/perimeter/a2a/app.py``).
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


# --- exception text that can be handed to a model -------------------------------------------
#
# THE GAP redact() DOES NOT CLOSE. redact() hides REGISTERED SECRET LITERALS and auth-header
# shapes. An internal address is neither, so it walks straight through. httpx builds its error
# message out of the REQUEST URL:
#
#     Client error '403 Forbidden' for url 'https://<internal-ip>:8006/api2/json/nodes/.../status'
#
# so any tool formatting the type-name-plus-message shape into a RESPONSE hands the caller the
# estate's topology. That is a RUNTIME leak: no source audit can ever catch it, because the
# string does not exist until the call fails.
#
# WHY NOT DROP THE MESSAGE. `_audited_run` keeps only the type name, which is right for a
# durable ledger. A model answering "why could you not read that storage?" needs "403
# Forbidden" to say anything useful. So the LOCATOR goes and the REASON stays.
_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>]+")
# Dotted quad with an optional port. Deliberately not a general hostname sweep: that would eat
# ordinary words and make messages unreadable, and a bare FQDN with no scheme is not the shape
# httpx produces.
_ADDR_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b")
# A filesystem path, quoted or bare. Opt-in (`paths=True`): the core's answers over a network
# face must not teach a remote caller the box's layout (a plan on a mis-moded token said
# "chmod 600 /path/to/token", lens 9); 0.44's callers compose their own messages around paths
# on purpose and keep the default. Quoted (either quote: Python's repr switches to double
# quotes for a path holding an apostrophe, JSON always uses them) a path may hold spaces; bare,
# it is two or more POSIX segments, a Windows drive path, or a `~`/`~user` path (the lens of
# 2026-10-09 named the first three shapes; `~user` carries a username, so it goes too).
# Lens fold, the same day: a path glued to a colon (`file:/a/b`), a UNC or doubled-slash path
# (`\\srv\share`, `//srv/a`) and a trailing slash are paths too.
_PATH_RE = re.compile(
    r"'(?:/|[A-Za-z]:[\\/])[^']*'"
    r'|"(?:/|[A-Za-z]:[\\/])[^"]*"'
    r"|(?<![\w/])/+(?:(?:[\w.@+-]|%[0-9A-Fa-f]{2})+/+)+(?:[\w.@+-]|%[0-9A-Fa-f]{2})*"
    r"|(?<!\w)[A-Za-z]:[\\/](?:(?:[\w.@+-]|%[0-9A-Fa-f]{2})+[\\/])*(?:[\w.@+-]|%[0-9A-Fa-f]{2})+"
    r"|(?<![\w\\])\\\\(?:[\w.@+-]|%[0-9A-Fa-f]{2})+(?:\\(?:[\w.@+-]|%[0-9A-Fa-f]{2})+)+"
    r"|(?<!\w)~[\w.-]*(?:/(?:[\w.@+-]|%[0-9A-Fa-f]{2})+)+"
)
# A BARE path holding a space is cut at the space, and the rest stood beside the marker
# ("<path> lab/secret.key", "<path> secret.key"); a single-quoted path cut early by an apostrophe
# left a glued residue ("<path>s b/c"). What follows a scrubbed path folds into it when it is
# glued word text, a word carrying a slash, or a filename (a word, a dot, a letter: `3.4` and
# `v1.2` are not); punctuation stands. The error is to over-scrub, the safe side of this seam.
_PATH_TAIL_RE = re.compile(r"<path>[\w']*(?:\s+(?:[^\s<>]*[\\/][^\s<>]*|[A-Za-z_][\w-]*\.[A-Za-z]\w*))*")
_MAX_EXC_TEXT = 400


def safe_exception_text(exc: BaseException, *, limit: int = _MAX_EXC_TEXT, paths: bool = False) -> str:
    """`Type: message` with every locator removed, safe to return to a caller.

    Strips URLs and bare IPv4[:port] before running the result through redact(), so both the
    estate's topology and any registered secret are gone. Returns the bare type name when the
    exception carries no message. Bounded, because an exception body is context the caller pays
    for. Use this anywhere exception text enters a RESPONSE; `_audited_run`'s type-only rule
    still governs what enters the LEDGER.
    """
    name = type(exc).__name__
    try:
        body = str(exc)
    except Exception:  # a __str__ that itself raises must not take the caller down
        body = ""
    return safe_text(f"{name}: {body}", limit=limit, paths=paths) if body else name


def safe_text(body: str, *, limit: int = _MAX_EXC_TEXT, paths: bool = False) -> str:
    """Vendor free text with every locator removed and registered secrets redacted, one line,
    bounded: what an exception's message gets, and what a task's exit text gets before it lands
    on a ledger row (B4, 2026-09-30). `paths=True` takes filesystem paths out as well."""
    body = _URL_RE.sub("<url>", str(body))
    body = _ADDR_RE.sub("<addr>", body)
    if paths:
        body = _PATH_TAIL_RE.sub("<path>", _PATH_RE.sub("<path>", body))
    text = " ".join(redact(body).split())  # one line: a multi-line body reads as structure it is not
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"
