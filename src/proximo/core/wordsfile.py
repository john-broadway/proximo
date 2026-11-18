"""One reader for the operator's words: the instructions file and each runbook file.

The words are DISCLOSED by design: every byte read here goes to a caller and on to its model. So
the read refuses on doubt (John, 2026-11-16: "zerotrust"), and it is one function so the two
halves cannot drift:

- the path is opened non-blocking and the OPENED descriptor is checked to be a regular file: a
  named pipe never blocks a door, and nothing is decided on a name that can be swapped after a
  check (open, then fstat; never stat, then open);
- at most `cap + 1` bytes are read, so a device or a huge file costs a bounded read;
- the text is UTF-8, a byte-order mark is dropped and never served, and a file of nothing but
  whitespace is empty;
- a file on a kernel filesystem (`/proc`, `/sys`, `/dev`) is never served: `/proc/self/environ`
  is a "regular file" to `fstat` and holds every secret in the environment;
- a file with more than one hard link is never served: a words file has one name, and a second
  name is how a credential is reached from outside the folder that holds it;
- a file that is, by FILE IDENTITY, one that another `PROXIMO_*` variable names (resolved the
  way the core resolves it, relative paths included), one inside a folder such a variable
  names, one the target registry names, or state the core places by default (the ledger, its
  key and archives, the memory file, the store and restore folders, the env file), is never
  served: a symlink to a credential is the same file. The set is read from the process's own
  configuration and the core's own resolvers at the moment of the read, never from a list
  written down here;
- when the set cannot be read (a registry that is set and unreadable), nothing is served: a
  guard that cannot look refuses.

A refusal carries a KIND and, for a collision, the NAME of the variable collided with. Never a
path, never a byte of the file: the caller turns the kind into its own sentence.
"""
from __future__ import annotations

import fcntl
import os
import stat
from collections.abc import Iterator
from typing import Any

#: The variables that name the words themselves: not secrets, and one may sit inside the other's folder.
OWN = frozenset({"PROXIMO_INSTRUCTIONS", "PROXIMO_RUNBOOKS_DIR"})
#: Kernel filesystems: nothing under them is an operator's words.
_KERNEL = ("/proc", "/sys", "/dev")
#: A name the core never reads (the instructions variable on the unmerged branch of #124): it names
#: no credential of Proximo's, so a words file it also names is still the operator's words.
_NEVER_READ = frozenset({"PROXIMO_MCP_INSTRUCTIONS"})

UNREADABLE, NOT_REGULAR, SECRET, UNPROVEN, LINKED, OVER, NOT_UTF8, EMPTY = (
    "unreadable", "not-regular", "secret", "unproven", "linked", "over", "not-utf8", "empty")


class Refused(Exception):
    """The words file is not served. `kind` is one of the eight; `collides` names the variable (or
    the config) whose file it is, for `SECRET`, and what could not be read, for `UNPROVEN`."""

    def __init__(self, kind: str, collides: str | None = None) -> None:
        super().__init__(kind)
        self.kind, self.collides = kind, collides


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


def _candidates() -> Iterator[tuple[str, str]]:
    """(path, the name it is configured under) for everything this process is configured to hold
    or places by default. A registry that is set and cannot be read raises `Refused(UNPROVEN)`."""
    from proximo.core import download, envfile, ledger, memory, registry, store  # noqa: PLC0415 -- stays importable alone
    for name, value in sorted(os.environ.items()):
        if name.startswith("PROXIMO_") and name not in OWN | _NEVER_READ and value.strip():
            yield value.strip(), name
    yield envfile.DEFAULT_PATH, envfile.PATH_ENV
    log = os.path.expanduser(os.environ.get("PROXIMO_AUDIT_LOG", "").strip() or ledger.DEFAULT_AUDIT_LOG)
    yield log, "PROXIMO_AUDIT_LOG"
    yield os.path.join(os.path.dirname(log), "audit.key"), "PROXIMO_AUDIT_KEY_PATH"
    folder, base = os.path.dirname(log) or ".", os.path.basename(log)
    try:
        beside = sorted(n for n in os.listdir(folder) if n.startswith(base + "."))
    except OSError:
        beside = []
    for name in beside:                                  # the sealed and rotated archives beside it
        yield os.path.join(folder, name), "PROXIMO_AUDIT_LOG"
    held = memory.path(log)
    for suffix in ("", "-wal", "-shm", "-journal"):
        yield held + suffix, "PROXIMO_MEMORY_PATH"
    yield store.directory(log), "PROXIMO_STORE_DIR"
    yield download._DEFAULT_DIR, download.DIR_ENV  # noqa: SLF001 -- the core's own default, read not copied
    try:
        targets = registry.load_registry()
    except Exception:  # noqa: BLE001 -- whatever the reason, the guard could not look
        raise Refused(UNPROVEN, registry.ENV) from None
    for value in _strings(targets):
        yield value, "the target registry"


def collides(opened: os.stat_result, real: str) -> str | None:
    """The name this file is already configured under, or None. A file by identity (so a symlink
    is caught); a folder by where the opened file really is (`real`, read from its descriptor)."""
    me = (opened.st_dev, opened.st_ino)
    for value, name in _candidates():
        candidate = os.path.abspath(os.path.expanduser(value))   # the core resolves a relative path against the cwd
        if os.path.realpath(candidate) == os.sep:                # the root is no one's folder
            continue
        try:
            st = os.stat(candidate)
        except (OSError, ValueError):
            continue                                             # a port, a flag, a URL, an absent file: names nothing
        if stat.S_ISREG(st.st_mode):
            if (st.st_dev, st.st_ino) == me:
                return name
        elif stat.S_ISDIR(st.st_mode):
            inside = os.path.realpath(candidate)
            if real == inside or real.startswith(inside.rstrip(os.sep) + os.sep):
                return name
    return None


def _where(fd: int) -> str:
    """Where the OPENED file really is, asked of the descriptor and never of the name again: a name
    can be swapped between the open and a second look. A platform that cannot say refuses."""
    if os.path.isdir("/proc/self/fd"):
        return os.path.realpath(f"/proc/self/fd/{fd}")
    getpath = getattr(fcntl, "F_GETPATH", None)                  # macOS
    if getpath is not None:
        try:
            return os.path.realpath(fcntl.fcntl(fd, getpath, bytes(1024)).rstrip(b"\0").decode())
        except (OSError, ValueError):
            pass
    raise Refused(UNPROVEN, "this platform")


def read(path: str, cap: int) -> str:
    """The text of the words file at `path`, or `Refused`. See the module's own account."""
    path = os.path.expanduser(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except (OSError, ValueError):
        raise Refused(UNREADABLE) from None                      # an OSError carries the path: never chained
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise Refused(NOT_REGULAR)
        real = _where(fd)
        if any(real == k or real.startswith(k + os.sep) for k in _KERNEL):
            raise Refused(NOT_REGULAR)
        if (name := collides(st, real)) is not None:
            raise Refused(SECRET, name)
        if st.st_nlink != 1:
            raise Refused(LINKED)
        raw = b""
        while len(raw) <= cap:
            try:
                chunk = os.read(fd, cap + 1 - len(raw))
            except OSError:
                raise Refused(UNREADABLE) from None
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(fd)
    if len(raw) > cap:
        raise Refused(OVER)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise Refused(NOT_UTF8) from None
    if not text.strip():
        raise Refused(EMPTY)
    return text
