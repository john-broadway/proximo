"""The operator's words to every client: the MCP `instructions` a session receives in `initialize`.

Issue #123. One Proximo serves many clients (several projects, a desktop app, coding sessions in
containers), and each needs the same site guidance: which targets exist, the approval rules per
tier, when a snapshot is wanted. Kept in each client, that text drifts; the server is the one place
every client already reads. `PROXIMO_MCP_INSTRUCTIONS` names a UTF-8 text file; its content is the
`instructions` string of the handshake, read once when the server is built (restart to change).
Unset, nothing is sent, as before.

It is operator config on the box, the trust of `targets.toml`, so it is not fenced as tainted data.
It is also TEXT FOR THE CLIENT ONLY: nothing in Proximo reads it, so it can grant nothing, arm
nothing and move no ceiling. Governance stays where it is.

Set and unusable (unreadable, not UTF-8, empty, over the cap), the door still starts and sends
none: the text governs nothing, so a typo or a missing bind mount costs the clients the guidance,
never the door (the rule for config that governs nothing: an unreadable registry keeps the selector
and warns, junk in `PROXIMO_EXIT_MAX_BYTES` keeps the defaults). It is said on stderr at start and
flagged by doctor, naming the variable, never the path or a byte of the file, since a mis-pointed
file could be a token. It lands in every session's context, so it is held to `CAP` bytes.
"""
from __future__ import annotations

import os
import sys
from typing import Any

from proximo.core.errors import ProximoError

ENV = "PROXIMO_MCP_INSTRUCTIONS"
#: Every session pays for these bytes before its first call: about two thousand tokens at most.
CAP = 8192
#: Past this, advice only: some clients cut a server's instructions short (Claude Code showed two
#: servers' cut at a few KB, 2026-11-01), so the rules that matter go first and the file stays short.
SOFT = 2048
#: Doctor's flag for a file over SOFT opens with this: advice, not incompleteness.
ADVISORY = ("the MCP instructions are over",)


def load() -> str | None:
    """The instructions text, or None when the variable is unset. Loud when set and unusable."""
    path = os.environ.get(ENV, "").strip()
    if not path:
        return None
    try:
        with open(path, "rb") as f:
            raw = f.read(CAP + 1)
    except OSError as e:
        raise ProximoError(f"{ENV} points to a file this process cannot read") from e
    if len(raw) > CAP:
        raise ProximoError(f"{ENV} is over {CAP} bytes: every session would carry it; shorten it")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ProximoError(f"{ENV} is not UTF-8 text") from e
    if not text.strip():
        raise ProximoError(f"{ENV} is set and its file is empty: unset it, or write the instructions")
    return text


def served() -> str | None:
    """What the door sends: `load()`'s text, or None with one stderr line when the file is unusable."""
    try:
        return load()
    except ProximoError as e:
        print(f"proximo: {e}; no client receives the instructions until it is fixed", file=sys.stderr)
        return None


def station(flags: list[str]) -> dict[str, Any]:
    """Doctor's section: configured, and the bytes served against the cap. Never where."""
    if not os.environ.get(ENV, "").strip():
        return {"configured": False}
    try:
        text = load()
    except ProximoError as e:
        flags.append(f"the MCP instructions are set and unusable, so no client receives them: {e}")
        return {"configured": True, "error": str(e)}
    size = len((text or "").encode())
    if size > SOFT:
        flags.append(f"{ADVISORY[0]} {SOFT} bytes ({size}): some clients truncate a server's instructions, "
                     "so put the rules that matter first, or shorten the file")
    return {"configured": True, "bytes": size, "cap": CAP}
