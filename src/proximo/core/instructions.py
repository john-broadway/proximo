"""The operator's instructions: one text file, carried to the caller by every door that has a slot.

Issue #123 (alexdelprete), widened. One Proximo serves many callers (several projects, a desktop
app, coding sessions in containers), and each needs the same site guidance: which targets exist,
the approval rules per tier, when a snapshot is wanted. Kept in each client, that text drifts; the
box is the one place every caller already reads. `PROXIMO_INSTRUCTIONS` names a UTF-8 text file;
its text is read once when a door starts (`core.words.at_start`; restart to change) and carried in
each protocol's own slot. Unset, nothing is sent, as before.

It is operator config on the box, the trust of `targets.toml`, so it is not fenced as tainted data.
It is also TEXT FOR THE CALLER ONLY: nothing in Proximo reads it, so it can grant nothing, arm
nothing and move no ceiling. Governance stays where it is.

Every byte is DISCLOSED, so the file is read through `core.wordsfile`, which refuses on doubt: a
file that is not a regular file, one another `PROXIMO_*` variable names, one with a second name.
Set and unusable, the door still starts and sends none: the text governs nothing, so a typo or a
missing bind mount costs the callers the guidance, never the door. It is said on stderr at start
and flagged by doctor, naming the variable (and, for a collision, the variable collided with),
never the path or a byte of the file. It lands in every session's context, so it is held to `CAP`.
"""
from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

from proximo.core import wordsfile
from proximo.core.errors import ProximoError

ENV = "PROXIMO_INSTRUCTIONS"
#: The name on the unmerged branch of #124. Never released, so never retired: it is not read, and
#: a door and doctor say so where they find it set.
OLD = "PROXIMO_MCP_INSTRUCTIONS"
OLD_SAID = f"{OLD} is set and is not read: the variable is {ENV}"
#: Every session pays for these bytes before its first call: about two thousand tokens at most.
CAP = 8192
#: Past this, advice only: some clients cut a server's instructions short, so the rules that
#: matter go first and the file stays short.
SOFT = 2048
#: Doctor's flag for a file over SOFT opens with this: advice, not incompleteness.
ADVISORY = ("the instructions are over",)


def why(env: str, refused: wordsfile.Refused, cap: int) -> str:
    """One sentence for a refused words file: the variable, the reason, never a path or a byte."""
    kind, other = refused.kind, refused.collides
    if kind == wordsfile.SECRET:
        return f"{env} points at a file that {other} names: a credential is never served"
    if kind == wordsfile.UNPROVEN and other == "this platform":
        return (f"{env} cannot be served: this platform cannot say where an opened file really is, "
                "so nothing proves this file is not a credential")
    if kind == wordsfile.UNPROVEN:
        return f"{env} cannot be served: {other} could not be read, so nothing proves this file is not a credential"
    return {
        wordsfile.UNREADABLE: f"{env} points to a file this process cannot read",
        wordsfile.NOT_REGULAR: f"{env} does not point to a regular file",
        wordsfile.LINKED: f"{env} points at a file with a second name (a hard link): a words file has one",
        wordsfile.OVER: f"{env} is over {cap} bytes: every session would carry it; shorten it",
        wordsfile.NOT_UTF8: f"{env} is not UTF-8 text",
        wordsfile.EMPTY: f"{env} is set and its file is empty: unset it, or write the instructions",
    }[kind]


def old_name_set() -> bool:
    return bool(os.environ.get(OLD, "").strip())


def load() -> str | None:
    """The instructions text, or None when the variable is unset. Loud when set and unusable."""
    path = os.environ.get(ENV, "").strip()
    if not path:
        return None
    try:
        return wordsfile.read(path, CAP)
    except wordsfile.Refused as refused:
        raise ProximoError(why(ENV, refused, CAP)) from None   # never chained: nothing of the file rides along


def station(flags: list[str], said: Callable[[ProximoError], str]) -> dict[str, Any]:
    """Doctor's section: configured, and the bytes served against the cap. Never where. It reads
    the file NOW: it describes the file, not a door already running. `said` is doctor's scrubber."""
    if old_name_set():
        flags.append(OLD_SAID)
    if not os.environ.get(ENV, "").strip():
        return {"configured": False}
    try:
        text = load()
    except ProximoError as e:
        flags.append(f"the instructions are set and unusable, so no caller receives them: {(reason := said(e))}")
        return {"configured": True, "error": reason}
    size = len((text or "").encode())
    if size > SOFT:
        flags.append(f"{ADVISORY[0]} {SOFT} bytes ({size}): some clients truncate a server's instructions, "
                     "so put the rules that matter first, or shorten the file")
    return {"configured": True, "bytes": size, "cap": CAP}
