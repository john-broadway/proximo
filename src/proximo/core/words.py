"""The operator's words, read once when a door starts: the instructions and the runbooks.

One read per door process, so every refusal is said once and a door cannot serve one half read
at start and the other read later. The bundle is handed down (`build_server(words=)`,
`dispatch.Core(words)`); nothing below this reads the environment for them.

A network door with no bearer token cannot tell one caller from another, so it serves no words
and this reads NOTHING for it (John, 2026-11-16: "zerotrust"): a file that is not opened cannot
be disclosed. The stdio door's caller is the operator's own process: it passes `bearer=True`.
"""
from __future__ import annotations

import os
import sys
from collections.abc import Callable
from typing import Any, NamedTuple

from proximo.core import instructions, runbooks, wordsfile
from proximo.core.errors import ProximoError


class Words(NamedTuple):
    instructions: str | None           # the text, or None
    runbooks: tuple[runbooks.Runbook, ...]   # the runbooks that passed, in name order
    said: tuple[str, ...]              # the stderr lines this read produced, already printed once


NONE = Words(None, (), ())
NO_BEARER = "this door has no bearer token, so the operator's words are not served on it"
#: Doctor's flags that are advice, not incompleteness.
ADVISORY = (*instructions.ADVISORY, runbooks.LONG)


def at_start(*, bearer: bool) -> Words:
    """Read both halves once and say each refusal once on stderr. `bearer=False` reads nothing."""
    said: list[str] = []
    text: str | None = None
    served: tuple[runbooks.Runbook, ...] = ()
    if instructions.old_name_set():
        said.append(f"proximo: {instructions.OLD_SAID}")
    if not bearer:
        if any(os.environ.get(name, "").strip() for name in wordsfile.OWN):
            said.append(f"proximo: {NO_BEARER}")
    else:
        try:
            text = instructions.load()
        except ProximoError as e:
            said.append(f"proximo: {e}; no caller receives the instructions until it is fixed")
        try:
            folder = runbooks.load()
        except ProximoError as e:
            said.append(f"proximo: {e}; no caller receives the operator's runbooks until it is fixed")
        else:
            if folder is not None:
                served = folder.served
                said.extend(f"proximo: {line}" for line in runbooks.said(folder))
    for line in said:
        print(line, file=sys.stderr)
    return Words(text, served, tuple(said))


def station(flags: list[str], said: Callable[[ProximoError], str]) -> dict[str, Any]:
    """Doctor's two sections. It reads the file and the folder NOW: it describes them, not a door
    already running. `said` is doctor's scrubber for a refusal it repeats."""
    section: dict[str, Any] = {"configured": False}
    if os.environ.get(runbooks.ENV, "").strip():
        section = {"configured": True, "cap": runbooks.CAP, "max": runbooks.MAX}
        try:
            folder = runbooks.load()
        except ProximoError as e:
            flags.append("the runbooks folder is set and unusable, so no caller receives the operator's "
                         f"runbooks: {(reason := said(e))}")
            section["error"] = reason
        else:
            assert folder is not None  # noqa: S101 -- the variable is set, so load() read a folder
            section.update(served=len(folder.served), refused=len(folder.refused), ignored=folder.ignored)
            flags.extend([*runbooks.said(folder), *runbooks.advice(folder)])
    return {"instructions": instructions.station(flags, said), "runbooks": section}
