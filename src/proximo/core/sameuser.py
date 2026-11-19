"""The boundary the pillars do not draw: what a process running as the door's own user can reach.

The pillars hold against a caller THROUGH the door. A process running as the door's own Unix user
is not through the door: it can edit the env file for the next start, rewrite the ledger with the
key that sits beside it, read the arm source, replace the operator's words. An owner check cannot
close that, since such a process and the door are one owner.

`proximo doctor` says it: one advisory flag, the KINDS of file and never their paths (a hijacked
session should not learn where the switches are). It fires on almost every install, because a door
owns the ledger key it mints: that is the point, not noise. What can be put outside this user's
reach and what cannot is SECURITY.md's hardened deployment; this line does not claim to know which
your box has done. It checks ownership and write permission only: a file this user can merely READ
is not seen here. Advice, never a refusal. Found by the 2026-11-19 read of the README's claims
against the code, which the README had not said.
"""
from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from typing import Any

from proximo.core import envfile, wire

#: the opening words of the flag; `doctor` sorts a flag that opens with one of these as advice
ADVISORY = ("the door's own user can write",)


def _mine(path: str | None) -> bool:
    """True when this process's user owns the file or can write it. A path that cannot be stat'ed
    is not held: an absent env file is nobody's."""
    if not path:
        return False
    full = os.path.expanduser(path)
    try:
        st = os.stat(full)
    except OSError:
        return False
    return st.st_uid == os.geteuid() or os.access(full, os.W_OK)


def station(lcfg: Any, flags: list[str], more: Mapping[str, Sequence[str | None]] | None = None) -> list[str]:
    """The kinds of authority-holding file this door's own user can write, and one flag naming them.
    `more` is a kind the caller knows and this module must not (the operator's words: only the doors
    and the doctor know those exist)."""
    held = {
        "the env file": [os.environ.get(envfile.PATH_ENV) or envfile.DEFAULT_PATH],
        "the ledger key": [getattr(lcfg, "audit_key_path", None)
                           or os.path.join(os.path.dirname(lcfg.audit_log_path) or ".", "audit.key")],
        "an arm source": [os.environ.get(wire._pair_var(p, "ARM_SOURCE")) for p in ("pve", "pbs", "pmg", "pdm")],
        **(more or {}),
    }
    kinds = [kind for kind, paths in held.items() if any(_mine(p) for p in paths)]
    if kinds:
        flags.append(f"{ADVISORY[0]}: {', '.join(kinds)}. A process running as this same user is not "
                     "through the door and can change what is listed; SECURITY.md (the hardened deployment) "
                     "says what can be put out of its reach")
    return kinds
