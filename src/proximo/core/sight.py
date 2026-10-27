"""TOKEN SIGHT: an empty list the token could not have seen into is not "none" (records/sight.toml).

Proxmox answers 200 and an EMPTY list, not a refusal, where the token lacks the privilege that
makes the entries visible: PVE hides backup volumes from a storage's content listing per volume,
and PBS shows a caller holding only `Datastore.Backup` just the groups and snapshots it owns. An
agent told `[]` reads "no backups" about a shelf it was never allowed to see (0.44 found this live
and refused it; the cut dropped the refusal).

The judgement is the record's: which address, which privileges make the list sighted (alternatives,
each a list of `privilege@path`), and why. This module only applies a row's line to an empty answer,
from the token's own `GET /access/permissions`:

- SIGHTED: some alternative is wholly held. The list is served as data; the receipt names the
  alternative that matched (privilege@path only), so the ledger proves why it was served.
- BLIND: the map was read and no alternative is held. An EMPTY list is refused, naming what the
  token would need; a NON-empty list is served and marked `partial` (the vendor filters by owner or
  by volume, so the rows are the token's own, not the shelf). A non-empty answer is never refused.
- UNKNOWN: the map could not be read (or is oversize, or not a permission map). An empty list is
  refused ("not vouched": 0.44 returned `[]` here; the core fails closed); a non-empty one is
  served and marked `unverified`.

A privilege is held at a path iff its key is DEFINED there, on the path itself or on an ancestor
that propagates (PVE's contract: the value is the propagate flag, informational at the exact path).
`@*` means held anywhere: VM.Backup on one guest is sight of that guest's archives, and the line
decides that scope is enough. The permission map's own text never reaches an answer (a failed read
is named by its exception type) and neither does a caller's namespace whole (`_clip`).
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from typing import Any

SIGHTED, BLIND, UNKNOWN = "sighted", "blind", "unknown"
NOT_ASKED = "not asked"     # the line does not apply to this question: nothing is judged
#: A permission map larger than this (serialised) is not judged: a bound on what the check reads.
MAP_CAP = 256 * 1024
#: The longest path or name an answer or a receipt echoes from the caller.
ECHO = 120

_SLOT = re.compile(r"(/?)\{([^{}]+)\}")


def _flags(perms: Any) -> dict[str, dict[str, bool]] | None:
    """{privilege: {path: propagate}} from the vendor's permission map, or None when it is not one
    (empty, not a map of maps, a value that is not a flag): a token holding nothing is answered 403,
    never 200 and `[]`, so an empty map proves nothing about what the token could see."""
    if not isinstance(perms, dict) or not perms or not all(isinstance(v, dict) for v in perms.values()):
        return None
    out: dict[str, dict[str, bool]] = {}
    for path, held in perms.items():
        for priv, propagate in held.items():
            if propagate is None:                           # None is no grant
                continue
            if isinstance(propagate, bool) or (isinstance(propagate, int) and propagate in (0, 1)):
                out.setdefault(str(priv), {})[str(path)] = bool(propagate)    # defined is held
            else:
                return None                                 # a value that is no flag: not the vendor's map
    return out


def _held(flags: dict[str, dict[str, bool]], priv: str, path: str) -> bool:
    if path == "*":
        return bool(flags.get(priv))
    return any(p == path or (propagate and (p == "/" or path.startswith(p + "/")))
               for p, propagate in flags.get(priv, {}).items())


def _clip(text: str) -> str:
    return text if len(text) <= ECHO else text[:ECHO] + "..."


def _where(template: str, bound: Mapping[str, str], args: Mapping[str, Any]) -> str:
    """A requirement's path with its placeholders filled from the path the question was asked at and
    its arguments. A placeholder with no value is an optional argument (a PBS namespace): its
    segment is dropped, so the privilege is asked at the datastore itself. A value that is not a
    clean path (an empty, `.` or `..` segment) is no path to judge a grant by: ValueError."""
    def one(m: re.Match[str]) -> str:
        value = bound.get(m.group(2), args.get(m.group(2)))
        if value in (None, ""):
            return ""
        if not isinstance(value, str) or any(seg in ("", ".", "..") for seg in value.split("/")):
            raise ValueError(m.group(2))
        return f"{m.group(1)}{value}"
    return _SLOT.sub(one, template).rstrip("/") or "/"


def _split(req: str) -> tuple[str, str]:
    priv, _, path = req.partition("@")
    return priv, path


def applies(line: Mapping[str, Any], args: Mapping[str, Any]) -> bool:
    """The line speaks to this question: each `when` parameter is absent (the default asks for
    everything, the hidden kind included) or is not provably about another value. Only a string, or
    a list of strings, none of them listed, is another question; a value the guard cannot read as a
    string (a number, a mapping) is asked, because the wire may still send it as the listed word."""
    for k, vals in line["when"].items():
        v = args.get(k)
        if v in (None, "", [], ()):
            continue
        items = v if isinstance(v, (list, tuple)) else [v]
        if not (all(isinstance(x, str) for x in items) and not any(x in vals for x in items)):
            continue
        return False
    return True


def judge(line: Mapping[str, Any], bound: Mapping[str, str], args: Mapping[str, Any],
          read: Callable[[], Any], *, empty: bool = True) -> tuple[str, str, list[str]]:
    """(state, sentence, matched) for an answer on a row with this sight line. `read` fetches the
    permission map and is called only when the line applies. `empty` shapes the sentence: an empty
    list is refused with it, a non-empty one is served marked with it. `matched` is the satisfied
    alternative as privilege@path (names only), empty unless SIGHTED."""
    what = line["what"]
    if not applies(line, args):
        return NOT_ASKED, "", []
    failure = ""
    flags = None
    try:
        raw = read()
        if len(json.dumps(raw, default=str)) > MAP_CAP:
            failure = "the permission map is over the size cap"
        else:
            flags = _flags(raw)
            failure = "" if flags is not None else "the answer was not a permission map"
        alternatives = ([[(priv, _where(path, bound, args)) for priv, path in map(_split, alt)]
                         for alt in line["sighted"]] if flags is not None else [])
    except ValueError:
        flags, failure, alternatives = None, "the namespace is not a clean path", []
    except Exception as exc:  # noqa: BLE001 -- the vendor's or the wire's; the type is the report, never its text
        flags, failure, alternatives = None, f"the read failed: {type(exc).__name__}", []
    if flags is None:
        if empty:
            return UNKNOWN, (f"empty list not vouched as none: whether this token can see {what} could not be "
                             f"read ({failure}), and Proxmox answers an empty list, not a refusal, where it "
                             "cannot."), []
        return UNKNOWN, f"unverified: whether this token sees all {what} here could not be read ({failure}).", []
    for alt in alternatives:
        if all(_held(flags, priv, path) for priv, path in alt):
            return SIGHTED, "", [_clip(f"{priv}@{path}") for priv, path in alt]
    need = " or ".join(" and ".join(f"{priv} on {'any path' if path == '*' else _clip(path)}" for priv, path in alt)
                       for alt in alternatives)
    if empty:
        return BLIND, (f"empty list not served as none: this token cannot see {what} here (Proxmox answers 200 "
                       f"and empty, not a refusal). It would need {need}. The {what} may exist."), []
    return BLIND, (f"partial: Proxmox filters {what} by what the token holds, so these rows are the token's own, "
                   f"not all of them. Seeing all needs {need}."), []
