"""The operator's runbooks: a folder of markdown files, each served beside Proximo's own five.

`PROXIMO_RUNBOOKS_DIR` names a folder. Each file in it named like `drain_node.md` is one runbook:
a title line (`# Drain a node`), a plane line (`plane: pve`), then the operator's own procedure
as fixed text. Proximo authors none of them and reads none of them to decide anything: a runbook
is words for the caller, and every step it names still runs through the one seam.

A runbook is held to the address rules Proximo's own five are tested with, made strict, because a
model follows what it is handed:

1. it names at least one address, a method and a path as the vendor publishes them (`GET /nodes`);
2. every address it names is a published address of its plane;
3. none of them is an address Proximo excludes or holds: published is not callable;
4. nothing but sentence punctuation follows a path, so the check judged the path as written;
5. no path stands without its method (so `**POST** /x`, a lowercase method, or the tools' own
   `path="/nodes/..."` form refuse: the check would not have seen them), and no vendor API URL
   is written.

A template is the vendor's own spelling (`/nodes/{node}/status`, never `/nodes/{n}/status`): any
other `{x}` would be checked as some sibling address. What the rules do NOT see, and SETUP says so:
a path written with no leading slash, and characters that only look like a slash.

A runbook that fails any rule is not served, and doctor names it. A broken file or folder costs
the guidance, never the door. Each file is read through `core.wordsfile`, so a runbook that is a
link to a credential is refused like the instructions file would be. Nothing is said about a file
but its name, which already matched `NAME`, and a matched method and path, the vendor's own words.
"""
from __future__ import annotations

import os
import re
from typing import NamedTuple

from proximo.core import apitree, engine, wordsfile
from proximo.core.errors import ProximoError

ENV = "PROXIMO_RUNBOOKS_DIR"
#: Per file: a runbook is text a session carries when it asks for it.
CAP = 8192
#: Runbook files read from one folder; the names of the rest are counted, never opened.
MAX = 32
#: Entries a folder may hold before it is refused whole: the listing itself is bounded.
FOLDER_MAX = 4096
#: Past this many characters served, advice only: Proximo's own five are each held under it, the
#: size a small model in a 4K window holds (John, 2026-11-17, asked of size limits: "yes i do").
SOFT = 1800

#: A runbook's file name. The name is all that is ever said about a file, so no odd byte can be in it.
NAME = re.compile(r"[a-z][a-z0-9_]{0,39}\.md")
#: Exactly the pattern Proximo's own five are tested with: one space, upper case, no dot in a path.
ADDRESS = re.compile(r"\b(GET|POST|PUT|DELETE) (/[A-Za-z0-9_{}/-]+)")
#: A slash that opens a name and does not follow a word (`and/or`, `n/a`) or the `://` of a link.
#: Every one must sit inside the path of an address, the inner slashes of `/nodes/{node}/x` included.
_SLASH = re.compile(r"(?<!\w)(?<!:/)/[A-Za-z0-9_{]")
#: What may follow a path before the next space: the end of a sentence, a quote, a code span.
_AFTER = re.compile(r"[`.,;:)!?\"']*(?=\s|\Z)")
_TITLE_MAX = 80
_QUOTE = 120                      # of a path, in a refusal
#: Doctor's flag for a served runbook over SOFT opens with this: advice, not incompleteness.
LONG = "an operator runbook is over"


class Runbook(NamedTuple):
    name: str
    title: str
    plane: str
    text: str                     # what is served: the one fixed line, a blank line, the file


class Refusal(NamedTuple):
    name: str
    reason: str


class Folder(NamedTuple):
    served: tuple[Runbook, ...]   # in name order
    refused: tuple[Refusal, ...]
    ignored: int                  # entries that are not runbook files by name
    unread: int                   # runbook files past the first MAX by name: never opened


def _own() -> frozenset[str]:
    from proximo.core import prompts  # noqa: PLC0415 -- prompts imports nothing of this module
    return frozenset(fn.__name__ for fn in prompts.RUNBOOKS)


def _unread(refused: wordsfile.Refused) -> str:
    kind, other = refused.kind, refused.collides
    if kind == wordsfile.SECRET:
        return f"it is a file that {other} names: a credential is never served"
    if kind == wordsfile.UNPROVEN and other == "this platform":
        return "this platform cannot say where an opened file really is, so nothing proves it is not a credential"
    if kind == wordsfile.UNPROVEN:
        return f"{other} could not be read, so nothing proves it is not a credential"
    return {wordsfile.UNREADABLE: "this process cannot read it",
            wordsfile.NOT_REGULAR: "it is not a regular file",
            wordsfile.LINKED: "it has a second name (a hard link): a words file has one",
            wordsfile.OVER: f"it is over {CAP} bytes",
            wordsfile.NOT_UTF8: "it is not UTF-8 text",
            wordsfile.EMPTY: "it is empty"}[kind]


def check(name: str, text: str) -> Runbook:
    """The runbook this text is, or `ProximoError` carrying the one reason it is not served."""
    lines = [line.rstrip("\r") for line in text.split("\n")]
    title = lines[0][2:].strip() if lines[0].startswith("# ") else ""
    if not 1 <= len(title) <= _TITLE_MAX or not title.isprintable():
        raise ProximoError(f"its first line is not a title (`# ` and 1 to {_TITLE_MAX} printable characters)")
    second = next((line.strip() for line in lines[1:] if line.strip()), "")
    plane = second.removeprefix("plane: ")
    if second != f"plane: {plane}" or plane not in apitree.PRODUCTS:
        raise ProximoError("the line after its title is not `plane: ` and one of " + ", ".join(apitree.PRODUCTS))
    named = list(ADDRESS.finditer(text))
    if not named:
        raise ProximoError("it names no address (a method and a path, as `GET /nodes`)")
    for m in named:
        method, path = m.group(1), m.group(2)
        said = f"{method} {path[:_QUOTE]}"
        try:
            row = engine.resolve(plane, method, path)
        except ProximoError:
            # `resolve` answers an excluded address like an unpublished one. The vendor does publish
            # it, so the sentence says which: the table is asked by the spelling as written.
            if engine.table().get((plane, method, path)) is None:
                raise ProximoError(f"it names an address {plane} does not publish: {said}") from None
            raise ProximoError(f"it names an address Proximo does not call: {said}") from None
        if row.excluded or row.held:
            raise ProximoError(f"it names an address Proximo does not call: {said}")
        if "{" in path and row.path != path:
            # `resolve` reads any `{x}` as "some value here", so `/nodes/{node}/{execute}` would be
            # judged as a sibling address. A template is the vendor's own spelling or it is refused.
            raise ProximoError(f"it names a template {plane} does not publish in that spelling: {said}")
        rest = text[m.end():]
        if _AFTER.match(rest) is None:
            raise ProximoError(f"something is written straight after a path, so the path checked is not "
                               f"the path written: {said}")
    if "/api2/" in text.lower():
        raise ProximoError("it writes a vendor API URL (`/api2/`): write the method and the path, as `GET /nodes`")
    inside = [(m.start(2), m.end(2)) for m in named]
    if any(not any(a <= m.start() < b for a, b in inside) for m in _SLASH.finditer(text)):
        raise ProximoError("it writes a path without its method (write `GET /nodes/...`, upper case, one space; "
                           "a runbook cannot mention a filesystem path)")
    return Runbook(name, title, plane, f"Operator runbook (not Proximo's): {name}.\n\n{text}")


def load() -> Folder | None:
    """The folder as it stands, or None when the variable is unset. `ProximoError` when the folder
    itself is unusable; one bad file is a `Refusal` beside the ones that are served."""
    where = os.environ.get(ENV, "").strip()
    if not where:
        return None
    names: list[str] = []
    ignored = 0
    try:
        with os.scandir(os.path.expanduser(where)) as entries:
            for seen, entry in enumerate(entries, start=1):
                if seen > FOLDER_MAX:
                    raise ProximoError(f"{ENV} names a folder of more than {FOLDER_MAX} entries: "
                                       "a runbooks folder holds runbooks")
                if NAME.fullmatch(entry.name):
                    names.append(entry.name)
                else:
                    ignored += 1
    except (OSError, ValueError):
        raise ProximoError(f"{ENV} does not name a folder this process can read") from None
    names.sort()
    own = _own()
    served: list[Runbook] = []
    refused: list[Refusal] = []
    for file in names[:MAX]:
        name = file.removesuffix(".md")
        try:
            if name in own:
                raise ProximoError("that is the name of one of Proximo's own runbooks")
            try:
                text = wordsfile.read(os.path.join(os.path.expanduser(where), file), CAP)
            except wordsfile.Refused as e:
                raise ProximoError(_unread(e)) from None
            served.append(check(name, text))
        except ProximoError as e:
            refused.append(Refusal(name, str(e)))
    return Folder(tuple(served), tuple(refused), ignored, max(0, len(names) - MAX))


def advice(folder: Folder) -> list[str]:
    """One sentence per served runbook over SOFT: doctor's advice, never a refusal."""
    return [f"{LONG} {SOFT} characters ({len(book.text)}): {book.name}: a small model in a 4K window may "
            "not hold it; Proximo's own five are each under that" for book in folder.served if len(book.text) > SOFT]


def said(folder: Folder) -> list[str]:
    """One sentence per thing not served: what a door says at start and doctor flags."""
    out = [f"an operator runbook is not served: {r.name}: {r.reason}" for r in folder.refused]
    if folder.unread:
        out.append(f"the runbooks folder holds {folder.unread + MAX} runbook files and only the first "
                   f"{MAX} by name are read")
    return out
