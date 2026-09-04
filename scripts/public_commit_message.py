#!/usr/bin/env python3
"""Build the PUBLIC release commit message for a version, from the CHANGELOG entry.

Why this exists. GitHub `main` carries a curated, squashed history: one commit per release,
created with `git commit-tree` rather than by merging our internal history. For six releases
that commit's message was the bare string "release: vX.Y.Z" — every word of reasoning lived on
the internal mirror, and the public face of the project showed no reason for any push. A
visitor reading the commit list learned nothing, and two releases that needed a follow-up push
appeared as the same version twice with no explanation of why.

The CHANGELOG entry for the version IS the explanation, already written and already gated. This
turns it into the commit body so the two cannot drift: there is no second place to write it.
The SUBJECT carries the entry's opening thesis as a one-line reason — the body alone was not
enough, because the subject is the only text GitHub shows in the file browser and commit list
(v0.36.1 through v0.39.0 all read as bare "release: vX.Y.Z" there; John caught it on 0.39.0).

Usage:  python scripts/public_commit_message.py 0.37.0
Prints the message to stdout. Exits non-zero (printing nothing) if the version has no CHANGELOG
entry, so a caller piping this into `git commit-tree` fails loud rather than committing an empty
body — the failure mode this script exists to end.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

WRAP = 78


def entry_for(version: str, changelog: str) -> str:
    """The CHANGELOG body for `version`, without its own heading."""
    start = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n", changelog, re.M)
    if not start:
        raise SystemExit(f"public_commit_message: CHANGELOG.md has no '## [{version}]' entry")
    rest = changelog[start.end():]
    nxt = re.search(r"^## \[", rest, re.M)
    return (rest[:nxt.start()] if nxt else rest).strip()


def reason_for(version: str, body: str) -> str:
    """The one-line reason for the SUBJECT, from the entry's opening bold thesis.

    The subject line is the only text GitHub shows beside files and in the commit list —
    a body-only reason left four releases reading as bare "release: vX.Y.Z" on every
    surface a visitor actually scans (caught by John on v0.39.0, the same defect the
    2026-08-24 release-title rule fixed one surface over). The entries open with a bold
    thesis by house convention; an entry that doesn't is an entry that never states its
    reason, and that refuses here rather than shipping bare.
    """
    # The thesis is the bold span that OPENS the entry. `\*\*(.+?)\*\*` looked right and was
    # not: `.+?` needs one character, so a literal `****` (an immediately-closed bold) does not
    # match empty, it skips forward and captures an unrelated LATER bold span as the "thesis".
    # A mechanics lens produced a 2476-char runaway that way (2026-09-04); it only got caught
    # because it happened to trip the length ceiling below, which is the wrong check saving us.
    # Requiring a non-asterisk first character makes `****` fail HERE, in the named refusal.
    m = re.match(r"\*\*([^*]+(?:\*[^*]+)*)\*\*", body, re.S)
    if not m:
        raise SystemExit(
            f"public_commit_message: the [{version}] entry has no opening **thesis** — "
            "the subject needs a one-line reason; start the entry with one in bold")
    reason = " ".join(m.group(1).split()).rstrip(".")
    if not reason:
        raise SystemExit(
            f"public_commit_message: the [{version}] entry's opening **thesis** is empty")
    reason = reason[0].lower() + reason[1:]
    subject = f"release: v{version}: {reason}"
    if len(subject) > 72:
        raise SystemExit(
            f"public_commit_message: subject would be {len(subject)} chars "
            f"(git's readable ceiling is ~72) — shorten the entry's opening thesis")
    return reason


def build(version: str, changelog: str) -> str:
    body = entry_for(version, changelog)
    if not body:
        raise SystemExit(f"public_commit_message: the [{version}] CHANGELOG entry is empty")
    header = f"release: v{version}: {reason_for(version, body)}"
    tail = (
        "Full history for this release, commit by commit, is on the internal mirror; this\n"
        "public branch carries one squashed commit per release by design.\n"
        "Every change here is described in CHANGELOG.md."
    )
    return f"{header}\n\n{body}\n\n{tail}\n"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        raise SystemExit("usage: public_commit_message.py X.Y.Z")
    root = Path(__file__).resolve().parent.parent
    print(build(argv[0], (root / "CHANGELOG.md").read_text(encoding="utf-8")), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
