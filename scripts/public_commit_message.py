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


def build(version: str, changelog: str) -> str:
    body = entry_for(version, changelog)
    if not body:
        raise SystemExit(f"public_commit_message: the [{version}] CHANGELOG entry is empty")
    header = f"release: v{version}"
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
