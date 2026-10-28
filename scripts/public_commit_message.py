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

The message ENDS with a `Co-authored-by:` trailer for every author and co-author of the internal
range (the previous CHANGELOG version's tag to HEAD) other than the minting identity. The curated
commit is the only commit the public graph ever sees, so without the trailers an outside
contributor's work goes public under the owner's name: 0.49.1 shipped RavenLiao's #107 that way,
580 of 580 lines, and the contributors graph never saw him (John, 2026-10-27). The graph reads
commit author and Co-authored-by on main; this is the one place the public commit can say who.

Usage:  python scripts/public_commit_message.py 0.37.0
Prints the message to stdout. Exits non-zero (printing nothing) if the version has no CHANGELOG
entry, so a caller piping this into `git commit-tree` fails loud rather than committing an empty
body — the failure mode this script exists to end.
"""
from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path

WRAP = 78

# `Name <email>` on one line: a trailer value that is not this shape is not minted, because a
# newline inside it would smuggle a second trailer and a bare name credits nobody the graph can find.
_IDENT = re.compile(r"^([^<>\n]+?)\s*<([^<>@\s]+@[^<>@\s]+)>$")


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


def coauthor_trailers(idents: Iterable[str], *, owner: str) -> list[str]:
    """`Co-authored-by:` lines for every ident but the owner's, each person once.

    `idents` are `Name <email>` strings: the author of every commit in the release range plus
    every Co-authored-by value those commits already carry. The owner is the curated commit's
    author, so naming them again would be noise; everyone else is named exactly once, keyed by
    name and email (case-folded), first spelling kept. Two names on one address stay two lines:
    the Claude models share one address, and which one wrote is part of the record. A
    malformed ident refuses: the mint never guesses.
    """
    om = _IDENT.match(owner.strip())
    if not om:
        raise SystemExit(f"public_commit_message: owner ident is not 'Name <email>': {owner!r}")
    owner_email = om.group(2).casefold()
    seen: set[tuple[str, str]] = set()
    out: list[str] = []
    for raw in idents:
        m = _IDENT.match(raw.strip())
        if not m:
            raise SystemExit(f"public_commit_message: author ident is not 'Name <email>': {raw!r}")
        name, email = m.group(1).strip(), m.group(2)
        key = (name.casefold(), email.casefold())
        if email.casefold() == owner_email or key in seen:
            continue
        seen.add(key)
        out.append(f"Co-authored-by: {name} <{email}>")
    return out


def previous_version(version: str, changelog: str) -> str | None:
    """The CHANGELOG version right below `version`, or None when it is the first entry."""
    heads = re.findall(r"^## \[([^\]]+)\]", changelog, re.M)
    if version.lower() == "unreleased":
        raise SystemExit("public_commit_message: 'Unreleased' is not a release; name the version")
    heads = [h for h in heads if h.lower() != "unreleased"]
    if version not in heads:
        raise SystemExit(f"public_commit_message: CHANGELOG.md has no '## [{version}]' entry")
    i = heads.index(version)
    return heads[i + 1] if i + 1 < len(heads) else None


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run git in `root` with a fixed argv (the one S603/S607 site; git is resolved from PATH on
    purpose: this script runs on the release box, in CI, and wherever a maintainer mints)."""
    return subprocess.run(["git", *args], capture_output=True, text=True, cwd=root)  # noqa: S603, S607


def range_idents(root: Path, prev: str | None) -> list[str]:
    """Every author and Co-authored-by ident of the commits in v<prev>..HEAD, in history order.

    A missing previous tag refuses rather than silently minting with no trailers: that is the
    exact failure this exists to end."""
    if prev is None:
        return []
    tag = f"v{prev}"
    if _git(root, "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}").returncode != 0:
        raise SystemExit(f"public_commit_message: no local tag {tag}; the release range cannot be read")
    log = _git(root, "log", "--reverse",
               "--format=%an <%ae>%n%(trailers:key=Co-authored-by,valueonly)", f"{tag}..HEAD")
    if log.returncode != 0:
        raise SystemExit(f"public_commit_message: git log {tag}..HEAD failed: {log.stderr.strip()}")
    return [ln.strip() for ln in log.stdout.splitlines() if ln.strip()]


def minting_ident(root: Path) -> str:
    """The `Name <email>` git will record as this commit's author: `git var GIT_AUTHOR_IDENT`,
    which honours the env overrides commit-tree honours, so the exclusion cannot drift from the
    author line. A box with no identity refuses; it could not mint the commit either."""
    r = _git(root, "var", "GIT_AUTHOR_IDENT")
    m = re.match(r"^(.*<[^<>]+>)\s+\d+\s+[+-]\d{4}$", r.stdout.strip()) if r.returncode == 0 else None
    if not m:
        raise SystemExit("public_commit_message: git has no author identity here; who mints this commit?")
    return m.group(1)


def build(version: str, changelog: str, coauthors: Iterable[str] = ()) -> str:
    body = entry_for(version, changelog)
    if not body:
        raise SystemExit(f"public_commit_message: the [{version}] CHANGELOG entry is empty")
    header = f"release: v{version}: {reason_for(version, body)}"
    tail = (
        "Full history for this release, commit by commit, is on the internal mirror; this\n"
        "public branch carries one squashed commit per release by design.\n"
        "Every change here is described in CHANGELOG.md."
    )
    trailers = list(coauthors)
    block = ("\n\n" + "\n".join(trailers)) if trailers else ""
    return f"{header}\n\n{body}\n\n{tail}{block}\n"


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        raise SystemExit("usage: public_commit_message.py X.Y.Z")
    root = Path(__file__).resolve().parent.parent
    version = argv[0]
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    idents = range_idents(root, previous_version(version, changelog))
    trailers = coauthor_trailers(idents, owner=minting_ident(root))
    print(build(version, changelog, trailers), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
