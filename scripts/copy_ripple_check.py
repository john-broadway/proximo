#!/usr/bin/env python3
"""Copy-drift gate — pins copy SHAPE the way version_tools.py pins version strings.

Canon (what these rules mean and why): docs/plans/internal/COPY-CANON.md (internal-only; not in the public tree).
The rules, mechanically:

  - README carries exactly ONE "New in <current>" callout — REPLACEd per release,
    never stacked.
  - The "Status — the arena record" section holds exactly ONE 🩸 bullet — the current
    release (older releases live in CHANGELOG.md) — and the README stays under the
    line fence (MAX_README_LINES).
  - Every TOTAL tool-count claim agrees with the canonical count (the LobeHub
    manifest's tools array). Scoped-registration *examples* ("that pair = 194
    tools") are exempt by their context markers.
  - Every "N trust controls" claim (README, and each satellite, HTML tiles included)
    equals the rows of SECURITY.md's control table.
  - The tagline phrase "governed client for Proxmox" survives on every metadata surface
    (pyproject / server.json / lhm.plugin.json descriptions).

Usage:
  python scripts/copy_ripple_check.py check                    # in-repo gate (also in tests)
  python scripts/copy_ripple_check.py satellites PATH [PATH…]  # each file must carry vCURRENT

Consumed by tests/test_copy_ripple.py (always-on) and the release ripple. Stdlib only.
"""
from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import version_tools  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent

MAX_STATUS_BULLETS = 1  # 2026-07-16: Status carries ONLY the current release; history lives in CHANGELOG.md
MAX_README_LINES = 300  # accretion fence — line-creep was invisible when only bullets counted (283 at 2026-07-16)
TAGLINE_PHRASE = "governed client for Proxmox"   # John 2026-10-28: not a Proxmox MCP server
TAGLINE_SURFACES = ("pyproject.toml", "server.json", "lhm.plugin.json")

_NEW_IN_RE = re.compile(r"\*\*New in (\d+\.\d+\.\d+[^ ]*)")
_STATUS_BULLET_RE = re.compile(r"(?m)^- 🩸 \*\*(\d+\.\d+\.\d+[^*]*)\*\*")
# A total-count claim: "N tools" / "N MCP tools". The (?<!\+) excludes the per-release
# delta form ("+12 tools → …"), which is an increment, not a total.
_TOOL_COUNT_RE = re.compile(r"(?<!\+)\b(\d{2,4}) (?:MCP )?tools\b")
# Lines carrying these markers are scoped-registration EXAMPLES, not total-count claims.
_EXAMPLE_MARKERS = ("PROXIMO_SURFACES", "pair =")

# Receipt docs: every semver literal in them is a LIVE claim (a worked example the
# reader runs, a support-table row) and must be the current version. VERIFY.md's
# examples and SECURITY.md's support table sat two releases stale before this rule
# (caught by the 2026-07-13 truth audit). Three-part versions only — "PVE 9.2",
# "TLS 1.3", "Python 3.13" are platform versions, not release claims, and a dotted-quad
# ("127.0.0.1") is an address, not a version — the lookarounds keep both out.
VERSION_LITERAL_DOCS = ("VERIFY.md", "SECURITY.md", "docs/THREAT_MODEL.md")
_SEMVER_LITERAL_RE = re.compile(r"(?<![\w.])v?(\d+\.\d+\.\d+)(?!\.\d)")
# The control count: SECURITY.md's "| Control | Defends against |" table is the one list of
# controls, and every "N trust controls" claim counts its rows. The site's tile said 13 for a
# release after 0.45 retired LEASE and SCOPE, dropped MIRROR, split ENVELOPE and added TIER (12),
# because this gate pinned versions and tool counts only (2026-10-19). A claim is read from the
# text a reader sees: comments dropped, entities decoded, tags stripped to nothing (`1<b>3</b>`
# is 13; the tile `<div class="num">12</div><div class="label">trust controls</div>` is
# "12trust controls"), emphasis and hyphens gone; the number before or after the label, in
# digits or words to ninety-nine (the lens on this rule, 2026-10-19, read thirteen spellings
# of a stale 13 as clean).
_CONTROL_TABLE_HEAD = "| Control | Defends against |"
_UNITS = ("zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen "
          "fifteen sixteen seventeen eighteen nineteen").split()
_TENS = {w: 10 * i for i, w in enumerate("twenty thirty forty fifty sixty seventy eighty ninety".split(), 2)}
_WORDS = rf"(?:(?:{'|'.join(_TENS)})(?: (?:{'|'.join(_UNITS[1:10])}))?|{'|'.join(_UNITS)})"
_LABEL = r"(?:trust|security) controls?"
_CONTROL_CLAIM_RE = re.compile(  # "12 trust controls" | "trust controls: 12" (a year after the label is not one)
    rf"(?<![\w])(\d[\d,]*|{_WORDS})\+? ?{_LABEL}\b|\b{_LABEL} ?:? ?(\d{{1,3}}|{_WORDS})(?![\w,])", re.I)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
_TAG_RE = re.compile(r"<[^>]+>")
# The install badge: "> 📦 **`0.39.1`**: on [PyPI](...), [GitHub](.../tag/v0.39.1), ...".
# Matched as a whole LINE so every version literal on it is checked, backticks and tag URL both.
_INSTALL_BADGE_RE = re.compile(r"(?m)^> 📦 \*\*`\d+\.\d+\.\d+[^`]*`\*\*.*$")


def check_new_in(text: str, current: str) -> list[str]:
    hits = _NEW_IN_RE.findall(text)
    if not hits:
        return [f'README has no "New in {current}" callout — the ripple did not run.']
    problems: list[str] = []
    if len(hits) > 1:
        problems.append(
            f'README carries {len(hits)} "New in" blocks ({", ".join(hits)}) — '
            f"exactly one is allowed; REPLACE the callout, never stack releases."
        )
    if hits[0] != current:
        problems.append(
            f'README "New in {hits[0]}" does not match current version {current}.'
        )
    return problems


def check_install_badge(text: str, current: str) -> list[str]:
    """The README's install badge names the current version, in every literal on the line.

    The badge is the first line under "Install & run": the one place a visitor looks to
    answer "what version is this". It carried the version twice, once in backticks and once
    inside the GitHub release-tag URL, and NOTHING checked either. A mechanics lens set it
    to 0.31.0 on the 0.39.1 tree and this gate still answered "copy: consistent", exit 0,
    with the whole suite green (2026-09-04).

    Scoped to the badge LINE on purpose. The README's prose legitimately cites older
    versions ("0.27.0 closed a path..."), so widening VERSION_LITERAL_DOCS to the whole
    README would fire on history rather than on the claim.
    """
    m = _INSTALL_BADGE_RE.search(text)
    if not m:
        return [
            'README has no "📦 **`<version>`**:" install badge — the ripple cannot check it; '
            "if the badge moved, move this rule with it."
        ]
    line = m.group(0)
    stale = sorted({v for v in _SEMVER_LITERAL_RE.findall(line) if v != current})
    if stale:
        return [
            f"README install badge names {', '.join(stale)} but the current version is "
            f"{current} — the badge carries the version in the backticks AND in the release "
            f"tag URL; both move."
        ]
    return []


def check_status(text: str, current: str) -> list[str]:
    bullets = _STATUS_BULLET_RE.findall(text)
    if not bullets:
        return ["README Status section has no 🩸 bullets — did the section move?"]
    problems: list[str] = []
    if len(bullets) > MAX_STATUS_BULLETS:
        problems.append(
            f"README Status has {len(bullets)} 🩸 bullets — max is {MAX_STATUS_BULLETS}; "
            f"REPLACE the bullet — older releases live in CHANGELOG.md, not the README."
        )
    if bullets[0].strip() != current:
        problems.append(
            f"README Status top bullet is {bullets[0].strip()} — current is {current}."
        )
    return problems


def check_tool_counts(
    files: dict[str, str], canonical: int, current: str | None = None
) -> list[str]:
    problems: list[str] = []
    for name, text in files.items():
        for line in text.splitlines():
            if any(m in line for m in _EXAMPLE_MARKERS):
                continue
            bullet = _STATUS_BULLET_RE.match(line)
            if bullet and current is not None and bullet.group(1).strip() != current:
                # A non-current 🩸 Status bullet is pinned history — its total was
                # true at that release. Only the current bullet makes a live claim.
                continue
            for count in _TOOL_COUNT_RE.findall(line):
                if int(count) != canonical:
                    problems.append(
                        f"{name}: claims {count} tools but the canonical count is "
                        f"{canonical} (LobeHub manifest) — stale total-count claim."
                    )
    return problems


def check_version_literals(files: dict[str, str], current: str) -> list[str]:
    return [
        f"{name}: carries version literal {found} but the current release is {current} "
        f"— stale worked example / support row; refresh it with the release ripple."
        for name, text in files.items()
        for found in sorted(set(_SEMVER_LITERAL_RE.findall(text)))
        if found != current
    ]


def check_tagline(files: dict[str, str]) -> list[str]:
    return [
        f'{name}: tagline phrase "{TAGLINE_PHRASE}" is missing — the pitch line was '
        f"rewritten; restore the pinned description (see COPY-CANON.md)."
        for name, text in files.items()
        if TAGLINE_PHRASE not in text
    ]


def canonical_control_count(security: str) -> int | None:
    """The rows of SECURITY.md's control table, or None when there is no such table (or no row)."""
    lines = security.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(_CONTROL_TABLE_HEAD):
            rows = 0
            for row in lines[i + 2:]:  # past the |---| separator
                if not row.startswith("|"):
                    break
                rows += 1
            return rows or None
    return None


def _reader_text(text: str) -> str:
    """The words a reader sees, for a count claim: no comments, no markup, one space between."""
    text = _TAG_RE.sub("", _COMMENT_RE.sub(" ", text))
    text = re.sub(r"[*`_]", "", html.unescape(text)).replace("-", " ")
    return " ".join(text.split())


def _number(found: str) -> int:
    found = found.lower().replace(",", "")
    if found.isdigit():
        return int(found)
    tens, _, unit = found.partition(" ")
    return _TENS[tens] + (_UNITS.index(unit) if unit else 0) if tens in _TENS else _UNITS.index(found)


def check_control_counts(files: dict[str, str], canonical: int | None) -> list[str]:
    problems: list[str] = []
    for name, text in files.items():
        for before, after in _CONTROL_CLAIM_RE.findall(_reader_text(text)):
            found = before or after
            if canonical is None:
                problems.append(f"{name}: claims {found} trust controls but SECURITY.md has no "
                                f"control table to count — the claim cannot be checked.")
            elif _number(found) != canonical:
                problems.append(f"{name}: claims {found} trust controls but SECURITY.md's control "
                                f"table has {canonical} rows — stale control count.")
    return problems


def _security_text(root: Path) -> str:
    path = root / "SECURITY.md"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def check_satellite_text(text: str, current: str, name: str) -> list[str]:
    problems = check_control_counts({name: text}, canonical_control_count(_security_text(REPO_ROOT)))
    if current not in text:
        problems.append(f"{name}: does not mention {current} — satellite copy is stale.")
    return problems


def _canonical_tool_count(root: Path) -> int | None:
    manifest = root / "lhm.plugin.json"
    if not manifest.exists():
        return None
    data = json.loads(manifest.read_text(encoding="utf-8"))
    tools = data.get("tools")
    return len(tools) if isinstance(tools, list) else None


def check_repo(root: Path) -> list[str]:
    current = version_tools.read_pyproject_version(root)
    readme = (root / "README.md").read_text(encoding="utf-8")

    problems = check_new_in(readme, current)
    problems += check_install_badge(readme, current)
    problems += check_status(readme, current)

    readme_lines = readme.count("\n") + 1
    if readme_lines > MAX_README_LINES:
        problems.append(
            f"README is {readme_lines} lines — the fence is {MAX_README_LINES}. "
            f"Cut or move content (docs/, CHANGELOG); do not raise the fence casually."
        )

    canonical = _canonical_tool_count(root)
    if canonical is not None:
        # README plus every RENDERED surface that bakes a tool count into an image. The
        # architecture SVGs are embedded at the top of the README via raw.githubusercontent, so a
        # stale number there is a wrong number on the public front page — and it went stale for
        # nine days in exactly that way (900 while the truth was 905), because this gate only ever
        # read README.md. An image is a copy surface; it just cannot be grepped by a human.
        counted = {"README.md": readme}
        for svg in sorted(root.glob("docs/brand/*.svg")):
            counted[svg.relative_to(root).as_posix()] = svg.read_text(encoding="utf-8")
        problems += check_tool_counts(counted, canonical, current)

    tagline_files = {
        name: (root / name).read_text(encoding="utf-8")
        for name in TAGLINE_SURFACES
        if (root / name).exists()
    }
    problems += check_tagline(tagline_files)

    receipt_docs = {
        name: (root / name).read_text(encoding="utf-8")
        for name in VERSION_LITERAL_DOCS
        if (root / name).exists()
    }
    problems += check_version_literals(receipt_docs, current)
    security = _security_text(root)
    if canonical_control_count(security) is None:
        problems.append("SECURITY.md has no control table (`| Control | Defends against |`) — "
                        "every trust-controls claim counts its rows.")
    problems += check_control_counts({"README.md": readme}, canonical_control_count(security))
    return problems


def _main(argv: list[str]) -> int:
    if argv[:1] == ["check"]:
        problems = check_repo(REPO_ROOT)
    elif argv[:1] == ["satellites"] and len(argv) > 1:
        current = version_tools.read_pyproject_version(REPO_ROOT)
        problems = []
        for p in argv[1:]:
            path = Path(p)
            problems += check_satellite_text(
                path.read_text(encoding="utf-8"), current, path.name
            )
    else:
        print(__doc__)
        return 2
    for p in problems:
        print(f"COPY DRIFT: {p}", file=sys.stderr)
    if problems:
        return 1
    print("copy: consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
