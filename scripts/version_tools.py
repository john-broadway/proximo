#!/usr/bin/env python3
"""Single source of truth for "where proximo's version lives" + a drift checker.

Consumed by:
  - tests/test_version_consistency.py  (the always-on gate)
  - scripts/release.sh                 (set_version on release)
  - .github/workflows                  (python scripts/version_tools.py check)

Stdlib only — tomllib ships on the project's Python floor (>=3.12).
"""
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = "pyproject.toml"
INIT = "src/proximo/__init__.py"
CHANGELOG = "CHANGELOG.md"

_INIT_RE = re.compile(r'(?m)^__version__\s*=\s*"([^"]+)"')
_HEADING_RE = re.compile(r'(?m)^##\s*\[([^\]]+)\]')


def read_pyproject_version(root: Path) -> str:
    data = tomllib.loads((root / PYPROJECT).read_text(encoding="utf-8"))
    return data["project"]["version"]


def read_init_version(root: Path) -> str:
    m = _INIT_RE.search((root / INIT).read_text(encoding="utf-8"))
    if not m:
        raise ValueError(f"no __version__ found in {INIT}")
    return m.group(1)


def read_changelog_headings(root: Path) -> list[str]:
    text = (root / CHANGELOG).read_text(encoding="utf-8")
    return [h.strip() for h in _HEADING_RE.findall(text)]


def top_released_changelog_version(root: Path) -> str | None:
    for h in read_changelog_headings(root):
        if h.lower() != "unreleased":
            return h
    return None


def check_consistency(root: Path) -> list[str]:
    """Always-on checks. Returns problems; empty == consistent."""
    problems: list[str] = []
    py = read_pyproject_version(root)
    init = read_init_version(root)
    if py != init:
        problems.append(f"pyproject version {py!r} != __init__ __version__ {init!r}")
    if py not in set(read_changelog_headings(root)):
        problems.append(
            f"CHANGELOG has no '## [{py}]' heading for version {py!r} "
            f"(add the release entry — a bare '## [Unreleased]' does not satisfy this)"
        )
    return problems


def check_release(root: Path, tag_version: str) -> list[str]:
    """Release-time checks: tag == pyproject == __init__ == CHANGELOG top released heading.

    Stricter than check_consistency: the git tag must match, and the version must be
    the TOP released CHANGELOG entry (catches out-of-order / stale headings).
    """
    problems = check_consistency(root)
    py = read_pyproject_version(root)
    if tag_version != py:
        problems.append(f"git tag version {tag_version!r} != pyproject version {py!r}")
    top = top_released_changelog_version(root)
    if top != py:
        problems.append(f"CHANGELOG top released heading {top!r} != version {py!r}")
    return problems


def set_version(root: Path, version: str) -> None:
    """Rewrite the version in pyproject.toml and src/proximo/__init__.py."""
    pp = root / PYPROJECT
    pp_new, n = re.subn(
        r'(?m)^version\s*=\s*"[^"]*"', f'version = "{version}"',
        pp.read_text(encoding="utf-8"), count=1,
    )
    if n != 1:
        raise ValueError(f"expected exactly one top-level version= in {PYPROJECT}, found {n}")
    pp.write_text(pp_new, encoding="utf-8")

    init = root / INIT
    init_new, n = re.subn(
        r'(?m)^__version__\s*=\s*"[^"]*"', f'__version__ = "{version}"',
        init.read_text(encoding="utf-8"), count=1,
    )
    if n != 1:
        raise ValueError(f"expected exactly one __version__= in {INIT}, found {n}")
    init.write_text(init_new, encoding="utf-8")


def _main(argv: list[str]) -> int:
    if argv[:1] == ["check"]:
        problems = check_consistency(REPO_ROOT)
        if problems:
            print("version drift:")
            for p in problems:
                print(f"  - {p}")
            return 1
        print(f"version consistent: {read_pyproject_version(REPO_ROOT)}")
        return 0
    if len(argv) == 2 and argv[0] == "release-check":
        tag = argv[1]
        tag = tag[1:] if tag.startswith("v") else tag
        problems = check_release(REPO_ROOT, tag)
        if problems:
            print("release drift:")
            for p in problems:
                print(f"  - {p}")
            return 1
        print(f"release consistent: {read_pyproject_version(REPO_ROOT)}")
        return 0
    if len(argv) == 2 and argv[0] == "set":
        set_version(REPO_ROOT, argv[1])
        print(f"set version -> {argv[1]}")
        return 0
    print("usage: version_tools.py [check | release-check vX.Y.Z | set X.Y.Z]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
