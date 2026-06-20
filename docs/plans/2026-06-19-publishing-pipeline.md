# Publishing Pipeline (Phase 1 — proximo on GitHub) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make proximo's release process drift-proof and tokenless — one command sets the version everywhere, a check fails the build on any version/tag/CHANGELOG mismatch, and PyPI publishes via OIDC (no token) behind a one-click human approval — plus the professional CI/security surface (secret scan, dependency-CVE scan, CodeQL, Dependabot, badges).

**Architecture:** Two layers. **Portable tool-checks** (plain commands: pytest, ruff, a version-consistency checker, gitleaks, pip-audit) form the muscle and will later run on any CI host. **GitHub-native features** (CodeQL, Dependabot, secret push-protection, Trusted Publishing + Environments) layer on top. A single Python module `scripts/version_tools.py` is the one source of truth for "where the version lives," consumed by the test, the release script, and the CI check.

**Tech Stack:** Python ≥3.12 (stdlib `tomllib`), pytest, ruff, bash, GitHub Actions, PyPI Trusted Publishing (OIDC).

## Global Constraints

- **Claude does ALL git.** John never runs a git command. (`feedback_john-doesnt-do-git`)
- **A push to public GitHub = John's go.** All local work (code, tests, YAML authoring, local validation, internal-gitea backup) is free/GREEN; the first push to `github.com/john-broadway/proximo` that lights up Actions waits for John's explicit go. (Rules of Engagement: public-facing publish is John's hand.)
- **NEVER force-push github `main`** — it is a squashed orphan, branch-protected (force/delete blocked). Releases fast-forward only.
- **Remote names are INVERTED in this repo:** `origin` = the INTERNAL gitea remote; `github` = PUBLIC GitHub. Internal backup → `git push origin …`; public push → `git push github …`. (This is the exact naming the global pre-push guard had to learn to classify by URL, not name. Confirm with `git remote -v` — do not assume `origin` is public.)
- **PyPI publish stays John's hand** — the `pypi` Environment's required-reviewer rule means the publish job pauses for John's approval click. Do not remove that gate.
- **PyPI Trusted Publisher + the PyPI-side config = John's hand** (his pypi.org account login). No token/secret is involved — that is the point.
- **Leak-audit before any public push** — no secrets, no internal IPs/hostnames, no `/root` paths, none of the redacted-marker shapes. (`feedback_secrets-by-reference-never-typed`)
- **Honest semver** — pre-1.0 stays `0.x`; a `>=1.0` bump must be intentional, never automatic.
- **proximo test command:** `cd . && uv run python -m pytest -q` (bare `uv run pytest` fails to spawn). Lint: `uv run ruff check src tests`. (`reference_proximo-dev-env`)
- **No standalone bandit** — proximo already runs flake8-bandit via ruff `S` (`[tool.ruff.lint] select`). Deliberate DRY deviation from the spec; CodeQL provides the deeper semantic layer.
- **Version lives in exactly two files:** `pyproject.toml` `[project].version` and `src/proximo/__init__.py` `__version__`. The CHANGELOG heading and the git tag mirror them. No other file hardcodes the version.
- **Publish asymmetry (intentional):** on a published Release the **GHCR image publishes immediately** (existing `release.yml`) while **PyPI waits for John's approval** (`release-pypi.yml`, `pypi` environment). The image is rebuildable/re-pushable; PyPI is the irreversible-ish artifact with the token-leak history — so PyPI gets the human gate, the image doesn't.
- **`release-pypi.yml` `build` runs no test job** — a conscious lean choice (the release is cut from a `main` commit CI already gated, plus the human approval). The GHCR `release.yml` *does* gate on tests; if symmetry is wanted, add a `needs:`-test job to the build. Decided by intent, not omission.

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `scripts/version_tools.py` | create | Single source of truth: read/check/set the version; CLI (`check`, `set`) |
| `tests/test_version_consistency.py` | create | Always-on gate: pyproject == `__init__` == CHANGELOG-has-entry; + drift-detection test |
| `tests/test_version_tools.py` | create | Unit tests for `set_version` (tmp sandbox) |
| `scripts/release.sh` | create | One-command release: set version + run local gate; never pushes |
| `.github/workflows/ci.yml` | modify | Add `version-consistency`, `gitleaks`, `pip-audit` jobs (keep test matrix) |
| `.github/workflows/codeql.yml` | create | CodeQL code scanning (Python) |
| `.github/workflows/release-pypi.yml` | create | Tokenless OIDC publish, gated by `pypi` Environment; TestPyPI dry-run path |
| `.github/dependabot.yml` | modify | Add the `pip` ecosystem (currently github-actions only) |
| `README.md` | modify | Add CI / CodeQL / PyPI / License badges |

**Phasing:** Tasks 1–6 + 7-author are **local/GREEN** (no GitHub). Task 7-config, Task 8, and all verification-by-push are **Phase B (John's go)**.

---

## PHASE A — local work (GREEN; commit locally + back up to internal gitea)

### Task 1: Version source-of-truth + always-on consistency gate

**Files:**
- Create: `scripts/version_tools.py`
- Create: `tests/test_version_consistency.py`

**Interfaces:**
- Produces (used by Tasks 2, 3, 7):
  - `read_pyproject_version(root: Path) -> str`
  - `read_init_version(root: Path) -> str`
  - `read_changelog_headings(root: Path) -> list[str]`
  - `top_released_changelog_version(root: Path) -> str | None`
  - `check_consistency(root: Path) -> list[str]`  (always-on; empty list == consistent)
  - `check_release(root: Path, tag_version: str) -> list[str]`  (release-time: tag == pyproject == __init__ == CHANGELOG top released heading)
  - `set_version(root: Path, version: str) -> None`  (added in Task 2)
  - CLI: `python scripts/version_tools.py check` (exit 1 on drift) / `release-check vX.Y.Z` / `set X.Y.Z`

- [ ] **Step 1: Write the failing test**

Create `tests/test_version_consistency.py`:

```python
"""The always-on version-drift gate: pyproject == __init__ == CHANGELOG-has-entry."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import version_tools  # noqa: E402


def test_live_repo_is_version_consistent():
    problems = version_tools.check_consistency(REPO_ROOT)
    assert problems == [], "version drift:\n" + "\n".join(problems)


def test_checker_flags_a_mismatch(tmp_path):
    # Build a tiny fake repo with a deliberate pyproject/__init__ mismatch.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1.2.3"\n', encoding="utf-8"
    )
    pkg = tmp_path / "src" / "proximo"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text("## [1.2.3]\n", encoding="utf-8")
    problems = version_tools.check_consistency(tmp_path)
    assert any("!=" in p for p in problems)


def test_checker_flags_missing_changelog_entry(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1.2.3"\n', encoding="utf-8"
    )
    pkg = tmp_path / "src" / "proximo"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text('__version__ = "1.2.3"\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text("## [Unreleased]\n", encoding="utf-8")
    problems = version_tools.check_consistency(tmp_path)
    assert any("CHANGELOG" in p for p in problems)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd . && uv run python -m pytest tests/test_version_consistency.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'version_tools'` (the module does not exist yet).

- [ ] **Step 3: Implement `scripts/version_tools.py`**

Create `scripts/version_tools.py`:

```python
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
            f"CHANGELOG has no heading for version {py!r} "
            f"(add a '## [{py}]' entry, or place it under '## [Unreleased]')"
        )
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
    if len(argv) == 2 and argv[0] == "set":
        set_version(REPO_ROOT, argv[1])
        print(f"set version -> {argv[1]}")
        return 0
    print("usage: version_tools.py [check | set X.Y.Z]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd . && uv run python -m pytest tests/test_version_consistency.py -q`
Expected: PASS (3 passed). The live repo is consistent at 0.6.0; the two synthetic tests prove the checker catches drift.

- [ ] **Step 5: Verify the CLI works**

Run: `cd . && uv run python scripts/version_tools.py check`
Expected: `version consistent: 0.6.0` (exit 0).

- [ ] **Step 6: Lint + commit**

Run: `cd . && uv run ruff check src tests`
Expected: no errors (the `# noqa: E402` covers the deliberate post-path-insert import).

```bash
git -C . add scripts/version_tools.py tests/test_version_consistency.py
git -C . commit -m "feat: version source-of-truth + always-on consistency gate"
```

---

### Task 2: `set_version` unit test + the `release.sh` tool

**Files:**
- Create: `tests/test_version_tools.py`
- Create: `scripts/release.sh`

**Interfaces:**
- Consumes: `version_tools.set_version`, `version_tools.read_pyproject_version`, `version_tools.read_init_version` (Task 1).
- Produces: `scripts/release.sh X.Y.Z` — sets version + runs the local gate, never pushes.

- [ ] **Step 1: Write the failing test for `set_version`**

Create `tests/test_version_tools.py`:

```python
"""Unit tests for version_tools.set_version (operates on a tmp sandbox)."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import version_tools  # noqa: E402


def _sandbox(tmp_path: Path, version: str) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        f'[build-system]\nrequires = ["hatchling"]\n\n'
        f'[project]\nname = "proximo-proxmox"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    pkg = tmp_path / "src" / "proximo"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    return tmp_path


def test_set_version_updates_both_files(tmp_path):
    root = _sandbox(tmp_path, "0.6.0")
    version_tools.set_version(root, "0.7.0")
    assert version_tools.read_pyproject_version(root) == "0.7.0"
    assert version_tools.read_init_version(root) == "0.7.0"


def test_set_version_is_idempotent(tmp_path):
    root = _sandbox(tmp_path, "0.7.0")
    version_tools.set_version(root, "0.7.0")
    assert version_tools.read_pyproject_version(root) == "0.7.0"
```

- [ ] **Step 2: Run to verify it passes** (set_version already exists from Task 1)

Run: `cd . && uv run python -m pytest tests/test_version_tools.py -q`
Expected: PASS (2 passed). (set_version was implemented in Task 1; this task adds its dedicated coverage and the release wrapper.)

- [ ] **Step 3: Write `scripts/release.sh`**

Create `scripts/release.sh`:

```bash
#!/usr/bin/env bash
# proximo release tool — make the MECHANICAL parts of a release deterministic.
#
# Sets the version in the ONE source (pyproject + __init__ via version_tools.py),
# then runs the local gate (consistency + lint + the version test). Writes NO prose:
# the CHANGELOG entry stays yours. NEVER pushes — stops at "ready".
#
# Usage: scripts/release.sh X.Y.Z     e.g.  scripts/release.sh 0.7.0
set -uo pipefail

V="${1:-}"
[ -n "$V" ] || { printf 'usage: release.sh X.Y.Z\n' >&2; exit 2; }

# Honest semver: pre-1.0 stays 0.x; a major>=1 must be intentional.
case "$V" in
  0.*) : ;;
  [1-9]*|*[!0-9.a-z-]*)
    if [ "${PROXIMO_RELEASE_FORCE_MAJOR:-}" != "1" ]; then
      printf 'release: refusing "%s" — pre-1.0 discipline keeps it 0.x; set PROXIMO_RELEASE_FORCE_MAJOR=1 to override.\n' "$V" >&2
      exit 1
    fi ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || { printf 'release: cannot cd to repo root\n' >&2; exit 1; }

printf '== release: setting version %s ==\n' "$V"
uv run python scripts/version_tools.py set "$V" || { printf 'release: version set failed\n' >&2; exit 1; }

if ! grep -q "## \[$V\]" CHANGELOG.md; then
  printf 'release: NOTE — CHANGELOG.md has no "## [%s]" entry yet. Write it (your words) before tagging.\n' "$V"
fi

printf '\n== gate ==\n'
RC=0
uv run python scripts/version_tools.py check || RC=1
uv run ruff check src tests || RC=1
uv run python -m pytest tests/test_version_consistency.py -q || RC=1

printf '\n----------------------------------------\n'
if [ "$RC" -eq 0 ]; then
  cat <<EOF
release: v$V set, gate GREEN.
NEXT (Claude does the git):
  1. write the CHANGELOG [$V] entry (human prose)
  2. commit, then: git tag v$V
  3. push branch + tag to github   (John's go — public push)
  4. create the GitHub Release for v$V
  5. approve the gated publish job  (John's click)
release.sh never pushes.
EOF
else
  printf 'release: GATE NOT GREEN — fix findings above before tagging.\n'
fi
exit "$RC"
```

- [ ] **Step 4: Make it executable and dry-run it at the current version (must be a safe no-op)**

```bash
chmod +x ./scripts/release.sh
cd . && ./scripts/release.sh 0.6.0
```
Expected: `== release: setting version 0.6.0 ==`, `set version -> 0.6.0`, gate GREEN block. Then confirm nothing actually changed:
Run: `git -C . status --porcelain pyproject.toml src/proximo/__init__.py`
Expected: empty (re-setting the same version is a no-op).

- [ ] **Step 5: Commit**

```bash
git -C . add tests/test_version_tools.py scripts/release.sh
git -C . commit -m "feat: scripts/release.sh — one-command version bump + local gate"
```

---

### Task 3: Extend CI — version-consistency + gitleaks + pip-audit jobs

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `python scripts/version_tools.py check` (Task 1).
- Produces: three new CI jobs that run on every push/PR.

- [ ] **Step 1: Replace `.github/workflows/ci.yml` with the extended version**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

# Explicit read-only floor (fork PRs already get this, but be unambiguous).
permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.12", "3.13"]
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install
        run: python -m pip install -e ".[dev]"
      - name: Lint
        run: ruff check .
      - name: Test
        run: pytest -q -ra

  version-consistency:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - name: Check version consistency (pyproject == __init__ == CHANGELOG)
        run: python scripts/version_tools.py check   # stdlib only, no install needed

  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0   # full history so gitleaks scans commits, not just the tree
      - name: Scan for committed secrets
        uses: gitleaks/gitleaks-action@v2
        # Free for public repos / personal accounts — no GITLEAKS_LICENSE needed.

  pip-audit:
    runs-on: ubuntu-latest
    # ON-RAMP: warn-only on the first pass so pre-existing advisories don't block the
    # first green release. Remove `continue-on-error` to make it a hard fail once the
    # baseline is clean (see plan Task 8 follow-up).
    continue-on-error: true
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - name: Audit dependencies for known CVEs
        uses: pypa/gh-action-pip-audit@v1.1.0
        with:
          local: true
```

- [ ] **Step 2: Validate YAML syntax locally**

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('./.github/workflows/ci.yml')); print('ci.yml OK')"`
Expected: `ci.yml OK`

- [ ] **Step 3: Commit** (verification-by-push happens in Phase B)

```bash
git -C . add .github/workflows/ci.yml
git -C . commit -m "ci: add version-consistency, gitleaks, pip-audit jobs"
```

---

### Task 4: CodeQL workflow

**Files:**
- Create: `.github/workflows/codeql.yml`

- [ ] **Step 1: Create `.github/workflows/codeql.yml`**

```yaml
name: CodeQL

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: "27 3 * * 1"   # weekly, Monday 03:27 UTC

permissions:
  contents: read

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # upload findings to the repo Security tab
      contents: read
    steps:
      - uses: actions/checkout@v6
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: python
      - name: Autobuild
        uses: github/codeql-action/autobuild@v3
      - name: Analyze
        uses: github/codeql-action/analyze@v3
```

- [ ] **Step 2: Validate YAML syntax locally**

Run: `python3 -c "import yaml; yaml.safe_load(open('./.github/workflows/codeql.yml')); print('codeql.yml OK')"`
Expected: `codeql.yml OK`

- [ ] **Step 3: Commit**

```bash
git -C . add .github/workflows/codeql.yml
git -C . commit -m "ci: add CodeQL code scanning (python)"
```

---

### Task 5: Dependabot — add the pip ecosystem

**Files:**
- Modify: `.github/dependabot.yml`

- [ ] **Step 1: Replace `.github/dependabot.yml`**

```yaml
version: 2
updates:
  # Keep GitHub Actions current — especially the SHA-pinned privileged actions in
  # the release workflows (login / build-push / attest / pypi-publish).
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    commit-message:
      prefix: ci

  # Keep Python dependencies current + surface CVE-driven bumps (reads pyproject.toml).
  - package-ecosystem: pip
    directory: /
    schedule:
      interval: weekly
    commit-message:
      prefix: deps
```

- [ ] **Step 2: Validate YAML syntax locally**

Run: `python3 -c "import yaml; yaml.safe_load(open('./.github/dependabot.yml')); print('dependabot.yml OK')"`
Expected: `dependabot.yml OK`

- [ ] **Step 3: Commit**

```bash
git -C . add .github/dependabot.yml
git -C . commit -m "ci: dependabot — add pip ecosystem"
```

---

### Task 6: README badges

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Inspect the current README header**

Run: `sed -n '1,12p' ./README.md`
Expected: see the title line (e.g. `# Proximo …`) so the badge block lands directly beneath it.

- [ ] **Step 2: Insert the badge block immediately after the title line (line 1)**

Add these four lines as a new paragraph right under the `# ...` title (exact owner/repo/dist names):

```markdown
[![CI](https://github.com/john-broadway/proximo/actions/workflows/ci.yml/badge.svg)](https://github.com/john-broadway/proximo/actions/workflows/ci.yml)
[![CodeQL](https://github.com/john-broadway/proximo/actions/workflows/codeql.yml/badge.svg)](https://github.com/john-broadway/proximo/actions/workflows/codeql.yml)
[![PyPI](https://img.shields.io/pypi/v/proximo-proxmox.svg)](https://pypi.org/project/proximo-proxmox/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
```

- [ ] **Step 3: Verify the badge block reads cleanly**

Run: `sed -n '1,8p' ./README.md`
Expected: title line, blank line, the four badge lines.

- [ ] **Step 4: Commit**

```bash
git -C . add README.md
git -C . commit -m "docs: add CI / CodeQL / PyPI / license badges"
```

---

### Task 7 (author): Trusted-Publishing release workflow

**Files:**
- Create: `.github/workflows/release-pypi.yml`

**Interfaces:**
- Consumes: `pyproject.toml` version; `scripts/version_tools.py check`; the `pypi` / `testpypi` GitHub Environments (configured in Phase B).
- Produces: a gated, tokenless publish triggered on a published Release; a `workflow_dispatch` → TestPyPI dry-run path.

- [ ] **Step 1: Create `.github/workflows/release-pypi.yml`**

```yaml
name: Release — PyPI (Trusted Publishing)

# Tokenless publish to PyPI via OIDC, gated behind the `pypi` Environment's
# required-reviewer rule (John approves before anything goes public).
#   - real release: when a GitHub Release is published
#   - dry run:      workflow_dispatch -> TestPyPI (prove the OIDC path first)
on:
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      target:
        description: "Where to publish"
        required: true
        default: testpypi
        type: choice
        options: [testpypi, pypi]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"

      - name: Verify tag matches package version (real releases only)
        if: github.event_name == 'release'
        run: |
          python scripts/version_tools.py check
          tag="${GITHUB_REF_NAME#v}"
          ver="$(python -c 'import tomllib,pathlib; print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])')"
          echo "tag=$tag  version=$ver"
          test "$tag" = "$ver" || { echo "::error::release tag '$tag' != package version '$ver'"; exit 1; }

      - name: Build sdist + wheel
        run: |
          python -m pip install build
          python -m build

      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

  publish-testpypi:
    needs: build
    if: github.event_name == 'workflow_dispatch' && inputs.target == 'testpypi'
    runs-on: ubuntu-latest
    environment: testpypi
    permissions:
      id-token: write   # OIDC — no token/secret
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          repository-url: https://test.pypi.org/legacy/

  publish-pypi:
    needs: build
    if: github.event_name == 'release' || (github.event_name == 'workflow_dispatch' && inputs.target == 'pypi')
    runs-on: ubuntu-latest
    environment: pypi    # required-reviewer rule pauses here for John's approval
    permissions:
      id-token: write    # OIDC — no token/secret
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/
      - uses: pypa/gh-action-pypi-publish@release/v1
```

- [ ] **Step 2: Validate YAML syntax locally**

Run: `python3 -c "import yaml; yaml.safe_load(open('./.github/workflows/release-pypi.yml')); print('release-pypi.yml OK')"`
Expected: `release-pypi.yml OK`

- [ ] **Step 3: Commit**

```bash
git -C . add .github/workflows/release-pypi.yml
git -C . commit -m "ci: tokenless OIDC PyPI publish, gated by the pypi environment"
```

- [ ] **Step 4: Leak-audit the whole branch diff before any push**

Run:
```bash
git -C . diff main...HEAD | grep -nE '172\.30\.|10\.4\.|\.lan|gitea@|bff|/root/|ghp_|pypi-|AAAA[0-9A-Za-z]|BEGIN [A-Z ]*PRIVATE KEY' || echo "leak-audit: clean"
```
Expected: `leak-audit: clean`. (If anything matches, stop and scrub before Phase B.)

- [ ] **Step 5: Back up the branch to internal gitea** (GREEN — internal, not public)

```bash
git -C . push origin ci/publishing-pipeline   # origin = INTERNAL gitea
```
(The global pre-push guard passes this as internal because the `origin` URL is the internal gitea, not github.com.)

---

## PHASE B — GitHub (requires John's go) + one-time config

> **GATE:** Do not start Phase B until John gives the go to push to public GitHub.

### Task 8: Stand up the GitHub config, prove the pipeline, ship the first gated release

**Files:** none (config + verification).

**One-time config — split by whose hand:**

- [ ] **Step 1 (Claude, via gh): create the working branch on GitHub and watch CI**

```bash
git -C . push github HEAD:ci/publishing-pipeline   # github = PUBLIC
gh -R john-broadway/proximo run list --branch ci/publishing-pipeline
gh -R john-broadway/proximo run watch
```
Expected: `test` (3.12/3.13), `version-consistency`, `gitleaks` green; `pip-audit` may report findings but does not fail (warn-only); `codeql` runs and uploads to the Security tab.

> ⚠️ **CodeQL default-vs-advanced conflict.** If *default* CodeQL setup is already enabled on the repo (Settings → Code security → Code scanning), the advanced `codeql.yml` workflow will error with a setup conflict. Check first: `gh api repos/john-broadway/proximo/code-scanning/default-setup --jq '.state'` — if it's `configured`, disable default setup in the web UI before relying on the workflow (they can't both run).

- [ ] **Step 2 (Claude): prove the gate actually catches drift**

On a throwaway branch, introduce a deliberate mismatch and confirm CI goes RED:
```bash
git -C . checkout -b drift-proof ci/publishing-pipeline
cd . && uv run python -c "import sys; sys.path.insert(0,'scripts'); import version_tools, pathlib; version_tools.set_version(pathlib.Path('.'), '0.6.1')"  # __init__/pyproject now 0.6.1, CHANGELOG still 0.6.0 -> drift
git -C . commit -am "test: deliberate version drift (must fail CI)"
git -C . push github drift-proof   # github = PUBLIC
gh -R john-broadway/proximo run watch
```
Expected: `version-consistency` job FAILS (proves the guard guards). Then delete the throwaway branch:
```bash
git -C . push github --delete drift-proof
git -C . checkout ci/publishing-pipeline
```

- [ ] **Step 3 (Claude, via gh OR John via web): create the `testpypi` and `pypi` Environments**

Web (clearest): repo → Settings → Environments → New environment.
- `testpypi` — no protection rule needed.
- `pypi` — add **Required reviewers** → `john-broadway`. This is the approval gate.

Or via gh API (Claude can run; `pypi` reviewer needs john-broadway's numeric user id from `gh api user --jq .id`):
```bash
gh api -X PUT repos/john-broadway/proximo/environments/testpypi >/dev/null && echo "testpypi env created"
JBID="$(gh api users/john-broadway --jq .id)"
gh api -X PUT repos/john-broadway/proximo/environments/pypi \
  -F "reviewers[][type]=User" -F "reviewers[][id]=${JBID}" >/dev/null && echo "pypi env created with required reviewer"
```

> 🔴 **CRITICAL — the approval gate fails OPEN silently.** `environment: pypi` only pauses for approval *if that environment already exists with a required-reviewer rule.* If a release fires before this step — or the rule didn't take — GitHub **auto-creates the environment with no protection and publishes immediately.** The workflow file looks identical either way; nothing in it can enforce this. So **verify the rule is live before cutting ANY release** — treat this as a hard precondition, not an assumption:
> ```bash
> gh api repos/john-broadway/proximo/environments/pypi --jq '.protection_rules'
> ```
> Expected: a non-empty array containing a `required_reviewers` rule with `john-broadway`. If it's empty/missing, the gate is OFF — do not release until it shows the reviewer.

- [ ] **Step 4 (JOHN's hand — his PyPI account): add the Trusted Publishers**

No token, no secret — just declaring which workflow may publish. On **pypi.org**: project `proximo-proxmox` → Manage → Publishing → Add a new pending/trusted publisher (GitHub):
- Owner: `john-broadway`
- Repository: `proximo`
- Workflow name: `release-pypi.yml`
- Environment: `pypi`

Repeat on **test.pypi.org** with Environment: `testpypi`.

(Claude provides these exact values; John clicks. If `proximo-proxmox` already exists on TestPyPI under a different owner, use a one-off `workflow_dispatch` name collision check first.)

- [ ] **Step 5 (Claude, via gh): enable secret-scanning + push-protection**

```bash
gh api -X PATCH repos/john-broadway/proximo \
  -f 'security_and_analysis[secret_scanning][status]=enabled' \
  -f 'security_and_analysis[secret_scanning][push_protection][status]=enabled' \
  >/dev/null && echo "secret-scanning + push-protection enabled"
```
Expected: confirmation line. (Free on public repos.)

- [ ] **Step 6 (Claude): TestPyPI dry-run — prove the OIDC path end to end**

```bash
gh -R john-broadway/proximo workflow run release-pypi.yml --ref ci/publishing-pipeline -f target=testpypi
gh -R john-broadway/proximo run watch
```
Expected: `build` then `publish-testpypi` green; the package appears at `https://test.pypi.org/project/proximo-proxmox/`. This proves tokenless publish works before we trust prod.

> ⚠️ **Use a throwaway version for the dry-run.** TestPyPI rejects a re-upload of an existing version ("file already exists"). The branch currently builds `0.6.0`; if that's already on TestPyPI the dry-run fails on upload, not on OIDC. Bump the branch to an unused dev version (e.g. `0.6.1.dev0` via `scripts/release.sh`) for the dry-run, or pick any version not yet on TestPyPI.

- [ ] **Step 7 (Claude): merge the branch to main**

```bash
git -C . checkout main
git -C . merge --ff-only ci/publishing-pipeline
git -C . push github main   # github = PUBLIC; fast-forward only; NEVER force
```

- [ ] **Step 8 (Claude + John): cut the first real gated release**

```bash
cd . && ./scripts/release.sh 0.6.1   # or the next intended version
# write the CHANGELOG [0.6.1] entry (human prose), then:
git -C . commit -am "release: 0.6.1"
git -C . tag v0.6.1
git -C . push github main --tags   # github = PUBLIC
gh -R john-broadway/proximo release create v0.6.1 --generate-notes
```
Then the `release-pypi.yml` `publish-pypi` job **pauses for approval**. **John clicks Approve** in the run's review prompt.
Expected: after approval, tokenless publish to PyPI succeeds; GHCR image builds via the existing `release.yml`.

- [ ] **Step 9 (Claude): acceptance — install the published artifact on a fresh venv**

```bash
python3 -m venv /tmp/proximo-accept && /tmp/proximo-accept/bin/pip install -q "proximo-proxmox==0.6.1"
/tmp/proximo-accept/bin/python -c "import proximo; print('installed:', proximo.__version__)"
```
Expected: `installed: 0.6.1` — matches the release. (Run-it-like-an-end-user: the published wheel, not the dev tree.)

---

## Self-Review

**1. Spec coverage** — every spec component maps to a task:
- Release tool → Task 2. Version-consistency gate (both modes) → Task 1 (always-on) + Task 7 build-step (release-time tag check). CI security trio → Task 3 (gitleaks, pip-audit; bandit intentionally dropped — ruff `S`). CodeQL → Task 4. Dependabot pip → Task 5. Secret push-protection → Task 8 Step 5. Trusted Publishing + Environments → Task 7 + Task 8 Steps 3–4, 6, 8. Badges → Task 6. TestPyPI dry-run → Task 8 Step 6. Acceptance/fresh-venv → Task 8 Step 9. Warn-only on-ramp → Task 3 (`continue-on-error`). No spec requirement is unmapped.

**2. Placeholder scan** — no TBD/TODO/"add error handling"/"similar to Task N". All code blocks are complete; the only intentional human-prose gap (the CHANGELOG entry) is called out as deliberately human, with the script reminding rather than faking it.

**3. Type/name consistency** — `version_tools` functions (`read_pyproject_version`, `read_init_version`, `read_changelog_headings`, `top_released_changelog_version`, `check_consistency`, `set_version`) are named identically everywhere they appear (Tasks 1, 2, 7, 8). CLI verbs (`check`, `set`) match across release.sh, ci.yml, and version_tools.py. Repo/dist names (`john-broadway/proximo`, `proximo-proxmox`) consistent in badges, workflows, and trusted-publisher config.

**Note on TDD shape for non-pytest tasks:** workflow YAML can only truly run on GitHub, so Tasks 3–7 use "validate locally → push → observe the run" as their test cycle (Phase B), and Task 8 Step 2 is an explicit adversarial proof that the gate fails on real drift.
