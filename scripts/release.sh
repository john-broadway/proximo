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
