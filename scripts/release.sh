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
# Hash-pinned lockfiles must match uv.lock — CI/Docker install them with --require-hashes.
./scripts/gen_requirements.sh >/dev/null 2>&1 || { printf 'release: gen_requirements.sh failed\n' >&2; RC=1; }
# Diff uv.lock too: a lock rewritten so its EXPORTS coincide (same pins, different lock metadata)
# would otherwise slip through unreviewed, since --frozen exports from whatever lock is committed.
git diff --exit-code --stat requirements/ uv.lock || { printf 'release: requirements/ or uv.lock drifted — commit the regenerated files.\n' >&2; RC=1; }
# lhm.plugin.json is generated (cold-start tool surface + version) — regenerate and fail on
# drift BEFORE TOOLS.md, which derives FROM it. (Lens catch 2026-08-12: a skipped manual
# manifest regen let both surfaces go stale together while the TOOLS.md gate passed green.)
uv run python scripts/gen_lobehub_manifest.py >/dev/null 2>&1 || { printf 'release: gen_lobehub_manifest.py failed\n' >&2; RC=1; }
git diff --exit-code --stat lhm.plugin.json || { printf 'release: lhm.plugin.json drifted — commit the regenerated file.\n' >&2; RC=1; }
# TOOLS.md is generated (version banner + tool surface) — regenerate and fail on drift.
# (Redteam catch on v0.21.1: the banner shipped one release stale; nothing gated it.)
uv run python scripts/gen_tools_doc.py >/dev/null 2>&1 || { printf 'release: gen_tools_doc.py failed\n' >&2; RC=1; }
git diff --exit-code --stat docs/TOOLS.md || { printf 'release: docs/TOOLS.md drifted — commit the regenerated file.\n' >&2; RC=1; }
uv run ruff check . || RC=1   # full repo — match CI's `ruff check .` (src+tests+scripts), not a subset
uv run python -m pytest tests/test_version_consistency.py -q || RC=1
uv run python scripts/release_leak_audit.py audit || RC=1   # model the public tree; refuse internal-infra leaks
# Public CI also runs gitleaks (entropy rules our leak-audit doesn't model — a mixed-case test
# sentinel failed CI on v0.13.0). Run the same scan over the modeled public tree when available.
if command -v gitleaks >/dev/null 2>&1; then
  GLTMP="$(mktemp -d)"
  if T="$(uv run python scripts/release_leak_audit.py build-tree 2>/dev/null | tail -1)" \
     && git archive "$T" | tar -x -C "$GLTMP"; then
    gitleaks detect --no-git --source "$GLTMP" --exit-code=2 || RC=1
  else
    printf 'release: could not model the public tree for gitleaks\n' >&2; RC=1
  fi
  rm -rf "$GLTMP"
else
  printf 'release: WARNING — gitleaks not installed; public CI runs it and WILL fail on entropy hits this gate never saw.\n' >&2
fi

printf '\n----------------------------------------\n'
if [ "$RC" -eq 0 ]; then
  cat <<EOF
release: v$V set, gate GREEN.
NEXT (Claude does the git; John's go for the public push):
  1. write the CHANGELOG [$V] entry (human prose)
  2. commit, then: git tag v$V   (internal gitea: git push origin main --tags)
  3. publish to github via the curated FF tree (strips .gitea/, refuses leaks):
       T=\$(uv run python scripts/release_leak_audit.py build-tree) || exit 1
       M=\$(uv run python scripts/public_commit_message.py $V) || exit 1   # the CHANGELOG entry IS the reason
       C=\$(printf '%s' "\$M" | git commit-tree "\$T" -p github/main -F -)
       git push github "\$C:main"          # fast-forward, NEVER --force
  4. gh release create v$V                 # fires the signed GHCR build
  5. approve the gated PyPI publish job     (John's click — tokenless OIDC)
release.sh never pushes.
EOF
else
  printf 'release: GATE NOT GREEN — fix findings above before tagging.\n'
fi
exit "$RC"
