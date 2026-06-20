# Publishing Pipeline — Design Spec

**Date:** 2026-06-19
**Status:** Approved (Phase 1 scope) — pending spec review
**Authors:** John Broadway, Claude (Anthropic)
**Applies to:** proximo first (the proving ground), then the wider fleet

---

## Plain-language summary (read this part)

Right now, every release leans on a human remembering to keep the version number
the same in ~4 places (`pyproject.toml`, the code, the git tag, the CHANGELOG) —
and to run the right publish steps by hand. When memory slips, you get drift:
wrong version, a tag with no release, stale docs. There's also a **token** in the
PyPI publish path that has leaked twice.

This spec makes a machine do the remembering:

1. **One command** sets the version everywhere — no hand-editing.
2. **A check that fails loud** if the version, tag, and CHANGELOG ever disagree.
3. **Tokenless publishing** — PyPI accepts a cryptographic per-run identity from
   the CI instead of a secret, so there is no token to leak. It still **pauses for
   your one-click approval** before anything goes public.
4. **The "professional" layer** — security scans (secrets, dependency CVEs, code
   analysis) and status badges, the things that make a repo look "with it."

Your only two touch-points stay: saying *"ship X.Y.Z"* and clicking *approve*.
Everything else is the machine's job.

---

## Goals

- Eliminate version/tag/doc/CHANGELOG drift by **enforcing** consistency (a check,
  not discipline).
- Replace the leak-prone PyPI **token** with **Trusted Publishing (OIDC)** — zero
  secret — while keeping a **human approval gate** before any public publish.
- Add a full, professional CI/security surface: tests, lint, secret scan,
  dependency-vulnerability scan, code scanning, and README badges.
- Build it as a **portable pattern** (most checks are plain commands) so the same
  workflow can later run on both GitHub and the internal mirror.

## Non-goals (this phase)

- Standing up the internal self-hosted runner — **Phase 2**.
- Rolling the pattern out to other repos — **Phase 3**.
- Removing the human approval gate — **never**; it is intentional (publishing and
  secret-minting stay a human hand by design).

---

## Architecture: two layers

**Layer 1 — portable tool-checks (the muscle).** These are just commands, so they
run identically on any CI runner, GitHub or otherwise:

- `pytest` — tests
- `ruff` — lint
- **version-consistency gate** — the anti-drift check
- **gitleaks** — secret scanning
- **pip-audit** — dependency vulnerability scanning
- **flake8-bandit (via ruff `S`)** — Python security linting; proximo already enables
  the `S` ruleset in `[tool.ruff.lint]`, so this runs today with no extra job. (A
  standalone `bandit` job would be redundant; CodeQL adds the deeper semantic layer.)

**Layer 2 — GitHub-native features (the bonus, layered on top).** No portable
equivalent, so they live on GitHub and the Layer-1 tools cover the same ground
everywhere else:

- **CodeQL** — GitHub's hosted code scanning (Security tab + badge)
- **Dependabot** — automated dependency-bump PRs + alerts
- **Secret push-protection** — GitHub blocks a push that contains a token
- **Trusted Publishing + Environments** — tokenless, human-gated PyPI publish

---

## Components (Phase 1 — proximo on GitHub)

1. **Release tool — `scripts/release.sh`** (modeled on maude's proven one).
   - Single source of truth = `pyproject.toml` `version`.
   - Propagates that version to `src/proximo/__init__.py` `__version__`; stamps any
     dated headers; runs the local gate (tests + lint + version check).
   - Refuses an accidental pre-1.0 → 1.0+ major bump unless explicitly forced
     (honest-semver discipline).
   - **Writes no prose** — the CHANGELOG entry stays human, in your words.
   - **Never pushes** — stops at "ready."

2. **Version-consistency gate — `tests/test_version_consistency.py`** (+ CI jobs).
   Two modes, because the git tag only exists at release time:
   - **Always-on (every push/PR):** `pyproject.toml` `version` ==
     `src/proximo/__init__.py` `__version__`, **and** the CHANGELOG contains a
     heading for that version (released, or under `## [Unreleased]`). These should
     never disagree regardless of release state. Runs as a unit test.
   - **Release-time (on a `vX.Y.Z` tag push / published Release):** the tag's
     version == `pyproject` == `__init__` == the CHANGELOG **top released heading**
     (first `## [X.Y.Z]` that is not `Unreleased`). The git tag is the most
     drift-prone of the four, so it is checked precisely at the moment it is minted.

   Either mode fails the build on a mismatch — nothing publishes on a red gate.

3. **CI workflow — extend `.github/workflows/ci.yml`.** Keep the existing
   py3.12/3.13 test+lint matrix; add jobs: `gitleaks`, `pip-audit`,
   `version-consistency`. (No standalone `bandit` — ruff `S` already covers it.)
   Read-only token floor stays.

4. **CodeQL — `.github/workflows/codeql.yml`.** GitHub code scanning for Python,
   on push/PR + a weekly schedule.

5. **Dependabot — extend `.github/dependabot.yml`.** Add the `pip` ecosystem
   (today it only covers `github-actions`).

6. **Repo security settings (one-time).** Enable secret-scanning + push-protection
   (repo setting; toggled via `gh`/API or the web UI).

7. **Trusted-Publishing release workflow — `.github/workflows/release-pypi.yml`.**
   On a published GitHub Release: build sdist + wheel → publish to PyPI via OIDC
   (`pypa/gh-action-pypi-publish`, **no token**) → the publish job runs inside a
   GitHub **Environment** (`pypi`) whose protection rule requires **John's
   approval** before it proceeds. Replaces the manual `uv publish` token path. The
   existing GHCR image release (already tokenless) is unchanged.

8. **README badges.** CI status, CodeQL, PyPI version, license.

---

## Data flow — one release, end to end

1. I run `scripts/release.sh X.Y.Z` → version propagated, dates stamped, local gate
   green.
2. I write the CHANGELOG `X.Y.Z` entry (prose, human).
3. I commit, tag `vX.Y.Z`, push to GitHub. *(I do all the git.)*
4. CI runs on the push: tests, lint, version-gate, gitleaks, pip-audit, bandit,
   CodeQL — **all must be green**.
5. I create the GitHub Release for the tag.
6. The release workflow builds, then **pauses at the publish step** for approval.
7. **John clicks approve** → tokenless OIDC publish to PyPI. (GHCR image builds the
   same way.)
8. Badges reflect the new green state.

**John's touch-points:** "ship X.Y.Z" + one approval click. Nothing else.

---

## Error handling / failure modes

| Failure | What stops it |
|---|---|
| Version/tag/CHANGELOG disagree | version-gate fails the build; no release proceeds |
| Secret in a diff | push-protection blocks the push (server-side) **and** gitleaks fails CI |
| Dependency CVE | pip-audit flags it (severity policy below) |
| Code-security issue | bandit / CodeQL flag it |
| No publish approval | release sits pending; nothing reaches PyPI |
| OIDC misconfig | publish step errors loudly; PyPI publish is atomic — no partial release |

---

## Testing / verification (definition of done — run it like an end-user)

- The version-gate ships with its own unit test that runs in CI.
- **Prove the OIDC path on TestPyPI once** (`workflow_dispatch` → TestPyPI) before
  trusting production PyPI — don't first-run a brand-new tokenless path against prod.
- **Acceptance:** after the gated publish, on a **fresh venv**,
  `pip install proximo-proxmox==X.Y.Z` from PyPI, confirm it imports and
  `proximo.__version__` matches. (Test the published artifact, not the dev tree.)

---

## Open questions (carry into the plan)

1. **Scan severity at first run:** fail the build on pip-audit/bandit findings, or
   warn-only initially? **Recommendation:** warn-only for the first release so a
   wall of pre-existing findings doesn't block day one, then flip to fail once the
   baseline is clean.
2. **TestPyPI dry-run:** confirmed yes (above) — one-time proof of the OIDC path.

---

## Phases beyond this spec (sketch only — separate specs)

- **Phase 2 — internal-mirror parity.** Stand up one self-hosted Actions runner for
  the internal Git mirror, then run the *same* portable workflow there. (Internal
  infrastructure specifics are tracked separately, not in this public repo.)
- **Phase 3 — fleet template.** Extract the portable workflow + release tool into a
  reusable template and apply it to the other repos as they go public.
