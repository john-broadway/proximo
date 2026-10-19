# Contributing to Proximo

Thanks for considering a contribution. Proximo points an AI agent at a Proxmox
cluster, so it holds itself to a higher-than-usual bar on **safety** and
**honesty** — and contributions are held to that same bar. This guide is short;
the spirit is *"leave the trust spine at least as strong as you found it."*

This is a small, independently-maintained project run on best-effort time.
Please be patient with review, and thank you for helping.

## Before you start

- **Security issues are not public.** If you've found a vulnerability, do **not**
  open an issue or a PR — follow [`SECURITY.md`](./SECURITY.md) (GitHub private
  vulnerability reporting).
- **For anything non-trivial, open an issue first.** A short discussion saves a
  rejected PR. Obvious fixes (typos, clear bugs) can go straight to a PR.

## Development setup

Proximo uses [`uv`](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/john-broadway/proximo.git
cd proximo
uv sync --extra dev
```

Run the same checks CI runs — a PR that doesn't pass all three won't merge:

```bash
uv run pytest -q                    # full suite — must be green
uv run ruff check .                 # lint — the full repo, exactly what CI runs
uv run pyright                      # types (src is the typed scope)
```

The tests are mock / in-process: you do **not** need a real Proxmox host to
develop.

## The trust spine — please don't weaken it

Proximo's whole reason to exist is that an agent can operate a cluster *without
being able to wreck it.* Four invariants hold that up — keep them intact:

- **PLAN** — every mutation builds and records a preview before it can run.
  Don't add a mutate path that skips the plan.
- **PROVE** — every plan and confirmation lands in the tamper-evident audit
  ledger. Don't add a path that mutates without recording.
- **UNDO** — snapshot-before-change wherever the platform supports it,
  fail-closed.
- **DIAGNOSE** — read-only evidence; flags are advisory.

Two postures are deliberate, not accidental — don't flip them to be more
convenient and less safe:

- **API-only by default.** In-container exec is opt-in (`PROXIMO_ENABLE_EXEC=1`)
  and announces that it grants near-root on the host. Keep it opt-in and loud.
- **Honest risk ratings.** The risk rating is an advisory heuristic, not a
  sandbox; the honesty notes in the docs and tool output are load-bearing.
  Don't quietly upgrade "advisory" to "safe."

## Submitting a change

1. Fork, and branch from `main`.
2. Make the change **with tests** — new behavior needs a test; a bug fix needs a
   test that fails before the fix and passes after.
3. Get all three checks green.
4. Add a line to [`CHANGELOG.md`](./CHANGELOG.md) under `## [Unreleased]`.
5. Open the PR and fill in the template.

Honest, small, well-tested PRs get reviewed fastest. **Strength and honor.**
