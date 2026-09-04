# Known issues

Staging ground for verified defects, in GitHub-issue form. File upstream on John's go.

---

## Config footgun: `PROXIMO_ENABLE_EXEC` (and every `PROXIMO_*` var) set in `proximo.env` is silently ignored by the stdio MCP

> **RESOLVED 2026-07-01** via fix **(2)** below: `config.load_env_file()` now sources `~/.config/proximo/proximo.env` (override: `PROXIMO_ENV_FILE`) into `os.environ` before any `from_env()`, at the top of every entry point — `proximo` (stdio), `proximo-a2a`, and both HTTP entries — filling only `PROXIMO_*` keys not already set (real/inline env still wins). What it loads prints to stderr. Kept here for provenance.
>
> **Addendum 2026-09-03 (the shadow, seen live):** the per-key merge has a second edge. A key that is set in BOTH stores is fed by the process environment and the file's copy of that ONE key is dead, silently, while the rest of the file still applies. Hit on 2026-09-02: a CTID added to `proximo.env`, verified, reconnected, and `ct_exec` refused again with text that named the variable and no store. Three things changed: the loader now prints every file key the process environment SHADOWS with a different value (keys, never the values; a same-value shadow is the documented shell-export flow and stays silent); every allowlist refusal names the store that actually fed the allowlist (the process environment, which is the MCP client's `mcpServers.<name>.env` block for a stdio server and the unit's `EnvironmentFile` for the daemon, or the env file; and it says when the file's copy is shadowed) and says a restart or reconnect is required, because the value is fixed when the server is launched; `proximo doctor` reports `ct_allowlist_source` and flags a shadowed key whose value differs. Refusing to start on a disagreement was considered and rejected: the loader's contract is non-breaking for inline-config deployments, and a stale file line must not take a working server down.
>
> **One honest limit of that fix:** it merges by individual key, not by plane — decommissioning a plane (removing its base-URL/token vars from the env you actually run with) does not clear that plane's old keys out of the default `proximo.env` file, so a stale PBS/PMG/PDM config still sitting there can silently reactivate on the next start with nothing left to override it.

**Type:** bug / docs · **Severity:** medium (security-relevant — it governs the near-root exec edge) · **Found:** 2026-07-01, dogfooding the end-user setup while enabling `ct_exec` for a lab test.

### Summary
`SETUP.md` documents **two homes for the same `PROXIMO_*` variables** and never says which one wins:
- **`~/.config/proximo/proximo.env`** — created at SETUP.md:92 (`Create ~/.config/proximo/proximo.env`), loaded via `set -a; . proximo.env; set +a` (SETUP.md:113), and used by the daemon unit (`EnvironmentFile=/etc/proximo/proximo.env`) and the `proximo-arm`/`-disarm`/`-admin` helper scripts.
- **The inline `"env": {…}` block** in the MCP client's `mcpServers` config (SETUP.md:137).

For a **stdio MCP deployment** (the default, and what SETUP.md:137 shows), the server's `os.environ` comes **only from the inline `mcpServers.env` block**. It never sources `proximo.env`. So a flag set in the documented `proximo.env` has **zero effect on the running server** — it only feeds the daemon and the helper scripts.

### Reproduce
1. Deploy Proximo as a stdio MCP with an inline `mcpServers.proximo.env` block (per SETUP.md:137), `PROXIMO_ENABLE_EXEC` unset/false there.
2. Set `PROXIMO_ENABLE_EXEC=true` in `~/.config/proximo/proximo.env` (the file SETUP.md:92 tells you to create), reconnect.
3. Call `ct_exec` → still `blocked:exec_disabled`. The value the server actually read is the inline one; `proximo.env` was never consulted.

### Root cause
`src/proximo/config.py` reads `os.environ.get("PROXIMO_ENABLE_EXEC", ...)`. Under stdio, `os.environ` is whatever the MCP client injected (the inline block). There is no wrapper that sources `proximo.env` for the stdio launch — unlike daemon mode, which uses `EnvironmentFile`. Two documented config surfaces, no disambiguation, and the one SETUP.md leads with (`proximo.env`) is **not** the one the stdio server reads.

### Impact
An adopter follows SETUP.md, sets a flag in `proximo.env`, and it silently does nothing. For a **security flag like `PROXIMO_ENABLE_EXEC`** (it gates near-root-on-host exec) this is worse than cosmetic: an operator can believe exec is off (or on) based on `proximo.env` while the server runs the opposite from the inline block. Burns time and undermines trust in the config.

### Fix (options)
1. **Single source of truth (preferred):** make the stdio launch source `proximo.env`, mirroring the daemon's `EnvironmentFile` — e.g. ship a launcher that does `set -a; . "${PROXIMO_ENV_FILE:-~/.config/proximo/proximo.env}"; exec proximo`, and document *that* as the `mcpServers.command`. Then flipping `proximo.env` Just Works as SETUP.md:92 implies.
2. **Or, load it in-process:** on startup, if `PROXIMO_ENV_FILE` (or the default path) exists, parse it and fill any `PROXIMO_*` not already in `os.environ` (env still wins, so no surprise for inline configs).
3. **Or, docs-only (minimum):** state loudly in SETUP.md that for the **stdio MCP** the inline `mcpServers.env` block is authoritative and `proximo.env` is only for daemon mode + the helper scripts — and don't lead with `proximo.env`.

Recommended: **(1)** — it makes the documented file real, kills the two-homes drift, and matches daemon mode.

### Follow-up: this bites Independent CONSENT *harder* (fail-open, not fail-closed)

`PROXIMO_CONSENT_DIR` (the Independent CONSENT gate) is the same class of `PROXIMO_*` var and inherits this footgun — but the **direction of the silent failure is worse.** `PROXIMO_ENABLE_EXEC` silently-off fails **safe** (exec stays disabled; nothing runs). `PROXIMO_CONSENT_DIR` silently-unset fails **dangerous**: `enforce_consent` hits its opt-in `if not dir_: return` and **every mutation proceeds ungated**, while the operator — having set the dir in `proximo.env` per the documented pattern — believes each mutation now needs a single-use human grant. A security control that is silently inert gives *false assurance*, the exact thing it exists to prevent.

**Also resolved by fix (2):** with `load_env_file()` running at every entry point, a `PROXIMO_CONSENT_DIR` set in `proximo.env` now reaches the server process, so the silent-inert case above is closed. Two legibility aids confirm it: `load_env_file()` prints what it loaded to stderr, and `config.py` warns loudly whenever `PROXIMO_CONSENT_DIR` is in the process env. The honest operating practice stands regardless: treat CONSENT as active only when that startup warning is actually observed, never from a `proximo.env` entry alone — the per-key merge limit noted at the top applies to this var like any other.
