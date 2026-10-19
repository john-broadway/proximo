# Known issues

Staging ground for verified defects, in GitHub-issue form. File upstream on John's go.

---

## Two homes for `PROXIMO_*`: the file and the client's `env` block

> **RESOLVED.** Every door (`proximo` over stdio, `proximo-core`, `proximo-http`,
> `proximo-mcp-http`, `proximo-a2a`) sources `~/.config/proximo/proximo.env` (or the file
> `PROXIMO_ENV_FILE` names) before its first env read, under one contract: only `PROXIMO_*`
> keys; only keys the process environment does NOT already hold; a key present in both stores
> with a different value is named as SHADOWED on stderr at start (the key, never the value).
> The 0.44 commands sourced the file and the first core doors did not; the default-command
> swap of 2026-10-17 closed that, and the cut of 2026-10-18 removed the 0.44 path.

**What it was.** `SETUP.md` documents two homes for the same variables: the env file, and
the inline `"env": {…}` block in an MCP client's `mcpServers` config. For a stdio
deployment the server's environment came only from the inline block, so a flag set in the
file silently did nothing. For a security flag like `PROXIMO_ENABLE_EXEC` (it gates near-root
exec on the host) that was worse than cosmetic, and for `PROXIMO_CONSENT_DIR` it failed in
the dangerous direction: an operator who believed the consent gate stood ran without it.

**The honest limit that remains.** The merge is by individual key, not by plane. Removing a
plane's base URL and token from the environment you actually run with does not clear that
plane if the file still carries it; the file's copy fills the gap, by design. Decommission a
plane in both stores.

---

## The arena's held lines move only by a release

`docs/arena.md` lists 20 published mutations refused on purpose, each with a sentence (login
tickets, the node's `execute`, the cluster join). Opening one is a line moved in
`src/proximo/core/tiers.toml` and shipped; there is no switch. That is the design, recorded
here because it reads like a gap when a plan answers `needs: "held"`.
