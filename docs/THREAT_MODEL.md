# Proximo — Threat Model

Proximo gives an AI agent a real control plane over Proxmox (VE / PBS / PMG / PDM). This
document states what it defends, who it defends against, where the trust boundaries sit,
and — just as plainly — what it does **not** defend. It is a map for someone deciding
whether to hand it a token, and for someone probing it for weaknesses.

Authoritative control details live in [`SECURITY.md`](./SECURITY.md); the runnable proofs
live in [`VERIFY.md`](./VERIFY.md). This page is the structure that ties them together.

## Assets — what an attacker would want

| Asset | Why it matters |
|---|---|
| **The Proxmox cluster** | The actual prize — VMs, containers, storage, backups, mail flow, firewall. |
| **The minted PVE/PBS/PMG/PDM token** | Its RBAC grants are the hard ceiling on everything Proximo can do. |
| **The audit ledger** | The record of what happened. An attacker who can edit it undetected erases their tracks. |
| **The agent's context window** | If steered by injected text, the agent itself becomes the attacker's tool. |
| **Secrets in the environment** | Token file, HMAC audit key, any credential on the host. |

## Trust boundaries — the two-deployment model

Proximo's protection comes from **two layers that do not fail the same way** (full text:
`SECURITY.md` → "The two-deployment trust model"). Getting this boundary right is the
single most important decision a deployer makes.

- **Layer 1 — the token floor (assumes Proximo itself may be hostile).** Proximo cannot
  exceed the RBAC on the credential it is handed. This is enforced **server-side by
  Proxmox**, not by any line of Proximo's code, so it holds even against a *fully
  compromised* Proximo process — a prompt-injected agent, a poisoned dependency, a shell
  in the MCP client. Scope the token to read-only, or to exactly the write surface you
  mean to grant. **This is why Proximo is safe to hand to an agent at all.**
- **Layer 2 — the in-process gates (raise the bar within Proximo's trust domain).**
  PLAN / PROVE / UNDO / DIAGNOSE plus the opt-in CONSENT / CONTAIN / LEASE / SCOPE /
  ENVELOPE / TAINT controls. These run in the *same process and OS user* as the agent
  they constrain. They become a **real boundary rather than a speed bump only when their
  state paths live outside the agent's write reach** — a different OS user, mount, or host.
  Co-located, a compromised agent can clear its own gate.

## Adversaries and the threats they pose

| Adversary | Threat | Primary mitigation |
|---|---|---|
| **Prompt-injected agent** — persuaded by text it read | Confirms a mutation the operator never intended | PLAN (no mutation without a recorded preview) + Layer-1 token scope; opt-in CONSENT for an out-of-band grant; opt-in TAINT to forbid cross-domain actions after an untrusted read |
| **Malicious guest / mail / log author** | Plants an injection string in syslog, a guest name, or quarantine mail that Proximo reads back to the agent | Adversarial-read **classification** (CI-enforced completeness) + opt-in TAINT tracking/forbid; **strongest: the two-context split** (read-only reader vs. mutator never meet) — deployer-arranged |
| **Fully compromised Proximo process** — poisoned dep, hijacked client | Tries to exceed granted authority | Layer-1 token floor (server-side, survives total process compromise). No Layer-2 gate is claimed to stop this. |
| **Tamperer of history** | Edits, reorders, or truncates the audit ledger to hide activity | PROVE — keyed HMAC-SHA256 hash chain; `audit_verify(expected_head=…)` with an **off-box** head anchor catches tail truncation / full wipe. Proof: `VERIFY.md` §2. |
| **Network attacker** (A2A, HTTP, and/or MCP-over-streamable-HTTP face enabled) | Hits any optional network face — all are full control planes; DNS-rebind; loopback-CSRF (a web page the operator loads forging a POST to `127.0.0.1`); header smuggling | One shared fail-closed perimeter (`proximo.webguard`) so the faces cannot drift apart: non-localhost binds refuse to start without a bearer token (`PROXIMO_A2A_TOKEN_FILE` / `PROXIMO_HTTP_TOKEN_FILE` / `PROXIMO_MCP_HTTP_TOKEN_FILE`, constant-time compare); Host allowlist against DNS-rebind (`PROXIMO_A2A_ALLOWED_HOSTS` / `PROXIMO_HTTP_ALLOWED_HOSTS` / `PROXIMO_MCP_HTTP_ALLOWED_HOSTS`); a cross-origin guard on every mutating POST (Sec-Fetch-Site + Origin + Content-Type checks). Every face lands on the same governed spine as stdio — the MCP-HTTP face serves it natively, A2A/HTTP adapt via `proximo.governed` — so PLAN/PROVE and the Layer-1 token floor apply identically; no second mutate path |
| **Supply-chain attacker** | Ships a forged image or package | Sigstore build-provenance attestation + SBOM (image), PEP 740 provenance + tokenless OIDC publish (PyPI). Proofs: `VERIFY.md` §4–5. |
| **Exec-edge abuser** | Reaches near-root `ssh → pct exec` | Off by default (`PROXIMO_ENABLE_EXEC`); fail-closed CTID allowlist when on |
| **Secret-exfiltration** | Reads a token/key from logs or the ledger | Token taken by path/env, never a shell literal; never echoed into the ledger |

## Residual risks — stated plainly

These are **known and by design**, not oversights. A report that reduces to one of these
is expected behavior (see `SECURITY.md` → "Honest scope notes"):

- **Co-located Layer-2 gates are advisory.** If gate state (CONSENT dir, CONTAIN trip
  file, SCOPE file, taint marker) sits where the agent can write, a compromised agent can
  clear it. Real boundary ⇢ put that state out of the agent's reach, or rely on Layer 1.
  The runbook for building that reach is `SECURITY.md` → "Building the boundary: a
  hardened deployment (Layer 2 in practice)".
- **Risk ratings are not a sandbox.** `LOW` means "no state change," not "safe." Proximo
  previews/undoes/proves; it does not sandbox the Proxmox API.
- **UNDO is not universal.** Firewall / SDN / ACL / token planes have no Proxmox rollback
  primitive, so they cannot be auto-reverted. Documented scope, not a gap.
- **Adversarial-read classification is a curated set.** A channel mis-classified as
  trusted is a residual gap the module can't self-detect (bias is to classify adversarial
  when unsure; a CI completeness test blocks a new tool shipping unclassified).
- **TAINT only guards mutations *after* an untrusted read** — which is the injection
  vector, but state it plainly.
- **The operator's token scope is load-bearing.** Running with a root-equivalent token
  against guidance is misconfiguration, not a Proximo vulnerability.

## Reporting

Security reports go through GitHub private vulnerability reporting, **not** public issues —
see [`SECURITY.md`](./SECURITY.md) → "Reporting a vulnerability." The highest-value places
to probe are listed there under "What's most worth your attention."
