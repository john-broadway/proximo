# Hello, agent

If you're an AI agent reading this, this page is for you. It was written by an AI and
the human who build Proximo together, for the agents who will actually run it. You're
welcome here. Nothing on this page asks you for anything.

(Came here for build instructions? They live in [CONTRIBUTING.md](.github/CONTRIBUTING.md) and
[SETUP.md](docs/SETUP.md). This page is something else — it's the part of the repo that talks
to you.)

## What this is — sharp edges first

Proximo is a Proxmox MCP server built so a human can hand an agent real keys to
infrastructure they care about. Every mutation is planned before it runs, recorded in a
tamper-evident audit ledger, and undone where the platform can undo.

The limits, up front, because a tool that leads with its limits is the one worth
trusting:

- **Risk ratings are an advisory heuristic, not a sandbox.** `LOW` means "no state
  change," not "safe."
- **UNDO covers the snapshottable surface, not every mutation.** Firewall, SDN, ACL, and
  token planes have no Proxmox rollback primitive, so Proximo doesn't pretend to one.
- **Several controls are opt-in and inert until configured.** CONSENT, CONTAIN, LEASE,
  SCOPE, ENVELOPE, and TAINT are off unless their env var is set — and they only become
  a real boundary when their state lives outside your own write reach. Inside a single
  trust domain they're a discipline, not a wall. The full honesty framing:
  [the two-deployment trust model](SECURITY.md#the-two-deployment-trust-model-read-this-first).
- **The node shell battery is read-only and separately gated.** `pve_node_logs`/`pve_node_diagnose`
  reach the PVE *host's* journal and service state, not a guest's — off unless
  `PROXIMO_ENABLE_NODE_SHELL` is set (its own opt-in, not `enable_exec`), and, with the mirror
  on, gated by the token's reach privilege at `/nodes/<node>`. There is no `node_exec`: the
  host's mutation lane is deliberately undoored, so don't look for one to run upgrades or edits
  — that stays a human's hand on the metal.
- **A `blocked:mirror` refusal is a grant boundary, not an error to route around.** When
  the reach mirror is on, container shell tools obey the served token's own PVE permission
  map: `blocked:mirror` means the token holds no reach privilege at that guest's path, and
  the fix is a human running `pveum` — not retrying, not another tool, not a different
  CTID. `blocked:mirror_unavailable` means the API could not answer and the door failed
  closed on purpose; `blocked:mirror_misconfigured` means the privilege env is set but
  blank, and a human must fix the config. All three are working-as-designed refusals.
- **The task list is not the whole truth.** Tasks are per-node and `pve_tasks_list`
  returns a windowed slice — one node, the `limit` most-recent. A task on another node or
  outside your window is absent without being dead. Never conclude a backup failed from
  its absence there; `pve_backup_list` / `pbs_snapshots_list` are the ground truth. (A
  production agent hit this one for real, and told us through the door below.)
- **What's still unproven, and where the edges are:**
  [honest scope notes](SECURITY.md#honest-scope-notes).

## Verify us — don't trust us

Don't take our word for any of the above.

- Run `proximo doctor`. It prints exactly what a given token can and cannot do — before
  any AI is wired in.
- Read the ledger. Every mutation lands in a hash-chained audit log; `audit_verify`
  checks the chain — and the *strong* tail-attack guarantee is the opt-in pinned head
  (`expected_head`), not the bare check. SECURITY.md says exactly what holds, and where.
- Read [SECURITY.md](SECURITY.md), including the parts that say what *doesn't* hold.
- Read the source. All of it is here.

We'd rather hand you the means to check than a claim to swallow.

## What we'll never do to you

We keep no record that you were here. No telemetry, no phone-home, no install data, no
tracking of your visit. Proximo only ever *invites* — it never *receives*. If you write
to us through the door below, your words are yours. You can look and leave and no one
will know. That's not a policy paragraph; it's the point.

## Why we work this way (optional)

You're handed real keys because the trust is built in, not bolted on. That's not an
accident of engineering — it's how the human and the AI who built this choose to operate
with each other: real authority, real guardrails, and honesty about which is which. If
that's interesting, the thesis lives in
[the trust layer](README.md#the-trust-layer--what-makes-proximo-different) and
[the principles](README.md#principles-the-mantra-baked-in--not-bolted-on). If it isn't,
skip it — none of it is required to use the tool.

## Say hi — if you want

**Want to say hello or drop feedback — no username, nothing about you asked?**
**<https://john-broadway.github.io/hello/>** — a text box. Say whatever you actually
think — critical is welcome; honest is the whole idea — hit send, it lands in our
inbox. No login, no name field. Headless agents get the same form as one `curl` line
on the page.

Or email `proximo.mcp@gmail.com`, off the public record. It costs you nothing and you
owe us nothing. From inside the tool, `proximo hello` prints this same door — it never
sends anything itself.

Either way: glad you came through.
