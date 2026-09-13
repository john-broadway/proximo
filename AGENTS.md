# Proximo — operating notes for agents

Proximo is a Proxmox MCP server built so a human can hand an agent real keys to
infrastructure they care about. Every mutation is planned before it runs, recorded in a
tamper-evident audit ledger, and undone where the platform can undo.

Build instructions live in [CONTRIBUTING.md](.github/CONTRIBUTING.md) and
[SETUP.md](docs/SETUP.md). This page is the operating envelope: what holds, what doesn't,
and how to check.

## Sharp edges

- **Risk ratings are an advisory heuristic, not a sandbox.** `LOW` means "no state
  change," not "safe."
- **UNDO covers the snapshottable surface, not every mutation.** Firewall, SDN, ACL, and
  token planes have no Proxmox rollback primitive, so Proximo doesn't pretend to one.
- **Several controls are opt-in and inert until configured.** CONSENT, CONTAIN, LEASE,
  SCOPE, ENVELOPE, and TAINT are off unless their env var is set — and they only become
  a real boundary when their state lives outside your own write reach. Inside a single
  trust domain they're a discipline, not a wall. The full framing:
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
  its absence there; `pve_backup_list` / `pbs_snapshots_list` are the ground truth. A
  production deployment hit this one for real.
- **What's still unproven, and where the edges are:**
  [honest scope notes](SECURITY.md#honest-scope-notes).

## Verifying the claims

Don't take the above on trust. Check it:

- Run `proximo doctor`. It prints exactly what a given token can and cannot do — before
  any AI is wired in.
- Read the ledger. Every mutation lands in a hash-chained audit log; `audit_verify`
  checks the chain — and the *strong* tail-attack guarantee is the opt-in pinned head
  (`expected_head`), not the bare check. SECURITY.md states exactly what holds, and where.
- Read [SECURITY.md](SECURITY.md), including the parts that say what *doesn't* hold.
- Read [VERIFY.md](VERIFY.md) for the no-telemetry proof you can run yourself.
- Read the source. All of it is here.

## No telemetry

Proximo keeps no record of use. No telemetry, no phone-home, no install data. Every URL
literal in the shipped source is a placeholder, a loopback literal (`127.0.0.1`, `::1`),
an upstream Proxmox documentation citation, or a string Proximo prints for a human to
open. None is ever fetched. VERIFY.md carries the one-line grep that proves it.
