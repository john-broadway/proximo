# Proximo — operating notes for agents

Proximo is the governed client for Proxmox, built so a human can hand an agent real keys to
infrastructure they care about; MCP is one of its doors. You get six tools over every address the four Proxmox
products publish. Every mutation is planned before it runs, recorded in a tamper-evident
audit ledger, and undone where the vendor publishes a write to put the record back.

Build instructions live in [CONTRIBUTING.md](.github/CONTRIBUTING.md) and
[SETUP.md](docs/SETUP.md). This page is the operating envelope: what holds, what doesn't,
and how to check.

## The grammar

- `proximo_find` turns words into an address. A verb picks the method (`list`/`get` are GET,
  `create`/`start` POST, `update`/`set` PUT, `delete` DELETE); the other words match the
  path, the vendor's description and the parameter names. A nonsense query returns nothing,
  not a handful of junk.
- `proximo_plan` is the verdict for one address, with the vendor's published parameters. For
  a mutation it also reads the target as it stands (one governed read, receipted) and says
  `current`, `change` and `noop`. It mutates nothing. Run it before `proximo_call`.
- `proximo_read` runs any published GET. Rows come back LEAN (names, states, ids) with a
  total; `fields=all` for the vendor's rows. `since=24h` answers "what changed" from the
  snapshots this door kept, with no vendor call. `diagnose=true` on a node or guest path runs
  its health battery. Credentials come back withheld, and the answer says which.
- `proximo_call` runs a governed POST/PUT/DELETE. Without `confirm=true` it returns the plan
  and mutates nothing. It is refused unless the operator is armed AND the address carries an
  authored blast-radius tier. A task-backed call is waited on and reports finished, failed or
  timed out, never "submitted". `method=undo` with a capture's id puts a record back.
- `audit_entries` reads the ledger back, newest first, bounded. `audit_verify` walks the chain
  and names the first break.

## Sharp edges

- **A refusal names what would change the answer, and that is the whole message.** `needs`
  is one of `arm`, `tier`, `held`, `contain`, `consent`, `forbid`, `rate`, `taint`, `config`,
  `undo`, `prove`, `arguments`, `path`, `store`, `sight` (an empty list the token could not see into is not
  served as "none": the refusal names the privileges it would need), or an opt-in lane's own name (`agent`, `shell`,
  `node`, `download`: the lane is off, or this guest is not on its allowlist). `arm` means a human swaps the token; `held` means the address is refused by design and
  nothing you send opens it; `consent` means a grant file only the operator writes. Retrying,
  rewording the arguments, or trying a sibling address is not the fix for any of them.
- **An argument the schema does not declare is refused, never dropped.** Read the schema the
  plan hands back; do not guess parameter names.
- **Tiers are a blast-radius judgement, not a sandbox.** A low tier means a small blast
  radius, not "safe." An address with no tier is refused for mutation, armed or not.
- **UNDO covers what the vendor publishes a write to put back.** A delete, a collection, or a
  path with no PUT gets a sentence instead of a restore. Do not promise an undo the receipt
  did not give you an `undo.id` for.
- **Several controls are opt-in and inert until configured.** CONSENT, CONTAIN, the FORBID and
  RATE envelope, and TAINT are off unless their env var is set — and they only become a real
  boundary when their state lives outside your own write reach. Inside a single trust domain
  they're a discipline, not a wall. The full framing:
  [the two-deployment trust model](SECURITY.md#the-two-deployment-trust-model-read-this-first).
- **The shell lanes are separate opt-ins, each judged like a mutation.** Container exec
  (`PROXIMO_ENABLE_EXEC` + a CTID allowlist), the in-guest agent (`PROXIMO_ENABLE_AGENT` + a
  VMID allowlist) and the read-only host battery (`PROXIMO_ENABLE_NODE_SHELL`). A closed lane
  is named in a diagnosis, never read as healthy. There is no host mutation lane: upgrades and
  edits on the metal stay a human's hand.
- **The task list is not the whole truth.** Tasks are per-node and a tasks read is a windowed
  slice. A task on another node or outside your window is absent without being dead. Never
  conclude a backup failed from its absence there; the archives on the storage are the ground
  truth. A production deployment hit this one for real.
- **What's still unproven, and where the edges are:**
  [honest scope notes](SECURITY.md#honest-scope-notes).

## Verifying the claims

Don't take the above on trust. Check it:

- Run `proximo doctor`. It reports which pillars stand, which planes are reached, and whether
  the ledger's chain is whole — before any AI is wired in.
- Read the ledger. Every call lands in a keyed hash-chained audit log; `audit_verify` checks
  the chain — and the *strong* tail-attack guarantee is the opt-in pinned head
  (`expected_head`), not the bare check. SECURITY.md states exactly what holds, and where.
- Read [SECURITY.md](SECURITY.md), including the parts that say what *doesn't* hold.
- Read [VERIFY.md](VERIFY.md) for the no-telemetry proof you can run yourself.
- Read the source. All of it is here.

## No telemetry

Proximo keeps no record of use. No telemetry, no phone-home, no install data. Every URL
literal in the shipped source is a placeholder, a loopback literal (`127.0.0.1`, `::1`), or
an upstream Proxmox documentation citation. None is ever fetched. VERIFY.md carries the
one-line grep that proves it.
