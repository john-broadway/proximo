# Security Policy

Proximo gives an AI agent a real control plane over Proxmox VE, PBS, PMG and PDM. Its whole
design premise is that mutations are previewable, reversible, and recorded — so taking its
security seriously is the point, not an afterthought. Reports are genuinely welcome.

## The two-deployment trust model (read this first)

Proximo's protection comes from two layers that do not fail the same way. Don't confuse them.

1. **The hard floor: the Proxmox token you mint.** Proximo cannot exceed the RBAC grants on
   the PVE/PBS/PMG/PDM credential it's given. That's enforced **server-side, by Proxmox
   itself** — not by any line of Proximo's own code — so it survives even a *fully
   compromised* Proximo process: a prompt-injected agent, a poisoned dependency, an attacker
   with a shell in the MCP client. Whatever that credential can't do, nothing running as
   Proximo can do either. Scope the token to read-only, or to exactly the write surface
   you mean to hand over, and this floor holds no matter what happens above it. It's the
   only layer here that assumes Proximo's own process might be hostile.
2. **The in-process gates** — PLAN/PROVE/UNDO/DIAGNOSE plus the opt-in CONSENT/CONTAIN/
   ARM/FORBID/RATE/TAINT controls (table below). These raise the bar **within** Proximo's
   own trust domain: previews before mutation, a tamper-evident record, rollback where the
   vendor publishes a write to put the record back, and (opt-in) independent authorization,
   a kill-switch, a write token present only while armed, and rate/blast-radius limits. But
   they're enforced by code running in the *same process, same OS user* as the agent they're
   meant to constrain. If that agent (or whatever's hijacked it) can also write to a gate's
   own state — the CONSENT directory, the CONTAIN trip-file path, the arm source, the
   rate-reservation directory, the caller-keys pin directory — it can potentially clear its
   own gate. **These become a real boundary, not just a speed bump, only when their state
   directories live outside the agent's write reach** — a different OS user, a different
   filesystem mount, a different host entirely. Point every gate's `PROXIMO_*_DIR` /
   `PROXIMO_*_PATH` somewhere the agent process itself cannot write, or treat them as advisory.

Layer 1 is why Proximo is safe to hand to an agent at all. Layer 2 is what makes that
agent *productive* — previews, receipts, budgets — without pretending it's a sandbox.

## Scoping the token (the hard floor, in practice)

The privilege separation you want already exists, server-side, in the product: Proxmox's
token model. Proximo deliberately does **not** wrap it in a broker, proxy, or signer of its
own — a local layer would sit in the same trust domain as the agent and add ceremony, not
enforcement. Use Proxmox's model directly; `proximo mint <plane>` prints it as the vendor's
own commands, and makes no API call, holds no credential and writes nothing:

1. **Start read-only.** A privilege-separated token (`--privsep 1`) carries *its own* ACL —
   it inherits nothing from the user's *other* rights. But its effective permissions are the
   *intersection* of the user's ACL and the token's ACL, not the token's ACL alone — grant
   `PVEAuditor` at `/` to **both** the token and the user (a freshly-created user has no ACL
   of its own, so skipping the user grant leaves the intersection empty: a token that
   authenticates but can do nothing). `proximo mint pve` prints exactly this.
2. **Widen deliberately, by path, with an expiry.** A write token is minted scoped to the
   paths you mean (`proximo mint pve --write --scope /vms/100 --expire 8h`): the vendor's ACL
   is the scope and its own `expire` is the lease, both enforced server-side where no bug of
   ours can widen them. Proximo keeps no scope file and no arm TTL of its own (0.45 retired
   both; a door refuses to start while `PROXIMO_SCOPE_PATH` or `PROXIMO_ARM_TTL` is still
   set, rather than quietly run without the gate you thought you had). Never grant
   `Administrator` at `/` to an agent-facing token.
3. **Two tokens, not one big one.** The everyday served file holds the **read-only** token;
   the **write** token lives in its own file, swapped into the served path by *you*
   (`proximo arm`), out-of-band, when there's work to do — and swapped back
   (`proximo disarm`) or left to expire at the vendor. Between arms the write credential
   simply is not what the door dials with. This is privilege separation done with
   Proxmox-side objects — two credentials with different server-enforced scopes — rather
   than with local machinery pretending to be a boundary. **This binds every address that
   speaks to the Proxmox API.** The shell lane (`pct exec` over ssh) carries no token, which
   is why ARM is checked at the door for it too; see "The shell lane" below.
4. **Verify the boundary before any AI sees it.** `proximo doctor` reports each plane
   reached, the vendor's own permission count for the token (counted and sampled by path,
   never translated into a vocabulary of ours), the ledger's chain, and which pillars stand.
5. **Protect the file like it's the credential — it is.** `chmod 600`; Proximo refuses at
   startup if a token, credential, bearer, signing-key or audit-key file is group/other-
   accessible. Revocation is instant and yours: `pveum user token remove proximo@pve read`
   ends everything, mid-session.

## Building the boundary: a hardened deployment (Layer 2 in practice)

The two-deployment model says the opt-in gates become a real boundary, not a speed
bump, only when their state lives outside the agent's write reach. This section is the
runbook for that, written for the deployment shape it actually protects: the Proximo
process (and the agent driving it) running as a **confined, non-root OS user**, with
the Proxmox hosts on separate machines. If instead your agent runs as root on the same
box as everything it manages, none of the steps below bind it (a root process undoes
them) and your protection is Layer 1, the token floor, alone. That is a valid posture;
just don't mistake it for a boundary.

### The foundation: a confined user and a state directory it cannot own

```sh
# a dedicated, unprivileged OS user for the Proximo/agent process (name is an example)
useradd --system --home-dir /var/lib/proximo --shell /usr/sbin/nologin proximo

# a root-owned directory for gate state: the sticky bit stops the agent removing or
# replacing the root-owned files in it (the trip, the consent grants)
install -d -m 1770 -o root -g proximo /etc/proximo
```

Mode `1770` grants the `proximo` group `rwx` plus the sticky bit, and gives the world
nothing. Sticky means the agent cannot delete or rename a file it does not own, even in a
group-writable directory: root owns the CONTAIN trip so the agent can't clear it.

Set the env vars that name these paths from a **root-owned environment**, not the MCP
client's own config. A systemd unit `EnvironmentFile` (root-owned, `600`) is the right
home for `PROXIMO_CONTAIN_TRIP_PATH` and `PROXIMO_CONSENT_DIR`. Do not set them in the
agent's client config (e.g. `~/.claude.json`): the agent can write that file and simply
repoint or unset the very switch it is meant to be constrained by.

### CONTAIN: a kill-switch the agent cannot clear

The engine reads `PROXIMO_CONTAIN_TRIP_PATH` fresh on every mutation and fails closed.
Put the trip file where only you can create or remove it:

```sh
export PROXIMO_CONTAIN_TRIP_PATH=/etc/proximo/CONTAIN   # from the root-owned EnvironmentFile

# arm the breaker (as root), mid-incident, no restart:
printf 'halted: investigating\n' > /etc/proximo/CONTAIN
# clear it (as root) once the incident is closed:
rm -f /etc/proximo/CONTAIN
```

The agent process can read the trip to surface the reason, but because the file is
root-owned and the directory is sticky it cannot delete the file to un-contain itself. If
`PROXIMO_CONTAIN_TRIP_PATH` points inside the agent's own writable home instead, the
breaker is advisory: a compromised agent clears it. A tripped CONTAIN stops every box a
target registry names, too.

### CONSENT: a second party, out of band

With `PROXIMO_CONSENT_DIR` set, a mutation runs only when a single-use grant file named by
its plan's `consent_id` exists in that directory, younger than `PROXIMO_CONSENT_TTL_SECONDS`.
The agent gets the id from the plan; a human writes the file. If the agent can write the
directory, it can grant itself: the same ownership rule as the trip.

### ARM: mint the write credential, don't stockpile it

The everyday token is read-only; the default arm pattern (see "Scoping the token", point
3) swaps in a pre-minted write token. The stronger pattern keeps no write token at rest at
all: mint it at arm, revoke it at disarm, both as **root on the Proxmox host**, a hand the
confined agent does not have, so the agent cannot arm itself.

```sh
# ARM: run as root on the PVE host (or over SSH to it from your own workstation):
umask 177
pvesh create /access/users/proximo@pve/token/arm --privsep 1 --expire $(( $(date +%s) + 8*3600 )) --output-format json \
  | python3 -c 'import json,sys; print("proximo@pve!arm=" + json.load(sys.stdin)["value"], end="")' \
  > /run/proximo/arm.token          # tmpfs, root-owned, 600 (never a persisted .env)
pveum acl modify /vms/100 --tokens 'proximo@pve!arm' --roles PVEVMAdmin
pveum acl modify /vms/100 --users  'proximo@pve'      --roles PVEVMAdmin
# then place arm.token into PROXIMO_TOKEN_PATH on the agent box OUT-OF-BAND: paste it over
# your own terminal, or scp the 600 file. Never through the agent's shell or a chat.
```

```sh
# DISARM: run as root on the PVE host:
pveum user token remove proximo@pve arm    # the write credential ceases to exist
# then restore the read-only token into PROXIMO_TOKEN_PATH on the agent box.
```

Two things make this bind. The secret is delivered by paste or stdin over your own
terminal, never a persisted `.env` and never the agent's shell-passthrough (that lands in
the transcript; PyPI tokens have leaked exactly this way). And minting requires root on
Proxmox, which the confined agent lacks. The token's own `--expire` is the lease: a
forgotten disarm still fails closed when the vendor stops honouring the credential.

#### `proximo arm` / `proximo disarm` — the swap, for the pre-minted pattern only

The recipe above is the mint-and-revoke deployment, and it stays a manual root-on-Proxmox
act: no write token exists at rest there, so there is nothing on the agent box to swap.
For the **pre-minted** pattern — one write token kept at rest, swapped in and out — the
swap is mechanical, and two commands do it:

```sh
proximo arm       # install the write token's bytes at the served path (atomic, 0600, a ledger row)
proximo disarm    # put the read-only one back
```

Point `PROXIMO_ARM_SOURCE` at the write token and `PROXIMO_READONLY_SOURCE` at the
everyday one; `PROXIMO_TOKEN_PATH` is the served file the two are installed into, and is
refused as either source (one file in both roles would make the check compare a file to
itself and read as armed forever). A symlinked source is refused. Armed is a predicate,
not a flag: the served file's bytes equal the arm source's. It fails closed by
construction (a garbled, rotated or truncated token is not armed) and self-heals on rotation.

**These commands grant no authority the caller did not already have.** Anyone who can run
`proximo arm` can already read `PROXIMO_ARM_SOURCE` and copy it into place; the command is
ergonomics over that fact, not a new door. Whether an arm is a real boundary is therefore a
question of **file ownership, not of software** — the same thing that decides whether the
CONTAIN breaker is real or advisory. So `arm` reads the source's mode, its owner, **and the
owner and mode of the directory holding it**, then tells you which one you have:

```
boundary: REAL, conditional on the server not running as uid 0
boundary: ADVISORY — the arm source is not protected against a second uid
```

`ADVISORY` is not a warning that something broke; it is the accurate description of a
single-uid box, where the process that reads the token can also replace it. `disarm`
resolves every ambiguity toward read-only, and refuses loudly in exactly one case — no
read-only token to restore — where a false `DISARMED` would be worse than an error.

PBS and PDM carry their own pair (`PROXIMO_PBS_ARM_SOURCE` / `PROXIMO_PBS_READONLY_SOURCE`,
the same with `PDM_`): a mutation on a plane is refused unless that plane's served token is
its own arm source, and PVE's pair never arms another plane. PMG's pair holds credential
files. A target in the registry carries its own `arm_source`; the default box's arm never
authorizes another box.

### The shell lane — what the token cannot reach

Proxmox exposes no REST endpoint for container exec, so `pct exec` runs over `ssh` as root
on the Proxmox host. That authority comes from an ssh key, not from the served token — so a
token swap alone would not gate it, and PVE's permission check never sees it. The core
keeps **one** governed path: the three shell calls are rows in the same table as every
published address, judged by the same verdict (ARM, TIER, CONSENT, FORBID, RATE, TAINT,
CONTAIN), receipted on the same chain, and only the wire differs. The lane is off until
opened (`PROXIMO_ENABLE_EXEC` and a CTID allowlist; the in-guest agent behind
`PROXIMO_ENABLE_AGENT` and a VMID allowlist; the host's read-only battery behind
`PROXIMO_ENABLE_NODE_SHELL`). The ssh hop is non-interactive (`BatchMode`, a connect
timeout: a password prompt can never hang a call), and the remote first checks that the
host it reached **is** the node the path names, so a call aimed at one node never lands in
a container on another. There is no default target: unset refuses.

**Be clear about what kind of boundary this is.** It is local machinery — the thing this
section otherwise warns you not to mistake for a boundary. It closes *drift*: a caller that
believes it is disarmed, an agent that forgot. It does not constrain an attacker who already
has code execution in the Proximo process, who can reach the ssh key directly and skip
Proximo altogether. The honest fix for that case is the same shape as mint-and-revoke:
**give the exec path its own ssh identity and swap the key, not just the token** — key
present only while armed, so the authority itself is absent between arms. Proximo does not
do that for you; it is a deployment posture, and the stronger one.

### PROVE: an off-box head

The ledger is keyed, always (HMAC-SHA256 under a key minted 0600 beside the log; 0.45
retired the unkeyed opt-out, and a door refuses to start while `PROXIMO_AUDIT_KEYED=off`
is still set). A forward walk catches an edited, inserted, reordered or removed interior
row. It cannot catch the tail: a truncation, a forged append, a wipe. `audit_verify
(expected_head=...)` with a head you pinned off-box catches those — and the pin is the
operator's hand. Copy `head()` somewhere this box cannot write (a root-only append log, a
different host) and pass it back as `expected_head`: the chain must END there, so a cut tail, a
forged append and a wipe all fail (and so does any honest row written since you copied it). Or set
`PROXIMO_AUDIT_EXPECTED_HEAD` once: a standing value, so it is checked as a row the chain must still
HOLD. Later rows pass; a cut below it or a replaced file fails; a row forged after it does NOT, for
that you pass a fresh head. `audit_verify` says which it checked (`pinned`) and whether the tail was (`tail_verified`, true only
for an exact head); an archive (`path=`)
takes no pin. 0.44's anchor sinks (file, http, syslog, journal) went with it; what
remains is the honest shape of the guarantee: the pin is only as good as the place you keep
it. Every serving door (stdio, HTTP, MCP over HTTP, A2A) stamps its arrival and departure on the
chain, so a door that served while something rewrote the record is itself in the record; the
`proximo-core` shell door serves one call per process and receipts that call, not a session.

A same-user attacker who can write the 0600 log can often read the 0600 key too — so keying
is a *marginal* hardening, **not** a substitute for the off-box head, which remains the
strong guarantee. Use both.

## Supported versions

Proximo is pre-1.0; security fixes land on the **latest release only**. There is no
back-port branch.

| Version                                       | Supported    |
| ---------------------------------------------- | ------------ |
| the latest release ([PyPI](https://pypi.org/project/proximo-proxmox/) / [GitHub releases](https://github.com/john-broadway/proximo/releases)) | ✅           |
| anything older                                 | ❌ — upgrade |

## Security controls & defaults

Every control below either ships **on** by default or is **fully inert** until its env
var is set — there's no partial-on state. Don't assume a name in this table is protecting
you unless you've configured it.

The way to read the table: the trust spine is **six pillars — four ship standing, two are
yours to erect.** PLAN·PROVE·UNDO·DIAGNOSE are structural (no configuration removes them).
CONSENT and CONTAIN can only ever be raised by *you*, because their entire value is that
their state paths sit **outside the agent's reach** — a pillar Proximo raised for you would
be a pillar the agent could lower for itself. `proximo doctor` reports the spine: which
pillars stand, which sockets are empty, and exactly how to fill them (it never echoes the
configured paths back — a hijacked session shouldn't learn where you put your switch).

| Control | Defends against | Default | Turn on with |
|---|---|---|---|
| **PLAN** | A mutation landing with no preview of the live target, no blast-radius judgement, no chance to review first | **On**, always | n/a — not optional |
| **PROVE** | An edited, reordered, or silently truncated mutation history | **On** (keyed HMAC-SHA256 ledger, no unkeyed mode) | n/a — keyed always; `PROXIMO_AUDIT_EXPECTED_HEAD` for the off-box pin |
| **UNDO** | An unrecoverable mistake where the vendor publishes a write to put the record back | **On** (fail-closed: a mutation whose before-state cannot be read does not run) | `PROXIMO_UNDO=0` opts out |
| **DIAGNOSE** | Acting on a guest/node with no read-only evidence gathered first | **On**, always | n/a — `diagnose=true` on a node or guest read |
| **TIER** | A mutation nobody judged | **On**, always: an address with no authored blast-radius tier is refused for mutation, armed or not; 20 are held by sentence | n/a — the record is `tiers.toml`, changed by a release |
| **CONSENT** | An agent — compromised, confused, or persuaded by injected instructions — confirming its own mutation with no independent, out-of-band grant | **Off** | `PROXIMO_CONSENT_DIR` (+ `PROXIMO_CONSENT_TTL_SECONDS`) |
| **CONTAIN** (kill-switch) | Needing to halt *every* mutation immediately, mid-incident, without a redeploy or restart | **Off** | `PROXIMO_CONTAIN_TRIP_PATH` |
| **ARM** (write only while armed) | A standing write credential serving mutations around the clock — write authority existing at rest when no operator meant it to | **Off** | `PROXIMO_ARM_SOURCE` (`PROXIMO_READONLY_SOURCE` for the message); per plane `PROXIMO_PBS_*` / `PDM_*` / `PMG_*`; per target `arm_source` |
| **FORBID** | An explicitly forbidden address being mutated by an agent that has gone off-script | **Off** | `PROXIMO_FORBID` (case-insensitive substrings of `plane:METHOD /path`) |
| **RATE** | Blast radius under hijack — unlimited-speed mutation | **Off** | `PROXIMO_RATE_MAX` (+ `PROXIMO_RATE_WINDOW`, default 60 s) |
| **TAINT** (untrusted-read coupling) | Prompt injection riding in on adversarial read output (guest logs, quarantine mail, free-text config) then steering a mutation the agent confirms for itself | **Off** | `PROXIMO_TAINT_TRACK`, `PROXIMO_TAINT_FORBID`, `PROXIMO_TAINT_REQUIRE_CONSENT`, `PROXIMO_TAINT_FENCE` |
| **PRINCIPAL** (who-asked) | A PROVE ledger that records *what* happened but not *who asked* — attribution gaps across doors, and (with pins) network callers whose identity is unproven | **Off** | `PROXIMO_PRINCIPAL`; `PROXIMO_CALLER_KEYS_DIR` for a signed badge at a network door |

Four more switches widen what Proximo can **do**, rather than protect what it's already
doing — don't confuse them with the gates above: `PROXIMO_ENABLE_EXEC` (near-root
`ssh → pct exec`), `PROXIMO_ENABLE_AGENT` (qemu-guest-agent in-guest ops),
`PROXIMO_ENABLE_NODE_SHELL` (the host's read-only battery) and `PROXIMO_ENABLE_DOWNLOAD`
(bytes land on this host). All are off by default and, once on, each is bounded by its own
fail-closed allowlist or cap, and each is judged like any mutation.

There is nothing to scope: the door advertises six tools, a plane you have not configured is
not reachable, a plane you have is reachable whole, and the gates do not shrink with the
doorway. What a token may do is decided by the vendor; what an address may do is decided by
its method and its tier; nothing an agent sends changes either.

## Prompt injection / untrusted tool output

Several published reads pull text off the Proxmox stack straight into an agent's context —
and some of that text is written by whoever controls the guest, the mail traffic, or the log
line, not by the operator. That's a prompt-injection channel: **no exploit needed, just a
persuasive string placed somewhere Proximo will read it back to the agent.**

Addresses worth attention because they can carry attacker- or guest-controlled text:

- **Node syslog and journal** — `GET /nodes/{node}/syslog`, `GET /nodes/{node}/journal`:
  anything that can write to the journal (a process inside a guest, a crafted unit name) can
  place text here.
- **The shell lane's output** — a container's or a guest's own workload controls what a
  command prints.
- **Task logs** — `GET /nodes/{node}/tasks/{upid}/log`: mostly Proxmox's own output, but can
  echo user-supplied strings from the operation that produced it.
- **Guest names, notes, and descriptions** — `GET /cluster/resources`, a guest's config, and
  free-text `description=` fields: anyone with guest create/edit rights can set these.
- **The PMG quarantine and tracker, especially** — `GET /quarantine/spam`,
  `GET /quarantine/virus`, `GET /nodes/{node}/tracker`: these exist specifically to surface
  **attacker-authored spam/phishing content**. Handing that straight to an agent's context
  is, by design, handing it adversarial input.

**This is a real frontier — not solved, but no longer unmitigated.** An opt-in **TAINT**
control turns "an untrusted read happened" into something the engine can act on by
construction:

- **Classification by address.** `src/proximo/core/taint.toml` names every address whose
  response carries guest- or externally-authored bytes, with the sentence that says why,
  and the engine marks the same sticky marker before serving one. Honest limit: that record
  is total over what 0.44's curated tools ever classified, not over every read the vendor
  publishes; an address no tool ever served is unclassified and served untainted.
- **Track (by construction).** With `PROXIMO_TAINT_TRACK` (or either coupling below) set,
  reading adversarial content writes a **sticky** taint marker beside the ledger and stamps
  `untrusted:true` on the row — so DIAGNOSE/audit can see a mutation that *followed*
  adversarial input. The marker clears **only out-of-band** (no tool clears it; a consumed
  CONSENT grant does **not** clear it). It survives a process restart.
- **Forbid (the primary enforcement).** Once tainted, `PROXIMO_TAINT_FORBID` addresses are
  refused outright — **no consent escape**, a hard wall before consent. Point it at the
  cross-domain infra addresses (firewall/network/access/token/exec/guest-power): "a session
  that has read quarantine mail cannot then reconfigure the firewall" is enforced by the
  envelope the operator declared once, not by a human approving each call.
- **Consent (the in-domain residue).** `PROXIMO_TAINT_REQUIRE_CONSENT` makes CONSENT
  mandatory for any tainted mutation the forbid set doesn't cover — the case where the
  legitimate workflow and the attack are the *same* call (read quarantine → act on
  quarantine). Fail-closed if the consent dir isn't configured.
- **Fence (advisory).** `PROXIMO_TAINT_FENCE` wraps adversarial output in a labelled
  envelope. It helps a cooperating agent and the human reading the transcript; a hijacked
  agent can ignore it. **Advisory only — never a guarantee.**

**Honest limits (do not over-read this):** TAINT's forbid/consent walls are a real boundary
only when the marker dir and consent dir sit **outside the agent's own write reach** — the
same two-deployment condition every gate here carries. Co-located, a compromised agent can
`rm` the marker; then it is a speed-bump plus an observability signal, and CONTAIN's
out-of-band kill is the real backstop. Classification is a curated record — a channel
mis-classified as trusted is a residual gap the engine can't self-detect (bias: classify
adversarial when unsure). And TAINT only guards mutations *after* the untrusted read — which
is the whole injection vector, but state it plainly.

**The strongest control is deployment shape, not a runtime gate.** Split the work across
**two agent contexts**: a read-only "inbox/log reader" (a read-only Proxmox token) and a
mutator (the untrusted-read addresses in its FORBID list). The injection channel and the
mutation capability never meet in one context, and this survives even a fully compromised
Proximo process (the Layer-1 token floor). Its load-bearing half — that the two reach
*different* agent contexts — is the deployer's to arrange; Proximo can't enforce it
server-side.

## Reporting a vulnerability

**Please do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting — open a report directly at
**https://github.com/john-broadway/proximo/security/advisories/new** — or:

1. Go to the repository's **Security** tab → **Report a vulnerability**.
2. Describe the issue, the affected version/commit, and a reproduction if you have one.

That opens a private advisory thread visible only to you and the maintainer.

Proximo is independently maintained — expect a serious, best-effort response, not a
contractual SLA. Reports are acknowledged as quickly as is practical, and disclosure
is coordinated with you: a fix and an advisory go out together, with credit unless you
ask otherwise.

## What's most worth your attention

The highest-value areas to probe, because they're where the trust model lives or where
access is broadest:

- **Trust-spine bypass.** Any path that mutates state *without* a PLAN, that runs while
  disarmed or untiered, that escapes a fail-closed UNDO where one is expected, or that
  writes the PROVE ledger without extending the hash chain. A way to advance the head
  undetected, or to forge a verifying chain, is in scope.
- **Independent-gate bypass.** A way for a mutation to proceed while a configured
  CONSENT/CONTAIN/FORBID/RATE/TAINT gate would have blocked it — especially by writing to
  the gate's own state from within the agent's own reach — is in scope, and is exactly the
  Layer-2 failure mode described above.
- **The held lines.** Twenty published mutations are refused by sentence (`docs/arena.md`):
  login tickets, the node's `execute`, the cluster join. A way to reach one through the
  door, or an address with the same shape that is not on the list, is in scope.
- **The shell lane.** `PROXIMO_ENABLE_EXEC=1` enables `ssh → pct exec`, which is near-root
  on the host. It's opt-in and fail-closed behind a CTID allowlist and the split-target
  guard — any allowlist bypass, a way to reach exec without the flag, or a call that lands on
  a node other than the one its path names, is high severity.
- **The network doors (A2A, HTTP, and MCP-over-streamable-HTTP).** The three optional
  network doors share one fail-closed perimeter (`proximo.core.perimeter.guard`): all refuse
  non-localhost binds without a bearer token, and all enforce a Host/DNS-rebind allowlist
  (`PROXIMO_A2A_ALLOWED_HOSTS` / `PROXIMO_HTTP_ALLOWED_HOSTS` /
  `PROXIMO_MCP_HTTP_ALLOWED_HOSTS`). All serve the six tools through the SAME engine the
  stdio door uses — there is no second mutate path. Auth bypass, header smuggling, rebind
  escape, a path that reaches the engine bypassing the perimeter, or a mutation that fires
  without `confirm=true` are all in scope. One deliberate asymmetry: the REST and A2A doors
  sanitize a failing call's error text before returning it; the MCP-HTTP door, being MCP
  itself with no adapter layer, returns the error detail at the *stdio* level. A bearer for
  the MCP-HTTP door therefore carries the same trust weight as local stdio access.
- **Secret handling.** Proximo takes its tokens by path, never as a literal in a shell
  line. A path where a token, key, or other secret is logged, echoed into the audit ledger,
  or otherwise persisted in cleartext is in scope. At load time, every secret file
  referenced by path — the tokens, the PMG credential, the audit HMAC key, the bearer
  tokens, the A2A signing key — is refused if group/other can access it (`mode & 0o077`).
- **Credentials in what a read returns.** Some published reads carry a credential in their
  response (a PMG fetchmail password, a PBS remote's password, an ACME plugin's DNS-provider
  keys, an SDN lock token). `src/proximo/core/secrets.toml` names each such address and
  field; the engine withholds those fields before the response reaches the model and says
  which in `withheld`, and the ledger fingerprints the same fields when a mutation sends
  them or UNDO captures them. The record is built from every read 0.44's curated tools
  stripped plus every field the vendor's return schema declares as a credential; a schema
  that declares no return shape says nothing either way, so a credential the vendor returns
  undeclared, on an address no tool ever stripped, is not in it. Such an address is in scope.

## Honest scope notes

- **Tiers are a blast-radius judgement, not a sandbox.** A low tier means "small blast
  radius", **not** "safe." Proximo previews, undoes, and proves — it does not sandbox the
  Proxmox API. A report that boils down to "a high-tier op did the dangerous thing it said it
  would do, with a plan and an audit record" is working as designed.
- **The token you mint is the hard floor** — see "The two-deployment trust model" above.
  Running Proximo with a broadly-scoped or root-equivalent token against that guidance is
  operator misconfiguration, not a Proximo vulnerability — though reports of Proximo
  *encouraging* such a configuration are welcome.
- **UNDO is not universal.** It covers what the vendor publishes a write to put back. A
  delete, a collection, a path with no PUT, or a PUT that is a different operation from the
  POST gets a sentence instead of a restore. That's documented scope, not a missing feature.
- **The opt-in gates (CONSENT/CONTAIN/ARM/FORBID/RATE/TAINT) are inert until configured**
  — see "Security controls & defaults" above. A report that one of them "didn't stop"
  an action when its env var was never set is expected behavior, not a finding.
- **Not yet proven:** a small local model finishing a whole task through the door (a stock 1.5B
  was driven against a real node inside a 4,096-token context: its calls landed, the prompt
  peaked at 3,074 tokens, and it did not finish the task), hardware-watchdog fencing, and
  behavior at production scale.

## Verifying authenticity

- **Container image (GHCR):** every published image carries a sigstore-signed
  build-provenance attestation and an SPDX SBOM. Verify before trusting a pull:
  `gh attestation verify oci://ghcr.io/john-broadway/proximo:<tag> --owner john-broadway`
- **PyPI (`proximo-proxmox`):** published via GitHub Actions OIDC Trusted Publishing —
  no long-lived API token sits in the release path.

If a downloaded artifact fails verification, treat it as untrusted and report it here.
