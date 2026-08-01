# Security Policy

Proximo gives an AI agent a real control plane over Proxmox VE and PBS. Its whole
design premise is that mutations are previewable, reversible, and recorded — so taking
its security seriously is the point, not an afterthought. Reports are genuinely welcome.

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
   LEASE/SCOPE/ENVELOPE controls (table below). These raise the bar **within** Proximo's
   own trust domain: previews before mutation, a tamper-evident record, rollback where
   Proxmox allows it, and (opt-in) independent authorization, a kill-switch, arm-TTL,
   declared scope, and rate/blast-radius limits. But they're enforced by code running in
   the *same process, same OS user* as the agent they're meant to constrain. If that agent
   (or whatever's hijacked it) can also write to a gate's own state — the CONSENT
   directory, the CONTAIN trip-file path, the SCOPE file, the rate-reservation directory, the caller-keys pin directory —
   it can potentially clear its own gate. **These become a real boundary, not just a
   speed bump, only when their state directories live outside the agent's write reach** —
   a different OS user, a different filesystem mount, a different host entirely. Point
   every gate's `PROXIMO_*_DIR` / `PROXIMO_*_PATH` somewhere the agent process itself
   cannot write, or treat them as advisory.

Layer 1 is why Proximo is safe to hand to an agent at all. Layer 2 is what makes that
agent *productive* — previews, receipts, budgets — without pretending it's a sandbox.

## Scoping the token (the hard floor, in practice)

The privilege separation you want already exists, server-side, in the product: Proxmox's
token model. Proximo deliberately does **not** wrap it in a broker, proxy, or signer of its
own — a local layer would sit in the same trust domain as the agent and add ceremony, not
enforcement. Use Proxmox's model directly:

1. **Start read-only.** A privilege-separated token (`--privsep 1`) carries *its own* ACL —
   it inherits nothing from the user's *other* rights. But its effective permissions are the
   *intersection* of the user's ACL and the token's ACL, not the token's ACL alone — grant
   `PVEAuditor` at `/` to **both** the token and the user (a freshly-created user has no ACL
   of its own, so skipping the user grant leaves the intersection empty: a token that
   authenticates but can do nothing). The click-by-click and CLI versions are in
   [SETUP.md](docs/SETUP.md) (Step 2); `proximo mint` prints the same runbook for every plane —
   PVE, PBS, PMG, PDM — each with its read-only and scoped-write role, granted to both.
2. **Widen deliberately, by path.** Write access is granted where you mean it and nowhere
   else: `pveum acl modify /vms/100 --tokens 'proximo@pve!readonly' --roles PVEVMAdmin`
   followed by the matching `--users 'proximo@pve'` grant arms exactly one VM. Never grant
   `Administrator` at `/` to an agent-facing token.
3. **Two tokens, not one big one.** The strongest single-box posture: the everyday
   `PROXIMO_TOKEN_PATH` holds the **read-only** token; a separately-scoped **write** token
   lives in a file the agent's user cannot read, swapped into place by *you*, out-of-band,
   when there's work to do — and swapped back (or left to the **LEASE** arm-TTL, which
   fails closed on a missing token file). The write credential simply does not exist in
   the agent's world between arms. This is privilege separation done with Proxmox-side
   objects — two credentials with different server-enforced scopes — rather than with
   local machinery pretending to be a boundary.
4. **Verify the boundary before any AI sees it.** `proximo doctor` prints the token's
   `can` / `cannot` lists — the grant, confirmed by Proxmox itself, in writing. When a
   capability is missing it prints the exact `pveum` command that would grant it, so
   widening stays a deliberate act.
5. **Protect the file like it's the credential — it is.** `chmod 600`; Proximo refuses at
   startup if the token or audit-key file is group/other-accessible. Revocation is instant
   and yours: `pveum user token remove proximo@pve readonly` ends everything, mid-session.

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

# a root-owned directory for gate state: the agent may write INTO it (for the anchor),
# but the sticky bit stops it removing or replacing the root-owned files (the trip)
install -d -m 1770 -o root -g proximo /etc/proximo
```

Mode `1770` grants the `proximo` group `rwx` plus the sticky bit, and gives the world
nothing (not `1777`/`1773`). Sticky means the agent cannot delete or rename a file it does
not own, even in a group-writable directory. That one mode serves both gates below:
root owns the CONTAIN trip so the agent can't clear it, while the agent can still write
the audit anchor.

Set the env vars that name these paths from a **root-owned environment**, not the MCP
client's own config. A systemd unit `EnvironmentFile` (root-owned, `600`) is the right
home for `PROXIMO_CONTAIN_TRIP_PATH` and `PROXIMO_AUDIT_ANCHOR_*`. Do not set them in the
agent's client config (e.g. `~/.claude.json`): the agent can write that file and simply
repoint or unset the very switch it is meant to be constrained by.

### CONTAIN: a kill-switch the agent cannot clear

`contain.py` reads `PROXIMO_CONTAIN_TRIP_PATH` fresh on every mutation and fails closed.
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
breaker is advisory: a compromised agent clears it.

### ARM: mint the write credential, don't stockpile it

The everyday token is read-only; the default arm pattern (see "Scoping the token", point
3) swaps in a pre-minted write token. The stronger pattern keeps no write token at rest at
all: mint it at arm, revoke it at disarm, both as **root on the Proxmox host**, a hand the
confined agent does not have, so the agent cannot arm itself.

```sh
# ARM: run as root on the PVE host (or over SSH to it from your own workstation):
umask 177
pvesh create /access/users/proximo@pve/token/arm --privsep 1 --output-format json \
  | python3 -c 'import json,sys; print("proximo@pve!arm=" + json.load(sys.stdin)["value"], end="")' \
  > /run/proximo/arm.token          # tmpfs, root-owned, 600 (never a persisted .env)
pveum acl modify /vms --tokens 'proximo@pve!arm' --roles PVEVMAdmin
pveum acl modify /vms --users  'proximo@pve'      --roles PVEVMAdmin
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
Proxmox, which the confined agent lacks. Compose it with LEASE (`PROXIMO_ARM_TTL`) so a
forgotten disarm still fails closed when the lease lapses, and with SCOPE
(`PROXIMO_SCOPE_PATH`) to bound the arm to named targets.

#### `proximo arm` / `proximo disarm` — the swap, for the pre-minted pattern only

The recipe above is the mint-and-revoke deployment, and it stays a manual root-on-Proxmox
act: no write token exists at rest there, so there is nothing on the agent box to swap.
For the **pre-minted** pattern — one write token kept at rest, swapped in and out — the
swap is mechanical, and two commands do it:

```sh
proximo arm     --session ci-7f2a      # install the write token
proximo disarm  --session ci-7f2a      # put the read-only one back
```

Point `PROXIMO_ARM_SOURCE` at the write token and `PROXIMO_READONLY_SOURCE` at the
everyday one. With `PROXIMO_SESSION_DIR` set, each session key gets its own token file, so
arming one caller leaves the others read-only. The key comes from `--session` or
`PROXIMO_SESSION_KEY` and is yours to choose — Proximo never infers it from a client's
environment.

Naming a session **without** `PROXIMO_SESSION_DIR` set is refused rather than served. The
only place left to install the token would be the shared `PROXIMO_TOKEN_PATH`, which arms
every caller on the box — wider than what was asked for, and widening authority past the
operator's stated intent is the failure this whole section exists to prevent. Drop
`--session` to arm globally on purpose. `disarm` does not mirror that refusal: its fallback
only ever *removes* authority, so it restores the shared token and says so.

**These commands grant no authority the caller did not already have.** Anyone who can run
`proximo arm` can already read `PROXIMO_ARM_SOURCE` and copy it into place; the command is
ergonomics over that fact, not a new door. Whether an arm is a real boundary is therefore a
question of **file ownership, not of software** — the same thing that decides whether the
CONTAIN breaker is real or advisory. So `arm` reads the source's mode, its owner, **and the
owner and mode of the directory holding it**, then tells you which one you have:

```
boundary: REAL, conditional on the server not running as uid 0
   (the arm source (the write token) is mode 0o600, owned by uid 0, in a directory owned by
   uid 0, and no other uid can read or replace it; …)
boundary: ADVISORY — the arm source is not protected against a second uid:
     - the arm source is owned by uid 65534, not the uid running this command (0), so that
       uid can rewrite it whatever its mode says
```

`ADVISORY` is not a warning that something broke; it is the accurate description of a
single-uid box, where the process that reads the token can also replace it.

To get a real boundary the file's mode is **not sufficient on its own**: mode `600` says
who may open the file, and says nothing about who may delete it and put another one there.
Whoever owns the containing directory can unlink and replace the entry, and whoever owns
the file can rewrite it regardless of its mode. So a real boundary needs the arm source
**and its directory** owned by the uid you arm from, neither group- nor other-writable,
armed from a root context — or use mint-and-revoke so no write token exists at rest at all.
`disarm` gets the same disclosure about `PROXIMO_READONLY_SOURCE`, because a read-only
source a second uid can rewrite is what turns a future `disarm` into a reported success
that leaves write authority live.

`disarm` resolves every ambiguity toward read-only: an unusable session key falls back to
the global token path rather than refusing, because a refused disarm is the one outcome
that leaves write authority live. It refuses loudly in exactly one case — no read-only
token to restore — where it cannot do the safe thing at all and a false `DISARMED` would be
worse than an error.

#### `proximo reap` — the arm that outlived its session

An arm is a file on disk, read fresh per call, so it survives the thing that asked for it.
A session that crashes, is killed, or simply loses its client leaves the write token sitting
in place with nobody left to disarm it. LEASE closes that by *expiring on time*; `reap`
closes it by *noticing the session is gone*, which needs no TTL and so does not cut a long
session short. They compose — use both.

```sh
proximo reap --dry-run     # decide, change nothing
proximo reap               # restore the read-only token for every ended session
```

**The kernel is the liveness oracle, not a heuristic.** A serving process holds a *shared*
`flock` on a sidecar `<session>.lock` for its whole life, and `reap` tries an *exclusive*
non-blocking lock: that can only succeed once every holder is gone, and the OS releases
those on exit, crash and `SIGKILL` alike. Nothing polls, nothing heartbeats, and nothing
inspects the client — which is what makes it work for any MCP client rather than one
particular agent harness. A shared lock (not exclusive) means several processes may serve
one session key while a single exclusive try still detects that all of them died.

Run it from a timer, or at the start of an operator session. It is safe to run at any
moment, including while sessions are live: a live holder is simply reported and skipped.

Two behaviours worth knowing before you rely on it:

- **Uncertainty resolves toward reaping.** A missing lock file, a permission error, or a
  symlinked lock path all read as *dead*. That is deliberate: reaping only ever **removes**
  write authority, so a wrong "dead" verdict costs one `arm`, while a wrong "live" verdict
  leaves the write key in place indefinitely. It also means a planted symlink cannot be used
  to keep an arm alive.
- **A brand-new arm is protected for `PROXIMO_REAP_GRACE` seconds (default 300).** Between
  `arm` and the server taking its lock, nobody holds it — without that window `reap` would
  cut an arm that is seconds old and about to be picked up. It is a startup-race guard, not
  a TTL: it expires nothing on its own. Set it to `0` only if you arm and connect in one
  motion, and note that a garbled value falls back to the default rather than to zero, so a
  typo cannot silently start cutting live arms.
- **File cleanup is opt-in and can only deny, never grant.** With `PROXIMO_REAP_UNLINK_DAYS`
  set, `reap` also unlinks session token + lock files that are proven read-only, unheld, and
  idle past the TTL — the removal happens while holding the file's own exclusive lock, so it
  cannot race a session that is just starting. A dangling symlink is cleaned on the same
  terms: it has no target to hold bytes, so it provably is not the write token by shape. Any
  other unreadable file stays put and is reported as an error — unreadable means unprovable.
  Note the garbled-value direction is the *opposite* of `PROXIMO_REAP_GRACE`: an unparseable
  value disables unlinking, because deletion is the destructive verb and a typo must not
  enable it.

Holding the lock is best-effort and never blocks startup, so the honest limit is this: an
arm that never gets held (an older server, a read-only session dir) reads as dead once the
grace window passes and is disarmed. That direction costs an `arm`, never authority.

If revoke-at-disarm is operationally too heavy (it needs root on the Proxmox host every
cycle), the lighter form keeps one pre-minted write token but seals it at rest with `age`
or `sops`, so it doesn't exist in cleartext in the agent's world between arms: arm
decrypts to a tmpfs path with your key, disarm shreds the plaintext. It's weaker than
mint-and-revoke, since the credential still exists (only encrypted), but it removes the
standing plaintext secret.

### PROVE: an off-box head anchor

`PROXIMO_AUDIT_EXPECTED_HEAD` pins the ledger head so a tail truncation, a forged append,
or a full wipe is caught. But **every recorded call advances the head, reads included**,
so a hand-pinned value goes stale immediately. Prefer the auto-anchor
(`PROXIMO_AUDIT_ANCHOR_SINK=file` + `PROXIMO_AUDIT_ANCHOR_FILE_PATH`): Proximo reads the
last pin at startup and verifies against it, and the anti-poisoning rule means it never
re-pins a head that has MOVED (a verify that just caught a truncation cannot overwrite the
good pin).

Placement is the whole game, because the anchor's value is that it's less compromisable
than the agent box:

- **The strong form is genuinely off-box.** Point the anchor file at a mount or store on
  a different, less-compromisable host, where this box writes the latest head but a
  separate authority retains and monitors history.
- **On a single box, mind the mechanism.** Proximo itself (as the agent user) writes the
  pin, via `audit_verify`'s on-demand export, so a file the agent literally *cannot* write
  fails closed and breaks the tool. The property you want is not "the agent can't touch
  it" but "the agent writes the latest, and can't erase the history you keep." Put the
  anchor in the root-owned `/etc/proximo` (group-writable, so the atomic publish works)
  and have root independently retain each published head: a root-only append log, or
  filesystem snapshots of the file. Without that retained history, a non-root compromise
  that bothers to rewrite the pin defeats a single-box anchor; it still catches the far
  more common truncate-or-wipe.

When you're done, verify the boundary you built. `proximo doctor` reports which pillars
stand and which sockets are empty, and it never echoes the configured paths back (a
hijacked session shouldn't learn where you put your switch).

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
be a pillar the agent could lower for itself. `proximo doctor` now reports the spine:
which pillars stand, which sockets are empty, and exactly how to fill them (it never echoes
the configured paths back — a hijacked session shouldn't learn where you put your switch).

| Control | Defends against | Default | Turn on with |
|---|---|---|---|
| **PLAN** | A mutation landing with no preview, no blast-radius accounting, no chance to review first | **On**, always | n/a — not optional |
| **PROVE** | An edited, reordered, or silently truncated mutation history | **On** (keyed HMAC-SHA256 ledger) | `PROXIMO_AUDIT_KEYED` (default `true`; `off` downgrades to unkeyed — not recommended). Catching *tail truncation / full wipe* needs an off-box head anchor — that's opt-in: `PROXIMO_AUDIT_EXPECTED_HEAD` / `PROXIMO_AUDIT_ANCHOR_*`. |
| **UNDO** | An unrecoverable mistake on a plane Proxmox can snapshot | **On** for the planes it covers (fail-closed) | No env var, but **not uniform**: `pve_guest_config_set` returns `prior_config` on every confirmed call (revertible via `pve_guest_config_revert`) and `pve_rollback` restores a guest snapshot — both always available. The **`ct_exec`/`ct_psql` auto-snapshot is OPT-IN PER CALL** (`snapshot=true`, default `false`); when requested it is fail-closed — the command does not run if the snapshot cannot be taken — but a default exec call takes no snapshot. firewall/SDN/ACL/token have no Proxmox rollback primitive by design, not by configuration. |
| **DIAGNOSE** | Acting on a guest/node with no read-only evidence gathered first | **On**, always | n/a — read-only, always available |
| **CONSENT** | An agent — compromised, confused, or persuaded by injected instructions — confirming its own mutation with no independent, out-of-band grant | **Off** | `PROXIMO_CONSENT_DIR` (+ `PROXIMO_CONSENT_TTL_SECONDS` for grant expiry) |
| **CONTAIN** (kill-switch) | Needing to halt *every* mutation immediately, mid-incident, without a redeploy or restart | **Off** | `PROXIMO_CONTAIN_TRIP_PATH` |
| **LEASE** (arm-TTL) | A write-armed token staying armed indefinitely after the operator meant to hand it back to read-only | **Off** | `PROXIMO_ARM_TTL` (also requires `PROXIMO_TOKEN_PATH` — an unresolvable path fails closed, never "assume fresh") |
| **SCOPE / provenance** | An agent mutating a target outside the box(es) the operator authorized at arm-time | **Off** | `PROXIMO_SCOPE_PATH` — a present-but-unreadable/garbled/empty scope file fails **closed**; an **absent** file reads as no-scope (unrestricted) — the transitional armed-not-written window. NB this differs from LEASE, which fails closed on an absent token: set the scope file before relying on SCOPE. |
| **ENVELOPE** (FORBID + RATE) | Blast radius under hijack — unlimited-speed mutation, or an explicitly forbidden action, from an agent that's been compromised or gone off-script | **Off** | `PROXIMO_FORBID` (global floor, always checked once set) + `PROXIMO_RATE_MAX` / `PROXIMO_RATE_WINDOW` (per-box budget) |
| **TAINT** (untrusted-read coupling) | Prompt injection riding in on adversarial read output (guest logs, quarantine mail, free-text config) then steering a mutation the agent confirms for itself | **Off** | `PROXIMO_TAINT_TRACK` (mark + record a sticky taint on an adversarial read) then, once tainted, `PROXIMO_TAINT_FORBID` (actions refused outright — the primary, no consent escape) and/or `PROXIMO_TAINT_REQUIRE_CONSENT` (any mutation now needs an out-of-band grant). `PROXIMO_TAINT_FENCE` adds an advisory content-fence. |
| **PRINCIPAL** (who-asked) | A PROVE ledger that records *what* happened but not *who asked* — attribution gaps across faces, and (with pins) network callers whose identity is unproven | **Off** | `PROXIMO_PRINCIPAL` stamps a declared name-tag on every entry (the operator's word, like the token). `PROXIMO_CALLER_KEYS_DIR` verifies signed ES256 caller badges against operator-pinned keys and, once set, **refuses an unverifiable caller on the network faces** (fail-closed). Identity, not authority — a verified name changes nothing about what a call may do; the token ACL remains the only authorization boundary. **Two honest limits.** *"Verified" is only as strong as the pin directory's isolation:* an agent that can write `PROXIMO_CALLER_KEYS_DIR` can pin a key it controls and be recorded `via:verified` — keep the pin dir outside the agent's own write reach, the same two-deployment caveat the gates above carry. *A badge is a long-lived bearer credential:* it does not expire unless minted with `--exp`, its only revocation is deleting the caller's pin file (which takes effect on that face's next protected request — the pin store is re-read whenever the directory changes, so revocation does not wait for a restart; rewriting an existing pin file in place is the one edit the directory stamp cannot see, and it requires ownership of that file), and it is not bound to a TLS session — so treat a leaked badge like a leaked bearer token (standing impersonation until unpinned), keep it off disk and out of logs, and rotate it. |

Two more flags widen what Proximo can **do**, rather than protect what it's already
doing — don't confuse them with the gates above: `PROXIMO_ENABLE_EXEC` (near-root
`ssh → pct exec`) and `PROXIMO_ENABLE_AGENT` (qemu-guest-agent in-guest ops). Both are
off by default and, once on, are each bounded by their own fail-closed CTID/VMID
allowlist.

Proximo *narrows* what it even offers to the planes in use. By default it **auto-scopes
to the planes you've configured**: a plane's tools are registered only when its
`PROXIMO_*_BASE_URL` is set (or a target of that kind exists), so a PVE+PBS-only box
never puts pmg_/pdm_ tools in the client's context. To pin an exact set, `PROXIMO_SURFACES`
(e.g. `pve,exec`) registers only the named planes — everything else is removed from the MCP
registry before serving, so it is not advertised in `tools/list` and does not cost your model
context. **It is NOT removed from reach.** `proximo_call` is resident in every mode and
dispatches by exact name from a snapshot taken before any scoping ran, so a scoped-away tool is
still callable if a caller names it — with every gate intact, because the gates live in each
tool's own body, not in whether it was registered. Treat surface scoping as CONTEXT SIZING, never
as a brake: if you need a capability to be unavailable, withhold it in the Proxmox token's ACL or
disable its call-time flag (`PROXIMO_ENABLE_EXEC` and `PROXIMO_WIKI` are opt-in and off unless
set; estate memory is on by default and `PROXIMO_MEMORY=0` opts out) — these are enforced at
call time and `proximo_call` cannot defeat them. `audit_verify` and `proximo_call` are always
kept. Precedence: `PROXIMO_TOOLS`, then `PROXIMO_TOOLSETS` (including the keywords `dynamic`,
`catalog`, `all`), then an explicit `PROXIMO_SURFACES` (`=all` forces the full surface);
`PROXIMO_AUTOSCOPE=off` disables plane auto-scoping; with nothing picked the default is the
dynamic facade — a small resident door with everything this box serves still callable through
it, never a surprise-empty server. An unknown surface name refuses startup rather than silently
serving a surface you didn't pick. This is context hygiene, not attack-surface reduction and not an
authorization control — the token's ACL remains the real boundary.

*Status note: CONSENT/CONTAIN/LEASE/SCOPE/ENVELOPE/TAINT/PRINCIPAL are present in this repository's
current source. Check `CHANGELOG.md` against the version you actually installed — a
published package can lag the tree you're reading; these gates land in a release only
when their changelog entry says so.*

## Prompt injection / untrusted tool output

Several of Proximo's read tools pull text off the Proxmox stack straight into an
agent's context — and some of that text is written by whoever controls the guest, the
mail traffic, or the log line, not by the operator. That's a prompt-injection channel:
**no exploit needed, just a persuasive string placed somewhere Proximo will read it
back to the agent.**

Tools worth attention because they can carry attacker- or guest-controlled text:

- **Node/CT syslog and journal** — `pve_node_syslog`, `pve_node_journal`,
  `pmg_node_syslog`: anything that can write to the journal (a process inside a guest, a
  crafted service/unit name) can place text here.
- **`ct_logs`** — tails a systemd unit's log inside a container; the container's own
  workload controls that content.
- **Task logs** — `pve_task_log`: mostly Proxmox's own output, but can echo
  user-supplied strings from the operation that produced it.
- **Guest names, notes, and descriptions** — `pve_list_guests`, `pve_guest_config_get`,
  `pve_cluster_resources`, and free-text `description=` fields on mappings/objects:
  anyone with guest create/edit rights can set these.
- **The PMG quarantine tools, especially** — `pmg_quarantine_spam`,
  `pmg_quarantine_virus`, `pmg_quarantine_attachment`, `pmg_tracker_list` /
  `pmg_tracker_detail`: these exist specifically to surface **attacker-authored
  spam/phishing content** — subject lines, sender strings, message bodies written by
  whoever sent the mail. Handing that straight to an agent's context is, by design,
  handing it adversarial input.

**This is a real frontier — not solved, but no longer unmitigated.** An opt-in **TAINT**
control (`taint.py`, off by default) turns "an untrusted read happened" into something the
server can act on by construction:

- **Classification by channel.** Every tool whose return carries guest- or externally-authored
  bytes is classified adversarial — the logs and quarantine tools above, *and* the exec-output
  tools (`ct_exec`, `ct_psql`, `pve_agent_exec`) and in-guest `pve_agent_file_read`, even though
  those mutate. A completeness test fails CI if a new tool ships unclassified, so the set can't
  silently fall behind the surface.
- **Track (by construction).** With `PROXIMO_TAINT_TRACK` (or either coupling below) set, reading
  adversarial content writes a **sticky** taint marker beside the ledger and stamps `untrusted:true`
  on the ledger entry — so DIAGNOSE/audit can see a mutation that *followed* adversarial input. The
  marker clears **only out-of-band** (no tool clears it; a consumed CONSENT grant does **not** clear
  it — otherwise a hijacked agent could get a sacrificial benign action approved to launder the
  taint). It survives a process restart.
- **Forbid (the primary enforcement).** Once tainted, `PROXIMO_TAINT_FORBID` actions are refused
  outright (`blocked:taint_forbidden`) — **no consent escape**, a hard wall before consent at every
  seam. Point it at the cross-domain infra actions (firewall/network/access/token/exec/guest-power):
  "a session that has read quarantine mail cannot then reconfigure the firewall" is enforced by the
  envelope the operator declared once, not by a human approving each call.
- **Consent (the in-domain residue).** `PROXIMO_TAINT_REQUIRE_CONSENT` makes CONSENT mandatory for
  any tainted mutation the forbid set doesn't cover — the case where the legitimate workflow and the
  attack are the *same* call (read quarantine → act on quarantine). Fail-closed if the consent dir
  isn't configured.
- **Fence (advisory).** `PROXIMO_TAINT_FENCE` wraps adversarial output in a labeled envelope. It
  helps a cooperating agent and the human reading the transcript; a hijacked agent can ignore it.
  **Advisory only — never a guarantee.**

**Honest limits (do not over-read this):** TAINT's forbid/consent walls are a real boundary only
when the marker dir and consent dir sit **outside the agent's own write reach** — the same
two-deployment condition every gate here carries. Co-located (agent shares the filesystem), a
compromised agent can `rm` the marker; then it is a speed-bump plus an observability signal, and
CONTAIN's out-of-band kill is the real backstop. Classification is a curated set — a channel that's
mis-classified as trusted is a residual gap the module can't self-detect (bias: classify adversarial
when unsure). And TAINT only guards mutations *after* the untrusted read — which is the whole
injection vector, but state it plainly.

**The strongest control is deployment shape, not a runtime gate.** Split the work across **two
agent contexts**: a read-only "inbox/log reader" (a read-only Proxmox token, mutation tools not on
its surface) and a mutator (the untrusted-read tools not on its surface). The injection channel and
the mutation capability never meet in one context, and this survives even a fully compromised Proximo
process (the Layer-1 token floor). Its load-bearing half — that the two surfaces reach *different*
agent contexts — is the deployer's to arrange; Proximo can't enforce it server-side. Prefer this for
any PMG-facing workflow; use the TAINT gate to protect the deployments that won't split. A
plan-pinning form (only mutations planned *before* the taint event may run) is a stronger future
direction, not yet built.

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

- **Trust-spine bypass.** Any path that mutates state *without* a PLAN, that escapes a
  fail-closed UNDO where one is expected, or that writes the PROVE ledger without
  extending the hash chain. The ledger's strong guarantee is the off-box `head()`
  anchor (head-pinning via `audit_verify(expected_head=…)`); a way to advance the head
  undetected, or to forge a verifying chain, is in scope.
- **Independent-gate bypass.** A way for a mutation to proceed while a configured
  CONSENT/CONTAIN/LEASE/SCOPE/ENVELOPE gate would have blocked it — especially by
  writing to the gate's own state (its trip file, scope file, consent grant, or rate
  reservation) from within the agent's own reach — is in scope, and is exactly the
  Layer-2 failure mode described above.
- **The in-container exec edge.** `PROXIMO_ENABLE_EXEC=1` enables `ssh → pct exec`,
  which is near-root on the host. It's opt-in and fail-closed behind a CTID allowlist —
  any allowlist bypass, or a way to reach exec without the flag, is high severity.
- **The network faces (A2A, HTTP, and MCP-over-streamable-HTTP).** The three optional network
  servers — `proximo-a2a` (Agent2Agent), `proximo-http` (HTTP/OpenAPI), and `proximo-mcp-http`
  (the MCP Streamable HTTP transport) — share one fail-closed perimeter (`proximo.webguard`):
  all refuse non-localhost binds without a bearer token, and all enforce a Host/DNS-rebind
  allowlist (`PROXIMO_A2A_ALLOWED_HOSTS` / `PROXIMO_HTTP_ALLOWED_HOSTS` /
  `PROXIMO_MCP_HTTP_ALLOWED_HOSTS`). All serve the FULL governed tool surface through the SAME
  spine path an MCP client takes — A2A and HTTP via the shared dispatch
  (`proximo.governed.call_governed`, the same `mcp.call_tool` path), the MCP-HTTP face by
  serving the FastMCP instance itself — so PLAN-by-default, PROVE, UNDO, the gates, and the
  Proxmox token scope apply identically, and there is no second mutate path. What each transport ADVERTISES is
  scoped by `PROXIMO_TOOLS`/`PROXIMO_TOOLSETS`/`PROXIMO_SURFACES`/autoscope; what any of them can
  REACH is the full registry via `proximo_call`, uniform for every transport, bounded by the token
  ACL and the per-tool gates. Auth bypass,
  header smuggling, rebind escape, a path that invokes a tool bypassing the spine, or a mutation
  that fires without the tool's own confirm gate are all in scope. One deliberate asymmetry: the
  A2A/HTTP dispatch sanitizes a failing tool's error text before returning it (the exec plane's
  raw exceptions can carry a command's argv or an SSH target); the MCP-HTTP face, being MCP
  itself with no adapter layer, returns tool-error detail at the *stdio* level, unsanitized. It
  is therefore not a regression over stdio — but a bearer token for the MCP-HTTP face carries the
  same trust weight as local stdio access, so scope it and reach it accordingly.
- **Secret handling.** Proximo takes its PVE token by path/env, never as a literal in a
  shell line. A path where a token, key, or other secret is logged, echoed into the
  audit ledger, or otherwise persisted in cleartext is in scope. At load time, every
  secret file referenced by path — the PVE/PBS/PDM tokens, the PMG password, the audit
  HMAC key, the A2A/HTTP/MCP-HTTP bearer tokens, and the A2A signing key — is refused if
  group/other can access it (`mode & 0o077`): a mis-deployed `0644` secret fails loud
  with the `chmod 600` fix, not silently. A way to load a secret past that guard on a
  POSIX box is in scope.

## Honest scope notes

- **Risk ratings are an advisory heuristic, not a sandbox.** A tool rated `LOW` means
  "no state change," **not** "safe." Proximo previews, undoes, and proves — it does not
  sandbox the Proxmox API. A report that boils down to "a HIGH-risk op did the dangerous
  thing it said it would do, with a plan and an audit record" is working as designed.
- **The token you mint is the hard floor** — see "The two-deployment trust model" above.
  Running Proximo with a broadly-scoped or root-equivalent token against that guidance is
  operator misconfiguration, not a Proximo vulnerability — though reports of Proximo
  *encouraging* such a configuration are welcome.
- **UNDO is not universal.** Some planes can't be snapshotted by Proxmox (firewall /
  SDN / ACL / token), so they have no rollback primitive by design. That's documented
  scope, not a missing feature.
- **The opt-in gates (CONSENT/CONTAIN/LEASE/SCOPE/ENVELOPE) are inert until configured**
  — see "Security controls & defaults" above. A report that one of them "didn't stop"
  an action when its env var was never set is expected behavior, not a finding.

## Verifying authenticity

- **Container image (GHCR):** every published image carries a sigstore-signed
  build-provenance attestation and an SPDX SBOM. Verify before trusting a pull:
  `gh attestation verify oci://ghcr.io/john-broadway/proximo:<tag> --owner john-broadway`
- **PyPI (`proximo-proxmox`):** published via GitHub Actions OIDC Trusted Publishing —
  no long-lived API token sits in the release path.

If a downloaded artifact fails verification, treat it as untrusted and report it here.
