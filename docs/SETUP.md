# Proximo — Setup (start here)

This guide gets you from nothing to a working, **safe** Proximo install. No prior experience assumed.
If you can log into your Proxmox web page, you can do this.

Proximo lets an AI assistant operate your Proxmox estate. The reason it's safe to point at a box you
care about is **one idea**, so read this part first:

> **You create a Proxmox token. Proxmox itself enforces what that token can do. Proximo can never do
> more than the token allows — no matter what Proximo's code does, and no matter what the AI tries.**
>
> So you start with a **read-only** token: the AI can *look* at everything and *change* nothing —
> enforced by Proxmox, not by us. When you're ready, you mint a **write** token scoped to exactly the
> guests you choose, with an expiry, and nowhere else. The keys never leave your hand.

That's defense in depth, in the right order:

- **The floor — your token's permissions.** Enforced by Proxmox, held by you, impossible for Proximo to exceed.
- **On top — Proximo's safety net.** Every mutation is **planned** (the verdict, the live target and the
  exact change, before anything runs), **proven** (a keyed, tamper-evident record of every move), and
  **undone where the vendor publishes a write to put the record back** (a mutation captures the record it
  is about to change; the restore is the vendor's own write with that record).

> 🔒 **Do every step below in YOUR OWN terminal / browser. Never paste your token secret into an AI chat.**

---

## Before you start

- A **Proxmox VE** server, and an admin login to it (you need admin *once*, to create the token).
- A machine with **Python 3.12+** (your laptop, a VM — anywhere; it talks to Proxmox over the network).
- *(Later, Step 5)* an MCP client — e.g. Claude Desktop or Claude Code.

---

## Step 1 — Install Proximo

```bash
pip install proximo-proxmox
```

(`pipx install proximo-proxmox` or `uvx proximo-proxmox` work too.) Confirm it landed:

```bash
proximo --help
```

---

## Step 2 — Mint a least-privilege token in Proxmox  ← the important step

A **token** is an API key with its own permissions, separate from your password, and revocable any time.
We'll make a **read-only** one first. Proximo prints the exact runbook for your product, and makes no
API call, holds no credential and writes nothing: minting is your act, on the vendor's host.

```bash
proximo mint pve
```

What it prints is the vendor's own commands, which you run **on the Proxmox host**: create a service
user, create a privilege-separated token, grant `PVEAuditor` at `/` to **both** the token and the user,
save the secret to a 600 file. Read it, then run it. The two things it tells you that people get wrong:

- A privilege-separated token's effective permissions are the **intersection** of the user's ACL and
  the token's ACL. A freshly created user has no ACL of its own, so a grant to the token alone leaves
  the intersection empty: a token that authenticates and can do nothing. Grant the role to both.
- The secret is shown **once**. The file holds `USER@REALM!TOKENID=SECRET` with no trailing newline,
  mode 600. Proximo refuses to start on a token file anyone else can read.

The same verb prints the runbook for the other products: `proximo mint pbs`, `proximo mint pmg`
(a credential file of two lines, PMG has no API tokens), `proximo mint pdm`.

---

## Step 3 — Point Proximo at your server

Create `~/.config/proximo/proximo.env`:

```bash
PROXIMO_API_BASE_URL=https://YOUR-PVE-HOST:8006/api2/json   # your Proxmox address, port 8006
PROXIMO_TOKEN_PATH=/home/you/.config/proximo/pve.served     # the SERVED file: a copy of the read token (mint's step 4)
PROXIMO_READONLY_SOURCE=/home/you/.config/proximo/pve-read.token  # the read token itself, what `disarm` restores
# If your Proxmox uses a self-signed certificate, DON'T disable TLS — pin the NODE's cert:
# PROXIMO_CA_BUNDLE=/home/you/.config/proximo/pve-node.pem
# or pin its fingerprint (the form the PVE GUI shows); wire-enforced, exact match:
# PROXIMO_FINGERPRINT=AA:BB:CC:...
```

Every door sources this file before its first env read (`PROXIMO_ENV_FILE` to point elsewhere).

**Which store wins.** Step 5 puts the same variables in your MCP client's `env` block (a daemon gets
them from its unit's `EnvironmentFile`). The door reads that first and fills in from `proximo.env`
only the keys it does not set. A key present in both is fed by the process environment, and the
file's copy of that key is never read. When the two values differ the door says so at start
(`1 key(s) in ... SHADOWED by the process environment`, the key, never the value). Every `PROXIMO_*`
value is fixed when the door starts: after editing either store, restart the server or reconnect
the client.

---

## Step 4 — Verify YOUR boundary, before any AI sees it

This is the safety check. Run the doctor:

```bash
proximo doctor
```

You'll get JSON. It reports, for each configured plane, whether Proximo reached it and what the
vendor says the token may do (counted and sampled by path, never translated into a vocabulary of
ours), whether the ledger's chain is whole, and which of the six pillars stand: PLAN, PROVE, UNDO
and DIAGNOSE always; CONSENT and CONTAIN only once you have given them a path outside the agent's
reach. An empty pillar is advice with the exact setting that fills it, never an echo of the paths
you configured. A retired switch still set in your env is named under `retired`.

With the read-only token, the plane is reached and every write the vendor publishes is refused
by Proxmox itself. That is the guarantee: no matter what the AI asks for, the write simply won't be
permitted.

If the plane is not reached or you see a TLS error, jump to **Troubleshooting** below.

---

## Step 5 — Wire Proximo into your AI client

Example — Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "proximo": {
      "command": "proximo",
      "timeout": 60,
      "env": {
        "PROXIMO_API_BASE_URL": "https://YOUR-PVE-HOST:8006/api2/json",
        "PROXIMO_TOKEN_PATH": "/home/you/.config/proximo/pve.served",
        "PROXIMO_READONLY_SOURCE": "/home/you/.config/proximo/pve-read.token"
      }
    }
  }
}
```

`timeout` is not optional decoration: some clients give up after three seconds and drop a server
**without telling you**. If your client names this setting something else, raise that instead.

Restart the client, then ask it: **"what's running on the cluster?"** It will find the address
(`proximo_find`), read it (`proximo_read pve /cluster/resources`), and answer with lean rows and a
total — and **change nothing**, because your token says so. Six tools do everything:

| tool | what it does |
|---|---|
| `proximo_find` | words to an address: a verb picks the method, the other words match the path, the vendor's description and the parameter names |
| `proximo_plan` | the verdict for one address and the vendor's published parameters; a mutation's plan also reads the target as it stands. Mutates nothing |
| `proximo_read` | any published GET. Lean rows and a total; `fields=all` for the vendor's rows; `since=24h` for what changed, from the door's own snapshots; `diagnose=true` on a node or guest for its health battery |
| `proximo_call` | a governed POST/PUT/DELETE. Dry-run by default; `confirm=true` runs it, armed and tiered, and waits on the task. `method=undo` puts a captured record back |
| `audit_entries` | the ledger read back, newest first |
| `audit_verify` | the chain walked, the first break named |

---

## Step 6 — (Optional) Grant scoped write, when you're ready

Mint a **second** token: a write token, scoped by the vendor's ACL to the guests you mean, with an
expiry the vendor enforces. Proximo keeps no scope file and no lease of its own; the token's own
ACL is the scope and its own `expire` is the lease, enforced server-side where no bug of ours can
widen them.

```bash
proximo mint pve --write --scope /vms/100 --expire 8h
```

Run the printed commands on the Proxmox host, save the secret to its own 600 file, then tell
Proximo which file is which:

```bash
PROXIMO_ARM_SOURCE=/home/you/.config/proximo/pve-write.token      # the write token, at rest
# PROXIMO_READONLY_SOURCE (Step 3) stays the read token; PROXIMO_TOKEN_PATH stays the served copy
```

The served file (`PROXIMO_TOKEN_PATH`) is never one of the two sources: `arm` and `disarm` install
the write or the read token's bytes **into** it, and a source pointed at the served path would make
the check compare a file to itself, so Proximo refuses that configuration.

### Turning write on and off — `proximo arm` / `proximo disarm`

Armed means one thing: the token the door serves (`PROXIMO_TOKEN_PATH`) is byte-for-byte the write
token. The two verbs install one or the other at the served path, atomically, mode 600, and write a
row to the ledger saying so:

```bash
proximo arm       # the write token in; a mutation may now run, if its address carries a tier
proximo disarm    # the read-only token back
```

`arm` tells you whether the arm is a **real** boundary or only **advisory**: on a single-user box
the process that reads the token can also replace it, so it says so rather than implying more. The
stronger pattern keeps no write token at rest at all: mint at arm, revoke at disarm, as root on the
Proxmox host ([SECURITY.md](../SECURITY.md), "ARM"). A `disarm` that cannot find a read-only token
to restore refuses loudly, because a reported success that leaves write authority live would be worse.

PBS and PDM have their own pair (`PROXIMO_PBS_ARM_SOURCE` / `PROXIMO_PBS_READONLY_SOURCE`, the same
with `PDM_`): a mutation on a plane is refused unless that plane's served token is its own arm
source, and PVE's pair never arms another plane. PMG's pair holds credential files (two lines:
`user@realm`, then the password), swapped by hand. Two files holding the same secret are refused,
for every plane, because disarming could never change anything.

### What a mutation needs

A `proximo_call` with `confirm=true` runs only when **all** of these hold, and the refusal names the
one that does not (`needs`): the operator is armed (`arm`); the address carries an authored
blast-radius tier (`tier`: an unjudged mutation is refused even armed); it is not held by sentence
(`held`); the CONTAIN trip is not set; it is not in your FORBID list; the RATE window has room; a
CONSENT grant exists if you configured consent; the session is not tainted past your TAINT policy;
the UNDO capture was taken (`undo`); a guest or host lane is opened for this id (`agent`, `shell`,
`node`, `download`). A call can also be refused before any of these: an argument the schema does
not declare (`arguments`), a path that is not a published address (`path`), a restore whose
capture does not verify on the ledger (`prove`), a `--since` window that is malformed or has no kept snapshot to answer from (`store`).
Every refusal is a receipt on the ledger.

### Seeing backups

The read token sees **zero** backup archives on every storage, and that is Proxmox, not Proximo:
PVE hides backup volumes from the content listing unless the token holds `Datastore.AllocateSpace`
on the storage **and** `VM.Backup` on the guest that owns the archive (or `Datastore.Allocate` on
the storage). A `PVEAuditor` token gets `200` and an empty list on a storage full of backups. To let
the AI see them, grant a narrow sight role on the backup storage and on the guests, to the token
**and** its user:

```bash
pveum role add ProximoBackupSight -privs "Datastore.Audit,Datastore.AllocateSpace,VM.Audit,VM.Backup"
pveum acl modify /storage/pbs --tokens 'proximo@pve!read' --roles ProximoBackupSight
pveum acl modify /storage/pbs --users  'proximo@pve'      --roles ProximoBackupSight
pveum acl modify /vms/100     --tokens 'proximo@pve!read' --roles ProximoBackupSight   # or /vms for all
pveum acl modify /vms/100     --users  'proximo@pve'      --roles ProximoBackupSight
```

A grant on `/vms/100` shows that guest's archives only; an empty list then means none for the guests
you granted, not none on the storage. The PBS plane has the same trap one level down: a PBS token
holding only `Datastore.Backup` is shown **its own** backup groups and no one else's; `DatastoreAudit`
on `/datastore/<store>` lets it list every group without reading the data.

### The download lane — a file out of a backup, onto this host

Five published reads answer bytes, not JSON (a file pulled out of a backup on PVE or PBS, a PBS blob,
a quarantined mail on PMG). They are a lane, opt-in like every lane that touches this host:
`PROXIMO_ENABLE_DOWNLOAD=1`. The bytes land under `PROXIMO_RESTORE_DIR` (default
`~/.local/state/proximo/restores`) in a fresh private directory, files 0600, never overwritten,
capped by `PROXIMO_RESTORE_MAX_BYTES` (default 256 MiB), named from the argument you sent and never
from the vendor's `Content-Disposition` (attacker-authored text on a quarantined mail). The answer
carries the local path, the byte count and the sha256, never the bytes: a backup holds guest
secrets, and your chat transcript is not where they belong.

---

## The shell lanes — what the API structurally cannot do

Proxmox publishes no REST address for running a command inside a container. Proximo keeps **one**
governed path: the three shell calls are rows in the same table as every published address,
judged by the same verdict (armed, tiered, consented, rated, receipted), and only the wire differs.
Each lane is **off** until you open it, because each is near-root somewhere:

| lane | opens with | reach |
|---|---|---|
| container exec (`pct exec` over ssh) | `PROXIMO_ENABLE_EXEC=1` + `PROXIMO_CT_ALLOWLIST=101,102` + `PROXIMO_SSH_TARGET=pve` | root inside the listed containers |
| the in-guest agent | `PROXIMO_ENABLE_AGENT=1` + `PROXIMO_AGENT_ALLOWLIST=200` | root inside the listed VMs, through the QEMU guest agent |
| the host battery (read-only) | `PROXIMO_ENABLE_NODE_SHELL=1` | the node's journal and service state, fixed reads, no mutation lane |

The ssh hop is non-interactive and checks that the host it reached **is** the node the path names
before `pct` runs: a call aimed at one node never lands in a container on another. There is no
default target: unset is a refusal, never a fallback. A diagnosis (`diagnose=true`) names a closed
lane in its answer rather than reading it as healthy.

---

## Many boxes from one Proximo — `target`

One Proximo can address several Proxmox remotes. Register them in a TOML file (see
`packaging/targets.example.toml`) and point `PROXIMO_TARGETS` at it:

```toml
[targets.backup-dc]
kind       = "pbs"          # pve | pbs | pmg | pdm
base_url   = "https://pbs.example.lan:8007"
token_path = "/etc/proximo/backup-dc.token"
```

`proximo_plan`, `proximo_read` and `proximo_call` then take `target="backup-dc"`, and the shell door
takes `--target` (`proximo-core pve GET /nodes --target east`). The selector appears in the schema
only when `PROXIMO_TARGETS` is set, so a one-box install's schemas do not carry it. A target's
mutations are judged by its **own** arm pair (`arm_source`, `readonly_source` in its entry): the
default box's arm never authorizes another box. A target's `kind` is enforced: a PBS target on a PVE
address refuses rather than guessing. Every target records to the same PROVE ledger, with the
target's name in each row's `remote` field, so a multi-box deployment still has one chain. A tripped
CONTAIN stops every box. The shell lanes dial only the default box's `PROXIMO_SSH_TARGET`, so they
refuse a target.

---

## No model at all — the shell door

The same install ships `proximo-core`, the engine from a shell or a cron job, with no model, no
agent and no protocol in the loop. This is the reference door: if the engine is governable from a
bash script, then MCP, A2A and HTTP are protocol adapters over the same decisions.

```bash
proximo-core pve GET /nodes/pve1/status
proximo-core pve GET /cluster/resources --fields name,status
proximo-core pve POST /nodes/pve1/qemu/100/status/start --plan     # the verdict, the schema, the target as it stands; mutates nothing
proximo-core pve POST /nodes/pve1/qemu/100/status/start            # runs it, armed and tiered, and waits on the task
proximo-core pve undo <undo.id>                                     # puts a captured record back
```

Exit codes are the contract: 0 executed, 2 refused by the spine, 3 the caller's own mistake (bad
syntax, an unconfigured estate, a retired switch still set), 4 the vendor refused or could not be
reached. The verbs `mint`, `doctor`, `badge`, `arm` and `disarm` are the same on both commands.

---

## Remote / multi-client (optional)

Steps 1–5 run Proximo **beside your client**: the client spawns it, it talks to Proxmox, and nothing
listens on the network. That's the default on purpose — daemonless, no open port, nothing exposed.

If you want *one* Proximo that several machines or clients reach over the network, start from what
your client speaks:

| Your client speaks | Use | Extra |
|---|---|---|
| **MCP** — Claude Desktop, Claude Code, Cursor | `proximo-mcp-http` | `[mcp-http]` |
| **REST / OpenAPI** — Open WebUI, dashboards, scripts, `curl` | `proximo-http` | `[http]` |
| **A2A** — agent-to-agent callers | `proximo-a2a` | `[a2a]` |

All three are doors over the same engine: the six tools, the same spine, your token's ACL still the
floor. All are opt-in, off unless you start them, and all carry the same fail-closed perimeter: a
non-localhost bind refuses to start without a bearer token, the bearer is checked on every call, plus
a Host/DNS-rebind allowlist and a CSRF guard. Every serving door stamps its arrival and departure on
the ledger (the one-shot `proximo-core` shell door receipts its call, not a session).

### MCP over the network — native

`proximo-mcp-http` serves the MCP protocol itself over **Streamable HTTP** — the same door the stdio
command runs, so there is no adapter layer and nothing to drift. No third-party stdio→HTTP bridge,
so the perimeter in the request path is **Proximo's own**.

```bash
pip install "proximo-proxmox[mcp-http]"

# The bearer token the perimeter enforces — file mode 600, like every Proximo secret:
openssl rand -hex 32 > mcp-bearer.token && chmod 600 mcp-bearer.token

PROXIMO_MCP_HTTP_HOST=0.0.0.0 \
PROXIMO_MCP_HTTP_TOKEN_FILE=./mcp-bearer.token \
proximo-mcp-http
```

Defaults and knobs (all `PROXIMO_MCP_HTTP_*`): binds loopback `127.0.0.1:41243` with no token
required; **any non-localhost `_HOST` refuses to start without `_TOKEN_FILE`**. `_PORT` and
`_ALLOWED_HOSTS` (comma-separated Host allowlist for the DNS-rebind guard — set it to your public
hostname behind a reverse proxy) work like the sibling doors. Serving is **stateless by default**
(multi-client behind a proxy is the deployment model; `_STATELESS=0` for session-stateful serving);
`_JSON=1` answers POSTs with plain JSON instead of SSE for clients that prefer it. Put a reverse
proxy in front for TLS, and prefer reaching it over a VPN to exposing it publicly; `GET /healthz`
is open for health checks. Keep the Proxmox token **read-only** (Step 2) until you've verified the
perimeter.

#### As an LXC on the Proxmox host

One line on the PVE node builds a Debian 13 container running exactly this door, on the
community-scripts engine (MIT) pointed at Proximo's own tree:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/john-broadway/proximo/main/packaging/lxc/ct/proximo.sh)"
```

The install creates a `proximo` system user, mints `/etc/proximo/mcp-bearer.token` (owned by it,
mode 600), writes `/etc/proximo/proximo.env` with `PROXIMO_MCP_HTTP_HOST=0.0.0.0`, the token file
and the ledger path, and enables the `proximo-mcp-http` service. Edit the env file with your
Proxmox address and token path, restart the service, and verify the perimeter below.

**Verify the perimeter before you wire any client** — a request with no bearer must be refused:

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://YOUR-HOST/mcp \
  -H 'Content-Type: application/json'
#   -> 401

curl -s -o /dev/null -w '%{http_code}\n' -X POST https://YOUR-HOST/mcp \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $(cat mcp-bearer.token)"
#   -> 400/406, i.e. the bearer was accepted and the request reached the MCP layer
```

**Claude Code** — connects natively:

```bash
claude mcp add --scope user --transport http proximo https://YOUR-HOST/mcp \
  --header "Authorization: Bearer YOUR_TOKEN"
```

`--scope user` matters: without it, `claude mcp add` defaults to *local* scope and the server is
registered only for the current directory.

**Claude Desktop** — needs a local shim to attach the header. Edit the config while Desktop is fully
closed (it rewrites that file from memory on exit, clobbering edits made while it runs):

```json
{
  "mcpServers": {
    "proximo": {
      "command": "uvx",
      "timeout": 60,
      "args": [
        "mcp-proxy",
        "--transport", "streamablehttp",
        "--headers", "Authorization", "Bearer YOUR_TOKEN",
        "https://YOUR-HOST/mcp"
      ]
    }
  }
}
```

### REST and A2A

`proximo-http` serves the six tools as `POST /tools/{name}` with an OpenAPI document at
`/openapi.json`, for no-code clients and scripts. `proximo-a2a` serves an Agent2Agent card whose
skills are the six tools, signed when you give it a key (`PROXIMO_A2A_SIGNING_KEY_FILE`). Both read
`PROXIMO_HTTP_*` / `PROXIMO_A2A_*` (`_HOST`, `_PORT`, `_TOKEN_FILE`, `_ALLOWED_HOSTS`) with the same
loopback-or-bearer rule. On a network door a caller may also present a signed badge naming **who**
asked (`proximo badge mint`, pinned under `PROXIMO_CALLER_KEYS_DIR`); identity, never authority.

---

## Pull the keys anytime

Revoke instantly in the GUI (**Datacenter → Permissions → API Tokens → Remove**) or:

```bash
pveum user token remove proximo@pve read
```

The moment the token is gone, Proximo can do nothing at all.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| **TLS / certificate error** | Your Proxmox uses a self-signed cert. Point `PROXIMO_CA_BUNDLE` at the NODE's certificate, not the cluster CA, or pin `PROXIMO_FINGERPRINT`; don't disable verification. |
| **`CA cert does not include key usage extension`** | You pinned the cluster CA. Proxmox issues it with `CA:TRUE` but no `keyUsage`, and a strict-verifying stack (Python 3.13 enables `VERIFY_X509_STRICT` by default) refuses it. Pin the node cert instead. |
| **401 Unauthorized** | Token secret wrong, or the file isn't exactly `user@realm!tokenid=secret` (no trailing newline). |
| **`refusing ... group/other-accessible`** | Your token (or audit-key) file is readable by other users on the box. The message names the file — `chmod 600` it. |
| **403 from the vendor** | The token lacks that privilege. Proxmox is the one refusing; grant the role to both the token and its user, scoped to the path you mean. |
| **`needs: "arm"` / `"tier"` / `"held"`** | Not errors: the refusal names what would change the answer. Arm (Step 6); an untiered address is never mutated; a held one never opens. |
| **`... is set, and the core no longer reads it`** | A switch of an older release is still in your env (`PROXIMO_SCOPE_PATH`, `PROXIMO_ARM_TTL`, `PROXIMO_AUDIT_KEYED=off`). The door refuses to start rather than quietly run without the gate you thought you had. Unset it; the message says the vendor's way. |
| **Connection refused / timeout** | Wrong host or port (the Proxmox API is `:8006`), or a firewall in the way. |
| **A shell call refused** | The lane is off by default; open it with its switch and allowlist, and set `PROXIMO_SSH_TARGET`. |
| **A remote MCP client can't connect** | The default `proximo` command serves stdio only — a networked MCP client needs `proximo-mcp-http`. The HTTP door speaks REST, not MCP. |
| **Running bare `proximo` in a terminal just sits there** | That's correct, not a hang: it's an MCP stdio server waiting for a client to speak the protocol over stdin. The verbs (`proximo doctor`, `proximo mint pve`) answer and exit. |

---

Stuck? `proximo doctor` is the source of truth for what stands and what is reached — start there.
