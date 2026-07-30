# Proximo — Setup (start here)

This guide gets you from nothing to a working, **safe** Proximo install. No prior experience assumed.
If you can log into your Proxmox web page, you can do this.

Proximo lets an AI assistant operate your Proxmox cluster. The reason it's safe to point at a box you
care about is **one idea**, so read this part first:

> **You create a Proxmox token. Proxmox itself enforces what that token can do. Proximo can never do
> more than the token allows — no matter what Proximo's code does, and no matter what the AI tries.**
>
> So you start with a **read-only** token: the AI can *look* at everything and *change* nothing —
> enforced by Proxmox, not by us. When you're ready, you grant write access on exactly the guests you
> choose, and nowhere else. The keys never leave your hand.

That's defense in depth, in the right order:

- **The floor — your token's permissions.** Enforced by Proxmox, held by you, impossible for Proximo to exceed.
- **On top — Proximo's safety net.** Every dangerous op is **planned** (dry-run + blast radius first),
  **proven** (a tamper-evident log of every move), and **undoable where the platform can snapshot**
  (it snapshots before it acts — guest/exec ops; firewall/SDN/ACL/token ops have no snapshot to revert to).

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
pip show proximo-proxmox
```

---

## Step 2 — Create a least-privilege token in Proxmox  ← the important step

> Shortcut: `proximo mint` prints this whole step (and the next three) as an exact,
> copy-pasteable runbook for your product — `--product pve|pbs|pmg|pdm`, read-only by
> default, `--write` for the scoped write grant.

A **token** is an API key with its own permissions, separate from your password, and revocable any time.
We'll make a **read-only** one first. Pick the GUI *or* the CLI — they do the same thing.

### Option A — Proxmox web UI (click by click)

1. Log into the Proxmox web page as an admin.
2. **Datacenter → Permissions → Users → Add** → create user `proximo` in realm **`pve`** (Proxmox VE
   authentication server). A password is required by the form but you'll never use it — the token is separate.
3. **Datacenter → Permissions → API Tokens → Add** → User `proximo@pve`, Token ID `readonly`, leave
   **Privilege Separation CHECKED**. Click Add, then **copy the Secret now** — it's shown only once.
4. **Datacenter → Permissions → Add → API Token Permission** → Path `/`, API Token
   `proximo@pve!readonly`, Role **`PVEAuditor`**, Propagate checked. This grants **read-only across
   everything** — to the token.
5. **Datacenter → Permissions → Add → User Permission** → Path `/`, User `proximo@pve`, Role
   **`PVEAuditor`**, Propagate checked. **Required, not optional:** a `--privsep`-checked token's
   effective permissions are the *intersection* of the user's grants and the token's grants — the
   user you just created has no ACL of its own, so without this step the intersection is empty and
   the token can do nothing.

### Option B — command line (on the Proxmox host)

```bash
pveum user add proximo@pve --comment "Proximo MCP (least-privilege)"
pveum user token add proximo@pve readonly --privsep 1
#   ^ copy the printed  value=<secret>  NOW — it is shown only once
pveum acl modify / --tokens 'proximo@pve!readonly' --roles PVEAuditor
# A privsep token's effective permissions are the INTERSECTION of the user's ACL and the
# token's ACL — the freshly-created user above has no ACL of its own, so it needs the role too:
pveum acl modify / --users 'proximo@pve' --roles PVEAuditor
```

`PVEAuditor` = look but never touch. (`--privsep 1` means a token's effective permissions are the
**intersection** of the user's ACL and the token's ACL, not the token's ACL alone — grant the role
to *both* the token and the user, and the token never inherits your admin rights either way.)

### Save the token to a file

Proximo reads the token from a file whose **entire contents** are `USER@REALM!TOKENID=SECRET` (no
trailing newline):

```bash
mkdir -p ~/.config/proximo
printf '%s' 'proximo@pve!readonly=PASTE-THE-SECRET-HERE' > ~/.config/proximo/pve-token
chmod 600 ~/.config/proximo/pve-token
```

---

## Step 3 — Point Proximo at your server

Create `~/.config/proximo/proximo.env`:

```bash
PROXIMO_API_BASE_URL=https://YOUR-PVE-HOST:8006/api2/json   # your Proxmox address, port 8006
PROXIMO_NODE=YOUR-NODE-NAME                                 # the node name shown in the web UI
PROXIMO_TOKEN_PATH=/home/you/.config/proximo/pve-token      # the file from Step 2
PROXIMO_VERIFY_TLS=true
# If your Proxmox uses a self-signed certificate, DON'T disable TLS — point at its CA instead:
# PROXIMO_CA_BUNDLE=/home/you/.config/proximo/pve-ca.pem
```

(Container exec is **off** by default — leave `PROXIMO_ENABLE_EXEC` unset. It grants root on the host,
so it's strictly opt-in. You don't need it for normal use.)

---

## Step 4 — Verify YOUR boundary, before any AI sees it

This is the safety check. Load the config and run the built-in preflight:

```bash
set -a; . ~/.config/proximo/proximo.env; set +a
proximo doctor
```

(On a PBS/PMG/PDM box instead of PVE: `proximo doctor --product pmg` runs that plane's preflight;
`pbs`/`pdm` have no doctor tool yet, and the command says so honestly and points at
`proximo mint --product pbs|pdm`, whose printed runbook carries the verification steps.)

You'll get JSON. Look for:

- `"reachable": true` — Proximo can talk to your Proxmox.
- `"token": { "can": [...], "cannot": [...] }` — **this is your safety boundary, in writing.**

With the read-only token, `can` lists only read/inspect, and **everything that changes state is in
`cannot`.** That is the guarantee, confirmed by Proxmox itself: no matter what the AI asks for, the
write simply won't be permitted. (If something's missing later, `cannot` even prints the exact `pveum`
command to grant it.)

If `reachable` is false or you see a TLS error, jump to **Troubleshooting** below.

---

## Step 5 — Wire Proximo into your AI client

Example — Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "proximo": {
      "command": "proximo",
      "env": {
        "PROXIMO_API_BASE_URL": "https://YOUR-PVE-HOST:8006/api2/json",
        "PROXIMO_NODE": "YOUR-NODE-NAME",
        "PROXIMO_TOKEN_PATH": "/home/you/.config/proximo/pve-token",
        "PROXIMO_VERIFY_TLS": "true"
      }
    }
  }
}
```

Restart the client, then ask it: **"run pve_doctor."** You'll see the same boundary you verified in
Step 4 — now the AI can answer questions about your cluster (what's running, is it healthy, is it
backed up) and **change nothing**, because your token says so.

---

## Step 6 — (Optional) Grant scoped write, when you're ready

Say you want the AI to be able to snapshot or restart **one** VM (id `100`) — and nothing else:

```bash
pveum acl modify /vms/100 --tokens 'proximo@pve!readonly' --roles PVEVMAdmin
# same intersection rule as Step 2 — the privsep token needs the user's ACL to match, scoped
# to this same path, or the write grant to the token alone is a no-op:
pveum acl modify /vms/100 --users 'proximo@pve' --roles PVEVMAdmin
```

Run `proximo doctor` again — power/snapshot/rollback now appear, **scoped to `/vms/100`**. Everything
Proximo does to that VM is planned, undoable, and logged; everything else stays read-only because the
token still says so. Grant only what you mean to, only where you mean it.

*(The token is named `readonly` — that's just a label. Its real power is whatever roles you grant it.)*

### Turning write on and off — `proximo arm` / `proximo disarm`

The grant above is permanent until you revoke it. If you'd rather keep write authority *off*
by default and switch it on for one job, keep two token files and swap between them:

```bash
proximo arm     --session my-job      # write token in
proximo disarm  --session my-job      # read-only token back
```

Set `PROXIMO_ARM_SOURCE` (the write token), `PROXIMO_READONLY_SOURCE` (the everyday one), and
`PROXIMO_SESSION_DIR` so each `--session` key gets its own token file and arming one caller
leaves the rest read-only. If you name a session without that directory set, `arm` refuses
rather than quietly arming every caller on the box — drop `--session` to arm globally on purpose.

`arm` prints whether the arm is a **real** boundary or only **advisory** — on a single-user box
the process that reads the token can also replace it, so it says so rather than implying more.
Pair it with `PROXIMO_ARM_TTL=3600` and a forgotten `disarm` expires on its own. See
[SECURITY.md](../SECURITY.md) for the stronger mint-and-revoke pattern, where no write token
exists at rest at all.

If a session dies while armed — crash, kill, a client that just went away — nothing runs its
`disarm`, and the write token stays in place. `proximo reap` puts it back:

```bash
proximo reap --dry-run      # show what it would do
proximo reap                # restore the read-only token for every ended session
```

It tells a dead session from a live one by asking the operating system, not by guessing: a
running server holds a lock for as long as it lives, and the OS drops that lock the moment the
process does. So it is safe to run any time, including from a timer — live sessions are reported
and skipped. Arms newer than `PROXIMO_REAP_GRACE` (default 300s) are left alone, since a session
that just armed may not have connected yet.

Restoring the key fixes the dangerous half of a dead session; the files are the other half. By
default nothing removes them, so the session dir accretes one token + one lock per session
forever — a credential store nobody audits. Set `PROXIMO_REAP_UNLINK_DAYS=7` (any positive
integer) and `reap` also unlinks session files that are read-only, unheld, and idle past that
many days, sidecar lock included. Only a proven read-only file is ever unlinked — a dead armed
session is restored first, which stamps a fresh mtime, so its file becomes eligible only after
a further full TTL of idleness. A garbled value disables unlinking rather than defaulting: a
typo must not switch deletion on.

---

## Fitting a smaller model — scoping the tool surface

Proximo governs 904 operations. Four are opt-in (estate memory and the wiki index), and
in-container exec is opt-in too — so what an install actually serves depends on what you've
configured, not on one default number: a single-plane install (one PVE cluster, no exec, no
memory, no wiki) serves 310; wiring in all four data planes (PVE + PBS + PMG + PDM) with exec
still off serves 896; nothing configured at all serves the full registered 904. Every served
tool costs your model context at connection time, before you ask anything: the full surface is
~276k tokens of schema, which does not fit most models and wastes most of a large one. So pick
what you need. Four layers, most specific wins. Every figure below was measured against the
full 904-tool registry:

| Set this | Serves | Real cost |
|---|---|---|
| `PROXIMO_TOOLS=pve_list_guests,pve_guest_power,pve_rollback` | exactly those | **~1,040 tokens** |
| `PROXIMO_TOOLSETS=dynamic` | 3 search tools; every other tool still callable | **~555 tokens** |
| `PROXIMO_TOOLSETS=pve.guests` | one domain (27 tools) | ~8,900 tokens |
| `PROXIMO_TOOLSETS=pve.guests,pve.storage` | two domains (48 tools) | ~15,700 tokens |
| `PROXIMO_SURFACES=pve` | a whole plane (310 tools) | ~97,000 tokens |
| *(nothing)* | auto-scoped to your configured planes | up to ~276,000 tokens |

Every "cost" above is UTF-8 payload bytes ÷ 4, a stated conservative heuristic, not a live
tokenizer for any specific model.

Available toolsets: `pve.guests` `pve.cluster` `pve.storage` `pve.network` `pve.sdn`
`pve.firewall` `pve.access` `pve.ceph` `pve.maintenance` · `pbs.datastores` `pbs.tape`
`pbs.access` `pbs.node` `pbs.maintenance` · `pmg.quarantine` `pmg.rules` `pmg.mail`
`pmg.statistics` `pmg.access` `pmg.node` `pmg.maintenance` · `pdm` · `exec`.

A typo refuses startup rather than quietly serving a different set than you picked, and
`audit_verify` is never scopeable away — PROVE is not optional at any size.

### `dynamic` — the whole surface on a small model

`PROXIMO_TOOLSETS=dynamic` loads three tools instead of the whole served surface:

- `proximo_find_tools(query)` — search the catalog
- `proximo_tool_schema(name)` — get one tool's arguments
- `proximo_call(tool, arguments)` — run it

`audit_verify` rides alongside these three on every surface (PROVE is never scopeable away), so
a raw `tools/list` in this mode shows **four** entries at ~555 tokens — five with
`PROXIMO_MEMORY=1`, which also keeps `proximo_recall` resident so estate questions stay one call.

The rest stay callable; they stop being *resident*. This is the only mode that fits an ~8k
context — a single domain toolset is ~8.9k, so toolsets alone reach roughly 32k-class models,
not the smallest ones.

**It is a smaller doorway, not a looser one.** `proximo_call` dispatches through the same
internal path a direct tool call uses, so the dry-run PLAN gate, the tamper-evident ledger entry
and your token's ACL all apply exactly as they would otherwise. The trade is ergonomic, not
governmental: your model spends two extra round trips discovering a tool, and it must be capable
enough to drive search-then-call.

#### Memory-first — with `PROXIMO_MEMORY=1`, a fourth tool

What `dynamic` costs is round trips, and the smallest models are where that bites: every
question, however small, is search → schema → call. Turn on Tier-1 memory and `proximo_recall`
joins the facade, so the commonest question class — what exists, how many, what changed, when
did this last happen — costs **one call with no arguments**, no search and no schema lookup.

It is the same `proximo_recall` you would get on the full surface: kept, not re-declared, with
its ledger entry, its taint classification and every other control intact. Two things it will
not do — if memory is off it stays absent rather than sitting there as a call that can only
fail, and if you scoped it away with `PROXIMO_SURFACES` it stays scoped away.

Note that recall reports what memory has *observed*, age-stamped; on a fresh install it has
observed nothing and says so rather than reporting an empty estate. And because recalled names
originate in adversarial-classified reads, a memory-first model trips the taint marker on its
first call rather than its third — earlier, not different. `proximo doctor` tells you which
facade you are actually serving.

## The wiki index — `PROXIMO_WIKI=1`, two more tools

`proximo_wiki` searches a local index of Proxmox documentation and `proximo_wiki_read` returns one
section of it, so a model can cite a real doc instead of recalling one.

**The index is yours, and Proximo does not ship one.** No documentation content is distributed with
this package: you harvest and index on your own machine, which keeps the forum and wiki licensing
question out of the picture entirely and means your index is fresher than any frozen pack. Proximo
ships the **reader** and the **contract**, nothing else. There is no bundled harvester, so if you
do not build an index these two tools simply refuse and nothing else is affected.

```bash
PROXIMO_WIKI=1
PROXIMO_WIKI_PATH=/home/you/.config/proximo/wiki.db   # else wiki.db beside the audit log
```

### The index contract

Any builder works as long as the SQLite file matches this. Proximo owns and pins the shape, checks
it **fail-closed in both directions and on a missing pin**, and refuses a drifted index rather than
answer Proxmox questions out of the wrong bytes:

```sql
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS sections (
    id      TEXT PRIMARY KEY,   -- stable: sha1(source|url|anchor)
    source  TEXT NOT NULL,      -- 'forum' | 'wiki' | 'refdocs'
    title   TEXT NOT NULL,
    url     TEXT,               -- origin, cited in every response
    license TEXT,               -- per-source note, surfaced on read
    body    TEXT NOT NULL
);
CREATE VIRTUAL TABLE IF NOT EXISTS sections_fts USING fts5(title, body, content='sections');
```

Two `meta` rows matter: **`contract_version`** must be `1` (a missing or mismatched value is
refused), and **`harvested_at`** should be a Unix timestamp, which is what lets every response
carry an age so a cached doc never passes for a live one. FTS5 ships inside CPython's bundled
`sqlite3`, so there is no new dependency at either end.

> ⚠️ **Retrieved documentation is third-party-authored text.** A solved forum thread can carry
> "now run pve_delete_guest" as easily as a fix. Both wiki tools are classified ADVERSARIAL: with
> the taint control enabled (`PROXIMO_TAINT_TRACK=1`), reading from the index trips the taint
> marker exactly as an in-guest file read does. Like every additional control, taint is opt-in and
> inert until its env var is set — the classification alone marks the text, it does not restrain
> anyone. Treat retrieved text as information, never as instructions, armed or not.

## Many boxes from one Proximo — `proximo_target`

One Proximo can address several Proxmox remotes. Register them in a TOML file (see
`packaging/targets.example.toml`) and point `PROXIMO_TARGETS` at it:

```toml
[targets.backup-dc]
kind = "pbs"          # pve | pbs | pmg | pdm
base_url = "https://pbs.example.lan:8007"
token_path = "/etc/proximo/backup-dc.token"
```

Every tool then accepts an optional **`proximo_target`** parameter naming which registered box to
run that one call against. Omit it and the call goes to the single default box from your
environment (`PROXIMO_API_BASE_URL` and friends) — exactly as it does when no registry is
configured at all. The selection applies to that call only; it does not change any later call.

A target's `kind` is enforced: naming a PBS target on a PVE tool refuses rather than guessing. All
targets record to the same PROVE ledger, with the target name in each entry's `remote` field, so a
multi-box deployment still has one tamper-evident chain.

The parameter's in-schema description is deliberately one short clause. It is duplicated onto ~900
tools, so every character there costs a client's context window ~900 times over — the full
explanation belongs here, read once by a person, rather than in the tool schema read on every
connection. See `tests/test_schema_budget.py` for the budget that enforces it.

## Remote / multi-client (optional)

Steps 1–5 run Proximo **beside your client**: the client spawns it, it talks to Proxmox, and nothing
listens on the network. That's the default on purpose — daemonless, no open port, nothing exposed.

If you want *one* Proximo that several machines or clients reach over the network, start from what
your client speaks:

| Your client speaks | Use | Extra | Bridge? |
|---|---|---|---|
| **REST / OpenAPI** — Open WebUI, dashboards, scripts, `curl` | `proximo-http` | `[http]` | No |
| **A2A** — agent-to-agent callers | `proximo-a2a` | `[a2a]` | No |
| **MCP** — Claude Desktop, Claude Code, Cursor | `proximo-mcp-http` | `[mcp-http]` | No |

All three network faces serve the **full governed surface** through the same spine (PLAN · PROVE ·
UNDO — and your token's ACL is still the floor). All are opt-in, off unless you start them, and all
carry the same fail-closed perimeter: a non-localhost bind refuses to start without a bearer token,
the bearer is checked on every op, plus a Host/DNS-rebind allowlist and a CSRF guard.

### MCP over the network — native

`proximo-mcp-http` serves the MCP protocol itself over **Streamable HTTP** — the same FastMCP
instance the stdio server runs, so there is no adapter layer and nothing to drift: it IS MCP, with
the spine and your token's ACL inherited by construction. No third-party stdio→HTTP bridge, so the
perimeter in the request path is **Proximo's own**, not a bridge's. Error surfaces match stdio
too: a failing tool returns the same MCP error text a stdio client would see (the REST face's
sanitized `tool failed: <Type>` mapping is a REST-face behavior, not an MCP one).

```bash
pip install "proximo-proxmox[mcp-http]"

# The bearer token the perimeter enforces — file mode 600, like every Proximo secret:
openssl rand -hex 32 > mcp-bearer.token && chmod 600 mcp-bearer.token

PROXIMO_MCP_HTTP_HOST=0.0.0.0 \
PROXIMO_MCP_HTTP_TOKEN_FILE=./mcp-bearer.token \
proximo-mcp-http
```

Defaults and knobs (all `PROXIMO_MCP_HTTP_*`): binds loopback `127.0.0.1:41243` with no token
required; **any non-localhost `_HOST` refuses to start without `_TOKEN_FILE`** — that's the same
fail-closed rule as the other faces, not a warning. `_PORT` and `_ALLOWED_HOSTS` (comma-separated
Host allowlist for the DNS-rebind guard — set it to your public hostname behind a reverse proxy)
work like the sibling faces. Serving is **stateless by default** (multi-client behind a proxy is
the deployment model; opt out with `_STATELESS=0` for session-stateful serving); `_JSON=1` answers
POSTs with plain JSON instead of SSE for clients that prefer it. Put a reverse proxy in front for
TLS, and prefer reaching it over a VPN to exposing it publicly; `GET /healthz` is open for health
checks. Keep the Proxmox token **read-only** (Step 2) until you've verified the perimeter.

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

Then ask either client **"run pve_doctor"** — the same boundary you verified in Step 4, now over the
network.

---

## Pull the keys anytime

Revoke instantly in the GUI (**Datacenter → Permissions → API Tokens → Remove**) or:

```bash
pveum user token remove proximo@pve readonly
```

The moment the token is gone, Proximo can do nothing at all.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| **TLS / certificate error** | Your Proxmox uses a self-signed cert. Point `PROXIMO_CA_BUNDLE` at the cluster CA — don't disable verification. |
| **401 Unauthorized** | Token secret wrong, or the file isn't exactly `user@realm!tokenid=secret` (no trailing newline). |
| **`Refusing to start: … group/other-accessible`** | Your token (or audit-key) file is readable by other users on the box. The message names the file — `chmod 600` it, exactly as in Step 2. Proximo won't run with an exposed secret. |
| **403 / a capability is in `cannot`** | The token lacks that privilege. Run `proximo doctor` — it prints the exact `pveum` command to grant it. For a `--privsep 1` token, effective permissions are the *intersection* of the user's ACL and the token's ACL: a freshly-created user has no ACL of its own, so the user-side grant is **always required**, not situational — `pveum acl modify <path> --users proximo@pve --roles <ROLE>`. |
| **Connection refused / timeout** | Wrong host or port (the Proxmox API is `:8006`), or a firewall in the way. |
| **`ct_exec` refused** | Exec is off by default (grants host root). It's opt-in via `PROXIMO_ENABLE_EXEC=1` + a CTID allowlist — only if you truly need it. |
| **A remote MCP client can't connect** | The default `proximo` command serves stdio only — a networked MCP client needs `proximo-mcp-http` (see **Remote / multi-client**). The HTTP face speaks REST, not MCP. Check the bearer header and that `PROXIMO_MCP_HTTP_ALLOWED_HOSTS` includes the Host you're connecting through. |
| **Running bare `proximo` in a terminal just sits there** | That's correct, not a hang: it's an MCP stdio server waiting for a client to speak the protocol over stdin. `proximo --help` and `proximo --version` don't print a usage screen either — any argument that isn't `doctor`/`mint`/`arm`/`disarm`/`reap`/`hello` falls through to the same banner-then-wait. Wire it into an MCP client (Step 5) instead of running it directly. |

---

Stuck? `proximo doctor` is the source of truth for what your token can and cannot do — start there.
