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
  (a config change returns the exact prior state; a risky in-container command takes a snapshot first when
  you pass `snapshot=true`, and refuses to run if it can't — firewall/SDN/ACL/token ops have no snapshot to
  revert to).

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
# If your Proxmox uses a self-signed certificate, DON'T disable TLS — pin the NODE's cert:
# PROXIMO_CA_BUNDLE=/home/you/.config/proximo/pve-node.pem
```

(Container exec is **off** by default — leave `PROXIMO_ENABLE_EXEC` unset. It grants root on the host,
so it's strictly opt-in. You don't need it for normal use.)

**Which store wins.** Step 5 puts the same variables in your MCP client's `env` block (a daemon
gets them from its unit's `EnvironmentFile`). The server reads that first and fills in from
`proximo.env` only the keys it does not set. A key present in both is fed by the process
environment, and the file's copy of that key is never read. When the two values differ the
server says so at start (`proximo: 1 key(s) in ... SHADOWED by the process environment`), an
allowlist refusal names the store it read, and `proximo doctor` flags a shadowed key whose value
differs. Every `PROXIMO_*` value is fixed when the server is launched: after editing either
store, restart the server or reconnect the client.

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
      "timeout": 60,
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

`timeout` is not optional decoration. Proximo answers `initialize` in about 3.5 seconds because it
registers its whole tool surface first, and some clients — Cline among them — give up after 3 and
drop the server **without telling you**: you get a session with no Proximo tools and no error. If
your client names this setting something else, raise that instead.

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

If you also use the target registry, give any exec-enabled target its own `arm_source` in that
file. It is not inherited from `PROXIMO_ARM_SOURCE`, which names this box's write token, and a
target with exec enabled and no `arm_source` is refused rather than armed by proxy. Do not point
`PROXIMO_ARM_SOURCE` at `PROXIMO_TOKEN_PATH` either: one file in both roles would make the check
compare a file to itself and read as armed forever, so Proximo refuses that configuration.

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

### The reach mirror — shell reach from Proxmox's own permission map

The CTID allowlist is a list in an env var; the mirror upgrades that perimeter to Proxmox's
own vocabulary. With it on, the container shell tools work only where the served token holds
a privilege *you* chose, at that guest's own ACL path — granted, moved, and revoked with
`pveum`, resolved by PVE per check. Erect it in four steps, from your own shell:

1. **Choose the privilege from evidence.** `proximo reach-audit` prints, per candidate, what
   it means in stock PVE and which roles already carry it on *your* cluster (granting any of
   those roles to the served token — or, privsep, its user — silently extends shell reach).
   Check the name exists on your PVE first: `pveum role add` refuses unknown privilege
   names, and older releases predate the granular guest-agent privileges — the audit reads
   *your* cluster, so what it lists is what exists. To decouple AI reach from human role
   grants, make a one-privilege custom role:
   `pveum role add ProximoReach -privs VM.GuestAgent.Unrestricted`
2. **Grant it where you mean the reach to be — to BOTH sides of a privsep token** (the same
   intersection rule as Step 2 of this page: effective privileges = user ACL ∩ token ACL,
   so a token-only grant leaves the mirror refusing):
   `pveum acl modify /vms/<ctid> --tokens '<user>@<realm>!<token>' --roles ProximoReach`
   `pveum acl modify /vms/<ctid> --users '<user>@<realm>' --roles ProximoReach`
3. **Set `PROXIMO_REACH_PRIVILEGE=VM.GuestAgent.Unrestricted`** (the privilege name, not the
   role name) in the server's env and restart. Unset = dormant, zero behavior change.
   Set-but-blank refuses loudly rather than guessing.
4. **Verify the refusal before trusting the grant:** pick an allowlisted guest you did *not*
   grant — `ct_logs` there must return `blocked:mirror`. Then the granted guest serves.
   `proximo doctor` shows the live state at `config.reach_grant.mirror.state`.

The allowlist still applies first — the mirror only narrows. Once you trust the mirror
alone, the allowlist can widen to `*`: the token's own map is then the whole boundary, and
reach moves only by `pveum`, in PVE's own ACL table — readable back any time with
`proximo reach-audit`. Be clear about what each record holds: the ledger witnesses the
*env side* of the perimeter (allowlist, switches, the privilege itself) at serve start and
every mirror refusal at the door — and while the mirror is enforcing, the serve-start
snapshot also *derives* the served token's per-guest reach from PVE (a `*` allowlist
enumerates the configured node's containers first), so a `pveum` grant or revoke lands as
a witnessed `derived_ct` delta at the next serve start (enforcement sees it
immediately; the witness sees it at start — that granularity is stated, not hidden).
Fail-closed by design: if the API cannot answer, shell reach refuses;
the break-glass is unsetting the privilege — on a `*`-allowlist estate a *widening* — and
that flip is itself a witnessed `reach_grant` change.

---

## Fitting a smaller model — scoping the tool surface

Proximo governs 906 operations, and **the default door is small**: with nothing configured,
the server serves the dynamic facade — search, schema, read, call, recall and the audit
trail (~1,740 tokens) — with everything this box serves still callable through it. That is the 0.30
flip, and the reason is measured: the catalog doors below cost your model context at
connection time, before you ask anything, and the full surface is ~290k tokens of schema —
~35x over the 8,192-token default window of a stock local model, which means dead on connect.
The catalog doors are explicit choices now. Four layers, most specific wins. Every figure
below was measured against the full 906-tool registry:

| Set this | Serves | Real cost |
|---|---|---|
| *(nothing — the default)* | the dynamic facade; every tool this box serves still callable | **~1,740 tokens** |
| `PROXIMO_TOOLS=pve_list_guests,pve_guest_power,pve_rollback` | exactly those, plus the audit trail and `proximo_call` | **~1,704 tokens** |
| `PROXIMO_TOOLSETS=pve.guests` | one domain (28 tools) | ~9,781 tokens |
| `PROXIMO_TOOLSETS=pve.guests,pve.storage` | two domains (49 tools) | ~16,825 tokens |
| `PROXIMO_SURFACES=pve` | the dynamic facade, with the *searchable* catalog scoped to that plane (312 tools). `proximo_recall` is **not** resident here: `memory` is a utility surface, not a plane, so naming planes scopes it away — add it (`PROXIMO_SURFACES=pve,memory`) to keep the one-call estate answer | **~868 tokens** |
| `PROXIMO_TOOLSETS=catalog` | the pre-0.30 default: full schemas, auto-scoped to your configured planes (~101,398 tokens on a pve-only box) | up to ~289,839 tokens |
| `PROXIMO_TOOLSETS=all` | the full surface, auto-scope overridden | ~289,839 tokens |

> These figures were **revised upward 16-20% on 2026-08-01**, and the surface did not grow.
> They are now measured from what `tools/list` actually serializes, verified by installing
> this package into a clean virtualenv and driving the real server over JSON-RPC. The
> earlier numbers were rebuilt by hand from name + description + input schema, which
> omitted `outputSchema` — 16.4% of the payload, present on 903 of 905 tools. What you
> pay has not changed; what we print now matches it.

Every "cost" above is UTF-8 payload bytes ÷ 4, a stated conservative heuristic, not a live
tokenizer for any specific model.

Available toolsets: `pve.guests` `pve.cluster` `pve.storage` `pve.network` `pve.sdn`
`pve.firewall` `pve.access` `pve.ceph` `pve.maintenance` · `pbs.datastores` `pbs.tape`
`pbs.access` `pbs.node` `pbs.maintenance` · `pmg.quarantine` `pmg.rules` `pmg.mail`
`pmg.statistics` `pmg.access` `pmg.node` `pmg.maintenance` · `pdm` · `exec`.

A typo refuses startup rather than quietly serving a different set than you picked, and
`audit_verify` and `proximo_call` are never scopeable away — PROVE is not optional at any
size, and neither is being able to reach a tool by name that scoping left unadvertised.

### `dynamic` — the default: the whole surface on a small model

The default door (also picked explicitly with `PROXIMO_TOOLSETS=dynamic`) loads a facade
instead of the whole served surface:

- `proximo_find_tools(query)` — search the catalog
- `proximo_tool_schema(name)` — get one tool's arguments
- `proximo_read(tool, arguments)` — run a READ-ONLY tool; refuses anything that can mutate,
  so its `readOnlyHint: true` is an enforced promise your client's permission policy can trust
- `proximo_call(tool, arguments)` — run anything (`readOnlyHint: false`, honestly)
- `proximo_recall()` — estate questions (what exists, how many, what changed) in one call

`audit_verify` and `audit_entries` ride alongside these on every surface (PROVE — the write
proof and the read-back — is never scopeable away), so a raw `tools/list` in this mode shows
**seven** entries at ~1,740 tokens — six at ~1,166 with `PROXIMO_MEMORY=0`, which removes
`proximo_recall` rather than leaving a call that could only fail.

The rest stay callable; they stop being *resident*. This is the only mode that fits an ~8k
context — a single domain toolset is ~8.9k, so toolsets alone reach roughly 32k-class models,
not the smallest ones.

**It is a smaller doorway, not a looser one.** `proximo_call` dispatches through the same
internal path a direct tool call uses, so the dry-run PLAN gate, the tamper-evident ledger entry
and your token's ACL all apply exactly as they would otherwise. The trade is ergonomic, not
governmental: your model spends two extra round trips discovering a tool, and it must be capable
enough to drive search-then-call.

#### Memory-first — `proximo_recall`, resident by default

What `dynamic` costs is round trips, and the smallest models are where that bites: every
question, however small, is search → schema → call. Tier-1 memory is on by default (opt out
with `PROXIMO_MEMORY=0`; the map is a local, derived, rebuildable SQLite beside the audit
ledger — nothing leaves the box), and `proximo_recall` sits in the facade, so the commonest
question class — what exists, how many, what changed, when did this last happen — costs
**one call with no arguments**, no search and no schema lookup.

It is the same `proximo_recall` you would get on the full surface: kept, not re-declared, with
its ledger entry, its taint classification and every other control intact. Two things it will
not do — if memory is off it stays absent rather than sitting there as a call that can only
fail, and if you scoped it away with `PROXIMO_SURFACES` it stays scoped away.

Note that recall reports what memory has *observed*, age-stamped; on a fresh install it has
observed nothing and says so rather than reporting an empty estate. And because recalled names
originate in adversarial-classified reads, a memory-first model trips the taint marker on its
first call rather than its third — earlier, not different. `proximo doctor` tells you which
facade you are actually serving.

#### Finding the right tool — the search stack, and what works with no config at all

Search is a stack. Each tier fills only the room the tier above left empty, and marks its
rows so you can always tell which one answered:

| order | tier | needs | marked |
|---|---|---|---|
| 1 | keyword | nothing | *(unmarked — exact matches, always first)* |
| 2 | semantic | `PROXIMO_EMBED_URL` | `"match": "semantic"` |
| 3 | lexical | nothing | `"match": "lexical"` |

**The lexical tier ships inside the wheel** — no model, no server, no download, no
dependency — because a search that needs configuration to work is not much of a search.
It expands your words into Proxmox's own (memory→mem/ram, container→lxc/ct/guest,
who/changed→audit/ledger) using a curated table you can read in `lexical.py`, then ranks
by character-n-gram TF-IDF. On the real ~900-tool catalog the first search builds the index
(~260 ms, then cached) and later searches take about 7 ms; it finds `audit_verify` for
"who changed this vm's config". An off-domain query returns nothing, deliberately — a
result must share a real word with your question, not just a fragment. Set
`PROXIMO_LEXICAL=off` to disable this tier.

The semantic tier is the optional upgrade in the middle: stronger at crossing vocabulary
gaps, at the cost of an embedding server you run. When it is configured it takes the room
below the keyword hits, and lexical fills whatever is left; when it is unreachable, search
falls back to lexical rather than to bare keyword.

#### Vector search — with `PROXIMO_EMBED_URL`, the drawers find themselves

Keyword search requires the operator's words to appear in a tool's name or description —
"memory usage of a container" matches nothing, because the tool that answers it says "runtime
status". Point `PROXIMO_EMBED_URL` at an OpenAI-compatible `/v1/embeddings` server **you run**
(ollama, llama.cpp and vLLM all serve one; nothing leaves your estate) and semantic matches fill
in behind the keyword hits — keyword precision stays first and untouched, each vector-ranked row
is marked `"match": "semantic"` so you can tell which ranking produced it, and `proximo_recall`
accepts a `query` that narrows entity rows semantically ("the git box" → your gitea container)
while every count still covers the whole estate.

```bash
PROXIMO_EMBED_URL=http://localhost:11434          # your embedding server, http(s) only
PROXIMO_EMBED_MODEL=qwen3-embedding               # optional; single-model servers ignore it
PROXIMO_EMBED_QUERY_PREFIX=                       # optional, for asymmetric models (see below)
PROXIMO_VECTORS_PATH=~/.config/proximo/vectors.db # else vectors.db beside the audit log
```

The index builds itself on the first semantic search and syncs by content hash after that —
no startup cost, and only new or changed texts ever re-embed. If your embedder is down, search
degrades to keyword-only with a warning on stderr; the facade never fails because an assist is
unreachable. Asymmetric embedding models rank better with an instruction prefix on the query
(e.g. Qwen3-Embedding's `Instruct: ...\nQuery: ` convention) — set `PROXIMO_EMBED_QUERY_PREFIX`
to your model's convention; it applies to queries only, so changing it never re-indexes.

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
| **TLS / certificate error** | Your Proxmox uses a self-signed cert. Point `PROXIMO_CA_BUNDLE` at the NODE's certificate, not the cluster CA, and don't disable verification. Proximo pins whatever you give it as a trust anchor in its own right. |
| **`CA cert does not include key usage extension`** | You pinned the cluster CA. Proxmox issues it with `CA:TRUE` but no `keyUsage`, and a strict-verifying stack (Python 3.13 enables `VERIFY_X509_STRICT` by default) refuses it. Pin the node's own certificate instead; it verifies on every interpreter. |
| **401 Unauthorized** | Token secret wrong, or the file isn't exactly `user@realm!tokenid=secret` (no trailing newline). |
| **`Refusing to start: … group/other-accessible`** | Your token (or audit-key) file is readable by other users on the box. The message names the file — `chmod 600` it, exactly as in Step 2. Proximo won't run with an exposed secret. |
| **403 / a capability is in `cannot`** | The token lacks that privilege. Run `proximo doctor` — it prints the exact `pveum` command to grant it. For a `--privsep 1` token, effective permissions are the *intersection* of the user's ACL and the token's ACL: a freshly-created user has no ACL of its own, so the user-side grant is **always required**, not situational — `pveum acl modify <path> --users proximo@pve --roles <ROLE>`. |
| **Connection refused / timeout** | Wrong host or port (the Proxmox API is `:8006`), or a firewall in the way. |
| **`ct_exec` refused** | Exec is off by default (grants host root). It's opt-in via `PROXIMO_ENABLE_EXEC=1` + a CTID allowlist — only if you truly need it. |
| **A remote MCP client can't connect** | The default `proximo` command serves stdio only — a networked MCP client needs `proximo-mcp-http` (see **Remote / multi-client**). The HTTP face speaks REST, not MCP. Check the bearer header and that `PROXIMO_MCP_HTTP_ALLOWED_HOSTS` includes the Host you're connecting through. |
| **Running bare `proximo` in a terminal just sits there** | That's correct, not a hang: it's an MCP stdio server waiting for a client to speak the protocol over stdin. `proximo --help` and `proximo --version` don't print a usage screen either — any argument that isn't `doctor`/`mint`/`arm`/`disarm`/`reap`/`hello` falls through to the same banner-then-wait. Wire it into an MCP client (Step 5) instead of running it directly. |

---

Stuck? `proximo doctor` is the source of truth for what your token can and cannot do — start there.
