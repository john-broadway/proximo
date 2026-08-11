<p align="center">
  <a href="https://john-broadway.github.io/proximo/">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/john-broadway/proximo/main/docs/brand/proximo-titlecard-dark-63e64dd5.png">
      <img alt="Proximo" src="https://raw.githubusercontent.com/john-broadway/proximo/main/docs/brand/proximo-titlecard-light-c1322c4d.png" width="880">
    </picture>
  </a>
</p>

<!-- mcp-name: io.github.john-broadway/proximo-proxmox -->

<p align="center">
  <a href="https://github.com/john-broadway/proximo/actions/workflows/ci.yml"><img src="https://github.com/john-broadway/proximo/actions/workflows/ci.yml/badge.svg" alt="CI"></a> <a href="https://github.com/john-broadway/proximo/actions/workflows/codeql.yml"><img src="https://github.com/john-broadway/proximo/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a> <a href="https://github.com/john-broadway/proximo/releases"><img src="https://img.shields.io/github/v/release/john-broadway/proximo" alt="Release"></a> <a href="https://pypi.org/project/proximo-proxmox/"><img src="https://img.shields.io/pypi/v/proximo-proxmox" alt="PyPI"></a> <a href="./pyproject.toml"><img src="https://img.shields.io/badge/python-3.12%2B-blue" alt="Python 3.12+"></a> <a href="./LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License Apache-2.0"></a>
</p>

<p align="center">
  <a href="https://scorecard.dev/viewer/?uri=github.com/john-broadway/proximo"><img src="https://api.scorecard.dev/projects/github.com/john-broadway/proximo/badge" alt="OpenSSF Scorecard"></a> <a href="https://www.bestpractices.dev/projects/13564"><img src="https://www.bestpractices.dev/projects/13564/badge" alt="OpenSSF Best Practices"></a> <a href="https://glama.ai/mcp/servers/john-broadway/proximo"><img src="https://glama.ai/mcp/servers/john-broadway/proximo/badges/score.svg" alt="Glama score"></a> <a href="https://lobehub.com/mcp/john-broadway-proximo"><img src="https://lobehub.com/badge/mcp/john-broadway-proximo?style=flat&v=3" alt="LobeHub — grade, tools, prompts"></a>
</p>

<p align="center">
  <a href="https://john-broadway.github.io/proximo/">Enter the ludus ↗</a> · <a href="#quickstart">Quickstart</a> · <a href="docs/SETUP.md">Setup</a> · <a href="#the-trust-layer-what-makes-proximo-different">Trust layer</a> · <a href="#demo">Demo</a> · <a href="#surfaces--tools-one-control-plane">Tools</a> · <a href="#install--run">Install</a> · <a href="SECURITY.md">Security</a> · <a href="#documentation">Docs</a>
</p>

*Named for Proximo, the lanista of* Gladiator. *The story is the design, joint for joint.*

He armed his fighter with exactly what he needed, never more. He answered for every move in the arena. A lanista, not a jailer. The Spaniard earns his name by conduct, on the record, and the helmet comes off: truth said plainly, at cost. His last act opened the cages, holding the wooden sword of his own freedom. *A tool should hope to end that well.*

>*"Win the crowd and you will win your freedom."*

The others make you pick: a read-only toy, or full keys and pray. Proximo won't. Every dangerous move is **planned**: see the blast radius first. Every move is **proven**: a tamper-evident record. And **undoable wherever the platform gives us a primitive**: a config change hands back the exact prior state, and a risky in-container command can take a snapshot first, and refuses to run if it can't.

Trust built into the substrate, not bolted on after. **Hand an AI agent the keys; keep the receipts.**

**Sovereign and agent-agnostic.** Your metal, your token, a ledger you own. No cloud, no phone-home, no standing server unless you opt in.

## What it does

Ask, in plain English: *"why is ct 105 thrashing?"* An AI agent pulls node and guest status, tails the logs, and runs a diagnostic *inside* the container to find out.

If there's a fix, it shows you the plan before it touches anything. Takes a snapshot first if you ask it to, and won't run if it can't. Applies. Hands you a signed receipt of exactly what changed.

That's the product: **a hypervisor an AI can operate without being able to wreck it.**

Read-only by default. No mutation runs on the first call: it returns its blast radius as a plan for you to see first. A tamper-evident receipt for every change.

The comparison isn't Proximo vs. the GUI. It's **Proximo vs. handing an LLM your root token and hoping.**

**Don't take our word for any of it. [Verify it yourself](VERIFY.md).**

<details>
<summary><b>Verify in 60 seconds</b>: three receipts, no trust required</summary>

```bash
# 1. The tool count is real. Ask the server itself, cold (=> 906).
#    (in a clone of this repo, after `uv sync`)
uv run python -c "import asyncio; from proximo import server; \
print(len(asyncio.run(server.mcp.list_tools())))"

# 2. The container image is what the repo built. Sigstore provenance (exit 0 = verified):
gh attestation verify oci://ghcr.io/john-broadway/proximo:latest --owner john-broadway

# 3. The security posture is graded by a third party, not by us:
#    https://scorecard.dev/viewer/?uri=github.com/john-broadway/proximo
```

The rest is in [VERIFY.md](VERIFY.md): forge a ledger byte and watch `verify()` refuse, grep
the outbound surface for phone-home (there is none). These checks work on any tool, from any
vendor. Demand them everywhere.

</details>

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/john-broadway/proximo/main/docs/brand/proximo-architecture-dark-ab52d834.svg">
    <img alt="Proximo architecture: MCP clients (stdio and Streamable HTTP), A2A, and HTTP/OpenAPI clients all land on one governed spine, pass the six-pillar trust spine (PLAN, PROVE, UNDO, DIAGNOSE standing by default; CONSENT and CONTAIN yours to raise), sit on the Proxmox-enforced token floor, and reach four products — PVE, PBS, PMG, PDM" src="https://raw.githubusercontent.com/john-broadway/proximo/main/docs/brand/proximo-architecture-light-5e79dd0b.svg" width="860">
  </picture>
</p>

<p align="center"><sub>Every transport enters <b>one governed dispatch</b> and crosses the <b>same trust spine</b>; the token floor beneath it all is enforced by Proxmox itself. <br>Watch it hold in the <a href="#demo">Demo</a>.</sub></p>

## Quickstart

```jsonc
// your MCP client config (Claude Desktop / Claude Code / Cursor / …)
{
  "mcpServers": {
    "proximo": {
      "command": "uvx",
      "args": ["proximo-proxmox"],
      "timeout": 60,                                     // startup is ~3.5s; a 3s client default drops the server silently
      "env": {
        "PROXIMO_API_BASE_URL": "https://your-pve:8006/api2/json",
        "PROXIMO_NODE": "your-node",
        "PROXIMO_TOKEN_PATH": "/path/to/token-file"   // USER@REALM!TOKENID=SECRET, by reference, never inlined
      }
    }
  }
}
```

Claude Code, one line:

```bash
claude mcp add proximo --env PROXIMO_API_BASE_URL=https://your-pve:8006/api2/json \
  --env PROXIMO_NODE=your-node --env PROXIMO_TOKEN_PATH=/path/to/token-file -- uvx proximo-proxmox
```

Or install with one click:

[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Proximo-0098FF?style=flat-square&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=proximo&inputs=%5B%7B%22id%22%3A%22proximo_api_base_url%22%2C%22type%22%3A%22promptString%22%2C%22description%22%3A%22PVE%20API%20base%20URL%2C%20e.g.%20https%3A%2F%2Fyour-pve%3A8006%2Fapi2%2Fjson%22%7D%2C%7B%22id%22%3A%22proximo_node%22%2C%22type%22%3A%22promptString%22%2C%22description%22%3A%22Default%20PVE%20node%20name%22%7D%2C%7B%22id%22%3A%22proximo_token_path%22%2C%22type%22%3A%22promptString%22%2C%22description%22%3A%22Path%20to%20your%20token%20FILE%20%28USER%40REALM%21TOKENID%3DSECRET%20inside%29%20%5Cu2014%20the%20secret%20itself%20is%20never%20entered%20here%22%7D%5D&config=%7B%22command%22%3A%22uvx%22%2C%22args%22%3A%5B%22proximo-proxmox%22%5D%2C%22env%22%3A%7B%22PROXIMO_API_BASE_URL%22%3A%22%24%7Binput%3Aproximo_api_base_url%7D%22%2C%22PROXIMO_NODE%22%3A%22%24%7Binput%3Aproximo_node%7D%22%2C%22PROXIMO_TOKEN_PATH%22%3A%22%24%7Binput%3Aproximo_token_path%7D%22%7D%7D)
[![Install in Cursor](https://img.shields.io/badge/Cursor-Install_Proximo-000000?style=flat-square)](https://cursor.com/install-mcp?name=proximo&config=eyJjb21tYW5kIjoidXZ4IiwiYXJncyI6WyJwcm94aW1vLXByb3htb3giXSwiZW52Ijp7IlBST1hJTU9fQVBJX0JBU0VfVVJMIjoiaHR0cHM6Ly95b3VyLXB2ZTo4MDA2L2FwaTIvanNvbiIsIlBST1hJTU9fTk9ERSI6InlvdXItbm9kZSIsIlBST1hJTU9fVE9LRU5fUEFUSCI6Ii9wYXRoL3RvL3Rva2VuLWZpbGUifX0%3D)

<sub>Both prompt for the token file **path**; the secret never lands in client config. No token yet? `uvx proximo-proxmox mint` prints the least-privilege runbook.</sub>

Then preflight what your token can actually do (read-only):

```
uvx proximo-proxmox doctor
```

Start with a **read-only token**. Proximo is useful long before you grant it write.
Full token-first walkthrough: **[docs/SETUP.md](docs/SETUP.md)** · more install paths: [Install & run](#install--run).

## Why Proximo exists

The Proxmox MCP landscape is split. **API-based servers** manage nodes and VMs but structurally *cannot* run a command inside an LXC: the REST API has no exec endpoint. **SSH-based servers** can, through broad shell access with little scoping.

Proximo builds the principled whole. Both halves, one audited surface, least-privilege. **Trust by construction:**

| | Read-only inspector | Full-access executor | **Proximo** |
|---|---|---|---|
| Can mutate | no, that's the safety | yes | yes, plan recorded first, then `confirm=true` |
| Preview before a change | n/a | rarely | **default**: blast radius + live state, every mutation |
| Record of what happened | no | app logs, editable | **keyed hash-chained ledger, tamper-evident, on by default** |
| Undo | n/a | rare | snapshot-first, wherever the platform can snapshot |
| Command inside an LXC | no | broad SSH | opt-in, fail-closed CTID allowlist |
| Products covered | usually PVE | usually PVE | **PVE + PBS + PMG + PDM**, one audited plane |
| Verify the artifact you run | varies | varies | signed image · PyPI provenance · SBOM · [Scorecard](https://scorecard.dev/viewer/?uri=github.com/john-broadway/proximo) |

*(The archetype columns describe the split above, not any specific project. There is no official Proxmox MCP; Proximo is a community project, standing on its own.)*

## The trust layer: what makes Proximo different

The spine has six pillars. Four stand by default:

| Control | What it does |
|---|---|
| **PLAN** | Every mutation first returns a recorded preview: the exact change, live state, blast radius, an advisory risk rating. Nothing mutates without its plan recorded; one `confirm=true` call records and performs. |
| **PROVE** | Keyed (HMAC-SHA256), hash-chained audit ledger; `audit_verify` catches edits, reordering, insertion. Pin the head off-box (`expected_head`) to catch truncation too: that's the strong guarantee, and it's opt-in. |
| **UNDO** | Where the platform has a primitive: a config change returns its `prior_config` automatically (revert with `pve_guest_config_revert`), `ct_exec`/`ct_psql` take `snapshot=true` for an auto-snapshot and then **fail closed** (if the snapshot can't be taken the command does not run) and `pve_rollback` restores a guest snapshot. The exec snapshot is **per call, not automatic**. Planes with no snapshot primitive (firewall/SDN/ACL) have no rollback, said plainly. |
| **DIAGNOSE** | Read-only evidence battery + node health → advisory flags that surface *incompleteness* too, so an empty list never reads as a false clean bill. |

Two are **yours to raise, by design**, off until their state paths exist, because both are only worth having if those paths sit outside the agent's reach. A pillar Proximo raised for you would be a pillar the agent could lower for itself:

| Pillar (off until configured) | What it holds |
|---|---|
| **CONSENT** | Independent, out-of-band approval per plan: an agent (compromised, confused, or steered by injected text) cannot confirm its own mutation. Grants live in a directory only you write (`PROXIMO_CONSENT_DIR`), expire on a TTL, and never clear a taint. |
| **CONTAIN** | The kill-switch: one trip file halts every mutation immediately, mid-incident, no redeploy and no restart. Checked fresh on every mutation; fails closed. Put the trip path where only you can write (`PROXIMO_CONTAIN_TRIP_PATH`). |

`proximo doctor` reports the spine: which pillars stand, which sockets are empty, and exactly how to fill them. Five more controls ship off until configured: an arm-**LEASE**, an arm-time **SCOPE**, a FORBID/RATE **ENVELOPE**, **TAINT** (the prompt-injection mitigation), and **PRINCIPAL** (who-asked attribution). What each one defends against: **[SECURITY.md](SECURITY.md)**.

> **Honesty note (load-bearing):** risk ratings are an *advisory heuristic*, not a sandbox — `LOW` means "no state change," **not** "safe," and the absence of a `HIGH` flag is not a safety signal. Review every change yourself.
> **The floor beneath it all is the token you mint:** Proxmox RBAC holds even if Proximo's process is fully compromised — a stronger guarantee than anything Proximo's own code provides. Scope it to exactly what you mean to grant: [SECURITY.md](SECURITY.md).

Hold any tool to this, including this one: **[The Keys Test](https://john-broadway.github.io/keys-test/)**. Ten questions to ask before you hand an AI agent real infrastructure. Proximo's own scorecard published, partials included.

## Demo

The record defends itself:

<p align="center">
  <img src="https://raw.githubusercontent.com/john-broadway/proximo/main/docs/demo/hand-the-keys.svg" alt="Hand-the-keys demo: three agent moves land in the keyed hash-chained ledger and audit_verify answers ok=True keyed=True; an in-place edit breaks the chain at the exact line (ok=False); a truncation that fools the forward walk is caught by the pinned head" width="860">
</p>

<p align="center"><sub>Three agent moves land in the keyed ledger; one entry gets edited in place; <code>audit_verify()</code> breaks at the exact line, <b>ok=False</b>; the truncation a forward walk would miss is caught against the pinned head. Real code, real crypto, nothing staged, recorded on 0.30.0.
Run it yourself anywhere: <a href="./scripts/demo/hand_the_keys.py"><code>scripts/demo/hand_the_keys.py</code></a> (needs only the pip package) · against your own host: <code>--live</code> · verify by hand: <a href="VERIFY.md">VERIFY.md</a>.</sub></p>

## Surfaces & tools: one control plane

| Surface | Backend | For |
|---|---|---|
| **Proxmox VE** | REST API + scoped token | node/guest lifecycle, storage, SDN, identity, HA, firewall |
| **Proxmox Backup Server** | REST API + scoped token | datastores, namespaces, snapshots, sync, GC, verify, tape |
| **Proxmox Mail Gateway** | Ticket auth | mail flow, quarantine, filtering rules, domains, services |
| **Proxmox Datacenter Manager** | API token | federated fleet: reads plus governed control (power/snapshot/migrate, dry-run-first) |
| **Container exec** | `ssh` → `pct exec` | run-command-in-container, `psql`, log tailing: what the API structurally can't do |

Those backends are deliberately boring. Anyone can call them. **The product is the trust layer over them.**

906 tools is an estate, not a starting point, and you only carry the part you use. Since 0.30 the floor IS the default: a bare install serves the search-and-call facade (~1,449 tokens of context) with every tool this box serves still callable; one domain like `pve.guests` runs ~9,123, a whole plane ~97,432, `PROXIMO_TOOLSETS=catalog` the classic auto-scoped catalog. **The estate is 906. The doorway is yours to size.** Coverage and context stopped being the same number.

Where an operator actually starts:

| You want to… | Start with | Worth knowing |
|---|---|---|
| See the whole cluster at once | `pve_cluster_resources`, `pve_list_guests` | one call, every node |
| Find out why a container is sick | `ct_diagnose`, `ct_logs`, `pve_guest_status` | read-only evidence battery |
| Preflight a token / config | `proximo doctor` (CLI) or `pve_doctor`, `pve_overbroad_grants` | run this before wiring an agent |
| Power / lifecycle | `pve_guest_power` | returns a PLAN first; nothing moves without `confirm=true` |
| Snapshot before touching anything | `pve_snapshot_create`, `pve_rollback` | UNDO's foundation |
| Check backups are actually fresh | `pve_backup_freshness`, `pbs_snapshots_list` | walks real archives; "task OK" is never evidence |
| Run a command in a container | `ct_exec` | opt-in (`PROXIMO_ENABLE_EXEC=1`), fail-closed allowlist |
| Trace / release mail | `pmg_tracker_list`, `pmg_quarantine_spam` | full PMG plane behind it |
| Operate the federated fleet | `pdm_resources_list`, `pdm_pve_lxc_list` | governed control, dry-run-first |
| Prove the record wasn't touched | `audit_verify` | registered on every surface, always |

Every tool with typed inputs: [`docs/TOOLS.md`](docs/TOOLS.md) · sizing the surface to your model: [`docs/SETUP.md`](docs/SETUP.md).

## Install & run

> 📦 **`0.32.0`**: on [PyPI](https://pypi.org/project/proximo-proxmox/), [GitHub](https://github.com/john-broadway/proximo/releases/tag/v0.32.0), and [GHCR](https://github.com/john-broadway/proximo/pkgs/container/proximo) (signed multi-arch image).
>
> **New in 0.32.0 (counted envelopes on the estate-scale listings — breaking).** Nine list
> tools whose rows grow with the estate — fleet inventory, HA resources, mail statistics —
> now return a counted envelope instead of a bare list: the server does the counting. The
> three per-correspondent statistics tools default to the top 100 by count, the per-message
> detail tool to the newest 100 (`limit=null` for all; the envelope's `total` always counts
> the complete set). PBS/PMG journals now default to the last 100 lines, matching their PVE
> sibling. Migration notes per tool in the CHANGELOG.
>
> Recent: **0.31.2** fixed every surviving finding from a full adversarial audit of 0.31.1. See [SECURITY.md](SECURITY.md) for what each control honestly holds.

Proximo runs **on your machine**, on demand. No daemon, no open port.

```
uvx proximo-proxmox            # zero-install run (PyPI package: proximo-proxmox; command stays `proximo`)
# or: pip install proximo-proxmox            the MCP core
# or: pip install "proximo-proxmox[a2a]"     + the optional A2A face
# or: pip install "proximo-proxmox[http]"    + the optional HTTP/OpenAPI face
# or: pip install "proximo-proxmox[mcp-http]" + the optional MCP-over-streamable-HTTP face
# or, from source:  git clone https://github.com/john-broadway/proximo.git && cd proximo && uv pip install -e .
```

Wire it into your MCP client as the command `proximo`, with the `PROXIMO_*` env vars; see `packaging/proximo.env.example`.

**Docker (GHCR):** `docker run -i --rm … ghcr.io/john-broadway/proximo:latest`. Multi-arch, SBOM, sigstore-signed provenance (`gh attestation verify oci://ghcr.io/john-broadway/proximo --owner john-broadway`). Mirrored to Docker Hub (`docker.io/jebroadway/proximo`, identical digest); GHCR stays the signed primary.

> **Safe by default:** API-only out of the box. The two near-root edges are opt-in and say so loudly: LXC exec (`PROXIMO_ENABLE_EXEC=1`, near-root on the host) and the qemu-guest-agent edge (`PROXIMO_ENABLE_AGENT=1`, near-root in a guest). Each is scoped by its own fail-closed allowlist.
>
> **Smallest footprint by design:** you don't have to load the whole estate: what a box *serves* is autoscoped to what it configures. A PBS-only box gets that plane's tools plus the always-on audit trail; `PROXIMO_SURFACES=pve,exec` scopes the searchable catalog to that pair (316 tools); a typo'd surface refuses startup rather than serving a surprise. Surfaces choose *which planes are searchable*, never *how many schemas load*; the doorway stays the default unless you name another with `PROXIMO_TOOLSETS`. Scoping is context hygiene, not an authorization control: it changes what is advertised, never what a token is allowed to do. The default doorway (dynamic mode) keeps three search-and-call tools resident plus the two ledger tools (`audit_verify` proves the chain, `audit_entries` reads who did what) and `proximo_recall` while estate memory is on (the default; `PROXIMO_MEMORY=0` opts out), with the full catalog reachable by name. That narrowing is guarded at every entry point (0.27.0 closed a path where an opt-in flag could silently cut the registry to 5 tools), and the gates don't shrink with the doorway: PLAN and PROVE apply however small the visible surface gets.

**The network faces (experimental, opt-in):** `proximo-a2a` speaks Agent2Agent. `proximo-http` serves plain HTTP + generated `/openapi.json` for no-code clients. `proximo-mcp-http` serves **MCP itself over Streamable HTTP** (the SDK's native transport) for networked MCP clients: no third-party stdio→HTTP bridge, so the perimeter stays Proximo's.

All three serve the full surface through the **same spine** as MCP. No second code path; trust spine and token scope inherited. Fail-closed perimeter: loopback, bearer-token required off-localhost, DNS-rebind and CSRF defended. Details: [SECURITY.md](SECURITY.md).

## At scale

One container is the demo. A cluster is the point.

- **The whole cluster in one call.** `pve_cluster_resources`: every VM, node, storage pool, SDN object.
- **One tamper-evident record across every node.** *"Show me every state-changing action this month, and prove the log wasn't touched"* becomes a query you can actually answer. No human at the CLI walks away with that.
- **Where the time comes back.** On one node a senior at the CLI is faster, and that's fine. Across a dozen nodes and hundreds of guests, a *bounded, audited* agent earns its keep.

**Many boxes, one Proximo:** register remotes in a TOML file (secrets by reference, never inlined), point `PROXIMO_TARGETS` at it, aim any tool with `proximo_target="edge-pve"`. The target travels with the call. PLAN and EXECUTE hit the same box, the ledger records which, cross-plane calls error. Config shape: `packaging/targets.example.toml`.

## Status: the arena record

- 🩸 **0.32.0**: **the estate-scale envelope batch.** The M4 sweep looked at all 229
  list-returning tools and classified every one; the nine whose rows grow with the estate now
  return counted envelopes — the server counts, the model reads the count — with a default
  cap of 100 on the mail statistics (top-by-count per correspondent, newest-by-time per
  message) and a 100-line default bound on the PBS/PMG journals. Breaking shapes batched
  deliberately into one honest pre-1.0 minor.

_Every release before it (every pillar, every redteam, every fix) lives in [`CHANGELOG.md`](./CHANGELOG.md)._

**The numbers, honestly:** 906 MCP tools, proved in two deliberate layers. **11,000+ in-process tests** (ruff + pyright clean) pin every tool's shape. A separate **live-smoke harness drives real Proxmox hardware**: a 3-node PVE 9.2 cluster, PBS 4.2, PMG 9.1, PDM 1.1.4, a real cross-datacenter move. The two are kept apart on purpose: passing shape tests never gets to masquerade as "works on a real host." And this workspace administers its own Proxmox estate through Proximo daily (dogfood). The **blast-radius engine** carries the destructive surface: across eleven op-classes it names the specific guests, nodes, principals, or disks at risk. Nothing falls back to a bare confirm.

**Proven live** (not mocks): the trust spine end-to-end; identity/storage/SDN/firewall/HA create→read→delete with the ledger verified throughout; offline + online live-migration and HA fencing (softdog) on a real 3-node cluster; full PBS/PMG/PDM planes including a real cross-datacenter move.
**Not yet proven — said plainly:** *hardware*-watchdog fencing (needs physical iTCO/IPMI) and behavior at production scale. The unrecoverable ops (SDN *apply*, etc.) are deliberately never fired live: proven by plan, held back by design, not a gap. Per-surface detail: [`CHANGELOG.md`](./CHANGELOG.md).

## Documentation

| Document | What it answers |
|---|---|
| **[Setup](docs/SETUP.md)** | Token-first walkthrough: mint a least-privilege token, verify it, widen deliberately. |
| **[Verify](VERIFY.md)** | Every trust claim paired with the command that proves it. Run them cold. |
| **[Security](SECURITY.md)** | The two-deployment trust model, all ten controls, what each honestly holds, reporting. |
| **[Threat model](docs/THREAT_MODEL.md)** | What Proximo defends against, what it doesn't, where the boundaries sit. |
| **[Tools](docs/TOOLS.md)** | All 906 tools, grouped by surface, typed inputs. |
| **[Agents](AGENTS.md)** | The page written for the agent itself: Proximo's sharp edges, stated first. |
| **[Known issues](docs/known-issues.md)** | What's broken or odd right now, said plainly. |
| **[Contributing](.github/CONTRIBUTING.md)** | Dev setup, the CI gates, what a PR is expected to keep intact. |
| **[Changelog](CHANGELOG.md)** | Every release, every redteam, every fix: the full build history. |

## License

Apache-2.0, chosen for the patent grant that suits infrastructure tooling. Full text in [`LICENSE`](./LICENSE).

## Credits

Built by **John Broadway** with **Claude** and **Maude**: a human-AI partnership, and the first thing we made on this box to give away to the world. **Claude Opus 4.8** built the trust pillars and the original tool surface and has carried the work since; **Claude Fable 5** ran the 101-agent release audit and the first publish. Every commit carries its co-author trailer.

---

*"Are you not entertained?"* Stars, issues, and sparring partners welcome. **Strength and honor.** ⚔️
