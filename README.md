<p align="center">
  <a href="https://john-broadway.github.io/proximo/">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/john-broadway/proximo/main/docs/brand/proximo-titlecard-dark-caec60e5.png">
      <img alt="Proximo" src="https://raw.githubusercontent.com/john-broadway/proximo/main/docs/brand/proximo-titlecard-light-d95073df.png" width="880">
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

The others make you pick: a read-only toy, or full keys and pray. Proximo won't. Every dangerous move is **planned**: the verdict, the live target and the change, before anything runs. Every move is **proven**: a tamper-evident record. And **undoable wherever the platform gives us a primitive**: a mutation captures the record it is about to change and puts it back through the vendor's own write; a risky in-container command can take a snapshot first, and refuses to run if it can't.

Trust built into the substrate, not bolted on after. **Hand an AI agent the keys; keep the receipts.**

**Sovereign and agent-agnostic.** Your metal, your token, a ledger you own. No cloud, no phone-home, no standing server unless you opt in.

## What it does

Ask, in plain English: *"why is ct 105 thrashing?"* An AI agent pulls node and guest status, tails the logs, and (if you opened that lane) runs a diagnostic *inside* the container to find out.

If there's a fix, it shows you the plan before it touches anything: the verdict, the target as it stands, the exact change. Takes a snapshot first if you ask it to, and won't run if it can't. Applies. Hands you a keyed receipt of exactly what changed, with the before-state captured so it can be put back.

It does all of that with **six tools**, over **every address the four Proxmox products publish**. No wrappers, no catalog to page through, no tool per endpoint: find the address, plan it, read or call it, and prove the record. The whole surface fits a small local model's window.

That's the product: **a hypervisor an AI can operate without being able to wreck it.**

Read-only by default. No mutation runs on the first call: it returns its blast radius as a plan for you to see first. A tamper-evident receipt for every change.

The comparison isn't Proximo vs. the GUI. It's **Proximo vs. handing an LLM your root token and hoping.**

**Don't take our word for any of it. [Verify it yourself](VERIFY.md).**

<details>
<summary><b>Verify in 60 seconds</b>: three receipts, no trust required</summary>

```bash
# 1. The tool count is real. Ask the door itself, cold (=> 6).
#    (in a clone of this repo, after `uv sync`)
uv run python -c "import asyncio; from proximo.core.doors.mcp import build_server; \
print(len(asyncio.run(build_server().list_tools())))"

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
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/john-broadway/proximo/main/docs/brand/proximo-architecture-dark-2de7d79e.svg">
    <img alt="Proximo architecture: MCP clients (stdio and Streamable HTTP), A2A, and HTTP/OpenAPI clients all land on one governed spine, pass the six-pillar trust spine (PLAN, PROVE, UNDO, DIAGNOSE standing by default; CONSENT and CONTAIN yours to raise), sit on the Proxmox-enforced token floor, and reach four products — PVE, PBS, PMG, PDM" src="https://raw.githubusercontent.com/john-broadway/proximo/main/docs/brand/proximo-architecture-light-0ce1a647.svg" width="860">
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
        "PROXIMO_TOKEN_PATH": "/path/to/token-file"   // USER@REALM!TOKENID=SECRET, by reference, never inlined
      }
    }
  }
}
```

Claude Code, one line:

```bash
claude mcp add proximo --env PROXIMO_API_BASE_URL=https://your-pve:8006/api2/json \
  --env PROXIMO_TOKEN_PATH=/path/to/token-file -- uvx proximo-proxmox
```

Or install with one click:

[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_Proximo-0098FF?style=flat-square&logo=visualstudiocode&logoColor=white)](https://insiders.vscode.dev/redirect/mcp/install?name=proximo&inputs=%5B%7B%22id%22%3A%22proximo_api_base_url%22%2C%22type%22%3A%22promptString%22%2C%22description%22%3A%22PVE%20API%20base%20URL%2C%20e.g.%20https%3A%2F%2Fyour-pve%3A8006%2Fapi2%2Fjson%22%7D%2C%7B%22id%22%3A%22proximo_token_path%22%2C%22type%22%3A%22promptString%22%2C%22description%22%3A%22Path%20to%20your%20token%20FILE%20%28USER%40REALM%21TOKENID%3DSECRET%20inside%29%20%5Cu2014%20the%20secret%20itself%20is%20never%20entered%20here%22%7D%5D&config=%7B%22command%22%3A%22uvx%22%2C%22args%22%3A%5B%22proximo-proxmox%22%5D%2C%22env%22%3A%7B%22PROXIMO_API_BASE_URL%22%3A%22%24%7Binput%3Aproximo_api_base_url%7D%22%2C%22PROXIMO_TOKEN_PATH%22%3A%22%24%7Binput%3Aproximo_token_path%7D%22%7D%7D)
[![Install in Cursor](https://img.shields.io/badge/Cursor-Install_Proximo-000000?style=flat-square)](https://cursor.com/install-mcp?name=proximo&config=eyJjb21tYW5kIjoidXZ4IiwiYXJncyI6WyJwcm94aW1vLXByb3htb3giXSwiZW52Ijp7IlBST1hJTU9fQVBJX0JBU0VfVVJMIjoiaHR0cHM6Ly95b3VyLXB2ZTo4MDA2L2FwaTIvanNvbiIsIlBST1hJTU9fVE9LRU5fUEFUSCI6Ii9wYXRoL3RvL3Rva2VuLWZpbGUifX0%3D)

<sub>Both prompt for the token file **path**; the secret never lands in client config. No token yet? `uvx proximo-proxmox mint pve` prints the least-privilege runbook.</sub>

Then preflight what your token can actually do (read-only):

```
uvx proximo-proxmox doctor
```

Start with a **read-only token**. Proximo is useful long before you grant it write.
Full token-first walkthrough: **[docs/SETUP.md](docs/SETUP.md)** · more install paths: [Install & run](#install--run).

## Why Proximo exists

Everything that touches a Proxmox product is a call: the web UI, `pct` and `qm` on a host, `curl` against the API, an agent's tool. Most of those calls leave no plan behind them, no receipt, and no way back. Proximo is the one client that governs the call before it runs, records it, and can put the record back, whichever door it came in by. **Trust by construction:**

| | A call on its own | Through Proximo |
|---|---|---|
| Before it runs | nothing | **a plan, recorded first**: the verdict, the live target, the exact change, the blast radius |
| Record of what happened | app logs, editable | **keyed, hash-chained ledger**; `audit_verify` catches edits, reordering and, against a pinned head, truncation |
| Undo | by hand, if you kept notes | the record captured first, restored through the vendor's own write |
| Command inside an LXC | broad SSH | opt-in, fail-closed allowlist, judged like any mutation |
| Products covered | one at a time | **PVE + PBS + PMG + PDM**, one governed plane |
| Verify the artifact you run | varies | signed image · PyPI provenance · SBOM · [Scorecard](https://scorecard.dev/viewer/?uri=github.com/john-broadway/proximo) |

Proximo is a community project, standing on its own. MCP, A2A, REST and a shell with no model in the loop are its doors; the governance is the product.

## The trust layer: what makes Proximo different

The spine has six pillars. Four stand by default:

| Control | What it does |
|---|---|
| **PLAN** | Every mutation first returns a recorded preview: the exact change, live state, blast radius, an advisory risk rating. Nothing mutates without its plan recorded; one `confirm=true` call records and performs. |
| **PROVE** | Keyed (HMAC-SHA256), hash-chained audit ledger; `audit_verify` catches edits, reordering, insertion. Pin the head off-box (`expected_head`) to catch truncation too: that's the strong guarantee, and it's opt-in. |
| **UNDO** | One rule: every mutation with a GET twin captures the record before it runs, and the receipt carries an `undo.id`; the restore is the vendor's own write at the same path, with the captured record, as a governed mutation (planned, armed, receipted, itself undoable). A container command can take a snapshot first and then **fail closed** if it can't. Where the vendor publishes no write to put a record back (a delete, a collection, a path with no PUT) the answer is a sentence, never a guessed reverse call. |
| **DIAGNOSE** | Read-only evidence battery + node health → advisory flags that surface *incompleteness* too, so an empty list never reads as a false clean bill. |

Two are **yours to raise, by design**, off until their state paths exist, because both are only worth having if those paths sit outside the agent's reach. A pillar Proximo raised for you would be a pillar the agent could lower for itself:

| Pillar (off until configured) | What it holds |
|---|---|
| **CONSENT** | Independent, out-of-band approval per plan: an agent (compromised, confused, or steered by injected text) cannot confirm its own mutation. Grants live in a directory only you write (`PROXIMO_CONSENT_DIR`), expire on a TTL, and never clear a taint. |
| **CONTAIN** | The kill-switch: one trip file halts every mutation immediately, mid-incident, no redeploy and no restart. Checked fresh on every mutation; fails closed. Put the trip path where only you can write (`PROXIMO_CONTAIN_TRIP_PATH`). |

`proximo doctor` reports the spine: which pillars stand, which sockets are empty, and exactly how to fill them. Four more controls ship off until configured: **ARM** (a mutation runs only while the served token *is* the write token), a FORBID/RATE **ENVELOPE**, **TAINT** (the prompt-injection mitigation), and **PRINCIPAL** (who-asked attribution). Scope and lease are not Proximo's any more: the write token's own ACL is the scope and its own `expire` is the lease, both enforced by Proxmox, and `proximo mint` prints the commands that make such a token. What each control defends against: **[SECURITY.md](SECURITY.md)**.

> **Honesty note (load-bearing):** risk ratings are an *advisory heuristic*, not a sandbox — `LOW` means "no state change," **not** "safe," and the absence of a `HIGH` flag is not a safety signal. Review every change yourself.
> **The floor beneath it all is the token you mint:** Proxmox RBAC holds even if Proximo's process is fully compromised — a stronger guarantee than anything Proximo's own code provides. Scope it to exactly what you mean to grant: [SECURITY.md](SECURITY.md).

Hold any tool to this, including this one: **[The Keys Test](https://john-broadway.github.io/keys-test/)**. Ten questions to ask before you hand an AI agent real infrastructure. Proximo's own scorecard published, partials included.

## Demo

The record defends itself:

<p align="center">
  <img src="https://raw.githubusercontent.com/john-broadway/proximo/main/docs/demo/hand-the-keys.svg" alt="Hand-the-keys demo: three agent moves land in the keyed hash-chained ledger and audit_verify answers ok=True keyed=True; an in-place edit breaks the chain at the exact line (ok=False); a truncation that fools the forward walk is caught by the pinned head" width="860">
</p>

<p align="center"><sub>Three agent moves land in the keyed ledger; one entry gets edited in place; <code>audit_verify()</code> breaks at the exact line, <b>ok=False</b>; the truncation a forward walk would miss is caught against the pinned head. Real code, real crypto, nothing staged, recorded on 0.30.0.
Forge a byte yourself and watch the chain refuse: <a href="VERIFY.md">VERIFY.md</a>, section 2.</sub></p>

## Surfaces & tools: one control plane

| Surface | Backend | For |
|---|---|---|
| **Proxmox VE** | REST API + scoped token | node/guest lifecycle, storage, SDN, identity, HA, firewall |
| **Proxmox Backup Server** | REST API + scoped token | datastores, namespaces, snapshots, sync, GC, verify, tape |
| **Proxmox Mail Gateway** | Ticket auth | mail flow, quarantine, filtering rules, domains, services |
| **Proxmox Datacenter Manager** | API token | federated fleet: reads plus governed control (power/snapshot/migrate, dry-run-first) |
| **Container and node shell** | `ssh` → `pct exec`, a fixed host battery | run-command-in-container, `psql`, log tailing, a host health read: what the API structurally can't do. Opt-in lanes, each behind its own switch and allowlist, judged like any mutation |

Those backends are deliberately boring. Anyone can call them. **The product is the trust layer over them.**

Six tools, every address. The vendor publishes the API; Proximo serves it whole and governs each address by what it is: 1,804 published addresses across the four products, 884 reads, 785 mutations open to an armed operator each with an authored blast-radius tier, 32 opened by an operator's switch (guest agent, container and node shell), 5 on the download lane, 20 held on purpose with a sentence, 78 excluded as not JSON calls. The record is generated from the vendor's own schema and a stale copy fails the suite: [`docs/arena.md`](docs/arena.md).

Where an operator actually starts, in the six-tool grammar:

| You want to… | Say | Worth knowing |
|---|---|---|
| Find the address | `proximo_find "list datastores"` | verbs pick the method; the vendor's own words match |
| See the whole cluster at once | `proximo_read pve /cluster/resources` | lean rows (names, states, ids) and a total; `fields=all` for the vendor's rows |
| Find out why a container is sick | `proximo_read pve /nodes/{node}/lxc/{vmid} diagnose=true` | the battery: status, storage, failed tasks, and the shell probes if that lane is open |
| Power / lifecycle, any mutation | `proximo_plan`, then `proximo_call … confirm=true` | the plan reads the target first; nothing moves without `confirm=true`, an arm and a tier |
| Put it back | `proximo_call pve undo <undo.id>` | the captured record, written back through the vendor's own PUT |
| Preflight a token / config | `proximo doctor` | run this before wiring an agent |
| Prove the record wasn't touched | `audit_verify` | on every door, always |

The six tools with typed inputs: [`docs/TOOLS.md`](docs/TOOLS.md) · the walkthrough: [`docs/SETUP.md`](docs/SETUP.md).

## Install & run

**The core alone, no model in the loop:** the same install ships `proximo-core pve GET /nodes/pve1/status` (or `--plan` on any address: the verdict and the published schema, touching nothing), and the estate memory behind `proximo-core learn | where 105 | uses local | changed 24h`: what the governed reads have seen, answered from one file beside the ledger, no model, no network. Its import closure is `httpx` and nothing else (measured by a test); every published address on all four products; the same arm gate, tiers and audit ledger as the MCP door. The core has its own network doors, each the 0.44 face's perimeter with the core behind it: `proximo-mcp-http` (MCP over streamable HTTP), `proximo-http` (REST, `POST /tools/{name}` with an OpenAPI document) and `proximo-a2a` (an Agent2Agent card whose skills are the six tools).

> 📦 **`0.50.0`**: on [PyPI](https://pypi.org/project/proximo-proxmox/), [GitHub](https://github.com/john-broadway/proximo/releases/tag/v0.50.0), and [GHCR](https://github.com/john-broadway/proximo/pkgs/container/proximo) (signed multi-arch image).
>
> **New in 0.50.0 (the estate memory is back).** Proximo keeps what its governed reads have seen in one SQLite file beside the ledger, derived and never proof, and answers `proximo-core learn | where 105 | uses local | changed 24h` with no model and no network: kind, node, status, how old the answer is, and the published path that reads the thing live. A thing it has not seen is "not in memory", never "does not exist"; only a whole, unfiltered list read may mark a thing gone. The file is the operator's alone (0600, never tightened), bounded, and every answer is a row on the ledger. `PROXIMO_MEMORY=0` opts out and creates nothing.
>
> Recent: **0.49.1** routed shell calls across a cluster by target and node (from PR #107) and gave the operator the shell wait; **0.49.0** put every model-facing answer under a hard byte ceiling at one exit on every door, and made a rollback take a safety snapshot first. See [SECURITY.md](SECURITY.md) for what each control honestly holds.

Proximo runs **on your machine**, on demand. No daemon, no open port.

```
uvx proximo-proxmox            # zero-install run (PyPI package: proximo-proxmox; command stays `proximo`)
# or: pip install proximo-proxmox            the core, MCP door included
# or: pip install "proximo-proxmox[a2a]"     + the optional A2A face
# or: pip install "proximo-proxmox[http]"    + the optional HTTP/OpenAPI face
# or: pip install "proximo-proxmox[mcp-http]" + the optional MCP-over-streamable-HTTP face
# or, from source:  git clone https://github.com/john-broadway/proximo.git && cd proximo && uv pip install -e .
```

Wire it into your MCP client as the command `proximo`, with the `PROXIMO_*` env vars; see `packaging/proximo.env.example`.

**Docker (GHCR):** `docker run -i --rm … ghcr.io/john-broadway/proximo:latest`. Multi-arch, SBOM, sigstore-signed provenance (`gh attestation verify oci://ghcr.io/john-broadway/proximo --owner john-broadway`). Mirrored to Docker Hub (`docker.io/jebroadway/proximo`, identical digest); GHCR stays the signed primary.

> **Safe by default:** API-only out of the box. The two near-root edges are opt-in and say so loudly: LXC exec (`PROXIMO_ENABLE_EXEC=1`, near-root on the host) and the qemu-guest-agent edge (`PROXIMO_ENABLE_AGENT=1`, near-root in a guest). Each is scoped by its own fail-closed allowlist.
>
> **Smallest footprint by construction:** the door advertises six schemas and nothing else. Measured on this release, `tools/list` over stdio is 5,544 bytes on the wire (about 1,400 tokens at the four-bytes-a-token heuristic; 1,568 as a stock 1.5B's chat template renders it, counted by its server), and that is the whole cost of connecting; the estate behind it is searched, not loaded. There is nothing to scope: a plane you have not configured is simply not reachable, a plane you have is reachable whole, and the gates do not shrink with the doorway. PLAN and PROVE apply to every address however small the model.

**The network faces (experimental, opt-in):** `proximo-a2a` speaks Agent2Agent. `proximo-http` serves plain HTTP + generated `/openapi.json` for no-code clients. `proximo-mcp-http` serves **MCP itself over Streamable HTTP** (the SDK's native transport) for networked MCP clients: no third-party stdio→HTTP bridge, so the perimeter stays Proximo's. **LXC on your Proxmox host, one line:** on the PVE node as root, `bash -c "$(curl -fsSL https://raw.githubusercontent.com/john-broadway/proximo/main/packaging/lxc/ct/proximo.sh)"` builds a Debian 13 container running `proximo-mcp-http` with Proximo from PyPI, its own service user, and a minted bearer on port 41243. Community-scripts engine (MIT) pointed at Proximo's own tree, their telemetry off; the same line inside the container updates it. Details: [docs/SETUP.md](docs/SETUP.md#as-an-lxc-on-the-proxmox-host), files: [`packaging/lxc/`](packaging/lxc/).

All three serve the full surface through the **same spine** as MCP. No second code path; trust spine and token scope inherited. Fail-closed perimeter: loopback, bearer-token required off-localhost, DNS-rebind and CSRF defended. Details: [SECURITY.md](SECURITY.md).

## At scale

One container is the demo. A cluster is the point.

- **The whole cluster in one call.** `proximo_read pve /cluster/resources`: every VM, node, storage pool, SDN object, as lean rows with a total.
- **One tamper-evident record across every node.** *"Show me every state-changing action this month, and prove the log wasn't touched"* becomes a query you can actually answer. No human at the CLI walks away with that.
- **Where the time comes back.** On one node a senior at the CLI is faster, and that's fine. Across a dozen nodes and hundreds of guests, a *bounded, audited* agent earns its keep.

**Many boxes, one Proximo:** register remotes in a TOML file (secrets by reference, never inlined), point `PROXIMO_TARGETS` at it, aim a call with `target="edge-pve"` (the shell door: `--target edge-pve`). The target travels with the call. PLAN and EXECUTE hit the same box, the ledger records which, cross-plane calls error. Config shape: `packaging/targets.example.toml`.

## Status: the arena record

- 🩸 **0.50.0**: **The estate memory is back.** One SQLite file beside the ledger, fed by reads that already
  happened; `learn`, `where`, `uses`, `changed` on the core door with no model and no network; derived, never
  proof; owner-only and bounded; three adversarial rounds closed on the branch. 4,323 tests.
_Every release before it (every pillar, every redteam, every fix) lives in [`CHANGELOG.md`](./CHANGELOG.md)._

**The numbers, honestly:** six tools over 1,804 published addresses, governed by what each address is (its method decides read or write, total by construction; the blast-radius tier is the one human-authored column, and an untiered mutation is refused, armed or not). **4,323 in-process tests** (ruff + pyright clean) pin the engine, the six pillars, the doors and the records, and a gate round neuters each pillar's gate one at a time and asks the suite to notice. This workspace administers its own Proxmox estate through Proximo daily (dogfood).

**Proven live** (not mocks): the governed path end to end against a real PVE 9 node through this door, plans reading the live target, receipts on the keyed chain, before-state captures and their restore. The 0.44 wrappers' live record (a 3-node cluster, PBS, PMG, PDM, a real cross-datacenter move) stays in [`CHANGELOG.md`](./CHANGELOG.md) where it was earned; it is not re-claimed for the core.
**Not yet proven — said plainly:** a small local model finishing a whole task through this door. Measured and driven on 0.45: a stock 1.5B behind llama.cpp with a 4,096-token context the server enforces, against a real PVE node, read-only. Its calls landed and the door's refusals named the fix each time (an invented field, the real ones listed); the prompt peaked at 3,074 tokens; the model did not finish the task, it invented a number. The window holds; a 1.5B does not. *Hardware*-watchdog fencing (needs physical iTCO/IPMI), and behavior at production scale. The 20 held addresses are never fired: refused by sentence, by design, not a gap.

## Documentation

| Document | What it answers |
|---|---|
| **[Setup](docs/SETUP.md)** | Token-first walkthrough: mint a least-privilege token, verify it, widen deliberately. |
| **[The Junction](docs/JUNCTION.md)** | Why Proximo exists: two roots on two planes, and the door that governs both lanes. |
| **[Verify](VERIFY.md)** | Every trust claim paired with the command that proves it. Run them cold. |
| **[Security](SECURITY.md)** | The two-deployment trust model, every control, what each honestly holds, reporting. |
| **[Threat model](docs/THREAT_MODEL.md)** | What Proximo defends against, what it doesn't, where the boundaries sit. |
| **[Tools](docs/TOOLS.md)** | The six tools, typed inputs: find, plan, read, call, and the two ledger reads. |
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
