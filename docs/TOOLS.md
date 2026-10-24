# Proximo — tool reference

The complete external interface of Proximo **v0.47.0**: every MCP tool it exposes, with its inputs. This file is generated from the live server's `tools/list` output (via `lhm.plugin.json`) by [`scripts/gen_tools_doc.py`](../scripts/gen_tools_doc.py) — do not hand-edit.

**Interface conventions.** Proximo speaks the [Model Context Protocol](https://modelcontextprotocol.io); each tool is also self-describing at runtime over the standard `tools/list` method. **Inputs** are the typed parameters listed per tool below. **Output** is a structured JSON result: reads return the requested data; `proximo_call` without `confirm=true` returns the **PLAN** (the verdict, the consent id, the target as it stands, the change) rather than acting, and every call is recorded in the tamper-evident audit ledger. The six tools are always registered; `target` appears on `proximo_plan`, `proximo_read` and `proximo_call` only where `PROXIMO_TARGETS` configures a registry.

**6 tools** across 1 surfaces.

## Contents

- [Core / trust spine](#core--trust-spine) — 6

## Core / trust spine

#### `audit_entries`

READ-ONLY: read the PROVE ledger back, newest first, bounded, rows with ids; says when it truncated.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `limit` | integer | no | (default: `20`) |
| `target` | string (nullable) | no | (default: `null`) |
| `action` | string (nullable) | no | (default: `null`) |
| `mutations_only` | boolean | no | (default: `false`) |

#### `audit_verify`

READ-ONLY: walk the chain and report the first break; expected_head catches a cut tail; path=<archive> verifies a sealed archive beside the ledger.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `expected_head` | string (nullable) | no | (default: `null`) |
| `path` | string (nullable) | no | (default: `null`) |

#### `proximo_call`

MUTATION: run a governed POST/PUT/DELETE. Dry-run by default: without confirm=true it returns the plan (verdict, consent id, current, change) and mutates nothing. Refused unless the operator is armed AND the address carries an authored blast-radius tier. Every call, refused or executed, is receipted. A task-backed call is waited on (wait=N s, default 60, max 600; 0 submits only) and reports finished, failed or timed out under 'task'. method=undo with path=<undo.id> puts that receipt's capture back through the vendor's PUT, plan first; withheld or unpublished keys come back as skipped.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `plane` | enum(pve, pbs, pmg, pdm) | yes |  |
| `method` | string | yes |  |
| `path` | string | yes |  |
| `args` | object (nullable) | no | (default: `null`) |
| `confirm` | boolean | no | (default: `false`) |
| `wait` | integer (nullable) | no | (default: `null`) |

#### `proximo_find`

READ-ONLY: search every API address the planes publish, in plain words ('list datastores', 'guest status'). A verb picks the method; other words match the path, the vendor's description, parameter names. 5 by default. Returns access and the authored blast-radius tier.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `query` | string | yes |  |
| `plane` | enum(pve, pbs, pmg, pdm) (nullable) | no | (default: `null`) |
| `limit` | integer | no | (default: `5`) |

#### `proximo_plan`

READ-ONLY: the governed verdict for one address and the vendor's published parameters. Mutates nothing. A mutation's plan also reads the target (one governed read, receipted): current, change (from/to per argument), noop. Run before proximo_call. path may be words: one match is planned, several come back to pick from.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `plane` | enum(pve, pbs, pmg, pdm) | yes |  |
| `method` | string | yes |  |
| `path` | string | yes |  |
| `args` | object (nullable) | no | (default: `null`) |

#### `proximo_read`

READ-ONLY: run any GET the plane publishes, by path. Rows come back LEAN with a total (names, states, ids) unless fields='all' or fields='name,status'. Over the cap: counts per state and the odd rows; fields= gets rows. since='24h' (30m, 7d): what changed, from the door's own snapshots, no vendor call. Credentials come back withheld. wait=N on a .../tasks/{upid}/status address waits up to N s (max 600) for the task's end. diagnose=true on a node or guest path: its health reads and advisory flags, one call.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `plane` | enum(pve, pbs, pmg, pdm) | yes |  |
| `path` | string | yes |  |
| `params` | object (nullable) | no | (default: `null`) |
| `fields` | string (nullable) | no | (default: `null`) |
| `since` | string (nullable) | no | (default: `null`) |
| `wait` | integer (nullable) | no | (default: `null`) |
| `diagnose` | boolean | no | (default: `false`) |
