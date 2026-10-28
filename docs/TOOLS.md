# Proximo — tool reference

The complete external interface of Proximo **v0.50.0**: every MCP tool it exposes, with its inputs. This file is generated from the live server's `tools/list` output (via `lhm.plugin.json`) by [`scripts/gen_tools_doc.py`](../scripts/gen_tools_doc.py) — do not hand-edit.

**Interface conventions.** Proximo speaks the [Model Context Protocol](https://modelcontextprotocol.io); each tool is also self-describing at runtime over the standard `tools/list` method. **Inputs** are the typed parameters listed per tool below. **Output** is a structured JSON result: reads return the requested data; `proximo_call` without `confirm=true` returns the **PLAN** (the verdict, the consent id, the target as it stands, the change) rather than acting, and every call is recorded in the tamper-evident audit ledger. The six tools are always registered; `target` appears on `proximo_plan`, `proximo_read` and `proximo_call` only where `PROXIMO_TARGETS` configures a registry.

**6 tools** across 1 surfaces.

## Contents

- [Core / trust spine](#core--trust-spine) — 6

## Core / trust spine

#### `audit_entries`

READ-ONLY: the PROVE ledger, newest first, bounded; says when it truncated.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `limit` | integer | no | (default: `20`) |
| `target` | string | no |  |
| `action` | string | no |  |
| `mutations_only` | boolean | no | (default: `false`) |

#### `audit_verify`

READ-ONLY: walk the chain, report the first break; expected_head catches a cut tail; path=<archive> checks a sealed archive.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `expected_head` | string | no |  |
| `path` | string | no |  |

#### `proximo_call`

MUTATION: run a governed POST/PUT/DELETE. Without confirm=true it returns the plan (verdict, consent id, current, change) and mutates nothing. Refused unless the operator is armed AND the address has an authored blast-radius tier. Every call, refused or executed, is receipted. Task-backed calls are waited on (wait=N s, default 60, max 600; 0 submits only). method=undo with path=<undo.id> puts a receipt's capture back, plan first; withheld or unpublished keys come back as skipped.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `plane` | enum(pve, pbs, pmg, pdm) | yes |  |
| `method` | string | yes |  |
| `path` | string | yes |  |
| `args` | object | no |  |
| `confirm` | boolean | no | (default: `false`) |
| `wait` | integer | no |  |

#### `proximo_find`

READ-ONLY: find API addresses by plain words ('list datastores'). A verb picks the method. Returns access and blast-radius tier. 5 by default.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `query` | string | yes |  |
| `plane` | enum(pve, pbs, pmg, pdm) | no |  |
| `limit` | integer | no | (default: `5`) |

#### `proximo_plan`

READ-ONLY, mutates nothing: the governed verdict (armed, tier, consent) for one address, with the parameters you gave and the required ones you lack; fields='name1,name2' or 'all' shows the vendor's full schema. A mutation's plan also reads the target: current, change, noop. Run before proximo_call. path may be words: one match is planned, several come back to pick from.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `plane` | enum(pve, pbs, pmg, pdm) | yes |  |
| `method` | string | yes |  |
| `path` | string | yes |  |
| `args` | object | no |  |
| `fields` | string | no |  |

#### `proximo_read`

READ-ONLY: run a GET by path or words (no leading slash). args = query parameters (params: old name). Rows come lean with a total; fields='all' or 'name,status' for others; over the cap you get counts and a next line. since='24h': what changed, from the door's snapshots. wait=N on .../tasks/{upid}/status waits up to N s (max 600). diagnose=true on a node or guest path: health and advisory flags. Credentials come back withheld.

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `plane` | enum(pve, pbs, pmg, pdm) | yes |  |
| `path` | string | yes |  |
| `args` | object | no |  |
| `fields` | string | no |  |
| `since` | string | no |  |
| `wait` | integer | no |  |
| `diagnose` | boolean | no | (default: `false`) |
| `params` | object | no |  |
