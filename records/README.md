# records/

What Proximo knows about every address Proxmox publishes. Nothing here ships in the package: `scripts/build_proximo_json.py` joins it into `src/proximo/core/proximo.json.gz`, the one file the engine reads, and refuses the build on any line that would do nothing. `tests/test_proximo_json.py` holds the shipped file to what this directory builds.

| File | What it is | Written by |
|---|---|---|
| `vendor.json.gz` | every `(product, method, path)` the official api-viewer publishes, with its parameters, its description, and the derived `access`, `gate` and `excluded` columns | `scripts/build_governance_table.py --fetch` (generated, never hand-edited) |
| `tiers.toml` | the blast radius of each mutation, its sentence, and the addresses held on purpose | a human, by name |
| `taint.toml` | the reads whose answer carries guest- or outsider-written bytes | a human, by name |
| `secrets.toml` | the fields withheld from an answer and the arguments fingerprinted in the ledger | a human, by name |
| `undo.toml` | the POSTs that create the record their path names, and the rollbacks that take a safety snapshot first | a human, by name |
| `shell.toml` | the shell lane's addresses (Proxmox publishes no REST call for `pct exec`), each command's snapshot net | a human, by name |
| `diagnose.toml` | DIAGNOSE's battery: each subject's probes, the fields kept, the advisory flags and their sentences | a human, by name |
| `vocab.toml` | find's synonyms, each quoting the vendor's own use of the word | a human, by name |
| `notes.toml` | what a plan says when a call's arguments meet a condition (a restore without `unique` keeps the archive's identity), or for every call to the address; advice, never a verdict | a human, by name |
| `consult.toml` | the mutations whose plan takes a second look at the estate before the change, and the judge that looks (`proximo.core.consult.JUDGES`: its reads, declared in code, made through `engine.execute` under a budget; a pure function over `proximo.core.estate`); the section rides the plan and the executing receipt, and a consult that cannot finish raises the tier to the judge's worst case; advice, never a refusal | a human, by name |
| `args.toml` | what a call must name, judged from its own arguments (a Ceph flags change with no flags is refused) | a human, by name |

## The columns the build computes

Beside the authored columns (`tier`, `why`, `held`, `untrusted`, `channel`, `secret`, `arg_secrets`, `creates`, `net`, `notes`, `raises`, `consult`), the build derives what the engine would otherwise have to ask of a path, once, and writes it on the row: `lane` (the opt-in lane a gated row is served on: agent, shell, node or download), `twin` (the GET at the same path: UNDO's capture and the plan's current), `state` and `expect` (the parent's `/current` a power action is read through, and the status it aims at), `task_status` (where the plane reports a task the mutation submits), and `secret` merged with the read twin's. The engine asks the row, never "which command is this?"; a column the table cannot honour (a net on an address the door does not serve, a task address the plane does not publish) refuses the build.

## The vendor's trees

| Product | Source | Fetched |
|---|---|---|
| pve | https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js | 2026-09-19 (Last-Modified 2026-09-18); re-fetched 2026-10-19, byte-identical |
| pbs | https://pbs.proxmox.com/docs/api-viewer/apidoc.js | 2026-09-19; re-fetched 2026-10-19, byte-identical |
| pmg | https://pmg.proxmox.com/pmg-docs/api-viewer/apidoc.js | 2026-09-19; re-fetched 2026-10-19, byte-identical |
| pdm | https://pdm.proxmox.com/docs/api-viewer/apidoc.js | 2026-09-19; re-fetched 2026-10-19, byte-identical |

The published trees track the current release; a live host of an older version has fewer operations. Re-fetch when the products move (`scripts/build_governance_table.py --fetch`), rebuild (`scripts/build_proximo_json.py`), move the pinned counts in `tests/test_engine.py`, and commit the diff, so the record is dated by this table, not by memory.
