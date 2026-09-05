# Proximo Live-Smoke Scripts

These are **live integration smoke tests** for Proximo. They are NOT unit tests — they require a real Proxmox VE host and a scoped API token, and they exercise Proximo's operations against that host.

**Scope of what they verify (be precise):** most of these smokes drive Proximo's per-plane operation functions (`clone_guest`, `vzdump_backup`, `snapshot_create`, `disk_resize`, …) and their `plan_*` previews directly, over Proximo's real token/httpx stack against live PVE — asserting the **PLAN** pillar (risk + blast disclosure) and, where applicable, **UNDO** (rollback actually reverts state). They do not go through the `@mcp.tool` `pve_*` wrappers. The **confirm-gate** and the **PROVE** audit-ledger are covered separately by **`prove-smoke.py`**, which drives the real `pve_*` tools (`confirm=True`) and verifies the ledger records the mutation, the hash chain stays valid, and tampering is detected — live. Between them, all four pillars (PLAN/PROVE/UNDO/DIAGNOSE) have live coverage.

They live here (not under `tests/`) precisely so that pytest does not auto-collect them.

---

## What each smoke does

| Script | What it exercises | Mutations? |
|---|---|---|
| `readonly-smoke.sh` | `pve_node_status`, `pve_storage_status`, `pve_storage_content`, `pve_backup_list` (on all discovered storages), `audit_verify` | None |
| `phase1-smoke.sh` | Create / clone / backup / restore / delete QEMU VMs in a throwaway pool | Yes — self-cleaning; operates only on the throwaway VMIDs you specify |
| `netplane-smoke.sh` | Firewall rule CRUD (cluster-level, firewall stays DISABLED), pool lifecycle, HA plan (dry-run) | Firewall rules + pool — self-cleaning; firewall never enabled |
| `fwobjects-smoke.sh` | Firewall **objects**: alias CRUD, ip-set create/entry/delete, security-group CRUD, options read + `options_set` PLAN (dry-run, never executed) | Firewall config objects — self-cleaning; passive (no rule references them); firewall never enabled |
| `harules-smoke.py` | **HA rules** full chain: create throwaway VM → HA-manage → `ha_rule` create/read/update/delete → teardown | VM + HA resource + HA rule — self-cleaning (reverse order); VM is empty + HA state=ignored (CRM never starts it). Run via `proximo-ha-liveprove.sh` (reuses the test-cluster token) |
| `sdn-smoke.py` | **SDN** chain: `simple` zone → vnet → subnet create/read/update/delete | PENDING-ONLY — `sdn_apply` is NEVER called, so no live-network effect; self-cleaning (reverse order). Confirms pending objects stage + revert cleanly |
| `tfa-smoke.py` | **TFA** bounded: `tfa_list`/`tfa_get` reads + `tfa_delete` API-reachability (non-existent entry) | No factor touched, no password sent. Live-verifies PVE forbids token-based TFA mutation (`403 need proper ticket`) — reads work, delete is shape-correct but ticket-gated by PVE |
| `fw-reach-smoke.py` | **Firewall/network reach** (blast-radius): PLAN a firewall rule add → prints the per-rule REACH + `affected`; if `PROXIMO_NODE` is set, also PLANs a network apply → prints best-effort mgmt-interface lockout naming | None — pure PLAN for the rule reach; one safe `network_list` read for the apply naming; `confirm` is never passed, nothing is applied |
| `content-delete-smoke.py` | **Content-delete in-use detection** (blast-radius): allocate a scratch disk on `SMOKE_STORE` attached to throwaway `SMOKE_VMID` → PLAN `content_delete` (asserts it detects the in-use guest disk + names the VM) → detach → PLAN again (still flagged via the `unused` slot) → delete the volume via `content_delete` → verify the boot disk is intact | Yes — one scratch disk on the VMID/storage you specify; self-cleaning (removes the dangling `unused` slot + the volume). Bound the token to that VM + storage |
| `guest-lifecycle-smoke.py` | **Guest power + snapshot/config/rollback lifecycle** (MUTATE→verify): on throwaway `SMOKE_VMID`, `guest_power` start→running→stop→stopped, then snapshot_create → config_set (`sockets`) → snapshot_rollback (asserts the field actually **reverted** to baseline) → snapshot_delete. Asserts post-state at every step (not just HTTP 200). Note: asserts on `sockets`, not `description` — PVE preserves description/tags across rollback | Yes — power-cycles the VM + one snapshot + one config field; baseline-snapshot first / rollback+delete last; self-cleaning via `try/finally`. VM must be STOPPED at baseline; left stopped. Bound the token to that VM (`VM.PowerMgmt`/`VM.Snapshot`/`VM.Snapshot.Rollback`/`VM.Config.*` on `/vms/<SMOKE_VMID>`) |
| `disk-resize-smoke.py` | **Disk resize grow + grow-only guard** (MUTATE→verify): allocate a 1 GiB scratch disk on `SMOKE_STORE` → PLAN `disk_resize '+1G'` (asserts RISK_MEDIUM + "not auto-undoable" disclosure) → resize → assert the disk actually GREW to 2G → assert an absolute shrink (`1G`) is BLOCKED at both plan (RISK_HIGH) and op (refused) and had no effect | Yes — one scratch disk on the storage you specify; self-cleaning (detach + delete). Bound the token to `Datastore.AllocateSpace` on `SMOKE_STORE` (and `VM.Config.Disk` on the VM) and nowhere else |
| `clone-smoke.py` | **Clone (target storage) + delete_guest** (MUTATE→verify): PLAN clone (asserts the target storage is disclosed) → FULL clone `SMOKE_SRC_VMID`→`SMOKE_NEW_VMID` with `storage=SMOKE_STORE` → assert the clone's boot disk landed on `SMOKE_STORE` (not the source) → `delete_guest --purge` → assert the guest is gone AND its disk was purged (no orphan volume) | Yes — creates + destroys one throwaway guest; disks only on `SMOKE_STORE`; self-cleaning. Needs the token scoped to allocate `/vms/<SMOKE_NEW_VMID>` + `SDN.Use` on the target bridge. **One-shot per grant:** destroying the guest strips its `/vms/<id>` ACL, so re-grant before re-running |
| `template-convert-smoke.py` | **template_convert** (MUTATE→verify, IRREVERSIBLE): clones a disposable guest first (never touches a baseline), asserts it is NOT a template, PLAN `template_convert` (asserts RISK_HIGH / one-way) → convert → assert the guest is now a template (`template == 1`) → `delete_guest --purge` | Yes — clones + converts + destroys one throwaway guest; QEMU only; disks only on `SMOKE_STORE`; self-cleaning. Same grants as `clone-smoke.py`. **One-shot per grant** (destroy strips the `/vms/<id>` ACL) |
| `backup-smoke.py` | **backup + backup_delete** (MUTATE→verify): PLAN backup (snapshot mode → asserts RISK_LOW) → vzdump `SMOKE_VMID` to `SMOKE_STORE` → assert a NEW archive for that VMID appears → `backup_delete` → assert it's gone | Yes — one vzdump archive on `SMOKE_STORE` (only the one this run creates is deleted); self-cleaning. Token needs `VM.Backup` on the VM + `Datastore.AllocateSpace` on `SMOKE_STORE`, and `SMOKE_STORE` must have `backup` content enabled |
| `create-container-smoke.py` | **create_container + delete_guest** (MUTATE→verify): PLAN create → `create_container SMOKE_VMID` from `SMOKE_TEMPLATE` on `SMOKE_STORE` → wait for the create-lock to clear → assert the CT materialized → `delete_guest --purge` → assert gone | Yes — creates + destroys one throwaway LXC on `SMOKE_STORE`; self-cleaning. Needs `/vms/<SMOKE_VMID>` (VM.Allocate) + Datastore on `SMOKE_STORE` + `SDN.Use` on the bridge + an LXC template at `SMOKE_TEMPLATE`. **One-shot per grant** (destroy strips the `/vms/<id>` ACL) |
| `prove-smoke.py` | **PROVE pillar + confirm-gate** (the headline): drives the real `pve_*` tools — `confirm=False` returns a PLAN and mutates nothing; `confirm=True` performs a real snapshot AND writes the tamper-evident audit ledger → asserts the ledger grew, still `verify()`s, recorded the mutation, and that a TAMPERED copy is detected (`entry_hash mismatch`); cleans up via `confirm=True` delete (also ledgered) | Yes — one snapshot on throwaway `SMOKE_VMID` via the full tool stack; self-cleaning. The tamper test runs on a COPY — never touches the real ledger. Bound the token to that VM |
| `envelope-smoke.py` | **CONTAIN's autonomy envelope** (`envelope.py`'s FORBID + RATE walls, unit-proven in `tests/test_envelope.py` but previously ZERO live coverage): (1) sets `PROXIMO_FORBID=pve_snapshot_create` → asserts a real `pve_snapshot_create(confirm=True)` call is refused BEFORE it reaches PVE (no mutation, ledger records `blocked:forbidden`); (2) sets a small `PROXIMO_RATE_MAX` → fires more concurrent callers than the budget at a `threading.Barrier` (real simultaneous `pve_snapshot_create` calls, not stubbed) → asserts EXACTLY `rate_max` succeed and the rest are refused with `blocked:rate_budget`, then verifies the successful snapshots really exist | Yes — only the ALLOWED rate-budget slots create real (uniquely-named) scratch snapshots on throwaway `SMOKE_VMID`; the FORBID half never reaches the backend at all; self-cleaning. Clears its own box's rate-reservation file before the concurrency test for a deterministic re-run (see the script's CAVEAT docstring) — don't run it concurrently with other mutating traffic against the same `PROXIMO_API_BASE_URL` |

### `guest-lifecycle-smoke.py` additional variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SMOKE_VMID` | **Yes** | — | A throwaway **QEMU** VMID that is STOPPED and whose `sockets` is not already `2` |
| `SMOKE_KIND` | No | `qemu` | Must be `qemu` (the rollback assertion uses a QEMU field) |

### `disk-resize-smoke.py` additional variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SMOKE_VMID` | **Yes** | — | A throwaway VMID with a free `SMOKE_SLOT` |
| `SMOKE_STORE` | **Yes** | — | An isolated test storage supporting `images`; grant the token `Datastore.AllocateSpace` there and nowhere else |
| `SMOKE_SLOT` | No | `scsi1` | Disk slot to allocate (must be free) |

### `content-delete-smoke.py` additional variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SMOKE_VMID` | **Yes** | — | A throwaway QEMU VMID that has a SCSI controller (`scsihw`) and a free `SMOKE_SLOT` |
| `SMOKE_STORE` | **Yes** | — | A test storage that supports `images` — isolate it from production; grant the token `Datastore.AllocateSpace` there and nowhere else |
| `SMOKE_SLOT` | No | `scsi1` | Disk slot to allocate (must be free on the VM) |
| `SMOKE_SIZE` | No | `1` | Scratch disk size in GiB |

### `envelope-smoke.py` additional variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SMOKE_VMID` | **Yes** | — | A throwaway VMID the token is scoped to (any existing guest; only snapshots are touched) |
| `SMOKE_KIND` | No | `qemu` | `qemu` or `lxc` — snapshot create/delete works on either |
| `SMOKE_ENVELOPE_RATE_MAX` | No | `2` | Rate budget configured for the concurrency test window |
| `SMOKE_ENVELOPE_RATE_EXTRA` | No | `3` | Extra concurrent callers fired beyond the budget (total callers = `RATE_MAX + RATE_EXTRA`) |
| `SMOKE_ENVELOPE_RATE_WINDOW` | No | `60` | Rate window in seconds |

All mutating smokes clean up after themselves via `try/finally` and print a loud manual-cleanup fallback if cleanup fails.

---

## Prerequisites

1. **A real Proxmox VE host** (tested against PVE 7.x and 8.x).
2. **A scoped API token** — see [Creating a least-privilege token](#creating-a-least-privilege-token) below.
3. **Proximo installed** — either `pip install proximo` or run from the repo root (the wrappers auto-detect both).
4. **`shred`** available on the runner (standard on Linux; `coreutils`).

---

## Required environment variables

Set these before running any smoke. **No infra literal is hardcoded** — the scripts fail fast with a clear error if a required variable is unset.

### All smokes

| Variable | Example | Notes |
|---|---|---|
| `PROXIMO_API_BASE_URL` | `https://pve.example.com:8006/api2/json` | Full URL to your PVE JSON API endpoint |
| `PROXIMO_NODE` | `your-node` | PVE node name (matches `pvesh get /nodes`) |
| `PROXIMO_VERIFY_TLS` | `false` | `true` = verify cert (recommended for production); `false` = accept self-signed |

### Auth (choose one)

| Variable | When to use |
|---|---|
| `PROXIMO_TOKEN_PATH` | Path to a plain file whose only content is the API token string (`user@realm!tokenid=<secret>`). You manage the file's lifecycle. |
| `PROXIMO_TOKEN_FILE` | Path to a shell env file that exports the token (e.g. `PROXMOX_TOKEN=user@realm!tokenid=<secret>`). The wrapper auto-detects the token, writes it to a `mktemp` file under `umask 077`, and shreds it on exit. |

### `phase1-smoke.sh` additional variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SMOKE_STORE` | **Yes** | — | Storage ID to use for backups (e.g. `your-backup-storage`) |
| `SMOKE_POOL` | No | `proximo-smoke-throwaway` | Pool to create throwaway VMs in |
| `SMOKE_VMID` | No | `9900` | Base VMID; three consecutive IDs are used (base, base+1, base+2). Choose IDs well above your highest production VMID. |
| `PROXIMO_CT_ALLOWLIST` | No | matches `SMOKE_VMID` range | Proximo's container allowlist; defaults to the three throwaway VMIDs |
| `PROXIMO_SSH_TARGET` | **Yes, for a run from a box that also runs Proximo against production** | `pve` (the product default) | `ct_exec` does NOT travel over the API: it runs `ssh <PROXIMO_SSH_TARGET> pct exec` scoped by the allowlist above. A run whose base URL points at the test host but whose ssh target is left to default (or inherited from `~/.config/proximo/proximo.env`, which `load_env_file` reads unless the variable is already set) lands exec on a DIFFERENT machine than the API reads. `proximo doctor` flags this as `SPLIT TARGET` and reports `exec_lands_on`; run it from the smoke's env first. An IP is a valid target. |

### `netplane-smoke.sh` additional variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SMOKE_FW_COMMENT` | No | `proximo-smoke-fwtest` | Comment tag applied to throwaway firewall rules |
| `SMOKE_POOL_ID` | No | `proximo-smoke-throwaway-pool` | Throwaway pool ID for the pool-lifecycle test |

### Override the Python interpreter

Set `PYTHON=/path/to/python3` to use a specific interpreter or virtualenv Python. The wrappers default to `python3` on `PATH`.

---

## Quick start

```sh
# Export required variables
export PROXIMO_API_BASE_URL="https://pve.example.com:8006/api2/json"
export PROXIMO_NODE="your-node"
export PROXIMO_VERIFY_TLS="false"   # or "true" if you have a valid cert
export PROXIMO_TOKEN_PATH="/path/to/token-file"   # file contains: user@realm!tokenid=<secret>

# Read-only smoke (safe; no mutations)
bash scripts/live-smoke/readonly-smoke.sh

# Mutate smoke (creates/deletes throwaway VMs)
export SMOKE_STORE="your-backup-storage"
export SMOKE_VMID="9900"   # choose IDs safe for throwaway use
bash scripts/live-smoke/phase1-smoke.sh

# Network/infra-plane smoke (firewall CRUD + pool lifecycle + HA plan)
bash scripts/live-smoke/netplane-smoke.sh
```

---

## Creating a least-privilege token

Proximo is designed around the principle of a **scoped API token** — one that has only the permissions the tool set actually needs. You should NOT use your root@pam password or a full-admin token for these tests.

### Step 1 — Create a dedicated user (optional but recommended)

```sh
pveum user add proximo-smoke@pve --comment "Proximo smoke test user"
```

### Step 2 — Create an API token for that user

```sh
pveum user token add proximo-smoke@pve smoke --comment "Proximo live-smoke token"
```

Save the printed secret — it is shown only once.

### Step 3 — Grant permissions

Minimum for **readonly smoke** (`Datastore.Audit` + `Sys.Audit`):

```sh
pveum acl modify / -user proximo-smoke@pve -token smoke -role PVEAuditor
```

Additional for **phase1 smoke** (VM lifecycle + backup):

```sh
pveum role add ProximoSmoke -privs "VM.Allocate VM.Clone VM.Config.CDROM VM.Config.CPU VM.Config.Disk VM.Config.HWType VM.Config.Memory VM.Config.Network VM.Config.Options VM.PowerMgmt VM.Snapshot Datastore.AllocateSpace Datastore.Audit Pool.Allocate Sys.Audit"
pveum acl modify / -user proximo-smoke@pve -token smoke -role ProximoSmoke
```

Additional for **netplane smoke** (firewall CRUD + pool lifecycle):

```sh
# Add to the role above, or grant additionally:
pveum acl modify / -user proximo-smoke@pve -token smoke -privs "Sys.Modify Pool.Audit"
```

> **Tip:** Start with narrow permissions and expand only when a specific step reports a 403. Proximo will tell you which tool failed.

---

## Security notes

- **Token secrets are never printed.** The wrappers pass the token via a file path, not via command-line arguments or environment variables visible in `ps`.
- **Temp files are shredded on exit.** When `PROXIMO_TOKEN_FILE` is used, the wrapper writes the extracted token to a `mktemp` file under `umask 077` and registers a `trap '... shred -u ...' EXIT` — crucially **without** using `exec` to launch Python, so the bash process resumes after Python exits and the trap fires reliably.
- **Mutations are throwaway-scoped.** All mutating operations target clearly-named throwaway artifacts (`proximo-smoke-*`, VMIDs you choose). No production guests, pools, or firewall rules are touched.
- **Firewall is never enabled.** The netplane smoke tests firewall rule CRUD at the API level but never calls `firewall_set_enabled` — the firewall remains in whatever state your PVE has it.
- **SDN/network changes are never applied.** Operations that would reload host networking (e.g. `sdn_apply`, `network_apply`) are not exercised — they carry unrecoverable risk on a production network.
