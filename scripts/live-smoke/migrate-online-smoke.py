#!/usr/bin/env python3
"""Live PROOF of ONLINE (zero-downtime) QEMU migration through Proximo's full stack.

This is the smoke that closes the roadmap's last migration gap: offline migration was proven
2026-06-10; ONLINE migration requires cluster + shared storage and stayed "unproven by design"
until that environment existed. It drives a REAL multi-node cluster:

  1. Assert the cluster is quorate with >= 2 nodes (pve_cluster_status).
  2. Ensure the shared NFS storage exists (pve_storage_create — PLAN first, assert the plan
     discloses the target, then execute; idempotent if already defined).
  3. Create a throwaway VM with its disk ON the shared storage (pve_create_vm), start it.
  4. PLAN the online migration — assert the plan discloses online semantics + blast radius.
  5. EXECUTE pve_guest_migrate(online=True) -> task OK, then assert POST-STATE:
     the guest is on the target node AND status == running (it never stopped: an online
     QEMU migration that can't stay live FAILS, it does not silently fall back to offline).
  6. Verify the PROVE ledger hash chain (audit_verify).

SAFETY: point PROXIMO_API_BASE_URL at a TEST cluster only (the sealed lab). SMOKE_VMID must be
a free throwaway id. Set SMOKE_KEEP=1 to leave the VM running (e.g. for a follow-on HA/fencing
proof); default self-cleans.

Run (example):
    PROXIMO_API_BASE_URL=https://<test-node>:8006/api2/json \
    PROXIMO_NODE=<source-node> PROXIMO_TOKEN_PATH=/path/to/rw-token \
    PROXIMO_FINGERPRINT=<sha256-pin> \
    SMOKE_VMID=90031 SMOKE_STORE=labshared SMOKE_NFS_SERVER=<nfs-server-ip> \
    SMOKE_NFS_EXPORT=/mnt/pve/lab SMOKE_TARGET=<target-node> \
    uv run python scripts/live-smoke/migrate-online-smoke.py
"""
from __future__ import annotations

import os
import sys
import time

from proximo import server

VMID = os.environ.get("SMOKE_VMID", "").strip()
STORE = os.environ.get("SMOKE_STORE", "").strip()
NFS_SERVER = os.environ.get("SMOKE_NFS_SERVER", "").strip()
NFS_EXPORT = os.environ.get("SMOKE_NFS_EXPORT", "").strip()
TARGET = os.environ.get("SMOKE_TARGET", "").strip()
SOURCE = os.environ.get("PROXIMO_NODE", "").strip()
KEEP = os.environ.get("SMOKE_KEEP", "").strip() in ("1", "true", "yes")

if not (VMID and STORE and NFS_SERVER and NFS_EXPORT and TARGET):
    sys.exit(
        "SMOKE_VMID, SMOKE_STORE, SMOKE_NFS_SERVER, SMOKE_NFS_EXPORT, SMOKE_TARGET "
        "are required. Refusing to guess."
    )

FAILED: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {label}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILED.append(label)


def wait_ok(upid: str, node: str | None = None, timeout: int = 300) -> bool:
    r = server.pve_task_wait(upid, node=node, timeout=timeout, interval=3)
    return bool(r.get("succeeded"))


def guest_locator(vmid: str) -> tuple[str | None, str | None]:
    """(node, status) for a qemu guest from the cluster-wide view, or (None, None)."""
    for e in server.pve_cluster_resources(resource_type="vm"):
        if str(e.get("vmid")) == str(vmid) and e.get("type") == "qemu":
            return e.get("node"), e.get("status")
    return None, None


def wait_running(vmid: str, node: str, tries: int = 12, pause: float = 3.0) -> tuple[str | None, str | None]:
    """Poll until the cluster view reports running on `node` — pvestatd refreshes the
    /cluster/resources status on a ~10s cadence, so a read right after a start task
    completes can honestly say 'unknown' for a moment."""
    where, status = None, None
    for _ in range(tries):
        where, status = guest_locator(vmid)
        if where == node and status == "running":
            break
        time.sleep(pause)
    return where, status


print(f"== migrate-online-smoke: {SOURCE} -> {TARGET}, vmid {VMID} on shared '{STORE}' ==")

# --- 1) cluster must be quorate, multi-node ---------------------------------------------
st = server.pve_cluster_status()
nodes = [e for e in st if e.get("type") == "node"]
quorate = any(e.get("type") == "cluster" and e.get("quorate") for e in st)
check("cluster quorate", quorate)
check("cluster has >= 2 nodes", len(nodes) >= 2, f"{len(nodes)} nodes")
node_names = {e.get("name") for e in nodes}
check("source in cluster", SOURCE in node_names, SOURCE)
check("target in cluster", TARGET in node_names, TARGET)
if FAILED:
    sys.exit("!! cluster preconditions failed — aborting before any mutation.")

# --- 2) shared NFS storage (idempotent) --------------------------------------------------
existing = {s.get("storage") for s in server.pve_storage_config_list()}
if STORE in existing:
    print(f"  [skip] storage '{STORE}' already defined")
else:
    plan = server.pve_storage_create(
        STORE, "nfs", server=NFS_SERVER, export=NFS_EXPORT, content="images", shared=True
    )
    ptxt = str(plan)
    check("storage PLAN discloses target", STORE in ptxt and NFS_SERVER in ptxt)
    server.pve_storage_create(
        STORE, "nfs", server=NFS_SERVER, export=NFS_EXPORT, content="images",
        shared=True, confirm=True,
    )
    time.sleep(3)
    check("storage created", STORE in {s.get("storage") for s in server.pve_storage_config_list()})

sst = server.pve_storage_status(STORE, node=SOURCE)
check("shared storage active on source", bool(sst.get("active")), f"avail={sst.get('avail')}")

created = False
try:
    # --- 3) throwaway VM, disk ON shared storage, running -------------------------------
    upid = server.pve_create_vm(
        VMID,
        node=SOURCE,
        options={
            "name": f"smoke-live-{VMID}",
            "cores": 1,
            "memory": 256,
            "scsi0": f"{STORE}:1",
            "scsihw": "virtio-scsi-pci",
            "net0": "virtio,bridge=vmbr0",
        },
        confirm=True,
    )["result"]
    created = True
    check("VM create task OK", wait_ok(upid, node=SOURCE))
    upid = server.pve_guest_power(VMID, "start", kind="qemu", node=SOURCE, confirm=True)["result"]
    check("VM start task OK", wait_ok(upid, node=SOURCE))
    node0, status0 = wait_running(VMID, SOURCE)
    check("VM running on source", node0 == SOURCE and status0 == "running", f"{node0}/{status0}")

    # --- 4) PLAN the online migration — the preview must disclose what's about to move --
    plan = server.pve_guest_migrate(VMID, TARGET, kind="qemu", node=SOURCE, online=True)
    ptxt = str(plan)
    check("migrate PLAN discloses source->target", SOURCE in ptxt and TARGET in ptxt)
    check("migrate PLAN discloses online mode", "online" in ptxt.lower())

    # --- 5) EXECUTE online migration -----------------------------------------------------
    t0 = time.monotonic()
    upid = server.pve_guest_migrate(
        VMID, TARGET, kind="qemu", node=SOURCE, online=True, confirm=True
    )["result"]
    check("online migrate task OK", wait_ok(upid, node=SOURCE, timeout=420))
    dt = time.monotonic() - t0
    node1, status1 = wait_running(VMID, TARGET)
    check("VM now on target", node1 == TARGET, f"{node1}")
    check("VM still RUNNING (never stopped)", status1 == "running", f"{status1} after {dt:.1f}s")

    # --- 6) PROVE -------------------------------------------------------------------------
    v = server.audit_verify()
    check("audit ledger verified", bool(v.get("ok")), f"{v.get('entries')} entries")

finally:
    if created and not KEEP:
        try:
            node_now, _ = guest_locator(VMID)
            server.pve_guest_power(VMID, "stop", kind="qemu", node=node_now, confirm=True)
            time.sleep(4)
            server.pve_delete_guest(VMID, kind="qemu", node=node_now, purge=True, confirm=True)
            print("  [clean] smoke VM removed")
        except Exception as e:  # cleanup is best-effort; the proof already stands
            print(f"  [clean] FAILED to remove {VMID}: {e}")
    elif created:
        print(f"  [keep] SMOKE_KEEP=1 — VM {VMID} left running on {TARGET}")

if FAILED:
    sys.exit(f"!! {len(FAILED)} check(s) FAILED: {FAILED}")
print("== ONLINE MIGRATION PROVEN — all checks green ==")
