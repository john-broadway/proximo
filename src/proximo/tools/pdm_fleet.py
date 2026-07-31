"""PDM fleet-control mutation tools (increment 1).

Governed guest lifecycle through Proxmox Datacenter Manager's remote proxy:
power / migrate / cross-remote migrate / snapshot, for qemu and lxc, every op
dry-run-by-default (PLAN) → confirm-to-fire, recorded to the hash-chained ledger
(PROVE), and a rollback takes an auto safety-snapshot first (UNDO, fail-closed).

All ops are task-backed (return a UPID): the tool records outcome="submitted",
never "ok" — an accepted task is not a finished one. See
docs/plans/2026-07-06-pdm-fleet-control-design.md.
"""
from __future__ import annotations

import time
from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.consent import enforce_consent
from proximo.contain import enforce_containment
from proximo.envelope import enforce_envelope_forbid, enforce_envelope_rate
from proximo.lease import enforce_lease
from proximo.planning import (
    plan_pdm_migrate,
    plan_pdm_power,
    plan_pdm_snapshot_create,
    plan_pdm_snapshot_delete,
    plan_pdm_snapshot_rollback,
    undo_snapname,
)
from proximo.principal import ledger_principal
from proximo.provenance import enforce_scope
from proximo.server import _audited, _ledger, _plan, tool
from proximo.targets import ledger_remote

_UNDO_TIMEOUT = 120
_UNDO_INTERVAL = 2


# ---------------------------------------------------------------------------
# Auto-undo — a safety snapshot before a rollback, waited to completion.
# ---------------------------------------------------------------------------

def _pdm_wait_task(pdm, remote: str, upid: str,
                   timeout: int = _UNDO_TIMEOUT, interval: int = _UNDO_INTERVAL) -> dict:
    """Poll a proxied PDM task to completion. Fail-closed: only an explicit exitstatus 'OK' passes."""
    deadline = time.monotonic() + timeout
    while True:
        st = pdm.task_status(remote, upid)
        if st.get("status") == "stopped":
            if st.get("exitstatus") != "OK":
                raise RuntimeError(f"task {upid} did not finish OK: {st.get('exitstatus')!r}")
            return st
        if time.monotonic() >= deadline:
            raise RuntimeError(f"task {upid} timed out after {timeout}s")
        time.sleep(interval)


def _pdm_auto_undo(action: str, target: str, pdm, remote: str, kind: str, vmid: str) -> dict:
    """Take a safety snapshot before a rollback and WAIT for it (fail-closed).

    On success records an 'undo_point' and returns {"snapshot": name, ...}. On failure
    records 'blocked:undo_unavailable' and returns that status — the caller MUST NOT roll
    back (no safety net, no risky act).
    """
    audit = _ledger()
    # DEFENSE-IN-DEPTH: snapshot_create below is a REAL mutation, so the auto-undo path must
    # clear the same six opt-in gates the primary mutation does — not just the trailing rollback.
    # Mirrors server._auto_undo exactly; without this, a tripped CONTAIN (or SCOPE/LEASE/FORBID/
    # CONSENT/RATE) would still fire the safety snapshot before being refused (redteam HIGH,
    # same bypass class fixed for ct_exec). begin_operation() in _plan already reset the per-op
    # rate reservation, so this reserves ONE slot across the op's seams, not one per seam.
    detail = {"remote": remote, "kind": kind, "vmid": vmid, "phase": "auto-undo"}
    enforce_containment(action, target, audit, detail=detail)
    enforce_scope(action, target, audit, detail=detail)
    enforce_lease(action, target, audit, detail=detail)
    enforce_envelope_forbid(action, target, audit, detail=detail)
    enforce_consent(action, target, audit, detail=detail)
    enforce_envelope_rate(action, target, audit, detail=detail)
    snapname = undo_snapname()
    try:
        upid = pdm.snapshot_create(remote, kind, vmid, snapname,
                                   description="proximo auto-undo before rollback")
        _pdm_wait_task(pdm, remote, upid)
    except Exception as e:
        audit.record(action, target=target, mutation=True, outcome="blocked:undo_unavailable",
                     detail={"error": type(e).__name__},
                     principal=ledger_principal(), remote=ledger_remote())
        return {
            "status": "blocked:undo_unavailable",
            "message": ("Requested a safety snapshot before rollback but it could not be "
                        "created/completed (the guest's storage may not support snapshots). "
                        "Rollback NOT run (fail-closed)."),
            "error": type(e).__name__,
        }
    audit.record(action, target=target, mutation=True, outcome="undo_point",
                 detail={"snapshot": snapname, "task": upid},
                 principal=ledger_principal(), remote=ledger_remote())
    return {"snapshot": snapname, "task": upid}


# ---------------------------------------------------------------------------
# Shared tool bodies (kind-parametrised; thin qemu/lxc wrappers below).
# ---------------------------------------------------------------------------

def _power(kind: str, remote: str, vmid: str, action: str, confirm: bool) -> dict:
    name = f"pdm_pve_{kind}_power"
    _, pdm = _proximo_server._pdm()
    target = f"{remote}:{kind}/{vmid}:{action}"
    plan = _plan(name, target, lambda: plan_pdm_power(pdm, remote, kind, vmid, action))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited(name, target, lambda: pdm.guest_power(remote, kind, vmid, action),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


def _migrate(kind: str, remote: str, vmid: str, target: str, online: bool, confirm: bool) -> dict:
    name = f"pdm_pve_{kind}_migrate"
    _, pdm = _proximo_server._pdm()
    tgt = f"{remote}:{kind}/{vmid}"
    plan = _plan(name, tgt, lambda: plan_pdm_migrate(pdm, remote, kind, vmid, target, online=online))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited(name, tgt, lambda: pdm.guest_migrate(remote, kind, vmid, target, online=online),
                    mutation=True, outcome="submitted", detail={"confirmed": True, "target": target})


def _remote_migrate(kind: str, remote: str, vmid: str, target_remote: str, target_bridge: str,
                    target_storage: str, target_vmid, online: bool, delete: bool,
                    confirm: bool) -> dict:
    name = f"pdm_pve_{kind}_remote_migrate"
    _, pdm = _proximo_server._pdm()
    tgt = f"{remote}:{kind}/{vmid}"
    plan = _plan(name, tgt, lambda: plan_pdm_migrate(pdm, remote, kind, vmid, target_remote,
                                                     cross_remote=True, delete=delete, online=online,
                                                     target_storage=target_storage,
                                                     target_bridge=target_bridge))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited(
        name, tgt,
        lambda: pdm.guest_remote_migrate(remote, kind, vmid, target_remote, target_bridge,
                                         target_storage, target_vmid=target_vmid,
                                         online=online, delete=delete),
        mutation=True, outcome="submitted",
        detail={"confirmed": True, "target_remote": target_remote, "delete": delete})


def _snapshot_create(kind: str, remote: str, vmid: str, snapname: str, description,
                     vmstate: bool, confirm: bool) -> dict:
    name = f"pdm_pve_{kind}_snapshot_create"
    _, pdm = _proximo_server._pdm()
    target = f"{remote}:{kind}/{vmid}:{snapname}"
    plan = _plan(name, target,
                 lambda: plan_pdm_snapshot_create(pdm, remote, kind, vmid, snapname, vmstate=vmstate))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited(
        name, target,
        lambda: pdm.snapshot_create(remote, kind, vmid, snapname,
                                    description=description, vmstate=vmstate),
        mutation=True, outcome="submitted", detail={"confirmed": True})


def _snapshot_delete(kind: str, remote: str, vmid: str, snapname: str, confirm: bool) -> dict:
    name = f"pdm_pve_{kind}_snapshot_delete"
    _, pdm = _proximo_server._pdm()
    target = f"{remote}:{kind}/{vmid}:{snapname}"
    plan = _plan(name, target, lambda: plan_pdm_snapshot_delete(pdm, remote, kind, vmid, snapname))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    return _audited(name, target, lambda: pdm.snapshot_delete(remote, kind, vmid, snapname),
                    mutation=True, outcome="submitted", detail={"confirmed": True})


def _snapshot_rollback(kind: str, remote: str, vmid: str, snapname: str, confirm: bool) -> dict:
    name = f"pdm_pve_{kind}_snapshot_rollback"
    _, pdm = _proximo_server._pdm()
    target = f"{remote}:{kind}/{vmid}:{snapname}"
    plan = _plan(name, target, lambda: plan_pdm_snapshot_rollback(pdm, remote, kind, vmid, snapname))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    # UNDO: safety snapshot BEFORE the destructive rollback, fail-closed.
    undo = _pdm_auto_undo(name, target, pdm, remote, kind, vmid)
    if undo.get("status") == "blocked:undo_unavailable":
        return undo
    res = _audited(name, target, lambda: pdm.snapshot_rollback(remote, kind, vmid, snapname),
                   mutation=True, outcome="submitted",
                   detail={"confirmed": True, "safety_snapshot": undo.get("snapshot")})
    # Surface the safety-snapshot name to the CALLER (not just the ledger) — it is the handle
    # to revert this rollback if it was a mistake. UNDO is only usable if the caller knows it.
    res["safety_snapshot"] = undo.get("snapshot")
    return res


# ---------------------------------------------------------------------------
# Tools — qemu / lxc wrappers (split to mirror the pdm_pve_{qemu,lxc}_* read plane).
# ---------------------------------------------------------------------------

@tool()
def pdm_pve_qemu_power(
    remote: Annotated[str, Field(description="PDM-registered remote (Proxmox cluster) hosting the VM.")],
    vmid: Annotated[str, Field(description="Numeric VMID of the target VM, as a string.")],
    action: Annotated[str, Field(description="Power action: 'start', 'stop', 'shutdown', or 'resume'.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes.")] = False,
) -> dict:
    """MUTATION: start/stop/shutdown/resume a VM on a PDM-registered remote (through PDM).

    For a container use pdm_pve_lxc_power; to drive a cluster directly without PDM use
    pve_guest_power. Dry-run by default: returns a PLAN (live state, blast radius, risk)
    recorded to the ledger. Re-call with confirm=True to submit. Task-backed → status='submitted'.
    """
    return _power("qemu", remote, vmid, action, confirm)


@tool()
def pdm_pve_lxc_power(
    remote: Annotated[str, Field(description="PDM-registered remote (Proxmox cluster) hosting the container.")],
    vmid: Annotated[str, Field(description="Numeric CTID of the target container, as a string.")],
    action: Annotated[str, Field(description="Power action: 'start', 'stop', or 'shutdown'.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes.")] = False,
) -> dict:
    """MUTATION: start/stop/shutdown a container on a PDM-registered remote (through PDM).

    For a VM use pdm_pve_qemu_power; to drive a cluster directly without PDM use
    pve_guest_power. Dry-run by default (PLAN); confirm=True to submit. Task-backed → 'submitted'.
    """
    return _power("lxc", remote, vmid, action, confirm)


@tool()
def pdm_pve_qemu_migrate(
    remote: Annotated[str, Field(description="PDM-registered remote (Proxmox cluster) currently hosting the VM.")],
    vmid: Annotated[str, Field(description="Numeric VMID of the VM to migrate, as a string.")],
    target: Annotated[str, Field(description="Destination node name within the same remote's cluster.")],
    online: Annotated[bool, Field(description="True live-migrates the VM; else it must be stopped.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a PLAN only; True submits it.")] = False,
) -> dict:
    """MUTATION: migrate a VM to another node within the remote's cluster (through PDM).

    For a container use pdm_pve_lxc_migrate; for a different remote/datacenter use
    pdm_pve_qemu_remote_migrate; to drive a cluster directly without PDM use pve_guest_migrate.
    online=True migrates it running; the default requires it stopped first. Dry-run by default
    (PLAN); confirm=True submits and returns a PDM task reference — track it with pdm_tasks_list (pve_task_status cannot poll a PDM UPID).
    """
    return _migrate("qemu", remote, vmid, target, online, confirm)


@tool()
def pdm_pve_lxc_migrate(
    remote: Annotated[str, Field(description="PDM-registered remote (Proxmox cluster) hosting the container.")],
    vmid: Annotated[str, Field(description="Numeric CTID of the container to migrate, as a string.")],
    target: Annotated[str, Field(description="Destination node name within the same remote's cluster.")],
    online: Annotated[bool, Field(description="True attempts online (restart) migration — real downtime for LXC; else the container must be stopped.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a PLAN only; True submits it.")] = False,
) -> dict:
    """MUTATION: relocate a container to another node within the same cluster, through PDM.

    For a move to a *different* PDM remote/datacenter use pdm_pve_lxc_remote_migrate; to drive a
    cluster directly without PDM use pve_guest_migrate. The container is moved, not copied — the
    source node stops hosting it (there is no separate source to delete). LXC has no live migration:
    online=True does a stop-move-start restart-migration (real downtime); the default (False) requires
    it already be stopped. Dry-run by default (returns a PLAN); confirm=True submits and returns a PDM
    task reference — track it with pdm_tasks_list (pve_task_status cannot poll a PDM UPID). Requires the
    wired PDM remote's token to permit migration (VM.Migrate).
    """
    return _migrate("lxc", remote, vmid, target, online, confirm)


@tool()
def pdm_pve_qemu_remote_migrate(
    remote: Annotated[str, Field(description="PDM-registered remote (Proxmox cluster) currently hosting the VM.")],
    vmid: Annotated[str, Field(description="Numeric VMID of the VM to migrate, as a string.")],
    target_remote: Annotated[str, Field(description="Destination PDM-registered remote (a different datacenter).")],
    target_bridge: Annotated[str, Field(description="Source-to-target network bridge mapping, e.g. 'vmbr0:vmbr0'.")],
    target_storage: Annotated[str, Field(description="Source-to-target storage mapping, e.g. 'local-lvm:local-lvm'.")],
    target_vmid: Annotated[str | None, Field(description="VMID on the destination; omit to keep same VMID.")] = None,
    online: Annotated[bool, Field(description="True live-migrates the VM; else it must be stopped.")] = False,
    delete: Annotated[bool, Field(description="True deletes source VM after successful move (irreversible).")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a PLAN only; True submits it.")] = False,
) -> dict:
    """MUTATION: migrate a VM to a DIFFERENT PDM-registered remote (datacenter-to-datacenter).

    For a container use pdm_pve_lxc_remote_migrate; for a same-cluster move use pdm_pve_qemu_migrate.
    target_bridge and target_storage mappings are required (e.g. 'vmbr0:vmbr0', 'local-lvm:local-lvm').
    delete=True removes the source VM after a successful move (irreversible). Dry-run by default
    (PLAN); confirm=True submits and returns a PDM task reference — track it with pdm_tasks_list (pve_task_status cannot poll a PDM UPID).
    """
    return _remote_migrate("qemu", remote, vmid, target_remote, target_bridge, target_storage,
                           target_vmid, online, delete, confirm)


@tool()
def pdm_pve_lxc_remote_migrate(
    remote: Annotated[str, Field(description="PDM-registered remote (Proxmox cluster) hosting the container.")],
    vmid: Annotated[str, Field(description="Numeric CTID of the container to migrate, as a string.")],
    target_remote: Annotated[str, Field(description="Destination PDM-registered remote (a different datacenter).")],
    target_bridge: Annotated[str, Field(description="Source-to-target network bridge mapping, e.g. 'vmbr0:vmbr0'.")],
    target_storage: Annotated[str, Field(description="Source-to-target storage mapping, e.g. 'local-lvm:local-lvm'.")],
    target_vmid: Annotated[str | None, Field(description="CTID on the destination; omit to keep same CTID.")] = None,
    online: Annotated[bool, Field(description="True attempts online (restart) migration — real downtime for LXC; else the container must be stopped.")] = False,
    delete: Annotated[bool, Field(description="True deletes container after successful move (destructive).")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a PLAN only; True submits it.")] = False,
) -> dict:
    """MUTATION: migrate a container to a DIFFERENT PDM-registered remote
    (datacenter-to-datacenter).

    For a VM use pdm_pve_qemu_remote_migrate; for a same-cluster move use pdm_pve_lxc_migrate.
    target_bridge and target_storage mappings are required (e.g. 'vmbr0:vmbr0', 'local-lvm:local-lvm').
    delete=True removes the source after a successful move (irreversible). Dry-run by default
    (PLAN); confirm=True submits and returns a PDM task reference — track it with pdm_tasks_list (pve_task_status cannot poll a PDM UPID).
    """
    return _remote_migrate("lxc", remote, vmid, target_remote, target_bridge, target_storage,
                           target_vmid, online, delete, confirm)


@tool()
def pdm_pve_qemu_snapshot_create(
    remote: Annotated[str, Field(description="PDM-registered remote (Proxmox cluster) hosting the VM.")],
    vmid: Annotated[str, Field(description="Numeric VMID of the target VM, as a string.")],
    snapname: Annotated[str, Field(description="Name to give the new snapshot.")],
    description: Annotated[str | None, Field(description="Optional free-text note stored with the snapshot.")] = None,
    vmstate: Annotated[bool, Field(description="True includes the VM's RAM state (larger, slower snapshot).")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a PLAN only; True creates it.")] = False,
) -> dict:
    """MUTATION: snapshot a VM on a PDM-registered remote (through PDM).

    For a container use pdm_pve_lxc_snapshot_create. vmstate=True includes the VM's RAM state
    (larger, slower). Additive (LOW risk) — creates a restore point, touches no existing state.
    Dry-run by default (PLAN); confirm=True creates it and returns the Proxmox task UPID.
    """
    return _snapshot_create("qemu", remote, vmid, snapname, description, vmstate, confirm)


@tool()
def pdm_pve_lxc_snapshot_create(
    remote: Annotated[str, Field(description="PDM-registered remote (Proxmox cluster) hosting the container.")],
    vmid: Annotated[str, Field(description="Numeric CTID of the target container, as a string.")],
    snapname: Annotated[str, Field(description="Name to give the new snapshot.")],
    description: Annotated[str | None, Field(description="Optional free-text note stored with the snapshot.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a PLAN only; True creates it.")] = False,
) -> dict:
    """MUTATION: snapshot a container on a PDM-registered remote (through PDM).

    For a VM use pdm_pve_qemu_snapshot_create. Containers have no RAM state, so there is no
    vmstate option. Additive (LOW risk) — creates a restore point, touches no existing state.
    Dry-run by default (PLAN); confirm=True creates it and returns the Proxmox task UPID.
    """
    return _snapshot_create("lxc", remote, vmid, snapname, description, False, confirm)


@tool()
def pdm_pve_qemu_snapshot_delete(
    remote: Annotated[str, Field(description="PDM-registered remote (Proxmox cluster) hosting the VM.")],
    vmid: Annotated[str, Field(description="Numeric VMID of the target VM, as a string.")],
    snapname: Annotated[str, Field(description="Name of the snapshot to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a PLAN only; True deletes it.")] = False,
) -> dict:
    """MUTATION: delete a named VM snapshot on a PDM-registered remote, through PDM.

    Removes only the snapshot's saved state, not the VM. Irreversible — there is no UNDO. For a
    container snapshot use pdm_pve_lxc_snapshot_delete; to create rather than delete a snapshot use
    pdm_pve_qemu_snapshot_create. Dry-run by default (returns a PLAN); confirm=True executes and
    returns a PDM task reference (track with pdm_tasks_list; pve_task_status cannot poll a PDM UPID)."""
    return _snapshot_delete("qemu", remote, vmid, snapname, confirm)


@tool()
def pdm_pve_lxc_snapshot_delete(
    remote: Annotated[str, Field(description="PDM-registered remote (Proxmox cluster) hosting the container.")],
    vmid: Annotated[str, Field(description="Numeric CTID of the target container, as a string.")],
    snapname: Annotated[str, Field(description="Name of the snapshot to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a PLAN only; True deletes it.")] = False,
) -> dict:
    """MUTATION: delete a named container snapshot on a PDM-registered remote, through PDM.

    Removes only the snapshot's saved state, not the container. Irreversible — there is no UNDO.
    For a VM snapshot use pdm_pve_qemu_snapshot_delete; to create rather than delete a snapshot use
    pdm_pve_lxc_snapshot_create. Dry-run by default (returns a PLAN); confirm=True executes and
    returns a PDM task reference (track with pdm_tasks_list; pve_task_status cannot poll a PDM UPID)."""
    return _snapshot_delete("lxc", remote, vmid, snapname, confirm)


@tool()
def pdm_pve_qemu_snapshot_rollback(
    remote: Annotated[str, Field(description="PDM-registered remote (Proxmox cluster) hosting the VM.")],
    vmid: Annotated[str, Field(description="Numeric VMID of the target VM, as a string.")],
    snapname: Annotated[str, Field(description="Name of the snapshot to roll back to.")],
    confirm: Annotated[bool, Field(description="False (default) returns a PLAN only; True runs it.")] = False,
) -> dict:
    """MUTATION: roll a VM back to a snapshot on a PDM-registered remote (through PDM).

    For a container use pdm_pve_lxc_snapshot_rollback; to roll back without PDM use pve_rollback.
    DESTRUCTIVE (discards current state). Takes an auto safety-snapshot first (fail-closed: no
    snapshot, no rollback) and returns its name as safety_snapshot — the handle to undo this
    rollback. Dry-run by default (PLAN); confirm=True submits and returns the Proxmox task UPID.
    """
    return _snapshot_rollback("qemu", remote, vmid, snapname, confirm)


@tool()
def pdm_pve_lxc_snapshot_rollback(
    remote: Annotated[str, Field(description="PDM-registered remote (Proxmox cluster) hosting the container.")],
    vmid: Annotated[str, Field(description="Numeric CTID of the target container, as a string.")],
    snapname: Annotated[str, Field(description="Name of the snapshot to roll back to.")],
    confirm: Annotated[bool, Field(description="False (default) returns a PLAN only; True runs it.")] = False,
) -> dict:
    """MUTATION: roll a container back to a snapshot on a PDM-registered remote (through PDM).

    For a VM use pdm_pve_qemu_snapshot_rollback; to roll back without PDM use pve_rollback.
    DESTRUCTIVE (discards current state). Takes an auto safety-snapshot first (fail-closed: no
    snapshot, no rollback) and returns its name as safety_snapshot — the handle to undo this
    rollback. Dry-run by default (PLAN); confirm=True submits and returns the Proxmox task UPID.
    """
    return _snapshot_rollback("lxc", remote, vmid, snapname, confirm)
