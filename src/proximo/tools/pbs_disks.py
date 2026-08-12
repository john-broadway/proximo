"""PBS disk administration wrappers (Wave 2d, full-surface campaign) —
`.scratch/2026-07-15-full-surface-campaign.md`, "2d — PBS disks".

Split out as its own tools module — mirrors tools/pbs_node.py's own split from a hypothetical
flat layout, and how tools/pve_node.py is separate from tools/pve_observability.py — because the
backend/plan logic lives in its own dedicated proximo.pbs_disks module. See that module's
docstring for the full endpoint table, the PBS-vs-PVE schema differences (9 of them), and the two
genuine schema gaps (no lvm/lvmthin on PBS at all; no zfs delete on PBS at all).
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_disks import (
    disk_directory_create,
    disk_directory_delete,
    disk_directory_list,
    disk_initgpt,
    disk_smart,
    disk_wipe,
    disk_zfs_create,
    disk_zfs_get,
    disk_zfs_list,
    disks_list,
    plan_disk_directory_create,
    plan_disk_directory_delete,
    plan_disk_initgpt,
    plan_disk_wipe,
    plan_disk_zfs_create,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Disks (reads) ---

@tool()
def pbs_node_disks_list(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    include_partitions: Annotated[bool | None, Field(description="Also include partitions in the result.")] = None,
    skipsmart: Annotated[bool | None, Field(description="Skip SMART checks (faster, less detail).")] = None,
    usage_type: Annotated[str | None, Field(description="Filter by usage: one of unused, mounted, lvm, zfs, devicemapper, partitions, filesystem.")] = None,
) -> list[dict]:
    """READ-ONLY: list physical disks on a PBS node. Returns name/devpath/disk-type/size/status/
    used/model/serial/wwn/wearout/rpm/gpt/partitions per disk. For one disk's SMART detail use
    pbs_node_disk_smart. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_disks_list", f"pbs/node/{node}/disks/list",
                    lambda: disks_list(pbs, node, include_partitions, skipsmart, usage_type))


@tool()
def pbs_node_disk_smart(
    disk: Annotated[str, Field(description="Bare block device name (e.g. 'sda', 'nvme0n1') — NOT a /dev/ path. As listed by pbs_node_disks_list.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    healthonly: Annotated[bool | None, Field(description="If True, returns only the health status (not the full attribute table).")] = None,
) -> dict:
    """READ-ONLY: get SMART attributes and health for one disk on a PBS node. Returns {status,
    attributes, wearout}. This is the GET form — it does NOT trigger a self-test. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_disk_smart", f"pbs/node/{node}/disks/{disk}",
                    lambda: disk_smart(pbs, disk, node, healthonly))


# --- Disks (mutations) ---

@tool()
def pbs_node_disk_wipe(
    disk: Annotated[str, Field(description="Bare block device or partition name to wipe (e.g. 'sda', 'sda1', 'nvme0n1p1') — NOT a /dev/ path. ALL data on the target is destroyed.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the irreversible wipe.")] = False,
) -> dict:
    """MUTATION: wipe ALL data and the partition table on a PBS disk or partition.

    RISK_HIGH, NO UNDO: DESTROYS all data, partitions, and filesystems on the named device — more
    destructive than pbs_node_disk_initgpt, which only overwrites the partition table. Unlike
    initgpt, 'disk' here MAY be a partition, not just a whole disk. Dry-run by default (returns a
    PLAN); confirm=True executes (PUT /nodes/{node}/disks/wipedisk, Smoke-confirm) and returns
    {"status": "submitted", "result": <task UPID | None>}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/disks/{disk}"
    return run_governed(
        "pbs_node_disk_wipe", tgt,
        plan=lambda: plan_disk_wipe(disk, node),
        execute=lambda: disk_wipe(pbs, disk, node),
        confirm=confirm, outcome="submitted", detail={"disk": disk})


@tool()
def pbs_node_disk_initgpt(
    disk: Annotated[str, Field(description="Bare WHOLE-disk name to initialize with a new GPT partition table (e.g. 'sda', 'nvme0n1') — NOT a /dev/ path and NOT a partition; overwrites the existing partition table.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    uuid: Annotated[str | None, Field(description="Optional UUID to assign to the new GPT table.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the irreversible GPT init.")] = False,
) -> dict:
    """MUTATION: initialize a GPT partition table on a whole PBS disk.

    RISK_HIGH: overwrites the existing partition table on the named disk; irreversible — less
    destructive than pbs_node_disk_wipe, which also erases the underlying data and accepts a
    partition target. Dry-run by default (returns a PLAN); confirm=True executes (POST
    /nodes/{node}/disks/initgpt, Smoke-confirm) and returns
    {"status": "submitted", "result": <task UPID | None>}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/disks/{disk}"
    return run_governed(
        "pbs_node_disk_initgpt", tgt,
        plan=lambda: plan_disk_initgpt(disk, node, uuid),
        execute=lambda: disk_initgpt(pbs, disk, node, uuid),
        confirm=confirm, outcome="submitted", detail={"disk": disk, "uuid": uuid})


# --- Directory backend ---

@tool()
def pbs_node_disk_directory_list(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
) -> list[dict]:
    """READ-ONLY: list systemd datastore mount units (the directory backend) on a PBS node.
    Returns device/name/path/removable/unitfile/filesystem/options per mount. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_disk_directory_list", f"pbs/node/{node}/disks/directory",
                    lambda: disk_directory_list(pbs, node))


@tool()
def pbs_node_disk_directory_create(
    disk: Annotated[str, Field(description="Bare whole-disk name to format (e.g. 'sda') — NOT a /dev/ path.")],
    name: Annotated[str, Field(description="Datastore name to create (3-32 chars, alnum/underscore start).")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    filesystem: Annotated[str | None, Field(description="Filesystem to format with: 'ext4' or 'xfs'. PBS default is ext4 if omitted.")] = None,
    add_datastore: Annotated[bool | None, Field(description="If True, also register a PBS datastore using this directory.")] = None,
    removable_datastore: Annotated[bool | None, Field(description="If True, mark the datastore as removable media.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: format a disk and mount it as a directory datastore on a PBS node.

    RISK_HIGH: FORMATS the named disk immediately — any pre-existing data is destroyed,
    irreversibly. To see what already exists use pbs_node_disk_directory_list; to remove one use
    pbs_node_disk_directory_delete (note: PBS's delete has NO cleanup-disks option — it never
    wipes the disk). Dry-run by default (returns a PLAN); confirm=True executes (POST
    /nodes/{node}/disks/directory, Smoke-confirm) and returns
    {"status": "submitted", "result": <task UPID | None>}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/disks/directory/{name}"
    return run_governed(
        "pbs_node_disk_directory_create", tgt,
        plan=lambda: plan_disk_directory_create(disk, name, node, filesystem, add_datastore, removable_datastore),
        execute=lambda: disk_directory_create(pbs, disk, name, node, filesystem, add_datastore, removable_datastore),
        confirm=confirm, outcome="submitted", detail={"disk": disk, "name": name, "filesystem": filesystem, "add_datastore": add_datastore, "removable_datastore": removable_datastore})


@tool()
def pbs_node_disk_directory_delete(
    name: Annotated[str, Field(description="Datastore name (directory backend) to remove.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the removal.")] = False,
) -> dict:
    """MUTATION: remove a directory datastore's mount unit and config mapping on a PBS node.

    RISK_HIGH: irreversibly destroys the datastore mapping. UNLIKE PVE's equivalent, PBS exposes
    NO cleanup-disks option here — the underlying disk data is NEVER wiped by this call, only the
    mount unit and config mapping are removed. This call is SYNCHRONOUS on PBS (unlike PVE's async
    version): confirm=True executes (DELETE /nodes/{node}/disks/directory/{name}) and returns
    {"status": "ok", "result": None} directly, not "submitted". Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/disks/directory/{name}"
    return run_governed(
        "pbs_node_disk_directory_delete", tgt,
        plan=lambda: plan_disk_directory_delete(name, node),
        execute=lambda: disk_directory_delete(pbs, name, node),
        confirm=confirm, detail={"name": name})


# --- ZFS backend ---

@tool()
def pbs_node_disk_zfs_list(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
) -> list[dict]:
    """READ-ONLY: list zpools (the zfs backend) on a PBS node. Returns name/health/size/alloc/
    free/frag/dedup per pool (summary only — for one pool's full vdev tree use
    pbs_node_disk_zfs_get). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_disk_zfs_list", f"pbs/node/{node}/disks/zfs",
                    lambda: disk_zfs_list(pbs, node))


@tool()
def pbs_node_disk_zfs_get(
    name: Annotated[str, Field(description="ZFS pool name (must start with a letter).")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
) -> dict:
    """READ-ONLY: get one zpool's status/vdev tree on a PBS node. This endpoint also exists on
    PVE at the identical path+verb, but Proximo has never built a wrapper for it there — a gap in
    Proximo's own PVE coverage, not a PBS-only feature. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_disk_zfs_get", f"pbs/node/{node}/disks/zfs/{name}",
                    lambda: disk_zfs_get(pbs, name, node))


@tool()
def pbs_node_disk_zfs_create(
    devices: Annotated[str, Field(description="Comma-separated bare disk names to consume (e.g. 'sda,sdb') — NOT /dev/ paths.")],
    name: Annotated[str, Field(description="Datastore name to create (3-32 chars, alnum/underscore start).")],
    raidlevel: Annotated[str, Field(description="ZFS RAID level: single, mirror, raid10, raidz, raidz2, or raidz3. (No dRAID — PBS's schema doesn't offer it, unlike PVE.)")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    ashift: Annotated[int | None, Field(description="Pool sector size exponent, 9-16 (PBS default 12 if omitted).")] = None,
    compression: Annotated[str | None, Field(description="ZFS compression algorithm: gzip, lz4, lzjb, zle, zstd, on, or off.")] = None,
    add_datastore: Annotated[bool | None, Field(description="If True, also register a PBS datastore using this zpool.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: create a zpool from disks and mount it as a zfs datastore on a PBS node.

    RISK_HIGH: FORMATS the named device(s) immediately — any pre-existing data is destroyed,
    irreversibly. Unlike the directory backend, PBS's API has NO delete endpoint for a zfs backend
    at all (module docstring gap #3) — once created, this zpool cannot be destroyed through this
    API. Dry-run by default (returns a PLAN, which names this no-delete gap explicitly);
    confirm=True executes (POST /nodes/{node}/disks/zfs, Smoke-confirm) and returns
    {"status": "submitted", "result": <task UPID | None>}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/disks/zfs/{name}"
    return run_governed(
        "pbs_node_disk_zfs_create", tgt,
        plan=lambda: plan_disk_zfs_create(devices, name, raidlevel, node, ashift, compression, add_datastore),
        execute=lambda: disk_zfs_create(pbs, devices, name, raidlevel, node, ashift, compression, add_datastore),
        confirm=confirm, outcome="submitted", detail={"devices": devices, "name": name, "raidlevel": raidlevel, "ashift": ashift, "compression": compression, "add_datastore": add_datastore})
