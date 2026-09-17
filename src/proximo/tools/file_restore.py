"""File-level restore tools: list the files inside a backup and pull one out, on both planes.
The mechanics, the permissions and the lab-walked wire grammar live in `proximo.file_restore`.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.file_restore import (
    pbs_catalog_list as pbs_catalog_list_op,
)
from proximo.file_restore import (
    pbs_file_download as pbs_file_download_op,
)
from proximo.file_restore import (
    plan_pbs_file_download,
    plan_pve_file_restore_download,
)
from proximo.file_restore import (
    pve_file_restore_download as pve_file_restore_download_op,
)
from proximo.file_restore import (
    pve_file_restore_list as pve_file_restore_list_op,
)
from proximo.server import _audited, run_governed, tool


@tool()
def pve_file_restore_list(
    storage: Annotated[str, Field(description="PBS-backed storage ID holding the backup (file restore works on PBS snapshots only).")],
    volid: Annotated[str, Field(description="Backup archive volume ID, as pve_backup_list returns it, e.g. pbs:backup/ct/101/2026-09-16T02:00:00Z.")],
    filepath: Annotated[str, Field(description="Path INSIDE the backup, starting with '/'. '/' lists the archive layer (e.g. data.pxar.didx or the container's root archive); then '/<archive>/etc/hosts'.")] = "/",
    node: Annotated[str | None, Field(description="Proxmox node hosting the storage; defaults to the configured node if omitted.")] = None,
) -> list[dict]:
    """READ-ONLY: list the files and directories at `filepath` INSIDE a guest's backup, without
    restoring the guest. Entries carry `path` (decoded), text, type (f/d), leaf, size, mtime.
    ADVERSARIAL: names are guest-authored free text. Needs the sighted grant (Datastore.AllocateSpace
    on the storage + VM.Backup on the guest, or Datastore.Allocate on the storage); a VM-image
    backup additionally needs proxmox-backup-file-restore on the node (it boots a restore VM, so
    the first call is slow). Then pve_file_restore_download pulls one entry out."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_file_restore_list", f"{storage}:{volid}",
                    lambda: pve_file_restore_list_op(api, storage, volid, filepath, node))


@tool()
def pve_file_restore_download(
    storage: Annotated[str, Field(description="PBS-backed storage ID holding the backup.")],
    volid: Annotated[str, Field(description="Backup archive volume ID, as pve_backup_list returns it.")],
    filepath: Annotated[str, Field(description="Path INSIDE the backup to pull out, starting with '/'; a directory downloads as an archive.")],
    tar: Annotated[bool, Field(description="For a directory: True downloads tar.zst, False (default) a zip.")] = False,
    node: Annotated[str | None, Field(description="Proxmox node hosting the storage; defaults to the configured node if omitted.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN naming source, path, destination and cap; True performs the download.")] = False,
) -> dict:
    """MUTATION (MEDIUM): pull ONE file or directory out of a guest's backup onto THIS host, without
    restoring the guest. Bytes land under PROXIMO_RESTORE_DIR (default ~/.local/state/proximo/restores)
    in a fresh private subdirectory, capped by PROXIMO_RESTORE_MAX_BYTES (default 256 MiB); the
    result carries the local path, byte count and sha256, NEVER the bytes. Dry-run by default: the PLAN
    pre-reads the entry's size and says so if it is over the cap. confirm=True to execute. The
    backup itself is never changed. Find the volid with pve_backup_list and the path with
    pve_file_restore_list first."""
    _, api, _, _ = _proximo_server._svc()
    return run_governed(
        "pve_file_restore_download", f"{storage}:{volid}",
        plan=lambda: plan_pve_file_restore_download(api, storage, volid, filepath, tar, node),
        execute=lambda: pve_file_restore_download_op(api, storage, volid, filepath, tar, node),
        confirm=confirm)


@tool()
def pbs_catalog_list(
    store: Annotated[str, Field(description="PBS datastore name.")],
    backup_type: Annotated[str, Field(description="Backup type of the snapshot: 'vm', 'ct', or 'host'.")],
    backup_id: Annotated[str, Field(description="Backup group ID (VMID/CTID or host name).")],
    backup_time: Annotated[int, Field(description="Snapshot timestamp as a Unix epoch integer (from pbs_snapshots_list).")],
    filepath: Annotated[str, Field(description="Path INSIDE the backup, starting with '/'. '/' lists the archive layer (e.g. data.pxar.didx or the container's root archive); then '/<archive>/etc/hosts'.")] = "/",
    ns: Annotated[str | None, Field(description="Namespace the snapshot lives in; omit for the root namespace.")] = None,
) -> list[dict]:
    """READ-ONLY: list the files and directories at `filepath` INSIDE one PBS snapshot (its catalog),
    directly on the backup server — works for host backups too, which PVE never sees. Entries carry
    `path` (decoded), text, type (f/d), leaf, size, mtime. ADVERSARIAL: names are guest-authored
    free text. Needs Datastore.Read on the datastore/namespace, or Datastore.Backup as the group's
    owner. Then pbs_file_download pulls one entry out."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/{store}" + (f"/{ns}" if ns else "") + f"/{backup_type}/{backup_id}/{backup_time}"
    return _audited("pbs_catalog_list", tgt,
                    lambda: pbs_catalog_list_op(pbs, store, backup_type, backup_id, backup_time, filepath, ns))


@tool()
def pbs_file_download(
    store: Annotated[str, Field(description="PBS datastore name.")],
    backup_type: Annotated[str, Field(description="Backup type of the snapshot: 'vm', 'ct', or 'host'.")],
    backup_id: Annotated[str, Field(description="Backup group ID (VMID/CTID or host name).")],
    backup_time: Annotated[int, Field(description="Snapshot timestamp as a Unix epoch integer (from pbs_snapshots_list).")],
    filepath: Annotated[str, Field(description="Path INSIDE the snapshot to pull out, starting with '/'; a directory downloads as an archive.")],
    ns: Annotated[str | None, Field(description="Namespace the snapshot lives in; omit for the root namespace.")] = None,
    tar: Annotated[bool, Field(description="For a directory: True downloads tar.zst, False (default) a zip.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN naming source, path, destination and cap; True performs the download.")] = False,
) -> dict:
    """MUTATION (MEDIUM): pull ONE file or directory out of a PBS snapshot onto THIS host. Bytes land
    under PROXIMO_RESTORE_DIR (default ~/.local/state/proximo/restores) in a fresh private
    subdirectory, capped by PROXIMO_RESTORE_MAX_BYTES (default 256 MiB); the result carries the local
    path, byte count and sha256, NEVER the bytes. Dry-run by default: the PLAN pre-reads the entry's size
    and says so if it is over the cap. confirm=True to execute. The snapshot is never changed. Find
    the snapshot with pbs_snapshots_list and the path with pbs_catalog_list first."""
    _, pbs = _proximo_server._pbs()
    snap = f"{backup_type}/{backup_id}/{backup_time}"
    tgt = f"pbs/{store}" + (f"/{ns}" if ns else "") + f"/{snap}"
    return run_governed(
        "pbs_file_download", tgt,
        plan=lambda: plan_pbs_file_download(pbs, store, backup_type, backup_id, backup_time, filepath, ns, tar),
        execute=lambda: pbs_file_download_op(pbs, store, backup_type, backup_id, backup_time, filepath, ns, tar),
        confirm=confirm)
