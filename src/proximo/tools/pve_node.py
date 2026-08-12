"""Node-lifecycle plane: disks, storage backends, node config (time/hosts/dns/certs), and bulk power
(startall/stopall/migrateall).

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated, Any

from pydantic import Field

import proximo.server as _proximo_server
from proximo.node_lifecycle import (
    _key_fingerprint,
    plan_node_cert_delete,
    plan_node_cert_upload,
    plan_node_disk_initgpt,
    plan_node_disk_wipe,
    plan_node_dns_set,
    plan_node_hosts_set,
    plan_node_migrateall,
    plan_node_startall,
    plan_node_stopall,
    plan_node_storage_backend_create,
    plan_node_storage_backend_delete,
    plan_node_time_set,
)
from proximo.server import (
    _audited,
    _plan,
    run_governed,
    tool,
)

# --- node-lifecycle plane (Wave 4) ---

# --- Disks (reads) ---

@tool()
def pve_node_disks_list(
    node: Annotated[str | None, Field(description="PVE node name to query; defaults to the configured node if omitted.")] = None,
) -> list[dict]:
    """READ-ONLY: list physical disks on a PVE node.

    GET /nodes/{node}/disks/list. VERIFIED live (PVE 9.2): returns a list of dicts
    (devpath/health/size/model/serial/used). For one disk's SMART detail use
    pve_node_disk_smart.
    """
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_disks_list", node or cfg.node,
                    lambda: api.node_disks_list(node))


@tool()
def pve_node_disk_smart(
    disk: Annotated[str, Field(description="Device path/identifier of the disk to query (e.g. /dev/sda), as listed by pve_node_disks_list.")],
    node: Annotated[str | None, Field(description="PVE node name the disk lives on; defaults to the configured node if omitted.")] = None,
) -> dict:
    """READ-ONLY: get SMART health data for one disk on a PVE node.

    GET /nodes/{node}/disks/smart?disk=…. VERIFIED live (PVE 9.2): returns a dict
    (health, type, text/attributes). This GET form does NOT trigger a self-test.
    To list all disks first use pve_node_disks_list.
    """
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_disk_smart", f"{node or cfg.node}:{disk}",
                    lambda: api.node_disk_smart(disk, node))


# --- Disks (mutations) ---

@tool()
def pve_node_disk_wipe(
    disk: Annotated[str, Field(description="Device path/identifier of the disk to wipe (e.g. /dev/sda); ALL data and the partition table are destroyed.")],
    node: Annotated[str | None, Field(description="PVE node name the disk lives on; defaults to the configured node if omitted.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the irreversible wipe.")] = False,
) -> dict:
    """MUTATION: wipe ALL data and the partition table on a node disk.

    RISK_HIGH, NO UNDO: DESTROYS all data, partitions, and filesystems on the named disk —
    more destructive than pve_node_disk_initgpt, which only overwrites the partition table.
    Dry-run by default (returns a PLAN); confirm=True executes (PUT /disks/wipedisk,
    Smoke-confirm) and returns {"status": "submitted", "result": <task UPID | None>}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/disks/{disk}"
    # Async (worker UPID) like the sibling disk/storage ops — record "submitted", not "ok": the
    # ledger must not claim the wipe finished when only the task was accepted.
    return run_governed(
        "pve_node_disk_wipe", tgt,
        plan=lambda: plan_node_disk_wipe(disk, node),
        execute=lambda: api.node_disk_wipe(disk, node),
        confirm=confirm, outcome="submitted", detail={"disk": disk})


@tool()
def pve_node_disk_initgpt(
    disk: Annotated[str, Field(description="Device path/identifier of the disk to initialize with a new GPT partition table (e.g. /dev/sda); overwrites the existing partition table.")],
    node: Annotated[str | None, Field(description="PVE node name the disk lives on; defaults to the configured node if omitted.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the irreversible GPT init.")] = False,
) -> dict:
    """MUTATION: initialize a GPT partition table on a node disk.

    RISK_HIGH: overwrites the existing partition table on the named disk; irreversible —
    less destructive than pve_node_disk_wipe, which also erases the underlying data.
    Dry-run by default (returns a PLAN); confirm=True executes (POST /disks/initgpt,
    Smoke-confirm) and returns {"status": "submitted", "result": <task UPID | None>}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/disks/{disk}"
    return run_governed(
        "pve_node_disk_initgpt", tgt,
        plan=lambda: plan_node_disk_initgpt(disk, node),
        execute=lambda: api.node_disk_initgpt(disk, node),
        confirm=confirm, outcome="submitted", detail={"disk": disk})


# --- Storage backends (reads + mutations) ---

@tool()
def pve_node_storage_backend_list(
    backend: Annotated[str, Field(description="Storage backend type to list: one of lvm, lvmthin, zfs, directory.")],
    node: Annotated[str | None, Field(description="PVE node name to query; defaults to the configured node if omitted.")] = None,
) -> list | dict:
    """READ-ONLY: list storage backends of a type on a PVE node.

    backend ∈ {lvm, lvmthin, zfs, directory}. GET /nodes/{node}/disks/{backend}.
    VERIFIED live (PVE 9.2): lvm returns a VG-tree dict; lvmthin/zfs/directory return a
    list. To create or destroy a backend use pve_node_storage_backend_create /
    pve_node_storage_backend_delete.
    """
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_storage_backend_list", f"{node or cfg.node}/disks/{backend}",
                    lambda: api.node_storage_backend_list(backend, node))


@tool()
def pve_node_storage_backend_create(
    backend: Annotated[str, Field(description="Storage backend type to create: one of lvm, lvmthin, zfs, directory.")],
    name: Annotated[str, Field(description="Name to assign to the new storage backend.")],
    devices: Annotated[str | None, Field(description="Disk device(s) consumed by the new backend: comma-separated list for zfs, a single disk path for lvm/lvmthin/directory.")] = None,
    node: Annotated[str | None, Field(description="PVE node name to create the backend on; defaults to the configured node if omitted.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
    **kw: Any,
) -> dict:
    """MUTATION: create a storage backend on the node (lvm/lvmthin/zfs/directory).

    Per-backend required params:
      zfs:       devices (comma-sep disk list) + raidlevel
      lvm/lvmthin: devices (single disk)
      directory: devices (disk path) + filesystem (e.g. ext4)

    RISK_HIGH: FORMATS the named disk(s) immediately — any pre-existing data is destroyed,
    irreversibly. To see what already exists use pve_node_storage_backend_list; to remove
    one use pve_node_storage_backend_delete. Dry-run by default (returns a PLAN);
    confirm=True executes (POST, Smoke-confirm) and returns
    {"status": "submitted", "result": <task UPID | None>}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/disks/{backend}/{name}"
    plan = _plan("pve_node_storage_backend_create", tgt,
                 lambda: plan_node_storage_backend_create(backend, name, devices, node, **kw))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    extra = {k: v for k, v in kw.items() if v is not None}
    return _audited("pve_node_storage_backend_create", tgt,
                    lambda: api.node_storage_backend_create(backend, name, node,
                                                            **({"devices": devices} if devices else {}),
                                                            **kw),
                    mutation=True, outcome="submitted",
                    detail={"backend": backend, "name": name, "devices": devices,
                            **extra, "confirmed": True})


@tool()
def pve_node_storage_backend_delete(
    backend: Annotated[str, Field(description="Storage backend type to destroy: one of lvm, lvmthin, zfs, directory.")],
    name: Annotated[str, Field(description="Name of the storage backend to destroy.")],
    node: Annotated[str | None, Field(description="PVE node name the backend lives on; defaults to the configured node if omitted.")] = None,
    cleanup: Annotated[bool, Field(description="If True, also removes the underlying disk data/partitions during backend removal.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the irreversible destroy.")] = False,
) -> dict:
    """MUTATION: destroy a storage backend on the node.

    RISK_HIGH, NO UNDO — backend-specific blast:
      zfs:        destroys the zpool and ALL data on it
      lvm/lvmthin: removes the VG — any storage built on it breaks
      directory:  removes the directory mapping (data on disk may persist)

    To create one instead use pve_node_storage_backend_create; to see what exists first
    use pve_node_storage_backend_list. Dry-run by default (returns a PLAN); confirm=True
    executes (DELETE, Smoke-confirm) and returns
    {"status": "submitted", "result": <task UPID | None>}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/disks/{backend}/{name}"
    # Async (worker UPID) like backend_create — record "submitted", not "ok".
    return run_governed(
        "pve_node_storage_backend_delete", tgt,
        plan=lambda: plan_node_storage_backend_delete(backend, name, node, cleanup),
        execute=lambda: api.node_storage_backend_delete(backend, name, node, cleanup),
        confirm=confirm, outcome="submitted", detail={"backend": backend, "name": name, "cleanup": cleanup})


# --- Node config (reads) ---

@tool()
def pve_node_time_get(
    node: Annotated[str | None, Field(description="PVE node name to query; defaults to the configured node if omitted.")] = None,
) -> dict:
    """READ-ONLY: get the current time and timezone of a PVE node.

    GET /nodes/{node}/time. VERIFIED live (PVE 9.2): returns a dict
    {localtime, time, timezone}. To change the timezone use pve_node_time_set.
    """
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_time_get", node or cfg.node,
                    lambda: api.node_time_get(node))


@tool()
def pve_node_hosts_get(
    node: Annotated[str | None, Field(description="PVE node name to query; defaults to the configured node if omitted.")] = None,
) -> dict:
    """READ-ONLY: get the /etc/hosts content of a PVE node.

    GET /nodes/{node}/hosts. VERIFIED live (PVE 9.2): returns a dict {data, digest} —
    digest is used for optimistic-concurrency on a follow-up pve_node_hosts_set.
    """
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_hosts_get", node or cfg.node,
                    lambda: api.node_hosts_get(node))


# --- Node config (mutations) ---

@tool()
def pve_node_time_set(
    timezone: Annotated[str, Field(description="IANA timezone name to set on the node (e.g. America/Chicago, UTC).")],
    node: Annotated[str | None, Field(description="PVE node name to configure; defaults to the configured node if omitted.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the timezone change.")] = False,
) -> dict:
    """MUTATION: set the timezone on a PVE node.

    RISK_LOW. CAPTURE: reads the current timezone before planning (also readable directly via
    pve_node_time_get); if unreadable → complete=False. Revert by re-applying the captured
    timezone. Dry-run by default (returns a PLAN); confirm=True executes (PUT, Smoke-confirm)
    and returns {"status": "ok", "result": None}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/time"
    return run_governed(
        "pve_node_time_set", tgt,
        plan=lambda: plan_node_time_set(api, timezone, node),
        execute=lambda: api.node_time_set(timezone, node),
        confirm=confirm, detail={"timezone": timezone})


@tool()
def pve_node_hosts_set(
    data: Annotated[str, Field(description="Full replacement content for the node's /etc/hosts file.")],
    node: Annotated[str | None, Field(description="PVE node name to configure; defaults to the configured node if omitted.")] = None,
    digest: Annotated[str | None, Field(description="Expected content digest of the current /etc/hosts, for optimistic-concurrency conflict detection.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the replacement.")] = False,
) -> dict:
    """MUTATION: replace the /etc/hosts file on a PVE node.

    RISK_MEDIUM. CAPTURE: reads current /etc/hosts before planning (also readable directly via
    pve_node_hosts_get; revert by re-applying captured content); if unreadable → complete=False.
    A bad /etc/hosts can break name resolution. Dry-run by default (returns a PLAN); confirm=True
    executes (POST, Smoke-confirm) and returns {"status": "ok", "result": None}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/hosts"
    return run_governed(
        "pve_node_hosts_set", tgt,
        plan=lambda: plan_node_hosts_set(api, data, node, digest),
        execute=lambda: api.node_hosts_set(data, node, digest),
        confirm=confirm)


@tool()
def pve_node_dns_set(
    search: Annotated[str | None, Field(description="DNS search domain to set on the node.")] = None,
    dns1: Annotated[str | None, Field(description="Primary DNS resolver IP address.")] = None,
    dns2: Annotated[str | None, Field(description="Secondary DNS resolver IP address.")] = None,
    dns3: Annotated[str | None, Field(description="Tertiary DNS resolver IP address.")] = None,
    node: Annotated[str | None, Field(description="PVE node name to configure; defaults to the configured node if omitted.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the DNS change.")] = False,
) -> dict:
    """MUTATION: update DNS resolver configuration on a PVE node.

    RISK_MEDIUM (a wrong resolver config breaks name resolution cluster-wide — same failure
    mode as node hosts_set). CAPTURE: reads current DNS config before planning (also readable
    directly via pve_node_dns); if unreadable → complete=False. Dry-run by default (returns a
    PLAN); confirm=True executes (PUT, Smoke-confirm) and returns {"status": "ok", "result": None}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/dns"
    return run_governed(
        "pve_node_dns_set", tgt,
        plan=lambda: plan_node_dns_set(api, search, dns1, dns2, dns3, node),
        execute=lambda: api.node_dns_set(node, search, dns1, dns2, dns3),
        confirm=confirm)


@tool()
def pve_node_cert_upload(
    certificates: Annotated[str, Field(description="PEM-encoded certificate chain (public, may appear in plans/logs).")],
    key: Annotated[str | None, Field(description="PEM-encoded TLS private key matching the certificate; a secret, unconditionally redacted in all output.")] = None,
    node: Annotated[str | None, Field(description="PVE node name to upload the certificate to; defaults to the configured node if omitted.")] = None,
    force: Annotated[bool, Field(description="If True, overwrite an existing custom certificate without requiring it be replaced explicitly.")] = False,
    restart: Annotated[bool, Field(description="If True, reload pveproxy after upload to apply the new certificate immediately (brief service interruption).")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the certificate upload.")] = False,
) -> dict:
    """MUTATION: upload a custom TLS certificate to a PVE node.

    RISK_HIGH, NO UNDO. A malformed cert/key can lock you out of the PVE web UI and API.
    restart=True reloads pveproxy after upload (brief service interruption). To view the
    node's currently configured certs use pve_node_certificates.

    PRIVATE KEY REDACTION: the 'key' param is a TLS private key (secret). It is
    UNCONDITIONALLY redacted — it NEVER appears in the plan, change, current state,
    detail, or ledger (regardless of redact_ledger setting). Only {"key": "[redacted]"}
    is recorded. The cert body (certificates) is public and may appear in plans/logs.

    Revert: re-upload a correct cert, or use pve_node_cert_delete to revert to self-signed.
    Dry-run by default (returns a PLAN); confirm=True executes (POST, Smoke-confirm) and
    returns {"status": "ok", "result": <dict | None>}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/certificates/custom"

    # UNCONDITIONAL: key redacted always; never passes through plan factory or ledger.
    key_detail = _key_fingerprint()

    return run_governed(
        "pve_node_cert_upload", tgt,
        plan=lambda: plan_node_cert_upload(certificates, node, force, restart),
        execute=lambda: api.node_cert_upload(certificates, node, key, force, restart),
        confirm=confirm, surface=key_detail)


@tool()
def pve_node_cert_delete(
    node: Annotated[str | None, Field(description="PVE node name to delete the custom certificate from; defaults to the configured node if omitted.")] = None,
    restart: Annotated[bool, Field(description="If True, reload pveproxy after deletion to apply the reverted self-signed certificate immediately.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete the custom TLS certificate from a PVE node.

    RISK_MEDIUM: PVE reverts to its self-signed certificate — recoverable by re-uploading via
    pve_node_cert_upload (to view current certs first use pve_node_certificates). restart=True
    reloads pveproxy after deletion. Dry-run by default (returns a PLAN); confirm=True executes
    (DELETE, Smoke-confirm) and returns {"status": "ok", "result": None}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/certificates/custom"
    return run_governed(
        "pve_node_cert_delete", tgt,
        plan=lambda: plan_node_cert_delete(node, restart),
        execute=lambda: api.node_cert_delete(node, restart),
        confirm=confirm)


# --- Bulk power (mutations) ---

@tool()
def pve_node_startall(
    node: Annotated[str | None, Field(description="PVE node name whose guests to start; defaults to the configured node if omitted.")] = None,
    vms: Annotated[str | None, Field(description="Optional comma-separated list of VMIDs/CTIDs to limit the scope; omit to start all guests on the node.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the bulk start.")] = False,
) -> dict:
    """MUTATION: start all (or filtered) guests on a PVE node.

    RISK_MEDIUM. Reversible — the inverse of pve_node_stopall. For a single guest instead of
    the whole node use pve_guest_power. vms = optional CSV of VMIDs to filter the scope.
    Dry-run by default (returns a PLAN); confirm=True executes (POST, Smoke-confirm on the
    vms param format) and returns {"status": "submitted", "result": <task UPID | None>}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/startall"
    plan = _plan("pve_node_startall", tgt,
                 lambda: plan_node_startall(node, vms))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    # node_startall() may return None for a synchronous, already-finished start rather than a
    # task UPID (backends.py's own documented contract: "Returns a task UPID or None") -- a
    # fixed outcome="submitted" would then falsely claim an in-flight task, in BOTH the returned
    # status and the ledger's own record. _audited()'s callable-outcome form resolves the honest
    # label from the actual result, after node_startall() runs, so the ledger is honest too.
    return _audited("pve_node_startall", tgt,
                    lambda: api.node_startall(node, vms),
                    mutation=True, outcome=lambda result: "ok" if result is None else "submitted",
                    detail={"confirmed": True, **({"vms": vms} if vms else {})})


@tool()
def pve_node_stopall(
    node: Annotated[str | None, Field(description="PVE node name whose guests to stop; defaults to the configured node if omitted.")] = None,
    vms: Annotated[str | None, Field(description="Optional comma-separated list of VMIDs/CTIDs to limit the scope; omit to stop ALL guests on the node.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the bulk stop.")] = False,
) -> dict:
    """MUTATION: stop ALL (or filtered) running guests on a PVE node.

    RISK_HIGH — fleet-wide service outage unless vms filters the scope. For a single guest
    instead of the whole node use pve_guest_power. Reversible via pve_node_startall, but
    guests must be restarted inside. Dry-run by default (returns a PLAN); confirm=True
    executes (POST, Smoke-confirm on the vms param format) and returns
    {"status": "submitted", "result": <task UPID | None>}.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/stopall"
    plan = _plan("pve_node_stopall", tgt,
                 lambda: plan_node_stopall(node, vms))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}
    # node_stopall() may return None for a synchronous, already-finished stop rather than a
    # task UPID (backends.py's own documented contract: "Returns a task UPID or None") -- a
    # fixed outcome="submitted" would then falsely claim an in-flight task, in BOTH the returned
    # status and the ledger's own record. _audited()'s callable-outcome form resolves the honest
    # label from the actual result, after node_stopall() runs, so the ledger is honest too.
    return _audited("pve_node_stopall", tgt,
                    lambda: api.node_stopall(node, vms),
                    mutation=True, outcome=lambda result: "ok" if result is None else "submitted",
                    detail={"confirmed": True, **({"vms": vms} if vms else {})})


@tool()
def pve_node_migrateall(
    target: Annotated[str, Field(description="Destination PVE node name to migrate guests to.")],
    node: Annotated[str | None, Field(description="Source PVE node name whose guests to migrate; defaults to the configured node if omitted.")] = None,
    vms: Annotated[str | None, Field(description="Optional comma-separated list of VMIDs/CTIDs to limit the scope; omit to migrate all guests on the node.")] = None,
    maxworkers: Annotated[int | None, Field(description="Maximum number of parallel migration workers to run.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the bulk migration.")] = False,
) -> dict:
    """MUTATION: migrate all (or filtered) guests from a node to a target node.

    RISK_HIGH, NOT auto-reversible: reversal requires a second pve_node_migrateall back,
    which may not restore the original state. target = destination node name (required).
    For a single guest instead of the whole node use pve_guest_migrate. Dry-run by default
    (returns a PLAN); confirm=True executes (POST, Smoke-confirm) and returns
    {"status": "submitted", "result": <task UPID | None>} — poll with pve_task_status.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/migrateall->{target}"
    # node_migrateall() may return None for a synchronous, already-finished migration rather
    # than a task UPID (backends.py's own documented contract: "Returns a task UPID or None")
    # -- a fixed outcome="submitted" would then falsely claim an in-flight task, in BOTH the
    # returned status and the ledger's own record. _audited()'s callable-outcome form resolves
    # the honest label from the actual result, after node_migrateall() runs, so the ledger is
    # honest too.
    return run_governed(
        "pve_node_migrateall", tgt,
        plan=lambda: plan_node_migrateall(target, node, vms, maxworkers),
        execute=lambda: api.node_migrateall(target, node, vms, maxworkers),
        confirm=confirm, outcome=lambda result: "ok" if result is None else "submitted", detail={"target": target})
