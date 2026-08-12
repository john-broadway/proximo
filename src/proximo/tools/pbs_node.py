"""PBS node OS administration wrappers (Wave 2c, full-surface campaign) —
`.scratch/2026-07-15-full-surface-campaign.md`, "2c — PBS node OS admin".

Split out as its own tools module (mirroring tools/pve_node.py's split from
tools/pve_observability.py's flat layout, and how tools/pbs_access.py is its own module
alongside tools/pbs.py) because the backend/plan logic lives in its own dedicated
proximo.pbs_node module — see that module's docstring for the endpoint table, the PBS-vs-PVE
schema differences, and the EXCLUSIONs (node hosts — PBS has no such endpoint at all; node
reboot/shutdown — deliberately excluded on both planes).
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_node import (
    _key_fingerprint,
    cert_delete,
    cert_upload,
    certificates_list,
    dns_get,
    dns_set,
    journal,
    network_iface_create,
    network_iface_delete,
    network_iface_get,
    network_iface_update,
    network_list,
    network_reload,
    network_revert,
    node_status,
    plan_cert_delete,
    plan_cert_upload,
    plan_dns_set,
    plan_network_iface_create,
    plan_network_iface_delete,
    plan_network_iface_update,
    plan_network_reload,
    plan_network_revert,
    plan_service_control,
    plan_subscription_check,
    plan_subscription_delete,
    plan_subscription_set,
    plan_task_stop,
    plan_time_set,
    service_control,
    service_status,
    services_list,
    subscription_check,
    subscription_delete,
    subscription_get,
    subscription_set,
    syslog,
    task_log,
    task_status,
    task_stop,
    time_get,
    time_set,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- DNS ---

@tool()
def pbs_node_dns_get(
    node: Annotated[str, Field(description="PBS node name (or 'localhost', the standard single-node PBS hostname).")] = "localhost",
) -> dict:
    """READ-ONLY: read a PBS node's DNS resolver configuration. Returns {search, dns1, dns2,
    dns3, digest}. Use pbs_node_dns_set to change it. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_dns_get", f"pbs/node/{node}/dns", lambda: dns_get(pbs, node))


@tool()
def pbs_node_dns_set(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    search: Annotated[str | None, Field(description="DNS search domain to set.")] = None,
    dns1: Annotated[str | None, Field(description="Primary DNS resolver IP address.")] = None,
    dns2: Annotated[str | None, Field(description="Secondary DNS resolver IP address.")] = None,
    dns3: Annotated[str | None, Field(description="Tertiary DNS resolver IP address.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear.")] = None,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest for optimistic-concurrency conflict detection.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the DNS change.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update DNS resolver configuration on a PBS node. Dry-run by default —
    the PLAN reads the node's current DNS config first (CAPTURE-or-declare). confirm=True executes
    (PUT /nodes/{node}/dns) and returns {"status": "ok", "result": None}. Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/dns"
    return run_governed(
        "pbs_node_dns_set", tgt,
        plan=lambda: plan_dns_set(pbs, node, search, dns1, dns2, dns3),
        execute=lambda: dns_set(pbs, node, search, dns1, dns2, dns3, delete_props, digest),
        confirm=confirm)


# --- Time ---

@tool()
def pbs_node_time_get(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
) -> dict:
    """READ-ONLY: read a PBS node's current time and timezone. Returns {localtime, time,
    timezone}. Use pbs_node_time_set to change the timezone. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_time_get", f"pbs/node/{node}/time", lambda: time_get(pbs, node))


@tool()
def pbs_node_time_set(
    timezone: Annotated[str, Field(description="IANA timezone name to set on the node (e.g. UTC, America/Chicago).")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the timezone change.")] = False,
) -> dict:
    """MUTATION (LOW): set the timezone on a PBS node. Dry-run by default — reads the current
    timezone first (also readable via pbs_node_time_get). confirm=True executes (PUT
    /nodes/{node}/time) and returns {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/time"
    return run_governed(
        "pbs_node_time_set", tgt,
        plan=lambda: plan_time_set(pbs, timezone, node),
        execute=lambda: time_set(pbs, timezone, node),
        confirm=confirm, detail={"timezone": timezone})


# --- Network (reads) ---

@tool()
def pbs_node_network_list(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
) -> list[dict]:
    """READ-ONLY: list network interfaces on a PBS node (with config digest). Use
    pbs_node_network_iface_get for one interface's full config. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_network_list", f"pbs/node/{node}/network", lambda: network_list(pbs, node))


@tool()
def pbs_node_network_iface_get(
    iface: Annotated[str, Field(description="Network interface name, e.g. 'eth0' or 'vmbr0'.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
) -> dict:
    """READ-ONLY: read one network interface's configuration on a PBS node. Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_network_iface_get", f"pbs/node/{node}/network/{iface}",
                    lambda: network_iface_get(pbs, iface, node))


# --- Network (mutations) ---

@tool()
def pbs_node_network_iface_create(
    iface: Annotated[str, Field(description="New network interface name.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    iface_type: Annotated[str | None, Field(description="Interface type: one of loopback, eth, bridge, bond, vlan, alias, unknown. PBS marks this OPTIONAL even on create.")] = None,
    options: Annotated[dict | None, Field(description="Additional interface fields (cidr, gateway, bridge_ports, bond_mode, mtu, autostart, comments, ...) forwarded verbatim.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): create a network interface configuration on a PBS node (staged, written
    to interfaces.new — NOT live until pbs_node_network_reload). Dry-run by default (checks for a
    name collision). confirm=True executes (POST /nodes/{node}/network) and returns
    {"status": "submitted", "result": None}. Apply with pbs_node_network_reload (RISK_HIGH) or
    discard with pbs_node_network_revert. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/network/{iface}"
    opts = options or {}
    return run_governed(
        "pbs_node_network_iface_create", tgt,
        plan=lambda: plan_network_iface_create(pbs, iface, node, iface_type, opts),
        execute=lambda: network_iface_create(pbs, iface, node, iface_type, **opts),
        confirm=confirm, outcome="submitted", detail={"iface_type": iface_type, **opts})


@tool()
def pbs_node_network_iface_update(
    iface: Annotated[str, Field(description="Existing network interface name to update.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    iface_type: Annotated[str | None, Field(description="Interface type: one of loopback, eth, bridge, bond, vlan, alias, unknown; omit to leave unchanged.")] = None,
    options: Annotated[dict | None, Field(description="Interface fields to change (cidr, gateway, bridge_ports, mtu, autostart, comments, ...) forwarded verbatim.")] = None,
    delete_props: Annotated[list[str] | None, Field(description="Property names to clear.")] = None,
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest for optimistic-concurrency conflict detection.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION (MEDIUM): update a network interface's configuration on a PBS node (staged — NOT
    live until pbs_node_network_reload). Dry-run by default — reads the interface's current
    config. Unlike PVE, PBS does not require re-sending 'type'. confirm=True executes (PUT
    /nodes/{node}/network/{iface}) and returns {"status": "ok", "result": None}. Apply with
    pbs_node_network_reload (RISK_HIGH) or discard with pbs_node_network_revert. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/network/{iface}"
    opts = options or {}
    return run_governed(
        "pbs_node_network_iface_update", tgt,
        plan=lambda: plan_network_iface_update(pbs, iface, node, iface_type, opts),
        execute=lambda: network_iface_update(pbs, iface, node, iface_type, delete_props, digest, **opts),
        confirm=confirm, detail={"iface_type": iface_type, **opts})


@tool()
def pbs_node_network_iface_delete(
    iface: Annotated[str, Field(description="Network interface name to remove.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    digest: Annotated[str | None, Field(description="Optional SHA256 config digest for optimistic-concurrency conflict detection.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the removal.")] = False,
) -> dict:
    """MUTATION (MEDIUM): remove a network interface's staged configuration on a PBS node (NOT
    live until pbs_node_network_reload). Dry-run by default — reads the interface's current
    config. confirm=True executes (DELETE /nodes/{node}/network/{iface}) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/network/{iface}"
    return run_governed(
        "pbs_node_network_iface_delete", tgt,
        plan=lambda: plan_network_iface_delete(pbs, iface, node),
        execute=lambda: network_iface_delete(pbs, iface, node, digest),
        confirm=confirm)


@tool()
def pbs_node_network_reload(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True applies the staged changes.")] = False,
) -> dict:
    """MUTATION (HIGH): apply staged network configuration changes on a PBS node — makes
    interfaces.new live. Dry-run by default. *** CONNECTIVITY-LOCKOUT RISK *** a misconfigured
    interface can drop SSH/API access; recovery requires console/physical access. confirm=True
    executes (PUT /nodes/{node}/network) and returns {"status": "ok", "result": None}. Review
    staged changes with pbs_node_network_list first; discard them instead with
    pbs_node_network_revert. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/network"
    return run_governed(
        "pbs_node_network_reload", tgt,
        plan=lambda: plan_network_reload(node),
        execute=lambda: network_reload(pbs, node),
        confirm=confirm)


@tool()
def pbs_node_network_revert(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True discards the staged changes.")] = False,
) -> dict:
    """MUTATION (LOW): discard staged network configuration changes on a PBS node (interfaces.new
    reverted) — the live config is untouched; safe. Dry-run by default. confirm=True executes
    (DELETE /nodes/{node}/network) and returns {"status": "ok", "result": None}. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/network"
    return run_governed(
        "pbs_node_network_revert", tgt,
        plan=lambda: plan_network_revert(node),
        execute=lambda: network_revert(pbs, node),
        confirm=confirm)


# --- Certificates ---

@tool()
def pbs_node_certificates_list(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
) -> list[dict]:
    """READ-ONLY: list TLS certificates configured on a PBS node. Returns filename/subject/
    issuer/validity dates/fingerprint per certificate. Use pbs_node_cert_upload to add/replace, or
    pbs_node_cert_delete to remove. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_certificates_list", f"pbs/node/{node}/certificates/info",
                    lambda: certificates_list(pbs, node))


@tool()
def pbs_node_cert_upload(
    certificates: Annotated[str, Field(description="PEM-encoded certificate chain (public, may appear in plans/logs).")],
    key: Annotated[str | None, Field(description="PEM-encoded TLS private key matching the certificate; a secret, unconditionally redacted in all output.")] = None,
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    force: Annotated[bool, Field(description="If True, overwrite an existing custom certificate.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the certificate upload.")] = False,
) -> dict:
    """MUTATION (HIGH, no undo): upload a custom TLS certificate to a PBS node. A malformed
    cert/key can lock you out of the PBS web UI and API. Dry-run by default.

    PRIVATE KEY REDACTION: `key` is UNCONDITIONALLY redacted — never appears in the plan, change,
    detail, or ledger. Only {"key": "[redacted]"} is recorded. NOTE: PBS's own schema documents a
    'restart' param on this endpoint as ignored ("UI compatibility parameter") — deliberately not
    exposed here.

    confirm=True executes (POST /nodes/{node}/certificates/custom) and returns
    {"status": "ok", "result": [...cert info dicts...]}. Revert with pbs_node_cert_delete. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/certificates/custom"
    key_detail = _key_fingerprint()
    return run_governed(
        "pbs_node_cert_upload", tgt,
        plan=lambda: plan_cert_upload(certificates, node, force),
        execute=lambda: cert_upload(pbs, certificates, key, node, force),
        confirm=confirm, surface=key_detail)


@tool()
def pbs_node_cert_delete(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION (MEDIUM): delete the custom TLS certificate on a PBS node; PBS regenerates a
    self-signed one. Dry-run by default. NOTE: PBS's 'restart' param on this endpoint is
    documented as ignored — not exposed here. confirm=True executes (DELETE
    /nodes/{node}/certificates/custom) and returns {"status": "ok", "result": None}. Recoverable
    by re-uploading (pbs_node_cert_upload). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/certificates/custom"
    return run_governed(
        "pbs_node_cert_delete", tgt,
        plan=lambda: plan_cert_delete(node),
        execute=lambda: cert_delete(pbs, node),
        confirm=confirm)


# --- Services ---

@tool()
def pbs_node_services_list(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
) -> list[dict]:
    """READ-ONLY: list all systemd services on a PBS node. Returns desc/name/service/state/
    unit-state per service. Use pbs_node_service_status for one service's state, or
    pbs_node_service_control to change a service's run state. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_services_list", f"pbs/node/{node}/services", lambda: services_list(pbs, node))


@tool()
def pbs_node_service_status(
    service: Annotated[str, Field(description="systemd service name, e.g. 'proxmox-backup-proxy' or 'sshd'.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
) -> dict:
    """READ-ONLY: get one systemd service's current state on a PBS node. Use
    pbs_node_services_list to list every service; pbs_node_service_control to change run state.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_service_status", f"pbs/node/{node}/services/{service}",
                    lambda: service_status(pbs, service, node))


@tool()
def pbs_node_service_control(
    service: Annotated[str, Field(description="systemd service name to control, e.g. 'proxmox-backup-proxy' or 'sshd'.")],
    action: Annotated[str, Field(description="Control action: 'start', 'stop', 'restart', or 'reload'.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the service control.")] = False,
) -> dict:
    """MUTATION: start/stop/restart/reload a service on a PBS node. Dry-run by default — the PLAN
    flags lockout-class services (proxmox-backup/proxmox-backup-proxy/sshd/networking/ifupdown2/
    chrony) as HIGH because stop/restart can sever management access or break backup jobs. There
    is NO auto-undo. confirm=True executes (POST /nodes/{node}/services/{service}/{action}) and
    returns {"status": "ok", "result": None}. Check current state first with
    pbs_node_service_status. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/services/{service}:{action}"
    return run_governed(
        "pbs_node_service_control", tgt,
        plan=lambda: plan_service_control(service, action, node),
        execute=lambda: service_control(pbs, service, action, node),
        confirm=confirm)


# --- Subscription ---

@tool()
def pbs_node_subscription_get(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
) -> dict:
    """READ-ONLY: read a PBS node's subscription status. Use pbs_node_subscription_set to
    install/change a key, pbs_node_subscription_check to force a status refresh, or
    pbs_node_subscription_delete to remove the record. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_subscription_get", f"pbs/node/{node}/subscription",
                    lambda: subscription_get(pbs, node))


@tool()
def pbs_node_subscription_set(
    key: Annotated[str, Field(description="Subscription key to install.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the installation.")] = False,
) -> dict:
    """MUTATION (MEDIUM): install and validate a subscription key on a PBS node. Dry-run by
    default. confirm=True executes (PUT /nodes/{node}/subscription) and returns
    {"status": "ok", "result": None}. Reversible via pbs_node_subscription_delete. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/subscription"
    return run_governed(
        "pbs_node_subscription_set", tgt,
        plan=lambda: plan_subscription_set(key, node),
        execute=lambda: subscription_set(pbs, key, node),
        confirm=confirm)


@tool()
def pbs_node_subscription_check(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    force: Annotated[bool, Field(description="If True, always re-check even if the cached status is fresh.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the check.")] = False,
) -> dict:
    """MUTATION (LOW): check and refresh a PBS node's subscription status by contacting Proxmox's
    server. Dry-run by default. No key/identity change — status-cache refresh only. confirm=True
    executes (POST /nodes/{node}/subscription) and returns {"status": "ok", "result": None}.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/subscription"
    return run_governed(
        "pbs_node_subscription_check", tgt,
        plan=lambda: plan_subscription_check(node, force),
        execute=lambda: subscription_check(pbs, node, force),
        confirm=confirm, detail={"force": force})


@tool()
def pbs_node_subscription_delete(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION (MEDIUM): delete the locally-stored subscription info on a PBS node. Dry-run by
    default. confirm=True executes (DELETE /nodes/{node}/subscription) and returns
    {"status": "ok", "result": None}. Reversible via pbs_node_subscription_set. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/subscription"
    return run_governed(
        "pbs_node_subscription_delete", tgt,
        plan=lambda: plan_subscription_delete(node),
        execute=lambda: subscription_delete(pbs, node),
        confirm=confirm)


# --- Status ---

@tool()
def pbs_node_status(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
) -> dict:
    """READ-ONLY: read a PBS node's memory/CPU/(root) disk usage. NOTE: PBS's own schema also
    exposes POST /nodes/{node}/status ("Reboot or shutdown the node") — deliberately NOT built
    here (mirrors PVE's identical, also-never-built POST /nodes/{node}/status; too dangerous for
    the default surface, same posture as the excluded node/execute endpoint). Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_status", f"pbs/node/{node}/status", lambda: node_status(pbs, node))


# --- Tasks ---

@tool()
def pbs_node_task_status(
    upid: Annotated[str, Field(description="The task's Unique Process ID (UPID) string.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
) -> dict:
    """READ-ONLY: get one PBS task's status by UPID (status/exitstatus/pid/starttime/...). Use
    pbs_tasks_list to find UPIDs, or pbs_node_task_log for the full log. Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_task_status", upid, lambda: task_status(pbs, upid, node))


@tool()
def pbs_node_task_log(
    upid: Annotated[str, Field(description="The task's Unique Process ID (UPID) string.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    start: Annotated[int, Field(description="Line offset to start returning log output from (for pagination).")] = 0,
    limit: Annotated[int, Field(description="Max number of log lines to return.")] = 50,
) -> list[dict]:
    """READ-ONLY: retrieve a PBS task's log output by UPID, paginated via start/limit. Use
    pbs_tasks_list to find UPIDs, or pbs_node_task_status for the terminal status only. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_task_log", upid, lambda: task_log(pbs, upid, node, start, limit))


@tool()
def pbs_node_task_stop(
    upid: Annotated[str, Field(description="The task's Unique Process ID (UPID) string to cancel.")],
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the cancellation.")] = False,
) -> dict:
    """MUTATION (HIGH): stop (cancel) a running PBS task. Dry-run by default — the PLAN warns that
    stopping a backup/restore/verify/sync/prune/GC task mid-flight can leave the datastore or a
    snapshot inconsistent, with NO undo. confirm=True executes (DELETE
    /nodes/{node}/tasks/{upid}) and returns {"status": "ok", "result": None} — a cancellation
    signal, not immediate. Find UPIDs via pbs_tasks_list. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return run_governed(
        "pbs_node_task_stop", upid,
        plan=lambda: plan_task_stop(upid, node),
        execute=lambda: task_stop(pbs, upid, node),
        confirm=confirm)


# --- Journal / Syslog (read-only; ADVERSARIAL — free-text logs) ---

@tool()
def pbs_node_journal(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    lastentries: Annotated[int | None, Field(description="Limit to the last N lines; defaults to 100 when no time range/cursor is given (a default-bounded listing is NOT the full journal). Conflicts with a cursor/time range.")] = None,
    since: Annotated[int | None, Field(description="Display log since this UNIX epoch (integer); conflicts with startcursor.")] = None,
    until: Annotated[int | None, Field(description="Display log until this UNIX epoch (integer); conflicts with endcursor.")] = None,
    startcursor: Annotated[str | None, Field(description="Start after this journal cursor token; conflicts with since.")] = None,
    endcursor: Annotated[str | None, Field(description="End before this journal cursor token; conflicts with until.")] = None,
) -> list[str]:
    """READ-ONLY: fetch systemd journal lines from a PBS node. Returns a list of journal-line
    strings. A bare call returns the last 100 lines (sibling parity with pve_node_journal) —
    NOT the full journal; widen with an explicit lastentries, a time range, or cursors.
    Note: since/until here are UNIX-epoch INTEGERS (the /journal convention on both PBS
    and PVE); the free-text date-time-string form is on the /syslog endpoint, not here. For the
    classic syslog view use pbs_node_syslog. Needs PROXIMO_PBS_* config."""
    if lastentries is None and since is None and until is None \
            and startcursor is None and endcursor is None:
        # lastentries conflicts with a range/cursor on PBS's own schema, so the default
        # is injected only on a bare call — a ranged query must never carry it.
        lastentries = 100
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_journal", f"pbs/node/{node}/journal",
                    lambda: journal(pbs, node, lastentries, since, until, startcursor, endcursor))


@tool()
def pbs_node_syslog(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    limit: Annotated[int | None, Field(description="Max number of syslog entries to return.")] = None,
    start: Annotated[int | None, Field(description="Start line number.")] = None,
    since: Annotated[str | None, Field(description="Display log since this date-time string.")] = None,
    until: Annotated[str | None, Field(description="Display log until this date-time string.")] = None,
    service: Annotated[str | None, Field(description="Filter to one systemd service's lines.")] = None,
) -> list[dict]:
    """READ-ONLY: fetch syslog entries from a PBS node. Returns a list of {n, t} dicts (n=line
    number, t=text). For the systemd journal (with epoch/cursor filtering) use pbs_node_journal
    instead. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_node_syslog", f"pbs/node/{node}/syslog",
                    lambda: syslog(pbs, node, limit, start, since, until, service))
