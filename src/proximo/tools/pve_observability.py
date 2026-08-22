"""PVE observability (node services/rrd/journal/syslog/dns/subscription/certs), notifications & metrics
endpoints, and hardware PCI/USB mappings.

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.hw_mappings import (
    hardware_list,
    mapping_pci_create,
    mapping_pci_delete,
    mapping_pci_list,
    mapping_pci_update,
    mapping_usb_create,
    mapping_usb_delete,
    mapping_usb_list,
    mapping_usb_update,
    plan_mapping_pci_create,
    plan_mapping_pci_delete,
    plan_mapping_pci_update,
    plan_mapping_usb_create,
    plan_mapping_usb_delete,
    plan_mapping_usb_update,
)
from proximo.notifications import (
    metrics_server_delete,
    metrics_server_list,
    metrics_server_set,
    notification_endpoint_create,
    notification_endpoint_delete,
    notification_endpoint_list,
    notification_endpoint_update,
    notification_matcher_delete,
    notification_matcher_set,
    plan_metrics_server_delete,
    plan_metrics_server_set,
    plan_notification_endpoint_create,
    plan_notification_endpoint_delete,
    plan_notification_endpoint_update,
    plan_notification_matcher_delete,
    plan_notification_matcher_set,
    plan_notification_test,
)
from proximo.notifications import (
    notification_test as notification_test_op,
)
from proximo.observability import (
    node_certificates_info,
    node_dns_get,
    node_journal,
    node_rrddata,
    node_service_control,
    node_service_status,
    node_services_list,
    node_subscription,
    node_syslog,
    plan_node_service_control,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Observability (REST API, read) ---

@tool()
def pve_node_services_list(
    node: Annotated[str | None, Field(description="PVE node name; defaults to the configured node")] = None,
) -> list[dict]:
    """READ-ONLY: list all services on a PVE node.

    No state change. Returns a list of service dicts with name, state (running/dead/
    inactive), and description for each service. For one service's current state use
    pve_node_service_status; to change a service's run state use pve_node_service_control."""
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_services_list", node or cfg.node,
                    lambda: node_services_list(api, node))


@tool()
def pve_node_service_status(
    service: Annotated[str, Field(description="systemd service name, e.g. 'pveproxy' or 'sshd'")],
    node: Annotated[str | None, Field(description="PVE node name; defaults to the configured node")] = None,
) -> dict:
    """READ-ONLY: get one systemd service's current state on a PVE node (e.g. pveproxy, sshd).

    No state change. Returns a dict with the service's name, state (running/dead/inactive) and
    description. To list every service use pve_node_services_list; to *change* a service's run state
    use pve_node_service_control."""
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_service_status", f"{node or cfg.node}/services/{service}",
                    lambda: node_service_status(api, service, node))


@tool()
def pve_node_rrddata(
    node: Annotated[str | None, Field(description="PVE node name; defaults to the configured node")] = None,
    timeframe: Annotated[str, Field(description="Rolling RRD window ENDING NOW: 'hour', 'day', 'week', 'month', or 'year'. 'day' is the last ~24 hours, NOT the calendar day")] = "hour",
    cf: Annotated[str | None, Field(description="RRD consolidation function: 'AVERAGE' or 'MAX'; defaults to server-side default")] = None,
) -> list[dict]:
    """READ-ONLY: fetch RRD (round-robin database) time-series telemetry for a PVE node.

    No state change. Returns a list of data-point dicts with timestamps and per-metric values
    (the exact metric keys vary by PVE version) over the specified timeframe, optionally aggregated by
    consolidation function (AVERAGE or MAX). Node-level only, not per-guest.

    **The window ROLLS and ends at now.** `day` means the last ~24 hours, which spans two
    calendar days for all but one instant. PVE's RRD endpoint accepts no start/end, so a
    CALENDAR day ("today", "yesterday", a named date) is NOT available from this tool and must
    not be reported as though it were: answer with the span the data actually covers, which the
    returned `time` fields state exactly. Asked for "today", say you are showing the last 24
    hours and give the real bounds."""
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_rrddata", node or cfg.node,
                    lambda: node_rrddata(api, node, timeframe, cf))


@tool()
def pve_node_journal(
    node: Annotated[str | None, Field(description="PVE node name; defaults to the configured node")] = None,
    lastentries: Annotated[int, Field(description="Number of most-recent journal lines to return, max 5000 (values above are rejected)")] = 100,
    since: Annotated[str | None, Field(description="Only return entries at or after this timestamp (journalctl-compatible format)")] = None,
    until: Annotated[str | None, Field(description="Only return entries at or before this timestamp (journalctl-compatible format)")] = None,
) -> list[str]:
    """READ-ONLY: fetch systemd journal lines from a PVE node for log inspection.

    No state change. Returns a list of journal-line strings. Narrow with since/until (timestamp
    format per PVE — typically epoch seconds or ISO 8601) and lastentries (most-recent N, max 5000;
    higher is rejected with an error). For the classic syslog view
    use pve_node_syslog; for one service's current state use pve_node_service_status."""
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_journal", node or cfg.node,
                    lambda: node_journal(api, node, lastentries, since, until))


@tool()
def pve_node_syslog(
    node: Annotated[str | None, Field(description="PVE node name; defaults to the configured node")] = None,
    limit: Annotated[int, Field(description="Maximum number of syslog entries to return, max 5000 (values above are rejected)")] = 100,
) -> list[dict]:
    """READ-ONLY: fetch syslog entries from a PVE node for log inspection.

    No state change. Returns a list of entry dicts, up to `limit` (max 5000; higher is rejected with an error).
    For the systemd journal (with since/until filtering) use pve_node_journal instead."""
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_syslog", node or cfg.node,
                    lambda: node_syslog(api, node, limit))


@tool()
def pve_node_dns(
    node: Annotated[str | None, Field(description="PVE node name; defaults to the configured node")] = None,
) -> dict:
    """READ-ONLY: Read a Proxmox node's DNS configuration. Returns a dict with
    search domain and configured nameservers (dns1/dns2/dns3). Use pve_node_dns_set
    to change it."""
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_dns", node or cfg.node, lambda: node_dns_get(api, node))


@tool()
def pve_node_subscription(
    node: Annotated[str | None, Field(description="PVE node name; defaults to the configured node")] = None,
) -> dict:
    """READ-ONLY: read a Proxmox node's subscription status.

    No state change. Returns a dict with status, product name, check time, next due
    date, and subscription level."""
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_subscription", node or cfg.node,
                    lambda: node_subscription(api, node))


@tool()
def pve_node_certificates(
    node: Annotated[str | None, Field(description="PVE node name; defaults to the configured node")] = None,
) -> list[dict]:
    """READ-ONLY: list TLS certificates configured on a Proxmox node.

    No state change. Returns a list of certificate dicts with filename, subject, issuer,
    validity dates (notbefore/notafter), SANs, and fingerprint. To add or replace a
    certificate use pve_node_cert_upload; to remove one use pve_node_cert_delete."""
    cfg, api, _, _ = _proximo_server._svc()
    return _audited("pve_node_certificates", node or cfg.node,
                    lambda: node_certificates_info(api, node))


# --- Observability (mutation) ---

@tool()
def pve_node_service_control(
    service: Annotated[str, Field(description="systemd service name to control, e.g. 'pveproxy' or 'sshd'")],
    action: Annotated[str, Field(description="Control action: 'start', 'stop', 'restart', or 'reload'")],
    node: Annotated[str | None, Field(description="PVE node name; defaults to the configured node")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the service control")] = False,
) -> dict:
    """MUTATION: start/stop/restart/reload a service on a PVE node. Dry-run by default — the
    PLAN flags lockout-class services (sshd/pveproxy/pvedaemon/pve-cluster/corosync/networking/
    ...) as HIGH because stop/restart can sever the management plane or break quorum. There is
    NO auto-undo for a service control. confirm=True executes and returns
    {"status": "submitted", "result": <UPID>} — poll that UPID with pve_task_status. Check
    current state first with pve_node_service_status.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"{node or cfg.node}/services/{service}:{action}"
    return run_governed(
        "pve_node_service_control", tgt,
        plan=lambda: plan_node_service_control(service, action, node),
        execute=lambda: node_service_control(api, service, action, node),
        confirm=confirm, outcome="submitted")


# --- Notifications & Metrics (Plane E) — PVE notification endpoints, matchers, metrics ---

@tool()
def pve_notification_endpoint_list() -> list[dict]:
    """READ-ONLY: list all PVE notification endpoints.

    No state change. Returns a list of dicts for each configured delivery channel (gotify,
    smtp, sendmail, webhook) with type, name, and endpoint-specific config. To add one use
    pve_notification_endpoint_create; to remove one use pve_notification_endpoint_delete."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_notification_endpoint_list", "cluster/notifications/endpoints",
                    lambda: notification_endpoint_list(api))


@tool()
def pve_notification_endpoint_create(
    ep_type: Annotated[str, Field(description="Notification endpoint type: 'gotify', 'smtp', 'sendmail', or 'webhook'")],
    name: Annotated[str, Field(description="Unique name for the new notification endpoint")],
    comment: Annotated[str | None, Field(description="Optional free-text comment stored with the endpoint")] = None,
    options: Annotated[dict | None, Field(description="Endpoint-specific config fields, e.g. sendmail: {'mailto-user':'root@pam'}; gotify: {'server':.., 'token':..}; webhook: {'url':..}")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation")] = False,
) -> dict:
    """MUTATION: create a PVE notification endpoint. ep_type = gotify|smtp|sendmail|webhook.
    `options` carries the endpoint-specific config (sendmail: {"mailto-user":"root@pam"};
    gotify: {"server":..,"token":..}; webhook: {"url":..}). Additive, low risk. Dry-run by
    default (returns a PLAN); confirm=True executes and returns {"status": "ok", "result": null} (no further
    payload). To modify an existing endpoint instead use pve_notification_endpoint_update."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/notifications/endpoints/{ep_type}/{name}"
    return run_governed(
        "pve_notification_endpoint_create", tgt,
        plan=lambda: plan_notification_endpoint_create(
                     ep_type, name, **{"comment": comment, **(options or {})}),
        execute=lambda: notification_endpoint_create(api, ep_type, name,
                                                         **{"comment": comment, **(options or {})}),
        confirm=confirm)


@tool()
def pve_notification_endpoint_update(
    ep_type: Annotated[str, Field(description="Notification endpoint type: 'gotify', 'smtp', 'sendmail', or 'webhook'")],
    name: Annotated[str, Field(description="Name of the existing notification endpoint to update")],
    comment: Annotated[str | None, Field(description="Optional free-text comment to set on the endpoint")] = None,
    options: Annotated[dict | None, Field(description="Endpoint-specific fields to change, same shape as create")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update")] = False,
) -> dict:
    """MUTATION: update a PVE notification endpoint. ep_type = gotify|smtp|sendmail|webhook.
    `options` carries the endpoint-specific fields to change (same shape as create). Dry-run
    by default — captures current config into the PLAN; confirm=True executes and returns
    {"status": "ok", "result": null} (no further payload). No snapshot primitive; re-apply the captured
    config to revert, or use pve_notification_endpoint_create to make a new one instead."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/notifications/endpoints/{ep_type}/{name}"
    return run_governed(
        "pve_notification_endpoint_update", tgt,
        plan=lambda: plan_notification_endpoint_update(
                     api, ep_type, name, **{"comment": comment, **(options or {})}),
        execute=lambda: notification_endpoint_update(api, ep_type, name,
                                                         **{"comment": comment, **(options or {})}),
        confirm=confirm)


@tool()
def pve_notification_endpoint_delete(
    ep_type: Annotated[str, Field(description="Notification endpoint type: 'gotify', 'smtp', 'sendmail', or 'webhook'")],
    name: Annotated[str, Field(description="Name of the notification endpoint to delete")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion")] = False,
) -> dict:
    """MUTATION: delete a PVE notification endpoint. ep_type = gotify|smtp|sendmail|webhook.
    Dry-run by default — captures current config. confirm=True executes and returns
    {"status": "ok", "result": null} (no further payload). No UNDO primitive — matchers referencing this
    endpoint silently fail until it is re-created with pve_notification_endpoint_create."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/notifications/endpoints/{ep_type}/{name}"
    return run_governed(
        "pve_notification_endpoint_delete", tgt,
        plan=lambda: plan_notification_endpoint_delete(api, ep_type, name),
        execute=lambda: notification_endpoint_delete(api, ep_type, name),
        confirm=confirm)


@tool()
def pve_notification_matcher_set(
    name: Annotated[str, Field(description="Name of the notification matcher (alert routing rule) to create or update")],
    comment: Annotated[str | None, Field(description="Optional free-text comment stored with the matcher")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the create/update")] = False,
) -> dict:
    """MUTATION: create-or-update a PVE notification matcher (alert routing rule). Dry-run
    by default (returns a PLAN); confirm=True executes and returns {"status": "ok", "result": null} (no
    further payload). No snapshot primitive — re-apply with this same tool to restore after
    deletion. To remove a matcher use pve_notification_matcher_delete."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/notifications/matchers/{name}"
    return run_governed(
        "pve_notification_matcher_set", tgt,
        plan=lambda: plan_notification_matcher_set(name, comment=comment),
        execute=lambda: notification_matcher_set(api, name, comment=comment),
        confirm=confirm)


@tool()
def pve_notification_matcher_delete(
    name: Annotated[str, Field(description="Name of the notification matcher to delete")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion")] = False,
) -> dict:
    """MUTATION: delete a PVE notification matcher. Dry-run by default. confirm=True
    executes and returns {"status": "ok", "result": null} (no further payload). No UNDO primitive — alerts
    matching this filter go un-routed until re-created with pve_notification_matcher_set."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/notifications/matchers/{name}"
    return run_governed(
        "pve_notification_matcher_delete", tgt,
        plan=lambda: plan_notification_matcher_delete(name),
        execute=lambda: notification_matcher_delete(api, name),
        confirm=confirm)


@tool()
def pve_notification_test(
    name: Annotated[str, Field(description="Name of the notification target to send a test notification to")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True sends a real test notification")] = False,
) -> dict:
    """MUTATION: send a test notification to a PVE notification target. Dry-run by default
    (returns a PLAN, nothing is sent); confirm=True SENDS A REAL NOTIFICATION to the target's
    recipients and returns {"status": "ok", "result": null}. No config changes. `name` is an existing
    endpoint or matcher name — see pve_notification_endpoint_list for endpoint names."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/notifications/targets/{name}"
    return run_governed(
        "pve_notification_test", tgt,
        plan=lambda: plan_notification_test(name),
        execute=lambda: notification_test_op(api, name),
        confirm=confirm)


@tool()
def pve_metrics_server_list() -> list[dict]:
    """READ-ONLY: list all PVE metrics server definitions.

    No state change. Returns a list of dicts for each configured metrics forwarding target
    (InfluxDB, Graphite, etc.), with id, type, server address, and port. To create or update
    one use pve_metrics_server_set; to remove one use pve_metrics_server_delete."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_metrics_server_list", "cluster/metrics/server",
                    lambda: metrics_server_list(api))


@tool()
def pve_metrics_server_set(
    metrics_id: Annotated[str, Field(description="Unique ID of the metrics server definition to create or update")],
    metrics_type: Annotated[str | None, Field(description="Metrics backend type, e.g. 'influxdb' or 'graphite'")] = None,
    server: Annotated[str | None, Field(description="Hostname or IP address of the metrics server")] = None,
    port: Annotated[int | None, Field(description="TCP/UDP port the metrics server listens on")] = None,
    disable: Annotated[bool | None, Field(description="True disables forwarding to this metrics server without deleting the definition")] = None,
    comment: Annotated[str | None, Field(description="Optional free-text comment stored with the metrics server definition")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the create/update")] = False,
) -> dict:
    """MUTATION: create-or-update a PVE metrics server definition. Dry-run by default
    (returns a PLAN); confirm=True executes and returns {"status": "ok", "result": null} (no further
    payload). Config-only — metrics forwarding adjusts to the new settings immediately; no
    snapshot primitive, so re-apply this same tool to revert. To remove it use
    pve_metrics_server_delete."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/metrics/server/{metrics_id}"
    return run_governed(
        "pve_metrics_server_set", tgt,
        plan=lambda: plan_metrics_server_set(metrics_id, type=metrics_type,
                                                 server=server, port=port,
                                                 disable=disable, comment=comment),
        execute=lambda: metrics_server_set(api, metrics_id, type=metrics_type,
                                              server=server, port=port,
                                              disable=disable, comment=comment),
        confirm=confirm)


@tool()
def pve_metrics_server_delete(
    metrics_id: Annotated[str, Field(description="ID of the metrics server definition to delete")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion")] = False,
) -> dict:
    """MUTATION: delete a PVE metrics server definition. Dry-run by default. confirm=True
    executes and returns {"status": "ok", "result": null} (no further payload). Metrics forwarding to this
    server ceases; no data loss, and config is re-creatable with pve_metrics_server_set."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/metrics/server/{metrics_id}"
    return run_governed(
        "pve_metrics_server_delete", tgt,
        plan=lambda: plan_metrics_server_delete(metrics_id),
        execute=lambda: metrics_server_delete(api, metrics_id),
        confirm=confirm)


# ============================================================================
# Plane F — Hardware PCI/USB Mappings
# ============================================================================

@tool()
def pve_hardware_list(
    node: Annotated[str, Field(description="PVE node name to list physical hardware devices on")],
    hw_type: Annotated[str, Field(description="Device class to list: 'pci' (default) or 'usb'")] = "pci",
) -> dict:
    """READ-ONLY: list physical PCI or USB devices attached to a PVE node
    (hw_type: 'pci' default or 'usb').

    No state change. Returns {"devices": [...]} — the node's raw hardware inventory,
    distinct from the cluster-scope passthrough mappings that VMs actually reference
    (pve_mapping_pci_list / pve_mapping_usb_list)."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_hardware_list", f"nodes/{node}/hardware/{hw_type}",
                    lambda: hardware_list(api, node, hw_type))


@tool()
def pve_mapping_pci_list() -> list[dict]:
    """READ-ONLY: list all PCI device mappings at cluster scope.

    No state change. Returns a list of dicts defining passthrough mappings for PCI devices
    assignable to VMs (PCI mapping is VM-only — LXC has no PCI-passthrough config), each with
    mapping ID, device list, and description. To see the
    raw physical devices on a node use pve_hardware_list; to create a mapping use
    pve_mapping_pci_create."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_mapping_pci_list", "cluster/mapping/pci",
                    lambda: mapping_pci_list(api))


@tool()
def pve_mapping_usb_list() -> list[dict]:
    """READ-ONLY: list all USB device mappings at cluster scope.

    No state change. Returns a list of dicts defining passthrough mappings for USB devices
    assignable to VMs/LXCs, each with mapping ID, device list, and description. To see the
    raw physical devices on a node use pve_hardware_list; to create a mapping use
    pve_mapping_usb_create."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_mapping_usb_list", "cluster/mapping/usb",
                    lambda: mapping_usb_list(api))


@tool()
def pve_mapping_pci_create(
    mapping_id: Annotated[str, Field(description="Unique ID for the new PCI cluster passthrough mapping")],
    description: Annotated[str | None, Field(description="Optional free-text description stored with the mapping")] = None,
    map: Annotated[str | None, Field(description="PCI device map string(s) defining the physical device(s) covered by this mapping")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation")] = False,
) -> dict:
    """MUTATION: create a PCI cluster passthrough mapping. Dry-run by default (returns a
    PLAN); confirm=True executes and returns {"status": "ok", "result": null} (no further payload).
    Additive — MEDIUM risk, since a mismatched IOMMU/VFIO map can prevent VMs from starting.
    To modify an existing mapping use pve_mapping_pci_update; to remove one use
    pve_mapping_pci_delete."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/mapping/pci/{mapping_id}"
    return run_governed(
        "pve_mapping_pci_create", tgt,
        plan=lambda: plan_mapping_pci_create(mapping_id, description=description, map=map),
        execute=lambda: mapping_pci_create(api, mapping_id, description=description, map=map),
        confirm=confirm)


@tool()
def pve_mapping_pci_update(
    mapping_id: Annotated[str, Field(description="ID of the existing PCI cluster mapping to update")],
    description: Annotated[str | None, Field(description="Optional free-text description to set on the mapping")] = None,
    map: Annotated[str | None, Field(description="PCI device map string(s) defining the physical device(s) covered by this mapping")] = None,
    digest: Annotated[str | None, Field(description="Optional config digest for optimistic-concurrency check against the current config")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update")] = False,
) -> dict:
    """MUTATION: update a PCI cluster mapping. Dry-run by default (reads current config into
    the PLAN); confirm=True executes and returns {"status": "ok", "result": null} (no further payload).
    MEDIUM risk — a running VM holding this mapping may need a restart to pick up the new
    device path. No snapshot primitive; re-apply the captured config to revert, or use
    pve_mapping_pci_delete to remove the mapping outright."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/mapping/pci/{mapping_id}"
    return run_governed(
        "pve_mapping_pci_update", tgt,
        plan=lambda: plan_mapping_pci_update(api, mapping_id,
                                                  description=description, map=map, digest=digest),
        execute=lambda: mapping_pci_update(api, mapping_id,
                                               description=description, map=map, digest=digest),
        confirm=confirm)


@tool()
def pve_mapping_pci_delete(
    mapping_id: Annotated[str, Field(description="ID of the PCI cluster mapping to delete")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion")] = False,
) -> dict:
    """MUTATION: delete a PCI cluster mapping. Dry-run by default (captures current config
    into the PLAN); confirm=True executes and returns {"status": "ok", "result": null} (no further payload).
    VMs referencing this mapping lose the device path and may fail to start. No UNDO
    primitive — re-create with pve_mapping_pci_create to restore."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/mapping/pci/{mapping_id}"
    return run_governed(
        "pve_mapping_pci_delete", tgt,
        plan=lambda: plan_mapping_pci_delete(api, mapping_id),
        execute=lambda: mapping_pci_delete(api, mapping_id),
        confirm=confirm)


@tool()
def pve_mapping_usb_create(
    mapping_id: Annotated[str, Field(description="Unique ID for the new USB cluster passthrough mapping")],
    description: Annotated[str | None, Field(description="Optional free-text description stored with the mapping")] = None,
    map: Annotated[str | None, Field(description="USB device map string(s) defining the physical device(s) covered by this mapping")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation")] = False,
) -> dict:
    """MUTATION: create a USB cluster passthrough mapping. Dry-run by default (returns a
    PLAN); confirm=True executes and returns {"status": "ok", "result": null} (no further payload).
    Additive — MEDIUM risk, since a mismatched USB device ID can prevent VMs from acquiring
    the device. To modify an existing mapping use pve_mapping_usb_update; to remove one use
    pve_mapping_usb_delete."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/mapping/usb/{mapping_id}"
    return run_governed(
        "pve_mapping_usb_create", tgt,
        plan=lambda: plan_mapping_usb_create(mapping_id, description=description, map=map),
        execute=lambda: mapping_usb_create(api, mapping_id, description=description, map=map),
        confirm=confirm)


@tool()
def pve_mapping_usb_update(
    mapping_id: Annotated[str, Field(description="ID of the existing USB cluster mapping to update")],
    description: Annotated[str | None, Field(description="Optional free-text description to set on the mapping")] = None,
    map: Annotated[str | None, Field(description="USB device map string(s) defining the physical device(s) covered by this mapping")] = None,
    digest: Annotated[str | None, Field(description="Optional config digest for optimistic-concurrency check against the current config")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update")] = False,
) -> dict:
    """MUTATION: update a USB cluster mapping. Dry-run by default (reads current config into
    the PLAN); confirm=True executes and returns {"status": "ok", "result": null} (no further payload).
    MEDIUM risk — a running VM holding this mapping may lose USB passthrough until
    restarted. No snapshot primitive; re-apply the captured config to revert, or use
    pve_mapping_usb_delete to remove the mapping outright."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/mapping/usb/{mapping_id}"
    return run_governed(
        "pve_mapping_usb_update", tgt,
        plan=lambda: plan_mapping_usb_update(api, mapping_id,
                                                  description=description, map=map, digest=digest),
        execute=lambda: mapping_usb_update(api, mapping_id,
                                               description=description, map=map, digest=digest),
        confirm=confirm)


@tool()
def pve_mapping_usb_delete(
    mapping_id: Annotated[str, Field(description="ID of the USB cluster mapping to delete")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion")] = False,
) -> dict:
    """MUTATION: delete a USB cluster mapping. Dry-run by default (captures current config
    into the PLAN); confirm=True executes and returns {"status": "ok", "result": null} (no further payload).
    VMs referencing this mapping lose the USB device path and may fail to start. No UNDO
    primitive — re-create with pve_mapping_usb_create to restore."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/mapping/usb/{mapping_id}"
    return run_governed(
        "pve_mapping_usb_delete", tgt,
        plan=lambda: plan_mapping_usb_delete(api, mapping_id),
        execute=lambda: mapping_usb_delete(api, mapping_id),
        confirm=confirm)
