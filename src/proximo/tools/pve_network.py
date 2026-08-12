"""PVE network & SDN: interfaces/bridges, SDN zones/vnets/subnets, and apply tools.

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.network import (
    network_apply,
    network_iface_create,
    network_iface_update,
    network_list,
    plan_iface_create,
    plan_iface_update,
    plan_network_apply,
    plan_sdn_apply,
    plan_sdn_lock_acquire,
    plan_sdn_lock_release,
    plan_sdn_rollback,
    plan_sdn_subnet_create,
    plan_sdn_subnet_delete,
    plan_sdn_subnet_update,
    plan_sdn_vnet_create,
    plan_sdn_vnet_delete,
    plan_sdn_vnet_update,
    plan_sdn_zone_create,
    plan_sdn_zone_delete,
    plan_sdn_zone_update,
    sdn_apply,
    sdn_dry_run,
    sdn_lock_acquire,
    sdn_lock_release,
    sdn_rollback,
    sdn_subnet_create,
    sdn_subnet_delete,
    sdn_subnet_get,
    sdn_subnet_list,
    sdn_subnet_update,
    sdn_vnet_create,
    sdn_vnet_delete,
    sdn_vnet_get,
    sdn_vnet_mac_vrf,
    sdn_vnet_update,
    sdn_vnets_list,
    sdn_zone_bridges,
    sdn_zone_content,
    sdn_zone_create,
    sdn_zone_delete,
    sdn_zone_get,
    sdn_zone_ip_vrf,
    sdn_zone_status_list,
    sdn_zone_update,
    sdn_zones_list,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Network & SDN (REST API, read) ---

@tool()
def pve_network_list(
    node: Annotated[str | None, Field(description="Node name to list interfaces on; defaults to the configured node.")] = None,
    iface_type: Annotated[str | None, Field(description="Filter to one interface type: bridge, bond, vlan, eth, or alias.")] = None,
) -> list[dict]:
    """READ-ONLY: list network interfaces (bridges/bonds/VLANs/etc) on a PVE node.

    No state change. Returns a list of dicts with iface name, type (bridge/bond/vlan/eth/alias),
    method, and address; filter by type with iface_type. For SDN zones/vnets use
    pve_sdn_zones_list / pve_sdn_vnets_list instead — that's a separate, cluster-scoped layer."""
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"nodes/{node or cfg.node}/network"
    return _audited("pve_network_list", tgt, lambda: network_list(api, node, iface_type))


@tool()
def pve_sdn_zones_list() -> list[dict]:
    """List SDN zones in the cluster (read-only). Returns zone id, type
    (simple/vlan/qinq/vxlan/evpn/faucet), and state. Use pve_sdn_zone_create to add and
    pve_sdn_apply to commit."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_zones_list", "cluster/sdn/zones", lambda: sdn_zones_list(api))


@tool()
def pve_sdn_vnets_list() -> list[dict]:
    """List SDN vnets in the cluster (read-only). Returns vnet name, zone, tag,
    alias, and vlanaware state. Use pve_sdn_vnet_create to add and pve_sdn_apply
    to commit."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_vnets_list", "cluster/sdn/vnets", lambda: sdn_vnets_list(api))


# --- Network & SDN (REST API, read) — Wave 7a gap-fill + node-status ---

@tool()
def pve_sdn_zone_get(
    zone: Annotated[str, Field(description="Existing SDN zone id to read.")],
    pending: Annotated[bool | None, Field(description="True nests staged-but-unapplied fields under a 'pending' key.")] = None,
    running: Annotated[bool | None, Field(description="True returns the currently-APPLIED config instead of the default staged-merged view.")] = None,
) -> dict:
    """READ-ONLY: read one SDN zone's configuration (closes the pre-Wave-7a gap — only the
    zones LIST existed before). Use pve_sdn_zones_list to enumerate zone ids first."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_zone_get", f"sdn/zones/{zone}",
                    lambda: sdn_zone_get(api, zone, pending, running))


@tool()
def pve_sdn_vnet_get(
    vnet: Annotated[str, Field(description="Existing SDN vnet name to read.")],
    pending: Annotated[bool | None, Field(description="True nests staged-but-unapplied fields under a 'pending' key.")] = None,
    running: Annotated[bool | None, Field(description="True returns the currently-APPLIED config instead of the default staged-merged view.")] = None,
) -> dict:
    """READ-ONLY: read one SDN vnet's configuration (closes the pre-Wave-7a gap — only the
    vnets LIST existed before). Use pve_sdn_vnets_list to enumerate vnet names first."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_vnet_get", f"sdn/vnets/{vnet}",
                    lambda: sdn_vnet_get(api, vnet, pending, running))


@tool()
def pve_sdn_subnet_get(
    vnet: Annotated[str, Field(description="SDN vnet name the subnet belongs to.")],
    subnet: Annotated[str, Field(description="Subnet id (CIDR or PVE-derived id) from pve_sdn_subnet_list to read.")],
    pending: Annotated[bool | None, Field(description="True nests staged-but-unapplied fields under a 'pending' key.")] = None,
    running: Annotated[bool | None, Field(description="True returns the currently-APPLIED config instead of the default staged-merged view.")] = None,
) -> dict:
    """READ-ONLY: read one SDN subnet's configuration (closes the pre-Wave-7a gap — only the
    subnets LIST existed before). Use pve_sdn_subnet_list to enumerate subnet ids first."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_subnet_get", f"sdn/vnets/{vnet}/subnets/{subnet}",
                    lambda: sdn_subnet_get(api, vnet, subnet, pending, running))


@tool()
def pve_sdn_dry_run(
    node: Annotated[str | None, Field(description="Node to render the preview against; defaults to the configured node.")] = None,
) -> dict:
    """READ-ONLY: preview what pve_sdn_apply would change — PVE's own rendered diff between the
    CURRENT and PENDING SDN configuration ({frr-diff?, interfaces-diff?}, either may be absent).

    `node` is required by PVE even though SDN config is cluster-scoped: the rendered result is
    computed per-node from the same staged config, so the diff shown is that node's own view —
    not a cluster-wide guarantee every node agrees."""
    cfg, api, _, _ = _proximo_server._svc()
    n = node or cfg.node
    return _audited("pve_sdn_dry_run", f"sdn/dry-run/{n}", lambda: sdn_dry_run(api, node))


@tool()
def pve_sdn_zone_status_list(
    node: Annotated[str | None, Field(description="Node to read zone apply-status on; defaults to the configured node.")] = None,
) -> list[dict]:
    """READ-ONLY: get the per-zone APPLY status (available/pending/error) on one node —
    node-scoped, distinct from pve_sdn_zones_list (which lists CONFIG, not per-node status)."""
    cfg, api, _, _ = _proximo_server._svc()
    n = node or cfg.node
    return _audited("pve_sdn_zone_status_list", f"nodes/{n}/sdn/zones",
                    lambda: sdn_zone_status_list(api, node))


@tool()
def pve_sdn_zone_bridges(
    zone: Annotated[str, Field(description='SDN zone id, or the reserved pseudo-zone name "localnetwork".')],
    node: Annotated[str | None, Field(description="Node to read bridge membership on; defaults to the configured node.")] = None,
) -> list[dict]:
    """READ-ONLY: list the bridges (vnets) that are part of a zone on one node, with their
    member ports (name, vmid/index for guest-attached ports, VLAN info on VLAN-aware bridges)."""
    cfg, api, _, _ = _proximo_server._svc()
    n = node or cfg.node
    return _audited("pve_sdn_zone_bridges", f"nodes/{n}/sdn/zones/{zone}/bridges",
                    lambda: sdn_zone_bridges(api, zone, node))


@tool()
def pve_sdn_zone_content(
    zone: Annotated[str, Field(description="Existing SDN zone id.")],
    node: Annotated[str | None, Field(description="Node to read zone content on; defaults to the configured node.")] = None,
) -> list[dict]:
    """READ-ONLY: list the vnets inside a zone with their per-vnet apply status on one node
    ({vnet, status?, statusmsg?})."""
    cfg, api, _, _ = _proximo_server._svc()
    n = node or cfg.node
    return _audited("pve_sdn_zone_content", f"nodes/{n}/sdn/zones/{zone}/content",
                    lambda: sdn_zone_content(api, zone, node))


@tool()
def pve_sdn_zone_ip_vrf(
    zone: Annotated[str, Field(description="Name of an EVPN zone.")],
    node: Annotated[str | None, Field(description="Node to read the IP VRF on; defaults to the configured node.")] = None,
) -> list[dict]:
    """READ-ONLY: get the IP VRF routing table of an EVPN zone on one node (CIDR + nexthops +
    protocol per entry). ADVERSARIAL: nexthops are peer-announced over the running routing
    protocol — a compromised BGP/EVPN peer controls these bytes."""
    cfg, api, _, _ = _proximo_server._svc()
    n = node or cfg.node
    return _audited("pve_sdn_zone_ip_vrf", f"nodes/{n}/sdn/zones/{zone}/ip-vrf",
                    lambda: sdn_zone_ip_vrf(api, zone, node))


@tool()
def pve_sdn_vnet_mac_vrf(
    vnet: Annotated[str, Field(description="SDN vnet name in an EVPN zone.")],
    node: Annotated[str | None, Field(description="Node to read the MAC VRF on; defaults to the configured node.")] = None,
) -> list[dict]:
    """READ-ONLY: get the MAC VRF of a VNet in an EVPN zone on one node (ip/mac/nexthop per
    entry). ADVERSARIAL: schema states this "self-originates or has learned via BGP" — a
    genuinely mixed local/wire-learned channel."""
    cfg, api, _, _ = _proximo_server._svc()
    n = node or cfg.node
    return _audited("pve_sdn_vnet_mac_vrf", f"nodes/{n}/sdn/vnets/{vnet}/mac-vrf",
                    lambda: sdn_vnet_mac_vrf(api, vnet, node))


# --- Network & SDN (REST API, MUTATION — confirm-gated) ---

@tool()
def pve_sdn_subnet_list(vnet: Annotated[str, Field(description="SDN vnet name whose subnets to list.")]) -> list[dict]:
    """READ-ONLY: list the subnets configured in a vnet. Returns a list of subnet dicts
    (the exact field set is not guaranteed by this endpoint). Use pve_sdn_subnet_create to
    add one and pve_sdn_apply to commit."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_subnet_list", f"sdn/vnets/{vnet}/subnets",
                    lambda: sdn_subnet_list(api, vnet))


@tool()
def pve_sdn_zone_create(
    zone: Annotated[str, Field(description="New SDN zone id to create.")],
    zone_type: Annotated[str, Field(description="Zone type: simple, vlan, qinq, vxlan, evpn, or faucet.")],
    options: Annotated[dict | None, Field(description="Type-specific zone options (e.g. bridge, mtu, controller).")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: create an SDN zone (PENDING — inert until pve_sdn_apply, NOT applied here).

    `zone_type` is simple/vlan/qinq/vxlan/evpn/faucet; `options` carries type-specific params. To
    update an existing zone use pve_sdn_zone_update; to remove one use pve_sdn_zone_delete. Dry-run
    by default (returns a PLAN); confirm=True creates the pending zone, returning {status, result}.
    RISK_LOW (staging, no live network effect).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/zones/{zone}"
    return run_governed(
        "pve_sdn_zone_create", tgt,
        plan=lambda: plan_sdn_zone_create(zone, zone_type, options),
        execute=lambda: sdn_zone_create(api, zone, zone_type, options, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_zone_update(
    zone: Annotated[str, Field(description="Existing SDN zone id to update.")],
    options: Annotated[dict | None, Field(description="Zone fields to set (type-specific, e.g. bridge, mtu, controller).")] = None,
    delete: Annotated[list[str] | None, Field(description="Zone option keys to unset.")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-concurrency checking.")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: update an SDN zone (PENDING). `options` sets fields; `delete` unsets keys.

    To create a new zone use pve_sdn_zone_create; to remove one use pve_sdn_zone_delete. Dry-run
    by default (returns a PLAN); confirm=True stages the edit and returns {status, result}.
    RISK_LOW (staging; inert until pve_sdn_apply).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/zones/{zone}"
    return run_governed(
        "pve_sdn_zone_update", tgt,
        plan=lambda: plan_sdn_zone_update(zone, options, delete),
        execute=lambda: sdn_zone_update(api, zone, options, delete, digest, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_zone_delete(
    zone: Annotated[str, Field(description="Existing SDN zone id to delete.")],
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: delete an SDN zone (PENDING). Dry-run by default — the PLAN shows the current zone.

    To create a zone instead use pve_sdn_zone_create. PVE refuses if a vnet still references it.
    confirm=True stages the removal and returns {status, result}; no config UNDO — re-create the
    zone to revert. RISK_MEDIUM (staging a removal an apply would enact).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/zones/{zone}"
    return run_governed(
        "pve_sdn_zone_delete", tgt,
        plan=lambda: plan_sdn_zone_delete(api, zone),
        execute=lambda: sdn_zone_delete(api, zone, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_vnet_create(
    vnet: Annotated[str, Field(description="New SDN vnet name to create.")],
    zone: Annotated[str, Field(description="SDN zone id the vnet belongs to.")],
    options: Annotated[dict | None, Field(description="Vnet options such as tag, alias, and vlanaware.")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: create an SDN vnet in a zone (PENDING). `options` carries tag/alias/vlanaware/etc.

    To update an existing vnet use pve_sdn_vnet_update; to remove one use pve_sdn_vnet_delete.
    Dry-run by default (returns a PLAN); confirm=True creates the pending vnet and returns
    {status, result}. RISK_LOW (staging; inert until pve_sdn_apply).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}"
    return run_governed(
        "pve_sdn_vnet_create", tgt,
        plan=lambda: plan_sdn_vnet_create(vnet, zone, options),
        execute=lambda: sdn_vnet_create(api, vnet, zone, options, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_vnet_update(
    vnet: Annotated[str, Field(description="Existing SDN vnet name to update.")],
    options: Annotated[dict | None, Field(description="Vnet fields to set (tag, alias, vlanaware, etc).")] = None,
    delete: Annotated[list[str] | None, Field(description="Vnet option keys to unset.")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-concurrency checking.")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: update an SDN vnet (PENDING — inert until pve_sdn_apply).

    `options` sets fields (tag/alias/vlanaware/etc), `delete` removes keys. To create a vnet use
    pve_sdn_vnet_create; to remove one use pve_sdn_vnet_delete. Dry-run by default (returns a
    PLAN); confirm=True stages the edit and returns {status, result}. RISK_LOW (staging, no live
    network effect)."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}"
    return run_governed(
        "pve_sdn_vnet_update", tgt,
        plan=lambda: plan_sdn_vnet_update(vnet, options, delete),
        execute=lambda: sdn_vnet_update(api, vnet, options, delete, digest, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_vnet_delete(
    vnet: Annotated[str, Field(description="Existing SDN vnet name to delete.")],
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: delete an SDN vnet (PENDING). Dry-run by default — the PLAN shows the current vnet.

    To create a vnet instead use pve_sdn_vnet_create. PVE refuses if a subnet still references it.
    confirm=True stages the removal and returns {status, result}; no config UNDO — re-create the
    vnet to revert. RISK_MEDIUM.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}"
    return run_governed(
        "pve_sdn_vnet_delete", tgt,
        plan=lambda: plan_sdn_vnet_delete(api, vnet),
        execute=lambda: sdn_vnet_delete(api, vnet, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_subnet_create(
    vnet: Annotated[str, Field(description="SDN vnet name the subnet belongs to.")],
    subnet: Annotated[str, Field(description="Subnet CIDR to create, e.g. 10.0.0.0/24.")],
    options: Annotated[dict | None, Field(description="Subnet options such as gateway, snat, and dhcp.")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: create an SDN subnet (PENDING). `subnet` is a CIDR (e.g. 10.0.0.0/24); `options`
    carries gateway/snat/dhcp params.

    To update this subnet use pve_sdn_subnet_update; to remove it use pve_sdn_subnet_delete.
    Dry-run by default (returns a PLAN); confirm=True creates the pending subnet and returns
    {status, result}. RISK_LOW (staging; inert until apply).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}/subnets/{subnet}"
    return run_governed(
        "pve_sdn_subnet_create", tgt,
        plan=lambda: plan_sdn_subnet_create(vnet, subnet, options),
        execute=lambda: sdn_subnet_create(api, vnet, subnet, options, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_subnet_update(
    vnet: Annotated[str, Field(description="SDN vnet name the subnet belongs to.")],
    subnet: Annotated[str, Field(description="Subnet id (CIDR) from pve_sdn_subnet_list to update.")],
    options: Annotated[dict | None, Field(description="Subnet fields to set (gateway, snat, dhcp, etc).")] = None,
    delete: Annotated[list[str] | None, Field(description="Subnet option keys to unset.")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-concurrency checking.")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: update an SDN subnet (PENDING). `subnet` is the id from pve_sdn_subnet_list.

    To create a subnet use pve_sdn_subnet_create; to remove one use pve_sdn_subnet_delete. Dry-run
    by default (returns a PLAN); confirm=True stages the edit and returns {status, result}.
    RISK_LOW (staging).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}/subnets/{subnet}"
    return run_governed(
        "pve_sdn_subnet_update", tgt,
        plan=lambda: plan_sdn_subnet_update(vnet, subnet, options, delete),
        execute=lambda: sdn_subnet_update(api, vnet, subnet, options, delete, digest, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_subnet_delete(
    vnet: Annotated[str, Field(description="SDN vnet name the subnet belongs to.")],
    subnet: Annotated[str, Field(description="Subnet id (CIDR) from pve_sdn_subnet_list to delete.")],
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: delete an SDN subnet (PENDING). `subnet` is the id from pve_sdn_subnet_list.

    To create a subnet instead use pve_sdn_subnet_create. Dry-run by default (returns a PLAN);
    confirm=True stages the removal and returns {status, result}; no config UNDO — re-create the
    subnet to revert. RISK_MEDIUM (staging a removal an apply would enact).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}/subnets/{subnet}"
    return run_governed(
        "pve_sdn_subnet_delete", tgt,
        plan=lambda: plan_sdn_subnet_delete(vnet, subnet),
        execute=lambda: sdn_subnet_delete(api, vnet, subnet, lock_token),
        confirm=confirm)


@tool()
def pve_network_iface_create(
    iface: Annotated[str, Field(description="New interface name to create, e.g. vmbr1 or eth0.100.")],
    iface_type: Annotated[str, Field(description="Interface type: bridge, bond, vlan, eth, or alias.")],
    node: Annotated[str | None, Field(description="Node to create the interface on; defaults to the configured node.")] = None,
    options: Annotated[dict | None, Field(description="Type-dependent fields: address, netmask, gateway, bridge_ports, etc.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True stages the interface (still not live until pve_network_apply).")] = False,
) -> dict:
    """MUTATION: create a new network interface config (staged — not live until pve_network_apply).

    `options` carries type-dependent fields (address, netmask, gateway, bridge_ports, …). To
    update an existing interface instead use pve_network_iface_update. Dry-run by default (returns
    a PLAN); confirm=True stages the interface, synchronously, and returns {status, result} —
    result is often None. RISK_MEDIUM (staged change, reversible before apply).
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"nodes/{node or cfg.node}/network/{iface}"
    return run_governed(
        "pve_network_iface_create", tgt,
        plan=lambda: plan_iface_create(api, iface, iface_type, node, options or {}),
        execute=lambda: network_iface_create(api, iface, iface_type, node, **(options or {})),
        confirm=confirm)


@tool()
def pve_network_iface_update(
    iface: Annotated[str, Field(description="Existing interface name to update, e.g. vmbr1 or eth0.100.")],
    node: Annotated[str | None, Field(description="Node the interface lives on; defaults to the configured node.")] = None,
    options: Annotated[dict | None, Field(description="Fields to update: address, netmask, bridge_ports, etc.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True stages the update (still not live until pve_network_apply).")] = False,
) -> dict:
    """MUTATION: update an existing network interface config (staged — not live until pve_network_apply).

    `options` carries fields to update (address, netmask, bridge_ports, …); the interface's type
    is preserved automatically and cannot be changed here — recreate via pve_network_iface_create
    for a type change. Dry-run by default (returns a PLAN); confirm=True stages the update and
    returns {status, result} — result is often None. RISK_MEDIUM (staged change, reversible before apply).
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"nodes/{node or cfg.node}/network/{iface}"
    return run_governed(
        "pve_network_iface_update", tgt,
        plan=lambda: plan_iface_update(api, iface, node, options or {}),
        execute=lambda: network_iface_update(api, iface, node, **(options or {})),
        confirm=confirm)


@tool()
def pve_network_apply(
    node: Annotated[str | None, Field(description="Node to apply staged network config on; defaults to the configured node.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True applies the staged config to the live network stack.")] = False,
) -> dict:
    """MUTATION (HIGH RISK): apply staged network config changes to the live network stack.

    Stage changes first with pve_network_iface_create / pve_network_iface_update — this applies
    whatever is currently staged; for SDN changes use pve_sdn_apply instead (a separate,
    cluster-scoped commit). Dry-run by default — the PLAN surfaces pending interfaces. confirm=True
    executes with no automatic undo; a misconfigured interface can lose SSH/API access, requiring
    console/physical access to recover. May return a UPID (async) or None (sync) — outcome='submitted'
    in either case.
    """
    cfg, api, _, _ = _proximo_server._svc()
    tgt = f"nodes/{node or cfg.node}/network"
    return run_governed(
        "pve_network_apply", tgt,
        plan=lambda: plan_network_apply(api, node),
        execute=lambda: network_apply(api, node),
        confirm=confirm, outcome="submitted")


@tool()
def pve_sdn_apply(
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held (from pve_sdn_lock_acquire).")] = None,
    release_lock: Annotated[bool | None, Field(description="Whether PVE releases the lock automatically after a successful commit (only relevant when lock_token is given; PVE's own default is True — omit to use it).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True applies pending SDN config cluster-wide.")] = False,
) -> dict:
    """MUTATION (HIGH RISK): apply pending SDN config changes (cluster-scoped).

    Stage zones/vnets/subnets first with pve_sdn_zone_create / pve_sdn_vnet_create /
    pve_sdn_subnet_create — this applies whatever is pending; for interface/bridge changes use
    pve_network_apply instead. Dry-run by default — the PLAN surfaces pending zones/vnets AND
    cites pve_sdn_dry_run's rendered diff (fail-open — an unreachable dry-run degrades to an
    honest note, never blocks this plan). confirm=True executes with no automatic undo (short of
    pve_sdn_rollback, which discards PENDING changes only — it cannot revert an already-applied,
    now-LIVE config), disrupting virtual networking for ALL guests cluster-wide if misconfigured.
    May return a UPID (async) or None (sync) — outcome='submitted' in either case.

    Wave 7a extension: pass lock_token/release_lock if you already hold a lock from
    pve_sdn_lock_acquire. Both omitted: byte-for-byte the same call as before this extension.
    lock_token is never written to the audit ledger (see network.py module docstring).
    """
    _, api, _, _ = _proximo_server._svc()
    return run_governed(
        "pve_sdn_apply", "cluster/sdn",
        plan=lambda: plan_sdn_apply(api),
        execute=lambda: sdn_apply(api, lock_token, release_lock),
        confirm=confirm, outcome="submitted")


@tool()
def pve_sdn_lock_acquire(
    allow_pending: Annotated[bool | None, Field(description="True bypasses PVE's own default refusal to lock over already-dirty pending state. Never default this on.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True acquires the lock.")] = False,
) -> dict:
    """MUTATION: acquire the global SDN configuration lock (RISK_MEDIUM).

    Blocks every OTHER legitimate SDN writer cluster-wide until released via
    pve_sdn_lock_release (or automatically by pve_sdn_apply/pve_sdn_rollback's own release_lock
    param) — a self-inflicted-DoS risk if you forget to release. Dry-run by default (returns a
    PLAN — there is no read-only way to check if the lock is already held, so the plan is a pure
    preview, not a live check). confirm=True acquires the lock and returns
    {"status": "ok", "result": "<lock token>"}.

    SECRET HANDLING: the token is a capability handle, not a password — it is returned ONCE in
    `result` and is NEVER written to the audit ledger (mirrors pve_token_create's own secret
    handling). Pass it as lock_token to subsequent SDN mutations, and to pve_sdn_lock_release /
    pve_sdn_apply / pve_sdn_rollback to release it. If the token is lost (session death, forgotten
    release), the only recovery is pve_sdn_lock_release(force=True) — HIGH risk, since it releases
    without proof of ownership.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = "cluster/sdn/lock"
    # SECRET HANDLING (mirrors pve_token_create): detail must NEVER contain the returned token —
    # only {"confirmed": True, "allow_pending": ...}. The token flows to the caller via `result`.
    return run_governed(
        "pve_sdn_lock_acquire", tgt,
        plan=lambda: plan_sdn_lock_acquire(allow_pending),
        execute=lambda: sdn_lock_acquire(api, allow_pending),
        confirm=confirm, detail={"allow_pending": allow_pending})


@tool()
def pve_sdn_lock_release(
    lock_token: Annotated[str | None, Field(description="Lock token from pve_sdn_lock_acquire to release your own held lock.")] = None,
    force: Annotated[bool | None, Field(description="True releases WITHOUT the token — can break a DIFFERENT caller's in-flight operation. Never default this on.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True releases the lock.")] = False,
) -> dict:
    """MUTATION: release the global SDN configuration lock. Risk is CONDITIONAL on `force`: LOW
    when releasing with your own token, HIGH when force=True (can break a different caller's
    in-flight operation). Dry-run by default (returns a PLAN); confirm=True releases and returns
    {"status": "ok", "result": None}. lock_token is never written to the audit ledger.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = "cluster/sdn/lock"
    return run_governed(
        "pve_sdn_lock_release", tgt,
        plan=lambda: plan_sdn_lock_release(lock_token, force),
        execute=lambda: sdn_lock_release(api, lock_token, force),
        confirm=confirm, detail={"force": force})


@tool()
def pve_sdn_rollback(
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    release_lock: Annotated[bool | None, Field(description="Whether PVE releases the lock automatically after a successful rollback (only relevant when lock_token is given; PVE's own default is True — omit to use it).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True discards all pending SDN config cluster-wide.")] = False,
) -> dict:
    """MUTATION: discard ALL pending SDN configuration changes cluster-wide — the plane's REAL
    undo primitive (RISK_MEDIUM).

    Bounded to the CONFIG plane only: never touches LIVE networking (that's pve_sdn_apply's job)
    — discards every staged zone/vnet/subnet/controller/dns/ipam/fabric/prefix-list/route-map edit
    at once, reverting to the applied state. NOTE: SDN config renders per-node; if a prior
    pve_sdn_apply failed or was interrupted partway, the state this reverts to may reflect
    cross-node inconsistency from that failed apply. Dry-run by default — the PLAN surfaces
    currently-pending zones/vnets AND cites pve_sdn_dry_run's rendered diff (fail-open) as evidence
    of what would be discarded. confirm=True executes and returns {"status": "ok", "result": None}.
    No undo of its own — once rolled back, the discarded pending edits are gone (re-author them
    from scratch). lock_token is never written to the audit ledger (see network.py module docstring).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = "cluster/sdn/rollback"
    return run_governed(
        "pve_sdn_rollback", tgt,
        plan=lambda: plan_sdn_rollback(api),
        execute=lambda: sdn_rollback(api, lock_token, release_lock),
        confirm=confirm)
