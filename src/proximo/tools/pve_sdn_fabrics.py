"""PVE SDN FABRICS: config CRUD (fabric container + fabric-node sub-family) + node-scoped
fabric STATUS reads (interfaces/neighbors/routes) — the FINAL chunk of Wave 7.

New module (Wave 7d, full-surface campaign) — see proximo/sdn_fabrics.py's module docstring
for the schema facts (the 3 confirmed upstream copy-paste description bugs, the
fabrics-index redundancy, the interfaces/neighbors/routes taint split — including a
documented divergence from this chunk's own dispatch-prompt summary — the digest/lock-token
asymmetries, and the `protocol`-required-on-update fact) and the mutation funnel these
wrappers depend on (proximo/server.py's module docstring).
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.sdn_fabrics import (
    fabric_create,
    fabric_delete,
    fabric_get,
    fabric_node_create,
    fabric_node_delete,
    fabric_node_get,
    fabric_node_update,
    fabric_nodes_list,
    fabric_nodes_list_all,
    fabric_status_interfaces,
    fabric_status_neighbors,
    fabric_status_routes,
    fabric_update,
    fabrics_all,
    fabrics_list,
    plan_fabric_create,
    plan_fabric_delete,
    plan_fabric_node_create,
    plan_fabric_node_delete,
    plan_fabric_node_update,
    plan_fabric_update,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- fabrics (REST API, read) ---

@tool()
def pve_sdn_fabrics_all(
    pending: Annotated[bool | None, Field(description="Display pending (staged, not-yet-applied) config.")] = None,
    running: Annotated[bool | None, Field(description="Display the currently-APPLIED (running) config instead.")] = None,
) -> dict:
    """READ-ONLY: AGGREGATE read — every SDN fabric's config AND every node across every
    fabric, in ONE call ({fabrics: [...], nodes: [...]}). 100% reconstructable from
    pve_sdn_fabrics_list + pve_sdn_fabric_nodes_list_all (2 calls) — built anyway for the
    cheap N+1-avoidance value."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_fabrics_all", "sdn/fabrics/all",
                    lambda: fabrics_all(api, pending, running))


@tool()
def pve_sdn_fabrics_list(
    pending: Annotated[bool | None, Field(description="Display pending (staged, not-yet-applied) config.")] = None,
    running: Annotated[bool | None, Field(description="Display the currently-APPLIED (running) config instead.")] = None,
) -> list[dict]:
    """READ-ONLY: list SDN fabrics (cluster-scoped, full objects). Use pve_sdn_fabric_create
    to add and pve_sdn_apply to commit."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_fabrics_list", "sdn/fabrics/fabric",
                    lambda: fabrics_list(api, pending, running))


@tool()
def pve_sdn_fabric_get(
    fabric: Annotated[str, Field(description="Existing SDN fabric id to read.")],
) -> dict:
    """READ-ONLY: read one SDN fabric's configuration. Upstream's own description for this
    endpoint says "Update a fabric" — a confirmed copy-paste bug; this is a plain read. No
    pending/running filter on this single-object endpoint (schema-verified absence, unlike
    the list tool above)."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_fabric_get", f"sdn/fabrics/fabric/{fabric}",
                    lambda: fabric_get(api, fabric))


# --- fabrics (REST API, MUTATION — confirm-gated) ---

@tool()
def pve_sdn_fabric_create(
    fabric: Annotated[str, Field(description="New SDN fabric id to create (2-8 chars, alnum + hyphen).")],
    protocol: Annotated[str, Field(description="Fabric routing protocol: openfabric, ospf, wireguard, or bgp.")],
    options: Annotated[dict | None, Field(description="Protocol-conditional fields (area, csnp_interval, hello_interval, ip_prefix, ip6_prefix, persistent_keepalive, redistribute, route_filter); PVE validates per protocol server-side. redistribute is schema-required for every protocol but only meaningful for ospf/bgp — omitting it for openfabric/wireguard is UNTESTED, Smoke-confirm.")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-concurrency checking — accepted on CREATE for this endpoint (one of three exceptions on this SDN plane to the 'digest never on create' convention).")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: create an SDN fabric (PENDING — inert until pve_sdn_apply).

    To update an existing fabric use pve_sdn_fabric_update; to remove one use
    pve_sdn_fabric_delete. Dry-run by default (returns a PLAN); confirm=True creates the
    pending fabric, returning {status, result}. RISK_LOW (staging, no live network effect).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/fabrics/fabric/{fabric}"
    return run_governed(
        "pve_sdn_fabric_create", tgt,
        plan=lambda: plan_fabric_create(fabric, protocol, options),
        execute=lambda: fabric_create(api, fabric, protocol, options, digest, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_fabric_update(
    fabric: Annotated[str, Field(description="Existing SDN fabric id to update.")],
    protocol: Annotated[str, Field(description="Fabric routing protocol — REQUIRED on update too (the schema requires restating it; unlike controller/dns/ipam, where type is immutable and absent from PUT). Whether passing a DIFFERENT protocol than the fabric's current one re-types it or is rejected is undocumented — forwarded verbatim.")],
    options: Annotated[dict | None, Field(description="Protocol-conditional fields to set (area, csnp_interval, hello_interval, ip_prefix, ip6_prefix, persistent_keepalive, redistribute, route_filter).")] = None,
    delete: Annotated[list[str] | None, Field(description="Field name(s) to unset — the valid enum is protocol-conditional (e.g. ip_prefix/ip6_prefix/hello_interval/csnp_interval/route_filter for openfabric; area/redistribute/route_filter for ospf; ip_prefix/ip6_prefix/redistribute/route_filter/route_map_in/route_map_out for bgp; persistent_keepalive for wireguard).")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-concurrency checking.")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: update an SDN fabric (PENDING). To create a new fabric use
    pve_sdn_fabric_create; to remove one use pve_sdn_fabric_delete. Dry-run by default
    (returns a PLAN); confirm=True stages the edit and returns {status, result}. RISK_LOW
    (staging; inert until pve_sdn_apply).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/fabrics/fabric/{fabric}"
    return run_governed(
        "pve_sdn_fabric_update", tgt,
        plan=lambda: plan_fabric_update(fabric, protocol, options, delete),
        execute=lambda: fabric_update(api, fabric, protocol, options, delete, digest, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_fabric_delete(
    fabric: Annotated[str, Field(description="Existing SDN fabric id to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: delete an SDN fabric (PENDING). Upstream's own description for this endpoint
    says "Add a fabric" — a confirmed copy-paste bug; this deletes. NO digest and NO
    lock_token parameter exists for this endpoint at all (schema-verified — unlike every
    other delete on this SDN plane).

    Referential-integrity refusal (e.g. an EVPN zone's own 'fabric' field still naming this
    fabric) is asserted BY ANALOGY to the zone/vnet precedent, not independently confirmed
    against this endpoint's own schema — Smoke-confirm. confirm=True stages the removal and
    returns {status, result}; no config UNDO — re-create the fabric to revert. RISK_MEDIUM
    (staging a removal an apply would enact).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/fabrics/fabric/{fabric}"
    return run_governed(
        "pve_sdn_fabric_delete", tgt,
        plan=lambda: plan_fabric_delete(api, fabric),
        execute=lambda: fabric_delete(api, fabric),
        confirm=confirm)


# --- fabric nodes (REST API, read) ---

@tool()
def pve_sdn_fabric_nodes_list_all(
    pending: Annotated[bool | None, Field(description="Display pending (staged, not-yet-applied) config.")] = None,
    running: Annotated[bool | None, Field(description="Display the currently-APPLIED (running) config instead.")] = None,
) -> list[dict]:
    """READ-ONLY: list EVERY fabric node across EVERY fabric in one call — NOT scoped to one
    fabric. Use pve_sdn_fabric_nodes_list to scope to one fabric_id."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_fabric_nodes_list_all", "sdn/fabrics/node",
                    lambda: fabric_nodes_list_all(api, pending, running))


@tool()
def pve_sdn_fabric_nodes_list(
    fabric_id: Annotated[str, Field(description="Existing SDN fabric id whose nodes to list.")],
    pending: Annotated[bool | None, Field(description="Display pending (staged, not-yet-applied) config.")] = None,
    running: Annotated[bool | None, Field(description="Display the currently-APPLIED (running) config instead.")] = None,
) -> list[dict]:
    """READ-ONLY: list the nodes belonging to ONE SDN fabric."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_fabric_nodes_list", f"sdn/fabrics/node/{fabric_id}",
                    lambda: fabric_nodes_list(api, fabric_id, pending, running))


@tool()
def pve_sdn_fabric_node_get(
    fabric_id: Annotated[str, Field(description="Existing SDN fabric id.")],
    node_id: Annotated[str, Field(description="Existing fabric node id (a PVE cluster node hostname) to read.")],
) -> dict:
    """READ-ONLY: read a single fabric node's configuration. No pending/running filter on
    this single-object endpoint (schema-verified absence, unlike the list tools above)."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_fabric_node_get", f"sdn/fabrics/node/{fabric_id}/{node_id}",
                    lambda: fabric_node_get(api, fabric_id, node_id))


# --- fabric nodes (REST API, MUTATION — confirm-gated) ---

@tool()
def pve_sdn_fabric_node_create(
    fabric_id: Annotated[str, Field(description="Existing SDN fabric id to add this node to.")],
    node_id: Annotated[str, Field(description="Fabric node id to create (a PVE cluster node hostname).")],
    protocol: Annotated[str, Field(description="Fabric routing protocol: openfabric, ospf, wireguard, or bgp — must match the fabric's own configured protocol.")],
    options: Annotated[dict | None, Field(description="Protocol-conditional fields (interfaces, ip, ip6, peers, allowed_ips, endpoint, public_key, role); PVE validates per protocol server-side.")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-concurrency checking — accepted on CREATE for this endpoint (one of three exceptions on this SDN plane to the 'digest never on create' convention).")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: add a node to an SDN fabric (PENDING — inert until pve_sdn_apply).

    To update an existing node use pve_sdn_fabric_node_update; to remove one use
    pve_sdn_fabric_node_delete. Dry-run by default (returns a PLAN); confirm=True creates the
    pending node, returning {status, result}. RISK_LOW (staging, no live network effect).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/fabrics/node/{fabric_id}/{node_id}"
    return run_governed(
        "pve_sdn_fabric_node_create", tgt,
        plan=lambda: plan_fabric_node_create(fabric_id, node_id, protocol, options),
        execute=lambda: fabric_node_create(api, fabric_id, node_id, protocol, options,
                                               digest, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_fabric_node_update(
    fabric_id: Annotated[str, Field(description="Existing SDN fabric id.")],
    node_id: Annotated[str, Field(description="Existing fabric node id to update.")],
    protocol: Annotated[str, Field(description="Fabric routing protocol — REQUIRED on update too (the schema requires restating it). Whether passing a DIFFERENT protocol re-types the node or is rejected is undocumented — forwarded verbatim.")],
    options: Annotated[dict | None, Field(description="Protocol-conditional fields to set (interfaces, ip, ip6, peers, allowed_ips, endpoint, public_key, role).")] = None,
    delete: Annotated[list[str] | None, Field(description="Field name(s) to unset — the valid enum is protocol-conditional (interfaces/ip/ip6 for bgp/openfabric/ospf; allowed_ips/endpoint/interfaces/ip/ip6/peers for wireguard).")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-concurrency checking.")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: update a fabric node (PENDING). To create a new node use
    pve_sdn_fabric_node_create; to remove one use pve_sdn_fabric_node_delete. Dry-run by
    default (returns a PLAN); confirm=True stages the edit and returns {status, result}.
    RISK_LOW (staging; inert until pve_sdn_apply).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/fabrics/node/{fabric_id}/{node_id}"
    return run_governed(
        "pve_sdn_fabric_node_update", tgt,
        plan=lambda: plan_fabric_node_update(fabric_id, node_id, protocol, options, delete),
        execute=lambda: fabric_node_update(api, fabric_id, node_id, protocol, options,
                                               delete, digest, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_fabric_node_delete(
    fabric_id: Annotated[str, Field(description="Existing SDN fabric id.")],
    node_id: Annotated[str, Field(description="Existing fabric node id to remove.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: remove a node from an SDN fabric (PENDING). Upstream's own description for
    this endpoint says "Add a node" — a confirmed copy-paste bug; this deletes. NO digest and
    NO lock_token parameter exists for this endpoint at all (schema-verified).

    Referential-integrity refusal is asserted BY ANALOGY only — Smoke-confirm. confirm=True
    stages the removal and returns {status, result}; no config UNDO — re-create the node to
    revert. RISK_MEDIUM (staging a removal an apply would enact).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/fabrics/node/{fabric_id}/{node_id}"
    return run_governed(
        "pve_sdn_fabric_node_delete", tgt,
        plan=lambda: plan_fabric_node_delete(api, fabric_id, node_id),
        execute=lambda: fabric_node_delete(api, fabric_id, node_id),
        confirm=confirm)


# --- node-scoped fabric status (REST API, read) ---

@tool()
def pve_sdn_fabric_status_interfaces(
    fabric: Annotated[str, Field(description="Existing SDN fabric id.")],
    node: Annotated[str | None, Field(description="Cluster node to query. Omit to use Proximo's configured default node.")] = None,
) -> list[dict]:
    """READ-ONLY: get all interfaces for a fabric on one node (name/state/type — the fabric's
    OWN locally-rendered network interfaces, not peer-controlled)."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_fabric_status_interfaces", f"sdn/fabrics/{fabric}/interfaces",
                    lambda: fabric_status_interfaces(api, fabric, node))


@tool()
def pve_sdn_fabric_status_neighbors(
    fabric: Annotated[str, Field(description="Existing SDN fabric id.")],
    node: Annotated[str | None, Field(description="Cluster node to query. Omit to use Proximo's configured default node.")] = None,
) -> list[dict]:
    """READ-ONLY: get all neighbors for a fabric on one node — neighbor/status/uptime, all
    self-announced by the remote peer as reported by FRR. Wire-learned content: a
    compromised/malicious peer controls these bytes."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_fabric_status_neighbors", f"sdn/fabrics/{fabric}/neighbors",
                    lambda: fabric_status_neighbors(api, fabric, node))


@tool()
def pve_sdn_fabric_status_routes(
    fabric: Annotated[str, Field(description="Existing SDN fabric id.")],
    node: Annotated[str | None, Field(description="Cluster node to query. Omit to use Proximo's configured default node.")] = None,
) -> list[dict]:
    """READ-ONLY: get all routes for a fabric on one node — route (CIDR) + via (nexthop
    list). The nexthops are wire-learned content: injected by whatever peer announces them
    over the running routing protocol."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_fabric_status_routes", f"sdn/fabrics/{fabric}/routes",
                    lambda: fabric_status_routes(api, fabric, node))
