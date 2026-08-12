"""PVE SDN vnet-scoped FIREWALL + IP MAPPINGS: rules/options (read+mutation, LIVE/IMMEDIATE)
and IP-to-MAC address mappings (read+mutation).

New module (Wave 7b, full-surface campaign) — see proximo/sdn_firewall.py's module
docstring for the LIVE/IMMEDIATE framing (NOT the staged-pending zone/vnet/subnet model on
the sibling proximo/network.py / proximo/tools/pve_network.py) and the mutation funnel
these wrappers depend on (proximo/server.py's module docstring).
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.sdn_firewall import (
    plan_vnet_firewall_options_set,
    plan_vnet_firewall_rule_add,
    plan_vnet_firewall_rule_remove,
    plan_vnet_firewall_rule_update,
    plan_vnet_ip_create,
    plan_vnet_ip_delete,
    plan_vnet_ip_update,
    vnet_firewall_options_get,
    vnet_firewall_options_set,
    vnet_firewall_rule_add,
    vnet_firewall_rule_get,
    vnet_firewall_rule_remove,
    vnet_firewall_rule_update,
    vnet_firewall_rules_list,
    vnet_ip_create,
    vnet_ip_delete,
    vnet_ip_update,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- vnet firewall (REST API, read) ---

@tool()
def pve_sdn_vnet_firewall_options_get(
    vnet: Annotated[str, Field(description="SDN vnet name.")],
) -> dict:
    """READ-ONLY: get vnet firewall options (enable, log_level_forward, policy_forward).

    LIVE/IMMEDIATE family — unlike the sibling zone/vnet/subnet SDN objects, vnet firewall
    state has NO pending/apply lifecycle: what pve_sdn_vnet_firewall_options_set writes here
    takes effect on live guest traffic immediately, not after pve_sdn_apply. `enable`
    defaults to 0 (schema-declared) if never set. Use pve_sdn_vnet_firewall_options_set to
    change these.
    """
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_vnet_firewall_options_get", f"sdn/vnets/{vnet}/firewall/options",
                    lambda: vnet_firewall_options_get(api, vnet))


@tool()
def pve_sdn_vnet_firewall_rules_list(
    vnet: Annotated[str, Field(description="SDN vnet name.")],
) -> list[dict]:
    """READ-ONLY: list vnet firewall rules, in ruleset order (position 0 first).

    LIVE/IMMEDIATE family (see pve_sdn_vnet_firewall_options_get). Use
    pve_sdn_vnet_firewall_rule_get to read one rule by position.
    """
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_vnet_firewall_rules_list", f"sdn/vnets/{vnet}/firewall/rules",
                    lambda: vnet_firewall_rules_list(api, vnet))


@tool()
def pve_sdn_vnet_firewall_rule_get(
    vnet: Annotated[str, Field(description="SDN vnet name.")],
    pos: Annotated[int, Field(description="Rule position (0-based index) in this vnet's rule list.")],
) -> dict:
    """READ-ONLY: get one vnet firewall rule by position.

    LIVE/IMMEDIATE family. Positions SHIFT after inserts/deletes — use
    pve_sdn_vnet_firewall_rules_list to find the current position before editing/removing.
    """
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_vnet_firewall_rule_get", f"sdn/vnets/{vnet}/firewall/rules/{pos}",
                    lambda: vnet_firewall_rule_get(api, vnet, pos))


# --- vnet firewall (REST API, MUTATION — confirm-gated; LIVE/IMMEDIATE) ---

@tool()
def pve_sdn_vnet_firewall_options_set(
    vnet: Annotated[str, Field(description="SDN vnet name.")],
    options: Annotated[dict | None, Field(description="Key-value bag of options to set: enable (bool), log_level_forward, policy_forward (ACCEPT/DROP).")] = None,
    delete: Annotated[list[str] | None, Field(description="List of option keys to unset.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock digest forwarded to PVE to abort if the options changed since a prior read.")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION (LIVE/IMMEDIATE): set vnet firewall options. Dry-run by default — the PLAN
    shows current values and a DIRECTION-AWARE blast-radius warning. RISK_HIGH when enable or
    policy_forward changes, else MEDIUM. Synchronous — confirm=True returns
    {"status": "ok", "result": None}; no task UPID to poll.

    The HIGH-risk warning is derived from the actual values being set: tightening (enable=
    True, policy_forward=DROP) warns this can immediately CUT forwarded traffic; loosening
    (enable=False, delete=["enable"], policy_forward=ACCEPT) warns this immediately REMOVES
    firewall protection instead — the two are never conflated. An unrecognized/conflicting
    combination gets a combined warning covering both directions rather than guessing.

    UNLIKE the staged zone/vnet/subnet SDN objects, this takes effect on live guest traffic
    THE INSTANT you confirm — there is no pve_sdn_apply gate and no pve_sdn_rollback
    coverage for this family. Requires at least one of options/delete. No UNDO — revert by
    setting the prior values back.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}/firewall/options"
    return run_governed(
        "pve_sdn_vnet_firewall_options_set", tgt,
        plan=lambda: plan_vnet_firewall_options_set(api, vnet, options, delete),
        execute=lambda: vnet_firewall_options_set(api, vnet, options, delete, digest),
        confirm=confirm)


@tool()
def pve_sdn_vnet_firewall_rule_add(
    vnet: Annotated[str, Field(description="SDN vnet name.")],
    action: Annotated[str, Field(description="Rule action: 'ACCEPT', 'DROP', or 'REJECT'.")],
    fw_type: Annotated[str, Field(description="Rule type: 'in', 'out', 'forward', or 'group' (richer than the guest/cluster/node firewall's in/out-only direction).")] = "in",
    source: Annotated[str | None, Field(description="Source address/CIDR/alias to match, or None for any.")] = None,
    dest: Annotated[str | None, Field(description="Destination address/CIDR/alias to match, or None for any.")] = None,
    proto: Annotated[str | None, Field(description="IP protocol to match, e.g. 'tcp', 'udp', 'icmp'.")] = None,
    dport: Annotated[str | None, Field(description="Destination port or port range to match, e.g. '22' or '8000:8010'.")] = None,
    sport: Annotated[str | None, Field(description="Source port or port range to match.")] = None,
    icmp_type: Annotated[str | None, Field(description="ICMP type, only valid when proto is icmp/icmpv6/ipv6-icmp.")] = None,
    iface: Annotated[str | None, Field(description="Network interface name to match.")] = None,
    log: Annotated[str | None, Field(description="Log level for this rule, e.g. 'info', 'nolog'.")] = None,
    macro: Annotated[str | None, Field(description="Predefined standard macro name.")] = None,
    comment: Annotated[str | None, Field(description="Free-text comment stored with the rule.")] = None,
    enable: Annotated[bool | None, Field(description="Whether the rule is active immediately; omit to use PVE's own default (enabled).")] = None,
    pos: Annotated[int | None, Field(description="Position to insert at — Smoke-confirm: this endpoint's schema declares 'pos' on CREATE with description text copy-pasted from its PUT sibling; actual create-time effect (insert-at-pos vs. append vs. ignored) is unconfirmed.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock digest — schema-declared on this endpoint's CREATE (a platform inconsistency vs. the shipped guest/cluster/node rule_add, which accepts none); forwarded when given.")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION (LIVE/IMMEDIATE): add a new vnet firewall rule. Dry-run by default — the PLAN
    shows vnet, type, action, and key address/port fields. RISK_MEDIUM floor (absence of
    HIGH is NOT a safety signal). Synchronous — confirm=True returns
    {"status": "ok", "result": None}; no task UPID to poll.

    UNLIKE the shipped guest/cluster/node pve_firewall_rule_add (always inserts at position
    0), this takes effect on live guest traffic THE INSTANT you confirm — no pve_sdn_apply
    gate, no pve_sdn_rollback coverage. A misplaced DROP/REJECT can sever traffic for every
    guest on this vnet immediately. No UNDO — revert by removing it with
    pve_sdn_vnet_firewall_rule_remove.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}/firewall/rules"
    return run_governed(
        "pve_sdn_vnet_firewall_rule_add", tgt,
        plan=lambda: plan_vnet_firewall_rule_add(vnet, action, fw_type, source, dest, dport,
                                                     proto, iface, pos),
        execute=lambda: vnet_firewall_rule_add(api, vnet, action, fw_type, source, dest,
                                                   proto, dport, sport, icmp_type, iface, log,
                                                   macro, comment, enable, pos, digest),
        confirm=confirm)


@tool()
def pve_sdn_vnet_firewall_rule_update(
    vnet: Annotated[str, Field(description="SDN vnet name.")],
    pos: Annotated[int, Field(description="Rule position (0-based index) to update.")],
    action: Annotated[str | None, Field(description="New rule action; omit to leave unchanged.")] = None,
    fw_type: Annotated[str | None, Field(description="New rule type: in/out/forward/group; omit to leave unchanged.")] = None,
    source: Annotated[str | None, Field(description="New source address/CIDR/alias; omit to leave unchanged.")] = None,
    dest: Annotated[str | None, Field(description="New destination address/CIDR/alias; omit to leave unchanged.")] = None,
    proto: Annotated[str | None, Field(description="New IP protocol; omit to leave unchanged.")] = None,
    dport: Annotated[str | None, Field(description="New destination port/range; omit to leave unchanged.")] = None,
    sport: Annotated[str | None, Field(description="New source port/range; omit to leave unchanged.")] = None,
    icmp_type: Annotated[str | None, Field(description="New ICMP type; omit to leave unchanged.")] = None,
    iface: Annotated[str | None, Field(description="New interface name; omit to leave unchanged.")] = None,
    log: Annotated[str | None, Field(description="New log level; omit to leave unchanged.")] = None,
    macro: Annotated[str | None, Field(description="New macro name; omit to leave unchanged.")] = None,
    comment: Annotated[str | None, Field(description="New free-text comment; omit to leave unchanged.")] = None,
    enable: Annotated[bool | None, Field(description="New enabled state; omit to leave unchanged.")] = None,
    moveto: Annotated[int | None, Field(description="Move the rule to this new position instead — PVE IGNORES every other argument in this same call when moveto is given (schema-documented). Do the move and the field edit in two separate calls if you need both.")] = None,
    digest: Annotated[str | None, Field(description="OPTIONAL optimistic-lock passthrough, forwarded verbatim when given. NEVER required, NEVER derived: this endpoint's reads (rules list / rule get) expose no digest field on this schema at all (schema-verified), so the PLAN cannot supply one — pass a digest only if you obtained one out-of-band.")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION (LIVE/IMMEDIATE): update a vnet firewall rule at position `pos`. Dry-run by
    default — the PLAN shows the rule's current state and the fields changing. RISK_MEDIUM
    floor. Synchronous — confirm=True returns {"status": "ok", "result": None}; no task UPID
    to poll.

    Takes effect on live guest traffic THE INSTANT you confirm — no pve_sdn_apply gate, no
    pve_sdn_rollback coverage. Positions SHIFT after inserts/deletes — re-list before
    updating. Only the fields you pass are changed (unless moveto is given — see its own
    description). UNLIKE the guest/cluster/node firewall family, this endpoint's reads never
    expose a digest (schema-verified) — the PLAN's captured rule is best-effort identity
    evidence only, not an optimistic lock; supply digest ONLY if you have one from
    out-of-band, and confirming with none (the default) is the normal, supported path. No
    UNDO — revert by updating it back, or remove it with pve_sdn_vnet_firewall_rule_remove.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}/firewall/rules/{pos}"
    changes: dict = {}
    if action is not None:
        changes["action"] = action
    if fw_type is not None:
        changes["fw_type"] = fw_type
    if source is not None:
        changes["source"] = source
    if dest is not None:
        changes["dest"] = dest
    if proto is not None:
        changes["proto"] = proto
    if dport is not None:
        changes["dport"] = dport
    if sport is not None:
        changes["sport"] = sport
    if icmp_type is not None:
        changes["icmp_type"] = icmp_type
    if iface is not None:
        changes["iface"] = iface
    if log is not None:
        changes["log"] = log
    if macro is not None:
        changes["macro"] = macro
    if comment is not None:
        changes["comment"] = comment
    if enable is not None:
        changes["enable"] = enable
    if moveto is not None:
        changes["moveto"] = moveto
    return run_governed(
        "pve_sdn_vnet_firewall_rule_update", tgt,
        plan=lambda: plan_vnet_firewall_rule_update(api, vnet, pos, **changes),
        execute=lambda: vnet_firewall_rule_update(api, vnet, pos, digest=digest, **changes),
        confirm=confirm)


@tool()
def pve_sdn_vnet_firewall_rule_remove(
    vnet: Annotated[str, Field(description="SDN vnet name.")],
    pos: Annotated[int, Field(description="Rule position (0-based index) to delete.")],
    digest: Annotated[str | None, Field(description="OPTIONAL optimistic-lock passthrough, forwarded verbatim when given. NEVER required, NEVER derived: this endpoint's reads (rules list / rule get) expose no digest field on this schema at all (schema-verified), so the PLAN cannot supply one — pass a digest only if you obtained one out-of-band.")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION (LIVE/IMMEDIATE): delete a vnet firewall rule by position. Dry-run by
    default — the PLAN shows the rule at that position. RISK_MEDIUM floor. Synchronous —
    confirm=True returns {"status": "ok", "result": None}; no task UPID to poll.

    Takes effect on live guest traffic THE INSTANT you confirm — no pve_sdn_apply gate, no
    pve_sdn_rollback coverage. Positions SHIFT after inserts/deletes. UNLIKE the guest/
    cluster/node firewall family, this endpoint's reads never expose a digest
    (schema-verified) — the PLAN's captured rule is best-effort identity evidence only, not
    an optimistic lock; supply digest ONLY if you have one from out-of-band, and confirming
    with none (the default) is the normal, supported path. No UNDO — revert by re-adding the
    rule with pve_sdn_vnet_firewall_rule_add.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}/firewall/rules/{pos}"
    return run_governed(
        "pve_sdn_vnet_firewall_rule_remove", tgt,
        plan=lambda: plan_vnet_firewall_rule_remove(api, vnet, pos),
        execute=lambda: vnet_firewall_rule_remove(api, vnet, pos, digest),
        confirm=confirm)


# --- vnet IP mappings (REST API, MUTATION — confirm-gated; no read endpoint exists) ---

@tool()
def pve_sdn_vnet_ip_create(
    vnet: Annotated[str, Field(description="SDN vnet name.")],
    zone: Annotated[str, Field(description="SDN zone the vnet belongs to.")],
    ip: Annotated[str, Field(description="IP address to associate with the given MAC address.")],
    mac: Annotated[str | None, Field(description="Unicast MAC address, XX:XX:XX:XX:XX:XX.")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: create an IP-to-MAC mapping in a vnet (IPAM record). Dry-run by default —
    the PLAN cannot show a 'current' preview (this endpoint has NO GET at all — declared
    honestly, not fabricated). RISK_LOW: reserves a mapping; no live traffic effect until a
    guest's NIC resolves through it. Synchronous — confirm=True returns
    {"status": "ok", "result": None}; no task UPID to poll.

    NO digest support on this endpoint at all (schema-verified) — no optimistic lock
    possible for this family. No UNDO — revert by deleting the mapping with
    pve_sdn_vnet_ip_delete.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}/ips"
    return run_governed(
        "pve_sdn_vnet_ip_create", tgt,
        plan=lambda: plan_vnet_ip_create(vnet, zone, ip, mac),
        execute=lambda: vnet_ip_create(api, vnet, zone, ip, mac),
        confirm=confirm)


@tool()
def pve_sdn_vnet_ip_update(
    vnet: Annotated[str, Field(description="SDN vnet name.")],
    zone: Annotated[str, Field(description="SDN zone the vnet belongs to.")],
    ip: Annotated[str, Field(description="IP address of the mapping to update.")],
    mac: Annotated[str | None, Field(description="New unicast MAC address, XX:XX:XX:XX:XX:XX.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID to associate with the mapping for tracking/audit purposes (PUT-only — not accepted on create/delete).")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: update an IP-to-MAC mapping in a vnet. Dry-run by default — no 'current'
    preview possible (no GET on this endpoint at all). RISK_LOW. Synchronous — confirm=True
    returns {"status": "ok", "result": None}; no task UPID to poll.

    `vmid` is accepted on THIS verb only (not create/delete — schema-verified). NO digest
    support on this endpoint at all. No UNDO — revert by updating it back to its prior
    mac/vmid.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}/ips"
    return run_governed(
        "pve_sdn_vnet_ip_update", tgt,
        plan=lambda: plan_vnet_ip_update(vnet, zone, ip, mac, vmid),
        execute=lambda: vnet_ip_update(api, vnet, zone, ip, mac, vmid),
        confirm=confirm)


@tool()
def pve_sdn_vnet_ip_delete(
    vnet: Annotated[str, Field(description="SDN vnet name.")],
    zone: Annotated[str, Field(description="SDN zone the vnet belongs to.")],
    ip: Annotated[str, Field(description="IP address of the mapping to delete.")],
    mac: Annotated[str | None, Field(description="MAC address of the mapping to delete, if disambiguation is needed.")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: delete an IP-to-MAC mapping from a vnet. Dry-run by default — no 'current'
    preview possible (no GET on this endpoint at all). RISK_MEDIUM: frees an address that
    may be in ACTIVE use by a running guest's NIC right now. Synchronous — confirm=True
    returns {"status": "ok", "result": None}; no task UPID to poll.

    NO digest support on this endpoint at all. No UNDO — re-create the mapping with
    pve_sdn_vnet_ip_create to revert.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/vnets/{vnet}/ips"
    return run_governed(
        "pve_sdn_vnet_ip_delete", tgt,
        plan=lambda: plan_vnet_ip_delete(vnet, zone, ip, mac),
        execute=lambda: vnet_ip_delete(api, vnet, zone, ip, mac),
        confirm=confirm)
