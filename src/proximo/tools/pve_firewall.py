"""PVE firewall: rules, options, aliases, IPSets, and security groups (read+mutation).

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.firewall import (
    alias_create,
    alias_delete,
    alias_list,
    alias_update,
    firewall_options_get,
    firewall_options_set,
    firewall_rule_add,
    firewall_rule_remove,
    firewall_rule_update,
    firewall_rules_list,
    firewall_set_enabled,
    ipset_create,
    ipset_delete,
    ipset_entry_add,
    ipset_entry_remove,
    ipset_list,
    plan_alias_create,
    plan_alias_delete,
    plan_alias_update,
    plan_firewall_options_set,
    plan_firewall_rule_add,
    plan_firewall_rule_remove,
    plan_firewall_rule_update,
    plan_firewall_set_enabled,
    plan_ipset_create,
    plan_ipset_delete,
    plan_ipset_entry_add,
    plan_ipset_entry_remove,
    plan_security_group_create,
    plan_security_group_delete,
    security_group_create,
    security_group_delete,
    security_groups_list,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Firewall (REST API, read) ---

@tool()
def pve_firewall_rules_list(
    scope: Annotated[str, Field(description="Firewall scope: 'cluster', 'node', or 'guest'.")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='node' or scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
) -> list[dict]:
    """READ-ONLY: List firewall rules for the given scope (cluster, node, or guest).

    Returns the active rules at that scope level, including action, direction, protocol,
    and address/port fields. Use pve_firewall_options_get to read firewall settings
    (enable flag, policy, log rate).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}"
    return _audited("pve_firewall_rules_list", tgt,
                    lambda: firewall_rules_list(api, scope, node, vmid, kind))


@tool()
def pve_firewall_options_get(
    scope: Annotated[str, Field(description="Firewall scope: 'cluster', 'node', or 'guest'.")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='node' or scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
) -> dict:
    """READ-ONLY: get the firewall option block (enable flag, default in/out policy, log rate limit,
    …) at cluster, node, or guest scope.

    No state change. Pair with pve_firewall_options_set to change these, and pve_firewall_rules_list
    to read the rules themselves. scope='node' requires `node`; scope='guest' requires `node`, `vmid`,
    and `kind` ('qemu'|'lxc'). Returns the option block as a dict."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/options"
    return _audited("pve_firewall_options_get", tgt,
                    lambda: firewall_options_get(api, scope, node, vmid, kind))


@tool()
def pve_security_groups_list() -> list[dict]:
    """READ-ONLY: List the cluster's firewall security groups.

    Returns each group's id (keyed `group`), comment, and digest. A security group is a reusable
    named rule set you attach to a VM/node firewall; use pve_firewall_rules_list to read
    a specific scope's active rules.
    """
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_security_groups_list", "firewall/cluster/groups",
                    lambda: security_groups_list(api))


@tool()
def pve_ipset_list(
    scope: Annotated[str, Field(description="Firewall scope: 'cluster' or 'guest' (no node-scope ipsets in the PVE API).")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
) -> list[dict]:
    """READ-ONLY: list IP sets for the given scope. Scope = cluster or guest only —
    the PVE API has no node-scope ipsets (node firewall = options/rules/log).

    No state change. Returns a list of IPSet dicts. To create/delete a set use
    pve_firewall_ipset_create/pve_firewall_ipset_delete; to edit membership use
    pve_firewall_ipset_entry_add/pve_firewall_ipset_entry_remove."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/ipset"
    return _audited("pve_ipset_list", tgt,
                    lambda: ipset_list(api, scope, node, vmid, kind))


# --- Firewall (REST API, MUTATION — confirm-gated) ---

@tool()
def pve_firewall_rule_add(
    action: Annotated[str, Field(description="Rule action: 'ACCEPT', 'DROP', or 'REJECT'.")],
    direction: Annotated[str, Field(description="Traffic direction the rule matches: 'in' or 'out'.")] = "in",
    scope: Annotated[str, Field(description="Firewall scope: 'cluster', 'node', or 'guest'.")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='node' or scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
    source: Annotated[str | None, Field(description="Source address/CIDR/alias to match, or None for any.")] = None,
    dest: Annotated[str | None, Field(description="Destination address/CIDR/alias to match, or None for any.")] = None,
    proto: Annotated[str | None, Field(description="IP protocol to match, e.g. 'tcp', 'udp', 'icmp'.")] = None,
    dport: Annotated[str | None, Field(description="Destination port or port range to match, e.g. '22' or '8000:8010'.")] = None,
    sport: Annotated[str | None, Field(description="Source port or port range to match, e.g. '22' or '8000:8010'.")] = None,
    comment: Annotated[str | None, Field(description="Free-text comment stored with the rule.")] = None,
    enable: Annotated[bool, Field(description="Whether the rule is active immediately (True) or created disabled (False).")] = True,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: add a new firewall rule. Dry-run by default — the PLAN shows scope, direction,
    action, and key address/port fields. Re-call with confirm=True to execute. Synchronous —
    confirm=True returns {"status": "ok", "result": None}; no task UPID to poll.

    WARNING: a misplaced DROP/REJECT can cause a connectivity lockout. PVE always inserts the
    new rule at position 0 (top), taking precedence over existing rules. No UNDO — revert by
    removing it with pve_firewall_rule_remove.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/rules"
    return run_governed(
        "pve_firewall_rule_add", tgt,
        plan=lambda: plan_firewall_rule_add(action, direction, scope, node, vmid, kind,
                                                source, dest, dport, proto),
        execute=lambda: firewall_rule_add(api, action, direction, scope, node,
                                             vmid, kind, source, dest, proto, dport,
                                             sport, comment, enable),
        confirm=confirm)


@tool()
def pve_firewall_rule_remove(
    pos: Annotated[int, Field(description="Rule position (0-based index) in the target scope's rule list.")],
    scope: Annotated[str, Field(description="Firewall scope: 'cluster', 'node', or 'guest'.")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='node' or scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock digest from the PLAN preview; pass on confirm to abort if the rule list changed since.")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: delete a firewall rule by position. Dry-run by default — the PLAN shows the rule
    at that position AND the optimistic-lock digest. Positions SHIFT after inserts/deletes — pass the
    digest from the plan back as `digest=` on confirm so PVE rejects the delete if the rule list moved
    since the preview (otherwise a concurrent insert can shift positions and remove the wrong rule).
    Synchronous — confirm=True returns {"status": "ok", "result": None}; no task UPID to poll.

    No UNDO: firewall config isn't in guest snapshots — revert by re-adding the rule with
    pve_firewall_rule_add.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/rules/{pos}"
    return run_governed(
        "pve_firewall_rule_remove", tgt,
        plan=lambda: plan_firewall_rule_remove(api, pos, scope, node, vmid, kind),
        execute=lambda: firewall_rule_remove(api, pos, scope, node, vmid, kind, digest),
        confirm=confirm)


@tool()
def pve_firewall_rule_update(
    pos: Annotated[int, Field(description="Rule position (0-based index) in the target scope's rule list.")],
    scope: Annotated[str, Field(description="Firewall scope: 'cluster', 'node', or 'guest'.")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='node' or scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
    action: Annotated[str | None, Field(description="New rule action: 'ACCEPT', 'DROP', or 'REJECT'; omit to leave unchanged.")] = None,
    direction: Annotated[str | None, Field(description="New traffic direction: 'in' or 'out'; omit to leave unchanged.")] = None,
    source: Annotated[str | None, Field(description="New source address/CIDR/alias to match; omit to leave unchanged.")] = None,
    dest: Annotated[str | None, Field(description="New destination address/CIDR/alias to match; omit to leave unchanged.")] = None,
    proto: Annotated[str | None, Field(description="New IP protocol to match, e.g. 'tcp'/'udp'/'icmp'; omit to leave unchanged.")] = None,
    dport: Annotated[str | None, Field(description="New destination port or port range; omit to leave unchanged.")] = None,
    sport: Annotated[str | None, Field(description="New source port or port range; omit to leave unchanged.")] = None,
    comment: Annotated[str | None, Field(description="New free-text comment; omit to leave unchanged.")] = None,
    enable: Annotated[bool | None, Field(description="New enabled state for the rule; omit to leave unchanged.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock digest from the PLAN preview; pass on confirm to abort if the rule list changed since.")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: update an existing firewall rule at position `pos`. Dry-run by default — the PLAN
    shows the rule's current state, the fields being changed, AND the optimistic-lock digest. Pass the
    digest from the plan back as `digest=` on confirm so PVE rejects the update if the rule list moved
    since the preview (positions shift and the wrong rule can be updated otherwise). Synchronous —
    confirm=True returns {"status": "ok", "result": None}; no task UPID to poll.

    Only the fields you pass are changed; omitted ones keep their current value. No UNDO — revert
    by updating the rule back to its prior values, or remove it with pve_firewall_rule_remove.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/rules/{pos}"
    # Build a dict of only the non-None update fields (matches plan_firewall_rule_update **new_fields).
    changes: dict = {}
    if action is not None:
        changes["action"] = action
    if direction is not None:
        changes["direction"] = direction
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
    if comment is not None:
        changes["comment"] = comment
    if enable is not None:
        changes["enable"] = enable
    return run_governed(
        "pve_firewall_rule_update", tgt,
        plan=lambda: plan_firewall_rule_update(api, pos, scope, node, vmid, kind, **changes),
        execute=lambda: firewall_rule_update(api, pos, scope, node, vmid, kind, digest=digest, **changes),
        confirm=confirm)


@tool()
def pve_firewall_set_enabled(
    enabled: Annotated[bool, Field(description="Desired firewall state: True to turn on, False to turn off.")],
    scope: Annotated[str, Field(description="Firewall scope: 'cluster', 'node', or 'guest'.")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='node' or scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION (HIGH RISK): toggle the firewall on or off for the given scope. Dry-run by default.
    RISK_HIGH both directions: enabling may instantly lock you out (default-DROP, no ACCEPT for 22/8006);
    disabling strips all protection. Cluster scope = master kill-switch. Synchronous — confirm=True
    returns {"status": "ok", "result": None}; no task UPID to poll.

    This is the focused tool for just the enable flag; for policy/log-level/ebtables options use
    pve_firewall_options_set. No UNDO — re-toggle manually to revert.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/options"
    return run_governed(
        "pve_firewall_set_enabled", tgt,
        plan=lambda: plan_firewall_set_enabled(api, enabled, scope, node, vmid, kind),
        execute=lambda: firewall_set_enabled(api, enabled, scope, node, vmid, kind),
        confirm=confirm)


@tool()
def pve_firewall_alias_list(
    scope: Annotated[str, Field(description="Firewall scope: 'cluster' or 'guest' (no node-scope aliases in the PVE API).")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
) -> list[dict]:
    """READ-ONLY: list firewall aliases (named CIDRs) for the given scope. Scope = cluster
    or guest only — the PVE API has no node-scope aliases (node firewall = options/rules/log).

    No state change. Returns a list of alias dicts (name, cidr, comment, ipversion). To create,
    change, or remove an alias use pve_firewall_alias_create / pve_firewall_alias_update /
    pve_firewall_alias_delete."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_firewall_alias_list", f"firewall/{scope}/aliases",
                    lambda: alias_list(api, scope, node, vmid, kind))


@tool()
def pve_firewall_alias_create(
    name: Annotated[str, Field(description="Name for the new alias, referenced by rules as this name.")],
    cidr: Annotated[str, Field(description="IP address or CIDR network the alias resolves to.")],
    scope: Annotated[str, Field(description="Firewall scope: 'cluster' or 'guest' (no node-scope aliases in the PVE API).")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
    comment: Annotated[str | None, Field(description="Free-text comment stored with the alias.")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: create a firewall alias (named CIDR). Dry-run by default — the PLAN shows the
    name, CIDR, and scope. Re-call with confirm=True to execute. Passive until a rule references it.
    Synchronous — confirm=True returns {"status": "ok", "result": None}; no task UPID to poll.

    No UNDO: revert by deleting the alias with pve_firewall_alias_delete. To change an existing
    alias instead, use pve_firewall_alias_update.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/aliases/{name}"
    return run_governed(
        "pve_firewall_alias_create", tgt,
        plan=lambda: plan_alias_create(name, cidr, scope, node, vmid, kind, comment),
        execute=lambda: alias_create(api, name, cidr, scope, node, vmid, kind, comment),
        confirm=confirm)


@tool()
def pve_firewall_alias_update(
    name: Annotated[str, Field(description="Name of the existing alias to update.")],
    scope: Annotated[str, Field(description="Firewall scope: 'cluster' or 'guest' (no node-scope aliases in the PVE API).")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
    cidr: Annotated[str | None, Field(description="New IP address/CIDR the alias should resolve to; omit to leave unchanged.")] = None,
    comment: Annotated[str | None, Field(description="New free-text comment; omit to leave unchanged.")] = None,
    rename: Annotated[str | None, Field(description="New name to rename the alias to; omit to keep the current name.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock digest forwarded to PVE to abort if the alias changed; this tool's PLAN does not surface a digest to copy (only the rule tools do).")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: update a firewall alias. Dry-run by default — the PLAN shows the current alias and
    the fields being changed. Changing the CIDR silently alters every referencing rule's match set.
    Synchronous — confirm=True returns {"status": "ok", "result": None}; no task UPID to poll.

    Requires at least one of cidr/comment/rename. No UNDO — revert by setting it back to its prior
    value; to create a new alias instead use pve_firewall_alias_create.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/aliases/{name}"
    return run_governed(
        "pve_firewall_alias_update", tgt,
        plan=lambda: plan_alias_update(api, name, scope, node, vmid, kind, cidr, comment, rename),
        execute=lambda: alias_update(api, name, scope, node, vmid, kind, cidr, comment, rename, digest),
        confirm=confirm)


@tool()
def pve_firewall_alias_delete(
    name: Annotated[str, Field(description="Name of the alias to delete.")],
    scope: Annotated[str, Field(description="Firewall scope: 'cluster' or 'guest' (no node-scope aliases in the PVE API).")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock digest forwarded to PVE to abort if the alias changed; this tool's PLAN does not surface a digest to copy (only the rule tools do).")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: delete a firewall alias. Dry-run by default — the PLAN shows the current alias.
    PVE refuses while any rule still references the alias. No UNDO: re-create it with
    pve_firewall_alias_create to revert. Synchronous — confirm=True returns
    {"status": "ok", "result": None}; no task UPID to poll.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/aliases/{name}"
    return run_governed(
        "pve_firewall_alias_delete", tgt,
        plan=lambda: plan_alias_delete(api, name, scope, node, vmid, kind),
        execute=lambda: alias_delete(api, name, scope, node, vmid, kind, digest),
        confirm=confirm)


@tool()
def pve_firewall_ipset_create(
    name: Annotated[str, Field(description="Name for the new IP set, referenced by rules as '+name'.")],
    scope: Annotated[str, Field(description="Firewall scope: 'cluster' or 'guest' (no node-scope ipsets in the PVE API).")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
    comment: Annotated[str | None, Field(description="Free-text comment stored with the IP set.")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: create an empty IP set. Dry-run by default — the PLAN shows the name and scope.
    Passive until a rule references it as '+name' and entries are added via
    pve_firewall_ipset_entry_add. Synchronous — confirm=True returns
    {"status": "ok", "result": None}; no task UPID to poll.

    No UNDO: revert by deleting it with pve_firewall_ipset_delete.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/ipset/{name}"
    return run_governed(
        "pve_firewall_ipset_create", tgt,
        plan=lambda: plan_ipset_create(name, scope, node, vmid, kind, comment),
        execute=lambda: ipset_create(api, name, scope, node, vmid, kind, comment),
        confirm=confirm)


@tool()
def pve_firewall_ipset_delete(
    name: Annotated[str, Field(description="Name of the IP set to delete.")],
    scope: Annotated[str, Field(description="Firewall scope: 'cluster' or 'guest' (no node-scope ipsets in the PVE API).")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
    force: Annotated[bool, Field(description="If True, wipe all member entries so the (now-empty) IP set can be deleted.")] = False,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: delete an IP set. Dry-run by default — the PLAN shows member count and the
    force semantics. force=True WIPES all members; PVE refuses while a rule references the set.
    Synchronous — confirm=True returns {"status": "ok", "result": None}; no task UPID to poll.

    No UNDO: re-create it with pve_firewall_ipset_create and re-add members to revert.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/ipset/{name}"
    return run_governed(
        "pve_firewall_ipset_delete", tgt,
        plan=lambda: plan_ipset_delete(api, name, scope, node, vmid, kind, force),
        execute=lambda: ipset_delete(api, name, scope, node, vmid, kind, force),
        confirm=confirm)


@tool()
def pve_firewall_ipset_entry_add(
    name: Annotated[str, Field(description="Name of the IP set to add the entry to.")],
    cidr: Annotated[str, Field(description="IP address or CIDR network to add as a member entry.")],
    scope: Annotated[str, Field(description="Firewall scope: 'cluster' or 'guest' (no node-scope ipsets in the PVE API).")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
    comment: Annotated[str | None, Field(description="Free-text comment stored with the entry.")] = None,
    nomatch: Annotated[bool, Field(description="If True, this entry is an exclusion (negative match) rather than an inclusion.")] = False,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: add an IP/Network entry to an IP set. Dry-run by default — the PLAN shows the
    entry and warns it changes every referencing rule's match set. nomatch=True = exclusion.
    Synchronous — confirm=True returns {"status": "ok", "result": None}; no task UPID to poll.

    No UNDO: revert by removing the entry with pve_firewall_ipset_entry_remove.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/ipset/{name}"
    return run_governed(
        "pve_firewall_ipset_entry_add", tgt,
        plan=lambda: plan_ipset_entry_add(name, cidr, scope, node, vmid, kind, comment, nomatch),
        execute=lambda: ipset_entry_add(api, name, cidr, scope, node, vmid, kind, comment, nomatch),
        confirm=confirm)


@tool()
def pve_firewall_ipset_entry_remove(
    name: Annotated[str, Field(description="Name of the IP set to remove the entry from.")],
    cidr: Annotated[str, Field(description="IP address or CIDR network of the member entry to remove.")],
    scope: Annotated[str, Field(description="Firewall scope: 'cluster' or 'guest' (no node-scope ipsets in the PVE API).")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock digest forwarded to PVE to abort if the set changed; this tool's PLAN does not surface a digest to copy (only the rule tools do).")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: remove an IP/Network entry from an IP set. Dry-run by default — the PLAN shows the
    entry and warns it changes every referencing rule's match set (may open or close access).
    Synchronous — confirm=True returns {"status": "ok", "result": None}; no task UPID to poll.

    No UNDO: revert by re-adding the entry with pve_firewall_ipset_entry_add.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/ipset/{name}"
    return run_governed(
        "pve_firewall_ipset_entry_remove", tgt,
        plan=lambda: plan_ipset_entry_remove(name, cidr, scope, node, vmid, kind),
        execute=lambda: ipset_entry_remove(api, name, cidr, scope, node, vmid, kind, digest),
        confirm=confirm)


@tool()
def pve_firewall_security_group_create(
    group: Annotated[str, Field(description="Name for the new cluster security group.")],
    comment: Annotated[str | None, Field(description="Free-text comment stored with the group.")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: create an empty cluster security group. Dry-run by default — the PLAN shows the
    name. Passive until rules are added and a rule references it (type=group). Synchronous —
    confirm=True returns {"status": "ok", "result": None}; no task UPID to poll.

    No UNDO: revert by deleting it with pve_firewall_security_group_delete.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/cluster/groups/{group}"
    return run_governed(
        "pve_firewall_security_group_create", tgt,
        plan=lambda: plan_security_group_create(group, comment),
        execute=lambda: security_group_create(api, group, comment),
        confirm=confirm)


@tool()
def pve_firewall_security_group_delete(
    group: Annotated[str, Field(description="Name of the cluster security group to delete.")],
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: delete a cluster security group. Dry-run by default — the PLAN shows how many rules
    the group holds. PVE refuses while the group is non-empty or still referenced by a rule.
    Synchronous — confirm=True returns {"status": "ok", "result": None}; no task UPID to poll.

    No UNDO: re-create it with pve_firewall_security_group_create and re-add its rules to revert.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/cluster/groups/{group}"
    return run_governed(
        "pve_firewall_security_group_delete", tgt,
        plan=lambda: plan_security_group_delete(api, group),
        execute=lambda: security_group_delete(api, group),
        confirm=confirm)


@tool()
def pve_firewall_options_set(
    scope: Annotated[str, Field(description="Firewall scope: 'cluster', 'node', or 'guest'.")] = "cluster",
    node: Annotated[str | None, Field(description="Node name, required for scope='node' or scope='guest'.")] = None,
    vmid: Annotated[str | None, Field(description="Guest VMID/CTID, required for scope='guest'.")] = None,
    kind: Annotated[str | None, Field(description="Guest kind for scope='guest': 'qemu' or 'lxc'.")] = None,
    options: Annotated[dict | None, Field(description="Key-value bag of firewall options to set, e.g. policy_in, policy_out, log_ratelimit, enable, ebtables.")] = None,
    delete: Annotated[list[str] | None, Field(description="List of option keys to unset/remove.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock digest forwarded to PVE to abort if the options changed; this tool's PLAN does not surface a digest to copy (only the rule tools do).")] = None,
    confirm: Annotated[bool, Field(description="Set True to execute the mutation; False (default) only returns a dry-run PLAN.")] = False,
) -> dict:
    """MUTATION: set firewall options for a scope (policy_in/out, log levels, ebtables, log_ratelimit,
    ...). `options` is a key->value bag; `delete` unsets keys. Dry-run by default — the PLAN shows the
    current values and flags lockout risk. RISK_HIGH when enabling the firewall or changing a policy.
    Synchronous — confirm=True returns {"status": "ok", "result": None}; no task UPID to poll.

    To read current values first use pve_firewall_options_get; to toggle just the enable flag use
    the focused pve_firewall_set_enabled. No UNDO — revert by setting the prior values.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"firewall/{scope}/options"
    return run_governed(
        "pve_firewall_options_set", tgt,
        plan=lambda: plan_firewall_options_set(api, scope, node, vmid, kind, options, delete),
        execute=lambda: firewall_options_set(api, scope, node, vmid, kind, options, delete, digest),
        confirm=confirm)
