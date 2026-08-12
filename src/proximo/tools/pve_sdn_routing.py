"""PVE SDN PREFIX-LISTS + ROUTE-MAPS: BGP/OSPF routing-policy primitives (read+mutation) for
the two families sharing the staged-pending SDN plane.

New module (Wave 7e, full-surface campaign) — see proximo/sdn_routing.py's module docstring
for the schema facts (url_seq opacity vs. order's proper typing, the three-way digest
asymmetry, route-maps' missing container CRUD, the match/set/exit-action generic-passthrough
argument) and the mutation funnel these wrappers depend on (proximo/server.py's module
docstring).
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.sdn_routing import (
    plan_prefix_list_create,
    plan_prefix_list_delete,
    plan_prefix_list_entry_create,
    plan_prefix_list_entry_delete,
    plan_prefix_list_entry_update,
    plan_prefix_list_update,
    plan_route_map_entry_create,
    plan_route_map_entry_delete,
    plan_route_map_entry_update,
    prefix_list_create,
    prefix_list_delete,
    prefix_list_entries_list,
    prefix_list_entry_create,
    prefix_list_entry_delete,
    prefix_list_entry_get,
    prefix_list_entry_update,
    prefix_list_get,
    prefix_list_update,
    prefix_lists_list,
    route_map_entries_list,
    route_map_entries_list_all,
    route_map_entry_create,
    route_map_entry_delete,
    route_map_entry_get,
    route_map_entry_update,
    route_maps_list,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- prefix-lists (REST API, read) ---

@tool()
def pve_sdn_prefix_lists_list(
    pending: Annotated[bool | None, Field(description="Display pending (staged, not-yet-applied) config.")] = None,
    running: Annotated[bool | None, Field(description="Display the currently-APPLIED (running) config instead.")] = None,
    verbose: Annotated[bool | None, Field(description="False returns id-only summaries; omit/True for the fuller per-item shape.")] = None,
) -> list[dict]:
    """READ-ONLY: list SDN prefix lists (cluster-scoped). Use pve_sdn_prefix_list_create to add
    and pve_sdn_apply to commit."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_prefix_lists_list", "sdn/prefix-lists",
                    lambda: prefix_lists_list(api, pending, running, verbose))


@tool()
def pve_sdn_prefix_list_get(
    prefix_list: Annotated[str, Field(description="Existing SDN prefix list id to read.")],
) -> dict:
    """READ-ONLY: read one SDN prefix list's configuration (including its entries).
    Use pve_sdn_prefix_lists_list to enumerate prefix-list ids first."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_prefix_list_get", f"sdn/prefix-lists/{prefix_list}",
                    lambda: prefix_list_get(api, prefix_list))


# --- prefix-lists (REST API, MUTATION — confirm-gated) ---

@tool()
def pve_sdn_prefix_list_create(
    prefix_list: Annotated[str, Field(description="New SDN prefix list id to create.")],
    entries: Annotated[list[dict] | None, Field(description="Optional bulk seed: a list of {action, prefix, ge?, le?, seq?} entry objects, created in the SAME call. PVE validates each item server-side.")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-concurrency checking — accepted on CREATE for this endpoint (a real exception to the plane-wide 'digest never on create' convention).")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: create an SDN prefix list (PENDING — inert until pve_sdn_apply).

    The more granular path is create empty, then add entries one at a time via
    pve_sdn_prefix_list_entry_create; `entries` here seeds them in bulk instead. To update an
    existing list use pve_sdn_prefix_list_update; to remove one use
    pve_sdn_prefix_list_delete. Dry-run by default (returns a PLAN); confirm=True creates the
    pending list, returning {status, result}. RISK_LOW (staging, no live network effect).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/prefix-lists/{prefix_list}"
    return run_governed(
        "pve_sdn_prefix_list_create", tgt,
        plan=lambda: plan_prefix_list_create(prefix_list, entries),
        execute=lambda: prefix_list_create(api, prefix_list, entries, digest, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_prefix_list_update(
    prefix_list: Annotated[str, Field(description="Existing SDN prefix list id to update.")],
    entries: Annotated[list[dict] | None, Field(description="Replacement entries array (whether this REPLACES or MERGES with existing entries by seq is undocumented in the schema — treat conservatively as a full REPLACE).")] = None,
    delete: Annotated[list[str] | None, Field(description="Field(s) to unset — only 'entries' is a valid value on this endpoint.")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-concurrency checking.")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: update an SDN prefix list (PENDING). To create a new list use
    pve_sdn_prefix_list_create; to remove one use pve_sdn_prefix_list_delete. Dry-run by
    default (returns a PLAN); confirm=True stages the edit and returns {status, result}.
    RISK_LOW (staging; inert until pve_sdn_apply).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/prefix-lists/{prefix_list}"
    return run_governed(
        "pve_sdn_prefix_list_update", tgt,
        plan=lambda: plan_prefix_list_update(prefix_list, entries, delete),
        execute=lambda: prefix_list_update(api, prefix_list, entries, delete, digest, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_prefix_list_delete(
    prefix_list: Annotated[str, Field(description="Existing SDN prefix list id to delete.")],
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: delete an SDN prefix list (PENDING). Dry-run by default — the PLAN shows the
    current list.

    Referential-integrity refusal (e.g. a fabric's route_filter still naming this list) is
    asserted BY ANALOGY to the zone/vnet precedent, not independently confirmed against this
    endpoint's own schema — Smoke-confirm. confirm=True stages the removal and returns
    {status, result}; no config UNDO — re-create the list to revert. RISK_MEDIUM (staging a
    removal an apply would enact).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/prefix-lists/{prefix_list}"
    return run_governed(
        "pve_sdn_prefix_list_delete", tgt,
        plan=lambda: plan_prefix_list_delete(api, prefix_list),
        execute=lambda: prefix_list_delete(api, prefix_list, lock_token),
        confirm=confirm)


# --- prefix-list entries (REST API, read) ---

@tool()
def pve_sdn_prefix_list_entries_list(
    prefix_list: Annotated[str, Field(description="Existing SDN prefix list id whose entries to list.")],
) -> list[dict]:
    """READ-ONLY: list a prefix list's entries. Use pve_sdn_prefix_list_entry_create to add
    one and pve_sdn_apply to commit."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_prefix_list_entries_list", f"sdn/prefix-lists/{prefix_list}/entries",
                    lambda: prefix_list_entries_list(api, prefix_list))


@tool()
def pve_sdn_prefix_list_entry_get(
    prefix_list: Annotated[str, Field(description="Existing SDN prefix list id.")],
    entry_id: Annotated[str | int, Field(description="OPAQUE entry path token (the schema's {url_seq}) — capture from a prior pve_sdn_prefix_list_entries_list/entry_get read; NOT guaranteed to be a plain integer even though it usually matches the entry's own 'seq' field.")],
) -> dict:
    """READ-ONLY: read a single prefix-list entry. `entry_id` is an OPAQUE path token — this
    endpoint's schema never formally types the {url_seq} path parameter on any of its 3
    methods (GET/PUT/DELETE), unlike route-map's own {order}."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_prefix_list_entry_get", f"sdn/prefix-lists/{prefix_list}/entries/{entry_id}",
                    lambda: prefix_list_entry_get(api, prefix_list, entry_id))


# --- prefix-list entries (REST API, MUTATION — confirm-gated) ---

@tool()
def pve_sdn_prefix_list_entry_create(
    prefix_list: Annotated[str, Field(description="Existing SDN prefix list id to add an entry to.")],
    action: Annotated[str, Field(description="Matching policy: 'permit' or 'deny'.")],
    prefix: Annotated[str, Field(description="CIDR network to match (e.g. 10.0.0.0/8, ::/0).")],
    ge: Annotated[int | None, Field(description="Lower bound on matched prefix length (0-128).")] = None,
    le: Annotated[int | None, Field(description="Upper bound on matched prefix length (0-128).")] = None,
    seq: Annotated[int | None, Field(description="Explicit sequence number (1-4294967295) — omit to let PVE assign one.")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: create a prefix-list entry (PENDING — inert until pve_sdn_apply).

    NO `digest` on this endpoint (schema-verified) — unlike this same entry's own UPDATE,
    which does accept one. To update an existing entry use
    pve_sdn_prefix_list_entry_update; to remove one use pve_sdn_prefix_list_entry_delete.
    Dry-run by default (returns a PLAN); confirm=True creates the pending entry, returning
    {status, result}. RISK_LOW (staging, no live network effect).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/prefix-lists/{prefix_list}/entries"
    return run_governed(
        "pve_sdn_prefix_list_entry_create", tgt,
        plan=lambda: plan_prefix_list_entry_create(prefix_list, action, prefix, ge, le, seq),
        execute=lambda: prefix_list_entry_create(api, prefix_list, action, prefix, ge, le, seq, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_prefix_list_entry_update(
    prefix_list: Annotated[str, Field(description="Existing SDN prefix list id.")],
    entry_id: Annotated[str | int, Field(description="OPAQUE entry path token (the schema's {url_seq}) — capture from a prior list/get read.")],
    action: Annotated[str | None, Field(description="New matching policy: 'permit' or 'deny'.")] = None,
    prefix: Annotated[str | None, Field(description="New CIDR network to match.")] = None,
    ge: Annotated[int | None, Field(description="New lower bound on matched prefix length (0-128).")] = None,
    le: Annotated[int | None, Field(description="New upper bound on matched prefix length (0-128).")] = None,
    seq: Annotated[int | None, Field(description="New sequence number (1-4294967295).")] = None,
    delete: Annotated[list[str] | None, Field(description="Field names to unset — only 'le', 'ge', 'seq' are valid values on this endpoint.")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-concurrency checking — accepted here (unlike this same entry's own CREATE, which has none).")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: update a prefix-list entry (PENDING). To create a new entry use
    pve_sdn_prefix_list_entry_create; to remove one use
    pve_sdn_prefix_list_entry_delete. Dry-run by default (returns a PLAN); confirm=True
    stages the edit and returns {status, result}. RISK_LOW (staging).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/prefix-lists/{prefix_list}/entries/{entry_id}"
    return run_governed(
        "pve_sdn_prefix_list_entry_update", tgt,
        plan=lambda: plan_prefix_list_entry_update(prefix_list, entry_id, action, prefix, ge, le, seq, delete),
        execute=lambda: prefix_list_entry_update(api, prefix_list, entry_id, action, prefix, ge, le, seq,
                                                     delete, digest, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_prefix_list_entry_delete(
    prefix_list: Annotated[str, Field(description="Existing SDN prefix list id.")],
    entry_id: Annotated[str | int, Field(description="OPAQUE entry path token (the schema's {url_seq}) — capture from a prior list/get read.")],
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: delete a prefix-list entry (PENDING). Dry-run by default — the PLAN shows
    the current entry (may fail to read if entry_id is stale — disclosed, not hidden).
    confirm=True stages the removal and returns {status, result}; no config UNDO — re-create
    the entry to revert. RISK_MEDIUM.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/prefix-lists/{prefix_list}/entries/{entry_id}"
    return run_governed(
        "pve_sdn_prefix_list_entry_delete", tgt,
        plan=lambda: plan_prefix_list_entry_delete(api, prefix_list, entry_id),
        execute=lambda: prefix_list_entry_delete(api, prefix_list, entry_id, lock_token),
        confirm=confirm)


# --- route-maps (REST API, read) ---

@tool()
def pve_sdn_route_maps_list(
    running: Annotated[bool | None, Field(description="Display the currently-APPLIED (running) config instead of the default staged-merged view.")] = None,
) -> list[dict]:
    """READ-ONLY: list SDN route maps (cluster-scoped, id-only summaries). NOTE: unlike every
    other list tool on this module, this one has NO `pending` filter (schema-verified — a
    real, isolated asymmetry). Use pve_sdn_route_map_entry_create to add entries — there is
    no container-level create for a route map itself."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_route_maps_list", "sdn/route-maps",
                    lambda: route_maps_list(api, running))


@tool()
def pve_sdn_route_map_entries_list_all(
    pending: Annotated[bool | None, Field(description="Display pending (staged, not-yet-applied) config.")] = None,
    running: Annotated[bool | None, Field(description="Display the currently-APPLIED (running) config instead.")] = None,
) -> list[dict]:
    """READ-ONLY: list EVERY route-map entry across ALL route-maps in one call. Use
    pve_sdn_route_map_entries_list to scope to one route-map id."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_route_map_entries_list_all", "sdn/route-maps/entries",
                    lambda: route_map_entries_list_all(api, pending, running))


@tool()
def pve_sdn_route_map_entries_list(
    route_map_id: Annotated[str, Field(description="Existing SDN route map id whose entries to list.")],
    pending: Annotated[bool | None, Field(description="Display pending (staged, not-yet-applied) config.")] = None,
    running: Annotated[bool | None, Field(description="Display the currently-APPLIED (running) config instead.")] = None,
) -> list[dict]:
    """READ-ONLY: list every entry belonging to ONE route map."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_route_map_entries_list", f"sdn/route-maps/entries/{route_map_id}",
                    lambda: route_map_entries_list(api, route_map_id, pending, running))


@tool()
def pve_sdn_route_map_entry_get(
    route_map_id: Annotated[str, Field(description="Existing SDN route map id.")],
    order: Annotated[int, Field(description="Entry position (0-65535) — a properly-typed, schema-required integer (unlike prefix-list's opaque entry token).")],
) -> dict:
    """READ-ONLY: read a single route-map entry by its (route_map_id, order) pair."""
    _, api, _, _ = _proximo_server._svc()
    return _audited("pve_sdn_route_map_entry_get", f"sdn/route-maps/entries/{route_map_id}/entry/{order}",
                    lambda: route_map_entry_get(api, route_map_id, order))


# --- route-map entries (REST API, MUTATION — confirm-gated; NO container-level CRUD exists) ---

@tool()
def pve_sdn_route_map_entry_create(
    route_map_id: Annotated[str, Field(description="Route map id to add this entry to — a FREE-FORM id chosen by the caller; there is no separate 'create a route map' call, so the FIRST entry_create for a given id implicitly brings that route map into existence.")],
    order: Annotated[int, Field(description="Entry position (0-65535, required).")],
    action: Annotated[str, Field(description="Matching policy: 'permit' or 'deny'.")],
    match: Annotated[list[dict] | None, Field(description="Array of {key, value} match-clause objects (route-type, vni, ip-address-prefix-list, metric, local-preference, peer, tag, ...); PVE validates each item's key server-side.")] = None,
    set_clauses: Annotated[list[dict] | None, Field(description="Array of {key, value} set-clause objects (ip-next-hop, local-preference, weight, metric, ...) — wire key is 'set'; renamed here to avoid shadowing the 'set' builtin.")] = None,
    exit_action: Annotated[dict | None, Field(description="Single {key, value} object: key is one of on-match-goto/on-match-next/continue.")] = None,
    call: Annotated[str | None, Field(description="Another route-map id to invoke as a sub-routine.")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-concurrency checking — accepted on CREATE for this endpoint (unlike prefix-list's own entry create, which has none).")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: create a route-map entry (PENDING — inert until pve_sdn_apply). There is NO
    container-level 'create a route map' tool — a route map is defined purely by having >=1
    entry.

    To update an existing entry use pve_sdn_route_map_entry_update; to remove one use
    pve_sdn_route_map_entry_delete. Dry-run by default (returns a PLAN); confirm=True
    creates the pending entry, returning {status, result}. RISK_LOW (staging, no live
    network effect).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/route-maps/entries/{route_map_id}"
    return run_governed(
        "pve_sdn_route_map_entry_create", tgt,
        plan=lambda: plan_route_map_entry_create(route_map_id, order, action, match, set_clauses,
                                                    exit_action, call),
        execute=lambda: route_map_entry_create(api, route_map_id, order, action, match, set_clauses,
                                                   exit_action, call, digest, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_route_map_entry_update(
    route_map_id: Annotated[str, Field(description="Existing SDN route map id.")],
    order: Annotated[int, Field(description="Entry position to update (0-65535, required — identifies WHICH entry; not itself changeable via this call).")],
    action: Annotated[str | None, Field(description="New matching policy: 'permit' or 'deny'.")] = None,
    match: Annotated[list[dict] | None, Field(description="Replacement array of {key, value} match-clause objects.")] = None,
    set_clauses: Annotated[list[dict] | None, Field(description="Replacement array of {key, value} set-clause objects (wire key 'set').")] = None,
    exit_action: Annotated[dict | None, Field(description="Replacement {key, value} exit-action object.")] = None,
    call: Annotated[str | None, Field(description="New route-map id to invoke as a sub-routine.")] = None,
    delete: Annotated[list[str] | None, Field(description="Field names to unset — only 'set', 'match', 'call', 'exit-action' are valid values on this endpoint (NOT action or order).")] = None,
    digest: Annotated[str | None, Field(description="Expected config digest for optimistic-concurrency checking.")] = None,
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: update a route-map entry (PENDING). To create a new entry use
    pve_sdn_route_map_entry_create; to remove one use
    pve_sdn_route_map_entry_delete. Dry-run by default (returns a PLAN); confirm=True
    stages the edit and returns {status, result}. RISK_LOW (staging).
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/route-maps/entries/{route_map_id}/entry/{order}"
    return run_governed(
        "pve_sdn_route_map_entry_update", tgt,
        plan=lambda: plan_route_map_entry_update(route_map_id, order, action, match, set_clauses,
                                                    exit_action, call, delete),
        execute=lambda: route_map_entry_update(api, route_map_id, order, action, match, set_clauses,
                                                   exit_action, call, delete, digest, lock_token),
        confirm=confirm)


@tool()
def pve_sdn_route_map_entry_delete(
    route_map_id: Annotated[str, Field(description="Existing SDN route map id.")],
    order: Annotated[int, Field(description="Entry position to delete (0-65535, required).")],
    lock_token: Annotated[str | None, Field(description="SDN cluster lock token to use for this write, if one is held.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the staged mutation.")] = False,
) -> dict:
    """MUTATION: delete a route-map entry (PENDING). Dry-run by default — the PLAN shows the
    current entry. If this is the LAST entry on this route-map id, whether PVE leaves an
    orphaned empty id or cleans it up automatically is UNDOCUMENTED (Smoke-confirm — no
    invented semantics). confirm=True stages the removal and returns {status, result}; no
    config UNDO — re-create the entry to revert. RISK_MEDIUM.
    """
    _, api, _, _ = _proximo_server._svc()
    tgt = f"sdn/route-maps/entries/{route_map_id}/entry/{order}"
    return run_governed(
        "pve_sdn_route_map_entry_delete", tgt,
        plan=lambda: plan_route_map_entry_delete(api, route_map_id, order),
        execute=lambda: route_map_entry_delete(api, route_map_id, order, lock_token),
        confirm=confirm)
