"""PBS notifications plane wrappers (Wave 3a, full-surface campaign) —
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 3 decomposition (PBS notifications +
ACME)". See `proximo.pbs_notifications` module docstring for the full endpoint table, the
schema-verified facts (9 of them), and the secret-redaction posture.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_notifications import (
    notification_endpoint_create,
    notification_endpoint_delete,
    notification_endpoint_get,
    notification_endpoint_list,
    notification_endpoint_update,
    notification_matcher_delete,
    notification_matcher_field_values,
    notification_matcher_fields,
    notification_matcher_get,
    notification_matcher_set,
    notification_matchers_list,
    notification_target_test,
    notification_targets_list,
    plan_notification_endpoint_create,
    plan_notification_endpoint_delete,
    plan_notification_endpoint_update,
    plan_notification_matcher_delete,
    plan_notification_matcher_set,
    plan_notification_target_test,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Reads ---

@tool()
def pbs_notification_targets_list() -> list[dict]:
    """READ-ONLY: list all PBS notification targets (the unified list — name, type, comment,
    disable, origin — across every endpoint type). For an endpoint's full type-specific config
    use pbs_notification_endpoint_get. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_notification_targets_list", "pbs/config/notifications/targets",
                    lambda: notification_targets_list(pbs))


@tool()
def pbs_notification_endpoint_list(
    ep_type: Annotated[str | None, Field(description="Optional filter: one of gotify, sendmail, smtp, webhook. Omit to aggregate all 4 types.")] = None,
) -> list[dict]:
    """READ-ONLY: list PBS notification endpoints with their full type-specific config.
    Aggregates GET .../endpoints/{type} across all 4 types (or just one if ep_type is given) —
    PBS's own GET .../endpoints (no type) is a directory index, not a usable list. Each item is
    tagged with its 'type' (the per-type responses don't carry one). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/notifications/endpoints/{ep_type}" if ep_type else "pbs/config/notifications/endpoints"
    return _audited("pbs_notification_endpoint_list", tgt,
                    lambda: notification_endpoint_list(pbs, ep_type))


@tool()
def pbs_notification_endpoint_get(
    ep_type: Annotated[str, Field(description="Notification endpoint type: 'gotify', 'sendmail', 'smtp', or 'webhook'.")],
    name: Annotated[str, Field(description="Name of the notification endpoint.")],
) -> dict:
    """READ-ONLY: get one PBS notification endpoint's full type-specific config. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/notifications/endpoints/{ep_type}/{name}"
    return _audited("pbs_notification_endpoint_get", tgt,
                    lambda: notification_endpoint_get(pbs, ep_type, name))


@tool()
def pbs_notification_matchers_list() -> list[dict]:
    """READ-ONLY: list all PBS notification matchers (alert routing rules). Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_notification_matchers_list", "pbs/config/notifications/matchers",
                    lambda: notification_matchers_list(pbs))


@tool()
def pbs_notification_matcher_get(
    name: Annotated[str, Field(description="Name of the notification matcher.")],
) -> dict:
    """READ-ONLY: get one PBS notification matcher's full config. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/notifications/matchers/{name}"
    return _audited("pbs_notification_matcher_get", tgt,
                    lambda: notification_matcher_get(pbs, name))


@tool()
def pbs_notification_matcher_fields() -> list[dict]:
    """READ-ONLY: list all known metadata field NAMES a matcher's match-field rule can target
    (e.g. 'type', 'datastore'). No params. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_notification_matcher_fields", "pbs/config/notifications/matcher-fields",
                    lambda: notification_matcher_fields(pbs))


@tool()
def pbs_notification_matcher_field_values() -> list[dict]:
    """READ-ONLY: list all known (field, value) pairs the system currently recognizes for
    matcher rules. No params. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_notification_matcher_field_values", "pbs/config/notifications/matcher-field-values",
                    lambda: notification_matcher_field_values(pbs))


# --- Mutations: Endpoints ---

@tool()
def pbs_notification_endpoint_create(
    ep_type: Annotated[str, Field(description="Notification endpoint type: 'gotify', 'sendmail', 'smtp', or 'webhook'.")],
    name: Annotated[str, Field(description="Unique name for the new notification endpoint (2-32 chars, alnum start).")],
    comment: Annotated[str | None, Field(description="Optional free-text comment stored with the endpoint.")] = None,
    disable: Annotated[bool | None, Field(description="If True, create the endpoint disabled.")] = None,
    options: Annotated[dict | None, Field(description="Type-specific config fields, e.g. gotify: {'server':.., 'token':..}; sendmail: {'mailto':[..]}; smtp: {'server':.., 'port':.., 'mailto':[..]}; webhook: {'url':.., 'method':.., 'header':[..], 'secret':[..]}. Credential-shaped keys (token/password/secret/header) are redacted from the PLAN preview and the audit ledger, but ARE sent to PBS on confirm=True.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PBS notification endpoint. ep_type = gotify|sendmail|smtp|webhook.
    `options` carries the endpoint-specific config. Additive, RISK_LOW. Dry-run by default
    (returns a PLAN — any secret in `options` is masked to "[redacted]" in the preview);
    confirm=True executes (POST .../endpoints/{type}, synchronous — PBS returns null, not a task)
    and returns {"status": "ok", "result": None}. To modify an existing endpoint use
    pbs_notification_endpoint_update. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/notifications/endpoints/{ep_type}/{name}"
    kw = {"comment": comment, "disable": disable, **(options or {})}
    return run_governed(
        "pbs_notification_endpoint_create", tgt,
        plan=lambda: plan_notification_endpoint_create(ep_type, name, **kw),
        execute=lambda: notification_endpoint_create(pbs, ep_type, name, **kw),
        confirm=confirm)


@tool()
def pbs_notification_endpoint_update(
    ep_type: Annotated[str, Field(description="Notification endpoint type: 'gotify', 'sendmail', 'smtp', or 'webhook'.")],
    name: Annotated[str, Field(description="Name of the existing notification endpoint to update.")],
    comment: Annotated[str | None, Field(description="Optional free-text comment to set on the endpoint.")] = None,
    disable: Annotated[bool | None, Field(description="True disables the endpoint; False re-enables it.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned. If set and stale, PBS rejects the update.")] = None,
    options: Annotated[dict | None, Field(description="Type-specific fields to change, same shape as create. Credential-shaped keys (token/password/secret/header) are redacted from the PLAN preview and the audit ledger, but ARE sent to PBS on confirm=True.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: update a PBS notification endpoint. ep_type = gotify|sendmail|smtp|webhook.
    Dry-run by default — captures current config into the PLAN (secrets masked); confirm=True
    executes (PUT .../endpoints/{type}/{name}, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. No snapshot primitive; re-apply the captured config to
    revert, or use pbs_notification_endpoint_create to make a new one instead. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/notifications/endpoints/{ep_type}/{name}"
    kw = {"comment": comment, "disable": disable, "digest": digest, **(options or {})}
    return run_governed(
        "pbs_notification_endpoint_update", tgt,
        plan=lambda: plan_notification_endpoint_update(pbs, ep_type, name, **kw),
        execute=lambda: notification_endpoint_update(pbs, ep_type, name, **kw),
        confirm=confirm)


@tool()
def pbs_notification_endpoint_delete(
    ep_type: Annotated[str, Field(description="Notification endpoint type: 'gotify', 'sendmail', 'smtp', or 'webhook'.")],
    name: Annotated[str, Field(description="Name of the notification endpoint to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PBS notification endpoint. ep_type = gotify|sendmail|smtp|webhook.
    Dry-run by default — captures current config (secrets masked). confirm=True executes
    (DELETE .../endpoints/{type}/{name}, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. No UNDO primitive — matchers referencing this endpoint
    silently fail until it is re-created with pbs_notification_endpoint_create. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/notifications/endpoints/{ep_type}/{name}"
    return run_governed(
        "pbs_notification_endpoint_delete", tgt,
        plan=lambda: plan_notification_endpoint_delete(pbs, ep_type, name),
        execute=lambda: notification_endpoint_delete(pbs, ep_type, name),
        confirm=confirm)


# --- Mutations: Matchers ---

@tool()
def pbs_notification_matcher_set(
    name: Annotated[str, Field(description="Name of the notification matcher (alert routing rule) to create or update (2-32 chars, alnum start).")],
    comment: Annotated[str | None, Field(description="Optional free-text comment stored with the matcher.")] = None,
    mode: Annotated[str | None, Field(description="How match-* filters combine: 'all' (default on PBS) or 'any'.")] = None,
    match_severity: Annotated[list[str] | None, Field(description="Severity levels to match (e.g. ['error','warning']).")] = None,
    match_field: Annotated[list[str] | None, Field(description="Metadata field filters to match (see pbs_notification_matcher_fields for known names).")] = None,
    match_calendar: Annotated[list[str] | None, Field(description="Calendar-event time-window filters to match.")] = None,
    invert_match: Annotated[bool | None, Field(description="If True, invert the whole filter's match result.")] = None,
    target: Annotated[list[str] | None, Field(description="Names of endpoints/targets to notify when this matcher fires.")] = None,
    disable: Annotated[bool | None, Field(description="If True, disable this matcher without deleting it.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock (update only): 64-char lowercase hex SHA-256 of the config PBS last returned. Ignored on create — PBS's own create schema has no digest field.")] = None,
    delete: Annotated[list[str] | None, Field(description="Update only: property names to clear (e.g. ['comment','target']). Ignored on create.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the create/update.")] = False,
) -> dict:
    """MUTATION: create-or-update a PBS notification matcher (alert routing rule). One safe read
    of the matchers collection decides create (POST, name in body) vs update (PUT .../{name}) —
    `digest`/`delete` only apply to the update branch. Dry-run by default (returns a PLAN);
    confirm=True executes (synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. No snapshot primitive — re-apply with this same tool to
    restore after deletion. To remove a matcher use pbs_notification_matcher_delete. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/notifications/matchers/{name}"
    return run_governed(
        "pbs_notification_matcher_set", tgt,
        plan=lambda: plan_notification_matcher_set(
                     name, comment=comment, mode=mode, match_severity=match_severity,
                     match_field=match_field, match_calendar=match_calendar,
                     invert_match=invert_match, target=target, disable=disable,
                     digest=digest, delete=delete),
        execute=lambda: notification_matcher_set(
                        pbs, name, comment=comment, mode=mode, match_severity=match_severity,
                        match_field=match_field, match_calendar=match_calendar,
                        invert_match=invert_match, target=target, disable=disable,
                        digest=digest, delete=delete),
        confirm=confirm)


@tool()
def pbs_notification_matcher_delete(
    name: Annotated[str, Field(description="Name of the notification matcher to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PBS notification matcher. Dry-run by default. confirm=True executes
    (DELETE .../matchers/{name}, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. No UNDO primitive — alerts matching this filter go
    un-routed until re-created with pbs_notification_matcher_set. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/notifications/matchers/{name}"
    return run_governed(
        "pbs_notification_matcher_delete", tgt,
        plan=lambda: plan_notification_matcher_delete(name),
        execute=lambda: notification_matcher_delete(pbs, name),
        confirm=confirm)


# --- Mutation: Target Test ---

@tool()
def pbs_notification_target_test(
    name: Annotated[str, Field(description="Name of the notification target (endpoint or matcher) to send a test notification to.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True SENDS A REAL test notification.")] = False,
) -> dict:
    """MUTATION: send a REAL test notification to a PBS notification target. Dry-run by default
    (returns a PLAN, nothing is sent); confirm=True SENDS A REAL NOTIFICATION to the target's
    recipients/webhook/gotify server and returns {"status": "ok", "result": None} (synchronous —
    PBS returns null). No config changes. `name` is an existing endpoint or matcher name — see
    pbs_notification_targets_list for target names. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/notifications/targets/{name}"
    return run_governed(
        "pbs_notification_target_test", tgt,
        plan=lambda: plan_notification_target_test(name),
        execute=lambda: notification_target_test(pbs, name),
        confirm=confirm)
