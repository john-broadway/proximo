"""Notifications & Metrics plane — PVE notification endpoints, matchers, and metrics servers.

Covers Plane E (PLAN + PROVE; no UNDO primitive — config is re-creatable after delete):
  - PVE notification endpoints  (/cluster/notifications/endpoints)
  - PVE notification matchers   (/cluster/notifications/matchers)
  - PVE notification target test (/cluster/notifications/targets)
  - PVE metrics server defs     (/cluster/metrics/server)

VERIFIED live shapes: None — all endpoint shapes carry "Smoke-confirm:" comments.

Security posture:
  - All path components validated with \\Z-anchored regexes (trailing-newline bypass rejected).
  - Endpoint type validated against a closed frozenset (no arbitrary string into URL path).
  - No snapshot primitive on this plane — plans declare re-creatable, NEVER imply undo.
  - RISK_LOW: config only; DELETE stops alerts/metrics silently (noted in plan honesty text).
"""

from __future__ import annotations

import re

from ._validate import redact_secrets
from .backends import ProximoError
from .planning import RISK_LOW, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# PVE notification endpoint types — documented PVE 8.x values (closed frozenset).
# Smoke-confirm: full accepted set on the deployed PVE version.
_VALID_ENDPOINT_TYPES = frozenset({"gotify", "smtp", "sendmail", "webhook"})

# Notification endpoint/matcher name: path segment in /cluster/notifications/endpoints/{type}/{name}
# Smoke-confirm: exact accepted charset and length limit against a live PVE instance.
_ENDPOINT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")

# Metrics server ID: path segment in /cluster/metrics/server/{id}
# Smoke-confirm: exact accepted charset and length limit.
_METRICS_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")

# Credential-shaped fields endpoint types carry: gotify `token`, smtp SMTP-AUTH `password`,
# webhook `secret` (HMAC/auth secret array, value base64-encoded by PVE) and `header` (can
# carry `Authorization: Bearer ...`). plan.change/current are BOTH returned to the caller AND
# written to the tamper-evident PROVE ledger, so the raw value must never appear there.
# WIDENED to match pbs_notifications.py's set — the two earlier keys missed webhook secrets.
_SECRET_KEYS = frozenset({"token", "password", "secret", "header"})


def _redact_secrets(d: dict) -> dict:
    """Mask credential-shaped fields before they enter a plan string or Plan.current — the
    shared `_validate.redact_secrets` mechanic over this plane's own `_SECRET_KEYS`."""
    return redact_secrets(d, _SECRET_KEYS)


def _check_endpoint_type(ep_type: str) -> str:
    # Do NOT strip — stripping defeats \\Z trailing-newline protection.
    if ep_type not in _VALID_ENDPOINT_TYPES:
        raise ProximoError(
            f"invalid notification endpoint type: {ep_type!r} "
            f"(expected one of {sorted(_VALID_ENDPOINT_TYPES)})"
        )
    return ep_type


def _check_endpoint_name(name: str) -> str:
    s = str(name)
    if not _ENDPOINT_NAME_RE.match(s):
        raise ProximoError(
            f"invalid notification endpoint/matcher name: {name!r} "
            "(must start with alnum, then alnum/_/-, <=64 chars, no slash)"
        )
    return s


def _check_metrics_id(metrics_id: str) -> str:
    s = str(metrics_id)
    if not _METRICS_ID_RE.match(s):
        raise ProximoError(
            f"invalid metrics server ID: {metrics_id!r} "
            "(must start with alnum, then alnum/_/-, <=64 chars, no slash)"
        )
    return s


# ---------------------------------------------------------------------------
# PVE Notification Endpoint operations
# ---------------------------------------------------------------------------

def notification_endpoint_list(api) -> list[dict]:
    """List all PVE notification endpoints (all types: gotify, smtp, sendmail, webhook).

    GET /cluster/notifications/endpoints
    Smoke-confirm: response shape — expected list of dicts with 'type' and 'name' fields.
    """
    return api._get("/cluster/notifications/endpoints") or []


def notification_endpoint_get(api, ep_type: str, name: str) -> dict:
    """Get one PVE notification endpoint config.

    GET /cluster/notifications/endpoints/{type}/{name}
    Smoke-confirm: exact response shape per endpoint type.
    """
    ep_type = _check_endpoint_type(ep_type)
    _check_endpoint_name(name)
    return api._get(f"/cluster/notifications/endpoints/{ep_type}/{name}") or {}


def notification_endpoint_create(api, ep_type: str, name: str, **kw) -> None:
    """Create a new PVE notification endpoint.

    POST /cluster/notifications/endpoints/{type}   (name goes in the BODY, not the path —
    live-confirmed 2026-06-25: POST to .../{type}/{name} returns 501 Not Implemented).
    Body: {name, ...type-specific options (server, port, recipients, token, ...)}
    MUTATION — confirm-gated + audited at the server layer.
    """
    ep_type = _check_endpoint_type(ep_type)
    _check_endpoint_name(name)
    data = {"name": name, **{k: v for k, v in kw.items() if v is not None}}
    # MUTATION — confirm-gated + audited at the server layer.
    api._post(f"/cluster/notifications/endpoints/{ep_type}", data)


def notification_endpoint_update(api, ep_type: str, name: str, **kw) -> None:
    """Update a PVE notification endpoint.

    PUT /cluster/notifications/endpoints/{type}/{name}
    Smoke-confirm: exact accepted body fields per endpoint type.
    MUTATION — confirm-gated + audited at the server layer.
    """
    ep_type = _check_endpoint_type(ep_type)
    _check_endpoint_name(name)
    data = {k: v for k, v in kw.items() if v is not None}
    # MUTATION — confirm-gated + audited at the server layer.
    api._put(f"/cluster/notifications/endpoints/{ep_type}/{name}", data)


def notification_endpoint_delete(api, ep_type: str, name: str) -> None:
    """Delete a PVE notification endpoint. Config is re-creatable; alerts via this endpoint fail.

    DELETE /cluster/notifications/endpoints/{type}/{name}
    Smoke-confirm: response shape.
    MUTATION — confirm-gated + audited at the server layer.
    """
    ep_type = _check_endpoint_type(ep_type)
    _check_endpoint_name(name)
    # MUTATION — confirm-gated + audited at the server layer.
    api._delete(f"/cluster/notifications/endpoints/{ep_type}/{name}")


# ---------------------------------------------------------------------------
# PVE Notification Matcher operations
# ---------------------------------------------------------------------------

def notification_matcher_set(api, name: str, **kw) -> None:
    """Create-or-update a PVE notification matcher (routing rule).

    Create: POST /cluster/notifications/matchers        {name, comment, ...}
    Update: PUT  /cluster/notifications/matchers/{name}  {comment, ...}
    Schema-verified 2026-07-06 (pve-docs api-viewer): the {name} path accepts only
    GET/PUT/DELETE — POST goes to the collection with the name in the body, so the
    upsert needs one safe read to pick the verb.
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_endpoint_name(name)
    data = {k: v for k, v in kw.items() if v is not None}
    existing = api._get("/cluster/notifications/matchers") or []
    names = {m.get("name") for m in existing if isinstance(m, dict)}
    # MUTATION — confirm-gated + audited at the server layer.
    if name in names:
        api._put(f"/cluster/notifications/matchers/{name}", data)
    else:
        api._post("/cluster/notifications/matchers", {"name": name, **data})


def notification_matcher_delete(api, name: str) -> None:
    """Delete a PVE notification matcher. Alerts matching this rule go un-routed.

    DELETE /cluster/notifications/matchers/{name}
    Smoke-confirm: response shape.
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_endpoint_name(name)
    # MUTATION — confirm-gated + audited at the server layer.
    api._delete(f"/cluster/notifications/matchers/{name}")


# ---------------------------------------------------------------------------
# PVE Notification Test operation
# ---------------------------------------------------------------------------

def notification_test(api, name: str) -> None:
    """Send a test notification to a PVE notification target (endpoint or matcher target).

    POST /cluster/notifications/targets/{name}/test
    Sends a REAL test notification — recipients will receive it.
    Smoke-confirm: exact path shape; whether body is needed.
    MUTATION — confirm-gated + audited at the server layer (real notification sent).
    """
    _check_endpoint_name(name)
    # MUTATION — confirm-gated + audited at the server layer.
    api._post(f"/cluster/notifications/targets/{name}/test")


# ---------------------------------------------------------------------------
# PVE Metrics Server operations
# ---------------------------------------------------------------------------

def metrics_server_list(api) -> list[dict]:
    """List all PVE metrics server definitions.

    GET /cluster/metrics/server
    Smoke-confirm: response shape — expected list of dicts with 'id', 'type', 'server' fields.
    """
    return api._get("/cluster/metrics/server") or []


def metrics_server_set(api, metrics_id: str, **kw) -> None:
    """Create-or-update a PVE metrics server definition.

    POST /cluster/metrics/server/{id}  (create)
    PUT  /cluster/metrics/server/{id}  (update)
    Body: {type, server, port, influxdbproto?, ...}
    Smoke-confirm: exact path (POST for create, PUT for update), required body fields.
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_metrics_id(metrics_id)
    data = {k: v for k, v in kw.items() if v is not None}
    # Smoke-confirm: PVE uses POST for create and PUT for update; using POST here as upsert.
    # MUTATION — confirm-gated + audited at the server layer.
    api._post(f"/cluster/metrics/server/{metrics_id}", data)


def metrics_server_delete(api, metrics_id: str) -> None:
    """Delete a PVE metrics server definition. Metrics forwarding ceases; config is re-creatable.

    DELETE /cluster/metrics/server/{id}
    Smoke-confirm: response shape.
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_metrics_id(metrics_id)
    # MUTATION — confirm-gated + audited at the server layer.
    api._delete(f"/cluster/metrics/server/{metrics_id}")


# ---------------------------------------------------------------------------
# Plan factories — Notification Endpoints
# ---------------------------------------------------------------------------

def plan_notification_endpoint_create(ep_type: str, name: str, **kw) -> Plan:
    """Plan creating a PVE notification endpoint (additive, LOW risk)."""
    _check_endpoint_type(ep_type)
    _check_endpoint_name(name)
    return Plan(
        action="pve_notification_endpoint_create",
        target=f"cluster/notifications/endpoints/{ep_type}/{name}",
        change=f"create PVE {ep_type!r} notification endpoint {name!r}: {_redact_secrets(kw)}",
        current={},
        blast_radius=["adds a new notification delivery channel (no existing alerts affected)"],
        risk=RISK_LOW,
        risk_reasons=["additive config — creates a new notification endpoint"],
        note=(
            "No snapshot primitive on this plane. Deleting the endpoint removes the config and "
            "silently stops alert delivery via this channel. Re-create with "
            "pve_notification_endpoint_create to restore."
        ),
    )


def plan_notification_endpoint_update(api, ep_type: str, name: str, **kw) -> Plan:
    """Plan updating a PVE notification endpoint. Reads current config for honesty."""
    _check_endpoint_type(ep_type)
    _check_endpoint_name(name)
    current = _redact_secrets(notification_endpoint_get(api, ep_type, name))
    return Plan(
        action="pve_notification_endpoint_update",
        target=f"cluster/notifications/endpoints/{ep_type}/{name}",
        change=f"update PVE {ep_type!r} notification endpoint {name!r}: {_redact_secrets(kw)}",
        current=current,
        blast_radius=["modifies delivery settings for an existing notification endpoint"],
        risk=RISK_LOW,
        risk_reasons=["config-only change — affects future notifications for this endpoint"],
        note=(
            "No snapshot primitive on this plane. Current config captured above — "
            "re-apply it manually to revert."
        ),
    )


def plan_notification_endpoint_delete(api, ep_type: str, name: str) -> Plan:
    """Plan deleting a PVE notification endpoint. Reads current config for honesty."""
    _check_endpoint_type(ep_type)
    _check_endpoint_name(name)
    current = _redact_secrets(notification_endpoint_get(api, ep_type, name))
    return Plan(
        action="pve_notification_endpoint_delete",
        target=f"cluster/notifications/endpoints/{ep_type}/{name}",
        change=f"delete PVE {ep_type!r} notification endpoint {name!r}",
        current=current,
        blast_radius=[
            "removes the notification endpoint config",
            "matchers referencing this endpoint will silently fail to deliver",
        ],
        risk=RISK_LOW,
        risk_reasons=["config-only change — may cause silent alert delivery failures"],
        note=(
            "No UNDO primitive on this plane. Current config captured above — "
            "re-create with pve_notification_endpoint_create to restore. "
            "WARN: matchers referencing this endpoint will silently fail until restored."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — Notification Matchers
# ---------------------------------------------------------------------------

def plan_notification_matcher_set(name: str, **kw) -> Plan:
    """Plan creating-or-updating a PVE notification matcher."""
    _check_endpoint_name(name)
    return Plan(
        action="pve_notification_matcher_set",
        target=f"cluster/notifications/matchers/{name}",
        change=f"create-or-update PVE notification matcher {name!r}: {kw}",
        current={},
        blast_radius=["creates or updates alert routing rules"],
        risk=RISK_LOW,
        risk_reasons=["config-only change — routes which endpoints receive which alerts"],
        note=(
            "No snapshot primitive on this plane. Re-create with pve_notification_matcher_set "
            "to restore after deletion."
        ),
    )


def plan_notification_matcher_delete(name: str) -> Plan:
    """Plan deleting a PVE notification matcher."""
    _check_endpoint_name(name)
    return Plan(
        action="pve_notification_matcher_delete",
        target=f"cluster/notifications/matchers/{name}",
        change=f"delete PVE notification matcher {name!r}",
        current={},
        blast_radius=[
            "removes the alert routing rule",
            "alerts matching this filter will no longer be routed to its endpoints",
        ],
        risk=RISK_LOW,
        risk_reasons=["config-only change — alerts may go undelivered after deletion"],
        note=(
            "No UNDO primitive on this plane. Re-create with pve_notification_matcher_set to restore. "
            "WARN: alerts will be silently un-routed until restored."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — Notification Test
# ---------------------------------------------------------------------------

def plan_notification_test(name: str) -> Plan:
    """Plan sending a test notification to a PVE target."""
    _check_endpoint_name(name)
    return Plan(
        action="pve_notification_test",
        target=f"cluster/notifications/targets/{name}",
        change=f"send test notification to PVE target {name!r}",
        current={},
        blast_radius=["sends a real test notification — recipients will see a test message"],
        risk=RISK_LOW,
        risk_reasons=["side-effect only — no config state is changed"],
        note=(
            "Sends a real notification; confirm=True triggers delivery. "
            "No config change — only the notification channel is exercised."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — Metrics Servers
# ---------------------------------------------------------------------------

def plan_metrics_server_set(metrics_id: str, **kw) -> Plan:
    """Plan creating-or-updating a PVE metrics server definition.

    Redacts `kw` before it enters the plan `change` string, same as its
    `plan_notification_endpoint_create`/`_update` siblings above (`_SECRET_KEYS = {"token",
    "password"}`). Latent-leak hardening: PVE's live `/cluster/metrics/server` schema DOES carry
    an optional per-server `token` field ("The InfluxDB access token. Only necessary when using
    the http v2 api.") — `pve_metrics_server_set`'s current tool surface doesn't expose a `token`
    parameter to callers, so no live leak exists today, but `metrics_server_set`/this factory both
    forward arbitrary `**kw`, and a future tool-surface widening to add `token` would otherwise
    leak it into the dry-run PLAN and the PROVE ledger on day one (Wave 5b review finding 2)."""
    _check_metrics_id(metrics_id)
    return Plan(
        action="pve_metrics_server_set",
        target=f"cluster/metrics/server/{metrics_id}",
        change=f"create-or-update PVE metrics server {metrics_id!r}: {_redact_secrets(kw)}",
        current={},
        blast_radius=["creates or updates a metrics forwarding target"],
        risk=RISK_LOW,
        risk_reasons=["config-only change — metrics forwarding is additive/modifying"],
        note=(
            "No snapshot primitive on this plane. Re-create with pve_metrics_server_set to restore "
            "after deletion."
        ),
    )


def plan_metrics_server_delete(metrics_id: str) -> Plan:
    """Plan deleting a PVE metrics server definition."""
    _check_metrics_id(metrics_id)
    return Plan(
        action="pve_metrics_server_delete",
        target=f"cluster/metrics/server/{metrics_id}",
        change=f"delete PVE metrics server definition {metrics_id!r}",
        current={},
        blast_radius=[
            "removes the metrics forwarding config",
            "metrics will no longer be forwarded to this server after deletion",
        ],
        risk=RISK_LOW,
        risk_reasons=["config-only change — stops metrics forwarding, no data loss"],
        note=(
            "No UNDO primitive on this plane. Re-create with pve_metrics_server_set to restore."
        ),
    )
