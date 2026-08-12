"""PVE ACME accounts/plugins and cert order/renew/revoke tools.

Split out of proximo.server (2026-07-02) — see proximo/server.py's module
docstring for the funnel these wrappers depend on.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.acme_certs import (
    acme_account_create,
    acme_account_delete,
    acme_account_update,
    acme_cert_order,
    acme_cert_renew,
    acme_cert_revoke,
    acme_plugin_create,
    acme_plugin_delete,
    acme_plugin_update,
    node_acme_config_set,
    plan_acme_account_create,
    plan_acme_account_delete,
    plan_acme_account_update,
    plan_acme_cert_order,
    plan_acme_cert_renew,
    plan_acme_cert_revoke,
    plan_acme_plugin_create,
    plan_acme_plugin_delete,
    plan_acme_plugin_update,
    plan_node_acme_domains_set,
)
from proximo.server import (
    run_governed,
    tool,
)

# ============================================================================
# Plane G — ACME & TLS Certs
# ============================================================================

@tool()
def pve_acme_account_create(
    name: Annotated[str, Field(description="Name to register the new ACME account under (cluster/acme/account/{name}).")],
    contact: Annotated[str, Field(description="Contact email address for the ACME account (CA renewal/expiry notices).")],
    tos_url: Annotated[str | None, Field(description="URL of the CA's terms-of-service to accept; omit to accept the CA's default ToS.")] = None,
    directory: Annotated[str | None, Field(description="ACME directory URL of the CA to register with; omit to use PVE's default CA.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the account registration.")] = False,
) -> dict:
    """MUTATION: register a new ACME account with the CA. Dry-run by default.

    Additive — does not affect any existing account. Pair with pve_acme_plugin_create (DNS-01) or
    standalone http-01, then pve_node_acme_domains_set + pve_acme_cert_order, to actually issue a
    cert; to remove an account instead use pve_acme_account_delete. confirm=True executes and
    returns {"status": "ok"}; the default returns a dry-run PLAN dict. Smoke-confirm: POST body
    shape (name in body) against a live PVE instance."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/acme/account/{name}"
    return run_governed(
        "pve_acme_account_create", tgt,
        plan=lambda: plan_acme_account_create(name, contact,
                                                   tos_url=tos_url, directory=directory),
        execute=lambda: acme_account_create(api, name, contact,
                                                tos_url=tos_url, directory=directory),
        confirm=confirm)


@tool()
def pve_acme_account_update(
    name: Annotated[str, Field(description="Name of the existing ACME account to update.")],
    contact: Annotated[str | None, Field(description="New contact email address for the ACME account; omit to leave unchanged.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: update ACME account contact info. Dry-run by default.

    LOW risk — metadata update only, no cert impact. To delete the account instead use
    pve_acme_account_delete. The dry-run PLAN includes the account's current config (contact,
    directory, tos); confirm=True executes and returns {"status": "ok"}."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/acme/account/{name}"
    return run_governed(
        "pve_acme_account_update", tgt,
        plan=lambda: plan_acme_account_update(api, name, contact=contact),
        execute=lambda: acme_account_update(api, name, contact=contact),
        confirm=confirm)


@tool()
def pve_acme_account_delete(
    name: Annotated[str, Field(description="Name of the ACME account to deactivate and delete from the CA.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the irreversible deletion.")] = False,
) -> dict:
    """MUTATION: IRREVERSIBLE — deactivate and delete an ACME account from the CA. Dry-run by default.

    HIGH risk: TLS lockout at cert expiry if this is the only account. The account key is
    destroyed — registering again with pve_acme_account_create creates a DIFFERENT CA account, not
    a restore of this one. The dry-run PLAN captures the current config as evidence only.
    confirm=True executes and returns {"status": "ok"}."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/acme/account/{name}"
    return run_governed(
        "pve_acme_account_delete", tgt,
        plan=lambda: plan_acme_account_delete(api, name),
        execute=lambda: acme_account_delete(api, name),
        confirm=confirm)


@tool()
def pve_acme_plugin_create(
    plugin_id: Annotated[str, Field(description="Identifier for the new ACME DNS challenge plugin (cluster/acme/plugins/{plugin_id}).")],
    plugin_type: Annotated[str, Field(description="ACME challenge plugin type, e.g. 'dns' for a DNS-01 challenge plugin.")],
    dns_api: Annotated[str | None, Field(description="DNS provider API name for a DNS-01 challenge (e.g. 'cf', 'route53'); maps to PVE's 'api' field.")] = None,
    data: Annotated[str | None, Field(description="Plugin-specific credential/config data (e.g. API tokens) required by the DNS provider.")] = None,
    disable: Annotated[bool | None, Field(description="Set to disable the plugin on creation; omit to leave it enabled.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the plugin creation.")] = False,
) -> dict:
    """MUTATION: create an ACME DNS challenge plugin. Dry-run by default.

    Additive — does not affect any existing plugin. dns_api = DNS provider name (e.g. 'cf',
    'route53'). Reference plugin_id from pve_node_acme_domains_set(plugin=...) to drive a DNS-01
    challenge with it; to remove the plugin use pve_acme_plugin_delete. confirm=True executes and
    returns {"status": "ok"}; the default returns a dry-run PLAN dict. Smoke-confirm: POST body
    shape (id in body) against a live PVE instance."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/acme/plugins/{plugin_id}"
    # dns_api maps to PVE's 'api' body field; the backend param is named 'backend', so no collision
    kw: dict = {}
    if dns_api is not None:
        kw["api"] = dns_api
    if data is not None:
        kw["data"] = data
    if disable is not None:
        kw["disable"] = disable
    return run_governed(
        "pve_acme_plugin_create", tgt,
        plan=lambda: plan_acme_plugin_create(plugin_id, plugin_type, **kw),
        execute=lambda: acme_plugin_create(api, plugin_id, plugin_type, **kw),
        confirm=confirm)


@tool()
def pve_acme_plugin_update(
    plugin_id: Annotated[str, Field(description="Identifier of the existing ACME DNS challenge plugin to update.")],
    dns_api: Annotated[str | None, Field(description="New DNS provider API name for a DNS-01 challenge; maps to PVE's 'api' field. Omit to leave unchanged.")] = None,
    data: Annotated[str | None, Field(description="New plugin-specific credential/config data; omit to leave unchanged.")] = None,
    disable: Annotated[bool | None, Field(description="Set to enable/disable the plugin; omit to leave unchanged.")] = None,
    digest: Annotated[str | None, Field(description="Config digest for optimistic-locking the update against concurrent changes; omit to skip the check.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: update an ACME DNS challenge plugin. Dry-run by default.

    MEDIUM risk — invalid new credentials break cert renewal for every domain using this plugin
    at the next attempt. To remove a plugin instead use pve_acme_plugin_delete. The dry-run PLAN
    includes the plugin's current config with any DNS-provider credential redacted; confirm=True
    executes and returns {"status": "ok"}."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/acme/plugins/{plugin_id}"
    # dns_api maps to PVE's 'api' field
    kw: dict = {}
    if dns_api is not None:
        kw["api"] = dns_api
    if data is not None:
        kw["data"] = data
    if disable is not None:
        kw["disable"] = disable
    if digest is not None:
        kw["digest"] = digest
    return run_governed(
        "pve_acme_plugin_update", tgt,
        plan=lambda: plan_acme_plugin_update(api, plugin_id, **kw),
        execute=lambda: acme_plugin_update(api, plugin_id, **kw),
        confirm=confirm)


@tool()
def pve_acme_plugin_delete(
    plugin_id: Annotated[str, Field(description="Identifier of the ACME DNS challenge plugin to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete an ACME DNS challenge plugin. Dry-run by default.

    HIGH risk: cert auto-renewal breaks for every domain using this plugin — TLS lockout at cert
    expiry unless a fallback challenge method is configured. No UNDO primitive — recreate with
    pve_acme_plugin_create, but the credentials must be re-supplied by the caller. The dry-run PLAN
    captures the current config (credential redacted) as evidence only; confirm=True executes and
    returns {"status": "ok"}."""
    _, api, _, _ = _proximo_server._svc()
    tgt = f"cluster/acme/plugins/{plugin_id}"
    return run_governed(
        "pve_acme_plugin_delete", tgt,
        plan=lambda: plan_acme_plugin_delete(api, plugin_id),
        execute=lambda: acme_plugin_delete(api, plugin_id),
        confirm=confirm)


# ---------------------------------------------------------------------------
# ACME cert order plane — the node-side "what to issue" + "do it now"
# (closes the gap: account+plugin existed, but nothing set node ACME domains nor ordered a cert)
# ---------------------------------------------------------------------------

@tool()
def pve_node_acme_domains_set(
    account: Annotated[str, Field(description="Name of the ACME account (created via pve_acme_account_create) to associate with the node.")],
    domains: Annotated[list[str], Field(description="Domain names to request a certificate for; replaces any existing acmedomainN entries on the node.")],
    node: Annotated[str | None, Field(description="Target PVE node name; omit to use the configured default node.")] = None,
    plugin: Annotated[str | None, Field(description="ACME DNS plugin ID for a DNS-01 challenge; omit to use standalone http-01 instead.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the node config change.")] = False,
) -> dict:
    """MUTATION: set a node's ACME account + domains (PUT /nodes/{node}/config). Dry-run by default.

    The "what to issue" half of an ACME cert: pair with pve_acme_account_create +
    pve_acme_plugin_create, then issue with pve_acme_cert_order. plugin=<id> uses a DNS-01
    challenge (written as acmedomain0..N=domain=...,plugin=...); omit plugin for standalone
    http-01 (domains ride in acme=...,domains=...). REPLACE semantics: stale acmedomainN entries
    are removed, not merged. MEDIUM — config only, no cert is issued by this step. confirm=True
    executes and returns {"status": "ok"}; the default returns a dry-run PLAN dict. Smoke-confirm:
    node-config body shape against a live PVE instance."""
    cfg, api, _, _ = _proximo_server._svc()
    n = node or cfg.node
    tgt = f"node/{n}/config:acme"
    return run_governed(
        "pve_node_acme_domains_set", tgt,
        plan=lambda: plan_node_acme_domains_set(api, n, account, domains, plugin),
        execute=lambda: node_acme_config_set(api, n, account, domains, plugin),
        confirm=confirm)


@tool()
def pve_acme_cert_order(
    node: Annotated[str | None, Field(description="Target PVE node name; omit to use the configured default node.")] = None,
    force: Annotated[bool, Field(description="Overwrite an existing custom certificate on the node if one is already installed.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True submits the ACME order task.")] = False,
) -> dict:
    """MUTATION: order a NEW ACME TLS certificate for the node's configured ACME domains. Dry-run
    by default. Async — returns a task UPID (poll pve_task_status/pve_task_wait).

    MEDIUM (lower than pve_node_cert_upload's HIGH): the cert is CA-validated and installed ONLY on
    a successful challenge — a failed challenge leaves the existing cert untouched, so it cannot
    lock you out. On success PVE reloads pveproxy. force=overwrite an existing custom cert.
    Revert to self-signed with pve_node_cert_delete. confirm=True to execute.
    Smoke-confirm: POST shape + async UPID against a live PVE instance."""
    cfg, api, _, _ = _proximo_server._svc()
    n = node or cfg.node
    tgt = f"node/{n}/certificates/acme/certificate"
    return run_governed(
        "pve_acme_cert_order", tgt,
        plan=lambda: plan_acme_cert_order(n, force=force),
        execute=lambda: acme_cert_order(api, n, force=force),
        confirm=confirm, outcome="submitted", detail={"force": force})


@tool()
def pve_acme_cert_renew(
    node: Annotated[str | None, Field(description="Target PVE node name; omit to use the configured default node.")] = None,
    force: Annotated[bool, Field(description="Renew now even if the current certificate has more than 30 days left before expiry.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True submits the ACME renewal task.")] = False,
) -> dict:
    """MUTATION: renew the node's existing ACME TLS certificate. Dry-run by default. Async — returns
    a task UPID (poll pve_task_status/pve_task_wait). MEDIUM: CA-validated, installed only on
    success (a failure can't lock you out); reloads pveproxy on success. force=renew even if more
    than 30 days to expiry. To order a fresh cert instead use pve_acme_cert_order; to revert to
    self-signed use pve_node_cert_delete. confirm=True to execute. Smoke-confirm: PUT shape + async
    UPID against a live PVE instance."""
    cfg, api, _, _ = _proximo_server._svc()
    n = node or cfg.node
    tgt = f"node/{n}/certificates/acme/certificate"
    return run_governed(
        "pve_acme_cert_renew", tgt,
        plan=lambda: plan_acme_cert_renew(n, force=force),
        execute=lambda: acme_cert_renew(api, n, force=force),
        confirm=confirm, outcome="submitted", detail={"force": force})


@tool()
def pve_acme_cert_revoke(
    node: Annotated[str | None, Field(description="Target PVE node name; omit to use the configured default node.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True submits the irreversible revocation task.")] = False,
) -> dict:
    """MUTATION: IRREVERSIBLE — revoke the node's ACME TLS certificate at the CA. Dry-run by default.
    Async — returns a UPID. HIGH: a revoked cert cannot be un-revoked; only a NEW pve_acme_cert_order
    restores trust. To fall back to PVE's self-signed cert WITHOUT revoking at the CA, use
    pve_node_cert_delete instead. confirm=True to execute. Smoke-confirm: DELETE shape against a live
    PVE instance."""
    cfg, api, _, _ = _proximo_server._svc()
    n = node or cfg.node
    tgt = f"node/{n}/certificates/acme/certificate"
    return run_governed(
        "pve_acme_cert_revoke", tgt,
        plan=lambda: plan_acme_cert_revoke(api, n),
        execute=lambda: acme_cert_revoke(api, n),
        confirm=confirm, outcome="submitted")
