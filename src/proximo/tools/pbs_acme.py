"""PBS ACME plane wrappers (Wave 3b, full-surface campaign) —
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 3 decomposition (PBS notifications +
ACME)". See `proximo.pbs_acme` module docstring for the full endpoint table, the schema-verified
facts (10 of them, incl. no PBS cert revoke and both cert order/renew declaring a null return),
and the secret-redaction posture.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_acme import (
    acme_account_create,
    acme_account_delete,
    acme_account_get,
    acme_account_list,
    acme_account_update,
    acme_cert_order,
    acme_cert_renew,
    acme_challenge_schema,
    acme_directories,
    acme_plugin_create,
    acme_plugin_delete,
    acme_plugin_get,
    acme_plugin_update,
    acme_plugins_list,
    acme_tos,
    plan_acme_account_create,
    plan_acme_account_delete,
    plan_acme_account_update,
    plan_acme_cert_order,
    plan_acme_cert_renew,
    plan_acme_plugin_create,
    plan_acme_plugin_delete,
    plan_acme_plugin_update,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Reads ---

@tool()
def pbs_acme_account_list() -> list[dict]:
    """READ-ONLY: list registered PBS ACME account NAMES (the schema's own response item is
    `{"name": str}` only — use pbs_acme_account_get for full account detail). Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_acme_account_list", "pbs/config/acme/account",
                    lambda: acme_account_list(pbs))


@tool()
def pbs_acme_account_get(
    name: Annotated[str, Field(description="Name of the ACME account.")],
) -> dict:
    """READ-ONLY: get one PBS ACME account's full config (account/directory/location/tos). Does
    NOT include eab_hmac_key — PBS never returns it on read. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/acme/account/{name}"
    return _audited("pbs_acme_account_get", tgt, lambda: acme_account_get(pbs, name))


@tool()
def pbs_acme_directories() -> list[dict]:
    """READ-ONLY: list PBS's built-in catalog of known ACME CA directory endpoints (name + URL
    pairs, e.g. Let's Encrypt production/staging). No params. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_acme_directories", "pbs/config/acme/directories",
                    lambda: acme_directories(pbs))


@tool()
def pbs_acme_tos(
    directory: Annotated[str | None, Field(description="ACME directory URL to look up the Terms of Service for; omit to use PBS's default CA.")] = None,
) -> str | None:
    """READ-ONLY: get the Terms-of-Service URL for an ACME directory (or None if the CA
    advertises no ToS). The PBS host fetches the given directory URL live (https-only,
    validated) and the response is authored by whoever controls that URL — classified
    ADVERSARIAL in the taint control for exactly that reason. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_acme_tos", "pbs/config/acme/tos", lambda: acme_tos(pbs, directory))


@tool()
def pbs_acme_challenge_schema() -> list[dict]:
    """READ-ONLY: list the catalog of known ACME challenge plugin types (id/name/schema/type per
    entry) — the parameter schema each plugin `type`+`data` pairing must satisfy. No params.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_acme_challenge_schema", "pbs/config/acme/challenge-schema",
                    lambda: acme_challenge_schema(pbs))


@tool()
def pbs_acme_plugins_list() -> list[dict]:
    """READ-ONLY: list all configured PBS ACME DNS challenge plugins, INCLUDING the raw `data`
    credential blob for each (PBS does not strip it on read). Handle the result as sensitive.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_acme_plugins_list", "pbs/config/acme/plugins",
                    lambda: acme_plugins_list(pbs))


@tool()
def pbs_acme_plugin_get(
    plugin_id: Annotated[str, Field(description="ID of the ACME DNS challenge plugin.")],
) -> dict:
    """READ-ONLY: get one PBS ACME plugin's full config, INCLUDING the raw `data` credential
    blob (PBS does not strip it on read). Handle the result as sensitive. Needs PROXIMO_PBS_*
    config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/acme/plugins/{plugin_id}"
    return _audited("pbs_acme_plugin_get", tgt, lambda: acme_plugin_get(pbs, plugin_id))


# --- Mutations: Accounts ---

@tool()
def pbs_acme_account_create(
    contact: Annotated[str, Field(description="Contact email address for the ACME account (CA renewal/expiry notices).")],
    name: Annotated[str | None, Field(description="Name to register the account under; omit to let PBS assign a default name.")] = None,
    directory: Annotated[str | None, Field(description="ACME directory URL of the CA to register with; omit to use PBS's default CA.")] = None,
    eab_hmac_key: Annotated[str | None, Field(description="HMAC key for External Account Binding (required by some CAs, e.g. ZeroSSL). Redacted from the PLAN preview and the audit ledger, but IS sent to PBS on confirm=True.")] = None,
    eab_kid: Annotated[str | None, Field(description="Key identifier for External Account Binding; pairs with eab_hmac_key.")] = None,
    tos_url: Annotated[str | None, Field(description="URL of the CA's terms-of-service to accept; omit to accept the CA's default ToS.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the account registration.")] = False,
) -> dict:
    """MUTATION: register a new ACME account with the CA. Dry-run by default.

    Additive — does not affect any existing account. Pair with pbs_acme_plugin_create (DNS-01
    challenge), then pbs_acme_cert_order, to actually issue a cert; to remove an account instead
    use pbs_acme_account_delete. confirm=True executes (POST /config/acme/account, synchronous —
    PBS returns null) and returns {"status": "ok", "result": None}; the default returns a dry-run
    PLAN dict. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/acme/account/{name}" if name else "pbs/config/acme/account"
    return run_governed(
        "pbs_acme_account_create", tgt,
        plan=lambda: plan_acme_account_create(
                     contact, name=name, directory=directory, eab_hmac_key=eab_hmac_key,
                     eab_kid=eab_kid, tos_url=tos_url),
        execute=lambda: acme_account_create(
                        pbs, contact, name=name, directory=directory,
                        eab_hmac_key=eab_hmac_key, eab_kid=eab_kid, tos_url=tos_url),
        confirm=confirm)


@tool()
def pbs_acme_account_update(
    name: Annotated[str, Field(description="Name of the existing ACME account to update.")],
    contact: Annotated[str | None, Field(description="New contact email address for the ACME account; omit to leave unchanged.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: update ACME account contact info. Dry-run by default.

    LOW risk — metadata update only, no cert impact. PBS's PUT accepts ONLY contact (no eab/tos
    fields on update — those are create-only). To delete the account instead use
    pbs_acme_account_delete. confirm=True executes (synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/acme/account/{name}"
    return run_governed(
        "pbs_acme_account_update", tgt,
        plan=lambda: plan_acme_account_update(pbs, name, contact=contact),
        execute=lambda: acme_account_update(pbs, name, contact=contact),
        confirm=confirm)


@tool()
def pbs_acme_account_delete(
    name: Annotated[str, Field(description="Name of the ACME account to deactivate and delete from the CA.")],
    force: Annotated[bool, Field(description="Delete the local account record even if the CA refuses to deactivate it.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the irreversible deletion.")] = False,
) -> dict:
    """MUTATION: IRREVERSIBLE — DEACTIVATES an ACME account at the CA (not just local config
    removal) and deletes the local record. Dry-run by default.

    HIGH risk: TLS lockout at cert expiry if this is the only account. The account key is
    destroyed — registering again with pbs_acme_account_create creates a DIFFERENT CA account,
    not a restore of this one. force=delete local data even if the CA refuses to deactivate
    (PBS-only escape hatch; PVE's equivalent tool has no such flag). The dry-run PLAN captures the
    current config as evidence only. confirm=True executes (synchronous — PBS returns null) and
    returns {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/acme/account/{name}"
    return run_governed(
        "pbs_acme_account_delete", tgt,
        plan=lambda: plan_acme_account_delete(pbs, name, force=force),
        execute=lambda: acme_account_delete(pbs, name, force=force),
        confirm=confirm, detail={"force": force})


# --- Mutations: Plugins ---

@tool()
def pbs_acme_plugin_create(
    plugin_id: Annotated[str, Field(description="Identifier for the new ACME DNS challenge plugin (1-32 chars, alnum/_/./- ; config/acme/plugins/{plugin_id}).")],
    plugin_type: Annotated[str, Field(description="ACME challenge plugin type (e.g. 'dns' or 'standalone'). PBS's own schema declares no enum here — validated defensively by charset only; see pbs_acme_challenge_schema for the live catalog of known types.")],
    dns_api: Annotated[str | None, Field(description="DNS provider API name for a DNS-01 challenge (e.g. 'cf', 'route53'); maps to PBS's 'api' field.")] = None,
    data: Annotated[str | None, Field(description="Base64-encoded plugin credential/config data (e.g. DNS provider API tokens) required by the challenge type. Redacted from the PLAN preview and the audit ledger, but IS sent to PBS on confirm=True.")] = None,
    disable: Annotated[bool | None, Field(description="Set to disable the plugin on creation; omit to leave it enabled.")] = None,
    validation_delay: Annotated[int | None, Field(description="Extra delay in seconds (0-172800) to wait before requesting validation — copes with long DNS TTLs.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the plugin creation.")] = False,
) -> dict:
    """MUTATION: create an ACME DNS challenge plugin. Dry-run by default.

    Additive — does not affect any existing plugin. dns_api = DNS provider name (e.g. 'cf',
    'route53'). Reference plugin_id when ordering a cert via a DNS-01 challenge; to remove the
    plugin use pbs_acme_plugin_delete. confirm=True executes (POST /config/acme/plugins,
    synchronous — PBS returns null) and returns {"status": "ok", "result": None}. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/acme/plugins/{plugin_id}"
    kw: dict = {}
    if dns_api is not None:
        kw["api"] = dns_api
    if data is not None:
        kw["data"] = data
    if disable is not None:
        kw["disable"] = disable
    if validation_delay is not None:
        kw["validation_delay"] = validation_delay
    return run_governed(
        "pbs_acme_plugin_create", tgt,
        plan=lambda: plan_acme_plugin_create(plugin_id, plugin_type, **kw),
        execute=lambda: acme_plugin_create(pbs, plugin_id, plugin_type, **kw),
        confirm=confirm)


@tool()
def pbs_acme_plugin_update(
    plugin_id: Annotated[str, Field(description="Identifier of the existing ACME DNS challenge plugin to update.")],
    dns_api: Annotated[str | None, Field(description="New DNS provider API name; maps to PBS's 'api' field. Omit to leave unchanged.")] = None,
    data: Annotated[str | None, Field(description="New base64-encoded plugin credential/config data; omit to leave unchanged. Redacted from the PLAN preview and the audit ledger, but IS sent to PBS on confirm=True.")] = None,
    disable: Annotated[bool | None, Field(description="Set to enable/disable the plugin; omit to leave unchanged.")] = None,
    validation_delay: Annotated[int | None, Field(description="New validation-delay in seconds (0-172800); omit to leave unchanged.")] = None,
    digest: Annotated[str | None, Field(description="Config digest for optimistic-locking the update against concurrent changes; omit to skip the check.")] = None,
    delete: Annotated[list[str] | None, Field(description="Property names to clear: 'disable' and/or 'validation-delay' (the only two the schema allows).")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: update an ACME DNS challenge plugin. Dry-run by default.

    MEDIUM risk — invalid new credentials break cert renewal for every domain using this plugin
    at the next attempt. To remove a plugin instead use pbs_acme_plugin_delete. The dry-run PLAN
    includes the plugin's current config with the credential blob redacted (PBS DOES return it on
    read — see module docstring); confirm=True executes (PUT /config/acme/plugins/{id},
    synchronous — PBS returns null) and returns {"status": "ok", "result": None}. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/acme/plugins/{plugin_id}"
    kw: dict = {}
    if dns_api is not None:
        kw["api"] = dns_api
    if data is not None:
        kw["data"] = data
    if disable is not None:
        kw["disable"] = disable
    if validation_delay is not None:
        kw["validation_delay"] = validation_delay
    if digest is not None:
        kw["digest"] = digest
    if delete is not None:
        kw["delete"] = delete
    return run_governed(
        "pbs_acme_plugin_update", tgt,
        plan=lambda: plan_acme_plugin_update(pbs, plugin_id, **kw),
        execute=lambda: acme_plugin_update(pbs, plugin_id, **kw),
        confirm=confirm)


@tool()
def pbs_acme_plugin_delete(
    plugin_id: Annotated[str, Field(description="Identifier of the ACME DNS challenge plugin to delete.")],
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete an ACME DNS challenge plugin. Dry-run by default.

    HIGH risk: cert auto-renewal breaks for every domain using this plugin — TLS lockout at cert
    expiry unless a fallback challenge method is configured. No UNDO primitive — recreate with
    pbs_acme_plugin_create, but the credentials must be re-supplied by the caller. The dry-run
    PLAN captures the current config (credential redacted) as evidence only; confirm=True executes
    (synchronous — PBS returns null) and returns {"status": "ok", "result": None}. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/acme/plugins/{plugin_id}"
    return run_governed(
        "pbs_acme_plugin_delete", tgt,
        plan=lambda: plan_acme_plugin_delete(pbs, plugin_id),
        execute=lambda: acme_plugin_delete(pbs, plugin_id),
        confirm=confirm)


# --- Mutations: node cert order/renew ---

@tool()
def pbs_acme_cert_order(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    force: Annotated[bool, Field(description="Overwrite existing certificate files on the node if already present.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True submits the ACME order.")] = False,
) -> dict:
    """MUTATION: order a NEW ACME TLS certificate for a PBS node. Dry-run by default.

    MEDIUM (mirrors pve_acme_cert_order's rating): the cert is CA-validated and installed ONLY on
    a successful challenge — a failed challenge leaves the existing cert untouched. PBS's schema
    declares a null return (unlike PVE's task UPID) — this does NOT mean issuance is synchronous;
    the ACME challenge round-trip with the CA still happens on the PBS side after this call
    returns, and there is nothing to poll here (no UPID exists to wait on). PBS has NO ACME cert
    revoke (unlike PVE). force=overwrite existing files. confirm=True executes (POST
    /nodes/{node}/certificates/acme/certificate) and returns {"status": "ok", "result": None}.
    Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/certificates/acme/certificate"
    return run_governed(
        "pbs_acme_cert_order", tgt,
        plan=lambda: plan_acme_cert_order(node, force=force),
        execute=lambda: acme_cert_order(pbs, node, force=force),
        confirm=confirm, detail={"force": force})


@tool()
def pbs_acme_cert_renew(
    node: Annotated[str, Field(description="PBS node name (or 'localhost').")] = "localhost",
    force: Annotated[bool, Field(description="Renew even if the current certificate is not yet within its renewal lead time.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True submits the ACME renewal.")] = False,
) -> dict:
    """MUTATION: renew the existing ACME TLS certificate for a PBS node. Dry-run by default.

    MEDIUM (mirrors pve_acme_cert_renew's rating): CA-validated, installed only on success (a
    failure can't lock you out). Same null-return honesty as pbs_acme_cert_order — PBS declares
    no return value for this call, but the renewal itself still completes asynchronously on the
    PBS side; there is no UPID to poll. force=renew even if not yet within the renewal lead time.
    PBS has NO ACME cert revoke. confirm=True executes (PUT /nodes/{node}/certificates/acme/
    certificate) and returns {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/node/{node}/certificates/acme/certificate"
    return run_governed(
        "pbs_acme_cert_renew", tgt,
        plan=lambda: plan_acme_cert_renew(node, force=force),
        execute=lambda: acme_cert_renew(pbs, node, force=force),
        confirm=confirm, detail={"force": force})
