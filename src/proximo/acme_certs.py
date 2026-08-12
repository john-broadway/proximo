"""ACME & TLS Certs plane — PVE cluster ACME account and plugin management.

Covers Plane G (PLAN + PROVE; HIGH risk on deletes — TLS cert renewal depends on
registered ACME accounts and DNS challenge plugins):
  - ACME accounts      (/cluster/acme/account)
  - ACME plugins       (/cluster/acme/plugins)

VERIFIED live shapes: None — all endpoint shapes carry "Smoke-confirm:" comments.

Security posture:
  - All path components validated with \\Z-anchored regexes (trailing-newline bypass rejected).
  - RISK_HIGH on deletes: ACME account deletion = IRREVERSIBLE (account key is gone; only a NEW
    registration can be made, not a restore). Plugin deletion breaks auto-renewal for every domain
    using that challenge method — TLS lockout if cert expires and renewal can't run.
  - plan_acme_account_delete and plan_acme_plugin_delete explicitly disclaim undo. Capturing current
    config is for EVIDENCE only — it does NOT enable restore.
"""

from __future__ import annotations

import re

from ._validate import redact_secrets
from .backends import ProximoError
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# ACME account name: path segment in /cluster/acme/account/{name}
# Smoke-confirm: exact accepted charset against a live PVE instance.
_ACME_ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")

# ACME plugin ID: path segment in /cluster/acme/plugins/{id}
# Smoke-confirm: exact accepted charset against a live PVE instance.
_ACME_PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")


def _check_acme_account_name(name: str) -> str:
    # Do NOT strip — stripping defeats \\Z trailing-newline protection.
    s = str(name)
    if not _ACME_ACCOUNT_RE.match(s):
        raise ProximoError(
            f"invalid ACME account name: {name!r} "
            "(must start with alnum, then alnum/_/-, <=64 chars, no slash)"
        )
    return s


def _check_acme_plugin_id(plugin_id: str) -> str:
    s = str(plugin_id)
    if not _ACME_PLUGIN_ID_RE.match(s):
        raise ProximoError(
            f"invalid ACME plugin ID: {plugin_id!r} "
            "(must start with alnum, then alnum/_/-, <=64 chars, no slash)"
        )
    return s


# Node name: path segment in /nodes/{node}/... . Mirrors backends._NODE_RE (kept local so the
# ACME plane validates its own path inputs; no trailing-newline bypass — \\Z, never strip).
_NODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\Z")

# Strict ASCII FQDN, optionally a single leading "*." wildcard (PVE/LE support wildcard certs via
# DNS-01). The value lands inside PVE's comma/equals-delimited node-config string
# (acmedomainN=domain=<fqdn>,plugin=<id>), so the charset itself IS the injection guard: a ',',
# '=', whitespace, or non-ASCII char cannot appear, so a domain can never smuggle an extra
# config property (e.g. ",plugin=evil"). '*' is safe — not a delimiter. Only a full-label leading
# wildcard ("*.") is allowed (not "*foo", not "a.*.b"). Requires a dotted FQDN (>=2 labels), alpha
# TLD, label<=63, total<=253, \\Z-anchored (trailing-newline bypass rejected).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\Z)"
    r"(?:\*\.)?"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\Z"
)

# Matches the per-domain node-config keys acmedomain0 .. acmedomain5 (capture the index).
_ACMEDOMAIN_KEY_RE = re.compile(r"^acmedomain([0-9]+)\Z")

# PVE exposes acmedomain0..acmedomain5 — at most 6 DNS-validated domains per node.
_MAX_ACME_DOMAINS = 6


def _check_node(node: str) -> str:
    # Do NOT strip — stripping defeats \\Z trailing-newline protection.
    s = str(node)
    if not _NODE_RE.match(s):
        raise ProximoError(
            f"invalid node name: {node!r} (start with alnum, then alnum/./_/-)"
        )
    return s


def _check_domain(domain: str) -> str:
    # Do NOT strip — stripping defeats \\Z trailing-newline protection.
    s = str(domain)
    if not _DOMAIN_RE.match(s):
        raise ProximoError(
            f"invalid ACME domain: {domain!r} (must be a dotted ASCII FQDN; "
            "no comma/equals/whitespace/non-ASCII; label<=63, total<=253)"
        )
    return s


# ---------------------------------------------------------------------------
# ACME account operations
# ---------------------------------------------------------------------------

def acme_account_get(api, name: str) -> dict:
    """Get one ACME account config.

    GET /cluster/acme/account/{name}
    Smoke-confirm: exact response shape (contact, directory, location, tos, ...).
    """
    _check_acme_account_name(name)
    return api._get(f"/cluster/acme/account/{name}") or {}


def acme_account_create(api, name: str, contact: str, **kw) -> None:
    """Register a new ACME account with the CA.

    POST /cluster/acme/account
    Body: {name, contact, directory?, tos_url?, ...}
    Smoke-confirm: name in body vs path + exact accepted body fields.
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_acme_account_name(name)
    data = {"name": name, "contact": contact, **kw}
    # MUTATION — confirm-gated + audited at the server layer.
    api._post("/cluster/acme/account", {k: v for k, v in data.items() if v is not None})


def acme_account_update(api, name: str, **kw) -> None:
    """Update ACME account contact info.

    PUT /cluster/acme/account/{name}
    Body: {contact?, ...}
    Smoke-confirm: exact accepted body fields.
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_acme_account_name(name)
    # MUTATION — confirm-gated + audited at the server layer.
    api._put(f"/cluster/acme/account/{name}", {k: v for k, v in kw.items() if v is not None})


def acme_account_delete(api, name: str) -> None:
    """Deactivate and delete an ACME account from the CA.

    DELETE /cluster/acme/account/{name}
    Smoke-confirm: response shape (null or task ID).
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_acme_account_name(name)
    # MUTATION — confirm-gated + audited at the server layer.
    api._delete(f"/cluster/acme/account/{name}")


# ---------------------------------------------------------------------------
# ACME plugin operations
# ---------------------------------------------------------------------------

def acme_plugin_get(api, plugin_id: str) -> dict:
    """Get one ACME plugin config.

    GET /cluster/acme/plugins/{id}
    Smoke-confirm: exact response shape (type, data, api, ...).
    """
    _check_acme_plugin_id(plugin_id)
    return api._get(f"/cluster/acme/plugins/{plugin_id}") or {}


def acme_plugin_create(backend, plugin_id: str, plugin_type: str, **kw) -> None:
    """Create an ACME DNS challenge plugin.

    POST /cluster/acme/plugins
    Body: {id, type, data?, api?, disable?, nodes?, validation-delay?, ...}
    Smoke-confirm: id in body vs path + exact accepted body fields.
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_acme_plugin_id(plugin_id)
    data = {"id": plugin_id, "type": plugin_type, **kw}
    # MUTATION — confirm-gated + audited at the server layer.
    backend._post("/cluster/acme/plugins", {k: v for k, v in data.items() if v is not None})


def acme_plugin_update(backend, plugin_id: str, **kw) -> None:
    """Update an ACME DNS challenge plugin.

    PUT /cluster/acme/plugins/{id}
    Body: {type?, data?, api?, disable?, nodes?, validation-delay?, digest?, ...}
    Smoke-confirm: exact accepted body fields.
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_acme_plugin_id(plugin_id)
    # MUTATION — confirm-gated + audited at the server layer.
    backend._put(f"/cluster/acme/plugins/{plugin_id}", {k: v for k, v in kw.items() if v is not None})


def acme_plugin_delete(api, plugin_id: str) -> None:
    """Delete an ACME DNS challenge plugin.

    DELETE /cluster/acme/plugins/{id}
    Smoke-confirm: response shape (null or empty).
    MUTATION — confirm-gated + audited at the server layer.
    """
    _check_acme_plugin_id(plugin_id)
    # MUTATION — confirm-gated + audited at the server layer.
    api._delete(f"/cluster/acme/plugins/{plugin_id}")


# ---------------------------------------------------------------------------
# Plan factories — ACME accounts
# ---------------------------------------------------------------------------

def plan_acme_account_create(name: str, contact: str, **kw) -> Plan:
    """Plan an ACME account registration (additive, MEDIUM risk)."""
    _check_acme_account_name(name)
    return Plan(
        action="pve_acme_account_create",
        target=f"cluster/acme/account/{name}",
        change=f"register ACME account {name!r} (contact: {contact!r}): {kw}",
        current={},
        blast_radius=["registers a new ACME account with the CA (no existing config affected)"],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "sends account registration to the ACME CA directory",
            "depends on correct contact email + TOS acceptance",
        ],
        note=(
            "Additive config. Delete with pve_acme_account_delete to deactivate. "
            "Smoke-confirm: exact POST body shape (name in body vs path) against a live PVE instance."
        ),
    )


def plan_acme_account_update(api, name: str, **kw) -> Plan:
    """Plan an ACME account contact update. Reads current config for honesty."""
    _check_acme_account_name(name)
    current = acme_account_get(api, name)
    return Plan(
        action="pve_acme_account_update",
        target=f"cluster/acme/account/{name}",
        change=f"update ACME account {name!r}: {kw}",
        current=current,
        blast_radius=["updates contact info on the CA side (no cert impact)"],
        risk=RISK_LOW,
        risk_reasons=["contact metadata update — does not affect cert issuance or renewal"],
        note=(
            "No snapshot primitive on this plane. Current config captured above — "
            "re-apply contact via pve_acme_account_update to revert."
        ),
    )


def plan_acme_account_delete(api, name: str) -> Plan:
    """Plan an ACME account deletion. IRREVERSIBLE — see honesty note.

    Captures current config as EVIDENCE ONLY — this does NOT enable restore.
    The account key is gone; only a NEW CA registration can be made.
    """
    _check_acme_account_name(name)
    current = acme_account_get(api, name)
    return Plan(
        action="pve_acme_account_delete",
        target=f"cluster/acme/account/{name}",
        change=f"IRREVERSIBLE: deactivate and delete ACME account {name!r} from the CA",
        current=current,
        blast_radius=[
            "ACME account deactivated at the CA — no new cert orders or renewals possible",
            "any TLS cert using this account will NOT renew — TLS lockout at expiry",
            "domains depending on this account require re-registration with a new account",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "IRREVERSIBLE: account key is destroyed; re-registration creates a NEW account, "
            "not a restore of this one",
            "TLS lockout risk: if this is the only ACME account, all auto-renewal stops",
        ],
        note=(
            "IRREVERSIBLE. Current config captured above is for EVIDENCE ONLY — "
            "it does NOT enable restore. The account key is not recoverable. "
            "A new account can be registered with pve_acme_account_create, "
            "but it will be a different CA account, not this one."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — ACME plugins
# ---------------------------------------------------------------------------

# Secret-shaped kwarg on this plane: the DNS-provider credential blob.
_PLUGIN_SECRET_KEYS = frozenset({"data"})


def _redact_plugin_kw(kw: dict) -> dict:
    """Mask the DNS-provider credential blob before it enters a plan string.

    `data` carries the provider's API secrets (e.g. ``CF_Token=...``, ``AWS_SECRET_ACCESS_KEY=...``).
    plan.change is BOTH returned to the caller AND written to the tamper-evident PROVE ledger, so the
    raw value must never appear there — this is the one credential field that lacked a redaction path.
    """
    return redact_secrets(kw, _PLUGIN_SECRET_KEYS)


def plan_acme_plugin_create(plugin_id: str, plugin_type: str, **kw) -> Plan:
    """Plan an ACME plugin creation (additive, MEDIUM risk)."""
    _check_acme_plugin_id(plugin_id)
    return Plan(
        action="pve_acme_plugin_create",
        target=f"cluster/acme/plugins/{plugin_id}",
        change=f"create ACME plugin {plugin_id!r} (type={plugin_type!r}): {_redact_plugin_kw(kw)}",
        current={},
        blast_radius=["adds a new ACME DNS challenge plugin (no existing config affected)"],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "DNS challenge plugin stores API credentials for the DNS provider",
            "incorrect credentials silently break cert issuance until renewal is attempted",
        ],
        note=(
            "Additive config. Delete with pve_acme_plugin_delete to remove. "
            "Smoke-confirm: exact POST body shape (id in body vs path) against a live PVE instance."
        ),
    )


def plan_acme_plugin_update(backend, plugin_id: str, **kw) -> Plan:
    """Plan an ACME plugin update. Reads current config for honesty."""
    _check_acme_plugin_id(plugin_id)
    # acme_plugin_get's own documented shape includes `data` (the DNS provider's raw
    # credential) — redact it the same way the proposed new value already is, since
    # Plan.current is written verbatim to the PROVE ledger on every call.
    current = _redact_plugin_kw(acme_plugin_get(backend, plugin_id))
    return Plan(
        action="pve_acme_plugin_update",
        target=f"cluster/acme/plugins/{plugin_id}",
        change=f"update ACME plugin {plugin_id!r}: {_redact_plugin_kw(kw)}",
        current=current,
        blast_radius=[
            "changes challenge credentials for all domains using this plugin",
            "incorrect new credentials break cert renewal for those domains",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "modifies DNS provider credentials — invalid update breaks challenge at next renewal",
        ],
        note=(
            "No snapshot primitive on this plane. Current config captured above — "
            "re-apply it manually to revert."
        ),
    )


def plan_acme_plugin_delete(api, plugin_id: str) -> Plan:
    """Plan an ACME plugin deletion. HIGH risk — cert renewal breaks.

    Captures current config as EVIDENCE ONLY — credentials must be re-supplied on re-create.
    """
    _check_acme_plugin_id(plugin_id)
    # acme_plugin_get's own documented shape includes `data` (the DNS provider's raw
    # credential) — redact it before it lands in Plan.current, written verbatim to the
    # PROVE ledger even on a confirm=False dry-run.
    current = _redact_plugin_kw(acme_plugin_get(api, plugin_id))
    return Plan(
        action="pve_acme_plugin_delete",
        target=f"cluster/acme/plugins/{plugin_id}",
        change=f"delete ACME plugin {plugin_id!r}",
        current=current,
        blast_radius=[
            "all domains using this plugin can no longer complete DNS challenges",
            "cert renewal fails at next renewal attempt — TLS lockout at cert expiry",
            "challenge type (http-01 standalone fallback may not cover all domains)",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "auto-renewal breaks for all domains referencing this plugin",
            "TLS lockout risk if no fallback challenge method is configured",
        ],
        note=(
            "No UNDO primitive on this plane. Current config captured above (any DNS-provider "
            "credential redacted) — re-create with pve_acme_plugin_create to restore, but "
            "credentials must be re-supplied; whether stored secrets are returned by the GET "
            "endpoint is unverified (see module header, 'VERIFIED live shapes: None'), so this "
            "plan redacts defensively rather than assuming they are re-supplied for free."
        ),
    )


# ---------------------------------------------------------------------------
# Node ACME config — the "what to issue" side (account selector + per-domain plugin)
# ---------------------------------------------------------------------------
#
# PVE splits node ACME setup across the node config (PUT /nodes/{node}/config):
#   acme        = account=<name>[,domains=<d;d;...>]      (which account; standalone http-01 domains)
#   acmedomain0..5 = domain=<fqdn>[,alias=<d>][,plugin=<plugin-id>]   (per-domain DNS-01)
# Verified against a live PVE 9.2.3 node's `pvesh usage` schema.

def _build_acme_node_config(
    account: str, domains: list[str], plugin: str | None = None, current: dict | None = None
) -> tuple[dict, str | None]:
    """Build the PVE node-config body (+ a `delete` list) for an ACME domain set.

    REPLACE semantics: when `plugin` is set, domains map to acmedomain0..N and any HIGHER
    acmedomainN already present is returned for deletion (a shrink never leaves a stale domain).
    When `plugin` is None (standalone http-01), domains ride in the `acme=...,domains=` line and
    ALL existing acmedomainN entries are deleted. Every domain is strictly FQDN-validated so it
    cannot inject an extra config property through the comma/equals delimiters.

    Returns (body, delete) where `delete` is a comma-joined field list or None.
    """
    name = _check_acme_account_name(account)
    if not domains:
        raise ProximoError("at least one ACME domain is required")
    if len(domains) > _MAX_ACME_DOMAINS:
        raise ProximoError(
            f"PVE supports at most {_MAX_ACME_DOMAINS} ACME domains per node "
            f"(acmedomain0..{_MAX_ACME_DOMAINS - 1}); got {len(domains)}"
        )
    doms = [_check_domain(d) for d in domains]
    plug = _check_acme_plugin_id(plugin) if plugin is not None else None
    current = current or {}

    # A wildcard (*.example.com) can ONLY be validated via DNS-01 — http-01 standalone cannot.
    if plug is None and any(d.startswith("*.") for d in doms):
        raise ProximoError(
            "wildcard domains require a DNS-01 plugin (plugin=...); "
            "http-01 standalone cannot validate a wildcard"
        )

    body: dict = {}
    if plug is None:
        # standalone http-01: domains ride in the acme= line; no per-domain plugin entries.
        body["acme"] = f"account={name},domains=" + ";".join(doms)
        set_indices: set[int] = set()
    else:
        body["acme"] = f"account={name}"
        for i, d in enumerate(doms):
            body[f"acmedomain{i}"] = f"domain={d},plugin={plug}"
        set_indices = set(range(len(doms)))

    # REPLACE: delete any acmedomainN in current that we are not (re)writing. Only PVE-valid
    # indices (0..5) participate — an out-of-range stray (e.g. acmedomain6 from external API
    # tampering) is ignored, never emitted in delete=, which would make PVE 400 the whole PUT.
    current_indices: set[int] = set()
    for key in current:
        m = _ACMEDOMAIN_KEY_RE.match(str(key))
        if m and int(m.group(1)) < _MAX_ACME_DOMAINS:
            current_indices.add(int(m.group(1)))
    stale = sorted(current_indices - set_indices)
    delete = ",".join(f"acmedomain{n}" for n in stale) if stale else None
    return body, delete


def node_config_get(api, node: str) -> dict:
    """Read a node's config (for ACME honesty/revert).

    GET /nodes/{node}/config
    """
    n = _check_node(node)
    return api._get(f"/nodes/{n}/config") or {}


def node_acme_config_set(api, node: str, account: str, domains: list[str],
                         plugin: str | None = None) -> None:
    """Set the node's ACME account + domains (PUT /nodes/{node}/config).

    Reads current config to compute REPLACE deletions, then writes the new acme/acmedomainN set.
    MUTATION — confirm-gated + audited at the server layer. Carries NO secret (plugin creds live
    on the plugin, set via pve_acme_plugin_create).
    """
    n = _check_node(node)
    # NOTE (TOCTOU, deferred — same class as audit.py's L16): the server confirm path reads node
    # config once here AND once in plan_node_acme_domains_set, so the delete-set is computed from
    # two independent reads. Under a concurrent ACME config change the planned vs executed delete
    # could differ. Threading the precomputed (body, delete) through would break the uniform
    # _plan/_audited shape; left consistent with the existing acknowledged limitation.
    current = node_config_get(api, n)
    body, delete = _build_acme_node_config(account, domains, plugin, current)
    data = dict(body)
    if delete:
        data["delete"] = delete
    # MUTATION — confirm-gated + audited at the server layer.
    api._put(f"/nodes/{n}/config", data)


# ---------------------------------------------------------------------------
# ACME cert order / renew / revoke — the "do it now" side
# ---------------------------------------------------------------------------

def acme_cert_order(api, node: str, force: bool = False):
    """Order a NEW ACME cert for the node's configured ACME domains (async → UPID).

    POST /nodes/{node}/certificates/acme/certificate  (force=overwrite existing custom cert)
    MUTATION — confirm-gated + audited at the server layer.
    """
    n = _check_node(node)
    data = {"force": 1} if force else {}
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"/nodes/{n}/certificates/acme/certificate", data)


def acme_cert_renew(api, node: str, force: bool = False):
    """Renew the node's existing ACME cert (async → UPID).

    PUT /nodes/{node}/certificates/acme/certificate  (force=renew even if >30d to expiry)
    MUTATION — confirm-gated + audited at the server layer.
    """
    n = _check_node(node)
    data = {"force": 1} if force else {}
    # MUTATION — confirm-gated + audited at the server layer.
    return api._put(f"/nodes/{n}/certificates/acme/certificate", data)


def acme_cert_revoke(api, node: str):
    """Revoke the node's ACME cert at the CA (async → UPID). IRREVERSIBLE at the CA.

    DELETE /nodes/{node}/certificates/acme/certificate
    MUTATION — confirm-gated + audited at the server layer.
    """
    n = _check_node(node)
    # MUTATION — confirm-gated + audited at the server layer.
    return api._delete(f"/nodes/{n}/certificates/acme/certificate")


# ---------------------------------------------------------------------------
# Plan factories — node ACME config + cert order/renew/revoke
# ---------------------------------------------------------------------------

def plan_node_acme_domains_set(api, node: str, account: str, domains: list[str],
                               plugin: str | None = None) -> Plan:
    """Plan a node ACME domain/account set (MEDIUM). Reads current config for honesty + revert."""
    n = _check_node(node)
    current = node_config_get(api, n)
    body, delete = _build_acme_node_config(account, domains, plugin, current)
    chg = f"set node ACME config {body}" + (f" (delete {delete})" if delete else "")
    return Plan(
        action="pve_node_acme_domains_set",
        target=f"node/{n}/config:acme",
        change=chg,
        current=current,
        blast_radius=[
            "sets which ACME account + domains this node requests/renews TLS certs for",
            "REPLACE: stale acmedomainN entries are removed (not merged)",
            "does NOT issue a cert by itself — pve_acme_cert_order does that",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "a wrong account/domain/plugin makes the next cert order fail its challenge",
            "config only — no cert is installed or replaced by this step",
        ],
        note=(
            "Config-only; no cert change yet. Current node config captured above — re-apply the "
            "prior acme/acmedomainN fields to revert. Then issue with pve_acme_cert_order."
        ),
    )


def plan_acme_cert_order(node: str, *, force: bool = False) -> Plan:
    """Plan an ACME cert order (MEDIUM — CA-validated, installs only on success)."""
    n = _check_node(node)
    return Plan(
        action="pve_acme_cert_order",
        target=f"node/{n}/certificates/acme/certificate",
        change=(
            f"order a new ACME TLS certificate for node {n!r}"
            + (" (force: overwrite existing custom cert)" if force else "")
        ),
        current={},
        blast_radius=[
            "requests a cert from the configured ACME CA for the node's configured ACME domains",
            "on SUCCESS, PVE installs the cert and reloads pveproxy (brief management-plane blip)",
            "on a failed DNS/HTTP challenge, the existing cert is left untouched",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "lower risk than pve_node_cert_upload (HIGH): the cert is CA-validated and installed "
            "ONLY on a successful challenge — a failure cannot lock you out",
            "talks to the public CA — repeated orders can hit CA rate limits (use the ACME "
            "staging directory while testing)",
        ],
        note=(
            "Async — returns a task UPID; poll with pve_task_status/pve_task_wait. Installs on "
            "success and reloads pveproxy. Revert to the self-signed cert with pve_node_cert_delete."
        ),
    )


def plan_acme_cert_renew(node: str, *, force: bool = False) -> Plan:
    """Plan an ACME cert renew (MEDIUM — same install-on-success guarantee as order)."""
    n = _check_node(node)
    return Plan(
        action="pve_acme_cert_renew",
        target=f"node/{n}/certificates/acme/certificate",
        change=(
            f"renew the existing ACME TLS certificate for node {n!r}"
            + (" (force: renew even if >30 days to expiry)" if force else "")
        ),
        current={},
        blast_radius=[
            "renews the node's existing ACME cert from the configured CA",
            "on SUCCESS, PVE installs the renewed cert and reloads pveproxy",
            "on a failed challenge, the existing cert is left untouched",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "CA-validated renew, installed only on success; a failure cannot lock you out",
            "talks to the public CA — repeated renews can hit CA rate limits",
        ],
        note=(
            "Async — returns a task UPID. Installs on success and reloads pveproxy. Revert with "
            "pve_node_cert_delete (self-signed) if a renewed cert misbehaves."
        ),
    )


def plan_acme_cert_revoke(api, node: str) -> Plan:
    """Plan an ACME cert revoke (HIGH — IRREVERSIBLE at the CA).

    Reads the node's certificates as EVIDENCE (fingerprint/subject of what is about to be revoked)
    so the PROVE ledger records which cert was destroyed — mirrors plan_acme_account_delete /
    plan_acme_plugin_delete. Capture is evidence ONLY; it does NOT enable an un-revoke.
    """
    n = _check_node(node)
    current = {"certificates": api._get(f"/nodes/{n}/certificates") or []}
    return Plan(
        action="pve_acme_cert_revoke",
        target=f"node/{n}/certificates/acme/certificate",
        change=f"IRREVERSIBLE: revoke the node's ACME TLS certificate at the CA for node {n!r}",
        current=current,
        blast_radius=[
            "the cert is revoked at the CA — clients that check revocation will reject it",
            "the node keeps serving the now-revoked cert until a new one is ordered/installed",
            "a fresh order (pve_acme_cert_order) is required to restore a valid TLS chain",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "IRREVERSIBLE at the CA: a revoked cert cannot be un-revoked; only a NEW order restores trust",
            "TLS-trust loss for clients honoring revocation; CA rate limits may delay re-issue",
        ],
        note=(
            "IRREVERSIBLE. Revocation cannot be undone — only a new pve_acme_cert_order restores a "
            "valid cert. Rarely needed (key compromise). NOT a way to 'reset' a cert — use "
            "pve_node_cert_delete to fall back to self-signed WITHOUT revoking at the CA."
        ),
    )
