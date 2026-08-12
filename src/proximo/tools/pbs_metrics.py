"""PBS metrics servers wrappers (Wave 5b, full-surface campaign) —
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 5 decomposition (PBS s3 + remainder)",
"5b — metrics servers". See `proximo.pbs_metrics` module docstring for the full endpoint table,
the schema-verified facts, and the risk-rating reasoning.
"""
from __future__ import annotations

from typing import Annotated

from pydantic import Field

import proximo.server as _proximo_server
from proximo.pbs_metrics import (
    influxdb_http_create,
    influxdb_http_delete,
    influxdb_http_get,
    influxdb_http_list,
    influxdb_http_update,
    influxdb_udp_create,
    influxdb_udp_delete,
    influxdb_udp_get,
    influxdb_udp_list,
    influxdb_udp_update,
    metrics_servers_list,
    metrics_status,
    plan_influxdb_http_create,
    plan_influxdb_http_delete,
    plan_influxdb_http_update,
    plan_influxdb_udp_create,
    plan_influxdb_udp_delete,
    plan_influxdb_udp_update,
)
from proximo.server import (
    _audited,
    run_governed,
    tool,
)

# --- Reads: cross-plane ---

@tool()
def pbs_metrics_servers_list() -> list[dict]:
    """READ-ONLY: list ALL configured PBS metric servers (both influxdb-http and influxdb-udp) in
    one unified view. Response is schema-enforced secret-free — no token field can appear here per
    the schema's own closed shape. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_metrics_servers_list", "pbs/admin/metrics",
                    lambda: metrics_servers_list(pbs))


@tool()
def pbs_metrics_status(
    history: Annotated[bool, Field(description="Include historic values (last 30 minutes).")] = False,
    start_time: Annotated[int | None, Field(description="Only return values with a timestamp > start_time. Only has an effect if history is also set.")] = None,
) -> dict:
    """READ-ONLY: return PBS backup server metrics — host CPU/memory/network and per-datastore
    performance telemetry. REVIEWED_TRUSTED: server-authored numeric telemetry, matching the
    pve_node_rrddata/pmg_node_rrddata precedent (see proximo.pbs_metrics module docstring fact
    #5). The live schema declares this endpoint's return type null despite its own description
    implying real data — passed through best-effort, matching pbs_s3_list_buckets's identical
    quirk (Wave 5a). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_metrics_status", "pbs/status/metrics",
                    lambda: metrics_status(pbs, history, start_time))


# --- Reads: influxdb-http ---

@tool()
def pbs_metrics_influxdb_http_list() -> list[dict]:
    """READ-ONLY: list configured PBS InfluxDB http metric servers. `token` DOES appear in the
    live schema's response shape (unlike pbs_s3's config reads, which are documented secret-free)
    — stripped here at the READ layer; this strip is REQUIRED, not merely defensive (see
    proximo.pbs_metrics module docstring fact #1). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_metrics_influxdb_http_list", "pbs/config/metrics/influxdb-http",
                    lambda: influxdb_http_list(pbs))


@tool()
def pbs_metrics_influxdb_http_get(
    name: Annotated[str, Field(description="Metrics Server ID (3-32 chars, alnum/underscore start, then alnum/./_/-).")],
) -> dict:
    """READ-ONLY: get one PBS InfluxDB http metric server's config, with `token` stripped at the
    READ layer (required strip, not merely defensive — module docstring fact #1). Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_metrics_influxdb_http_get", f"pbs/config/metrics/influxdb-http/{name}",
                    lambda: influxdb_http_get(pbs, name))


# --- Reads: influxdb-udp ---

@tool()
def pbs_metrics_influxdb_udp_list() -> list[dict]:
    """READ-ONLY: list configured PBS InfluxDB udp metric servers. No secret field exists on this
    sub-plane at all (verified field-by-field — module docstring fact #2); no read-layer strip is
    needed. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_metrics_influxdb_udp_list", "pbs/config/metrics/influxdb-udp",
                    lambda: influxdb_udp_list(pbs))


@tool()
def pbs_metrics_influxdb_udp_get(
    name: Annotated[str, Field(description="Metrics Server ID (3-32 chars, alnum/underscore start, then alnum/./_/-).")],
) -> dict:
    """READ-ONLY: get one PBS InfluxDB udp metric server's config. No secret field exists on this
    sub-plane (module docstring fact #2). Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    return _audited("pbs_metrics_influxdb_udp_get", f"pbs/config/metrics/influxdb-udp/{name}",
                    lambda: influxdb_udp_get(pbs, name))


# --- Mutations: influxdb-http ---

@tool()
def pbs_metrics_influxdb_http_create(
    name: Annotated[str, Field(description="New Metrics Server ID (3-32 chars, alnum/underscore start, then alnum/./_/-).")],
    url: Annotated[str, Field(description="HTTP(s) url with optional port, e.g. 'https://influx.example.com:8086'.")],
    bucket: Annotated[str | None, Field(description="InfluxDB Bucket (1-32 chars). Defaults to 'proxmox' server-side if omitted.")] = None,
    comment: Annotated[str | None, Field(description="Comment (<=128 chars, no control chars).")] = None,
    enable: Annotated[bool | None, Field(description="Enables or disables the metrics server. Defaults True server-side if omitted.")] = None,
    max_body_size: Annotated[int | None, Field(description="Maximum body size in bytes. Defaults to 25000000 server-side if omitted; no upper bound stated by the schema.")] = None,
    organization: Annotated[str | None, Field(description="InfluxDB Organization (1-32 chars). Defaults to 'proxmox' server-side if omitted.")] = None,
    token: Annotated[str | None, Field(description="API token. SECRET — never written to the audit ledger or the dry-run PLAN.")] = None,
    verify_tls: Annotated[bool | None, Field(description="If true, the endpoint's certificate is validated. Defaults True server-side if omitted.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PBS InfluxDB http metrics server configuration.

    RISK_MEDIUM: this sub-plane can hold a stored API token — mirrors pbs_s3_client_create's
    credential-bearing-create reasoning, a step up from PVE's LOW-rated pve_metrics_server_set
    (whose currently-shipped tool surface doesn't expose a token parameter at all, even though
    PVE's own schema has one — pbs_metrics.py module docstring's 2026-07-15 correction).
    SECRET CONTRACT: `token` is NEVER
    written to the audit ledger or the dry-run PLAN — forwarded RAW only to the real PBS API on
    confirm=True (the create must actually work). Dry-run by default (returns a PLAN); confirm=True
    executes (POST /config/metrics/influxdb-http, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/metrics/influxdb-http/{name}"
    # SECRET HANDLING: detail must NEVER contain token — only non-secret params.
    return run_governed(
        "pbs_metrics_influxdb_http_create", tgt,
        plan=lambda: plan_influxdb_http_create(
        name, url, bucket, comment, enable, max_body_size, organization, token, verify_tls,
    ),
        execute=lambda: influxdb_http_create(
            pbs, name, url, bucket, comment, enable, max_body_size, organization, token,
            verify_tls,
        ),
        confirm=confirm, detail={"url": url})


@tool()
def pbs_metrics_influxdb_http_update(
    name: Annotated[str, Field(description="Id of the existing InfluxDB http metrics server to update.")],
    bucket: Annotated[str | None, Field(description="New InfluxDB Bucket (1-32 chars).")] = None,
    comment: Annotated[str | None, Field(description="New comment (<=128 chars, no control chars).")] = None,
    enable: Annotated[bool | None, Field(description="Enable or disable the metrics server.")] = None,
    max_body_size: Annotated[int | None, Field(description="New maximum body size in bytes.")] = None,
    organization: Annotated[str | None, Field(description="New InfluxDB Organization (1-32 chars).")] = None,
    token: Annotated[str | None, Field(description="New API token. SECRET — never written to the audit ledger or the dry-run PLAN.")] = None,
    url: Annotated[str | None, Field(description="New HTTP(s) url with optional port.")] = None,
    verify_tls: Annotated[bool | None, Field(description="Validate the endpoint's certificate.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned.")] = None,
    delete: Annotated[list[str] | None, Field(description="Property names to clear: any of enable/token/bucket/organization/max-body-size/verify-tls/comment. name/url are NOT deletable — rotate them with a new value instead.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: update a PBS InfluxDB http metrics server configuration.

    RISK_MEDIUM: rotating the token/url/bucket can silently redirect or break metrics delivery —
    mirrors pbs_s3_client_update. SECRET CONTRACT: `token` (if given) is NEVER written to the audit
    ledger or the dry-run PLAN. Dry-run by default (captures current token-free config into the
    PLAN, redacted again defensively); confirm=True executes (PUT
    /config/metrics/influxdb-http/{name}, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. No snapshot primitive. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/metrics/influxdb-http/{name}"
    return run_governed(
        "pbs_metrics_influxdb_http_update", tgt,
        plan=lambda: plan_influxdb_http_update(
        pbs, name, bucket, comment, enable, max_body_size, organization, token, url, verify_tls,
        digest, delete,
    ),
        execute=lambda: influxdb_http_update(
            pbs, name, bucket, comment, enable, max_body_size, organization, token, url,
            verify_tls, digest, delete,
        ),
        confirm=confirm)


@tool()
def pbs_metrics_influxdb_http_delete(
    name: Annotated[str, Field(description="Id of the InfluxDB http metrics server to delete.")],
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PBS InfluxDB http metrics server configuration.

    RISK_MEDIUM: removes a config entry that may hold a stored API token — mirrors
    pbs_s3_client_delete. PBS stops sending host/datastore metrics to this endpoint immediately.
    Dry-run by default (captures current token-free config); confirm=True executes (DELETE
    /config/metrics/influxdb-http/{name}, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. No UNDO primitive — re-create with
    pbs_metrics_influxdb_http_create (a fresh token, if any, must be re-supplied). Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/metrics/influxdb-http/{name}"
    return run_governed(
        "pbs_metrics_influxdb_http_delete", tgt,
        plan=lambda: plan_influxdb_http_delete(pbs, name, digest),
        execute=lambda: influxdb_http_delete(pbs, name, digest),
        confirm=confirm)


# --- Mutations: influxdb-udp ---

@tool()
def pbs_metrics_influxdb_udp_create(
    name: Annotated[str, Field(description="New Metrics Server ID (3-32 chars, alnum/underscore start, then alnum/./_/-).")],
    host: Annotated[str, Field(description="host:port combination (host can be a DNS name or IP address; port REQUIRED), e.g. '192.0.2.10:8089'.")],
    comment: Annotated[str | None, Field(description="Comment (<=128 chars, no control chars).")] = None,
    enable: Annotated[bool | None, Field(description="Enables or disables the metrics server. Defaults True server-side if omitted.")] = None,
    mtu: Annotated[int | None, Field(description="The MTU. Defaults to 1500 server-side if omitted; no upper bound stated by the schema.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the creation.")] = False,
) -> dict:
    """MUTATION: create a PBS InfluxDB udp metrics server configuration.

    RISK_LOW: matches PVE's pve_metrics_server_set baseline exactly — no credential field exists
    on this sub-plane at all (schema-verified). Dry-run by default (returns a PLAN); confirm=True
    executes (POST /config/metrics/influxdb-udp, synchronous — PBS returns null) and returns
    {"status": "ok", "result": None}. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/metrics/influxdb-udp/{name}"
    return run_governed(
        "pbs_metrics_influxdb_udp_create", tgt,
        plan=lambda: plan_influxdb_udp_create(
        name, host, comment, enable, mtu,
    ),
        execute=lambda: influxdb_udp_create(pbs, name, host, comment, enable, mtu),
        confirm=confirm, detail={"host": host})


@tool()
def pbs_metrics_influxdb_udp_update(
    name: Annotated[str, Field(description="Id of the existing InfluxDB udp metrics server to update.")],
    comment: Annotated[str | None, Field(description="New comment (<=128 chars, no control chars).")] = None,
    enable: Annotated[bool | None, Field(description="Enable or disable the metrics server.")] = None,
    host: Annotated[str | None, Field(description="New host:port combination (port REQUIRED).")] = None,
    mtu: Annotated[int | None, Field(description="New MTU.")] = None,
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned.")] = None,
    delete: Annotated[list[str] | None, Field(description="Property names to clear: any of enable/mtu/comment. name/host are NOT deletable — rotate them with a new value instead.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the update.")] = False,
) -> dict:
    """MUTATION: update a PBS InfluxDB udp metrics server configuration.

    RISK_LOW: config-only change — no credential field exists on this sub-plane, matching PVE's
    LOW-rated pve_metrics_server_set baseline. Dry-run by default (captures current config into
    the PLAN); confirm=True executes (PUT /config/metrics/influxdb-udp/{name}, synchronous — PBS
    returns null) and returns {"status": "ok", "result": None}. No snapshot primitive. Needs
    PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/metrics/influxdb-udp/{name}"
    return run_governed(
        "pbs_metrics_influxdb_udp_update", tgt,
        plan=lambda: plan_influxdb_udp_update(
        pbs, name, comment, enable, host, mtu, digest, delete,
    ),
        execute=lambda: influxdb_udp_update(pbs, name, comment, enable, host, mtu, digest, delete),
        confirm=confirm)


@tool()
def pbs_metrics_influxdb_udp_delete(
    name: Annotated[str, Field(description="Id of the InfluxDB udp metrics server to delete.")],
    digest: Annotated[str | None, Field(description="Optimistic-lock: 64-char lowercase hex SHA-256 of the config PBS last returned.")] = None,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN only; True executes the deletion.")] = False,
) -> dict:
    """MUTATION: delete a PBS InfluxDB udp metrics server configuration.

    RISK_LOW: config-only change — stops metrics forwarding, no credential or data loss, matching
    PVE's LOW-rated pve_metrics_server_delete baseline. Dry-run by default (captures current
    config); confirm=True executes (DELETE /config/metrics/influxdb-udp/{name}, synchronous — PBS
    returns null) and returns {"status": "ok", "result": None}. No UNDO primitive — re-create with
    pbs_metrics_influxdb_udp_create. Needs PROXIMO_PBS_* config."""
    _, pbs = _proximo_server._pbs()
    tgt = f"pbs/config/metrics/influxdb-udp/{name}"
    return run_governed(
        "pbs_metrics_influxdb_udp_delete", tgt,
        plan=lambda: plan_influxdb_udp_delete(pbs, name, digest),
        execute=lambda: influxdb_udp_delete(pbs, name, digest),
        confirm=confirm)
