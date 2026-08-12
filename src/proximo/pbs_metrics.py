"""PBS metrics servers plane (Wave 5b of the full-surface campaign,
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 5 decomposition (PBS s3 + remainder —
CLOSES THE PBS PLANE)", "5b — metrics servers"). Mirrors PBS's `notifications.py` metrics
sibling on PVE (`pve_metrics_server_list/set/delete`, `src/proximo/notifications.py`) — this
module does NOT rebuild that; PVE's metrics plane is a separate, simpler, single-endpoint-per-op
surface (`/cluster/metrics/server/{id}`) with no split by metric-server TYPE. PBS instead splits
by type into two full CRUD sub-planes (influxdb-http, influxdb-udp) plus two cross-plane reads.

Schema truth: `.scratch/api-schemas-2026-07-15/wave5b-pbs-metrics-schema.json` (extracted from
the live PBS apidoc, pulled 2026-07-15, by walking `/admin/metrics`, `/config/metrics` [+its two
children `influxdb-http`/`influxdb-udp`, each with a `{name}` leaf], `/status/metrics`).

Endpoint table (12 tools total — 6 read, 6 mutation):

  GET    /admin/metrics                               — pbs_metrics_servers_list       (read)
  GET    /status/metrics                               — pbs_metrics_status             (read)
  GET    /config/metrics/influxdb-http                 — pbs_metrics_influxdb_http_list  (read)
  GET    /config/metrics/influxdb-http/{name}           — pbs_metrics_influxdb_http_get   (read)
  POST   /config/metrics/influxdb-http                 — pbs_metrics_influxdb_http_create (MUTATION, MEDIUM)
  PUT    /config/metrics/influxdb-http/{name}           — pbs_metrics_influxdb_http_update (MUTATION, MEDIUM)
  DELETE /config/metrics/influxdb-http/{name}           — pbs_metrics_influxdb_http_delete (MUTATION, MEDIUM)
  GET    /config/metrics/influxdb-udp                   — pbs_metrics_influxdb_udp_list   (read)
  GET    /config/metrics/influxdb-udp/{name}            — pbs_metrics_influxdb_udp_get    (read)
  POST   /config/metrics/influxdb-udp                   — pbs_metrics_influxdb_udp_create (MUTATION, LOW)
  PUT    /config/metrics/influxdb-udp/{name}             — pbs_metrics_influxdb_udp_update (MUTATION, LOW)
  DELETE /config/metrics/influxdb-udp/{name}             — pbs_metrics_influxdb_udp_delete (MUTATION, LOW)

NOT BUILT: `GET /config/metrics` (bare, no further path segment) is a "Directory index." stub
(`returns: null`, `additionalProperties: true`, `permissions: {"user": "all"}`) — the SAME shape
as `/admin/s3/{id}` (Wave 5a) and `/tape/media/list/{uuid}` (Wave 4d): a bare API-tree pointer to
its own children (`influxdb-http`, `influxdb-udp`), not a real data endpoint. Not built here.

SCHEMA-VERIFIED FACTS (binding on this build — from the live schema, not memory):

  1. **`GET /config/metrics/influxdb-http[/{name}]` responses DO carry `token` — unlike Wave 5a's
     S3 plane, this is NOT a defensive-only strip.** The S3 plane's read responses are explicitly
     typed "without secret" (`secret-key` genuinely never appears in that schema's response
     shape) — this plane's response schema has NO such carve-out: `token` is a plain, unmarked
     `optional` property on BOTH the list-item shape and the single-item GET shape, with no
     "without secret" language anywhere in the endpoint descriptions. Confirmed field-by-field
     against both response shapes. **This means the read-layer strip in `influxdb_http_list`/
     `influxdb_http_get` is a REQUIRED fix for a real, schema-confirmed leak path, not merely
     defense-in-depth against a documented-safe read the way Wave 5a's S3 strip was** — per the
     task's own framing: "never trust documented secret-free reads." Here the read isn't even
     documented secret-free.
  2. **`influxdb-udp` carries NO secret field at all — verified field-by-field, not assumed by
     analogy to influxdb-http.** Its GET/POST/PUT parameter and response shapes contain exactly
     five fields total (`comment`, `enable`, `host`, `mtu`, `name`) across all three verbs; no
     `token`/`password`/`secret`/`key`-shaped property exists anywhere on this sub-plane. No
     read-layer strip is applied here — there is nothing to strip (documented explicitly rather
     than silently omitted, so a reviewer does not have to re-derive this from the schema).
  3. **`GET /admin/metrics` (the cross-plane list) is schema-enforced secret-free, not merely
     secret-absent-in-practice**: its response item schema declares `"additionalProperties":
     false` with exactly five properties (`comment`, `enable`, `name`, `server`, `type`) — `token`
     is not merely absent from observed responses, it CANNOT appear per the schema's own closed
     shape (`server` is the InfluxDB endpoint's target address as a display string, not a
     credential). No read-layer strip needed or applied.
  4. **`GET /status/metrics` declares `"returns": {"type": "null"}` despite its own description
     ("Return backup server metrics.") and its permission note implying real per-resource data**
     ("Users need Sys.Audit on /system/status for host metrics and Datastore.Audit on
     /datastore/{store} for datastore metrics") — the SAME "returns null despite real data" schema
     quirk seen repeatedly across this campaign (ACME cert order/renew Wave 3b, tape backup-job
     run Wave 4d, tape media status-get Wave 4d). Passed through best-effort (`api._get(...) or
     {}`), matching `pbs_s3_list_buckets`'s own handling of the identical quirk. Params: `history`
     (bool, default False, "Include historic values (last 30 minutes)") and `start-time`
     (integer, default 0, "Only return values with a timestamp > start-time. Only has an effect if
     'history' is also set") — both forwarded as query params.
  5. **`pbs_metrics_status` is classified REVIEWED_TRUSTED, matching the `pve_node_rrddata`/
     `pmg_node_rrddata` precedent (per the task's explicit instruction), not `ADVERSARIAL_TOOLS`.**
     The content is server-authored numeric performance telemetry (host CPU/memory/network,
     datastore I/O — the same category as RRD data), not free text a guest/attacker can shape;
     unlike `pbs_snapshots_list`/`pve_storage_content` (which carry guest-chosen names/labels),
     nothing about this endpoint's shape suggests an attacker-influenced string channel. Argued
     explicitly rather than defaulted, per the task's instruction to classify honestly.
  6. **`POST`/`PUT`/`DELETE` on both influxdb-http and influxdb-udp uniformly declare `"returns":
     {"type": "null"}`** — confirmed on all six mutation endpoints. Config CRUD on this plane is
     synchronous; outcome is always `"ok"`, never `"submitted"` (no UPID anywhere on this plane).
  7. **The `{name}` PATH PARAMETER on GET/PUT/DELETE for both sub-planes is ALSO listed as a
     REQUIRED body-schema property with no `"optional"` flag** — the same "merged path+body
     parameter schema" artifact `pbs_s3.py`'s module docstring fact #4 already documented for
     `{id}`/"Job ID.": the live apidoc's parameter schema is the FULL request schema (path+query+
     body combined), not a body-only shape. `name` is supplied via the URL path on PUT/DELETE, not
     duplicated in the JSON body — matches `pbs_s3.py`'s `s3_client_update`/`s3_client_delete`
     convention exactly (their own `id` is never added to the PUT/DELETE body dict either).
  8. **`url` (influxdb-http) is REQUIRED on POST, optional on PUT; `host` (influxdb-udp) is
     REQUIRED on POST, optional on PUT** — confirmed via the presence/absence of `"optional": 1`
     on each verb's own copy of the property. `token` is `optional` on BOTH POST and PUT for
     influxdb-http — this module does NOT treat it as create-required, matching the schema's own
     "(optional) API token" wording; `bucket`/`organization` both default to `"proxmox"` server-
     side when omitted (schema-stated defaults, not invented here).
  9. **`bucket`/`organization` carry NO character pattern at all** — only `minLength: 1,
     maxLength: 32` — the SAME "length-bound-only, no invented charset" situation `pbs_s3.py`'s
     module docstring fact documents for its own `bucket`/`store_prefix` fields (Wave 5a). Only a
     length bound + a defensive no-control-chars check are applied; no AWS/InfluxDB-naming
     charset is invented. `comment` carries the SAME `[[:^cntrl:]]*` (no-control-chars) pattern +
     `maxLength: 128` bound used by every other PBS module's own `comment` field.
 10. **`mtu` (influxdb-udp, default 1500) and `max-body-size` (influxdb-http, default 25000000)
     are BOTH typed as bare integers with NO bound stated at all** — unlike `pbs_s3.py`'s `port`
     field (which at least has an obvious standard TCP-range ceiling to defensively apply), these
     two have no equivalent well-known ceiling. Only a defensive "must be a positive integer"
     floor is applied here (mirrors `pbs_s3._check_port`'s own "defensive default, NOT
     schema-stated" framing) — no upper bound is invented for either field.
 11. **`delete` (property-clear list) enums differ by sub-plane**: influxdb-http accepts
     `{enable, token, bucket, organization, max-body-size, verify-tls, comment}` (7 values,
     `name`/`url` are NOT clearable — rotate them with a new value instead, matching `pbs_s3.py`'s
     own "`id`/`endpoint` never in the deletable set" precedent); influxdb-udp accepts
     `{enable, mtu, comment}` (3 values, `host`/`name` NOT clearable). Both lists are forwarded
     UN-VALIDATED against their own enum — the established "pass the list through, let the live
     API enforce its own enum" convention (`pbs_s3.py`/`pbs_tape_media.py`/`pbs_tape_config.py`).
 12. **`digest` (SHA-256 hex optimistic-lock) exists on PUT/DELETE for BOTH sub-planes** —
     confirmed on all four endpoints (http PUT/DELETE, udp PUT/DELETE); absent on both POSTs (a
     fresh resource being created, nothing to lock against yet — same absence-is-expected
     reasoning as every CREATE across this codebase).

RISK RATING (module-specific reasoning — mirrors PVE's metrics plane baseline where PBS's own
schema justifies it; PBS's own schema is what carries these ratings, not the PVE comparison):

  CORRECTED 2026-07-15 (Wave 5b adversarial review finding 2): an earlier version of this section
  claimed "PVE's metrics-server config carries no per-server API-token field at all." That claim
  is FALSE — verified against `.scratch/pve-apidoc-live-2026-07-15.json`: PVE's live
  `/cluster/metrics/server/{id}` POST schema has an optional `token` property ("The InfluxDB
  access token. Only necessary when using the http v2 api.") and a `type` enum that includes
  `"influxdb"`. What's actually true: the currently-shipped `pve_metrics_server_set` tool
  (`src/proximo/tools/pve_observability.py`) doesn't expose a `token` parameter to callers at
  all — so no MCP client can push a token through THAT tool today, which is why its RISK_LOW
  rating is honest for the surface Proximo actually exposes, not because PVE's own schema lacks
  the field. PBS's influxdb-http sub-plane, by contrast, DOES expose `token` directly on this
  tool surface (fact #8) — that is the real, load-bearing distinction below, not a PVE-schema gap
  that doesn't exist. (The redaction gap this false claim helped mask —
  `plan_metrics_server_set` building its `change` string from raw, unredacted `kw` — is fixed
  separately in `notifications.py`.)

  - **influxdb_http_create/update/delete = RISK_MEDIUM** — NOT the LOW rating PVE's
    `pve_metrics_server_set`/`pve_metrics_server_delete` carry (`notifications.py`,
    `RISK_LOW` for both). PBS's influxdb-http sub-plane exposes an optional `token` field
    directly on this tool surface (fact #8), unlike PVE's currently-shipped tool surface (see
    correction above) — this module rates the WHOLE influxdb-http CRUD surface MEDIUM uniformly
    (mirroring `pbs_s3_client_create`/`update`/`delete`'s own "credential-bearing entry"
    reasoning, Wave 5a), the same way `pbs_encryption_key_create` stays MEDIUM even though its
    own `key` param is ALSO optional (server auto-generates one if omitted) — the PLANE holds
    credential material at rest, so the rating is per-action, not conditional on whether a given
    call happens to supply the secret.
  - **influxdb_udp_create/update/delete = RISK_LOW** — matches PVE's `pve_metrics_server_set`/
    `pve_metrics_server_delete` baseline (schema-verified, fact #2: this sub-plane carries NO
    credential field of any kind, and neither does PVE's own tool surface, per the correction
    above). Additive/modifying/removing a fire-and-forget UDP metrics target is config-only, no
    different in kind from PVE's own metrics-server config as Proximo exposes it.

Taint:
  - **`pbs_metrics_influxdb_http_list`/`_get`/`_create`/`_update`/`_delete`,
    `pbs_metrics_influxdb_udp_list`/`_get`/`_create`/`_update`/`_delete`,
    `pbs_metrics_servers_list` = REVIEWED_TRUSTED**: operator-authored config; mutations return
    opaque `null` (fact #6); reads carry no attacker-shapeable free-text channel (`comment` is
    operator-authored free text, same category as every other PBS module's own `comment` field,
    already REVIEWED_TRUSTED elsewhere in this codebase — e.g. `pbs_notifications.py`,
    `pbs_tape_config.py`).
  - **`pbs_metrics_status` = REVIEWED_TRUSTED** — see fact #5's explicit argument (matches the
    `pve_node_rrddata`/`pmg_node_rrddata` precedent per the task's instruction, not the
    `pbs_s3_list_buckets`/`pbs_acme_tos`-style externally-authored-content precedent).

VERIFIED live shapes: None — all backend functions carry "Smoke-confirm:" comments; every shape
here is schema-derived, not live-proven against a running PBS with real influxdb-http/udp config.
"""

from __future__ import annotations

import re

from ._validate import check_digest as _check_digest
from ._validate import redact_secrets
from .backends import ProximoError
from .pbs import PbsBackend, _check_delete_list
from .planning import RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# Metrics Server ID — BYTE-IDENTICAL shape to pbs_s3.py's own `_ID_RE` (Wave 5a) and
# pbs_tape_config.py's `_check_tape_id` (Wave 4a): `^[A-Za-z0-9_][A-Za-z0-9._-]*$`, 3-32 chars.
# Kept as a fresh copy per this module — the established "each PBS module keeps its own copy,
# even for an identical shape" convention (a genuinely different field: a metrics-server id here,
# not an S3 client id or a tape drive/changer name).
_NAME_RE = re.compile(r"^(?:[A-Za-z0-9_][A-Za-z0-9._\-]*)\Z")

# Complete no-control-characters class, shared by every free-text-ish field on this plane the
# schema gives no character pattern for (bucket, organization) plus the explicit no-control-chars
# pattern the schema DOES give for comment (`[[:^cntrl:]]*`) — both land on the identical
# `[^\x00-\x1f\x7f]` class. Mirrors pbs_s3.py's own `_NO_CONTROL_RE`.
_NO_CONTROL_RE = re.compile(r"^[^\x00-\x1f\x7f]*\Z")

# influxdb-http `url` — copied VERBATIM from the live schema's own pattern (not hand-derived),
# re-anchored to \Z per this codebase's convention (see pbs_s3.py's `_ENDPOINT_RE` comment for why
# the pattern is preserved faithfully rather than reformatted). https?:// + hostname/IPv4/IPv6
# [+port] + an optional /path (control chars excluded from the path).
_URL_RE = re.compile(
    "https?://(?:(?:(?:(?:(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]*[a-zA-Z0-9])?)\\.)*(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]*[a-zA-Z0-9])?))|(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|\\[(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){6})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:::(?:(?:[0-9a-fA-F]{1,4}):){5})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){4})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,1}(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){3})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,2}(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){2})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,3}(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){1})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,4}(?:[0-9a-fA-F]{1,4}))?::)(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,5}(?:[0-9a-fA-F]{1,4}))?::)(?:[0-9a-fA-F]{1,4}))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,6}(?:[0-9a-fA-F]{1,4}))?::))))\\]))(?::(?:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]))?)|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){6})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:::(?:(?:[0-9a-fA-F]{1,4}):){5})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){4})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,1}(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){3})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,2}(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){2})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,3}(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){1})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,4}(?:[0-9a-fA-F]{1,4}))?::)(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,5}(?:[0-9a-fA-F]{1,4}))?::)(?:[0-9a-fA-F]{1,4}))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,6}(?:[0-9a-fA-F]{1,4}))?::))))(?:/[^\x00-\x1f\x7f]*)?\\Z"
)

# influxdb-udp `host` — copied VERBATIM from the live schema's own pattern, re-anchored to \Z.
# hostname/IPv4/IPv6 + a REQUIRED trailing :port (unlike `url` above, the port is NOT optional
# here — module docstring fact: the udp plane's own GET/POST/PUT all share this identical
# required-port shape, confirmed on all three verbs, not just one).
_HOST_RE = re.compile(
    "(?:(?:(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]*[a-zA-Z0-9])?)\\.)*(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]*[a-zA-Z0-9])?))|(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|\\[(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){6})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:::(?:(?:[0-9a-fA-F]{1,4}):){5})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){4})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,1}(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){3})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,2}(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){2})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,3}(?:[0-9a-fA-F]{1,4}))?::(?:(?:[0-9a-fA-F]{1,4}):){1})(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,4}(?:[0-9a-fA-F]{1,4}))?::)(?:(?:(?:(?:(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9])\\.){3}(?:25[0-5]|(?:2[0-4]|1[0-9]|[1-9])?[0-9]))|(?:[0-9a-fA-F]{1,4}):(?:[0-9a-fA-F]{1,4}))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,5}(?:[0-9a-fA-F]{1,4}))?::)(?:[0-9a-fA-F]{1,4}))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4}):){0,6}(?:[0-9a-fA-F]{1,4}))?::))))\\])):(?:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])\\Z"
)


def _check_name(value: str) -> str:
    s = str(value)
    if not (3 <= len(s) <= 32) or not _NAME_RE.match(s):
        raise ProximoError(
            f"invalid name: {value!r} (must start alnum/underscore, then alnum/./_/-, 3-32 chars)"
        )
    return s


def _check_url(value: str) -> str:
    s = str(value)
    if not _URL_RE.match(s):
        raise ProximoError(
            f"invalid url: {value!r} — expected an http(s) URL with a hostname, IPv4, or IPv6 "
            "host (optional port, optional path) per the live PBS schema"
        )
    return s


def _check_host(value: str) -> str:
    s = str(value)
    if not _HOST_RE.match(s):
        raise ProximoError(
            f"invalid host: {value!r} — expected a hostname:port, IPv4:port, or [IPv6]:port "
            "combination (port REQUIRED) per the live PBS schema"
        )
    return s


def _check_comment(value: str) -> str:
    s = str(value)
    if not _NO_CONTROL_RE.match(s):
        raise ProximoError(f"invalid comment: {value!r} — control characters not allowed")
    if len(s) > 128:
        raise ProximoError(f"invalid comment: {value!r} — must be <=128 chars")
    return s


def _check_short_field(value: str, field: str) -> str:
    """bucket/organization: schema gives NO character pattern at all, only minLength 1 /
    maxLength 32 (module docstring fact #9) — only the length bound + a defensive
    no-control-chars check apply; no invented InfluxDB-naming charset."""
    s = str(value)
    if not _NO_CONTROL_RE.match(s):
        raise ProximoError(f"invalid {field}: {value!r} — control characters not allowed")
    if not (1 <= len(s) <= 32):
        raise ProximoError(f"invalid {field}: {value!r} — length must be 1-32 chars")
    return s


def _check_bucket(value: str) -> str:
    return _check_short_field(value, "bucket")


def _check_organization(value: str) -> str:
    return _check_short_field(value, "organization")


def _check_positive_int(value, field: str) -> int:
    """mtu/max-body-size: schema gives NO bound at all (module docstring fact #10) — only a
    defensive 'must be positive' floor is applied here, mirroring pbs_s3.py's own
    `_check_port` framing ('a defensive default, NOT a schema-stated constraint'). No upper
    bound is invented for either field."""
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid {field}: {value!r} (must be an integer)") from exc
    if n <= 0:
        raise ProximoError(f"invalid {field}: {value!r} — must be a positive integer")
    return n


def _check_start_time(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid start_time: {value!r} (must be an integer)") from exc


# Credential-shaped field on this plane (module docstring fact #1): `token` (influxdb-http only —
# influxdb-udp carries no secret field at all, fact #2).
_SECRET_KEYS = frozenset({"token"})


def _redact_secrets(d: dict) -> dict:
    """Mask credential-shaped fields before they enter a plan string or Plan.current — the
    shared `_validate.redact_secrets` mechanic over this plane's own `_SECRET_KEYS`."""
    return redact_secrets(d, _SECRET_KEYS)


def _http_fields(
    bucket: str | None = None,
    comment: str | None = None,
    enable: bool | None = None,
    max_body_size: int | None = None,
    organization: str | None = None,
    token: str | None = None,
    url: str | None = None,
    verify_tls: bool | None = None,
) -> dict:
    """Shared field-assembly + validation for BOTH influxdb_http_create (where `url` is required
    — enforced by the caller's own signature, not here) and influxdb_http_update (where every
    field, including `url`, is optional). Builds a WIRE-hyphenated dict of whichever fields are
    not None. Mirrors pbs_s3.py's `_s3_fields` sharing idiom."""
    data: dict = {}
    if bucket is not None:
        data["bucket"] = _check_bucket(bucket)
    if comment is not None:
        data["comment"] = _check_comment(comment)
    if enable is not None:
        data["enable"] = bool(enable)
    if max_body_size is not None:
        data["max-body-size"] = _check_positive_int(max_body_size, "max_body_size")
    if organization is not None:
        data["organization"] = _check_organization(organization)
    if token is not None:
        # Control-char hygiene, no value in error message (secret-shaped) — mirrors
        # pbs_s3.py's `_s3_fields` handling of access_key/secret_key.
        if not _NO_CONTROL_RE.match(str(token)):
            raise ProximoError("invalid token: contains control characters")
        data["token"] = str(token)
    if url is not None:
        data["url"] = _check_url(url)
    if verify_tls is not None:
        data["verify-tls"] = bool(verify_tls)
    return data


def _udp_fields(
    comment: str | None = None,
    enable: bool | None = None,
    host: str | None = None,
    mtu: int | None = None,
) -> dict:
    """Shared field-assembly + validation for BOTH influxdb_udp_create (where `host` is required
    — enforced by the caller's own signature) and influxdb_udp_update (where every field is
    optional). Mirrors `_http_fields` above / pbs_s3.py's `_s3_fields` sharing idiom."""
    data: dict = {}
    if comment is not None:
        data["comment"] = _check_comment(comment)
    if enable is not None:
        data["enable"] = bool(enable)
    if host is not None:
        data["host"] = _check_host(host)
    if mtu is not None:
        data["mtu"] = _check_positive_int(mtu, "mtu")
    return data


# ---------------------------------------------------------------------------
# Backend functions — reads, cross-plane
# ---------------------------------------------------------------------------

def metrics_servers_list(api: PbsBackend) -> list[dict]:
    """GET /admin/metrics — list ALL configured metric servers (both influxdb-http and
    influxdb-udp) in one unified view. Response items are schema-enforced secret-free
    (`additionalProperties: false`, exactly 5 fields — module docstring fact #3); no read-layer
    strip is needed. Smoke-confirm: response shape."""
    return api._get("/admin/metrics") or []


def metrics_status(api: PbsBackend, history: bool = False, start_time: int | None = None) -> dict:
    """GET /status/metrics — backup server host + datastore performance metrics. Schema declares
    `returns: null` despite the description implying real data (module docstring fact #4) —
    best-effort passthrough, same handling as `pbs_s3_list_buckets`'s identical quirk (Wave 5a).
    REVIEWED_TRUSTED: server-authored numeric telemetry (module docstring fact #5). Smoke-confirm:
    response shape."""
    params: dict = {"history": bool(history)}
    if start_time is not None:
        params["start-time"] = _check_start_time(start_time)
    return api._get("/status/metrics", params=params) or {}


# ---------------------------------------------------------------------------
# Backend functions — reads, influxdb-http
# ---------------------------------------------------------------------------

def influxdb_http_list(api: PbsBackend) -> list[dict]:
    """GET /config/metrics/influxdb-http — list configured InfluxDB http metric servers. `token`
    IS present in the live schema's response shape (module docstring fact #1 — NOT a documented
    secret-free read, unlike pbs_s3's config reads) — stripped here at the READ layer. This strip
    is REQUIRED, not merely defensive. Smoke-confirm: response shape."""
    items = api._get("/config/metrics/influxdb-http") or []
    return [{k: v for k, v in it.items() if k != "token"}
            for it in items if isinstance(it, dict)]


def influxdb_http_get(api: PbsBackend, name: str) -> dict:
    """GET /config/metrics/influxdb-http/{name} — one InfluxDB http metric server's full shape,
    with `token` stripped at the READ layer (module docstring fact #1 — required, not merely
    defensive). Smoke-confirm: response shape."""
    name = _check_name(name)
    data = api._get(f"/config/metrics/influxdb-http/{name}") or {}
    return {k: v for k, v in data.items() if k != "token"}


# ---------------------------------------------------------------------------
# Backend functions — mutations, influxdb-http
# ---------------------------------------------------------------------------

def influxdb_http_create(
    api: PbsBackend,
    name: str,
    url: str,
    bucket: str | None = None,
    comment: str | None = None,
    enable: bool | None = None,
    max_body_size: int | None = None,
    organization: str | None = None,
    token: str | None = None,
    verify_tls: bool | None = None,
) -> None:
    """POST /config/metrics/influxdb-http — name/url REQUIRED, all else optional. Returns null
    (synchronous, module docstring fact #6). MUTATION — confirm-gated + audited at the server
    layer. `token` is forwarded RAW here (the create must actually work) but never recorded to
    the ledger — see plan_influxdb_http_create's redaction."""
    name = _check_name(name)
    data: dict = {"name": name, "url": _check_url(url)}
    data.update(_http_fields(
        bucket=bucket, comment=comment, enable=enable, max_body_size=max_body_size,
        organization=organization, token=token, verify_tls=verify_tls,
    ))
    api._post("/config/metrics/influxdb-http", data)


def influxdb_http_update(
    api: PbsBackend,
    name: str,
    bucket: str | None = None,
    comment: str | None = None,
    enable: bool | None = None,
    max_body_size: int | None = None,
    organization: str | None = None,
    token: str | None = None,
    url: str | None = None,
    verify_tls: bool | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> None:
    """PUT /config/metrics/influxdb-http/{name} — all body fields optional. Returns null
    (synchronous). MUTATION — confirm-gated + audited at the server layer. `token` (if given) is
    forwarded RAW here but never recorded to the ledger — see plan_influxdb_http_update's
    redaction."""
    name = _check_name(name)
    data = _http_fields(
        bucket=bucket, comment=comment, enable=enable, max_body_size=max_body_size,
        organization=organization, token=token, url=url, verify_tls=verify_tls,
    )
    if digest is not None:
        data["digest"] = _check_digest(digest)
    if delete is not None:
        data["delete"] = _check_delete_list(delete)
    api._put(f"/config/metrics/influxdb-http/{name}", data)


def influxdb_http_delete(api: PbsBackend, name: str, digest: str | None = None) -> None:
    """DELETE /config/metrics/influxdb-http/{name}. Returns null (synchronous). MUTATION —
    confirm-gated + audited at the server layer."""
    name = _check_name(name)
    params: dict = {}
    if digest is not None:
        params["digest"] = _check_digest(digest)
    api._delete(f"/config/metrics/influxdb-http/{name}", params=params)


# ---------------------------------------------------------------------------
# Backend functions — reads, influxdb-udp
# ---------------------------------------------------------------------------

def influxdb_udp_list(api: PbsBackend) -> list[dict]:
    """GET /config/metrics/influxdb-udp — list configured InfluxDB udp metric servers.
    REVIEWED_TRUSTED: no secret field exists on this sub-plane at all (module docstring fact #2 —
    verified field-by-field, not assumed by analogy to influxdb-http); no read-layer strip is
    applied — there is nothing to strip. Smoke-confirm: response shape."""
    return api._get("/config/metrics/influxdb-udp") or []


def influxdb_udp_get(api: PbsBackend, name: str) -> dict:
    """GET /config/metrics/influxdb-udp/{name} — one InfluxDB udp metric server's full shape.
    No secret field exists on this sub-plane (module docstring fact #2). Smoke-confirm: response
    shape."""
    name = _check_name(name)
    return api._get(f"/config/metrics/influxdb-udp/{name}") or {}


# ---------------------------------------------------------------------------
# Backend functions — mutations, influxdb-udp
# ---------------------------------------------------------------------------

def influxdb_udp_create(
    api: PbsBackend,
    name: str,
    host: str,
    comment: str | None = None,
    enable: bool | None = None,
    mtu: int | None = None,
) -> None:
    """POST /config/metrics/influxdb-udp — name/host REQUIRED, all else optional. Returns null
    (synchronous). MUTATION — confirm-gated + audited at the server layer. No secret field exists
    on this sub-plane (module docstring fact #2)."""
    name = _check_name(name)
    data: dict = {"name": name, "host": _check_host(host)}
    data.update(_udp_fields(comment=comment, enable=enable, mtu=mtu))
    api._post("/config/metrics/influxdb-udp", data)


def influxdb_udp_update(
    api: PbsBackend,
    name: str,
    comment: str | None = None,
    enable: bool | None = None,
    host: str | None = None,
    mtu: int | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> None:
    """PUT /config/metrics/influxdb-udp/{name} — all body fields optional. Returns null
    (synchronous). MUTATION — confirm-gated + audited at the server layer."""
    name = _check_name(name)
    data = _udp_fields(comment=comment, enable=enable, host=host, mtu=mtu)
    if digest is not None:
        data["digest"] = _check_digest(digest)
    if delete is not None:
        data["delete"] = _check_delete_list(delete)
    api._put(f"/config/metrics/influxdb-udp/{name}", data)


def influxdb_udp_delete(api: PbsBackend, name: str, digest: str | None = None) -> None:
    """DELETE /config/metrics/influxdb-udp/{name}. Returns null (synchronous). MUTATION —
    confirm-gated + audited at the server layer."""
    name = _check_name(name)
    params: dict = {}
    if digest is not None:
        params["digest"] = _check_digest(digest)
    api._delete(f"/config/metrics/influxdb-udp/{name}", params=params)


# ---------------------------------------------------------------------------
# Plan factories — influxdb-http
# ---------------------------------------------------------------------------

def plan_influxdb_http_create(
    name: str,
    url: str,
    bucket: str | None = None,
    comment: str | None = None,
    enable: bool | None = None,
    max_body_size: int | None = None,
    organization: str | None = None,
    token: str | None = None,
    verify_tls: bool | None = None,
) -> Plan:
    """Plan creating a PBS InfluxDB http metrics server. RISK_MEDIUM (module docstring's RISK
    RATING note — mirrors pbs_s3_client_create, NOT PVE's LOW-rated pve_metrics_server_set: this
    sub-plane exposes `token` directly on its tool surface, unlike PVE's currently-shipped
    pve_metrics_server_set tool — see module docstring's 2026-07-15 correction). PURE — no
    API read. SECRET CONTRACT: `token` is masked to '[redacted]' before entering the Plan."""
    name = _check_name(name)
    _check_url(url)
    extra = _http_fields(
        bucket=bucket, comment=comment, enable=enable, max_body_size=max_body_size,
        organization=organization, token=token, verify_tls=verify_tls,
    )
    kw = {"name": name, "url": url, **extra}
    return Plan(
        action="pbs_metrics_influxdb_http_create",
        target=f"pbs/config/metrics/influxdb-http/{name}",
        change=f"create PBS InfluxDB http metrics server {name!r}: {_redact_secrets(kw)}",
        current={},
        blast_radius=[
            f"creates a new InfluxDB http metrics server config {name!r} — PBS will begin "
            "pushing host/datastore metrics to this endpoint; no existing config is affected",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "this sub-plane can hold a stored API token — mirrors pbs_s3_client_create's "
            "credential-bearing-create reasoning, a step up from PVE's LOW-rated "
            "pve_metrics_server_set (whose currently-shipped tool surface doesn't expose a "
            "token parameter at all, even though PVE's own schema has one)",
        ],
        note=(
            "token is UNCONDITIONALLY redacted — only \"[redacted]\" appears in plans and the "
            "audit ledger. No snapshot primitive on this plane. Config is re-creatable — delete "
            "with pbs_metrics_influxdb_http_delete and re-create to correct a mistake."
        ),
    )


def plan_influxdb_http_update(
    api: PbsBackend,
    name: str,
    bucket: str | None = None,
    comment: str | None = None,
    enable: bool | None = None,
    max_body_size: int | None = None,
    organization: str | None = None,
    token: str | None = None,
    url: str | None = None,
    verify_tls: bool | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> Plan:
    """Plan updating a PBS InfluxDB http metrics server. CAPTURE: reads current config via
    influxdb_http_get (already token-stripped at the READ layer — module docstring fact #1) and
    redacts it AGAIN defensively (same defense-in-depth idiom as pbs_s3.py's own CAPTURE reads —
    belt-and-suspenders, not redundant given fact #1's severity)."""
    name = _check_name(name)
    kw = _http_fields(
        bucket=bucket, comment=comment, enable=enable, max_body_size=max_body_size,
        organization=organization, token=token, url=url, verify_tls=verify_tls,
    )
    if digest is not None:
        _check_digest(digest)
    current = _redact_secrets(influxdb_http_get(api, name))
    display = dict(_redact_secrets(kw))
    if delete is not None:
        # `is not None`, NOT truthiness — but delete=[] is REJECTED, not disclosed: httpx's
        # form encoding drops an empty-list value entirely, so a disclosed "delete=[]" would
        # never match what confirm=True actually sends (Wave 5b review finding 1).
        # _check_delete_list raises loudly here instead of silently under-disclosing.
        display["delete"] = _check_delete_list(delete)
    change_desc = ", ".join(f"{k}={v!r}" for k, v in display.items()) if display else "no fields changed"
    return Plan(
        action="pbs_metrics_influxdb_http_update",
        target=f"pbs/config/metrics/influxdb-http/{name}",
        change=f"update PBS InfluxDB http metrics server {name!r}: {change_desc}",
        current=current,
        blast_radius=[
            f"InfluxDB http metrics server {name!r}: rotating the token/url/bucket can "
            "silently redirect or break metrics delivery until the change is verified",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "this sub-plane can hold a stored API token — rotating credentials/endpoint can "
            "break metrics delivery — mirrors pbs_s3_client_update's reasoning",
        ],
        note=(
            "token (if given) is UNCONDITIONALLY redacted here. No snapshot primitive on this "
            "plane. Current config captured above (token-free) — re-apply it to revert."
        ),
    )


def plan_influxdb_http_delete(api: PbsBackend, name: str, digest: str | None = None) -> Plan:
    """Plan deleting a PBS InfluxDB http metrics server. CAPTURE: reads current config
    (token-stripped at the READ layer, then redacted again defensively). RISK_MEDIUM — mirrors
    pbs_s3_client_delete."""
    name = _check_name(name)
    if digest is not None:
        _check_digest(digest)
    current = _redact_secrets(influxdb_http_get(api, name))
    return Plan(
        action="pbs_metrics_influxdb_http_delete",
        target=f"pbs/config/metrics/influxdb-http/{name}",
        change=f"delete PBS InfluxDB http metrics server {name!r}",
        current=current,
        blast_radius=[
            f"removes InfluxDB http metrics server config {name!r} — PBS stops sending host/"
            "datastore metrics to this endpoint immediately; any stored API token is discarded "
            "from PBS's config (re-enter it if this config is re-created)",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "removes a config entry that may hold a stored API token — mirrors "
            "pbs_s3_client_delete's credential-bearing-delete reasoning",
        ],
        note=(
            "No snapshot primitive on this plane. Config is re-creatable — re-create with "
            "pbs_metrics_influxdb_http_create using the captured fields above (a fresh token, "
            "if any, must be re-supplied)."
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — influxdb-udp
# ---------------------------------------------------------------------------

def plan_influxdb_udp_create(
    name: str,
    host: str,
    comment: str | None = None,
    enable: bool | None = None,
    mtu: int | None = None,
) -> Plan:
    """Plan creating a PBS InfluxDB udp metrics server. RISK_LOW — matches PVE's
    pve_metrics_server_set baseline exactly: no credential field exists on this sub-plane at all
    (module docstring fact #2). PURE — no API read."""
    name = _check_name(name)
    _check_host(host)
    extra = _udp_fields(comment=comment, enable=enable, mtu=mtu)
    kw = {"name": name, "host": host, **extra}
    return Plan(
        action="pbs_metrics_influxdb_udp_create",
        target=f"pbs/config/metrics/influxdb-udp/{name}",
        change=f"create PBS InfluxDB udp metrics server {name!r}: {kw}",
        current={},
        blast_radius=[
            f"creates a new InfluxDB udp metrics server config {name!r} — PBS will begin "
            "pushing host/datastore metrics to this endpoint over UDP (fire-and-forget, no "
            "delivery guarantee); no existing config is affected",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "additive config-only change — this sub-plane carries NO credential field at all "
            "(schema-verified: no token/password/secret param exists on influxdb-udp), matching "
            "PVE's LOW-rated pve_metrics_server_set baseline exactly",
        ],
        note=(
            "No snapshot primitive on this plane. Re-create with "
            "pbs_metrics_influxdb_udp_create to restore after deletion."
        ),
    )


def plan_influxdb_udp_update(
    api: PbsBackend,
    name: str,
    comment: str | None = None,
    enable: bool | None = None,
    host: str | None = None,
    mtu: int | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> Plan:
    """Plan updating a PBS InfluxDB udp metrics server. CAPTURE: reads current config (no secret
    field exists on this sub-plane — module docstring fact #2 — nothing to redact). RISK_LOW."""
    name = _check_name(name)
    kw = _udp_fields(comment=comment, enable=enable, host=host, mtu=mtu)
    if digest is not None:
        _check_digest(digest)
    current = influxdb_udp_get(api, name)
    display = dict(kw)
    if delete is not None:
        # See plan_influxdb_http_update: delete=[] is REJECTED, not disclosed (Wave 5b review
        # finding 1 — httpx drops an empty-list form value, so it never reaches the wire).
        display["delete"] = _check_delete_list(delete)
    change_desc = ", ".join(f"{k}={v!r}" for k, v in display.items()) if display else "no fields changed"
    return Plan(
        action="pbs_metrics_influxdb_udp_update",
        target=f"pbs/config/metrics/influxdb-udp/{name}",
        change=f"update PBS InfluxDB udp metrics server {name!r}: {change_desc}",
        current=current,
        blast_radius=[
            f"InfluxDB udp metrics server {name!r}: changing host/mtu redirects or disrupts "
            "metrics delivery until the change is verified",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "config-only change — no credential field exists on this sub-plane, matching PVE's "
            "LOW-rated pve_metrics_server_set baseline",
        ],
        note=(
            "No snapshot primitive on this plane. Current config captured above — re-apply it "
            "manually to revert."
        ),
    )


def plan_influxdb_udp_delete(api: PbsBackend, name: str, digest: str | None = None) -> Plan:
    """Plan deleting a PBS InfluxDB udp metrics server. CAPTURE: reads current config. RISK_LOW —
    matches PVE's pve_metrics_server_delete baseline exactly."""
    name = _check_name(name)
    if digest is not None:
        _check_digest(digest)
    current = influxdb_udp_get(api, name)
    return Plan(
        action="pbs_metrics_influxdb_udp_delete",
        target=f"pbs/config/metrics/influxdb-udp/{name}",
        change=f"delete PBS InfluxDB udp metrics server {name!r}",
        current=current,
        blast_radius=[
            f"removes InfluxDB udp metrics server config {name!r} — PBS stops sending host/"
            "datastore metrics to this endpoint immediately; no data loss (fire-and-forget UDP "
            "carried no durable state)",
        ],
        risk=RISK_LOW,
        risk_reasons=[
            "config-only change — stops metrics forwarding, no credential or data loss, matching "
            "PVE's LOW-rated pve_metrics_server_delete baseline",
        ],
        note=(
            "No UNDO primitive on this plane. Re-create with pbs_metrics_influxdb_udp_create to "
            "restore."
        ),
    )
