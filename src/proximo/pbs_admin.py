"""PBS admin job views + node odds + pull/push (Wave 5c of the full-surface campaign,
`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 5 decomposition (PBS s3 + remainder —
CLOSES THE PBS PLANE)", "5c — admin job views + node odds + pull/push"). This is the FINAL chunk
of Wave 5, which closes the PBS plane.

Schema truth: `.scratch/api-schemas-2026-07-15/wave5c-pbs-admin-schema.json` (13 nodes extracted
from the live PBS apidoc, pulled 2026-07-15, by walking /admin/gc, /admin/prune, /admin/sync,
/admin/verify, /admin/traffic-control, /nodes/{node}/config, /nodes/{node}/identity,
/nodes/{node}/rrd, /nodes/{node}/report, /version, /pull, /push, /ping).

Endpoint table (13 tools total — 11 read, 2 mutation):

  Admin job views (5, all read):
    GET /admin/gc[?store=]                    — pbs_admin_gc_jobs_list
    GET /admin/prune[?store=]                 — pbs_admin_prune_jobs_list
    GET /admin/sync[?store=&sync-direction=]  — pbs_admin_sync_jobs_list
    GET /admin/verify[?store=]                — pbs_admin_verify_jobs_list
    GET /admin/traffic-control                — pbs_admin_traffic_control_status

  Node odds (6, 5 read + 1 mutation):
    GET /nodes/{node}/config                  — pbs_node_config_get   (read)
    PUT /nodes/{node}/config                  — pbs_node_config_set   (MUTATION, HIGH)
    GET /nodes/{node}/identity                — pbs_node_identity     (read)
    GET /nodes/{node}/rrd?cf=&timeframe=       — pbs_node_rrd          (read)
    GET /nodes/{node}/report                  — pbs_node_report       (read, ADVERSARIAL)
    GET /version                              — pbs_version           (read)

  Pull/push (2, both mutation):
    POST /pull                                — pbs_pull  (MUTATION, MEDIUM/HIGH)
    POST /push                                — pbs_push  (MUTATION, MEDIUM/HIGH)

NOT BUILT — genuinely covered elsewhere, not a gap (verified against the live registry, not
assumed):

  1. **`POST /admin/prune/{id}/run`, `POST /admin/sync/{id}/run`, `POST /admin/verify/{id}/run`
     are ALREADY SHIPPED** as the generic `pbs_job_run(job_type, job_id, confirm)` tool
     (`src/proximo/tools/pve_backup.py`, backed by `backup_schedules.pbs_scheduled_job_run`,
     which itself calls `POST /admin/{job_type}/{job_id}/run` — byte-identical to these three
     paths). The task brief that scoped this wave listed
     `pbs_admin_prune_job_run`/`pbs_admin_sync_job_run`/`pbs_admin_verify_job_run` as candidates
     to build; building type-specific wrappers around an endpoint the generic tool already
     covers would be a duplicate MCP tool name space for the SAME wire call — not built here.
     This reduces the wave's admin-job-views section from the originally-estimated 8 tools to 5
     (the four LIST views + traffic-control status; the three RUN endpoints are out).

     **Genuine bug found while researching this dedup — FIXED in Wave 5d (Wave 5c review
     Finding 4):** `pbs_scheduled_job_run`'s old docstring claimed "Returns a UPID (async
     task)" and `pve_backup.py`'s `pbs_job_run` wrapper hardcoded `outcome="submitted"` — but
     the LIVE schema for all three of `/admin/{prune,sync,verify}/{id}/run` declares
     `"returns": {"type": "null"}`, the SAME "returns null despite doing real work" quirk this
     campaign has confirmed repeatedly (Wave 3b ACME cert order/renew, Wave 4d tape backup-job
     run, Wave 5b metrics status). The wrapper now resolves its outcome from the real return
     via the callable idiom (`"submitted" if result else "ok"`), and the backend docstring
     states the schema-verified contract.
  2. **`GET /ping`** — SKIPPED per the task brief's own default: a doctor-level liveness probe
     ("Dummy method which replies with `{"pong": True}`", `permissions: {"user": "world"}` — no
     auth needed at all) with no governance value as an audited MCP tool. Any other read tool on
     this server already proves the API daemon is reachable and authenticated as a side effect;
     `/ping` adds nothing `pbs_version` (also trivial, but at least returns real version
     identity) doesn't already cover. Not built.
  3. **`GET /admin/prune/{id}` and `GET /admin/sync/{id}` and `GET /admin/verify/{id}`** (bare,
     no further path segment) are "Directory index." stubs (`returns: null`) — the SAME shape as
     `/admin/s3/{id}` (Wave 5a) / `/config/metrics` (Wave 5b) / `/tape/media/list/{uuid}`
     (Wave 4d): a bare API-tree pointer to `run`, not a real data endpoint. Not built.

PLANE-CLOSE HONESTY NOTE (the checkable claim the 0.23.0 release makes — REWRITTEN in Wave 5d
after the Wave 5c adversarial review proved the original note FALSE: 14+ real endpoints were
missing and on no exclusion list; `pbs_datastore_admin.py` built them. This note is now
SELF-CONTAINED — it recaps exclusions living in OTHER modules' docstrings too — and is proven
programmatically by `.scratch/sdd/wave-5d-plane-close-audit.py`, which walks the live apidoc's
(method, path) set, diffs it against every `api._get/_post/_put/_delete` call across all pbs
modules, and FAILS if any residual is not on this list.):

After Wave 5d, PBS Management-API coverage is complete except these documented dispositions —

  A. CLIENT WIRE PROTOCOL: the apidoc's `/backup/_upgrade_` (Backup API, HTTP/2) and
     `/reader/_upgrade_` (Restore API, HTTP/2) roots wholesale, plus their Management-root
     upgrade stubs `GET /backup` / `GET /reader` — chunk-stream protocols for
     `proxmox-backup-client`, not an admin surface.
  B. CONSOLE CLASS (Wave 11, GATED behind an explicit John decision — "handing an agent a
     console is a different trust category"): `GET /nodes/{node}/vncwebsocket`,
     `POST /nodes/{node}/termproxy`, `POST /access/vncticket` (VNC-ticket verification).
  C. SESSION/BROWSER AUTH HANDSHAKE: `POST /access/ticket` + `DELETE /access/ticket`
     (login-session tickets — Proximo authenticates with a scoped API token, never tickets)
     and `POST /access/openid/auth-url` + `POST /access/openid/login` (the OpenID
     browser-redirect flow; meaningless outside an interactive browser).
  D. PASSWORD SELF-CHANGE: `PUT /access/password` (self-service semantics, distinct from
     `pbs_user_update`'s admin-path reset) — excluded Wave 2a.
  E. NODE POWER: `POST /nodes/{node}/status` ("Reboot or shutdown the node") — excluded in
     `pbs_node.py` (Wave 2c), mirroring the identical never-built PVE-side exclusion; a future
     opt-in PROXIMO_ENABLE_NODE_POWER gate could add both sides. (Recapped here per Wave 5c
     review Finding 6 — the exclusion predates this module but the note must stand alone.)
  F. LIVENESS PROBE: `GET /ping` — see NOT BUILT #2 above.
  G. SNAPSHOT-CONTENT BROWSE/TRANSFER (Wave 5d disposition): `GET .../catalog`,
     `GET .../download`, `GET .../download-decoded`, `GET .../pxar-file-download`,
     `POST .../upload-backup-log` (all under /admin/datastore/{store}) — these serve/accept the
     raw BYTES of files inside backup snapshots (octet streams, not JSON admin data; the JSON
     API backend doesn't model byte-stream responses), the content-plane sibling of exclusion A.
  H. ALIASES/AGGREGATES OF COVERED CAPABILITY (no missing capability, argued per entry):
     `GET /admin/gc/{store}` (path-alias of pbs_admin_gc_jobs_list's store filter — fact #1);
     `GET /nodes` ("only for compatibility" per its own schema; PBS is single-node);
     `GET /access/domains` (unified realm index == the per-type pbs_realm_*_list reads, 2b);
     `GET /config/datastore` (== pbs_datastores_list + pbs_datastore_get per name);
     `GET /admin/datastore/{store}/files` (the files array already rides in every
     pbs_snapshots_list item); `GET /tape/changer` / `GET /tape/drive` (runtime aggregate
     views — config fields via pbs_tape_changer_list/pbs_tape_drive_list, hardware
     vendor/model/serial via pbs_tape_scan_*, drive activity/state via pbs_tape_drive_status).
  I. DOCUMENTED FOLLOW-UP DEBT (campaign doc, not silent gaps): `GET /tape/backup`
     (job list with last-run status fields — Wave 4d debt) and
     `PUT /tape/drive/{drive}/export-media` (Wave 4c debt).
  Plus 31 "Directory index." routing stubs (returns:null pointers to their own children —
  never data endpoints; the audit script lists them).

  A gap found LATER that isn't on this list is a real miss, not a silently-accepted one — run
  the audit script to check; it exits nonzero on any undocumented residual.

SCHEMA-VERIFIED FACTS (binding on this build — from the live schema, not memory):

  1. **`/admin/{gc,prune,sync,verify}` job runs (POST .../{id}/run) all declare
     `"returns": {"type": "null"}`** — confirmed on all three (gc has no RUN equivalent — GC's
     "run" is the existing per-datastore `POST /admin/datastore/{store}/gc`, already shipped as
     `pbs_gc_start`, which the live schema DOES confirm returns a UPID string, unlike these
     three). This directly falsified the task brief's own open question ("prune_job_run — UPID?
     verify") — the answer, checked against the schema, is NO UPID; see NOT BUILT #1 above for
     why these three aren't rebuilt here regardless.
     **`GET /admin/gc/{store}` (the 4th sibling's own path child — Wave 5c review Finding 5,
     now schema-CHECKED rather than silently assumed):** unlike `/admin/{prune,sync,verify}/
     {id}` (genuine "Directory index." stubs, `returns: null`), `/admin/gc/{store}` is a REAL
     endpoint — but it is the PATH-SEGMENT ALIAS of the collection GET's own `store=` query
     filter, verified on all three axes: byte-identical description ("List all GC jobs (max one
     per datastore)"), byte-identical `returns` schema (the same GC-job-info array), and its
     `store` property STILL carries `"optional": 1` even in the path form (the same merged
     path+body parameter-schema artifact as pbs_s3.py fact #4). `pbs_admin_gc_jobs_list(store=
     ...)` already exposes the identical capability via the query form — the alias is not built
     as a separate tool.
  2. **`/admin/sync`'s `sync-direction` list filter is a closed 3-value enum
     (`all`/`push`/`pull`, default `"pull"`)** — validated here (small, fully-documented closed
     set worth catching a typo on, matching `pbs_s3.py`'s `provider-quirks` precedent) rather
     than passed through un-validated.
  3. **`/pull`'s `remote` parameter is OPTIONAL; `/push`'s `remote` parameter is REQUIRED** —
     confirmed field-by-field on both live parameter schemas (pull: `"optional": 1` present on
     `remote`; push: absent). A genuine, deliberate asymmetry — NOT normalized to "both required"
     or "both optional" here; the schema is trusted over an intuition that a pull needs to name
     its source just as much as a push needs to name its destination. Smoke-confirm what PBS
     actually does when `remote` is omitted on a pull (local-to-local sync between namespaces on
     the same datastore? A configured default remote? The schema does not say).
  4. **`POST /pull` and `POST /push` BOTH declare `"returns": {"type": "null"}`** — no UPID, for
     an operation that transfers real backup data over the network and can run for a long time.
     This is the SAME "returns null despite real work" quirk as fact #1 above and this
     campaign's prior waves, but with materially higher operational stakes: pull/push are
     genuinely long-running network transfers, unlike a quick job-config trigger. **Smoke-confirm
     against a live PBS whether this call blocks synchronously for the FULL transfer duration, or
     whether the schema is simply under-documented and a UPID is returned in practice** — an MCP
     client treating `confirm=True` as a fire-and-forget call could otherwise time out waiting on
     a multi-GB sync. `outcome="ok"` here means "the HTTP call returned", not a schema-confirmed
     guarantee about how long that takes. Flagged prominently in both tool docstrings below.
  5. **`/pull` carries `decryption-keys` (list) + `resync-corrupt` (bool) that `/push` does NOT
     have; `/push` carries `encryption-key` (singular) that `/pull` does NOT have** — confirmed
     field-by-field, not assumed symmetric. Makes sense directionally: pulling FROM a remote may
     need to decrypt what's already encrypted there and can retry a locally-corrupted
     verification; pushing TO a remote may need to (re-)encrypt under a locally-registered key.
     Neither `decryption-keys` nor `encryption-key` is treated as secret material here — they are
     CALLER-CHOSEN REFERENCES to encryption keys already registered via `pbs_encryption_key_*`
     (`pbs_s3.py`, Wave 5a) or `pbs_tape_key_*` (Wave 4b); the raw key material itself never
     flows through this endpoint.
  6. **`remove-vanished` (both pull and push, default `false`) deletes real data**: pull's own
     description — "Delete vanished backups. This removes the local copy if the remote backup was
     deleted." — matches the task brief's framing exactly; push's identical-text description
     means the SAME thing mirrored onto the REMOTE side (a vanished-locally backup gets deleted
     on the remote datastore push is writing to). Both permission blocks single out
     `remove-vanished` as needing ADDITIONAL privilege beyond the base transfer privilege
     (`Datastore.Prune` for pull, an unspecified "additional privileges" note for push) —
     independent confirmation this is a materially different risk class than the rest of the
     call's params. Risk escalates when set (see RISK RATING below).
  7. **`group-filter` (both) selects WHICH backup groups the whole call touches; omitting it
     means "every group in scope"** — its own schema description: `[<exclude:|include:>]
     <type:<vm|ct|host>|group:GROUP|regex:RE>`. Not validated against this compound grammar here
     (too fragile to hand-roll a parser that might reject a valid-to-PBS filter string) — each
     entry gets only a defensive no-control-chars check, matching the established
     "pass compound/enum-ish strings through, let the live API enforce its own grammar"
     convention (`pbs_s3.py`'s `delete`, `pbs_tape_media.py`'s `store` mapping).
  8. **`ns`/`remote-ns` (namespace) on `/pull`/`/push` share the SAME nested-namespace shape as
     the already-shipped `/admin/datastore/{store}/verify`'s own `ns` param** — reuses
     `pbs._check_namespace` directly rather than a fresh copy (an established SHARED validator
     already used across `pbs.py`'s own `verify_start`/`prune`, unlike per-plane fields like
     `pbs_s3.py`'s `region` that get their own module-local copy even for an identical shape).
  9. **`max-depth` (0-7) and `worker-threads` (1-32) both carry hard schema bounds** — validated
     here (unlike, say, `pbs_metrics.py`'s `mtu`/`max-body-size`, which the schema leaves fully
     unbounded and this codebase does not invent a ceiling for). `transfer-last` has a floor
     (>=1) but NO declared ceiling — only the floor is enforced, no invented upper bound.
 10. **`GET /nodes/{node}/config` returns `http-proxy` (a general `[http://]<host>[:port]`
     string, 1-128 chars) with NO character pattern given at all** — the schema neither confirms
     nor rules out that an operator's proxy URL embeds HTTP Basic-auth userinfo
     (`http://user:pass@host:port`, valid per the URL spec and a common real-world proxy-auth
     idiom). Unlike `pbs_s3.py`'s `secret-key` (schema-confirmed to NEVER appear in a read) or
     `pbs_metrics.py`'s `token` (schema-confirmed to ALWAYS appear), this field is genuinely
     ambiguous — **decided (per this task's explicit "check + argue it" instruction): treat
     `http-proxy` as secret-SHAPED, not secret-typed.** `_redact_http_proxy` masks ONLY an
     embedded `user[:pass]@` prefix if present (regex match on standard URL userinfo syntax),
     leaving the operationally-useful `host[:port]` visible — full redaction would make the read
     tool useless for verifying which proxy is actually configured, but a userinfo-embedded
     credential must never land in the Plan/ledger unmasked. Applied at the single shared
     `node_config_get` read-layer function (used by BOTH the read tool and
     `plan_node_config_set`'s CAPTURE) — one masking point, not two. The RAW caller-supplied
     value is still forwarded unmasked to the live PBS API on `confirm=True` (the mutation must
     actually work) and masked only in the Plan's `change` display string.
 11. **`ciphers-tls-1.2`/`ciphers-tls-1.3` are settable on this node-config plane** — Python
     cannot name a parameter with an embedded dot, so the wire hyphenation convention this
     codebase otherwise derives mechanically from the Python name (underscore -> hyphen) does
     NOT apply cleanly here; `ciphers_tls_1_2`/`ciphers_tls_1_3` are mapped to their exact wire
     names via an explicit dict, not the generic transform. Misconfiguring either can make the
     API/web proxy refuse ALL TLS connections — see RISK RATING.
 12. **`GET /nodes/{node}/identity`'s `node` path parameter is OPTIONAL** — the ONLY one of the
     four node-scoped endpoints in this module where that's true (`config`/`rrd`/`report` all
     REQUIRE it per their own schemas, no `optional` flag). Confirmed field-by-field, not assumed
     uniform. `node: str = "localhost"` is still the Python default here for interface
     consistency with the rest of this module and `pbs_node.py`'s own established convention —
     harmless either way since PBS accepts it.
 13. **`GET /nodes/{node}/rrd`'s `cf` and `timeframe` are BOTH REQUIRED, no server-side default**
     — unlike PVE's own `/nodes/{node}/rrddata` (`observability.py`'s `node_rrddata`, which
     defaults `timeframe="hour"` because PVE's schema gives PVE a default). PBS's schema gives
     neither a default, so BOTH are required Python params here too — not silently defaulted for
     ergonomics. `cf` enum is `{MAX, AVERAGE}` (same 2 values as PVE); `timeframe` enum is
     `{hour, day, week, month, year, decade}` — PBS adds `decade`, which PVE's own enum lacks.
     Declares `"returns": {"type": "null"}` despite being a real telemetry read — the now-
     familiar quirk (facts #1/#4 above); passed through best-effort as a dict, matching
     `pbs_metrics_status`'s identical handling (Wave 5b) — Smoke-confirm the real shape (list of
     time-series points, like PVE's `rrddata`, vs. a flat current-values dict, like
     `pbs_metrics_status` — genuinely unknown from a `null`-declared schema).

RISK RATING (module-specific reasoning):
  - **Admin job-view LISTs + traffic-control status = read-only, no risk rating** (not
    mutations).
  - **`pbs_node_config_set` = RISK_HIGH, uniform across the whole PUT** (per-action, not
    conditional on which specific field a given call happens to touch — mirrors
    `pbs_metrics.py`'s "the PLANE holds credential material at rest, so the rating is
    per-action" reasoning, applied here to a different hazard: **the PLANE can silently break
    host administrability**). Three independent lockout-class paths through this ONE endpoint:
    (a) `ciphers-tls-1.2`/`ciphers-tls-1.3` misconfiguration can make the API/web proxy refuse
    all TLS connections — mirrors `pbs_node.py`'s `network_reload`=HIGH ("applies staged->live",
    can sever connectivity) and `cert_upload`=HIGH (replaces the cert, could break HTTPS); (b)
    `http-proxy` misconfiguration can silently break outbound connectivity needed by
    notifications/ACME renewal/subscription-check; (c) `acme`/`acmedomain0-4` misconfiguration
    can break automatic certificate renewal. CAPTURE-or-declare (mirrors `pbs_node.py`'s
    `plan_dns_set` idiom): reads current config first via the masked `node_config_get`; on read
    failure -> `complete=False` + an honest note.
  - **`pbs_pull`/`pbs_push` = RISK_MEDIUM by default, escalating to RISK_HIGH when
    `remove_vanished=True`** — matches the task brief's explicit framing exactly (fact #6 above).
    MEDIUM baseline: both WRITE real backup data (pull into the LOCAL datastore, push into the
    REMOTE datastore) — disk consumption, and an over-broad `group-filter` (or none at all) pulls
    or pushes every group in scope, not a targeted set. HIGH when `remove_vanished=True`: a real,
    permanent DELETE of snapshots on the RECEIVING side that vanished on the SENDING side — no
    dry-run knob exists on this endpoint (unlike `pbs_prune`'s own `dry_run` param), so the
    caller cannot preview which snapshots would be deleted before they are gone. No rollback
    primitive for either direction — deleted snapshots (remove-vanished) or written-then-unwanted
    data (an over-broad pull/push) both require manual cleanup after the fact.

Taint:
  - **`pbs_admin_gc_jobs_list`/`pbs_admin_prune_jobs_list`/`pbs_admin_sync_jobs_list`/
    `pbs_admin_verify_jobs_list` = REVIEWED_TRUSTED** — job comments/schedules are OPERATOR-
    AUTHORED config (the SAME `comment`/`schedule` field category as `pbs_jobs_list`
    (`backup_schedules.pbs_scheduled_jobs_list`, already REVIEWED_TRUSTED), just the job-level
    admin VIEW of the identical underlying jobs rather than the `/config/{type}` config-CRUD
    view — matches that precedent exactly, argued rather than defaulted per the task's
    instruction.
  - **`pbs_admin_traffic_control_status` = REVIEWED_TRUSTED** — per-rule config (`comment`,
    `network`, rate/burst limits — operator-authored) PLUS live counters (`cur-rate-in`,
    `cur-rate-out` — server-computed numbers). No attacker-shapeable free-text channel; matches
    the task's explicit "traffic-control status = counters -> REVIEWED_TRUSTED" instruction.
    Distinct from the ALREADY-SHIPPED `pbs_traffic_controls_list` (`GET /config/traffic-control`,
    `tools/pbs.py`) — that tool is the CONFIG-CRUD view (create/update rules with
    `pbs_traffic_control_upsert`); this one is the LIVE STATUS view (current ingress/egress
    rates per rule, no mutation counterpart) — named/documented to keep the two distinct rather
    than colliding on "traffic control list".
  - **`pbs_node_config_get`/`pbs_node_config_set` = REVIEWED_TRUSTED** — structured operator
    config; `http-proxy` is defensively masked (fact #10) before it can reach a Plan/ledger
    surface, so even the genuinely-ambiguous field never lands unredacted downstream of that one
    masking point.
  - **`pbs_node_identity` = REVIEWED_TRUSTED** — a single machine-derived identifier
    (`/etc/machine-id`), not attacker-shapeable free text.
  - **`pbs_node_rrd` = REVIEWED_TRUSTED** — matches the `pve_node_rrddata`/`pmg_node_rrddata`/
    `pbs_metrics_status` precedent (server-authored numeric telemetry), per the task's explicit
    instruction.
  - **`pbs_node_report` = ADVERSARIAL** — per the task's explicit instruction: a free-text
    diagnostic bundle (`returns: {"type": "string"}`) that PBS's own description says is a
    "report" — the same category of externally-influenceable free text as
    `pve_node_syslog`/`pbs_node_journal`/`pbs_node_task_log` (already `ADVERSARIAL_TOOLS`): a
    diagnostic report plausibly embeds config values, log tails, and system state an attacker
    with prior host access could have shaped.
  - **`pbs_version` = REVIEWED_TRUSTED** — three fixed version-identity strings, not
    attacker-shapeable.
  - **`pbs_pull`/`pbs_push` = REVIEWED_TRUSTED** — both declare `returns: null` (fact #4); no
    content channel exists to classify at all, matching `pbs_s3_check`/`pbs_s3_reset_counters`'s
    identical null-return reasoning (Wave 5a).

VERIFIED live shapes: None — all backend functions carry "Smoke-confirm:" comments; every shape
here is schema-derived, not live-proven against a running PBS with real jobs/node-config/remote
configured.
"""

from __future__ import annotations

import re

from ._validate import check_digest as _check_digest
from .backends import ProximoError
from .pbs import PbsBackend, _check_delete_list, _check_namespace, _check_pbs_node, _check_store
from .planning import RISK_HIGH, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# PBS "resource id" shape shared by remote/decryption-keys/encryption-key on this plane —
# BYTE-IDENTICAL to pbs_s3.py's `_ID_RE` / pbs_metrics.py's `_NAME_RE` / pbs_tape_config.py's
# `_check_tape_id` (all `^[A-Za-z0-9_][A-Za-z0-9._-]*$`, 3-32 chars) — kept as a fresh copy per
# this module's own convention (each PBS module keeps its own copy, even for an identical shape).
_ID_RE = re.compile(r"^(?:[A-Za-z0-9_][A-Za-z0-9._\-]*)\Z")

# Complete no-control-characters class, shared by every free-text-ish field on this plane the
# schema gives no character pattern for. Mirrors pbs_s3.py's/pbs_metrics.py's `_NO_CONTROL_RE`.
_NO_CONTROL_RE = re.compile(r"^[^\x00-\x1f\x7f]*\Z")

# "description" (node config) is explicitly MULTILINE per its own schema pattern
# (`/(?m)^([[:^cntrl:]]*)$/`) — newlines are line separators, not a forbidden control char, unlike
# every other free-text field on this plane. \n (0x0a) is deliberately excluded from the banned
# range below (0x00-0x09, 0x0b-0x1f, 0x7f) so a multi-line comment round-trips.
_MULTILINE_NO_CONTROL_RE = re.compile(r"^[^\x00-\x09\x0b-\x1f\x7f]*\Z")

# ciphers-tls-1.2 / ciphers-tls-1.3: OpenSSL cipher-list charset, copied verbatim from the live
# schema pattern.
_CIPHERS_RE = re.compile(r"^[0-9A-Za-z_:, +!\-@=.]+\Z")

# email-from: single-line no-control-chars (schema pattern `/^[[:^cntrl:]]*$/`, NOT multiline —
# unlike `description` above).
_EMAIL_FROM_RE = re.compile(r"^[^\x00-\x1f\x7f]*\Z")

# HTTP proxy optional scheme prefix — the userinfo/host split is NOT done by regex: Wave 5c
# review Finding 3 proved the original single-regex form (`[^/@\s]+@` = match to the FIRST @)
# leaked the password TAIL when the password itself contained a literal @ ('user:p@ss@host' ->
# '[redacted]@ss@host'). The fix in `_redact_http_proxy` strips the scheme with this pattern,
# then splits the remaining authority on the LAST @ (`str.rsplit("@", 1)`) — RFC 3986 authority
# semantics: the host part never legally contains @ (IPv6 hosts are bracketed, no @ inside), so
# everything before the last @ is userinfo, however many @s the password carries.
_PROXY_SCHEME_RE = re.compile(r"^(?P<prefix>(?:[a-zA-Z][a-zA-Z0-9+.\-]*://)?)(?P<authority>.*)\Z", re.DOTALL)

# default-lang: closed enum copied verbatim from the live schema.
_VALID_DEFAULT_LANGS = frozenset({
    "ar", "ca", "da", "de", "en", "es", "eu", "fa", "fr", "gl", "he", "hu", "it", "ja", "kr",
    "nb", "nl", "nn", "pl", "pt_BR", "ru", "sl", "sv", "tr", "zh_CN", "zh_TW",
})

# Properties deletable via PUT /nodes/{node}/config's `delete` list — copied verbatim from the
# live schema enum. NOT validated against here (passed through un-validated, matching the
# established "pass compound/enum-ish lists through, let the live API enforce its own enum"
# convention — pbs_s3.py/pbs_metrics.py/pbs_tape_media.py); documented for completeness only.
_NODE_CONFIG_DELETABLE = frozenset({
    "acme", "acmedomain0", "acmedomain1", "acmedomain2", "acmedomain3", "acmedomain4",
    "http-proxy", "email-from", "ciphers-tls-1.3", "ciphers-tls-1.2", "default-lang",
    "description", "task-log-max-days", "consent-text", "location",
})

# sync-direction: closed 3-value enum (module docstring fact #2) — validated (small,
# fully-documented closed set worth catching a typo on, matching pbs_s3.py's `provider-quirks`
# precedent) rather than passed through.
_VALID_SYNC_DIRECTIONS = frozenset({"all", "push", "pull"})

# RRD consolidation function / timeframe enums (module docstring fact #13) — PBS-specific copies,
# NOT reused from observability.py's PVE-scoped `_VALID_CF`/`_VALID_TIMEFRAMES`: PBS's timeframe
# enum additionally includes "decade", which PVE's own enum lacks.
_VALID_CF = frozenset({"MAX", "AVERAGE"})
_VALID_RRD_TIMEFRAMES = frozenset({"hour", "day", "week", "month", "year", "decade"})

# Python identifier -> wire name for the two dotted cipher fields, which Python cannot spell
# directly (module docstring fact #11) — an explicit mapping, not the generic underscore->hyphen
# transform every other field on this plane uses.
_CIPHER_WIRE_NAMES = {
    "ciphers_tls_1_2": "ciphers-tls-1.2",
    "ciphers_tls_1_3": "ciphers-tls-1.3",
}


def _check_id(value: str, label: str = "id") -> str:
    s = str(value)
    if not (3 <= len(s) <= 32) or not _ID_RE.match(s):
        raise ProximoError(
            f"invalid {label}: {value!r} (must start alnum/underscore, then alnum/./_/-, "
            "3-32 chars)"
        )
    return s


def _check_no_control(value: str, field: str, min_len: int = 0, max_len: int | None = None) -> str:
    s = str(value)
    if not _NO_CONTROL_RE.match(s):
        raise ProximoError(f"invalid {field}: {value!r} — control characters not allowed")
    if len(s) < min_len or (max_len is not None and len(s) > max_len):
        bound = f"{min_len}-{max_len}" if max_len is not None else f">= {min_len}"
        raise ProximoError(f"invalid {field}: {value!r} — length must be {bound} chars")
    return s


def _check_byte_size(value: str, field: str) -> str:
    """rate-in/rate-out/burst-in/burst-out: schema gives length bounds (1-64) but no character
    pattern — validated defensively (length + no control chars), matching pbs_s3.py's
    `_check_byte_size` precedent, not an invented numeric-with-unit regex."""
    return _check_no_control(value, field, min_len=1, max_len=64)


def _check_description(value: str) -> str:
    s = str(value)
    if not _MULTILINE_NO_CONTROL_RE.match(s):
        raise ProximoError(f"invalid description: {value!r} — control characters (other than newline) not allowed")
    return s


def _check_email_from(value: str) -> str:
    s = str(value)
    if not (2 <= len(s) <= 64) or not _EMAIL_FROM_RE.match(s):
        raise ProximoError(f"invalid email_from: {value!r} — 2-64 chars, no control characters")
    return s


def _check_http_proxy(value: str) -> str:
    """Schema gives NO character pattern at all for http-proxy — only length bounds (1-128) are
    schema-derived; the no-control-chars check is a defensive addition (module docstring fact
    #10). This does NOT validate/reject an embedded userinfo credential — that's handled by
    `_redact_http_proxy` at the Plan/ledger surface, not here."""
    return _check_no_control(value, "http_proxy", min_len=1, max_len=128)


def _check_consent_text(value: str) -> str:
    """Schema gives ONLY a maxLength (65536) — no character pattern, no minLength. A consent
    banner may legitimately contain any formatting an operator wants; no no-control-chars check
    is invented here (unlike description/email-from, which the schema DOES pattern-constrain)."""
    s = str(value)
    if len(s) > 65536:
        raise ProximoError(f"invalid consent_text: length must be <= 65536 chars, got {len(s)}")
    return s


def _check_location(value: str) -> str:
    """Schema gives NO pattern and NO length bound at all for location — only a defensive
    no-control-chars check is applied; no bound is invented (mirrors pbs_s3.py's
    `_check_key_material` framing)."""
    s = str(value)
    if not _NO_CONTROL_RE.match(s):
        raise ProximoError(f"invalid location: {value!r} — control characters not allowed")
    return s


def _check_ciphers(value: str, field: str) -> str:
    s = str(value)
    if not _CIPHERS_RE.match(s):
        raise ProximoError(f"invalid {field}: {value!r} — OpenSSL cipher-list charset only")
    return s


def _check_acme_field(value: str, field: str) -> str:
    """acme/acmedomain0-4 are accepted as PRE-FORMATTED compound strings per PBS's own typetext
    syntax (e.g. 'account=myaccount' or 'domain=example.com,alias=other.com,plugin=cf') — this
    module does NOT decompose/re-encode them into structured kwargs, since PBS's own API models
    each as a SINGLE compound string, not a nested object; the schema's 'format' sub-block is
    documentation of the compound syntax, not a separately-settable shape. Only a defensive
    no-control-chars check is applied; no compound-grammar parser is hand-rolled here."""
    s = str(value)
    if not _NO_CONTROL_RE.match(s):
        raise ProximoError(f"invalid {field}: {value!r} — control characters not allowed")
    return s


def _check_task_log_max_days(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid task_log_max_days: {value!r} (must be an integer)") from exc
    if n < 0:
        raise ProximoError(f"invalid task_log_max_days: {value!r} — must be >= 0")
    return n


def _check_default_lang(value: str) -> str:
    s = str(value)
    if s not in _VALID_DEFAULT_LANGS:
        raise ProximoError(
            f"invalid default_lang: {value!r} (expected one of {sorted(_VALID_DEFAULT_LANGS)})"
        )
    return s


def _check_sync_direction(value: str) -> str:
    s = str(value)
    if s not in _VALID_SYNC_DIRECTIONS:
        raise ProximoError(
            f"invalid sync_direction: {value!r} (expected one of {sorted(_VALID_SYNC_DIRECTIONS)})"
        )
    return s


def _check_cf(value: str) -> str:
    s = str(value)
    if s not in _VALID_CF:
        raise ProximoError(f"invalid cf: {value!r} (expected one of {sorted(_VALID_CF)})")
    return s


def _check_rrd_timeframe(value: str) -> str:
    s = str(value)
    if s not in _VALID_RRD_TIMEFRAMES:
        raise ProximoError(
            f"invalid timeframe: {value!r} (expected one of {sorted(_VALID_RRD_TIMEFRAMES)})"
        )
    return s


def _check_max_depth(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid max_depth: {value!r} (must be an integer)") from exc
    if not (0 <= n <= 7):
        raise ProximoError(f"invalid max_depth: {value!r} — must be 0-7")
    return n


def _check_worker_threads(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid worker_threads: {value!r} (must be an integer)") from exc
    if not (1 <= n <= 32):
        raise ProximoError(f"invalid worker_threads: {value!r} — must be 1-32")
    return n


def _check_transfer_last(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid transfer_last: {value!r} (must be an integer)") from exc
    if n < 1:
        raise ProximoError(f"invalid transfer_last: {value!r} — must be >= 1 (no upper bound in schema)")
    return n


def _check_group_filter(items) -> list[str] | None:
    """List of group-filter strings (module docstring fact #7). Not validated against PBS's own
    compound grammar (`[<exclude:|include:>]<type:<vm|ct|host>|group:GROUP|regex:RE>`) — only a
    defensive no-control-chars check per entry, matching the established "pass compound strings
    through, let the live API enforce its own grammar" convention."""
    if items is None:
        return None
    out = []
    for v in items:
        s = str(v)
        if not _NO_CONTROL_RE.match(s):
            raise ProximoError(f"invalid group_filter entry: {v!r} — control characters not allowed")
        out.append(s)
    return out


def _redact_http_proxy(value: str | None) -> str | None:
    """Defensively mask an embedded HTTP-proxy userinfo credential (user[:pass]@host[:port])
    before the value can enter a Plan/ledger surface (module docstring fact #10). host[:port]
    stays visible — the operationally useful part of the field. A value with no @ at all passes
    through unchanged.

    Wave 5c review Finding 3 (FIXED, Wave 5d): the userinfo is everything up to the LAST @ in
    the authority — `rsplit("@", 1)` — never the first (the first-@ regex form leaked the
    password tail whenever the password contained a literal @). A host part never legally
    contains @ (RFC 3986; IPv6 hosts are bracketed), so last-@ semantics are exact; if a
    malformed value put an @ in the "host", this over-redacts — the safe direction."""
    if value is None:
        return None
    s = str(value)
    m = _PROXY_SCHEME_RE.match(s)
    if m is None:  # unreachable — both groups are optional/greedy — but fail SAFE if it ever isn't
        return "[redacted]"
    prefix, authority = m.group("prefix"), m.group("authority")
    if "@" in authority:
        _userinfo, host = authority.rsplit("@", 1)
        return f"{prefix}[redacted]@{host}"
    return s


# ---------------------------------------------------------------------------
# Backend functions — Admin job views (reads)
# ---------------------------------------------------------------------------

def gc_jobs_list(api: PbsBackend, store: str | None = None) -> list[dict]:
    """GET /admin/gc[?store=] — job-level view of GC jobs (max one per datastore), across ALL
    datastores unless `store` filters to one. Distinct from the existing per-datastore
    `pbs_gc_status` (GET /admin/datastore/{store}/gc, single-store detail only, no
    schedule/next-run fields). REVIEWED_TRUSTED. Smoke-confirm: response shape."""
    params: dict = {}
    if store is not None:
        params["store"] = _check_store(store)
    return api._get("/admin/gc", params=params) or []


def prune_jobs_list(api: PbsBackend, store: str | None = None) -> list[dict]:
    """GET /admin/prune[?store=] — job-level view of prune jobs. REVIEWED_TRUSTED (job
    comment/schedule, matches pbs_jobs_list precedent — module docstring's Taint section).
    Smoke-confirm: response shape."""
    params: dict = {}
    if store is not None:
        params["store"] = _check_store(store)
    return api._get("/admin/prune", params=params) or []


def sync_jobs_list(
    api: PbsBackend, store: str | None = None, sync_direction: str | None = None,
) -> list[dict]:
    """GET /admin/sync[?store=&sync-direction=] — job-level view of sync jobs. `sync_direction`
    filters to push/pull/all (PBS default "pull" if omitted — module docstring fact #2).
    REVIEWED_TRUSTED. Smoke-confirm: response shape."""
    params: dict = {}
    if store is not None:
        params["store"] = _check_store(store)
    if sync_direction is not None:
        params["sync-direction"] = _check_sync_direction(sync_direction)
    return api._get("/admin/sync", params=params) or []


def verify_jobs_list(api: PbsBackend, store: str | None = None) -> list[dict]:
    """GET /admin/verify[?store=] — job-level view of verification jobs. REVIEWED_TRUSTED.
    Smoke-confirm: response shape."""
    params: dict = {}
    if store is not None:
        params["store"] = _check_store(store)
    return api._get("/admin/verify", params=params) or []


def traffic_control_status(api: PbsBackend) -> list[dict]:
    """GET /admin/traffic-control — LIVE current traffic (cur-rate-in/cur-rate-out) per traffic-
    control rule, PLUS the rule's own config (comment/network/rate/burst/timeframe). Distinct
    from the already-shipped `pbs_traffic_controls_list` (GET /config/traffic-control — the
    CONFIG-CRUD view; use pbs_traffic_control_upsert to create/modify rules there).
    REVIEWED_TRUSTED (counters + operator config — module docstring's Taint section).
    Smoke-confirm: response shape."""
    return api._get("/admin/traffic-control") or []


# ---------------------------------------------------------------------------
# Backend functions — Node odds
# ---------------------------------------------------------------------------

def node_config_get(api: PbsBackend, node: str = "localhost") -> dict:
    """GET /nodes/{node}/config — node-wide settings (description, email-from, http-proxy,
    task-log-max-days, consent-text, default-lang, ciphers, location, acme/acmedomain0-4).
    `http-proxy` is defensively masked for any embedded userinfo credential before return (module
    docstring fact #10) — this is the ONE shared masking point also used by
    `plan_node_config_set`'s CAPTURE. Smoke-confirm: response shape."""
    node = _check_pbs_node(node)
    data = api._get(f"/nodes/{node}/config") or {}
    if "http-proxy" in data:
        data = {**data, "http-proxy": _redact_http_proxy(data["http-proxy"])}
    return data


def node_config_set(
    api: PbsBackend,
    node: str = "localhost",
    acme: str | None = None,
    acmedomain0: str | None = None,
    acmedomain1: str | None = None,
    acmedomain2: str | None = None,
    acmedomain3: str | None = None,
    acmedomain4: str | None = None,
    ciphers_tls_1_2: str | None = None,
    ciphers_tls_1_3: str | None = None,
    consent_text: str | None = None,
    default_lang: str | None = None,
    description: str | None = None,
    email_from: str | None = None,
    http_proxy: str | None = None,
    location: str | None = None,
    task_log_max_days: int | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> None:
    """PUT /nodes/{node}/config — all fields optional. Returns null (synchronous). MUTATION —
    confirm-gated + audited at the server layer. `http_proxy` (if given) is forwarded RAW here
    (the update must actually work) but only ever reaches the Plan/ledger masked — see
    plan_node_config_set's redaction."""
    node = _check_pbs_node(node)
    data: dict = _node_config_fields(
        acme=acme, acmedomain0=acmedomain0, acmedomain1=acmedomain1, acmedomain2=acmedomain2,
        acmedomain3=acmedomain3, acmedomain4=acmedomain4, ciphers_tls_1_2=ciphers_tls_1_2,
        ciphers_tls_1_3=ciphers_tls_1_3, consent_text=consent_text, default_lang=default_lang,
        description=description, email_from=email_from, http_proxy=http_proxy, location=location,
        task_log_max_days=task_log_max_days,
    )
    if digest is not None:
        data["digest"] = _check_digest(digest)
    if delete is not None:
        data["delete"] = _check_delete_list(delete)
    api._put(f"/nodes/{node}/config", data)


def _node_config_fields(
    *,
    acme: str | None = None,
    acmedomain0: str | None = None,
    acmedomain1: str | None = None,
    acmedomain2: str | None = None,
    acmedomain3: str | None = None,
    acmedomain4: str | None = None,
    ciphers_tls_1_2: str | None = None,
    ciphers_tls_1_3: str | None = None,
    consent_text: str | None = None,
    default_lang: str | None = None,
    description: str | None = None,
    email_from: str | None = None,
    http_proxy: str | None = None,
    location: str | None = None,
    task_log_max_days: int | None = None,
) -> dict:
    """Shared field-assembly + validation for node_config_set. Builds a WIRE-hyphenated dict of
    whichever fields are not None. Mirrors pbs_s3.py's `_s3_fields` sharing idiom."""
    data: dict = {}
    if acme is not None:
        data["acme"] = _check_acme_field(acme, "acme")
    for i, v in enumerate((acmedomain0, acmedomain1, acmedomain2, acmedomain3, acmedomain4)):
        if v is not None:
            data[f"acmedomain{i}"] = _check_acme_field(v, f"acmedomain{i}")
    if ciphers_tls_1_2 is not None:
        data[_CIPHER_WIRE_NAMES["ciphers_tls_1_2"]] = _check_ciphers(ciphers_tls_1_2, "ciphers_tls_1_2")
    if ciphers_tls_1_3 is not None:
        data[_CIPHER_WIRE_NAMES["ciphers_tls_1_3"]] = _check_ciphers(ciphers_tls_1_3, "ciphers_tls_1_3")
    if consent_text is not None:
        data["consent-text"] = _check_consent_text(consent_text)
    if default_lang is not None:
        data["default-lang"] = _check_default_lang(default_lang)
    if description is not None:
        data["description"] = _check_description(description)
    if email_from is not None:
        data["email-from"] = _check_email_from(email_from)
    if http_proxy is not None:
        data["http-proxy"] = _check_http_proxy(http_proxy)
    if location is not None:
        data["location"] = _check_location(location)
    if task_log_max_days is not None:
        data["task-log-max-days"] = _check_task_log_max_days(task_log_max_days)
    return data


def node_identity(api: PbsBackend, node: str = "localhost") -> dict:
    """GET /nodes/{node}/identity — unique server identity derived from /etc/machine-id.
    `node` is OPTIONAL per the live schema (module docstring fact #12, the only one of this
    module's four node-scoped reads where that's true). REVIEWED_TRUSTED. Smoke-confirm: response
    shape."""
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/identity") or {}


def node_rrd(api: PbsBackend, cf: str, timeframe: str, node: str = "localhost") -> dict:
    """GET /nodes/{node}/rrd?cf=&timeframe= — node stats telemetry. `cf`/`timeframe` are BOTH
    REQUIRED per the live schema (module docstring fact #13 — no server-side default, unlike
    PVE's own rrddata). Declares returns:null despite being real telemetry — best-effort
    passthrough as a dict (Smoke-confirm the real shape). REVIEWED_TRUSTED (matches the
    pve_node_rrddata/pmg_node_rrddata/pbs_metrics_status precedent)."""
    node = _check_pbs_node(node)
    cf = _check_cf(cf)
    timeframe = _check_rrd_timeframe(timeframe)
    params = {"cf": cf, "timeframe": timeframe}
    return api._get(f"/nodes/{node}/rrd", params=params) or {}


def node_report(api: PbsBackend, node: str = "localhost") -> str:
    """GET /nodes/{node}/report — free-text diagnostic bundle. ADVERSARIAL (module docstring's
    Taint section — matches pve_node_syslog/pbs_node_journal/pbs_node_task_log). Smoke-confirm:
    content shape (likely a large multi-section plaintext dump)."""
    node = _check_pbs_node(node)
    return api._get(f"/nodes/{node}/report") or ""


def version(api: PbsBackend) -> dict:
    """GET /version — PBS API version identity (release/repoid/version). REVIEWED_TRUSTED.
    Smoke-confirm: response shape."""
    return api._get("/version") or {}


# ---------------------------------------------------------------------------
# Backend functions — Pull / Push
# ---------------------------------------------------------------------------

def _sync_fields(
    *,
    burst_in: str | None = None,
    burst_out: str | None = None,
    encrypted_only: bool | None = None,
    group_filter: list[str] | None = None,
    max_depth: int | None = None,
    ns: str | None = None,
    rate_in: str | None = None,
    rate_out: str | None = None,
    remote_ns: str | None = None,
    remove_vanished: bool | None = None,
    transfer_last: int | None = None,
    verified_only: bool | None = None,
    worker_threads: int | None = None,
) -> dict:
    """Shared field-assembly + validation for the params pull AND push have in COMMON (module
    docstring fact #5 — decryption-keys/resync-corrupt are pull-only; encryption-key is
    push-only, assembled separately by each caller). Empty `group_filter` is treated as
    equivalent to omitted (not forwarded) — unlike `delete`'s destructive-clear semantics, an
    empty filter list here means the SAME thing as no filter at all ("every group in scope"), so
    silently dropping it (httpx's own empty-list form-encoding behavior — pbs.py's
    `_check_delete_list` docstring) does not misrepresent intent."""
    data: dict = {}
    if burst_in is not None:
        data["burst-in"] = _check_byte_size(burst_in, "burst_in")
    if burst_out is not None:
        data["burst-out"] = _check_byte_size(burst_out, "burst_out")
    if encrypted_only is not None:
        data["encrypted-only"] = bool(encrypted_only)
    if group_filter:
        data["group-filter"] = _check_group_filter(group_filter)
    if max_depth is not None:
        data["max-depth"] = _check_max_depth(max_depth)
    if ns is not None:
        data["ns"] = _check_namespace(ns)
    if rate_in is not None:
        data["rate-in"] = _check_byte_size(rate_in, "rate_in")
    if rate_out is not None:
        data["rate-out"] = _check_byte_size(rate_out, "rate_out")
    if remote_ns is not None:
        data["remote-ns"] = _check_namespace(remote_ns)
    if remove_vanished is not None:
        data["remove-vanished"] = bool(remove_vanished)
    if transfer_last is not None:
        data["transfer-last"] = _check_transfer_last(transfer_last)
    if verified_only is not None:
        data["verified-only"] = bool(verified_only)
    if worker_threads is not None:
        data["worker-threads"] = _check_worker_threads(worker_threads)
    return data


def pull(
    api: PbsBackend,
    store: str,
    remote_store: str,
    remote: str | None = None,
    remote_ns: str | None = None,
    ns: str | None = None,
    burst_in: str | None = None,
    burst_out: str | None = None,
    decryption_keys: list[str] | None = None,
    encrypted_only: bool | None = None,
    group_filter: list[str] | None = None,
    max_depth: int | None = None,
    rate_in: str | None = None,
    rate_out: str | None = None,
    remove_vanished: bool | None = None,
    resync_corrupt: bool | None = None,
    transfer_last: int | None = None,
    verified_only: bool | None = None,
    worker_threads: int | None = None,
) -> None:
    """POST /pull — `store`/`remote-store` REQUIRED; `remote` is OPTIONAL per the live schema
    (module docstring fact #3 — Smoke-confirm what PBS does when omitted). Returns null
    (module docstring fact #4 — Smoke-confirm whether this blocks for the full transfer
    duration). MUTATION — confirm-gated + audited at the server layer. WRITES into the LOCAL
    datastore `store`; DELETES local snapshots that vanished remotely if remove_vanished=True."""
    store = _check_store(store)
    remote_store = _check_store(remote_store)
    data: dict = {"store": store, "remote-store": remote_store}
    if remote is not None:
        data["remote"] = _check_id(remote, "remote")
    if decryption_keys:
        data["decryption-keys"] = [_check_id(k, "decryption_keys") for k in decryption_keys]
    if resync_corrupt is not None:
        data["resync-corrupt"] = bool(resync_corrupt)
    data.update(_sync_fields(
        burst_in=burst_in, burst_out=burst_out, encrypted_only=encrypted_only,
        group_filter=group_filter, max_depth=max_depth, ns=ns, rate_in=rate_in,
        rate_out=rate_out, remote_ns=remote_ns, remove_vanished=remove_vanished,
        transfer_last=transfer_last, verified_only=verified_only, worker_threads=worker_threads,
    ))
    api._post("/pull", data)


def push(
    api: PbsBackend,
    store: str,
    remote: str,
    remote_store: str,
    remote_ns: str | None = None,
    ns: str | None = None,
    burst_in: str | None = None,
    burst_out: str | None = None,
    encrypted_only: bool | None = None,
    encryption_key: str | None = None,
    group_filter: list[str] | None = None,
    max_depth: int | None = None,
    rate_in: str | None = None,
    rate_out: str | None = None,
    remove_vanished: bool | None = None,
    transfer_last: int | None = None,
    verified_only: bool | None = None,
    worker_threads: int | None = None,
) -> None:
    """POST /push — `store`/`remote`/`remote-store` ALL REQUIRED (module docstring fact #3 —
    `remote` required here, unlike pull's optional). Returns null (module docstring fact #4).
    MUTATION — confirm-gated + audited at the server layer. WRITES into the REMOTE datastore
    `remote-store`; DELETES remote snapshots that vanished locally if remove_vanished=True."""
    store = _check_store(store)
    remote = _check_id(remote, "remote")
    remote_store = _check_store(remote_store)
    data: dict = {"store": store, "remote": remote, "remote-store": remote_store}
    if encryption_key is not None:
        data["encryption-key"] = _check_id(encryption_key, "encryption_key")
    data.update(_sync_fields(
        burst_in=burst_in, burst_out=burst_out, encrypted_only=encrypted_only,
        group_filter=group_filter, max_depth=max_depth, ns=ns, rate_in=rate_in,
        rate_out=rate_out, remote_ns=remote_ns, remove_vanished=remove_vanished,
        transfer_last=transfer_last, verified_only=verified_only, worker_threads=worker_threads,
    ))
    api._post("/push", data)


# ---------------------------------------------------------------------------
# Plan factories — Node config
# ---------------------------------------------------------------------------

def plan_node_config_set(
    api: PbsBackend,
    node: str = "localhost",
    acme: str | None = None,
    acmedomain0: str | None = None,
    acmedomain1: str | None = None,
    acmedomain2: str | None = None,
    acmedomain3: str | None = None,
    acmedomain4: str | None = None,
    ciphers_tls_1_2: str | None = None,
    ciphers_tls_1_3: str | None = None,
    consent_text: str | None = None,
    default_lang: str | None = None,
    description: str | None = None,
    email_from: str | None = None,
    http_proxy: str | None = None,
    location: str | None = None,
    task_log_max_days: int | None = None,
    digest: str | None = None,
    delete: list[str] | None = None,
) -> Plan:
    """Plan updating PBS node-wide config. CAPTURE-or-declare (mirrors pbs_node.py's
    plan_dns_set): reads current config via the masked node_config_get; on read failure ->
    complete=False + an honest note. RISK_HIGH, uniform across the whole PUT (module docstring's
    RISK RATING section — ciphers/http-proxy/acme misconfiguration are each independently
    lockout-class or connectivity-breaking)."""
    node = _check_pbs_node(node)
    kw = _node_config_fields(
        acme=acme, acmedomain0=acmedomain0, acmedomain1=acmedomain1, acmedomain2=acmedomain2,
        acmedomain3=acmedomain3, acmedomain4=acmedomain4, ciphers_tls_1_2=ciphers_tls_1_2,
        ciphers_tls_1_3=ciphers_tls_1_3, consent_text=consent_text, default_lang=default_lang,
        description=description, email_from=email_from, http_proxy=http_proxy, location=location,
        task_log_max_days=task_log_max_days,
    )
    if digest is not None:
        _check_digest(digest)

    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = node_config_get(api, node)
    except Exception:
        complete = False
        note_capture = " Could not capture current node config — no guided revert available."

    display = dict(kw)
    if "http-proxy" in display:
        display["http-proxy"] = _redact_http_proxy(display["http-proxy"])
    if delete is not None:
        # is not None, NOT truthiness — delete=[] is REJECTED, not disclosed (pbs.py's
        # `_check_delete_list` — httpx drops an empty-list form value entirely).
        display["delete"] = _check_delete_list(delete)
    change_desc = ", ".join(f"{k}={v!r}" for k, v in display.items()) if display else "no fields changed"

    return Plan(
        action="pbs_node_config_set",
        target=f"pbs/nodes/{node}/config",
        change=f"update PBS node {node!r} config: {change_desc}",
        current=current,
        blast_radius=[
            f"node {node!r} config change — ciphers-tls-1.2/ciphers-tls-1.3 misconfiguration "
            "can make the API/web proxy refuse ALL TLS connections (a lockout-class risk, "
            "mirrors network_reload/cert_upload); http-proxy misconfiguration can silently break "
            "outbound connectivity needed by notifications/ACME renewal/subscription-check; "
            "acme/acmedomain0-4 misconfiguration can break automatic certificate renewal",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "the PLANE can silently break host administrability via three independent paths "
            "(TLS ciphers, outbound proxy, ACME identity) — rated uniformly HIGH per-action, not "
            "conditional on which field a given call happens to touch",
        ],
        complete=complete,
        note=(
            "http-proxy (if given) is masked here for any embedded userinfo credential; the RAW "
            "value is still forwarded to PBS on confirm=True. No snapshot primitive — revert by "
            "re-applying the captured current config above with pbs_node_config_set."
            + note_capture
        ),
    )


# ---------------------------------------------------------------------------
# Plan factories — Pull / Push
# ---------------------------------------------------------------------------

def _sync_display_fields(
    *,
    burst_in=None, burst_out=None, encrypted_only=None, group_filter=None, max_depth=None,
    ns=None, rate_in=None, rate_out=None, remote_ns=None, remove_vanished=None,
    transfer_last=None, verified_only=None, worker_threads=None,
) -> dict:
    """PURE re-validation for the Plan's display string — mirrors what `_sync_fields` builds for
    the real wire call, so the preview and the executed payload can never silently diverge."""
    return _sync_fields(
        burst_in=burst_in, burst_out=burst_out, encrypted_only=encrypted_only,
        group_filter=group_filter, max_depth=max_depth, ns=ns, rate_in=rate_in,
        rate_out=rate_out, remote_ns=remote_ns, remove_vanished=remove_vanished,
        transfer_last=transfer_last, verified_only=verified_only, worker_threads=worker_threads,
    )


def plan_pull(
    store: str,
    remote_store: str,
    remote: str | None = None,
    remote_ns: str | None = None,
    ns: str | None = None,
    burst_in: str | None = None,
    burst_out: str | None = None,
    decryption_keys: list[str] | None = None,
    encrypted_only: bool | None = None,
    group_filter: list[str] | None = None,
    max_depth: int | None = None,
    rate_in: str | None = None,
    rate_out: str | None = None,
    remove_vanished: bool | None = None,
    resync_corrupt: bool | None = None,
    transfer_last: int | None = None,
    verified_only: bool | None = None,
    worker_threads: int | None = None,
) -> Plan:
    """Plan pulling backups from a remote PBS datastore into the LOCAL datastore `store`.
    PURE — no natural "current" snapshot exists for a transfer operation (unlike a config PUT);
    pbs_snapshots_list is how a caller inspects datastore state before/after. RISK_MEDIUM,
    escalating to RISK_HIGH when remove_vanished=True (module docstring's RISK RATING section —
    matches the task brief's explicit framing)."""
    store = _check_store(store)
    remote_store = _check_store(remote_store)
    remove_vanished_bool = bool(remove_vanished)

    kw: dict = {"store": store, "remote-store": remote_store}
    if remote is not None:
        kw["remote"] = _check_id(remote, "remote")
    if decryption_keys:
        kw["decryption-keys"] = [_check_id(k, "decryption_keys") for k in decryption_keys]
    if resync_corrupt is not None:
        kw["resync-corrupt"] = bool(resync_corrupt)
    kw.update(_sync_display_fields(
        burst_in=burst_in, burst_out=burst_out, encrypted_only=encrypted_only,
        group_filter=group_filter, max_depth=max_depth, ns=ns, rate_in=rate_in,
        rate_out=rate_out, remote_ns=remote_ns, remove_vanished=remove_vanished,
        transfer_last=transfer_last, verified_only=verified_only, worker_threads=worker_threads,
    ))
    change_desc = ", ".join(f"{k}={v!r}" for k, v in kw.items())

    remote_desc = f"remote {remote!r}" if remote else "the (schema-optional, unspecified) remote"
    ns_disp = repr(ns) if ns else "(root)"
    remote_ns_disp = repr(remote_ns) if remote_ns else "(root)"
    group_filter_disp = repr(group_filter) if group_filter else "NOT set — every group in scope is pulled"
    blast = [
        f"WRITES new backup data into the LOCAL datastore {store!r} (namespace "
        f"{ns_disp}) from {remote_desc}'s datastore {remote_store!r} "
        f"(namespace {remote_ns_disp})",
        f"group_filter={group_filter_disp}",
    ]
    if remove_vanished_bool:
        blast.append(
            "remove_vanished=True: PERMANENTLY DELETES local snapshots in "
            f"{store!r} that no longer exist on the remote — a real local deletion, no dry-run "
            "preview exists on this endpoint (unlike pbs_prune's own dry_run param)"
        )
    if resync_corrupt:
        blast.append(
            "resync_corrupt=True: re-pulls and OVERWRITES any local snapshot that previously "
            "failed verification"
        )
    blast.append(
        "returns null per the live schema — no UPID to poll; Smoke-confirm whether this call "
        "blocks synchronously for the full transfer duration (module docstring fact #4)"
    )

    return Plan(
        action="pbs_pull",
        target=f"pbs/pull/{store}",
        change=f"pull backups: {change_desc}",
        current={},
        blast_radius=blast,
        risk=RISK_HIGH if remove_vanished_bool else RISK_MEDIUM,
        risk_reasons=(
            ["remove_vanished=True permanently deletes local snapshots that vanished remotely — "
             "no dry-run preview on this endpoint"]
            if remove_vanished_bool else
            ["writes new backup data into the local datastore; an over-broad or absent "
             "group_filter transfers every group in scope, not a targeted set"]
        ),
        note=(
            "No rollback primitive. Written-then-unwanted data requires manual "
            "pbs_snapshot_delete cleanup; remove_vanished deletions cannot be undone at all."
        ),
    )


def plan_push(
    store: str,
    remote: str,
    remote_store: str,
    remote_ns: str | None = None,
    ns: str | None = None,
    burst_in: str | None = None,
    burst_out: str | None = None,
    encrypted_only: bool | None = None,
    encryption_key: str | None = None,
    group_filter: list[str] | None = None,
    max_depth: int | None = None,
    rate_in: str | None = None,
    rate_out: str | None = None,
    remove_vanished: bool | None = None,
    transfer_last: int | None = None,
    verified_only: bool | None = None,
    worker_threads: int | None = None,
) -> Plan:
    """Plan pushing backups from the LOCAL datastore `store` to a REMOTE PBS datastore. PURE — no
    natural "current" snapshot exists for a transfer operation. RISK_MEDIUM, escalating to
    RISK_HIGH when remove_vanished=True (module docstring's RISK RATING section)."""
    store = _check_store(store)
    remote = _check_id(remote, "remote")
    remote_store = _check_store(remote_store)
    remove_vanished_bool = bool(remove_vanished)

    kw: dict = {"store": store, "remote": remote, "remote-store": remote_store}
    if encryption_key is not None:
        kw["encryption-key"] = _check_id(encryption_key, "encryption_key")
    kw.update(_sync_display_fields(
        burst_in=burst_in, burst_out=burst_out, encrypted_only=encrypted_only,
        group_filter=group_filter, max_depth=max_depth, ns=ns, rate_in=rate_in,
        rate_out=rate_out, remote_ns=remote_ns, remove_vanished=remove_vanished,
        transfer_last=transfer_last, verified_only=verified_only, worker_threads=worker_threads,
    ))
    change_desc = ", ".join(f"{k}={v!r}" for k, v in kw.items())

    ns_disp = repr(ns) if ns else "(root)"
    remote_ns_disp = repr(remote_ns) if remote_ns else "(root)"
    group_filter_disp = repr(group_filter) if group_filter else "NOT set — every group in scope is pushed"
    blast = [
        f"WRITES new backup data into the REMOTE {remote!r} datastore {remote_store!r} "
        f"(namespace {remote_ns_disp}) from the LOCAL datastore "
        f"{store!r} (namespace {ns_disp})",
        f"group_filter={group_filter_disp}",
    ]
    if remove_vanished_bool:
        blast.append(
            "remove_vanished=True: PERMANENTLY DELETES snapshots on the REMOTE datastore that no "
            "longer exist locally — a real remote deletion, no dry-run preview exists on this "
            "endpoint"
        )
    blast.append(
        "returns null per the live schema — no UPID to poll; Smoke-confirm whether this call "
        "blocks synchronously for the full transfer duration (module docstring fact #4)"
    )

    return Plan(
        action="pbs_push",
        target=f"pbs/push/{store}",
        change=f"push backups: {change_desc}",
        current={},
        blast_radius=blast,
        risk=RISK_HIGH if remove_vanished_bool else RISK_MEDIUM,
        risk_reasons=(
            ["remove_vanished=True permanently deletes remote snapshots that vanished locally — "
             "no dry-run preview on this endpoint"]
            if remove_vanished_bool else
            ["writes new backup data into the remote datastore; an over-broad or absent "
             "group_filter transfers every group in scope, not a targeted set"]
        ),
        note=(
            "No rollback primitive. Written-then-unwanted remote data requires manual cleanup on "
            "the remote PBS; remove_vanished deletions cannot be undone at all."
        ),
    )
