"""PMG node core administration — network / DNS / time / node-config (ACME domain-mapping) /
certificates-info / services-list / subscription.

Wave 9 of the full-surface campaign (`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 9
decomposition"), chunks 9a AND 9b of `.scratch/sdd/wave-9-draft-decomposition.md` §2, combined in
one module — coordinator RULING 5 (binding): `pmg.py` was already 5409 lines pre-Wave-9 and 9a/9b
together add ~43 tools' worth of node-admin surface, so this family gets its own module pair,
matching the Wave 2d (`pbs_disks.py` beside `pbs_node.py`) / Wave 8b (`pmg_welcomelist.py` beside
`pmg.py`) new-module precedent. This file covers exactly the methods classified `"chunk": "9a"`
(19) and `"chunk": "9b"` (24) in `.scratch/sdd/wave-9-classification.json` — 43 methods, no more,
no fewer.

Chunk 9a (19 tools, LANDED 2026-07-17, commit 0c086f6): network/DNS/time/node-config/
certs-info/services/subscription — see the "SCHEMA-VERIFIED FACTS" section below (facts 1-13,
unchanged from that landing).

Chunk 9b (24 tools, this addition): task-stop/task-log/task-status, report, journal, backup
files (list/delete/restore), Postfix queue (list/message-get/action/delete-all/delete-queue/
message-delete/message-deliver), Postfix address-verify-cache discard, ClamAV/SpamAssassin
signature-DB reads+updates, and the 4 named service-lifecycle verbs (start/stop/restart/reload)
— see the "CHUNK 9b — SCHEMA-VERIFIED FACTS" section below for the endpoint table and facts.

Schema truth: the live PMG API-viewer schema, `.scratch/api-schemas-2026-07-15/
pmg-apidoc-live-2026-07-17.json` (425-method full-plane pull, 2026-07-17) — every path/verb/
param/return below was read directly from that JSON tree's `info.{GET,POST,PUT,DELETE}` blocks
under `/nodes/{node}/network*`, `/nodes/{node}/dns`, `/nodes/{node}/time`, `/nodes/{node}/config`,
`/nodes/{node}/certificates/info`, `/nodes/{node}/services`, `/nodes/{node}/subscription` — never
from memory, never from the draft's prose alone. NONE of this module is live-verified against a
running PMG yet (Wave 8's own lab smoke never touched this region); every "Smoke-confirm:" note
names a specific unconfirmed detail.

Closest structural sibling: `pbs_node.py` (PBS Wave 2c) — same endpoint family shape (network/
dns/time/certs/services/subscription) on a sibling Proxmox-family plane. Divergences from that
sibling (and from PVE's own `network.py`) are FACTS, verified against this plane's own schema,
not assumed:

Endpoint table (19 methods, all confirmed against the live schema above):

  Network (7):
    GET    /nodes/{node}/network            — network_list          (read)
    GET    /nodes/{node}/network/{iface}     — network_get           (read)
    POST   /nodes/{node}/network             — network_create        (MUTATION, MEDIUM — staged)
    PUT    /nodes/{node}/network/{iface}     — network_update         (MUTATION, MEDIUM — staged)
    DELETE /nodes/{node}/network/{iface}     — network_delete         (MUTATION, MEDIUM — staged)
    DELETE /nodes/{node}/network             — network_revert         (MUTATION, LOW — discards staged)
    PUT    /nodes/{node}/network             — network_reload         (MUTATION, HIGH — applies staged->live)

  DNS (2):
    GET  /nodes/{node}/dns                   — dns_get                (read)
    PUT  /nodes/{node}/dns                    — dns_set                (MUTATION, MEDIUM)

  Time (2):
    GET  /nodes/{node}/time                   — time_get               (read)
    PUT  /nodes/{node}/time                   — time_set               (MUTATION, LOW)

  Node config — ACME domain-mapping only, NOT a general node-settings block (2):
    GET  /nodes/{node}/config                 — config_get             (read)
    PUT  /nodes/{node}/config                 — config_set             (MUTATION, MEDIUM, digest-gated)

  Certificates info (1):
    GET  /nodes/{node}/certificates/info      — certificates_info      (read)

  Services (1):
    GET  /nodes/{node}/services                — services_list          (read)

  Subscription (4):
    GET    /nodes/{node}/subscription          — subscription_get       (read, defensive key-strip)
    PUT    /nodes/{node}/subscription          — subscription_set       (MUTATION, MEDIUM — installs a key)
    POST   /nodes/{node}/subscription          — subscription_check     (MUTATION, LOW — online refresh)
    DELETE /nodes/{node}/subscription          — subscription_delete    (MUTATION, MEDIUM)

SCHEMA-VERIFIED FACTS (binding on this build — read directly off the live JSON, not memory):

1. **`type` is REQUIRED on BOTH network create AND update** (neither the POST's nor the PUT's
   `type` property carries `optional: 1` on the live schema) — this matches **PVE's** own
   behavior (whose `network_iface_update` reads the current type and injects it as a workaround,
   `network.py:289`), NOT PBS's (where both verbs mark `type` optional, `pbs_node.py` fact
   confirmed 2026-07-15). `network_update` here follows PVE's workaround shape: if the caller
   doesn't pass `iface_type`, the current type is read via `network_get` and injected — but
   (a genuine, argued divergence from PVE's own stricter refusal) a caller-supplied `iface_type`
   IS forwarded as given rather than rejected, since nothing in PMG's schema documents `type` as
   immutable-after-creation the way PVE's own docstring asserts; this is a builder judgment call,
   flagged for the reviewer, not a silent choice.
2. **The network `type` enum DIFFERS between the LIST filter and the CREATE/UPDATE value** — the
   list's optional `?type=` filter enum is `{bridge, bond, eth, alias, vlan, OVSBridge, OVSBond,
   OVSPort, OVSIntPort, any_bridge}`; the create/update VALUE enum is `{bridge, bond, eth, alias,
   vlan, OVSBridge, OVSBond, OVSPort, OVSIntPort, unknown}` — the filter has `any_bridge` where the
   value has `unknown`. Validated against two SEPARATE enums here, not one shared set.
3. **`iface` is schema-bounded 2-20 chars** (`minLength: 2, maxLength: 20`, format `pve-iface`,
   no explicit charset pattern declared) — the 20-char cap is the SCHEMA'S OWN bound, not a
   defensive addition (unlike PBS's 15-char IFNAMSIZ-style guess, which PBS's own schema declares
   no length limit for at all). The charset validator itself (letters/digits/._-) is defensive,
   mirroring the sibling planes.
4. **`GET /nodes/{node}/network` (list) is schema-thin** (`items: {properties: {}}` — no field
   names declared at all) — the real runtime shape is presumably richer (iface/type/method/
   address/...); Smoke-confirm before trusting any specific field name out of this read.
5. **`GET /nodes/{node}/network/{iface}` (single) types only `{method, type}`** — thinner than
   PBS's own single-iface read but at least names two real fields; other fields (address,
   gateway, bridge_ports, ...) are presumably present at runtime but undeclared. Smoke-confirm.
6. **`PUT /nodes/{node}/network` (bare, "Reload network configuration") returns `type: string`**
   on the live schema — draft §3 Fact #18's open question, now schema-CONFIRMED as a string
   return (not null, not typed as a UPID object either). Whether that string IS a UPID (an async
   task handle) or a synchronous plain status message is NOT resolvable from the schema alone —
   `network_reload` returns the raw string unchanged and the tool docstring states this plainly;
   Smoke-confirm against a live PMG before any docstring claims a specific shape.
7. **`DELETE /nodes/{node}/network` ("Revert network configuration changes") is functionally
   IDENTICAL to PBS's/PVE's own revert** — same description text, same "discards interfaces.new,
   never touches the live config" semantics. The draft's own chunk table rated this MEDIUM; this
   build rates it **LOW** instead, matching the established PBS (`plan_network_revert`, "the safe
   undo — it never touches the live config") and PVE precedent for the IDENTICAL operation — a
   reasoned divergence from the draft's guess, not a silent override, flagged for the reviewer.
8. **`search` is REQUIRED on `PUT /nodes/{node}/dns`** (no `optional: 1` on that property) —
   unlike this codebase's existing `node_lifecycle.py` PVE `dns_set` (which treats `search` as an
   optional Python kwarg) and PBS's own `pbs_node.py` `dns_set` (same). `dns_set` here makes
   `search` a required positional parameter, forwarded unconditionally, matching PMG's own
   schema rather than copying the sibling planes' more permissive signature.
9. **PMG's node `/config` is a NARROW ACME-domain-mapping block ONLY** (`acme`, `acmedomain[n]`,
   `digest` — three fields, all optional except node) — genuinely different scope from PBS's own
   `node_config_get/set` (`description`, `email-from`, `http-proxy`, `task-log-max-days`,
   `consent-text`, `default-lang`, `ciphers-tls-1.{2,3}`, `location`, PLUS the same acme/
   acmedomain family). `acme`/`acmedomain0`-`acmedomain4` are accepted here as PRE-FORMATTED
   compound strings (e.g. `"account=myaccount"`, `"domain=example.com,usage=smtp,plugin=cf"`) —
   matching `pbs_admin.py`'s own documented reasoning for the identical field shape: PMG's schema
   models each as a SINGLE compound string (the `format` sub-block is documentation of the
   compound syntax, not a separately-settable nested object), so this module does not hand-roll a
   compound-grammar parser either.
10. **The node-config `digest` is 40 hex chars max** (`maxLength: 40` — a SHA1-length digest,
    matching PVE's OWN node-config convention) — NOT the same shape as this module's other two
    digest-adjacent fields already established in `pmg.py` (the APT-plane `_PMG_APT_DIGEST_RE`,
    `maxLength: 80`, no pattern). A SEPARATE, narrower validator is defined here for this
    specific field (per this codebase's per-field digest-validator rule: only the identical
    64-char SHA-256 config digest is shared, via `_validate.check_digest`; divergent shapes
    like this one keep their own validator).
11. **`GET /nodes/{node}/certificates/info` has an OPEN permission** (`permissions: {user: "all"}`
    — any authenticated user, not `admin`/`audit` like every other read in this chunk) — a real
    schema fact, not an oversight; carried through unchanged (Proximo enforces no additional
    authorization layer beyond what the caller's own PMG credential already grants). Returns
    `pem`/fingerprint/subject/issuer/san/validity timestamps — the PUBLIC half of the cert only;
    no private key field appears anywhere in this return (schema-verified field-by-field).
12. **`GET /nodes/{node}/subscription` is schema-thin** (`returns: {type: "object"}`, zero
    declared properties) — whether the `key` field the PUT accepts also echoes back on GET is
    UNCONFIRMED either way. `subscription_get` here defensively strips any `key` field from the
    response regardless (mirrors `pbs_config.py`'s own `_strip_password` idiom: a plain read has
    no legitimate reason to echo a credential, so the strip costs nothing even if the field never
    actually appears).
13. **Subscription exposes FOUR verbs (GET/POST/PUT/DELETE)** — matches the shape already
    confirmed on BOTH PBS and PVE (per `pbs_node.py`'s own module docstring: "PVE also exposes all
    four... a gap in our PVE coverage, not in PVE's API"). PMG's own POST is named `update`
    (description: "Update subscription info.", `force` param) and PUT is named `set` (description:
    "Set subscription key.", `key` param) — the SAME get/set/check/delete naming split as PBS's
    tools, mapped to PMG's own verb assignment (PUT=set-with-key, POST=check-with-force), not
    assumed from verb order alone.

CHUNK 9b — Endpoint table (24 methods, all confirmed against the live schema, dumped fresh
2026-07-17 — `.scratch/api-schemas-2026-07-15/pmg-apidoc-live-2026-07-17.json`):

  Tasks (3):
    DELETE /nodes/{node}/tasks/{upid}          — task_stop    (MUTATION, HIGH)
    GET    /nodes/{node}/tasks/{upid}/log      — task_log     (read, ADVERSARIAL)
    GET    /nodes/{node}/tasks/{upid}/status   — task_status  (read, REVIEWED_TRUSTED)

  Diagnostics (2):
    GET /nodes/{node}/report   — report   (read, ADVERSARIAL)
    GET /nodes/{node}/journal  — journal  (read, ADVERSARIAL)

  Backup files (3):
    GET    /nodes/{node}/backup             — backup_list     (read, REVIEWED_TRUSTED)
    DELETE /nodes/{node}/backup/{filename}  — backup_delete   (MUTATION, MEDIUM)
    POST   /nodes/{node}/backup/{filename}  — backup_restore  (MUTATION, HIGH — no undo)

  Postfix queue (7) + address-verify cache (1):
    GET    /nodes/{node}/postfix/queue/{queue}             — postfix_queue_list            (read, ADVERSARIAL)
    GET    /nodes/{node}/postfix/queue/{queue}/{queue_id}  — postfix_queue_message_get     (read, ADVERSARIAL)
    POST   /nodes/{node}/postfix/queue/{queue}             — postfix_queue_action          (MUTATION, cond. HIGH/MEDIUM)
    DELETE /nodes/{node}/postfix/queue                     — postfix_queue_delete_all      (MUTATION, HIGH)
    DELETE /nodes/{node}/postfix/queue/{queue}             — postfix_queue_delete_queue    (MUTATION, HIGH)
    DELETE /nodes/{node}/postfix/queue/{queue}/{queue_id}  — postfix_queue_message_delete  (MUTATION, MEDIUM)
    POST   /nodes/{node}/postfix/queue/{queue}/{queue_id}  — postfix_queue_message_deliver (MUTATION, LOW)
    POST   /nodes/{node}/postfix/discard_verify_cache      — postfix_discard_verify_cache  (MUTATION, LOW)

  ClamAV + SpamAssassin signature DBs (4):
    GET  /nodes/{node}/clamav/database       — clamav_database_get        (read, REVIEWED_TRUSTED)
    POST /nodes/{node}/clamav/database       — clamav_database_update     (MUTATION, MEDIUM)
    GET  /nodes/{node}/spamassassin/rules    — spamassassin_rules_get     (read, REVIEWED_TRUSTED)
    POST /nodes/{node}/spamassassin/rules    — spamassassin_rules_update  (MUTATION, MEDIUM)

  Service lifecycle remainder (4) — the 4 literally-named schema endpoints beyond the already-
  shipped generic `pmg_service_control`/`pmg_service_status` dispatcher (tools/pmg_mail.py):
    POST /nodes/{node}/services/{service}/start    — service_start    (MUTATION, MEDIUM)
    POST /nodes/{node}/services/{service}/stop     — service_stop     (MUTATION, conditional HIGH/MEDIUM)
    POST /nodes/{node}/services/{service}/restart  — service_restart  (MUTATION, MEDIUM)
    POST /nodes/{node}/services/{service}/reload   — service_reload   (MUTATION, MEDIUM)

CHUNK 9b — SCHEMA-VERIFIED FACTS (binding on this build):

14. **`pmg_node_task_log` is classified ADVERSARIAL, a DIVERGENCE from the draft's own
    REVIEWED_TRUSTED guess** ("task metadata, not mail content"). The schema's own return shape
    is `{n: integer, t: string}` per line — `t` ("Line text") is free-text log content, exactly
    the shape that earned `pve_task_log`/`pbs_node_task_log` their ADVERSARIAL classification in
    `taint.py` (a task whose log lines can embed mail-processing output, e.g. sender/recipient
    strings from a postfix-queue-action task). `pmg_node_task_status`'s return (`{pid: integer,
    status: enum}`) carries no free text and stays REVIEWED_TRUSTED, matching both the draft and
    the pve_task_status/pbs_node_task_status precedent (neither is in `ADVERSARIAL_TOOLS`).
15. **`download` (task_log's whole-file mode) is NOT exposed** — matches PBS's own
    `pbs_node.py::task_log` precedent (which declines the identical param for the identical
    reason): this module's backend always requests the structured `{n,t}` array, never the raw
    file stream.
16. **The backup-file LIST endpoint's own description text says "files named
    proxmox-backup_{DATE}.tgz" but the `filename` schema PATTERN it declares is
    `pmg-backup_[0-9A-Za-z_-]+\\.tgz`** — a second instance of the Wave 9a Fact #12-style upstream
    copy-paste sloppiness (PMG's own webUI code was likely adapted from PBS's, and the description
    prose wasn't updated to match). The PATTERN is schema-authoritative here, not the prose.
17. **`backup_restore` (`POST /nodes/{node}/backup/{filename}`) has NO undo, no dry-run
    companion, and no scoping parameter for the `database` branch** — `database=True` (the
    schema's own default) replaces the SAME rule database `pmg_ruledb_reset` (pmg.py) wipes to
    factory defaults. `plan_backup_restore` reuses `pmg.py`'s own
    `_ruledb_reset_capture_count`/`ruledb_rules_list`/`who_groups_list`/`what_groups_list`/
    `when_groups_list`/`action_objects_list` verbatim (same capture helper, same five counts) to
    render the "what will be replaced" toll, exactly mirroring `plan_ruledb_reset`'s own shape.
    `config=True` ALSO restores PMG's "system configuration" — a scope PMG's schema does not
    itself enumerate beyond the label, so the plan states this honestly rather than inventing a
    field list.
18. **Both `backup_restore` (POST) and `backup_create`'s own already-shipped schema (POST
    /nodes/{node}/backup, `pmg.py`) type their return as a plain STRING** — `backup_create`'s
    existing tool (`tools/pmg_mail.py::pmg_backup_create`, pre-Wave-9) records outcome="ok" for
    this ambiguous string. This NEW tool applies the MORE RIGOROUS standard Wave 9a's own review
    established for network_reload (an ambiguous schema-typed string return records
    outcome="submitted" with the raw string ALSO recorded in the ledger's own `detail.raw_result`)
    — a deliberate, argued divergence from the older sibling tool's convention, not a silent fix
    of that other (out-of-chunk, different-file) tool. The SAME reasoning is applied to
    `clamav_database_update`, `spamassassin_rules_update`, and all four `service_*` verbs below —
    all five/six return a schema-typed STRING and all record outcome="submitted". This is a KNOWN
    inconsistency with the pre-Wave-9 `pmg_backup_create`/`pmg_service_control` tools (both
    "ok" for the identical ambiguous-string shape) — flagged here explicitly, not silently
    papered over, and not fixed in those other files (out of this chunk's scope).
19. **The 4 service-lifecycle tools built here (`service_start/stop/restart/reload`) hit
    LITERALLY-NAMED schema endpoints** (`/nodes/{node}/services/{service}/{start,stop,restart,
    reload}`) that are structurally DIFFERENT from the already-shipped generic
    `pmg_service_control(service, action)` dispatcher (`tools/pmg_mail.py`, pre-Wave-9), which
    builds the identical URL via an f-string with `action` as the variable segment. Both reach the
    same PMG behavior in practice; this module builds the 4 named tools anyway because the
    wave's classification artifact (`wave-9-classification.json`) tracks the literal named
    endpoints as a distinct, un-covered region (the generic dispatcher's `f"...{action}"`
    construction doesn't statically prove coverage of the 4 fixed-suffix paths to the coverage
    generator) — consistent with "this plane offers almost no collapse" (draft §1.4).
    `_check_service` (this module's, imported from `pmg.py`) is REUSED here rather than a
    stricter schema-enum validator, even though this chunk's own schema dump confirms `service`
    IS enum-typed on all 4 of these endpoints (and on the already-shipped `/state` read too) —
    kept consistent with `pmg.py`'s own existing `service_status`/`service_control` precedent
    ("No hardcoded enum — any valid name is accepted; unknown names return a PMG 404"), rather
    than diverging behavior across tools that address the same conceptual `service` parameter.
20. **`pmg_node_service_stop`'s risk is CONDITIONAL: RISK_HIGH for `service in {postfix,
    pmg-smtp-filter}`, RISK_MEDIUM otherwise** — mirrors RULING 3's established conditional-tier
    precedent (`pmg_access_user_create`'s HIGH-when-admin-role / MEDIUM-otherwise; the SDN
    lock-release LOW/HIGH shape) rather than inventing a fifth risk tier. The criterion is
    narrowly the draft's own named one (mail-flow halting) — stopping `pmgproxy`/`pmgdaemon` has
    its own (non-mail) blast radius this module does NOT elevate to HIGH; a deliberate scoping
    choice, flagged for the reviewer rather than silently widened.
21. **`pmg_node_postfix_queue_action`'s risk is CONDITIONAL: RISK_HIGH for `action='delete'`,
    RISK_MEDIUM for `action='deliver'`** — this is the EXACT SAME delete/deliver dichotomy
    `pmg.py`'s own `plan_quarantine_action` already uses (same action vocabulary, same
    reasoning), reused here rather than re-derived.
22. **`pmg_node_postfix_queue_delete_all` (bare) and `pmg_node_postfix_queue_delete_queue`
    (per-queue) are BOTH RISK_HIGH** ("queue-delete-all class" per the dispatch law) — the bare
    form wipes all 4 queues unconditionally, the per-queue form wipes one queue unconditionally;
    both are undifferentiated full wipes, unlike `postfix_queue_action`/`_message_delete`, which
    are bounded to caller-enumerated ID(s).
23. **`pmg_node_postfix_queue_message_deliver` is rated RISK_LOW**, not the draft's vague
    "LOW-MEDIUM" (not a real tier — no invented fifth tier) — it mirrors the ALREADY-SHIPPED
    `pmg_postfix_flush`'s own RISK_LOW rating (`pmg.py::plan_postfix_flush`) exactly: same
    "attempt immediate delivery, no data deleted" semantics, scoped to ONE message rather than
    ALL four queues (arguably lower-impact than the sibling tool it mirrors).
24. **`journal`'s `since`/`until` are typed `int | None` from the start** — the schema
    confirms both `integer` (min 0) on this endpoint, so this module does NOT repeat the
    pre-existing PVE bug (`observability.py::node_journal` types them `str | None` against a live
    PVE schema that types them `integer`, logged as follow-up debt in the campaign doc, not fixed
    here — a different plane/file, out of this chunk's scope). PMG's own already-shipped
    `tasks_list` (`pmg.py`) already types since/until as `int | None` too — this module is
    consistent with that existing PMG-plane precedent, not just avoiding the PVE bug in isolation.
25. **No secret-shaped field exists anywhere in this chunk's 24-method schema** (verified
    field-by-field against the live dump) — task/report/journal/backup/postfix-queue/clamav/
    spamassassin/service-lifecycle carry no password/key/token field. The wave's secret density
    (§5 of the draft) lives entirely in chunks 9c/9f/9g/9h, not here. `report`/`journal`'s
    free-text bodies COULD plausibly embed config values incidentally (the same caveat
    `pbs_node_report`/`pbs_node_journal` carry) — handled by ADVERSARIAL taint classification,
    not by field-level redaction (there is no known field to redact).

Security posture:
- All path components validated with `\\Z`-anchored regexes (trailing-newline bypass rejected) —
  matches `pmg.py`'s and `pbs_node.py`'s own discipline.
- `iface`: charset-validated (letters/digits/._-, 2-20 chars per the SCHEMA'S OWN bound, fact #3)
  PLUS an explicit dot-traversal guard (a lone `.` or an embedded `..` is rejected even though the
  charset alone would otherwise accept it) — mirrors `pbs_node.py`'s `_reject_dot_traversal`.
- `node`: reuses `pmg.py`'s own `_check_node` (already \\Z-anchored) — no independent copy.
- Subscription `key`: defensively stripped from every read (fact #12); the write path forwards it
  to PMG unmodified (the install genuinely needs the real value) but the CALLER-FACING plan/detail
  never carries it raw — see `_key_fingerprint`-equivalent handling in the tools wrapper.
- CAPTURE-or-declare: `dns_set`/`time_set`/`config_set`/`network_update`/`network_delete`'s plan
  factories read current state first where a cheap, safe read exists; on read failure ->
  `complete=False` + an honest note (mirrors `pbs_node.py`'s own `plan_dns_set`/`plan_time_set`).
"""

from __future__ import annotations

import re

from .backends import ProximoError, _check_timezone, _check_upid
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan
from .pmg import (
    PmgBackend,
    _check_node,
    _check_service,
    _ruledb_reset_capture_count,
    action_objects_list,
    ruledb_rules_list,
    what_groups_list,
    when_groups_list,
    who_groups_list,
)

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# iface: schema states minLength 2 / maxLength 20 (format 'pve-iface'), no charset pattern
# declared — the length bound IS the schema's own (fact #3), the charset itself is a defensive
# addition mirroring the sibling planes' own iface validators.
_IFACE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{1,19}\Z")

# Two SEPARATE enums (fact #2) — the list filter's `type` differs from the create/update value's
# `type` (any_bridge vs unknown).
_VALID_IFACE_TYPE_FILTER = frozenset({
    "bridge", "bond", "eth", "alias", "vlan",
    "OVSBridge", "OVSBond", "OVSPort", "OVSIntPort", "any_bridge",
})
_VALID_IFACE_TYPE_VALUE = frozenset({
    "bridge", "bond", "eth", "alias", "vlan",
    "OVSBridge", "OVSBond", "OVSPort", "OVSIntPort", "unknown",
})

# Node /config digest: maxLength 40 (SHA1-length, fact #10) — a SEPARATE, narrower validator from
# pmg.py's own APT-plane `_PMG_APT_DIGEST_RE` (maxLength 80), per this codebase's per-field digest
# validator precedent.
_CONFIG_DIGEST_RE = re.compile(r"^[0-9a-fA-F]{1,40}\Z")


def _reject_dot_traversal(s: str, label: str) -> None:
    """Reject a '.'/'..'-containing identifier that flows into a URL path segment — mirrors
    `pbs_node.py`'s identical guard (the iface charset alone would otherwise accept '..')."""
    if s == "." or ".." in s:
        raise ProximoError(f"invalid {label}: {s!r} — path-traversal segment rejected")


def _check_iface(iface: str) -> str:
    s = str(iface)
    _reject_dot_traversal(s, "interface name")
    if not _IFACE_RE.match(s):
        raise ProximoError(
            f"invalid interface name: {iface!r} "
            "(letters/digits/._- only, 2-20 chars, starting with alnum/underscore)"
        )
    return s


def _check_iface_type_filter(iface_type: str) -> str:
    t = str(iface_type)
    if t not in _VALID_IFACE_TYPE_FILTER:
        raise ProximoError(
            f"invalid PMG interface type filter: {iface_type!r} "
            f"(expected one of {sorted(_VALID_IFACE_TYPE_FILTER)})"
        )
    return t


def _check_iface_type_value(iface_type: str) -> str:
    t = str(iface_type)
    if t not in _VALID_IFACE_TYPE_VALUE:
        raise ProximoError(
            f"invalid PMG interface type: {iface_type!r} "
            f"(expected one of {sorted(_VALID_IFACE_TYPE_VALUE)})"
        )
    return t


def _check_config_digest(digest: str | None) -> str | None:
    if digest is None:
        return None
    s = str(digest).strip()
    if not _CONFIG_DIGEST_RE.match(s):
        raise ProximoError(
            f"invalid digest: {digest!r} — expected up to 40 hex chars (SHA1-length)"
        )
    return s


def _join_delete_props(delete_props) -> str:
    """Comma-join a delete-property list, or pass a pre-joined string through. Mirrors
    `pmg.py`'s own `spam_config_update` convention on THIS plane (a plain comma-separated
    string), not PBS's list-typed helper — kept plane-internally consistent."""
    if isinstance(delete_props, (list, tuple)):
        return ",".join(delete_props)
    return str(delete_props)


def _delete_list(delete_props) -> list[str]:
    """Normalize a delete/delete_props argument (list, tuple, pre-joined comma string, or None)
    into a list of individual property-name strings, for PER-KEY disclosure in a plan's
    blast_radius (Wave 9a review CRITICAL finding). Presentation-only — the wire format stays
    `_join_delete_props`'s comma-joined string; this never touches the request body."""
    if delete_props is None:
        return []
    if isinstance(delete_props, (list, tuple)):
        return [str(p) for p in delete_props]
    return [p for p in str(delete_props).split(",") if p]


def _strip_subscription_key(resp: dict) -> dict:
    """Defensively drop a 'key' field from a subscription-read RESPONSE before it reaches the
    caller. The schema is thin (fact #12) so whether PMG ever echoes the key is unconfirmed —
    this keeps it out of the client-visible return regardless, mirroring `pbs_config.py`'s own
    `_strip_password` idiom (narrowed to `dict` here since the one call site already normalizes
    a falsy response to `{}` before calling this)."""
    return {k: v for k, v in resp.items() if k != "key"}


# ---------------------------------------------------------------------------
# Chunk 9b validators
# ---------------------------------------------------------------------------

# Postfix queue name — a fixed 4-value schema enum, not a free-form identifier.
_QUEUE_NAMES = frozenset({"deferred", "active", "incoming", "hold"})


def _check_queue(queue: str) -> str:
    s = str(queue)
    if s not in _QUEUE_NAMES:
        raise ProximoError(
            f"invalid postfix queue name: {queue!r} (expected one of {sorted(_QUEUE_NAMES)})"
        )
    return s


# Postfix queue-action verb — schema enum {delete, deliver}.
_QUEUE_ACTIONS = frozenset({"delete", "deliver"})


def _check_postfix_queue_action(action: str) -> str:
    s = str(action)
    if s not in _QUEUE_ACTIONS:
        raise ProximoError(
            f"invalid postfix queue action: {action!r} (expected one of {sorted(_QUEUE_ACTIONS)})"
        )
    return s


# Postfix queue ID (format 'pmg-postfix-queue-id'/'...-id-list' — PMG's schema declares no
# pattern beyond the format name). Defensive: alnum + comma (a caller-supplied ids list is
# comma-joined per schema) only — rejects '/', '..', whitespace, control chars — a single
# queue_id (path segment) never carries a comma; the comma allowance is only exercised by
# `postfix_queue_action`'s `ids` argument, which reuses this same charset check per-token.
_QUEUE_ID_RE = re.compile(r"^[A-Za-z0-9]{1,40}\Z")


def _check_queue_id(queue_id: str) -> str:
    s = str(queue_id)
    if not _QUEUE_ID_RE.match(s):
        raise ProximoError(
            f"invalid postfix queue id: {queue_id!r} (must be 1-40 alphanumeric chars)"
        )
    return s


def _check_queue_ids(ids: str) -> str:
    """Validate a comma-separated list of queue IDs (the `ids` param on `postfix_queue_action`,
    schema format 'pmg-postfix-queue-id-list'). Each comma-separated token is checked with the
    same charset as a single queue_id. A malformed list (empty string, a lone comma, or an
    embedded empty token like 'ABC,,DEF') is REJECTED loudly — tokens are never silently
    dropped, so the validated string is always exactly what gets forwarded on the wire."""
    s = str(ids)
    tokens = s.split(",")
    if not tokens or any(not t for t in tokens):
        raise ProximoError(
            f"invalid ids: {ids!r} (must be one or more comma-separated queue IDs, "
            "no empty tokens)"
        )
    for t in tokens:
        _check_queue_id(t)
    return s


# Backup filename — schema pattern 'pmg-backup_[0-9A-Za-z_-]+\.tgz', minLength 4 / maxLength 256
# (fact #16 — the schema's own PATTERN, not the description prose's "proxmox-backup_" text).
_BACKUP_FILENAME_RE = re.compile(r"^pmg-backup_[0-9A-Za-z_-]+\.tgz\Z")


def _check_backup_filename(filename: str) -> str:
    s = str(filename)
    if len(s) < 4 or len(s) > 256 or not _BACKUP_FILENAME_RE.match(s):
        raise ProximoError(
            f"invalid backup filename: {filename!r} "
            r"(must match pmg-backup_[0-9A-Za-z_-]+\.tgz, 4-256 chars)"
        )
    return s


# Postfix mailq sort field/direction — schema enums on GET .../postfix/queue/{queue}.
_SORTFIELDS = frozenset({"arrival_time", "message_size", "sender", "receiver", "reason"})
_SORTDIRS = frozenset({"ASC", "DESC"})


def _check_sortfield(sortfield: str) -> str:
    s = str(sortfield)
    if s not in _SORTFIELDS:
        raise ProximoError(f"invalid sortfield: {sortfield!r} (expected one of {sorted(_SORTFIELDS)})")
    return s


def _check_sortdir(sortdir: str) -> str:
    s = str(sortdir)
    if s not in _SORTDIRS:
        raise ProximoError(f"invalid sortdir: {sortdir!r} (expected one of {sorted(_SORTDIRS)})")
    return s


# Postfix mailq filter — schema declares maxLength: 64, no charset pattern, on the same
# GET .../postfix/queue/{queue} endpoint (Wave-9b-review MINOR fix). Bounds-only, mirrors
# _check_backup_filename/_check_config_digest's own maxLength-enforcement convention on this
# same module.
_QUEUE_FILTER_MAXLEN = 64


def _check_queue_filter(value: str) -> str:
    s = str(value)
    if len(s) > _QUEUE_FILTER_MAXLEN:
        raise ProximoError(
            f"invalid filter: too long ({len(s)} chars, max {_QUEUE_FILTER_MAXLEN})"
        )
    return s


def _check_nonneg_int(value, field: str) -> int:
    """Mirrors `pbs_node.py`'s own `_check_nonneg_int` (start/limit/lastentries/since/until on
    this chunk's task-log/journal/queue-list families all declare schema `minimum: 0`)."""
    try:
        n = int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid {field}: {value!r} (must be an integer)") from exc
    if n < 0:
        raise ProximoError(f"invalid {field}: {value!r} (must be >= 0)")
    return n


_MAIL_CRITICAL_SERVICES = frozenset({"postfix", "pmg-smtp-filter"})


def _service_stop_risk(service: str) -> str:
    """Conditional risk for `service_stop` (fact #20 — RULING 3's conditional-tier precedent, no
    invented fifth tier). HIGH specifically for postfix/pmg-smtp-filter (mail-flow halting, the
    draft's own named criterion); MEDIUM for every other service on the schema's enum."""
    return RISK_HIGH if str(service) in _MAIL_CRITICAL_SERVICES else RISK_MEDIUM


# ---------------------------------------------------------------------------
# Backend functions — Network
# ---------------------------------------------------------------------------

def network_list(api: PmgBackend, node: str, iface_type: str | None = None) -> list[dict]:
    """GET /nodes/{node}/network — list network interfaces (optional ?type= filter).

    Schema-thin return (fact #4) — Smoke-confirm actual per-interface field names."""
    node = _check_node(node)
    params = None
    if iface_type is not None:
        params = {"type": _check_iface_type_filter(iface_type)}
    return api._get(f"/nodes/{node}/network", params=params) or []


def network_get(api: PmgBackend, iface: str, node: str) -> dict:
    """GET /nodes/{node}/network/{iface} — read one interface's configuration.

    Schema types only {method, type} (fact #5) — other fields likely present at runtime but
    undeclared; Smoke-confirm."""
    iface = _check_iface(iface)
    node = _check_node(node)
    return api._get(f"/nodes/{node}/network/{iface}") or {}


def network_create(
    api: PmgBackend,
    node: str,
    iface: str,
    iface_type: str,
    **opts,
) -> object:
    """POST /nodes/{node}/network — create a network interface configuration (staged, written to
    interfaces.new — not live until network_reload). Returns None.

    'type' is SCHEMA-REQUIRED here (fact #1, matching PVE not PBS) — no injection workaround
    needed on create (unlike update), since a brand-new interface has no prior type to preserve.
    """
    iface = _check_iface(iface)
    iface_type = _check_iface_type_value(iface_type)
    node = _check_node(node)
    if "type" in opts or "iface" in opts:
        raise ProximoError(
            "opts must not contain reserved keys 'type' or 'iface' — "
            "pass iface_type as its own argument"
        )
    data: dict = {"iface": iface, "type": iface_type, **opts}
    return api._post(f"/nodes/{node}/network", data)


def _resolve_iface_type(api: PmgBackend, node: str, iface: str, iface_type: str | None) -> str:
    """Resolve the iface_type actually sent on a network_update call: the caller-supplied value
    (validated as normal), or — when omitted — the interface's CURRENT type read live (fact #1's
    injection workaround). Wave 9a review MINOR finding (f): the injected value is now run
    through the SAME `_check_iface_type_value` validation as an explicit caller value — an
    unvalidated live read could otherwise carry an empty/garbage type straight onto the wire. A
    live value that fails validation is an honest DIVERGENCE report (PMG's own stored config
    disagrees with its documented create/update enum) — a `ProximoError`, not a crash — not a
    caller mistake, so it's raised with different wording than the plain caller-input rejection.

    Shared by `network_update` (execution) and the tool wrapper (so the ledger's
    `detail.iface_type` always records the value actually sent — Wave 9a review MAJOR finding).

    NOTE: a read FAILURE (the `network_get` call itself raising — connectivity/auth/etc.) is NOT
    caught here and propagates uncaught — matches PVE's own identical asymmetry
    (`network.py`'s `_current_iface_type`/`network_iface_update`, which has no try/except around
    its own current-type read either); not widened beyond that established precedent.
    """
    if iface_type is not None:
        return _check_iface_type_value(iface_type)
    current = network_get(api, iface, node)
    current_type = current.get("type") if isinstance(current, dict) else None
    if current_type is None:
        raise ProximoError(
            f"cannot update interface {iface!r} on {node!r}: could not read its current type "
            "to inject (schema requires 'type' on every update) — pass iface_type explicitly"
        )
    try:
        return _check_iface_type_value(current_type)
    except ProximoError as e:
        raise ProximoError(
            f"interface {iface!r} on {node!r} reports a LIVE type {current_type!r} that fails "
            f"PMG's own network type validation ({e}) — a live-config/schema divergence, not a "
            "caller mistake; pass iface_type explicitly to override"
        ) from e


def network_update(
    api: PmgBackend,
    node: str,
    iface: str,
    iface_type: str | None = None,
    delete_props=None,
    **opts,
) -> object:
    """PUT /nodes/{node}/network/{iface} — update an interface's configuration (staged — not live
    until network_reload). Returns None.

    'type' is SCHEMA-REQUIRED on update too (fact #1, matching PVE not PBS). If `iface_type` is
    omitted, the interface's CURRENT type is read (via `_resolve_iface_type`, which also
    validates it — Wave 9a review MINOR finding (f)) and injected — a plain field-only update
    needs no explicit type. UNLIKE PVE's own stricter workaround (which silently REJECTS a
    caller-supplied type as an illegal "structural change"), a caller-supplied `iface_type` here
    IS forwarded as given: nothing in PMG's schema documents type as immutable after creation, so
    refusing an intentional type change would be an unproven assumption. This is a builder
    judgment call (module docstring fact #1), not schema-mandated either way.

    NOTE: unlike `config_set`, this endpoint's schema carries NO `digest` field at all (verified
    field-by-field against the live schema — `create`/`update`/both `delete` verbs on the whole
    network family are digest-free; only node `/config` carries one on this chunk). No digest
    parameter is exposed here — inventing one would silently offer a param PMG would reject.
    """
    iface = _check_iface(iface)
    node = _check_node(node)
    if "type" in opts:
        raise ProximoError("opts must not contain the reserved key 'type' — pass iface_type instead")
    if "delete" in opts:
        raise ProximoError(
            "opts must not contain the reserved key 'delete' — pass delete_props instead"
        )
    iface_type = _resolve_iface_type(api, node, iface, iface_type)
    data: dict = {"type": iface_type, **opts}
    if delete_props is not None:
        data["delete"] = _join_delete_props(delete_props)
    return api._put(f"/nodes/{node}/network/{iface}", data)


def network_delete(api: PmgBackend, iface: str, node: str) -> object:
    """DELETE /nodes/{node}/network/{iface} — remove an interface's staged configuration (not
    live until network_reload). Returns None."""
    iface = _check_iface(iface)
    node = _check_node(node)
    return api._delete(f"/nodes/{node}/network/{iface}")


def network_revert(api: PmgBackend, node: str) -> object:
    """DELETE /nodes/{node}/network — "Revert network configuration changes": discards whatever
    is staged in interfaces.new, WITHOUT touching the live config. Returns None. Safe undo
    primitive for network_create/update/delete, before network_reload is ever called. (Rated LOW
    here — fact #7 — not the draft's guessed MEDIUM.)"""
    node = _check_node(node)
    return api._delete(f"/nodes/{node}/network")


def network_reload(api: PmgBackend, node: str) -> object:
    """PUT /nodes/{node}/network — "Reload network configuration": applies whatever is staged in
    interfaces.new, making it live. Returns a STRING (schema-confirmed, fact #6) — whether it's a
    UPID or a plain status message is unresolved from schema alone; returned unchanged.

    *** CONNECTIVITY-LOCKOUT RISK *** — mirrors PVE's/PBS's own network apply/reload.
    """
    node = _check_node(node)
    return api._put(f"/nodes/{node}/network")


# ---------------------------------------------------------------------------
# Backend functions — DNS
# ---------------------------------------------------------------------------

def dns_get(api: PmgBackend, node: str) -> dict:
    """GET /nodes/{node}/dns — read DNS resolver settings (dns1/dns2/dns3/search, all optional on
    the read side)."""
    node = _check_node(node)
    return api._get(f"/nodes/{node}/dns") or {}


def dns_set(
    api: PmgBackend,
    node: str,
    search: str,
    dns1: str | None = None,
    dns2: str | None = None,
    dns3: str | None = None,
) -> object:
    """PUT /nodes/{node}/dns — update DNS resolver settings. Returns None on success.

    `search` is SCHEMA-REQUIRED here (fact #8) — forwarded unconditionally, unlike the sibling
    PVE/PBS tools on this codebase which treat it as optional."""
    search = str(search)
    node = _check_node(node)
    data: dict = {"search": search}
    if dns1 is not None:
        data["dns1"] = dns1
    if dns2 is not None:
        data["dns2"] = dns2
    if dns3 is not None:
        data["dns3"] = dns3
    return api._put(f"/nodes/{node}/dns", data)


# ---------------------------------------------------------------------------
# Backend functions — Time
# ---------------------------------------------------------------------------

def time_get(api: PmgBackend, node: str) -> dict:
    """GET /nodes/{node}/time — read server time + timezone ({localtime, time, timezone})."""
    node = _check_node(node)
    return api._get(f"/nodes/{node}/time") or {}


def time_set(api: PmgBackend, node: str, timezone: str) -> object:
    """PUT /nodes/{node}/time — set the node's timezone. Returns None on success."""
    timezone = _check_timezone(timezone)
    node = _check_node(node)
    return api._put(f"/nodes/{node}/time", {"timezone": timezone})


# ---------------------------------------------------------------------------
# Backend functions — Node config (ACME domain-mapping only, fact #9)
# ---------------------------------------------------------------------------

def config_get(api: PmgBackend, node: str) -> dict:
    """GET /nodes/{node}/config — node-specific ACME settings only: {acme, acmedomain[n],
    digest} (fact #9 — a narrower scope than PBS's own node /config)."""
    node = _check_node(node)
    return api._get(f"/nodes/{node}/config") or {}


def config_set(
    api: PmgBackend,
    node: str,
    acme: str | None = None,
    acmedomain0: str | None = None,
    acmedomain1: str | None = None,
    acmedomain2: str | None = None,
    acmedomain3: str | None = None,
    acmedomain4: str | None = None,
    delete=None,
    digest: str | None = None,
) -> object:
    """PUT /nodes/{node}/config — set node ACME account/domain-mapping config. Returns None.

    `acme`/`acmedomain0`-`acmedomain4` are PRE-FORMATTED compound strings (fact #9), e.g.
    'account=myaccount' or 'domain=example.com,usage=smtp,plugin=cf' — not decomposed/re-encoded
    into structured kwargs (PMG's schema models each as ONE compound string, matching
    `pbs_admin.py`'s identical reasoning for the same field family)."""
    node = _check_node(node)
    data: dict = {k: v for k, v in {
        "acme": acme,
        "acmedomain0": acmedomain0,
        "acmedomain1": acmedomain1,
        "acmedomain2": acmedomain2,
        "acmedomain3": acmedomain3,
        "acmedomain4": acmedomain4,
    }.items() if v is not None}
    if delete is not None:
        data["delete"] = _join_delete_props(delete)
    digest = _check_config_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/nodes/{node}/config", data)


# ---------------------------------------------------------------------------
# Backend functions — Certificates info
# ---------------------------------------------------------------------------

def certificates_info(api: PmgBackend, node: str) -> list[dict]:
    """GET /nodes/{node}/certificates/info — list TLS certificates configured on the node.

    PUBLIC cert data only (pem/fingerprint/subject/issuer/san/validity) — no private key field
    exists anywhere in this return (schema-verified field-by-field, fact #11). Open permission
    (`user: all`, fact #11) — carried through unchanged, no additional Proximo-side gate."""
    node = _check_node(node)
    return api._get(f"/nodes/{node}/certificates/info") or []


# ---------------------------------------------------------------------------
# Backend functions — Services
# ---------------------------------------------------------------------------

def services_list(api: PmgBackend, node: str) -> list[dict]:
    """GET /nodes/{node}/services — list systemd services on the node (schema-thin item shape;
    Smoke-confirm actual per-service fields)."""
    node = _check_node(node)
    return api._get(f"/nodes/{node}/services") or []


# ---------------------------------------------------------------------------
# Backend functions — Subscription
# ---------------------------------------------------------------------------

def subscription_get(api: PmgBackend, node: str) -> dict:
    """GET /nodes/{node}/subscription — read subscription status. `key` is defensively stripped
    from the response regardless of schema silence (fact #12)."""
    node = _check_node(node)
    resp = api._get(f"/nodes/{node}/subscription") or {}
    return _strip_subscription_key(resp)


def subscription_set(api: PmgBackend, node: str, key: str) -> object:
    """PUT /nodes/{node}/subscription — "Set subscription key." Installs and validates a new
    subscription key. Returns None."""
    node = _check_node(node)
    return api._put(f"/nodes/{node}/subscription", {"key": key})


def subscription_check(api: PmgBackend, node: str, force: bool = False) -> object:
    """POST /nodes/{node}/subscription — "Update subscription info.": contacts Proxmox's server
    to refresh the cached status. force=True always re-checks even if the cache is fresh. Returns
    None. No key/identity change — a status-cache refresh only (fact #13's verb mapping)."""
    node = _check_node(node)
    data = {"force": True} if force else None
    return api._post(f"/nodes/{node}/subscription", data)


def subscription_delete(api: PmgBackend, node: str) -> object:
    """DELETE /nodes/{node}/subscription — "Delete subscription key." Removes the locally-stored
    subscription record. Returns None. Reversible: re-install via subscription_set."""
    node = _check_node(node)
    return api._delete(f"/nodes/{node}/subscription")


# ---------------------------------------------------------------------------
# Backend functions — Chunk 9b: Tasks
# ---------------------------------------------------------------------------

def task_stop(api: PmgBackend, upid: str, node: str) -> object:
    """DELETE /nodes/{node}/tasks/{upid} — "Stop a task." Returns None: a cancellation signal —
    the task may run briefly before it observes it (mirrors PVE's `tasks_pools.py::task_stop` and
    PBS's `pbs_node.py::task_stop` contract exactly)."""
    upid = _check_upid(upid)
    node = _check_node(node)
    return api._delete(f"/nodes/{node}/tasks/{upid}")


def task_log(api: PmgBackend, upid: str, node: str, start: int = 0, limit: int = 50) -> list[dict]:
    """GET /nodes/{node}/tasks/{upid}/log — a task's log lines, `{n: line number, t: line text}`
    per entry. ADVERSARIAL (fact #14) — free-text log content. `download` (whole-file mode) is
    NOT exposed (fact #15, matches PBS's own `task_log` precedent)."""
    upid = _check_upid(upid)
    node = _check_node(node)
    start = _check_nonneg_int(start, "start")
    limit = _check_nonneg_int(limit, "limit")
    return api._get(f"/nodes/{node}/tasks/{upid}/log", params={"start": start, "limit": limit}) or []


def task_status(api: PmgBackend, upid: str, node: str) -> dict:
    """GET /nodes/{node}/tasks/{upid}/status — one task's status (`{pid: integer, status:
    running|stopped}`). REVIEWED_TRUSTED (fact #14) — task metadata only, no free text."""
    upid = _check_upid(upid)
    node = _check_node(node)
    return api._get(f"/nodes/{node}/tasks/{upid}/status") or {}


# ---------------------------------------------------------------------------
# Backend functions — Chunk 9b: Diagnostics (report / journal)
# ---------------------------------------------------------------------------

def report(api: PmgBackend, node: str) -> str:
    """GET /nodes/{node}/report — "Gather various system information about a node": a free-text
    diagnostic bundle. ADVERSARIAL — exact `pbs_node_report` precedent (plausibly embeds config
    values, log tails, system state)."""
    node = _check_node(node)
    return api._get(f"/nodes/{node}/report") or ""


def journal(
    api: PmgBackend,
    node: str,
    lastentries: int | None = None,
    since: int | None = None,
    until: int | None = None,
    startcursor: str | None = None,
    endcursor: str | None = None,
) -> list[str]:
    """GET /nodes/{node}/journal — systemd journal lines (list of plain strings). ADVERSARIAL —
    matches `pmg_node_syslog`/`pve_node_journal`/`pbs_node_journal` (free-text log content).
    since/until are UNIX-epoch INTEGERS from the start (fact #24 — this module does NOT repeat
    the pre-existing PVE since/until-typed-as-str bug). startcursor/endcursor are mutually
    exclusive with since/until per the schema's own field descriptions; not enforced client-side
    (matches PBS's own `journal` precedent, `pbs_node.py`)."""
    node = _check_node(node)
    params: dict = {}
    if lastentries is not None:
        params["lastentries"] = _check_nonneg_int(lastentries, "lastentries")
    if since is not None:
        params["since"] = _check_nonneg_int(since, "since")
    if until is not None:
        params["until"] = _check_nonneg_int(until, "until")
    if startcursor is not None:
        params["startcursor"] = str(startcursor)
    if endcursor is not None:
        params["endcursor"] = str(endcursor)
    return api._get(f"/nodes/{node}/journal", params=params or None) or []


# ---------------------------------------------------------------------------
# Backend functions — Chunk 9b: Backup files
# ---------------------------------------------------------------------------

def backup_list(api: PmgBackend, node: str) -> list[dict]:
    """GET /nodes/{node}/backup — list stored PMG configuration backup files (`{filename, size,
    timestamp}`). REVIEWED_TRUSTED — structured metadata; filenames are schema-pattern-bounded
    (fact #16), not free text."""
    node = _check_node(node)
    return api._get(f"/nodes/{node}/backup") or []


def backup_delete(api: PmgBackend, node: str, filename: str) -> object:
    """DELETE /nodes/{node}/backup/{filename} — delete a stored backup file. Returns None.
    RISK_MEDIUM (see plan_backup_delete) — removes one recovery artifact; other backups and the
    live config are untouched."""
    filename = _check_backup_filename(filename)
    node = _check_node(node)
    return api._delete(f"/nodes/{node}/backup/{filename}")


def backup_restore(
    api: PmgBackend,
    node: str,
    filename: str,
    config: bool = False,
    database: bool = True,
    statistic: bool = False,
) -> object:
    """POST /nodes/{node}/backup/{filename} — "Restore the system configuration." Returns a
    schema-typed STRING (ambiguous — Smoke-confirm; fact #18). `database=True` (schema default)
    replaces the entire rule database — the SAME data `pmg_ruledb_reset` wipes to factory
    defaults (fact #17). `config=True` ALSO restores PMG's system configuration (scope
    undocumented beyond the label). `statistic` is "only considered when you restore the
    'database'" per the schema's own description. RISK_HIGH, no undo — see plan_backup_restore.
    All three flags are always sent explicitly (matching PMG's own documented defaults) for a
    deterministic wire payload."""
    filename = _check_backup_filename(filename)
    node = _check_node(node)
    data = {"config": bool(config), "database": bool(database), "statistic": bool(statistic)}
    return api._post(f"/nodes/{node}/backup/{filename}", data)


# ---------------------------------------------------------------------------
# Backend functions — Chunk 9b: Postfix queue + address-verify cache
# ---------------------------------------------------------------------------

def postfix_queue_list(
    api: PmgBackend,
    node: str,
    queue: str,
    filter: str | None = None,  # noqa: A002 — matches PMG's own param name (pbs_access.py precedent)
    limit: int | None = None,
    sortfield: str | None = None,
    sortdir: str | None = None,
    start: int | None = None,
) -> list[dict]:
    """GET /nodes/{node}/postfix/queue/{queue} — list mail queued in one Postfix queue
    (deferred/active/incoming/hold). ADVERSARIAL — the schema's own `sortfield` enum
    (arrival_time/message_size/sender/receiver/reason) confirms sender/receiver are real item
    fields even though the declared item shape is thin (`{}`); mail metadata is
    attacker-shapeable (whoever sent/addressed the message controls those bytes)."""
    queue = _check_queue(queue)
    node = _check_node(node)
    if sortdir is not None and sortfield is None:
        raise ProximoError("sortdir requires sortfield (schema: 'requires' sortfield)")
    params: dict = {}
    if filter is not None:
        params["filter"] = _check_queue_filter(filter)
    if limit is not None:
        params["limit"] = _check_nonneg_int(limit, "limit")
    if sortfield is not None:
        params["sortfield"] = _check_sortfield(sortfield)
    if sortdir is not None:
        params["sortdir"] = _check_sortdir(sortdir)
    if start is not None:
        params["start"] = _check_nonneg_int(start, "start")
    return api._get(f"/nodes/{node}/postfix/queue/{queue}", params=params or None) or []


def postfix_queue_message_get(
    api: PmgBackend,
    node: str,
    queue: str,
    queue_id: str,
    header: bool = True,
    body: bool = False,
    decode_header: bool = False,
) -> str:
    """GET /nodes/{node}/postfix/queue/{queue}/{queue_id} — "Get the contents of a queued mail"
    (schema-typed as a bare string). ADVERSARIAL — the message's own header/body content is
    entirely attacker-authored (matches the quarantine-content-read reasoning one family over)."""
    queue = _check_queue(queue)
    queue_id = _check_queue_id(queue_id)
    node = _check_node(node)
    params = {"header": bool(header), "body": bool(body), "decode-header": bool(decode_header)}
    return api._get(f"/nodes/{node}/postfix/queue/{queue}/{queue_id}", params=params) or ""


def postfix_queue_action(api: PmgBackend, node: str, queue: str, action: str, ids: str) -> object:
    """POST /nodes/{node}/postfix/queue/{queue} — "Perform an action on the given queue IDs
    (delete/deliver)." Bulk, but SCOPED to caller-enumerated `ids` (not "all queue contents").
    REVIEWED_TRUSTED — the ids/action params are caller-authored, not mail-authored. Returns
    None. Conditional risk — see plan_postfix_queue_action (fact #21)."""
    queue = _check_queue(queue)
    action = _check_postfix_queue_action(action)
    ids = _check_queue_ids(ids)
    node = _check_node(node)
    return api._post(f"/nodes/{node}/postfix/queue/{queue}", {"action": action, "ids": ids})


def postfix_queue_delete_all(api: PmgBackend, node: str) -> object:
    """DELETE /nodes/{node}/postfix/queue (bare — no queue param) — "Delete all mails in all
    postfix queues." Wipes deferred+active+incoming+hold in ONE call. RISK_HIGH (fact #22 —
    queue-delete-all class). Returns None."""
    node = _check_node(node)
    return api._delete(f"/nodes/{node}/postfix/queue")


def postfix_queue_delete_queue(api: PmgBackend, node: str, queue: str) -> object:
    """DELETE /nodes/{node}/postfix/queue/{queue} — "Delete all mails in the queue." Wipes ONE
    named queue entirely. RISK_HIGH (fact #22 — queue-delete-all class). Returns None."""
    queue = _check_queue(queue)
    node = _check_node(node)
    return api._delete(f"/nodes/{node}/postfix/queue/{queue}")


def postfix_queue_message_delete(api: PmgBackend, node: str, queue: str, queue_id: str) -> object:
    """DELETE /nodes/{node}/postfix/queue/{queue}/{queue_id} — "Delete one message with the named
    queue ID." RISK_MEDIUM (single-message class). Returns None."""
    queue = _check_queue(queue)
    queue_id = _check_queue_id(queue_id)
    node = _check_node(node)
    return api._delete(f"/nodes/{node}/postfix/queue/{queue}/{queue_id}")


def postfix_queue_message_deliver(api: PmgBackend, node: str, queue: str, queue_id: str) -> object:
    """POST /nodes/{node}/postfix/queue/{queue}/{queue_id} — "Schedule immediate delivery of
    deferred mail with the specified queue ID." RISK_LOW (fact #23 — mirrors the already-shipped
    `pmg_postfix_flush`'s own LOW rating). Returns None."""
    queue = _check_queue(queue)
    queue_id = _check_queue_id(queue_id)
    node = _check_node(node)
    return api._post(f"/nodes/{node}/postfix/queue/{queue}/{queue_id}")


def postfix_discard_verify_cache(api: PmgBackend, node: str) -> object:
    """POST /nodes/{node}/postfix/discard_verify_cache — "Discards the address verification
    cache." RISK_LOW — Postfix rebuilds it lazily on demand; no mail is affected. Returns
    None."""
    node = _check_node(node)
    return api._post(f"/nodes/{node}/postfix/discard_verify_cache")


# ---------------------------------------------------------------------------
# Backend functions — Chunk 9b: ClamAV / SpamAssassin signature DBs
# ---------------------------------------------------------------------------

def clamav_database_get(api: PmgBackend, node: str) -> list[dict]:
    """GET /nodes/{node}/clamav/database — ClamAV virus database status (per-DB `build_time`/
    `nsigs`/`type`/`version`). REVIEWED_TRUSTED — structured version/count metadata from
    ClamAV's own database files, no attacker-shapeable channel."""
    node = _check_node(node)
    return api._get(f"/nodes/{node}/clamav/database") or []


def clamav_database_update(api: PmgBackend, node: str) -> object:
    """POST /nodes/{node}/clamav/database — "Update ClamAV virus databases." Fetches fresh
    signature DBs from ClamAV's upstream mirrors. RISK_MEDIUM — protective in direction; network-
    dependent. Returns a schema-typed STRING (ambiguous — fact #18)."""
    node = _check_node(node)
    return api._post(f"/nodes/{node}/clamav/database")


def spamassassin_rules_get(api: PmgBackend, node: str) -> list[dict]:
    """GET /nodes/{node}/spamassassin/rules — SpamAssassin rule-channel status (`channel`/
    `last_updated`/`update_avail`/`update_version`/`version`). REVIEWED_TRUSTED — structured
    version/count metadata, no attacker-shapeable channel."""
    node = _check_node(node)
    return api._get(f"/nodes/{node}/spamassassin/rules") or []


def spamassassin_rules_update(api: PmgBackend, node: str) -> object:
    """POST /nodes/{node}/spamassassin/rules — "Update SpamAssassin rules." RISK_MEDIUM —
    protective in direction; network-dependent. Returns a schema-typed STRING (ambiguous —
    fact #18)."""
    node = _check_node(node)
    return api._post(f"/nodes/{node}/spamassassin/rules")


# ---------------------------------------------------------------------------
# Backend functions — Chunk 9b: Service lifecycle remainder
# ---------------------------------------------------------------------------

def service_start(api: PmgBackend, node: str, service: str) -> object:
    """POST /nodes/{node}/services/{service}/start — start a PMG system service. RISK_MEDIUM —
    resumes normal operation of a stopped service. Returns a schema-typed STRING (ambiguous —
    fact #18). See fact #19 for this tool's relationship to the already-shipped generic
    `pmg_service_control` dispatcher."""
    service = _check_service(service)
    node = _check_node(node)
    return api._post(f"/nodes/{node}/services/{service}/start")


def service_stop(api: PmgBackend, node: str, service: str) -> object:
    """POST /nodes/{node}/services/{service}/stop — stop a PMG system service. Conditional risk
    (fact #20): RISK_HIGH for postfix/pmg-smtp-filter (halts ALL mail flow), RISK_MEDIUM
    otherwise. Returns a schema-typed STRING (ambiguous — fact #18)."""
    service = _check_service(service)
    node = _check_node(node)
    return api._post(f"/nodes/{node}/services/{service}/stop")


def service_restart(api: PmgBackend, node: str, service: str) -> object:
    """POST /nodes/{node}/services/{service}/restart — restart a PMG system service. RISK_MEDIUM
    — brief interruption while the service restarts. Returns a schema-typed STRING (ambiguous —
    fact #18)."""
    service = _check_service(service)
    node = _check_node(node)
    return api._post(f"/nodes/{node}/services/{service}/restart")


def service_reload(api: PmgBackend, node: str, service: str) -> object:
    """POST /nodes/{node}/services/{service}/reload — reload a PMG system service's
    configuration. RISK_MEDIUM — typically non-disruptive but still a live config re-read, not
    rated RISK_LOW without live confirmation. Returns a schema-typed STRING (ambiguous —
    fact #18)."""
    service = _check_service(service)
    node = _check_node(node)
    return api._post(f"/nodes/{node}/services/{service}/reload")


# ---------------------------------------------------------------------------
# Plan factories — Network
# ---------------------------------------------------------------------------

def plan_network_create(
    api: PmgBackend,
    node: str,
    iface: str,
    iface_type: str,
    opts: dict | None = None,
) -> Plan:
    """Preview creating a PMG network interface. Reads network_list (a safe read) to detect a
    name collision. RISK_MEDIUM: staged, not live until network_reload."""
    iface = _check_iface(iface)
    iface_type = _check_iface_type_value(iface_type)
    node = _check_node(node)
    opts = opts or {}

    taken = False
    check_error: str | None = None
    try:
        ifaces = network_list(api, node) or []
        taken = any(
            isinstance(i, dict) and (i.get("iface") == iface or i.get("name") == iface)
            for i in ifaces
        )
    except Exception as e:
        check_error = type(e).__name__

    if check_error is not None:
        blast = [f"collision check failed ({check_error}) — could not confirm {iface!r} is free"]
        reasons = [f"staged create of interface {iface!r} on {node}", "collision check unavailable"]
    elif taken:
        blast = [f"create will FAIL — interface {iface!r} already exists on {node}"]
        reasons = [f"{iface!r} is already configured on {node}; create will be rejected by PMG"]
    else:
        blast = [
            f"stages new interface {iface!r} (type={iface_type!r}) on {node} "
            "(written to interfaces.new)",
            "change is NOT live until pmg_node_network_reload is run",
        ]
        reasons = [f"staged configuration change: creates interface {iface!r} on {node}",
                   "reversible before reload: pmg_node_network_revert discards it"]

    if opts:
        blast.append("staged fields: " + ", ".join(f"{k}={opts[k]}" for k in sorted(opts)))

    return Plan(
        action="pmg_node_network_create",
        target=f"pmg/node/{node}/network/{iface}",
        change=f"create interface {iface!r} (type={iface_type!r}) on {node} (staged)",
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=reasons,
        note=("Staged (interfaces.new) — no live effect until pmg_node_network_reload, which "
              "carries RISK_HIGH (connectivity-lockout). Discard the staged change with "
              "pmg_node_network_revert."),
    )


def plan_network_update(
    api: PmgBackend,
    node: str,
    iface: str,
    iface_type: str | None = None,
    opts: dict | None = None,
    delete_props=None,
) -> Plan:
    """Preview updating a PMG network interface. Reads the interface's current config (a safe
    read; also the source of the type-injection when iface_type is omitted). RISK_MEDIUM: staged,
    not live until network_reload.

    Wave 9a review fixes:
      - CRITICAL: `delete_props`, if given, is disclosed explicitly in blast_radius (one line per
        property) — previously the PLAN never received this argument at all, so a real property
        deletion that confirm=True then executed was invisible to the dry-run preview.
      - MAJOR (d): when an explicit `iface_type` differs from the interface's CAPTURED current
        type, this is flagged as a TYPE CHANGE (not just a bare restatement of the new value) —
        PVE's own equivalent tool refuses this outright; PMG's schema does not document type as
        immutable, so this build allows it, but the plan must say so plainly. Degrades honestly
        when the capture failed: no current type is known, so no TYPE CHANGE claim is made either
        way (the explicit-type line still renders).
    """
    iface = _check_iface(iface)
    node = _check_node(node)
    if iface_type is not None:
        iface_type = _check_iface_type_value(iface_type)
    opts = opts or {}

    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = network_get(api, iface, node)
    except Exception:
        complete = False
        note_capture = " Could not read current config for this interface."

    blast = [
        f"updates interface {iface!r} on {node} (staged — written to interfaces.new)",
        "change is NOT live until pmg_node_network_reload is run",
    ]
    current_type = current.get("type")
    if iface_type:
        if current_type and current_type != iface_type:
            blast.append(
                f"*** TYPE CHANGE *** from {current_type!r} to {iface_type!r} — PVE's own "
                "equivalent tool refuses this; PMG's schema does not document type as immutable"
            )
        else:
            blast.append(f"type={iface_type!r} (explicit)")
    elif current_type:
        blast.append(f"type={current_type!r} (preserved from current config)")
    if opts:
        blast.append("staged fields: " + ", ".join(f"{k}={opts[k]}" for k in sorted(opts)))
    if delete_props:
        for p in _delete_list(delete_props):
            blast.append(f"DELETES {p!r} from interface {iface!r} on {node}")

    return Plan(
        action="pmg_node_network_update",
        target=f"pmg/node/{node}/network/{iface}",
        change=f"update interface {iface!r} on {node} (staged)",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[f"staged modification of existing interface {iface!r} on {node}",
                      "reversible before reload: pmg_node_network_revert discards it"],
        complete=complete,
        note=("Staged (interfaces.new) — no live effect until pmg_node_network_reload "
              "(RISK_HIGH)." + note_capture),
    )


def plan_network_delete(api: PmgBackend, iface: str, node: str) -> Plan:
    """Preview deleting a PMG network interface's staged config. RISK_MEDIUM: staged removal, not
    live until network_reload."""
    iface = _check_iface(iface)
    node = _check_node(node)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = network_get(api, iface, node)
    except Exception:
        complete = False
        note_capture = " Could not read current config for this interface."
    return Plan(
        action="pmg_node_network_delete",
        target=f"pmg/node/{node}/network/{iface}",
        change=f"remove interface {iface!r} from {node}'s staged config (interfaces.new)",
        current=current,
        blast_radius=[
            f"stages removal of interface {iface!r} on {node} — NOT live until "
            "pmg_node_network_reload",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[f"staged removal of interface {iface!r} on {node}",
                      "reversible before reload: pmg_node_network_revert discards the staged removal"],
        complete=complete,
        note=("Staged — no live effect until pmg_node_network_reload (RISK_HIGH)." + note_capture),
    )


def plan_network_revert(node: str) -> Plan:
    """Preview discarding staged PMG network changes. RISK_LOW (fact #7 — a reasoned divergence
    from the draft's guessed MEDIUM): this is the safe undo — it never touches the live config,
    only interfaces.new, matching PBS's/PVE's identical operation."""
    node = _check_node(node)
    return Plan(
        action="pmg_node_network_revert",
        target=f"pmg/node/{node}/network",
        change=f"discard staged network configuration changes on {node} (interfaces.new discarded)",
        current={},
        blast_radius=[
            f"node/{node}: any un-applied pmg_node_network_create/update/delete staged edits are lost",
        ],
        risk=RISK_LOW,
        risk_reasons=["reverts only the STAGED (interfaces.new) file — the live config is untouched"],
        note=("Safe: does not affect live connectivity. Re-stage changes with the network "
              "create/update/delete tools if needed."),
    )


def plan_network_reload(node: str) -> Plan:
    """Preview applying staged PMG network changes. RISK_HIGH, unconditional — mirrors PBS's/
    PVE's own network apply/reload: a mis-applied config can lose SSH/API/mail connectivity,
    requiring console/physical recovery. No pre-read of pending state (PMG exposes no diff/
    pending-preview endpoint for /network)."""
    node = _check_node(node)
    return Plan(
        action="pmg_node_network_reload",
        target=f"pmg/node/{node}/network",
        change=f"apply staged network configuration changes on {node} (interfaces.new -> live)",
        current={},
        blast_radius=[
            f"*** CONNECTIVITY-LOCKOUT RISK *** node/{node}: a misconfigured interface can drop "
            "SSH/API/mail access; recovery requires console or physical access",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "applying a misconfigured network interface can lose connectivity to the node; "
            "no automatic undo",
        ],
        note=("RISK_HIGH is unconditional — review staged changes (pmg_node_network_list/"
              "pmg_node_network_get) before reload. To discard staged changes instead, use "
              "pmg_node_network_revert."),
    )


# ---------------------------------------------------------------------------
# Plan factories — DNS / Time (CAPTURE-or-declare)
# ---------------------------------------------------------------------------

def plan_dns_set(
    api: PmgBackend,
    node: str,
    search: str,
    dns1: str | None = None,
    dns2: str | None = None,
    dns3: str | None = None,
) -> Plan:
    """Preview updating PMG node DNS config. CAPTURE-or-declare: reads GET /dns first. RISK_MEDIUM
    (mirrors pbs_node.py's plan_dns_set)."""
    node = _check_node(node)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        result = dns_get(api, node)
        current = {k: result[k] for k in ("search", "dns1", "dns2", "dns3") if k in result}
    except Exception:
        complete = False
        note_capture = " Could not capture current DNS config — no guided revert available."

    changes = {k: v for k, v in {"search": search, "dns1": dns1, "dns2": dns2, "dns3": dns3}.items() if v is not None}
    return Plan(
        action="pmg_node_dns_set",
        target=f"pmg/node/{node}/dns",
        change=f"update DNS resolver config on PMG node {node!r}: {changes}",
        current=current,
        blast_radius=[f"node/{node} DNS resolver config — affects name resolution for mail delivery/relay"],
        risk=RISK_MEDIUM,
        risk_reasons=["DNS config change takes effect immediately; incorrect config can break name resolution"],
        complete=complete,
        note="Revert by re-applying the captured DNS settings with pmg_node_dns_set." + note_capture,
    )


def plan_time_set(api: PmgBackend, node: str, timezone: str) -> Plan:
    """Preview setting PMG node timezone. CAPTURE-or-declare: reads GET /time first. RISK_LOW
    (mirrors pbs_node.py's plan_time_set)."""
    timezone = _check_timezone(timezone)
    node = _check_node(node)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        result = time_get(api, node)
        current = {"timezone": result.get("timezone", "unknown")}
    except Exception:
        complete = False
        note_capture = " Could not capture current timezone — no guided revert available."
    return Plan(
        action="pmg_node_time_set",
        target=f"pmg/node/{node}/time",
        change=f"set PMG node timezone to {timezone!r}",
        current=current,
        blast_radius=[f"node/{node} timezone configuration"],
        risk=RISK_LOW,
        risk_reasons=["timezone change takes effect immediately on the node"],
        complete=complete,
        note="Revert by re-applying the captured timezone with pmg_node_time_set." + note_capture,
    )


# ---------------------------------------------------------------------------
# Plan factories — Node config
# ---------------------------------------------------------------------------

def plan_config_set(
    api: PmgBackend,
    node: str,
    acme: str | None = None,
    acmedomain0: str | None = None,
    acmedomain1: str | None = None,
    acmedomain2: str | None = None,
    acmedomain3: str | None = None,
    acmedomain4: str | None = None,
    delete=None,
) -> Plan:
    """Preview updating PMG node ACME account/domain-mapping config. CAPTURE-or-declare: reads
    GET /config first. RISK_MEDIUM: a misconfigured acme/acmedomain mapping can break automatic
    certificate renewal (mirrors pbs_admin.py's plan_node_config_set reasoning for the identical
    field family).

    Wave 9a review CRITICAL fix: `delete`, if given, is disclosed explicitly in blast_radius (one
    line per cleared property) — previously the PLAN never received this argument at all, so a
    real property deletion (e.g. clearing `acmedomain0`, which can break automatic certificate
    renewal per this same module's own risk framing) that confirm=True then executed was
    invisible to the dry-run preview."""
    node = _check_node(node)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = config_get(api, node)
    except Exception:
        complete = False
        note_capture = " Could not capture current node config — no guided revert available."

    changes = {k: v for k, v in {
        "acme": acme, "acmedomain0": acmedomain0, "acmedomain1": acmedomain1,
        "acmedomain2": acmedomain2, "acmedomain3": acmedomain3, "acmedomain4": acmedomain4,
    }.items() if v is not None}
    blast = [f"node/{node} ACME account/domain-mapping config — a misconfiguration can "
             "break automatic certificate renewal"]
    if delete:
        for p in _delete_list(delete):
            blast.append(f"DELETES {p!r} from PMG node {node!r}'s ACME config")
    return Plan(
        action="pmg_node_config_set",
        target=f"pmg/node/{node}/config",
        change=f"update ACME account/domain-mapping config on PMG node {node!r}: {changes}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["ACME config change takes effect on the next renewal attempt"],
        complete=complete,
        note="Revert by re-applying the captured config with pmg_node_config_set." + note_capture,
    )


# ---------------------------------------------------------------------------
# Plan factories — Subscription
# ---------------------------------------------------------------------------

def plan_subscription_set(node: str, key: str) -> Plan:
    """Preview installing a PMG subscription key. RISK_MEDIUM: changes the node's entitlement
    record, reversible via pmg_node_subscription_delete."""
    node = _check_node(node)
    return Plan(
        action="pmg_node_subscription_set",
        target=f"pmg/node/{node}/subscription",
        change=f"install and validate a subscription key on PMG node {node!r}",
        current={},
        blast_radius=[f"node/{node} subscription record — changes entitlement/support-level state"],
        risk=RISK_MEDIUM,
        risk_reasons=["installs a new subscription key, contacting Proxmox's server to validate it"],
        note="Revert with pmg_node_subscription_delete (removes the record) or install a different key.",
    )


def plan_subscription_check(node: str, force: bool = False) -> Plan:
    """Preview refreshing PMG subscription status. RISK_LOW: an online status refresh, no
    identity/key change (mirrors PBS's plan_subscription_check / the Wave 1 apt_update_refresh
    precedent)."""
    node = _check_node(node)
    return Plan(
        action="pmg_node_subscription_check",
        target=f"pmg/node/{node}/subscription",
        change=f"check and refresh subscription status on PMG node {node!r}" + (" (force=True)" if force else ""),
        current={},
        blast_radius=[f"node/{node} subscription cache — refreshed from Proxmox's server; no key/identity change"],
        risk=RISK_LOW,
        risk_reasons=["refreshes cached subscription status only; no state change to the installed key"],
    )


def plan_subscription_delete(node: str) -> Plan:
    """Preview removing PMG subscription info. RISK_MEDIUM: reversible via
    pmg_node_subscription_set (re-install the key)."""
    node = _check_node(node)
    return Plan(
        action="pmg_node_subscription_delete",
        target=f"pmg/node/{node}/subscription",
        change=f"delete subscription info on PMG node {node!r}",
        current={},
        blast_radius=[
            f"node/{node} subscription record removed — entitlement/support-level state reverts "
            "to unlicensed",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["removes the locally-stored subscription record"],
        note="Reversible: re-install a key with pmg_node_subscription_set.",
    )


# ---------------------------------------------------------------------------
# Plan factories — Chunk 9b: Tasks
# ---------------------------------------------------------------------------

def plan_task_stop(upid: str, node: str) -> Plan:
    """Preview stopping (cancelling) a PMG task. RISK_HIGH — mirrors PVE's `pve_task_stop`
    (`tasks_pools.py::plan_task_stop`) and PBS's `pbs_node_task_stop` (`pbs_node.py`), both rated
    HIGH for the identical operation on sibling planes: stopping a backup/restore/mail-processing
    task mid-flight can leave PMG state inconsistent, with NO undo."""
    upid = _check_upid(upid)
    node = _check_node(node)
    return Plan(
        action="pmg_node_task_stop",
        target=f"pmg/node/{node}/tasks/{upid}",
        change=f"stop (cancel) task {upid} on {node}",
        current={},
        blast_radius=[
            f"sends a cancellation signal to task {upid} on {node}",
            "if this task is a backup, restore, or mail-processing job: it is interrupted "
            "MID-FLIGHT — PMG state may be left inconsistent or partial",
            "CANNOT be automatically undone — there is no undo for an interrupted task",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "stopping a running task can interrupt a backup/restore/mail-processing job mid-flight",
            "matches PVE's pve_task_stop and PBS's pbs_node_task_stop — both rated HIGH for the "
            "identical operation on sibling planes",
        ],
        note="task_stop is a cancellation signal — the task may run briefly before it observes it.",
    )


# ---------------------------------------------------------------------------
# Plan factories — Chunk 9b: Backup files
# ---------------------------------------------------------------------------

def plan_backup_delete(node: str, filename: str) -> Plan:
    """Preview deleting a stored PMG backup file. RISK_MEDIUM — removes one recovery artifact;
    other backups and the live config are untouched."""
    filename = _check_backup_filename(filename)
    node = _check_node(node)
    return Plan(
        action="pmg_node_backup_delete",
        target=f"pmg/node/{node}/backup/{filename}",
        change=f"delete backup file {filename!r} on {node}",
        current={},
        blast_radius=[
            f"removes {filename!r} from /var/lib/pmg/backup/ on {node}",
            "other backup files and the live config are untouched",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["removes a recovery artifact; if this was the only recent backup, restore options narrow"],
    )


def plan_backup_restore(
    api: PmgBackend,
    node: str,
    filename: str,
    config: bool = False,
    database: bool = True,
    statistic: bool = False,
) -> Plan:
    """Preview restoring PMG state from a stored backup file. NOT pure — best-effort CAPTURE of
    what will be overwritten, degrading honestly on any read failure (fact #17): reuses
    `pmg.py`'s own `_ruledb_reset_capture_count` + rules/who/what/when/action-object readers
    VERBATIM — the same helper `plan_ruledb_reset` uses — since `database=True` (the default)
    replaces the identical ruledb region that factory-reset wipes.

    RISK_HIGH, unconditional. NO UNDO exists: PMG exposes no restore-preview/dry-run companion
    and no "what changed" diff; the only recovery is a fresh `pmg_backup_create` taken
    beforehand — mirrors `plan_ruledb_reset`'s own "no undo" first blast_radius line exactly.
    """
    filename = _check_backup_filename(filename)
    node = _check_node(node)

    # Existence check (best-effort, degrades honestly) — mirrors network_create's collision
    # check, inverted: here we check the target file IS present, not absent.
    exists: bool | None = None
    fail_notes: list[str] = []
    try:
        files = backup_list(api, node) or []
        names = {f.get("filename") for f in files if isinstance(f, dict)}
        exists = filename in names
    except Exception as e:
        fail_notes.append(f"backup file existence check failed: {type(e).__name__}: {e}")

    # Ruledb capture (only meaningful when database=True, the schema default and the only
    # ruledb-touching branch) — reuses pmg.py's own factory-reset capture helper verbatim.
    counts: dict[str, int | None] = {}
    if database:
        for key, reader in (
            ("rules", lambda: ruledb_rules_list(api)),
            ("who_groups", lambda: who_groups_list(api)),
            ("what_groups", lambda: what_groups_list(api)),
            ("when_groups", lambda: when_groups_list(api)),
            ("action_objects", lambda: action_objects_list(api)),
        ):
            count, fail = _ruledb_reset_capture_count(key, reader)
            counts[key] = count
            if fail:
                fail_notes.append(fail)

    blast = ["Proximo has NO undo for this; take pmg_backup_create first."]
    if exists is False:
        blast.append(f"restore will FAIL — {filename!r} was not found in pmg_node_backup_list")
    elif exists is None:
        blast.append(f"could not confirm {filename!r} exists in the stored backup list")

    if database:
        def _fmt(key: str) -> str:
            v = counts.get(key)
            return str(v) if v is not None else "an unknown number of"

        blast.append(
            f"REPLACES the entire rule database: {_fmt('rules')} rules, {_fmt('who_groups')} "
            f"who / {_fmt('what_groups')} what / {_fmt('when_groups')} when groups, "
            f"{_fmt('action_objects')} action objects — same scope as pmg_ruledb_reset"
        )
        if statistic:
            blast.append("ALSO restores mail statistics databases (statistic=True)")
    else:
        blast.append("database=False: the rule database is left untouched")

    if config:
        blast.append(
            "ALSO restores the PMG system configuration from the backup file — Proximo cannot "
            "enumerate the exact scope of 'system configuration' from PMG's schema alone; treat "
            "this as replacing node-wide settings, not just the ruledb"
        )

    blast.extend(fail_notes)

    return Plan(
        action="pmg_node_backup_restore",
        target=f"pmg/node/{node}/backup/{filename}",
        change=(f"restore PMG state from backup file {filename!r} on {node} "
                f"(config={config}, database={database}, statistic={statistic})"),
        current=counts,
        blast_radius=blast,
        risk=RISK_HIGH,
        risk_reasons=[
            "overwrites live PMG state from a stored file with no undo primitive and no "
            "restore-preview/diff endpoint",
            "database=True (the default) replaces the ENTIRE rule database, matching "
            "pmg_ruledb_reset's own destructive scope",
        ],
        complete=not fail_notes,
        note=("No dry-run companion exists upstream. Take a fresh pmg_backup_create before "
              "running this with confirm=True."),
    )


# ---------------------------------------------------------------------------
# Plan factories — Chunk 9b: Postfix queue + address-verify cache
# ---------------------------------------------------------------------------

def plan_postfix_queue_action(node: str, queue: str, action: str, ids: str) -> Plan:
    """Preview a bulk delete/deliver action on caller-enumerated queue IDs. Conditional risk
    (fact #21 — mirrors `pmg.py`'s own `plan_quarantine_action`: action='delete' => RISK_HIGH,
    action='deliver' => RISK_MEDIUM, the same delete/deliver dichotomy, no invented fifth
    tier)."""
    queue = _check_queue(queue)
    action = _check_postfix_queue_action(action)
    ids = _check_queue_ids(ids)
    node = _check_node(node)
    risk = RISK_HIGH if action == "delete" else RISK_MEDIUM
    return Plan(
        action="pmg_node_postfix_queue_action",
        target=f"pmg/node/{node}/postfix/queue/{queue}",
        change=f"{action} queue ID(s) {ids!r} in the {queue!r} queue on {node}",
        current={},
        blast_radius=[
            f"applies {action!r} to queue ID(s): {ids}",
            ("delete: permanently removes the named message(s) — no undo" if action == "delete"
             else "deliver: attempts immediate delivery — additive, no message deleted"),
            "scope is bounded to the caller-enumerated ids, not the whole queue",
        ],
        risk=risk,
        risk_reasons=[
            ("HIGH for action='delete': permanently removes the named message(s), no undo"
             if action == "delete" else
             "MEDIUM for action='deliver': additive delivery attempt; a bounced message stays queued"),
        ],
    )


def plan_postfix_queue_delete_all(node: str) -> Plan:
    """Preview wiping ALL Postfix queues on a PMG node. RISK_HIGH (fact #22 — queue-delete-all
    class) — no scoping, no undo; every deferred/active/incoming/hold message is gone."""
    node = _check_node(node)
    return Plan(
        action="pmg_node_postfix_queue_delete_all",
        target=f"pmg/node/{node}/postfix/queue",
        change=f"delete ALL mail in ALL Postfix queues on {node} (deferred+active+incoming+hold)",
        current={},
        blast_radius=[
            f"*** DESTROYS EVERY QUEUED MESSAGE *** on {node} across all 4 Postfix queues",
            "no undo — messages are gone, not just requeued",
        ],
        risk=RISK_HIGH,
        risk_reasons=["unconditional wipe of every queued message on the node; no scoping param exists upstream"],
    )


def plan_postfix_queue_delete_queue(node: str, queue: str) -> Plan:
    """Preview wiping ONE named Postfix queue on a PMG node. RISK_HIGH (fact #22 —
    queue-delete-all class) — scoped to one queue but still an unconditional full wipe of it."""
    queue = _check_queue(queue)
    node = _check_node(node)
    return Plan(
        action="pmg_node_postfix_queue_delete_queue",
        target=f"pmg/node/{node}/postfix/queue/{queue}",
        change=f"delete ALL mail in the {queue!r} Postfix queue on {node}",
        current={},
        blast_radius=[
            f"*** DESTROYS EVERY MESSAGE *** in the {queue!r} queue on {node}",
            "no undo",
        ],
        risk=RISK_HIGH,
        risk_reasons=[f"unconditional wipe of every message in the {queue!r} queue"],
    )


def plan_postfix_queue_message_delete(node: str, queue: str, queue_id: str) -> Plan:
    """Preview deleting ONE queued message. RISK_MEDIUM (single-message class, per chunk law)."""
    queue = _check_queue(queue)
    queue_id = _check_queue_id(queue_id)
    node = _check_node(node)
    return Plan(
        action="pmg_node_postfix_queue_message_delete",
        target=f"pmg/node/{node}/postfix/queue/{queue}/{queue_id}",
        change=f"delete message {queue_id!r} from the {queue!r} queue on {node}",
        current={},
        blast_radius=[
            f"permanently removes message {queue_id!r} from the {queue!r} queue",
            "no undo",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["deletes exactly one queued message; scope is bounded, unlike the delete-all family"],
    )


def plan_postfix_queue_message_deliver(node: str, queue: str, queue_id: str) -> Plan:
    """Preview scheduling immediate delivery of ONE deferred message. RISK_LOW (fact #23 —
    mirrors `pmg.py`'s own already-shipped `plan_postfix_flush`, same "attempt delivery"
    semantics scoped to one message rather than all queues)."""
    queue = _check_queue(queue)
    queue_id = _check_queue_id(queue_id)
    node = _check_node(node)
    return Plan(
        action="pmg_node_postfix_queue_message_deliver",
        target=f"pmg/node/{node}/postfix/queue/{queue}/{queue_id}",
        change=f"schedule immediate delivery of message {queue_id!r} in the {queue!r} queue on {node}",
        current={},
        blast_radius=[
            f"attempts immediate delivery of message {queue_id!r}",
            "additive: no message is deleted; a message that cannot be delivered stays queued",
        ],
        risk=RISK_LOW,
        risk_reasons=["additive delivery attempt scoped to one message; mirrors pmg_postfix_flush's LOW rating"],
    )


def plan_postfix_discard_verify_cache(node: str) -> Plan:
    """Preview discarding the Postfix address-verification cache. RISK_LOW — cache-only; Postfix
    rebuilds it lazily, no mail is affected."""
    node = _check_node(node)
    return Plan(
        action="pmg_node_postfix_discard_verify_cache",
        target=f"pmg/node/{node}/postfix/discard_verify_cache",
        change=f"discard the Postfix address-verification cache on {node}",
        current={},
        blast_radius=[
            f"clears the cached address-verification results on {node}; Postfix rebuilds it on demand",
        ],
        risk=RISK_LOW,
        risk_reasons=["cache-only; Postfix rebuilds it lazily, no mail is affected"],
    )


# ---------------------------------------------------------------------------
# Plan factories — Chunk 9b: ClamAV / SpamAssassin signature DBs
# ---------------------------------------------------------------------------

def plan_clamav_database_update(node: str) -> Plan:
    """Preview fetching fresh ClamAV signature databases. RISK_MEDIUM — protective in direction,
    network-dependent."""
    node = _check_node(node)
    return Plan(
        action="pmg_node_clamav_database_update",
        target=f"pmg/node/{node}/clamav/database",
        change=f"fetch fresh ClamAV virus signature databases on {node}",
        current={},
        blast_radius=[
            f"refreshes ClamAV signature DBs on {node} from upstream mirrors",
            "protective direction: improves detection; briefly busies clamav-freshclam",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["network-dependent fetch; a failed fetch leaves the prior DB in place (no data loss)"],
    )


def plan_spamassassin_rules_update(node: str) -> Plan:
    """Preview fetching fresh SpamAssassin rule channels. RISK_MEDIUM — protective in direction,
    network-dependent."""
    node = _check_node(node)
    return Plan(
        action="pmg_node_spamassassin_rules_update",
        target=f"pmg/node/{node}/spamassassin/rules",
        change=f"fetch fresh SpamAssassin rule channels on {node}",
        current={},
        blast_radius=[
            f"refreshes SpamAssassin rule channels on {node}",
            "protective direction: improves spam detection",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["network-dependent fetch; a bad rule channel could affect spam scoring accuracy"],
    )


# ---------------------------------------------------------------------------
# Plan factories — Chunk 9b: Service lifecycle remainder
# ---------------------------------------------------------------------------

def plan_service_start(node: str, service: str) -> Plan:
    """Preview starting a PMG system service. RISK_MEDIUM — resumes normal operation."""
    service = _check_service(service)
    node = _check_node(node)
    return Plan(
        action="pmg_node_service_start",
        target=f"pmg/node/{node}/services/{service}",
        change=f"start service {service!r} on {node}",
        current={},
        blast_radius=[f"resumes normal operation of {service!r} on {node}"],
        risk=RISK_MEDIUM,
        risk_reasons=["starting a stopped service resumes its function; direction is additive"],
    )


def plan_service_stop(node: str, service: str) -> Plan:
    """Preview stopping a PMG system service. Conditional risk (fact #20): RISK_HIGH for
    postfix/pmg-smtp-filter (halts ALL mail flow), RISK_MEDIUM otherwise — direction-aware
    blast_radius (the Wave-7b defect-shape lesson: never state a one-sided consequence that
    doesn't actually apply to every case)."""
    service = _check_service(service)
    node = _check_node(node)
    risk = _service_stop_risk(service)
    blast = [f"halts {service!r} on {node} until manually restarted"]
    if service in _MAIL_CRITICAL_SERVICES:
        blast.append(
            f"*** {service!r} is mail-flow-critical *** — stopping it halts ALL mail delivery "
            "through this PMG node"
        )
        reasons = [f"{service!r} is mail-flow-critical — stopping it halts ALL mail delivery"]
    else:
        reasons = [f"stopping {service!r} interrupts its function; no mail-flow impact documented for this service"]
    return Plan(
        action="pmg_node_service_stop",
        target=f"pmg/node/{node}/services/{service}",
        change=f"stop service {service!r} on {node}",
        current={},
        blast_radius=blast,
        risk=risk,
        risk_reasons=reasons,
    )


def plan_service_restart(node: str, service: str) -> Plan:
    """Preview restarting a PMG system service. RISK_MEDIUM — brief interruption while it
    restarts; self-healing direction."""
    service = _check_service(service)
    node = _check_node(node)
    return Plan(
        action="pmg_node_service_restart",
        target=f"pmg/node/{node}/services/{service}",
        change=f"restart service {service!r} on {node}",
        current={},
        blast_radius=[f"brief interruption of {service!r} on {node} while it restarts"],
        risk=RISK_MEDIUM,
        risk_reasons=["restart causes a brief service interruption; direction is self-healing"],
    )


def plan_service_reload(node: str, service: str) -> Plan:
    """Preview reloading a PMG system service's configuration. RISK_MEDIUM — typically
    non-disruptive but still a live config re-read."""
    service = _check_service(service)
    node = _check_node(node)
    return Plan(
        action="pmg_node_service_reload",
        target=f"pmg/node/{node}/services/{service}",
        change=f"reload service {service!r} on {node}",
        current={},
        blast_radius=[f"re-reads {service!r}'s configuration on {node}; typically non-disruptive"],
        risk=RISK_MEDIUM,
        risk_reasons=["reload is typically non-disruptive but is still a live config re-read"],
    )
