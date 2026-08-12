"""SDN CONTROLLERS + DNS + IPAMs pillar (Wave 7c, full-surface campaign).

Three named-object config families on the SAME staged-pending SDN plane as
`network.py`'s zone/vnet/subnet CRUD:
  controllers -> /cluster/sdn/controllers[/{controller}]
  dns         -> /cluster/sdn/dns[/{dns}]
  ipams       -> /cluster/sdn/ipams[/{ipam}][/status]

Schema truth: `.scratch/api-schemas-2026-07-15/wave7-pve-sdn-schema.json` (49 paths, 90
methods; live PVE apidoc pull, 2026-07-15) — the `controllers`/`dns`/`ipams` paths read in
full field-by-field for this build, not assumed from the draft's summary.

All three families are PENDING (staged) config, same lifecycle as zone/vnet/subnet: inert
until `pve_sdn_apply`, and — per Wave 7a's UNDO-honesty upgrade — recoverable either
narrowly (a second CRUD call) or broadly via `pve_sdn_rollback` (discards every pending SDN
edit cluster-wide). Every create/update/delete plan factory states both paths, mirroring
`network.py`'s own `_sdn_pending_blast` framing (a fresh, family-scoped copy of that helper
lives here rather than importing it, since the exact wording differs per object type and
the helper itself is tiny — matches the established per-module tiny-helper-duplication
convention, e.g. `sdn_firewall.py`'s own `_parse_delete_keys`).

*** THE SECRET RULING — REINSTATED, FINAL (strike-and-correct note, this build): an earlier
version of this module claimed reads return the API's raw, unstripped response, citing
`.scratch/sdd/wave-7-draft-decomposition.md` Fact #14 as authorizing that reversal, "binding,
from the coordinator." That claim was FALSE and the citation was backwards — Fact #14 (and
the 7c task-brief spine item at `.scratch/2026-07-15-full-surface-campaign.md:788-792`) both
say the OPPOSITE: default to redact defensively on a schema-undocumented read (the Wave 5b
influxdb-http lesson — assuming "probably stripped" was wrong once already on this exact
shape of question). The reversal traced to a dispatch-prompt override during this build's
own session, not to either named ground-truth document; the coordinator re-checked the
shipped precedent this fact itself cites — `pbs_metrics.py`'s `influxdb_http_get`/`_list`
strips `token` AT THE READ LAYER, documented there as "a REQUIRED fix for a real,
schema-confirmed leak path... not merely defense-in-depth" — and reinstated the pinned
ruling on adversarial review (Wave 7c review, HIGH-1).

THE RULING, AS SHIPPED: `dns_get`/`ipam_get` STRIP their own family's secret field
(`key`/`token` respectively) AT THE READ LAYER, mirroring `influxdb_http_get`'s exact
mechanism — the field is REMOVED from the returned dict entirely (`_strip_secrets_at_read`,
a plain dict-comprehension exclusion, byte-for-byte the same shape as
`influxdb_http_get`'s own `{k: v for k, v in data.items() if k != "token"}` — NOT masked
with a placeholder; a plain read has no legitimate reason to echo a credential at all). This
is a REQUIRED strip, not merely defensive, precisely because the schema is silent (Fact
#14's own reasoning: silence means assume the worse case, not the better one).
`dns_list`/`ipams_list` are NOT stripped — schema-verified, their declared list-item shape is
a narrow `{dns, type}` / `{ipam, type}` id-summary (unlike `controllers_list`, whose item
shape carries the FULL object, every protocol-conditional field included) — `key`/`token`
structurally cannot appear there per the schema's own declared shape, so a strip would be
dead code; documented here rather than silently omitted or silently added as a no-op.

Plan CAPTURE snapshots (the update/delete plan factories' own `current` preview) and ledger
lines ALSO redact `key`/`token` (to `"[redacted]"`, the established Wave 3a/5b
`_SECRET_KEYS`/`_redact_secrets` idiom, `pbs_notifications.py`/`pbs_metrics.py`) — a second,
independent layer, belt-and-suspenders on top of the read-layer strip, mirroring
`plan_influxdb_http_update`'s own "CAPTURE via an already-stripped read, then redact AGAIN
defensively" idiom exactly (not redundant, given how costly getting this exact question
wrong has already been once, Wave 5b). In practice this needs no special ledger-side
machinery beyond that: `_audited()` never writes a plain read's return value into the ledger
`detail` at all (verified against `server.py`'s own `_audited`/`_record_plan`
implementations — a read call passes no `detail=`), so the ONLY place a captured secret
could reach the ledger is a plan factory's own `Plan.current` (written verbatim into the
"planned" ledger entry by `_record_plan`). ***

*** THE URL-USERINFO RULING (Wave 7c review, HIGH-2 — see fact #11 below): `url` (dns/ipam)
can legally carry embedded HTTP Basic-auth userinfo and the schema neither confirms nor
rules this out — the same genuinely-ambiguous shape `pbs_admin.py`'s `http-proxy` field
carries, decided the same way: secret-SHAPED, not secret-typed. `_redact_url_userinfo`
(a fresh per-module copy of `pbs_admin.py`'s `_redact_http_proxy`, same last-`@`-rsplit
mechanism) masks ONLY an embedded `user[:pass]@` prefix, applied at `dns_get`/`ipam_get`
(the shared read layer) and inside `_redact_secrets` (covering the create/update plan
factories' own fresh-input display, which never goes through a read). ***

Schema-verified facts for THIS build (checked field-by-field, not assumed from the draft):

1. **`type` is IMMUTABLE after creation, uniformly across all three families** — none of
   controller/dns/ipam's PUT (update) param schemas include a `type` key at all (confirmed:
   absent from all three). Create requires it (`optional: 0` on all three POST schemas,
   except ipam's own `type` — also required, no `optional` flag at all meaning required by
   the schema's own convention of marking optional fields explicitly). To change an
   object's type, delete and re-create it — stated in every `_update` docstring.
2. **`digest` exists on UPDATE only, never on CREATE, across all three** — matches the
   universal PVE convention (digest guards updates-to-existing-content). None of the 5 new
   DELETE endpoints accept `digest` either (only `lock-token`) — matches the shipped
   zone/vnet/subnet `_delete` precedent in `network.py` exactly.
3. **`pending`/`running` exist on controllers list+get, but NOWHERE on dns/ipam** — a real,
   load-bearing asymmetry. `GET /cluster/sdn/controllers` and `GET
   /cluster/sdn/controllers/{controller}` both accept optional `pending`/`running` query
   flags (the SAME shape as zone/vnet — this module exposes them on
   `pve_sdn_controller_get` only, mirroring `network.py`'s own choice to expose them on the
   single-object GETs but not the LIST tools: `sdn_zones_list`/`sdn_vnets_list` take no
   params at all despite the schema plausibly supporting filters there too). `GET
   /cluster/sdn/dns[/{dns}]` and `GET /cluster/sdn/ipams[/{ipam}]` carry NO `pending`/
   `running` param anywhere — checked on all 4 methods, zero hits. Not an oversight to
   "fix" — genuinely absent from the schema.
4. **DNS's `reversemaskv6`/`reversev6mask` POST-vs-PUT asymmetry is real, not a typo in this
   module.** CREATE accepts BOTH `reversemaskv6` AND `reversev6mask` (two distinct fields,
   schema-confirmed, both plain optional integers with no stated bound). UPDATE accepts
   ONLY `reversemaskv6` — `reversev6mask` is absent from the PUT param schema entirely.
   Whether this is an upstream oversight or deliberate (perhaps `reversev6mask` is a
   create-only convenience alias PVE derives once and folds into `reversemaskv6`
   thereafter) is not stated anywhere in the schema — documented as-is, not silently
   normalized away or "fixed" by exposing a `reversev6mask` param update can't actually use.
5. **`url`/`key`/`token` carry NO character pattern OR length bound at all** — unlike PBS's
   influxdb-http `url` (Wave 5b, `pbs_metrics.py`), which the live PBS schema types with a
   full copy-verbatim regex, THIS schema's `url` (dns create/update, ipam create/update),
   `key` (dns create/update), and `token` (ipam create/update) are all bare
   `{"type": "string"}` with no `pattern`/`minLength`/`maxLength` anywhere. No URL-shape or
   length constraint is invented here — only a defensive no-control-characters check is
   applied (the established "don't invent a charset/bound the schema doesn't state"
   convention, e.g. `pbs_metrics.py`'s own `bucket`/`organization` fact #9). `key`/`token`
   are the two SECRET fields on this plane (see the ruling above) — stripped at the read
   layer, masked in plans/ledger, forwarded raw on the wire (the mutation must actually
   work). `url`'s own unbounded, schema-silent shape is ALSO the reason it needs the
   separate userinfo-credential treatment in fact #11 below — the same silence that drove
   the `key`/`token` ruling applies to it too.
6. **`fingerprint` (dns + ipam, create+update) carries a REAL schema pattern, copied
   verbatim**: `([A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}` — a standard 32-byte (SHA-256)
   colon-separated hex fingerprint, identical on all 4 methods it appears on. Re-anchored to
   a leading ``^`` + trailing ``\\Z`` per this codebase's convention (blocks embedded-newline smuggling — the
   `network.py _check_iface` / `pbs_metrics.py _URL_RE` precedent), not reformatted.
   **Argued, not silently decided (Wave 7c review LOW-3): `fingerprint` is deliberately
   EXCLUDED from `_SECRET_KEYS` — it is a SHA-256 hash of a PUBLIC certificate, the same
   disclosure category as an SSH host-key fingerprint. Publishing it grants no access and
   reveals no credential; it is a verification aid (lets a caller confirm which certificate
   an integration currently trusts), not a secret. Contrast `key`/`token`, which ARE bearer
   credentials — the two are not the same risk shape despite both being schema-pattern-like
   strings on this plane.**
7. **`section` (ipam only, create+update) is a bare optional integer with no bound stated**
   — passed through with only a defensive int-cast (`ProximoError` on a non-integer), no
   invented floor/ceiling (phpipam's own "section" concept is an opaque numeric id from the
   caller's phpipam instance, not something this module can usefully range-check).
8. **Every mutation on this sub-plane returns `null`** (checked field-by-field: all 3
   controller verbs, all 3 dns verbs, all 3 ipam verbs) — synchronous, callable-outcome
   idiom, `outcome="ok"`, never a UPID (Wave 7 draft Fact #2, re-verified here for this
   specific 9-mutation family, not assumed from the zone/vnet/subnet precedent).
9. **`ipam_status` (`GET /cluster/sdn/ipams/{ipam}/status`) gives ZERO item-shape
   documentation** (`returns: {"type": "array"}`, no `items` key at all) — the most
   undocumented read on the whole SDN plane (Wave 7 draft Fact #13). Combined with the
   domain knowledge that these entries carry guest IP/MAC/hostname (genuinely
   guest-influenced — whatever guest holds that address chose to be there): ADVERSARIAL,
   registered in `taint.ADVERSARIAL_TOOLS`. No plan factory on this module CAPTURES from
   `ipam_status` — the create/update/delete plan factories for `ipam` capture from
   `ipam_get` (the ipam's OWN config object), a structurally different read from the
   address-entries view `ipam_status` exposes; `capture_adversarial_current` is therefore
   not needed in this module (nothing here bypasses `_audited()` to read an
   ADVERSARIAL-classified source inside a plan factory).
10. **Controllers use the GENERIC `options: dict` passthrough idiom (Fact #10) — a
    deliberate, argued DIVERGENCE for dns/ipam.** Fact #10 recommends generic passthrough
    for all three families "since no formal `requires` constraint exists anywhere in this
    schema" — followed exactly for controllers, whose 14 protocol-conditional fields
    (asn/bgp-mode/ebgp/isis-domain/isis-net/loopback/node/nodes/peer-group-name/peers/
    route-map-in/route-map-out/fabric/...) genuinely differ by `type` (bgp vs. evpn vs.
    isis vs. faucet) exactly the way zone's own type-conditional fields do. For dns (8
    total fields, ONE type value today) and ipam (6 total fields, no per-type field
    variation visible anywhere in the schema — all 3 ipam types share the identical
    url/token/section/fingerprint param set), a generic dict would bury the SECRET fields
    (`key`/`token`) inside an opaque bag that a redaction sweep has to scan generically
    rather than name explicitly — this module instead exposes dns/ipam fields as EXPLICIT
    named parameters (mirrors `pbs_metrics.py`'s own `_http_fields`/`_udp_fields` sharing
    idiom exactly: named params for a small, non-type-conditional field set, with the
    secret field named and redacted directly). This is the one place this build diverges
    from Fact #10's letter while following its spirit (server-side validation, no
    hand-enumerated per-protocol branching) — argued here rather than silently decided.
11. **`url` (dns/ipam, create+update+read) can legally carry embedded HTTP Basic-auth
    userinfo** (`scheme://user:pass@host[:port]/path` — valid per standard URL grammar) and
    the schema neither confirms nor rules this out (fact #5: `url` is a bare, unbounded
    string). The SAME genuinely-ambiguous shape as PBS's `http-proxy`
    (`pbs_admin.py`'s module docstring fact #10, fixed Wave 5c/5d) — decided the same way,
    for the same reason: treat `url` as secret-SHAPED, not secret-typed. `_redact_url_userinfo`
    (a fresh per-module copy of `pbs_admin.py`'s `_redact_http_proxy`, not cross-imported)
    masks ONLY an embedded `user[:pass]@` prefix (last-`@`-rsplit semantics, IPv6-host-safe —
    copied byte-for-byte reasoning: RFC 3986 authority grammar means a host never legally
    contains `@`, so everything up to the LAST `@` is userinfo, however many `@`s the
    password itself carries), leaving `host[:port]` visible — full redaction would make the
    read tool useless for verifying which endpoint is actually configured. Applied at the
    single shared `dns_get`/`ipam_get` read-layer functions (used by BOTH the read tool and
    the update/delete plan factories' CAPTURE) and inside `_redact_secrets` (covering the
    create/update plan factories' own fresh-input `kw` display, which never goes through a
    read) — the same two-surface coverage the `key`/`token` ruling above uses, adapted for a
    partial rather than whole-value mask. Likelihood is lower than `http-proxy`'s case (none
    of PowerDNS/netbox/phpipam's own conventional auth mechanisms use URL userinfo — that's
    presumably why `key`/`token` exist as separate fields at all), which tempers likelihood,
    not risk shape: the field is still unbounded, caller-supplied, and one paste away from
    carrying a credential into a tamper-evident ledger with no way to scrub it after the fact.

Validators: `controller`/`dns`/`ipam` ids reuse `network.py`'s existing `_check_sdn_id`
(alnum/_/- up to 64 chars) rather than a fresh, narrower validator against each family's own
stricter schema pattern (controller: `[a-zA-Z][a-zA-Z0-9_-]*[a-zA-Z0-9]`, 2-64 chars; dns/
ipam: `[a-zA-Z][a-zA-Z0-9]*[a-zA-Z0-9]`, minLength 2, no stated maxLength) — every string
each family's OWN pattern accepts is ALSO accepted by `_check_sdn_id` (a strict superset for
all practical PVE-length names), the same "the existing looser validator already accepts
every legal input, PVE is the real gate" reasoning Wave 7a's own adversarial review Finding
1 established (killing a needless duplicate validator) and Wave 7b's `sdn_firewall.py`
followed for vnet/zone. `delete` (settings-to-unset) reuses `network.py`'s `_sdn_csv` (a
pure list/str -> comma-string helper, no object-specific reserved-key logic, safe to share).

Taint: controllers/dns/ipams list+get are REVIEWED_TRUSTED (operator-authored SDN config,
same channel as the already-REVIEWED_TRUSTED zone/vnet/subnet/dry-run/zone-status family in
`network.py`) — including `dns_get`/`ipam_get` despite their schema-undocumented shape: the
CONTENT itself (a DNS integration's url/key or an IPAM integration's url/token/section) is
operator-typed configuration, not guest/peer-authored bytes; the ruling above is about
secret HANDLING (strip `key`/`token` at the read layer, mask `url` userinfo, redact again
on capture/ledger), a separate concern from taint's guest/external-content classification —
REVIEWED_TRUSTED describes the CONTENT's authorship, not whether a field on it happens to be
handled as a secret. `ipam_status` is the sole ADVERSARIAL tool in this module (fact #9).
Mutations all return `null` (fact #8) — no content channel to classify either way, all
REVIEWED_TRUSTED regardless of the underlying object's own credential-bearing nature (the
existing `pbs_s3_client_create`/`pbs_metrics_influxdb_http_create` precedent: a
credential-bearing PLANE still classifies its mutations REVIEWED_TRUSTED on the taint axis —
secret-handling and content-trust are orthogonal concerns in this codebase's own model).

Risk ratings (coordinator ruling, `.scratch/2026-07-15-full-surface-campaign.md` § Wave 7
ruling block + `.scratch/sdd/wave-7-draft-decomposition.md` §3): create/update = LOW
(pending, inert until apply — mirrors zone/vnet/subnet create/update exactly); delete =
MEDIUM (staging a removal an apply would enact). Referential-integrity claims ("PVE refuses
to delete a controller/dns/ipam still referenced by a zone") are asserted BY ANALOGY ONLY,
Smoke-confirm labeled per the coordinator's ruling #4 — this schema's own terse generic
delete descriptions ("Delete sdn controller object configuration.", etc.) do not themselves
state a refusal-on-reference behavior the way the zone/vnet precedent's sentence was
independently verified; the analogy is plausible (zones reference controllers/dns/ipams by
name) but not re-derived from THIS schema, so every delete docstring/plan says so honestly.
"""

from __future__ import annotations

import re

from ._validate import redact_secrets
from .backends import ProximoError
from .network import _check_sdn_id, _sdn_csv, _sdn_get_query
from .planning import RISK_LOW, RISK_MEDIUM, Plan

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

_VALID_CONTROLLER_TYPES = frozenset({"bgp", "evpn", "faucet", "isis"})
_VALID_DNS_TYPES = frozenset({"powerdns"})
_VALID_IPAM_TYPES = frozenset({"netbox", "phpipam", "pve"})

# Complete no-control-characters class — the only defensive check applied to url/key/token
# (module docstring fact #5: this schema states NO pattern/length bound for any of the
# three). Mirrors pbs_metrics.py's own `_NO_CONTROL_RE` (a fresh, per-module copy — not
# cross-imported from a PBS module into a PVE one).
_NO_CONTROL_RE = re.compile(r"^[^\x00-\x1f\x7f]*\Z")

# Cert-fingerprint pattern, copied VERBATIM from the live schema (both dns and ipam share
# it byte-for-byte), re-anchored to \Z per this codebase's convention (module docstring
# fact #6).
_FINGERPRINT_RE = re.compile(r"^(?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}\Z")


def _check_controller_type(value: str) -> str:
    t = str(value).strip()
    if t not in _VALID_CONTROLLER_TYPES:
        raise ProximoError(
            f"invalid SDN controller type: {value!r} (expected one of "
            f"{sorted(_VALID_CONTROLLER_TYPES)})"
        )
    return t


def _check_dns_type(value: str) -> str:
    t = str(value).strip()
    if t not in _VALID_DNS_TYPES:
        raise ProximoError(
            f"invalid SDN dns type: {value!r} (expected one of {sorted(_VALID_DNS_TYPES)})"
        )
    return t


def _check_ipam_type(value: str) -> str:
    t = str(value).strip()
    if t not in _VALID_IPAM_TYPES:
        raise ProximoError(
            f"invalid SDN ipam type: {value!r} (expected one of {sorted(_VALID_IPAM_TYPES)})"
        )
    return t


def _check_no_control(value: str, field: str) -> str:
    s = str(value)
    if not _NO_CONTROL_RE.match(s):
        raise ProximoError(f"invalid {field}: contains control characters")
    return s


def _check_fingerprint(value: str) -> str:
    s = str(value)
    if not _FINGERPRINT_RE.match(s):
        raise ProximoError(
            f"invalid fingerprint: {value!r} (expected 32 colon-separated hex byte pairs, "
            "e.g. a SHA-256 certificate fingerprint)"
        )
    return s


def _check_int(value, field: str) -> int:
    """Bare int cast, no invented bound (module docstring facts #3/#7 — reversemaskv6/
    reversev6mask/ttl/section all carry NO stated bound in the schema)."""
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid {field}: {value!r} (must be an integer)") from exc


# Reserved keys for the controller `options` bag (generic passthrough, module docstring
# fact #10) — a FRESH set, not network.py's `_SDN_RESERVED`: the identity field here is
# "controller", not "zone"/"vnet"/"subnet", and reusing the zone-shaped reserved set would
# fail to block a caller from smuggling a colliding "controller" key inside options (which
# would silently override the explicit positional id in the wire payload, since options is
# spread AFTER the explicit fields in the outgoing dict).
_CONTROLLER_RESERVED = frozenset({"controller", "type", "delete", "digest", "lock-token", "lock_token"})


def _check_controller_options(options: dict | None) -> None:
    bad = _CONTROLLER_RESERVED & set(options or {})
    if bad:
        raise ProximoError(
            f"reserved key(s) {sorted(bad)} cannot be passed inside options — use the "
            "dedicated controller/type/delete/digest/lock_token parameters instead"
        )


# Credential-shaped fields on this plane (the ruling above): dns `key`, ipam `token`.
_SECRET_KEYS = frozenset({"key", "token"})

# HTTP Basic-auth userinfo split for `url` (module docstring fact #11) — copied from
# pbs_admin.py's `_redact_http_proxy` idiom (Wave 5c/5d precedent), a fresh per-module copy,
# not cross-imported. The userinfo/host split is NOT done by a single greedy regex: matching
# to the FIRST '@' leaks the password TAIL when the password itself contains a literal '@'
# ('user:p@ss@host' -> '[redacted]@ss@host'). Strip an optional scheme prefix, then split the
# remaining authority on the LAST '@' (`str.rsplit("@", 1)`) — RFC 3986 authority semantics:
# the host part never legally contains '@' (IPv6 hosts are bracketed, no '@' inside), so
# everything before the last '@' is userinfo, however many '@'s the password carries.
_URL_SCHEME_RE = re.compile(r"^(?P<prefix>(?:[a-zA-Z][a-zA-Z0-9+.\-]*://)?)(?P<authority>.*)\Z", re.DOTALL)


def _redact_url_userinfo(value: str | None) -> str | None:
    """Defensively mask an embedded HTTP Basic-auth userinfo credential in `url`
    (user[:pass]@host[:port]) before the value can enter a Plan/ledger surface or a plain
    read's own return (module docstring fact #11). host[:port] stays visible — the
    operationally useful part of the field. A value with no '@' at all passes through
    unchanged. Mirrors `pbs_admin.py`'s `_redact_http_proxy` EXACTLY (last-`@` rsplit
    semantics — see the module-level comment on `_URL_SCHEME_RE` above)."""
    if value is None:
        return None
    s = str(value)
    m = _URL_SCHEME_RE.match(s)
    if m is None:  # unreachable — both groups are optional/greedy — but fail SAFE if it ever isn't
        return "[redacted]"
    prefix, authority = m.group("prefix"), m.group("authority")
    if "@" in authority:
        _userinfo, host = authority.rsplit("@", 1)
        return f"{prefix}[redacted]@{host}"
    return s


def _redact_secrets(d: dict) -> dict:
    """Mask credential-shaped fields before they enter a plan string or Plan.current. `key`/
    `token` are the confirmed-secret fields (THE SECRET RULING above) — whole-value swap to
    `"[redacted]"` via the shared `_validate.redact_secrets` mechanic over this plane's own
    `_SECRET_KEYS`. This module keeps a thin wrapper (the A11 consolidation's one divergent
    redactor) because `url` is additionally masked for an embedded HTTP Basic-auth userinfo
    credential ONLY (module docstring fact #11, THE URL-USERINFO RULING) — mirrors
    `pbs_admin.py`'s `_redact_http_proxy` idiom for the identical secret-SHAPED-not-
    secret-typed risk: host[:port] stays visible, only user[:pass]@ is masked. This is the
    ONLY place `url` masking happens for a create/update plan's own fresh caller-supplied
    value (which never goes through a read) — `dns_get`/`ipam_get`'s own read-layer strip
    (`_strip_secrets_at_read`) handles the CAPTURED-current side independently."""
    out = redact_secrets(d, _SECRET_KEYS)
    if "url" in out:
        out["url"] = _redact_url_userinfo(out["url"])
    return out


def _strip_secrets_at_read(data: dict, secret_field: str) -> dict:
    """Read-layer strip for `dns_get`/`ipam_get` — mirrors `pbs_metrics.py`'s
    `influxdb_http_get`/`influxdb_http_list` mechanism EXACTLY: `secret_field` (`"key"` for
    dns, `"token"` for ipam) is REMOVED from the dict entirely via a plain dict-comprehension
    exclusion (`{k: v for k, v in data.items() if k != secret_field}`), NOT masked with a
    placeholder — a plain read has no legitimate reason to echo a credential at all, unlike
    the Plan/ledger display text `_redact_secrets` protects, where seeing THAT a field
    existed and was masked is itself useful. This is THE REINSTATED RULING (see module
    docstring's strike-and-correct note) — a REQUIRED strip, not merely defensive, given the
    schema's silence on whether the secret echoes back (Fact #14). `url` (if present) is
    additionally masked for an embedded HTTP Basic-auth userinfo credential via
    `_redact_url_userinfo` (module docstring fact #11) — the single shared masking point also
    used, via `_redact_secrets`, by the update/delete plan factories' CAPTURE (belt-and-
    suspenders, mirrors `pbs_admin.py`'s `node_config_get` "one masking point, not two"
    idiom, adapted here to two independent layers for defense-in-depth on the `key`/`token`
    side specifically)."""
    out = {k: v for k, v in data.items() if k != secret_field}
    if "url" in out:
        out["url"] = _redact_url_userinfo(out["url"])
    return out


def _pending_blast(lead: str) -> list[str]:
    """Same shape as network.py's `_sdn_pending_blast`, a fresh per-family copy (the exact
    wording differs by object type)."""
    return [
        lead,
        "INERT until pve_sdn_apply (a separate RISK_HIGH step) — no live network effect yet",
        "no NARROW undo at config level: revert by deleting the pending object before apply, OR "
        "call pve_sdn_rollback to discard EVERY pending SDN edit cluster-wide (broad, "
        "all-or-nothing, but a REAL undo primitive)",
    ]


def _kv_parts(fields: dict) -> list[str]:
    """Sorted 'k=v' parts, secrets ALREADY redacted by the caller before this is invoked —
    mirrors network.py's own `_sdn_kv_parts` shape."""
    return [f"{k}={fields[k]}" for k in sorted(fields)]


# ===========================================================================
# CONTROLLERS
# ===========================================================================

def controllers_list(api, controller_type: str | None = None) -> list[dict]:
    """List SDN controllers (cluster-scoped). GET /cluster/sdn/controllers?type=.

    Optional `controller_type` filters to one type (bgp/evpn/faucet/isis) — matches the
    same enum as create. `pending`/`running` exist on this endpoint's schema (module
    docstring fact #3) but, mirroring sdn_zones_list/sdn_vnets_list's own scope choice, are
    not exposed here — use pve_sdn_controller_get for the pending/running single-object view.
    REVIEWED_TRUSTED (operator-authored SDN config)."""
    path = "/cluster/sdn/controllers"
    if controller_type is not None:
        controller_type = _check_controller_type(controller_type)
        path = f"{path}?type={controller_type}"
    return api._get(path) or []


def controller_get(api, controller: str, pending: bool | None = None,
                    running: bool | None = None) -> dict:
    """Read a single SDN controller's configuration. GET /cluster/sdn/controllers/{controller}.

    Optional pending=True nests staged-but-unapplied fields under a `pending` key;
    running=True asks for the currently-APPLIED config instead of the default staged-merged
    view (module docstring fact #3 — this endpoint DOES carry pending/running, unlike
    dns_get/ipam_get). REVIEWED_TRUSTED."""
    c = _check_sdn_id(controller, "controller")
    return api._get(f"/cluster/sdn/controllers/{c}{_sdn_get_query(pending, running)}") or {}


def controller_create(api, controller: str, controller_type: str, options: dict | None = None,
                       lock_token: str | None = None) -> object:
    """Create an SDN controller (PENDING). POST /cluster/sdn/controllers {type, controller, ...}.

    `controller_type` is bgp/evpn/faucet/isis; `options` carries the protocol-conditional
    fields (asn, peers, isis-domain, fabric, ...) — generic passthrough (module docstring
    fact #10), PVE validates per type server-side. Inert until pve_sdn_apply."""
    c = _check_sdn_id(controller, "controller")
    t = _check_controller_type(controller_type)
    _check_controller_options(options)
    data: dict = {"type": t, "controller": c, **(options or {})}
    if lock_token is not None:
        data["lock-token"] = lock_token
    return api._post("/cluster/sdn/controllers", data)


def controller_update(api, controller: str, options: dict | None = None,
                       delete: list | str | None = None, digest: str | None = None,
                       lock_token: str | None = None) -> object:
    """Update an SDN controller (PENDING). PUT /cluster/sdn/controllers/{controller}.

    `type` is IMMUTABLE (module docstring fact #1 — not accepted on this endpoint at all;
    delete and re-create to change it). Requires >=1 set/unset."""
    c = _check_sdn_id(controller, "controller")
    _check_controller_options(options)
    if not options and not delete:
        raise ProximoError("controller_update requires at least one option to set or delete")
    data: dict = dict(options or {})
    if delete:
        data["delete"] = _sdn_csv(delete)
    if digest is not None:
        data["digest"] = digest
    if lock_token is not None:
        data["lock-token"] = lock_token
    return api._put(f"/cluster/sdn/controllers/{c}", data)


def controller_delete(api, controller: str, lock_token: str | None = None) -> object:
    """Delete an SDN controller (PENDING). DELETE /cluster/sdn/controllers/{controller}.

    No `digest` on this endpoint (module docstring fact #2). Referential-integrity refusal
    (a zone/evpn-controller reference) is asserted BY ANALOGY only — Smoke-confirm, not
    re-derived from this schema's own terse delete description."""
    c = _check_sdn_id(controller, "controller")
    params: dict = {}
    if lock_token is not None:
        params["lock-token"] = lock_token
    return api._delete(f"/cluster/sdn/controllers/{c}", params)


# ===========================================================================
# DNS
# ===========================================================================

def dns_list(api, dns_type: str | None = None) -> list[dict]:
    """List SDN dns integrations (cluster-scoped). GET /cluster/sdn/dns?type=.

    Optional `dns_type` filters (only "powerdns" exists today). No pending/running on this
    endpoint at all (module docstring fact #3). NO read-layer strip is applied here — the
    schema's declared list-item shape is a narrow `{dns, type}` id-summary only
    (schema-verified: zero other properties, unlike `controllers_list`'s own full-object item
    shape) — `key` structurally cannot appear on this endpoint's documented shape, so a strip
    would be dead code (see module docstring's reinstated secret ruling). REVIEWED_TRUSTED."""
    path = "/cluster/sdn/dns"
    if dns_type is not None:
        dns_type = _check_dns_type(dns_type)
        path = f"{path}?type={dns_type}"
    return api._get(path) or []


def dns_get(api, dns: str) -> dict:
    """Read a single SDN dns integration's configuration. GET /cluster/sdn/dns/{dns}.

    Schema declares a bare `{"type": "object"}` return — undocumented whether `key` (the
    secret) is echoed back. RULING, REINSTATED (see module docstring's strike-and-correct
    note): a schema-undocumented read defaults to redact defensively (the Wave 5b lesson) —
    `key` is REMOVED here at the READ layer (`_strip_secrets_at_read`), mirroring
    `pbs_metrics.py`'s `influxdb_http_get` mechanism exactly; a required strip, not merely
    defensive. `url` is separately masked for an embedded HTTP Basic-auth userinfo credential
    (module docstring fact #11). REVIEWED_TRUSTED (the content itself is operator-typed
    DNS-integration config, not guest/peer-authored bytes — a separate axis from the
    secret-handling ruling)."""
    d = _check_sdn_id(dns, "dns")
    data = api._get(f"/cluster/sdn/dns/{d}") or {}
    return _strip_secrets_at_read(data, "key")


def dns_create(api, dns: str, dns_type: str, url: str, key: str,
                fingerprint: str | None = None, reversemaskv6: int | None = None,
                reversev6mask: int | None = None, dns_ttl: int | None = None,
                lock_token: str | None = None) -> object:
    """Create an SDN dns integration (PENDING). POST /cluster/sdn/dns
    {type, dns, url, key, ...}.

    `url`/`key` are REQUIRED (schema `optional: 0`) — `key` is a SECRET, forwarded raw here
    (the create must actually work) but never recorded to the ledger — see
    plan_dns_create's redaction. `dns_type` today has one legal value ("powerdns") but is
    still explicit + validated (Fact #10's "today, more later" framing). `dns_ttl` is named
    with a `dns_` prefix (not the schema's bare `ttl`) because this codebase reserves the
    bare parameter name `ttl` for the out-of-band arm-lease mechanism
    (`test_lease.py::test_no_tool_accepts_a_ttl_kwarg`) — the wire key stays PVE's own
    `ttl`, only the Python parameter name differs (mirrors `dns_type`'s own wire-key-vs-
    param-name split for `type`). Inert until pve_sdn_apply."""
    d = _check_sdn_id(dns, "dns")
    t = _check_dns_type(dns_type)
    data: dict = {
        "type": t, "dns": d,
        "url": _check_no_control(url, "url"),
        "key": _check_no_control(key, "key"),
    }
    if fingerprint is not None:
        data["fingerprint"] = _check_fingerprint(fingerprint)
    if reversemaskv6 is not None:
        data["reversemaskv6"] = _check_int(reversemaskv6, "reversemaskv6")
    if reversev6mask is not None:
        data["reversev6mask"] = _check_int(reversev6mask, "reversev6mask")
    if dns_ttl is not None:
        data["ttl"] = _check_int(dns_ttl, "dns_ttl")
    if lock_token is not None:
        data["lock-token"] = lock_token
    return api._post("/cluster/sdn/dns", data)


def dns_update(api, dns: str, url: str | None = None, key: str | None = None,
               fingerprint: str | None = None, reversemaskv6: int | None = None,
               dns_ttl: int | None = None, delete: list | str | None = None,
               digest: str | None = None, lock_token: str | None = None) -> object:
    """Update an SDN dns integration (PENDING). PUT /cluster/sdn/dns/{dns}.

    `type` is IMMUTABLE (fact #1). `reversev6mask` does NOT exist on this endpoint at all —
    only `reversemaskv6` (module docstring fact #4, a real schema asymmetry, not a typo).
    `key` (if given) is forwarded raw but never recorded to the ledger. `dns_ttl` maps to
    the wire key `ttl` (see dns_create's docstring for why the Python param isn't bare
    `ttl`). Requires >=1 set/unset."""
    d = _check_sdn_id(dns, "dns")
    data: dict = {}
    if url is not None:
        data["url"] = _check_no_control(url, "url")
    if key is not None:
        data["key"] = _check_no_control(key, "key")
    if fingerprint is not None:
        data["fingerprint"] = _check_fingerprint(fingerprint)
    if reversemaskv6 is not None:
        data["reversemaskv6"] = _check_int(reversemaskv6, "reversemaskv6")
    if dns_ttl is not None:
        data["ttl"] = _check_int(dns_ttl, "dns_ttl")
    if not data and not delete:
        raise ProximoError("dns_update requires at least one field to set or delete")
    if delete:
        data["delete"] = _sdn_csv(delete)
    if digest is not None:
        data["digest"] = digest
    if lock_token is not None:
        data["lock-token"] = lock_token
    return api._put(f"/cluster/sdn/dns/{d}", data)


def dns_delete(api, dns: str, lock_token: str | None = None) -> object:
    """Delete an SDN dns integration (PENDING). DELETE /cluster/sdn/dns/{dns}.

    No `digest` on this endpoint (fact #2). Referential-integrity refusal asserted BY
    ANALOGY only — Smoke-confirm."""
    d = _check_sdn_id(dns, "dns")
    params: dict = {}
    if lock_token is not None:
        params["lock-token"] = lock_token
    return api._delete(f"/cluster/sdn/dns/{d}", params)


# ===========================================================================
# IPAMs
# ===========================================================================

def ipams_list(api, ipam_type: str | None = None) -> list[dict]:
    """List SDN ipam integrations (cluster-scoped). GET /cluster/sdn/ipams?type=.

    Optional `ipam_type` filters (netbox/phpipam/pve). No pending/running on this endpoint
    at all (module docstring fact #3). NO read-layer strip is applied here — the schema's
    declared list-item shape is a narrow `{ipam, type}` id-summary only (schema-verified:
    zero other properties, unlike `controllers_list`'s own full-object item shape) — `token`
    structurally cannot appear on this endpoint's documented shape, so a strip would be dead
    code (see module docstring's reinstated secret ruling). REVIEWED_TRUSTED."""
    path = "/cluster/sdn/ipams"
    if ipam_type is not None:
        ipam_type = _check_ipam_type(ipam_type)
        path = f"{path}?type={ipam_type}"
    return api._get(path) or []


def ipam_get(api, ipam: str) -> dict:
    """Read a single SDN ipam integration's configuration. GET /cluster/sdn/ipams/{ipam}.

    Schema declares a bare `{"type": "object"}` return — undocumented whether `token` (the
    secret) is echoed back. RULING, REINSTATED (see module docstring's strike-and-correct
    note): a schema-undocumented read defaults to redact defensively (the Wave 5b lesson) —
    `token` is REMOVED here at the READ layer (`_strip_secrets_at_read`), mirroring
    `pbs_metrics.py`'s `influxdb_http_get` mechanism exactly; a required strip, not merely
    defensive. `url` is separately masked for an embedded HTTP Basic-auth userinfo credential
    (module docstring fact #11). REVIEWED_TRUSTED (operator-typed IPAM-integration config —
    a separate axis from the secret-handling ruling)."""
    i = _check_sdn_id(ipam, "ipam")
    data = api._get(f"/cluster/sdn/ipams/{i}") or {}
    return _strip_secrets_at_read(data, "token")


def ipam_status(api, ipam: str) -> list:
    """List the address entries a PVE-managed IPAM is currently tracking.
    GET /cluster/sdn/ipams/{ipam}/status.

    Schema gives ZERO item-shape documentation (`returns: {"type": "array"}`, no `items`
    key at all — module docstring fact #9, the most undocumented read on the whole SDN
    plane). ADVERSARIAL: entries carry guest IP/MAC/hostname — genuinely guest-influenced
    content (whatever guest holds that address chose to be there)."""
    i = _check_sdn_id(ipam, "ipam")
    return api._get(f"/cluster/sdn/ipams/{i}/status") or []


def ipam_create(api, ipam: str, ipam_type: str, url: str | None = None,
                 token: str | None = None, section: int | None = None,
                 fingerprint: str | None = None, lock_token: str | None = None) -> object:
    """Create an SDN ipam integration (PENDING). POST /cluster/sdn/ipams {type, ipam, ...}.

    `ipam_type` is netbox/phpipam/pve; all field params (url/token/section/fingerprint) are
    OPTIONAL on create (unlike dns's required url/key) and shared identically across all 3
    types (no per-type field variation in this schema — module docstring fact #10). `token`
    is a SECRET, forwarded raw here but never recorded to the ledger — see
    plan_ipam_create's redaction. Inert until pve_sdn_apply."""
    i = _check_sdn_id(ipam, "ipam")
    t = _check_ipam_type(ipam_type)
    data: dict = {"type": t, "ipam": i}
    if url is not None:
        data["url"] = _check_no_control(url, "url")
    if token is not None:
        data["token"] = _check_no_control(token, "token")
    if section is not None:
        data["section"] = _check_int(section, "section")
    if fingerprint is not None:
        data["fingerprint"] = _check_fingerprint(fingerprint)
    if lock_token is not None:
        data["lock-token"] = lock_token
    return api._post("/cluster/sdn/ipams", data)


def ipam_update(api, ipam: str, url: str | None = None, token: str | None = None,
                 section: int | None = None, fingerprint: str | None = None,
                 delete: list | str | None = None, digest: str | None = None,
                 lock_token: str | None = None) -> object:
    """Update an SDN ipam integration (PENDING). PUT /cluster/sdn/ipams/{ipam}.

    `type` is IMMUTABLE (fact #1). `token` (if given) is forwarded raw but never recorded
    to the ledger. Requires >=1 set/unset."""
    i = _check_sdn_id(ipam, "ipam")
    data: dict = {}
    if url is not None:
        data["url"] = _check_no_control(url, "url")
    if token is not None:
        data["token"] = _check_no_control(token, "token")
    if section is not None:
        data["section"] = _check_int(section, "section")
    if fingerprint is not None:
        data["fingerprint"] = _check_fingerprint(fingerprint)
    if not data and not delete:
        raise ProximoError("ipam_update requires at least one field to set or delete")
    if delete:
        data["delete"] = _sdn_csv(delete)
    if digest is not None:
        data["digest"] = digest
    if lock_token is not None:
        data["lock-token"] = lock_token
    return api._put(f"/cluster/sdn/ipams/{i}", data)


def ipam_delete(api, ipam: str, lock_token: str | None = None) -> object:
    """Delete an SDN ipam integration (PENDING). DELETE /cluster/sdn/ipams/{ipam}.

    No `digest` on this endpoint (fact #2). Referential-integrity refusal asserted BY
    ANALOGY only — Smoke-confirm."""
    i = _check_sdn_id(ipam, "ipam")
    params: dict = {}
    if lock_token is not None:
        params["lock-token"] = lock_token
    return api._delete(f"/cluster/sdn/ipams/{i}", params)


# ===========================================================================
# Plan factories — controllers
# ===========================================================================

def plan_controller_create(controller: str, controller_type: str,
                            options: dict | None = None) -> Plan:
    """Preview creating an SDN controller. PURE. RISK_LOW — pending, inert until apply."""
    c = _check_sdn_id(controller, "controller")
    t = _check_controller_type(controller_type)
    _check_controller_options(options)
    lead = f"stages a PENDING SDN controller '{c}' (type={t})"
    if options:
        lead += f", options: {', '.join(_kv_parts(options))}"
    return Plan(
        action="pve_sdn_controller_create", target=f"sdn/controllers/{c}",
        change=f"create SDN {t} controller '{c}' (pending)", current={},
        blast_radius=_pending_blast(lead),
        risk=RISK_LOW, risk_reasons=["SDN object create is a pending config change — inert until apply"],
    )


def plan_controller_update(controller: str, options: dict | None = None,
                            delete: list | str | None = None) -> Plan:
    """Preview updating an SDN controller. PURE. RISK_LOW — pending, inert until apply."""
    c = _check_sdn_id(controller, "controller")
    _check_controller_options(options)
    if not options and not delete:
        raise ProximoError("controller_update requires at least one option to set or delete")
    del_keys = delete if isinstance(delete, list) else ([delete] if delete else [])
    parts = _kv_parts(options or {}) + [f"-{k}" for k in del_keys]
    return Plan(
        action="pve_sdn_controller_update", target=f"sdn/controllers/{c}",
        change=f"update SDN controller '{c}' (pending): {', '.join(parts) or '(none)'}",
        current={},
        blast_radius=_pending_blast(f"stages a PENDING update to SDN controller '{c}'"),
        risk=RISK_LOW, risk_reasons=["SDN object update is a pending config change — inert until apply"],
    )


def plan_controller_delete(api, controller: str) -> Plan:
    """Preview deleting an SDN controller. Reads current controllers (one safe read).
    RISK_MEDIUM — staging a removal an apply would enact."""
    c = _check_sdn_id(controller, "controller")
    current: dict = {}
    read_failed = False
    try:
        current = next((x for x in (controllers_list(api) or []) if x.get("controller") == c), {})
    except Exception:
        current = {}
        read_failed = True
    blast = [
        f"stages REMOVAL of SDN controller '{c}' (pending)",
        "takes effect on pve_sdn_apply; if the controller is live-applied, applying removes it",
        "referential-integrity refusal (a zone/EVPN-controller reference) is asserted BY ANALOGY "
        "to the zone/vnet precedent, NOT independently confirmed against this endpoint's own "
        "schema — Smoke-confirm before relying on it",
        "no NARROW undo at config level: re-create the controller to revert, OR call "
        "pve_sdn_rollback to discard EVERY pending SDN edit cluster-wide",
    ]
    if read_failed:
        blast.append("could not read the current SDN controller config — prior value UNKNOWN")
    return Plan(
        action="pve_sdn_controller_delete", target=f"sdn/controllers/{c}",
        change=f"delete SDN controller '{c}' (pending)", current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["staging removal of an SDN controller — an apply would disrupt routing that depends on it"],
        complete=not read_failed,
    )


# ===========================================================================
# Plan factories — dns
# ===========================================================================

def plan_dns_create(dns: str, dns_type: str, url: str, key: str,
                     fingerprint: str | None = None, reversemaskv6: int | None = None,
                     reversev6mask: int | None = None, dns_ttl: int | None = None) -> Plan:
    """Preview creating an SDN dns integration. PURE. RISK_LOW — pending, inert until apply.
    SECRET CONTRACT: `key` is masked to '[redacted]' before entering the Plan; `url` (if it
    embeds HTTP Basic-auth userinfo) has only the user[:pass]@ portion masked, host[:port]
    stays visible (module docstring fact #11, `_redact_secrets`)."""
    d = _check_sdn_id(dns, "dns")
    t = _check_dns_type(dns_type)
    _check_no_control(url, "url")
    _check_no_control(key, "key")
    extra: dict = {}
    if fingerprint is not None:
        extra["fingerprint"] = fingerprint
    if reversemaskv6 is not None:
        extra["reversemaskv6"] = reversemaskv6
    if reversev6mask is not None:
        extra["reversev6mask"] = reversev6mask
    if dns_ttl is not None:
        extra["ttl"] = dns_ttl
    kw = {"dns": d, "type": t, "url": url, "key": key, **extra}
    lead = f"stages a PENDING SDN dns integration '{d}' (type={t}): {', '.join(_kv_parts(_redact_secrets(kw)))}"
    return Plan(
        action="pve_sdn_dns_create", target=f"sdn/dns/{d}",
        change=f"create SDN dns integration '{d}' (pending)", current={},
        blast_radius=_pending_blast(lead),
        risk=RISK_LOW, risk_reasons=["SDN object create is a pending config change — inert until apply"],
        note="key is UNCONDITIONALLY redacted — only \"[redacted]\" appears in the plan and the audit ledger.",
    )


def plan_dns_update(api, dns: str, url: str | None = None, key: str | None = None,
                     fingerprint: str | None = None, reversemaskv6: int | None = None,
                     dns_ttl: int | None = None, delete: list | str | None = None) -> Plan:
    """Preview updating an SDN dns integration. CAPTURE: reads current config via dns_get
    (already `key`-stripped and `url`-userinfo-masked at the read layer — module docstring's
    reinstated ruling) and redacts it AGAIN defensively BEFORE it enters Plan.current — the
    defense-in-depth idiom (mirrors plan_influxdb_http_update's own CAPTURE-then-redact
    shape). A fresh `key`/`url` passed as a NEW value here (not captured from a read) is
    masked the same way via `_redact_secrets` on the display `kw`."""
    d = _check_sdn_id(dns, "dns")
    kw: dict = {}
    if url is not None:
        _check_no_control(url, "url")
        kw["url"] = url
    if key is not None:
        _check_no_control(key, "key")
        kw["key"] = key
    if fingerprint is not None:
        kw["fingerprint"] = fingerprint
    if reversemaskv6 is not None:
        kw["reversemaskv6"] = reversemaskv6
    if dns_ttl is not None:
        kw["ttl"] = dns_ttl
    if not kw and not delete:
        raise ProximoError("dns_update requires at least one field to set or delete")

    current: dict = {}
    read_failed = False
    try:
        current = _redact_secrets(dns_get(api, d))
    except Exception:
        read_failed = True

    del_keys = delete if isinstance(delete, list) else ([delete] if delete else [])
    parts = _kv_parts(_redact_secrets(kw)) + [f"-{k}" for k in del_keys]
    blast = _pending_blast(f"stages a PENDING update to SDN dns integration '{d}'")
    if read_failed:
        blast.append("could not read current dns config — prior value UNKNOWN")
    return Plan(
        action="pve_sdn_dns_update", target=f"sdn/dns/{d}",
        change=f"update SDN dns integration '{d}' (pending): {', '.join(parts) or '(none)'}",
        current=current,
        blast_radius=blast,
        risk=RISK_LOW, risk_reasons=["SDN object update is a pending config change — inert until apply"],
        complete=not read_failed,
        note="key is UNCONDITIONALLY redacted — only \"[redacted]\" appears in the plan and the audit ledger.",
    )


def plan_dns_delete(api, dns: str) -> Plan:
    """Preview deleting an SDN dns integration. CAPTURE: reads current config (redacted
    before it enters Plan.current). RISK_MEDIUM."""
    d = _check_sdn_id(dns, "dns")
    current: dict = {}
    read_failed = False
    try:
        current = _redact_secrets(dns_get(api, d))
    except Exception:
        read_failed = True
    blast = [
        f"stages REMOVAL of SDN dns integration '{d}' (pending)",
        "takes effect on pve_sdn_apply; if applied, removes the dns integration",
        "referential-integrity refusal is asserted BY ANALOGY only — Smoke-confirm",
        "no NARROW undo at config level: re-create the dns integration to revert (the key must "
        "be re-supplied — it is never captured/displayed here), OR call pve_sdn_rollback",
    ]
    if read_failed:
        blast.append("could not read the current dns config — prior value UNKNOWN")
    return Plan(
        action="pve_sdn_dns_delete", target=f"sdn/dns/{d}",
        change=f"delete SDN dns integration '{d}' (pending)", current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["staging removal of an SDN dns integration — an apply would disrupt DNS "
                      "registration relying on it"],
        complete=not read_failed,
        note="key (if present in current) is UNCONDITIONALLY redacted.",
    )


# ===========================================================================
# Plan factories — ipams
# ===========================================================================

def plan_ipam_create(ipam: str, ipam_type: str, url: str | None = None,
                      token: str | None = None, section: int | None = None,
                      fingerprint: str | None = None) -> Plan:
    """Preview creating an SDN ipam integration. PURE. RISK_LOW — pending, inert until apply.
    SECRET CONTRACT: `token` is masked to '[redacted]' before entering the Plan; `url` (if it
    embeds HTTP Basic-auth userinfo) has only the user[:pass]@ portion masked, host[:port]
    stays visible (module docstring fact #11, `_redact_secrets`)."""
    i = _check_sdn_id(ipam, "ipam")
    t = _check_ipam_type(ipam_type)
    kw: dict = {"ipam": i, "type": t}
    if url is not None:
        _check_no_control(url, "url")
        kw["url"] = url
    if token is not None:
        _check_no_control(token, "token")
        kw["token"] = token
    if section is not None:
        kw["section"] = section
    if fingerprint is not None:
        kw["fingerprint"] = fingerprint
    lead = f"stages a PENDING SDN ipam integration '{i}' (type={t}): {', '.join(_kv_parts(_redact_secrets(kw)))}"
    return Plan(
        action="pve_sdn_ipam_create", target=f"sdn/ipams/{i}",
        change=f"create SDN ipam integration '{i}' (pending)", current={},
        blast_radius=_pending_blast(lead),
        risk=RISK_LOW, risk_reasons=["SDN object create is a pending config change — inert until apply"],
        note="token is UNCONDITIONALLY redacted — only \"[redacted]\" appears in the plan and the audit ledger.",
    )


def plan_ipam_update(api, ipam: str, url: str | None = None, token: str | None = None,
                      section: int | None = None, fingerprint: str | None = None,
                      delete: list | str | None = None) -> Plan:
    """Preview updating an SDN ipam integration. CAPTURE: reads current config via ipam_get
    (already `token`-stripped and `url`-userinfo-masked at the read layer — module
    docstring's reinstated ruling) and redacts it AGAIN defensively BEFORE it enters
    Plan.current. A fresh `token`/`url` passed as a NEW value here (not captured from a
    read) is masked the same way via `_redact_secrets` on the display `kw`."""
    i = _check_sdn_id(ipam, "ipam")
    kw: dict = {}
    if url is not None:
        _check_no_control(url, "url")
        kw["url"] = url
    if token is not None:
        _check_no_control(token, "token")
        kw["token"] = token
    if section is not None:
        kw["section"] = section
    if fingerprint is not None:
        kw["fingerprint"] = fingerprint
    if not kw and not delete:
        raise ProximoError("ipam_update requires at least one field to set or delete")

    current: dict = {}
    read_failed = False
    try:
        current = _redact_secrets(ipam_get(api, i))
    except Exception:
        read_failed = True

    del_keys = delete if isinstance(delete, list) else ([delete] if delete else [])
    parts = _kv_parts(_redact_secrets(kw)) + [f"-{k}" for k in del_keys]
    blast = _pending_blast(f"stages a PENDING update to SDN ipam integration '{i}'")
    if read_failed:
        blast.append("could not read current ipam config — prior value UNKNOWN")
    return Plan(
        action="pve_sdn_ipam_update", target=f"sdn/ipams/{i}",
        change=f"update SDN ipam integration '{i}' (pending): {', '.join(parts) or '(none)'}",
        current=current,
        blast_radius=blast,
        risk=RISK_LOW, risk_reasons=["SDN object update is a pending config change — inert until apply"],
        complete=not read_failed,
        note="token is UNCONDITIONALLY redacted — only \"[redacted]\" appears in the plan and the audit ledger.",
    )


def plan_ipam_delete(api, ipam: str) -> Plan:
    """Preview deleting an SDN ipam integration. CAPTURE: reads current config (redacted
    before it enters Plan.current). RISK_MEDIUM."""
    i = _check_sdn_id(ipam, "ipam")
    current: dict = {}
    read_failed = False
    try:
        current = _redact_secrets(ipam_get(api, i))
    except Exception:
        read_failed = True
    blast = [
        f"stages REMOVAL of SDN ipam integration '{i}' (pending)",
        "takes effect on pve_sdn_apply; if applied, removes the ipam integration",
        "referential-integrity refusal is asserted BY ANALOGY only — Smoke-confirm",
        "no NARROW undo at config level: re-create the ipam integration to revert (the token "
        "must be re-supplied — it is never captured/displayed here), OR call pve_sdn_rollback",
    ]
    if read_failed:
        blast.append("could not read the current ipam config — prior value UNKNOWN")
    return Plan(
        action="pve_sdn_ipam_delete", target=f"sdn/ipams/{i}",
        change=f"delete SDN ipam integration '{i}' (pending)", current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["staging removal of an SDN ipam integration — an apply would disrupt "
                      "address allocation relying on it"],
        complete=not read_failed,
        note="token (if present in current) is UNCONDITIONALLY redacted.",
    )
