r"""PMG identity — auth realms, local users, two-factor authentication, global appliance config,
and cluster bootstrap/join.

Wave 9 of the full-surface campaign (`.scratch/2026-07-15-full-surface-campaign.md`, "Wave 9
decomposition"), chunks 9h AND 9i of `.scratch/sdd/wave-9-draft-decomposition.md` §2, combined in
one module — coordinator RULING 5 (binding): 9i "EXTENDS the new pmg_identity.py from 9h
(global-appliance config + cluster belong with identity per the draft §2)". This file covers
exactly the methods classified `"chunk": "9h"` (16) and `"chunk": "9i"` (14) PLUS the 4 methods
classified `"class": "cluster-ruling"` in `.scratch/sdd/wave-9-classification.json` — 34 methods
total, no more, no fewer.

Chunk 9h (16 tools, LANDED 2026-07-17, commit a53a866) — the wave's **highest secret-density
chunk** (password, crypt_pass, a THIRD user secret this build found [`keys`, yubico key
material — see Fact 3 below], TFA recovery codes, TFA step-up password, and OIDC client-key all
in one place): auth realms, local users, TFA — see the "SCHEMA-VERIFIED FACTS" section below
(facts 1-12, unchanged from that landing).

Chunk 9i (18 tools, this addition — 14 classified "9i" + 4 cluster-ruling mutations): global
single-object appliance config (admin/clamav/mail/spamquar/virusquar/tfa-webauthn — each a GET+PUT
pair, GET /config/mail already shipped as `pmg.relay_config`/`pmg_relay_config` so only its PUT is
new here) PLUS the wave's one DANGER item — PMG cluster bootstrap/join. Coordinator RULING 1
(binding): all 4 cluster mutations BUILD — `create`/`join` RISK_HIGH (no undo, no visibility into
un-clustering — the ruledb factory-reset precedent's own bar), `nodes`/`update-fingerprints`
RISK_MEDIUM (bookkeeping). See the "CHUNK 9i — SCHEMA-VERIFIED FACTS" section below for the
endpoint table, facts, and the cluster secret contract.

Schema truth: the live PMG API-viewer schema, `.scratch/api-schemas-2026-07-15/
pmg-apidoc-live-2026-07-17.json` (425-method full-plane pull, 2026-07-17) — every path/verb/
param/return below was read directly from that JSON tree's `info.{GET,POST,PUT,DELETE}` blocks
under `/access/auth-realm*`, `/access/users*`, `/access/tfa*`, never from memory, never from the
draft's prose alone. NONE of this module is live-verified against a running PMG yet; every
"Smoke-confirm:" note names a specific unconfirmed detail.

Closest structural sibling: `pbs_access.py` (PBS Wave 2a/2b) — same identity-plane shape
(realms/users/TFA) on a sibling Proxmox-family API. This module MIRRORS that sibling's
risk/taint/secret decisions everywhere the two planes genuinely match, and documents every
divergence as a FACT below, verified against THIS plane's own schema — never assumed from the
PBS precedent alone.

Endpoint table (16 methods, all confirmed against the live schema above):

  Auth realms (/access/auth-realm) — 5:
    GET    /access/auth-realm                — realm_list     (read)
    GET    /access/auth-realm/{realm}        — realm_get       (read, defensive client-key strip)
    POST   /access/auth-realm                — realm_create    (MUTATION, MEDIUM)
    PUT    /access/auth-realm/{realm}        — realm_update    (MUTATION, MEDIUM, digest-gated)
    DELETE /access/auth-realm/{realm}        — realm_delete    (MUTATION, MEDIUM)

  Local users (/access/users) — 6 (the LIST half, `GET /access/users`, already shipped inside
  `pmg.py`'s `access_permissions` — used internally by `pmg_doctor`; NOT re-exposed here, and
  correctly classed "covered" in the classification artifact, not "9h"):
    GET    /access/users/{userid}            — user_get        (read, defensive secret strip)
    POST   /access/users                     — user_create     (MUTATION, conditional MEDIUM/HIGH — RULING 3)
    PUT    /access/users/{userid}            — user_update     (MUTATION, conditional MEDIUM/HIGH — RULING 3)
    DELETE /access/users/{userid}            — user_delete     (MUTATION, MEDIUM)
    PUT    /access/users/{userid}/unlock-tfa — user_unlock_tfa (MUTATION, HIGH — see Fact 8)

  TFA (/access/tfa) — 5:
    GET    /access/tfa                       — tfa_list        (read)
    GET    /access/tfa/{userid}               — tfa_user_list   (read)
    GET    /access/tfa/{userid}/{id}          — tfa_entry_get   (read)
    POST   /access/tfa/{userid}               — tfa_add         (MUTATION, MEDIUM — recovery codes secret-bearing)
    PUT    /access/tfa/{userid}/{id}           — tfa_update      (MUTATION, MEDIUM)
    DELETE /access/tfa/{userid}/{id}           — tfa_delete      (MUTATION, HIGH — see Fact 9)

SCHEMA-VERIFIED FACTS (binding on this build — read directly off the live JSON, not memory):

1. **`role` is REQUIRED on `POST /access/users` (create)** — the live schema's `role` property
   carries no `optional: 1` marker (unlike the draft's prose, which implied an optional field
   gated conditionally). Enum: `{root, admin, helpdesk, qmanager, audit}` — "Role 'root' is
   reserved for the Unix Superuser." `role` IS optional on `PUT /access/users/{userid}` (update).
   RULING 3's admin-equivalent set is `{root, admin}` — both grant full PMG control; `helpdesk`/
   `qmanager`/`audit` are lesser-privilege roles, MEDIUM.

2. **`PUT /access/users/{userid}` carries NO `digest` field at all** (schema-verified,
   `additionalProperties: 0` on that endpoint's parameter block) — a genuine PMG-vs-PBS
   divergence: PBS's own `pbs_access.py` `user_update`/`user_delete` DO accept `digest`. This
   build does NOT invent one for PMG's user update/delete — sending an undeclared param would
   only be silently dropped or rejected server-side. Same for `DELETE /access/users/{userid}`
   (only `userid` in its parameter block) and `PUT /access/users/{userid}/unlock-tfa` (only
   `userid`) and every TFA endpoint (none carry `digest`). ONLY `PUT /access/auth-realm/{realm}`
   in this chunk carries `digest` — matching draft §3 Fact 9's "whole-object PUT families carry
   digest" pattern, and matching PBS's own realm-PUT digest support.

3. **A THIRD user secret this build found, beyond the draft's password/crypt_pass pair**: `keys`
   ("Keys for two factor auth (yubico)", maxLength 128) is present on BOTH `POST /access/users`
   and `PUT /access/users/{userid}` — a credential-shaped field the draft's §5 secret-contract
   table did not name. Treated identically to `password`/`crypt_pass`: never-in-ledger on write.
   Read-side: the rich `GET /access/users` LIST schema (`comment, enable, role, tfa-locked-until,
   totp-locked, userid`) does NOT carry `keys` (schema-confirmed absent, matching the draft's
   password/crypt_pass finding) — no read-strip needed on the list; the single-user GET is
   schema-thin (`returns: {"type": "object"}`, no properties declared) so `keys` (and
   `password`/`crypt_pass`) are defensively stripped there regardless of schema silence,
   mirroring `pmg_node.py`'s `_strip_subscription_key` idiom.

4. **`crypt_pass` is forwarded VERBATIM, not locally validated** — its schema `pattern`
   (`\$\d\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+`, a crypt(3) hash shape) is real but genuinely complex;
   this module does not attempt to be a crypt(3) validator, matching the established
   "forwarded-verbatim compound field" idiom already used for LDAP's `sync-attributes` and
   similar upstream-formatted strings elsewhere in this codebase. PMG's own API rejects a
   malformed value; Proximo's job here is transport + secret-handling, not shape enforcement.

5. **PMG's TFA `type` enum has only 4 members: `{totp, u2f, webauthn, recovery}`** —
   schema-confirmed on `POST /access/tfa/{userid}`. `yubico` is ABSENT (a genuine PMG-vs-PBS
   divergence — PBS's own `_TFA_TYPES` includes a 5th member, `yubico`). This build's
   `_TFA_TYPES` enum reflects PMG's own schema, not copied from the PBS sibling.

6. **`GET /access/tfa/{userid}` (single-user TFA list) is RICHLY typed on this plane** — full
   `{created, description, enable, id, type}` per entry, unlike PBS's own module docstring, which
   flags the identical-shaped PBS endpoint as carrying a copy-paste doc-label bug ("Add a TOTP
   secret..." on a GET). PMG's schema carries no such label artifact here — description reads
   plainly "List TFA configurations of users." Treated as a straightforward list read.

7. **`GET /access/tfa/{userid}/{id}` (single TFA entry) is ALSO richly typed** —
   `{created, description, enable, id, type}` — a genuine PMG-vs-PBS divergence: PBS's own
   sibling endpoint is schema-typed literally `null` (a schema-generation quirk PBS's own
   docstring calls out). PMG declares real fields here; passed through as returned, not
   defensively thinned to match the PBS precedent.

8. **`PUT /access/users/{userid}/unlock-tfa` risk: ESCALATED TO HIGH, matching the shipped PBS
   twin's RISK_HIGH for the IDENTICAL wire endpoint and operation** (PBS's `pbs_access.py`
   `plan_tfa_unlock`/`tfa_unlock` — literally the same path, `/access/users/{userid}/unlock-tfa`,
   same "clears a TOTP lockout" semantics). This chunk originally shipped at MEDIUM per its own
   dispatch instruction ("re-enables a locked-out account"), flagged at the time as a documented
   divergence from the twin for the reviewer to confirm or escalate. The Wave 9h review (Major 1)
   ruled the divergence indefensible: the only stated justification was the dispatch instruction
   itself, not an argued technical difference, and PBS's own reasoning ("clears the anti-brute-
   force throttle guarding a 6-digit TOTP keyspace... this plane guards backups, so under-flagging
   an auth-weakening act would be dishonest") applies with EQUAL force to PMG's own admin-grantable
   identity plane — re-unlocking a locked-out account is an attack-recovery vector regardless of
   which Proxmox-family plane it sits on. Escalated per the campaign's own "ratings consistent with
   twins incl. shipped pbs_access" law (9e), the same law this chunk already correctly applied to
   escalate `tfa_delete` (Fact 9, below) from the draft's own un-argued MEDIUM guess.

9. **`DELETE /access/tfa/{userid}/{id}` (TFA factor delete) risk: BUILT AT HIGH, matching the
   PBS twin exactly** (`pbs_access.py`'s `plan_tfa_delete`, RISK_HIGH — "removes a 2FA factor...
   WEAKENS authentication... account-takeover enabler"). The draft's own chunk table guessed
   MEDIUM for this method; this build diverges UPWARD from that guess, applying the standing
   "classify by direction, not by reciting" (9d) + "ratings consistent with twins incl. shipped
   pbs_access" (9e) laws: removing a 2FA factor is unconditionally a security-LOOSENING act with
   no offsetting direction (unlike e.g. tlspolicy's genuinely bidirectional weak/strong values),
   so a flat HIGH — matching the twin — is the honest classification, not a silent recitation of
   the draft's un-reasoned guess.

10. **Realm `type` enum is `{oidc, pam, pmg}` — no `ad`/`ldap`** — a structural divergence from
    PBS, which exposes `ad`/`ldap`/`openid`/`pam`/`pbs` as FIVE separate per-type endpoints. PMG
    folds all its realm types into ONE unified `/access/auth-realm` endpoint with `type` as a
    discriminator field (schema-confirmed: `type` is REQUIRED on POST, ABSENT from PUT — a
    realm's type is fixed at creation, matching PBS's own "type is inherent to the endpoint"
    posture, just expressed as a field instead of a URL segment). PMG's own LDAP integration is a
    SEPARATE, already-shipped family (`/config/ldap/{profile}`, chunk 9c, `pmg_ldap_profile_*`) —
    genuinely distinct from the auth-realm concept; not duplicated here.

11. **`autocreate-role` (deprecated) / `autocreate-role-assignment` on realm create/update can
    auto-provision users at an admin-equivalent role on first login** — schema-confirmed
    (`autocreate-role` enum includes `admin`). This is a REALM-level authority-grant vector,
    distinct from RULING 3's direct-user-create vector; noted here as a real fact (not silently
    missed) but not separately risk-escalated — `realm_create`/`realm_update` stay flat MEDIUM
    (auth config, matching the PBS twin's flat-MEDIUM realm-mutation posture), since the
    escalation only manifests on a FUTURE login event, not at call time, and PMG's own schema
    documents no bounded enumeration of who that will affect (unlike RULING 3's direct, immediate
    grant). Flagged for the reviewer, not silently defaulted.

12. **Single-realm GET (`GET /access/auth-realm/{realm}`) is schema-thin** (`returns: {}`, no
    properties declared) while the LIST form (`GET /access/auth-realm`) is schema-rich
    (`{comment, realm, type}` — no `client-key`, confirmed absent) — the now-familiar "single-item
    GET thinness" pattern (draft §3 Fact 19). `client-key` is defensively stripped from the
    single-realm read regardless of the schema's silence; the list needs no strip (confirmed
    absent already).

THE SECRET CONTRACT (this chunk's defining risk axis — 5 secret-shaped fields):
  - `password` (user create/update): never-in-ledger on write. List read confirmed NOT echoed
    (rich schema); single-user GET defensively stripped (schema-thin).
  - `crypt_pass` (user create/update): same contract as `password` (Fact 4: forwarded verbatim,
    not locally shape-validated).
  - `keys` (user create/update, Fact 3 — the THIRD secret this build found): same contract.
  - TFA `password` (the caller's OWN current password, step-up re-auth on add/update/delete):
    never-in-ledger on write. Never echoed on any TFA read (schema-confirmed absent from every
    TFA read's declared properties, Facts 6/7).
  - TFA `recovery` (one-time recovery codes, returned ONLY in `tfa_add`'s own response when
    `tfa_type='recovery'`): never-in-ledger on the CREATE RESPONSE — surfaces once to the caller,
    exact Wave-2b PBS precedent (`pbs_access.py`'s `tfa_add`).
  - `client-key` (OIDC realm create/update): never-in-ledger on write. List confirmed NOT echoed
    (rich schema); single-realm GET defensively stripped (Fact 12, schema-thin).

7d "hunt a 3rd/4th secret" — one step further than the above five: `tfa_add`'s `totp` param (a
caller-generated `otpauth://` URI that embeds a long-lived shared TOTP secret, sent to PMG on
registration) and its `value`/`challenge` registration payload are NOT given an explicit
`"[redacted]"` marker — matching the shipped PBS twin's own `tools/pbs_access.py` convention
exactly: the server-layer `detail=` dict for `tfa_add` only ever contains `password`/`confirmed`/
`type`, so `totp`/`value`/`challenge` are excluded by OMISSION, never even considered for the
ledger in the first place. Proven with a raw-ledger-bytes assertion (not just a source read) in
`tests/test_confirm_sweep_pmg_identity.py`, since a future refactor that widens the `detail=` dict
could otherwise leak this unnoticed.

TAINT CLASSIFICATION (all 16 tools `REVIEWED_TRUSTED`, `tests/test_taint_classification_complete.
py`): structured, operator-authored realm/identity/TFA config — reads return realm comment/type,
user comment/role/enable, or TFA entry metadata (created/description/enable/id/type), never free
text an attacker could shape (unlike 9c's `pmg_ldap_users_list`/etc, which return directory-
sourced content). Wave 9h review (Major 2) closes a specific gap in that reasoning rather than
leaving it un-examined: this chunk's own Fact 11 already documents that an OIDC realm's
`autocreate`/`username-claim` can derive a PMG userid FROM AN EXTERNAL IdP CLAIM at login time
(schema-confirmed: `username-claim`, "OIDC claim used to generate the unique username") — meaning
a LATER `pmg_access_user_get`/`pmg_access_realm_get` read on such an account surfaces
IdP-influenced identifier content back through Proximo. Argued explicitly here, NOT overturning
`REVIEWED_TRUSTED`:
  1. the surfaced content is a single validated, narrow identifier string — PMG's own
     `pmg-userid` format (4-64 chars, checked by `_check_userid`) — not the arbitrary/unbounded
     free text `pmg_ldap_users_list`'s directory dump carries; a materially weaker
     prompt-injection vector by shape alone.
  2. no schema field on ANY of these 16 endpoints documents PMG copying OTHER arbitrary IdP
     claims into a free-text profile field — `comment`/`email`/`firstname`/`lastname` are all
     caller/operator-supplied on create/update per the schema, never IdP-populated.
  3. the authority angle of `autocreate`/`autocreate-role` (Fact 11) is a separate, already-argued
     concern — that's about GRANTED PERMISSIONS on a future login, not about CONTENT flowing back
     through a read; this section addresses the content angle specifically, so as not to leave a
     reader wondering whether it was considered and rejected versus simply missed.
This argument is narrower than a blanket "identity data is safe" claim — it holds specifically
because the one externally-influenced field (userid) is schema-bounded and narrow, not because
OIDC-sourced content is inherently trustworthy. A future PMG schema field that echoes free-text
IdP claims verbatim (e.g. a raw `preferred_username` or profile JSON blob) would need
reclassification to `taint.ADVERSARIAL_TOOLS`, and this reasoning would need revisiting at that
point — flagged the same way Fact 11 flags the authority angle, not silently assumed permanent.

Validators are module-local — PMG's own charset/length bounds are read from the live schema
(`pmg-userid`: minLength 4, maxLength 64; `pmg-realm`: maxLength 32), not copied from PBS's own
patterns (which are PBS-format-named and not confirmed identical here).

===============================================================================================
CHUNK 9i — global appliance config + cluster bootstrap/join
===============================================================================================

Endpoint table (18 tools: 14 classified "9i" + 4 cluster-ruling mutations):

  Global config — admin (2):
    GET  /config/admin                        — admin_config_get         (read)
    PUT  /config/admin                        — admin_config_update      (MUTATION, MEDIUM, digest-gated)

  Global config — clamav (2):
    GET  /config/clamav                       — clamav_config_get        (read)
    PUT  /config/clamav                       — clamav_config_update     (MUTATION, MEDIUM, digest-gated)

  Global config — mail (1; GET already shipped as pmg.relay_config/pmg_relay_config):
    PUT  /config/mail                         — mail_config_update       (MUTATION, MEDIUM, digest-gated)

  Global config — spamquar (2):
    GET  /config/spamquar                     — spamquar_config_get      (read)
    PUT  /config/spamquar                     — spamquar_config_update   (MUTATION, MEDIUM, digest-gated)

  Global config — virusquar (2):
    GET  /config/virusquar                    — virusquar_config_get     (read)
    PUT  /config/virusquar                    — virusquar_config_update  (MUTATION, MEDIUM, digest-gated)

  Global config — tfa/webauthn (2):
    GET  /config/tfa/webauthn                 — tfa_webauthn_config_get     (read)
    PUT  /config/tfa/webauthn                 — tfa_webauthn_config_update  (MUTATION, MEDIUM, digest-gated, SHA1)

  Cluster reads (3):
    GET  /config/cluster/join                 — cluster_join_info        (read — join-info, PUBLIC)
    GET  /config/cluster/nodes                — cluster_nodes_list       (read)
    GET  /config/cluster/status               — cluster_status           (read)

  Cluster mutations (4, RULING 1 — held for coordinator ruling in the draft, BUILT here):
    POST /config/cluster/create               — cluster_create           (MUTATION, RISK_HIGH, no undo)
    POST /config/cluster/join                 — cluster_join             (MUTATION, RISK_HIGH, 3rd-party cred)
    POST /config/cluster/nodes                — cluster_node_add         (MUTATION, RISK_MEDIUM, bookkeeping)
    POST /config/cluster/update-fingerprints  — cluster_update_fingerprints (MUTATION, RISK_MEDIUM)

CHUNK 9i — SCHEMA-VERIFIED FACTS (binding on this build — read directly off the live JSON):

13. **`GET /config/{admin,clamav,mail,spamquar,virusquar}` are ALL schema-thin on the READ side**
    (`returns: {"type": "object"}`, ZERO declared properties — even thinner than Fact 3/12's
    "single-item GET thinness" pattern, since even the LIST-equivalent form here declares
    nothing) — passed through best-effort, never invented. `GET /config/tfa/webauthn` is the ONE
    exception in this family: richly typed (`{allow-subdomains, id, origin, rp}`).
14. **`http_proxy` (admin config) uses PMG's own UNDERSCORE wire name** (`http_proxy`, not PBS's
    hyphenated `http-proxy`) — schema-confirmed (`properties.http_proxy`, no dash) — a genuine
    naming divergence even though the field SHAPE is identical (`'http://user:pass@host:port/'`
    per the schema's own example text). Still secret-SHAPED, not secret-typed (matches
    `pbs_admin.py`'s own classification for the identical shape). This build reuses the FIX (the
    Wave 5d last-`@` RFC-3986 rsplit correction) via a fresh per-module copy
    (`_redact_pmg_http_proxy`) — mirrors `sdn_objects.py`'s own established "fresh copy, not
    cross-imported" precedent for this exact situation, rather than importing across planes.
15. **Five of the six global-config PUTs (`admin`, `clamav`, `mail`, `spamquar`, `virusquar`)
    carry a `digest` field with the SAME shape as this module's existing realm digest** (Fact 2:
    `maxLength: 64`, generic "different digest" wording, no algorithm named — SHA-256 implied) —
    this build REUSES the already-established `_check_digest` (64 lowercase hex) rather than
    re-deriving. **`PUT /config/tfa/webauthn`'s digest is a DOCUMENTED SHA1 DIVERGENCE**
    (`maxLength: 40`, description explicitly says "different SHA1 digest") — a genuinely
    different shape requiring a NEW validator, `_check_digest_sha1` (40 lowercase hex), not a
    silent reuse of the 64-char one.
16. **`PUT /config/tfa/webauthn`'s own description is BYTE-IDENTICAL to its GET sibling's**
    ("Read the webauthn configuration.") — a SECOND instance of the exact upstream copy-paste
    label bug this module already documented once (Fact 12, `GET /access/auth-realm/{realm}`
    thinness) and that the draft's own §3 Fact 12 also names — trust the verb/param/return shape,
    never the label text.
17. **The cluster GET reads (`join`, `nodes`, `status`) carry ONLY public verification
    material** — `fingerprint` (SSL cert SHA-256 fingerprint), `hostrsapubkey`/`rootrsapubkey`
    (SSH host/root PUBLIC keys), `ip`, `name`, `type`, `cid`, plus `join`'s own `product`/
    `version` — no secret anywhere in any of the three reads (schema-confirmed, field-by-field).
    Argued explicitly, not defaulted: this is the SAME reasoning class as a TLS cert fingerprint
    being safe to return unredacted elsewhere in this codebase — these fields exist specifically
    so a JOINING node can verify the MASTER before trusting it, the opposite of a credential.
18. **`POST /config/cluster/join`'s `fingerprint`/`master_ip`/`password` are ALL REQUIRED** — none
    of the three carries an `optional` key at all on the live schema (matching Fact 1's own
    "absence of `optional` = required" convention, cross-checked against `POST /access/users`'
    `userid`/`role`, which use the identical no-key-present shape for their own required fields).
    `password`'s own description reads plainly "Superuser password" — this is the TARGET MASTER's
    OWN root/superuser credential, a THIRD-PARTY credential passed through Proximo IN TRANSIT
    (never stored, never echoed anywhere on any read) — a genuinely different secret-handling
    shape than every other secret this campaign has handled (which all belong to the CALLER's own
    configured target). Never-in-ledger, and the plan factory (`plan_cluster_join`) deliberately
    takes NO `password` parameter at all — mirrors `plan_user_create`'s identical discipline for
    keeping a secret fully outside the plan-building path.
19. **`POST /config/cluster/create` and `POST /config/cluster/join` BOTH return `type: string`**
    — schema-ambiguous (UPID-shaped async handle vs. a plain synchronous status message is NOT
    resolvable from the schema alone) — mirrors `pmg_node.py`'s `pmg_node_network_reload`
    established idiom EXACTLY: `outcome="submitted"`, the raw string recorded BOTH in the
    envelope's `result` and in the ledger's own `detail.raw_result`, never asserted as
    synchronous completion. Smoke-confirm before any future docstring claims a specific shape.
20. **`POST /config/cluster/nodes` (`add_node`) returns a REAL (if thin) array** — `{cid:
    <integer>}` per item, "Returns the resulting node list" — synchronous and unambiguous, NOT
    part of the ambiguous-string family above; `outcome="ok"`. `POST
    /config/cluster/update-fingerprints` returns `type: null` — also synchronous `outcome="ok"`.
21. **RULING 1 (binding, campaign coordinator, `.scratch/2026-07-15-full-surface-campaign.md`
    "Wave 9 decomposition"):** cluster `create`/`join` = **RISK_HIGH unconditional**, with the
    PLAN's FIRST `blast_radius` line stating plainly that Proximo has NO undo and no visibility
    into un-clustering — matching `pmg_ruledb_reset`'s own "no undo" first-line precedent, BUT
    genuinely worse: unlike ruledb reset, there is NO `pmg_backup_create`-style escape hatch here
    at all (a PMG config backup does not capture/restore cluster membership state) — the plan
    text says this explicitly rather than silently reusing the ruledb-reset wording, which would
    be dishonest here. `nodes`/`update-fingerprints` = **RISK_MEDIUM** (bookkeeping — registration
    /fingerprint refresh, not identity fusion).

CHUNK 9i — DIRECTION-AWARE SECURITY TOGGLES (the 9d/9e lesson: classify the value passed, never
recite both directions statically for every call). Given the field surface here is wide (~70
fields across 6 config families), direction-aware analysis is applied to the fields PMG's OWN
schema descriptions single out as security- or continuity-relevant, not to every numeric tuning
knob:
  - admin: `demo=True` STOPS the SMTP filter entirely (upstream: "Demo mode - do not start SMTP
    filter") — flagged whenever the caller explicitly sets it True. `clamav=False` disables
    ClamAV virus scanning — flagged whenever explicitly set False.
  - clamav: `archiveblockencrypted` transitioning True->False (via a captured prior value) removes
    the encrypted-archive heuristic. The 4 scan-limit fields (`archivemaxfiles`/`archivemaxrec`/
    `archivemaxsize`/`maxscansize`) are flagged when the NEW value is LOWER than the captured
    current value (narrows what actually gets scanned — files above the new ceiling pass through
    unscanned).
  - mail: `tls=False`/`spf=False` (explicit disable) and a `relay`/`smarthost` CHANGE (reroutes
    ALL outbound mail to a new destination — a routing blast-radius fact, not a security
    direction per se, but the highest-consequence field in this 39-field family) are flagged.
  - spamquar: `quarantinelink=True` is flagged verbatim against upstream's OWN caution ("Enables
    user self-service for Quarantine Links. Caution: this is accessible without authentication").
    `authmode` transitioning toward `'ticket'` (no LDAP requirement) from `'ldap'`/`'ldapticket'`
    (via a captured prior value) is flagged as weakening the quarantine-interface auth mode.
  - virusquar: `allowhrefs=True` (explicit enable) is flagged — quarantined virus mail can carry
    phishing links; rendering them clickable is a real caution PMG's own description names
    ("Allow to view hyperlinks").
  - tfa/webauthn: `id`/`origin`/`rp` changes are flagged with the upstream's OWN "will"/"may"
    break existing credentials wording verbatim (schema description text, not this build's own
    guess) — a service-continuity risk, matching the DKIM-selector-rotation caution style (draft
    §3 Fact 14).

CHUNK 9i — THE CLUSTER SECRET CONTRACT:
  - `password` (cluster join, target master's superuser credential): never-in-ledger on write,
    never echoed on any read (Fact 18 — a THIRD-PARTY credential, structurally distinct from every
    other secret in this module). The plan factory (`plan_cluster_join`) never receives it.
  - `http_proxy` (admin config): secret-SHAPED (embedded userinfo), never secret-typed — masked at
    the read layer (if present, Fact 14 — schema-thin, unconfirmed either way) and at the
    Plan/ledger DISPLAY layer; forwarded RAW on the actual write (the update must work).

CHUNK 9i taint: all 18 tools REVIEWED_TRUSTED — structured, operator-authored appliance config and
cluster topology/verification material; no free text an attacker could shape (unlike, e.g.,
`pmg_node_report`/`pmg_node_journal` elsewhere on this plane). Cluster reads carry PUBLIC
verification material by design (Fact 17), not attacker-influenced content.
"""

from __future__ import annotations

import re

from ._validate import check_digest as _check_digest
from .backends import ProximoError
from .planning import RISK_HIGH, RISK_MEDIUM, Plan
from .pmg import PmgBackend, access_permissions, relay_config

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

# userid: schema format 'pmg-userid', minLength 4, maxLength 64. No pattern published — this
# mirrors the general 'user@realm' shape used everywhere else in this codebase (PVE/PBS), with
# PMG's own length bound as the schema's own fact, not a defensive guess.
_USERID_RE = re.compile(r"^[^\s:/\x00-\x1f\x7f]+@[A-Za-z0-9_][A-Za-z0-9._-]*\Z")

# realm: schema format 'pmg-realm', maxLength 32, no minLength published, no pattern published.
# Charset mirrors the identical validator already proven for PBS realms (backup_schedules.py's
# _check_realm) — same 'letters/digits first, then letters/digits/._-' shape, since every other
# Proxmox-family realm-name field in this codebase uses this charset; PMG's own schema does not
# publish a stricter/looser pattern to diverge from.
_REALM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}\Z")

_ROLE_ENUM = frozenset({"root", "admin", "helpdesk", "qmanager", "audit"})
# RULING 3 (binding, campaign coordinator ruling #3): admin-equivalent roles grant full PMG
# control in the SAME call that creates/updates the user (unlike PVE/PBS, where role/permission
# is a separate ACL-grant step already independently rated HIGH elsewhere in this campaign).
_ADMIN_EQUIVALENT_ROLES = frozenset({"root", "admin"})

# Wave 9h review, Seam 2a: the admin-equivalent set above is confirmed COMPLETE against PMG's own
# 5-member role enum (re-verified against the live apidoc) — this is the enum's remaining, known
# non-admin members. Used by `_classify_captured_role` below: only an EXACT (case-sensitive)
# match against THIS set resolves "confirmed non-admin" from a captured (server-echoed) role
# value; anything else — including a case-variant of one of these three — fails open.
_NON_ADMIN_ROLES = _ROLE_ENUM - _ADMIN_EQUIVALENT_ROLES

_REALM_TYPE_ENUM = frozenset({"oidc", "pam", "pmg"})

# TFA type enum: PMG's OWN schema (Fact 5) — only 4 members, no 'yubico' (PBS has 5).
_TFA_TYPES = frozenset({"totp", "u2f", "webauthn", "recovery"})

# TFA entry id: PMG's own schema documents 'id' only as "A TFA entry id" — no pattern, no length
# limit. Guarded defensively (it flows into the URL path) mirroring the PBS sibling's own
# proxmox-tfa-crate-shaped guess (pbs_access.py's _TFA_ID_RE) — not live-verified on PMG
# specifically.
_TFA_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]*\Z")


def _reject_dot_traversal(s: str, label: str) -> None:
    """Reject a '.'/'..'-containing identifier — it flows into the URL path and the HTTP client
    normalizes dot-segments BEFORE sending, so a crafted value can retarget the request onto a
    different endpoint entirely. Mirrors access.py's/pbs_access.py's identical guard."""
    if s == "." or ".." in s:
        raise ProximoError(f"invalid {label}: {s!r} — path-traversal segment rejected")


def _check_userid(userid: str) -> str:
    s = str(userid).strip()
    if len(s) < 4 or len(s) > 64:
        raise ProximoError(
            f"invalid PMG userid: {userid!r} — schema requires 4-64 chars"
        )
    if not _USERID_RE.match(s):
        raise ProximoError(
            f"invalid PMG userid: {userid!r} — expected 'user@realm' "
            "(user part: no whitespace/colon/slash/control chars; "
            "realm: letters/digits/._- only, starting with a letter/digit/underscore)"
        )
    _reject_dot_traversal(s, "userid")
    return s


def _check_realm(realm: str) -> str:
    s = str(realm).strip()
    if not _REALM_RE.match(s):
        raise ProximoError(
            f"invalid PMG realm name: {realm!r} "
            "(must start with alnum, then alnum/._/-, <=32 chars, no slash)"
        )
    _reject_dot_traversal(s, "realm")
    return s


def _check_role(role: str) -> str:
    s = str(role).strip()
    if s not in _ROLE_ENUM:
        raise ProximoError(f"invalid PMG role: {role!r} — expected one of {sorted(_ROLE_ENUM)}")
    return s


def _check_realm_type(realm_type: str) -> str:
    s = str(realm_type).strip()
    if s not in _REALM_TYPE_ENUM:
        raise ProximoError(
            f"invalid PMG realm type: {realm_type!r} — expected one of {sorted(_REALM_TYPE_ENUM)}"
        )
    return s


def _check_tfa_type(tfa_type: str) -> str:
    s = str(tfa_type).strip()
    if s not in _TFA_TYPES:
        raise ProximoError(
            f"invalid PMG TFA type: {tfa_type!r} — expected one of {sorted(_TFA_TYPES)} "
            "(PMG has no 'yubico' TFA type, unlike PBS — Fact 5)"
        )
    return s


def _check_tfa_id(tfa_id: str) -> str:
    s = str(tfa_id).strip()
    if not _TFA_ID_RE.match(s):
        raise ProximoError(
            f"invalid PMG TFA entry id: {tfa_id!r} — expected alnum/:._- only, "
            "starting with a letter/digit"
        )
    _reject_dot_traversal(s, "TFA entry id")
    return s


def _is_admin_equivalent(role: str | None) -> bool:
    return role is not None and role in _ADMIN_EQUIVALENT_ROLES


def _classify_captured_role(role_value: object, role_key_present: bool) -> str:
    """Tri-state classification of a ROLE VALUE READ FROM A SUCCESSFUL CAPTURE (i.e. a live GET
    that did not raise) — NEVER for caller-supplied `role`, which `_check_role` already
    exact-match validates against `_ROLE_ENUM` and raises on any deviation.

    Wave 9h review, Critical finding: `GET /access/users/{userid}` is schema-thin (Fact 3, zero
    declared properties) — a genuinely successful capture may still omit `role` entirely, carry
    `role: null`, or (in principle, for a future/unknown server value) carry a string this build
    doesn't recognize. None of those may be silently read as "confirmed non-admin" — that was the
    fail-open gap the review found. Returns one of:

      - "admin": the value is admin-equivalent (`root`/`admin`), OR a case/whitespace-variant of
        one (e.g. `'Admin'`, `' ROOT '`) — a server echoing admin authority in unexpected case is
        not evidence of NON-admin status, so this resolves to the same tier as a clean match.
      - "safe": the value is an EXACT (case-sensitive, post-strip) match for one of PMG's own
        known non-admin roles (`_NON_ADMIN_ROLES` = `{helpdesk, qmanager, audit}`) — the ONLY
        outcome a caller may treat as confirmed non-admin.
      - "unknown": the role key is absent, the value is `None`/non-string, or the value doesn't
        exactly match a known role in either set above (this deliberately also covers a
        case-variant of a NON-admin role, e.g. `'Helpdesk'` — only an exact match is "safe";
        everything else, including a genuinely new/future PMG role string, fails open) — callers
        must treat "unknown" IDENTICALLY to a capture exception: fail open to the HIGH tier.
    """
    if not role_key_present or not isinstance(role_value, str):
        return "unknown"
    s = role_value.strip()
    if s in _ADMIN_EQUIVALENT_ROLES:
        return "admin"
    if s.lower() in {r.lower() for r in _ADMIN_EQUIVALENT_ROLES}:
        return "admin"
    if s in _NON_ADMIN_ROLES:
        return "safe"
    return "unknown"


# ---------------------------------------------------------------------------
# Secret redaction / defensive-strip helpers
# ---------------------------------------------------------------------------

def _user_secret_redacted_detail(
    password: str | None, crypt_pass: str | None, keys: str | None,
) -> dict:
    """Unconditional redaction for the THREE user-create/update secrets (Fact 3: `keys` is a
    THIRD secret this build found, beyond the draft's password/crypt_pass pair). Returns only the
    keys that were actually supplied — honest: nothing to redact when a field wasn't given."""
    detail: dict = {}
    if password is not None:
        detail["password"] = "[redacted]"  # noqa: S105 — a redaction marker, not a credential
    if crypt_pass is not None:
        detail["crypt_pass"] = "[redacted]"  # noqa: S105 — a redaction marker, not a credential
    if keys is not None:
        detail["keys"] = "[redacted]"
    return detail


def _tfa_password_redacted_detail(password: str | None) -> dict:
    """Unconditional redaction for the TFA step-up `password` param (add/update/delete) — the
    ACTING user's own current password, never echoed anywhere on read (Facts 6/7) but still a
    live secret in the request path."""
    return {"password": "[redacted]"} if password is not None else {}


def _client_key_redacted_detail(client_key: str | None) -> dict:
    """Unconditional redaction for the OIDC realm `client-key` credential field."""
    return {"client-key": "[redacted]"} if client_key is not None else {}


def _strip_user_secret_fields(resp: dict) -> dict:
    """Defensively drop password/crypt_pass/keys from a single-user GET response before it
    reaches the caller. The schema is thin (`returns: {"type": "object"}`, no properties
    declared) so whether PMG ever echoes any of these is unconfirmed — this keeps them out of the
    client-visible return regardless, mirroring `pmg_node.py`'s `_strip_subscription_key` idiom."""
    return {k: v for k, v in resp.items() if k not in ("password", "crypt_pass", "keys")}


def _strip_realm_client_key(resp: dict) -> dict:
    """Defensively drop `client-key` from a single-realm GET response (Fact 12: schema-thin,
    `returns: {}`) — the LIST form is schema-confirmed to omit it already, but the single-item
    read carries no such guarantee."""
    return {k: v for k, v in resp.items() if k != "client-key"}


# ---------------------------------------------------------------------------
# Backend functions — Auth realms
# ---------------------------------------------------------------------------

def realm_list(api: PmgBackend) -> list[dict]:
    """GET /access/auth-realm — list configured auth realms (comment/realm/type; no client-key,
    schema-confirmed absent)."""
    return api._get("/access/auth-realm") or []


def realm_get(api: PmgBackend, realm: str) -> dict:
    """GET /access/auth-realm/{realm} — read one realm's config. `client-key` is defensively
    stripped (Fact 12: schema-thin, unconfirmed either way)."""
    realm = _check_realm(realm)
    resp = api._get(f"/access/auth-realm/{realm}") or {}
    return _strip_realm_client_key(resp)


def realm_create(
    api: PmgBackend,
    realm: str,
    realm_type: str,
    comment: str | None = None,
    default: bool | None = None,
    issuer_url: str | None = None,
    client_id: str | None = None,
    client_key: str | None = None,
    autocreate: bool | None = None,
    autocreate_role: str | None = None,
    autocreate_role_assignment: str | None = None,
    acr_values: str | None = None,
    audiences: str | None = None,
    prompt: str | None = None,
    scopes: str | None = None,
    username_claim: str | None = None,
) -> object:
    """POST /access/auth-realm — create an auth realm. `realm` and `realm_type` (wire: `type`,
    one of `oidc`/`pam`/`pmg` — Fact 10, PMG has NO `ad`/`ldap` realm types, unlike PBS) are
    required. `client_key` (the OIDC client secret) is UNCONDITIONALLY redacted at the server
    layer — never written to any plan/ledger surface. `autocreate_role`/
    `autocreate_role_assignment` can auto-provision users at an admin-equivalent role on a FUTURE
    login (Fact 11) — a real authority vector, distinct from RULING 3's direct-create vector."""
    realm = _check_realm(realm)
    realm_type = _check_realm_type(realm_type)
    data: dict = {"realm": realm, "type": realm_type}
    fields = dict(
        comment=comment, default=default, **{"issuer-url": issuer_url, "client-id": client_id},
        autocreate=autocreate,
        **{"autocreate-role": autocreate_role, "autocreate-role-assignment": autocreate_role_assignment},
        **{"acr-values": acr_values}, audiences=audiences, prompt=prompt, scopes=scopes,
        **{"username-claim": username_claim},
    )
    for k, v in fields.items():
        if v is not None:
            data[k] = v
    if client_key is not None:
        data["client-key"] = str(client_key)
    return api._post("/access/auth-realm", data)


def realm_update(
    api: PmgBackend,
    realm: str,
    comment: str | None = None,
    default: bool | None = None,
    issuer_url: str | None = None,
    client_id: str | None = None,
    client_key: str | None = None,
    autocreate: bool | None = None,
    autocreate_role: str | None = None,
    autocreate_role_assignment: str | None = None,
    acr_values: str | None = None,
    audiences: str | None = None,
    prompt: str | None = None,
    scopes: str | None = None,
    delete_props: list[str] | None = None,
    digest: str | None = None,
) -> object:
    """PUT /access/auth-realm/{realm} — update a realm's config. NO `realm_type`/`username_claim`
    params here — both are schema-confirmed CREATE-ONLY (Fact 10/11 area; PUT's own parameter
    block does not declare either, and is `additionalProperties: 0` so sending them would
    hard-fail the whole request server-side). `digest` IS supported here (Fact 2 — the ONE
    digest-bearing method in this chunk)."""
    realm = _check_realm(realm)
    data: dict = {}
    fields = dict(
        comment=comment, default=default, **{"issuer-url": issuer_url, "client-id": client_id},
        autocreate=autocreate,
        **{"autocreate-role": autocreate_role, "autocreate-role-assignment": autocreate_role_assignment},
        **{"acr-values": acr_values}, audiences=audiences, prompt=prompt, scopes=scopes,
    )
    for k, v in fields.items():
        if v is not None:
            data[k] = v
    if client_key is not None:
        data["client-key"] = str(client_key)
    if delete_props is not None:
        data["delete"] = ",".join(delete_props) if isinstance(delete_props, (list, tuple)) else str(delete_props)
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"/access/auth-realm/{realm}", data or None)


def realm_delete(api: PmgBackend, realm: str) -> object:
    """DELETE /access/auth-realm/{realm} — remove an auth realm. Permanent. NO `digest` param
    (Fact 2 — schema-verified: this endpoint's parameter block declares only `realm`)."""
    realm = _check_realm(realm)
    return api._delete(f"/access/auth-realm/{realm}")


# ---------------------------------------------------------------------------
# Backend functions — Local users
# ---------------------------------------------------------------------------

def user_get(api: PmgBackend, userid: str) -> dict:
    """GET /access/users/{userid} — read one user's config. `password`/`crypt_pass`/`keys` are
    defensively stripped (Fact 3: schema-thin, `returns: {"type": "object"}`, unconfirmed either
    way)."""
    userid = _check_userid(userid)
    resp = api._get(f"/access/users/{userid}") or {}
    return _strip_user_secret_fields(resp)


def user_create(
    api: PmgBackend,
    userid: str,
    role: str,
    realm: str | None = None,
    comment: str | None = None,
    email: str | None = None,
    enable: bool | None = None,
    expire: int | None = None,
    firstname: str | None = None,
    lastname: str | None = None,
    password: str | None = None,
    crypt_pass: str | None = None,
    keys: str | None = None,
) -> object:
    """POST /access/users — create a user. `role` is REQUIRED (Fact 1 — a genuine schema
    divergence from the draft's guess of an optional field), enum
    `{root, admin, helpdesk, qmanager, audit}` ('root' reserved for the Unix Superuser).
    `password`/`crypt_pass`/`keys` are ALL secret-shaped (Fact 3) — UNCONDITIONALLY redacted at
    the server layer, never written to any plan/ledger surface. `realm` defaults to PMG's own
    'pmg' realm when omitted (schema default). Returns None on success."""
    userid = _check_userid(userid)
    role = _check_role(role)
    data: dict = {"userid": userid, "role": role}
    fields = dict(comment=comment, email=email, enable=enable, firstname=firstname, lastname=lastname)
    for k, v in fields.items():
        if v is not None:
            data[k] = v
    if expire is not None:
        data["expire"] = int(expire)
    if realm is not None:
        data["realm"] = _check_realm(realm)
    if password is not None:
        data["password"] = str(password)
    if crypt_pass is not None:
        data["crypt_pass"] = str(crypt_pass)  # Fact 4: forwarded verbatim, not shape-validated
    if keys is not None:
        data["keys"] = str(keys)
    return api._post("/access/users", data)


def user_update(
    api: PmgBackend,
    userid: str,
    comment: str | None = None,
    email: str | None = None,
    enable: bool | None = None,
    expire: int | None = None,
    firstname: str | None = None,
    lastname: str | None = None,
    realm: str | None = None,
    role: str | None = None,
    password: str | None = None,
    crypt_pass: str | None = None,
    keys: str | None = None,
    delete_props: list[str] | None = None,
) -> object:
    """PUT /access/users/{userid} — update user config. `role` is OPTIONAL here (unlike create) —
    omit to leave unchanged; RULING 3's conditional risk applies to a supplied `role` here too
    (see `plan_user_update`). NO `digest` param exists on this endpoint (Fact 2 — a genuine
    PMG-vs-PBS divergence; PBS's own `user_update` accepts one). `password`/`crypt_pass`/`keys`
    redacted identically to `user_create`'s."""
    userid = _check_userid(userid)
    data: dict = {}
    fields = dict(comment=comment, email=email, enable=enable, firstname=firstname, lastname=lastname)
    for k, v in fields.items():
        if v is not None:
            data[k] = v
    if expire is not None:
        data["expire"] = int(expire)
    if realm is not None:
        data["realm"] = _check_realm(realm)
    if role is not None:
        data["role"] = _check_role(role)
    if password is not None:
        data["password"] = str(password)
    if crypt_pass is not None:
        data["crypt_pass"] = str(crypt_pass)
    if keys is not None:
        data["keys"] = str(keys)
    if delete_props is not None:
        data["delete"] = ",".join(delete_props) if isinstance(delete_props, (list, tuple)) else str(delete_props)
    return api._put(f"/access/users/{userid}", data or None)


def user_delete(api: PmgBackend, userid: str) -> object:
    """DELETE /access/users/{userid} — remove a user. Permanent — no undo. NO `digest` param
    (Fact 2 — schema-verified: only `userid` in this endpoint's parameter block)."""
    userid = _check_userid(userid)
    return api._delete(f"/access/users/{userid}")


def user_unlock_tfa(api: PmgBackend, userid: str) -> bool:
    """PUT /access/users/{userid}/unlock-tfa — clear a TOTP lockout for `userid`. Returns whether
    the user was previously locked out. See Fact 8 for this build's MEDIUM rating and its
    documented divergence from the shipped PBS twin's HIGH."""
    userid = _check_userid(userid)
    return bool(api._put(f"/access/users/{userid}/unlock-tfa"))


# ---------------------------------------------------------------------------
# Backend functions — TFA
# ---------------------------------------------------------------------------

def tfa_list(api: PmgBackend) -> list[dict]:
    """GET /access/tfa — list ALL users' TFA configuration."""
    return api._get("/access/tfa") or []


def tfa_user_list(api: PmgBackend, userid: str) -> list[dict]:
    """GET /access/tfa/{userid} — list ONE user's TFA entries. Richly typed on this plane
    (Fact 6) — no copy-paste doc-label artifact the way PBS's identical-shaped sibling carries."""
    userid = _check_userid(userid)
    return api._get(f"/access/tfa/{userid}") or []


def tfa_entry_get(api: PmgBackend, userid: str, tfa_id: str) -> dict:
    """GET /access/tfa/{userid}/{id} — read a single TFA entry. Richly typed on this plane
    (Fact 7 — a genuine PMG-vs-PBS divergence; PBS's own sibling is schema-typed `null`)."""
    userid = _check_userid(userid)
    tfa_id = _check_tfa_id(tfa_id)
    return api._get(f"/access/tfa/{userid}/{tfa_id}") or {}


def tfa_add(
    api: PmgBackend,
    userid: str,
    tfa_type: str,
    description: str | None = None,
    password: str | None = None,
    totp: str | None = None,
    value: str | None = None,
    challenge: str | None = None,
) -> dict:
    """POST /access/tfa/{userid} — add a TFA entry. `tfa_type` one of
    `{totp, u2f, webauthn, recovery}` (Fact 5 — PMG has NO 'yubico' type, unlike PBS).

    SECRET-BEARING RESPONSE: for `tfa_type='recovery'`, the result carries
    `{"recovery": [<one-time codes>], "id": ...}` — SERVER-GENERATED secret material, shown ONCE
    and never retrievable again — never written to the audit ledger (see tools/pmg_identity.py's
    SECRET HANDLING comment). `password` (the caller's own current password, step-up re-auth) is
    UNCONDITIONALLY redacted at the server layer.
    """
    userid = _check_userid(userid)
    tfa_type = _check_tfa_type(tfa_type)
    data: dict = {"type": tfa_type}
    if description is not None:
        data["description"] = description
    if password is not None:
        data["password"] = str(password)
    if totp is not None:
        data["totp"] = totp
    if value is not None:
        data["value"] = value
    if challenge is not None:
        data["challenge"] = challenge
    result = api._post(f"/access/tfa/{userid}", data)
    return result or {}


def tfa_update(
    api: PmgBackend,
    userid: str,
    tfa_id: str,
    description: str | None = None,
    enable: bool | None = None,
    password: str | None = None,
) -> object:
    """PUT /access/tfa/{userid}/{id} — update a TFA entry's description/enabled flag. `password`
    (step-up) redacted identically to `tfa_add`'s."""
    userid = _check_userid(userid)
    tfa_id = _check_tfa_id(tfa_id)
    data: dict = {}
    if description is not None:
        data["description"] = description
    if enable is not None:
        data["enable"] = enable
    if password is not None:
        data["password"] = str(password)
    return api._put(f"/access/tfa/{userid}/{tfa_id}", data or None)


def tfa_delete(api: PmgBackend, userid: str, tfa_id: str, password: str | None = None) -> object:
    """DELETE /access/tfa/{userid}/{id} — permanently remove one TFA factor. `password` (step-up)
    redacted identically to `tfa_add`'s. See Fact 9 for this build's HIGH rating."""
    userid = _check_userid(userid)
    tfa_id = _check_tfa_id(tfa_id)
    params: dict = {}
    if password is not None:
        params["password"] = str(password)
    return api._delete(f"/access/tfa/{userid}/{tfa_id}", params=params or None)


# ---------------------------------------------------------------------------
# Plan functions — pure analysis (or CAPTURE-or-declare where a cheap safe read adds honest
# context); return a Plan the caller can inspect. Never self-gate.
# ---------------------------------------------------------------------------

def plan_realm_create(realm: str, realm_type: str, **fields) -> Plan:
    """Preview creating an auth realm. PURE — no API call. RISK_MEDIUM: adds a new auth source; a
    misconfigured realm can let unintended principals authenticate, or none at all if broken.
    Deliberately takes NO client_key parameter — the plan factory never receives the secret at
    all (mirrors plan_user_create's identical discipline)."""
    realm = _check_realm(realm)
    realm_type = _check_realm_type(realm_type)
    blast = [f"creates PMG auth realm {realm!r} (type={realm_type!r})"]
    if fields.get("autocreate") and fields.get("autocreate_role") in _ADMIN_EQUIVALENT_ROLES:
        blast.append(
            f"autocreate_role={fields['autocreate_role']!r} auto-provisions FUTURE logins via "
            "this realm at an admin-equivalent role (Fact 11) — a realm-level authority vector"
        )
    return Plan(
        action="pmg_access_realm_create",
        target=f"pmg/access/auth-realm/{realm}",
        change=f"create PMG auth realm {realm!r} (type={realm_type!r})",
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["adds a new authentication source to the PMG appliance"],
        note="client_key, if supplied, is redacted from every plan/ledger surface — it never appears here.",
    )


def plan_realm_update(api: PmgBackend, realm: str, **fields) -> Plan:
    """Preview updating a realm's config. CAPTURE-or-declare (reads current config for context).
    RISK_MEDIUM. `client_key` is never received by this function (server layer only)."""
    realm = _check_realm(realm)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = realm_get(api, realm)
    except Exception:
        complete = False
        note_capture = " Could not capture current realm config — no guided revert available."
    change_summary = "; ".join(f"{k}={v!r}" for k, v in sorted(fields.items()) if v is not None)
    return Plan(
        action="pmg_access_realm_update",
        target=f"pmg/access/auth-realm/{realm}",
        change=(f"update PMG auth realm {realm!r}: {change_summary}" if change_summary
                else f"update PMG auth realm {realm!r} (no fields specified)"),
        current=current,
        blast_radius=[f"changes realm {realm!r}'s configuration — affects future logins via this realm"],
        risk=RISK_MEDIUM,
        risk_reasons=["modifies an existing authentication source"],
        complete=complete,
        note="revert by re-applying the captured config with pmg_access_realm_update." + note_capture,
    )


def plan_realm_delete(api: PmgBackend, realm: str) -> Plan:
    """Preview deleting an auth realm. CAPTURE-or-declare. RISK_MEDIUM — permanent, no undo; any
    user authenticating via this realm loses login access."""
    realm = _check_realm(realm)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = realm_get(api, realm)
    except Exception:
        complete = False
        note_capture = " Could not read current realm config."
    return Plan(
        action="pmg_access_realm_delete",
        target=f"pmg/access/auth-realm/{realm}",
        change=f"delete PMG auth realm {realm!r}",
        current=current,
        blast_radius=[
            f"PERMANENTLY removes realm {realm!r} — no undo",
            "any user authenticating via this realm loses login access immediately",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["permanent removal of an authentication source; no rollback primitive"],
        complete=complete,
        note="irreversible; recreate with pmg_access_realm_create to recover (config only, "
             "no user-session recovery)." + note_capture,
    )


def plan_user_create(userid: str, role: str, **fields) -> Plan:
    """Preview creating a PMG local user. PURE — no API call.

    RULING 3 (binding, campaign coordinator ruling #3): CONDITIONAL risk on `role` —
    RISK_HIGH when `role` is admin-equivalent (`root`/`admin` — grants full PMG control in this
    SAME call, unlike PVE/PBS where role/permission is a separate ACL-grant step), RISK_MEDIUM
    otherwise (`helpdesk`/`qmanager`/`audit`). No invented fifth tier (the SDN lock-release
    conditional precedent, `network.py`'s `plan_sdn_lock_release`).

    Deliberately takes NO password/crypt_pass/keys parameters — the plan factory never receives
    any of the three user secrets (Fact 3) at all; the server-layer wrapper adds the redacted
    markers itself, without ever routing the real values through this function.
    """
    userid = _check_userid(userid)
    role = _check_role(role)
    realm = fields.get("realm")
    admin_equivalent = _is_admin_equivalent(role)
    blast = [f"creates PMG user {userid!r} with role={role!r}" + (f" in realm {realm!r}" if realm else "")]
    if admin_equivalent:
        blast.append(
            f"role={role!r} is ADMIN-EQUIVALENT — this user gets FULL PMG control the instant "
            "this call executes, in the SAME call that creates the account (PMG grants role "
            "directly on create, unlike PVE/PBS's separate ACL-grant step)"
        )
    if fields.get("enable") is False:
        blast.append(f"user {userid!r} is created DISABLED (enable=False) — cannot log in until enabled")
    risk = RISK_HIGH if admin_equivalent else RISK_MEDIUM
    reasons = (
        ["role grants admin-equivalent authority in the SAME call that creates the identity — "
         "RULING 3's conditional-HIGH branch"]
        if admin_equivalent else
        ["creates a new principal at a non-admin-equivalent role — RULING 3's conditional-MEDIUM branch"]
    )
    return Plan(
        action="pmg_access_user_create",
        target=f"pmg/access/users/{userid}",
        change=(f"create PMG user {userid!r} (role={role!r}, realm={realm!r})" if realm
                else f"create PMG user {userid!r} (role={role!r})"),
        current={},
        blast_radius=blast,
        risk=risk,
        risk_reasons=reasons,
        note="password/crypt_pass/keys, if supplied, are redacted from every plan/ledger surface "
             "— none of them ever appear here.",
    )


def plan_user_update(api: PmgBackend, userid: str, role: str | None = None, **fields) -> Plan:
    """Preview updating a PMG user. CAPTURE-or-declare (reads current config, including the
    EXISTING role, for RULING 3's resolved-effective-role determination).

    RULING 3 applies here too: if `role` is supplied, the EFFECTIVE risk is based on the
    RESOLVED role (the supplied value — already exact-match validated by `_check_role` above, so
    no ambiguity is possible there); if `role` is omitted, the resolved role comes from the
    capture, via `_classify_captured_role`.

    Wave 9h review, CRITICAL FIX: a capture that SUCCEEDS but whose response omits `role`
    entirely, carries `role: null`, or carries a value that isn't an EXACT match for one of
    PMG's own known roles (case-sensitive — a case-variant of a KNOWN NON-ADMIN role, or any
    unrecognized/future role string, does NOT count as "confirmed non-admin") is now treated
    IDENTICALLY to a capture EXCEPTION: the effective role is UNKNOWN, so this fails OPEN to
    RISK_HIGH and `complete=False` — never silently MEDIUM. Previously `current.get("role")`'s
    implicit `None`-coalescing conflated "role key genuinely absent from a schema-plausible
    response" with "confirmed non-admin," which is exactly the gap the review reproduced. A
    case-variant of an ADMIN-equivalent role (e.g. `'Admin'`, `'ROOT'`) still resolves HIGH, but
    as a CONFIRMED admin-equivalent classification, not merely "unknown" — both outcomes land on
    the same tier, so the distinction only affects `.complete`/the disclosed reasoning, not risk.
    """
    userid = _check_userid(userid)
    role = _check_role(role) if role is not None else None
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = user_get(api, userid)
    except Exception:
        complete = False
        note_capture = " Could not capture current user config — resolved effective role unknown."

    if not complete:
        # The capture raised outright — regardless of whether `role` was supplied, we couldn't
        # even read the account's current state; fail open unconditionally (unchanged from prior
        # behavior — the NEW logic below only covers the "capture succeeded but role
        # unresolvable" gap, not this pre-existing exception path).
        admin_equivalent = False
        role_unknown = True
    elif role is not None:
        # Caller-supplied role is already exact-match validated above — no ambiguity possible.
        admin_equivalent = _is_admin_equivalent(role)
        role_unknown = False
    else:
        role_status = _classify_captured_role(current.get("role"), "role" in current)
        admin_equivalent = role_status == "admin"
        role_unknown = role_status == "unknown"
        if role_unknown:
            complete = False
            note_capture += (
                " Current user config WAS captured, but its 'role' field was absent, null, or "
                "not an exact match for a known PMG role — could not confirm this account is NOT "
                "admin-equivalent."
            )

    resolved_role = role if role is not None else current.get("role")

    new_realm = fields.get("realm")
    blast = [f"updates PMG user {userid!r}"]
    if role is not None:
        blast.append(f"role changes to {role!r}" + (" (ADMIN-EQUIVALENT)" if admin_equivalent else ""))
    elif admin_equivalent:
        blast.append(
            f"user {userid!r} is CURRENTLY admin-equivalent (role={resolved_role!r}) — "
            "unchanged by this update"
        )
    elif role_unknown:
        blast.append(
            f"could not confirm {userid!r}'s current role is NOT admin-equivalent (role "
            "missing/null/unrecognized in the capture, or the capture failed) — treating this "
            "as a possible admin-equivalent account"
        )
    if new_realm is not None:
        blast.append(f"realm changes to {new_realm!r}")
    if fields.get("enable") is False:
        blast.append(f"enable=False STOPS LOGIN for {userid!r} immediately")

    if role_unknown:
        risk = RISK_HIGH
        reasons = [
            "could not resolve the account's effective role — RULING 3 requires knowing the "
            "resolved effective role; failing OPEN to HIGH (not MEDIUM) is the honest choice "
            "whenever that resolution fails, whether from a capture exception, a missing/null "
            "`role` field on an otherwise-successful capture, or an unrecognized role value — "
            "since silently under-rating a possible admin-equivalent account would be the worse "
            "dishonesty"
        ]
    elif admin_equivalent:
        risk = RISK_HIGH
        reasons = ["resolved effective role is admin-equivalent — RULING 3's conditional-HIGH branch"]
    else:
        risk = RISK_MEDIUM
        reasons = ["resolved effective role is not admin-equivalent — RULING 3's conditional-MEDIUM branch"]

    return Plan(
        action="pmg_access_user_update",
        target=f"pmg/access/users/{userid}",
        change=f"update PMG user {userid!r}" + (f" (role={role!r})" if role is not None else ""),
        current=current,
        blast_radius=blast,
        risk=risk,
        risk_reasons=reasons,
        complete=complete,
        note="password/crypt_pass/keys, if supplied, are redacted from every plan/ledger surface. "
             "revert by re-applying the captured config with pmg_access_user_update." + note_capture,
    )


def _last_admin_unresolved_warning(userid: str) -> str:
    """Shared wording for plan_user_delete's fail-open caution when this account's role could not
    be determined with confidence from EITHER the single-user capture OR the account list — the
    option-(b) fallback from the Wave 9h review's fix direction, used when option (a) (resolving
    from the list) itself comes up empty."""
    return (
        f"*** COULD NOT CONFIRM {userid!r} IS NOT THE LAST ENABLED ADMIN-EQUIVALENT ACCOUNT *** "
        "— its role could not be resolved from either the single-user read or the account list; "
        "treat this deletion as a possible last-admin lockout risk"
    )


def plan_user_delete(api: PmgBackend, userid: str) -> Plan:
    """Preview deleting a PMG local user. CAPTURE-or-declare.

    CAPTURE: reads GET /access/users/{userid} -> plan.current (best-effort). ALSO checks whether
    this would remove the LAST admin-equivalent account on the appliance — reusing the
    already-shipped `access_permissions` (GET /access/users list, `pmg.py`) rather than inventing
    a new read — and, if so, adds an explicit footgun warning to the blast radius (chunk-specific
    instruction: "check if deleting the last admin is a footgun the plan should warn about").

    Wave 9h review, CRITICAL FIX: the single-user capture (`current`) is schema-thin (Fact 3) —
    its `role` field may be absent, null, or unrecognized on a genuinely SUCCESSFUL read. That
    must NOT be silently read as "confirmed non-admin," which previously skipped the last-admin
    check entirely and let the sole admin account go out with ZERO warning at MEDIUM. Fixed via
    `_classify_captured_role`, with a two-step fail-open resolution when the single-user capture
    can't confirm the role:
      (a) fall back to the SAME already-fetched `access_permissions` LIST (schema-rich, DOES
          carry `role`) and resolve the target's role by matching `userid` there instead — no
          new read, since the list is queried anyway once we know we can't trust the thin GET;
      (b) if the account still can't be resolved even via the list (e.g. missing from it too, or
          the cross-check read itself fails), fail open with an explicit "could not confirm ...
          is NOT the last admin" warning rather than silence — never a quiet non-admin default.

    RISK_MEDIUM (matches the PBS twin's flat-MEDIUM user-delete posture; RULING 3 governs
    create/update only, per the coordinator ruling's own text) — unconditionally; only the
    WARNING (fires / doesn't fire / fails open) changes with the role resolution above, never the
    risk tier itself. Permanent — no undo.
    """
    userid = _check_userid(userid)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = user_get(api, userid)
    except Exception:
        complete = False
        note_capture = " Could not read current user config."

    blast = [f"PERMANENTLY removes PMG user {userid!r} — no undo"]
    last_admin_warning = None
    unresolved_warning = None
    try:
        role_status = _classify_captured_role(current.get("role"), "role" in current)
        if role_status != "safe":
            # Not confirmed non-admin from the single-user capture -- either it's admin-equivalent
            # already, or it's unknown and needs the list (option a) to try to resolve it.
            all_users = access_permissions(api)
            if role_status == "unknown":
                target_entries = [u for u in all_users if u.get("userid") == userid]
                if target_entries:
                    entry = target_entries[0]
                    role_status = _classify_captured_role(entry.get("role"), "role" in entry)
                else:
                    role_status = "unknown"  # not found in the list either -- still unresolved
            if role_status == "admin":
                admin_users = [
                    u for u in all_users
                    if u.get("role") in _ADMIN_EQUIVALENT_ROLES and u.get("enable", True) is not False
                ]
                if len(admin_users) <= 1:
                    last_admin_warning = (
                        f"*** {userid!r} MAY BE THE LAST ENABLED ADMIN-EQUIVALENT ACCOUNT *** on "
                        "this PMG appliance — deleting it could remove all administrative access "
                        "entirely"
                    )
            elif role_status == "unknown":
                # Option (b): still can't resolve even via the list -- fail open with an explicit
                # caution rather than silently treating this as a routine non-admin deletion.
                unresolved_warning = _last_admin_unresolved_warning(userid)
                complete = False
                note_capture += (
                    " Could not resolve this account's role from either the single-user read "
                    "or the account list."
                )
    except Exception:
        complete = False
        note_capture += " Could not check whether this is the last admin-equivalent account."
        unresolved_warning = _last_admin_unresolved_warning(userid)

    if last_admin_warning:
        blast.append(last_admin_warning)
    if unresolved_warning:
        blast.append(unresolved_warning)

    return Plan(
        action="pmg_access_user_delete",
        target=f"pmg/access/users/{userid}",
        change=f"delete PMG user {userid!r}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=(
            ["permanent removal of a principal; no rollback primitive"]
            + (["this may be the last admin-equivalent account on the appliance — a real "
                "lockout footgun"] if last_admin_warning else [])
            + (["could not confirm this account is NOT the last admin-equivalent account — "
                "failing open to a caution rather than silence"] if unresolved_warning else [])
        ),
        complete=complete,
        note="irreversible; no PMG snapshot primitive applies to access-control state." + note_capture,
    )


def plan_user_unlock_tfa(userid: str) -> Plan:
    """Preview clearing a user's TOTP lockout. PURE — no API call.

    RISK: RISK_HIGH — escalated to match the shipped PBS twin (`pbs_access.py`'s
    `plan_tfa_unlock`, RISK_HIGH for the IDENTICAL wire endpoint,
    `/access/users/{userid}/unlock-tfa`, and identical "clears a TOTP lockout" semantics). See
    Fact 8: this build originally shipped at MEDIUM per this chunk's dispatch instruction, but
    the Wave 9h review ruled that divergence indefensible — there is no argued PMG-specific
    reason clearing a brute-force throttle is less dangerous on PMG's admin-grantable identity
    plane than on PBS's, and the campaign's own consistency law ("ratings consistent with twins
    incl. shipped pbs_access") applies here exactly as it did to escalate `tfa_delete` (Fact 9)
    from the draft's own MEDIUM guess. Escalated, not silently left divergent.
    """
    userid = _check_userid(userid)
    return Plan(
        action="pmg_access_user_unlock_tfa",
        target=f"pmg/access/users/{userid}/unlock-tfa",
        change=f"clear TOTP lockout for PMG user {userid!r}",
        current={},
        blast_radius=[
            f"clears any active TOTP lockout for {userid!r}, re-enabling login attempts "
            "immediately",
            "if the lockout was triggered by a real brute-force attempt against this account, "
            "clearing it removes that protection early — an attack-recovery vector, matching "
            "the shipped PBS twin's reasoning exactly",
        ],
        risk=RISK_HIGH,
        risk_reasons=[
            "clears an anti-brute-force throttle guarding a 6-digit TOTP keyspace on an "
            "admin-grantable identity plane — matches the shipped PBS twin's identical RISK_HIGH "
            "rating for the same wire endpoint (Fact 8, escalated from this chunk's original "
            "MEDIUM per the Wave 9h review's match-twins ruling)",
        ],
    )


def plan_tfa_add(userid: str, tfa_type: str, description: str | None = None) -> Plan:
    """Preview adding a TFA entry. PURE — no API call. RISK_MEDIUM: creates a new auth factor;
    for `tfa_type='recovery'`, the confirmed result carries one-time codes (never in this plan —
    they don't exist yet)."""
    userid = _check_userid(userid)
    tfa_type = _check_tfa_type(tfa_type)
    blast = [f"adds a {tfa_type!r} TFA entry for PMG user {userid!r}"]
    if tfa_type == "recovery":
        blast.append(
            "type='recovery' generates ONE-TIME recovery codes, returned ONCE in the execute "
            "result — never written to the audit ledger"
        )
    return Plan(
        action="pmg_access_tfa_add",
        target=f"pmg/access/tfa/{userid}",
        change=f"add {tfa_type!r} TFA entry for {userid!r}" + (f" ({description!r})" if description else ""),
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["adds a new authentication factor — additive, does not weaken existing auth"],
        note="password (step-up), if supplied, is redacted from every plan/ledger surface.",
    )


def plan_tfa_update(
    api: PmgBackend, userid: str, tfa_id: str, description: str | None = None,
    enable: bool | None = None,
) -> Plan:
    """Preview updating a TFA entry. CAPTURE-or-declare. RISK_MEDIUM — metadata-only change
    (description/enable); enable=False disables the factor without removing it (recoverable via
    a second update, unlike delete)."""
    userid = _check_userid(userid)
    tfa_id = _check_tfa_id(tfa_id)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = tfa_entry_get(api, userid, tfa_id)
    except Exception:
        complete = False
        note_capture = " Could not read the current TFA entry."
    blast = [f"updates TFA entry {tfa_id!r} for {userid!r}"]
    if enable is False:
        blast.append(
            f"enable=False disables this factor for {userid!r} immediately "
            "(recoverable — re-enable with a second update)"
        )
    return Plan(
        action="pmg_access_tfa_update",
        target=f"pmg/access/tfa/{userid}/{tfa_id}",
        change=f"update TFA entry {tfa_id!r} for {userid!r}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["metadata-only change (description/enable); the factor itself is not removed"],
        complete=complete,
        note="password (step-up), if supplied, is redacted from every plan/ledger surface." + note_capture,
    )


def plan_tfa_delete(api: PmgBackend, userid: str, tfa_id: str) -> Plan:
    """Preview deleting a TFA factor. CAPTURE-or-declare (best-effort reads how many factors this
    user has, for context).

    RISK_HIGH — see Fact 9: removing a 2FA factor WEAKENS authentication unconditionally (an
    account-takeover enabler, and a lockout if it's the user's last factor on a TFA-required
    account); matches the shipped PBS twin's `plan_tfa_delete` exactly, a reasoned UPWARD
    divergence from the draft's own un-argued MEDIUM guess.
    """
    userid = _check_userid(userid)
    tfa_id = _check_tfa_id(tfa_id)
    total: int | None = None
    note_capture = ""
    complete = True
    try:
        entries = tfa_user_list(api, userid)
        total = len(entries)
    except Exception:
        complete = False
        note_capture = " Could not read the user's TFA entries — remaining-factor count unknown."
    blast = [
        f"PERMANENTLY removes TFA entry {tfa_id!r} from user {userid!r} — no undo, the factor "
        "must be re-enrolled to restore it",
        "WEAKENS the account's authentication: one fewer 2FA factor lowers the bar for account "
        "TAKEOVER, and can lock the user out if this was their last factor",
    ]
    if total is not None:
        blast.insert(1, f"user currently has {total} TFA entry/entries")
        if total <= 1:
            blast.append(
                f"if this is {userid!r}'s LAST factor, the user loses 2FA entirely (may be "
                "unable to log in on a TFA-required account)"
            )
    return Plan(
        action="pmg_access_tfa_delete",
        target=f"pmg/access/tfa/{userid}/{tfa_id}",
        change=f"delete TFA entry {tfa_id!r} for {userid!r}",
        current={},
        blast_radius=blast,
        risk=RISK_HIGH,
        risk_reasons=[
            "removes a 2FA factor — unconditionally weakens authentication (account-takeover "
            "enabler / possible lockout); no rollback primitive; matches the shipped PBS twin's "
            "identical RISK_HIGH rating (Fact 9)",
        ],
        complete=complete,
        note="irreversible; re-enroll a new factor with pmg_access_tfa_add to restore 2FA coverage." + note_capture,
    )


# ===========================================================================
# CHUNK 9i — Global appliance config + cluster bootstrap/join
# ===========================================================================

# ---------------------------------------------------------------------------
# Validators / redaction helpers — 9i additions
# ---------------------------------------------------------------------------

_DIGEST_SHA1_RE = re.compile(r"^[a-f0-9]{40}\Z")


def _check_digest_sha1(digest: str | None) -> str | None:
    """`PUT /config/tfa/webauthn`'s digest is a DOCUMENTED SHA1 divergence (Fact 15: maxLength
    40, description explicitly says "different SHA1 digest") — a genuinely different shape from
    this module's other five 64-char SHA256 digests, which reuse the existing `_check_digest`.
    Strict no-strip since the A11 adjudication (2026-08-11): it was the last digest validator
    still stripping before matching, which re-admits the trailing newline the \\Z anchor exists
    to refuse — divergent SHAPE, same law."""
    if digest is None:
        return None
    s = str(digest)
    if not _DIGEST_SHA1_RE.match(s):
        raise ProximoError(
            f"invalid digest: {digest!r} — expected 40 lowercase hex chars (SHA-1); "
            "PUT /config/tfa/webauthn's digest is schema-documented as SHA1, a genuine "
            "divergence from this module's other 64-char SHA256 config digests"
        )
    return s


# Fresh per-module copy of pbs_admin.py's `_redact_http_proxy` (Wave 5d's last-@ RFC-3986 fix) —
# same field SHAPE (embedded proxy userinfo credential), PMG's own wire name is `http_proxy`
# (underscore, Fact 14), not PBS's `http-proxy` (hyphen). Not cross-imported, matching
# sdn_objects.py's own established precedent for this identical situation.
_PROXY_SCHEME_RE = re.compile(r"^(?P<prefix>(?:[a-zA-Z][a-zA-Z0-9+.\-]*://)?)(?P<authority>.*)\Z", re.DOTALL)


def _redact_pmg_http_proxy(value: str | None) -> str | None:
    """Mask an embedded HTTP-proxy userinfo credential (user[:pass]@host[:port]) before the value
    can enter a Plan/ledger surface or a read response. host[:port] stays visible — the
    operationally useful part. Last-`@` rsplit (never first) — a host part never legally contains
    `@` (RFC 3986), so this is exact; a value with no `@` at all passes through unchanged."""
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


def _join_password_redacted_detail(password: str | None) -> dict:
    """Unconditional redaction for `POST /config/cluster/join`'s `password` — the TARGET MASTER's
    own root/superuser credential, a THIRD-PARTY credential passed through Proximo in transit
    (Fact 18). Never-in-ledger, never echoed."""
    return {"password": "[redacted]"} if password is not None else {}  # noqa: S105


def _join_delete(delete_props) -> str | None:
    """Comma-join a delete-property list, or pass a pre-joined string through, or None. Mirrors
    this module's own inline realm_update/user_update convention (a plain comma-separated
    string), kept as a shared helper here since 6 config families use it."""
    if delete_props is None:
        return None
    return ",".join(delete_props) if isinstance(delete_props, (list, tuple)) else str(delete_props)


def _delete_prop_list(delete_props) -> list[str]:
    """Normalize a delete/delete_props argument (list, tuple, pre-joined comma string, or None)
    into a list of individual property-name strings, for PER-KEY disclosure in a plan's
    blast_radius — the Wave 9a review CRITICAL lesson (a plan that doesn't disclose every deleted
    key while confirm executes them is the trust-guarantee gap that review found). Presentation
    only — the wire format stays `_join_delete`'s comma-joined string."""
    if delete_props is None:
        return []
    if isinstance(delete_props, (list, tuple)):
        return [str(p) for p in delete_props]
    return [p for p in str(delete_props).split(",") if p]


def _require_at_least_one_config_field(action: str, fields: dict, delete_props) -> None:
    """Standing law: an update tool with an all-optional field bag must refuse a genuinely no-op
    call (mirrors `pmg.py`'s own `plan_spam_config_update` guard on this same plane) rather than
    silently sending an empty PUT. `digest` alone does not count as a field — it is a concurrency
    guard, not a change, and is never passed through `fields`."""
    changes = {k: v for k, v in fields.items() if v is not None}
    if not changes and not delete_props:
        raise ProximoError(
            f"{action}: at least one field (or delete_props) must be provided — "
            "nothing to update (all values are None)"
        )


def _flag_if_narrower(blast: list, current: dict, key: str, new_value, label: str, *,
                       capture_ok: bool = True) -> bool:
    """Append a blast_radius line when `new_value` is numerically LOWER than the captured current
    value for `key` — used by clamav's 4 scan-limit fields (Fact-block "DIRECTION-AWARE SECURITY
    TOGGLES").

    Wave 9i review, MAJOR FIX (mirrors the Wave 9h fail-open lesson on this same plane,
    `_classify_captured_role`): the underlying GET is schema-thin (Fact 13, zero declared
    properties) — a genuinely SUCCESSFUL capture can still omit `key` entirely, carry `None`, or
    carry a non-numeric value. Silently treating that as "not narrower" (the old behavior) was a
    false-assurance gap: `Plan.complete` stayed `True` while the security-loosening callout this
    tool's own docstring promises unconditionally simply never fired. Now tri-state on `current`:

      - `key` present with a comparable number: normal direction comparison (unchanged behavior).
      - `key` absent/None/non-numeric AND `capture_ok=True` (the GET itself succeeded — the
        schema-plausible partial-response shape): FAILS OPEN — appends an explicit "could not
        confirm ..." line and returns True, so the caller marks `Plan.complete=False` (never
        silent).
      - `key` absent/None/non-numeric AND `capture_ok=False` (the GET itself already raised — a
        pre-existing failure already disclosed via the caller's own `note_capture`): stays silent
        (returns False) so the same root cause isn't warned about twice.

    Returns True iff an "undetermined direction" warning was appended.
    """
    old = current.get(key)
    if isinstance(old, (int, float)) and not isinstance(old, bool):
        if isinstance(new_value, (int, float)) and not isinstance(new_value, bool) and new_value < old:
            blast.append(
                f"{label} narrows from {old!r} to {new_value!r} — files/archives above the new "
                "ceiling pass through UNSCANNED by ClamAV"
            )
        return False
    if capture_ok:
        blast.append(
            f"could not confirm this change does not narrow {label} (current value "
            "unavailable) — files/archives above the new ceiling may already be passing "
            "through UNSCANNED, direction unknown"
        )
        return True
    return False


# ---------------------------------------------------------------------------
# Backend functions — Global config: admin
# ---------------------------------------------------------------------------

def admin_config_get(api: PmgBackend) -> dict:
    """GET /config/admin — read PMG admin/appliance-wide config. Schema-thin on this plane
    (Fact 13: `returns: {"type": "object"}`, zero declared properties) — passed through
    best-effort. `http_proxy`, if present, is defensively masked (Fact 14)."""
    data = api._get("/config/admin") or {}
    if "http_proxy" in data:
        data = {**data, "http_proxy": _redact_pmg_http_proxy(data["http_proxy"])}
    return data


def _admin_config_fields(
    admin_mail_from: str | None = None, advfilter: bool | None = None, avast: bool | None = None,
    clamav: bool | None = None, consent_text: str | None = None, custom_check: bool | None = None,
    custom_check_path: str | None = None, dailyreport: bool | None = None, demo: bool | None = None,
    dkim_use_domain: str | None = None, dkim_selector: str | None = None, dkim_sign: bool | None = None,
    dkim_sign_all_mail: bool | None = None, email: str | None = None, http_proxy: str | None = None,
    statlifetime: int | None = None,
) -> dict:
    """Shared field-assembly for admin_config_update/plan_admin_config_update — builds a
    WIRE-keyed dict of whichever fields are not None (every one of the 16 real fields on this
    endpoint, Fact-verified). `http_proxy` is forwarded RAW here (the write must actually work);
    masked only at the read/Plan-display layer, never here."""
    data: dict = {}
    if admin_mail_from is not None:
        data["admin-mail-from"] = admin_mail_from
    if advfilter is not None:
        data["advfilter"] = advfilter
    if avast is not None:
        data["avast"] = avast
    if clamav is not None:
        data["clamav"] = clamav
    if consent_text is not None:
        data["consent-text"] = consent_text
    if custom_check is not None:
        data["custom_check"] = custom_check
    if custom_check_path is not None:
        data["custom_check_path"] = custom_check_path
    if dailyreport is not None:
        data["dailyreport"] = dailyreport
    if demo is not None:
        data["demo"] = demo
    if dkim_use_domain is not None:
        data["dkim-use-domain"] = dkim_use_domain
    if dkim_selector is not None:
        data["dkim_selector"] = dkim_selector
    if dkim_sign is not None:
        data["dkim_sign"] = dkim_sign
    if dkim_sign_all_mail is not None:
        data["dkim_sign_all_mail"] = dkim_sign_all_mail
    if email is not None:
        data["email"] = email
    if http_proxy is not None:
        data["http_proxy"] = str(http_proxy)
    if statlifetime is not None:
        data["statlifetime"] = int(statlifetime)
    return data


def admin_config_update(
    api: PmgBackend,
    admin_mail_from: str | None = None, advfilter: bool | None = None, avast: bool | None = None,
    clamav: bool | None = None, consent_text: str | None = None, custom_check: bool | None = None,
    custom_check_path: str | None = None, dailyreport: bool | None = None, demo: bool | None = None,
    dkim_use_domain: str | None = None, dkim_selector: str | None = None, dkim_sign: bool | None = None,
    dkim_sign_all_mail: bool | None = None, email: str | None = None, http_proxy: str | None = None,
    statlifetime: int | None = None, delete_props=None, digest: str | None = None,
) -> object:
    """PUT /config/admin — update PMG admin/appliance-wide config. Returns null. digest-gated
    (64-char, this module's existing `_check_digest`, Fact 15)."""
    data = _admin_config_fields(
        admin_mail_from, advfilter, avast, clamav, consent_text, custom_check, custom_check_path,
        dailyreport, demo, dkim_use_domain, dkim_selector, dkim_sign, dkim_sign_all_mail, email,
        http_proxy, statlifetime,
    )
    dp = _join_delete(delete_props)
    if dp is not None:
        data["delete"] = dp
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put("/config/admin", data or None)


# ---------------------------------------------------------------------------
# Backend functions — Global config: clamav
# ---------------------------------------------------------------------------

def clamav_config_get(api: PmgBackend) -> dict:
    """GET /config/clamav — read PMG ClamAV config. Schema-thin (Fact 13) — passed through
    best-effort."""
    return api._get("/config/clamav") or {}


def _clamav_config_fields(
    archiveblockencrypted: bool | None = None, archivemaxfiles: int | None = None,
    archivemaxrec: int | None = None, archivemaxsize: int | None = None, dbmirror: str | None = None,
    maxcccount: int | None = None, maxscansize: int | None = None, scriptedupdates: bool | None = None,
) -> dict:
    """Shared field-assembly for clamav_config_update/plan_clamav_config_update (all 8 real
    fields on this endpoint)."""
    data: dict = {}
    if archiveblockencrypted is not None:
        data["archiveblockencrypted"] = archiveblockencrypted
    if archivemaxfiles is not None:
        data["archivemaxfiles"] = int(archivemaxfiles)
    if archivemaxrec is not None:
        data["archivemaxrec"] = int(archivemaxrec)
    if archivemaxsize is not None:
        data["archivemaxsize"] = int(archivemaxsize)
    if dbmirror is not None:
        data["dbmirror"] = dbmirror
    if maxcccount is not None:
        data["maxcccount"] = int(maxcccount)
    if maxscansize is not None:
        data["maxscansize"] = int(maxscansize)
    if scriptedupdates is not None:
        data["scriptedupdates"] = scriptedupdates
    return data


def clamav_config_update(
    api: PmgBackend,
    archiveblockencrypted: bool | None = None, archivemaxfiles: int | None = None,
    archivemaxrec: int | None = None, archivemaxsize: int | None = None, dbmirror: str | None = None,
    maxcccount: int | None = None, maxscansize: int | None = None, scriptedupdates: bool | None = None,
    delete_props=None, digest: str | None = None,
) -> object:
    """PUT /config/clamav — update PMG ClamAV config. Returns null. digest-gated (64-char,
    Fact 15)."""
    data = _clamav_config_fields(
        archiveblockencrypted, archivemaxfiles, archivemaxrec, archivemaxsize, dbmirror,
        maxcccount, maxscansize, scriptedupdates,
    )
    dp = _join_delete(delete_props)
    if dp is not None:
        data["delete"] = dp
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put("/config/clamav", data or None)


# ---------------------------------------------------------------------------
# Backend functions — Global config: mail (GET already shipped as pmg.relay_config)
# ---------------------------------------------------------------------------

# Python-name -> wire-name for every one of the 39 real fields on /config/mail's PUT (Fact
# "wire every field"). Table-driven (not 39 individual if-branches) to stay under the mccabe
# complexity gate (pyproject.toml's max-complexity=21) while still forwarding each field.
_MAIL_WIRE_MAP: dict[str, str] = {
    "accept_broken_mime": "accept-broken-mime", "banner": "banner",
    "before_queue_filtering": "before_queue_filtering", "conn_count_limit": "conn_count_limit",
    "conn_rate_limit": "conn_rate_limit", "dnsbl_sites": "dnsbl_sites",
    "dnsbl_threshold": "dnsbl_threshold", "dwarning": "dwarning", "ext_port": "ext_port",
    "filter_timeout": "filter-timeout", "greylist": "greylist", "greylist6": "greylist6",
    "greylistmask4": "greylistmask4", "greylistmask6": "greylistmask6", "helotests": "helotests",
    "hide_received": "hide_received", "int_port": "int_port", "log_headers": "log-headers",
    "max_filters": "max_filters", "max_policy": "max_policy", "max_smtpd_in": "max_smtpd_in",
    "max_smtpd_out": "max_smtpd_out", "maxsize": "maxsize", "message_rate_limit": "message_rate_limit",
    "ndr_on_block": "ndr_on_block", "queue_lifetime": "queue-lifetime", "rejectunknown": "rejectunknown",
    "rejectunknownsender": "rejectunknownsender", "relay": "relay", "relaynomx": "relaynomx",
    "relayport": "relayport", "relayprotocol": "relayprotocol", "smarthost": "smarthost",
    "smarthostport": "smarthostport", "smtputf8": "smtputf8", "spf": "spf", "tls": "tls",
    "tlsheader": "tlsheader", "tlslog": "tlslog", "verifyreceivers": "verifyreceivers",
}


def _mail_config_fields(
    accept_broken_mime: bool | None = None, banner: str | None = None,
    before_queue_filtering: bool | None = None, conn_count_limit: int | None = None,
    conn_rate_limit: int | None = None, dnsbl_sites: str | None = None,
    dnsbl_threshold: int | None = None, dwarning: int | None = None, ext_port: int | None = None,
    filter_timeout: int | None = None, greylist: bool | None = None, greylist6: bool | None = None,
    greylistmask4: int | None = None, greylistmask6: int | None = None, helotests: bool | None = None,
    hide_received: bool | None = None, int_port: int | None = None, log_headers: bool | None = None,
    max_filters: int | None = None, max_policy: int | None = None, max_smtpd_in: int | None = None,
    max_smtpd_out: int | None = None, maxsize: int | None = None, message_rate_limit: int | None = None,
    ndr_on_block: bool | None = None, queue_lifetime: int | None = None, rejectunknown: bool | None = None,
    rejectunknownsender: bool | None = None, relay: str | None = None, relaynomx: bool | None = None,
    relayport: int | None = None, relayprotocol: str | None = None, smarthost: str | None = None,
    smarthostport: int | None = None, smtputf8: bool | None = None, spf: bool | None = None,
    tls: bool | None = None, tlsheader: bool | None = None, tlslog: bool | None = None,
    verifyreceivers: str | None = None,
) -> dict:
    """Shared field-assembly for mail_config_update/plan_mail_config_update — all 39 real fields
    on this endpoint (the single richest config surface on the whole PMG plane, per the draft's
    own chunk-table note). Table-driven via `_MAIL_WIRE_MAP` — every value here is already the
    caller-typed Python value (bool/int/str); PMG's own `_put`/`_form` layer handles bool->1/0
    coercion (matches `pmg.py`'s `spam_config_update` comment), so no re-casting happens here."""
    values = {
        "accept_broken_mime": accept_broken_mime, "banner": banner,
        "before_queue_filtering": before_queue_filtering, "conn_count_limit": conn_count_limit,
        "conn_rate_limit": conn_rate_limit, "dnsbl_sites": dnsbl_sites,
        "dnsbl_threshold": dnsbl_threshold, "dwarning": dwarning, "ext_port": ext_port,
        "filter_timeout": filter_timeout, "greylist": greylist, "greylist6": greylist6,
        "greylistmask4": greylistmask4, "greylistmask6": greylistmask6, "helotests": helotests,
        "hide_received": hide_received, "int_port": int_port, "log_headers": log_headers,
        "max_filters": max_filters, "max_policy": max_policy, "max_smtpd_in": max_smtpd_in,
        "max_smtpd_out": max_smtpd_out, "maxsize": maxsize, "message_rate_limit": message_rate_limit,
        "ndr_on_block": ndr_on_block, "queue_lifetime": queue_lifetime, "rejectunknown": rejectunknown,
        "rejectunknownsender": rejectunknownsender, "relay": relay, "relaynomx": relaynomx,
        "relayport": relayport, "relayprotocol": relayprotocol, "smarthost": smarthost,
        "smarthostport": smarthostport, "smtputf8": smtputf8, "spf": spf, "tls": tls,
        "tlsheader": tlsheader, "tlslog": tlslog, "verifyreceivers": verifyreceivers,
    }
    return {_MAIL_WIRE_MAP[k]: v for k, v in values.items() if v is not None}


def mail_config_update(
    api: PmgBackend,
    accept_broken_mime: bool | None = None, banner: str | None = None,
    before_queue_filtering: bool | None = None, conn_count_limit: int | None = None,
    conn_rate_limit: int | None = None, dnsbl_sites: str | None = None,
    dnsbl_threshold: int | None = None, dwarning: int | None = None, ext_port: int | None = None,
    filter_timeout: int | None = None, greylist: bool | None = None, greylist6: bool | None = None,
    greylistmask4: int | None = None, greylistmask6: int | None = None, helotests: bool | None = None,
    hide_received: bool | None = None, int_port: int | None = None, log_headers: bool | None = None,
    max_filters: int | None = None, max_policy: int | None = None, max_smtpd_in: int | None = None,
    max_smtpd_out: int | None = None, maxsize: int | None = None, message_rate_limit: int | None = None,
    ndr_on_block: bool | None = None, queue_lifetime: int | None = None, rejectunknown: bool | None = None,
    rejectunknownsender: bool | None = None, relay: str | None = None, relaynomx: bool | None = None,
    relayport: int | None = None, relayprotocol: str | None = None, smarthost: str | None = None,
    smarthostport: int | None = None, smtputf8: bool | None = None, spf: bool | None = None,
    tls: bool | None = None, tlsheader: bool | None = None, tlslog: bool | None = None,
    verifyreceivers: str | None = None, delete_props=None, digest: str | None = None,
) -> object:
    """PUT /config/mail — update PMG mail/SMTP/relay/greylist/DNSBL config. Returns null.
    digest-gated (64-char, Fact 15). GET is already shipped as `pmg.relay_config`/
    `pmg_relay_config` — not re-exposed here."""
    data = _mail_config_fields(
        accept_broken_mime, banner, before_queue_filtering, conn_count_limit, conn_rate_limit,
        dnsbl_sites, dnsbl_threshold, dwarning, ext_port, filter_timeout, greylist, greylist6,
        greylistmask4, greylistmask6, helotests, hide_received, int_port, log_headers,
        max_filters, max_policy, max_smtpd_in, max_smtpd_out, maxsize, message_rate_limit,
        ndr_on_block, queue_lifetime, rejectunknown, rejectunknownsender, relay, relaynomx,
        relayport, relayprotocol, smarthost, smarthostport, smtputf8, spf, tls, tlsheader,
        tlslog, verifyreceivers,
    )
    dp = _join_delete(delete_props)
    if dp is not None:
        data["delete"] = dp
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put("/config/mail", data or None)


# ---------------------------------------------------------------------------
# Backend functions — Global config: spamquar
# ---------------------------------------------------------------------------

def spamquar_config_get(api: PmgBackend) -> dict:
    """GET /config/spamquar — read PMG spam-quarantine config. Schema-thin (Fact 13)."""
    return api._get("/config/spamquar") or {}


def _spamquar_config_fields(
    allowhrefs: bool | None = None, authmode: str | None = None, hostname: str | None = None,
    lifetime: int | None = None, mailfrom: str | None = None, port: int | None = None,
    protocol: str | None = None, quarantinelink: bool | None = None, reportstyle: str | None = None,
    viewimages: str | None = None,
) -> dict:
    """Shared field-assembly for spamquar_config_update/plan_spamquar_config_update (all 10 real
    fields)."""
    data: dict = {}
    if allowhrefs is not None:
        data["allowhrefs"] = allowhrefs
    if authmode is not None:
        data["authmode"] = authmode
    if hostname is not None:
        data["hostname"] = hostname
    if lifetime is not None:
        data["lifetime"] = int(lifetime)
    if mailfrom is not None:
        data["mailfrom"] = mailfrom
    if port is not None:
        data["port"] = int(port)
    if protocol is not None:
        data["protocol"] = protocol
    if quarantinelink is not None:
        data["quarantinelink"] = quarantinelink
    if reportstyle is not None:
        data["reportstyle"] = reportstyle
    if viewimages is not None:
        data["viewimages"] = viewimages
    return data


def spamquar_config_update(
    api: PmgBackend,
    allowhrefs: bool | None = None, authmode: str | None = None, hostname: str | None = None,
    lifetime: int | None = None, mailfrom: str | None = None, port: int | None = None,
    protocol: str | None = None, quarantinelink: bool | None = None, reportstyle: str | None = None,
    viewimages: str | None = None, delete_props=None, digest: str | None = None,
) -> object:
    """PUT /config/spamquar — update PMG spam-quarantine config. Returns null. digest-gated
    (64-char, Fact 15)."""
    data = _spamquar_config_fields(
        allowhrefs, authmode, hostname, lifetime, mailfrom, port, protocol, quarantinelink,
        reportstyle, viewimages,
    )
    dp = _join_delete(delete_props)
    if dp is not None:
        data["delete"] = dp
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put("/config/spamquar", data or None)


# ---------------------------------------------------------------------------
# Backend functions — Global config: virusquar
# ---------------------------------------------------------------------------

def virusquar_config_get(api: PmgBackend) -> dict:
    """GET /config/virusquar — read PMG virus-quarantine config. Schema-thin (Fact 13)."""
    return api._get("/config/virusquar") or {}


def _virusquar_config_fields(
    allowhrefs: bool | None = None, lifetime: int | None = None, viewimages: str | None = None,
) -> dict:
    """Shared field-assembly for virusquar_config_update/plan_virusquar_config_update (all 3
    real fields)."""
    data: dict = {}
    if allowhrefs is not None:
        data["allowhrefs"] = allowhrefs
    if lifetime is not None:
        data["lifetime"] = int(lifetime)
    if viewimages is not None:
        data["viewimages"] = viewimages
    return data


def virusquar_config_update(
    api: PmgBackend, allowhrefs: bool | None = None, lifetime: int | None = None,
    viewimages: str | None = None, delete_props=None, digest: str | None = None,
) -> object:
    """PUT /config/virusquar — update PMG virus-quarantine config. Returns null. digest-gated
    (64-char, Fact 15)."""
    data = _virusquar_config_fields(allowhrefs, lifetime, viewimages)
    dp = _join_delete(delete_props)
    if dp is not None:
        data["delete"] = dp
    digest = _check_digest(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put("/config/virusquar", data or None)


# ---------------------------------------------------------------------------
# Backend functions — Global config: tfa/webauthn
# ---------------------------------------------------------------------------

def tfa_webauthn_config_get(api: PmgBackend) -> dict:
    """GET /config/tfa/webauthn — read PMG webauthn config. Richly typed (Fact 13's ONE
    exception): {allow-subdomains, id, origin, rp}."""
    return api._get("/config/tfa/webauthn") or {}


def _webauthn_config_fields(
    allow_subdomains: bool | None = None, id_: str | None = None, origin: str | None = None,
    rp: str | None = None,
) -> dict:
    """Shared field-assembly for tfa_webauthn_config_update/plan_tfa_webauthn_config_update (all
    4 real fields). `id_` (trailing underscore) avoids shadowing the builtin, matching this
    codebase's established `id_`/`roleid` naming convention for identity-bearing params."""
    data: dict = {}
    if allow_subdomains is not None:
        data["allow-subdomains"] = allow_subdomains
    if id_ is not None:
        data["id"] = id_
    if origin is not None:
        data["origin"] = origin
    if rp is not None:
        data["rp"] = rp
    return data


def tfa_webauthn_config_update(
    api: PmgBackend, allow_subdomains: bool | None = None, id_: str | None = None,
    origin: str | None = None, rp: str | None = None, delete_props=None, digest: str | None = None,
) -> object:
    """PUT /config/tfa/webauthn — update PMG webauthn config. Returns null. digest-gated —
    **SHA1, 40-char** (Fact 15 divergence — uses `_check_digest_sha1`, NOT this module's other
    64-char `_check_digest`). Despite the upstream description text being byte-identical to the
    GET's own ("Read the webauthn configuration.", Fact 16 — a copy-paste label bug), this is a
    genuine PUT/write per its own verb/param/return shape."""
    data = _webauthn_config_fields(allow_subdomains, id_, origin, rp)
    dp = _join_delete(delete_props)
    if dp is not None:
        data["delete"] = dp
    digest = _check_digest_sha1(digest)
    if digest is not None:
        data["digest"] = digest
    return api._put("/config/tfa/webauthn", data or None)


# ---------------------------------------------------------------------------
# Backend functions — Cluster
# ---------------------------------------------------------------------------

def cluster_join_info(api: PmgBackend) -> dict:
    """GET /config/cluster/join — join-info (master's own address + cert fingerprint), meant to
    be base64-encoded and pasted into a NEW node's own join dialog. PUBLIC verification material
    only (Fact 17) — no secret."""
    return api._get("/config/cluster/join") or {}


def cluster_nodes_list(api: PmgBackend) -> list[dict]:
    """GET /config/cluster/nodes — list cluster member nodes. PUBLIC verification material only
    (Fact 17: fingerprint/hostrsapubkey/rootrsapubkey are PUBLIC keys, not secrets)."""
    return api._get("/config/cluster/nodes") or []


def cluster_status(api: PmgBackend, list_single_node: bool | None = None) -> list[dict]:
    """GET /config/cluster/status — cluster node status. `list_single_node=True` also lists the
    local node when no cluster is defined (upstream note: RSA keys/fingerprint are not valid in
    that case). PUBLIC verification material only (Fact 17)."""
    params = {}
    if list_single_node is not None:
        params["list_single_node"] = list_single_node
    return api._get("/config/cluster/status", params=params or None) or []


def cluster_create(api: PmgBackend) -> object:
    """POST /config/cluster/create — bootstrap THIS node as a NEW cluster's master. No
    parameters (schema: additionalProperties: 0). Returns a schema-ambiguous string (Fact 19) —
    forwarded unchanged, never asserted synchronous.

    RULING 1 (RISK_HIGH, no undo) — see plan_cluster_create for the full blast-radius reasoning.
    """
    return api._post("/config/cluster/create")


def cluster_join(api: PmgBackend, fingerprint: str, master_ip: str, password: str) -> object:
    """POST /config/cluster/join — join THIS node to an EXISTING cluster identified by
    `master_ip`/`fingerprint`. `password` is the TARGET MASTER's OWN superuser password
    (Fact 18) — a THIRD-PARTY credential, forwarded RAW here (the join must actually work) but
    NEVER logged/redacted anywhere upstream of this call. Returns a schema-ambiguous string
    (Fact 19) — forwarded unchanged, never asserted synchronous.

    RULING 1 (RISK_HIGH, no undo, third-party credential) — see plan_cluster_join.
    """
    data = {"fingerprint": fingerprint, "master_ip": master_ip, "password": str(password)}
    return api._post("/config/cluster/join", data)


def cluster_node_add(
    api: PmgBackend, fingerprint: str, hostrsapubkey: str, ip: str, name: str, rootrsapubkey: str,
    max_cid: int | None = None,
) -> list[dict]:
    """POST /config/cluster/nodes — register a node into the cluster config (bookkeeping, not
    identity fusion — RULING 1's MEDIUM branch). `fingerprint`/`hostrsapubkey`/`rootrsapubkey` are
    PUBLIC verification material (Fact 17), not secrets. `max_cid` is upstream's own "used
    internally, do not modify" field — forwarded only when the caller explicitly supplies it.
    Returns the resulting node list (real, if thin: `{cid}` per item — Fact 20, unambiguous)."""
    data: dict = {
        "fingerprint": fingerprint, "hostrsapubkey": hostrsapubkey, "ip": ip, "name": name,
        "rootrsapubkey": rootrsapubkey,
    }
    if max_cid is not None:
        data["maxcid"] = int(max_cid)
    return api._post("/config/cluster/nodes", data) or []


def cluster_update_fingerprints(api: PmgBackend) -> None:
    """POST /config/cluster/update-fingerprints — refresh API certificate fingerprints for every
    cluster node (fetched via ssh). No parameters. Returns null — synchronous (Fact 20)."""
    return api._post("/config/cluster/update-fingerprints")


# ---------------------------------------------------------------------------
# Plan functions — Global config
# ---------------------------------------------------------------------------

def plan_admin_config_update(
    api: PmgBackend, delete_props=None, **fields,
) -> Plan:
    """Preview updating PMG admin/appliance-wide config. CAPTURE-or-declare (reads current config
    for context + direction-aware comparison). RISK_MEDIUM. Direction-aware: `demo=True` and
    `clamav=False` are flagged loudly (see the module's own "DIRECTION-AWARE SECURITY TOGGLES"
    section) — classified by the VALUE PASSED, never recited for every call regardless of value
    (the 9d Major-1 lesson)."""
    _require_at_least_one_config_field("pmg_config_admin_update", fields, delete_props)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = admin_config_get(api)
    except Exception:
        complete = False
        note_capture = " Could not capture current admin config — no guided revert available."

    display = dict(_admin_config_fields(**fields))
    if "http_proxy" in display:
        display["http_proxy"] = _redact_pmg_http_proxy(display["http_proxy"])
    changes = ", ".join(f"{k}={v!r}" for k, v in sorted(display.items())) or "no fields specified"

    blast = [f"changes PMG admin/appliance-wide config: {changes}"]
    if fields.get("demo") is True:
        blast.append(
            "*** demo=True STOPS THE SMTP FILTER *** — upstream: 'Demo mode - do not start SMTP "
            "filter' — PMG stops filtering mail entirely while this is set"
        )
    if fields.get("clamav") is False:
        blast.append(
            "clamav=False disables ClamAV virus scanning — SECURITY-LOOSENING: inbound/outbound "
            "mail is no longer scanned for viruses via ClamAV"
        )
    dp_list = _delete_prop_list(delete_props)
    for p in dp_list:
        blast.append(f"DELETES {p!r} from PMG's admin config (resets it to its default)")

    return Plan(
        action="pmg_config_admin_update",
        target="pmg/config/admin",
        change=f"update PMG admin config: {changes}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["changes appliance-wide behavior; some fields (demo/clamav) can stop mail filtering entirely"],
        complete=complete,
        note="http_proxy, if given, is masked in this display; the raw value is still forwarded "
             "on confirm=True. Revert by re-applying the captured config with "
             "pmg_config_admin_update." + note_capture,
    )


def plan_clamav_config_update(api: PmgBackend, delete_props=None, **fields) -> Plan:
    """Preview updating PMG ClamAV config. CAPTURE-or-declare. RISK_MEDIUM. Direction-aware:
    `archiveblockencrypted` True->False and any of the 4 scan-limit fields narrowing below their
    captured current value are flagged (`_flag_if_narrower`).

    Wave 9i review, MAJOR FIX: when the capture itself SUCCEEDS but the specific key a
    direction-aware check needs is absent/None/non-numeric (schema-thin GET, Fact 13 — a
    plausible partial response), this fails OPEN — an explicit "could not confirm ..." line is
    appended AND `complete` is set False — rather than silently skipping the check while
    `complete` stayed True (the false-assurance gap the review reproduced). When the capture
    itself raises, behavior is unchanged from before this fix: `note_capture` alone discloses the
    failure, no per-field duplicate warning."""
    _require_at_least_one_config_field("pmg_config_clamav_update", fields, delete_props)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = clamav_config_get(api)
    except Exception:
        complete = False
        note_capture = " Could not capture current clamav config — no guided revert available."
    # Snapshot BEFORE the per-field direction checks below may separately clear `complete` — this
    # must stay fixed to "did the capture itself succeed", not get overwritten mid-loop.
    capture_ok = complete

    display = _clamav_config_fields(**fields)
    changes = ", ".join(f"{k}={v!r}" for k, v in sorted(display.items())) or "no fields specified"

    blast = [f"changes PMG ClamAV config: {changes}"]
    if fields.get("archiveblockencrypted") is False:
        old_ablock = current.get("archiveblockencrypted")
        if "archiveblockencrypted" not in current or old_ablock is None:
            if capture_ok:
                blast.append(
                    "could not confirm this change does not weaken archiveblockencrypted "
                    "(current value unavailable) — the encrypted-archive heuristic's prior state "
                    "is unknown"
                )
                complete = False
        elif old_ablock:
            blast.append(
                "archiveblockencrypted transitions True->False — removes the encrypted-archive "
                "heuristic (encrypted archives/documents no longer raise the Spam Score)"
            )
    for key, label in (
        ("archivemaxfiles", "archivemaxfiles"), ("archivemaxrec", "archivemaxrec"),
        ("archivemaxsize", "archivemaxsize"), ("maxscansize", "maxscansize"),
    ):
        if display.get(key) is not None:
            if _flag_if_narrower(blast, current, key, display[key], label, capture_ok=capture_ok):
                complete = False
    dp_list = _delete_prop_list(delete_props)
    for p in dp_list:
        blast.append(f"DELETES {p!r} from PMG's clamav config (resets it to its default)")

    return Plan(
        action="pmg_config_clamav_update",
        target="pmg/config/clamav",
        change=f"update PMG ClamAV config: {changes}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["changes ClamAV scanning behavior appliance-wide, effective on new mail immediately"],
        complete=complete,
        note="Revert by re-applying the captured config with pmg_config_clamav_update." + note_capture,
    )


def plan_mail_config_update(api: PmgBackend, delete_props=None, **fields) -> Plan:
    """Preview updating PMG mail/SMTP/relay/greylist/DNSBL config — the single richest config
    surface on the whole PMG plane (39 fields). CAPTURE-or-declare (reuses the already-shipped
    `relay_config` read). RISK_MEDIUM. Direction-aware: `tls=False`/`spf=False` (explicit
    disable) and a `relay`/`smarthost` change (reroutes ALL outbound mail) are flagged."""
    _require_at_least_one_config_field("pmg_config_mail_update", fields, delete_props)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = relay_config(api)
    except Exception:
        complete = False
        note_capture = " Could not capture current mail config — no guided revert available."

    display = _mail_config_fields(**fields)
    changes = ", ".join(f"{k}={v!r}" for k, v in sorted(display.items())) or "no fields specified"

    blast = [f"changes PMG mail/SMTP config: {changes}"]
    if fields.get("tls") is False:
        blast.append("tls=False disables TLS — SECURITY-LOOSENING: SMTP traffic is no longer encrypted")
    if fields.get("spf") is False:
        blast.append("spf=False disables Sender Policy Framework checks — SECURITY-LOOSENING")
    if fields.get("relay") is not None or fields.get("smarthost") is not None:
        blast.append(
            "changes mail ROUTING (relay/smarthost) — ALL matching outbound/inbound mail is "
            "rerouted to the new destination immediately"
        )
    dp_list = _delete_prop_list(delete_props)
    for p in dp_list:
        blast.append(f"DELETES {p!r} from PMG's mail config (resets it to its default)")

    return Plan(
        action="pmg_config_mail_update",
        target="pmg/config/mail",
        change=f"update PMG mail config: {changes}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["changes SMTP/relay/greylist/DNSBL behavior for ALL mail flow immediately"],
        complete=complete,
        note="Revert by re-applying the captured config (pmg_relay_config) with "
             "pmg_config_mail_update." + note_capture,
    )


def plan_spamquar_config_update(api: PmgBackend, delete_props=None, **fields) -> Plan:
    """Preview updating PMG spam-quarantine config. CAPTURE-or-declare. RISK_MEDIUM.
    Direction-aware: `quarantinelink=True` is flagged verbatim against upstream's own
    unauthenticated-access caution; `authmode` weakening toward `'ticket'` (from
    `'ldap'`/`'ldapticket'`, via the captured prior value) is flagged.

    Wave 9i review, MAJOR FIX: when the capture itself SUCCEEDS but `authmode` is absent/None
    from the response (schema-thin GET, Fact 13 — a plausible partial response), this fails OPEN
    — an explicit "could not confirm ..." line is appended AND `complete` is set False — rather
    than silently skipping the check while `complete` stayed True. When the capture itself
    raises, behavior is unchanged from before this fix: `note_capture` alone discloses the
    failure, no duplicate warning."""
    _require_at_least_one_config_field("pmg_config_spamquar_update", fields, delete_props)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = spamquar_config_get(api)
    except Exception:
        complete = False
        note_capture = " Could not capture current spamquar config — no guided revert available."
    # Snapshot BEFORE the direction check below may separately clear `complete` (same discipline
    # as plan_clamav_config_update's `capture_ok`).
    capture_ok = complete

    display = _spamquar_config_fields(**fields)
    changes = ", ".join(f"{k}={v!r}" for k, v in sorted(display.items())) or "no fields specified"

    blast = [f"changes PMG spam-quarantine config: {changes}"]
    if fields.get("quarantinelink") is True:
        blast.append(
            "*** quarantinelink=True *** — upstream: 'Enables user self-service for Quarantine "
            "Links. Caution: this is accessible without authentication'"
        )
    new_authmode = fields.get("authmode")
    if new_authmode == "ticket":
        if "authmode" not in current or current.get("authmode") is None:
            if capture_ok:
                blast.append(
                    "could not confirm this change does not weaken authmode (current value "
                    "unavailable) — cannot tell whether the quarantine interface currently "
                    "requires an LDAP account to log in"
                )
                complete = False
        else:
            old_authmode = current.get("authmode")
            if old_authmode in ("ldap", "ldapticket"):
                blast.append(
                    f"authmode weakens from {old_authmode!r} to 'ticket' — the quarantine "
                    "interface no longer requires an LDAP account to log in"
                )
    dp_list = _delete_prop_list(delete_props)
    for p in dp_list:
        blast.append(f"DELETES {p!r} from PMG's spamquar config (resets it to its default)")

    return Plan(
        action="pmg_config_spamquar_update",
        target="pmg/config/spamquar",
        change=f"update PMG spam-quarantine config: {changes}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["changes spam-quarantine access/behavior appliance-wide"],
        complete=complete,
        note="Revert by re-applying the captured config with pmg_config_spamquar_update." + note_capture,
    )


def plan_virusquar_config_update(api: PmgBackend, delete_props=None, **fields) -> Plan:
    """Preview updating PMG virus-quarantine config. CAPTURE-or-declare. RISK_MEDIUM.
    Direction-aware: `allowhrefs=True` (explicit enable) is flagged — quarantined virus mail can
    carry phishing links."""
    _require_at_least_one_config_field("pmg_config_virusquar_update", fields, delete_props)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = virusquar_config_get(api)
    except Exception:
        complete = False
        note_capture = " Could not capture current virusquar config — no guided revert available."

    display = _virusquar_config_fields(**fields)
    changes = ", ".join(f"{k}={v!r}" for k, v in sorted(display.items())) or "no fields specified"

    blast = [f"changes PMG virus-quarantine config: {changes}"]
    if fields.get("allowhrefs") is True:
        blast.append(
            "allowhrefs=True renders hyperlinks in quarantined virus mail clickable — upstream: "
            "'Allow to view hyperlinks' — quarantined mail is attacker-authored; clickable links "
            "are a phishing risk"
        )
    dp_list = _delete_prop_list(delete_props)
    for p in dp_list:
        blast.append(f"DELETES {p!r} from PMG's virusquar config (resets it to its default)")

    return Plan(
        action="pmg_config_virusquar_update",
        target="pmg/config/virusquar",
        change=f"update PMG virus-quarantine config: {changes}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["changes virus-quarantine display behavior appliance-wide"],
        complete=complete,
        note="Revert by re-applying the captured config with pmg_config_virusquar_update." + note_capture,
    )


def plan_tfa_webauthn_config_update(api: PmgBackend, delete_props=None, **fields) -> Plan:
    """Preview updating PMG webauthn config. CAPTURE-or-declare. RISK_MEDIUM. Direction-aware:
    `id`/`origin`/`rp` changes are flagged with upstream's OWN "will"/"may" break existing
    credentials wording verbatim (schema description text)."""
    _require_at_least_one_config_field("pmg_config_tfa_webauthn_update", fields, delete_props)
    current: dict = {}
    complete = True
    note_capture = ""
    try:
        current = tfa_webauthn_config_get(api)
    except Exception:
        complete = False
        note_capture = " Could not capture current webauthn config — no guided revert available."

    display = _webauthn_config_fields(**fields)
    changes = ", ".join(f"{k}={v!r}" for k, v in sorted(display.items())) or "no fields specified"

    blast = [f"changes PMG webauthn config: {changes}"]
    if display.get("id") is not None:
        blast.append(
            "changing 'id' (relying party ID) WILL break existing WebAuthn credentials (upstream "
            "wording verbatim) — enrolled users must re-register"
        )
    if display.get("origin") is not None:
        blast.append(
            "changing 'origin' MAY break existing WebAuthn credentials (upstream wording verbatim)"
        )
    if display.get("rp") is not None:
        blast.append(
            "changing 'rp' (relying party name) MAY break existing WebAuthn credentials (upstream "
            "wording verbatim)"
        )
    dp_list = _delete_prop_list(delete_props)
    for p in dp_list:
        blast.append(f"DELETES {p!r} from PMG's webauthn config (resets it to its default)")

    return Plan(
        action="pmg_config_tfa_webauthn_update",
        target="pmg/config/tfa/webauthn",
        change=f"update PMG webauthn config: {changes}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["changes WebAuthn relying-party identity; id/origin changes can break existing credentials"],
        complete=complete,
        note="digest here is SHA1 (40-char), a documented divergence from this module's other "
             "config families (Fact 15). Revert by re-applying the captured config with "
             "pmg_config_tfa_webauthn_update." + note_capture,
    )


# ---------------------------------------------------------------------------
# Plan functions — Cluster
# ---------------------------------------------------------------------------

_CLUSTER_NO_UNDO_LINE = (
    "*** NO UNDO *** Proximo has NO undo for this, and NO visibility into un-clustering once "
    "complete. Unlike pmg_ruledb_reset, there is NO backup-and-restore escape hatch here — a PMG "
    "config backup does not capture/restore cluster membership state. Un-clustering a PMG "
    "appliance is an out-of-band administrative procedure this tool cannot see or reverse "
    "(RULING 1, campaign coordinator)."
)


def _cluster_already_clustered_note(api: PmgBackend) -> tuple[list[dict], bool, str]:
    """Best-effort CAPTURE of current cluster status, shared by plan_cluster_create/
    plan_cluster_join — a properly gated cluster tool should surface whether this node is
    ALREADY part of a cluster before fusing/re-fusing it (RULING 1's own "FOR building" argument:
    "a properly gated tool could refuse silently-wrong inputs")."""
    try:
        status = cluster_status(api, list_single_node=True)
        return status, True, ""
    except Exception:
        return [], False, " Could not read current cluster status — unknown whether this node is already clustered."


def plan_cluster_create(api: PmgBackend) -> Plan:
    """Preview bootstrapping THIS node as a NEW cluster master. CAPTURE-or-declare (reads current
    cluster status for context — see `_cluster_already_clustered_note`).

    RULING 1 (binding): RISK_HIGH unconditional. First blast_radius line: no undo, no visibility
    into un-clustering (see `_CLUSTER_NO_UNDO_LINE`).
    """
    status, capture_ok, note_capture = _cluster_already_clustered_note(api)
    blast = [_CLUSTER_NO_UNDO_LINE]
    if capture_ok and len(status) > 1:
        blast.append(
            f"current cluster status shows {len(status)} node(s) already — this node MAY already "
            "be part of a cluster; re-running create against an existing cluster is likely to fail "
            "or be rejected upstream"
        )
    elif not capture_ok:
        blast.append(
            "could not confirm whether this node is ALREADY part of a cluster before bootstrapping "
            "a new one"
        )
    return Plan(
        action="pmg_cluster_create",
        target="pmg/config/cluster/create",
        change="bootstrap THIS PMG node as a new cluster's master",
        current={"cluster_status": status},
        blast_radius=blast,
        risk=RISK_HIGH,
        risk_reasons=[
            "creates a new cluster with this node as master — an identity-fusion event with no "
            "documented undo primitive anywhere in the PMG API surface (RULING 1)",
        ],
        complete=capture_ok,
        note="Returns a schema-ambiguous string (UPID vs. plain status) — recorded as "
             "outcome='submitted' with the raw value in the ledger's own detail.raw_result." + note_capture,
    )


def plan_cluster_join(api: PmgBackend, fingerprint: str, master_ip: str) -> Plan:
    """Preview joining THIS node to an EXISTING cluster. CAPTURE-or-declare. Deliberately takes
    NO `password` parameter — the plan factory never receives the target master's superuser
    credential at all (mirrors plan_user_create's identical discipline for a create-time secret).

    RULING 1 (binding): RISK_HIGH unconditional. First blast_radius line: no undo, no visibility
    into un-clustering. Second: this transmits a THIRD-PARTY credential (the target master's own
    root/superuser password) through Proximo in transit (Fact 18).
    """
    status, capture_ok, note_capture = _cluster_already_clustered_note(api)
    blast = [
        _CLUSTER_NO_UNDO_LINE,
        f"transmits the TARGET MASTER's ({master_ip!r}) OWN superuser password through Proximo "
        "IN TRANSIT to authenticate the join — a THIRD-PARTY credential, not the caller's own "
        "configured secret; never logged, never echoed anywhere",
        f"fuses this node's identity into the cluster at {master_ip!r} (fingerprint {fingerprint!r}) "
        "PERMANENTLY, until manually un-clustered via means Proximo does not otherwise govern",
    ]
    if capture_ok and len(status) > 1:
        blast.append(
            f"current cluster status shows {len(status)} node(s) already — this node MAY already "
            "be part of a DIFFERENT cluster; joining while already clustered is likely to fail or "
            "produce an inconsistent cluster state"
        )
    elif not capture_ok:
        blast.append(
            "could not confirm whether this node is ALREADY part of a cluster before joining a "
            "new one"
        )
    return Plan(
        action="pmg_cluster_join",
        target="pmg/config/cluster/join",
        change=f"join THIS PMG node to the cluster at master_ip={master_ip!r}",
        current={"cluster_status": status},
        blast_radius=blast,
        risk=RISK_HIGH,
        risk_reasons=[
            "fuses this node's identity into an existing cluster — an identity-fusion event with "
            "no documented undo primitive anywhere in the PMG API surface (RULING 1)",
            "requires transmitting a THIRD-PARTY (the target master's) root/superuser credential "
            "through Proximo, a genuinely different secret-handling shape than any other secret "
            "this campaign handles (Fact 18)",
        ],
        complete=capture_ok,
        note="password is NEVER received by this plan factory — it is redacted at the server "
             "layer and only ever forwarded raw to the actual join call on confirm=True. Returns "
             "a schema-ambiguous string (UPID vs. plain status) — recorded as outcome='submitted' "
             "with the raw value in the ledger's own detail.raw_result." + note_capture,
    )


def plan_cluster_node_add(
    fingerprint: str, hostrsapubkey: str, ip: str, name: str, rootrsapubkey: str,
    max_cid: int | None = None,
) -> Plan:
    """Preview registering a node into the cluster config. PURE — no API call. RULING 1's MEDIUM
    branch: bookkeeping (registration), not identity fusion — the ACTUAL fusion already happened
    via a prior pmg_cluster_create/pmg_cluster_join on the node being registered. Public
    verification material only (fingerprint/hostrsapubkey/rootrsapubkey, Fact 17) — not
    echoed in full here to keep the plan readable (they're long base64/hex blobs), just noted as
    supplied."""
    blast = [
        f"registers node {name!r} ({ip!r}) into this cluster's config, with the supplied "
        "certificate fingerprint and SSH host/root public keys",
    ]
    if max_cid is not None:
        blast.append(
            f"max_cid={max_cid!r} explicitly supplied — upstream's own field description: 'used "
            "internally, do not modify' unless you know what you're doing"
        )
    return Plan(
        action="pmg_cluster_node_add",
        target="pmg/config/cluster/nodes",
        change=f"add node {name!r} ({ip!r}) to the cluster config",
        current={},
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=["cluster-membership bookkeeping (registration), not identity fusion (RULING 1)"],
        note="Returns the resulting node list (real, if thin: {cid} per item) — synchronous, unambiguous.",
    )


def plan_cluster_update_fingerprints() -> Plan:
    """Preview refreshing API certificate fingerprints for every cluster node (via ssh). PURE —
    no API call, no parameters. RULING 1's MEDIUM branch: bookkeeping."""
    return Plan(
        action="pmg_cluster_update_fingerprints",
        target="pmg/config/cluster/update-fingerprints",
        change="refresh API certificate fingerprints for every cluster node (fetched via ssh)",
        current={},
        blast_radius=["refreshes fingerprint bookkeeping for every cluster node — no identity change"],
        risk=RISK_MEDIUM,
        risk_reasons=["cluster-membership bookkeeping (fingerprint refresh), not identity fusion (RULING 1)"],
        note="Returns null — synchronous.",
    )
