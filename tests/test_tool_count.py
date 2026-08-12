"""Pin the MCP tool surface count so doc/count drift can't recur.

History: a session once chased a phantom "145 vs 146" discrepancy. The 146 was a
`grep -c '@mcp.tool()'` artifact — it counted the prose mention of `@mcp.tool()` in
server.py's module docstring as if it were a decorator. The authoritative count is the
FastMCP registry (`mcp.list_tools()`), which dedupes by tool name. This test makes the
number machine-checked: bump EXPECTED_TOOL_COUNT *intentionally* when you add/remove a
tool (same discipline as the version), never let it drift silently.

The second test catches a real bug: if two functions register under the same tool name,
the registry silently keeps one and drops the other (a "lost tool"). That shows up as
real-decorators > registry-entries — so we count the actual decorator LINES (anchored to
line-start, which excludes docstring/comment mentions) and require them to equal the
exposed surface. The equality also proves no decorator is env-gated (e.g. an exec-mode
tool behind a flag) — a conditional one would make the unconditional source count exceed
the runtime count.

Decorator lines are counted across server.py AND every per-plane submodule under
`proximo/tools/` (2026-07-02 split): server.py keeps the mutation funnel (mcp, tool, the
5-gate wiring) plus the three manual-audit-path exec tools, while the ~348 thin per-plane
wrappers now live in `proximo/tools/*.py` and are re-imported into server.py by name for
registration + `server.<tool>` surface parity. The registry is still the single source of
truth for the exposed count; this just widens WHERE we look for the source-level decorator
count it's compared against.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import proximo.door as door
import proximo.server as server

EXPECTED_TOOL_COUNT = 906  # +1 (audit_entries, 2026-08-01): the READ side of PROVE. 0.29.0
# recorded the principal on every ledger entry and nothing could read one back, so "who changed
# this guest" was unanswerable through Proximo while the answer sat on disk — a shipped claim
# with no read path. Found on the live estate by a local qwen3:8b that read the catalog and
# correctly reported no tool does this. Resident in every mode: a chain you cannot read is a
# claim, not a control.
# Prior: 905  # +1 (the by-name escape hatch, 2026-08-01): proximo_call is now a
# MODULE-LEVEL tool rather than a closure inside apply_lean, so it is resident in every mode and
# in _ALWAYS_REGISTERED. Four scoping layers ship and every one of them could strand a working
# tool — unreachable on every transport, with no way back inside a live session. Dispatch is from
# FULL_CATALOG, snapshotted before any layer prunes. See tests/test_escape_hatch.py.
# Prior: 904  # +2 (wiki seam reader side, 2026-07-29): proximo_wiki +
# proximo_wiki_read — BM25 search and one-section read over a LOCAL docs index built by
# an operator-supplied builder (proximo/wiki.py). Opt-in via PROXIMO_WIKI; the seam is a file
# contract, so proximo imports nothing from the builder.
# Prior: 902  # +1 (Tier-1 memory increment 2, 2026-07-29): proximo_baseline —
# per-guest cpu/mem distribution rollups from rrddata, stored-first (proximo/memory.py).
# Prior: 901  # +1 (Tier-1 estate memory increment 1, 2026-07-29): proximo_recall
# — the age-stamped local estate-map read (opt-in PROXIMO_MEMORY; proximo/memory.py).
# Prior: 900  # +11 (Wave 9j — PMG quarantine + statistics remainder, the FINAL
# chunk that CLOSES the PMG plane, extends pmg.py/tools/pmg_mail.py, campaign RULING 4 +
# RULING 5): 10 reads — pmg_quarantine_users_list, pmg_quarantine_content_get (ADVERSARIAL),
# pmg_quarantine_attachments_list (ADVERSARIAL), pmg_quarantine_link_get (RULING 4 — its return
# is a bearer-credential-equivalent, never-in-ledger on the read's own logged return),
# pmg_statistics_contact (ADVERSARIAL), pmg_statistics_detail (ADVERSARIAL),
# pmg_statistics_maildistribution, pmg_statistics_recentreceivers (ADVERSARIAL),
# pmg_statistics_recentsenders (ADVERSARIAL), pmg_statistics_rejectcount — + 1 mutation —
# pmg_quarantine_sendlink (LOW, sends a REAL email containing a quarantine login link, matches
# pbs_notification_target_test's precedent). See pmg.py's own "Wave 9j" module section +
# tests/test_confirm_sweep_pmg_quarantine_statistics.py for the full argument.
# Was 889 after Wave 9i — +18 (Wave 9i — PMG global appliance config + cluster bootstrap/join,
# extends pmg_identity.py/tools/pmg_identity.py, campaign RULING 1 + RULING 5): 8 reads —
# pmg_config_admin_get, pmg_config_clamav_get, pmg_config_spamquar_get, pmg_config_virusquar_get,
# pmg_config_tfa_webauthn_get, pmg_cluster_join_info, pmg_cluster_nodes_list, pmg_cluster_status
# — + 10 mutations — pmg_config_admin_update/pmg_config_clamav_update/pmg_config_mail_update
# (GET already shipped as pmg_relay_config)/pmg_config_spamquar_update/
# pmg_config_virusquar_update (all MEDIUM, digest-gated 64-char SHA256, direction-aware:
# demo=True/clamav=False in admin; scan-limit narrowing/archiveblockencrypted in clamav;
# tls=False/spf=False/relay-smarthost-change in mail; quarantinelink=True/authmode-weakening in
# spamquar; allowhrefs=True in virusquar)/pmg_config_tfa_webauthn_update (MEDIUM, digest-gated
# but SHA1 40-char — a genuine divergence from the other 5 families — id/origin/rp changes
# flagged with upstream's own break-credentials wording) + the wave's DANGER item, RULING 1
# (binding, all 4 cluster mutations BUILT): pmg_cluster_create/pmg_cluster_join (RISK_HIGH,
# unconditional — first blast_radius line states plainly no undo + no visibility into
# un-clustering, unlike pmg_ruledb_reset there is NO backup-and-restore escape hatch; join's
# password is the TARGET MASTER's own third-party superuser credential, never-in-ledger, the
# plan factory never receives it at all)/pmg_cluster_node_add/pmg_cluster_update_fingerprints
# (RISK_MEDIUM — bookkeeping, not identity fusion). Exactly the 14 methods classified
# "chunk": "9i" PLUS the 4 methods classified "class": "cluster-ruling" in
# .scratch/sdd/wave-9-classification.json — no more, no fewer. cluster create/join return a
# schema-ambiguous string (UPID vs. plain status) -> outcome="submitted" + ledger detail.raw_result,
# mirroring pmg_node_network_reload's established idiom exactly.
# Was 871 after Wave 9h (below) — +16 (Wave 9h — PMG identity: auth-realm, local users, TFA — NEW
# modules pmg_identity.py + tools/pmg_identity.py, campaign RULING 5, since 9g confirmed the
# module was still unbuilt): 6 reads — pmg_access_realm_list, pmg_access_realm_get,
# pmg_access_user_get, pmg_access_tfa_list, pmg_access_tfa_user_list, pmg_access_tfa_get — + 10
# mutations — pmg_access_realm_create/_update (MEDIUM, client-key never-in-ledger)/_delete
# (MEDIUM, no digest param — schema-verified), pmg_access_user_create/_update (RULING 3:
# CONDITIONAL MEDIUM/HIGH — HIGH when role is admin-equivalent 'root'/'admin', MEDIUM otherwise
# 'helpdesk'/'qmanager'/'audit'; password/crypt_pass/keys never-in-ledger — THREE user secrets,
# 'keys' [yubico] a genuine find beyond the draft's password/crypt_pass pair)/_delete (MEDIUM,
# last-admin-equivalent-account footgun warning, reuses the shipped access_permissions read;
# Wave 9h REVIEW Critical fix: an unresolvable role from a schema-thin capture now fails open
# to the same warning via the access_permissions list, rather than silently reading as
# non-admin), pmg_access_user_unlock_tfa (HIGH — escalated from this chunk's original MEDIUM
# by the Wave 9h REVIEW, Major 1, to match the shipped PBS twin's RISK_HIGH for the identical
# wire endpoint; no argued PMG-specific reason it's less dangerous),
# pmg_access_tfa_add (MEDIUM, recovery codes never-in-ledger on the CREATE RESPONSE)/_update
# (MEDIUM)/_delete (HIGH — matches the shipped PBS twin exactly, a reasoned upward divergence
# from the draft's own un-argued MEDIUM guess). Exactly the 16 methods classified "chunk": "9h" in
# .scratch/sdd/wave-9-classification.json — no more, no fewer. KEY REUSE: mirrors the shipped
# pbs_access.py (Wave 2a/2b) risk/taint/secret idiom everywhere the planes match; PMG-vs-PBS
# divergences argued in pmg_identity.py's own module section (12 facts) include: PMG's realm
# endpoint is UNIFIED with `type` as a discriminator ({oidc,pam,pmg}, no ad/ldap) vs PBS's 5
# separate per-type endpoints; PMG's TFA type enum has only 4 members (no yubico); PMG's user
# PUT/DELETE carry NO digest param at all (PBS's do); PMG's single-TFA-entry reads are richly
# typed (PBS's is null-typed).
# Was 855 after Wave 9g (below) — +19 (Wave 9g — PMG ACME accounts/plugins + node cert order/renew/
# revoke + custom-cert upload, extends pmg.py/tools/pmg_mail.py per campaign RULING 5): 8 reads —
# pmg_acme_account_list, pmg_acme_account_get, pmg_acme_plugin_list, pmg_acme_plugin_get,
# pmg_acme_tos, pmg_acme_meta, pmg_acme_directories, pmg_acme_challenge_schema — + 11 mutations —
# pmg_acme_account_create (MEDIUM), pmg_acme_account_update (LOW), pmg_acme_account_delete (HIGH
# — DEACTIVATES at the CA, mirrors pbs_acme_account_delete/acme_certs.py), pmg_acme_plugin_create/
# _update (MEDIUM), pmg_acme_plugin_delete (HIGH — breaks auto-renewal), pmg_node_cert_acme_order/
# _renew (MEDIUM — CA-validated, install-on-success only), pmg_node_cert_acme_revoke (HIGH,
# IRREVERSIBLE — the tool PBS never shipped), pmg_node_cert_custom_upload (HIGH, no undo — matches
# pve_node_cert_upload/pbs_node_cert_upload, NOT downgraded despite the draft's own hedge),
# pmg_node_cert_custom_delete (MEDIUM, recoverable). Exactly the 19 methods classified
# "chunk": "9g" in .scratch/sdd/wave-9-classification.json — no more, no fewer. KEY REUSE: mirrors
# the shipped pbs_acme.py (Wave 3b)/acme_certs.py idiom; PMG-vs-PBS/PVE divergences (11, argued in
# pmg.py's own Wave 9g module section) include: PMG HAS node cert revoke (PBS doesn't); PMG's node
# cert endpoints carry a real dual {api,smtp} cert-type path segment (neither PVE nor PBS has
# this); PMG's account create/update/delete AND node cert order/renew/revoke all declare a bare
# STRING return (PBS's account trio is null; PVE's cert trio is a confirmed UPID) — treated with
# outcome="submitted" + raw_result honesty, never assumed. THE SECRET CONTRACT: `eab-hmac-key`/
# `eab-kid` (account) and `data` (plugin, DNS-API credential blob) DEFENSIVELY stripped on every
# read (both schema-thin/unconfirmed — a divergence from PBS's own MANDATORY strip, since PMG's
# plugin list is schema-confirmed THIN/id-only, unlike PBS's rich list); never-in-ledger on write.
# Custom-cert `key` (PEM private key, REQUIRED per PMG's schema) UNCONDITIONALLY redacted — no
# read on this plane ever returns raw key material. `pmg_acme_tos`/`pmg_acme_meta` ADVERSARIAL
# (caller-chosen CA directory URL fetch, https-only validated, mirrors pbs_acme_tos — `meta` has
# no PBS equivalent at all, a genuinely new read this wave).
# Was 836 after Wave 9f — PMG PBS remote config + node-side PBS backup jobs,
# extends pmg.py/tools/pmg_mail.py per campaign RULING 5): pmg_pbs_remote_list, pmg_pbs_remote_get,
# pmg_node_pbs_jobs_list (3 reads) + pmg_pbs_remote_create, pmg_pbs_remote_update (2 MEDIUM —
# create/update a PERSISTENT CREDENTIAL-BEARING link to an external PBS instance, mirrors
# pbs_remote_create/pbs_s3_client_create) + pmg_pbs_remote_delete (1 MEDIUM, mirrors
# pbs_remote_delete) + pmg_node_pbs_snapshots_list, pmg_node_pbs_snapshot_get (2 ADVERSARIAL reads
# — remote-authored snapshot labels) + pmg_node_pbs_snapshot_create (1 MEDIUM — backup + configured
# prune, mirrors plan_pbs_job_run's 'sync' tier) + pmg_node_pbs_snapshot_forget (1 HIGH, no undo,
# mirrors pbs_snapshot_delete) + pmg_node_pbs_snapshot_restore (1 HIGH, no undo, mirrors
# pmg_node_backup_restore extended to a remote source) + pmg_node_pbs_snapshot_verify (1 LOW,
# mirrors pbs_verify_start) + pmg_node_pbs_timer_get (1 read) + pmg_node_pbs_timer_create,
# pmg_node_pbs_timer_delete (2 LOW, mirror pbs_job_create/pbs_job_delete). Exactly the 15 methods
# classified "chunk": "9f" in .scratch/sdd/wave-9-classification.json — no more, no fewer. THE
# SECRET CONTRACT: `password`/`encryption-key` CONFIRMED echoing on BOTH list forms (GET
# /config/pbs, GET /nodes/{node}/pbs) — MANDATORY read-strip; DEFENSIVE strip on the single-item
# GET (bare schema); never-in-ledger on write (both fields, plus a possible server-generated
# encryption-key in the create/update RESPONSE when encryption_key='autogen'). `fingerprint`/
# `master-pubkey` are PUBLIC, pass through unredacted.
# Was 821 after Wave 9e — PMG DKIM + customscores, extends pmg.py/
# tools/pmg_mail.py per campaign RULING 5): pmg_dkim_domains_list, pmg_dkim_domain_get,
# pmg_dkim_selector_get, pmg_dkim_selectors_list, pmg_customscores_list, pmg_customscores_get (6
# reads) + pmg_dkim_domain_create, pmg_dkim_domain_update, pmg_dkim_domain_delete (3 LOW
# comment-only/additive mutations) + pmg_dkim_selector_generate (1 MEDIUM — rotates the DKIM
# signing key; PMG's own warning "All future mail will be signed with the new key!"; matches the
# already-shipped bindpw/fetchmail-password rotation MEDIUM precedent, not a HIGH-class
# destructive event) + pmg_customscores_create (1 LOW, additive) + pmg_customscores_update,
# pmg_customscores_delete (2 MEDIUM, digest-gated — update CAPTURES the prior score to state a
# real raise/lower delta) + pmg_customscores_revert_all, pmg_customscores_apply (2 MEDIUM bulk
# mutations — apply is digest-gated, returns an ambiguous string, outcome="submitted" mirroring
# pmg_node_network_reload). Exactly the 15 methods classified "chunk": "9e" in
# .scratch/sdd/wave-9-classification.json — no more, no fewer. NO secret-shaped field anywhere in
# this chunk (checked every param/return property individually) — DKIM's private key is
# server-generated and NEVER returned by any read (the DNS TXT record is PUBLIC by design, not a
# secret); `digest` (customscores only) is an optimistic-concurrency token. All 15 REVIEWED_TRUSTED.
# Was 806 after Wave 9d — PMG mail routing config remainder, extends pmg.py/
# tools/pmg_mail.py per campaign RULING 5): pmg_domain_get, pmg_transport_list,
# pmg_transport_get, pmg_mynetworks_list, pmg_mynetworks_get, pmg_tlspolicy_list,
# pmg_tlspolicy_get, pmg_tls_inbound_domains_list, pmg_mimetypes_list, pmg_regextest (10 reads —
# regextest is POST-verbed but a pure evaluator, classified by EFFECT not verb, so it carries no
# PLAN/confirm ceremony either, same as the other 9 reads) + pmg_domain_update,
# pmg_mynetworks_update (2 LOW comment-only full-replace mutations) + pmg_transport_update
# (1 MEDIUM partial-update mutation, at-least-one-field guard) + pmg_tlspolicy_create,
# pmg_tlspolicy_update, pmg_tlspolicy_delete (3 MEDIUM direction-aware mutations — TLS policy can
# tighten or loosen enforcement depending on the value) + pmg_tls_inbound_domains_create (1 LOW,
# tightens security), pmg_tls_inbound_domains_delete (1 LOW mechanically but LOOSENS security,
# direction called out in the docstring). Exactly the 18 methods classified "chunk": "9d" in
# .scratch/sdd/wave-9-classification.json — no more, no fewer. No secret-shaped field anywhere
# in this chunk (checked every param/return property individually) — all 18 REVIEWED_TRUSTED.
# Was 788 after Wave 9c — PMG LDAP profiles + fetchmail, extends pmg.py/
# tools/pmg_mail.py per campaign RULING 5): pmg_ldap_profiles_list, pmg_ldap_profile_config_get
# (2 reads) + pmg_ldap_profile_create, pmg_ldap_profile_delete, pmg_ldap_profile_config_update,
# pmg_ldap_profile_sync (4 mutations, all MEDIUM) + pmg_ldap_users_list,
# pmg_ldap_user_emails_get, pmg_ldap_groups_list, pmg_ldap_group_members_get (4
# ADVERSARIAL reads — directory-sourced content) + pmg_fetchmail_list, pmg_fetchmail_get (2
# reads, `pass` MANDATORILY stripped — CONFIRMED echoed on both) + pmg_fetchmail_create,
# pmg_fetchmail_update, pmg_fetchmail_delete (3 mutations, all MEDIUM). Secret contract: LDAP
# bindpw never-in-ledger on write + defensive read-strip on the single-profile GET (schema-thin,
# unconfirmed); fetchmail pass MANDATORY read-strip on both reads (schema-rich, confirmed) +
# never-in-ledger on write.
# Was 773 after Wave 9b — PMG node ops odds: task-stop/task-log/task-status,
# report, journal, backup files (list/delete/restore), Postfix queue (list/message-get/action/
# delete-all/delete-queue/message-delete/message-deliver), Postfix address-verify-cache discard,
# ClamAV/SpamAssassin signature-DB reads+updates, and the 4 named service-lifecycle verbs —
# SAME module as 9a, pmg_node.py/tools/pmg_node.py): pmg_node_task_log, pmg_node_task_status,
# pmg_node_report, pmg_node_journal, pmg_node_backup_list, pmg_node_postfix_queue_list,
# pmg_node_postfix_queue_message_get, pmg_node_clamav_database_get,
# pmg_node_spamassassin_rules_get (9 reads) + pmg_node_task_stop, pmg_node_backup_delete,
# pmg_node_backup_restore, pmg_node_postfix_queue_action, pmg_node_postfix_queue_delete_all,
# pmg_node_postfix_queue_delete_queue, pmg_node_postfix_queue_message_delete,
# pmg_node_postfix_queue_message_deliver, pmg_node_postfix_discard_verify_cache,
# pmg_node_clamav_database_update, pmg_node_spamassassin_rules_update, pmg_node_service_start,
# pmg_node_service_stop, pmg_node_service_restart, pmg_node_service_reload (15 mutations).
# Exactly the 24 methods classified "chunk": "9b" in .scratch/sdd/wave-9-classification.json —
# no more, no fewer. Schema-verified divergences/facts from the draft (pmg_node.py module
# docstring's chunk 9b facts, full detail there): (14) pmg_node_task_log is ADVERSARIAL — a
# DIVERGENCE from the draft's own REVIEWED_TRUSTED guess, matching pve_task_log/
# pbs_node_task_log's free-text-log-line precedent instead; pmg_node_task_status stays
# REVIEWED_TRUSTED (no free text). (16) backup filename schema PATTERN
# ('pmg-backup_[0-9A-Za-z_-]+.tgz') diverges from the LIST endpoint's own description prose
# ("proxmox-backup_{DATE}.tgz") — pattern is authoritative. (17)/(18) pmg_node_backup_restore is
# RISK_HIGH with NO undo, reusing pmg.py's own plan_ruledb_reset capture helper verbatim (its
# database=True default replaces the identical ruledb region factory-reset wipes); its
# ambiguous-string return records outcome="submitted" (the more rigorous Wave-9a-established
# standard), a KNOWN, argued divergence from the older pmg_backup_create/pmg_service_control
# tools' "ok" convention for the identical ambiguous-string shape (not silently fixed in those
# other files). (19) the 4 service_start/stop/restart/reload tools hit literally-named schema
# endpoints distinct from the already-shipped generic pmg_service_control dispatcher — built
# anyway since the classification artifact tracks the literal endpoints as their own region.
# (20) pmg_node_service_stop is conditional RISK_HIGH (postfix/pmg-smtp-filter) / RISK_MEDIUM
# (all other services) — RULING 3's conditional-tier precedent, no invented fifth tier. (21)
# pmg_node_postfix_queue_action mirrors pmg.py's own plan_quarantine_action's conditional
# delete=HIGH/deliver=MEDIUM dichotomy exactly. (22) both postfix_queue_delete_all (bare, all 4
# queues) and postfix_queue_delete_queue (one named queue) are RISK_HIGH — "queue-delete-all
# class", unconditional full wipes, unlike the ID-bounded postfix_queue_action/
# _message_delete. (23) postfix_queue_message_deliver is RISK_LOW, mirroring the already-shipped
# pmg_postfix_flush's own LOW rating exactly (same "attempt delivery" semantics, scoped to one
# message). (24) journal's since/until are int|None from the start (PMG's own schema; does NOT
# repeat the logged pre-existing PVE since/until-str bug). (25) no secret-shaped field exists
# anywhere in this chunk's schema — the wave's secret density lives in chunks 9c/9f/9g/9h.
# Taint: 5 ADVERSARIAL (pmg_node_report, pmg_node_journal, pmg_node_task_log,
# pmg_node_postfix_queue_list, pmg_node_postfix_queue_message_get — free-text/mail-metadata
# content) + 19 REVIEWED_TRUSTED (structured metadata/config, ambiguous-string mutation returns
# with no attacker-shapeable content documented). Was 749 after Wave 9a — PMG node core:
# network/dns/time/node-config/certs-info/services/subscription, NEW pmg_node.py/
# tools/pmg_node.py — coordinator RULING 5, pmg.py was already 5409 lines pre-Wave-9):
# pmg_node_network_list, pmg_node_network_get,
# pmg_node_dns_get, pmg_node_time_get, pmg_node_config_get, pmg_node_certificates_info,
# pmg_node_services_list, pmg_node_subscription_get (8 reads) + pmg_node_network_create,
# pmg_node_network_update, pmg_node_network_delete, pmg_node_network_revert,
# pmg_node_network_reload, pmg_node_dns_set, pmg_node_time_set, pmg_node_config_set,
# pmg_node_subscription_set, pmg_node_subscription_check, pmg_node_subscription_delete
# (11 mutations). Exactly the 19 methods classified "chunk": "9a" in
# .scratch/sdd/wave-9-classification.json — no more, no fewer. Schema-verified divergences from
# the draft (`.scratch/sdd/wave-9-draft-decomposition.md` §2 chunk 9a): (1) network create/update
# both require `type` (matches PVE, not PBS's optional) — update auto-injects the CURRENT type via
# a network_get read when the caller omits it, but (unlike PVE's stricter refusal) forwards an
# explicit caller-supplied type as a genuine change, a builder judgment call since nothing in
# PMG's schema documents type as immutable; (2) the network list `?type=` filter enum
# (any_bridge) DIFFERS from the create/update value enum (unknown) — validated against two
# separate sets; (3) `pmg_node_network_revert` rated LOW here, not the draft's guessed MEDIUM —
# functionally identical to PBS's/PVE's own "safe undo, live config untouched" revert, argued
# not silently overridden; (4) `search` is schema-REQUIRED on DNS write (unlike the existing PVE/
# PBS tools on this codebase, which treat it as optional); (5) PMG's node /config is a narrow
# ACME-only block (acme/acmedomain[n]/digest), not PBS's richer general-settings block at the
# same path; (6) `pmg_node_network_reload`'s bare PUT returns a schema-confirmed STRING (not
# null) — whether it's a UPID or a plain status message is unresolved from schema alone and the
# docstring says so; (7) subscription `key` is defensively stripped on read (schema-thin, echo
# unconfirmed either way, mirrors pbs_config.py's `_strip_password` idiom). Taint: all 19
# REVIEWED_TRUSTED — every read is operator-authored structured config (network/dns/time/acme
# domain-mapping/cert public-data/service-list/subscription-status), no attacker-shapeable free
# text on this chunk (postfix queue / journal / report — the ADVERSARIAL candidates on this plane
# — are chunk 9b, not built here). Was 730 after Wave 8b — PMG GLOBAL welcomelist, new
# pmg_welcomelist.py/tools/pmg_welcomelist.py — separate module, no ogroup concept on this plane):
# pmg_welcomelist_objects_list, pmg_welcomelist_object_get (2 reads) +
# pmg_welcomelist_object_add, pmg_welcomelist_object_update, pmg_welcomelist_object_delete
# (3 mutations, coordinator RULING 3: MEDIUM create/update — no bind/activate gate, live
# cluster-wide the instant it lands, argued a tier above the per-user
# pmg_quarantine_welcomelist_add precedent's LOW; LOW delete — removing a bypass is protective,
# an argued asymmetry from ruledb who/what object delete's own MEDIUM). Naming (coordinator
# RULING 5): kept pmg_welcomelist_* (the schema's own vocabulary) despite sitting one word from
# the already-shipped, semantically different pmg_quarantine_welcomelist_add/list/remove
# (per-mailbox quarantine bypass) — mandatory disambiguation lines added to both families'
# docstrings, including a doc-only reverse-cross-reference diff on the 3 shipped
# pmg_quarantine_welcomelist_* tools in tools/pmg_mail.py. Every typed-object GET/list-all is
# schema-thin ({id: <type>} only) — docstrings say so, no richer return-shape invented. Was 725
# after Wave 8a — PMG ruledb per-object reads + ldapuser + the direct
# rule<->action-group read + RuleDB factory reset, new pmg.py W6a section +
# tools/pmg_rules.py): pmg_who_object_get, pmg_what_object_get, pmg_when_object_get,
# pmg_action_bcc_get, pmg_action_field_get, pmg_action_notification_get,
# pmg_action_disclaimer_get, pmg_action_removeattachments_get,
# pmg_ruledb_rule_action_groups_list (9 reads) + pmg_ruledb_reset (1 mutation, RISK_HIGH — the
# wave's only above-MEDIUM rating, coordinator RULING 1: build it, plan CAPTURES current scope +
# states "no undo" as its first line). PLUS 2 signature extensions (NOT counted as new tools):
# pmg_who_object_add/pmg_who_object_update gain type_='ldapuser' + an 'account' kwarg
# (additive-compat — the 6 pre-existing type values and their tests are unchanged). Naming
# (coordinator RULING 2): pmg_ruledb_rule_action_groups_list deliberately breaks sibling-naming
# symmetry with from_list/to_list/what_list/when_list to avoid a one-letter typo collision with
# the already-shipped, differently-shaped pmg_ruledb_rule_actions_list (plural — reads /config
# and extracts an embedded, unverified 'action' key; this new tool reads the direct singular
# /config/ruledb/rules/{id}/action endpoint instead). Every per-object GET on this whole region
# is schema-thin ({id: <type>} only) — docstrings say so, no richer return-shape invented. Was
# 715 after Wave 7d — SDN fabrics, the FINAL chunk of Wave 7, new
# sdn_fabrics.py/tools/pve_sdn_fabrics.py): pve_sdn_fabrics_all, pve_sdn_fabrics_list,
# pve_sdn_fabric_get, pve_sdn_fabric_nodes_list_all, pve_sdn_fabric_nodes_list,
# pve_sdn_fabric_node_get, pve_sdn_fabric_status_interfaces, pve_sdn_fabric_status_neighbors,
# pve_sdn_fabric_status_routes (9 reads) + pve_sdn_fabric_create, pve_sdn_fabric_update,
# pve_sdn_fabric_delete, pve_sdn_fabric_node_create, pve_sdn_fabric_node_update,
# pve_sdn_fabric_node_delete (6 mutations). 3 confirmed upstream copy-paste description bugs
# on this family (GET fabric/{id} says "Update a fabric", DELETE fabric/{id} says "Add a
# fabric", DELETE node says "Add a node") — trusted verb/params/returns throughout, never the
# description string. fabric/fabric-node DELETE accept NEITHER digest NOR lock-token — the
# only delete family on the whole SDN plane with zero optimistic-lock support (schema-
# verified). fabric/fabric-node UPDATE require restating `protocol` in the body (unlike
# controller/dns/ipam's own immutable-and-absent `type`). fabric_status_interfaces is
# REVIEWED_TRUSTED (local, not peer-controlled); neighbors/routes are ADVERSARIAL
# (wire-learned FRR-reported content) — see taint.py's own entry comment. This CLOSES Wave 7
# (7a+7b+7c+7d+7e = 12+10+16+15+17 = 70 new tools + 1 signature extension, 645 -> 715).
# Was 700 after Wave 7e — SDN prefix-lists + route-maps, new
# sdn_routing.py/tools/pve_sdn_routing.py): pve_sdn_prefix_lists_list, pve_sdn_prefix_list_get,
# pve_sdn_prefix_list_entries_list, pve_sdn_prefix_list_entry_get, pve_sdn_route_maps_list,
# pve_sdn_route_map_entries_list_all, pve_sdn_route_map_entries_list, pve_sdn_route_map_entry_get
# (8 reads) + pve_sdn_prefix_list_create, pve_sdn_prefix_list_update, pve_sdn_prefix_list_delete,
# pve_sdn_prefix_list_entry_create, pve_sdn_prefix_list_entry_update,
# pve_sdn_prefix_list_entry_delete, pve_sdn_route_map_entry_create, pve_sdn_route_map_entry_update,
# pve_sdn_route_map_entry_delete (9 mutations). `url_seq` (prefix-list entry path segment) is an
# OPAQUE, schema-untyped token — never validated as an integer, unlike route-map's own `order`
# (a properly-typed required integer 0-65535 on all 3 of its methods). Route-maps have NO
# container-level create/update/delete — only entries (the first entry_create for an id
# implicitly creates the route map). No secret-shaped field on this plane (unlike Wave 7c's dns
# key/ipam token) — REVIEWED_TRUSTED throughout. Was 683 after Wave 7c — SDN controllers + DNS +
# IPAMs, new
# sdn_objects.py/tools/pve_sdn_objects.py): pve_sdn_controllers_list, pve_sdn_controller_get,
# pve_sdn_dns_list, pve_sdn_dns_get, pve_sdn_ipams_list, pve_sdn_ipam_get,
# pve_sdn_ipam_status (7 reads) + pve_sdn_controller_create, pve_sdn_controller_update,
# pve_sdn_controller_delete, pve_sdn_dns_create, pve_sdn_dns_update, pve_sdn_dns_delete,
# pve_sdn_ipam_create, pve_sdn_ipam_update, pve_sdn_ipam_delete (9 mutations). `type` is
# immutable after creation across all three families; dns `key`/ipam `token` are secrets
# (redacted in plan/ledger CAPTURE, never at the read layer — see sdn_objects.py's module
# docstring RULING). Was 667 after Wave 7b — vnet-scoped firewall + IP mappings, new
# sdn_firewall.py/tools/pve_sdn_firewall.py): pve_sdn_vnet_firewall_options_get,
# pve_sdn_vnet_firewall_rules_list, pve_sdn_vnet_firewall_rule_get (3 reads) +
# pve_sdn_vnet_firewall_options_set, pve_sdn_vnet_firewall_rule_add,
# pve_sdn_vnet_firewall_rule_update, pve_sdn_vnet_firewall_rule_remove,
# pve_sdn_vnet_ip_create, pve_sdn_vnet_ip_update, pve_sdn_vnet_ip_delete (7 mutations).
# LIVE/IMMEDIATE family — no pending/apply lifecycle, no sdn-rollback coverage. Was 657
# after Wave 7a — PVE SDN gap-fill + global control plane):
# pve_sdn_zone_get, pve_sdn_vnet_get, pve_sdn_subnet_get, pve_sdn_dry_run,
# pve_sdn_zone_status_list, pve_sdn_zone_bridges, pve_sdn_zone_content, pve_sdn_zone_ip_vrf,
# pve_sdn_vnet_mac_vrf (9 reads) + pve_sdn_lock_acquire, pve_sdn_lock_release, pve_sdn_rollback
# (3 mutations). pve_sdn_apply also gained optional lock_token/release_lock params — a
# signature extension on an EXISTING tool, not counted as a new one. Was 645 after Wave 6d —
# PVE Ceph pools + CephFS, CLOSES Wave 6):
# pve_ceph_pool_list, pve_ceph_pool_status, pve_ceph_fs_list (3 reads) + pve_ceph_pool_create,
# pve_ceph_pool_set, pve_ceph_pool_destroy, pve_ceph_fs_create, pve_ceph_fs_destroy
# (5 mutations). Was 637 after Wave 6c — PVE Ceph OSD): pve_ceph_osd_tree, pve_ceph_osd_lv_info,
# pve_ceph_osd_metadata (3 reads) + pve_ceph_osd_create, pve_ceph_osd_destroy, pve_ceph_osd_in,
# pve_ceph_osd_out, pve_ceph_osd_scrub (5 mutations). Was 629 after Wave 6b — PVE Ceph services
# lifecycle: pve_ceph_mon_list,
# pve_ceph_mgr_list, pve_ceph_mds_list (3 reads) + pve_ceph_mon_create, pve_ceph_mon_destroy,
# pve_ceph_mgr_create, pve_ceph_mgr_destroy, pve_ceph_mds_create, pve_ceph_mds_destroy,
# pve_ceph_init, pve_ceph_service_start, pve_ceph_service_stop, pve_ceph_service_restart
# (10 mutations). Was 616 after Wave 6a (PVE Ceph core observability + flags, the first Ceph
# chunk): pve_ceph_status, pve_ceph_metadata, pve_ceph_flags_list, pve_ceph_flag_get,
# pve_ceph_cfg_db, pve_ceph_cfg_raw, pve_ceph_cfg_value, pve_ceph_crush, pve_ceph_log,
# pve_ceph_rules, pve_ceph_cmd_safety (11 reads) + pve_ceph_flags_set, pve_ceph_flag_set
# (2 mutations). Was 603 after Wave 5d — the ACTUAL PBS plane closer, built from the Wave 5c
# adversarial review's Finding 1+2 missing-endpoint list): pbs_groups_list, pbs_group_delete,
# pbs_group_notes_{get,set}, pbs_group_move, pbs_snapshot_protected_get, pbs_namespace_move,
# pbs_datastore_{mount,unmount,prune,s3_refresh,rrd,active_operations}, pbs_datastores_usage,
# pbs_remote_scan, pbs_remote_scan_{groups,namespaces}. Was 586 after Wave 5c's
# +13: pbs_admin_{gc,prune,sync,verify}_jobs_list,
# pbs_admin_traffic_control_status, pbs_node_{config_get,config_set,identity,rrd,report},
# pbs_version, pbs_pull, pbs_push — PBS admin job views + node odds + pull/push, Wave 5c
# (CLOSES Wave 5 / the PBS plane). The task brief estimated ~17; 3 were dedup'd against the
# already-shipped generic pbs_job_run(job_type, job_id) (which already covers
# /admin/{prune,sync,verify}/{id}/run) and 1 (/ping) was skipped per the brief's own default —
# see pbs_admin.py module docstring's NOT BUILT section. Was 573 after Wave 5b's +12:
# pbs_metrics_servers_list, pbs_metrics_status,
# pbs_metrics_influxdb_http_{list,get,create,update,delete},
# pbs_metrics_influxdb_udp_{list,get,create,update,delete} — PBS metrics servers, Wave 5b
# (continues Wave 5, closes the PBS plane after 5c). Was 561 after Wave 5a's +12:
# pbs_s3_{client_list,client_get,client_create,client_update,client_delete,list_buckets,check,
# reset_counters} + pbs_encryption_key_{list,create,delete,toggle_archive} — PBS S3 client
# configs + client encryption keys (starts Wave 5). Was 549 after Wave 4d's +15:
# pbs_tape_media_{list,content,sets,status_get,destroy,status_set,move} +
# pbs_tape_backup_job_{list,get,create,update,delete,run} + pbs_tape_backup + pbs_tape_restore —
# PBS tape media catalog + tape-backup jobs + backup/restore (CLOSES Wave 4: PBS tape).

_TOOLS_DIR = Path(__file__).resolve().parent.parent / "src" / "proximo" / "tools"
_SOURCE_FILES = [Path(server.__file__), *sorted(_TOOLS_DIR.glob("*.py"))]
_SERVER_SRC = "\n".join(p.read_text(encoding="utf-8") for p in _SOURCE_FILES)
# A real decorator: the line, after optional indentation, starts with `@mcp.tool(`. The
# line-start anchor (not the parens) is what excludes the backtick-wrapped mention inside
# the module docstring; matching `@mcp.tool(` rather than `@mcp.tool()` also stays correct
# if a tool is ever registered with an explicit name= argument.
# Matches both the plain FastMCP decorator (@mcp.tool(...)) and the target-aware wrapper
# (@tool(...)) that wraps it for multi-target — both register exactly one exposed tool.
_DECORATOR_RE = re.compile(r"^[ \t]*@(?:mcp\.)?tool\(", re.MULTILINE)


def _exposed_tools() -> list[str]:
    return [t.name for t in asyncio.run(server.mcp.list_tools())]


def test_exposed_tool_count_is_pinned():
    names = _exposed_tools()
    assert len(names) == EXPECTED_TOOL_COUNT, (
        f"tool surface changed: registry exposes {len(names)}, expected "
        f"{EXPECTED_TOOL_COUNT}. If intentional, bump EXPECTED_TOOL_COUNT and the count "
        f"in README.md / CHANGELOG.md / CLAUDE.md."
    )


def test_no_silently_shadowed_tools():
    """Every @mcp.tool() decorator must yield a distinct exposed tool.

    The registry is name-keyed, so a same-name collision never shows up as a *duplicate* —
    it shows up as a *missing* entry. So the meaningful guard is decorator-lines == exposed
    count; if two decorators share a name, one is dropped and this assertion fires.
    """
    names = _exposed_tools()
    decorator_count = len(_DECORATOR_RE.findall(_SERVER_SRC))
    assert decorator_count == len(names), (
        f"{decorator_count} @mcp.tool() decorators but only {len(names)} tools exposed — "
        f"a tool name collides and is being silently shadowed (lost tool)."
    )


def test_readme_surface_subset_counts_are_real():
    """A `PROXIMO_SURFACES=<spec>` example that quotes a tool count must quote the TRUE one.

    `copy_ripple_check.check_tool_counts` deliberately skips these lines (_EXAMPLE_MARKERS),
    and rightly so: a scoped subset is not the canonical total, so comparing it to the full
    surface would be a guaranteed false positive. But skipping is all it did — nothing then
    checked the subset claim, so README's "PROXIMO_SURFACES=pve,exec (that pair = 202 tools)"
    sat at 202 while the real answer grew to 314. Off by 112, in the file every MCP directory
    scrapes.

    The exemption stays (it is correct). This is the check that should have stood behind it:
    resolve the spec through the same `surface_keep` the server uses at startup and compare.
    """
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text()
    names = _exposed_tools()
    spec_re = re.compile(r"PROXIMO_SURFACES=([a-z0-9,_-]+)")
    count_re = re.compile(r"(?<!\+)\b(\d{2,4}) (?:MCP )?tools\b")

    checked = 0
    for line in readme.splitlines():
        spec = spec_re.search(line)
        claim = count_re.search(line)
        if not (spec and claim):
            continue
        checked += 1
        actual = len(door.surface_keep(names, spec.group(1)))
        assert int(claim.group(1)) == actual, (
            f"README claims PROXIMO_SURFACES={spec.group(1)} yields {claim.group(1)} tools, "
            f"but surface_keep resolves {actual}. Refresh the worked example with the "
            f"release ripple — this line is exempt from check_tool_counts by design."
        )
    assert checked, (
        "no PROXIMO_SURFACES example with a tool count found in README.md — if the worked "
        "example was removed, drop this test; do not let it pass vacuously."
    )
