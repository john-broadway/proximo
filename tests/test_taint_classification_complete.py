"""Completeness guard: EVERY tool registered on the live MCP surface is classified one way or
the other — adversarial (`taint.ADVERSARIAL_TOOLS`) or explicitly reviewed-trusted
(`REVIEWED_TRUSTED` below). This is the anti-fail-open backstop the design doc calls for
(`.scratch/taint-design-v2-2026-07-02.md` §Component 0): classification is a curated set, so an
adversarial channel added later and never classified is a real gap — this test makes an
UNCLASSIFIED/UNREVIEWED tool fail CI, not fail-open at runtime.

`REVIEWED_TRUSTED` was generated once from the live registry (`set(names) - ADVERSARIAL_TOOLS`)
and hand-spot-checked: it contains only structured-return / operator-authored-content tools
(status/config-CRUD/list-of-ids surfaces), no free-text guest/external channel. Notably absent
from it (because they're correctly in `taint.ADVERSARIAL_TOOLS` instead): `ct_exec`, `ct_psql`,
`ct_logs`, `ct_diagnose`, `pve_agent_exec`, `pve_agent_info`, `pve_agent_file_read`, and the
`pmg_quarantine_*`/`pmg_tracker_*` email-content tools.

When this test fails after adding a tool: classify it. Guest/log/quarantine/free-text-external
content -> add to `taint.ADVERSARIAL_TOOLS`. Structured, operator-authored, no attacker-shapeable
free text -> add to `REVIEWED_TRUSTED` below. Do not add to `REVIEWED_TRUSTED` just to make the
test pass — that's exactly the fail-open path this test exists to block.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import proximo.server as server
from proximo import taint

# Generated once via `set(names) - taint.ADVERSARIAL_TOOLS` against the live registry
# (352 tools, 2026-07-02), then hand-reviewed. Keep sorted for readable diffs.
REVIEWED_TRUSTED: frozenset[str] = frozenset({
    # proximo_call is a DISPATCHER, not a reader: it carries no bytes of its own, it returns
    # whatever the inner tool returned, and the inner tool's OWN classification is what fires.
    # Verified against a control rather than reasoned — calling pve_list_guests directly and
    # calling it by name through the hatch both taint, and both name `pve_list_guests`, never
    # `proximo_call` (the marker is written in _audited on the name it is called with, and
    # dispatch runs the decorated wrapper). Pinned by
    # tests/test_escape_hatch.py::test_taint_fires_with_the_INNER_tool_name_through_the_hatch.
    #
    # Classifying it adversarial would be strictly WRONG, not merely cautious: it would taint
    # every by-name call including pure reads of operator-authored config, and it would
    # attribute untrusted bytes to the dispatcher instead of to the tool that actually carried
    # them — losing the one fact taint_sources() exists to record.
    'proximo_call',
    'audit_verify', 'pbs_acl_get', 'pbs_acl_update',
    'pbs_acme_account_create', 'pbs_acme_account_delete', 'pbs_acme_account_get',
    'pbs_acme_account_list', 'pbs_acme_account_update', 'pbs_acme_cert_order',
    'pbs_acme_cert_renew', 'pbs_acme_challenge_schema', 'pbs_acme_directories',
    'pbs_acme_plugin_create', 'pbs_acme_plugin_delete', 'pbs_acme_plugin_get',
    'pbs_acme_plugin_update', 'pbs_acme_plugins_list',
    # NOT 'pbs_acme_tos' — Wave 3b review reclassified it ADVERSARIAL (caller-chosen URL
    # fetched by the PBS host; response text is attacker-shapeable).
    'pbs_apt_repositories_get', 'pbs_apt_repository_add',
    'pbs_apt_repository_set', 'pbs_apt_update_refresh', 'pbs_apt_updates_list', 'pbs_apt_versions',
    'pbs_datastore_create', 'pbs_datastore_delete', 'pbs_datastore_get', 'pbs_datastore_status',
    'pbs_datastore_update', 'pbs_datastores_list', 'pbs_gc_start', 'pbs_gc_status', 'pbs_group_change_owner',
    'pbs_job_create', 'pbs_job_delete', 'pbs_job_run', 'pbs_job_update', 'pbs_jobs_list', 'pbs_namespace_create',
    'pbs_namespace_delete', 'pbs_namespaces_list',
    'pbs_node_cert_delete', 'pbs_node_cert_upload', 'pbs_node_certificates_list',
    'pbs_node_disk_directory_create', 'pbs_node_disk_directory_delete', 'pbs_node_disk_directory_list',
    'pbs_node_disk_initgpt', 'pbs_node_disk_smart', 'pbs_node_disk_wipe',
    'pbs_node_disk_zfs_create', 'pbs_node_disk_zfs_get', 'pbs_node_disk_zfs_list', 'pbs_node_disks_list',
    'pbs_node_dns_get', 'pbs_node_dns_set', 'pbs_node_network_iface_create',
    'pbs_node_network_iface_delete', 'pbs_node_network_iface_get', 'pbs_node_network_iface_update',
    'pbs_node_network_list', 'pbs_node_network_reload', 'pbs_node_network_revert',
    'pbs_node_service_control', 'pbs_node_service_status', 'pbs_node_services_list',
    'pbs_node_status', 'pbs_node_subscription_check', 'pbs_node_subscription_delete',
    'pbs_node_subscription_get', 'pbs_node_subscription_set', 'pbs_node_task_status',
    'pbs_node_task_stop', 'pbs_node_time_get', 'pbs_node_time_set',
    'pbs_notification_endpoint_create', 'pbs_notification_endpoint_delete',
    'pbs_notification_endpoint_get', 'pbs_notification_endpoint_list',
    'pbs_notification_endpoint_update',
    'pbs_notification_matcher_delete', 'pbs_notification_matcher_field_values',
    'pbs_notification_matcher_fields', 'pbs_notification_matcher_get',
    'pbs_notification_matcher_set', 'pbs_notification_matchers_list',
    'pbs_notification_target_test', 'pbs_notification_targets_list',
    'pbs_permissions_get', 'pbs_prune',
    'pbs_realm_ad_create', 'pbs_realm_ad_delete', 'pbs_realm_ad_get', 'pbs_realm_ad_list',
    'pbs_realm_ad_update', 'pbs_realm_ldap_create', 'pbs_realm_ldap_delete', 'pbs_realm_ldap_get',
    'pbs_realm_ldap_list', 'pbs_realm_ldap_update', 'pbs_realm_openid_create',
    'pbs_realm_openid_delete', 'pbs_realm_openid_get', 'pbs_realm_openid_list',
    'pbs_realm_openid_update', 'pbs_realm_pam_get', 'pbs_realm_pam_set', 'pbs_realm_pbs_get',
    'pbs_realm_pbs_set', 'pbs_realm_sync',
    'pbs_remote_create', 'pbs_remote_delete', 'pbs_remote_get', 'pbs_remote_update', 'pbs_remotes_list',
    'pbs_roles_list', 'pbs_snapshot_delete',
    'pbs_snapshot_notes_set', 'pbs_snapshot_protected_set',
    # Wave 4a (2026-07-15): PBS tape hardware config (drive/changer CRUD) — structured,
    # operator-authored config, no attacker-shapeable free text. The two scan reads carry
    # device-reported vendor/model/serial strings — hardware-authored, matching the precedent
    # already set by pve_hardware_list / pbs_node_disks_list / pbs_node_disk_smart (all three
    # also REVIEWED_TRUSTED despite carrying autodetected hardware fields).
    'pbs_tape_changer_create', 'pbs_tape_changer_delete', 'pbs_tape_changer_get',
    'pbs_tape_changer_list', 'pbs_tape_changer_update',
    'pbs_tape_drive_create', 'pbs_tape_drive_delete', 'pbs_tape_drive_get',
    'pbs_tape_drive_list', 'pbs_tape_drive_update',
    'pbs_tape_scan_changers', 'pbs_tape_scan_drives',
    # Wave 4b (2026-07-15): PBS tape media-pool + encryption-key config — same rationale as
    # Wave 4a above: structured, operator-authored config, no attacker-shapeable free text.
    # comment/hint/template are operator-authored free-text fields, same category as
    # pbs_notifications.py's own comment fields (already REVIEWED_TRUSTED), not an external/
    # guest-authored channel. Encryption-key reads return PUBLIC metadata only (never key
    # material/password — schema-verified, pbs_tape_media.py module docstring fact #9).
    'pbs_tape_key_create', 'pbs_tape_key_delete', 'pbs_tape_key_get', 'pbs_tape_key_list',
    'pbs_tape_key_update_password',
    'pbs_tape_pool_create', 'pbs_tape_pool_delete', 'pbs_tape_pool_get', 'pbs_tape_pool_list',
    'pbs_tape_pool_update',
    # Wave 4c (2026-07-15): PBS tape drive/changer OPERATIONS. Reads: drive status/
    # volume-statistics are pure device telemetry — no label-text field in either response
    # (unlike read-label/inventory/cartridge-memory/changer_status, which ARE in
    # taint.ADVERSARIAL_TOOLS instead — see pbs_tape_ops.py module docstring's Taint section).
    # Mutations: all 13 return either an opaque UPID (task identifier, PBS-generated) or null —
    # none echo back media-authored free text, so all are REVIEWED_TRUSTED regardless of their
    # real-world physical/robotics side effects (taint classifies the RETURN channel, not the
    # mutation's physical consequences).
    'pbs_tape_drive_status', 'pbs_tape_drive_volume_statistics',
    'pbs_tape_drive_load_media', 'pbs_tape_drive_load_slot', 'pbs_tape_drive_unload',
    'pbs_tape_drive_eject', 'pbs_tape_drive_rewind', 'pbs_tape_drive_clean',
    'pbs_tape_drive_inventory_update', 'pbs_tape_drive_label_media',
    'pbs_tape_drive_barcode_label_media', 'pbs_tape_drive_format', 'pbs_tape_drive_catalog',
    'pbs_tape_drive_restore_key', 'pbs_tape_changer_transfer',
    # Wave 4d (2026-07-15): PBS tape media CATALOG + tape-backup JOBS + backup/restore — CLOSES
    # Wave 4 (PBS tape). Reads: pbs_tape_media_sets carries NO label-text field at all (confirmed
    # field-by-field against the live schema — media-set-name is PBS-generated from the pool's
    # operator-authored template, not physical-media content; a deliberate divergence from the
    # campaign brief's own premise, argued in pbs_tape_jobs.py's module docstring). NOT here:
    # pbs_tape_media_list/pbs_tape_media_content/pbs_tape_media_status_get — all three are in
    # taint.ADVERSARIAL_TOOLS instead. pbs_tape_backup_job_list/get are operator-authored
    # scheduled-job config, matching pve_backup_job_list/create's existing REVIEWED_TRUSTED
    # classification. Mutations: all 9 return either an opaque UPID or null — none echo back
    # media/guest-authored free text, including pbs_tape_media_destroy (a GET-verb mutation —
    # taint classifies the RETURN channel, not the HTTP verb or the mutation's consequences,
    # same rule Wave 4c's 13 mutations already established).
    'pbs_tape_media_sets', 'pbs_tape_backup_job_list', 'pbs_tape_backup_job_get',
    'pbs_tape_media_destroy', 'pbs_tape_media_status_set', 'pbs_tape_media_move',
    'pbs_tape_backup_job_create', 'pbs_tape_backup_job_update', 'pbs_tape_backup_job_delete',
    'pbs_tape_backup_job_run', 'pbs_tape_backup', 'pbs_tape_restore',
    # Wave 5a (2026-07-15): PBS S3 client configs + client encryption keys — starts Wave 5
    # (closes the PBS plane after 5c). Reads: pbs_s3_client_list/get are operator-authored config
    # ("without secret" per the live schema — access-key is a non-secret identifier, secret-key
    # never returned); pbs_encryption_key_list is operator/import-authored metadata, no key
    # material ever returned. NOT here: pbs_s3_list_buckets — in taint.ADVERSARIAL_TOOLS instead
    # (externally-authored bucket-name content). Mutations: all 8 return null (opaque, no
    # content) — pbs_s3_check/pbs_s3_reset_counters are confirm-gated PUT-verb tools with a real
    # (check) or observability-only (reset_counters) effect but carry no return content either.
    'pbs_s3_client_list', 'pbs_s3_client_get', 'pbs_s3_client_create', 'pbs_s3_client_update',
    'pbs_s3_client_delete', 'pbs_s3_check', 'pbs_s3_reset_counters',
    'pbs_encryption_key_list', 'pbs_encryption_key_create', 'pbs_encryption_key_delete',
    'pbs_encryption_key_toggle_archive',
    # Wave 5b (2026-07-15): PBS metrics servers — operator-authored config on both influxdb-http
    # and influxdb-udp sub-planes; all mutations return null (opaque, no content).
    # pbs_metrics_influxdb_http_list/get strip `token` at the read layer (a REQUIRED strip — the
    # live schema's response shape DOES carry it, unlike pbs_s3's documented-secret-free reads) —
    # once stripped, the remaining shape is the same operator-authored config category as every
    # other PBS config-CRUD read. pbs_metrics_servers_list is schema-enforced secret-free
    # (additionalProperties: false, 5 fields, no token property can appear at all).
    # pbs_metrics_status is server-authored numeric telemetry (host/datastore performance
    # metrics) — matches the pve_node_rrddata/pmg_node_rrddata REVIEWED_TRUSTED precedent, argued
    # explicitly in pbs_metrics.py's module docstring (NOT the externally-authored-content
    # precedent that landed pbs_s3_list_buckets in taint.ADVERSARIAL_TOOLS instead).
    # proximo_baseline returns numeric distribution rollups (n/mean/p50/p95/max) computed
    # server-side from rrddata plus advisory strings the SERVER composes from those numbers —
    # no attacker-shapeable free text is echoed (guest names/tags are NOT in its output; the
    # memory tool that re-serves those, proximo_recall, is in taint.ADVERSARIAL_TOOLS).
    # Matches the pve_node_rrddata/pmg_node_rrddata numeric-telemetry precedent.
    'proximo_baseline',
    'pbs_metrics_servers_list', 'pbs_metrics_status',
    'pbs_metrics_influxdb_http_list', 'pbs_metrics_influxdb_http_get',
    'pbs_metrics_influxdb_http_create', 'pbs_metrics_influxdb_http_update',
    'pbs_metrics_influxdb_http_delete',
    'pbs_metrics_influxdb_udp_list', 'pbs_metrics_influxdb_udp_get',
    'pbs_metrics_influxdb_udp_create', 'pbs_metrics_influxdb_udp_update',
    'pbs_metrics_influxdb_udp_delete',
    # Wave 5c (2026-07-15): PBS admin job views + node odds + pull/push — CLOSES the PBS plane.
    # Admin job-view LISTs carry job comment/schedule (operator-authored config), matching
    # pbs_jobs_list's existing REVIEWED_TRUSTED precedent — argued explicitly in pbs_admin.py's
    # module docstring Taint section, not defaulted. traffic-control status = live counters
    # (cur-rate-in/cur-rate-out) + operator rule config, no attacker-shapeable free text.
    # node_config_get/set = structured operator config (http-proxy is defensively masked for any
    # embedded userinfo credential before it can reach a Plan/ledger surface — see pbs_admin.py
    # module docstring fact #10 — so even that genuinely-ambiguous field never lands unredacted).
    # node_identity = a single machine-derived identifier. node_rrd = server-authored numeric
    # telemetry, matches the pve_node_rrddata/pmg_node_rrddata/pbs_metrics_status precedent.
    # version = fixed version-identity strings. pull/push both declare returns:null (no content
    # channel to classify) — matches pbs_s3_check/pbs_s3_reset_counters's identical reasoning.
    # NOT here: pbs_node_report — in taint.ADVERSARIAL_TOOLS instead (free-text diagnostic
    # bundle, same category as pve_node_syslog/pbs_node_journal/pbs_node_task_log).
    'pbs_admin_gc_jobs_list', 'pbs_admin_prune_jobs_list', 'pbs_admin_sync_jobs_list',
    'pbs_admin_verify_jobs_list', 'pbs_admin_traffic_control_status',
    'pbs_node_config_get', 'pbs_node_config_set', 'pbs_node_identity', 'pbs_node_rrd',
    'pbs_version', 'pbs_pull', 'pbs_push',
    # Wave 5d (2026-07-15): PBS datastore-admin remainder — the ACTUAL plane closer.
    # snapshot_protected_get: argued via its paired write-half's schema-typed boolean (against
    # the media_status_get conservative default — see pbs_datastore_admin.py fact #7).
    # datastore_rrd/active_operations/datastores_usage: numeric/typed server telemetry
    # (rrddata + datastore_status precedents). Mutations: group_delete returns a closed-shape
    # counter object; group_notes_set returns null; the other six return opaque UPIDs — no
    # content channel. NOT here: pbs_groups_list, pbs_group_notes_get, pbs_remote_scan,
    # pbs_remote_scan_groups, pbs_remote_scan_namespaces — all in taint.ADVERSARIAL_TOOLS
    # (guest-influenced ids/notes; remote-authored scan content).
    'pbs_snapshot_protected_get', 'pbs_datastore_rrd', 'pbs_datastore_active_operations',
    'pbs_datastores_usage',
    'pbs_group_delete', 'pbs_group_notes_set', 'pbs_group_move', 'pbs_namespace_move',
    'pbs_datastore_mount', 'pbs_datastore_unmount', 'pbs_datastore_prune',
    'pbs_datastore_s3_refresh',
    'pbs_tasks_list',
    'pbs_tfa_add', 'pbs_tfa_delete', 'pbs_tfa_entry_get', 'pbs_tfa_list', 'pbs_tfa_unlock',
    'pbs_tfa_update', 'pbs_tfa_user_get', 'pbs_tfa_webauthn_get', 'pbs_tfa_webauthn_set',
    'pbs_token_create',
    'pbs_token_delete', 'pbs_token_update', 'pbs_traffic_control_delete',
    'pbs_traffic_control_upsert', 'pbs_traffic_controls_list', 'pbs_user_create', 'pbs_user_delete',
    'pbs_user_get', 'pbs_user_token_get', 'pbs_user_tokens_list', 'pbs_user_update', 'pbs_users_list',
    'pbs_verify_start', 'pdm_acl_list',
    'pdm_node_status', 'pdm_pbs_datastores_list', 'pdm_pbs_remote_status', 'pdm_pbs_snapshots_list', 'pdm_ping',
    'pdm_pve_cluster_status', 'pdm_pve_lxc_migrate', 'pdm_pve_lxc_power',
    'pdm_pve_lxc_remote_migrate', 'pdm_pve_lxc_snapshot_create', 'pdm_pve_lxc_snapshot_delete',
    'pdm_pve_lxc_snapshot_rollback', 'pdm_pve_node_list', 'pdm_pve_qemu_migrate',
    'pdm_pve_qemu_power', 'pdm_pve_qemu_remote_migrate', 'pdm_pve_qemu_snapshot_create',
    'pdm_pve_qemu_snapshot_delete', 'pdm_pve_qemu_snapshot_rollback', 'pdm_remote_config_get',
    'pdm_remote_version', 'pdm_remotes_list', 'pdm_resources_list', 'pdm_resources_status', 'pdm_roles_list',
    'pdm_tasks_list', 'pdm_users_list', 'pdm_version', 'pmg_action_bcc_create', 'pmg_action_bcc_update',
    'pmg_action_delete', 'pmg_action_disclaimer_create', 'pmg_action_disclaimer_update', 'pmg_action_field_create',
    'pmg_action_field_update', 'pmg_action_notification_create', 'pmg_action_notification_update',
    'pmg_action_objects_list', 'pmg_action_removeattachments_create', 'pmg_action_removeattachments_update',
    'pmg_apt_repositories_get', 'pmg_apt_repository_add', 'pmg_apt_repository_set',
    'pmg_apt_update_refresh', 'pmg_apt_updates_list', 'pmg_apt_versions',
    'pmg_backup_create', 'pmg_doctor', 'pmg_domain_create', 'pmg_domain_delete', 'pmg_domains_list',
    'pmg_mynetworks_add', 'pmg_mynetworks_remove', 'pmg_node_rrddata', 'pmg_node_status', 'pmg_postfix_flush',
    'pmg_postfix_qshape', 'pmg_quarantine_action', 'pmg_quarantine_blocklist_add',
    'pmg_quarantine_blocklist_remove', 'pmg_quarantine_welcomelist_add', 'pmg_quarantine_welcomelist_remove',
    'pmg_relay_config', 'pmg_ruledb_digest', 'pmg_ruledb_rule_action_attach', 'pmg_ruledb_rule_action_detach',
    'pmg_ruledb_rule_actions_list', 'pmg_ruledb_rule_create', 'pmg_ruledb_rule_delete',
    'pmg_ruledb_rule_from_attach', 'pmg_ruledb_rule_from_detach', 'pmg_ruledb_rule_from_list',
    'pmg_ruledb_rule_get', 'pmg_ruledb_rule_to_attach', 'pmg_ruledb_rule_to_detach', 'pmg_ruledb_rule_to_list',
    'pmg_ruledb_rule_update', 'pmg_ruledb_rule_what_attach', 'pmg_ruledb_rule_what_detach',
    'pmg_ruledb_rule_what_list', 'pmg_ruledb_rule_when_attach', 'pmg_ruledb_rule_when_detach',
    'pmg_ruledb_rule_when_list', 'pmg_ruledb_rules_list', 'pmg_service_control', 'pmg_service_status',
    'pmg_spam_config', 'pmg_spam_config_update', 'pmg_statistics_mail',
    'pmg_statistics_mailcount', 'pmg_statistics_recent', 'pmg_statistics_spamscores', 'pmg_statistics_virus',
    'pmg_tasks_list', 'pmg_transport_create', 'pmg_transport_delete', 'pmg_what_group_create',
    'pmg_what_group_delete', 'pmg_what_group_get', 'pmg_what_group_objects', 'pmg_what_group_update',
    'pmg_what_groups_list', 'pmg_what_object_add', 'pmg_what_object_delete', 'pmg_what_object_update',
    'pmg_when_group_create', 'pmg_when_group_delete', 'pmg_when_group_get', 'pmg_when_group_objects',
    'pmg_when_group_update', 'pmg_when_groups_list', 'pmg_when_object_add', 'pmg_when_object_delete',
    'pmg_when_object_update', 'pmg_who_group_create', 'pmg_who_group_delete', 'pmg_who_group_get',
    'pmg_who_group_objects', 'pmg_who_group_update', 'pmg_who_groups_list', 'pmg_who_object_add',
    'pmg_who_object_delete', 'pmg_who_object_update', 'pve_acl_list', 'pve_acl_modify', 'pve_acl_prune',
    'pve_acme_account_create', 'pve_acme_account_delete', 'pve_acme_account_update', 'pve_acme_cert_order',
    'pve_acme_cert_renew', 'pve_acme_cert_revoke', 'pve_acme_plugin_create', 'pve_acme_plugin_delete',
    'pve_acme_plugin_update', 'pve_agent_file_write', 'pve_agent_fs', 'pve_agent_set_password',
    'pve_apt_repositories_get', 'pve_apt_repository_add', 'pve_apt_repository_set',
    'pve_apt_update_refresh', 'pve_apt_updates_list', 'pve_apt_versions', 'pve_backup',
    'pve_backup_delete', 'pve_backup_job_create', 'pve_backup_job_delete', 'pve_backup_job_list',
    'pve_backup_job_update', 'pve_backup_list',
    # Wave 6a (2026-07-16): PVE Ceph core observability + flags. status/flags-list/flag-get/
    # cfg_db/cfg_raw/cfg_value/crush/rules/cmd_safety are operator- or Ceph-daemon-authored
    # CLOSED-shape structured data, no attacker-shapeable free text (cfg_raw/cfg_db carry
    # ceph.conf content — matches the pbs_node_config_get config-read precedent). Both mutations
    # (flags_set/flag_set) return either an opaque UPID or null — no content channel. NOT here:
    # pve_ceph_log (free-text log lines) AND pve_ceph_metadata (Wave 6a review Finding 2,
    # reclassified — schema-open additionalProperties:1 daemon-self-reported hostname/addr/name
    # strings, the pbs_remote_scan precedent) — both in taint.ADVERSARIAL_TOOLS instead. See
    # proximo/ceph.py module docstring's Taint section for the full per-tool argument.
    'pve_ceph_status', 'pve_ceph_flags_list', 'pve_ceph_flag_get',
    'pve_ceph_flags_set', 'pve_ceph_flag_set', 'pve_ceph_cfg_db', 'pve_ceph_cfg_raw',
    'pve_ceph_cfg_value', 'pve_ceph_crush', 'pve_ceph_rules', 'pve_ceph_cmd_safety',
    # Wave 6b (2026-07-16): PVE Ceph services lifecycle mutations. Each returns only an opaque
    # UPID or null — no content channel at all (same reasoning as flags_set/flag_set above). NOT
    # here: pve_ceph_{mon,mgr,mds}_list (they're in taint.ADVERSARIAL_TOOLS instead — see
    # taint.py's own entry comment + proximo/ceph.py's module docstring Taint section).
    'pve_ceph_mon_create', 'pve_ceph_mon_destroy', 'pve_ceph_mgr_create', 'pve_ceph_mgr_destroy',
    'pve_ceph_mds_create', 'pve_ceph_mds_destroy', 'pve_ceph_init',
    'pve_ceph_service_start', 'pve_ceph_service_stop', 'pve_ceph_service_restart',
    # Wave 6c (2026-07-16): PVE Ceph OSD. pve_ceph_osd_lv_info is REVIEWED_TRUSTED — argued, not
    # defaulted, against the pve_ceph_osd_tree/pve_ceph_osd_metadata precedent immediately below
    # (both ADVERSARIAL instead): closed schema shape (no additionalProperties:1) and content
    # sourced from a LOCAL `lvs` shell-out on the SAME host administering the OSD, not a
    # cross-daemon network self-report at cluster registration — see proximo/ceph.py's module
    # docstring Taint section for the full argument. The 5 osd mutations (create/destroy/in/out/
    # scrub) each return only an opaque UPID or null — no content channel at all (same reasoning
    # as every prior mutation on this plane). NOT here: pve_ceph_osd_tree/pve_ceph_osd_metadata
    # (they're in taint.ADVERSARIAL_TOOLS instead).
    'pve_ceph_osd_lv_info',
    'pve_ceph_osd_create', 'pve_ceph_osd_destroy', 'pve_ceph_osd_in', 'pve_ceph_osd_out',
    'pve_ceph_osd_scrub',
    # Wave 6d (2026-07-16): PVE Ceph pools + CephFS — CLOSES Wave 6. This chunk originally shipped
    # pool_list/pool_status/fs_list here as REVIEWED_TRUSTED; the Wave 6d adversarial review
    # (2026-07-17, Finding 1) REVERSED that ruling to ADVERSARIAL -- they now live in
    # taint.ADVERSARIAL_TOOLS instead (see taint.py's own entry comment + proximo/ceph.py's module
    # docstring Taint section for the full corrected argument: pool_name/fs name are unconstrained
    # free-text creatable outside Proximo's own create surface, and application_metadata is a
    # third channel settable via raw `ceph osd pool application set`). The 5 mutations
    # (pool_create/pool_set/pool_destroy/fs_create/fs_destroy) stay REVIEWED_TRUSTED here,
    # unaffected by the reversal -- each returns only an opaque UPID, no content channel at all
    # (same reasoning as every prior mutation on this plane).
    'pve_ceph_pool_create', 'pve_ceph_pool_set', 'pve_ceph_pool_destroy',
    'pve_ceph_fs_create', 'pve_ceph_fs_destroy',
    'pve_clone', 'pve_cloudinit_get', 'pve_cloudinit_set',
    'pve_cluster_status', 'pve_create_container', 'pve_create_vm', 'pve_delete_guest', 'pve_diagnose',
    'pve_disk_move', 'pve_disk_resize', 'pve_doctor', 'pve_firewall_alias_create', 'pve_firewall_alias_delete',
    'pve_firewall_alias_list', 'pve_firewall_alias_update', 'pve_firewall_ipset_create',
    'pve_firewall_ipset_delete', 'pve_firewall_ipset_entry_add', 'pve_firewall_ipset_entry_remove',
    'pve_firewall_options_get', 'pve_firewall_options_set', 'pve_firewall_rule_add', 'pve_firewall_rule_remove',
    'pve_firewall_rule_update', 'pve_firewall_rules_list', 'pve_firewall_security_group_create',
    'pve_firewall_security_group_delete', 'pve_firewall_set_enabled', 'pve_group_create', 'pve_group_delete',
    'pve_group_get', 'pve_group_update', 'pve_groups_list', 'pve_guest_config_revert', 'pve_guest_config_set',
    'pve_guest_migrate', 'pve_guest_power', 'pve_guest_status', 'pve_ha_groups_list', 'pve_ha_resource_add',
    'pve_ha_resource_remove', 'pve_ha_resources_list', 'pve_ha_rule_create', 'pve_ha_rule_delete',
    'pve_ha_rule_update', 'pve_ha_rules_list', 'pve_hardware_list', 'pve_ipset_list', 'pve_mapping_pci_create',
    'pve_mapping_pci_delete', 'pve_mapping_pci_list', 'pve_mapping_pci_update', 'pve_mapping_usb_create',
    'pve_mapping_usb_delete', 'pve_mapping_usb_list', 'pve_mapping_usb_update', 'pve_metrics_server_delete',
    'pve_metrics_server_list', 'pve_metrics_server_set', 'pve_network_apply', 'pve_network_iface_create',
    'pve_network_iface_update', 'pve_network_list', 'pve_node_acme_domains_set', 'pve_node_cert_delete',
    'pve_node_cert_upload', 'pve_node_certificates', 'pve_node_disk_initgpt', 'pve_node_disk_smart',
    'pve_node_disk_wipe', 'pve_node_disks_list', 'pve_node_dns', 'pve_node_dns_set', 'pve_node_hosts_get',
    'pve_node_hosts_set', 'pve_node_migrateall', 'pve_node_rrddata', 'pve_node_service_control',
    'pve_node_service_status', 'pve_node_services_list', 'pve_node_startall', 'pve_node_status',
    'pve_node_stopall', 'pve_node_storage_backend_create', 'pve_node_storage_backend_delete',
    'pve_node_storage_backend_list', 'pve_node_subscription', 'pve_node_time_get', 'pve_node_time_set',
    'pve_notification_endpoint_create', 'pve_notification_endpoint_delete', 'pve_notification_endpoint_list',
    'pve_notification_endpoint_update', 'pve_notification_matcher_delete', 'pve_notification_matcher_set',
    'pve_notification_test', 'pve_overbroad_grants', 'pve_pool_create', 'pve_pool_delete', 'pve_pool_get',
    'pve_pool_update', 'pve_pools_list', 'pve_realm_create', 'pve_realm_delete', 'pve_realm_get',
    'pve_realm_update', 'pve_realms_list', 'pve_replication_create', 'pve_replication_delete',
    'pve_replication_update', 'pve_restore', 'pve_role_create', 'pve_role_delete', 'pve_role_update',
    'pve_roles_list', 'pve_rollback', 'pve_sdn_apply', 'pve_sdn_subnet_create', 'pve_sdn_subnet_delete',
    'pve_sdn_subnet_list', 'pve_sdn_subnet_update', 'pve_sdn_vnet_create', 'pve_sdn_vnet_delete',
    'pve_sdn_vnet_update', 'pve_sdn_vnets_list', 'pve_sdn_zone_create', 'pve_sdn_zone_delete',
    'pve_sdn_zone_update', 'pve_sdn_zones_list',
    # Wave 7a (2026-07-17): PVE SDN gap-fill + global control plane. zone_get/vnet_get/
    # subnet_get are single-object reads of the SAME operator-authored zone/vnet/subnet config
    # already REVIEWED_TRUSTED via the list tools above. dry_run's frr-diff/interfaces-diff is
    # DERIVED from that same staged config — not a new content channel. zone_status_list is
    # PVE's own config-apply state machine (available/pending/error), not guest/peer-influenced.
    # zone_bridges' guest-NIC `index`/`vmid` fields are PVE-assigned ordinals fixed at
    # VM/CT-config time (not guest-writable free text at runtime) — argued on that
    # non-runtime-writability axis (MINOR #1 fix, post-review 2026-07-17: the earlier
    # "argued against the pve_guest_config_get precedent" citation was self-contradicting,
    # since pve_guest_config_get is itself ADVERSARIAL, not a REVIEWED_TRUSTED precedent).
    # zone_content's statusmsg is free-text but
    # reflects PVE's OWN apply/reload process, not guest input. lock_acquire/lock_release/
    # rollback all return either a PVE-generated lock token or null — a SEPARATE ledger-
    # redaction concern (see network.py module docstring "Lock-token handling"), not a taint
    # channel. NOT here: pve_sdn_zone_ip_vrf, pve_sdn_vnet_mac_vrf — both in
    # taint.ADVERSARIAL_TOOLS instead (peer-announced/wire-learned routing content). See
    # network.py's module docstring Taint section for the full per-tool argument.
    'pve_sdn_zone_get', 'pve_sdn_vnet_get', 'pve_sdn_subnet_get', 'pve_sdn_dry_run',
    'pve_sdn_zone_status_list', 'pve_sdn_zone_bridges', 'pve_sdn_zone_content',
    'pve_sdn_lock_acquire', 'pve_sdn_lock_release', 'pve_sdn_rollback',
    # Wave 7b (2026-07-17): vnet-scoped firewall + IP mappings (new sdn_firewall.py /
    # tools/pve_sdn_firewall.py). Follows the shipped firewall.py family's OWN precedent
    # exactly: pve_firewall_rules_list/pve_firewall_options_get/the rule and options
    # mutations are none of them in taint.ADVERSARIAL_TOOLS either — rule `comment` is
    # operator-typed free text, the same class already REVIEWED_TRUSTED for
    # pve_firewall_alias_create's/pve_firewall_ipset_entry_add's own comment fields. The
    # vnet IP-mapping mutations (ip_create/update/delete) return null and have no read
    # endpoint at all on this schema — no adversarial content channel. See
    # sdn_firewall.py's module docstring Taint section for the full argument.
    'pve_sdn_vnet_firewall_options_get', 'pve_sdn_vnet_firewall_rules_list',
    'pve_sdn_vnet_firewall_rule_get', 'pve_sdn_vnet_firewall_options_set',
    'pve_sdn_vnet_firewall_rule_add', 'pve_sdn_vnet_firewall_rule_update',
    'pve_sdn_vnet_firewall_rule_remove', 'pve_sdn_vnet_ip_create', 'pve_sdn_vnet_ip_update',
    'pve_sdn_vnet_ip_delete',
    # Wave 7c (2026-07-17): SDN controllers + DNS + IPAMs (new sdn_objects.py /
    # tools/pve_sdn_objects.py). All list/get reads are operator-authored SDN integration
    # config, same channel as the already-REVIEWED_TRUSTED zone/vnet/subnet family above.
    # dns_get/ipam_get's schema-undocumented single-object GET shape (bare
    # `{"type": "object"}`, no properties) is a SECRET-HANDLING concern (whether `key`/
    # `token` echo back) — argued explicitly in sdn_objects.py's module docstring RULING —
    # NOT a content-trust/taint concern: the underlying content is operator-typed DNS/IPAM
    # integration config, not guest/peer-authored bytes. All 9 mutations return `null`
    # (schema-verified field-by-field) — no content channel to classify either way,
    # REVIEWED_TRUSTED regardless of the credential-bearing nature of the underlying object
    # (matches the pbs_s3_client_create/pbs_metrics_influxdb_http_create precedent: secret-
    # handling and content-trust are orthogonal axes in this codebase's model). NOT here:
    # pve_sdn_ipam_status — in taint.ADVERSARIAL_TOOLS instead (guest IP/MAC/hostname
    # address entries, zero schema item-shape documentation).
    'pve_sdn_controllers_list', 'pve_sdn_controller_get',
    'pve_sdn_controller_create', 'pve_sdn_controller_update', 'pve_sdn_controller_delete',
    'pve_sdn_dns_list', 'pve_sdn_dns_get',
    'pve_sdn_dns_create', 'pve_sdn_dns_update', 'pve_sdn_dns_delete',
    'pve_sdn_ipams_list', 'pve_sdn_ipam_get',
    'pve_sdn_ipam_create', 'pve_sdn_ipam_update', 'pve_sdn_ipam_delete',
    # Wave 7e (2026-07-17): SDN prefix-lists + route-maps (new sdn_routing.py /
    # tools/pve_sdn_routing.py). Both families are pure routing-policy primitives — ids,
    # CIDRs, action enums, integers, and generic-passthrough match/set/exit-action composite
    # objects — no url/key/token-shaped field exists anywhere on this plane (unlike Wave 7c's
    # dns key / ipam token), so there is no secret-handling concern to separate from the
    # taint axis here. All reads are operator-authored routing-policy config, same channel as
    # the already-REVIEWED_TRUSTED zone/vnet/subnet/controller/dns/ipam family; no field on
    # this plane carries wire-learned/peer-announced/guest-influenced content. All 9
    # mutations return `null` (schema-verified field-by-field) — no content channel to
    # classify either way, REVIEWED_TRUSTED regardless.
    'pve_sdn_prefix_lists_list', 'pve_sdn_prefix_list_get',
    'pve_sdn_prefix_list_entries_list', 'pve_sdn_prefix_list_entry_get',
    'pve_sdn_prefix_list_create', 'pve_sdn_prefix_list_update', 'pve_sdn_prefix_list_delete',
    'pve_sdn_prefix_list_entry_create', 'pve_sdn_prefix_list_entry_update',
    'pve_sdn_prefix_list_entry_delete',
    'pve_sdn_route_maps_list', 'pve_sdn_route_map_entries_list_all',
    'pve_sdn_route_map_entries_list', 'pve_sdn_route_map_entry_get',
    'pve_sdn_route_map_entry_create', 'pve_sdn_route_map_entry_update',
    'pve_sdn_route_map_entry_delete',
    # Wave 7d (2026-07-17): SDN fabrics (new sdn_fabrics.py / tools/pve_sdn_fabrics.py) — the
    # FINAL chunk of Wave 7. fabrics_all/fabrics_list/fabric_get/fabric_nodes_list_all/
    # fabric_nodes_list/fabric_node_get are operator-authored fabric CONFIG, same channel as
    # the already-REVIEWED_TRUSTED zone/vnet/subnet/controller/dns/ipam/prefix-list/route-map
    # family above (all six also STRIP `lock-token` at the read layer — the live SDN
    # cluster-lock capability secret, MAJOR #2 post-review fix — see sdn_fabrics.py's module
    # docstring "THE LOCK-TOKEN RULING"). fabric_status_interfaces returns {name, state,
    # type} — the fabric's OWN locally-rendered network interface, no field documented as
    # peer-announced or FRR-reported (checked field-by-field against the raw schema) —
    # REVIEWED_TRUSTED, a deliberate divergence from this chunk's own dispatch-prompt summary
    # ("ALL ADVERSARIAL"). Basis, on the record (STRIKE-AND-CORRECT: an earlier version of
    # this comment cited "this pinned campaign doc's own Wave 7d chunk listing" — that
    # citation was FABRICATED, no such section exists): the schema's local-only field shape
    # PLUS the 2026-07-17 COORDINATOR RE-RULING (`.scratch/2026-07-15-full-surface-
    # campaign.md` lines 853-864, binding) — see sdn_fabrics.py's module docstring fact #3 for
    # the full argument. All 6 mutations return `null` (schema-verified field-by-field) — no
    # content channel to classify either way, REVIEWED_TRUSTED regardless. NOT here:
    # pve_sdn_fabric_status_neighbors, pve_sdn_fabric_status_routes — both in
    # taint.ADVERSARIAL_TOOLS instead (wire-learned/peer-announced routing content).
    'pve_sdn_fabrics_all', 'pve_sdn_fabrics_list', 'pve_sdn_fabric_get',
    'pve_sdn_fabric_create', 'pve_sdn_fabric_update', 'pve_sdn_fabric_delete',
    'pve_sdn_fabric_nodes_list_all', 'pve_sdn_fabric_nodes_list', 'pve_sdn_fabric_node_get',
    'pve_sdn_fabric_node_create', 'pve_sdn_fabric_node_update', 'pve_sdn_fabric_node_delete',
    'pve_sdn_fabric_status_interfaces',
    # Wave 8a (2026-07-17): PMG ruledb per-object reads + the direct rule<->action-group read +
    # RuleDB factory reset. The 9 reads are all operator-authored, closed-shape content: who/
    # what-object match criteria (email/domain/regex/ip/cidr/ldap-mode/account — the same channel
    # already REVIEWED_TRUSTED for pmg_who_object_add/pmg_what_object_add); when-object is a pure
    # H:i schedule; the 5 action-object reads are operator-authored templates/targets (bcc target,
    # header field/value, notification subject/body, disclaimer text, removeattachments
    # replacement text — matching the already-shipped action_*_create/update tools' own
    # REVIEWED_TRUSTED classification just above). pmg_ruledb_rule_action_groups_list returns bare
    # [{id: int}], the identical shape/trust level as the already-REVIEWED_TRUSTED
    # pmg_ruledb_rule_from_list/to_list/what_list/when_list siblings. pmg_ruledb_reset (the
    # mutation, RISK_HIGH) returns null (schema-verified) — no content channel to classify either
    # way, REVIEWED_TRUSTED regardless of its blast radius (taint classifies the RETURN channel,
    # not the mutation's consequences, same rule established since Wave 4c/4d). None of the 9
    # reads carry wire-learned or externally-authored bytes — none belong in
    # taint.ADVERSARIAL_TOOLS.
    'pmg_who_object_get', 'pmg_what_object_get', 'pmg_when_object_get',
    'pmg_action_bcc_get', 'pmg_action_field_get', 'pmg_action_notification_get',
    'pmg_action_disclaimer_get', 'pmg_action_removeattachments_get',
    'pmg_ruledb_rule_action_groups_list', 'pmg_ruledb_reset',
    # Wave 8b (2026-07-17): PMG GLOBAL welcomelist (new pmg_welcomelist.py/tools/
    # pmg_welcomelist.py — separate module, no ogroup concept on this plane at all). The 2 reads
    # (pmg_welcomelist_objects_list/pmg_welcomelist_object_get) are operator-authored match
    # criteria (email/domain/regex/ip/cidr) — the same channel already REVIEWED_TRUSTED for
    # pmg_who_object_get/pmg_what_object_get above. The 3 mutations
    # (pmg_welcomelist_object_add/_update/_delete) carry no content channel to classify either
    # way — REVIEWED_TRUSTED regardless of their MEDIUM/MEDIUM/LOW blast radius (taint classifies
    # the RETURN channel, not the mutation's consequences, same rule since Wave 4c/4d). NOT the
    # same family as pmg_quarantine_welcomelist_add/remove above (also REVIEWED_TRUSTED, but
    # per-mailbox — pmg_quarantine_welcomelist_list is the one ADVERSARIAL sibling, in
    # taint.ADVERSARIAL_TOOLS, unaffected by this wave) — these 5 are the GLOBAL admin welcomelist.
    'pmg_welcomelist_objects_list', 'pmg_welcomelist_object_get',
    'pmg_welcomelist_object_add', 'pmg_welcomelist_object_update', 'pmg_welcomelist_object_delete',
    # Wave 9a (2026-07-17): PMG node core — network/dns/time/node-config/certs-info/services/
    # subscription (new pmg_node.py/tools/pmg_node.py). All 8 reads are operator-authored
    # structured config: network list/get (interface config, schema-thin but no attacker channel
    # documented), dns/time/config (ACME account/domain-mapping only) reads, certificates_info
    # (PUBLIC cert data — pem/fingerprint/subject/issuer/san — no private key field, schema-
    # verified field-by-field), services_list (systemd service names), subscription_get (`key`
    # defensively stripped at the read layer regardless of schema silence, matching
    # pbs_config.py's `_strip_password` idiom — a secret-handling concern, not a taint one, same
    # orthogonal-axes precedent as sdn_objects.py's dns/ipam reads). All 11 mutations return
    # either `null` or (network_reload only) a schema-confirmed plain STRING with no attacker-
    # shapeable content documented (Smoke-confirm whether it's a UPID or a status message; either
    # way it carries no external/guest-authored bytes) — no content channel to classify either
    # way, REVIEWED_TRUSTED regardless of blast radius (taint classifies the RETURN channel, not
    # the mutation's consequences, same rule since Wave 4c/4d).
    'pmg_node_network_list', 'pmg_node_network_get', 'pmg_node_dns_get', 'pmg_node_time_get',
    'pmg_node_config_get', 'pmg_node_certificates_info', 'pmg_node_services_list',
    'pmg_node_subscription_get',
    'pmg_node_network_create', 'pmg_node_network_update', 'pmg_node_network_delete',
    'pmg_node_network_revert', 'pmg_node_network_reload', 'pmg_node_dns_set', 'pmg_node_time_set',
    'pmg_node_config_set', 'pmg_node_subscription_set', 'pmg_node_subscription_check',
    'pmg_node_subscription_delete',
    # Wave 9b (2026-07-17): PMG node ops odds (pmg_node.py chunk 9b). NOT here (in
    # taint.ADVERSARIAL_TOOLS instead): pmg_node_report, pmg_node_journal, pmg_node_task_log,
    # pmg_node_postfix_queue_list, pmg_node_postfix_queue_message_get — free-text/mail-metadata
    # content, see taint.py's own entry comment for the full argument. task_status carries only
    # {pid, status} — no free text. backup_list's filenames are schema-pattern-bounded, not free
    # text. clamav/spamassassin reads are structured version/count metadata from local DB files,
    # no attacker-shapeable channel. All 15 mutations here return either `null` or a
    # schema-confirmed ambiguous STRING (backup_restore, clamav_database_update,
    # spamassassin_rules_update, service_{start,stop,restart,reload}) with no attacker-shapeable
    # content documented — REVIEWED_TRUSTED regardless of blast radius (taint classifies the
    # RETURN channel, not the mutation's consequences).
    'pmg_node_task_status',
    'pmg_node_backup_list', 'pmg_node_backup_delete', 'pmg_node_backup_restore',
    'pmg_node_postfix_queue_action', 'pmg_node_postfix_queue_delete_all',
    'pmg_node_postfix_queue_delete_queue', 'pmg_node_postfix_queue_message_delete',
    'pmg_node_postfix_queue_message_deliver', 'pmg_node_postfix_discard_verify_cache',
    'pmg_node_clamav_database_get', 'pmg_node_clamav_database_update',
    'pmg_node_spamassassin_rules_get', 'pmg_node_spamassassin_rules_update',
    'pmg_node_service_start', 'pmg_node_service_stop', 'pmg_node_service_restart',
    'pmg_node_service_reload', 'pmg_node_task_stop',
    # Wave 9c (2026-07-17): PMG LDAP profiles + fetchmail (extends pmg.py/tools/pmg_mail.py).
    # LDAP profile CRUD/config/sync reads+mutations are operator-authored config, same channel as
    # the already-REVIEWED_TRUSTED `pmg_domain_*`/`pmg_transport_*` families in this same file;
    # `bindpw` is defensively/mandatorily stripped at the read layer and unconditionally redacted
    # in every Plan/ledger surface (a secret-HANDLING concern, not a taint one — see pmg.py's Wave
    # 9c module section). Fetchmail CRUD is the same class (operator-authored mail-source config);
    # `pass` is MANDATORILY stripped at the read layer (CONFIRMED echoed on both list and
    # single-item schemas) and unconditionally redacted in every Plan/ledger surface. NOT here (in
    # taint.ADVERSARIAL_TOOLS instead): pmg_ldap_users_list, pmg_ldap_user_emails_get,
    # pmg_ldap_groups_list, pmg_ldap_group_members_get — directory-sourced, externally-authored
    # content (see taint.py's own entry comment for the full argument).
    'pmg_ldap_profiles_list', 'pmg_ldap_profile_config_get',
    'pmg_ldap_profile_create', 'pmg_ldap_profile_delete', 'pmg_ldap_profile_config_update',
    'pmg_ldap_profile_sync',
    'pmg_fetchmail_list', 'pmg_fetchmail_get',
    'pmg_fetchmail_create', 'pmg_fetchmail_update', 'pmg_fetchmail_delete',
    # Wave 9d (2026-07-17): PMG mail routing config remainder (extends pmg.py/tools/pmg_mail.py
    # — same file as the already-REVIEWED_TRUSTED pmg_domain_*/pmg_transport_*/pmg_mynetworks_*
    # families above). All 18 tools are operator-authored config CRUD or static catalog data —
    # no secret-shaped field and no externally-authored content channel anywhere in this chunk
    # (checked every param/return property individually; see pmg.py's Wave 9d module section
    # fact #1). pmg_regextest tests a CALLER-supplied regex/text pair server-side — caller ==
    # operator here (not an attacker-controlled channel), matching this campaign's own
    # channel-not-verb classification discipline.
    'pmg_domain_get', 'pmg_domain_update',
    'pmg_transport_list', 'pmg_transport_get', 'pmg_transport_update',
    'pmg_mynetworks_list', 'pmg_mynetworks_get', 'pmg_mynetworks_update',
    'pmg_tlspolicy_list', 'pmg_tlspolicy_get', 'pmg_tlspolicy_create',
    'pmg_tlspolicy_update', 'pmg_tlspolicy_delete',
    'pmg_tls_inbound_domains_list', 'pmg_tls_inbound_domains_create',
    'pmg_tls_inbound_domains_delete',
    'pmg_mimetypes_list', 'pmg_regextest',
    # Wave 9e (2026-07-17): PMG DKIM + customscores (extends pmg.py/tools/pmg_mail.py). NO
    # secret-shaped field anywhere in this chunk (checked every param/return property
    # individually) — DKIM's private signing key is generated server-side and NEVER returned by
    # any read (only the PUBLIC key, rendered as a DNS TXT record, is readable — public by
    # design, not a secret); customscores' `digest` is an optimistic-concurrency token, not a
    # secret. All 15 are operator-authored config CRUD — no externally-authored content channel.
    'pmg_dkim_domains_list', 'pmg_dkim_domain_get', 'pmg_dkim_domain_create',
    'pmg_dkim_domain_update', 'pmg_dkim_domain_delete',
    'pmg_dkim_selector_get', 'pmg_dkim_selector_generate', 'pmg_dkim_selectors_list',
    'pmg_customscores_list', 'pmg_customscores_get', 'pmg_customscores_create',
    'pmg_customscores_update', 'pmg_customscores_delete', 'pmg_customscores_revert_all',
    'pmg_customscores_apply',
    # Wave 9f (2026-07-17): PMG PBS remote config + node-side PBS backup jobs (extends pmg.py/
    # tools/pmg_mail.py). `pmg_pbs_remote_list`/`_get`/`pmg_node_pbs_jobs_list` are
    # operator-authored config, secret-stripped at the read layer (password/encryption-key —
    # MANDATORY on both list forms, DEFENSIVE on the single-item read; a secret-HANDLING concern,
    # not a taint one, argued in pmg.py's Wave 9f module section). The remote create/update/delete
    # mutations and the node-side snapshot create/forget/restore/verify + timer create/delete
    # mutations all return either `null`, a schema-confirmed-ambiguous STRING, or a small typed
    # dict with no free-text/externally-authored field — REVIEWED_TRUSTED regardless of blast
    # radius (taint classifies the RETURN channel, not the mutation's consequences, the standing
    # rule since Wave 4c/4d). NOT here (in taint.ADVERSARIAL_TOOLS instead):
    # `pmg_node_pbs_snapshots_list`, `pmg_node_pbs_snapshot_get` — remote-authored snapshot labels.
    'pmg_pbs_remote_list', 'pmg_pbs_remote_get', 'pmg_pbs_remote_create',
    'pmg_pbs_remote_update', 'pmg_pbs_remote_delete',
    'pmg_node_pbs_jobs_list',
    'pmg_node_pbs_snapshot_create', 'pmg_node_pbs_snapshot_forget',
    'pmg_node_pbs_snapshot_restore', 'pmg_node_pbs_snapshot_verify',
    'pmg_node_pbs_timer_get', 'pmg_node_pbs_timer_create', 'pmg_node_pbs_timer_delete',
    # PMG ACME accounts/plugins + node cert order/renew/revoke + custom-cert upload (Wave 9g,
    # 2026-07-17, extends pmg.py/tools/pmg_mail.py). Account/plugin list+get are
    # operator-authored config, defensively secret-stripped at the read layer (eab-hmac-key/
    # eab-kid/data — a secret-HANDLING concern, not a taint one, argued in pmg.py's Wave 9g
    # module section). Every mutation's return is either `null`, a schema-confirmed-ambiguous
    # STRING, or (custom-cert-upload) a small typed object of PUBLIC cert material only —
    # REVIEWED_TRUSTED regardless of blast radius (taint classifies the RETURN channel, not the
    # mutation's consequences, the standing rule since Wave 4c/4d). `directories`/
    # `challenge_schema` are PMG's own static built-in catalogs, no caller-influenced URL. NOT
    # here (in taint.ADVERSARIAL_TOOLS instead): `pmg_acme_tos`, `pmg_acme_meta` — both fetch a
    # caller-chosen CA directory URL live.
    'pmg_acme_account_list', 'pmg_acme_account_get', 'pmg_acme_account_create',
    'pmg_acme_account_update', 'pmg_acme_account_delete',
    'pmg_acme_plugin_list', 'pmg_acme_plugin_get', 'pmg_acme_plugin_create',
    'pmg_acme_plugin_update', 'pmg_acme_plugin_delete',
    'pmg_acme_directories', 'pmg_acme_challenge_schema',
    'pmg_node_cert_acme_order', 'pmg_node_cert_acme_renew', 'pmg_node_cert_acme_revoke',
    'pmg_node_cert_custom_upload', 'pmg_node_cert_custom_delete',
    # PMG identity: auth-realm, local users, TFA (Wave 9h, 2026-07-17, NEW pmg_identity.py +
    # tools/pmg_identity.py). All 16 tools are structured, operator-authored config/identity data
    # — no attacker-shapeable free text (unlike pmg_ldap_users_list/etc above, which are
    # directory-sourced). Reads return realm comment/type, user comment/role/enable, or TFA entry
    # metadata (created/description/enable/id/type) — never a secret (password/crypt_pass/keys/
    # client-key are all defensively stripped or never echoed at the read layer, a
    # secret-HANDLING concern argued in pmg_identity.py's own module section, not a taint one).
    # TFA add's one-time 'recovery' codes and the TFA/user step-up 'password' are handled the same
    # way — never-in-ledger, not a taint concern (the RETURN CHANNEL here is always a small typed
    # object/list, never free text).
    # Wave 9h REVIEW (Major 2) — the OIDC autocreate/username-claim angle, examined explicitly
    # rather than left silent: an OIDC realm's `username-claim` can derive a PMG userid from an
    # EXTERNAL IdP claim at login (Fact 11), so a later pmg_access_user_get/realm_get read on such
    # an account surfaces IdP-influenced identifier content. Still REVIEWED_TRUSTED, not
    # overturned, because (1) the surfaced content is one validated narrow identifier string
    # (pmg-userid format, 4-64 chars), not the unbounded free text pmg_ldap_users_list's directory
    # dump carries; (2) no schema field here documents PMG copying OTHER arbitrary IdP claims into
    # a free-text profile field (comment/email/firstname/lastname are caller-supplied, never
    # IdP-populated per the schema); (3) the authority angle of autocreate-role (Fact 11) is a
    # separate, already-argued concern about future GRANTED PERMISSIONS, not this content
    # question. Full argument: pmg_identity.py's own "TAINT CLASSIFICATION" module-docstring
    # section. Narrower than a blanket claim — a future schema field echoing free-text IdP claims
    # verbatim would need reclassification to ADVERSARIAL.
    'pmg_access_realm_list', 'pmg_access_realm_get', 'pmg_access_realm_create',
    'pmg_access_realm_update', 'pmg_access_realm_delete',
    'pmg_access_user_get', 'pmg_access_user_create', 'pmg_access_user_update',
    'pmg_access_user_delete', 'pmg_access_user_unlock_tfa',
    'pmg_access_tfa_list', 'pmg_access_tfa_user_list', 'pmg_access_tfa_get',
    'pmg_access_tfa_add', 'pmg_access_tfa_update', 'pmg_access_tfa_delete',
    # PMG global appliance config + cluster bootstrap/join (Wave 9i, 2026-07-18, extends
    # pmg_identity.py/tools/pmg_identity.py). All 18 tools are structured, operator-authored
    # appliance config or cluster topology/verification material — no attacker-shapeable free
    # text. The 5 config-family reads (admin/clamav/spamquar/virusquar/tfa-webauthn) are
    # schema-thin appliance settings, not mail content; the 6 config-family updates return
    # `null`/synchronous "ok" — the RETURN channel never carries external bytes. The 3 cluster
    # reads (join-info/nodes/status) return ONLY public verification material by design
    # (fingerprint/SSH host+root PUBLIC keys/ip/name/type — argued in pmg_identity.py's own
    # Fact 17, the same reasoning class as a TLS cert fingerprint being safe to return
    # unredacted). The 4 cluster mutations (create/join/node_add/update_fingerprints, RULING 1)
    # return either a schema-ambiguous status STRING (create/join — not attacker-influenced, PMG
    # generates it itself), a thin real node list (`{cid}` per item, node_add), or null
    # (update_fingerprints) — never free text an attacker could shape. join's `password`
    # (a third-party credential) and the 6 config families' secret-SHAPED `http_proxy` are
    # secret-HANDLING concerns (never-in-ledger / masked), argued in pmg_identity.py's own
    # module section, not a taint one.
    'pmg_config_admin_get', 'pmg_config_admin_update',
    'pmg_config_clamav_get', 'pmg_config_clamav_update',
    'pmg_config_mail_update',
    'pmg_config_spamquar_get', 'pmg_config_spamquar_update',
    'pmg_config_virusquar_get', 'pmg_config_virusquar_update',
    'pmg_config_tfa_webauthn_get', 'pmg_config_tfa_webauthn_update',
    'pmg_cluster_join_info', 'pmg_cluster_nodes_list', 'pmg_cluster_status',
    'pmg_cluster_create', 'pmg_cluster_join', 'pmg_cluster_node_add',
    'pmg_cluster_update_fingerprints',
    # Quarantine + statistics remainder (Wave 9j, 2026-07-18, THE FINAL CHUNK — closes the PMG
    # plane, extends pmg.py/tools/pmg_mail.py). `pmg_quarantine_link_get`'s return is a
    # bearer-credential-equivalent (RULING 4) — a SECRET-handling concern (never-in-ledger on
    # the read's own logged return, pmg.py's own Wave 9j module section), not a taint one: the
    # link is PMG-generated, never attacker content. `pmg_quarantine_users_list` lists PMG's own
    # per-mailbox BL/WL config (operator-managed, not mail content). `pmg_quarantine_sendlink`'s
    # own return is `null` (a mutation; the REAL email it sends never transits this tool's
    # response). `pmg_statistics_maildistribution`/`pmg_statistics_rejectcount` are pure
    # aggregate-numeric twins of the already-REVIEWED_TRUSTED `pmg_statistics_mailcount` (see
    # taint.py's own Wave 9j comment for the full per-tool argument, including which siblings
    # went to ADVERSARIAL instead: content_get/attachments_list/contact/detail/
    # recentreceivers/recentsenders).
    'pmg_quarantine_link_get', 'pmg_quarantine_users_list', 'pmg_quarantine_sendlink',
    'pmg_statistics_maildistribution', 'pmg_statistics_rejectcount',
    'pve_security_groups_list', 'pve_snapshot_create',
    'pve_snapshot_delete', 'pve_storage_config_get', 'pve_storage_config_list', 'pve_storage_content_delete',
    'pve_storage_create', 'pve_storage_delete', 'pve_storage_download', 'pve_storage_status', 'pve_storage_update',
    'pve_task_status', 'pve_task_stop', 'pve_task_wait', 'pve_tasks_list', 'pve_template_convert',
    'pve_tfa_delete', 'pve_tfa_get', 'pve_tfa_list', 'pve_token_create', 'pve_token_revoke', 'pve_tokens_list',
    'pve_user_create', 'pve_user_delete', 'pve_user_get', 'pve_user_update', 'pve_users_list',
})


def _registered_names() -> list[str]:
    return [t.name for t in asyncio.run(server.mcp.list_tools())]


def test_no_obviously_adversarial_tool_hides_in_reviewed_trusted():
    """Spot-check: a handful of tools that clearly carry guest/external bytes must NOT be in
    REVIEWED_TRUSTED (they belong in taint.ADVERSARIAL_TOOLS instead)."""
    obviously_adversarial = {
        "ct_exec", "ct_psql", "ct_logs", "ct_diagnose",
        "pve_agent_exec", "pve_agent_info", "pve_agent_file_read",
        "pmg_quarantine_spam", "pmg_quarantine_virus",
    }
    assert obviously_adversarial.isdisjoint(REVIEWED_TRUSTED)
    assert obviously_adversarial <= taint.ADVERSARIAL_TOOLS


def test_adversarial_tools_are_all_really_registered():
    """Every name in taint.ADVERSARIAL_TOOLS must be a REAL tool on the live registry — catches a
    typo or a renamed/removed tool that would otherwise silently ride as "classified" while not
    actually being gated by anything."""
    names = set(_registered_names())
    missing = taint.ADVERSARIAL_TOOLS - names
    assert not missing, (
        f"taint.ADVERSARIAL_TOOLS names not found on the live registry (typo, or the tool was "
        f"renamed/removed and the classification wasn't updated): {sorted(missing)}"
    )
    assert taint.ADVERSARIAL_TOOLS <= names


def test_every_registered_tool_is_classified():
    """The completeness guard: every tool the server actually exposes must be EITHER
    adversarial-classified OR explicitly reviewed-trusted. If this fails after adding a tool,
    it means a new tool shipped unclassified — classify it (see module docstring) rather than
    silencing this test."""
    names = set(_registered_names())
    known = taint.ADVERSARIAL_TOOLS | REVIEWED_TRUSTED
    unclassified = names - known
    stale = known - names
    assert names == known, (
        "Tool classification is out of sync with the live registry.\n"
        f"Unclassified (registered but neither adversarial nor reviewed-trusted): {sorted(unclassified)}\n"
        f"Stale (classified but no longer registered): {sorted(stale)}\n"
        "Fix: classify a new tool as adversarial (guest/log/quarantine/free-text-external content) "
        "in taint.ADVERSARIAL_TOOLS, or as REVIEWED_TRUSTED in this test file (structured, "
        "operator-authored, no attacker-shapeable free text). Never add to REVIEWED_TRUSTED just "
        "to silence this test — that reintroduces the fail-open gap this test exists to close."
    )


def test_no_tool_can_clear_taint():
    """Structural invariant taint.py's docstring promises (and design-doc invariant #5): NO
    @mcp.tool clears taint — the clear is out-of-band only, the same trust boundary as CONTAIN's
    re-arm. Mirrors test_envelope.py's/test_consent.py's structural guards. `clear_taint` must never
    be referenced from the tool surface (server.py + tools/*.py); it lives only in taint.py + the
    operator-side out-of-band path. A source scan is the right shape: a tool wiring it in would be
    the exact regression this guards, and it wouldn't show up in the registry signature.
    """
    src_dir = Path(server.__file__).resolve().parent
    surface = [src_dir / "server.py", *sorted((src_dir / "tools").glob("*.py"))]
    offenders = [p.name for p in surface if "clear_taint" in p.read_text(encoding="utf-8")]
    assert not offenders, (
        f"clear_taint is referenced from the tool surface {offenders} — taint must only be cleared "
        "out-of-band (no @mcp.tool clears it). Remove the reference; the clear is an operator act."
    )
