"""PMG (Proxmox Mail Gateway) lane tests — fully mocked, no live PMG.

Mirrors test_pbs.py style:
- _pmg_backend() uses a mock httpx transport to test PmgBackend's HTTP layer.
- _api() is a recording SimpleNamespace for tool/plan function tests.
- Validator-rejection tests use pytest.raises(ProximoError).
- Plan tests verify honest risk ratings and blast radius content.

Auth model: ticket-based (CONFIRMED against PMG 9.1).
- Login: POST /access/ticket → {ticket, CSRFPreventionToken}
- Reads: Cookie: PMGAuthCookie=<ticket>   (no CSRF)
- Mutations: Cookie + CSRFPreventionToken header
- On 401: re-login once, retry; if still 401, raise.
"""

from __future__ import annotations

import json
import pathlib
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest

from proximo.backends import ProximoError
from proximo.planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM
from proximo.pmg import (
    PmgBackend,
    PmgConfig,
    _check_acme_account_name,
    _check_acme_challenge_type,
    _check_acme_contact,
    _check_acme_directory_url,
    _check_acme_plugin_api,
    _check_acme_plugin_delete_props,
    _check_acme_plugin_digest,
    _check_acme_plugin_id,
    _check_acme_plugin_nodes,
    _check_acme_validation_delay,
    _check_action_object_id,
    _check_action_position,
    _check_backup_notify,
    _check_cidr,
    _check_customscore_name,
    _check_customscore_score,
    _check_customscores_digest,
    _check_direction,
    _check_dkim_keysize,
    _check_domain,
    _check_email_address,
    _check_fetchmail_id,
    _check_fetchmail_interval,
    _check_fetchmail_port,
    _check_fetchmail_protocol,
    _check_fetchmail_user,
    _check_ldap_comment,
    _check_ldap_config_digest,
    _check_ldap_gid,
    _check_ldap_mode,
    _check_ldap_port,
    _check_ldap_profile,
    _check_ldap_server_address,
    _check_mail_id,
    _check_node,
    _check_ogroup,
    _check_pbs_datastore,
    _check_pbs_keep_count,
    _check_pbs_remote_digest,
    _check_pbs_remote_fingerprint,
    _check_pbs_remote_id,
    _check_pbs_remote_namespace,
    _check_pbs_remote_port,
    _check_pbs_remote_server,
    _check_pbs_remote_username,
    _check_pbs_snapshot_backup_id,
    _check_pbs_snapshot_backup_time,
    _check_pbs_timer_delay,
    _check_pbs_timer_schedule,
    _check_pmg_cert_type,
    _check_priority,
    _check_quarantine_type,
    _check_quarusers_list,
    _check_recent_hours,
    _check_recent_limit,
    _check_regextest_field,
    _check_rrddata_cf,
    _check_rrddata_timeframe,
    _check_ruledb_id,
    _check_service,
    _check_service_action,
    _check_statistics_detail_type,
    _check_tls_destination,
    _check_transport_protocol,
    _check_what_object_type,
    _check_who_object_type,
    access_permissions,
    acme_account_create,
    acme_account_delete,
    acme_account_get,
    acme_account_list,
    acme_account_update,
    acme_challenge_schema,
    acme_directories,
    acme_meta,
    acme_plugin_create,
    acme_plugin_delete,
    acme_plugin_get,
    acme_plugin_update,
    acme_plugins_list,
    acme_tos,
    action_bcc_create,
    action_bcc_get,
    action_bcc_update,
    action_delete,
    action_disclaimer_create,
    action_disclaimer_get,
    action_disclaimer_update,
    action_field_create,
    action_field_get,
    action_field_update,
    action_notification_create,
    action_notification_get,
    action_notification_update,
    action_objects_list,
    action_removeattachments_create,
    action_removeattachments_get,
    action_removeattachments_update,
    backup_create,
    customscores_apply,
    customscores_create,
    customscores_delete,
    customscores_get,
    customscores_list,
    customscores_revert_all,
    customscores_update,
    dkim_domain_create,
    dkim_domain_delete,
    dkim_domain_get,
    dkim_domain_update,
    dkim_domains_list,
    dkim_selector_generate,
    dkim_selector_get,
    dkim_selectors_list,
    domain_create,
    domain_delete,
    domain_get,
    domain_update,
    domains_list,
    fetchmail_create,
    fetchmail_delete,
    fetchmail_get,
    fetchmail_list,
    fetchmail_update,
    ldap_group_members_get,
    ldap_groups_list,
    ldap_profile_config_get,
    ldap_profile_config_update,
    ldap_profile_create,
    ldap_profile_delete,
    ldap_profile_sync,
    ldap_profiles_list,
    ldap_user_emails_get,
    ldap_users_list,
    mimetypes_list,
    mynetworks_add,
    mynetworks_get,
    mynetworks_list,
    mynetworks_remove,
    mynetworks_update,
    node_cert_acme_order,
    node_cert_acme_renew,
    node_cert_acme_revoke,
    node_cert_custom_delete,
    node_cert_custom_upload,
    node_pbs_jobs_list,
    node_pbs_snapshot_create,
    node_pbs_snapshot_forget,
    node_pbs_snapshot_get,
    node_pbs_snapshot_restore,
    node_pbs_snapshot_verify,
    node_pbs_snapshots_list,
    node_pbs_timer_create,
    node_pbs_timer_delete,
    node_pbs_timer_get,
    node_rrddata,
    node_status,
    node_syslog,
    node_version,
    pbs_remote_create,
    pbs_remote_delete,
    pbs_remote_get,
    pbs_remote_list,
    pbs_remote_update,
    plan_acme_account_create,
    plan_acme_account_delete,
    plan_acme_account_update,
    plan_acme_plugin_create,
    plan_acme_plugin_delete,
    plan_acme_plugin_update,
    plan_action_bcc_create,
    plan_action_bcc_update,
    plan_action_delete,
    plan_action_disclaimer_create,
    plan_action_disclaimer_update,
    plan_action_field_create,
    plan_action_field_update,
    plan_action_notification_create,
    plan_action_notification_update,
    plan_action_removeattachments_create,
    plan_action_removeattachments_update,
    plan_backup_create,
    plan_customscores_apply,
    plan_customscores_create,
    plan_customscores_delete,
    plan_customscores_revert_all,
    plan_customscores_update,
    plan_dkim_domain_create,
    plan_dkim_domain_delete,
    plan_dkim_domain_update,
    plan_dkim_selector_generate,
    plan_domain_create,
    plan_domain_delete,
    plan_domain_update,
    plan_fetchmail_create,
    plan_fetchmail_delete,
    plan_fetchmail_update,
    plan_ldap_profile_config_update,
    plan_ldap_profile_create,
    plan_ldap_profile_delete,
    plan_ldap_profile_sync,
    plan_mynetworks_add,
    plan_mynetworks_remove,
    plan_mynetworks_update,
    plan_node_cert_acme_order,
    plan_node_cert_acme_renew,
    plan_node_cert_acme_revoke,
    plan_node_cert_custom_delete,
    plan_node_cert_custom_upload,
    plan_node_pbs_snapshot_create,
    plan_node_pbs_snapshot_forget,
    plan_node_pbs_snapshot_restore,
    plan_node_pbs_snapshot_verify,
    plan_node_pbs_timer_create,
    plan_node_pbs_timer_delete,
    plan_pbs_remote_create,
    plan_pbs_remote_delete,
    plan_pbs_remote_update,
    plan_postfix_flush,
    plan_quarantine_action,
    plan_quarantine_blocklist_add,
    plan_quarantine_blocklist_remove,
    plan_quarantine_sendlink,
    plan_quarantine_welcomelist_add,
    plan_quarantine_welcomelist_remove,
    plan_ruledb_reset,
    plan_ruledb_rule_action_attach,
    plan_ruledb_rule_action_detach,
    plan_ruledb_rule_create,
    plan_ruledb_rule_delete,
    plan_ruledb_rule_from_attach,
    plan_ruledb_rule_from_detach,
    plan_ruledb_rule_to_attach,
    plan_ruledb_rule_to_detach,
    plan_ruledb_rule_update,
    plan_ruledb_rule_what_attach,
    plan_ruledb_rule_what_detach,
    plan_ruledb_rule_when_attach,
    plan_ruledb_rule_when_detach,
    plan_service_control,
    plan_spam_config_update,
    plan_tls_inbound_domains_create,
    plan_tls_inbound_domains_delete,
    plan_tlspolicy_create,
    plan_tlspolicy_delete,
    plan_tlspolicy_update,
    plan_transport_create,
    plan_transport_delete,
    plan_transport_update,
    plan_what_group_create,
    plan_what_group_delete,
    plan_what_group_update,
    plan_what_object_add,
    plan_what_object_delete,
    plan_what_object_update,
    plan_when_group_create,
    plan_when_group_delete,
    plan_when_group_update,
    plan_when_object_add,
    plan_when_object_delete,
    plan_when_object_update,
    plan_who_group_create,
    plan_who_group_delete,
    plan_who_group_update,
    plan_who_object_add,
    plan_who_object_delete,
    plan_who_object_update,
    postfix_flush,
    postfix_qshape,
    quarantine_action,
    quarantine_attachment,
    quarantine_attachments_list,
    quarantine_blocklist_add,
    quarantine_blocklist_list,
    quarantine_blocklist_remove,
    quarantine_content_get,
    quarantine_link_get,
    quarantine_sendlink,
    quarantine_spam,
    quarantine_spamstatus,
    quarantine_spamusers,
    quarantine_users_list,
    quarantine_virus,
    quarantine_virusstatus,
    quarantine_welcomelist_add,
    quarantine_welcomelist_list,
    quarantine_welcomelist_remove,
    regextest,
    relay_config,
    ruledb_digest,
    ruledb_reset,
    ruledb_rule_action_attach,
    ruledb_rule_action_detach,
    ruledb_rule_action_groups_list,
    ruledb_rule_actions_list,
    ruledb_rule_create,
    ruledb_rule_delete,
    ruledb_rule_from_attach,
    ruledb_rule_from_detach,
    ruledb_rule_from_list,
    ruledb_rule_get,
    ruledb_rule_to_attach,
    ruledb_rule_to_detach,
    ruledb_rule_to_list,
    ruledb_rule_update,
    ruledb_rule_what_attach,
    ruledb_rule_what_detach,
    ruledb_rule_what_list,
    ruledb_rule_when_attach,
    ruledb_rule_when_detach,
    ruledb_rule_when_list,
    ruledb_rules_list,
    service_control,
    service_status,
    spam_config,
    spam_config_update,
    statistics_contact,
    statistics_detail,
    statistics_domains,
    statistics_mail,
    statistics_mailcount,
    statistics_maildistribution,
    statistics_receiver,
    statistics_recent,
    statistics_recentreceivers,
    statistics_recentsenders,
    statistics_rejectcount,
    statistics_sender,
    statistics_spamscores,
    statistics_virus,
    tasks_list,
    tls_inbound_domains_create,
    tls_inbound_domains_delete,
    tls_inbound_domains_list,
    tlspolicy_create,
    tlspolicy_delete,
    tlspolicy_get,
    tlspolicy_list,
    tlspolicy_update,
    tracker_detail,
    tracker_list,
    transport_create,
    transport_delete,
    transport_get,
    transport_list,
    transport_update,
    what_group_create,
    what_group_delete,
    what_group_get,
    what_group_objects,
    what_group_update,
    what_groups_list,
    what_object_add,
    what_object_delete,
    what_object_get,
    what_object_update,
    when_group_create,
    when_group_delete,
    when_group_get,
    when_group_objects,
    when_group_update,
    when_groups_list,
    when_object_add,
    when_object_delete,
    when_object_get,
    when_object_update,
    who_group_create,
    who_group_delete,
    who_group_get,
    who_group_objects,
    who_group_update,
    who_groups_list,
    who_object_add,
    who_object_delete,
    who_object_get,
    who_object_update,
)

# ---------------------------------------------------------------------------
# PmgConfig helpers
# ---------------------------------------------------------------------------

def _cfg(**kw) -> PmgConfig:
    base = dict(
        base_url="https://pmg.example.lan:8006/api2/json",
        password_path="/run/pmg-password",
    )
    base.update(kw)
    return PmgConfig(**base)


# ---------------------------------------------------------------------------
# PmgConfig.from_env
# ---------------------------------------------------------------------------

def test_pmgconfig_from_env_reads_required_vars(monkeypatch):
    monkeypatch.setenv("PROXIMO_PMG_BASE_URL", "https://pmg:8006/api2/json")
    monkeypatch.setenv("PROXIMO_PMG_PASSWORD_PATH", "/run/pmg-pass")
    monkeypatch.delenv("PROXIMO_PMG_USERNAME", raising=False)
    monkeypatch.delenv("PROXIMO_PMG_NODE", raising=False)
    monkeypatch.delenv("PROXIMO_PMG_VERIFY_TLS", raising=False)
    monkeypatch.delenv("PROXIMO_PMG_CA_BUNDLE", raising=False)
    cfg = PmgConfig.from_env()
    assert cfg.base_url == "https://pmg:8006/api2/json"
    assert cfg.password_path == "/run/pmg-pass"
    assert cfg.username == "root@pam"
    assert cfg.node == "pmg"
    assert cfg.verify_tls is True
    assert cfg.ca_bundle is None


def test_pmgconfig_from_env_strips_trailing_slash(monkeypatch):
    monkeypatch.setenv("PROXIMO_PMG_BASE_URL", "https://pmg:8006/api2/json/")
    monkeypatch.setenv("PROXIMO_PMG_PASSWORD_PATH", "/run/pmg-pass")
    cfg = PmgConfig.from_env()
    assert not cfg.base_url.endswith("/")


def test_pmgconfig_from_env_optional_vars(monkeypatch):
    monkeypatch.setenv("PROXIMO_PMG_BASE_URL", "https://pmg:8006/api2/json")
    monkeypatch.setenv("PROXIMO_PMG_PASSWORD_PATH", "/run/pmg-pass")
    monkeypatch.setenv("PROXIMO_PMG_USERNAME", "admin@pve")
    monkeypatch.setenv("PROXIMO_PMG_NODE", "mail1")
    monkeypatch.setenv("PROXIMO_PMG_VERIFY_TLS", "false")
    monkeypatch.setenv("PROXIMO_PMG_CA_BUNDLE", "/etc/ssl/ca.pem")
    # ca_bundle IS set — no TLS warning fires
    cfg = PmgConfig.from_env()
    assert cfg.username == "admin@pve"
    assert cfg.node == "mail1"
    assert cfg.verify_tls is False
    assert cfg.ca_bundle == "/etc/ssl/ca.pem"


def test_pmgconfig_from_env_missing_url_raises(monkeypatch):
    monkeypatch.delenv("PROXIMO_PMG_BASE_URL", raising=False)
    monkeypatch.setenv("PROXIMO_PMG_PASSWORD_PATH", "/run/pmg-pass")
    with pytest.raises(RuntimeError, match="PROXIMO_PMG_BASE_URL"):
        PmgConfig.from_env()


def test_pmgconfig_from_env_missing_password_path_raises(monkeypatch):
    monkeypatch.setenv("PROXIMO_PMG_BASE_URL", "https://pmg:8006/api2/json")
    monkeypatch.delenv("PROXIMO_PMG_PASSWORD_PATH", raising=False)
    with pytest.raises(RuntimeError, match="PROXIMO_PMG_PASSWORD_PATH"):
        PmgConfig.from_env()


def test_pmgconfig_from_env_warns_on_no_tls_verify_no_bundle(monkeypatch):
    monkeypatch.setenv("PROXIMO_PMG_BASE_URL", "https://pmg:8006/api2/json")
    monkeypatch.setenv("PROXIMO_PMG_PASSWORD_PATH", "/run/pmg-pass")
    monkeypatch.setenv("PROXIMO_PMG_VERIFY_TLS", "false")
    monkeypatch.delenv("PROXIMO_PMG_CA_BUNDLE", raising=False)
    with pytest.warns(UserWarning, match="without cert validation"):
        PmgConfig.from_env()


# ---------------------------------------------------------------------------
# PmgBackend FAIL-CLOSED
# ---------------------------------------------------------------------------

def test_pmgbackend_fails_closed_on_unverified_tls():
    """A credential-bearing backend must REFUSE to construct over unverified TLS (no ca_bundle)."""
    with pytest.raises(ProximoError):
        PmgBackend(_cfg(verify_tls=False))


def test_pmgbackend_fingerprint_refusal_names_env_var():
    # 1.6: a garbled PROXIMO_PMG_FINGERPRINT must not forward the validator's raw ValueError —
    # the message must name the exact env var and the expected shape (64-char SHA-256 hex).
    with pytest.raises(ProximoError, match="PROXIMO_PMG_FINGERPRINT") as exc_info:
        PmgBackend(_cfg(fingerprint="not-a-fingerprint"))
    assert "64" in str(exc_info.value)


def test_pmgbackend_ok_with_ca_bundle_even_when_verify_false():
    """A ca_bundle provides a trust anchor — construction is allowed."""
    backend = PmgBackend(_cfg(verify_tls=False, ca_bundle="/etc/ssl/certs/ca-certificates.crt"))
    assert backend.config.ca_bundle == "/etc/ssl/certs/ca-certificates.crt"


def test_pmgbackend_ok_with_default_verify():
    backend = PmgBackend(_cfg())  # verify_tls defaults True
    assert backend.config.verify_tls is True


# ---------------------------------------------------------------------------
# PmgConfig is frozen / immutable
# ---------------------------------------------------------------------------

def test_pmgconfig_is_frozen():
    from dataclasses import FrozenInstanceError
    cfg = _cfg()
    with pytest.raises(FrozenInstanceError):
        cfg.base_url = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# PmgBackend — lazy login (no network call at construction time)
# ---------------------------------------------------------------------------

def test_pmgbackend_no_login_at_construction(tmp_path):
    """PmgBackend constructs without any POST to /access/ticket."""
    pw_file = tmp_path / "password"
    pw_file.write_text("secret\n")

    mock_client = MagicMock()
    backend = PmgBackend(_cfg(password_path=str(pw_file)))
    backend._client = mock_client

    # No network calls at construction
    mock_client.post.assert_not_called()
    mock_client.get.assert_not_called()
    assert backend._ticket is None
    assert backend._csrf is None


# ---------------------------------------------------------------------------
# PmgBackend — login flow
# ---------------------------------------------------------------------------

def _make_login_resp(ticket: str = "PMG:root@pam::ticket", csrf: str = "csrf-tok") -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"data": {"ticket": ticket, "CSRFPreventionToken": csrf,
                                        "username": "root@pam"}}
    resp.raise_for_status = MagicMock()
    return resp


def test_login_posts_to_access_ticket(tmp_path):
    """_login() POSTs to /access/ticket and caches ticket + CSRF."""
    pw_file = tmp_path / "password"
    pw_file.write_text("s3cr3t\n")

    mock_client = MagicMock()
    mock_client.post.return_value = _make_login_resp()

    backend = PmgBackend(_cfg(password_path=str(pw_file)))
    backend._client = mock_client
    backend._login()

    mock_client.post.assert_called_once()
    call_args = mock_client.post.call_args
    assert "/access/ticket" in call_args[0][0]
    assert backend._ticket == "PMG:root@pam::ticket"
    assert backend._csrf == "csrf-tok"


def test_login_reads_password_from_file(tmp_path):
    """_login() reads the password from the file, not from a cached value."""
    pw_file = tmp_path / "password"
    pw_file.write_text("my-password\n")

    mock_client = MagicMock()
    mock_client.post.return_value = _make_login_resp()

    backend = PmgBackend(_cfg(password_path=str(pw_file), username="root@pam"))
    backend._client = mock_client
    backend._login()

    call_kwargs = mock_client.post.call_args[1]
    form_data = call_kwargs.get("data", {})
    assert form_data.get("username") == "root@pam"
    assert form_data.get("password") == "my-password"


def test_login_password_not_cached_disk(tmp_path):
    """Password is read at login time, not stored in config or backend state."""
    pw_file = tmp_path / "password"
    pw_file.write_text("pass-v1\n")

    mock_client = MagicMock()
    mock_client.post.return_value = _make_login_resp(ticket="t1")

    backend = PmgBackend(_cfg(password_path=str(pw_file)))
    backend._client = mock_client
    backend._login()

    # Change the file — next login reads the new password
    pw_file.write_text("pass-v2\n")
    mock_client.post.return_value = _make_login_resp(ticket="t2")
    backend._ticket = None  # force re-login
    backend._login()

    calls = mock_client.post.call_args_list
    assert calls[0][1]["data"]["password"] == "pass-v1"
    assert calls[1][1]["data"]["password"] == "pass-v2"


def test_ensure_ticket_calls_login_once(tmp_path):
    """_ensure_ticket() calls _login() only when no ticket is cached."""
    pw_file = tmp_path / "password"
    pw_file.write_text("s3cr3t\n")

    mock_client = MagicMock()
    mock_client.post.return_value = _make_login_resp()

    backend = PmgBackend(_cfg(password_path=str(pw_file)))
    backend._client = mock_client

    backend._ensure_ticket()
    backend._ensure_ticket()  # second call — ticket already cached

    assert mock_client.post.call_count == 1


def test_ensure_ticket_concurrent_login_called_once(tmp_path):
    """Two threads racing on _ensure_ticket() must trigger _login() exactly once.

    A Barrier forces both threads to the check point simultaneously; a sleep inside
    the mocked _login widens the race window so the double-login is deterministic
    without the fix (and reliably absent with it).
    """
    pw_file = tmp_path / "password"
    pw_file.write_text("secret\n")

    backend = PmgBackend(_cfg(password_path=str(pw_file)))

    login_call_count = 0
    barrier = threading.Barrier(2)

    def slow_login() -> None:
        nonlocal login_call_count
        login_call_count += 1
        time.sleep(0.05)  # widen the window: second thread sees _ticket is None
        backend._ticket = "PMG:root@pam::ticket"
        backend._csrf = "csrf-tok"

    backend._login = slow_login  # type: ignore[method-assign]

    errors: list[Exception] = []

    def run() -> None:
        try:
            barrier.wait()  # both threads reach _ensure_ticket simultaneously
            backend._ensure_ticket()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    t1 = threading.Thread(target=run)
    t2 = threading.Thread(target=run)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert not errors, f"thread error(s): {errors}"
    assert login_call_count == 1, (
        f"_login called {login_call_count} times — expected exactly once (race condition)"
    )


# ---------------------------------------------------------------------------
# PmgBackend — cookie and CSRF headers
# ---------------------------------------------------------------------------

def _mock_backend(response_data, *, status_code: int = 200,
                  password_content: str = "s3cr3t") -> tuple:  # noqa: S107
    """Returns (backend, mock_client) with a pre-seeded ticket (already logged in).

    Login is NOT exercised by this helper — use the login-flow tests for that.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = {"data": response_data}
    mock_resp.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp
    mock_client.post.return_value = mock_resp

    tmp = pathlib.Path(tempfile.mkdtemp()) / "password"
    tmp.write_text(password_content + "\n")

    backend = PmgBackend(_cfg(password_path=str(tmp)))
    backend._client = mock_client
    # Pre-seed ticket so tests don't trigger login (login tested in separate section)
    backend._ticket = "PMG:root@pam::test-ticket"
    backend._csrf = "test-csrf-token"
    return backend, mock_client


def test_get_sends_pmg_auth_cookie():
    """GET sends Cookie: PMGAuthCookie=<ticket> — no CSRF header."""
    backend, mock_client = _mock_backend({})
    backend._get("/nodes/pmg/version")
    call_kwargs = mock_client.get.call_args[1]
    headers = call_kwargs.get("headers", {})
    assert headers.get("Cookie") == "PMGAuthCookie=PMG:root@pam::test-ticket"
    assert "CSRFPreventionToken" not in headers


def test_post_sends_cookie_and_csrf():
    """POST (mutation) sends both PMGAuthCookie and CSRFPreventionToken."""
    backend, mock_client = _mock_backend(None)
    backend._post("/quarantine/mails/abc123/deliver")
    call_kwargs = mock_client.post.call_args[1]
    headers = call_kwargs.get("headers", {})
    assert headers.get("Cookie") == "PMGAuthCookie=PMG:root@pam::test-ticket"
    assert headers.get("CSRFPreventionToken") == "test-csrf-token"


def test_get_does_not_send_csrf():
    """GET must NOT include CSRFPreventionToken — reads don't need CSRF."""
    backend, mock_client = _mock_backend({})
    backend._get("/access/permissions")
    headers = mock_client.get.call_args[1].get("headers", {})
    assert "CSRFPreventionToken" not in headers


def test_post_csrf_different_from_cookie_key():
    """CSRFPreventionToken header key is distinct from the cookie key."""
    backend, mock_client = _mock_backend(None)
    backend._post("/quarantine/mails/abc123/deliver")
    headers = mock_client.post.call_args[1].get("headers", {})
    assert "CSRFPreventionToken" in headers
    assert "PMGAuthCookie" in headers.get("Cookie", "")


# ---------------------------------------------------------------------------
# PmgBackend — 401 retry
# ---------------------------------------------------------------------------

def test_get_on_401_relogins_and_retries(tmp_path):
    """On HTTP 401 from GET: clear ticket, re-login once, retry; succeed on second try."""
    pw_file = tmp_path / "password"
    pw_file.write_text("secret\n")

    login_resp = _make_login_resp(ticket="new-ticket", csrf="new-csrf")

    resp_401 = MagicMock()
    resp_401.status_code = 401

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.json.return_value = {"data": {"version": "9.1"}}
    resp_200.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.get.side_effect = [resp_401, resp_200]
    mock_client.post.return_value = login_resp  # login POST

    backend = PmgBackend(_cfg(password_path=str(pw_file)))
    backend._ticket = "stale-ticket"
    backend._csrf = "stale-csrf"
    backend._client = mock_client

    result = backend._get("/nodes/pmg/version")

    assert result == {"version": "9.1"}
    assert backend._ticket == "new-ticket"
    assert backend._csrf == "new-csrf"
    # GET was called twice (first 401, then retry)
    assert mock_client.get.call_count == 2
    # Login (POST /access/ticket) was called exactly once
    assert mock_client.post.call_count == 1
    assert "/access/ticket" in mock_client.post.call_args[0][0]


def test_get_on_persistent_401_raises(tmp_path):
    """If retry after re-login also returns 401, raise_for_status must raise."""
    pw_file = tmp_path / "password"
    pw_file.write_text("secret\n")

    login_resp = _make_login_resp()

    resp_401 = MagicMock()
    resp_401.status_code = 401

    resp_401_retry = MagicMock()
    resp_401_retry.status_code = 401
    resp_401_retry.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError("401", request=MagicMock(), response=MagicMock())
    )

    mock_client = MagicMock()
    mock_client.get.side_effect = [resp_401, resp_401_retry]
    mock_client.post.return_value = login_resp

    backend = PmgBackend(_cfg(password_path=str(pw_file)))
    backend._ticket = "stale-ticket"
    backend._csrf = "stale-csrf"
    backend._client = mock_client

    with pytest.raises(httpx.HTTPStatusError):
        backend._get("/nodes/pmg/version")
    assert mock_client.get.call_count == 2


def test_post_on_401_relogins_and_retries(tmp_path):
    """On HTTP 401 from POST: clear ticket, re-login once, retry; succeed on second try."""
    pw_file = tmp_path / "password"
    pw_file.write_text("secret\n")

    login_resp = _make_login_resp(ticket="new-ticket", csrf="new-csrf")

    resp_401 = MagicMock()
    resp_401.status_code = 401

    resp_200 = MagicMock()
    resp_200.status_code = 200
    resp_200.json.return_value = {"data": None}
    resp_200.raise_for_status = MagicMock()

    mock_client = MagicMock()
    # post: first call is the data POST (401), second is login, third is retry data POST
    mock_client.post.side_effect = [resp_401, login_resp, resp_200]

    backend = PmgBackend(_cfg(password_path=str(pw_file)))
    backend._ticket = "stale-ticket"
    backend._csrf = "stale-csrf"
    backend._client = mock_client

    backend._post("/quarantine/mails/abc123/deliver")

    # 3 POST calls: data-401, login, data-retry
    assert mock_client.post.call_count == 3
    assert "/access/ticket" in mock_client.post.call_args_list[1][0][0]


# ---------------------------------------------------------------------------
# PmgBackend HTTP methods — basic call-through
# ---------------------------------------------------------------------------

def test_get_calls_httpx_get():
    backend, mock_client = _mock_backend({"version": "8.0"})
    backend._get("/nodes/pmg/version")
    mock_client.get.assert_called_once()
    call_args = mock_client.get.call_args
    assert call_args[0][0] == "/nodes/pmg/version"


def test_get_with_params_passes_params():
    backend, mock_client = _mock_backend([])
    backend._get("/statistics/mail", params={"start": 1717000000})
    call_kwargs = mock_client.get.call_args[1]
    assert call_kwargs.get("params", {}).get("start") == 1717000000


def test_post_calls_httpx_post():
    backend, mock_client = _mock_backend(None)
    backend._post("/quarantine/mails/abc123/deliver")
    mock_client.post.assert_called_once()


def test_get_raises_for_status():
    """raise_for_status is called on every response."""
    backend, mock_client = _mock_backend({})
    backend._get("/nodes/pmg/version")
    mock_client.get.return_value.raise_for_status.assert_called_once()


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

class TestCheckNode:
    def test_valid_node(self):
        assert _check_node("pmg") == "pmg"

    def test_valid_node_with_hyphen(self):
        assert _check_node("pmg-node1") == "pmg-node1"

    def test_valid_alphanumeric(self):
        assert _check_node("mail1") == "mail1"

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_node("pmg/node")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_node("pmg\n")

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_node("")

    def test_rejects_leading_hyphen(self):
        with pytest.raises(ProximoError):
            _check_node("-pmg")

    def test_rejects_space(self):
        with pytest.raises(ProximoError):
            _check_node("pmg node")

    def test_rejects_dotdot(self):
        with pytest.raises(ProximoError):
            _check_node("../etc")


class TestCheckMailId:
    def test_valid_alphanumeric(self):
        assert _check_mail_id("abc123") == "abc123"

    def test_valid_with_dots_and_hyphens(self):
        assert _check_mail_id("msg-2024.01.15") == "msg-2024.01.15"

    def test_valid_with_underscore(self):
        assert _check_mail_id("A1_B2") == "A1_B2"

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_mail_id("abc/def")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_mail_id("abc\n")

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_mail_id("")

    def test_rejects_leading_dot(self):
        with pytest.raises(ProximoError):
            _check_mail_id(".hidden")

    def test_rejects_dotdot_traversal(self):
        with pytest.raises(ProximoError):
            _check_mail_id("../etc")


# ---------------------------------------------------------------------------
# _api() — recording SimpleNamespace for tool/plan tests
# ---------------------------------------------------------------------------

def _api() -> SimpleNamespace:
    """Minimal PMG API fake recording _get / _post / _put / _delete calls.

    Includes a mock config with username="root@pam" to match the real
    PmgBackend — quarantine_blocklist / quarantine_blocklist_add now
    default pmail to api.config.username when none is supplied (PMG 9.1
    live-verified: pmail is required for root@pam).

    W3: added _put and _delete recorders so W3 mutation ops can be tested
    without AttributeError.
    """
    seen: dict = {}

    def fake_get(path, params=None):
        seen["method"] = "GET"
        seen["path"] = path
        seen["params"] = params or {}
        return {}

    def fake_post(path, data=None):
        seen["method"] = "POST"
        seen["path"] = path
        seen["data"] = data or {}
        return None

    def fake_put(path, data=None):
        seen["method"] = "PUT"
        seen["path"] = path
        seen["data"] = data or {}
        return None

    def fake_delete(path, params=None):
        seen["method"] = "DELETE"
        seen["path"] = path
        seen["params"] = params or {}
        return None

    config = SimpleNamespace(username="root@pam")
    return SimpleNamespace(
        _get=fake_get, _post=fake_post, _put=fake_put, _delete=fake_delete,
        seen=seen, config=config,
    )


# ---------------------------------------------------------------------------
# READ operations — URL shapes and duck-typed API
# ---------------------------------------------------------------------------

class TestNodeVersion:
    def test_uses_correct_path(self):
        # PMG 9.1 live-verified: version is global; path is /version (no node segment)
        api = _api()
        node_version(api, "pmg")
        assert api.seen["path"] == "/version"
        assert api.seen["method"] == "GET"

    def test_node_not_in_path(self):
        # The node param is validated but NOT used in the path — PMG version is global
        api = _api()
        node_version(api, "mail1")
        assert api.seen["path"] == "/version"
        assert "mail1" not in api.seen["path"]

    def test_rejects_invalid_node(self):
        api = _api()
        with pytest.raises(ProximoError):
            node_version(api, "bad/node")

    def test_rejects_newline_in_node(self):
        api = _api()
        with pytest.raises(ProximoError):
            node_version(api, "pmg\n")


class TestAccessPermissions:
    def test_uses_correct_path(self):
        # PMG 9.1 live-verified: no /access/permissions endpoint; user/role info is
        # at /access/users
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path, params=params or {}) or []
        )
        access_permissions(api)
        assert api.seen["path"] == "/access/users"
        assert api.seen["method"] == "GET"

    def test_no_path_params(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        access_permissions(api)
        assert api.seen["params"] == {}


class TestNodeStatus:
    def test_uses_correct_path(self):
        api = _api()
        node_status(api, "pmg")
        assert api.seen["path"] == "/nodes/pmg/status"
        assert api.seen["method"] == "GET"

    def test_rejects_invalid_node(self):
        api = _api()
        with pytest.raises(ProximoError):
            node_status(api, "../etc")


class TestRelayConfig:
    def test_uses_correct_path(self):
        # PMG 9.1 live-verified: relay/smarthost settings are in /config/mail
        api = _api()
        relay_config(api)
        assert api.seen["path"] == "/config/mail"
        assert api.seen["method"] == "GET"


class TestDomainsList:
    def test_uses_correct_path(self):
        api = _api()
        # Patch to return a list (fake_get returns {} but domains_list falls back to [])
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path, params=params or {}) or []
        )
        domains_list(api)
        assert api.seen["path"] == "/config/domains"
        assert api.seen["method"] == "GET"

    def test_returns_list(self):
        api = _api()
        api._get = lambda path, params=None: []
        result = domains_list(api)
        assert isinstance(result, list)


class TestMailStatistics:
    def test_uses_correct_path(self):
        api = _api()
        statistics_mail(api)
        assert api.seen["path"] == "/statistics/mail"
        assert api.seen["method"] == "GET"

    def test_no_params_when_none(self):
        api = _api()
        statistics_mail(api)
        assert api.seen["params"] == {}


class TestQuarantineSpam:
    def test_uses_correct_path(self):
        # PMG 9.1 live-verified: spam quarantine list is at /quarantine/spam
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path, params=params or {}) or []
        )
        quarantine_spam(api)
        assert api.seen["path"] == "/quarantine/spam"
        assert api.seen["method"] == "GET"

    def test_no_params_when_none(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_spam(api)
        assert api.seen["params"] == {}


# ---------------------------------------------------------------------------
# MUTATION operations — URL shapes and methods
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# TLS hardening regression
# ---------------------------------------------------------------------------

def test_pmgbackend_ca_bundle_path_no_httpx_deprecation():
    """PMG backend with a CA-bundle path must not hit httpx's deprecated verify=<str>."""
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        backend = PmgBackend(_cfg(verify_tls=False, ca_bundle="/etc/ssl/certs/ca-certificates.crt"))
    assert backend._client is not None


# ---------------------------------------------------------------------------
# W2: _check_service validator
# ---------------------------------------------------------------------------

class TestCheckService:
    def test_valid_simple(self):
        assert _check_service("postfix") == "postfix"

    def test_valid_with_hyphen(self):
        assert _check_service("pmg-smtp-filter") == "pmg-smtp-filter"

    def test_valid_alphanumeric(self):
        assert _check_service("clamav") == "clamav"

    def test_valid_spamassassin(self):
        assert _check_service("spamassassin") == "spamassassin"

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_service("../../etc/passwd")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_service("postfix\n")

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_service("")

    def test_rejects_leading_hyphen(self):
        with pytest.raises(ProximoError):
            _check_service("-postfix")

    def test_rejects_space(self):
        with pytest.raises(ProximoError):
            _check_service("pmg daemon")


# ---------------------------------------------------------------------------
# W2 READ operations — URL shapes and duck-typed API
# ---------------------------------------------------------------------------

class TestStatisticsDomains:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path, params=params or {}) or []
        )
        statistics_domains(api)
        assert api.seen["path"] == "/statistics/domains"

    def test_maps_start_to_starttime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_domains(api, start=1717000000)
        assert api.seen["params"].get("starttime") == 1717000000
        assert "start" not in api.seen["params"]

    def test_maps_end_to_endtime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_domains(api, end=1717099999)
        assert api.seen["params"].get("endtime") == 1717099999
        assert "end" not in api.seen["params"]

    def test_no_params_when_neither_given(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params) or []
        )
        statistics_domains(api)
        # params should be None when no start/end given
        assert api.seen.get("params") is None

    def test_rejects_non_int_start(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_domains(api, start="not-a-time")

    def test_rejects_non_int_end(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_domains(api, end="not-a-time")


class TestStatisticsVirus:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path, params=params or {}) or []
        )
        statistics_virus(api)
        assert api.seen["path"] == "/statistics/virus"

    def test_maps_start_to_starttime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_virus(api, start=1717000000)
        assert api.seen["params"].get("starttime") == 1717000000

    def test_rejects_non_int_start(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_virus(api, start="bad")


class TestStatisticsSpamscores:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path, params=params or {}) or []
        )
        statistics_spamscores(api)
        assert api.seen["path"] == "/statistics/spamscores"

    def test_maps_start_to_starttime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_spamscores(api, start=1717000000, end=1717099999)
        assert api.seen["params"].get("starttime") == 1717000000
        assert api.seen["params"].get("endtime") == 1717099999

    def test_rejects_non_int_end(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_spamscores(api, end="bad")


class TestStatisticsRecent:
    def test_uses_correct_path(self):
        api = _api()
        statistics_recent(api)
        assert api.seen["path"] == "/statistics/recent"
        assert api.seen["method"] == "GET"

    def test_hours_forwarded_as_param(self):
        api = _api()
        statistics_recent(api, hours=6)
        assert api.seen["params"].get("hours") == 6

    def test_default_hours_is_1(self):
        api = _api()
        statistics_recent(api)
        assert api.seen["params"].get("hours") == 1

    def test_invalid_hours_raises_proximo_error(self):
        api = _api()
        with pytest.raises(ProximoError, match="invalid hours"):
            statistics_recent(api, hours="bad")


class TestQuarantineBlocklistList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path, params=params) or []
        )
        quarantine_blocklist_list(api)
        assert api.seen["path"] == "/quarantine/blocklist"

    def test_pmail_defaults_to_username_when_none(self):
        # PMG 9.1 live-verified: pmail is required for root@pam.
        # When no pmail is given, the function defaults to api.config.username.
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params) or []
        )
        quarantine_blocklist_list(api)
        # No explicit pmail → defaults to api.config.username ("root@pam")
        assert api.seen.get("params") == {"pmail": "root@pam"}

    def test_pmail_included_when_provided(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_blocklist_list(api, pmail="user@example.com")
        assert api.seen["params"].get("pmail") == "user@example.com"


class TestPostfixQshape:
    def test_uses_correct_path(self):
        api = _api()
        postfix_qshape(api, "pmg")
        assert api.seen["path"] == "/nodes/pmg/postfix/qshape"
        assert api.seen["method"] == "GET"

    def test_rejects_invalid_node(self):
        api = _api()
        with pytest.raises(ProximoError):
            postfix_qshape(api, "../etc")


class TestSpamConfig:
    def test_uses_correct_path(self):
        api = _api()
        spam_config(api)
        assert api.seen["path"] == "/config/spam"
        assert api.seen["method"] == "GET"


class TestServiceStatus:
    def test_uses_correct_path(self):
        api = _api()
        service_status(api, "postfix", "pmg")
        assert api.seen["path"] == "/nodes/pmg/services/postfix/state"
        assert api.seen["method"] == "GET"

    def test_defaults_node_to_pmg(self):
        api = _api()
        service_status(api, "clamav")
        assert "/nodes/pmg/services/clamav/state" == api.seen["path"]

    def test_rejects_invalid_service(self):
        api = _api()
        with pytest.raises(ProximoError):
            service_status(api, "../../etc/passwd")

    def test_rejects_service_with_newline(self):
        api = _api()
        with pytest.raises(ProximoError):
            service_status(api, "postfix\n")

    def test_rejects_invalid_node(self):
        api = _api()
        with pytest.raises(ProximoError):
            service_status(api, "postfix", "../etc")


# ---------------------------------------------------------------------------
# W2 MUTATION operations — body shapes
# ---------------------------------------------------------------------------

class TestQuarantineBlocklistAdd:
    def test_uses_correct_path_and_method(self):
        api = _api()
        quarantine_blocklist_add(api, "spam@evil.com")
        assert api.seen["path"] == "/quarantine/blocklist"
        assert api.seen["method"] == "POST"

    def test_body_includes_address(self):
        api = _api()
        quarantine_blocklist_add(api, "spam@evil.com")
        assert api.seen["data"].get("address") == "spam@evil.com"

    def test_pmail_included_in_body_when_given(self):
        api = _api()
        quarantine_blocklist_add(api, "spam@evil.com", pmail="user@example.com")
        assert api.seen["data"].get("pmail") == "user@example.com"

    def test_pmail_defaults_to_username_when_none(self):
        # PMG 9.1 live-verified: pmail is required for root@pam.
        # When no pmail is given, defaults to api.config.username.
        api = _api()
        quarantine_blocklist_add(api, "spam@evil.com")
        assert api.seen["data"].get("pmail") == "root@pam"


class TestQuarantineAction:
    def test_uses_correct_path_and_method(self):
        api = _api()
        quarantine_action(api, "deliver", "abc123")
        assert api.seen["path"] == "/quarantine/content"
        assert api.seen["method"] == "POST"

    def test_body_includes_action(self):
        api = _api()
        quarantine_action(api, "delete", "abc123")
        assert api.seen["data"].get("action") == "delete"

    def test_body_includes_id(self):
        api = _api()
        quarantine_action(api, "deliver", "abc123")
        assert api.seen["data"].get("id") == "abc123"

    def test_invalid_action_raises_proximo_error(self):
        api = _api()
        with pytest.raises(ProximoError, match="invalid quarantine action"):
            quarantine_action(api, "explode", "abc123")

    def test_all_valid_actions_accepted(self):
        for action in ("deliver", "delete", "mark-seen", "mark-unseen", "blocklist", "welcomelist"):
            api = _api()
            quarantine_action(api, action, "abc123")  # must not raise
            assert api.seen["data"].get("action") == action


class TestPostfixFlush:
    def test_uses_correct_path_and_method(self):
        api = _api()
        postfix_flush(api, "pmg")
        assert api.seen["path"] == "/nodes/pmg/postfix/flush_queues"
        assert api.seen["method"] == "POST"

    def test_rejects_invalid_node(self):
        api = _api()
        with pytest.raises(ProximoError):
            postfix_flush(api, "../etc")


# ---------------------------------------------------------------------------
# W2 PLAN operations — risk ratings and blast radius
# ---------------------------------------------------------------------------

class TestPlanQuarantineBlocklistAdd:
    def test_risk_is_low(self):
        p = plan_quarantine_blocklist_add("spam@evil.com")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_quarantine_blocklist_add("spam@evil.com")
        assert p.action == "pmg_quarantine_blocklist_add"

    def test_blast_radius_non_empty(self):
        p = plan_quarantine_blocklist_add("spam@evil.com")
        assert len(p.blast_radius) > 0

    def test_blast_mentions_additive(self):
        p = plan_quarantine_blocklist_add("spam@evil.com")
        text = " ".join(p.blast_radius).lower()
        assert "additive" in text or "not deleted" in text or "no message" in text

    def test_change_mentions_address(self):
        p = plan_quarantine_blocklist_add("spam@evil.com")
        assert "spam@evil.com" in p.change

    def test_rejects_invalid_mail_id(self):
        # No _check on address (it's POST body, not a URL segment) — just verify plan builds
        p = plan_quarantine_blocklist_add("any-address")
        assert p.action == "pmg_quarantine_blocklist_add"


class TestPlanQuarantineAction:
    def test_risk_is_medium(self):
        p = plan_quarantine_action("deliver", "abc123")
        assert p.risk == RISK_MEDIUM

    def test_delete_is_high(self):
        # permanent, irreversible message deletion must be HIGH, not MEDIUM
        p = plan_quarantine_action("delete", "abc123")
        assert p.risk == RISK_HIGH

    def test_action_string(self):
        p = plan_quarantine_action("delete", "abc123")
        assert p.action == "pmg_quarantine_action"

    def test_blast_radius_mentions_delete_irreversible(self):
        p = plan_quarantine_action("delete", "abc123")
        text = " ".join(p.blast_radius).lower()
        assert "irreversible" in text or "permanent" in text

    def test_blast_radius_mentions_action(self):
        p = plan_quarantine_action("deliver", "abc123")
        text = " ".join(p.blast_radius).lower()
        assert "deliver" in text

    def test_invalid_action_raises_proximo_error(self):
        with pytest.raises(ProximoError, match="invalid quarantine action"):
            plan_quarantine_action("explode", "abc123")

    def test_change_mentions_action_and_ids(self):
        p = plan_quarantine_action("mark-seen", "abc123")
        assert "mark-seen" in p.change
        assert "abc123" in p.change


class TestPlanPostfixFlush:
    def test_risk_is_low(self):
        p = plan_postfix_flush("pmg")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_postfix_flush("pmg")
        assert p.action == "pmg_postfix_flush"

    def test_blast_radius_non_empty(self):
        p = plan_postfix_flush("pmg")
        assert len(p.blast_radius) > 0

    def test_blast_mentions_queue_flush(self):
        p = plan_postfix_flush("pmg")
        text = " ".join(p.blast_radius).lower()
        assert "queue" in text or "flush" in text or "deliver" in text

    def test_rejects_invalid_node(self):
        with pytest.raises(ProximoError):
            plan_postfix_flush("../etc")


# ---------------------------------------------------------------------------
# W3: validators
# ---------------------------------------------------------------------------

class TestCheckDomain:
    def test_valid_simple_domain(self):
        assert _check_domain("example.com") == "example.com"

    def test_valid_single_char(self):
        assert _check_domain("a") == "a"

    def test_valid_with_hyphens(self):
        assert _check_domain("my-mail-server.example.com") == "my-mail-server.example.com"

    def test_valid_with_underscores(self):
        assert _check_domain("_dmarc.example.com") == "_dmarc.example.com"

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_domain("example/com")

    def test_rejects_dotdot_traversal(self):
        with pytest.raises(ProximoError):
            _check_domain("../etc")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_domain("example.com\n")

    def test_rejects_space(self):
        with pytest.raises(ProximoError):
            _check_domain("example com")

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_domain("")

    def test_rejects_leading_hyphen(self):
        with pytest.raises(ProximoError):
            _check_domain("-example.com")


class TestCheckCidr:
    def test_valid_ipv4_cidr(self):
        assert _check_cidr("10.0.0.0/8") == "10.0.0.0/8"

    def test_valid_slash32(self):
        assert _check_cidr("192.168.1.1/32") == "192.168.1.1/32"

    def test_valid_ipv6_cidr(self):
        _check_cidr("2001:db8::/32")  # must not raise

    def test_rejects_invalid_cidr(self):
        with pytest.raises(ProximoError):
            _check_cidr("not-a-cidr")

    def test_rejects_dotdot_traversal(self):
        with pytest.raises(ProximoError):
            _check_cidr("../etc")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_cidr("10.0.0.0/8\n")

    def test_rejects_invalid_octet(self):
        # IPv4 octets must be 0-255; 300 is out of range
        with pytest.raises(ProximoError):
            _check_cidr("300.300.300.300/8")


class TestCheckTransportProtocol:
    def test_valid_smtp(self):
        assert _check_transport_protocol("smtp") == "smtp"

    def test_valid_lmtp(self):
        assert _check_transport_protocol("lmtp") == "lmtp"

    def test_rejects_ftp(self):
        with pytest.raises(ProximoError):
            _check_transport_protocol("ftp")

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_transport_protocol("")

    def test_rejects_uppercase(self):
        with pytest.raises(ProximoError):
            _check_transport_protocol("SMTP")

    def test_error_message_lists_valid_values(self):
        with pytest.raises(ProximoError, match="lmtp"):
            _check_transport_protocol("ftp")


class TestCheckServiceAction:
    def test_valid_start(self):
        assert _check_service_action("start") == "start"

    def test_valid_stop(self):
        assert _check_service_action("stop") == "stop"

    def test_valid_restart(self):
        assert _check_service_action("restart") == "restart"

    def test_valid_reload(self):
        assert _check_service_action("reload") == "reload"

    def test_rejects_invalid(self):
        with pytest.raises(ProximoError):
            _check_service_action("explode")

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_service_action("")

    def test_error_message_lists_valid_values(self):
        with pytest.raises(ProximoError, match="restart"):
            _check_service_action("kill")


# ---------------------------------------------------------------------------
# W3 READ operations — URL shapes
# ---------------------------------------------------------------------------

class TestQuarantineWelcomelistList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path, params=params) or []
        )
        quarantine_welcomelist_list(api)
        assert api.seen["path"] == "/quarantine/welcomelist"
        assert api.seen["method"] == "GET"

    def test_pmail_defaults_to_username_when_none(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params) or []
        )
        quarantine_welcomelist_list(api)
        assert api.seen.get("params", {}).get("pmail") == "root@pam"

    def test_pmail_passed_when_provided(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_welcomelist_list(api, pmail="user@example.com")
        assert api.seen["params"].get("pmail") == "user@example.com"


# ---------------------------------------------------------------------------
# W3 MUTATION operations — body / path shapes
# ---------------------------------------------------------------------------

class TestDomainCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        domain_create(api, "example.com")
        assert api.seen["path"] == "/config/domains"
        assert api.seen["method"] == "POST"

    def test_body_includes_domain(self):
        api = _api()
        domain_create(api, "example.com")
        assert api.seen["data"].get("domain") == "example.com"

    def test_comment_included_when_provided(self):
        api = _api()
        domain_create(api, "example.com", comment="primary domain")
        assert api.seen["data"].get("comment") == "primary domain"

    def test_comment_absent_when_not_provided(self):
        api = _api()
        domain_create(api, "example.com")
        assert "comment" not in api.seen["data"]

    def test_rejects_invalid_domain(self):
        api = _api()
        with pytest.raises(ProximoError):
            domain_create(api, "../etc")


class TestDomainDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        domain_delete(api, "example.com")
        assert api.seen["path"] == "/config/domains/example.com"
        assert api.seen["method"] == "DELETE"

    def test_rejects_invalid_domain(self):
        api = _api()
        with pytest.raises(ProximoError):
            domain_delete(api, "bad/domain")


class TestTransportCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        transport_create(api, "example.com", "relay.example.com")
        assert api.seen["path"] == "/config/transport"
        assert api.seen["method"] == "POST"

    def test_body_includes_required_fields(self):
        api = _api()
        transport_create(api, "example.com", "relay.example.com")
        d = api.seen["data"]
        assert d.get("domain") == "example.com"
        assert d.get("host") == "relay.example.com"
        assert d.get("port") == 25
        assert d.get("protocol") == "smtp"

    def test_custom_port_and_protocol(self):
        api = _api()
        transport_create(api, "example.com", "relay.example.com", port=24, protocol="lmtp")
        assert api.seen["data"]["port"] == 24
        assert api.seen["data"]["protocol"] == "lmtp"

    def test_rejects_invalid_protocol(self):
        api = _api()
        with pytest.raises(ProximoError):
            transport_create(api, "example.com", "relay.example.com", protocol="ftp")

    def test_rejects_invalid_domain(self):
        api = _api()
        with pytest.raises(ProximoError):
            transport_create(api, "../etc", "relay.example.com")

    def test_rejects_port_out_of_range(self):
        api = _api()
        with pytest.raises(ProximoError):
            transport_create(api, "example.com", "relay.example.com", port=0)

    def test_rejects_port_too_large(self):
        api = _api()
        with pytest.raises(ProximoError):
            transport_create(api, "example.com", "relay.example.com", port=65536)


class TestTransportDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        transport_delete(api, "example.com")
        assert api.seen["path"] == "/config/transport/example.com"
        assert api.seen["method"] == "DELETE"

    def test_rejects_invalid_domain(self):
        api = _api()
        with pytest.raises(ProximoError):
            transport_delete(api, "bad/domain")


class TestMynetworksAdd:
    def test_uses_correct_path_and_method(self):
        api = _api()
        mynetworks_add(api, "10.0.0.0/8")
        assert api.seen["path"] == "/config/mynetworks"
        assert api.seen["method"] == "POST"

    def test_body_includes_cidr(self):
        api = _api()
        mynetworks_add(api, "10.0.0.0/8")
        assert api.seen["data"].get("cidr") == "10.0.0.0/8"

    def test_rejects_invalid_cidr(self):
        api = _api()
        with pytest.raises(ProximoError):
            mynetworks_add(api, "not-a-cidr")


class TestMynetworksRemove:
    def test_uses_correct_path_and_method(self):
        api = _api()
        mynetworks_remove(api, "10.0.0.0/8")
        assert api.seen["method"] == "DELETE"

    def test_cidr_slash_is_url_encoded_in_path(self):
        api = _api()
        mynetworks_remove(api, "10.0.0.0/8")
        # / → %2F so PMG does not interpret it as a path separator
        assert api.seen["path"] == "/config/mynetworks/10.0.0.0%2F8"

    def test_rejects_invalid_cidr(self):
        api = _api()
        with pytest.raises(ProximoError):
            mynetworks_remove(api, "not-a-cidr")


# ---------------------------------------------------------------------------
# Wave 9d — mail routing config remainder: validators
# ---------------------------------------------------------------------------

class TestCheckTlsDestination:
    def test_valid_plain_domain(self):
        assert _check_tls_destination("example.com") == "example.com"

    def test_valid_nexthop_with_brackets_and_port(self):
        assert _check_tls_destination("[relay.example.com]:587") == "[relay.example.com]:587"

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_tls_destination("")

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_tls_destination("relay/example.com")

    def test_rejects_dotdot(self):
        with pytest.raises(ProximoError):
            _check_tls_destination("../etc")

    def test_rejects_whitespace(self):
        with pytest.raises(ProximoError):
            _check_tls_destination("relay example.com")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_tls_destination("relay.example.com\n")


class TestCheckRegextestField:
    def test_accepts_within_bound(self):
        assert _check_regextest_field("a" * 1024, "regex") == "a" * 1024

    def test_rejects_over_bound(self):
        with pytest.raises(ProximoError):
            _check_regextest_field("a" * 1025, "regex")


# ---------------------------------------------------------------------------
# Wave 9d READ operations — URL shapes
# ---------------------------------------------------------------------------

class TestDomainGet:
    def test_uses_correct_path_and_method(self):
        api = _api()
        domain_get(api, "example.com")
        assert api.seen["path"] == "/config/domains/example.com"
        assert api.seen["method"] == "GET"

    def test_rejects_invalid_domain(self):
        api = _api()
        with pytest.raises(ProximoError):
            domain_get(api, "bad/domain")


class TestTransportList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path) or []
        )
        transport_list(api)
        assert api.seen["path"] == "/config/transport"
        assert api.seen["method"] == "GET"


class TestTransportGet:
    def test_uses_correct_path_and_method(self):
        api = _api()
        transport_get(api, "example.com")
        assert api.seen["path"] == "/config/transport/example.com"
        assert api.seen["method"] == "GET"

    def test_rejects_invalid_domain(self):
        api = _api()
        with pytest.raises(ProximoError):
            transport_get(api, "bad/domain")


class TestMynetworksList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path) or []
        )
        mynetworks_list(api)
        assert api.seen["path"] == "/config/mynetworks"
        assert api.seen["method"] == "GET"


class TestMynetworksGet:
    def test_uses_correct_path_and_method(self):
        api = _api()
        mynetworks_get(api, "10.0.0.0/8")
        assert api.seen["path"] == "/config/mynetworks/10.0.0.0%2F8"
        assert api.seen["method"] == "GET"

    def test_rejects_invalid_cidr(self):
        api = _api()
        with pytest.raises(ProximoError):
            mynetworks_get(api, "not-a-cidr")


class TestTlspolicyList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path) or []
        )
        tlspolicy_list(api)
        assert api.seen["path"] == "/config/tlspolicy"
        assert api.seen["method"] == "GET"


class TestTlspolicyGet:
    def test_uses_correct_path_and_method(self):
        api = _api()
        tlspolicy_get(api, "example.com")
        assert api.seen["path"] == "/config/tlspolicy/example.com"
        assert api.seen["method"] == "GET"

    def test_destination_is_url_encoded(self):
        api = _api()
        tlspolicy_get(api, "[relay.example.com]:587")
        assert api.seen["path"] == "/config/tlspolicy/%5Brelay.example.com%5D%3A587"

    def test_rejects_invalid_destination(self):
        api = _api()
        with pytest.raises(ProximoError):
            tlspolicy_get(api, "bad/destination")


class TestTlsInboundDomainsList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path) or []
        )
        tls_inbound_domains_list(api)
        assert api.seen["path"] == "/config/tls-inbound-domains"
        assert api.seen["method"] == "GET"

    def test_returns_list_of_strings(self):
        api = _api()
        api._get = lambda path, params=None: ["example.com", "other.example.com"]
        result = tls_inbound_domains_list(api)
        assert result == ["example.com", "other.example.com"]
        assert all(isinstance(x, str) for x in result)


class TestMimetypesList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(method="GET", path=path) or []
        )
        mimetypes_list(api)
        assert api.seen["path"] == "/config/mimetypes"
        assert api.seen["method"] == "GET"


class TestRegextest:
    def test_uses_correct_path_and_method(self):
        api = _api()
        regextest(api, "^foo", "foobar")
        assert api.seen["path"] == "/config/regextest"
        assert api.seen["method"] == "POST"

    def test_body_includes_regex_and_text(self):
        api = _api()
        regextest(api, "^foo", "foobar")
        assert api.seen["data"].get("regex") == "^foo"
        assert api.seen["data"].get("text") == "foobar"

    def test_rejects_regex_too_long(self):
        api = _api()
        with pytest.raises(ProximoError):
            regextest(api, "a" * 1025, "text")

    def test_rejects_text_too_long(self):
        api = _api()
        with pytest.raises(ProximoError):
            regextest(api, "regex", "a" * 1025)


# ---------------------------------------------------------------------------
# Wave 9d MUTATION operations — body / path shapes
# ---------------------------------------------------------------------------

class TestDomainUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        domain_update(api, "example.com", "a comment")
        assert api.seen["path"] == "/config/domains/example.com"
        assert api.seen["method"] == "PUT"

    def test_body_includes_only_comment(self):
        api = _api()
        domain_update(api, "example.com", "a comment")
        assert api.seen["data"] == {"comment": "a comment"}

    def test_empty_comment_allowed(self):
        api = _api()
        domain_update(api, "example.com", "")
        assert api.seen["data"] == {"comment": ""}

    def test_rejects_invalid_domain(self):
        api = _api()
        with pytest.raises(ProximoError):
            domain_update(api, "bad/domain", "x")


class TestTransportUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        transport_update(api, "example.com", host="relay2.example.com")
        assert api.seen["path"] == "/config/transport/example.com"
        assert api.seen["method"] == "PUT"

    def test_body_omits_domain(self):
        api = _api()
        transport_update(api, "example.com", host="relay2.example.com")
        assert "domain" not in api.seen["data"]
        assert api.seen["data"] == {"host": "relay2.example.com"}

    def test_body_includes_only_provided_fields(self):
        api = _api()
        transport_update(api, "example.com", comment="new comment", port=587)
        assert api.seen["data"] == {"comment": "new comment", "port": 587}

    def test_rejects_no_fields_provided(self):
        api = _api()
        with pytest.raises(ProximoError):
            transport_update(api, "example.com")

    def test_rejects_invalid_protocol(self):
        api = _api()
        with pytest.raises(ProximoError):
            transport_update(api, "example.com", protocol="ftp")

    def test_rejects_port_out_of_range(self):
        api = _api()
        with pytest.raises(ProximoError):
            transport_update(api, "example.com", port=0)

    def test_rejects_invalid_domain(self):
        api = _api()
        with pytest.raises(ProximoError):
            transport_update(api, "bad/domain", comment="x")


class TestMynetworksUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        mynetworks_update(api, "10.0.0.0/8", "internal net")
        assert api.seen["path"] == "/config/mynetworks/10.0.0.0%2F8"
        assert api.seen["method"] == "PUT"

    def test_body_includes_only_comment(self):
        api = _api()
        mynetworks_update(api, "10.0.0.0/8", "internal net")
        assert api.seen["data"] == {"comment": "internal net"}

    def test_rejects_invalid_cidr(self):
        api = _api()
        with pytest.raises(ProximoError):
            mynetworks_update(api, "not-a-cidr", "x")


class TestTlspolicyCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        tlspolicy_create(api, "example.com", "secure")
        assert api.seen["path"] == "/config/tlspolicy"
        assert api.seen["method"] == "POST"

    def test_body_includes_destination_and_policy(self):
        api = _api()
        tlspolicy_create(api, "example.com", "secure")
        assert api.seen["data"] == {"destination": "example.com", "policy": "secure"}

    def test_rejects_invalid_destination(self):
        api = _api()
        with pytest.raises(ProximoError):
            tlspolicy_create(api, "bad/destination", "secure")

    def test_rejects_empty_policy(self):
        api = _api()
        with pytest.raises(ProximoError):
            tlspolicy_create(api, "example.com", "")


class TestTlspolicyUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        tlspolicy_update(api, "example.com", "none")
        assert api.seen["path"] == "/config/tlspolicy/example.com"
        assert api.seen["method"] == "PUT"

    def test_body_includes_only_policy(self):
        api = _api()
        tlspolicy_update(api, "example.com", "none")
        assert api.seen["data"] == {"policy": "none"}

    def test_rejects_empty_policy(self):
        api = _api()
        with pytest.raises(ProximoError):
            tlspolicy_update(api, "example.com", "")


class TestTlspolicyDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        tlspolicy_delete(api, "example.com")
        assert api.seen["path"] == "/config/tlspolicy/example.com"
        assert api.seen["method"] == "DELETE"

    def test_rejects_invalid_destination(self):
        api = _api()
        with pytest.raises(ProximoError):
            tlspolicy_delete(api, "bad/destination")


class TestTlsInboundDomainsCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        tls_inbound_domains_create(api, "example.com")
        assert api.seen["path"] == "/config/tls-inbound-domains"
        assert api.seen["method"] == "POST"

    def test_body_includes_domain(self):
        api = _api()
        tls_inbound_domains_create(api, "example.com")
        assert api.seen["data"] == {"domain": "example.com"}

    def test_rejects_invalid_domain(self):
        api = _api()
        with pytest.raises(ProximoError):
            tls_inbound_domains_create(api, "bad/domain")


class TestTlsInboundDomainsDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        tls_inbound_domains_delete(api, "example.com")
        assert api.seen["path"] == "/config/tls-inbound-domains/example.com"
        assert api.seen["method"] == "DELETE"

    def test_rejects_invalid_domain(self):
        api = _api()
        with pytest.raises(ProximoError):
            tls_inbound_domains_delete(api, "bad/domain")


class TestSpamConfigUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        spam_config_update(api, bounce_score=5)
        assert api.seen["path"] == "/config/spam"
        assert api.seen["method"] == "PUT"

    def test_only_non_none_fields_in_body(self):
        api = _api()
        spam_config_update(api, bounce_score=5, use_bayes=None, use_razor=None)
        data = api.seen["data"]
        assert "bounce_score" in data
        assert "use_bayes" not in data
        assert "use_razor" not in data

    def test_multiple_fields_sent(self):
        api = _api()
        spam_config_update(api, use_bayes=True, maxspamsize=1000)
        data = api.seen["data"]
        assert "use_bayes" in data
        assert "maxspamsize" in data
        assert "bounce_score" not in data

    def test_empty_body_when_all_none(self):
        # When all kwargs are None, the body is empty (no PMG fields overridden)
        api = _api()
        spam_config_update(api)
        assert api.seen["data"] == {}


class TestQuarantineWelcomelistAdd:
    def test_uses_correct_path_and_method(self):
        api = _api()
        quarantine_welcomelist_add(api, "good@example.com")
        assert api.seen["path"] == "/quarantine/welcomelist"
        assert api.seen["method"] == "POST"

    def test_body_includes_address_and_pmail(self):
        api = _api()
        quarantine_welcomelist_add(api, "good@example.com")
        d = api.seen["data"]
        assert d.get("address") == "good@example.com"
        assert d.get("pmail") == "root@pam"  # defaults to api.config.username

    def test_pmail_override(self):
        api = _api()
        quarantine_welcomelist_add(api, "good@example.com", pmail="user@example.com")
        assert api.seen["data"].get("pmail") == "user@example.com"


class TestQuarantineWelcomelistRemove:
    def test_uses_correct_path_and_method(self):
        api = _api()
        quarantine_welcomelist_remove(api, "good@example.com")
        assert api.seen["path"] == "/quarantine/welcomelist"
        assert api.seen["method"] == "DELETE"

    def test_address_and_pmail_as_params(self):
        api = _api()
        quarantine_welcomelist_remove(api, "good@example.com")
        p = api.seen["params"]
        assert p.get("address") == "good@example.com"
        assert p.get("pmail") == "root@pam"

    def test_pmail_override(self):
        api = _api()
        quarantine_welcomelist_remove(api, "good@example.com", pmail="user@example.com")
        assert api.seen["params"].get("pmail") == "user@example.com"


class TestQuarantineBlocklistRemove:
    """Test the W2 executor that the W3 plan function now gates."""

    def test_uses_correct_path_and_method(self):
        api = _api()
        quarantine_blocklist_remove(api, "spam@evil.com")
        assert api.seen["path"] == "/quarantine/blocklist"
        assert api.seen["method"] == "DELETE"

    def test_address_and_pmail_as_params(self):
        api = _api()
        quarantine_blocklist_remove(api, "spam@evil.com")
        p = api.seen["params"]
        assert p.get("address") == "spam@evil.com"
        assert p.get("pmail") == "root@pam"  # defaults to api.config.username

    def test_pmail_override(self):
        api = _api()
        quarantine_blocklist_remove(api, "spam@evil.com", pmail="user@example.com")
        assert api.seen["params"].get("pmail") == "user@example.com"


class TestQuarantineBlocklistRemovePlan:
    """Test the new plan function (executor already existed in W2)."""

    def test_risk_is_low(self):
        p = plan_quarantine_blocklist_remove("spam@evil.com")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_quarantine_blocklist_remove("spam@evil.com")
        assert p.action == "pmg_quarantine_blocklist_remove"

    def test_change_mentions_address(self):
        p = plan_quarantine_blocklist_remove("spam@evil.com")
        assert "spam@evil.com" in p.change

    def test_blast_radius_non_empty(self):
        p = plan_quarantine_blocklist_remove("spam@evil.com")
        assert len(p.blast_radius) > 0

    def test_target_is_quarantine_blocklist(self):
        p = plan_quarantine_blocklist_remove("spam@evil.com")
        assert "blocklist" in p.target


class TestServiceControl:
    def test_uses_correct_path_and_method(self):
        api = _api()
        service_control(api, "postfix", "restart", "pmg")
        assert api.seen["path"] == "/nodes/pmg/services/postfix/restart"
        assert api.seen["method"] == "POST"

    def test_defaults_node_to_pmg(self):
        api = _api()
        service_control(api, "clamav", "stop")
        assert api.seen["path"] == "/nodes/pmg/services/clamav/stop"

    def test_rejects_invalid_action(self):
        api = _api()
        with pytest.raises(ProximoError):
            service_control(api, "postfix", "explode")

    def test_rejects_invalid_service(self):
        api = _api()
        with pytest.raises(ProximoError):
            service_control(api, "../../etc/passwd", "start")

    def test_all_valid_actions_accepted(self):
        for action in ("start", "stop", "restart", "reload"):
            api = _api()
            service_control(api, "postfix", action, "pmg")  # must not raise
            assert action in api.seen["path"]


# ---------------------------------------------------------------------------
# W3 PLAN operations — risk ratings and blast radius
# ---------------------------------------------------------------------------

class TestPlanDomainCreate:
    def test_risk_is_low(self):
        p = plan_domain_create("example.com")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_domain_create("example.com")
        assert p.action == "pmg_domain_create"

    def test_change_mentions_domain(self):
        p = plan_domain_create("example.com")
        assert "example.com" in p.change

    def test_blast_radius_non_empty(self):
        p = plan_domain_create("example.com")
        assert len(p.blast_radius) > 0

    def test_rejects_invalid_domain(self):
        with pytest.raises(ProximoError):
            plan_domain_create("../etc")


class TestPlanDomainDelete:
    def test_risk_is_medium(self):
        p = plan_domain_delete("example.com")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_domain_delete("example.com")
        assert p.action == "pmg_domain_delete"

    def test_change_mentions_domain(self):
        p = plan_domain_delete("example.com")
        assert "example.com" in p.change

    def test_rejects_invalid_domain(self):
        with pytest.raises(ProximoError):
            plan_domain_delete("bad/domain")


class TestPlanTransportCreate:
    def test_risk_is_low(self):
        p = plan_transport_create("example.com", "relay.example.com")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_transport_create("example.com", "relay.example.com")
        assert p.action == "pmg_transport_create"

    def test_change_mentions_domain_and_host(self):
        p = plan_transport_create("example.com", "relay.example.com")
        assert "example.com" in p.change
        assert "relay.example.com" in p.change

    def test_rejects_invalid_protocol(self):
        with pytest.raises(ProximoError):
            plan_transport_create("example.com", "relay.example.com", protocol="ftp")

    def test_rejects_invalid_domain(self):
        with pytest.raises(ProximoError):
            plan_transport_create("bad/domain", "relay.example.com")


class TestPlanTransportDelete:
    def test_risk_is_medium(self):
        p = plan_transport_delete("example.com")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_transport_delete("example.com")
        assert p.action == "pmg_transport_delete"

    def test_rejects_invalid_domain(self):
        with pytest.raises(ProximoError):
            plan_transport_delete("bad/domain")


class TestPlanMynetworksAdd:
    def test_risk_is_low(self):
        p = plan_mynetworks_add("10.0.0.0/8")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_mynetworks_add("10.0.0.0/8")
        assert p.action == "pmg_mynetworks_add"

    def test_change_mentions_cidr(self):
        p = plan_mynetworks_add("10.0.0.0/8")
        assert "10.0.0.0/8" in p.change

    def test_rejects_invalid_cidr(self):
        with pytest.raises(ProximoError):
            plan_mynetworks_add("not-a-cidr")


class TestPlanMynetworksRemove:
    def test_risk_is_medium(self):
        p = plan_mynetworks_remove("10.0.0.0/8")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_mynetworks_remove("10.0.0.0/8")
        assert p.action == "pmg_mynetworks_remove"

    def test_rejects_invalid_cidr(self):
        with pytest.raises(ProximoError):
            plan_mynetworks_remove("not-a-cidr")


# ---------------------------------------------------------------------------
# Wave 9d PLAN functions
# ---------------------------------------------------------------------------

class TestPlanDomainUpdate:
    def test_risk_is_low(self):
        p = plan_domain_update("example.com", "new comment")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_domain_update("example.com", "new comment")
        assert p.action == "pmg_domain_update"

    def test_change_mentions_comment(self):
        p = plan_domain_update("example.com", "new comment")
        assert "new comment" in p.change

    def test_rejects_invalid_domain(self):
        with pytest.raises(ProximoError):
            plan_domain_update("bad/domain", "x")


class TestPlanTransportUpdate:
    def test_risk_is_medium(self):
        p = plan_transport_update("example.com", host="relay2.example.com")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_transport_update("example.com", host="relay2.example.com")
        assert p.action == "pmg_transport_update"

    def test_rejects_no_fields_provided(self):
        with pytest.raises(ProximoError):
            plan_transport_update("example.com")

    def test_rejects_invalid_domain(self):
        with pytest.raises(ProximoError):
            plan_transport_update("bad/domain", comment="x")

    def test_comment_only_blast_radius_notes_no_routing_effect(self):
        p = plan_transport_update("example.com", comment="just a note")
        joined = " ".join(p.blast_radius)
        assert "comment-only" in joined.lower()

    def test_host_change_blast_radius_warns_of_reroute(self):
        p = plan_transport_update("example.com", host="relay2.example.com")
        joined = " ".join(p.blast_radius).lower()
        assert "rerouted" in joined or "reroute" in joined

    def test_use_mx_only_change_blast_radius_warns_of_delivery_impact(self):
        # use_mx is named in this function's OWN docstring in the same breath as host/port/
        # protocol as delivery-affecting ("changing host/port/protocol/use_mx changes where mail
        # ... is actually delivered") — but the reroute-warning check-set only tested
        # {"host", "port", "protocol"}, dropping use_mx. A use_mx-only call must not produce a
        # bare one-line preview with no operational warning at all.
        p = plan_transport_update("example.com", use_mx=False)
        assert len(p.blast_radius) > 1
        joined = " ".join(p.blast_radius).lower()
        assert "rerouted" in joined or "reroute" in joined or "delivered" in joined


class TestPlanMynetworksUpdate:
    def test_risk_is_low(self):
        p = plan_mynetworks_update("10.0.0.0/8", "internal net")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_mynetworks_update("10.0.0.0/8", "internal net")
        assert p.action == "pmg_mynetworks_update"

    def test_rejects_invalid_cidr(self):
        with pytest.raises(ProximoError):
            plan_mynetworks_update("not-a-cidr", "x")


class TestPlanTlspolicyCreate:
    def test_risk_is_medium(self):
        p = plan_tlspolicy_create("example.com", "secure")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_tlspolicy_create("example.com", "secure")
        assert p.action == "pmg_tlspolicy_create"

    def test_downgrade_and_enforce_blast_radius_actually_differ_by_value(self):
        # REPLACES the old `test_blast_radius_is_direction_aware`, which only asserted both
        # "downgrade" and "tighten" appear for a SINGLE call (policy="none") — true of every
        # call regardless of the value, since both words were always present as static
        # boilerplate. This is the real diff: two opposite-direction calls must produce blast
        # text that actually differs, each naming the correct direction for its own value.
        p_down = plan_tlspolicy_create("example.com", "none")
        p_up = plan_tlspolicy_create("example.com", "secure")
        assert p_down.blast_radius != p_up.blast_radius

        down_joined = " ".join(p_down.blast_radius).lower()
        up_joined = " ".join(p_up.blast_radius).lower()

        assert "downgrade" in down_joined
        assert "enforces" not in down_joined

        assert "enforces" in up_joined
        assert "downgrade" not in up_joined

    def test_unrecognized_policy_value_gets_honest_fallback_not_a_guessed_direction(self):
        p = plan_tlspolicy_create("example.com", "bogus-tier")
        joined = " ".join(p.blast_radius).lower()
        assert "not a recognized" in joined or "unrecognized" in joined
        assert "downgrade" not in joined
        assert "enforces" not in joined

    def test_rejects_invalid_destination(self):
        with pytest.raises(ProximoError):
            plan_tlspolicy_create("bad/destination", "secure")


class TestPlanTlspolicyUpdate:
    def test_risk_is_medium(self):
        p = plan_tlspolicy_update("example.com", "none")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_tlspolicy_update("example.com", "none")
        assert p.action == "pmg_tlspolicy_update"

    def test_downgrade_and_enforce_blast_radius_actually_differ_by_value(self):
        p_down = plan_tlspolicy_update("example.com", "none")
        p_up = plan_tlspolicy_update("example.com", "secure")
        assert p_down.blast_radius != p_up.blast_radius

        down_joined = " ".join(p_down.blast_radius).lower()
        up_joined = " ".join(p_up.blast_radius).lower()

        assert "downgrade" in down_joined
        assert "enforces" not in down_joined

        assert "enforces" in up_joined
        assert "downgrade" not in up_joined

    def test_unrecognized_policy_value_gets_honest_fallback_not_a_guessed_direction(self):
        p = plan_tlspolicy_update("example.com", "bogus-tier")
        joined = " ".join(p.blast_radius).lower()
        assert "not a recognized" in joined or "unrecognized" in joined
        assert "downgrade" not in joined
        assert "enforces" not in joined

    def test_does_not_claim_a_before_after_delta_it_cannot_see(self):
        # update is PURE (current={} always, no capture of the destination's PRIOR policy) — it
        # must never claim a "downgrade FROM x" / "upgrade FROM x" delta it has no way to know.
        # It may only state the RESULTING enforcement level this call sets, plus an explicit
        # note that the prior level is not captured.
        p = plan_tlspolicy_update("example.com", "none")
        joined = " ".join(p.blast_radius).lower()
        assert "from " not in joined
        assert "prior" in joined or "not captured" in joined or "does not know" in joined

    def test_rejects_invalid_destination(self):
        with pytest.raises(ProximoError):
            plan_tlspolicy_update("bad/destination", "none")


class TestPlanTlspolicyDelete:
    def test_risk_is_medium(self):
        p = plan_tlspolicy_delete("example.com")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_tlspolicy_delete("example.com")
        assert p.action == "pmg_tlspolicy_delete"

    def test_rejects_invalid_destination(self):
        with pytest.raises(ProximoError):
            plan_tlspolicy_delete("bad/destination")


class TestPlanTlsInboundDomainsCreate:
    def test_risk_is_low(self):
        p = plan_tls_inbound_domains_create("example.com")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_tls_inbound_domains_create("example.com")
        assert p.action == "pmg_tls_inbound_domains_create"

    def test_rejects_invalid_domain(self):
        with pytest.raises(ProximoError):
            plan_tls_inbound_domains_create("bad/domain")


class TestPlanTlsInboundDomainsDelete:
    def test_risk_is_low(self):
        p = plan_tls_inbound_domains_delete("example.com")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_tls_inbound_domains_delete("example.com")
        assert p.action == "pmg_tls_inbound_domains_delete"

    def test_blast_radius_notes_security_loosening_direction(self):
        p = plan_tls_inbound_domains_delete("example.com")
        joined = " ".join(p.blast_radius).lower()
        assert "loosen" in joined

    def test_rejects_invalid_domain(self):
        with pytest.raises(ProximoError):
            plan_tls_inbound_domains_delete("bad/domain")


class TestPlanSpamConfigUpdate:
    def test_risk_is_medium(self):
        p = plan_spam_config_update(bounce_score=5)
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_spam_config_update(use_bayes=True)
        assert p.action == "pmg_spam_config_update"

    def test_change_mentions_field(self):
        p = plan_spam_config_update(bounce_score=5)
        assert "bounce_score" in p.change

    def test_blast_radius_mentions_mail_impact(self):
        p = plan_spam_config_update(bounce_score=5)
        text = " ".join(p.blast_radius).lower()
        assert "mail" in text or "spam" in text or "filter" in text

    def test_raises_when_all_none(self):
        with pytest.raises(ProximoError):
            plan_spam_config_update()


class TestPlanQuarantineWelcomelistAdd:
    def test_risk_is_low(self):
        p = plan_quarantine_welcomelist_add("good@example.com")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_quarantine_welcomelist_add("good@example.com")
        assert p.action == "pmg_quarantine_welcomelist_add"

    def test_change_mentions_address(self):
        p = plan_quarantine_welcomelist_add("good@example.com")
        assert "good@example.com" in p.change

    def test_blast_radius_non_empty(self):
        p = plan_quarantine_welcomelist_add("good@example.com")
        assert len(p.blast_radius) > 0


class TestPlanQuarantineWelcomelistRemove:
    def test_risk_is_low(self):
        p = plan_quarantine_welcomelist_remove("good@example.com")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_quarantine_welcomelist_remove("good@example.com")
        assert p.action == "pmg_quarantine_welcomelist_remove"


class TestPlanServiceControl:
    def test_risk_is_medium(self):
        # non-critical service — baseline MEDIUM tier. (Was "postfix" — updated by the
        # Wave-9b-review MAJOR fix: stop of a mail-critical service is now RISK_HIGH here too,
        # see TestPlanServiceControlMailCriticalStop below.)
        p = plan_service_control("clamav", "stop")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_service_control("postfix", "start")
        assert p.action == "pmg_service_control"

    def test_change_mentions_service_and_action(self):
        p = plan_service_control("postfix", "restart")
        assert "postfix" in p.change
        assert "restart" in p.change

    def test_blast_radius_warns_mail_delivery_interruption(self):
        p = plan_service_control("postfix", "stop")
        text = " ".join(p.blast_radius).lower()
        assert "interrupts mail delivery" in text

    def test_blast_radius_warns_manually_restarted(self):
        p = plan_service_control("postfix", "stop")
        text = " ".join(p.blast_radius).lower()
        assert "manually restarted" in text

    def test_invalid_action_raises_proximo_error(self):
        with pytest.raises(ProximoError):
            plan_service_control("postfix", "explode")

    def test_invalid_service_raises_proximo_error(self):
        with pytest.raises(ProximoError):
            plan_service_control("../../etc/passwd", "stop")


class TestPlanServiceControlMailCriticalStop:
    """Wave-9b-review MAJOR fix: `plan_service_control` and `pmg_node.py`'s `plan_service_stop`
    both build a POST to the identical wire endpoint (/nodes/{node}/services/{service}/stop) for
    the same (service, action="stop") inputs — they must agree on risk tier. Mirrors
    `test_pmg_node.py::TestPlanServiceStop`'s own mail-critical/non-critical cases exactly."""

    @pytest.mark.parametrize("service", ["postfix", "pmg-smtp-filter"])
    def test_stop_mail_critical_service_is_high(self, service):
        p = plan_service_control(service, "stop")
        assert p.risk == RISK_HIGH

    def test_stop_non_critical_service_stays_medium(self):
        p = plan_service_control("clamav", "stop")
        assert p.risk == RISK_MEDIUM

    def test_start_mail_critical_service_stays_medium(self):
        # only action="stop" is escalated — start/restart/reload of postfix are unaffected
        p = plan_service_control("postfix", "start")
        assert p.risk == RISK_MEDIUM

    def test_restart_mail_critical_service_stays_medium(self):
        p = plan_service_control("postfix", "restart")
        assert p.risk == RISK_MEDIUM

    def test_stop_mail_critical_blast_radius_mentions_mail_flow_critical(self):
        p = plan_service_control("postfix", "stop")
        text = " ".join(p.blast_radius).lower()
        assert "mail-flow-critical" in text


# ---------------------------------------------------------------------------
# W4 Validator tests
# ---------------------------------------------------------------------------

class TestCheckRrddataTimeframe:
    def test_valid_values_pass(self):
        for v in ("hour", "day", "week", "month", "year"):
            assert _check_rrddata_timeframe(v) == v

    def test_invalid_value_raises(self):
        with pytest.raises(ProximoError):
            _check_rrddata_timeframe("minute")

    def test_empty_raises(self):
        with pytest.raises(ProximoError):
            _check_rrddata_timeframe("")


class TestCheckRrddataCf:
    def test_valid_values_pass(self):
        assert _check_rrddata_cf("AVERAGE") == "AVERAGE"
        assert _check_rrddata_cf("MAX") == "MAX"

    def test_invalid_value_raises(self):
        with pytest.raises(ProximoError):
            _check_rrddata_cf("MIN")

    def test_lowercase_raises(self):
        with pytest.raises(ProximoError):
            _check_rrddata_cf("average")


class TestCheckBackupNotify:
    def test_valid_values_pass(self):
        for v in ("always", "error", "never"):
            assert _check_backup_notify(v) == v

    def test_invalid_value_raises(self):
        with pytest.raises(ProximoError):
            _check_backup_notify("sometimes")


class TestCheckQuarantineType:
    def test_valid_values_pass(self):
        for v in ("spam", "virus", "attachment"):
            assert _check_quarantine_type(v) == v

    def test_invalid_value_raises(self):
        with pytest.raises(ProximoError):
            _check_quarantine_type("phishing")


# ---------------------------------------------------------------------------
# W4 READ op tests
# ---------------------------------------------------------------------------

class TestTrackerList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params or {}) or []
        )
        tracker_list(api, "pmg")
        assert api.seen["path"] == "/nodes/pmg/tracker"

    def test_always_sends_limit(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        tracker_list(api, "pmg")
        assert api.seen["params"].get("limit") == 2000

    def test_maps_start_to_starttime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        tracker_list(api, "pmg", start=1717000000)
        assert api.seen["params"].get("starttime") == 1717000000
        assert "start" not in api.seen["params"]

    def test_maps_from__to_from_key(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        tracker_list(api, "pmg", from_="sender@example.com")
        assert api.seen["params"].get("from") == "sender@example.com"
        assert "from_" not in api.seen["params"]

    def test_rejects_invalid_node(self):
        api = _api()
        with pytest.raises(ProximoError):
            tracker_list(api, "../../etc")

    def test_rejects_non_int_start(self):
        api = _api()
        with pytest.raises(ProximoError):
            tracker_list(api, "pmg", start="bad")


class TestTrackerDetail:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        tracker_detail(api, "pmg", "msg-abc123")
        assert api.seen["path"] == "/nodes/pmg/tracker/msg-abc123"

    def test_id_traversal_rejected(self):
        # id_ is a URL path segment — slash/traversal/injection metachars must be rejected
        api = _api()
        for bad in ("some/id", "../../etc", "id?x=1", "a#b", "id\nlog"):
            with pytest.raises(ProximoError, match="invalid tracker id"):
                tracker_detail(api, "pmg", bad)

    def test_clean_id_with_colon_passes(self):
        # mail-ish chars (e.g. ':') are still allowed — only structural metachars are blocked
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        tracker_detail(api, "pmg", "queue:ABC123")
        assert api.seen["path"] == "/nodes/pmg/tracker/queue:ABC123"

    def test_maps_start_to_starttime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        tracker_detail(api, "pmg", "mid", start=1717000000)
        assert api.seen["params"].get("starttime") == 1717000000

    def test_no_params_when_no_start_end(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params) or []
        )
        tracker_detail(api, "pmg", "mid")
        assert api.seen.get("params") is None


class TestQuarantineVirus:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        quarantine_virus(api)
        assert api.seen["path"] == "/quarantine/virus"

    def test_defaults_pmail_to_config_username(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_virus(api)
        assert api.seen["params"].get("pmail") == "root@pam"

    def test_explicit_pmail_overrides_default(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_virus(api, pmail="user@domain.com")
        assert api.seen["params"].get("pmail") == "user@domain.com"

    def test_maps_start_to_starttime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_virus(api, start=1717000000)
        assert api.seen["params"].get("starttime") == 1717000000


class TestQuarantineAttachment:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        quarantine_attachment(api)
        assert api.seen["path"] == "/quarantine/attachment"

    def test_defaults_pmail_to_config_username(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_attachment(api)
        assert api.seen["params"].get("pmail") == "root@pam"

    def test_maps_end_to_endtime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_attachment(api, end=1717099999)
        assert api.seen["params"].get("endtime") == 1717099999


class TestQuarantineVirusstatus:
    def test_uses_correct_path(self):
        api = _api()
        quarantine_virusstatus(api)
        assert api.seen["path"] == "/quarantine/virusstatus"
        assert api.seen["method"] == "GET"


class TestQuarantineSpamstatus:
    def test_uses_correct_path(self):
        api = _api()
        quarantine_spamstatus(api)
        assert api.seen["path"] == "/quarantine/spamstatus"
        assert api.seen["method"] == "GET"


class TestQuarantineSpamusers:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params or {}) or []
        )
        quarantine_spamusers(api)
        assert api.seen["path"] == "/quarantine/spamusers"

    def test_maps_quarantine_type_to_hyphen_key(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_spamusers(api, quarantine_type="virus")
        assert api.seen["params"].get("quarantine-type") == "virus"
        assert "quarantine_type" not in api.seen["params"]

    def test_default_quarantine_type_is_spam(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_spamusers(api)
        assert api.seen["params"].get("quarantine-type") == "spam"

    def test_invalid_quarantine_type_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            quarantine_spamusers(api, quarantine_type="phishing")

    def test_maps_start_to_starttime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_spamusers(api, start=1717000000)
        assert api.seen["params"].get("starttime") == 1717000000


class TestStatisticsMailcount:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params or {}) or []
        )
        statistics_mailcount(api)
        assert api.seen["path"] == "/statistics/mailcount"

    def test_always_sends_timespan(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_mailcount(api)
        assert api.seen["params"].get("timespan") == 3600

    def test_maps_start_to_starttime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_mailcount(api, start=1717000000)
        assert api.seen["params"].get("starttime") == 1717000000

    def test_rejects_non_int_timespan(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_mailcount(api, timespan="bad")

    def test_rejects_timespan_below_min(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_mailcount(api, timespan=100)

    def test_rejects_timespan_above_max(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_mailcount(api, timespan=99999999)


class TestStatisticsSender:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or []
        )
        statistics_sender(api)
        assert api.seen["path"] == "/statistics/sender"

    def test_no_params_when_none_given(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params) or []
        )
        statistics_sender(api)
        assert api.seen.get("params") is None

    def test_orderby_not_sent_to_api(self):
        # PMG 9.1 live-verified: /statistics/sender rejects 'orderby' with HTTP 400.
        # Proximo accepts the param for API compatibility but silently drops it.
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_sender(api, orderby="count:desc")
        assert "orderby" not in api.seen.get("params", {}), \
            "orderby must NOT be sent to PMG /statistics/sender (causes 400)"

    def test_maps_filter__to_filter_key(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_sender(api, filter_="example.com")
        assert api.seen["params"].get("filter") == "example.com"
        assert "filter_" not in api.seen["params"]

    def test_maps_start_to_starttime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_sender(api, start=1717000000)
        assert api.seen["params"].get("starttime") == 1717000000


class TestStatisticsReceiver:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or []
        )
        statistics_receiver(api)
        assert api.seen["path"] == "/statistics/receiver"

    def test_no_params_when_none_given(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params) or []
        )
        statistics_receiver(api)
        assert api.seen.get("params") is None

    def test_orderby_passed_raw(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_receiver(api, orderby="bytes:asc")
        assert api.seen["params"].get("orderby") == "bytes:asc"

    def test_maps_filter__to_filter_key(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_receiver(api, filter_="user@example.com")
        assert api.seen["params"].get("filter") == "user@example.com"

    def test_rejects_non_int_start(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_receiver(api, start="bad")


class TestNodeSyslog:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or []
        )
        node_syslog(api, "pmg")
        assert api.seen["path"] == "/nodes/pmg/syslog"

    def test_no_params_when_none_given(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params) or []
        )
        node_syslog(api, "pmg")
        assert api.seen.get("params") is None

    def test_passes_optional_params(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        node_syslog(api, "pmg", limit=100, service="postfix")
        p = api.seen["params"]
        assert p.get("limit") == 100
        assert p.get("service") == "postfix"

    def test_rejects_invalid_node(self):
        api = _api()
        with pytest.raises(ProximoError):
            node_syslog(api, "../../etc")


class TestNodeRrddata:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params or {}) or []
        )
        node_rrddata(api, "pmg", "day")
        assert api.seen["path"] == "/nodes/pmg/rrddata"

    def test_sends_timeframe_param(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        node_rrddata(api, "pmg", "week")
        assert api.seen["params"].get("timeframe") == "week"

    def test_optional_cf_sent_when_given(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        node_rrddata(api, "pmg", "day", cf="MAX")
        assert api.seen["params"].get("cf") == "MAX"

    def test_cf_absent_when_not_given(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        node_rrddata(api, "pmg", "day")
        assert "cf" not in api.seen["params"]

    def test_invalid_timeframe_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            node_rrddata(api, "pmg", "minute")

    def test_invalid_cf_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            node_rrddata(api, "pmg", "day", cf="MIN")


class TestTasksList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or []
        )
        tasks_list(api, "pmg")
        assert api.seen["path"] == "/nodes/pmg/tasks"

    def test_no_params_when_none_given(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params) or []
        )
        tasks_list(api, "pmg")
        assert api.seen.get("params") is None

    def test_errors_bool_to_int(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        tasks_list(api, "pmg", errors=True)
        assert api.seen["params"].get("errors") == 1

    def test_rejects_invalid_node(self):
        api = _api()
        with pytest.raises(ProximoError):
            tasks_list(api, "../../etc")


# ---------------------------------------------------------------------------
# W4 MUTATION op tests
# ---------------------------------------------------------------------------

class TestBackupCreate:
    def test_posts_to_correct_path(self):
        api = _api()
        backup_create(api, "pmg")
        assert api.seen["path"] == "/nodes/pmg/backup"
        assert api.seen["method"] == "POST"

    def test_sends_notify_and_statistic(self):
        api = _api()
        backup_create(api, "pmg", notify="error", statistic=False)
        data = api.seen.get("data", {})
        assert data.get("notify") == "error"
        assert data.get("statistic") is False

    def test_invalid_notify_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            backup_create(api, "pmg", notify="sometimes")

    def test_invalid_node_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            backup_create(api, "../../etc")


# ---------------------------------------------------------------------------
# W4 PLAN function tests
# ---------------------------------------------------------------------------

class TestPlanBackupCreate:
    def test_risk_is_low(self):
        p = plan_backup_create("pmg")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_backup_create("pmg")
        assert p.action == "pmg_backup_create"

    def test_change_mentions_node(self):
        p = plan_backup_create("pmg")
        assert "pmg" in p.change

    def test_blast_radius_mentions_backup_path(self):
        p = plan_backup_create("pmg")
        text = " ".join(p.blast_radius)
        assert "/var/lib/pmg/backup/" in text

    def test_blast_radius_mentions_additive(self):
        p = plan_backup_create("pmg")
        text = " ".join(p.blast_radius).lower()
        assert "additive" in text

    def test_blast_radius_mentions_notify(self):
        p = plan_backup_create("pmg", notify="always")
        text = " ".join(p.blast_radius)
        assert "always" in text

    def test_invalid_notify_raises(self):
        with pytest.raises(ProximoError):
            plan_backup_create("pmg", notify="bad")

    def test_invalid_node_raises(self):
        with pytest.raises(ProximoError):
            plan_backup_create("../../etc")


# ---------------------------------------------------------------------------
# W5a Validator tests
# ---------------------------------------------------------------------------

class TestCheckRuledbId:
    def test_valid_integer_string(self):
        assert _check_ruledb_id("100") == "100"

    def test_valid_single_digit(self):
        assert _check_ruledb_id("0") == "0"

    def test_valid_large_id(self):
        assert _check_ruledb_id("99999") == "99999"

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_ruledb_id("100/200")

    def test_rejects_alpha(self):
        with pytest.raises(ProximoError):
            _check_ruledb_id("abc")

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_ruledb_id("")

    def test_rejects_dotdot_traversal(self):
        with pytest.raises(ProximoError):
            _check_ruledb_id("../etc")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_ruledb_id("100\n")

    def test_rejects_space(self):
        with pytest.raises(ProximoError):
            _check_ruledb_id("100 200")


class TestCheckOgroup:
    def test_valid_simple(self):
        assert _check_ogroup("group1") == "group1"

    def test_valid_with_hyphen(self):
        assert _check_ogroup("my-group") == "my-group"

    def test_valid_with_underscore(self):
        assert _check_ogroup("my_group") == "my_group"

    def test_valid_single_char(self):
        assert _check_ogroup("a") == "a"

    def test_valid_mixed(self):
        assert _check_ogroup("Grp1-A_B") == "Grp1-A_B"

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_ogroup("group/bad")

    def test_rejects_dotdot_traversal(self):
        with pytest.raises(ProximoError):
            _check_ogroup("../etc")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_ogroup("group\n")

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_ogroup("")

    def test_rejects_leading_hyphen(self):
        with pytest.raises(ProximoError):
            _check_ogroup("-group")

    def test_rejects_space(self):
        with pytest.raises(ProximoError):
            _check_ogroup("my group")


# ---------------------------------------------------------------------------
# W5a READ op tests
# ---------------------------------------------------------------------------

class TestRuledbRulesList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, method="GET") or []
        )
        ruledb_rules_list(api)
        assert api.seen["path"] == "/config/ruledb/rules"
        assert api.seen["method"] == "GET"

    def test_returns_list(self):
        api = _api()
        api._get = lambda path, params=None: []
        result = ruledb_rules_list(api)
        assert isinstance(result, list)


class TestRuledbRuleGet:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_get(api, "100")
        assert api.seen["path"] == "/config/ruledb/rules/100/config"
        assert api.seen["method"] == "GET"

    def test_id_interpolated_into_path(self):
        api = _api()
        ruledb_rule_get(api, "200")
        assert "200" in api.seen["path"]

    def test_rejects_invalid_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_get(api, "bad/id")

    def test_rejects_newline_in_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_get(api, "100\n")


class TestRuledbRuleFromList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        ruledb_rule_from_list(api, "100")
        assert api.seen["path"] == "/config/ruledb/rules/100/from"

    def test_id_interpolated(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        ruledb_rule_from_list(api, "42")
        assert "42" in api.seen["path"]

    def test_rejects_invalid_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_from_list(api, "../etc")


class TestRuledbRuleToList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        ruledb_rule_to_list(api, "100")
        assert api.seen["path"] == "/config/ruledb/rules/100/to"

    def test_rejects_invalid_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_to_list(api, "bad")


class TestRuledbRuleWhatList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        ruledb_rule_what_list(api, "100")
        assert api.seen["path"] == "/config/ruledb/rules/100/what"

    def test_rejects_invalid_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_what_list(api, "bad")


class TestRuledbRuleWhenList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        ruledb_rule_when_list(api, "100")
        assert api.seen["path"] == "/config/ruledb/rules/100/when"

    def test_rejects_invalid_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_when_list(api, "bad")


class TestRuledbRuleActionsList:
    def test_uses_correct_path(self):
        # PMG 9.1 live-verified: /rules/{id}/actions returns 501.
        # Actions are embedded in the rule config under the 'action' key.
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or {}
        )
        ruledb_rule_actions_list(api, "100")
        assert api.seen["path"] == "/config/ruledb/rules/100/config"

    def test_extracts_action_list(self):
        # Confirm we return the embedded 'action' list, not the whole config dict.
        api = _api()
        action_data = [{"id": 18, "name": "Block"}]
        api._get = lambda path, params=None: {"action": action_data, "name": "myrule"}
        result = ruledb_rule_actions_list(api, "100")
        assert result == action_data

    def test_id_interpolated(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or {}
        )
        ruledb_rule_actions_list(api, "500")
        assert "500" in api.seen["path"]

    def test_rejects_invalid_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_actions_list(api, "bad/id")


class TestWhoGroupsList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, method="GET") or []
        )
        who_groups_list(api)
        assert api.seen["path"] == "/config/ruledb/who"
        assert api.seen["method"] == "GET"


class TestWhoGroupGet:
    def test_uses_correct_path(self):
        # PMG 9.1 live-verified: ogroup must be numeric ID (e.g. '2'), not a name.
        api = _api()
        who_group_get(api, "2")
        assert api.seen["path"] == "/config/ruledb/who/2/config"
        assert api.seen["method"] == "GET"

    def test_ogroup_interpolated(self):
        api = _api()
        who_group_get(api, "3")
        assert "3" in api.seen["path"]

    def test_rejects_non_numeric_ogroup(self):
        # Names like 'mygroup' are rejected — PMG 9.1 requires numeric IDs.
        api = _api()
        with pytest.raises(ProximoError):
            who_group_get(api, "mygroup")

    def test_rejects_slash_in_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_group_get(api, "2/3")

    def test_rejects_newline_in_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_group_get(api, "2\n")


class TestWhoGroupObjects:
    def test_uses_correct_path(self):
        # PMG 9.1 live-verified: ogroup must be numeric ID (e.g. '2'), not a name.
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        who_group_objects(api, "2")
        assert api.seen["path"] == "/config/ruledb/who/2/objects"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_group_objects(api, "mygroup")

    def test_rejects_traversal(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_group_objects(api, "../etc")


class TestWhatGroupsList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, method="GET") or []
        )
        what_groups_list(api)
        assert api.seen["path"] == "/config/ruledb/what"
        assert api.seen["method"] == "GET"


class TestWhatGroupGet:
    def test_uses_correct_path(self):
        # PMG 9.1 live-verified: ogroup must be numeric ID (e.g. '8'), not a name.
        api = _api()
        what_group_get(api, "8")
        assert api.seen["path"] == "/config/ruledb/what/8/config"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_group_get(api, "mygroup")

    def test_rejects_slash(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_group_get(api, "8/9")


class TestWhatGroupObjects:
    def test_uses_correct_path(self):
        # PMG 9.1 live-verified: ogroup must be numeric ID (e.g. '8'), not a name.
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        what_group_objects(api, "8")
        assert api.seen["path"] == "/config/ruledb/what/8/objects"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_group_objects(api, "mygroup")

    def test_rejects_traversal(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_group_objects(api, "../etc")


class TestWhenGroupsList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, method="GET") or []
        )
        when_groups_list(api)
        assert api.seen["path"] == "/config/ruledb/when"
        assert api.seen["method"] == "GET"


class TestWhenGroupGet:
    def test_uses_correct_path(self):
        # PMG 9.1 live-verified: ogroup must be numeric ID (e.g. '4'), not a name.
        api = _api()
        when_group_get(api, "4")
        assert api.seen["path"] == "/config/ruledb/when/4/config"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            when_group_get(api, "mygroup")

    def test_rejects_slash(self):
        api = _api()
        with pytest.raises(ProximoError):
            when_group_get(api, "4/5")


class TestWhenGroupObjects:
    def test_uses_correct_path(self):
        # PMG 9.1 live-verified: ogroup must be numeric ID (e.g. '4'), not a name.
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        when_group_objects(api, "4")
        assert api.seen["path"] == "/config/ruledb/when/4/objects"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            when_group_objects(api, "mygroup")

    def test_rejects_traversal(self):
        api = _api()
        with pytest.raises(ProximoError):
            when_group_objects(api, "../etc")


class TestActionObjectsList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, method="GET") or []
        )
        action_objects_list(api)
        assert api.seen["path"] == "/config/ruledb/action/objects"
        assert api.seen["method"] == "GET"

    def test_returns_list(self):
        api = _api()
        api._get = lambda path, params=None: []
        result = action_objects_list(api)
        assert isinstance(result, list)


class TestRuledbDigest:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_digest(api)
        assert api.seen["path"] == "/config/ruledb/digest"
        assert api.seen["method"] == "GET"

    def test_no_params(self):
        api = _api()
        ruledb_digest(api)
        assert api.seen.get("params", {}) == {}


# ---------------------------------------------------------------------------
# W5b Validator
# ---------------------------------------------------------------------------

class TestCheckWhoObjectType:
    def test_accepts_all_valid_types(self):
        for t in ("email", "domain", "regex", "ip", "network", "ldap"):
            assert _check_who_object_type(t) == t

    def test_accepts_ldapuser(self):
        # Wave 8a: ldapuser is the 7th who-object type, additive to the pre-existing 6 (this test
        # is NEW, appended alongside — test_accepts_all_valid_types above is byte-for-byte
        # unchanged, proving the additive-compat claim rather than just asserting it).
        assert _check_who_object_type("ldapuser") == "ldapuser"

    def test_rejects_invalid_type(self):
        with pytest.raises(ProximoError):
            _check_who_object_type("spf")

    def test_rejects_empty_string(self):
        with pytest.raises(ProximoError):
            _check_who_object_type("")

    def test_rejects_name_with_slashes(self):
        with pytest.raises(ProximoError):
            _check_who_object_type("email/injection")


# ---------------------------------------------------------------------------
# W5b: WHO group CRUD ops
# ---------------------------------------------------------------------------

class TestWhoGroupCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        who_group_create(api, "Blocklist")
        assert api.seen["path"] == "/config/ruledb/who"
        assert api.seen["method"] == "POST"

    def test_sends_name_in_body(self):
        api = _api()
        who_group_create(api, "Blocklist")
        assert api.seen["data"].get("name") == "Blocklist"

    def test_sends_optional_info(self):
        api = _api()
        who_group_create(api, "Blocklist", info="My blocklist")
        assert api.seen["data"].get("info") == "My blocklist"

    def test_sends_and_flag(self):
        api = _api()
        who_group_create(api, "Blocklist", and_=True)
        assert api.seen["data"].get("and") is True

    def test_sends_invert_flag(self):
        api = _api()
        who_group_create(api, "Blocklist", invert=True)
        assert api.seen["data"].get("invert") is True

    def test_omits_none_optionals(self):
        api = _api()
        who_group_create(api, "Blocklist")
        assert "info" not in api.seen["data"]
        assert "and" not in api.seen["data"]
        assert "invert" not in api.seen["data"]


class TestWhoGroupUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        who_group_update(api, "2", name="Renamed")
        assert api.seen["path"] == "/config/ruledb/who/2/config"
        assert api.seen["method"] == "PUT"

    def test_sends_name_in_body(self):
        api = _api()
        who_group_update(api, "2", name="Renamed")
        assert api.seen["data"].get("name") == "Renamed"

    def test_sends_and_flag(self):
        api = _api()
        who_group_update(api, "2", and_=False)
        assert api.seen["data"].get("and") is False

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_group_update(api, "mygroup", name="x")

    def test_omits_none_optionals(self):
        api = _api()
        who_group_update(api, "2")
        assert api.seen["data"] == {}


class TestWhoGroupDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        who_group_delete(api, "2")
        assert api.seen["path"] == "/config/ruledb/who/2"
        assert api.seen["method"] == "DELETE"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_group_delete(api, "mygroup")


# ---------------------------------------------------------------------------
# W5b: WHAT group CRUD ops
# ---------------------------------------------------------------------------

class TestWhatGroupCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        what_group_create(api, "DangerousContent")
        assert api.seen["path"] == "/config/ruledb/what"
        assert api.seen["method"] == "POST"

    def test_sends_name_in_body(self):
        api = _api()
        what_group_create(api, "DangerousContent")
        assert api.seen["data"].get("name") == "DangerousContent"

    def test_omits_none_optionals(self):
        api = _api()
        what_group_create(api, "DangerousContent")
        assert "info" not in api.seen["data"]
        assert "and" not in api.seen["data"]
        assert "invert" not in api.seen["data"]


class TestWhatGroupUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        what_group_update(api, "8", name="Renamed")
        assert api.seen["path"] == "/config/ruledb/what/8/config"
        assert api.seen["method"] == "PUT"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_group_update(api, "mygroup", name="x")

    def test_omits_none_optionals(self):
        api = _api()
        what_group_update(api, "8")
        assert api.seen["data"] == {}


class TestWhatGroupDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        what_group_delete(api, "8")
        assert api.seen["path"] == "/config/ruledb/what/8"
        assert api.seen["method"] == "DELETE"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_group_delete(api, "mygroup")


# ---------------------------------------------------------------------------
# W5b: WHEN group CRUD ops
# ---------------------------------------------------------------------------

class TestWhenGroupCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        when_group_create(api, "OfficeHours")
        assert api.seen["path"] == "/config/ruledb/when"
        assert api.seen["method"] == "POST"

    def test_sends_name_in_body(self):
        api = _api()
        when_group_create(api, "OfficeHours")
        assert api.seen["data"].get("name") == "OfficeHours"

    def test_omits_none_optionals(self):
        api = _api()
        when_group_create(api, "OfficeHours")
        assert "info" not in api.seen["data"]
        assert "and" not in api.seen["data"]
        assert "invert" not in api.seen["data"]


class TestWhenGroupUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        when_group_update(api, "4", name="Renamed")
        assert api.seen["path"] == "/config/ruledb/when/4/config"
        assert api.seen["method"] == "PUT"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            when_group_update(api, "mygroup", name="x")

    def test_omits_none_optionals(self):
        api = _api()
        when_group_update(api, "4")
        assert api.seen["data"] == {}


class TestWhenGroupDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        when_group_delete(api, "4")
        assert api.seen["path"] == "/config/ruledb/when/4"
        assert api.seen["method"] == "DELETE"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            when_group_delete(api, "mygroup")


# ---------------------------------------------------------------------------
# W5b: WHO object CRUD ops
# ---------------------------------------------------------------------------

class TestWhoObjectAdd:
    def test_email_uses_correct_path(self):
        api = _api()
        who_object_add(api, "2", "email", email="bad@evil.com")
        assert api.seen["path"] == "/config/ruledb/who/2/email"
        assert api.seen["method"] == "POST"

    def test_email_sends_email_field(self):
        api = _api()
        who_object_add(api, "2", "email", email="bad@evil.com")
        assert api.seen["data"].get("email") == "bad@evil.com"

    def test_domain_uses_correct_path(self):
        api = _api()
        who_object_add(api, "2", "domain", domain="evil.com")
        assert api.seen["path"] == "/config/ruledb/who/2/domain"

    def test_domain_sends_domain_field(self):
        api = _api()
        who_object_add(api, "2", "domain", domain="evil.com")
        assert api.seen["data"].get("domain") == "evil.com"

    def test_regex_uses_correct_path(self):
        api = _api()
        who_object_add(api, "2", "regex", regex=r".*@spam\.com")
        assert api.seen["path"] == "/config/ruledb/who/2/regex"

    def test_regex_sends_regex_field(self):
        api = _api()
        who_object_add(api, "2", "regex", regex=r".*@spam\.com")
        assert api.seen["data"].get("regex") == r".*@spam\.com"

    def test_ip_uses_correct_path(self):
        api = _api()
        who_object_add(api, "2", "ip", ip="1.2.3.4")
        assert api.seen["path"] == "/config/ruledb/who/2/ip"

    def test_ip_sends_ip_field(self):
        api = _api()
        who_object_add(api, "2", "ip", ip="1.2.3.4")
        assert api.seen["data"].get("ip") == "1.2.3.4"

    def test_network_uses_correct_path(self):
        api = _api()
        who_object_add(api, "2", "network", cidr="10.0.0.0/8")
        assert api.seen["path"] == "/config/ruledb/who/2/network"

    def test_network_sends_cidr_field(self):
        api = _api()
        who_object_add(api, "2", "network", cidr="10.0.0.0/8")
        assert api.seen["data"].get("cidr") == "10.0.0.0/8"

    def test_ldap_uses_correct_path(self):
        api = _api()
        who_object_add(api, "2", "ldap", mode="group", profile="corp", group="admins")
        assert api.seen["path"] == "/config/ruledb/who/2/ldap"

    def test_ldap_sends_ldap_fields(self):
        api = _api()
        who_object_add(api, "2", "ldap", mode="group", profile="corp", group="admins")
        assert api.seen["data"].get("mode") == "group"
        assert api.seen["data"].get("profile") == "corp"
        assert api.seen["data"].get("group") == "admins"

    def test_ldapuser_uses_correct_path(self):
        # Wave 8a: ldapuser extension of _WHO_OBJECT_TYPES/_who_object_body — additive.
        api = _api()
        who_object_add(api, "2", "ldapuser", account="jdoe", profile="corp")
        assert api.seen["path"] == "/config/ruledb/who/2/ldapuser"
        assert api.seen["method"] == "POST"

    def test_ldapuser_sends_account_and_profile_fields(self):
        api = _api()
        who_object_add(api, "2", "ldapuser", account="jdoe", profile="corp")
        assert api.seen["data"].get("account") == "jdoe"
        assert api.seen["data"].get("profile") == "corp"

    def test_ldapuser_omits_account_when_none(self):
        api = _api()
        who_object_add(api, "2", "ldapuser", profile="corp")
        assert "account" not in api.seen["data"]

    def test_rejects_invalid_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_object_add(api, "2", "spf", email="x@y.com")

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_object_add(api, "mygroup", "email", email="x@y.com")


class TestWhoObjectUpdate:
    def test_email_uses_correct_path(self):
        api = _api()
        who_object_update(api, "2", "email", "5", email="new@evil.com")
        assert api.seen["path"] == "/config/ruledb/who/2/email/5"
        assert api.seen["method"] == "PUT"

    def test_email_sends_email_field(self):
        api = _api()
        who_object_update(api, "2", "email", "5", email="new@evil.com")
        assert api.seen["data"].get("email") == "new@evil.com"

    def test_network_uses_correct_path(self):
        api = _api()
        who_object_update(api, "2", "network", "7", cidr="192.168.0.0/16")
        assert api.seen["path"] == "/config/ruledb/who/2/network/7"

    def test_ldapuser_uses_correct_path(self):
        # Wave 8a: ldapuser extension — additive, existing types unaffected.
        api = _api()
        who_object_update(api, "2", "ldapuser", "9", account="jdoe2")
        assert api.seen["path"] == "/config/ruledb/who/2/ldapuser/9"
        assert api.seen["method"] == "PUT"

    def test_ldapuser_sends_account_field(self):
        api = _api()
        who_object_update(api, "2", "ldapuser", "9", account="jdoe2")
        assert api.seen["data"].get("account") == "jdoe2"

    def test_rejects_invalid_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_object_update(api, "2", "spf", "5", email="x@y.com")

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_object_update(api, "mygroup", "email", "5", email="x@y.com")

    def test_rejects_non_numeric_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_object_update(api, "2", "email", "obj-abc", email="x@y.com")

    def test_empty_body_when_no_fields(self):
        api = _api()
        who_object_update(api, "2", "email", "5")
        assert api.seen["data"] == {}


class TestWhoObjectDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        who_object_delete(api, "2", "5")
        assert api.seen["path"] == "/config/ruledb/who/2/objects/5"
        assert api.seen["method"] == "DELETE"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_object_delete(api, "mygroup", "5")

    def test_rejects_non_numeric_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_object_delete(api, "2", "abc")


# ---------------------------------------------------------------------------
# W5b: Plan functions
# ---------------------------------------------------------------------------

class TestPlanWhoGroupCreate:
    def test_risk_is_low(self):
        p = plan_who_group_create("Blocklist")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_who_group_create("Blocklist")
        assert p.action == "pmg_who_group_create"

    def test_change_mentions_name(self):
        p = plan_who_group_create("Blocklist")
        assert "Blocklist" in p.change

    def test_blast_radius_non_empty(self):
        p = plan_who_group_create("Blocklist")
        assert len(p.blast_radius) > 0

    def test_target_is_who_path(self):
        p = plan_who_group_create("Blocklist")
        assert "config/ruledb/who" in p.target


class TestPlanWhoGroupUpdate:
    def test_risk_is_medium(self):
        p = plan_who_group_update("2", name="Renamed")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_who_group_update("2")
        assert p.action == "pmg_who_group_update"

    def test_target_includes_ogroup(self):
        p = plan_who_group_update("2")
        assert "2" in p.target

    def test_blast_radius_non_empty(self):
        p = plan_who_group_update("2")
        assert len(p.blast_radius) > 0

    def test_rejects_non_numeric_ogroup(self):
        with pytest.raises(ProximoError):
            plan_who_group_update("mygroup")

    def test_blast_radius_discloses_new_name(self):
        p = plan_who_group_update("2", name="Renamed")
        assert any("Renamed" in entry for entry in p.blast_radius)

    def test_no_fields_noted_as_no_op(self):
        p = plan_who_group_update("2")
        assert any("no-op" in entry or "no fields" in entry for entry in p.blast_radius)


class TestPlanWhoGroupDelete:
    def test_risk_is_medium(self):
        p = plan_who_group_delete("2")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_who_group_delete("2")
        assert p.action == "pmg_who_group_delete"

    def test_target_includes_ogroup(self):
        p = plan_who_group_delete("2")
        assert "2" in p.target

    def test_blast_radius_non_empty(self):
        p = plan_who_group_delete("2")
        assert len(p.blast_radius) > 0

    def test_rejects_non_numeric_ogroup(self):
        with pytest.raises(ProximoError):
            plan_who_group_delete("mygroup")


class TestPlanWhatGroupCreate:
    def test_risk_is_low(self):
        p = plan_what_group_create("DangerousContent")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_what_group_create("DangerousContent")
        assert p.action == "pmg_what_group_create"

    def test_change_mentions_name(self):
        p = plan_what_group_create("DangerousContent")
        assert "DangerousContent" in p.change

    def test_blast_radius_non_empty(self):
        p = plan_what_group_create("DangerousContent")
        assert len(p.blast_radius) > 0


class TestPlanWhatGroupUpdate:
    def test_risk_is_medium(self):
        p = plan_what_group_update("8")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_what_group_update("8")
        assert p.action == "pmg_what_group_update"

    def test_rejects_non_numeric_ogroup(self):
        with pytest.raises(ProximoError):
            plan_what_group_update("mygroup")

    def test_blast_radius_discloses_new_name(self):
        p = plan_what_group_update("8", name="Renamed")
        assert any("Renamed" in entry for entry in p.blast_radius)


class TestPlanWhatGroupDelete:
    def test_risk_is_medium(self):
        p = plan_what_group_delete("8")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_what_group_delete("8")
        assert p.action == "pmg_what_group_delete"

    def test_rejects_non_numeric_ogroup(self):
        with pytest.raises(ProximoError):
            plan_what_group_delete("mygroup")


class TestPlanWhenGroupCreate:
    def test_risk_is_low(self):
        p = plan_when_group_create("OfficeHours")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_when_group_create("OfficeHours")
        assert p.action == "pmg_when_group_create"

    def test_change_mentions_name(self):
        p = plan_when_group_create("OfficeHours")
        assert "OfficeHours" in p.change

    def test_blast_radius_non_empty(self):
        p = plan_when_group_create("OfficeHours")
        assert len(p.blast_radius) > 0


class TestPlanWhenGroupUpdate:
    def test_risk_is_medium(self):
        p = plan_when_group_update("4")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_when_group_update("4")
        assert p.action == "pmg_when_group_update"

    def test_rejects_non_numeric_ogroup(self):
        with pytest.raises(ProximoError):
            plan_when_group_update("mygroup")

    def test_blast_radius_discloses_new_name(self):
        p = plan_when_group_update("4", name="Renamed")
        assert any("Renamed" in entry for entry in p.blast_radius)


class TestPlanWhenGroupDelete:
    def test_risk_is_medium(self):
        p = plan_when_group_delete("4")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_when_group_delete("4")
        assert p.action == "pmg_when_group_delete"

    def test_rejects_non_numeric_ogroup(self):
        with pytest.raises(ProximoError):
            plan_when_group_delete("mygroup")


class TestPlanWhoObjectAdd:
    def test_risk_is_low(self):
        p = plan_who_object_add("2", "email", email="x@y.com")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_who_object_add("2", "email")
        assert p.action == "pmg_who_object_add"

    def test_target_includes_type(self):
        p = plan_who_object_add("2", "email")
        assert "email" in p.target

    def test_target_includes_ogroup(self):
        p = plan_who_object_add("2", "email")
        assert "2" in p.target

    def test_blast_radius_non_empty(self):
        p = plan_who_object_add("2", "email")
        assert len(p.blast_radius) > 0

    def test_rejects_invalid_type(self):
        with pytest.raises(ProximoError):
            plan_who_object_add("2", "spf")

    def test_rejects_non_numeric_ogroup(self):
        with pytest.raises(ProximoError):
            plan_who_object_add("mygroup", "email")

    def test_accepts_ldapuser_account_kwarg(self):
        # Wave 8a: additive signature extension — accepted without error, same as every other
        # type-specific kwarg this PURE plan function already takes but doesn't render per-field.
        p = plan_who_object_add("2", "ldapuser", account="jdoe")
        assert p.risk == RISK_LOW

    def test_note_for_ldap_says_pmgsh_verified(self):
        # Regression: pre-existing 6 types (ldap included) are genuinely pmgsh-verified.
        p = plan_who_object_add("2", "ldap", mode="dc", profile="corp")
        assert "pmgsh-verified" in p.note
        assert "Smoke-confirm" not in p.note

    def test_note_for_ldapuser_says_smoke_confirm_not_pmgsh_verified(self):
        # Wave 8a: ldapuser is schema-verified only, never live-tested — note must reflect that.
        p = plan_who_object_add("2", "ldapuser", account="jdoe", profile="corp")
        assert "Smoke-confirm" in p.note
        assert "not yet live-tested" in p.note
        assert "pmgsh-verified" not in p.note


class TestPlanWhoObjectUpdate:
    def test_risk_is_medium(self):
        p = plan_who_object_update("2", "email", "5")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_who_object_update("2", "email", "5")
        assert p.action == "pmg_who_object_update"

    def test_target_includes_type_and_id(self):
        p = plan_who_object_update("2", "email", "5")
        assert "email" in p.target
        assert "5" in p.target

    def test_blast_radius_non_empty(self):
        p = plan_who_object_update("2", "email", "5")
        assert len(p.blast_radius) > 0

    def test_rejects_invalid_type(self):
        with pytest.raises(ProximoError):
            plan_who_object_update("2", "spf", "5")

    def test_rejects_non_numeric_ogroup(self):
        with pytest.raises(ProximoError):
            plan_who_object_update("mygroup", "email", "5")

    def test_rejects_non_numeric_id(self):
        with pytest.raises(ProximoError):
            plan_who_object_update("2", "email", "obj-abc")

    def test_blast_radius_discloses_new_value(self):
        p = plan_who_object_update("2", "email", "5", email="attacker@evil.example")
        assert any("attacker@evil.example" in entry for entry in p.blast_radius)

    def test_ldapuser_account_discloses_in_blast_radius(self):
        # Wave 8a: account is threaded into _who_object_body, so the update preview shows it
        # the same way email/domain/etc. already do.
        p = plan_who_object_update("2", "ldapuser", "9", account="jdoe2")
        assert any("jdoe2" in entry for entry in p.blast_radius)

    def test_note_for_ldap_says_pmgsh_verified(self):
        # Regression: pre-existing 6 types (ldap included) are genuinely pmgsh-verified.
        p = plan_who_object_update("2", "ldap", "9", mode="dc", profile="corp")
        assert "pmgsh-verified" in p.note
        assert "Smoke-confirm" not in p.note

    def test_note_for_ldapuser_says_smoke_confirm_not_pmgsh_verified(self):
        # Wave 8a: ldapuser is schema-verified only, never live-tested — note must reflect that.
        p = plan_who_object_update("2", "ldapuser", "9", account="jdoe2", profile="corp")
        assert "Smoke-confirm" in p.note
        assert "not yet live-tested" in p.note
        assert "pmgsh-verified" not in p.note


class TestPlanWhoObjectDelete:
    def test_risk_is_medium(self):
        p = plan_who_object_delete("2", "5")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_who_object_delete("2", "5")
        assert p.action == "pmg_who_object_delete"

    def test_target_includes_ogroup_and_id(self):
        p = plan_who_object_delete("2", "5")
        assert "2" in p.target
        assert "5" in p.target

    def test_blast_radius_non_empty(self):
        p = plan_who_object_delete("2", "5")
        assert len(p.blast_radius) > 0

    def test_rejects_non_numeric_ogroup(self):
        with pytest.raises(ProximoError):
            plan_who_object_delete("mygroup", "5")

    def test_rejects_non_numeric_id(self):
        with pytest.raises(ProximoError):
            plan_who_object_delete("2", "abc")


# ---------------------------------------------------------------------------
# W5c: _check_what_object_type validator
# ---------------------------------------------------------------------------

class TestCheckWhatObjectType:
    def test_valid_types_pass(self):
        for t in ("contenttype", "matchfield", "spamfilter", "virusfilter",
                  "filenamefilter", "archivefilter", "archivefilenamefilter"):
            assert _check_what_object_type(t) == t

    def test_invalid_type_raises(self):
        with pytest.raises(ProximoError):
            _check_what_object_type("email")

    def test_empty_string_raises(self):
        with pytest.raises(ProximoError):
            _check_what_object_type("")

    def test_error_lists_valid_types(self):
        with pytest.raises(ProximoError, match="contenttype"):
            _check_what_object_type("bogus")


# ---------------------------------------------------------------------------
# W5c: _check_action_position validator
# ---------------------------------------------------------------------------

class TestCheckActionPosition:
    def test_start_passes(self):
        assert _check_action_position("start") == "start"

    def test_end_passes(self):
        assert _check_action_position("end") == "end"

    def test_invalid_raises(self):
        with pytest.raises(ProximoError):
            _check_action_position("middle")


# ---------------------------------------------------------------------------
# W5c: _check_action_object_id validator
# ---------------------------------------------------------------------------

class TestCheckActionObjectId:
    def test_valid_compound_id(self):
        assert _check_action_object_id("13_26") == "13_26"

    def test_leading_zeros_ok(self):
        assert _check_action_object_id("0_0") == "0_0"

    def test_plain_numeric_rejected(self):
        with pytest.raises(ProximoError):
            _check_action_object_id("26")

    def test_slash_rejected(self):
        with pytest.raises(ProximoError):
            _check_action_object_id("13/26")

    def test_empty_rejected(self):
        with pytest.raises(ProximoError):
            _check_action_object_id("")

    def test_letters_rejected(self):
        with pytest.raises(ProximoError):
            _check_action_object_id("abc_def")


# ---------------------------------------------------------------------------
# W5c: what_object_add op tests
# ---------------------------------------------------------------------------

class TestWhatObjectAdd:
    def test_contenttype_uses_correct_path(self):
        api = _api()
        what_object_add(api, "8", "contenttype", contenttype="text/plain")
        assert api.seen["path"] == "/config/ruledb/what/8/contenttype"
        assert api.seen["method"] == "POST"

    def test_contenttype_body_has_contenttype(self):
        api = _api()
        what_object_add(api, "8", "contenttype", contenttype="text/plain")
        assert api.seen["data"].get("contenttype") == "text/plain"

    def test_contenttype_only_content_hyphen_key(self):
        api = _api()
        what_object_add(api, "8", "contenttype", contenttype="text/html", only_content=True)
        assert api.seen["data"].get("only-content") is True

    def test_matchfield_uses_correct_path(self):
        api = _api()
        what_object_add(api, "8", "matchfield", field="Subject", value="spam")
        assert api.seen["path"] == "/config/ruledb/what/8/matchfield"

    def test_matchfield_body_has_field_and_value(self):
        api = _api()
        what_object_add(api, "8", "matchfield", field="Subject", value="spam")
        assert api.seen["data"].get("field") == "Subject"
        assert api.seen["data"].get("value") == "spam"

    def test_matchfield_top_part_only_hyphen_key(self):
        api = _api()
        what_object_add(api, "8", "matchfield", field="X", value="v", top_part_only=True)
        assert api.seen["data"].get("top-part-only") is True

    def test_spamfilter_uses_correct_path(self):
        api = _api()
        what_object_add(api, "8", "spamfilter", spamlevel=5)
        assert api.seen["path"] == "/config/ruledb/what/8/spamfilter"

    def test_spamfilter_body_has_spamlevel(self):
        api = _api()
        what_object_add(api, "8", "spamfilter", spamlevel=5)
        assert api.seen["data"].get("spamlevel") == 5

    def test_virusfilter_uses_correct_path(self):
        api = _api()
        what_object_add(api, "8", "virusfilter")
        assert api.seen["path"] == "/config/ruledb/what/8/virusfilter"

    def test_virusfilter_sends_empty_body(self):
        api = _api()
        what_object_add(api, "8", "virusfilter")
        assert api.seen["data"] == {}

    def test_filenamefilter_uses_correct_path(self):
        api = _api()
        what_object_add(api, "8", "filenamefilter", filename="*.exe")
        assert api.seen["path"] == "/config/ruledb/what/8/filenamefilter"

    def test_filenamefilter_body_has_filename(self):
        api = _api()
        what_object_add(api, "8", "filenamefilter", filename="*.exe")
        assert api.seen["data"].get("filename") == "*.exe"

    def test_archivefilter_uses_correct_path(self):
        api = _api()
        what_object_add(api, "8", "archivefilter", contenttype="application/zip")
        assert api.seen["path"] == "/config/ruledb/what/8/archivefilter"

    def test_archivefilter_body_has_contenttype(self):
        api = _api()
        what_object_add(api, "8", "archivefilter", contenttype="application/zip")
        assert api.seen["data"].get("contenttype") == "application/zip"

    def test_archivefilter_only_content_hyphen_key(self):
        api = _api()
        what_object_add(api, "8", "archivefilter", contenttype="application/zip",
                        only_content=False)
        assert "only-content" in api.seen["data"]

    def test_archivefilenamefilter_uses_correct_path(self):
        api = _api()
        what_object_add(api, "8", "archivefilenamefilter", filename="*.bat")
        assert api.seen["path"] == "/config/ruledb/what/8/archivefilenamefilter"

    def test_archivefilenamefilter_body_has_filename(self):
        api = _api()
        what_object_add(api, "8", "archivefilenamefilter", filename="*.bat")
        assert api.seen["data"].get("filename") == "*.bat"

    def test_invalid_type_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_object_add(api, "8", "email")

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_object_add(api, "mygroup", "virusfilter")


# ---------------------------------------------------------------------------
# W5c: what_object_update op tests
# ---------------------------------------------------------------------------

class TestWhatObjectUpdate:
    def test_contenttype_uses_correct_path(self):
        api = _api()
        what_object_update(api, "8", "contenttype", "5", contenttype="text/plain")
        assert api.seen["path"] == "/config/ruledb/what/8/contenttype/5"
        assert api.seen["method"] == "PUT"

    def test_matchfield_uses_correct_path(self):
        api = _api()
        what_object_update(api, "8", "matchfield", "3", field="From", value="spammer")
        assert api.seen["path"] == "/config/ruledb/what/8/matchfield/3"

    def test_only_none_fields_not_sent(self):
        api = _api()
        what_object_update(api, "8", "matchfield", "3", field="From")
        assert "value" not in api.seen["data"]

    def test_top_part_only_hyphen_key_on_update(self):
        api = _api()
        what_object_update(api, "8", "matchfield", "3", top_part_only=True)
        assert api.seen["data"].get("top-part-only") is True

    def test_rejects_non_numeric_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_object_update(api, "8", "contenttype", "abc")

    def test_invalid_type_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_object_update(api, "8", "bogustype", "5")


# ---------------------------------------------------------------------------
# W5c: what_object_delete op tests
# ---------------------------------------------------------------------------

class TestWhatObjectDelete:
    def test_uses_objects_sub_path(self):
        api = _api()
        what_object_delete(api, "8", "5")
        assert api.seen["path"] == "/config/ruledb/what/8/objects/5"
        assert api.seen["method"] == "DELETE"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_object_delete(api, "mygroup", "5")

    def test_rejects_non_numeric_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_object_delete(api, "8", "abc")


# ---------------------------------------------------------------------------
# W5c: when_object_add op tests
# ---------------------------------------------------------------------------

class TestWhenObjectAdd:
    def test_uses_correct_path(self):
        api = _api()
        when_object_add(api, "4", start="08:00", end="17:00")
        assert api.seen["path"] == "/config/ruledb/when/4/timeframe"
        assert api.seen["method"] == "POST"

    def test_body_has_start_and_end(self):
        api = _api()
        when_object_add(api, "4", start="08:00", end="17:00")
        assert api.seen["data"].get("start") == "08:00"
        assert api.seen["data"].get("end") == "17:00"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            when_object_add(api, "mygroup", start="08:00", end="17:00")


# ---------------------------------------------------------------------------
# W5c: when_object_update op tests
# ---------------------------------------------------------------------------

class TestWhenObjectUpdate:
    def test_uses_correct_path(self):
        api = _api()
        when_object_update(api, "4", "7", start="09:00", end="17:00")
        assert api.seen["path"] == "/config/ruledb/when/4/timeframe/7"
        assert api.seen["method"] == "PUT"

    def test_both_start_and_end_in_body(self):
        # PMG 9.1 timeframe PUT requires both start and end;
        # a partial body (start only) returns 400 — live-proven 2026-06-26.
        api = _api()
        when_object_update(api, "4", "7", start="09:00", end="17:00")
        assert api.seen["data"].get("start") == "09:00"
        assert api.seen["data"].get("end") == "17:00"

    def test_rejects_non_numeric_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            when_object_update(api, "4", "abc", start="09:00", end="17:00")


# ---------------------------------------------------------------------------
# W5c: when_object_delete op tests
# ---------------------------------------------------------------------------

class TestWhenObjectDelete:
    def test_uses_objects_sub_path(self):
        api = _api()
        when_object_delete(api, "4", "7")
        assert api.seen["path"] == "/config/ruledb/when/4/objects/7"
        assert api.seen["method"] == "DELETE"

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            when_object_delete(api, "mygroup", "7")


# ---------------------------------------------------------------------------
# W5c: action_bcc_create op tests
# ---------------------------------------------------------------------------

class TestActionBccCreate:
    def test_uses_correct_path(self):
        api = _api()
        action_bcc_create(api, name="copy-admin", target="admin@example.com")
        assert api.seen["path"] == "/config/ruledb/action/bcc"
        assert api.seen["method"] == "POST"

    def test_body_has_required_fields(self):
        api = _api()
        action_bcc_create(api, name="copy-admin", target="admin@example.com")
        assert api.seen["data"].get("name") == "copy-admin"
        assert api.seen["data"].get("target") == "admin@example.com"

    def test_optional_original_sent_when_provided(self):
        api = _api()
        action_bcc_create(api, name="n", target="t@t.com", original=True)
        assert api.seen["data"].get("original") is True

    def test_optional_info_sent_when_provided(self):
        api = _api()
        action_bcc_create(api, name="n", target="t@t.com", info="desc")
        assert api.seen["data"].get("info") == "desc"


# ---------------------------------------------------------------------------
# W5c: action_bcc_update op tests
# ---------------------------------------------------------------------------

class TestActionBccUpdate:
    def test_uses_correct_path(self):
        api = _api()
        action_bcc_update(api, "13_26", target="new@example.com")
        assert api.seen["path"] == "/config/ruledb/action/bcc/13_26"
        assert api.seen["method"] == "PUT"

    def test_only_non_none_sent(self):
        api = _api()
        action_bcc_update(api, "13_26", target="new@example.com")
        assert "name" not in api.seen["data"]

    def test_rejects_non_compound_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_bcc_update(api, "26", target="x@x.com")


# ---------------------------------------------------------------------------
# W5c: action_field_create op tests
# ---------------------------------------------------------------------------

class TestActionFieldCreate:
    def test_uses_correct_path(self):
        api = _api()
        action_field_create(api, name="add-tag", field="X-Spam", value="yes")
        assert api.seen["path"] == "/config/ruledb/action/field"
        assert api.seen["method"] == "POST"

    def test_body_has_required_fields(self):
        api = _api()
        action_field_create(api, name="add-tag", field="X-Spam", value="yes")
        assert api.seen["data"].get("name") == "add-tag"
        assert api.seen["data"].get("field") == "X-Spam"
        assert api.seen["data"].get("value") == "yes"


# ---------------------------------------------------------------------------
# W5c: action_field_update op tests
# ---------------------------------------------------------------------------

class TestActionFieldUpdate:
    def test_uses_correct_path(self):
        api = _api()
        action_field_update(api, "5_10", name="tag", field="X-Spam", value="no")
        assert api.seen["path"] == "/config/ruledb/action/field/5_10"
        assert api.seen["method"] == "PUT"

    def test_required_fields_all_in_body(self):
        # PMG 9.1 field action PUT requires name+field+value;
        # a partial body (value only) returns 400 — live-proven 2026-06-26.
        api = _api()
        action_field_update(api, "5_10", name="tag", field="X-Spam", value="no")
        assert api.seen["data"].get("name") == "tag"
        assert api.seen["data"].get("field") == "X-Spam"
        assert api.seen["data"].get("value") == "no"

    def test_rejects_non_compound_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_field_update(api, "10", name="tag", field="X-Spam", value="no")


# ---------------------------------------------------------------------------
# W5c: action_notification_create op tests
# ---------------------------------------------------------------------------

class TestActionNotificationCreate:
    def test_uses_correct_path(self):
        api = _api()
        action_notification_create(api, name="notify-admin", to="admin@example.com",
                                   subject="Alert", body_text="Mail matched.")
        assert api.seen["path"] == "/config/ruledb/action/notification"
        assert api.seen["method"] == "POST"

    def test_body_has_required_fields(self):
        api = _api()
        action_notification_create(api, name="notify-admin", to="admin@example.com",
                                   subject="Alert", body_text="Mail matched.")
        assert api.seen["data"].get("name") == "notify-admin"
        assert api.seen["data"].get("to") == "admin@example.com"
        assert api.seen["data"].get("subject") == "Alert"
        assert api.seen["data"].get("body") == "Mail matched."

    def test_body_text_maps_to_body_key(self):
        api = _api()
        action_notification_create(api, name="n", to="t@t.com",
                                   subject="s", body_text="content")
        assert "body_text" not in api.seen["data"]
        assert api.seen["data"].get("body") == "content"

    def test_attach_sent_when_provided(self):
        api = _api()
        action_notification_create(api, name="n", to="t@t.com",
                                   subject="s", body_text="b", attach=True)
        assert api.seen["data"].get("attach") is True


# ---------------------------------------------------------------------------
# W5c: action_notification_update op tests
# ---------------------------------------------------------------------------

class TestActionNotificationUpdate:
    def test_uses_correct_path(self):
        api = _api()
        action_notification_update(
            api, "7_14", name="n", to="a@a.com", subject="New subject", body_text="b"
        )
        assert api.seen["path"] == "/config/ruledb/action/notification/7_14"
        assert api.seen["method"] == "PUT"

    def test_body_text_maps_to_body_key_on_update(self):
        # PMG 9.1 notification PUT requires name+to+subject+body_text;
        # a partial body (subject only) returns 400 — live-proven 2026-06-26.
        # body_text maps to API param 'body'.
        api = _api()
        action_notification_update(
            api, "7_14", name="n", to="a@a.com", subject="s", body_text="updated"
        )
        assert api.seen["data"].get("body") == "updated"
        assert "body_text" not in api.seen["data"]

    def test_rejects_non_compound_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_notification_update(
                api, "14", name="n", to="a@a.com", subject="x", body_text="b"
            )


# ---------------------------------------------------------------------------
# W5c: action_disclaimer_create op tests
# ---------------------------------------------------------------------------

class TestActionDisclaimerCreate:
    def test_uses_correct_path(self):
        api = _api()
        action_disclaimer_create(api, name="footer", disclaimer="Confidential")
        assert api.seen["path"] == "/config/ruledb/action/disclaimer"
        assert api.seen["method"] == "POST"

    def test_body_has_required_fields(self):
        api = _api()
        action_disclaimer_create(api, name="footer", disclaimer="Confidential")
        assert api.seen["data"].get("name") == "footer"
        assert api.seen["data"].get("disclaimer") == "Confidential"

    def test_add_separator_hyphen_key(self):
        api = _api()
        action_disclaimer_create(api, name="footer", disclaimer="text",
                                 add_separator=True)
        assert api.seen["data"].get("add-separator") is True
        assert "add_separator" not in api.seen["data"]

    def test_position_validated(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_disclaimer_create(api, name="footer", disclaimer="text",
                                     position="middle")

    def test_position_start_accepted(self):
        api = _api()
        action_disclaimer_create(api, name="footer", disclaimer="text", position="start")
        assert api.seen["data"].get("position") == "start"


# ---------------------------------------------------------------------------
# W5c: action_disclaimer_update op tests
# ---------------------------------------------------------------------------

class TestActionDisclaimerUpdate:
    def test_uses_correct_path(self):
        api = _api()
        action_disclaimer_update(api, "2_9", disclaimer="New text")
        assert api.seen["path"] == "/config/ruledb/action/disclaimer/2_9"
        assert api.seen["method"] == "PUT"

    def test_add_separator_hyphen_key_on_update(self):
        api = _api()
        action_disclaimer_update(api, "2_9", add_separator=False)
        assert "add-separator" in api.seen["data"]
        assert "add_separator" not in api.seen["data"]

    def test_rejects_non_compound_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_disclaimer_update(api, "9", disclaimer="x")


# ---------------------------------------------------------------------------
# W5c: action_removeattachments_create op tests
# ---------------------------------------------------------------------------

class TestActionRemoveattachmentsCreate:
    def test_uses_correct_path(self):
        api = _api()
        action_removeattachments_create(api, name="strip-attach", text="[removed]")
        assert api.seen["path"] == "/config/ruledb/action/removeattachments"
        assert api.seen["method"] == "POST"

    def test_body_has_required_fields(self):
        api = _api()
        action_removeattachments_create(api, name="strip-attach", text="[removed]")
        assert api.seen["data"].get("name") == "strip-attach"
        assert api.seen["data"].get("text") == "[removed]"

    def test_all_maps_to_all_key_not_all_underscore(self):
        api = _api()
        action_removeattachments_create(api, name="n", text="t", all_=True)
        assert api.seen["data"].get("all") is True
        assert "all_" not in api.seen["data"]

    def test_quarantine_sent_when_provided(self):
        api = _api()
        action_removeattachments_create(api, name="n", text="t", quarantine=True)
        assert api.seen["data"].get("quarantine") is True


# ---------------------------------------------------------------------------
# W5c: action_removeattachments_update op tests
# ---------------------------------------------------------------------------

class TestActionRemoveattachmentsUpdate:
    def test_uses_correct_path(self):
        api = _api()
        action_removeattachments_update(api, "3_5", text="[stripped]")
        assert api.seen["path"] == "/config/ruledb/action/removeattachments/3_5"
        assert api.seen["method"] == "PUT"

    def test_all_maps_to_all_key_on_update(self):
        api = _api()
        action_removeattachments_update(api, "3_5", all_=False)
        assert "all" in api.seen["data"]
        assert "all_" not in api.seen["data"]

    def test_rejects_non_compound_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_removeattachments_update(api, "5", text="x")


# ---------------------------------------------------------------------------
# W5c: action_delete op tests
# ---------------------------------------------------------------------------

class TestActionDelete:
    def test_uses_objects_sub_path(self):
        api = _api()
        action_delete(api, "13_26")
        assert api.seen["path"] == "/config/ruledb/action/objects/13_26"
        assert api.seen["method"] == "DELETE"

    def test_rejects_plain_numeric_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_delete(api, "26")

    def test_rejects_slash_in_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_delete(api, "13/26")


# ---------------------------------------------------------------------------
# W5c: plan_what_object_* tests
# ---------------------------------------------------------------------------

class TestPlanWhatObjectAdd:
    def test_risk_is_low(self):
        p = plan_what_object_add("8", "filenamefilter")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_what_object_add("8", "virusfilter")
        assert p.action == "pmg_what_object_add"

    def test_target_includes_ogroup_and_type(self):
        p = plan_what_object_add("8", "spamfilter")
        assert "8" in p.target
        assert "spamfilter" in p.target

    def test_blast_radius_non_empty(self):
        p = plan_what_object_add("8", "virusfilter")
        assert len(p.blast_radius) > 0

    def test_rejects_non_numeric_ogroup(self):
        with pytest.raises(ProximoError):
            plan_what_object_add("mygroup", "virusfilter")

    def test_rejects_invalid_type(self):
        with pytest.raises(ProximoError):
            plan_what_object_add("8", "bogus")


class TestPlanWhatObjectUpdate:
    def test_risk_is_medium(self):
        p = plan_what_object_update("8", "contenttype", "5")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_what_object_update("8", "matchfield", "3")
        assert p.action == "pmg_what_object_update"

    def test_target_includes_ogroup_type_and_id(self):
        p = plan_what_object_update("8", "spamfilter", "3")
        assert "8" in p.target
        assert "spamfilter" in p.target
        assert "3" in p.target

    def test_rejects_non_numeric_id(self):
        with pytest.raises(ProximoError):
            plan_what_object_update("8", "contenttype", "abc")

    def test_blast_radius_discloses_new_value(self):
        p = plan_what_object_update("8", "matchfield", "3", field="Subject", value="malicious")
        assert any("malicious" in entry for entry in p.blast_radius)


class TestPlanWhatObjectDelete:
    def test_risk_is_medium(self):
        p = plan_what_object_delete("8", "5")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_what_object_delete("8", "5")
        assert p.action == "pmg_what_object_delete"

    def test_target_includes_ogroup_and_id(self):
        p = plan_what_object_delete("8", "5")
        assert "8" in p.target
        assert "5" in p.target

    def test_blast_radius_non_empty(self):
        p = plan_what_object_delete("8", "5")
        assert len(p.blast_radius) > 0


# ---------------------------------------------------------------------------
# W5c: plan_when_object_* tests
# ---------------------------------------------------------------------------

class TestPlanWhenObjectAdd:
    def test_risk_is_low(self):
        p = plan_when_object_add("4", start="08:00", end="17:00")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_when_object_add("4", start="08:00", end="17:00")
        assert p.action == "pmg_when_object_add"

    def test_target_includes_ogroup(self):
        p = plan_when_object_add("4", start="08:00", end="17:00")
        assert "4" in p.target

    def test_blast_radius_non_empty(self):
        p = plan_when_object_add("4", start="08:00", end="17:00")
        assert len(p.blast_radius) > 0

    def test_rejects_non_numeric_ogroup(self):
        with pytest.raises(ProximoError):
            plan_when_object_add("mygroup", start="08:00", end="17:00")


class TestPlanWhenObjectUpdate:
    def test_risk_is_medium(self):
        p = plan_when_object_update("4", "7")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_when_object_update("4", "7")
        assert p.action == "pmg_when_object_update"

    def test_target_includes_ogroup_and_id(self):
        p = plan_when_object_update("4", "7")
        assert "4" in p.target
        assert "7" in p.target

    def test_rejects_non_numeric_id(self):
        with pytest.raises(ProximoError):
            plan_when_object_update("4", "abc")

    def test_blast_radius_discloses_new_value(self):
        p = plan_when_object_update("4", "7", start="03:00", end="04:00")
        assert any("03:00" in entry for entry in p.blast_radius)


class TestPlanWhenObjectDelete:
    def test_risk_is_medium(self):
        p = plan_when_object_delete("4", "7")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_when_object_delete("4", "7")
        assert p.action == "pmg_when_object_delete"

    def test_target_includes_ogroup_and_id(self):
        p = plan_when_object_delete("4", "7")
        assert "4" in p.target
        assert "7" in p.target

    def test_blast_radius_non_empty(self):
        p = plan_when_object_delete("4", "7")
        assert len(p.blast_radius) > 0


# ---------------------------------------------------------------------------
# W5c: plan_action_* tests
# ---------------------------------------------------------------------------

class TestPlanActionBccCreate:
    def test_risk_is_low(self):
        p = plan_action_bcc_create("copy-admin", "admin@example.com")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_action_bcc_create("n", "t@t.com")
        assert p.action == "pmg_action_bcc_create"

    def test_blast_radius_non_empty(self):
        p = plan_action_bcc_create("n", "t@t.com")
        assert len(p.blast_radius) > 0


class TestPlanActionBccUpdate:
    def test_risk_is_medium(self):
        p = plan_action_bcc_update("13_26")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_action_bcc_update("13_26")
        assert p.action == "pmg_action_bcc_update"

    def test_target_includes_id(self):
        p = plan_action_bcc_update("13_26")
        assert "13_26" in p.target

    def test_rejects_non_compound_id(self):
        with pytest.raises(ProximoError):
            plan_action_bcc_update("26")

    def test_blast_radius_discloses_new_target(self):
        p = plan_action_bcc_update("13_26", target="attacker@evil.example")
        assert any("attacker@evil.example" in entry for entry in p.blast_radius)


class TestPlanActionFieldCreate:
    def test_risk_is_low(self):
        p = plan_action_field_create("tag", "X-Spam", "yes")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_action_field_create("tag", "X-Spam", "yes")
        assert p.action == "pmg_action_field_create"


class TestPlanActionFieldUpdate:
    def test_risk_is_medium(self):
        p = plan_action_field_update("5_10")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_action_field_update("5_10")
        assert p.action == "pmg_action_field_update"

    def test_blast_radius_discloses_new_value(self):
        p = plan_action_field_update("5_10", name="tag", field="X-Spam", value="evil-payload")
        assert any("evil-payload" in entry for entry in p.blast_radius)

    def test_rejects_non_compound_id(self):
        with pytest.raises(ProximoError):
            plan_action_field_update("10")


class TestPlanActionNotificationCreate:
    def test_risk_is_low(self):
        p = plan_action_notification_create("n", "t@t.com")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_action_notification_create("n", "t@t.com")
        assert p.action == "pmg_action_notification_create"


class TestPlanActionNotificationUpdate:
    def test_risk_is_medium(self):
        p = plan_action_notification_update("7_14")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_action_notification_update("7_14")
        assert p.action == "pmg_action_notification_update"

    def test_blast_radius_discloses_new_value(self):
        p = plan_action_notification_update("7_14", to="attacker@evil.example")
        assert any("attacker@evil.example" in entry for entry in p.blast_radius)

    def test_rejects_non_compound_id(self):
        with pytest.raises(ProximoError):
            plan_action_notification_update("14")


class TestPlanActionDisclaimerCreate:
    def test_risk_is_low(self):
        p = plan_action_disclaimer_create("footer")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_action_disclaimer_create("footer")
        assert p.action == "pmg_action_disclaimer_create"


class TestPlanActionDisclaimerUpdate:
    def test_risk_is_medium(self):
        p = plan_action_disclaimer_update("2_9")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_action_disclaimer_update("2_9")
        assert p.action == "pmg_action_disclaimer_update"

    def test_blast_radius_discloses_new_value(self):
        p = plan_action_disclaimer_update("2_9", disclaimer="malicious text")
        assert any("malicious text" in entry for entry in p.blast_radius)

    def test_rejects_non_compound_id(self):
        with pytest.raises(ProximoError):
            plan_action_disclaimer_update("9")


class TestPlanActionRemoveattachmentsCreate:
    def test_risk_is_low(self):
        p = plan_action_removeattachments_create("strip")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_action_removeattachments_create("strip")
        assert p.action == "pmg_action_removeattachments_create"


class TestPlanActionRemoveattachmentsUpdate:
    def test_risk_is_medium(self):
        p = plan_action_removeattachments_update("3_5")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_action_removeattachments_update("3_5")
        assert p.action == "pmg_action_removeattachments_update"

    def test_blast_radius_discloses_new_value(self):
        p = plan_action_removeattachments_update("3_5", text="stripped-notice")
        assert any("stripped-notice" in entry for entry in p.blast_radius)

    def test_rejects_non_compound_id(self):
        with pytest.raises(ProximoError):
            plan_action_removeattachments_update("5")


class TestPlanActionDelete:
    def test_risk_is_medium(self):
        p = plan_action_delete("13_26")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_action_delete("13_26")
        assert p.action == "pmg_action_delete"

    def test_target_includes_id(self):
        p = plan_action_delete("13_26")
        assert "13_26" in p.target

    def test_blast_radius_non_empty(self):
        p = plan_action_delete("13_26")
        assert len(p.blast_radius) > 0

    def test_rejects_non_compound_id(self):
        with pytest.raises(ProximoError):
            plan_action_delete("26")


# ---------------------------------------------------------------------------
# W5d Validators
# ---------------------------------------------------------------------------


class TestCheckDirection:
    def test_accepts_zero(self):
        assert _check_direction(0) == 0

    def test_accepts_one(self):
        assert _check_direction(1) == 1

    def test_accepts_two(self):
        assert _check_direction(2) == 2

    def test_rejects_three(self):
        with pytest.raises(ProximoError):
            _check_direction(3)

    def test_rejects_negative(self):
        with pytest.raises(ProximoError):
            _check_direction(-1)

    def test_rejects_non_int(self):
        with pytest.raises(ProximoError):
            _check_direction("both")


class TestCheckPriority:
    def test_accepts_zero(self):
        assert _check_priority(0) == 0

    def test_accepts_hundred(self):
        assert _check_priority(100) == 100

    def test_accepts_fifty(self):
        assert _check_priority(50) == 50

    def test_rejects_negative(self):
        with pytest.raises(ProximoError):
            _check_priority(-1)

    def test_rejects_over_hundred(self):
        with pytest.raises(ProximoError):
            _check_priority(101)

    def test_rejects_non_int(self):
        with pytest.raises(ProximoError):
            _check_priority("high")


# ---------------------------------------------------------------------------
# W5d: ruledb_rule_create op tests
# ---------------------------------------------------------------------------


class TestRuledbRuleCreate:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_create(api, "my-rule", 50)
        assert api.seen["path"] == "/config/ruledb/rules"
        assert api.seen["method"] == "POST"

    def test_body_has_required_fields(self):
        api = _api()
        ruledb_rule_create(api, "my-rule", 50)
        assert api.seen["data"].get("name") == "my-rule"
        assert api.seen["data"].get("priority") == 50

    def test_active_defaults_false(self):
        api = _api()
        ruledb_rule_create(api, "my-rule", 50)
        assert api.seen["data"].get("active") is False

    def test_active_can_be_set_true(self):
        api = _api()
        ruledb_rule_create(api, "my-rule", 50, active=True)
        assert api.seen["data"].get("active") is True

    def test_hyphen_params_sent_with_hyphen_keys(self):
        api = _api()
        ruledb_rule_create(api, "r", 10, from_and=True, from_invert=False,
                           to_and=True, to_invert=False,
                           what_and=True, what_invert=False,
                           when_and=True, when_invert=False)
        assert api.seen["data"].get("from-and") is True
        assert api.seen["data"].get("from-invert") is False
        assert api.seen["data"].get("to-and") is True
        assert api.seen["data"].get("what-and") is True
        assert api.seen["data"].get("when-and") is True
        # underscore form must NOT appear in the API body
        assert "from_and" not in api.seen["data"]

    def test_direction_sent_when_provided(self):
        api = _api()
        ruledb_rule_create(api, "r", 10, direction=2)
        assert api.seen["data"].get("direction") == 2

    def test_rejects_invalid_priority(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_create(api, "r", 200)

    def test_rejects_invalid_direction(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_create(api, "r", 10, direction=5)


# ---------------------------------------------------------------------------
# W5d: ruledb_rule_update op tests
# ---------------------------------------------------------------------------


class TestRuledbRuleUpdate:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_update(api, "100", name="renamed")
        assert api.seen["path"] == "/config/ruledb/rules/100/config"
        assert api.seen["method"] == "PUT"

    def test_only_non_none_fields_sent(self):
        api = _api()
        ruledb_rule_update(api, "100", name="renamed")
        assert "priority" not in api.seen["data"]
        assert "active" not in api.seen["data"]

    def test_hyphen_params_sent_with_hyphen_keys(self):
        api = _api()
        ruledb_rule_update(api, "100", from_and=True, what_invert=True)
        assert api.seen["data"].get("from-and") is True
        assert api.seen["data"].get("what-invert") is True
        assert "from_and" not in api.seen["data"]

    def test_rejects_invalid_rule_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_update(api, "abc", name="x")

    def test_rejects_invalid_priority(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_update(api, "100", priority=999)


# ---------------------------------------------------------------------------
# W5d: ruledb_rule_delete op tests
# ---------------------------------------------------------------------------


class TestRuledbRuleDelete:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_delete(api, "100")
        assert api.seen["path"] == "/config/ruledb/rules/100"
        assert api.seen["method"] == "DELETE"

    def test_rejects_invalid_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_delete(api, "abc")


# ---------------------------------------------------------------------------
# W5d: attach op tests (5 attach verbs)
# ---------------------------------------------------------------------------


class TestRuledbRuleFromAttach:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_from_attach(api, "100", "2")
        assert api.seen["path"] == "/config/ruledb/rules/100/from"
        assert api.seen["method"] == "POST"

    def test_ogroup_in_body(self):
        api = _api()
        ruledb_rule_from_attach(api, "100", "2")
        assert api.seen["data"].get("ogroup") == "2"


class TestRuledbRuleToAttach:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_to_attach(api, "100", "3")
        assert api.seen["path"] == "/config/ruledb/rules/100/to"
        assert api.seen["method"] == "POST"

    def test_ogroup_in_body(self):
        api = _api()
        ruledb_rule_to_attach(api, "100", "3")
        assert api.seen["data"].get("ogroup") == "3"


class TestRuledbRuleWhatAttach:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_what_attach(api, "100", "8")
        assert api.seen["path"] == "/config/ruledb/rules/100/what"
        assert api.seen["method"] == "POST"

    def test_ogroup_in_body(self):
        api = _api()
        ruledb_rule_what_attach(api, "100", "8")
        assert api.seen["data"].get("ogroup") == "8"


class TestRuledbRuleWhenAttach:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_when_attach(api, "100", "4")
        assert api.seen["path"] == "/config/ruledb/rules/100/when"
        assert api.seen["method"] == "POST"

    def test_ogroup_in_body(self):
        api = _api()
        ruledb_rule_when_attach(api, "100", "4")
        assert api.seen["data"].get("ogroup") == "4"


class TestRuledbRuleActionAttach:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_action_attach(api, "100", "13")
        # PMG 9.1 live-verified: singular /action (not /actions — that path returns 501)
        assert api.seen["path"] == "/config/ruledb/rules/100/action"
        assert api.seen["method"] == "POST"

    def test_ogroup_in_body(self):
        api = _api()
        ruledb_rule_action_attach(api, "100", "13")
        assert api.seen["data"].get("ogroup") == "13"


# ---------------------------------------------------------------------------
# W5d: detach op tests (5 detach verbs — ogroup in the DELETE path)
# ---------------------------------------------------------------------------


class TestRuledbRuleFromDetach:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_from_detach(api, "100", "2")
        assert api.seen["path"] == "/config/ruledb/rules/100/from/2"
        assert api.seen["method"] == "DELETE"


class TestRuledbRuleToDetach:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_to_detach(api, "100", "3")
        assert api.seen["path"] == "/config/ruledb/rules/100/to/3"
        assert api.seen["method"] == "DELETE"


class TestRuledbRuleWhatDetach:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_what_detach(api, "100", "8")
        assert api.seen["path"] == "/config/ruledb/rules/100/what/8"
        assert api.seen["method"] == "DELETE"


class TestRuledbRuleWhenDetach:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_when_detach(api, "100", "4")
        assert api.seen["path"] == "/config/ruledb/rules/100/when/4"
        assert api.seen["method"] == "DELETE"


class TestRuledbRuleActionDetach:
    def test_uses_correct_path(self):
        api = _api()
        ruledb_rule_action_detach(api, "100", "13")
        # PMG 9.1 live-verified: singular /action (not /actions — that path returns 501)
        assert api.seen["path"] == "/config/ruledb/rules/100/action/13"
        assert api.seen["method"] == "DELETE"


# ---------------------------------------------------------------------------
# W5d: plan_ruledb_rule_create tests
# ---------------------------------------------------------------------------


class TestPlanRuledbRuleCreate:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_create("r", 50)
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_ruledb_rule_create("r", 50)
        assert p.action == "pmg_ruledb_rule_create"

    def test_active_defaults_false_in_signature(self):
        # active must default to False to satisfy the safety requirement
        p = plan_ruledb_rule_create("r", 50)
        assert "active=False" in p.change or "active=False" in str(p.blast_radius)

    def test_mail_flow_warning_in_blast_radius(self):
        p = plan_ruledb_rule_create("r", 50)
        combined = " ".join(p.blast_radius)
        assert "live mail processing" in combined

    def test_rejects_invalid_priority(self):
        with pytest.raises(ProximoError):
            plan_ruledb_rule_create("r", 999)

    def test_rejects_invalid_direction(self):
        with pytest.raises(ProximoError):
            plan_ruledb_rule_create("r", 50, direction=5)


# ---------------------------------------------------------------------------
# W5d: plan_ruledb_rule_update tests
# ---------------------------------------------------------------------------


class TestPlanRuledbRuleUpdate:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_update("100")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_ruledb_rule_update("100")
        assert p.action == "pmg_ruledb_rule_update"

    def test_mail_flow_warning_in_blast_radius(self):
        p = plan_ruledb_rule_update("100")
        combined = " ".join(p.blast_radius)
        assert "live mail processing" in combined

    def test_active_true_note_present(self):
        p = plan_ruledb_rule_update("100", active=True)
        combined = " ".join(p.blast_radius)
        assert "activates" in combined or "active" in combined

    def test_rejects_invalid_rule_id(self):
        with pytest.raises(ProximoError):
            plan_ruledb_rule_update("abc")

    def test_rejects_invalid_priority(self):
        with pytest.raises(ProximoError):
            plan_ruledb_rule_update("100", priority=200)

    def test_blast_radius_discloses_new_name(self):
        p = plan_ruledb_rule_update("100", name="Renamed-Rule")
        assert any("Renamed-Rule" in entry for entry in p.blast_radius)


# ---------------------------------------------------------------------------
# W5d: plan_ruledb_rule_delete tests
# ---------------------------------------------------------------------------


class TestPlanRuledbRuleDelete:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_delete("100")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_ruledb_rule_delete("100")
        assert p.action == "pmg_ruledb_rule_delete"

    def test_target_includes_id(self):
        p = plan_ruledb_rule_delete("100")
        assert "100" in p.target

    def test_rejects_invalid_rule_id(self):
        with pytest.raises(ProximoError):
            plan_ruledb_rule_delete("abc")


# ---------------------------------------------------------------------------
# W5d: attach/detach plan tests
# ---------------------------------------------------------------------------


class TestPlanRuledbRuleFromAttach:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_from_attach("100", "2")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_ruledb_rule_from_attach("100", "2")
        assert p.action == "pmg_ruledb_rule_from_attach"

    def test_mail_flow_note_in_blast_radius(self):
        p = plan_ruledb_rule_from_attach("100", "2")
        combined = " ".join(p.blast_radius)
        assert "only affects flow if the rule is active" in combined


class TestPlanRuledbRuleFromDetach:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_from_detach("100", "2")
        assert p.risk == RISK_MEDIUM

    def test_action_string(self):
        p = plan_ruledb_rule_from_detach("100", "2")
        assert p.action == "pmg_ruledb_rule_from_detach"


class TestPlanRuledbRuleToAttach:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_to_attach("100", "3")
        assert p.risk == RISK_MEDIUM

    def test_mail_flow_note_in_blast_radius(self):
        p = plan_ruledb_rule_to_attach("100", "3")
        combined = " ".join(p.blast_radius)
        assert "only affects flow if the rule is active" in combined


class TestPlanRuledbRuleToDetach:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_to_detach("100", "3")
        assert p.risk == RISK_MEDIUM


class TestPlanRuledbRuleWhatAttach:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_what_attach("100", "8")
        assert p.risk == RISK_MEDIUM

    def test_mail_flow_note_in_blast_radius(self):
        p = plan_ruledb_rule_what_attach("100", "8")
        combined = " ".join(p.blast_radius)
        assert "only affects flow if the rule is active" in combined


class TestPlanRuledbRuleWhatDetach:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_what_detach("100", "8")
        assert p.risk == RISK_MEDIUM


class TestPlanRuledbRuleWhenAttach:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_when_attach("100", "4")
        assert p.risk == RISK_MEDIUM

    def test_mail_flow_note_in_blast_radius(self):
        p = plan_ruledb_rule_when_attach("100", "4")
        combined = " ".join(p.blast_radius)
        assert "only affects flow if the rule is active" in combined


class TestPlanRuledbRuleWhenDetach:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_when_detach("100", "4")
        assert p.risk == RISK_MEDIUM


class TestPlanRuledbRuleActionAttach:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_action_attach("100", "13")
        assert p.risk == RISK_MEDIUM

    def test_mail_flow_note_in_blast_radius(self):
        p = plan_ruledb_rule_action_attach("100", "13")
        combined = " ".join(p.blast_radius)
        assert "only affects flow if the rule is active" in combined


class TestPlanRuledbRuleActionDetach:
    def test_risk_is_medium(self):
        p = plan_ruledb_rule_action_detach("100", "13")
        assert p.risk == RISK_MEDIUM


class TestQuarantinePlanScopeHonesty:
    """H1 (2026-07-10 audit): PMG quarantine block/welcomelist entries are PER-USER. The executor
    always sends pmail, defaulting to the authenticated user (api.config.username), so the effect is
    NEVER global. The PLAN preview (the trust surface the operator confirms against) must not claim a
    global/all-users block, and when the effective default user is known it must name that per-user
    scope so the preview matches the exact request that will be executed."""

    @staticmethod
    def _txt(p):
        return (" ".join(p.blast_radius) + " " + p.change).lower()

    def test_blocklist_add_not_falsely_global(self):
        assert "global" not in self._txt(plan_quarantine_blocklist_add("spam@evil.com"))

    def test_blocklist_remove_not_falsely_global(self):
        assert "global" not in self._txt(plan_quarantine_blocklist_remove("spam@evil.com"))

    def test_welcomelist_add_not_falsely_global(self):
        assert "global" not in self._txt(plan_quarantine_welcomelist_add("ok@good.com"))

    def test_welcomelist_remove_not_falsely_global(self):
        assert "global" not in self._txt(plan_quarantine_welcomelist_remove("ok@good.com"))

    def test_blocklist_add_names_default_user_when_pmail_omitted(self):
        # The plan must preview the SAME per-user scope the executor sends (root@pam here).
        assert "root@pam" in self._txt(
            plan_quarantine_blocklist_add("spam@evil.com", default_pmail="root@pam"))

    def test_welcomelist_add_names_default_user_when_pmail_omitted(self):
        assert "root@pam" in self._txt(
            plan_quarantine_welcomelist_add("ok@good.com", default_pmail="root@pam"))

    def test_explicit_pmail_still_shown(self):
        # Regression guard: an explicitly-passed pmail must still appear as the per-user scope.
        assert "alice@corp" in self._txt(
            plan_quarantine_blocklist_add("spam@evil.com", pmail="alice@corp"))


class TestStatisticsSenderOrderbyDocHonesty:
    """M2 (2026-07-10 audit): the backend statistics_sender SILENTLY DROPS orderby (PMG 9.1 rejects it;
    pinned by test_orderby_not_sent_to_api). The agent-facing tool description must not promise a
    'passthrough' it does not perform — that made agents trust a sort that never happens."""

    def test_sender_description_does_not_claim_orderby_passthrough(self):
        import asyncio

        import proximo.server as server

        tools = {t.name: t for t in asyncio.run(server.mcp.list_tools())}
        desc = tools["pmg_statistics_sender"].description.lower()
        assert "passthrough" not in desc, "sender orderby is dropped, not passed through"
        assert any(w in desc for w in ("ignored", "not sent", "rejected")), \
            "sender description must disclose orderby is accepted-but-ignored"


class TestLowFindingDocHonesty20260710:
    """LOW findings from the 2026-07-10 audit: plan/doc surfaces must match code behavior."""

    def test_who_object_add_plan_renders_ogroup_value_not_literal(self):
        # L3: the WARNING blast line was a plain string -> the {ogroup} placeholder printed literally.
        p = plan_who_object_add("7", "email", email="ceo@example.com")
        text = " ".join(p.blast_radius)
        assert "{ogroup}" not in text
        assert "7" in text

    def test_group_get_object_tools_document_numeric_id_not_name(self):
        # L4: these six read tools require a NUMERIC ogroup ID; the old doc said "object group name",
        # which makes PMG return HTTP 400 and steers agents wrong on every call.
        import asyncio

        import proximo.server as server

        tools = {t.name: t for t in asyncio.run(server.mcp.list_tools())}
        for name in ["pmg_who_group_get", "pmg_who_group_objects", "pmg_what_group_get",
                     "pmg_what_group_objects", "pmg_when_group_get", "pmg_when_group_objects"]:
            desc = tools[name].description.lower()
            assert "numeric id" in desc, f"{name} must document ogroup as a numeric ID"
            assert "object group name" not in desc, f"{name} still says 'object group name'"


# ---------------------------------------------------------------------------
# W6a (Wave 8a): ruledb per-object reads + the direct rule<->action-group read + RuleDB
# factory reset. See proximo/pmg.py's own W6a section header for the coordinator rulings
# (.scratch/2026-07-15-full-surface-campaign.md, "Wave 8 decomposition").
# ---------------------------------------------------------------------------

class TestWhoObjectGet:
    def test_uses_correct_path(self):
        api = _api()
        who_object_get(api, "2", "email", "5")
        assert api.seen["path"] == "/config/ruledb/who/2/email/5"
        assert api.seen["method"] == "GET"

    def test_ldapuser_uses_correct_path(self):
        api = _api()
        who_object_get(api, "2", "ldapuser", "9")
        assert api.seen["path"] == "/config/ruledb/who/2/ldapuser/9"

    def test_rejects_invalid_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_object_get(api, "2", "spf", "5")

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_object_get(api, "mygroup", "email", "5")

    def test_rejects_non_numeric_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            who_object_get(api, "2", "email", "obj-abc")

    def test_falls_back_to_empty_dict(self):
        api = _api()
        api._get = lambda path, params=None: None
        result = who_object_get(api, "2", "email", "5")
        assert result == {}


class TestWhatObjectGet:
    def test_uses_correct_path(self):
        api = _api()
        what_object_get(api, "8", "contenttype", "3")
        assert api.seen["path"] == "/config/ruledb/what/8/contenttype/3"
        assert api.seen["method"] == "GET"

    def test_rejects_invalid_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_object_get(api, "8", "bogus", "3")

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_object_get(api, "mygroup", "contenttype", "3")

    def test_rejects_non_numeric_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            what_object_get(api, "8", "contenttype", "obj-abc")

    def test_falls_back_to_empty_dict(self):
        api = _api()
        api._get = lambda path, params=None: None
        result = what_object_get(api, "8", "contenttype", "3")
        assert result == {}


class TestWhenObjectGet:
    def test_uses_correct_path(self):
        api = _api()
        when_object_get(api, "4", "6")
        assert api.seen["path"] == "/config/ruledb/when/4/timeframe/6"
        assert api.seen["method"] == "GET"

    def test_no_type_param(self):
        # 'when' has only one object type (timeframe) — mirrors when_object_add's signature.
        import inspect
        sig = inspect.signature(when_object_get)
        assert "type_" not in sig.parameters

    def test_rejects_non_numeric_ogroup(self):
        api = _api()
        with pytest.raises(ProximoError):
            when_object_get(api, "mygroup", "6")

    def test_rejects_non_numeric_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            when_object_get(api, "4", "obj-abc")

    def test_falls_back_to_empty_dict(self):
        api = _api()
        api._get = lambda path, params=None: None
        result = when_object_get(api, "4", "6")
        assert result == {}


class TestActionBccGet:
    def test_uses_correct_path(self):
        api = _api()
        action_bcc_get(api, "13_26")
        assert api.seen["path"] == "/config/ruledb/action/bcc/13_26"
        assert api.seen["method"] == "GET"

    def test_rejects_non_compound_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_bcc_get(api, "26")


class TestActionFieldGet:
    def test_uses_correct_path(self):
        api = _api()
        action_field_get(api, "13_27")
        assert api.seen["path"] == "/config/ruledb/action/field/13_27"
        assert api.seen["method"] == "GET"

    def test_rejects_non_compound_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_field_get(api, "27")


class TestActionNotificationGet:
    def test_uses_correct_path(self):
        api = _api()
        action_notification_get(api, "13_28")
        assert api.seen["path"] == "/config/ruledb/action/notification/13_28"
        assert api.seen["method"] == "GET"

    def test_rejects_non_compound_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_notification_get(api, "28")


class TestActionDisclaimerGet:
    def test_uses_correct_path(self):
        api = _api()
        action_disclaimer_get(api, "13_29")
        assert api.seen["path"] == "/config/ruledb/action/disclaimer/13_29"
        assert api.seen["method"] == "GET"

    def test_rejects_non_compound_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_disclaimer_get(api, "29")


class TestActionRemoveattachmentsGet:
    def test_uses_correct_path(self):
        api = _api()
        action_removeattachments_get(api, "13_30")
        assert api.seen["path"] == "/config/ruledb/action/removeattachments/13_30"
        assert api.seen["method"] == "GET"

    def test_rejects_non_compound_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            action_removeattachments_get(api, "30")


class TestRuledbRuleActionGroupsList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, method="GET") or []
        )
        ruledb_rule_action_groups_list(api, "100")
        assert api.seen["path"] == "/config/ruledb/rules/100/action"
        assert api.seen["method"] == "GET"

    def test_returns_bare_id_list(self):
        api = _api()
        api._get = lambda path, params=None: [{"id": 7}]
        result = ruledb_rule_action_groups_list(api, "100")
        assert result == [{"id": 7}]

    def test_id_interpolated(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        ruledb_rule_action_groups_list(api, "500")
        assert "500" in api.seen["path"]

    def test_rejects_invalid_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            ruledb_rule_action_groups_list(api, "bad/id")

    def test_distinct_from_plural_workarounds_config_path(self):
        # Sanity: reads the SINGULAR /action endpoint directly — never rule's /config (the plural
        # ruledb_rule_actions_list's own path, which this function does NOT touch).
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or []
        )
        ruledb_rule_action_groups_list(api, "100")
        assert not api.seen["path"].endswith("/config")
        assert api.seen["path"].endswith("/action")


class TestRuledbReset:
    def test_uses_correct_path_and_method(self):
        api = _api()
        ruledb_reset(api)
        assert api.seen["path"] == "/config/ruledb"
        assert api.seen["method"] == "POST"

    def test_sends_empty_body(self):
        api = _api()
        ruledb_reset(api)
        assert api.seen["data"] == {}


class TestPlanRuledbReset:
    """plan_ruledb_reset is NOT pure — it captures the current scope via 5 best-effort reads.
    The fake here is path-aware (unlike _api(), which returns one fixed value for every GET)."""

    @staticmethod
    def _capturing_api(gets: dict | None = None, raise_on: set | None = None):
        gets = gets or {}
        raise_on = raise_on or set()

        def fake_get(path, params=None):
            if path in raise_on:
                raise ProximoError(f"simulated capture failure for {path}")
            return gets.get(path, [])

        return SimpleNamespace(_get=fake_get)

    def test_risk_is_high(self):
        api = self._capturing_api()
        p = plan_ruledb_reset(api)
        assert p.risk == RISK_HIGH

    def test_action_and_target(self):
        api = self._capturing_api()
        p = plan_ruledb_reset(api)
        assert p.action == "pmg_ruledb_reset"
        assert p.target == "pmg/config/ruledb"

    def test_first_blast_line_states_no_undo(self):
        api = self._capturing_api()
        p = plan_ruledb_reset(api)
        assert p.blast_radius[0] == "Proximo has NO undo for this; take pmg_backup_create first."

    def test_toll_line_reflects_captured_counts(self):
        api = self._capturing_api(gets={
            "/config/ruledb/rules": [{"id": 1}, {"id": 2}],
            "/config/ruledb/who": [{"id": 1}],
            "/config/ruledb/what": [{"id": 1}, {"id": 2}, {"id": 3}],
            "/config/ruledb/when": [],
            "/config/ruledb/action/objects": [{"id": 1}],
        })
        p = plan_ruledb_reset(api)
        toll = p.blast_radius[1]
        assert "2 rules" in toll
        assert "1 who" in toll
        assert "3 what" in toll
        assert "0 when" in toll
        assert "1 action objects" in toll

    def test_complete_true_when_all_captures_succeed(self):
        api = self._capturing_api()
        p = plan_ruledb_reset(api)
        assert p.complete is True

    def test_degrades_honestly_on_capture_failure(self):
        api = self._capturing_api(
            gets={"/config/ruledb/rules": [{"id": 1}]},
            raise_on={"/config/ruledb/who"},
        )
        p = plan_ruledb_reset(api)
        assert p.complete is False
        assert any("who_groups count capture failed" in note for note in p.blast_radius)
        # the plan still renders — HIGH risk, first line intact — even with a partial capture
        assert p.risk == RISK_HIGH
        assert p.blast_radius[0] == "Proximo has NO undo for this; take pmg_backup_create first."

    def test_unknown_count_rendered_honestly_in_toll(self):
        api = self._capturing_api(raise_on={"/config/ruledb/what"})
        p = plan_ruledb_reset(api)
        assert "an unknown number of what" in p.blast_radius[1]

    def test_current_carries_the_captured_counts(self):
        api = self._capturing_api(gets={"/config/ruledb/rules": [{"id": 1}]})
        p = plan_ruledb_reset(api)
        assert p.current["rules"] == 1


# ===========================================================================
# Wave 9c: LDAP profiles + fetchmail
# ===========================================================================

class TestCheckLdapProfile:
    def test_accepts_valid(self):
        assert _check_ldap_profile("my-ad_1") == "my-ad_1"

    def test_rejects_leading_hyphen(self):
        with pytest.raises(ProximoError):
            _check_ldap_profile("-bad")

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_ldap_profile("a/b")

    def test_rejects_trailing_newline(self):
        with pytest.raises(ProximoError):
            _check_ldap_profile("profile\n")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_ldap_profile("a" * 65)


class TestCheckLdapMode:
    def test_accepts_each_valid_mode(self):
        for m in ("ldap", "ldaps", "ldap+starttls"):
            assert _check_ldap_mode(m) == m

    def test_rejects_unknown_mode(self):
        with pytest.raises(ProximoError):
            _check_ldap_mode("ldapz")


class TestCheckLdapPort:
    def test_accepts_boundary_values(self):
        assert _check_ldap_port(1) == 1
        assert _check_ldap_port(65535) == 65535

    def test_rejects_zero(self):
        with pytest.raises(ProximoError):
            _check_ldap_port(0)

    def test_rejects_out_of_range(self):
        with pytest.raises(ProximoError):
            _check_ldap_port(65536)

    def test_rejects_non_integer(self):
        with pytest.raises(ProximoError):
            _check_ldap_port("not-a-port")


class TestCheckLdapServerAddress:
    def test_accepts_reasonable_address(self):
        assert _check_ldap_server_address("ldap.example.com", "server1") == "ldap.example.com"

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_ldap_server_address("a" * 257, "server1")


class TestCheckLdapComment:
    def test_accepts_reasonable_comment(self):
        assert _check_ldap_comment("a directory profile") == "a directory profile"

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_ldap_comment("a" * 4097)


class TestCheckLdapConfigDigest:
    def test_none_passes_through(self):
        assert _check_ldap_config_digest(None) is None

    def test_accepts_reasonable_digest(self):
        assert _check_ldap_config_digest("abc123") == "abc123"

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_ldap_config_digest("a" * 65)


class TestCheckEmailAddress:
    def test_accepts_valid_email(self):
        assert _check_email_address("user@example.com") == "user@example.com"

    def test_rejects_missing_at(self):
        with pytest.raises(ProximoError):
            _check_email_address("not-an-email")

    def test_rejects_too_short(self):
        with pytest.raises(ProximoError):
            _check_email_address("a@")

    def test_rejects_whitespace(self):
        with pytest.raises(ProximoError):
            _check_email_address("user @example.com")

    def test_rejects_slash_in_domain(self):
        with pytest.raises(ProximoError):
            _check_email_address("user@exa/mple.com")


class TestCheckLdapGid:
    def test_accepts_integer_string(self):
        assert _check_ldap_gid("42") == 42

    def test_accepts_int(self):
        assert _check_ldap_gid(42) == 42

    def test_rejects_non_integer(self):
        with pytest.raises(ProximoError):
            _check_ldap_gid("not-a-number")


class TestCheckFetchmailId:
    def test_accepts_alnum(self):
        assert _check_fetchmail_id("Ab12") == "Ab12"

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_fetchmail_id("a" * 17)

    def test_rejects_special_chars(self):
        with pytest.raises(ProximoError):
            _check_fetchmail_id("has-dash")


class TestCheckFetchmailProtocol:
    def test_accepts_pop3_and_imap(self):
        assert _check_fetchmail_protocol("pop3") == "pop3"
        assert _check_fetchmail_protocol("imap") == "imap"

    def test_rejects_smtp(self):
        with pytest.raises(ProximoError):
            _check_fetchmail_protocol("smtp")


class TestCheckFetchmailPort:
    def test_accepts_boundary_values(self):
        assert _check_fetchmail_port(1) == 1
        assert _check_fetchmail_port(65535) == 65535

    def test_rejects_out_of_range(self):
        with pytest.raises(ProximoError):
            _check_fetchmail_port(0)


class TestCheckFetchmailInterval:
    def test_accepts_boundary_values(self):
        assert _check_fetchmail_interval(1) == 1
        assert _check_fetchmail_interval(2016) == 2016

    def test_rejects_out_of_range(self):
        with pytest.raises(ProximoError):
            _check_fetchmail_interval(2017)
        with pytest.raises(ProximoError):
            _check_fetchmail_interval(0)


class TestCheckFetchmailUser:
    def test_accepts_reasonable_user(self):
        assert _check_fetchmail_user("alice") == "alice"

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_fetchmail_user("")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_fetchmail_user("a" * 65)


# ---------------------------------------------------------------------------
# LDAP profile backend functions
# ---------------------------------------------------------------------------

class TestLdapProfilesList:
    def test_uses_correct_path(self):
        api = _api()
        ldap_profiles_list(api)
        assert api.seen["path"] == "/config/ldap"
        assert api.seen["method"] == "GET"


class TestLdapProfileConfigGet:
    def test_uses_correct_path(self):
        api = _api()
        ldap_profile_config_get(api, "my-ad")
        assert api.seen["path"] == "/config/ldap/my-ad/config"

    def test_strips_bindpw_defensively(self):
        """THE SECRET CONTRACT: even though the schema is bare (returns: {}), bindpw is stripped
        regardless if the fake backend hands one back."""
        api = SimpleNamespace(_get=lambda path, params=None: {
            "profile": "my-ad", "server1": "ldap.example.com", "bindpw": "sentinel-leaked-bindpw",
        })
        result = ldap_profile_config_get(api, "my-ad")
        assert "bindpw" not in result
        assert result["profile"] == "my-ad"

    def test_rejects_invalid_profile(self):
        api = _api()
        with pytest.raises(ProximoError):
            ldap_profile_config_get(api, "bad/profile")


class TestLdapProfileCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        ldap_profile_create(api, "my-ad", "ldap.example.com")
        assert api.seen["path"] == "/config/ldap"
        assert api.seen["method"] == "POST"

    def test_required_fields_in_body(self):
        api = _api()
        ldap_profile_create(api, "my-ad", "ldap.example.com")
        assert api.seen["data"] == {"profile": "my-ad", "server1": "ldap.example.com"}

    def test_bindpw_forwarded_raw_on_the_wire(self):
        """The mutation must actually work — bindpw IS sent to PMG (never-in-ledger is a
        ledger/Plan-surface concern, not a wire-forwarding one)."""
        api = _api()
        ldap_profile_create(api, "my-ad", "ldap.example.com", bindpw="sentinel-bindpw")
        assert api.seen["data"]["bindpw"] == "sentinel-bindpw"

    def test_optional_fields_omitted_when_none(self):
        api = _api()
        ldap_profile_create(api, "my-ad", "ldap.example.com")
        assert "mode" not in api.seen["data"]
        assert "bindpw" not in api.seen["data"]

    def test_optional_fields_included_when_given(self):
        api = _api()
        ldap_profile_create(
            api, "my-ad", "ldap.example.com", mode="ldaps", port=636, verify=True, disable=False,
        )
        assert api.seen["data"]["mode"] == "ldaps"
        assert api.seen["data"]["port"] == 636
        assert api.seen["data"]["verify"] is True
        assert api.seen["data"]["disable"] is False

    def test_rejects_invalid_mode(self):
        api = _api()
        with pytest.raises(ProximoError):
            ldap_profile_create(api, "my-ad", "ldap.example.com", mode="bogus")


class TestLdapProfileDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        ldap_profile_delete(api, "my-ad")
        assert api.seen["path"] == "/config/ldap/my-ad"
        assert api.seen["method"] == "DELETE"


class TestLdapProfileConfigUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        ldap_profile_config_update(api, "my-ad", comment="updated")
        assert api.seen["path"] == "/config/ldap/my-ad/config"
        assert api.seen["method"] == "PUT"

    def test_requires_at_least_one_field(self):
        api = _api()
        with pytest.raises(ProximoError):
            ldap_profile_config_update(api, "my-ad")

    def test_delete_alone_satisfies_the_guard(self):
        api = _api()
        ldap_profile_config_update(api, "my-ad", delete="comment")
        assert api.seen["data"]["delete"] == "comment"

    def test_bindpw_forwarded_raw_on_the_wire(self):
        api = _api()
        ldap_profile_config_update(api, "my-ad", bindpw="sentinel-bindpw")
        assert api.seen["data"]["bindpw"] == "sentinel-bindpw"

    def test_digest_forwarded_when_given(self):
        api = _api()
        ldap_profile_config_update(api, "my-ad", comment="x", digest="abc123")
        assert api.seen["data"]["digest"] == "abc123"

    def test_digest_omitted_when_none(self):
        api = _api()
        ldap_profile_config_update(api, "my-ad", comment="x")
        assert "digest" not in api.seen["data"]

    def test_rejects_invalid_port(self):
        api = _api()
        with pytest.raises(ProximoError):
            ldap_profile_config_update(api, "my-ad", port=99999)


class TestLdapProfileSync:
    def test_uses_correct_path_and_method(self):
        api = _api()
        ldap_profile_sync(api, "my-ad")
        assert api.seen["path"] == "/config/ldap/my-ad/sync"
        assert api.seen["method"] == "POST"

    def test_sends_empty_body(self):
        api = _api()
        ldap_profile_sync(api, "my-ad")
        assert api.seen["data"] == {}


class TestLdapUsersList:
    def test_uses_correct_path(self):
        api = _api()
        ldap_users_list(api, "my-ad")
        assert api.seen["path"] == "/config/ldap/my-ad/users"


class TestLdapUserEmailsGet:
    def test_uses_correct_path(self):
        api = _api()
        ldap_user_emails_get(api, "my-ad", "user@example.com")
        assert api.seen["path"] == "/config/ldap/my-ad/users/user@example.com"

    def test_rejects_invalid_email(self):
        api = _api()
        with pytest.raises(ProximoError):
            ldap_user_emails_get(api, "my-ad", "not-an-email")


class TestLdapGroupsList:
    def test_uses_correct_path(self):
        api = _api()
        ldap_groups_list(api, "my-ad")
        assert api.seen["path"] == "/config/ldap/my-ad/groups"


class TestLdapGroupMembersGet:
    def test_uses_correct_path(self):
        api = _api()
        ldap_group_members_get(api, "my-ad", 42)
        assert api.seen["path"] == "/config/ldap/my-ad/groups/42"

    def test_accepts_string_gid(self):
        api = _api()
        ldap_group_members_get(api, "my-ad", "42")
        assert api.seen["path"] == "/config/ldap/my-ad/groups/42"


# ---------------------------------------------------------------------------
# fetchmail backend functions
# ---------------------------------------------------------------------------

class TestFetchmailList:
    def test_uses_correct_path(self):
        api = _api()
        fetchmail_list(api)
        assert api.seen["path"] == "/config/fetchmail"

    def test_strips_pass_mandatorily(self):
        """THE SECRET CONTRACT: pass is CONFIRMED echoed on the live list schema — mandatory
        strip, not defensive."""
        api = SimpleNamespace(_get=lambda path, params=None: [
            {"id": "abc123", "server": "mail.example.com", "pass": "sentinel-leaked-pass"},
        ])
        result = fetchmail_list(api)
        assert len(result) == 1
        assert "pass" not in result[0]
        assert result[0]["id"] == "abc123"


class TestFetchmailGet:
    def test_uses_correct_path(self):
        api = _api()
        fetchmail_get(api, "abc123")
        assert api.seen["path"] == "/config/fetchmail/abc123"

    def test_strips_pass_mandatorily(self):
        api = SimpleNamespace(_get=lambda path, params=None: {
            "id": "abc123", "server": "mail.example.com", "pass": "sentinel-leaked-pass",
        })
        result = fetchmail_get(api, "abc123")
        assert "pass" not in result
        assert result["id"] == "abc123"

    def test_rejects_invalid_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            fetchmail_get(api, "has-a-dash")


class TestFetchmailCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        fetchmail_create(api, "mail.example.com", "alice", "sentinel-pass", "user@example.com", "pop3")
        assert api.seen["path"] == "/config/fetchmail"
        assert api.seen["method"] == "POST"

    def test_required_fields_in_body(self):
        api = _api()
        fetchmail_create(api, "mail.example.com", "alice", "sentinel-pass", "user@example.com", "pop3")
        assert api.seen["data"] == {
            "server": "mail.example.com", "user": "alice", "pass": "sentinel-pass",
            "target": "user@example.com", "protocol": "pop3",
        }

    def test_pass_forwarded_raw_on_the_wire(self):
        api = _api()
        fetchmail_create(api, "mail.example.com", "alice", "sentinel-pass", "user@example.com", "imap")
        assert api.seen["data"]["pass"] == "sentinel-pass"

    def test_optional_fields_included_when_given(self):
        api = _api()
        fetchmail_create(
            api, "mail.example.com", "alice", "sentinel-pass", "user@example.com", "pop3",
            enable=True, interval=5, keep=True, port=995, ssl=True,
        )
        assert api.seen["data"]["enable"] is True
        assert api.seen["data"]["interval"] == 5
        assert api.seen["data"]["keep"] is True
        assert api.seen["data"]["port"] == 995
        assert api.seen["data"]["ssl"] is True

    def test_rejects_invalid_protocol(self):
        api = _api()
        with pytest.raises(ProximoError):
            fetchmail_create(api, "mail.example.com", "alice", "sentinel-pass", "user@example.com", "smtp")

    def test_rejects_invalid_target(self):
        api = _api()
        with pytest.raises(ProximoError):
            fetchmail_create(api, "mail.example.com", "alice", "sentinel-pass", "not-an-email", "pop3")


class TestFetchmailUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        fetchmail_update(api, "abc123", server="mail2.example.com")
        assert api.seen["path"] == "/config/fetchmail/abc123"
        assert api.seen["method"] == "PUT"

    def test_requires_at_least_one_field(self):
        api = _api()
        with pytest.raises(ProximoError):
            fetchmail_update(api, "abc123")

    def test_pass_forwarded_raw_on_the_wire(self):
        api = _api()
        fetchmail_update(api, "abc123", password="sentinel-newpass")
        assert api.seen["data"]["pass"] == "sentinel-newpass"

    def test_rejects_invalid_protocol(self):
        api = _api()
        with pytest.raises(ProximoError):
            fetchmail_update(api, "abc123", protocol="smtp")


class TestFetchmailDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        fetchmail_delete(api, "abc123")
        assert api.seen["path"] == "/config/fetchmail/abc123"
        assert api.seen["method"] == "DELETE"


# ---------------------------------------------------------------------------
# Plan factories — LDAP
# ---------------------------------------------------------------------------

class TestPlanLdapProfileCreate:
    def test_risk_is_medium(self):
        p = plan_ldap_profile_create("my-ad", "ldap.example.com")
        assert p.risk == RISK_MEDIUM

    def test_bindpw_never_appears_in_plan(self):
        p = plan_ldap_profile_create("my-ad", "ldap.example.com", bindpw="sentinel-bindpw")
        dumped = json.dumps(p.as_dict())
        assert "sentinel-bindpw" not in dumped
        assert "[redacted]" in dumped

    def test_non_secret_field_visible(self):
        p = plan_ldap_profile_create("my-ad", "ldap.example.com", comment="a directory")
        dumped = json.dumps(p.as_dict())
        assert "a directory" in dumped

    def test_no_capture_current_is_empty(self):
        p = plan_ldap_profile_create("my-ad", "ldap.example.com")
        assert p.current == {}


class TestPlanLdapProfileDelete:
    def test_risk_is_medium(self):
        api = SimpleNamespace(_get=lambda path, params=None: [])
        p = plan_ldap_profile_delete(api, "my-ad")
        assert p.risk == RISK_MEDIUM

    def test_captures_current_config_redacted(self):
        """ldap_profile_config_get already strips bindpw entirely at the read layer (mandatory/
        defensive) — the plan's own _redact_ldap_secrets is belt-and-suspenders for THIS call
        chain; the observable proof is that bindpw is simply absent, never echoed raw."""
        api = SimpleNamespace(_get=lambda path, params=None: {
            "profile": "my-ad", "server1": "ldap.example.com", "bindpw": "sentinel-bindpw",
        })
        p = plan_ldap_profile_delete(api, "my-ad")
        assert "bindpw" not in p.current
        assert p.current["server1"] == "ldap.example.com"
        dumped = json.dumps(p.as_dict())
        assert "sentinel-bindpw" not in dumped

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_ldap_profile_delete(api, "my-ad")
        assert p.complete is False
        assert any("prior value UNKNOWN" in line for line in p.blast_radius)


class TestPlanLdapProfileConfigUpdate:
    def test_risk_is_medium(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_ldap_profile_config_update(api, "my-ad", comment="updated")
        assert p.risk == RISK_MEDIUM

    def test_requires_at_least_one_field(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        with pytest.raises(ProximoError):
            plan_ldap_profile_config_update(api, "my-ad")

    def test_bindpw_never_appears_in_plan(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_ldap_profile_config_update(api, "my-ad", bindpw="sentinel-bindpw")
        dumped = json.dumps(p.as_dict())
        assert "sentinel-bindpw" not in dumped
        assert "[redacted]" in dumped

    def test_captured_current_redacted_even_when_secret_bearing(self):
        """Defense-in-depth: even if the read layer's own strip regressed, the plan factory
        redacts AGAIN on capture."""
        api = SimpleNamespace(_get=lambda path, params=None: {"bindpw": "sentinel-leaked-capture"})
        p = plan_ldap_profile_config_update(api, "my-ad", comment="updated")
        dumped = json.dumps(p.as_dict())
        assert "sentinel-leaked-capture" not in dumped

    def test_delete_disclosed_in_change_text(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_ldap_profile_config_update(api, "my-ad", delete="comment")
        assert "-comment" in p.change


class TestPlanLdapProfileSync:
    def test_risk_is_medium(self):
        p = plan_ldap_profile_sync("my-ad")
        assert p.risk == RISK_MEDIUM

    def test_no_capture_current_is_empty(self):
        p = plan_ldap_profile_sync("my-ad")
        assert p.current == {}

    def test_profile_named_in_change(self):
        p = plan_ldap_profile_sync("my-ad")
        assert "my-ad" in p.change


# ---------------------------------------------------------------------------
# Plan factories — fetchmail
# ---------------------------------------------------------------------------

class TestPlanFetchmailCreate:
    def test_risk_is_medium(self):
        p = plan_fetchmail_create("mail.example.com", "alice", "sentinel-pass", "user@example.com", "pop3")
        assert p.risk == RISK_MEDIUM

    def test_pass_never_appears_in_plan(self):
        p = plan_fetchmail_create("mail.example.com", "alice", "sentinel-pass", "user@example.com", "pop3")
        dumped = json.dumps(p.as_dict())
        assert "sentinel-pass" not in dumped
        assert "[redacted]" in dumped

    def test_non_secret_fields_visible(self):
        p = plan_fetchmail_create("mail.example.com", "alice", "sentinel-pass", "user@example.com", "pop3")
        dumped = json.dumps(p.as_dict())
        assert "mail.example.com" in dumped
        assert "alice" in dumped
        assert "user@example.com" in dumped

    def test_no_capture_current_is_empty(self):
        p = plan_fetchmail_create("mail.example.com", "alice", "sentinel-pass", "user@example.com", "pop3")
        assert p.current == {}


class TestPlanFetchmailUpdate:
    def test_risk_is_medium(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_fetchmail_update(api, "abc123", server="mail2.example.com")
        assert p.risk == RISK_MEDIUM

    def test_requires_at_least_one_field(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        with pytest.raises(ProximoError):
            plan_fetchmail_update(api, "abc123")

    def test_pass_never_appears_in_plan(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_fetchmail_update(api, "abc123", password="sentinel-newpass")
        dumped = json.dumps(p.as_dict())
        assert "sentinel-newpass" not in dumped
        assert "[redacted]" in dumped

    def test_captured_current_redacted_even_when_secret_bearing(self):
        api = SimpleNamespace(_get=lambda path, params=None: {"pass": "sentinel-leaked-capture"})
        p = plan_fetchmail_update(api, "abc123", server="mail2.example.com")
        dumped = json.dumps(p.as_dict())
        assert "sentinel-leaked-capture" not in dumped

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_fetchmail_update(api, "abc123", server="mail2.example.com")
        assert p.complete is False


class TestPlanFetchmailDelete:
    def test_risk_is_medium(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_fetchmail_delete(api, "abc123")
        assert p.risk == RISK_MEDIUM

    def test_captures_current_config_redacted(self):
        """fetchmail_get already strips pass entirely at the read layer (MANDATORY, confirmed
        echoed) — the plan's own _redact_fetchmail_secrets is belt-and-suspenders for THIS call
        chain; the observable proof is that pass is simply absent, never echoed raw."""
        api = SimpleNamespace(_get=lambda path, params=None: {
            "id": "abc123", "server": "mail.example.com", "pass": "sentinel-bindpw",
        })
        p = plan_fetchmail_delete(api, "abc123")
        assert "pass" not in p.current
        assert p.current["server"] == "mail.example.com"
        dumped = json.dumps(p.as_dict())
        assert "sentinel-bindpw" not in dumped

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_fetchmail_delete(api, "abc123")
        assert p.complete is False


# ===========================================================================
# Wave 9e: DKIM + customscores
# ===========================================================================

class TestCheckCustomscoreName:
    def test_accepts_valid(self):
        assert _check_customscore_name("MY_RULE-1.x") == "MY_RULE-1.x"

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_customscore_name("a/b")

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_customscore_name("")

    def test_rejects_space(self):
        with pytest.raises(ProximoError):
            _check_customscore_name("has space")

    def test_rejects_trailing_newline(self):
        with pytest.raises(ProximoError):
            _check_customscore_name("RULE\n")


class TestCheckCustomscoresDigest:
    def test_none_passes_through(self):
        assert _check_customscores_digest(None) is None

    def test_accepts_reasonable_digest(self):
        assert _check_customscores_digest("abc123") == "abc123"

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_customscores_digest("a" * 65)


class TestCheckCustomscoreScore:
    def test_accepts_int(self):
        assert _check_customscore_score(5) == 5.0

    def test_accepts_float(self):
        assert _check_customscore_score(-2.5) == -2.5

    def test_accepts_numeric_string(self):
        assert _check_customscore_score("3.2") == 3.2

    def test_rejects_non_numeric(self):
        with pytest.raises(ProximoError):
            _check_customscore_score("not-a-number")


class TestCheckDkimKeysize:
    def test_accepts_minimum(self):
        assert _check_dkim_keysize(1024) == 1024

    def test_accepts_larger(self):
        assert _check_dkim_keysize(2048) == 2048

    def test_rejects_below_minimum(self):
        with pytest.raises(ProximoError):
            _check_dkim_keysize(1023)

    def test_rejects_non_integer(self):
        with pytest.raises(ProximoError):
            _check_dkim_keysize("not-a-number")


# ---------------------------------------------------------------------------
# DKIM backend functions
# ---------------------------------------------------------------------------

class TestDkimDomainsList:
    def test_uses_correct_path(self):
        api = _api()
        dkim_domains_list(api)
        assert api.seen["path"] == "/config/dkim/domains"
        assert api.seen["method"] == "GET"


class TestDkimDomainGet:
    def test_uses_correct_path(self):
        api = _api()
        dkim_domain_get(api, "example.com")
        assert api.seen["path"] == "/config/dkim/domains/example.com"

    def test_rejects_invalid_domain(self):
        api = _api()
        with pytest.raises(ProximoError):
            dkim_domain_get(api, "bad/domain")


class TestDkimDomainCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        dkim_domain_create(api, "example.com")
        assert api.seen["path"] == "/config/dkim/domains"
        assert api.seen["method"] == "POST"

    def test_required_field_in_body(self):
        api = _api()
        dkim_domain_create(api, "example.com")
        assert api.seen["data"] == {"domain": "example.com"}

    def test_comment_included_when_given(self):
        api = _api()
        dkim_domain_create(api, "example.com", comment="primary")
        assert api.seen["data"]["comment"] == "primary"

    def test_comment_omitted_when_none(self):
        api = _api()
        dkim_domain_create(api, "example.com")
        assert "comment" not in api.seen["data"]


class TestDkimDomainUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        dkim_domain_update(api, "example.com", "updated")
        assert api.seen["path"] == "/config/dkim/domains/example.com"
        assert api.seen["method"] == "PUT"

    def test_domain_not_resent_in_body(self):
        api = _api()
        dkim_domain_update(api, "example.com", "updated")
        assert api.seen["data"] == {"comment": "updated"}


class TestDkimDomainDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        dkim_domain_delete(api, "example.com")
        assert api.seen["path"] == "/config/dkim/domains/example.com"
        assert api.seen["method"] == "DELETE"


class TestDkimSelectorGet:
    def test_uses_correct_path(self):
        api = _api()
        dkim_selector_get(api)
        assert api.seen["path"] == "/config/dkim/selector"
        assert api.seen["method"] == "GET"

    def test_no_private_key_field_invented(self):
        """THE NON-SECRET CONTRACT: the fake backend hands back exactly the schema-typed fields
        — no private key field exists anywhere in this shape, and this function does not
        strip/invent one (there is nothing to strip: fact #1)."""
        api = SimpleNamespace(_get=lambda path, params=None: {
            "keysize": 2048, "record": "v=DKIM1;...", "selector": "mail",
        })
        result = dkim_selector_get(api)
        assert result == {"keysize": 2048, "record": "v=DKIM1;...", "selector": "mail"}


class TestDkimSelectorsList:
    def test_uses_correct_path(self):
        api = _api()
        dkim_selectors_list(api)
        assert api.seen["path"] == "/config/dkim/selectors"


class TestDkimSelectorGenerate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        dkim_selector_generate(api, "mail", 2048)
        assert api.seen["path"] == "/config/dkim/selector"
        assert api.seen["method"] == "POST"

    def test_required_fields_in_body(self):
        api = _api()
        dkim_selector_generate(api, "mail", 2048)
        assert api.seen["data"] == {"selector": "mail", "keysize": 2048}

    def test_force_included_when_given(self):
        api = _api()
        dkim_selector_generate(api, "mail", 2048, force=True)
        assert api.seen["data"]["force"] is True

    def test_force_omitted_when_none(self):
        api = _api()
        dkim_selector_generate(api, "mail", 2048)
        assert "force" not in api.seen["data"]

    def test_rejects_keysize_below_minimum(self):
        api = _api()
        with pytest.raises(ProximoError):
            dkim_selector_generate(api, "mail", 512)


# ---------------------------------------------------------------------------
# customscores backend functions
# ---------------------------------------------------------------------------

class TestCustomscoresList:
    def test_uses_correct_path(self):
        api = _api()
        customscores_list(api)
        assert api.seen["path"] == "/config/customscores"
        assert api.seen["method"] == "GET"


class TestCustomscoresGet:
    def test_uses_correct_path(self):
        api = _api()
        customscores_get(api, "MY_RULE")
        assert api.seen["path"] == "/config/customscores/MY_RULE"

    def test_rejects_invalid_name(self):
        api = _api()
        with pytest.raises(ProximoError):
            customscores_get(api, "bad name")


class TestCustomscoresCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        customscores_create(api, "MY_RULE", 3.0)
        assert api.seen["path"] == "/config/customscores"
        assert api.seen["method"] == "POST"

    def test_required_fields_in_body(self):
        api = _api()
        customscores_create(api, "MY_RULE", 3.0)
        assert api.seen["data"] == {"name": "MY_RULE", "score": 3.0}

    def test_optional_fields_included_when_given(self):
        api = _api()
        customscores_create(api, "MY_RULE", 3.0, comment="a rule", digest="abc123")
        assert api.seen["data"]["comment"] == "a rule"
        assert api.seen["data"]["digest"] == "abc123"

    def test_optional_fields_omitted_when_none(self):
        api = _api()
        customscores_create(api, "MY_RULE", 3.0)
        assert "comment" not in api.seen["data"]
        assert "digest" not in api.seen["data"]

    def test_rejects_invalid_name(self):
        api = _api()
        with pytest.raises(ProximoError):
            customscores_create(api, "bad name", 3.0)

    def test_rejects_non_numeric_score(self):
        api = _api()
        with pytest.raises(ProximoError):
            customscores_create(api, "MY_RULE", "not-a-number")


class TestCustomscoresUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        customscores_update(api, "MY_RULE", 4.0)
        assert api.seen["path"] == "/config/customscores/MY_RULE"
        assert api.seen["method"] == "PUT"

    def test_name_not_resent_in_body(self):
        api = _api()
        customscores_update(api, "MY_RULE", 4.0)
        assert api.seen["data"] == {"score": 4.0}

    def test_digest_forwarded_when_given(self):
        api = _api()
        customscores_update(api, "MY_RULE", 4.0, digest="abc123")
        assert api.seen["data"]["digest"] == "abc123"

    def test_digest_omitted_when_none(self):
        api = _api()
        customscores_update(api, "MY_RULE", 4.0)
        assert "digest" not in api.seen["data"]


class TestCustomscoresDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        customscores_delete(api, "MY_RULE")
        assert api.seen["path"] == "/config/customscores/MY_RULE"
        assert api.seen["method"] == "DELETE"

    def test_digest_forwarded_as_query_param(self):
        api = _api()
        customscores_delete(api, "MY_RULE", digest="abc123")
        assert api.seen["params"] == {"digest": "abc123"}

    def test_no_params_when_digest_none(self):
        api = _api()
        customscores_delete(api, "MY_RULE")
        assert api.seen["params"] == {}


class TestCustomscoresRevertAll:
    def test_uses_correct_path_and_method(self):
        api = _api()
        customscores_revert_all(api)
        assert api.seen["path"] == "/config/customscores"
        assert api.seen["method"] == "DELETE"

    def test_sends_no_params(self):
        api = _api()
        customscores_revert_all(api)
        assert api.seen["params"] == {}


class TestCustomscoresApply:
    def test_uses_correct_path_and_method(self):
        api = _api()
        customscores_apply(api)
        assert api.seen["path"] == "/config/customscores"
        assert api.seen["method"] == "PUT"

    def test_empty_body_by_default(self):
        api = _api()
        customscores_apply(api)
        assert api.seen["data"] == {}

    def test_digest_and_restart_daemon_forwarded(self):
        api = _api()
        customscores_apply(api, digest="abc123", restart_daemon=True)
        assert api.seen["data"] == {"digest": "abc123", "restart-daemon": True}


# ---------------------------------------------------------------------------
# Plan factories — DKIM
# ---------------------------------------------------------------------------

class TestPlanDkimDomainCreate:
    def test_risk_is_low(self):
        p = plan_dkim_domain_create("example.com")
        assert p.risk == RISK_LOW

    def test_no_capture_current_is_empty(self):
        p = plan_dkim_domain_create("example.com")
        assert p.current == {}

    def test_domain_named_in_change(self):
        p = plan_dkim_domain_create("example.com")
        assert "example.com" in p.change


class TestPlanDkimDomainUpdate:
    def test_risk_is_low(self):
        p = plan_dkim_domain_update("example.com", "updated")
        assert p.risk == RISK_LOW

    def test_no_capture_current_is_empty(self):
        p = plan_dkim_domain_update("example.com", "updated")
        assert p.current == {}


class TestPlanDkimDomainDelete:
    def test_risk_is_medium(self):
        p = plan_dkim_domain_delete("example.com")
        assert p.risk == RISK_MEDIUM

    def test_blast_radius_states_signing_stops(self):
        p = plan_dkim_domain_delete("example.com")
        joined = " ".join(p.blast_radius).lower()
        assert "no longer dkim-signed" in joined


class TestPlanDkimSelectorGenerate:
    def _api(self, current=None):
        current = {} if current is None else current
        return SimpleNamespace(_get=lambda path, params=None: current)

    def test_risk_is_medium(self):
        p = plan_dkim_selector_generate(self._api(), "mail", 2048)
        assert p.risk == RISK_MEDIUM

    def test_captures_current_selector(self):
        api = self._api({"selector": "mail", "keysize": 2048, "record": "v=DKIM1..."})
        p = plan_dkim_selector_generate(api, "mail", 2048)
        assert p.current["selector"] == "mail"

    def test_blast_radius_states_upstream_warning(self):
        p = plan_dkim_selector_generate(self._api(), "mail", 2048)
        joined = " ".join(p.blast_radius).lower()
        assert "all future mail will be signed with the new key" in joined

    def test_blast_radius_states_rotation_impact_on_capture_success(self):
        api = self._api({"selector": "mail", "keysize": 2048, "record": "v=DKIM1..."})
        p = plan_dkim_selector_generate(api, "mail", 2048)
        joined = " ".join(p.blast_radius).lower()
        assert "rotates the signing selector" in joined
        assert "previous selector" in joined
        assert "validation" in joined
        assert p.complete is True

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_dkim_selector_generate(api, "mail", 2048)
        joined = " ".join(p.blast_radius).lower()
        assert "current selector unavailable" in joined
        assert p.complete is False

    def test_rejects_keysize_below_minimum(self):
        with pytest.raises(ProximoError):
            plan_dkim_selector_generate(self._api(), "mail", 512)


# ---------------------------------------------------------------------------
# Plan factories — customscores
# ---------------------------------------------------------------------------

class TestPlanCustomscoresCreate:
    def test_risk_is_low(self):
        p = plan_customscores_create("MY_RULE", 3.0)
        assert p.risk == RISK_LOW

    def test_no_capture_current_is_empty(self):
        p = plan_customscores_create("MY_RULE", 3.0)
        assert p.current == {}

    def test_positive_score_states_toward_spam(self):
        p = plan_customscores_create("MY_RULE", 3.0)
        joined = " ".join(p.blast_radius).lower()
        assert "more spam-like" in joined

    def test_negative_score_states_toward_ham(self):
        p = plan_customscores_create("MY_RULE", -3.0)
        joined = " ".join(p.blast_radius).lower()
        assert "less spam-like" in joined

    def test_zero_score_states_neutral(self):
        p = plan_customscores_create("MY_RULE", 0)
        joined = " ".join(p.blast_radius).lower()
        assert "neutral" in joined


class TestPlanCustomscoresUpdate:
    def test_risk_is_medium(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_customscores_update(api, "MY_RULE", 4.0)
        assert p.risk == RISK_MEDIUM

    def test_raising_score_states_toward_spam(self):
        api = SimpleNamespace(_get=lambda path, params=None: {"name": "MY_RULE", "score": 2.0})
        p = plan_customscores_update(api, "MY_RULE", 5.0)
        joined = " ".join(p.blast_radius).lower()
        assert "raises" in joined
        assert "toward spam" in joined

    def test_lowering_score_states_toward_ham(self):
        api = SimpleNamespace(_get=lambda path, params=None: {"name": "MY_RULE", "score": 5.0})
        p = plan_customscores_update(api, "MY_RULE", 2.0)
        joined = " ".join(p.blast_radius).lower()
        assert "lowers" in joined
        assert "toward ham" in joined

    def test_captures_current_score(self):
        api = SimpleNamespace(_get=lambda path, params=None: {"name": "MY_RULE", "score": 2.0})
        p = plan_customscores_update(api, "MY_RULE", 5.0)
        assert p.current["score"] == 2.0

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_customscores_update(api, "MY_RULE", 5.0)
        assert p.complete is False
        joined = " ".join(p.blast_radius).lower()
        assert "prior value unknown" in joined


class TestPlanCustomscoresDelete:
    def test_risk_is_medium(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_customscores_delete(api, "MY_RULE")
        assert p.risk == RISK_MEDIUM

    def test_captures_current_score(self):
        api = SimpleNamespace(_get=lambda path, params=None: {"name": "MY_RULE", "score": 2.0})
        p = plan_customscores_delete(api, "MY_RULE")
        assert p.current["score"] == 2.0

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_customscores_delete(api, "MY_RULE")
        assert p.complete is False


class TestPlanCustomscoresRevertAll:
    def test_risk_is_medium(self):
        p = plan_customscores_revert_all()
        assert p.risk == RISK_MEDIUM

    def test_no_capture_current_is_empty(self):
        p = plan_customscores_revert_all()
        assert p.current == {}

    def test_blast_radius_states_all_rules(self):
        p = plan_customscores_revert_all()
        joined = " ".join(p.blast_radius).lower()
        assert "every custom score" in joined


class TestPlanCustomscoresApply:
    def test_risk_is_medium(self):
        p = plan_customscores_apply()
        assert p.risk == RISK_MEDIUM

    def test_restart_daemon_true_discloses_interruption(self):
        p = plan_customscores_apply(restart_daemon=True)
        joined = " ".join(p.blast_radius).lower()
        assert "restart" in joined

    def test_restart_daemon_none_discloses_necessary_warning(self):
        p = plan_customscores_apply()
        joined = " ".join(p.blast_radius).lower()
        assert "necessary for the changes to work" in joined


# ===========================================================================
# Wave 9f: PBS remote config + node-side PBS backup jobs
# ===========================================================================

class TestCheckPbsRemoteId:
    def test_accepts_valid(self):
        assert _check_pbs_remote_id("my-pbs_1") == "my-pbs_1"

    def test_rejects_leading_hyphen(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_id("-bad")

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_id("a/b")

    def test_rejects_trailing_newline(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_id("remote\n")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_id("a" * 65)


class TestCheckPbsDatastore:
    def test_accepts_valid(self):
        assert _check_pbs_datastore("ds1") == "ds1"

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_pbs_datastore("a/b")

    def test_rejects_leading_hyphen(self):
        with pytest.raises(ProximoError):
            _check_pbs_datastore("-bad")


class TestCheckPbsRemoteServer:
    def test_accepts_reasonable_address(self):
        assert _check_pbs_remote_server("pbs.example.com") == "pbs.example.com"

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_server("a" * 257)


class TestCheckPbsRemoteUsername:
    def test_accepts_valid(self):
        assert _check_pbs_remote_username("user@pbs") == "user@pbs"

    def test_rejects_missing_at(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_username("nouser")

    def test_rejects_too_short(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_username("a@")

    def test_rejects_whitespace(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_username("user @pbs")


class TestCheckPbsRemoteFingerprint:
    def test_accepts_valid(self):
        fp = ":".join(["ab"] * 32)
        assert _check_pbs_remote_fingerprint(fp) == fp

    def test_rejects_too_short(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_fingerprint("AA:BB:CC")

    def test_rejects_non_hex(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_fingerprint(":".join(["zz"] * 32))


class TestCheckPbsRemotePort:
    def test_accepts_boundary_values(self):
        assert _check_pbs_remote_port(1) == 1
        assert _check_pbs_remote_port(65535) == 65535

    def test_rejects_zero(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_port(0)

    def test_rejects_out_of_range(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_port(65536)

    def test_rejects_non_integer(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_port("not-a-port")


class TestCheckPbsRemoteNamespace:
    def test_accepts_empty_root(self):
        assert _check_pbs_remote_namespace("") == ""

    def test_accepts_single_level(self):
        assert _check_pbs_remote_namespace("tenant-a") == "tenant-a"

    def test_accepts_nested_levels(self):
        assert _check_pbs_remote_namespace("tenant-a/site-1") == "tenant-a/site-1"

    def test_accepts_max_depth_eight_levels(self):
        ns = "/".join(["a"] * 8)
        assert _check_pbs_remote_namespace(ns) == ns

    def test_rejects_too_many_levels(self):
        ns = "/".join(["a"] * 9)
        with pytest.raises(ProximoError):
            _check_pbs_remote_namespace(ns)

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_namespace("a" * 257)

    def test_accepts_boundary_length(self):
        ns = "a" * 256
        assert _check_pbs_remote_namespace(ns) == ns

    def test_rejects_leading_slash(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_namespace("/tenant-a")

    def test_accepts_trailing_slash_per_schema_pattern(self):
        """The schema's own pattern's final segment is OPTIONAL after the repeated 'seg/' group,
        so a trailing slash is technically schema-legal (e.g. 'a/' = one 'seg/' repetition + an
        empty optional final segment) — a real quirk of the given pattern, not invented leniency;
        verified directly against the raw regex, not assumed."""
        assert _check_pbs_remote_namespace("tenant-a/") == "tenant-a/"

    def test_rejects_double_slash(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_namespace("tenant-a//site-1")

    def test_rejects_space(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_namespace("tenant a")

    def test_rejects_segment_starting_with_hyphen(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_namespace("-tenant")


class TestCheckPbsKeepCount:
    def test_accepts_zero(self):
        assert _check_pbs_keep_count(0, "keep-last") == 0

    def test_accepts_positive(self):
        assert _check_pbs_keep_count(5, "keep-last") == 5

    def test_rejects_negative(self):
        with pytest.raises(ProximoError):
            _check_pbs_keep_count(-1, "keep-last")

    def test_rejects_non_integer(self):
        with pytest.raises(ProximoError):
            _check_pbs_keep_count("nope", "keep-last")


class TestCheckPbsRemoteDigest:
    def test_none_passes_through(self):
        assert _check_pbs_remote_digest(None) is None

    def test_accepts_reasonable_digest(self):
        assert _check_pbs_remote_digest("abc123") == "abc123"

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_pbs_remote_digest("a" * 65)


class TestCheckPbsSnapshotBackupId:
    def test_accepts_hostname(self):
        assert _check_pbs_snapshot_backup_id("myhost") == "myhost"

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_pbs_snapshot_backup_id("")

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_pbs_snapshot_backup_id("a/b")

    def test_rejects_dotdot(self):
        with pytest.raises(ProximoError):
            _check_pbs_snapshot_backup_id("..")

    def test_rejects_control_chars(self):
        with pytest.raises(ProximoError):
            _check_pbs_snapshot_backup_id("bad\nid")


class TestCheckPbsSnapshotBackupTime:
    def test_accepts_rfc3339_string(self):
        assert _check_pbs_snapshot_backup_time("2026-07-17T00:00:00Z") == "2026-07-17T00:00:00Z"

    def test_accepts_int_coerced_to_string(self):
        """This chunk's schema types backup-time a STRING, unlike pbs.py's own epoch-int
        convention — an int is still accepted (coerced via str()) since PMG's own wire format is
        forgiving, but the validated value returned is the string form."""
        assert _check_pbs_snapshot_backup_time(1700000000) == "1700000000"

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_pbs_snapshot_backup_time("")

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_pbs_snapshot_backup_time("a/b")

    def test_rejects_control_chars(self):
        with pytest.raises(ProximoError):
            _check_pbs_snapshot_backup_time("bad\ntime")


class TestCheckPbsTimerSchedule:
    def test_accepts_daily(self):
        assert _check_pbs_timer_schedule("daily") == "daily"

    def test_accepts_oncalendar_syntax(self):
        assert _check_pbs_timer_schedule("Mon *-*-* 02:00:00") == "Mon *-*-* 02:00:00"

    def test_rejects_bad_chars(self):
        with pytest.raises(ProximoError):
            _check_pbs_timer_schedule("bad;schedule")


class TestCheckPbsTimerDelay:
    def test_accepts_valid(self):
        assert _check_pbs_timer_delay("5min") == "5min"

    def test_rejects_bad_chars(self):
        with pytest.raises(ProximoError):
            _check_pbs_timer_delay("5;min")


# ---------------------------------------------------------------------------
# Backend functions — PBS remote config
# ---------------------------------------------------------------------------

class TestPbsRemoteList:
    def test_uses_correct_path(self):
        api = _api()
        pbs_remote_list(api)
        assert api.seen["path"] == "/config/pbs"

    def test_strips_secrets_mandatorily(self):
        """THE SECRET CONTRACT: password/encryption-key CONFIRMED echoed on the live list
        schema — mandatory strip, not defensive."""
        api = SimpleNamespace(_get=lambda path, params=None: [
            {"remote": "r1", "server": "pbs.example.com",
             "password": "sentinel-leaked-password", "encryption-key": "sentinel-leaked-enckey"},
        ])
        result = pbs_remote_list(api)
        assert len(result) == 1
        assert "password" not in result[0]
        assert "encryption-key" not in result[0]
        assert result[0]["remote"] == "r1"

    def test_fingerprint_and_master_pubkey_pass_through(self):
        """fingerprint/master-pubkey are PUBLIC — never stripped."""
        api = SimpleNamespace(_get=lambda path, params=None: [
            {"remote": "r1", "fingerprint": "AA:BB", "master-pubkey": "sentinel-pubkey-pem"},
        ])
        result = pbs_remote_list(api)
        assert result[0]["fingerprint"] == "AA:BB"
        assert result[0]["master-pubkey"] == "sentinel-pubkey-pem"


class TestPbsRemoteGet:
    def test_uses_correct_path(self):
        api = _api()
        pbs_remote_get(api, "r1")
        assert api.seen["path"] == "/config/pbs/r1"

    def test_strips_secrets_defensively(self):
        """The single-item schema is bare (returns: {}) — defensive strip regardless."""
        api = SimpleNamespace(_get=lambda path, params=None: {
            "remote": "r1", "password": "sentinel-leaked-password",
            "encryption-key": "sentinel-leaked-enckey",
        })
        result = pbs_remote_get(api, "r1")
        assert "password" not in result
        assert "encryption-key" not in result
        assert result["remote"] == "r1"

    def test_rejects_invalid_remote(self):
        api = _api()
        with pytest.raises(ProximoError):
            pbs_remote_get(api, "bad/remote")


class TestPbsRemoteCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        pbs_remote_create(api, "r1", "ds1", "pbs.example.com")
        assert api.seen["path"] == "/config/pbs"
        assert api.seen["method"] == "POST"

    def test_required_fields_in_body(self):
        api = _api()
        pbs_remote_create(api, "r1", "ds1", "pbs.example.com")
        assert api.seen["data"] == {"remote": "r1", "datastore": "ds1", "server": "pbs.example.com"}

    def test_password_forwarded_raw_on_the_wire(self):
        api = _api()
        pbs_remote_create(api, "r1", "ds1", "pbs.example.com", password="sentinel-pw")
        assert api.seen["data"]["password"] == "sentinel-pw"

    def test_encryption_key_forwarded_raw_on_the_wire(self):
        api = _api()
        pbs_remote_create(api, "r1", "ds1", "pbs.example.com", encryption_key="autogen")
        assert api.seen["data"]["encryption-key"] == "autogen"

    def test_optional_fields_included_when_given(self):
        api = _api()
        pbs_remote_create(
            api, "r1", "ds1", "pbs.example.com", port=8008, username="user@pbs",
            fingerprint=":".join(["ab"] * 32), keep_daily=7, notify="error", disable=False,
            namespace="tenant-a",
        )
        assert api.seen["data"]["port"] == 8008
        assert api.seen["data"]["username"] == "user@pbs"
        assert api.seen["data"]["fingerprint"] == ":".join(["ab"] * 32)
        assert api.seen["data"]["keep-daily"] == 7
        assert api.seen["data"]["notify"] == "error"
        assert api.seen["data"]["disable"] is False
        assert api.seen["data"]["namespace"] == "tenant-a"

    def test_optional_fields_omitted_when_none(self):
        api = _api()
        pbs_remote_create(api, "r1", "ds1", "pbs.example.com")
        assert "password" not in api.seen["data"]
        assert "port" not in api.seen["data"]
        assert "namespace" not in api.seen["data"]

    def test_rejects_invalid_notify(self):
        api = _api()
        with pytest.raises(ProximoError):
            pbs_remote_create(api, "r1", "ds1", "pbs.example.com", notify="sometimes")

    def test_rejects_invalid_namespace(self):
        api = _api()
        with pytest.raises(ProximoError):
            pbs_remote_create(api, "r1", "ds1", "pbs.example.com", namespace="/leading-slash")


class TestPbsRemoteUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        pbs_remote_update(api, "r1", server="pbs2.example.com")
        assert api.seen["path"] == "/config/pbs/r1"
        assert api.seen["method"] == "PUT"

    def test_requires_at_least_one_field(self):
        api = _api()
        with pytest.raises(ProximoError):
            pbs_remote_update(api, "r1")

    def test_password_forwarded_raw_on_the_wire(self):
        api = _api()
        pbs_remote_update(api, "r1", password="sentinel-newpw")
        assert api.seen["data"]["password"] == "sentinel-newpw"

    def test_encryption_key_forwarded_raw_on_the_wire(self):
        api = _api()
        pbs_remote_update(api, "r1", encryption_key="sentinel-enckey")
        assert api.seen["data"]["encryption-key"] == "sentinel-enckey"

    def test_delete_forwarded(self):
        api = _api()
        pbs_remote_update(api, "r1", delete="comment")
        assert api.seen["data"]["delete"] == "comment"

    def test_digest_forwarded(self):
        api = _api()
        pbs_remote_update(api, "r1", server="pbs2.example.com", digest="abc123")
        assert api.seen["data"]["digest"] == "abc123"

    def test_remote_not_resent_in_body(self):
        api = _api()
        pbs_remote_update(api, "r1", server="pbs2.example.com")
        assert "remote" not in api.seen["data"]

    def test_namespace_forwarded_raw_on_the_wire(self):
        api = _api()
        pbs_remote_update(api, "r1", namespace="tenant-a")
        assert api.seen["data"]["namespace"] == "tenant-a"

    def test_namespace_alone_satisfies_at_least_one_field(self):
        """namespace-only update must NOT raise the 'requires at least one field' error —
        partial-update semantics must treat namespace like any other optional field."""
        api = _api()
        pbs_remote_update(api, "r1", namespace="tenant-a")
        assert api.seen["data"] == {"namespace": "tenant-a"}

    def test_rejects_invalid_namespace(self):
        api = _api()
        with pytest.raises(ProximoError):
            pbs_remote_update(api, "r1", namespace="bad//ns")


class TestPbsRemoteDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        pbs_remote_delete(api, "r1")
        assert api.seen["path"] == "/config/pbs/r1"
        assert api.seen["method"] == "DELETE"


# ---------------------------------------------------------------------------
# Backend functions — node-side PBS backup jobs
# ---------------------------------------------------------------------------

class TestNodePbsJobsList:
    def test_uses_correct_path(self):
        api = _api()
        node_pbs_jobs_list(api, "pmg1")
        assert api.seen["path"] == "/nodes/pmg1/pbs"

    def test_strips_secrets_mandatorily(self):
        api = SimpleNamespace(_get=lambda path, params=None: [
            {"remote": "r1", "password": "sentinel-leaked-password",
             "encryption-key": "sentinel-leaked-enckey"},
        ])
        result = node_pbs_jobs_list(api, "pmg1")
        assert "password" not in result[0]
        assert "encryption-key" not in result[0]


class TestNodePbsSnapshotsList:
    def test_uses_correct_path(self):
        api = _api()
        node_pbs_snapshots_list(api, "pmg1", "r1")
        assert api.seen["path"] == "/nodes/pmg1/pbs/r1/snapshot"


class TestNodePbsSnapshotCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        node_pbs_snapshot_create(api, "pmg1", "r1")
        assert api.seen["path"] == "/nodes/pmg1/pbs/r1/snapshot"
        assert api.seen["method"] == "POST"

    def test_optional_fields_included_when_given(self):
        api = _api()
        node_pbs_snapshot_create(api, "pmg1", "r1", notify="always", statistic=False)
        assert api.seen["data"]["notify"] == "always"
        assert api.seen["data"]["statistic"] is False

    def test_optional_fields_omitted_when_none(self):
        api = _api()
        node_pbs_snapshot_create(api, "pmg1", "r1")
        assert api.seen["data"] == {}


class TestNodePbsSnapshotGet:
    def test_uses_correct_path(self):
        api = _api()
        node_pbs_snapshot_get(api, "pmg1", "r1", "myhost")
        assert api.seen["path"] == "/nodes/pmg1/pbs/r1/snapshot/myhost"

    def test_rejects_invalid_backup_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            node_pbs_snapshot_get(api, "pmg1", "r1", "../etc")


class TestNodePbsSnapshotForget:
    def test_uses_correct_path_and_method(self):
        api = _api()
        node_pbs_snapshot_forget(api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        assert api.seen["path"] == "/nodes/pmg1/pbs/r1/snapshot/myhost/2026-07-17T00:00:00Z"
        assert api.seen["method"] == "DELETE"


class TestNodePbsSnapshotRestore:
    def test_uses_correct_path_and_method(self):
        api = _api()
        node_pbs_snapshot_restore(api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        assert api.seen["path"] == "/nodes/pmg1/pbs/r1/snapshot/myhost/2026-07-17T00:00:00Z"
        assert api.seen["method"] == "POST"

    def test_sends_all_three_flags_explicitly(self):
        api = _api()
        node_pbs_snapshot_restore(api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        assert api.seen["data"] == {"config": False, "database": True, "statistic": False}

    def test_custom_flags_forwarded(self):
        api = _api()
        node_pbs_snapshot_restore(
            api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z",
            config=True, database=False, statistic=True,
        )
        assert api.seen["data"] == {"config": True, "database": False, "statistic": True}


class TestNodePbsSnapshotVerify:
    def test_uses_correct_path_and_method(self):
        api = _api()
        node_pbs_snapshot_verify(api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        assert api.seen["path"] == "/nodes/pmg1/pbs/r1/snapshot/myhost/2026-07-17T00:00:00Z/verify"
        assert api.seen["method"] == "POST"


class TestNodePbsTimerGet:
    def test_uses_correct_path(self):
        api = _api()
        node_pbs_timer_get(api, "pmg1", "r1")
        assert api.seen["path"] == "/nodes/pmg1/pbs/r1/timer"


class TestNodePbsTimerCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        node_pbs_timer_create(api, "pmg1", "r1")
        assert api.seen["path"] == "/nodes/pmg1/pbs/r1/timer"
        assert api.seen["method"] == "POST"

    def test_optional_fields_included_when_given(self):
        api = _api()
        node_pbs_timer_create(api, "pmg1", "r1", schedule="weekly", delay="10min")
        assert api.seen["data"]["schedule"] == "weekly"
        assert api.seen["data"]["delay"] == "10min"

    def test_optional_fields_omitted_when_none(self):
        api = _api()
        node_pbs_timer_create(api, "pmg1", "r1")
        assert api.seen["data"] == {}


class TestNodePbsTimerDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        node_pbs_timer_delete(api, "pmg1", "r1")
        assert api.seen["path"] == "/nodes/pmg1/pbs/r1/timer"
        assert api.seen["method"] == "DELETE"


# ---------------------------------------------------------------------------
# Plan factories — PBS remote config
# ---------------------------------------------------------------------------

class TestPlanPbsRemoteCreate:
    def test_risk_is_medium(self):
        p = plan_pbs_remote_create("r1", "ds1", "pbs.example.com")
        assert p.risk == RISK_MEDIUM

    def test_secrets_never_appear_in_plan(self):
        p = plan_pbs_remote_create(
            "r1", "ds1", "pbs.example.com",
            password="sentinel-pw", encryption_key="sentinel-enckey",
        )
        dumped = json.dumps(p.as_dict())
        assert "sentinel-pw" not in dumped
        assert "sentinel-enckey" not in dumped
        assert "[redacted]" in dumped

    def test_fingerprint_and_master_pubkey_visible(self):
        fp = ":".join(["ab"] * 32)
        p = plan_pbs_remote_create(
            "r1", "ds1", "pbs.example.com", fingerprint=fp, master_pubkey="sentinel-pubkey",
        )
        dumped = json.dumps(p.as_dict())
        assert fp in dumped
        assert "sentinel-pubkey" in dumped

    def test_autogen_encryption_key_discloses_capture_warning(self):
        p = plan_pbs_remote_create("r1", "ds1", "pbs.example.com", encryption_key="autogen")
        joined = " ".join(p.blast_radius).lower()
        assert "autogen" in joined
        assert "never" in joined

    def test_no_capture_current_is_empty(self):
        p = plan_pbs_remote_create("r1", "ds1", "pbs.example.com")
        assert p.current == {}

    def test_namespace_visible_not_redacted(self):
        """namespace is a plain identifier, not a secret — it must show as-is in the plan."""
        p = plan_pbs_remote_create("r1", "ds1", "pbs.example.com", namespace="tenant-a")
        dumped = json.dumps(p.as_dict())
        assert "tenant-a" in dumped


class TestPlanPbsRemoteUpdate:
    def test_risk_is_medium(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_pbs_remote_update(api, "r1", server="pbs2.example.com")
        assert p.risk == RISK_MEDIUM

    def test_requires_at_least_one_field(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        with pytest.raises(ProximoError):
            plan_pbs_remote_update(api, "r1")

    def test_secrets_never_appear_in_plan(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_pbs_remote_update(api, "r1", password="sentinel-newpw")
        dumped = json.dumps(p.as_dict())
        assert "sentinel-newpw" not in dumped
        assert "[redacted]" in dumped

    def test_captured_current_redacted_even_when_secret_bearing(self):
        api = SimpleNamespace(_get=lambda path, params=None: {
            "remote": "r1", "password": "sentinel-leaked-capture",
        })
        p = plan_pbs_remote_update(api, "r1", server="pbs2.example.com")
        dumped = json.dumps(p.as_dict())
        assert "sentinel-leaked-capture" not in dumped

    def test_delete_disclosed_in_change_text(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_pbs_remote_update(api, "r1", delete="comment")
        assert "-comment" in p.change

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_pbs_remote_update(api, "r1", server="pbs2.example.com")
        assert p.complete is False

    def test_namespace_visible_not_redacted(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_pbs_remote_update(api, "r1", namespace="tenant-a")
        dumped = json.dumps(p.as_dict())
        assert "tenant-a" in dumped


class TestPlanPbsRemoteDelete:
    def test_risk_is_medium(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_pbs_remote_delete(api, "r1")
        assert p.risk == RISK_MEDIUM

    def test_captures_current_config_redacted(self):
        api = SimpleNamespace(_get=lambda path, params=None: {
            "remote": "r1", "server": "pbs.example.com", "password": "sentinel-pw",
        })
        p = plan_pbs_remote_delete(api, "r1")
        assert "password" not in p.current
        assert p.current["server"] == "pbs.example.com"
        dumped = json.dumps(p.as_dict())
        assert "sentinel-pw" not in dumped

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_pbs_remote_delete(api, "r1")
        assert p.complete is False


# ---------------------------------------------------------------------------
# Plan factories — node-side PBS backup jobs
# ---------------------------------------------------------------------------

class TestPlanNodePbsSnapshotCreate:
    def test_risk_is_medium(self):
        p = plan_node_pbs_snapshot_create("pmg1", "r1")
        assert p.risk == RISK_MEDIUM

    def test_discloses_prune_side_effect(self):
        p = plan_node_pbs_snapshot_create("pmg1", "r1")
        joined = " ".join(p.blast_radius).lower()
        assert "prune" in joined

    def test_no_capture_current_is_empty(self):
        p = plan_node_pbs_snapshot_create("pmg1", "r1")
        assert p.current == {}


class TestPlanNodePbsSnapshotForget:
    def test_risk_is_high(self):
        p = plan_node_pbs_snapshot_forget("pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        assert p.risk == RISK_HIGH

    def test_discloses_permanent_deletion(self):
        p = plan_node_pbs_snapshot_forget("pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        joined = " ".join(p.blast_radius).lower()
        assert "permanently deletes" in joined


class TestPlanNodePbsSnapshotRestore:
    def test_risk_is_high(self):
        api = SimpleNamespace(_get=lambda path, params=None: [])
        p = plan_node_pbs_snapshot_restore(api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        assert p.risk == RISK_HIGH

    def test_states_no_undo_first(self):
        api = SimpleNamespace(_get=lambda path, params=None: [])
        p = plan_node_pbs_snapshot_restore(api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        assert "no undo" in p.blast_radius[0].lower()

    def test_captures_ruledb_counts_when_database_true(self):
        api = SimpleNamespace(_get=lambda path, params=None: [1, 2, 3])
        p = plan_node_pbs_snapshot_restore(
            api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z", database=True,
        )
        assert p.current["rules"] == 3

    def test_database_false_skips_ruledb_capture(self):
        api = SimpleNamespace(_get=lambda path, params=None: [1, 2, 3])
        p = plan_node_pbs_snapshot_restore(
            api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z", database=False,
        )
        assert p.current == {}
        joined = " ".join(p.blast_radius).lower()
        assert "left untouched" in joined

    def test_config_true_discloses_system_config_scope(self):
        api = SimpleNamespace(_get=lambda path, params=None: [])
        p = plan_node_pbs_snapshot_restore(
            api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z", config=True,
        )
        joined = " ".join(p.blast_radius).lower()
        assert "system configuration" in joined

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_node_pbs_snapshot_restore(api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        assert p.complete is False

    def test_states_target_not_found_when_snapshot_missing(self):
        """Mirrors plan_backup_restore's (9b) own existence pre-check, extended to the remote
        snapshot lookup (node_pbs_snapshot_get) — a missing target must be disclosed, not
        silently skipped (the Minor-1 fix: the docstring's 'mirrors ... exactly' claim now holds
        for the existence check too, not just the first blast_radius line)."""
        api = SimpleNamespace(_get=lambda path, params=None: [])
        p = plan_node_pbs_snapshot_restore(api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        joined = " ".join(p.blast_radius).lower()
        assert "not found" in joined

    def test_no_not_found_warning_when_snapshot_exists(self):
        def fake_get(path, params=None):
            if path == "/nodes/pmg1/pbs/r1/snapshot/myhost":
                return [{"backup-time": "2026-07-17T00:00:00Z"}]
            return []
        api = SimpleNamespace(_get=fake_get)
        p = plan_node_pbs_snapshot_restore(api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        joined = " ".join(p.blast_radius).lower()
        assert "not found" not in joined

    def test_existence_check_failure_alone_marks_incomplete(self):
        """Even when the ruledb capture succeeds, a failed existence check alone must degrade
        `complete` honestly — the two reads are independent, mirroring plan_backup_restore's own
        'best-effort, degrades honestly' existence-check discipline."""
        def fake_get(path, params=None):
            if path == "/nodes/pmg1/pbs/r1/snapshot/myhost":
                raise ProximoError("simulated read failure")
            return [1, 2, 3]
        api = SimpleNamespace(_get=fake_get)
        p = plan_node_pbs_snapshot_restore(api, "pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        assert p.complete is False
        assert p.current["rules"] == 3


class TestPlanNodePbsSnapshotVerify:
    def test_risk_is_low(self):
        p = plan_node_pbs_snapshot_verify("pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        assert p.risk == RISK_LOW

    def test_non_destructive_stated(self):
        p = plan_node_pbs_snapshot_verify("pmg1", "r1", "myhost", "2026-07-17T00:00:00Z")
        joined = " ".join(p.blast_radius).lower()
        assert "non-destructive" in joined


class TestPlanNodePbsTimerCreate:
    def test_risk_is_low(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_node_pbs_timer_create(api, "pmg1", "r1")
        assert p.risk == RISK_LOW

    def test_flags_existing_timer(self):
        api = SimpleNamespace(_get=lambda path, params=None: {"schedule": "daily"})
        p = plan_node_pbs_timer_create(api, "pmg1", "r1")
        joined = " ".join(p.blast_radius).lower()
        assert "already appears configured" in joined

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_node_pbs_timer_create(api, "pmg1", "r1")
        assert p.complete is False


class TestPlanNodePbsTimerDelete:
    def test_risk_is_low(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_node_pbs_timer_delete(api, "pmg1", "r1")
        assert p.risk == RISK_LOW

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_node_pbs_timer_delete(api, "pmg1", "r1")
        assert p.complete is False


# ---------------------------------------------------------------------------
# Wave 9g: ACME accounts/plugins + node cert order/renew/revoke + custom-cert upload
# ---------------------------------------------------------------------------

class TestCheckAcmeAccountName:
    def test_accepts_valid(self):
        assert _check_acme_account_name("default") == "default"
        assert _check_acme_account_name("my.account-1") == "my.account-1"

    def test_rejects_leading_dot(self):
        with pytest.raises(ProximoError):
            _check_acme_account_name(".bad")

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_acme_account_name("a/b")

    def test_rejects_trailing_newline(self):
        with pytest.raises(ProximoError):
            _check_acme_account_name("default\n")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_acme_account_name("a" * 257)


class TestCheckAcmePluginId:
    def test_accepts_valid(self):
        assert _check_acme_plugin_id("my_plugin.1") == "my_plugin.1"

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_acme_plugin_id("a/b")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_acme_plugin_id("a" * 65)


class TestCheckAcmeChallengeType:
    def test_accepts_dns(self):
        assert _check_acme_challenge_type("dns") == "dns"

    def test_accepts_standalone(self):
        assert _check_acme_challenge_type("standalone") == "standalone"

    def test_rejects_unknown(self):
        with pytest.raises(ProximoError):
            _check_acme_challenge_type("http-01")


class TestCheckAcmePluginApi:
    def test_accepts_valid(self):
        assert _check_acme_plugin_api("cf") == "cf"
        assert _check_acme_plugin_api("route53") == "route53"

    def test_rejects_uppercase(self):
        with pytest.raises(ProximoError):
            _check_acme_plugin_api("CF")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_acme_plugin_api("a" * 65)

    def test_rejects_whitespace(self):
        with pytest.raises(ProximoError):
            _check_acme_plugin_api("c f")


class TestCheckAcmeContact:
    def test_accepts_bare_email(self):
        assert _check_acme_contact("user@example.com") == "user@example.com"

    def test_accepts_mailto_prefix(self):
        assert _check_acme_contact("mailto:user@example.com") == "mailto:user@example.com"

    def test_accepts_comma_separated_list(self):
        v = "mailto:a@example.com,mailto:b@example.com"
        assert _check_acme_contact(v) == v

    def test_rejects_missing_at(self):
        with pytest.raises(ProximoError):
            _check_acme_contact("not-an-email")

    def test_rejects_whitespace(self):
        with pytest.raises(ProximoError):
            _check_acme_contact("user @example.com")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_acme_contact("a@" + "b" * 1025)


class TestCheckAcmeDirectoryUrl:
    def test_accepts_https(self):
        url = "https://acme-v02.api.letsencrypt.org/directory"
        assert _check_acme_directory_url(url, "directory") == url

    def test_rejects_http(self):
        """STRICTER THAN SCHEMA BY CHOICE — schema permits http, this validator does not
        (mirrors pbs_acme.py's own review-finding-driven https-only enforcement)."""
        with pytest.raises(ProximoError):
            _check_acme_directory_url("http://example.com/directory", "directory")

    def test_rejects_whitespace(self):
        with pytest.raises(ProximoError):
            _check_acme_directory_url("https://example.com/ bad", "directory")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_acme_directory_url("https://example.com/" + "a" * 512, "directory")


class TestCheckAcmePluginDigest:
    def test_accepts_none(self):
        assert _check_acme_plugin_digest(None) is None

    def test_accepts_valid(self):
        assert _check_acme_plugin_digest("abc123") == "abc123"

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_acme_plugin_digest("a" * 65)


class TestCheckAcmePluginNodes:
    def test_accepts_single_node(self):
        assert _check_acme_plugin_nodes("pmg1") == "pmg1"

    def test_accepts_comma_separated(self):
        assert _check_acme_plugin_nodes("pmg1,pmg2") == "pmg1,pmg2"

    def test_rejects_empty_segment(self):
        with pytest.raises(ProximoError):
            _check_acme_plugin_nodes("pmg1,,pmg2")

    def test_rejects_invalid_node_name(self):
        with pytest.raises(ProximoError):
            _check_acme_plugin_nodes("pmg1,bad/node")


class TestCheckAcmePluginDeleteProps:
    def test_accepts_single_valid_prop(self):
        assert _check_acme_plugin_delete_props("disable") == "disable"

    def test_accepts_comma_separated_valid_props(self):
        v = "disable,validation-delay"
        assert _check_acme_plugin_delete_props(v) == v

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_acme_plugin_delete_props("")

    def test_rejects_unknown_property(self):
        """Closed to THIS endpoint's own writable optional properties — 'id'/'type'/'digest'/
        'delete' are not themselves deletable."""
        with pytest.raises(ProximoError):
            _check_acme_plugin_delete_props("comment")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_acme_plugin_delete_props("disable," * 1000)


class TestCheckAcmeValidationDelay:
    def test_accepts_valid(self):
        assert _check_acme_validation_delay(30) == 30
        assert _check_acme_validation_delay(0) == 0
        assert _check_acme_validation_delay(172800) == 172800

    def test_rejects_negative(self):
        with pytest.raises(ProximoError):
            _check_acme_validation_delay(-1)

    def test_rejects_over_max(self):
        with pytest.raises(ProximoError):
            _check_acme_validation_delay(172801)

    def test_rejects_float(self):
        with pytest.raises(ProximoError):
            _check_acme_validation_delay(12.9)

    def test_rejects_bool(self):
        with pytest.raises(ProximoError):
            _check_acme_validation_delay(True)


class TestCheckPmgCertType:
    def test_accepts_api(self):
        assert _check_pmg_cert_type("api") == "api"

    def test_accepts_smtp(self):
        assert _check_pmg_cert_type("smtp") == "smtp"

    def test_rejects_unknown(self):
        with pytest.raises(ProximoError):
            _check_pmg_cert_type("web")


# ---------------------------------------------------------------------------
# Backend functions — ACME accounts
# ---------------------------------------------------------------------------

class TestAcmeAccountList:
    def test_uses_correct_path(self):
        api = _api()
        acme_account_list(api)
        assert api.seen["path"] == "/config/acme/account"

    def test_strips_secrets_defensively(self):
        api = SimpleNamespace(_get=lambda path, params=None: [
            {"name": "default", "eab-hmac-key": "sentinel-leaked-key", "eab-kid": "sentinel-leaked-kid"},
        ])
        result = acme_account_list(api)
        assert "eab-hmac-key" not in result[0]
        assert "eab-kid" not in result[0]
        assert result[0]["name"] == "default"


class TestAcmeAccountGet:
    def test_uses_correct_path(self):
        api = _api()
        acme_account_get(api, "default")
        assert api.seen["path"] == "/config/acme/account/default"

    def test_defaults_to_default_account(self):
        api = _api()
        acme_account_get(api)
        assert api.seen["path"] == "/config/acme/account/default"

    def test_strips_secrets_defensively(self):
        api = SimpleNamespace(_get=lambda path, params=None: {
            "directory": "https://example.com/directory",
            "eab-hmac-key": "sentinel-leaked-key", "eab-kid": "sentinel-leaked-kid",
        })
        result = acme_account_get(api, "default")
        assert "eab-hmac-key" not in result
        assert "eab-kid" not in result
        assert result["directory"] == "https://example.com/directory"

    def test_rejects_invalid_name(self):
        api = _api()
        with pytest.raises(ProximoError):
            acme_account_get(api, "bad/name")


# ---------------------------------------------------------------------------
# Backend functions — ACME plugins
# ---------------------------------------------------------------------------

class TestAcmePluginsList:
    def test_uses_correct_path(self):
        api = _api()
        acme_plugins_list(api)
        assert api.seen["path"] == "/config/acme/plugins"

    def test_forwards_type_filter(self):
        api = _api()
        acme_plugins_list(api, plugin_type="dns")
        assert api.seen["params"]["type"] == "dns"

    def test_no_filter_when_omitted(self):
        api = _api()
        acme_plugins_list(api)
        assert not api.seen["params"]

    def test_strips_data_defensively(self):
        """PMG's own list is schema-confirmed THIN/id-only (does NOT echo `data` per the schema)
        — stripped anyway per the mature post-9c-review discipline."""
        api = SimpleNamespace(_get=lambda path, params=None: [
            {"plugin": "p1", "data": "sentinel-leaked-data-blob"},
        ])
        result = acme_plugins_list(api)
        assert "data" not in result[0]
        assert result[0]["plugin"] == "p1"


class TestAcmePluginGet:
    def test_uses_correct_path(self):
        api = _api()
        acme_plugin_get(api, "p1")
        assert api.seen["path"] == "/config/acme/plugins/p1"

    def test_strips_data_defensively(self):
        api = SimpleNamespace(_get=lambda path, params=None: {
            "plugin": "p1", "data": "sentinel-leaked-data-blob",
        })
        result = acme_plugin_get(api, "p1")
        assert "data" not in result
        assert result["plugin"] == "p1"

    def test_rejects_invalid_id(self):
        api = _api()
        with pytest.raises(ProximoError):
            acme_plugin_get(api, "bad/id")


# ---------------------------------------------------------------------------
# Backend functions — ACME CA metadata (tos/meta/directories/challenge-schema)
# ---------------------------------------------------------------------------

class TestAcmeTos:
    def test_uses_correct_path(self):
        api = _api()
        acme_tos(api)
        assert api.seen["path"] == "/config/acme/tos"

    def test_forwards_directory(self):
        api = _api()
        acme_tos(api, directory="https://example.com/directory")
        assert api.seen["params"]["directory"] == "https://example.com/directory"

    def test_rejects_http_directory(self):
        api = _api()
        with pytest.raises(ProximoError):
            acme_tos(api, directory="http://example.com/directory")


class TestAcmeMeta:
    def test_uses_correct_path(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        acme_meta(api)

    def test_forwards_directory(self):
        seen = {}

        def fake_get(path, params=None):
            seen["path"] = path
            seen["params"] = params
            return {}
        api = SimpleNamespace(_get=fake_get)
        acme_meta(api, directory="https://example.com/directory")
        assert seen["path"] == "/config/acme/meta"
        assert seen["params"]["directory"] == "https://example.com/directory"

    def test_rejects_http_directory(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        with pytest.raises(ProximoError):
            acme_meta(api, directory="http://example.com/directory")


class TestAcmeDirectories:
    def test_uses_correct_path(self):
        api = _api()
        acme_directories(api)
        assert api.seen["path"] == "/config/acme/directories"


class TestAcmeChallengeSchema:
    def test_uses_correct_path(self):
        api = _api()
        acme_challenge_schema(api)
        assert api.seen["path"] == "/config/acme/challenge-schema"


# ---------------------------------------------------------------------------
# Backend functions — ACME account mutations
# ---------------------------------------------------------------------------

class TestAcmeAccountCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        acme_account_create(api, "mailto:a@example.com")
        assert api.seen["path"] == "/config/acme/account"
        assert api.seen["method"] == "POST"

    def test_contact_in_body(self):
        api = _api()
        acme_account_create(api, "mailto:a@example.com")
        assert api.seen["data"]["contact"] == "mailto:a@example.com"

    def test_eab_fields_forwarded_raw_on_the_wire(self):
        api = _api()
        acme_account_create(
            api, "mailto:a@example.com", eab_hmac_key="sentinel-hmac", eab_kid="sentinel-kid",
        )
        assert api.seen["data"]["eab-hmac-key"] == "sentinel-hmac"
        assert api.seen["data"]["eab-kid"] == "sentinel-kid"

    def test_name_omitted_lets_pmg_default(self):
        api = _api()
        acme_account_create(api, "mailto:a@example.com")
        assert "name" not in api.seen["data"]

    def test_name_forwarded_when_given(self):
        api = _api()
        acme_account_create(api, "mailto:a@example.com", name="custom")
        assert api.seen["data"]["name"] == "custom"

    def test_rejects_invalid_directory(self):
        api = _api()
        with pytest.raises(ProximoError):
            acme_account_create(api, "mailto:a@example.com", directory="http://example.com/directory")

    def test_rejects_invalid_contact(self):
        api = _api()
        with pytest.raises(ProximoError):
            acme_account_create(api, "not-an-email")


class TestAcmeAccountUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        acme_account_update(api, "default", contact="mailto:new@example.com")
        assert api.seen["path"] == "/config/acme/account/default"
        assert api.seen["method"] == "PUT"

    def test_no_guard_on_empty_update(self):
        """Deliberate exception: PMG's own schema states omitting contact triggers a CA refresh
        — NOT an error, unlike this codebase's usual 'at least one field' guard."""
        api = _api()
        acme_account_update(api, "default")
        assert api.seen["data"] == {}

    def test_contact_forwarded_raw_on_the_wire(self):
        api = _api()
        acme_account_update(api, "default", contact="mailto:new@example.com")
        assert api.seen["data"]["contact"] == "mailto:new@example.com"


class TestAcmeAccountDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        acme_account_delete(api, "default")
        assert api.seen["path"] == "/config/acme/account/default"
        assert api.seen["method"] == "DELETE"

    def test_force_forwarded_when_true(self):
        api = _api()
        acme_account_delete(api, "default", force=True)
        assert api.seen["params"]["force"] == 1

    def test_force_omitted_when_false(self):
        api = _api()
        acme_account_delete(api, "default", force=False)
        assert api.seen["params"] == {}


# ---------------------------------------------------------------------------
# Backend functions — ACME plugin mutations
# ---------------------------------------------------------------------------

class TestAcmePluginCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        acme_plugin_create(api, "p1", "dns")
        assert api.seen["path"] == "/config/acme/plugins"
        assert api.seen["method"] == "POST"

    def test_required_fields_in_body(self):
        api = _api()
        acme_plugin_create(api, "p1", "dns")
        assert api.seen["data"] == {"id": "p1", "type": "dns"}

    def test_data_forwarded_raw_on_the_wire(self):
        api = _api()
        acme_plugin_create(api, "p1", "dns", data="sentinel-b64-blob")
        assert api.seen["data"]["data"] == "sentinel-b64-blob"

    def test_dns_api_maps_to_api_field(self):
        api = _api()
        acme_plugin_create(api, "p1", "dns", dns_api="cf")
        assert api.seen["data"]["api"] == "cf"

    def test_optional_fields_included_when_given(self):
        api = _api()
        acme_plugin_create(api, "p1", "dns", disable=True, nodes="pmg1", validation_delay=60)
        assert api.seen["data"]["disable"] is True
        assert api.seen["data"]["nodes"] == "pmg1"
        assert api.seen["data"]["validation-delay"] == 60

    def test_rejects_invalid_plugin_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            acme_plugin_create(api, "p1", "http-01")

    def test_rejects_invalid_validation_delay(self):
        api = _api()
        with pytest.raises(ProximoError):
            acme_plugin_create(api, "p1", "dns", validation_delay=999999)


class TestAcmePluginUpdate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        acme_plugin_update(api, "p1", disable=True)
        assert api.seen["path"] == "/config/acme/plugins/p1"
        assert api.seen["method"] == "PUT"

    def test_digest_forwarded(self):
        api = _api()
        acme_plugin_update(api, "p1", digest="abc123")
        assert api.seen["data"]["digest"] == "abc123"

    def test_delete_forwarded(self):
        api = _api()
        acme_plugin_update(api, "p1", delete="disable")
        assert api.seen["data"]["delete"] == "disable"

    def test_rejects_invalid_delete_prop(self):
        api = _api()
        with pytest.raises(ProximoError):
            acme_plugin_update(api, "p1", delete="comment")

    def test_id_not_resent_in_body(self):
        api = _api()
        acme_plugin_update(api, "p1", disable=True)
        assert "id" not in api.seen["data"]


class TestAcmePluginDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        acme_plugin_delete(api, "p1")
        assert api.seen["path"] == "/config/acme/plugins/p1"
        assert api.seen["method"] == "DELETE"


# ---------------------------------------------------------------------------
# Backend functions — node cert order/renew/revoke (ACME-issued)
# ---------------------------------------------------------------------------

class TestNodeCertAcmeOrder:
    def test_uses_correct_path_and_method(self):
        api = _api()
        node_cert_acme_order(api, "pmg1", "api")
        assert api.seen["path"] == "/nodes/pmg1/certificates/acme/api"
        assert api.seen["method"] == "POST"

    def test_force_forwarded(self):
        api = _api()
        node_cert_acme_order(api, "pmg1", "api", force=True)
        assert api.seen["data"]["force"] == 1

    def test_rejects_invalid_cert_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            node_cert_acme_order(api, "pmg1", "web")


class TestNodeCertAcmeRenew:
    def test_uses_correct_path_and_method(self):
        api = _api()
        node_cert_acme_renew(api, "pmg1", "smtp")
        assert api.seen["path"] == "/nodes/pmg1/certificates/acme/smtp"
        assert api.seen["method"] == "PUT"


class TestNodeCertAcmeRevoke:
    def test_uses_correct_path_and_method(self):
        api = _api()
        node_cert_acme_revoke(api, "pmg1", "api")
        assert api.seen["path"] == "/nodes/pmg1/certificates/acme/api"
        assert api.seen["method"] == "DELETE"


# ---------------------------------------------------------------------------
# Backend functions — node custom-cert upload/delete
# ---------------------------------------------------------------------------

class TestNodeCertCustomUpload:
    def test_uses_correct_path_and_method(self):
        api = _api()
        node_cert_custom_upload(api, "pmg1", "api", "CERTDATA", "KEYDATA")
        assert api.seen["path"] == "/nodes/pmg1/certificates/custom/api"
        assert api.seen["method"] == "POST"

    def test_certificates_and_key_forwarded_raw_on_the_wire(self):
        api = _api()
        node_cert_custom_upload(api, "pmg1", "api", "CERTDATA", "KEYDATA")
        assert api.seen["data"]["certificates"] == "CERTDATA"
        assert api.seen["data"]["key"] == "KEYDATA"

    def test_force_and_restart_forwarded(self):
        api = _api()
        node_cert_custom_upload(api, "pmg1", "api", "CERTDATA", "KEYDATA", force=True, restart=True)
        assert api.seen["data"]["force"] == 1
        assert api.seen["data"]["restart"] == 1

    def test_rejects_invalid_cert_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            node_cert_custom_upload(api, "pmg1", "web", "CERTDATA", "KEYDATA")


class TestNodeCertCustomDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        node_cert_custom_delete(api, "pmg1", "smtp")
        assert api.seen["path"] == "/nodes/pmg1/certificates/custom/smtp"
        assert api.seen["method"] == "DELETE"

    def test_restart_forwarded_when_true(self):
        api = _api()
        node_cert_custom_delete(api, "pmg1", "api", restart=True)
        assert api.seen["params"]["restart"] == 1

    def test_restart_omitted_when_false(self):
        api = _api()
        node_cert_custom_delete(api, "pmg1", "api", restart=False)
        assert api.seen["params"] == {}


# ---------------------------------------------------------------------------
# Plan factories — ACME accounts
# ---------------------------------------------------------------------------

class TestPlanAcmeAccountCreate:
    def test_risk_is_medium(self):
        p = plan_acme_account_create("mailto:a@example.com")
        assert p.risk == RISK_MEDIUM

    def test_secrets_never_appear_in_plan(self):
        p = plan_acme_account_create(
            "mailto:a@example.com", eab_hmac_key="sentinel-hmac", eab_kid="sentinel-kid",
        )
        dumped = json.dumps(p.as_dict())
        assert "sentinel-hmac" not in dumped
        assert "sentinel-kid" not in dumped
        assert "[redacted]" in dumped

    def test_contact_visible_not_redacted(self):
        p = plan_acme_account_create("mailto:a@example.com")
        dumped = json.dumps(p.as_dict())
        assert "mailto:a@example.com" in dumped

    def test_no_capture_current_is_empty(self):
        p = plan_acme_account_create("mailto:a@example.com")
        assert p.current == {}

    def test_rejects_invalid_directory(self):
        with pytest.raises(ProximoError):
            plan_acme_account_create("mailto:a@example.com", directory="http://example.com/directory")


class TestPlanAcmeAccountUpdate:
    def test_risk_is_low(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_acme_account_update(api, "default", contact="mailto:new@example.com")
        assert p.risk == RISK_LOW

    def test_no_guard_when_contact_omitted(self):
        """Deliberate exception (divergence #11) — no ProximoError raised."""
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_acme_account_update(api, "default")
        assert "refresh" in p.change.lower()

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_acme_account_update(api, "default", contact="mailto:new@example.com")
        assert p.complete is False

    def test_captured_current_redacted_even_when_secret_bearing(self):
        api = SimpleNamespace(_get=lambda path, params=None: {
            "directory": "https://example.com/directory", "eab-hmac-key": "sentinel-leaked",
        })
        p = plan_acme_account_update(api, "default", contact="mailto:new@example.com")
        dumped = json.dumps(p.as_dict())
        assert "sentinel-leaked" not in dumped


class TestPlanAcmeAccountDelete:
    def test_risk_is_high(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_acme_account_delete(api, "default")
        assert p.risk == RISK_HIGH

    def test_discloses_irreversible(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_acme_account_delete(api, "default")
        assert "irreversible" in p.change.lower()

    def test_captures_current_config_redacted(self):
        api = SimpleNamespace(_get=lambda path, params=None: {
            "directory": "https://example.com/directory", "eab-hmac-key": "sentinel-leaked",
        })
        p = plan_acme_account_delete(api, "default")
        assert "eab-hmac-key" not in p.current
        dumped = json.dumps(p.as_dict())
        assert "sentinel-leaked" not in dumped

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_acme_account_delete(api, "default")
        assert p.complete is False


# ---------------------------------------------------------------------------
# Plan factories — ACME plugins
# ---------------------------------------------------------------------------

class TestPlanAcmePluginCreate:
    def test_risk_is_medium(self):
        p = plan_acme_plugin_create("p1", "dns")
        assert p.risk == RISK_MEDIUM

    def test_secrets_never_appear_in_plan(self):
        p = plan_acme_plugin_create("p1", "dns", data="sentinel-b64-blob")
        dumped = json.dumps(p.as_dict())
        assert "sentinel-b64-blob" not in dumped
        assert "[redacted]" in dumped

    def test_rejects_invalid_plugin_type(self):
        with pytest.raises(ProximoError):
            plan_acme_plugin_create("p1", "http-01")


class TestPlanAcmePluginUpdate:
    def test_risk_is_medium(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_acme_plugin_update(api, "p1", disable=True)
        assert p.risk == RISK_MEDIUM

    def test_secrets_never_appear_in_plan(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_acme_plugin_update(api, "p1", data="sentinel-b64-blob")
        dumped = json.dumps(p.as_dict())
        assert "sentinel-b64-blob" not in dumped
        assert "[redacted]" in dumped

    def test_captured_current_redacted_even_when_secret_bearing(self):
        api = SimpleNamespace(_get=lambda path, params=None: {
            "plugin": "p1", "data": "sentinel-leaked-capture",
        })
        p = plan_acme_plugin_update(api, "p1", disable=True)
        dumped = json.dumps(p.as_dict())
        assert "sentinel-leaked-capture" not in dumped

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_acme_plugin_update(api, "p1", disable=True)
        assert p.complete is False

    def test_rejects_invalid_delete_prop(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        with pytest.raises(ProximoError):
            plan_acme_plugin_update(api, "p1", delete="comment")


class TestPlanAcmePluginDelete:
    def test_risk_is_high(self):
        api = SimpleNamespace(_get=lambda path, params=None: {})
        p = plan_acme_plugin_delete(api, "p1")
        assert p.risk == RISK_HIGH

    def test_captures_current_config_redacted(self):
        api = SimpleNamespace(_get=lambda path, params=None: {
            "plugin": "p1", "data": "sentinel-leaked",
        })
        p = plan_acme_plugin_delete(api, "p1")
        assert "data" not in p.current
        dumped = json.dumps(p.as_dict())
        assert "sentinel-leaked" not in dumped

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_acme_plugin_delete(api, "p1")
        assert p.complete is False


# ---------------------------------------------------------------------------
# Plan factories — node cert order/renew/revoke (ACME-issued)
# ---------------------------------------------------------------------------

class TestPlanNodeCertAcmeOrder:
    def test_risk_is_medium(self):
        p = plan_node_cert_acme_order("pmg1", "api")
        assert p.risk == RISK_MEDIUM

    def test_api_slot_names_web_ui(self):
        p = plan_node_cert_acme_order("pmg1", "api")
        assert "management-api" in p.change.lower()

    def test_smtp_slot_names_mail_tls(self):
        p = plan_node_cert_acme_order("pmg1", "smtp")
        assert "smtp" in p.change.lower()

    def test_no_capture_current_is_empty(self):
        p = plan_node_cert_acme_order("pmg1", "api")
        assert p.current == {}


class TestPlanNodeCertAcmeRenew:
    def test_risk_is_medium(self):
        p = plan_node_cert_acme_renew("pmg1", "api")
        assert p.risk == RISK_MEDIUM


class TestPlanNodeCertAcmeRevoke:
    def test_risk_is_high(self):
        api = SimpleNamespace(_get=lambda path, params=None: [])
        p = plan_node_cert_acme_revoke(api, "pmg1", "api")
        assert p.risk == RISK_HIGH

    def test_discloses_irreversible(self):
        api = SimpleNamespace(_get=lambda path, params=None: [])
        p = plan_node_cert_acme_revoke(api, "pmg1", "api")
        assert "irreversible" in p.change.lower()

    def test_captures_cert_info_as_evidence(self):
        api = SimpleNamespace(_get=lambda path, params=None: [{"fingerprint": "AA:BB"}])
        p = plan_node_cert_acme_revoke(api, "pmg1", "api")
        assert p.current["certificates"] == [{"fingerprint": "AA:BB"}]

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_node_cert_acme_revoke(api, "pmg1", "api")
        assert p.complete is False


# ---------------------------------------------------------------------------
# Plan factories — node custom-cert upload/delete
# ---------------------------------------------------------------------------

class TestPlanNodeCertCustomUpload:
    def test_risk_is_high(self):
        api = SimpleNamespace(_get=lambda path, params=None: [])
        p = plan_node_cert_custom_upload(api, "CERTDATA", "pmg1", "api")
        assert p.risk == RISK_HIGH

    def test_key_never_appears_anywhere(self):
        """UNCONDITIONAL redaction — `key` is never even a parameter to this function."""
        import inspect
        assert "key" not in inspect.signature(plan_node_cert_custom_upload).parameters

    def test_api_slot_names_web_ui_lockout(self):
        api = SimpleNamespace(_get=lambda path, params=None: [])
        p = plan_node_cert_custom_upload(api, "CERTDATA", "pmg1", "api")
        joined = " ".join(p.risk_reasons).lower()
        assert "web ui" in joined or "lock" in joined

    def test_smtp_slot_names_mail_tls_breakage(self):
        api = SimpleNamespace(_get=lambda path, params=None: [])
        p = plan_node_cert_custom_upload(api, "CERTDATA", "pmg1", "smtp")
        joined = " ".join(p.risk_reasons).lower()
        assert "mail" in joined or "smtp" in joined

    def test_captures_cert_info_as_evidence(self):
        api = SimpleNamespace(_get=lambda path, params=None: [{"fingerprint": "AA:BB"}])
        p = plan_node_cert_custom_upload(api, "CERTDATA", "pmg1", "api")
        assert p.current["certificates"] == [{"fingerprint": "AA:BB"}]

    def test_degrades_honestly_on_capture_failure(self):
        def raising_get(path, params=None):
            raise ProximoError("simulated read failure")
        api = SimpleNamespace(_get=raising_get)
        p = plan_node_cert_custom_upload(api, "CERTDATA", "pmg1", "api")
        assert p.complete is False


class TestPlanNodeCertCustomDelete:
    def test_risk_is_medium(self):
        p = plan_node_cert_custom_delete("pmg1", "api")
        assert p.risk == RISK_MEDIUM

    def test_discloses_recoverable(self):
        p = plan_node_cert_custom_delete("pmg1", "api")
        assert "recoverable" in p.note.lower()


# ===========================================================================
# Wave 9j (2026-07-18, THE FINAL CHUNK — closes the PMG plane): quarantine + statistics
# remainder. See pmg.py's own "Wave 9j" module section for the full RULING 4 / taint argument.
# ===========================================================================


class TestCheckQuarusersList:
    def test_valid_values_pass(self):
        for v in ("BL", "WL"):
            assert _check_quarusers_list(v) == v

    def test_invalid_value_raises(self):
        with pytest.raises(ProximoError):
            _check_quarusers_list("XX")

    def test_lowercase_raises(self):
        with pytest.raises(ProximoError):
            _check_quarusers_list("bl")


class TestCheckStatisticsDetailType:
    def test_valid_values_pass(self):
        for v in ("contact", "sender", "receiver"):
            assert _check_statistics_detail_type(v) == v

    def test_invalid_value_raises(self):
        with pytest.raises(ProximoError):
            _check_statistics_detail_type("domain")


class TestCheckRecentHours:
    def test_valid_bounds_pass(self):
        assert _check_recent_hours(1) == 1
        assert _check_recent_hours(24) == 24
        assert _check_recent_hours("12") == 12

    def test_below_min_raises(self):
        with pytest.raises(ProximoError):
            _check_recent_hours(0)

    def test_above_max_raises(self):
        with pytest.raises(ProximoError):
            _check_recent_hours(25)

    def test_non_int_raises(self):
        with pytest.raises(ProximoError):
            _check_recent_hours("bad")


class TestCheckRecentLimit:
    def test_valid_bounds_pass(self):
        assert _check_recent_limit(1) == 1
        assert _check_recent_limit(50) == 50

    def test_below_min_raises(self):
        with pytest.raises(ProximoError):
            _check_recent_limit(0)

    def test_above_max_raises(self):
        with pytest.raises(ProximoError):
            _check_recent_limit(51)

    def test_non_int_raises(self):
        with pytest.raises(ProximoError):
            _check_recent_limit("bad")


class TestQuarantineUsersList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or []
        )
        quarantine_users_list(api)
        assert api.seen["path"] == "/quarantine/quarusers"

    def test_no_list_filter_sends_no_params(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params) or []
        )
        quarantine_users_list(api)
        assert api.seen["params"] is None

    def test_list_filter_forwarded(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_users_list(api, list_="WL")
        assert api.seen["params"].get("list") == "WL"

    def test_invalid_list_filter_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            quarantine_users_list(api, list_="bogus")


class TestQuarantineContentGet:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or {}
        )
        quarantine_content_get(api, "C1R1T1700000000")
        assert api.seen["path"] == "/quarantine/content"

    def test_id_sent_as_param(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or {}
        )
        quarantine_content_get(api, "C1R1T1700000000")
        assert api.seen["params"].get("id") == "C1R1T1700000000"

    def test_images_true_sends_1(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or {}
        )
        quarantine_content_get(api, "abc123", images=True)
        assert api.seen["params"].get("images") == 1

    def test_images_false_sends_0(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or {}
        )
        quarantine_content_get(api, "abc123", images=False)
        assert api.seen["params"].get("images") == 0

    def test_raw_omitted_when_none(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or {}
        )
        quarantine_content_get(api, "abc123")
        assert "raw" not in api.seen["params"]

    def test_raw_true_sends_1(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or {}
        )
        quarantine_content_get(api, "abc123", raw=True)
        assert api.seen["params"].get("raw") == 1

    def test_invalid_id_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            quarantine_content_get(api, "not/valid")

    def test_falsy_empty_dict_return_passes_through(self):
        api = _api()
        api._get = lambda path, params=None: None
        assert quarantine_content_get(api, "abc123") == {}


class TestQuarantineAttachmentsList:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or []
        )
        quarantine_attachments_list(api, "abc123")
        assert api.seen["path"] == "/quarantine/listattachments"

    def test_id_sent_as_param(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        quarantine_attachments_list(api, "abc123")
        assert api.seen["params"].get("id") == "abc123"

    def test_invalid_id_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            quarantine_attachments_list(api, "bad id with spaces")

    def test_falsy_none_return_becomes_empty_list(self):
        api = _api()
        api._get = lambda path, params=None: None
        assert quarantine_attachments_list(api, "abc123") == []


class TestQuarantineLinkGet:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or {"link": "https://sentinel/link"}
        )
        quarantine_link_get(api, "user@example.com")
        assert api.seen["path"] == "/quarantine/link"

    def test_mail_sent_as_param(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or {}
        )
        quarantine_link_get(api, "user@example.com")
        assert api.seen["params"].get("mail") == "user@example.com"

    def test_invalid_mail_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            quarantine_link_get(api, "not-an-email")

    def test_link_value_reaches_the_caller(self):
        """THE SECRET must reach the caller (it's the whole point of the tool) — only the
        LEDGER redaction (RULING 4) forbids it from being logged, proven separately in
        tests/test_confirm_sweep_pmg_quarantine_statistics.py."""
        api = _api()
        api._get = lambda path, params=None: {"link": "https://pmg.example.com/quarantine?t=SECRETTOKEN"}
        result = quarantine_link_get(api, "user@example.com")
        assert result["link"] == "https://pmg.example.com/quarantine?t=SECRETTOKEN"

    def test_falsy_none_return_becomes_empty_dict(self):
        api = _api()
        api._get = lambda path, params=None: None
        assert quarantine_link_get(api, "user@example.com") == {}


class TestQuarantineSendlink:
    def test_uses_correct_path(self):
        api = _api()
        quarantine_sendlink(api, "user@example.com")
        assert api.seen["path"] == "/quarantine/sendlink"
        assert api.seen["method"] == "POST"

    def test_mail_sent_in_body(self):
        api = _api()
        quarantine_sendlink(api, "user@example.com")
        assert api.seen["data"] == {"mail": "user@example.com"}

    def test_invalid_mail_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            quarantine_sendlink(api, "not-an-email")


class TestPlanQuarantineSendlink:
    def test_risk_is_low(self):
        p = plan_quarantine_sendlink("user@example.com")
        assert p.risk == RISK_LOW

    def test_change_mentions_mail(self):
        p = plan_quarantine_sendlink("user@example.com")
        assert "user@example.com" in p.change

    def test_blast_radius_mentions_bearer_credential(self):
        p = plan_quarantine_sendlink("user@example.com")
        joined = " ".join(p.blast_radius).lower()
        assert "credential" in joined or "access" in joined

    def test_risk_reasons_cite_no_revert(self):
        p = plan_quarantine_sendlink("user@example.com")
        joined = " ".join(p.risk_reasons).lower()
        assert "recall" in joined or "revert" in joined

    def test_invalid_mail_raises(self):
        with pytest.raises(ProximoError):
            plan_quarantine_sendlink("not-an-email")

    def test_action_and_target(self):
        p = plan_quarantine_sendlink("user@example.com")
        assert p.action == "pmg_quarantine_sendlink"
        assert p.target == "quarantine/sendlink"


class TestStatisticsContact:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or []
        )
        statistics_contact(api)
        assert api.seen["path"] == "/statistics/contact"

    def test_no_params_sends_none(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params) or []
        )
        statistics_contact(api)
        assert api.seen["params"] is None

    def test_maps_start_to_starttime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_contact(api, start=1717000000)
        assert api.seen["params"].get("starttime") == 1717000000

    def test_filter_forwarded(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_contact(api, filter_="evil.example")
        assert api.seen["params"].get("filter") == "evil.example"

    def test_orderby_forwarded(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_contact(api, orderby='{"property":"contact"}')
        assert api.seen["params"].get("orderby") == '{"property":"contact"}'

    def test_day_month_year_forwarded(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_contact(api, day=15, month=6, year=2026)
        assert api.seen["params"]["day"] == 15
        assert api.seen["params"]["month"] == 6
        assert api.seen["params"]["year"] == 2026

    def test_day_out_of_range_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_contact(api, day=32)

    def test_month_out_of_range_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_contact(api, month=13)

    def test_year_out_of_range_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_contact(api, year=1800)


class TestStatisticsDetail:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or []
        )
        statistics_detail(api, "user@example.com", "sender")
        assert api.seen["path"] == "/statistics/detail"

    def test_address_and_type_always_sent(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_detail(api, "user@example.com", "receiver")
        assert api.seen["params"]["address"] == "user@example.com"
        assert api.seen["params"]["type"] == "receiver"

    def test_invalid_address_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_detail(api, "not-an-email", "sender")

    def test_invalid_type_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_detail(api, "user@example.com", "domain")

    def test_day_month_year_forwarded(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_detail(api, "user@example.com", "contact", day=1, month=1, year=2020)
        assert api.seen["params"]["day"] == 1
        assert api.seen["params"]["month"] == 1
        assert api.seen["params"]["year"] == 2020


class TestStatisticsMaildistribution:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or []
        )
        statistics_maildistribution(api)
        assert api.seen["path"] == "/statistics/maildistribution"

    def test_no_params_sends_none(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params) or []
        )
        statistics_maildistribution(api)
        assert api.seen["params"] is None

    def test_day_month_year_forwarded(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_maildistribution(api, day=15, month=6, year=2026)
        assert api.seen["params"]["day"] == 15
        assert api.seen["params"]["month"] == 6
        assert api.seen["params"]["year"] == 2026

    def test_month_out_of_range_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_maildistribution(api, month=0)


class TestStatisticsRecentreceivers:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or []
        )
        statistics_recentreceivers(api)
        assert api.seen["path"] == "/statistics/recentreceivers"

    def test_defaults_hours_12_limit_5(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_recentreceivers(api)
        assert api.seen["params"] == {"hours": 12, "limit": 5}

    def test_explicit_hours_and_limit_forwarded(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_recentreceivers(api, hours=3, limit=20)
        assert api.seen["params"] == {"hours": 3, "limit": 20}

    def test_hours_out_of_range_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_recentreceivers(api, hours=25)

    def test_limit_out_of_range_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_recentreceivers(api, limit=51)


class TestStatisticsRecentsenders:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or []
        )
        statistics_recentsenders(api)
        assert api.seen["path"] == "/statistics/recentsenders"

    def test_defaults_hours_12_limit_5(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_recentsenders(api)
        assert api.seen["params"] == {"hours": 12, "limit": 5}

    def test_hours_out_of_range_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_recentsenders(api, hours=0)

    def test_limit_out_of_range_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_recentsenders(api, limit=0)


class TestStatisticsRejectcount:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path, params=params) or []
        )
        statistics_rejectcount(api)
        assert api.seen["path"] == "/statistics/rejectcount"

    def test_always_sends_timespan(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_rejectcount(api)
        assert api.seen["params"].get("timespan") == 3600

    def test_maps_start_to_starttime(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_rejectcount(api, start=1717000000)
        assert api.seen["params"].get("starttime") == 1717000000

    def test_day_month_year_forwarded(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(params=params or {}) or []
        )
        statistics_rejectcount(api, day=15, month=6, year=2026)
        assert api.seen["params"]["day"] == 15
        assert api.seen["params"]["month"] == 6
        assert api.seen["params"]["year"] == 2026

    def test_rejects_non_int_timespan(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_rejectcount(api, timespan="bad")

    def test_rejects_timespan_below_min(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_rejectcount(api, timespan=100)

    def test_rejects_timespan_above_max(self):
        api = _api()
        with pytest.raises(ProximoError):
            statistics_rejectcount(api, timespan=99999999)
