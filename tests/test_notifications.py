"""Tests for notifications.py — validators, operations, and plan factories.

Mirrors test_pbs.py / test_backup_schedules.py style:
  - _Api: recording fake for ApiBackend (no live network).
  - Validator tests: prove \\Z-anchored rejections (trailing newline, slash, bad type).
  - Operation tests: prove correct HTTP verb + path; result passthrough.
  - Plan tests: prove honest risk, correct current capture, no implied undo.
"""

from __future__ import annotations

import pytest

from proximo.backends import ProximoError
from proximo.notifications import (
    _check_endpoint_name,
    _check_endpoint_type,
    _check_metrics_id,
    metrics_server_delete,
    metrics_server_list,
    metrics_server_set,
    notification_endpoint_create,
    notification_endpoint_delete,
    notification_endpoint_get,
    notification_endpoint_list,
    notification_endpoint_update,
    notification_matcher_delete,
    notification_matcher_set,
    notification_test,
    plan_metrics_server_delete,
    plan_metrics_server_set,
    plan_notification_endpoint_create,
    plan_notification_endpoint_delete,
    plan_notification_endpoint_update,
    plan_notification_matcher_delete,
    plan_notification_matcher_set,
    plan_notification_test,
)
from proximo.planning import RISK_LOW

# ---------------------------------------------------------------------------
# Recording fake
# ---------------------------------------------------------------------------

class _Api:
    """Recording fake for ApiBackend (HTTP verb tracking, no live network)."""

    def __init__(self, get_return=None):
        self._get_return = get_return if get_return is not None else {}
        self.gets: list[str] = []
        self.posts: list[tuple] = []
        self.puts: list[tuple] = []
        self.dels: list[tuple] = []

    def _get(self, path: str):
        self.gets.append(path)
        return self._get_return

    def _post(self, path: str, data=None):
        self.posts.append((path, data))
        return None

    def _put(self, path: str, data=None):
        self.puts.append((path, data))
        return None

    def _delete(self, path: str, params=None):
        self.dels.append((path, params))
        return None


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

class TestCheckEndpointType:
    def test_valid_gotify(self):
        assert _check_endpoint_type("gotify") == "gotify"

    def test_valid_smtp(self):
        assert _check_endpoint_type("smtp") == "smtp"

    def test_valid_sendmail(self):
        assert _check_endpoint_type("sendmail") == "sendmail"

    def test_valid_webhook(self):
        assert _check_endpoint_type("webhook") == "webhook"

    def test_invalid_slack_raises(self):
        with pytest.raises(ProximoError, match="invalid notification endpoint type"):
            _check_endpoint_type("slack")

    def test_empty_raises(self):
        with pytest.raises(ProximoError):
            _check_endpoint_type("")

    def test_uppercase_raises(self):
        """Type check is case-sensitive (closed frozenset)."""
        with pytest.raises(ProximoError):
            _check_endpoint_type("SMTP")


class TestCheckEndpointName:
    def test_valid_simple(self):
        assert _check_endpoint_name("mail1") == "mail1"

    def test_valid_with_hyphen(self):
        assert _check_endpoint_name("alert-smtp") == "alert-smtp"

    def test_slash_raises(self):
        with pytest.raises(ProximoError, match="invalid notification endpoint/matcher name"):
            _check_endpoint_name("name/slash")

    def test_trailing_newline_raises(self):
        """\\Z anchoring: a trailing newline must not slip through."""
        with pytest.raises(ProximoError):
            _check_endpoint_name("name\n")

    def test_empty_raises(self):
        with pytest.raises(ProximoError):
            _check_endpoint_name("")

    def test_control_char_raises(self):
        with pytest.raises(ProximoError):
            _check_endpoint_name("name\x00")


class TestCheckMetricsId:
    def test_valid(self):
        assert _check_metrics_id("influx1") == "influx1"

    def test_valid_with_underscore(self):
        assert _check_metrics_id("influx_prod") == "influx_prod"

    def test_trailing_newline_raises(self):
        with pytest.raises(ProximoError, match="invalid metrics server ID"):
            _check_metrics_id("influx1\n")

    def test_slash_raises(self):
        with pytest.raises(ProximoError):
            _check_metrics_id("influx/slash")

    def test_empty_raises(self):
        with pytest.raises(ProximoError):
            _check_metrics_id("")


# ---------------------------------------------------------------------------
# PVE Notification Endpoint operations
# ---------------------------------------------------------------------------

class TestNotificationEndpointList:
    def test_calls_correct_path(self):
        api = _Api(get_return=[{"type": "smtp", "name": "mail1"}])
        result = notification_endpoint_list(api)
        assert api.gets == ["/cluster/notifications/endpoints"]
        assert result == [{"type": "smtp", "name": "mail1"}]

    def test_empty_api_returns_empty_list(self):
        api = _Api(get_return=None)
        result = notification_endpoint_list(api)
        assert result == []


class TestNotificationEndpointGet:
    def test_correct_path(self):
        api = _Api(get_return={"name": "mail1", "server": "smtp.example.com"})
        result = notification_endpoint_get(api, "smtp", "mail1")
        assert api.gets == ["/cluster/notifications/endpoints/smtp/mail1"]
        assert result["name"] == "mail1"

    def test_invalid_type_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_endpoint_get(api, "slack", "n1")

    def test_invalid_name_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_endpoint_get(api, "smtp", "name/slash")

    def test_trailing_newline_on_name_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_endpoint_get(api, "smtp", "mail1\n")


class TestNotificationEndpointCreate:
    def test_posts_to_correct_path(self):
        api = _Api()
        notification_endpoint_create(api, "smtp", "mail1", server="smtp.example.com")
        assert len(api.posts) == 1
        path, data = api.posts[0]
        # live-confirmed 2026-06-25: PVE create = POST to the TYPE path with name in the BODY
        # (POST to .../{type}/{name} returns 501 Not Implemented).
        assert path == "/cluster/notifications/endpoints/smtp"
        assert data["name"] == "mail1"
        assert data["server"] == "smtp.example.com"

    def test_none_kwargs_excluded(self):
        api = _Api()
        notification_endpoint_create(api, "smtp", "mail1", server=None)
        _, data = api.posts[0]
        assert "server" not in data

    def test_invalid_type_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_endpoint_create(api, "discord", "n1")

    def test_invalid_name_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_endpoint_create(api, "smtp", "bad/name")


class TestNotificationEndpointUpdate:
    def test_puts_to_correct_path(self):
        api = _Api()
        notification_endpoint_update(api, "smtp", "mail1", server="smtp2.example.com")
        assert len(api.puts) == 1
        path, data = api.puts[0]
        assert path == "/cluster/notifications/endpoints/smtp/mail1"
        assert data["server"] == "smtp2.example.com"

    def test_none_kwargs_excluded(self):
        api = _Api()
        notification_endpoint_update(api, "smtp", "mail1", server=None)
        _, data = api.puts[0]
        assert "server" not in data

    def test_invalid_type_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_endpoint_update(api, "slack", "n1")


class TestNotificationEndpointDelete:
    def test_deletes_correct_path(self):
        api = _Api()
        notification_endpoint_delete(api, "smtp", "mail1")
        assert len(api.dels) == 1
        assert api.dels[0][0] == "/cluster/notifications/endpoints/smtp/mail1"

    def test_invalid_type_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_endpoint_delete(api, "badtype", "n1")

    def test_trailing_newline_on_name_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_endpoint_delete(api, "smtp", "mail1\n")


# ---------------------------------------------------------------------------
# PVE Notification Matcher operations
# ---------------------------------------------------------------------------

class TestNotificationMatcherSet:
    # Schema-verified 2026-07-06 (pve-docs api-viewer): /cluster/notifications/matchers/{name}
    # accepts GET/PUT/DELETE only; create is POST on the collection with the name in the body.

    def test_create_posts_to_collection_with_name_in_body(self):
        api = _Api(get_return=[])  # matcher does not exist yet
        notification_matcher_set(api, "all-alerts", comment="route all")
        assert api.gets == ["/cluster/notifications/matchers"]
        assert len(api.posts) == 1 and not api.puts
        path, data = api.posts[0]
        assert path == "/cluster/notifications/matchers"
        assert data["name"] == "all-alerts"
        assert data["comment"] == "route all"

    def test_update_puts_to_name_path(self):
        api = _Api(get_return=[{"name": "all-alerts"}])  # matcher already exists
        notification_matcher_set(api, "all-alerts", comment="route all")
        assert len(api.puts) == 1 and not api.posts
        path, data = api.puts[0]
        assert path == "/cluster/notifications/matchers/all-alerts"
        assert data["comment"] == "route all"
        assert "name" not in data

    def test_none_kwargs_excluded(self):
        api = _Api(get_return=[])
        notification_matcher_set(api, "matcher1", comment=None)
        _, data = api.posts[0]
        assert "comment" not in data

    def test_invalid_name_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_matcher_set(api, "bad/name")

    def test_trailing_newline_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_matcher_set(api, "matcher\n")


class TestNotificationMatcherDelete:
    def test_deletes_correct_path(self):
        api = _Api()
        notification_matcher_delete(api, "all-alerts")
        assert api.dels[0][0] == "/cluster/notifications/matchers/all-alerts"

    def test_invalid_name_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_matcher_delete(api, "bad/name")


# ---------------------------------------------------------------------------
# PVE Notification Test
# ---------------------------------------------------------------------------

class TestNotificationTest:
    def test_posts_to_correct_path(self):
        api = _Api()
        notification_test(api, "smtp1")
        assert len(api.posts) == 1
        assert api.posts[0][0] == "/cluster/notifications/targets/smtp1/test"

    def test_invalid_name_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_test(api, "bad/name")

    def test_trailing_newline_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            notification_test(api, "smtp1\n")


# ---------------------------------------------------------------------------
# PVE Metrics Server operations
# ---------------------------------------------------------------------------

class TestMetricsServerList:
    def test_calls_correct_path(self):
        api = _Api(get_return=[{"id": "influx1", "type": "influxdb"}])
        result = metrics_server_list(api)
        assert api.gets == ["/cluster/metrics/server"]
        assert result == [{"id": "influx1", "type": "influxdb"}]

    def test_empty_api_returns_empty_list(self):
        api = _Api(get_return=None)
        assert metrics_server_list(api) == []


class TestMetricsServerSet:
    def test_posts_to_correct_path(self):
        api = _Api()
        metrics_server_set(api, "influx1", type="influxdb", server="influx.example.com")
        assert len(api.posts) == 1
        path, data = api.posts[0]
        assert path == "/cluster/metrics/server/influx1"
        assert data["type"] == "influxdb"
        assert data["server"] == "influx.example.com"

    def test_none_kwargs_excluded(self):
        api = _Api()
        metrics_server_set(api, "influx1", server=None)
        _, data = api.posts[0]
        assert "server" not in data

    def test_invalid_id_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            metrics_server_set(api, "bad/id")

    def test_trailing_newline_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            metrics_server_set(api, "influx1\n")


class TestMetricsServerDelete:
    def test_deletes_correct_path(self):
        api = _Api()
        metrics_server_delete(api, "influx1")
        assert api.dels[0][0] == "/cluster/metrics/server/influx1"

    def test_invalid_id_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            metrics_server_delete(api, "bad/id")

    def test_trailing_newline_raises(self):
        api = _Api()
        with pytest.raises(ProximoError):
            metrics_server_delete(api, "influx1\n")


# ---------------------------------------------------------------------------
# Plan factories — Notification Endpoints
# ---------------------------------------------------------------------------

class TestPlanNotificationEndpointCreate:
    def test_is_low_risk(self):
        plan = plan_notification_endpoint_create("smtp", "mail1")
        assert plan.risk == RISK_LOW

    def test_current_is_empty(self):
        plan = plan_notification_endpoint_create("smtp", "mail1")
        assert plan.current == {}

    def test_target_correct(self):
        plan = plan_notification_endpoint_create("gotify", "gotify1")
        assert plan.target == "cluster/notifications/endpoints/gotify/gotify1"

    def test_change_includes_type_and_name(self):
        plan = plan_notification_endpoint_create("smtp", "mail1")
        assert "smtp" in plan.change and "mail1" in plan.change

    def test_invalid_type_raises(self):
        with pytest.raises(ProximoError):
            plan_notification_endpoint_create("slack", "n1")

    def test_invalid_name_raises(self):
        with pytest.raises(ProximoError):
            plan_notification_endpoint_create("smtp", "bad/name")

    def test_redacts_token_from_change(self):
        # gotify's `token` is a bearer auth secret. plan.change is BOTH returned to the
        # caller AND written to the tamper-evident PROVE ledger, even on confirm=False.
        plan = plan_notification_endpoint_create("gotify", "gotify1", token="LIVETOKEN")
        assert "LIVETOKEN" not in plan.change
        assert "[redacted]" in plan.change

    def test_redacts_password_from_change(self):
        # smtp's `password` is an SMTP-AUTH secret.
        plan = plan_notification_endpoint_create("smtp", "mail1", password="LIVEPW")
        assert "LIVEPW" not in plan.change
        assert "[redacted]" in plan.change

    def test_redacts_webhook_secret_from_change(self):
        # webhook's `secret` array carries HMAC/auth secrets (value base64-encoded by PVE).
        # Same leak surface as token/password: change is returned AND ledgered on confirm=False.
        plan = plan_notification_endpoint_create("webhook", "hook1", secret="LIVEHMAC")
        assert "LIVEHMAC" not in plan.change
        assert "[redacted]" in plan.change

    def test_redacts_webhook_header_from_change(self):
        # webhook's `header` can carry `Authorization=Bearer ...`.
        plan = plan_notification_endpoint_create("webhook", "hook1", header="Authorization=Bearer LIVEBEARER")
        assert "LIVEBEARER" not in plan.change
        assert "[redacted]" in plan.change


class TestPlanNotificationEndpointUpdate:
    def test_reads_current_from_api(self):
        api = _Api(get_return={"name": "mail1", "server": "smtp.example.com"})
        plan = plan_notification_endpoint_update(api, "smtp", "mail1")
        assert plan.risk == RISK_LOW
        assert "name" in plan.current   # captured from fake API

    def test_redacts_token_from_current(self):
        # The live GET result is stored in Plan.current (PROVE ledger) even when the
        # update call itself doesn't touch the token field.
        api = _Api(get_return={"name": "gotify1", "token": "LIVETOKEN"})
        plan = plan_notification_endpoint_update(api, "gotify", "gotify1", server="new-host")
        assert "LIVETOKEN" not in str(plan.current)
        assert plan.current["token"] == "[redacted]"

    def test_redacts_token_from_change(self):
        api = _Api(get_return={"name": "gotify1"})
        plan = plan_notification_endpoint_update(api, "gotify", "gotify1", token="NEWTOKEN")
        assert "NEWTOKEN" not in plan.change
        assert "[redacted]" in plan.change

    def test_no_implied_undo_in_note(self):
        api = _Api(get_return={"name": "mail1"})
        plan = plan_notification_endpoint_update(api, "smtp", "mail1")
        note_lower = plan.note.lower()
        assert "no snapshot" in note_lower or "no undo" in note_lower or "re-apply" in note_lower


class TestPlanNotificationEndpointDelete:
    def test_reads_current_from_api(self):
        api = _Api(get_return={"name": "mail1", "type": "smtp"})
        plan = plan_notification_endpoint_delete(api, "smtp", "mail1")
        assert plan.risk == RISK_LOW
        assert "name" in plan.current

    def test_warn_about_silent_failure(self):
        api = _Api(get_return={"name": "mail1"})
        plan = plan_notification_endpoint_delete(api, "smtp", "mail1")
        note_upper = plan.note.upper()
        assert "WARN" in note_upper

    def test_redacts_webhook_secret_and_header_from_current(self):
        # A webhook endpoint's stored secret/header come back from the live GET and land in
        # plan.current (returned to caller AND written to the tamper-evident ledger). The
        # delete path previously stored current unredacted.
        api = _Api(get_return={"name": "hook1", "type": "webhook",
                               "secret": "LIVEHMAC", "header": "Authorization=Bearer LIVEBEARER"})
        plan = plan_notification_endpoint_delete(api, "webhook", "hook1")
        assert "LIVEHMAC" not in str(plan.current)
        assert "LIVEBEARER" not in str(plan.current)
        assert plan.current["secret"] == "[redacted]"
        assert plan.current["header"] == "[redacted]"


# ---------------------------------------------------------------------------
# Plan factories — Notification Matchers
# ---------------------------------------------------------------------------

class TestPlanNotificationMatcherSet:
    def test_is_low_risk(self):
        plan = plan_notification_matcher_set("all-alerts")
        assert plan.risk == RISK_LOW

    def test_current_is_empty(self):
        plan = plan_notification_matcher_set("all-alerts")
        assert plan.current == {}

    def test_invalid_name_raises(self):
        with pytest.raises(ProximoError):
            plan_notification_matcher_set("bad/name")


class TestPlanNotificationMatcherDelete:
    def test_is_low_risk(self):
        plan = plan_notification_matcher_delete("all-alerts")
        assert plan.risk == RISK_LOW

    def test_warn_in_note(self):
        plan = plan_notification_matcher_delete("all-alerts")
        assert "WARN" in plan.note.upper()

    def test_invalid_name_raises(self):
        with pytest.raises(ProximoError):
            plan_notification_matcher_delete("bad/name")


# ---------------------------------------------------------------------------
# Plan factories — Notification Test
# ---------------------------------------------------------------------------

class TestPlanNotificationTest:
    def test_is_low_risk(self):
        plan = plan_notification_test("smtp1")
        assert plan.risk == RISK_LOW

    def test_current_is_empty(self):
        plan = plan_notification_test("smtp1")
        assert plan.current == {}

    def test_change_mentions_test_notification(self):
        plan = plan_notification_test("smtp1")
        assert "test" in plan.change.lower()

    def test_invalid_name_raises(self):
        with pytest.raises(ProximoError):
            plan_notification_test("bad/name")


# ---------------------------------------------------------------------------
# Plan factories — Metrics Servers
# ---------------------------------------------------------------------------

class TestPlanMetricsServerSet:
    def test_is_low_risk(self):
        plan = plan_metrics_server_set("influx1")
        assert plan.risk == RISK_LOW

    def test_current_is_empty(self):
        plan = plan_metrics_server_set("influx1")
        assert plan.current == {}

    def test_target_correct(self):
        plan = plan_metrics_server_set("influx1")
        assert plan.target == "cluster/metrics/server/influx1"

    def test_invalid_id_raises(self):
        with pytest.raises(ProximoError):
            plan_metrics_server_set("bad/id")

    def test_redacts_token_from_change(self):
        # PVE's live /cluster/metrics/server schema DOES carry an optional per-server `token`
        # field (InfluxDB http v2 access token) — mirrors plan_notification_endpoint_create's
        # own gotify-token redaction test above (Wave 5b review finding 2: this factory built
        # its change string from raw kw while its siblings redacted).
        plan = plan_metrics_server_set("influx1", token="LIVETOKEN")
        assert "LIVETOKEN" not in plan.change
        assert "[redacted]" in plan.change


class TestPlanMetricsServerDelete:
    def test_is_low_risk(self):
        plan = plan_metrics_server_delete("influx1")
        assert plan.risk == RISK_LOW

    def test_current_is_empty(self):
        plan = plan_metrics_server_delete("influx1")
        assert plan.current == {}

    def test_blast_radius_mentions_metrics_stop(self):
        plan = plan_metrics_server_delete("influx1")
        blast_text = " ".join(plan.blast_radius).lower()
        assert "metrics" in blast_text or "forwarding" in blast_text

    def test_invalid_id_raises(self):
        with pytest.raises(ProximoError):
            plan_metrics_server_delete("bad/id")
