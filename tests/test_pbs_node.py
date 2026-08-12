"""PBS node OS admin plane tests (Wave 2c, full-surface campaign) — fully mocked, no live PBS.

Mirrors test_pbs_access.py's style: `_api()` is a minimal recording fake for backend-function
tests (path/verb/payload shape); validator-rejection tests use pytest.raises(ProximoError); plan
tests verify honest risk ratings, blast-radius content, and CAPTURE-or-declare behavior.

Covers: validators (iface, iface type, digest, service name/action, lockout-set membership);
backend functions for all 27 ops (13 read, 14 mutation); plan factories (risk ratings,
blast-radius content, CAPTURE-or-declare where applicable); module structure (the PBS/PVE schema
differences named in the module docstring — no hosts endpoint, restart params excluded, etc).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from proximo.backends import ProximoError
from proximo.pbs_node import (
    _check_digest,
    _check_iface,
    _check_iface_type,
    _check_service,
    _check_service_action,
    _is_lockout_service,
    _key_fingerprint,
    _normalize_service_name,
    cert_delete,
    cert_upload,
    certificates_list,
    dns_get,
    dns_set,
    journal,
    network_iface_create,
    network_iface_delete,
    network_iface_get,
    network_iface_update,
    network_list,
    network_reload,
    network_revert,
    node_status,
    plan_cert_delete,
    plan_cert_upload,
    plan_dns_set,
    plan_network_iface_create,
    plan_network_iface_delete,
    plan_network_iface_update,
    plan_network_reload,
    plan_network_revert,
    plan_service_control,
    plan_subscription_check,
    plan_subscription_delete,
    plan_subscription_set,
    plan_task_stop,
    plan_time_set,
    service_control,
    service_status,
    services_list,
    subscription_check,
    subscription_delete,
    subscription_get,
    subscription_set,
    syslog,
    task_log,
    task_status,
    task_stop,
    time_get,
    time_set,
)
from proximo.planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM

# ---------------------------------------------------------------------------
# Fake API
# ---------------------------------------------------------------------------

def _api(get_return=None, raise_on_get=None) -> SimpleNamespace:
    """Minimal PBS API fake recording the LAST _get/_post/_put/_delete call."""
    seen: dict = {}

    def fake_get(path, params=None):
        seen["get_path"] = path
        seen["get_params"] = params
        if raise_on_get is not None:
            raise raise_on_get
        return get_return

    def fake_post(path, data=None):
        seen["post_path"] = path
        seen["post_data"] = data
        return None

    def fake_put(path, data=None):
        seen["put_path"] = path
        seen["put_data"] = data
        return None

    def fake_delete(path, params=None):
        seen["delete_path"] = path
        seen["delete_params"] = params
        return None

    return SimpleNamespace(
        _get=fake_get, _post=fake_post, _put=fake_put, _delete=fake_delete, seen=seen,
    )


# ---------------------------------------------------------------------------
# Module structure — the schema differences named in the module docstring
# ---------------------------------------------------------------------------

def test_module_docstring_names_the_hosts_exclusion_and_restart_noop():
    import proximo.pbs_node as m
    doc = m.__doc__ or ""
    assert "hosts" in doc.lower()
    assert "ignored" in doc.lower()  # the cert restart-param no-op


def test_no_hosts_functions_exist():
    import proximo.pbs_node as m
    assert not hasattr(m, "hosts_get")
    assert not hasattr(m, "hosts_set")


def test_no_node_power_function_exists():
    """POST /nodes/{node}/status (reboot/shutdown) is deliberately excluded."""
    import proximo.pbs_node as m
    assert not hasattr(m, "node_reboot")
    assert not hasattr(m, "node_shutdown")
    assert not hasattr(m, "node_power")


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

class TestCheckIface:
    def test_valid(self):
        assert _check_iface("eth0") == "eth0"
        assert _check_iface("vmbr0") == "vmbr0"

    def test_rejects_traversal(self):
        with pytest.raises(ProximoError):
            _check_iface("..")

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_iface("eth0/foo")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_iface("a" * 20)

    def test_rejects_leading_dot(self):
        with pytest.raises(ProximoError):
            _check_iface(".eth0")


class TestCheckIfaceType:
    def test_valid_values(self):
        for t in ("loopback", "eth", "bridge", "bond", "vlan", "alias", "unknown"):
            assert _check_iface_type(t) == t

    def test_rejects_ovs_types(self):
        """PBS has NO OVS types, unlike PVE."""
        with pytest.raises(ProximoError):
            _check_iface_type("OVSBridge")

    def test_rejects_unknown_string(self):
        with pytest.raises(ProximoError):
            _check_iface_type("bogus")


class TestCheckDigest:
    def test_none_passthrough(self):
        assert _check_digest(None) is None

    def test_valid(self):
        d = "a" * 64
        assert _check_digest(d) == d

    def test_rejects_wrong_length(self):
        with pytest.raises(ProximoError):
            _check_digest("abc")

    def test_rejects_uppercase(self):
        with pytest.raises(ProximoError):
            _check_digest("A" * 64)

    def test_rejects_trailing_newline(self):
        # A11 tightening: the retired per-module copy .strip()ped before matching, which
        # re-admitted the trailing newline the \Z anchor exists to refuse.
        with pytest.raises(ProximoError):
            _check_digest("a" * 64 + "\n")


class TestCheckService:
    def test_valid(self):
        assert _check_service("proxmox-backup-proxy") == "proxmox-backup-proxy"
        assert _check_service("sshd.service") == "sshd.service"

    def test_rejects_whitespace(self):
        with pytest.raises(ProximoError):
            _check_service("sshd extra")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_service("a" * 65)


class TestCheckServiceAction:
    def test_valid_actions(self):
        for a in ("start", "stop", "restart", "reload"):
            assert _check_service_action(a) == a

    def test_rejects_unknown(self):
        with pytest.raises(ProximoError):
            _check_service_action("kill")


class TestLockoutSet:
    def test_proxmox_backup_proxy_is_lockout(self):
        assert _is_lockout_service("proxmox-backup-proxy") is True

    def test_proxmox_backup_is_lockout(self):
        assert _is_lockout_service("proxmox-backup") is True

    def test_case_insensitive_with_service_suffix(self):
        assert _is_lockout_service("SSHD.service") is True

    def test_non_lockout_service(self):
        assert _is_lockout_service("cron") is False

    def test_normalize_strips_service_suffix_and_lowers(self):
        assert _normalize_service_name("Chrony.SERVICE".lower()) == "chrony"


def test_key_fingerprint_is_unconditional_redaction_marker():
    assert _key_fingerprint() == {"key": "[redacted]"}


# ---------------------------------------------------------------------------
# Backend functions — DNS / Time
# ---------------------------------------------------------------------------

class TestDnsGet:
    def test_path_defaults_localhost(self):
        api = _api(get_return={"search": "example.test"})
        result = dns_get(api)
        assert api.seen["get_path"] == "/nodes/localhost/dns"
        assert result == {"search": "example.test"}

    def test_returns_dict_on_none(self):
        api = _api(get_return=None)
        assert dns_get(api) == {}


class TestDnsSet:
    def test_minimal_payload(self):
        api = _api()
        dns_set(api, search="example.test", dns1="9.9.9.9")
        assert api.seen["put_path"] == "/nodes/localhost/dns"
        assert api.seen["put_data"] == {"search": "example.test", "dns1": "9.9.9.9"}

    def test_delete_props_comma_joined(self):
        api = _api()
        dns_set(api, delete_props=["dns2", "dns3"])
        assert api.seen["put_data"] == {"delete": "dns2,dns3"}

    def test_digest_forwarded(self):
        api = _api()
        digest = "b" * 64
        dns_set(api, dns1="1.1.1.1", digest=digest)
        assert api.seen["put_data"]["digest"] == digest

    def test_no_op_sends_none_body(self):
        api = _api()
        dns_set(api)
        assert api.seen["put_data"] is None


class TestTimeGet:
    def test_path(self):
        api = _api(get_return={"timezone": "UTC"})
        result = time_get(api)
        assert api.seen["get_path"] == "/nodes/localhost/time"
        assert result == {"timezone": "UTC"}


class TestTimeSet:
    def test_payload(self):
        api = _api()
        time_set(api, "Europe/Berlin")
        assert api.seen["put_path"] == "/nodes/localhost/time"
        assert api.seen["put_data"] == {"timezone": "Europe/Berlin"}


# ---------------------------------------------------------------------------
# Backend functions — Network
# ---------------------------------------------------------------------------

class TestNetworkList:
    def test_path(self):
        api = _api(get_return=[{"name": "eth0"}])
        result = network_list(api)
        assert api.seen["get_path"] == "/nodes/localhost/network"
        assert result == [{"name": "eth0"}]

    def test_returns_list_on_none(self):
        api = _api(get_return=None)
        assert network_list(api) == []


class TestNetworkIfaceGet:
    def test_path(self):
        api = _api(get_return={"iface": "eth0"})
        result = network_iface_get(api, "eth0")
        assert api.seen["get_path"] == "/nodes/localhost/network/eth0"
        assert result == {"iface": "eth0"}


class TestNetworkIfaceCreate:
    def test_iface_only(self):
        api = _api()
        network_iface_create(api, "eth1")
        assert api.seen["post_path"] == "/nodes/localhost/network"
        assert api.seen["post_data"] == {"iface": "eth1"}

    def test_type_optional_but_validated(self):
        api = _api()
        network_iface_create(api, "eth1", iface_type="bridge")
        assert api.seen["post_data"] == {"iface": "eth1", "type": "bridge"}

    def test_extra_opts_forwarded(self):
        api = _api()
        network_iface_create(api, "vmbr1", iface_type="bridge", bridge_ports="eth0", autostart=True)
        assert api.seen["post_data"] == {
            "iface": "vmbr1", "type": "bridge", "bridge_ports": "eth0", "autostart": True,
        }

    def test_rejects_reserved_kwarg_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            network_iface_create(api, "eth1", type="bridge")

    def test_rejects_invalid_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            network_iface_create(api, "eth1", iface_type="OVSBridge")


class TestNetworkIfaceUpdate:
    def test_no_type_required(self):
        """Unlike PVE, PBS does not require re-sending 'type' on update."""
        api = _api()
        network_iface_update(api, "eth0", cidr="10.0.0.1/24")
        assert api.seen["put_path"] == "/nodes/localhost/network/eth0"
        assert api.seen["put_data"] == {"cidr": "10.0.0.1/24"}

    def test_delete_props_and_digest(self):
        api = _api()
        digest = "c" * 64
        network_iface_update(api, "eth0", delete_props=["mtu"], digest=digest)
        assert api.seen["put_data"] == {"delete": "mtu", "digest": digest}

    def test_rejects_reserved_kwarg_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            network_iface_update(api, "eth0", type="bridge")


class TestNetworkIfaceDelete:
    def test_path_no_digest(self):
        api = _api()
        network_iface_delete(api, "eth1")
        assert api.seen["delete_path"] == "/nodes/localhost/network/eth1"
        assert api.seen["delete_params"] is None

    def test_digest_forwarded(self):
        api = _api()
        digest = "d" * 64
        network_iface_delete(api, "eth1", digest=digest)
        assert api.seen["delete_params"] == {"digest": digest}


class TestNetworkReload:
    def test_put_no_body(self):
        api = _api()
        network_reload(api)
        assert api.seen["put_path"] == "/nodes/localhost/network"
        assert api.seen["put_data"] is None


class TestNetworkRevert:
    def test_delete_network_path(self):
        api = _api()
        network_revert(api)
        assert api.seen["delete_path"] == "/nodes/localhost/network"


# ---------------------------------------------------------------------------
# Backend functions — Certificates
# ---------------------------------------------------------------------------

class TestCertificatesList:
    def test_path(self):
        api = _api(get_return=[{"filename": "pveproxy-ssl.pem"}])
        result = certificates_list(api)
        assert api.seen["get_path"] == "/nodes/localhost/certificates/info"
        assert result == [{"filename": "pveproxy-ssl.pem"}]


class TestCertUpload:
    def test_cert_only(self):
        api = _api()
        cert_upload(api, "PEM-CERT-BODY")
        assert api.seen["post_path"] == "/nodes/localhost/certificates/custom"
        assert api.seen["post_data"] == {"certificates": "PEM-CERT-BODY"}

    def test_key_and_force_forwarded(self):
        api = _api()
        cert_upload(api, "PEM-CERT-BODY", key="PEM-KEY-BODY", force=True)
        assert api.seen["post_data"] == {
            "certificates": "PEM-CERT-BODY", "key": "PEM-KEY-BODY", "force": True,
        }

    def test_no_restart_param_reaches_api(self):
        """PBS documents 'restart' as ignored on this endpoint — never sent."""
        api = _api()
        cert_upload(api, "PEM-CERT-BODY")
        assert "restart" not in api.seen["post_data"]

    def test_returns_list_on_none(self):
        api = _api()
        assert cert_upload(api, "PEM-CERT-BODY") == []


class TestCertDelete:
    def test_path_no_restart_param(self):
        api = _api()
        cert_delete(api)
        assert api.seen["delete_path"] == "/nodes/localhost/certificates/custom"
        assert api.seen["delete_params"] is None


# ---------------------------------------------------------------------------
# Backend functions — Services
# ---------------------------------------------------------------------------

class TestServicesList:
    def test_path(self):
        api = _api(get_return=[{"service": "sshd"}])
        result = services_list(api)
        assert api.seen["get_path"] == "/nodes/localhost/services"
        assert result == [{"service": "sshd"}]


class TestServiceStatus:
    def test_path(self):
        api = _api(get_return={"service": "sshd", "state": "running"})
        result = service_status(api, "sshd")
        assert api.seen["get_path"] == "/nodes/localhost/services/sshd/state"
        assert result == {"service": "sshd", "state": "running"}


class TestServiceControl:
    def test_path_per_action(self):
        api = _api()
        service_control(api, "proxmox-backup-proxy", "restart")
        assert api.seen["post_path"] == "/nodes/localhost/services/proxmox-backup-proxy/restart"

    def test_rejects_invalid_action(self):
        api = _api()
        with pytest.raises(ProximoError):
            service_control(api, "sshd", "kill")


# ---------------------------------------------------------------------------
# Backend functions — Subscription
# ---------------------------------------------------------------------------

class TestSubscriptionGet:
    def test_path(self):
        api = _api(get_return={"status": "active"})
        result = subscription_get(api)
        assert api.seen["get_path"] == "/nodes/localhost/subscription"
        assert result == {"status": "active"}


class TestSubscriptionSet:
    def test_key_payload(self):
        api = _api()
        subscription_set(api, "pbss-FAKE-KEY-sentinel")
        assert api.seen["put_path"] == "/nodes/localhost/subscription"
        assert api.seen["put_data"] == {"key": "pbss-FAKE-KEY-sentinel"}


class TestSubscriptionCheck:
    def test_default_no_body(self):
        api = _api()
        subscription_check(api)
        assert api.seen["post_path"] == "/nodes/localhost/subscription"
        assert api.seen["post_data"] is None

    def test_force_sends_true(self):
        api = _api()
        subscription_check(api, force=True)
        assert api.seen["post_data"] == {"force": True}


class TestSubscriptionDelete:
    def test_path(self):
        api = _api()
        subscription_delete(api)
        assert api.seen["delete_path"] == "/nodes/localhost/subscription"


# ---------------------------------------------------------------------------
# Backend functions — Status
# ---------------------------------------------------------------------------

class TestNodeStatus:
    def test_path(self):
        api = _api(get_return={"cpu": 0.1})
        result = node_status(api)
        assert api.seen["get_path"] == "/nodes/localhost/status"
        assert result == {"cpu": 0.1}


# ---------------------------------------------------------------------------
# Backend functions — Tasks
# ---------------------------------------------------------------------------

_UPID = "UPID:localhost:00001234:0000ABCD:00000000:00000001:backup:ds1:root@pam:"


class TestTaskStatus:
    def test_path(self):
        api = _api(get_return={"status": "stopped", "exitstatus": "OK"})
        result = task_status(api, _UPID)
        assert api.seen["get_path"] == f"/nodes/localhost/tasks/{_UPID}/status"
        assert result == {"status": "stopped", "exitstatus": "OK"}

    def test_rejects_invalid_upid(self):
        api = _api()
        with pytest.raises(ProximoError):
            task_status(api, "not-a-upid")


class TestTaskLog:
    def test_default_params(self):
        api = _api(get_return=[{"n": 1, "t": "line one"}])
        result = task_log(api, _UPID)
        assert api.seen["get_path"] == f"/nodes/localhost/tasks/{_UPID}/log"
        assert api.seen["get_params"] == {"start": 0, "limit": 50}
        assert result == [{"n": 1, "t": "line one"}]

    def test_custom_params(self):
        api = _api(get_return=[])
        task_log(api, _UPID, start=10, limit=5)
        assert api.seen["get_params"] == {"start": 10, "limit": 5}

    def test_rejects_negative_start(self):
        api = _api()
        with pytest.raises(ProximoError):
            task_log(api, _UPID, start=-1)


class TestTaskStop:
    def test_path_no_params(self):
        api = _api()
        task_stop(api, _UPID)
        assert api.seen["delete_path"] == f"/nodes/localhost/tasks/{_UPID}"


# ---------------------------------------------------------------------------
# Backend functions — Journal / Syslog
# ---------------------------------------------------------------------------

class TestJournal:
    def test_default_no_params(self):
        api = _api(get_return=["-- cursor --", "line one"])
        result = journal(api)
        assert api.seen["get_path"] == "/nodes/localhost/journal"
        assert api.seen["get_params"] is None
        assert result == ["-- cursor --", "line one"]

    def test_since_until_are_ints(self):
        api = _api(get_return=[])
        journal(api, since=1700000000, until=1700003600)
        assert api.seen["get_params"] == {"since": 1700000000, "until": 1700003600}

    def test_lastentries_and_cursors(self):
        api = _api(get_return=[])
        journal(api, lastentries=100, startcursor="abc", endcursor="def")
        assert api.seen["get_params"] == {
            "lastentries": 100, "startcursor": "abc", "endcursor": "def",
        }

    def test_returns_list_on_none(self):
        api = _api(get_return=None)
        assert journal(api) == []


class TestSyslog:
    def test_default_no_params(self):
        api = _api(get_return=[{"n": 1, "t": "line"}])
        result = syslog(api)
        assert api.seen["get_path"] == "/nodes/localhost/syslog"
        assert api.seen["get_params"] is None
        assert result == [{"n": 1, "t": "line"}]

    def test_all_params_forwarded(self):
        api = _api(get_return=[])
        syslog(api, limit=50, start=0, since="2026-07-15", until="2026-07-16", service="sshd")
        assert api.seen["get_params"] == {
            "limit": 50, "start": 0, "since": "2026-07-15", "until": "2026-07-16", "service": "sshd",
        }


# ---------------------------------------------------------------------------
# Plan factories — DNS / Time (CAPTURE-or-declare)
# ---------------------------------------------------------------------------

class TestPlanDnsSet:
    def test_risk_medium_and_captures_current(self):
        api = _api(get_return={"search": "old.test", "dns1": "1.1.1.1"})
        plan = plan_dns_set(api, search="new.test")
        assert plan.risk == RISK_MEDIUM
        assert plan.complete is True
        assert plan.current == {"search": "old.test", "dns1": "1.1.1.1"}

    def test_capture_failure_sets_incomplete(self):
        api = _api(raise_on_get=RuntimeError("boom"))
        plan = plan_dns_set(api, search="new.test")
        assert plan.complete is False
        assert "could not capture" in plan.note.lower()


class TestPlanTimeSet:
    def test_risk_low_and_captures_current(self):
        api = _api(get_return={"timezone": "UTC"})
        plan = plan_time_set(api, "Europe/Berlin")
        assert plan.risk == RISK_LOW
        assert plan.current == {"timezone": "UTC"}

    def test_capture_failure_sets_incomplete(self):
        api = _api(raise_on_get=RuntimeError("boom"))
        plan = plan_time_set(api, "UTC")
        assert plan.complete is False


# ---------------------------------------------------------------------------
# Plan factories — Network
# ---------------------------------------------------------------------------

class TestPlanNetworkIfaceCreate:
    def test_risk_medium_no_collision(self):
        api = _api(get_return=[{"name": "eth0"}])
        plan = plan_network_iface_create(api, "eth1")
        assert plan.risk == RISK_MEDIUM
        assert any("eth1" in b for b in plan.blast_radius)

    def test_collision_flagged(self):
        api = _api(get_return=[{"name": "eth1"}])
        plan = plan_network_iface_create(api, "eth1")
        assert any("FAIL" in b for b in plan.blast_radius)

    def test_reload_and_revert_named_in_note(self):
        api = _api(get_return=[])
        plan = plan_network_iface_create(api, "eth1")
        assert "network_reload" in plan.note
        assert "RISK_HIGH" in plan.note


class TestPlanNetworkIfaceUpdate:
    def test_risk_medium_reads_current(self):
        api = _api(get_return={"iface": "eth0", "cidr": "10.0.0.1/24"})
        plan = plan_network_iface_update(api, "eth0", opts={"mtu": 9000})
        assert plan.risk == RISK_MEDIUM
        assert plan.current == {"iface": "eth0", "cidr": "10.0.0.1/24"}


class TestPlanNetworkIfaceDelete:
    def test_risk_medium(self):
        api = _api(get_return={"iface": "eth1"})
        plan = plan_network_iface_delete(api, "eth1")
        assert plan.risk == RISK_MEDIUM
        assert "eth1" in plan.change


class TestPlanNetworkReload:
    def test_risk_high_unconditional(self):
        plan = plan_network_reload()
        assert plan.risk == RISK_HIGH
        assert "LOCKOUT" in " ".join(plan.blast_radius).upper()


class TestPlanNetworkRevert:
    def test_risk_low_safe_undo(self):
        plan = plan_network_revert()
        assert plan.risk == RISK_LOW


# ---------------------------------------------------------------------------
# Plan factories — Certificates
# ---------------------------------------------------------------------------

class TestPlanCertUpload:
    def test_risk_high_no_key_in_plan(self):
        plan = plan_cert_upload("PEM-CERT-BODY-not-real-secretkeymaterial")
        assert plan.risk == RISK_HIGH
        assert "key" not in plan.as_dict()
        # the cert body IS public and may appear in the plan preview
        assert "PEM-CERT" in plan.change


class TestPlanCertDelete:
    def test_risk_medium_recoverable(self):
        plan = plan_cert_delete()
        assert plan.risk == RISK_MEDIUM
        assert "self-signed" in plan.change.lower()


# ---------------------------------------------------------------------------
# Plan factories — Services (lockout-aware, mirrors PVE's observability.py table)
# ---------------------------------------------------------------------------

class TestPlanServiceControl:
    def test_lockout_stop_is_high(self):
        plan = plan_service_control("proxmox-backup-proxy", "stop")
        assert plan.risk == RISK_HIGH

    def test_lockout_restart_is_high(self):
        plan = plan_service_control("sshd", "restart")
        assert plan.risk == RISK_HIGH

    def test_lockout_start_is_low(self):
        plan = plan_service_control("proxmox-backup", "start")
        assert plan.risk == RISK_LOW

    def test_non_lockout_stop_is_medium(self):
        plan = plan_service_control("cron", "stop")
        assert plan.risk == RISK_MEDIUM

    def test_non_lockout_start_is_low(self):
        plan = plan_service_control("cron", "start")
        assert plan.risk == RISK_LOW

    def test_no_undo_note_present(self):
        plan = plan_service_control("cron", "restart")
        assert "not automatic" in plan.note.lower()


# ---------------------------------------------------------------------------
# Plan factories — Subscription
# ---------------------------------------------------------------------------

class TestPlanSubscriptionSet:
    def test_risk_medium(self):
        plan = plan_subscription_set("pbss-FAKE-KEY-sentinel")
        assert plan.risk == RISK_MEDIUM


class TestPlanSubscriptionCheck:
    def test_risk_low(self):
        plan = plan_subscription_check()
        assert plan.risk == RISK_LOW


class TestPlanSubscriptionDelete:
    def test_risk_medium_reversible(self):
        plan = plan_subscription_delete()
        assert plan.risk == RISK_MEDIUM
        assert "reversible" in plan.note.lower()


# ---------------------------------------------------------------------------
# Plan factories — Tasks
# ---------------------------------------------------------------------------

class TestPlanTaskStop:
    def test_risk_high_matches_pve_rating(self):
        """Deliberately HIGH, matching PVE's actual shipped tasks_pools.plan_task_stop rating
        for the identical operation — not the MEDIUM a first pass might guess."""
        plan = plan_task_stop(_UPID)
        assert plan.risk == RISK_HIGH
        assert "no undo" in plan.note.lower()
