"""OBSERVABILITY pillar tests.

Fully mocked, no live Proxmox.  Mirrors test_cluster_ops.py style:
- _api() records _get / _post calls; assertions verify URL + param shapes.
- Validator-rejection tests use pytest.raises(ProximoError).
- plan_node_service_control honesty tests cover every risk branch:
  lockout-service stop/restart/reload (HIGH), lockout start (LOW),
  non-lockout stop/restart (MEDIUM), non-lockout start/reload (LOW).
- Lockout membership tests verify case-insensitivity and .service suffix tolerance.
- Newline-injection tests confirm shell-metacharacter rejection.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from proximo.backends import ProximoError
from proximo.observability import (
    _is_lockout_service,
    node_certificates_info,
    node_dns_get,
    node_journal,
    node_rrddata,
    node_service_control,
    node_service_status,
    node_services_list,
    node_subscription,
    node_syslog,
    plan_node_service_control,
)
from proximo.planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM

# ---------------------------------------------------------------------------
# Shared fake
# ---------------------------------------------------------------------------


def _api(node: str = "pve") -> SimpleNamespace:
    """Minimal API fake that records _get / _post calls."""
    seen: dict = {}

    def fake_get(path):
        seen["method"] = "GET"
        seen["path"] = path
        return []

    def fake_post(path, data=None):
        seen["method"] = "POST"
        seen["path"] = path
        seen["data"] = data or {}
        return "UPID:pve:00001:0:0:0:srvrestart:sshd:root@pam:"

    return SimpleNamespace(
        config=SimpleNamespace(node=node),
        _get=fake_get,
        _post=fake_post,
        seen=seen,
    )


# ---------------------------------------------------------------------------
# node_services_list
# ---------------------------------------------------------------------------


def test_node_services_list_correct_path():
    api = _api()
    node_services_list(api)
    assert api.seen["path"] == "/nodes/pve/services"
    assert api.seen["method"] == "GET"


def test_node_services_list_uses_explicit_node():
    api = _api(node="pve2")
    node_services_list(api, node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_node_services_list_uses_config_node_when_none():
    api = _api(node="nodeA")
    node_services_list(api)
    assert "/nodes/nodeA/" in api.seen["path"]


def test_node_services_list_returns_list():
    api = _api()
    result = node_services_list(api)
    assert isinstance(result, list)


def test_node_services_list_rejects_invalid_node():
    api = _api()
    with pytest.raises(ProximoError):
        node_services_list(api, node="bad/node")


def test_node_services_list_rejects_node_with_newline():
    api = _api()
    with pytest.raises(ProximoError):
        node_services_list(api, node="pve\n")


# ---------------------------------------------------------------------------
# node_service_status
# ---------------------------------------------------------------------------


def test_node_service_status_correct_path():
    api = _api()
    node_service_status(api, "pveproxy")
    assert api.seen["path"] == "/nodes/pve/services/pveproxy/state"
    assert api.seen["method"] == "GET"


def test_node_service_status_uses_explicit_node():
    api = _api(node="pve2")
    node_service_status(api, "sshd", node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_node_service_status_uses_config_node_when_none():
    api = _api(node="nodeB")
    node_service_status(api, "cron")
    assert "/nodes/nodeB/" in api.seen["path"]


def test_node_service_status_returns_dict():
    api = _api()
    api._get = lambda path: {"state": "running"}
    result = node_service_status(api, "pveproxy")
    assert isinstance(result, dict)


def test_node_service_status_returns_empty_dict_on_none():
    api = _api()
    api._get = lambda path: None
    result = node_service_status(api, "pveproxy")
    assert result == {}


def test_node_service_status_rejects_invalid_service():
    api = _api()
    with pytest.raises(ProximoError):
        node_service_status(api, "bad service!")


def test_node_service_status_rejects_service_with_newline():
    api = _api()
    with pytest.raises(ProximoError):
        node_service_status(api, "sshd\n")


def test_node_service_status_rejects_service_with_semicolon():
    api = _api()
    with pytest.raises(ProximoError):
        node_service_status(api, "sshd;rm -rf /")


def test_node_service_status_rejects_invalid_node():
    api = _api()
    with pytest.raises(ProximoError):
        node_service_status(api, "sshd", node="bad node")


# ---------------------------------------------------------------------------
# node_rrddata
# ---------------------------------------------------------------------------


def test_node_rrddata_default_timeframe_is_hour():
    api = _api()
    node_rrddata(api)
    assert "timeframe=hour" in api.seen["path"]


def test_node_rrddata_all_valid_timeframes_accepted():
    for tf in ("hour", "day", "week", "month", "year"):
        api = _api()
        node_rrddata(api, timeframe=tf)
        assert f"timeframe={tf}" in api.seen["path"]


def test_node_rrddata_correct_base_path():
    api = _api()
    node_rrddata(api)
    assert api.seen["path"].startswith("/nodes/pve/rrddata")
    assert api.seen["method"] == "GET"


def test_node_rrddata_with_cf_average():
    api = _api()
    node_rrddata(api, cf="AVERAGE")
    assert "cf=AVERAGE" in api.seen["path"]


def test_node_rrddata_with_cf_max():
    api = _api()
    node_rrddata(api, cf="MAX")
    assert "cf=MAX" in api.seen["path"]


def test_node_rrddata_cf_case_insensitive_normalization():
    """cf='average' should be normalized to 'AVERAGE' without error."""
    api = _api()
    node_rrddata(api, cf="average")
    assert "cf=AVERAGE" in api.seen["path"]


def test_node_rrddata_no_cf_when_not_provided():
    api = _api()
    node_rrddata(api)
    assert "cf=" not in api.seen["path"]


def test_node_rrddata_uses_explicit_node():
    api = _api(node="pve2")
    node_rrddata(api, node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_node_rrddata_rejects_invalid_timeframe():
    api = _api()
    with pytest.raises(ProximoError):
        node_rrddata(api, timeframe="second")


def test_node_rrddata_rejects_invalid_cf():
    api = _api()
    with pytest.raises(ProximoError):
        node_rrddata(api, cf="MIN")


def test_node_rrddata_returns_list():
    api = _api()
    result = node_rrddata(api)
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# node_journal
# ---------------------------------------------------------------------------


def test_node_journal_correct_base_path():
    api = _api()
    node_journal(api)
    assert api.seen["path"].startswith("/nodes/pve/journal")
    assert api.seen["method"] == "GET"


def test_node_journal_default_lastentries():
    api = _api()
    node_journal(api)
    assert "lastentries=100" in api.seen["path"]


def test_node_journal_custom_lastentries():
    api = _api()
    node_journal(api, lastentries=50)
    assert "lastentries=50" in api.seen["path"]


def test_node_journal_includes_since_when_provided():
    api = _api()
    node_journal(api, since="1717200000")
    assert "since=1717200000" in api.seen["path"]


def test_node_journal_includes_until_when_provided():
    api = _api()
    node_journal(api, until="1717286400")
    assert "until=1717286400" in api.seen["path"]


def test_node_journal_both_since_and_until():
    api = _api()
    node_journal(api, since="1717200000", until="1717286400")
    path = api.seen["path"]
    assert "since=1717200000" in path
    assert "until=1717286400" in path


def test_node_journal_omits_since_when_not_provided():
    api = _api()
    node_journal(api)
    assert "since=" not in api.seen["path"]


def test_node_journal_omits_until_when_not_provided():
    api = _api()
    node_journal(api)
    assert "until=" not in api.seen["path"]


def test_node_journal_uses_explicit_node():
    api = _api(node="pve2")
    node_journal(api, node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_node_journal_rejects_zero_lastentries():
    api = _api()
    with pytest.raises(ProximoError):
        node_journal(api, lastentries=0)


def test_node_journal_rejects_negative_lastentries():
    api = _api()
    with pytest.raises(ProximoError):
        node_journal(api, lastentries=-1)


def test_node_journal_rejects_over_cap_lastentries():
    api = _api()
    with pytest.raises(ProximoError):
        node_journal(api, lastentries=5001)


def test_node_journal_accepts_cap_exactly():
    api = _api()
    node_journal(api, lastentries=5000)
    assert "lastentries=5000" in api.seen["path"]


def test_node_journal_rejects_non_integer_lastentries():
    api = _api()
    with pytest.raises(ProximoError):
        node_journal(api, lastentries="abc")


def test_node_journal_returns_list():
    api = _api()
    result = node_journal(api)
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# node_syslog
# ---------------------------------------------------------------------------


def test_node_syslog_correct_path():
    api = _api()
    node_syslog(api)
    assert api.seen["path"] == "/nodes/pve/syslog?limit=100"
    assert api.seen["method"] == "GET"


def test_node_syslog_custom_limit():
    api = _api()
    node_syslog(api, limit=50)
    assert "limit=50" in api.seen["path"]


def test_node_syslog_uses_explicit_node():
    api = _api(node="pve2")
    node_syslog(api, node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_node_syslog_rejects_zero_limit():
    api = _api()
    with pytest.raises(ProximoError):
        node_syslog(api, limit=0)


def test_node_syslog_rejects_negative_limit():
    api = _api()
    with pytest.raises(ProximoError):
        node_syslog(api, limit=-5)


def test_node_syslog_rejects_non_integer_limit():
    api = _api()
    with pytest.raises(ProximoError):
        node_syslog(api, limit="lots")


def test_node_syslog_returns_list():
    api = _api()
    result = node_syslog(api)
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# node_dns_get
# ---------------------------------------------------------------------------


def test_node_dns_get_correct_path():
    api = _api()
    node_dns_get(api)
    assert api.seen["path"] == "/nodes/pve/dns"
    assert api.seen["method"] == "GET"


def test_node_dns_get_uses_explicit_node():
    api = _api(node="pve2")
    node_dns_get(api, node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_node_dns_get_returns_dict():
    api = _api()
    api._get = lambda path: {"search": "example.com", "dns1": "1.1.1.1"}
    result = node_dns_get(api)
    assert isinstance(result, dict)


def test_node_dns_get_returns_empty_dict_on_none():
    api = _api()
    api._get = lambda path: None
    result = node_dns_get(api)
    assert result == {}


def test_node_dns_get_rejects_invalid_node():
    api = _api()
    with pytest.raises(ProximoError):
        node_dns_get(api, node="bad/node")


# ---------------------------------------------------------------------------
# node_subscription
# ---------------------------------------------------------------------------


def test_node_subscription_correct_path():
    api = _api()
    node_subscription(api)
    assert api.seen["path"] == "/nodes/pve/subscription"
    assert api.seen["method"] == "GET"


def test_node_subscription_uses_explicit_node():
    api = _api(node="pve2")
    node_subscription(api, node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_node_subscription_returns_dict():
    api = _api()
    api._get = lambda path: {"status": "Active"}
    result = node_subscription(api)
    assert isinstance(result, dict)


def test_node_subscription_returns_empty_dict_on_none():
    api = _api()
    api._get = lambda path: None
    result = node_subscription(api)
    assert result == {}


# ---------------------------------------------------------------------------
# node_certificates_info
# ---------------------------------------------------------------------------


def test_node_certificates_info_correct_path():
    api = _api()
    node_certificates_info(api)
    assert api.seen["path"] == "/nodes/pve/certificates/info"
    assert api.seen["method"] == "GET"


def test_node_certificates_info_uses_explicit_node():
    api = _api(node="pve2")
    node_certificates_info(api, node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_node_certificates_info_returns_list():
    api = _api()
    result = node_certificates_info(api)
    assert isinstance(result, list)


def test_node_certificates_info_returns_empty_list_on_none():
    api = _api()
    api._get = lambda path: None
    result = node_certificates_info(api)
    assert result == []


# ---------------------------------------------------------------------------
# node_service_control (mutation)
# Schema-verified 2026-07-06 (pve-docs api-viewer): mutations are
# POST /nodes/{node}/services/{service}/{action}; /state is the GET-only status endpoint.
# ---------------------------------------------------------------------------


def test_node_service_control_correct_path_restart():
    api = _api()
    node_service_control(api, "sshd", "restart")
    assert api.seen["path"] == "/nodes/pve/services/sshd/restart"
    assert api.seen["method"] == "POST"


def test_node_service_control_correct_path_start():
    api = _api()
    node_service_control(api, "cron", "start")
    assert api.seen["path"] == "/nodes/pve/services/cron/start"


def test_node_service_control_correct_path_stop():
    api = _api()
    node_service_control(api, "cron", "stop")
    assert api.seen["path"] == "/nodes/pve/services/cron/stop"


def test_node_service_control_correct_path_reload():
    api = _api()
    node_service_control(api, "pveproxy", "reload")
    assert api.seen["path"] == "/nodes/pve/services/pveproxy/reload"


def test_node_service_control_uses_explicit_node():
    api = _api(node="pve2")
    node_service_control(api, "sshd", "restart", node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_node_service_control_uses_config_node_when_none():
    api = _api(node="nodeX")
    node_service_control(api, "sshd", "start")
    assert "/nodes/nodeX/" in api.seen["path"]


def test_node_service_control_returns_upid():
    api = _api()
    result = node_service_control(api, "cron", "restart")
    assert isinstance(result, str) and result.startswith("UPID:")


def test_node_service_control_all_valid_actions_accepted():
    for action in ("start", "stop", "restart", "reload"):
        api = _api()
        node_service_control(api, "cron", action)
        assert action in api.seen["path"]


def test_node_service_control_rejects_invalid_action():
    api = _api()
    with pytest.raises(ProximoError):
        node_service_control(api, "sshd", "enable")


def test_node_service_control_rejects_invalid_service():
    api = _api()
    with pytest.raises(ProximoError):
        node_service_control(api, "bad service!", "start")


def test_node_service_control_rejects_service_with_newline():
    api = _api()
    with pytest.raises(ProximoError):
        node_service_control(api, "sshd\nrm -rf /", "start")


def test_node_service_control_rejects_invalid_node():
    api = _api()
    with pytest.raises(ProximoError):
        node_service_control(api, "sshd", "start", node="bad/node")


def test_node_service_control_accepts_dotservice_suffix():
    """Service names with .service suffix should be accepted by the validator."""
    api = _api()
    node_service_control(api, "sshd.service", "restart")


# ---------------------------------------------------------------------------
# _is_lockout_service — membership, case, .service suffix
# ---------------------------------------------------------------------------


def test_is_lockout_service_exact_match():
    assert _is_lockout_service("sshd") is True


def test_is_lockout_service_uppercase():
    assert _is_lockout_service("SSHD") is True


def test_is_lockout_service_mixed_case():
    assert _is_lockout_service("Pveproxy") is True


def test_is_lockout_service_with_dotservice_suffix_lowercase():
    assert _is_lockout_service("sshd.service") is True


def test_is_lockout_service_with_dotservice_suffix_uppercase():
    assert _is_lockout_service("SSHD.SERVICE") is True


def test_is_lockout_service_corosync_dotservice():
    assert _is_lockout_service("corosync.service") is True


def test_is_lockout_service_pve_cluster_dotservice():
    assert _is_lockout_service("pve-cluster.service") is True


def test_is_lockout_service_networking():
    assert _is_lockout_service("networking") is True


def test_is_lockout_service_ssh():
    assert _is_lockout_service("ssh") is True


def test_is_lockout_service_non_lockout_returns_false():
    assert _is_lockout_service("cron") is False


def test_is_lockout_service_nginx_not_lockout():
    assert _is_lockout_service("nginx") is False


def test_is_lockout_service_random_service_not_lockout():
    assert _is_lockout_service("myapp") is False


# ---------------------------------------------------------------------------
# plan_node_service_control — risk branches
# ---------------------------------------------------------------------------


def test_plan_lockout_service_stop_is_high_risk():
    p = plan_node_service_control("sshd", "stop")
    assert p.risk == RISK_HIGH


def test_plan_lockout_service_restart_is_high_risk():
    p = plan_node_service_control("pveproxy", "restart")
    assert p.risk == RISK_HIGH


def test_plan_lockout_service_reload_is_high_risk():
    p = plan_node_service_control("pvedaemon", "reload")
    assert p.risk == RISK_HIGH


def test_plan_lockout_service_start_is_low_risk():
    """'start' of a lockout service is additive — LOW, not HIGH."""
    p = plan_node_service_control("sshd", "start")
    assert p.risk == RISK_LOW


def test_plan_non_lockout_service_stop_is_medium_risk():
    p = plan_node_service_control("cron", "stop")
    assert p.risk == RISK_MEDIUM


def test_plan_non_lockout_service_restart_is_medium_risk():
    p = plan_node_service_control("nginx", "restart")
    assert p.risk == RISK_MEDIUM


def test_plan_non_lockout_service_start_is_low_risk():
    p = plan_node_service_control("cron", "start")
    assert p.risk == RISK_LOW


def test_plan_non_lockout_service_reload_is_low_risk():
    p = plan_node_service_control("cron", "reload")
    assert p.risk == RISK_LOW


def test_plan_lockout_service_stop_blast_mentions_lockout():
    p = plan_node_service_control("sshd", "stop")
    text = " ".join(p.blast_radius).lower()
    assert "management" in text or "lock" in text or "ssh" in text


def test_plan_lockout_service_blast_mentions_no_undo():
    p = plan_node_service_control("sshd", "stop")
    text = " ".join(p.blast_radius + [p.note]).lower()
    assert "cannot" in text or "undo" in text or "inverse" in text or "manually" in text


def test_plan_non_lockout_service_blast_mentions_no_undo():
    p = plan_node_service_control("cron", "stop")
    text = " ".join(p.blast_radius + [p.note]).lower()
    assert "cannot" in text or "undo" in text or "inverse" in text or "manually" in text


def test_plan_action_string():
    p = plan_node_service_control("sshd", "restart")
    assert p.action == "pve_node_service_control"


def test_plan_target_includes_service_and_action():
    p = plan_node_service_control("sshd", "restart")
    assert "sshd" in p.target and "restart" in p.target


def test_plan_change_includes_service_and_action():
    p = plan_node_service_control("cron", "stop")
    assert "cron" in p.change and "stop" in p.change


def test_plan_uses_node_label_in_target():
    p = plan_node_service_control("sshd", "restart", node="pve1")
    assert "pve1" in p.target


def test_plan_default_node_label_when_none():
    p = plan_node_service_control("sshd", "restart")
    # default node is labeled in target (contains "<default>" or similar)
    assert p.target  # at minimum it must be non-empty


def test_plan_rejects_invalid_service():
    with pytest.raises(ProximoError):
        plan_node_service_control("bad service!", "start")


def test_plan_rejects_invalid_action():
    with pytest.raises(ProximoError):
        plan_node_service_control("sshd", "enable")


def test_plan_rejects_invalid_node():
    with pytest.raises(ProximoError):
        plan_node_service_control("sshd", "restart", node="bad/node")


def test_plan_corosync_stop_is_high_risk():
    p = plan_node_service_control("corosync", "stop")
    assert p.risk == RISK_HIGH


def test_plan_pve_cluster_restart_is_high_risk():
    p = plan_node_service_control("pve-cluster", "restart")
    assert p.risk == RISK_HIGH


def test_plan_networking_stop_is_high_risk():
    p = plan_node_service_control("networking", "stop")
    assert p.risk == RISK_HIGH


def test_plan_sshd_dotservice_stop_is_high_risk():
    """'sshd.service' must be recognized as a lockout service."""
    p = plan_node_service_control("sshd.service", "stop")
    assert p.risk == RISK_HIGH


def test_plan_sshd_uppercase_stop_is_high_risk():
    """'SSHD' (uppercase) must be recognized as a lockout service."""
    p = plan_node_service_control("SSHD", "stop")
    assert p.risk == RISK_HIGH


def test_plan_lockout_start_blast_says_additive():
    """'start' of lockout service blast must reflect additive nature."""
    p = plan_node_service_control("sshd", "start")
    text = " ".join(p.blast_radius).lower()
    assert "additive" in text or "start" in text


def test_plan_note_always_mentions_no_undo():
    for action in ("start", "stop", "restart", "reload"):
        p = plan_node_service_control("cron", action)
        assert p.note  # note field must be non-empty
        assert "undo" in p.note.lower() or "inverse" in p.note.lower() or "manually" in p.note.lower()


# ---------------------------------------------------------------------------
# Redteam-hardening regression tests (2026-06-08)
# ---------------------------------------------------------------------------

def test_node_journal_since_cannot_smuggle_params():
    """A since value containing '&...' must be percent-encoded, not become a 2nd param."""
    api = _api()
    node_journal(api, since="2026-01-01&lastentries=99999")
    path = api.seen["path"]
    # The injected '&' and '=' are encoded — there is exactly ONE lastentries param.
    assert path.count("lastentries=") == 1
    assert "lastentries=99999" not in path
    assert "%26" in path or "%3D" in path  # the & or = got encoded


def test_node_journal_until_newline_is_encoded():
    """A newline in until must be encoded, never reach the request as a raw control char."""
    api = _api()
    node_journal(api, until="2026-01-01\ninjected")
    path = api.seen["path"]
    assert "\n" not in path
    assert "%0A" in path or "%0a" in path


def test_node_syslog_rejects_over_cap_limit():
    api = _api()
    with pytest.raises(ProximoError):
        node_syslog(api, limit=5001)


def test_node_syslog_accepts_cap_exactly():
    api = _api()
    node_syslog(api, limit=5000)
    assert "limit=5000" in api.seen["path"]


def test_node_journal_returns_strings_passthrough():
    """VERIFIED live (PVE 9.1.7): the journal endpoint returns a list of STRINGS, not dicts.
    node_journal must pass them through unchanged (no dict assumption)."""
    seen: dict = {}

    def fake_get(path):
        seen["path"] = path
        return ["cursor;s=abc", "Mar 02 23:32 pve1 pveproxy[1]: worker started"]

    api = __import__("types").SimpleNamespace(config=__import__("types").SimpleNamespace(node="pve"),
                                              _get=fake_get)
    out = node_journal(api)
    assert out == ["cursor;s=abc", "Mar 02 23:32 pve1 pveproxy[1]: worker started"]
    assert all(isinstance(x, str) for x in out)


# --------------------------------------------------------- the window must not lie (2026-07-30)
#
# A forum reviewer asked an agent for "utilization charts for today" and got a confident answer
# built on the last 24 HOURS — which spans two calendar days. The model was not hallucinating:
# the schema offered a `day` timeframe and said only "over the specified timeframe", so `day`
# read as "today". RRD windows are ROLLING and end at now; these endpoints expose no start/end
# at all. The schema has to say so, or the tool description is the thing telling the lie.
#
# Pinned across the whole CLASS, not the one site that was reported: the same wording shipped
# on five tools over four planes, and fixing only the reported one leaves four lies standing.

RRD_TOOL_SITES = [
    ("pve_observability.py", "pve_node_rrddata"),
    ("pmg_mail.py", "pmg_node_rrddata"),
    ("pbs_admin.py", "pbs_node_rrd"),
    ("pbs_datastore_admin.py", "pbs_datastore_rrd"),
    ("memory_tools.py", "proximo_baseline"),
]


def _tool_text(module: str, fn: str) -> str:
    """The schema text as the MODEL receives it: signature Field descriptions plus docstring.
    Read from the FILE, not an import: these modules are only importable through server.py's
    registration order, and the property under test is what the text SAYS."""
    from pathlib import Path

    import proximo
    src = (Path(proximo.__file__).parent / "tools" / module).read_text()
    start = src.index(f"def {fn}(")
    nxt = src.find("@tool()", start)
    return src[start:nxt if nxt != -1 else len(src)]


@pytest.mark.parametrize("module,fn", RRD_TOOL_SITES)
def test_every_rrd_window_is_disclosed_as_rolling_and_ending_now(module, fn):
    text = _tool_text(module, fn).lower()
    assert "rolling" in text, f"{fn}: must say the window ROLLS, or 'day' reads as 'today'"
    assert "now" in text, f"{fn}: must say the window ENDS AT NOW"


@pytest.mark.parametrize("module,fn", RRD_TOOL_SITES)
def test_every_rrd_schema_warns_a_calendar_day_is_not_available(module, fn):
    """The honest half: these endpoints expose no start/end, so 'today' or any specific date
    CANNOT be served. Saying so in the schema is what stops a model claiming it did."""
    text = _tool_text(module, fn).lower()
    assert "calendar" in text, f"{fn}: must name the calendar-day limit"
    assert "not" in text, f"{fn}: must state the limit negatively, not imply it"
