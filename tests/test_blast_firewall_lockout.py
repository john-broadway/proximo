"""firewall-lockout blast — enabling the firewall (or setting policy_in=DROP) under default-DROP
locks out management on every node whose (datacenter ∪ node) ruleset lacks an inbound ACCEPT for
SSH(22)/PVE(8006).

Spec: docs/specs/2026-06-19-firewall-lockout-blast-radius.md (internal-only). Soundness (no under-flag): a rule only
counts as protective if ENABLED + inbound + ACCEPT + tcp-ish + covers 22/8006; a disabled rule, a
udp/22 rule, or a source-restricted ACCEPT must NOT be treated as blanket protection.
"""
from __future__ import annotations

from proximo.planning import RISK_HIGH


def _rule(action="ACCEPT", type="in", dport="22", source=None, proto="tcp", enable=1, pos=0):
    r = {"action": action, "type": type, "enable": enable, "pos": pos, "proto": proto}
    if dport is not None:
        r["dport"] = dport
    if source is not None:
        r["source"] = source
    return r


def _at_risk(result):
    return {a["node"] for a in result.affected}


def test_cluster_enable_names_node_without_mgmt_accept():
    from proximo.blast import compute_firewall_lockout_blast

    node_rules = {"pve1": [], "pve2": [_rule(dport="22", source=None)]}  # pve2 has open SSH
    r = compute_firewall_lockout_blast("cluster", ["pve1", "pve2"], [], node_rules)

    assert r.risk == RISK_HIGH
    locked = {a["node"] for a in r.affected if a["state"] == "lockout"}
    assert "pve1" in locked            # no management ACCEPT → lockout
    assert "pve2" not in _at_risk(r)   # open mgmt ACCEPT → not in the at-risk set


def test_disabled_mgmt_accept_does_not_protect():
    """SOUNDNESS GATE: a DISABLED ACCEPT offers no protection → still a lockout."""
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("node", ["pve1"], [], {"pve1": [_rule(source=None, enable=0)]})
    assert any(a["node"] == "pve1" and a["state"] == "lockout" for a in r.affected)


def test_udp_22_does_not_protect_tcp_ssh():
    """SOUNDNESS GATE: SSH/8006 are tcp — a udp/22 ACCEPT must not be counted as protective."""
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("node", ["pve1"], [], {"pve1": [_rule(dport="22", proto="udp", source=None)]})
    assert any(a["node"] == "pve1" and a["state"] == "lockout" for a in r.affected)


def test_out_direction_accept_does_not_protect_inbound_mgmt():
    """SOUNDNESS GATE: an OUTbound ACCEPT does not grant inbound management access."""
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("node", ["pve1"], [], {"pve1": [_rule(type="out", source=None)]})
    assert any(a["node"] == "pve1" and a["state"] == "lockout" for a in r.affected)


def test_source_restricted_host_is_conditional_lockout():
    """A management ACCEPT restricted to a specific public host → conditional lockout (named)."""
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("node", ["pve1"], [], {"pve1": [_rule(dport="22", source="203.0.113.9")]})
    entry = [a for a in r.affected if a["node"] == "pve1"]
    assert entry and entry[0]["state"] == "conditional"


def test_internal_restricted_is_disclosed_not_named_lockout():
    """An internal/RFC1918-restricted mgmt ACCEPT is the common safe case → disclosed, not at-risk."""
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("node", ["pve1"], [], {"pve1": [_rule(dport="22", source="10.0.0.0/8")]})
    assert "pve1" not in _at_risk(r)
    assert any("internal" in line.lower() for line in r.summary_lines)


def test_datacenter_rule_protects_node_with_no_own_rule():
    """Combined ruleset: a datacenter-level open ACCEPT protects a node with no own rule."""
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("cluster", ["pve1"], [_rule(dport="8006", source=None)], {"pve1": []})
    assert "pve1" not in _at_risk(r)


def test_all_ports_accept_covers_mgmt():
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("node", ["pve1"], [], {"pve1": [_rule(dport=None, source=None)]})
    assert "pve1" not in _at_risk(r)


def test_8006_inside_a_range_covers_mgmt():
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("node", ["pve1"], [], {"pve1": [_rule(dport="8000:8010", source=None)]})
    assert "pve1" not in _at_risk(r)


def test_unreadable_node_rules_is_incomplete_and_high():
    """SOUNDNESS GATE: rules unreadable for a node → incomplete, HIGH, never 'safe'."""
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("node", ["pve1"], [], {"pve1": None})
    assert r.complete is False
    assert r.risk == RISK_HIGH
    assert any(a["node"] == "pve1" and a["state"] == "incomplete" for a in r.affected)


def test_unreadable_datacenter_rules_makes_every_node_incomplete():
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("cluster", ["pve1"], None, {"pve1": []})
    assert r.complete is False
    assert any(a["node"] == "pve1" and a["state"] == "incomplete" for a in r.affected)


def test_empty_node_enumeration_fails_closed():
    """SOUNDNESS GATE: an EMPTY node list at cluster scope is silent degradation (a real cluster has
    ≥1 node) — it must fail closed (complete=False + loud), not report 'analyzed, nothing at risk'."""
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("cluster", [], [], {})
    assert r.complete is False
    assert r.risk == RISK_HIGH
    assert any("enumerat" in line.lower() for line in r.summary_lines)


def test_enable_false_bool_does_not_protect():
    """SOUNDNESS GATE: enable=False / 'false' is a DISABLED rule → no protection → still a lockout."""
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("node", ["pve1"], [], {"pve1": [_rule(source=None, enable=False)]})
    assert any(a["node"] == "pve1" and a["state"] == "lockout" for a in r.affected)


def test_nodes_unenumerable_is_high_and_loud():
    from proximo.blast import compute_firewall_lockout_blast

    r = compute_firewall_lockout_blast("cluster", None, [], {})
    assert r.risk == RISK_HIGH
    assert r.complete is False
    assert any("enumerat" in line.lower() for line in r.summary_lines)
