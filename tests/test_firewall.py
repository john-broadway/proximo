"""Firewall pillar tests — fully mocked, no live Proxmox.

Mirrors test_provisioning.py / test_storage.py style:
- Op functions: SimpleNamespace fake apis that record _post / _delete / _put calls.
- Plan functions: fake apis that supply firewall_rules_list / firewall_options_get.
- Validator-rejection tests use pytest.raises(ProximoError).
- Every test is self-contained — no shared mutable state.

Key invariants verified:
  1. URL / param construction for each scope (cluster / node / guest).
  2. PLAN-before-mutate (plan factories are separate from ops — server gates them).
  3. RISK_HIGH for firewall_set_enabled (both enable and disable directions).
  4. RISK_MEDIUM floor for rule add / remove / update.
  5. Validator rejection for bad scope / pos / action / direction.
  6. plan_firewall_rule_remove reads the current rule (one safe read) to show what is removed.
  7. plan_firewall_set_enabled reads current options to show the current state.
  8. No-UNDO language present in all mutating plans.
  9. Lockout warning present in set_enabled plans.
 10. Cluster-scope kill-switch warning in set_enabled plans.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from proximo.backends import ProximoError
from proximo.firewall import (
    alias_create,
    alias_delete,
    alias_list,
    alias_update,
    firewall_options_get,
    firewall_options_set,
    firewall_rule_add,
    firewall_rule_remove,
    firewall_rule_update,
    firewall_rules_list,
    firewall_set_enabled,
    ipset_create,
    ipset_delete,
    ipset_entry_add,
    ipset_entry_remove,
    ipset_list,
    plan_alias_create,
    plan_alias_delete,
    plan_alias_update,
    plan_firewall_options_set,
    plan_firewall_rule_add,
    plan_firewall_rule_remove,
    plan_firewall_rule_update,
    plan_firewall_set_enabled,
    plan_ipset_create,
    plan_ipset_delete,
    plan_ipset_entry_add,
    plan_ipset_entry_remove,
    plan_security_group_create,
    plan_security_group_delete,
    security_group_create,
    security_group_delete,
    security_groups_list,
)
from proximo.planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM

# ---------------------------------------------------------------------------
# Test fakes
# ---------------------------------------------------------------------------


def _api(node: str = "pve") -> SimpleNamespace:
    """Fake api that records _get / _post / _delete / _put calls and exposes config.node.

    By default _get returns [{"pos": 0, "digest": "test-digest-abc"}] so that
    firewall_rule_remove and firewall_rule_update can obtain a digest (FIX 3).
    Override seen["_get_return"] to change the returned list.
    """
    seen: dict = {}

    def fake_get(path):
        seen["method"] = "GET"
        seen["path"] = path
        # Default: a single rule entry with a digest so remove/update ops have a digest.
        return seen.get("_get_return", [{"pos": 0, "digest": "test-digest-abc"}])

    def fake_post(path, data=None):
        seen["method"] = "POST"
        seen["path"] = path
        seen["data"] = data
        return None

    def fake_delete(path, params=None):
        seen["method"] = "DELETE"
        seen["path"] = path
        seen["params"] = params
        return None

    def fake_put(path, data=None):
        seen["method"] = "PUT"
        seen["path"] = path
        seen["data"] = data
        return None

    return SimpleNamespace(
        config=SimpleNamespace(node=node),
        _get=fake_get,
        _post=fake_post,
        _delete=fake_delete,
        _put=fake_put,
        seen=seen,
    )


class _RulesApi:
    """Fake api for plan_firewall_rule_remove and plan_firewall_rule_update:
    supplies firewall_rules_list via a fake _get that returns configured rules."""

    def __init__(
        self,
        rules: list[dict],
        node: str = "pve",
        raise_on_list: bool = False,
    ):
        self._rules = rules
        self.config = SimpleNamespace(node=node)
        self._raise = raise_on_list
        self._get_calls: list = []

    def _get(self, path):
        self._get_calls.append(path)
        if self._raise:
            raise RuntimeError("api unavailable")
        return self._rules


class _OptionsApi:
    """Fake api for plan_firewall_set_enabled: supplies firewall_options_get via _get."""

    def __init__(
        self,
        options: dict | None,
        node: str = "pve",
        raise_on_get: bool = False,
    ):
        self._options = options
        self.config = SimpleNamespace(node=node)
        self._raise = raise_on_get

    def _get(self, path):
        if self._raise:
            raise RuntimeError("api unavailable")
        # Path-aware: the lockout blast now also reads firewall rules + node enumeration. Serve the
        # options for /options and empty lists for the new reads (these fixtures have no rules/nodes).
        if path.endswith("/options"):
            return self._options or {}
        if path.endswith("/rules"):
            return []
        if "/cluster/resources" in path:
            return []
        return {}


# ---------------------------------------------------------------------------
# READ: firewall_rules_list — URL construction per scope
# ---------------------------------------------------------------------------


def test_rules_list_cluster_scope():
    api = _api()
    firewall_rules_list(api, scope="cluster")
    assert api.seen["path"] == "/cluster/firewall/rules"
    assert api.seen["method"] == "GET"


def test_rules_list_node_scope():
    api = _api(node="pve")
    firewall_rules_list(api, scope="node")
    assert api.seen["path"] == "/nodes/pve/firewall/rules"


def test_rules_list_node_scope_explicit_node():
    api = _api(node="pve")
    firewall_rules_list(api, scope="node", node="node2")
    assert "/nodes/node2/" in api.seen["path"]


def test_rules_list_guest_scope_lxc():
    api = _api()
    firewall_rules_list(api, scope="guest", vmid="100", kind="lxc")
    assert api.seen["path"] == "/nodes/pve/lxc/100/firewall/rules"


def test_rules_list_guest_scope_qemu():
    api = _api()
    firewall_rules_list(api, scope="guest", vmid="200", kind="qemu")
    assert api.seen["path"] == "/nodes/pve/qemu/200/firewall/rules"


def test_rules_list_returns_empty_list_on_none():
    api = _api()
    api.seen["_get_return"] = None
    result = firewall_rules_list(api, scope="cluster")
    assert result == []


def test_rules_list_rejects_bad_scope():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_rules_list(api, scope="vpc")


def test_rules_list_guest_scope_requires_vmid():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_rules_list(api, scope="guest")


# ---------------------------------------------------------------------------
# READ: firewall_options_get — URL construction per scope
# ---------------------------------------------------------------------------


def test_options_get_cluster_scope():
    api = _api()
    firewall_options_get(api, scope="cluster")
    assert api.seen["path"] == "/cluster/firewall/options"


def test_options_get_node_scope():
    api = _api()
    firewall_options_get(api, scope="node")
    assert "/firewall/options" in api.seen["path"]
    assert "/nodes/" in api.seen["path"]


def test_options_get_guest_scope():
    api = _api()
    firewall_options_get(api, scope="guest", vmid="100")
    assert api.seen["path"] == "/nodes/pve/lxc/100/firewall/options"


def test_options_get_returns_empty_dict_on_none():
    api = _api()
    api.seen["_get_return"] = None
    result = firewall_options_get(api, scope="cluster")
    assert result == {}


# ---------------------------------------------------------------------------
# READ: security_groups_list
# ---------------------------------------------------------------------------


def test_security_groups_list_uses_cluster_path():
    api = _api()
    security_groups_list(api)
    assert api.seen["path"] == "/cluster/firewall/groups"
    assert api.seen["method"] == "GET"


# ---------------------------------------------------------------------------
# READ: ipset_list
# ---------------------------------------------------------------------------


def test_ipset_list_cluster_scope():
    api = _api()
    ipset_list(api, scope="cluster")
    assert api.seen["path"] == "/cluster/firewall/ipset"


def test_ipset_list_node_scope_rejected():
    # Schema-verified 2026-07-06 (pve-docs api-viewer): node firewall exposes only
    # options/rules/log — there is NO /nodes/{node}/firewall/ipset endpoint.
    api = _api()
    with pytest.raises(ProximoError, match="node scope"):
        ipset_list(api, scope="node")


# ---------------------------------------------------------------------------
# MUTATION: firewall_rule_add — URL + data shapes
# ---------------------------------------------------------------------------


def test_rule_add_cluster_scope_posts_correct_path():
    api = _api()
    firewall_rule_add(api, "ACCEPT", scope="cluster")
    assert api.seen["path"] == "/cluster/firewall/rules"
    assert api.seen["method"] == "POST"


def test_rule_add_node_scope_posts_correct_path():
    api = _api()
    firewall_rule_add(api, "DROP", scope="node")
    assert api.seen["path"] == "/nodes/pve/firewall/rules"


def test_rule_add_guest_scope_posts_correct_path():
    api = _api()
    firewall_rule_add(api, "ACCEPT", scope="guest", vmid="100")
    assert api.seen["path"] == "/nodes/pve/lxc/100/firewall/rules"


def test_rule_add_sends_required_fields():
    api = _api()
    firewall_rule_add(api, "ACCEPT", direction="in")
    d = api.seen["data"]
    assert d["action"] == "ACCEPT"
    assert d["type"] == "in"
    assert "enable" in d


def test_rule_add_enable_true_sends_1():
    api = _api()
    firewall_rule_add(api, "DROP", enable=True)
    assert api.seen["data"]["enable"] == 1


def test_rule_add_enable_false_sends_0():
    api = _api()
    firewall_rule_add(api, "DROP", enable=False)
    assert api.seen["data"]["enable"] == 0


def test_rule_add_sends_optional_fields():
    api = _api()
    firewall_rule_add(api, "ACCEPT", source="192.168.1.0/24", dest="0.0.0.0/0",
                      dport="22", comment="allow ssh")
    d = api.seen["data"]
    assert d["source"] == "192.168.1.0/24"
    assert d["dest"] == "0.0.0.0/0"
    assert d["dport"] == "22"
    assert d["comment"] == "allow ssh"


def test_rule_add_plan_discloses_top_insertion_not_append():
    # PVE inserts a new rule at the TOP (pos 0) and shifts existing rules down — so a new DROP takes
    # PRECEDENCE and can shadow a lower ACCEPT (e.g. for SSH) and cause a lockout. The plan must NOT
    # tell the operator the opposite ("appended / positions not shifted").
    p = plan_firewall_rule_add("DROP", direction="in", dport="22")
    text = " ".join(p.blast_radius).lower()
    assert "append" not in text and "not shifted" not in text   # the false, dangerous claim is gone
    assert ("top" in text) or ("position 0" in text) or ("precedence" in text)


def test_rule_add_omits_absent_optional_fields():
    api = _api()
    firewall_rule_add(api, "ACCEPT")
    d = api.seen["data"]
    assert "source" not in d
    assert "dest" not in d
    assert "dport" not in d
    assert "comment" not in d


def test_rule_add_rejects_invalid_action():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_rule_add(api, "FORWARD")


def test_rule_add_rejects_invalid_direction():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_rule_add(api, "ACCEPT", direction="both")


def test_rule_add_rejects_bad_scope():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_rule_add(api, "ACCEPT", scope="unknown")


def test_rule_add_action_is_uppercased():
    api = _api()
    firewall_rule_add(api, "accept")
    assert api.seen["data"]["action"] == "ACCEPT"


def test_rule_add_direction_is_lowercased():
    api = _api()
    firewall_rule_add(api, "DROP", direction="IN")
    assert api.seen["data"]["type"] == "in"


# ---------------------------------------------------------------------------
# MUTATION: firewall_rule_remove — URL + method
# ---------------------------------------------------------------------------


def test_rule_remove_cluster_scope_deletes_correct_path():
    api = _api()
    firewall_rule_remove(api, 3, scope="cluster")
    assert api.seen["path"] == "/cluster/firewall/rules/3"
    assert api.seen["method"] == "DELETE"


def test_rule_remove_node_scope():
    api = _api()
    firewall_rule_remove(api, 0, scope="node")
    assert api.seen["path"] == "/nodes/pve/firewall/rules/0"


def test_rule_remove_guest_scope():
    api = _api()
    firewall_rule_remove(api, 2, scope="guest", vmid="100")
    assert api.seen["path"] == "/nodes/pve/lxc/100/firewall/rules/2"


def test_rule_remove_rejects_negative_pos():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_rule_remove(api, -1, scope="cluster")


def test_rule_remove_rejects_non_numeric_pos():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_rule_remove(api, "first")


def test_rule_remove_rejects_bad_scope():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_rule_remove(api, 0, scope="region")


# ---------------------------------------------------------------------------
# MUTATION: firewall_rule_update — URL + data + PUT verb
# ---------------------------------------------------------------------------


def test_rule_update_cluster_scope_puts_correct_path():
    api = _api()
    firewall_rule_update(api, 1, action="DROP")
    assert api.seen["path"] == "/cluster/firewall/rules/1"
    assert api.seen["method"] == "PUT"


def test_rule_update_node_scope():
    api = _api()
    firewall_rule_update(api, 2, scope="node", comment="updated")
    assert api.seen["path"] == "/nodes/pve/firewall/rules/2"


def test_rule_update_guest_scope():
    api = _api()
    firewall_rule_update(api, 0, scope="guest", vmid="100", action="REJECT")
    assert api.seen["path"] == "/nodes/pve/lxc/100/firewall/rules/0"


def test_rule_update_sends_action_field():
    api = _api()
    firewall_rule_update(api, 0, action="REJECT")
    assert api.seen["data"]["action"] == "REJECT"


def test_rule_update_sends_direction_as_type():
    api = _api()
    firewall_rule_update(api, 0, direction="out")
    assert api.seen["data"]["type"] == "out"


def test_rule_update_sends_enable_as_int():
    api = _api()
    firewall_rule_update(api, 0, enable=True)
    assert api.seen["data"]["enable"] == 1


def test_rule_update_rejects_empty_update():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_rule_update(api, 0)


def test_rule_update_rejects_bad_action():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_rule_update(api, 0, action="PASS")


def test_rule_update_rejects_negative_pos():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_rule_update(api, -3, action="DROP")


# ---------------------------------------------------------------------------
# MUTATION: firewall_set_enabled — URL + data + PUT verb
# ---------------------------------------------------------------------------


def test_set_enabled_cluster_scope_puts_correct_path():
    api = _api()
    firewall_set_enabled(api, True, scope="cluster")
    assert api.seen["path"] == "/cluster/firewall/options"
    assert api.seen["method"] == "PUT"


def test_set_enabled_node_scope():
    api = _api()
    firewall_set_enabled(api, False, scope="node")
    assert api.seen["path"] == "/nodes/pve/firewall/options"


def test_set_enabled_guest_scope():
    api = _api()
    firewall_set_enabled(api, True, scope="guest", vmid="100")
    assert api.seen["path"] == "/nodes/pve/lxc/100/firewall/options"


def test_set_enabled_true_sends_enable_1():
    api = _api()
    firewall_set_enabled(api, True)
    assert api.seen["data"]["enable"] == 1


def test_set_enabled_false_sends_enable_0():
    api = _api()
    firewall_set_enabled(api, False)
    assert api.seen["data"]["enable"] == 0


def test_set_enabled_rejects_bad_scope():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_set_enabled(api, True, scope="datacenter")


# ---------------------------------------------------------------------------
# PLAN: plan_firewall_rule_add
# ---------------------------------------------------------------------------


def test_plan_rule_add_bare_accept_is_maximal_high():
    # ACCEPT/in with no source + no dport => permits ALL ports from anywhere => MAXIMAL HIGH
    # (raised, never lowered — the per-rule reach engine never reads an empty field as benign).
    p = plan_firewall_rule_add("ACCEPT", scope="cluster")
    assert p.risk == RISK_HIGH


def test_plan_rule_add_single_host_nonsensitive_keeps_medium_floor():
    # A narrow, non-mgmt open stays at the MEDIUM floor — never below it.
    p = plan_firewall_rule_add("ACCEPT", source="203.0.113.5", dport="8080")
    assert p.risk == RISK_MEDIUM


def test_plan_firewall_rule_add_names_reach():
    p = plan_firewall_rule_add("ACCEPT", "in", "cluster", source="0.0.0.0/0", dport="22")
    assert p.affected and p.affected[0]["effect"] == "permits"
    assert p.affected[0]["severity"] == "high"
    assert p.risk == RISK_HIGH
    assert any("PERMITS inbound" in line for line in p.blast_radius)
    # per-rule-reach framing present; never asserts "cluster exposed" as fact
    assert any("per-rule" in line.lower() for line in p.blast_radius)


def test_plan_firewall_rule_add_reflects_proto_not_hardcoded_tcp():
    # a udp rule preview must NOT be narrated as '/tcp' (same false-content class as egress/_port_label)
    p = plan_firewall_rule_add("ACCEPT", "in", "cluster", source="0.0.0.0/0", dport="53", proto="udp")
    assert p.affected and "/tcp" not in p.affected[0]["service"]
    assert "udp" in p.affected[0]["service"]


def test_plan_rule_add_action_string():
    p = plan_firewall_rule_add("DROP")
    assert p.action == "pve_firewall_rule_add"


def test_plan_rule_add_surfaces_scope_in_target():
    p = plan_firewall_rule_add("ACCEPT", scope="cluster")
    assert "cluster" in p.target


def test_plan_rule_add_surfaces_rule_in_change():
    p = plan_firewall_rule_add("ACCEPT", direction="in", scope="cluster")
    assert "ACCEPT" in p.change
    assert "in" in p.change


def test_plan_rule_add_surfaces_source_and_dport_when_given():
    p = plan_firewall_rule_add("ACCEPT", source="10.0.0.0/8", dport="22")
    assert "10.0.0.0/8" in p.change or any("10.0.0.0/8" in b for b in p.blast_radius)
    assert "22" in p.change or any("22" in b for b in p.blast_radius)


def test_plan_rule_add_blast_mentions_no_undo():
    p = plan_firewall_rule_add("ACCEPT")
    text = " ".join(p.blast_radius).lower()
    assert "no undo" in text or "not in guest snapshots" in text


def test_plan_rule_add_risk_reasons_not_empty():
    p = plan_firewall_rule_add("DROP")
    assert len(p.risk_reasons) >= 1


def test_plan_rule_add_rejects_invalid_action():
    with pytest.raises(ProximoError):
        plan_firewall_rule_add("MASQUERADE")


def test_plan_rule_add_rejects_bad_scope():
    with pytest.raises(ProximoError):
        plan_firewall_rule_add("ACCEPT", scope="zone")


def test_plan_rule_add_action_case_insensitive():
    p = plan_firewall_rule_add("accept")
    assert "ACCEPT" in p.change


# ---------------------------------------------------------------------------
# PLAN: plan_firewall_rule_remove
# ---------------------------------------------------------------------------


def test_plan_rule_remove_bare_drop_in_is_lockout_high():
    # DROP/in with no source+dport => blocks ALL ports from anywhere => removing it RE-PERMITS
    # everything; the removed rule's reach is lockout-class => HIGH (raised, never lowered).
    api = _RulesApi([{"pos": 0, "action": "DROP", "type": "in"}])
    p = plan_firewall_rule_remove(api, 0)
    assert p.risk == RISK_HIGH


def test_plan_rule_remove_narrow_accept_keeps_medium_floor():
    api = _RulesApi([{"pos": 0, "action": "ACCEPT", "type": "in",
                      "source": "203.0.113.5", "dport": "8080"}])
    p = plan_firewall_rule_remove(api, 0)
    assert p.risk == RISK_MEDIUM


def test_plan_rule_remove_names_what_closes():
    # removing an ACCEPT names what it CLOSES + carries the removed rule's reach
    api = _RulesApi([{"pos": 0, "action": "ACCEPT", "type": "in",
                      "source": "0.0.0.0/0", "dport": "22"}])
    p = plan_firewall_rule_remove(api, 0)
    text = " ".join(p.blast_radius).lower()
    assert "clos" in text or "no longer permit" in text
    assert p.affected and p.affected[0]["effect"] == "permits"


def test_plan_rule_remove_drop_names_what_re_permits():
    api = _RulesApi([{"pos": 0, "action": "DROP", "type": "in",
                      "source": "0.0.0.0/0", "dport": "8006"}])
    p = plan_firewall_rule_remove(api, 0)
    text = " ".join(p.blast_radius).lower()
    assert "re-permit" in text or "re-open" in text or "reopen" in text
    assert p.affected and p.affected[0]["effect"] == "blocks"


def test_plan_rule_remove_action_string():
    api = _RulesApi([])
    p = plan_firewall_rule_remove(api, 1)
    assert p.action == "pve_firewall_rule_remove"


def test_plan_rule_remove_reads_rule_and_surfaces_in_current():
    api = _RulesApi([{"pos": 2, "action": "ACCEPT", "type": "in", "dport": "22"}])
    p = plan_firewall_rule_remove(api, 2)
    assert p.current.get("action") == "ACCEPT"
    assert p.current.get("pos") == 2


def test_plan_rule_remove_surfaces_action_in_change():
    api = _RulesApi([{"pos": 0, "action": "DROP", "type": "in"}])
    p = plan_firewall_rule_remove(api, 0)
    assert "DROP" in p.change or "DROP" in " ".join(p.blast_radius)


def test_plan_rule_remove_blast_mentions_position_shift():
    api = _RulesApi([{"pos": 0, "action": "DROP", "type": "out"}])
    p = plan_firewall_rule_remove(api, 0)
    text = " ".join(p.blast_radius).lower()
    assert "shift" in text or "position" in text


def test_plan_rule_remove_blast_mentions_no_undo():
    api = _RulesApi([])
    p = plan_firewall_rule_remove(api, 0)
    text = " ".join(p.blast_radius).lower()
    assert "no undo" in text or "not in guest snapshots" in text


def test_plan_rule_remove_blast_mentions_lockout_risk():
    api = _RulesApi([{"pos": 0, "action": "ACCEPT", "type": "in"}])
    p = plan_firewall_rule_remove(api, 0)
    text = " ".join(p.blast_radius).lower()
    assert "lockout" in text or "ssh" in text or "8006" in text


def test_plan_rule_remove_discloses_lookup_failure():
    api = _RulesApi([], raise_on_list=True)
    p = plan_firewall_rule_remove(api, 0)
    text = " ".join(p.blast_radius + p.risk_reasons).lower()
    assert "failed" in text or "could not" in text


def test_plan_rule_remove_rejects_negative_pos():
    api = _RulesApi([])
    with pytest.raises(ProximoError):
        plan_firewall_rule_remove(api, -1)


def test_plan_rule_remove_pos_in_target():
    api = _RulesApi([{"pos": 5, "action": "DROP", "type": "in"}])
    p = plan_firewall_rule_remove(api, 5)
    assert "5" in p.target


# ---------------------------------------------------------------------------
# PLAN: plan_firewall_rule_update
# ---------------------------------------------------------------------------


def test_plan_rule_update_to_drop_all_from_anywhere_is_lockout_high():
    # ACCEPT/in -> DROP/in with no source/dport => post-update blocks ALL ports from anywhere
    # => lockout-class HIGH (raised, never lowered).
    api = _RulesApi([{"pos": 1, "action": "ACCEPT", "type": "in"}])
    p = plan_firewall_rule_update(api, 1, action="DROP")
    assert p.risk == RISK_HIGH
    assert p.affected and p.affected[0]["effect"] == "blocks"


def test_plan_rule_update_narrow_change_keeps_medium_floor():
    api = _RulesApi([{"pos": 1, "action": "ACCEPT", "type": "in",
                      "source": "203.0.113.5", "dport": "8080"}])
    p = plan_firewall_rule_update(api, 1, comment="note")
    assert p.risk == RISK_MEDIUM


def test_plan_rule_update_merges_new_direction_over_stored_type():
    # KEY-MISMATCH TRAP: stored direction is under 'type', new_fields carries it as 'direction'.
    # Changing an inbound ACCEPT to OUTBOUND must classify the post-update rule as egress (lower),
    # proving new direction merges over the stored 'type'.
    api = _RulesApi([{"pos": 0, "action": "ACCEPT", "type": "in",
                      "source": "0.0.0.0/0", "dport": "22"}])
    p = plan_firewall_rule_update(api, 0, direction="out")
    assert p.affected and p.affected[0]["direction"] == "out"


def test_plan_rule_update_post_update_widens_source_to_anywhere_high():
    # narrowing/widening: stored narrow ACCEPT, update widens source to anywhere => HIGH
    api = _RulesApi([{"pos": 0, "action": "ACCEPT", "type": "in",
                      "source": "10.0.0.0/8", "dport": "22"}])
    p = plan_firewall_rule_update(api, 0, source="0.0.0.0/0")
    assert p.risk == RISK_HIGH
    assert any("PERMITS inbound" in line for line in p.blast_radius)


def test_plan_rule_update_action_string():
    api = _RulesApi([])
    p = plan_firewall_rule_update(api, 0, comment="new")
    assert p.action == "pve_firewall_rule_update"


def test_plan_rule_update_reads_current_state():
    api = _RulesApi([{"pos": 2, "action": "ACCEPT", "type": "out", "enable": 1}])
    p = plan_firewall_rule_update(api, 2, action="DROP")
    assert p.current.get("action") == "ACCEPT"


def test_plan_rule_update_change_includes_new_fields():
    api = _RulesApi([{"pos": 0, "action": "DROP", "type": "in"}])
    p = plan_firewall_rule_update(api, 0, action="ACCEPT", dport="443")
    assert "ACCEPT" in p.change or any("ACCEPT" in b for b in p.blast_radius)


def test_plan_rule_update_blast_mentions_position_shift():
    api = _RulesApi([{"pos": 0, "action": "DROP", "type": "in"}])
    p = plan_firewall_rule_update(api, 0, action="ACCEPT")
    text = " ".join(p.blast_radius).lower()
    assert "shift" in text or "position" in text


def test_plan_rule_update_blast_mentions_no_undo():
    api = _RulesApi([])
    p = plan_firewall_rule_update(api, 0, comment="x")
    text = " ".join(p.blast_radius).lower()
    assert "no undo" in text or "not in guest snapshots" in text


def test_plan_rule_update_discloses_lookup_failure():
    api = _RulesApi([], raise_on_list=True)
    p = plan_firewall_rule_update(api, 0, action="DROP")
    text = " ".join(p.blast_radius + p.risk_reasons).lower()
    assert "failed" in text or "could not" in text


# ---------------------------------------------------------------------------
# PLAN: plan_firewall_set_enabled
# ---------------------------------------------------------------------------


def test_plan_set_enabled_is_high_risk_when_enabling():
    api = _OptionsApi({"enable": 0})
    p = plan_firewall_set_enabled(api, True)
    assert p.risk == RISK_HIGH


def test_plan_set_enabled_is_high_risk_when_disabling():
    api = _OptionsApi({"enable": 1})
    p = plan_firewall_set_enabled(api, False)
    assert p.risk == RISK_HIGH


def test_plan_set_enabled_action_string():
    api = _OptionsApi({})
    p = plan_firewall_set_enabled(api, True)
    assert p.action == "pve_firewall_set_enabled"


def test_plan_set_enabled_reads_current_state():
    api = _OptionsApi({"enable": 0})
    p = plan_firewall_set_enabled(api, True)
    assert p.current.get("enable") == 0


def test_plan_set_enabled_enable_blast_mentions_lockout():
    api = _OptionsApi({"enable": 0})
    p = plan_firewall_set_enabled(api, True)
    text = " ".join(p.blast_radius).lower()
    assert "lockout" in text or "lock" in text or "block access" in text or "8006" in text or "ssh" in text


def test_plan_set_enabled_disable_blast_strips_protection():
    api = _OptionsApi({"enable": 1})
    p = plan_firewall_set_enabled(api, False)
    text = " ".join(p.blast_radius).lower()
    assert "strip" in text or "protection" in text or "disables" in text


def test_plan_set_enabled_cluster_scope_mentions_kill_switch():
    api = _OptionsApi({"enable": 1})
    p = plan_firewall_set_enabled(api, False, scope="cluster")
    text = " ".join(p.blast_radius).lower()
    assert "cluster" in text or "all nodes" in text or "kill" in text


def test_plan_set_enabled_enable_blast_mentions_no_undo():
    api = _OptionsApi({"enable": 0})
    p = plan_firewall_set_enabled(api, False)
    text = " ".join(p.blast_radius).lower()
    assert "no undo" in text or "not in guest snapshots" in text or "re-enable" in text


def test_plan_set_enabled_change_says_enable():
    api = _OptionsApi({})
    p = plan_firewall_set_enabled(api, True)
    assert "enable" in p.change.lower() or "ENABLE" in p.change


def test_plan_set_enabled_change_says_disable():
    api = _OptionsApi({})
    p = plan_firewall_set_enabled(api, False)
    assert "disable" in p.change.lower() or "DISABLE" in p.change


def test_plan_set_enabled_discloses_lookup_failure_stays_high():
    api = _OptionsApi({}, raise_on_get=True)
    p = plan_firewall_set_enabled(api, True)
    assert p.risk == RISK_HIGH
    text = " ".join(p.blast_radius + p.risk_reasons).lower()
    assert "could not" in text or "unknown" in text or "failed" in text


def test_plan_set_enabled_node_scope_target():
    api = _OptionsApi({})
    p = plan_firewall_set_enabled(api, True, scope="node")
    assert "node" in p.target


def test_plan_set_enabled_guest_scope_target():
    api = _OptionsApi({})
    p = plan_firewall_set_enabled(api, True, scope="guest", vmid="100")
    assert "guest" in p.target


# ---------------------------------------------------------------------------
# PLAN-before-mutate contract: plan factories return Plans, ops are separate
# ---------------------------------------------------------------------------


def test_firewall_rule_add_does_not_call_plan():
    """Op function is pure mutation — it calls _post, not any plan factory."""
    api = _api()
    firewall_rule_add(api, "ACCEPT")
    # If plan was called, _get would also appear in seen; only POST must be seen.
    assert api.seen["method"] == "POST"


def test_firewall_rule_remove_does_not_call_plan():
    """Op function is pure mutation — it calls _delete, not any plan factory."""
    api = _api()
    firewall_rule_remove(api, 0)
    assert api.seen["method"] == "DELETE"


def test_firewall_rule_update_does_not_call_plan():
    """Op function is pure mutation — it calls _put, not any plan factory."""
    api = _api()
    firewall_rule_update(api, 0, action="DROP")
    assert api.seen["method"] == "PUT"


def test_firewall_set_enabled_does_not_call_plan():
    """Op function is pure mutation — it calls _put, not any plan factory."""
    api = _api()
    firewall_set_enabled(api, True)
    assert api.seen["method"] == "PUT"


def test_plan_rule_add_does_not_call_api():
    """Plan factory is pure — no API call happens at plan time."""
    # If this raises AttributeError (no api arg), the factory incorrectly tried to call one.
    p = plan_firewall_rule_add("DROP", direction="out")
    assert p.risk == RISK_MEDIUM


# ---------------------------------------------------------------------------
# Scope / node / vmid edge cases
# ---------------------------------------------------------------------------


def test_rules_list_uses_config_node_when_none():
    api = _api(node="pve3")
    firewall_rules_list(api, scope="node")
    assert "/nodes/pve3/" in api.seen["path"]


def test_rule_add_uses_explicit_node_over_config():
    api = _api(node="pve")
    firewall_rule_add(api, "DROP", scope="node", node="node5")
    assert "/nodes/node5/" in api.seen["path"]


def test_rule_remove_uses_explicit_node_over_config():
    api = _api(node="pve")
    firewall_rule_remove(api, 1, scope="node", node="node9")
    assert "/nodes/node9/" in api.seen["path"]


def test_set_enabled_guest_scope_uses_qemu_kind():
    api = _api()
    firewall_set_enabled(api, False, scope="guest", vmid="200", kind="qemu")
    assert "/qemu/200/" in api.seen["path"]


def test_rules_list_guest_scope_rejects_invalid_vmid():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_rules_list(api, scope="guest", vmid="abc")


def test_set_enabled_guest_scope_rejects_invalid_vmid():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_set_enabled(api, True, scope="guest", vmid="not-a-number")


# ---------------------------------------------------------------------------
# plan_firewall_rule_update: new_fields validation (action / direction)
# ---------------------------------------------------------------------------


def test_plan_rule_update_rejects_invalid_action_in_new_fields():
    """plan_firewall_rule_update must validate action in new_fields at plan time."""
    api = _RulesApi([{"pos": 0, "action": "ACCEPT", "type": "in"}])
    with pytest.raises(ProximoError):
        plan_firewall_rule_update(api, 0, action="GARBAGE")


def test_plan_rule_update_rejects_invalid_direction_in_new_fields():
    """plan_firewall_rule_update must validate direction in new_fields at plan time."""
    api = _RulesApi([{"pos": 0, "action": "DROP", "type": "in"}])
    with pytest.raises(ProximoError):
        plan_firewall_rule_update(api, 0, direction="both")


def test_plan_rule_update_normalizes_action_case_in_new_fields():
    """plan_firewall_rule_update must uppercase the action in new_fields."""
    api = _RulesApi([{"pos": 0, "action": "DROP", "type": "in"}])
    p = plan_firewall_rule_update(api, 0, action="accept")
    # The change string should reference the normalized ACCEPT, not the raw 'accept'.
    assert "ACCEPT" in p.change or any("ACCEPT" in b for b in p.blast_radius)


# ---------------------------------------------------------------------------
# Return-value contract: mutating ops return None (synchronous, no UPID)
# ---------------------------------------------------------------------------


def test_rule_add_returns_none():
    """firewall_rule_add is synchronous and must return None (no UPID)."""
    api = _api()
    result = firewall_rule_add(api, "ACCEPT")
    assert result is None


def test_rule_remove_returns_none():
    """firewall_rule_remove is synchronous and must return None."""
    api = _api()
    result = firewall_rule_remove(api, 0)
    assert result is None


def test_rule_update_returns_none():
    """firewall_rule_update is synchronous and must return None (no UPID)."""
    api = _api()
    result = firewall_rule_update(api, 0, action="DROP")
    assert result is None


def test_set_enabled_returns_none():
    """firewall_set_enabled is synchronous and must return None (no UPID)."""
    api = _api()
    result = firewall_set_enabled(api, True)
    assert result is None


# ---------------------------------------------------------------------------
# FIX 3: digest optimistic-locking — remove and update send digest in body/params
# ---------------------------------------------------------------------------


def test_rule_remove_sends_digest_in_delete_params():
    """firewall_rule_remove must re-read rules and pass the digest as a DELETE param."""
    api = _api()
    api.seen["_get_return"] = [{"pos": 3, "digest": "abc123"}]
    firewall_rule_remove(api, 3, scope="cluster")
    # _delete is called with params containing the digest.
    assert api.seen.get("params", {}).get("digest") == "abc123"


def test_rule_remove_aborts_when_no_digest_available():
    """If rules list has no digest field, firewall_rule_remove must raise ProximoError."""
    from proximo.backends import ProximoError as PE
    api = _api()
    api.seen["_get_return"] = [{"pos": 0, "action": "ACCEPT"}]  # no 'digest' key
    with pytest.raises(PE, match="digest"):
        firewall_rule_remove(api, 0, scope="cluster")


def test_rule_update_sends_digest_in_put_body():
    """firewall_rule_update must re-read rules and include the digest in the PUT body."""
    api = _api()
    api.seen["_get_return"] = [{"pos": 1, "digest": "def456"}]
    firewall_rule_update(api, 1, action="DROP")
    assert api.seen.get("data", {}).get("digest") == "def456"


def test_rule_update_aborts_when_no_digest_available():
    """If rules list has no digest field, firewall_rule_update must raise ProximoError."""
    from proximo.backends import ProximoError as PE
    api = _api()
    api.seen["_get_return"] = [{"pos": 0, "action": "ACCEPT"}]  # no 'digest' key
    with pytest.raises(PE, match="digest"):
        firewall_rule_update(api, 0, action="DROP")


# ===========================================================================
# ALIASES — alias_list / alias_create / alias_update / alias_delete
# Grounded against live PVE 9.2 schema (2026-06-14):
#   POST   /cluster/firewall/aliases           {name, cidr, comment?}   (NO digest on create)
#   PUT    /cluster/firewall/aliases/{name}     {cidr?, comment?, rename?, digest?}
#   DELETE /cluster/firewall/aliases/{name}     {digest?}
# Aliases are passive named CIDRs: they change traffic only when a rule references them.
# ===========================================================================


def test_alias_list_cluster_scope():
    api = _api()
    alias_list(api)
    assert api.seen["method"] == "GET"
    assert api.seen["path"] == "/cluster/firewall/aliases"


def test_alias_list_node_scope_rejected():
    # Schema-verified 2026-07-06 (pve-docs api-viewer): node firewall exposes only
    # options/rules/log — there is NO /nodes/{node}/firewall/aliases endpoint.
    api = _api(node="n1")
    with pytest.raises(ProximoError, match="node scope"):
        alias_list(api, scope="node")


def test_alias_list_guest_scope_lxc():
    api = _api(node="n1")
    alias_list(api, scope="guest", vmid="100", kind="lxc")
    assert api.seen["path"] == "/nodes/n1/lxc/100/firewall/aliases"


def test_alias_list_returns_empty_list_on_none():
    api = _api()
    api.seen["_get_return"] = None
    assert alias_list(api) == []


def test_alias_create_cluster_path_and_required_fields():
    api = _api()
    alias_create(api, name="web", cidr="10.0.0.0/24")
    assert api.seen["method"] == "POST"
    assert api.seen["path"] == "/cluster/firewall/aliases"
    assert api.seen["data"]["name"] == "web"
    assert api.seen["data"]["cidr"] == "10.0.0.0/24"


def test_alias_create_includes_comment_when_given():
    api = _api()
    alias_create(api, name="web", cidr="10.0.0.0/24", comment="web servers")
    assert api.seen["data"]["comment"] == "web servers"


def test_alias_create_rejects_invalid_cidr():
    # consistency with ipset entries: validate the cidr fail-fast (it also prints into the plan)
    api = _api()
    with pytest.raises(ProximoError):
        alias_create(api, name="web", cidr="not-a-cidr")


def test_alias_create_omits_comment_when_absent():
    api = _api()
    alias_create(api, name="web", cidr="10.0.0.0/24")
    assert "comment" not in api.seen["data"]


def test_alias_create_node_scope_rejected():
    api = _api(node="n1")
    with pytest.raises(ProximoError, match="node scope"):
        alias_create(api, name="web", cidr="10.0.0.0/24", scope="node")


def test_alias_create_rejects_bad_name():
    api = _api()
    with pytest.raises(ProximoError):
        alias_create(api, name="-bad name!", cidr="10.0.0.0/24")


def test_alias_create_rejects_bad_scope():
    api = _api()
    with pytest.raises(ProximoError):
        alias_create(api, name="web", cidr="10.0.0.0/24", scope="bogus")


def test_alias_update_puts_correct_path_and_cidr():
    api = _api()
    alias_update(api, name="web", cidr="10.0.0.0/8")
    assert api.seen["method"] == "PUT"
    assert api.seen["path"] == "/cluster/firewall/aliases/web"
    assert api.seen["data"]["cidr"] == "10.0.0.0/8"


def test_alias_update_requires_at_least_one_field():
    api = _api()
    with pytest.raises(ProximoError):
        alias_update(api, name="web")


def test_alias_update_includes_digest_when_given():
    api = _api()
    alias_update(api, name="web", cidr="10.0.0.0/8", digest="abc123")
    assert api.seen["data"]["digest"] == "abc123"


def test_alias_update_includes_rename_and_comment():
    api = _api()
    alias_update(api, name="web", rename="webnew", comment="renamed")
    assert api.seen["data"]["rename"] == "webnew"
    assert api.seen["data"]["comment"] == "renamed"


def test_alias_delete_deletes_correct_path():
    api = _api()
    alias_delete(api, name="web")
    assert api.seen["method"] == "DELETE"
    assert api.seen["path"] == "/cluster/firewall/aliases/web"


def test_alias_delete_includes_digest_when_given():
    api = _api()
    alias_delete(api, name="web", digest="abc123")
    assert api.seen["params"]["digest"] == "abc123"


def test_alias_delete_omits_digest_when_absent():
    api = _api()
    alias_delete(api, name="web")
    assert "digest" not in (api.seen["params"] or {})


# --- alias PLAN factories ---


def test_plan_alias_create_is_low_risk_no_undo():
    plan = plan_alias_create(name="web", cidr="10.0.0.0/24")
    assert plan.risk == RISK_LOW
    assert "web" in plan.change
    assert "10.0.0.0/24" in plan.change
    assert any("no undo" in b.lower() for b in plan.blast_radius)


def test_plan_alias_update_reads_current_and_is_medium():
    api = _api()
    api.seen["_get_return"] = [{"name": "web", "cidr": "10.0.0.0/24", "comment": "old"}]
    plan = plan_alias_update(api, name="web", cidr="10.0.0.0/8")
    assert plan.risk == RISK_MEDIUM
    # current state surfaced from the safe read
    assert plan.current.get("cidr") == "10.0.0.0/24"
    # a referencing-rule caveat is present
    assert any("referenc" in b.lower() for b in plan.blast_radius)


def test_plan_alias_delete_reads_current_and_warns_referencing():
    api = _api()
    api.seen["_get_return"] = [{"name": "web", "cidr": "10.0.0.0/24"}]
    plan = plan_alias_delete(api, name="web")
    assert plan.risk == RISK_MEDIUM
    assert plan.current.get("cidr") == "10.0.0.0/24"
    assert any("referenc" in b.lower() for b in plan.blast_radius)


# ===========================================================================
# IP-SETS — ipset_create / ipset_delete / ipset_entry_add / ipset_entry_remove
# Grounded against live PVE 9.2 schema (2026-06-14):
#   POST   {base}/ipset                  {name, comment?}          create empty set
#   DELETE {base}/ipset/{name}            {force?}                  delete set (force wipes members)
#   POST   {base}/ipset/{name}            {cidr, comment?, nomatch?} add entry
#   DELETE {base}/ipset/{name}/{cidr}     {digest?}                 remove entry
# An ipset is referenced from rules as '+name'. Empty set = passive (LOW); entry
# changes alter every referencing rule's match set (MEDIUM). No UNDO.
# ===========================================================================


def test_ipset_create_cluster_path_and_name():
    api = _api()
    ipset_create(api, name="blocklist")
    assert api.seen["method"] == "POST"
    assert api.seen["path"] == "/cluster/firewall/ipset"
    assert api.seen["data"]["name"] == "blocklist"


def test_ipset_create_includes_comment():
    api = _api()
    ipset_create(api, name="blocklist", comment="bad actors")
    assert api.seen["data"]["comment"] == "bad actors"


def test_ipset_create_node_scope_rejected():
    api = _api(node="n1")
    with pytest.raises(ProximoError, match="node scope"):
        ipset_create(api, name="blocklist", scope="node")


def test_alias_ipset_plans_reject_node_scope_everywhere():
    # PLAN honesty: the dry-run must fail the same way execution will — a plan that
    # renders fine for node scope and then dies on confirm=True is a lying plan.
    api = _api(node="n1")
    calls = [
        lambda: plan_alias_create("web", "10.0.0.0/24", scope="node"),
        lambda: plan_alias_update(api, "web", scope="node", cidr="10.0.0.0/24"),
        lambda: plan_alias_delete(api, "web", scope="node"),
        lambda: plan_ipset_create("blocklist", scope="node"),
        lambda: plan_ipset_delete(api, "blocklist", scope="node"),
        lambda: plan_ipset_entry_add("blocklist", "10.0.0.1", scope="node"),
        lambda: plan_ipset_entry_remove("blocklist", "10.0.0.1", scope="node"),
    ]
    for call in calls:
        with pytest.raises(ProximoError, match="node scope"):
            call()


def test_alias_ipset_family_rejects_node_scope_everywhere():
    # Every alias/ipset op must fail-fast on node scope, not emit a 501 against PVE.
    api = _api(node="n1")
    calls = [
        lambda: alias_update(api, "web", scope="node", cidr="10.0.0.0/24"),
        lambda: alias_delete(api, "web", scope="node"),
        lambda: ipset_delete(api, "blocklist", scope="node"),
        lambda: ipset_entry_add(api, "blocklist", "10.0.0.1", scope="node"),
        lambda: ipset_entry_remove(api, "blocklist", "10.0.0.1", scope="node"),
    ]
    for call in calls:
        with pytest.raises(ProximoError, match="node scope"):
            call()


def test_ipset_create_rejects_bad_name():
    api = _api()
    with pytest.raises(ProximoError):
        ipset_create(api, name="bad/name")


def test_ipset_delete_path_no_force_sends_empty_params():
    api = _api()
    ipset_delete(api, name="blocklist")
    assert api.seen["method"] == "DELETE"
    assert api.seen["path"] == "/cluster/firewall/ipset/blocklist"
    assert "force" not in (api.seen["params"] or {})


def test_ipset_delete_with_force_sends_one():
    api = _api()
    ipset_delete(api, name="blocklist", force=True)
    assert api.seen["params"]["force"] == 1


def test_ipset_entry_add_path_and_cidr():
    api = _api()
    ipset_entry_add(api, name="blocklist", cidr="10.0.0.0/24")
    assert api.seen["method"] == "POST"
    assert api.seen["path"] == "/cluster/firewall/ipset/blocklist"
    assert api.seen["data"]["cidr"] == "10.0.0.0/24"


def test_ipset_entry_add_nomatch_true_sends_one_with_comment():
    api = _api()
    ipset_entry_add(api, name="blocklist", cidr="10.0.0.5", nomatch=True, comment="allow one")
    assert api.seen["data"]["nomatch"] == 1
    assert api.seen["data"]["comment"] == "allow one"


def test_ipset_entry_add_nomatch_false_omitted():
    api = _api()
    ipset_entry_add(api, name="blocklist", cidr="10.0.0.0/24")
    assert "nomatch" not in api.seen["data"]


def test_ipset_entry_remove_path_includes_cidr():
    api = _api()
    ipset_entry_remove(api, name="blocklist", cidr="10.0.0.0/24")
    assert api.seen["method"] == "DELETE"
    assert api.seen["path"] == "/cluster/firewall/ipset/blocklist/10.0.0.0/24"


def test_ipset_entry_remove_includes_digest_when_given():
    api = _api()
    ipset_entry_remove(api, name="blocklist", cidr="10.0.0.0/24", digest="abc")
    assert api.seen["params"]["digest"] == "abc"


# --- ipset PLAN factories ---


def test_plan_ipset_create_is_low_no_undo():
    plan = plan_ipset_create(name="blocklist")
    assert plan.risk == RISK_LOW
    assert "blocklist" in plan.change
    assert any("no undo" in b.lower() for b in plan.blast_radius)


def test_plan_ipset_delete_is_medium_surfaces_force():
    api = _api()
    api.seen["_get_return"] = [{"cidr": "10.0.0.0/24"}, {"cidr": "10.0.0.5"}]
    plan = plan_ipset_delete(api, name="blocklist", force=True)
    assert plan.risk == RISK_MEDIUM
    # the force/member-wipe semantics are surfaced
    assert any("force" in b.lower() or "member" in b.lower() for b in plan.blast_radius)


def test_plan_ipset_entry_add_is_medium():
    plan = plan_ipset_entry_add(name="blocklist", cidr="10.0.0.0/24")
    assert plan.risk == RISK_MEDIUM
    assert "10.0.0.0/24" in plan.change


def test_plan_ipset_entry_remove_is_medium():
    plan = plan_ipset_entry_remove(name="blocklist", cidr="10.0.0.0/24")
    assert plan.risk == RISK_MEDIUM
    assert "10.0.0.0/24" in plan.change


# ===========================================================================
# SECURITY GROUPS — security_group_create / security_group_delete (cluster-only)
# Grounded against live PVE 9.2 schema (2026-06-14):
#   POST   /cluster/firewall/groups          {group, comment?}   create empty group
#   DELETE /cluster/firewall/groups/{group}                       delete group (NO params; must be empty)
# A group is referenced from a rule via type=group. Empty group = passive (LOW).
# Deleting needs the group emptied of rules AND unreferenced (MEDIUM). No UNDO.
# ===========================================================================


def test_security_group_create_path_and_group():
    api = _api()
    security_group_create(api, group="web-dmz")
    assert api.seen["method"] == "POST"
    assert api.seen["path"] == "/cluster/firewall/groups"
    assert api.seen["data"]["group"] == "web-dmz"


def test_security_group_create_includes_comment():
    api = _api()
    security_group_create(api, group="web-dmz", comment="dmz hosts")
    assert api.seen["data"]["comment"] == "dmz hosts"


def test_security_group_create_rejects_bad_name():
    api = _api()
    with pytest.raises(ProximoError):
        security_group_create(api, group="bad group!")


def test_security_group_delete_path_no_params():
    api = _api()
    security_group_delete(api, group="web-dmz")
    assert api.seen["method"] == "DELETE"
    assert api.seen["path"] == "/cluster/firewall/groups/web-dmz"
    # PVE delete takes no params — we send an empty dict
    assert api.seen["params"] == {}


def test_security_group_delete_rejects_bad_name():
    api = _api()
    with pytest.raises(ProximoError):
        security_group_delete(api, group="bad/name")


def test_plan_security_group_create_is_low_no_undo():
    plan = plan_security_group_create(group="web-dmz")
    assert plan.risk == RISK_LOW
    assert "web-dmz" in plan.change
    assert any("no undo" in b.lower() for b in plan.blast_radius)


def test_plan_security_group_delete_is_medium_reads_rules():
    api = _api()
    api.seen["_get_return"] = [{"pos": 0, "action": "ACCEPT"}, {"pos": 1, "action": "DROP"}]
    plan = plan_security_group_delete(api, group="web-dmz")
    assert plan.risk == RISK_MEDIUM
    # surfaces that the group must be empty + unreferenced
    assert any("empt" in b.lower() or "referenc" in b.lower() for b in plan.blast_radius)
    assert plan.current.get("rules") == 2


# ===========================================================================
# OPTIONS SET — firewall_options_set (scope-aware)
# Grounded against live PVE 9.2 schema (2026-06-14):
#   PUT {base}/options  {<option>: <value>, ..., delete?: csv, digest?}
# Options vary by scope (cluster: enable/policy_in/out/forward/ebtables/log_ratelimit;
#   node/guest: enable/policy_in/out/log_level_in/out/...). PVE validates per scope.
# RISK_HIGH when 'enable' or any 'policy*' key changes (lockout / default-policy);
# else RISK_MEDIUM. No UNDO — config-file state.
# ===========================================================================


def test_options_set_cluster_path_and_field():
    api = _api()
    firewall_options_set(api, options={"policy_in": "DROP"})
    assert api.seen["method"] == "PUT"
    assert api.seen["path"] == "/cluster/firewall/options"
    assert api.seen["data"]["policy_in"] == "DROP"


def test_options_set_node_scope_path():
    api = _api(node="n1")
    firewall_options_set(api, scope="node", options={"log_level_in": "info"})
    assert api.seen["path"] == "/nodes/n1/firewall/options"


def test_options_set_guest_scope_path():
    api = _api()
    firewall_options_set(api, scope="guest", vmid="100", options={"dhcp": 1})
    assert api.seen["path"] == "/nodes/pve/lxc/100/firewall/options"


def test_options_set_delete_list_becomes_csv():
    api = _api()
    firewall_options_set(api, options={"policy_in": "ACCEPT"}, delete=["log_ratelimit", "ebtables"])
    assert api.seen["data"]["delete"] == "log_ratelimit,ebtables"


def test_options_set_includes_digest():
    api = _api()
    firewall_options_set(api, options={"ebtables": 1}, digest="abc")
    assert api.seen["data"]["digest"] == "abc"


def test_options_set_requires_options_or_delete():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_options_set(api)


def test_options_set_digest_alone_is_not_a_change():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_options_set(api, digest="abc")


# --- options-set PLAN factory ---


def test_plan_options_set_enable_is_high():
    api = _api()
    api.seen["_get_return"] = {"enable": 0}
    plan = plan_firewall_options_set(api, options={"enable": 1})
    assert plan.risk == RISK_HIGH


def test_plan_options_set_policy_is_high():
    api = _api()
    api.seen["_get_return"] = {"policy_in": "ACCEPT"}
    plan = plan_firewall_options_set(api, options={"policy_in": "DROP"})
    assert plan.risk == RISK_HIGH
    assert any("lockout" in b.lower() or "lock you out" in b.lower() for b in plan.blast_radius)


def test_plan_options_set_log_level_is_medium():
    api = _api()
    api.seen["_get_return"] = {}
    plan = plan_firewall_options_set(api, scope="node", options={"log_level_in": "info"})
    assert plan.risk == RISK_MEDIUM


def test_plan_options_set_reads_current_and_has_no_undo():
    api = _api()
    api.seen["_get_return"] = {"policy_in": "ACCEPT", "enable": 1}
    plan = plan_firewall_options_set(api, options={"policy_in": "DROP"})
    assert plan.current.get("policy_in") == "ACCEPT"
    assert any("no undo" in b.lower() for b in plan.blast_radius)


# ===========================================================================
# REDTEAM FIXES (2026-06-14) — hardening found by adversarial review
# ===========================================================================


# Fix 1: _check_fw_name must reject a trailing newline (regex '$' bypass).
def test_alias_create_rejects_trailing_newline_name():
    api = _api()
    with pytest.raises(ProximoError):
        alias_create(api, name="web\n", cidr="10.0.0.0/24")


def test_security_group_create_rejects_trailing_newline_name():
    api = _api()
    with pytest.raises(ProximoError):
        security_group_create(api, group="grp\n")


def test_ipset_create_rejects_trailing_newline_name():
    api = _api()
    with pytest.raises(ProximoError):
        ipset_create(api, name="set\n")


# Fix 2: cidr in ipset_entry_remove goes into the URL path — must be validated.
def test_ipset_entry_remove_rejects_path_traversal_cidr():
    api = _api()
    with pytest.raises(ProximoError):
        ipset_entry_remove(api, name="blocklist", cidr="../../nodes/x")


def test_ipset_entry_remove_accepts_valid_cidr_ip_and_ipv6():
    api = _api()
    ipset_entry_remove(api, name="blocklist", cidr="10.0.0.0/24")
    assert api.seen["path"] == "/cluster/firewall/ipset/blocklist/10.0.0.0/24"
    ipset_entry_remove(api, name="blocklist", cidr="10.0.0.5")
    ipset_entry_remove(api, name="blocklist", cidr="2001:db8::/32")


def test_ipset_entry_add_rejects_bad_cidr():
    api = _api()
    with pytest.raises(ProximoError):
        ipset_entry_add(api, name="blocklist", cidr="not a cidr!!")


# Fix 3: options HIGH-risk classification must not be bypassable.
def test_options_set_rejects_reserved_delete_key_in_options():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_options_set(api, options={"delete": "enable"})


def test_options_set_rejects_reserved_digest_key_in_options():
    api = _api()
    with pytest.raises(ProximoError):
        firewall_options_set(api, options={"digest": "x"})


def test_plan_options_set_rejects_reserved_key_in_options():
    api = _api()
    api.seen["_get_return"] = {}
    with pytest.raises(ProximoError):
        plan_firewall_options_set(api, options={"delete": "enable"})


def test_plan_options_set_delete_csv_string_with_policy_is_high():
    api = _api()
    api.seen["_get_return"] = {}
    plan = plan_firewall_options_set(api, delete="ebtables,policy_in")
    assert plan.risk == RISK_HIGH


def test_plan_options_set_delete_list_with_enable_is_high():
    api = _api()
    api.seen["_get_return"] = {}
    plan = plan_firewall_options_set(api, delete=["enable"])
    assert plan.risk == RISK_HIGH


# Fix 4: a failed members-read must NOT present as a confirmed zero-member wipe.
def test_plan_ipset_delete_read_failure_surfaces_unknown():
    bad = SimpleNamespace(
        config=SimpleNamespace(node="pve"),
        _get=lambda p: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    plan = plan_ipset_delete(bad, name="blocklist", force=True)
    assert any("unknown" in b.lower() or "read failed" in b.lower() for b in plan.blast_radius)
    assert not any("all 0 member" in b.lower() for b in plan.blast_radius)


def test_plan_security_group_delete_read_failure_surfaces_unknown():
    bad = SimpleNamespace(
        config=SimpleNamespace(node="pve"),
        _get=lambda p: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    plan = plan_security_group_delete(bad, group="web-dmz")
    assert any("unknown" in b.lower() or "read failed" in b.lower() for b in plan.blast_radius)


# ---------------------------------------------------------------------------
# PLAN: firewall-lockout blast-radius wiring (set_enabled / options_set)
# Spec: docs/specs/2026-06-19-firewall-lockout-blast-radius.md (internal-only)
# ---------------------------------------------------------------------------


class _LockoutApi:
    """Path-aware fake: serves firewall options, cluster+node firewall rules, and node enumeration
    so plan_firewall_set_enabled / plan_firewall_options_set can compute the lockout blast."""

    def __init__(self, *, node="pve", options=None, dc_rules=None,
                 node_names=("pve1",), node_rules=None):
        self.config = SimpleNamespace(node=node)
        self._options = options or {}
        self._dc = [] if dc_rules is None else dc_rules
        self._node_names = list(node_names)
        self._node_rules = node_rules or {}

    def _get(self, path):
        if path.endswith("/options"):
            return self._options
        if "/cluster/resources" in path:
            return [{"type": "node", "node": n} for n in self._node_names]
        if path == "/cluster/firewall/rules":
            return self._dc
        if path.endswith("/firewall/rules"):
            return self._node_rules.get(path.split("/")[2], [])
        return {}


def _accept_ssh(source=None):
    return {"action": "ACCEPT", "type": "in", "enable": 1, "proto": "tcp", "dport": "22",
            "source": source, "pos": 0}


def test_plan_set_enabled_cluster_names_lockout_node():
    api = _LockoutApi(options={"enable": 0}, node_names=("pve1", "pve2"),
                      node_rules={"pve1": [], "pve2": [_accept_ssh()]})  # pve1 bare, pve2 open SSH
    p = plan_firewall_set_enabled(api, True, scope="cluster")
    assert p.risk == RISK_HIGH
    locked = {a["node"] for a in p.affected if a["state"] == "lockout"}
    assert "pve1" in locked
    assert "pve2" not in {a["node"] for a in p.affected}
    assert p.complete is True


def test_plan_set_enabled_disable_does_not_run_lockout_engine():
    """Disabling strips protection (a different graph) — the lockout engine must NOT name nodes."""
    api = _LockoutApi(options={"enable": 1}, node_names=("pve1",), node_rules={"pve1": []})
    p = plan_firewall_set_enabled(api, False, scope="cluster")
    assert p.affected == []
    assert p.risk == RISK_HIGH


def test_plan_options_set_policy_drop_names_lockout_node():
    api = _LockoutApi(node_names=("pve1",), node_rules={"pve1": []})
    p = plan_firewall_options_set(api, scope="cluster", options={"policy_in": "DROP"})
    assert p.risk == RISK_HIGH
    assert any(a["node"] == "pve1" and a["state"] == "lockout" for a in p.affected)


def test_plan_options_set_policy_accept_is_not_a_lockout_trigger():
    """policy_in=ACCEPT is a WIDENING — not a lockout trigger; the engine must not run."""
    api = _LockoutApi(node_names=("pve1",), node_rules={"pve1": []})
    p = plan_firewall_options_set(api, scope="cluster", options={"policy_in": "ACCEPT"})
    assert p.affected == []


def test_plan_options_set_enable_true_triggers_lockout_engine():
    api = _LockoutApi(node_names=("pve1",), node_rules={"pve1": []})
    p = plan_firewall_options_set(api, scope="cluster", options={"enable": 1})
    assert any(a["node"] == "pve1" and a["state"] == "lockout" for a in p.affected)


class TestFirewallRuleDigestPinning:
    """M1 (2026-07-10 audit): firewall_rule_remove/update fetch the config digest at OP time, so the
    'optimistic lock' always matches current config and cannot detect the concurrent rule-insert that
    happens in the plan->confirm window (positions shift -> the WRONG rule is removed, e.g. the SSH/8006
    ACCEPT -> lockout). Fix: accept a caller-pinned digest (read at PLAN time) and use it verbatim; the
    plan must surface the digest so the caller can pin it on confirm."""

    def test_remove_uses_caller_pinned_digest(self):
        # A pinned digest must be sent verbatim, NOT the fake's op-time default 'test-digest-abc'.
        api = _api()
        firewall_rule_remove(api, 3, digest="pinned-123")
        assert api.seen["params"]["digest"] == "pinned-123"

    def test_remove_falls_back_to_optime_digest_when_unpinned(self):
        # Backward compat: no pinned digest -> current op-time fetch behavior (fake default).
        api = _api()
        firewall_rule_remove(api, 3)
        assert api.seen["params"]["digest"] == "test-digest-abc"

    def test_update_uses_caller_pinned_digest(self):
        api = _api()
        firewall_rule_update(api, 3, comment="note", digest="pinned-xyz")
        assert api.seen["data"]["digest"] == "pinned-xyz"

    def test_update_falls_back_to_optime_digest_when_unpinned(self):
        api = _api()
        firewall_rule_update(api, 3, comment="note")
        assert api.seen["data"]["digest"] == "test-digest-abc"

    def test_plan_remove_surfaces_digest_for_pinning(self):
        # The operator must be able to read the digest off the dry-run and pin it on confirm.
        api = _RulesApi([{"pos": 0, "digest": "test-digest-abc", "action": "ACCEPT", "type": "in"}])
        p = plan_firewall_rule_remove(api, 0)
        blob = str(p.current) + " " + " ".join(p.blast_radius)
        assert "test-digest-abc" in blob

    def test_plan_update_surfaces_digest_for_pinning(self):
        api = _RulesApi([{"pos": 0, "digest": "test-digest-abc", "action": "ACCEPT", "type": "in"}])
        p = plan_firewall_rule_update(api, 0, comment="note")
        blob = str(p.current) + " " + " ".join(p.blast_radius)
        assert "test-digest-abc" in blob


class TestPlanReadFailureCompleteness:
    """2026-07-10 audit M7/L17: plan factories must not present a failed current-state read as an
    empty current with complete=True — a failed read means the revert baseline is UNKNOWN."""

    def test_options_set_read_failure_is_incomplete(self):
        # M7: HIGH-risk lockout-class mutation; a swallowed options read must set complete=False.
        api = _OptionsApi(None, raise_on_get=True)
        p = plan_firewall_options_set(api, scope="cluster", options={"log_level_in": "info"})
        assert p.complete is False
        assert any("could not read" in b.lower() or "unknown" in b.lower() for b in p.blast_radius)

    def test_alias_update_read_failure_is_incomplete(self):
        # L17: _find_alias merged 'absent' with 'read failed' — a read failure must be disclosed.
        api = _RulesApi([], raise_on_list=True)
        p = plan_alias_update(api, "web", cidr="10.0.0.0/8")
        assert p.complete is False

    def test_alias_delete_read_failure_is_incomplete(self):
        api = _RulesApi([], raise_on_list=True)
        p = plan_alias_delete(api, "web")
        assert p.complete is False


class TestFirewallCommentFreetextGuard:
    """L9 (2026-07-10 audit): firewall comment fields are stored in PVE's line-based config, the same
    threat class the access modules already guard with _check_freetext. Reject control chars/newlines
    here too, so the repo's own stated threat model is enforced consistently."""

    def test_alias_create_rejects_newline_in_comment(self):
        api = _api()
        with pytest.raises(ProximoError):
            alias_create(api, "web", "10.0.0.0/8", comment="x\n[RULES]\nIN ACCEPT -p tcp")

    def test_rule_add_rejects_newline_in_comment(self):
        api = _api()
        with pytest.raises(ProximoError):
            firewall_rule_add(api, "ACCEPT", comment="bad\ncomment")

    def test_alias_create_allows_normal_comment(self):
        api = _api()
        alias_create(api, "web", "10.0.0.0/8", comment="web servers")
        assert api.seen["method"] == "POST"
