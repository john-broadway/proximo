"""CLUSTER / HA / MIGRATION pillar tests.

Fully mocked, no live Proxmox.  Mirrors test_provisioning.py / test_backends.py style:
- _api() records _get / _post / _delete calls; assertions verify URL + param shapes.
- _StatusApi supplies guest_status for plan_migrate's live-state read.
- Validator-rejection tests use pytest.raises(ProximoError).
- PLAN-before-mutate is enforced by the server layer (not tested here per spec); these tests
  verify that op functions build the correct requests and plan_* functions produce correct,
  honest, non-contradictory Plans.
"""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from proximo.backends import ProximoError
from proximo.cluster_ops import (
    _build_sid,
    cluster_resources,
    cluster_status,
    guest_migrate,
    ha_groups_list,
    ha_resource_add,
    ha_resource_remove,
    ha_resources_list,
    ha_rule_create,
    ha_rule_delete,
    ha_rule_update,
    ha_rules_list,
    plan_ha_resource_add,
    plan_ha_resource_remove,
    plan_ha_rule_create,
    plan_ha_rule_delete,
    plan_ha_rule_update,
    plan_migrate,
)
from proximo.planning import RISK_HIGH, RISK_MEDIUM

# ---------------------------------------------------------------------------
# Shared fakes
# ---------------------------------------------------------------------------

def _api(node: str = "pve") -> SimpleNamespace:
    """Minimal API fake that records _get / _post / _delete calls."""
    seen: dict = {}

    def fake_get(path):
        seen["method"] = "GET"
        seen["path"] = path
        return seen.get("_get_return", [])  # default [] preserves existing behavior

    def fake_post(path, data=None):
        seen["method"] = "POST"
        seen["path"] = path
        seen["data"] = data or {}
        return "UPID:pve:00001:0:0:0:qmigrate:100:root@pam:"

    def fake_put(path, data=None):
        seen["method"] = "PUT"
        seen["path"] = path
        seen["data"] = data or {}
        return None

    def fake_delete(path, params=None):
        seen["method"] = "DELETE"
        seen["path"] = path
        seen["params"] = params
        return None  # HA remove returns null (synchronous write)

    return SimpleNamespace(
        config=SimpleNamespace(node=node),
        _get=fake_get,
        _post=fake_post,
        _put=fake_put,
        _delete=fake_delete,
        seen=seen,
    )


class _StatusApi:
    """Fake for plan_migrate: supplies guest_status + config.node."""

    def __init__(
        self,
        status: dict | None,
        node: str = "pve",
        raise_on_status: bool = False,
    ):
        self._status = status
        self.config = SimpleNamespace(node=node)
        self._raise = raise_on_status
        self.calls: list = []

    def guest_status(self, vmid, kind="lxc", node=None):
        self.calls.append((vmid, kind, node))
        if self._raise:
            raise RuntimeError("transient API error")  # no .response → unknown
        if self._status is None:
            err = RuntimeError("not found")
            err.response = SimpleNamespace(status_code=404)
            raise err
        return self._status

    def _get(self, path):
        # The migrate disk-residency blast reads the guest config + cluster storage.cfg. Model a
        # CLEAN shared-storage guest so these source-side tests keep their base risk (the local-disk
        # escalation + naming are covered by test_blast_migrate.py and the wiring tests below).
        if path.endswith("/config"):
            return {"scsi0": "shared-store:vm-1-disk-0,size=8G"}
        if path == "/storage":
            return [{"storage": "shared-store", "shared": 1}]
        return {}


# ---------------------------------------------------------------------------
# cluster_status
# ---------------------------------------------------------------------------

def test_cluster_status_uses_correct_path():
    api = _api()
    cluster_status(api)
    assert api.seen["path"] == "/cluster/status"
    assert api.seen["method"] == "GET"


def test_cluster_status_is_not_node_scoped():
    api = _api()
    cluster_status(api)
    assert "/nodes/" not in api.seen["path"]


def test_cluster_status_returns_list():
    api = _api()
    result = cluster_status(api)
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# cluster_resources
# ---------------------------------------------------------------------------

def test_cluster_resources_no_type_uses_base_path():
    api = _api()
    cluster_resources(api)
    assert api.seen["path"] == "/cluster/resources"
    assert api.seen["method"] == "GET"


def test_cluster_resources_with_type_appends_query():
    api = _api()
    cluster_resources(api, resource_type="vm")
    assert api.seen["path"] == "/cluster/resources?type=vm"


def test_cluster_resources_all_valid_types_accepted():
    for rt in ("vm", "storage", "node", "sdn"):
        api = _api()
        cluster_resources(api, resource_type=rt)
        assert f"type={rt}" in api.seen["path"]


def test_cluster_resources_rejects_invalid_type():
    api = _api()
    with pytest.raises(ProximoError):
        cluster_resources(api, resource_type="container")


def test_cluster_resources_is_not_node_scoped():
    api = _api()
    cluster_resources(api)
    assert "/nodes/" not in api.seen["path"]


# ---------------------------------------------------------------------------
# ha_groups_list
# ---------------------------------------------------------------------------

def test_ha_groups_list_uses_correct_path():
    api = _api()
    ha_groups_list(api)
    assert api.seen["path"] == "/cluster/ha/groups"
    assert api.seen["method"] == "GET"


def test_ha_groups_list_is_not_node_scoped():
    api = _api()
    ha_groups_list(api)
    assert "/nodes/" not in api.seen["path"]


def _api_get_raises(exc: Exception) -> SimpleNamespace:
    def fake_get(path):
        raise exc
    return SimpleNamespace(config=SimpleNamespace(node="pve"), _get=fake_get)


def test_ha_groups_list_translates_pve9_migration_500_to_clear_error():
    """PVE 9 returns 500 'migrated to rules' — translate to a ProximoError pointing at rules,
    NOT a raw HTTPStatusError."""
    req = httpx.Request("GET", "https://x:8006/api2/json/cluster/ha/groups")
    resp = httpx.Response(
        500, text="cannot index groups: ha groups have been migrated to rules", request=req
    )
    exc = httpx.HTTPStatusError(
        "Server error '500 cannot index groups: ha groups have been migrated to rules'",
        request=req, response=resp,
    )
    with pytest.raises(ProximoError, match="migrated to HA rules"):
        ha_groups_list(_api_get_raises(exc))


def test_ha_groups_list_reraises_unrelated_http_errors():
    """A non-migration HTTP error (e.g. 403) is NOT swallowed — it re-raises unchanged."""
    req = httpx.Request("GET", "https://x:8006/api2/json/cluster/ha/groups")
    resp = httpx.Response(403, text="Permission check failed", request=req)
    exc = httpx.HTTPStatusError("403", request=req, response=resp)
    with pytest.raises(httpx.HTTPStatusError):
        ha_groups_list(_api_get_raises(exc))


def test_ha_rules_list_uses_correct_path():
    api = _api()
    ha_rules_list(api)
    assert api.seen["path"] == "/cluster/ha/rules"
    assert api.seen["method"] == "GET"


def test_ha_rules_list_is_not_node_scoped():
    api = _api()
    ha_rules_list(api)
    assert "/nodes/" not in api.seen["path"]


# ---------------------------------------------------------------------------
# ha_resources_list
# ---------------------------------------------------------------------------

def test_ha_resources_list_uses_correct_path():
    api = _api()
    ha_resources_list(api)
    assert api.seen["path"] == "/cluster/ha/resources"
    assert api.seen["method"] == "GET"


def test_ha_resources_list_is_not_node_scoped():
    api = _api()
    ha_resources_list(api)
    assert "/nodes/" not in api.seen["path"]


# ---------------------------------------------------------------------------
# _build_sid — SID construction
# ---------------------------------------------------------------------------

def test_build_sid_qemu_uses_vm_prefix():
    assert _build_sid("100", "qemu") == "vm:100"


def test_build_sid_lxc_uses_ct_prefix():
    assert _build_sid("200", "lxc") == "ct:200"


# ---------------------------------------------------------------------------
# guest_migrate — URL + param shapes
# ---------------------------------------------------------------------------

def test_guest_migrate_lxc_offline_correct_path():
    api = _api()
    guest_migrate(api, "100", "pve2", kind="lxc")
    assert api.seen["path"] == "/nodes/pve/lxc/100/migrate"
    assert api.seen["method"] == "POST"


def test_guest_migrate_qemu_offline_correct_path():
    api = _api()
    guest_migrate(api, "300", "pve2", kind="qemu")
    assert api.seen["path"] == "/nodes/pve/qemu/300/migrate"


def test_guest_migrate_uses_explicit_node():
    api = _api(node="pve2")
    guest_migrate(api, "100", "pve3", kind="lxc", node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_guest_migrate_uses_config_node_when_none():
    api = _api(node="nodeA")
    guest_migrate(api, "100", "nodeB", kind="lxc")
    assert "/nodes/nodeA/" in api.seen["path"]


def test_guest_migrate_sends_target():
    api = _api()
    guest_migrate(api, "100", "pve2", kind="lxc")
    assert api.seen["data"]["target"] == "pve2"


def test_guest_migrate_offline_sends_no_online_or_restart():
    api = _api()
    guest_migrate(api, "100", "pve2", kind="lxc", online=False)
    assert "online" not in api.seen["data"]
    assert "restart" not in api.seen["data"]


def test_guest_migrate_qemu_online_sends_online_1():
    api = _api()
    guest_migrate(api, "300", "pve2", kind="qemu", online=True)
    assert api.seen["data"].get("online") == 1
    assert "restart" not in api.seen["data"]


def test_guest_migrate_lxc_online_sends_restart_1_not_online():
    """LXC has no live migration — 'online=True' maps to restart=1, NOT online=1."""
    api = _api()
    guest_migrate(api, "100", "pve2", kind="lxc", online=True)
    assert api.seen["data"].get("restart") == 1
    assert "online" not in api.seen["data"]


def test_guest_migrate_returns_upid():
    api = _api()
    result = guest_migrate(api, "100", "pve2", kind="lxc")
    assert isinstance(result, str) and result.startswith("UPID:")


def test_guest_migrate_rejects_nonnumeric_vmid():
    api = _api()
    with pytest.raises(ProximoError):
        guest_migrate(api, "abc", "pve2")


def test_guest_migrate_rejects_bad_kind():
    api = _api()
    with pytest.raises(ProximoError):
        guest_migrate(api, "100", "pve2", kind="docker")


def test_guest_migrate_rejects_empty_target():
    api = _api()
    with pytest.raises(ProximoError):
        guest_migrate(api, "100", "")


def test_guest_migrate_rejects_invalid_node():
    api = _api()
    with pytest.raises(ProximoError):
        guest_migrate(api, "100", "pve2", node="bad/node")


# ---------------------------------------------------------------------------
# ha_resource_add — URL + param shapes
# ---------------------------------------------------------------------------

def test_ha_resource_add_uses_cluster_path():
    api = _api()
    ha_resource_add(api, "100", kind="qemu")
    assert api.seen["path"] == "/cluster/ha/resources"
    assert api.seen["method"] == "POST"


def test_ha_resource_add_is_not_node_scoped():
    api = _api()
    ha_resource_add(api, "100", kind="qemu")
    assert "/nodes/" not in api.seen["path"]


def test_ha_resource_add_qemu_builds_vm_sid():
    api = _api()
    ha_resource_add(api, "100", kind="qemu")
    assert api.seen["data"]["sid"] == "vm:100"


def test_ha_resource_add_lxc_builds_ct_sid():
    api = _api()
    ha_resource_add(api, "200", kind="lxc")
    assert api.seen["data"]["sid"] == "ct:200"


def test_ha_resource_add_sends_group_when_provided():
    api = _api()
    ha_resource_add(api, "100", kind="qemu", group="mygroup")
    assert api.seen["data"]["group"] == "mygroup"


def test_ha_resource_add_omits_group_when_not_provided():
    api = _api()
    ha_resource_add(api, "100", kind="qemu")
    assert "group" not in api.seen["data"]


def test_ha_resource_add_sends_state_when_provided():
    api = _api()
    ha_resource_add(api, "100", kind="qemu", state="started")
    assert api.seen["data"]["state"] == "started"


def test_ha_resource_add_omits_state_when_not_provided():
    api = _api()
    ha_resource_add(api, "100", kind="qemu")
    assert "state" not in api.seen["data"]


def test_ha_resource_add_sends_max_restart_when_provided():
    api = _api()
    ha_resource_add(api, "100", kind="qemu", max_restart=3)
    assert api.seen["data"]["max_restart"] == 3


def test_ha_resource_add_sends_max_relocate_when_provided():
    api = _api()
    ha_resource_add(api, "100", kind="qemu", max_relocate=2)
    assert api.seen["data"]["max_relocate"] == 2


def test_ha_resource_add_rejects_invalid_state():
    api = _api()
    with pytest.raises(ProximoError):
        ha_resource_add(api, "100", kind="qemu", state="running")


def test_ha_resource_add_rejects_nonnumeric_vmid():
    api = _api()
    with pytest.raises(ProximoError):
        ha_resource_add(api, "abc", kind="qemu")


def test_ha_resource_add_rejects_bad_kind():
    api = _api()
    with pytest.raises(ProximoError):
        ha_resource_add(api, "100", kind="kvm")


def test_ha_resource_add_rejects_bad_group_name():
    api = _api()
    with pytest.raises(ProximoError):
        ha_resource_add(api, "100", kind="qemu", group="bad:group")


def test_ha_resource_add_can_return_none():
    """HA add is a synchronous pmxcfs write — null return is normal, not an error."""
    api = _api()
    # Override _post to return None (synchronous success)
    api._post = lambda path, data=None: None
    result = ha_resource_add(api, "100", kind="qemu")
    assert result is None  # not a UPID — do NOT validate as one


# ---------------------------------------------------------------------------
# ha_resource_remove — URL + param shapes
# ---------------------------------------------------------------------------

def test_ha_resource_remove_qemu_uses_vm_sid_in_path():
    api = _api()
    ha_resource_remove(api, "100", kind="qemu")
    assert api.seen["path"] == "/cluster/ha/resources/vm:100"
    assert api.seen["method"] == "DELETE"


def test_ha_resource_remove_lxc_uses_ct_sid_in_path():
    api = _api()
    ha_resource_remove(api, "200", kind="lxc")
    assert api.seen["path"] == "/cluster/ha/resources/ct:200"


def test_ha_resource_remove_path_is_not_node_scoped():
    api = _api()
    ha_resource_remove(api, "100", kind="lxc")
    assert "/nodes/" not in api.seen["path"]


def test_ha_resource_remove_colon_not_percent_encoded():
    """The raw colon in vm:100 must NOT be percent-encoded in the DELETE path."""
    api = _api()
    ha_resource_remove(api, "100", kind="qemu")
    assert "vm:100" in api.seen["path"]
    assert "vm%3A" not in api.seen["path"]


def test_ha_resource_remove_can_return_none():
    """HA remove is a synchronous pmxcfs write — null return is normal."""
    api = _api()
    result = ha_resource_remove(api, "100", kind="lxc")
    assert result is None


def test_ha_resource_remove_rejects_nonnumeric_vmid():
    api = _api()
    with pytest.raises(ProximoError):
        ha_resource_remove(api, "xyz", kind="lxc")


def test_ha_resource_remove_rejects_bad_kind():
    api = _api()
    with pytest.raises(ProximoError):
        ha_resource_remove(api, "100", kind="docker")


# ---------------------------------------------------------------------------
# plan_migrate — risk ratings, blast radius, live-state read
# ---------------------------------------------------------------------------

def test_plan_migrate_qemu_offline_is_high_risk():
    api = _StatusApi({"status": "stopped", "name": "vm-a"})
    p = plan_migrate(api, "300", "pve2", kind="qemu", node="pve")
    assert p.risk == RISK_HIGH


def test_plan_migrate_lxc_offline_is_high_risk():
    api = _StatusApi({"status": "stopped", "name": "ct-a"})
    p = plan_migrate(api, "100", "pve2", kind="lxc", node="pve")
    assert p.risk == RISK_HIGH


def test_plan_migrate_qemu_online_is_medium_risk():
    """QEMU live migration = MEDIUM (designed for zero-downtime, with caveats)."""
    api = _StatusApi({"status": "running", "name": "vm-b"})
    p = plan_migrate(api, "300", "pve2", kind="qemu", node="pve", online=True)
    assert p.risk == RISK_MEDIUM


def test_plan_migrate_lxc_online_is_high_risk():
    """LXC 'online' migration = restart = confirmed downtime = HIGH."""
    api = _StatusApi({"status": "running", "name": "ct-b"})
    p = plan_migrate(api, "100", "pve2", kind="lxc", node="pve", online=True)
    assert p.risk == RISK_HIGH


def test_plan_migrate_lxc_online_blast_mentions_downtime():
    api = _StatusApi({"status": "running", "name": "ct-b"})
    p = plan_migrate(api, "100", "pve2", kind="lxc", node="pve", online=True)
    text = " ".join(p.blast_radius).lower()
    assert "downtime" in text or "stop" in text


def test_plan_migrate_names_source_and_target():
    api = _StatusApi({"status": "running", "name": "vm-c"})
    p = plan_migrate(api, "300", "pve2", kind="qemu", node="pve")
    assert "pve2" in p.change and "300" in p.change


def test_plan_migrate_reads_live_status():
    api = _StatusApi({"status": "running", "name": "live-vm"})
    p = plan_migrate(api, "300", "pve2", kind="qemu", node="pve")
    assert p.current.get("name") == "live-vm"
    assert p.current.get("status") == "running"


def test_plan_migrate_not_found_stays_high_risk():
    api = _StatusApi(None)  # 404 → guest not found
    p = plan_migrate(api, "300", "pve2", kind="qemu", node="pve")
    assert p.risk == RISK_HIGH


def test_plan_migrate_not_found_blast_says_will_fail():
    api = _StatusApi(None)
    p = plan_migrate(api, "300", "pve2", kind="qemu", node="pve")
    assert any("will fail" in b.lower() or "not found" in b.lower() for b in p.blast_radius)


def test_plan_migrate_transient_error_discloses_uncertainty():
    api = _StatusApi(None, raise_on_status=True)
    p = plan_migrate(api, "300", "pve2", kind="qemu", node="pve")
    assert p.risk == RISK_HIGH
    text = " ".join(p.blast_radius).lower()
    assert "could not" in text or "uncertain" in text or "failed" in text


def test_plan_migrate_blast_says_no_undo():
    api = _StatusApi({"status": "stopped", "name": "vm"})
    p = plan_migrate(api, "300", "pve2", kind="qemu", node="pve")
    text = " ".join(p.blast_radius + [p.note]).lower()
    assert "cannot" in text or "undo" in text or "migrate back" in text


def test_plan_migrate_action_string():
    api = _StatusApi({"status": "stopped", "name": "vm"})
    p = plan_migrate(api, "300", "pve2", kind="qemu", node="pve")
    assert p.action == "pve_guest_migrate"


def test_plan_migrate_target_includes_vmid_and_dest():
    api = _StatusApi({"status": "stopped", "name": "vm"})
    p = plan_migrate(api, "300", "pve2", kind="qemu", node="pve")
    assert "300" in p.target and "pve2" in p.target


def test_plan_migrate_rejects_nonnumeric_vmid():
    api = _StatusApi({})
    with pytest.raises(ProximoError):
        plan_migrate(api, "abc", "pve2")


def test_plan_migrate_rejects_bad_kind():
    api = _StatusApi({})
    with pytest.raises(ProximoError):
        plan_migrate(api, "100", "pve2", kind="xen")


def test_plan_migrate_rejects_empty_target():
    api = _StatusApi({})
    with pytest.raises(ProximoError):
        plan_migrate(api, "100", "")


# ---------------------------------------------------------------------------
# plan_ha_resource_add — risk ratings, blast radius
# ---------------------------------------------------------------------------

def test_plan_ha_resource_add_default_is_medium_risk():
    p = plan_ha_resource_add("100", kind="qemu")
    assert p.risk == RISK_MEDIUM


def test_plan_ha_resource_add_surfaces_max_restart_zero():
    # max_restart=0 silently disables CRM auto-restart — the plan must surface it, not hide it
    p = plan_ha_resource_add("100", kind="qemu", max_restart=0)
    blast = " ".join(p.blast_radius)
    assert "max_restart=0" in blast
    assert "NOT auto-restart" in blast
    assert "max_restart=0" in p.change


def test_plan_ha_resource_add_started_state_is_medium():
    p = plan_ha_resource_add("100", kind="qemu", state="started")
    assert p.risk == RISK_MEDIUM


def test_plan_ha_resource_add_stopped_state_is_high_risk():
    """state='stopped' tells the CRM to stop the guest — confirmed downtime → HIGH."""
    p = plan_ha_resource_add("100", kind="qemu", state="stopped")
    assert p.risk == RISK_HIGH


def test_plan_ha_resource_add_stopped_blast_mentions_stop():
    p = plan_ha_resource_add("100", kind="qemu", state="stopped")
    text = " ".join(p.blast_radius).lower()
    assert "stop" in text


def test_plan_ha_resource_add_includes_sid_in_blast():
    p = plan_ha_resource_add("100", kind="qemu")
    assert any("vm:100" in b for b in p.blast_radius)


def test_plan_ha_resource_add_lxc_includes_ct_sid():
    p = plan_ha_resource_add("200", kind="lxc")
    assert any("ct:200" in b for b in p.blast_radius)


def test_plan_ha_resource_add_includes_group_in_blast_when_provided():
    p = plan_ha_resource_add("100", kind="qemu", group="prod")
    assert any("prod" in b for b in p.blast_radius)


def test_plan_ha_resource_add_blast_mentions_undo_path():
    p = plan_ha_resource_add("100", kind="qemu")
    text = " ".join(p.blast_radius).lower()
    assert "ha_resource_remove" in text or "remove" in text


def test_plan_ha_resource_add_action_string():
    p = plan_ha_resource_add("100", kind="qemu")
    assert p.action == "pve_ha_resource_add"


def test_plan_ha_resource_add_target_is_sid():
    p = plan_ha_resource_add("100", kind="qemu")
    assert p.target == "vm:100"


def test_plan_ha_resource_add_rejects_invalid_state():
    with pytest.raises(ProximoError):
        plan_ha_resource_add("100", kind="qemu", state="running")


def test_plan_ha_resource_add_rejects_nonnumeric_vmid():
    with pytest.raises(ProximoError):
        plan_ha_resource_add("abc", kind="qemu")


def test_plan_ha_resource_add_rejects_bad_kind():
    with pytest.raises(ProximoError):
        plan_ha_resource_add("100", kind="kvm")


# ---------------------------------------------------------------------------
# plan_ha_resource_remove — risk ratings, blast radius
# ---------------------------------------------------------------------------

def test_plan_ha_resource_remove_is_medium_risk():
    p = plan_ha_resource_remove("100", kind="qemu")
    assert p.risk == RISK_MEDIUM


def test_plan_ha_resource_remove_blast_says_no_guest_stop():
    """Removing from HA does NOT stop the guest — blast must not claim it does."""
    p = plan_ha_resource_remove("100", kind="qemu")
    text = " ".join(p.blast_radius).lower()
    # Must NOT say guest is stopped by this op.
    assert "not stopped" in text or "not affected" in text or "guest itself is not" in text


def test_plan_ha_resource_remove_blast_says_protection_lost():
    p = plan_ha_resource_remove("100", kind="qemu")
    text = " ".join(p.blast_radius).lower()
    assert "failover" in text or "protection" in text or "ha" in text


def test_plan_ha_resource_remove_blast_mentions_re_add_path():
    p = plan_ha_resource_remove("100", kind="qemu")
    text = " ".join(p.blast_radius).lower()
    assert "ha_resource_add" in text or "re-add" in text


def test_plan_ha_resource_remove_includes_correct_sid():
    p = plan_ha_resource_remove("100", kind="qemu")
    assert "vm:100" in p.target


def test_plan_ha_resource_remove_lxc_uses_ct_sid():
    p = plan_ha_resource_remove("200", kind="lxc")
    assert "ct:200" in p.target


def test_plan_ha_resource_remove_action_string():
    p = plan_ha_resource_remove("100", kind="qemu")
    assert p.action == "pve_ha_resource_remove"


def test_plan_ha_resource_remove_rejects_nonnumeric_vmid():
    with pytest.raises(ProximoError):
        plan_ha_resource_remove("abc")


def test_plan_ha_resource_remove_rejects_bad_kind():
    with pytest.raises(ProximoError):
        plan_ha_resource_remove("100", kind="docker")


# ---------------------------------------------------------------------------
# FIX 7: ha_resource_add wraps bad max_restart / max_relocate in ProximoError
# ---------------------------------------------------------------------------

def test_ha_resource_add_rejects_string_max_restart():
    """Non-numeric max_restart must raise ProximoError, not bare ValueError."""
    api = _api()
    with pytest.raises(ProximoError, match="max_restart"):
        ha_resource_add(api, "100", kind="qemu", max_restart="bad")


def test_ha_resource_add_rejects_none_coercion_max_restart():
    """max_restart=None should NOT raise (None → skipped), only non-int strings."""
    api = _api()
    ha_resource_add(api, "100", kind="qemu", max_restart=None)
    assert "max_restart" not in api.seen.get("data", {})


def test_ha_resource_add_rejects_string_max_relocate():
    """Non-numeric max_relocate must raise ProximoError, not bare ValueError."""
    api = _api()
    with pytest.raises(ProximoError, match="max_relocate"):
        ha_resource_add(api, "100", kind="qemu", max_relocate="bad")


def test_ha_resource_add_rejects_list_max_restart():
    """A list passed as max_restart (TypeError) must also raise ProximoError."""
    api = _api()
    with pytest.raises(ProximoError, match="max_restart"):
        ha_resource_add(api, "100", kind="qemu", max_restart=[1, 2])


# ===========================================================================
# HA RULES — ha_rule_create / update / delete  (PVE 9 replacement for HA groups)
# Grounded against live PVE 9.1.7 schema (2026-06-14):
#   POST   /cluster/ha/rules          {rule, type, resources, comment?, disable?}
#     [type=node-affinity]      + {nodes, strict?}
#     [type=resource-affinity]  + {affinity: positive|negative}
#   PUT    /cluster/ha/rules/{rule}    {comment?, disable?, resources?, type?, nodes?, strict?,
#                                       affinity?, delete?: csv, digest?}
#   DELETE /cluster/ha/rules/{rule}    (no params)
# HA groups CRUD is intentionally NOT built — groups 500 at runtime on PVE 9 (migrated to rules).
# Rules are config-file state: no UNDO; revert = inverse op. RISK_MEDIUM (HA placement constraints).
# ===========================================================================


def test_ha_rule_create_node_affinity_posts_correct():
    api = _api()
    ha_rule_create(api, "pin-web", "node-affinity", "vm:100", nodes="pve1:2,pve2:1")
    assert api.seen["method"] == "POST"
    assert api.seen["path"] == "/cluster/ha/rules"
    assert api.seen["data"]["rule"] == "pin-web"
    assert api.seen["data"]["type"] == "node-affinity"
    assert api.seen["data"]["resources"] == "vm:100"
    assert api.seen["data"]["nodes"] == "pve1:2,pve2:1"


def test_ha_rule_create_node_affinity_strict_sends_one():
    api = _api()
    ha_rule_create(api, "pin-web", "node-affinity", "vm:100", nodes="pve1", strict=True)
    assert api.seen["data"]["strict"] == 1


def test_ha_rule_create_node_affinity_requires_nodes():
    api = _api()
    with pytest.raises(ProximoError):
        ha_rule_create(api, "pin-web", "node-affinity", "vm:100")


def test_ha_rule_create_resource_affinity_posts_affinity():
    api = _api()
    ha_rule_create(api, "keep-apart", "resource-affinity", "vm:100,ct:101", affinity="negative")
    assert api.seen["data"]["type"] == "resource-affinity"
    assert api.seen["data"]["affinity"] == "negative"
    assert api.seen["data"]["resources"] == "vm:100,ct:101"


def test_ha_rule_create_resource_affinity_requires_affinity():
    api = _api()
    with pytest.raises(ProximoError):
        ha_rule_create(api, "keep-apart", "resource-affinity", "vm:100,ct:101")


def test_ha_rule_create_rejects_bad_affinity_value():
    api = _api()
    with pytest.raises(ProximoError):
        ha_rule_create(api, "x", "resource-affinity", "vm:100", affinity="sideways")


def test_ha_rule_create_rejects_bad_type():
    api = _api()
    with pytest.raises(ProximoError):
        ha_rule_create(api, "x", "magnet-affinity", "vm:100", nodes="pve1")


def test_ha_rule_create_rejects_bad_rule_name():
    api = _api()
    with pytest.raises(ProximoError):
        ha_rule_create(api, "bad rule!", "node-affinity", "vm:100", nodes="pve1")


def test_ha_rule_create_rejects_bad_resources():
    api = _api()
    with pytest.raises(ProximoError):
        ha_rule_create(api, "x", "node-affinity", "foo:100", nodes="pve1")  # bad prefix
    with pytest.raises(ProximoError):
        ha_rule_create(api, "x", "node-affinity", "vm:abc", nodes="pve1")   # non-numeric


def test_ha_rule_create_disable_sends_one():
    api = _api()
    ha_rule_create(api, "x", "node-affinity", "vm:100", nodes="pve1", disable=True)
    assert api.seen["data"]["disable"] == 1


def test_ha_rule_update_puts_correct_path_and_fields():
    api = _api()
    ha_rule_update(api, "pin-web", comment="updated", disable=True)
    assert api.seen["method"] == "PUT"
    assert api.seen["path"] == "/cluster/ha/rules/pin-web"
    assert api.seen["data"]["comment"] == "updated"
    assert api.seen["data"]["disable"] == 1


def test_ha_rule_update_requires_a_field():
    api = _api()
    with pytest.raises(ProximoError):
        ha_rule_update(api, "pin-web")


def test_ha_rule_update_includes_digest():
    api = _api()
    ha_rule_update(api, "pin-web", comment="x", digest="abc")
    assert api.seen["data"]["digest"] == "abc"


def test_ha_rule_update_delete_list_becomes_csv():
    api = _api()
    ha_rule_update(api, "pin-web", delete=["strict", "comment"])
    assert api.seen["data"]["delete"] == "strict,comment"


def test_ha_rule_update_disable_false_sends_zero():
    api = _api()
    ha_rule_update(api, "pin-web", disable=False)
    assert api.seen["data"]["disable"] == 0


def test_ha_rule_delete_path_no_params():
    api = _api()
    ha_rule_delete(api, "pin-web")
    assert api.seen["method"] == "DELETE"
    assert api.seen["path"] == "/cluster/ha/rules/pin-web"


def test_ha_rule_delete_rejects_bad_name():
    api = _api()
    with pytest.raises(ProximoError):
        ha_rule_delete(api, "bad/name")


# --- HA rule PLAN factories ---


def test_plan_ha_rule_create_node_affinity_is_medium_no_undo():
    plan = plan_ha_rule_create("pin-web", "node-affinity", "vm:100", nodes="pve1")
    assert plan.risk == RISK_MEDIUM
    assert "pin-web" in plan.change
    assert any("no undo" in b.lower() for b in plan.blast_radius)


def test_plan_ha_rule_create_strict_node_affinity_warns_strand():
    plan = plan_ha_rule_create("pin-web", "node-affinity", "vm:100", nodes="pve1", strict=True)
    assert any("strict" in b.lower() or "only" in b.lower() for b in plan.blast_radius)


def test_plan_ha_rule_create_resource_affinity_is_medium():
    plan = plan_ha_rule_create("keep-apart", "resource-affinity", "vm:100,ct:101", affinity="negative")
    assert plan.risk == RISK_MEDIUM


def test_plan_ha_rule_update_reads_current_and_is_medium():
    api = _api()
    api.seen["_get_return"] = [{"rule": "pin-web", "type": "node-affinity", "nodes": "pve1"}]
    plan = plan_ha_rule_update(api, "pin-web", comment="x")
    assert plan.risk == RISK_MEDIUM
    assert plan.current.get("type") == "node-affinity"


def test_plan_ha_rule_delete_reads_current_and_is_medium():
    api = _api()
    api.seen["_get_return"] = [{"rule": "pin-web", "type": "node-affinity"}]
    plan = plan_ha_rule_delete(api, "pin-web")
    assert plan.risk == RISK_MEDIUM
    assert plan.current.get("rule") == "pin-web"


def test_plan_ha_rule_delete_read_failure_surfaces_unknown():
    bad = SimpleNamespace(
        config=SimpleNamespace(node="pve"),
        _get=lambda p: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    plan = plan_ha_rule_delete(bad, "pin-web")
    assert any("unknown" in b.lower() or "read failed" in b.lower() for b in plan.blast_radius)


# --- HA rule REDTEAM fixes (2026-06-14): plan/op parity + delete surfacing ---


def test_plan_ha_rule_create_node_affinity_requires_nodes_parity():
    # the plan must reject what the op rejects, so a dry-run never previews an invalid create
    with pytest.raises(ProximoError):
        plan_ha_rule_create("pin-web", "node-affinity", "vm:100")


def test_plan_ha_rule_create_resource_affinity_requires_affinity_parity():
    with pytest.raises(ProximoError):
        plan_ha_rule_create("keep-apart", "resource-affinity", "vm:100,ct:101")


def test_plan_ha_rule_create_rejects_bad_affinity_parity():
    with pytest.raises(ProximoError):
        plan_ha_rule_create("x", "resource-affinity", "vm:100", affinity="sideways")


def test_plan_ha_rule_update_surfaces_delete():
    api = _api()
    api.seen["_get_return"] = [{"rule": "pin-web", "type": "node-affinity"}]
    plan = plan_ha_rule_update(api, "pin-web", delete=["strict"])
    blob = (plan.change + " " + " ".join(plan.blast_radius)).lower()
    assert "strict" in blob or "delete" in blob


def test_ha_rule_update_auto_includes_type_when_omitted():
    # PVE's PUT needs the `type` discriminator; auto-fetch it from the current rule so a
    # partial update (e.g. comment-only) "just works" instead of 400-ing (live-surfaced 2026-06-14).
    api = _api()
    api.seen["_get_return"] = [{"rule": "pin-web", "type": "node-affinity"}]
    ha_rule_update(api, "pin-web", comment="x")
    assert api.seen["data"]["type"] == "node-affinity"


def test_ha_rule_update_caller_type_not_overridden_by_autofetch():
    api = _api()
    api.seen["_get_return"] = [{"rule": "pin-web", "type": "node-affinity"}]
    ha_rule_update(api, "pin-web", rule_type="resource-affinity", affinity="positive")
    assert api.seen["data"]["type"] == "resource-affinity"  # caller wins


# ---------------------------------------------------------------------------
# plan_migrate — disk-residency blast wiring
# Spec: docs/specs/2026-06-19-migrate-disk-residency-blast.md (internal-only)
# ---------------------------------------------------------------------------


class _MigrateApi:
    """Path-aware fake for plan_migrate disk-residency wiring: guest_status + guest config + storage.cfg."""

    def __init__(self, *, status, node="pveA", disk="local-lvm:vm-1-disk-0,size=8G", storages=None):
        self.config = SimpleNamespace(node=node)
        self._status = status
        self._disk = disk
        self._storages = storages if storages is not None else [{"storage": "local-lvm", "shared": 0}]

    def guest_status(self, vmid, kind="lxc", node=None):
        if self._status is None:
            err = RuntimeError("not found")
            err.response = SimpleNamespace(status_code=404)
            raise err
        return self._status

    def _get(self, path):
        if path.endswith("/config"):
            return {"scsi0": self._disk} if self._disk else {}
        if path == "/storage":
            return self._storages
        return {}


def test_plan_migrate_local_disk_escalates_and_names_it():
    """A LIVE (online qemu) migrate is MEDIUM by default, but a local disk makes it impossible → HIGH."""
    api = _MigrateApi(status={"status": "running", "name": "vm"},
                      disk="local-lvm:vm-1-disk-0,size=8G", storages=[{"storage": "local-lvm", "shared": 0}])
    p = plan_migrate(api, "100", "pveB", kind="qemu", online=True)
    assert p.risk == RISK_HIGH
    assert any(a["state"] == "local" and a["storage"] == "local-lvm" for a in p.affected)


def test_plan_migrate_shared_disk_keeps_base_risk():
    api = _MigrateApi(status={"status": "running", "name": "vm"},
                      disk="ceph:vm-1-disk-0,size=8G", storages=[{"storage": "ceph", "shared": 1}])
    p = plan_migrate(api, "100", "pveB", kind="qemu", online=True)
    assert p.risk == RISK_MEDIUM
    assert p.affected == []


def test_plan_migrate_not_found_does_not_run_engine():
    api = _MigrateApi(status=None)  # 404
    p = plan_migrate(api, "100", "pveB", kind="qemu", online=True)
    assert p.affected == []
    assert p.risk == RISK_HIGH


def test_ha_rule_create_rejects_newline_in_comment():
    # L9 (2026-07-10 audit): HA rule comments are stored in pmxcfs line-based config, same threat
    # class the access modules guard — reject control chars/newlines here too.
    api = _api()
    with pytest.raises(ProximoError):
        ha_rule_create(api, "pin-web", "node-affinity", "vm:100", nodes="pve1", comment="bad\ncomment")
