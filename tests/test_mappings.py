"""Tests for hw_mappings.py — PVE hardware list + PCI/USB cluster mapping CRUD.

Coverage:
  - Validator: trailing-newline bypass rejected (\\Z anchor), slash rejected, bad hw_type rejected
  - Operations: correct HTTP verb, path, and body shape (id in body for creates)
  - Plan factories: risk level, blast_radius, note content
"""

from __future__ import annotations

import pytest

from proximo.backends import ProximoError
from proximo.hw_mappings import (
    _check_hw_type,
    _check_mapping_id,
    _check_node,
    hardware_list,
    mapping_pci_create,
    mapping_pci_delete,
    mapping_pci_get,
    mapping_pci_update,
    mapping_usb_create,
    mapping_usb_delete,
    mapping_usb_get,
    mapping_usb_update,
    plan_mapping_pci_create,
    plan_mapping_pci_delete,
    plan_mapping_pci_update,
    plan_mapping_usb_create,
    plan_mapping_usb_delete,
    plan_mapping_usb_update,
)
from proximo.planning import RISK_MEDIUM

# ---------------------------------------------------------------------------
# Recording fake API
# ---------------------------------------------------------------------------

class _Api:
    """Recording fake: captures all calls for assertion."""

    def __init__(self, get_returns: dict | None = None):
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict]] = []
        self.puts: list[tuple[str, dict]] = []
        self.dels: list[str] = []
        self._get_returns: dict = get_returns or {}

    def _get(self, path: str):
        self.gets.append(path)
        return self._get_returns.get(path)

    def _post(self, path: str, data: dict | None = None):
        self.posts.append((path, data or {}))

    def _put(self, path: str, data: dict | None = None):
        self.puts.append((path, data or {}))

    def _delete(self, path: str):
        self.dels.append(path)


# ---------------------------------------------------------------------------
# Validator tests
# ---------------------------------------------------------------------------

class TestCheckMappingId:
    def test_valid_simple(self):
        assert _check_mapping_id("gpu-passthrough") == "gpu-passthrough"

    def test_valid_alphanumeric(self):
        assert _check_mapping_id("USB1") == "USB1"

    def test_valid_with_underscore(self):
        assert _check_mapping_id("my_gpu_0") == "my_gpu_0"

    def test_rejects_trailing_newline(self):
        # \\Z anchor — newline after valid name must be rejected
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            _check_mapping_id("gpu-pass\n")

    def test_rejects_slash(self):
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            _check_mapping_id("gpu/slot")

    def test_rejects_empty(self):
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            _check_mapping_id("")

    def test_rejects_leading_hyphen(self):
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            _check_mapping_id("-bad")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            _check_mapping_id("a" * 65)


class TestCheckNode:
    def test_valid(self):
        assert _check_node("pve-node1") == "pve-node1"

    def test_valid_with_dot(self):
        assert _check_node("node.local") == "node.local"

    def test_rejects_trailing_newline(self):
        with pytest.raises(ProximoError, match="invalid node name"):
            _check_node("pve\n")

    def test_rejects_slash(self):
        with pytest.raises(ProximoError, match="invalid node name"):
            _check_node("pve/node")


class TestCheckHwType:
    def test_valid_pci(self):
        assert _check_hw_type("pci") == "pci"

    def test_valid_usb(self):
        assert _check_hw_type("usb") == "usb"

    def test_rejects_invalid(self):
        with pytest.raises(ProximoError, match="invalid hardware type"):
            _check_hw_type("disk")

    def test_rejects_trailing_newline(self):
        with pytest.raises(ProximoError, match="invalid hardware type"):
            _check_hw_type("pci\n")


# ---------------------------------------------------------------------------
# hardware_list (read operation)
# ---------------------------------------------------------------------------

class TestHardwareList:
    def test_pci_calls_correct_path(self):
        api = _Api(get_returns={"/nodes/pve1/hardware/pci": [{"id": "0000:01:00.0"}]})
        result = hardware_list(api, "pve1", "pci")
        assert api.gets == ["/nodes/pve1/hardware/pci"]
        assert result == {"devices": [{"id": "0000:01:00.0"}]}

    def test_usb_calls_correct_path(self):
        api = _Api(get_returns={"/nodes/pve1/hardware/usb": [{"busnum": 1}]})
        result = hardware_list(api, "pve1", "usb")
        assert api.gets == ["/nodes/pve1/hardware/usb"]
        assert result == {"devices": [{"busnum": 1}]}

    def test_defaults_to_pci(self):
        api = _Api(get_returns={"/nodes/pve1/hardware/pci": []})
        hardware_list(api, "pve1")
        assert api.gets == ["/nodes/pve1/hardware/pci"]

    def test_returns_empty_list_on_none(self):
        api = _Api()
        result = hardware_list(api, "pve1", "pci")
        assert result == {"devices": []}

    def test_rejects_invalid_node(self):
        api = _Api()
        with pytest.raises(ProximoError, match="invalid node name"):
            hardware_list(api, "bad/node", "pci")

    def test_rejects_invalid_hw_type(self):
        api = _Api()
        with pytest.raises(ProximoError, match="invalid hardware type"):
            hardware_list(api, "pve1", "sata")


# ---------------------------------------------------------------------------
# PCI mapping operations
# ---------------------------------------------------------------------------

class TestMappingPciGet:
    def test_calls_correct_path(self):
        api = _Api(get_returns={"/cluster/mapping/pci/my-gpu": {"id": "my-gpu", "map": []}})
        result = mapping_pci_get(api, "my-gpu")
        assert api.gets == ["/cluster/mapping/pci/my-gpu"]
        assert result["id"] == "my-gpu"

    def test_returns_empty_dict_on_none(self):
        api = _Api()
        assert mapping_pci_get(api, "missing") == {}

    def test_rejects_invalid_id(self):
        api = _Api()
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            mapping_pci_get(api, "bad/id")


class TestMappingPciCreate:
    def test_posts_to_collection_with_id_in_body(self):
        """CREATE URL shape: POST /cluster/mapping/pci with id in body (Wave 1 lesson #2)."""
        api = _Api()
        mapping_pci_create(api, "my-gpu", description="primary GPU")
        assert api.posts == [("/cluster/mapping/pci", {"id": "my-gpu", "description": "primary GPU"})]

    def test_strips_none_kwargs(self):
        api = _Api()
        mapping_pci_create(api, "gpu1", description=None)
        path, body = api.posts[0]
        assert "description" not in body
        assert body["id"] == "gpu1"

    def test_rejects_invalid_id(self):
        api = _Api()
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            mapping_pci_create(api, "bad\nid")

    def test_no_get_calls(self):
        api = _Api()
        mapping_pci_create(api, "gpu1")
        assert api.gets == []


class TestMappingPciUpdate:
    def test_puts_to_item_path(self):
        api = _Api()
        mapping_pci_update(api, "my-gpu", description="updated")
        assert api.puts == [("/cluster/mapping/pci/my-gpu", {"description": "updated"})]

    def test_strips_none_kwargs(self):
        api = _Api()
        mapping_pci_update(api, "gpu1", description=None, map="0000:01:00.0")
        path, body = api.puts[0]
        assert "description" not in body
        assert body["map"] == "0000:01:00.0"

    def test_rejects_invalid_id(self):
        api = _Api()
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            mapping_pci_update(api, "bad/id")


class TestMappingPciDelete:
    def test_deletes_item_path(self):
        api = _Api()
        mapping_pci_delete(api, "my-gpu")
        assert api.dels == ["/cluster/mapping/pci/my-gpu"]

    def test_no_other_side_effects(self):
        api = _Api()
        mapping_pci_delete(api, "my-gpu")
        assert api.gets == [] and api.posts == [] and api.puts == []

    def test_rejects_invalid_id(self):
        api = _Api()
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            mapping_pci_delete(api, "bad\nid")


# ---------------------------------------------------------------------------
# USB mapping operations
# ---------------------------------------------------------------------------

class TestMappingUsbGet:
    def test_calls_correct_path(self):
        api = _Api(get_returns={"/cluster/mapping/usb/my-usb": {"id": "my-usb"}})
        result = mapping_usb_get(api, "my-usb")
        assert api.gets == ["/cluster/mapping/usb/my-usb"]
        assert result["id"] == "my-usb"

    def test_returns_empty_dict_on_none(self):
        api = _Api()
        assert mapping_usb_get(api, "missing") == {}

    def test_rejects_invalid_id(self):
        api = _Api()
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            mapping_usb_get(api, "bad/id")


class TestMappingUsbCreate:
    def test_posts_to_collection_with_id_in_body(self):
        """CREATE URL shape: POST /cluster/mapping/usb with id in body."""
        api = _Api()
        mapping_usb_create(api, "my-usb", description="usb dongle")
        assert api.posts == [("/cluster/mapping/usb", {"id": "my-usb", "description": "usb dongle"})]

    def test_strips_none_kwargs(self):
        api = _Api()
        mapping_usb_create(api, "usb1", description=None)
        path, body = api.posts[0]
        assert "description" not in body

    def test_rejects_invalid_id(self):
        api = _Api()
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            mapping_usb_create(api, "bad\nid")


class TestMappingUsbUpdate:
    def test_puts_to_item_path(self):
        api = _Api()
        mapping_usb_update(api, "my-usb", description="updated")
        assert api.puts == [("/cluster/mapping/usb/my-usb", {"description": "updated"})]

    def test_strips_none_kwargs(self):
        api = _Api()
        mapping_usb_update(api, "usb1", description=None, map="0x1234:0x5678")
        path, body = api.puts[0]
        assert "description" not in body

    def test_rejects_invalid_id(self):
        api = _Api()
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            mapping_usb_update(api, "bad/id")


class TestMappingUsbDelete:
    def test_deletes_item_path(self):
        api = _Api()
        mapping_usb_delete(api, "my-usb")
        assert api.dels == ["/cluster/mapping/usb/my-usb"]

    def test_no_other_side_effects(self):
        api = _Api()
        mapping_usb_delete(api, "my-usb")
        assert api.gets == [] and api.posts == [] and api.puts == []

    def test_rejects_invalid_id(self):
        api = _Api()
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            mapping_usb_delete(api, "bad\nid")


# ---------------------------------------------------------------------------
# Plan factory tests — PCI
# ---------------------------------------------------------------------------

class TestPlanMappingPciCreate:
    def test_risk_is_medium(self):
        plan = plan_mapping_pci_create("gpu1")
        assert plan.risk == RISK_MEDIUM

    def test_target_shape(self):
        plan = plan_mapping_pci_create("gpu1")
        assert plan.target == "cluster/mapping/pci/gpu1"

    def test_action_name(self):
        plan = plan_mapping_pci_create("gpu1")
        assert plan.action == "pve_mapping_pci_create"

    def test_current_is_empty(self):
        plan = plan_mapping_pci_create("gpu1")
        assert plan.current == {}

    def test_note_mentions_smoke_confirm(self):
        plan = plan_mapping_pci_create("gpu1")
        assert "Smoke-confirm" in plan.note

    def test_note_does_not_imply_undo(self):
        plan = plan_mapping_pci_create("gpu1")
        # Must mention delete to restore, not "restore" as if it is automatic
        assert "pve_mapping_pci_delete" in plan.note

    def test_rejects_invalid_id(self):
        with pytest.raises(ProximoError, match="invalid mapping ID"):
            plan_mapping_pci_create("bad/id")

    def test_no_api_calls(self):
        # create plan does not need api — it's purely additive
        plan = plan_mapping_pci_create("gpu1", description="test")
        assert plan.complete is True


class TestPlanMappingPciUpdate:
    def test_risk_is_medium(self):
        api = _Api(get_returns={"/cluster/mapping/pci/gpu1": {"id": "gpu1"}})
        plan = plan_mapping_pci_update(api, "gpu1", description="new")
        assert plan.risk == RISK_MEDIUM

    def test_reads_current_config(self):
        api = _Api(get_returns={"/cluster/mapping/pci/gpu1": {"id": "gpu1", "map": []}})
        plan = plan_mapping_pci_update(api, "gpu1", description="new")
        assert api.gets == ["/cluster/mapping/pci/gpu1"]
        assert plan.current == {"id": "gpu1", "map": []}

    def test_blast_radius_mentions_vms(self):
        api = _Api(get_returns={"/cluster/mapping/pci/gpu1": {}})
        plan = plan_mapping_pci_update(api, "gpu1")
        assert any("VM" in r or "vm" in r.lower() for r in plan.blast_radius)

    def test_note_does_not_imply_undo(self):
        api = _Api(get_returns={"/cluster/mapping/pci/gpu1": {}})
        plan = plan_mapping_pci_update(api, "gpu1")
        assert "No snapshot" in plan.note


class TestPlanMappingPciDelete:
    def test_risk_is_medium(self):
        api = _Api(get_returns={"/cluster/mapping/pci/gpu1": {"id": "gpu1"}})
        plan = plan_mapping_pci_delete(api, "gpu1")
        assert plan.risk == RISK_MEDIUM

    def test_reads_current_config_for_evidence(self):
        api = _Api(get_returns={"/cluster/mapping/pci/gpu1": {"id": "gpu1", "map": []}})
        plan = plan_mapping_pci_delete(api, "gpu1")
        assert api.gets == ["/cluster/mapping/pci/gpu1"]
        assert plan.current == {"id": "gpu1", "map": []}

    def test_note_says_no_undo_primitive(self):
        api = _Api(get_returns={"/cluster/mapping/pci/gpu1": {}})
        plan = plan_mapping_pci_delete(api, "gpu1")
        assert "No UNDO primitive" in plan.note

    def test_note_says_recreatable(self):
        api = _Api(get_returns={"/cluster/mapping/pci/gpu1": {}})
        plan = plan_mapping_pci_delete(api, "gpu1")
        assert "pve_mapping_pci_create" in plan.note

    def test_blast_radius_mentions_vms(self):
        api = _Api(get_returns={"/cluster/mapping/pci/gpu1": {}})
        plan = plan_mapping_pci_delete(api, "gpu1")
        assert any("VM" in r or "vm" in r.lower() for r in plan.blast_radius)


# ---------------------------------------------------------------------------
# Plan factory tests — USB
# ---------------------------------------------------------------------------

class TestPlanMappingUsbCreate:
    def test_risk_is_medium(self):
        plan = plan_mapping_usb_create("usb1")
        assert plan.risk == RISK_MEDIUM

    def test_target_shape(self):
        plan = plan_mapping_usb_create("usb1")
        assert plan.target == "cluster/mapping/usb/usb1"

    def test_action_name(self):
        plan = plan_mapping_usb_create("usb1")
        assert plan.action == "pve_mapping_usb_create"

    def test_current_is_empty(self):
        plan = plan_mapping_usb_create("usb1")
        assert plan.current == {}


class TestPlanMappingUsbUpdate:
    def test_risk_is_medium(self):
        api = _Api(get_returns={"/cluster/mapping/usb/usb1": {"id": "usb1"}})
        plan = plan_mapping_usb_update(api, "usb1", description="new")
        assert plan.risk == RISK_MEDIUM

    def test_reads_current_config(self):
        api = _Api(get_returns={"/cluster/mapping/usb/usb1": {"id": "usb1"}})
        plan = plan_mapping_usb_update(api, "usb1", description="new")
        assert api.gets == ["/cluster/mapping/usb/usb1"]
        assert plan.current == {"id": "usb1"}


class TestPlanMappingUsbDelete:
    def test_risk_is_medium(self):
        api = _Api(get_returns={"/cluster/mapping/usb/usb1": {"id": "usb1"}})
        plan = plan_mapping_usb_delete(api, "usb1")
        assert plan.risk == RISK_MEDIUM

    def test_reads_current_config_for_evidence(self):
        api = _Api(get_returns={"/cluster/mapping/usb/usb1": {"id": "usb1"}})
        plan_mapping_usb_delete(api, "usb1")
        assert api.gets == ["/cluster/mapping/usb/usb1"]

    def test_note_says_no_undo_primitive(self):
        api = _Api(get_returns={"/cluster/mapping/usb/usb1": {}})
        plan = plan_mapping_usb_delete(api, "usb1")
        assert "No UNDO primitive" in plan.note

    def test_note_says_recreatable(self):
        api = _Api(get_returns={"/cluster/mapping/usb/usb1": {}})
        plan = plan_mapping_usb_delete(api, "usb1")
        assert "pve_mapping_usb_create" in plan.note


class TestMappingListReads:
    def test_pci_list_gets_collection(self):
        from proximo.hw_mappings import mapping_pci_list

        class _Api:
            def __init__(self): self.got = []
            def _get(self, p):
                self.got.append(p)
                return [{"id": "m1"}]
        api = _Api()
        assert mapping_pci_list(api) == [{"id": "m1"}]
        assert api.got == ["/cluster/mapping/pci"]

    def test_usb_list_gets_collection(self):
        from proximo.hw_mappings import mapping_usb_list

        class _Api:
            def __init__(self): self.got = []
            def _get(self, p):
                self.got.append(p)
                return []
        api = _Api()
        assert mapping_usb_list(api) == []
        assert api.got == ["/cluster/mapping/usb"]


# ---------------------------------------------------------------------------
# Free-text body hygiene (description/map) — reject control chars/newlines,
# for parity with the firewall/access _check_freetext guard.
# ---------------------------------------------------------------------------

class TestMappingFreetext:
    def test_pci_create_rejects_newline_in_description(self):
        api = _Api()
        with pytest.raises(ProximoError):
            mapping_pci_create(api, "gpu0", description="line1\nline2")
        assert api.posts == []  # refused before any write

    def test_pci_update_rejects_control_char_in_description(self):
        api = _Api()
        with pytest.raises(ProximoError):
            mapping_pci_update(api, "gpu0", description="bad\x00desc")
        assert api.puts == []

    def test_usb_create_rejects_newline_in_map(self):
        api = _Api()
        with pytest.raises(ProximoError):
            mapping_usb_create(api, "yubi0", map="host=1050:0407\ninjected")
        assert api.posts == []

    def test_clean_description_is_accepted(self):
        api = _Api()
        mapping_pci_create(api, "gpu0", description="RTX 4090 passthrough")
        assert len(api.posts) == 1

    def test_rejects_newline_in_list_valued_map_element(self):
        # PVE `map` is often a repeated per-node LIST; a newline in an element must still be caught.
        api = _Api()
        with pytest.raises(ProximoError):
            mapping_pci_create(api, "gpu0", map=["node=pve1,path=0000:01:00.0", "node=pve2\ninjected"])
        assert api.posts == []
