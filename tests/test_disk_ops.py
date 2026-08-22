"""DISK OPERATIONS tests — fully mocked, no live Proxmox.

Mirrors test_provisioning.py / test_backup.py style:
- Op functions: fake api objects that record calls (url/verb/params) for shape assertions.
- Plan functions: lightweight fake apis that supply _get (config read).
- Every test is self-contained — no shared mutable state.

WHAT THESE TESTS COVER:
  - URL/verb/param construction for disk_resize and disk_move.
  - Shrink detection: provable shrink → ProximoError at op layer; RISK_HIGH in plan.
  - Relative grow ('+NUnit') allowed at both layers; rated RISK_MEDIUM.
  - Absolute grow (new > current, current readable) allowed; rated RISK_MEDIUM.
  - delete_source=True → 'delete=1' in move body; plan rated RISK_HIGH.
  - delete_source=False → no 'delete' key; plan rated RISK_MEDIUM with undo note.
  - UNDO disclosure: every resize plan surfaces grow-is-not-undoable text.
  - UNDO disclosure: move plan with delete_source=False names source-retained as undo path.
  - Input validation: bad vmid, disk, size, storage, kind, node → ProximoError.

WHAT THESE TESTS CANNOT COVER (by design — documented, not hidden):
  - The server-layer "plan-before-mutate" weld: that is in server.py/_plan/_audited, both
    off-limits per the task constraint. plan-weld correctness lives in test_server_plan.py.
  - Live PVE endpoint contract: all URL/param shapes are mocked assumptions (see SHAPE-RISK
    section in disk_ops.py docstring) — only a live smoke confirms them.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from proximo.backends import ProximoError
from proximo.disk_ops import (
    disk_move,
    disk_resize,
    plan_disk_move,
    plan_disk_resize,
)
from proximo.planning import RISK_HIGH, RISK_MEDIUM

# ---------------------------------------------------------------------------
# Test fakes
# ---------------------------------------------------------------------------


def _resize_api(
    node: str = "pve",
    *,
    put_return=None,
    config_entry: str | None = None,
    config_raises: bool = False,
) -> SimpleNamespace:
    """Fake api object for disk_resize tests.

    Provides:
    - config.node
    - _get (returns guest config with the named disk entry, or raises)
    - _client.request (records PUT calls; returns a mock httpx response)
    - _auth_header (returns dummy header dict)
    """
    seen: dict = {}

    def fake_get(path):
        if config_raises:
            raise RuntimeError("config unavailable")
        # Return a config dict that includes the requested disk if config_entry is set.
        # The disk name is extracted from the path's last segment (not needed here — we just
        # return a fixed config; tests control which key is present via the disk param).
        return _build_config(config_entry)

    def _build_config(entry: str | None) -> dict:
        # The plan/op code looks up cfg.get(disk); we don't know the disk name here,
        # so each test controls config_entry and uses the disk param consistently.
        # We encode the disk name into the fake so callers pass it through _ResizeConfigApi.
        return {}  # base: no disk found unless overridden

    mock_response = MagicMock()
    mock_response.json.return_value = {"data": put_return or "UPID:pve:00010:0:0:0:qmresize:100:root@pam:"}
    mock_response.raise_for_status.return_value = None

    def fake_request(method, path, headers=None, data=None):
        seen["method"] = method
        seen["path"] = path
        seen["data"] = data
        return mock_response

    client = SimpleNamespace(request=fake_request)
    api = SimpleNamespace(
        config=SimpleNamespace(node=node),
        _client=client,
        _get=fake_get,
        _auth_header=lambda: {"Authorization": "PVEAPIToken=fake"},
        seen=seen,
    )
    return api


class _ResizeConfigApi:
    """Fake api for disk_resize and plan_disk_resize that returns a configurable config dict."""

    def __init__(
        self,
        node: str = "pve",
        *,
        disk_key: str = "scsi0",
        disk_value: str | None = None,
        config_raises: bool = False,
        put_return: str | None = None,
    ):
        self.config = SimpleNamespace(node=node)
        self._disk_key = disk_key
        self._disk_value = disk_value
        self._config_raises = config_raises
        self._seen: dict = {}
        self._put_return = put_return or "UPID:pve:00010:0:0:0:qmresize:100:root@pam:"
        self.seen = self._seen

        mock_response = MagicMock()
        mock_response.json.return_value = {"data": self._put_return}
        mock_response.raise_for_status.return_value = None

        def fake_request(method, path, headers=None, data=None):
            self._seen["method"] = method
            self._seen["path"] = path
            self._seen["data"] = data
            return mock_response

        self._client = SimpleNamespace(request=fake_request)

    def _auth_header(self):
        return {"Authorization": "PVEAPIToken=fake"}

    def _get(self, path):
        if self._config_raises:
            raise RuntimeError("config unavailable")
        if "/config" in path:
            if self._disk_value is not None:
                return {self._disk_key: self._disk_value}
            return {}  # disk not present
        return {}


def _move_api(node: str = "pve", *, disk_key: str = "scsi0", disk_value: str | None = None,
              config_raises: bool = False) -> SimpleNamespace:
    """Fake api for disk_move / plan_disk_move tests."""
    seen: dict = {}

    def fake_post(path, data=None):
        seen["method"] = "POST"
        seen["path"] = path
        seen["data"] = data
        return "UPID:pve:00020:0:0:0:move_disk:100:root@pam:"

    def fake_get(path):
        if config_raises:
            raise RuntimeError("config unavailable")
        if "/config" in path:
            if disk_value is not None:
                return {disk_key: disk_value}
            return {}
        return {}

    api = SimpleNamespace(
        config=SimpleNamespace(node=node),
        _post=fake_post,
        _get=fake_get,
        seen=seen,
    )
    return api


# ---------------------------------------------------------------------------
# disk_resize: relative grow ('+NUnit') — URL + param shapes
# ---------------------------------------------------------------------------

def test_disk_resize_relative_puts_to_correct_lxc_path():
    api = _ResizeConfigApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    disk_resize(api, "100", "scsi0", "+5G", kind="lxc")
    assert api.seen["method"] == "PUT"
    assert api.seen["path"] == "/nodes/pve/lxc/100/resize"


def test_disk_resize_relative_puts_to_correct_qemu_path():
    api = _ResizeConfigApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    disk_resize(api, "100", "scsi0", "+5G", kind="qemu")
    assert api.seen["path"] == "/nodes/pve/qemu/100/resize"


def test_disk_resize_sends_disk_and_size():
    api = _ResizeConfigApi(disk_key="virtio0", disk_value="local-lvm:vm-200-disk-0,size=20G")
    disk_resize(api, "200", "virtio0", "+10G", kind="qemu")
    d = api.seen["data"]
    assert d["disk"] == "virtio0"
    assert d["size"] == "+10G"


def test_disk_resize_uses_explicit_node():
    api = _ResizeConfigApi(node="pve2", disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    disk_resize(api, "100", "scsi0", "+5G", kind="qemu", node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_disk_resize_uses_config_node_when_none():
    api = _ResizeConfigApi(node="pve3", disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    disk_resize(api, "100", "scsi0", "+5G")
    assert "/nodes/pve3/" in api.seen["path"]


def test_disk_resize_returns_upid():
    api = _ResizeConfigApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    result = disk_resize(api, "100", "scsi0", "+5G")
    assert "UPID:" in result


# ---------------------------------------------------------------------------
# disk_resize: SHRINK BLOCKED at op layer
# ---------------------------------------------------------------------------

def test_disk_resize_blocks_absolute_shrink():
    # Current size 20G, trying to set to 10G → must raise.
    api = _ResizeConfigApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=20G")
    with pytest.raises(ProximoError, match="BLOCKED|shrink"):
        disk_resize(api, "100", "scsi0", "10G")


def test_disk_resize_blocks_equal_size_noop():
    # Equal size (no-op) also blocked (new <= current).
    api = _ResizeConfigApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=20G")
    with pytest.raises(ProximoError):
        disk_resize(api, "100", "scsi0", "20G")


def test_disk_resize_blocks_absolute_when_config_unreadable():
    # Cannot verify grow vs shrink when config read fails → op must refuse.
    api = _ResizeConfigApi(disk_key="scsi0", config_raises=True)
    with pytest.raises(ProximoError, match="cannot verify"):
        disk_resize(api, "100", "scsi0", "50G")


def test_disk_resize_allows_absolute_grow_when_verifiable():
    # Current 10G, new 20G → allowed.
    api = _ResizeConfigApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    result = disk_resize(api, "100", "scsi0", "20G")
    assert result  # does not raise; returns something


# ---------------------------------------------------------------------------
# disk_resize: validators reject bad input
# ---------------------------------------------------------------------------

def test_disk_resize_rejects_nonnumeric_vmid():
    api = _ResizeConfigApi()
    with pytest.raises(ProximoError):
        disk_resize(api, "abc", "scsi0", "+5G")


def test_disk_resize_rejects_bad_disk_identifier():
    api = _ResizeConfigApi()
    with pytest.raises(ProximoError):
        disk_resize(api, "100", "badisk0", "+5G")


def test_disk_resize_rejects_empty_disk():
    api = _ResizeConfigApi()
    with pytest.raises(ProximoError):
        disk_resize(api, "100", "", "+5G")


def test_disk_resize_rejects_bad_size_format():
    api = _ResizeConfigApi()
    with pytest.raises(ProximoError):
        disk_resize(api, "100", "scsi0", "not-a-size")


def test_disk_resize_rejects_empty_size():
    api = _ResizeConfigApi()
    with pytest.raises(ProximoError):
        disk_resize(api, "100", "scsi0", "")


def test_disk_resize_rejects_negative_relative():
    api = _ResizeConfigApi()
    with pytest.raises(ProximoError):
        disk_resize(api, "100", "scsi0", "-5G")


def test_disk_resize_rejects_unsupported_kind():
    api = _ResizeConfigApi()
    with pytest.raises(ProximoError):
        disk_resize(api, "100", "scsi0", "+5G", kind="docker")


def test_disk_resize_rejects_bad_node():
    api = _ResizeConfigApi()
    with pytest.raises(ProximoError):
        disk_resize(api, "100", "scsi0", "+5G", node="bad/node")


# ---------------------------------------------------------------------------
# disk_move: URL + param shapes
# ---------------------------------------------------------------------------

def test_disk_move_qemu_posts_to_correct_path():
    api = _move_api(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu")
    assert api.seen["path"] == "/nodes/pve/qemu/100/move_disk"
    assert api.seen["method"] == "POST"


def test_disk_move_lxc_posts_to_correct_path():
    api = _move_api(disk_key="rootfs", disk_value="local-lvm:vm-100-disk-0")
    disk_move(api, "100", "rootfs", "ceph-pool", kind="lxc")
    assert api.seen["path"] == "/nodes/pve/lxc/100/move_volume"


def test_disk_move_qemu_sends_disk_param():
    api = _move_api(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu")
    assert api.seen["data"]["disk"] == "scsi0"


def test_disk_move_lxc_sends_volume_param():
    api = _move_api(disk_key="rootfs", disk_value="local-lvm:vm-100-disk-0")
    disk_move(api, "100", "rootfs", "ceph-pool", kind="lxc")
    assert api.seen["data"]["volume"] == "rootfs"


def test_disk_move_sends_storage_param():
    api = _move_api(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu")
    assert api.seen["data"]["storage"] == "ceph-pool"


def test_disk_move_delete_source_false_no_delete_param():
    api = _move_api(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu", delete_source=False)
    assert "delete" not in api.seen["data"]


def test_disk_move_delete_source_true_sends_delete_1():
    api = _move_api(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu", delete_source=True)
    assert api.seen["data"]["delete"] == 1


def test_disk_move_uses_explicit_node():
    api = _move_api(node="pve2")
    disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu", node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_disk_move_uses_config_node_when_none():
    api = _move_api(node="pve5")
    disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu")
    assert "/nodes/pve5/" in api.seen["path"]


def test_disk_move_returns_upid():
    api = _move_api(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    result = disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu")
    assert result.startswith("UPID:")


# ---------------------------------------------------------------------------
# disk_move: validators reject bad input
# ---------------------------------------------------------------------------

def test_disk_move_rejects_nonnumeric_vmid():
    api = _move_api()
    with pytest.raises(ProximoError):
        disk_move(api, "abc", "scsi0", "ceph-pool")


def test_disk_move_rejects_bad_disk_identifier():
    api = _move_api()
    with pytest.raises(ProximoError):
        disk_move(api, "100", "notadisk", "ceph-pool")


def test_disk_move_rejects_empty_storage():
    api = _move_api()
    with pytest.raises(ProximoError):
        disk_move(api, "100", "scsi0", "")


def test_disk_move_rejects_bad_storage_chars():
    api = _move_api()
    with pytest.raises(ProximoError):
        disk_move(api, "100", "scsi0", "stor/../../etc")


def test_disk_move_rejects_unsupported_kind():
    api = _move_api()
    with pytest.raises(ProximoError):
        disk_move(api, "100", "scsi0", "ceph-pool", kind="kvm")


def test_disk_move_rejects_bad_node():
    api = _move_api()
    with pytest.raises(ProximoError):
        disk_move(api, "100", "scsi0", "ceph-pool", node="bad node!")


# ---------------------------------------------------------------------------
# plan_disk_resize: risk levels + blast content
# ---------------------------------------------------------------------------

class _PlanResizeApi:
    """Fake api for plan_disk_resize: configurable disk config entry."""

    def __init__(self, node="pve", *, disk_key="scsi0", disk_value=None, config_raises=False):
        self.config = SimpleNamespace(node=node)
        self._disk_key = disk_key
        self._disk_value = disk_value
        self._config_raises = config_raises

    def _get(self, path):
        if self._config_raises:
            raise RuntimeError("api down")
        if "/config" in path:
            if self._disk_value is not None:
                return {self._disk_key: self._disk_value}
            return {}
        return {}


def test_plan_resize_relative_grow_is_medium_risk():
    api = _PlanResizeApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    p = plan_disk_resize(api, "100", "scsi0", "+5G")
    assert p.risk == RISK_MEDIUM


def test_plan_resize_absolute_grow_is_medium_risk():
    api = _PlanResizeApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    p = plan_disk_resize(api, "100", "scsi0", "20G")
    assert p.risk == RISK_MEDIUM


def test_plan_resize_shrink_is_high_risk():
    api = _PlanResizeApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=20G")
    p = plan_disk_resize(api, "100", "scsi0", "10G")
    assert p.risk == RISK_HIGH


def test_plan_resize_shrink_blast_says_blocked():
    api = _PlanResizeApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=20G")
    p = plan_disk_resize(api, "100", "scsi0", "10G")
    text = " ".join(p.blast_radius).lower()
    assert "blocked" in text or "shrink" in text


def test_plan_resize_config_read_failure_is_high_risk():
    api = _PlanResizeApi(config_raises=True)
    p = plan_disk_resize(api, "100", "scsi0", "50G")
    assert p.risk == RISK_HIGH


def test_plan_resize_config_read_failure_discloses_uncertainty():
    api = _PlanResizeApi(config_raises=True)
    p = plan_disk_resize(api, "100", "scsi0", "50G")
    text = " ".join(p.blast_radius + p.risk_reasons).lower()
    assert "could not" in text or "unknown" in text or "cannot verify" in text


def test_plan_resize_relative_grow_discloses_not_undoable():
    api = _PlanResizeApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    p = plan_disk_resize(api, "100", "scsi0", "+5G")
    text = " ".join(p.blast_radius).lower()
    assert "not auto-undoable" in text or "cannot shrink" in text or "irreversible" in text


def test_plan_resize_absolute_grow_discloses_not_undoable():
    api = _PlanResizeApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    p = plan_disk_resize(api, "100", "scsi0", "20G")
    text = " ".join(p.blast_radius).lower()
    assert "not auto-undoable" in text or "cannot shrink" in text or "irreversible" in text


def test_plan_resize_action_string():
    api = _PlanResizeApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    p = plan_disk_resize(api, "100", "scsi0", "+5G")
    assert p.action == "pve_disk_resize"


def test_plan_resize_target_includes_disk():
    api = _PlanResizeApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    p = plan_disk_resize(api, "100", "scsi0", "+5G")
    assert "scsi0" in p.target


def test_plan_resize_current_includes_size_when_readable():
    api = _PlanResizeApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    p = plan_disk_resize(api, "100", "scsi0", "+5G")
    assert p.current.get("current_size") == "10G"


def test_plan_resize_rejects_nonnumeric_vmid():
    api = _PlanResizeApi()
    with pytest.raises(ProximoError):
        plan_disk_resize(api, "abc", "scsi0", "+5G")


def test_plan_resize_rejects_bad_disk():
    api = _PlanResizeApi()
    with pytest.raises(ProximoError):
        plan_disk_resize(api, "100", "invalid!disk", "+5G")


def test_plan_resize_rejects_bad_size():
    api = _PlanResizeApi()
    with pytest.raises(ProximoError):
        plan_disk_resize(api, "100", "scsi0", "abc")


# ---------------------------------------------------------------------------
# plan_disk_move: risk levels + blast content
# ---------------------------------------------------------------------------

class _PlanMoveApi:
    """Fake api for plan_disk_move: configurable config response."""

    def __init__(self, node="pve", *, disk_key="scsi0", disk_value=None, config_raises=False):
        self.config = SimpleNamespace(node=node)
        self._disk_key = disk_key
        self._disk_value = disk_value
        self._config_raises = config_raises

    def _get(self, path):
        if self._config_raises:
            raise RuntimeError("api down")
        # Model the target-blast reads so a NORMAL move sees a readable, fitting target with no
        # co-tenants (the scenario these source-side tests intend). Capacity-unknown→HIGH and
        # co-tenant naming are covered by test_blast_disk_move.py + the wiring tests below.
        if path == "/cluster/resources":
            return []
        if path.endswith("/status") and "/storage/" in path:
            return {"avail": 500 * (1024 ** 3), "total": 1024 * (1024 ** 3), "enabled": 1}
        if "/config" in path:
            if self._disk_value is not None:
                return {self._disk_key: self._disk_value}
            return {}
        return {}


def test_plan_move_delete_source_false_is_medium_risk():
    # sized disk + a fitting target (modeled by _PlanMoveApi) → the move fits → base MEDIUM preserved
    api = _PlanMoveApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0,size=10G")
    p = plan_disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu", delete_source=False)
    assert p.risk == RISK_MEDIUM


def test_plan_move_delete_source_true_is_high_risk():
    api = _PlanMoveApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    p = plan_disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu", delete_source=True)
    assert p.risk == RISK_HIGH


def test_plan_move_delete_source_true_blast_says_no_undo():
    api = _PlanMoveApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    p = plan_disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu", delete_source=True)
    text = " ".join(p.blast_radius).lower()
    assert "deletes" in text or "no easy undo" in text or "source" in text


def test_plan_move_delete_source_false_blast_says_source_retained():
    api = _PlanMoveApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    p = plan_disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu", delete_source=False)
    text = " ".join(p.blast_radius).lower()
    assert "retained" in text or "source" in text


def test_plan_move_delete_source_false_mentions_undo_path():
    api = _PlanMoveApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    p = plan_disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu", delete_source=False)
    text = " ".join(p.blast_radius).lower()
    assert "undo" in text or "natural" in text or "retained" in text


def test_plan_move_surfaces_source_storage_from_config():
    api = _PlanMoveApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    p = plan_disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu")
    assert p.current.get("source_storage") == "local-lvm"


def test_plan_move_config_failure_disclosed_in_blast():
    api = _PlanMoveApi(config_raises=True)
    p = plan_disk_move(api, "100", "scsi0", "ceph-pool", kind="qemu")
    text = " ".join(p.blast_radius).lower()
    assert "config read failed" in text or "unknown" in text


def test_plan_move_action_string():
    api = _PlanMoveApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    p = plan_disk_move(api, "100", "scsi0", "ceph-pool")
    assert p.action == "pve_disk_move"


def test_plan_move_target_includes_disk():
    api = _PlanMoveApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    p = plan_disk_move(api, "100", "scsi0", "ceph-pool")
    assert "scsi0" in p.target


def test_plan_move_change_includes_target_storage():
    api = _PlanMoveApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    p = plan_disk_move(api, "100", "scsi0", "ceph-pool")
    assert "ceph-pool" in p.change


def test_plan_move_delete_source_true_change_says_delete():
    api = _PlanMoveApi(disk_key="scsi0", disk_value="local-lvm:vm-100-disk-0")
    p = plan_disk_move(api, "100", "scsi0", "ceph-pool", delete_source=True)
    assert "delete" in p.change.lower()


def test_plan_move_rejects_nonnumeric_vmid():
    api = _PlanMoveApi()
    with pytest.raises(ProximoError):
        plan_disk_move(api, "abc", "scsi0", "ceph-pool")


def test_plan_move_rejects_bad_disk():
    api = _PlanMoveApi()
    with pytest.raises(ProximoError):
        plan_disk_move(api, "100", "bad!disk", "ceph-pool")


def test_plan_move_rejects_bad_storage():
    api = _PlanMoveApi()
    with pytest.raises(ProximoError):
        plan_disk_move(api, "100", "scsi0", "stor/bad")


def test_plan_move_rejects_bad_kind():
    api = _PlanMoveApi()
    with pytest.raises(ProximoError):
        plan_disk_move(api, "100", "scsi0", "ceph-pool", kind="notreal")


# ---------------------------------------------------------------------------
# Disk identifier validator coverage — all valid forms
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("disk", [
    "rootfs", "scsi0", "scsi15", "virtio0", "virtio3",
    "sata0", "sata5", "ide0", "ide3", "mp0", "mp7",
    "efidisk0", "tpmstate0", "unused0", "unused12",
])
def test_valid_disk_identifiers_pass(disk):
    api = _PlanMoveApi(disk_key=disk, disk_value="local-lvm:vol-0,size=10G")
    # Should not raise on valid disk identifiers.
    p = plan_disk_move(api, "100", disk, "ceph-pool")
    assert "pve_disk_move" in p.action


@pytest.mark.parametrize("disk", [
    "", "scsi", "virtio", "disk0", "hda", "vda", "sdb", "bad disk", "scsi0; rm -rf /",
])
def test_invalid_disk_identifiers_rejected(disk):
    api = _PlanMoveApi()
    with pytest.raises(ProximoError):
        plan_disk_move(api, "100", disk, "ceph-pool")


# ---------------------------------------------------------------------------
# Size validator coverage
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("size", [
    "+1G", "+10G", "+512M", "+1T", "+100K",
    "10G", "512M", "1T", "1024",
    "+1g", "+10m",  # lowercase units
])
def test_valid_sizes_pass(size):
    from proximo.disk_ops import _check_size
    assert _check_size(size) == size.strip()


@pytest.mark.parametrize("size", [
    "", "-5G", "abc", "+abc", "G", "+G", "10X", "--5G",
])
def test_invalid_sizes_rejected(size):
    from proximo.disk_ops import _check_size
    with pytest.raises(ProximoError):
        _check_size(size)


# ---------------------------------------------------------------------------
# plan_disk_move — TARGET blast-radius wiring (capacity + co-tenants)
# Spec: docs/specs/2026-06-19-disk-move-blast-radius.md (internal-only)
# ---------------------------------------------------------------------------

_GiB = 1024 ** 3


def _move_blast_api(node="pve", *, source_disk="fast:vm-100-disk-0,size=50G",
                    target="slow", target_avail=10 * _GiB, target_total=500 * _GiB,
                    rows=None, configs=None, resources_raises=False):
    """Path-aware fake for plan_disk_move blast wiring: serves the moved guest's config,
    target storage status, cluster resources, and each co-tenant's config."""
    rows = rows if rows is not None else [
        {"vmid": "100", "type": "qemu", "node": node, "name": "self", "status": "running"},
        {"vmid": "200", "type": "qemu", "node": node, "name": "db", "status": "running"},
    ]
    configs = configs if configs is not None else {
        "100": {"scsi0": source_disk, "bootdisk": "scsi0"},
        "200": {"scsi0": f"{target}:vm-200-disk-0,size=8G", "bootdisk": "scsi0"},
    }

    def fake_get(path):
        if path == "/cluster/resources":
            if resources_raises:
                raise RuntimeError("cluster unreachable")
            return rows
        if path.endswith("/status") and f"/storage/{target}/" in path:
            return {"avail": target_avail, "total": target_total, "enabled": 1}
        if path.endswith("/config"):
            vmid = path.strip("/").split("/")[3]   # /nodes/<node>/<kind>/<vmid>/config
            return configs.get(vmid, {})
        raise AssertionError(f"unexpected GET {path}")

    return SimpleNamespace(config=SimpleNamespace(node=node), _get=fake_get)


def test_plan_disk_move_wont_fit_escalates_and_names_cotenant():
    """A retain-move (base MEDIUM) onto a target it won't fit → escalated to HIGH + co-tenant named."""
    api = _move_blast_api(target_avail=10 * _GiB)  # 50G disk, 10G free → won't fit
    plan = plan_disk_move(api, "100", "scsi0", "slow", kind="qemu", delete_source=False)
    assert plan.risk == RISK_HIGH                       # escalated from MEDIUM by the won't-fit verdict
    assert any(e["vmid"] == "200" for e in plan.affected)
    assert all(e["vmid"] != "100" for e in plan.affected)  # never the guest being moved
    assert plan.complete is True


def test_plan_disk_move_fits_keeps_base_risk_no_crywolf():
    """Ample headroom → no escalation, no co-tenants flagged."""
    api = _move_blast_api(target_avail=400 * _GiB)  # 50G disk, 400G free → fits
    plan = plan_disk_move(api, "100", "scsi0", "slow", kind="qemu", delete_source=False)
    assert plan.risk == RISK_MEDIUM                     # base risk preserved
    assert plan.affected == []
    assert plan.complete is True


def test_plan_disk_move_incomplete_enum_is_high_and_marked():
    """Cluster enumeration fails → complete=False + escalated HIGH (uncertainty is not safe)."""
    api = _move_blast_api(target_avail=400 * _GiB, resources_raises=True)
    plan = plan_disk_move(api, "100", "scsi0", "slow", kind="qemu", delete_source=False)
    assert plan.complete is False
    assert plan.risk == RISK_HIGH


# ---------------------------------------------------------------------------
# _parse_size_bytes — defensive hardening (fail-closed: never a wrong small int)
# Redteam (2026-06-19): negative → negative bytes (theoretical under-flag); whitespace → IndexError.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["-5G", "0", "0G", "0M", "   ", ""])
def test_parse_size_bytes_nonpositive_or_blank_is_none(bad):
    from proximo.disk_ops import _parse_size_bytes
    assert _parse_size_bytes(bad) is None


@pytest.mark.parametrize("good,expected", [
    ("10G", 10 * 1024 ** 3),
    ("512M", 512 * 1024 ** 2),
    ("1T", 1024 ** 4),
    ("1024", 1024),
    ("1g", 1024 ** 3),   # lowercase unit
])
def test_parse_size_bytes_valid(good, expected):
    from proximo.disk_ops import _parse_size_bytes
    assert _parse_size_bytes(good) == expected
