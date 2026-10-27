# ruff: noqa: F811, I001  (the `plane` fixture is imported from the net tests, then used as an argument)
"""Lens 3 against ad7f0ec: probes of the rollback net and its consent binding, the findings fixed and
pinned, the held behaviours kept."""
from __future__ import annotations

import os

import pytest
from test_core_pdm_rollback_net import (  # noqa: F401
    GUESTS, STORAGES, Api, _paths, _plan, _posts, _rollback, _rows, _wire, plane,
)

from proximo.core import engine, risk, safetynet, spine, undo
from proximo.core.errors import ProximoError

PVE_QEMU = GUESTS[0][4]
PVE_LXC = GUESTS[1][4]
PDM_QEMU = GUESTS[2][4]


@pytest.fixture
def grants(monkeypatch, tmp_path):
    g = tmp_path / "grants"
    g.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(g))
    return g


def _grant(g, cid):
    p = g / os.path.basename(spine.grant_path(cid))
    p.touch()
    return p


# --- held ---------------------------------------------------------------------------------------

def test_held_disarmed_plan_names_no_id_for_a_rollback(plane, monkeypatch, grants):
    _wire(monkeypatch)
    monkeypatch.setattr(engine.arm, "arm_state", lambda cfg=None: engine.arm.ArmGateState(False, False, "disarmed"))
    planned = _plan(plane, "pve", "qemu", PVE_QEMU)
    assert planned["needs"] == "arm" and "consent_id" not in planned


def test_held_forbid_cannot_name_the_snapshot_without_the_rollback(plane, monkeypatch, grants):
    monkeypatch.setenv("PROXIMO_FORBID", "qemu/100/snapshot")
    api = _wire(monkeypatch)
    with pytest.raises(ProximoError, match="forbid"):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert _posts(api) == []


def test_held_cloudinit_and_cdrom_never_count(plane, monkeypatch):
    _wire(monkeypatch, config={"scsi0": "local-lvm:vm-100-disk-0",
                               "ide2": "local:100/vm-100-cloudinit.qcow2,media=cdrom",
                               "ide0": "local:iso/x.iso,media=cdrom", "sata0": "none,media=cdrom"})
    net = _plan(plane, "pve", "qemu", PVE_QEMU)["safety_net"]
    assert net["taken"] is True and not net.get("unsettled")


def test_held_qcow2_on_dir_without_chain_takes_the_net(plane, monkeypatch):
    _wire(monkeypatch, config={"scsi0": "local:100/vm-100-disk-0.qcow2", "efidisk0": "local:100/vm-100-disk-1.qcow2"})
    net = _plan(plane, "pve", "qemu", PVE_QEMU)["safety_net"]
    assert net["taken"] is True and not net.get("unsettled")


def test_held_tpmstate_raw_on_dir_is_cannot(plane, monkeypatch):
    _wire(monkeypatch, config={"scsi0": "local:100/vm-100-disk-0.qcow2", "tpmstate0": "local:100/vm-100-disk-2.raw"})
    net = _plan(plane, "pve", "qemu", PVE_QEMU)["safety_net"]
    assert net["taken"] is False and safetynet.IMPOSSIBLE_SENTENCE in net["why"]


def test_held_no_argument_turns_the_net_off(plane, monkeypatch):
    _wire(monkeypatch)
    for extra in ({"undo": "off"}, {"PROXIMO_UNDO": "off"}, {"net": "off"}, {"snapshot": False}):
        planned = _plan(plane, "pve", "qemu", PVE_QEMU, **extra)
        assert planned.get("safety_net", {}).get("taken") is not False, extra


def test_held_plan_and_execute_agree_on_the_word_when_the_estate_is_stable(plane, monkeypatch, grants):
    for config in ({"scsi0": "tank:vm-100-disk-0"}, {"scsi0": "local:100/vm-100-disk-0.raw"},
                   {"scsi0": "weird:vm-100-disk-0"}):
        api = _wire(monkeypatch, config=config, storages=None if "weird" not in config["scsi0"] else
                    [{"storage": "weird", "type": "iscsi"}])
        planned = _plan(plane, "pve", "qemu", PVE_QEMU)
        _grant(grants, planned["consent_id"])
        out = _rollback(plane, "pve", "qemu", PVE_QEMU)
        assert out["undo"]["captured"] is planned["safety_net"]["taken"], config
        assert any(p.endswith("/rollback") for p in _posts(api))


def test_held_pdm_with_and_without_node_give_different_ids(plane, monkeypatch, grants):
    _wire(monkeypatch, config={"scsi0": "tank:vm-100-disk-0"}, storages=[{"storage": "tank", "type": "zfspool"}])
    a = _plan(plane, "pdm", "qemu", PDM_QEMU, node="pve1")
    b = _plan(plane, "pdm", "qemu", PDM_QEMU)
    assert a["safety_net"]["taken"] is False and b["safety_net"]["taken"] is True
    assert a["consent_id"] != b["consent_id"]


def test_held_a_snapshot_volume_with_no_storage_is_named_unsettled(plane, monkeypatch):
    _wire(monkeypatch, config={"scsi0": "local-lvm:vm-100-disk-0"},
          snapcfg={"scsi0": "local-lvm:vm-100-disk-0", "scsi1": "/dev/sdb"})
    net = _plan(plane, "pve", "qemu", PVE_QEMU)["safety_net"]
    assert "a volume of the snapshot that names no storage" in net.get("unsettled", [])


def test_held_pdm_current_config_read_asks_the_active_state(plane, monkeypatch):
    api = _wire(monkeypatch)
    _plan(plane, "pdm", "qemu", PDM_QEMU, node="pve1")
    cur = [a for m, p, a in api.calls if m == "GET" and p.endswith("/config") and not a.get("snapshot")]
    assert cur and all(a.get("state") == "active" and "current" not in a for a in cur)


# --- the taint couplings that remain, now that the net's reads taint nothing -------------------------

@pytest.mark.parametrize("product,kind,concrete", [("pve", "qemu", PVE_QEMU), ("pdm", "qemu", PDM_QEMU)])
def test_require_consent_on_a_tainted_session_without_a_consent_dir_refuses(
        plane, monkeypatch, product, kind, concrete):
    """The look the consent split moved into `_net_verdict`: an ALREADY tainted session under
    REQUIRE_CONSENT with no consent to verify. (Deleting it let the rollback run.)"""
    monkeypatch.setenv(spine.TAINT_REQUIRE_CONSENT_ENV, "1")
    api = _wire(monkeypatch)
    spine.mark_tainted(engine._audit_dir(None), "something-the-model-read-earlier")
    with pytest.raises(ProximoError, match="consent cannot be verified"):
        _rollback(plane, product, kind, concrete, **({"node": "pve1"} if product == "pdm" else {}))
    assert _posts(api) == []
    refuse = [r for r in _rows() if r["action"] == "core.refuse"][-1]
    assert refuse["detail"].get("taint_required") is True


@pytest.mark.parametrize("product,kind,concrete", [("pve", "qemu", PVE_QEMU), ("pdm", "qemu", PDM_QEMU)])
def test_require_consent_on_a_clean_session_is_not_tainted_by_the_nets_reads(
        plane, monkeypatch, product, kind, concrete):
    monkeypatch.setenv(spine.TAINT_REQUIRE_CONSENT_ENV, "1")
    api = _wire(monkeypatch)
    _rollback(plane, product, kind, concrete, **({"node": "pve1"} if product == "pdm" else {}))
    assert concrete + "/snapshot/before/rollback" in _posts(api)
    assert not spine.is_tainted(engine._audit_dir(None))


# --- L3-2: the rollback and its net cost two rate slots, taken together before the grant is spent ------

def test_a_cap_of_one_refuses_before_the_grant_is_spent_naming_the_two_slots(plane, monkeypatch, grants):
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    api = _wire(monkeypatch)
    grant = _grant(grants, _plan(plane, "pve", "qemu", PVE_QEMU)["consent_id"])
    with pytest.raises(ProximoError, match="a rollback with a safety net costs two"):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert _posts(api) == [] and grant.exists()
    assert not any(r["action"] == "core.consent_spent" for r in _rows())
    assert [r["detail"]["needs"] for r in _rows() if r["action"] == "core.refuse"][-1] == "rate"


def test_a_cap_of_two_runs_a_rollback_and_its_net_and_no_more(plane, monkeypatch):
    monkeypatch.setenv("PROXIMO_RATE_MAX", "2")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    api = _wire(monkeypatch)
    assert _rollback(plane, "pve", "qemu", PVE_QEMU)["undo"]["captured"] is True
    with pytest.raises(ProximoError, match="rate refused"):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert len([p for p in _posts(api) if p.endswith("/rollback")]) == 1


@pytest.mark.parametrize("how", ["net-off", "net-skipped-on-zfs"])
def test_where_no_snapshot_is_taken_the_rollback_costs_one_slot(plane, monkeypatch, how):
    monkeypatch.setenv("PROXIMO_RATE_MAX", "1")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    if how == "net-off":
        monkeypatch.setenv(spine.UNDO_ENV, "off")
    api = _wire(monkeypatch, config={"scsi0": "tank:vm-100-disk-0"} if how != "net-off" else None)
    _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert _paths(PVE_QEMU)[1] in _posts(api) and _paths(PVE_QEMU)[0] not in _posts(api)


def test_two_slots_are_taken_together_or_not_at_all(tmp_path):
    base = "https://pve.invalid:8006"
    caps = (3, 600)
    assert spine.reserve_rate(base, str(tmp_path), cap=caps, count=2) is None
    refusal = spine.reserve_rate(base, str(tmp_path), cap=caps, count=2)           # one left: neither is taken
    assert refusal is not None and refusal.needs == "rate" and "costs two" in refusal.reason
    assert spine.reserve_rate(base, str(tmp_path), cap=caps, count=1) is None      # the one slot was still there
    assert spine.reserve_rate(base, str(tmp_path), cap=caps, count=1) is not None


# --- L3-3: a path that is not a storage volume cannot be snapshotted ------------------------------------

def test_an_lxc_bind_mount_means_no_safety_snapshot_is_possible(plane, monkeypatch):
    api = _wire(monkeypatch, config={"rootfs": "local-lvm:vm-100-disk-0", "mp0": "/srv/data,mp=/data"},
                snapcfg={"rootfs": "local-lvm:vm-100-disk-0"})
    planned = _plan(plane, "pve", "lxc", PVE_LXC)
    net = planned["safety_net"]
    assert net["taken"] is False and "also" not in planned
    assert safetynet.IMPOSSIBLE_SENTENCE in net["why"] and safetynet.DEVICE_REASON in net["why"]
    assert "srv" not in net["why"] and "data" not in net["why"]                # never by the guest's own text
    out = _rollback(plane, "pve", "lxc", PVE_LXC)
    assert out["undo"]["captured"] is False and out["undo"]["skipped"] == "storage"
    assert _paths(PVE_LXC)[1] in _posts(api) and _paths(PVE_LXC)[0] not in _posts(api)


def test_a_qemu_passthrough_disk_means_no_safety_snapshot_is_possible(plane, monkeypatch):
    _wire(monkeypatch, config={"scsi0": "local-lvm:vm-100-disk-0", "scsi1": "/dev/disk/by-id/ata-X"},
          snapcfg={"scsi0": "local-lvm:vm-100-disk-0"})
    net = _plan(plane, "pve", "qemu", PVE_QEMU)["safety_net"]
    assert net["taken"] is False and safetynet.DEVICE_REASON in net["why"]


def test_a_device_mount_is_not_what_blocks_a_rollback(plane, monkeypatch):
    """The two judgements stay apart: the rollback is blocked only by the snapshot's own storage
    volumes, so a path in the CURRENT config names no storage type to block with."""
    _wire(monkeypatch, config={"scsi0": "local-lvm:vm-100-disk-0", "scsi1": "/dev/sdb"},
          snapcfg={"scsi0": "local-lvm:vm-100-disk-0"})
    net = _plan(plane, "pve", "qemu", PVE_QEMU)["safety_net"]
    assert "block the rollback" not in net["why"]


def test_qed_is_not_snapshottable_since_plugin_pm_lists_qcow2_only(plane, monkeypatch):
    assert safetynet.can_snapshot("dir", "100/vm-100-disk-0.qed") is False
    assert safetynet.can_snapshot("lvm", "vm-100-disk-0.qed") is False
    _wire(monkeypatch, config={"scsi0": "local:100/vm-100-disk-0.qed"})
    assert _plan(plane, "pve", "qemu", PVE_QEMU)["safety_net"]["taken"] is False


# --- L3-6: the restore plan says what its own safety_net says ------------------------------------------

def test_restore_notes_agree_with_the_plans_safety_net_when_the_net_is_off(plane, monkeypatch):
    _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    monkeypatch.setenv(spine.UNDO_ENV, "off")
    planned = undo.restore(out["undo"]["id"], cfg=plane("pve"))
    assert planned["safety_net"]["taken"] is False
    notes = " ".join(planned["undo_notes"])
    assert "takes its own safety snapshot first" not in notes and "takes no safety snapshot of its own" in notes


def test_restore_notes_agree_when_the_storage_blocks(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    api.config["scsi0"] = "tank:vm-100-disk-0"
    api.snapcfg = api.config
    planned = undo.restore(out["undo"]["id"], cfg=plane("pve"))
    assert planned["safety_net"]["taken"] is False
    assert "takes its own safety snapshot first" not in " ".join(planned["undo_notes"])


def test_restore_notes_say_a_net_when_the_plan_takes_one(plane, monkeypatch):
    _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    planned = undo.restore(out["undo"]["id"], cfg=plane("pve"))
    assert planned["safety_net"]["taken"] is True and "takes its own safety snapshot first" in " ".join(
        planned["undo_notes"])


def test_the_confirmed_restore_derives_its_note_from_what_happened(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    api.config["scsi0"] = "tank:vm-100-disk-0"
    api.snapcfg = api.config
    done = undo.restore(out["undo"]["id"], cfg=plane("pve"), confirm=True)
    assert done["undo"]["captured"] is False
    assert "takes its own safety snapshot first" not in " ".join(done["undo_notes"])


# --- a capture is rolled back to once ------------------------------------------------------------------

def test_a_second_undo_of_one_capture_is_refused_before_it_rolls_the_guest_back_again(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref = out["undo"]["id"]
    undo.restore(ref, cfg=plane("pve"), confirm=True)
    before = len([p for p in _posts(api) if p.endswith("/rollback")])
    with pytest.raises(ProximoError, match="already rolled back to"):
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    with pytest.raises(ProximoError, match="already rolled back to"):
        undo.restore(ref, cfg=plane("pve"))                                   # nor does its plan pretend
    assert len([p for p in _posts(api) if p.endswith("/rollback")]) == before


def test_a_restore_that_failed_may_be_tried_again(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    ref = out["undo"]["id"]
    api.fail_on = "/rollback"
    with pytest.raises(Exception):  # noqa: B017,PT011  (the vendor refused: whatever the type, the capture is unused)
        undo.restore(ref, cfg=plane("pve"), confirm=True)
    api.fail_on = None
    assert undo.restore(ref, cfg=plane("pve"), confirm=True)["restores"] == ref


# --- L3-7: the PVE config read asks for the MAIN section ------------------------------------------------

class Pending(Api):
    """A running guest with a pending change: `current=0` (the default) merges `pending` in."""

    def __init__(self, pending, **kw):
        super().__init__(**kw)
        self.pending = pending

    def call(self, method, path, params=None):
        data = super().call(method, path, params)
        merged_view = path.endswith("/config") and not (params or {}).get("snapshot") \
            and not (params or {}).get("current") and not (params or {}).get("state")
        return {**data, **self.pending} if merged_view else data


@pytest.mark.parametrize("kind,concrete,config,pending", [
    ("qemu", PVE_QEMU, {"scsi0": "local:100/vm-100-disk-0.qcow2"}, {"tpmstate0": "local:100/vm-100-disk-1.raw"}),
    ("lxc", PVE_LXC, {"rootfs": "local:100/vm-100-disk-0.qcow2"}, {"mp0": "local:100/vm-100-disk-1.raw,mp=/x"}),
])
def test_a_pending_change_does_not_cost_a_guest_its_net(plane, monkeypatch, kind, concrete, config, pending):
    api = Pending(pending, config=config, snapcfg=config)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: api)
    net = _plan(plane, "pve", kind, concrete)["safety_net"]
    assert net["taken"] is True and not net.get("unsettled")
    reads = [a for m, p, a in api.calls if m == "GET" and p.endswith("/config") and not a.get("snapshot")]
    assert reads and all(a.get("current") in (True, 1) and "state" not in a for a in reads)
    out = _rollback(plane, "pve", kind, concrete)
    assert out["undo"]["captured"] is True


def test_the_net_still_sees_a_main_section_volume_that_cannot_be_snapshotted(plane, monkeypatch):
    config = {"scsi0": "local:100/vm-100-disk-0.qcow2", "tpmstate0": "local:100/vm-100-disk-1.raw"}
    api = Pending({}, config=config, snapcfg={"scsi0": "local:100/vm-100-disk-0.qcow2"})
    monkeypatch.setattr(engine, "_client", lambda product, c=None: api)
    assert _plan(plane, "pve", "qemu", PVE_QEMU)["safety_net"]["taken"] is False


# --- risk.py: a device node is judged by what the command does with it ---------------------------------------

@pytest.mark.parametrize("cmd", [
    ["cat", "dev/watchdog"], ["cat", "/DEV/watchdog"], ["cat", "//dev//watchdog"], ["cat", "/dev/./watchdog"],
    ["cat", "../dev/watchdog"], ["head", "-c1", "./dev/watchdog"], ["cat", "/proc/1/fd/0"], ["cat", "/proc/self/fd/3"],
    ["tail", "-f", "/proc/12/fd/1"], ["grep", "x", "/dev/mem"], ["cat", "/proc/self/mem"], ["wc", "-c", "/dev/zero"],
    ["cat", "if=/dev/zero"],
])
def test_a_content_reader_on_a_device_or_a_descriptor_is_not_a_read(cmd):
    assert risk.classify_command(cmd)[0] != "read"


@pytest.mark.parametrize("cmd", [
    ["ls", "/dev/"], ["ls", "-l", "/dev/watchdog"], ["stat", "/dev/watchdog"], ["ls", "/dev"], ["ls", "/proc/1/fd"],
    ["cat", "/dev/null"], ["cat", "/devices.txt"], ["ls", "/home/dev/x"], ["cat", "/etc/udev/dev.conf"],
])
def test_listing_a_device_or_naming_something_else_is_still_a_read(cmd):
    assert risk.classify_command(cmd)[0] == "read"
