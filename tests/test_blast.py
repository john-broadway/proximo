"""Blast-radius engine — pure unit tests (zero API) + the I/O layer with a path-aware fake.

The pure reasoning (volid/slot parse, boot detection, classify, compute) is exercised with
fabricated configs. gather_storage_dependents/storage_blast use a SimpleNamespace fake whose
_get dispatches by path. Honesty contract is asserted directly: incomplete enumeration is loud,
never lowers risk, and never reads as "nothing affected = safe".
"""

from __future__ import annotations

from types import SimpleNamespace

from proximo.blast import (
    _boot_slot,
    _classify_guest,
    _disk_slots,
    _is_disk_key,
    _storage_of_volid,
    compute_storage_blast,
    gather_storage_dependents,
    storage_blast,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

def _guest(vmid="101", kind="qemu", node="pve1", name="web", status="running"):
    return {"vmid": vmid, "type": kind, "node": node, "name": name, "status": status}


def _cfg_on(storage, slot="scsi0", bootdisk="scsi0"):
    return {slot: f"{storage}:1/vm-1-disk-0.qcow2,size=8G", "bootdisk": bootdisk}


def _fake_api(rows, configs, *, fail_resources=False, fail_config_for=()):
    cfg = SimpleNamespace(node="pve1")

    def _get(path):
        if path == "/cluster/resources":
            if fail_resources:
                raise RuntimeError("cluster unreachable")
            return rows
        if path.endswith("/config"):
            vmid = path.strip("/").split("/")[3]   # /nodes/<node>/<kind>/<vmid>/config
            if vmid in fail_config_for:
                raise RuntimeError("node down")
            return configs[vmid]
        raise AssertionError(f"unexpected GET {path}")

    return SimpleNamespace(_get=_get, config=cfg)


# ---------------------------------------------------------------------------
# volid + disk-slot parsing (pure)
# ---------------------------------------------------------------------------

def test_storage_of_volid_extracts_storage():
    assert _storage_of_volid("nas:101/vm-101-disk-0.qcow2,size=32G") == "nas"
    assert _storage_of_volid("local-lvm:vm-101-disk-0,size=8G") == "local-lvm"


def test_storage_of_volid_none_for_non_volumes():
    assert _storage_of_volid("none") is None          # cdrom-empty / no media
    assert _storage_of_volid("/dev/disk/by-id/x") is None  # raw passthrough path
    assert _storage_of_volid("") is None


def test_is_disk_key():
    for k in ("rootfs", "scsi0", "virtio15", "sata1", "ide2", "mp0", "unused3",
              "efidisk0", "tpmstate0"):
        assert _is_disk_key(k), k
    for k in ("net0", "name", "boot", "memory", "cores", "scsihw", "ostype"):
        assert not _is_disk_key(k), k


def test_disk_slots_maps_data_disks_to_storage():
    cfg = {"scsi0": "local-lvm:vm-1-disk-0,size=8G",
           "scsi1": "nas:1/vm-1-disk-1.qcow2,size=50G",
           "net0": "virtio=AA:BB,bridge=vmbr0",
           "cores": "2"}
    assert _disk_slots(cfg) == {"scsi0": "local-lvm", "scsi1": "nas"}


def test_disk_slots_excludes_cdrom_media():
    cfg = {"ide2": "nas:iso/debian.iso,media=cdrom",
           "scsi0": "nas:1/vm-1-disk-0.qcow2,size=8G"}
    assert _disk_slots(cfg) == {"scsi0": "nas"}        # cdrom mount is not guest data


# ---------------------------------------------------------------------------
# boot-slot detection + per-guest classification (pure)
# ---------------------------------------------------------------------------

def test_boot_slot_lxc_is_rootfs():
    assert _boot_slot({"rootfs": "nas:subvol-1-disk-0,size=8G"}, "lxc") == "rootfs"
    assert _boot_slot({}, "lxc") is None


def test_boot_slot_qemu_prefers_bootdisk_then_order():
    assert _boot_slot({"bootdisk": "scsi0", "boot": "order=ide2;scsi0"}, "qemu") == "scsi0"
    assert _boot_slot({"boot": "order=scsi0;net0"}, "qemu") == "scsi0"
    assert _boot_slot({"boot": "order=net0;ide2"}, "qemu") == "ide2"  # first DISK in order
    assert _boot_slot({"cores": "2"}, "qemu") is None                 # not determinable


def test_classify_only_copy_wont_boot_high():
    cfg = {"scsi0": "nas:101/vm-101-disk-0.qcow2,size=32G", "bootdisk": "scsi0"}
    e = _classify_guest("nas", _guest(), cfg)
    assert e.severity == "high" and e.only_copy is True and e.via == ["scsi0"]
    assert "will NOT boot" in e.effect and "RUNNING" in e.effect


def test_classify_degraded_when_boot_disk_elsewhere_medium():
    cfg = {"scsi0": "local-lvm:vm-101-disk-0,size=8G",   # boot disk, NOT on nas
           "scsi1": "nas:101/vm-101-disk-1.qcow2,size=50G",  # data disk on nas
           "bootdisk": "scsi0"}
    e = _classify_guest("nas", _guest(status="stopped"), cfg)
    assert e.severity == "medium" and e.only_copy is False and e.via == ["scsi1"]
    assert "degraded" in e.effect and "RUNNING" not in e.effect


def test_classify_not_affected_returns_none():
    cfg = {"scsi0": "local-lvm:vm-101-disk-0,size=8G", "bootdisk": "scsi0"}
    assert _classify_guest("nas", _guest(), cfg) is None


def test_classify_lxc_rootfs_on_target_wont_boot():
    cfg = {"rootfs": "nas:subvol-200-disk-0,size=8G"}
    e = _classify_guest("nas", _guest(vmid="200", kind="lxc"), cfg)
    assert e.severity == "high" and e.resource == "lxc/200"


def test_classify_indeterminate_boot_with_partial_loss_is_conservative_high():
    # scsi0 elsewhere, scsi1 on nas, NO bootdisk/boot line -> boot disk indeterminate.
    # The lost disk (scsi1) MAY be the boot disk, so this is NOT a survivable "degraded"
    # loss: over-flag as won't-boot, the engine's stated doctrine (never under-flag).
    cfg = {"scsi0": "local-lvm:vm-1-disk-0,size=8G",     # some disk elsewhere
           "scsi1": "nas:1/vm-1-disk-1.qcow2,size=9G"}   # data on nas; NO bootdisk/boot line
    e = _classify_guest("nas", _guest(status="stopped"), cfg)
    assert e.severity == "high" and e.only_copy is False and e.via == ["scsi1"]
    assert "may NOT boot" in e.effect
    assert "could not be determined" in e.effect


def test_classify_indeterminate_boot_does_not_falsely_claim_boot_disk_elsewhere():
    # Regression: the engine used to assert "boot disk is elsewhere" even when it could
    # NOT see the boot disk — a false reassurance. It must not claim that when boot is
    # indeterminate (the lost disk could itself be the boot disk).
    cfg = {"scsi0": "local-lvm:vm-1-disk-0,size=8G",
           "scsi1": "nas:1/vm-1-disk-1.qcow2,size=9G"}
    e = _classify_guest("nas", _guest(status="stopped"), cfg)
    assert "boot disk is elsewhere" not in e.effect


def test_classify_netboot_order_is_intentionally_over_flagged():
    # ACCEPTED over-flag (documents intent so a later session doesn't "fix" it into an
    # under-flag): a `boot: order=net0` PXE guest names no DISK token, so `_boot_slot`
    # returns None -> treated as indeterminate -> high. The guest may actually boot from
    # the network and survive the lost data disk, so this is imprecise — but it is the
    # SAFE direction per the over-flag doctrine. Tightening `_boot_slot` to recognise a
    # disk-less boot order is a future precision enhancement, not a safety fix.
    cfg = {"boot": "order=net0",                          # PXE; no disk in the order
           "scsi0": "local-lvm:vm-1-disk-0,size=8G",      # a data disk elsewhere -> not only-copy
           "scsi1": "nas:1/vm-1-disk-1.qcow2,size=9G"}    # the data disk lost on nas
    e = _classify_guest("nas", _guest(status="stopped"), cfg)
    assert e.severity == "high" and "may NOT boot" in e.effect


# ---------------------------------------------------------------------------
# compute_storage_blast aggregator + INCOMPLETE contract (pure)
# ---------------------------------------------------------------------------

def test_compute_sorts_high_before_medium_then_vmid():
    guests = [_guest(vmid="105"), _guest(vmid="102"), _guest(vmid="200", kind="lxc")]
    configs = {
        "105": {"scsi0": "local-lvm:vm-105-disk-0,size=8G",          # boot elsewhere
                "scsi1": "nas:105/vm-105-disk-1.qcow2,size=9G", "bootdisk": "scsi0"},  # medium
        "102": _cfg_on("nas"),                                        # high (only copy)
        "200": {"rootfs": "nas:subvol-200-disk-0,size=8G"},           # high (lxc rootfs)
    }
    r = compute_storage_blast("nas", guests, configs, complete=True)
    # high before medium; within a severity, by vmid ("102" < "200" < "105"-as-medium)
    assert [e.resource for e in r.affected] == ["qemu/102", "lxc/200", "qemu/105"]
    assert r.max_severity == "high" and r.complete is True
    assert any("ENUMERATED 3 guest" in line for line in r.summary_lines)


def test_compute_empty_complete_says_none_found_but_not_safe():
    guests = [_guest(vmid="102")]
    configs = {"102": {"scsi0": "local-lvm:vm-102-disk-0,size=8G", "bootdisk": "scsi0"}}
    r = compute_storage_blast("nas", guests, configs, complete=True)
    assert r.affected == [] and r.max_severity == "none"
    assert any("no guest config references storage 'nas'" in line for line in r.summary_lines)
    assert any("not proof" in line for line in r.summary_lines)


def test_compute_indeterminate_boot_guest_drives_high_severity():
    # A guest losing a disk on the target with an indeterminate boot config must escalate
    # the aggregate to high (raising the plan's risk floor) — not be reported as a
    # survivable medium "degraded" loss.
    guests = [_guest(vmid="109")]
    configs = {"109": {"scsi0": "local-lvm:vm-109-disk-0,size=8G",        # disk elsewhere
                       "scsi1": "nas:109/vm-109-disk-1.qcow2,size=9G"}}    # NO bootdisk/boot line
    r = compute_storage_blast("nas", guests, configs, complete=True)
    assert r.max_severity == "high"
    assert r.affected[0].severity == "high"


def test_compute_incomplete_is_loud_forces_high_and_adds_sentinel():
    guests = [_guest(vmid="102"), _guest(vmid="103")]
    configs = {"102": _cfg_on("nas"), "103": None}      # 103 config read failed
    r = compute_storage_blast("nas", guests, configs, complete=False)
    assert r.complete is False and r.max_severity == "high"
    assert r.summary_lines[0].startswith("⚠ INCOMPLETE")
    assert "1 of 2" in r.summary_lines[0]
    assert any(e.severity == "unknown" for e in r.affected)   # sentinel present
    assert r.affected_dicts()[-1]["severity"] == "unknown"


# ---------------------------------------------------------------------------
# gather_storage_dependents + storage_blast (I/O, failure-catching)
# ---------------------------------------------------------------------------

def test_gather_filters_to_guests_and_reads_each_config():
    rows = [{"vmid": "101", "type": "qemu", "node": "pve1", "name": "a", "status": "running"},
            {"vmid": "200", "type": "lxc", "node": "pve2", "name": "b", "status": "stopped"},
            {"type": "storage", "node": "pve1"},          # filtered out
            {"type": "node", "node": "pve1"}]             # filtered out
    configs = {"101": {"scsi0": "nas:101/d.qcow2,size=8G"},
               "200": {"rootfs": "local-lvm:subvol-200,size=8G"}}
    api = _fake_api(rows, configs)
    guests, got, complete = gather_storage_dependents(api, "nas")
    assert complete is True
    assert {g["vmid"] for g in guests} == {"101", "200"}
    assert got["101"]["scsi0"].startswith("nas:")


def test_gather_total_failure_is_incomplete_not_raise():
    api = _fake_api([], {}, fail_resources=True)
    guests, got, complete = gather_storage_dependents(api, "nas")
    assert guests == [] and got == {} and complete is False


def test_gather_per_guest_config_failure_marks_incomplete():
    rows = [{"vmid": "101", "type": "qemu", "node": "pve1", "name": "a", "status": "running"}]
    api = _fake_api(rows, {}, fail_config_for=("101",))
    guests, got, complete = gather_storage_dependents(api, "nas")
    assert complete is False and got["101"] is None and len(guests) == 1


def test_storage_blast_end_to_end_pure_plus_io():
    rows = [{"vmid": "101", "type": "qemu", "node": "pve1", "name": "web", "status": "running"}]
    configs = {"101": {"scsi0": "nas:101/d.qcow2,size=8G", "bootdisk": "scsi0"}}
    r = storage_blast(_fake_api(rows, configs), "nas")
    assert r.complete is True and r.max_severity == "high"
    assert r.affected[0].resource == "qemu/101"


# ---------------------------------------------------------------------------
# Redteam-driven hardening (2026-06-15)
# ---------------------------------------------------------------------------

def test_gather_empty_config_is_treated_as_incomplete():
    # HTTP 200 with {"data": null} -> guest_config_get coalesces to {} (no exception). A real
    # guest config is never empty, so an empty one means we could NOT see its disks -> partial read.
    rows = [{"vmid": "101", "type": "qemu", "node": "pve1", "name": "a", "status": "running"}]
    api = _fake_api(rows, {"101": {}})
    guests, got, complete = gather_storage_dependents(api, "nas")
    assert complete is False and got["101"] is None and len(guests) == 1


def test_classify_efidisk_only_slot_on_target_is_boot_critical_high():
    cfg = {"scsi0": "local-lvm:vm-1-disk-0,size=60G",   # boot disk elsewhere
           "efidisk0": "nas:vm-1-efidisk-0,size=4M",     # UEFI vars on the target storage
           "bootdisk": "scsi0"}
    e = _classify_guest("nas", _guest(status="stopped"), cfg)
    assert e.severity == "high" and "UEFI/TPM" in e.effect and e.via == ["efidisk0"]


def test_classify_tpmstate_only_slot_on_target_is_boot_critical_high():
    cfg = {"scsi0": "local-lvm:vm-1-disk-0,size=60G",
           "tpmstate0": "nas:vm-1-tpmstate-0,size=4M",
           "bootdisk": "scsi0"}
    e = _classify_guest("nas", _guest(status="stopped"), cfg)
    assert e.severity == "high" and "UEFI/TPM" in e.effect


# ---------------------------------------------------------------------------
# Sensitive-port coverage: a numeric admin/auth port whose SERVICE name is
# sensitive must also be flagged by NUMBER (the "over-flag, never under-flag"
# contract). LDAP 389 / LDAPS 636 were named-only before.
# ---------------------------------------------------------------------------

class TestSensitivePortNumbers:
    def test_ldaps_636_is_sensitive_by_number(self):
        from proximo.blast import _port_is_sensitive
        assert _port_is_sensitive("636") is True

    def test_ldap_389_is_sensitive_by_number(self):
        from proximo.blast import _port_is_sensitive
        assert _port_is_sensitive("389") is True

    def test_random_high_port_is_not_sensitive(self):
        from proximo.blast import _port_is_sensitive
        assert _port_is_sensitive("49123") is False
