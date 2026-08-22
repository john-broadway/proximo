"""storage content-delete blast — deleting a volume that is an ACTIVE guest disk destroys that disk's
data. Scans guest configs for the exact volid.

Spec: coverage push rank 9 (docs/specs/2026-06-19-disk-move-blast-radius.md (internal-only) lists the order).
"""
from __future__ import annotations


def _guest(vmid="101", kind="qemu", node="pve1", name="web"):
    return {"vmid": vmid, "type": kind, "node": node, "name": name}


def test_volid_in_use_as_boot_disk_is_high_and_wont_boot():
    from proximo.blast import compute_content_delete_blast

    guests = [_guest(vmid="101")]
    configs = {"101": {"scsi0": "local-lvm:vm-101-disk-0,size=8G", "bootdisk": "scsi0"}}
    r = compute_content_delete_blast("local-lvm:vm-101-disk-0", guests, configs, complete=True)

    assert r.max_severity == "high"
    assert any(a["vmid"] == "101" for a in r.affected)
    assert any("not boot" in line.lower() for line in r.summary_lines)


def test_volid_in_use_as_data_disk_is_high():
    from proximo.blast import compute_content_delete_blast

    guests = [_guest(vmid="101")]
    configs = {"101": {"scsi0": "local-lvm:vm-101-disk-0,size=8G",   # boot disk, elsewhere
                       "scsi1": "nas:vm-101-disk-1,size=50G", "bootdisk": "scsi0"}}
    r = compute_content_delete_blast("nas:vm-101-disk-1", guests, configs, complete=True)

    assert r.max_severity == "high"
    assert any(a["vmid"] == "101" and "scsi1" in a["via"] for a in r.affected)


def test_orphan_volume_not_referenced_is_clean():
    from proximo.blast import compute_content_delete_blast

    guests = [_guest(vmid="101")]
    configs = {"101": {"scsi0": "local-lvm:vm-101-disk-0,size=8G"}}
    r = compute_content_delete_blast("local-lvm:vm-999-disk-0", guests, configs, complete=True)

    assert r.affected == []
    assert r.max_severity == "none"


def test_exact_volid_match_no_prefix_false_positive():
    """SOUNDNESS: deleting vm-101-disk-0 must not match vm-101-disk-00 (exact head match)."""
    from proximo.blast import compute_content_delete_blast

    guests = [_guest(vmid="101")]
    configs = {"101": {"scsi0": "local-lvm:vm-101-disk-00,size=8G"}}
    r = compute_content_delete_blast("local-lvm:vm-101-disk-0", guests, configs, complete=True)

    assert r.affected == []


def test_cdrom_mounted_volid_not_flagged_as_active_disk():
    """A volid a guest mounts as cdrom MEDIA is not its active disk — deleting it breaks a mount, not
    data. It must not be mislabeled 'ACTIVE disk — DESTROYS data' (matches _disk_slots cdrom exclusion)."""
    from proximo.blast import compute_content_delete_blast

    guests = [_guest(vmid="101")]
    configs = {"101": {"ide2": "local:iso/x.iso,media=cdrom",
                       "scsi0": "local-lvm:vm-101-disk-0,size=8G"}}
    r = compute_content_delete_blast("local:iso/x.iso", guests, configs, complete=True)

    assert r.affected == []   # cdrom mount, not an active disk


def test_incomplete_enumeration_is_loud_and_marked():
    from proximo.blast import compute_content_delete_blast

    guests = [_guest(vmid="101"), _guest(vmid="102")]
    configs = {"101": {"scsi0": "local-lvm:vm-101-disk-0"}, "102": None}
    r = compute_content_delete_blast("nas:vm-102-disk-0", guests, configs, complete=False)

    assert r.complete is False
    assert any("incomplete" in line.lower() for line in r.summary_lines)
