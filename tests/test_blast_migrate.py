"""guest-migrate disk-residency blast — a guest's disks can only migrate cleanly if each sits on
storage that is SHARED and available on the target node. Local (shared=0) storage forces a copy (or
fails); a nodes-restricted storage absent from the target can't place the disk at all.

Spec: docs/specs/2026-06-19-migrate-disk-residency-blast.md (internal-only). Soundness: a disk is OK (unflagged) ONLY
when its storage is provably shared AND available on the target — local/unavailable/unknown all flag.
"""
from __future__ import annotations


def _meta(shared=True, nodes=None):
    return {"shared": shared, "nodes": nodes}


def test_local_disk_blocks_clean_migration():
    from proximo.blast import compute_migrate_blast

    r = compute_migrate_blast("pveB", {"scsi0": "local-lvm"}, {"local-lvm": _meta(shared=False)},
                              config_complete=True, online=False, kind="qemu")
    assert r.max_severity == "high"
    assert any(a["storage"] == "local-lvm" and a["state"] == "local" for a in r.affected)


def test_shared_disk_available_on_target_is_clean():
    from proximo.blast import compute_migrate_blast

    r = compute_migrate_blast("pveB", {"scsi0": "ceph"}, {"ceph": _meta(shared=True, nodes=None)},
                              config_complete=True, online=True, kind="qemu")
    assert r.max_severity == "none"
    assert r.affected == []


def test_shared_storage_not_on_target_node_fails():
    """SOUNDNESS: a shared storage restricted to nodes that EXCLUDE the target can't place the disk."""
    from proximo.blast import compute_migrate_blast

    r = compute_migrate_blast("pveB", {"scsi0": "ceph"}, {"ceph": _meta(shared=True, nodes={"pveA"})},
                              config_complete=True, online=False, kind="qemu")
    assert r.max_severity == "high"
    assert any(a["storage"] == "ceph" and a["state"] == "unavailable" for a in r.affected)


def test_shared_storage_includes_target_is_clean():
    from proximo.blast import compute_migrate_blast

    r = compute_migrate_blast("pveB", {"scsi0": "ceph"},
                              {"ceph": _meta(shared=True, nodes={"pveA", "pveB"})},
                              config_complete=True, online=False, kind="qemu")
    assert r.affected == []
    assert r.max_severity == "none"


def test_unknown_storage_metadata_is_flagged_and_incomplete():
    """SOUNDNESS: storage whose config we couldn't read is never assumed migratable."""
    from proximo.blast import compute_migrate_blast

    r = compute_migrate_blast("pveB", {"scsi0": "mystery"}, {}, config_complete=True,
                              online=False, kind="qemu")
    assert r.complete is False
    assert r.max_severity == "high"
    assert any(a["storage"] == "mystery" and a["state"] == "unknown" for a in r.affected)


def test_unreadable_guest_config_is_loud_and_high():
    """SOUNDNESS: can't read the guest config → can't enumerate disks → never 'safe'."""
    from proximo.blast import compute_migrate_blast

    r = compute_migrate_blast("pveB", {}, {}, config_complete=False, online=False, kind="qemu")
    assert r.complete is False
    assert r.max_severity == "high"
    assert any("incomplete" in line.lower() or "could not" in line.lower() for line in r.summary_lines)


def test_live_qemu_with_local_disk_is_high():
    """The key catch: a LIVE (online qemu) migration is impossible with a local disk → HIGH."""
    from proximo.blast import compute_migrate_blast

    r = compute_migrate_blast("pveB", {"scsi0": "local-lvm"}, {"local-lvm": _meta(shared=False)},
                              config_complete=True, online=True, kind="qemu")
    assert r.max_severity == "high"
    assert any("local" in line.lower() for line in r.summary_lines)


def test_multiple_disks_mixed_flags_only_the_blocker():
    from proximo.blast import compute_migrate_blast

    r = compute_migrate_blast("pveB", {"scsi0": "ceph", "scsi1": "local-lvm"},
                              {"ceph": _meta(shared=True), "local-lvm": _meta(shared=False)},
                              config_complete=True, online=False, kind="qemu")
    states = {a["storage"]: a["state"] for a in r.affected}
    assert states.get("local-lvm") == "local"
    assert "ceph" not in states              # shared + available → not flagged (no cry-wolf)
    assert r.max_severity == "high"


def test_raw_passthrough_disk_is_flagged_not_dropped():
    """SOUNDNESS GATE: a raw /dev passthrough disk names no PVE storage and CANNOT follow the guest to
    another node — it must be flagged, never silently dropped into a 'clean migrate' verdict."""
    from proximo.blast import compute_migrate_blast

    r = compute_migrate_blast("pveB", {}, {}, config_complete=True, online=False, kind="qemu",
                              raw_slots=["scsi0"])
    assert r.max_severity == "high"
    assert any(a["slot"] == "scsi0" and a["state"] == "raw" for a in r.affected)


def test_raw_disk_alongside_shared_is_not_called_clean():
    from proximo.blast import compute_migrate_blast

    r = compute_migrate_blast("pveB", {"scsi1": "ceph"}, {"ceph": _meta(shared=True)},
                              config_complete=True, online=False, kind="qemu", raw_slots=["scsi0"])
    assert r.max_severity == "high"
    assert not any("no disk copy required" in line.lower() for line in r.summary_lines)


def test_disk_slots_split_separates_raw_from_storage_backed():
    from proximo.blast import _disk_slots_split

    backed, raw = _disk_slots_split({
        "scsi0": "ceph:vm-1-disk-0,size=8G",        # storage-backed
        "scsi1": "/dev/disk/by-id/ata-X,size=100G",  # raw passthrough
        "ide2": "none,media=cdrom",                  # cdrom — excluded from both
        "net0": "virtio=AA:BB,bridge=vmbr0",         # not a disk key
    })
    assert backed == {"scsi0": "ceph"}
    assert raw == ["scsi1"]


def test_diskless_guest_is_clean():
    from proximo.blast import compute_migrate_blast

    r = compute_migrate_blast("pveB", {}, {}, config_complete=True, online=True, kind="qemu")
    assert r.affected == []
    assert r.max_severity == "none"
