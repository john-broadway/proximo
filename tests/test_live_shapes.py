"""Characterization tests — assert Proximo's blast engine parses REAL Proxmox response shapes.

The fixtures in ``live_shapes/fixtures/`` were captured from a real PVE (read-only) and scrubbed of
infra literals; they preserve PVE's serialization QUIRKS so a wrong API-shape assumption fails fast
here instead of silently producing a confidently-wrong blast against a live cluster:

  - PVE **omits** unset backup-job selection keys (``pool``/``vmid``/``selMode``) rather than sending
    ``null`` — the tri-state coverage resolver depends on this.
  - the snapshot list always carries a synthetic ``{"name": "current"}`` entry that is NOT a snapshot.
  - ``all`` serializes as an int (``1``), ``exclude`` as a comma-string, disks as ``slot: volid``.

Track A of the live-CI scope: shape-only, point-in-time, credential-free. Complements (does not
replace) the live mutate-verify smokes in ``scripts/live-smoke/``. Re-capture with
``scripts/live-smoke/capture-shapes.py`` after a PVE major upgrade.
"""
import json
from pathlib import Path

from proximo.blast import (
    GuestDestroyInputs,
    _boot_slot,
    _disk_slots,
    compute_acl_blast,
    compute_guest_destroy_blast,
)

FIX = json.loads(
    (Path(__file__).parent / "live_shapes" / "fixtures" / "pve_real_shapes.json").read_text()
)


def _destroy_inputs(vmid: str, **over) -> GuestDestroyInputs:
    base = dict(
        vmid=vmid, kind="qemu", purge=True, force=False,
        guest_config=FIX["guest_config"], status="stopped",
        ha_resources=[], replication_jobs=[], backup_jobs=FIX["backup_jobs"],
        pools=[], snapshots=FIX["guest_snapshots"], clone_configs={},
    )
    base.update(over)
    return GuestDestroyInputs(**base)


# --- backup-job selection-mode serialization (the assessor's #1 risk) ---

def test_real_backup_job_omits_unset_selection_keys():
    """Ground truth: real PVE OMITS pool/vmid/selMode on an all=1 job — it does NOT send null. The
    resolver's ``.get(key, "")`` default relies on this; a future null-serialization is a different
    shape this fixture would catch."""
    job = FIX["backup_jobs"][0]
    assert job["all"] == 1                  # int, not "1"
    assert job["exclude"] == "100,101,102"  # comma-string
    assert "pool" not in job                # OMITTED, not null
    assert "vmid" not in job
    assert "selMode" not in job


def test_guest_destroy_backup_coverage_excluded_vmid_real_shape():
    """vmid 100 is in the real job's exclude list → NOT covered → no backup_job reference emitted."""
    res = compute_guest_destroy_blast(_destroy_inputs("100"))
    assert [a for a in res.affected if a.get("kind") == "backup_job"] == []


def test_guest_destroy_backup_coverage_included_vmid_real_shape():
    """A vmid NOT excluded → covered by the all=1 job → exactly one backup_job reference."""
    res = compute_guest_destroy_blast(_destroy_inputs("200"))
    assert len([a for a in res.affected if a.get("kind") == "backup_job"]) == 1


# --- snapshot synthetic 'current' entry ---

def test_guest_destroy_excludes_synthetic_current_snapshot_real_shape():
    """The real snapshot list is just the synthetic 'current' entry; it must NOT count as a snapshot."""
    assert any(s["name"] == "current" for s in FIX["guest_snapshots"])  # the quirk is present
    res = compute_guest_destroy_blast(_destroy_inputs("100"))
    assert [a for a in res.affected if a.get("kind") == "snapshots"] == []


# --- guest config disk-slot enumeration ---

def test_disk_slots_real_config_excludes_cdrom():
    slots = _disk_slots(FIX["guest_config"])
    assert slots == {"scsi0": "local-lvm"}   # scsi0 is the data disk; ide2 (media=cdrom) excluded
    assert "ide2" not in slots


def test_boot_slot_real_config_uses_boot_order():
    # real 'boot' = 'order=scsi0;ide2' → first disk in the order is the boot slot
    assert _boot_slot(FIX["guest_config"], "qemu") == "scsi0"


# --- ACL entries ---

def test_compute_acl_blast_parses_real_acl_entries():
    """Feed the real ACL list as the current cluster ACL; the engine must run over the real
    path/roleid/type/ugid shape without crashing and return a structured result."""
    res = compute_acl_blast(
        path="/", roles="Administrator", target="newuser@pam", kind="user",
        delete=False, acl_entries=FIX["acl"],
    )
    assert isinstance(res.affected, list)
