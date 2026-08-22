"""disk-move blast — moving a disk onto a target storage consumes that storage's capacity, putting
every co-tenant guest (one with a disk on the target) at risk if the target fills or the move
won't fit.

Spec: docs/specs/2026-06-19-disk-move-blast-radius.md (internal-only). Load-bearing invariants:
- fit check uses PROVISIONED size (worst case) → only over-flags "won't fit", never under-flags;
- co-tenants = every guest with a disk on the target (minus the guest being moved);
- capacity-unknown (size or avail None) is NEVER read as safe → forced HIGH;
- cry-wolf control: when the disk fits comfortably, co-tenants are NOT flagged as affected.
"""
from __future__ import annotations

GiB = 1024 ** 3


def _guest(vmid="101", kind="qemu", node="pve1", name="web", status="running"):
    return {"vmid": vmid, "type": kind, "node": node, "name": name, "status": status}


def _cfg_on(storage, slot="scsi0", size="8G", bootdisk="scsi0"):
    cfg = {slot: f"{storage}:vm-1-{slot}.qcow2,size={size}"}
    if bootdisk:
        cfg["bootdisk"] = bootdisk
    return cfg


def test_wont_fit_is_high_and_names_cotenants():
    """SZ >= target avail → move fails / fills T → HIGH; the co-tenants sharing T are named."""
    from proximo.blast import compute_disk_move_blast

    # moving qemu/100's 50G disk onto 'slow'; 'slow' has only 10G free → won't fit
    guests = [
        _guest(vmid="200", node="pve1", name="db"),       # co-tenant: disk on slow
        _guest(vmid="201", node="pve2", name="cache"),    # co-tenant: disk on slow
        _guest(vmid="300", node="pve1", name="elsewhere"),  # NOT on slow
    ]
    configs = {
        "200": _cfg_on("slow"),
        "201": _cfg_on("slow"),
        "300": _cfg_on("fast"),
    }
    r = compute_disk_move_blast(
        target_storage="slow",
        disk_size_bytes=50 * GiB,
        target_avail=10 * GiB,
        target_total=500 * GiB,
        moved_resource="qemu/100",
        guests=guests,
        configs=configs,
        complete=True,
    )

    assert r.max_severity == "high"
    assert {e.vmid for e in r.affected} == {"200", "201"}   # only the co-tenants on slow
    assert all(e.vmid != "100" for e in r.affected)         # never the guest being moved
    assert any("fit" in line.lower() for line in r.summary_lines)


def test_fits_comfortably_does_not_cry_wolf():
    """Ample headroom → no affected co-tenants, max_severity none, no scare line."""
    from proximo.blast import compute_disk_move_blast

    guests = [_guest(vmid="200", node="pve1")]   # co-tenant on slow, but plenty of room
    configs = {"200": _cfg_on("slow")}
    r = compute_disk_move_blast(
        target_storage="slow",
        disk_size_bytes=8 * GiB,
        target_avail=400 * GiB,
        target_total=500 * GiB,
        moved_resource="qemu/100",
        guests=guests,
        configs=configs,
        complete=True,
    )

    assert r.affected == []
    assert r.max_severity == "none"
    assert not any("will not fit" in line.lower() for line in r.summary_lines)


def test_tight_fit_is_medium_and_names_cotenants():
    """Fits, but leaves < 10% of total free → tight → MEDIUM, co-tenants named."""
    from proximo.blast import compute_disk_move_blast

    guests = [_guest(vmid="200", node="pve1")]
    configs = {"200": _cfg_on("slow")}
    # avail 60G, total 500G; moving 40G → post-move free 20G = 4% of total → tight
    r = compute_disk_move_blast(
        target_storage="slow",
        disk_size_bytes=40 * GiB,
        target_avail=60 * GiB,
        target_total=500 * GiB,
        moved_resource="qemu/100",
        guests=guests,
        configs=configs,
        complete=True,
    )

    assert r.max_severity == "medium"
    assert {e.vmid for e in r.affected} == {"200"}


def test_tight_by_absolute_floor_even_without_total():
    """SOUNDNESS GATE: leaving almost nothing free is TIGHT even when target total is unreadable —
    an absolute-free floor catches it without needing the percentage (which needs total)."""
    from proximo.blast import compute_disk_move_blast

    guests = [_guest(vmid="200", node="pve1")]
    configs = {"200": _cfg_on("slow")}
    # avail 12G, total UNKNOWN; moving 10G leaves only 2G free → below the absolute floor → tight
    r = compute_disk_move_blast(
        target_storage="slow",
        disk_size_bytes=10 * GiB,
        target_avail=12 * GiB,
        target_total=None,            # total unreadable — must NOT route a tight move to "fits"
        moved_resource="qemu/100",
        guests=guests,
        configs=configs,
        complete=True,
    )

    assert r.max_severity == "medium"
    assert {e.vmid for e in r.affected} == {"200"}


def test_total_unknown_but_roomy_does_not_reassure():
    """Total unreadable + ample absolute free → won't-fit ruled out, but fullness can't be assessed,
    so the engine discloses the unknown rather than reassuring."""
    from proximo.blast import compute_disk_move_blast

    guests = [_guest(vmid="200", node="pve1")]
    configs = {"200": _cfg_on("slow")}
    r = compute_disk_move_blast(
        target_storage="slow",
        disk_size_bytes=8 * GiB,
        target_avail=400 * GiB,
        target_total=None,
        moved_resource="qemu/100",
        guests=guests,
        configs=configs,
        complete=True,
    )

    assert r.max_severity == "none"          # fits available space; won't-fit ruled out
    text = " ".join(r.summary_lines).lower()
    assert "ample headroom" not in text
    assert "total" in text and ("unknown" in text or "unreadable" in text)


def test_capacity_unknown_is_never_safe():
    """SOUNDNESS GATE: unreadable target avail → cannot assess fit → forced HIGH, loud, no 'safe'."""
    from proximo.blast import compute_disk_move_blast

    guests = [_guest(vmid="200", node="pve1")]
    configs = {"200": _cfg_on("slow")}
    r = compute_disk_move_blast(
        target_storage="slow",
        disk_size_bytes=8 * GiB,
        target_avail=None,            # storage_status read failed
        target_total=None,
        moved_resource="qemu/100",
        guests=guests,
        configs=configs,
        complete=True,
    )

    assert r.max_severity == "high"
    assert any("capacity" in line.lower() for line in r.summary_lines)


def test_unknown_disk_size_is_never_safe():
    """SOUNDNESS GATE: unparseable disk size → cannot assess fit → forced HIGH."""
    from proximo.blast import compute_disk_move_blast

    r = compute_disk_move_blast(
        target_storage="slow",
        disk_size_bytes=None,         # couldn't parse the moved disk's size
        target_avail=400 * GiB,
        target_total=500 * GiB,
        moved_resource="qemu/100",
        guests=[],
        configs={},
        complete=True,
    )

    assert r.max_severity == "high"


def test_incomplete_enumeration_is_loud_and_high():
    """Guest enumeration incomplete → loud INCOMPLETE, forced HIGH, 'unknown' sentinel appended."""
    from proximo.blast import compute_disk_move_blast

    guests = [_guest(vmid="200", node="pve1"), _guest(vmid="201", node="pve2")]
    configs = {"200": _cfg_on("slow"), "201": None}   # 201 unreadable
    r = compute_disk_move_blast(
        target_storage="slow",
        disk_size_bytes=8 * GiB,
        target_avail=400 * GiB,
        target_total=500 * GiB,
        moved_resource="qemu/100",
        guests=guests,
        configs=configs,
        complete=False,
    )

    assert r.max_severity == "high"
    assert any("incomplete" in line.lower() for line in r.summary_lines)
    assert any(e.severity == "unknown" for e in r.affected)


def test_fits_but_incomplete_does_not_reassure():
    """When guest enumeration is incomplete, the 'fits' branch must NOT emit a co-tenant
    reassurance (the count is a floor, not exhaustive) — it must flag the list as incomplete.
    Mirrors the sibling functions' `elif complete:` honesty contract."""
    from proximo.blast import compute_disk_move_blast

    guests = [_guest(vmid="200", node="pve1"), _guest(vmid="201", node="pve2")]
    configs = {"200": _cfg_on("slow"), "201": None}   # 201 unread → incomplete, but disk fits
    r = compute_disk_move_blast(
        target_storage="slow",
        disk_size_bytes=8 * GiB,
        target_avail=400 * GiB,
        target_total=500 * GiB,
        moved_resource="qemu/100",
        guests=guests,
        configs=configs,
        complete=False,
    )
    text = " ".join(r.summary_lines).lower()
    assert "ample headroom" not in text          # no blanket reassurance when incomplete
    assert "incomplete" in text                   # the loud INCOMPLETE marker is present
    assert r.max_severity == "high"               # and risk stays forced HIGH


def test_moved_guest_never_listed_as_its_own_cotenant():
    """The guest being moved already has a disk on the target → must NOT appear as a co-tenant."""
    from proximo.blast import compute_disk_move_blast

    guests = [_guest(vmid="100", node="pve1", name="self")]   # the guest being moved, already on slow
    configs = {"100": _cfg_on("slow")}
    r = compute_disk_move_blast(
        target_storage="slow",
        disk_size_bytes=50 * GiB,
        target_avail=10 * GiB,
        target_total=500 * GiB,
        moved_resource="qemu/100",
        guests=guests,
        configs=configs,
        complete=True,
    )

    assert r.affected == []        # self is excluded; no OTHER guest affected
    assert r.max_severity == "high"  # still won't fit → high (capacity verdict stands)
