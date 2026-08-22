"""network-iface attachment blast — editing a bridge disrupts every guest with a NIC on it when the
staged change is applied. Names the attached guests.

Spec: docs/specs/2026-06-19-firewall-lockout-blast-radius.md (internal-only) (coverage push, rank 4).
"""
from __future__ import annotations


def _guest(vmid="101", kind="qemu", node="pve1", name="web"):
    return {"vmid": vmid, "type": kind, "node": node, "name": name}


def _cfg(*bridges, extra=None):
    """A guest config with one netN per given bridge."""
    cfg = {f"net{i}": f"virtio=AA:BB:CC:DD:EE:0{i},bridge={b},firewall=1" for i, b in enumerate(bridges)}
    if extra:
        cfg.update(extra)
    return cfg


def test_names_guest_attached_to_edited_bridge():
    from proximo.blast import compute_iface_blast

    guests = [_guest(vmid="101", name="web"), _guest(vmid="102", name="db")]
    configs = {"101": _cfg("vmbr1"), "102": _cfg("vmbr0")}   # only 101 on vmbr1
    r = compute_iface_blast("vmbr1", guests, configs, complete=True)

    assert {a["vmid"] for a in r.affected} == {"101"}
    assert r.affected[0]["nics"] == ["net0"]
    assert r.max_severity == "medium"


def test_guest_on_other_bridge_not_flagged():
    from proximo.blast import compute_iface_blast

    guests = [_guest(vmid="101")]
    configs = {"101": _cfg("vmbr0")}
    r = compute_iface_blast("vmbr1", guests, configs, complete=True)

    assert r.affected == []
    assert r.max_severity == "none"
    assert any("no guest" in line.lower() for line in r.summary_lines)


def test_multiple_nics_on_bridge_all_named():
    from proximo.blast import compute_iface_blast

    guests = [_guest(vmid="101")]
    configs = {"101": _cfg("vmbr1", "vmbr1")}   # net0 and net1 both on vmbr1
    r = compute_iface_blast("vmbr1", guests, configs, complete=True)

    assert r.affected[0]["nics"] == ["net0", "net1"]


def test_substring_bridge_name_not_false_matched():
    """SOUNDNESS: editing 'vmbr1' must NOT match a guest on 'vmbr10' (token match, not substring)."""
    from proximo.blast import compute_iface_blast

    guests = [_guest(vmid="101")]
    configs = {"101": _cfg("vmbr10")}
    r = compute_iface_blast("vmbr1", guests, configs, complete=True)

    assert r.affected == []


def test_incomplete_enumeration_is_loud_and_marked():
    from proximo.blast import compute_iface_blast

    guests = [_guest(vmid="101"), _guest(vmid="102")]
    configs = {"101": _cfg("vmbr1"), "102": None}   # 102 unreadable
    r = compute_iface_blast("vmbr1", guests, configs, complete=False)

    assert r.complete is False
    assert any("incomplete" in line.lower() for line in r.summary_lines)
