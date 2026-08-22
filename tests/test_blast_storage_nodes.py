"""storage_update(nodes-restrict) blast — restricting a storage's `nodes` strands guests on the
excluded nodes from their disks on that storage.

Spec: docs/specs/2026-06-19-storage-nodes-restrict-blast.md (internal-only). The load-bearing invariant: a guest is
stranded iff it has a disk on S AND its node ∉ new_nodes. node ∈ new_nodes ⟹ keeps access (no
under-flag path); the only error direction is over-flag (safe).
"""
from __future__ import annotations

from types import SimpleNamespace

from proximo.planning import RISK_HIGH, RISK_MEDIUM


def _guest(vmid="101", kind="qemu", node="pve1", name="web", status="running"):
    return {"vmid": vmid, "type": kind, "node": node, "name": name, "status": status}


def _cfg_on(storage, slot="scsi0", bootdisk="scsi0"):
    return {slot: f"{storage}:1/vm-1-disk-0.qcow2,size=8G", "bootdisk": bootdisk}


def _fake_api(rows, configs):
    """Path-aware fake: /cluster/resources -> rows; .../config -> configs[vmid]."""
    def _get(path):
        if path == "/cluster/resources":
            return rows
        if path.endswith("/config"):
            return configs[path.strip("/").split("/")[3]]  # /nodes/<node>/<kind>/<vmid>/config
        raise AssertionError(f"unexpected GET {path}")

    return SimpleNamespace(_get=_get, config=SimpleNamespace(node="pve1"))


def test_strands_guest_on_excluded_node():
    from proximo.blast import compute_storage_nodes_blast

    guests = [_guest(vmid="101", node="pve1")]
    configs = {"101": _cfg_on("nas")}  # boot disk on nas, node pve1 excluded from {pve2}

    r = compute_storage_nodes_blast("nas", {"pve2"}, guests, configs, complete=True)

    assert [e.vmid for e in r.affected] == ["101"]
    assert r.affected[0].node == "pve1"
    assert r.affected[0].severity == "high"  # boot disk lost → won't boot
    assert r.max_severity == "high"


def test_guest_on_included_node_is_not_stranded():
    """SOUNDNESS GATE: node ∈ new_nodes ⟹ keeps access ⟹ never flagged."""
    from proximo.blast import compute_storage_nodes_blast

    guests = [_guest(vmid="101", node="pve2")]  # on pve2, which STAYS in the node set
    configs = {"101": _cfg_on("nas")}

    r = compute_storage_nodes_blast("nas", {"pve2"}, guests, configs, complete=True)

    assert r.affected == []
    assert r.max_severity == "none"


def test_empty_new_nodes_strands_all_disk_holders():
    from proximo.blast import compute_storage_nodes_blast

    guests = [_guest(vmid="101", node="pve1"), _guest(vmid="102", node="pve2")]
    configs = {"101": _cfg_on("nas"), "102": _cfg_on("nas")}

    r = compute_storage_nodes_blast("nas", set(), guests, configs, complete=True)

    assert {e.vmid for e in r.affected} == {"101", "102"}  # available nowhere → all stranded


def test_widening_strands_nobody_without_crying_wolf():
    from proximo.blast import compute_storage_nodes_blast

    guests = [_guest(vmid="101", node="pve1"), _guest(vmid="102", node="pve2")]
    configs = {"101": _cfg_on("nas"), "102": _cfg_on("nas")}

    r = compute_storage_nodes_blast("nas", {"pve1", "pve2", "pve3"}, guests, configs, complete=True)

    assert r.affected == []
    assert r.max_severity == "none"
    # must say "no guests stranded" — NOT a generic "lose access" scare line
    assert any("no guest" in line.lower() for line in r.summary_lines)
    assert not any("lose access" in line.lower() for line in r.summary_lines)


def test_incomplete_enumeration_is_loud_and_high():
    from proximo.blast import compute_storage_nodes_blast

    guests = [_guest(vmid="101", node="pve1"), _guest(vmid="102", node="pve2")]
    configs = {"101": _cfg_on("nas"), "102": None}  # 102's config read failed

    r = compute_storage_nodes_blast("nas", {"pve2"}, guests, configs, complete=False)

    assert r.complete is False
    assert r.max_severity == "high"  # uncertainty is HIGH, never lowered
    assert any("INCOMPLETE" in line for line in r.summary_lines)
    assert any(e.severity == "unknown" for e in r.affected)  # sentinel


def test_running_guest_on_excluded_node_surfaces_live_crash():
    from proximo.blast import compute_storage_nodes_blast

    guests = [_guest(vmid="101", node="pve1", status="running")]
    configs = {"101": _cfg_on("nas")}

    r = compute_storage_nodes_blast("nas", {"pve2"}, guests, configs, complete=True)

    assert r.affected[0].running is True
    assert "RUNNING" in r.affected[0].effect


# --- wiring: plan_storage_update(nodes=...) ---


def test_plan_storage_update_nodes_names_stranded_guest_and_escalates():
    from proximo.storage_admin import plan_storage_update

    rows = [{"vmid": "101", "type": "qemu", "node": "pve1", "name": "web", "status": "running"}]
    configs = {"101": _cfg_on("nas")}  # boot disk on nas, guest on pve1
    api = _fake_api(rows, configs)

    p = plan_storage_update(api, "nas", nodes="pve2")  # restrict to pve2 → pve1 excluded

    assert [a["vmid"] for a in p.affected] == ["101"]
    assert p.risk == RISK_HIGH  # boot disk lost + running
    assert p.complete is True
    text = " ".join(p.blast_radius).lower()
    assert "strands" in text and "101" in text


def test_plan_storage_update_disable_dominates_over_nodes():
    from proximo.storage_admin import plan_storage_update

    # guest on pve2 (an INCLUDED node) — nodes=pve2 alone would NOT strand it...
    rows = [{"vmid": "101", "type": "qemu", "node": "pve2", "name": "web", "status": "running"}]
    configs = {"101": _cfg_on("nas")}
    api = _fake_api(rows, configs)

    p = plan_storage_update(api, "nas", nodes="pve2", disable=True)  # ...but disable cuts everyone

    assert [a["vmid"] for a in p.affected] == ["101"]  # disable dominates (cluster-wide)
    assert p.risk == RISK_HIGH


def test_plan_storage_update_empty_nodes_is_widening_not_strand_all():
    """nodes="" CLEARS the restriction (PVE: empty/omitted nodes = available on ALL nodes) → a
    WIDENING that strands nobody. Must NOT cry wolf with maximal stranding."""
    from proximo.storage_admin import plan_storage_update

    rows = [{"vmid": "101", "type": "qemu", "node": "pve1", "name": "web", "status": "running"},
            {"vmid": "102", "type": "lxc", "node": "pve2", "name": "db", "status": "running"}]
    configs = {"101": _cfg_on("nas"), "102": _cfg_on("nas", slot="rootfs", bootdisk="rootfs")}
    api = _fake_api(rows, configs)

    p = plan_storage_update(api, "nas", nodes="")

    assert p.affected == []  # widening strands nobody — no maximal-stranding scare
    assert p.risk == RISK_MEDIUM
    text = " ".join(p.blast_radius).lower()
    assert "all nodes" in text or "clears the node restriction" in text


def test_plan_storage_update_disable_false_still_computes_nodes():
    """disable=False (explicit re-enable) + a nodes restriction → the nodes branch must still run."""
    from proximo.storage_admin import plan_storage_update

    rows = [{"vmid": "101", "type": "qemu", "node": "pve1", "name": "web", "status": "running"}]
    configs = {"101": _cfg_on("nas")}
    api = _fake_api(rows, configs)

    p = plan_storage_update(api, "nas", nodes="pve2", disable=False)

    assert [a["vmid"] for a in p.affected] == ["101"]  # nodes branch ran despite disable=False
