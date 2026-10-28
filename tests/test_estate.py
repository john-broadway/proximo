"""The estate model: plain records built from the vendor's own answers, and the relations between
them, with no I/O. Every judge reads this, from a live consult or (later) the memory file, so a plan
and a terminal answer agree by construction.

The intents ported from 0.44 (`git show 2d87019^:tests/test_blast_content_delete.py`, `test_blast.py`):
a disk is a data-volume slot (rootfs, scsiN, virtioN, mpN, unusedN, efidisk0, tpmstate0), never a NIC
or a cdrom; a volid's storage is the segment before the colon, never a raw path; the boot slot is
`bootdisk`, else the first disk in `boot: order=`, and rootfs for a container; a volid matches
exactly (`vm-101-disk-0` is not `vm-101-disk-00`). New here: a field the vendor omitted is unknown
(None), never zero, false or empty.
"""
from __future__ import annotations

import pytest

from proximo.core import estate

RESOURCES = [
    {"id": "qemu/101", "type": "qemu", "vmid": 101, "node": "pve1", "name": "web", "status": "running",
     "template": 0, "pool": "prod", "tags": "a;b"},
    {"id": "lxc/105", "type": "lxc", "vmid": 105, "node": "pve2", "name": "dns", "status": "stopped"},
    {"id": "node/pve1", "type": "node", "node": "pve1", "status": "online"},
    {"id": "storage/pve1/local-lvm", "type": "storage", "node": "pve1", "storage": "local-lvm",
     "status": "available", "shared": 0, "content": "images,rootdir", "plugintype": "lvmthin"},
]


# --- the vendor's answers become records -------------------------------------------------------------

def test_resources_give_guests_nodes_and_storage():
    guests = estate.guests_from_resources(RESOURCES)
    assert [(g.kind, g.vmid, g.node, g.name) for g in guests] == [("qemu", "101", "pve1", "web"),
                                                                    ("lxc", "105", "pve2", "dns")]
    assert guests[0].running is True and guests[1].running is False
    assert guests[0].template is False and guests[0].pool == "prod" and guests[0].tags == ("a", "b")
    assert [n.name for n in estate.nodes_from_resources(RESOURCES)] == ["pve1"]
    (s,) = estate.storages_from_resources(RESOURCES)
    assert (s.id, s.node, s.shared, s.content) == ("local-lvm", "pve1", False, ("images", "rootdir"))


def test_a_field_the_vendor_omitted_is_unknown_not_zero():
    """`lxc/105` carries no template, pool or tags: unknown, never False/empty. A guest row with no
    status is not 'stopped'."""
    g = estate.guests_from_resources([{"type": "lxc", "vmid": 105}])[0]
    assert g.template is None and g.pool is None and g.tags is None
    assert g.node is None and g.name is None and g.status is None and g.running is None
    (s,) = estate.storages_from_resources([{"type": "storage", "storage": "nas"}])
    assert s.shared is None and s.content is None and s.node is None


def test_the_vmid_comes_from_the_id_when_the_row_omits_it():
    (g,) = estate.guests_from_resources([{"id": "qemu/300", "type": "qemu", "node": "pve1"}])
    assert g.vmid == "300" and g.key == "qemu/300"


def test_rows_that_are_not_records_are_skipped_not_fatal():
    assert estate.guests_from_resources([None, "x", 3, {"type": "qemu"}]) == ()   # no vmid: not a guest


# --- a guest's config: disks and NICs ----------------------------------------------------------------

QEMU = {"scsi0": "local-lvm:vm-101-disk-0,size=32G", "scsi1": "nas:101/vm-101-disk-1.qcow2,size=8G",
        "ide2": "local:iso/debian.iso,media=cdrom", "efidisk0": "local-lvm:vm-101-disk-2,size=4M",
        "unused0": "nas:vm-101-disk-9", "sata0": "/dev/disk/by-id/ata-X",
        "net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0",
        "net1": "e1000=AA:BB:CC:DD:EE:00,bridge=vmbr10,firewall=1", "boot": "order=scsi0;ide2;net0", "name": "web"}


def test_disks_are_data_slots_never_nics_or_names():
    disks = {d.slot: d for d in estate.disks_from_config("qemu", "101", QEMU)}
    assert set(disks) == {"scsi0", "scsi1", "ide2", "efidisk0", "unused0", "sata0"}
    assert disks["scsi0"].volid == "local-lvm:vm-101-disk-0" and disks["scsi0"].storage == "local-lvm"
    assert disks["scsi1"].storage == "nas"
    assert disks["ide2"].cdrom is True and disks["scsi0"].cdrom is False
    assert disks["sata0"].storage is None and disks["sata0"].volid is None      # a raw passthrough
    assert disks["scsi0"].guest == "qemu/101"


@pytest.mark.parametrize("value,storage", [
    ("local-lvm:vm-101-disk-0,size=8G", "local-lvm"),
    ("nas:101/vm-101-disk-0.qcow2,size=32G", "nas"),
    ("none", None), ("/dev/sdb", None), ("/mnt/x:y", None), (":vm-1", None), ("nas:", None),
])
def test_a_volids_storage_is_the_segment_before_the_colon(value, storage):
    assert estate.storage_of_volid(value) == storage


def test_the_disk_key_rule_is_0_44s():
    for key in ("rootfs", "mp0", "mp12", "scsi30", "virtio15", "ide3", "sata5", "efidisk0", "tpmstate0", "unused3",
                "vmstate"):
        assert estate.is_disk_key(key), key
    for key in ("net0", "boot", "bootdisk", "scsihw", "memory", "ipconfig0", "hostpci0", "scsi", "mpx", "vmstate0"):
        assert not estate.is_disk_key(key), key


def test_nics_name_their_bridge_by_token():
    nics = {n.slot: n for n in estate.nics_from_config("qemu", "101", QEMU)}
    assert nics["net0"].bridge == "vmbr0" and nics["net1"].bridge == "vmbr10"
    lxc = estate.nics_from_config("lxc", "105", {"net0": "name=eth0,bridge=vmbr1,hwaddr=AA:BB,ip=dhcp"})
    assert lxc[0].bridge == "vmbr1" and lxc[0].guest == "lxc/105"
    assert estate.nics_from_config("qemu", "1", {"net0": "virtio=AA"})[0].bridge is None   # unknown, not ""


@pytest.mark.parametrize("config,kind,slot", [
    ({"bootdisk": "virtio0", "boot": "order=scsi0"}, "qemu", "virtio0"),
    ({"boot": "order=net0;scsi1;scsi0"}, "qemu", "scsi1"),
    ({"boot": "cdn"}, "qemu", None),
    ({}, "qemu", None),
    ({"rootfs": "local:105/vm-105-disk-0.raw"}, "lxc", "rootfs"),
    ({}, "lxc", None),
])
def test_the_boot_slot(config, kind, slot):
    assert estate.boot_slot(config, kind) == slot


# --- the other sources ---------------------------------------------------------------------------------

def test_storage_config_content_jobs_pools_and_network():
    (s,) = estate.storages_from_config([{"storage": "nas", "type": "nfs", "shared": 1, "content": "images,backup",
                                         "nodes": "pve1,pve2", "disable": 0}])
    assert (s.type, s.shared, s.nodes, s.disabled) == ("nfs", True, ("pve1", "pve2"), False)
    (s2,) = estate.storages_from_config([{"storage": "local", "type": "dir"}])
    assert s2.nodes is None and s2.disabled is None and s2.shared is None          # all nodes: unknown here
    vols = estate.volumes_from_content("nas", [{"volid": "nas:backup/vzdump-qemu-101-2026.vma.zst",
                                                 "content": "backup", "vmid": 101, "size": 5, "ctime": 7}])
    assert (vols[0].volid, vols[0].vmid, vols[0].content, vols[0].size, vols[0].storage) == \
        ("nas:backup/vzdump-qemu-101-2026.vma.zst", "101", "backup", 5, "nas")
    (j,) = estate.jobs_from_backup([{"id": "backup-1", "vmid": "101,105", "storage": "nas", "enabled": 1}])
    assert j.vmids == ("101", "105") and j.all is None and j.enabled is True and j.pool is None
    (p,) = estate.pools_from_pools([{"poolid": "prod", "members": [{"id": "qemu/101", "type": "qemu", "vmid": 101}]}])
    assert p.members == ("qemu/101",)
    (p2,) = estate.pools_from_pools([{"poolid": "dev"}])
    assert p2.members is None                                                         # not listed: unknown
    (i,) = estate.ifaces_from_network("pve1", [{"iface": "vmbr0", "type": "bridge", "active": 1,
                                                "cidr": "192.0.2.10/24", "bridge_ports": "eno1"}])
    assert (i.node, i.iface, i.type, i.active, i.ports) == ("pve1", "vmbr0", "bridge", True, ("eno1",))


# --- the estate and its relations ---------------------------------------------------------------------

def _estate(**configs):
    reads = [estate.Answer("/cluster/resources", {}, RESOURCES)]
    for key, cfg in configs.items():
        kind, vmid = key.split("_")
        node = "pve1" if kind == "qemu" else "pve2"
        reads.append(estate.Answer(f"/nodes/{{node}}/{kind}/{{vmid}}/config", {"node": node, "vmid": vmid}, cfg))
    return estate.build(reads)


def test_build_joins_a_config_to_its_guest():
    e = _estate(qemu_101=QEMU, lxc_105={"rootfs": "local-lvm:vm-105-disk-0,size=8G",
                                        "net0": "name=eth0,bridge=vmbr0"})
    assert [g.key for g in e.guests_on_storage("local-lvm")] == ["qemu/101", "lxc/105"]
    assert [g.key for g in e.guests_on_storage("nas")] == ["qemu/101"]
    assert [g.key for g in e.guests_on_storage("local")] == []          # an ISO mounted as cdrom is not data
    assert [g.key for g in e.guests_on_bridge("vmbr0")] == ["qemu/101", "lxc/105"]
    assert [g.key for g in e.guests_on_bridge("vmbr1")] == []           # token match: vmbr1 is not vmbr10
    assert {d.slot for d in e.disks_of("lxc/105")} == {"rootfs"}
    assert e.unread == frozenset()


def test_a_guest_whose_config_was_not_read_is_unread_not_diskless():
    """0.44's rule (`gather_storage_dependents`): an enumerated guest with no config, or an EMPTY one,
    is a failed read, never 'no disks, so not affected'."""
    e = _estate(qemu_101=QEMU, lxc_105={})
    assert e.unread == frozenset({"lxc/105"})
    e2 = _estate(qemu_101=QEMU)
    assert e2.unread == frozenset({"lxc/105"})


def test_disks_using_matches_a_volid_exactly():
    e = _estate(qemu_101={"scsi0": "local-lvm:vm-101-disk-00,size=8G", "scsi1": "local-lvm:vm-101-disk-0"},
                lxc_105={"rootfs": "local-lvm:vm-105-disk-0"})
    assert [(d.guest, d.slot) for d in e.disks_using("local-lvm:vm-101-disk-0")] == [("qemu/101", "scsi1")]


def test_backups_jobs_and_pools():
    reads = [estate.Answer("/cluster/resources", {}, RESOURCES),
             estate.Answer("/nodes/{node}/storage/{storage}/content", {"node": "pve1", "storage": "nas"},
                           [{"volid": "nas:backup/vzdump-qemu-101-1.vma.zst", "content": "backup", "vmid": 101},
                            {"volid": "nas:iso/x.iso", "content": "iso"}]),
             estate.Answer("/cluster/backup", {}, [
                 {"id": "all", "all": 1, "exclude": "105"},
                 {"id": "pool", "pool": "prod"},
                 {"id": "list", "vmid": "105"},
                 {"id": "odd", "all": 0}]),
             estate.Answer("/pools", {}, [{"poolid": "prod", "members": [{"id": "qemu/101"}]}])]
    e = estate.build(reads)
    assert [v.volid for v in e.backups_of("101")] == ["nas:backup/vzdump-qemu-101-1.vma.zst"]
    cover = {j.id: c for j, c in e.jobs_covering("101")}
    assert cover == {"all": True, "pool": True, "list": False, "odd": None}
    cover105 = {j.id: c for j, c in e.jobs_covering("105")}
    assert cover105 == {"all": False, "pool": False, "list": True, "odd": None}
    assert [g.key for g in e.guests_in_pool("prod")] == ["qemu/101"]


def test_pool_coverage_without_pool_members_is_unresolved_not_false():
    e = estate.build([estate.Answer("/cluster/backup", {}, [{"id": "pool", "pool": "prod"}])])
    assert [c for _, c in e.jobs_covering("101")] == [None]


def test_an_answer_from_an_address_the_estate_does_not_read_is_refused():
    with pytest.raises(ValueError, match="/version"):
        estate.build([estate.Answer("/version", {}, {})])


def test_every_source_is_a_published_get():
    from proximo.core import engine
    for template in estate.SOURCES:
        assert engine.resolve("pve", "GET", template).access == "read", template


# --- the lens (2026-10-25): a wrong shape is a failed read; views; the volume's spellings ---------------

@pytest.mark.parametrize("answer,words", [
    (None, "NoneType"), ("x", "str"), (42, "int"), ({"data": []}, "dict"),
    ([{"type": "qemu"}], "no vmid"), (["x"], "not a record"),
])
def test_a_resources_answer_of_the_wrong_shape_is_malformed_not_empty(answer, words):
    e = estate.build([estate.Answer("/cluster/resources", {}, answer)])
    assert e.guests == () and e.malformed and words in e.malformed[0]


def test_a_well_formed_answer_is_not_malformed():
    assert estate.build([estate.Answer("/cluster/resources", {}, RESOURCES)]).malformed == ()
    assert estate.build([estate.Answer("/cluster/resources", {}, [])]).malformed == ()
    assert estate.build([estate.Answer("/pools", {}, {"poolid": "x"})]).malformed       # every list source


PENDING = [{"key": "scsi0", "value": "local-lvm:vm-101-disk-0"},
           {"key": "scsi1", "value": "local-lvm:vm-101-disk-1", "delete": 1},          # detached at next start
           {"key": "scsi2", "pending": "local-lvm:vm-101-disk-2"},                     # attached at next start
           {"key": "scsi3", "value": "local-lvm:vm-101-disk-3", "pending": "local-lvm:vm-101-disk-4"},
           {"key": "memory", "value": 2048, "pending": 4096},
           {"key": "name", "value": "web"}, {"key": "bootdisk", "value": "scsi0"}]


def test_the_pending_read_is_two_views():
    current, after = estate.views_from_pending(PENDING)
    assert current == {"scsi0": "local-lvm:vm-101-disk-0", "scsi1": "local-lvm:vm-101-disk-1",
                       "scsi3": "local-lvm:vm-101-disk-3", "memory": 2048, "name": "web", "bootdisk": "scsi0"}
    assert after == {"scsi0": "local-lvm:vm-101-disk-0", "scsi2": "local-lvm:vm-101-disk-2",
                     "scsi3": "local-lvm:vm-101-disk-4", "memory": 4096, "name": "web", "bootdisk": "scsi0"}
    assert estate.views_from_pending({"scsi0": "x"}) is None


def test_a_guest_read_through_pending_has_the_disks_of_both_views():
    """In use now (value, even marked for delete) or at the next start (pending): every one counts."""
    e = estate.build([estate.Answer("/cluster/resources", {}, RESOURCES),
                      estate.Answer("/nodes/{node}/qemu/{vmid}/pending", {"node": "pve1", "vmid": "101"}, PENDING),
                      estate.Answer("/nodes/{node}/lxc/{vmid}/pending", {"node": "pve2", "vmid": "105"},
                                    [{"key": "rootfs", "value": "local-lvm:vm-105-disk-0"}, {"key": "hostname",
                                                                                            "value": "dns"}])])
    assert [(d.slot, d.volid) for d in e.disks_of("qemu/101")] == [
        ("scsi0", "local-lvm:vm-101-disk-0"), ("scsi1", "local-lvm:vm-101-disk-1"),
        ("scsi2", "local-lvm:vm-101-disk-2"), ("scsi3", "local-lvm:vm-101-disk-3"),
        ("scsi3", "local-lvm:vm-101-disk-4")]
    assert e.guest("qemu/101").boot == "scsi0" and e.unread == frozenset() and e.malformed == ()


def test_a_guest_name_the_resources_read_lacks_comes_from_its_config():
    e = estate.build([estate.Answer("/cluster/resources", {}, [{"type": "lxc", "vmid": 105, "node": "pve2"}]),
                      estate.Answer("/nodes/{node}/lxc/{vmid}/pending", {"node": "pve2", "vmid": "105"},
                                    [{"key": "rootfs", "value": "local-lvm:vm-105-disk-0"},
                                     {"key": "hostname", "value": "dns"}])])
    assert e.guest("lxc/105").name == "dns"


@pytest.mark.parametrize("rows,unread,malformed", [
    ([], True, False), ({"scsi0": "x"}, True, True), ([{"value": "x"}], True, True), (["x"], True, True),
])
def test_a_pending_answer_that_says_nothing_is_unread(rows, unread, malformed):
    e = estate.build([estate.Answer("/nodes/{node}/qemu/{vmid}/pending", {"node": "pve1", "vmid": "101"}, rows)])
    assert (e.unread == frozenset({"qemu/101"})) is unread and bool(e.malformed) is malformed


@pytest.mark.parametrize("volid,value,hit", [
    ("local-zfs:vm-101-disk-0", "local-zfs:base-100-disk-0/vm-101-disk-0,size=8G", True),
    ("local-zfs:base-100-disk-0", "local-zfs:base-100-disk-0/vm-101-disk-0", True),
    ("local:101/vm-101-disk-0.qcow2", "local:100/base-100-disk-0.qcow2/101/vm-101-disk-0.qcow2", True),
    ("local:100/base-100-disk-0.qcow2", "local:100/base-100-disk-0.qcow2/101/vm-101-disk-0.qcow2", True),
    ("local-lvm:vm-101-disk-0", "local-lvm:vm-101-disk-00", False),
    ("local-lvm:vm-101-disk-0", "nas:vm-101-disk-0", False),
    ("local:iso/x.iso", "local:iso/x.iso,media=cdrom", False),
])
def test_a_volume_is_matched_by_its_name_components_on_its_storage(volid, value, hit):
    e = _estate(qemu_101={"scsi0": value})
    assert bool(e.disks_using(volid)) is hit


# --- lens 2: what a token holds, and a pending answer that cannot say which disk -------------------------

@pytest.mark.parametrize("perms,held", [
    ({"/vms": {"VM.Audit": 1}}, True), ({"/": {"VM.Audit": 1}}, True), ({"/vms": {"VM.Audit": True}}, True),
    ({"/": {"VM.Audit": 1}, "/vms/105": {"VM.Audit": 0}}, True),        # a per-guest key that holds it
    ({"/": {"VM.Audit": 1}, "/vms/105": {"VM.Audit": 1}, "/pool/p": {"VM.Audit": 1, "Datastore.Audit": 1}}, True),
    ({"/vms": {"VM.Audit": 1}, "/pool": {"VM.Audit": 1}, "/pool/p": {"VM.Audit": 1}}, True),
    # A pool ACL is how PVE scopes a guest by membership, and the map does not say who is in the
    # pool: a pool path defined without VM.Audit may be the path that hides a member, so it is blind.
    ({"/": {"VM.Audit": 1}, "/vms/105": {"VM.Audit": 1}, "/pool/p": {"Datastore.Audit": 1}}, False),
    ({"/vms": {"VM.Audit": 1}, "/pool/p": {}}, False),
    ({"/vms": {"VM.Audit": 1}, "/pool": {"Sys.Audit": 1}}, False),
    ({"/vms": {"VM.Audit": 1}, "/poolx": {}}, True),                     # not a pool path
    ({"/vms": {"VM.Audit": 0}}, False), ({"/vms/101": {"VM.Audit": 1}}, False), ({"/vms": {}}, False),
    ({"/": {"VM.Audit": 0}}, False), ({"/vm": {"VM.Audit": 1}}, False),
    ({"/": {"VM.Audit": 1}, "/vms": {}}, False),                        # a NoAccess on /vms decides alone
    ({"/": {"VM.Audit": 1}, "/vms": {"VM.Audit": 0}}, False),
    ({"/vms": {"VM.Audit": 1}, "/vms/105": {}}, False),                 # a NoAccess on one guest hides it
    ({"/vms": {"VM.Audit": 1}, "/vms/105": {"Sys.Audit": 1}}, False),
])
def test_vm_audit_reaches_every_guest_only_by_the_most_specific_defined_path(perms, held):
    e = estate.build([estate.Answer("/access/permissions", {}, perms)])
    assert e.sees_every("VM.Audit", "/vms") is held and e.malformed == ()


@pytest.mark.parametrize("perms", [{}, [], "x", {"/vms": {"VM.Audit": 2}}, {"/vms": ["VM.Audit"]},
                                   {"/vms": {"VM.Audit": None}}])
def test_an_answer_that_is_no_permission_map_is_not_read(perms):
    """A null flag included: the vendor writes 1 or 0, so a null is not its map."""
    e = estate.build([estate.Answer("/access/permissions", {}, perms)])
    assert e.sees_every("VM.Audit", "/vms") is None and e.malformed
    assert estate.Estate().sees_every("VM.Audit", "/vms") is None            # not read at all


def test_a_repeated_pending_key_and_a_disk_value_that_is_no_volume_are_malformed():
    e = estate.build([estate.Answer("/nodes/{node}/qemu/{vmid}/pending", {"node": "pve1", "vmid": "101"},
                                    [{"key": "scsi0", "value": "local-lvm:vm-101-disk-0"},
                                     {"key": "scsi0", "value": "local-lvm:vm-101-disk-9"},
                                     {"key": "scsi1", "value": 5}, {"key": "memory", "value": 2048}])])
    assert any("repeats the key scsi0" in m for m in e.malformed)
    assert any("scsi1 is a disk key whose value is int" in m for m in e.malformed)
    assert not any("memory" in m for m in e.malformed)                  # a number is fine off a disk key


def test_realistic_lxc_pending_rows_are_not_malformed():
    rows = [{"key": "arch", "value": "amd64"}, {"key": "digest", "value": "0f3a" * 10},
            {"key": "lock", "value": "backup"}, {"key": "cores", "value": 2},
            {"key": "rootfs", "value": "local-lvm:vm-105-disk-0,size=8G"},
            {"key": "mp0", "value": "local-lvm:vm-105-disk-1,mp=/mnt/data,backup=1,size=32G"},
            {"key": "mp1", "pending": "/mnt/host,mp=/mnt/bind"},
            {"key": "unused0", "value": "local-lvm:vm-105-disk-2", "delete": 1},
            {"key": "net0", "value": "name=eth0,bridge=vmbr0,ip=dhcp"}]
    e = estate.build([estate.Answer("/nodes/{node}/lxc/{vmid}/pending", {"node": "pve2", "vmid": "105"}, rows)])
    assert e.malformed == () and not e.unread
    assert {d.slot for d in e.disks} == {"rootfs", "mp0", "mp1", "unused0"}


def test_a_null_pending_on_a_disk_key_is_malformed():
    """`{"key": "scsi1", "value": ..., "pending": null}`: the vendor writes a pending value or leaves
    the key out, so a null is not its row; the current view still keeps the disk."""
    rows = [{"key": "scsi1", "value": "local-lvm:vm-101-disk-1", "pending": None}]
    e = estate.build([estate.Answer("/nodes/{node}/qemu/{vmid}/pending", {"node": "pve1", "vmid": "101"}, rows)])
    assert e.malformed and [d.slot for d in e.disks] == ["scsi1"]


# --- the relations, named once (memory keeps them as edges; a judge asks the methods) ---------------

def test_the_edges_are_the_relations_the_judges_ask():
    est = estate.build([
        estate.Answer("/cluster/resources", {}, [
            {"type": "lxc", "vmid": 105, "node": "pve1", "status": "running"},
            {"type": "qemu", "vmid": 100, "node": "pve1", "status": "stopped", "pool": "core"}]),
        estate.Answer("/nodes/{node}/lxc/{vmid}/pending", {"node": "pve1", "vmid": "105"},
                      [{"key": "rootfs", "value": "local:105/vm-105-disk-0.raw"},
                       {"key": "net0", "value": "name=eth0,bridge=vmbr0"}]),
        estate.Answer("/nodes/{node}/qemu/{vmid}/pending", {"node": "pve1", "vmid": "100"},
                      [{"key": "scsi0", "value": "nas:100/vm-100-disk-0.qcow2"},
                       {"key": "ide2", "value": "local:iso/x.iso,media=cdrom"}]),
        estate.Answer("/cluster/backup", {}, [{"id": "nightly", "vmid": "105"}]),
        estate.Answer("/nodes/{node}/storage/{storage}/content", {"node": "pve1", "storage": "nas"},
                      [{"volid": "nas:backup/vzdump-lxc-105-x.tar.zst", "content": "backup", "vmid": 105}]),
        estate.Answer("/access/acl", {}, [{"path": "/vms/105", "type": "user", "ugid": "ops@pve",
                                           "roleid": "PVEVMUser", "propagate": 1}]),
    ])
    edges = set(est.edges())
    assert {e.rel for e in edges} <= set(estate.RELATIONS)
    assert edges == {
        estate.Edge("lxc/105", "runs_on", "node/pve1"), estate.Edge("qemu/100", "runs_on", "node/pve1"),
        estate.Edge("lxc/105", "disk_on", "storage/local"), estate.Edge("qemu/100", "disk_on", "storage/nas"),
        estate.Edge("lxc/105", "nic_on", "bridge/vmbr0"), estate.Edge("qemu/100", "in_pool", "pool/core"),
        estate.Edge("lxc/105", "covered_by", "job/nightly"),
        estate.Edge("volume/nas:backup/vzdump-lxc-105-x.tar.zst", "backup_of", "lxc/105"),
        estate.Edge("user/ops@pve", "granted_on", "path/vms/105"),
    }
    for s in ("local", "nas"):     # the same answer either way: an edge IS the method's relation
        assert {e.src for e in edges if e.rel == "disk_on" and e.dst == f"storage/{s}"} == \
            {g.key for g in est.guests_on_storage(s)}
    (acl,) = est.acls
    assert (acl.path, acl.type, acl.ugid, acl.role, acl.propagate) == ("/vms/105", "user", "ops@pve", "PVEVMUser", True)
