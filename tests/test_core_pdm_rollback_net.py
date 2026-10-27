"""A rollback takes a safety snapshot first, waited, and is not run when the snapshot does not land
(capabilities `pdm-rollback-safety-snapshot`, and the direct rollbacks John added, 2026-10-25).

0.44's `_pdm_auto_undo` did it for `pdm_pve_{qemu,lxc}_snapshot_rollback`: a rollback discards
everything since the snapshot, and the vendor publishes no read of a guest to capture, so the only
net is another snapshot. The core's net (`engine._snapshot_first`) existed for the shell lane's
rows, where the CALLER asks for it (`snapshot=true`); this one is not asked for. `records/undo.toml`
[net] names the four rollbacks (the datacenter manager's two and the node's two), the build
derives the snapshot and the rollback from the address, and the engine does the rest through
`execute`: the snapshot is a governed mutation of its own (armed, tiered, receipted, waited),
riding the rollback's consent.

Who can turn it off: only the OPERATOR, by `PROXIMO_UNDO=off`, which turns off every net and which
the plan and the receipt both say. No argument a caller or a model passes can skip it.

The net is STORAGE-AWARE (`core/safetynet.py`): on a storage whose plugin refuses to roll back to a
snapshot that is not the most recent (ZFS always, qcow2 volume chains with the flag), the safety
snapshot would BLOCK the rollback it guards, so none is taken, and the plan and the receipt say so
plainly before and after. An unreadable or unsettled storage takes the net (the fail-closed side).
The rollback's target is checked to exist BEFORE any snapshot is taken.
"""
from __future__ import annotations

import json
import os
import re

import httpx
import pytest

from proximo.core import engine, safetynet, spine, undo, wire
from proximo.core.errors import ProximoError

VMID = "100"
UPID = "UPID:pve1:000A1B2C:0D3E4F50:68DA0000:qmsnapshot:100:root@pam!proximo:"
# (id, product, kind, base path template, concrete base)
GUESTS = [
    ("pve-qemu", "pve", "qemu", "/nodes/{node}/qemu/{vmid}", "/nodes/pve1/qemu/100"),
    ("pve-lxc", "pve", "lxc", "/nodes/{node}/lxc/{vmid}", "/nodes/pve1/lxc/100"),
    ("pdm-qemu", "pdm", "qemu", "/pve/remotes/{remote}/qemu/{vmid}", "/pve/remotes/dc1/qemu/100"),
    ("pdm-lxc", "pdm", "lxc", "/pve/remotes/{remote}/lxc/{vmid}", "/pve/remotes/dc1/lxc/100"),
]
IDS = [g[0] for g in GUESTS]
LOCAL = {"scsi0": "local-lvm:vm-100-disk-0,size=8G", "rootfs": "local-lvm:subvol-100-disk-0,size=8G", "cores": 2}
STORAGES = [{"storage": "local-lvm", "type": "lvmthin"}, {"storage": "local", "type": "dir"},
            {"storage": "tank", "type": "zfspool"}, {"storage": "ceph", "type": "rbd"},
            {"storage": "chain", "type": "dir", "snapshot-as-volume-chain": 1},
            {"storage": "bt", "type": "btrfs"}]


SAME = object()      # the snapshot's config is the guest's, unless the test says otherwise (None: unreadable)


class Api:
    """The vendor's HTTP side for a guest with one snapshot called `before`: lists and configs
    answer what the test set, a snapshot or rollback POST answers a task id, the task's status
    answers `exitstatus` (OK unless told otherwise)."""

    posted = 0

    def __init__(self, exitstatus="OK", fail_on=None, config=None, snapcfg=SAME, storages=None, status="running",
                 snaps=("before",), unreadable=()):
        self.exitstatus, self.fail_on, self.calls = exitstatus, fail_on, []
        self.config = dict(LOCAL if config is None else config)
        self.snapcfg = self.config if snapcfg is SAME else snapcfg
        self.storages, self.status, self.snaps = storages, status, list(snaps)
        self.unreadable = tuple(unreadable)

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        if self.fail_on is not None and method == "POST" and path.endswith(self.fail_on):
            # the vendor ANSWERED with an error: a refusal (as httpx raises it), not a lost answer
            req = httpx.Request(method, "https://pve.invalid:8006/api2/json" + path)
            raise httpx.HTTPStatusError("HTTP 500", request=req, response=httpx.Response(500, request=req))
        if getattr(self, "lose_answer_on", None) and method == "POST" and path.endswith(self.lose_answer_on):
            self.posted_unanswered = True
            raise httpx.ReadTimeout("read timed out")            # it may have been sent and acted on
        if method == "POST":
            if path.endswith("/snapshot"):
                self.snaps.append((params or {}).get("snapname"))
            Api.posted += 1                       # a task id is unique, as the vendor's is
            return f"UPID:pve1:{Api.posted:08X}:0D3E4F50:68DA0000:qmsnapshot:100:root@pam!proximo:"
        if any(path.endswith(u) for u in self.unreadable):
            raise RuntimeError("HTTP 403")
        if "/tasks/" in path:
            return {"status": "stopped", "exitstatus": self.exitstatus, "upid": UPID}
        if path.endswith("/snapshot"):
            return [{"name": n} for n in self.snaps] + [{"name": "current"}]
        if path.endswith("/config"):
            if path.startswith("/pve/remotes/") and (params or {}).get("state") != "active":
                raise RuntimeError("HTTP 400")          # PDM's config read REQUIRES `state`
            if (params or {}).get("snapshot"):
                if self.snapcfg is None:
                    raise RuntimeError("HTTP 501")
                return self.snapcfg
            return self.config
        if path == "/storage" or path.endswith("/storage"):
            return STORAGES if self.storages is None else self.storages
        if path.endswith("/status/current") or path.endswith("/status"):
            return {"status": self.status}
        return {}


def _rows() -> list[dict]:
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


@pytest.fixture
def plane(armed_plane, monkeypatch):
    monkeypatch.setattr(spine, "_SLEEP", lambda s: None)

    def make(product):
        if product == "pve":
            return armed_plane
        return wire.Plane(product, f"https://{product}.invalid:8443/api2/json", armed_plane.token_path)
    return make


def _wire(monkeypatch, **kw):
    api = Api(**kw)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: api)
    return api


def _key(product, kind):
    base = "/nodes/{node}/%s/{vmid}" if product == "pve" else "/pve/remotes/{remote}/%s/{vmid}"
    return (product, "POST", base % kind + "/snapshot/{snapname}/rollback")


def _paths(concrete, name="before"):
    return f"{concrete}/snapshot", f"{concrete}/snapshot/{name}/rollback"


def _rollback(plane, product, kind, concrete, **args):
    return engine.execute(engine.table()[_key(product, kind)], args, cfg=plane(product),
                          path=_paths(concrete)[1])


def _posts(api):
    return [p for m, p, _ in api.calls if m == "POST"]


def _plan(plane, product, kind, concrete, **args):
    return engine.plan(engine.table()[_key(product, kind)], args, _paths(concrete)[1], cfg=plane(product))


# --- the record --------------------------------------------------------------------------------

def test_the_four_rollbacks_carry_the_net_and_nothing_else_does_on_the_api_wire():
    t = engine.table()
    for _, product, kind, base, _ in GUESTS:
        tmpl = base + "/snapshot"
        assert dict(t[_key(product, kind)].net) == {"snapshot": f"POST {tmpl}",
                                                    "rollback": f"POST {tmpl}/{{snapname}}/rollback"}
    nets = sorted(k for k, r in t.items() if r.net)
    assert nets == sorted([_key(p, k) for _, p, k, _, _ in GUESTS]
                          + [("pve", "POST", "/nodes/{node}/lxc/{vmid}/exec"),
                             ("pve", "POST", "/nodes/{node}/lxc/{vmid}/psql")])
    for k in (("pdm", "POST", "/pve/remotes/{remote}/qemu/{vmid}/snapshot"),
              ("pdm", "DELETE", "/pve/remotes/{remote}/qemu/{vmid}/snapshot/{snapname}"),
              ("pve", "POST", "/nodes/{node}/qemu/{vmid}/snapshot")):
        assert t[k].net is None


# --- the plan says what the net will do, before approval -----------------------------------------

@pytest.mark.parametrize("gid,product,kind,base,concrete", GUESTS, ids=IDS)
def test_the_plan_says_it_takes_a_snapshot_first_with_no_credential(monkeypatch, gid, product, kind, base, concrete):
    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_TOKEN_PATH", "PROXIMO_PDM_BASE_URL", "PROXIMO_PDM_TOKEN_PATH"):
        monkeypatch.delenv(var, raising=False)
    out = engine.plan(engine.table()[_key(product, kind)], {}, _paths(concrete)[1])
    assert out["also"]["address"] == f"POST {base}/snapshot"
    assert "rollback is not run" in out["also"]["why"] and out["also"]["consent"].startswith("covered")
    assert out["safety_net"]["taken"] is True                       # storage unread: the fail-closed side takes it


@pytest.mark.parametrize("gid,product,kind,base,concrete", GUESTS, ids=IDS)
def test_a_plan_on_a_template_path_still_says_it(gid, product, kind, base, concrete):
    out = engine.plan(engine.table()[_key(product, kind)], {})
    assert out["safety_net"]["taken"] is True and "template" in out["safety_net"]["why"]


# --- the net -----------------------------------------------------------------------------------

@pytest.mark.parametrize("gid,product,kind,base,concrete", GUESTS, ids=IDS)
def test_the_snapshot_lands_first_then_the_rollback_and_the_capture_names_the_way_back(
        plane, monkeypatch, gid, product, kind, base, concrete):
    api = _wire(monkeypatch)
    out = _rollback(plane, product, kind, concrete, start=True)
    snap_path, rollback = _paths(concrete)
    posts = [(p, a) for m, p, a in api.calls if m == "POST"]
    assert [p for p, _ in posts] == [snap_path, rollback]                  # the snapshot, THEN the rollback
    name = posts[0][1]["snapname"]
    assert re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{2,39}", name) and "before a governed" in posts[0][1]["description"]
    assert posts[1][1] == {"start": True}
    status = [i for i, c in enumerate(api.calls) if c[0] == "GET" and "/tasks/" in c[1]]
    assert status and status[0] < api.calls.index(("POST", rollback, {"start": True}))     # waited, then rolled back
    u = out["undo"]
    assert u["captured"] is True and u["snapshot"] == name and len(u["id"]) == 12 and u["running"] is True
    assert u["rollback"] == f"POST {snap_path}/{name}/rollback"
    rows = _rows()
    point = [r for r in rows if r["action"] == "core.undo_point"][-1]
    assert point["detail"]["snapshot"] == name and point["detail"]["plane"] == product
    assert point["detail"]["running"] is True
    last = max(i for i, r in enumerate(rows) if r["action"] == "core.execute" and r["outcome"] == "executing")
    assert rows.index(point) < last                                          # the net is on the chain BEFORE the act
    executing = [r for r in rows if r["action"] == "core.execute" and r["outcome"] == "executing"]
    assert executing[-1]["target"] == rollback and executing[-1]["detail"]["undo"]["snapshot"] == name


def test_the_node_the_caller_named_goes_to_the_snapshot_too(plane, monkeypatch):
    api = _wire(monkeypatch)
    _rollback(plane, "pdm", "qemu", GUESTS[2][4], node="pve1")
    snap = next(a for m, p, a in api.calls if m == "POST" and p == _paths(GUESTS[2][4])[0])
    assert snap["node"] == "pve1"


def test_no_node_named_none_is_invented(plane, monkeypatch):
    api = _wire(monkeypatch)
    _rollback(plane, "pdm", "qemu", GUESTS[2][4])
    snap = next(a for m, p, a in api.calls if m == "POST" and p == _paths(GUESTS[2][4])[0])
    assert "node" not in snap


@pytest.mark.parametrize("kw", [{"exitstatus": "snapshot feature is not available"}, {"fail_on": "/snapshot"}],
                         ids=["task-failed", "post-failed"])
@pytest.mark.parametrize("gid,product,kind,base,concrete", GUESTS, ids=IDS)
def test_a_snapshot_that_does_not_land_refuses_the_rollback_fail_closed_and_names_it(
        plane, monkeypatch, kw, gid, product, kind, base, concrete):
    api = _wire(monkeypatch, **kw)
    with pytest.raises(ProximoError, match="undo unavailable") as caught:
        _rollback(plane, product, kind, concrete)
    assert _paths(concrete)[1] not in _posts(api)                            # the rollback was never dialed
    refuse = [r for r in _rows() if r["action"] == "core.refuse"]
    assert refuse and refuse[-1]["detail"]["needs"] == "undo"
    name = refuse[-1]["detail"]["snapshot"]
    assert name in str(caught.value)                  # the CALLER hears of a snapshot that may be on the guest
    assert not any(r["action"] == "core.execute" and r["target"].endswith("/rollback") for r in _rows())


def test_a_snapshot_task_not_seen_to_finish_refuses_the_rollback(plane, monkeypatch):
    api = _wire(monkeypatch)
    monkeypatch.setattr(engine, "SNAPSHOT_WAIT", 0)
    with pytest.raises(ProximoError, match="undo unavailable"):
        _rollback(plane, "pdm", "qemu", GUESTS[2][4])
    assert _paths(GUESTS[2][4])[1] not in _posts(api)


def test_a_rollback_the_vendor_then_refuses_names_the_snapshot_it_left_to_the_caller(plane, monkeypatch):
    api = _wire(monkeypatch, fail_on="/rollback")
    with pytest.raises(ProximoError, match=r"failed after its safety snapshot (proximo_\w+) was taken") as caught:
        _rollback(plane, "pve", "qemu", GUESTS[0][4])
    name = re.search(r"snapshot (proximo_\w+) was taken", str(caught.value)).group(1)
    assert name in [a["snapname"] for m, p, a in api.calls if m == "POST" and "snapname" in a]
    assert "still on the guest" in str(caught.value)


def test_a_receipt_that_cannot_be_written_after_the_snapshot_names_it(plane, monkeypatch):
    _wire(monkeypatch)
    real = engine._record

    def refusing(cfg, action, *a, **k):
        if action == "core.undo_point" and k.get("detail", {}).get("snapshot"):
            raise OSError("disk full")
        return real(cfg, action, *a, **k)
    monkeypatch.setattr(engine, "_record", refusing)
    with pytest.raises(ProximoError, match=r"safety snapshot proximo_\w+ landed.*still on the guest"):
        _rollback(plane, "pve", "qemu", GUESTS[0][4])


# --- who can turn it off: the operator, by config, and nobody else ----------------------------------

@pytest.mark.parametrize("gid,product,kind,base,concrete", GUESTS, ids=IDS)
def test_the_operators_opt_out_is_honoured_and_the_plan_and_the_receipt_say_so(
        plane, monkeypatch, gid, product, kind, base, concrete):
    monkeypatch.setenv("PROXIMO_UNDO", "off")
    api = _wire(monkeypatch)
    planned = _plan(plane, product, kind, concrete)
    assert planned["safety_net"]["taken"] is False and "PROXIMO_UNDO=off" in planned["safety_net"]["why"]
    assert "also" not in planned                            # E18: with undo off the plan does not announce a snapshot
    out = _rollback(plane, product, kind, concrete)
    assert _posts(api) == [_paths(concrete)[1]]
    assert out["undo"]["captured"] is False and "PROXIMO_UNDO" in out["undo"]["why"]
    executing = [r for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "executing"]
    assert "PROXIMO_UNDO" in executing[-1]["detail"]["undo"]["why"]


@pytest.mark.parametrize("name", ["snapshot", "undo", "net", "safety_net", "no_snapshot", "skip_snapshot",
                                  "skip_undo", "force", "confirm", "dry_run", "safety", "captured", "take_snapshot",
                                  "snapshot=false", "PROXIMO_UNDO"])
@pytest.mark.parametrize("gid,product,kind,base,concrete", GUESTS, ids=IDS)
def test_no_argument_can_skip_the_net(plane, monkeypatch, name, gid, product, kind, base, concrete):
    """The rollback publishes `start` (and the node and path) and nothing else; anything else is
    refused before the wire, so there is no word a caller or a model can pass to opt out."""
    api = _wire(monkeypatch)
    for value in (False, 0, "0", "false", "off", None):
        with pytest.raises(ProximoError, match="does not publish"):
            _rollback(plane, product, kind, concrete, **{name: value})
    assert api.calls == []


@pytest.mark.parametrize("gid,product,kind,base,concrete", GUESTS, ids=IDS)
def test_the_published_arguments_of_a_rollback_name_no_switch_for_the_net(gid, product, kind, base, concrete):
    row = engine.table()[_key(product, kind)]
    assert set(row.params) <= {"start", "node", "remote", "vmid", "snapname"}
    assert "snapshot" not in row.params


# --- storage-aware ------------------------------------------------------------------------------

def test_the_storage_effects_are_the_pve_storage_sources():
    e = safetynet.blocks
    assert e("zfspool", None, True) is True and e("zfs", 0, True) is True           # ZFSPlugin inherits ZFSPoolPlugin
    assert [e(t, None, True) for t in ("dir", "nfs", "cifs", "glusterfs", "cephfs", "lvm")] == [False] * 6
    assert [e(t, 1, True) for t in ("dir", "nfs", "cifs", "glusterfs", "cephfs", "lvm")] == [True] * 6
    assert e("dir", "0", True) is False and e("dir", "1", True) is True and e("dir", True, True) is True
    assert e("lvmthin", 1, True) is False and e("btrfs", 1, True) is False
    assert e("rbd", None, True) is False and e("rbd", 1, True) is False     # RBDPlugin cannot carry the chain flag
    assert e("iscsi", None, True) is None and e(None, None, True) is None
    # the datacenter manager's node storage list is a status list: the flag is never there
    assert [e(t, None, False) for t in ("dir", "nfs", "cifs", "glusterfs", "cephfs", "lvm")] == [None] * 6
    assert e("zfspool", None, False) is True and e("lvmthin", None, False) is False and e("rbd", None, False) is False


def test_which_volumes_can_be_snapshotted_at_all():
    c = safetynet.can_snapshot
    assert [c(t, "vm-1-disk-0") for t in ("zfspool", "zfs", "lvmthin", "btrfs", "rbd")] == [True] * 5
    assert c("dir", "100/vm-100-disk-0.qcow2") is True and c("dir", "100/vm-100-disk-0.qed") is False
    assert c("dir", "100/vm-100-disk-0.raw") is False and c("nfs", "100/vm-100-disk-0.vmdk") is False
    assert c("dir", "100/subvol-100-disk-0.subvol") is False
    assert c("lvm", "vm-100-disk-0.qcow2") is True and c("lvm", "vm-100-disk-0") is False
    assert c("iscsi", "x") is None and c(None, "x") is None


def test_the_volumes_of_a_config_are_the_ones_pve_iterates_for_a_snapshot():
    cfg = {"scsi0": "tank:vm-100-disk-0,size=8G", "efidisk0": "local-lvm:vm-1-d", "tpmstate0": "local-lvm:vm-1-t",
           "rootfs": "tank2:subvol-1-disk-0", "mp0": "/srv/data,mp=/data", "mp1": "tank4:subvol-1-disk-1,mp=/x",
           "net0": "virtio,bridge=vmbr0", "hostpci0": "0000:01:00.0", "name": "web:1",
           "vmstate": "tank3:state", "unused0": "local:100/vm-100-disk-1.qcow2", "ide2": "local:iso/x.iso,media=cdrom",
           "sata0": "none"}
    vols, unread = safetynet.volumes_of(cfg)
    assert sorted(vols) == [("local-lvm", "vm-1-d"), ("local-lvm", "vm-1-t"), ("tank", "vm-100-disk-0"),
                            ("tank2", "subvol-1-disk-0"), ("tank4", "subvol-1-disk-1")]
    assert unread == 1                                       # the bind mount names no storage: counted, not guessed
    # NOT a volume for a snapshot: vmstate, unused0, the CD-ROM and `none`
    assert safetynet.storages_of(cfg) == {"tank", "local-lvm", "tank2", "tank4"}
    assert safetynet.volumes_of(None) == ([], 0) and safetynet.volumes_of([]) == ([], 0)


def test_a_cdrom_is_no_volume_and_no_reason_to_drop_the_net(plane, monkeypatch):
    cfg = {"scsi0": "local-lvm:vm-100-disk-0", "ide2": "tank:iso/x.iso,media=cdrom"}
    api = _wire(monkeypatch, config=cfg)
    out = _rollback(plane, "pve", "qemu", GUESTS[0][4])
    assert out["undo"]["captured"] is True and _paths(GUESTS[0][4])[0] in _posts(api)


@pytest.mark.parametrize("gid,product,kind,base,concrete", [GUESTS[0], GUESTS[1]], ids=["pve-qemu", "pve-lxc"])
@pytest.mark.parametrize("volume,takes", [
    ("local-lvm:vm-100-disk-0", True),       # thin LVM never blocks
    ("local:100/vm-100-disk-0.qcow2", True),  # a directory without the chain flag does not block
    ("bt:100/vm-100-disk-0", True),          # btrfs never blocks
    ("tank:vm-100-disk-0", False),           # ZFS blocks
    ("chain:100/vm-100-disk-0.qcow2", False),  # a directory WITH snapshot-as-volume-chain blocks
    ("ceph:vm-100-disk-0", True),            # RBD cannot carry the flag and never blocks
    ("local:100/vm-100-disk-0.raw", False),  # a raw image on a directory cannot be snapshotted at all
])
def test_the_net_is_not_taken_where_the_storage_would_block_the_rollback(
        plane, monkeypatch, gid, product, kind, base, concrete, volume, takes):
    api = _wire(monkeypatch, config={"scsi0": volume, "rootfs": volume})
    planned = _plan(plane, product, kind, concrete)
    out = _rollback(plane, product, kind, concrete)
    assert planned["safety_net"]["taken"] is takes and ("also" in planned) is takes
    assert (_paths(concrete)[0] in _posts(api)) is takes
    assert _paths(concrete)[1] in _posts(api)                          # the rollback runs either way
    assert out["undo"]["captured"] is takes
    if not takes:
        said = planned["safety_net"]["why"]
        assert ("a safety snapshot would block the rollback, so none is taken" in said
                or "no safety snapshot is possible on this guest, so none is taken" in said)
        assert "take a backup first if you need a way back" in said
        assert out["undo"]["skipped"] == "storage" and out["undo"]["why"] == said
        executing = [r for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "executing"]
        assert executing[-1]["detail"]["undo"]["skipped"] == "storage"          # and the receipt says it


@pytest.mark.parametrize("current,kind", [
    ({"scsi0": "local-lvm:vm-100-disk-0", "scsi1": "local:100/vm-100-disk-1.raw"}, "dir"),  # raw on a dir
    ({"scsi0": "local-lvm:vm-100-disk-0", "scsi1": "local:100/vm-100-disk-1.vmdk"}, "dir"),
    ({"scsi0": "local-lvm:vm-100-disk-0", "scsi1": "thick:vm-100-disk-1"}, "lvm"),         # thick LVM, no chain
])
def test_where_the_safety_snapshot_itself_cannot_be_taken_none_is_tried_and_the_plan_says_so(
        plane, monkeypatch, current, kind):
    """A disk added after the snapshot (so not in the snapshot's config, and no reason for the
    rollback to refuse) can still make the SAFETY snapshot die; the plan never promises it."""
    api = _wire(monkeypatch, config=current, snapcfg={"scsi0": "local-lvm:vm-100-disk-0"},
                storages=STORAGES + [{"storage": "thick", "type": "lvm"}])
    planned = _plan(plane, "pve", "qemu", GUESTS[0][4])
    said = planned["safety_net"]["why"]
    assert planned["safety_net"]["taken"] is False and "also" not in planned
    assert "no safety snapshot is possible on this guest, so none is taken" in said
    assert "take a backup first if you need a way back" in said
    assert kind in said                                          # by storage TYPE ...
    for guest_text in ("vm-100", "local", "thick"):               # ... never by the guest's own names
        assert guest_text not in said.replace("local-lvm", "")
    out = _rollback(plane, "pve", "qemu", GUESTS[0][4])
    assert out["undo"]["captured"] is False and out["undo"]["skipped"] == "storage" and out["undo"]["why"] == said
    assert _paths(GUESTS[0][4])[0] not in _posts(api) and _paths(GUESTS[0][4])[1] in _posts(api)


def test_a_snapshot_possible_current_config_with_a_qcow2_chain_volume_is_netted(plane, monkeypatch):
    api = _wire(monkeypatch, config={"scsi0": "local:100/vm-100-disk-0.qcow2"})
    assert _rollback(plane, "pve", "qemu", GUESTS[0][4])["undo"]["captured"] is True
    assert _paths(GUESTS[0][4])[0] in _posts(api)


def test_a_vmstate_on_a_blocking_storage_does_not_drop_the_net(plane, monkeypatch):
    """pve-guest-common checks the snapshot's DRIVES for a rollback; the vmstate is handled apart
    (`__snapshot_rollback_vm_start`), so a vmstate on ZFS cannot make the rollback refuse."""
    api = _wire(monkeypatch, snapcfg={"vmstate": "tank:vm-100-state-before", "scsi0": "local-lvm:vm-100-disk-0"})
    out = _rollback(plane, "pve", "qemu", GUESTS[0][4])
    assert out["undo"]["captured"] is True and _paths(GUESTS[0][4])[0] in _posts(api)


def test_any_one_blocking_volume_of_the_snapshot_is_enough(plane, monkeypatch):
    api = _wire(monkeypatch, config={"scsi0": "local-lvm:vm-100-disk-0", "scsi1": "tank:vm-100-disk-1"})
    assert _rollback(plane, "pve", "qemu", GUESTS[0][4])["undo"]["captured"] is False
    assert _paths(GUESTS[0][4])[0] not in _posts(api)


@pytest.mark.parametrize("kw,what", [
    ({"config": {"scsi0": "san:vm-100-disk-0"}, "storages": [{"storage": "san", "type": "iscsi"}]}, "iscsi"),
    ({"config": {"scsi0": "mystery:vm-100-disk-0"}}, "unknown"),         # a storage no definition names
    ({"snapcfg": None}, "the snapshot's own config could not be read"),   # never a silent ignore
    ({"unreadable": ("/config",)}, "the guest's config could not be read"),
    ({"unreadable": ("/storage",), "config": {"scsi0": "tank:vm-1-d"}}, "unknown"),   # definitions unread: even ZFS
])
def test_what_is_not_settled_takes_the_net_and_says_so(plane, monkeypatch, kw, what):
    api = _wire(monkeypatch, **kw)
    planned = _plan(plane, "pve", "qemu", GUESTS[0][4])
    assert planned["safety_net"]["taken"] is True and what in planned["safety_net"]["unsettled"]
    assert "storage not settled" in planned["safety_net"]["why"]
    out = _rollback(plane, "pve", "qemu", GUESTS[0][4])
    assert out["undo"]["captured"] is True and out["undo"]["note"] == planned["safety_net"]["why"]
    assert _paths(GUESTS[0][4])[0] in _posts(api)


def test_pdm_publishes_no_storage_definition_without_a_node_so_it_is_unsettled_and_taken(plane, monkeypatch):
    _wire(monkeypatch, config={"scsi0": "tank:vm-100-disk-0"})
    planned = _plan(plane, "pdm", "qemu", GUESTS[2][4])
    assert planned["safety_net"]["taken"] is True and planned["safety_net"]["unsettled"] == ["unknown"]


def test_pdm_with_the_node_reads_its_storage_list_and_a_zfs_guest_takes_no_net(plane, monkeypatch):
    api = _wire(monkeypatch, config={"scsi0": "tank:vm-100-disk-0"})
    out = _rollback(plane, "pdm", "qemu", GUESTS[2][4], node="pve1")
    assert out["undo"]["captured"] is False and out["undo"]["skipped"] == "storage"
    assert any(p == "/pve/remotes/dc1/nodes/pve1/storage" for m, p, _ in api.calls)
    assert _paths(GUESTS[2][4])[1] in _posts(api) and _paths(GUESTS[2][4])[0] not in _posts(api)


def test_the_storage_reads_go_through_execute_and_are_receipted(plane, monkeypatch):
    _wire(monkeypatch)
    _rollback(plane, "pve", "qemu", GUESTS[0][4])
    read_targets = {r["target"] for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "ok"
                    and r["target"].startswith(("/storage", "/nodes/pve1/qemu/100/config"))}
    assert {"/storage", "/nodes/pve1/qemu/100/config"} <= read_targets


# --- the target exists, or nothing is taken ---------------------------------------------------------

@pytest.mark.parametrize("gid,product,kind,base,concrete", GUESTS, ids=IDS)
def test_a_rollback_to_a_snapshot_that_is_not_there_takes_no_snapshot_and_refuses(
        plane, monkeypatch, gid, product, kind, base, concrete):
    api = _wire(monkeypatch, snaps=("other",))
    planned = _plan(plane, product, kind, concrete)
    assert planned["safety_net"]["taken"] is False and "not on this guest" in planned["safety_net"]["why"]
    assert "also" not in planned
    with pytest.raises(ProximoError, match="not on this guest"):
        _rollback(plane, product, kind, concrete)
    assert _posts(api) == []                                   # not a snapshot, not a rollback
    refuse = [r for r in _rows() if r["action"] == "core.refuse"]
    assert refuse and refuse[-1]["detail"]["needs"] == "arguments"


def test_a_target_that_cannot_be_confirmed_takes_no_snapshot_and_refuses(plane, monkeypatch):
    api = _wire(monkeypatch, unreadable=("/snapshot",))
    with pytest.raises(ProximoError, match="could not confirm"):
        _rollback(plane, "pve", "qemu", GUESTS[0][4])
    assert _posts(api) == []
    assert _rows()[-1]["detail"]["needs"] == "undo"


def test_the_target_is_checked_before_the_snapshot_is_taken(plane, monkeypatch):
    api = _wire(monkeypatch)
    _rollback(plane, "pve", "qemu", GUESTS[0][4])
    first_list = next(i for i, c in enumerate(api.calls) if c[0] == "GET" and c[1].endswith("/snapshot"))
    first_post = next(i for i, c in enumerate(api.calls) if c[0] == "POST")
    assert first_list < first_post


# --- consent and the other gates ----------------------------------------------------------------

def test_under_enforced_consent_one_grant_for_the_rollback_covers_its_snapshot(plane, monkeypatch, tmp_path):
    g = tmp_path / "grants"
    g.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(g))
    api = _wire(monkeypatch)
    concrete = GUESTS[2][4]
    cid = _plan(plane, "pdm", "qemu", concrete)["consent_id"]
    (g / os.path.basename(spine.grant_path(cid))).touch()
    out = _rollback(plane, "pdm", "qemu", concrete)
    assert out["undo"]["captured"] is True and _paths(concrete)[1] in _posts(api)
    assert list(g.iterdir()) == []                                           # the ONE grant, spent once
    snap = [r for r in _rows() if r["outcome"] == "executing" and r["target"] == _paths(concrete)[0]]
    assert snap and snap[0]["detail"]["consent_of"] == {"command": _paths(concrete)[1], "consent_id": cid}


def test_under_enforced_consent_no_grant_means_no_snapshot_and_no_rollback(plane, monkeypatch, tmp_path):
    g = tmp_path / "grants"
    g.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(g))
    api = _wire(monkeypatch)
    with pytest.raises(ProximoError, match="consent"):
        _rollback(plane, "pdm", "qemu", GUESTS[2][4])
    assert _posts(api) == []                              # the net's READS happened; nothing was written


def test_a_refused_rollback_shows_the_operator_the_plan_the_id_binds_net_included(plane, monkeypatch, tmp_path, capsys):
    """The plan's consent id carries the net it said; the refusal's proposal keeps that net, so
    `consent show` reproduces the id the operator was handed."""
    from proximo.core.doors import cli
    g = tmp_path / "grants"
    g.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(g))
    _wire(monkeypatch)
    concrete = GUESTS[2][4]
    cid = _plan(plane, "pdm", "qemu", concrete)["consent_id"]
    with pytest.raises(ProximoError, match="consent"):
        _rollback(plane, "pdm", "qemu", concrete)
    assert cli.main(["consent", "show", cid]) == cli.EXIT_OK
    import json
    shown = json.loads(capsys.readouterr().out)
    assert shown["consent_id"] == cid and shown["reproduces_id"] is True and shown["net"]


def test_a_tripped_containment_stops_the_snapshot_as_well_as_the_rollback(plane, monkeypatch, tmp_path):
    trip = tmp_path / "CONTAIN"
    trip.touch()
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))
    api = _wire(monkeypatch)
    with pytest.raises(ProximoError):
        _rollback(plane, "pdm", "qemu", GUESTS[2][4])
    assert api.calls == []


# --- undo by receipt ---------------------------------------------------------------------------

@pytest.mark.parametrize("gid,product,kind,base,concrete", GUESTS, ids=IDS)
def test_undo_by_receipt_rolls_the_guest_back_to_the_safety_snapshot(
        plane, monkeypatch, gid, product, kind, base, concrete):
    api = _wire(monkeypatch)
    out = _rollback(plane, product, kind, concrete)
    ref, name = out["undo"]["id"], out["undo"]["snapshot"]
    way_back = f"{_paths(concrete)[0]}/{name}/rollback"
    planned = undo.restore(ref, cfg=plane(product))
    assert planned["status"] == "plan" and planned["called_path"] == way_back and planned["restores"] == ref
    assert way_back not in _posts(api)                                       # a plan writes nothing
    done = undo.restore(ref, cfg=plane(product), confirm=True)
    assert ("POST", way_back, {"start": True}) in api.calls and done["restores"] == ref


@pytest.mark.parametrize("status,start", [("running", True), ("stopped", None), ("paused", None)])
def test_undo_puts_the_guest_back_to_the_state_it_was_in_not_to_running(plane, monkeypatch, status, start):
    api = _wire(monkeypatch, status=status)
    out = _rollback(plane, "pve", "qemu", GUESTS[0][4])
    assert out["undo"]["running"] is (True if status == "running" else False if status == "stopped" else None)
    undo.restore(out["undo"]["id"], cfg=plane("pve"), confirm=True)
    way_back = f"{_paths(GUESTS[0][4])[0]}/{out['undo']['snapshot']}/rollback"
    sent = next(a for m, p, a in api.calls if m == "POST" and p == way_back)
    assert sent == ({"start": True} if start else {})


def test_undo_keeps_the_callers_node_hint(plane, monkeypatch):
    api = _wire(monkeypatch)
    out = _rollback(plane, "pdm", "qemu", GUESTS[2][4], node="pve1")
    undo.restore(out["undo"]["id"], cfg=plane("pdm"), confirm=True)
    way_back = f"{_paths(GUESTS[2][4])[0]}/{out['undo']['snapshot']}/rollback"
    sent = next(a for m, p, a in api.calls if m == "POST" and p == way_back)
    assert sent == {"start": True, "node": "pve1"}


# --- the build holds the record to the table ----------------------------------------------------

_WHY = "Vendor: a rollback discards what happened since the snapshot and nothing reads it back"


def _real_undo():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import build_proximo_json as bj
    return bj.read_inputs()[1]["undo.toml"]


def _line(addr, body=f'why = "{_WHY}"'):
    return f'"{addr}" = {{ {body} }}\n'


@pytest.mark.parametrize("line,words", [
    (_line("pdm:POST /pve/remotes/{remote}/qemu/{vmid}/snapshot/{snapname}/nowhere"),
     "matches no published address"),
    (_line("pdm:POST /pve/remotes/{remote}/qemu/{vmid}/shutdown"), "is not a snapshot rollback"),
    (_line("pdm:POST /pve/remotes/{remote}/qemu/{vmid}/snapshot"), "is not a snapshot rollback"),
    (_line("pve:POST /nodes/{node}/lxc/{vmid}/exec"), "is not a snapshot rollback"),    # an ssh row has its own net
    (_line("pdm:DELETE /pve/remotes/{remote}/qemu/{vmid}/snapshot/{snapname}"), "is not a snapshot rollback"),
    (_line("pve:POST /nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback", 'why = "short"'), "takes exactly a why"),
    (_line("pve:POST /nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback",
           f'why = "{_WHY}", snapshot = "POST /nodes/{{node}}/lxc/{{vmid}}/snapshot"'), "takes exactly a why"),
])
def test_the_build_refuses_a_net_line_that_would_do_nothing_or_mislead(records, line, words):
    with pytest.raises(ProximoError, match=f"undo.toml: .*{words}"):
        addr = line.split('"')[1]
        kept = "".join(x for x in _real_undo().splitlines(True) if not x.startswith(f'"{addr}"'))
        records(**{"undo.toml": kept + "\n" + line})


def test_the_shipped_net_lines_are_exactly_the_four_rollbacks():
    import tomllib
    lines = tomllib.loads(_real_undo())["net"]
    assert sorted(lines) == sorted(f"{k[0]}:{k[1]} {k[2]}" for k in (_key(p, kd) for _, p, kd, _, _ in GUESTS))
    assert all(len(v["why"].split()) >= 12 and set(v) == {"why"} for v in lines.values())
