"""B2, UNDO restore: the before-state a mutation's receipt captured is written back (2026-10-02).

0.44 restored in three shapes: `guest_config_set` handed back `prior_config` and
`pve_guest_config_revert` wrote it back (digest from the current record, keys added since
deleted, computed keys skipped); `pve_rollback` rolled a guest back to a snapshot; and exec
with `snapshot=true` took a snapshot first and failed closed. The core captured the before-state
on every mutation with a GET twin (`core.undo_point`) and nothing restored from it.

ONE RULE, like PLAN's read: the restore is the PUT the vendor publishes at the same path,
written with the captured record, governed like any call (armed, tiered, consented, receipted,
with its own capture, so an undo is undoable). Nothing is invented where the vendor publishes
no such write; the answer says so. The capture is found by the id every executed mutation
returns under `undo.id` (the receipt row's hash), the chain is verified before the capture is
trusted, and what the receipt withheld (a credential) or the write does not publish is named
as skipped, never written.

The fixtures are two real guest configs read from the estate through Proximo (2026-10-02),
scrubbed to documentation addresses: the keys are what Proxmox sends, not what a test imagined.
"""
from __future__ import annotations

import json
import os

import httpx
import pytest

from proximo.core import engine, spine, undo, wire
from proximo.core.doors import mcp as door
from proximo.core.errors import ProximoError
from proximo.core.ledger import in_flight
from proximo.core.ledger import parse_lines as undo_parse
from test_tiers_harvest import HARVESTED, bj  # the records are built, with their checks, by the build

LXC_PATH = "/nodes/pve1/lxc/1201/config"
QEMU_PATH = "/nodes/pve1/qemu/101/config"
UPID = "UPID:pve1:000A1B2C:0D3E4F50:68DA0000:qmconfig:101:root@pam!proximo:"

# A real LXC config (a CT on the estate), addresses scrubbed. `digest` is the vendor's lock;
# `net0`/`net1` are the indexed spelling the PUT publishes as `net[n]`.
LXC = {
    "arch": "amd64", "cores": 4, "digest": "0123456789abcdef0123456789abcdef01234567",
    "features": "nesting=1", "hostname": "ct-example", "memory": 16384, "nameserver": "192.0.2.53",
    "net0": ("name=eth0,bridge=vmbr0,firewall=1,gw=192.0.2.1,hwaddr=BC:24:11:00:00:01,ip=192.0.2.71/24,"
             "ip6=dhcp,type=veth"),
    "net1": "name=eth1,bridge=vmbr1,hwaddr=BC:24:11:00:00:02,ip=198.51.100.71/24,type=veth",
    "onboot": 1, "ostype": "debian", "rootfs": "local-lvm:vm-1201-disk-0,size=120G", "swap": 8192,
    "tags": "a;b", "unprivileged": 1,
}
# A real QEMU config (a lab VM), scrubbed. `meta` is not a PUT parameter; `smbios1` and
# `vmgenid` are, and are left alone when they did not drift.
QEMU = {
    "boot": "order=scsi0;ide2", "cores": 2, "cpu": "host",
    "digest": "fedcba9876543210fedcba9876543210fedcba98",
    "ide2": "lab:iso/example.iso,media=cdrom,size=1667264K", "memory": "4096",
    "meta": "creation-qemu=11.0.0,ctime=1782581613", "name": "vm-example",
    "net0": "virtio=BC:24:11:00:00:03,bridge=vmbr1", "onboot": 0, "ostype": "l26",
    "scsi0": "lab:101/vm-101-disk-0.raw,size=32G", "scsihw": "virtio-scsi-single",
    "smbios1": "uuid=be962c66-0a59-4fb9-9dcc-97a85125f2a5", "tags": " ",
    "vmgenid": "b73d8e23-ff03-425d-84e9-7d5c949d055d",
}
META_SKIPPED = {"meta": "the write does not publish it"}


class Wire:
    """A wire that answers GET with the record of the moment (records in order; the last
    repeats) and records every mutation. Never dials."""

    def __init__(self, *records, answer=None):
        self.calls: list[tuple[str, str, dict]] = []
        self.records = list(records)
        self.answer = answer

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        if method == "GET":
            return self.records.pop(0) if len(self.records) > 1 else self.records[0]
        return self.answer

    def mutations(self):
        return [(m, p, a) for m, p, a in self.calls if m != "GET"]


def _rows() -> list[dict]:
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def _tiered(product, method, path, tier="restorable"):
    row = engine.resolve(product, method, path)
    return engine.Row(**{**row.__dict__, "tier": tier})


def _wire(monkeypatch, *records, answer=None):
    w = Wire(*records, answer=answer)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    return w


def _mutate(box, monkeypatch, path, args, record, kind="qemu"):
    """One governed config write whose receipt captures `record`; returns its answer."""
    _wire(monkeypatch, record)
    return engine.execute(_tiered("pve", "PUT", f"/nodes/{{node}}/{kind}/{{vmid}}/config"), args, cfg=box, path=path)


def _pbs(box):
    return wire.Plane("pbs", "https://pbs.invalid:8007/api2/json", box.token_path)


def _no_sleep(monkeypatch):
    now = [0.0]

    def sleep(s):
        now[0] += s
    monkeypatch.setattr(spine, "_SLEEP", sleep)
    monkeypatch.setattr(spine, "_CLOCK", lambda: now[0])


@pytest.fixture
def box(armed_plane):
    return armed_plane


# --- the id: every executed mutation says which receipt holds its before-state ------------------

def test_an_executed_mutation_returns_the_id_of_its_capture_and_the_row_names_the_plane(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    point = [r for r in _rows() if r["action"] == "core.undo_point"][-1]
    assert out["undo"] == {"captured": True, "read": "GET /nodes/{node}/qemu/{vmid}/config",
                           "id": point["entry_hash"][:12]}
    assert point["detail"]["plane"] == "pve" and point["target"] == QEMU_PATH


def test_audit_entries_rows_carry_the_id_so_a_capture_is_findable_without_the_file(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    rows = door.audit_entries(action="core.undo_point")["entries"]
    assert rows[0]["id"] == out["undo"]["id"]


# --- the plan: what goes back, from what, read now ------------------------------------------------

def test_a_restore_plans_the_put_that_writes_the_capture_back_with_the_current_digest(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    drifted = {**QEMU, "memory": "8192", "digest": "1111111111111111111111111111111111111111"}
    w = _wire(monkeypatch, drifted)
    plan = undo.restore(out["undo"]["id"], cfg=box)
    assert plan["status"] == "plan" and plan["restores"] == out["undo"]["id"]
    assert w.calls == [("GET", QEMU_PATH, {})] and w.mutations() == []      # read now; nothing written
    assert plan["address"] == "PUT /nodes/{node}/qemu/{vmid}/config" and plan["allowed"] is True
    assert plan["arguments"] == {"memory": "4096", "digest": drifted["digest"]}   # the lock is the CURRENT one
    assert plan["change"] == {"memory": {"from": "8192", "to": "4096"}} and plan["noop"] is False
    assert plan["skipped"] == META_SKIPPED and plan["captured"] == _rows()[0]["ts"]


def test_a_restore_reads_a_record_bigger_than_the_answer_cap_to_diff_it(box, monkeypatch):
    """The door reads the record to compute the change back, under the evaluation cap; only what it SHOWS
    is capped (a 3 KB note is over the 1.125 KiB answer cap and must not be 'over the door's cap now')."""
    big = {**QEMU, "notes": "n" * 3000}
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, big)
    drifted = {**big, "memory": "8192", "digest": "1111111111111111111111111111111111111111"}
    _wire(monkeypatch, drifted)
    plan = undo.restore(out["undo"]["id"], cfg=box)
    assert plan["status"] == "plan" and plan["arguments"]["memory"] == "4096"
    assert len(json.dumps(plan, separators=(",", ":"))) <= 2000


def test_a_restore_writes_only_what_drifted_deletes_what_was_added_and_is_itself_captured(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192", "description": "x"}, QEMU)
    drifted = {**QEMU, "memory": "8192", "description": "x", "digest": "2222222222222222222222222222222222222222"}
    w = _wire(monkeypatch, drifted)
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.mutations() == [("PUT", QEMU_PATH, {"memory": "4096", "delete": "description",
                                                  "digest": drifted["digest"]})]
    assert done["restored"] == ["memory"] and done["deleted"] == ["description"] and done["skipped"] == META_SKIPPED
    assert done["restores"] == out["undo"]["id"] and done["undo"]["captured"] is True
    rows = [r for r in _rows() if r["mutation"] and r["action"] in ("core.undo_point", "core.execute")]
    assert [r["outcome"] for r in rows] == ["undo_point", "executing", "ok", "undo_point", "executing", "ok"]
    # the ledger links them, under the capture's RESOLVED hash (whatever spelling the caller typed)
    assert rows[4]["detail"]["restores"] == rows[5]["detail"]["restores"] == rows[0]["entry_hash"]
    assert rows[0]["entry_hash"].startswith(out["undo"]["id"])
    assert rows[3]["detail"]["before"] == drifted                                                # an undo is undoable
    assert in_flight(_rows()) == []


def test_indexed_keys_restore_by_their_numbered_spelling(box, monkeypatch):
    out = _mutate(box, monkeypatch, LXC_PATH, {"net1": "name=eth1,bridge=vmbr9,type=veth"}, LXC, kind="lxc")
    w = _wire(monkeypatch, {**LXC, "net1": "name=eth1,bridge=vmbr9,type=veth"})
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.mutations()[0][2] == {"net1": LXC["net1"], "digest": LXC["digest"]}
    assert done["restored"] == ["net1"] and done["skipped"] == {}


def test_a_key_removed_since_is_set_again(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"delete": "onboot"}, QEMU)
    now = {k: v for k, v in QEMU.items() if k != "onboot"}
    w = _wire(monkeypatch, now)
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.mutations()[0][2] == {"onboot": 0, "digest": QEMU["digest"]} and done["restored"] == ["onboot"]


def test_nothing_drifted_is_a_noop_that_writes_nothing_and_spends_nothing(box, monkeypatch, tmp_path):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    grants = tmp_path / "grants"
    grants.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(grants))
    w = _wire(monkeypatch, QEMU)                       # the record is back as it was
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert done["status"] == "noop" and "no published key differs" in done["why"] and done["skipped"] == META_SKIPPED
    assert w.mutations() == [] and list(grants.iterdir()) == []      # no write, no consent asked
    assert _rows()[-1]["action"] == "core.execute" and _rows()[-1]["target"] == QEMU_PATH   # the read's own receipt


# --- what is never written: a credential the receipt withheld, a key the write does not publish --

def test_a_value_the_receipt_withheld_is_skipped_and_named_never_written(box, monkeypatch):
    before = {"type": "cifs", "server": "nas.invalid", "username": "u", "password": "hunter2", "digest": "d" * 40}
    _wire(monkeypatch, before)
    engine.execute(_tiered("pve", "PUT", "/storage/{storage}"), {"server": "nas2.invalid"}, cfg=box,
                   path="/storage/nas")
    point = [r for r in _rows() if r["action"] == "core.undo_point"][-1]
    assert point["detail"]["before"]["password"].startswith("[redacted sha256:")   # the capture withheld it
    w = _wire(monkeypatch, {**before, "server": "nas2.invalid", "password": "changed"})
    done = undo.restore(point["entry_hash"][:12], cfg=box, confirm=True)
    sent = w.mutations()[0][2]
    assert "password" not in sent and sent["server"] == "nas.invalid"
    assert done["skipped"]["password"] == "withheld or masked by the receipt (a credential); set it by hand"
    assert done["skipped"]["type"] == "the write does not publish it"
    assert "hunter2" not in json.dumps(w.calls)


def test_a_key_the_write_does_not_publish_is_skipped_even_when_it_drifted(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    w = _wire(monkeypatch, {**QEMU, "memory": "8192", "meta": "creation-qemu=12.0.0,ctime=1"})
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert "meta" not in w.mutations()[0][2] and done["skipped"] == META_SKIPPED


def test_a_key_added_since_is_named_where_the_write_publishes_no_delete_list(box, monkeypatch):
    assert "delete" not in engine.resolve("pve", "PUT", "/nodes/{node}/dns").params
    before = {"dns1": "192.0.2.53", "search": "example.invalid"}
    _wire(monkeypatch, before)
    out = engine.execute(_tiered("pve", "PUT", "/nodes/{node}/dns"),
                         {"dns1": "192.0.2.54", "search": "example.invalid", "dns2": "192.0.2.55"},
                         cfg=box, path="/nodes/pve1/dns")
    w = _wire(monkeypatch, {**before, "dns1": "192.0.2.54", "dns2": "192.0.2.55"})
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.mutations()[0][2] == {"dns1": "192.0.2.53", "search": "example.invalid"}  # search: required, carried
    assert done["restored"] == ["dns1"] and done["deleted"] == []
    assert done["skipped"] == {"dns2": "added since the capture; the write publishes no delete list"}


def test_a_delete_list_the_vendor_publishes_as_an_array_is_sent_as_one(box, monkeypatch):
    # PBS publishes a digest as 64 hex characters: the fixture carries a value the vendor accepts.
    before = {"dns1": "192.0.2.53", "search": "example.invalid", "digest": "a" * 64}
    _wire(monkeypatch, before)
    out = engine.execute(_tiered("pbs", "PUT", "/nodes/{node}/dns"), {"dns1": "192.0.2.54", "dns2": "192.0.2.55"},
                         cfg=_pbs(box), path="/nodes/pbs1/dns")
    w = _wire(monkeypatch, {**before, "dns1": "192.0.2.54", "dns2": "192.0.2.55", "digest": "b" * 64})
    done = undo.restore(out["undo"]["id"], cfg=_pbs(box), confirm=True)
    assert w.mutations()[0][2] == {"dns1": "192.0.2.53", "delete": ["dns2"], "digest": "b" * 64}
    assert done["deleted"] == ["dns2"]


def test_a_boolean_delete_flag_is_not_a_delete_list(box, monkeypatch):
    """`PUT /access/acl` publishes `delete` as a boolean (remove this ACL); a restore must not
    send a key list through it."""
    assert engine.resolve("pve", "PUT", "/access/acl").params["delete"]["type"] == "boolean"
    assert undo._delete_shape(engine.resolve("pve", "PUT", "/access/acl")) is None


# --- what cannot be restored says why -------------------------------------------------------------

def test_a_truncated_capture_is_refused_with_its_size(box, monkeypatch):
    big = {**QEMU, "description": "x" * 70_000}
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, big)
    w = _wire(monkeypatch, big)
    with pytest.raises(ProximoError, match="over the receipt's bound"):
        undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.calls == []


def test_a_deleted_record_has_no_write_that_restores_it(box, monkeypatch):
    _wire(monkeypatch, {"type": "dir", "path": "/mnt/x", "digest": "d" * 40})
    out = engine.execute(_tiered("pve", "DELETE", "/storage/{storage}"), {}, cfg=box, path="/storage/x")
    w = _wire(monkeypatch, {})
    with pytest.raises(ProximoError, match="no write that restores a deleted record"):
        undo.restore(out["undo"]["id"], cfg=box)
    assert w.calls == []


def test_a_path_with_no_put_is_named_not_invented(box, monkeypatch):
    _wire(monkeypatch, {"running": 1, "allowed_nodes": ["pve2"]}, answer=UPID)
    out = engine.execute(_tiered("pve", "POST", "/nodes/{node}/qemu/{vmid}/migrate"), {"target": "pve2"},
                         cfg=box, path="/nodes/pve1/qemu/101/migrate", wait=0)
    assert out["undo"]["captured"] is True
    with pytest.raises(ProximoError, match=r"publishes no PUT /nodes/\{node\}/qemu/\{vmid\}/migrate"):
        undo.restore(out["undo"]["id"], cfg=box)


def test_a_capture_that_is_a_collection_is_not_a_record_to_write(box, monkeypatch):
    w = _wire(monkeypatch, [{"path": "/", "roleid": "Administrator", "ugid": "u@pam", "type": "user"}])
    out = engine.execute(_tiered("pve", "PUT", "/access/acl"), {"path": "/", "roles": "PVEAuditor"},
                         cfg=box, path="/access/acl")
    with pytest.raises(ProximoError, match="a collection, not a record"):
        undo.restore(out["undo"]["id"], cfg=box)
    assert w.mutations() == [("PUT", "/access/acl", {"path": "/", "roles": "PVEAuditor"})]


def test_an_unknown_short_or_wrong_id_is_refused(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    with pytest.raises(ProximoError, match="no capture"):
        undo.restore("000000000000", cfg=box)
    with pytest.raises(ProximoError, match="at least 8"):
        undo.restore(out["undo"]["id"][:4], cfg=box)
    with pytest.raises(ProximoError, match="not a capture"):
        undo.restore(_rows()[-1]["entry_hash"][:12], cfg=box)      # the `ok` row, not the undo point


def test_a_capture_from_before_the_plane_was_recorded_asks_for_it(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    log = os.environ["PROXIMO_AUDIT_LOG"]
    rows = _rows()
    for r in rows:
        if r["action"] == "core.undo_point":
            del r["detail"]["plane"]
    open(log, "w", encoding="utf-8").write("".join(json.dumps(r) + "\n" for r in rows))
    monkeypatch.setattr(undo, "_verified", lambda cfg, lines: None)   # the rewrite is not the chain under test
    _wire(monkeypatch, QEMU)
    with pytest.raises(ProximoError, match="names no plane"):
        undo.restore(out["undo"]["id"], cfg=box)
    assert undo.restore(out["undo"]["id"], plane="pve", cfg=box)["status"] == "noop"


# --- PROVE guards UNDO: a before-state on a broken chain is not evidence ---------------------------

def test_a_broken_chain_refuses_the_restore_and_receipts_it(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    log = os.environ["PROXIMO_AUDIT_LOG"]
    lines = open(log, encoding="utf-8").read().splitlines()
    lines[0] = lines[0].replace('"outcome"', '"outcomf"', 1)                # one byte in the first row
    open(log, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"})
    with pytest.raises(ProximoError, match="chain is broken at 1"):
        undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.calls == []
    last = _rows()[-1]
    assert last["action"] == "core.refuse" and last["detail"]["needs"] == "prove" and last["target"] == QEMU_PATH


# --- the restore is governed like any call ---------------------------------------------------------

def test_an_unarmed_restore_is_refused_at_arm_and_nothing_is_written(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    monkeypatch.setattr(engine.arm, "arm_state", lambda cfg=None: engine.arm.ArmGateState(True, False, "disarmed"))
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"})
    plan = undo.restore(out["undo"]["id"], cfg=box)
    assert plan["allowed"] is False and plan["needs"] == "arm" and plan["arguments"]["memory"] == "4096"
    with pytest.raises(ProximoError, match="arm"):
        undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.mutations() == [] and _rows()[-1]["detail"]["needs"] == "arm"


def test_an_untiered_write_refuses_the_restore(box, monkeypatch, records):
    # Since 2026-10-04 the record leaves no published mutation unjudged, so the control strips
    # the family line that opens /cluster/options: the restore's twin resolves with no sentence.
    real = bj.tiers(HARVESTED.read_text())
    stripped = {**real, "family": {k: v for k, v in real["family"].items() if k != "pve:/cluster/options"}}
    monkeypatch.setattr(bj, "tiers", lambda _text: stripped)
    records()
    try:
        assert engine.resolve("pve", "PUT", "/cluster/options").tier is None
        _wire(monkeypatch, {"keyboard": "en-us", "console": "html5"})
        out = engine.execute(_tiered("pve", "PUT", "/cluster/options"), {"keyboard": "de"}, cfg=box,
                             path="/cluster/options")
        w = _wire(monkeypatch, {"keyboard": "de", "console": "html5"})
        plan = undo.restore(out["undo"]["id"], cfg=box)
        assert plan["allowed"] is False and plan["needs"] == "tier"
        with pytest.raises(ProximoError):
            undo.restore(out["undo"]["id"], cfg=box, confirm=True)
        assert w.mutations() == []
    finally:
        engine.table.cache_clear()


def test_a_restore_the_vendor_answers_with_a_task_is_waited_on(box, monkeypatch):
    _no_sleep(monkeypatch)
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"}, {"status": "stopped", "exitstatus": "OK"}, answer=UPID)
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True, wait=10)
    assert done["task"]["succeeded"] is True and done["restored"] == ["memory"]
    assert [r["outcome"] for r in _rows() if r["action"] == "core.task"] == ["finished"]
    assert w.calls[-1][1] == f"/nodes/pve1/tasks/{UPID}/status"


# --- the doors ------------------------------------------------------------------------------------

def test_the_mcp_door_restores_through_proximo_call_with_method_undo_and_the_id_as_the_path(box, monkeypatch):
    """No seventh tool: the 4K gate had nine tokens of room and a tool costs two hundred. The
    shell door's spelling (method `undo`, the id where the path goes) is the one shape on both."""
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"})
    plan = door.call("pve", "undo", out["undo"]["id"], cfg=box)
    assert plan["status"] == "plan" and plan["arguments"]["memory"] == "4096" and w.mutations() == []
    done = door.call("pve", "UNDO", out["undo"]["id"], confirm=True, cfg=box)
    assert done["restored"] == ["memory"] and len(w.mutations()) == 1
    with pytest.raises(ProximoError, match="no capture"):
        door.call("pve", "undo", "ffffffffffff", cfg=box)
    assert "method=undo" in door.build_server()._tool_manager._tools["proximo_call"].description


def test_the_shell_door_takes_undo_as_the_method_and_the_id_as_the_path(box, monkeypatch, capsys):
    from proximo.core.doors import cli
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    monkeypatch.setattr(wire.Plane, "from_env", classmethod(lambda cls, product: box))
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"})
    assert cli.main(["pve", "undo", out["undo"]["id"], "--plan"]) == cli.EXIT_OK
    printed = json.loads(capsys.readouterr().out)
    assert printed["status"] == "plan" and printed["arguments"]["memory"] == "4096" and w.mutations() == []
    assert cli.main(["pve", "undo", out["undo"]["id"]]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["restored"] == ["memory"] and len(w.mutations()) == 1
    assert cli.main(["pve", "undo", "ffffffffffff"]) == cli.EXIT_REFUSED
    assert "no capture" in capsys.readouterr().err


# --- LENS 1 FOLD (sonnet, 2026-10-02, 6 BLOCKING): each planted against the shipped bytes ----------

def _rewrite_unkeyed(log: str, edit) -> None:
    """Forge the live log as a valid UNKEYED sha256 chain (the downgrade the HMAC key exists to
    catch), applying `edit` to each row's body on the way."""
    from proximo.core import ledger as L
    rows = [json.loads(x) for x in open(log, encoding="utf-8") if x.strip()]
    prev = L.GENESIS_HASH
    out = []
    for r in rows:
        body = {k: v for k, v in r.items() if k not in ("prev_hash", "entry_hash", "alg")}
        edit(body)
        h = L._hash(body, prev, None)
        out.append({**body, "prev_hash": prev, "entry_hash": h})
        prev = h
    open(log, "w", encoding="utf-8").write("".join(json.dumps(r) + "\n" for r in out))


def test_b1_a_keyed_ledger_rewritten_unkeyed_is_broken_and_the_forged_capture_is_not_written(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)

    def forge(body):
        if body.get("action") == "core.undo_point":
            body["detail"]["before"]["hookscript"] = "local:snippets/evil.sh"
    _rewrite_unkeyed(os.environ["PROXIMO_AUDIT_LOG"], forge)
    forged_id = [r for r in _rows() if r["action"] == "core.undo_point"][-1]["entry_hash"][:12]
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"})
    with pytest.raises(ProximoError, match="chain is broken"):
        undo.restore(forged_id, cfg=box, confirm=True)
    assert w.calls == [] and "evil" not in json.dumps(w.calls)
    assert out["undo"]["id"] != forged_id                              # the rewrite moved every hash


def test_b2_a_fenced_record_is_refused_and_an_untrusted_one_is_labelled(box, monkeypatch):
    assert engine.resolve("pve", "GET", "/nodes/{node}/qemu/{vmid}/config").untrusted
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", "1")
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"})
    with pytest.raises(ProximoError, match="fenced"):
        undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.mutations() == []
    monkeypatch.delenv("PROXIMO_TAINT_FENCE")
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"})
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert done["untrusted"] is True and w.mutations()[0][2] == {"memory": "4096", "digest": QEMU["digest"]}


def test_b3_only_a_key_the_captured_mutation_added_rides_the_delete_list(box, monkeypatch):
    disk = "lab:101/vm-101-disk-1.raw,size=8G"
    out = _mutate(box, monkeypatch, QEMU_PATH, {"delete": "scsi1", "description": "x"}, {**QEMU, "scsi1": disk})
    now = {**QEMU, "description": "x", "unused0": "lab:101/vm-101-disk-1.raw", "lock": "backup"}
    w = _wire(monkeypatch, now)
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    sent = w.mutations()[0][2]
    assert sent == {"scsi1": disk, "delete": "description", "digest": QEMU["digest"]}
    assert done["deleted"] == ["description"]
    assert done["skipped"]["unused0"] == undo.NOT_BY_THE_MUTATION == done["skipped"]["lock"]
    assert undo.NOT_BY_THE_MUTATION.endswith("not removed")


def test_b3_with_no_executing_row_nothing_added_since_is_removed(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"description": "x"}, QEMU)
    log = os.environ["PROXIMO_AUDIT_LOG"]
    rows = [r for r in _rows() if not (r["action"] == "core.execute" and r["mutation"])]   # a crash before executing
    open(log, "w", encoding="utf-8").write("".join(json.dumps(r) + "\n" for r in rows))
    monkeypatch.setattr(undo, "_verified", lambda cfg, lines: None)
    w = _wire(monkeypatch, {**QEMU, "description": "x"})
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.mutations() == [] and done["status"] == "noop"
    assert done["skipped"]["description"].startswith("added since the capture by something other")


def test_b4_a_post_capture_restores_only_where_the_put_is_the_same_operation(box, monkeypatch):
    # QEMU's async config POST publishes every parameter its PUT does: restorable through the PUT
    _wire(monkeypatch, QEMU, answer=UPID)
    out = engine.execute(_tiered("pve", "POST", "/nodes/{node}/qemu/{vmid}/config"), {"memory": "8192"},
                         cfg=box, path=QEMU_PATH, wait=0)
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"})
    assert undo.restore(out["undo"]["id"], cfg=box)["arguments"]["memory"] == "4096"
    # apt repositories: the POST changes a repo, the PUT adds a standard one; not the same write
    _wire(monkeypatch, {"files": [], "standard-repos": [{"handle": "enterprise", "status": 1}]})
    out = engine.execute(_tiered("pve", "POST", "/nodes/{node}/apt/repositories"),
                         {"index": 0, "path": "/etc/apt/x", "enabled": 1}, cfg=box, path="/nodes/pve1/apt/repositories")
    w = _wire(monkeypatch, {"files": [{"x": 1}], "standard-repos": []})
    with pytest.raises(ProximoError, match="different operation"):
        undo.restore(out["undo"]["id"], cfg=box)
    assert w.calls == []
    assert undo.same_write(engine.resolve("pve", "POST", "/nodes/{node}/qemu/{vmid}/config")) is not None
    assert undo.same_write(engine.resolve("pve", "POST", "/nodes/{node}/subscription")) is None


def test_b4_a_write_with_no_published_parameters_is_refused_not_a_noop(box, monkeypatch):
    # MANUFACTURED: this address had no parameters in the table until B19 flattened the vendor's
    # nested `allOf` (2026-10-05); the control no longer waits for a gap in the table to exist.
    _wire(monkeypatch, {"name": "store", "comment": "old"})
    out = engine.execute(_tiered("pbs", "PUT", "/config/datastore/{name}"), {}, cfg=_pbs(box),
                         path="/config/datastore/store")
    key = ("pbs", "PUT", "/config/datastore/{name}")
    table = dict(engine.table())
    table[key] = engine.Row(**{**table[key].__dict__, "params": {}})
    monkeypatch.setattr(engine, "table", lambda: table)
    with pytest.raises(ProximoError, match="publishes no parameters"):
        undo.restore(out["undo"]["id"], cfg=_pbs(box))


def test_b19_a_pbs_datastore_update_now_restores(box, monkeypatch):
    """B19: PBS nests its update body in `allOf`, so the table had no parameters for the datastore
    PUT and the core could neither update a datastore nor restore one. Flattened, both work."""
    assert "comment" in engine.resolve("pbs", "PUT", "/config/datastore/{name}").params
    _wire(monkeypatch, {"name": "store", "comment": "old"})
    out = engine.execute(_tiered("pbs", "PUT", "/config/datastore/{name}"), {"comment": "new"}, cfg=_pbs(box),
                         path="/config/datastore/store")
    w = _wire(monkeypatch, {"name": "store", "comment": "new"})
    undo.restore(out["undo"]["id"], cfg=_pbs(box), confirm=True)
    writes = [(m, p, a.get("comment")) for m, p, a in w.mutations()]
    assert ("PUT", "/config/datastore/store", "old") in writes


def test_b19_a_typed_union_requires_only_what_every_variant_requires():
    """PVE's HA rules publish a `oneOf` keyed by `type`: `nodes` is required by node-affinity
    only. The merge kept the first variant's spec, made `nodes` required for every rule, and
    refused a resource-affinity rule the vendor takes (lens, 2026-10-05)."""
    row = engine.table()[("pve", "POST", "/cluster/ha/rules")]
    engine.check_args(row, {"rule": "r1", "type": "resource-affinity", "resources": "vm:100,vm:101",
                            "affinity": "negative"})
    with pytest.raises(ProximoError, match="requires"):
        engine.check_args(row, {"type": "resource-affinity", "resources": "vm:100"})


def test_b19_the_builder_merges_a_typed_union_by_every_variant(monkeypatch):
    """The rule itself, not only the shipped table: a name is required only when EVERY variant
    publishes it and requires it."""
    import importlib.util
    import pathlib
    path = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "build_governance_table.py"
    spec = importlib.util.spec_from_file_location("build_governance_table", path)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    merged = builder.properties({"oneOf": [
        {"properties": {"a": {"type": "string"}, "b": {"type": "string"}, "c": {"type": "string", "optional": 1}}},
        {"properties": {"a": {"type": "string"}, "c": {"type": "string"}}},
    ]})
    assert not merged["a"].get("optional")         # required by both
    assert merged["b"]["optional"] == 1            # one variant lacks it
    assert merged["c"]["optional"] == 1            # one variant marks it optional


def test_b4_a_noop_names_the_keys_that_differ_and_were_not_written(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    w = _wire(monkeypatch, {**QEMU, "meta": "creation-qemu=12.0.0,ctime=9"})
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert done["status"] == "noop" and w.mutations() == []
    assert done["why"] == "no published key differs from the capture; nothing to write"
    assert done["differs_unwritten"] == ["meta"]


def test_b5_a_capture_from_a_registered_box_is_restored_only_on_that_box(box, monkeypatch):
    lab2 = wire.Plane("pve", "https://lab2.invalid:8006/api2/json", box.token_path, name="lab2")
    _wire(monkeypatch, QEMU)
    out = engine.execute(_tiered("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config"), {"memory": "8192"}, cfg=lab2,
                         path=QEMU_PATH)
    assert [r for r in _rows() if r["action"] == "core.undo_point"][-1]["remote"] == "lab2"
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"})
    with pytest.raises(ProximoError, match="captured on lab2"):
        undo.restore(out["undo"]["id"], cfg=box)                      # the env box
    with pytest.raises(ProximoError, match="captured on lab2"):
        undo.restore(out["undo"]["id"], cfg=None, plane="pve")
    assert w.calls == []
    assert undo.restore(out["undo"]["id"], cfg=lab2)["arguments"]["memory"] == "4096"
    env_out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    with pytest.raises(ProximoError, match="captured on the env box"):
        undo.restore(env_out["undo"]["id"], cfg=lab2)


def test_b6_a_failed_task_claims_nothing_restored(box, monkeypatch):
    _no_sleep(monkeypatch)
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    _wire(monkeypatch, {**QEMU, "memory": "8192"}, {"status": "stopped", "exitstatus": "ERROR: lock failed"},
          answer=UPID)
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True, wait=10)
    assert done["task"]["succeeded"] is False
    assert done["restored"] == [] and done["deleted"] == [] and done["status"] == "failed"
    assert done["attempted"] == {"restored": ["memory"], "deleted": []}


def test_arguments_on_an_undo_are_refused_on_both_doors(box, monkeypatch, capsys):
    from proximo.core.doors import cli
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"})
    with pytest.raises(ProximoError, match="takes no arguments"):
        door.call("pve", "undo", out["undo"]["id"], {"memory": "1"}, cfg=box)
    monkeypatch.setattr(wire.Plane, "from_env", classmethod(lambda cls, product: box))
    assert cli.main(["pve", "undo", out["undo"]["id"], "memory=1", "--plan"]) == cli.EXIT_REFUSED
    assert "takes no arguments" in capsys.readouterr().err and w.calls == []


def test_a_captured_write_control_and_a_null_are_never_sent(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"},
                  {**QEMU, "delete": "onboot,tags", "description": None})
    w = _wire(monkeypatch, {**QEMU, "memory": "8192", "description": "x"})
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.mutations()[0][2] == {"memory": "4096", "digest": QEMU["digest"]}
    assert done["skipped"]["delete"] == "a write control in the capture, not state"
    assert done["skipped"]["description"] == "the capture holds no value for it"


def test_an_archived_capture_says_the_live_log_was_searched(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    with pytest.raises(ProximoError, match="not in the live log .*; sealed archives beside it are not searched"):
        undo.restore("f" * 12, cfg=box)
    assert out["undo"]["id"]


# --- LENS 2 FOLD (sonnet, 2026-10-02, 3 BLOCKING on the fold of lens 1) -----------------------------

def test_l2b1_a_keyed_box_with_its_key_gone_refuses_the_forgery(box, monkeypatch):
    _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    log = os.environ["PROXIMO_AUDIT_LOG"]

    def forge(body):
        if body.get("action") == "core.undo_point":
            body["detail"]["before"]["hookscript"] = "local:snippets/evil.sh"
    _rewrite_unkeyed(log, forge)
    os.remove(os.path.join(os.path.dirname(log), "audit.key"))            # the key beside the log, gone
    forged = [r for r in _rows() if r["action"] == "core.undo_point"][-1]["entry_hash"][:12]
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"})
    with pytest.raises(ProximoError, match="configured keyed and no key is readable"):
        undo.restore(forged, cfg=box, confirm=True)
    assert w.calls == [] and "evil" not in json.dumps(w.calls)


def test_l2b1_an_unreadable_key_file_is_a_refusal_not_a_traceback(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    key = os.path.join(os.path.dirname(os.environ["PROXIMO_AUDIT_LOG"]), "audit.key")
    os.remove(key)
    os.mkdir(key)                                                          # a directory where the key should be
    w = _wire(monkeypatch, {**QEMU, "memory": "8192"})
    with pytest.raises(ProximoError, match="audit key could not be read"):
        undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.calls == []


def test_l2b2_a_credential_the_mutation_set_is_named_never_silent(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"cipassword": "hunter2", "description": "x"}, QEMU)
    assert engine.resolve("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config").params.get("cipassword")
    w = _wire(monkeypatch, {**QEMU, "cipassword": "**********", "description": "x"})
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.mutations()[0][2] == {"delete": "description", "digest": QEMU["digest"]}
    assert done["skipped"]["cipassword"] == "withheld by the read now (a credential the mutation set); not removed"
    assert "cipassword" not in json.dumps(w.mutations())
    # only the credential was set: a noop that SAYS so
    out = _mutate(box, monkeypatch, QEMU_PATH, {"cipassword": "hunter2"}, QEMU)
    w = _wire(monkeypatch, {**QEMU, "cipassword": "**********"})
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert done["status"] == "noop" and done["differs_unwritten"] == ["cipassword"] and w.mutations() == []
    assert "cipassword" in done["skipped"]


@pytest.mark.parametrize("polls,state", [
    ([], "submitted"),                                                     # wait=0: submitted only
    ([{"status": "running"}], "timed_out"),                                # the wait ran out
    ([{"status": "stopped", "exitstatus": "ERROR: lock failed"}], "failed"),
])
def test_l2b3_the_restore_says_which_way_an_unfinished_task_went(box, monkeypatch, polls, state):
    _no_sleep(monkeypatch)
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    _wire(monkeypatch, {**QEMU, "memory": "8192"}, *polls, answer=UPID)
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True, wait=0 if not polls else 4)
    assert done["status"] == state and done["restored"] == [] and done["attempted"]["restored"] == ["memory"]
    assert done["task"]["succeeded"] is False


def test_l2b3_an_unpollable_task_is_unknown(box, monkeypatch):
    _no_sleep(monkeypatch)
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    w = Wire({**QEMU, "memory": "8192"}, answer=UPID)
    real = w.call

    def call(method, path, params=None):
        if method == "GET" and "/tasks/" in path:
            raise RuntimeError("poll failed")
        return real(method, path, params)
    w.call = call
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True, wait=4)
    assert done["status"] == "unknown" and done["restored"] == [] and done["task"]["poll_error"]


def test_the_executing_row_is_paired_by_the_captures_own_id_not_by_path(box, monkeypatch):
    a = _mutate(box, monkeypatch, QEMU_PATH, {"description": "a"}, QEMU)
    b = _mutate(box, monkeypatch, QEMU_PATH, {"hookscript": "local:snippets/b.sh"}, {**QEMU, "description": "a"})
    log = os.environ["PROXIMO_AUDIT_LOG"]
    rows = _rows()
    ex = [i for i, r in enumerate(rows) if r["outcome"] == "executing"]
    rows[ex[0]], rows[ex[1]] = rows[ex[1]], rows[ex[0]]                   # interleaved twins: B's executing first
    open(log, "w", encoding="utf-8").write("".join(json.dumps(r) + "\n" for r in rows))
    monkeypatch.setattr(undo, "_verified", lambda cfg, lines: None)      # the reorder is not the chain under test
    w = _wire(monkeypatch, {**QEMU, "description": "a", "hookscript": "local:snippets/b.sh"})
    done = undo.restore(a["undo"]["id"], cfg=box, confirm=True)
    assert w.mutations()[0][2] == {"delete": "description", "digest": QEMU["digest"]}   # A's own key, not B's
    assert done["skipped"]["hookscript"] == undo.NOT_BY_THE_MUTATION and b["undo"]["id"] != a["undo"]["id"]


def test_the_ledger_is_read_once_for_verify_find_and_pair(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    reads, seen = [], {}
    real_read, real_verify, real_find, real_pair = undo.read_log, undo.verify_lines, undo.find_entry, undo.executing_for
    monkeypatch.setattr(undo, "read_log", lambda p: (reads.append(p), real_read(p))[1])
    monkeypatch.setattr(undo, "verify_lines", lambda lines, key, h=None: (seen.__setitem__("verify", id(lines)),
                                                                           real_verify(lines, key, h))[1])
    monkeypatch.setattr(undo, "parse_lines", lambda lines: (seen.__setitem__("parse", id(lines)), undo_parse(lines))[1])
    monkeypatch.setattr(undo, "find_entry", lambda e, r, p: (seen.__setitem__("find", id(e)), real_find(e, r, p))[1])
    monkeypatch.setattr(undo, "executing_for", lambda e, c: (seen.__setitem__("pair", id(e)), real_pair(e, c))[1])
    _wire(monkeypatch, {**QEMU, "memory": "8192"})
    assert undo.restore(out["undo"]["id"], cfg=box)["status"] == "plan"
    assert len(reads) == 1                                                 # the evidence is read once
    assert seen["verify"] == seen["parse"] and seen["find"] == seen["pair"]   # and judged, found and paired in it


def test_the_plans_untrusted_label_is_the_twins(box, monkeypatch):
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, QEMU)
    _wire(monkeypatch, {**QEMU, "memory": "8192"})
    plan = undo.restore(out["undo"]["id"], cfg=box)
    assert plan["status"] == "plan" and plan["untrusted"] is True and plan["channel"]


# --- LENS 3 FOLD (sonnet, 2026-10-02, 1 BLOCKING in the second fold) --------------------------------

@pytest.mark.parametrize("sep", [" ", " ", "\x85"])
def test_l3b1_a_row_holding_a_unicode_line_separator_is_one_row(box, monkeypatch, sep):
    """`json.dumps(ensure_ascii=False)` leaves U+2028, U+2029 and U+0085 raw inside a string; the
    one-read refactor split rows with `splitlines`, which cuts on those too, so a genuine row read
    as two unparseable fragments: the restore said "not in the live log" and `audit_verify`
    accused a clean ledger."""
    from proximo.core.ledger import AuditLedger, LedgerConfig, ledger_key
    record = {**QEMU, "description": f"notes{sep}more"}
    out = _mutate(box, monkeypatch, QEMU_PATH, {"memory": "8192"}, record)
    cfg = LedgerConfig.from_env()
    assert AuditLedger(cfg.audit_log_path, key=ledger_key(cfg)).verify().ok
    w = _wire(monkeypatch, {**record, "memory": "8192"})
    done = undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert done["restored"] == ["memory"] and w.mutations()[0][2]["memory"] == "4096"


# --- the create gap: a record that was not there is captured as absent, and the vendor's own delete puts it back ---
#
# `_undo_before` reads the GET twin and refuses the mutation when the read fails, so a CREATE at
# an item path (a token, a realm-sync job, a metric server) could never run with UNDO on: its twin
# 404s (PVE answers 500 for "no such user") before the record exists (live, the lab, 2026-10-06).
# The fix is keyed on the ADDRESS, never the shape: of 28 published POSTs at an item path, 13 have
# a GET and a DELETE twin, and several are ACTIONS (pmg `backup/{filename}` RESTORES a backup,
# pve `content/{volume}` COPIES one, the firewall group POST adds a RULE while its DELETE removes
# the GROUP). A judged list in `undo.toml` names the five creates; a failed read-back on one of
# them is recorded `before: absent` with the vendor's status, and the restore is the DELETE twin,
# sent only when the ledger shows the create itself landed `ok` (the vendor refuses a duplicate,
# so a create that landed is the proof nothing was there).

TOKEN_ROW = ("pve", "POST", "/access/users/{userid}/token/{tokenid}")
TOKEN_PATH = "/access/users/proximo@pve/token/write"
TOKEN_DELETE = "DELETE /access/users/{userid}/token/{tokenid}"
MINTED = {"full-tokenid": "proximo@pve!write", "info": {"privsep": 1}, "value": "S3CR3T"}
EXACT_CREATES = 5


def _status_error(status, method="GET", path=TOKEN_PATH):
    req = httpx.Request(method, "https://pve.invalid:8006/api2/json" + path)
    return httpx.HTTPStatusError(str(status), request=req, response=httpx.Response(status, request=req))


class CreateWire(Wire):
    """GET raises `error` (the record is not there); a mutation answers `answer`, or raises it."""

    def __init__(self, error, answer=None):
        super().__init__(answer=answer)
        self.error = error

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        if method == "GET":
            raise self.error
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


def _create_wire(monkeypatch, error, answer=None):
    w = CreateWire(error, answer)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    return w


def _capture_rows():
    return [r for r in _rows() if r["action"] == "core.undo_point"]


def test_the_create_record_names_five_addresses_each_with_the_read_and_the_delete_at_its_path():
    t = engine.table()
    creates = {r.key: r.creates for r in t.values() if r.creates}
    assert len(creates) == EXACT_CREATES, sorted(creates)
    for key, why in creates.items():
        product, _, address = key.partition(":")
        method, _, path = address.partition(" ")
        row = t[(product, method, path)]
        assert method == "POST" and row.access == engine.MUTATE and not row.gate and not row.excluded, key
        for m in ("GET", "DELETE"):
            twin = t.get((product, m, path))
            assert twin is not None and not twin.gate and not twin.excluded, (key, m)
            # the twins are called with the path alone (the capture's read, the restore's delete)
            assert not [k for k, v in twin.params.items()
                        if not v.get("optional") and k not in engine.placeholders(path)], (key, m)
        assert len(why.split()) >= 4 and row.creates, key
    assert not engine.resolve("pve", "POST", "/cluster/firewall/groups/{group}").creates


def _dicts():
    """The table as the build sees it: one dict per row, before any Row exists."""
    return {k: vars(r) for k, r in engine.table().items()}


@pytest.mark.parametrize("body,match", [
    (b'[create]\n"pve:POST /nodes/{n}/token" = { why = "a key that matches no published address" }', "matches no"),
    (b'[create]\n"pve:POST /access/users/{userid}/token/{tokenid}" = { why = "short" }', "without a why"),
    (b'[create]\n"pve:POST /access/users/{userid}/token/{tokenid}" = "a bare string is not a line"', "without a why"),
    (b'[create]\n"pve:POST /access/tfa/{userid}" = { why = "a TFA entry: the path has a GET but no DELETE" }',
     "no DELETE"),
    (b'[create]\n"pve:POST /nodes/{node}/ceph/mon/{monid}" = { why = "a monitor: the path has a DELETE, no GET" }',
     "no GET"),
    (b'[create]\n"pve:GET /access/users/{userid}/token/{tokenid}" = { why = "a read is not a create at all" }',
     "not a POST"),
    (b'[create\n', "not a readable TOML"),
])
def test_a_create_line_that_cannot_deliver_its_undo_refuses_the_record_at_load(body, match):
    """A line names an undo the engine will deliver: the address must be a published POST, its GET
    must exist to read the record back and its DELETE must exist to put absence back. A line that
    cannot is a lie the file tells its reader, refused whole (the tier record's own rule)."""
    with pytest.raises(ProximoError, match=match):
        bj.creates(body.decode(), _dicts())


@pytest.mark.parametrize("status", [404, 500])
def test_a_listed_create_whose_read_back_fails_runs_and_its_capture_says_absent_with_the_vendors_status(
        box, monkeypatch, status):
    """PVE answers 404 for a token that is not there and 500 for a user that is not there (live,
    2026-10-06); both are recorded as the vendor said them, and neither stops the create."""
    w = _create_wire(monkeypatch, _status_error(status), answer=MINTED)
    out = engine.execute(_tiered(*TOKEN_ROW), {}, cfg=box, path=TOKEN_PATH)
    assert w.mutations() == [("POST", TOKEN_PATH, {})]
    point = _capture_rows()[-1]
    assert out["undo"] == {"captured": True, "read": "GET /access/users/{userid}/token/{tokenid}",
                           "absent": True, "id": point["entry_hash"][:12]}
    assert point["detail"]["absent"] is True and "before" not in point["detail"]      # its own key, never a value
    assert point["detail"]["read_back"] == {"error": "HTTPStatusError", "status": status}
    assert "S3CR3T" not in json.dumps(point)
    landed = [r for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "ok"][-1]
    assert landed["detail"]["capture"] == out["undo"]["id"]                           # the ok row names its capture


def test_the_control_an_unlisted_post_at_an_item_path_with_the_same_failing_read_is_still_refused(box, monkeypatch):
    """The firewall group's POST adds a RULE and its DELETE removes the GROUP: "absent" here would
    make undo delete a security group after one rule was added. Not listed, so fail-closed stays."""
    w = _create_wire(monkeypatch, _status_error(404, path="/cluster/firewall/groups/g1"), answer=None)
    with pytest.raises(ProximoError, match="undo unavailable"):
        engine.execute(_tiered("pve", "POST", "/cluster/firewall/groups/{group}"), {"action": "ACCEPT", "type": "in"},
                       cfg=box, path="/cluster/firewall/groups/g1")
    assert w.mutations() == [] and _capture_rows() == []


def test_the_control_without_its_line_the_token_create_is_refused_again(box, monkeypatch):
    row = engine.Row(**{**_tiered(*TOKEN_ROW).__dict__, "creates": None})   # the row without its line
    w = _create_wire(monkeypatch, _status_error(404), answer=MINTED)
    with pytest.raises(ProximoError, match="undo unavailable"):
        engine.execute(row, {}, cfg=box, path=TOKEN_PATH)
    assert w.mutations() == []


def test_a_plan_of_a_listed_create_whose_read_fails_says_the_record_is_not_there(box, monkeypatch):
    _create_wire(monkeypatch, _status_error(404))
    p = engine.plan(_tiered(*TOKEN_ROW), {}, TOKEN_PATH, cfg=box)
    assert p["current"] == {"creates": True, "exists": False, "read_back": {"error": "HTTPStatusError", "status": 404}}
    assert p["change"] == {"creates": TOKEN_PATH} and p["noop"] is False


def test_an_absent_capture_is_restored_by_the_vendors_delete_plan_first_then_sent_and_receipted(box, monkeypatch):
    out = engine.execute(_tiered(*TOKEN_ROW), {}, cfg=box, path=TOKEN_PATH) if _create_wire(
        monkeypatch, _status_error(404), answer=MINTED) else None
    ref = out["undo"]["id"]
    w = _wire(monkeypatch, {"privsep": 1, "expire": 0})          # the token is there now
    plan = undo.restore(ref, cfg=box)
    assert plan["status"] == "plan" and plan["restores"] == ref and plan["address"] == TOKEN_DELETE
    assert plan["removes"] == TOKEN_PATH and plan["allowed"] is True and w.mutations() == []
    done = undo.restore(ref, cfg=box, confirm=True)
    assert done["removes"] == TOKEN_PATH and done["restores"] == ref and done["captured"] == _capture_rows()[0]["ts"]
    assert w.mutations() == [("DELETE", TOKEN_PATH, {})]
    executed = [r for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "ok"][-1]
    assert executed["detail"]["restores"].startswith(ref) and len(executed["detail"]["restores"]) == 64
    assert executed["detail"]["governed_as"] == TOKEN_DELETE
    assert done["undo"]["captured"] is True                       # the delete is itself captured: the record now


def test_an_absent_capture_whose_create_did_not_land_deletes_nothing(box, monkeypatch):
    """The proof of absence is the create landing (the vendor refuses a duplicate), not the failed
    read: a read that failed for another reason, over a record that IS there, followed by a create
    the vendor refused, must never end in that record's deletion."""
    w = _create_wire(monkeypatch, _status_error(404), answer=_status_error(500, "POST"))
    with pytest.raises(httpx.HTTPStatusError):
        engine.execute(_tiered(*TOKEN_ROW), {}, cfg=box, path=TOKEN_PATH)
    ref = _capture_rows()[-1]["entry_hash"][:12]
    w2 = _wire(monkeypatch, {"privsep": 1})
    with pytest.raises(ProximoError, match="did not land"):
        undo.restore(ref, cfg=box, confirm=True)
    assert w2.mutations() == [] and w.mutations() == [("POST", TOKEN_PATH, {})]


def test_an_absent_capture_with_no_terminal_row_deletes_nothing(box, monkeypatch):
    """A process that died between the executing row and the terminal one: not seen to land."""
    out = engine.execute(_tiered(*TOKEN_ROW), {}, cfg=box, path=TOKEN_PATH) if _create_wire(
        monkeypatch, _status_error(404), answer=MINTED) else None
    log = os.environ["PROXIMO_AUDIT_LOG"]
    lines = open(log, encoding="utf-8").read().splitlines(keepends=True)
    with open(log, "w", encoding="utf-8") as f:                   # the chain stays whole: a prefix of itself
        f.writelines(lines[:-1])
    w = _wire(monkeypatch, {"privsep": 1})
    with pytest.raises(ProximoError, match="did not land"):
        undo.restore(out["undo"]["id"], cfg=box, confirm=True)
    assert w.mutations() == []


def test_an_absent_capture_whose_record_is_already_gone_is_a_noop_that_sends_nothing(box, monkeypatch):
    out = engine.execute(_tiered(*TOKEN_ROW), {}, cfg=box, path=TOKEN_PATH) if _create_wire(
        monkeypatch, _status_error(404), answer=MINTED) else None
    w = _create_wire(monkeypatch, _status_error(404))             # gone again: the delete's read 404s
    plan = undo.restore(out["undo"]["id"], cfg=box)
    assert plan["noop"] is True and plan["current"]["exists"] is False and w.mutations() == []


def test_a_refused_create_then_a_later_write_at_the_same_path_is_not_the_create_landing(box, monkeypatch):
    """LENS 2026-10-08, BLOCKING: the first `_landed` accepted only `core.execute` rows and paired
    by intent (the path alone), so it scanned past the refused create's `core.error` row to a LATER
    PUT's ok row at the same path and undo deleted the token that had been there all along. The
    terminal rows name their capture now; the pairing is by id."""
    _create_wire(monkeypatch, _status_error(500), answer=_status_error(400, "POST"))       # a duplicate, refused
    with pytest.raises(httpx.HTTPStatusError):
        engine.execute(_tiered(*TOKEN_ROW), {}, cfg=box, path=TOKEN_PATH)
    ref = _capture_rows()[-1]["entry_hash"][:12]
    error = [r for r in _rows() if r["action"] == "core.error"][-1]
    assert error["detail"]["capture"] == ref                                              # the error row names it too
    w2 = _wire(monkeypatch, {"privsep": 1, "comment": "old"})            # then an unrelated write at the path lands
    engine.execute(_tiered("pve", "PUT", "/access/users/{userid}/token/{tokenid}"), {"comment": "new"},
                   cfg=box, path=TOKEN_PATH)
    assert w2.mutations() == [("PUT", TOKEN_PATH, {"comment": "new"})]
    with pytest.raises(ProximoError, match="did not land \\(error\\)"):
        undo.restore(ref, cfg=box, confirm=True)
    assert w2.mutations() == [("PUT", TOKEN_PATH, {"comment": "new"})]                    # no DELETE went


def test_an_absent_capture_is_put_back_once(box, monkeypatch):
    """LENS 2026-10-08, MAJOR: nothing marked a capture restored, so `undo <id>` again deleted
    whatever was made at the path since. The second asks is refused by the ledger's own row."""
    out = engine.execute(_tiered(*TOKEN_ROW), {}, cfg=box, path=TOKEN_PATH) if _create_wire(
        monkeypatch, _status_error(404), answer=MINTED) else None
    ref = out["undo"]["id"]
    w = _wire(monkeypatch, {"privsep": 1})
    undo.restore(ref, cfg=box, confirm=True)
    assert w.mutations() == [("DELETE", TOKEN_PATH, {})]
    w2 = _wire(monkeypatch, {"privsep": 0, "comment": "a new token of the same name"})
    with pytest.raises(ProximoError, match="already put back"):
        undo.restore(ref, cfg=box, confirm=True)
    with pytest.raises(ProximoError, match="already put back"):
        undo.restore(ref, cfg=box)                                                        # not even a plan
    assert w2.mutations() == []


def test_two_creates_at_one_path_interleaved_pair_each_with_its_own_landing(box, monkeypatch):
    """Pairing by intent (the path alone) with the error row honoured still fails here: A's rows
    are open when B captures, lands and closes, so the first terminal row at the intent after A's
    executing row is B's ok. Only the id on the row tells them apart."""
    class Interleaved(CreateWire):
        def call(self, method, path, params=None):
            self.calls.append((method, path, dict(params or {})))
            if method == "GET":
                raise self.error
            if not getattr(self, "inner_done", False):            # A's POST: B runs whole inside it, then A is refused
                self.inner_done = True
                self.inner = engine.execute(_tiered(*TOKEN_ROW), {}, cfg=box, path=TOKEN_PATH)
                raise _status_error(400, "POST")
            return MINTED
    w = Interleaved(_status_error(404))
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    with pytest.raises(httpx.HTTPStatusError):
        engine.execute(_tiered(*TOKEN_ROW), {}, cfg=box, path=TOKEN_PATH)
    a, b = (r["entry_hash"][:12] for r in _capture_rows())
    assert w.inner["undo"]["id"] == b
    assert [r["outcome"] for r in _rows() if r["action"] in ("core.execute", "core.error")] == [
        "executing", "executing", "ok", "error"]
    w2 = _wire(monkeypatch, {"privsep": 1})
    with pytest.raises(ProximoError, match="did not land \\(error\\)"):
        undo.restore(a, cfg=box, confirm=True)
    assert w2.mutations() == []
    assert undo.restore(b, cfg=box)["address"] == TOKEN_DELETE                              # B's own landing is B's


@pytest.mark.parametrize("twin", ["GET", "DELETE"])
def test_a_create_line_whose_twin_requires_an_argument_beyond_the_path_is_refused(twin):
    """No published twin of the five asks for one today; the control plants a required `foo` on the
    token's twin and the loader must refuse the line, since UNDO calls the twin with the path alone."""
    real = _dicts()
    key = ("pve", twin, "/access/users/{userid}/token/{tokenid}")
    planted = {**real[key], "params": {**real[key]["params"], "foo": {"type": "string"}}}
    body = '[create]\n"pve:POST /access/users/{userid}/token/{tokenid}" = { why = "a create whose twin now asks" }'
    with pytest.raises(ProximoError, match=f"{twin} .* requires foo"):
        bj.creates(body, {**real, key: planted})
    assert "pve:POST /access/users/{userid}/token/{tokenid}" in bj.creates(body, real)   # the real twin: fine


CREATES = [
    # (plane, POST row, concrete path, the create's own required arguments)
    ("pve", "/access/users/{userid}/token/{tokenid}", "/access/users/proximo@pve/token/write", {}),
    ("pbs", "/access/users/{userid}/token/{token-name}", "/access/users/proximo@pbs/token/write", {}),
    ("pdm", "/access/users/{userid}/token/{token-name}", "/access/users/proximo@pdm/token/write", {}),
    ("pve", "/cluster/jobs/realm-sync/{id}", "/cluster/jobs/realm-sync/nightly", {"schedule": "daily"}),
    ("pve", "/cluster/metrics/server/{id}", "/cluster/metrics/server/influx1",
     {"type": "influxdb", "server": "metrics.invalid", "port": 8089}),
]


@pytest.mark.parametrize("plane,template,path,args", CREATES, ids=[c[1] for c in CREATES])
def test_every_judged_create_captures_absent_runs_and_is_put_back_by_its_own_delete(box, monkeypatch, plane,
                                                                                    template, path, args):
    """THE AXIS NOT VARIED: every driven restore above runs the PVE token. The record spans three
    planes and two placeholder spellings (`{tokenid}`, `{token-name}`), and realm-sync and the
    metric server carry required arguments of their own; each line is driven whole here."""
    cfg = box if plane == "pve" else wire.Plane(plane, f"https://{plane}.invalid:8007/api2/json", box.token_path)
    w = _create_wire(monkeypatch, _status_error(404, path=path), answer={"value": "S3CR3T"} if "token" in path else {})
    out = engine.execute(_tiered(plane, "POST", template), args, cfg=cfg, path=path)
    assert out["undo"]["absent"] is True and w.mutations()[0][:2] == ("POST", path)
    w2 = _wire(monkeypatch, {"id": path.rsplit("/", 1)[1], **{k: str(v) for k, v in args.items()}})
    plan = undo.restore(out["undo"]["id"], cfg=cfg)
    assert plan["status"] == "plan" and plan["address"] == f"DELETE {template}" and plan["removes"] == path
    done = undo.restore(out["undo"]["id"], cfg=cfg, confirm=True)
    assert done["removes"] == path and w2.mutations() == [("DELETE", path, {})]
