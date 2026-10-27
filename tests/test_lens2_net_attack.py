"""Lens 2 against 0db204e: attacks on the rollback safety net, each finding fixed and pinned.

The findings: the net was dropped by volumes PVE never checks for a rollback (F1), `zfs` was
unsettled (F2), the datacenter manager can never show the chain flag (F3), a plan promised a net
it had not looked for (F4), the net's own reads and the taint wall disagreed by storage (F5), a
grant did not hold what the plan said about the net (F6), and four smaller readings. The plain
tests pin behaviour the lens checked and found holding.
"""
# ruff: noqa: F811, I001  (the `plane` fixture is imported from the net tests, then used as an argument)
from __future__ import annotations

import os

import pytest
from test_core_pdm_rollback_net import GUESTS, Api, _paths, _plan, _posts, _rollback, _rows, _wire, plane  # noqa: F401

from proximo.core import engine, spine, undo
from proximo.core.errors import ProximoError

PVE_QEMU = GUESTS[0][4]
PVE_LXC = GUESTS[1][4]
PDM_QEMU = GUESTS[2][4]


# --- F1: the volume set is wider than what PVE checks on rollback ------------------------------
# pve-guest-common AbstractConfig::snapshot_rollback runs __snapshot_rollback_vol_possible via
# foreach_volume over the SNAPSHOT's config: no include_unused, vmstate handled apart. A volume
# outside that set cannot make the rollback refuse, so a blocking storage there is no reason to
# drop the net.

def test_an_unused_volume_on_zfs_does_not_drop_the_net(plane, monkeypatch):
    api = _wire(monkeypatch, config={"scsi0": "local-lvm:vm-100-disk-0", "unused0": "tank:vm-100-disk-1"},
                snapcfg={"scsi0": "local-lvm:vm-100-disk-0"})
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert out["undo"]["captured"] is True and _paths(PVE_QEMU)[0] in _posts(api)


def test_a_vmstate_on_zfs_does_not_drop_the_net(plane, monkeypatch):
    api = _wire(monkeypatch, config={"scsi0": "local-lvm:vm-100-disk-0"},
                snapcfg={"vmstate": "tank:vm-100-state-before", "scsi0": "local-lvm:vm-100-disk-0"})
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert out["undo"]["captured"] is True and _paths(PVE_QEMU)[0] in _posts(api)


def test_a_disk_added_after_the_target_snapshot_does_not_drop_the_net(plane, monkeypatch):
    api = _wire(monkeypatch, config={"scsi0": "local-lvm:vm-100-disk-0", "scsi1": "tank:vm-100-disk-1"},
                snapcfg={"scsi0": "local-lvm:vm-100-disk-0"})
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert out["undo"]["captured"] is True and _paths(PVE_QEMU)[0] in _posts(api)


def test_a_containers_unused_volume_on_zfs_does_not_drop_the_net(plane, monkeypatch):
    api = _wire(monkeypatch, config={"rootfs": "local-lvm:subvol-100-disk-0", "unused0": "tank:subvol-100-disk-1"},
                snapcfg={"rootfs": "local-lvm:subvol-100-disk-0"})
    out = _rollback(plane, "pve", "lxc", PVE_LXC)
    assert out["undo"]["captured"] is True and _paths(PVE_LXC)[0] in _posts(api)


# --- F2: `zfs` (ZFS over iSCSI) is settled, and it blocks --------------------------------------
# pve-storage ZFSPlugin.pm: `use base qw(PVE::Storage::ZFSPoolPlugin)`, type 'zfs', no override
# of volume_rollback_is_possible: it dies "not most recent snapshot" exactly like zfspool.

def test_zfs_over_iscsi_takes_no_net(plane, monkeypatch):
    api = _wire(monkeypatch, config={"scsi0": "iscsi-zfs:vm-100-disk-0"},
                storages=[{"storage": "iscsi-zfs", "type": "zfs"}])
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert out["undo"]["captured"] is False and _paths(PVE_QEMU)[0] not in _posts(api)


# --- F3: PDM's node storage list is a STATUS list: the chain flag is never there ------------------
# PDM GET /pve/remotes/{remote}/nodes/{node}/storage is "Get status for all datastores" (vendor
# schema), PVE's /nodes/{node}/storage; snapshot-as-volume-chain lives only in /storage config.
# A chained qcow2 dir behind PDM reads FREE: net taken, the rollback then fails, and nothing said
# beforehand that it was not settled.

def test_a_dir_behind_pdm_is_not_settled(plane, monkeypatch):
    _wire(monkeypatch, config={"scsi0": "local:100/vm-100-disk-0.qcow2"},
          storages=[{"storage": "local", "type": "dir", "active": 1, "enabled": 1}])   # what a status list holds
    planned = _plan(plane, "pdm", "qemu", PDM_QEMU, node="pve1")
    assert planned["safety_net"].get("unsettled")


# --- F4: the plan claims a net it never looked for ---------------------------------------------

def test_a_plan_whose_target_read_failed_does_not_promise_the_net(plane, monkeypatch):
    _wire(monkeypatch, unreadable=("/snapshot",))
    planned = _plan(plane, "pve", "qemu", PVE_QEMU)
    with pytest.raises(ProximoError, match="could not confirm"):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert planned["safety_net"]["taken"] is False or planned["safety_net"].get("why")


def test_a_plan_whose_target_read_failed_says_execute_will_refuse(plane, monkeypatch):
    _wire(monkeypatch, unreadable=("/snapshot",))
    net = _plan(plane, "pve", "qemu", PVE_QEMU)["safety_net"]
    assert "could not confirm" in net["why"] and "refused unless it can be confirmed" in net["why"]


# --- F5: taint x net, both orders --------------------------------------------------------------

@pytest.fixture
def forbid_post(monkeypatch):
    monkeypatch.setenv(spine.TAINT_FORBID_ENV, "POST")


def test_a_snapshot_refused_before_the_wire_does_not_claim_an_orphan(plane, monkeypatch):
    """Nothing was sent: the sentence about a snapshot the vendor may have created is not said."""
    api = _wire(monkeypatch)
    real = engine.execute

    def wall(row, args=None, **kw):
        if kw.get("net_of") is not None:
            raise ProximoError("a wall in front of the snapshot")
        return real(row, args, **kw)
    monkeypatch.setattr(engine, "execute", wall)
    with pytest.raises(ProximoError) as e:
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    said = str(e.value)
    assert "Nothing was sent to the vendor" in said and "if the vendor created it anyway" not in said
    assert _posts(api) == []
    assert "snapshot" not in _rows()[-1]["detail"]


# --- F6: the grant holds what the plan said about the net --------------------------------------

def test_a_grant_approved_on_net_taken_does_not_run_a_rollback_with_no_net(plane, monkeypatch, tmp_path):
    g = tmp_path / "grants"
    g.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(g))
    api = _wire(monkeypatch)                                   # lvmthin: the plan says the net is taken
    planned = _plan(plane, "pve", "qemu", PVE_QEMU)
    assert planned["safety_net"]["taken"] is True
    grant = g / os.path.basename(spine.grant_path(planned["consent_id"]))
    grant.touch()
    api.config["scsi0"] = "tank:vm-100-disk-0"                 # the guest's config moves before execute
    api.snapcfg = api.config
    with pytest.raises(ProximoError, match="the safety net changed since the plan"):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert _posts(api) == [] and grant.exists()                # nothing written, the grant not spent


def test_a_grant_approved_on_net_skipped_does_not_run_a_rollback_that_would_take_one(plane, monkeypatch, tmp_path):
    g = tmp_path / "grants"
    g.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(g))
    api = _wire(monkeypatch, config={"scsi0": "tank:vm-100-disk-0"})
    planned = _plan(plane, "pve", "qemu", PVE_QEMU)
    assert planned["safety_net"]["taken"] is False
    (g / os.path.basename(spine.grant_path(planned["consent_id"]))).touch()
    api.config["scsi0"] = "local-lvm:vm-100-disk-0"
    api.snapcfg = api.config
    with pytest.raises(ProximoError, match="the safety net changed since the plan"):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert _posts(api) == []


def test_the_grant_for_the_plan_as_shown_still_runs_and_is_spent(plane, monkeypatch, tmp_path):
    g = tmp_path / "grants"
    g.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(g))
    _wire(monkeypatch)
    planned = _plan(plane, "pve", "qemu", PVE_QEMU)
    (g / os.path.basename(spine.grant_path(planned["consent_id"]))).touch()
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert out["undo"]["captured"] is True and list(g.iterdir()) == []


def test_a_missing_target_spends_no_grant_and_no_rate_slot(plane, monkeypatch, tmp_path):
    g = tmp_path / "grants"
    g.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(g))
    monkeypatch.setenv("PROXIMO_RATE_MAX", "2")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    api = _wire(monkeypatch, snaps=("other",))
    planned = _plan(plane, "pve", "qemu", PVE_QEMU)
    grant = g / os.path.basename(spine.grant_path(planned["consent_id"]))
    grant.touch()
    with pytest.raises(ProximoError, match="not on this guest"):
        _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert grant.exists() and _posts(api) == []
    api.snaps.append("before")
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)            # both rate slots and the grant were still there
    assert out["undo"]["captured"] is True


# --- the off switch ----------------------------------------------------------------------------

@pytest.mark.parametrize("value,on", [("off", False), (" OFF ", False), ("0", False), ("false", False),
                                      ("no", False), ("junk", True), ("", True), ("disable", True),
                                      ("none", True), ("n", True)])
def test_only_the_four_falsy_words_turn_the_net_off(plane, monkeypatch, value, on):
    monkeypatch.setenv(spine.UNDO_ENV, value)
    api = _wire(monkeypatch)
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert (_paths(PVE_QEMU)[0] in _posts(api)) is on
    assert out["undo"]["captured"] is on


# --- undo of an unread state -------------------------------------------------------------------

def test_undo_of_an_unread_state_starts_nothing_and_says_so(plane, monkeypatch):
    api = _wire(monkeypatch, unreadable=("/status/current",))
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    assert out["undo"]["running"] is None
    planned = undo.restore(out["undo"]["id"], cfg=plane("pve"))
    assert "start" not in planned["arguments"]
    notes = " ".join(planned["undo_notes"])
    assert "not known" in notes and "nothing is started" in notes
    assert "safety snapshot" in notes and api.calls          # and it says a further net is taken


def test_undo_of_a_stopped_guest_says_it_stays_stopped(plane, monkeypatch):
    _wire(monkeypatch, status="stopped")
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    planned = undo.restore(out["undo"]["id"], cfg=plane("pve"))
    assert "start" not in planned["arguments"] and "stays stopped" in " ".join(planned["undo_notes"])


def test_an_old_capture_without_running_starts_nothing(plane, monkeypatch):
    """A capture written before `running` was recorded: its state is not known, so nothing is
    started, and the plan says so."""
    _wire(monkeypatch, status="stopped")
    out = _rollback(plane, "pve", "qemu", PVE_QEMU)
    point = next(r for r in _rows() if r["action"] == "core.undo_point" and "rollback" in r["detail"])
    detail = dict(point["detail"])
    detail.pop("running")
    entry = {**point, "detail": detail}
    monkeypatch.setattr(undo, "_verified", lambda lcfg, lines: None)
    monkeypatch.setattr(engine, "plan", lambda row, args, *a, **k: {"arguments": args})
    got = undo._rollback(out["undo"]["id"], entry, detail, [], None, plane("pve"), None, None, False, None)
    assert got["arguments"] == {} and "not known" in " ".join(got["undo_notes"])


def test_the_restore_of_a_container_command_says_it_takes_a_further_net(plane, monkeypatch):
    _wire(monkeypatch)
    out = _rollback(plane, "pve", "lxc", PVE_LXC)
    planned = undo.restore(out["undo"]["id"], cfg=plane("pve"))
    assert any("further net" in n for n in planned["undo_notes"])


# --- risk.py: readings of "read" that are not -------------------------------------------------

def test_a_schema_qualified_function_is_not_the_allowlisted_one():
    from proximo.core import risk
    assert risk.classify_sql("SELECT myschema.lower(x) FROM t")[0] != "read"


def test_pg_catalog_is_the_one_schema_that_keeps_the_builtins_trust():
    from proximo.core import risk
    assert risk.classify_sql("SELECT pg_catalog.lower(x) FROM t")[0] == "read"
    assert risk.classify_sql('SELECT "pg_catalog".lower(x) FROM t')[0] == "read"
    for sql in ("SELECT public.lower(x) FROM t", "SELECT a.b.lower(x) FROM t", 'SELECT "myschema".lower(x) FROM t'):
        assert risk.classify_sql(sql)[0] != "read", sql


def test_a_backslash_quote_does_not_hide_a_drop():
    from proximo.core import risk
    assert risk.classify_sql("SELECT 'a\\'' ; DROP TABLE t; --'")[0] != "read"


def test_attribute_notation_calls_a_function_and_reads_as_read():
    """Reported, inherent: `t.fn` is `fn(t)` in PostgreSQL; no parenthesis, no call seen."""
    from proximo.core import risk
    assert risk.classify_sql("SELECT t.fn FROM t")[0] == "read"


def test_a_template_plan_with_the_net_off_says_it_is_off(monkeypatch):
    """Checks the `undo-off-plan` survivor: the template branch of `_safety_net_plan` when off."""
    monkeypatch.setenv(spine.UNDO_ENV, "off")
    row = engine.table()[("pve", "POST", "/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback")]
    net = engine.plan(row, {}, None)["safety_net"]
    assert net["taken"] is False and spine.UNDO_ENV in net["why"]
