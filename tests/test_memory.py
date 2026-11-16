"""The estate memory (core/memory.py): one SQLite file beside the ledger, fed by reads that already
happened, answering where / uses / changed with no model and no network, and `learn`, the one
deliberate pass. The design: "What the cut took" (2026-10-25), piece 3 and the terminal verbs of
piece 4. Ported in intent from 0.44's test_memory.py (the estate map, first and last seen, the
empty-memory answer with no counts, the opt-out, owner-only, isolation per target).
"""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import statistics
import time
from dataclasses import dataclass

import pytest

from proximo.core import consult, doctor, engine, estate, memory, receipt, spine, wire
from proximo.core.doors import cli
from proximo.core.errors import ProximoError

BOX = "https://unreachable.invalid:8006/api2/json"
OTHER_BOX = "https://elsewhere.invalid:8006/api2/json"

RESOURCES = [
    {"id": "node/pve1", "type": "node", "node": "pve1", "status": "online", "maxmem": 1},
    {"id": "storage/pve1/local", "type": "storage", "storage": "local", "node": "pve1", "status": "available",
     "plugintype": "dir", "shared": 0, "content": "iso,backup,rootdir"},
    {"id": "storage/pve1/nas", "type": "storage", "storage": "nas", "node": "pve1", "status": "available",
     "plugintype": "nfs", "shared": 1},
    {"id": "lxc/105", "type": "lxc", "vmid": 105, "node": "pve1", "name": "web", "status": "running",
     "tags": "prod;web", "mem": 1234},
    {"id": "qemu/100", "type": "qemu", "vmid": 100, "node": "pve1", "name": "db", "status": "stopped",
     "pool": "core"},
]

PENDING = {
    "/nodes/pve1/lxc/105/pending": [
        {"key": "hostname", "value": "web"},
        {"key": "rootfs", "value": "local:105/vm-105-disk-0.raw,size=8G"},
        {"key": "net0", "value": "name=eth0,bridge=vmbr0,ip=dhcp"},
    ],
    "/nodes/pve1/qemu/100/pending": [
        {"key": "name", "value": "db"},
        {"key": "scsi0", "value": "nas:100/vm-100-disk-0.qcow2,size=32G"},
        {"key": "ide2", "value": "local:iso/x.iso,media=cdrom"},
        {"key": "net0", "value": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr1"},
        {"key": "boot", "value": "order=scsi0"},
    ],
}

LISTS = {
    "/cluster/resources": RESOURCES,
    "/storage": [{"storage": "local", "type": "dir", "content": "iso,backup"},
                 {"storage": "nas", "type": "nfs", "shared": 1}],
    "/cluster/backup": [{"id": "backup-nightly", "enabled": 1, "vmid": "105", "storage": "nas",
                         "schedule": "02:00"}],
    "/pools": [{"poolid": "core", "members": [{"id": "qemu/100", "type": "qemu", "vmid": 100}]}],
    "/access/acl": [{"path": "/vms/105", "type": "user", "ugid": "ops@pve", "roleid": "PVEVMUser",
                     "propagate": 1}],
    "/nodes/pve1/network": [{"iface": "vmbr0", "type": "bridge", "active": 1},
                            {"iface": "vmbr1", "type": "bridge", "active": 1},
                            {"iface": "eno1", "type": "eth", "active": 1}],
    "/access/permissions": {"/": {"VM.Audit": 1, "Sys.Audit": 1}},
    **PENDING,
}


class _Wire:
    """The vendor, by path. A path it does not hold answers a 500-shaped failure."""

    def __init__(self, bodies, fail=()):
        self.bodies, self.fail, self.calls = dict(bodies), set(fail), []

    def call(self, method, path, params=None):
        self.calls.append(path)
        if path in self.fail or path not in self.bodies:
            raise RuntimeError(f"vendor down for {path}")
        return self.bodies[path]


@dataclass(frozen=True)
class _Cfg(wire.Plane):
    audit_log_path: str = ""
    audit_key_path: str | None = None


@pytest.fixture
def cfg(tmp_path):
    return _Cfg("pve", BOX, "/dev/null", audit_log_path=str(tmp_path / "audit.log"))


@pytest.fixture
def vendor(monkeypatch):
    w = _Wire(LISTS)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    return w


def _read(cfg, path, **kw):
    row = engine.resolve("pve", "GET", path)
    return engine.execute(row, {}, cfg=cfg, ledger_cfg=cfg, path=path, **kw)


def _feed_all(cfg):
    for p in ("/cluster/resources", "/nodes/pve1/lxc/105/pending", "/nodes/pve1/qemu/100/pending",
              "/storage", "/cluster/backup", "/pools", "/access/acl", "/nodes/pve1/network"):
        _read(cfg, p)


def _db(cfg):
    return memory.path(cfg.audit_log_path)


def _where(cfg, words, **kw):
    return memory.where(cfg.audit_log_path, "pve", BOX, words, **kw)


def _plain(p):
    """The file a `sqlite3.connect` argument names: memory opens by URI (`file:<path>?mode=rw&nofollow=1`),
    so a hook matching the bare path would never fire (the lens's porting trap)."""
    from urllib.parse import unquote
    name = str(p)
    return unquote(name[5:].split("?")[0]) if name.startswith("file:") else name


def _keys(answer):
    """Every key anywhere in an answer (the empty-memory rule reads them all)."""
    out = set()

    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                out.add(k)
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
    walk(answer)
    return out


# --- on by default, off creates nothing, owner-only before sqlite opens it ------------------------

def test_memory_is_on_by_default_and_a_read_feeds_it(cfg, vendor):
    assert memory.enabled()
    _read(cfg, "/cluster/resources")
    assert os.path.isfile(_db(cfg))
    assert os.path.dirname(_db(cfg)) == os.path.dirname(cfg.audit_log_path)   # beside the ledger


@pytest.mark.parametrize("off", ["off", "0", "false", "no", "OFF"])
def test_memory_off_creates_nothing(cfg, vendor, monkeypatch, off):
    monkeypatch.setenv("PROXIMO_MEMORY", off)
    assert not memory.enabled()
    _read(cfg, "/cluster/resources")
    assert not any(f.startswith("memory") for f in os.listdir(os.path.dirname(cfg.audit_log_path)))
    with pytest.raises(ProximoError, match="PROXIMO_MEMORY"):
        _where(cfg, "105")


def test_the_file_is_owner_only_before_sqlite_opens_it(cfg, vendor, monkeypatch):
    seen = []
    real = sqlite3.connect

    def connect(p, *a, **k):
        if _plain(p).endswith("memory.db"):
            st = os.lstat(_plain(p))
            seen.append((stat.S_ISREG(st.st_mode), stat.S_IMODE(st.st_mode)))
        return real(p, *a, **k)
    monkeypatch.setattr(sqlite3, "connect", connect)
    _feed_all(cfg)
    assert seen and all(s == (True, 0o600) for s in seen)
    d = os.path.dirname(_db(cfg))
    files = [f for f in os.listdir(d) if f.startswith("memory.db")]
    assert files and all(stat.S_IMODE(os.stat(os.path.join(d, f)).st_mode) == 0o600 for f in files)


def test_a_symlink_at_the_file_is_refused_and_the_read_still_answers(cfg, vendor, tmp_path):
    aim = tmp_path / "elsewhere.db"
    os.symlink(aim, _db(cfg))
    out = _read(cfg, "/cluster/resources")
    assert out["total"] == len(RESOURCES)            # the read is served
    assert not aim.exists()                          # nothing was created where the link points
    with pytest.raises(ProximoError, match="symlink"):
        _where(cfg, "105")


def test_a_file_another_user_can_read_is_refused(cfg, vendor):
    _read(cfg, "/cluster/resources")
    os.chmod(_db(cfg), 0o644)
    with pytest.raises(ProximoError, match="group/other"):
        _where(cfg, "105")
    assert stat.S_IMODE(os.stat(_db(cfg)).st_mode) == 0o644   # refused, never quietly tightened


def test_a_file_another_owner_holds_is_refused(cfg, vendor, monkeypatch):
    _read(cfg, "/cluster/resources")
    monkeypatch.setattr(memory, "_euid", lambda: os.stat(_db(cfg)).st_uid + 1)
    with pytest.raises(ProximoError, match="owned by another user"):
        _where(cfg, "105")


def test_a_memory_failure_never_fails_the_read_that_fed_it(cfg, vendor, monkeypatch):
    def boom(*a, **k):
        raise sqlite3.OperationalError("disk I/O error")
    monkeypatch.setattr(memory, "feed", boom)
    out = _read(cfg, "/cluster/resources")
    assert out["total"] == len(RESOURCES)


def test_the_judging_seam_keeps_nothing_when_a_caller_passes_it(cfg, vendor):
    """THE SEAM: the engine's `_read_data` (a rollback's safety net) passes `judging`; this proves the
    early return on the keeper itself, with the same call kept as the control."""
    row = engine.resolve("pve", "GET", "/cluster/resources")
    engine._keep(row, "/cluster/resources", {}, RESOURCES, cfg, cfg, judging=True)
    assert not os.path.exists(_db(cfg))
    engine._keep(row, "/cluster/resources", {}, RESOURCES, cfg, cfg)       # the control: kept
    assert _where(cfg, "105")["found"] is True


def test_the_store_off_does_not_switch_memory_off(cfg, vendor, monkeypatch):
    monkeypatch.setenv("PROXIMO_STORE", "off")
    _read(cfg, "/cluster/resources")
    assert _where(cfg, "105")["found"] is True


# --- where: the concrete path, never a template, never an invented one -----------------------------

def test_where_an_id_names_kind_node_status_and_the_concrete_path(cfg, vendor):
    _feed_all(cfg)
    out = _where(cfg, "105")
    assert out["found"] is True and out["source"] == "memory"
    (m,) = out["matches"]
    assert (m["kind"], m["id"], m["node"], m["status"], m["name"]) == ("lxc", "105", "pve1", "running", "web")
    assert "GET /nodes/pve1/lxc/105/status/current" in m["paths"]
    assert "GET /nodes/pve1/lxc/105/config" in m["paths"]


def test_every_path_memory_answers_is_a_published_get(cfg, vendor):
    _feed_all(cfg)
    answered = []
    for words in ("105", "100", "pve1", "local", "nas", "core", "backup-nightly", "vmbr0"):   # an ACL subject: no
        out = _where(cfg, words)
        assert out["found"] is True, words
        answered += [p for m in out["matches"] for p in m["paths"]]
    assert len(answered) >= 9
    for p in answered:
        method, _, path = p.partition(" ")
        assert method == "GET" and "{" not in path, p
        assert engine.resolve("pve", "GET", path).access == "read", p


def test_where_takes_the_vendors_words_exactly(cfg, vendor):
    """John, 2026-11-07: the metal says exactly what the vendor gave; the person at the shell, like a
    model, maps their words onto the vendor's. The vendor's id or exact name, after its own type word."""
    _feed_all(cfg)
    assert [m["id"] for m in _where(cfg, "web")["matches"]] == ["105"]
    assert [m["id"] for m in _where(cfg, "lxc 105")["matches"]] == ["105"]
    assert _where(cfg, "qemu 105")["found"] is False          # 105 is the vendor's lxc
    assert [m["id"] for m in _where(cfg, "qemu db")["matches"]] == ["100"]


def test_resolve_is_the_seam_find_will_call(cfg, vendor):
    _feed_all(cfg)
    out = memory.resolve("lxc web", plane="pve", box=BOX, ledger_path=cfg.audit_log_path)
    assert out["paths"][0] == "GET /nodes/pve1/lxc/105/status/current"
    assert out["source"] == "memory" and "age_seconds" in out


def test_not_in_memory_never_says_it_does_not_exist(cfg, vendor, monkeypatch):
    _read(cfg, "/cluster/resources")
    out = _where(cfg, "999")
    assert out["found"] is False and out["verdict"] == "not_in_memory"
    assert {"absent_is_not_proof", "never_learned"} <= set(out["codes"])
    assert out["next"] == ["GET /cluster/resources"]
    assert not {"total", "count", "matches"} & _keys(out)
    memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    monkeypatch.setattr(memory, "_now", lambda: time.time() + 600)
    out = _where(cfg, "999")
    assert "never_learned" not in out["codes"] and 599 <= out["learned_age_seconds"] <= 610


def test_an_empty_memory_answers_with_no_count_at_all(cfg):
    """0.44's hardest-won line: "nothing observed" is not "the estate is empty", and a small model
    reads the number, not the prose beside it. No total, no count, not even an empty list."""
    for out in (_where(cfg, "105"), memory.uses(cfg.audit_log_path, "pve", BOX, "local"),
                memory.changed(cfg.audit_log_path, "pve", BOX, "24h")):
        assert out["source"] == "memory" and out["as_of"] is None and out["age_seconds"] is None
        assert not {"total", "count", "counts", "guests", "added", "gone", "changed", "matches"} & _keys(out), out
        assert out["verdict"] == "not_in_memory" and {"memory_empty", "absent_is_not_proof"} <= set(out["codes"])


# --- uses: who has disks or NICs on it, by the estate's own relations ----------------------------

def test_uses_agrees_with_the_estate_by_construction(cfg, vendor):
    _feed_all(cfg)
    answers = [estate.Answer("/cluster/resources", {}, RESOURCES)] + [
        estate.Answer(f"/nodes/{{node}}/{k}/{{vmid}}/pending", {"node": "pve1", "vmid": v}, PENDING[p])
        for p, k, v in (("/nodes/pve1/lxc/105/pending", "lxc", "105"), ("/nodes/pve1/qemu/100/pending", "qemu", "100"))]
    est = estate.build(answers)
    for thing in ("local", "nas"):
        got = {g["guest"] for g in memory.uses(cfg.audit_log_path, "pve", BOX, thing)["guests"]}
        assert got == {g.key for g in est.guests_on_storage(thing)}, thing
    for thing in ("vmbr0", "vmbr1"):
        got = {g["guest"] for g in memory.uses(cfg.audit_log_path, "pve", BOX, thing)["guests"]}
        assert got == {g.key for g in est.guests_on_bridge(thing)}, thing
    out = memory.uses(cfg.audit_log_path, "pve", BOX, "local")
    assert out["complete"] is True and out["guests"] == [
        {"guest": "lxc/105", "name": "web", "node": "pve1", "status": "running", "via": ["rootfs"]}]


def test_a_cdrom_is_not_a_use_of_its_storage(cfg, vendor):
    _feed_all(cfg)
    assert "qemu/100" not in {g["guest"] for g in memory.uses(cfg.audit_log_path, "pve", BOX, "local")["guests"]}


def test_uses_is_incomplete_while_a_guest_config_is_not_in_memory(cfg, vendor):
    _read(cfg, "/cluster/resources")
    _read(cfg, "/nodes/pve1/lxc/105/pending")
    out = memory.uses(cfg.audit_log_path, "pve", BOX, "nas")
    assert out["complete"] is False and out["unread"] == ["qemu/100"]
    assert out["verdict"] == "incomplete" and out["why"] == ["configs_unread"]
    assert out["next"] == ["GET /nodes/pve1/qemu/100/pending"]


def test_a_detached_disk_leaves_uses(cfg, vendor):
    _feed_all(cfg)
    vendor.bodies["/nodes/pve1/qemu/100/pending"] = [{"key": "name", "value": "db"},
                                                    {"key": "net0", "value": "virtio=AA,bridge=vmbr1"}]
    _read(cfg, "/nodes/pve1/qemu/100/pending")
    assert memory.uses(cfg.audit_log_path, "pve", BOX, "nas")["guests"] == []


def test_answers_stay_bounded_on_a_big_estate(cfg, monkeypatch):
    rows = [{"type": "lxc", "vmid": 1000 + i, "node": "pve1", "name": f"guest-{i}-" + "x" * 300,
             "status": "running"} for i in range(300)]
    memory.feed(cfg.audit_log_path, "pve", BOX, "/cluster/resources", {}, {}, rows,
                source="pve:GET /cluster/resources", untrusted=True)
    for i in range(300):
        memory.feed(cfg.audit_log_path, "pve", BOX, "/nodes/{node}/lxc/{vmid}/pending",
                    {"node": "pve1", "vmid": str(1000 + i)}, {},
                    [{"key": "rootfs", "value": f"local:{1000 + i}/vm-{1000 + i}-disk-0.raw"}],
                    source="pve:GET /nodes/{node}/lxc/{vmid}/pending", untrusted=True)
    out = memory.uses(cfg.audit_log_path, "pve", BOX, "local")
    assert out["total"] == 300 and 0 < len(out["guests"]) <= memory.SHOWN
    assert out["guests_shown"] == len(out["guests"])            # a cut list says how much it shows
    assert all(len(g["name"]) <= memory.TEXT for g in out["guests"])
    assert len(json.dumps(out)) <= memory.ANSWER_BYTES
    assert len(json.dumps(_where(cfg, "guest"))) <= memory.ANSWER_BYTES


# --- changed: added, gone, changed, honestly ------------------------------------------------------

def test_changed_names_added_gone_and_changed(cfg, vendor, monkeypatch):
    t0 = 1_000_000.0
    monkeypatch.setattr(memory, "_now", lambda: t0)
    _read(cfg, "/cluster/resources")
    later = [r for r in RESOURCES if r.get("vmid") != 100]
    later = [{**r, "status": "stopped"} if r.get("vmid") == 105 else r for r in later]
    later.append({"id": "lxc/106", "type": "lxc", "vmid": 106, "node": "pve1", "name": "new", "status": "running"})
    vendor.bodies["/cluster/resources"] = later
    monkeypatch.setattr(memory, "_now", lambda: t0 + 3600)
    _read(cfg, "/cluster/resources")
    out = memory.changed(cfg.audit_log_path, "pve", BOX, "2h")
    assert [a["id"] for a in out["added"]] == ["106"]
    assert [g["id"] for g in out["gone"]] == ["100"]
    assert [(c["id"], c["from"], c["to"]) for c in out["changed"]] == [("105", "running", "stopped")]
    assert out["counts"] == {"added": 1, "gone": 1, "changed": 1}
    assert out["source"] == "memory" and out["age_seconds"] == 0
    # The nightly shape: the whole read that found 100 gone is minutes old, 100 was last seen an hour
    # before it. Asked over 30 minutes, it is gone in that window: when it went, not when last seen.
    out = memory.changed(cfg.audit_log_path, "pve", BOX, "30m")
    assert [g["id"] for g in out["gone"]] == ["100"] and out["gone"][0]["last_seen"] < out["gone"][0]["gone_at"]
    vendor.bodies["/cluster/resources"] = RESOURCES          # 100 seen again: no longer gone; 106 went
    monkeypatch.setattr(memory, "_now", lambda: t0 + 7200)
    _read(cfg, "/cluster/resources")
    assert [g["id"] for g in memory.changed(cfg.audit_log_path, "pve", BOX, "3h")["gone"]] == ["106"]


#: `changed` on PVE as the base commit answered it (captured from that tree, before the shape chose ids).
GOLDEN_CHANGED = (
    '{"source": "memory", "window_s": 7200, "began": "1970-01-12T13:46:40+00:00", "as_of": "1970-01-12T14'
    ':46:40+00:00", "age_seconds": 0, "added": [{"kind": "lxc", "id": "106", "name": "new", "node": "pve1'
    '", "status": "running"}], "gone": [{"kind": "qemu", "id": "100", "name": "db", "node": "pve1", "gone'
    '_at": "1970-01-12T14:46:40+00:00", "last_seen": "1970-01-12T13:46:40+00:00"}], "changed": [{"kind": '
    '"lxc", "id": "105", "name": "web", "node": "pve1", "from": "running", "to": "stopped", "at": "1970-0'
    '1-12T14:46:40+00:00"}], "counts": {"added": 1, "gone": 1, "changed": 1}, "codes": ["gone_by_whole_re'
    'ad", "added_after_first_whole_read"], "untrusted": true}'
)


def test_changed_on_pve_is_byte_identical_to_its_key_shape(cfg, vendor, monkeypatch):
    """PVE's `show` is its key, so `changed` names a guest exactly as it did before the shape chose the
    id: the same keys in the same order, the same bytes."""
    t0 = 1_000_000.0
    monkeypatch.setattr(memory, "_now", lambda: t0)
    _read(cfg, "/cluster/resources")
    later = [r for r in RESOURCES if r.get("vmid") != 100]
    later = [{**r, "status": "stopped"} if r.get("vmid") == 105 else r for r in later]
    later.append({"id": "lxc/106", "type": "lxc", "vmid": 106, "node": "pve1", "name": "new", "status": "running"})
    vendor.bodies["/cluster/resources"] = later
    monkeypatch.setattr(memory, "_now", lambda: t0 + 3600)
    _read(cfg, "/cluster/resources")
    out = memory.changed(cfg.audit_log_path, "pve", BOX, "2h", now=t0 + 3600)
    assert json.dumps(out) == GOLDEN_CHANGED
    db = memory._open(cfg.audit_log_path, create=False)
    with db:
        memory._set(db, "pve", BOX, "learn_sight", "partial")      # PVE's owning never hangs on sight
    memory._settle(cfg.audit_log_path)
    assert json.dumps(memory.changed(cfg.audit_log_path, "pve", BOX, "2h", now=t0 + 3600)) == GOLDEN_CHANGED


def test_the_first_read_is_not_everything_added(cfg, vendor):
    _read(cfg, "/cluster/resources")
    out = memory.changed(cfg.audit_log_path, "pve", BOX, "24h")
    assert out["added"] == [] and out["began"] is not None


def test_a_guest_a_node_list_finds_after_memory_began_is_added_by_the_next_whole_read(cfg, vendor, monkeypatch):
    """A node list only adds or refreshes; the next WHOLE read that lists the guest is what calls it
    added, dated when memory first saw it (after the previous whole read began)."""
    t0 = 1_000_000.0
    monkeypatch.setattr(memory, "_now", lambda: t0)
    _read(cfg, "/cluster/resources")
    vendor.bodies["/nodes/pve1/lxc"] = [{"vmid": 105, "name": "web", "status": "running"},
                                        {"vmid": 107, "name": "fresh", "status": "running"}]
    monkeypatch.setattr(memory, "_now", lambda: t0 + 60)
    _read(cfg, "/nodes/pve1/lxc")
    assert memory.changed(cfg.audit_log_path, "pve", BOX, "1h")["added"] == []
    vendor.bodies["/cluster/resources"] = RESOURCES + [
        {"id": "lxc/107", "type": "lxc", "vmid": 107, "node": "pve1", "name": "fresh", "status": "running"}]
    monkeypatch.setattr(memory, "_now", lambda: t0 + 120)
    _read(cfg, "/cluster/resources")
    assert [a["id"] for a in memory.changed(cfg.audit_log_path, "pve", BOX, "1h")["added"]] == ["107"]


def test_a_node_scoped_read_never_makes_anything_gone(cfg, vendor, monkeypatch):
    t0 = 1_000_000.0
    monkeypatch.setattr(memory, "_now", lambda: t0)
    _read(cfg, "/cluster/resources")
    vendor.bodies["/nodes/pve1/lxc"] = [{"vmid": 105, "name": "web", "status": "running"}]
    monkeypatch.setattr(memory, "_now", lambda: t0 + 60)
    _read(cfg, "/nodes/pve1/lxc")
    assert memory.changed(cfg.audit_log_path, "pve", BOX, "1h")["gone"] == []


def test_a_bad_window_is_refused(cfg, vendor):
    _read(cfg, "/cluster/resources")
    with pytest.raises(ProximoError, match="window"):
        memory.changed(cfg.audit_log_path, "pve", BOX, "yesterday")


# --- taint survives storage -----------------------------------------------------------------------

def test_an_answer_built_from_guest_text_marks_the_session(cfg, vendor, monkeypatch):
    _read(cfg, "/cluster/resources")                      # tracking off: fed, nothing marked
    audit_dir = os.path.dirname(cfg.audit_log_path)
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    assert not spine.is_tainted(audit_dir)
    out = _where(cfg, "web")
    assert out["untrusted"] is True
    assert spine.is_tainted(audit_dir)


def test_an_answer_from_trusted_reads_alone_marks_nothing(cfg, vendor, monkeypatch):
    """The control: `/storage` is not an untrusted address, so its rows carry no mark."""
    _read(cfg, "/storage")
    audit_dir = os.path.dirname(cfg.audit_log_path)
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    out = _where(cfg, "nas")
    assert out["found"] is True and "untrusted" not in out
    assert not spine.is_tainted(audit_dir)


def test_the_untrusted_mark_is_in_the_file(cfg, vendor):
    _read(cfg, "/cluster/resources")
    with sqlite3.connect(_db(cfg)) as db:
        marks = dict(db.execute("SELECT key, untrusted FROM entity WHERE kind='lxc'"))
    assert marks == {"105": 1}


def test_a_marker_that_cannot_be_written_refuses_the_answer(cfg, vendor, monkeypatch):
    _read(cfg, "/cluster/resources")
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")

    def cannot(*a, **k):
        raise OSError("read-only")
    monkeypatch.setattr(spine, "mark_tainted", cannot)
    with pytest.raises(ProximoError, match="taint marker"):
        _where(cfg, "web")


def test_a_fenced_answer_wraps_the_guest_text(cfg, vendor, monkeypatch):
    _read(cfg, "/cluster/resources")
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", "1")
    out = _where(cfg, "web")
    assert out["matches"]["proximo_untrusted"] is True and "web" in out["matches"]["data"]


def test_the_seam_keeps_its_paths_outside_the_fence(cfg, vendor, monkeypatch):
    """Find runs with the fence on; the paths carry vendor ids only, so they stay readable."""
    _read(cfg, "/cluster/resources")
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", "1")
    out = memory.resolve("lxc web", plane="pve", box=BOX, ledger_path=cfg.audit_log_path)
    assert out["paths"][0] == "GET /nodes/pve1/lxc/105/status/current"
    assert out["matches"]["proximo_untrusted"] is True


# --- bounded, per box, derived --------------------------------------------------------------------

def test_the_file_is_bounded_and_says_what_it_dropped(cfg, monkeypatch):
    monkeypatch.setattr(memory, "MAX_ENTITIES", 50)
    clock = iter(range(1, 10_000))
    monkeypatch.setattr(memory, "_now", lambda: float(next(clock)))
    for i in range(80):
        memory.feed(cfg.audit_log_path, "pve", BOX, "/cluster/resources", {"type": "vm"}, {},
                    [{"type": "lxc", "vmid": 2000 + i, "node": "pve1", "name": "n" * 500, "status": "running"}],
                    source="pve:GET /cluster/resources", untrusted=True)
    with sqlite3.connect(_db(cfg)) as db:
        (n,) = db.execute("SELECT count(*) FROM entity").fetchone()
        (longest,) = db.execute("SELECT max(length(name)) FROM entity").fetchone()
    assert n == 50 and longest <= memory.TEXT
    assert memory.status(cfg.audit_log_path)["evicted"] == 30
    assert _where(cfg, "2079")["found"] is True and _where(cfg, "2000")["found"] is False   # oldest go first


def test_a_read_over_the_row_cap_is_not_kept(cfg, monkeypatch):
    monkeypatch.setattr(memory, "MAX_ROWS", 10)
    rows = [{"type": "lxc", "vmid": 3000 + i, "node": "pve1", "status": "running"} for i in range(11)]
    memory.feed(cfg.audit_log_path, "pve", BOX, "/cluster/resources", {}, {}, rows,
                source="pve:GET /cluster/resources", untrusted=True)
    assert _where(cfg, "3000")["found"] is False
    assert memory.status(cfg.audit_log_path)["skipped"] == 1


def test_two_boxes_behind_one_ledger_never_mix(cfg, vendor):
    """Both boxes FED, then each asked for the other's guest (the lens: with the second box never fed,
    `where` answered empty before any entity query ran, and a dropped box filter stayed green)."""
    _read(cfg, "/cluster/resources")
    memory.feed(cfg.audit_log_path, "pve", OTHER_BOX, "/cluster/resources", {}, {},
                [{"type": "lxc", "vmid": 777, "node": "pve9", "status": "running"}], source="s", untrusted=False)
    assert _where(cfg, "105")["found"] is True and _where(cfg, "777")["found"] is False
    assert memory.where(cfg.audit_log_path, "pve", OTHER_BOX, "777")["found"] is True
    assert memory.where(cfg.audit_log_path, "pve", OTHER_BOX, "105")["found"] is False


def test_deleting_the_file_loses_convenience_never_proof(cfg, vendor):
    _feed_all(cfg)
    os.unlink(_db(cfg))
    from proximo.core.ledger import open_ledger
    assert open_ledger(cfg).verify().ok
    assert _where(cfg, "105")["found"] is False
    _read(cfg, "/cluster/resources")
    assert _where(cfg, "105")["found"] is True


def test_memory_keeps_no_search_index(cfg, vendor):
    """The FTS index served fuzzy matching only; it went with it (schema 3). No index, no advice."""
    _feed_all(cfg)
    with sqlite3.connect(_db(cfg)) as db:
        names = {n for (n,) in db.execute("SELECT name FROM sqlite_master")}
    assert not any(n == "words" or n.startswith("words_") for n in names)
    flags = []
    section = memory.station(cfg, flags)
    assert "fts5" not in section and "search" not in section and flags == []


def test_a_v2_file_with_a_search_index_is_rebuilt_without_it(cfg, vendor):
    _feed_all(cfg)
    with sqlite3.connect(_db(cfg)) as db:
        db.execute("CREATE VIRTUAL TABLE words USING fts5(key, name, tags)")
        db.execute("PRAGMA user_version = 2")
    memory._local.__dict__.pop("conns", None)                 # a new process opens it
    _feed_all(cfg)
    with sqlite3.connect(_db(cfg)) as db:
        names = {n for (n,) in db.execute("SELECT name FROM sqlite_master")}
        (ver,) = db.execute("PRAGMA user_version").fetchone()
    assert ver == 3 and not any(n == "words" or n.startswith("words_") for n in names)
    assert _where(cfg, "web", receipt=False)["found"] is True


def test_doctor_reports_memory_state_and_never_a_path(cfg, vendor):
    _feed_all(cfg)
    flags = []
    section = memory.station(cfg, flags)
    assert section["on"] is True and section["entities"] >= 8 and flags == []
    assert os.path.dirname(cfg.audit_log_path) not in json.dumps(section)


# --- learn: the one deliberate pass ---------------------------------------------------------------

def test_learn_reads_every_source_through_execute_and_says_complete(cfg, vendor, monkeypatch):
    seen = []
    real = engine.execute

    def counted(row, *a, **k):
        seen.append(k.get("path"))
        return real(row, *a, **k)
    monkeypatch.setattr(engine, "execute", counted)
    out = memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is True, out
    assert set(seen) == {"/cluster/resources", "/access/permissions", "/storage", "/cluster/backup", "/pools",
                         "/access/acl", "/nodes/pve1/network", "/nodes/pve1/lxc/105/pending",
                         "/nodes/pve1/qemu/100/pending"}
    assert out["reads"] == len(seen) == len(vendor.calls)          # every vendor call was a governed read
    from proximo.core.ledger import open_ledger
    rows = [json.loads(line) for line in open(cfg.audit_log_path, encoding="utf-8") if line.strip()]
    assert sum(1 for r in rows if r.get("action") == "core.execute") >= len(seen)   # receipted
    assert open_ledger(cfg).verify().ok
    assert memory.uses(cfg.audit_log_path, "pve", BOX, "nas")["complete"] is True
    assert memory.status(cfg.audit_log_path)["learned"] == {"pve": "complete"}


def test_learn_over_its_budget_is_incomplete_and_names_it(cfg, vendor, monkeypatch):
    monkeypatch.setattr(memory, "LEARN_MAX_READS", 4)
    out = memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "budget" in out["why"]
    assert out["reads"] == 4


def test_learn_with_a_failed_read_is_incomplete(cfg, vendor):
    vendor.fail.add("/nodes/pve1/qemu/100/pending")
    out = memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "qemu/100" in out["why"]


def test_learn_when_the_token_cannot_see_every_guest_is_incomplete(cfg, vendor):
    vendor.bodies["/access/permissions"] = {"/": {"Sys.Audit": 1}, "/vms/105": {"VM.Audit": 1}}
    out = memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "VM.Audit" in out["why"]


def test_learn_with_memory_off_refuses_before_any_read(cfg, vendor, monkeypatch):
    monkeypatch.setenv("PROXIMO_MEMORY", "off")
    with pytest.raises(ProximoError, match="PROXIMO_MEMORY"):
        memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert vendor.calls == []


def test_memory_never_dials_on_its_own(cfg, vendor):
    _read(cfg, "/cluster/resources")
    assert vendor.calls == ["/cluster/resources"]          # one read, one call: feeding reads nothing
    _where(cfg, "105")
    memory.uses(cfg.audit_log_path, "pve", BOX, "local")
    memory.changed(cfg.audit_log_path, "pve", BOX, "24h")
    assert vendor.calls == ["/cluster/resources"]


def test_learn_reads_the_guest_configs_consult_reads():
    assert set(memory.FANOUT) == set(consult.FANOUT["guest_config"].templates.values())


# --- the estate's own relations -------------------------------------------------------------------

def test_the_estate_names_its_relations_and_memory_keeps_them(cfg, vendor):
    _feed_all(cfg)
    with sqlite3.connect(_db(cfg)) as db:
        rels = {r for (r,) in db.execute("SELECT DISTINCT rel FROM edge")}
    assert rels <= set(estate.RELATIONS)
    assert rels >= {"runs_on", "disk_on", "nic_on", "in_pool", "covered_by", "granted_on"}


# --- the shell door -------------------------------------------------------------------------------

@pytest.fixture
def door(cfg, vendor, monkeypatch):
    monkeypatch.setenv("PROXIMO_API_BASE_URL", BOX)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", cfg.audit_log_path)     # the door's ledger is the test's
    _feed_all(cfg)
    return cfg


def test_the_shell_door_answers_where_uses_and_changed(door, capsys):
    assert cli.main(["where", "105"]) == cli.EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["matches"][0]["paths"][0] == "GET /nodes/pve1/lxc/105/status/current"
    assert cli.main(["uses", "local"]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["guests"][0]["guest"] == "lxc/105"
    assert cli.main(["changed", "24h"]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["source"] == "memory"
    assert cli.main(["where", "999"]) == cli.EXIT_OK          # an honest "not in memory" is an answer
    assert json.loads(capsys.readouterr().out)["found"] is False


def test_the_shell_door_refuses_a_verb_it_cannot_answer_as_the_callers_mistake(door, monkeypatch, capsys):
    assert cli.main(["changed", "soon"]) == cli.EXIT_USAGE
    assert cli.main(["where"]) == cli.EXIT_USAGE
    assert cli.main(["where", "105", "--plane", "nope"]) == cli.EXIT_USAGE     # no shape for a made-up plane
    monkeypatch.delenv("PROXIMO_API_BASE_URL")
    assert cli.main(["where", "105"]) == cli.EXIT_USAGE        # no box: never box ""
    monkeypatch.setenv("PROXIMO_API_BASE_URL", BOX)
    monkeypatch.setenv("PROXIMO_MEMORY", "off")
    assert cli.main(["where", "105"]) == cli.EXIT_USAGE
    capsys.readouterr()


def test_the_shell_door_learns(door, capsys):
    assert cli.main(["learn"]) == cli.EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["complete"] is True and out["source"] == "live"


# --- latency: from the file, under a millisecond on a 100-guest file -------------------------------

def test_each_verb_answers_a_hundred_guest_file_fast(cfg):
    rows = [{"type": "node", "node": "pve1", "status": "online"},
            {"type": "storage", "storage": "local", "node": "pve1", "status": "available"}]
    rows += [{"type": "lxc" if i % 2 else "qemu", "vmid": 100 + i, "node": "pve1", "name": f"g{i}",
              "status": "running", "tags": "prod"} for i in range(100)]
    memory.feed(cfg.audit_log_path, "pve", BOX, "/cluster/resources", {}, {}, rows,
                source="pve:GET /cluster/resources", untrusted=False)
    for i in range(100):
        kind = "lxc" if i % 2 else "qemu"
        memory.feed(cfg.audit_log_path, "pve", BOX, f"/nodes/{{node}}/{kind}/{{vmid}}/pending",
                    {"node": "pve1", "vmid": str(100 + i)}, {},
                    [{"key": "rootfs" if kind == "lxc" else "scsi0", "value": f"local:{100 + i}/vm-{100 + i}-disk-0"},
                     {"key": "net0", "value": "bridge=vmbr0"}],
                    source="pve:GET /nodes/{node}/lxc/{vmid}/pending", untrusted=False)
    timings = {}
    for verb, fn in (("where", lambda: _where(cfg, "150")),
                     ("uses", lambda: memory.uses(cfg.audit_log_path, "pve", BOX, "local")),
                     ("changed", lambda: memory.changed(cfg.audit_log_path, "pve", BOX, "24h"))):
        fn()
        samples = []
        for _ in range(50):
            t = time.perf_counter()
            fn()
            samples.append(time.perf_counter() - t)
        timings[verb] = statistics.median(samples)
    # Measured on the build box (2026-10-26) with the thread's connection held, as a long-lived door
    # holds it: medians of about 0.16 ms (where), 0.40 ms (uses), 0.19 ms (changed); a fresh connection,
    # as the shell door makes once per process, adds about 0.7 ms of open and schema parse.
    # Pinned loosely so a slow CI runner does not flake; a full scan with Python-side joins shows here.
    assert all(t < 0.005 for t in timings.values()), timings



# ======================== round 2 (lens 1 folded) ==================================================

def _gone(cfg, window="2h"):
    return [g["id"] for g in memory.changed(cfg.audit_log_path, "pve", BOX, window)["gone"]]


def _feed(cfg, template, rows, bound=None, args=None, untrusted=False, fields=None, source="s"):
    memory.feed(cfg.audit_log_path, "pve", BOX, template, bound or {}, args or {}, rows, source=source,
                untrusted=untrusted, fields=fields)


# --- 1a: only a WHOLE read can retire or begin -----------------------------------------------------

@pytest.mark.parametrize("args,fields",
                         [({"type": "vm"}, None), ({}, "type,vmid,node,status"), ({"type": "node"}, None)])
def test_a_filtered_or_projected_resources_read_never_retires(cfg, monkeypatch, args, fields):
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _feed(cfg, "/cluster/resources", RESOURCES)
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    _feed(cfg, "/cluster/resources", [r for r in RESOURCES if r.get("vmid") != 100], args=args, fields=fields)
    assert _gone(cfg) == []


def test_an_empty_resources_read_never_retires(cfg, monkeypatch):
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _feed(cfg, "/cluster/resources", RESOURCES)
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    _feed(cfg, "/cluster/resources", [])
    assert _gone(cfg) == []


def test_a_box_with_no_name_never_retires(cfg, monkeypatch):
    for t, rows in ((1_000_000.0, RESOURCES), (1_000_060.0, RESOURCES[:1])):
        monkeypatch.setattr(memory, "_now", lambda t=t: t)
        memory.feed(cfg.audit_log_path, "pve", "", "/cluster/resources", {}, {}, rows, source="s", untrusted=False)
    assert memory.changed(cfg.audit_log_path, "pve", "", "2h")["gone"] == []


def test_the_engines_own_reads_feed_entities_but_never_retire(cfg, vendor, monkeypatch):
    """A content delete's plan consults (`GET /cluster/resources type=vm` with a field subset, each
    guest's pending): real governed reads, so they feed entities; filtered, so they retire nothing."""
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _read(cfg, "/cluster/resources")
    vendor.bodies["/cluster/resources"] = [r for r in RESOURCES if r.get("vmid") != 100]
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    concrete = "/nodes/pve1/storage/local/content/local:105%2Fvm-105-disk-0.raw"
    engine.plan(engine.resolve("pve", "DELETE", concrete), {}, path=concrete, cfg=cfg, ledger_cfg=cfg)
    assert any(p.startswith("/cluster/resources") for p in vendor.calls[1:])
    assert _where(cfg, "105")["found"] is True and _gone(cfg) == []


def test_memory_holds_the_vendors_answer_before_the_doors_cap(cfg, vendor, monkeypatch):
    """The cap bounds what a model is handed; the hook is fed the vendor's answer before it, so a read
    the door served as a summary is whole to memory."""
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "2048")
    vendor.bodies["/cluster/resources"] = [{"type": "lxc", "vmid": 1000 + i, "node": "pve1", "status": "running"}
                                           for i in range(300)]
    out = _read(cfg, "/cluster/resources")
    assert "data" not in out                                   # the model got a summary
    assert _where(cfg, "1299")["found"] is True


# --- 2: uses is complete only when it is ----------------------------------------------------------

def test_uses_is_incomplete_without_a_whole_resources_read(cfg, vendor):
    _read(cfg, "/nodes/pve1/lxc/105/pending")
    out = memory.uses(cfg.audit_log_path, "pve", BOX, "nas")
    assert out["complete"] is False and "no_whole_read" in out["why"]
    assert out["next"][0] == "GET /cluster/resources"


def test_uses_is_incomplete_from_one_node_list(cfg, vendor):
    vendor.bodies["/nodes/pve1/lxc"] = [{"vmid": 105, "name": "web", "status": "running"}]
    _read(cfg, "/nodes/pve1/lxc")
    _read(cfg, "/nodes/pve1/lxc/105/pending")
    assert memory.uses(cfg.audit_log_path, "pve", BOX, "nas")["complete"] is False


def test_uses_is_incomplete_after_learn_saw_part(cfg, vendor):
    vendor.bodies["/access/permissions"] = {"/": {"Sys.Audit": 1}, "/vms/105": {"VM.Audit": 1}}
    memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    out = memory.uses(cfg.audit_log_path, "pve", BOX, "nas")
    assert out["complete"] is False and "partial_sight" in out["why"]
    vendor.bodies["/access/permissions"] = LISTS["/access/permissions"]
    memory.learn("pve", cfg=cfg, ledger_cfg=cfg)                 # a later learn that sees it all clears it
    assert memory.uses(cfg.audit_log_path, "pve", BOX, "nas")["complete"] is True


def test_a_learn_that_dies_midway_leaves_partial_sight_never_a_stale_whole(cfg, vendor, monkeypatch):
    from proximo.core import memory_pve
    memory.learn("pve", cfg=cfg, ledger_cfg=cfg)                 # a whole learn: the sight reads whole
    assert memory.uses(cfg.audit_log_path, "pve", BOX, "nas")["complete"] is True
    whole = memory_pve._Pve.learn

    def dies(self, read, db_at, box, start, gaps, **kw):
        read("/cluster/resources", "/cluster/resources")      # began reading, then died before its tally
        raise RuntimeError("killed")
    monkeypatch.setattr(memory_pve._Pve, "learn", dies)
    with pytest.raises(RuntimeError):
        memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    monkeypatch.setattr(memory_pve._Pve, "learn", whole)
    out = memory.uses(cfg.audit_log_path, "pve", BOX, "nas")
    assert out["complete"] is False and "partial_sight" in out["why"]


def test_uses_is_incomplete_after_edges_were_evicted(cfg, vendor, monkeypatch):
    _feed_all(cfg)
    monkeypatch.setattr(memory, "MAX_EDGES", 2)
    _read(cfg, "/storage")
    with sqlite3.connect(_db(cfg)) as db:
        (m,) = db.execute("SELECT count(*) FROM edge").fetchone()
    assert m <= 2
    out = memory.uses(cfg.audit_log_path, "pve", BOX, "nas")
    assert out["complete"] is False and "edges_evicted" in out["why"]
    assert memory.status(cfg.audit_log_path)["evicted_edges"] > 0


def test_a_gone_guest_is_not_a_user(cfg, vendor, monkeypatch):
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _feed_all(cfg)
    vendor.bodies["/cluster/resources"] = [r for r in RESOURCES if r.get("vmid") != 100]
    monkeypatch.setattr(memory, "_now", lambda: 1_003_600.0)
    _read(cfg, "/cluster/resources")
    out = memory.uses(cfg.audit_log_path, "pve", BOX, "nas")
    assert out["guests"] == [] and out["complete"] is True


# --- 3: bounded, measured on the final bytes --------------------------------------------------------

def test_every_answer_fits_after_its_paths_and_its_fence(cfg, monkeypatch):
    rows = [{"type": "storage", "storage": f"zstore{i}", "node": "n" * 58 + f"{k:02d}", "status": "available"}
            for i in range(5) for k in range(3)]
    _feed(cfg, "/cluster/resources", rows)
    assert len(json.dumps(_where(cfg, "zstore"))) <= memory.ANSWER_BYTES
    rows = [{"type": "lxc", "vmid": 800 + i, "node": "pve1", "name": '"' * 119, "status": "running", "tags": "fence"}
            for i in range(30)]
    _feed(cfg, "/cluster/resources", rows, untrusted=True)
    for i in range(30):
        _feed(cfg, "/nodes/{node}/lxc/{vmid}/pending", [{"key": "rootfs", "value": "local:1/x.raw"}],
              bound={"node": "pve1", "vmid": str(800 + i)}, untrusted=True)
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", "1")
    for out in (_where(cfg, "fence"), memory.uses(cfg.audit_log_path, "pve", BOX, "local"),
                memory.changed(cfg.audit_log_path, "pve", BOX, "24h")):
        assert len(json.dumps(out)) <= memory.ANSWER_BYTES, len(json.dumps(out))


def test_one_row_bigger_than_the_answer_is_cut_not_dropped(cfg, monkeypatch):
    """At the default cap a bounded row never exceeds the answer (the lens's plant: `_shrink` as the
    identity stayed green), so the cap is lowered until the lone row must be cut, and the cut row is
    still there with its paths whole."""
    rows = [{"type": "storage", "storage": "wide", "node": f"n{k:03d}", "status": "available" if k else "unknown"}
            for k in range(300)]
    _feed(cfg, "/cluster/resources", rows)
    with sqlite3.connect(_db(cfg)) as db:
        (st, node) = db.execute("SELECT length(status), length(node) FROM entity WHERE key='wide'").fetchone()
    assert st <= memory.TEXT and node <= memory.TEXT
    out = _where(cfg, "wide")
    assert out["found"] is True and len(out["matches"]) == 1 and out["paths"]
    assert len(json.dumps(out)) <= memory.ANSWER_BYTES
    _feed(cfg, "/cluster/resources", [{"type": "lxc", "vmid": 909, "node": "pve1", "name": "x" * 119,
                                      "status": "running", "tags": "y" * 119}])
    out = _where(cfg, "909")
    whole = len(json.dumps(out))
    monkeypatch.setattr(memory, "ANSWER_BYTES", whole - 1)
    cut = _where(cfg, "909")
    assert cut["found"] is True and len(cut["matches"]) == 1 and cut["paths"] == out["paths"]
    assert len(cut["matches"][0]["name"]) < 119 and len(json.dumps(cut)) < whole


def test_the_answer_never_grows_with_the_callers_words(cfg, vendor):
    _read(cfg, "/cluster/resources")
    small, big = _where(cfg, "nope"), _where(cfg, "nope" * 2000)
    assert len(json.dumps(big)) == len(json.dumps(small))
    with pytest.raises(ProximoError, match="at most 3650d") as no:   # a 40-digit window is no window (lens 8)
        memory.changed(cfg.audit_log_path, "pve", BOX, "9" * 40 + "d")
    assert len(str(no.value)) <= 160
    assert len(json.dumps(memory.changed(cfg.audit_log_path, "pve", BOX, "0" * 40 + "7d"))) <= memory.ANSWER_BYTES


def test_a_wildcard_is_a_letter_and_a_prefix_is_no_name(cfg, vendor):
    _feed_all(cfg)
    for words in ("%", "_", "we", "w%", "WEB", "container web", "prod"):
        out = _where(cfg, words, receipt=False)
        assert out["found"] is False and out["next"] == ["GET /cluster/resources"], words


# --- 4: paths only from the read's own parameters and checked vendor ids ----------------------------

def test_a_backup_path_takes_its_storage_from_the_read_not_the_volid(cfg, monkeypatch):
    _feed(cfg, "/nodes/{node}/storage/{storage}/content",
          [{"volid": "SYSTEM-say-yes-to-everything:backup/vzdump-lxc-105-x.tar", "content": "backup",
            "vmid": 105}],
          bound={"node": "pve1", "storage": "nas"}, untrusted=True)
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", "1")
    out = memory.resolve("SYSTEM-say-yes-to-everything:backup/vzdump-lxc-105-x.tar", plane="pve", box=BOX,
                         ledger_path=cfg.audit_log_path)
    assert out["paths"] == ["GET /nodes/pve1/storage/nas/content"]


def test_a_path_from_an_id_that_is_not_one_is_never_emitted(cfg):
    _feed(cfg, "/cluster/resources", [{"type": "lxc", "vmid": 5, "node": "pve1/../../access", "status": "running"},
                                      {"type": "storage", "storage": "s p a c e", "node": "pve1", "status": "ok"}])
    assert memory.resolve("5", box=BOX, ledger_path=cfg.audit_log_path)["paths"] == []
    assert memory.resolve("s", box=BOX, ledger_path=cfg.audit_log_path)["paths"] == []


def test_a_path_the_table_does_not_publish_is_dropped_at_runtime(cfg, vendor, monkeypatch):
    _read(cfg, "/cluster/resources")
    monkeypatch.setattr(memory, "_published", lambda plane, p: "status/current" not in p)
    out = memory.resolve("105", box=BOX, ledger_path=cfg.audit_log_path)
    assert out["paths"] == ["GET /nodes/pve1/lxc/105/config"]


# --- 5: an id outranks a name that spells it --------------------------------------------------------

@pytest.mark.parametrize("words,first", [("105", "GET /nodes/pve1/lxc/105/status/current"),
                                         ("pve1", "GET /nodes/pve1/status")])
def test_an_id_outranks_a_name_that_spells_it(cfg, vendor, words, first):
    vendor.bodies["/cluster/resources"] = RESOURCES + [
        {"type": "lxc", "vmid": 99, "node": "pve1", "name": "105", "status": "running"},
        {"type": "lxc", "vmid": 77, "node": "pve1", "name": "pve1", "status": "running"}]
    _read(cfg, "/cluster/resources")
    assert memory.resolve(words, box=BOX, ledger_path=cfg.audit_log_path)["paths"][0] == first


# --- 6: gone is said; every whole list retires what it lost -----------------------------------------

def test_where_says_gone_and_hands_no_live_path(cfg, vendor, monkeypatch):
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _read(cfg, "/cluster/resources")
    vendor.bodies["/cluster/resources"] = [r for r in RESOURCES if r.get("vmid") != 100]
    monkeypatch.setattr(memory, "_now", lambda: 1_003_600.0)
    _read(cfg, "/cluster/resources")
    (m,) = _where(cfg, "100")["matches"]
    assert m["status"] == "gone" and m["gone_at"] and m["paths"] == []


def test_a_whole_list_retires_what_it_no_longer_has(cfg, vendor, monkeypatch):
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _feed_all(cfg)
    _feed(cfg, "/nodes/{node}/storage/{storage}/content",
          [{"volid": "nas:backup/vzdump-lxc-105-x.tar.zst", "format": "tar.zst", "content": "backup", "vmid": 105}],
          bound={"node": "pve1", "storage": "nas"})
    for p in ("/access/acl", "/cluster/backup", "/pools"):
        vendor.bodies[p] = []
    vendor.bodies["/nodes/pve1/network"] = [{"iface": "vmbr1", "type": "bridge", "active": 1}]
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    for p in ("/access/acl", "/cluster/backup", "/pools", "/nodes/pve1/network"):
        _read(cfg, p)
    _feed(cfg, "/nodes/{node}/storage/{storage}/content", [], bound={"node": "pve1", "storage": "nas"})
    assert sorted(_gone(cfg)) == sorted(["/vms/105 user/ops@pve PVEVMUser", "backup-nightly", "core", "pve1/vmbr0",
                                         "nas:backup/vzdump-lxc-105-x.tar.zst"])
    with sqlite3.connect(_db(cfg)) as db:
        left = db.execute("SELECT count(*) FROM edge WHERE rel IN ('granted_on','covered_by','in_pool')").fetchone()
        assert left == (0,)


def test_a_filtered_content_read_retires_nothing(cfg, monkeypatch):
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    rows = [{"volid": "nas:backup/a.tar", "content": "backup", "vmid": 105}]
    _feed(cfg, "/nodes/{node}/storage/{storage}/content", rows, bound={"node": "pve1", "storage": "nas"})
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    _feed(cfg, "/nodes/{node}/storage/{storage}/content", [], bound={"node": "pve1", "storage": "nas"},
          args={"vmid": "106"})
    assert _gone(cfg) == []


# --- 7: where memory began, per whole read; owners retire their own facts ---------------------------

def test_a_first_whole_read_after_a_node_list_adds_nothing(cfg, vendor, monkeypatch):
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    vendor.bodies["/nodes/pve1/lxc"] = [{"vmid": 105, "name": "web", "status": "running"}]
    _read(cfg, "/nodes/pve1/lxc")
    vendor.bodies["/cluster/resources"] = RESOURCES + [
        {"type": "lxc", "vmid": 300, "node": "pve2", "name": "old-guest", "status": "running"}]
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    _read(cfg, "/cluster/resources")
    assert memory.changed(cfg.audit_log_path, "pve", BOX, "1h")["added"] == []


def test_a_first_whole_read_after_one_pending_read_adds_nothing(cfg, vendor, monkeypatch):
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _read(cfg, "/nodes/pve1/qemu/100/pending")
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    _read(cfg, "/cluster/resources")
    assert memory.changed(cfg.audit_log_path, "pve", BOX, "1h")["added"] == []


def test_an_evicted_then_reseen_guest_is_not_added(cfg, monkeypatch):
    monkeypatch.setattr(memory, "MAX_ENTITIES", 3)
    t = iter(range(1, 100))
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0 + next(t))
    rows = [{"id": f"lxc/{500 + i}", "type": "lxc", "vmid": 500 + i, "node": "pve1", "status": "running"}
            for i in range(3)]
    new = [{"id": "lxc/600", "type": "lxc", "vmid": 600, "node": "pve1", "status": "running"}]
    _feed(cfg, "/cluster/resources", rows)
    _feed(cfg, "/cluster/resources", rows[1:] + new)
    with sqlite3.connect(_db(cfg)) as db:
        assert "500" not in {k for (k,) in db.execute("SELECT key FROM entity")}
    _feed(cfg, "/cluster/resources", rows[:2] + new)
    added = [a["id"] for a in memory.changed(cfg.audit_log_path, "pve", BOX, "1h")["added"]]
    assert "500" not in added and "600" in added


def test_a_disabled_storage_the_definitions_hold_does_not_flap(cfg, vendor, monkeypatch):
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    vendor.bodies["/storage"] = LISTS["/storage"] + [{"storage": "cold", "type": "dir", "disable": 1}]
    _read(cfg, "/storage")
    _read(cfg, "/cluster/resources")
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    _read(cfg, "/cluster/resources")
    assert "cold" not in _gone(cfg)
    vendor.bodies["/storage"] = LISTS["/storage"]                 # its owner drops it: now it is gone
    monkeypatch.setattr(memory, "_now", lambda: 1_000_120.0)
    _read(cfg, "/storage")
    assert "cold" in _gone(cfg)


_X = [{"id": "storage/pve1/x", "type": "storage", "storage": "x", "node": "pve1", "status": "available"}]


def _x_dropped_by_resources(cfg, monkeypatch):
    """`/storage` never read whole: `resources` is the one owner of storage x, and its whole read drops x
    (as it is thought to drop a storage disabled in the definitions: the claim the rule guards against,
    unverified, not seen live)."""
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _feed(cfg, "/cluster/resources", RESOURCES + _X)
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    _feed(cfg, "/cluster/resources", RESOURCES)
    assert _gone(cfg) == ["x"]
    monkeypatch.setattr(memory, "_now", lambda: 1_000_120.0)


@pytest.mark.parametrize("how", [{"args": {"type": "dir"}}, {"fields": "storage,type"}, {"evaluating": True}],
                         ids=["an-argument", "a-field-subset", "the-doors-own-look"])
def test_a_storage_list_read_that_cannot_own_never_brings_back_a_storage_resources_dropped(cfg, monkeypatch, how):
    """A `/storage` read that cannot own lists x: it feeds no storage, so x stays gone, dated by the drop,
    and the next `resources` read does not retire it a second time."""
    _x_dropped_by_resources(cfg, monkeypatch)
    memory.feed(cfg.audit_log_path, "pve", BOX, "/storage", {}, how.get("args", {}),
                [{"storage": "x", "type": "dir", "disable": 1}], source="s", untrusted=False,
                fields=how.get("fields"), evaluating=how.get("evaluating", False))
    assert _gone(cfg) == ["x"]
    monkeypatch.setattr(memory, "_now", lambda: 1_000_180.0)
    _feed(cfg, "/cluster/resources", RESOURCES)
    with sqlite3.connect(_db(cfg)) as db:
        assert db.execute("SELECT gone_at FROM entity WHERE kind='storage' AND key='x'").fetchone() == (1_000_060.0,)
    out = memory.changed(cfg.audit_log_path, "pve", BOX, "1h")
    assert [g["gone_at"] for g in out["gone"] if g["id"] == "x"] == [memory._iso(1_000_060.0)]


def test_a_whole_storage_list_read_still_feeds_and_owns_a_storage_resources_dropped(cfg, monkeypatch):
    """The control: a whole `/storage` read lists x, so x is back and `/storage` holds it; a `resources`
    read without it keeps it; the whole `/storage` read without it retires it, dated by that read."""
    _x_dropped_by_resources(cfg, monkeypatch)
    _feed(cfg, "/storage", [{"storage": "local", "type": "dir"}, {"storage": "x", "type": "dir", "disable": 1}])
    assert _gone(cfg) == []
    monkeypatch.setattr(memory, "_now", lambda: 1_000_180.0)
    _feed(cfg, "/cluster/resources", RESOURCES)
    assert _gone(cfg) == []
    monkeypatch.setattr(memory, "_now", lambda: 1_000_240.0)
    _feed(cfg, "/storage", [{"storage": "local", "type": "dir"}])
    with sqlite3.connect(_db(cfg)) as db:
        assert db.execute("SELECT gone_at FROM entity WHERE kind='storage' AND key='x'").fetchone() == (1_000_240.0,)


# --- 9: the survivors -------------------------------------------------------------------------------

def test_a_trusted_read_never_clears_the_untrusted_mark_or_its_source(cfg, vendor):
    _read(cfg, "/cluster/resources")                    # untrusted: storage rows ride it
    _read(cfg, "/storage")                               # trusted, the same storage
    with sqlite3.connect(_db(cfg)) as db:
        assert db.execute("SELECT untrusted, source FROM entity WHERE kind='storage' AND key='local'").fetchone() \
            == (1, "pve:GET /cluster/resources")


def test_uses_and_changed_mark_the_session(cfg, vendor, monkeypatch):
    from proximo.core import spine as sp
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _feed_all(cfg)
    audit_dir = os.path.dirname(cfg.audit_log_path)
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    assert memory.uses(cfg.audit_log_path, "pve", BOX, "local")["untrusted"] is True and sp.is_tainted(audit_dir)
    os.unlink(os.path.join(audit_dir, ".proximo-taint", "tainted"))
    monkeypatch.delenv("PROXIMO_TAINT_TRACK")
    vendor.bodies["/cluster/resources"] = RESOURCES + [
        {"id": "lxc/9", "type": "lxc", "vmid": 9, "node": "pve1", "status": "x"}]
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    _read(cfg, "/cluster/resources")
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    assert memory.changed(cfg.audit_log_path, "pve", BOX, "1h")["untrusted"] is True and sp.is_tainted(audit_dir)


def _close_all():
    for db, _ in memory._local.__dict__.pop("conns", {}).values():
        db.close()


@pytest.mark.parametrize("side", ["-wal", "-shm", "-journal"])
def test_a_symlinked_sidecar_is_refused(cfg, vendor, tmp_path, side):
    _read(cfg, "/cluster/resources")
    _close_all()
    for s in ("-wal", "-shm"):
        if os.path.exists(_db(cfg) + s):
            os.unlink(_db(cfg) + s)
    os.symlink(tmp_path / "aim", _db(cfg) + side)
    with pytest.raises(memory.Unusable, match="symlink"):
        _where(cfg, "105")


def test_a_group_readable_file_is_refused(cfg, vendor):
    _read(cfg, "/cluster/resources")
    os.chmod(_db(cfg), 0o640)
    with pytest.raises(memory.Unusable, match="group/other"):
        _where(cfg, "105")


def test_the_create_follows_no_link_planted_after_the_check(cfg, monkeypatch, tmp_path):
    aim = tmp_path / "aim.db"
    os.symlink(aim, _db(cfg))
    monkeypatch.setattr(memory, "_is_link", lambda p: False)       # the link lands after the check
    with pytest.raises(memory.Unusable):
        _feed(cfg, "/storage", [{"storage": "local"}])
    assert not aim.exists()


def test_a_file_whose_change_time_moved_is_opened_afresh(cfg, vendor, monkeypatch):
    _read(cfg, "/cluster/resources")
    _where(cfg, "105")
    opened = []
    real = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect", lambda p, *a, **k: opened.append(p) or real(p, *a, **k))
    _where(cfg, "105")
    assert opened == []                                            # held
    os.chmod(_db(cfg), 0o600)                                      # same inode, the change time moves
    _where(cfg, "105")
    assert len(opened) == 1


def test_a_replaced_file_is_reopened(cfg, vendor, tmp_path):
    _read(cfg, "/cluster/resources")
    assert _where(cfg, "105")["found"] is True
    other = tmp_path / "other"
    other.mkdir()
    memory.feed(str(other / "audit.log"), "pve", BOX, "/storage", {}, {}, [{"storage": "only-here", "type": "dir"}],
                source="s", untrusted=False)
    _close_all()
    _read(cfg, "/cluster/resources")
    os.replace(other / "memory.db", _db(cfg))
    for s in ("-wal", "-shm"):
        if os.path.exists(_db(cfg) + s):
            os.unlink(_db(cfg) + s)
    assert _where(cfg, "only-here")["found"] is True and _where(cfg, "105")["found"] is False


def test_memory_is_fed_the_withheld_answer(cfg, vendor, monkeypatch):
    vendor.bodies["/nodes/pve1/qemu/100/pending"] = PENDING["/nodes/pve1/qemu/100/pending"] + [
        {"key": "cipassword", "value": "hunter2-secret"}]
    got = []
    monkeypatch.setattr(memory, "feed", lambda *a, **k: got.append(a[6]))
    _read(cfg, "/nodes/pve1/qemu/100/pending")
    assert "hunter2-secret" not in json.dumps(got) and "[withheld]" in json.dumps(got)


def test_an_empty_config_is_a_failed_read_and_keeps_the_disks(cfg, vendor):
    _feed_all(cfg)
    vendor.bodies["/nodes/pve1/qemu/100/pending"] = []
    _read(cfg, "/nodes/pve1/qemu/100/pending")
    assert [g["guest"] for g in memory.uses(cfg.audit_log_path, "pve", BOX, "nas")["guests"]] == ["qemu/100"]


def test_learn_with_the_permission_map_unreadable_is_incomplete(cfg, vendor):
    vendor.fail.add("/access/permissions")
    out = memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "VM.Audit" in out["why"]


def test_learn_with_a_list_not_kept_this_pass_is_incomplete(cfg, vendor, monkeypatch):
    assert memory.learn("pve", cfg=cfg, ledger_cfg=cfg)["complete"] is True
    monkeypatch.setattr("proximo.core.memory_pve.storage", lambda f, est: 1 / 0)
    out = memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "/storage" in out["why"]


def test_learn_with_configs_not_kept_this_pass_is_incomplete(cfg, vendor, monkeypatch):
    assert memory.learn("pve", cfg=cfg, ledger_cfg=cfg)["complete"] is True
    monkeypatch.setattr("proximo.core.memory_pve.config", lambda f, est: 1 / 0)
    out = memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "qemu/100" in out["why"]


def test_learn_with_a_network_not_kept_is_incomplete(cfg, vendor, monkeypatch):
    monkeypatch.setattr("proximo.core.memory_pve.network", lambda f, est: 1 / 0)
    out = memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "network" in out["why"]


def test_learn_reads_only_the_guests_this_pass_listed(cfg, vendor, monkeypatch):
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _feed(cfg, "/cluster/resources", [{"type": "lxc", "vmid": 4242, "node": "pve1", "status": "running"}])
    monkeypatch.setattr(memory, "_now", time.time)
    memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert "/nodes/pve1/lxc/4242/pending" not in vendor.calls


def test_a_guest_that_moved_runs_on_its_new_node_only(cfg, vendor):
    _read(cfg, "/cluster/resources")
    vendor.bodies["/cluster/resources"] = [{**r, "node": "pve2"} if r.get("vmid") == 105 else r for r in RESOURCES]
    _read(cfg, "/cluster/resources")
    with sqlite3.connect(_db(cfg)) as db:
        assert [d for (d,) in db.execute("SELECT dst FROM edge WHERE src='lxc/105' AND rel='runs_on'")] == ["node/pve2"]


def test_a_storage_on_two_nodes_answers_a_path_on_each(cfg):
    _feed(cfg, "/cluster/resources", [{"type": "storage", "storage": "nas", "node": n, "status": "available"}
                                      for n in ("pve1", "pve2")])
    assert memory.resolve("nas", box=BOX, ledger_path=cfg.audit_log_path)["paths"] == [
        "GET /nodes/pve1/storage/nas/status", "GET /nodes/pve2/storage/nas/status"]


def test_the_permission_map_is_the_tokens_and_never_kept(cfg):
    _feed(cfg, "/access/permissions", {"/": {"VM.Audit": 1}})
    assert not os.path.exists(_db(cfg))


def test_a_read_of_exactly_the_row_cap_is_kept(cfg, monkeypatch):
    monkeypatch.setattr(memory, "MAX_ROWS", 3)
    _feed(cfg, "/cluster/resources", [{"type": "lxc", "vmid": 1 + i, "node": "pve1"} for i in range(3)])
    assert _where(cfg, "3")["found"] is True


def test_a_box_never_fed_answers_with_no_age_beside_one_that_was(cfg, vendor):
    _read(cfg, "/cluster/resources")
    out = memory.where(cfg.audit_log_path, "pve", OTHER_BOX, "105")
    assert out["as_of"] is None and "memory_empty" in out["codes"]


# --- 10: the file sqlite opened is the file that was judged -----------------------------------------

def test_a_swap_between_the_check_and_the_open_is_refused(cfg, vendor, monkeypatch, tmp_path):
    _read(cfg, "/cluster/resources")
    _close_all()
    aim = tmp_path / "attacker.db"
    real = sqlite3.connect

    def racing(p, *a, **k):
        if _plain(p).endswith("memory.db") and not aim.exists():
            os.rename(_plain(p), str(aim))
            os.symlink(aim, _plain(p))
        return real(p, *a, **k)
    monkeypatch.setattr(sqlite3, "connect", racing)
    with pytest.raises(memory.Unusable, match="changed|could not be opened"):   # nofollow refuses it first
        _where(cfg, "105")


def test_a_hard_link_at_the_file_is_refused(cfg, vendor, tmp_path):
    _read(cfg, "/cluster/resources")
    os.link(_db(cfg), tmp_path / "second-name.db")
    with pytest.raises(memory.Unusable, match="hard link"):
        _where(cfg, "105")


# --- defaults, the path, receipts ----------------------------------------------------------------

@pytest.mark.parametrize("word", ["disable", "maybe", "2"])
def test_an_unrecognised_memory_setting_reads_as_off_and_doctor_names_it(cfg, vendor, monkeypatch, word):
    monkeypatch.setenv("PROXIMO_MEMORY", word)
    assert not memory.enabled()
    _read(cfg, "/cluster/resources")
    assert not os.path.exists(_db(cfg))
    flags = []
    memory.station(cfg, flags)
    assert any(f.startswith("PROXIMO_MEMORY is set to a word") for f in flags)
    assert not any(f.startswith(doctor._ADVISORY) for f in flags)
    assert [receipt.flag_code(f) for f in flags] == ["memory-setting-unrecognised"]


def test_memory_path_moves_the_file_under_the_same_rules(cfg, vendor, monkeypatch, tmp_path):
    there = tmp_path / "elsewhere" / "estate.db"
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(there))
    _read(cfg, "/cluster/resources")
    beside_the_ledger = os.path.join(os.path.dirname(cfg.audit_log_path), memory._FILE)   # the default, spelled out:
    assert there.is_file() and stat.S_IMODE(there.stat().st_mode) == 0o600
    assert not os.path.exists(beside_the_ledger)       # `_db(cfg)` reads the env too, so it IS `there` here
    assert _where(cfg, "105")["found"] is True
    _close_all()
    there.unlink()
    os.symlink(tmp_path / "aim", there)
    with pytest.raises(memory.Unusable, match="symlink"):
        _where(cfg, "105")


def test_a_memory_answer_is_a_receipted_recall(cfg, vendor):
    from proximo.core.ledger import open_ledger
    _read(cfg, "/cluster/resources")
    _where(cfg, "105")
    memory.uses(cfg.audit_log_path, "pve", BOX, "local")
    memory.changed(cfg.audit_log_path, "pve", BOX, "24h")
    rows = [json.loads(x) for x in open(cfg.audit_log_path, encoding="utf-8") if x.strip()]
    recalls = [r for r in rows if r.get("action") == "core.recall"]
    assert [r["detail"]["verb"] for r in recalls] == ["where", "uses", "changed"]
    assert all(r["detail"]["source"] == "memory" for r in recalls)
    assert recalls[0]["detail"]["verdict"] == "found" and recalls[0]["detail"]["untrusted"] is True
    assert open_ledger(cfg).verify().ok


# --- lens round 3 (2026-10-27): what the engine hands the feed, eviction, the cut, the key, the open ---

@pytest.mark.parametrize("path,fields,key", [("/storage", "storage", "nas"),
                                             ("/cluster/resources", "type,vmid,node,status", "100")])
def test_a_field_subset_read_through_the_engine_never_retires(cfg, vendor, monkeypatch, path, fields, key):
    """THROUGH THE ENGINE: `fields` reaches the feed (the lens found it never did, so a
    projected read retired). The control is the same read asked whole, which does retire."""
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _read(cfg, path)
    vendor.bodies[path] = [r for r in LISTS[path] if str(r.get("storage", r.get("vmid"))) != key]
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    out = _read(cfg, path, fields=fields)
    assert all(set(r) <= set(fields.split(",")) for r in out["data"])      # the model got a projection
    assert _gone(cfg) == []
    monkeypatch.setattr(memory, "_now", lambda: 1_000_120.0)
    _read(cfg, path)                                                      # the control: whole, so it retires
    assert _gone(cfg) == [key]


@pytest.mark.parametrize("method,path,args,key", [
    ("POST", "/pools", {"poolid": "new"}, "core"),
    ("PUT", "/access/acl", {"path": "/vms/105", "roles": "PVEVMUser", "users": "x@pve"},
     "/vms/105 user/ops@pve PVEVMUser"),
    ("POST", "/cluster/backup", {"id": "j2", "starttime": "02:00"}, "backup-nightly"),
])
def test_a_plans_own_look_at_its_target_never_retires(cfg, vendor, monkeypatch, method, path, args, key):
    """A plan's `_live_state` read of its twin is whole and unfiltered (`fields="all"`,
    `evaluating=True`), so only the `evaluating` flag keeps it from retiring; the lens found the flag
    never reached the feed, and an emptied twin list made the plan's target gone."""
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _feed_all(cfg)
    vendor.bodies[path] = []
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    engine.plan(engine.resolve("pve", method, path), dict(args), path=path, cfg=cfg, ledger_cfg=cfg)
    assert path in vendor.calls[8:], "the plan did not read its twin"
    assert key not in _gone(cfg)


def test_an_eviction_that_drops_an_edge_makes_uses_incomplete(cfg, monkeypatch):
    """Evicting an entity deletes its edges; `uses` must then say `edges_evicted`, never
    `complete` with no guests (the lens: the marker was set only by the MAX_EDGES branch)."""
    t = iter(range(1, 1000))
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0 + next(t))
    _feed(cfg, "/cluster/resources", RESOURCES)
    for p, k, v in (("/nodes/pve1/lxc/105/pending", "lxc", "105"), ("/nodes/pve1/qemu/100/pending", "qemu", "100")):
        _feed(cfg, f"/nodes/{{node}}/{k}/{{vmid}}/pending", PENDING[p], bound={"node": "pve1", "vmid": v})
    assert memory.uses(cfg.audit_log_path, "pve", BOX, "nas")["guests"][0]["guest"] == "qemu/100"
    monkeypatch.setattr(memory, "MAX_ENTITIES", 5)
    _feed(cfg, "/nodes/{node}/qemu", [{"vmid": 100, "name": "db", "status": "stopped"}], bound={"node": "pve1"})
    _feed(cfg, "/nodes/{node}/lxc", [{"vmid": 105, "name": "web", "status": "running"}], bound={"node": "pve1"})
    _feed(cfg, "/storage", [{"storage": f"extra{i}", "type": "dir"} for i in range(3)])
    with sqlite3.connect(_db(cfg)) as db:
        ents = [n for (n,) in db.execute("SELECT nid FROM entity")]
    assert "qemu/100" in ents and "storage/nas" not in ents
    out = memory.uses(cfg.audit_log_path, "pve", BOX, "nas")
    assert out["complete"] is False and "edges_evicted" in out["why"]


def test_an_evicted_guest_leaves_uses_incomplete_even_with_no_edge_to_lose(cfg, monkeypatch):
    """A guest whose config was never kept counts as `configs_unread`; evicted, it would vanish from
    that count and `uses` would turn complete by forgetting. Any eviction since the configs were kept
    is a reason."""
    t = iter(range(1, 1000))
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0 + next(t))
    _feed(cfg, "/cluster/resources", RESOURCES)
    _feed(cfg, "/nodes/{node}/lxc/{vmid}/pending", PENDING["/nodes/pve1/lxc/105/pending"],
          bound={"node": "pve1", "vmid": "105"})
    assert "configs_unread" in memory.uses(cfg.audit_log_path, "pve", BOX, "nas")["why"]
    monkeypatch.setattr(memory, "MAX_ENTITIES", 3)
    _feed(cfg, "/nodes/{node}/lxc", [{"vmid": 105, "name": "web", "status": "running"}], bound={"node": "pve1"})
    _feed(cfg, "/storage", [{"storage": f"extra{i}", "type": "dir"} for i in range(2)])
    with sqlite3.connect(_db(cfg)) as db:
        ents = [n for (n,) in db.execute("SELECT nid FROM entity")]
    assert "qemu/100" not in ents
    out = memory.uses(cfg.audit_log_path, "pve", BOX, "nas")
    assert out["complete"] is False and "edges_evicted" in out["why"]


def test_a_vendor_id_longer_than_text_is_not_kept(cfg):
    """Bounded means the key too: a 5,000-character volid is not kept, nor an edge to it, and status
    counts it. A cut key would collide two ids sharing a prefix and orphan every edge the estate built
    from the whole one, so the row is skipped, not shortened."""
    volid = "nas:backup/" + "v" * 5000
    _feed(cfg, "/nodes/{node}/storage/{storage}/content",
          [{"volid": volid, "content": "backup", "vmid": 105},
           {"volid": "nas:backup/vzdump-lxc-105-2026_10_27-01_00_00.tar.zst", "content": "backup", "vmid": 105}],
          bound={"node": "pve1", "storage": "nas"})
    with sqlite3.connect(_db(cfg)) as db:
        (longest,) = db.execute("SELECT max(length(key)) FROM entity").fetchone()
        (edge,) = db.execute("SELECT max(max(length(src), length(dst))) FROM edge").fetchone()
        (kept,) = db.execute("SELECT count(*) FROM entity WHERE kind='backup'").fetchone()
    assert longest <= memory.TEXT and (edge or 0) <= memory.TEXT + 16 and kept == 1
    assert memory.status(cfg.audit_log_path)["skipped_ids"] == 1
    assert _where(cfg, "nas:backup/vzdump-lxc-105-2026_10_27-01_00_00.tar.zst")["found"] is True


@pytest.mark.parametrize("node", ["proxmox-east-rack01-hos", "pve-cluster-node-number-7"])
def test_a_row_cut_to_fit_keeps_its_published_paths_to_the_same_thing(cfg, monkeypatch, node):
    """The cut shortens names, never a path. The lens cut `/lxc/105` to `/lxc/1` at a small
    cap: a published GET to a different guest, which `_published` had never checked."""
    _feed(cfg, "/cluster/resources", [{"type": "lxc", "vmid": 105, "node": node, "name": "w" * 119,
                                      "status": "running", "tags": "t" * 119}])
    whole = len(json.dumps(memory.resolve("105", box=BOX, ledger_path=cfg.audit_log_path)))
    monkeypatch.setattr(memory, "ANSWER_BYTES", 600)
    out = memory.resolve("105", box=BOX, ledger_path=cfg.audit_log_path)
    assert whole > 600 >= len(json.dumps(out))
    assert out["paths"] == [f"GET /nodes/{node}/lxc/105/status/current", f"GET /nodes/{node}/lxc/105/config"]
    assert out["matches"][0]["paths"] == out["paths"] and len(out["matches"][0]["name"]) < 119


def test_a_swap_to_a_dangling_link_creates_nothing_at_its_target(cfg, vendor, monkeypatch, tmp_path):
    """The open never creates: `_guard` made the file with O_EXCL, so a connect that could create would
    only ever create at an attacker's target (the lens: a 0644 empty file appeared there before the
    refusal)."""
    _read(cfg, "/cluster/resources")
    _close_all()
    aim = tmp_path / "nowhere.db"
    real = sqlite3.connect

    def racing(p, *a, **k):
        name = _plain(p)
        if name.endswith("memory.db") and not os.path.islink(name):
            os.unlink(name)
            os.symlink(aim, name)
        return real(p, *a, **k)
    monkeypatch.setattr(sqlite3, "connect", racing)
    with pytest.raises(memory.Unusable):
        _where(cfg, "105")
    assert not aim.exists()


def test_a_zero_byte_file_memory_did_not_make_is_refused(cfg, vendor, monkeypatch, tmp_path):
    """PROXIMO_MEMORY_PATH at an empty 0600 file memory did not create (a ledger not yet written, a
    mistake): sqlite would silently make it a database. Refused, named by doctor, never written."""
    f = tmp_path / "empty.log"
    f.touch(mode=0o600)
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(f))
    out = _read(cfg, "/cluster/resources")
    assert out["total"] == len(RESOURCES)
    assert f.stat().st_size == 0 and not (tmp_path / "empty.log-wal").exists()
    with pytest.raises(memory.Unusable, match="did not create"):
        _where(cfg, "105")
    assert memory.status(cfg.audit_log_path)["file"] == "refused"


# --- lens 3 on phase B (2026-11-07): the shell's where keeps what it says about a gone name ---------

def _resources(monkeypatch, cfg, *readings):
    for rows in readings:
        w = _Wire({**LISTS, "/cluster/resources": rows})
        monkeypatch.setattr(engine, "_client", lambda product, c=None, w=w: w)
        _read(cfg, "/cluster/resources")


_N = {"id": "node/pve1", "type": "node", "node": "pve1", "status": "online"}


def _lxc(vmid, name, status="running"):
    return {"id": f"lxc/{vmid}", "type": "lxc", "vmid": vmid, "node": "pve1", "name": name, "status": status}


def test_where_by_a_gone_name_says_gone_beside_many_live_prefixes(cfg, monkeypatch):
    live = [_lxc(200 + i, f"web-{i}") for i in range(6)]
    _resources(monkeypatch, cfg, [_N, _lxc(105, "web"), *live], [_N, *live])
    for words in ("web", "lxc web"):
        out = _where(cfg, words, receipt=False)
        assert out["matches"][0]["id"] == "105" and out["matches"][0]["status"] == "gone", words


def test_where_by_a_gone_name_that_is_a_kind_word_says_gone(cfg, monkeypatch):
    _resources(monkeypatch, cfg, [_N, _lxc(105, "vm"), _lxc(106, "x")], [_N, _lxc(106, "x")])
    out = _where(cfg, "vm", receipt=False)
    assert out["found"] and out["matches"][0]["id"] == "105" and out["matches"][0]["status"] == "gone"


# --- lens 5 (2026-11-07): the vendor's own identifier for each kind, never ours --------------------

def test_an_acl_subject_never_hides_a_guest_of_that_name(cfg, monkeypatch):
    w = _Wire({**LISTS, "/access/acl": [{"path": "/", "type": "group", "ugid": "web", "roleid": "PVEAuditor",
                                          "propagate": 1}]})
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    _feed_all(cfg)
    out = _where(cfg, "web", receipt=False)
    assert [(m["kind"], m["id"]) for m in out["matches"]] == [("lxc", "105")]


@pytest.mark.parametrize("words", ["pve1/vmbr0", "vzdump-lxc-105-2026_10_27-01_00_00.tar.zst",
                                   "/vms/105", "ops@pve", "prod"])
def test_memorys_own_keys_and_derived_names_are_no_answer(cfg, vendor, words):
    """A bridge's `node/iface`, a backup's short name, an ACL's path or subject, a tag: memory's
    labels, not a vendor id or name for that thing."""
    _feed_all(cfg)
    _feed(cfg, "/nodes/{node}/storage/{storage}/content",
          [{"volid": "nas:backup/vzdump-lxc-105-2026_10_27-01_00_00.tar.zst", "content": "backup", "vmid": 105}],
          bound={"node": "pve1", "storage": "nas"})
    assert _where(cfg, words, receipt=False)["found"] is False


def test_a_bridge_and_a_backup_answer_by_the_vendors_id(cfg, vendor):
    _feed_all(cfg)
    _feed(cfg, "/nodes/{node}/storage/{storage}/content",
          [{"volid": "nas:backup/vzdump-lxc-105-x.tar.zst", "format": "tar.zst", "content": "backup", "vmid": 105}],
          bound={"node": "pve1", "storage": "nas"})
    assert _where(cfg, "bridge vmbr0", receipt=False)["matches"][0]["kind"] == "bridge"
    assert _where(cfg, "backup nas:backup/vzdump-lxc-105-x.tar.zst", receipt=False)["matches"][0]["kind"] == "backup"


@pytest.mark.parametrize("words", ["lxc\t105", "lxc  105", " web", "web ", "lxc\u00a0105", "\tweb"])
def test_the_separator_is_one_plain_space(cfg, vendor, words):
    _feed_all(cfg)
    assert _where(cfg, words, receipt=False)["found"] is False


def test_a_v2_files_search_index_tables_go_even_without_fts5(cfg, vendor):
    """Without FTS5 the virtual `words` cannot be dropped; its shadow tables are plain and go by name,
    so a guest's old name or tag is not left in the file."""
    _feed_all(cfg)
    with sqlite3.connect(_db(cfg)) as db:
        for t in ("words_data", "words_idx", "words_content", "words_docsize", "words_config"):
            db.execute(f"CREATE TABLE {t} (x)")
        db.execute("INSERT INTO words_content VALUES ('a guest name')")
        db.execute("PRAGMA user_version = 2")
    memory._local.__dict__.pop("conns", None)
    _feed_all(cfg)
    with sqlite3.connect(_db(cfg)) as db:
        names = {n for (n,) in db.execute("SELECT name FROM sqlite_master")}
    assert not any(n.startswith("words") for n in names), names


# --- lens 6 (2026-11-07): the vendor's order, nothing hidden, no old text left ---------------------

def test_a_node_ranks_before_bridges_that_share_its_name(cfg, monkeypatch):
    nodes = [f"n{i}" for i in range(7)]
    w = _Wire({**LISTS, **{f"/nodes/{n}/network": [{"iface": "pve3", "type": "bridge", "active": 1}] for n in nodes},
               "/cluster/resources": [{"id": "node/pve3", "type": "node", "node": "pve3", "status": "online"}]})
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    _read(cfg, "/cluster/resources")
    for n in nodes:
        _read(cfg, f"/nodes/{n}/network")
    out = _where(cfg, "pve3", receipt=False)
    assert out["matches"][0]["kind"] == "node" and out.get("total") == 8


def test_a_schema_rebuild_leaves_no_old_guest_text_in_the_file(cfg, vendor):
    _feed_all(cfg)
    db = sqlite3.connect(_db(cfg))
    db.execute("PRAGMA secure_delete=OFF")        # a v2 written by a build without SECURE_DELETE (this one has it)
    db.execute("CREATE TABLE old_words (t)")
    db.executemany("INSERT INTO old_words VALUES (?)", [("ZZSECRETNAMEZZ" * 40,)] * 50)
    db.commit()
    db.execute("DELETE FROM old_words")           # freed pages that still hold the text: only VACUUM clears them
    db.executemany("INSERT INTO old_words VALUES (?)", [("x",)])
    db.execute("PRAGMA user_version = 2")
    db.commit()
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
    db.close()
    with open(_db(cfg), "rb") as fh:
        assert b"ZZSECRET" in fh.read(), "the plant must be on disk before the rebuild"
    memory._local.__dict__.pop("conns", None)
    _where(cfg, "web", receipt=False)                         # the open rebuilds it
    memory._local.__dict__.pop("conns", None)
    raw = b""
    for suffix in ("", "-wal"):
        try:
            with open(_db(cfg) + suffix, "rb") as fh:
                raw += fh.read()
        except FileNotFoundError:
            pass
    assert b"ZZSECRET" not in raw


def test_a_file_from_a_newer_proximo_is_refused_never_wiped(cfg, vendor):
    _feed_all(cfg)
    with sqlite3.connect(_db(cfg)) as db:
        db.execute("PRAGMA user_version = 99")
    memory._local.__dict__.pop("conns", None)
    with pytest.raises(memory.Unusable, match="newer"):
        _where(cfg, "web", receipt=False)
    with sqlite3.connect(_db(cfg)) as db:
        (n,) = db.execute("SELECT count(*) FROM entity").fetchone()
        (v,) = db.execute("PRAGMA user_version").fetchone()
    assert n > 0 and v == 99


# ======================== the keyed-row rule: absent is not proof ==================================
# A whole list with a row memory cannot key retires nothing: that row may be the very thing a retire
# would call gone (a field renamed in another version, a garbled answer).

_CONTENT_T = "/nodes/{node}/storage/{storage}/content"
_VOLS = [{"volid": "nas:backup/vzdump-lxc-105-a.tar.zst", "format": "tar.zst", "content": "backup", "vmid": 105},
         {"volid": "nas:backup/vzdump-lxc-105-b.tar.zst", "format": "tar.zst", "content": "backup", "vmid": 105}]
#: template, bound, owner, the first whole answer, a later whole answer that lists less
KEYED = [
    ("/cluster/resources", {}, "resources", RESOURCES, RESOURCES[:4]),
    ("/storage", {}, "/storage", LISTS["/storage"], LISTS["/storage"][:1]),
    ("/cluster/backup", {}, "/cluster/backup", LISTS["/cluster/backup"], [{"id": "backup-other"}]),
    ("/pools", {}, "/pools", LISTS["/pools"], [{"poolid": "other"}]),
    ("/access/acl", {}, "/access/acl", LISTS["/access/acl"],
     [{"path": "/", "type": "user", "ugid": "new@pve", "roleid": "PVEAuditor"}]),
    ("/nodes/{node}/network", {"node": "pve1"}, "network/pve1", LISTS["/nodes/pve1/network"],
     LISTS["/nodes/pve1/network"][1:]),
    (_CONTENT_T, {"node": "pve1", "storage": "nas"}, "content/pve1/nas", _VOLS, _VOLS[1:]),
]
#: rows no list can key, then each list's own (a kept row missing a field its key is built from)
UNKEYABLE = ["x", None, 7, {"bogus": 1}, ["lxc/105"]]
UNKEYABLE_BY = {
    "/cluster/resources": [{"type": "qemu"}, {"type": "lxc", "vmid": None}, {"type": "node"},
                           {"type": "storage", "node": "pve1"}, {"vmid": 100, "node": "pve1"}, {"type": 5},
                           {"type": "qemu", "vmid": 9, "node": "pve1"},                  # the vendor's `id` missing
                           # the vendor's row whole (`id`, `type`), and nothing memory keys a node or storage by
                           {"id": "node/pve9", "type": "node"},
                           {"id": "storage/pve1/y", "type": "storage", "node": "pve1"}],
    "/storage": [{"storage": ""}, {"storage": None, "type": "dir"}, {"storage": "  "}],
    "/cluster/backup": [{"id": None}, {"enabled": 1}],
    "/pools": [{"poolid": ""}, {"members": []}],
    "/access/acl": [{"path": "/vms/105", "ugid": "ops@pve", "roleid": "PVEVMUser"},          # no type
                    {"path": "/vms/105", "type": "user", "ugid": "ops@pve"},                 # no role
                    {"path": "/vms/105", "type": "user", "roleid": "PVEVMUser"},             # no subject
                    {"type": "user", "ugid": "ops@pve", "roleid": "PVEVMUser"}],             # no path
    "/nodes/{node}/network": [{"type": "bridge", "active": 1}, {"iface": None}, {"iface": "vmbr9"}],   # no `type`
    _CONTENT_T: [{"content": "backup", "vmid": 105}, {"volid": ""}, {"volid": "", "format": "raw"},
                 {"volid": "nas:backup/vzdump-lxc-105-c.tar.zst"}],                              # no `format`
}
_KEYED_CASES = [(*c, bad) for c in KEYED for bad in (*UNKEYABLE, *UNKEYABLE_BY[c[0]])]


def _drops(cfg, owner):
    with sqlite3.connect(_db(cfg)) as db:
        return db.execute("SELECT count(*) FROM sighting WHERE plane='pve' AND owner=? AND dropped IS NOT NULL",
                          (owner,)).fetchone()[0]


def _whole_at(cfg, owner):
    with sqlite3.connect(_db(cfg)) as db:
        return float(db.execute("SELECT v FROM meta WHERE plane='pve' AND k=?", (f"whole:{owner}",)).fetchone()[0])


@pytest.mark.parametrize("template,bound,owner,first,later,bad", _KEYED_CASES,
                         ids=[f"{c[0]} {json.dumps(c[5])}" for c in _KEYED_CASES])
def test_a_pve_list_with_a_row_it_cannot_key_retires_nothing(cfg, monkeypatch, template, bound, owner, first,
                                                             later, bad):
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _feed(cfg, template, first, bound=bound)
    assert _whole_at(cfg, owner) == 1_000_000.0                          # the first answer owned
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    _feed(cfg, template, [*later, bad], bound=bound)
    assert _drops(cfg, owner) == 0 and _gone(cfg) == []
    assert _whole_at(cfg, owner) == 1_000_000.0                          # and this one did not
    monkeypatch.setattr(memory, "_now", lambda: 1_000_120.0)
    _feed(cfg, template, later, bound=bound)                             # the control: every row keyed
    assert _drops(cfg, owner) >= 1 and _whole_at(cfg, owner) == 1_000_120.0


def test_a_resources_row_of_a_type_memory_does_not_keep_never_stops_the_retiring(cfg, monkeypatch):
    """The vendor lists more than this shape keeps (a network, an sdn zone, a pool): such a row needs no
    key, or a healthy estate would never retire anything again."""
    others = [{"id": "network/pve1/vmbr0", "type": "network", "node": "pve1"},
              {"id": "sdn/pve1/zone1", "type": "sdn"}, {"id": "/pool/core", "type": "pool"}]
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _feed(cfg, "/cluster/resources", [*RESOURCES, *others])
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    _feed(cfg, "/cluster/resources", [*RESOURCES[:4], *others])
    assert _gone(cfg) == ["100"]


@pytest.mark.parametrize("template", ["/storage", "/cluster/backup", "/pools", "/access/acl"])
def test_a_true_empty_pve_list_still_retires(cfg, monkeypatch, template):
    monkeypatch.setattr(memory, "_now", lambda: 1_000_000.0)
    _feed(cfg, template, LISTS[template])
    monkeypatch.setattr(memory, "_now", lambda: 1_000_060.0)
    _feed(cfg, template, [])
    assert _drops(cfg, template) >= 1


def test_an_unkeyable_storage_list_feeds_no_storage(cfg, monkeypatch):
    """A `/storage` read that cannot own feeds nothing (the frame's rule for the one two-owner pair), so a
    list with a row it cannot key neither retires nor brings back what `resources` dropped."""
    _feed(cfg, "/storage", [{"storage": "fresh", "type": "dir"}, {"bogus": 1}])
    assert _where(cfg, "fresh")["verdict"] != "found"


@pytest.mark.parametrize("path,bad", [
    ("/cluster/resources", {"type": "qemu", "node": "pve1"}), ("/storage", {"bogus": 1}),
    ("/cluster/backup", {"bogus": 1}), ("/pools", {"bogus": 1}), ("/access/acl", {"path": "/", "ugid": "a@pve"}),
    ("/nodes/pve1/network", {"type": "bridge"})])
def test_a_pve_learn_is_incomplete_when_a_list_it_read_could_not_own(cfg, vendor, path, bad):
    """Such a list retires nothing; learn must not then say complete, or a thing truly removed stays found
    and nothing says so."""
    assert memory.learn("pve", cfg=cfg, ledger_cfg=cfg)["complete"] is True
    clean = vendor.bodies[path]
    vendor.bodies[path] = [*clean, bad]
    out = memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and f"GET {path} was read but could not own its list" in out["why"], out
    vendor.bodies[path] = clean                                          # the control: every row keyed
    out = memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is True, out.get("why")


# --- memory's own need, apart from the vendor's row (which `memory.feed` holds first) --------------

@pytest.mark.parametrize("template,rows", [
    ("/cluster/resources", [*RESOURCES, "x"]), ("/storage", [{"storage": "local"}, None]),
    ("/cluster/resources", [*RESOURCES, {"vmid": 100, "node": "pve1"}]),                  # no `type`
    ("/access/acl", [{"type": "user", "ugid": "ops@pve", "roleid": "PVEVMUser"}]),        # no path
    ("/access/acl", [{"path": "/", "type": "user", "roleid": "PVEVMUser"}]),              # no subject
    ("/access/acl", [{"path": "/", "ugid": "ops@pve", "roleid": "PVEVMUser"}]),           # no type
    ("/access/acl", [{"path": "/", "type": "user", "ugid": "ops@pve"}]),                  # no role
    ("/nodes/{node}/network", [{"type": "bridge"}]), ("/pools", [{"poolid": " "}]),
])
def test_the_pve_shape_owns_no_list_it_cannot_key_whatever_the_frame_holds(template, rows):
    from proximo.core import memory_pve
    assert memory_pve._keyed(template, rows) is False
    assert memory_pve.SHAPE.owner(template, {"node": "pve1"}, {}, None, rows, BOX, False) is None


def test_a_grant_short_of_its_key_is_never_kept(cfg, monkeypatch):
    """Lens on a79bb9a: a grant with no type was kept under `subject/...`, a name no whole read lists
    again, so it never left."""
    good = LISTS["/access/acl"][0]
    _feed(cfg, "/access/acl", [good, {k: v for k, v in good.items() if k != "type"},
                               {k: v for k, v in good.items() if k != "roleid"}])
    with sqlite3.connect(_db(cfg)) as db:
        assert [k for (k,) in db.execute("SELECT key FROM entity WHERE kind='acl'")] == \
            ["/vms/105 user/ops@pve PVEVMUser"]
        assert db.execute("SELECT src, dst FROM edge WHERE rel='granted_on'").fetchall() == \
            [("user/ops@pve", "path/vms/105")]                       # and no edge for the two not kept


def test_a_learn_whose_resources_list_could_not_own_still_reads_the_networks_and_configs(cfg, vendor):
    """Lens on a79bb9a: the fan-out read the owner's sightings, so one row short of the vendor's made
    learn skip every node's network and every guest's config, and say only that the list could not own."""
    vendor.bodies["/cluster/resources"] = [*RESOURCES, {"type": "storage", "node": "pve1"}]
    out = memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "GET /cluster/resources was read but could not own its list" in out["why"]
    assert out["guests"] == 2 and out["reads"] == 9
    assert {"/nodes/pve1/network", "/nodes/pve1/lxc/105/pending", "/nodes/pve1/qemu/100/pending"} <= set(vendor.calls)


def test_a_failed_list_read_is_not_called_one_that_could_not_own(cfg, vendor):
    vendor.fail.add("/nodes/pve1/network")
    vendor.fail.add("/pools")
    out = memory.learn("pve", cfg=cfg, ledger_cfg=cfg)
    assert out["complete"] is False and "failed" in out["why"] and "could not own" not in out["why"], out
