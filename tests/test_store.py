"""Step 5, the smaller one (John, 2026-09-27: "would this matter if we could just make sure all
calls fit" -> "go build the smaller one"). The 4K door already makes every call fit. Two things
fitting cannot give, and only those:

1. A list over the cap came back CUT: 16 of 37 rows, a fitting answer missing most of the estate.
   Now a default read over the cap answers WHOLE and smaller: the count, a tally per state field,
   and the rows not in the most common state. `fields=` still gets rows by name, cut as before.
2. "What changed since yesterday" is not a call; the vendor keeps no yesterday. Every list read the
   door serves leaves a snapshot on disk, and `since=` answers added / gone / changed from disk,
   no vendor call, stamped with the snapshots' times.
"""
from __future__ import annotations

import dataclasses
import json
import os
import stat
from dataclasses import dataclass

import pytest

from proximo.core import engine, store, wire
from proximo.core.errors import ProximoError


class _Wire:
    def __init__(self, body):
        self.body = body
        self.calls = 0

    def call(self, method, path, params=None):
        self.calls += 1
        return self.body


@dataclass(frozen=True)
class _Cfg(wire.Plane):
    audit_log_path: str = ""
    audit_key_path: str | None = None


@pytest.fixture
def cfg(tmp_path):
    return _Cfg("pve", "https://unreachable.invalid:8006/api2/json", "/dev/null",
                audit_log_path=str(tmp_path / "audit.log"))


def _guests(n, stopped=(), locked=()):
    return [{"id": f"lxc/{100 + i}", "vmid": 100 + i, "name": f"ct{i}", "type": "lxc", "node": "n1",
             "status": "stopped" if i in stopped else "running",
             **({"lock": "backup"} if i in locked else {}),
             "mem": 1000 + i * 7, "uptime": 5000 + i} for i in range(n)]


def _read(monkeypatch, cfg, body, **kw):
    w = _Wire(body)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    out = engine.execute(engine.resolve("pve", "GET", "/cluster/resources"), {}, cfg=cfg,
                         ledger_cfg=cfg, path="/cluster/resources", **kw)
    return out, w


def _store_dir(cfg):
    return os.path.join(os.path.dirname(cfg.audit_log_path), "store")


# --- 1. over the cap: whole and smaller, never cut ---------------------------------------------

def test_a_default_read_over_the_cap_answers_whole_as_a_tally_and_the_minority(monkeypatch, cfg):
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "2048")
    out, _ = _read(monkeypatch, cfg, _guests(300, stopped={3, 250}, locked={7}))
    assert out["total"] == 300 and out["summarized"] is True
    assert "data" not in out and "truncated" not in out
    assert out["tally"]["status"] == {"running": 298, "stopped": 2}
    assert out["tally"]["type"] == {"lxc": 300}
    ids = sorted(r["id"] for r in out["minority"])
    assert ids == ["lxc/103", "lxc/107", "lxc/350"]
    assert {"id": "lxc/103", "vmid": 103, "name": "ct3", "node": "n1", "status": "stopped"} in out["minority"]
    assert len(json.dumps(out)) <= 2048 + 1024      # the envelope's labels ride on top of the cap


def test_rows_asked_for_by_name_are_still_cut_by_rows(monkeypatch, cfg):
    """The control: `fields=` is a request for ROWS, so over the cap it is the old cut."""
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "2048")
    out, _ = _read(monkeypatch, cfg, _guests(300), fields="all")
    assert out["truncated"] is True and "summarized" not in out
    out, _ = _read(monkeypatch, cfg, _guests(5))             # under the cap: rows, as always
    assert "summarized" not in out and len(out["data"]) == 5


def test_a_minority_too_big_for_the_cap_is_itself_cut_with_its_count(monkeypatch, cfg):
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "2048")
    out, _ = _read(monkeypatch, cfg, _guests(300, stopped=set(range(0, 300, 2))))
    assert out["tally"]["status"] == {"running": 150, "stopped": 150}
    assert out["minority_total"] == 150 and out["minority_returned"] < 150


# --- 2. the snapshot the door keeps --------------------------------------------------------------

def test_a_list_read_leaves_an_owner_only_lean_snapshot(monkeypatch, cfg):
    _read(monkeypatch, cfg, _guests(3))
    d = _store_dir(cfg)
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    files = [os.path.join(r, f) for r, _, fs in os.walk(d) for f in fs]
    assert files and all(stat.S_IMODE(os.stat(f).st_mode) == 0o600 for f in files)
    snap = store.latest(d, "pve", cfg.base_url, "/cluster/resources", {})
    assert snap["rows"][0] == {"id": "lxc/100", "vmid": 100, "name": "ct0", "type": "lxc",
                               "node": "n1", "status": "running"}   # lean: no counters kept


def test_the_store_off_switch_writes_nothing(monkeypatch, cfg):
    monkeypatch.setenv("PROXIMO_STORE", "off")
    _read(monkeypatch, cfg, _guests(3))
    assert not os.path.exists(_store_dir(cfg))


def test_an_untrusted_answer_from_the_store_marks_the_session_like_the_read(monkeypatch, cfg, tmp_path):
    """Cluster resources is in the taint record (guest names ride every row). Keeping it is the
    point; answering from it must mark and fence exactly as the live read does."""
    row = engine.resolve("pve", "GET", "/cluster/resources")
    assert row.untrusted, "the premise: the estate read is classified untrusted"
    _read(monkeypatch, cfg, _guests(3))
    marks = []
    monkeypatch.setattr(engine, "_taint_before_the_wire", lambda *a, **k: marks.append(a[0].key))
    monkeypatch.setattr(engine.spine, "fence_on", lambda: True)
    out, w = _read(monkeypatch, cfg, None, since="1m")
    assert w.calls == 0 and marks == [row.key] and out["untrusted"] is True
    assert out["changes"] == engine.spine.fence(row.key, [])


# --- 3. since: what changed, from disk ------------------------------------------------------------

def test_since_answers_added_gone_and_changed_with_no_vendor_call(monkeypatch, cfg):
    clock = [1_000_000.0]
    monkeypatch.setattr(store, "_now", lambda: clock[0])
    _read(monkeypatch, cfg, _guests(4))                              # yesterday
    clock[0] += 26 * 3600
    today = [g for g in _guests(5, stopped={1}) if g["vmid"] != 102]  # 102 gone, 104 new, 101 stopped
    _read(monkeypatch, cfg, today)
    clock[0] += 60
    out, w = _read(monkeypatch, cfg, None, since="24h")
    assert w.calls == 0, "a since answer is read from disk, never the vendor"
    assert out["source"] == "store" and out["counts"] == {"added": 1, "gone": 1, "changed": 1}
    by = {c["change"]: c for c in out["changes"]}
    assert by["added"]["id"] == "lxc/104" and by["gone"]["id"] == "lxc/102"
    assert by["changed"] == {"change": "changed", "id": "lxc/101", "status": ["running", "stopped"]}
    assert out["to_age_s"] == 60 and out["window_s"] == 26 * 3600


def test_since_with_nothing_kept_refuses_and_says_how_to_fix_it(monkeypatch, cfg):
    with pytest.raises(ProximoError, match="read it once"):
        _read(monkeypatch, cfg, None, since="24h")


def test_since_says_when_it_cannot_reach_back_as_far_as_asked(monkeypatch, cfg):
    clock = [1_000_000.0]
    monkeypatch.setattr(store, "_now", lambda: clock[0])
    _read(monkeypatch, cfg, _guests(2))
    clock[0] += 3600
    _read(monkeypatch, cfg, _guests(3))
    out, _ = _read(monkeypatch, cfg, None, since="24h")
    assert out["window_s"] == 3600 and "only" in out["note"]
    assert out["counts"]["added"] == 1


def test_since_is_refused_on_a_bad_spelling_and_a_store_that_is_off(monkeypatch, cfg):
    with pytest.raises(ProximoError, match="30m, 24h or 7d"):
        _read(monkeypatch, cfg, None, since="yesterday")
    monkeypatch.setenv("PROXIMO_STORE", "off")
    with pytest.raises(ProximoError, match="store is off"):
        _read(monkeypatch, cfg, None, since="24h")



def test_a_day_file_is_kept_per_utc_day_and_old_days_are_pruned(monkeypatch, cfg):
    clock = [1_000_000.0]
    monkeypatch.setattr(store, "_now", lambda: clock[0])
    for _ in range(12):
        _read(monkeypatch, cfg, _guests(2))
        clock[0] += 86400
    d = os.path.join(_store_dir(cfg), store.key("pve", cfg.base_url, "/cluster/resources", {}))
    days = sorted(f for f in os.listdir(d) if f != "latest.json.gz")
    assert len(days) == store.KEEP_DAYS


def test_two_boxes_behind_one_ledger_are_never_diffed_against_each_other(monkeypatch, cfg):
    """A registry target beside the env box shares the ledger, so it shares the store directory.
    The box is in the key; without it one box's guests would read as the other's added and gone."""
    other = dataclasses.replace(cfg, base_url="https://other.invalid:8006/api2/json")
    _read(monkeypatch, cfg, _guests(2))
    w = _Wire(_guests(5))
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    engine.execute(engine.resolve("pve", "GET", "/cluster/resources"), {}, cfg=other, ledger_cfg=cfg,
                   path="/cluster/resources")
    out, _ = _read(monkeypatch, cfg, None, since="1m")
    assert out["counts"] == {"added": 0, "gone": 0, "changed": 0}
    assert len(store.latest(_store_dir(cfg), "pve", cfg.base_url, "/cluster/resources", {})["rows"]) == 2


def test_a_comma_list_in_another_order_is_not_a_change(monkeypatch, cfg):
    """Measured live 2026-09-27: two reads seconds apart returned storage `content` as
    "rootdir,images" then "images,rootdir", and since= called three storages changed."""
    clock = [1_000_000.0]
    monkeypatch.setattr(store, "_now", lambda: clock[0])
    _read(monkeypatch, cfg, [{"id": "storage/n1/lvm", "content": "rootdir,images"}])
    clock[0] += 60
    _read(monkeypatch, cfg, [{"id": "storage/n1/lvm", "content": "images,rootdir"}])
    out, _ = _read(monkeypatch, cfg, None, since="1m")
    assert out["counts"] == {"added": 0, "gone": 0, "changed": 0}
    clock[0] += 60                                           # the control: a real change still is one
    _read(monkeypatch, cfg, [{"id": "storage/n1/lvm", "content": "images"}])
    out, _ = _read(monkeypatch, cfg, None, since="1m")
    assert out["counts"]["changed"] == 1


def test_a_mixed_list_judges_the_common_state_within_each_type(monkeypatch, cfg):
    """Measured live: cluster resources over the cap named 18 of 37 rows exceptions, storage's
    "available" read against the guests' "running". Within its type, only the odd one is odd."""
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "1024")
    rows = _guests(40, stopped={5}) + [
        {"id": f"storage/n1/s{i}", "type": "storage", "node": "n1", "status": "available"} for i in range(8)]
    out, _ = _read(monkeypatch, cfg, rows)
    assert out["summarized"] is True
    assert [r["id"] for r in out["minority"]] == ["lxc/105"]


# --- LENS FOLD (sonnet, 2026-09-28, 4 BLOCKING), each watched red first --------------------------

def test_a_summary_over_the_cap_itself_falls_back_to_the_row_cut(monkeypatch, cfg):
    """Only the minority was bounded: 200 rows x 150 five-valued fields made a 9 KB 'summary'
    against a 2 KB cap. A summary that does not fit is not smaller; the cut is."""
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "2048")
    rows = [{"id": f"r{i}", **{f"f{j}": f"v{(i + j) % 5}" for j in range(150)}} for i in range(200)]
    out, _ = _read(monkeypatch, cfg, rows)
    assert "summarized" not in out and out["truncated"] is True


def test_a_log_with_a_level_keeps_its_lines(monkeypatch, cfg):
    """A `level` field is a state, but every row also carries its own message: the rows are the
    content, and a tally of levels would erase every line. The cut keeps them."""
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "2048")
    rows = [{"id": f"l{i}", "level": "ERROR" if i % 20 == 0 else "INFO", "line": f"message {i} " + "x" * 20}
            for i in range(300)]
    out, _ = _read(monkeypatch, cfg, rows)
    assert "summarized" not in out and all("line" in r for r in out["data"])


def test_a_corrupt_snapshot_is_a_refusal_and_a_bad_day_file_is_skipped(monkeypatch, cfg):
    clock = [1_000_000.0]
    monkeypatch.setattr(store, "_now", lambda: clock[0])
    _read(monkeypatch, cfg, _guests(2))
    clock[0] += 90000
    _read(monkeypatch, cfg, _guests(3))
    d = os.path.join(_store_dir(cfg), store.key("pve", cfg.base_url, "/cluster/resources", {}))
    days = sorted(f for f in os.listdir(d) if f != "latest.json.gz")
    with open(os.path.join(d, days[0]), "wb") as f:
        f.write(b"garbage, not a gzip file")
    out, _ = _read(monkeypatch, cfg, None, since="1h")          # the bad day is skipped, not fatal
    assert out["source"] == "store"
    with open(os.path.join(d, "latest.json.gz"), "wb") as f:
        f.write(b"garbage")
    with pytest.raises(ProximoError, match="unreadable"):
        _read(monkeypatch, cfg, None, since="1h")


def test_a_symlink_planted_at_the_key_is_never_written_through(monkeypatch, cfg, tmp_path):
    """The key is computable from public facts. A symlink planted there must not carry estate
    inventory into a directory the door did not make owner-only."""
    elsewhere = tmp_path / "open"
    elsewhere.mkdir(mode=0o755)
    base = _store_dir(cfg)
    os.makedirs(base, mode=0o700)
    os.symlink(elsewhere, os.path.join(base, store.key("pve", cfg.base_url, "/cluster/resources", {})))
    out, _ = _read(monkeypatch, cfg, _guests(3))
    assert out["total"] == 3                     # the read is served; the convenience is skipped
    assert os.listdir(elsewhere) == []
