"""Third adversarial lens: each test states what the claim ("every model-facing answer is capped") promises,
and each finding it caught is now fixed (the xfail markers are gone). Plain tests pin what held."""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import pytest

from proximo.core import diagnose, engine, rawdoor, wire
from proximo.core.doors import mcp as door
from proximo.core.errors import ProximoError
from test_core_diagnose import NODE, _node_wire, box  # noqa: F401  (fixture re-export)


@dataclass(frozen=True)
class _Cfg(wire.Plane):
    audit_log_path: str = ""
    audit_key_path: str | None = None


class _Body:
    def __init__(self, body):
        self.body = body

    def call(self, method, path, params=None):
        return self.body


@pytest.fixture
def cfg(tmp_path):
    return _Cfg("pve", "https://unreachable.invalid:8006/api2/json", "/dev/null",
                audit_log_path=str(tmp_path / "audit.log"))


def _c(x):
    return json.dumps(x, separators=(",", ":"), default=str)


def _over(out, cap=None) -> bool:
    t = _c(out)
    return not rawdoor.fits(len(t.encode()), t, cap=cap)


_QEMU_CREATE = "POST", "/nodes/{node}/qemu", "/nodes/pve1/qemu"
_CONFIG = "PUT", "/nodes/{node}/qemu/{vmid}/config", "/nodes/pve1/qemu/100/config"


# --- 1. the window promise: answers that are not capped ------------------------------------------------

def test_a_plan_with_many_long_given_arguments_is_capped(cfg):
    row = engine.resolve("pve", _QEMU_CREATE[0], _QEMU_CREATE[1])
    args = {n: "v" * 500 for n in [n for n in row.params if "[" not in n][:60]}   # 60 given args, 500 chars each
    out = engine.plan(row, args, _QEMU_CREATE[2], cfg=cfg, ledger_cfg=cfg)
    # round 6 (John's ruling): the plan does not echo the model's values back; every name stays
    assert len(out["arguments"]) == 48 and out["arguments_more"] == len(args) - 48 and "vvvv" not in _c(out)


def test_a_plan_that_changes_one_long_value_costs_it_once_at_most_and_is_capped(monkeypatch, cfg):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Body({"name": "vm", "description": "d " * 300}))
    row = engine.resolve("pve", _CONFIG[0], _CONFIG[1])
    out = engine.plan(row, {"description": "x" * 4000}, _CONFIG[2], cfg=cfg, ledger_cfg=cfg)
    assert "change" in out                                                # the diff was computed ...
    assert not _over(out, rawdoor.plan_cap()), len(_c(out))              # ... and was 5 KB against the cap


def test_a_plan_of_twelve_dense_config_edits_stays_under_the_cap(monkeypatch, cfg):
    mac = "virtio=AA:BB:CC:DD:EE:%02X,bridge=vmbr9,tag=%d"
    rec = {"name": "vm", **{f"net{i}": f"virtio=11:22:33:44:55:{i:02X},bridge=vmbr0" for i in range(12)}}
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Body(rec))
    row = engine.resolve("pve", _CONFIG[0], _CONFIG[1])
    args = {f"net{i}": mac % (i, 200 + i) for i in range(12)}
    out = engine.plan(row, args, _CONFIG[2], cfg=cfg, ledger_cfg=cfg)
    assert not _over(out, rawdoor.plan_cap()), len(_c(out))


def test_a_read_of_a_very_long_path_is_refused_short_and_a_long_one_is_echoed_clipped(monkeypatch, cfg):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Body({"status": "ok"}))
    huge = "/nodes/" + "N" * 20000 + "/status"
    with pytest.raises(ProximoError) as e:
        engine.execute(engine.resolve("pve", "GET", huge), {}, cfg=cfg, ledger_cfg=cfg, path=huge)
    assert len(str(e.value)) < 200 and "NNNN" not in str(e.value)
    path = "/nodes/" + "N" * 300 + "/status"                       # a long path the door takes: echoed clipped
    out = engine.execute(engine.resolve("pve", "GET", path), {}, cfg=cfg, ledger_cfg=cfg, path=path)
    assert "chars, sha256:" in out["called_path"] and len(out["called_path"]) < 220
    assert not _over(out), len(_c(out))


def _tool(server, name, args):
    try:
        asyncio.run(server.call_tool(name, args))
    except Exception as e:  # noqa: BLE001 -- the SDK wraps every refusal; the text is what the model reads
        return str(e)
    raise AssertionError("expected a refusal")


@pytest.fixture
def server(monkeypatch, tmp_path):
    import os
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":
            monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    return door.build_server()


@pytest.mark.parametrize("tool,args", [
    ("proximo_call", {"plane": "pve", "method": "Z" * 60000, "path": "/x"}),
    ("proximo_plan", {"plane": "pve", "method": "Z" * 60000, "path": "/x"}),
    ("audit_verify", {"path": "Z" * 60000}),
])
def test_a_refusal_never_echoes_what_the_model_sent_whole(server, tool, args):
    # a REFUSAL is an answer the model is handed: 60 KB in, 60 KB (30,000 real tokens) back
    said = _tool(server, tool, args)
    assert len(said) <= 2000, f"{tool} echoed {len(said)} bytes of a 60000-byte input"


# --- 2/4. a clip is not a trim --------------------------------------------------------------------------

def test_a_clipped_string_in_a_plan_says_it_was_clipped(monkeypatch, cfg):
    row = engine.resolve("pve", _CONFIG[0], _CONFIG[1])
    for n in range(8, 30):                      # the first size at which clipping alone makes the plan fit
        rec = {"name": "vm", "memory": 2048, "description": "runbook " + "word " * 50,
               **{f"net{i}": f"virtio=AA:BB:CC:DD:EE:{i:02X},bridge=vmbr0,firewall=1" for i in range(n)}}
        monkeypatch.setattr(engine, "_client", lambda product, c=None, rec=rec: _Body(rec))
        out = engine.plan(row, {"memory": 4096}, _CONFIG[2], cfg=cfg, ledger_cfg=cfg)
        if "trimmed" in out and "description" in out["current"]:
            break
    desc = out["current"]["description"]
    assert "(" in desc and "chars, sha256:" in desc                  # the vendor's text was cut; the cut says so
    assert "clipped" in " ".join(out["trimmed"].values()), out.get("trimmed")


# --- 4. diagnose ----------------------------------------------------------------------------------------

def test_a_diagnosis_with_many_flags_is_capped(box, monkeypatch):  # noqa: F811
    storage = [{"storage": f"nfs-{i}", "type": "nfs", "active": 0, "enabled": 1, "total": 10**12, "used": 10**11,
                "avail": 9 * 10**11, "content": "iso,backup", "shared": 1} for i in range(80)]
    _node_wire(monkeypatch, storage=storage)
    out = diagnose.run("pve", NODE, cfg=box)
    assert len(out["flags"]) == 1 and out["flags"][0].split(" ", 1)[1].startswith("storages are inactive")
    assert rawdoor.fits(len(_c(out).encode()), _c(out), cap=rawdoor.composed_cap()), len(_c(out))


def test_diagnose_trimming_keeps_every_flag_and_names_what_it_cut(box, monkeypatch):  # noqa: F811
    """HELD: the flags are computed before the trim and never touched by it; `trimmed` names each halving."""
    storage = [{"storage": f"nfs-{i}", "type": "nfs", "active": 0, "enabled": 1} for i in range(30)]
    _node_wire(monkeypatch, storage=storage)
    out = diagnose.run("pve", NODE, cfg=box)
    assert len(out["flags"]) == 1 and out["flags"][0].startswith("30 storages are inactive")
    assert "nfs-29" not in out["flags"][0] and "27 more" in out["flags"][0]
    assert out["trimmed"] and out["next"]


# --- 5. summaries ---------------------------------------------------------------------------------------

def _rows(n):
    return [{"id": f"qemu/{100 + i}", "type": "qemu", "node": "pve1", "vmid": 100 + i, "name": f"svc-{i:02d}",
             "status": "running" if i % 3 else "stopped", "tags": "prod;web", "cpu": 0.0123 + i / 1000,
             "disk": 1234567890 + i, "maxmem": 2147483648, "uptime": 123456 + i} for i in range(n)]


def test_the_next_of_a_cut_never_suggests_what_the_caller_already_did(monkeypatch, cfg):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Body(_rows(300)))
    out = engine.execute(engine.resolve("pve", "GET", "/cluster/resources"), {}, cfg=cfg, ledger_cfg=cfg,
                         path="/cluster/resources", fields="name,status")
    assert out["truncated"] is True and out["returned"] < out["total"]
    assert "fields='name,status'" not in out["next"]


def test_a_summary_and_the_cut_it_points_at_are_truthful(monkeypatch, cfg):
    """HELD: totals and counts are from the raw rows; the minority count is whole, the returned count is what's kept."""
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Body(_rows(100)))
    out = engine.execute(engine.resolve("pve", "GET", "/cluster/resources"), {}, cfg=cfg, ledger_cfg=cfg,
                         path="/cluster/resources")
    assert out["summarized"] is True and out["total"] == 100
    assert sum(out["tally"]["status"].values()) == 100 and out["tally"]["status"]["stopped"] == 34
    assert out["minority_total"] == 34 and out["minority_returned"] == len(out["minority"]) < 34


# --- 6. read-by-words -----------------------------------------------------------------------------------

def test_a_mutating_verb_reaching_a_get_is_a_read_and_says_so(monkeypatch, cfg):
    """A GET whose own path names the verb is a read and is not refused; the answer says it only read."""
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Body({"ok": 1}))
    out = door.read("pbs", "destroy tape media", cfg=cfg)
    assert out["access"] == "read" and out["called_path"] == "/tape/media/destroy"
    assert "nothing was changed" in out["read_only"]


# --- 8. the find cap ------------------------------------------------------------------------------------

def test_a_find_that_dropped_matches_is_still_under_the_byte_cap():
    out = door.find("quarantine clamav", limit=25)
    assert out["truncated"] is True
    assert len(_c(out).encode()) <= rawdoor.DEFAULT_MAX_BYTES, len(_c(out).encode())
