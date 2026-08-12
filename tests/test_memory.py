"""Tier-1 estate memory — increment 1: the estate map + "what changed" diff.

Design: docs/plans/internal/2026-07-29-tiered-memory-design.md. The rails under test:
opt-in (PROXIMO_MEMORY unset => fully inert, no file ever created); derived + rebuildable
(delete the db, the next observe recreates it); age-stamped recall (as_of / age_seconds /
source:"memory" — cached state never masquerades as a live read); a memory write failure
NEVER fails the read that triggered it; honest diff vocabulary (not_seen_since is a fact,
"vanished" would be an inference the map cannot make).

Mirrors the house style: pure-logic tests on EstateMemory first, then the module-level
wrapper seams with monkeypatched env, then the server seam with a fake api + real ledger.
"""

from __future__ import annotations

import os
import stat
import time

import pytest

from proximo.backends import ProximoError
from proximo.memory import (
    EstateMemory,
    memory_enabled,
    observe_guests,
    observe_resources,
    recall_state,
)

NOW = 1_700_000_000.0

GUEST_ROWS = [
    {"vmid": 100, "name": "web", "type": "lxc", "status": "running", "uptime": 5,
     "cpu": 0.1, "mem": 10, "tags": "prod"},
    {"vmid": 200, "name": "db", "type": "qemu", "status": "stopped", "uptime": 0},
]

RESOURCE_ROWS = [
    {"id": "lxc/100", "type": "lxc", "node": "pve", "status": "running", "name": "web",
     "vmid": 100},
    {"id": "node/pve", "type": "node", "node": "pve", "status": "online"},
    {"id": "storage/pve/local", "type": "storage", "node": "pve", "status": "available",
     "storage": "local"},
]


# ---------------------------------------------------------------------------
# Pure logic — EstateMemory
# ---------------------------------------------------------------------------

def _mem(tmp_path) -> EstateMemory:
    return EstateMemory(str(tmp_path / "memory.db"))


def test_observe_creates_the_map_with_first_and_last_seen(tmp_path):
    mem = _mem(tmp_path)
    mem.observe_guests("default", GUEST_ROWS, now=NOW)
    out = mem.recall("default", now=NOW + 10)
    assert out["total"] == 2
    assert out["by_kind"] == {"lxc": 1, "qemu": 1}
    assert out["by_status"] == {"running": 1, "stopped": 1}
    (web,) = [e for e in out["entities"] if e["name"] == "web"]
    assert web["kind"] == "lxc" and web["key"] == "100"
    # default entities are LEAN (identity + status only) — live-caught 2026-07-29: a 12B
    # drowned in 9-field rows with float timestamps and miscounted; depth is opt-in.
    # `node` is keys-if-present (same rule as projection): this guest row never carried one.
    assert set(web) == {"kind", "key", "name", "status"}
    (webf,) = [e for e in mem.recall("default", now=NOW, detail="full")["entities"]
               if e["name"] == "web"]
    assert webf["first_seen"] == webf["last_seen"]


def test_reobserve_moves_last_seen_and_keeps_first_seen(tmp_path):
    mem = _mem(tmp_path)
    mem.observe_guests("default", GUEST_ROWS, now=NOW)
    mem.observe_guests("default", GUEST_ROWS, now=NOW + 100)
    (web,) = [e for e in mem.recall("default", now=NOW + 100, detail="full")["entities"]
              if e["name"] == "web"]
    assert web["first_seen"] < web["last_seen"]


def test_status_change_records_prev_and_when(tmp_path):
    mem = _mem(tmp_path)
    mem.observe_guests("default", GUEST_ROWS, now=NOW)
    changed = [dict(GUEST_ROWS[0], status="stopped"), GUEST_ROWS[1]]
    mem.observe_guests("default", changed, now=NOW + 60)
    (web,) = [e for e in mem.recall("default", now=NOW + 60, detail="full")["entities"]
              if e["name"] == "web"]
    assert web["status"] == "stopped"
    assert web["prev_status"] == "running"
    assert web["status_changed_at"] == NOW + 60


def test_observe_resources_maps_node_and_storage_kinds(tmp_path):
    mem = _mem(tmp_path)
    mem.observe_resources("default", RESOURCE_ROWS, now=NOW)
    out = mem.recall("default", now=NOW)
    assert out["by_kind"] == {"lxc": 1, "node": 1, "storage": 1}
    (st,) = [e for e in out["entities"] if e["kind"] == "storage"]
    assert st["name"] == "local" and st["node"] == "pve"


def test_recall_is_age_stamped_and_names_its_source(tmp_path):
    mem = _mem(tmp_path)
    mem.observe_guests("default", GUEST_ROWS, now=NOW)
    out = mem.recall("default", now=NOW + 90)
    assert out["source"] == "memory"
    assert out["as_of"] == NOW
    assert out["age_seconds"] == 90


def test_recall_diff_appeared_changed_and_not_seen_since(tmp_path):
    mem = _mem(tmp_path)
    mem.observe_guests("default", GUEST_ROWS, now=NOW)
    # later sweep: web changed status, db is gone from the listing, a new guest appeared
    later = [dict(GUEST_ROWS[0], status="stopped"),
             {"vmid": 300, "name": "new", "type": "lxc", "status": "running"}]
    mem.observe_guests("default", later, now=NOW + 100)
    out = mem.recall("default", now=NOW + 100, since_ts=NOW + 50)
    assert [e["name"] for e in out["appeared"]] == ["new"]
    (chg,) = out["status_changed"]
    assert chg["name"] == "web" and chg["prev_status"] == "running"
    # honest vocabulary: db was last observed BEFORE the window — a fact, not "vanished"
    assert [e["name"] for e in out["not_seen_since"]] == ["db"]


def test_recall_carries_an_unambiguous_guest_summary(tmp_path):
    # Live-caught 2026-07-29: with guests+nodes+storage in the map, mistral-nemo answered
    # "36 guests" — the headline total counts ENTITIES, and the model (correctly) trusted
    # the headline. The dominant question class gets its own server-side count.
    mem = _mem(tmp_path)
    mem.observe_guests("default", GUEST_ROWS, now=NOW)
    mem.observe_resources("default", RESOURCE_ROWS, now=NOW)
    out = mem.recall("default", now=NOW)
    assert out["total"] == 4  # entities: 2 guests + node + storage
    assert out["guest_summary"] == {"total": 2,
                                    "by_status": {"running": 1, "stopped": 1}}


def test_recall_detail_summary_drops_entities_and_full_keeps_depth(tmp_path):
    mem = _mem(tmp_path)
    mem.observe_guests("default", GUEST_ROWS, now=NOW)
    summ = mem.recall("default", now=NOW, detail="summary")
    assert "entities" not in summ and summ["total"] == 2
    with pytest.raises(ProximoError):
        mem.recall("default", now=NOW, detail="everything")


def test_recall_on_empty_memory_says_so(tmp_path):
    mem = _mem(tmp_path)
    out = mem.recall("default", now=NOW)
    assert "empty" in out["note"]


def test_empty_memory_reports_no_count_at_all(tmp_path):
    """An unobserved map must not answer a counting question with a zero.

    `total: 0` beside an explanatory note is the 0.26.0 defect in its purest form: a small model
    reads the NUMBER, not the prose around it (a 12B read total:36 and answered a question about
    28 guests). "Nothing observed yet" and "the estate is empty" are different facts and only one
    of them is knowable here. Increment 5 makes this the FIRST call a small model makes on a
    fresh install, so the wrong answer stops being unreachable.
    """
    mem = _mem(tmp_path)
    out = mem.recall("default", now=NOW)
    for field in ("total", "by_kind", "by_status", "guest_summary", "entities"):
        assert field not in out, f"empty memory emitted a count in {field!r}: {out[field]!r}"
    # as_of/age_seconds stay, explicitly null — the baseline precedent: say "no reading",
    # never fabricate one.
    assert out["as_of"] is None and out["age_seconds"] is None


def test_empty_memory_disclaims_the_estate_and_names_the_live_tool(tmp_path):
    """The refusal-shaped response is the highest-stakes prose in the product."""
    mem = _mem(tmp_path)
    note = mem.recall("default", now=NOW)["note"]
    assert "not" in note.lower()
    assert "pve_list_guests" in note


def test_recall_state_refuses_outright_when_nothing_has_been_observed(tmp_path, monkeypatch):
    """LIVE-CAUGHT 2026-07-29, and the reason the counts alone were not enough.

    With every countable field already stripped, qwen3:4b called proximo_recall against an empty
    map and answered "0" — three runs out of three. The note told it in words that this was NOT
    a statement about the estate and named pve_list_guests; it did neither. Removing the number
    left a HOLE and the model filled the hole with zero.

    For a small model prose is not a guardrail. The only thing that reliably stops an answer is
    not returning something answer-shaped, so an unfed map takes the posture the disabled map
    already takes: refuse. `pve_doctor` remains the place to ask whether memory is populated.

    PVE is explicitly configured here — this is the "PVE box, nothing observed yet" scenario the
    live catch actually was. The pve_list_guests/pve_cluster_resources pointer is honest ONLY on
    this shape; see the sibling tests below for the non-PVE remedy (verdict 1.2).
    """
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "empty.db"))
    with pytest.raises(ProximoError) as e:
        recall_state()
    msg = str(e.value)
    assert "pve_list_guests" in msg
    assert "not" in msg.lower()


def test_recall_unfed_remedy_does_not_name_pve_tools_on_a_pbs_only_box(tmp_path, monkeypatch):
    """VERDICT 1.2 (hostile-adopter arena, pbs-only-walk.md #2): the old remedy hardcoded
    pve_list_guests/pve_cluster_resources regardless of which plane is active. On a PBS-only box
    neither tool is even registered, so the remedy pointed the operator at two dead ends. The
    estate map is fed ONLY by PVE-plane reads (observe_guests/observe_resources are wired from
    pve_guest.py/pve_cluster.py alone) — so the honest fix is not a fictitious pbs_* pointer
    (that tool would not feed the map either) but saying plainly that PVE feeds this map and this
    deployment has none configured.
    """
    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_TARGETS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs.example:8007/api2/json")
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "empty.db"))
    with pytest.raises(ProximoError) as e:
        recall_state()
    msg = str(e.value)
    # The defect was an INSTRUCTION to call two unregistered tools — the tool names may still
    # appear as honest context for what feeds the map, but "call pve_list_guests" (a dead-end
    # directive on this deployment shape) must not.
    assert "call pve_list_guests" not in msg
    assert "no PVE plane configured" in msg
    assert "not" in msg.lower()
    assert "proximo doctor" in msg


def test_recall_unfed_remedy_is_honest_with_nothing_configured_at_all(tmp_path, monkeypatch):
    """The cold-start-nothing shape: same non-PVE remedy, no plane configured at all."""
    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_PBS_BASE_URL", "PROXIMO_PMG_BASE_URL",
                "PROXIMO_PDM_BASE_URL", "PROXIMO_TARGETS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "empty.db"))
    with pytest.raises(ProximoError) as e:
        recall_state()
    msg = str(e.value)
    assert "call pve_list_guests" not in msg
    assert "no PVE plane configured" in msg
    assert "not" in msg.lower()


def test_a_journal_entry_is_still_reachable_with_an_unfed_estate_map(tmp_path, monkeypatch):
    """Refuse only when there is genuinely nothing to report.

    diagnose/doctor feed the journal; list reads feed the estate map. Run the first and not the
    second and the map is empty while the journal is not — refusing there would hide real
    recorded history behind a map that simply has not been fed.
    """
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "journal-only.db"))
    mem = EstateMemory(str(tmp_path / "journal-only.db"))
    mem.add_journal("default", "pve_doctor", "preflight", True, "clean")
    mem.close()

    out = recall_state(journal=5)
    assert len(out["journal"]) == 1
    for field in ("total", "guest_summary", "entities"):
        assert field not in out, f"an unfed estate map still emitted {field!r}"


def test_targets_are_isolated(tmp_path):
    mem = _mem(tmp_path)
    mem.observe_guests("default", GUEST_ROWS, now=NOW)
    mem.observe_guests("edge", [GUEST_ROWS[0]], now=NOW)
    assert mem.recall("default", now=NOW)["total"] == 2
    assert mem.recall("edge", now=NOW)["total"] == 1


def test_deleting_the_db_loses_convenience_never_truth(tmp_path):
    mem = _mem(tmp_path)
    mem.observe_guests("default", GUEST_ROWS, now=NOW)
    os.unlink(str(tmp_path / "memory.db"))
    mem2 = _mem(tmp_path)
    mem2.observe_guests("default", GUEST_ROWS, now=NOW + 5)
    assert mem2.recall("default", now=NOW + 5)["total"] == 2


# ---------------------------------------------------------------------------
# Module seam — env-gated wrappers the tools call
# ---------------------------------------------------------------------------

def test_memory_defaults_on(monkeypatch):
    """The 0.30 flip: unset means ENABLED — the estate map is part of the default install."""
    monkeypatch.delenv("PROXIMO_MEMORY", raising=False)
    assert memory_enabled()


def test_every_opt_out_spelling_disables(monkeypatch):
    for v in ("0", "false", "no", "off", "OFF", " 0 "):
        monkeypatch.setenv("PROXIMO_MEMORY", v)
        assert not memory_enabled(), v


def test_opted_out_means_fully_inert_no_file(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    observe_guests(GUEST_ROWS)
    assert not memory_enabled()
    assert not (tmp_path / "memory.db").exists()


def test_disabled_recall_refuses_with_the_reenable_hint(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    with pytest.raises(ProximoError) as ei:
        recall_state()
    assert "PROXIMO_MEMORY" in str(ei.value)


def test_enabled_observe_then_recall_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    observe_guests(GUEST_ROWS)
    observe_resources(RESOURCE_ROWS)
    out = recall_state()
    assert out["total"] == 4  # 100/200 from guests + node + storage (lxc/100 == guest 100)
    assert out["source"] == "memory"
    assert out["age_seconds"] >= 0


def test_recall_since_accepts_relative_and_iso(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    observe_guests(GUEST_ROWS)
    out = recall_state(since="24h")
    assert [e["name"] for e in sorted(out["appeared"], key=lambda e: e["key"])] == ["web", "db"]
    out2 = recall_state(since="2001-01-01T00:00:00")
    assert len(out2["appeared"]) == 2
    with pytest.raises(ProximoError):
        recall_state(since="not-a-time")


def test_observe_failure_never_breaks_the_read(tmp_path, monkeypatch):
    # a directory where the db file should be => sqlite cannot open it
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path))  # a DIRECTORY, not a file
    with pytest.warns(UserWarning, match="memory"):
        observe_guests(GUEST_ROWS)  # must not raise


# ---------------------------------------------------------------------------
# Server seam — the tools observe opportunistically; proximo_recall is a governed tool
# ---------------------------------------------------------------------------

def _wire(monkeypatch, tmp_path, api_obj):
    import proximo.server as server
    from proximo.audit import AuditLedger
    from proximo.config import ProximoConfig

    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve",
                        token_path="/run/x", audit_log_path=str(tmp_path / "audit.log"))
    ledger = AuditLedger(str(tmp_path / "audit.log"))
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api_obj, None, ledger))
    return server


class _GuestApi:
    def list_guests(self, node=None):
        return [dict(r) for r in GUEST_ROWS]


def test_pve_list_guests_feeds_the_estate_map(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    server = _wire(monkeypatch, tmp_path, _GuestApi())
    out = server.pve_list_guests()
    assert out["total"] == 2  # the envelope is unchanged by memory
    assert recall_state()["total"] == 2


def test_pve_list_guests_survives_a_broken_memory_path(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path))  # a DIRECTORY
    server = _wire(monkeypatch, tmp_path, _GuestApi())
    with pytest.warns(UserWarning, match="memory"):
        out = server.pve_list_guests()
    assert out["total"] == 2


def test_proximo_recall_is_a_governed_read_on_the_ledger(monkeypatch, tmp_path):
    import json

    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    server = _wire(monkeypatch, tmp_path, _GuestApi())
    server.pve_list_guests()
    out = server.proximo_recall()
    assert out["total"] == 2 and out["source"] == "memory"
    with open(str(tmp_path / "audit.log"), encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    assert any(e["action"] == "proximo_recall" and e["mutation"] is False
               for e in entries)


def test_memory_defaults_beside_the_audit_log(monkeypatch, tmp_path):
    # No PROXIMO_MEMORY_PATH: the db lands next to the audit log the env names.
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.delenv("PROXIMO_MEMORY_PATH", raising=False)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "sub" / "audit.log"))
    observe_guests(GUEST_ROWS)
    assert (tmp_path / "sub" / "memory.db").exists()


def test_recall_freshness_is_wall_clock(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    t0 = time.time()
    observe_guests(GUEST_ROWS)
    out = recall_state()
    assert 0 <= out["age_seconds"] < max(5.0, time.time() - t0 + 5.0)


# ---------------------------------------------------------------------------
# Increment 2 — baselines from rrddata rollups
# ---------------------------------------------------------------------------

RRD_SAMPLES = [
    # a week-ish of rrddata shape: time + metric keys; None/missing values happen (stopped spans)
    {"time": 1_699_900_000 + i * 100, "cpu": c, "mem": m, "maxmem": 2048}
    for i, (c, m) in enumerate(
        [(0.10, 900), (0.20, 1000), (0.30, 1100), (0.40, 1200), (None, None),
         (0.10, 900), (0.15, 950), (0.20, 1000), (0.25, 1050), (0.90, 1900)])
]


def test_rollup_computes_distribution_and_skips_missing():
    from proximo.memory import rollup_samples
    r = rollup_samples(RRD_SAMPLES, metrics=("cpu", "mem"))
    assert r["cpu"]["n"] == 9  # the None sample is skipped, not counted as zero
    assert r["cpu"]["max"] == 0.90
    assert r["cpu"]["p50"] == 0.20
    assert r["cpu"]["p95"] == 0.90
    assert round(r["cpu"]["mean"], 4) == round(sum(
        c for c, _ in [(0.10, 0), (0.20, 0), (0.30, 0), (0.40, 0), (0.10, 0),
                       (0.15, 0), (0.20, 0), (0.25, 0), (0.90, 0)]) / 9, 4)
    assert r["mem"]["max"] == 1900


def test_rollup_with_no_usable_samples_refuses():
    from proximo.memory import rollup_samples
    with pytest.raises(ProximoError, match="no usable samples"):
        rollup_samples([{"time": 1, "cpu": None}], metrics=("cpu",))


def test_baseline_store_and_get_roundtrip(tmp_path):
    from proximo.memory import rollup_samples
    mem = _mem(tmp_path)
    rollups = rollup_samples(RRD_SAMPLES, metrics=("cpu", "mem"))
    mem.store_baseline("default", "lxc", "100", "week", rollups,
                       window=(1_699_900_000, 1_699_900_900), now=NOW)
    got = mem.get_baseline("default", "lxc", "100", "week")
    assert got["metrics"]["cpu"]["p95"] == 0.90
    assert got["updated_at"] == NOW
    assert got["window"] == [1_699_900_000, 1_699_900_900]
    assert mem.get_baseline("default", "lxc", "999", "week") is None


class _RrdApi:
    """Fake api: guest rrddata + call counting (the stored-baseline path must NOT call PVE)."""

    def __init__(self):
        from types import SimpleNamespace
        self.rrd_calls = 0
        self.config = SimpleNamespace(node="pve")

    def _get(self, path):
        self.rrd_calls += 1
        assert "/lxc/100/rrddata" in path
        return [dict(s) for s in RRD_SAMPLES]

    def list_guests(self, node=None):  # unused here; keeps the fake honest if reused
        return []


def test_proximo_baseline_pulls_stores_and_assesses(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    api = _RrdApi()
    server = _wire(monkeypatch, tmp_path, api)
    out = server.proximo_baseline(vmid="100", kind="lxc", timeframe="week")
    assert out["source"] == "live+memory" and api.rrd_calls == 1
    assert out["baseline"]["cpu"]["p95"] == 0.90
    # current = the newest usable sample (0.90 cpu) — at the observed max
    assert out["current"]["cpu"] == 0.90
    assert "advisory" in out["assessment"]["note"]
    assert "p95" in out["assessment"]["cpu"] or "max" in out["assessment"]["cpu"]


def test_proximo_baseline_serves_stored_without_a_pve_call(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    api = _RrdApi()
    server = _wire(monkeypatch, tmp_path, api)
    server.proximo_baseline(vmid="100", kind="lxc", timeframe="week")
    out = server.proximo_baseline(vmid="100", kind="lxc", timeframe="week")
    assert api.rrd_calls == 1  # second call answered from memory
    assert out["source"] == "memory"
    assert out["age_seconds"] >= 0
    assert out["current"] is None  # no live pull happened; say so rather than fake one
    assert "refresh" in out["hint"]


def test_proximo_baseline_refresh_forces_the_pull(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    api = _RrdApi()
    server = _wire(monkeypatch, tmp_path, api)
    server.proximo_baseline(vmid="100", kind="lxc", timeframe="week")
    server.proximo_baseline(vmid="100", kind="lxc", timeframe="week", refresh=True)
    assert api.rrd_calls == 2


def test_proximo_baseline_opted_out_refuses_with_hint(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    server = _wire(monkeypatch, tmp_path, _RrdApi())
    with pytest.raises(ProximoError, match="PROXIMO_MEMORY"):
        server.proximo_baseline(vmid="100", kind="lxc")


def test_proximo_baseline_pull_path_raises_proximo_error_with_no_pve_env(monkeypatch, tmp_path):
    """VERDICT 1.5: proximo_baseline is structurally PVE-guest-only. The stored-rollup path
    already answers with no PVE env (test above, unbroken by this change); the LIVE PULL path
    genuinely needs a configured PVE plane to fetch rrddata, and on a PBS/PMG/PDM-only box it
    must say so as a named ProximoError, not leak the api thunk's bare RuntimeError."""
    import proximo.server as server

    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH",
                "PROXIMO_TARGETS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("PROXIMO_LEDGER_REDACT", "1")
    server._svc_cache_clear()
    try:
        with pytest.raises(ProximoError, match="configured PVE plane"):
            server.proximo_baseline(vmid="999", kind="lxc")  # no stored rollup for this vmid
    finally:
        server._svc_cache_clear()


def test_proximo_baseline_docstring_states_pve_guest_only_scope():
    """VERDICT 1.5(a): the docstring must say plainly this tool has nothing to report on a
    PBS/PMG/PDM-only deployment — matching proximo_wiki's existing scope-honesty pattern."""
    import proximo.server as server
    doc = server.proximo_baseline.__doc__ or ""
    assert "PVE-guest-only" in doc
    assert "PBS/PMG/PDM-only" in doc


def test_proximo_baseline_is_on_the_ledger(monkeypatch, tmp_path):
    import json

    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    server = _wire(monkeypatch, tmp_path, _RrdApi())
    server.proximo_baseline(vmid="100", kind="lxc", timeframe="week")
    with open(str(tmp_path / "audit.log"), encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    assert any(e["action"] == "proximo_baseline" and e["target"] == "lxc/100"
               and e["mutation"] is False for e in entries)


# ---------------------------------------------------------------------------
# Increment 3 — the diagnosis journal ("when did this last happen?")
# ---------------------------------------------------------------------------

def test_journal_digest_is_compact_and_never_raw_output():
    from proximo.memory import journal_digest
    ok, summary = journal_digest({"flags": [], "status": {"uptime": 1}})
    assert ok is True and summary == "clean"
    ok, summary = journal_digest({"flags": ["storage local at 93%", "1 recent failed task(s)"]})
    assert ok is False
    assert "storage local at 93%" in summary and "failed task" in summary
    # errored sections are findings too — a diagnose that half-ran is not "clean"
    ok, summary = journal_digest({"flags": [], "storage": {"error": "Timeout"}})
    assert ok is False and "storage errored: Timeout" in summary


def test_journal_digest_truncates_a_flag_flood():
    from proximo.memory import journal_digest
    ok, summary = journal_digest({"flags": [f"flag {i}" for i in range(9)]})
    assert ok is False
    assert "flag 4" in summary and "flag 8" not in summary
    assert "+4 more" in summary


def test_journal_add_get_order_limit_and_since(tmp_path):
    mem = _mem(tmp_path)
    for i in range(5):
        mem.add_journal("default", "pve_diagnose", "node/pve", i % 2 == 0,
                        f"entry {i}", now=NOW + i * 10)
    got = mem.get_journal("default", limit=3, now=NOW + 100)
    assert [g["summary"] for g in got] == ["entry 4", "entry 3", "entry 2"]  # newest first
    assert got[0]["age_seconds"] == 60  # NOW+100 - (NOW+40)
    assert got[0]["ok"] is True and got[1]["ok"] is False
    windowed = mem.get_journal("default", limit=10, since_ts=NOW + 25, now=NOW + 100)
    assert [g["summary"] for g in windowed] == ["entry 4", "entry 3"]
    assert mem.get_journal("elsewhere", limit=10) == []


def test_journal_record_module_seam_is_env_gated(tmp_path, monkeypatch):
    from proximo.memory import journal_record
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    journal_record("pve_diagnose", "node/pve", {"flags": []})
    assert not (tmp_path / "memory.db").exists()
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    journal_record("pve_diagnose", "node/pve", {"flags": ["node memory at 95%"]})
    # A bare recall asks for the ESTATE MAP, and no list read has fed it — that refuses, journal
    # history or not. Asking for the journal is what makes the journal reportable.
    with pytest.raises(ProximoError):
        recall_state()
    # journal entries surface through recall on request
    out = recall_state(journal=5)
    assert out["journal"][0]["tool"] == "pve_diagnose"
    assert out["journal"][0]["ok"] is False
    assert "memory at 95%" in out["journal"][0]["summary"]


class _DiagApi:
    """Fake api for diagnose_node: healthy except one failed task."""

    def node_status(self, node=None):
        return {"uptime": 100, "cpu": 0.1, "loadavg": [0.1], "memory": {"used": 1, "total": 10}}

    def node_storage(self, node=None):
        return []

    def node_tasks(self, node=None):
        return [{"upid": "UPID:x", "status": "some error", "endtime": 2}]

    def list_guests(self, node=None):
        return []


def test_pve_diagnose_feeds_the_journal(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    server = _wire(monkeypatch, tmp_path, _DiagApi())
    report = server.pve_diagnose()
    assert "failed task" in " ".join(report.get("flags", []))
    out = recall_state(journal=3)
    (entry,) = out["journal"]
    assert entry["tool"] == "pve_diagnose" and entry["ok"] is False
    assert "failed task" in entry["summary"]


def test_recall_without_journal_param_has_no_journal_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    observe_guests(GUEST_ROWS)
    assert "journal" not in recall_state()


# ---------------------------------------------------------------------------
# Increment 4 — the doctor's memory section
# ---------------------------------------------------------------------------

def test_memory_status_opted_out_reports_the_reenable_hint(monkeypatch):
    from proximo.memory import memory_status
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    out = memory_status()
    assert out["enabled"] is False
    assert "PROXIMO_MEMORY=1" in out["hint"]


def test_memory_status_reports_size_counts_and_freshness(tmp_path, monkeypatch):
    from proximo.memory import journal_record, memory_status
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    observe_guests(GUEST_ROWS)
    journal_record("pve_diagnose", "node/pve", {"flags": []})
    out = memory_status()
    assert out["enabled"] is True
    assert out["path"].endswith("memory.db") and out["db_bytes"] > 0
    assert out["target"] == "default"
    assert out["entities"] == 2
    assert out["baselines"] == 0
    assert out["journal_entries"] == 1
    assert out["newest_observation_age_seconds"] >= 0
    assert out["oldest_observation_age_seconds"] >= out["newest_observation_age_seconds"]


def test_memory_status_on_an_empty_map_says_so(tmp_path, monkeypatch):
    from proximo.memory import memory_status
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    out = memory_status()
    assert out["enabled"] is True and out["entities"] == 0
    assert "fills as reads happen" in out["note"]


def test_memory_status_never_raises_on_a_broken_db(tmp_path, monkeypatch):
    from proximo.memory import memory_status
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path))  # a DIRECTORY
    out = memory_status()
    assert out["enabled"] is True
    assert "error" in out  # doctor must never die on a memory problem


def test_doctor_report_carries_the_memory_section(tmp_path, monkeypatch):
    from proximo.doctor import doctor_check
    from test_doctor import _DoctorApi  # not "tests.": bare `pytest` (CI) has tests/ on sys.path, not the repo root
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    observe_guests(GUEST_ROWS)
    report = doctor_check(_DoctorApi())
    assert report["memory"]["enabled"] is True
    assert report["memory"]["entities"] == 2
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    report = doctor_check(_DoctorApi())
    assert report["memory"]["enabled"] is False


def test_doctor_flags_a_broken_memory_db(tmp_path, monkeypatch):
    from proximo.doctor import doctor_check
    from test_doctor import _DoctorApi  # not "tests.": bare `pytest` (CI) has tests/ on sys.path, not the repo root
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path))  # a DIRECTORY
    report = doctor_check(_DoctorApi())
    assert any("memory" in f for f in report["flags"])


# --- the file mode ---------------------------------------------------------------------------
#
# REDTEAM 2026-07-29: memory.db was created at the process umask (0644 on a default box), in the
# SAME directory where audit.py deliberately creates the ledger at 0600 with the comment "entries
# carry command/SQL detail, so the umask default is too open". The map holds the estate's
# inventory in plaintext — guest names, node names, target names, status history, and a journal of
# operations. "Nothing leaves the box" was true and incomplete: it stayed on the box and was
# readable by every local user.

def test_a_new_memory_db_is_owner_only(tmp_path):
    from proximo.memory import EstateMemory
    p = str(tmp_path / "memory.db")
    m = EstateMemory(p)
    m.close()
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600, oct(stat.S_IMODE(os.stat(p).st_mode))


def test_estate_memory_refuses_a_directory_path_instead_of_leaking_sqlite_error(tmp_path):
    """VERDICT 1.10a: PROXIMO_MEMORY_PATH pointed at an existing directory (the exact typo a
    copy-paste of SETUP.md's example path risks) must raise the same ProximoError style as
    wiki.py's sibling isdir guard, never a raw sqlite3.OperationalError."""
    with pytest.raises(ProximoError, match="directory, not a file"):
        EstateMemory(str(tmp_path))


def test_an_existing_loose_memory_db_is_tightened_on_open(tmp_path):
    """Repair installs already created by the looser code — this is derived data we own."""
    from proximo.memory import EstateMemory
    p = str(tmp_path / "memory.db")
    EstateMemory(p).close()
    os.chmod(p, 0o644)  # noqa: S103 -- reproducing the defect being repaired
    EstateMemory(p).close()
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert not mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH), oct(mode)


def test_recall_refuses_as_itself_on_a_box_with_no_pve_env(monkeypatch, tmp_path):
    """Recall must not demand PVE env — memory is local (ultra review 2026-07-30). On an
    unfed map the correct refusal is the unfed-map ProximoError; before the fix this died
    earlier and wronger, with RuntimeError('Missing required Proximo env var: ...') from
    the wrapper's discarded _svc() call. Real _svc on purpose — the _wire mock is why the
    suite missed it."""
    import proximo.server as server

    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH",
                "PROXIMO_TARGETS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    # The recommended posture; also keeps the redact advisory out of the suite.
    monkeypatch.setenv("PROXIMO_LEDGER_REDACT", "1")
    server._svc_cache_clear()
    try:
        with pytest.raises(ProximoError, match="observed nothing yet"):
            server.proximo_recall()
    finally:
        server._svc_cache_clear()


def test_a_stored_baseline_answers_with_no_pve_env_as_the_docstring_promises(
        monkeypatch, tmp_path):
    """The stored path says 'NO PVE call' — so it must not demand PVE env either. The
    eager _svc() unpack blocked the memory-only answer on a PVE-less box; api now
    resolves lazily, at the moment rrddata is actually needed (2nd-lens find,
    2026-07-30). Real _svc again, on purpose."""
    import proximo.server as server
    from proximo import memory as memory_mod

    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH",
                "PROXIMO_TARGETS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("PROXIMO_LEDGER_REDACT", "1")
    target = memory_mod._active_target_name()
    mem = memory_mod.EstateMemory(memory_mod.memory_path())
    mem.store_baseline(target, "lxc", "101", "week",
                       {"cpu": {"n": 3, "mean": 0.5, "p50": 0.5, "p95": 0.9, "max": 1.0}},
                       window=(1_700_000_000.0, 1_700_600_000.0))
    mem.close()
    server._svc_cache_clear()
    try:
        out = server.proximo_baseline(vmid="101", kind="lxc")
        assert out["source"] == "memory"
        assert out["current"] is None
    finally:
        server._svc_cache_clear()


def test_next_pointer_names_the_reader_and_says_what_is_never_here(tmp_path, monkeypatch):
    """Two live-run defects, 2026-08-01, pinned together because they live in one dict:
    (1) for_more still pointed the who-changed question at audit_verify — the PROVER —
    after audit_entries (the READER) shipped; (2) map_holds stated the map's contents only
    positively, and one of ten qwen3:8b runs filled the silence with a fabricated "1.5GB".
    A tool response is a prompt: the limit must be stated negatively."""
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    observe_guests(GUEST_ROWS)
    nxt = recall_state(query="web")["next"]
    assert "audit_entries" in nxt["for_more"]
    assert "not_held" in nxt
    low = nxt["not_held"].lower()
    assert "never" in low and "mem" in low


def test_startup_names_the_memory_file_while_it_is_on(tmp_path, monkeypatch, capsys):
    """EXTERNAL VET 2026-08-02: default-on must not mean unannounced.

    The objection was never to the rails (0600-before-open, O_NOFOLLOW — the reviewer rated
    those solid); it was that 0.30.0 made every existing install grow a plaintext inventory of
    its guests, nodes and targets with nothing said. John's call was keep the default, make it
    loud. "Loud" means the PATH: "memory is on" is not something an operator can act on.
    """
    import proximo.server as server
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    server._announce_estate_memory()
    err = capsys.readouterr().err
    assert str(tmp_path / "memory.db") in err, err
    assert "PROXIMO_MEMORY=0" in err          # the opt-out travels with the announcement


def test_startup_says_nothing_when_memory_is_off(tmp_path, monkeypatch, capsys):
    """Opted out is opted out: no file, and no line about a file."""
    import proximo.server as server
    monkeypatch.setenv("PROXIMO_MEMORY", "0")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    server._announce_estate_memory()
    assert capsys.readouterr().err == ""
