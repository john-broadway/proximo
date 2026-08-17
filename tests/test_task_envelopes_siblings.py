"""Task-list envelopes for the three sibling planes (PBS / PMG / PDM).

Every fixture below is the shape those planes ACTUALLY returned when probed against the
sealed lab on 2026-08-13 (PBS 4.2, PMG 9.1, PDM 1.1.4). They are not PVE rows with the
names changed, because the planes genuinely disagree:

  * PBS and PDM name their columns `worker_type`/`worker_id`; PVE and PMG use `type`/`id`.
    Asking for one plane's names on another is REFUSED by `project_rows` with the available
    names listed (pinned below by test_an_unknown_field_is_refused_with_the_available_names),
    so the disagreement surfaces loudly rather than as empty rows.
  * A RUNNING PBS row omits BOTH `endtime` and `status` (proven twice: aptupdate and
    garbage_collection).
  * PDM's `upid` is remote-qualified (`pve:pve-test4!UPID:…`) and its `status` carries raw
    error TEXT.
  * PMG never produced a failure or an in-flight row across four attempts, so its failure
    vocabulary is UNOBSERVED. The tests here pin that the classifier degrades safely under
    that ignorance rather than pretending to know it.
"""
import json
from types import SimpleNamespace

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.config import ProximoConfig


def _wire(tmp_path, monkeypatch, *, pbs=None, pmg=None, pdm=None):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve",
                        token_path="/run/x", audit_log_path=log)
    ledger = AuditLedger(log)
    monkeypatch.setattr(server, "_svc",
                        lambda: (cfg, SimpleNamespace(), SimpleNamespace(), ledger))
    if pbs is not None:
        monkeypatch.setattr(server, "_pbs", lambda: (SimpleNamespace(), pbs))
    if pmg is not None:
        monkeypatch.setattr(server, "_pmg",
                            lambda: (SimpleNamespace(node="pmg-test"), pmg))
    if pdm is not None:
        monkeypatch.setattr(server, "_pdm", lambda: (SimpleNamespace(), pdm))
    return log


# --- PBS ----------------------------------------------------------------------

PBS_FINISHED = {"upid": "UPID:pbs-test:AA:1:0:X:garbage_collection:test-ds:root@pam!live:",
                "node": "localhost", "pid": 170, "pstart": 453945221, "starttime": 1786594540,
                "worker_type": "garbage_collection", "worker_id": "test-ds",
                "user": "root@pam!live", "endtime": 1786594545, "status": "OK"}
# Transcribed from the live in-flight row, NOT derived from PBS_FINISHED: a fixture computed
# from the claim it is meant to evidence would agree with a misreading of the probe. Both
# `endtime` and `status` are absent, and that pair of absences is the whole tell.
PBS_RUNNING = {"upid": "UPID:pbs-test:91:1B0EA779:0:X:aptupdate::root@pam!proximo-live:",
               "node": "localhost", "pid": 145, "pstart": 453945209,
               "starttime": 1786594532, "worker_type": "aptupdate", "worker_id": None,
               "user": "root@pam!proximo-live"}
# A real WARNINGS row: its upid agrees with its worker_type (the earlier version inherited a
# garbage_collection upid while claiming aptupdate — a row no PBS would emit).
PBS_WARN = {**PBS_FINISHED,
            "upid": "UPID:pbs-test:1550:01D24B81:0:X:aptupdate::root@pam:",
            "worker_type": "aptupdate", "worker_id": None, "status": "WARNINGS: 1"}



def test_pbs_envelope_uses_worker_type_not_pve_type(tmp_path, monkeypatch):
    import proximo.tools.pbs as tools_pbs
    monkeypatch.setattr(tools_pbs, "pbs_tasks_list_op",
                        lambda *a, **k: [PBS_FINISHED, PBS_WARN])
    _wire(tmp_path, monkeypatch, pbs=SimpleNamespace())
    out = server.pbs_tasks_list()
    assert out["returned"] == 2
    assert out["by_outcome"] == {"ok": 1, "warnings": 1}
    assert set(out["tasks"][0]) == {"upid", "worker_type", "worker_id", "user",
                                    "status", "starttime", "endtime"}
    assert "type" not in out["tasks"][0], "PBS has no `type` column; projecting it yields nothing"


def test_pbs_running_row_has_neither_endtime_nor_status(tmp_path, monkeypatch):
    import proximo.tools.pbs as tools_pbs
    monkeypatch.setattr(tools_pbs, "pbs_tasks_list_op",
                        lambda *a, **k: [PBS_RUNNING, PBS_FINISHED])
    _wire(tmp_path, monkeypatch, pbs=SimpleNamespace())
    out = server.pbs_tasks_list()
    assert out["by_outcome"] == {"running": 1, "ok": 1}, (
        "a live PBS row drops both keys while running; classing it anything but "
        "`running` would report an in-flight task as an outcome"
    )


# --- PMG ----------------------------------------------------------------------

PMG_OK = {"upid": "UPID:pmg-test:200:1B0F00DC:X:srvrestart:postfix:root@pam:",
          "node": "pmg-test", "pid": 512, "pstart": 453968092, "starttime": 1786594588,
          "endtime": 1786594589, "id": "postfix", "type": "srvrestart",
          "user": "root@pam", "status": "OK"}


def test_pmg_envelope_uses_type_and_id(tmp_path, monkeypatch):
    import proximo.tools.pmg_mail as tools_pmg
    monkeypatch.setattr(tools_pmg, "pmg_tasks_list_op", lambda *a, **k: [PMG_OK])
    _wire(tmp_path, monkeypatch, pmg=SimpleNamespace())
    out = server.pmg_tasks_list()
    assert out["by_outcome"] == {"ok": 1}
    assert set(out["tasks"][0]) == {"upid", "type", "id", "user", "status",
                                    "starttime", "endtime"}
    assert "worker_type" not in out["tasks"][0], "PMG is not shaped like PBS"


def test_pmg_unobserved_failure_vocabulary_degrades_safely(tmp_path, monkeypatch):
    """PMG never failed across four real attempts, so its failure text is UNKNOWN.

    The classifier must therefore never guess healthy: an unrecognised status has to land
    on `failed`, and an absent one on `unknown`. Both are the safe direction, and this is
    what makes reusing the PVE classifier honest on a plane we could not fully measure.
    """
    import proximo.tools.pmg_mail as tools_pmg
    # Only the first row is a measured PMG shape. The rest are HYPOTHETICAL statuses PMG has
    # never been seen to emit — including the WARNINGS form, which the vocabulary doc lists as
    # UNPROVEN for PMG. They are here to exercise the classifier's behaviour under ignorance,
    # NOT as a record of what PMG returns; do not read them back as PMG evidence.
    rows = [PMG_OK,
            {**PMG_OK, "status": "some future PMG error nobody has seen"},
            {**PMG_OK, "status": ""},
            {**PMG_OK, "status": "WARNINGS: 2"}]
    monkeypatch.setattr(tools_pmg, "pmg_tasks_list_op", lambda *a, **k: rows)
    _wire(tmp_path, monkeypatch, pmg=SimpleNamespace())
    out = server.pmg_tasks_list()
    assert out["by_outcome"] == {"ok": 1, "failed": 1, "unknown": 1, "warnings": 1}


# --- the shared law across all three -------------------------------------------

def test_no_plane_reports_a_count_it_did_not_measure(tmp_path, monkeypatch):
    """A row the classifier cannot read must never inflate a healthy class."""
    import proximo.tools.pbs as tools_pbs
    junk = [None, 42, "nonsense", {"status": None, "endtime": 1}]
    monkeypatch.setattr(tools_pbs, "pbs_tasks_list_op", lambda *a, **k: junk)
    _wire(tmp_path, monkeypatch, pbs=SimpleNamespace())
    out = server.pbs_tasks_list()
    assert out["by_outcome"].get("ok") is None, "garbage must never class as ok"
    assert out["by_outcome"]["unknown"] == len(junk)


def test_known_edge_a_keyless_dict_classes_as_running(tmp_path, monkeypatch):
    """Documented wart, pinned so it is a decision rather than a surprise.

    Running is detected by the ABSENCE of `endtime`, and a keyless dict is absent
    everything, so `{}` reports as a task in flight — a state nothing measured. Requiring
    `upid` would close it (every real row on all four planes carries one, live-probed
    2026-08-13), but that changes a classifier PVE depends on and whose contract
    test_projection.py pins against minimal dicts. Left alone deliberately: the trade needs
    a review, not a late edit. Real backends have not produced this shape.
    """
    import proximo.tools.pbs as tools_pbs
    monkeypatch.setattr(tools_pbs, "pbs_tasks_list_op", lambda *a, **k: [{}])
    _wire(tmp_path, monkeypatch, pbs=SimpleNamespace())
    assert server.pbs_tasks_list()["by_outcome"] == {"running": 1}


# --- the `fields` surface, which this commit added and nothing guarded -----------

def test_fields_all_returns_raw_rows_on_every_plane(tmp_path, monkeypatch):
    import proximo.tools.pbs as tools_pbs
    import proximo.tools.pmg_mail as tools_pmg
    monkeypatch.setattr(tools_pbs, "pbs_tasks_list_op", lambda *a, **k: [PBS_FINISHED])
    monkeypatch.setattr(tools_pmg, "pmg_tasks_list_op", lambda *a, **k: [PMG_OK])
    pdm = SimpleNamespace(tasks_list=lambda *a, **k: [PBS_FINISHED])
    _wire(tmp_path, monkeypatch, pbs=SimpleNamespace(), pmg=SimpleNamespace(), pdm=pdm)

    assert server.pbs_tasks_list(fields="all")["tasks"][0] == PBS_FINISHED
    assert server.pmg_tasks_list(fields="all")["tasks"][0] == PMG_OK
    assert server.pdm_tasks_list(fields="all")["tasks"][0] == PBS_FINISHED


def test_a_custom_field_list_narrows_rows_but_never_the_counts(tmp_path, monkeypatch):
    """The docstrings promise a projection cannot skew by_outcome. Pin it per plane.

    Making `fields` a no-op left 90 tests green, so the parameter was plumbed but unguarded:
    a caller asking for `all` would silently have received the lean set.
    """
    import proximo.tools.pbs as tools_pbs
    monkeypatch.setattr(tools_pbs, "pbs_tasks_list_op",
                        lambda *a, **k: [PBS_FINISHED, PBS_WARN, PBS_RUNNING])
    _wire(tmp_path, monkeypatch, pbs=SimpleNamespace())

    lean = server.pbs_tasks_list()
    narrow = server.pbs_tasks_list(fields="upid")
    assert list(narrow["tasks"][0]) == ["upid"], "the projection must actually narrow"
    assert narrow["by_outcome"] == lean["by_outcome"] == {"ok": 1, "warnings": 1, "running": 1}, (
        "by_outcome is classified from RAW rows; projecting away `status` must not change it"
    )
    assert server.pbs_tasks_list(fields="all")["tasks"][0] == PBS_FINISHED


def test_an_unknown_field_is_refused_with_the_available_names(tmp_path, monkeypatch):
    import proximo.tools.pmg_mail as tools_pmg
    from proximo.backends import ProximoError
    monkeypatch.setattr(tools_pmg, "pmg_tasks_list_op", lambda *a, **k: [PMG_OK])
    _wire(tmp_path, monkeypatch, pmg=SimpleNamespace())
    try:
        server.pmg_tasks_list(fields="worker_type")   # PBS's column name, not PMG's
    except ProximoError as e:
        assert "worker_type" in str(e) and "upid" in str(e), "the refusal must name what IS available"
    else:
        raise AssertionError("a field this plane does not have must be refused, not silently dropped")


def test_known_gap_an_empty_row_list_cannot_validate_field_names(tmp_path, monkeypatch):
    """Documented, deliberately NOT fixed here.

    `project_rows` learns the valid field names from the rows themselves, so with zero rows a
    typo passes and renders as a clean empty read — a refusal and "nothing to report" become
    indistinguishable on a quiet node. The fix belongs in `project_rows`, which PVE shares, so
    it earns its own commit and its own review rather than riding inside a PBS/PMG/PDM change.
    Pinned here so the behaviour is a known decision, not a surprise.
    """
    import proximo.tools.pbs as tools_pbs
    monkeypatch.setattr(tools_pbs, "pbs_tasks_list_op", lambda *a, **k: [])
    _wire(tmp_path, monkeypatch, pbs=SimpleNamespace())
    out = server.pbs_tasks_list(fields="totally_bogus_field")
    assert out == {"returned": 0, "by_outcome": {}, "tasks": []}


def test_audit_ledger_records_each_sibling_read(tmp_path, monkeypatch):
    import proximo.tools.pbs as tools_pbs
    monkeypatch.setattr(tools_pbs, "pbs_tasks_list_op", lambda *a, **k: [PBS_FINISHED])
    log = _wire(tmp_path, monkeypatch, pbs=SimpleNamespace())
    server.pbs_tasks_list()
    with open(log, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    assert any(e.get("action") == "pbs_tasks_list" for e in entries), (
        "the envelope must not bypass the audited funnel"
    )
