"""B4, task wait: a task-backed mutation reports finished, not just submitted (2026-09-30).

The 0.44 tools `pve_task_wait` / `pve_task_status` were the only way to learn whether a
migrate, backup, clone or snapshot the vendor ACCEPTED then actually FINISHED; the core
returned the UPID and stopped, which is the answer a small model cannot use. One helper,
`spine.task_wait`, carries 0.44's contract (a failed or timed-out task is a RESULT, never an
exception; `succeeded` is fail-closed), and the engine polls the plane's own task-status
address through the client it already built, one ledger row for the whole wait.
"""
from __future__ import annotations

import json
import os

import pytest

from proximo.core import engine, spine, wire
from proximo.core.errors import ProximoError


@pytest.fixture
def armed(armed_plane, tmp_path):
    """The shared armed box (conftest), in the (cfg, _, tmp) shape these tests were written to."""
    return armed_plane, None, tmp_path


def _tiered(monkeypatch, product, method, path, tier="read-back"):
    row = engine.resolve(product, method, path)
    return engine.Row(**{**row.__dict__, "tier": tier})


def _rows() -> list[dict]:
    with open(os.environ["PROXIMO_AUDIT_LOG"], encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


UPID = "UPID:pve1:000A1B2C:0D3E4F50:68DA0000:qmstart:100:root@pam:"
CFG_PATH = "/nodes/pve1/qemu/100/status/start"


class Sequence:
    """A wire that answers the mutation with a UPID and the status polls in order; the last
    answer repeats, so a wait that outlives the script keeps seeing it."""

    def __init__(self, answer=UPID, polls=()):
        self.calls: list[tuple[str, str, dict]] = []
        self.answer = answer
        self.polls = list(polls)

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        if method != "GET":
            return self.answer
        return self.polls.pop(0) if len(self.polls) > 1 else (self.polls[0] if self.polls else {})


def _no_sleep(monkeypatch, step: float = 0.0):
    """A clock the test owns: `_SLEEP` advances it by the seconds asked (or `step`), so a
    timeout is reached by counting, never by waiting."""
    now = [0.0]

    def sleep(s):
        now[0] += step if step else s

    monkeypatch.setattr(spine, "_SLEEP", sleep)
    monkeypatch.setattr(spine, "_CLOCK", lambda: now[0])
    return now


def _start_row(monkeypatch):
    return _tiered(monkeypatch, "pve", "POST", "/nodes/{node}/qemu/{vmid}/status/start")


# --- the helper: 0.44's contract, carried -------------------------------------------------------

def test_task_wait_carries_the_0_44_contract(monkeypatch):
    _no_sleep(monkeypatch)
    answers = iter([{"status": "running"}, {"status": "running"}, {"status": "stopped", "exitstatus": "OK"}])
    out = spine.task_wait(lambda: next(answers), timeout=30, interval=2)
    assert out == {"finished": True, "succeeded": True, "status": "stopped", "exitstatus": "OK",
                   "timed_out": False, "polls": 3}


def test_a_stopped_task_without_ok_is_not_a_success(monkeypatch):
    _no_sleep(monkeypatch)
    out = spine.task_wait(lambda: {"status": "stopped", "exitstatus": "unable to start"}, timeout=5, interval=1)
    assert out["finished"] and out["succeeded"] is False and out["exitstatus"] == "unable to start"
    out = spine.task_wait(lambda: {"status": "stopped"}, timeout=5, interval=1)
    assert out["finished"] and out["succeeded"] is False and out["exitstatus"] is None


def test_a_wait_that_outlives_its_timeout_says_so(monkeypatch):
    now = _no_sleep(monkeypatch)
    polls = []
    out = spine.task_wait(lambda: polls.append(1) or {"status": "running"}, timeout=7, interval=2)
    assert out["timed_out"] is True and out["finished"] is False and out["succeeded"] is False
    assert out["status"] == "running" and out["polls"] == len(polls) == 5   # 0, 2, 4, 6, 8 s: one past
    assert now[0] >= 7                                                        # the clock did move


def test_an_api_error_from_the_poll_still_raises(monkeypatch):
    _no_sleep(monkeypatch)

    def _boom():
        raise ConnectionError("gone")

    with pytest.raises(ConnectionError):
        spine.task_wait(_boom, timeout=5, interval=1)


@pytest.mark.parametrize("upid,node", [
    (UPID, "pve1"),
    ("UPID:pbs-a:00001B2C:0000000A:00000001:68DA0000:backup:store:root@pam:", "pbs-a"),
    ("UPID:pmg1:00001B2C:0D3E4F50:68DA0000:pmgbackup::root@pam:", "pmg1"),
    ("pve:lab!UPID:pve1:000A1B2C:0D3E4F50:68DA0000:qmstart:100:root@pam:", "pve1"),   # PDM's remote form
    ("UPID:pve1:000A1B2C:0D3E4F50:68DA0000:qmstart:100:root@pam!proximo:", "pve1"),   # a token's own ! (lens 5)
    ("pve:lab!UPID:pve1:000A1B2C:0D3E4F50:68DA0000:qmstart:100:root@pam!tok:", "pve1"),
    ("UPID:pbs-a:00001B2C:0000000A:00000001:68DA0000:backup:store\\x3ahost\\x2fvm\\x2f100:root@pam:",
     "pbs-a"),                                                                        # PBS escapes
    ("UPID:pve1/../x:000A1B2C:0D3E4F50:68DA0000:qmstart:100:root@pam:", None),        # a slash is a path
    ("UPID:pve1:000A%2F:0D3E4F50:68DA0000:qmstart:100:root@pam:", None),              # so is an escape
    ("done", None),
    (None, None),
    ({"status": "ok"}, None),
])
def test_upid_node_reads_the_node_from_a_upid_and_nothing_else(upid, node):
    assert spine.upid_node(upid) == node


# --- the seam: a task-backed mutation ---------------------------------------------------------

def test_a_task_backed_mutation_reports_finished_and_polls_the_node_the_upid_names(armed, monkeypatch):
    cfg, _, _ = armed
    _no_sleep(monkeypatch)
    w = Sequence(polls=[{"status": "running"}, {"status": "running"}, {"status": "stopped", "exitstatus": "OK"}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=30)
    assert out["data"] == UPID
    assert out["task"] == {"upid": UPID, "finished": True, "succeeded": True, "status": "stopped",
                           "exitstatus": "OK", "timed_out": False, "polls": 3, "seconds": 4}
    gets = [p for m, p, _ in w.calls if m == "GET"]
    assert gets == [f"/nodes/pve1/tasks/{UPID}/status"] * 3       # the node from the UPID, not the call
    rows = [r for r in _rows() if r["action"] in ("core.execute", "core.task")]
    assert [r["outcome"] for r in rows] == ["executing", "submitted", "finished"]
    task = rows[-1]
    assert task["detail"]["upid"] == UPID and task["detail"]["polls"] == 3
    assert task["detail"]["intent"] == rows[0]["detail"]["intent"]   # the same intent closes it


def test_a_failed_task_is_a_result_with_its_reason_scrubbed_on_the_ledger(armed, monkeypatch):
    cfg, _, _ = armed
    _no_sleep(monkeypatch)
    reason = "unable to start: storage 'https://pve.example.invalid:8006/x' at 192.0.2.7:8007 is down"
    w = Sequence(polls=[{"status": "stopped", "exitstatus": reason}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=30)
    assert out["task"]["succeeded"] is False and out["task"]["finished"] is True
    assert "unable to start" in out["task"]["exitstatus"]
    row = [r for r in _rows() if r["action"] == "core.task"][-1]
    assert row["outcome"] == "failed"
    text = json.dumps(row)
    assert "unable to start" in text and "pve.example.invalid" not in text and "192.0.2.7" not in text


def test_a_timed_out_wait_is_a_result_and_a_row(armed, monkeypatch):
    cfg, _, _ = armed
    now = _no_sleep(monkeypatch)
    w = Sequence(polls=[{"status": "running"}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=5)
    assert out["task"]["timed_out"] is True and out["task"]["finished"] is False
    assert out["task"]["polls"] == 4 and now[0] >= 5     # 0, 2, 4, 6 s: the last poll is past the deadline
    row = [r for r in _rows() if r["action"] == "core.task"][-1]
    assert row["outcome"] == "timed_out" and row["detail"]["seconds"] >= 5


def test_wait_zero_submits_only_and_the_row_says_submitted(armed, monkeypatch):
    cfg, _, _ = armed
    _no_sleep(monkeypatch)
    w = Sequence(polls=[{"status": "stopped", "exitstatus": "OK"}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=0)
    assert out["task"] == {"upid": UPID, "finished": False, "succeeded": False, "status": None,
                           "exitstatus": None, "timed_out": False, "polls": 0, "seconds": 0}
    assert [m for m, _, _ in w.calls] == ["POST"]                     # nothing polled
    rows = [r for r in _rows() if r["action"] in ("core.execute", "core.task")]
    assert [r["outcome"] for r in rows] == ["executing", "submitted"]


def test_an_answer_that_is_not_a_task_is_ok_and_carries_no_task(armed, monkeypatch):
    cfg, _, _ = armed
    w = Sequence(answer=None)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=30)
    assert "task" not in out and [m for m, _, _ in w.calls] == ["POST"]
    rows = [r for r in _rows() if r["action"] in ("core.execute", "core.task")]
    assert [r["outcome"] for r in rows] == ["executing", "ok"]


def test_a_task_id_that_is_not_a_upid_shape_is_reported_and_never_polled(armed, monkeypatch):
    """The UPID is vendor bytes going back into a URL path: a slash or an escape in it is a path
    the vendor wrote, not a task to poll."""
    cfg, _, _ = armed
    bad = "UPID:pve1/../access:000A1B2C:0D3E4F50:68DA0000:qmstart:100:root@pam:"
    w = Sequence(answer=bad, polls=[{"status": "stopped", "exitstatus": "OK"}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=30)
    assert out["data"] == bad and out["task"]["polls"] == 0 and "not polled" in out["task"]["why"]
    assert [m for m, _, _ in w.calls] == ["POST"]
    rows = [r for r in _rows() if r["action"] in ("core.execute", "core.task")]
    assert [r["outcome"] for r in rows] == ["executing", "submitted"]      # it said UPID: never ok
    assert rows[1]["detail"]["upid"] == bad


def test_a_token_started_task_is_polled(armed, monkeypatch):
    """The core authenticates by token, so the vendor's UPID ends `root@pam!proximo:`; splitting
    on `!` for PDM's prefix read every such task as no task and receipted it ok (lens 5)."""
    cfg, _, _ = armed
    _no_sleep(monkeypatch)
    tok_upid = "UPID:pve1:000A1B2C:0D3E4F50:68DA0000:qmstart:100:root@pam!proximo:"
    w = Sequence(answer=tok_upid, polls=[{"status": "stopped", "exitstatus": "OK"}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=30)
    assert out["task"]["succeeded"] is True and out["task"]["polls"] == 1
    assert [p for m, p, _ in w.calls if m == "GET"] == [f"/nodes/pve1/tasks/{tok_upid}/status"]
    rows = [r for r in _rows() if r["action"] in ("core.execute", "core.task")]
    assert [r["outcome"] for r in rows] == ["executing", "submitted", "finished"]
    assert rows[1]["detail"]["upid"] == tok_upid                          # the id on the submitted row


def test_a_pbs_task_with_escapes_in_its_worker_id_is_polled(armed, monkeypatch, tmp_path):
    cfg, _, _ = armed
    _no_sleep(monkeypatch)
    pbs = wire.Plane("pbs", "https://pbs.invalid:8007/api2/json", str(tmp_path / "token"))
    upid = "UPID:pbs-a:00001B2C:0000000A:00000001:68DA0000:prune:store\\x3ahost\\x2fvm\\x2f100:root@pam!tok:"
    w = Sequence(answer=upid, polls=[{"status": "stopped", "exitstatus": "OK"}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    row = _tiered(monkeypatch, "pbs", "POST", "/admin/prune/{id}/run")
    out = engine.execute(row, {}, cfg=pbs, path="/admin/prune/p1/run", wait=30)
    assert out["task"]["succeeded"] is True
    assert [p for m, p, _ in w.calls if m == "GET"] == [f"/nodes/pbs-a/tasks/{upid}/status"]


def test_a_poll_that_fails_is_receipted_and_the_id_still_comes_back(armed, monkeypatch):
    """The vendor accepted the work; a poll failure must not turn into an exception that loses
    the id (a caller would fire it again) or into a wire failure with no row (lens 5)."""
    import httpx
    cfg, _, _ = armed
    _no_sleep(monkeypatch)
    req = httpx.Request("GET", "https://pve.example.invalid:8006/api2/json/x")

    class Flaky(Sequence):
        def call(self, method, path, params=None):
            self.calls.append((method, path, dict(params or {})))
            if method != "GET":
                return UPID
            if len(self.calls) >= 3:
                raise httpx.HTTPStatusError(f"Server error '503' for url '{req.url}'", request=req,
                                            response=httpx.Response(503, request=req))
            return {"status": "running"}

    w = Flaky()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=30)
    assert out["data"] == UPID and out["task"]["upid"] == UPID and out["task"]["finished"] is False
    assert out["task"]["poll_error"] == {"error": "HTTPStatusError", "status": 503} and out["task"]["polls"] == 2
    rows = [r for r in _rows() if r["action"] in ("core.execute", "core.task")]
    assert [r["outcome"] for r in rows] == ["executing", "submitted", "error"]
    assert rows[-1]["detail"]["poll_error"] == {"error": "HTTPStatusError", "status": 503}
    assert rows[-1]["detail"]["upid"] == UPID and "pve.example.invalid" not in json.dumps(rows)


def test_the_answers_exit_text_is_scrubbed_and_bounded_like_the_ledgers(armed, monkeypatch):
    cfg, _, _ = armed
    _no_sleep(monkeypatch)
    from proximo.core.secretfile import register_secret
    register_secret("hunter2-shape-secret")
    reason = "failed: token hunter2-shape-secret at https://pve.example.invalid:8006/x " + "A" * 5000
    w = Sequence(polls=[{"status": "stopped", "exitstatus": reason}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=30)
    text = out["task"]["exitstatus"]
    assert text.startswith("failed:") and "hunter2-shape-secret" not in text
    assert "pve.example.invalid" not in text and len(text) <= 400


def test_an_unshaped_id_lands_on_the_row_scrubbed_and_bounded(armed, monkeypatch):
    """The path built for odd vendor bytes wrote them raw into the hash chain (lens 6)."""
    from proximo.core.secretfile import register_secret
    cfg, _, _ = armed
    register_secret("hunter2-shape-secret")
    odd = "UPID: hunter2-shape-secret at https://pve.example.invalid:8006/x " + "A" * 20000
    w = Sequence(answer=odd)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=30)
    raw = open(os.environ["PROXIMO_AUDIT_LOG"], encoding="utf-8").read()
    assert "hunter2-shape-secret" not in raw and "pve.example.invalid" not in raw and len(raw) < 3000
    row = [r for r in _rows() if r["outcome"] == "submitted"][-1]
    assert row["detail"]["upid"].startswith("UPID:") and len(row["detail"]["upid"]) <= 400
    assert out["task"]["upid"] == row["detail"]["upid"] and out["task"]["polls"] == 0


def test_a_failed_poll_carries_the_last_status_it_saw(armed, monkeypatch):
    cfg, _, _ = armed
    _no_sleep(monkeypatch)

    class Flaky(Sequence):
        def call(self, method, path, params=None):
            self.calls.append((method, path, dict(params or {})))
            if method != "GET":
                return UPID
            if len(self.calls) >= 3:
                raise ConnectionError("gone")
            return {"status": "running"}

    monkeypatch.setattr(engine, "_client", lambda product, c=None: Flaky())
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=30)
    assert out["task"]["status"] == "running" and out["task"]["poll_error"] == {"error": "ConnectionError"}
    row = [r for r in _rows() if r["action"] == "core.task"][-1]
    assert row["detail"]["status"] == "running"


def test_the_undo_capture_does_not_close_a_twins_executing_row_either(armed, monkeypatch):
    """Same class as the wait's receipt: the UNDO capture is written BEFORE its own executing
    row, so a twin's capture popped a stranded first executing (lens 6, pre-existing)."""
    from proximo.core.ledger import in_flight
    cfg, _, _ = armed
    w = Sequence(answer=None)
    w.call = lambda m, p, params=None: {"memory": "1"} if m == "GET" else None
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    row = _tiered(monkeypatch, "pve", "PUT", "/nodes/{node}/qemu/{vmid}/config")
    engine.execute(row, {"memory": "2"}, cfg=cfg, path="/nodes/pve1/qemu/101/config")
    rows = [r for r in _rows() if r["action"] in ("core.undo_point", "core.execute")]
    undo_point, executing, ok = rows
    assert undo_point["action"] == "core.undo_point" and in_flight(rows) == []
    stranded = dict(executing)
    assert [e["outcome"] for e in in_flight([stranded, undo_point, executing, ok])] == ["executing"]


def test_the_waits_receipt_does_not_close_a_twins_executing_row(armed, monkeypatch):
    """Three rows per intent now (executing, submitted, core.task): `in_flight` closed the most
    recent open executing on ANY later row, so a twin's stranded executing vanished (lens 5)."""
    from proximo.core.ledger import in_flight
    cfg, _, _ = armed
    _no_sleep(monkeypatch)
    w = Sequence(polls=[{"status": "stopped", "exitstatus": "OK"}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=30)
    rows = [r for r in _rows() if r["action"] in ("core.execute", "core.task")]
    executing, submitted, task = rows
    assert in_flight([executing, submitted, task]) == []
    twin = dict(executing)                                   # an identical op, overlapping, stranded
    assert [e["outcome"] for e in in_flight([executing, submitted, twin, task])] == ["executing"]


def test_a_pdm_remote_task_polls_the_remote_address_from_the_governed_path(armed, monkeypatch, tmp_path):
    cfg, _, _ = armed
    _no_sleep(monkeypatch)
    pdm = wire.Plane("pdm", "https://pdm.invalid:8443/api2/json", str(tmp_path / "token"))
    remote_upid = "pve:lab!" + UPID
    w = Sequence(answer=remote_upid, polls=[{"status": "stopped", "exitstatus": "OK"}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    row = _tiered(monkeypatch, "pdm", "POST", "/pve/remotes/{remote}/qemu/{vmid}/shutdown")
    out = engine.execute(row, {}, cfg=pdm, path="/pve/remotes/lab/qemu/100/shutdown", wait=30)
    assert out["task"]["succeeded"] is True
    assert [p for m, p, _ in w.calls if m == "GET"] == [f"/pve/remotes/lab/tasks/{remote_upid}/status"]


def test_the_wait_is_clamped_to_0_600(armed, monkeypatch):
    cfg, _, _ = armed
    now = _no_sleep(monkeypatch)
    w = Sequence(polls=[{"status": "running"}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=10_000)
    assert out["task"]["timed_out"] is True and 600 <= now[0] < 610
    w2 = Sequence(polls=[{"status": "stopped", "exitstatus": "OK"}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w2)
    out = engine.execute(_start_row(monkeypatch), {}, cfg=cfg, path=CFG_PATH, wait=-5)
    assert out["task"]["polls"] == 0


# --- the second door in: a status read with wait= (0.44's pve_task_wait on a UPID in hand) ----

def test_a_status_read_with_wait_polls_until_the_task_stops(armed, monkeypatch):
    cfg, _, _ = armed
    _no_sleep(monkeypatch)

    class Status(Sequence):
        def call(self, method, path, params=None):
            self.calls.append((method, path, dict(params or {})))
            return self.polls.pop(0) if len(self.polls) > 1 else self.polls[0]

    w = Status(polls=[{"status": "running"}, {"status": "running"}, {"status": "stopped", "exitstatus": "OK"}])
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    row = engine.resolve("pve", "GET", "/nodes/{node}/tasks/{upid}/status")
    path = f"/nodes/pve1/tasks/{UPID}/status"
    out = engine.execute(row, {}, cfg=cfg, path=path, wait=30)
    assert out["data"] == {"status": "stopped", "exitstatus": "OK"}
    assert out["task"]["succeeded"] is True and out["task"]["polls"] == 3 and out["task"]["upid"] == UPID
    assert len(w.calls) == 3 and all(p == path for _, p, _ in w.calls)
    rows = [r for r in _rows() if r["action"] in ("core.execute", "core.task")]
    assert [r["outcome"] for r in rows] == ["ok"]      # a read is one row; the wait rides in it
    assert rows[0]["detail"]["polls"] == 3


def test_a_read_with_wait_on_an_address_that_is_not_a_task_status_is_refused(armed, monkeypatch):
    cfg, _, _ = armed
    w = Sequence(answer={"status": "running"})
    w.call = lambda m, p, params=None: {"x": 1}
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    row = engine.resolve("pve", "GET", "/nodes/{node}/status")
    with pytest.raises(ProximoError, match="wait"):
        engine.execute(row, {}, cfg=cfg, path="/nodes/pve1/status", wait=5)
