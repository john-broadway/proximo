"""B5's last guest-agent half: the exec-status poll (2026-10-04).

0.44's `pve_agent_exec` POSTed the command, took the `pid` the agent answered, and polled
`exec-status` once a second until the agent said `exited`, up to a timeout: "ok" only on an
observed exit, "running" with the pid at the deadline, never a faked finish. The core served both
addresses on the agent lane but did not wait, so a guest exec answered `{pid}` and nothing else.

Now a POST to `/nodes/{node}/qemu/{vmid}/agent/exec` whose answer carries an integer pid is
SUBMITTED, not done, and `wait=` (the task wait's knob and bounds; 0 submits only) polls the
vendor's `exec-status` for that pid through the client the mutation already built, as the UPID
wait does. The output comes back through the status read's own envelope (bounded, labelled
untrusted, fenced when the fence is on); the vendor's own `out-truncated`/`err-truncated` are
carried and say the stream is a prefix; one `core.exec` receipt says exited / running / error with
the exit code and never the output.
"""
from __future__ import annotations

import json
import os

import pytest

from proximo.core import engine, spine
from proximo.core.errors import ProximoError

NODE, VM = "pve1", "101"
EXEC = f"/nodes/{NODE}/qemu/{VM}/agent/exec"
STATUS = EXEC + "-status"


class Agent:
    """The vendor: POST exec answers a pid; exec-status answers each queued status in turn."""

    def __init__(self, statuses, pid=4242, fail=None):
        self.statuses, self.pid, self.fail, self.calls = list(statuses), pid, fail, []

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        if method == "POST":
            return {"pid": self.pid}
        if self.fail is not None:
            raise self.fail
        return self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]


@pytest.fixture
def box(armed_plane, monkeypatch):
    monkeypatch.setenv("PROXIMO_ENABLE_AGENT", "1")
    monkeypatch.setenv("PROXIMO_AGENT_ALLOWLIST", VM)
    clock = [0.0]
    monkeypatch.setattr(spine, "_CLOCK", lambda: clock[0])
    monkeypatch.setattr(spine, "_SLEEP", lambda s: clock.__setitem__(0, clock[0] + s))
    return armed_plane


def _wire(monkeypatch, statuses, **kw):
    a = Agent(statuses, **kw)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: a)
    return a


def _exec(box, wait=None, path=EXEC):
    return engine.execute(engine.resolve("pve", "POST", path), {"command": ["id"]}, cfg=box, path=path, wait=wait)


def _rows() -> list[dict]:
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


DONE = {"exited": True, "exitcode": 0, "out-data": "uid=0(root)\n", "err-data": ""}


def test_a_guest_exec_waits_for_the_exit_and_hands_back_the_output(box, monkeypatch):
    a = _wire(monkeypatch, [{"exited": False}, {"exited": 0}, DONE])     # 1 counts too: tested below
    out = _exec(box)
    polls = [c for c in a.calls if c[0] == "GET"]
    assert [c[1] for c in polls] == [STATUS] * 3 and all(c[2] == {"pid": 4242} for c in polls)
    ex = out["exec"]
    assert ex["exited"] is True and ex["exitcode"] == 0 and ex["polls"] == 3 and ex["pid"] == 4242
    assert ex["output"]["data"]["out-data"] == "uid=0(root)\n" and ex["output"]["untrusted"] is True
    assert out["untrusted"] is True                          # guest bytes in the answer: labelled
    acts = [(r["action"], r["outcome"]) for r in _rows()]
    assert ("core.execute", "submitted") in acts and acts[-1] == ("core.exec", "exited")
    assert _rows()[-1]["detail"]["exitcode"] == 0 and _rows()[-1]["detail"]["pid"] == 4242


@pytest.mark.parametrize("never", [{"exited": False}, {"exited": 0}, {}, {"exited": "yes"}, {"exited": 1.0},
                                   {"exited": "1"}, "not a dict"])
def test_nothing_but_exited_true_is_a_finish(box, monkeypatch, never):
    _wire(monkeypatch, [never])
    ex = _exec(box, wait=3)["exec"]
    assert ex["exited"] is False and ex["timed_out"] is True and "output" not in ex
    assert _rows()[-1]["action"] == "core.exec" and _rows()[-1]["outcome"] == "running"


def test_the_deadline_says_running_with_the_pid_and_no_output(box, monkeypatch):
    _wire(monkeypatch, [{"exited": False}])
    ex = _exec(box, wait=5)["exec"]
    assert ex == {**ex, "pid": 4242, "exited": False, "timed_out": True} and "output" not in ex
    assert 5 <= ex["seconds"] <= 6


def test_wait_zero_submits_only_and_polls_nothing(box, monkeypatch):
    a = _wire(monkeypatch, [DONE])
    out = _exec(box, wait=0)
    assert [c for c in a.calls if c[0] == "GET"] == [] and out["exec"]["polls"] == 0
    assert out["exec"]["pid"] == 4242 and "exec-status" in out["exec"]["why"]
    assert not any(r["action"] == "core.exec" for r in _rows())


def test_a_poll_that_fails_is_receipted_and_keeps_the_pid(box, monkeypatch):
    _wire(monkeypatch, [DONE], fail=RuntimeError("HTTP 500"))
    ex = _exec(box)["exec"]
    assert ex["pid"] == 4242 and ex["exited"] is False and "poll_error" in ex
    assert _rows()[-1]["action"] == "core.exec" and _rows()[-1]["outcome"] == "error"


def test_the_guests_output_never_reaches_the_ledger(box, monkeypatch):
    secret = "s3cr3t-guest-output-7f2a"
    _wire(monkeypatch, [{**DONE, "out-data": secret, "err-data": secret}])
    _exec(box)
    assert secret not in json.dumps(_rows())


def test_the_vendors_own_truncation_is_carried_and_named(box, monkeypatch):
    _wire(monkeypatch, [{**DONE, "out-truncated": True}])
    ex = _exec(box)["exec"]
    assert ex["truncated"] == ["out-data"] and ex["output"]["data"]["out-truncated"] is True
    assert _rows()[-1]["detail"]["truncated"] == ["out-data"]


def test_a_signal_is_carried(box, monkeypatch):
    _wire(monkeypatch, [{"exited": True, "signal": 9}])
    ex = _exec(box)["exec"]
    assert ex["signal"] == 9 and _rows()[-1]["detail"]["signal"] == 9


def test_the_fence_wraps_the_guests_output(box, monkeypatch):
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", "1")
    _wire(monkeypatch, [DONE])
    ex = _exec(box)["exec"]
    assert "proximo_untrusted" in json.dumps(ex["output"]["data"])


@pytest.mark.parametrize("answer", [{"pid": "4242"}, {"pid": True}, {"pid": -1}, {"pid": 0}, {}, ["4242"]])
def test_an_answer_without_an_integer_pid_is_not_polled(box, monkeypatch, answer):
    a = _wire(monkeypatch, [DONE])
    monkeypatch.setattr(a, "call", lambda m, p, params=None: (a.calls.append((m, p, params)), answer)[1])
    out = _exec(box)
    assert [c for c in a.calls if c[0] == "GET"] == [] and "exec" not in out


def test_another_post_that_answers_a_pid_is_not_polled(box, monkeypatch):
    a = _wire(monkeypatch, [DONE])
    path = f"/nodes/{NODE}/qemu/{VM}/agent/fstrim"         # the trigger is the row, not the shape
    out = engine.execute(engine.resolve("pve", "POST", path), {}, cfg=box, path=path)
    assert [c for c in a.calls if c[0] == "GET"] == [] and "exec" not in out


def test_the_poll_taints_before_it_reads_and_a_failed_mark_refuses(box, monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    marked = []
    monkeypatch.setattr(spine, "mark_tainted", lambda d, key: marked.append(key))
    _wire(monkeypatch, [DONE])
    _exec(box)
    assert "pve:GET /nodes/{node}/qemu/{vmid}/agent/exec-status" in marked

    def boom(d, key):
        if key.endswith("exec-status"):
            raise OSError("no marker")
    monkeypatch.setattr(spine, "mark_tainted", boom)
    a = _wire(monkeypatch, [DONE])
    with pytest.raises(ProximoError, match="taint marker"):
        _exec(box)
    # the lens (2026-11-22): this refused AFTER the POST, so the command had run and its pid was
    # lost. The status read is marked with the exec now: the refusal comes before anything is sent.
    assert a.calls == []


def test_the_integer_one_is_an_exit(box, monkeypatch):
    _wire(monkeypatch, [{"exited": 1, "exitcode": 3}])
    ex = _exec(box)["exec"]
    assert ex["exited"] is True and ex["exitcode"] == 3


# --- #98's last lines: an unconfirmed exit says what did NOT happen, and how to ask again ---------

def test_the_deadline_says_nothing_was_stopped_or_rerun_and_how_to_ask_again(box, monkeypatch):
    a = _wire(monkeypatch, [{"exited": False}])
    ex = _exec(box, wait=5)["exec"]
    assert "exitcode" not in ex                                   # no exit code is made up
    why = ex["why"]
    assert "not confirmed" in why and "not stopped" in why and "will not be run again" in why
    assert f"GET {STATUS}" in why and "pid=4242" in why
    assert [c for c in a.calls if c[0] == "POST"] == [("POST", EXEC, {"command": ["id"]})]   # ran once


def test_a_failed_poll_says_the_same_and_claims_no_exit(box, monkeypatch):
    _wire(monkeypatch, [DONE], fail=RuntimeError("HTTP 500"))
    ex = _exec(box)["exec"]
    assert "exitcode" not in ex and "not confirmed" in ex["why"] and "pid=4242" in ex["why"]


def test_an_observed_exit_carries_no_unconfirmed_sentence(box, monkeypatch):
    _wire(monkeypatch, [DONE])
    ex = _exec(box)["exec"]
    assert ex["exited"] is True and ex["exitcode"] == 0 and "why" not in ex


def test_a_later_check_reads_exec_status_for_the_pid_and_runs_nothing(box, monkeypatch):
    a = _wire(monkeypatch, [DONE])
    row = engine.resolve("pve", "GET", STATUS)
    assert row.access == "read"
    out = engine.execute(row, {"pid": 4242}, cfg=box, path=STATUS)
    assert a.calls == [("GET", STATUS, {"pid": 4242})]           # one read, no POST
    assert out["data"]["exitcode"] == 0 and out["untrusted"] is True



# --- the lens on the #98 port (2026-11-22) ---------------------------------------------------------

@pytest.mark.parametrize("status", [{"exited": False, "exitcode": 0}, {"exited": 0, "exitcode": 3, "signal": 9},
                                    {"exitcode": 0}, {"exited": "true", "exitcode": 0}])
def test_a_running_status_that_carries_an_exit_code_reports_none(box, monkeypatch, status):
    _wire(monkeypatch, [status])
    ex = _exec(box, wait=4)["exec"]
    assert ex["exited"] is False and "exitcode" not in ex and "signal" not in ex and "output" not in ex
    row = [r for r in _rows() if r["action"] == "core.exec"][-1]
    assert row["outcome"] == "running" and "exitcode" not in row["detail"]


@pytest.mark.parametrize("bad", [True, 1.0, "0", None, [0]])
def test_an_exit_code_or_signal_that_is_not_an_integer_is_dropped(box, monkeypatch, bad):
    _wire(monkeypatch, [{"exited": True, "exitcode": bad, "signal": bad}])
    ex = _exec(box)["exec"]
    assert ex["exited"] is True and "exitcode" not in ex and "signal" not in ex


def test_the_wait_is_clamped_to_the_task_wait_ceiling(box, monkeypatch):
    _wire(monkeypatch, [{"exited": False}])
    ex = _exec(box, wait=10**9)["exec"]
    assert ex["timed_out"] is True and ex["seconds"] <= spine.TASK_WAIT_MAX + spine.TASK_INTERVAL


@pytest.mark.parametrize("wait", [float("inf"), float("nan"), "soon"])
def test_a_wait_that_is_not_a_number_keeps_the_pid(box, monkeypatch, wait):
    a = _wire(monkeypatch, [DONE])
    ex = _exec(box, wait=wait)["exec"]
    assert ex["pid"] == 4242 and "exitcode" not in ex and "not confirmed" in ex["why"]
    assert [c for c in a.calls if c[0] == "GET"] == []


def test_a_second_failed_mark_inside_the_wait_keeps_the_pid(box, monkeypatch):
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    seen = []

    def second_fails(d, key):          # the pre-wire mark lands; the poll's own mark does not
        seen.append(key)
        if key.endswith("exec-status") and seen.count(key) > 1:
            raise OSError("no marker")
    monkeypatch.setattr(spine, "mark_tainted", second_fails)
    a = _wire(monkeypatch, [DONE])
    ex = _exec(box)["exec"]
    assert ex["pid"] == 4242 and "not confirmed" in ex["why"] and "exitcode" not in ex
    assert [c for c in a.calls if c[0] == "GET"] == []


def test_a_receipt_that_could_not_be_written_says_so(box, monkeypatch):
    _wire(monkeypatch, [DONE])
    real = engine._record
    monkeypatch.setattr(engine, "_record", lambda cfg, action, *a, **k:
                        None if action == "core.exec" else real(cfg, action, *a, **k))
    ex = _exec(box)["exec"]
    assert ex["exited"] is True and "not recorded" in ex["receipt"]


def test_the_door_over_cap_answer_keeps_the_exec_verdict_and_its_sentence():
    from proximo.core import rawdoor
    why = ("exit not confirmed: the wait ran out after 6s. The process was not stopped and will not be "
           "run again; ask the agent with GET /nodes/pve1/qemu/101/agent/exec-status pid=4242")
    answer = {"address": "POST /nodes/{node}/qemu/{vmid}/agent/exec", "plane": "pve", "data": {"pid": 4242},
              "exec": {"pid": 4242, "exited": False, "timed_out": True, "polls": 4, "seconds": 6, "why": why,
                       "output": {"data": {"out-data": "x" * 5000}}}}
    out = rawdoor.over_cap("proximo_call", answer, 6000, 2048)
    assert out["exec"]["pid"] == 4242 and out["exec"]["timed_out"] is True and out["exec"]["why"] == why
    assert "output" not in out["exec"] and "exec" not in out.get("counts", {})
    done = {**answer, "exec": {"pid": 7, "exited": True, "timed_out": False, "exitcode": 3, "signal": 9,
                               "truncated": ["out-data"], "output": {"data": {"out-data": "y" * 5000}}}}
    kept = rawdoor.over_cap("proximo_call", done, 6000, 2048)["exec"]
    assert kept == {"pid": 7, "exited": True, "timed_out": False, "exitcode": 3, "signal": 9,
                    "truncated": ["out-data"]}



# --- the lens on the fold (2026-11-22) -------------------------------------------------------------

def test_wait_zero_marks_nothing_and_a_wait_marks_the_status_read_first(box, monkeypatch):
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    marked = []
    monkeypatch.setattr(spine, "mark_tainted", lambda d, key: marked.append(key))
    _wire(monkeypatch, [DONE])
    _exec(box, wait=0)
    assert not any(k.endswith("exec-status") for k in marked)   # no guest bytes read, no taint
    _exec(box, wait=5)
    assert any(k.endswith("exec-status") for k in marked)


def test_a_failed_poll_whose_receipt_cannot_be_written_says_so(box, monkeypatch):
    _wire(monkeypatch, [DONE], fail=RuntimeError("HTTP 500"))
    real = engine._record
    monkeypatch.setattr(engine, "_record", lambda cfg, action, *a, **k:
                        None if action == "core.exec" else real(cfg, action, *a, **k))
    ex = _exec(box)["exec"]
    assert "poll_error" in ex and "not recorded" in ex["receipt"]


def test_a_wait_whose_conversion_raises_anything_keeps_the_pid(box, monkeypatch):
    class Odd:
        def __int__(self):
            raise RuntimeError("no")
    _wire(monkeypatch, [DONE])
    ex = _exec(box, wait=Odd())["exec"]
    assert ex["pid"] == 4242 and "not confirmed" in ex["why"]


def test_the_over_cap_exec_block_keeps_only_integers_and_caps_its_sentences():
    from proximo.core import rawdoor
    answer = {"address": "POST /nodes/{node}/qemu/{vmid}/agent/exec", "plane": "pve",
              "exec": {"pid": 9, "exited": True, "timed_out": False, "exitcode": "0", "signal": 1.5,
                       "why": "w" * 900, "receipt": "r" * 900}}
    kept = rawdoor.over_cap("proximo_call", answer, 6000, 2048)["exec"]
    assert "exitcode" not in kept and "signal" not in kept
    assert len(kept["why"]) < 320 and "900 chars" in kept["why"]           # cut, and says so
    assert len(kept["receipt"]) < 180 and "900 chars" in kept["receipt"]
