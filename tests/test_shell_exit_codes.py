"""The shell door's exit code says how the WORK ended, not only whether the call went through
(kevwillow's no-skill round, #142 items 2, 3, 4, 30 and 34; John's rulings 2026-11-27).

Earlier, `proximo-core` exited 0 for every call the vendor accepted: a snapshot whose task
failed, a backup still running when `--wait` ran out, and `false` run inside a guest all read as
success to a cron job, while SETUP called the exit codes the contract. Now:

    0  it ran and ended in success (a task that ends `WARNINGS: n` is a success, with the count)
    5  it ran and failed: a task that ended any other way, a guest command that exited non-zero
       or was killed
    6  not known to have finished: the wait ran out, the status could not be read after the
       call, or the exit carries no result
    4  the vendor refused the call or could not be reached for it (as before, and only that:
       a status read that fails AFTER the call is 6, because the work was accepted and a script
       that sends again on 4 would run it twice)

A READ exits 0 whatever it found: a lane probe's `returncode` is data. The one read with an outcome
of its own is a task-status read with `--wait`.

The rule is a table (`cli.exit_of`). Every cell is written here by hand, and the same answers are
then produced by the engine itself, so the table is held to what `execute` really returns."""
from __future__ import annotations

import json

import httpx
import pytest

from proximo.core import engine, shell, spine, undo
from proximo.core.doors import cli

UPID = "UPID:pve1:000A1B2C:0D3E4F50:68DA0000:qmstart:100:root@pam:"
START = "/nodes/pve1/qemu/100/status/start"
EXEC = "/nodes/pve1/qemu/101/agent/exec"
CT_EXEC = "/nodes/pve1/lxc/101/exec"

TASK_OK = {"finished": True, "succeeded": True, "status": "stopped", "exitstatus": "OK", "timed_out": False, "polls": 2}
TASK_WARNED = {**TASK_OK, "exitstatus": "WARNINGS: 1", "warnings": 1}
TASK_FAILED = {**TASK_OK, "succeeded": False, "exitstatus": "snapshot name 'before' already used"}
TASK_RUNNING = {"finished": False, "succeeded": False, "status": "running", "exitstatus": None, "timed_out": True,
                "polls": 3}
TASK_SUBMITTED = {"upid": UPID, "finished": False, "succeeded": False, "status": None, "exitstatus": None,
                  "timed_out": False, "polls": 0, "seconds": 0}
TASK_UNASKED = {**TASK_SUBMITTED, "polls": 2, "poll_error": {"error": "ReadTimeout"}}
EXEC_OK = {"pid": 7, "exited": True, "timed_out": False, "polls": 1, "seconds": 0, "exitcode": 0}
EXEC_UNPOLLED = {"pid": 7, "exited": False, "timed_out": False, "polls": 0, "seconds": 0}

TASK_UNSHAPED = {**TASK_SUBMITTED, "why": "the id is not a UPID shape; not polled"}
LANE_FAILED = {"data": {"returncode": 1, "stdout": "", "stderr": ""}}
#: ssh's own 255 after the command started: it exited 255, or the connection dropped while it ran
LANE_DROPPED = {"data": {"returncode": 255, "stdout": "", "stderr": "", "exit_ambiguous": "255 is also ssh's own exit"}}

#: every cell of the table for a MUTATION: (the answer, the caller's --wait, the exit code)
CELLS = [
    ({"data": {"a": 1}}, None, 0),                                             # a write with no task
    ({"data": UPID, "task": TASK_OK}, None, 0),
    ({"data": UPID, "task": TASK_WARNED}, None, 0),
    ({"data": UPID, "task": TASK_FAILED}, None, 5),
    ({"data": UPID, "task": TASK_RUNNING}, 1, 6),
    ({"data": UPID, "task": TASK_SUBMITTED}, 0, 0),                            # --wait 0 submits only
    ({"data": UPID, "task": TASK_SUBMITTED}, -1, 0),                           # a negative wait is clamped to 0
    ({"data": UPID, "task": TASK_UNASKED}, None, 6),                           # the status read failed: unknown
    ({"data": UPID, "task": TASK_UNSHAPED}, None, 6),                          # a wait was wanted; nothing polled
    ({"data": UPID, "task": TASK_UNSHAPED}, 30, 6),
    ({"data": UPID, "task": TASK_UNSHAPED}, 0, 0),
    ({"data": {"pid": 7}, "exec": EXEC_OK}, None, 0),
    ({"data": {"pid": 7}, "exec": {**EXEC_OK, "exitcode": 1}}, None, 5),
    ({"data": {"pid": 7}, "exec": {**EXEC_OK, "exitcode": 0, "signal": 9}}, None, 5),
    ({"data": {"pid": 7}, "exec": {k: v for k, v in EXEC_OK.items() if k != "exitcode"} | {"signal": 9}}, None, 5),
    ({"data": {"pid": 7}, "exec": {k: v for k, v in EXEC_OK.items() if k != "exitcode"}}, None, 6),   # no result
    ({"data": {"pid": 7}, "exec": {**EXEC_UNPOLLED, "timed_out": True, "polls": 2}}, 3, 6),
    ({"data": {"pid": 7}, "exec": {**EXEC_UNPOLLED, "polls": 1, "poll_error": {"error": "ReadTimeout"}}}, None, 6),
    ({"data": {"pid": 7}, "exec": EXEC_UNPOLLED}, 0, 0),                       # --wait 0 submits only
    ({"data": {"pid": 7}, "exec": EXEC_UNPOLLED}, -1, 0),                      # and so does a negative one
    ({"data": {"pid": 7}, "exec": EXEC_UNPOLLED}, None, 6),                    # a wait was wanted; nothing polled
    ({"data": {"returncode": 0, "stdout": "", "stderr": ""}}, None, 0),
    ({"data": {"returncode": 1, "stdout": "", "stderr": ""}}, None, 5),
    ({"data": {"returncode": 255, "exit_ambiguous": "ssh"}}, None, 6),     # ssh's own exit too: not known to have ended
    ({"data": {"returncode": 254, "stdout": "", "stderr": ""}}, None, 5),
    ({"data": {"proximo_untrusted": True, "data": json.dumps({"returncode": 3, "stdout": "x"})}}, None, 5),
    ({"data": {"proximo_untrusted": True, "data": json.dumps({"returncode": 0})}}, None, 0),
    ({"data": {"proximo_untrusted": True, "data": "not json"}}, None, 0),
    ({"data": {"returncode": True}}, None, 0),                                 # a bool is not an exit code
    ({"data": {"returncode": "1"}}, None, 0),                                  # nor is a vendor's string field
    ({"data": {"proximo_untrusted": True, "data": "[" * 100_000 + "]" * 100_000}}, None, 0),   # never raises
    # a result outranks a doubt (no answer the engine builds carries both; the rule is total anyway)
    ({"data": UPID, "task": TASK_UNASKED, "exec": {**EXEC_OK, "exitcode": 1}}, None, 5),
    ({"data": UPID, "task": TASK_FAILED, "exec": {**EXEC_UNPOLLED, "timed_out": True}}, None, 5),
    ("not a dict", None, 0), (None, None, 0), ([], None, 0),
    ({"task": [1, 2], "exec": "x", "data": 7}, None, 0), ({"task": "UPID", "data": UPID}, None, 0),   # wrong types
]


@pytest.mark.parametrize(("answer", "wait", "code"), CELLS)
def test_the_exit_table(answer, wait, code):
    assert cli.exit_of(answer, wait, command=True) == code
    assert cli.exit_of(answer, wait, command=True) in (0, 5, 6)                 # never 2, 3 or 4: those are the door's


#: a READ's cells: what it found is data. Only a task it WAITED on has an end of its own.
READ_CELLS = [
    (LANE_FAILED, None, 0),                                                    # a probe of a standalone node: pvecm's 2
    ({"data": {"returncode": 127, "stdout": "", "stderr": "not found"}}, None, 0),
    ({"data": {"proximo_untrusted": True, "data": json.dumps({"returncode": 3})}}, None, 0),
    ({"data": {"exited": True, "exitcode": 1}}, None, 0),                      # exec-status read: the vendor's record
    ({"data": {"status": "stopped", "exitstatus": "boom"}}, None, 0),          # task status, not waited on
    ({"data": {"status": "stopped"}, "task": TASK_FAILED}, 5, 5),              # ... waited on: the task's own end
    ({"data": {"status": "running"}, "task": TASK_RUNNING}, 3, 6),
    ({"data": {"status": "stopped"}, "task": TASK_OK}, 5, 0),
]


@pytest.mark.parametrize(("answer", "wait", "code"), READ_CELLS)
def test_a_read_exits_zero_whatever_it_found_but_for_a_task_it_waited_on(answer, wait, code):
    assert cli.exit_of(answer, wait) == code


def test_the_codes_are_the_published_numbers():
    assert (cli.EXIT_OK, cli.EXIT_REFUSED, cli.EXIT_USAGE, cli.EXIT_VENDOR, cli.EXIT_FAILED, cli.EXIT_UNFINISHED) \
        == (0, 2, 3, 4, 5, 6)


def test_the_shell_and_undo_read_a_tasks_end_by_one_rule():
    for task, state in ((TASK_OK, None), (TASK_WARNED, None), (TASK_FAILED, "failed"), (TASK_RUNNING, "timed_out"),
                        (TASK_SUBMITTED, "submitted"), (TASK_UNASKED, "unknown")):
        assert undo.task_state({"task": task}) == state


# --- a task that ends in warnings completed (item 34) ------------------------------------------------

@pytest.fixture
def clock(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(spine, "_CLOCK", lambda: now[0])
    monkeypatch.setattr(spine, "_SLEEP", lambda s: now.__setitem__(0, now[0] + s))
    return now


@pytest.mark.parametrize(("text", "succeeded", "warnings"), [
    ("OK", True, None), ("WARNINGS: 1", True, 1), ("WARNINGS: 12", True, 12), ("WARNINGS: 0", True, 0),
    ("WARNINGS: ", False, None), ("WARNINGS: x", False, None), ("WARNINGS: 1 ", False, None),
    (" WARNINGS: 1", False, None), ("warnings: 1", False, None), ("WARNINGS: 1\nOK", False, None),
    ("WARNINGS: -1", False, None), ("WARNINGS: 1.5", False, None), ("WARNINGS: １", False, None),
    ("WARNINGS: 123456789", True, 123456789), ("WARNINGS: 1234567890", False, None),
    ("WARNINGS: " + "9" * 5000, False, None),                                  # a bound: int() of 5,000 digits raises
    ("unable to start", False, None), ("ok", False, None), (None, False, None), (1, False, None),
])
def test_only_the_vendors_exact_warnings_line_is_a_success(clock, text, succeeded, warnings):
    out = spine.task_wait(lambda: {"status": "stopped", "exitstatus": text}, timeout=5, interval=1)
    assert out["finished"] is True and out["succeeded"] is succeeded and out.get("warnings") == warnings
    assert ("warnings" in out) is (warnings is not None)


class Sequence:
    """A wire that answers the mutation with a UPID and each status poll in turn; the last repeats."""

    def __init__(self, polls, fail=None):
        self.polls, self.fail, self.calls = list(polls), fail, []

    def call(self, method, path, params=None):
        self.calls.append((method, path))
        if method != "GET":
            return UPID
        if self.fail is not None:
            raise self.fail
        return self.polls.pop(0) if len(self.polls) > 1 else self.polls[0]


def _start(armed_plane, monkeypatch, polls, wait=30, fail=None):
    row = engine.resolve("pve", "POST", "/nodes/{node}/qemu/{vmid}/status/start")
    row = engine.Row(**{**row.__dict__, "tier": "read-back"})
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Sequence(polls, fail))
    return engine.execute(row, {}, cfg=armed_plane, path=START, wait=wait)


def _rows(action):
    import os
    with open(os.environ["PROXIMO_AUDIT_LOG"], encoding="utf-8") as f:
        return [r for r in (json.loads(x) for x in f if x.strip()) if r["action"] == action]


def test_a_start_that_ends_in_warnings_is_finished_everywhere(armed_plane, monkeypatch, clock):
    out = _start(armed_plane, monkeypatch, [{"status": "stopped", "exitstatus": "WARNINGS: 1"}])
    assert out["task"]["succeeded"] is True and out["task"]["warnings"] == 1
    assert out["task"]["exitstatus"] == "WARNINGS: 1"                          # the vendor's words stay
    assert _rows("core.task")[-1]["outcome"] == "finished"
    assert cli.exit_of(out, None, command=True) == 0


# --- the engine's own answers, through the table ---------------------------------------------------

def test_a_failed_task_exits_5(armed_plane, monkeypatch, clock):
    out = _start(armed_plane, monkeypatch, [{"status": "stopped", "exitstatus": "shrinking disks is not supported"}])
    assert cli.exit_of(out, None, command=True) == 5


def test_a_wait_that_runs_out_exits_6_and_wait_zero_exits_0(armed_plane, monkeypatch, clock):
    assert cli.exit_of(_start(armed_plane, monkeypatch, [{"status": "running"}], wait=1), 1, command=True) == 6
    assert cli.exit_of(_start(armed_plane, monkeypatch, [{"status": "running"}], wait=0), 0, command=True) == 0


def test_a_status_read_that_fails_after_the_call_exits_6_never_4(armed_plane, monkeypatch, clock):
    """The start was accepted and may be running. 4 is "the vendor refused or was not reached": a script
    that sends again on 4 would start it twice (lens, 2026-11-27)."""
    out = _start(armed_plane, monkeypatch, [{}], fail=httpx.ReadTimeout("read timed out"))
    assert out["task"]["poll_error"] and cli.exit_of(out, None, command=True) == 6


def test_an_id_the_door_would_not_poll_is_not_called_finished(armed_plane, monkeypatch, clock):
    row = engine.resolve("pve", "POST", "/nodes/{node}/qemu/{vmid}/status/start")
    row = engine.Row(**{**row.__dict__, "tier": "read-back"})

    class Odd:
        def call(self, method, path, params=None):
            return "UPID:x"
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Odd())
    out = engine.execute(row, {}, cfg=armed_plane, path=START, wait=30)
    assert out["task"]["polls"] == 0 and "not polled" in out["task"]["why"]
    assert cli.exit_of(out, 30, command=True) == 6 and cli.exit_of(out, 0, command=True) == 0


class Agent:
    def __init__(self, statuses, fail=None):
        self.statuses, self.fail = list(statuses), fail

    def call(self, method, path, params=None):
        if method == "POST":
            return {"pid": 4242}
        if self.fail is not None:
            raise self.fail
        return self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]


def _guest(armed_plane, monkeypatch, statuses, wait=20, fail=None):
    monkeypatch.setenv("PROXIMO_ENABLE_AGENT", "1")
    monkeypatch.setenv("PROXIMO_AGENT_ALLOWLIST", "101")
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Agent(statuses, fail))
    return engine.execute(engine.resolve("pve", "POST", EXEC), {"command": ["false"]}, cfg=armed_plane, path=EXEC,
                          wait=wait)


@pytest.mark.parametrize(("statuses", "wait", "code"), [
    ([{"exited": True, "exitcode": 0}], 20, 0),
    ([{"exited": True, "exitcode": 1}], 20, 5),                                # /usr/bin/false
    ([{"exited": True, "signal": 9}], 20, 5),                                  # kill -9 $$
    ([{"exited": False}], 3, 6),                                               # sleep 12 --wait 3
    ([{"exited": False}], 0, 0),                                               # --wait 0 submits only
])
def test_a_guest_commands_own_end_is_the_exit(armed_plane, monkeypatch, clock, statuses, wait, code):
    assert cli.exit_of(_guest(armed_plane, monkeypatch, statuses, wait=wait), wait, command=True) == code


def test_a_guest_status_read_that_fails_exits_6(armed_plane, monkeypatch, clock):
    out = _guest(armed_plane, monkeypatch, [{}], fail=httpx.ReadTimeout("read timed out"))
    assert cli.exit_of(out, 20, command=True) == 6


@pytest.mark.parametrize("fence", ["0", "1"])
@pytest.mark.parametrize(("rc", "code"), [(0, 0), (1, 5), (127, 5)])
def test_a_container_commands_return_code_is_the_exit_fenced_or_not(armed_plane, monkeypatch, fence, rc, code):
    monkeypatch.setenv(shell.TARGET_ENV, "pve")
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101")
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", fence)

    def run(argv, timeout=None):
        import re
        ran = re.search(r"proximo-ran-([0-9a-f]{32})", argv[-1]).group(1)
        return rc, "out\n", f"proximo-ran-{ran}\n"
    monkeypatch.setattr(shell, "_run", run)
    out = engine.execute(engine.resolve("pve", "POST", CT_EXEC), {"command": ["false"]}, cfg=armed_plane,
                         path=CT_EXEC)
    assert cli.exit_of(out, None, command=True) == code


@pytest.mark.parametrize("fence", ["0", "1"])
def test_a_lane_read_that_found_a_nonzero_exit_is_still_exit_0_at_the_door(armed_plane, monkeypatch, capsys, fence):
    """`GET /nodes/{node}/probe probe=cluster` on a standalone node: `pvecm status` exits 2 and the node is
    healthy (records/diagnose.toml: "its exit is data"). The first cut of this table exited 5 for it."""
    monkeypatch.setenv(shell.TARGET_ENV, "pve")
    monkeypatch.setenv("PROXIMO_ENABLE_NODE_SHELL", "1")
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", fence)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", armed_plane.base_url)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", armed_plane.token_path)

    def run(argv, timeout=None):
        import re
        ran = re.search(r"proximo-ran-([0-9a-f]{32})", argv[-1]).group(1)
        return 2, "", f"proximo-ran-{ran}\nnot in a cluster\n"
    monkeypatch.setattr(shell, "_run", run)
    assert cli.main(["pve", "GET", "/nodes/pve/probe", "probe=cluster"]) == 0
    said = json.loads(capsys.readouterr().out)
    assert "returncode" in json.dumps(said)                                    # the 2 is in the answer, as data


# --- the door itself returns the table's answer ----------------------------------------------------

@pytest.mark.parametrize(("answer", "argv", "code"), [
    ({"data": UPID, "task": TASK_FAILED}, ["pve", "POST", START, "--confirm"], 5),
    ({"data": UPID, "task": TASK_RUNNING}, ["pve", "POST", START, "--confirm", "--wait", "1"], 6),
    ({"data": UPID, "task": TASK_SUBMITTED}, ["pve", "POST", START, "--confirm", "--wait", "0"], 0),
    ({"data": UPID, "task": TASK_WARNED}, ["pve", "POST", START, "--confirm"], 0),
    ({"data": {"pid": 7}, "exec": EXEC_UNPOLLED}, ["pve", "POST", EXEC, "command=id", "--confirm", "--wait", "0"], 0),
    ({"data": {"pid": 7}, "exec": EXEC_UNPOLLED}, ["pve", "POST", EXEC, "command=id", "--confirm"], 6),
    (LANE_FAILED, ["pve", "POST", CT_EXEC, 'command=["false"]', "--confirm"], 5),           # a command: its exit
    (LANE_FAILED, ["pve", "POST", CT_EXEC, 'command=["false"]', "--confirm", "--wait", "0"], 5),   # no task to submit
    (LANE_FAILED, ["pve", "POST", "/nodes/pve1/lxc/101/psql", "sql=select 1", "--confirm"], 5),
    (LANE_DROPPED, ["pve", "POST", CT_EXEC, 'command=["sleep","9"]', "--confirm"], 6),       # may still be running
    ({"data": {"returncode": 255, "stdout": "", "stderr": ""}},                    # 255 with no note beside it
     ["pve", "POST", "/nodes/pve1/lxc/101/psql", "sql=select 1", "--confirm"], 6),
    (LANE_DROPPED, ["pve", "GET", "/nodes/pve1/lxc/101/logs", "unit=ssh"], 0),              # a read: still data
    (LANE_FAILED, ["pve", "POST", START, "--confirm"], 0),                                  # not a lane: a record
    (LANE_FAILED, ["pve", "GET", "/nodes/pve1/lxc/101/logs", "unit=ssh"], 0),               # a read: data
    ({"data": {"status": "stopped"}, "task": TASK_FAILED},
     ["pve", "GET", f"/nodes/pve1/tasks/{UPID}/status", "--wait", "5"], 5),                 # the one read that waits
])
def test_the_door_exits_with_the_tables_code_and_still_prints_the_answer(monkeypatch, capsys, answer, argv, code):
    monkeypatch.setattr(engine, "execute", lambda row, args, **kw: answer)
    assert cli.main(argv) == code
    assert json.loads(capsys.readouterr().out) == answer


def test_an_undo_whose_write_failed_exits_5_and_its_plan_is_untouched(monkeypatch, capsys):
    monkeypatch.setattr(undo, "restore", lambda *a, **k: {"allowed": True, "status": "failed", "task": TASK_FAILED})
    assert cli.main(["pve", "undo", "someid", "--confirm"]) == 5
    for wait, code in ((["--wait", "0"], 0), ([], 6)):                # an undo given --wait 0 submitted only
        monkeypatch.setattr(undo, "restore", lambda *a, **k: {"allowed": True, "status": "submitted",
                                                              "task": TASK_SUBMITTED})
        assert cli.main(["pve", "undo", "someid", "--confirm", *wait]) == code
    monkeypatch.setattr(undo, "restore", lambda *a, **k: {"allowed": True, "status": "noop"})
    assert cli.main(["pve", "undo", "someid", "--confirm"]) == 0
    for status, task, code in (("timed_out", TASK_RUNNING, 6), ("unknown", TASK_UNASKED, 6)):
        said = {"allowed": True, "status": status, "task": task}
        monkeypatch.setattr(undo, "restore", lambda *a, said=said, **k: said)
        assert cli.main(["pve", "undo", "someid", "--confirm"]) == code
    monkeypatch.setattr(undo, "restore", lambda *a, **k: {"allowed": True, "status": "plan"})
    assert cli.main(["pve", "undo", "someid", "--plan"]) == 0
    assert cli.main(["pve", "undo", "someid"]) == 3                 # a bare undo printed its plan, ran nothing
    monkeypatch.setattr(undo, "restore", lambda *a, **k: {"allowed": False, "status": "plan"})
    assert cli.main(["pve", "undo", "someid", "--confirm"]) == 2
    capsys.readouterr()


# --- sent, and nobody knows: NOT decided at this door ----------------------------------------------
# A mutation sent and never answered is still 4, and a lane command whose ssh timed out is still 2,
# as on every release before. Both may have run, and SETUP says so. Telling them apart belongs to the
# wire, per request (John's ruling 2026-11-27, after three reviews of doing it at the door). These
# pin what the door does until that lands, so a change to either is a decision and not a drift.

def _door(armed_plane, monkeypatch):
    monkeypatch.setenv("PROXIMO_API_BASE_URL", armed_plane.base_url)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", armed_plane.token_path)
    monkeypatch.setattr(engine.arm, "arm_state", lambda cfg=None: engine.arm.ArmGateState(True, True, "armed"))


class Raises:
    def __init__(self, on, exc):
        self.on, self.exc = on, exc

    def call(self, method, path, params=None):
        if method == self.on:
            raise self.exc
        return {}


@pytest.mark.parametrize(("exc", "delivery"), [
    (httpx.ReadTimeout("read timed out"), "unknown"),                 # sent, no answer: it may have run
    (httpx.RemoteProtocolError("server disconnected"), "unknown"),
    (httpx.ConnectError("connection refused"), "never-sent"),         # nothing ran
])
def test_a_mutation_the_wire_failed_is_4_and_the_ledger_says_how_far_it_got(armed_plane, monkeypatch, capsys,
                                                                          exc, delivery):
    _door(armed_plane, monkeypatch)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Raises("POST", exc))
    assert cli.main(["pve", "POST", "/pools", "poolid=exit-probe", "--confirm"]) == 4
    assert capsys.readouterr().err.startswith("vendor: unreachable")
    assert _rows("core.error")[-1]["detail"]["delivery"] == delivery


def test_a_read_that_times_out_is_still_4(armed_plane, monkeypatch, capsys):
    _door(armed_plane, monkeypatch)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Raises("GET", httpx.ReadTimeout("read timed out")))
    assert cli.main(["pve", "GET", "/nodes/pve1/status"]) == 4
    assert capsys.readouterr().err.startswith("vendor: unreachable")


def test_a_vendors_no_is_still_4(armed_plane, monkeypatch, capsys):
    _door(armed_plane, monkeypatch)
    req = httpx.Request("POST", "https://pve.invalid:8006/api2/json/pools")
    refused = httpx.HTTPStatusError("HTTP 403", request=req, response=httpx.Response(403, request=req))
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Raises("POST", refused))
    assert cli.main(["pve", "POST", "/pools", "poolid=exit-probe", "--confirm"]) == 4
    assert capsys.readouterr().err.startswith("vendor: HTTP 403")


@pytest.mark.parametrize(("raised", "word", "says"), [
    (__import__("subprocess").TimeoutExpired("ssh", 60), "refused: no answer from pve within", "may still be running"),
    (BrokenPipeError(32, "broken pipe"), "refused: the ssh session to pve failed after it started", "may have run"),
    (FileNotFoundError(2, "no ssh"), "refused: ssh to pve could not be started", "nothing ran"),
])
def test_a_lane_command_whose_ssh_failed_is_2_and_its_words_say_whether_it_may_have_run(armed_plane, monkeypatch,
                                                                                      capsys, raised, word, says):
    _door(armed_plane, monkeypatch)
    monkeypatch.setenv(shell.TARGET_ENV, "pve")
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101")

    def run(argv, timeout=None):
        raise raised
    monkeypatch.setattr(shell, "_run", run)
    psql = ["pve", "POST", "/nodes/pve1/lxc/101/psql", "sql=select 1"]
    for call in (["pve", "POST", CT_EXEC, 'command=["id"]'], psql):
        assert cli.main([*call, "--confirm"]) == 2
        err = capsys.readouterr().err
        assert err.startswith(word) and says in err
