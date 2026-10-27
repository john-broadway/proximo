"""The reach grant, observable (capability `reach-grant-observable`).

`PROXIMO_CT_ALLOWLIST` and `PROXIMO_AGENT_ALLOWLIST` are the perimeter of the one channel a
Proxmox ACL cannot scope (ssh -> pct exec). A door compares the grant it starts with against the
last grant the ledger recorded and writes a `core.reach_grant` row when it moved, so "who widened
what the agent can reach, and when" is provable from the chain. Doctor reads it back, and
optionally tells which allowlisted guests the served token holds a chosen privilege on.
"""
from __future__ import annotations

import json
import os

import httpx
import pytest

from proximo.core import doctor, engine, envfile, reach, spine

MARK = "zq9x-secret-marker"


@pytest.fixture
def lane(monkeypatch, tmp_path):
    """A clean reach environment: no allowlist, no switch, no mirror; a ledger under tmp."""
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var not in ("PROXIMO_ENV_FILE", "PROXIMO_AUDIT_LOG"):
            monkeypatch.delenv(var)
    envfile._STATE.update(envfile._fresh_state())

    def set_(ct=None, agent=None, exec_on=None, agent_on=None):
        for name, val in (("PROXIMO_CT_ALLOWLIST", ct), ("PROXIMO_AGENT_ALLOWLIST", agent)):
            if val is not None:
                monkeypatch.setenv(name, val)
        if exec_on is not None:
            monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1" if exec_on else "0")
        if agent_on is not None:
            monkeypatch.setenv("PROXIMO_ENABLE_AGENT", "1" if agent_on else "0")
    return set_


def _rows():
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def _reach_rows():
    return [r for r in _rows() if r["action"] == "core.reach_grant"]


def _greet(face="stdio"):
    return reach.greet("proximo-test", face)


# --- the row: first seen, widened, narrowed, unchanged --------------------------------------------

def test_the_first_start_records_the_grant_as_first_seen(lane):
    lane(ct="105, 101", exec_on=True)
    assert _greet() is True
    (row,) = _reach_rows()
    d = row["detail"]
    assert d["change"] == "first" and d["face"] == "stdio"
    assert d["lanes"]["shell"] == {"enabled": True, "ids": ["101", "105"], "garbled": False, "grants": True}
    assert d["lanes"]["agent"] == {"enabled": False, "ids": [], "garbled": False, "grants": False}
    assert set(d["lanes"]) == set(spine._LANES)          # every opt-in lane the spine keeps, node and download too


def test_an_unchanged_restart_records_nothing(lane):
    lane(ct="101,105", exec_on=True)
    _greet()
    _greet()
    assert len(_reach_rows()) == 1


def test_the_same_ids_in_another_order_are_the_same_grant(lane, monkeypatch):
    lane(ct="101,105", exec_on=True)
    _greet()
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", " 105 ,101,, 105")
    _greet()
    assert len(_reach_rows()) == 1


def test_ids_added_are_a_widening_and_name_exactly_what_was_added(lane, monkeypatch):
    lane(ct="101", exec_on=True)
    _greet()
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101,110,105")
    _greet()
    d = _reach_rows()[-1]["detail"]
    assert d["change"] == "widened"
    assert d["added"] == {"shell": ["105", "110"]} and d["removed"] == {}


def test_a_star_appearing_is_a_widening(lane, monkeypatch):
    lane(ct="101", exec_on=True)
    _greet()
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101, *")
    _greet()
    d = _reach_rows()[-1]["detail"]
    assert d["change"] == "widened" and d["lanes"]["shell"]["ids"] == ["*"]
    assert d["added"] == {"shell": ["*"]}


def test_ids_removed_are_a_narrowing(lane, monkeypatch):
    lane(ct="101,105,110", exec_on=True)
    _greet()
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101")
    _greet()
    d = _reach_rows()[-1]["detail"]
    assert d["change"] == "narrowed" and d["removed"] == {"shell": ["105", "110"]} and d["added"] == {}


def test_a_star_leaving_is_a_narrowing(lane, monkeypatch):
    lane(ct="*", exec_on=True)
    _greet()
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101")
    _greet()
    d = _reach_rows()[-1]["detail"]
    assert d["change"] == "narrowed" and d["removed"] == {"shell": ["*"]}


def test_switching_a_lane_on_is_a_widening_though_the_ids_did_not_move(lane, monkeypatch):
    lane(ct="101", exec_on=False)
    _greet()
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    _greet()
    d = _reach_rows()[-1]["detail"]
    assert d["change"] == "widened" and d["added"] == {"shell": ["enabled"]}


def test_the_agent_lane_is_a_grant_too(lane, monkeypatch):
    lane(agent="100", agent_on=True)
    _greet()
    monkeypatch.setenv("PROXIMO_AGENT_ALLOWLIST", "100,200")
    _greet()
    d = _reach_rows()[-1]["detail"]
    assert d["change"] == "widened" and d["added"] == {"agent": ["200"]}


def test_a_widening_and_a_removal_together_is_a_widening_naming_both(lane, monkeypatch):
    lane(ct="101,105", exec_on=True)
    _greet()
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101,300")
    _greet()
    d = _reach_rows()[-1]["detail"]
    assert d["change"] == "widened" and d["added"] == {"shell": ["300"]} and d["removed"] == {"shell": ["105"]}


def test_a_garbled_grant_is_recorded_as_denying_everything(lane):
    lane(exec_on=True)
    os.environ["PROXIMO_CT_ALLOWLIST"] = "101"
    _greet()
    # the list shape is unreachable from a process env; the parser's own garbled answer is what the row carries
    assert reach.current()["shell"]["garbled"] is False
    assert reach._lane_of(frozenset(), False, True, True) == {
        "enabled": True, "ids": [], "garbled": True, "grants": False}


def test_the_row_carries_ids_and_a_source_in_words_never_a_path_or_a_value_of_another_key(lane, tmp_path, monkeypatch):
    f = tmp_path / f"{MARK}.env"
    f.write_text("PROXIMO_CT_ALLOWLIST=101\nPROXIMO_ENABLE_EXEC=1\n")
    monkeypatch.setenv("PROXIMO_ENV_FILE", str(f))
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", f"/etc/{MARK}-token")
    envfile.load(announce=False)
    _greet()
    raw = json.dumps(_reach_rows()[0])
    assert MARK not in raw and "/" not in json.dumps(_reach_rows()[0]["detail"]["lanes"])
    assert _reach_rows()[0]["detail"]["source"]["shell"] == "the env file"


# --- a ledger that cannot be compared against -----------------------------------------------------

def _tamper_the_first_row():
    log = os.environ["PROXIMO_AUDIT_LOG"]
    rows = open(log, encoding="utf-8").read().splitlines()
    first = json.loads(rows[0])
    first["target"] = "forged"
    rows[0] = json.dumps(first, separators=(",", ":"))
    open(log, "w", encoding="utf-8").write("\n".join(rows) + "\n")


def _unreadable_ledger():
    """A ledger the door cannot read or open: the path is a directory."""
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if os.path.exists(log):
        os.remove(log)
    os.mkdir(log)


def test_a_chain_that_will_not_verify_does_not_brick_the_door_it_is_loud_and_still_names_a_widening(
        lane, capsys, monkeypatch):
    lane(ct="101", exec_on=True)
    _greet()
    _tamper_the_first_row()
    capsys.readouterr()
    assert _greet() is True                                    # the engine keeps receipting on such a chain
    err = capsys.readouterr().err
    assert "UNPROVEN" in err and "audit_verify" in err and os.environ["PROXIMO_AUDIT_LOG"] not in err
    assert len(_reach_rows()) == 1                             # unchanged: loud, but no heartbeat row
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101,999")
    assert _greet() is True
    last = _reach_rows()[-1]
    assert last["detail"]["change"] == "widened" and last["detail"]["added"] == {"shell": ["999"]}
    assert last["outcome"] == "unproven" and "does not verify" in last["detail"]["reason"]


def test_doctor_flags_an_unprovable_baseline_and_the_report_is_not_complete(box, lane):
    lane(ct="101", exec_on=True)
    _greet()
    _tamper_the_first_row()
    r = doctor.run()
    assert any(f.startswith("reach: the grant's record cannot be proven") for f in r["flags"])
    assert r["complete"] is False


def test_a_ledger_that_cannot_be_read_refuses_the_start_when_a_lane_is_open(lane, capsys):
    lane(ct="101", exec_on=True)
    _unreadable_ledger()
    assert _greet() is False
    err = capsys.readouterr().err
    assert "could not be compared" in err and "refuses to start" in err and os.environ["PROXIMO_AUDIT_LOG"] not in err


def test_with_every_lane_closed_an_unreadable_ledger_is_said_and_the_door_starts(lane, capsys):
    lane(ct="101", exec_on=False)
    _unreadable_ledger()
    assert _greet() is True
    assert "every lane is closed" in capsys.readouterr().err


def test_a_row_that_cannot_be_written_refuses_the_start_when_a_lane_is_open(lane, monkeypatch):
    from proximo.core.ledger import AuditLedger  # noqa: PLC0415

    def boom(self, *a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(AuditLedger, "record", boom)
    lane(ct="101", exec_on=True)
    assert _greet() is False


def test_a_node_shell_or_download_lane_open_counts_as_open_when_the_grant_cannot_be_written(lane, monkeypatch):
    monkeypatch.setenv("PROXIMO_ENABLE_DOWNLOAD", "1")
    _unreadable_ledger()
    assert _greet() is False


@pytest.mark.parametrize("env,lane_name", [("PROXIMO_ENABLE_NODE_SHELL", "node"),
                                           ("PROXIMO_ENABLE_DOWNLOAD", "download")])
def test_switching_a_lane_with_no_allowlist_on_is_a_widening(lane, monkeypatch, env, lane_name):
    lane(ct="101", exec_on=True)
    _greet()
    monkeypatch.setenv(env, "1")
    _greet()
    d = _reach_rows()[-1]["detail"]
    assert d["change"] == "widened" and d["added"] == {lane_name: ["enabled"]}


def test_a_lane_switched_on_with_an_empty_allowlist_is_open_for_the_record_and_grants_nothing(box, lane, capsys):
    lane(exec_on=True)
    _greet()
    assert _reach_rows()[0]["detail"]["lanes"]["shell"]["grants"] is False
    r = doctor.run()
    assert any("shell lane is switched on and grants nothing" in f for f in r["flags"])
    _unreadable_ledger()
    capsys.readouterr()
    assert _greet() is False and "shell grant(s) nothing" in capsys.readouterr().err


# --- per face: two deployments with different env must not hide behind each other ------------------

def test_a_face_is_compared_with_its_own_last_row_not_the_newest_row_of_another_face(lane, monkeypatch):
    lane(ct="101", exec_on=True)
    _greet("stdio")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "*")
    _greet("http")                                   # another deployment, wide: its own first row
    _greet("stdio")                                  # stdio widened 101 -> *: hidden if the baseline were http's
    d = _reach_rows()[-1]["detail"]
    assert d["face"] == "stdio" and d["change"] == "widened" and d["added"] == {"shell": ["*"]}


def test_two_faces_with_different_env_do_not_flap_widened_narrowed_every_start(lane, monkeypatch):
    for _ in range(3):
        monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
        monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101")
        _greet("stdio")
        monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101,105,110")
        _greet("http")
    rows = [(r["detail"]["face"], r["detail"]["change"]) for r in _reach_rows()]
    assert rows == [("stdio", "first"), ("http", "first")]


# --- a wiped, replaced or rotated ledger does not read as a clean first ---------------------------

def test_a_wiped_ledger_with_the_key_left_behind_is_first_with_history_and_unproven_with_a_lane_open(
        lane, capsys):
    lane(ct="101", exec_on=True)
    _greet()
    os.remove(os.environ["PROXIMO_AUDIT_LOG"])                  # the key stays beside it
    capsys.readouterr()
    assert _greet() is True
    row = _reach_rows()[-1]
    assert row["detail"]["change"] == "first_with_history" and row["outcome"] == "unproven"
    assert "UNPROVEN" in capsys.readouterr().err


def test_first_with_history_with_every_lane_closed_is_recorded_but_not_unproven(lane):
    lane(ct="101", exec_on=False)
    _greet()
    os.remove(os.environ["PROXIMO_AUDIT_LOG"])
    _greet()
    row = _reach_rows()[-1]
    assert row["detail"]["change"] == "first_with_history" and row["outcome"] == "ok"


def test_a_ledger_that_held_receipts_but_no_reach_row_is_first_with_history(lane):
    """The upgrade case, and the same shape as a wipe that kept some rows: said, not assumed clean."""
    from proximo.core.ledger import LedgerConfig, open_ledger  # noqa: PLC0415
    open_ledger(LedgerConfig.from_env()).record("session_start", target="face/stdio", detail={})
    lane(ct="101", exec_on=True)
    _greet()
    assert _reach_rows()[0]["detail"]["change"] == "first_with_history"


def test_a_sealed_rotation_archive_is_followed_for_the_last_reach_row(lane, monkeypatch):
    """An unkeyed ledger is sealed and rotated by open_ledger at the start: the live log is then
    empty of reach rows, and the widening must still be named against the archive's last row."""
    from proximo.core.ledger import AuditLedger  # noqa: PLC0415
    lane(ct="101", exec_on=True)
    lanes = reach.current()
    AuditLedger(os.environ["PROXIMO_AUDIT_LOG"]).record(           # an unkeyed 0.44-era chain with a reach row
        reach.ACTION, target=reach.TARGET, detail={"face": "stdio", "change": "first", "lanes": lanes})
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101,105")
    _greet()
    d = _reach_rows()[-1]["detail"]
    assert d["change"] == "widened" and d["added"] == {"shell": ["105"]}


def test_the_operators_pin_makes_a_rolled_back_ledger_unprovable(lane, monkeypatch, capsys):
    lane(ct="101", exec_on=True)
    _greet()
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101,105")
    _greet()
    log = os.environ["PROXIMO_AUDIT_LOG"]
    rows = open(log, encoding="utf-8").read().splitlines()
    monkeypatch.setenv("PROXIMO_AUDIT_EXPECTED_HEAD", json.loads(rows[-1])["entry_hash"])   # the widening is pinned
    open(log, "w", encoding="utf-8").write(rows[0] + "\n")                                  # ...then cut away
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101,105,110")
    capsys.readouterr()
    _greet()
    last = _reach_rows()[-1]
    assert last["outcome"] == "unproven" and "pinned row not in the chain" in last["detail"]["reason"]
    assert "UNPROVEN" in capsys.readouterr().err


def test_concurrent_starts_write_one_row_for_one_change(lane, monkeypatch):
    import threading
    import time
    lane(ct="101", exec_on=True)
    real = reach.baseline
    inside, calls = threading.Event(), []

    def slow(lcfg, **k):
        got = real(lcfg, **k)
        calls.append(1)
        if len(calls) == 1:
            inside.set()
            time.sleep(0.4)                      # the first start has read "none" and is about to write
        return got
    monkeypatch.setattr(reach, "baseline", slow)
    t1 = threading.Thread(target=_greet)
    t1.start()
    inside.wait(5)
    t2 = threading.Thread(target=_greet)
    t2.start()
    t1.join(10)
    t2.join(10)
    assert len(_reach_rows()) == 1


# --- the doors -------------------------------------------------------------------------------------

def test_the_stdio_door_records_the_grant_before_session_start_and_refuses_when_it_cannot_read_the_ledger(
        lane, monkeypatch):
    from proximo.core.doors import mcp  # noqa: PLC0415

    class _Server:
        def run(self):
            return None
    monkeypatch.setattr(mcp, "build_server", lambda *a, **k: _Server())
    lane(ct="101", exec_on=True)
    assert mcp.main([]) == 0
    assert [r["action"] for r in _rows()] == ["core.reach_grant", "session_start", "session_end"]
    assert _reach_rows()[0]["detail"]["face"] == "stdio"
    _unreadable_ledger()
    ran = []
    monkeypatch.setattr(mcp, "build_server", lambda *a, **k: type("S", (), {"run": lambda s: ran.append(1)})())
    assert mcp.main([]) == 3
    assert ran == []


@pytest.mark.parametrize("modname,prefix", [("mcphttp", "MCP_HTTP"), ("http", "HTTP"), ("a2a", "A2A")])
def test_every_network_door_records_the_grant_before_it_serves(lane, monkeypatch, modname, prefix):
    import importlib

    import uvicorn
    mod = importlib.import_module(f"proximo.core.doors.{modname}")
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: None)
    monkeypatch.setenv(f"PROXIMO_{prefix}_HOST", "127.0.0.1")
    lane(ct="101", exec_on=True)
    assert mod.main([]) == 0
    assert [r["action"] for r in _rows()] == ["core.reach_grant", "session_start", "session_end"]
    _unreadable_ledger()
    served = []
    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: served.append(1))
    assert mod.main([]) == 3 and served == []


def test_the_shell_door_greets_before_a_call_that_can_mutate_and_not_before_a_read(box, lane, monkeypatch):
    from proximo.core.doors import cli  # noqa: PLC0415
    greeted, ran = [], []
    monkeypatch.setattr(reach, "greet", lambda prog, face: greeted.append(face) or True)
    monkeypatch.setattr(engine, "execute", lambda *a, **k: ran.append(a[0].method) or {})
    assert cli.main(["pve", "GET", "/version"]) == 0
    assert greeted == []
    assert cli.main(["pve", "POST", "/nodes/pve1/qemu/100/status/start"]) == 0
    assert greeted == ["cli"] and ran == ["GET", "POST"]
    monkeypatch.setattr(reach, "greet", lambda prog, face: False)
    assert cli.main(["pve", "POST", "/nodes/pve1/qemu/100/status/stop"]) == 3 and len(ran) == 2


# --- doctor: the reach section ---------------------------------------------------------------------

class Wire:
    """Answers the doctor's reads and the per-guest permission query; `held` maps a guest path to
    the privileges the served token holds there, as PVE's per-path query answers them."""

    def __init__(self, held=None, fail=False):
        self.calls = []
        self.held = held or {}
        self.fail = fail

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        if path == "/version":
            return {"version": "9.2.2"}
        if path == "/access/permissions":
            if params and params.get("path"):
                if self.fail:
                    req = httpx.Request(method, "https://pve.invalid:8006/api2/json" + path)
                    raise httpx.HTTPStatusError("403", request=req, response=httpx.Response(403, request=req))
                p = params["path"]
                return {p: {k: 1 for k in self.held.get(p, ())}} if self.held.get(p) else {}
            return {"/": {"Sys.Audit": 1}}
        raise AssertionError(f"unexpected read {method} {path}")


@pytest.fixture
def box(lane, armed_plane, monkeypatch):
    os.chmod(armed_plane.token_path, 0o600)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", armed_plane.base_url)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", armed_plane.token_path)
    w = Wire()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    return w


def test_doctor_reach_reads_back_the_grant_its_source_and_the_last_change(box, lane, monkeypatch):
    lane(ct="101,105", exec_on=True)
    _greet()
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101,105,110")
    _greet()
    r = doctor.run()
    sec = r["reach"]
    assert sec["lanes"]["shell"] == {"enabled": True, "ids": ["101", "105", "110"], "garbled": False,
                                     "grants": True, "source": "the process environment"}
    assert sec["faces"]["stdio"]["change"] == "widened"
    assert sec["last_change"]["change"] == "widened" and sec["last_change"]["added"] == {"shell": ["110"]}
    assert sec["last_change"]["ts"] and sec["recorded_matches_current"] is True
    assert not any("reach grant" in f for f in r["flags"])


def test_doctor_flags_a_grant_no_door_has_recorded_yet(box, lane):
    lane(ct="101,105", exec_on=True)
    r = doctor.run()                                # nothing greeted the ledger: a door has not started
    assert r["reach"]["recorded_matches_current"] is False and r["reach"]["last_change"] is None
    assert any(f.startswith("the reach grant") for f in r["flags"])
    assert r["complete"] is True                    # advisory: it moves no exit code


def test_doctor_names_a_widening_not_yet_recorded(box, lane, monkeypatch):
    lane(ct="101", exec_on=True)
    _greet()
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "*")
    r = doctor.run()
    assert r["reach"]["recorded_matches_current"] is False
    assert any(f.startswith("the reach grant") and "differs" in f for f in r["flags"])


def test_the_mirror_is_inert_unless_a_privilege_is_named(box, lane):
    lane(ct="101", exec_on=True)
    doctor.run()
    assert all(c[2] == {} for c in box.calls)                         # no per-guest query was made


def test_the_mirror_flags_allowlisted_guests_the_token_holds_no_privilege_on(box, lane, monkeypatch):
    lane(ct="101,102,103", exec_on=True)
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "VM.GuestAgent.Unrestricted")
    box.held = {"/vms/101": ["VM.GuestAgent.Unrestricted"], "/vms/102": ["VM.Audit"]}
    r = doctor.run()
    m = r["reach"]["mirror"]
    assert m["privilege"] == "VM.GuestAgent.Unrestricted" and m["checked"] == 3
    assert m["without"] == ["102", "103"] and m["unanswered"] == []
    assert any("102" in f and "103" in f and "VM.GuestAgent.Unrestricted" in f for f in r["flags"])
    assert r["complete"] is True and r["exit"] == 0                   # advisory, never a gate
    asked = [c[2]["path"] for c in box.calls if c[2]]
    assert asked == ["/vms/101", "/vms/102", "/vms/103"]              # PVE's own per-path resolution
    reads = [x["target"] for x in _rows() if x["action"] == "core.execute"]
    assert "/access/permissions" in reads                              # through the engine, receipted


def test_a_guest_the_token_does_hold_is_not_flagged(box, lane, monkeypatch):
    lane(ct="101", exec_on=True)
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "VM.Console")
    box.held = {"/vms/101": ["VM.Console"]}
    r = doctor.run()
    assert r["reach"]["mirror"]["without"] == [] and not any("holds no" in f for f in r["flags"])


def test_a_refused_permissions_read_is_unanswered_never_allowed(box, lane, monkeypatch):
    lane(ct="101", exec_on=True)
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "VM.Console")
    box.fail = True
    r = doctor.run()
    m = r["reach"]["mirror"]
    assert m["unanswered"] == ["101"] and m["without"] == []
    assert any("could not be read" in f and "101" in f for f in r["flags"])


def test_an_allow_all_grant_is_not_judged_per_guest_and_says_so(box, lane, monkeypatch):
    lane(ct="*", exec_on=True)
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "VM.Console")
    m = doctor.run()["reach"]["mirror"]
    assert m["skipped"].startswith("the container allowlist is '*'") and m["checked"] == 0


def test_a_blank_privilege_is_a_flagged_misconfiguration_not_silence(box, lane, monkeypatch):
    lane(ct="101", exec_on=True)
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "   ")
    r = doctor.run()
    assert r["reach"]["mirror"]["error"].startswith("PROXIMO_REACH_PRIVILEGE is set but blank")
    assert any("PROXIMO_REACH_PRIVILEGE is set but blank" in f for f in r["flags"])


def test_the_mirror_reads_are_bounded(box, lane, monkeypatch):
    lane(ct=",".join(str(100 + i) for i in range(reach.MIRROR_CAP + 10)), exec_on=True)
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "VM.Console")
    m = doctor.run()["reach"]["mirror"]
    assert m["checked"] == reach.MIRROR_CAP and m["capped"] is True


def test_a_lane_that_is_closed_is_not_mirrored(box, lane, monkeypatch):
    lane(ct="101", exec_on=False)
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "VM.Console")
    m = doctor.run()["reach"]["mirror"]
    assert m["skipped"] == "the container shell lane is off" and m["checked"] == 0


def test_a_mirror_whose_address_is_not_served_is_skipped_never_a_crash(box, lane, monkeypatch):
    from proximo.core.errors import ProximoError  # noqa: PLC0415
    lane(ct="101", exec_on=True)
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "VM.Console")
    real = engine.resolve

    def resolve(plane, method, path):
        if path == "/access/permissions" and method == "GET" and getattr(resolve, "armed", False):
            raise ProximoError("not served")
        return real(plane, method, path)
    monkeypatch.setattr(engine, "resolve", resolve)
    resolve.armed = True
    # the doctor's own plane read goes through resolve too; the mirror's skip is what is under test
    out = reach._mirror(None, reach.current(), [])
    assert out["skipped"].startswith("pve is not configured") or "does not serve" in out["skipped"]


def test_the_mirror_says_what_it_did_not_ask(box, lane, monkeypatch):
    ids = ",".join(str(100 + i) for i in range(reach.MIRROR_CAP + 3)) + ",db-main"
    lane(ct=ids, exec_on=True)
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "VM.Console")
    r = doctor.run()
    m = r["reach"]["mirror"]
    assert m["not_asked"] == ["db-main"] and m["not_mirrored"] == ["agent"]
    assert any("beyond the first 25" in f for f in r["flags"])
    assert any("not container ids (db-main)" in f for f in r["flags"])
    assert r["complete"] is True                                   # all advisory
