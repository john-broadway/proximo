"""The exit ceiling is the operator's to raise (issue #114): `PROXIMO_EXIT_MAX_BYTES`, whole bytes from 3072 to
65536, is one ceiling for every read, plan and composed answer a model is handed; unset is the three ceilings
it always was, and the refusal ceiling never moves. A value that is set and is not that is junk: the defaults
stand, doctor flags it, and an over-cap answer names the variable after its operator line when that still fits
under the ceiling, never the value, and never at the cost of the rich shape. No argument a model sends moves it;
the raw cap below the exit is a separate knob."""

from __future__ import annotations

import json
import os
import re

import pytest

from proximo.core import doctor, engine, mcpcompat, rawdoor, receipt, shell
from proximo.core.doors import mcp as door

DEFAULTS = {"read": 1152, "plan": 2048, "composed": 3072, "refusal": 512}


def _bytes(answer) -> int:
    return len(json.dumps(answer, separators=(",", ":"), ensure_ascii=False, default=str).encode())


def _exec_answer(stdout_bytes: int) -> dict:
    """What `proximo_call` answers for a shell exec whose command printed `stdout_bytes` of text."""
    return {"address": "POST /nodes/pve0/lxc/111/exec", "plane": "pve", "allowed": True, "consent_id": "c" * 64,
            "status": "ok", "data": {"returncode": 0, "stdout": "r" * stdout_bytes, "stderr": ""},
            "undo": {"id": "u" * 24}, "task": {"status": "stopped", "exitstatus": "OK"}}


def test_unset_is_the_ceilings_it_always_was(monkeypatch):
    monkeypatch.delenv(rawdoor.EXIT_ENV, raising=False)
    assert rawdoor.ceilings() == DEFAULTS and rawdoor.CEILINGS == DEFAULTS
    out = rawdoor.finish("proximo_call", _exec_answer(3400))
    assert out["over_cap"] is True and out["cap"] == 2048 and "stdout" not in str(out)
    assert rawdoor.EXIT_ENV in out["next"]            # the knob is named where the output went missing


@pytest.mark.parametrize("value,ceiling", [("4096", 4096), (" 65536 ", 65536), ("3072", 3072)])
def test_a_set_value_is_one_ceiling_for_every_kind_but_refusal(monkeypatch, value, ceiling):
    monkeypatch.setenv(rawdoor.EXIT_ENV, value)
    assert rawdoor.ceilings() == {"read": ceiling, "plan": ceiling, "composed": ceiling, "refusal": 512}
    assert rawdoor.CEILINGS == DEFAULTS                                     # the defaults are a constant


def test_the_exit_alone_passes_the_exec_output_alexdelprete_measured(monkeypatch):
    """The exit's half only: the lane's own cap is the companion test below (raw cap raised too)."""
    monkeypatch.setenv(rawdoor.EXIT_ENV, "16384")
    for printed in (3368, 3370, 6628, 8700):                                 # docker ps, doctor, 50 log lines, WUD
        out = rawdoor.finish("proximo_call", _exec_answer(printed))
        assert "over_cap" not in out and out["data"]["stdout"] == "r" * printed
    out = rawdoor.finish("proximo_call", _exec_answer(20000))               # over even the raised ceiling
    assert out["over_cap"] is True and out["cap"] == 16384 and out["undo"] == "u" * 24
    assert rawdoor.EXIT_ENV not in out["next"]                              # already raised: not named again


def test_the_whole_mcp_exit_hands_the_output_over_when_raised(monkeypatch):
    monkeypatch.setenv(rawdoor.EXIT_ENV, "16384")
    blocks, final = mcpcompat.seal_result("proximo_call", ([], _exec_answer(8700)))
    assert final["data"]["stdout"] == "r" * 8700 and json.loads(blocks[0].text) == final
    monkeypatch.delenv(rawdoor.EXIT_ENV)
    blocks, final = mcpcompat.seal_result("proximo_call", ([], _exec_answer(8700)))
    assert final["over_cap"] is True and _bytes(final) <= 2048 and json.loads(blocks[0].text) == final


@pytest.mark.parametrize("value", ["0", "3071", "65537", "-5", "4096.5", "1e4", "big", "4k", "٤٠٩٦", "16 KiB"])
def test_anything_else_is_junk_the_defaults_stand_and_it_is_named_not_echoed(monkeypatch, value):
    monkeypatch.setenv(rawdoor.EXIT_ENV, value)
    assert rawdoor.ceilings() == DEFAULTS
    problem = rawdoor.exit_problem()
    assert problem and rawdoor.EXIT_ENV in problem and "3072 to 65536" in problem
    assert not re.search(rf"(?<![0-9]){re.escape(value.strip())}(?![0-9])", problem)   # the junk is not echoed
    assert problem not in rawdoor.cap_problems()                    # doctor's alone: never a note on a cut read
    out = rawdoor.finish("proximo_call", _exec_answer(3400))
    assert out["over_cap"] is True and out["cap"] == 2048 and rawdoor.EXIT_ENV in out["next"]
    assert value.strip() not in out["next"] and _bytes(out) <= 2048


def test_an_empty_value_is_unset(monkeypatch):
    monkeypatch.setenv(rawdoor.EXIT_ENV, "  ")
    assert rawdoor.ceilings() == DEFAULTS and rawdoor.exit_problem() is None


def test_the_refusal_ceiling_never_moves(monkeypatch):
    monkeypatch.setenv(rawdoor.EXIT_ENV, "65536")
    assert rawdoor.ceilings()["refusal"] == 512 and len(rawdoor.refusal_text("x" * 9000).encode()) <= 512


def test_an_exec_comes_back_whole_only_when_the_raw_cap_is_raised_too(monkeypatch):
    """The issue's own case: the wire's cap (shell._bounded) trims stdout before the exit sees it."""
    result = {"returncode": 0, "stdout": "r" * 8700, "stderr": ""}
    monkeypatch.delenv("PROXIMO_RAW_MAX_BYTES", raising=False)
    monkeypatch.delenv("PROXIMO_RAW_MAX_TOKENS", raising=False)
    monkeypatch.setenv(rawdoor.EXIT_ENV, "16384")
    cut = shell._bounded(result)
    assert cut["truncated"] == {"stdout": 8700} and len(cut["stdout"]) < 8700
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "16384")
    whole = shell._bounded(result)
    assert whole == result
    _, final = mcpcompat.seal_result("proximo_call", ([], {**_exec_answer(0), "data": whole}))
    assert final["data"]["stdout"] == "r" * 8700 and "over_cap" not in final


# --- the cut stream's own line, through the engine (lens 3: a hand-built dict proved the wrong shape) ----

_LANE_ROWS = {"exec": ("POST", "exec", {"command": ["docker", "ps"]}), "probe": ("GET", "probe", {"probe": "disk"})}


def _exec(box, monkeypatch, out, err, rc=1, node="pve1", vmid="101", kind="exec"):
    """One shell-lane call through engine.execute with a fake host, as proximo_call (or a read of the lane's
    probe row) runs it."""
    from test_core_shell_lane import Runner, _on
    method, suffix, args = _LANE_ROWS[kind]
    path = f"/nodes/{node}/lxc/{vmid}/{suffix}"
    monkeypatch.setenv(shell.TARGET_ENV, "pve")
    _on(monkeypatch, allow=vmid)
    monkeypatch.setattr(shell, "_run", Runner(rc=rc, out=out, err=err))
    return engine.execute(engine.resolve("pve", method, path), dict(args), cfg=box, path=path)


def _dense(n, seed):
    import random
    import string
    rng = random.Random(seed)  # noqa: S311 -- a seeded fixture, not a secret
    return "".join(rng.choice(string.hexdigits + ":./-") for _ in range(n))


@pytest.fixture
def raw_defaults(monkeypatch):
    for var in ("PROXIMO_RAW_MAX_BYTES", "PROXIMO_RAW_MAX_TOKENS", rawdoor.EXIT_ENV):
        monkeypatch.delenv(var, raising=False)


def test_a_cut_exec_names_the_raw_cap_only_while_neither_cap_is_set(armed_plane, monkeypatch, raw_defaults):
    """alexdelprete, #114: exit raised, raw cap left alone, 200 bytes kept and nothing said which knob. The
    line rides on that state alone; any set cap, bytes or tokens, is the operator's and names nothing (lens
    rounds 3 and 4: every rule that tried to say WHICH knob bound the cut was wrong in some cell)."""
    monkeypatch.setenv(rawdoor.EXIT_ENV, "16384")
    out = _exec(armed_plane, monkeypatch, "r" * 8700, "")
    assert out["data"]["truncated"] == {"stdout": 8700} and "PROXIMO_RAW_MAX_BYTES" in out["data"]["next"]
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "2048")                     # set, and still cut: theirs
    out = _exec(armed_plane, monkeypatch, "r" * 8700, "")
    assert out["data"]["truncated"] == {"stdout": 8700} and "next" not in out["data"]
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "16384")                    # whole: nothing to name
    out = _exec(armed_plane, monkeypatch, "r" * 8700, "")
    assert out["data"]["stdout"] == "r" * 8700 and "truncated" not in out["data"] and "next" not in out["data"]
    monkeypatch.delenv("PROXIMO_RAW_MAX_BYTES")
    for tokens, body in (("2000", _dense(20000, 1)), ("1000", "r" * 400), ("500", _dense(20000, 2))):
        monkeypatch.setenv("PROXIMO_RAW_MAX_TOKENS", tokens)                # a token cap set: theirs, any size
        out = _exec(armed_plane, monkeypatch, body, body)
        assert out["data"]["truncated"] and "next" not in out["data"], tokens


@pytest.mark.parametrize("var", ["PROXIMO_RAW_MAX_BYTES", "PROXIMO_RAW_MAX_TOKENS"])
@pytest.mark.parametrize("junk", ["6k", "-7", "lots"])
def test_a_junk_raw_cap_on_a_cut_exec_names_nothing_and_doctor_flags_it(armed_plane, monkeypatch, raw_defaults,
                                                                      var, junk):
    """Junk is doctor's to flag (it is), never a sentence on the answer that could be false on the wire
    (lens 4: 'the default token cap stands' was untrue beside a valid byte cap)."""
    monkeypatch.setenv(var, junk)
    out = _exec(armed_plane, monkeypatch, "r" * 8700, "")
    assert out["data"]["truncated"] == {"stdout": 8700} and "next" not in out["data"]
    assert any(var in f for f in doctor.run()["flags"])


@pytest.mark.parametrize("tokens", ["200", "250", "300", "350", "400", "500", "750"])
def test_a_token_capped_exec_keeps_its_dict_at_every_cap(armed_plane, monkeypatch, raw_defaults, tokens):
    """Lens 3: the first cut of the line named the byte knob on every unset byte cap, and at 200 to 300
    tokens that pushed the whole shell dict out of the envelope: returncode and the truncated counts gone.
    A token cap the operator set is theirs, so no line rides, and the dict is the one the cap allows."""
    monkeypatch.setenv("PROXIMO_RAW_MAX_TOKENS", tokens)
    out = _exec(armed_plane, monkeypatch, _dense(20000, 1), _dense(20000, 2))
    data = out["data"]
    assert isinstance(data, dict) and data["returncode"] == 1
    assert data["truncated"] == {"stdout": 20000, "stderr": 20000}
    assert "next" not in data and "keys" not in out


@pytest.mark.parametrize("env", [{"PROXIMO_RAW_MAX_BYTES": "6k", "PROXIMO_RAW_MAX_TOKENS": "250"},
                                 {"PROXIMO_RAW_MAX_TOKENS": "6k", "PROXIMO_RAW_MAX_BYTES": "320"},
                                 {"PROXIMO_RAW_MAX_BYTES": "6k", "PROXIMO_RAW_MAX_TOKENS": "lots"}])
def test_junk_beside_a_small_valid_cap_keeps_the_dict(armed_plane, monkeypatch, raw_defaults, env):
    """Lens 4: junk on one knob and a small valid value on the other was a default cap WITH a line and no
    room, and the line pushed the dict into a key description. No line rides once either knob is set."""
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    out = _exec(armed_plane, monkeypatch, _dense(20000, 1), _dense(20000, 2))
    data = out["data"]
    assert isinstance(data, dict) and data["returncode"] == 1 and "next" not in data and "keys" not in out
    assert data["truncated"] == {"stdout": 20000, "stderr": 20000}


@pytest.mark.parametrize("rc,out,err,fence,node,vmid,kind,line", [
    (1, "dense", "dense", False, "pve1", "101", "exec", True),
    (255, "dense", "dense", False, "pve1", "101", "exec", True),
    (7, "dense", "dense", False, "pve1", "101", "exec", True),
    (1, "nl", "nl", True, "pve1", "101", "exec", True),
    (7, "nl", "nl", True, "pve1", "101", "exec", True),
    (1, "wide", "wide", True, "pve1", "101", "exec", True),
    (255, "leanw", "leanw", True, "pve1", "101", "exec", False),
    # lens 6: a called path of 29 characters (a nine-character node and vmid 101, or three and 999999999)
    (255, "lean", "lean", True, "naaaaaaaa", "101", "exec", False),
    (255, "lean", "lean", True, "naa", "999999999", "exec", False),
    (255, "leanw", "leanw", True, "naaaaaaaa", "101", "exec", False),
    # lens 7: ONE short token-dense stream beside a cut one, rc 255, no fence: the dict with the line is over
    # the engine's room by a token, and the drop has to run before a description, which always fits, breaks
    (255, "short_upper", "upper", False, "pve1", "101", "exec", False),
    (1, "short_upper", "upper", False, "pve1", "101", "exec", True),
    (255, "upper", "short_upper", False, "pve1", "101", "exec", False),   # (fenced, this cell's BARE dict is described)
    (255, "short_digit", "digit", False, "pve1", "999999999", "exec", True),
    # lens 8: the lane's READ row (the probe) through the same drop; d8e413c tipped it at 148 uppercase chars
    (255, "short_upper148", "upper", False, "pve1", "101", "probe", False),
    (1, "short_upper", "upper", False, "pve1", "101", "probe", True),
])
def test_the_line_never_costs_the_answer_its_dict(armed_plane, monkeypatch, raw_defaults,
                                                  rc, out, err, fence, node, vmid, kind, line):
    """Lens 5: the lane budgets less for the envelope than the engine spends, so a dict inside that band is
    described, and the line was what pushed 41 cells (rc 255's ambiguity text, the taint fence's wrapper)
    into it. Lens 6: with the line dropped only when it was over the room, the engine's shrink step was
    still computed from the with-line body, and seven cells of 441 (every one a called path of 29
    characters) landed the room under the lean dict. Now the engine drops a lane's `next` the moment the
    answer with it is over, by the room or by the cap, and retries the same room, so from there the loop
    runs as the bare one. So whenever the dict without the line keeps its shape through the engine, the
    dict with it keeps its shape too; `line` says whether the line rides in that cell (it does unless the
    dict with it is over the engine's room or the answer with it is over the engine's cap: lens 8), and a
    plant that strips it unconditionally turns the True cells red."""
    bodies = {"dense": _dense(20000, 1), "nl": "ab\n" * 7000, "wide": "\u4e2d" * 20000,
              "lean": "r" * 20000, "leanw": "lean " * 4000, "upper": "A" * 20000, "short_upper": "A" * 125,
              "digit": "7" * 20000, "short_digit": "7" * 125, "short_upper148": "A" * 148}
    if fence:
        monkeypatch.setenv("PROXIMO_TAINT_FENCE", "1")

    def data_of(answer):
        """The lane's dict, out of the taint fence when the row is fenced (the old reader took the fence
        wrapper for the dict and skipped every fenced cell's body: lens 6)."""
        d = answer.get("data")
        if isinstance(d, dict) and d.get("proximo_untrusted") and isinstance(d.get("data"), str):
            return json.loads(d["data"])
        return d

    cell = (rc, out, err, fence, node, vmid, kind)
    got = _exec(armed_plane, monkeypatch, bodies[out], bodies[err], rc=rc, node=node, vmid=vmid, kind=kind)
    monkeypatch.setattr(rawdoor, "raw_cap_line", lambda: None)             # the same cell with no line at all
    bare = _exec(armed_plane, monkeypatch, bodies[out], bodies[err], rc=rc, node=node, vmid=vmid, kind=kind)
    bare_data = data_of(bare)
    assert isinstance(bare_data, dict) and "returncode" in bare_data, cell  # every cell keeps its bare dict
    data = data_of(got)
    assert isinstance(data, dict) and data["returncode"] == rc and data["truncated"], cell
    assert ("next" in data) == line, cell
    if line:
        assert "PROXIMO_RAW_MAX_BYTES" in data["next"]
    assert "keys" not in got                                                # never described because of the line


def test_the_drop_by_the_cap_retries_the_same_room(monkeypatch, raw_defaults):
    """Lens 8: when the dict with the line fits the room but the answer with it is over the cap, the line is
    dropped and the SAME room is tried; a drop that fell through to a shrink computed from the with-line body
    (here 134 tokens off the room instead of 10) put the lean dict under the shrunk room in 40,752 cells of
    1.19M. This is the first of them, the envelope driven as execute drives it: a fenced exec, rc 255, 113
    digits beside a cut digit stream; the dict without the line keeps its shape, so the dict with it must
    too. (Both keeps are the loop's stall exit: the kept fenced answer sits one token over the engine's cap
    at every room, a pre-existing class the byte-only exit never replaces; a change to the stall rule would
    redden this cell for that reason, not the drop's.)"""
    EXEC = "/nodes/pve1/lxc/101/exec"                  # the band moves with the called path's length
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", "1")
    row = engine.resolve("pve", "POST", EXEC)
    result = {"returncode": 255, "stdout": "7" * 113, "stderr": "7" * 20000,
              "exit_ambiguous": "255 is also ssh's own exit: the command started, and either it exited 255 or the "
                                "connection dropped before it finished"}
    with_line = shell._bounded(result)
    assert "next" in with_line and with_line["truncated"] == {"stderr": 20000}
    lean = {k: v for k, v in with_line.items() if k != "next"}        # what the drop hands the same room

    def data_of(answer):
        d = answer.get("data")
        return json.loads(d["data"]) if isinstance(d, dict) and isinstance(d.get("data"), str) else d

    kept = data_of(engine._envelope(row, EXEC, lean))
    assert isinstance(kept, dict) and kept["returncode"] == 255, "the band is wrong: the lean dict must be kept"
    got = data_of(engine._envelope(row, EXEC, with_line))
    assert isinstance(got, dict) and got["returncode"] == 255 and got["truncated"] == {"stderr": 20000}


def test_the_drop_is_the_shell_lanes_alone_a_reads_next_field_is_never_stripped(monkeypatch, raw_defaults):
    """Lens 6 and 7: the drop is scoped to the ssh wire. A vendor read whose dict carries a string `next` and
    is over the room is described whole, as every read is; it never loses that one field silently. The band:
    the dict with `next` is over the room, the dict without it fits (a plant that drops the wire test keeps
    the lean dict here)."""
    row = engine.resolve("pve", "GET", "/nodes/{node}/qemu/{vmid}/config")
    assert row.wire != "ssh"
    lean = {"name": "v" * 720}                      # kept alone from 500 to 800, described with `next` from 640
    data = {**lean, "next": "n" * 160}
    kept = engine._envelope(row, "/nodes/pve1/qemu/100/config", lean)
    assert kept["data"] == lean, "the band is wrong: the lean dict must fit"
    out = engine._envelope(row, "/nodes/pve1/qemu/100/config", data)
    assert "data" not in out and "keys" in out and "next" in out["keys"], out


def test_doctor_reports_the_effective_ceilings_and_flags_a_garbled_one(monkeypatch):
    monkeypatch.setenv(rawdoor.EXIT_ENV, "8192")
    rep = doctor.run()
    assert rep["pillars"]["DIAGNOSE"]["exit_ceilings"] == {"read": 8192, "plan": 8192, "composed": 8192, "refusal": 512}
    assert receipt.allowed(rep)["pillars"]["DIAGNOSE"]["exit_ceilings"]["plan"] == 8192
    monkeypatch.setenv(rawdoor.EXIT_ENV, "lots")
    rep = doctor.run()
    assert rep["pillars"]["DIAGNOSE"]["exit_ceilings"] == DEFAULTS
    flags = [f for f in rep["flags"] if receipt.flag_code(f) == "exit-ceiling-garbled"]
    assert len(flags) == 1 and "lots" not in flags[0]
    monkeypatch.delenv(rawdoor.EXIT_ENV)
    assert doctor.run()["pillars"]["DIAGNOSE"]["exit_ceilings"] == DEFAULTS


# --- through the door: the raw cap below the exit and the exit itself are two knobs ------------------------

class _Wire:
    def __init__(self, body):
        self.body = body

    def call(self, method, path, params=None):
        return self.body


@pytest.fixture
def server(monkeypatch, tmp_path):
    for var in [v for v in os.environ if v.startswith("PROXIMO_") and v != "PROXIMO_ENV_FILE"]:
        monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.invalid:8006/api2/json")
    monkeypatch.setenv("PROXIMO_API_TOKEN_PATH", str(tmp_path / "t"))
    (tmp_path / "t").write_text("x")
    return door.build_server()


def _read(server, monkeypatch, rows):
    import asyncio
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Wire(rows))
    res = asyncio.run(server.call_tool("proximo_read", {"plane": "pve", "path": "/cluster/resources", "fields": "all"}))
    structured = getattr(res, "structured_content", None)
    if structured is None and isinstance(res, tuple):
        structured = res[1]
    return structured


def test_a_read_over_the_old_ceiling_comes_back_whole_only_when_both_knobs_are_raised(server, monkeypatch):
    rows = [{"id": f"lxc/{i}", "name": f"ct-{i:03d}", "status": "running", "node": "pve0"} for i in range(120)]
    assert _bytes(rows) > 3072
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "65536")
    monkeypatch.setenv(rawdoor.EXIT_ENV, "65536")
    out = _read(server, monkeypatch, rows)
    assert "over_cap" not in out and len(out["data"]) == 120 and out.get("truncated") is None
    monkeypatch.delenv(rawdoor.EXIT_ENV)                                    # the raw cap alone is not enough
    out = _read(server, monkeypatch, rows)
    assert out["over_cap"] is True and out["cap"] == 1152 and rawdoor.EXIT_ENV in out["next"]


def test_a_junk_exit_value_never_costs_a_trimmed_read_its_rows(server, monkeypatch):
    """The exit's flag is doctor's and the over-cap answer's; it never rides the raw cap's note on a cut read."""
    rows = [{"id": f"lxc/{i}", "name": f"ct-{i:03d}", "status": "running", "node": "pve0"} for i in range(120)]
    monkeypatch.delenv("PROXIMO_RAW_MAX_BYTES", raising=False)
    monkeypatch.delenv(rawdoor.EXIT_ENV, raising=False)
    before = _read(server, monkeypatch, rows)
    monkeypatch.setenv(rawdoor.EXIT_ENV, "lots")
    after = _read(server, monkeypatch, rows)
    assert "over_cap" not in before and after == before and "lots" not in json.dumps(after)
    assert "cap_problem" not in after and rawdoor.EXIT_ENV not in json.dumps(after)


def test_the_knob_suffix_never_costs_a_fitting_shape_its_fields(monkeypatch):
    """Lens 2: a read's over-cap shape that fits at 1152 without the suffix keeps its fields; the suffix rides
    only when it fits too. Measured against the same shape with the knob set (no suffix) at the same ceiling;
    the sweep crosses the band where the pure shape is (1095, 1152] bytes (every kept scalar at 52 to 57)."""
    def answer(width):
        s = lambda c: c * width  # noqa: E731
        return {"address": s("a"), "plane": "pve", "allowed": True, "needs": s("n"), "tier": s("t"),
                "consent_id": s("c"), "status": s("s"), "intent": s("i"), "ok": True, "incomplete": False,
                "restores": s("r"), "called_path": s("p"), "total": 10 ** 9, "returned": 10, "reason": "R" * 100,
                "undo": {"id": "u" * 24},
                "task": {"status": "x" * 40, "exitstatus": "y" * 40}, **{f"l{i}": [1] * 3 for i in range(8)}}
    dropped_to_floor_while_fitting, crossed = [], False
    for width in range(40, 64):
        monkeypatch.setenv(rawdoor.EXIT_ENV, "65536")                       # the pure shape: no suffix
        pure = rawdoor.over_cap("proximo_read", answer(width), 99999, 1152)
        monkeypatch.delenv(rawdoor.EXIT_ENV)
        got = rawdoor.over_cap("proximo_read", answer(width), 99999, 1152)
        assert _bytes(got) <= 1152
        if _bytes(pure) <= 1152 and "address" in pure and "address" not in got:
            dropped_to_floor_while_fitting.append(width)
        if "address" in got and rawdoor.EXIT_ENV not in got["next"]:
            crossed = True
            with_knob = {**got, "next": got["next"] + "; the operator can raise the exit: " + rawdoor.EXIT_ENV}
            assert _bytes(with_knob) > 1152
    assert dropped_to_floor_while_fitting == [] and crossed                # the band was reached, and held
