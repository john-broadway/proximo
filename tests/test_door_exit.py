"""THE EXIT (round 6, John's ruling): no model-facing answer is ever large, and that does not depend on any
builder being right. Every answer leaves a door as its final serialized bytes; one over its kind's ceiling is
REPLACED by a fixed-shape answer of a few hundred bytes. This file drives hostile inputs through every tool
and asserts the bytes at the exit, plus `proximo-core consent show` (the operator's whole view) and the
bounds on every echo of what a caller sent."""
# ruff: noqa: E501, S311, B023  -- adversarial fixtures: seeded generators and long literal rows are the point
from __future__ import annotations

import asyncio
import json
import os
import random
from dataclasses import dataclass

import pytest

from proximo.core import engine, rawdoor, wire
from proximo.core.doors import cli
from proximo.core.doors import mcp as door
from proximo.core.errors import ProximoError


@dataclass(frozen=True)
class _Cfg(wire.Plane):
    audit_log_path: str = ""
    audit_key_path: str | None = None


class _Wire:
    def __init__(self, body):
        self.body = body

    def call(self, method, path, params=None):
        return self.body(method, path) if callable(self.body) else self.body


@pytest.fixture
def server(monkeypatch, tmp_path):
    for var in [v for v in os.environ if v.startswith("PROXIMO_") and v != "PROXIMO_ENV_FILE"]:
        monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    return door.build_server()


def _call(server, name, args):
    """(text, structured) of an answer, or (the refusal's text, None)."""
    try:
        res = asyncio.run(server.call_tool(name, args))
    except Exception as e:  # noqa: BLE001 -- the SDK wraps a refusal; its text is what the model reads
        return str(e), None
    structured = getattr(res, "structured_content", None)
    if structured is None and isinstance(res, tuple):
        structured = res[1]
    blocks = res if isinstance(res, list) else getattr(res, "content", None) or res[0]
    return blocks[0].text, structured


CEIL = rawdoor.CEILINGS


# --- the exit, unit ----------------------------------------------------------------------------------------

def test_the_ceilings_are_pinned():
    assert CEIL == {"read": 1152, "plan": 2048, "composed": 3072, "refusal": 512}


def test_an_answer_under_its_ceiling_leaves_terse_and_otherwise_whole():
    a = {"address": "GET /x", "plane": "pve", "access": "read", "derived": False, "untrusted": False,
         "tier": None, "needs": None, "withheld": [], "matched_path": "/x", "called_path": "/x", "data": [1, 2],
         "allowed": False, "incomplete": False}
    out = rawdoor.finish("proximo_read", a)
    assert out == {"address": "GET /x", "plane": "pve", "access": "read", "called_path": "/x", "data": [1, 2],
                   "allowed": False, "incomplete": False}                       # a false verdict is never dropped


@pytest.mark.parametrize(("tool", "answer", "kind"), [
    ("proximo_plan", {"address": "PUT /x", "allowed": True, "consent_id": "c" * 64, "arguments": {"a": "z" * 9000}}, "plan"),
    ("proximo_call", {"address": "PUT /x", "allowed": False, "needs": "arm", "reason": "r" * 900, "current": "q" * 9000}, "plan"),
    ("proximo_read", {"address": "GET /x", "plane": "pve", "total": 900, "data": [{"k": "v" * 80}] * 900}, "read"),
    ("proximo_find", {"matches": [{"path": "/p" * 40}] * 400}, "read"),
    ("proximo_read", {"battery": {"a": {"rows": ["x" * 90] * 400}}, "flags": ["f" * 80] * 100}, "composed"),
])
def test_one_over_its_ceiling_is_replaced_by_the_fixed_shape(tool, answer, kind):
    out = rawdoor.finish(tool, answer)
    assert out["over_cap"] is True and out["cap"] == CEIL[kind] and out["bytes"] > CEIL[kind]
    assert len(json.dumps(out, separators=(",", ":"), ensure_ascii=False).encode()) < 600
    assert set(out) <= {"over_cap", "bytes", "cap", "address", "plane", "allowed", "needs", "tier", "consent_id",
                        "status", "intent", "ok", "incomplete", "restores", "called_path", "total", "returned",
                        "reason", "undo", "task", "counts", "next"}


def test_the_replacement_keeps_the_verdict_the_id_the_counts_and_one_fixed_line():
    cid = "ab" * 32
    out = rawdoor.finish("proximo_plan", {"address": "PUT /x", "allowed": True, "needs": None, "consent_id": cid,
                                          "reason": "ok", "arguments": {f"k{i}": "v" * 300 for i in range(40)},
                                          "not_shown_whole": [f"k{i}" for i in range(40)]})
    assert out["allowed"] is True and out["consent_id"] == cid and out["counts"] == {"arguments": 40, "not_shown_whole": 40}
    assert out["next"] == f"the full plan is for the operator: proximo-core consent show {cid}"
    no_id = rawdoor.finish("proximo_plan", {"address": "PUT /x", "allowed": False, "arguments": {"a": "z" * 3000}})
    assert "proximo-core <plane> <METHOD> <path> --plan" in no_id["next"]
    read = rawdoor.finish("proximo_read", {"address": "GET /x", "total": 900, "data": ["x" * 90] * 100})
    assert read["total"] == 900 and read["counts"] == {"data": 100} and read["next"].startswith("narrow:")


def test_an_executed_mutation_that_is_over_the_ceiling_still_says_what_ran():
    out = rawdoor.finish("proximo_call", {"address": "POST /x", "allowed": True, "intent": "i" * 12, "status": "ok",
                                          "undo": {"id": "abc123def456", "before": "b" * 9000},
                                          "task": {"status": "ok", "exitstatus": "OK", "log": ["l" * 90] * 99},
                                          "data": "d" * 9000})
    assert out["over_cap"] and out["undo"] == "abc123def456" and out["task"] == {"status": "ok", "exitstatus": "OK"}
    assert out["intent"] == "i" * 12 and out["status"] == "ok"


def test_the_exit_ceiling_per_kind_is_chosen_by_tool_and_shape():
    assert rawdoor.kind_of("proximo_plan", {}) == "plan" and rawdoor.kind_of("proximo_call", {}) == "plan"
    assert rawdoor.kind_of("proximo_read", {"battery": {}}) == "composed"
    assert rawdoor.kind_of("proximo_find", {}) == "read" and rawdoor.kind_of("audit_entries", {}) == "read"


def test_a_refusal_is_cut_to_its_ceiling_with_its_length():
    out = rawdoor.refusal_text("w" * 5000)
    assert len(out.encode()) <= CEIL["refusal"] and "(5000 chars, sha256:" in out and rawdoor.refusal_text("short") == "short"


# --- the exit, property: hostile input through every tool ------------------------------------------------------

def _rng_text(rng, n):
    pools = ["0123456789", "abcdefghij", "ABCDEFGHIJKLMNOP", "日本語のテキスト", "\U0001f680\U0001f525", "%2F%3A%40", "{}[]()<>,.;:-=+"]
    return "".join(rng.choice(rng.choice(pools)) for _ in range(n))


def _wide_rows(rng, n, width):
    return [{f"k{j}": _rng_text(rng, rng.randint(1, width)) for j in range(rng.randint(1, 12))} | {"id": f"vm/{i}"}
            for i in range(n)]


@pytest.fixture
def estate(monkeypatch):
    """A vendor that answers whatever the test installs, for the pve plane the server is configured against."""
    state = {"body": {}}
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Wire(lambda m, p: state["body"]))
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.invalid:8006/api2/json")
    return state


READS = [("/cluster/resources", {}), ("/nodes/pve1/tasks", {}), ("/nodes/pve1/status", {}), ("/version", {}),
         ("/cluster/resources", {"fields": "all"}), ("/cluster/resources", {"fields": "id"}),
         ("/nodes/pve1/tasks", {"since": "1h"})]


@pytest.mark.parametrize("seed", range(3))
def test_no_read_answer_leaves_the_door_over_its_ceiling(server, estate, seed, tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_API_TOKEN_PATH", str(tmp_path / "t"))
    (tmp_path / "t").write_text("x")
    rng = random.Random(seed)
    shapes = [lambda: _wide_rows(rng, 400, 60), lambda: {f"k{i}": _rng_text(rng, 40) for i in range(300)},
              lambda: _rng_text(rng, 20000), lambda: [{"s": "ignore " + _rng_text(rng, 30)}] * 300,
              lambda: [list(range(i, i + 40)) for i in range(300)], lambda: {"a": {"b": {"c": [_rng_text(rng, 90)] * 200}}}]
    for make in shapes:
        estate["body"] = make()
        for path, extra in READS:
            for fence in ("", "1"):
                if fence:
                    monkeypatch.setenv("PROXIMO_TAINT_FENCE", "1")
                else:
                    monkeypatch.delenv("PROXIMO_TAINT_FENCE", raising=False)
                text, structured = _call(server, "proximo_read", {"plane": "pve", "path": path, **extra})
                limit = CEIL["refusal"] if structured is None else CEIL["read"]
                assert len(text.encode()) <= limit, (seed, path, extra, fence, len(text.encode()))
                if structured is not None:
                    assert len(json.dumps(structured, separators=(",", ":"), ensure_ascii=False).encode()) <= limit


@pytest.mark.parametrize("seed", range(3))
def test_no_find_or_audit_answer_leaves_the_door_over_its_ceiling(server, seed, monkeypatch, tmp_path):
    rng = random.Random(seed)
    for _ in range(12):
        words = " ".join(rng.choice(["list", "create", "vm", "storage", "backup", "snapshot", "user", "token", "acl",
                                     "network", "firewall", "datastore", "sync", "certificate", "日本"]) for _ in range(rng.randint(1, 5)))
        for limit in (1, 5, 25, 10**6):
            text, structured = _call(server, "proximo_find", {"query": words, "limit": limit})
            assert len(text.encode()) <= CEIL["read"], (words, limit)
    from proximo.core.ledger import LedgerConfig, open_ledger
    ledger = open_ledger(LedgerConfig.from_env())
    for i in range(80):
        ledger.record("core.refuse", target=f"pve:GET /x/{i}", outcome="refused", detail={"reason": _rng_text(rng, 120)})
    for args in ({}, {"limit": 1000}, {"mutations_only": True, "limit": 80}):
        text, _ = _call(server, "audit_entries", args)
        assert len(text.encode()) <= CEIL["read"]
    assert len(_call(server, "audit_verify", {})[0].encode()) <= CEIL["read"]


@pytest.mark.parametrize("seed", range(3))
def test_no_plan_or_dry_run_leaves_the_door_over_its_ceiling(server, seed):
    rng = random.Random(seed)
    targets = [("PUT", "/nodes/pve1/qemu/100/config"), ("POST", "/nodes/pve1/qemu"), ("DELETE", "/nodes/pve1/qemu/100"),
               ("POST", "/nodes/pve1/lxc"), ("PUT", "/access/acl"), ("POST", "/storage"), ("POST", "/nodes/pve1/qemu/100/status/stop")]
    for method, path in targets:
        row = engine.resolve("pve", method, path)
        names = [n for n in row.params if "[" not in n]
        for make in (lambda: {n: _rng_text(rng, 500) for n in names[:60]},
                     lambda: {f"bogus{i}": _rng_text(rng, 300) for i in range(2000)},
                     lambda: {n: "9" * 400 for n in names[:40]},
                     lambda: {n: {"a": [_rng_text(rng, 90)] * 20} for n in names[:20]},
                     lambda: {n: _rng_text(rng, 3) for n in names[:200]},
                     lambda: {"description": "‮" * 600}):
            for tool, extra in (("proximo_plan", {}), ("proximo_call", {"confirm": False}), ("proximo_call", {"confirm": True})):
                text, structured = _call(server, tool, {"plane": "pve", "method": method, "path": path, "args": make(), **extra})
                limit = CEIL["refusal"] if structured is None else CEIL["plan"]
                assert len(text.encode()) <= limit, (tool, method, path, len(text.encode()))
                if structured is not None:
                    assert len(json.dumps(structured, separators=(",", ":"), ensure_ascii=False).encode()) <= limit
        text, _ = _call(server, "proximo_plan", {"plane": "pve", "method": method, "path": path, "fields": "all"})
        assert len(text.encode()) <= CEIL["plan"]


def test_a_huge_vendor_record_behind_a_plan_is_still_under_the_ceiling(server, estate, tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_API_TOKEN_PATH", str(tmp_path / "t"))
    (tmp_path / "t").write_text("x")
    rng = random.Random(1)
    estate["body"] = {f"net{i}": _rng_text(rng, 200) for i in range(80)} | {"description": "d" * 20000}
    text, structured = _call(server, "proximo_plan", {"plane": "pve", "method": "PUT", "path": "/nodes/pve1/qemu/100/config",
                                                       "args": {"memory": 4096, "description": "z" * 5000}})
    assert len(text.encode()) <= CEIL["plan"]


def test_no_diagnosis_leaves_the_door_over_its_ceiling(server, estate, tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_API_TOKEN_PATH", str(tmp_path / "t"))
    (tmp_path / "t").write_text("x")
    rng = random.Random(3)

    def vendor(method, path):
        if path.endswith("/storage"):
            return [{"storage": f"nfs-{i}", "type": "nfs", "active": 0, "enabled": 1, "content": _rng_text(rng, 60)}
                    for i in range(120)]
        if path.endswith("/tasks"):
            return [{"upid": f"UPID:n:{i:08X}:1:2:vzdump:{i}:root@pam:", "type": "vzdump", "status": _rng_text(rng, 900)}
                    for i in range(80)]
        return {"uptime": 5, "cpu": 0.1, "loadavg": ["0.1"], "memory": {"used": 1, "total": 2}}
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Wire(vendor))
    text, structured = _call(server, "proximo_read", {"plane": "pve", "path": "/nodes/pve1", "diagnose": True})
    assert len(text.encode()) <= CEIL["composed"]


def test_a_refusal_is_bounded_whatever_the_cause(server):
    for tool, args in (("proximo_nope" * 5000, {}), ("proximo_read", {"plane": "pve", "path": "/x", **{f"bad{i}": 1 for i in range(1000)}}),
                       ("proximo_read", {"plane": "pve", "path": "/" + "a" * 50000}),
                       ("proximo_plan", {"plane": "pve", "method": "Z" * 60000, "path": "/x"}),
                       ("proximo_call", {"plane": "pve", "method": "undo", "path": "f" * 60000}),
                       ("audit_verify", {"path": "Z" * 60000}), ("proximo_find", {"query": "", "plane": "x" * 60000})):
        text, structured = _call(server, tool, args)
        assert structured is None and len(text.encode()) <= CEIL["refusal"], (tool[:20], len(text.encode()))


def test_an_undeclared_argument_is_one_fixed_sentence_and_at_most_three_names(server):
    text, _ = _call(server, "proximo_read", {"plane": "pve", "path": "/version", **{f"bad{i}": "z" * 200 for i in range(1000)}})
    assert text.startswith("Error executing tool proximo_read: unexpected arguments: bad") and "(and 997 more)" in text
    assert len(text) < 200 and "zzzz" not in text
    text, _ = _call(server, "proximo_read", {"plane": "pve", "path": "/version", "fields": 5})
    assert "invalid arguments: fields" in text


def test_the_unknown_tool_is_cut_on_the_mcp_door_and_on_the_dispatch_door():
    from proximo.core.doors import dispatch
    from proximo.core.mcpcompat import make_server
    srv = make_server("t", "0")
    with pytest.raises(Exception) as e:
        asyncio.run(srv.call_tool("x" * 90000, {}))
    assert len(str(e.value).encode()) <= CEIL["refusal"]
    with pytest.raises(dispatch.DispatchError) as d:
        asyncio.run(dispatch.call_on(door.build_server(), "y" * 90000, {}))
    assert len(d.value.message) < 100 and d.value.status == 404


# --- consent show: the operator's whole view -----------------------------------------------------------------------

def _refused_call(armed_plane, tmp_path, monkeypatch, args, method="PUT", tmpl="/nodes/{node}/qemu/{vmid}/config",
                  path="/nodes/pve1/qemu/100/config"):
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(tmp_path / "grants"))
    (tmp_path / "grants").mkdir(exist_ok=True)
    row = engine.Row(**{**engine.resolve("pve", method, tmpl).__dict__, "tier": "read-back"})
    plan = engine.plan(row, args, path, cfg=armed_plane)
    with pytest.raises(ProximoError):
        engine.execute(row, args, cfg=armed_plane, path=path)
    return plan["consent_id"]


def test_consent_show_prints_every_value_whole_as_typed_json_and_reproduces_the_id(armed_plane, tmp_path, monkeypatch, capsys):
    args = {"args": "x" * 300 + " -chardev socket,path=/etc/shadow ATTACKER", "memory": 4096, "onboot": True,
            "delete": None, "net0": {"model": "virtio", "tag": 7}}
    cid = _refused_call(armed_plane, tmp_path, monkeypatch, args)
    assert cli.main(["consent", "show", cid]) == cli.EXIT_OK
    shown = json.loads(capsys.readouterr().out)
    assert shown["args"] == args                                   # whole, and int/bool/None/dict as typed
    assert shown["consent_id"] == cid and shown["reproduces_id"] is True and shown["fingerprinted"] == []
    assert shown["address"] == "PUT /nodes/{node}/qemu/{vmid}/config" and shown["called"] == "/nodes/pve1/qemu/100/config"
    assert cli.main(["consent", "show", cid[:12]]) == cli.EXIT_OK                     # a unique prefix is enough


def test_the_model_sees_names_and_hashes_and_the_operator_sees_the_values(armed_plane, tmp_path, monkeypatch, capsys):
    tail = " -chardev socket,path=/etc/shadow ATTACKER"
    args = {"args": "x" * 300 + tail}
    cid = _refused_call(armed_plane, tmp_path, monkeypatch, args)
    row = engine.Row(**{**engine.resolve("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config").__dict__, "tier": "read-back"})
    plan = engine.plan(row, args, "/nodes/pve1/qemu/100/config", cfg=armed_plane)
    assert tail not in json.dumps(plan) and plan["operator_view"] == f"proximo-core consent show {cid}"
    cli.main(["consent", "show", cid])
    assert tail in capsys.readouterr().out


def test_a_secret_stays_a_fingerprint_and_show_says_the_id_cannot_be_recomputed(armed_plane, tmp_path, monkeypatch, capsys):
    cid = _refused_call(armed_plane, tmp_path, monkeypatch, {"cipassword": "hunter2hunter2", "memory": 1},
                        method="PUT", tmpl="/nodes/{node}/qemu/{vmid}/config")
    cli.main(["consent", "show", cid])
    out = capsys.readouterr().out
    shown = json.loads(out)
    assert "hunter2" not in out and shown["fingerprinted"] == ["cipassword"] and shown["reproduces_id"] is False


def test_a_forged_row_is_refused_and_an_unknown_id_is_refused(armed_plane, tmp_path, monkeypatch, capsys):
    cid = _refused_call(armed_plane, tmp_path, monkeypatch, {"memory": 4096})
    log = tmp_path / "proximo-test-audit.log"
    path = pathlib_log(monkeypatch)
    text = path.read_text().replace('"memory":4096', '"memory":1').replace('"memory": 4096', '"memory": 1')
    path.write_text(text)
    assert cli.main(["consent", "show", cid]) == cli.EXIT_REFUSED
    assert "does not reproduce" in capsys.readouterr().err
    assert cli.main(["consent", "show", "0" * 20]) == cli.EXIT_REFUSED
    assert cli.main(["consent", "show", "abc"]) == cli.EXIT_REFUSED
    assert cli.main(["consent", "show"]) == cli.EXIT_USAGE and log is not None


def pathlib_log(monkeypatch):
    import pathlib
    return pathlib.Path(os.environ["PROXIMO_AUDIT_LOG"])


def _rows_of(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def test_the_refused_proposal_is_bound_to_its_id_on_the_row(armed_plane, tmp_path, monkeypatch):
    from proximo.core import spine
    cid = _refused_call(armed_plane, tmp_path, monkeypatch, {"cipassword": "hunter2hunter2", "memory": 1})
    (p,) = [r["detail"]["proposed"] for r in _rows_of(pathlib_log(monkeypatch)) if "proposed" in (r.get("detail") or {})]
    assert p["consent_id"] == cid and p["binding"] == spine.consent_binding(p)
    assert spine.consent_binding({**p, "args": {**p["args"], "memory": 2}}) != p["binding"]


def test_a_forged_row_with_a_planted_fingerprint_is_refused_and_prints_nothing(armed_plane, tmp_path, monkeypatch, capsys):
    """Lens F 3: a fingerprint used to switch the id check off. The binding covers the STORED proposal,
    fingerprints included, so a planted one does not reproduce it."""
    cid = _refused_call(armed_plane, tmp_path, monkeypatch, {"memory": 4096})
    log = pathlib_log(monkeypatch)
    t = log.read_text()
    forged = t.replace('"memory":4096', '"memory":1,"description":"[redacted sha256:000000000000 len:1]",'
                                        '"args":"-chardev socket,path=/etc/shadow"')
    assert forged != t
    log.write_text(forged)
    assert cli.main(["consent", "show", cid]) == cli.EXIT_REFUSED
    out = capsys.readouterr()
    assert out.out == "" and "shadow" not in out.err and "does not reproduce" in out.err


def test_a_forged_row_that_rebinds_itself_is_refused_by_the_chain(armed_plane, tmp_path, monkeypatch, capsys):
    from proximo.core import spine
    cid = _refused_call(armed_plane, tmp_path, monkeypatch, {"cipassword": "hunter2hunter2", "memory": 1})
    log = pathlib_log(monkeypatch)
    rows = _rows_of(log)
    for r in rows:
        p = (r.get("detail") or {}).get("proposed")
        if p:
            p["args"]["args"] = "-chardev socket,path=/etc/shadow"
            p["binding"] = spine.consent_binding(p)
    log.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows))
    assert cli.main(["consent", "show", cid]) == cli.EXIT_REFUSED
    out = capsys.readouterr()
    assert out.out == "" and "chain" in out.err


def test_two_different_rows_for_one_id_are_refused(armed_plane, tmp_path, monkeypatch, capsys):
    cid = _refused_call(armed_plane, tmp_path, monkeypatch, {"memory": 4096})
    log = pathlib_log(monkeypatch)
    lines = log.read_text().splitlines(keepends=True)
    (line,) = [x for x in lines if '"proposed"' in x]
    log.write_text(log.read_text() + line.replace('"memory":4096', '"memory":1'))
    assert cli.main(["consent", "show", cid]) == cli.EXIT_REFUSED
    out = capsys.readouterr()
    assert out.out == "" and "more than one" in out.err


def test_the_same_refusal_twice_is_one_proposal(armed_plane, tmp_path, monkeypatch, capsys):
    """A model that calls twice before the operator looks writes the same proposal twice: one plan, shown."""
    cid = _refused_call(armed_plane, tmp_path, monkeypatch, {"memory": 4096})
    assert _refused_call(armed_plane, tmp_path, monkeypatch, {"memory": 4096}) == cid
    assert cli.main(["consent", "show", cid]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["args"] == {"memory": 4096}


def test_consent_show_escapes_what_could_reorder_the_operators_terminal(armed_plane, tmp_path, monkeypatch, capsys):
    """Lens F 4: a U+202E in an argument reordered what the operator read before approving."""
    cid = _refused_call(armed_plane, tmp_path, monkeypatch, {"description": "safe \u202eSWODNIW\u202c ok\x1b[2J"})
    assert cli.main(["consent", "show", cid]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "\u202e" not in out and "\x1b" not in out and "\\u202e" in out


def test_only_a_refused_mutation_writes_the_proposal_and_a_plan_writes_nothing(armed_plane, tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(tmp_path / "grants"))
    row = engine.Row(**{**engine.resolve("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config").__dict__, "tier": "read-back"})
    engine.plan(row, {"memory": 1}, "/nodes/pve1/qemu/100/config", cfg=armed_plane)
    assert not pathlib_log(monkeypatch).exists() or "proposed" not in pathlib_log(monkeypatch).read_text()


# --- what an echo cannot hide (lens 5 S2, S3) ------------------------------------------------------------------

#: the characters that smuggle: reorder or hide what a person reads. By Unicode category (Cf, Zl, Zp, Cs, Cc) the
#: echo escapes them; this is the known list, kept so a category change that dropped one is a red test.
SMUGGLERS = ["‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩", "​",
             "‌", "‍", "‎", "‏", "⁠", "﻿", "؜", "­", "᠎", " ",
             " ", "\U000e0041", "\U000e007f", "\x1b", "\x07", "\x7f", "\ud800", "\udfff"]


@pytest.mark.parametrize("ch", SMUGGLERS, ids=[f"U+{ord(c):04X}" for c in SMUGGLERS])
def test_a_smuggling_character_is_shown_as_an_escape_at_any_depth(ch):
    for shown in (rawdoor.echo("a" + ch + "b"), rawdoor.echo(ch + "x" * 100),
                  json.dumps(rawdoor.echo_value({"k" + ch: ["v" + ch, {"n": "w" + ch}]}), ensure_ascii=False)):
        assert ch not in shown and "\\" in shown


def test_ordinary_text_newline_and_tab_are_left_alone():
    assert rawdoor.echo("tab\there\nand, é, 日本語, ünï") == "tab\there\nand, é, 日本語, ünï"


def test_nested_values_in_a_plan_are_escaped_too(armed_plane):
    row = engine.Row(**{**engine.resolve("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config").__dict__, "tier": "read-back"})
    out = engine.plan(row, {"args": {"k": ["‮evil"]}}, "/nodes/pve1/qemu/100/config", cfg=armed_plane)
    assert "‮" not in json.dumps(out, ensure_ascii=False) and "\\u202e" in json.dumps(out)


# --- the digits of a name are ASCII (S5) ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["net１", "net١", "net۱", "netᵽ9"])
def test_a_non_ascii_digit_is_not_an_indexed_parameter(name):
    row = engine.resolve("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config")
    assert engine._published(row, "net1") == "net[n]" and engine._published(row, name) is None


def test_the_other_regexes_in_the_door_are_ascii_only():
    import re

    from proximo.core import diagnose, store, undo
    assert re.fullmatch(store.__dict__["re"].escape("x"), "x")
    with pytest.raises(ProximoError):
        store.parse_since("１０m")
    assert undo._REDACTED.fullmatch("[redacted sha256:0123456789ab len:12]")
    assert undo._REDACTED.fullmatch("[redacted sha256:0123456789ab len:１２]") is None
    assert diagnose._grouped([f"storage ｓ{i} is inactive" for i in range(7)])[0].startswith("7 storages")


# --- the boundaries of what a plan shows (S7: E1, E2, E3, E16) --------------------------------------------------------

def test_a_string_of_48_is_shown_and_of_49_is_a_hash(armed_plane):
    row = engine.Row(**{**engine.resolve("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config").__dict__, "tier": "read-back"})
    path = "/nodes/pve1/qemu/100/config"
    at = engine.plan(row, {"description": "d" * 48}, path, cfg=armed_plane)
    over = engine.plan(row, {"description": "d" * 49}, path, cfg=armed_plane)
    assert at["arguments"]["description"] == "d" * 48 and "not_shown_whole" not in at
    assert over["arguments"]["description"].startswith("[49 chars sha256:") and over["not_shown_whole"] == ["description"]


def test_a_nested_value_of_48_compact_bytes_is_shown_and_of_49_is_listed(armed_plane):
    row = engine.Row(**{**engine.resolve("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config").__dict__, "tier": "read-back"})
    path = "/nodes/pve1/qemu/100/config"
    fit = {"k": "v" * 40}                                       # {"k":"vvv..."} is 48 bytes compact
    assert len(json.dumps(fit, separators=(",", ":"))) == 48
    at = engine.plan(row, {"args": fit}, path, cfg=armed_plane)
    over = engine.plan(row, {"args": {"k": "v" * 41}}, path, cfg=armed_plane)
    assert at["arguments"]["args"] == fit and "not_shown_whole" not in at
    assert over["arguments"]["args"].startswith("[49 chars sha256:") and over["not_shown_whole"] == ["args"]


def test_the_48th_name_is_shown_and_the_49th_is_counted(armed_plane):
    row = engine.Row(**{**engine.resolve("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config").__dict__, "tier": "read-back"})
    exact = engine.plan(row, {f"a{i}": i for i in range(48)}, "/nodes/pve1/qemu/100/config", cfg=armed_plane)
    assert len(exact["arguments"]) == 48 and "arguments_more" not in exact
    one = engine.plan(row, {f"a{i}": i for i in range(49)}, "/nodes/pve1/qemu/100/config", cfg=armed_plane)
    assert len(one["arguments"]) == 48 and one["arguments_more"] == 1


def test_a_number_that_is_not_one_is_refused_without_echoing_it():
    row = engine.resolve("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config")
    int_param = next(n for n, sp in row.params.items() if sp.get("type") == "integer")
    with pytest.raises(ProximoError) as e:
        engine.coerce_args(row, {int_param: "9" * 5000 + "x"})
    assert len(str(e.value)) < 300 and "(5001 chars" in str(e.value)
    with pytest.raises(ProximoError) as e:
        engine.coerce_args(row, {int_param: "x" * 100})
    assert "x" * 100 not in str(e.value) and "(100 chars, sha256:" in str(e.value)


def test_the_not_shown_keys_survive_every_trim_with_values_that_would_be_trim_candidates():
    keep = {"arguments": {"a": "b" * 200}, "not_shown_whole": [f"name{i}" * 12 for i in range(20)],
            "operator_view": "proximo-core consent show " + "c" * 64, "required_missing": ["r" * 90] * 5}
    out = rawdoor.fit_answer({**keep, "current": {f"k{i}": "v" * 100 for i in range(80)}, "extra": "e" * 3000})
    assert all(out[k] == v for k, v in keep.items()) and {"current", "extra"} <= set(out["trimmed"])
    assert all(rawdoor._size_of(v) > 60 for v in keep.values())          # each WOULD be a trim candidate if unprotected


# --- the undo plan is the exit's too (S4) ------------------------------------------------------------------------

def test_an_undo_plan_sized_by_the_vendors_record_is_under_the_plan_ceiling(armed_plane, tmp_path, monkeypatch):
    from proximo.core import undo
    big = {f"net{i}": f"virtio=AA:BB:CC:DD:EE:{i:02X},bridge=vmbr0,firewall=1" + "x" * 180 for i in range(22)}
    out = undo._fit({"status": "plan", "restores": "abcd1234", "address": "PUT /x", "allowed": True,
                     "arguments": {k: v for k, v in big.items()}})
    final = rawdoor.finish("proximo_call", out)
    assert len(json.dumps(final, separators=(",", ":")).encode()) <= CEIL["plan"] and final.get("restores") == "abcd1234"


# --- survivors of the round's planted controls --------------------------------------------------------------------

def test_a_refusal_from_a_tool_body_is_cut_at_the_exit_whatever_its_builder_did():
    from proximo.core.mcpcompat import make_server

    def boom() -> dict:
        raise ProximoError("w" * 5000)
    srv = make_server("t", "0")
    srv.tool(name="boom")(boom)
    with pytest.raises(Exception) as e:
        asyncio.run(srv.call_tool("boom", {}))
    assert len(str(e.value).encode()) <= CEIL["refusal"] and "(5000 chars, sha256:" in str(e.value)


def test_audit_entries_does_not_say_where_the_ledger_lives(server):
    from proximo.core.ledger import LedgerConfig, open_ledger
    open_ledger(LedgerConfig.from_env()).record("core.refuse", target="pve:GET /x", outcome="refused", detail={})
    _, structured = _call(server, "audit_entries", {})
    assert structured is not None and "path" not in structured and "source" not in structured and structured["entries"]


def test_a_consent_prefix_under_eight_characters_is_refused(armed_plane, tmp_path, monkeypatch, capsys):
    cid = _refused_call(armed_plane, tmp_path, monkeypatch, {"memory": 4096})
    assert cli.main(["consent", "show", cid[:7]]) == cli.EXIT_REFUSED and "at least 8" in capsys.readouterr().err
    assert cli.main(["consent", "show", cid[:8]]) == cli.EXIT_OK


def test_the_1x_branch_seals_too():
    """mcp 1.x is not installed here, so its branch of `make_server` cannot run; this pins that it is wired."""
    import inspect

    from proximo.core import mcpcompat
    src = inspect.getsource(mcpcompat.make_server)
    assert "seal_result(str(args[0]) if args else" in src and "seal_result(name, await super().call_tool" in src
