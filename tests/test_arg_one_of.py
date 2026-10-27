"""records/args.toml: a call that must name at least one of a set of parameters (capability
`ceph-zero-flags-guard`).

0.44's CHANGELOG carried it as a security finding: "a zero-flags call that silently fired a real
Ceph worker task". `PUT /cluster/ceph/flags` publishes eleven optional flags and requires none, so
the vendor accepts the empty call and starts a worker task that changes nothing. Bar 4 leaves
argument judgement to the vendor, and the vendor said yes; so the refusal is authored, on the
address, with its why. It reads the call's own arguments and nothing else, so it is judged the
same armed, unarmed or with no credential at all.

PRESENCE, NOT TRUTH: `noout=0` clears a flag and is a real change; only a call that names none of
them is refused.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from proximo.core import engine
from proximo.core.errors import ProximoError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import build_proximo_json as bj  # noqa: E402

FLAGS = "/cluster/ceph/flags"
KEY = ("pve", "PUT", FLAGS)
ELEVEN = ["nobackfill", "nodeep-scrub", "nodown", "noin", "noout", "norebalance", "norecover", "noscrub",
          "notieragent", "noup", "pause"]


class Wire:
    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        return None if method == "PUT" else []


def _rows() -> list[dict]:
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


# --- the shipped line -------------------------------------------------------------------------

def test_the_ceph_flags_put_carries_the_rule_over_every_flag_it_publishes():
    row = engine.table()[KEY]
    assert sorted(row.one_of["names"]) == ELEVEN
    # the line names every parameter the address publishes: a flag Proxmox adds later is a red here
    assert sorted(row.params) == ELEVEN
    assert "worker task" in row.one_of["why"]
    # the single-flag address requires its flag and its value already: no rule there
    assert engine.table()[("pve", "PUT", "/cluster/ceph/flags/{flag}")].one_of is None
    assert sum(r.one_of is not None for r in engine.table().values()) == 1


# --- the plan --------------------------------------------------------------------------------

def test_the_plan_of_an_empty_flags_call_says_no_with_no_credential(monkeypatch):
    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_TOKEN_PATH"):
        monkeypatch.delenv(var, raising=False)
    out = engine.plan(engine.table()[KEY], {}, FLAGS)
    assert out["allowed"] is False and out["needs"] == "arguments"
    assert "at least one of" in out["reason"] and "noout" in out["reason"]


def test_the_plan_of_an_empty_flags_call_says_no_when_armed_too(armed_plane, monkeypatch):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Wire())
    out = engine.plan(engine.table()[KEY], {}, FLAGS, cfg=armed_plane)
    assert (out["allowed"], out["needs"]) == (False, "arguments")


@pytest.mark.parametrize("args", [{"noout": 1}, {"noout": 0}, {"noout": False}, {"pause": "false"},
                                  {"noout": 1, "nodown": 1}])
def test_a_call_naming_a_flag_is_planned_allowed_whatever_its_value(armed_plane, monkeypatch, args):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Wire())
    out = engine.plan(engine.table()[KEY], args, FLAGS, cfg=armed_plane)
    assert out["allowed"] is True, out["reason"]


# --- the call --------------------------------------------------------------------------------

@pytest.mark.parametrize("args", [{}, {"noout": None}, {"noout": ""}, {"noout": "  "}])
def test_an_empty_flags_call_is_refused_before_the_wire_and_receipted(armed_plane, monkeypatch, args):
    w = Wire()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    with pytest.raises(ProximoError, match="at least one of"):
        engine.execute(engine.table()[KEY], args, cfg=armed_plane, path=FLAGS)
    assert not any(m == "PUT" for m, _, _ in w.calls)                       # nothing was sent
    refused = [r for r in _rows() if r["action"] == "core.refuse"]
    assert refused and refused[-1]["detail"]["needs"] == "arguments"
    assert not any(r["outcome"] == "executing" for r in _rows())            # and nothing was opened


@pytest.mark.parametrize("args", [{"noout": 1}, {"noout": 0}, {"pause": False}])
def test_a_call_naming_a_flag_reaches_the_wire(armed_plane, monkeypatch, args):
    w = Wire()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    engine.execute(engine.table()[KEY], args, cfg=armed_plane, path=FLAGS)
    assert [m for m, p, _ in w.calls if m == "PUT" and p == FLAGS] == ["PUT"]


# --- the build and the loader ----------------------------------------------------------------

_WHY = "Vendor: the call is accepted with no flags and starts a worker task"


def _line(addr="pve:PUT /cluster/ceph/flags", **fields):
    one = {"names": ["noout", "pause"], "why": _WHY, **fields}
    body = ", ".join(f"{k} = {json.dumps(v)}" for k, v in one.items() if v is not ...)
    return f'[one_of]\n"{addr}" = {{ {body} }}\n'


@pytest.mark.parametrize("line,words", [
    (_line("pve:PUT /cluster/ceph/nowhere"), "matches no published address"),
    (_line("pve:GET /cluster/ceph/flags"), "is not a mutation the door serves"),
    (_line(names=["nonesuch"]), "names nonesuch, which the address does not publish"),
    (_line(names=[]), "names no parameter"),
    (_line(names=["noout", "noout"]), "names a parameter twice"),
    (_line(names="noout"), "names are a list of parameter names"),
    (_line(why="short"), "is without a why"),
    (_line(why=" " + _WHY), "carries a why with space around it"),
    (_line(names=...), "takes exactly names and why"),
    (_line(extra=1), "takes exactly names and why"),
    (_line("pve:PUT /nodes/{node}/qemu/{vmid}/config", names=["node"]), "names node, which the path binds"),
])
def test_the_build_refuses_a_line_that_would_do_nothing_or_mislead(records, line, words):
    with pytest.raises(ProximoError, match=f"args.toml: .*{words}"):
        records(**{"args.toml": line})


def test_no_record_no_rule(records):
    assert not any(r.one_of for r in records(**{"args.toml": None}).values())


def test_a_planted_line_rides_its_row_and_refuses(records, armed_plane, monkeypatch):
    table = records(**{"args.toml": _line("pve:PUT /cluster/options", names=["keyboard", "language"])})
    row = table[("pve", "PUT", "/cluster/options")]
    assert row.one_of["names"] == ("keyboard", "language")
    with pytest.raises(ProximoError, match="at least one of keyboard, language"):
        engine.check_args(row, {})
    assert engine.check_args(row, {"language": "en"}) == {"language": "en"}


def _shipped():
    import gzip
    return json.loads(gzip.decompress(bj.OUT.read_bytes()))


def _flags(rows):
    return next(r for r in rows if (r["product"], r["method"], r["path"]) == KEY)


@pytest.mark.parametrize("damage", [
    lambda r: r.update(one_of=[]),                                    # not a record
    lambda r: r["one_of"].update(names=["nonesuch"]),                 # an unpublished name
    lambda r: r["one_of"].update(names=[]),                           # no names
    lambda r: r["one_of"].update(why=7),                              # not a sentence
    lambda r: r["one_of"].update(extra=1),                            # a key no line has
    lambda r: r.update(access="read"),                                # (caught by the access column too)
])
def test_a_rule_the_build_would_not_write_refuses_every_address(monkeypatch, damage):
    from conftest import _clear_data_caches
    from test_proximo_json import _serve

    doc = _shipped()
    damage(_flags(doc["rows"]))
    _serve(monkeypatch, doc)
    try:
        with pytest.raises(ProximoError, match="proximo.json.gz"):
            engine.resolve("pve", "GET", "/version")
    finally:
        monkeypatch.undo()
        _clear_data_caches()


def test_a_rule_on_a_read_refuses_every_address(monkeypatch):
    from conftest import _clear_data_caches
    from test_proximo_json import _serve

    doc = _shipped()
    read = next(r for r in doc["rows"] if (r["product"], r["method"], r["path"]) == ("pve", "GET", FLAGS))
    read["one_of"] = dict(_flags(doc["rows"])["one_of"])
    _serve(monkeypatch, doc)
    try:
        with pytest.raises(ProximoError, match="carries a rule"):
            engine.resolve("pve", "GET", "/version")
    finally:
        monkeypatch.undo()
        _clear_data_caches()


# --- what counts as naming a flag is what the wire will send (lens: noout=[] reached the wire empty) ----

@pytest.mark.parametrize("value", [True, False, 0, 1, 2, -1, "0", "1", "true", "false", " x "])
def test_a_value_the_wire_sends_names_its_flag(value):
    import httpx

    from proximo.core import wire
    assert engine._names_it(value) is True
    body = httpx.Request("PUT", "https://pve.invalid/x", data=wire._form({"noout": value})).content
    assert body.startswith(b"noout=")                                    # accepted only if the body carries it


@pytest.mark.parametrize("value", [None, "", "  ", "\t", [], {}, [1], {"a": 1}, (), 1.5, 0.0, b"1", object()])
def test_a_value_the_wire_drops_or_the_vendor_cannot_read_names_nothing(armed_plane, monkeypatch, value):
    import httpx

    from proximo.core import wire
    assert engine._names_it(value) is False
    w = Wire()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    row = engine.table()[KEY]
    assert engine.plan(row, {"noout": value}, FLAGS, cfg=armed_plane)["allowed"] is False
    with pytest.raises(ProximoError, match="at least one of"):
        engine.execute(row, {"noout": value}, cfg=armed_plane, path=FLAGS)
    assert not any(m == "PUT" for m, _, _ in w.calls)
    if value in ([], ()):                      # the shape the lens found: an EMPTY body at the vendor
        assert httpx.Request("PUT", "https://pve.invalid/x", data=wire._form({"noout": value})).content == b""


def test_one_named_flag_among_empty_ones_is_a_call_that_names_a_flag(armed_plane, monkeypatch):
    w = Wire()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    engine.execute(engine.table()[KEY], {"noout": [], "nodown": 1}, cfg=armed_plane, path=FLAGS)
    assert any(m == "PUT" for m, _, _ in w.calls)
