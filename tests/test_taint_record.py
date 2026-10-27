"""The untrusted-channel RECORD: `records/taint.toml`, address-level, exact, and read by
the engine as `Row.untrusted`/`Row.channel`.

The 0.44 module classified tools by NAME; the door serves addresses, so the classification
had to move to the address or the door served `GET /nodes/{node}/syslog` untainted while the
wrapper for it was the only taint-tracked path. Generated once (scripts/harvest_taint.py) from
the name set joined to the addresses those tools reach, then read line by line; the file is the
record now, and these tests pin its shape: every key a live address the engine serves, every
line a sentence, no shorthand, the exact count, and a file that does not parse refuses by name.
"""
from __future__ import annotations

import pathlib
import re
import tomllib

import pytest

from proximo.core import engine
from proximo.core.errors import ProximoError
from test_tiers_harvest import bj  # the record is built, with its checks, by the build

RECORD = pathlib.Path(__file__).resolve().parent.parent / "records" / "taint.toml"

#: pmg 34 · pve 29 · pbs 21 · pdm 5 on 2026-09-23 (the 0.44 ADVERSARIAL_TOOLS' addresses), + 14
#: pve guest-agent reads on 2026-10-03 (B5: the agent lane is opt-in now, not a hard wall, so its
#: guest-authored reads carry a taint line like any other guest-byte channel).
EXACT_LINES = 112  # +1 B3: GET /nodes/{node}/lxc/{vmid}/probe; +1 node shell: GET /nodes/{node}/probe;
#  +1 the download lane (2026-10-04): pmg GET /quarantine/download, attacker bytes to disk
#  +2 consult (2026-10-25): pve GET /nodes/{node}/qemu|lxc/{vmid}/pending, the guest config fan-out


def _lines() -> list[tuple[str, str]]:
    parsed = tomllib.loads(RECORD.read_text())["untrusted"]
    return [(k, v.get("why", "").strip()) for k, v in parsed.items()]


def test_the_record_is_exact_and_names_only_addresses_the_engine_serves():
    live = {f"{r.product}:{r.method} {r.path}": r for r in engine.table().values()}
    keys = [k for k, _ in _lines()]
    assert not (set(keys) - set(live)), sorted(set(keys) - set(live))[:5]
    # an OPT-IN gated row (the guest-agent lane) is served when the operator opts in, so a taint
    # line on one is live, not inert; a HARD gate or a tunnel still is.
    inert = [k for k in keys if (live[k].gate and live[k].lane is None)
             or live[k].excluded]
    assert not inert, inert[:5]
    assert len(keys) == EXACT_LINES, f"the record holds {len(keys)} lines, the pin says {EXACT_LINES}"


def test_every_line_is_a_sentence_that_names_its_provenance():
    # a bracketed provenance at the end: a 0.44 tool name ([pbs_node_syslog]) or, for the B5
    # guest-agent reads, the authoring stamp ([Claude, 2026-10-03, guest-agent lane B5]).
    bad = [(k, s) for k, s in _lines()
           if len(s.split()) < 4 or not re.search(r"\[[A-Za-z0-9_,\- ]+\]$", s) or s[0] == "["]
    assert not bad, bad[:3]


def test_no_line_is_a_shorthand():
    """`{}` fits any segment; lens 2 rejected `{qemu|lxc}` in prose and the same rule holds
    here: one line, one published spelling."""
    bad = [k for k, _ in _lines() if "{}" in k or "|" in k]
    assert not bad, bad


def test_the_engine_reads_the_record_onto_the_row():
    row = engine.resolve("pve", "GET", "/nodes/{node}/syslog")
    assert row.untrusted is True and "log" in row.channel
    clean = engine.resolve("pve", "GET", "/nodes/{node}/status")
    assert clean.untrusted is False and clean.channel is None
    assert engine.untrusted_addresses() == {k for k, _ in _lines()}


@pytest.mark.parametrize("body,match", [
    (b'"pve:GET /x" = { why = "a" }\n"pve:GET /x" = { why = "b" }\n', "not a readable TOML table"),
    (b'"pve:GET /nodes/{node}/syslog" = { why = "" }\n', "without a why"),
    (b'"pve:GET /nodes/{node}/syslog" = "yes"\n', "without a why"),
])
def test_a_record_that_cannot_be_read_refuses_the_table_by_name(body, match):
    with pytest.raises(ProximoError, match=match):
        bj.untrusted((b"[untrusted]\n" + body).decode())


def test_a_line_for_an_address_the_engine_never_serves_is_refused_at_load(monkeypatch):
    """A HARD-gated or excluded row is refused before taint is read; a line for it does nothing
    and says it did. Since 2026-10-04 every gated row is a lane (agent, shell, node, download),
    so the hard gate is manufactured on a live row; a tunnel is still a real excluded row."""
    rows = dict(engine.table())
    assert not [r for r in rows.values() if r.gate and r.lane is None]
    tunnel = next(f"{r.product}:{r.method} {r.path}" for r in rows.values() if r.excluded)
    with pytest.raises(ProximoError, match="match no address the engine serves"):
        bj.refuse_inert_untrusted(rows, {tunnel: "a sentence [tool]"})
    key = ("pve", "GET", "/version")
    planted = {**rows, key: engine.Row(**{**rows[key].__dict__, "gate": "a planted hard gate"})}
    with pytest.raises(ProximoError, match="match no address the engine serves"):
        bj.refuse_inert_untrusted(planted, {"pve:GET /version": "a sentence [tool]"})
    with pytest.raises(ProximoError, match="match no address the engine serves"):
        bj.refuse_inert_untrusted(rows, {"pve:GET /nodes/{n}/syslog": "the wrong placeholder [tool]"})


def test_the_build_itself_refuses_an_inert_taint_line(records):
    """Not the function: the BUILD. A lens found `build()` green with its `refuse_inert_untrusted`
    call deleted, because every test drove the function directly."""
    real = bj.read_inputs()[1]["taint.toml"]
    line = '"pve:GET /nodes/{node}/not-a-thing" = { why = "a sentence for an address nobody publishes [lens]" }'
    inert = real + "\n" + line + "\n"
    with pytest.raises(ProximoError, match="taint.toml names 1 key"):
        records(**{"taint.toml": inert})
