"""The receipt over REAL `doctor.run` reports, not planted dicts.

An independent lens and a security review each got estate identifiers through the first receipt
by routes the planted fixture never took: a registry target's name inside the TOML error text,
the CONTAIN trip file's free text, the operator's log basename in the sealed-archive name. Each is
reproduced here against the live doctor, and a generated test injects an identifier-like string
into EVERY string field of every report the doctor can be made to write and asserts none survives.
Hosts are `.invalid`/`.example`/`.test` (the release leak audit accepts those).
"""
from __future__ import annotations

import json

import pytest

from proximo.core import doctor, engine, receipt
from proximo.core.doors import cli


class _Down:
    def call(self, method, path, params=None):
        raise RuntimeError("connect to gw-lab7.zq.invalid (192.0.2.44) failed as ops@pve!proximo-write")


@pytest.fixture
def estate(monkeypatch, tmp_path):
    """A pve plane whose host and token path carry markers, a registry that is wrong in a way that
    names a target, a CONTAIN trip with prose in it, and a sealed archive beside an operator log."""
    tok = tmp_path / "zq-token-file"
    tok.write_text("zq-secret-bytes")
    tok.chmod(0o600)
    reg = tmp_path / "zq-targets.toml"
    reg.write_text("[targets.east-annex]\nkind = 'pxe'\nbase_url = 'https://east-annex.invalid:8006'\n")
    trip = tmp_path / "zq-trip"
    trip.write_text("tripped by alice: hv-zq on fire, call Bob at acme\n")
    log = tmp_path / "acme-prod-audit.jsonl"
    (tmp_path / "acme-prod-audit.jsonl.keyed-20260101T000000Z-abcdef12").write_text("")
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://gw-lab7.zq.invalid:8006/api2/json")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(tok))
    monkeypatch.setenv("PROXIMO_TARGETS", str(reg))
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(log))
    for var in ("PROXIMO_PBS_BASE_URL", "PROXIMO_PMG_BASE_URL", "PROXIMO_PDM_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Down())
    return tmp_path


LEAKS = ("east-annex", "pxe", "alice", "hv-zq", "Bob", "acme", "on fire", "gw-lab7", "zq.invalid", "192.0.2.44",
         "proximo-write", "zq-token-file", "zq-secret-bytes", "zq-targets", "zq-trip", "20260101", "abcdef12")


def test_the_live_report_really_carries_each_route(estate):
    """The control: without it the three tests below could be green because the report was empty."""
    raw = json.dumps(doctor.run(), default=str)
    for route in ("east-annex", "tripped by alice", "acme-prod-audit.jsonl.keyed-20260101"):
        assert route in raw, route


def _printed(capsys, *argv):
    code = cli.doctor_main(["--receipt", *argv])
    return code, capsys.readouterr().out


def test_a_registry_target_name_in_the_toml_error_does_not_leak(estate, capsys):
    _, out = _printed(capsys)
    assert "east-annex" not in out and "pxe" not in out


def test_the_contain_trip_files_free_text_does_not_leak(estate, capsys):
    _, out = _printed(capsys)
    for word in ("alice", "hv-zq", "Bob", "acme", "on fire"):
        assert word not in out, word


def test_the_sealed_archive_name_does_not_leak(estate, capsys):
    _, out = _printed(capsys)
    assert "acme-prod" not in out and "20260101" not in out and "abcdef12" not in out


def test_nothing_from_the_live_estate_survives_and_the_diagnosis_does(estate, capsys):
    code, out = _printed(capsys)
    for leak in LEAKS + (str(estate),):
        assert leak not in out, leak
    assert code == cli.EXIT_VENDOR
    assert "proximo receipt" in out and "fingerprint" in out
    assert "CONTAIN" in out and "tripped" in out.lower()


# --- generated: an identifier-like string in EVERY string field, one field at a time -------------

def _string_paths(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _string_paths(v, (*path, k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _string_paths(v, (*path, i))
    elif isinstance(obj, str):
        yield path


def _set(obj, path, value):
    for p in path[:-1]:
        obj = obj[p]
    obj[path[-1]] = value


def _reports(estate_up):
    """The live report, plus the same report with the box healthy-looking (no refusal text)."""
    yield doctor.run()


SHAPES = ("zqmark{n}", "Zq-Mark-{n}.example", "zq_mark_{n}", "/srv/zqmark{n}/k", "zqmark{n}@pve!tok",
          "https://zqmark{n}.invalid:8006/x", "zqmark{n}.co.uk", "ZQMARKQUIET{n}")


def test_an_identifier_injected_into_any_string_field_never_reaches_the_receipt(estate):
    base = doctor.run()
    base.pop("exit")
    paths = list(_string_paths(base))
    assert len(paths) > 20, "the report has too few string fields to prove anything"
    survivors = []
    for n, path in enumerate(paths):
        for shape in SHAPES:
            marker = shape.format(n=n)
            rep = json.loads(json.dumps(base))
            _set(rep, path, marker)
            out = receipt.render(rep, version="0.48.1", generated_at="2026-10-25T00:00:00Z").lower()
            token = marker.lower()
            core = [t for t in ("zqmark", "zq-mark", "zq_mark", "zqmarkquiet") if t in token][0]
            if core in out:
                survivors.append((path, marker))
    assert not survivors, survivors[:10]


def test_an_identifier_injected_into_any_dict_key_never_reaches_the_receipt(estate):
    rep = doctor.run()
    rep.pop("exit")
    rep["zqmarkkey"] = {"zqmarkinner": "x"}
    rep["planes"]["zqmarkplane"] = {"configured": True}
    rep["pillars"]["zqmarkpillar"] = {"standing": True}
    assert "zqmark" not in receipt.render(rep, version="0.48.1", generated_at="t").lower()


def test_a_bare_word_injected_into_any_planes_reach_version_never_reaches_the_receipt(estate):
    """The live report's versions are error dicts (the wire is down), so the string walk never
    reached the version field's strictness. Set it directly, on every plane."""
    base = doctor.run()
    base.pop("exit")
    for product in ("pve", "pbs", "pmg", "pdm"):
        for marker in ("zqmark", "zqmark.example", "192.168.1", "ZQMARKQUIET"):
            rep = json.loads(json.dumps(base))
            rep["planes"].setdefault(product, {"configured": True}).setdefault("reach", {})["version"] = marker
            out = receipt.render(rep, version="0.48.1", generated_at="2026-10-25T00:00:00Z")
            assert marker.lower() not in out.lower(), (product, marker)
            assert "version: [text]" in out
