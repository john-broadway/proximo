"""THE 4K DOOR: a local model in a 4,000-token window drives the whole estate.

2026-09-27, measured on the real cluster through the shell door: the door's six tools cost 907
tokens and one estate read (cluster resources, 37 rows) cost 4,299, because the core served the
vendor's raw rows where the 0.44 wrappers projected them. Four rules, one door, no wrapper:

  1. a list read comes back LEAN with a COUNT: a row keeps its names, states and ids and drops
     its counters; `fields="all"` is the raw escape hatch; `fields="a,b"` is exact
  2. the cap is 4K-shaped, and a list over it is cut by ROWS with total/returned, never a head
  3. find ranks a plane you named first, a read before a mutation, then the shortest address,
     and hands back a handful
  4. plan takes words: an argument with no leading slash is a query, not a path

The gate lives in tests/test_door_fixes.py (section 5), in the unit the sentence uses, tokens: the
door carries the budget, so the cap on every answer is a TOKEN cap too, and the six tools, a find, a
plan and the largest read the cap lets through fit with the model's thousand to spare. The control
here: the same rows raw exceed the cap.
"""
from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass

import pytest

from proximo.core import engine, rawdoor, wire
from proximo.core.doors import mcp as door
from proximo.core.errors import ProximoError

# THE REAL SHAPE of GET /cluster/resources on 2026-09-27 (37 rows: 29 guests, 6 storages, a node, a
# network zone), values replaced by placeholders of the same kind and encoded length, so the
# fixture weighs what the estate weighs (11,301 bytes against 11,323 real) and carries no name.
_SHAPE = json.loads((pathlib.Path(__file__).parent / "fixtures" / "cluster-resources-shape.json").read_text())["rows"]


def _value(spec: str):
    kind, n = spec[0], int(spec[1:])
    if kind == "s":
        return "x" * (n - 2)
    if kind == "b":
        return n == 4
    if kind == "z":
        return None
    if kind == "f":
        return float("1." + "1" * (n - 2)) if n > 2 else 1.0
    return int("1" * n)


def _resources(n: int = 37) -> list[dict]:
    return [{k: _value(v) for k, v in _SHAPE[i % len(_SHAPE)].items()} for i in range(n)]


class _Body:
    def __init__(self, body):
        self.body = body
        self.calls = []

    def call(self, method, path, params=None):
        self.calls.append((method, path, params))
        return self.body


@dataclass(frozen=True)
class _Cfg(wire.Plane):
    audit_log_path: str = ""
    audit_key_path: str | None = None


@pytest.fixture
def cfg(tmp_path):
    return _Cfg("pve", "https://unreachable.invalid:8006/api2/json", "/dev/null",
                audit_log_path=str(tmp_path / "audit.log"))


@pytest.fixture
def big(monkeypatch):
    """Rule 1 is about WHAT a row keeps, not the cap: an operator's byte cap stands alone (the token
    cap stands down) and 64 KiB is room for all 37 rows."""
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "65536")


def _serve(monkeypatch, cfg, body, **kw):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Body(body))
    return engine.execute(engine.resolve("pve", "GET", "/cluster/resources"), {}, cfg=cfg,
                          ledger_cfg=cfg, path="/cluster/resources", **kw)


# --- rule 1: lean by default, with a count -----------------------------------------------------

def test_a_list_read_comes_back_lean_with_a_count(monkeypatch, cfg, big):
    out = _serve(monkeypatch, cfg, _resources())
    assert out["total"] == 37 and len(out["data"]) == 37 and "truncated" not in out
    guest = next(r for r in out["data"] if "vmid" in r)
    assert isinstance(guest["id"], str) and isinstance(guest["status"], str) and isinstance(guest["vmid"], int)
    assert not any(k in guest for k in ("mem", "netin", "uptime", "template", "cpu", "disk"))


def test_fields_all_returns_the_vendors_rows_untouched(monkeypatch, cfg, big):
    rows = _resources(3)
    out = _serve(monkeypatch, cfg, rows, fields="all")
    assert out["data"] == rows and out["total"] == 3


def test_fields_names_exact_keys_in_order_and_refuses_a_name_no_row_carries(monkeypatch, cfg, big):
    out = _serve(monkeypatch, cfg, _resources(), fields="status,name")
    assert list(out["data"][0]) == ["status", "name"] and list(out["data"][-1]) == ["status"]   # the zone has no name
    with pytest.raises(ProximoError, match="no row carries 'nme'") as e:
        _serve(monkeypatch, cfg, _resources(), fields="nme")
    assert "name" in str(e.value)                       # the refusal teaches the available names


def test_a_row_with_no_lean_key_stays_whole(monkeypatch, cfg):
    """Projection fails OPEN: thinning a row to nothing would hide that the vendor answered."""
    rows = [{"n": i, "m": i * 2} for i in range(3)]
    out = _serve(monkeypatch, cfg, rows)
    assert out["data"] == rows and out["total"] == 3


def test_the_count_comes_from_the_raw_rows_whatever_fields_says(monkeypatch, cfg):
    for fields in (None, "all", "name"):
        assert _serve(monkeypatch, cfg, _resources(), fields=fields)["total"] == 37


def test_a_dict_read_is_not_projected(monkeypatch, cfg):
    body = {"cpu": 0.5, "memory": {"used": 1, "total": 2}, "kversion": "6.x"}
    out = _serve(monkeypatch, cfg, body)
    assert out["data"] == body and "total" not in out


# --- rule 2: a 4K-shaped cap, cut by rows --------------------------------------------------------

def test_the_default_cap_is_four_k_shaped():
    """1.125 KiB and 750 estimated tokens; test_door_fixes.py says why."""
    assert rawdoor.DEFAULT_MAX_BYTES == 1152 and rawdoor.DEFAULT_MAX_TOKENS == 750


def test_a_list_over_the_cap_is_cut_by_rows_with_total_and_returned(monkeypatch, cfg):
    """Rows asked for by name. Step 5 (2026-09-27): a DEFAULT read over the cap with states to
    count answers whole as a tally instead (tests/test_store.py); this is the rows' own rule."""
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "2048")
    assert _serve(monkeypatch, cfg, _resources(300))["summarized"] is True
    out = _serve(monkeypatch, cfg, _resources(300), fields="all")
    assert out["truncated"] is True and out["total"] == 300
    assert 0 < out["returned"] < 300 and len(out["data"]) == out["returned"]
    assert len(json.dumps(out["data"], separators=(",", ":"))) <= 2048 and "head" not in out
    out = _serve(monkeypatch, cfg, _resources(5))          # the control: under the cap, whole
    assert "truncated" not in out and out["returned"] == 5 if "returned" in out else out["total"] == 5


# --- rule 3: find ranks the shortest address first, a handful by default -----------------------

def test_find_ranks_the_shortest_address_first_and_hands_back_a_handful():
    out = door.find("pbs GET datastore")
    assert out["matches"][0]["path"] == "/admin/datastore"
    assert len(out["matches"]) == 5 and out["truncated"] is True
    assert len(door.find("pbs GET datastore", limit=25)["matches"]) > 5      # the control


# --- rule 4: plan takes words -------------------------------------------------------------------

def test_plan_takes_words_when_the_path_has_no_leading_slash(cfg):
    out = door.plan("pve", "GET", "lxc status current")
    assert out["address"] == "GET /nodes/{node}/lxc/{vmid}/status/current"


def test_plan_on_words_that_match_several_addresses_returns_the_matches(cfg):
    out = door.plan("pbs", "GET", "datastore")
    assert "matches" in out and out["matches"][0]["path"] == "/admin/datastore" and "address" not in out


def test_plan_on_words_that_match_nothing_refuses_like_an_unknown_address(cfg):
    with pytest.raises(ProximoError, match="no published address matched"):
        door.plan("pve", "GET", "zorblax frobnicate")


# --- THE CONTROL: the same rows raw exceed the cap ---------------------------------------------

def test_the_estate_raw_is_over_the_cap_and_comes_back_cut_not_whole(monkeypatch, cfg):
    raw = _serve(monkeypatch, cfg, _resources(), fields="all")
    assert raw["truncated"] is True and raw["returned"] < 37


# --- LENS FOLD (sonnet, 2026-09-27, 4 BLOCKING): each planted against the shipped bytes ---------

def test_one_stray_non_dict_row_does_not_switch_lean_off_for_the_rest(monkeypatch, cfg):
    """BLOCKING 1: `all(isinstance(r, dict))` fell through to raw for the whole list on one None."""
    rows = _resources(5) + [None]
    out = _serve(monkeypatch, cfg, rows)
    assert out["total"] == 6 and out["data"][-1] is None
    assert "mem" not in out["data"][0] and "id" in out["data"][0]


def test_empty_fields_is_refused_not_an_empty_row(monkeypatch, cfg):
    """BLOCKING 2: fields="" and "," emptied every row to {} past the fail-open rule."""
    for fields in ("", ",", " , "):
        with pytest.raises(ProximoError, match="fields: give"):
            _serve(monkeypatch, cfg, _resources(3), fields=fields)


def test_fields_all_is_recognised_however_it_is_spelled(monkeypatch, cfg, big):
    rows = _resources(3)
    for fields in (" all ", "ALL"):
        assert _serve(monkeypatch, cfg, rows, fields=fields)["data"] == rows


def test_the_shell_door_takes_fields_and_defaults_to_lean(monkeypatch, cfg, capsys):
    """BLOCKING 3: the reference door had no way to ask for raw rows."""
    from proximo.core.doors import cli
    monkeypatch.setattr(engine, "_client", lambda product, c=None: _Body(_resources(3)))
    monkeypatch.setattr(engine, "execute", lambda row, args, **kw: engine._envelope(row, "/cluster/resources",
                                                                                     _resources(3), kw.get("fields")))
    assert cli.main(["pve", "GET", "/cluster/resources"]) == cli.EXIT_OK
    lean_out = json.loads(capsys.readouterr().out)
    assert "mem" not in lean_out["data"][0] and lean_out["total"] == 3
    assert cli.main(["pve", "GET", "/cluster/resources", "--fields", "all"]) == cli.EXIT_OK
    raw_out = json.loads(capsys.readouterr().out)
    assert "mem" in raw_out["data"][0]
    assert cli.main(["pve", "GET", "/cluster/resources", "--fields", "nme"]) == cli.EXIT_REFUSED


def test_find_puts_the_named_plane_and_reads_before_a_shorter_mutation_elsewhere():
    """BLOCKING 4: 'pbs datastore' ranked pmg POST /config/pbs (disruptive) first, on path length."""
    first = door.find("pbs datastore")["matches"][0]
    assert first["plane"] == "pbs" and first["access"] == "read" and first["path"] == "/admin/datastore"


def test_plan_refuses_a_blank_query_instead_of_listing_every_address():
    for path in ("", " ", "GET"):
        with pytest.raises(ProximoError, match="give proximo_plan a /path or words"):
            door.plan("pve", "GET", path)


def test_the_no_match_refusal_says_a_path_starts_with_a_slash():
    with pytest.raises(ProximoError, match="a path starts with '/'"):
        door.plan("pve", "GET", "nodes/x/zorblax")


def test_a_list_of_strings_is_counted_and_refuses_fields(monkeypatch, cfg):
    lines = [f"line {i}" for i in range(4)]
    out = _serve(monkeypatch, cfg, lines)
    assert out["data"] == lines and out["total"] == 4
    with pytest.raises(ProximoError, match="rows are not records"):
        _serve(monkeypatch, cfg, lines, fields="name")
