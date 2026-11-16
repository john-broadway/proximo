"""The vendor's row: for a list read, the fields the vendor publishes as present on every row.

Each api-viewer publishes, per call, what the call returns. For a list it is `returns.items`: the
row's fields, each marked `optional` or not. The vendor stage reads that (`row_fields` in
`scripts/build_governance_table.py`) and the one JSON carries it as the `row` column, verbatim names,
so nothing downstream writes its own idea of what a row must hold.
"""
import importlib.util
import json
import pathlib

import pytest

from proximo.core import apitree, engine, memory
from proximo.core.errors import ProximoError
from test_proximo_json import _at, _serve, _shipped

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def bgt():
    spec = importlib.util.spec_from_file_location("bgt_row", ROOT / "scripts" / "build_governance_table.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _obj(**props):
    return {"type": "object", "properties": props}


REQ, OPT = {"type": "string"}, {"type": "string", "optional": 1}


@pytest.mark.parametrize("returns,want", [
    ({"type": "array", "items": _obj(id=REQ, name=OPT)}, ["id"]),
    ({"type": "array", "items": _obj(b=REQ, a=REQ)}, ["a", "b"]),                                # sorted
    ({"type": "array", "items": _obj(a=OPT)}, []),                              # fields named, none required
    ({"type": "array", "items": _obj()}, []),
    # the vendor's spellings of `optional`: 1, 0, "1", true, or left out
    ({"type": "array", "items": _obj(a={"optional": 0}, b={"optional": "1"}, c={"optional": True}, d={})},
     ["a", "d"]),
    # PBS and PDM nest a row in `allOf`: every block describes it
    ({"type": "array", "items": {"allOf": [_obj(name=REQ), _obj(path=REQ, comment=OPT)]}}, ["name", "path"]),
    ({"type": "array", "items": {"allOf": [_obj(a=REQ), {"allOf": [_obj(b=REQ), _obj(c=OPT)]}]}}, ["a", "b"]),
    # a row that is one of several kinds: only what every kind requires
    ({"type": "array", "items": {"oneOf": [_obj(id=REQ, vmid=REQ), _obj(id=REQ, node=REQ)]}}, ["id"]),
    ({"type": "array", "items": {"oneOf": [_obj(id=REQ), {"type": "object"}]}}, []),
    ({"type": "array", "items": {"oneOf": [{"allOf": [_obj(id=REQ), _obj(a=REQ)]}, _obj(id=REQ)]}}, ["id"]),
    # the field the vendor names a row's kind by is on every row, unless its own schema says optional
    ({"type": "array", "items": {"oneOf": [_obj(id=REQ, vmid=REQ), _obj(id=REQ)], "type-property": "type"}},
     ["id", "type"]),
    ({"type": "array", "items": {"oneOf": [_obj(id=REQ)], "type-property": "type",
                                 "type-property-schema": {"type": "string", "optional": 1}}}, ["id"]),
    ({"type": "array", "items": {"oneOf": [{"type": "object"}], "type-property": "kind"}}, ["kind"]),
    ({"type": "array", "items": {"allOf": [{"type": "object"}, {"description": "x"}]}}, None),   # blocks naming nothing
    # not a list of objects, or no field named: nothing published
    ({"type": "array", "items": {"type": "string"}}, None),
    ({"type": "array", "items": {"type": "object"}}, None),
    ({"type": "array"}, None), ({"type": "object", "properties": {"a": REQ}}, None), ({"type": "null"}, None),
    (None, None), ("array", None),
])
def test_the_row_is_read_as_the_vendor_publishes_it(bgt, returns, want):
    assert bgt.row_fields(returns, "x") == want


@pytest.mark.parametrize("items", [{"anyOf": [_obj(a=REQ)]}, {"$ref": "#/x"}, {"properties": ["a"]},
                                   {"allOf": []}, {"allOf": ["x"]}, {"oneOf": {}},
                                   {"allOf": [{"anyOf": [_obj(a=REQ)]}]},
                                   {**_obj(a=REQ), "required": ["a"]}, {**_obj(a=REQ), "invented": 1},   # any new word
                                   {**_obj(a=REQ), "type-property": "type"},              # a kind with no oneOf
                                   {"oneOf": [_obj(a=REQ)], "type-property": 5}])
def test_a_form_the_reader_does_not_know_refuses_the_build(bgt, items):
    """Never guessed: a new vendor shape stops the next refresh instead of riding in unread."""
    with pytest.raises(SystemExit, match="pve GET /x: the vendor's returns"):
        bgt.row_fields({"type": "array", "items": items}, "pve GET /x")


@pytest.mark.parametrize("key,want", [
    (("pve", "GET", "/access/acl"), ("path", "roleid", "type", "ugid")),
    (("pve", "GET", "/cluster/resources"), ("id", "type")),
    (("pve", "GET", "/pools"), ("poolid",)),
    (("pbs", "GET", "/admin/datastore/{store}/namespace"), ("ns",)),
    (("pbs", "GET", "/admin/datastore/{store}/groups"),                                    # an `allOf` row
     ("backup-count", "backup-id", "backup-type", "files", "last-backup")),
    (("pdm", "GET", "/pve/remotes/{remote}/resources"), ("id", "node", "status", "type")),  # a `oneOf` row, by `type`
    (("pmg", "GET", "/config/ruledb/rules"), ("id",)),
    (("pve", "GET", "/version"), None),                                                     # one record, not a list
    (("pve", "POST", "/pools"), None),
    (("pve", "POST", "/nodes/{node}/lxc/{vmid}/exec"), None),                               # Proximo's own row
])
def test_the_shipped_file_carries_the_vendors_row(key, want):
    assert engine.table()[key].row == want


def test_only_a_vendors_read_carries_a_row():
    rows = apitree.published()["rows"]
    carried = [r for r in rows if r["row"] is not None]
    assert carried and all(r["method"] == "GET" and r["wire"] == "http" for r in carried)
    assert {r["product"] for r in carried} == set(apitree.PRODUCTS)


def test_the_vendor_stage_carries_what_the_api_viewer_says(bgt, tmp_path, monkeypatch):
    tree = [{"path": "/things", "text": "things", "info": {
        "GET": {"returns": {"type": "array", "items": _obj(id=REQ, note=OPT)}},
        "POST": {"returns": {"type": "array", "items": _obj(id=REQ)}}}}]
    for product in apitree.PRODUCTS:
        (tmp_path / f"{product}-apidoc.js").write_text("const apiSchema = " + json.dumps(tree) + ";")
    monkeypatch.setattr(bgt, "gates", lambda: {})
    rows = {(r["product"], r["method"]): r["row"] for r in bgt.build(tmp_path)}
    assert rows[("pve", "GET")] == ["id"] and rows[("pve", "POST")] is None      # a read's row only


@pytest.mark.parametrize("damage", [
    lambda rows: _at(rows, ("pve", "POST", "/pools")).update(row=["poolid"]),               # not a read
    lambda rows: next(r for r in rows if r["wire"] == "ssh" and r["method"] == "GET").update(row=["x"]),   # ours
    lambda rows: _at(rows, ("pve", "GET", "/pools")).update(row=["poolid", "poolid"]),      # a field twice
    lambda rows: _at(rows, ("pve", "GET", "/pools")).update(row=[""]),
    lambda rows: _at(rows, ("pve", "GET", "/pools")).update(row=[5]),
    lambda rows: _at(rows, ("pve", "GET", "/pools")).update(row="poolid"),
    lambda rows: _at(rows, ("pve", "GET", "/pools")).pop("row"),
])
def test_a_damaged_row_column_refuses_every_address(monkeypatch, damage):
    from conftest import _clear_data_caches

    doc = _shipped()
    damage(doc["rows"])
    _serve(monkeypatch, doc)
    try:
        with pytest.raises(ProximoError, match="proximo.json.gz"):
            engine.resolve("pve", "GET", "/version")
    finally:
        monkeypatch.undo()
        _clear_data_caches()


# ---- the estate memory holds a list to the vendor's row before it may retire by it -------------------

_ACL = {"path": "/vms/105", "type": "user", "ugid": "ops@pve", "roleid": "PVEVMUser"}
_REMOTE = {"id": "alpha", "type": "pve", "authid": "root@pam!pdm", "nodes": [{"hostname": "pve1.example"}]}


@pytest.mark.parametrize("plane,template,rows,whole", [
    ("pve", "/access/acl", [_ACL], True),                                         # `propagate` is optional
    *(("pve", "/access/acl", [{k: v for k, v in _ACL.items() if k != gone}], False) for gone in _ACL),
    ("pve", "/access/acl", [_ACL, {**_ACL, "roleid": None}], False),             # a null is an absent field
    ("pve", "/access/acl", [_ACL, "x"], False), ("pve", "/access/acl", [None], False),
    ("pve", "/access/acl", [], True),
    ("pve", "/nodes/{node}/network", [{"iface": "vmbr0", "type": "bridge"}], True),
    ("pve", "/nodes/{node}/network", [{"iface": "vmbr0"}], False),
    ("pve", "/cluster/resources", [{"id": "network/pve1/vmbr0", "type": "network"}], True),
    ("pve", "/cluster/resources", [{"type": "lxc", "vmid": 105}], False),
    ("pbs", "/admin/datastore/{store}/namespace", [{"ns": ""}, {"ns": "prod"}], True),   # the root: a value
    ("pbs", "/admin/datastore/{store}/namespace", [{"ns": None}], False),
    ("pbs", "/admin/datastore", [{"store": "tank"}], False),
    ("pbs", "/admin/datastore", [{"store": "tank", "backend-type": "filesystem", "mount-status": "nonremovable"}],
     True),
    ("pmg", "/config/domains", [{"domain": "example.org", "comment": ""}], True),
    ("pmg", "/config/domains", [{"domain": "example.org"}], False),
    ("pmg", "/nodes", [{"anything": 1}], True), ("pmg", "/nodes", ["mx1"], False),   # fields named, none required
    # PDM publishes `token` on every remote; Proximo withholds it before memory is fed, so it is not asked for
    ("pdm", "/remotes/remote", [_REMOTE], True),
    ("pdm", "/remotes/remote", [{k: v for k, v in _REMOTE.items() if k != "type"}], False),
    # no row published for the address: not judged
    ("pve", "/nodes/{node}/qemu/{vmid}/config", ["anything"], True),
    ("pve", "/no/such/address", [{"x": 1}], True),
    ("pve", "/access/acl", {"not": "a list"}, True),
])
def test_a_row_is_held_to_what_the_vendor_publishes(plane, template, rows, whole):
    assert memory._rows_as_published(plane, template, rows) is whole


def test_a_field_proximo_withholds_is_not_asked_of_a_row():
    assert "token" in engine.table()[("pdm", "GET", "/remotes/remote")].row
    assert memory._vendor_row("pdm", "/remotes/remote") == ("authid", "id", "nodes", "type")


def test_every_list_the_memory_feeds_on_is_one_the_vendor_publishes_or_is_named_here():
    """The lists the memory may retire by, and the one row each the vendor names no field for. A new fed
    list with nothing published turns this red, so it is seen and said, never assumed."""
    unpublished = {(plane, t) for plane in apitree.PRODUCTS for t in memory.shape(plane).feeds
                   if engine.table()[(plane, "GET", t)].row is None}
    assert unpublished == {("pve", "/nodes/{node}/lxc/{vmid}/config"), ("pve", "/nodes/{node}/qemu/{vmid}/config")}
