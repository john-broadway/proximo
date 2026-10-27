"""Token sight (records/sight.toml): an empty list the token could not have seen into is not "none".

Proxmox answers 200 and an EMPTY list, not a refusal, where the token lacks the privilege that
makes a backup visible. PVE filters backup volumes out of a storage's content listing per volume
(a token without Datastore.AllocateSpace on the storage and VM.Backup on the owner guest, or
Datastore.Allocate on the storage, gets `[]` on a storage full of archives). PBS shows a caller
holding only Datastore.Backup its OWN groups and snapshots; Datastore.Audit shows all. 0.44
refused to serve such a list as "no backups" (live-found 2026-07-09 and 2026-09-16); the core
served `[]` as data from the cut (2026-10-18) until this record.

The judgement is a record line: which address, what makes the list sighted, and why. The engine
reads the row. An empty answer on such a row is judged from the token's own
`GET /access/permissions`: sighted is served, blind is refused with what it would need, and a
permission map that cannot be read is not evidence of anything, so the empty list is not vouched
for either. A non-empty list is served and the permissions are never read.
"""
from __future__ import annotations

import gzip
import json
import os
import sys
from pathlib import Path

import pytest

from proximo.core import engine, wire
from proximo.core.errors import ProximoError

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import build_proximo_json as bj  # noqa: E402

PVE_LIST = "/nodes/{node}/storage/{storage}/content"
SNAPSHOTS, GROUPS = "/admin/datastore/{store}/snapshots", "/admin/datastore/{store}/groups"
PERMS = "/access/permissions"
ARCHIVE = {"volid": "pbs:backup/ct/443/2026-09-16T02:00:00Z", "content": "backup", "size": 1}


class Wire:
    """Answers each path from a dict; the permission map is its own answer (or an exception)."""

    def __init__(self, listing, perms):
        self.listing, self.perms = listing, perms
        self.calls: list[tuple[str, str, dict]] = []

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        if path == PERMS:
            if isinstance(self.perms, BaseException):
                raise self.perms
            return self.perms
        return self.listing

    @property
    def read_permissions(self) -> bool:
        return any(p == PERMS for _, p, _ in self.calls)


def _rows() -> list[dict]:
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


@pytest.fixture
def pbs_plane(tmp_path):
    tok = tmp_path / "pbs-token"
    tok.write_text("secret-token")
    return wire.Plane("pbs", "https://pbs.invalid:8007/api2/json", str(tok))


def _pve(monkeypatch, plane, listing, perms, args=None, path="/nodes/pve1/storage/local/content"):
    w = Wire(listing, perms)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    row = engine.resolve("pve", "GET", PVE_LIST)
    asked = {"content": "backup"} if args is None else args
    return w, lambda: engine.execute(row, asked, cfg=plane, path=path, fields="all")


def _pbs(monkeypatch, plane, tail, listing, perms, args=None):
    w = Wire(listing, perms)
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    row = engine.resolve("pbs", "GET", SNAPSHOTS if tail == "snapshots" else GROUPS)
    return w, lambda: engine.execute(row, args or {}, cfg=plane, path=f"/admin/datastore/ds/{tail}", fields="all")


def _receipt(action="core.execute") -> dict:
    return [r for r in _rows() if r.get("action") == action][-1]["detail"]


# --- PVE: the storage's backup volumes --------------------------------------------------------

@pytest.mark.parametrize("perms,missing", [
    ({"/": {"Datastore.Audit": 1, "VM.Audit": 1}}, "Datastore.AllocateSpace"),                  # the auditor
    ({"/storage/local": {"Datastore.AllocateSpace": 1}, "/": {"VM.Audit": 1}}, "VM.Backup"),
    ({"/storage": {"Datastore.AllocateSpace": 0}, "/": {"VM.Backup": 1}}, "Datastore.AllocateSpace"),
    ({"/storage/other": {"Datastore.Allocate": 1}}, "Datastore.Allocate"),
])
def test_an_empty_backup_list_the_token_could_not_see_is_refused(armed_plane, monkeypatch, perms, missing):
    w, run = _pve(monkeypatch, armed_plane, [], perms)
    with pytest.raises(ProximoError) as e:
        run()
    said = str(e.value)
    assert missing in said and "/storage/local" in said and "cannot see backup volumes" in said
    assert len(said) < 600                                       # the 4K window pays for every word
    assert w.read_permissions


def test_the_refusal_is_receipted_with_what_it_needed(armed_plane, monkeypatch):
    _, run = _pve(monkeypatch, armed_plane, [], {"/": {"Datastore.Audit": 1}})
    with pytest.raises(ProximoError):
        run()
    refusal = [r for r in _rows() if r.get("action") == "core.refuse"][-1]
    assert refusal["detail"]["needs"] == "sight" and refusal["detail"]["state"] == "blind"
    assert not [r for r in _rows() if r.get("action") == "core.execute"]    # an answer never served is no "ok"


@pytest.mark.parametrize("perms", [
    {"/storage/local": {"Datastore.Allocate": 1}},                                              # the bypass
    {"/": {"Datastore.Allocate": 1}},                                                           # at the root
    {"/storage": {"Datastore.AllocateSpace": 1}, "/vms": {"VM.Backup": 1}},                      # both, propagating
    {"/storage/local": {"Datastore.AllocateSpace": 0}, "/vms/100": {"VM.Backup": 0}},
    {"/storage/local": {"Datastore.AllocateSpace": 1}, "/vms/999": {"VM.Backup": 1}},
])
def test_an_empty_backup_list_the_token_could_see_is_served(armed_plane, monkeypatch, perms):
    _, run = _pve(monkeypatch, armed_plane, [], perms)
    out = run()
    assert out["data"] == []
    assert [r for r in _rows() if r.get("action") == "core.execute"][-1]["detail"]["sight"] == "sighted"


def test_a_backup_list_with_archives_is_served_whole_when_the_token_sees_all(armed_plane, monkeypatch):
    w, run = _pve(monkeypatch, armed_plane, [ARCHIVE], {"/storage/local": {"Datastore.Allocate": 1}})
    out = run()
    assert out["data"] == [ARCHIVE] and "sight" not in out
    assert _receipt()["sight"] == "sighted"
    assert _receipt()["sight_by"] == ["Datastore.Allocate@/storage/local"]    # why it was served, names only


@pytest.mark.parametrize("perms", [
    {"/storage/local": {"Datastore.AllocateSpace": 1}, "/vms/999": {"VM.Backup": 1}},          # one guest only
    {"/": {"Datastore.Audit": 1}},
])
def test_a_partial_pve_view_is_served_and_marked_never_refused(armed_plane, monkeypatch, perms):
    if "/vms/999" in perms:
        perms = {"/storage/local": {"Datastore.AllocateSpace": 1}, "/": {"VM.Audit": 1}}       # no VM.Backup anywhere
    _, run = _pve(monkeypatch, armed_plane, [ARCHIVE], perms)
    out = run()
    assert out["data"] == [ARCHIVE] and out["sight"] == "partial"
    assert "Datastore.Allocate" in out["sight_says"] and len(out["sight_says"]) < 300
    assert _receipt()["sight"] == "partial"


def test_a_permission_map_that_cannot_be_read_marks_a_nonempty_list_unverified(armed_plane, monkeypatch):
    _, run = _pve(monkeypatch, armed_plane, [ARCHIVE], RuntimeError("https://leak.invalid/abc123"))
    out = run()
    assert out["data"] == [ARCHIVE] and out["sight"] == "unverified" and "abc123" not in out["sight_says"]
    assert _receipt()["sight"] == "unverified"


@pytest.mark.parametrize("tail", ["snapshots", "groups"])
def test_a_pbs_list_of_ones_own_rows_is_served_and_marked_partial(pbs_plane, monkeypatch, tail):
    w, run = _pbs(monkeypatch, pbs_plane, tail, [{"backup-id": "101"}], {"/datastore/ds": {"Datastore.Backup": True}})
    out = run()
    assert out["data"] == [{"backup-id": "101"}] and out["sight"] == "partial"
    assert "Datastore.Audit" in out["sight_says"] and w.read_permissions
    assert _receipt()["sight"] == "partial"


@pytest.mark.parametrize("tail", ["snapshots", "groups"])
def test_a_pbs_list_with_rows_from_an_auditing_token_carries_no_mark(pbs_plane, monkeypatch, tail):
    _, run = _pbs(monkeypatch, pbs_plane, tail, [{"backup-id": "101"}], {"/datastore/ds": {"Datastore.Audit": True}})
    assert "sight" not in run()


@pytest.mark.parametrize("perms", [
    RuntimeError("403"),                        # unreadable
    {},                                         # a token holding nothing gets 403, never 200: malformed
    [],                                         # not a map
    "forbidden",
    {"/": "Datastore.Allocate"},                # a map of the wrong shape proves nothing
])
def test_a_permission_map_that_cannot_be_read_does_not_vouch_for_the_empty_list(armed_plane, monkeypatch, perms):
    _, run = _pve(monkeypatch, armed_plane, [], perms)
    with pytest.raises(ProximoError) as e:
        run()
    assert "not vouched" in str(e.value) and "could not be read" in str(e.value)
    assert [r for r in _rows() if r.get("action") == "core.refuse"][-1]["detail"]["state"] == "unknown"


def test_an_unreadable_map_names_the_failure_by_type_not_by_text(armed_plane, monkeypatch):
    _, run = _pve(monkeypatch, armed_plane, [], RuntimeError("https://secret.invalid/token=abc123"))
    with pytest.raises(ProximoError) as e:
        run()
    assert "RuntimeError" in str(e.value) and "abc123" not in str(e.value) and "secret.invalid" not in str(e.value)


@pytest.mark.parametrize("args,judged", [
    ({"content": "backup"}, True),
    ({}, True),                                  # no filter lists every kind, backups among them
    ({"content": "iso"}, False),                 # a question about something PVE never hides
    ({"content": "vztmpl"}, False),
])
def test_only_a_question_about_backups_is_judged(armed_plane, monkeypatch, args, judged):
    w, run = _pve(monkeypatch, armed_plane, [], {"/": {"Datastore.Audit": 1}}, args=args)
    if judged:
        with pytest.raises(ProximoError):
            run()
    else:
        assert run()["data"] == []
    assert w.read_permissions is judged


# --- PBS: the datastore's groups and snapshots ------------------------------------------------

@pytest.mark.parametrize("tail", ["snapshots", "groups"])
def test_an_empty_pbs_list_from_a_backup_only_token_is_refused(pbs_plane, monkeypatch, tail):
    w, run = _pbs(monkeypatch, pbs_plane, tail, [], {"/datastore/ds": {"Datastore.Backup": True}})
    with pytest.raises(ProximoError) as e:
        run()
    said = str(e.value)
    assert "Datastore.Audit" in said and "/datastore/ds" in said and len(said) < 600
    assert w.read_permissions


@pytest.mark.parametrize("tail", ["snapshots", "groups"])
@pytest.mark.parametrize("perms", [
    {"/datastore/ds": {"Datastore.Audit": True}},
    {"/datastore": {"Datastore.Audit": True}},        # an ancestor that propagates
    {"/": {"Datastore.Audit": True, "Datastore.Backup": True}},
])
def test_an_empty_pbs_list_from_an_auditing_token_is_served(pbs_plane, monkeypatch, tail, perms):
    _, run = _pbs(monkeypatch, pbs_plane, tail, [], perms)
    assert run()["data"] == []


@pytest.mark.parametrize("tail", ["snapshots", "groups"])
def test_the_namespace_is_judged_at_its_own_path(pbs_plane, monkeypatch, tail):
    held_on_the_datastore = {"/datastore/ds": {"Datastore.Audit": True}}      # reaches a child: propagates
    _, run = _pbs(monkeypatch, pbs_plane, tail, [], held_on_the_datastore, args={"ns": "team/prod"})
    assert run()["data"] == []
    elsewhere = {"/datastore/ds/other": {"Datastore.Audit": True}, "/datastore/ds/team": {"Datastore.Backup": True}}
    _, run = _pbs(monkeypatch, pbs_plane, tail, [], elsewhere, args={"ns": "team/prod"})
    with pytest.raises(ProximoError, match="/datastore/ds/team/prod"):
        run()


def test_a_filtered_empty_snapshot_list_is_judged_too(pbs_plane, monkeypatch):
    _, run = _pbs(monkeypatch, pbs_plane, "snapshots", [], {"/datastore/ds": {"Datastore.Backup": True}},
                  args={"backup-type": "vm", "backup-id": "999"})
    with pytest.raises(ProximoError, match="Datastore.Audit"):
        run()


@pytest.mark.parametrize("perms", [RuntimeError("403"), {}, []])
def test_an_unreadable_pbs_map_does_not_vouch_for_the_empty_list(pbs_plane, monkeypatch, perms):
    _, run = _pbs(monkeypatch, pbs_plane, "groups", [], perms)
    with pytest.raises(ProximoError, match="not vouched"):
        run()


# --- the lens: what a value, a prefix or a shape could slip past --------------------------------

@pytest.mark.parametrize("content", [["backup"], ("backup",), ["backup", "iso"], 7, True, {"x": 1}])
def test_a_content_value_that_is_not_a_listed_string_is_still_asked(armed_plane, monkeypatch, content):
    """httpx sends content=backup for a one-item list; a value the guard cannot read is judged."""
    _, run = _pve(monkeypatch, armed_plane, [], {"/": {"Datastore.Audit": 1}}, args={"content": content})
    with pytest.raises(ProximoError, match="cannot see backup volumes"):
        run()


@pytest.mark.parametrize("content", [["iso"], ("vztmpl",), "iso"])
def test_a_list_of_unlisted_strings_is_not_asked(armed_plane, monkeypatch, content):
    w, run = _pve(monkeypatch, armed_plane, [], {"/": {"Datastore.Audit": 1}}, args={"content": content})
    assert run()["data"] == [] and not w.read_permissions


@pytest.mark.parametrize("empty", [None, {}, ""])
def test_every_shape_of_nothing_is_judged_as_empty(armed_plane, monkeypatch, empty):
    _, run = _pve(monkeypatch, armed_plane, empty, {"/": {"Datastore.Audit": 1}})
    with pytest.raises(ProximoError, match="cannot see backup volumes"):
        run()


def test_content_not_given_at_all_is_judged(armed_plane, monkeypatch):
    w, run = _pve(monkeypatch, armed_plane, [], {"/": {"Datastore.Audit": 1}}, args={})
    with pytest.raises(ProximoError):
        run()
    assert w.read_permissions


def test_a_grant_on_a_prefix_sibling_does_not_cover_the_storage(armed_plane, monkeypatch):
    perms = {"/storage/loc": {"Datastore.Allocate": 1}, "/vms": {"VM.Backup": 1}}
    _, run = _pve(monkeypatch, armed_plane, [], perms)
    with pytest.raises(ProximoError, match="cannot see backup volumes"):
        run()
    perms = {"/storage": {"Datastore.Allocate": 1}}                     # a real ancestor still covers it
    _, run = _pve(monkeypatch, armed_plane, [], perms)
    assert run()["data"] == []


def test_a_privilege_whose_value_is_none_is_no_grant(armed_plane, monkeypatch):
    _, run = _pve(monkeypatch, armed_plane, [], {"/storage/local": {"Datastore.Allocate": None}, "/": {"VM.Audit": 1}})
    with pytest.raises(ProximoError, match="cannot see backup volumes"):
        run()


@pytest.mark.parametrize("value", ["yes", "1", 2, -1, [1], {"a": 1}, 1.5])
def test_a_privilege_value_that_is_not_a_flag_is_not_a_permission_map(armed_plane, monkeypatch, value):
    _, run = _pve(monkeypatch, armed_plane, [], {"/storage/local": {"Datastore.Allocate": value}})
    with pytest.raises(ProximoError, match="not vouched"):
        run()


@pytest.mark.parametrize("ns", ["x/../y", "a//b", "..", ".", "/a", "a/"])
def test_a_namespace_that_is_not_a_clean_path_is_not_vouched(pbs_plane, monkeypatch, ns):
    perms = {"/datastore/ds/x": {"Datastore.Audit": True}, "/datastore/ds": {"Datastore.Backup": True}}
    _, run = _pbs(monkeypatch, pbs_plane, "groups", [], perms, args={"ns": ns})
    with pytest.raises(ProximoError, match="not vouched"):
        run()


def test_a_huge_namespace_is_never_echoed_whole(pbs_plane, monkeypatch):
    ns = "a" * 100_000
    _, run = _pbs(monkeypatch, pbs_plane, "groups", [], {"/datastore/ds": {"Datastore.Backup": True}}, args={"ns": ns})
    with pytest.raises(ProximoError) as e:
        run()
    assert len(str(e.value)) < 800 and "..." in str(e.value)
    assert len(json.dumps(_receipt("core.refuse"))) < 1500


def test_an_oversize_permission_map_is_unknown_not_judged(armed_plane, monkeypatch):
    big = {f"/vms/{i}": {"VM.Backup": 1} for i in range(40_000)}
    big["/storage/local"] = {"Datastore.Allocate": 1}
    _, run = _pve(monkeypatch, armed_plane, [], big)
    with pytest.raises(ProximoError, match="not vouched"):
        run()


# --- the record ---------------------------------------------------------------------------------

def test_the_three_shipped_lines_and_no_other_row_carries_sight():
    rows = [r for r in engine.table().values() if r.sight]
    assert sorted(r.key for r in rows) == sorted([f"pve:GET {PVE_LIST}", f"pbs:GET {SNAPSHOTS}", f"pbs:GET {GROUPS}"])
    for r in rows:
        assert r.sight["why"].strip() and r.sight["what"] and r.sight["sighted"]


def test_sight_gates_nothing_and_changes_no_verdict():
    row = engine.resolve("pve", "GET", PVE_LIST)
    assert row.access == engine.READ and row.tier is None and not row.gate


def _toml(v) -> str:
    """A value as TOML spells it inline (json.dumps spells a table with colons, which TOML refuses)."""
    if isinstance(v, dict):
        return "{ " + ", ".join(f"{json.dumps(k)} = {_toml(x)}" for k, x in v.items()) + " }"
    return "[" + ", ".join(_toml(x) for x in v) + "]" if isinstance(v, list) else json.dumps(v)


def _line(addr=f"pve:GET {PVE_LIST}", **fields):
    s = {"when": {"content": ["backup"]}, "sighted": [["Datastore.Allocate@/storage/{storage}"]],
         "what": "backup volumes", "why": "Vendor: a why of four words", **fields}
    body = ", ".join(f"{k} = {_toml(v)}" for k, v in s.items() if v is not ...)
    return f'"{addr}" = {{ {body} }}'


@pytest.mark.parametrize("line,words", [
    (_line("pve:GET /nodes/{node}/nowhere"), "matches no published address"),
    (_line("pve:POST /nodes/{node}/qemu"), "is not a read the door serves"),
    (_line(when={"nonesuch": ["backup"]}), "names nonesuch, which the address does not publish"),
    (_line(when={"storage": ["local"]}), "names storage, which the path binds"),
    (_line(when={"content": []}), "when takes parameter names and lists of values"),
    (_line(sighted=[]), "sighted is a non-empty list of alternatives"),
    (_line(sighted=[[]]), "sighted is a non-empty list of alternatives"),
    (_line(sighted=[["Datastore.Allocate"]]), "is not privilege@path"),
    (_line(sighted=[["Datastore.Allocate@storage/{storage}"]]), "is not privilege@path"),
    (_line(sighted=[["Datastore.Allocate@/storage/{nonesuch}"]]), "names {nonesuch}"),
    (_line(what="x"), "is without a what"),
    (_line(why="short"), "is without a why"),
    (_line(why=" Vendor: a why of four words"), "carries a why with space around it"),
    (_line(extra=1), "takes exactly when, sighted, what and why"),
    (_line(when=...), "takes exactly when, sighted, what and why"),
])
def test_the_build_refuses_a_line_that_would_do_nothing_or_mislead(records, line, words):
    with pytest.raises(ProximoError, match=f"sight.toml: .*{words}"):
        records(**{"sight.toml": f"[sight]\n{line}\n"})


def test_the_build_refuses_a_plane_that_publishes_no_permission_read(records, monkeypatch):
    """A line on a plane that cannot say what the token holds could never be judged: PMG and PDM
    publish their own, but a plane without the read would refuse every empty list forever."""
    vendor, real, _ = bj.read_inputs()
    cut = [r for r in vendor if (r["product"], r["method"], r["path"]) != ("pve", "GET", PERMS)]
    with pytest.raises(ProximoError, match="sight.toml: .*publishes no GET /access/permissions"):
        bj.build(cut, {**real, "sight.toml": f"[sight]\n{_line()}\n"})


def test_no_record_no_sight(records):
    table = records(**{"sight.toml": None})
    assert not any(r.sight for r in table.values())


def test_the_builds_sight_loads_and_rides_the_row(records):
    table = records(**{"sight.toml": f"[sight]\n{_line()}\n"})
    s = table[("pve", "GET", PVE_LIST)].sight
    assert s["sighted"] == (("Datastore.Allocate@/storage/{storage}",),) and s["what"] == "backup volumes"


def test_a_planted_record_changes_what_the_engine_refuses(records, armed_plane, monkeypatch):
    """The engine asks the row: a line that names a privilege this token does hold serves the list."""
    records(**{"sight.toml": f"[sight]\n{_line(sighted=[['VM.Audit@*']])}\n"})
    _, run = _pve(monkeypatch, armed_plane, [], {"/": {"VM.Audit": 1}})
    assert run()["data"] == []


# --- the loader: no line the build would not write ----------------------------------------------

def _shipped():
    return json.loads(gzip.decompress(bj.OUT.read_bytes()))


def _row(doc, product, path):
    return next(r for r in doc["rows"] if (r["product"], r["method"], r["path"]) == (product, "GET", path))


@pytest.mark.parametrize("damage", [
    lambda r: r.update(sight="yes"),                                         # not a record
    lambda r: r["sight"].update(exists=False),                               # a key no line has
    lambda r: r["sight"].update(sighted=[["Datastore.Allocate"]]),           # not privilege@path
    lambda r: r["sight"].update(when={"nonesuch": ["backup"]}),              # an unpublished name
    lambda r: r["sight"].update(why=" " + r["sight"]["why"]),                # padded: never built
    lambda r: r["sight"].update(sighted=[]),                                 # nothing would ever serve it
])
def test_a_line_the_build_would_not_write_refuses_every_address(monkeypatch, damage):
    from conftest import _clear_data_caches
    from test_proximo_json import _serve

    doc = _shipped()
    damage(_row(doc, "pve", PVE_LIST))
    _serve(monkeypatch, doc)
    try:
        with pytest.raises(ProximoError, match="proximo.json.gz"):
            engine.resolve("pve", "GET", "/version")
    finally:
        monkeypatch.undo()
        _clear_data_caches()


def test_a_line_on_a_mutation_refuses_every_address(monkeypatch):
    from conftest import _clear_data_caches
    from test_proximo_json import _serve

    doc = _shipped()
    post = next(r for r in doc["rows"]
                if (r["product"], r["method"], r["path"]) == ("pve", "POST", "/nodes/{node}/qemu"))
    post["sight"] = dict(_row(doc, "pve", PVE_LIST)["sight"])
    _serve(monkeypatch, doc)
    try:
        with pytest.raises(ProximoError, match="proximo.json.gz"):
            engine.resolve("pve", "GET", "/version")
    finally:
        monkeypatch.undo()
        _clear_data_caches()
