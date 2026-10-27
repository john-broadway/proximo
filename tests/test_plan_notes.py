"""Plan notes (records/notes.toml): a consequence the tier cannot say, shown by the plan and kept
on the receipt (#100 finding 1, a regression of #82, 2026-10-24).

A restore from a backup without `unique` keeps the archive's MAC (and on QEMU its SMBIOS UUID):
right for a rebuild in place, two guests with one identity for a copy. 0.44.2 defaulted
`unique=1`; the core does not change what the vendor's call does, so the plan says it instead.
Measured on a PVE 9.2.2 lab node through the shell door on 2026-10-24: the restore without
`unique` came back with the source's MAC and SMBIOS UUID, `unique=1` with new ones.

A note's condition reads the call's own arguments, nothing else: it never reads, never gates,
and is judged the same armed, unarmed or with no credential at all.
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

QEMU, LXC = "/nodes/{node}/qemu", "/nodes/{node}/lxc"
ARCHIVE = "local:backup/vzdump-qemu-100-2026_10_24-00_00_00.vma.zst"


class Wire:
    """Every GET answers the node's guest list (the create's twin); every POST answers nothing."""

    def __init__(self, guests=()):
        self.guests = list(guests)
        self.calls: list[tuple[str, str, dict]] = []

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        return self.guests if method == "GET" else None


def _rows() -> list[dict]:
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def _says(out) -> list[str]:
    return [n["says"] for n in out.get("notes", [])]


# --- the shipped lines -------------------------------------------------------------------------

def test_the_two_shipped_lines_are_the_restores():
    q, x = engine.resolve("pve", "POST", "/nodes/n/qemu"), engine.resolve("pve", "POST", "/nodes/n/lxc")
    assert [(n["given"], n["not_given"]) for n in q.notes] == [(("archive",), ("unique",))]
    assert [(n["given"], n["not_given"]) for n in x.notes] == [(("restore",), ("unique",))]
    assert "MAC and SMBIOS UUID" in q.notes[0]["says"] and "SMBIOS" not in x.notes[0]["says"]
    assert all(n["why"] for n in (*q.notes, *x.notes))
    # every other row carries none but the four rollbacks (tests/test_rollback_note.py): a note
    # is judged by name, one address at a time
    assert sum(bool(r.notes) for r in engine.table().values()) == 2 + 4


# --- the plan --------------------------------------------------------------------------------

@pytest.mark.parametrize("args,shown", [
    ({"vmid": 10001, "archive": ARCHIVE}, True),
    ({"vmid": 10001, "archive": ARCHIVE, "unique": 0}, True),
    ({"vmid": 10001, "archive": ARCHIVE, "unique": "0"}, True),
    ({"vmid": 10001, "archive": ARCHIVE, "unique": False}, True),
    ({"vmid": 10001, "archive": ARCHIVE, "unique": ""}, True),
    ({"vmid": 10001, "archive": ARCHIVE, "unique": "off"}, True),
    ({"vmid": 10001, "archive": ARCHIVE, "unique": "No"}, True),
    ({"vmid": 10001, "archive": ARCHIVE, "unique": 1}, False),
    ({"vmid": 10001, "archive": ARCHIVE, "unique": "1"}, False),
    ({"vmid": 10001, "archive": ARCHIVE, "unique": True}, False),
    ({"vmid": 10001, "archive": ARCHIVE, "force": 1}, True),        # in place or onto another id: it names both
    ({"vmid": 10001, "archive": ""}, False),                         # no archive: a create, not a restore
    ({"vmid": 10001, "memory": 512}, False),
])
def test_a_qemu_restore_without_unique_carries_the_note(armed_plane, monkeypatch, args, shown):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Wire())
    row = engine.resolve("pve", "POST", QEMU)
    out = engine.plan(row, args, "/nodes/pve1/qemu", cfg=armed_plane)
    assert ("notes" in out) is shown
    if shown:
        assert out["notes"] == [{"says": row.notes[0]["says"], "why": row.notes[0]["why"]}]
        assert "unique=1" in out["notes"][0]["says"]


@pytest.mark.parametrize("args,shown", [
    ({"vmid": 201, "ostemplate": "local:backup/vzdump-lxc-200.tar.zst", "restore": 1}, True),
    ({"vmid": 201, "ostemplate": "local:backup/vzdump-lxc-200.tar.zst", "restore": 1, "unique": 1}, False),
    ({"vmid": 201, "ostemplate": "local:vztmpl/debian-13.tar.zst"}, False),          # a create from a template
    ({"vmid": 201, "ostemplate": "local:vztmpl/debian-13.tar.zst", "restore": 0}, False),
])
def test_an_lxc_restore_without_unique_carries_the_note(armed_plane, monkeypatch, args, shown):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Wire())
    out = engine.plan(engine.resolve("pve", "POST", LXC), args, "/nodes/pve1/lxc", cfg=armed_plane)
    assert ("notes" in out) is shown


def test_the_note_is_the_same_unarmed_and_with_no_credential(monkeypatch):
    """A plan is never quieter for knowing less: the condition reads the arguments alone."""
    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_TOKEN_PATH"):
        monkeypatch.delenv(var, raising=False)
    row = engine.resolve("pve", "POST", QEMU)
    out = engine.plan(row, {"vmid": 10001, "archive": ARCHIVE}, "/nodes/pve1/qemu")
    assert out["allowed"] is False                                        # refused: not armed
    assert "credential" in json.dumps(out["current"])                     # and nothing read
    assert _says(out) == [row.notes[0]["says"]]


def test_the_note_is_the_same_when_the_targets_read_is_refused(armed_plane, monkeypatch):
    class Down(Wire):
        def call(self, method, path, params=None):
            raise OSError("no route")

    monkeypatch.setattr(engine, "_client", lambda product, c=None: Down())
    row = engine.resolve("pve", "POST", QEMU)
    out = engine.plan(row, {"vmid": 10001, "archive": ARCHIVE}, "/nodes/pve1/qemu", cfg=armed_plane)
    assert _says(out) == [row.notes[0]["says"]]


def test_a_template_path_plan_still_carries_the_note():
    row = engine.resolve("pve", "POST", QEMU)
    assert _says(engine.plan(row, {"archive": ARCHIVE})) == [row.notes[0]["says"]]


def test_a_note_gates_nothing(armed_plane, monkeypatch):
    """Advice, not a verdict: with and without the note, the same answer to may-it-run."""
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Wire())
    row = engine.resolve("pve", "POST", QEMU)
    a = engine.plan(row, {"vmid": 10001, "archive": ARCHIVE}, "/nodes/pve1/qemu", cfg=armed_plane)
    b = engine.plan(row, {"vmid": 10001, "archive": ARCHIVE, "unique": 1}, "/nodes/pve1/qemu", cfg=armed_plane)
    assert a["allowed"] is True
    assert (a["allowed"], a["reason"], a["needs"]) == (b["allowed"], b["reason"], b["needs"])


# --- one reading: the plan and the receipt judge the same call the same way (lens 1, BLOCKING) ----
# The plan read `unique=n` as given (no note) while `coerce_args` sent the vendor `unique=False`
# and the guest kept its identity. Both now read a boolean through `bool_word`.

_SPELLINGS = [  # (unique, the note shows)
    ("n", True), ("f", True), (" N ", True), ("off", True), ("0", True), ("", True), ("no", True),
    ("false", True), (False, True), (0, True),
    ("y", False), ("t", False), ("1 ", False), (" TRUE", False), ("on", False), ("yes", False), ("true", False),
    ("1", False), (True, False), (1, False),
    (2, True), (-1, True), (1.0, True), ([1], True), ("0.0", True), ("maybe", True),   # cannot be told: shown
]


@pytest.mark.parametrize("unique,shown", _SPELLINGS)
def test_the_plan_and_the_receipt_read_unique_the_same_way(armed_plane, monkeypatch, unique, shown):
    w = Wire()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    row = engine.resolve("pve", "POST", QEMU)
    args = {"vmid": 10001, "archive": ARCHIVE, "unique": unique}
    planned = "notes" in engine.plan(row, args, "/nodes/pve1/qemu", cfg=armed_plane)
    assert planned is shown
    try:
        engine.execute(row, args, cfg=armed_plane, path="/nodes/pve1/qemu")
    except ProximoError:
        # refused before the wire, and ONLY for a value nobody reads as a boolean (lens 2: a word
        # dropped from the vocabulary was refused here and the test stayed green)
        assert isinstance(unique, list) or (isinstance(unique, str) and engine.bool_word(unique) is None)
        assert shown
        return
    executing = [r for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "executing"]
    assert ("notes" in executing[0]["detail"]) is planned               # the receipt agrees with the plan
    sent = next(a for m, _, a in w.calls if m == "POST")
    if planned:      # every call the plan stayed quiet on sends the vendor a true unique
        return
    assert sent.get("unique") in (True, 1)


@pytest.mark.parametrize("archive,shown", [("0", True), ("false", True), ("-", True), (" ", False), ("", False)])
def test_archive_is_a_string_any_value_is_a_restore(armed_plane, monkeypatch, archive, shown):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Wire())
    out = engine.plan(engine.resolve("pve", "POST", QEMU), {"vmid": 10001, "archive": archive}, "/nodes/pve1/qemu",
                      cfg=armed_plane)
    assert ("notes" in out) is shown


def test_notes_come_back_in_authored_order(records):
    first, second = _line(given=["archive"], not_given=[], says="the first note says this"), \
        _line(given=["archive", "force"], not_given=[], says="the second note says this")
    lines = f"{first[:-1]}, {second[second.index('[') + 1:]}"
    row = records(**{"notes.toml": f"[note]\n{lines}\n"})[("pve", "POST", QEMU)]
    held = engine.notes_held(row, {"archive": ARCHIVE, "force": 1})
    assert [n["says"] for n in held] == ["the first note says this", "the second note says this"]


def test_every_given_name_must_be_there(records):
    """`given` is each name, not any: a two-name condition with one name given shows nothing."""
    line = _line(given=["archive", "force"], not_given=[])
    row = records(**{"notes.toml": f"[note]\n{line}\n"})[("pve", "POST", QEMU)]
    assert engine.notes_held(row, {"archive": ARCHIVE}) == []
    assert engine.notes_held(row, {"archive": ARCHIVE, "force": "1"}) == [{"says": _SAYS, "why": _WHY}]


# --- the receipt -----------------------------------------------------------------------------

def test_the_executing_row_carries_the_note_that_held(armed_plane, monkeypatch):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Wire())
    row = engine.resolve("pve", "POST", QEMU)
    engine.execute(row, {"vmid": 10001, "archive": ARCHIVE}, cfg=armed_plane, path="/nodes/pve1/qemu")
    executing = [r for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "executing"]
    assert [r["detail"].get("notes") for r in executing] == [[row.notes[0]["says"]]]


def test_a_call_with_no_note_writes_no_key(armed_plane, monkeypatch):
    monkeypatch.setattr(engine, "_client", lambda product, c=None: Wire())
    row = engine.resolve("pve", "POST", QEMU)
    engine.execute(row, {"vmid": 10001, "archive": ARCHIVE, "unique": 1}, cfg=armed_plane,
                   path="/nodes/pve1/qemu")
    executing = [r for r in _rows() if r["action"] == "core.execute" and r["outcome"] == "executing"]
    assert len(executing) == 1 and "notes" not in executing[0]["detail"]


# --- the build ---------------------------------------------------------------------------------

_SAYS, _WHY = "a sentence that says it", "Vendor: a why of four words"


def _line(addr="pve:POST /nodes/{node}/qemu", **fields):
    """One notes.toml line: the good note, with `fields` changed (a value of ... drops the key)."""
    note = {"given": ["archive"], "not_given": ["unique"], "says": _SAYS, "why": _WHY, **fields}
    body = ", ".join(f"{k} = {json.dumps(v)}" for k, v in note.items() if v is not ...)
    return f'"{addr}" = [{{ {body} }}]'


@pytest.mark.parametrize("line,words", [
    (_line("pve:POST /nodes/{node}/nowhere"), "matches no published address"),
    (_line("pve:GET /nodes/{node}/qemu"), "is not a mutation the door serves"),
    (_line("pve:POST /nodes/{node}/qemu/{vmid}/agent/exec"), "is not a mutation the door serves"),
    (_line(given=["nonesuch"]), "names nonesuch, which the address does not publish"),
    (_line(given=["unique"]), "names unique in both given and not_given"),
    (_line(not_given=...), "takes exactly given, not_given, says and why"),
    (_line(says="short"), "is without a says"),
    (_line(why=""), "is without a why"),
    (_line(exists=False), "takes exactly given, not_given, says and why"),
    ('"pve:POST /nodes/{node}/qemu" = []', "is not a list of notes"),
    (_line(given="archive"), "given and not_given are lists of parameter names"),
    (_line(given=["archive", "archive"]), "names a parameter twice"),
    (_line("pve:PUT /nodes/{node}/qemu/{vmid}/config", given=["vmid"], not_given=[]),
     "names vmid, which the path binds"),
    (_line(says=" a sentence that says it"), "carries a says with space around it"),
    (_line(why="Vendor: a why of four words "), "carries a why with space around it"),
    (f"{_line()[:-1]}, {_line()[_line().index('[') + 1:]}", "carries two notes with one condition"),
])
def test_the_build_refuses_a_note_that_would_do_nothing_or_mislead(records, line, words):
    with pytest.raises(ProximoError, match=f"notes.toml: .*{words}"):
        records(**{"notes.toml": f"[note]\n{line}\n"})


def _always(addr="pve:PUT /nodes/{node}/qemu/{vmid}/config", **fields):
    note = {"always": True, "says": _SAYS, "why": _WHY, **fields}
    body = ", ".join(f"{k} = {json.dumps(v)}" for k, v in note.items() if v is not ...)
    return f'"{addr}" = [{{ {body} }}]'


def test_a_note_that_says_always_is_on_for_every_call(records):
    """On for every call is written out, `always = true`, never left to an empty condition."""
    row = records(**{"notes.toml": f"[note]\n{_always()}\n"})[("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config")]
    assert engine.notes_held(row, {}) == [{"says": _SAYS, "why": _WHY}]
    assert engine.notes_held(row, {"memory": 512}) == [{"says": _SAYS, "why": _WHY}]
    assert row.notes[0]["always"] is True


@pytest.mark.parametrize("line,words", [
    (_line(given=[], not_given=[]), "has no condition; a note that holds for every call says `always = true`"),
    (_always(always=False), "says always but not `always = true`"),
    (_always(always="yes"), "says always but not `always = true`"),
    (_always(given=["memory"]), "takes exactly"),
    (_always(not_given=[]), "takes exactly"),
    (_always(says=...), "takes exactly"),
    (_always(says="short"), "is without a says"),
    (_always("pve:GET /nodes/{node}/qemu"), "is not a mutation the door serves"),
])
def test_the_build_refuses_an_always_note_that_is_not_written_out(records, line, words):
    with pytest.raises(ProximoError, match=f"notes.toml: .*{words}"):
        records(**{"notes.toml": f"[note]\n{line}\n"})


def test_two_always_notes_on_one_address_are_refused(records):
    one = _always()
    two = f"{one[:-1]}, {one[one.index('[') + 1:]}"
    with pytest.raises(ProximoError, match="notes.toml: .*carries two notes with one condition"):
        records(**{"notes.toml": f"[note]\n{two}\n"})


def test_an_always_note_beside_a_conditional_one_is_allowed(records):
    one, two = _always(), _line("pve:PUT /nodes/{node}/qemu/{vmid}/config", given=["memory"], not_given=[])
    row = records(**{"notes.toml": f"[note]\n{one[:-1]}, {two[two.index('[') + 1:]}\n"})[
        ("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config")]
    assert len(engine.notes_held(row, {"memory": 1})) == 2 and len(engine.notes_held(row, {})) == 1


def test_no_record_no_notes(records):
    table = records(**{"notes.toml": None})
    assert not any(r.notes for r in table.values())


def test_the_builds_notes_load_and_ride_the_row(records):
    line = _line("pve:PUT /nodes/{node}/qemu/{vmid}/config", given=["memory"], not_given=[])
    table = records(**{"notes.toml": f"[note]\n{line}\n"})
    row = table[("pve", "PUT", "/nodes/{node}/qemu/{vmid}/config")]
    assert row.notes == ({"given": ("memory",), "not_given": (), "says": _SAYS, "why": _WHY},)


# --- the loader: no note the build would not write ---------------------------------------------

def _shipped():
    import gzip
    return json.loads(gzip.decompress(bj.OUT.read_bytes()))


def _restore(rows):
    return next(r for r in rows if (r["product"], r["method"], r["path"]) == ("pve", "POST", QEMU))


@pytest.mark.parametrize("damage", [
    lambda r: r.update(notes=None),                                                   # not a list
    lambda r: r["notes"][0].update(exists=False),                                     # a key no note has
    lambda r: r["notes"][0].update(given=["nonesuch"]),                               # an unpublished name
    lambda r: r["notes"][0].update(says=7),                                           # not a sentence
    lambda r: r["notes"][0].update(given=[], not_given=[]),                           # no condition, not always
    lambda r: r["notes"][0].update(always=True),                                      # both shapes at once
    lambda r: r["notes"][0].update(not_given=["archive"]),                            # a name on both sides
    lambda r: r["notes"][0].update(says=" " + r["notes"][0]["says"]),                  # padded: never built
    lambda r: r["notes"][0].update(given=["node"]),                                   # a name the path binds
    lambda r: r["notes"].append(dict(r["notes"][0])),                                 # two notes, one condition
])
def test_a_note_the_build_would_not_write_refuses_every_address(monkeypatch, damage):
    from conftest import _clear_data_caches
    from test_proximo_json import _serve

    doc = _shipped()
    damage(_restore(doc["rows"]))
    _serve(monkeypatch, doc)
    try:
        with pytest.raises(ProximoError, match="proximo.json.gz"):
            engine.resolve("pve", "GET", "/version")
    finally:
        monkeypatch.undo()
        _clear_data_caches()


def test_a_note_on_a_read_refuses_every_address(monkeypatch):
    from conftest import _clear_data_caches
    from test_proximo_json import _serve

    doc = _shipped()
    read = next(r for r in doc["rows"] if (r["product"], r["method"], r["path"]) == ("pve", "GET", QEMU))
    read["notes"] = [dict(_restore(doc["rows"])["notes"][0], given=[], not_given=["full"])]
    _serve(monkeypatch, doc)
    try:
        with pytest.raises(ProximoError, match="carries a note"):
            engine.resolve("pve", "GET", "/version")
    finally:
        monkeypatch.undo()
        _clear_data_caches()
