"""proximo_find: the operator's words to the published address (parity row B10).

A small local model cannot do a job whose address it cannot find. Matching every word
against the path found the right address first 38% of the time on 0.44's own tool names, and
answered 2% of 0.44's own docstring sentences at all (2026-09-29). The gate below holds the new
search to the 0.44 vocabulary, per plane (a slice install) and without one (the bundle), and a
control proves the gate can fail: the old every-word rule, run through the same gate, does.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from proximo.core import apitree, engine, search
from proximo.core.doors import mcp as door
from proximo.core.errors import ProximoError

BENCH = json.loads((pathlib.Path(__file__).parent / "fixtures" / "find-bench-0.44.json").read_text())

#: measured 2026-09-29, hit@5 over all 449 cases, (plane, bundle): the floor (every word in the
#: path) names 50/46, lines 2/2; this search names 94/90, lines 86/84, and on the held-out half
#: no tuning ever read, names 94/91, lines 82/81. The gate sits under both, far over the floor.
GATE = {("name", True): 0.88, ("name", False): 0.84, ("line", True): 0.78, ("line", False): 0.77}


def _hit5(field: str, with_plane: bool, find=door.find) -> float:
    hits = 0
    for c in BENCH["cases"]:
        got = find(c[field], plane=c["plane"] if with_plane else None, limit=5)["matches"]
        hits += (c["method"], c["path"]) in [(m["method"], apitree.norm(m["path"])) for m in got]
    return hits / len(BENCH["cases"])


@pytest.mark.parametrize("field,with_plane", list(GATE))
def test_the_04_vocabulary_finds_its_address(field, with_plane):
    assert len(BENCH["cases"]) == 449 and BENCH["source"].startswith("v0.44.0")
    got = _hit5(field, with_plane)
    assert got >= GATE[(field, with_plane)], f"{field} {'plane' if with_plane else 'bundle'}: hit@5 {got:.0%}"


def test_the_gate_fails_the_old_every_word_rule():
    """The control: the pre-2026-09-29 contract (every word in the path) through the same gate."""
    def every_word(query, plane=None, limit=5):
        try:
            return search.find(query, plane=plane, limit=limit, strict=True)
        except ProximoError:
            return {"matches": []}
    assert _hit5("name", True, every_word) < GATE[("name", True)]
    assert _hit5("line", True, every_word) < GATE[("line", True)]


# --- the cases a lens named, and the rules, each on its own -------------------------------------

def _addrs(out):
    return [(m["plane"], m["method"], m["path"]) for m in out["matches"]]


def test_guest_status_finds_both_kinds_of_guest():
    got = _addrs(door.find("guest status", plane="pve"))
    assert ("pve", "GET", "/nodes/{node}/qemu/{vmid}/status") in got
    assert ("pve", "GET", "/nodes/{node}/lxc/{vmid}/status") in got


def test_node_status_on_a_plane_is_the_nodes_status():
    assert _addrs(door.find("node status", plane="pve"))[0] == ("pve", "GET", "/nodes/{node}/status")


def test_on_the_bundle_a_question_every_plane_answers_says_so():
    out = door.find("node status")
    assert len(out["planes"]) > 1 and "name the plane" in out["note"]
    assert "planes" not in door.find("node status", plane="pve")


def test_a_verb_picks_the_method():
    assert _addrs(door.find("delete user", plane="pbs"))[0][1] == "DELETE"
    assert _addrs(door.find("list users", plane="pbs"))[0][1] == "GET"


def test_plurals_fold_and_a_parenthetical_or_a_possessive_is_not_a_word():
    assert _addrs(door.find("list datastores", plane="pbs"))[0][2] in ("/admin/datastore", "/config/datastore")
    assert _addrs(door.find("get a PBS user's config (userid, enable, expire)", plane="pbs"))[0] == \
        ("pbs", "GET", "/access/users/{userid}")


@pytest.mark.parametrize("plural,singular", [("nodes", "node"), ("statuses", "status"), ("boxes", "box"),
                                             ("entries", "entry"), ("datastores", "datastore"),
                                             ("viruses", "virus"), ("addresses", "address")])
def test_a_plural_and_its_singular_fold_to_one_word(plural, singular):
    assert search.stem(plural) == search.stem(singular)


def test_nonsense_finds_nothing_rather_than_a_handful_of_junk():
    out = door.find("zxqv wombat")
    assert out["matches"] == [] and "no published address matched" in out["note"]


def test_a_word_the_table_spells_is_never_filler():
    assert not (search._stopwords() & {t for _, segs, _, _ in search._index() for t in segs})
    assert "current" in search._STOP and "current" not in search._stopwords()     # the control


def test_the_descriptions_never_ship_in_the_answer():
    m = door.find("list datastores", plane="pbs")["matches"][0]
    assert set(m) == {"plane", "method", "path", "access", "tier", "why", "params"}


def test_every_row_of_the_table_has_the_vendors_sentence_or_none_published():
    desc = search.descriptions()
    rows = {(r.product, r.method, r.path) for r in engine.table().values()}
    assert rows == set(desc), sorted(rows ^ set(desc))[:5]
    assert sum(1 for v in desc.values() if v) >= 1780


# --- the vocabulary record ----------------------------------------------------------------------

def test_every_synonym_means_a_word_the_table_spells():
    segs = {t for _, s, _, _ in search._index() for t in s}
    for word, means in search.synonyms().items():
        assert {search.stem(m) for m in means} <= segs, word


@pytest.mark.parametrize("body", [
    b'[synonym]\nguest = { means = ["qemu"] }\n',
    b'[synonym]\nguest = { means = [], why = "x y z" }\n',
])
def test_a_synonym_without_a_why_or_a_meaning_is_refused(monkeypatch, body):
    class _File:
        def joinpath(self, _name):
            return self

        def read_text(self):
            return body.decode()

    monkeypatch.setattr(search.resources, "files", lambda _pkg: _File())
    search.synonyms.cache_clear()
    try:
        with pytest.raises(ProximoError, match="without a why or a meaning"):
            search.synonyms()
    finally:
        search.synonyms.cache_clear()


# --- plan acts on words: it must never land on a different address -------------------------------

def _wrong_singles(query_of) -> list[tuple[str, str, str, str]]:
    wrong = []
    for r in engine.table().values():
        words = " ".join(s for s in r.path.strip("/").split("/") if s and not s.startswith("{"))
        if not words:
            continue
        try:
            out = door.words_to_address(r.product, r.method, query_of(r, words).split())
        except ProximoError:          # every word is filler ("/" and the like): no match, no plan
            continue
        if out.get("total") == 1 and (out["matches"][0]["method"], out["matches"][0]["path"]) != (r.method, r.path):
            wrong.append((r.product, r.method, r.path, out["matches"][0]["path"]))
    return wrong


def test_planning_an_address_by_its_own_words_never_lands_on_another():
    """Over the WHOLE table: an address's own path words, with its method, resolve to that address
    or to a choice, never silently to a different one. Lens 2026-09-29: the literal "post" was a
    word to find, so "POST create subscription keys" planned /auto-install/prepared."""
    assert _wrong_singles(lambda r, words: words) == []


def test_the_control_the_sweep_sees_a_wrong_single(monkeypatch):
    """The sweep is not vacuous: a find that answers ONE address with another, singly, is caught."""
    real = search.find

    def misplans(query, plane=None, limit=5, *, strict=False, method=None):
        out = real(query, plane=plane, limit=limit, strict=strict, method=method)
        if query == "subscriptions keys" and method == "POST" and plane == "pdm":
            return {"matches": [{"method": "POST", "path": "/auto-install/prepared"}], "total": 1}
        return out

    monkeypatch.setattr(search, "find", misplans)
    assert _wrong_singles(lambda r, words: words) == [("pdm", "POST", "/subscriptions/keys", "/auto-install/prepared")]


def test_plan_on_words_gives_a_choice_rather_than_a_guess():
    out = door.plan("pdm", "POST", "create subscription keys")
    assert "address" not in out
    assert ("POST", "/subscriptions/keys") in [(m["method"], m["path"]) for m in out["matches"]]
