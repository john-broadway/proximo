"""lexical-find: proximo_find understands an operator's words with no model (capability row
`lexical-find`, ported from 0.44's test_lexical.py).

Two tiers behind the word tier, neither a model:

  1. THE VOCABULARY (`records/vocab.toml`): operator words onto the words the vendor spells, each
     line quoting the vendor's own use of the word. 0.44 measured this table, not the n-grams, as
     what moved "memory usage of a container" from a miss to a hit.
  2. CHARACTER 3/4-GRAMS (`core/lexical.py`), TF-IDF over the words the table spells: a typo or an
     unseen spelling lands. It ranks ONLY what the word tier left unanswered, its answer marked
     `"match": "lexical"`, and a nonsense query still returns nothing.
"""
from __future__ import annotations

import json
import re

import pytest

from proximo.core import apitree, lexical, search
from proximo.core.doors import mcp as door
from proximo.core.errors import ProximoError


def _addrs(out):
    return [(m["plane"], m["method"], m["path"]) for m in out["matches"]]


# --- the vocabulary: operator words onto the vendor's, the 0.44 probes ----------------------------

def test_memory_usage_of_a_container_reaches_the_containers_status():
    """0.44's headline probe. Before the vocabulary the top five were a probe, a node status and a
    create; the container's own status was not among them."""
    got = _addrs(door.find("memory usage of a container", plane="pve"))
    assert ("pve", "GET", "/nodes/{node}/lxc/{vmid}/status/current") in got


@pytest.mark.parametrize("words,plane,address", [
    ("node stats", "pbs", ("pbs", "GET", "/nodes/{node}/rrd")),
    ("system log", "pmg", ("pmg", "GET", "/nodes/{node}/syslog")),
    ("cpu of the node", "pbs", ("pbs", "GET", "/nodes/{node}/status")),
    ("permission", "pve", ("pve", "GET", "/access/acl")),
])
def test_an_operators_word_reaches_the_address_the_vendor_spells(words, plane, address):
    assert address in _addrs(door.find(words, plane=plane))


def test_a_vocabulary_answer_is_the_word_tiers_and_carries_no_lexical_mark():
    out = door.find("memory usage of a container", plane="pve")
    assert all("match" not in m for m in out["matches"]) and "guessed" not in out


def _vendor_texts() -> set[str]:
    import gzip
    import pathlib
    rows = json.loads(gzip.open(pathlib.Path(__file__).parent.parent / "records" / "vendor.json.gz").read())
    out = set()
    for r in rows:
        out.add((r["description"] or "").lower())
        out.update((p.get("description") or "").lower() for p in r["params"].values())
    return out


_QUOTE = re.compile(r"(?:^|[\s(])'(.+?)'(?=$|[\s,;.)])")


def test_every_quoted_why_is_a_sentence_the_vendor_published():
    """The record's rule was a promise in prose; this makes it a check. Every 'quoted' fragment of a
    `why` must occur in an operation's or a parameter's published description."""
    texts = _vendor_texts()
    doc = apitree.published()["vocab"]
    assert len(doc) >= 16
    missing = []
    for line in doc:
        quotes = _QUOTE.findall(line["why"])
        if not quotes:
            missing.append((line["word"], "no quoted vendor text"))
        for q in quotes:
            if not any(q.lower().rstrip(".") in t for t in texts):
                missing.append((line["word"], q))
    assert missing == []


def test_the_quote_check_can_fail():
    """The control: a why that invents a vendor sentence is what the check above reports."""
    texts = _vendor_texts()
    q = _QUOTE.findall("PVE: 'Free space left on the storage.'")[0]
    assert not any(q.lower().rstrip(".") in t for t in texts)


# --- the n-gram tier ------------------------------------------------------------------------------

@pytest.mark.parametrize("typo,landed", [
    ("snaphsot", "snapshot"),
    ("datastroes", "datastore"),
    ("firwall", "firewall"),
    ("backpu", "backup"),
])
def test_a_typo_still_lands_and_says_what_it_heard(typo, landed):
    """0.44's 'snaphsot' class. The word tier answers nothing for these."""
    assert door.find(typo)["matches"][0]["path"]            # answered at all
    out = door.find(typo)
    assert out["matches"] and all(m["match"] == "lexical" for m in out["matches"])
    assert out["guessed"] == {typo: landed}
    assert all(landed in m["path"] for m in out["matches"])


def test_a_typo_beside_a_verb_and_a_synonym_composes_with_the_word_tier():
    out = door.find("list snaphsots of a container", plane="pve")
    assert ("pve", "GET", "/nodes/{node}/lxc/{vmid}/snapshot") in _addrs(out)
    assert out["matches"][0]["method"] == "GET"


def test_a_typo_of_a_vocabulary_word_is_read_as_the_word():
    """`memroy` is neither a path word nor a synonym key; its neighbour `memory` is a key, so the
    vocabulary's `means` come with it."""
    out = door.find("memroy usage of container", plane="pve")
    assert out["guessed"] == {"memroy": "memory"}
    assert ("pve", "GET", "/nodes/{node}/lxc/{vmid}/status/current") in _addrs(out)


def test_datastores_is_the_word_tiers_and_needs_no_lexical_help():
    """0.44's plural probe: the plural fold answers it, so the n-grams are never asked."""
    out = door.find("datastores", plane="pbs")
    assert out["matches"][0]["path"] in ("/admin/datastore", "/config/datastore")
    assert all("match" not in m for m in out["matches"])


@pytest.mark.parametrize("nonsense", [
    "zxqv wombat",
    "asdfgh qwerty zxcvb",
    "recipe for banana bread",          # 0.44's lens: shared a 3-gram with `wipe`, offered wipedisk
    "weather forecast tomorrow",         # `weather` is 0.67 cosine from `rather`: a near word, not a typo
    "kubernetes pizza",
])
def test_nonsense_still_returns_nothing(nonsense):
    out = door.find(nonsense)
    assert out["matches"] == [] and "no published address matched" in out["note"] and "guessed" not in out


def test_the_typo_shapes_are_what_keeps_a_near_word_out_of_the_answer():
    """THE CONTROL on the line above: the n-gram score alone passes `weather` -> `rather` (so a floor
    on cosine cannot be the whole defence), and only a slip of the fingers is accepted."""
    ix = search._lexical_index()
    best = ix.neighbours("weather")[0]
    assert best[1] == "rather" and best[0] >= lexical.MIN_SIMILARITY
    assert ix.repair("weather") is None
    assert lexical.is_typo("snaphsot", "snapshot")                     # neighbours swapped
    assert lexical.is_typo("firwall", "firewall") and lexical.is_typo("snapshoot", "snapshot")
    assert lexical.is_typo("storagr", "storage")                       # r is beside e
    assert not lexical.is_typo("storagx", "storage")                   # x is not
    assert not lexical.is_typo("router", "route") and not lexical.is_typo("routes", "route")   # an end
    assert not lexical.is_typo("nsapshot", "snapshot")                 # the first letter is right


@pytest.mark.parametrize("length", [6, 8, 9, 12])
def test_one_slip_is_read_at_any_length_and_two_are_not(length, monkeypatch):
    """The bound is one slip at EVERY length (the first version allowed two beyond eight letters and
    read 2,678 real words as typos). Boundary lengths, built on a synthetic index."""
    monkeypatch.setattr(lexical, "MIN_SIMILARITY", 0.0)         # this is the bound's test, not the floor's
    word = "q" + "abcdefghijkl"[: length - 1]
    ix = lexical.WordIndex([word, "unrelated", "another", "thing"])
    one = word[:2] + word[3] + word[2] + word[4:]
    assert ix.repair(one) == word
    two = word[:2] + word[3] + word[2] + word[5] + word[4] + word[6:]
    assert length < 8 or ix.repair(two) is None


def test_a_plural_typo_is_read_through_its_stem():
    """`firwalls` is two slips from `firewall` as said (an `s` and the missing `e`) and one from its
    stem. The stem is what is repaired; mutant: repairing the word as said."""
    out = door.find("firwalls")
    assert out["guessed"] == {"firwalls": "firewall"} and out["matches"]
    assert door.find("snaphsots")["guessed"] == {"snaphsots": "snapshot"}


def test_tf_is_logarithmic():
    """`(1 + log tf) * idf`, checked against the formula written out here, not the module's."""
    import math
    words = ["banana", "cabana", "zebra"]
    ix = lexical.WordIndex(words)
    grams = lexical._grams

    def vec(w):
        return {g: (1 + math.log(k)) * ix._idf.get(g, 1.0) for g, k in grams(w).items()}
    q, d = vec("banano"), vec("banana")
    want = sum(q[g] * d.get(g, 0) for g in q) / (math.hypot(*q.values()) * math.hypot(*d.values()))
    got = dict((w, s) for s, w in ix.neighbours("banano", top=3))["banana"]
    assert got == pytest.approx(want)


# --- the lens's findings: a guess is labelled, weaker, and never an identifier -----------------------

@pytest.mark.parametrize("word", ["storage01", "proxy1", "backup01", "pve1node", "vmid100", "snap1shot", "fire1wall"])
def test_a_word_with_a_digit_is_an_identifier_and_never_repaired(word):
    assert search._lexical_index().repair(word) is None
    assert "guessed" not in door.find(f"list {word}")


@pytest.mark.parametrize("real", ["unverified", "implicitly", "production", "portainer", "router", "president"])
def test_a_real_english_word_the_table_does_not_spell_is_not_read_as_another(real):
    """The lens's own examples (each was read as a different word)."""
    assert search._lexical_index().repair(real) is None


def test_what_the_operator_said_stays_beside_the_guess():
    """`integrations` is read as `iteration` by the first version, which REPLACED the word and lost
    the address the bench expects. Now the word stays and a guess only adds a weaker landing."""
    terms, methods, _, said = search._terms("list SDN dns integrations")
    kept, _, _ = search._hear(terms, said, methods)
    assert [(alts, own) for alts, own, _ in kept] == [(alts, own) for alts, own, _ in terms]


def test_a_guess_weighs_less_than_the_same_landing_of_a_word_said():
    def hit(term):
        return [h for h in search._rank([term], set(), "pve", None, False)
                if h.row.path == "/nodes/{node}/lxc/{vmid}/snapshot" and h.row.method == "GET"][0]
    said = hit((frozenset({"snapshot"}), frozenset({"snapshot"}), frozenset()))
    guess = hit((frozenset({"snaphsot"}), frozenset({"snaphsot"}), frozenset({"snapshot"})))
    assert guess.guessed and not said.guessed and guess.score == said.score - 1


@pytest.mark.parametrize("word", ["restarting", "destroyed", "stopped", "listing", "migrating", "creation"])
def test_a_folded_verb_is_not_a_word_to_find_and_never_picks_the_method(word):
    """Only a verb the operator LITERALLY said picks the method. A gerund, a participle or a -tion
    noun that folds to a verb is read as description (`snapshot creation` asks about a snapshot)."""
    terms, methods, _, said = search._terms(f"{word} container")
    kept, after, guessed = search._hear(terms, said, methods)
    assert after == methods == set() and len(kept) == 1 and word in guessed


@pytest.mark.parametrize("question", [
    "snapshot creation", "which backups were deleted", "datastore stopped",
    "container restarting", "snapshot ordering", "list deleted", "show stopped"])
def test_a_folded_word_never_ranks_a_mutation_first_on_a_read_question(question):
    """The second lens's repros: each put a POST or a DELETE first where the base put a read."""
    out = door.find(question)
    assert not out["matches"] or out["matches"][0]["access"] == "read", out["matches"][0]


@pytest.mark.parametrize("question", ["restore migrated", "list deleted", "get destroyed"])
def test_a_question_of_only_verbs_and_folded_verbs_finds_nothing(question):
    """The base answered none (the second word is unknown); folding must not turn it into every row."""
    assert door.find(question)["matches"] == []
    assert door.find("restore")["matches"], "a bare verb still lists, as it always did"


@pytest.mark.parametrize("question", ["view rolledback", "show restarting container"])
def test_a_read_question_never_ranks_a_mutation_first_on_an_inflected_verb(question):
    """The lens's repros: `view rolledback` put POST rollback first, `get destroyed` a DELETE."""
    out = door.find(question)
    assert all(m["access"] == "read" for m in out["matches"])


def test_the_inflection_is_folded_before_the_typo_is_looked_for():
    assert door.find("restarting a container", plane="pve")["guessed"] == {"restarting": "restart"}
    assert door.find("rolledback", plane="pve")["guessed"] == {"rolledback": "rollback"}


def test_a_guess_is_labelled_a_guess_and_only_on_the_rows_that_leaned_on_it():
    out = door.find("list snaphsot of container", plane="pve")
    assert out["guessed"] == {"snaphsot": "snapshot"}
    mixed = door.find("list datastores snaphsot")
    assert any(m.get("match") == "lexical" for m in mixed["matches"])
    plain = door.find("list datastores", plane="pbs")
    assert "guessed" not in plain and all("match" not in m for m in plain["matches"])


def test_a_row_the_word_said_alone_reached_is_not_marked_lexical():
    from proximo.core import search  # the search itself: the door caps a find (MAX_FIND), this asks for all
    out = search.find("datastore snaphsot", plane="pbs", limit=200)
    marks = [m.get("match") for m in out["matches"]]
    assert "lexical" in marks and None in marks, "every row was stamped, or none"


@pytest.mark.parametrize("words", ["PUT permission", "PUT ssl", "POST backup"])
def test_a_match_reached_only_through_a_synonym_is_a_choice_not_a_plan(words):
    """The lens: `PUT permission` planned /access/acl and `PUT ssl` the ACME certificate as single
    matches through the new synonyms alone. plan returns the find answer to confirm instead."""
    method, word = words.split()
    plane = {"permission": "pve", "ssl": "pve", "backup": "pve"}[word]
    out = door.plan(plane, method, word)
    assert "matches" in out and "address" not in out


def test_a_word_said_plainly_still_plans_as_one_match():
    out = door.plan("pve", "PUT", "acl")
    assert out["address"] == "PUT /access/acl" and "choose" not in out


def test_one_thousand_unknown_words_are_looked_at_a_bounded_number_of_times(monkeypatch):
    calls = []
    real = lexical.WordIndex.repair
    monkeypatch.setattr(lexical.WordIndex, "repair", lambda self, w: calls.append(w) or real(self, w))
    words = " ".join(f"zq{i}wxv" for i in range(1000))
    out = door.find("list datastores " + words)
    assert len(calls) == search.MAX_LOOKED and out["matches"] == []


def test_the_cap_counts_guesses_not_junk_and_is_three():
    """Junk before the typos must not use up the cap; and only three typos are read."""
    out = door.find("zzzzzz snaphsot bakcup datastroe shutdwon firwall")
    assert search.MAX_GUESSES == 3 and len(out["guessed"]) == 3
    assert set(out["guessed"]) <= {"snaphsot", "bakcup", "datastroe", "shutdwon", "firwall"}
    assert list(out["guessed"]) == ["snaphsot", "bakcup", "datastroe"], "the first three real typos"


def test_a_guess_never_lands_in_a_parameter_name():
    """A word that only some operation's parameter spells (no path segment, no sentence) adds
    nothing as a guess, where the same word SAID adds a point: `store` as a parameter is noise."""
    index = search._index()
    allseg = set().union(*(s | d for _, s, d, _ in index))
    cands = sorted({p for row, s, _, params in index if "datastore" in s for p in params} - allseg)
    assert cands
    word = cands[0]
    base = (frozenset({"datastore"}),) * 2 + (frozenset(),)
    said = (frozenset({word}), frozenset({word}), frozenset())
    guess = (frozenset({"zzzzzz"}), frozenset({"zzzzzz"}), frozenset({word}))

    def scores(extra):
        return {(h.row.product, h.row.method, h.row.path): h.score
                for h in search._rank([base, extra], set(), None, None, False)}
    a, g = scores(said), scores(guess)
    carrying = [k for k in a if k in g and a[k] > g[k]]
    assert carrying, "the word said weighs a point in a parameter"
    assert all(a[k] - g[k] == 1 for k in carrying) and not any(g[k] > a[k] for k in g if k in a)


def test_a_known_word_one_slip_from_another_known_word_is_left_alone():
    """`knows` is not redundant: the word is its own best neighbour, but the next neighbour may be a
    slip away from it, and a word the table spells is never read as another."""
    ix = search._lexical_index()
    pairs = [(w, c) for w in ix.words if len(w) >= lexical.MIN_LENGTH and w.isalpha()
             for _, c in ix.neighbours(w) if lexical.is_typo(w, c)]
    assert pairs
    word, other = pairs[0]
    assert ix.knows(word) and ix.repair(word) is None
    assert lexical.is_typo(word, other)


def test_an_end_letter_is_never_a_slip():
    assert not lexical.is_typo("router", "route") and not lexical.is_typo("route", "router")
    assert not lexical.is_typo("backu", "backup") and not lexical.is_typo("backups", "backup")
    assert lexical.is_typo("bakcup", "backup") and lexical.is_typo("bckup", "backup")


def test_a_short_word_is_never_corrected():
    """`bread` is one letter from `read`, and `bakup` from `backup`; below six letters the tier
    does not guess (a short word is as often a real word we do not know)."""
    assert search._lexical_index().repair("bread") is None
    assert search._lexical_index().repair("bakup") is None and door.find("bakup")["matches"] == []
    assert door.find("bread")["matches"] == []


def test_lexical_off_returns_what_the_word_tier_alone_answers(monkeypatch):
    monkeypatch.setenv("PROXIMO_LEXICAL", "off")
    out = door.find("snaphsot")
    assert out["matches"] == [] and "no published address matched" in out["note"]


@pytest.mark.parametrize("spelling", ["0", "false", "no", "off", "OFF", " False "])
def test_every_documented_off_spelling_disables_the_tier(monkeypatch, spelling):
    monkeypatch.setenv("PROXIMO_LEXICAL", spelling)
    assert lexical.enabled() is False and door.find("snaphsot")["matches"] == []


@pytest.mark.parametrize("spelling", ["", "1", "on", "true", "yes"])
def test_anything_else_leaves_it_on(monkeypatch, spelling):
    monkeypatch.setenv("PROXIMO_LEXICAL", spelling)
    assert lexical.enabled() is True and door.find("snaphsot")["matches"]


def test_unset_means_on(monkeypatch):
    monkeypatch.delenv("PROXIMO_LEXICAL", raising=False)
    assert lexical.enabled() is True


def test_the_ngrams_touch_only_a_word_no_tier_knew(monkeypatch):
    """A question made of words the table spells never reaches the n-gram index (it would be built
    here): the tier fills what the word tier could not hear, it never second-guesses what it did."""
    def boom(*a, **k):
        raise AssertionError("the lexical tier ran for a question the word tier answered")
    monkeypatch.setattr(search, "_lexical_index", boom)
    assert door.find("list datastores", plane="pbs")["matches"]
    assert door.find("memory usage of a container", plane="pve")["matches"]


def test_a_plan_on_words_is_never_resolved_by_a_guess():
    """`proximo_plan` acts on a single match, so it asks `strict`: a misspelt word must not plan a
    different address (the same rule that made `strict` look in the path alone)."""
    out = door.words_to_address("pve", "POST", ["snaphsot"])
    assert out["matches"] == [] and "guessed" not in out


def test_the_index_is_built_lazily_once_and_cached(records):
    records()                                                    # a clean cache, the real table
    search._lexical_index.cache_clear()
    door.find("list datastores", plane="pbs")
    assert search._lexical_index.cache_info().currsize == 0, "the word tier built the n-gram index"
    door.find("snaphsot")
    door.find("firwall")
    info = search._lexical_index.cache_info()
    assert info.currsize == 1 and info.misses == 1 and info.hits >= 1


def test_the_answer_keeps_its_shape_and_its_size():
    """The 4K window: a lexical answer is the same handful, plus its mark and what it guessed."""
    word = door.find("list datastores", plane="pbs")
    lex = door.find("snaphsot")
    assert len(lex["matches"]) <= 5 and len(door.find("snaphsot", limit=2)["matches"]) == 2
    assert {"plane", "method", "path", "access", "match"} <= set(lex["matches"][0])
    assert set(word["matches"][0]) <= {"plane", "method", "path", "access", "tier", "why", "params"}
    assert len(json.dumps(lex, separators=(",", ":"))) // 4 < 1000, "a lexical answer outgrew its handful"
    assert len(json.dumps(lex)) < len(json.dumps(door.find("list datastores", plane="pbs", limit=5))) * 2


def test_the_index_is_deterministic_and_needs_no_process_hash():
    """0.44 bucketed grams with blake2b because the builtin hash is salted per process. This index
    keys on the gram itself, so there is nothing to salt; two builds rank the same."""
    words = ["snapshot", "snapname", "datastore", "firewall", "backup", "memory", "storage"]
    a = lexical.WordIndex(words).neighbours("snaphsot")
    b = lexical.WordIndex(list(reversed(words))).neighbours("snaphsot")
    assert a == b and a[0][1] == "snapshot"


def test_idf_downweights_grams_every_word_carries():
    """TF-IDF, not term counts: a gram in every word decides nothing. With `ing` on all but one
    word, the query that shares only `ing` must score far below the one sharing a rare gram."""
    words = [f"{c}ing" for c in "bcdfghjklm"] + ["quarantine"]
    ix = lexical.WordIndex(words)
    common = dict((w, s) for s, w in ix.neighbours("ziing"))
    rare = dict((w, s) for s, w in ix.neighbours("quarantne"))
    assert max(common.values(), default=0) < rare["quarantine"] / 2


def test_a_word_the_table_spells_is_not_corrected():
    """`mon`, `osd` and `qdevice` are addresses. A word the table knows is left as it is."""
    ix = search._lexical_index()
    for known in ("datastore", "qdevice", "snapshot", "rrddata"):
        assert ix.knows(known) and ix.repair(known) is None


def test_blank_and_stopword_only_queries_still_refuse():
    with pytest.raises(ProximoError):
        door.find("   ")


def test_the_floor_refuses_a_pair_whose_grams_barely_meet(monkeypatch):
    """The second lock: `orhpan` is one swap from `orphan`, but the two share too few grams (0.21).
    With the floor lowered to nothing it is read; with it, it is not. A named cost of the floor."""
    ix = search._lexical_index()
    score = dict((w, s) for s, w in ix.neighbours("orhpan"))["orphan"]
    assert score < lexical.MIN_SIMILARITY
    assert ix.repair("orhpan") is None
    monkeypatch.setattr(lexical, "MIN_SIMILARITY", 0.0)
    assert ix.repair("orhpan") == "orphan"
