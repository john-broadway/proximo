"""In-package lexical vectors + the vocabulary tier — no model, no network, no deps.

The tier this exists to be: an adopter who installs the wheel and configures nothing
still gets semantic-ish recall. Keyword search needs the operator's words to appear in
a tool's text ("memory usage of a container" matches nothing, because the tool that
answers it says "runtime status"); the neural rung crosses that gap but costs an
embedder. This layer sits between them, in the wheel:

  1. VOCABULARY expands the query in Proxmox's own terms (memory->mem/ram,
     container->lxc/ct/guest, who/changed->audit/ledger). Curated data, auditable,
     one table shared with lean's keyword synonyms so the two can never drift.
  2. Hashed char-n-gram TF-IDF vectors, cosine-ranked, pure stdlib.

Contract under test:

- STABLE HASH. Python's builtin hash() on str is randomized per process
  (PYTHONHASHSEED), so a bucket computed in one process does not match the same gram
  in another. Anything persisted or compared across processes MUST NOT use it.
- Expansion WIDENS, never replaces: a bare "vm" query must still find pve_create_vm.
- Ranking beats bare lexical on the probes that motivated the tier, and the probe
  assertions name the tool, not a score.
- search_tools stays keyword-first; lexical fills behind it, marked "match": "lexical";
  the neural rung (when configured) outranks lexical for the remaining room.
- Blank/garbage queries never return the catalog.
"""
from __future__ import annotations

import contextlib

import pytest

from proximo import lean, lexical


@contextlib.contextmanager
def swapped(obj, attr, value):
    """Temporarily replace an attribute — for tests that toggle module state mid-body
    rather than for their whole duration."""
    original = getattr(obj, attr)
    setattr(obj, attr, value)
    try:
        yield
    finally:
        setattr(obj, attr, original)


class FakeTool:
    def __init__(self, description: str):
        self.description = description


CATALOG = {
    "pve_guest_status": FakeTool("READ-ONLY: runtime status of one guest — cpu, mem, uptime."),
    "pve_list_guests": FakeTool("READ-ONLY: list all VMs and LXC containers with state."),
    "pve_snapshot_create": FakeTool("Create a snapshot of a guest."),
    "pve_storage_status": FakeTool("READ-ONLY: storage usage — disk used and available."),
    "pve_firewall_set_enabled": FakeTool("Enable or disable the firewall for a guest."),
    "pve_create_vm": FakeTool("Create a new QEMU virtual machine."),
    "audit_verify": FakeTool("READ-ONLY: verify the PROVE ledger hash chain — who did what."),
}


# --- the stable-hash law -----------------------------------------------------------------

def test_gram_bucket_is_stable_across_processes():
    """Python's builtin hash() on str is SALTED per process (PYTHONHASHSEED).

    A vector built in one process would land its grams in different buckets than the
    query embedded in another — silently, with no error, producing garbage similarity.
    The first prototype of this module used the builtin; this test is why it does not.

    Pinned against a literal, so a change of hash function is a deliberate act (it
    invalidates any persisted index) rather than an invisible drift.
    """
    assert lexical._bucket("mem", 4096) == lexical._bucket("mem", 4096)
    assert lexical._bucket("mem", 4096) == 2202, (
        "the gram->bucket function changed; any persisted lexical index is now invalid")


def test_bucket_does_not_use_builtin_hash(monkeypatch):
    """Mutant it kills: reverting _bucket to `hash(gram) % dim`."""
    monkeypatch.setattr("builtins.hash", lambda o: 0)
    assert lexical._bucket("mem", 4096) == 2202, "builtin hash() leaked into the bucket function"
    assert lexical._bucket("ram", 4096) != lexical._bucket("mem", 4096), (
        "distinct grams collided — a bucket function returning a constant would satisfy "
        "the assertion above, so pin that it discriminates too")


# --- the vocabulary tier -----------------------------------------------------------------

def test_expansion_widens_and_never_replaces():
    """A bare 'vm' must still find pve_create_vm (whose text says vm, not guest)."""
    expanded = lexical.expand_query("vm")
    assert "vm" in expanded, "the original term was replaced, not widened"
    assert "guest" in expanded


def test_expansion_covers_the_domain_gaps_that_motivated_it():
    for term, expected in (("memory", "mem"), ("container", "lxc"),
                           ("who", "audit"), ("changed", "config")):
        assert expected in lexical.expand_query(term), f"{term!r} does not reach {expected!r}"


def test_unknown_terms_pass_through_untouched():
    assert lexical.expand_query("zzzqqq") == ["zzzqqq"]


def _real_catalog() -> dict:
    """The real published tool surface, from the tracked manifest — 900+ real names and
    descriptions. A synthetic fixture cannot show a blast radius; only a real corpus can."""
    import json
    import pathlib

    manifest = pathlib.Path(__file__).resolve().parent.parent / "lhm.plugin.json"
    tools = json.loads(manifest.read_text()).get("tools") or []
    return {t["name"]: FakeTool(t.get("description", "")) for t in tools if t.get("name")}


def test_keyword_vocabulary_does_not_blow_up_the_and_filter():
    """THE guard on the two-table split, measured against the real 905-tool catalog.

    The wide VOCABULARY briefly fed keyword search on the reasoning that one table cannot
    drift from itself. An adversarial lens killed that with numbers: "on" then matched
    905 of 905 tools (100%), "show" 824, "list" 814, "check cluster health" 187 — because
    concept-level expansions (health→status, check→status) land on words nearly every
    description carries, so the AND across terms stopped filtering and lean mode's
    OR-blowup returned. No comment can hold that line; this measurement can.

    Mutant it kills: pointing `lean._term_variants` back at `lexical.VOCABULARY`, or
    adding a concept-level jump to KEYWORD_VOCABULARY.

    Asserted as a DELTA against the same search with NO synonyms, not as an absolute
    ceiling, because one pre-existing effect would swamp an absolute number and wrongly
    blame this table for it: keyword matching is per-term SUBSTRING, so the two-letter
    query "on" matched 905 of 905 tools BEFORE any of this work existed ("connection",
    "monitor", "on the node"). Measured at f9925c7 to be sure rather than assumed. That is
    a real weakness of short-term substring matching and it is not what this test is for.
    What this test owns is the widening: "show" went 48 -> 824 and "check cluster health"
    0 -> 187 when the wide table fed the keyword tier.
    """
    catalog = _real_catalog()
    assert len(catalog) > 500, "the tracked manifest did not load; this test proves nothing"
    for query in ("show", "list", "check", "changed", "health", "usage", "status",
                  "check health", "check cluster health", "turn off"):
        with_vocab = [h for h in lean.search_tools(catalog, query, limit=len(catalog) + 1)
                      if "match" not in h]
        with swapped(lexical, "KEYWORD_VOCABULARY", {}):
            bare = [h for h in lean.search_tools(catalog, query, limit=len(catalog) + 1)
                    if "match" not in h]
        # A rename may legitimately add hits (vm->guest finds real guest tools). A concept
        # jump multiplies them. 2x plus a small floor separates the two on real data.
        ceiling = max(2 * len(bare), 25)
        assert len(with_vocab) <= ceiling, (
            f"keyword query {query!r} matched {len(with_vocab)} of {len(catalog)} tools "
            f"with synonyms vs {len(bare)} without — a KEYWORD_VOCABULARY entry is widening "
            "onto a near-universal word and the AND filter has stopped filtering")


def test_the_ranking_vocabulary_is_still_wide():
    """The other half: the split must not be 'fixed' by narrowing BOTH tables. The wide
    table is what lets the ranking tier cross the vocabulary gap at all."""
    for term, expected in (("health", "status"), ("check", "diagnose"), ("who", "audit"),
                           ("space", "storage"), ("left", "available")):
        assert expected in lexical.expand_query(term), (
            f"the RANKING vocabulary lost {term}->{expected}")
        assert expected not in lean._term_variants(term), (
            f"{term}->{expected} leaked into the keyword tier, where it blows up the filter")


def test_keyword_synonyms_are_near_exact_renames_only():
    """Every KEYWORD_VOCABULARY entry must be a rename, not a concept jump — the property
    that keeps the AND filter a filter. Checked structurally as well as by blast radius:
    a rename maps a name for a thing onto another name for the SAME thing."""
    for term, expansions in lexical.KEYWORD_VOCABULARY.items():
        assert len(expansions) <= 2, (
            f"{term!r} expands to {len(expansions)} terms — that is concept-level widening, "
            "which belongs in the ranking VOCABULARY, not here")
        for e in expansions:
            assert e == e.lower() and e != term
    for term in ("vm", "container", "ct"):
        assert "guest" in lean._term_variants(term)
    assert "delete" in lean._term_variants("destroy")


def test_idf_downweights_grams_that_are_everywhere():
    """TF-IDF, not bare term frequency: a gram in EVERY document carries no information
    and must not decide the ranking.

    Mutant it kills: dropping `* self.idf.get(gram, 1.0)` from the weighting, which
    survived the whole suite before this test existed — nothing measured that the IDF
    half of TF-IDF was doing anything at all.

    Ranking ORDER does not separate the two implementations — the rare-term document wins
    either way — which is why two earlier versions of this test passed with idf dropped.
    What differs is HOW FAR the common-only documents are pushed down, measured by running
    the real mutation rather than a stand-in class: with idf they score 0.163 against the
    rare document's 0.70; without, 0.386 against 0.78. So the assertion is the ratio.
    """
    docs = {f"filler{i}": "readonly proxmox node tool" for i in range(8)}
    docs["has_rare"] = "quarantine mail gateway readonly"
    hits = dict(lexical.LexicalIndex(docs).search("readonly quarantine", limit=9))
    fillers = [s for n, s in hits.items() if n.startswith("filler")]
    assert max(hits, key=hits.get) == "has_rare"
    assert fillers and max(fillers) < hits["has_rare"] / 3, (
        "documents matching only the term EVERY document carries scored close to the one "
        f"matching the rare term — idf is not being applied: {hits}")


def test_vocabulary_entries_are_lowercase_and_self_consistent():
    """Guards the table itself: an uppercase key can never match a lowercased query term,
    and a term mapping to itself is dead weight that widens nothing."""
    for term, expansions in lexical.VOCABULARY.items():
        assert term == term.lower(), f"{term!r} can never match a lowercased query"
        assert term not in expansions, f"{term!r} expands to itself"
        assert all(e == e.lower() for e in expansions), f"{term!r} has uppercase expansions"


# --- ranking, on the probes that motivated the tier --------------------------------------

def _rank(query, catalog=CATALOG, limit=3):
    docs = {n: f"{n}: {t.description}" for n, t in catalog.items()}
    index = lexical.LexicalIndex(docs)
    return [name for name, _ in index.search(query, limit=limit)]


def test_probe_memory_usage_of_a_container_finds_guest_status():
    """The motivating failure: keyword AND-search returns NOTHING for this phrase, and
    bare lexical (no vocabulary) ranked pve_create_container first on the word alone."""
    assert "pve_guest_status" in _rank("memory usage of a container")


def test_probe_who_changed_this_finds_the_ledger():
    assert "audit_verify" in _rank("who changed this vm's config")


def test_probe_space_left_for_backups_finds_storage_status():
    assert "pve_storage_status" in _rank("how much space is left for backups")


def test_probe_turn_off_firewall_finds_set_enabled():
    assert "pve_firewall_set_enabled" in _rank("turn off the firewall for one guest")


def test_vocabulary_is_what_makes_the_hard_probe_work():
    """Non-vacuity: prove the vocabulary tier is load-bearing, not decoration riding on
    n-grams that would have matched anyway.

    The probe is chosen because it is DECISIVE, measured both ways: "how much space is
    left for backups" shares no surface form with "storage usage — disk used and
    available", so with the vocabulary emptied `pve_storage_status` is absent entirely,
    and with it, it ranks first (0.68). The first version of this test used the memory
    probe, where guest_status places top-3 with OR without the vocabulary on this small
    fixture — it would have passed whether or not the tier existed. Same trap as the
    counts fixture an adversarial lens caught the same day: a fixture that does not cross
    the threshold cannot test the threshold.
    """
    docs = {n: f"{n}: {t.description}" for n, t in CATALOG.items()}
    query = "how much space is left for backups"
    with_vocab = [n for n, _ in lexical.LexicalIndex(docs).search(query, 3)]
    without = [n for n, _ in lexical.LexicalIndex(docs, vocabulary={}).search(query, 3)]
    assert with_vocab[0] == "pve_storage_status", "the vocabulary tier stopped working"
    assert "pve_storage_status" not in without, (
        "the probe is not decisive — n-grams alone already find it, so this proves nothing "
        "about the vocabulary")


def test_offtopic_english_never_surfaces_a_tool_on_ngram_coincidence():
    """The floor alone did NOT make "garbage returns nothing" true.

    Measured by an adversarial lens on the real catalog: "recipe for banana bread"
    returned `pve_node_disk_wipe` — "MUTATION: wipe ALL data and the partition table...
    RISK_HIGH, NO UNDO" — at 0.162, above the 0.15 floor, purely because "recipe" and
    "wipe" share the character-3-gram "ipe". Offering a destructive tool as the answer to
    an off-domain question is the worst available outcome for the small models this tier
    exists to serve. Admission now requires a whole-token overlap; n-grams still rank.

    Mutant it kills: removing the `query_tokens & self.doc_tokens[name]` admission check.
    """
    catalog = _real_catalog()
    docs = {n: f"{n}: {t.description}" for n, t in catalog.items()}
    hits = lexical.LexicalIndex(docs).search("recipe for banana bread", limit=10)
    assert hits == [], f"off-domain English matched real tools on n-gram coincidence: {hits}"
    # and the specific destructive tool that was surfacing, named so a regression is legible
    assert "pve_node_disk_wipe" not in dict(hits)


def test_admission_rule_does_not_break_real_queries():
    """The other half: requiring a token overlap must not silence the probes. Without this,
    the fix above could be 'passed' by admitting nothing at all."""
    catalog = _real_catalog()
    docs = {n: f"{n}: {t.description}" for n, t in catalog.items()}
    index = lexical.LexicalIndex(docs)
    for query, expected in (("who changed this vm's config", "audit_verify"),
                            ("how much space is left for backups", "pve_backup"),
                            ("turn off the firewall for one guest", "pve_firewall_set_enabled")):
        names = [n for n, _ in index.search(query, limit=5)]
        assert expected in names, f"{query!r} lost {expected} — admission is too strict: {names}"


def test_blank_and_garbage_queries_never_return_the_catalog():
    docs = {n: f"{n}: {t.description}" for n, t in CATALOG.items()}
    index = lexical.LexicalIndex(docs)
    with pytest.raises(ValueError):
        index.search("   ", limit=5)
    assert index.search("zzzqqq wwwxxx", limit=5) == [], (
        "a query matching nothing returned rows — a floor of noise is worse than no answer")


def test_scores_are_finite_and_ordered():
    docs = {n: f"{n}: {t.description}" for n, t in CATALOG.items()}
    hits = lexical.LexicalIndex(docs).search("guest status", limit=5)
    scores = [s for _, s in hits]
    assert scores == sorted(scores, reverse=True)
    assert all(0.0 < s <= 1.0001 for s in scores), scores


def test_index_build_is_deterministic():
    docs = {n: f"{n}: {t.description}" for n, t in CATALOG.items()}
    a = lexical.LexicalIndex(docs).search("guest status", limit=5)
    b = lexical.LexicalIndex(dict(reversed(list(docs.items())))).search("guest status", limit=5)
    assert a == b, "index order changed the ranking — the build is not deterministic"


# --- wiring into search_tools ------------------------------------------------------------

def test_lexical_fills_behind_keyword_and_is_marked(monkeypatch):
    monkeypatch.delenv("PROXIMO_EMBED_URL", raising=False)
    rows = lean.search_tools(CATALOG, "snapshot", limit=4)
    assert rows[0]["name"] == "pve_snapshot_create" and "match" not in rows[0]
    assert all(r.get("match") == "lexical" for r in rows[1:])
    assert len({r["name"] for r in rows}) == len(rows), "a tool appeared twice"


def test_lexical_answers_the_hard_probe_through_search_tools(monkeypatch):
    """End to end, with NOTHING configured — the whole point of the tier."""
    monkeypatch.delenv("PROXIMO_EMBED_URL", raising=False)
    names = [r["name"] for r in lean.search_tools(CATALOG, "memory usage of a container", limit=5)]
    assert "pve_guest_status" in names


def test_lexical_never_exceeds_the_limit(monkeypatch):
    monkeypatch.delenv("PROXIMO_EMBED_URL", raising=False)
    assert len(lean.search_tools(CATALOG, "guest", limit=2)) <= 2


def test_index_is_built_once_per_catalog(monkeypatch):
    """The index is O(corpus) to build (~0.76s at 905 tools). Rebuilding per search made
    every call pay it — an adversarial lens measured ~790ms per `lexical_fill` on the real
    catalog against a claimed "~2ms search", which described only the already-built vector
    math. Cache on catalog identity; a CHANGED catalog must still build its own.

    Mutant it kills: reverting `_cached_index` to a bare `LexicalIndex(documents)`.
    """
    lexical._INDEX_CACHE.clear()
    built = []
    real_init = lexical.LexicalIndex.__init__

    def counting_init(self, documents, *a, **k):
        built.append(len(documents))
        real_init(self, documents, *a, **k)

    monkeypatch.setattr(lexical.LexicalIndex, "__init__", counting_init)
    docs = {"a": "alpha thing", "b": "beta thing"}
    for _ in range(3):
        lexical.lexical_fill(docs, "alpha", set(), 2)
    assert len(built) == 1, f"the index was rebuilt per search: {len(built)} builds"
    lexical.lexical_fill({**docs, "c": "gamma thing"}, "alpha", set(), 2)
    assert len(built) == 2, "a changed catalog reused a stale index"


def test_index_cache_is_bounded():
    """A per-corpus cache with no bound is a leak nobody would notice."""
    lexical._INDEX_CACHE.clear()
    for i in range(30):
        lexical.lexical_fill({f"t{i}": f"doc number {i}"}, f"doc number {i}", set(), 1)
    assert len(lexical._INDEX_CACHE) <= 8, f"cache grew to {len(lexical._INDEX_CACHE)}"


def test_lexical_off_switch_accepts_every_documented_spelling(monkeypatch):
    """Mutant it kills: narrowing _TRUTHY_OFF to ("off",). Every test previously used
    only "off", so dropping "0"/"false"/"no" survived the whole suite."""
    for spelling in ("0", "false", "no", "off", "OFF", "False"):
        monkeypatch.setenv("PROXIMO_LEXICAL", spelling)
        assert lexical.lexical_enabled() is False, f"{spelling!r} did not disable the tier"
    for spelling in ("", "1", "true", "on", "yes"):
        monkeypatch.setenv("PROXIMO_LEXICAL", spelling)
        assert lexical.lexical_enabled() is True, f"{spelling!r} wrongly disabled the tier"


def test_expansion_dedups_cross_referencing_terms():
    """VOCABULARY entries cross-reference (mem→memory/ram, memory→mem/ram), so without the
    de-dup guard a query repeating them balloons and shifts its own scoring. Mutant it
    kills: dropping `if e not in out`."""
    expanded = lexical.expand_query("mem memory ram")
    assert len(expanded) == len(set(expanded)), f"duplicate terms survived: {expanded}"


def test_lexical_can_be_turned_off(monkeypatch):
    """Default-on is only safe if it is switchable — an operator who wants exact-match
    semantics must be able to have them."""
    monkeypatch.delenv("PROXIMO_EMBED_URL", raising=False)
    monkeypatch.setenv("PROXIMO_LEXICAL", "off")
    rows = lean.search_tools(CATALOG, "snapshot", limit=4)
    assert [r["name"] for r in rows] == ["pve_snapshot_create"]


def test_blank_query_still_raises_with_lexical_on(monkeypatch):
    monkeypatch.delenv("PROXIMO_EMBED_URL", raising=False)
    with pytest.raises(ValueError):
        lean.search_tools(CATALOG, "   ", limit=5)


def test_neural_outranks_lexical_when_both_are_available(monkeypatch, tmp_path):
    """Tier order: keyword, then neural (measured stronger), then lexical for what is left.
    Both fills must still be present and distinguishable."""
    from proximo import vectors
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    monkeypatch.setenv("PROXIMO_VECTORS_PATH", str(tmp_path / "v.db"))
    # "guest status": keyword takes pve_guest_status; lexical alone would then rank
    # pve_storage_status ahead of pve_list_guests. The stub embedder inverts that
    # preference, so seeing pve_list_guests in the semantic slot proves the neural rung
    # ran FIRST rather than the two tiers happening to agree.
    monkeypatch.setattr(vectors, "embed_texts",
                        lambda texts: [[1.0, 0.0] if t.startswith("pve_list_guests")
                                       or t == "guest status" else [0.0, 1.0] for t in texts])
    rows = lean.search_tools(CATALOG, "guest status", limit=3)
    assert rows[0]["name"] == "pve_guest_status" and "match" not in rows[0], (
        "keyword lost its first place")
    assert rows[1] == {**rows[1], "name": "pve_list_guests", "match": "semantic"}, (
        f"the neural rung did not outrank lexical: {rows[1]}")
    # No assertion that lexical takes the LAST slot, deliberately. The neural rung has no
    # minimum-score floor (it cannot honestly have one — see vectors.semantic_fill: dense
    # scores are model-scaled and unrelated text still scores high), so when it is
    # configured it fills all remaining room and lexical legitimately gets none. Asserting
    # otherwise would pin a behaviour the design does not promise. Lexical's own reach is
    # proven by the tests that run without an embedder, and by the degrade test below.
    assert not any(r.get("match") == "lexical" for r in rows), (
        "lexical rows appeared while an embedder was available — the tiers double-filled")


def test_lexical_still_fills_when_the_embedder_is_down(monkeypatch, tmp_path):
    """The degrade path must fall to LEXICAL, not all the way back to bare keyword —
    the in-wheel tier is exactly what an unreachable embedder should reveal."""
    from proximo import vectors
    from proximo.backends import ProximoError
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    monkeypatch.setenv("PROXIMO_VECTORS_PATH", str(tmp_path / "v.db"))

    def down(texts):
        raise ProximoError("embedding endpoint failed — check PROXIMO_EMBED_URL")

    monkeypatch.setattr(vectors, "embed_texts", down)
    names = [r["name"] for r in lean.search_tools(CATALOG, "memory usage of a container", limit=5)]
    assert "pve_guest_status" in names


def test_prose_only_keyword_hits_do_not_crowd_out_the_lower_tiers():
    """Rank-3 (prose-only) keyword matches are the WEAKEST evidence keyword produces, and
    "keyword always first" handed them the whole limit.

    Measured on the real catalog: `configuration audit` returned
    pbs_metrics_influxdb_http_create and pbs_s3_client_create — tools that merely CONTAIN
    those words in prose — filling every slot, so the audit tools the lexical tier ranks
    first never got a place. A live qwen3:8b then reported that no tool tracks who changed
    a config. Strong keyword ranks (the NAME matched) still win absolutely; prose-only
    goes behind the lower tiers.

    Mutant it kills: restoring `results = [row[2] for row in scored[:limit]]`.
    """
    catalog = _real_catalog()
    names = [r["name"] for r in lean.search_tools(catalog, "configuration audit", limit=4)]
    assert any(n.startswith("audit_") for n in names), (
        f"prose-only keyword hits still crowd out the audit tools: {names}")

    # The other half: a NAME match must still take first place, unmarked.
    rows = lean.search_tools(catalog, "snapshot", limit=3)
    assert "snapshot" in rows[0]["name"] and "match" not in rows[0], (
        f"a strong keyword hit lost its place: {rows[0]}")
