"""Vector search over the estate sqlite — opt-in, self-healing, honestly degraded.

Contract under test:

- INERT unless PROXIMO_EMBED_URL is set (the memory/wiki opt-in discipline): keyword
  search behaves byte-identically and the store is never touched.
- embed_texts speaks OpenAI-compatible /v1/embeddings (ollama, llama.cpp, vLLM all
  serve it), batches, re-orders by the response's own index field, and raises
  ProximoError naming the env var on failure or a count/shape mismatch — never a
  silent partial result.
- VectorStore syncs by content hash (model name included, so swapping the embedding
  model re-embeds everything rather than comparing vectors from different spaces),
  deletes keys absent from the sync set, stores unit vectors, ranks by dot product.
- search_tools: keyword hits stay FIRST and unchanged; semantic rows only FILL the
  remaining room, marked {"match": "semantic"} so a reader knows which ranking
  produced each row. Blank query still raises. An embedder failure at search time
  degrades to keyword-only with a stderr warning — a search assist must never take
  the facade down.
- recall_state(query=...) ALWAYS works: neural when PROXIMO_EMBED_URL is configured,
  the in-wheel lexical tier when it is not — a parameter advertised on every install
  must function on every install. COUNTS stay whole-estate either way (a filtered list
  must never masquerade as the census — memory.py's law).
"""
from __future__ import annotations

import json
import os
import stat
import struct

import pytest

from proximo import lean, vectors
from proximo.backends import ProximoError


class FakeTool:
    def __init__(self, description: str):
        self.description = description


CATALOG = {
    "pve_guest_status": FakeTool("READ-ONLY: runtime status of one guest — cpu, mem, uptime."),
    "pve_list_guests": FakeTool("READ-ONLY: list all VMs and LXC containers with state."),
    "pve_snapshot_create": FakeTool("Create a snapshot of a guest."),
    "pbs_datastore_status": FakeTool("READ-ONLY: PBS datastore usage."),
}


def fake_embedder(vocab: dict[str, list[float]]):
    """Deterministic 'embeddings': cosine neighborhoods declared by hand, calls counted."""
    calls = {"texts": []}

    def embed(texts):
        calls["texts"].append(list(texts))
        out = []
        for t in texts:
            for needle, vec in vocab.items():
                if needle in t:
                    out.append(vec)
                    break
            else:
                out.append([0.0, 0.0, 1.0])
        return out

    return embed, calls


@pytest.fixture(autouse=True)
def _clear_warning_memo():
    """`vectors._warned` is a process-global "once per reason" memo, so a warning already
    emitted by an EARLIER test is silently suppressed in a later one — any assertion on
    stderr is otherwise order-dependent. Caught for real: the degrade test passed alone
    and failed in the full suite. Clear it around every test in this file."""
    from proximo.memory import _warned
    _warned.clear()
    yield
    _warned.clear()


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    s = vectors.VectorStore(str(tmp_path / "vectors.db"))
    yield s
    s.close()


# --- inert unless configured ------------------------------------------------------------

def test_disabled_without_env(monkeypatch):
    monkeypatch.delenv("PROXIMO_EMBED_URL", raising=False)
    assert vectors.vectors_enabled() is False


def test_search_tools_untouched_when_disabled(monkeypatch):
    monkeypatch.delenv("PROXIMO_EMBED_URL", raising=False)

    def boom(*a, **k):  # any store/HTTP touch is a failure
        raise AssertionError("vector path touched while disabled")

    monkeypatch.setattr(vectors, "semantic_fill", boom)
    rows = lean.search_tools(CATALOG, "snapshot", limit=5)
    assert [r["name"] for r in rows] == ["pve_snapshot_create"]
    assert all("match" not in r for r in rows)


# --- embed_texts contract ---------------------------------------------------------------

def _http_double(monkeypatch, responder):
    class _Resp:
        def __init__(self, payload):
            self._payload = payload
        def read(self):
            return json.dumps(self._payload).encode()
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=None):
        return _Resp(responder(json.loads(req.data)))

    monkeypatch.setattr(vectors.urllib.request, "urlopen", fake_urlopen)


def test_embed_texts_orders_by_index_field(monkeypatch):
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    _http_double(monkeypatch, lambda body: {"data": [
        {"index": 1, "embedding": [0.0, 1.0]},
        {"index": 0, "embedding": [1.0, 0.0]},
    ]})
    assert vectors.embed_texts(["a", "b"]) == [[1.0, 0.0], [0.0, 1.0]]


def test_embed_texts_batches(monkeypatch):
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    seen = []
    def responder(body):
        seen.append(len(body["input"]))
        return {"data": [{"index": i, "embedding": [1.0, 0.0]}
                         for i in range(len(body["input"]))]}
    _http_double(monkeypatch, responder)
    out = vectors.embed_texts([f"t{i}" for i in range(vectors._BATCH + 3)])
    assert len(out) == vectors._BATCH + 3
    assert seen == [vectors._BATCH, 3]


def test_embed_url_refuses_non_http_schemes(monkeypatch):
    """A file:/custom scheme would turn the embedder call into a local read — refuse it."""
    for bad in ("file:///etc/passwd", "ftp://x", "unix:///tmp/sock"):
        monkeypatch.setenv("PROXIMO_EMBED_URL", bad)
        with pytest.raises(ProximoError, match="http"):
            vectors.embed_texts(["a"])


def test_embed_texts_refuses_a_non_permutation_index(monkeypatch):
    """Counting rows is not enough. An endpoint answering {index:-1},{index:0} for two
    inputs passes a count check and lands its vector in the WRONG input's slot — text and
    vector silently misaligned, every later score wrong with nothing raised. Duplicates do
    the same. Found by an adversarial lens, 2026-08-01; both shapes pinned.
    """
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    for bad in ([{"index": -1, "embedding": [5.0, 5.0]}, {"index": 0, "embedding": [1.0, 1.0]}],
                [{"index": 0, "embedding": [9.0, 9.0]}, {"index": 0, "embedding": [1.0, 0.0]}],
                [{"index": 0, "embedding": [1.0, 0.0]}, {"index": 7, "embedding": [0.0, 1.0]}]):
        _http_double(monkeypatch, lambda body, rows=bad: {"data": rows})
        with pytest.raises(ProximoError, match="permutation"):
            vectors.embed_texts(["input-A", "input-B"])


def test_embed_texts_refuses_ragged_dimensions(monkeypatch):
    """A mixed-dimension batch would crash search()'s strict zip later, far from here."""
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    _http_double(monkeypatch, lambda body: {"data": [
        {"index": 0, "embedding": [1.0, 0.0]},
        {"index": 1, "embedding": [1.0, 0.0, 0.0]},
    ]})
    with pytest.raises(ProximoError, match="mixed dimensions"):
        vectors.embed_texts(["a", "b"])


def test_embed_texts_refuses_non_finite_values(monkeypatch):
    """A NaN propagates through _normalize into EVERY score, and json.dumps writes the
    bare token `NaN` — invalid JSON, which can fail a strict client's parse of the whole
    response, not just misrank one row."""
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    for bad in ([float("nan"), 1.0], [float("inf"), 1.0], [1.0, float("-inf")]):
        _http_double(monkeypatch, lambda body, v=bad: {"data": [{"index": 0, "embedding": v}]})
        with pytest.raises(ProximoError, match="non-finite"):
            vectors.embed_texts(["a"])


def test_embed_texts_bounds_dimensionality(monkeypatch):
    """An unbounded dim lets a misbehaving endpoint inflate the store without limit."""
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    monkeypatch.setenv("PROXIMO_EMBED_MAX_DIM", "8")
    _http_double(monkeypatch, lambda body: {"data": [
        {"index": 0, "embedding": [0.1] * 9}]})
    with pytest.raises(ProximoError, match="ceiling"):
        vectors.embed_texts(["a"])
    monkeypatch.setenv("PROXIMO_EMBED_MAX_DIM", "16")   # the other half: under it passes
    assert len(vectors.embed_texts(["a"])[0]) == 9


def test_embed_texts_count_mismatch_refuses(monkeypatch):
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    _http_double(monkeypatch, lambda body: {"data": [{"index": 0, "embedding": [1.0]}]})
    with pytest.raises(ProximoError, match="PROXIMO_EMBED_URL"):
        vectors.embed_texts(["a", "b"])


def test_embed_texts_http_failure_names_the_env(monkeypatch):
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    def fake_urlopen(req, timeout=None):
        raise OSError("connection refused")
    monkeypatch.setattr(vectors.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(ProximoError, match="PROXIMO_EMBED_URL"):
        vectors.embed_texts(["a"])


# --- the store --------------------------------------------------------------------------

def test_symlinked_store_path_is_refused(tmp_path, monkeypatch):
    """A symlink at the store path defeated BOTH guarantees the docstrings claim.

    A DANGLING symlink fails os.path.exists(), takes the O_NOFOLLOW create branch, fails
    ELOOP, and the best-effort swallow returned as if nothing were wrong — then
    sqlite3.connect() followed the link with an ordinary open and created the estate
    inventory at the attacker's target, world-readable (0644 measured), somewhere the
    operator never configured. A symlink to an EXISTING file was worse in a second way:
    the tighten branch chmod'ed the LINK TARGET, narrowing an unrelated file.
    Found by an adversarial lens, 2026-08-01. Both shapes refused, and the escape asserted
    absent rather than merely "an error was raised".
    """
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    escaped = tmp_path / "escaped-outside-dir.db"
    dangling = tmp_path / "dangling.db"
    dangling.symlink_to(escaped)
    with pytest.raises(ProximoError, match="symlink"):
        vectors.VectorStore(str(dangling))
    assert not escaped.exists(), "the create followed the link and escaped the configured path"

    victim = tmp_path / "victim.txt"
    victim.write_text("unrelated")
    victim.chmod(0o644)
    link = tmp_path / "link.db"
    link.symlink_to(victim)
    with pytest.raises(ProximoError, match="symlink"):
        vectors.VectorStore(str(link))
    assert stat.S_IMODE(os.stat(victim).st_mode) == 0o644, (
        "an unrelated file's permissions were narrowed through the link")


def test_symlinked_memory_path_is_refused(tmp_path):
    """Same guard, same reason, on the estate map itself — _own_the_file is shared."""
    from proximo import memory
    escaped = tmp_path / "escaped-memory.db"
    link = tmp_path / "memory-link.db"
    link.symlink_to(escaped)
    with pytest.raises(ProximoError, match="symlink"):
        memory.EstateMemory(str(link))
    assert not escaped.exists()


def test_store_file_is_owner_only(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    path = tmp_path / "vectors.db"
    vectors.VectorStore(str(path)).close()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_sync_embeds_only_new_or_changed(store, monkeypatch):
    embed, calls = fake_embedder({"gitea": [1.0, 0.0, 0.0]})
    monkeypatch.setattr(vectors, "embed_texts", embed)
    store.sync("t", [("a", "gitea box"), ("b", "other")])
    assert sum(len(c) for c in calls["texts"]) == 2
    store.sync("t", [("a", "gitea box"), ("b", "other")])         # unchanged: no embeds
    assert sum(len(c) for c in calls["texts"]) == 2
    store.sync("t", [("a", "gitea box CHANGED"), ("b", "other")])  # one changed: one embed
    assert sum(len(c) for c in calls["texts"]) == 3


def test_sync_deletes_absent_keys(store, monkeypatch):
    embed, _ = fake_embedder({})
    monkeypatch.setattr(vectors, "embed_texts", embed)
    store.sync("t", [("a", "x"), ("b", "y")])
    store.sync("t", [("a", "x")])
    rows = store._db.execute("SELECT key FROM vectors WHERE namespace='t'").fetchall()
    assert rows == [("a",)]


def test_model_change_re_embeds(store, monkeypatch):
    embed, calls = fake_embedder({})
    monkeypatch.setattr(vectors, "embed_texts", embed)
    monkeypatch.setenv("PROXIMO_EMBED_MODEL", "model-one")
    store.sync("t", [("a", "x")])
    monkeypatch.setenv("PROXIMO_EMBED_MODEL", "model-two")
    store.sync("t", [("a", "x")])
    assert sum(len(c) for c in calls["texts"]) == 2


def test_query_prefix_applies_to_queries_never_documents(store, monkeypatch):
    """PROXIMO_EMBED_QUERY_PREFIX rides the query embedding only — documents stay
    unprefixed and their hashes stable, so setting it costs no re-index."""
    embed, calls = fake_embedder({})
    monkeypatch.setattr(vectors, "embed_texts", embed)
    monkeypatch.setenv("PROXIMO_EMBED_QUERY_PREFIX", "Instruct: find the tool\nQuery: ")
    store.sync("t", [("a", "doc text")])
    store.search("t", "user question")
    flat = [t for batch in calls["texts"] for t in batch]
    assert flat == ["doc text", "Instruct: find the tool\nQuery: user question"]


def test_cross_dimension_row_is_skipped_not_fatal(store, monkeypatch):
    """A row from another embedding space must be SKIPPED, not crash the search.

    The lens proved this branch had no test: deleting it kept 21/21 green, and when the
    scenario was actually constructed the strict zip raised ValueError — so one stale row
    (two processes racing the store under different PROXIMO_EMBED_MODEL, or a model
    swapped mid-life) took down EVERY search. Assert the good row still comes back.
    """
    embed, _ = fake_embedder({"query": [1.0, 0.0, 0.0], "good": [1.0, 0.0, 0.0]})
    monkeypatch.setattr(vectors, "embed_texts", embed)
    store.sync("t", [("good", "good doc")])
    store._db.execute(                                  # a 5-dim row beside 3-dim rows
        "INSERT INTO vectors (namespace, key, text_hash, dim, vec) VALUES (?,?,?,?,?)",
        ("t", "otherspace", "h", 5, struct.pack("5f", *[0.4] * 5)))
    store._db.commit()
    ranked = store.search("t", "query text")
    assert [k for k, _ in ranked] == ["good"]


def test_semantic_fill_drops_off_catalog_names_even_without_a_sync(monkeypatch, tmp_path):
    """The `name not in candidates` guard, pinned at the door sync() does not cover.

    The lens deleted this guard and the whole suite stayed green, because semantic_fill
    always syncs the authoritative set first, so no off-catalog row can survive to be
    filtered. That makes the guard the SECOND of two overlapping guarantees — real, but
    only exercised by a caller that searches without syncing. Simulate exactly that:
    stub the sync to a no-op, leave a stale row in the store, and require it stays out.
    """
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    monkeypatch.setenv("PROXIMO_VECTORS_PATH", str(tmp_path / "vectors.db"))
    embed, _ = fake_embedder({"retired": [1.0, 0.0, 0.0], "wanted": [0.9, 0.1, 0.0],
                              "find something": [1.0, 0.0, 0.0]})
    monkeypatch.setattr(vectors, "embed_texts", embed)

    seed = vectors.VectorStore(vectors.vectors_path())
    seed.sync("tools", [("retired_tool", "retired thing"), ("live_tool", "wanted thing")])
    seed.close()
    monkeypatch.setattr(vectors.VectorStore, "sync", lambda *a, **k: None)

    rows = vectors.semantic_fill({"live_tool": "wanted thing"}, "find something", set(), 5)
    assert [r["name"] for r in rows] == ["live_tool"], (
        "a vector for a tool absent from the candidate catalog surfaced")


def test_search_ranks_by_similarity(store, monkeypatch):
    embed, _ = fake_embedder({
        "memory": [1.0, 0.0, 0.0],
        "near":   [0.9, 0.1, 0.0],
        "far":    [0.0, 1.0, 0.0],
    })
    monkeypatch.setattr(vectors, "embed_texts", embed)
    store.sync("t", [("hit", "near thing"), ("miss", "far thing")])
    ranked = store.search("t", "memory usage")
    assert [k for k, _ in ranked][0] == "hit"
    assert ranked[0][1] > ranked[1][1]


# --- search_tools hybrid ----------------------------------------------------------------

def _wire_semantic(monkeypatch, tmp_path, vocab):
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    monkeypatch.setenv("PROXIMO_VECTORS_PATH", str(tmp_path / "vectors.db"))
    embed, calls = fake_embedder(vocab)
    monkeypatch.setattr(vectors, "embed_texts", embed)
    return calls


def test_semantic_fills_behind_keyword(monkeypatch, tmp_path):
    """The query is one keyword genuinely cannot reach, and the precondition says so.

    This test used to ask "memory usage of a container" and assert pve_guest_status came
    back marked `semantic`. That premise DIED on 2026-08-01, in a good way: keyword
    search now draws its synonyms from the shared lexical.VOCABULARY, so memory->mem,
    usage->status and container->guest let the KEYWORD tier answer that probe outright —
    it arrives unmarked, and the old assertion failed with KeyError('match'). A test whose
    premise has quietly become false proves nothing, so the query moved to one no synonym
    bridges, and the precondition is now asserted rather than assumed.
    """
    _wire_semantic(monkeypatch, tmp_path, {
        "provisioning ceremony": [1.0, 0.0, 0.0],
        "runtime status": [0.95, 0.05, 0.0],   # pve_guest_status: near the query
    })
    monkeypatch.setenv("PROXIMO_LEXICAL", "off")   # isolate the neural rung
    with monkeypatch.context() as m:               # precondition: keyword alone finds none
        m.setattr(vectors, "vectors_enabled", lambda: False)
        assert lean.search_tools(CATALOG, "provisioning ceremony", limit=3) == [], (
            "keyword already answers this query, so the test cannot prove semantic fill")
    rows = lean.search_tools(CATALOG, "provisioning ceremony", limit=3)
    sem = [r for r in rows if r["name"] == "pve_guest_status"]
    assert sem and sem[0]["match"] == "semantic"


def test_keyword_hits_stay_first_and_unmarked(monkeypatch, tmp_path):
    _wire_semantic(monkeypatch, tmp_path, {
        "snapshot": [1.0, 0.0, 0.0],
        "runtime status": [0.9, 0.1, 0.0],
    })
    rows = lean.search_tools(CATALOG, "snapshot", limit=3)
    assert rows[0]["name"] == "pve_snapshot_create"
    assert "match" not in rows[0]
    assert all(r.get("match") == "semantic" for r in rows[1:])
    assert len({r["name"] for r in rows}) == len(rows)  # no dupes


def test_semantic_never_exceeds_limit(monkeypatch, tmp_path):
    _wire_semantic(monkeypatch, tmp_path, {"": [1.0, 0.0, 0.0]})
    assert len(lean.search_tools(CATALOG, "snapshot", limit=2)) <= 2


def test_blank_query_still_raises(monkeypatch, tmp_path):
    _wire_semantic(monkeypatch, tmp_path, {})
    with pytest.raises(ValueError):
        lean.search_tools(CATALOG, "   ", limit=5)


def test_embedder_failure_degrades_and_warns(monkeypatch, tmp_path, capsys):
    """An unreachable embedder must cost ONE loud warning and nothing else.

    Renamed from ..._degrades_to_keyword on 2026-08-01: with the in-wheel lexical tier
    the fall is to LEXICAL, not to bare keyword, which is the whole point of having a
    tier that needs no server. Both halves asserted here — keyword's own hit survives
    unmarked and first, and the warning names the env var — while
    test_lexical.py::test_lexical_still_fills_when_the_embedder_is_down pins the catch.
    """
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    monkeypatch.setenv("PROXIMO_VECTORS_PATH", str(tmp_path / "vectors.db"))
    def down(texts):
        raise ProximoError("embedding endpoint failed — check PROXIMO_EMBED_URL")
    monkeypatch.setattr(vectors, "embed_texts", down)
    rows = lean.search_tools(CATALOG, "snapshot", limit=5)
    assert rows[0]["name"] == "pve_snapshot_create" and "match" not in rows[0]
    assert all(r.get("match") == "lexical" for r in rows[1:]), (
        "the degrade path skipped the in-wheel tier")
    assert "PROXIMO_EMBED_URL" in capsys.readouterr().err


def test_stale_vector_for_removed_tool_never_surfaces(monkeypatch, tmp_path):
    _wire_semantic(monkeypatch, tmp_path, {"runtime status": [1.0, 0.0, 0.0],
                                           "memory usage": [1.0, 0.0, 0.0]})
    lean.search_tools(CATALOG, "memory usage", limit=4)          # index the full catalog
    smaller = {k: v for k, v in CATALOG.items() if k != "pve_guest_status"}
    rows = lean.search_tools(smaller, "memory usage", limit=4)
    assert "pve_guest_status" not in [r["name"] for r in rows]


# --- recall query -----------------------------------------------------------------------

def test_recall_query_works_with_no_embedder_configured(tmp_path, monkeypatch):
    """`query` is advertised on every install, so it must WORK on every install.

    For one day it refused without PROXIMO_EMBED_URL, and a live qwen3:8b run showed the
    cost: asked "is there a container named gitea", the model saw `query` in the schema,
    used it, got "recall query needs vector search... set PROXIMO_EMBED_URL", and ended
    the task telling its operator to go configure an embedding server — with the answer
    one argument away. A schema that offers what the default install cannot serve is a
    prompt to fail. The in-wheel lexical tier needs no model, server or config, so the
    fallback lives there.

    Mutant it kills: restoring the `if not vectors_enabled(): raise` guard.
    """
    monkeypatch.delenv("PROXIMO_EMBED_URL", raising=False)
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    from proximo import memory
    mem = memory.EstateMemory(str(tmp_path / "memory.db"))
    mem.observe("default", [
        {"kind": "lxc", "key": "3000", "name": "gitea", "node": "n1", "status": "running"},
        {"kind": "lxc", "key": "6379", "name": "redis", "node": "n1", "status": "running"},
        {"kind": "lxc", "key": "8200", "name": "openbao", "node": "n1", "status": "running"}])
    mem.close()
    out = memory.recall_state(query="gitea")
    assert out["entities"], "the query returned nothing with no embedder configured"
    assert out["entities"][0]["name"] == "gitea"
    assert out["total"] == 3, "counts must still cover the whole estate"


def test_recall_query_filters_rows_but_counts_stay_whole(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    monkeypatch.setenv("PROXIMO_VECTORS_PATH", str(tmp_path / "vectors.db"))
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    embed, _ = fake_embedder({"gitea": [1.0, 0.0, 0.0], "git box": [0.98, 0.02, 0.0]})
    monkeypatch.setattr(vectors, "embed_texts", embed)
    from proximo import memory
    mem = memory.EstateMemory(str(tmp_path / "memory.db"))
    mem.observe("default", [
        {"kind": "lxc", "key": "3000", "name": "gitea", "node": "n1", "status": "running"},
        {"kind": "lxc", "key": "6379", "name": "redis", "node": "n1", "status": "running"},
    ])
    mem.close()
    out = memory.recall_state(query="the git box")
    names = [e["name"] for e in out["entities"]]
    assert names[0] == "gitea"
    assert out["query"] == "the git box"
    assert "top" in out["note"].lower() or "match" in out["note"].lower()


def test_recall_query_counts_stay_whole_when_rows_are_actually_dropped(tmp_path, monkeypatch):
    """The counts-vs-rows invariant, on an estate BIGGER than the filter's limit.

    The first version of this test seeded 2 entities against entity_filter's default
    limit=8, so nothing was ever dropped — the rows came back merely reordered and
    `total == 2` passed whether or not the invariant existed. An adversarial lens
    proved it vacuous by adding `out["total"] = len(out["entities"])` to recall_state:
    the whole suite stayed green, and the same mutant reports total=8 of 20 here.
    A fixture that never crosses the threshold cannot test the threshold.
    """
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    monkeypatch.setenv("PROXIMO_VECTORS_PATH", str(tmp_path / "vectors.db"))
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    embed, _ = fake_embedder({"gitea": [1.0, 0.0, 0.0], "git box": [0.99, 0.01, 0.0]})
    monkeypatch.setattr(vectors, "embed_texts", embed)
    from proximo import memory
    mem = memory.EstateMemory(str(tmp_path / "memory.db"))
    mem.observe("default", [{"kind": "lxc", "key": "3000", "name": "gitea",
                             "node": "n1", "status": "running"}]
                + [{"kind": "lxc", "key": str(7000 + i), "name": f"box{i}",
                    "node": "n1", "status": "running"} for i in range(19)])
    mem.close()
    out = memory.recall_state(query="the git box")
    assert len(out["entities"]) < 20, (
        "precondition: the filter must actually drop rows here, else this proves nothing")
    assert out["total"] == 20, "counts must stay whole-estate under a query filter"
    assert out["by_kind"]["lxc"] == 20
    assert out["guest_summary"]["total"] == 20


def test_recall_summary_with_query_refuses(tmp_path, monkeypatch):
    """detail='summary' carries no entity rows, so a query there filtered nothing —
    and worse, synced an EMPTY authoritative set, whose stale-key deletion wiped every
    cached entity vector for the target. It also injected an `entities: []` key the
    summary shape omits, under a note claiming matches were made. Refuse instead.
    Both halves asserted: the refusal, AND that the cache survives it.
    """
    monkeypatch.setenv("PROXIMO_EMBED_URL", "http://embed.invalid")
    monkeypatch.setenv("PROXIMO_VECTORS_PATH", str(tmp_path / "vectors.db"))
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    embed, calls = fake_embedder({"gitea": [1.0, 0.0, 0.0]})
    monkeypatch.setattr(vectors, "embed_texts", embed)
    from proximo import memory
    mem = memory.EstateMemory(str(tmp_path / "memory.db"))
    mem.observe("default", [{"kind": "lxc", "key": "3000", "name": "gitea",
                             "node": "n1", "status": "running"}])
    mem.close()

    memory.recall_state(query="git")                      # builds the entity cache
    embedded_before = sum(len(c) for c in calls["texts"])
    with pytest.raises(ProximoError, match="summary"):
        memory.recall_state(detail="summary", query="git")
    memory.recall_state(query="git")                      # cache must still be warm
    assert sum(len(c) for c in calls["texts"]) == embedded_before + 1, (
        "the summary+query call evicted the entity vectors — the next query re-embedded")


def test_summary_without_query_still_works(tmp_path, monkeypatch):
    """The other half: the refusal must be scoped to summary+QUERY, not to summary."""
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    from proximo import memory
    mem = memory.EstateMemory(str(tmp_path / "memory.db"))
    mem.observe("default", [{"kind": "lxc", "key": "3000", "name": "gitea",
                             "node": "n1", "status": "running"}])
    mem.close()
    out = memory.recall_state(detail="summary")
    assert out["total"] == 1 and "entities" not in out


# --- the next-tool pointer: what the map cannot answer, named by the server ---------------

def test_recall_names_the_tool_the_map_cannot_be(tmp_path, monkeypatch):
    """Two live qwen3:8b runs ended by declaring a capability absent that exists.

    Asked for redis's memory, the model got the entity and said "the available tools do
    not include memory consumption metrics for containers" — false, pve_guest_status
    returns mem. Asked who changed a config, it said no such tool exists — false,
    audit_verify was resident in its own tool list. It never searched, and telling it to
    search in the system prompt changed nothing across both runs. The server knows what
    the map does not hold, so it says the tool name in the response.

    Mutant it kills: dropping the `next` key, or making the pointer unconditional.
    """
    monkeypatch.delenv("PROXIMO_EMBED_URL", raising=False)
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    from proximo import memory
    mem = memory.EstateMemory(str(tmp_path / "memory.db"))
    mem.observe("default", [
        {"kind": "lxc", "key": "6379", "name": "redis", "node": "n1", "status": "running"},
        {"kind": "lxc", "key": "3000", "name": "gitea", "node": "n1", "status": "running"}])
    mem.close()

    # THE CALL SHAPE A MODEL ACTUALLY MAKES. The first version of this test asked with the
    # user's whole sentence ("how much memory is redis using") and passed — while the real
    # thing did not fire at all, because qwen3:8b sends `query='redis'`, a SEARCH TERM. A
    # fixture using input no model produces cannot test the path it names.
    out = memory.recall_state(query="redis")
    assert out["next"], "no pointer on the call shape a model actually makes"
    assert out["next"]["subject"]["vmid"] == "6379", "pointed at no subject"
    assert "pve_guest_status" in out["next"]["for_more"]
    # audit_entries, not audit_verify (2026-08-01): the who-question needs the ledger READER,
    # not the chain prover — the old row sent a live 8B to a tool that could never answer it.
    assert "audit_entries" in out["next"]["for_more"]
    assert "6379" in out["next"]["hint"], "the hint does not name the subject to act on"
    cost = len(json.dumps(out["next"])) // 4
    assert cost <= 150, f"the pointer costs ~{cost} tokens; it rides on every filtered recall"


def test_next_tool_pointer_needs_a_subject(tmp_path, monkeypatch):
    """A pointer with no entity behind it is advice the caller cannot act on."""
    monkeypatch.delenv("PROXIMO_EMBED_URL", raising=False)
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    monkeypatch.setenv("PROXIMO_MEMORY_PATH", str(tmp_path / "memory.db"))
    from proximo import memory
    mem = memory.EstateMemory(str(tmp_path / "memory.db"))
    mem.observe("default", [{"kind": "lxc", "key": "3000", "name": "gitea",
                             "node": "n1", "status": "running"}])
    mem.close()
    out = memory.recall_state(query="memory usage of zzzznotathing")
    assert out.get("next") is None or out["entities"], "pointer offered with no subject"
