"""Opt-in vector search over the estate sqlite — the drawers find themselves.

INERT unless ``PROXIMO_EMBED_URL`` names an OpenAI-compatible ``/v1/embeddings``
server (ollama, llama.cpp and vLLM all serve one) — the memory/wiki opt-in
discipline: no env, no behavior change, no store, no network. The operator points
at an embedder THEY run, so nothing leaves their estate. ``PROXIMO_EMBED_MODEL``
optionally names the model (servers hosting one model ignore it).

Zero new dependencies (wiki.py's law): vectors are struct-packed float32 BLOBs in
sqlite, similarity is a pure-python dot product over unit vectors. At catalog
scale (~900 rows) a search costs tens of milliseconds — beside an embedding HTTP
round trip, arithmetic is not the cost.

Everything is LAZY and self-healing: no startup hook, no embed inside observe.
The first semantic search syncs the index (content-hashed, so only new/changed
texts embed — the model name is part of the hash, so swapping embedding models
re-embeds rather than comparing vectors from different spaces). An embedder that
is down costs exactly one degraded search, never a slow server start and never a
poisoned read path. Degradation is LOUD (stderr, once per reason) and callers
mark which ranking produced each row — a reader must be able to tell semantic
fill from keyword precision.

The store lives beside the audit log (``PROXIMO_VECTORS_PATH`` overrides) and is
created owner-only via memory's _own_the_file: embedded entity names are derived
ESTATE INVENTORY, the same class of data memory.db learned to protect on 07-29.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import struct
import sys
import urllib.request
from math import isfinite, sqrt

from proximo.backends import ProximoError
from proximo.memory import _DEFAULT_AUDIT_LOG, _own_the_file, _warned
from proximo.ranking import rows_from_hits

_BATCH = 64
_ENV = "PROXIMO_EMBED_URL"


def _max_dim() -> int:
    """Headroom over every embedding model in common use (the largest are 4096-dim), so a
    real model never trips it and a misbehaving endpoint cannot inflate the store. Read
    per call, never at import, so the env is honored wherever it is set."""
    return int(os.environ.get("PROXIMO_EMBED_MAX_DIM", "16384"))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vectors (
  namespace TEXT NOT NULL,
  key       TEXT NOT NULL,
  text_hash TEXT NOT NULL,
  dim       INTEGER NOT NULL,
  vec       BLOB NOT NULL,
  PRIMARY KEY (namespace, key)
);
"""


def vectors_enabled() -> bool:
    return bool(os.environ.get(_ENV, "").strip())


def _embed_url() -> str:
    url = os.environ.get(_ENV, "").strip()
    if not url:
        raise ProximoError(
            f"{_ENV} is not set — point it at an OpenAI-compatible /v1/embeddings "
            "server you run (ollama, llama.cpp, vLLM) to enable vector search")
    if not url.lower().startswith(("http://", "https://")):
        # A file:/custom scheme here would turn the embedder call into a local read.
        raise ProximoError(
            f"{_ENV} must be an http(s) URL, got {url!r}")
    return url.rstrip("/")


def _embed_model() -> str:
    return os.environ.get("PROXIMO_EMBED_MODEL", "default")


def vectors_path() -> str:
    explicit = os.environ.get("PROXIMO_VECTORS_PATH")
    if explicit:
        return explicit
    audit = os.environ.get("PROXIMO_AUDIT_LOG", _DEFAULT_AUDIT_LOG)
    return os.path.join(os.path.dirname(audit) or ".", "vectors.db")


def embed_texts(texts: list[str]) -> list[list[float]]:
    """Batched OpenAI-style embeddings, re-ordered by the response's own index field.

    Raises ProximoError naming the env var on any failure or shape mismatch — a
    silent partial result would let a half-indexed catalog masquerade as searched.
    """
    out: list[list[float]] = []
    timeout = float(os.environ.get("PROXIMO_EMBED_TIMEOUT", "30"))
    for i in range(0, len(texts), _BATCH):
        chunk = texts[i:i + _BATCH]
        body = json.dumps({"model": _embed_model(), "input": chunk}).encode()
        req = urllib.request.Request(  # noqa: S310 — scheme pinned http(s) in _embed_url
            _embed_url() + "/v1/embeddings", data=body,
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — as above
                payload = json.loads(r.read())
        except ProximoError:
            raise
        except Exception as e:
            raise ProximoError(
                f"embedding endpoint failed ({type(e).__name__}: {e}) — check {_ENV} "
                "points at a live OpenAI-compatible /v1/embeddings server") from e
        rows = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(rows, list) or len(rows) != len(chunk):
            got = len(rows) if isinstance(rows, list) else "no"
            raise ProximoError(
                f"embedding endpoint returned {got} vectors for {len(chunk)} inputs "
                f"— check {_ENV} / PROXIMO_EMBED_MODEL")
        # The index field must be a PERMUTATION of 0..n-1, checked before it is trusted
        # to re-order. Counting rows is not enough: an endpoint answering {index:-1},
        # {index:0} for two inputs passes a count check and lands its vector in the WRONG
        # input's slot — text and vector silently misaligned, every later score wrong with
        # nothing raised. Duplicates do the same. Found by an adversarial lens, 2026-08-01.
        indices = [row.get("index") for row in rows]
        if sorted(i for i in indices if isinstance(i, int)) != list(range(len(chunk))):
            raise ProximoError(
                f"embedding endpoint returned indices {indices!r} for {len(chunk)} inputs "
                f"— not a 0..n-1 permutation, so vectors cannot be matched to their text; "
                f"check {_ENV} / PROXIMO_EMBED_MODEL")
        rows = sorted(rows, key=lambda d: d["index"])
        vecs = [row.get("embedding") for row in rows]
        if any(not isinstance(v, list) or not v for v in vecs):
            raise ProximoError(
                f"embedding endpoint returned a malformed vector — check {_ENV} / "
                "PROXIMO_EMBED_MODEL")
        # One dimension for the whole response, bounded, and finite. A ragged batch would
        # crash the strict zip in search(); an unbounded dim lets a misbehaving endpoint
        # inflate the store without limit (2M floats accepted before this); a NaN
        # propagates through normalize into every score AND serializes as the bare token
        # `NaN`, which is invalid JSON and can fail a strict client's parse of the WHOLE
        # response. All three: refuse the batch, name the endpoint.
        dim, ceiling = len(vecs[0]), _max_dim()
        if dim > ceiling:
            raise ProximoError(
                f"embedding endpoint returned {dim}-dimensional vectors, over the "
                f"{ceiling} ceiling (raise PROXIMO_EMBED_MAX_DIM if your model is "
                f"genuinely larger) — check {_ENV}")
        for v in vecs:
            if len(v) != dim:
                raise ProximoError(
                    f"embedding endpoint returned mixed dimensions ({dim} and {len(v)}) "
                    f"in one batch — check {_ENV} / PROXIMO_EMBED_MODEL")
            if not all(isinstance(x, (int, float)) and isfinite(x) for x in v):
                raise ProximoError(
                    f"embedding endpoint returned a non-finite value (NaN/Inf) — check "
                    f"{_ENV} / PROXIMO_EMBED_MODEL")
        out.extend(vecs)
    return out


def _normalize(vec: list[float]) -> list[float]:
    norm = sqrt(sum(x * x for x in vec))
    return [x / norm for x in vec] if norm else vec


def _text_hash(text: str) -> str:
    return hashlib.sha256(f"{_embed_model()}\x00{text}".encode()).hexdigest()


class VectorStore:
    """Content-hash-synced vector index in the estate sqlite. Owner-only on create."""

    def __init__(self, path: str):
        if os.path.isdir(path):
            raise ProximoError(
                f"{path} is a directory, not a file — point PROXIMO_VECTORS_PATH at "
                "the .db file itself")
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        _own_the_file(path)
        self._db = sqlite3.connect(path)
        self._db.executescript(_SCHEMA)
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def sync(self, namespace: str, items: list[tuple[str, str]]) -> None:
        """Make the namespace hold exactly `items`, embedding only new/changed texts."""
        existing = dict(self._db.execute(
            "SELECT key, text_hash FROM vectors WHERE namespace=?", (namespace,)))
        keep = {key for key, _ in items}
        stale = [(namespace, k) for k in existing if k not in keep]
        if stale:
            self._db.executemany(
                "DELETE FROM vectors WHERE namespace=? AND key=?", stale)
        todo = [(key, text, _text_hash(text)) for key, text in items
                if existing.get(key) != _text_hash(text)]
        if todo:
            embedded = embed_texts([text for _, text, _ in todo])
            for (key, _, h), vec in zip(todo, embedded, strict=True):
                unit = _normalize(vec)
                self._db.execute(
                    "INSERT OR REPLACE INTO vectors (namespace, key, text_hash, dim, vec)"
                    " VALUES (?,?,?,?,?)",
                    (namespace, key, h, len(unit), struct.pack(f"{len(unit)}f", *unit)))
        self._db.commit()

    def search(self, namespace: str, query: str, limit: int = 10) -> list[tuple[str, float]]:
        # Query-side only: asymmetric embedding models (Qwen3-Embedding, bge, nomic) rank
        # measurably better with an instruction/task prefix on the QUERY. Never applied to
        # documents, so setting or changing it costs no re-index. Measured live 2026-08-01:
        # it moved pve_guest_status into top-3 for "memory usage of a container" where the
        # unprefixed query returned only storage-plane noise.
        prefix = os.environ.get("PROXIMO_EMBED_QUERY_PREFIX", "")
        qv = _normalize(embed_texts([prefix + query])[0])
        scored: list[tuple[float, str]] = []
        for key, dim, blob in self._db.execute(
                "SELECT key, dim, vec FROM vectors WHERE namespace=?", (namespace,)):
            if dim != len(qv):
                # A row from a different embedding space — two processes racing the same
                # store under different PROXIMO_EMBED_MODEL, or a model swapped mid-life.
                # Skipping is the whole point: without it the strict zip below raises and
                # ONE stale row takes down every search. sync() heals the row on next pass.
                continue
            vec = struct.unpack(f"{dim}f", blob)
            scored.append((sum(a * b for a, b in zip(qv, vec, strict=True)), key))
        scored.sort(key=lambda row: (-row[0], row[1]))
        return [(key, round(score, 4)) for score, key in scored[:limit]]


def _warn_once(reason: str) -> None:
    if reason not in _warned:
        _warned.add(reason)
        print(f"proximo: {reason}", file=sys.stderr)


def semantic_fill(candidates: dict[str, str], query: str,
                  taken: set[str], room: int) -> list[dict]:
    """Top-`room` semantic matches from `candidates` (name -> summary), skipping `taken`.

    Syncs the tools namespace first (content-hashed: steady-state cost is one query
    embedding). Only names present in `candidates` are returned, so a stale vector
    for a since-removed or since-scoped-away tool can never surface. Callers own
    degradation: this raises ProximoError when the embedder is unreachable.

    ⚠️ **There is deliberately NO minimum-score floor here, and that is a real limit
    worth stating rather than papering over.** `lexical.py` can have one because its
    scores are sparse-overlap: garbage genuinely scores near zero. Dense embeddings do
    not behave that way — everything is somewhat similar to everything, and the scale is
    model-specific. Measured 2026-08-01 against Qwen3-Embedding-0.6B on the real 313-tool
    index: "how much space is left for backups" scored 0.69/0.63/0.63 on its top three,
    while **"recipe for banana bread" scored 0.47** on tools it has nothing to do with —
    only ~1.4x below signal, and another model would put both somewhere else entirely.
    So a constant here would be a guess that silently drops real answers on one model and
    admits nonsense on another. The neural rung fills its room and marks every row
    `"semantic"`; the marking is what lets a reader discount it. An operator who wants
    only exact matches has `limit` and the keyword tier for that.
    """
    if room <= 0:
        return []
    store = VectorStore(vectors_path())
    try:
        store.sync("tools", [(name, f"{name}: {summary}")
                             for name, summary in sorted(candidates.items())])
        hits = store.search("tools", query, limit=room + len(taken))
    finally:
        store.close()
    return rows_from_hits(hits, candidates, taken, room, "semantic")


def _entity_text(row: dict) -> str:
    return (f"{row['kind']} {row['key']} named {row.get('name') or '?'} "
            f"on node {row.get('node') or '?'}, {row.get('status') or 'unknown'}")


def entity_filter(target: str, rows: list[dict], query: str, limit: int = 8) -> list[dict]:
    """Top-`limit` entity rows for `query`, scoped to the live rows only.

    Uses the neural index when `PROXIMO_EMBED_URL` is configured, and the in-wheel
    lexical tier when it is not — never refuses for want of an embedder.

    It DID refuse, for one day, and a live run showed exactly what that costs. A
    qwen3:8b asked "is there a container named gitea", saw `query` advertised on
    proximo_recall, used it, got back "recall query needs vector search… set
    PROXIMO_EMBED_URL" — and ended the task by telling its operator to go configure an
    embedding server. The unfiltered answer it needed was one argument away and it never
    tried. ⭐ **A schema that advertises a capability the default install cannot serve is
    a prompt to fail** (`feedback_a-tool-description-is-a-prompt`). The parameter is
    always offered, so it must always work; `lexical.py` needs no model, no server and
    no config, which is precisely why the fallback belongs there.
    """
    by_key = {f"{r['kind']}/{r['key']}": r for r in rows}
    if not vectors_enabled():
        from proximo.lexical import LexicalIndex

        if not by_key:
            return []
        index = LexicalIndex({key: _entity_text(r) for key, r in by_key.items()})
        return [by_key[key] for key, _ in index.search(query, limit=limit) if key in by_key]
    store = VectorStore(vectors_path())
    try:
        store.sync(f"entities:{target}",
                   [(key, _entity_text(r)) for key, r in sorted(by_key.items())])
        hits = store.search(f"entities:{target}", query, limit=limit)
    finally:
        store.close()
    return [by_key[key] for key, _ in hits if key in by_key]
