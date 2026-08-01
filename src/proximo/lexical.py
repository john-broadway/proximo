"""The in-package search tier — a vocabulary table and lexical vectors, no model at all.

WHY THIS TIER EXISTS. Keyword search (``lean.search_tools``) requires the operator's
words to appear in a tool's name or description. Operators do not type our vocabulary:
"memory usage of a container" matches NOTHING, because the tool that answers it says
"runtime status of one guest — cpu, mem, uptime". The neural rung (``vectors.py``)
crosses that gap, but it costs an embedding server the adopter has to run.

This layer sits between them and ships INSIDE the wheel: pure stdlib, no dependency, no
network, no model, no download. An adopter who installs Proximo and configures nothing
still gets a search that finds the right drawer. Two mechanisms, in order:

1. **The vocabulary tier** — ``VOCABULARY`` maps operator language onto Proxmox's own
   terms (memory→mem/ram, container→lxc/ct/guest, who/changed→audit/ledger). It is
   CURATED DATA, not a model: every mapping is one readable line an operator can audit
   and extend. Measured 2026-08-01 on the live catalog, this table is what moved the hard
   probes from miss to hit — bare lexical vectors alone ranked `pve_create_container`
   first for "memory usage of a container" (matching the WORD) and never found
   `pve_guest_status` at all. It serves RANKING ONLY; the keyword tier draws from the
   deliberately narrower ``KEYWORD_VOCABULARY`` (see its comment for the measurement
   that forced the split).

2. **Lexical vectors** — hashed character 3/4-grams plus whole words, TF-IDF weighted,
   cosine over unit vectors. N-grams give sub-word robustness (typos, "backups" vs
   "backup", "firewalls" vs "firewall") that exact substring matching cannot.

⚠️ **The bucket hash must be STABLE ACROSS PROCESSES.** Python's builtin ``hash()`` on
str is salted per interpreter (PYTHONHASHSEED), so the same gram lands in different
buckets in different processes — silently, no error, garbage similarity. The first
prototype of this module used the builtin; ``_bucket`` uses blake2b instead and a test
pins its output against a literal, so changing it is a deliberate act rather than
invisible drift.

This tier is DEFAULT-ON (``PROXIMO_LEXICAL=off`` disables it) because it is strictly
additive: it never removes or reorders a keyword hit, only fills room the keyword search
left empty. Requiring an env var to get a working search would defeat the purpose.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter

from proximo.ranking import rows_from_hits

_TRUTHY_OFF = ("0", "false", "no", "off")

# Function words carry no domain signal, so they must not ADMIT a document to the result
# set (they still contribute to ranking, where idf already discounts them). Without this,
# "recipe for banana bread" was admitted to `pmg_statistics_receiver` on the word "for"
# alone — the same class of false answer as the n-gram collision that motivated the
# admission rule, one layer up.
_STOPWORDS = frozenset("""
a an the and or of for to in on at by with from is are was were be been being this that
these those it its as if then than so how what when where which who whom whose why do does
did done have has had can could should would will shall may might must not no yes all any
some my your our their his her one two i you he she we they me him us them
""".split())
_DIM = 4096
# Below this a "match" is n-gram noise and reporting it is worse than reporting nothing —
# a small model reads a returned row as an answer. MEASURED on the real 313-tool catalog
# 2026-08-01, not chosen by taste: genuine hits score 0.29-0.55 ("who changed this vm's
# config" -> audit_verify 0.52), while deliberate garbage ("asdfgh qwerty zxcvb") tops out
# at 0.10. The same split holds on the small test fixture (hits 0.35-0.68, garbage 0.03).
_MIN_SCORE = 0.15

# Operator language → Proxmox's own terms. CURATED, auditable, one line per mapping.
# WIDENS a query, never replaces it: "vm" must still find pve_create_vm (whose text says
# vm, not guest) while also reaching pve_delete_guest. Keep entries lowercase; a term
# must not expand to itself (both pinned by tests).
#
# ⚠️ **THIS TABLE IS FOR RANKING ONLY. It must never feed the keyword tier** — see
# KEYWORD_VOCABULARY below for why, and `test_vocabulary_width_is_safe_for_ranking_only`
# for the measurement that enforces it.
VOCABULARY: dict[str, tuple[str, ...]] = {
    # what a thing is
    "vm": ("guest", "qemu"),
    "container": ("guest", "lxc", "ct"),
    "ct": ("guest", "lxc"),
    "lxc": ("guest",),
    "qemu": ("guest", "vm"),
    "machine": ("guest", "vm"),
    "server": ("node", "host"),
    "box": ("node", "guest"),
    "host": ("node",),
    # what you want done
    "destroy": ("delete", "remove"),
    "remove": ("delete",),
    "kill": ("stop", "shutdown"),
    "reboot": ("restart", "power"),
    "turn": ("set", "power"),
    "off": ("disable", "stop", "shutdown"),
    "on": ("enable", "start"),
    "make": ("create",),
    "new": ("create",),
    "list": ("get", "status"),
    "show": ("get", "status", "list"),
    "check": ("status", "doctor", "diagnose"),
    "fix": ("doctor", "diagnose", "repair"),
    "undo": ("rollback", "revert", "restore"),
    # what you want to know
    "memory": ("mem", "ram"),
    "mem": ("memory", "ram"),
    "ram": ("mem", "memory"),
    "cpu": ("status", "load"),
    "usage": ("status", "used", "current"),
    "space": ("disk", "storage", "usage"),
    "free": ("available", "usage"),
    "left": ("available", "free", "usage"),
    "full": ("usage", "status"),
    "size": ("disk", "usage"),
    "health": ("status", "doctor", "diagnose"),
    "broken": ("diagnose", "doctor", "error"),
    "failed": ("error", "diagnose", "task"),
    "slow": ("diagnose", "load", "status"),
    # provenance — the PROVE plane, which operators ask for in plain words
    "who": ("audit", "ledger", "verify"),
    "changed": ("config", "audit", "ledger", "history"),
    "history": ("audit", "ledger", "task"),
    "when": ("task", "audit", "history"),
    "log": ("task", "audit", "journal"),
    # domain nouns operators shorten
    "backup": ("vzdump", "pbs"),
    "backups": ("backup", "vzdump", "pbs"),
    "snapshot": ("snap",),
    "disk": ("storage", "volume"),
    "network": ("net", "iface", "bridge"),
    "ip": ("network", "iface"),
    "firewall": ("fw", "rule"),
    "user": ("access", "acl", "token"),
    "permission": ("acl", "role", "access"),
    "password": ("access", "token", "user"),
    "mail": ("pmg", "mailgw"),
    "spam": ("pmg", "quarantine"),
    "cluster": ("node", "quorum"),
}


# The keyword tier's synonyms — DELIBERATELY NARROW, and a separate table on purpose.
#
# Sharing the wide VOCABULARY above with keyword search was tried on 2026-08-01 and was a
# design error, caught by an adversarial lens with a measurement: on the real 905-tool
# catalog the query "on" matched 905 of 905 tools (100%), "show" 824, "list" 814, and the
# natural phrase "check cluster health" 187 — because `check`→status/doctor/diagnose and
# `health`→status/doctor/diagnose each widen onto words that appear in most descriptions,
# so an AND across terms stops filtering. That is precisely the OR-blowup lean mode's
# AND-semantics exists to prevent, re-introduced by the widening.
#
# The two tiers need OPPOSITE widths and cannot share one table:
#   keyword  AND-FILTERS. A synonym that matches everything makes the filter useless.
#            Every entry here must be a near-exact rename (vm/ct→guest), never a
#            concept-level jump (health→status).
#   lexical  RANKS by cosine. A wide vocabulary HELPS: the ranking sorts out the noise
#            and the score floor drops the rest. That is why VOCABULARY stays wide.
#
# Guarded by test_lexical.py's blast-radius test, which measures both tables against the
# real tracked 905-tool manifest and fails if a single-term keyword query matches more
# than a small fraction of the catalog. A comment cannot hold this line; a measurement can.
KEYWORD_VOCABULARY: dict[str, tuple[str, ...]] = {
    "vm": ("guest",),
    "container": ("guest",),
    "ct": ("guest",),
    "lxc": ("guest",),
    "qemu": ("guest",),
    "destroy": ("delete",),
    "remove": ("delete",),
    "vzdump": ("backup",),
}


def lexical_enabled() -> bool:
    return os.environ.get("PROXIMO_LEXICAL", "").strip().lower() not in _TRUTHY_OFF


def _bucket(gram: str, dim: int) -> int:
    """Stable gram→bucket. NEVER the builtin hash(): it is salted per process, so the
    same gram would land in different buckets in different processes — silently, and
    fatally for any persisted index. Pinned against a literal by test."""
    digest = hashlib.blake2b(gram.encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") % dim


def _tokens(text: str) -> list[str]:
    return re.sub(r"[^a-z0-9 ]", " ", text.lower()).split()


def _grams(text: str) -> list[str]:
    """Character 3/4-grams (padded, so word boundaries matter) plus the whole words."""
    out: list[str] = []
    for token in _tokens(text):
        padded = f" {token} "
        for n in (3, 4):
            out += [padded[i:i + n] for i in range(len(padded) - n + 1)]
        out.append(token)
    return out


def expand_query(query: str, vocabulary: dict[str, tuple[str, ...]] | None = None) -> list[str]:
    """Query terms PLUS their vocabulary expansions. Widens, never replaces."""
    vocab = VOCABULARY if vocabulary is None else vocabulary
    terms = _tokens(query)
    out = list(terms)
    for term in terms:
        out += [e for e in vocab.get(term, ()) if e not in out]
    return out


class LexicalIndex:
    """TF-IDF over hashed n-grams for a fixed document set. Deterministic, and never
    persisted — nothing on disk, no staleness, no index to invalidate. The build is
    O(corpus) (measured: ~0.26s at 313 tools, ~0.76s at 905), so callers go through
    `_cached_index`; building it per search cost ~790ms on every call, and this docstring
    previously called that "cheap" while the CHANGELOG quoted a different figure again."""

    def __init__(self, documents: dict[str, str],
                 vocabulary: dict[str, tuple[str, ...]] | None = None, dim: int = _DIM):
        self.dim = dim
        self.vocabulary = VOCABULARY if vocabulary is None else vocabulary
        doc_grams = {name: _grams(text) for name, text in documents.items()}
        n_docs = max(len(doc_grams), 1)
        df: Counter = Counter()
        for grams in doc_grams.values():
            df.update(set(grams))
        self.idf = {g: math.log(n_docs / (1 + f)) + 1 for g, f in df.items()}
        self.vectors = {name: self._vector(grams) for name, grams in doc_grams.items()}
        # Whole-token sets, for the admission rule in search(): n-grams rank, tokens admit.
        # Plain token sets. Stopwords are filtered on the QUERY side only (see search()) —
        # that is where the rule belongs ("which query terms may admit a document"), and
        # filtering both sides made each half individually redundant: a mutant deleting
        # EITHER subtraction survived the whole suite, because the other still emptied the
        # intersection. Two halves no test can tell apart are not defense in depth, they
        # are untestable code.
        self.doc_tokens = {name: set(_tokens(text)) for name, text in documents.items()}

    def _vector(self, grams: list[str]) -> dict[int, float]:
        """Sparse: a dict of bucket→weight. Dense lists cost 4096 floats per document for
        a few hundred non-zero buckets, and the dot product below only ever needs the
        overlap."""
        counts = Counter(grams)
        vec: dict[int, float] = {}
        for gram, n in counts.items():
            bucket = _bucket(gram, self.dim)
            vec[bucket] = vec.get(bucket, 0.0) + (1 + math.log(n)) * self.idf.get(gram, 1.0)
        norm = math.sqrt(sum(w * w for w in vec.values()))
        return {b: w / norm for b, w in vec.items()} if norm else vec

    def search(self, query: str, limit: int = 10) -> list[tuple[str, float]]:
        """Top-`limit` (name, score). Blank query RAISES — "no filter" must never degrade
        into "the whole catalog", the same law keyword search holds. A query that matches
        nothing returns nothing: a floor of n-gram noise is worse than an empty answer."""
        if not query or not query.strip():
            raise ValueError("query must not be blank — lexical search never returns everything")
        terms = expand_query(query, self.vocabulary)
        qv = self._vector(_grams(" ".join(terms)))
        # A candidate must share at least one WHOLE TOKEN with the (expanded) query. The
        # n-gram score alone is not enough to admit a row: character n-grams match on
        # coincidental sub-word overlap, and the score floor does not catch it. Measured
        # by an adversarial lens 2026-08-01 — "recipe for banana bread" returned
        # `pve_node_disk_wipe` ("MUTATION: wipe ALL data... RISK_HIGH, NO UNDO") at 0.162,
        # above the 0.15 floor, purely because "recipe" and "wipe" share the 3-gram "ipe".
        # Offering a destructive tool as the answer to an off-domain question is the worst
        # available outcome for exactly the small models this tier exists to serve.
        # n-grams still do the RANKING (typo and plural robustness); they no longer decide
        # ADMISSION.
        query_tokens = set(terms) - _STOPWORDS
        scored = []
        for name, dv in self.vectors.items():
            if not (query_tokens & self.doc_tokens[name]):
                continue
            small, large = (qv, dv) if len(qv) < len(dv) else (dv, qv)
            score = sum(w * large[b] for b, w in small.items() if b in large)
            if score > _MIN_SCORE:
                scored.append((-score, name))
        scored.sort()
        return [(name, round(-neg, 4)) for neg, name in scored[:limit]]


_INDEX_CACHE: dict[tuple, LexicalIndex] = {}


def _cached_index(documents: dict[str, str]) -> LexicalIndex:
    """One index per distinct document set, built once per process.

    The build is O(corpus): measured 2026-08-01 at ~0.26s for 313 tools and ~0.76s for
    905, roughly 0.85ms per tool. Rebuilding it per search — which this did until an
    adversarial lens measured the real caller cost at ~790ms on a 905-tool catalog —
    turned a 2ms ranking step into a per-call second. The "~2ms search" figure was real
    but described only the vector math on an already-built index, which no caller ever
    got. Cached on the catalog's identity (names + summaries), so a scoped or changed
    catalog builds its own entry and a stale one can never be served.
    """
    key = tuple(sorted(documents.items()))
    index = _INDEX_CACHE.get(key)
    if index is None:
        # Bounded: a handful of distinct catalogs exist per process (full, scoped, tests).
        # Cleared wholesale rather than evicted cleverly — this is a search assist, and an
        # unbounded dict of corpora is a leak nobody would notice.
        if len(_INDEX_CACHE) >= 8:
            _INDEX_CACHE.clear()
        index = _INDEX_CACHE[key] = LexicalIndex(documents)
    return index


def lexical_fill(candidates: dict[str, str], query: str,
                 taken: set[str], room: int) -> list[dict]:
    """Top-`room` lexical matches from `candidates` (name → summary), skipping `taken`.

    Mirrors vectors.semantic_fill's contract so `lean.search_tools` treats the two rungs
    identically; rows are marked "lexical" so a reader can tell which tier answered.
    """
    if room <= 0 or not candidates:
        return []
    index = _cached_index({name: f"{name}: {summary}" for name, summary in candidates.items()})
    hits = index.search(query, limit=room + len(taken))
    return rows_from_hits(hits, candidates, taken, room, "lexical")
