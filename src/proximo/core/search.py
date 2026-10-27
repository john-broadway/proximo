"""proximo_find: the words an operator says, to the address the vendor publishes.

A small model asks "list the datastores" or "guest status"; the table spells `/admin/datastore`
and `/nodes/{node}/qemu/{vmid}/status/current`. Matching every word against the path found the
right address first 38% of the time and nothing at all 46% of the time, on 0.44's own tool names
(2026-09-29). What this does instead, all of it measured, none of it a model:

  * VERBS PICK THE METHOD. `list/get/show` mean GET, `create/add/start` POST, `update/set` PUT,
    `delete/remove` DELETE (HTTP semantics). A verb is never looked for in the path; it weighs
    for the method it names and against the others.
  * WORDS SCORE BY WHERE THEY LAND: a path segment 3, the vendor's description of the operation
    2, a parameter name 1. Paths split on `/ - _`, plurals fold ("datastores" is `datastore`).
  * ENOUGH OF THE QUESTION MUST LAND: a third of its words, and at least one in a segment or the
    description, or nothing comes back (a nonsense query returns nothing, not a handful of junk).
  * A PARENTHETICAL IS DETAIL about the answer, not words for the address, and is dropped.
  * SYNONYMS ARE A RECORD (`records/vocab.toml`, shipped in the one JSON), each quoting the
    vendor's own use of the word.
  * A WORD NO TIER KNOWS MAY BE AN INFLECTION OR A TYPO (`core/lexical.py`): `restarting` is read as
    a verb, `snaphsot` as a possible `snapshot`, offered as a WEAKER alternative to what was said
    (what the operator said is never replaced). Those answers say `"match": "lexical"` on the rows
    that leaned on the guess and `"guessed"` with what was read as what; `PROXIMO_LEXICAL=off`
    turns the tier off, and an answer that ACTS (`strict`, what proximo_plan resolves) never takes it.

The descriptions rank; they never ship in the answer, so the door's 4K budget holds.
"""
from __future__ import annotations

import math
import re
from functools import cache
from typing import Any

from proximo.core import apitree, engine, lexical
from proximo.core.errors import ProximoError

# HTTP semantics, not a vocabulary guess: what each verb asks the vendor to do.
_VERBS = {
    "GET": {"list", "get", "read", "show", "view", "fetch", "query", "describe", "info", "retrieve", "check",
            "see", "display", "inspect", "look"},
    "POST": {"create", "add", "new", "start", "stop", "run", "trigger", "send", "upload", "execute",
             "shutdown", "reboot", "suspend", "resume", "restore", "migrate", "clone", "order",
             "renew", "generate", "apply", "reload", "restart"},
    "PUT": {"update", "set", "edit", "modify", "change", "configure", "rename", "move", "resize"},
    "DELETE": {"delete", "remove", "destroy", "purge", "drop", "forget", "revoke", "unregister"},
}
_VERB_OF = {w: m for m, ws in _VERBS.items() for w in ws}
_STOP = {"the", "an", "of", "for", "to", "in", "on", "and", "or", "all", "by", "with", "is", "this",
         "its", "from", "at", "as", "be", "via", "per", "one", "single", "each", "every", "any",
         "current", "given"}
_SEGMENT, _DESCRIPTION, _PARAM = 3, 2, 1


def stem(word: str) -> str:
    """Fold a plural: datastores -> datastore, entries -> entry, boxes -> box, statuses -> status.
    `es` comes off only after s/x/z/sh: `nodes` is node + s, never nod + es (2026-09-29: it was,
    and "node" matched no /nodes/ segment in the table). status/virus/address keep their s, so
    `statuses` folds to the same `status`."""
    if len(word) <= 4 or word.endswith(("ss", "us", "is")):     # status, virus, analysis
        return word
    if word.endswith("ies"):
        return word[:-3] + "y"
    if word.endswith("es") and word[:-2].endswith(("s", "x", "z", "sh")):
        return word[:-2]
    return word[:-1] if word.endswith("s") else word


def verb_methods(words: list[str]) -> set[str]:
    """The HTTP methods the verbs among `words` ask for ("delete", "stop", "list"): what the
    operator literally said, for a caller that must not act on words that ask for something else."""
    return {_VERB_OF[w.lower()] for w in words if w.lower() in _VERB_OF}


def tokens(text: str) -> list[str]:
    return [stem(t) for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


@cache
def synonyms() -> dict[str, frozenset[str]]:
    """The vocabulary from the one JSON (`compile_vocab`, the check the build ran on
    `records/vocab.toml`), in the record's own order."""
    return compile_vocab(apitree.published()["vocab"])


def compile_vocab(section: list[dict[str, Any]]) -> dict[str, frozenset[str]]:
    """The record, refused by name when a line has no why or means nothing. `section` is the one
    JSON's `vocab` list (`{word, means, why}` per entry). Pure: the build and the load share it."""
    bad = [v.get("word") for v in section
           if not (isinstance(v, dict) and isinstance(v.get("word"), str) and v["word"]
                   and isinstance(v.get("why"), str) and v["why"].strip()
                   and isinstance(v.get("means"), list) and v["means"]
                   and all(isinstance(m, str) and m for m in v["means"]))]
    if bad:
        raise ProximoError(f"vocab.toml carries lines without a why or a meaning: {sorted(str(b) for b in bad)}")
    return {v["word"]: frozenset(v["means"]) for v in section}


@cache
def descriptions() -> dict[tuple[str, str, str], str]:
    """(plane, METHOD, path) -> the vendor's sentence; the shell lane's authored rows carry their
    own, so `find` reaches them by meaning."""
    return {(r["product"], r["method"], r["path"]): r["description"] for r in apitree.published()["rows"]}


@cache
def _index() -> tuple[tuple[engine.Row, frozenset[str], frozenset[str], frozenset[str]], ...]:
    desc = descriptions()
    out = []
    for row in engine.table().values():
        segs = frozenset(t for s in row.path.strip("/").split("/") if not s.startswith("{") for t in tokens(s))
        said = frozenset(tokens(desc.get((row.product, row.method, row.path), ""))) - _STOP
        params = frozenset(t for p in row.params for t in tokens(p))
        out.append((row, segs, said, params))
    return tuple(out)


def _said(alts: frozenset[str], said: frozenset[str]) -> bool:
    """A word the vendor's sentence uses, or begins (4 letters or more): `config` is in
    "configuration", `stat` in "statistics". The path must match whole; prose abbreviates."""
    return bool(alts & said) or any(len(a) >= 4 and w.startswith(a) for a in alts for w in said)


@cache
def _stopwords() -> frozenset[str]:
    """Filler words, minus any the table spells as a path segment: `current` is filler in "the
    current config" and an address in `/status/current`, and an address word is never dropped."""
    return frozenset(_STOP - {t for _, segs, _, _ in _index() for t in segs})


@cache
def _known_words() -> frozenset[str]:
    """Every word the table spells: path segments, the vendor's sentences, parameter names, and
    the vocabulary's own words."""
    words: set[str] = {stem(k) for k in synonyms()}
    for _, segs, said, params in _index():
        words |= segs | said | params
    return frozenset(words)


@cache
def _lexical_index() -> lexical.WordIndex:
    """The n-gram index over `_known_words`. Built on the first question that says a word the table
    does not spell, never before: a question made of known words never pays for it."""
    return lexical.WordIndex(_known_words())


#: how many distinct words one question may have read as another. A question is a sentence, not a
#: document; the rest are left as said.
MAX_GUESSES = 3
#: and how many it may LOOK at: a guess is cheap to refuse but not free (about 2.6 ms a word)
MAX_LOOKED = 20

# a term: (what was said, with its synonyms), (what was said alone), (what it may have meant)
Term = tuple[frozenset[str], frozenset[str], frozenset[str]]


def _terms(query: str) -> tuple[list[Term], set[str], set[str], list[str]]:
    """The question's words (each with its synonyms), the verbs' methods, any plane named, and the
    word each term was said as (parallel to the terms)."""
    q = re.sub(r"\([^)]*\)?", " ", query.lower())
    raw = [t for t in re.split(r"[^a-z0-9]+", q) if len(t) > 1]    # a lone letter is a possessive's tail
    syn = synonyms()
    stop = _stopwords()
    named = {t for t in raw if t in apitree.PRODUCTS}
    methods = {_VERB_OF[t] for t in raw if t in _VERB_OF}
    said = [t for t in raw if t not in apitree.PRODUCTS and t not in _VERB_OF and t not in stop]
    terms = [(frozenset({stem(t)} | {stem(m) for m in syn.get(t, ())}), frozenset({stem(t)}), frozenset())
             for t in said]
    return terms, methods, named, said


class _Hit:
    """A row that scored: how, and whether the score leaned on a guess or on a synonym alone."""
    __slots__ = ("score", "row", "guessed", "by_synonym")

    def __init__(self, score: int, row: engine.Row, guessed: bool, by_synonym: bool):
        self.score, self.row, self.guessed, self.by_synonym = score, row, guessed, by_synonym


def _rank(terms: list[Term], methods: set[str], plane: str | None, method: str | None,
          strict: bool) -> list[_Hit]:
    need = len(terms) if strict else max(1, math.ceil(len(terms) / 3))
    scored = []
    for row, segs, said, params in _index():
        if (plane and row.product != plane) or (method and row.method != method):
            continue
        score = matched = 0
        guessed = by_synonym = False
        landed = False
        for alts, own, maybe in terms:
            weight = (_SEGMENT if alts & segs else 0 if strict
                      else _DESCRIPTION if _said(alts, said) else _PARAM if alts & params else 0)
            if weight == _SEGMENT and strict and not own & segs:
                by_synonym = True
            if not weight and maybe:
                # a guess may admit a row (that is how a typo lands) but weighs one less than the same
                # landing of a word said, so a real word that already scores is not displaced
                # a guess lands one weight lower than the same landing said, and never in a parameter name
                weight = _SEGMENT - 1 if maybe & segs else _DESCRIPTION - 1 if _said(maybe, said) else 0
                if weight:
                    guessed = True
                    landed = landed or bool(maybe & (segs | said))
            else:
                landed = landed or bool(alts & (segs | said))
            score += weight
            matched += weight > 0
        if terms and (matched < need or not landed):
            continue
        if methods:
            if guessed and row.method not in methods:
                continue           # a guess never puts a mutation (or a read) the question did not ask for
            score += 2 if row.method in methods else -2
        scored.append(_Hit(score, row, guessed, by_synonym))
    return scored


def _hear(terms: list[Term], said: list[str], methods: set[str]) -> tuple[list[Term], set[str], dict[str, str]]:
    """What the words nobody knows may have meant. A word NO tier knows (not a path word, a sentence
    word, a parameter or a vocabulary word) is first read as an inflection of one that is known
    (`restarting`, `destroyed`, `rolledback`): one that folds to a VERB is dropped (it is
    description, `snapshot creation` asks about a snapshot, and it never picks the method: only a
    verb the operator literally said does), any other word is offered as a weaker alternative.
    Failing that, a typo of a known word is offered the same way. What the operator said always
    stays. At most `MAX_LOOKED` distinct unknown words are looked at and `MAX_GUESSES` of them read
    (junk does not use the cap); the n-gram index is not built for a question of known words."""
    known = _known_words()
    syn = synonyms()
    seen: dict[str, int] = {}
    for i, w in enumerate(said):
        if stem(w) not in known and w not in syn:
            seen.setdefault(w, i)
    if not seen:
        return terms, methods, {}
    out, guessed, dropped = list(terms), {}, set()
    by_stem = {stem(k): m for k, m in syn.items()}
    for word, i in list(seen.items())[:MAX_LOOKED]:
        if len(guessed) >= MAX_GUESSES:
            break
        meant = None
        for b in lexical.bases(word):
            if b in _VERB_OF:
                dropped.add(i)
                guessed[word] = b
                break
            if stem(b) in known or b in syn:
                meant = stem(b)
                guessed[word] = b
                break
        else:
            if len(word) >= lexical.MIN_LENGTH:
                meant = _lexical_index().repair(stem(word))
                if meant is not None:
                    guessed[word] = meant
        if meant is not None and i not in dropped:
            alts, own, _ = out[i]
            out[i] = (alts, own, frozenset({meant} | {stem(m) for m in by_stem.get(meant, ())}))
    return [t for j, t in enumerate(out) if j not in dropped], methods, guessed


def find(query: str, plane: str | None = None, limit: int = 5, *, strict: bool = False,
         method: str | None = None) -> dict[str, Any]:
    """`method` filters to one HTTP method; it is never a word to look for. `strict`: every word
    must be a segment of the PATH ITSELF, for a caller that ACTS on a single match (proximo_plan
    given words) and so needs the address to say it, not a parameter name that happens to (lens
    2026-09-29: "POST create subscription keys" planned /auto-install/prepared, whose parameters
    spell post, subscription and key, because the literal "post" was a word to find). A single
    strict match that only a synonym reached comes back marked `choose`: plan does not act on it."""
    terms, methods, named, said = _terms(query)
    if not terms and not methods:
        raise ProximoError("give proximo_find one or more words to look for")
    guessed: dict[str, str] = {}
    if terms and not strict and lexical.enabled():
        terms, methods, guessed = _hear(terms, said, methods)
        if not terms:      # every word said was a verb in disguise: nothing is left to look for
            return {"matches": [], "note": f"no published address matched {query[:80]!r}; try other words "
                                           f"(a verb and a noun: 'list datastores') or a plane filter"}
    scored = _rank(terms, methods, plane, method, strict)
    if not scored:
        return {"matches": [], "note": f"no published address matched {query[:80]!r}; try other words "
                                       f"(a verb and a noun: 'list datastores') or a plane filter"}
    scored.sort(key=lambda h: (-h.score, bool(named) and h.row.product not in named,
                               not methods and h.row.access != engine.READ,
                               h.row.path.count("/"), len(h.row.path), h.row.product, h.row.method, h.row.path))
    top = scored[:limit]
    out: dict[str, Any] = {
        "matches": [{"plane": h.row.product, "method": h.row.method, "path": h.row.path,
                     "access": h.row.access, "tier": h.row.tier, "why": h.row.why,
                     "params": sorted(h.row.params), **({"match": "lexical"} if h.guessed else {})}
                    for h in top],
        "total": len(scored), "truncated": len(scored) > limit}
    if guessed:
        out["guessed"] = guessed
    if strict and len(scored) == 1 and scored[0].by_synonym:
        out["choose"] = "reached only through a synonym; confirm the address before acting on it"
    # the bundle's honest answer: when the best score is shared by several planes and none was
    # named, say which, so the caller picks one instead of trusting an order the words cannot set
    best = {h.row.product for h in scored if h.score == scored[0].score}
    if not plane and not named and len(best) > 1:
        out["planes"] = sorted(best)
        out["note"] = f"{', '.join(sorted(best))} each publish this; name the plane you mean"
    return out
