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
  * SYNONYMS ARE A RECORD (`vocab.toml`), each quoting the vendor's own use of the word.

The descriptions rank; they never ship in the answer, so the door's 4K budget holds.
"""
from __future__ import annotations

import json
import math
import re
import tomllib
from functools import cache
from importlib import resources
from typing import Any

from proximo.core import apitree, engine
from proximo.core.errors import ProximoError

# HTTP semantics, not a vocabulary guess: what each verb asks the vendor to do.
_VERBS = {
    "GET": {"list", "get", "read", "show", "view", "fetch", "query", "describe", "info", "retrieve"},
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


def tokens(text: str) -> list[str]:
    return [stem(t) for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


@cache
def synonyms() -> dict[str, frozenset[str]]:
    """The record, refused by name when a line has no why or means nothing."""
    raw = tomllib.loads(resources.files("proximo.core").joinpath("vocab.toml").read_text())["synonym"]
    bad = {k: v for k, v in raw.items()
           if not (isinstance(v, dict) and isinstance(v.get("why"), str) and v["why"].strip()
                   and isinstance(v.get("means"), list) and v["means"]
                   and all(isinstance(m, str) and m for m in v["means"]))}
    if bad:
        raise ProximoError(f"vocab.toml carries lines without a why or a meaning: {sorted(bad)}")
    return {k: frozenset(v["means"]) for k, v in raw.items()}


@cache
def descriptions() -> dict[tuple[str, str, str], str]:
    """(plane, METHOD, path) -> the vendor's sentence, from the vendored api-viewer trees."""
    out = {}
    base = resources.files("proximo.core").joinpath("apidoc")
    for plane in apitree.PRODUCTS:
        for path, method, text in json.loads(base.joinpath(f"{plane}.desc.json").read_text()):
            out[(plane, method, path)] = text
    # The authored rows (shell.toml) carry their own sentence, so `find` reaches them by meaning.
    for r in engine._shell_rows(set()):
        out[(r["product"], r["method"], r["path"])] = r["description"]
    return out


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


def _terms(query: str) -> tuple[list[frozenset[str]], set[str], set[str]]:
    """The question's words (each with its synonyms), the verbs' methods, and any plane named."""
    q = re.sub(r"\([^)]*\)?", " ", query.lower())
    raw = [t for t in re.split(r"[^a-z0-9]+", q) if len(t) > 1]    # a lone letter is a possessive's tail
    syn = synonyms()
    stop = _stopwords()
    named = {t for t in raw if t in apitree.PRODUCTS}
    methods = {_VERB_OF[t] for t in raw if t in _VERB_OF}
    terms = [frozenset({stem(t)} | {stem(m) for m in syn.get(t, ())})
             for t in raw if t not in apitree.PRODUCTS and t not in _VERB_OF and t not in stop]
    return terms, methods, named


def find(query: str, plane: str | None = None, limit: int = 5, *, strict: bool = False,
         method: str | None = None) -> dict[str, Any]:
    """`method` filters to one HTTP method; it is never a word to look for. `strict`: every word
    must be a segment of the PATH ITSELF, for a caller that ACTS on a single match (proximo_plan
    given words) and so needs the address to say it, not a parameter name that happens to (lens
    2026-09-29: "POST create subscription keys" planned /auto-install/prepared, whose parameters
    spell post, subscription and key, because the literal "post" was a word to find)."""
    terms, methods, named = _terms(query)
    if not terms and not methods:
        raise ProximoError("give proximo_find one or more words to look for")
    need = len(terms) if strict else max(1, math.ceil(len(terms) / 3))
    scored = []
    for row, segs, said, params in _index():
        if (plane and row.product != plane) or (method and row.method != method):
            continue
        score = matched = 0
        for alts in terms:
            weight = (_SEGMENT if alts & segs else 0 if strict
                      else _DESCRIPTION if _said(alts, said) else _PARAM if alts & params else 0)
            score += weight
            matched += weight > 0
        if terms and (matched < need or not any(alts & (segs | said) for alts in terms)):
            continue
        if methods:
            score += 2 if row.method in methods else -2
        scored.append((score, row))
    if not scored:
        return {"matches": [], "note": f"no published address matched {query[:80]!r}; try other words "
                                       f"(a verb and a noun: 'list datastores') or a plane filter"}
    scored.sort(key=lambda s: (-s[0], bool(named) and s[1].product not in named,
                               not methods and s[1].access != engine.READ,
                               s[1].path.count("/"), len(s[1].path), s[1].product, s[1].method, s[1].path))
    top = scored[:limit]
    out: dict[str, Any] = {
        "matches": [{"plane": r.product, "method": r.method, "path": r.path, "access": r.access,
                     "tier": r.tier, "why": r.why, "params": sorted(r.params)} for _, r in top],
        "total": len(scored), "truncated": len(scored) > limit}
    # the bundle's honest answer: when the best score is shared by several planes and none was
    # named, say which, so the caller picks one instead of trusting an order the words cannot set
    best = {r.product for s, r in scored if s == scored[0][0]}
    if not plane and not named and len(best) > 1:
        out["planes"] = sorted(best)
        out["note"] = f"{', '.join(sorted(best))} each publish this; name the plane you mean"
    return out
