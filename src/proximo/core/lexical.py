"""The n-gram tier of proximo_find: a misspelt word is read as the word the table spells. No model.

`search.find` answers by words: a path segment, the vendor's sentence, a parameter name. A word the
table does not spell, and no vocabulary line covers, finds nothing, and a typo is exactly that
("snaphsot"). This offers the word's nearest neighbour among the words the table does spell as a
WEAKER alternative to it (it never replaces what the operator said), and `find` says it guessed.

  * CHARACTER 3/4-GRAMS, TF-IDF, COSINE (0.44's `lexical.py`, kept): each known word is a sparse
    vector over its padded 3- and 4-grams, a gram's weight is `(1 + log tf) * idf`, and the query
    word is scored against the words that share a gram. Pure stdlib, built once, in memory.
  * NO BUCKETS. 0.44 hashed grams into 4,096 buckets with blake2b because Python's builtin `hash`
    is salted per process. Here the gram string itself is the key of an inverted index, so there is
    nothing to salt and nothing to collide, and the index is never persisted.
  * A NEAR WORD IS NOT A TYPO. The n-gram score alone reads "weather" as "rather" (0.67) and
    "bread" as "read" (0.79), and an edit bound alone (even one edit) reads a third of English as
    typos: "router" as "route", "implicitly" as "explicitly". So a neighbour is taken only when
    it is a TYPO of the word, in the shapes typing makes: two neighbouring letters swapped, one
    letter dropped or doubled inside the word, or one letter struck for a key beside it on a
    QWERTY board; the first letter is right; and the word is six letters or more, with no digit
    in it (an identifier is not a typo). A nonsense query has no such neighbour.
  * A WORD THE TABLE SPELLS IS NEVER CORRECTED, and `PROXIMO_LEXICAL=off` turns the tier off.

Measured 2026-10-25 against the shipped table (about 1,800 words) and `/usr/share/dict/words`, its
55,963 lowercase ASCII words of six letters or more, each asked alone: 345 (0.62%) are offered as a
typo of a different table word (the first version's bare edit bound did this to 2,678, 4.8%), and a
further 889 (1.6%) are folded as an inflection of a table word (`attached` is `attach`; most of
these are the same word). 3,000 random strings of 6 to 10 letters are read as nothing. Of 727
random single-edit typos of the table's own words (seed 7) 580 (80%) are read as the right word:
every doubled letter, 98% of the dropped ones, 90% of the swaps, and 28% of the random
substitutions (a random substitution is mostly not a slip beside a key; that is the recall paid).
A guess is only an alternative to what was said, and `find` labels it.
"""
from __future__ import annotations

import math
import os
from collections import Counter, defaultdict
from collections.abc import Iterable

#: below this cosine a neighbour is gram noise (a shared word-start is not a typo)
MIN_SIMILARITY = 0.30
#: a word shorter than this is as often a real word we do not spell as a typo of one
MIN_LENGTH = 6
_OFF = ("0", "false", "no", "off")
_KEYS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
_AT = {ch: (r, i) for r, row in enumerate(_KEYS) for i, ch in enumerate(row)}


def enabled() -> bool:
    """On unless `PROXIMO_LEXICAL` says off (0, false, no, off). It only ever fills what the word
    tier could not hear, so it is on by default: a search that needs a switch to work is not one."""
    return os.environ.get("PROXIMO_LEXICAL", "").strip().lower() not in _OFF


def _beside(a: str, b: str) -> bool:
    if a not in _AT or b not in _AT:
        return False
    (r1, c1), (r2, c2) = _AT[a], _AT[b]
    return abs(r1 - r2) <= 1 and abs(c1 - c2) <= 1


def is_typo(said: str, word: str) -> bool:
    """`said` is `word` with one slip of the fingers: a swap of neighbours, a letter dropped or
    doubled inside the word (not at an end: `route` is a word, not a `router` with a slip), or a
    letter struck for the key beside it. The first letter must be right."""
    if said == word or not said or said[0] != word[0]:
        return False
    if len(said) == len(word):
        diff = [i for i in range(len(said)) if said[i] != word[i]]
        if len(diff) == 1:
            return _beside(said[diff[0]], word[diff[0]])
        return (len(diff) == 2 and diff[1] == diff[0] + 1
                and said[diff[0]] == word[diff[1]] and said[diff[1]] == word[diff[0]])
    short, long_ = (said, word) if len(said) < len(word) else (word, said)
    if len(long_) != len(short) + 1:
        return False
    return any(long_[:i] + long_[i + 1:] == short for i in range(1, len(long_) - 1))


def bases(word: str) -> list[str]:
    """What `word` may be an inflection of (-ing, -ed, -ied, -tion/-ation, a fused `rolledback`),
    most likely first. Candidates only: the caller keeps the ones the table spells."""
    out: list[str] = []

    def add(x: str) -> None:
        if len(x) >= 3 and x != word and x not in out:
            out.append(x)

    for suffix in ("ing", "ed"):
        if word.endswith(suffix) and len(word) > len(suffix) + 2:
            b = word[:-len(suffix)]
            add(b)
            add(b + "e")
            if b[-1] == b[-2]:
                add(b[:-1])
    if word.endswith("ied"):
        add(word[:-3] + "y")
    if word.endswith("ation"):
        add(word[:-5] + "e")
        add(word[:-3] + "e")
    elif word.endswith("tion"):
        add(word[:-3] + "e")
    for infix in ("ed", "ing"):
        if infix in word[2:-1]:
            add(word.replace(infix, "", 1))
    return out


def _grams(word: str) -> Counter[str]:
    padded = f" {word} "
    return Counter(padded[i:i + n] for n in (3, 4) for i in range(len(padded) - n + 1))


class WordIndex:
    """TF-IDF over the character 3/4-grams of a fixed set of words. Deterministic for a given set."""

    def __init__(self, words: Iterable[str]):
        self.words = sorted(set(words))
        self._known = frozenset(self.words)
        counts = [_grams(w) for w in self.words]
        df: Counter[str] = Counter()
        for c in counts:
            df.update(c.keys())
        n = max(len(self.words), 1)
        self._idf = {g: math.log(n / (1 + f)) + 1 for g, f in df.items()}
        self._post: dict[str, list[tuple[int, float]]] = defaultdict(list)
        for i, c in enumerate(counts):
            vec = self._weigh(c)
            norm = math.sqrt(sum(x * x for x in vec.values()))
            for g, x in vec.items():
                self._post[g].append((i, x / norm))

    def _weigh(self, counts: Counter[str]) -> dict[str, float]:
        return {g: (1 + math.log(k)) * self._idf.get(g, 1.0) for g, k in counts.items()}

    def knows(self, word: str) -> bool:
        return word in self._known

    def neighbours(self, word: str, top: int = 3) -> list[tuple[float, str]]:
        """The `top` known words nearest `word` by cosine, best first (ties by spelling)."""
        vec = self._weigh(_grams(word))
        norm = math.sqrt(sum(x * x for x in vec.values()))
        if not norm:
            return []
        score: dict[int, float] = defaultdict(float)
        for g, x in vec.items():
            for i, w in self._post.get(g, ()):
                score[i] += x / norm * w
        best = sorted(((s, self.words[i]) for i, s in score.items()), key=lambda p: (-p[0], p[1]))
        return best[:top]

    def repair(self, word: str) -> str | None:
        """The known word `word` is a typo of, or None: not for a known word, a short one or one
        with a digit, and only a neighbour above the floor that `is_typo` accepts."""
        if len(word) < MIN_LENGTH or self.knows(word) or any(c.isdigit() for c in word):
            return None
        for s, cand in self.neighbours(word):
            if s >= MIN_SIMILARITY and is_typo(word, cand):
                return cand
        return None
