"""The one place a ranked tier turns scores into `search_tools` rows.

Both search rungs — neural (`vectors.semantic_fill`) and in-wheel lexical
(`lexical.lexical_fill`) — answer the same question for `lean.search_tools`: given
ranked (name, score) pairs, hand back at most `room` rows for names not already
`taken`, marked with the tier that found them. That loop was written twice, identically,
including its skip guard and its early break. Once is enough.
"""
from __future__ import annotations

from collections.abc import Iterable


def rows_from_hits(hits: Iterable[tuple[str, float]], candidates: dict[str, str],
                   taken: set[str], room: int, match: str) -> list[dict]:
    """Up to `room` result rows from ranked hits, skipping `taken`.

    Names absent from `candidates` are dropped. For the neural tier that is the second of
    two overlapping guarantees — its store sync already deletes off-catalog rows, so
    nothing off-catalog can reach here while every caller syncs first; this keeps the
    promise true for a caller that does not. Both tiers pin it by test (an adversarial
    lens found the branch had none, 2026-08-01).
    """
    out: list[dict] = []
    for name, score in hits:
        if name in taken or name not in candidates:
            continue
        out.append({"name": name, "summary": candidates[name],
                    "match": match, "score": score})
        if len(out) == room:
            break
    return out
