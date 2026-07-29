"""Field projection — lean list responses.

Schema bloat wastes context; response bloat corrupts answers. A list tool's raw PVE payload
carries dozens of counters (PSI pressure metrics, byte counters, pids) per row; a model
reasoning over that answers *worse*, not just slower. List tools therefore return a curated
lean field set by default and take a `fields` parameter as the escape hatch:

- ``fields=None``   -> the tool's lean set (keys kept only where a row actually has them)
- ``fields="all"``  -> the raw payload, untouched
- ``fields="a,b"``  -> exactly those keys, in the requested order, kept where present

Rows are shape-heterogeneous (a stopped guest has no ``pid``; qemu rows add ``memhost``), so
projection keeps a listed key only where the row carries it. A requested field that appears in
NO row fails closed with the available field names — same posture as the scoping layers: a
typo gets an error that teaches, never a silently empty answer.
"""

from __future__ import annotations

from collections import Counter

from proximo.backends import ProximoError


def envelope_rows(raw_rows: list, projected_rows: list, key: str, by: str) -> dict:
    """Wrap projected rows in a counted envelope: {"total", "by_<axis>", <key>}.

    Counting is the server's job, not the model's — live-proven 2026-07-28: a 12B local
    model given the lean 28-guest listing counted 24; given this envelope it answered
    28/18/10 three runs out of three. Counts always come from the RAW rows, so a custom
    projection that drops the axis column cannot skew them.
    """
    counts = Counter(
        (r.get(by, "unknown") if isinstance(r, dict) else "unknown") for r in raw_rows)
    return {"total": len(raw_rows), f"by_{by}": dict(counts), key: projected_rows}


def project_rows(rows: list, fields: str | None, lean: tuple[str, ...]) -> list:
    """Project a list-tool response down to the lean set, a custom field list, or not at all."""
    if fields is None:
        wanted = lean
    else:
        spec = fields.strip()
        if spec.lower() == "all":
            return rows
        wanted = tuple(f.strip() for f in spec.split(",") if f.strip())
        if not wanted:
            raise ProximoError(
                "fields must be 'all' or a comma-separated list of field names")
        if rows:
            available = {k for r in rows if isinstance(r, dict) for k in r}
            unknown = [f for f in wanted if f not in available]
            if unknown:
                raise ProximoError(
                    f"unknown field(s) {', '.join(unknown)} — "
                    f"available: {', '.join(sorted(available))}")
    return [
        {k: r[k] for k in wanted if k in r} if isinstance(r, dict) else r
        for r in rows
    ]
