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
from datetime import UTC, datetime

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


def classify_task_outcome(row) -> str:  # noqa: ANN001 — row shape is heterogeneous by design
    """Deterministic outcome class for a PVE task row — string matching on what the API
    returned, never inference. A still-running task carries no ``endtime``; a finished row's
    ``status`` is raw exitstatus TEXT ("OK", "WARNINGS: n", or the full error message —
    live-proven e.g. "command 'apt-get update' failed: exit code 100"), so bucketing by that
    string would hand a model N distinct error keys exactly when tasks fail. Classes:
    running / ok / warnings / failed / unknown (statusless-finished or garbage — disclosed,
    not guessed; a row we cannot read must NEVER fail open into a healthy-looking class)."""
    if not isinstance(row, dict):
        return "unknown"
    if "endtime" not in row:
        return "running"
    status = row.get("status")
    if status is None or str(status) == "":
        return "unknown"
    s = str(status)
    if s == "OK":
        return "ok"
    if s.startswith("WARNINGS: "):
        return "warnings"
    return "failed"


def envelope_windowed(rows: list, projected_rows: list, key: str, classify) -> dict:  # noqa: ANN001
    """Counted envelope for a listing the BACKEND truncates before this server ever sees a row:
    {"returned", "by_outcome", <key>}. Deliberately NO "total" — the population count never
    reached us, and a number that only describes the fetched window must not wear the
    population's name (the 08-12 lens caught exactly that claim in prose). Outcomes are
    classified from the RAW rows via the deterministic ``classify``, so a custom projection
    cannot skew them."""
    counts = Counter(classify(r) for r in rows)
    return {"returned": len(rows), "by_outcome": dict(counts), key: projected_rows}


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


def cap_newest(rows: list, limit: int | None, ts_key: str) -> list:
    """Opt-in newest-first cap for hazard-class listings (backups, snapshots, volumes).

    These surfaces are absence-check ground truth — "never conclude a backup failed from
    absence" — so ``limit=None`` returns the rows UNTOUCHED (order included), and a capped
    slice is only ever something the caller explicitly asked for. A positive limit returns
    the newest N by ``ts_key`` (rows missing the key sort oldest); zero/negative is refused
    outright, never coerced to "all".
    """
    n = _checked_limit(limit)
    if n is None:
        return rows
    return sorted(rows, key=lambda r: _metric(r, ts_key), reverse=True)[:n]


def cap_top(rows: list, limit: int | None, count_key: str) -> list:
    """Top-N by a numeric metric column, descending (per-correspondent statistics).

    These rows carry no timestamp, so "newest" is meaningless here — the honest slice is
    the largest by ``count_key``. ``limit=None`` returns the rows UNTOUCHED (order
    included); rows missing the metric sort as zero; zero/negative is refused outright,
    never coerced to "all".
    """
    n = _checked_limit(limit)
    if n is None:
        return rows
    return sorted(rows, key=lambda r: _metric(r, count_key), reverse=True)[:n]


def envelope_capped(rows: list, capped_rows: list, key: str) -> dict:
    """Counted envelope for capped estate-scale listings: {"total", "returned", <key>}.

    The by-less sibling of envelope_rows, for rows with no categorical axis. ``total``
    always counts the RAW rows, so a capped slice can never masquerade as the population.
    """
    return {"total": len(rows), "returned": len(capped_rows), key: capped_rows}


def _checked_limit(limit: int | None) -> int | None:
    if limit is None:
        return None
    n = int(limit)
    if n <= 0:
        raise ProximoError(f"limit must be a positive integer, got {limit!r}")
    return n


def _metric(r, key: str) -> float:  # noqa: ANN001 — row shape is heterogeneous by design
    v = r.get(key) if isinstance(r, dict) else None
    if v is None:
        return 0.0       # missing sorts oldest / last
    try:
        return float(v)  # a backend handing epoch-as-string still sorts by its value
    except (TypeError, ValueError):
        pass
    # PMG's view of PBS snapshots types backup-time as an RFC 3339 STRING (its own
    # documented divergence from the epoch-int convention) — order by the instant,
    # never let a typed string collapse "newest N" into "first N in API order".
    try:
        dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)  # naive pins to UTC — never box-TZ order
        return dt.timestamp()
    except ValueError:
        return 0.0       # non-temporal sorts oldest, never crashes the listing
