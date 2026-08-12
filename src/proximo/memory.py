"""Tier-1 estate memory — increment 1: the estate map + "what changed" diff.

Design: docs/plans/internal/2026-07-29-tiered-memory-design.md. The thesis is the counted
envelope's, one tier up: everything the server can know, the model shouldn't have to
re-derive. A derived, rebuildable SQLite beside the PROVE ledger remembers WHAT EXISTS
(guests/nodes/storage identity, first/last-seen, last status) so "what changed since
yesterday" is a query, not a re-derivation — and a small model can get estate answers
without any raw payload in context.

The rails (each one is load-bearing, argued in the design doc):

- **Default-on, opt-out.** Since the 0.30 flip: ``PROXIMO_MEMORY`` unset => enabled — the
  estate map is part of the default install, kept beside the ledger the install already
  keeps. ``PROXIMO_MEMORY=0`` (or false/no/off) => fully inert: no file is ever created,
  observe is a no-op, recall refuses with the re-enable hint.
- **Opportunistic writes only.** Memory is fed by reads that already happened
  (``pve_list_guests``, ``pve_cluster_resources``); it NEVER initiates I/O against PVE.
- **A memory failure never fails the read.** The observe path warns (once per process per
  reason) and returns; breaking a live read to preserve a convenience cache would invert
  the value order.
- **Age-stamped, source-named recall.** Every recall carries ``source: "memory"``,
  ``as_of`` and ``age_seconds`` — cached state never masquerades as a live read.
- **Honest diff vocabulary.** ``not_seen_since`` (a fact: last observed before the window)
  — never "vanished" (an inference: a node-scoped read simply doesn't see other nodes).
- **Derived and rebuildable.** Deleting the db loses convenience, never truth. The PROVE
  ledger never depends on memory.
- **Not a boundary.** The db sits inside the agent's write reach — a convenience layer
  within the trust domain (SECURITY.md's two-deployment honesty seam applies).
- **Taint carries through storage.** Names/tags stored here originate from
  ADVERSARIAL_TOOLS-classified reads; ``proximo_recall`` is itself classified adversarial
  in taint.py so recalled bytes re-enter the taint model instead of laundering through it.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import time
import warnings
from datetime import UTC, datetime

from proximo.backends import ProximoError

_FALSY = ("0", "false", "no", "off")
_DEFAULT_AUDIT_LOG = os.path.expanduser("~/.local/state/proximo/audit.log")

# once-per-process-per-reason warning memo, so a broken path warns loudly but not per-call
_warned: set[str] = set()

def _own_the_file(path: str) -> None:
    """Make the map owner-only BEFORE sqlite ever opens it, and tighten one that is already loose.

    The map is derived, but it is derived ESTATE INVENTORY: guest names, node names, target names,
    status history and a journal of operations, all plaintext. It defaults to living beside the
    audit log, which audit.py deliberately creates at 0600 ("entries carry command/SQL detail, so
    the umask default is too open"). This file had no such step, so a default box left it 0644.

    Created here rather than chmod-ed afterwards so there is no window in which the inventory sits
    world-readable, and O_NOFOLLOW so a planted symlink cannot aim the create somewhere else. The
    tighten branch repairs installs made by the looser code; it is our own derived file, so
    narrowing its mode can lose nothing. Best-effort throughout: memory is a convenience layer and
    must never be the reason the server cannot start.
    """
    # A symlink at this path is REFUSED outright, before any branch below — the one
    # condition here that is an attack rather than an inconvenience, so it is the one
    # thing this function does not treat as best-effort. O_NOFOLLOW alone did NOT cover
    # it: a DANGLING symlink fails os.path.exists(), takes the create branch, fails with
    # ELOOP, and the swallow returned as if nothing were wrong — then the caller's own
    # sqlite3.connect() followed the link with an ordinary open and created the estate
    # inventory at the attacker's target, at umask default (0644 measured), somewhere the
    # operator never configured. A symlink to an EXISTING file was worse in a second way:
    # the tighten branch chmod'ed the LINK TARGET, silently narrowing an unrelated file.
    # Found by an adversarial lens, 2026-08-01.
    if os.path.islink(path):
        raise ProximoError(
            f"{path} is a symlink — refusing to open estate state through it. Point "
            "PROXIMO_MEMORY_PATH / PROXIMO_VECTORS_PATH at a real file: a link here can "
            "aim the create at another location or narrow an unrelated file's permissions.")
    try:
        if os.path.exists(path):
            mode = stat.S_IMODE(os.stat(path).st_mode)
            if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
                os.chmod(path, mode & ~(stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH))
            return
        os.close(os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600))
    except OSError:
        return


_SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    target            TEXT NOT NULL,
    kind              TEXT NOT NULL,
    key               TEXT NOT NULL,
    name              TEXT,
    node              TEXT,
    status            TEXT,
    prev_status       TEXT,
    first_seen        REAL NOT NULL,
    last_seen         REAL NOT NULL,
    status_changed_at REAL,
    PRIMARY KEY (target, kind, key)
);
CREATE TABLE IF NOT EXISTS baselines (
    target       TEXT NOT NULL,
    kind         TEXT NOT NULL,
    key          TEXT NOT NULL,
    timeframe    TEXT NOT NULL,
    metric       TEXT NOT NULL,
    n            INTEGER NOT NULL,
    mean         REAL NOT NULL,
    p50          REAL NOT NULL,
    p95          REAL NOT NULL,
    vmax         REAL NOT NULL,
    window_start REAL,
    window_end   REAL,
    updated_at   REAL NOT NULL,
    PRIMARY KEY (target, kind, key, timeframe, metric)
);
CREATE TABLE IF NOT EXISTS journal (
    target  TEXT NOT NULL,
    ts      REAL NOT NULL,
    tool    TEXT NOT NULL,
    subject TEXT NOT NULL,
    ok      INTEGER NOT NULL,
    summary TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS journal_target_ts ON journal (target, ts DESC);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', '3');
"""


def journal_digest(report: dict) -> tuple[bool, str]:
    """Compact digest of a diagnose/doctor report for the journal: findings only, NEVER raw
    output (probe stdout / task logs are adversarial-classified content and stay out of the
    db). Findings = the report's own advisory flags plus any section that errored — a
    diagnose that half-ran is not "clean". A flag flood truncates: the journal answers "when
    did this last happen", not "what exactly was in the logs"."""
    findings = [str(f) for f in (report.get("flags") or [])]
    for k, v in report.items():
        if isinstance(v, dict) and "error" in v:
            findings.append(f"{k} errored: {v['error']}")
    if not findings:
        return True, "clean"
    shown = findings[:5]
    if len(findings) > 5:
        shown.append(f"+{len(findings) - 5} more")
    return False, "; ".join(shown)

BASELINE_METRICS = ("cpu", "mem")


def rollup_samples(samples: list, metrics: tuple[str, ...] = BASELINE_METRICS) -> dict:
    """Distribution rollup per metric over rrddata samples: n / mean / p50 / p95 / max.

    None/missing values are SKIPPED, never counted as zero — a stopped span must not drag
    a running guest's baseline down. Percentiles are nearest-rank. Refuses when no metric
    has a single usable sample (an all-stopped window has no baseline to offer).
    """
    out: dict = {}
    for m in metrics:
        vals = sorted(s[m] for s in samples
                      if isinstance(s, dict) and s.get(m) is not None)
        if not vals:
            continue
        def rank(p: float, v: list = vals) -> float:
            import math
            return v[max(0, math.ceil(p * len(v)) - 1)]
        out[m] = {"n": len(vals), "mean": sum(vals) / len(vals),
                  "p50": rank(0.50), "p95": rank(0.95), "max": vals[-1]}
    if not out:
        raise ProximoError(
            "no usable samples in the rrddata window — no baseline to compute "
            "(guest stopped for the whole window, or metrics absent)")
    return out


def memory_enabled() -> bool:
    """Default-on since the 0.30 flip; only an explicit falsy value opts out."""
    return os.environ.get("PROXIMO_MEMORY", "").strip().lower() not in _FALSY


def memory_path() -> str:
    """PROXIMO_MEMORY_PATH, else memory.db beside the audit log the env names."""
    explicit = os.environ.get("PROXIMO_MEMORY_PATH")
    if explicit:
        return explicit
    audit = os.environ.get("PROXIMO_AUDIT_LOG", _DEFAULT_AUDIT_LOG)
    return os.path.join(os.path.dirname(audit) or ".", "memory.db")


def _guest_entities(rows: list) -> list[dict]:
    out = []
    for r in rows:
        if not isinstance(r, dict) or "vmid" not in r:
            continue
        out.append({"kind": str(r.get("type") or "guest"), "key": str(r["vmid"]),
                    "name": r.get("name"), "node": r.get("node"),
                    "status": r.get("status")})
    return out


def _resource_entities(rows: list) -> list[dict]:
    out = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        rtype = r.get("type")
        if rtype in ("lxc", "qemu") or "vmid" in r:
            out.append({"kind": str(rtype or "guest"), "key": str(r.get("vmid")),
                        "name": r.get("name"), "node": r.get("node"),
                        "status": r.get("status")})
        elif rtype == "node":
            out.append({"kind": "node", "key": str(r.get("node") or r.get("id")),
                        "name": r.get("node"), "node": r.get("node"),
                        "status": r.get("status")})
        elif rtype == "storage":
            out.append({"kind": "storage", "key": str(r.get("id")),
                        "name": r.get("storage"), "node": r.get("node"),
                        "status": r.get("status")})
        elif rtype:  # sdn and future resource types: keep identity, stay honest about kind
            out.append({"kind": str(rtype), "key": str(r.get("id")),
                        "name": r.get("name"), "node": r.get("node"),
                        "status": r.get("status")})
    return out


class EstateMemory:
    """The Tier-1 map. Pure local SQLite; no network; every method total under WAL."""

    def __init__(self, path: str):
        self.path = path
        if os.path.isdir(path):
            # Same guard, same wording as wiki.py's WikiIndex — a directory here (the exact
            # typo a copy-paste of SETUP.md's example path risks) used to reach sqlite3.connect()
            # unguarded and leak a raw OperationalError instead of a named remedy.
            raise ProximoError(
                f"{path} is a directory, not a file — point PROXIMO_MEMORY_PATH at the .db "
                f"file itself")
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        _own_the_file(path)
        self._db = sqlite3.connect(path)
        self._db.executescript(_SCHEMA)
        self._db.commit()

    def close(self) -> None:
        self._db.close()

    def observe(self, target: str, entities: list[dict], now: float | None = None) -> None:
        now = time.time() if now is None else now
        for e in entities:
            row = self._db.execute(
                "SELECT status FROM entities WHERE target=? AND kind=? AND key=?",
                (target, e["kind"], e["key"])).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO entities (target, kind, key, name, node, status,"
                    " first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?)",
                    (target, e["kind"], e["key"], e.get("name"), e.get("node"),
                     e.get("status"), now, now))
            elif row[0] != e.get("status"):
                self._db.execute(
                    "UPDATE entities SET name=?, node=?, prev_status=status, status=?,"
                    " status_changed_at=?, last_seen=? WHERE target=? AND kind=? AND key=?",
                    (e.get("name"), e.get("node"), e.get("status"), now, now,
                     target, e["kind"], e["key"]))
            else:
                self._db.execute(
                    "UPDATE entities SET name=?, node=?, last_seen=?"
                    " WHERE target=? AND kind=? AND key=?",
                    (e.get("name"), e.get("node"), now, target, e["kind"], e["key"]))
        self._db.commit()

    def store_baseline(self, target: str, kind: str, key: str, timeframe: str,
                       rollups: dict, window: tuple[float, float] | None = None,
                       now: float | None = None) -> None:
        now = time.time() if now is None else now
        w0, w1 = window if window else (None, None)
        for metric, r in rollups.items():
            self._db.execute(
                "INSERT OR REPLACE INTO baselines (target, kind, key, timeframe, metric,"
                " n, mean, p50, p95, vmax, window_start, window_end, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (target, kind, key, timeframe, metric, r["n"], r["mean"], r["p50"],
                 r["p95"], r["max"], w0, w1, now))
        self._db.commit()

    def get_baseline(self, target: str, kind: str, key: str, timeframe: str) -> dict | None:
        rows = self._db.execute(
            "SELECT metric, n, mean, p50, p95, vmax, window_start, window_end, updated_at"
            " FROM baselines WHERE target=? AND kind=? AND key=? AND timeframe=?",
            (target, kind, key, timeframe)).fetchall()
        if not rows:
            return None
        metrics = {m: {"n": n, "mean": mean, "p50": p50, "p95": p95, "max": vmax}
                   for m, n, mean, p50, p95, vmax, _, _, _ in rows}
        _, _, _, _, _, _, w0, w1, updated = rows[0]
        return {"metrics": metrics, "updated_at": updated,
                "window": None if w0 is None else [w0, w1]}

    def add_journal(self, target: str, tool: str, subject: str, ok: bool,
                    summary: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._db.execute(
            "INSERT INTO journal (target, ts, tool, subject, ok, summary) VALUES (?,?,?,?,?,?)",
            (target, now, tool, subject, int(ok), summary))
        self._db.commit()

    def get_journal(self, target: str, limit: int, since_ts: float | None = None,
                    now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        q = "SELECT ts, tool, subject, ok, summary FROM journal WHERE target=?"
        args: list = [target]
        if since_ts is not None:
            q += " AND ts > ?"
            args.append(since_ts)
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(int(limit))
        return [{"ts": ts, "age_seconds": round(now - ts, 3), "tool": tool,
                 "subject": subject, "ok": bool(ok), "summary": summary}
                for ts, tool, subject, ok, summary in self._db.execute(q, args)]

    def observe_guests(self, target: str, rows: list, now: float | None = None) -> None:
        self.observe(target, _guest_entities(rows), now=now)

    def observe_resources(self, target: str, rows: list, now: float | None = None) -> None:
        self.observe(target, _resource_entities(rows), now=now)

    def recall(self, target: str, now: float | None = None,
               since_ts: float | None = None, detail: str = "lean") -> dict:
        if detail not in ("summary", "lean", "full"):
            raise ProximoError(
                f"unknown detail: {detail!r} — use summary, lean (default), or full")
        now = time.time() if now is None else now
        cols = ("kind", "key", "name", "node", "status", "prev_status",
                "first_seen", "last_seen", "status_changed_at")
        rows = [dict(zip(cols, r, strict=True)) for r in self._db.execute(
            "SELECT kind, key, name, node, status, prev_status,"
            " first_seen, last_seen, status_changed_at"
            " FROM entities WHERE target=? ORDER BY kind, key", (target,))]
        if not rows:
            # NO COUNTS HERE, deliberately — not total, not by_kind, not even an empty
            # entities list. "Nothing has been observed yet" and "the estate is empty" are
            # different facts and only the first one is knowable from here; every countable
            # field in this branch would answer the second. A small model reads the number and
            # not the prose beside it (live-caught: a 12B read total:36 and answered a question
            # about 28 guests), so the note cannot protect a `total: 0`. as_of/age_seconds stay
            # explicitly null — the baseline rule: report no reading, never fabricate one.
            return {"source": "memory", "as_of": None, "age_seconds": None,
                    "note": "memory is empty — no reads have been observed yet. This is NOT a "
                            "statement that the estate is empty; nothing has been counted. For "
                            "live state call pve_list_guests."}

        # Default rows are LEAN (identity + status) and extra columns are opt-in — live-caught
        # 2026-07-29: a 12B drowned in 9-field rows with float timestamps and miscounted even
        # WITH correct summary counts present. Depth must never crowd out the answer.
        def render(r: dict, extra: tuple[str, ...] = ()) -> dict:
            if detail == "full":
                return r
            keep = ("kind", "key", "name", "node", "status") + extra
            return {k: r[k] for k in keep if r.get(k) is not None}

        as_of = max(r["last_seen"] for r in rows)
        # "how many guests" is the dominant question class and `total` counts ENTITIES —
        # live-caught 2026-07-29: a 12B answered the headline total (36) when asked for
        # guests (28). Count guests server-side; never make the model add by_kind entries.
        guests = [r for r in rows if r["kind"] in ("lxc", "qemu")]
        out: dict = {
            "source": "memory",
            "as_of": as_of,
            "age_seconds": round(now - as_of, 3),
            "total": len(rows),
            "by_kind": _count(rows, "kind"),
            "by_status": _count(rows, "status"),
            "guest_summary": {"total": len(guests), "by_status": _count(guests, "status")},
        }
        if detail != "summary":
            out["entities"] = [render(r) for r in rows]
        if since_ts is not None:
            out["since"] = since_ts
            out["appeared"] = [render(r) for r in rows if r["first_seen"] > since_ts]
            out["status_changed"] = [render(r, ("prev_status", "status_changed_at"))
                                     for r in rows
                                     if (r["status_changed_at"] or 0) > since_ts]
            out["not_seen_since"] = [render(r, ("last_seen",))
                                     for r in rows if r["last_seen"] < since_ts]
        return out


def _count(rows: list[dict], field: str) -> dict:
    counts: dict = {}
    for r in rows:
        k = r.get(field) or "unknown"
        counts[k] = counts.get(k, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Module seams the tools call — env-gated, target-aware, failure-isolated
# ---------------------------------------------------------------------------

def _active_target_name() -> str:
    from proximo.targets import active_target
    return active_target() or "default"


def _recall_unfed_remedy() -> str:
    """The proximo_recall "nothing observed yet" remedy clause, branched on the deployment shape.

    The estate map is fed ONLY by PVE-plane reads — observe_guests/observe_resources are wired
    from pve_guest.py/pve_cluster.py alone, nowhere in the pbs/pmg/pdm tool modules — so on a box
    with no PVE plane configured, pointing at pve_list_guests/pve_cluster_resources names two
    tools that are not even registered there (verdict 1.2, hostile-adopter arena 2026-07-29,
    pbs-only-walk.md #2). The honest branch says plainly that PVE feeds this map and this
    deployment has none, rather than inventing a pbs_*/pmg_*/pdm_* pointer that would not
    actually feed the map either.

    Lazy import: proximo.server imports proximo.tools.memory_tools (which imports this module)
    by name near the bottom of its own file, so a module-level import here would be a real cycle.
    """
    from proximo.door import configured_surfaces
    if "pve" in configured_surfaces():
        return ("Memory fills opportunistically from reads; call pve_list_guests or "
                "pve_cluster_resources for live state (which also feeds the map). "
                "`proximo doctor` reports what memory currently holds.")
    return ("The map is fed only by PVE-plane reads (pve_list_guests / pve_cluster_resources); "
            "this deployment has no PVE plane configured, so there is nothing that can feed it "
            "yet. `proximo doctor` reports what memory currently holds.")


def _observe(method: str, rows: list) -> None:
    if not memory_enabled():
        return
    try:
        mem = EstateMemory(memory_path())
        try:
            getattr(mem, method)(_active_target_name(), rows)
        finally:
            mem.close()
    except Exception as e:  # NEVER fail the read that fed us — warn loudly, once per path+reason
        reason = f"{memory_path()}: {type(e).__name__}: {e}"
        if reason not in _warned:
            _warned.add(reason)
            warnings.warn(
                f"proximo memory: observe failed ({reason}) — the read succeeded; "
                f"the estate map at {memory_path()} did not update", stacklevel=2)


def observe_guests(rows: list) -> None:
    _observe("observe_guests", rows)


def observe_resources(rows: list) -> None:
    _observe("observe_resources", rows)


def memory_status() -> dict:
    """The doctor's memory section: enabled? where? how big? how fresh? NEVER raises —
    doctor must never die on a memory problem; a broken db becomes a reported error
    (and a doctor flag), not an exception."""
    if not memory_enabled():
        return {"enabled": False,
                "hint": "estate memory is opted out (PROXIMO_MEMORY=0) — unset it or set "
                        "PROXIMO_MEMORY=1 to re-enable the Tier-1 estate map "
                        "(local, derived, rebuildable — nothing leaves the box)"}
    path = memory_path()
    out: dict = {"enabled": True, "path": path}
    try:
        out["db_bytes"] = os.path.getsize(path) if os.path.exists(path) else 0
        mem = EstateMemory(path)
        try:
            target = _active_target_name()
            n, oldest, newest = mem._db.execute(
                "SELECT COUNT(*), MIN(first_seen), MAX(last_seen) FROM entities"
                " WHERE target=?", (target,)).fetchone()
            out["target"] = target
            out["entities"] = n
            out["baselines"] = mem._db.execute(
                "SELECT COUNT(*) FROM baselines WHERE target=?", (target,)).fetchone()[0]
            out["journal_entries"] = mem._db.execute(
                "SELECT COUNT(*) FROM journal WHERE target=?", (target,)).fetchone()[0]
            if newest is not None:
                now = time.time()
                out["newest_observation_age_seconds"] = round(now - newest, 1)
                out["oldest_observation_age_seconds"] = round(now - oldest, 1)
            else:
                out["note"] = "memory is empty — it fills as reads happen"
        finally:
            mem.close()
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out


def journal_record(tool: str, subject: str, report: dict) -> None:
    """Opportunistic journal feed from a diagnose/doctor wrapper. Env-gated, failure-isolated:
    a journal failure never fails the diagnosis that fed it."""
    if not memory_enabled():
        return
    try:
        ok, summary = journal_digest(report if isinstance(report, dict) else {})
        mem = EstateMemory(memory_path())
        try:
            mem.add_journal(_active_target_name(), tool, subject, ok, summary)
        finally:
            mem.close()
    except Exception as e:
        reason = f"{memory_path()}: {type(e).__name__}: {e}"
        if reason not in _warned:
            _warned.add(reason)
            warnings.warn(
                f"proximo memory: journal write failed ({reason}) — the diagnosis succeeded; "
                f"the journal did not update", stacklevel=2)


def _parse_since(since: str) -> float:
    spec = since.strip().lower()
    if spec and spec[-1] in "smhd" and spec[:-1].isdigit():
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[spec[-1]]
        return time.time() - int(spec[:-1]) * mult
    try:
        dt = datetime.fromisoformat(since)
    except ValueError:
        raise ProximoError(
            f"unparseable since: {since!r} — use ISO8601 (2026-07-29T00:00:00) "
            f"or a relative window like 24h / 7d / 30m") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.timestamp()


def _fmt(v: float) -> str:
    """Sane precision for model-facing prose: 16-digit floats drown the comparison."""
    return f"{v:.4g}"


def _assess(current: dict, rollups: dict) -> dict:
    """Position current values against the stored distribution. Advisory wording only —
    this is a heuristic read on history, never an alarm or a health verdict."""
    out: dict = {"note": "advisory heuristic from stored history, not an alarm"}
    for m, v in current.items():
        b = rollups.get(m)
        if b is None:
            continue
        if v >= b["max"]:
            out[m] = f"current {_fmt(v)} at/above the observed max {_fmt(b['max'])}"
        elif v > b["p95"]:
            out[m] = f"current {_fmt(v)} above p95 {_fmt(b['p95'])}"
        else:
            out[m] = (f"current {_fmt(v)} within baseline "
                      f"(p50 {_fmt(b['p50'])}, p95 {_fmt(b['p95'])})")
    return out


def baseline_state(api, vmid: str, kind: str = "lxc", node: str | None = None,
                   timeframe: str = "week", refresh: bool = False) -> dict:
    """The proximo_baseline body: stored-first, rrddata pull only when missing or refreshed.

    This is the ONE deliberate exception to "memory never initiates PVE I/O": pulling
    rrddata is this tool's declared job (design doc, Tier-1 baselines). The stored path
    makes no network call at all and says so (`current: None`, never a fabricated reading).

    `api` may be a zero-arg callable resolving to the api backend; it is resolved only on
    the pull path, so the stored path needs no PVE configuration at all — the docstring's
    "NO PVE call" includes not demanding PVE env for an answer served from memory.
    """
    if not memory_enabled():
        raise ProximoError(
            "estate memory is opted out (PROXIMO_MEMORY=0) — unset it or set PROXIMO_MEMORY=1 "
            "to re-enable baselines "
            "(a derived, rebuildable SQLite beside the audit log; nothing leaves the box)")
    from proximo.observability import guest_rrddata

    target = _active_target_name()
    mem = EstateMemory(memory_path())
    try:
        stored = mem.get_baseline(target, kind, str(vmid), timeframe)
        if stored is not None and not refresh:
            now = time.time()
            return {"source": "memory", "vmid": str(vmid), "kind": kind,
                    "timeframe": timeframe, "baseline": stored["metrics"],
                    "window": stored["window"], "as_of": stored["updated_at"],
                    "age_seconds": round(now - stored["updated_at"], 3),
                    "current": None,
                    "hint": "stored rollup only — pass refresh=True to pull fresh rrddata"}
        if callable(api):
            try:
                api = api()
            except RuntimeError as e:
                # The pull path is the ONE place this tool genuinely needs PVE (rrddata is a
                # PVE-guest concept) — the thunk's RuntimeError is the real reason (missing env
                # or a bad config), so it rides along rather than being swallowed (verdict 1.5).
                raise ProximoError(
                    "proximo_baseline needs a configured PVE plane to pull guest data — this "
                    f"deployment has none configured ({e}). PVE-guest-only: on a "
                    "PBS/PMG/PDM-only deployment this tool has nothing to report; a stored "
                    "rollup, if one exists, still answers with no PVE call.") from e
        samples = guest_rrddata(api, str(vmid), kind, node, timeframe, "AVERAGE")
        rollups = rollup_samples(samples)
        times = [s["time"] for s in samples if isinstance(s, dict) and s.get("time")]
        window = (min(times), max(times)) if times else None
        mem.store_baseline(target, kind, str(vmid), timeframe, rollups, window=window)
        newest = max((s for s in samples if isinstance(s, dict)
                      and any(s.get(m) is not None for m in BASELINE_METRICS)),
                     key=lambda s: s.get("time", 0), default=None)
        current = ({m: newest[m] for m in BASELINE_METRICS if newest.get(m) is not None}
                   if newest else {})
        return {"source": "live+memory", "vmid": str(vmid), "kind": kind,
                "timeframe": timeframe, "baseline": rollups,
                "window": list(window) if window else None,
                "current": current or None,
                "assessment": _assess(current, rollups) if current else None}
    finally:
        mem.close()


# What the map CANNOT answer, and which governed tool can — keyed on what the operator
# asked for, not on what we hold. The map carries identity and status; live metrics,
# stored config and provenance all live behind a real call.
#
# WHY THIS IS DATA AND NOT PROSE. Two live qwen3:8b runs on the real estate ended the same
# way: the model queried the map, got the right entity, and then concluded the capability
# did not exist — "the available tools do not include memory consumption metrics for
# containers" (false: pve_guest_status returns mem), and "there is no tool to track who
# changed a guest's configuration" (false: audit_verify is resident in its own tool list).
# It never searched. Telling it to search, in the system prompt, changed nothing across
# both runs. ⭐ The 07-29 law in the other direction: prose could not stop a small model
# fabricating, and prose cannot make it reach either. So the server, which already knows
# what it does not hold, says the tool name in the response itself.
_NEXT_TOOL = (
    ("pve_guest_status", "live cpu/mem/uptime"),
    # audit_entries, not audit_verify (live-caught 2026-08-01): verify PROVES the chain is
    # intact; entries READS who changed what. Pointing the who-question at the prover sent
    # a live 8B to a tool that could never answer it.
    ("audit_entries", "who changed what, from the ledger"),
    ("pve_guest_config_get", "stored config"),
    ("pve_backup_list", "backups"),
)


def _next_tool_for(query: str, entities: list[dict]) -> dict | None:
    """What the map does NOT hold, and which tool does — attached to every filtered recall.

    ⚠️ This must NOT key on the query text, and the first version did. It matched trigger
    words like "memory"/"who" against the query string, which passed a test fed the user's
    whole question — and then did not fire once in a live run, because a model does not
    send its user's question. Asked "how much memory is the container named redis using",
    qwen3:8b called `proximo_recall(query='redis')`: a SEARCH TERM. The words the trigger
    needed were in the sentence the server never receives. My fixture used input no model
    produces, so a green test proved nothing about the path it named.

    So the pointer is unconditional whenever a filter ran and matched something, and kept
    to one short line per class (~30 tokens) — cheap enough to always carry, which is the
    only way it can be there for the call that actually needs it.
    """
    if not entities:
        return None
    first = entities[0]
    vmid = first.get("key")
    return {
        "map_holds": "identity, name, node, status only",
        # Stated NEGATIVELY on purpose (1 of 10 live qwen3:8b runs, 2026-08-01, answered a
        # memory question from this response with a fabricated "1.5GB"): a tool response is
        # a prompt, and what it fails to forbid, a small model fills in.
        "not_held": "cpu/mem/disk/uptime numbers are NEVER in this response — do not state "
                    "them from here; read them via the tools below",
        "for_more": dict(_NEXT_TOOL),
        "subject": {"vmid": vmid, "kind": first.get("kind")},
        "hint": f"call these via proximo_call, e.g. pve_guest_status(vmid={vmid!r})",
    }


def recall_state(since: str | None = None, detail: str = "lean", journal: int = 0,
                 query: str | None = None) -> dict:
    if not memory_enabled():
        raise ProximoError(
            "estate memory is opted out (PROXIMO_MEMORY=0) — unset it or set PROXIMO_MEMORY=1 "
            "to re-enable the local map "
            "(a derived, rebuildable SQLite beside the audit log; nothing leaves the box)")
    if not isinstance(journal, int) or journal < 0:
        raise ProximoError(f"journal must be a non-negative entry count, got {journal!r}")
    since_ts = _parse_since(since) if since else None
    target = _active_target_name()
    mem = EstateMemory(memory_path())
    try:
        out = mem.recall(target, since_ts=since_ts, detail=detail)
        entries = mem.get_journal(target, journal, since_ts=since_ts) if journal else []
        # An unfed map REFUSES rather than returning something answer-shaped. Stripping the
        # counts was necessary and not sufficient: live-caught 2026-07-29, qwen3:4b read the
        # remaining note — which says in words that this is not a statement about the estate,
        # and names pve_list_guests — and answered "0" three runs out of three. Prose is not a
        # guardrail for a small model; a hole gets filled with zero. Same posture the disabled
        # path takes one branch up, for the same reason: memory has nothing to say.
        # Only when there is genuinely nothing to report — a journal entry is real history and
        # is reported even when no list read has fed the estate map yet.
        if "total" not in out and not entries:
            raise ProximoError(
                "estate memory is enabled but has observed nothing yet — this is NOT a "
                "statement that the estate is empty, it is the absence of an observation. "
                + _recall_unfed_remedy())
        if journal:
            out["journal"] = entries
        if query and query.strip():
            # Semantic entity filter (opt-in vectors; refuses when unconfigured rather
            # than silently returning everything). ROWS are filtered; COUNTS are not:
            # a filtered list must never masquerade as the census — the same law as
            # the empty-map branch above, one tier up. The note says so in-band.
            #
            # detail="summary" carries NO entities by design, so a query there has
            # nothing to filter. Refuse rather than proceed: the old code called
            # entity_filter with [], which returned [] (inventing an "entities" key
            # the summary shape omits, under a note claiming matches were made) AND
            # synced an EMPTY authoritative set, whose stale-key deletion wiped every
            # cached entity vector for the target — a silent cache eviction that
            # forced a full re-embed on the next real query. Found by an adversarial
            # lens, 2026-08-01.
            if detail == "summary":
                raise ProximoError(
                    "detail='summary' returns counts only and carries no entity rows, so "
                    "there is nothing for query to filter — use detail='lean' (default) "
                    "or 'full' with a query, or drop the query for counts alone")
            from proximo import vectors
            out["entities"] = vectors.entity_filter(
                target, out.get("entities") or [], query.strip())
            out["query"] = query.strip()
            out["next"] = _next_tool_for(query, out["entities"])
            out["note"] = ("entities lists the top semantic matches for the query only; "
                           "total/by_kind/by_status/guest_summary still count the WHOLE "
                           "estate.")
        return out
    finally:
        mem.close()
