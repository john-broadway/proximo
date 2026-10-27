"""THE STORE: what the door saw last time, so "what changed" is a read from disk.

The vendor keeps no yesterday, so no live call of any size answers "what changed since
yesterday". Every list read the engine serves leaves a snapshot here, as a side effect of a read
that already happened: never a call of its own. `changes` compares two snapshots of the SAME read
(plane, called path, arguments), so a row absent from the later one is gone from what that read
returns, not an inference across different reads.

What is kept: the LEAN rows (names, states, ids), after the credential withhold. Counters change
on every read and would make every row "changed"; they are the vendor's to answer live. An
address the taint record marks untrusted IS kept (cluster resources is one: guest names ride
every row), and the engine answers from it the way it serves the read: the session is marked and
the rows are fenced, so storage never launders guest- or externally-authored bytes.

Layout, one directory per read: `latest.json.gz`, plus the first snapshot of each UTC day as
`YYYY-MM-DD.json.gz`, the last `KEEP_DAYS` of them. Owner-only (0700 / 0600): it is estate
inventory in plaintext. Written by a per-process temp file and a rename, so a reader never sees a
half file and two writers never share a temp name.

`PROXIMO_STORE=off` keeps nothing. `PROXIMO_STORE_DIR` moves it; the default is `store/` beside
the audit ledger. HONEST LIMIT, the ledger's own: co-located with the agent this is a convenience
the agent could edit, and every answer says it came from the store and when.
"""
from __future__ import annotations

import datetime
import gzip
import hashlib
import json
import os
import re
import stat
import tempfile
import time
from typing import Any

from proximo.core.errors import ProximoError

KEEP_DAYS = 8
_LATEST = "latest.json.gz"
_MAX_BYTES = 4 * 1024 * 1024        # a read bigger than this is not kept; the door says nothing
_IDENTITY = ("id", "vmid", "volid", "name")


def _now() -> float:
    return time.time()


def enabled() -> bool:
    return os.environ.get("PROXIMO_STORE", "").strip().lower() not in {"0", "false", "no", "off"}


def directory(audit_log_path: str) -> str:
    return os.environ.get("PROXIMO_STORE_DIR") or os.path.join(
        os.path.dirname(audit_log_path) or ".", "store")


def key(plane: str, box: str, called: str, args: dict[str, Any]) -> str:
    """One read on one box. The box is in the key: two boxes behind one ledger (a registry
    target beside the env box) must never be diffed against each other."""
    spelled = json.dumps([plane, box, called, sorted((k, str(v)) for k, v in args.items())])
    return hashlib.sha256(spelled.encode()).hexdigest()[:24]


def _write(path: str, blob: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".keep-", suffix=f".{os.getpid()}")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def keep(base: str, plane: str, box: str, called: str, args: dict[str, Any], rows: list[dict]) -> None:
    """Snapshot one read. Raises on a filesystem failure; the engine swallows it, because a
    convenience must never fail the read it rides on."""
    now = _now()
    blob = gzip.compress(json.dumps({"plane": plane, "called": called, "args": args, "ts": now,
                                     "rows": rows}, default=str).encode())
    if len(blob) > _MAX_BYTES:
        return
    d = os.path.join(base, key(plane, box, called, args))
    for path in (base, d):
        os.makedirs(path, mode=0o700, exist_ok=True)
        _own(path)
    _write(os.path.join(d, _LATEST), blob)
    day = datetime.datetime.fromtimestamp(now, datetime.UTC).strftime("%Y-%m-%d") + ".json.gz"
    if not os.path.exists(os.path.join(d, day)):
        _write(os.path.join(d, day), blob)
    days = (f for f in os.listdir(d) if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\.json\.gz", f))
    for old in sorted(days)[:-KEEP_DAYS]:
        os.unlink(os.path.join(d, old))


def _own(path: str) -> None:
    """A store directory is a real directory this process owns, made owner-only. The key is
    computable from public facts, so a symlink planted at it would carry estate inventory
    wherever it points (lens 2026-09-28); `makedirs` accepts one and `mode=` only applies on
    creation. Refused here, and the engine skips the snapshot."""
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
        raise PermissionError(f"{path} is not a directory this process owns")
    os.chmod(path, 0o700)


class _Unreadable(Exception):
    pass


def _load(path: str) -> dict[str, Any] | None:
    """None when absent; `_Unreadable` when present and not a snapshot (a torn write, a disk
    fault, an edit), so a caller can skip one bad day instead of crashing every answer."""
    try:
        with gzip.open(path, "rb") as f:
            snap = json.loads(f.read())
    except FileNotFoundError:
        return None
    except (OSError, EOFError, ValueError) as e:
        raise _Unreadable(type(e).__name__) from e
    if not (isinstance(snap, dict) and isinstance(snap.get("ts"), (int, float))
            and isinstance(snap.get("rows"), list)):
        raise _Unreadable("not a snapshot")
    return snap


def _load_or_skip(path: str) -> dict[str, Any] | None:
    try:
        return _load(path)
    except _Unreadable:
        return None


def latest(base: str, plane: str, box: str, called: str, args: dict[str, Any]) -> dict[str, Any] | None:
    return _load_or_skip(os.path.join(base, key(plane, box, called, args), _LATEST))


def parse_since(since: str) -> int:
    m = re.fullmatch(r"\s*([0-9]+)\s*([mhd])\s*", since or "", re.ASCII)
    if not m or int(m.group(1)) == 0:
        shown = repr(since) if len(since or "") <= 40 else f"{since[:40]!r}... ({len(since)} chars)"
        raise ProximoError(f"since={shown} is not a window: say 30m, 24h or 7d")
    return int(m.group(1)) * {"m": 60, "h": 3600, "d": 86400}[m.group(2)]


def _identity(rows: list[dict]) -> str | None:
    for k in _IDENTITY:
        if rows and all(k in r for r in rows):
            return k
    return None


def changes(base: str, plane: str, box: str, called: str, args: dict[str, Any], since: str) -> dict[str, Any]:
    """Added, gone and changed between the newest snapshot and the newest one at least `since`
    older than now (or the oldest kept, said so). A list of changes plus their counts."""
    window = parse_since(since)
    d = os.path.join(base, key(plane, box, called, args))
    try:
        if os.path.lexists(d):
            _own(d)
        now_snap = _load(os.path.join(d, _LATEST))
    except (_Unreadable, OSError) as e:
        raise ProximoError(f"the snapshot kept for {plane} GET {called} is unreadable "
                           f"({e}); read it live once and the next one replaces it") from e
    if now_snap is None:
        raise ProximoError(f"nothing is kept for {plane} GET {called} yet: read it once (a cron job "
                           f"on the shell door keeps it current) and ask again")
    snaps = [s for s in (_load_or_skip(os.path.join(d, f)) for f in sorted(os.listdir(d))
                         if f.endswith(".json.gz")) if s is not None]
    cutoff = _now() - window
    older = [s for s in snaps if s["ts"] <= cutoff]
    then = max(older, key=lambda s: s["ts"]) if older else min(snaps, key=lambda s: s["ts"])
    ident = _identity(then["rows"] + now_snap["rows"])

    def by_id(rows: list[dict]) -> dict[str, dict]:
        return {str(r[ident]) if ident else json.dumps(r, sort_keys=True): r for r in rows}

    def same(x: Any, y: Any) -> bool:
        # PVE hands a comma list back in any order ("rootdir,images" then "images,rootdir",
        # measured live on storage `content`): the same set is not a change.
        if isinstance(x, str) and isinstance(y, str) and "," in x:
            return sorted(x.split(",")) == sorted(y.split(","))
        return x == y

    a, b = by_id(then["rows"]), by_id(now_snap["rows"])
    out: list[dict] = [{"change": "added", **b[k]} for k in b if k not in a]
    out += [{"change": "gone", **a[k]} for k in a if k not in b]
    for k in (k for k in b if k in a):
        diff = {f: [a[k].get(f), b[k].get(f)] for f in sorted(set(a[k]) | set(b[k]))
                if not same(a[k].get(f), b[k].get(f))}
        if diff:
            out.append({"change": "changed", **({ident: b[k][ident]} if ident else {}), **diff})
    counts = {c: sum(1 for x in out if x["change"] == c) for c in ("added", "gone", "changed")}
    span = int(now_snap["ts"] - then["ts"])
    answer: dict[str, Any] = {
        "source": "store", "counts": counts, "changes": out,
        "from": _iso(then["ts"]), "to": _iso(now_snap["ts"]),
        "window_s": span, "to_age_s": int(_now() - now_snap["ts"]),
    }
    if not older:
        answer["note"] = (f"asked for {since}; the oldest snapshot kept is only {span}s before the "
                          f"newest, so this is the change over that span")
    return answer


def _iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, datetime.UTC).isoformat(timespec="seconds")
