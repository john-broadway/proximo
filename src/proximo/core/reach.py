"""The reach grant, made observable (capability `reach-grant-observable`).

Every opt-in lane the spine keeps (`spine._LANES`: the guest-agent lane, the container shell lane,
the node shell lane, the download lane) is a REACH GRANT: its switch, and for the two that name
guests, its allowlist (`PROXIMO_CT_ALLOWLIST`, `PROXIMO_AGENT_ALLOWLIST`). The shell lane is the
perimeter for the one channel a Proxmox ACL cannot scope (`ssh -> pct exec` answers to no PVE
privilege). Widening it is the most consequential change the system allows, and it lives in env,
not in the ledger, so until a door compared it nothing durable showed it grow from three containers
to `*` between two restarts.

At each door's start `greet` compares the grant the door starts with, parsed by the spine's own
parser, against the last grant a `core.reach_grant` row recorded FOR THAT FACE (two deployments with
different env must not hide behind each other's rows), and writes a row when it moved: `first`,
`first_with_history`, `widened` (an id or `*` appeared, or a lane was switched on) or `narrowed`.
An unchanged start writes nothing (the ledger stays signal, not heartbeat). A row carries ids, the
lane switches and the STORE each allowlist came from (`envfile.source`, in words), never a path, a
host or a value of any other key. The `proximo-core` shell door greets before a call that can
mutate (a non-GET, or an undo), not per call: it has no start, and a read cannot use a lane.

TWO KINDS OF "CANNOT PROVE", treated differently on purpose.
- The ledger cannot be READ or the row cannot be WRITTEN: the grant is not on the chain and cannot
  be put there. With a lane open the door REFUSES TO START (rc 3); with every lane closed it starts
  and says so on stderr.
- The chain does not VERIFY (a torn line, a forged row, a pin that is no longer held): the engine
  keeps receipting mutations on such a chain (it never verifies before a write), so refusing the
  door would only brick the box with no repair verb. The door STARTS, compares against the last
  parseable row for its face anyway (honest widenings are still named), writes the row with outcome
  `unproven` and the reason, and says so loudly on stderr; `doctor` flags it as incomplete. The
  repair path is the chain's own: `audit_verify` names the broken row, and moving the log aside by
  hand archives it as evidence and starts a fresh chain (the next start then reads `first_with_history`).

A WIPE OR A ROLLBACK must not read as a clean first. The baseline is read under the operator's pin
(`PROXIMO_AUDIT_EXPECTED_HEAD`, a row the chain must still hold, as `audit_verify` takes it) and
follows a sealed rotation archive when the live log holds no row for the face. When there is no row
at all but the box has history (an archive, an audit key that already existed, a log that held rows)
the row is `first_with_history`, not `first`, and with a lane open it is `unproven`. Once per
upgraded box this reads loudly, since a box upgraded from before this check holds history and no
reach row; the row then stands as the baseline. A `not_compared` row is never a baseline.

HONEST LIMITS. It runs at door START, so an env edit takes effect (and is witnessed) at the restart
that applies it. The ssh target is a switch too (the same ids on another host), but its value is a
host and the row carries ids only, so a re-pointed target is not witnessed here. A face that starts
for the first time records `first`; it is not compared with another face's grant. Only the newest
rotation archive is followed. Concurrent starts serialise on a sidecar lock beside the ledger and
re-read the baseline under it, so one change is one row.

The REACH MIRROR, as an advisory only. 0.44 refused a container op unless the served token held an
operator-named privilege on that guest. A gate re-does the vendor's ACL in Proximo's words and had
a break-glass that WIDENED reach, so the core keeps the one thing the vendor cannot do: ask PVE,
per allowlisted container, whether the served token holds `PROXIMO_REACH_PRIVILEGE` there, and let
doctor say which guests it does not (`report`). The privilege is the operator's to name, because
what means "may run a command as root" is a judgement 0.44's own audit got wrong once: `VM.Console`
gates a console attach (a login prompt), not `pct exec`. Unset, nothing is asked. It covers the
container shell lane only (the agent lane is vendor-ACL'd), at most MIRROR_CAP guests, and says what
it did not ask about.
"""
from __future__ import annotations

import fcntl
import os
import sys
from dataclasses import dataclass, field
from typing import Any

from proximo.core import envfile, spine
from proximo.core.errors import ProximoError
from proximo.core.ledger import (
    LedgerConfig,
    find_rotation_archive,
    ledger_key,
    looks_like_head,
    open_ledger,
    parse_lines,
    read_log,
    verify_chain,
    verify_lines,
)
from proximo.core.principal import ledger_principal

ACTION = "core.reach_grant"
TARGET = "reach/grant"
PRIVILEGE_ENV = "PROXIMO_REACH_PRIVILEGE"
PIN_ENV = "PROXIMO_AUDIT_EXPECTED_HEAD"
MIRROR_CAP = 25            # one receipted read per guest: a large allowlist is sampled, and says so

#: the doctor flags this module writes that are ADVISORY (`doctor._ADVISORY`): they move no exit code.
#: The flags that open with "reach:" (a baseline that cannot be proven) are NOT: they make the report incomplete.
ADVISORY = ("the reach grant", "the served token holds no", "the served token's rights",
            f"{PRIVILEGE_ENV} is set but blank")

Moved = dict[str, list[str]]


def _lane_of(entries: frozenset[str], allow_all: bool, garbled: bool, enabled: bool,
             *, allowlisted: bool = True) -> dict[str, Any]:
    ids = ["*"] if allow_all else sorted(entries, key=_idkey)
    grants = enabled and (not allowlisted or (bool(ids) and not garbled))   # open, but to nothing?
    return {"enabled": enabled, "ids": ids, "garbled": garbled, "grants": grants}


def _idkey(c: str) -> tuple[int, int, str]:
    return (0, int(c), c) if c.isdigit() else (1, 0, c)


def current() -> dict[str, dict[str, Any]]:
    """The grant this process holds, per lane, built from the spine's own lane registry and its own
    parser (no second list to drift): every opt-in lane, with its switch, and its ids where it has an
    allowlist. A lane with no allowlist is its switch alone."""
    out = {}
    for lane, (enable, allow, *_rest) in spine._LANES.items():
        enabled = spine._env_truthy(enable)
        if allow is None:
            out[lane] = _lane_of(frozenset(), False, False, enabled, allowlisted=False)
        else:
            entries, allow_all, garbled = spine._parse_allowlist(os.environ.get(allow))
            out[lane] = _lane_of(entries, allow_all, garbled, enabled)
    return out


def _open_lanes(grant: dict[str, dict[str, Any]]) -> list[str]:
    return [lane for lane, g in grant.items() if g["enabled"]]


def diff(prev: dict[str, Any], cur: dict[str, dict[str, Any]]) -> tuple[str, Moved, Moved]:
    """(change, added, removed) from a recorded grant to the current one. `*` subsumes every id, so
    `*` appearing adds `*` and no ids, and `*` leaving removes `*` and adds none of the ids that
    replace it. A lane switched on adds "enabled". Any addition makes the change `widened`."""
    added: Moved = {}
    removed: Moved = {}
    for lane, now in cur.items():
        was = prev.get(lane) or {"enabled": False, "ids": []}
        a: list[str] = []
        r: list[str] = []
        was_ids, now_ids = set(was.get("ids") or ()), set(now["ids"])
        if "*" in now_ids:
            a += [] if "*" in was_ids else ["*"]
        elif "*" in was_ids:
            r += ["*"]
        else:
            a += sorted(now_ids - was_ids, key=_idkey)
            r += sorted(was_ids - now_ids, key=_idkey)
        if now["enabled"] and not was.get("enabled"):
            a.append("enabled")
        if was.get("enabled") and not now["enabled"]:
            r.append("enabled")
        if a:
            added[lane] = a
        if r:
            removed[lane] = r
    return ("widened" if added else "narrowed" if removed else "unchanged"), added, removed


def _sources() -> dict[str, str]:
    return {lane: envfile.source(allow) for lane, (_e, allow, *_r) in spine._LANES.items() if allow}


@dataclass
class Baseline:
    """What the ledger says about the grant. `status`: `ok` (read and verified), `unverified` (read,
    the chain does not verify: `why`), `unreadable` (could not be read: `why`). `faces` is the last
    grant row per face (live log first, then the newest rotation archive), `last` the newest of all
    (None when none), `any_reach` whether any reach row exists at all, `history` whether the box held
    anything before this reading."""
    status: str = "ok"
    why: str = ""
    faces: dict[str, dict] = field(default_factory=dict)
    last: dict | None = None
    any_reach: bool = False
    history: bool = False


def _pin() -> tuple[str | None, str]:
    raw = os.environ.get(PIN_ENV, "").strip().lower()
    if not raw:
        return None, ""
    return (raw, "") if looks_like_head(raw) else (None, f"{PIN_ENV} is not a 64-char hex head")


def _grant_rows(lines: list[str]) -> list[dict]:
    out = []
    for entry in parse_lines(lines):
        d = entry.get("detail") or {}
        if entry.get("action") == ACTION and isinstance(d.get("lanes"), dict):
            out.append(entry)
    return out


def baseline(lcfg: Any, *, history: bool = False) -> Baseline:
    """Read the grant's history from the ledger, verifying what is read. Never writes."""
    b = Baseline(history=history)
    try:
        lines = read_log(lcfg.audit_log_path)
    except ProximoError:
        lines = []                                  # no ledger yet
    except OSError as exc:
        return Baseline("unreadable", f"the ledger cannot be read ({type(exc).__name__})", history=history)
    try:
        key = ledger_key(lcfg)
    except (OSError, ValueError) as exc:
        return Baseline("unreadable", f"the audit key cannot be read ({type(exc).__name__})", history=history)
    pin, bad_pin = _pin()
    if bad_pin:
        b.status, b.why = "unverified", bad_pin
    elif key is None and any(x.strip() for x in lines):
        b.status, b.why = "unverified", "the audit key is missing"
    else:
        v = verify_lines(lines, key, pinned_row=pin)
        if not v.ok:
            b.status, b.why = "unverified", f"the ledger's chain does not verify ({v.reason})"
    groups = [_grant_rows(lines)]
    archive = find_rotation_archive(lcfg.audit_log_path)
    if archive:
        b.history = True
        try:
            arows = read_log(archive)
            if b.status == "ok" and not verify_chain(archive, key).ok:
                b.status, b.why = "unverified", "the newest sealed archive's chain does not verify"
            groups.append(_grant_rows(arows))
        except (ProximoError, OSError):
            b.status, b.why = "unverified", "the newest sealed archive cannot be read"
    b.history = b.history or any(x.strip() for x in lines if ACTION not in x)
    for rows in reversed(groups):                   # archive first, so the live log's rows win
        for entry in rows:
            if entry["detail"].get("change") != "not_compared":
                b.faces[str(entry["detail"].get("face"))] = entry
    b.any_reach = any(groups)
    b.last = next((e for rows in groups for e in reversed(rows)), None)
    return b


def _lock(path: str):
    """The reach lock beside the ledger (a sidecar: the log's own flock is held inside `record`, and
    a second flock on it from here would deadlock). O_NOFOLLOW like the ledger's other locks."""
    f = open(path + ".reach.lock", "a+", encoding="utf-8",   # noqa: SIM115 -- closed by the caller's with
             opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW, 0o600))
    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    return f


def _history_before(lcfg: Any) -> bool:
    """Whether the box held a ledger or its key before this start's `open_ledger` may mint them."""
    key_path = lcfg.audit_key_path or os.path.join(os.path.dirname(lcfg.audit_log_path) or ".", "audit.key")
    try:
        return os.path.exists(key_path) or os.path.getsize(lcfg.audit_log_path) > 0
    except OSError:
        return False


def greet(prog: str, face: str) -> bool:
    """Compare the grant with this face's last record and write the row if it moved. True = the door
    may start; False = it must refuse (rc 3): the grant is not on the chain and cannot be put there,
    and a lane is open."""
    cur = current()
    lcfg = LedgerConfig.from_env()
    history = _history_before(lcfg)
    try:
        led = open_ledger(lcfg)
    except (OSError, RuntimeError, ValueError) as exc:
        return _cannot(prog, cur, f"the ledger cannot be opened ({type(exc).__name__})")
    try:
        lock = _lock(lcfg.audit_log_path)
    except OSError as exc:
        return _cannot(prog, cur, f"the reach lock cannot be taken ({type(exc).__name__})")
    with lock:
        b = baseline(lcfg, history=history)            # re-read under the lock: one change, one row
        if b.status == "unreadable":
            return _cannot(prog, cur, b.why)
        detail: dict[str, Any] = {"face": face, "lanes": cur, "source": _sources()}
        prev = b.faces.get(face)
        unproven = b.status == "unverified"
        if prev is not None:
            change, added, removed = diff(prev["detail"]["lanes"], cur)
            if change == "unchanged":
                if unproven:
                    _loud(prog, b.why, cur)
                return True
            detail |= {"change": change, "added": added, "removed": removed,
                       "previous": str(prev["entry_hash"])[:12]}
        elif unproven and not b.any_reach:
            detail |= {"change": "not_compared", "reason": b.why}
        elif not b.any_reach and b.history:
            detail |= {"change": "first_with_history", "added": {}, "removed": {},
                       "reason": "no reach row, but the box already held a ledger, its key or an archive"}
            unproven = unproven or bool(_open_lanes(cur))
        else:
            detail |= {"change": "first", "added": {}, "removed": {}}
        if unproven:
            detail["reason"] = b.why or detail.get("reason", "")
        try:
            led.record(ACTION, target=TARGET, outcome="unproven" if unproven else "ok", detail=detail,
                       principal=ledger_principal())
        except (OSError, RuntimeError, ValueError) as exc:
            return _cannot(prog, cur, f"the row could not be written ({type(exc).__name__})")
        if unproven:
            _loud(prog, detail.get("reason", ""), cur)
    return True


def _loud(prog: str, why: str, cur: dict[str, dict[str, Any]]) -> None:
    opened = _open_lanes(cur)
    print(f"{prog}: the reach grant is UNPROVEN ({why}); the door starts"
          + (f" with the {', '.join(opened)} lane(s) open" if opened else "")
          + ". Run `proximo-core doctor`; `audit_verify` names a broken row, and moving the ledger aside by "
            "hand archives it as evidence and starts a fresh chain.", file=sys.stderr)


def _cannot(prog: str, cur: dict[str, dict[str, Any]], why: str) -> bool:
    """The grant is not on the chain and cannot be put there. Refuse when a lane is open."""
    opened = _open_lanes(cur)
    nothing = [lane for lane in opened if not cur[lane]["grants"]]
    print(f"{prog}: the reach grant could not be compared with the ledger ({why})"
          + (f"; the {', '.join(opened)} lane(s) are open"
             + (f" ({', '.join(nothing)} grant(s) nothing)" if nothing else "")
             + ", so this door refuses to start. Repair the ledger (`proximo-core doctor` says what is wrong) "
               "or close the lane" if opened else "; every lane is closed, so the door starts"), file=sys.stderr)
    return not opened


# ---- doctor's reach section ---------------------------------------------------------------------

def _summary(entry: dict[str, Any]) -> dict[str, Any]:
    d = entry["detail"]
    return {"ts": entry.get("ts"), "id": str(entry.get("entry_hash", ""))[:12], "change": d.get("change"),
            "face": d.get("face"), "outcome": entry.get("outcome"), "added": d.get("added", {}),
            "removed": d.get("removed", {})}


def report(lcfg: Any, flags: list[str]) -> dict[str, Any]:
    """Doctor's reach section: the grant per lane with the store that fed it, the last change the
    ledger recorded (and per face), whether a door has recorded the grant it would start with now,
    and (when `PROXIMO_REACH_PRIVILEGE` is set) the mirror. The baseline is read AND verified here
    (doctor never opens the ledger for writing). Flags: a baseline that cannot be proven or read is
    a "reach:" flag and makes the report incomplete; the rest are advisory."""
    cur = current()
    src = _sources()
    b = baseline(lcfg)
    section: dict[str, Any] = {
        "lanes": {lane: {**g, **({"source": src[lane]} if lane in src else {})} for lane, g in cur.items()},
        "last_change": _summary(b.last) if b.last else None,
        "faces": {f: _summary(e) for f, e in sorted(b.faces.items())}}
    matches = any(diff(e["detail"]["lanes"], cur)[0] == "unchanged" for e in b.faces.values())
    section["recorded_matches_current"] = matches
    opened = _open_lanes(cur)
    if b.status != "ok":
        flags.append(f"reach: the grant's record cannot be proven ({b.why}); "
                     + ("a widening cannot be told from the chain" if b.status == "unreadable" else
                        "rows read are unverified evidence, and `audit_verify` names the break"))
    if b.last and b.last["detail"].get("change") == "first_with_history":
        flags.append("the reach grant was first recorded on a box that already held a ledger or its key: a wiped "
                     "or replaced ledger looks like this too; verify the chain and any archive beside it")
    if opened and not matches:
        if b.last is None:
            flags.append("the reach grant has not been recorded by any door start yet; the next start records it")
        else:
            _c, added, removed = diff(b.last["detail"]["lanes"], cur)
            flags.append(f"the reach grant differs from the last one a door recorded (added {added or 'nothing'}, "
                         f"removed {removed or 'nothing'}); the next door start records it")
    for lane in opened:
        if not cur[lane]["grants"]:
            flags.append(f"the reach grant: the {lane} lane is switched on and grants nothing (empty or garbled "
                         "allowlist)")
    mirror = _mirror(lcfg, cur, flags)
    if mirror is not None:
        section["mirror"] = mirror
    return section


def _mirror(lcfg: Any, cur: dict[str, dict[str, Any]], flags: list[str]) -> dict[str, Any] | None:
    raw = os.environ.get(PRIVILEGE_ENV)
    if raw is None:
        return None
    priv = raw.strip()
    if not priv:
        msg = (f"{PRIVILEGE_ENV} is set but blank: refusing to guess between 'mirror off' and 'mirror on': "
               "unset it or name a privilege")
        flags.append(msg)
        return {"error": msg}
    out: dict[str, Any] = {"privilege": priv, "checked": 0, "without": [], "unanswered": [],
                           "not_mirrored": ["agent"]}   # the agent lane is vendor-ACL'd; only ssh -> pct exec is not
    shell = cur["shell"]
    if not shell["enabled"]:
        return out | {"skipped": "the container shell lane is off"}
    if shell["ids"] == ["*"]:
        return out | {"skipped": "the container allowlist is '*': no list of guests to ask about"}
    ids = [c for c in shell["ids"] if c.isdigit()]
    odd = [c for c in shell["ids"] if not c.isdigit()]
    out["capped"] = len(ids) > MIRROR_CAP
    if odd:
        out["not_asked"] = odd
        flags.append(f"the served token's rights on allowlist entries that are not container ids ({', '.join(odd)}) "
                     "were not asked about")
    if out["capped"]:
        flags.append(f"the served token's rights on {len(ids) - MIRROR_CAP} allowlisted container(s) beyond the "
                     f"first {MIRROR_CAP} were not asked about (the mirror reads at most {MIRROR_CAP}, each a receipt)")
    from proximo.core import engine, wire  # noqa: PLC0415  (lazy: the grant check above needs neither)
    try:
        cfg = wire.Plane.from_env("pve")
    except RuntimeError:
        return out | {"skipped": "pve is not configured"}
    try:
        row = engine.resolve("pve", "GET", "/access/permissions")
    except ProximoError:
        return out | {"skipped": "the record does not serve GET /access/permissions"}
    for ctid in ids[:MIRROR_CAP]:
        path = f"/vms/{ctid}"
        out["checked"] += 1
        try:   # PVE resolves propagation and deeper NoAccess server-side for the per-path query
            env = engine.execute(row, {"path": path}, cfg=cfg, path="/access/permissions", ledger_cfg=lcfg,
                                 fields="all", evaluating=True)
            data = env.get("data")
            if not isinstance(data, dict):        # cut, fenced or not a record: not an answer
                raise ValueError("no record")
            if not (data.get(path) or {}).get(priv):    # a keying drift reads as absent: fails closed
                out["without"].append(ctid)
        except Exception:  # noqa: BLE001 -- the vendor's or the spine's refusal: unanswered, never allowed
            out["unanswered"].append(ctid)
    if out["without"]:
        flags.append(f"the served token holds no {priv} on allowlisted container(s) {', '.join(out['without'])}: "
                     "ssh -> pct exec reaches them anyway, because no PVE privilege scopes that channel")
    if out["unanswered"]:
        flags.append(f"the served token's rights on container(s) {', '.join(out['unanswered'])} could not be "
                     "read; whether it holds the reach privilege there is not known")
    return out
