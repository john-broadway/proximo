"""UNDO's restore: the before-state a receipt captured, written back through the vendor's own write.

Every mutation with a GET twin captures the record before it runs (`engine.execute`, the
`core.undo_point` row) and hands back the row's id under `undo.id`. This module is the other
half 0.44 had and the core did not: ONE RULE, like PLAN's read. The restore is the PUT the
vendor publishes at the same path, written with the captured record, as a governed mutation
through `execute` (armed, tiered, consented, rated, receipted, with its own capture, so an
undo is undoable). The plan of a restore is the plan of that PUT, so `change` says exactly what
goes back and `noop` says nothing drifted. Nothing is invented where the vendor publishes no
such write: a deleted record, a collection, a path with no PUT, a PUT that publishes no
parameters, each get a sentence, never a guessed reverse call. A capture of a POST restores
through the PUT only where the vendor's schema says the two are one write (every parameter the
PUT publishes, the POST publishes too: QEMU's async config); elsewhere the PUT at the same path
is a different operation (apt repositories: POST changes a repo, PUT adds a standard one) and
the restore refuses rather than lie `noop` (lens 1).

A CREATE at an item path has no record to read back before it runs: its GET twin fails (404; PVE
answers 500 for "no such user"), and `_undo_before` refuses a mutation whose read-back fails, so
a token, a realm-sync job or a metric server could never be made with UNDO on. `undo.toml` names
the five addresses the vendor's own sentences call a create of the record the path names (keyed
on the address, never the shape: a POST at an item path with both twins can be a restore, a copy,
or a rule added to a group, whose "absent" would delete what was there). For one of them a failed
read-back is captured `before: absent` with the vendor's status, and the restore is the DELETE the
vendor publishes at the same path, through `execute` like the PUT. The proof of absence is not
the failed read but the create landing: every listed vendor refuses a duplicate, so the DELETE is
sent only when the terminal row that names the capture says `ok` (the error row and the ok row both
carry the capture's id; pairing by intent read a later write at the path as the landing); an error,
a create not seen to finish, or no terminal row at all deletes nothing and says so, and a capture
already put back is put back once.

What is never written: a value the receipt withheld or masked (a credential, fingerprinted on
the row; 0.44's `skipped_unsettable`), a key the write does not publish (`meta` on a QEMU
config, `type` on a storage; the vendor's own schema is the allowlist, not a hand list), a write
control the capture happens to hold (`delete`), a null, and `digest` from the capture (the lock
is the CURRENT record's, so a write that raced this one is refused by the vendor, 0.44's rule).
A key added since the capture is removed only when the captured mutation itself added it (its
`executing` row names its arguments) and the write publishes a delete list (a comma string on
PVE and PMG, an array on PBS and PDM; a boolean `delete` is a flag that means something else);
a key that appeared by other hands (`unused0` after a detach, `lock` under a backup) is named,
never removed (lens 1). A parameter the write requires rides along at its captured value.

PROVE guards UNDO: the live chain is verified with the ledger's own key before the capture is
trusted, which is what catches a keyed ledger rewritten unkeyed (lens 1); a before-state on a
broken chain is not evidence, and writing it would be writing an attacker's bytes. A capture
made on a registered box is restored on that box only, and a record the fence has wrapped is
not diffed at all. A write the vendor's task then fails claims nothing restored.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import stat
import time
from collections.abc import Set as AbstractSet
from typing import Any

from proximo.core import engine, rawdoor, spine, wire
from proximo.core.errors import ProximoError
from proximo.core.ledger import (
    EXECUTING,
    LedgerConfig,
    executing_for,
    find_entry,
    ledger_key,
    parse_lines,
    read_log,
    verify_lines,
)

WITHHELD = "withheld or masked by the receipt (a credential); set it by hand"
UNPUBLISHED = "the write does not publish it"
NOT_BY_THE_MUTATION = "added since the capture by something other than the captured mutation; not removed"
_REDACTED = re.compile(r"\[redacted( sha256:[0-9a-f]{12} len:[0-9]+)?\]")
_CONTROLS = frozenset({"delete", "digest"})


def restore(ref: str, *, plane: str | None = None, cfg: wire.Plane | None = None, ledger_cfg: Any = None,
            confirm: bool = False, wait: int | None = None) -> dict[str, Any]:
    """Plan (default) or run the write that puts the record captured on receipt `ref` back.

    `plane` is needed only for a capture recorded before captures carried theirs. `cfg` is the
    plane's connection when a door holds one; else the env box. The answer is the PUT's plan
    (`status: plan`), its execution (`restored`, `deleted`, `skipped`, the envelope; `status:
    failed` with `attempted` when the vendor's task did not land), or `status: noop` when no
    published key differs from the capture and nothing is written or spent.
    """
    rawdoor.check_input("id", ref)        # a receipt id is 8 to 64 hex characters; the rest is refused
    lcfg = ledger_cfg or LedgerConfig.from_env()
    # ONE READ. The bytes are read once and verified, found in and paired within; three separate
    # reads of a writable file let a swap between them put a forged capture on the wire (lens 2).
    lines, entries, entry, detail, product, aimed_at = _capture(ref, plane, cfg, lcfg)
    if "snapshot" in detail:
        return _rollback(ref, entry, detail, lines, lcfg, cfg, ledger_cfg, aimed_at, confirm, wait, product,
                         entries)
    method, _, published = str(detail.get("governed_as", "")).partition(" ")
    target = entry.get("target") or ""
    before = detail.get("before")
    if detail.get("absent") is True:
        return _delete_back(ref, entry, entries, lines, lcfg, cfg, ledger_cfg, product, published, target,
                            aimed_at, confirm, wait)
    if method == "DELETE":
        raise ProximoError(f"{product} publishes no write that restores a deleted record; the before-state of "
                           f"{target} is on receipt {ref} ({entry.get('ts')})")
    if isinstance(before, dict) and before.get("truncated") is True and "sha256" in before:
        raise ProximoError(f"capture {ref} is {before.get('bytes')} bytes, over the receipt's bound; only its "
                           f"hash is on the row, so nothing can be written back from it")
    if isinstance(before, list):
        raise ProximoError(f"capture {ref} is a collection, not a record; no write restores it")
    if not isinstance(before, dict):
        raise ProximoError(f"capture {ref} holds no record to write back")
    table = engine.table()
    put = table.get((product, "PUT", published))
    if put is None or put.excluded:
        raise ProximoError(f"{product} publishes no PUT {published}; nothing restores receipt {ref} by this door "
                           f"(the before-state is on the row)")
    if put.gate:
        raise ProximoError(f"the write of {published} is gated: {put.gate}; nothing restores receipt {ref}")
    if method != "PUT" and same_write(table[(product, method, published)]) is None:
        raise ProximoError(f"capture {ref} is of {method} {published}; the PUT at this path is a different "
                           f"operation by the vendor's own schema, so nothing restores it")
    if not _body(put):
        raise ProximoError(f"PUT {published} publishes no parameters in the table, so nothing can be written "
                           f"back from capture {ref} (parity row B19)")
    twin = table.get((product, "GET", published))
    if twin is None or twin.excluded or twin.gate:
        raise ProximoError(f"{product} no longer serves GET {published}; the record now cannot be read")
    try:
        _verified(lcfg, lines)
    except ProximoError as exc:
        engine._record(ledger_cfg, "core.refuse", put, outcome="refused",
                       detail={"reason": str(exc), "needs": "prove", "restores": ref}, called=target, remote=aimed_at)
        raise
    plane_cfg = cfg if cfg is not None else wire.Plane.from_env(product)
    # THE RECORD NOW, through execute: receipted, withheld, tainted, bounded like any read.
    env = engine.execute(twin, {}, cfg=plane_cfg, path=target, ledger_cfg=ledger_cfg, fields="all",
                         evaluating=True)         # the door reads the record to diff it, not to show it
    if "data" not in env:
        raise ProximoError(f"the record at {target} is over the door's cap now; the change back cannot be computed")
    untrusted = bool(env.get("untrusted"))
    withheld_now = set(env.get("withheld") or [])    # credentials the record holds NOW, stripped from data
    current = env["data"]
    if not isinstance(current, dict):
        raise ProximoError(f"the record at {target} is not a record now; nothing to diff the capture against")
    # THE BYTES, NOT THE SWITCH: a fenced record arrives as the fence's wrapper, and the wrapper
    # diffed against the capture read every key as drifted and sent the whole config unlocked
    # (lens 1). The wrapper is recognised by its own shape, whatever switch produced it.
    if "proximo_untrusted" in current:
        raise ProximoError(f"the record at {target} is attacker-authored and fenced; nothing is diffed against a "
                           f"fence, so nothing restores capture {ref} while {spine.TAINT_FENCE_ENV} is on")
    added_by = executing_for(entries, entry)
    d = _args(put, before, current, set((added_by or {}).get("args") or {}), withheld_now)
    shown = _reported(d)
    answer: dict[str, Any] = {"restores": ref, "captured": entry.get("ts"), "skipped": shown["skipped"],
                              **({"skipped_more": shown["skipped_more"]} if shown["skipped_more"] else {}),
                              **({"untrusted": True, "channel": twin.channel} if untrusted else {})}
    if not d["restored"] and not d["deleted"]:
        return _fit({"status": "noop", **answer, "why": "no published key differs from the capture; nothing to write",
                     **shown["differs"]})
    if not confirm:                           # the restore's own labels last: the twin's, not the PUT row's
        return _fit({**engine.plan(put, d["args"], target, cfg=plane_cfg, ledger_cfg=ledger_cfg, env=env),
                     "status": "plan", **answer})
    out = engine.execute(put, d["args"], cfg=plane_cfg, path=target, ledger_cfg=ledger_cfg, wait=wait,
                         restores=str(entry.get("entry_hash") or ref))
    # THE CLAIM FOLLOWS THE TASK (lens 1), AND SAYS WHICH WAY IT WENT (lens 2): a task that
    # finished and failed landed nothing; one merely submitted, timed out or unpollable may
    # land yet, and "failed" for it would send a caller to retry a write that took.
    state = _task_state(out)
    if state is not None:
        return _fit({**out, **answer, "status": state, "restored": [], "deleted": [],
                     "attempted": {k: _names(d[k]) for k in ("restored", "deleted")}})
    return _fit({**out, **answer, **{k: _names(d[k]) for k in ("restored", "deleted")}})


#: how many keys of a capture the model is shown by name; the rest are counted (a capture is up to 64 KB)
REPORT_KEYS = 8


def _names(names: Any) -> Any:
    """A list of key names, or the first REPORT_KEYS of it with `... (N more)` as the last entry's tail.
    The restore wrote them all; this is only how many the model is told by name."""
    if not isinstance(names, list) or len(names) <= REPORT_KEYS:
        return names
    return [rawdoor.echo(str(n), 40) for n in names[:REPORT_KEYS]] + [f"... and {len(names) - REPORT_KEYS} more"]


def _reported(d: dict[str, Any]) -> dict[str, Any]:
    """`skipped` (key -> why) and `differs_unwritten` (keys) as bounded entries and a count of the rest."""
    skipped, more = rawdoor.echo_map(d["skipped"], REPORT_KEYS, 120)
    differs = {"differs_unwritten": _names(d["differs_unwritten"])}
    return {"skipped": skipped, "skipped_more": more, "differs": differs}


def _fit(answer: dict[str, Any]) -> dict[str, Any]:
    return rawdoor.fit_answer(answer)


def _capture(ref: str, plane: str | None, cfg: wire.Plane | None, lcfg: Any) -> tuple:
    """The capture `ref` names, read ONCE, and the plane and box it must be restored on."""
    lines = read_log(lcfg.audit_log_path)
    entries = parse_lines(lines)
    entry = find_entry(entries, ref, lcfg.audit_log_path)
    if entry.get("action") != "core.undo_point":
        raise ProximoError(f"{ref} is not a capture: it is a {entry.get('action')} row ({entry.get('outcome')})")
    detail = entry.get("detail") or {}
    product = plane or detail.get("plane")
    if not product:
        raise ProximoError(f"capture {ref} names no plane (recorded before captures carried one); give plane=")
    if plane and detail.get("plane") and plane != detail["plane"]:
        raise ProximoError(f"capture {ref} is on plane {detail['plane']}, not {plane}")
    # THE BOX THE CAPTURE NAMES. A registered target's rows carry `remote`; the env box's carry
    # none. A capture of one estate's guest restored onto the other's path (this workspace runs
    # two) is the unsafe direction, so the two must agree (lens 1).
    captured_on, aimed_at = entry.get("remote"), (cfg.name if cfg is not None else None)
    if captured_on != aimed_at:
        raise ProximoError(f"capture {ref} was captured on {captured_on or 'the env box'}, not "
                           f"{aimed_at or 'the env box'}; restore it through the box it names")
    return lines, entries, entry, detail, product, aimed_at


def _task_state(out: dict[str, Any]) -> str | None:
    """None when the write's task landed (or it had none); else which way it went. A task that
    finished and failed landed nothing; one merely submitted, timed out or unpollable may land
    yet, and "failed" for it would send a caller to retry a write that took (lens 2)."""
    task = out.get("task")
    if task is None or task.get("succeeded"):
        return None
    return ("failed" if task.get("finished")
            else "submitted" if not task.get("polls") and not task.get("poll_error")
            else "timed_out" if task.get("timed_out") else "unknown")


def _rollback(ref: str, entry: dict, detail: dict, lines: list[str], lcfg: Any, cfg: wire.Plane | None,
              ledger_cfg: Any, aimed_at: str | None, confirm: bool, wait: int | None,
              product: str = "pve", entries: list[dict] | None = None) -> dict[str, Any]:
    """A snapshot capture (B5 stage 2: a container command run with snapshot=true; a PDM rollback's
    safety snapshot, undo.toml [net]) is restored by
    the vendor's own rollback of THAT snapshot, through `execute` like every write: plan by
    default, armed and tiered to run, receipted, its task's outcome reported as it went. The
    rollback address is rebuilt from the row's own spelling, never taken as written."""
    target, name = entry.get("target") or "", str(detail.get("snapshot") or "")
    # THE TARGET IS THE ROW'S OWN SPELLING. A template matched `/lxc/abc/exec` and the rollback
    # went to `/lxc/abc/...` (lens 3 F3): the bound values must be the vendor's types (an
    # integer vmid) and fill the template back to exactly the target, so a trailing slash or
    # an encoded node in a capture is refused, as the consent exemption refuses them.
    try:
        cmd = engine.resolve(product, "POST", target) if target else None
        bound = engine.coerce_args(cmd, engine.bind(cmd, target)) if cmd is not None else {}
    except ProximoError:
        cmd, bound = None, {}
    if (cmd is None or engine.fill(cmd.path, bound) != target or not cmd.net
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", name)):
        raise ProximoError(f"capture {ref} names no container snapshot this door can roll back")
    method, _, template = cmd.net["rollback"].partition(" ")   # the command's own net, never a literal
    path = engine.fill(template, {**bound, "snapname": name})
    if detail.get("rollback") != f"{method} {path}":
        raise ProximoError(f"capture {ref}'s rollback address does not match its own target; refused")
    row = engine.table().get((product, method, template))
    if row is None or row.gate or row.excluded:
        raise ProximoError("the vendor's guest rollback is not served; nothing rolls back this capture")
    canonical = str(entry.get("entry_hash") or ref)
    shape = re.search(r"/(qemu|lxc)/(\d+)/snapshot/", path)
    guest = (shape.group(1), shape.group(2), name) if shape else None
    harm = "rolling the guest back to it again would discard the work done on it since"
    with _receipted(row, ledger_cfg, path, aimed_at, canonical):
        _refuse_a_second(entries or [], canonical, ref, "rolled back to", harm, path, guest)
    try:
        _verified(lcfg, lines)
    except ProximoError as exc:
        engine._record(ledger_cfg, "core.refuse", row, outcome="refused",
                       detail={"reason": str(exc), "needs": "prove", "restores": ref}, called=path, remote=aimed_at)
        raise
    plane_cfg = cfg if cfg is not None else wire.Plane.from_env(product)
    answer = {"restores": ref, "captured": entry.get("ts"), "snapshot": name, "called_path": rawdoor.echo(path, 160)}
    # THE GUEST COMES BACK AS IT WAS. The vendor's rollback leaves it stopped (live, lab 10-04), so
    # it is started again only if the capture says it was RUNNING when the net was taken. A stopped
    # guest stays stopped; a state that was never read (or a capture from before it was recorded)
    # starts nothing, and the plan says so.
    running = detail.get("running")
    args: dict[str, Any] = {"start": True} if "start" in row.params and running is True else {}
    node = detail.get("node")
    if isinstance(node, str) and "node" in row.params and "node" not in engine.placeholders(row.path):
        args["node"] = node                                  # the caller's hint rides back, as it rode out
    if not confirm:
        planned = engine.plan(row, args, path, cfg=plane_cfg, ledger_cfg=ledger_cfg)
        answer["undo_notes"] = _rollback_notes(row, running, (planned.get("safety_net") or {}).get("taken"))
        return _fit({**planned, "status": "plan", **answer})
    with contextlib.ExitStack() as held:
        with _receipted(row, ledger_cfg, path, aimed_at, canonical):
            held.enter_context(_once_lock(lcfg, canonical))
            # the check again, on the log as it is NOW, and the rollback inside the same lock: two
            # undos racing (each saw a clean log) cannot both roll the guest back
            _refuse_a_second(parse_lines(read_log(lcfg.audit_log_path)), canonical, ref, "rolled back to",
                             harm, path, guest)
        out = engine.execute(row, args, cfg=plane_cfg, path=path, ledger_cfg=ledger_cfg, wait=wait,
                             restores=canonical)
    answer["undo_notes"] = _rollback_notes(row, running, (out.get("undo") or {}).get("captured"))
    state = _task_state(out)
    return {**out, **answer, **({"status": state} if state else {})}


def _rollback_notes(row: engine.Row, running: Any, net_taken: Any) -> list[str]:
    """What the restore's plan says that the plan of an ordinary write would not. The net sentence is
    derived from the SAME verdict the plan carries (`safety_net.taken`), never from the row alone."""
    notes = []
    if "start" in row.params and running is not True:
        notes.append("the guest was stopped when the capture was taken: it stays stopped after this rollback"
                     if running is False else
                     "the guest's run state was not known when the capture was taken: nothing is started, and the "
                     "guest stays stopped if the rollback leaves it so")
    if row.net and net_taken is True:
        notes.append("this rollback takes its own safety snapshot first, like any rollback here (see `also` and "
                     "`safety_net`), so undoing a container command takes a further net")
    elif row.net:
        notes.append("this rollback takes no safety snapshot of its own; `safety_net` says why")
    return notes


def _delete_back(ref: str, entry: dict, entries: list[dict], lines: list[str], lcfg: Any, cfg: wire.Plane | None,
                 ledger_cfg: Any, product: str, published: str, target: str, aimed_at: str | None,
                 confirm: bool, wait: int | None) -> dict[str, Any]:
    """An absent capture (a judged create whose read-back failed, undo.toml) is restored by the
    DELETE the vendor publishes at the same path, through `execute` like every write: plan by
    default, armed and tiered to run, receipted with `restores`, its own capture the record as it
    stands now. ONLY WHEN THE CREATE LANDED: the failed read is not proof the record was absent
    (a read can fail over a record that is there), the create landing is (the vendor refuses a
    duplicate). Its terminal row must say `ok`; anything else deletes nothing."""
    table = engine.table()
    row = table.get((product, "DELETE", published))
    if row is None or row.excluded or row.gate:
        raise ProximoError(f"{product} publishes no DELETE {published} this door serves; nothing puts back the absence "
                           f"captured on receipt {ref}")
    landed = _landed(entries, entry)
    if landed != "ok":
        raise ProximoError(f"the create captured on {ref} did not land ({landed}); a record the vendor did not make "
                           f"is not deleted")
    # ONCE. The capture stays on the chain after its DELETE went; a second `undo` of it would
    # delete whatever was made at that path since (lens, 2026-10-08).
    canonical = str(entry.get("entry_hash") or ref)
    harm = f"a second delete would remove a record made at {target} since"
    with _receipted(row, ledger_cfg, target, aimed_at, canonical):
        _refuse_a_second(entries, canonical, ref, "put back", harm)
    try:
        _verified(lcfg, lines)
    except ProximoError as exc:
        engine._record(ledger_cfg, "core.refuse", row, outcome="refused",
                       detail={"reason": str(exc), "needs": "prove", "restores": ref}, called=target, remote=aimed_at)
        raise
    plane_cfg = cfg if cfg is not None else wire.Plane.from_env(product)
    answer = {"restores": ref, "captured": entry.get("ts"), "removes": target}
    if not confirm:
        return _fit({**engine.plan(row, {}, target, cfg=plane_cfg, ledger_cfg=ledger_cfg), "status": "plan", **answer})
    with contextlib.ExitStack() as held:
        with _receipted(row, ledger_cfg, target, aimed_at, canonical):
            held.enter_context(_once_lock(lcfg, canonical))
            _refuse_a_second(parse_lines(read_log(lcfg.audit_log_path)), canonical, ref, "put back", harm)
        out = engine.execute(row, {}, cfg=plane_cfg, path=target, ledger_cfg=ledger_cfg, wait=wait,
                             restores=canonical)
    state = _task_state(out)
    return {**out, **answer, **({"status": state} if state else {})}


def _same_capture(recorded: Any, canonical: str) -> bool:
    """Whether a `restores` the ledger holds names this capture, however it was spelled: the row's hash
    is the id, and any 8+ character prefix of it (what the doors print is 12) names it. Compared on
    the RESOLVED hash, never on the spelling the caller typed."""
    return isinstance(recorded, str) and len(recorded) >= 8 and canonical.startswith(recorded)


@contextlib.contextmanager
def _receipted(row: engine.Row, ledger_cfg: Any, called: str, remote: str | None, canonical: str):
    """A refusal of the once-guard or the undo lock is an event: it leaves a `core.refuse` row, as every
    other refusal does, naming the capture. (The rollback's own refusals are receipted by `execute`.)"""
    try:
        yield
    except ProximoError as exc:
        engine._record(ledger_cfg, "core.refuse", row, outcome="refused",
                       detail={"reason": str(exc), "needs": "undo", "restores": canonical}, called=called,
                       remote=remote)
        raise


UNDO_LOCK_WAIT = 30          # seconds one restore waits for another restore of the SAME capture


def _attempts(entries: list[dict], canonical: str, guest: tuple[str, str, str] | None = None) -> list[dict[str, Any]]:
    """Every attempt to roll back to this capture, from the ledger, each `done`, `unknown` or `failed`:
    `done` landed (the call answered ok, or its task finished OK), `failed` provably did not (the
    request never reached the vendor, or the vendor answered with a refusal, or its task finished with
    an error), and `unknown` may have: an EXECUTING row with no terminal row after a crash, an error
    after the request went out with no answer (a timeout, a reset), a task that timed out or whose end
    was never seen. `done` and `unknown` close the capture: a second rollback over work that may
    already have been rolled back is the harm this guards.

    An attempt is an `undo` of the capture (its rows carry `restores`) OR a direct rollback to its
    safety snapshot (`guest` = kind, vmid, the snapshot's name: the name is unique and the guest is the
    same whichever plane or node path the operator used). A terminal row closes an attempt only of ITS
    OWN kind: the same `restores` (or none, for a direct one) and the same intent. An error row ends an
    attempt as `failed` only when it says `delivery` was `answered` or `never-sent`; a row without it
    (written before delivery was recorded) closes the attempt as `unknown`."""
    tasks = {(e.get("detail") or {}).get("upid"): e.get("outcome") for e in entries if e.get("action") == "core.task"}
    attempts: list[dict[str, Any]] = []
    direct_path = re.compile(rf"/{guest[0]}/{guest[1]}/snapshot/{re.escape(guest[2])}/rollback$") if guest else None

    def kind(e: dict[str, Any], d: dict[str, Any]) -> tuple[bool, Any]:
        restores = d.get("restores")
        mine = _same_capture(restores, canonical)
        direct = not restores and direct_path is not None and bool(direct_path.search(str(e.get("target") or "")))
        return mine or direct, (restores if mine else None)

    for e in entries:
        d = e.get("detail") or {}
        if e.get("action") not in ("core.execute", "core.error"):
            continue
        counts, restores = kind(e, d)
        if not counts:
            continue
        key = (d.get("intent"), restores)
        if e.get("action") == "core.execute" and e.get("outcome") == EXECUTING:
            attempts.append({"ts": e.get("ts"), "key": key, "state": "unknown", "upid": None, "closed": False})
            continue
        open_ = next((a for a in reversed(attempts) if a["key"] == key and not a["closed"]), None)
        if open_ is None:
            continue
        if e.get("action") == "core.error":
            provably = d.get("delivery") in ("answered", "never-sent")
            open_.update(state="failed" if provably else "unknown", closed=True)
        elif e.get("outcome") == "ok":
            open_.update(state="done", closed=True)
        elif e.get("outcome") == "submitted":
            open_.update(upid=d.get("upid"), closed=True)
    for a in attempts:
        if a["upid"] is not None:
            outcome = tasks.get(a["upid"])
            a["state"] = "done" if outcome == "finished" else "failed" if outcome == "failed" else "unknown"
    return attempts


def _refuse_a_second(entries: list[dict], canonical: str, ref: str, verb: str, harm: str,
                     target: str | None = None, guest: tuple[str, str, str] | None = None) -> None:
    """Refuse when this capture was restored, or may have been. `unknown` reads as done (the safe
    side) and the refusal says what the operator can actually do: nothing in the ledger can reopen the
    capture, so the way on is a direct rollback to the safety snapshot, which is counted too."""
    attempts = _attempts(entries, canonical, guest)
    done = next((a for a in attempts if a["state"] == "done"), None)
    if done is not None:
        raise ProximoError(f"capture {ref} was already {verb} on {done['ts']}; {harm}")
    unknown = next((a for a in attempts if a["state"] == "unknown"), None)
    if unknown is not None:
        raise ProximoError(
            f"a restore of capture {ref} was started on {unknown['ts']} and the ledger does not show how it "
            f"ended (the process may have died, or its task was not seen to finish), so it may have landed: "
            f"{harm}. `undo` stays closed for this capture. Read the guest and the vendor's task log"
            + (f" (task {unknown['upid']})" if unknown["upid"] else "")
            + (f"; if the rollback did not land, roll back yourself with proximo_call POST {target} (it takes its "
               "own safety snapshot first, and a rollback to this capture's snapshot closes the capture too)"
               if target else ""))


@contextlib.contextmanager
def _once_lock(lcfg: Any, canonical: str):
    """An exclusive lock for ONE capture, held across the once-check AND the rollback it guards, so
    two undos of it racing (no consent, or advisory consent) cannot both pass the check and both roll
    the guest back, while undos of other captures go on. The lock files live in a directory beside
    the ledger (refused if it is a symlink, as the rate reservation's is); the wait is bounded, and a
    lock that cannot be taken in time refuses with a sentence."""
    if not re.fullmatch(r"[0-9a-f]{8,64}", canonical):
        raise ProximoError("the capture's id is not a ledger hash; nothing is restored")
    directory = os.path.join(os.path.dirname(lcfg.audit_log_path) or ".", ".proximo-undo")
    try:
        if os.path.islink(directory):
            raise OSError("refusing to use a symlinked undo lock directory")
        os.makedirs(directory, mode=0o700, exist_ok=True)
        st = os.lstat(directory)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
            raise OSError("refusing to use an undo lock directory that is not ours alone")
        fd = os.open(os.path.join(directory, f"{canonical}.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        raise ProximoError(f"the undo lock beside the ledger could not be opened ({type(exc).__name__}); "
                           "nothing is restored") from exc
    try:
        deadline = time.monotonic() + UNDO_LOCK_WAIT
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ProximoError("another restore of this capture is still running; nothing was done. "
                                       "Try again when it has finished") from None
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


def _landed(entries: list[dict], capture: dict) -> str:
    """How the mutation captured on `capture` ended, in the ledger's own words: the outcome of the
    terminal row (`core.execute` ok or submitted, `core.error`) that NAMES this capture under
    `capture`, or why there is none. Never paired by intent: an intent is the path alone, and the
    first version read a later write at the same path as this create's landing after the vendor
    had refused the create (lens, 2026-10-08). A row without the name is not a landing."""
    ref = str(capture.get("entry_hash", ""))[:12]
    for e in entries:
        if (e.get("action") in ("core.execute", "core.error") and e.get("outcome") != EXECUTING
                and (e.get("detail") or {}).get("capture") == ref):
            return str(e.get("outcome"))
    return "no terminal row names this capture: not seen to finish"


def _verified(lcfg: Any, lines: list[str]) -> None:
    """The LIVE chain under the ledger's own key, over the lines already read. `verify_chain`
    walks an archive by each row's declared algorithm, which is the attacker's to declare; a
    keyed ledger rewritten as an unkeyed chain passed it and a forged capture reached the wire
    (lens 1). A box CONFIGURED keyed whose key is gone is refused outright: with no key the
    same forgery read as a clean unkeyed chain (lens 2)."""
    try:
        key = ledger_key(lcfg)
    except (OSError, ValueError) as exc:
        raise ProximoError(f"the audit key could not be read ({type(exc).__name__}); the chain cannot be judged "
                           f"and nothing is restored") from exc
    if key is None and any(line.strip() for line in lines):
        raise ProximoError("the ledger is configured keyed and no key is readable (gone, or not yet minted); a chain "
                           "that cannot be judged under its key is not evidence and nothing is restored")
    v = verify_lines(lines, key)
    if not v.ok:
        raise ProximoError(f"the ledger's chain is broken at {v.broken_at} ({v.reason}); a before-state on a "
                           f"broken chain is not evidence and nothing is restored")


def _body(row: engine.Row) -> set[str]:
    """The parameters a write takes in its body: what it publishes less the path's own."""
    return set(row.params) - set(engine.placeholders(row.path))


def same_write(post: engine.Row) -> engine.Row | None:
    """The PUT at a POST's path when the vendor's schema says they are one write: every
    parameter the PUT publishes, the POST publishes too (QEMU's async config POST carries the
    PUT's whole body plus `background_delay`). Where the PUT's body is not inside the POST's,
    the two are different operations and nothing is restored through the PUT."""
    put = engine.table().get((post.product, "PUT", post.path))
    if put is None or put.excluded or put.gate:
        return None
    body = _body(put)
    return put if body and body <= _body(post) else None


def _delete_shape(put: engine.Row) -> str | None:
    """How this write takes the keys to remove: 'string' (a comma list), 'array', or None when
    it publishes no list (a boolean `delete` is a flag, never a list)."""
    kind = (put.params.get("delete") or {}).get("type")
    return kind if kind in ("string", "array") else None


def _withheld(value: Any) -> bool:
    return bool(_REDACTED.search(json.dumps(value, default=str)))


def _args(put: engine.Row, before: dict, current: dict, added_by_mutation: set[str],
          withheld_now: AbstractSet[str] = frozenset()) -> dict[str, Any]:
    """The write's arguments: every captured key the write publishes, whose value the receipt
    did not withhold, that differs from the record now (compared as strings, PLAN's rule); the
    keys the captured mutation added, on the delete list; the lock from the record now; a
    required parameter carried at its captured value so the write is whole. And the honest
    remainder: `skipped` says why a key is not written, `differs_unwritten` which of those
    differ from the record now, so a noop never reads as "nothing changed"."""
    args: dict[str, Any] = {}
    skipped: dict[str, str] = {}
    for key, value in before.items():
        if key in _CONTROLS:
            if key != "digest":
                skipped[key] = "a write control in the capture, not state"
        elif value is None:
            skipped[key] = "the capture holds no value for it"
        elif _withheld(value):
            skipped[key] = WITHHELD
        elif not engine._published(put, key):
            skipped[key] = UNPUBLISHED
        elif key not in current or str(current[key]) != str(value):
            args[key] = value
    restored = sorted(args)
    for key, spec in put.params.items():
        if (not spec.get("optional") and key not in args and key not in engine.placeholders(put.path)
                and key in before and not _withheld(before[key])):
            args[key] = before[key]
    shape = _delete_shape(put)
    deleted: list[str] = []
    for key in current:
        if key in _CONTROLS or key in before:
            continue
        if not engine._published(put, key):
            skipped[key] = f"added since the capture; {UNPUBLISHED}"
        elif key not in added_by_mutation:
            skipped[key] = NOT_BY_THE_MUTATION
        elif shape is None:
            skipped[key] = "added since the capture; the write publishes no delete list"
        else:
            deleted.append(key)
    # A CREDENTIAL THE RECORD HOLDS NOW is stripped from the read and named in `withheld`; the
    # diff never saw it, so a mutation that only set one answered "nothing differs" (lens 2).
    # It is never removed (a delete of a credential is a write this door does not guess at)
    # and never silent.
    for key in sorted(withheld_now):
        if key not in before and key not in skipped:
            skipped[key] = "withheld by the read now (a credential the mutation set); not removed"
    deleted.sort()
    if deleted:
        args["delete"] = deleted if shape == "array" else ",".join(deleted)
    if "digest" in put.params and "digest" in current:
        args["digest"] = current["digest"]
    # (a withheld name is never in `current`, so it lists itself: changed or not cannot be told)
    differs = sorted(k for k in skipped if k not in _CONTROLS
                     and (k not in before or k not in current or str(before[k]) != str(current[k])))
    return {"args": args, "restored": restored, "deleted": deleted, "skipped": skipped, "differs_unwritten": differs}
