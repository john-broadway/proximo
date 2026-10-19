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

import json
import re
from collections.abc import Set as AbstractSet
from typing import Any

from proximo.core import engine, spine, wire
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
_REDACTED = re.compile(r"\[redacted( sha256:[0-9a-f]{12} len:\d+)?\]")
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
    lcfg = ledger_cfg or LedgerConfig.from_env()
    # ONE READ. The bytes are read once and verified, found in and paired within; three separate
    # reads of a writable file let a swap between them put a forged capture on the wire (lens 2).
    lines, entries, entry, detail, product, aimed_at = _capture(ref, plane, cfg, lcfg)
    if "snapshot" in detail:
        return _rollback(ref, entry, detail, lines, lcfg, cfg, ledger_cfg, aimed_at, confirm, wait)
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
    env = engine.execute(twin, {}, cfg=plane_cfg, path=target, ledger_cfg=ledger_cfg, fields="all")
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
    answer: dict[str, Any] = {"restores": ref, "captured": entry.get("ts"), "skipped": d["skipped"],
                              **({"untrusted": True, "channel": twin.channel} if untrusted else {})}
    if not d["restored"] and not d["deleted"]:
        return {"status": "noop", **answer, "why": "no published key differs from the capture; nothing to write",
                "differs_unwritten": d["differs_unwritten"]}
    if not confirm:                           # the restore's own labels last: the twin's, not the PUT row's
        return {**engine.plan(put, d["args"], target, cfg=plane_cfg, ledger_cfg=ledger_cfg, env=env),
                "status": "plan", **answer}
    out = engine.execute(put, d["args"], cfg=plane_cfg, path=target, ledger_cfg=ledger_cfg, wait=wait, restores=ref)
    # THE CLAIM FOLLOWS THE TASK (lens 1), AND SAYS WHICH WAY IT WENT (lens 2): a task that
    # finished and failed landed nothing; one merely submitted, timed out or unpollable may
    # land yet, and "failed" for it would send a caller to retry a write that took.
    state = _task_state(out)
    if state is not None:
        return {**out, **answer, "status": state, "restored": [], "deleted": [],
                "attempted": {"restored": d["restored"], "deleted": d["deleted"]}}
    return {**out, **answer, "restored": d["restored"], "deleted": d["deleted"]}


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
              ledger_cfg: Any, aimed_at: str | None, confirm: bool, wait: int | None) -> dict[str, Any]:
    """A snapshot capture (B5 stage 2: a container command run with snapshot=true) is restored by
    the vendor's own rollback of THAT snapshot, through `execute` like every write: plan by
    default, armed and tiered to run, receipted, its task's outcome reported as it went. The
    rollback address is rebuilt from the row's own spelling, never taken as written."""
    target, name = entry.get("target") or "", str(detail.get("snapshot") or "")
    m = re.fullmatch(r"(/nodes/[^/]+/lxc/\d+)/(?:exec|psql)", target)
    if m is None or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,39}", name):
        raise ProximoError(f"capture {ref} names no container snapshot this door can roll back")
    path = f"{m.group(1)}/snapshot/{name}/rollback"
    if detail.get("rollback") != f"POST {path}":
        raise ProximoError(f"capture {ref}'s rollback address does not match its own target; refused")
    row = engine.table().get(("pve", "POST", "/nodes/{node}/lxc/{vmid}/snapshot/{snapname}/rollback"))
    if row is None or row.gate or row.excluded:
        raise ProximoError("the vendor's container rollback is not served; nothing rolls back this capture")
    try:
        _verified(lcfg, lines)
    except ProximoError as exc:
        engine._record(ledger_cfg, "core.refuse", row, outcome="refused",
                       detail={"reason": str(exc), "needs": "prove", "restores": ref}, called=path, remote=aimed_at)
        raise
    plane_cfg = cfg if cfg is not None else wire.Plane.from_env("pve")
    answer = {"restores": ref, "captured": entry.get("ts"), "snapshot": name, "called_path": path}
    # THE CONTAINER COMES BACK UP. The vendor's rollback leaves it stopped (live, lab 10-04), and
    # it was running when the snapshot was taken: `pct exec` needs a running container.
    args = {"start": True} if "start" in row.params else {}
    if not confirm:
        return {**engine.plan(row, args, path, cfg=plane_cfg, ledger_cfg=ledger_cfg), "status": "plan", **answer}
    out = engine.execute(row, args, cfg=plane_cfg, path=path, ledger_cfg=ledger_cfg, wait=wait, restores=ref)
    state = _task_state(out)
    return {**out, **answer, **({"status": state} if state else {})}


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
    done = next((e for e in entries if e.get("action") == "core.execute" and e.get("outcome") in ("ok", "submitted")
                 and (e.get("detail") or {}).get("restores") == ref), None)
    if done is not None:
        raise ProximoError(f"capture {ref} was already put back on {done.get('ts')} ({done.get('outcome')}); a second "
                           f"delete would remove a record made at {target} since")
    try:
        _verified(lcfg, lines)
    except ProximoError as exc:
        engine._record(ledger_cfg, "core.refuse", row, outcome="refused",
                       detail={"reason": str(exc), "needs": "prove", "restores": ref}, called=target, remote=aimed_at)
        raise
    plane_cfg = cfg if cfg is not None else wire.Plane.from_env(product)
    answer = {"restores": ref, "captured": entry.get("ts"), "removes": target}
    if not confirm:
        return {**engine.plan(row, {}, target, cfg=plane_cfg, ledger_cfg=ledger_cfg), "status": "plan", **answer}
    out = engine.execute(row, {}, cfg=plane_cfg, path=target, ledger_cfg=ledger_cfg, wait=wait, restores=ref)
    state = _task_state(out)
    return {**out, **answer, **({"status": state} if state else {})}


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
