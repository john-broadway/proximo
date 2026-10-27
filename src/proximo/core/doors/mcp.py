"""The MCP door: a handful of tools over the engine, for a model that speaks MCP.

The shell door proved the engine needs no model. This door proves a model needs no wrappers:
six tools reach every address the four products publish, governed by the same `resolve`,
`govern` and `execute`, receipted in the same ledger, from the same config.

    proximo_find     search the published addresses (path, method, parameter names)
    proximo_plan     the verdict, the published schema and the target as it stands; mutates nothing
    proximo_read     run a published GET
    proximo_call     run a governed mutation: armed AND tiered, or refused
    audit_entries    read the PROVE chain back
    audit_verify     walk the chain and report the first break

`mcp` is an OPTIONAL extra of this package and is imported only inside `build_server` and
`main`: the engine, the wire, the ledger, the arm predicate and the shell door never see it,
and `tests/test_closure.py` asserts that importing this module adds nothing to what `import
httpx` alone loads. A missing SDK is a one-line error naming the extra, never a traceback.

WHAT GOVERNS A `proximo_call` HERE: ARM and TIER in `govern`, then CONTAIN, FORBID and
CONSENT (`proximo.core.spine`, the pure half, so `proximo_plan` reports every one of them and
the consent id with its grant path), then in `execute` the consent consume and
the RATE reservation, the UNDO read-back, an `executing` row before the wire and its terminal
partner after. That is every pillar the 0.44 server ran at its seams, for every published
address rather than for the wrappers that remembered to call them, and ARM for every mutation
where 0.44 armed three shell tools. `records/tiers.toml` authors the ratified grant (150 addresses, each
with the sentence that justifies it; the file is the hand-authored record); every other
mutating address is refused even when armed. TAINT keys on addresses (`taint.toml`: the mail
quarantine, tracker and log reads and their kin): this door marks the session before serving
one, fences the data when asked, and its mutations honour the taint walls; the guest-exec and
console addresses the name set marks are `gate`d rows the engine refuses first. Every row says
who asked (`proximo.core.principal`: the name tag, or the badge a network face verified), and
`doors/mcphttp.py` serves these same six tools over the network. Multi-target: where
`PROXIMO_TARGETS` is set, plan, read and call take `target` (`proximo.core.registry`), and the box
it names is the Plane the engine governs. An argument a tool does not declare is refused.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Literal

import httpx

from proximo import __version__
from proximo.core import anchor, apitree, engine, prompts, rawdoor, registry, search, wire
from proximo.core import diagnose as diagnose_mod
from proximo.core import undo as restore_mod
from proximo.core.doors import BANNER
from proximo.core.errors import ProximoError
from proximo.core.ledger import (
    AuditLedger,
    LedgerConfig,
    ledger_key,
    looks_like_head,
    read_entries,
    read_log,
    verify_chain,
    verify_lines,
)
from proximo.core.secretfile import safe_exception_text

#: The four planes, as the schema says them: a model picks one; a word that is none of them is refused
#: by name (the bar-3 drive of 2026-10-18 sent "default" when the schema said only `str`).
Plane = Literal["pve", "pbs", "pmg", "pdm"]

_HELP = "the MCP door needs the mcp SDK: pip install proximo-proxmox"


def _execute(row: engine.Row, args: dict[str, Any], path: str,
             cfg: wire.Plane | None = None, fields: str | None = None,
             since: str | None = None, wait: int | None = None,
             asked: str | None = None) -> dict[str, Any]:
    """DECIDE BEFORE CONFIGURING. `execute` governs first and builds the plane's client from
    env only after the verdict, so an unarmed mutation on an unconfigured box is refused as
    "not armed" and receipted, never as a missing env var. The env-var error, when it does
    come, is rephrased in the door's words: a RuntimeError inside a tool body is what the 2.x
    SDK sanitizes to a bare tool name."""
    try:
        return engine.execute(row, args, path=path, cfg=cfg, fields=fields, since=since, wait=wait, asked=asked)
    except ProximoError:
        raise
    except (httpx.HTTPStatusError, httpx.TransportError) as e:
        # THE VENDOR'S ERROR CARRIES THE ESTATE'S ADDRESS. httpx builds its message from the
        # request URL, so a 403 or a refused connection names host, port and path. On mcp 1.x
        # that text reached the client verbatim; on 2.x the SDK replaced it with a bare tool
        # name. Neither is the door's words: strip the locators and keep the reason, as the
        # shell door does (lens, 2026-09-22).
        raise ProximoError(f"the vendor did not complete the call: {safe_exception_text(e)}") from e
    except RuntimeError as e:
        raise ProximoError(f"{row.product} is not configured on this Proximo ({e})") from e


#: How many addresses one find may return, whatever `limit` says: each carries its parameter names
#: and a sentence, and a find of 'list' was 505 KB at limit=10**6.
MAX_FIND = 25


def _shape(found: dict[str, Any], cap: rawdoor.Cap | None = None,
           extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """A find answer a small model can hold. Each match keeps its address, method, access and tier;
    the authored sentence is cut to its first sentence (a plan carries it whole) and the parameter
    names to the first six with a count (`proximo_plan fields=` lists the rest). Then matches
    leave from the end until the whole answer is under the cap, and the answer says so."""
    matches = []
    for m in found.get("matches", []):
        # CAPABILITY BY AVAILABILITY: only an address this door will serve (published, not gated, held or
        # excluded) is offered; a held row or a console tunnel in a find is a path no one can use
        if not engine._suggestible(m["plane"], m["method"], m["path"]):  # noqa: SLF001
            continue
        m = {k: v for k, v in m.items() if v not in (None, [], "")}
        why = m.get("why")
        if isinstance(why, str) and len(why) > 100:
            first = why.split(". ", 1)[0]
            m["why"] = (first if len(first) <= 100 else first[:97].rstrip()) + "..."
        params = m.get("params") or []
        if len(params) > 6:
            m["params"], m["params_more"] = params[:6], len(params) - 6
        matches.append(m)
    out = {**found, "matches": matches, **(extra or {})}       # `extra` is part of the answer: measured with it
    cap = cap or rawdoor.answer_cap()

    def fits_with(extra: dict[str, Any]) -> bool:
        body = json.dumps({**out, **extra}, separators=(",", ":"), default=str)
        return rawdoor.fits(len(body.encode()), body, cap=cap)

    if fits_with({}):
        return out
    # The trailer (`truncated`, `returned`, `next`, a junk-cap note) is part of the answer, so it is
    # measured with the matches that stay, never added after the fit.
    trailer = rawdoor.note_problems({"truncated": True, "returned": 99, "next": _FIND_NEXT})
    while len(out["matches"]) > 1 and not fits_with(trailer):
        out["matches"] = out["matches"][:-1]
    return {**out, **trailer, "returned": len(out["matches"])}


_FIND_NEXT = "narrow: add words or a plane"


def find(query: str, plane: Plane | None = None, limit: int = 5) -> dict[str, Any]:
    """The operator's words to a published address: verbs pick the method, words score by where
    they land (path segment, the vendor's description, a parameter), a handful by default so a
    4K window is never handed a list it cannot hold. `proximo.core.search` says how, and why."""
    if not query or not query.strip():
        raise ProximoError("give proximo_find one or more words to look for")
    if limit < 0:
        raise ProximoError(f"limit must be 0 or more, not {limit}")
    if plane is not None and plane not in apitree.PRODUCTS:
        raise ProximoError(f"unknown plane {rawdoor.quote(plane)}; known planes: {', '.join(apitree.PRODUCTS)}")
    note = {"limit_note": f"limit <= {MAX_FIND}"} if limit > MAX_FIND else {}
    return _shape(search.find(query, plane=plane, limit=min(limit, MAX_FIND)), extra=note)


def words_to_address(plane: str, method: str, words: list[str]) -> dict[str, Any]:
    """What plan resolves words through: `method` filters, it is never a word, and every word must
    be a segment of the path itself (search's strict). One place, so the whole-table sweep in
    tests/test_search.py drives exactly what plan acts on."""
    return search.find(" ".join(words), plane=plane, strict=True, method=method)


def _tokens_of(path: str) -> set[str]:
    return {t for seg in path.strip("/").split("/") if not seg.startswith("{") for t in search.tokens(seg)}


def _resolve_words(tool: str, plane: str, method: str, path: str) -> tuple[str, dict[str, Any] | None]:
    """A PATH STARTS WITH A SLASH; ANYTHING ELSE IS WORDS TO FIND. Plan and read both take words, so
    one place says how: (the path, None) when the argument was a path; (the address, the find answer)
    when the words named exactly one; ("", the find answer) when several matched or the one is only
    a choice; a refusal when none did. The words never reach the spelling gate as a path.

    A READ FAILS CLOSED ON A VERB FOR A MUTATION: "delete cluster nextid" must not come back as a GET
    that succeeded. But a verb that is a SEGMENT of a published GET is part of its name ("show apt
    update" is `GET /nodes/{node}/apt/update`), so the refusal stands only when no ungated GET carries
    every such verb in its own path."""
    rawdoor.check_input("path" if path.startswith("/") else "words", path)
    if path.startswith("/"):
        return path, None
    words = [w for w in path.split() if w and w.upper() != method]
    if not words:
        raise ProximoError(f"give {tool} a /path or words to find")
    asks = sorted(search.verb_methods(words) - {"GET"}) if method == "GET" and tool == "proximo_read" else []
    if asks:
        verbs = {search.stem(w.lower()) for w in words if search.verb_methods([w]) - {"GET"}}
        wide = search.find(" ".join(words), plane=plane, strict=True, method="GET", limit=100)["matches"]
        named = [m for m in wide if verbs <= _tokens_of(m["path"]) and engine._suggestible(plane, "GET", m["path"])]
        if not named:
            # FAIL CLOSED: "stop vm 100" must never come back as a read that succeeded.
            raise ProximoError(f"{rawdoor.quote(path)} asks to {asks[0]} something, and proximo_read only "
                               "reads: proximo_plan shows what it would do, proximo_call runs it")
        found = {"matches": named, "total": len(named), "truncated": False}
    else:
        found = words_to_address(plane, method, words)
    hits = found["matches"]
    if not hits:
        raise ProximoError(f"no published address matched {rawdoor.quote(path)} (a path starts with '/'; "
                           f"anything else is words to find: try fewer or different words)")
    if len(hits) > 1 or found.get("total", 1) > 1 or "choose" in found:
        return "", _shape(found)
    return hits[0]["path"], _shape(found)


def plan(plane: Plane, method: str, path: str, args: dict[str, Any] | None = None,
         cfg: wire.Plane | None = None, fields: str | None = None) -> dict[str, Any]:
    """The governed decision and the published schema. Answers on a box that holds no credential.
    `cfg` is the Plane of a registry target (`registry.plane`), or None for the env box.
    A PATH STARTS WITH A SLASH; ANYTHING ELSE IS WORDS TO FIND. One match is planned as if its
    address had been named; several come back as the find answer to pick from; none is the
    same refusal find gives. The words never reach the spelling gate as a path."""
    path, found = _resolve_words("proximo_plan", plane, method, path)
    if not path:
        return found or {}
    return engine.plan(engine.resolve(plane, method, path), args, path, cfg=cfg, detail=fields)


def read(plane: Plane, path: str, args: dict[str, Any] | None = None,
         cfg: wire.Plane | None = None, fields: str | None = None,
         since: str | None = None, wait: int | None = None, diagnose: bool = False,
         params: dict[str, Any] | None = None) -> dict[str, Any]:
    """Run a published GET. `args` is the one argument name on every tool; `params` is the old name
    for it, still accepted so no client breaks, and DEPRECATED. Giving both with something in each
    is refused: which one the caller meant is not ours to guess (an empty one beside the other is
    nothing, and is let through: a model fills in `params: {}` unasked).

    A PATH STARTS WITH A SLASH; ANYTHING ELSE IS WORDS TO FIND, as in `proximo_plan`: one match that
    can run is read; several come back as the find answer to pick from; one that still has holes
    (`{node}`, `{vmid}`) comes back with what to fill in, and nothing is dialled."""
    if args and params:
        raise ProximoError("give args or params, not both: params is the old name for args")
    args = args or params
    asked = path if not path.startswith("/") else None
    # WORDS THAT CONTAIN A VERB FOR A MUTATION ("destroy tape media") can reach a published GET whose own
    # name holds the verb. That is a read, and the answer says so, plainly, so a model does not report
    # a deletion that never happened.
    said_read_only = asked is not None and bool(search.verb_methods(asked.split()) - {"GET"})
    note = {"read_only": "read only; nothing was changed"} if said_read_only else {}
    path, found = _resolve_words("proximo_read", plane, "GET", path)
    if found is not None and (not path or "{" in path):
        holes = engine.placeholders(path) if path else []
        return {**found, **note} if not holes else {**found, **note, "next": (
            f"{path} needs {', '.join('{' + h + '}' for h in holes)}: put real values in and call "
            f"proximo_read with that path")}
    if diagnose:
        # DIAGNOSE (B3): a read's mode, like since= and wait=; the subject is the path, alone.
        # Every probe is its own governed read inside, so a vendor failure is a section, not an
        # error here; the one error left is the plane's own, said in the door's words.
        if args or fields is not None or since is not None or wait is not None:
            raise ProximoError("diagnose takes the path alone: no args, fields, since or wait")
        try:
            return {**diagnose_mod.run(plane, path, cfg=cfg), **note}
        except RuntimeError as e:
            raise ProximoError(f"{plane} is not configured on this Proximo ({e})") from e
    row = engine.resolve(plane, "GET", path)
    return {**_execute(row, dict(args or {}), path, cfg, fields=fields, since=since, wait=wait, asked=asked), **note}


def call(plane: Plane, method: str, path: str, args: dict[str, Any] | None = None,
         confirm: bool = False, cfg: wire.Plane | None = None, wait: int | None = None) -> dict[str, Any]:
    """PLAN BY DEFAULT. Without `confirm` this returns the governed plan and mutates nothing,
    the ritual every 0.44 mutation carries; with it the engine runs the call. A one-shot
    confirm cannot skip the preview: `execute` writes the same preview into the `executing`
    row before the wire, so the plan is on the chain whether or not the caller read it."""
    if method.lower() == "undo":
        # THE RESTORE (B2), in the shell door's spelling: the id a call returned is the path.
        # One shape across doors, and no seventh tool for the 4K window to pay for. The capture
        # is the argument; args handed alongside were silently ignored (lens 1), now refused.
        if args:
            raise ProximoError("undo takes no arguments: the capture is the argument; drop args")
        return undo(path, plane, confirm, cfg=cfg, wait=wait)
    row = engine.resolve(plane, method, path)
    if row.access == engine.READ:
        raise ProximoError(f"{row.address} is a read; use proximo_read")
    if not confirm:
        return {"status": "plan", **engine.plan(row, args, path, cfg=cfg)}
    return _execute(row, dict(args or {}), path, cfg, wait=wait)


def undo(id: str, plane: Plane | None = None, confirm: bool = False, cfg: wire.Plane | None = None,
         wait: int | None = None) -> dict[str, Any]:
    """PLAN BY DEFAULT, like `call`: the write that puts a capture back, its plan without
    `confirm`, its execution with it (`proximo.core.undo`). The vendor's errors come out in the
    door's words, as `_execute` gives them."""
    try:
        return restore_mod.restore(id, plane=plane, cfg=cfg, confirm=confirm, wait=wait)
    except ProximoError:
        raise
    except (httpx.HTTPStatusError, httpx.TransportError) as e:
        raise ProximoError(f"the vendor did not complete the call: {safe_exception_text(e)}") from e
    except RuntimeError as e:
        raise ProximoError(f"{plane or 'the plane'} is not configured on this Proximo ({e})") from e


def audit_entries(limit: int = 20, target: str | None = None, action: str | None = None,
                  mutations_only: bool = False) -> dict[str, Any]:
    out = read_entries(limit=limit, target=target, action=action, mutations_only=mutations_only)
    out.pop("path", None)               # where the ledger lives is the operator's, not the model's
    out.pop("source", None)
    rest = {k: v for k, v in out.items() if k != "entries"}
    over = rawdoor.bounded(out["entries"], rawdoor.answer_cap().minus(*rawdoor.spent(rest)))
    if over is not None and "returned" in over:
        # The ledger rows are the largest thing the door hands a model (20 rows ran 10 KB): cut by
        # rows under the same cap as every read, newest first, and say how to ask for less.
        out.update(entries=over["data"], returned=over["returned"], truncated=True,
                   next=f"{over['returned']} of {len(out['entries'])} rows fit: ask for fewer with limit=, "
                        "or narrow with target=, action= or mutations_only=true")
        rawdoor.note_problems(out)
    return out


def audit_verify(expected_head: str | None = None, path: str | None = None) -> dict[str, Any]:
    """A READ. `open_ledger` is the WRITER's door: on a box with no ledger yet it mints the HMAC
    key as a side effect, which is the box's signing identity for every future row -- created by
    a tool whose hint promised it touched nothing (lens, 2026-09-22). Verify opens what exists
    with the key that exists, and creates neither.

    `path` names a ROTATION ARCHIVE beside the live log (a bare file name, never a path): the
    live chain is checked under one algorithm, an archive row by row under the algorithm each
    row carries, because a sealed archive can legitimately change algorithm at its seam and the
    live log never can."""
    cfg = LedgerConfig.from_env()
    key = ledger_key(cfg)
    if path is not None:
        rawdoor.check_input("name", path)
        if os.path.basename(path) != path or path in ("", ".", ".."):
            raise ProximoError("path must be the bare name of an archive beside the ledger, "
                               f"not {rawdoor.quote(path)}")
        target = os.path.join(os.path.dirname(cfg.audit_log_path) or ".", path)
        if not os.path.isfile(target):
            raise ProximoError(f"no archive named {rawdoor.quote(path)} beside the ledger")
        v = verify_chain(target, key)
        return {"ok": v.ok, "entries": v.entries, "broken_at": v.broken_at, "reason": v.reason,
                "head": v.head, "segments": [list(s) for s in v.segments], "archive": path}
    pin, pinned = _pinned_head(expected_head)
    anchored = anchor.from_env()
    exists = os.path.exists(cfg.audit_log_path)
    if not exists and pin is None and anchored is None:
        return {"ok": True, "entries": 0, "broken_at": None, "reason": None, "head": None, "keyed": None,
                "note": f"no ledger at {cfg.audit_log_path}: nothing has been recorded here, or "
                        "PROXIMO_AUDIT_LOG points elsewhere"}
    if exists:
        ledger = AuditLedger(cfg.audit_log_path, key=key)
        v = ledger.verify(pin, None) if pinned == "argument" else ledger.verify(None, pin)
        head, keyed = ledger.head(), ledger.keyed
    else:   # a pin names a ledger that must exist: an absent file is a wipe, not "nothing happened"
        v = verify_lines([], key, pin, None) if pinned == "argument" else verify_lines([], key, None, pin)
        head, keyed = None, None
    out = {"ok": v.ok, "entries": v.entries, "broken_at": v.broken_at, "reason": v.reason,
           "head": head, "keyed": keyed, "pinned": pinned,
           # Only an exact head speaks for the tail; a held row or no pin cannot see a row forged after.
           "tail_verified": v.ok and pinned == "argument"}
    if anchored is not None:
        # The anchored head is a row the chain must still hold, like the env pin: the head moves on
        # every row. It speaks for the tail only when it IS the head. Anything that stops the anchor
        # proving (unreachable, empty, misconfigured, diverged) is a refusal, never a pass.
        answer = anchored.check(read_log(cfg.audit_log_path) if exists else [], key)
        out["anchor"] = {k: x for k, x in answer.items() if k not in ("ok", "reason")}
        if not answer["ok"]:
            out["ok"], out["tail_verified"] = False, False
            out["reason"] = out["reason"] or f"anchor {answer['state']}: {answer['reason']}"
        elif answer.get("head_is_chain_head") and v.ok:
            out["tail_verified"] = True
    return out


def _pinned_head(expected_head: str | None) -> tuple[str | None, str | None]:
    """(the pin, where it came from). The argument wins and is the exact head (a fresh off-box
    copy asks about the tail); with none, PROXIMO_AUDIT_EXPECTED_HEAD, a standing value, is a row
    the chain must still hold, since the head moves on every row. Normalised, then shape-checked,
    so a typo is a caller error and never reads as a cut tail; an archive (`path=`) is not the
    live chain and takes no pin."""
    if expected_head is not None:
        pin, source, name = expected_head, "argument", "expected_head"
    elif os.environ.get("PROXIMO_AUDIT_EXPECTED_HEAD", "").strip():
        pin, source, name = os.environ["PROXIMO_AUDIT_EXPECTED_HEAD"], "env", "PROXIMO_AUDIT_EXPECTED_HEAD"
    else:
        return None, None
    pin = pin.strip().lower()
    if not looks_like_head(pin):
        raise ProximoError(f"{name} must be a 64-char hex head() value")   # the value is not echoed
    return pin, source


def _targets_advertised() -> bool:
    """Whether the door offers `target`: a registry is configured, or one is set and cannot be read
    (then the selector stays, so a call naming a target fails loudly with the registry's own error,
    and the operator is warned now rather than at the first call)."""
    try:
        return bool(registry.load_registry())
    except ProximoError as e:
        print(f"proximo: {e}; the target selector stays advertised and a call naming a "
              "target will refuse with this error", file=sys.stderr)
        return True


def build_server(name: str = "proximo") -> Any:
    """The MCP server with the six tools registered. Imports the SDK here and nowhere else."""
    try:
        from proximo.core.mcpcompat import forbid_undeclared, make_server, slim_schemas, tool_annotations_kwargs
    except ImportError as e:
        raise ProximoError(_HELP) from e
    server = make_server(name, __version__)
    ro = tool_annotations_kwargs(read_only=True)
    rw = tool_annotations_kwargs(read_only=False)

    # readOnlyHint is what a client's permission policy reads. find/plan/audit touch the
    # local table and ledger only; read runs a GET; call is the ONE tool that can mutate.
    server.tool(name="proximo_find", description=(
        "READ-ONLY: find API addresses by plain words ('list datastores'). A verb picks the method. "
        "Returns access and blast-radius tier. 5 by default."), **ro)(find)
    # `target` names a box PROXIMO_TARGETS registers (B16): resolved to its Plane here, so the
    # engine governs it with its own arm pair, forbid and rate, and every receipt names it. It is
    # ADVERTISED only where a registry is configured (0.44's rule, door._slim_registry_schemas):
    # a one-estate box pays nothing in the 4K window for a selector with nothing to select.
    if _targets_advertised():
        # One name per tool, one signature per branch (the SDK titles the schema by __name__).
        def _plan(  # pyright: ignore[reportRedeclaration]
                  plane: Plane, method: str, path: str, args: dict[str, Any] | None = None,
                  fields: str | None = None, target: str = "") -> dict[str, Any]:
            return plan(plane, method, path, args, cfg=registry.plane(plane, target or None), fields=fields)

        def _read(  # pyright: ignore[reportRedeclaration]
                  plane: Plane, path: str, args: dict[str, Any] | None = None,
                  fields: str | None = None, since: str | None = None, wait: int | None = None,
                  diagnose: bool = False, params: dict[str, Any] | None = None,
                  target: str = "") -> dict[str, Any]:
            return read(plane, path, args, cfg=registry.plane(plane, target or None), fields=fields,
                        since=since, wait=wait, diagnose=diagnose, params=params)

        def _call(  # pyright: ignore[reportRedeclaration]
                  plane: Plane, method: str, path: str, args: dict[str, Any] | None = None,
                  confirm: bool = False, wait: int | None = None, target: str = "") -> dict[str, Any]:
            return call(plane, method, path, args, confirm, cfg=registry.plane(plane, target or None), wait=wait)
    else:                                  # the one-estate signatures: no `target` to advertise
        def _plan(plane: Plane, method: str, path: str, args: dict[str, Any] | None = None,
                  fields: str | None = None) -> dict[str, Any]:
            return plan(plane, method, path, args, fields=fields)

        def _read(plane: Plane, path: str, args: dict[str, Any] | None = None,
                  fields: str | None = None, since: str | None = None, wait: int | None = None,
                  diagnose: bool = False, params: dict[str, Any] | None = None) -> dict[str, Any]:
            return read(plane, path, args, fields=fields, since=since, wait=wait, diagnose=diagnose,
                        params=params)

        def _call(plane: Plane, method: str, path: str, args: dict[str, Any] | None = None,
                  confirm: bool = False, wait: int | None = None) -> dict[str, Any]:
            return call(plane, method, path, args, confirm, wait=wait)

    server.tool(name="proximo_plan", description=(
        "READ-ONLY, mutates nothing: the governed verdict (armed, tier, consent) for one address, with the "
        "parameters you gave and the required ones you lack; fields='name1,name2' or 'all' shows the "
        "vendor's full schema. A mutation's plan also reads the target: current, change, noop. Run "
        "before proximo_call. path may be words: one match is planned, several come back to pick from."), **ro)(_plan)
    server.tool(name="proximo_read", description=(
        "READ-ONLY: run a GET by path or words (no leading slash). args = query parameters (params: old "
        "name). Rows come lean with a total; fields='all' or 'name,status' for others; over the cap you "
        "get counts and a next line. since='24h': what changed, from the door's snapshots. wait=N on "
        ".../tasks/{upid}/status waits up to N s (max 600). diagnose=true on a node or guest path: health "
        "and advisory flags. Credentials come back withheld."), **ro)(_read)
    server.tool(name="proximo_call", description=(
        "MUTATION: run a governed POST/PUT/DELETE. Without confirm=true it returns the plan (verdict, "
        "consent id, current, change) and mutates nothing. Refused unless the operator is armed AND the "
        "address has an authored blast-radius tier. Every call, refused or executed, is receipted. "
        "Task-backed calls are waited on (wait=N s, default 60, max 600; 0 submits only). method=undo with "
        "path=<undo.id> puts a receipt's capture back, plan first; withheld or unpublished keys come back "
        "as skipped."), **rw)(_call)
    server.tool(name="audit_entries", description=(
        "READ-ONLY: the PROVE ledger, newest first, bounded; says when it truncated."), **ro)(audit_entries)
    server.tool(name="audit_verify", description=(
        "READ-ONLY: walk the chain, report the first break; expected_head catches a cut tail; "
        "path=<archive> checks a sealed archive."), **ro)(audit_verify)
    # An argument a tool does not declare is REFUSED, never dropped (lens 3: an unadvertised
    # `target` ran the call on the env box). Last, so it covers every tool registered above.
    forbid_undeclared(server)
    slim_schemas(server)   # after: the refusal reads the argument models, the model reads these
    prompts.register(server)   # the five runbooks: text over these six tools, no authority
    return server


PROG = "proximo"
_VERBS = ("mint", "doctor", "badge", "arm", "disarm")
_USAGE = f"""usage: {PROG}                 serve the MCP door over stdio (six tools, every published address)
       {PROG} mint|doctor|badge|arm|disarm   the operator's verbs, the same as `proximo-core <verb>`
       {PROG} --help

configured by env: PROXIMO_API_BASE_URL + PROXIMO_TOKEN_PATH (pve), PROXIMO_PBS_/PMG_/PDM_ for the
other planes, PROXIMO_TARGETS for a registry of boxes, PROXIMO_AUDIT_LOG for the record. Stdout is
the protocol; the banner and every refusal go to stderr.
"""


def main(argv: list[str] | None = None) -> int:
    """`proximo`: `--help` prints usage and exits 0 before any config is read or socket opened (the
    2026-08-07 footgun was a door that served on `--help`); a verb runs on the shell door; anything
    else on the command line refuses (rc 3). Serving sources the operator's env file first
    (`core.envfile`; the process environment wins), refuses `PROXIMO_SURFACES` like the network
    doors, and stamps `session_start`/`session_end` through
    the core's recorder, the second in a `finally`, so this door greets the ledger like the network
    doors do: any door, one spine."""
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] in (["-h"], ["--help"]):
        print(_USAGE, end="")
        return 0
    if argv[:1] and argv[0] in _VERBS:
        from proximo.core.doors.cli import main as shell_main  # noqa: PLC0415
        return shell_main(argv)   # the shell door sources the env file itself, quietly
    if argv:
        print(f"{PROG}: unknown argument {argv[0]!r}\n{_USAGE}", file=sys.stderr)
        return 3
    from proximo.core import envfile  # noqa: PLC0415
    from proximo.core.doors.network import recorder, refuse_surfaces  # noqa: PLC0415
    envfile.load(prog=PROG)   # the operator's file, before the first env read; the process env wins
    if refuse_surfaces(PROG):
        return 3
    try:
        server = build_server()
    except ProximoError as e:
        print(f"{PROG}: {e}", file=sys.stderr)
        return 3
    from proximo.core import reach  # noqa: PLC0415
    if not reach.greet(PROG, "stdio"):   # the reach grant is on the ledger first, or the door does not start
        return 3
    record = recorder(PROG)
    print(BANNER, file=sys.stderr)   # stderr: stdout is the protocol
    record("session_start", target="face/stdio", detail={"face": "stdio"})
    try:
        server.run()
    finally:
        record("session_end", target="face/stdio", detail={"face": "stdio"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
