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
where 0.44 armed three shell tools. `tiers.toml` ships the ratified grant (150 addresses, each
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

import os
import sys
from typing import Any, Literal

import httpx

from proximo import __version__
from proximo.core import apitree, engine, registry, search, wire
from proximo.core import diagnose as diagnose_mod
from proximo.core import undo as restore_mod
from proximo.core.doors import BANNER
from proximo.core.errors import ProximoError
from proximo.core.ledger import AuditLedger, LedgerConfig, ledger_key, looks_like_head, read_entries, verify_chain
from proximo.core.secretfile import safe_exception_text

#: The four planes, as the schema says them: a model picks one; a word that is none of them is refused
#: by name (the bar-3 drive of 2026-10-18 sent "default" when the schema said only `str`).
Plane = Literal["pve", "pbs", "pmg", "pdm"]

_HELP = "the MCP door needs the mcp SDK: pip install proximo-proxmox"


def _execute(row: engine.Row, args: dict[str, Any], path: str,
             cfg: wire.Plane | None = None, fields: str | None = None,
             since: str | None = None, wait: int | None = None) -> dict[str, Any]:
    """DECIDE BEFORE CONFIGURING. `execute` governs first and builds the plane's client from
    env only after the verdict, so an unarmed mutation on an unconfigured box is refused as
    "not armed" and receipted, never as a missing env var. The env-var error, when it does
    come, is rephrased in the door's words: a RuntimeError inside a tool body is what the 2.x
    SDK sanitizes to a bare tool name."""
    try:
        return engine.execute(row, args, path=path, cfg=cfg, fields=fields, since=since, wait=wait)
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


def find(query: str, plane: Plane | None = None, limit: int = 5) -> dict[str, Any]:
    """The operator's words to a published address: verbs pick the method, words score by where
    they land (path segment, the vendor's description, a parameter), a handful by default so a
    4K window is never handed a list it cannot hold. `proximo.core.search` says how, and why."""
    if not query or not query.strip():
        raise ProximoError("give proximo_find one or more words to look for")
    if limit < 0:
        raise ProximoError(f"limit must be 0 or more, not {limit}")
    if plane is not None and plane not in apitree.PRODUCTS:
        raise ProximoError(f"unknown plane {plane!r}; known planes: {', '.join(apitree.PRODUCTS)}")
    return search.find(query, plane=plane, limit=limit)


def words_to_address(plane: str, method: str, words: list[str]) -> dict[str, Any]:
    """What plan resolves words through: `method` filters, it is never a word, and every word must
    be a segment of the path itself (search's strict). One place, so the whole-table sweep in
    tests/test_search.py drives exactly what plan acts on."""
    return search.find(" ".join(words), plane=plane, strict=True, method=method)


def plan(plane: Plane, method: str, path: str, args: dict[str, Any] | None = None,
         cfg: wire.Plane | None = None) -> dict[str, Any]:
    """The governed decision and the published schema. Answers on a box that holds no credential.
    `cfg` is the Plane of a registry target (`registry.plane`), or None for the env box.
    A PATH STARTS WITH A SLASH; ANYTHING ELSE IS WORDS TO FIND. One match is planned as if its
    address had been named; several come back as the find answer to pick from; none is the
    same refusal find gives. The words never reach the spelling gate as a path."""
    if not path.startswith("/"):
        words = [w for w in path.split() if w and w.upper() != method]
        if not words:
            raise ProximoError("give proximo_plan a /path or words to find")
        found = words_to_address(plane, method, words)
        hits = found["matches"]
        if not hits:
            raise ProximoError(f"no published address matched {path!r} (a path starts with '/'; "
                               f"anything else is words to find: try fewer or different words)")
        if len(hits) > 1 or found.get("total", 1) > 1:
            return found
        path = hits[0]["path"]
    return engine.plan(engine.resolve(plane, method, path), args, path, cfg=cfg)


def read(plane: Plane, path: str, params: dict[str, Any] | None = None,
         cfg: wire.Plane | None = None, fields: str | None = None,
         since: str | None = None, wait: int | None = None, diagnose: bool = False) -> dict[str, Any]:
    if diagnose:
        # DIAGNOSE (B3): a read's mode, like since= and wait=; the subject is the path, alone.
        # Every probe is its own governed read inside, so a vendor failure is a section, not an
        # error here; the one error left is the plane's own, said in the door's words.
        if params or fields is not None or since is not None or wait is not None:
            raise ProximoError("diagnose takes the path alone: no params, fields, since or wait")
        try:
            return diagnose_mod.run(plane, path, cfg=cfg)
        except RuntimeError as e:
            raise ProximoError(f"{plane} is not configured on this Proximo ({e})") from e
    row = engine.resolve(plane, "GET", path)
    return _execute(row, dict(params or {}), path, cfg, fields=fields, since=since, wait=wait)


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
    return read_entries(limit=limit, target=target, action=action, mutations_only=mutations_only)


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
        if os.path.basename(path) != path or path in ("", ".", ".."):
            raise ProximoError("path must be the bare name of an archive beside the ledger, "
                               f"not {path!r}")
        target = os.path.join(os.path.dirname(cfg.audit_log_path) or ".", path)
        if not os.path.isfile(target):
            raise ProximoError(f"no archive named {path!r} beside the ledger")
        v = verify_chain(target, key)
        return {"ok": v.ok, "entries": v.entries, "broken_at": v.broken_at, "reason": v.reason,
                "head": v.head, "segments": [list(s) for s in v.segments], "archive": path}
    if not os.path.exists(cfg.audit_log_path):
        return {"ok": True, "entries": 0, "broken_at": None, "reason": None, "head": None, "keyed": None,
                "note": f"no ledger at {cfg.audit_log_path}: nothing has been recorded here, or "
                        "PROXIMO_AUDIT_LOG points elsewhere"}
    pin, pinned = _pinned_head(expected_head)
    ledger = AuditLedger(cfg.audit_log_path, key=key)
    v = ledger.verify(pin, None) if pinned == "argument" else ledger.verify(None, pin)
    return {"ok": v.ok, "entries": v.entries, "broken_at": v.broken_at, "reason": v.reason,
            "head": ledger.head(), "keyed": ledger.keyed, "pinned": pinned,
            # Only an exact head speaks for the tail; a held row or no pin cannot see a row forged after.
            "tail_verified": v.ok and pinned == "argument"}


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
        from proximo.core.mcpcompat import forbid_undeclared, make_server, tool_annotations_kwargs
    except ImportError as e:
        raise ProximoError(_HELP) from e
    server = make_server(name, __version__)
    ro = tool_annotations_kwargs(read_only=True)
    rw = tool_annotations_kwargs(read_only=False)

    # readOnlyHint is what a client's permission policy reads. find/plan/audit touch the
    # local table and ledger only; read runs a GET; call is the ONE tool that can mutate.
    server.tool(name="proximo_find", description=(
        "READ-ONLY: search every API address the planes publish, in plain "
        "words ('list datastores', 'guest status'). A verb picks the method; other words match "
        "the path, the vendor's description, parameter names. 5 by default. Returns access "
        "and the authored blast-radius tier."), **ro)(find)
    # `target` names a box PROXIMO_TARGETS registers (B16): resolved to its Plane here, so the
    # engine governs it with its own arm pair, forbid and rate, and every receipt names it. It is
    # ADVERTISED only where a registry is configured (0.44's rule, door._slim_registry_schemas):
    # a one-estate box pays nothing in the 4K window for a selector with nothing to select.
    if _targets_advertised():
        # One name per tool, one signature per branch (the SDK titles the schema by __name__).
        def _plan(  # pyright: ignore[reportRedeclaration]
                  plane: Plane, method: str, path: str, args: dict[str, Any] | None = None,
                  target: str = "") -> dict[str, Any]:
            return plan(plane, method, path, args, cfg=registry.plane(plane, target or None))

        def _read(  # pyright: ignore[reportRedeclaration]
                  plane: Plane, path: str, params: dict[str, Any] | None = None,
                  fields: str | None = None, since: str | None = None, wait: int | None = None,
                  diagnose: bool = False, target: str = "") -> dict[str, Any]:
            return read(plane, path, params, cfg=registry.plane(plane, target or None), fields=fields,
                        since=since, wait=wait, diagnose=diagnose)

        def _call(  # pyright: ignore[reportRedeclaration]
                  plane: Plane, method: str, path: str, args: dict[str, Any] | None = None,
                  confirm: bool = False, wait: int | None = None, target: str = "") -> dict[str, Any]:
            return call(plane, method, path, args, confirm, cfg=registry.plane(plane, target or None), wait=wait)
    else:                                  # the one-estate signatures: no `target` to advertise
        def _plan(plane: Plane, method: str, path: str,
                  args: dict[str, Any] | None = None) -> dict[str, Any]:
            return plan(plane, method, path, args)

        def _read(plane: Plane, path: str, params: dict[str, Any] | None = None,
                  fields: str | None = None, since: str | None = None, wait: int | None = None,
                  diagnose: bool = False) -> dict[str, Any]:
            return read(plane, path, params, fields=fields, since=since, wait=wait, diagnose=diagnose)

        def _call(plane: Plane, method: str, path: str, args: dict[str, Any] | None = None,
                  confirm: bool = False, wait: int | None = None) -> dict[str, Any]:
            return call(plane, method, path, args, confirm, wait=wait)

    server.tool(name="proximo_plan", description=(
        "READ-ONLY: the governed verdict for one address and the vendor's published parameters. "
        "Mutates nothing. A mutation's plan also reads the target (one governed read, receipted): "
        "current, change (from/to per argument), noop. Run before proximo_call. path may be "
        "words: one match is planned, several come back to pick from."), **ro)(_plan)
    server.tool(name="proximo_read", description=(
        "READ-ONLY: run any GET the plane publishes, by path. Rows come back LEAN with a total "
        "(names, states, ids) unless fields='all' or fields='name,status'. Over the cap: counts "
        "per state and the odd rows; fields= gets rows. since='24h' (30m, 7d): what changed, from "
        "the door's own snapshots, no vendor call. Credentials come back withheld. wait=N on a "
        ".../tasks/{upid}/status address waits up to N s (max 600) for the task's end. "
        "diagnose=true on a node or guest path: its health reads and advisory flags, one call."), **ro)(_read)
    server.tool(name="proximo_call", description=(
        "MUTATION: run a governed POST/PUT/DELETE. Dry-run by default: without confirm=true it "
        "returns the plan (verdict, consent id, current, change) and mutates nothing. Refused "
        "unless the operator is armed AND the address carries an authored blast-radius tier. "
        "Every call, refused or executed, is receipted. A task-backed call is waited on (wait=N s, "
        "default 60, max 600; 0 submits only) and reports finished, failed or timed out under "
        "'task'. method=undo with path=<undo.id> puts that "
        "receipt's capture back through the vendor's PUT, plan first; withheld or unpublished keys "
        "come back as skipped."), **rw)(_call)
    server.tool(name="audit_entries", description=(
        "READ-ONLY: read the PROVE ledger back, newest first, bounded, rows with ids; says when it "
        "truncated."), **ro)(audit_entries)
    server.tool(name="audit_verify", description=(
        "READ-ONLY: walk the chain and report the first break; expected_head catches a cut tail; "
        "path=<archive> verifies a sealed archive beside the ledger."), **ro)(audit_verify)
    # An argument a tool does not declare is REFUSED, never dropped (lens 3: an unadvertised
    # `target` ran the call on the env box). Last, so it covers every tool registered above.
    forbid_undeclared(server)
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
