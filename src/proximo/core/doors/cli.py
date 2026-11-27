"""The shell door — Proximo with no model, no agent and no protocol in the loop.

THIS IS THE REFERENCE DOOR, not a convenience wrapper. If the engine is governable from a bash
script and a cron job, then MCP, A2A and HTTP are protocol adapters over the same decisions
rather than three places where governance might differ. Agent-agnostic stops being a claim in a
README and becomes a property the test suite checks.

    proximo-core pve GET /nodes/pve1/status
    proximo-core pve DELETE /nodes/pve1/qemu/101 purge=1            # its plan; nothing moves
    proximo-core pve DELETE /nodes/pve1/qemu/101 purge=1 --confirm  # run it
    proximo-core pve GET /nodes --target east      # a box PROXIMO_TARGETS names
    proximo-core learn                              # the one deliberate pass that fills the memory
    proximo-core where 105                          # kind, node, status, the concrete path
    proximo-core uses local                         # the guests with a disk or NIC on it
    proximo-core changed 24h                        # added, gone, changed
    proximo-core instructions                       # the operator's instructions, as a door serves them
    proximo-core runbook list                       # the operator's runbooks: name, plane, title
    proximo-core runbook show drain_node            # one of them, as a door serves it
    proximo-core audit verify                       # walk the ledger's chain; exit 2 when it does not hold
    proximo-core audit entries --limit 5            # the newest rows, as every tool door serves them

Exit codes are the contract for scripts: 0 executed and ended in success, 2 refused by the spine,
3 the caller's own mistake (bad syntax, unconfigured estate, a mutation given neither --confirm nor
--plan: its plan is printed and stderr says it did not run), 4 the vendor refused or could not be
reached (a request that was sent and got no answer is 4 too, and may have run), 5 it ran and
failed (a task that did not end in success, a guest or container command
that exited non-zero or was killed), 6 not known to have finished (the wait ran out, the status could not be
read after the call, or the exit carries no result). `--wait 0` on a task or a guest-agent exec
submits only and exits 0. A task
that ends `WARNINGS: n` is a success. A read exits 0 whatever it found, but for a task-status
read with `--wait`, which exits by the task's own end.
Anything else is a bug in Proximo and prints a traceback on purpose: a crash must not be
laundered into a tidy refusal, because a script that cannot tell "the spine said no" from "the
door broke" will retry the wrong one.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import httpx

from proximo.core import diagnose, doctor, engine, envfile, rawdoor, reach, registry, shell, undo
from proximo.core.doors import BANNER
from proximo.core.errors import ProximoError
from proximo.core.secretfile import safe_exception_text, safe_text

EXIT_OK, EXIT_REFUSED, EXIT_USAGE, EXIT_VENDOR = 0, 2, 3, 4
#: THE CALL WENT THROUGH AND THE WORK DID NOT (kevwillow's no-skill round, #142 items 2 to 4; John's
#: ruling 2026-11-27). 5: it ran and failed (a task that ended in anything but success, a guest
#: command that exited non-zero or was killed). 6: not known to have finished (the wait ran out, the
#: status could not be read, or the exit carries no result). Until then all of these exited 0, and a
#: cron job read a failed snapshot, a backup still running and `false` in a guest as success. 4 stays
#: what it was: the vendor refused the call, or the request failed on the wire. That still holds a
#: mutation that was SENT and got no answer, which may have run; a lane command whose ssh timed out is
#: still 2. Telling "sent, outcome unknown" from "never sent" belongs to the wire, per request, and is
#: not decided at this door (John's ruling 2026-11-27, after three reviews of doing it here).
EXIT_FAILED, EXIT_UNFINISHED = 5, 6


def exit_of(out: Any, wait: int | None, *, command: bool = False) -> int:
    """The exit code of an answer that EXECUTED: the task's or the guest command's own outcome.

    A table. 5 outranks 6 where one answer carries both; nothing here is ever 2, 3 or 4:
      a task that finished and did not succeed            5
      a guest command that exited non-zero or was killed  5  (the agent's exec; a lane COMMAND's `returncode`)
      a wait that ran out                                 6
      a status read that failed after the call            6  (the work was accepted and may be running:
                                                              4 would tell a script to send it again)
      a guest command that exited with no result          6  (neither an exit code nor a signal)
      a wait that was wanted and polled nothing           6
      a lane command that answered ssh's own 255          6  (it started, and either it exited 255 or the
                                                              connection dropped while it ran: the lane
                                                              says `exit_ambiguous`, and 5 would say it ended)
      anything else                                       0  (succeeded, a wait of 0, or nothing to wait on)
    `wait` is the caller's `--wait`: 0 or less submits only and is never a failure to finish.
    `command` is true only for a lane's COMMAND (the door passes the row's own access and wire: a
    mutation on the ssh lanes, `exec` and `psql`). A lane READ's `returncode` is data, never an exit
    (a probe of a standalone node answers `pvecm`'s 2 and the node
    is healthy; records/diagnose.toml), so no read exits 5 for what it found. A read that WAITS on a
    task (`GET .../tasks/{upid}/status --wait N`) is the one read with an outcome of its own."""
    if not isinstance(out, dict):
        return EXIT_OK
    wanted = wait is None or wait > 0
    codes = [EXIT_OK]
    task = out.get("task")
    if isinstance(task, dict):
        state = undo.task_state(out)
        codes.append(EXIT_OK if state is None else EXIT_FAILED if state == "failed"
                     else EXIT_UNFINISHED if state == "timed_out"
                     else (EXIT_UNFINISHED if wanted else EXIT_OK) if state == "submitted"
                     else EXIT_UNFINISHED)
    ran = out.get("exec")
    if isinstance(ran, dict):
        if ran.get("timed_out"):
            codes.append(EXIT_UNFINISHED)
        elif ran.get("exited") is True:
            code, signal = ran.get("exitcode"), ran.get("signal")
            known = type(code) is int or type(signal) is int
            codes.append(EXIT_UNFINISHED if not known else EXIT_FAILED if code or type(signal) is int else EXIT_OK)
        elif wanted:                           # nothing confirmed an exit: a status read that failed lands here too
            codes.append(EXIT_UNFINISHED)
    data = out.get("data") if command else None
    if isinstance(data, dict) and data.get("proximo_untrusted") is True and isinstance(data.get("data"), str):
        try:                                   # the fence wraps a lane's answer for a model: the code is inside
            data = json.loads(data["data"])
        except (ValueError, RecursionError):
            data = None
    rc = data.get("returncode") if isinstance(data, dict) else None
    if type(rc) is int and rc != 0:
        codes.append(EXIT_UNFINISHED if rc == shell.SSH_EXIT else EXIT_FAILED)
    return EXIT_FAILED if EXIT_FAILED in codes else EXIT_UNFINISHED if EXIT_UNFINISHED in codes else EXIT_OK


_AUDIT_USAGE = ("usage: proximo-core audit verify [--expected-head H] [--path ARCHIVE] | "
                "audit entries [--limit N] [--target T] [--action A] [--mutations-only]")
_AUDIT_FLAGS = {"verify": {"--expected-head": "expected_head", "--path": "path"},
                "entries": {"--limit": "limit", "--target": "target", "--action": "action"}}


def _audit_args(argv: list[str]) -> tuple[str, dict[str, Any]] | None:
    """(verb, keyword arguments), or None for anything this verb does not take. Parsed by hand: argparse
    prints its own usage and exits 2, which on this door is the spine's refusal, never a typo."""
    if not argv or argv[0] not in _AUDIT_FLAGS:
        return None
    verb, rest, kw = argv[0], argv[1:], {}
    while rest:
        flag = rest.pop(0)
        if verb == "entries" and flag == "--mutations-only":
            kw["mutations_only"] = True
        elif flag in _AUDIT_FLAGS[verb] and rest:
            kw[_AUDIT_FLAGS[verb][flag]] = rest.pop(0)
        else:
            return None
    if "limit" in kw:
        if not kw["limit"].isdigit() or not 1 <= int(kw["limit"]) <= 1000:
            return None
        kw["limit"] = int(kw["limit"])
    return verb, kw


def audit_main(argv: list[str]) -> int:
    """`proximo-core audit verify [--expected-head H] [--path ARCHIVE]` and `audit entries [--limit N]
    [--target T] [--action A] [--mutations-only]`: the two ledger tools every tool door serves, by the
    same two functions, so the README's "on every door" holds on this one too. Reads; they write no
    row and mint no key. `verify` exits 0 ONLY when the chain was walked and holds: a broken chain, a
    ledger that cannot be read at all (a directory, bytes that are not text) and an answer that is not
    a plain yes all exit 2, with the answer printed so a script reads why. `entries` exits 0 with the
    rows, 2 when the ledger's bytes cannot be read. 3 is the caller's (an unknown flag, a limit outside
    1..1000, and for `entries` a box with no ledger at all: there is nothing to list)."""
    from proximo.core.doors import mcp as tools  # noqa: PLC0415 -- only this verb reads the ledger's tools
    parsed = _audit_args(argv)
    if parsed is None:
        print(_AUDIT_USAGE, file=sys.stderr)
        return EXIT_USAGE
    verb, kw = parsed
    try:
        out = tools.audit_verify(**kw) if verb == "verify" else tools.audit_entries(**kw)
    except ProximoError as exc:
        print(f"proximo-core: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, ValueError) as exc:           # a ledger that is not text raises a ValueError
        why = f"the ledger could not be read ({type(exc).__name__}); a chain that cannot be read does not hold"
        if verb == "verify":
            print(json.dumps({"ok": False, "reason": why}, separators=(",", ":"), sort_keys=True))
        else:
            print(f"proximo-core: {why}", file=sys.stderr)
        return EXIT_REFUSED
    print(json.dumps(out, separators=(",", ":"), sort_keys=True, default=str))
    return EXIT_OK if verb == "entries" or out.get("ok") is True else EXIT_REFUSED


def _not_run() -> int:
    """A mutation given neither --plan nor --confirm: its plan was printed and nothing ran. Exit 3, the
    caller's, and a line on stderr: a script written when a bare mutation ran must not read "exit 0" and
    believe its backup, its restart or its delete happened. `--plan` asks for the plan and exits 0."""
    print("proximo-core: planned, not run: a mutation runs with --confirm (--plan prints the plan and exits 0)",
          file=sys.stderr)
    return EXIT_USAGE


def parse_args(pairs: list[str]) -> dict[str, str]:
    """`k=v` pairs. Values stay STRINGS: the vendor's schema decides types, not this parser."""
    out: dict[str, str] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            # ValueError, NOT ProximoError: this is the caller's syntax, not the spine's
            # verdict. Raising a refusal here made a typo exit 2 and read as "governance said
            # no", which is the one thing a calling script must be able to tell apart.
            raise ValueError(f"argument {pair!r} is not k=v")
        out[key] = value
    return out


def mint_main(argv: list[str]) -> int:
    """`proximo-core mint <plane> [--write --scope PATH] [--expire 8h]`: print the vendor's own
    commands for a credential. Calls nothing, reads no secret, writes nothing."""
    from proximo.core import mint  # noqa: PLC0415 -- only this verb needs it

    ap = argparse.ArgumentParser(prog="proximo-core mint", description=(mint.__doc__ or "").split("\n")[0])
    ap.add_argument("product", choices=mint.PRODUCTS)
    mint.add_mint_options(ap)
    ns = ap.parse_args(argv)
    try:
        recipe = mint.recipe_from_args(ns)
    except ValueError as exc:
        print(f"proximo-core mint: {exc}", file=sys.stderr)
        return EXIT_USAGE
    print(json.dumps(recipe, indent=2) if ns.json else mint.render_text(recipe), end="" if not ns.json else "\n")
    return EXIT_OK


def words_main(argv: list[str]) -> int:
    """`proximo-core instructions`, `runbook list`, `runbook show <name>`: the operator's words as
    a door serves them, printed. The shell is the operator's own terminal, so nothing is withheld
    for want of a bearer. They read the file or folder now, write no ledger row and no file. Exit 0
    shown; 3 the caller's (the variable unset, an unknown name, a bad argument); 2 set and refused,
    the refusal on stderr."""
    from proximo.core import instructions, runbooks  # noqa: PLC0415 -- only these verbs read the words
    try:
        if argv == ["instructions"]:
            text = instructions.load()
            if text is None:
                print(f"proximo-core: {instructions.ENV} is not set", file=sys.stderr)
                return EXIT_USAGE
            sys.stdout.write(text)
            return EXIT_OK
        if argv not in (["runbook", "list"], ["runbook", "show", *argv[2:3]]) or argv == ["runbook", "show"]:
            print("usage: proximo-core instructions | runbook list | runbook show <name>", file=sys.stderr)
            return EXIT_USAGE
        folder = runbooks.load()
        if folder is None:
            print(f"proximo-core: {runbooks.ENV} is not set", file=sys.stderr)
            return EXIT_USAGE
    except ProximoError as exc:
        print(f"proximo-core: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    if argv[1] == "list":
        for line in runbooks.said(folder):
            print(f"proximo-core: {line}", file=sys.stderr)
        for book in folder.served:
            print(f"{book.name}\t{book.plane}\t{book.title}")
        # A FILE THAT IS SET AND REFUSED IS EXIT 2 HERE TOO, as `show` and SETUP say (#142 item 30): a
        # folder whose only file was refused listed nothing and exited 0. The ones served still print.
        return EXIT_REFUSED if folder.refused else EXIT_OK
    name = argv[2]
    for book in folder.served:
        if book.name == name:
            sys.stdout.write(book.text)
            return EXIT_OK
    for refusal in folder.refused:
        if refusal.name == name:
            print(f"proximo-core: an operator runbook is not served: {name}: {refusal.reason}", file=sys.stderr)
            return EXIT_REFUSED
    print("proximo-core: no operator runbook has that name (`proximo-core runbook list` names them)", file=sys.stderr)
    return EXIT_USAGE


def doctor_main(argv: list[str]) -> int:
    """`proximo-core doctor [--receipt [--deny NAME]...]`: the gate diagnoses itself (the record,
    the planes, the chain, the pillars). Vendor reads only, each receipted like any read; JSON
    out; the exit is the door's contract and the flags move it not. `--receipt` prints the same
    report as one estate-redacted, fingerprinted text to paste (`core.receipt`); it sends nothing,
    and `--deny NAME` (repeatable) names a bare estate word the redactor cannot see."""
    receipt_out, deny, rest = False, [], list(argv)
    while rest:
        arg = rest.pop(0)
        if arg == "--receipt":
            receipt_out = True
        elif arg == "--deny" and rest:
            deny.append(rest.pop(0))
        else:
            print("usage: doctor takes no arguments but --receipt [--deny NAME]...", file=sys.stderr)
            return EXIT_USAGE
    if deny and not receipt_out:
        print("usage: --deny belongs to --receipt", file=sys.stderr)
        return EXIT_USAGE
    report = doctor.run()
    code = report.pop("exit")
    if receipt_out:
        from datetime import UTC, datetime  # noqa: PLC0415 -- the clock is the door's; the receipt takes it in

        from proximo import __version__  # noqa: PLC0415
        from proximo.core import receipt  # noqa: PLC0415

        print(receipt.render(report, version=__version__, deny=receipt.compile_denylist(deny),
                             generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")), end="")
        return code
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return code


def badge_main(argv: list[str]) -> int:
    """`proximo-core badge mint --key KEY.pem --sub NAME [--exp 90d] [--jwk-out PATH]` mints a caller
    badge (a compact ES256 JWS) and writes the public JWK to pin beside the key; `badge inspect
    BADGE` decodes one without verifying it. The camera at every network door reads the badge
    (`core.perimeter.badge`); this is where it is minted. Moved here from the 0.44 `proximo badge`
    at the default-command swap, same flags, same refusals."""
    import os  # noqa: PLC0415
    import time  # noqa: PLC0415

    from proximo.core.perimeter.badge import _b64url_dec, mint_badge, public_jwk  # noqa: PLC0415
    from proximo.core.secretfile import refuse_exposed_secret, register_secret  # noqa: PLC0415

    ap = argparse.ArgumentParser(prog="proximo-core badge")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mint")
    m.add_argument("--key", required=True, help="EC P-256 private key PEM (caller keeps this)")
    m.add_argument("--sub", required=True, help="caller name; must match the pinned filename stem")
    m.add_argument("--exp", default=None, help="optional lifetime, e.g. 90d / 12h / 30m (default 30d)")
    m.add_argument("--jwk-out", default=None, help="where to write the public .jwk to pin (default: beside the key)")
    sub.add_parser("inspect").add_argument("badge")
    ns = ap.parse_args(argv)
    try:
        if ns.cmd == "inspect":
            h_b64, p_b64, _ = ns.badge.strip().split(".")
            print(json.dumps({"header": json.loads(_b64url_dec(h_b64)), "payload": json.loads(_b64url_dec(p_b64)),
                              "note": "NOT VERIFIED; inspection only"}, indent=2))
            return EXIT_OK
        # The same floor every other secret loaded by path gets: this one mints identities.
        refuse_exposed_secret(ns.key, "caller badge signing key")
        with open(ns.key, "rb") as f:
            pem = f.read()
        register_secret(pem.decode("utf-8", errors="replace"))
        exp = None
        if ns.exp:
            try:
                unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[ns.exp[-1]]
                exp = int(time.time()) + int(ns.exp[:-1]) * unit
            except (KeyError, ValueError) as e:
                raise ValueError(f"malformed --exp {ns.exp!r}: expected <int><s|m|h|d>, e.g. 90d") from e
        jwk = public_jwk(pem, ns.sub)
        if ns.jwk_out:
            out = ns.jwk_out
        else:
            # Beside the key, never cwd-relative; --sub must be a bare stem (basename() alone would
            # swallow a traversal instead of refusing it, so safe must equal the argument).
            safe = os.path.basename(ns.sub)
            if not safe or safe in (".", "..") or safe != ns.sub:
                raise ValueError(f"--sub {ns.sub!r} is not a safe filename stem for the default JWK path; "
                                 "pass --jwk-out explicitly")
            out = os.path.join(os.path.dirname(os.path.abspath(ns.key)), f"{safe}.jwk")
        if os.path.islink(out):
            raise ValueError(f"refusing to write JWK to a symlink: {out}")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(jwk, f, indent=2)
        print(mint_badge(pem, ns.sub, exp=exp))
        if exp is None:
            print("no --exp given: the badge expires after the default 30d (never minted without an expiry); "
                  "pass --exp <int><s|m|h|d> to change the lifetime.", file=sys.stderr)
        print(f"pinned public key written to {out}; copy it into the operator's PROXIMO_CALLER_KEYS_DIR",
              file=sys.stderr)
        return EXIT_OK
    except Exception as e:  # noqa: BLE001 -- the verb's contract: one prefixed line, rc 3, never a traceback
        print(f"proximo-core badge: {safe_text(str(e)) or type(e).__name__}", file=sys.stderr)
        return EXIT_USAGE


def _install_atomic(src: str, dst: str) -> None:
    """Copy `src` over `dst` by temp + rename in `dst`'s own directory, mode 600: a door reading the
    token per call sees the old bytes or the new ones, never a partial write; the source is read
    whole before the destination is touched, so an unreadable source leaves no truncated token."""
    with open(src, "rb") as f:
        data = f.read()
    tmp = _stage(data, dst)
    try:
        os.replace(tmp, dst)
    except BaseException:
        _discard(tmp)       # lens 3 on e17e8b6: the rename sat outside the cleanup and left the bytes
        raise


def _stage(data: bytes, dst: str) -> str:
    """`data` in a new mode-600 temp file in `dst`'s own directory (made, private, when missing), its
    path returned for a rename over `dst`, or for `arm` to check first. A failure leaves no staged file (a
    directory it made stays, empty and private)."""
    import tempfile  # noqa: PLC0415
    directory = os.path.dirname(os.path.abspath(dst)) or "."
    if not os.path.isdir(directory):
        # A fresh state dir has no served/ yet (alexdelprete, #114: ENOENT on served/.tok.<rand>). The token's
        # own directory is made, private; a missing grandparent is the operator's path to fix, not ours to build.
        # Two arms racing: the loser finds the directory the winner made and carries on (lens 3).
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            if not os.path.isdir(directory):
                raise
    fd, tmp = tempfile.mkstemp(prefix=".tok.", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
    except BaseException:
        _discard(tmp)
        raise
    return tmp


def _discard(tmp: str) -> None:
    try:
        os.unlink(tmp)
    except OSError:
        pass


def _source(env: str, what: str) -> str:
    from proximo.core.secretfile import refuse_exposed_secret  # noqa: PLC0415
    path = os.environ.get(env, "").strip()
    if not path:
        raise ValueError(f"{env} is unset: there is no {what} to install from")
    if os.path.islink(path) or not os.path.isfile(path):
        raise ValueError(f"{what} is missing, a symlink, or not a regular file: {path}")
    refuse_exposed_secret(path, what)   # the floor every secret loaded by path gets (0.44 only advised)
    return path


def arm_main(verb: str, argv: list[str]) -> int:
    """`proximo-core arm|disarm [--plane P] [--serve PATH] [--user USER] [--json]`: CONSENT's switch, the
    operator's hand. THE TICKET IS THE ARM (2026-11-05): `arm` logs the operator in (`POST /access/ticket`,
    the vendor's own call, from a terminal of their own: the password is typed at a silent prompt and sent
    once) and serves the vendor's ticket at the plane's served path; the engine's predicate reads the
    ticket's own issue time, so it is armed for the vendor's two hours and dies on its own. `disarm`
    installs the plane's read-only token (`PROXIMO_[<PLANE>_]READONLY_SOURCE`). Each plane has its own
    served path and its own pair; `--plane` says which (pve by default), `--serve` names another file. A
    job with nobody at a keyboard keeps the token pair (`PROXIMO_[<PLANE>_]ARM_SOURCE`, served by
    configuration); this verb is for a person. Refusals: no terminal on stdin (rc 3, nothing written); a
    login the vendor refuses (rc 2, nothing written, a refused row)."""
    import json as _json  # noqa: PLC0415

    from proximo.core import wire  # noqa: PLC0415
    from proximo.core.arm import TICKET_LIFETIME, served_credential  # noqa: PLC0415
    from proximo.core.doors.network import recorder  # noqa: PLC0415

    ap = argparse.ArgumentParser(prog=f"proximo-core {verb}")
    ap.add_argument("--json", action="store_true", help="emit the result as JSON")
    ap.add_argument("--plane", default="pve", choices=("pve", "pbs", "pdm"), help="which box (default pve)")
    ap.add_argument("--serve", default=None, help="the served credential path (default: the plane's own)")
    if verb == "arm":
        ap.add_argument("--user", default=None, help="who logs in (default: the served token's own user)")
        ap.add_argument("--target", default=None, help="a registered target's name: its box, its file, its user")
    ns = ap.parse_args(argv)
    token_var = "PROXIMO_TOKEN_PATH" if ns.plane == "pve" else f"PROXIMO_{ns.plane.upper()}_TOKEN_PATH"
    ro_var, arm_var = wire._pair_var(ns.plane, "READONLY_SOURCE"), wire._pair_var(ns.plane, "ARM_SOURCE")
    try:
        if verb == "arm" and ns.target:
            from proximo.core import registry  # noqa: PLC0415
            registered = registry.plane(ns.plane, ns.target)
            if registered is None:
                raise ValueError("--target names a registered target")
            ns.registered = registered
            target = (ns.serve or registered.token_path or "").strip()
        else:
            ns.registered = None
            target = (ns.serve or wire.env_token_path(ns.plane) or "").strip()
        if not target:
            raise ValueError(f"{token_var} is unset and --serve not given: there is no served path to write")
        if os.path.islink(target):
            raise ValueError(f"refusing to install over a symlink: {target}")
        if verb != "arm":
            src = _source(ro_var, "read-only token")
            armed = os.environ.get(arm_var, "").strip()      # a job's pair, when the box has one
            if armed:
                try:
                    with open(armed, "rb") as a, open(src, "rb") as r:
                        same = a.read() == r.read()
                except OSError:
                    same = False   # nothing to compare; refusing here would leave write authority live
                if same:
                    raise ValueError("refusing to disarm: the read-only source is byte-identical to the write "
                                     f"token at {arm_var}, so restoring it would install write authority "
                                     f"and report DISARMED. Point {ro_var} at a genuinely read-only "
                                     "credential. Nothing was changed.")
            _install_atomic(src, target)
    except (OSError, ValueError, RuntimeError, ProximoError) as e:   # RuntimeError: an exposed source
        print(f"proximo-core {verb}: {safe_text(str(e))}", file=sys.stderr)
        return EXIT_USAGE
    record = recorder("proximo-core")
    if verb != "arm":
        record("core.disarm", target="token", detail={"armed": False, "plane": ns.plane})
        print(_json.dumps({"armed": False, "target": target, "plane": ns.plane}, indent=2) if ns.json else
              "DISARMED: the served credential is the read-only token.")
        return EXIT_OK
    return _arm_with_a_ticket(ns, target, served_credential, TICKET_LIFETIME, record)


def _prompt_secret(label: str) -> str:
    """A silent prompt on the operator's own terminal. A seam for the suite; never patched outside it."""
    import getpass  # noqa: PLC0415
    return getpass.getpass(label)


def _arm_with_a_ticket(ns: argparse.Namespace, target: str, served_credential: Any, lifetime: int,
                       record: Any) -> int:
    import json as _json  # noqa: PLC0415
    from datetime import UTC, datetime  # noqa: PLC0415

    import httpx  # noqa: PLC0415

    from proximo.core import wire  # noqa: PLC0415
    from proximo.core.arm import credential_from_bytes  # noqa: PLC0415
    from proximo.core.spine import wire_error  # noqa: PLC0415
    if not sys.stdin.isatty():
        print("proximo-core arm: run this from a terminal of your own: the password is typed at a silent prompt "
              "there and nowhere else (an agent's shell passthrough has no terminal and would keep it in its "
              "transcript). Nothing was changed.", file=sys.stderr)
        return EXIT_USAGE
    plane = getattr(ns, "registered", None)
    if plane is None:
        try:
            plane = wire.Plane.from_env(ns.plane)
        except RuntimeError as e:
            print(f"proximo-core arm: the {ns.plane} plane is not usable here: {safe_text(str(e))}", file=sys.stderr)
            return EXIT_USAGE
    user = ns.user
    for path in ([target, plane.token_path or ""] if not user else []):
        # the served file's own user, then the plane's own: the identity the vendor already knows this box by.
        # A token line is `user@realm!name=secret`; a line with no `!` names no user (and is not echoed).
        kind, cred = served_credential(path) if path else ("unreadable", "")
        if kind == "token" and isinstance(cred, bytes):
            line = cred.decode("utf-8", errors="replace")
            user = line.split("!", 1)[0].strip() if "!" in line else None
        elif kind == "ticket" and isinstance(cred, dict):
            user = str(cred["user"])
        if user:
            break
    if not user or "@" not in user or "!" in user or not user.isprintable():
        print("proximo-core arm: say who logs in with --user user@realm (the served file names no user)",
              file=sys.stderr)
        return EXIT_USAGE
    print(f"logging in as {safe_text(user)} ({ns.plane})", file=sys.stderr)
    try:
        try:
            out = wire.ticket_login(plane, user, _prompt_secret("password: "))
            if "tfa_challenge" in out:
                out = wire.ticket_login(plane, user, _prompt_secret("second factor: "),
                                        tfa_challenge=out["tfa_challenge"])
        except (EOFError, KeyboardInterrupt):
            print("proximo-core arm: no password given. Nothing was changed.", file=sys.stderr)
            return EXIT_USAGE
        # THE VENDOR'S ANSWER IS READ BEFORE IT IS SERVED: what the one reader cannot read is never written
        # (lens 3: a ticket the reader rejected clobbered the served file and died uncaught).
        data = _json.dumps({"ticket": out["ticket"], "csrf": out["csrf"], "box": plane.base_url}).encode("utf-8")
        kind, cred = credential_from_bytes(data)
        if kind != "ticket" or not isinstance(cred, dict):
            raise ProximoError(f"the vendor's ticket cannot be served: {cred}")
    except httpx.HTTPStatusError as exc:
        status = wire_error(exc).get("status")
        why = (f"{status}: the vendor did not accept the login (a wrong password or second factor, or a user "
               f"with none)" if status == 401 else f"the vendor answered {status} to the login")
        record("core.arm", target="ticket", outcome="refused", detail={"armed": False, "user": user, "status": status})
        if ns.json:
            print(_json.dumps({"armed": False, "target": target, "status": status, "why": why}, indent=2))
        print(f"proximo-core arm: NOT ARMED: {why}. Nothing was changed.", file=sys.stderr)
        return EXIT_REFUSED
    except (httpx.TransportError, ProximoError) as exc:
        record("core.arm", target="ticket", outcome="refused", detail={"armed": False, "user": user,
                                                                       "why": safe_text(str(exc))})
        print(f"proximo-core arm: NOT ARMED: {safe_text(str(exc))}. Nothing was changed.", file=sys.stderr)
        return EXIT_REFUSED
    try:
        staged = _stage(data, target)
        try:
            os.replace(staged, target)
        except BaseException:
            _discard(staged)
            raise
    except OSError as e:
        print(f"proximo-core arm: the ticket could not be served: {safe_text(str(e))}", file=sys.stderr)
        return EXIT_USAGE
    until = datetime.fromtimestamp(cred["issued"] + lifetime, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    record("core.arm", target="ticket", detail={"armed": True, "plane": ns.plane, "user": user, "box": plane.base_url,
                                                "until": until})
    print(_json.dumps({"armed": True, "target": target, "user": user, "until": until}, indent=2) if ns.json
          else f"ARMED: a ticket for {user}, until {until} (the vendor's two hours). Every mutation still plans "
               "first and is recorded. Put it back sooner: proximo-core disarm")
    return EXIT_OK


MEMORY_VERBS = ("learn", "where", "uses", "changed")


def memory_main(verb: str, argv: list[str]) -> int:
    """`proximo-core learn | where <id or name> | uses <storage or bridge> | changed <window>`, each
    with `--plane pve|pbs|pmg|pdm` and `--target NAME`. where, uses and changed answer from the estate memory
    (`core.memory`) with no vendor call and say how old they are; learn is the one deliberate pass that
    fills it, every read through the engine and receipted. 0 answered (an honest "not in memory"
    included), 2 the spine refused (a taint marker that cannot be written), 3 the caller's or the
    box's configuration (memory off, its file refused, no box, a bad window, a plane memory has no
    shape for, uses on a plane that relates nothing)."""
    import sqlite3  # noqa: PLC0415

    from proximo.core import memory, store, wire  # noqa: PLC0415 -- only these verbs need them
    from proximo.core.ledger import LedgerConfig  # noqa: PLC0415

    ap = argparse.ArgumentParser(prog=f"proximo-core {verb}", description=(memory_main.__doc__ or "").split("\n")[0])
    if verb == "where":
        ap.add_argument("words", nargs="+", help=(
            "the vendor's id or exact name, alone or after one of that plane's own type words "
            "(on pve: qemu|lxc|node|storage|pool|bridge|backup, as in lxc 105)"))
    elif verb == "uses":
        ap.add_argument("thing", help="a storage id or a bridge name")
    elif verb == "changed":
        ap.add_argument("window", help="30m, 24h or 7d")
    ap.add_argument("--plane", default="pve", help="pve, pbs, pmg or pdm (default pve)")
    ap.add_argument("--target", default=None, help="a box the PROXIMO_TARGETS registry names; omit for the env box")
    try:
        ns = ap.parse_args(argv)
    except SystemExit as e:
        return EXIT_OK if e.code == 0 else EXIT_USAGE
    try:
        # The caller's and the box's configuration first, each a 3: never mistaken for a verdict.
        if memory.shape(ns.plane) is None:
            raise memory.Unusable(f"the estate memory has no shape for {ns.plane}")
        if verb == "changed":
            store.parse_since(ns.window)
        cfg = registry.plane(ns.plane, ns.target)
        box = cfg.base_url if cfg is not None else wire.env_base_url(ns.plane)
        if not box:
            raise memory.Unusable(f"no box to answer for: set {wire.base_url_var(ns.plane)} or name a --target")
        ledger = LedgerConfig.from_env().audit_log_path
    except (ProximoError, RuntimeError) as e:
        print(f"unconfigured: {safe_text(str(e), paths=True)}", file=sys.stderr)
        return EXIT_USAGE
    try:
        if verb == "learn":
            out = memory.learn(ns.plane, cfg=cfg)
        elif verb == "where":
            out = memory.where(ledger, ns.plane, box, " ".join(ns.words))
        elif verb == "uses":
            out = memory.uses(ledger, ns.plane, box, ns.thing)
        else:
            out = memory.changed(ledger, ns.plane, box, ns.window)
    except memory.Unusable as e:
        print(f"unconfigured: {safe_text(str(e), paths=True)}", file=sys.stderr)
        return EXIT_USAGE
    except ProximoError as e:             # the taint marker could not be written: the spine's refusal
        print(f"refused: {e}", file=sys.stderr)
        return EXIT_REFUSED
    except (OSError, sqlite3.Error) as e:
        print(f"unconfigured: the estate memory could not be read ({safe_exception_text(e, paths=True)})",
              file=sys.stderr)
        return EXIT_USAGE
    print(json.dumps(out, indent=2, sort_keys=True, default=str))
    return EXIT_OK


def _greeted(mutates: bool) -> bool:
    """A call that can mutate greets the ledger with the reach grant first (`reach.greet`); a read,
    a plan and a verb that only prints do not: this door has no start, and a read cannot use a lane."""
    return not mutates or reach.greet("proximo-core", "cli")


def _fingerprinted(value: Any, path: str = "") -> list[str]:
    """The names of the arguments the ledger kept only as a fingerprint (a secret), at any depth."""
    if isinstance(value, str):
        return [path or "?"] if value.startswith("[redacted sha256:") else []
    items = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, list) else ()
    return [n for k, v in items for n in _fingerprinted(v, f"{path}.{k}" if path else str(k))]


def consent_show(argv: list[str]) -> int:
    """`proximo-core consent show <consent_id>`: what a refused mutation proposed, every argument whole, as typed
    JSON, from the ledger row the refusal wrote. A secret stays a fingerprint (secrets.toml judges which). The
    operator's view: no model reads it, so nothing is capped; what could reorder or hide text on a terminal
    (bidi marks, zero-width and control characters: rawdoor's escape rule) is shown as its escape.

    NOTHING IS PRINTED FROM A ROW THAT DOES NOT PROVE ITSELF (the ledger is same-uid writable). The row must
    be the only proposal for its id (the same proposal written twice is one); its `binding` must reproduce over
    the stored proposal, fingerprints included (`spine.consent_binding`); with no fingerprint in it, the id
    must be recomputed from what is shown, box and net included; and the ledger's keyed chain must verify
    (to `PROXIMO_AUDIT_EXPECTED_HEAD` when it is pinned), so a row rewritten with its binding recomputed is
    caught by the chain. Any of those failing exits refused with the arguments unprinted."""
    from proximo.core import rawdoor, spine  # noqa: PLC0415
    from proximo.core.ledger import LedgerConfig, ledger_key, parse_lines, read_log, verify_lines  # noqa: PLC0415
    if len(argv) != 1 or not argv[0].strip():
        print("usage: proximo-core consent show <consent_id>", file=sys.stderr)
        return EXIT_USAGE
    want = argv[0].strip().lower()
    cfg = LedgerConfig.from_env()

    def refuse(why: str) -> int:
        print(f"refused: {rawdoor.echo(why, 400)}", file=sys.stderr)
        return EXIT_REFUSED
    try:
        lines = read_log(cfg.audit_log_path)
    except ProximoError as exc:
        return refuse(str(exc))
    rows = [e for e in parse_lines(lines)
            if e.get("action") == "core.refuse" and isinstance((e.get("detail") or {}).get("proposed"), dict)
            and str(e["detail"]["proposed"].get("consent_id", "")).startswith(want)]
    if not rows or len(want) < 8:
        return refuse(f"no refused call carries consent id {rawdoor.quote(want, 20)} (at least 8 characters)")
    ids = {str(e["detail"]["proposed"].get("consent_id")) for e in rows}
    if len(ids) > 1:
        return refuse(f"{rawdoor.quote(want, 20)} is the start of {len(ids)} consent ids; give more of it")
    proposals = {json.dumps(e["detail"]["proposed"], sort_keys=True, default=str) for e in rows}
    if len(proposals) > 1:
        return refuse(f"more than one different proposal carries consent id {next(iter(ids))[:12]}: "
                      "a forged ledger row; nothing is shown")
    row = rows[-1]
    p = row["detail"]["proposed"]
    cid = str(p.get("consent_id"))
    need = ("plane", "method", "published", "called", "args", "box", "binding")
    if any(k not in p for k in need) or not isinstance(p["args"], dict):
        return refuse(f"the row for consent id {cid[:12]} is not a whole proposal: a forged ledger row")
    if p["binding"] != spine.consent_binding(p):
        return refuse(f"the row does not reproduce the binding of consent id {cid[:12]}: a forged ledger row")
    held = _fingerprinted(p["args"])
    recomputed = spine.consent_id(p["plane"], p["method"], p["published"], p["called"], p["args"], p["box"],
                                  net=str(p.get("net") or ""))
    if not held and recomputed != cid:
        return refuse(f"the row does not reproduce consent id {cid[:12]}: a forged ledger row")
    chain = verify_lines(lines, ledger_key(cfg), pinned_row=os.environ.get("PROXIMO_AUDIT_EXPECTED_HEAD") or None)
    if not chain.ok:
        return refuse(f"the ledger chain does not verify (row {chain.broken_at}: {chain.reason}); "
                      "a proposal on it proves nothing, so nothing is shown")
    shown = {"consent_id": cid, "at": row.get("ts"), "address": f"{p['method']} {p['published']}",
             "called": p["called"], "plane": p["plane"], "box": p["box"], **({"net": p["net"]} if p.get("net") else {}),
             "args": p["args"], "fingerprinted": held, "reproduces_id": not held and recomputed == cid,
             "binding_verified": True, "reason": (row.get("detail") or {}).get("reason")}
    print(json.dumps(rawdoor.plain_deep(shown), indent=2, ensure_ascii=False))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    envfile.load(announce=False, prog="proximo-core")   # the operator's file; quiet: stderr is a contract here
    # These verbs run past a retired switch: disarm DROPS write authority, doctor names the switch,
    # mint and badge print. Arm and every call refuse while one is set.
    if argv[:1] == ["mint"]:
        return mint_main(argv[1:])
    if argv[:1] == ["doctor"]:
        return doctor_main(argv[1:])
    if argv[:1] == ["badge"]:
        return badge_main(argv[1:])
    if argv[:1] == ["disarm"]:
        return arm_main("disarm", argv[1:])
    if argv[:2] == ["consent", "show"]:
        return consent_show(argv[2:])
    if argv[:1] in (["instructions"], ["runbook"]):
        return words_main(argv)
    from proximo.core.doors.network import refuse_surfaces  # noqa: PLC0415
    if refuse_surfaces("proximo-core"):                   # a retired switch still set: told here, not served past
        return EXIT_USAGE
    if argv[:1] == ["audit"]:                             # after the retired-switch refusal, like any call
        return audit_main(argv[1:])
    if argv[:1] == ["arm"] or argv[:1] and argv[0] in MEMORY_VERBS:
        return arm_main("arm", argv[1:]) if argv[0] == "arm" else memory_main(argv[0], argv[1:])
    ap = argparse.ArgumentParser(prog="proximo-core", description=(__doc__ or "").split("\n")[0],
                                 epilog=BANNER, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("plane", help="pve, pbs, pmg or pdm")
    ap.add_argument("method", help="GET, POST, PUT, DELETE, or `undo` (then path is a capture's id)")
    ap.add_argument("path", help="API path, concrete or templated; with `undo`, the id a call returned under undo.id")
    ap.add_argument("args", nargs="*", help="k=v parameters published by the vendor")
    ap.add_argument("--plan", action="store_true",
                    help="show the governed decision, the published schema, the target as it "
                         "stands and, on PVE, what the vendor's own door answers the served token "
                         "(governed reads, receipted); mutate nothing")
    ap.add_argument("--confirm", action="store_true",
                    help="run a mutation. Without it a POST, PUT, DELETE or `undo` prints its plan and "
                         "mutates nothing, as on every other door; a read needs no flag")
    ap.add_argument("--fields", default=None,
                    help="a read's rows are LEAN by default (names, states, ids); 'all' for the "
                         "vendor's rows, 'a,b' for exactly those")
    ap.add_argument("--wait", default=None, type=int,
                    help="seconds (0..600) to poll a task-backed mutation to its end, default 60; "
                         "0 submits only. On a read, allowed on a .../tasks/{upid}/status address")
    ap.add_argument("--since", default=None,
                    help="a read only: what was added, gone and changed over 30m/24h/7d, from the "
                         "snapshots this door kept, no vendor call (a cron job of reads keeps them)")
    ap.add_argument("--diagnose", action="store_true",
                    help="a GET of a node or guest path alone: its health reads (status, storage, "
                         "failed tasks; a guest's status; the container's or the host's fixed shell "
                         "battery when its lane is opted in) through the engine, each receipted, with "
                         "advisory flags; a closed lane is named in the answer, never read as healthy")
    ap.add_argument("--target", default=None,
                    help="a box the PROXIMO_TARGETS registry names, of this plane's kind; its own arm "
                         "pair, forbid and rate govern the call and every receipt names it as remote. "
                         "Omit for the box the environment configures")
    # argparse exits 2 on a usage error, which is EXIT_REFUSED -- so a typo was indistinguishable
    # from a governance refusal, and EXIT_USAGE was unreachable. A script branching on 2 must be
    # reading the spine's verdict, never argv.
    try:
        ns = ap.parse_args(argv)
    except SystemExit as e:
        return EXIT_OK if e.code == 0 else EXIT_USAGE

    token = rawdoor.OPERATOR_VIEW.set(True)    # no model reads this door: a plan prints every argument in full
    try:
        return _run(ns)
    finally:
        rawdoor.OPERATOR_VIEW.reset(token)


def _run(ns: argparse.Namespace) -> int:
    """The verb `main` parsed, run under the operator's view of a plan."""
    try:
        # The box is resolved BEFORE anything is judged: an unknown name, a target of another
        # kind or an unreadable registry is the caller's configuration (3), never a verdict (2).
        cfg = registry.plane(ns.plane, ns.target)
    except ProximoError as e:
        print(f"unconfigured: {e}", file=sys.stderr)
        return EXIT_USAGE
    # --plan WINS over --confirm, everywhere: a line that asks for the plan mutates nothing, whatever else it says.
    run = ns.confirm and not ns.plan
    if not _greeted(ns.method.upper() != "GET" and run and not ns.diagnose):   # a plan greets nobody
        return EXIT_USAGE
    try:
        if ns.diagnose:
            # DIAGNOSE (B3): a read's flag, like --since; the subject is the path, alone.
            if ns.method.upper() != "GET":
                print("usage: diagnose is a read: give GET and the subject's path", file=sys.stderr)
                return EXIT_USAGE
            if ns.args or ns.plan or ns.fields is not None or ns.since is not None or ns.wait is not None:
                print("usage: diagnose takes the path alone: no k=v, --plan, --fields, --since or --wait",
                      file=sys.stderr)
                return EXIT_USAGE
            out = diagnose.run(ns.plane, ns.path, cfg=cfg)
            print(json.dumps(out, separators=(",", ":"), sort_keys=True, default=str))
            return EXIT_OK
        if ns.method.lower() == "undo":
            # The restore (B2): its plan unless --confirm; the id is the path argument.
            if ns.args:
                raise ProximoError("undo takes no arguments: the capture is the argument; drop k=v")
            out = undo.restore(ns.path, plane=ns.plane, cfg=cfg, confirm=run, wait=ns.wait)
            print(json.dumps(out, separators=(",", ":"), sort_keys=True, default=str))
            if not out.get("allowed", True):
                return EXIT_REFUSED
            ended = exit_of(out, ns.wait) if run else EXIT_OK   # a restore that ran: its write's own end
            if ended != EXIT_OK:
                return ended
            return EXIT_OK if run or ns.plan or out.get("status") != "plan" else _not_run()
        row = engine.resolve(ns.plane, ns.method, ns.path)
        args = parse_args(ns.args)
        # PLAN BY DEFAULT, AS ON EVERY OTHER DOOR. Until 2026-11-19 a bare mutation here RAN, the one door
        # where it did, and the README's "nothing moves without confirm" was false of it (the 2026-11-19
        # read). A mutation now runs only with --confirm; without it the plan is printed and nothing moves.
        if ns.plan or (row.access != engine.READ and not run):
            out = engine.plan(row, args, ns.path, cfg=cfg, detail=ns.fields)   # --fields: the full schema of those
            print(json.dumps(out, separators=(",", ":"), sort_keys=True))
            if not out["allowed"]:
                return EXIT_REFUSED
            return EXIT_OK if ns.plan else _not_run()
        out = engine.execute(row, args, path=ns.path, cfg=cfg, fields=ns.fields, since=ns.since, wait=ns.wait)
        print(json.dumps(out, separators=(",", ":"), sort_keys=True, default=str))
        return exit_of(out, ns.wait, command=row.access != engine.READ and row.wire == "ssh")
    except ProximoError as e:
        print(f"refused: {e}", file=sys.stderr)
        return EXIT_REFUSED
    except RuntimeError as e:
        # An unconfigured estate. Not a governance refusal and not the caller's syntax error:
        # it raised as an uncaught traceback with exit 1, which is in no contract at all.
        print(f"unconfigured: {e}", file=sys.stderr)
        return EXIT_USAGE
    except httpx.HTTPStatusError as e:
        # The vendor answered and said no (403, 500, ...). Not our refusal, not the caller's
        # syntax: a script must be able to tell "Proxmox refused" from "the spine refused".
        # The body is the vendor's reason; it goes out redacted and bounded.
        print(f"vendor: HTTP {e.response.status_code}: {safe_exception_text(e)}", file=sys.stderr)
        return EXIT_VENDOR
    except httpx.TransportError as e:
        print(f"vendor: unreachable: {safe_exception_text(e)}", file=sys.stderr)
        return EXIT_VENDOR
    except (KeyError, ValueError, OSError) as e:
        print(f"usage: {e}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
