"""The shell door — Proximo with no model, no agent and no protocol in the loop.

THIS IS THE REFERENCE DOOR, not a convenience wrapper. If the engine is governable from a bash
script and a cron job, then MCP, A2A and HTTP are protocol adapters over the same decisions
rather than three places where governance might differ. Agent-agnostic stops being a claim in a
README and becomes a property the test suite checks.

    proximo-core pve GET /nodes/pve1/status
    proximo-core pve DELETE /nodes/pve1/qemu/101 purge=1
    proximo-core pve GET /nodes --target east      # a box PROXIMO_TARGETS names

Exit codes are the contract for scripts: 0 executed, 2 refused by the spine, 3 the caller's
own mistake (bad syntax, unconfigured estate), 4 the vendor refused or could not be reached.
Anything else is a bug in Proximo and prints a traceback on purpose: a crash must not be
laundered into a tidy refusal, because a script that cannot tell "the spine said no" from "the
door broke" will retry the wrong one.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import httpx

from proximo.core import diagnose, doctor, engine, envfile, registry, undo
from proximo.core.doors import BANNER
from proximo.core.errors import ProximoError
from proximo.core.secretfile import safe_exception_text, safe_text

EXIT_OK, EXIT_REFUSED, EXIT_USAGE, EXIT_VENDOR = 0, 2, 3, 4


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


def doctor_main(argv: list[str]) -> int:
    """`proximo-core doctor`: the gate diagnoses itself (the record, the planes, the chain, the
    pillars). Vendor reads only, each receipted like any read; JSON out; the exit is the door's
    contract and the flags move it not."""
    if argv:
        print("usage: doctor takes no arguments", file=sys.stderr)
        return EXIT_USAGE
    report = doctor.run()
    code = report.pop("exit")
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
    import tempfile  # noqa: PLC0415
    with open(src, "rb") as f:
        data = f.read()
    directory = os.path.dirname(os.path.abspath(dst)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tok.", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        os.replace(tmp, dst)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


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
    """`proximo-core arm|disarm [--json]`: CONSENT's switch, the operator's hand. `arm` installs the
    write token's bytes (`PROXIMO_ARM_SOURCE`) at the served token path (`PROXIMO_TOKEN_PATH`);
    `disarm` installs the read-only token's (`PROXIMO_READONLY_SOURCE`). The engine's arm predicate
    reads the served file per call (`core.arm`: armed <=> served bytes == arm source bytes), so the
    swap takes effect on the next call, no restart. Refusals, rc 3: an unset or unusable source;
    a disarm whose read-only source is byte-identical to the write token (it would install write
    authority and report DISARMED). Each swap is a ledger row. The 0.44 verb's per-session arms
    and the `reap` of stale ones were LEASE (retired to the vendor's own `expire`); this verb is
    global, as the predicate is."""
    import json as _json  # noqa: PLC0415

    from proximo.core.arm import ARM_SOURCE_ENV, READONLY_SOURCE_ENV, TOKEN_PATH_ENV  # noqa: PLC0415
    from proximo.core.doors.network import recorder  # noqa: PLC0415

    ap = argparse.ArgumentParser(prog=f"proximo-core {verb}")
    ap.add_argument("--json", action="store_true", help="emit the result as JSON")
    ns = ap.parse_args(argv)
    try:
        target = os.environ.get(TOKEN_PATH_ENV, "").strip()
        if not target:
            raise ValueError(f"{TOKEN_PATH_ENV} is unset: there is no served token path to install at")
        if os.path.islink(target):
            raise ValueError(f"refusing to install over a symlink: {target}")
        if verb == "arm":
            src = _source(ARM_SOURCE_ENV, "write token (arm source)")
        else:
            src = _source(READONLY_SOURCE_ENV, "read-only token")
            armed = os.environ.get(ARM_SOURCE_ENV, "").strip()
            if armed:
                try:
                    with open(armed, "rb") as a, open(src, "rb") as r:
                        same = a.read() == r.read()
                except OSError:
                    same = False   # nothing to compare; refusing here would leave write authority live
                if same:
                    raise ValueError("refusing to disarm: the read-only source is byte-identical to the write "
                                     f"token at {ARM_SOURCE_ENV}, so restoring it would install write authority "
                                     f"and report DISARMED. Point {READONLY_SOURCE_ENV} at a genuinely read-only "
                                     "credential. Nothing was changed.")
        _install_atomic(src, target)
    except (OSError, ValueError, RuntimeError) as e:   # RuntimeError: an exposed source, refuse_exposed_secret's
        print(f"proximo-core {verb}: {safe_text(str(e))}", file=sys.stderr)
        return EXIT_USAGE
    recorder("proximo-core")(f"core.{verb}", target="token", detail={"armed": verb == "arm"})
    result = {"armed": verb == "arm", "target": target}
    print(_json.dumps(result, indent=2) if ns.json else
          ("ARMED: the served token is the write token; every mutation still plans first and is recorded."
           if verb == "arm" else "DISARMED: the served token is the read-only token."))
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
    from proximo.core.doors.network import refuse_surfaces  # noqa: PLC0415
    if refuse_surfaces("proximo-core"):                   # a retired switch still set: told here, not served past
        return EXIT_USAGE
    if argv[:1] == ["arm"]:
        return arm_main("arm", argv[1:])
    ap = argparse.ArgumentParser(prog="proximo-core", description=(__doc__ or "").split("\n")[0],
                                 epilog=BANNER, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("plane", help="pve, pbs, pmg or pdm")
    ap.add_argument("method", help="GET, POST, PUT, DELETE, or `undo` (then path is a capture's id)")
    ap.add_argument("path", help="API path, concrete or templated; with `undo`, the id a call returned under undo.id")
    ap.add_argument("args", nargs="*", help="k=v parameters published by the vendor")
    ap.add_argument("--plan", action="store_true",
                    help="show the governed decision, the published schema and the target as it "
                         "stands (one governed read, receipted); mutate nothing")
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

    try:
        # The box is resolved BEFORE anything is judged: an unknown name, a target of another
        # kind or an unreadable registry is the caller's configuration (3), never a verdict (2).
        cfg = registry.plane(ns.plane, ns.target)
    except ProximoError as e:
        print(f"unconfigured: {e}", file=sys.stderr)
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
            print(json.dumps(out, indent=2, sort_keys=True, default=str))
            return EXIT_OK
        if ns.method.lower() == "undo":
            # The restore (B2): plan with --plan, run without; the id is the path argument.
            if ns.args:
                raise ProximoError("undo takes no arguments: the capture is the argument; drop k=v")
            out = undo.restore(ns.path, plane=ns.plane, cfg=cfg, confirm=not ns.plan, wait=ns.wait)
            print(json.dumps(out, indent=2, sort_keys=True, default=str))
            return EXIT_OK if out.get("allowed", True) else EXIT_REFUSED
        row = engine.resolve(ns.plane, ns.method, ns.path)
        args = parse_args(ns.args)
        if ns.plan:
            out = engine.plan(row, args, ns.path, cfg=cfg)  # published_parameters is a plain dict: JSON-able
            print(json.dumps(out, indent=2, sort_keys=True))
            return EXIT_OK if out["allowed"] else EXIT_REFUSED
        out = engine.execute(row, args, path=ns.path, cfg=cfg, fields=ns.fields, since=ns.since, wait=ns.wait)
        print(json.dumps(out, indent=2, sort_keys=True, default=str))
        return EXIT_OK
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
