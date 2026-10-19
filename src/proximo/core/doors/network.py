"""What the core's network doors share: their rows, and the one way a door comes up.

Three doors serve the core over the network (`mcphttp`, `http`, `a2a`), each the 0.44 face's
perimeter with the core behind it. What differs is the protocol and the port; what is the same is
here, once: how a door writes its own rows (arrival, departure, the badge camera's callers, a
face's rejections) through the core's ONE ledger opener, and how `main` reads the face's env,
refuses a public bind with no token, builds the app, serves and stamps `session_end` even when the
host dies. A door module is its `FACE`, its `build_app`, and a call to `main_of`.

What a core door does NOT carry from its 0.44 twin, said once: `PROXIMO_SURFACES` (refused at
start; the core has no surfaces), the 0.44 server's reach-grant check at serve time (parity row
B16), and session rows land on every start and stop (0.44 wrote them only with the principal
feature configured).
"""
from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from typing import Any

from proximo.core import envfile
from proximo.core.doors import BANNER
from proximo.core.errors import ProximoError
from proximo.core.principal import ledger_principal, set_serving_face

Recorder = Callable[..., None]


def recorder(prog: str) -> Recorder:
    """The door's row writer: `record(action, target=, outcome=, detail=)`, the shape
    `guard.guard_middleware` and the perimeter's rejection paths call. Best-effort: a box whose
    ledger cannot be written still refuses every mutation (those rows are required), so a missing
    door row must not stop the door, but it must not be silent either."""
    def record(action: str, *, target: str, outcome: str = "ok", detail: dict | None = None) -> None:
        from proximo.core.ledger import LedgerConfig, open_ledger
        try:
            open_ledger(LedgerConfig.from_env()).record(
                action, target=target, outcome=outcome, detail=detail or {},
                principal=ledger_principal())
        except Exception as e:  # noqa: BLE001 -- reported, never raised: see the docstring
            print(f"{prog}: {action} not recorded ({type(e).__name__})", file=sys.stderr)
    return record


def refuse_surfaces(prog: str) -> bool:
    """A door refuses to START on a switch the core does not read, so a box configured for a gate
    the core no longer keeps is told at the door, not served wider. PROXIMO_SURFACES: the 0.44
    faces scoped their 900 tools by it; the core has six tools over every address and no surfaces
    to pick. PROXIMO_SCOPE_PATH / PROXIMO_ARM_TTL: SCOPE and LEASE, retired to the vendor
    (`spine.retired_refusal`, which the engine also raises per call). True = refused (rc 3)."""
    from proximo.core import spine  # noqa: PLC0415
    if os.environ.get("PROXIMO_SURFACES", "").strip():
        print(f"{prog}: PROXIMO_SURFACES is set, and the core has no surfaces (six tools, every "
              "published address): unset it for this door", file=sys.stderr)
        return True
    retired = spine.retired_refusal()
    if retired is not None:
        print(f"{prog}: {retired.reason}", file=sys.stderr)
        return True
    return False


def main_of(prog: str, face: str, *, prefix: str, default_port: int, token_env: str, help_: str,
            doc: str, extra_env: str, build: Callable[[str, str | None, list[str] | None], Any],
            argv: list[str] | None = None) -> int:
    """A door's `main`: `--help` and nothing else on the command line (an unknown argument refuses,
    rc 3), the operator's env file sourced (`core.envfile`), the face set before any row, the env
    read (`PROXIMO_{prefix}_HOST/_PORT/_TOKEN_FILE/_ALLOWED_HOSTS`), a public bind with no token
    refused before a socket exists, the app built by
    `build(url, token, allowed_hosts)`, served; `session_start` and `session_end` rows land
    through the core's ledger, the second in a `finally` so a stop is still an exit with a row.
    A missing extra is the one-line hint `help_`, never a traceback."""
    ap = argparse.ArgumentParser(
        prog=prog, description=doc.split("\n")[0],
        epilog=f"configured by env: PROXIMO_{prefix}_HOST (127.0.0.1), _PORT ({default_port}), "
               f"_TOKEN_FILE (required off loopback), _ALLOWED_HOSTS{extra_env}\n\n" + BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    try:
        ap.parse_args(argv)
    except SystemExit as e:
        return 0 if e.code == 0 else 3
    envfile.load(prog=prog)   # the operator's file, before the first env read; the process env wins
    set_serving_face(face)
    record = recorder(prog)
    if refuse_surfaces(prog):
        return 3
    try:
        import uvicorn  # noqa: F401 -- probed here so a missing extra is the hint, not a traceback

        from proximo.core.perimeter.guard import read_face_env, require_auth_for_public, serve, url_authority
        host, port, token, allowed = read_face_env(prefix, default_port=default_port)
        require_auth_for_public(host, token, where="bind host", face=face.upper(), token_env=token_env)
        app = build(f"http://{url_authority(host)}:{port}/", token, allowed)
    except ImportError:
        print(f"{prog}: {help_}", file=sys.stderr)
        return 3
    except (ProximoError, ValueError, RuntimeError) as e:
        print(f"{prog}: {e}", file=sys.stderr)
        return 3
    print(BANNER, file=sys.stderr)
    record("session_start", target=f"face/{face}", detail={"face": face})
    try:
        serve(app, host=host, port=port)   # a systemd stop is an exit: session_end still lands
    finally:
        record("session_end", target=f"face/{face}", detail={"face": face})
    return 0
