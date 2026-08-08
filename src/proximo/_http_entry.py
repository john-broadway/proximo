"""Console-script shim for ``proximo-http``.

The HTTP face is an optional extra, but the console script is registered in the base wheel.
Importing ``proximo.httpface``'s server path without the extra raises ModuleNotFoundError
inside the starlette/uvicorn import chain; this shim turns that into a one-line install hint
instead of a traceback. (Same shape as ``_a2a_entry`` — the [http] extra is starlette +
uvicorn only, no a2a-sdk.)
"""

from __future__ import annotations

import sys

# Top-level modules the [http] extra provides — only their absence means "extra not installed".
# Any other ModuleNotFoundError is a real bug and must traceback, not hide behind the hint.
_EXTRA_MODULES = ("starlette", "uvicorn")


def main() -> None:
    # --help must print usage and EXIT — never bind a socket. Checked FIRST, before load_env_file()
    # and before the extra-probe, and stdlib-only so it works on a wheel without the [http] extra.
    from proximo.config import print_face_usage, wants_help
    if wants_help(sys.argv[1:]):
        print_face_usage("proximo-http", "HTTP", 41242, "http")
        raise SystemExit(0)
    # Source proximo.env before the app reads any config (same footgun + fail-dangerous shape as
    # the stdio path — the HTTP face routes through the same trust core, so a silently-inert
    # PROXIMO_CONSENT_DIR would leave it ungated too). Real/inline env still wins.
    from proximo.config import load_env_file
    load_env_file()
    try:
        # main() imports uvicorn lazily at serve time and build_app imports starlette lazily —
        # probe both HERE so a missing extra gets the hint below, not a traceback mid-startup.
        import starlette  # noqa: F401
        import uvicorn  # noqa: F401

        from proximo.httpface import main as http_main
    except ModuleNotFoundError as exc:
        # Exact top-level match only: a missing SUBmodule (e.g. 'starlette._core') means the
        # package is installed but broken — that must traceback so the real error is visible.
        missing = exc.name or ""
        if missing not in _EXTRA_MODULES:
            raise
        print(
            f"proximo-http needs the optional HTTP dependencies ('{missing}' is not installed).\n"
            'Install them with:  pip install "proximo-proxmox[http]"',
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    http_main()
