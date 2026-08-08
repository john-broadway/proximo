"""Console-script shim for ``proximo-mcp-http``.

The MCP-over-streamable-HTTP face is an optional extra, but the console script is registered in
the base wheel. Importing ``proximo.mcphttp``'s server path without the extra raises
ModuleNotFoundError inside the starlette/uvicorn import chain; this shim turns that into a
one-line install hint instead of a traceback. (Same shape as ``_http_entry`` — the [mcp-http]
extra is starlette + uvicorn + the SDK's streamable-HTTP floor, no a2a-sdk.)
"""

from __future__ import annotations

import sys

# Top-level modules the [mcp-http] extra provides — only their absence means "extra not
# installed". Any other ModuleNotFoundError is a real bug and must traceback, not hide behind
# the hint. (``mcp`` itself is a base dep, so it is never probed here; the extra only raises
# its version floor for the streamable-HTTP API.)
_EXTRA_MODULES = ("starlette", "uvicorn")


def main() -> None:
    # --help must print usage and EXIT — never bind a socket. Checked FIRST, before load_env_file()
    # and the extra-probe, and stdlib-only so it works on a wheel without the [mcp-http] extra.
    from proximo.config import print_face_usage, wants_help
    if wants_help(sys.argv[1:]):
        print_face_usage("proximo-mcp-http", "MCP_HTTP", 41243, "mcp-http")
        raise SystemExit(0)
    # Source proximo.env before the app reads any config (same footgun + fail-dangerous shape as
    # the stdio path — this face serves the same trust core, so a silently-inert
    # PROXIMO_CONSENT_DIR would leave it ungated too). Real/inline env still wins.
    from proximo.config import load_env_file
    load_env_file()
    try:
        # main() imports uvicorn lazily at serve time and build_app imports starlette lazily —
        # probe both HERE so a missing extra gets the hint below, not a traceback mid-startup.
        import starlette  # noqa: F401
        import uvicorn  # noqa: F401

        from proximo.mcphttp import main as mcp_http_main
    except ModuleNotFoundError as exc:
        # Exact top-level match only: a missing SUBmodule (e.g. 'starlette._core') means the
        # package is installed but broken — that must traceback so the real error is visible.
        missing = exc.name or ""
        if missing not in _EXTRA_MODULES:
            raise
        print(
            f"proximo-mcp-http needs the optional MCP-HTTP dependencies ('{missing}' is not installed).\n"
            'Install them with:  pip install "proximo-proxmox[mcp-http]"',
            file=sys.stderr,
        )
        raise SystemExit(2) from None
    mcp_http_main()
