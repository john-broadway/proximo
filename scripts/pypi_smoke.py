#!/usr/bin/env python3
"""Cold-start smoke against an INSTALLED proximo — the shared verifier for the adopter path.

Extracted from release-pypi.yml's inline verify step (2026-08-20; every check preserved, one
seam rerouted — see the floor note below) so two workflows run ONE verifier instead of
drifting copies:

- release-pypi.yml `verify-pypi`: after a publish, both mcp majors, pinned per leg.
- pypi-smoke.yml (daily): the published wheel fresh-resolved from PyPI — the path an adopter's
  bare `uvx proximo-proxmox` takes, which between releases nothing else exercised (the residual
  named by the 2026-08-20 external report; the mcp 2.0.0 class bit two repos in August).

Runs INSIDE the venv holding the install (it imports the mcp client): invoke it as
`<venv>/bin/python scripts/pypi_smoke.py`; the server binary is found beside sys.executable.

Env contract:
- PROXIMO_SMOKE_VERSION (required): the version the installed server must report ("v" prefix ok).
- PROXIMO_SMOKE_MCP_MAJOR (optional): "1"/"2" — assert the venv's mcp pin HELD (an unpinned
  resolve following PyPI's whim is exactly how the v0.33.0 run broke). Unset = no pin to hold
  (the daily adopter leg is deliberately unpinned); the resolved major is printed either way.
  The dual-major serverInfo seam comes from the INSTALLED package's own _mcpcompat helper,
  never spelled here — the seam guard bans per-major reads outside that module, scripts too.

Failures are explicit sys.exit calls, never assert: this runs as an ops verifier, and an
assert vanishes under `python -O` — a check that can be optimized away is not a check.

Checks are deliberately version-agnostic (name, version echo, non-empty tools/list): the
daily run verifies whatever is currently PUBLISHED with whatever script is on main, so anything
tied to one release's surface belongs in the calling workflow, not here.
"""
import asyncio
import importlib.metadata
import os
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# FLOOR: the seam module entered the wheel at 0.33.0 (the dual-major port). The inline
# original spelled the per-major serverInfo read itself and could verify any wheel; routing
# through the installed package's seam trades that for one source of truth, so a verify-only
# dispatch of a pre-0.33.0 version fails HERE, by name, not three steps later on a bare
# ModuleNotFoundError.
try:
    from proximo._mcpcompat import init_server_info
except ImportError:
    sys.exit("pypi-smoke FAILED: this proximo wheel predates the _mcpcompat seam (0.33.0) — "
             "versions below v0.33.0 cannot be verified by this script")


def fail(msg: str) -> None:
    sys.exit(f"pypi-smoke FAILED: {msg}")


want = os.environ["PROXIMO_SMOKE_VERSION"].lstrip("v")
resolved = importlib.metadata.version("mcp")
pin = os.environ.get("PROXIMO_SMOKE_MCP_MAJOR")
if pin and int(resolved.split(".")[0]) != int(pin):
    # The leg's pin must have held — an unpinned resolve following PyPI's whim is exactly
    # how the v0.33.0 run broke.
    fail(f"venv resolved mcp {resolved}, leg pins major {pin}")

# The server binary installed beside this interpreter — works for any venv layout.
proximo_bin = os.path.join(os.path.dirname(sys.executable), "proximo")
if not os.path.exists(proximo_bin):
    fail(f"no proximo binary beside {sys.executable}")


async def main():
    d = tempfile.mkdtemp()
    tok = os.path.join(d, "verify.tok")
    with open(tok, "w") as fh:
        fh.write("verify@pam!t=00000000-0000-0000-0000-000000000000")  # dummy; no live PVE
    os.chmod(tok, 0o600)  # the config guard refuses group/other-readable tokens
    env = {
        **os.environ,
        "PROXIMO_API_BASE_URL": "https://127.0.0.1:8006/api2/json",  # unreachable on purpose
        "PROXIMO_NODE": "verify-node",
        "PROXIMO_TOKEN_PATH": tok,
        "PROXIMO_VERIFY_TLS": "true",
        "PROXIMO_AUDIT_LOG": os.path.join(d, "verify-audit.log"),
    }
    params = StdioServerParameters(command=proximo_bin, args=[], env=env)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            init = await asyncio.wait_for(s.initialize(), timeout=60)
            si = init_server_info(init)
            if si.name != "proximo":
                fail(f"server identifies as {si.name!r}, not 'proximo'")
            got = si.version
            if got != want:
                fail(f"published wheel reports {got}, expected {want}")
            tools = await asyncio.wait_for(s.list_tools(), timeout=60)
            n = len(tools.tools)
            if n == 0:
                fail("tools/list returned an empty surface")
            print(f"cold-start OK on mcp {resolved}: proximo {got}, {n} tools served")


asyncio.run(main())
