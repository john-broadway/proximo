"""THE PROPERTY JOHN ASKED FOR, asserted mechanically: "with or without you".

The core runs with no model, no agent and no protocol in the loop. Two claims carry that,
and a dependency claim nobody tests is a comment:

  1. Importing the shell door loads httpx and NOTHING ELSE from outside the standard library.
     Stated positively (the allowed set), not negatively ("not mcp"): a negative list is green
     the day a second SDK sneaks in under a name it did not list.
  2. The built wheel's `proximo-core` script answers a --plan in a fresh interpreter on a box
     that holds no credential. That is the sentence "it can operate from the shell with or
     without you" as an exit code.

The core was briefly its own distribution (`proximo-core`, httpx only). The owner's ruling
(2026-09-22) is ONE distribution, `proximo-proxmox`, so the property moved from "installs with
httpx only" to "its import closure adds nothing to httpx": the doors never drag the MCP SDK,
pydantic or the big server in, and that is measured, not listed.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys

import pytest

# Fixed literal argv throughout, no interpolation of untrusted input (the house pattern of
# tests/test_seam_guard.py), so the two subprocess lints are off for this file.
# ruff: noqa: S603, S607

CORE = pathlib.Path(__file__).resolve().parent.parent

_PROBE = """
import sys
{imports}
roots = {{m.split(".")[0] for m in sys.modules}}
print(" ".join(sorted(r for r in roots
      if r not in sys.stdlib_module_names and not r.startswith("_") and r != "proximo")))
"""


def _third_party_after(imports: str) -> set[str]:
    out = subprocess.run([sys.executable, "-c", _PROBE.format(imports=imports)],
                         capture_output=True, text=True, check=True)
    return set(out.stdout.split())


def test_the_door_adds_nothing_to_what_httpx_alone_loads():
    """Measured against `import httpx` in the SAME interpreter, not against a list typed here:
    httpx pulls click and pygments in when they happen to be installed (its own CLI), and a
    hand-written allowed set is either wrong on this venv or wrong on a clean one. The
    property is that the core adds NOTHING of its own; what httpx does is httpx's."""
    baseline = _third_party_after("import httpx")
    # The MCP door module is imported too: its SDK import lives INSIDE build_server(), and this
    # is what keeps it there. A module-level `import mcp` in doors/mcp.py goes red here.
    door = _third_party_after("import proximo.core.doors.cli, proximo.core.doors.mcp, "
                              "proximo.core.doors.mcphttp, proximo.core.doors.http, "
                              "proximo.core.doors.a2a, proximo.core.wire")
    assert "httpx" in door, "the probe did not load the wire, so it proved nothing"
    assert door <= baseline, f"the core reached outside httpx: {sorted(door - baseline)}"


def test_the_sdk_is_not_in_the_doors_closure():
    """Importing the core's doors must not load the MCP SDK or pydantic as a side effect: the
    shell door answers on a box with neither installed."""
    out = subprocess.run(
        [sys.executable, "-c", "import proximo.core.doors.cli, proximo.core.doors.mcp, "
         "proximo.core.doors.mcphttp, proximo.core.doors.http, proximo.core.doors.a2a, sys; "
         "print(sorted(m for m in sys.modules if m in ('mcp', 'pydantic')))"],
        capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]", out.stdout


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")
def test_the_built_distribution_answers_from_the_shell(tmp_path):
    """Fresh venv, the one distribution built from this tree, and the `proximo-core` script
    answers `--plan` on a box that holds no credential at all. Skipped where uv is absent (the
    GitHub matrix); the internal runner has it, so the proof runs on every push to canon."""
    venv = tmp_path / "venv"
    env = {k: v for k, v in os.environ.items() if not k.startswith("PROXIMO_") or k == "PROXIMO_ENV_FILE"}
    env["VIRTUAL_ENV"] = str(venv)
    subprocess.run(["uv", "venv", "-q", str(venv)], check=True, env=env)
    subprocess.run(["uv", "pip", "install", "-q", "--python", str(venv / "bin" / "python"), str(CORE)],
                   check=True, env=env)
    door = venv / "bin" / "proximo-core"
    plan = subprocess.run([str(door), "pve", "DELETE", "/nodes/x/qemu/1", "--plan"],
                          capture_output=True, text=True, env=env)
    assert plan.returncode == 2, plan.stderr            # refused by the spine: not armed, no tier
    assert '"allowed": false' in plan.stdout and '"needs": "arm"' in plan.stdout
    read = subprocess.run([str(door), "pve", "GET", "/nodes/x/status", "--plan"],
                          capture_output=True, text=True, env=env)
    assert read.returncode == 0 and '"access": "read"' in read.stdout, read.stderr
    listing = subprocess.run([str(venv / "bin" / "python"), "-c",
                              "import importlib.metadata as m; print(sorted(d.name for d in m.distributions()))"],
                             capture_output=True, text=True, check=True, env=env).stdout
    assert "proximo-proxmox" in listing and "proximo-core" not in listing, listing
