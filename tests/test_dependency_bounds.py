"""Every runtime dependency must bound its MAJOR version.

Earned 2026-07-30, the hard way. `pyproject.toml` declared `mcp>=1.2.0` with no upper bound.
The MCP SDK published 2.0.0 on 2026-07-28, which removed `mcp.server.fastmcp` — the module
`proximo.server` imports on line 29. From that moment every fresh `pip install
proximo-proxmox` (any version) resolved mcp 2.0.0 and could not import the package at all.
`uvx proximo-proxmox`, the zero-install path the README leads with, was broken too.

Nothing in this repo could see it: `uv.lock` and the hash-pinned `requirements/*.txt` hold mcp
at a 1.x, so CI, the container and every local run were fine. Those pins deliberately do NOT
enter the wheel — PyPI consumers resolve their own dependencies, which is exactly the hole.
A lockfile protects the build; only a bound in the metadata protects an adopter.

So: this test reads the metadata an adopter actually resolves against, and fails on any runtime
requirement that leaves the next major version open.
"""
from __future__ import annotations

import re
import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"

# A bound that closes the CURRENT major: `<2`, `<2.0`, `<2.0.0`, or `~=1.2` / `==1.*`.
_BOUNDED = re.compile(r"<\s*\d|~=|==\s*\d+\.\*")


# `dev` is exempt, and the reason is a real distinction rather than a convenience: nobody
# installs it off PyPI to USE proximo. It is resolved by `uv sync --extra dev` against the
# committed uv.lock, which pins exact versions with hashes — so a breaking upstream major
# cannot reach a contributor unnoticed the way it reaches an adopter. Every extra an ADOPTER
# can type (`[a2a]`, `[http]`, `[mcp-http]`) is checked.
_LOCK_PROTECTED = {"dev"}


def _requirements() -> list[tuple[str, str]]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    out: list[tuple[str, str]] = [("dependencies", r) for r in data["project"]["dependencies"]]
    for extra, reqs in (data["project"].get("optional-dependencies") or {}).items():
        if extra in _LOCK_PROTECTED:
            continue
        out += [(f"optional-dependencies.{extra}", r) for r in reqs]
    return out


def test_every_runtime_requirement_bounds_its_major():
    unbounded = [f"{where}: {req}" for where, req in _requirements()
                 if not _BOUNDED.search(req)]
    assert not unbounded, (
        "these requirements leave the next major version open, so a breaking release by an "
        "upstream project silently breaks every new install off PyPI — bound the major "
        "(e.g. 'mcp>=1.2.0,<2'):\n  " + "\n  ".join(unbounded)
    )


def test_the_mcp_bound_excludes_the_sdk_major_that_removed_fastmcp():
    """Named explicitly, because this is the one that actually bit."""
    reqs = [r for where, r in _requirements()
            if where == "dependencies" and r.split(">=")[0].strip() == "mcp"]
    assert reqs, "mcp is a runtime dependency; it must stay declared"
    assert all("<2" in r.replace(" ", "") for r in reqs), (
        f"mcp must be capped below 2.0.0 until proximo.server is ported off "
        f"mcp.server.fastmcp, which 2.x removed: {reqs}")
