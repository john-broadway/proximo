"""Every runtime dependency must bound its MAJOR version.

Earned 2026-07-30, the hard way. `pyproject.toml` declared `mcp>=1.2.0` with no upper bound.
The MCP SDK published 2.0.0 on 2026-07-28, which removed `mcp.server.fastmcp` — the module
`proximo.server` imported at the time (the A13 dual-major port later moved that import behind
the `_mcpcompat` seam). From that moment every fresh `pip install
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


def test_the_cryptography_floor_excludes_the_bleichenbacher_range():
    """Named explicitly, because this is the second one that actually bit — and the test above
    could not see it.

    GHSA-g6cj-pr64-35w5 (HIGH, 2026-08-03) affects `cryptography>=44.0.0,<50.0.0`. Through
    0.31.0 the adopter-facing extras declared `cryptography>=49.0.0,<50`, which held every
    `[a2a]` / `[http]` / `[mcp-http]` install INSIDE the affected range with no resolution path
    to the patched 50.0.0 — our own bound, not an upstream one.

    `test_every_runtime_requirement_bounds_its_major` cannot catch that and never could: it asks
    only whether SOME upper bound closes the next major. Proven by mutation — lowering the floor
    to `>=49.0.0`, or all the way to `>=44.0.0`, leaves that test green. The ceiling and the floor
    carry different properties: the ceiling stops a breaking upstream major, the floor is what
    excludes a known-vulnerable range. Only the ceiling had a guard, so the floor gets its own.

    Deliberately a version literal rather than a live advisory lookup: this test must fail
    offline, in CI, and in a year, without depending on a network service still serving the same
    JSON. Raise the floor here when a future advisory forces it; do not lower it to make a
    resolution problem go away.
    """
    floor = (50, 0, 0)
    offenders: list[str] = []
    for where, req in _requirements():
        name, _, spec = req.partition(">=")
        if name.strip().split("[")[0] != "cryptography":
            continue
        got = tuple(int(p) for p in spec.split(",")[0].strip().split(".") if p.isdigit())
        if got < floor:
            offenders.append(f"{where}: {req}")
    assert not offenders, (
        "these extras admit a cryptography version inside GHSA-g6cj-pr64-35w5's affected range "
        f"(>=44.0.0,<50.0.0) — the floor must stay at or above {'.'.join(map(str, floor))}:\n  "
        + "\n  ".join(offenders)
    )


# The mcp majors this build actually RUNS, proven by the full suite on each (the CI matrix
# re-proves both on every push). A new major joins this set only when its port lands — never
# because the resolver found it. Twin of _mcpcompat's own closed-set assertion.
SUPPORTED_MAJORS = {"mcp": {1, 2}}


def test_the_mcp_bounds_admit_exactly_the_supported_majors():
    """Replaces the `<2`-era guard, and NOT with a substring: pacioli's twin of the old check
    (`"<2" in req`) was proven to pass `<2.5` — which resolves mcp 2.0.0 — because a substring
    answers an easier question than "what does this range admit". `packaging` evaluates the
    real specifier. Three properties, each with teeth: every supported major is admitted, the
    floor stays at the MEASURED 1.24 (1.2.0 could not import; 1.22-1.23 could not run the
    suite — see pyproject's dependency comment), and the unproven next major is excluded
    including its prereleases (the exact unbounded shape of the 2026-07-30 outage)."""
    from packaging.requirements import Requirement

    mcp_reqs = [Requirement(r) for where, r in _requirements() if where == "dependencies"
                and Requirement(r).name == "mcp"]
    assert mcp_reqs, "mcp is a runtime dependency; it must stay declared"
    spec = mcp_reqs[0].specifier

    for major in sorted(SUPPORTED_MAJORS["mcp"]):
        assert spec.contains(f"{major}.99.0"), (
            f"mcp major {major} is suite-proven supported but the declared range {spec} "
            f"excludes it")
    assert spec.contains("1.24"), (
        f"the range {spec} excludes the measured floor 1.24 itself — a silently RAISED floor "
        "is a compat break for adopters on the proven releases (the first lens caught this "
        "assertion missing: without it, '>=1.28,<3' passed every bounds test)")
    assert not spec.contains("1.23.0"), (
        f"the range {spec} admits releases below the measured floor 1.24 — 1.21.1-1.23 import "
        "but cannot run the suite (no streamable_http_client), and 1.21.0 and below cannot "
        "import proximo (probed: a fastmcp union-annotation registration crash through 1.21.0; "
        "ToolAnnotations itself absent through 1.6)")
    next_major = max(SUPPORTED_MAJORS["mcp"]) + 1
    assert not spec.contains(f"{next_major}.0.0"), (
        f"the unproven mcp {next_major}.x is admitted by {spec} — the 2026-07-30 outage shape")
    assert not spec.contains(f"{next_major}.0.0rc1", prereleases=True), (
        f"a prerelease of mcp {next_major}.x slips through {spec}")
