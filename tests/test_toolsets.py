"""PROXIMO_TOOLSETS — domain-level tool scoping, one layer finer than PROXIMO_SURFACES.

PROXIMO_SURFACES scopes by PLANE (pve/pbs/pmg/pdm/exec). That is too coarse to help: a
pve-only box still registers 310 tools (~97k tokens), which is 12x an 8k local context. The
field standard — GitHub's MCP server — scopes by DOMAIN (`repos`, `issues`, `pull_requests`)
with per-tool override, and reports ~60-90% context reduction from loading 3-10 tools. Adopting
that vocabulary means adopters already know it.

Four layers, most specific wins:

    PROXIMO_TOOLS      exact tool names           finest
    PROXIMO_TOOLSETS   domain groups (this file)
    PROXIMO_SURFACES   planes                     (already shipped)
    autoscope          configured planes          coarsest, default

THE SAFETY PROPERTY THIS FILE EXISTS FOR: every registered tool must belong to at least one
toolset. A tool in zero toolsets is unreachable the moment anyone scopes by toolset — silently,
with no error, because "not in the set you asked for" and "in no set at all" look identical from
the outside. That test is the load-bearing one; the rest is ergonomics.
"""
from __future__ import annotations

import pytest

from proximo import server
from proximo.server import TOOLSETS, toolset_keep

REGISTRY = sorted(server.mcp._tool_manager._tools)


# The always-registered set, read from the code rather than restated. These assertions used to
# spell "audit_verify" as a literal in six places, so adding a second always-registered tool
# (proximo_call, the by-name escape hatch) meant six edits and six chances to miss one. The
# property under test is "this filter keeps its plane PLUS whatever is never scopeable", and
# that is what this now says.
ALWAYS = set(server._ALWAYS_REGISTERED)

# --- the load-bearing invariant ----------------------------------------------------------

def test_every_tool_belongs_to_at_least_one_toolset():
    """No tool may be orphaned. An orphan is unreachable and nothing would report it."""
    covered = set()
    for prefixes in TOOLSETS.values():
        covered |= {n for n in REGISTRY if n.startswith(prefixes)}
    orphans = sorted(set(REGISTRY) - covered - ALWAYS)
    assert not orphans, (
        f"{len(orphans)} tools belong to NO toolset and would be unreachable when scoping "
        f"by toolset: {orphans[:12]}"
    )


def test_toolsets_are_a_partition_of_their_plane():
    """A toolset's tools must all come from one plane — mixed toolsets make scoping unpredictable."""
    for name, prefixes in TOOLSETS.items():
        plane = name.split(".", 1)[0]
        if plane in ("exec", "core", "memory", "wiki"):
            # exec/memory/wiki are deliberately cross-plane utility sets, not plane domains.
            # wiki indexes docs for ALL FOUR planes (that is why it is not named pve_docs),
            # so a per-plane partition is the wrong shape for it by construction.
            continue
        for n in (x for x in REGISTRY if x.startswith(prefixes)):
            assert n.startswith(plane + "_"), f"toolset {name!r} claims cross-plane tool {n!r}"


# --- filtering behaviour -------------------------------------------------------------------

def test_unset_is_inert():
    assert toolset_keep(REGISTRY, None) == set(REGISTRY)
    assert toolset_keep(REGISTRY, "  ") == set(REGISTRY)


def test_single_toolset_narrows_to_that_domain():
    kept = toolset_keep(REGISTRY, "pve.ceph")
    assert kept, "pve.ceph selected nothing"
    assert all(n.startswith("pve_ceph") or n in ALWAYS for n in kept)


def test_multiple_toolsets_union():
    ceph = toolset_keep(REGISTRY, "pve.ceph")
    tape = toolset_keep(REGISTRY, "pbs.tape")
    assert toolset_keep(REGISTRY, "pve.ceph,pbs.tape") == ceph | tape


def test_audit_verify_is_never_scopeable_away():
    """PROVE is not optional. Same rule PROXIMO_SURFACES already enforces."""
    assert "audit_verify" in toolset_keep(REGISTRY, "pve.ceph")


def test_unknown_toolset_refuses_startup():
    """Fail-closed: a typo must never silently serve a different set than the operator believes."""
    with pytest.raises(ValueError, match="unknown toolset"):
        toolset_keep(REGISTRY, "pve.cephh")


def test_unknown_toolset_error_names_the_valid_ones():
    with pytest.raises(ValueError, match="pve.ceph"):
        toolset_keep(REGISTRY, "nope")


# --- the reason any of this exists ----------------------------------------------------------

# --- what size machine this actually buys ---------------------------------------------------
# Measured, then asserted — NOT a target the numbers were bent to meet. The honest tiers:
#
#   ~8k context    dynamic mode only (~900 tokens). NO toolset fits with working room; the
#                  smallest real domain is ~1.3k and the median is ~9.6k. Say so plainly rather
#                  than implying toolsets rescue the tiniest models — they do not.
#   ~32k context   any single toolset (largest ~26k), or two typical ones.
#   200k+          whole planes or the full surface.
#
# The first line is the one worth keeping honest: an earlier draft of this test asserted a
# number that made toolsets look like they solved the 8k case. They do not.
LARGEST_TOOLSET_BUDGET = 120_000     # ~30k tokens — must clear a 32k window
TWO_TOOLSET_BUDGET = 110_000         # ~27k tokens — two common domains together
MEDIAN_TOOLSET_BUDGET = 50_000       # ~12k tokens — the typical pick


def _payload(names) -> int:
    import json

    reg = server.mcp._tool_manager._tools
    return len(json.dumps([
        {"name": n, "description": getattr(reg[n], "description", "") or "",
         "inputSchema": getattr(reg[n], "parameters", {}) or {}}
        for n in sorted(names)
    ]))


def test_every_toolset_fits_a_32k_context():
    """No single domain may exceed a 32k local window — that is the tier toolsets serve."""
    oversized = {
        name: _payload({n for n in REGISTRY if n.startswith(prefixes)})
        for name, prefixes in TOOLSETS.items()
    }
    over = {k: v for k, v in oversized.items() if v > LARGEST_TOOLSET_BUDGET}
    assert not over, f"toolsets too big for a 32k context: { {k: f'{v:,}B' for k, v in over.items()} }"


def test_the_typical_toolset_is_small():
    sizes = sorted(
        _payload({n for n in REGISTRY if n.startswith(p)}) for p in TOOLSETS.values()
    )
    median = sizes[len(sizes) // 2]
    assert median <= MEDIAN_TOOLSET_BUDGET, f"median toolset is {median:,} B (~{median // 4:,} tok)"


def test_two_common_toolsets_fit_a_32k_context():
    payload = _payload(toolset_keep(REGISTRY, "pve.guests,pve.cluster"))
    assert payload <= TWO_TOOLSET_BUDGET, (
        f"pve.guests+pve.cluster is {payload:,} B (~{payload // 4:,} tokens)"
    )


def test_toolsets_do_not_claim_to_solve_the_8k_case():
    """Honesty guard: if someone later claims 8k support from toolsets, this should be why not.

    The smallest REAL domain (not exec, which is 4 tools) must still be documented as too large
    for an 8k window with working room. If that ever stops being true, update the copy — do not
    silently start claiming it.
    """
    real_domains = {k: v for k, v in TOOLSETS.items()
                    if k not in ("exec", "memory", "wiki")}
    # exec = 4 tools, memory = 1 tool, wiki = 2 tools: deliberately tiny cross-plane utility
    # sets, not the "domain" tier the 8k docs claim is about
    smallest = min(
        _payload({n for n in REGISTRY if n.startswith(p)}) for p in real_domains.values()
    )
    assert smallest > 4_000, (
        "a real domain toolset now fits an 8k context — the docs claim dynamic mode is required "
        "for that tier; re-check the claim before relaxing this test"
    )
