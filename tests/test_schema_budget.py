"""Tool-schema payload budget — the cost of the surface BEFORE anyone asks a question.

Every tool's name + description + inputSchema crosses to the client on `tools/list`, once,
at connection time. With 900 tools that payload is the single largest fixed cost Proximo
imposes on a client's context window, and nothing measured it while the surface grew
365 -> 493 -> 603 -> 715 -> 900. A local model with an 8k-32k window dies on it before a
question is asked; a 200k cloud model spends most of its window on schema.

Two structural rules and three ceilings, so the surface can never grow silently again:

- Anything attached to the SHARED target-aware decorator is multiplied by ~900. A one-line
  description there is not a one-line cost. Keep it lean by test, not by intention.
- Pydantic emits a `title` next to every property ("vmid" -> title "Vmid"), which restates
  the key it already sits under. Multiplied across ~3k properties it is pure freight.

The ceilings are policy, not measurement: they are set with headroom over the current real
payload so ordinary work never trips them, and a careless surface addition does.
"""
from __future__ import annotations

import json

from proximo import server
from proximo.targets import _TARGET_DESC

REGISTRY = server.mcp._tool_manager._tools


def _schema(tool) -> dict:
    for attr in ("parameters", "inputSchema", "input_schema"):
        value = getattr(tool, attr, None)
        if value:
            return value
    return {}


def _payload_bytes(names) -> int:
    """Serialized size of what `tools/list` actually hands the client for `names`."""
    return len(json.dumps([
        {
            "name": n,
            "description": getattr(REGISTRY[n], "description", "") or "",
            "inputSchema": _schema(REGISTRY[n]),
        }
        for n in names
    ]))


def _titles_in(schema: dict) -> list[str]:
    found = []
    for key, value in (schema.get("properties") or {}).items():
        if isinstance(value, dict) and "title" in value:
            found.append(key)
    return found


# --- the shared parameter: one sentence, ~900 times -------------------------------------

def test_shared_target_description_stays_lean():
    """_TARGET_DESC rides on ~every tool, so its length is multiplied by the surface size.

    At 374 chars it cost ~84k tokens of identical prose across the registry — more than a
    third of the whole schema payload for one repeated paragraph.
    """
    assert len(_TARGET_DESC) <= 96, (
        f"_TARGET_DESC is {len(_TARGET_DESC)} chars and is duplicated onto "
        f"{sum('proximo_target' in (_schema(t).get('properties') or {}) for t in REGISTRY.values())} "
        "tools — every char here costs ~900x. Keep it to one short clause."
    )


def test_target_param_is_still_documented():
    """Lean is not absent — the parameter must keep a description on every tool that has it.

    Guards the trim against overcorrecting into the 0%-schema-coverage state that put the
    long description there in the first place.
    """
    undocumented = [
        name for name, tool in REGISTRY.items()
        if "proximo_target" in (_schema(tool).get("properties") or {})
        and not (_schema(tool)["properties"]["proximo_target"].get("description") or "").strip()
    ]
    assert not undocumented, f"proximo_target undocumented on {len(undocumented)} tools"


# --- pydantic title freight --------------------------------------------------------------

def test_schemas_carry_no_redundant_titles():
    """A property's `title` restates the key it sits under; across ~3k properties it is freight."""
    offenders = {n: t for n, t in ((n, _titles_in(_schema(tool))) for n, tool in REGISTRY.items()) if t}
    assert not offenders, (
        f"{len(offenders)} tools carry pydantic `title` keys "
        f"(e.g. {list(offenders)[:3]}) — strip them from the generated schema."
    )


# --- the ceilings ------------------------------------------------------------------------

# Set from measurement, with ~8% headroom over the real payload — tight enough that a careless
# addition trips them, loose enough that ordinary work does not. Raising one is a deliberate act:
# it means the surface got more expensive for every client, so say why in the commit.
#
# What the remaining payload is made of (measured at 900 tools, after both strips above):
#   tool descriptions  ~347k B / ~87k tok   <- real content: how a model knows what a tool does
#   parameter schemas  ~682k B / ~170k tok  <- of which ~152k B is the per-call target selector
# There is no further FREE cut here. Getting a local model (8k-32k window) onto Proximo needs a
# smaller SURFACE — fewer, coarser tools — not tidier bytes on the same 900. Trimming descriptions
# would buy ~87k tokens at the cost of the model knowing what it is calling: a capability trade,
# not a cleanup, and not one to make silently inside a budget test.
FULL_SURFACE_BUDGET = 1_200_000
PVE_SURFACE_BUDGET = 420_000
PER_TOOL_AVERAGE_BUDGET = 1_300


def test_full_surface_payload_within_budget():
    size = _payload_bytes(list(REGISTRY))
    assert size <= FULL_SURFACE_BUDGET, (
        f"full-surface tools/list payload is {size:,} B (~{size // 4:,} tokens), "
        f"over the {FULL_SURFACE_BUDGET:,} B budget"
    )


def test_single_plane_payload_within_budget():
    """The realistic deployment: one plane, auto-scoped. This is what a local model faces."""
    pve = server.surface_keep(list(REGISTRY), "pve")
    size = _payload_bytes(sorted(pve))
    assert size <= PVE_SURFACE_BUDGET, (
        f"pve-only payload is {size:,} B (~{size // 4:,} tokens) across {len(pve)} tools, "
        f"over the {PVE_SURFACE_BUDGET:,} B budget"
    )


def test_average_tool_cost_within_budget():
    """Guards shape, not total: catches per-tool bloat even if the count stays flat."""
    average = _payload_bytes(list(REGISTRY)) // len(REGISTRY)
    assert average <= PER_TOOL_AVERAGE_BUDGET, (
        f"average tool costs {average:,} B (~{average // 4} tokens), "
        f"over the {PER_TOOL_AVERAGE_BUDGET:,} B budget"
    )
