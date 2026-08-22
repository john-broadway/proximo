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

import asyncio
import json
import pathlib

import pytest

from proximo import door, server
from proximo.targets import _TARGET_DESC

REGISTRY = server.mcp._tool_manager._tools


def _schema(tool) -> dict:
    """Internal registry Tools spell their JSON schema `.parameters` on BOTH mcp majors —
    every caller in this file feeds REGISTRY values, never wire Tools. Spelled directly so a
    future rename fails LOUD: the old three-spelling getattr chain here was exactly the
    quiet-fallback shape _mcpcompat's accessors forbid (first lens, finding 8)."""
    return tool.parameters or {}


def _payload_bytes(names, registry=None) -> int:
    """Serialized size of what `tools/list` actually hands the client for `names`.

    ⚠️ Measured through the MCP layer's OWN serialization, not rebuilt from the registry.
    This function used to construct `{name, description, inputSchema}` by hand — and a
    reconstruction cannot see a field it does not know about. It missed `outputSchema`,
    which FastMCP emits for 903 of 905 tools and which costs **45,468 tokens, 16.4% of
    the whole doorway**. Every figure this module pinned, and every token number in
    SETUP.md and the CHANGELOG, was therefore understated by up to 20%: the full surface
    reads ~231,700 by the old method and **~277,376 on the wire**.

    Caught by installing the package from gitea into a clean venv and speaking JSON-RPC
    to the real `proximo` binary — the adopter path. `model_dump(by_alias=True,
    exclude_none=True)` reproduces that wire payload byte-for-byte (verified against a
    live server: 36,494 B for pve.guests, both ways).

    `registry` defaults to the module's own full-catalog REGISTRY; callers measuring a
    registry that doesn't share tool objects with it (e.g. a lean/dynamic facade, whose
    search tools don't exist in the full catalog) pass their own.
    """
    reg = REGISTRY if registry is None else registry
    wanted = set(names)
    listed = asyncio.run(_list_tools_for(reg))
    return len(json.dumps([t.model_dump(by_alias=True, exclude_none=True)
                           for t in listed if t.name in wanted]))


async def _list_tools_for(registry):
    """The MCP `tools/list` payload for a registry, via the server's own converter."""
    from proximo._mcpcompat import ServerClass

    probe = ServerClass("proximo-budget-probe")
    probe._tool_manager._tools = dict(registry)
    return await probe.list_tools()


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
# What the remaining payload is made of (measured at 905 tools ON THE WIRE, after both
# strips above):
#   tool descriptions  ~347k B / ~87k tok   <- real content: how a model knows what a tool does
#   parameter schemas  ~682k B / ~170k tok  <- of which ~152k B is the per-call target selector
#   outputSchema       ~182k B / ~45k tok   <- 16.4% of the doorway, on 903 of 905 tools
#
# ⚠️ The three ceilings below ROSE ~20% on 2026-08-01. That is NOT the surface growing: it is
# this module starting to measure the real wire payload instead of a hand-rebuilt
# {name, description, inputSchema}, which silently omitted outputSchema. The old numbers were
# never what an adopter paid.
#
# outputSchema is mostly boilerplate ({"result": {"type": "object"}} plus a generated title),
# but it is NOT free to remove: the server also returns `structuredContent`, verified live on
# an adopter install, and MCP pairs the two. Suppressing it (`structured_output=False`) is a
# capability trade for a human to weigh, not a cleanup to make inside a budget test — the same
# rule the description-trimming note below already states.
#
# Getting a local model (8k-32k window) onto Proximo still needs a smaller SURFACE — fewer,
# coarser tools — not tidier bytes on the same 905.
FULL_SURFACE_BUDGET = 1_200_000
PVE_SURFACE_BUDGET = 425_000
PER_TOOL_AVERAGE_BUDGET = 1_330


def test_full_surface_payload_within_budget():
    size = _payload_bytes(list(REGISTRY))
    assert size <= FULL_SURFACE_BUDGET, (
        f"full-surface tools/list payload is {size:,} B (~{size // 4:,} tokens), "
        f"over the {FULL_SURFACE_BUDGET:,} B budget"
    )


def test_single_plane_payload_within_budget():
    """The realistic deployment: one plane, auto-scoped. This is what a local model faces."""
    pve = door.surface_keep(list(REGISTRY), "pve")
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


# --- doc-printed token figures, pinned against a live measurement -------------------------
#
# docs/SETUP.md and CHANGELOG.md print a table of "if you scope like this, it costs about
# that many tokens" figures. Nothing compared them to a live measurement, so a surface
# addition could silently invalidate every row (this is exactly how 1.11/1.13 in the
# 0.27.0 arena verdict were found — by hand, not by a gate). +/-10% tolerance: tight enough
# that real growth trips it, loose enough that the bytes//4 heuristic's own rounding and the
# doc's own "~" hedge don't.

def _lean_facade_registry() -> dict:
    """A throwaway registry carrying just the dynamic-mode facade, safe to prune.

    Mirrors tests/test_lean_wiring.py's `_fresh_mcp()`: `apply_lean` mutates its argument
    in place, and the facade tools it registers (`proximo_find_tools`, etc.) don't exist in
    the full-catalog REGISTRY, so this must not be a bare copy of REGISTRY's keys pointed
    back at REGISTRY's objects — it needs its own tool objects, from its own registry.
    """
    from proximo._mcpcompat import ServerClass

    m = ServerClass("proximo-test-schema-budget")
    m._tool_manager._tools = dict(REGISTRY)
    door.apply_lean(m)
    return m._tool_manager._tools


DOC_PRINTED_TOKEN_FIGURES = {
    # 2026-08-01: 582 -> 888 and 1,273 -> 1,579. audit_entries joined _ALWAYS_REGISTERED,
    # so both of these doorways are one tool wider. The READ side of PROVE is resident by
    # design; that is a deliberate cost, stated rather than absorbed silently.
    # 2026-08-01 (the 0.30 flip): 888 -> 1,449. Estate memory is default-on now, so
    # proximo_recall (and its memory-first find_tools description) is part of the DEFAULT
    # door. This row is what a bare install serves. Still ~18% of ollama's default 8,192
    # window; the 888 figure survives as the PROXIMO_MEMORY=0 variant, not pinned here.
    # 2026-08-20: 1,449 -> 1,595 -> 1,740, one night, two deliberate costs. First the facade
    # readOnlyHints (find_tools/tool_schema True, proximo_call False; the external "the facade
    # swallows the hint" report) — ~29 tokens, which tripped the re-measure and exposed +117 of
    # accumulated drift since the 08-01 pin. Then proximo_read, the ENFORCED read-only door John
    # commissioned on that report, joined the facade: +145. Every row below was re-measured the
    # same night (all had drifted 4-8% in-band across 0.34/0.35's description work); the MEMORY=0
    # variant moved ~888 -> ~1,020 -> ~1,166 (printed, still unpinned).
    "dynamic (the default; also PROXIMO_TOOLSETS=dynamic)": 1_740,
    # Added 2026-07-31. These two SETUP.md rows were NOT pinned here, so nothing watched them.
    # The toolsets row had genuinely drifted 17% after the doorway work. The PROXIMO_TOOLS row
    # had NOT — a review lens and I both measured it at 828 by summing the three NAMED tools,
    # forgetting that tool_keep always adds audit_verify, so the real figure is 4 tools. The doc
    # was right and we were about to "fix" it. Pinning both here is what makes that unrepeatable:
    # a figure nobody measures the same way twice needs a guard, not another careful reader.
    # 2026-08-01: 1,000 -> 1,130. NOT drift — a structural change. `proximo_call`, the by-name
    # escape hatch, joined `_ALWAYS_REGISTERED`, so this row is now 5 tools (the three named +
    # audit_verify + the hatch), not 4. Same trap as the note above, one tool further along:
    # the figure is never just the tools you named.
    # 2026-08-01: EVERY row below rose ~16-20%, and not because the surface grew. The
    # measurement above stopped rebuilding the payload by hand and started reading what
    # `tools/list` actually serializes — which includes outputSchema. Verified against a
    # clean venv installed from gitea and driven over real JSON-RPC: that adopter server
    # sent 36,494 B for pve.guests and 1,109,504 B for the full surface, matching these
    # numbers byte-for-byte. The figures a user was reading before were understated by up
    # to 20%.
    "three exact tools (PROXIMO_TOOLS)": 1_704,
    "two domain toolsets (pve.guests,pve.storage)": 16_825,
    "one domain toolset (pve.guests)": 9_781,
    # Relabelled 2026-08-02: this measures the pve PLANE CATALOG, and PROXIMO_SURFACES=pve stopped
    # producing it when surfaces became scope-only — that config now serves the facade (~868
    # tokens). The measurement is unchanged and still real; it is what `PROXIMO_TOOLSETS=catalog`
    # costs on a pve-only box. The old label was true of the filter and false of the env var, the
    # same shape as the README line the external vet caught.
    "one plane catalog (PROXIMO_TOOLSETS=catalog on a pve-only box)": 101_398,
    # Label updated at the 0.30 flip: nothing-configured now serves the dynamic facade;
    # the full surface is an explicit choice.
    "full surface (PROXIMO_TOOLSETS=all)": 289_839,
}


# Every LIVE surface that prints the default-doorway figure. 2026-08-20 lens finding: the
# re-measure gate above pinned the README/SETUP rows, but lean.py's module docstring and
# proximo.env.example printed the same figure UNWATCHED — both sat at the stale ~1,449 while
# this gate reported success. A figure that prints in N places needs all N in one list, or the
# gate's green speaks for a subset while reading as the whole. (CHANGELOG and debian/changelog
# are deliberately absent: their old figures live inside dated release entries, true at their
# time.) The MEMORY=0 variant figure rides along where it prints.
DOORWAY_FIGURE_SURFACES = [
    "README.md",
    "docs/SETUP.md",
    "src/proximo/lean.py",
    "packaging/proximo.env.example",
]
_MEMORY0_DOORWAY_TOKENS = 1_166  # the PROXIMO_MEMORY=0 variant; printed, not pinned to a live run

# Every figure a live surface ever printed for the two doorway rows above. When a re-measure
# moves the pin, append the OUTGOING figures here rather than replacing — the stale check walks
# this whole history, so a surface reverted to ANY old number reds, not just last release's.
# (Advisor catch, same night the gate was born: a hardcoded two-figure tuple would itself have
# gone stale on the very next re-measure.)
_SUPERSEDED_DOORWAY_FIGURES = ("~1,449", "~888", "~1,595", "~1,020")


@pytest.mark.parametrize("surface", DOORWAY_FIGURE_SURFACES)
def test_live_surfaces_print_the_current_doorway_figure(surface):
    """Each surface prints the CURRENT default-doorway figure and no superseded one."""
    current = DOC_PRINTED_TOKEN_FIGURES["dynamic (the default; also PROXIMO_TOOLSETS=dynamic)"]
    text = (pathlib.Path(__file__).resolve().parents[1] / surface).read_text()
    assert f"~{current:,} tokens" in text, (
        f"{surface} does not print the pinned default-doorway figure ~{current:,}"
    )
    for stale in _SUPERSEDED_DOORWAY_FIGURES:
        assert stale not in text, (
            f"{surface} still prints superseded doorway figure {stale} — "
            f"re-measure moved it (default ~{current:,}, MEMORY=0 ~{_MEMORY0_DOORWAY_TOKENS:,})"
        )


@pytest.mark.parametrize("label,doc_tokens", DOC_PRINTED_TOKEN_FIGURES.items())
def test_doc_printed_token_figures_match_live_measurement(label, doc_tokens):
    """Each row of SETUP.md's/CHANGELOG.md's token table, re-measured live at +/-10%."""
    if label.startswith("dynamic"):
        lean_registry = _lean_facade_registry()
        names, registry = list(lean_registry), lean_registry
    elif label.startswith("one domain toolset"):
        names, registry = sorted(door.toolset_keep(REGISTRY.keys(), "pve.guests")), REGISTRY
    elif label.startswith("three exact tools"):
        names = sorted(door.tool_keep(set(REGISTRY), "pve_list_guests,pve_guest_power,pve_rollback"))
        registry = REGISTRY
    elif label.startswith("two domain toolsets"):
        names = sorted(door.toolset_keep(REGISTRY.keys(), "pve.guests,pve.storage"))
        registry = REGISTRY
    elif label.startswith("one plane"):
        names, registry = sorted(door.surface_keep(list(REGISTRY), "pve")), REGISTRY
    else:
        names, registry = list(REGISTRY), REGISTRY

    measured_tokens = _payload_bytes(names, registry=registry) // 4
    low, high = doc_tokens * 0.9, doc_tokens * 1.1
    assert low <= measured_tokens <= high, (
        f"{label}: docs say ~{doc_tokens:,} tokens, live measurement is "
        f"{measured_tokens:,} across {len(names)} tools — outside +/-10%, the docs need "
        "a re-measure"
    )


# --- two cuts the 900-tool measurement above called impossible -------------------------------
#
# That note concluded "no further FREE cut here", measuring bytes on a fixed surface with the
# target selector treated as mandatory. Both assumptions had room in them.

def test_nullable_anyof_is_collapsed_to_a_type_union():
    """`anyOf:[{type:X},{type:null}]` and `type:[X,"null"]` are the SAME JSON Schema; one is
    ~30 chars longer, and pydantic emits it on every optional parameter across the surface."""
    from proximo.door import collapse_nullable_anyof

    node = {"properties": {"node": {"anyOf": [{"type": "string"}, {"type": "null"}],
                                    "default": None, "description": "d"}}}
    collapse_nullable_anyof(node)
    prop = node["properties"]["node"]
    assert "anyOf" not in prop
    assert prop["type"] == ["string", "null"]
    assert prop["default"] is None and prop["description"] == "d"  # nothing else touched


def test_nullable_anyof_collapse_leaves_real_unions_alone():
    """Only the two-branch X-or-null shape collapses. A genuine union, or a branch carrying
    more than `type`, must survive untouched — a shorter schema that means something else is
    not a saving."""
    from proximo.door import collapse_nullable_anyof

    real = {"anyOf": [{"type": "string"}, {"type": "integer"}]}
    constrained = {"anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]}
    three = {"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}]}
    for node in (real, constrained, three):
        before = dict(node)
        collapse_nullable_anyof(node)
        assert node == before, f"collapsed a shape it must not touch: {before}"


def test_target_param_dropped_when_no_registry_but_kept_when_configured():
    """`proximo_target` names an entry in the PROXIMO_TARGETS registry. With no registry the
    only thing a caller can do with it is get 'no target registry configured' back — so on a
    single-box deployment it is pure payload advertised on ~every tool. Same principle autoscope
    already applies: do not advertise what this box cannot serve.

    Both directions asserted, because a prune that fires unconditionally would silently remove a
    parameter that multi-target deployments genuinely need.
    """
    from proximo.door import drop_unusable_target_param

    def fresh():
        return {"properties": {"vmid": {"type": "string"},
                               "proximo_target": {"type": "string", "description": "d"}},
                "required": ["vmid"]}

    no_registry = fresh()
    drop_unusable_target_param(no_registry, registry_configured=False)
    assert "proximo_target" not in no_registry["properties"]
    assert "vmid" in no_registry["properties"], "pruned more than the target selector"

    configured = fresh()
    drop_unusable_target_param(configured, registry_configured=True)
    assert "proximo_target" in configured["properties"], (
        "a multi-target deployment lost the parameter it needs")
