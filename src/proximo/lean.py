"""LEAN mode — a searchable catalog instead of 900 resident tool schemas.

WHY THIS EXISTS. Proximo's tools/list payload is ~276k tokens across 900 tools (~97k for one
auto-scoped plane). A local model with an 8k-32k window cannot connect at all: the catalog
arrives before the first question and exhausts the context. That was reported from the outside,
with a measurement, and it is correct. Byte-trimming already took ~21% off and cannot close a
12x gap — the remaining payload is descriptions, which is how a model knows what it is calling.

What closes it is making the catalog NON-RESIDENT. Lean mode serves three small tools:

    proximo_find_tools(query)      search names + one-line summaries
    proximo_tool_schema(name)      the full input schema, for the one or two that matched
    proximo_call(tool, arguments)  dispatch

~900 tokens resident instead of ~276,000. The 900 tools still exist and still work; they stop
being sent to every client on every connection. This is the same pattern the agent harnesses
themselves use at this scale — deferred schemas fetched on demand — and it is the only approach
measured here that fits a small local context.

THE SAFETY INVARIANT. Dispatch MUST go through `ToolManager.call_tool`, which is literally the
path the MCP protocol handler uses: it resolves the Tool and awaits `tool.run(arguments)`, and
`tool.fn` is the decorated function carrying `target_aware`, the PLAN gate, the PROVE ledger
write and every opt-in control. Lean mode therefore adds NO second mutate path — the property
this module must never lose. Anything that reaches around `call_tool` to the undecorated
function is a bypass, not an optimization.

This module is deliberately pure: search and lookup take the catalog as an argument and touch
no globals, so they are testable without standing up a server.
"""
from __future__ import annotations

import difflib
from typing import Any

# A search result's summary is the first sentence of the docstring, capped. The cap is the whole
# point: a result set that carried full descriptions would re-import the cost lean mode removes.
_SUMMARY_MAX = 140
_DEFAULT_LIMIT = 25


def _summary_of(description: str) -> str:
    """First line/sentence of a tool docstring, collapsed to one short line."""
    first_line = (description or "").strip().split("\n", 1)[0].strip()
    sentence, _, _ = first_line.partition(". ")
    text = (sentence or first_line).strip()
    if len(text) > _SUMMARY_MAX:
        text = text[: _SUMMARY_MAX - 1].rstrip() + "…"
    return text


def search_tools(catalog: dict[str, Any], query: str, limit: int = _DEFAULT_LIMIT) -> list[dict]:
    """Term-wise AND search over tool names + descriptions, ranked by where the terms landed.

    Substring per TERM, not per phrase. Models type phrases ("firewall lockout", "ceph pool
    status") that appear nowhere contiguously; matching the whole string returned zero hits for
    every natural query when run against the real 900-tool catalog. Splitting on whitespace and
    requiring ALL terms keeps precision without that failure.

    AND, not OR: on a 900-tool catalog an OR match returns most of the catalog for any query
    containing a common word, which re-imports the payload problem lean mode exists to remove.

    Ranked, because the limit truncates. Alphabetical ordering put `ct_exec` above
    `pve_snapshot_create` for the query "snapshot" — a tool that merely mentions auto-snapshot in
    prose, outranking the snapshot tool, then surviving the cut while the real answer did not.
    Name matches beat description-only matches; ties break alphabetically so repeated identical
    searches stay stable.

    A blank query RAISES rather than returning everything — "no filter" degrading into "the whole
    catalog" is the exact blowup this mode prevents.
    """
    terms = [t for t in (query or "").strip().lower().split() if t]
    if not terms:
        raise ValueError("query must not be blank — lean mode never returns the whole catalog")

    scored: list[tuple[int, str, dict]] = []
    for name, tool in catalog.items():
        lname = name.lower()
        description = getattr(tool, "description", "") or ""
        ldesc = description.lower()
        if not all(t in lname or t in ldesc for t in terms):
            continue
        in_name = sum(t in lname for t in terms)
        if lname == "_".join(terms) or lname == "".join(terms):
            rank = 0                      # exact name
        elif in_name == len(terms):
            rank = 1                      # every term in the name
        elif in_name:
            rank = 2                      # name carries part of it
        else:
            rank = 3                      # prose-only mention
        scored.append((rank, name, {"name": name, "summary": _summary_of(description)}))

    scored.sort(key=lambda row: (row[0], row[1]))
    return [row[2] for row in scored[:limit]]


def tool_schema(catalog: dict[str, Any], name: str) -> dict:
    """Full description + JSON input schema for one tool.

    Fail-closed on an unknown name, with near-miss suggestions: search-then-call loops mistype
    names, and a KeyError carrying candidates is recoverable where an empty schema is not — a
    model handed `{}` would call blind, which is the worst outcome available here.
    """
    if name not in catalog:
        near = difflib.get_close_matches(name, catalog, n=3, cutoff=0.6)
        hint = f" — did you mean: {', '.join(near)}" if near else ""
        raise KeyError(f"unknown tool {name!r}{hint}")
    tool = catalog[name]
    return {
        "name": name,
        "description": getattr(tool, "description", "") or "",
        "schema": getattr(tool, "parameters", None) or {"type": "object", "properties": {}},
    }
