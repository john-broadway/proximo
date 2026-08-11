"""LEAN mode — a searchable catalog instead of 906 resident tool schemas. THE DEFAULT since
the 0.30 flip.

WHY THIS EXISTS. Proximo's tools/list payload is ~277k tokens across 906 tools (~97k for one
auto-scoped plane). A local model with an 8k-32k window cannot connect at all: the catalog
arrives before the first question and exhausts the context. That was reported from the outside,
with a measurement, and it is correct. Byte-trimming already took ~21% off and cannot close a
12x gap — the remaining payload is descriptions, which is how a model knows what it is calling.

What closes it is making the catalog NON-RESIDENT. Lean mode serves three small tools:

    proximo_find_tools(query)      search names + one-line summaries
    proximo_tool_schema(name)      the full input schema, for the one or two that matched
    proximo_call(tool, arguments)  dispatch

~1,449 tokens resident by default (six entries, `proximo_recall` and the audit pair included;
~888 with PROXIMO_MEMORY=0) instead of ~277,376 (measured on the wire). The ~906 tools still
exist and still work; they stop
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

# Legacy verb-first names are the only tools not in `plane_noun_verb` form, and did-you-mean ranks
# on the shared verb SUFFIX — so the natural noun_verb name an agent fabricates (`pve_vm_create`)
# mis-ranks to an unrelated tool (`pve_realm_create`) instead of the real one. Map those fabricated
# guesses to the real tools so a direct call, proximo_call, and the unknown-name interceptor all
# route them correctly rather than dead-ending. Keys are the guesses; values are real tool names.
ALIASES: dict[str, str] = {
    "pve_vm_create": "pve_create_vm",
    "pve_container_create": "pve_create_container",
    "pve_ct_create": "pve_create_container",
    "pve_guest_delete": "pve_delete_guest",
    "pve_vm_delete": "pve_delete_guest",
    "pve_container_delete": "pve_delete_guest",
    "pve_guests_list": "pve_list_guests",
    "pve_guest_list": "pve_list_guests",
}


def resolve_alias(name: str) -> str:
    """Map a fabricated verb-order guess to the real tool name; pass any other name through."""
    return ALIASES.get(name, name)

def _term_variants(term: str) -> tuple[str, ...]:
    """A query term plus its synonyms, so any spelling finds a tool.

    This WIDENS a term, it does not replace it: a bare "vm" query must still find
    `pve_create_vm`, whose own name says vm, not guest, while also finding `pve_delete_guest`
    via the vm->guest mapping. Swapping the term outright would fix one query and break the
    other.

    Synonyms come from `lexical.KEYWORD_VOCABULARY`, which is deliberately NARROW and a
    DIFFERENT table from the wide `lexical.VOCABULARY` the ranking tier uses.

    This briefly read from the wide table on the reasoning that one table cannot drift from
    itself. That was wrong, and a measurement killed it: on the real 905-tool catalog "on"
    then matched 905 of 905 tools, "show" 824, and "check cluster health" 187, because
    concept-level expansions (health→status, check→status) land on words nearly every
    description contains — so the AND across terms stopped filtering and lean mode's
    OR-blowup came back through the front door. Keyword AND-matching needs near-exact
    renames only; the ranking tier is where a wide vocabulary belongs, because cosine order
    plus a score floor can sort out what an AND filter cannot. Both widths are pinned by a
    blast-radius test against the real tracked manifest.
    """
    from proximo.lexical import KEYWORD_VOCABULARY

    return (term, *KEYWORD_VOCABULARY.get(term, ()))


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

    Each term is matched by ITSELF OR its synonym from `lexical.KEYWORD_VOCABULARY`: "delete
    vm" must find `pve_delete_guest`, whose name says "guest"/"delete", never "vm". That table
    is deliberately narrow — see `_term_variants` for the measurement behind the split.
    """
    terms = [t for t in (query or "").strip().lower().split() if t]
    if not terms:
        raise ValueError("query must not be blank — lean mode never returns the whole catalog")

    variants_per_term = [_term_variants(t) for t in terms]

    scored: list[tuple[int, str, dict]] = []
    for name, tool in catalog.items():
        lname = name.lower()
        description = getattr(tool, "description", "") or ""
        ldesc = description.lower()
        if not all(
            any(v in lname or v in ldesc for v in variants) for variants in variants_per_term
        ):
            continue
        in_name = sum(any(v in lname for v in variants) for variants in variants_per_term)
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
    # Rank 3 is a PROSE-ONLY match: every term appeared somewhere in a description, nowhere
    # in the name. That is the weakest evidence keyword search produces, and it is not
    # better than a strong lexical match — but "keyword always first" handed it the whole
    # limit anyway. Measured on the real catalog: `configuration audit` returned
    # pbs_metrics_influxdb_http_create / pbs_s3_client_create (both merely CONTAIN those
    # words in prose) and filled all four slots, so `audit_entries` — which the lexical
    # tier ranks first for the same intent — never got a place. A live qwen3:8b then
    # reported no such tool exists.
    #
    # So the strong keyword ranks (0-2, the name matched) keep absolute priority, and
    # prose-only hits go BEHIND the lower tiers rather than ahead of them. Nothing is
    # dropped; only the order changes, and every row still says which tier found it.
    strong = [row[2] for row in scored if row[0] < 3]
    prose_only = [row[2] for row in scored if row[0] == 3]
    results = strong[:limit]

    # THE TIERS, strongest-precision first. Keyword hits are never removed, reordered or
    # marked; each lower tier only fills room the tier above left empty, and marks its rows
    # so a reader can tell which one answered:
    #
    #   1. keyword   exact terms (above). Highest precision, zero recall for operator
    #                language that shares no words with our tool text.
    #   2. semantic  opt-in neural (PROXIMO_EMBED_URL). Measured strongest at crossing the
    #                vocabulary gap, but costs an embedding server the adopter runs.
    #   3. lexical   in-wheel, default-on. Vocabulary-expanded n-gram TF-IDF: no model, no
    #                network, no dependency, so an adopter who configures NOTHING still
    #                gets it — and it is what an unreachable embedder degrades to, rather
    #                than falling all the way back to bare keyword.
    #
    # Each tier is independently fail-soft. A search assist must never take the facade down.
    # (No `except ValueError: raise` in the loop below. It was written to keep a blank query
    # raising, but the blank check above already guarantees a non-blank query by this line —
    # the branch was unreachable, and unreachable code that looks like a guard is worse than
    # none: it reads as protection.)
    if len(results) < limit:
        summaries = {n: _summary_of(getattr(t, "description", "") or "")
                     for n, t in catalog.items()}
        from proximo import lexical, vectors
        for enabled, fill, label in ((vectors.vectors_enabled, vectors.semantic_fill, "semantic"),
                                     (lexical.lexical_enabled, lexical.lexical_fill, "lexical")):
            if len(results) >= limit or not enabled():
                continue
            try:
                results += fill(summaries, query, {row["name"] for row in results},
                                limit - len(results))
            except Exception as e:
                vectors._warn_once(f"{label} search degraded: {e}")
    if len(results) < limit:                      # prose-only keyword hits, last
        seen = {row["name"] for row in results}
        results += [row for row in prose_only if row["name"] not in seen][:limit - len(results)]
    return results


def tool_schema(catalog: dict[str, Any], name: str) -> dict:
    """Full description + JSON input schema for one tool.

    Fail-closed on an unknown name, with near-miss suggestions: search-then-call loops mistype
    names, and a KeyError carrying candidates is recoverable where an empty schema is not — a
    model handed `{}` would call blind, which is the worst outcome available here.
    """
    name = resolve_alias(name)  # a fabricated verb-order guess resolves to the real tool
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
