"""LEAN mode — serve a searchable catalog instead of 900 resident schemas.

The reported defect (forum, 2026-07-28): a local model cannot use Proximo at all. The full
tools/list payload is ~276k tokens after the 0.25.x schema strip, and ~97k for a single
auto-scoped plane. An 8k-32k context dies at connection time, before a question is asked.

Trimming bytes cannot close a 12x gap. What closes it is making the catalog non-resident:
serve three small tools (find / schema / call) and let the model pull the one or two schemas
it actually needs. The 900 tools do not go away — they stop being sent to every client on
every connection.

The invariant that makes this safe: dispatch goes through the SAME `ToolManager.call_tool`
path the MCP protocol itself uses, so `target_aware`, PLAN, PROVE, UNDO and every gate still
fire. Lean mode must never become a second mutate path — that is the property these tests pin.
"""
from __future__ import annotations

import anyio
import pytest

from proximo import lean, server
from proximo.backends import ProximoError


class _FakeTool:
    def __init__(self, name, description, parameters=None):
        self.name = name
        self.description = description
        self.parameters = parameters or {"properties": {}, "type": "object"}


CATALOG = {
    "pve_list_guests": _FakeTool(
        "pve_list_guests",
        "READ-ONLY: list every guest on the cluster.\n\nNo state change.",
    ),
    "pve_guest_power": _FakeTool(
        "pve_guest_power",
        "MUTATION: start, stop, shutdown or reboot a guest.",
        {"properties": {"vmid": {"type": "string"}}, "type": "object"},
    ),
    "pbs_datastore_status": _FakeTool(
        "pbs_datastore_status", "READ-ONLY: usage and health for a backup datastore."
    ),
    "pmg_quarantine_list": _FakeTool(
        "pmg_quarantine_list", "READ-ONLY: list mails held in quarantine."
    ),
}


# --- search ------------------------------------------------------------------------------

def test_search_finds_tools_by_name_fragment():
    hits = lean.search_tools(CATALOG, "guest")
    assert {h["name"] for h in hits} == {"pve_list_guests", "pve_guest_power"}


def test_search_finds_tools_by_description_word():
    hits = lean.search_tools(CATALOG, "quarantine")
    assert [h["name"] for h in hits] == ["pmg_quarantine_list"]


def test_search_returns_one_line_summaries_not_full_descriptions():
    """The whole point is that a search result is cheap; a full docstring is not."""
    hit = next(h for h in lean.search_tools(CATALOG, "list_guests"))
    assert "\n" not in hit["summary"]
    assert hit["summary"].startswith("READ-ONLY: list every guest")


def test_search_is_case_insensitive():
    assert lean.search_tools(CATALOG, "QUARANTINE") == lean.search_tools(CATALOG, "quarantine")


def test_search_respects_limit():
    assert len(lean.search_tools(CATALOG, "READ-ONLY", limit=2)) == 2


def test_search_with_no_match_returns_empty_not_everything():
    """A miss must not degrade into 'here is the whole catalog' — that is the bug we are fixing."""
    assert lean.search_tools(CATALOG, "zzzznotathing") == []


def test_blank_query_refuses_rather_than_dumping_the_catalog():
    with pytest.raises(ValueError, match="query"):
        lean.search_tools(CATALOG, "   ")


# --- defects found by running against the REAL 900-tool catalog ---------------------------
# A 4-tool fixture cannot show either of these: both need a big catalog and the kind of query
# a model actually types. Found by pointing search at the live registry, not by reasoning.

def test_multi_word_query_matches_terms_separately():
    """'guest power' must find pve_guest_power even though that phrase appears nowhere.

    Whole-phrase substring matching returned 0 hits for every natural multi-word query
    ('firewall lockout', 'ceph pool status'). A model types phrases, not identifiers.
    """
    hits = lean.search_tools(CATALOG, "guest power")
    assert [h["name"] for h in hits] == ["pve_guest_power"]


def test_multi_word_query_requires_all_terms():
    """AND, not OR — 'quarantine backup' matches neither tool, and must not return both."""
    assert lean.search_tools(CATALOG, "quarantine backup") == []


def test_name_matches_outrank_description_only_matches():
    """A tool whose NAME carries the term is what the searcher meant.

    On the real catalog, searching 'snapshot' put ct_exec and ct_psql (which merely mention
    auto-snapshot in prose) above pve_snapshot_create, because ordering was alphabetical and
    the limit truncated before the real matches. Relevance has to beat the alphabet.
    """
    catalog = dict(CATALOG)
    # Name must NOT contain the term — otherwise it is a legitimate name match, not the
    # description-only case under test. (First draft of this fixture got that wrong.)
    catalog["aaa_unrelated_thing"] = _FakeTool(
        "aaa_unrelated_thing", "READ-ONLY: something that merely mentions guests in passing."
    )
    names = [h["name"] for h in lean.search_tools(catalog, "guests")]
    assert names[0] == "pve_list_guests", f"description-only match outranked a name match: {names}"


def test_limit_truncates_after_ranking_not_before():
    """With a tight limit the BEST matches must survive, not the alphabetically luckiest."""
    catalog = dict(CATALOG)
    for i in range(5):
        catalog[f"aaa_filler_{i}"] = _FakeTool(f"aaa_filler_{i}", "mentions guests in prose only.")
    names = [h["name"] for h in lean.search_tools(catalog, "guests", limit=1)]
    assert names == ["pve_list_guests"]


def test_exact_name_query_outranks_every_other_match():
    """A model that already knows the tool name must get it first, not a prose mention."""
    names = [h["name"] for h in lean.search_tools(CATALOG, "pve guest power")]
    assert names[0] == "pve_guest_power"


def test_operator_synonyms_surface_pve_delete_guest():
    """Real operators type "delete vm", "remove vm", "destroy vm", "delete container" —
    pve_delete_guest's name and docstring say "guest"/"delete", never "vm" or "container", so
    all four phrasings returned zero hits against the real 904-tool catalog. Bare "delete"
    separately buried it 68th, past the default limit, behind alphabetically-tied
    pbs_*_delete tools.
    """
    from proximo import server

    catalog = dict(server.mcp._tool_manager._tools)
    for query in ("delete vm", "delete container", "remove vm", "destroy vm"):
        names = [h["name"] for h in lean.search_tools(catalog, query)]
        assert "pve_delete_guest" in names, f"{query!r} missed pve_delete_guest: {names}"


def test_synonym_widens_the_match_it_does_not_replace_the_term():
    """A synonym must ADD a match, never remove one — "vm" alone must still find a tool whose
    own name literally says vm, even though it now also finds guest-named tools via the
    vm->guest synonym.
    """
    catalog = dict(CATALOG)
    catalog["pve_create_vm"] = _FakeTool("pve_create_vm", "MUTATION: create a new QEMU VM.")
    names = {h["name"] for h in lean.search_tools(catalog, "vm")}
    assert names == {"pve_create_vm", "pve_guest_power", "pve_list_guests"}


# --- schema lookup -----------------------------------------------------------------------

def test_tool_schema_returns_the_full_input_schema():
    got = lean.tool_schema(CATALOG, "pve_guest_power")
    assert got["schema"]["properties"] == {"vmid": {"type": "string"}}
    assert got["description"].startswith("MUTATION:")


def test_tool_schema_on_unknown_name_fails_loud():
    """Fail-closed: never return an empty schema that a model would call blind."""
    with pytest.raises(KeyError, match="nope_not_here"):
        lean.tool_schema(CATALOG, "nope_not_here")


def test_tool_schema_suggests_near_misses():
    """A wrong name is the common failure in a search-then-call loop; make it recoverable."""
    with pytest.raises(KeyError) as exc:
        lean.tool_schema(CATALOG, "pve_guest_powr")
    assert "pve_guest_power" in str(exc.value)


# --- dispatch: unknown-name fail-closed (server.dispatch_tool) ----------------------------
#
# `proximo_tool_schema` (above) already fails closed on a typo with did-you-mean candidates.
# `proximo_call` -> `server.dispatch_tool` is the OTHER unknown-name path, and the one a small
# model in dynamic mode is most likely to hit directly: its whole incentive is conserving round
# trips, which is exactly the incentive to skip the schema-lookup step and call a remembered or
# guessed name straight through. A bare KeyError there is a dead end with no recovery signal;
# this pins dispatch_tool raising the SAME shape tool_schema does, as ProximoError (the type
# every other refusal in this codebase uses), not a bare KeyError.

def _fresh_mcp_mirroring_the_real_registry():
    """A throwaway FastMCP server whose registry mirrors the real one, safe to prune in a test."""
    from mcp.server.fastmcp import FastMCP

    m = FastMCP("proximo-test-lean-dispatch")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    return m


def test_dispatch_tool_refuses_unknown_name_as_proximo_error():
    m = _fresh_mcp_mirroring_the_real_registry()
    catalog = dict(m._tool_manager._tools)

    async def go():
        return await server.dispatch_tool(m, catalog, "pve_delete_gust", {})

    with pytest.raises(ProximoError, match="pve_delete_gust"):
        anyio.run(go)


def test_dispatch_tool_unknown_name_suggests_near_matches():
    """Same did-you-mean mechanism proximo_tool_schema already gives, so a model that calls
    directly and skips the schema step still lands somewhere recoverable."""
    m = _fresh_mcp_mirroring_the_real_registry()
    catalog = dict(m._tool_manager._tools)

    async def go():
        return await server.dispatch_tool(m, catalog, "pve_delete_gust", {})

    with pytest.raises(ProximoError) as exc:
        anyio.run(go)
    assert "pve_delete_guest" in str(exc.value)
