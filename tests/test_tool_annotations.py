"""M1 — every plane tool derives an MCP readOnlyHint from its own MUTATION/READ-ONLY marker.

Clients (Claude Code among them) use readOnlyHint for permission-prompt policy; the prose marker
was the only signal before. Derivation is by STARTSWITH (the unambiguous case); a docstring with
neither marker at the start gets no annotation rather than a guessed one.
"""
import proximo.server as server
from proximo._mcpcompat import annotations_read_only


def _hint(name):
    t = server.mcp._tool_manager._tools.get(name)
    a = getattr(t, "annotations", None)
    return annotations_read_only(a)


def test_read_only_tool_marks_read_only_hint():
    assert _hint("pve_list_guests") is True


def test_mutating_tools_mark_not_read_only():
    assert _hint("pve_guest_power") is False
    assert _hint("ct_exec") is False


def test_annotations_derived_from_the_marker_helper():
    from mcp.types import ToolAnnotations
    assert server._annotations_from_doc("READ-ONLY: list things.") == ToolAnnotations(readOnlyHint=True)
    assert server._annotations_from_doc("MUTATION: change things.") == ToolAnnotations(readOnlyHint=False)
    assert server._annotations_from_doc("MUTATION-CAPABLE: maybe.") == ToolAnnotations(readOnlyHint=False)
    assert server._annotations_from_doc("Does a thing, no marker.") is None
    assert server._annotations_from_doc(None) is None


def test_most_of_the_surface_carries_a_hint():
    """A regression guard: the derivation must cover the large majority (871 startswith at audit),
    not silently fall to zero if the marker convention or the parse breaks."""
    if not server._MCP_TOOL_SUPPORTS_ANNOTATIONS:  # old mcp: graceful no-op, nothing to assert
        return
    tm = server.mcp._tool_manager._tools
    with_hint = sum(1 for t in tm.values()
                    if getattr(t, "annotations", None) is not None
                    and annotations_read_only(t.annotations) is not None)
    assert with_hint > 800, f"only {with_hint} tools carry a readOnly hint — derivation regressed"


def test_facade_doorway_tools_carry_hints():
    """The DEFAULT door is the facade, and an unannotated facade swallows every hint below it
    (2026-08-20 external report: 'the client can't tell a status read from a power cycle').
    proximo_call can dispatch mutations, so it is honestly readOnlyHint=False; find_tools and
    tool_schema only read the local catalog, so True. Registered two places: proximo_call at
    import time on server.mcp, the other two by door.apply_lean on the runtime instance."""
    if not server._MCP_TOOL_SUPPORTS_ANNOTATIONS:  # old mcp: graceful no-op, nothing to assert
        return
    assert _hint("proximo_call") is False

    from proximo import door
    from proximo._mcpcompat import ServerClass
    m = ServerClass("proximo-test-facade-annotations")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    door.apply_lean(m)
    for name, want in (("proximo_find_tools", True), ("proximo_tool_schema", True),
                       ("proximo_read", True)):
        t = m._tool_manager._tools[name]
        assert annotations_read_only(getattr(t, "annotations", None)) is want, name


def test_unmarked_tools_are_exactly_the_known_two():
    """Closing the class behind the 2026-08-20 sweep: 33 read-shaped tools sat unmarked —
    hint-invisible to clients and refused by the read door's fail-closed rule. The only tools
    allowed to stay unmarked are the two that genuinely defy the binary: audit_verify (a verify
    read that may advance the anchor pin file) and proximo_call (dispatches either kind; its
    hint is set explicitly, not derived). A new tool shipping without a marker fails HERE, not
    in an adopter's permission prompt."""
    unmarked = {n for n, t in server.mcp._tool_manager._tools.items()
                if server._annotations_from_doc(getattr(t.fn, "__doc__", None)) is None}
    assert unmarked == {"audit_verify", "proximo_call"}, (
        f"unexpected unmarked tools: {sorted(unmarked ^ {'audit_verify', 'proximo_call'})} — "
        "lead the docstring with READ-ONLY:/MUTATION:, or justify an allowlist change here"
    )
