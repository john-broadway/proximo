"""M1 — every plane tool derives an MCP readOnlyHint from its own MUTATION/READ-ONLY marker.

Clients (Claude Code among them) use readOnlyHint for permission-prompt policy; the prose marker
was the only signal before. Derivation is by STARTSWITH (the unambiguous case); a docstring with
neither marker at the start gets no annotation rather than a guessed one.
"""
import proximo.server as server


def _hint(name):
    t = server.mcp._tool_manager._tools.get(name)
    a = getattr(t, "annotations", None)
    return None if a is None else a.readOnlyHint


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
                    and t.annotations.readOnlyHint is not None)
    assert with_hint > 800, f"only {with_hint} tools carry a readOnly hint — derivation regressed"
