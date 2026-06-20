"""Pin the MCP tool surface count so doc/count drift can't recur.

History: a session once chased a phantom "145 vs 146" discrepancy. The 146 was a
`grep -c '@mcp.tool()'` artifact — it counted the prose mention of `@mcp.tool()` in
server.py's module docstring as if it were a decorator. The authoritative count is the
FastMCP registry (`mcp.list_tools()`), which dedupes by tool name. This test makes the
number machine-checked: bump EXPECTED_TOOL_COUNT *intentionally* when you add/remove a
tool (same discipline as the version), never let it drift silently.

The second test catches a real bug: if two functions register under the same tool name,
the registry silently keeps one and drops the other (a "lost tool"). That shows up as
real-decorators > registry-entries — so we count the actual decorator LINES (anchored to
line-start, which excludes docstring/comment mentions) and require them to equal the
exposed surface. The equality also proves no decorator is env-gated (e.g. an exec-mode
tool behind a flag) — a conditional one would make the unconditional source count exceed
the runtime count.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

import proximo.server as server

EXPECTED_TOOL_COUNT = 145

_SERVER_SRC = Path(server.__file__).read_text(encoding="utf-8")
# A real decorator: the line, after optional indentation, starts with `@mcp.tool(`. The
# line-start anchor (not the parens) is what excludes the backtick-wrapped mention inside
# the module docstring; matching `@mcp.tool(` rather than `@mcp.tool()` also stays correct
# if a tool is ever registered with an explicit name= argument.
_DECORATOR_RE = re.compile(r"^[ \t]*@mcp\.tool\(", re.MULTILINE)


def _exposed_tools() -> list[str]:
    return [t.name for t in asyncio.run(server.mcp.list_tools())]


def test_exposed_tool_count_is_pinned():
    names = _exposed_tools()
    assert len(names) == EXPECTED_TOOL_COUNT, (
        f"tool surface changed: registry exposes {len(names)}, expected "
        f"{EXPECTED_TOOL_COUNT}. If intentional, bump EXPECTED_TOOL_COUNT and the count "
        f"in README.md / CHANGELOG.md / CLAUDE.md."
    )


def test_no_silently_shadowed_tools():
    """Every @mcp.tool() decorator must yield a distinct exposed tool.

    The registry is name-keyed, so a same-name collision never shows up as a *duplicate* —
    it shows up as a *missing* entry. So the meaningful guard is decorator-lines == exposed
    count; if two decorators share a name, one is dropped and this assertion fires.
    """
    names = _exposed_tools()
    decorator_count = len(_DECORATOR_RE.findall(_SERVER_SRC))
    assert decorator_count == len(names), (
        f"{decorator_count} @mcp.tool() decorators but only {len(names)} tools exposed — "
        f"a tool name collides and is being silently shadowed (lost tool)."
    )
