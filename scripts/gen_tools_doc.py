#!/usr/bin/env python3
"""Regenerate docs/TOOLS.md — the human-readable reference for Proximo's tool surface.

Derived from `lhm.plugin.json` (itself a live-server `tools/list` dump written by
`gen_lobehub_manifest.py` at release time), so the reference always matches the
shipped catalog. Each tool's inputs come straight from its MCP JSON input schema.

Run after `gen_lobehub_manifest.py` in the release ripple:
    uv run python scripts/gen_tools_doc.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "lhm.plugin.json"
OUT = ROOT / "docs" / "TOOLS.md"

# (prefix-predicate, section title). Order defines the document order. First match wins.
SURFACES: list[tuple[str, str]] = [
    ("pve_agent_", "Proxmox VE — in-guest agent (opt-in)"),
    ("pve_", "Proxmox VE (PVE)"),
    ("pbs_", "Proxmox Backup Server (PBS)"),
    ("pmg_", "Proxmox Mail Gateway (PMG)"),
    ("pdm_", "Proxmox Datacenter Manager (PDM)"),
    ("ct_", "Container exec (opt-in)"),
]
CORE_TITLE = "Core / trust spine"


def gh_anchor(title: str) -> str:
    """GitHub's heading-anchor rule: lowercase, drop punctuation (keep word chars,
    spaces, hyphens), spaces -> hyphens. Does NOT collapse repeated hyphens, so a
    ' — ' between words yields a double hyphen exactly as GitHub renders it."""
    a = re.sub(r"[^\w\s-]", "", title.lower())
    return a.replace(" ", "-")


def surface_of(name: str) -> str:
    for prefix, title in SURFACES:
        if name.startswith(prefix):
            return title
    return CORE_TITLE


def type_str(prop: dict) -> str:
    """Render a JSON-schema property's type compactly."""
    if "enum" in prop:
        return "enum(" + ", ".join(str(v) for v in prop["enum"]) + ")"
    if "type" in prop:
        t = prop["type"]
        if isinstance(t, list):
            # pydantic v2 emits LIST-form types for a nullable/union scalar, e.g.
            # ["string", "null"] for `str | None`. Rendering str(t) leaked "['string', 'null']"
            # into ~1,100 doc cells; strip null, mark nullable, join the rest (works for any
            # list-form, e.g. ["integer", "null"] too).
            nullable = "null" in t
            parts = [str(x) for x in t if x != "null"]
            base = " | ".join(dict.fromkeys(parts)) or "any"
            return f"{base} (nullable)" if nullable else base
        if t == "array":
            items = prop.get("items") or {}
            inner = items.get("type") or (type_str(items) if items else "any")
            return f"array<{inner}>"
        return str(t)
    if "anyOf" in prop:
        parts = [type_str(p) for p in prop["anyOf"]]
        nullable = "null" in parts
        parts = [p for p in parts if p != "null"]
        base = " | ".join(dict.fromkeys(parts)) or "any"
        return f"{base} (nullable)" if nullable else base
    return "any"


def cell(text: str) -> str:
    """Make a string safe for a Markdown table cell."""
    return str(text).replace("|", r"\|").replace("\n", " ").strip()


def render_tool(tool: dict) -> list[str]:
    name = tool["name"]
    desc = (tool.get("description") or "").strip()
    schema = tool.get("inputSchema") or {}
    props: dict = schema.get("properties") or {}
    required = set(schema.get("required") or [])

    out = [f"#### `{name}`", ""]
    if desc:
        out += [desc, ""]
    if props:
        out += ["| Parameter | Type | Required | Description |",
                "| --- | --- | --- | --- |"]
        for pname, prop in props.items():
            pdesc = prop.get("description", "")
            if "default" in prop:
                d = json.dumps(prop["default"])
                pdesc = f"{pdesc} (default: `{d}`)".strip()
            out.append(
                f"| `{cell(pname)}` | {cell(type_str(prop))} | "
                f"{'yes' if pname in required else 'no'} | {cell(pdesc)} |"
            )
        out.append("")
    else:
        out += ["_No parameters._", ""]
    return out


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    tools = manifest.get("tools") or []
    version = manifest.get("version", "")
    if not tools:
        raise SystemExit("no tools in lhm.plugin.json — run gen_lobehub_manifest.py first")

    # group -> [tools], preserving SURFACES order then Core
    order = [t for _, t in SURFACES] + [CORE_TITLE]
    groups: dict[str, list[dict]] = {title: [] for title in order}
    for t in tools:
        groups[surface_of(t["name"])].append(t)
    for title in groups:
        groups[title].sort(key=lambda t: t["name"])

    lines: list[str] = [
        "# Proximo — tool reference",
        "",
        f"The complete external interface of Proximo **v{version}**: every MCP tool it "
        "exposes, with its inputs. This file is generated from the live server's "
        "`tools/list` output (via `lhm.plugin.json`) by "
        "[`scripts/gen_tools_doc.py`](../scripts/gen_tools_doc.py) — do not hand-edit.",
        "",
        "**Interface conventions.** Proximo speaks the "
        "[Model Context Protocol](https://modelcontextprotocol.io); each tool is also "
        "self-describing at runtime over the standard `tools/list` method. **Inputs** are "
        "the typed parameters listed per tool below. **Output** is a structured JSON "
        "result: read tools return the requested data; every mutating tool first returns "
        "a **PLAN** preview (the action and its blast radius) rather than acting, and each "
        "call is recorded in the tamper-evident audit ledger. Which tools are registered "
        "depends on `PROXIMO_SURFACES` and whether the opt-in exec/agent edges are enabled; "
        "this reference lists the **full** catalog.",
        "",
        f"**{len(tools)} tools** across {sum(1 for t in order if groups[t])} surfaces.",
        "",
        "## Contents",
        "",
    ]
    for title in order:
        if groups[title]:
            lines.append(f"- [{title}](#{gh_anchor(title)}) — {len(groups[title])}")
    lines.append("")

    for title in order:
        bucket = groups[title]
        if not bucket:
            continue
        lines += [f"## {title}", ""]
        for tool in bucket:
            lines += render_tool(tool)

    OUT.write_text("\n".join(lines).rstrip() + "\n")
    counts = ", ".join(f"{t.split(' (')[0].split(' —')[0]}={len(groups[t])}"
                       for t in order if groups[t])
    print(f"wrote {OUT.relative_to(ROOT)} — {len(tools)} tools ({counts})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
