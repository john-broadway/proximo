#!/usr/bin/env python3
"""Regenerate lhm.plugin.json — the LobeHub Marketplace manifest — from the live server.

LobeHub scores a listing partly on declared capabilities (a non-empty `tools`
array sets the "tools" capability and satisfies the "Includes At Least One Skill"
required score item). Their crawler extracts tools by cold-starting the server and
calling `tools/list`; if that extraction ever misses, the listing drops to grade F.
Publishing an owner-declared `tools` array is authoritative and a re-crawl never
overwrites it, so we ship the real surface in the manifest.

This script cold-starts `proximo` over stdio with NO PROXIMO_* env (exactly the
crawler's view), reads the full tool list, and writes it into lhm.plugin.json with
the version single-sourced from pyproject.toml. Run at release time, then
`lhm plugin publish --dir .`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "lhm.plugin.json"

# Static listing fields. identifier is assigned by the marketplace at first
# listing — never invent it; keep name/description in sync with the README lead.
BASE = {
    "identifier": "john-broadway-proximo",
    # "Proxmox" must appear in the NAME, not just the description — LobeHub/Glama
    # keyword search matches the name field, and "Proximo" doesn't contain the
    # substring "proxmox" (2026-07-10 community audit: invisible in "proxmox" search).
    "name": "Proximo — the Proxmox MCP you can hand the keys",
    # description is NOT here on purpose — see pyproject_description(). It used to be a
    # hardcoded copy of the pyproject line, and the two silently diverged: CLAUDE.md said
    # "description comes from pyproject" while this literal was the real source, so a
    # regen re-wrote the STALE text over a corrected one (2026-07-26).
}


def pyproject_version() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    return data["project"]["version"]


def pyproject_description() -> str:
    """The ONE description, read from pyproject — the same line PyPI ships.

    Every listing that quotes a different sentence is a listing that drifts on its own
    clock. Keep the estate on one source: pyproject -> PyPI + this manifest, and the same
    text pasted into server.json (the MCP registry caps title/description at 100 chars,
    so the line is written to fit that ceiling and therefore fits everywhere else too).
    """
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    return data["project"]["description"]


def list_capabilities(timeout: float = 90.0) -> dict[str, list[dict]]:
    """Cold-start proximo and return its tools + prompts — the crawler's-eye view.

    One stdio session, both `tools/list` and `prompts/list`, so the manifest
    declares every capability the server actually exposes on a cold start.
    """
    import selectors

    env = {k: v for k, v in os.environ.items() if not k.startswith("PROXIMO")}
    # The marketplace listing must declare the FULL catalog, not a surface auto-scoped to this
    # box. main() re-loads ~/.config/proximo/proximo.env from disk (bypassing the strip above),
    # so its PROXIMO_API_BASE_URL would trigger auto-scope → a truncated tool list. Force full.
    env["PROXIMO_SURFACES"] = "all"
    proc = subprocess.Popen(
        ["uv", "run", "proximo"],  # noqa: S603, S607  # dev/release helper; fixed argv, uv on PATH
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )

    def send(obj: dict) -> None:
        assert proc.stdin  # noqa: S101  # Popen(PIPE) guarantees these streams; assert documents the invariant
        proc.stdin.write((json.dumps(obj) + "\n").encode())
        proc.stdin.flush()

    # id 2 -> tools/list, id 3 -> prompts/list
    want = {2: "tools", 3: "prompts"}
    got: dict[str, list[dict]] = {}
    try:
        send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05", "capabilities": {},
                "clientInfo": {"name": "gen-lobehub-manifest", "version": "1"},
            },
        })
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        send({"jsonrpc": "2.0", "id": 3, "method": "prompts/list", "params": {}})

        assert proc.stdout  # noqa: S101  # Popen(PIPE) guarantees this stream; assert documents the invariant
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        while len(got) < len(want):
            if not sel.select(timeout=timeout):
                break
            line = proc.stdout.readline()
            if not line:
                break
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = want.get(msg.get("id"))
            if key is not None:
                got[key] = msg.get("result", {}).get(key, [])
        if "tools" not in got:
            raise SystemExit(
                "no tools/list response; stderr tail:\n"
                + proc.stderr.read().decode(errors="replace")[-2000:]
            )
        return got
    finally:
        proc.kill()


def main() -> int:
    caps = list_capabilities()
    tools, prompts = caps.get("tools", []), caps.get("prompts", [])
    if not tools:
        raise SystemExit("refusing to write an empty tools array")
    manifest = {
        **BASE,
        "description": pyproject_description(),
        "version": pyproject_version(),
        "tools": [
            {"name": t["name"], "description": t.get("description", ""),
             "inputSchema": t["inputSchema"]}
            for t in tools
        ],
    }
    if prompts:
        manifest["prompts"] = [
            {"name": p["name"], "description": p.get("description", ""),
             "arguments": p.get("arguments", [])}
            for p in prompts
        ]
    MANIFEST.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(
        f"wrote {MANIFEST.relative_to(ROOT)} — {len(tools)} tools, "
        f"{len(prompts)} prompts, v{manifest['version']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
