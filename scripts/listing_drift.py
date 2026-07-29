#!/usr/bin/env python3
"""Check what the MCP directories SAY about Proximo against what is true.

`reach.py` answers "how far did we travel". This answers "is what they print still
correct". Different question, and the one that goes wrong silently: a directory
indexes you once and freezes, while its version field keeps auto-updating, so the
listing looks maintained and reads a year out of date.

    python scripts/listing_drift.py           # human table
    python scripts/listing_drift.py --json    # machine-readable

Truth comes from lhm.plugin.json (the same canonical source copy_ripple_check.py
uses for the tool count) and pyproject (version). Nothing here trusts a number
typed into a doc.

WHY THIS EXISTS (2026-07-26). Every stale listing found that day was found because
John happened to look: mcp.so was advertising 325 tools and no Datacenter Manager,
a product two whole planes out of date; Smithery and mcpservers.org were both
carrying an identical frozen blurb generated around v0.21.1; the README's own
scoped-surface example claimed 202 tools against a real 314. Nothing was watching,
so "stale" was discovered rather than reported.

HONESTY, and the whole point of the exit codes: a surface this script cannot READ
is never reported as fine. Glama silently drops non-browser TLS fingerprints (a
connection that completes the handshake and then returns zero bytes) and PulseMCP
answers 403, so both are UNREACHABLE, not CURRENT. A checker that quietly passes
what it failed to fetch is the exact bug this repo spent 2026-07-26 closing in
three other places.

KNOWN FALSE-POSITIVE, stated plainly so nobody trusts this further than it earns: a
listing that renders our README or CHANGELOG contains every tool count we have ever
shipped ("493 -> 603 tools"), and this script cannot tell a live claim from quoted
history. That is why MIXED exists as its own verdict instead of being called STALE:
MIXED means "the true number IS here, and so are others — go look at which field holds
the wrong one". Only STALE (the true number appears nowhere) is unambiguous.

Exit: 0 = every readable surface current. 1 = at least one surface STALE. 2 = nothing
outright stale, but something needs human eyes (MIXED, NO CLAIM, or UNREACHABLE).

Stdlib only — no deps, runs under any python3.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
TIMEOUT = 45  # LobeHub's page is ~730KB and slow; 25s produced a spurious UNREACHABLE.

# A total-count claim. Mirrors copy_ripple_check._TOOL_COUNT_RE: the (?<!\+) keeps the
# per-release delta form ("+12 tools") out, since that is an increment, not a total.
_COUNT_RE = re.compile(r"(?<!\+)\b(\d{2,4}) (?:MCP )?tools\b")
_VER_RE = re.compile(r"\b(\d+\.\d+\.\d+)\b")

SURFACES = [
    ("mcp.so",         "https://mcp.so/server/proximo/john-broadway"),
    ("mcpservers.org", "https://mcpservers.org/servers/john-broadway/proximo"),
    ("smithery",       "https://smithery.ai/server/john-broadway/proximo"),
    ("glama",          "https://glama.ai/mcp/servers/john-broadway/proximo"),
    ("pulsemcp",       "https://www.pulsemcp.com/servers/john-broadway-proximo"),
    ("lobehub",        "https://lobehub.com/mcp/john-broadway-proximo"),
]


def canonical() -> tuple[int, str]:
    """(tool_count, version) — from the generated manifest, which the test suite pins."""
    man = json.loads((ROOT / "lhm.plugin.json").read_text())
    return len(man["tools"]), man["version"]


def fetch(url: str) -> tuple[str | None, str]:
    """(body, note). body is None when the surface could not be read — never '' on failure,
    so an unreadable surface can't be mistaken for an empty-but-fine one."""
    if not url.startswith("https://"):  # only ever called with the fixed consts above; enforce it
        raise ValueError(f"refusing non-https surface URL: {url!r}")
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})  # noqa: S310
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # noqa: S310 — https enforced above
            return r.read().decode("utf-8", "replace"), ""
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except TimeoutError:
        return None, "timeout (TLS completed, zero bytes — bot-fingerprint drop)"
    except Exception as e:  # noqa: BLE001 — a checker must survive any one surface being down
        return None, type(e).__name__


def audit(count: int, version: str) -> list[dict]:
    rows = []
    for name, url in SURFACES:
        body, note = fetch(url)
        if body is None:
            rows.append({"surface": name, "url": url, "state": "UNREACHABLE",
                         "note": note, "counts": [], "versions": []})
            continue
        counts = sorted({int(c) for c in _COUNT_RE.findall(body)})
        vers = sorted({v for v in _VER_RE.findall(body)})
        wrong = [c for c in counts if c != count]
        # Four states, deliberately. The trap is collapsing "no claim found" into CURRENT:
        # a page that never prints a count has not been VERIFIED, it has been un-checked, and
        # calling that a pass is how a checker starts lying (pulsemcp did exactly this on the
        # first run of this script). Only a positive sighting of the true number is a pass.
        if not counts:
            state, why = "NO CLAIM", "page states no tool count — nothing to verify"
        elif count in counts and wrong:
            state, why = "MIXED", f"true {count} present, also {wrong} — check which field holds the wrong one"
        elif wrong:
            state, why = "STALE", f"claims {wrong} tools, truth is {count}"
        else:
            state, why = "CURRENT", f"{count} tools"
        rows.append({"surface": name, "url": url, "state": state, "note": why,
                     "counts": counts, "versions": vers[:4]})
    return rows


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Check directory listings against the truth.")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    count, version = canonical()
    rows = audit(count, version)

    if args.json:
        print(json.dumps({"truth": {"tools": count, "version": version},
                          "surfaces": rows}, indent=2))
    else:
        print(f"Proximo listings — truth: {count} tools, v{version}\n")
        print(f"  {'surface':16} {'state':12} detail")
        print(f"  {'-'*16} {'-'*12} {'-'*44}")
        for r in rows:
            detail = r["note"] or f"{r['counts']} tools"
            print(f"  {r['surface']:16} {r['state']:12} {detail}")
        stale = [r["surface"] for r in rows if r["state"] == "STALE"]
        unread = [r["surface"] for r in rows if r["state"] == "UNREACHABLE"]
        print()
        if stale:
            print(f"  STALE: {', '.join(stale)} — these print a number that is not true.")
        if unread:
            print(f"  COULD NOT READ: {', '.join(unread)} — NOT a pass. Open them yourself.")
        mixed = [r["surface"] for r in rows if r["state"] in ("MIXED", "NO CLAIM")]
        if mixed:
            print(f"  NEEDS EYES: {', '.join(mixed)} — a rendered README/CHANGELOG quotes every")
            print("    count we ever shipped, so this cannot tell a live claim from history.")
        if not stale and not unread and not mixed:
            print("  every surface current.")

    if any(r["state"] == "STALE" for r in rows):
        return 1
    if any(r["state"] in ("MIXED", "NO CLAIM", "UNREACHABLE") for r in rows):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
