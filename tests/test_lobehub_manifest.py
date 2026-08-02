"""The LobeHub manifest generator must ask for a DOOR, not a SCOPE.

`lhm.plugin.json` is the canonical tool-count source for `copy_ripple_check.py` and
`listing_drift.py`, and `scripts/gen_tools_doc.py` regenerates the published `docs/TOOLS.md`
from it. It is also the array LobeHub's crawler scores: a listing it extracts no real tools
from is graded F ("Low-Quality, use with caution"), which this project recovered from once
already (F→A, 2026-07-05, by publishing an authoritative array).

WHY THIS FILE EXISTS (external re-vet, 2026-08-02). The generator forced a full surface with
`PROXIMO_SURFACES=all`. That worked only while surfaces still chose the DOOR. The moment
surfaces became scope-only — every plane *searchable* behind the six-tool facade — the same
line started producing a SIX-tool manifest, and nothing in the suite noticed: the generator
had no test at all, and every consumer above reads the committed file rather than running it.
The release ripple would have published a thin listing and a six-tool TOOLS.md.

So the property is not "the env says all". It is "the env names a door", plus a floor on the
committed artifact so a thin regeneration cannot be committed silently.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _generator():
    """Import the generator by path — scripts/ is not a package."""
    spec = importlib.util.spec_from_file_location(
        "gen_lobehub_manifest", ROOT / "scripts" / "gen_lobehub_manifest.py")
    assert spec and spec.loader                                    # noqa: S101
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_generator_env_asks_for_a_door_not_a_scope():
    """The cold-start env must select a DOOR keyword; a scope var cannot make the catalog resident.

    Read from the generator's own source rather than a docstring: the bug was a live env
    assignment, and a comment saying "force full" stayed true-looking while the line under it
    silently stopped forcing anything.
    """
    src = (ROOT / "scripts" / "gen_lobehub_manifest.py").read_text()
    assert 'env["PROXIMO_TOOLSETS"] = "all"' in src, (
        "the generator must ask for the full DOOR (PROXIMO_TOOLSETS=all). Setting only "
        "PROXIMO_SURFACES scopes planes and leaves the facade as the door — which publishes a "
        "six-tool manifest.")
    assert 'env["PROXIMO_SURFACES"] = "all"' not in src, (
        "PROXIMO_SURFACES=all no longer means 'full surface' — it means 'every plane searchable "
        "behind the facade'. It cannot be what forces a full manifest.")


def test_committed_manifest_is_not_a_facade_sized_stub():
    """A floor on the committed artifact: the manifest must carry the real catalog, not the door.

    Deliberately compared against the live registry rather than a hardcoded number, so this
    tracks the surface as it grows instead of going stale the way the count in a doc does. The
    floor is what matters — a manifest at facade size (single digits) is the failure this
    catches, and an exact match would just fight every staged feature.
    """
    from proximo import server

    manifest = json.loads((ROOT / "lhm.plugin.json").read_text())
    declared = len(manifest.get("tools", []))
    registered = len(server.mcp._tool_manager._tools)

    assert declared > 100, (
        f"lhm.plugin.json declares only {declared} tools — that is facade-sized, not the "
        f"catalog. Regenerate with scripts/gen_lobehub_manifest.py and check the door env.")
    assert declared >= registered * 0.9, (
        f"lhm.plugin.json declares {declared} tools but {registered} are registered — the "
        f"manifest is stale or was generated behind a scoped/leaned door.")
