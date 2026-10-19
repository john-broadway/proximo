#!/usr/bin/env python3
"""Generate the governance table: every published Proxmox address, governed, from the vendor schema.

THE TABLE IS GENERATED, NEVER HAND-EDITED. Governance that a human retypes is governance that
drifts; the whole point of keying on the vendor's own schema is that coverage tracks the vendor
instead of tracking whoever last had time. `tests/test_engine.py` cross-checks the committed
artifact against `proximo.core.apitree` (a SECOND independently vendored source) so a stale table is a
red test, not a silent 61%.

Sources are the four api-viewer `apidoc.js` files named in `proximo.core.apitree.SOURCES`. They are
NOT vendored (15.7 MB); this reads a local cache and `--fetch` refreshes it.

    python scripts/build_governance_table.py --cache .apidoc-cache [--fetch]
"""
from __future__ import annotations

import argparse
import gzip
import json
import pathlib
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from proximo.core import apitree, rawdoor  # noqa: E402

OUT = (pathlib.Path(__file__).resolve().parent.parent
       / "src" / "proximo" / "core" / "table.json.gz")


def fetch(cache: pathlib.Path) -> None:
    cache.mkdir(parents=True, exist_ok=True)
    for product, url in apitree.SOURCES.items():
        with urllib.request.urlopen(url, timeout=120) as r:  # noqa: S310 - vendor doc, https
            (cache / f"{product}-apidoc.js").write_bytes(r.read())
        print(f"fetched {product}")


def parse(path: pathlib.Path) -> list:
    """The file is `const apiSchema = [...]` followed by viewer JS; decode only the array."""
    text = path.read_text()
    return json.JSONDecoder().raw_decode(text[text.index("["):])[0]


def walk(node: dict, path: str = "") -> list[tuple[str, str, dict]]:
    here = node.get("path", path)
    out = [(here, method, info) for method, info in (node.get("info") or {}).items()]
    for child in node.get("children") or []:
        out.extend(walk(child, here))
    return out


def properties(params: dict) -> dict:
    """Every parameter an address publishes, its `allOf` blocks merged in, recursively.

    PBS (and one PVE address) nest the body: `{"allOf": [{"properties": {...}}, {"allOf": [...]}]}`
    with no top-level `properties`. Reading the top level alone gave 78 addresses an EMPTY table
    entry, so the engine refused every argument there: the core could not update a PBS datastore,
    a remote or a user, and no restore reached them (parity B19, 2026-10-02 / 2026-10-05). A name
    published twice keeps its first spec: the outer block is the address's own.
    """
    out: dict = {}
    for name, spec in (params.get("properties") or {}).items():
        out.setdefault(name, spec)
    # A TYPED body (`oneOf` keyed by `type-property`, PVE's HA rules): the discriminator is a
    # parameter the vendor requires, published with its own schema; each variant's parameters are
    # merged as a union (one a variant does not take is still refused by the vendor, as now).
    if params.get("type-property") and isinstance(params.get("type-property-schema"), dict):
        out.setdefault(params["type-property"], params["type-property-schema"])
    for block in params.get("allOf") or []:
        if isinstance(block, dict):
            for name, spec in properties(block).items():
                out.setdefault(name, spec)
    # A UNION IS OPTIONAL WHERE ANY VARIANT IS. Keeping the first variant's spec made `nodes`
    # (required by node-affinity only) required for every HA rule, and refused a resource-affinity
    # rule the vendor takes. A name is required only when every variant requires it.
    variants = [properties(b) for b in params.get("oneOf") or [] if isinstance(b, dict)]
    for name in dict.fromkeys(n for v in variants for n in v):
        if name in out:
            continue
        spec = next(v[name] for v in variants if name in v)
        if not all(name in v and not v[name].get("optional") for v in variants):
            spec = {**spec, "optional": 1}
        out[name] = spec
    return out


def gates() -> dict[str, list[tuple[str, str]]]:
    """The address-independent policy Proximo ALREADY enforces, read out of the code that owns it.

    Lifted programmatically from `rawdoor._GATED` rather than retyped: two copies of a policy are
    one check, and the copy always loses.
    """
    return {product: list(entries) for product, entries in rawdoor._GATED.items()}


def build(cache: pathlib.Path) -> list[dict]:
    gated = gates()
    rows: list[dict] = []
    for product in apitree.PRODUCTS:
        source = cache / f"{product}-apidoc.js"
        if not source.exists():
            raise SystemExit(f"missing {source} - run with --fetch")
        for node in parse(source):
            for path, method, info in walk(node):
                props = properties(info.get("parameters") or {})
                gate = next((why for prefix, why in gated.get(product, ())
                             if path.startswith(prefix)), None)
                rows.append({
                    "product": product,
                    "path": path,
                    "method": method,
                    # DERIVED, TOTAL, CANNOT DRIFT. This one column replaces 924 docstring markers.
                    "access": "read" if method == "GET" else "mutate",
                    # Not REST reads/writes (console + migration tunnels, protocol roots).
                    "excluded": bool(apitree.excluded(product, path)),
                    # A curated tool already stands guard here; the door points at it.
                    "gate": gate,
                    # The vendor's own parameter schema. Argument validation is PUBLISHED.
                    "params": {
                        name: {
                            "type": spec.get("type"),
                            "optional": bool(spec.get("optional")),
                            "description": (spec.get("description") or "")[:200],
                        }
                        for name, spec in props.items()
                    },
                    # THE ONLY HUMAN-AUTHORED COLUMN. None = untiered = strictest handling.
                    "tier": None,
                })
    rows.sort(key=lambda r: (r["product"], r["path"], r["method"]))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", default=".apidoc-cache", type=pathlib.Path)
    ap.add_argument("--fetch", action="store_true")
    args = ap.parse_args()
    if args.fetch:
        fetch(args.cache)
    rows = build(args.cache)
    blob = json.dumps(rows, separators=(",", ":"), sort_keys=True).encode()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(gzip.compress(blob, mtime=0))  # mtime=0 -> byte-reproducible
    print(f"{len(rows)} rows -> {OUT} ({OUT.stat().st_size:,} B gz, {len(blob):,} B raw)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
