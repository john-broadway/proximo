#!/usr/bin/env python3
"""What would this tiers file OPEN? Answer before copying it over `tiers.toml`.

A tier does not restrict an address, it opens it: with no tier an address is refused even when
the operator is armed. So adopting a tiers file is a grant, and the one question a `cp` cannot
answer is "a grant of what, exactly".

This prints every address a candidate file would make executable, grouped by tier, with the
gated and read-only rows separated out so the count is not inflated by rows that stay refused
for other reasons.

    python scripts/tier_preview.py src/proximo/core/tiers.toml
    python scripts/tier_preview.py candidate.toml --verbose
"""
from __future__ import annotations

import argparse
import collections
import pathlib
import sys
import tomllib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from proximo.core import engine  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("candidate", type=pathlib.Path)
    ap.add_argument("--verbose", action="store_true", help="list every opened address")
    args = ap.parse_args()

    parsed = tomllib.loads(args.candidate.read_text()).get("tier", {})
    def _tier(v):
        return v["tier"] if isinstance(v, dict) else v
    addresses = {k: _tier(v) for k, v in parsed.items() if k != "family"}
    families = {k: _tier(v) for k, v in parsed.get("family", {}).items()}

    rows = engine.table().values()
    opened, inert = [], []
    for key, tier in {**addresses}.items():
        hit = [r for r in rows if f"{r.product}:{r.method} {r.path}" == key]
        (opened if hit else inert).append((key, tier, hit))
    for key, tier in families.items():
        hit = [r for r in rows if f"{r.product}:{engine.family(r.path)}" == key]
        (opened if hit else inert).append((key, tier, hit))

    flat = [(tier, r) for _, tier, hits in opened for r in hits]
    live = [(t, r) for t, r in flat if r.access == "mutate" and not r.excluded and not r.gate]
    held = [(t, r) for t, r in flat if r.access == "mutate" and (r.excluded or r.gate)]
    reads = [(t, r) for t, r in flat if r.access == "read"]

    print(f"candidate: {args.candidate}")
    print(f"  lines                        : {len(addresses)} address, {len(families)} family")
    print(f"  MUTATIONS THIS WOULD OPEN    : {len(live)}   <-- the grant")
    print(f"  mutations still held (gated/excluded): {len(held)}")
    print(f"  reads incidentally labelled  : {len(reads)}")
    if inert:
        print(f"  !! keys matching NO address  : {len(inert)}  {[k for k, _, _ in inert][:3]}")
    print()
    by = collections.Counter(t for t, _ in live)
    for tier, n in by.most_common():
        print(f"  {tier:12s} opens {n:4d} mutating addresses")
    if args.verbose:
        print()
        for tier, r in sorted(live, key=lambda t: (t[0], t[1].product, t[1].path)):
            print(f"    {tier:12s} {r.product} {r.method:6s} {r.path}")
    # A family line that opens far more than its author likely pictured is the C1 failure mode.
    for key, tier, hits in opened:
        live_here = [r for r in hits if r.access == "mutate" and not r.excluded and not r.gate]
        if key.split(":", 1)[1].count("/") <= 2 and len(live_here) > 8:
            print(f"\n  ** {key} = {tier!r} opens {len(live_here)} mutating addresses. "
                  f"Read them before accepting this line.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
