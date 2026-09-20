#!/usr/bin/env python3
"""API coverage receipt — how much of the four Proxmox API trees Proximo's code reaches.

Denominator: every `(path, method)` in the official api-viewer trees, vendored under
`src/proximo/apidoc/*.ops.json` (`fetch` rewrites them from the published `apidoc.js`);
the matching rules live in `proximo.apitree`, shared with the raw GET door.
Numerator: every path literal in `src/proximo/**/*.py`, attributed to a product by
module name (`pbs*`/`pmg*`/`pdm*`, else PVE) and, for a helper another plane's tool module
imports by name, to that plane too for exactly the imported defs, with `{...}` segments as wildcards,
query strings dropped, and `f"{self._helper(...)}/tail"` expanded through the helper's
own literal. Three numbers per product, weakest first:

  strict   (path, method) pairs where the method is named on the same line as the literal
  touched  operations whose path appears anywhere in the source (any method)
  paths    distinct paths reached / distinct paths in the tree

Exclusions (stated, not hidden): the PBS backup/reader wire protocols and the console and
migration tunnel endpoints are not REST tools and are dropped from the denominator; PMG's
`/config/whitelist` is the deprecated alias of `/config/welcomelist`.

Usage:
  python scripts/api_coverage.py                 # table + untouched subtrees per product
  python scripts/api_coverage.py --json          # machine-readable
  python scripts/api_coverage.py --untouched pve # every untouched path for one product
  python scripts/api_coverage.py fetch           # re-vendor the four trees (network)

Consumed by tests/test_api_coverage.py (controls both ways) and the internal ceiling doc.
Stdlib only.
"""

from __future__ import annotations

import collections
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "proximo"
sys.path.insert(0, str(SRC.parent))
from proximo.apitree import (  # noqa: E402
    EXCLUDED_EXACT,
    EXCLUDED_PREFIXES,
    EXCLUDED_TAILS,
    PRODUCTS,
    SOURCES,
    matches,
    norm,
)

APIDOC = SRC / "apidoc"
ROOTS = frozenset(
    {
        "nodes",
        "cluster",
        "access",
        "storage",
        "pools",
        "version",
        "admin",
        "config",
        "tape",
        "status",
        "ping",
        "remotes",
        "pve",
        "pbs",
        "quarantine",
        "statistics",
        "resources",
        "sdn",
        "ceph",
        "subscriptions",
        "auto-install",
        "backup",
        "reader",
    }
)
_LIT = re.compile(r"""(?:f|rf|fr)?(["'])((?:\{[^}]*\})?/(?:(?!\1).)*)\1""")
_VERB = re.compile(
    r"""(?:^|[\W_])(get|post|put|delete)\(|method\s*=\s*["'](GET|POST|PUT|DELETE)["']|["'](GET|POST|PUT|DELETE)["']\s*,"""
)
_HELPER_CALL = re.compile(r"\{(?:self\.)?(_\w+)\([^}]*\)\}(.*)")
_VAR_SUBPATH_CALL = re.compile(r"(?:self\.)?(_\w+)\(\s*\w+\s*,\s*(\w+)\s*[,)]")
_VAR_HEAD = re.compile(r"\{(\w+)\}(.*)")
_DEF = re.compile(r"^(\s*)def (\w+)\(")
_SET_DEF = re.compile(r"^(_?[A-Z][A-Z0-9_]+)\s*=\s*(?:frozenset\()?\{")
_SET_UNION = re.compile(r"^(_?[A-Z][A-Z0-9_]+)\s*=\s*(_?[A-Z][A-Z0-9_]+(?:\s*\|\s*_?[A-Z][A-Z0-9_]+)+)\s*$")
_MEMBER = re.compile(r"""["']([a-z][a-z0-9_-]*)["']""")
_GATED = re.compile(r"\b(\w+)\s+(?:not\s+)?in\s+(_?[A-Z][A-Z0-9_]+)\b")
_RETURN = re.compile(r"""^\s*(?:return|\w+\s*=)\s*f?(["'])(/(?:(?!\1).)*)\1""")
_ASSIGN = re.compile(r"^\s*(\w+)(?:\s*,\s*\w+)*\s*=\s*(?:self\.)?(_\w+)\(")
_SUBPATH_CALL = re.compile(r"""(?:self\.)?(_\w+)\(\s*[^()"']*?(?:f|rf|fr)?(["'])([a-z{](?:(?!\2).)*)\2""")


def excluded(product: str, path: str) -> bool:
    return (
        path in EXCLUDED_EXACT[product]
        or path.startswith(EXCLUDED_PREFIXES[product])
        or path.rsplit("/", 1)[-1] in EXCLUDED_TAILS
    )


def product_of(module: Path) -> str:
    name = module.name
    for p in ("pbs", "pmg", "pdm"):
        if p in name:
            return p
    return "pve"


def load_tree(product: str, apidoc_dir: Path = APIDOC) -> set[tuple[str, str]]:
    ops = json.loads((apidoc_dir / f"{product}.ops.json").read_text())
    return {(norm(p), m) for p, m in ops if not excluded(product, norm(p))}


def _owners(lines: list[str]) -> list[str | None]:
    """The `def` each line belongs to (None at module level)."""
    out: list[str | None] = []
    current: str | None = None
    indent = 0
    for line in lines:
        d = _DEF.match(line)
        if d:
            current, indent = d.group(2), len(d.group(1))
        else:
            stripped = line.strip()
            if current and stripped and not stripped.startswith(")") and (len(line) - len(line.lstrip())) <= indent:
                current = None
        out.append(current)
    return out


def _helper_returns(lines: list[str]) -> dict[str, list[str]]:
    """Every `def` in the file mapped to the path literals it `return`s or binds to a local.
    A helper such as `_fw_base` returns one of three bases; a caller's `f"{base}/rules"`
    reaches all three."""
    out: dict[str, list[str]] = collections.defaultdict(list)
    for owner, line in zip(_owners(lines), lines, strict=True):
        if owner and (r := _RETURN.match(line)):
            out[owner].append(r.group(2))
    return out


def _expand(lit: str, lines: list[str], at: int, helpers: dict[str, list[str]]) -> list[str]:
    """A literal that opens with `{...}` is a base plus a tail; resolve the base through the
    helper it came from (called inline, or assigned to a local a few lines up)."""
    if not lit.startswith("{"):
        return [lit]
    if call := _HELPER_CALL.match(lit):
        return [base + call.group(2) for base in helpers.get(call.group(1), [])]
    var = _VAR_HEAD.match(lit)
    if not var:
        return []
    for back in range(at - 1, max(-1, at - 40), -1):
        asg = _ASSIGN.match(lines[back])
        if asg and asg.group(1) == var.group(1):
            return [base + var.group(2) for base in helpers.get(asg.group(2), [])]
    return []


def _string_sets(lines: list[str]) -> dict[str, set[str]]:
    """Module-level `NAME = frozenset({...})` string sets, and `A = B | C` unions of them: the
    allowlists a helper checks a slot against before building its path."""
    sets: dict[str, set[str]] = {}
    i = 0
    while i < len(lines):
        if d := _SET_DEF.match(lines[i]):
            block = ""
            depth = 0
            while i < len(lines):
                block += lines[i]
                depth += lines[i].count("{") - lines[i].count("}")
                i += 1
                if depth <= 0:
                    break
            sets[d.group(1)] = set(_MEMBER.findall(block))
            continue
        if u := _SET_UNION.match(lines[i]):
            sets[u.group(1)] = set().union(*(sets.get(n.strip(), set()) for n in u.group(2).split("|")))
        i += 1
    return sets


def _gated_slots(
    lines: list[str], owners: list[str | None], sets: dict[str, set[str]]
) -> dict[str, dict[str, set[str]]]:
    """Per def: slot variables checked with `x in NAME` against known string sets (all of them
    unioned: the first check is the allowlist, later ones dispatch within it)."""
    out: dict[str, dict[str, set[str]]] = collections.defaultdict(dict)
    for owner, line in zip(owners, lines, strict=True):
        if owner:
            for var, name in _GATED.findall(line):
                if name in sets:
                    out[owner][var] = out[owner].get(var, set()) | sets[name]
    return out


def _params(lines: list[str], at: int) -> list[str]:
    """Parameter names of the def starting at line `at`, `self` dropped."""
    sig = ""
    for line in lines[at:]:
        sig += line
        if ")" in line:
            break
    inner = sig[sig.index("(") + 1 : sig.rindex(")")]
    names = [re.split(r"[:=]", part.strip(), maxsplit=1)[0].strip().lstrip("*") for part in inner.split(",")]
    return [n for n in names if n and n != "self"]


def _split_args(text: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _forwarded(lines: list[str], owner: str, param: str) -> list[str]:
    """String literals that callers of `owner` pass in the `param` slot, positionally or by
    keyword, so a wrapper that forwards `kind` to a proxy helper counts what it was handed."""
    starts = [i for i, line in enumerate(lines) if (d := _DEF.match(line)) and d.group(2) == owner]
    if not starts:
        return []
    params = _params(lines, starts[0])
    if param not in params:
        return []
    idx = params.index(param)
    lits: list[str] = []
    call = re.compile(r"(?:self\.)?" + re.escape(owner) + r"\((.*)\)")
    for i, line in enumerate(lines):
        if i in starts:
            continue
        for m in call.finditer(line):
            args = _split_args(m.group(1))
            for j, arg in enumerate(args):
                key = arg.split("=", 1)[0].strip() if "=" in arg and not arg.startswith(('"', "'")) else None
                val = arg.split("=", 1)[1].strip() if key else arg
                if (key == param or (key is None and j == idx)) and val[:1] in "\"'" and val[-1:] == val[:1]:
                    lits.append(val[1:-1])
    return lits


_IMPORT_BLOCK = re.compile(r"^from proximo\.(\w+) import \(([^)]*)\)", re.M | re.S)
_IMPORT_LINE = re.compile(r"^from proximo\.(\w+) import ([^(\n]+)$", re.M)


def cross_plane_imports(src: Path = SRC) -> dict[Path, dict[str, set[str]]]:
    """helper module -> {plane: names} for every `tools/<plane>_*.py` that imports names from a
    helper of ANOTHER plane. The PDM identity core rides proximo.pbs_access with a PdmBackend:
    the defs it imports reach the PDM tree too, and only those (the realm and TFA helpers it does
    not import stay PBS-only)."""
    table: dict[Path, dict[str, set[str]]] = collections.defaultdict(lambda: collections.defaultdict(set))
    for tool in (src / "tools").glob("*.py"):
        plane = product_of(tool)
        text = tool.read_text()
        hits = [(m.group(1), m.group(2)) for m in _IMPORT_BLOCK.finditer(text)]
        hits += [(m.group(1), m.group(2)) for m in _IMPORT_LINE.finditer(text)]
        for mod, names in hits:
            helper = src / f"{mod}.py"
            if not helper.exists() or product_of(helper) == plane:
                continue
            table[helper][plane].update(n.strip() for n in names.replace("\n", ",").split(",") if n.strip())
    return table


def source_literals(src: Path = SRC) -> dict[str, set[tuple[str, str | None]]]:
    """Every API-shaped path literal in the package, per product, with the method when the
    line names one. Helper-built prefixes are expanded through the helper's own returns; a
    proxy helper whose base ends in a sub-path slot (`/pve/remotes/{r}/{subpath}`) counts
    only what its callers pass, never the slot itself."""
    # rawdoor.py names the paths it REFUSES; counting them would credit the door with reach.
    modules = [m for m in src.rglob("*.py") if not m.name.startswith("test") and m.name != "rawdoor.py"]
    helpers: dict[str, list[str]] = collections.defaultdict(list)
    per_file: dict[Path, list[str]] = {}
    passthrough: set[str] = set()
    for m in modules:
        per_file[m] = m.read_text().split("\n")
        for name, rets in _helper_returns(per_file[m]).items():
            helpers[name].extend(rets)
        for line in per_file[m]:
            passthrough.update(name for name, _q, _t in _SUBPATH_CALL.findall(line))
            passthrough.update(name for name, _v in _VAR_SUBPATH_CALL.findall(line))
    passthrough = {n for n in passthrough if any(norm(b).endswith("/{}") for b in helpers.get(n, []))}
    found: dict[str, set[tuple[str, str | None]]] = collections.defaultdict(set)
    cross = cross_plane_imports(src)
    for m in modules:
        product = product_of(m)
        lines = per_file[m]
        owners = _owners(lines)
        credit = cross.get(m, {})
        gated = _gated_slots(lines, owners, _string_sets(lines))
        for i, line in enumerate(lines):
            verb = _VERB.search(line)
            method = (verb.group(1) or verb.group(2) or verb.group(3)).upper() if verb else None
            raws = [raw for _q, raw in _LIT.findall(line)]
            if owners[i] in passthrough:
                raws = [r for r in raws if not norm(r).endswith("/{}")]
            bases = {
                name: [re.sub(r"\{[^}]*\}$", "", b) for b in helpers[name] if norm(b).endswith("/{}")]
                for name in passthrough
            }
            for name, _q, tail in _SUBPATH_CALL.findall(line):
                if name in passthrough:
                    raws += [b + tail for b in bases[name]]
            for name, var in _VAR_SUBPATH_CALL.findall(line):
                # `self._pve_remote_get(remote, kind)`: kind is a parameter of this def, so the
                # tails are whatever callers of this def pass in that slot.
                if name in passthrough and owners[i]:
                    raws += [b + t for b in bases[name] for t in _forwarded(lines, owners[i], var)]
            for raw in raws:
                for slot, members in gated.get(owners[i] or "", {}).items():
                    if "{" + slot + "}" in raw:
                        raws += [raw.replace("{" + slot + "}", m) for m in members]
                        raw = ""
                if not raw:
                    continue
                for lit in _expand(raw, lines, i, helpers):
                    if " " in lit or lit.startswith("//"):
                        continue
                    if lit.strip("/").split("/")[0] not in ROOTS:
                        continue
                    found[product].add((norm(lit), method))
                    for plane, names in credit.items():
                        if owners[i] in names:
                            found[plane].add((norm(lit), method))
    return found


def measure(src: Path = SRC, apidoc_dir: Path = APIDOC) -> dict[str, dict]:
    lits = source_literals(src)
    report: dict[str, dict] = {}
    for product in PRODUCTS:
        api = load_tree(product, apidoc_dir)
        mine = lits.get(product, set())
        strict = {op for op in api if any(lm == op[1] and matches(lp, op[0]) for lp, lm in mine)}
        touched = {op for op in api if any(matches(lp, op[0]) for lp, _ in mine)}
        api_paths = {p for p, _ in api}
        touched_paths = {p for p, _ in touched}
        reads = {op for op in api if op[1] == "GET"}
        muts = api - reads
        report[product] = {
            "ops": len(api),
            "strict": len(strict),
            "touched": len(touched),
            "paths": [len(touched_paths), len(api_paths)],
            "reads": [len(strict & reads), len(reads)],
            "mutating": [len(strict & muts), len(muts)],
            "untouched_paths": sorted(api_paths - touched_paths),
        }
    return report


def _subtree(path: str, depth: int) -> str:
    return "/".join(path.split("/")[:depth])


def render(report: dict[str, dict]) -> str:
    out = ["product | ops | strict | touched | paths | strict reads | strict mutating"]
    tot = collections.Counter()
    for product, r in report.items():
        out.append(
            f"{product:7} | {r['ops']:4} | {r['strict']:4} ({100 * r['strict'] // r['ops']:2}%) | "
            f"{r['touched']:4} ({100 * r['touched'] // r['ops']:2}%) | "
            f"{r['paths'][0]:3}/{r['paths'][1]:3} ({100 * r['paths'][0] // r['paths'][1]:2}%) | "
            f"{r['reads'][0]:3}/{r['reads'][1]:3} | {r['mutating'][0]:3}/{r['mutating'][1]:3}"
        )
        for k in ("ops", "strict", "touched"):
            tot[k] += r[k]
        tot["tp"] += r["paths"][0]
        tot["ap"] += r["paths"][1]
    out.append(
        f"{'TOTAL':7} | {tot['ops']:4} | {tot['strict']:4} ({100 * tot['strict'] // tot['ops']:2}%) | "
        f"{tot['touched']:4} ({100 * tot['touched'] // tot['ops']:2}%) | "
        f"{tot['tp']:3}/{tot['ap']:3} ({100 * tot['tp'] // tot['ap']:2}%) |"
    )
    for product, r in report.items():
        depth = 4 if product == "pve" else 3
        by = collections.Counter(_subtree(p, depth) for p in r["untouched_paths"])
        top = ", ".join(f"{k}={v}" for k, v in by.most_common(12))
        out.append(f"untouched {product}: {top}")
    return "\n".join(out)


def fetch(apidoc_dir: Path = APIDOC) -> None:
    import urllib.request

    def walk(nodes: list, out: list) -> None:
        for n in nodes:
            for m in n.get("info") or {}:
                if m in ("GET", "POST", "PUT", "DELETE"):
                    out.append((n["path"], m))
            walk(n.get("children") or [], out)

    for product, url in SOURCES.items():
        with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 — fixed https URLs
            text = resp.read().decode("utf-8", "replace")
        tree, _ = json.JSONDecoder().raw_decode(text, text.find("["))
        ops: list = []
        walk(tree, ops)
        (apidoc_dir / f"{product}.ops.json").write_text(json.dumps(sorted(ops), separators=(",", ":")))
        print(f"{product}: {len(ops)} operations")


def main(argv: list[str]) -> int:
    if argv[:1] == ["fetch"]:
        fetch()
        return 0
    report = measure()
    if "--json" in argv:
        print(json.dumps(report, indent=1))
    elif "--untouched" in argv:
        product = argv[argv.index("--untouched") + 1]
        print("\n".join(report[product]["untouched_paths"]))
    else:
        print(render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
