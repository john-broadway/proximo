"""Every address whose vendor RETURN schema names a credential-shaped field: the second source
of `src/proximo/core/secrets.toml`, generated so a guard can hold the record to it. Every method:
until 2026-10-04 this scanned GETs alone, and two lenses found the class it left out, a MUTATION
whose answer is a one-time secret its read never shows (a token mint's value, a second factor's
recovery codes, an auto-generated storage encryption key).

The first source (every read a backend strips) is scanned from the code by
tests/test_secret_record.py. This one reads the published api-viewer (`apidoc.js`, the same
four URLs `proximo.core.apitree.SOURCES` names) and writes `tests/fixtures/vendor-secret-returns.json`:
`{"plane:METHOD /path": [field, ...]}` for every return-schema field whose NAME looks like a
credential. A name is a candidate, not a verdict: the guard makes every candidate either a
record line or a named exclusion with its reason.

    python scripts/secret_returns.py                 # fetch the four apidoc.js and write
    python scripts/secret_returns.py --from DIR      # DIR/{pve,pbs,pmg,pdm}.js, already fetched
"""
from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path

from proximo.core.apitree import SOURCES

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "vendor-secret-returns.json"
#: a credential-shaped last name segment; wide on purpose (the guard sorts the candidates)
CANDIDATE = re.compile(r"pass|secret|hmac|private|bindpw|credential|token|recovery|challenge|ticket|csrf"
                       r"|authkey|(^|[-_])keys?$|^key$|^value$", re.I)    # value: a token mint's one-time secret


def _fields(schema: object, prefix: str = "") -> list[str]:
    """Dotted field names in a return schema, `[]` marking an array level."""
    if not isinstance(schema, dict):
        return []
    if schema.get("type") == "array" and "items" in schema:
        return _fields(schema["items"], prefix + "[]")
    out = []
    for name, sub in (schema.get("properties") or {}).items():
        out.append(prefix + name)
        out += _fields(sub, prefix + name + ".")
    # PBS nests a schema in `allOf` blocks (and the vendor uses oneOf/anyOf too): reading the
    # top level alone missed every field inside them, the same blind spot the table builder had
    # for parameters until B19 (2026-10-05). Six candidates surfaced, all judged in the guard.
    for key in ("allOf", "oneOf", "anyOf"):
        for block in schema.get(key) or []:
            out += _fields(block, prefix)
    return out


def scan(text: str, plane: str) -> dict[str, list[str]]:
    tree, _ = json.JSONDecoder().raw_decode(text, text.find("["))
    found: dict[str, list[str]] = {}

    def walk(nodes: list) -> None:
        for n in nodes:
            for method, info in (n.get("info") or {}).items():
                if method not in ("GET", "POST", "PUT", "DELETE"):
                    continue
                hits = sorted({f for f in _fields(info.get("returns") or {})
                               if CANDIDATE.search(f.split(".")[-1].lstrip("[]"))})
                if hits:
                    found[f"{plane}:{method} {n['path']}"] = hits
            walk(n.get("children") or [])

    walk(tree)
    return found


def main(argv: list[str]) -> int:
    src = Path(argv[argv.index("--from") + 1]) if "--from" in argv else None
    out: dict[str, list[str]] = {}
    for plane, url in SOURCES.items():
        if src is not None:
            text = (src / f"{plane}.js").read_text()
        else:
            with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 — fixed https URLs
                text = resp.read().decode("utf-8", "replace")
        out.update(scan(text, plane))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(dict(sorted(out.items())), indent=1) + "\n")
    print(f"{len(out)} addresses, {sum(map(len, out.values()))} candidate fields -> {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
