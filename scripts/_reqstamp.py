#!/usr/bin/env python3
"""Input-hash stamp for the COMPILED requirements (build.txt, sbom.txt).

runtime.txt and dev.txt are `uv export` snapshots of uv.lock, and the drift guard in
tests/test_requirements_lock.py already watches those two. build.txt and sbom.txt are different:
they are `uv pip compile` outputs whose inputs are a `.in` source plus a constraining export. Those
inputs can move — a bump in build.in, or a constraint change in dev.txt — without anyone re-running
the compile, and nothing watched them. build.txt is what builds the published wheel and the
container's build stage, so a stale pin there is shipped-surface drift.

This stamps a hash of each compiled file's INPUTS (its `.in` source + the content lines of its
constraint) into the file as a trailing comment. `stamp` (re)writes the stamps; `check` recomputes
and exits non-zero on any mismatch. tests/test_requirements_lock.py runs `check` in-process.

Honest bound: this proves the inputs are UNCHANGED since the last compile — not that a fresh
resolution would still pick these versions (that needs the network). release.sh regenerates all
four and diffs, which is the path that catches a moved upstream. Stdlib only: it must run in the
pip-installed CI `test` job where uv is absent.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REQ_DIR = Path(__file__).resolve().parent.parent / "requirements"
STAMP_PREFIX = "# input-sha256: "

# compiled file -> (its `.in` source, the export it is constrained by)
COMPILED: dict[str, tuple[str, str]] = {
    "build.txt": ("build.in", "dev.txt"),
    "sbom.txt": ("sbom.in", "runtime.txt"),
}


def _content_lines(text: str) -> list[str]:
    """Non-comment, non-blank lines — the pins, ignoring the header command line that carries a
    path and would otherwise make the hash depend on cosmetic header text."""
    return [ln for ln in text.splitlines() if ln and not ln.lstrip().startswith("#")]


def input_hash(in_name: str, constraint_name: str, req_dir: Path = REQ_DIR) -> str:
    src = (req_dir / in_name).read_text(encoding="utf-8")
    con = "\n".join(_content_lines((req_dir / constraint_name).read_text(encoding="utf-8")))
    return hashlib.sha256((src + "\x00" + con).encode("utf-8")).hexdigest()


def _strip_stamp(text: str) -> str:
    kept = [ln for ln in text.splitlines() if not ln.startswith(STAMP_PREFIX)]
    return "\n".join(kept).rstrip("\n") + "\n"


def stamp(req_dir: Path = REQ_DIR) -> None:
    for compiled, (in_name, constraint) in COMPILED.items():
        f = req_dir / compiled
        body = _strip_stamp(f.read_text(encoding="utf-8"))
        h = input_hash(in_name, constraint, req_dir)
        f.write_text(body + STAMP_PREFIX + h + "\n", encoding="utf-8")
        print(f"stamped {compiled} <- {in_name} + {constraint}: {h[:12]}")


def check(req_dir: Path = REQ_DIR) -> list[str]:
    """Return a list of human-readable drift messages; empty when every stamp matches."""
    problems: list[str] = []
    for compiled, (in_name, constraint) in COMPILED.items():
        text = (req_dir / compiled).read_text(encoding="utf-8")
        stamped = next((ln[len(STAMP_PREFIX):].strip()
                        for ln in text.splitlines() if ln.startswith(STAMP_PREFIX)), None)
        if stamped is None:
            problems.append(f"{compiled}: no {STAMP_PREFIX.strip()} line — run scripts/gen_requirements.sh")
            continue
        want = input_hash(in_name, constraint, req_dir)
        if stamped != want:
            problems.append(
                f"{compiled}: input stamp {stamped[:12]} != current {want[:12]} — "
                f"{in_name}/{constraint} changed without regenerating; run scripts/gen_requirements.sh"
            )
    return problems


def _main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "check"
    if cmd == "stamp":
        stamp()
        return 0
    if cmd == "check":
        problems = check()
        for p in problems:
            print(p, file=sys.stderr)
        return 1 if problems else 0
    print("usage: _reqstamp.py [stamp|check]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
