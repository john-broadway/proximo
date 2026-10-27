"""Every `PROXIMO_*` the operator is told to set is one the core reads, or one it refuses.

Lens 2 (2026-10-18) found `PROXIMO_NODE` (read again since default-node came back) in the README
quickstart, SETUP, mint's steps, the env example and the LXC installer, and `PROXIMO_LEDGER_REDACT`
in the env example: read by nothing,
so a setting that looked like configuration did nothing. A name the code reads is an exact string
constant (`"PROXIMO_FORBID"`) or one the planes and doors compose from a prefix and a suffix
(`PROXIMO_PBS_TOKEN_PATH`, `PROXIMO_HTTP_PORT`). The composed set is over-approximated (every
prefix with every suffix), so this can only miss an unread composed name, never flag a read one.
"""
from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

from proximo.core import spine, wire

ROOT = Path(__file__).parents[1]
SRC = ROOT / "src" / "proximo"
# Every tracked file an operator reads, found from git, never listed by hand: a hand list missed the
# man page and the LXC manifest (lens 3, 10-18). History (CHANGELOG, debian/changelog) and the
# internal plans and specs are records of what was, not instructions.
_OPERATOR = re.compile(r"^([^/]+\.md|docs/[^/]+\.md|debian/.+|packaging/.+|\.github/CONTRIBUTING\.md)$")
_HISTORY = {"CHANGELOG.md", "CLAUDE.md", "debian/changelog"}


def _documented() -> list[str]:
    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True,  # noqa: S603, S607
                             check=True).stdout
    return [f for f in tracked.split() if _OPERATOR.match(f) and f not in _HISTORY
            and not f.endswith((".png", ".gz", ".svg"))]


NAME = re.compile(r"PROXIMO_[A-Z0-9_]*[A-Z0-9]")
FAMILY = re.compile(r"_\*")   # `PROXIMO_PBS_*` names a family, not a variable
SHELL_OWN = {"PROXIMO_VERSION", "PROXIMO_BANNER"}   # an installer variable, a heredoc delimiter: no environment read


def _read_names() -> set[str]:
    exact, suffixes, doors = set(), set(), set()
    for py in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(py.read_text())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and NAME.fullmatch(node.value):
                exact.add(node.value)
            elif isinstance(node, ast.JoinedStr) and node.values:
                head, tail = node.values[0], node.values[-1]
                if isinstance(tail, ast.Constant) and re.fullmatch(r"_?[A-Z][A-Z_]*", str(tail.value)):
                    suffixes.add(str(tail.value).lstrip("_"))
                if isinstance(head, ast.Constant) and re.fullmatch(r"PROXIMO_[A-Z_]+_", str(head.value)):
                    doors.add(str(head.value).removeprefix("PROXIMO_"))   # f"PROXIMO_MCP_HTTP_{name}"
            elif isinstance(node, ast.Call):
                fn = getattr(node.func, "id", getattr(node.func, "attr", ""))
                if fn == "_pair_var" and len(node.args) == 2 and isinstance(node.args[1], ast.Constant):
                    suffixes.add(node.args[1].value)
                if (isinstance(node.func, ast.Name) and len(node.args) == 1 and isinstance(node.args[0], ast.Constant)
                        and re.fullmatch(r"[A-Z][A-Z_]*", str(node.args[0].value))):
                    suffixes.add(node.args[0].value)                                 # _flag("STATELESS")
                for kw in node.keywords:
                    if fn == "main_of" and kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                        doors.add(kw.value.value + "_")
    prefixes = {s["prefix"] for s in wire._SPEC.values()} | doors
    return exact | {f"PROXIMO_{p}{s}" for p in prefixes for s in suffixes}


def test_the_reader_sees_a_constant_and_a_composed_name():
    names = _read_names()
    assert "PROXIMO_FORBID" in names and "PROXIMO_PBS_TOKEN_PATH" in names and "PROXIMO_HTTP_PORT" in names
    assert "PROXIMO_MCP_HTTP_STATELESS" in names                       # through `_flag("STATELESS")`
    assert "PROXIMO_NODE" in names                                      # read again: the default-node capability
    assert "PROXIMO_LEDGER_REDACT" not in names   # the control: a name the lens found documented and read by nothing


def test_every_documented_proximo_name_is_read_or_refused():
    allowed = _read_names() | set(spine.RETIRED_ENV) | {"PROXIMO_SURFACES"} | SHELL_OWN
    unread = set()
    docs = _documented()
    assert "debian/proximo.1" in docs and "packaging/lxc/json/proximo.json" in docs   # the two a list missed
    for doc in docs:
        text = (ROOT / doc).read_text()
        unread |= {(doc, m.group()) for m in NAME.finditer(text)
                   if m.group() not in allowed and not FAMILY.match(text, m.end())}
    assert not unread, sorted(unread)
