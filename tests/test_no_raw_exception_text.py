"""Structural guard: no source file formats a RAW exception message into a string.

THE CLASS. httpx builds its error message out of the request URL, so `f"{type(e).__name__}:
{e}"` carries the estate's internal host:port into whatever the string lands in -- a tool
response, a warning, a returned reason. `redact()` does not catch it: that hides REGISTERED
SECRET LITERALS and auth-header shapes, and an address is neither.

Found by an adversarial lens in `proximo/capacity.py` on 2026-09-20, where the comment on the
offending line NAMED the risk and formatted str(exc) anyway. It was never one file's bug: 13
sites across 11 modules carried the same shape. `safe_exception_text` exists so the class has
one answer, and this test exists so the answer stays applied.

THIS CHECKER'S BLIND SPOT IS SHAPED LIKE ITS TREE. It matches the exact shape the sweep
removed. A NEW way of writing the same mistake -- `str(exc)` assigned first, `repr(exc)`,
`"%s" % exc`, an exception passed whole into a dict -- is not caught here and needs its own
arm the first time it appears. A structural test proves the shapes it was handed, never the
idea.
"""
from __future__ import annotations

import pathlib
import re

SRC = pathlib.Path(__file__).resolve().parent.parent / "src" / "proximo"

# f"...{type(e).__name__}: {e}..." -- the type name immediately followed by its own message.
_RAW = re.compile(r"__name__\}:\s*\{")


def _hits(text: str) -> list[int]:
    return [i for i, line in enumerate(text.splitlines(), 1) if _RAW.search(line)]


def test_no_module_formats_a_raw_exception_message():
    found = []
    for path in sorted(SRC.rglob("*.py")):
        for line in _hits(path.read_text(encoding="utf-8")):
            found.append(f"{path.relative_to(SRC)}:{line}")
    assert not found, (
        "raw exception message formatted into a string -- the message can carry an internal "
        "URL/host:port. Use proximo._secretfile.safe_exception_text(exc):\n  "
        + "\n  ".join(found)
    )


def test_the_matcher_actually_matches_the_shape_it_forbids():
    """PLANTED CONTROL. A guard that cannot see its own target passes for free."""
    assert _hits('    msg = f"boom: {type(e).__name__}: {e}"')
    assert _hits('    x = f"{type(exc).__name__}: {exc}"')


def test_the_matcher_does_not_accuse_the_safe_shape():
    """The type name ALONE is the safe form and must stay legal (the ledger uses it)."""
    assert not _hits('    detail = {"error": type(e).__name__}')
    assert not _hits('    return None, type(e).__name__')


def test_the_helper_is_actually_importable():
    """The sweep points every site at one function; if it moved, the guard is advice."""
    from proximo._secretfile import safe_exception_text

    assert callable(safe_exception_text)
