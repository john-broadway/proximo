"""The Dockerfile's two stages pin ONE base digest (lens B, 2026-09-03).

A base-image bump moves both FROM lines; a partial bump (one stage moved, one left) builds and
scans fine and ships a runtime on a different base than the one that built the wheel. No test
guarded the agreement: a desync mutant survived every suite. This one pins it, and the shape of
the pin (tag + full sha256), so a hand edit that drops the digest is loud too.
"""

from __future__ import annotations

import re
from pathlib import Path

_FROM = re.compile(r"^FROM (python:3\.13-slim)@(sha256:[0-9a-f]{64})(?: AS \w+)?$", re.M)


def _dockerfile() -> str:
    return (Path(__file__).resolve().parent.parent / "Dockerfile").read_text(encoding="utf-8")


def test_both_stages_pin_the_same_base_digest():
    pins = _FROM.findall(_dockerfile())
    assert len(pins) == 2, f"expected two digest-pinned FROM lines, found {pins}"
    assert pins[0][1] == pins[1][1], f"build and runtime stages pin different digests: {pins}"


def test_every_from_line_is_digest_pinned():
    froms = [ln for ln in _dockerfile().splitlines() if ln.startswith("FROM ")]
    assert froms and all(_FROM.match(ln) for ln in froms), froms
