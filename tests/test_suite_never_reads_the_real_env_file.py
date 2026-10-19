"""No test may let a door read the operator's REAL `~/.config/proximo/proximo.env`.

2026-10-17, the hour the core doors took over sourcing the env file: `tests/conftest.py` pins
`PROXIMO_ENV_FILE` at an absent path for every test, and a subprocess test that stripped every
`PROXIMO_*` key from the child's environment stripped the pin with them. The door it spawned read
this box's real file, dialed the real estate and made one GET (a hostname lookup that failed).
A test that touches the real home is the class, not the instance: every place a test strips
`PROXIMO_*` must keep the pin, and this scan holds all of them to it, with a control that shows it
can fail.
"""
from __future__ import annotations

import pathlib
import re

import pytest

TESTS = pathlib.Path(__file__).resolve().parent
STRIP = re.compile(r'startswith\("PROXIMO_"\)')
PIN = "PROXIMO_ENV_FILE"


def strips_without_the_pin(text: str) -> list[int]:
    """1-based line numbers of a `startswith("PROXIMO_")` strip whose statement does not keep the
    pin: the pin must be named on the same line or one of the next four (a delenv loop's body, a
    comprehension's tail, a setenv right after). A snapshot-and-restore (`before = {...}` and a
    loop that pops only what `before` lacks) is not a strip: the pin was there before, it stays."""
    lines = text.splitlines()
    bad = []
    for i, line in enumerate(lines):
        if not STRIP.search(line):
            continue
        window = lines[i:i + 5]
        if any(PIN in later for later in window) or any("before" in later for later in window):
            continue
        bad.append(i + 1)
    return bad


@pytest.mark.parametrize("path", sorted(p for p in TESTS.glob("test_*.py") if p.name != pathlib.Path(__file__).name),
                         ids=lambda p: p.name)
def test_every_strip_of_proximo_vars_keeps_the_env_file_pin(path):
    bad = strips_without_the_pin(path.read_text(encoding="utf-8"))
    assert bad == [], f"{path.name}: a PROXIMO_* strip at line(s) {bad} drops {PIN}; the real file would be read"


def test_the_control_a_strip_without_the_pin_is_caught():
    planted = 'env = {k: v for k, v in os.environ.items() if not k.startswith("PROXIMO_")}\n' \
              'env["PROXIMO_AUDIT_LOG"] = "x"\nparams = Stdio(env=env)\n'
    assert strips_without_the_pin(planted) == [1]
    kept = planted.replace('startswith("PROXIMO_")}', 'startswith("PROXIMO_") or k == "PROXIMO_ENV_FILE"}')
    assert strips_without_the_pin(kept) == []
    restore = ('before = {k for k in os.environ if k.startswith("PROXIMO_")}\nyield\n'
               'for k in [k for k in os.environ if k.startswith("PROXIMO_")]:\n'
               '    if k not in before:\n        os.environ.pop(k)\n')
    assert strips_without_the_pin(restore) == []
    assert strips_without_the_pin(restore.replace("before", "seen")) == [1, 3]   # the word is the idiom


def test_the_pin_is_set_for_this_very_test(monkeypatch):
    """The conftest fixture is what every other test relies on; see it stand."""
    import os  # noqa: PLC0415
    assert PIN in os.environ and not pathlib.Path(os.environ[PIN]).exists()
