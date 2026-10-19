"""Every `needs` the core can put on a refusal is named where an agent and a reader look for it.

Lens 2 (2026-10-18): AGENTS.md and the `Verdict` docstring listed nine values; the core produces
eighteen (the four opt-in lanes, `arguments`, `path`, `undo`, `store`, `prove` were missing). The
set is swept from the code: a `Refusal(...)`'s first argument, a `Verdict(...)`'s third, a `needs=`
keyword, a `"needs":` dict key, and the opt-in lanes, which refuse under their own name.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from proximo.core import engine, spine

ROOT = Path(__file__).parents[1]


def _producible() -> set[str]:
    found = set(spine._LANES)
    for py in (ROOT / "src" / "proximo" / "core").rglob("*.py"):
        for n in ast.walk(ast.parse(py.read_text())):
            if isinstance(n, ast.Call):
                fn = getattr(n.func, "id", getattr(n.func, "attr", ""))
                pos = {"Refusal": 0, "Verdict": 2}.get(fn)
                if pos is not None and len(n.args) > pos and isinstance(n.args[pos], ast.Constant):
                    found.add(n.args[pos].value)
                found |= {k.value.value for k in n.keywords
                          if k.arg == "needs" and isinstance(k.value, ast.Constant)}
            elif isinstance(n, ast.Dict):
                found |= {v.value for k, v in zip(n.keys, n.values, strict=True)
                          if isinstance(k, ast.Constant) and k.value == "needs" and isinstance(v, ast.Constant)}
    return {v for v in found if isinstance(v, str) and v}


def test_the_sweep_sees_the_values_it_was_written_for():
    assert {"arm", "tier", "arguments", "prove", "agent", "download"} <= _producible()


def test_agents_md_names_every_needs():
    sentence = re.search(r"`needs`\s+is one of (.+?)\.\s", (ROOT / "AGENTS.md").read_text(), re.S).group(1)
    assert _producible() <= set(re.findall(r"`([a-z]+)`", sentence))


def test_the_verdict_docstring_names_every_needs():
    assert _producible() <= set(re.findall(r'"([a-z]+)"', engine.Verdict.__doc__ or ""))
