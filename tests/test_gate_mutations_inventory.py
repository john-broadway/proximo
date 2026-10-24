"""Every gate the round neuters is still exactly where the harness expects it.

`scripts/gate_mutations.py` turns gates off by exact-string replacement. A target found zero
times (the gate was renamed or moved) or twice (a copy appeared) makes the round print SKIP and
count the gate as survived, which reads like a decoration when it is a stale harness. This holds
each target to ONE site and each core-only test file to an existing file, so the drift is red
here, at the cost of one read per gate, instead of a wrong word in a round nobody ran. Since the
cut (2026-10-18) it also holds the tree to the cut: the package is the core, every core module
imports, and no test or script names a module that is gone.
"""
from __future__ import annotations

import ast
import importlib
import importlib.util
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "proximo"
TESTS = ROOT / "tests"
_spec = importlib.util.spec_from_file_location("gate_mutations", ROOT / "scripts" / "gate_mutations.py")
gm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gm)


@pytest.mark.parametrize("name,rel,old,new", gm.M, ids=[m[0] for m in gm.M])
def test_each_gate_is_at_exactly_one_site_and_the_mutation_changes_it(name, rel, old, new):
    src = (ROOT / rel).read_text(encoding="utf-8")
    assert src.count(old) == 1, f"{name}: the gate text is at {src.count(old)} sites in {rel}"
    assert old != new, f"{name}: the neutered form is the gate itself"


def _type_checking(test: ast.expr) -> bool:
    return (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or \
        (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING")


def _imports_of(path: pathlib.Path, *, everywhere: bool, text: str | None = None) -> list[tuple[str, int, bool]]:
    """(dotted module, level, runs on import) for every import in the file: all of them for a test
    file (a test runs its function bodies), only those that run on import for a source file (what
    importing it pulls in). An import runs on import anywhere outside a function or lambda, a
    `try`, an `if` or a class body included (the lens of 2026-10-16 planted all three and the old
    rule, a direct child of the module body, called each of them lazy); the body of
    `if TYPE_CHECKING:` never runs and is lazy, its `else` runs. A relative `from .. import name`
    names a submodule too, so the aliases are expanded at every level, not only for `proximo.`.
    `text` stands in for the file's bytes so a control can plant a line."""
    tree = ast.parse(path.read_text(encoding="utf-8") if text is None else text)
    out: list[tuple[str, int, bool]] = []

    def names(n: ast.Import | ast.ImportFrom, runs: bool) -> list[tuple[str, int, bool]]:
        if isinstance(n, ast.Import):
            return [(a.name, 0, runs) for a in n.names]
        base = n.module or ""
        found = [(base, n.level, runs)]
        if n.level or base.startswith("proximo"):
            found += [(f"{base}.{a.name}" if base else a.name, n.level, runs) for a in n.names]
        return found                                                # `from proximo import taint`

    def walk(nodes, runs: bool) -> None:
        for n in nodes:
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                if everywhere or runs:
                    out.extend(names(n, runs))
            elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                walk(ast.iter_child_nodes(n), False)
            elif isinstance(n, ast.If) and _type_checking(n.test):
                walk(n.body, False)
                walk(n.orelse, runs)
            else:
                walk(ast.iter_child_nodes(n), runs)

    walk(tree.body, True)
    return out


def _resolve(mod: str, level: int, here: pathlib.Path) -> pathlib.Path | None:
    if level:                                                      # relative: inside the package
        pkg = here.parent
        for _ in range(level - 1):
            pkg = pkg.parent
        parts = mod.split(".") if mod else []
        init = pkg.joinpath(*parts, "__init__.py") if parts else pkg / "__init__.py"
        for cand in (init, pkg.joinpath(*parts).with_suffix(".py")):
            if cand.is_file():
                return cand
        return None
    if mod.startswith("proximo"):
        rel = pathlib.Path(*mod.split("."))
        for cand in (SRC.parent / rel / "__init__.py", (SRC.parent / rel).with_suffix(".py")):
            if cand.is_file():
                return cand
        return None
    if mod.startswith("test_"):                                    # a sibling test module, bare
        cand = TESTS / (mod.split(".")[0] + ".py")
        return cand if cand.is_file() else None
    return None


def _is_core(target: pathlib.Path) -> bool:
    return target.is_relative_to(SRC / "core") or target in (SRC / "__init__.py", SRC / "__main__.py")


# --- the package is the core (the cut, 2026-10-18) -------------------------------------------------

def test_every_file_in_the_package_is_the_core():
    """0.44 is gone from the tree: `src/proximo/` holds `core/`, the version and `python -m`. A file
    anywhere else under the package is red here by name (a stray `__pycache__` included: a leftover
    `proximo/tools/__pycache__/` would let `import proximo.tools` succeed as a namespace package)."""
    stray = sorted(str(p.relative_to(SRC.parent)) for p in SRC.iterdir()
                   if p.name not in ("core", "__pycache__", "__init__.py", "__main__.py"))
    stray += sorted(str(p.relative_to(SRC.parent)) for p in SRC.rglob("*")
                    if p.is_file() and "__pycache__" not in p.parts and not _is_core(p))
    assert stray == [], stray


CORE_MODULES = sorted(".".join(("proximo", *p.relative_to(SRC).with_suffix("").parts)).removesuffix(".__init__")
                      for p in (SRC / "core").rglob("*.py") if "__pycache__" not in p.parts)


@pytest.mark.parametrize("dotted", CORE_MODULES)
def test_every_core_module_imports(dotted):
    """The runtime check the static walk below cannot make: every module under the core imports,
    so no core file still names a module the cut removed (`from proximo.core import store` with
    no `store.py` is an ImportError here, by module name)."""
    importlib.import_module(dotted)


TREE = sorted(p for d in ("src", "tests", "scripts") for p in (ROOT / d).rglob("*.py") if "__pycache__" not in p.parts)
_ON_PATH = [str(TESTS), str(ROOT / "scripts")]           # what pytest and the scripts' own sys.path.insert give them
_NOT_A_MODULE = re.compile(r"\.(env|sh|json|gz|toml|service|log|md|py|txt|yml|yaml|db|pem|jwk|token|crt|example)$")


def _module_exists(dotted: str) -> bool:
    saved = list(sys.path)
    sys.path[:0] = _ON_PATH
    try:
        return importlib.util.find_spec(dotted) is not None
    except (ModuleNotFoundError, ValueError):
        return False
    finally:
        sys.path[:] = saved


def _names_something(dotted: str) -> bool:
    """A module, or a module and an attribute chain on it. The attribute step is taken only for
    `proximo` modules (importing one is what the suite does anyway); a sibling test's or a
    third-party module's attributes are the collector's to find."""
    if _module_exists(dotted):
        return True
    parts = dotted.split(".")
    for k in range(len(parts) - 1, 0, -1):
        head = ".".join(parts[:k])
        if _module_exists(head):
            if not head.startswith("proximo"):
                return True
            obj = importlib.import_module(head)
            for name in parts[k:]:
                if not hasattr(obj, name):
                    return False
                obj = getattr(obj, name)
            return True
    return False


def unresolved_names(path: pathlib.Path, text: str | None = None) -> set[str]:
    """Every name in a file that no module answers to: an import at any level (a bare `import
    api_coverage` in a script included, with `scripts/` and `tests/` on the path as they are at run
    time), and every string literal shaped like a dotted `proximo` name (an `importlib.import_module`
    argument, a `monkeypatch.setattr` target). The pre-cut walk SKIPPED an import that resolved to
    no file and never read a string; after the cut those are exactly the shapes of a stale name."""
    src = path.read_text(encoding="utf-8") if text is None else text
    out: set[str] = set()
    for mod, level, _ in _imports_of(path, everywhere=True, text=src):
        if level:
            if _resolve(mod, level, path) is None and _resolve(mod.rpartition(".")[0], level, path) is None:
                out.add(mod)
            continue
        if not _names_something(mod):
            out.add(mod)
    if path.resolve() == pathlib.Path(__file__).resolve() and text is None:
        return out                                        # this file's own controls spell names of nothing on purpose
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            v = node.value
            if re.fullmatch(r"proximo(\.[A-Za-z_]\w*)+", v) and not _NOT_A_MODULE.search(v) and not _names_something(v):
                out.add(v)
    return out


@pytest.mark.parametrize("path", TREE, ids=[str(p.relative_to(ROOT)) for p in TREE])
def test_every_name_in_the_tree_is_answered_by_a_module(path):
    assert unresolved_names(path) == set(), sorted(unresolved_names(path))


@pytest.mark.parametrize("plant,expect", [
    ("\n\ndef _p():\n    from proximo.backends import ProxmoxClient\n",
     {"proximo.backends", "proximo.backends.ProxmoxClient"}),
    ("\n\ndef _p():\n    from proximo.core import prompts\n", {"proximo.core.prompts"}),
    ("\n\nimport proximo.server\n", {"proximo.server"}),
    ("\n\nfrom proximo import tools\n", {"proximo.tools"}),
    ("\n\nfrom proximo.core import the\n", {"proximo.core.the"}),
    ("\n\nimport importlib\nm = importlib.import_module(\"proximo.server\")\n", {"proximo.server"}),
    ("\n\nx = (\"proximo.core.engine.no_such_name\", 1)\n", {"proximo.core.engine.no_such_name"}),
    ("\n\nimport api_coverage\n", {"api_coverage"}),
    ("\n\ndef _p():\n    from proximo.core.errors import ProximoError\n", set()),
    ("\n\nfrom proximo import __version__\n", set()),
    ("\n\nx = \"proximo.core.doors.mcp.main\"\n", set()),
    ("\n\nx = \"proximo.env\"\n", set()),
], ids=["lazy-044-module", "alias-of-a-cut-file", "top-044-module", "alias-that-is-a-word-in-the-docstring",
        "alias-of-nothing", "string-import", "string-attribute", "bare-script-import", "core-internal", "version",
        "string-that-names-a-function", "a-filename-not-a-module"])
def test_the_control_a_planted_stale_name_is_named(plant, expect):
    """The walk sees its own failure, for every shape the lens of 2026-10-18 planted: a 0.44
    module at any level, a cut core file named as an alias, an alias that is merely a word in the
    package's docstring, a string-form import, a string attribute target, a bare import of a cut
    script. A core import, the version, a string naming a real function and a filename are not.
    Planted into this file's own text."""
    me = pathlib.Path(__file__)
    base = "import os\n"                                # a text with no name of its own to answer for
    assert unresolved_names(me, base) == set()
    assert unresolved_names(me, base + plant) == expect


@pytest.mark.parametrize("name,rel,old,new", gm.M, ids=[m[0] for m in gm.M])
def test_each_mutant_still_parses(name, rel, old, new):
    """A mutant that breaks the syntax errors every test, and an error is not a kill; the round
    would print ERROR, but this says so before anyone runs it."""
    src = (ROOT / rel).read_text(encoding="utf-8")
    ast.parse(src.replace(old, new, 1))


def test_the_control_a_planted_second_site_is_caught():
    """The inventory sees its own failure: a copy of one gate makes the count two."""
    name, rel, old, _ = gm.M[0]
    src = (ROOT / rel).read_text(encoding="utf-8")
    assert (src + old).count(old) == 2


# --- the perimeter has no caller of its own (step 1b, 2026-10-17) --------------------------------

@pytest.mark.parametrize(("mod", "params"), [
    ("proximo.core.perimeter.rest", ("dispatch", "record")),
    ("proximo.core.perimeter.mcp_http", ("instance", "record")),
    ("proximo.core.perimeter.a2a.app", ("dispatch", "record")),
])
def test_the_perimeter_has_no_default_caller(mod, params):
    """`build_app` without a caller used to mean the 0.44 server. It is a TypeError: the core door
    passes its own dispatch, instance and recorder, and nothing else builds a perimeter."""
    import importlib  # noqa: PLC0415
    import inspect  # noqa: PLC0415
    sig = inspect.signature(importlib.import_module(mod).build_app)
    for name in params:
        assert sig.parameters[name].default is inspect.Parameter.empty, f"{mod}.build_app({name}=...) has a default"


def test_every_mutant_has_its_own_id():
    """The round reports by id: two mutants sharing `M24` read as one line in a report a human
    scans for survivors (it happened, 2026-10-24: M24/M25 named a PROVE mutant and a CONSENT one)."""
    ids = [m[0].split("-", 1)[0] for m in gm.M]
    assert len(ids) == len(set(ids)), sorted({i for i in ids if ids.count(i) > 1})
