"""THE CAPABILITY GATE: a capability leaves Proximo only by a ruling written on its own row.

0.45.0's cut deleted everything outside `core/` by directory, and twenty-five capabilities went
with the wrappers they sat beside (records/capabilities.toml says which, and why each matters).
A green suite said nothing, because the tests that held them went in the same cut. This gate
reads the record and fails on each way a capability can leave quietly:

  1. a row disappears                        -> KNOWN pins every id ever recorded
  2. a standing capability slips back        -> STANDING pins every id that ever stood
  3. an owed capability is quietly downgraded -> OWED pins every id owed; it stands or is retired
  4. a proving test is deleted or renamed     -> read statically, with the reason
  5. a proving test no longer PASSES          -> run: skipped, xfailed, importorskip'd, shadowed
                                                 or deselected all read as not proven
  6. a retirement carries no ruling (who, date: words) or no replacement
  7. a lost capability has nowhere to come back from (`was` must name 0.44 source)

NAMED LIMITS, which no gate of this shape can see: a proof gutted to `pass`, or one that asserts
less than its row's `what`. Those are the lens's to catch, by reading the proof against the row.
The pins live in this file beside the checks, so one diff can move both: the protection there is
review, and a pin that shrinks is the line a reviewer reads first.

Moving a row forward (owed -> standing) is the work; add its id to STANDING in the same change.
Every check is planted at the bottom and watched red.
"""
from __future__ import annotations

import ast
import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib
from xml.etree import ElementTree

ROOT = pathlib.Path(__file__).resolve().parent.parent
RECORD = ROOT / "records" / "capabilities.toml"
STATUSES = ("standing", "unproven", "owed", "ask", "retired")
RULING = re.compile(r"^\S[^,]*, \d{4}-\d{2}-\d{2}: \S")          # who, when: what
ORIGIN = re.compile(r"^(field|design): \S")
WAS = re.compile(r"^src/proximo/[\w/]+\.py(:[\w.]+)?$")

# Every id the record has ever held. A row is never deleted; it is retired by name.
KNOWN = frozenset({
    "arm-gates-every-mutation", "split-ssh-target-refused", "secrets-withheld-at-any-depth",
    "privsep-token-and-user-grant", "ledger-tail-cut-caught", "unkeyed-chain-sealed-not-deleted",
    "arguments-cast-to-published-types", "pdm-typed-arrays",
    "token-sight-guard", "backup-freshness-fence", "blast-dependents", "access-blast",
    "lockout-naming", "estate-memory", "last-backup-and-coverage", "allowlist-compares-grants",
    "lexical-find", "offbox-anchor", "vendor-safety-checks-in-plan",
    "rollback-keeps-description-and-tags", "command-risk-hint", "pdm-rollback-safety-snapshot",
    "create-plan-network-and-vmid", "config-host-crossings", "shareable-doctor-receipt",
    "composed-reads", "semantic-find", "docs-knowledge", "pmg-and-sync-classifiers",
    "default-node", "ceph-zero-flags-guard",
    "reach-grant-observable", "runbook-prompts",
    "scope-file", "arm-lease", "client-argument-validation", "door-services-raised",
})

# Every id that has ever stood. It stays standing, or is retired by ruling; it never slips back.
STANDING = frozenset({
    "arm-gates-every-mutation", "split-ssh-target-refused", "secrets-withheld-at-any-depth",
    "privsep-token-and-user-grant", "ledger-tail-cut-caught", "unkeyed-chain-sealed-not-deleted",
    "arguments-cast-to-published-types", "allowlist-compares-grants", "door-services-raised",
    "token-sight-guard", "runbook-prompts", "pdm-typed-arrays", "offbox-anchor", "reach-grant-observable",
    "shareable-doctor-receipt", "lexical-find", "estate-memory",
    "rollback-keeps-description-and-tags", "command-risk-hint", "pdm-rollback-safety-snapshot",
    "default-node", "ceph-zero-flags-guard",
})

# Every id ever owed. It comes back (standing) or is retired by ruling; never quietly ask/unproven.
OWED = frozenset({
    "token-sight-guard", "backup-freshness-fence", "blast-dependents", "access-blast",
    "lockout-naming", "estate-memory", "last-backup-and-coverage", "allowlist-compares-grants",
    "lexical-find", "offbox-anchor", "vendor-safety-checks-in-plan",
    "rollback-keeps-description-and-tags", "command-risk-hint", "pdm-rollback-safety-snapshot",
    "create-plan-network-and-vmid", "config-host-crossings", "shareable-doctor-receipt",
    "composed-reads", "semantic-find", "docs-knowledge", "pmg-and-sync-classifiers",
    "default-node", "ceph-zero-flags-guard", "reach-grant-observable", "runbook-prompts",
})


def load(path: pathlib.Path = RECORD) -> dict[str, dict]:
    return tomllib.loads(path.read_text(encoding="utf-8")).get("capability", {})


# ---- static: the proof is there, by name ----------------------------------------------------------

_SKIP_MARKS = frozenset({"skip", "skipif", "xfail"})


def _mark_name(node: ast.expr) -> str | None:
    """`pytest.mark.<name>` (called or not) -> name; anything else -> None. A decorator that only
    CONTAINS the word (parametrize over "skip", a fixture called skipper) is not a skip mark."""
    if isinstance(node, ast.Call):
        node = node.func
    if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute)
            and node.value.attr == "mark" and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "pytest"):
        return node.attr
    return None


def _skipped(node: ast.AST) -> bool:
    return any(_mark_name(d) in _SKIP_MARKS for d in getattr(node, "decorator_list", []))


def proof_problem(ref: str, root: pathlib.Path = ROOT) -> str | None:
    """None when `file::func` (or `file::Class::func`) names one test function; else why not. The
    run (`proof_outcomes`) is what proves it passes; this says, in words, what is missing."""
    file, _, rest = ref.partition("::")
    if not rest:
        return f"{ref!r} is not file::test"
    path = root / file
    if not path.is_file():
        return f"{ref!r}: {file} does not exist"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    scope: list[ast.stmt] = tree.body
    *classes, func = rest.split("::")
    for cls in classes:
        found = [n for n in scope if isinstance(n, ast.ClassDef) and n.name == cls]
        if not found:
            return f"{ref!r}: no class {cls}"
        if _skipped(found[-1]):
            return f"{ref!r}: class {cls} is skipped"
        scope = found[-1].body
    defs = [n for n in scope if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == func]
    if not defs:
        return f"{ref!r}: no test {func} in {file}"
    if len(defs) > 1:
        return f"{ref!r}: {func} is defined {len(defs)} times; pytest runs only the last"
    if not func.startswith("test"):
        return f"{ref!r}: {func} is not collected (no test prefix)"
    if _skipped(defs[0]):
        return f"{ref!r}: skipped or xfailed"
    return None


# ---- run: the proof passes -----------------------------------------------------------------------

def proof_outcomes(refs: list[str], root: pathlib.Path = ROOT) -> dict[str, list[str]]:
    """Run the proofs and return each ref's outcomes (a parametrized test has several), read from
    pytest's own JUnit report, so a skip carries its node id. `-P` keeps the repo root off
    sys.path, the shape of CI's bare `pytest`, so a proof that only passes with the root
    importable fails here too."""
    if not refs:
        return {}
    with tempfile.TemporaryDirectory() as tmp:
        report = pathlib.Path(tmp) / "proofs.xml"
        subprocess.run([sys.executable, "-P", "-m", "pytest",  # noqa: S603  (fixed argv; refs come from our own record) "-q", "-p", "no:cacheprovider",
                        f"--junitxml={report}", *refs], cwd=root, capture_output=True, text=True, timeout=600)
        # pytest's own report, written here a moment ago: not untrusted input
        root_el = ElementTree.parse(report).getroot() if report.exists() else None  # noqa: S314
        cases = root_el.iter("testcase") if root_el is not None else []
        seen: dict[str, list[str]] = {r: [] for r in refs}
        for case in cases:
            parts = case.get("classname", "").split(".")
            # junit classname is dotted: tests.test_x[.Class]; the file is the longest prefix on disk
            for cut in range(len(parts), 0, -1):
                file = "/".join(parts[:cut]) + ".py"
                if (root / file).is_file():
                    node = "::".join([file, *parts[cut:], case.get("name", "").split("[", 1)[0]])
                    break
            else:
                continue
            outcome = ("SKIPPED" if case.find("skipped") is not None else
                       "FAILED" if case.find("failure") is not None else
                       "ERROR" if case.find("error") is not None else "PASSED")
            if node in seen:
                seen[node].append(outcome)
        return seen


def run_problems(rows: dict[str, dict], root: pathlib.Path = ROOT) -> list[str]:
    refs = sorted({ref for row in rows.values() if row.get("status") == "standing"
                   for ref in row.get("proof", []) if isinstance(ref, str) and "::" in ref})
    outcomes = proof_outcomes(refs, root)
    out = []
    for ref in refs:
        got = outcomes.get(ref, [])
        if not got:
            out.append(f"{ref}: not collected or not run")
        elif any(o != "PASSED" for o in got):
            out.append(f"{ref}: {', '.join(sorted(set(got)))}, not a pass")
    return out


# ---- the record ----------------------------------------------------------------------------------

def _status_problems(cid: str, row: dict, status: str, root: pathlib.Path,
                     standing: frozenset[str]) -> list[str]:
    """What each status requires of its row: proof to stand, a source to come back from, a ruling to retire."""
    out: list[str] = []
    proof = row.get("proof", [])
    if not isinstance(proof, list):
        out.append(f"{cid}: proof must be a list of file::test")
        proof = []
    if status == "standing":
        if not proof:
            out.append(f"{cid}: standing with no proof")
        if cid not in standing:
            out.append(f"{cid}: now standing; add it to STANDING in the same change")
        out += [f"{cid}: {why}" for ref in proof if (why := proof_problem(str(ref), root)) is not None]
    if status in ("owed", "ask", "unproven"):
        was = row.get("was")
        if not was or not isinstance(was, list):
            out.append(f"{cid}: {status} with no `was`: nothing says where it comes back from")
        else:
            out += [f"{cid}: was {w!r} is not 0.44 source (src/proximo/<file>.py[:name])"
                    for w in was if not WAS.match(str(w))]
    if status == "retired":
        if not RULING.match(str(row.get("ruling", ""))):
            out.append(f"{cid}: retired with no ruling of the shape 'who, YYYY-MM-DD: words'")
        if not str(row.get("instead", "")).strip():
            out.append(f"{cid}: retired with no instead")
    return out


def problems(rows: dict[str, dict], root: pathlib.Path = ROOT, known: frozenset[str] = KNOWN,
             standing: frozenset[str] = STANDING, owed: frozenset[str] = OWED) -> list[str]:
    out: list[str] = []
    for gone in sorted(known - rows.keys()):
        out.append(f"{gone}: the row is gone; retire it by name instead")
    for cid in sorted(rows.keys() - known):
        out.append(f"{cid}: a new row; add it to KNOWN in the same change")
    for cid, row in sorted(rows.items()):
        status = row.get("status")
        if status not in STATUSES:
            out.append(f"{cid}: status {status!r} is not one of {STATUSES}")
            continue
        if not str(row.get("what", "")).strip():
            out.append(f"{cid}: no what")
        if not ORIGIN.match(str(row.get("origin", ""))):
            out.append(f"{cid}: origin must start 'field: ' or 'design: '")
        if cid in standing and status not in ("standing", "retired"):
            out.append(f"{cid}: stood once and is now {status}; it stays standing or is retired by ruling")
        if cid in owed and status not in ("owed", "standing", "retired"):
            out.append(f"{cid}: owed and now {status}; it comes back or is retired by ruling")
        out += _status_problems(cid, row, status, root, standing)
    return out


def test_every_capability_is_accounted_for():
    assert problems(load()) == []


def test_every_standing_proof_passes_when_run():
    assert run_problems(load()) == []


def test_the_owed_count_is_said_out_loud(capsys):
    rows = load()
    open_ = sum(r["status"] in ("owed", "ask", "unproven") for r in rows.values())
    with capsys.disabled():
        print(f"\ncapabilities: {len(rows)} recorded, "
              f"{sum(r['status'] == 'standing' for r in rows.values())} standing, {open_} owed or open")


# --- PLANTED: each way a capability leaves quietly, watched red ----------------------------------

def _plant(tmp_path, body: str, test_src: str = "def test_real():\n    pass\n"):
    (tmp_path / "records").mkdir(parents=True)
    (tmp_path / "tests").mkdir(parents=True)
    (tmp_path / "records" / "capabilities.toml").write_text(body)
    (tmp_path / "tests" / "test_x.py").write_text(test_src)
    return load(tmp_path / "records" / "capabilities.toml")


_GOOD = ('[capability.a]\nwhat = "w"\norigin = "design: o"\nstatus = "standing"\n'
         'proof = ["tests/test_x.py::test_real"]\n')
_A = frozenset({"a"})


def test_planted_a_clean_record_passes(tmp_path):
    rows = _plant(tmp_path, _GOOD)
    assert problems(rows, tmp_path, _A, _A, frozenset()) == []
    assert run_problems(rows, tmp_path) == []


def test_planted_a_deleted_row_is_red(tmp_path):
    rows = _plant(tmp_path, _GOOD)
    assert any("row is gone" in p for p in problems(rows, tmp_path, frozenset({"a", "b"}), _A, frozenset()))


def test_planted_a_deleted_proof_test_is_red(tmp_path):
    rows = _plant(tmp_path, _GOOD, "def test_other():\n    pass\n")
    assert any("no test test_real" in p for p in problems(rows, tmp_path, _A, _A, frozenset()))
    assert any("not collected" in p for p in run_problems(rows, tmp_path))


def test_planted_a_decorated_skip_is_red(tmp_path):
    rows = _plant(tmp_path, _GOOD, "import pytest\n@pytest.mark.skip\ndef test_real():\n    pass\n")
    assert any("skipped" in p for p in problems(rows, tmp_path, _A, _A, frozenset()))
    assert any("SKIPPED" in p for p in run_problems(rows, tmp_path))


def test_planted_a_word_that_only_contains_skip_is_not_a_skip(tmp_path):
    src = 'import pytest\n@pytest.mark.parametrize("mode", ["skip", "run"])\ndef test_real(mode):\n    pass\n'
    rows = _plant(tmp_path, _GOOD, src)
    assert problems(rows, tmp_path, _A, _A, frozenset()) == []
    assert run_problems(rows, tmp_path) == []


def test_planted_a_skip_inside_the_body_is_red_when_run(tmp_path):
    rows = _plant(tmp_path, _GOOD, "import pytest\ndef test_real():\n    pytest.skip('no')\n")
    assert any("SKIPPED" in p for p in run_problems(rows, tmp_path))


def test_planted_a_module_importorskip_is_red_when_run(tmp_path):
    src = "import pytest\npytest.importorskip('no_such_module_anywhere')\ndef test_real():\n    pass\n"
    rows = _plant(tmp_path, _GOOD, src)
    assert any("not collected" in p for p in run_problems(rows, tmp_path))


def test_planted_a_marker_alias_is_red_when_run(tmp_path):
    src = "import pytest\nS = pytest.mark.skip\n@S\ndef test_real():\n    pass\n"
    rows = _plant(tmp_path, _GOOD, src)
    assert any("SKIPPED" in p for p in run_problems(rows, tmp_path))


def test_planted_a_shadowing_redefinition_is_red(tmp_path):
    src = "import pytest\ndef test_real():\n    pass\n@pytest.mark.skip\ndef test_real():\n    pass\n"
    rows = _plant(tmp_path, _GOOD, src)
    assert any("defined 2 times" in p for p in problems(rows, tmp_path, _A, _A, frozenset()))
    assert any("SKIPPED" in p for p in run_problems(rows, tmp_path))


def test_planted_a_failing_proof_is_red_when_run(tmp_path):
    rows = _plant(tmp_path, _GOOD, "def test_real():\n    assert False\n")
    assert any("FAILED" in p for p in run_problems(rows, tmp_path))


def test_planted_a_standing_capability_slipping_back_is_red(tmp_path):
    rows = _plant(tmp_path, '[capability.a]\nwhat = "w"\norigin = "design: o"\nstatus = "owed"\n'
                            'was = ["src/proximo/x.py"]\n')
    assert any("stood once" in p for p in problems(rows, tmp_path, _A, _A, frozenset()))


def test_planted_an_owed_capability_quietly_downgraded_is_red(tmp_path):
    rows = _plant(tmp_path, '[capability.a]\nwhat = "w"\norigin = "design: o"\nstatus = "ask"\n'
                            'was = ["src/proximo/x.py"]\n')
    assert any("owed and now ask" in p for p in problems(rows, tmp_path, _A, frozenset(), _A))


def test_planted_a_retirement_with_no_real_ruling_is_red(tmp_path):
    for ruling in ('', 'x'):
        rows = _plant(tmp_path / ruling.join("rr"), f'[capability.a]\nwhat = "w"\norigin = "design: o"\n'
                                                   f'status = "retired"\ninstead = "i"\nruling = "{ruling}"\n')
        assert any("no ruling" in p for p in problems(rows, tmp_path, _A, frozenset(), frozenset()))


def test_planted_a_proper_retirement_passes(tmp_path):
    rows = _plant(tmp_path, '[capability.a]\nwhat = "w"\norigin = "design: o"\nstatus = "retired"\n'
                            'instead = "i"\nruling = "John, 2026-10-05: the bar"\n')
    assert problems(rows, tmp_path, _A, frozenset(), frozenset()) == []


def test_planted_an_owed_row_with_nowhere_real_to_come_back_from_is_red(tmp_path):
    for was in ('', 'was = ["x"]\n'):
        rows = _plant(tmp_path / str(len(was)), f'[capability.a]\nwhat = "w"\norigin = "design: o"\n'
                                                f'status = "owed"\n{was}')
        assert any("was" in p for p in problems(rows, tmp_path, _A, frozenset(), _A))


def test_planted_a_new_standing_row_not_pinned_is_red(tmp_path):
    rows = _plant(tmp_path, _GOOD)
    assert any("add it to STANDING" in p for p in problems(rows, tmp_path, _A, frozenset(), frozenset()))
