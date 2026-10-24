"""`scripts/verify_ledger.py`: the ledger checker that needs no Proximo.

Every fixture is written by the REAL ledger, so the script is held to what Proximo writes, not to
a hand-made file; every planted break is judged by both the core and the script, and they must
agree to the line and the word. The script runs with `-I -S` beside a planted `proximo` package
that raises on import, and again without the flags, so "needs no Proximo" is checked, not claimed.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

from proximo.core import ledger
from proximo.core.ledger import LedgerConfig, open_ledger

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "verify_ledger.py"


def _script():
    spec = importlib.util.spec_from_file_location("verify_ledger", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _planted(tmp_path: Path) -> Path:
    """A dir holding a `proximo` package whose import raises: on the path, any import is caught."""
    d = tmp_path / "planted"
    (d / "proximo").mkdir(parents=True, exist_ok=True)
    (d / "proximo" / "__init__.py").write_text('import sys; sys.stderr.write("planted proximo was imported"); '
                                              'raise SystemExit(97)\n')
    return d


def _run(tmp_path: Path, *argv: str, isolated: bool = True) -> subprocess.CompletedProcess:
    planted = _planted(tmp_path)
    flags = ["-I", "-S"] if isolated else []
    return subprocess.run(  # noqa: S603 -- fixed argv: this interpreter, this repo's script
        [sys.executable, *flags, str(SCRIPT), *argv], cwd=planted, env={"PYTHONPATH": str(planted)},
        capture_output=True, text=True, check=False)


def _keyed_log(tmp_path: Path, n: int = 3, target: str = "pve:POST /nodes/pve1/qemu/{i}/snapshot"):
    path = tmp_path / "audit.log"
    led = open_ledger(LedgerConfig(audit_log_path=str(path)))
    for i in range(n):
        led.record("core.execute", target=target.format(i=100 + i), mutation=True,
                   detail={"tier": "restorable", "i": i})
    return path, tmp_path / "audit.key", led


def _key(keyfile: Path) -> bytes:
    return bytes.fromhex(keyfile.read_text().strip())


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").split("\n")


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines), encoding="utf-8")


# --- the clean path -----------------------------------------------------------------------------

def test_a_clean_keyed_log_verifies_and_prints_its_head(tmp_path):
    path, keyfile, led = _keyed_log(tmp_path)
    r = _run(tmp_path, str(path), "--key", str(keyfile))
    assert r.returncode == 0, r.stderr
    assert r.stdout == f"ok 3 {led.head()}\n"


def test_the_script_never_imports_proximo(tmp_path):
    path, keyfile, _ = _keyed_log(tmp_path)
    for isolated in (True, False):          # without -S too: no import at all, not one -S hid
        r = _run(tmp_path, str(path), "--key", str(keyfile), isolated=isolated)
        assert r.returncode == 0 and "planted" not in r.stderr, r.stderr
    planted = _planted(tmp_path)            # the control: the plant does fire on an import
    c = subprocess.run([sys.executable, "-c", "import proximo"], env={"PYTHONPATH": str(planted)},  # noqa: S603
                       capture_output=True, text=True, check=False)
    assert c.returncode == 97 and "planted" in c.stderr


def test_an_unkeyed_archive_verifies_without_a_key(tmp_path):
    path = tmp_path / "archive.log"
    old = ledger.AuditLedger(str(path))
    old.record("core.execute", target="pve:PUT /x", mutation=True)
    old.record("core.execute", target="pve:PUT /y", mutation=True)
    r = _run(tmp_path, str(path))
    assert r.returncode == 0 and r.stdout == f"ok 2 {old.head()}\n", r.stdout + r.stderr


# --- parity: the script and the core judge the same lines the same way ----------------------------

def _downgrade(row: str) -> str:
    entry = json.loads(row)
    entry.pop("alg")
    body = {k: v for k, v in entry.items() if k not in ("prev_hash", "entry_hash", "alg")}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    entry["entry_hash"] = hashlib.sha256(entry["prev_hash"].encode("ascii") + canon).hexdigest()
    return json.dumps(entry, separators=(",", ":"), ensure_ascii=False)


def _plant(plant: str, path: Path, led) -> list[str]:
    if plant == "row_after_seal":
        led.record("audit_rotate", target="ledger", detail={"sealed": True})
        led.record("core.execute", target="pve:PUT /after", mutation=True)
        return _lines(path)
    rows = _lines(path)
    if plant == "alter_field":
        rows[1] = rows[1].replace("qemu/101", "qemu/999")
    elif plant == "delete_middle":
        del rows[1]
    elif plant == "swap_two":
        rows[0], rows[1] = rows[1], rows[0]
    elif plant == "alg_downgrade":
        rows[2] = _downgrade(rows[2])
    elif plant == "entry_hash_not_str":
        e = json.loads(rows[1])
        e["entry_hash"] = 42
        rows[1] = json.dumps(e)
    elif plant == "unparseable":
        rows[1] = "{"
    elif plant == "non_object":
        rows[1] = "[1]"
    return rows


@pytest.mark.parametrize("plant", ["alter_field", "delete_middle", "swap_two", "alg_downgrade",
                                   "entry_hash_not_str", "row_after_seal", "unparseable", "non_object"])
def test_the_script_and_the_core_agree_on_every_planted_break(tmp_path, plant):
    path, keyfile, led = _keyed_log(tmp_path)
    rows = _plant(plant, path, led)
    _write(path, rows)
    core = ledger.verify_lines(rows, _key(keyfile))
    ok, n, line, reason, _head = _script().verify(rows, _key(keyfile), None)
    assert not core.ok, "the plant did not break the chain: the case proves nothing"
    assert (ok, n, line, reason) == (core.ok, core.entries, core.broken_at, core.reason)
    r = _run(tmp_path, str(path), "--key", str(keyfile))
    assert r.returncode == 1 and r.stdout == f"broken at line {core.broken_at}: {core.reason}\n"


def test_expected_head_catches_a_cut_tail(tmp_path):
    path, keyfile, led = _keyed_log(tmp_path)
    head = led.head()
    rows = [x for x in _lines(path) if x.strip()]
    _write(path, rows[:-1] + [""])
    r = _run(tmp_path, str(path), "--key", str(keyfile), "--expected-head", head)
    core = ledger.verify_lines(_lines(path), _key(keyfile), head)
    assert r.returncode == 1 and r.stdout == f"broken: {core.reason}\n"


def test_a_keyed_log_with_no_key_is_broken_not_ok(tmp_path):
    path, _, _ = _keyed_log(tmp_path)
    core = ledger.verify_lines(_lines(path), None)
    r = _run(tmp_path, str(path))
    assert r.returncode == 1 and r.stdout == f"broken at line 1: {core.reason}\n"


def test_a_u2028_in_a_target_is_one_row(tmp_path):
    path, keyfile, led = _keyed_log(tmp_path, n=2, target="pve:PUT /a b/{i}")
    r = _run(tmp_path, str(path), "--key", str(keyfile))
    assert r.returncode == 0 and r.stdout == f"ok 2 {led.head()}\n", r.stdout + r.stderr


def test_crlf_line_endings_agree_with_the_core(tmp_path):
    path, keyfile, led = _keyed_log(tmp_path)
    path.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
    core = ledger.verify_lines(path.read_text(encoding="utf-8").split("\n"), _key(keyfile))
    r = _run(tmp_path, str(path), "--key", str(keyfile))
    assert core.ok and r.returncode == 0 and r.stdout == f"ok 3 {led.head()}\n", r.stdout + r.stderr


# --- refusals: the check could not run, so it says so and exits 2 --------------------------------

def test_key_file_shapes(tmp_path):
    path, keyfile, led = _keyed_log(tmp_path)
    upper = tmp_path / "upper.key"
    upper.write_text(keyfile.read_text().strip().upper() + "\n")
    assert _run(tmp_path, str(path), "--key", str(upper)).returncode == 0
    for name, text in (("short.key", "ab" * 31), ("hex.key", "zz" * 32), ("empty.key", "\n")):
        bad = tmp_path / name
        bad.write_text(text)
        r = _run(tmp_path, str(path), "--key", str(bad))
        assert r.returncode == 2 and r.stdout == "", (name, r.stdout, r.stderr)


def test_zero_rows_refuses(tmp_path):
    for name, text in (("empty.log", ""), ("blank.log", "\n\n  \n")):
        p = tmp_path / name
        p.write_text(text)
        r = _run(tmp_path, str(p))
        assert r.returncode == 2 and r.stdout == "" and "no rows" in r.stderr, (name, r.stderr)


def test_a_missing_log_refuses(tmp_path):
    r = _run(tmp_path, str(tmp_path / "nope.log"))
    assert r.returncode == 2 and r.stdout == ""


# --- the written format is the code's format -------------------------------------------------------

def test_the_format_doc_names_what_the_code_does():
    doc = (ROOT / "docs" / "ledger-format.md").read_text(encoding="utf-8")
    for field in ledger._CHAIN_FIELDS:
        assert f"`{field}`" in doc, field
    assert ledger.GENESIS_HASH in doc and ledger._KEY_ALG in doc
    assert "ledger: 1" in doc and 'separators=(",", ":")' in doc and "ensure_ascii=False" in doc
    for action in ("audit_rotate", "core.consent_spent"):
        assert f"`{action}`" in doc, action
    assert f"{ledger._AUDIT_TARGET_MAX}" in doc


# --- the FILE, not pre-split lines: every checker reads the same bytes the same way ---------------

def _three_way(tmp_path, path, keyfile):
    """The live log's verify (what audit_verify runs), the archive walk, and the script, on one file."""
    key = _key(keyfile)
    live = ledger.AuditLedger(str(path), key=key).verify()
    arch = ledger.verify_chain(str(path), key)
    r = _run(tmp_path, str(path), "--key", str(keyfile))
    return live, arch, r


def _crafted(plant: str, path: Path) -> None:
    raw = path.read_bytes()
    rows = raw.split(b"\n")
    if plant == "lone_cr_between_rows":
        path.write_bytes(b"\r".join(r for r in rows if r) + b"\n")
    elif plant == "cr_as_json_whitespace":
        rows[1] = rows[1].replace(b',"mutation"', b',\r"mutation"', 1)
        path.write_bytes(b"\n".join(rows))
    elif plant == "huge_int":
        rows[1] = rows[1].replace(b'"i":1', b'"i":' + b"9" * 5000, 1)
        path.write_bytes(b"\n".join(rows))
    elif plant == "deep_nesting":
        rows[1] = b"[" * 100000
        path.write_bytes(b"\n".join(rows))
    elif plant == "lone_surrogate":
        rows[1] = rows[1].replace(b'"i":1', b'"i":"\\ud800"', 1)
        path.write_bytes(b"\n".join(rows))
    elif plant == "not_utf8":
        rows[1] = rows[1].replace(b"qemu/101", b"qemu/1\xff1", 1)
        path.write_bytes(b"\n".join(rows))
    elif plant == "deleted_row":
        del rows[1]
        path.write_bytes(b"\n".join(rows))
    elif plant == "swapped_rows":
        rows[0], rows[1] = rows[1], rows[0]
        path.write_bytes(b"\n".join(rows))


@pytest.mark.parametrize("plant", ["lone_cr_between_rows", "cr_as_json_whitespace", "huge_int",
                                   "deep_nesting", "lone_surrogate", "not_utf8",
                                   "deleted_row", "swapped_rows"])
def test_every_checker_agrees_on_the_same_crafted_file(tmp_path, plant):
    path, keyfile, _ = _keyed_log(tmp_path)
    _crafted(plant, path)
    live, arch, r = _three_way(tmp_path, path, keyfile)
    assert (live.ok, live.entries, live.broken_at, live.reason) == \
           (arch.ok, arch.entries, arch.broken_at, arch.reason), "the live check and the archive walk differ"
    if live.ok:
        assert r.returncode == 0 and r.stdout.startswith(f"ok {live.entries} "), r.stdout + r.stderr
    else:
        assert r.returncode == 1 and r.stdout == f"broken at line {live.broken_at}: {live.reason}\n", \
            r.stdout + r.stderr


def test_a_changed_byte_that_changes_no_content_is_not_a_break(tmp_path):
    # the hash covers the canonical BODY, not the bytes: JSON whitespace is not content
    path, keyfile, _ = _keyed_log(tmp_path)
    _crafted("cr_as_json_whitespace", path)
    live, _, r = _three_way(tmp_path, path, keyfile)
    assert live.ok and r.returncode == 0


def test_an_empty_key_argument_refuses_rather_than_checking_unkeyed(tmp_path):
    path = tmp_path / "archive.log"
    ledger.AuditLedger(str(path)).record("core.execute", target="pve:PUT /x", mutation=True)
    r = _run(tmp_path, str(path), "--key", "")
    assert r.returncode == 2 and r.stdout == ""


def test_an_uppercase_pin_is_the_same_pin(tmp_path):
    # audit_verify lowercases the pin it is given; the script must not answer differently
    path, keyfile, led = _keyed_log(tmp_path)
    r = _run(tmp_path, str(path), "--key", str(keyfile), "--expected-head", led.head().upper())
    assert r.returncode == 0, r.stdout + r.stderr
