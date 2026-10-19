"""The chain is total over what the file already holds.

The 2026-09-21 incident: a shell-door proof wrote receipts with the bare `AuditLedger(path)` onto
a chain that had been HMAC-keyed since June. Nothing refused. The next keyed start read the
unkeyed TAIL as the whole file's mode, sealed 8,599 rows into an archive as if they were all
unkeyed, and started a fresh log. Three things were wrong and each has a test here: the writer
did not look at what it was appending to; the mode detector read one row; and verify() could not
walk the result. Every test that asserts a refusal also asserts the file did not change.
"""
from __future__ import annotations

import json
import os

import pytest

from proximo.core import ledger as L
from proximo.core.ledger import AuditLedger, LedgerConfig, open_ledger


def _rows(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def _keyed(tmp_path):
    cfg = LedgerConfig(audit_log_path=str(tmp_path / "audit.log"))
    led = open_ledger(cfg)
    led.record("core.execute", target="/a", mutation=True)
    led.record("core.execute", target="/b", mutation=True)
    return cfg, led


# --- the writer looks at the chain it is appending to ---------------------------------------

def test_the_0921_bypass_is_refused_and_the_chain_is_untouched(tmp_path):
    """THE PLANTED INCIDENT. A bare constructor on a keyed chain must refuse, not append."""
    cfg, led = _keyed(tmp_path)
    before = open(cfg.audit_log_path, "rb").read()
    with pytest.raises(ValueError, match="open_ledger"):
        AuditLedger(cfg.audit_log_path).record("core.execute", target="/c", mutation=True)
    assert open(cfg.audit_log_path, "rb").read() == before
    assert led.verify().ok
    assert L.find_rotation_archive(cfg.audit_log_path) is None


def test_a_keyed_writer_on_an_unkeyed_chain_is_refused_too(tmp_path):
    """The mirror direction. open_ledger migrates; a constructor never does."""
    path = str(tmp_path / "audit.log")
    AuditLedger(path).record("x", target="/a")
    before = open(path, "rb").read()
    with pytest.raises(ValueError, match="open_ledger"):
        AuditLedger(path, key=b"k" * 32).record("x", target="/b")
    assert open(path, "rb").read() == before


def test_a_matching_writer_still_appends(tmp_path):
    """The guard is about MISMATCH: the same-alg constructor path (reads, tests, tools that hold
    the key) keeps working, because refusing it would make every existing caller a migration."""
    cfg, led = _keyed(tmp_path)
    AuditLedger(cfg.audit_log_path, key=led.key).record("core.execute", target="/c", mutation=True)
    assert led.verify().ok and len(_rows(cfg.audit_log_path)) == 3


def test_an_empty_file_takes_either_writer(tmp_path):
    path = str(tmp_path / "audit.log")
    AuditLedger(path, key=b"k" * 32).record("x", target="/a")
    assert _rows(path)[0]["alg"] == "hmac-sha256"


# --- the detector reads the whole file, and says "mixed" when it is -------------------------

def _mixed(tmp_path) -> tuple[str, bytes]:
    """A chain built the way the incident built it: keyed rows, then unkeyed rows chained onto
    them by hand (the guard above now makes the writer refuse this, so the test forges the lines
    itself -- that is the shape an OLD Proximo left on disk and this code must still read)."""
    cfg, led = _keyed(tmp_path)
    prev = led.head()
    with open(cfg.audit_log_path, "a", encoding="utf-8") as f:
        for i in range(3):
            body = {"ts": "t", "action": "shell", "target": f"/u{i}", "mutation": True,
                    "outcome": "ok", "detail": {}}
            entry = {**body, "prev_hash": prev, "entry_hash": L._hash(body, prev, None)}
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
            prev = entry["entry_hash"]
    return cfg.audit_log_path, led.key


def test_detect_mode_reports_mixed(tmp_path):
    path, _ = _mixed(tmp_path)
    assert L.detect_mode(path) == "mixed"


def test_open_ledger_seals_a_mixed_chain_and_the_custody_row_tells_the_truth(tmp_path):
    """The 09-22 custody row said `prev_alg: sha256` about a file that was 99.7% HMAC. A seam
    must be recorded as what it is, with the line the algorithm changed on."""
    path, key = _mixed(tmp_path)
    with pytest.warns(UserWarning, match="mixed"):
        led = open_ledger(LedgerConfig(audit_log_path=path))
    archive = L.find_rotation_archive(path)
    assert archive and archive.endswith(tuple("0123456789abcdef"))
    genesis = _rows(path)[0]
    assert genesis["action"] == "audit_rotate"
    assert genesis["detail"]["prev_alg"] == "mixed"
    assert genesis["detail"]["seam_line"] == 3  # rows 1-2 keyed, row 3 is the first unkeyed
    assert led.verify().ok
    # the archive's seal is chained with the TAIL's alg (the only one that can extend the tail)
    assert _rows(archive)[-1]["action"] == "audit_rotate" and "alg" not in _rows(archive)[-1]


# --- an archive is provable, not just intact --------------------------------------------------

def test_verify_chain_walks_a_mixed_archive_per_row(tmp_path):
    path, key = _mixed(tmp_path)
    v = L.verify_chain(path, key)
    assert v.ok and v.entries == 5
    assert v.segments == (("hmac-sha256", 2), ("sha256", 3))


def test_verify_chain_sees_its_own_failure(tmp_path):
    """CONTROL: an altered row in the keyed segment, and the wrong key, both go red at the row."""
    path, key = _mixed(tmp_path)
    rows = _rows(path)
    rows[1]["target"] = "/tampered"
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(json.dumps(r, separators=(",", ":")) + "\n" for r in rows)
    v = L.verify_chain(path, key)
    assert not v.ok and v.broken_at == 2
    assert not L.verify_chain(path, b"w" * 32).ok


def test_verify_chain_refuses_a_keyed_row_without_a_key(tmp_path):
    path, _ = _mixed(tmp_path)
    v = L.verify_chain(path, None)
    assert not v.ok and v.broken_at == 1 and "key" in v.reason


def test_the_door_can_verify_an_archive(tmp_path, monkeypatch):
    """audit_verify(path=<archive>) on the MCP door: the estate's June-to-September chain lives
    in one of these, and 'intact' is not 'provable' until the door can say so."""
    from proximo.core.doors import mcp as door
    path, key = _mixed(tmp_path)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", path)
    open_ledger(LedgerConfig(audit_log_path=path))         # seals + rotates
    archive = L.find_rotation_archive(path)
    out = door.audit_verify(path=os.path.basename(archive))
    assert out["ok"] and out["segments"] == [["hmac-sha256", 2], ["sha256", 4]]
    assert door.audit_verify()["ok"]                        # the live log, unchanged behaviour
    with pytest.raises(Exception, match="beside the ledger"):
        door.audit_verify(path="/etc/passwd")               # only siblings of the ledger


def test_verify_chain_refuses_a_row_after_the_seal(tmp_path):
    """LENS B2. The one verifier built for SEALED archives did not check the seal was terminal:
    a row appended after `audit_rotate{sealed:true}` verified as ok. Same rule as verify()."""
    path, key = _mixed(tmp_path)
    open_ledger(LedgerConfig(audit_log_path=path))
    archive = L.find_rotation_archive(path)
    assert L.verify_chain(archive, key).ok
    rows = _rows(archive)
    prev = rows[-1]["entry_hash"]
    body = {"ts": "t", "action": "shell", "target": "/late", "mutation": True, "outcome": "ok", "detail": {}}
    with open(archive, "a", encoding="utf-8") as f:
        f.write(json.dumps({**body, "prev_hash": prev, "entry_hash": L._hash(body, prev, None)},
                           separators=(",", ":")) + "\n")
    v = L.verify_chain(archive, key)
    assert not v.ok and v.broken_at == len(rows) + 1 and "seal" in v.reason
