"""PROVE on the LIVE chain, through the door: a broken ledger is named by the way it broke.

The gate round of 2026-10-16 neutered every core gate one at a time under the core-only tests
(the ones that import nothing of 0.44) and two of them survived: the live chain's `prev_hash`
check and its keyed-downgrade check. Neither survival was a hole in detection, because the
hash of every row is computed over the RUNNING previous hash with the ledger's own key, so a
removed, reordered or downgraded row still fails the hash compare. What the two checks carry
is the DIAGNOSIS: "removed or reordered" and "downgrade" instead of "altered". An operator
reading "altered" when a row was cut out of the middle looks for the wrong attacker. These
tests drive the door's `audit_verify` on a live ledger written through `open_ledger` (the ONE
writer) and pin the reason for each class of break, with a control that proves the fixture
reads intact before it is broken.
"""
from __future__ import annotations

import json
import os

import pytest

from proximo.core import ledger as L
from proximo.core.doors import mcp as door
from proximo.core.ledger import LedgerConfig, ledger_key, open_ledger


def _rows(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


def _write(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(json.dumps(r, separators=(",", ":")) + "\n" for r in rows)


@pytest.fixture
def live(monkeypatch, tmp_path):
    """Four rows on a KEYED live ledger (the default), the door aimed at it."""
    path = str(tmp_path / "audit.log")
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":   # the pin on the real file stays
            monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", path)
    led = open_ledger(LedgerConfig(audit_log_path=path))
    for t in ("/a", "/b", "/c", "/d"):
        led.record("core.execute", target=t, mutation=True)
    assert ledger_key(LedgerConfig(audit_log_path=path)) is not None   # keyed, as every live log is
    return path


def test_the_control_an_intact_live_chain_verifies_through_the_door(live):
    out = door.audit_verify()
    assert out["ok"] and out["entries"] == 4 and out["broken_at"] is None


def test_a_row_cut_from_the_middle_is_named_removed_not_altered(live):
    rows = _rows(live)
    del rows[1]
    _write(live, rows)
    out = door.audit_verify()
    assert not out["ok"] and out["broken_at"] == 2
    assert "removed" in out["reason"] and "altered" not in out["reason"]


def test_two_rows_swapped_are_named_reordered_at_the_first_of_them(live):
    rows = _rows(live)
    rows[1], rows[2] = rows[2], rows[1]
    _write(live, rows)
    out = door.audit_verify()
    assert not out["ok"] and out["broken_at"] == 2 and "reordered" in out["reason"]


def test_a_row_altered_in_place_is_named_altered(live):
    """THE AXIS NOT VARIED: a body edit keeps every link and breaks only its own hash."""
    rows = _rows(live)
    rows[2]["target"] = "/tampered"
    _write(live, rows)
    out = door.audit_verify()
    assert not out["ok"] and out["broken_at"] == 3 and "altered" in out["reason"]


def test_a_row_rewritten_without_the_key_is_named_a_downgrade(live):
    """A writer who can append but cannot read the key strips `alg` and signs with the plain
    hash: the keyed ledger must say DOWNGRADE at that row, never let the row's own `alg` pick
    the algorithm it is judged by."""
    rows = _rows(live)
    rows[1].pop("alg")
    body = {k: v for k, v in rows[1].items() if k not in L._CHAIN_FIELDS}
    rows[1]["entry_hash"] = L._hash(body, rows[1]["prev_hash"], None)      # the plain, keyless hash
    _write(live, rows)
    out = door.audit_verify()
    assert not out["ok"] and out["broken_at"] == 2 and "downgrade" in out["reason"]


def test_a_truncated_tail_is_invisible_to_the_walk_and_caught_by_the_pinned_head(live):
    """Cutting the LAST row leaves a chain that verifies on its own (the walk is forward); the
    head the operator pinned off-box is the only thing that sees it, and the door takes it."""
    head = door.audit_verify()["head"]
    rows = _rows(live)
    _write(live, rows[:-1])
    assert door.audit_verify()["ok"]                                   # the walk alone: blind
    out = door.audit_verify(expected_head=head)
    assert not out["ok"] and out["broken_at"] is None and "head mismatch" in out["reason"]
