"""INTENT — a stable id per operation, and an `executing` entry recorded BEFORE the mutation.

Closes the hole server.py documented and deferred (the L16 note): between `fn()` firing and the
outcome `audit.record()`, process death (SIGKILL/OOM/power loss) leaves an executed mutation with
NO ledger entry. PROVE could not answer "what was running when we died" — the one question that
matters most after a crash on a hypervisor.

The competing approach is a separate mutable SQLite job store. This rides the ledger already in
place, which is append-only and HMAC hash-chained, so the crash record inherits tamper-evidence a
side-store cannot offer. Two properties fall out of one change:

  crash forensics   an `executing` entry with no terminal entry for the same intent means that
                    operation was in flight when the process stopped.
  retry linkage     the intent id is DERIVED from (action, target), so a retried operation
                    carries the same id with no cooperation from the caller. Proxmox's own UPID
                    identifies an ATTEMPT; the intent identifies the OPERATION across attempts.

Deriving rather than accepting a caller-supplied id is deliberate. A `proximo_intent` parameter
would ride ~900 tool schemas, and that multiplication is exactly the defect this codebase just
spent a day removing (84k tokens of one repeated sentence). Derivation costs zero schema bytes.

MUTATIONS ONLY. A read that dies mid-flight changed nothing, so pre-recording reads would double
ledger volume to answer a question nobody asks.
"""
from __future__ import annotations

import json

import pytest

from proximo import audit, server


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_AUDIT_KEYED", "false")
    led = audit.AuditLedger(path=str(tmp_path / "audit.log"), key=None)
    monkeypatch.setattr(server, "_ledger", lambda: led)
    return led


def _entries(led) -> list[dict]:
    with open(led.path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# --- the intent id ---------------------------------------------------------------------------

def test_intent_id_is_stable_for_the_same_operation():
    """Two attempts at the same operation must carry the same intent id — that IS the linkage."""
    a = server.intent_id("pve_guest_power", "nodes/n1/qemu/100/status/start")
    b = server.intent_id("pve_guest_power", "nodes/n1/qemu/100/status/start")
    assert a == b


def test_intent_id_differs_across_operations():
    start = server.intent_id("pve_guest_power", "nodes/n1/qemu/100/status/start")
    other = server.intent_id("pve_guest_power", "nodes/n1/qemu/101/status/start")
    action = server.intent_id("pve_delete_guest", "nodes/n1/qemu/100")
    assert len({start, other, action}) == 3


def test_intent_id_is_short_enough_to_read():
    """It lands in every mutation's ledger detail; a full sha256 is noise in a forensic read."""
    assert len(server.intent_id("pve_guest_power", "nodes/n1/qemu/100/status/start")) <= 16


# --- the executing entry ---------------------------------------------------------------------

def test_mutation_records_executing_before_the_call(ledger):
    """The entry must exist BEFORE fn() runs — that is the whole point.

    Asserted by observing the ledger from INSIDE fn(), which is the only way to prove ordering.
    A post-hoc check of the finished log cannot distinguish "written first" from "written after".
    """
    seen = {}

    def fn():
        seen["during"] = _entries(ledger)
        return {"ok": True}

    server._audited("pve_guest_power", "nodes/n1/qemu/100/status/start", fn, mutation=True)
    assert len(seen["during"]) == 1, "no ledger entry existed while the mutation was running"
    assert seen["during"][0]["outcome"] == "executing"


def test_executing_and_outcome_share_one_intent(ledger):
    server._audited("pve_guest_power", "nodes/n1/qemu/100/status/start",
                    lambda: {"ok": True}, mutation=True)
    rows = _entries(ledger)
    assert [r["outcome"] for r in rows] == ["executing", "ok"]
    assert rows[0]["detail"]["intent"] == rows[1]["detail"]["intent"]


def test_a_failed_mutation_still_pairs(ledger):
    def boom():
        raise RuntimeError("nope")

    with pytest.raises(RuntimeError):
        server._audited("pve_guest_power", "nodes/n1/qemu/100/status/start", boom, mutation=True)
    rows = _entries(ledger)
    assert [r["outcome"] for r in rows] == ["executing", "error"]
    assert rows[0]["detail"]["intent"] == rows[1]["detail"]["intent"]


def test_reads_are_not_pre_recorded(ledger):
    """A read that dies changed nothing. Pre-recording reads is pure ledger bloat."""
    server._audited("pve_list_guests", "cluster/resources", lambda: [], mutation=False)
    assert [r["outcome"] for r in _entries(ledger)] == ["ok"]


def test_redacted_exec_plan_does_not_ledger_the_operator_cleartext(ledger):
    """L2: operator_cleartext is a PREVIEW-only field. _record_plan must not write it (nor the raw
    command it holds) into the durable, redaction-protected ledger — only the dry-run return carries it."""
    from proximo.planning import plan_exec
    p = plan_exec("105", ["mysql", "--password", "hunter2"], redact=True)
    assert p.as_dict()["operator_cleartext"] == "mysql --password hunter2"  # present in the preview
    server._record_plan(p)
    blob = json.dumps(_entries(ledger))
    assert "hunter2" not in blob             # raw secret never persisted to the ledger
    assert "operator_cleartext" not in blob  # the preview field is not written to the ledger


def test_a_retry_reuses_the_intent_across_attempts(ledger):
    """Attempt 1 fails, attempt 2 succeeds: one intent, four entries, no caller cooperation."""
    with pytest.raises(RuntimeError):
        server._audited("pve_guest_power", "nodes/n1/qemu/100/status/start",
                        lambda: (_ for _ in ()).throw(RuntimeError("x")), mutation=True)
    server._audited("pve_guest_power", "nodes/n1/qemu/100/status/start",
                    lambda: {"ok": True}, mutation=True)
    rows = _entries(ledger)
    assert [r["outcome"] for r in rows] == ["executing", "error", "executing", "ok"]
    assert len({r["detail"]["intent"] for r in rows}) == 1


# --- crash forensics -------------------------------------------------------------------------

def test_in_flight_finds_an_operation_that_never_terminated(ledger):
    """The question PROVE could not answer before: what was running when we died?"""
    server._audited("pve_guest_power", "nodes/n1/qemu/100/status/start",
                    lambda: {"ok": True}, mutation=True)
    # simulate death: an executing entry with no terminal partner
    ledger.record("pve_delete_guest", target="nodes/n1/qemu/999", mutation=True,
                  outcome="executing", detail={"intent": server.intent_id(
                      "pve_delete_guest", "nodes/n1/qemu/999")})
    stranded = audit.in_flight(_entries(ledger))
    assert [s["action"] for s in stranded] == ["pve_delete_guest"]


def test_in_flight_is_empty_when_everything_completed(ledger):
    server._audited("pve_guest_power", "nodes/n1/qemu/100/status/start",
                    lambda: {"ok": True}, mutation=True)
    assert audit.in_flight(_entries(ledger)) == []


def test_in_flight_reports_stranded_op_when_two_identical_ops_overlap(ledger):
    # intent_id hashes only action+target, so two IDENTICAL ops share one intent. One terminates,
    # one is stranded. The old dict (last-writer-wins) reported ZERO in-flight; the per-intent
    # stack reports the one that never terminated.
    intent = server.intent_id("pve_delete_guest", "nodes/n1/qemu/999")
    ledger.record("pve_delete_guest", target="nodes/n1/qemu/999", mutation=True,
                  outcome="executing", detail={"intent": intent})
    ledger.record("pve_delete_guest", target="nodes/n1/qemu/999", mutation=True,
                  outcome="executing", detail={"intent": intent})
    ledger.record("pve_delete_guest", target="nodes/n1/qemu/999", mutation=True,
                  outcome="ok", detail={"intent": intent})  # only ONE of the two terminates
    stranded = audit.in_flight(_entries(ledger))
    assert [s["action"] for s in stranded] == ["pve_delete_guest"]


def test_in_flight_empty_when_both_identical_ops_complete(ledger):
    # Guard against over-reporting: two identical-intent ops that BOTH terminate -> nothing open.
    intent = server.intent_id("pve_delete_guest", "nodes/n1/qemu/999")
    for _ in range(2):
        ledger.record("pve_delete_guest", target="nodes/n1/qemu/999", mutation=True,
                      outcome="executing", detail={"intent": intent})
    for _ in range(2):
        ledger.record("pve_delete_guest", target="nodes/n1/qemu/999", mutation=True,
                      outcome="ok", detail={"intent": intent})
    assert audit.in_flight(_entries(ledger)) == []


def test_in_flight_ignores_reads_and_refusals(ledger):
    """Only `executing` opens an interval; a refusal never ran and must not look stranded."""
    ledger.record("pve_delete_guest", target="nodes/n1/qemu/5", mutation=True,
                  outcome="blocked:contained", detail={})
    ledger.record("pve_list_guests", target="cluster/resources", mutation=False, outcome="ok")
    assert audit.in_flight(_entries(ledger)) == []


def test_the_chain_still_verifies_with_executing_entries(ledger):
    """A new outcome value must not disturb hash-chain verification."""
    server._audited("pve_guest_power", "nodes/n1/qemu/100/status/start",
                    lambda: {"ok": True}, mutation=True)
    result = ledger.verify()
    assert result.ok is True
    assert result.entries == 2, "executing + outcome should both be in the chain"


def test_in_flight_terminal_on_empty_stack_is_ignored(ledger):
    # A terminal whose intent has no open executing (e.g. the log starts mid-operation) must not
    # crash (stack .get is None) nor report anything.
    intent = server.intent_id("pve_delete_guest", "nodes/n1/qemu/7")
    ledger.record("pve_delete_guest", target="nodes/n1/qemu/7", mutation=True, outcome="ok",
                  detail={"intent": intent})
    assert audit.in_flight(_entries(ledger)) == []


def test_in_flight_more_terminals_than_executing_never_goes_negative(ledger):
    intent = server.intent_id("pve_delete_guest", "nodes/n1/qemu/7")
    ledger.record("pve_delete_guest", target="nodes/n1/qemu/7", mutation=True,
                  outcome="executing", detail={"intent": intent})
    for _ in range(3):  # 3 terminals for 1 executing
        ledger.record("pve_delete_guest", target="nodes/n1/qemu/7", mutation=True,
                      outcome="ok", detail={"intent": intent})
    assert audit.in_flight(_entries(ledger)) == []
