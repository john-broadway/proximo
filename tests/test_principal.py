"""Principal-in-ledger: the name tag + per-request caller identity (spec 2026-07-16)."""
import contextvars

import pytest

from proximo import principal
from proximo.audit import AuditLedger
from proximo.backends import ProximoError


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("PROXIMO_PRINCIPAL", raising=False)
    monkeypatch.delenv("PROXIMO_CALLER_KEYS_DIR", raising=False)
    principal.set_serving_face("stdio")


def test_process_principal_unset_is_none():
    assert principal.process_principal() is None


def test_process_principal_blank_is_none(monkeypatch):
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "   ")
    assert principal.process_principal() is None


def test_sanitize_id_strips_null_and_control_chars():
    assert principal.sanitize_id("claude\x00-code\x07@ops") == "claude-code@ops"


def test_process_principal_sanitized(monkeypatch):
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "claude\x07-code\n@ops")
    assert principal.process_principal() == "claude-code@ops"


def test_process_principal_length_capped(monkeypatch):
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "x" * 500)
    assert len(principal.process_principal()) == 120


def test_ledger_principal_none_when_unconfigured():
    assert principal.ledger_principal() is None


def test_ledger_principal_spawn(monkeypatch):
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "claude-code@ops")
    assert principal.ledger_principal() == {
        "id": "claude-code@ops", "via": "spawn", "face": "stdio"}


def test_ledger_principal_verified_caller_wins(monkeypatch):
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "claude-code@ops")
    principal.set_serving_face("http")
    tok = principal.set_active_caller("fleet-7")
    try:
        assert principal.ledger_principal() == {
            "id": "fleet-7", "via": "verified", "face": "http"}
    finally:
        principal.reset_active_caller(tok)
    assert principal.ledger_principal()["via"] == "spawn"


def test_active_caller_isolated_per_context(monkeypatch):
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", "/etc/proximo")  # feature on

    def in_ctx():
        principal.set_active_caller("other")
        return principal.ledger_principal()["id"]

    ctx = contextvars.copy_context()
    assert ctx.run(in_ctx) == "other"
    assert principal.ledger_principal() is None   # outer context untouched


def test_feature_active(monkeypatch):
    assert principal.principal_feature_active() is False
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "a")
    assert principal.principal_feature_active() is True
    monkeypatch.delenv("PROXIMO_PRINCIPAL")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", "/etc/proximo/callers")
    assert principal.principal_feature_active() is True


# --- server plumbing: every ledger write carries the principal when configured ---
#
# Mirrors the `_svc` monkeypatch fixture used throughout tests/test_server_plan.py and
# tests/test_server_multitarget.py — a real AuditLedger in tmp_path, backends left None
# (unused by these ledger-only paths), bypassing the cached PVE-config resolution entirely
# so the test needs no PROXIMO_API_BASE_URL/NODE/TOKEN_PATH triple.


def _wire_ledger(monkeypatch, tmp_path):
    from proximo import server
    log = tmp_path / "audit.jsonl"
    ledger = AuditLedger(str(log))
    monkeypatch.setattr(server, "_svc", lambda: (None, None, None, ledger))
    return server, log


def test_audited_entries_carry_principal(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "claude-code@ops")
    server, log = _wire_ledger(monkeypatch, tmp_path)
    server._audited("unit_test_read", target="t", mutation=False, fn=lambda: {"ok": True})
    raw = log.read_text()
    assert '"principal":{"id":"claude-code@ops","via":"spawn","face":"stdio"}' in raw


def test_session_entries_gated_on_feature(monkeypatch, tmp_path):
    server, log = _wire_ledger(monkeypatch, tmp_path)
    server._record_session("session_start")          # unconfigured -> no entry
    assert not log.exists()
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "claude-code@ops")
    server._record_session("session_start")
    raw = log.read_text()
    assert '"action":"session_start"' in raw and '"principal"' in raw


# --- gate refusals: the highest-signal who-asked category (plan-gap 3b) ---
#
# A refused mutation never reaches server._audited()'s own principal-tagged record() call — each
# gate (consent/lease/scope/envelope/...) records its OWN "blocked:*" entry directly. Those entries
# must carry principal too, or the who-asked trail goes dark exactly where it matters most: a
# refusal. Exercised via server._audited() (mutation=True) — the same path every real mutation
# takes — with PROXIMO_CONSENT_DIR set and no grant present, so proximo.consent.enforce_consent
# fires its "blocked:consent_no_plan" refusal. consent.set_pending_consent("") makes the "no
# pending consent_id" state explicit (mirroring tests/test_consent.py's own precedent) rather than
# relying on module import order — proximo.consent's contextvar is process-wide, so a prior test
# file (which never resets it) could otherwise leave a stale consent_id pending here.


def test_consent_refusal_carries_principal(monkeypatch, tmp_path):
    from proximo import consent

    monkeypatch.setenv("PROXIMO_PRINCIPAL", "claude-code@ops")
    consent_dir = tmp_path / "consent"
    consent_dir.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(consent_dir))
    consent.set_pending_consent("")  # explicitly no pending consent_id -> "no plan" refusal
    server, log = _wire_ledger(monkeypatch, tmp_path)

    with pytest.raises(ProximoError):
        server._audited("unit_test_mutate", target="t", mutation=True, fn=lambda: {"ok": True})

    raw = log.read_text()
    assert '"outcome":"blocked:consent_no_plan"' in raw
    assert '"principal"' in raw
    assert '"via":"spawn"' in raw


# --- the EXECUTING pre-record: attribution matters MOST where the record is the only one ---
#
# `_audited` writes a crash-safety pre-record (outcome=EXECUTING) before fn() runs, so a mutation
# that never returns (OOM / SIGKILL / host reboot) still leaves a trace; `audit.in_flight()` exists
# to surface exactly those. That stranded entry is then the ONLY record the operation will ever
# have -- which makes it the single place a missing `principal=` costs the most. The EXECUTING
# block is main-only code that arrived during the 113-commit drift, so it never appeared as a
# rebase conflict and no hand-edit touched it.

def test_executing_prerecord_carries_the_principal(tmp_path, monkeypatch):
    from test_audit_harden_0_7_1 import _entries, _wire_server  # noqa: PLC0415

    _wire_server(tmp_path, monkeypatch)
    log = str(tmp_path / "audit.log")
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "ops-bot")
    monkeypatch.delenv("PROXIMO_CALLER_KEYS_DIR", raising=False)
    import proximo.server as srv  # noqa: PLC0415

    srv._audited("test_action", "node/x", lambda: None, mutation=True)

    executing = [e for e in _entries(log) if e["outcome"] == "executing"]
    assert executing, "no EXECUTING pre-record was written at all"
    assert executing[-1].get("principal") == {"id": "ops-bot", "via": "spawn", "face": "stdio"}, (
        "the crash-safety pre-record dropped who-asked -- an operation that dies mid-flight would "
        "leave its ONLY ledger entry unattributed")
