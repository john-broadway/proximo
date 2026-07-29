"""0.7.1 harden-pass regression tests (from the 2026-06-23 review/harden pass on the 0.7.0 PROVE surface).

Each test below fails against the 0.7.0 code and passes after the harden patch. The PROVE crypto
guarantees themselves (chain integrity, downgrade-rejection, no-key forgery, tail-pin detection)
were independently re-verified as HOLDING and are NOT re-tested here — see test_ledger.py for those.
This file covers the robustness / crash-consistency / upgrade-UX gaps the adversarial pass surfaced.
"""

from __future__ import annotations

import json
import os
import warnings
from types import SimpleNamespace

import pytest

from proximo.audit import AuditLedger, find_rotation_archive, open_ledger, seal_and_rotate
from proximo.config import ProximoConfig

_KEY = bytes(range(32))  # deterministic 32-byte key for tests


def _ledger(tmp_path):
    return AuditLedger(str(tmp_path / "audit.log"))


def _svc_cfg(tmp_path, **kw):
    # mirrors test_ledger._cfg: a duck-typed cfg for open_ledger (reads only these three).
    base = dict(audit_log_path=str(tmp_path / "audit.log"), audit_key_path=None, audit_keyed=True)
    base.update(kw)
    return SimpleNamespace(**base)


def _base_env(monkeypatch, **extra):
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/run/x")
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


# --- Finding: malformed pin bricks all 145 tools (from_env runs on every tool via _svc) ----------


def test_expected_head_normalizes_uppercase_and_whitespace(monkeypatch):
    # A SHA-256 hexdigest is case-insensitive; an operator copy-pasting the head from the migration
    # warning may uppercase it or carry a trailing newline. Normalize instead of raising — a raise
    # in from_env() breaks EVERY tool (all 145 go through _svc -> from_env), not just audit_verify.
    h = "a" * 64
    for raw in (h.upper(), " " + h, h + "\n", "  " + h.upper() + "  "):
        _base_env(monkeypatch, PROXIMO_AUDIT_EXPECTED_HEAD=raw)
        assert ProximoConfig.from_env().expected_head == h


def test_expected_head_still_rejects_genuinely_malformed(monkeypatch):
    # Guard: normalization must not weaken validation. Wrong length / non-hex still raises.
    for bad in ("a" * 63, "a" * 65, "g" * 64, "not-a-hash"):
        _base_env(monkeypatch, PROXIMO_AUDIT_EXPECTED_HEAD=bad)
        with pytest.raises(RuntimeError, match="PROXIMO_AUDIT_EXPECTED_HEAD"):
            ProximoConfig.from_env()


def test_audit_keyed_opt_out_tolerates_whitespace(monkeypatch):
    # ' off ' (e.g. an unquoted docker-compose env value) must still opt out. Silently staying
    # keyed would trigger an unwanted migration + head rotation behind the operator's back.
    for raw in (" off ", "off ", " OFF", " false "):
        _base_env(monkeypatch, PROXIMO_AUDIT_KEYED=raw)
        assert ProximoConfig.from_env().audit_keyed is False


# --- Finding: verify() crashes (TypeError) instead of failing-clean on non-string entry_hash -----


@pytest.mark.parametrize("bad", [42, [1, 2], {"k": "v"}, True, 3.14])
def test_verify_nonstring_entry_hash_returns_false_not_crash(tmp_path, bad):
    # A tampered entry whose entry_hash is a truthy non-string must verify ok=False, not raise
    # TypeError (a writer-with-access DoS on the verify pillar; `... or ""` only coerces falsy).
    led = _ledger(tmp_path)
    led.record("a", target="t1")
    p = tmp_path / "audit.log"
    e = json.loads(p.read_text().strip())
    e["entry_hash"] = bad
    p.write_text(json.dumps(e) + "\n")
    v = led.verify()  # must not raise
    assert not v.ok


@pytest.mark.parametrize("bad_line", ["42", "[1, 2]", '"a string"', "3.14", "true"])
def test_last_hash_tolerates_nondict_json_line(tmp_path, bad_line):
    # Symmetric to the verify() guard (H-1): a valid-JSON *non-dict* tail line must not crash
    # _last_hash — which record() calls to chain the next entry and head()/audit_verify reach.
    # Without the isinstance guard, json.loads(line)["entry_hash"] raises TypeError, which would
    # (a) crash record() AFTER the PVE call fired — the mutation goes unrecorded — and
    # (b) DoS audit_verify instead of cleanly reporting the corrupt line.
    led = _ledger(tmp_path)
    led.record("a", target="t1")
    p = tmp_path / "audit.log"
    p.write_text(p.read_text() + bad_line + "\n")  # append a junk (valid-JSON, non-dict) tail line
    led.head()                    # must not raise (this is the audit_verify path)
    led.record("b", target="t2")  # must not raise mid-mutation
    assert '"action":"b"' in p.read_text()  # the new entry actually made it to disk (compact JSON)


# --- Finding: torn last line (crash mid-append) concatenates the next entry onto one line --------


def test_record_after_torn_line_does_not_concatenate(tmp_path):
    # A crash can leave the last line without its trailing newline. The next record() must start on
    # a fresh physical line — never glue two JSON objects onto one line (which the forward walk then
    # reads as a single unparseable line, silently re-anchoring the chain at GENESIS).
    led = _ledger(tmp_path)
    led.record("first", target="t1")
    led.record("second", target="t2")
    p = tmp_path / "audit.log"
    p.write_text(p.read_text().rstrip("\n"))  # simulate torn write: drop the final newline
    led.record("third", target="t3")

    lines = [ln for ln in p.read_text().splitlines() if ln.strip()]
    assert len(lines) == 3, "appended entry concatenated onto the torn line"
    for ln in lines:
        json.loads(ln)  # each physical line must be independently parseable JSON
    assert led.verify().ok  # and the repaired chain verifies end-to-end


# --- Finding (F1): seal_and_rotate vs record() lock different objects -> interloper at line 1 -----


def test_seal_and_rotate_clobbers_interloper_in_rename_window(tmp_path, monkeypatch):
    # record() flocks the LOG inode; seal_and_rotate flocks a sidecar .lock — different objects, so
    # they don't mutually exclude. A racer (e.g. a still-running pre-0.7.0 process) that writes an
    # UNKEYED entry to log_path in the window between the archive-rename and the new keyed genesis
    # must NOT end up at line 1 of the new keyed log (which would make it fail verify() forever).
    log = str(tmp_path / "audit.log")
    AuditLedger(log).record("legacy", target="t1")  # pre-existing unkeyed ledger

    real_rename = os.rename

    def racing_rename(src, dst, *a, **k):
        real_rename(src, dst, *a, **k)  # archive the old log
        if os.fspath(src) == log:  # we're now in the rotate window
            AuditLedger(log).record("interloper", target="race")  # racer writes UNKEYED to fresh log_path

    monkeypatch.setattr(os, "rename", racing_rename)
    seal_and_rotate(log, _KEY)
    monkeypatch.undo()  # restore os.rename before inspecting

    led = AuditLedger(log, key=_KEY)
    v = led.verify()
    assert v.ok, f"interloper corrupted the new keyed log: {v.reason}"
    assert "interloper" not in (tmp_path / "audit.log").read_text()


# --- Finding (F3): silent migration -> stale pin reads as bare 'head mismatch' (== a tail attack) -


def test_audit_verify_distinguishes_migration_rotation_from_tamper(tmp_path, monkeypatch):
    # After a keyed-default upgrade rotates the head, a stale off-box pin verifies as a bare
    # "head mismatch" — byte-identical to a real tail attack, with the only notice on stderr
    # (which MCP stdio clients swallow). When a sibling .unkeyed-* archive exists, audit_verify
    # must surface a rotation_hint so the operator can tell a benign upgrade from tampering.
    import proximo.server as server

    log = str(tmp_path / "audit.log")
    AuditLedger(log).record("legacy", target="t1")  # pre-existing unkeyed ledger
    old_head = AuditLedger(log).head()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        led = open_ledger(_svc_cfg(tmp_path))  # migrate: rotates head, archives the unkeyed log

    cfg = SimpleNamespace(expected_head=old_head)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))
    out = server.audit_verify()  # pinned to the now-stale pre-migration head
    assert not out["ok"] and "head mismatch" in out["reason"]
    assert out.get("rotation_hint"), "no signal distinguishing migration from a tail attack"
    assert "re-pin" in out["rotation_hint"].lower()


def test_audit_verify_param_pin_normalizes_uppercase(tmp_path, monkeypatch):
    # Consistency with the env-var pin: an uppercased/whitespaced head passed directly to the tool
    # should normalize and match, not raise a confusing "invalid expected_head" caller error.
    import proximo.server as server

    led = AuditLedger(str(tmp_path / "audit.log"), key=_KEY)
    led.record("a", target="t1")
    cfg = SimpleNamespace(expected_head=None)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))
    out = server.audit_verify(expected_head="  " + led.head().upper() + "\n")
    assert out["ok"] and out["expected_head"] == led.head()


def test_audit_verify_blank_param_treated_as_unpinned(tmp_path, monkeypatch):
    # A whitespace-only / empty expected_head must be treated as "no pin" (like the config path
    # does with `or None`), not raise a confusing "invalid expected_head". Keep the two entry points
    # consistent.
    import proximo.server as server

    led = AuditLedger(str(tmp_path / "audit.log"), key=_KEY)
    led.record("a", target="t1")
    cfg = SimpleNamespace(expected_head=None)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))
    out = server.audit_verify(expected_head="   ")
    assert out["ok"] and out["expected_head"] is None


def test_open_ledger_migration_loser_does_not_warn(tmp_path, monkeypatch):
    # In a concurrent-start race the LOSER gets ("", head) from seal_and_rotate (the winner already
    # rotated). open_ledger must NOT emit a migration warning reading "archived to <empty>" — only
    # the winner (with a real archive path) should warn.
    import proximo.audit as audit_mod

    log = str(tmp_path / "audit.log")
    AuditLedger(log).record("legacy", target="t1")  # unkeyed -> enters the keyed-default migration path
    monkeypatch.setattr(audit_mod, "seal_and_rotate",
                        lambda lp, k: ("", AuditLedger(lp, key=k).head()))  # simulate the race loser
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any warning becomes a failure
        led = open_ledger(_svc_cfg(tmp_path))
    assert led.keyed


# --- Finding (F2): a stale fd can append to the archived (sealed) log after the terminal seal -------


def test_verify_rejects_entries_after_a_seal(tmp_path):
    # seal_and_rotate's atomic-replace closes the NEW-log interloper race, but a process holding a
    # stale fd on the OLD inode can still append to it after the terminal "sealed" entry (the inode
    # lives on as the archive). A sealed ledger must have the seal as its LAST entry — verify() flags
    # anything chained after it (detection is the PROVE guarantee).
    log = str(tmp_path / "audit.log")
    AuditLedger(log).record("legacy", target="t1")  # unkeyed
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        open_ledger(_svc_cfg(tmp_path))  # seals + archives the unkeyed log

    archive = find_rotation_archive(log)
    assert archive
    assert AuditLedger(archive).verify().ok  # a normally-sealed archive (seal is last) verifies clean

    AuditLedger(archive).record("late_write", target="t2")  # stale-fd append AFTER the seal
    v = AuditLedger(archive).verify()
    assert not v.ok and "seal" in (v.reason or "").lower()


# --- Finding: NaN/Inf in detail writes non-RFC8259 JSON (strict external parsers choke) -----------


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_record_rejects_non_finite_detail(tmp_path, bad):
    # Reject NaN/Infinity at write time — they serialize to non-RFC8259 tokens that strict external
    # audit parsers (Go/Rust/jq) can't read. Caught loudly instead of silently corrupting the log.
    led = _ledger(tmp_path)
    with pytest.raises(ValueError, match="finite"):
        led.record("a", target="t1", detail={"v": bad})


def test_record_accepts_finite_floats(tmp_path):
    # Guard: ordinary finite floats (incl. very large) must still record + verify fine.
    led = _ledger(tmp_path)
    led.record("a", target="t1", detail={"v": 1.5, "big": 1e308, "neg": -3.0})
    assert led.verify().ok


# --- Finding (F4): explicit key path silently overrides KEYED=off ---------------------------------


def test_open_ledger_warns_when_keypath_overrides_keyed_off(tmp_path):
    # Setting an explicit key path forces keyed mode even with audit_keyed=False (key path wins) —
    # intentional precedence, but silent. Warn so the operator isn't surprised by an unexpected
    # keyed ledger (and the migration it implies).
    kp = str(tmp_path / "audit.key")
    with pytest.warns(UserWarning, match="key path"):
        led = open_ledger(_svc_cfg(tmp_path, audit_key_path=kp, audit_keyed=False))
    assert led.keyed


# --- Finding: leak gate's CLAUDE.md deny only matches root (startswith) -> nested copies slip -----


def test_leak_gate_strips_nested_claude_md():
    # DENY_PREFIXES uses str.startswith, so "CLAUDE.md" only matches the repo root. A nested
    # docs/CLAUDE.md or src/proximo/CLAUDE.md (internal dev memory) must ALSO be stripped from the
    # public mirror — otherwise it publishes unscanned (deny paths are never leak-scanned).
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
    import release_leak_audit as rla

    kept, stripped = rla.partition_paths(
        ["README.md", "CLAUDE.md", "docs/CLAUDE.md", "src/proximo/CLAUDE.md"]
    )
    assert "README.md" in kept
    for s in ("CLAUDE.md", "docs/CLAUDE.md", "src/proximo/CLAUDE.md"):
        assert s in stripped, f"{s} should be stripped from the public mirror"


# --- Finding: audit-target content injection (systemic, all 347 callsites) ----------------------
#
# _audited / _plan / _record_plan / a2a executor all pass a caller-derived `target` string into
# audit.record() *before* backend validation fires. A hostile caller can inject C0 control chars
# (newline, NUL, TAB, CR) or overlong strings so that, when a strict log-scanner reads the ledger,
# the injected content fragments or spoofs entries. The HMAC chain integrity is NOT broken; this
# is about audit-log legibility and content injection into error-outcome records.
#
# Fix: _sanitize_target() at the record() chokepoint in audit.py. These tests cover:
#   (a) control-char sanitization on the SUCCESS path (recorded by _audited)
#   (b) control-char sanitization on the ERROR/EXCEPTION path (the primary injection vector:
#       validation rejects the call *after* _audited already built the target from the raw arg)
#   (c) over-long target truncation
#   (d) the _plan error path (mutation dry-run raises during planning: another pre-validation write)
# ------------------------------------------------------------------------------------------------


def _wire_server(tmp_path, monkeypatch):
    """Wire proximo.server with a real ledger and a minimal stub backend."""
    import proximo.server as server
    from proximo.audit import AuditLedger
    from proximo.config import ProximoConfig

    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json",
        node="pve",
        token_path="/run/x",
        audit_log_path=log,
        audit_keyed=False,
    )
    led = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))
    return server, led


def _entries(log_path):
    import json
    from pathlib import Path
    return [json.loads(ln) for ln in Path(log_path).read_text().splitlines() if ln.strip()]


def test_audit_target_control_chars_sanitized_on_success_path(tmp_path, monkeypatch):
    """Control chars in target are replaced with '?' in the recorded entry (success path)."""
    server, led = _wire_server(tmp_path, monkeypatch)
    log = str(tmp_path / "audit.log")

    import proximo.server as srv
    # Call _audited directly with a target that contains a newline and NUL.
    srv._audited("test_action", "node/vm\x00id\nINJECTED", lambda: {"ok": True})

    entries = _entries(log)
    assert len(entries) == 1
    assert entries[0]["target"] == "node/vm?id?INJECTED"
    assert entries[0]["outcome"] == "ok"
    # Verify chain integrity is preserved through the sanitized body.
    assert led.verify().ok


def test_audit_target_control_chars_sanitized_on_error_path(tmp_path, monkeypatch):
    """The PRIMARY injection vector: validation raises inside fn(), but _audited has already built
    the raw target. The error-outcome ledger entry must carry the sanitized target, not the raw one."""
    server, led = _wire_server(tmp_path, monkeypatch)
    log = str(tmp_path / "audit.log")

    import proximo.server as srv
    from proximo.backends import ProximoError

    hostile_target = "pbs/config/remote/../../x\nINJECTED_ACTION: pwned"

    def _bad_fn():
        raise ProximoError("validation rejected: path traversal")

    with pytest.raises(ProximoError):
        srv._audited("pbs_remote_get", hostile_target, _bad_fn)

    entries = _entries(log)
    assert len(entries) == 1
    assert entries[0]["outcome"] == "error"
    # The raw newline must NOT appear in the recorded target.
    assert "\n" not in entries[0]["target"]
    # The injection text should appear sanitized (newline replaced with '?').
    assert "INJECTED_ACTION" in entries[0]["target"]
    assert "?" in entries[0]["target"]
    assert led.verify().ok


def test_audit_target_all_c0_control_chars_replaced(tmp_path, monkeypatch):
    """Every C0 control char (U+0000–U+001F) is replaced with '?'; printable chars pass through."""
    from proximo.audit import AuditLedger

    led = AuditLedger(str(tmp_path / "audit.log"))
    # Build a target with a representative set of C0 control chars.
    raw = "a\x00b\x01c\x09d\x0ae\x0df\x1fg"  # NUL, SOH, TAB, LF, CR, US, printable
    entry = led.record("x", target=raw)
    assert entry["target"] == "a?b?c?d?e?f?g"
    # Verify chain integrity holds after sanitization.
    assert led.verify().ok


def test_audit_target_overlong_is_truncated(tmp_path, monkeypatch):
    """A target longer than 512 chars is capped at 512 content chars + '…[truncated]'."""
    from proximo.audit import _AUDIT_TARGET_MAX, AuditLedger

    led = AuditLedger(str(tmp_path / "audit.log"))
    long_target = "x" * (_AUDIT_TARGET_MAX + 100)
    entry = led.record("x", target=long_target)

    recorded = entry["target"]
    assert recorded == "x" * _AUDIT_TARGET_MAX + "…[truncated]"
    assert len(recorded) == _AUDIT_TARGET_MAX + len("…[truncated]")
    assert led.verify().ok


def test_audit_target_overlong_with_injection_truncated_safely(tmp_path, monkeypatch):
    """An overlong target that also contains control chars: sanitize first, then truncate."""
    from proximo.audit import _AUDIT_TARGET_MAX, AuditLedger

    led = AuditLedger(str(tmp_path / "audit.log"))
    # Pad to well over max, with a newline injection buried near the end.
    long_target = "a" * (_AUDIT_TARGET_MAX + 50) + "\nINJECTED"
    entry = led.record("x", target=long_target)

    recorded = entry["target"]
    assert "\n" not in recorded
    assert recorded.endswith("…[truncated]")
    assert len(recorded) == _AUDIT_TARGET_MAX + len("…[truncated]")
    assert led.verify().ok


def test_audit_target_clean_string_passes_through_unchanged(tmp_path, monkeypatch):
    """A normal target (no control chars, under max length) is recorded verbatim."""
    from proximo.audit import AuditLedger

    led = AuditLedger(str(tmp_path / "audit.log"))
    normal = "pbs/config/remote/my-remote"
    entry = led.record("pbs_remote_get", target=normal)
    assert entry["target"] == normal
    assert led.verify().ok


# --- Task 5b: _audited's `outcome` may resolve from the mutation result ------------------------
#
# Some mutations (pve_backup_delete's underlying backup_delete()) only reveal sync-vs-async
# AFTER they run -- a task UPID string means "submitted", a None return means "ok" (already
# finished). Before this change, _audited() bound `outcome` to a plain string at the caller's
# call site, before fn() ran, so the LEDGER's recorded outcome could never reflect that. This
# extends `outcome` to accept a callable `(result) -> str`, resolved only after fn() succeeds.
# String-outcome callers (the other ~360 call sites) must be byte-for-byte unaffected, and a
# raising fn() must still record today's plain "error" outcome without ever invoking the callable.
# -------------------------------------------------------------------------------------------


def test_audited_outcome_callable_resolved_from_result(tmp_path, monkeypatch):
    """A callable `outcome` is invoked with fn()'s return value AFTER fn() succeeds, and its
    resolved string becomes both the ledger's recorded outcome and the mutation envelope's
    "status" -- e.g. None (sync/no-UPID) resolves to "ok", a UPID string resolves to "submitted"."""
    server, led = _wire_server(tmp_path, monkeypatch)
    log = str(tmp_path / "audit.log")
    import proximo.server as srv

    def resolver(result):
        return "ok" if result is None else "submitted"

    out_sync = srv._audited("test_action", "node/x", lambda: None,
                             mutation=True, outcome=resolver)
    assert out_sync["status"] == "ok"
    assert _entries(log)[-1]["outcome"] == "ok"

    out_async = srv._audited("test_action", "node/x", lambda: "UPID:pve:1:0:0:0:task:1:root@pam:",
                              mutation=True, outcome=resolver)
    assert out_async["status"] == "submitted"
    assert _entries(log)[-1]["outcome"] == "submitted"


def test_audited_outcome_string_still_behaves_identically(tmp_path, monkeypatch):
    """Regression guard: a plain string `outcome` (the existing contract, ~360 call sites) is
    unchanged byte-for-byte -- recorded to the ledger and returned as "status" exactly as before."""
    server, led = _wire_server(tmp_path, monkeypatch)
    log = str(tmp_path / "audit.log")
    import proximo.server as srv

    out = srv._audited("test_action", "node/x", lambda: {"ok": True},
                        mutation=True, outcome="submitted")
    assert out["status"] == "submitted"
    assert _entries(log)[-1]["outcome"] == "submitted"


def test_audited_outcome_callable_never_invoked_on_failure(tmp_path, monkeypatch):
    """A raising fn() records the same failure outcome as today ("error"), unconditionally --
    the outcome callable has no result to resolve from and must never be invoked."""
    server, led = _wire_server(tmp_path, monkeypatch)
    log = str(tmp_path / "audit.log")
    import proximo.server as srv

    calls: list[object] = []

    def resolver(result):
        calls.append(result)
        return "should-not-be-recorded"

    def _boom():
        raise ValueError("boom")

    with pytest.raises(ValueError):
        srv._audited("test_action", "node/x", _boom, mutation=True, outcome=resolver)

    assert calls == []
    assert _entries(log)[-1]["outcome"] == "error"


def test_audited_outcome_resolver_failure_still_writes_ledger_entry(tmp_path, monkeypatch):
    """If the outcome RESOLVER raises after fn() succeeded, the mutation is already REAL --
    it must never be trace-free. The failure is recorded to the ledger (outcome
    "error:outcome_resolution_failed", detail carrying the resolver's exception type) and THEN
    the exception propagates, mirroring the taint-marker-failure pattern."""
    server, led = _wire_server(tmp_path, monkeypatch)
    log = str(tmp_path / "audit.log")
    import proximo.server as srv

    ran: list[object] = []

    def _mutation():
        ran.append(1)
        return {"done": True}

    def _bad_resolver(result):
        raise KeyError("resolver bug")

    with pytest.raises(KeyError):
        srv._audited("test_action", "node/x", _mutation, mutation=True, outcome=_bad_resolver)

    assert ran == [1]  # the mutation really executed
    entries = _entries(log)
    # Two entries now: mutations pre-record `executing` before fn() so a process death mid-call
    # is still visible (see audit.in_flight). The resolver-failure entry is the TERMINAL one.
    assert len(entries) == 2
    assert entries[0]["outcome"] == "executing"
    assert entries[-1]["outcome"] == "error:outcome_resolution_failed"
    assert entries[-1]["mutation"] is True
    assert entries[-1]["detail"]["error"] == "KeyError"
    assert entries[0]["detail"]["intent"] == entries[-1]["detail"]["intent"]
    assert led.verify().ok


def test_audited_outcome_resolver_nonstr_return_is_resolution_failure(tmp_path, monkeypatch):
    """A buggy resolver returning a non-str (e.g. None) must not write None into the ledger
    outcome / envelope status -- it takes the same guarded resolution-failure path: the ledger
    entry records "error:outcome_resolution_failed" and the failure propagates."""
    server, led = _wire_server(tmp_path, monkeypatch)
    log = str(tmp_path / "audit.log")
    import proximo.server as srv

    with pytest.raises(TypeError):
        srv._audited("test_action", "node/x", lambda: {"done": True},
                     mutation=True, outcome=lambda result: None)  # type: ignore[arg-type,return-value]

    entries = _entries(log)
    assert len(entries) == 2          # `executing` + terminal (see audit.in_flight)
    assert entries[0]["outcome"] == "executing"
    assert entries[-1]["outcome"] == "error:outcome_resolution_failed"
    assert entries[-1]["mutation"] is True
    assert entries[-1]["detail"]["error"] == "TypeError"
    assert led.verify().ok
