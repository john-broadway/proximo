"""Tamper-evidence tests — the PROVE pillar's whole point is that these pass."""

from __future__ import annotations

import json
import os
import re as _re
import stat
import threading
from types import SimpleNamespace

import pytest

from proximo.audit import (
    _KEY_ALG,
    GENESIS_HASH,
    AuditLedger,
    _hash,
    detect_mode,
    find_rotation_archive,
    load_or_create_key,
    looks_like_head,
    open_ledger,
    seal_and_rotate,
    seal_keyed_and_rotate,
)
from proximo.backends import ProximoError

_KEY = bytes(range(32))          # deterministic 32-byte key for tests
_KEY2 = bytes(range(1, 33))      # a different key


def _ledger(tmp_path):
    return AuditLedger(str(tmp_path / "audit.log"))


def test_empty_ledger_verifies(tmp_path):
    v = _ledger(tmp_path).verify()
    assert v.ok and v.entries == 0


def test_chain_links_and_verifies(tmp_path):
    led = _ledger(tmp_path)
    e1 = led.record("a", target="t1")
    e2 = led.record("b", target="t2", mutation=True)
    assert e1["prev_hash"] == GENESIS_HASH
    assert e2["prev_hash"] == e1["entry_hash"]  # chain linkage
    v = led.verify()
    assert v.ok and v.entries == 2
    assert led.head() == e2["entry_hash"]


def test_record_survives_nonstring_entry_hash(tmp_path):
    # a crafted line with a non-string entry_hash must not brick the write path: _hash() does
    # prev_hash.encode("ascii"), so prev MUST stay a str. The crafted line is ignored, not consumed.
    led = _ledger(tmp_path)
    e1 = led.record("a", target="t1")
    with open(led.path, "a", encoding="utf-8") as f:
        f.write('{"entry_hash": 12345}\n')   # non-string entry_hash
    e2 = led.record("b", target="t2")          # must NOT raise
    assert isinstance(e2["prev_hash"], str)
    assert e2["prev_hash"] == e1["entry_hash"]  # chained off the last VALID entry, not the junk line


def test_detects_altered_field(tmp_path):
    led = _ledger(tmp_path)
    led.record("a", target="t1")
    led.record("b", target="t2")
    p = tmp_path / "audit.log"
    lines = p.read_text().splitlines()
    lines[0] = lines[0].replace('"t1"', '"HACKED"')  # tamper the first entry's target
    p.write_text("\n".join(lines) + "\n")
    v = led.verify()
    assert not v.ok
    assert v.broken_at == 1
    assert "altered" in (v.reason or "")


def test_detects_deleted_entry(tmp_path):
    led = _ledger(tmp_path)
    led.record("a", target="t1")
    led.record("b", target="t2")
    led.record("c", target="t3")
    p = tmp_path / "audit.log"
    lines = p.read_text().splitlines()
    del lines[1]  # remove the middle entry
    p.write_text("\n".join(lines) + "\n")
    v = led.verify()
    assert not v.ok
    assert "mismatch" in (v.reason or "")


def test_detects_reorder(tmp_path):
    led = _ledger(tmp_path)
    led.record("a", target="t1")
    led.record("b", target="t2")
    p = tmp_path / "audit.log"
    lines = p.read_text().splitlines()
    lines.reverse()  # swap order
    p.write_text("\n".join(lines) + "\n")
    assert not led.verify().ok


def test_ledger_adds_no_secret_fields(tmp_path):
    e = _ledger(tmp_path).record("x", target="t")
    assert set(e) == {"ts", "action", "target", "mutation", "outcome", "detail", "prev_hash", "entry_hash"}


def test_nondict_line_fails_clean_not_crash(tmp_path):
    # Redteam Finding 2: a valid-JSON-but-not-object line must fail cleanly, not crash verify().
    led = _ledger(tmp_path)
    led.record("a", target="t1")
    p = tmp_path / "audit.log"
    p.write_text(p.read_text() + "123\n")
    v = led.verify()
    assert not v.ok
    assert "non-object" in (v.reason or "")


def test_tail_deletion_caught_only_with_anchor(tmp_path):
    # Redteam Finding 1: a forward walk can't see tail truncation; an off-box head anchor can.
    led = _ledger(tmp_path)
    led.record("a", target="t1")
    led.record("b", target="t2")
    pinned = led.head()
    p = tmp_path / "audit.log"
    lines = p.read_text().splitlines()
    del lines[-1]  # truncate the tail
    p.write_text("\n".join(lines) + "\n")
    assert led.verify().ok  # honest limit: undetectable by the walk alone
    v = led.verify(expected_head=pinned)  # ...but the anchor catches it
    assert not v.ok
    assert "head mismatch" in (v.reason or "")


# --- keyed (HMAC) mode -----------------------------------------------------------------------


def _keyed(tmp_path, key=_KEY):
    return AuditLedger(str(tmp_path / "audit.log"), key=key)


def test_keyed_chain_verifies_with_key(tmp_path):
    led = _keyed(tmp_path)
    e1 = led.record("a", target="t1")
    led.record("b", target="t2", mutation=True)
    assert led.keyed and e1["alg"] == _KEY_ALG
    v = led.verify()
    assert v.ok and v.entries == 2


def test_keyed_chain_fails_with_wrong_key(tmp_path):
    _keyed(tmp_path).record("a", target="t1")
    v = AuditLedger(str(tmp_path / "audit.log"), key=_KEY2).verify()  # holder of a DIFFERENT key
    assert not v.ok and "mismatch" in (v.reason or "")


def test_keyed_chain_fails_without_key(tmp_path):
    _keyed(tmp_path).record("a", target="t1")
    v = AuditLedger(str(tmp_path / "audit.log")).verify()  # no key at all
    assert not v.ok and "keyed" in (v.reason or "")


def test_keyed_detects_altered_field(tmp_path):
    led = _keyed(tmp_path)
    led.record("a", target="t1")
    p = tmp_path / "audit.log"
    lines = p.read_text().splitlines()
    lines[0] = lines[0].replace('"t1"', '"HACKED"')
    p.write_text("\n".join(lines) + "\n")
    v = led.verify()
    assert not v.ok and "altered" in (v.reason or "")


def test_keyed_downgrade_attack_is_caught(tmp_path):
    """THE cardinal property: an attacker WITHOUT the key cannot rewrite a keyed entry as plain
    SHA-256 (strip `alg`, recompute) and pass — the ledger's key is authoritative, not the entry tag."""
    led = _keyed(tmp_path)
    led.record("a", target="t1")
    p = tmp_path / "audit.log"
    entry = json.loads(p.read_text().splitlines()[0])
    body = {k: v for k, v in entry.items() if k not in ("prev_hash", "entry_hash", "alg")}
    body["target"] = "HACKED"  # the forgery
    forged = {**body, "prev_hash": entry["prev_hash"],
              "entry_hash": _hash(body, entry["prev_hash"], None)}  # recomputed UNKEYED (no key)
    p.write_text(json.dumps(forged, separators=(",", ":")) + "\n")
    v = led.verify()  # verified by the legit operator, who holds the key
    assert not v.ok and "downgrade" in (v.reason or "")


def test_keyed_entry_has_alg_and_no_secret_fields(tmp_path):
    e = _keyed(tmp_path).record("x", target="t")
    assert e["alg"] == _KEY_ALG
    assert set(e) == {"ts", "action", "target", "mutation", "outcome", "detail",
                      "prev_hash", "entry_hash", "alg"}


def test_keyed_head_anchor_catches_tail_truncation(tmp_path):
    led = _keyed(tmp_path)
    led.record("a", target="t1")
    led.record("b", target="t2")
    pinned = led.head()
    p = tmp_path / "audit.log"
    lines = p.read_text().splitlines()
    del lines[-1]
    p.write_text("\n".join(lines) + "\n")
    assert led.verify().ok                          # the walk alone can't see a tail truncation
    assert not led.verify(expected_head=pinned).ok  # the off-box anchor does


def test_unkeyed_default_has_no_alg_and_stays_byte_compatible(tmp_path):
    e = _ledger(tmp_path).record("x", target="t")
    assert "alg" not in e and AuditLedger(str(tmp_path / "x")).keyed is False
    assert set(e) == {"ts", "action", "target", "mutation", "outcome", "detail", "prev_hash", "entry_hash"}


def test_load_or_create_key_generates_0600_and_is_idempotent(tmp_path):
    kp = str(tmp_path / "sub" / "audit.key")
    k1 = load_or_create_key(kp)
    assert len(k1) == 32
    assert stat.S_IMODE(os.stat(kp).st_mode) == 0o600
    assert load_or_create_key(kp) == k1  # second call reads the same key, doesn't regenerate


def test_load_or_create_key_rejects_empty(tmp_path):
    kp = tmp_path / "empty.key"
    kp.write_text("")
    with pytest.raises(ValueError, match="empty"):
        load_or_create_key(str(kp))


def test_load_or_create_key_rejects_non_hex(tmp_path):
    kp = tmp_path / "bad.key"
    kp.write_text("zz-not-hex\n")
    with pytest.raises(ValueError, match="hex"):
        load_or_create_key(str(kp))


def test_load_or_create_key_rejects_short_key(tmp_path):
    # Redteam (key-handling): a hand-rolled <32-byte key is weak — fail closed, don't silently accept it.
    kp = tmp_path / "short.key"
    kp.write_text("deadbeef\n")  # 4 bytes
    with pytest.raises(ValueError, match="too short"):
        load_or_create_key(str(kp))


def test_ledger_file_created_owner_only(tmp_path):
    """The ledger holds command/SQL detail — it must be created 0600, not the umask default."""
    log = str(tmp_path / "audit.log")
    AuditLedger(log).record("ct_psql", target="100", detail={"sql": "select 1"})
    assert stat.S_IMODE(os.stat(log).st_mode) == 0o600


def test_ledger_existing_file_keeps_operator_mode(tmp_path):
    """0600 applies at creation only — an operator-loosened existing file is not re-tightened."""
    log = str(tmp_path / "audit.log")
    ledger = AuditLedger(log)
    ledger.record("a", target="t")
    os.chmod(log, 0o644)
    ledger.record("b", target="t")
    assert stat.S_IMODE(os.stat(log).st_mode) == 0o644


# --- detect_mode inspector -----------------------------------------------------------------------


def test_detect_mode_empty_for_absent(tmp_path):
    assert detect_mode(str(tmp_path / "nope.log")) == "empty"


def test_detect_mode_unkeyed(tmp_path):
    _ledger(tmp_path).record("a", target="t1")
    assert detect_mode(str(tmp_path / "audit.log")) == "unkeyed"


def test_detect_mode_keyed(tmp_path):
    _keyed(tmp_path).record("a", target="t1")
    assert detect_mode(str(tmp_path / "audit.log")) == "keyed"


def test_detect_mode_empty_for_blank_file(tmp_path):
    p = tmp_path / "audit.log"
    p.write_text("\n\n")
    assert detect_mode(str(p)) == "empty"


# --- seal_and_rotate -----------------------------------------------------------------------


def test_seal_and_rotate_archives_and_starts_keyed(tmp_path):
    log = str(tmp_path / "audit.log")
    old = AuditLedger(log)
    old.record("a", target="t1")
    old.record("b", target="t2")
    pre_head = old.head()

    archive, sealed_head = seal_and_rotate(log, _KEY)

    # archive named with the sealed head's first 8 chars; old chain still verifies UNKEYED
    assert _re.search(r"audit\.log\.unkeyed-\d{8}T\d{6}Z-[0-9a-f]{8}$", archive)
    assert sealed_head[:8] in archive
    assert AuditLedger(archive).verify().ok            # old log intact as an unkeyed chain
    arch_lines = (tmp_path / archive.split("/")[-1]).read_text().splitlines()
    assert json.loads(arch_lines[-1])["action"] == "audit_rotate"   # terminal sealed marker
    assert json.loads(arch_lines[-1])["detail"]["sealed"] is True

    # new keyed log exists, verifies WITH the key, and records the custody seam
    new = AuditLedger(log, key=_KEY)
    assert new.verify().ok and new.keyed
    genesis = json.loads((tmp_path / "audit.log").read_text().splitlines()[0])
    assert genesis["action"] == "audit_rotate"
    assert genesis["detail"]["prev_head"] == sealed_head
    assert genesis["detail"]["prev_log"].startswith("audit.log.unkeyed-")
    assert genesis["alg"] == _KEY_ALG
    assert pre_head != sealed_head   # the terminal entry advanced the old head


def test_seal_and_rotate_is_idempotent_on_keyed(tmp_path):
    log = str(tmp_path / "audit.log")
    AuditLedger(log, key=_KEY).record("a", target="t1")   # already keyed
    archive, _ = seal_and_rotate(log, _KEY)
    assert archive == ""                                   # no-op: nothing to seal
    assert AuditLedger(log, key=_KEY).verify().ok


# --- open_ledger factory -----------------------------------------------------------------------


def _cfg(tmp_path, **kw):
    base = dict(audit_log_path=str(tmp_path / "audit.log"), audit_key_path=None, audit_keyed=True)
    base.update(kw)
    return SimpleNamespace(**base)


def test_open_ledger_keyed_default_for_new_log(tmp_path):
    led = open_ledger(_cfg(tmp_path))
    assert led.keyed
    led.record("a", target="t1")
    assert (tmp_path / "audit.key").exists()          # default key path beside the log
    assert led.verify().ok


def test_open_ledger_opt_out_is_unkeyed(tmp_path):
    led = open_ledger(_cfg(tmp_path, audit_keyed=False))
    assert not led.keyed


def test_open_ledger_explicit_key_path_wins(tmp_path):
    kp = str(tmp_path / "custom.key")
    # explicit key path wins even if the keyed flag is off — and that override now warns (0.7.1)
    with pytest.warns(UserWarning, match="key path takes precedence"):
        led = open_ledger(_cfg(tmp_path, audit_key_path=kp, audit_keyed=False))
    led.record("a", target="t1")
    assert led.keyed and (tmp_path / "custom.key").exists()


def test_open_ledger_rotates_existing_unkeyed_log(tmp_path):
    log = str(tmp_path / "audit.log")
    AuditLedger(log).record("legacy", target="t1")    # pre-existing unkeyed ledger
    led = open_ledger(_cfg(tmp_path))
    assert led.keyed and led.verify().ok
    archives = list(tmp_path.glob("audit.log.unkeyed-*"))
    assert len(archives) == 1                          # old log archived, not lost
    assert AuditLedger(str(archives[0])).verify().ok   # ...and still verifiable unkeyed


def test_open_ledger_keeps_existing_keyed_log(tmp_path):
    kp = str(tmp_path / "audit.key")
    key = load_or_create_key(kp)
    AuditLedger(str(tmp_path / "audit.log"), key=key).record("a", target="t1")
    led = open_ledger(_cfg(tmp_path))
    assert led.keyed and led.verify().ok
    assert not list(tmp_path.glob("audit.log.unkeyed-*"))   # no rotation of an already-keyed log


def test_open_ledger_fail_closed_on_keygen_error(tmp_path, monkeypatch):
    import proximo.audit as audit_mod
    def _boom(_p):
        raise OSError("read-only fs")
    monkeypatch.setattr(audit_mod, "load_or_create_key", _boom)
    with pytest.raises(RuntimeError, match="PROXIMO_AUDIT_KEYED=off"):
        open_ledger(_cfg(tmp_path))


# --- keyed→unkeyed migration (finding: L17 silent chain corruption) ---------------------------------


def test_open_ledger_warns_and_archives_existing_keyed_log_on_downgrade(tmp_path):
    """Keyed→unkeyed: open_ledger must warn, archive the keyed chain, and start a fresh unkeyed log.

    Without this fix, open_ledger silently returns AuditLedger(log) (unkeyed), which appends
    bare-SHA-256 entries onto the HMAC chain, making verify() return False forever with no
    operator-readable migration guidance.
    """
    log = str(tmp_path / "audit.log")
    key = load_or_create_key(str(tmp_path / "audit.key"))
    AuditLedger(log, key=key).record("keyed-entry", target="t1")
    old_head = AuditLedger(log, key=key).head()

    with pytest.warns(UserWarning, match="DOWNGRADED") as caught:
        led = open_ledger(_cfg(tmp_path, audit_keyed=False))

    assert not led.keyed                                        # new ledger is unkeyed
    assert led.verify().ok                                      # clean unkeyed chain

    archives = list(tmp_path.glob("audit.log.keyed-*"))
    assert len(archives) == 1                                   # keyed log archived, not lost
    # archive still verifies with the original key
    assert AuditLedger(str(archives[0]), key=key).verify().ok
    # custody seam: new genesis records where the keyed log went
    genesis = json.loads((tmp_path / "audit.log").read_text().splitlines()[0])
    assert genesis["action"] == "audit_rotate"
    assert genesis["detail"]["prev_head"] == old_head
    assert genesis["detail"]["prev_alg"] == _KEY_ALG
    # the warning must carry the re-pin guidance an operator with a pinned head needs
    assert "PROXIMO_AUDIT_EXPECTED_HEAD" in str(caught[0].message)


def test_open_ledger_keyed_to_unkeyed_no_silent_chain_corruption(tmp_path):
    """New entries on a downgraded log must NOT corrupt the keyed chain — they go to a fresh log."""
    log = str(tmp_path / "audit.log")
    key = load_or_create_key(str(tmp_path / "audit.key"))
    AuditLedger(log, key=key).record("keyed-entry", target="t1")

    with pytest.warns(UserWarning):
        led = open_ledger(_cfg(tmp_path, audit_keyed=False))

    led.record("new-entry", target="t2")
    assert led.verify().ok      # new unkeyed chain is clean — not a mixed chain that fails verify()


def test_open_ledger_unkeyed_opt_out_on_new_log_no_warning(tmp_path, recwarn):
    """Negative: a fresh log opened with audit_keyed=False must emit no warning and start cleanly."""
    led = open_ledger(_cfg(tmp_path, audit_keyed=False))
    user_warnings = [w for w in recwarn if issubclass(w.category, UserWarning)]
    assert len(user_warnings) == 0   # no spurious downgrade warning on a brand-new log
    assert not led.keyed


def test_open_ledger_unkeyed_opt_out_on_existing_unkeyed_log_no_warning(tmp_path, recwarn):
    """Negative: re-opening an existing UNKEYED log with audit_keyed=False must emit no warning."""
    log = str(tmp_path / "audit.log")
    AuditLedger(log).record("a", target="t1")   # pre-existing unkeyed log

    led = open_ledger(_cfg(tmp_path, audit_keyed=False))
    user_warnings = [w for w in recwarn if issubclass(w.category, UserWarning)]
    assert len(user_warnings) == 0   # detect_mode "unkeyed" → no keyed→unkeyed branch fired
    assert not led.keyed
    assert not list(tmp_path.glob("audit.log.keyed-*"))   # no archive for a plain unkeyed log


# --- seal_keyed_and_rotate (mirrors seal_and_rotate for the reverse direction) -------------------


def test_seal_keyed_and_rotate_archives_and_starts_unkeyed(tmp_path):
    log = str(tmp_path / "audit.log")
    key = load_or_create_key(str(tmp_path / "audit.key"))
    led = AuditLedger(log, key=key)
    led.record("a", target="t1")
    led.record("b", target="t2")
    old_head = led.head()

    archive, sealed_head = seal_keyed_and_rotate(log)

    assert sealed_head == old_head
    assert _re.search(r"audit\.log\.keyed-\d{8}T\d{6}Z-[0-9a-f]{8}$", archive)
    assert sealed_head[:8] in archive

    # archive verifies with the original key
    assert AuditLedger(archive, key=key).verify().ok

    # new log is unkeyed and verifies cleanly
    new = AuditLedger(log)
    assert new.verify().ok and not new.keyed

    # custody seam in the new genesis
    genesis = json.loads((tmp_path / "audit.log").read_text().splitlines()[0])
    assert genesis["action"] == "audit_rotate"
    assert genesis["detail"]["prev_head"] == old_head
    assert genesis["detail"]["prev_alg"] == _KEY_ALG
    assert "keyed-to-unkeyed" in genesis["detail"]["reason"]


def test_seal_keyed_and_rotate_is_idempotent_on_unkeyed(tmp_path):
    log = str(tmp_path / "audit.log")
    AuditLedger(log).record("a", target="t1")   # already unkeyed
    archive, _ = seal_keyed_and_rotate(log)
    assert archive == ""                         # no-op: nothing to archive
    assert AuditLedger(log).verify().ok


def test_find_rotation_archive_finds_keyed_archives(tmp_path):
    """find_rotation_archive should surface keyed archives as well as unkeyed ones."""
    log = str(tmp_path / "audit.log")
    key = load_or_create_key(str(tmp_path / "audit.key"))
    AuditLedger(log, key=key).record("a", target="t1")
    seal_keyed_and_rotate(log)
    # The .keyed-* archive should be discoverable so stale-pin holders know why the head changed.
    assert find_rotation_archive(log) is not None


def test_svc_builds_keyed_ledger_by_default(tmp_path, monkeypatch):
    import proximo.server as server
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/run/x")
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    server._svc.cache_clear()
    try:
        _, _, _, audit = server._svc()
        assert audit.keyed   # keyed by default through the real factory path
    finally:
        server._svc.cache_clear()


# --- server.audit_verify() tool wiring tests -----------------------------------------------------------------------


def _wire_audit(tmp_path, monkeypatch, *, cfg_head=None, key=None):
    import proximo.server as server
    led = AuditLedger(str(tmp_path / "audit.log"), key=key)
    cfg = SimpleNamespace(expected_head=cfg_head)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))
    return server, led


def test_audit_verify_pins_param_match(tmp_path, monkeypatch):
    server, led = _wire_audit(tmp_path, monkeypatch)
    led.record("a", target="t1")
    out = server.audit_verify(expected_head=led.head())
    assert out["ok"] and out["expected_head"] == led.head() and out["head"] == led.head()


def test_audit_verify_pins_param_mismatch_catches_truncation(tmp_path, monkeypatch):
    server, led = _wire_audit(tmp_path, monkeypatch)
    led.record("a", target="t1")
    led.record("b", target="t2")
    pinned = led.head()
    p = tmp_path / "audit.log"
    p.write_text("\n".join(p.read_text().splitlines()[:-1]) + "\n")  # truncate tail
    out = server.audit_verify(expected_head=pinned)
    assert not out["ok"] and "head mismatch" in out["reason"]
    assert out["expected_head"] == pinned and out["head"] != pinned


def test_audit_verify_falls_back_to_config_default(tmp_path, monkeypatch):
    server, led = _wire_audit(tmp_path, monkeypatch, cfg_head="f" * 64)
    led.record("a", target="t1")
    out = server.audit_verify()                 # no param -> uses cfg.expected_head
    assert not out["ok"] and out["expected_head"] == "f" * 64


def test_audit_verify_unpinned_shows_null(tmp_path, monkeypatch):
    server, led = _wire_audit(tmp_path, monkeypatch)
    led.record("a", target="t1")
    out = server.audit_verify()
    assert out["ok"] and out["expected_head"] is None   # legibly unprotected against tail attacks


# --- migration warning + head-advancement interaction ---------------------------------------------------


def test_open_ledger_migration_warns_and_advances_head(tmp_path):
    log = str(tmp_path / "audit.log")
    AuditLedger(log).record("legacy", target="t1")  # pre-existing unkeyed ledger
    old_head = AuditLedger(log).head()
    with pytest.warns(UserWarning, match="upgraded to keyed mode"):
        led = open_ledger(_cfg(tmp_path))
    new_head = led.head()
    assert new_head != old_head                                   # rotation advanced the head
    assert list(tmp_path.glob("audit.log.unkeyed-*"))             # archived, not lost
    # the known interaction: a stale pin (the pre-migration head) now reads as a head mismatch
    v = led.verify(expected_head=old_head)
    assert not v.ok and "head mismatch" in (v.reason or "")


# --- expected_head shape validation: a typo'd pin is a caller error, not a tamper alarm ----------


def test_looks_like_head_accepts_64_lowercase_hex():
    assert looks_like_head("a" * 64)
    assert looks_like_head(GENESIS_HASH)  # the all-zeros genesis is a valid head shape


def test_looks_like_head_rejects_malformed():
    assert not looks_like_head("xyz")          # too short / nonsense
    assert not looks_like_head("A" * 64)       # uppercase is not a hexdigest shape
    assert not looks_like_head("a" * 63)       # one char short
    assert not looks_like_head("a" * 65)       # one char long
    assert not looks_like_head("g" * 64)       # non-hex character


def test_audit_verify_malformed_pin_raises_not_tamper_alarm(tmp_path, monkeypatch):
    # A fat-fingered pin must raise a CLEAR caller error — never masquerade as a
    # "head mismatch" tamper alarm (crying wolf on a security signal).
    server, led = _wire_audit(tmp_path, monkeypatch)
    led.record("a", target="t1")
    with pytest.raises(ProximoError, match="invalid expected_head"):
        server.audit_verify(expected_head="not-a-real-head")


def test_audit_verify_unpinned_emits_discoverability_hint(tmp_path, monkeypatch):
    # Unpinned = unprotected against tail attacks; the response nudges the operator to pin (legible).
    server, led = _wire_audit(tmp_path, monkeypatch)
    led.record("a", target="t1")
    out = server.audit_verify()
    assert out["hint"] is not None
    assert "PROXIMO_AUDIT_EXPECTED_HEAD" in out["hint"]


def test_audit_verify_pinned_has_no_hint(tmp_path, monkeypatch):
    # A pinned verify is already protected — no nudge.
    server, led = _wire_audit(tmp_path, monkeypatch)
    led.record("a", target="t1")
    out = server.audit_verify(expected_head=led.head())
    assert out["hint"] is None


# --- multi-target: the `remote` field (which box an op hit) ---

def test_record_targeted_includes_remote(tmp_path):
    led = _ledger(tmp_path)
    entry = led.record("pve_guest_power", target="131", mutation=True, remote="edge")
    assert entry["remote"] == "edge"
    assert led.verify().ok


def test_record_default_omits_remote_unchanged_body(tmp_path):
    led = _ledger(tmp_path)
    entry = led.record("pve_guest_power", target="131", mutation=True)  # no remote
    assert "remote" not in entry
    assert led.verify().ok


def test_mixed_remote_and_default_entries_verify(tmp_path):
    led = _ledger(tmp_path)
    led.record("a", target="1")                    # default box
    led.record("b", target="2", remote="edge")     # targeted
    led.record("c", target="3")                    # default box
    assert led.verify().ok


# --- symlink containment: a co-located writer must not redirect ledger/lock opens --------------
#
# Mirrors test_envelope.py's `test_symlinked_lock_refused_not_followed` (Fix 6): the ledger and its
# rotation sidecar-locks must open with O_NOFOLLOW so a planted symlink at the ledger/lock path is
# refused (OSError, ELOOP) rather than silently followed into an arbitrary target the service can
# write — a containment escape on the flagship tamper-evident PROVE pillar.


def test_record_refuses_symlinked_ledger_path(tmp_path):
    """A symlink planted AT the ledger path itself must not have appends redirected through it."""
    log = tmp_path / "audit.log"
    evil_target = tmp_path / "evil-target"
    log.symlink_to(evil_target)

    led = AuditLedger(str(log))
    with pytest.raises(OSError):
        led.record("a", target="t1")
    assert not evil_target.exists()  # never followed/created through the symlink


def test_seal_and_rotate_refuses_symlinked_lock_file(tmp_path):
    """seal_and_rotate's sidecar `<log>.lock` open must reject a symlinked lock path."""
    log = tmp_path / "audit.log"
    AuditLedger(str(log)).record("a", target="t1")  # a real unkeyed log to rotate
    lock_path = tmp_path / "audit.log.lock"
    evil_target = tmp_path / "evil-target"
    lock_path.symlink_to(evil_target)

    with pytest.raises(OSError):
        seal_and_rotate(str(log), _KEY)
    assert not evil_target.exists()  # never followed/created through the symlink
    # the log itself must be untouched — no rotation happened through the refused lock
    assert AuditLedger(str(log)).verify().ok
    assert not list(tmp_path.glob("audit.log.unkeyed-*"))


def test_seal_keyed_and_rotate_refuses_symlinked_lock_file(tmp_path):
    """seal_keyed_and_rotate's sidecar `<log>.lock` open must reject a symlinked lock path."""
    log = tmp_path / "audit.log"
    key = load_or_create_key(str(tmp_path / "audit.key"))
    AuditLedger(str(log), key=key).record("a", target="t1")  # a real keyed log to rotate
    lock_path = tmp_path / "audit.log.lock"
    evil_target = tmp_path / "evil-target"
    lock_path.symlink_to(evil_target)

    with pytest.raises(OSError):
        seal_keyed_and_rotate(str(log))
    assert not evil_target.exists()  # never followed/created through the symlink
    assert AuditLedger(str(log), key=key).verify().ok
    assert not list(tmp_path.glob("audit.log.keyed-*"))


def test_ledger_refuses_symlinked_directory(tmp_path):
    """A symlinked ledger PARENT dir redirects every append onto an attacker-chosen path — the
    per-file O_NOFOLLOW can't catch a symlinked parent, so AuditLedger must refuse at construction."""
    evil = tmp_path / "evil"
    evil.mkdir()
    link_dir = tmp_path / "ledgerdir"
    link_dir.symlink_to(evil)  # a symlink whose target is a real dir

    with pytest.raises(OSError):
        AuditLedger(str(link_dir / "audit.log"))
    assert not (evil / "audit.log").exists()  # nothing created through the symlinked dir


def test_load_or_create_key_refuses_symlinked_directory(tmp_path):
    """load_or_create_key's key dir gets the same guard — a symlinked key dir could redirect the
    HMAC key (and its atomic-link publish) onto an attacker path."""
    evil = tmp_path / "evil"
    evil.mkdir()
    link_dir = tmp_path / "keydir"
    link_dir.symlink_to(evil)

    with pytest.raises(OSError):
        load_or_create_key(str(link_dir / "audit.key"))
    assert not (evil / "audit.key").exists()  # key never created through the symlinked dir


def test_record_refuses_directory_swapped_to_symlink_after_construction(tmp_path):
    """The symlinked-directory guard must re-run on every record(), not just at construction — a
    co-located writer that replaces the ledger's PARENT directory with a symlink AFTER the ledger
    object is already open (a long-lived process, e.g. the server's lru_cache'd instance ledger)
    must not have subsequent appends silently redirected onto the attacker-chosen target."""
    real_dir = tmp_path / "ledgerdir"
    real_dir.mkdir()
    log = real_dir / "audit.log"

    led = AuditLedger(str(log))
    led.record("a", target="t1")  # succeeds — real directory, nothing suspicious yet

    evil = tmp_path / "evil"
    evil.mkdir()
    real_dir.rename(tmp_path / "ledgerdir-orig")  # move the real (already-written) dir aside
    real_dir.symlink_to(evil)  # same path the open AuditLedger still points at, now a symlink

    with pytest.raises(OSError):
        led.record("a", target="t2")
    assert not (evil / "audit.log").exists()  # never written through the swapped-in symlink


def test_head_refuses_directory_swapped_to_symlink_after_construction(tmp_path):
    """head() must re-check the symlink guard too — a forged chain planted at a redirected path
    must not be read back as if it were the legitimate ledger."""
    real_dir = tmp_path / "ledgerdir"
    real_dir.mkdir()
    log = real_dir / "audit.log"

    led = AuditLedger(str(log))
    led.record("a", target="t1")

    evil = tmp_path / "evil"
    evil.mkdir()
    real_dir.rename(tmp_path / "ledgerdir-orig")
    real_dir.symlink_to(evil)

    with pytest.raises(OSError):
        led.head()


def test_verify_refuses_directory_swapped_to_symlink_after_construction(tmp_path):
    """verify() must re-check the symlink guard too — audit_verify() reporting 'ok: true' over a
    forged chain reached through a redirected directory would defeat PROVE silently."""
    real_dir = tmp_path / "ledgerdir"
    real_dir.mkdir()
    log = real_dir / "audit.log"

    led = AuditLedger(str(log))
    led.record("a", target="t1")

    evil = tmp_path / "evil"
    evil.mkdir()
    real_dir.rename(tmp_path / "ledgerdir-orig")
    real_dir.symlink_to(evil)

    with pytest.raises(OSError):
        led.verify()


# --- concurrency: real threads, real fcntl.flock, no mocking -----------------------------------
#
# Mirrors test_envelope.py's `test_rate_concurrency_barrier` pattern: real threading.Barrier so
# every thread genuinely races into record() at the same instant, real flock serialization (no
# mocked locks), proving the read-prev + append critical section is atomic under concurrency.


def test_concurrent_appends_serialize_no_gaps_no_dupes(tmp_path):
    """N threads call record() on the SAME ledger simultaneously. flock around the read-prev +
    append critical section must fully serialize them: every thread's append must land, no two
    entries may share a prev_hash (a gap/interleave), no entry_hash may repeat (a dupe), the
    resulting file must contain exactly N lines forming one unbroken chain from GENESIS, and
    verify() must pass afterward."""
    led = _ledger(tmp_path)
    n = 40
    barrier = threading.Barrier(n)
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def worker(i: int) -> None:
        barrier.wait()
        try:
            led.record("concurrent", target=f"t{i}")
        except BaseException as e:  # noqa: BLE001 - surface ANY escaping exception as a test failure
            with errors_lock:
                errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []  # no thread's record() call raised

    lines = [json.loads(ln) for ln in (tmp_path / "audit.log").read_text().splitlines() if ln.strip()]
    assert len(lines) == n  # no dropped append, no extra/duplicated line

    entry_hashes = [e["entry_hash"] for e in lines]
    assert len(set(entry_hashes)) == n  # no duplicate entry_hash (no clobbered/duplicated append)

    targets_seen = {e["target"] for e in lines}
    assert targets_seen == {f"t{i}" for i in range(n)}  # every thread's own entry actually landed

    prev_hashes = [e["prev_hash"] for e in lines]
    assert prev_hashes[0] == GENESIS_HASH
    assert prev_hashes[1:] == entry_hashes[:-1]  # each entry chains off the immediately-prior one

    v = led.verify()
    assert v.ok and v.entries == n  # the hash chain is fully valid end-to-end


def test_concurrent_appends_keyed_serialize_and_verify(tmp_path):
    """Same concurrency proof, keyed (HMAC) mode — the more security-relevant path in practice
    since PROXIMO_AUDIT_KEYED defaults on."""
    led = _keyed(tmp_path)
    n = 30
    barrier = threading.Barrier(n)
    errors: list[BaseException] = []
    errors_lock = threading.Lock()

    def worker(i: int) -> None:
        barrier.wait()
        try:
            led.record("concurrent", target=f"t{i}", mutation=True)
        except BaseException as e:  # noqa: BLE001
            with errors_lock:
                errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    v = led.verify()
    assert v.ok and v.entries == n

    lines = [json.loads(ln) for ln in (tmp_path / "audit.log").read_text().splitlines() if ln.strip()]
    assert len(lines) == n
    assert all(e["alg"] == _KEY_ALG for e in lines)
    entry_hashes = [e["entry_hash"] for e in lines]
    assert len(set(entry_hashes)) == n
    prev_hashes = [e["prev_hash"] for e in lines]
    assert prev_hashes[0] == GENESIS_HASH
    assert prev_hashes[1:] == entry_hashes[:-1]


def test_audit_verify_works_on_a_box_with_no_pve_env(monkeypatch, tmp_path):
    """audit_verify verifies a LOCAL file — the PROVE pillar must stand on a PBS-only or
    zero-config box (arena find, 2026-07-30: raw RuntimeError traceback on first contact,
    the same defect class 741211b fixed for recall/wiki/baseline). Real _svc on purpose:
    _wire_audit above mocks it, which is why this path was never exercised."""
    import proximo.server as server

    for var in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH",
                "PROXIMO_TARGETS", "PROXIMO_AUDIT_EXPECTED_HEAD"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("PROXIMO_LEDGER_REDACT", "1")
    server._svc_cache_clear()
    try:
        led = server._instance_ledger()
        led.record("a", target="t1")
        out = server.audit_verify()
        assert out["ok"] and out["head"] == led.head()
    finally:
        server._svc_cache_clear()


def test_record_principal_present_and_verifies(tmp_path):
    led = _ledger(tmp_path)
    e = led.record("pve_version", target="cluster", mutation=False,
                   principal={"id": "fleet-7", "via": "verified", "face": "http"})
    assert e["principal"] == {"id": "fleet-7", "via": "verified", "face": "http"}
    assert led.verify().ok


def test_record_no_principal_body_byte_identical(tmp_path):
    """The compat guarantee: principal=None leaves the raw line without the key at all."""
    led = _ledger(tmp_path)
    led.record("pve_version", target="cluster")
    raw = (tmp_path / "audit.log").read_text()
    assert '"principal"' not in raw
    assert led.verify().ok


def test_record_principal_tamper_detected(tmp_path):
    p = tmp_path / "audit.log"
    led = _ledger(tmp_path)
    led.record("pve_version", target="cluster",
               principal={"id": "fleet-7", "via": "verified", "face": "http"})
    tampered = p.read_text().replace('"fleet-7"', '"mallory"')
    p.write_text(tampered)
    assert not AuditLedger(str(p)).verify().ok


def test_audit_verify_does_not_publish_anchor_when_verify_fails(tmp_path, monkeypatch):
    """L4: audit_verify() published to the off-box anchor with entries=v.entries even when the
    just-computed verify FAILED — overwriting the anchor's good entry count with a count sourced
    from a tampered ledger. An interior-body tamper leaves the tail head unchanged, so the old
    head-equality gate still fired. Pin that a failed verify leaves the anchor intact."""
    import proximo.server as server
    from proximo.audit_anchor import FileSink

    led = AuditLedger(str(tmp_path / "audit.log"))
    led.record("a", target="t1")
    led.record("b", target="t2")
    led.record("c", target="t3")
    good_head = led.head()
    good_entries = led.verify().entries
    assert good_entries == 3

    sink = FileSink(str(tmp_path / "anchor.json"))
    sink.publish(good_head, "t0", "pve", led.path, entries=good_entries)  # pin the GOOD count

    cfg = SimpleNamespace(expected_head=None, node="pve", anchor_sink=sink)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))

    # Tamper an INTERIOR line's body; leave every entry_hash (incl. the tail) intact so head()
    # is unchanged and the old head-equality publish gate would fire.
    p = tmp_path / "audit.log"
    lines = p.read_text().splitlines()
    obj = json.loads(lines[0])
    obj["action"] = "TAMPERED"
    lines[0] = json.dumps(obj)
    p.write_text("\n".join(lines) + "\n")

    out = server.audit_verify()
    assert not out["ok"]                                  # tamper detected
    assert AuditLedger(str(p)).head() == good_head        # tail head genuinely unchanged
    assert sink.last_pin()["entries"] == good_entries     # anchor NOT overwritten by tampered count


def test_audit_verify_first_anchor_run_with_failed_verify_does_not_crash(tmp_path, monkeypatch):
    """The v.ok publish guard must not crash on a FIRST anchor run (no prior pin, prev=None) whose
    verify FAILED: the else branch reads prev.get(...) and would AttributeError on None."""
    import proximo.server as server
    from proximo.audit_anchor import FileSink

    led = AuditLedger(str(tmp_path / "audit.log"))
    led.record("a", target="t1")
    led.record("b", target="t2")
    # Tamper an interior line so verify fails; the anchor sink is EMPTY (first run -> prev None).
    p = tmp_path / "audit.log"
    lines = p.read_text().splitlines()
    obj = json.loads(lines[0])
    obj["action"] = "TAMPERED"
    lines[0] = json.dumps(obj)
    p.write_text("\n".join(lines) + "\n")

    sink = FileSink(str(tmp_path / "anchor.json"))  # never published -> last_pin() is None
    cfg = SimpleNamespace(expected_head=None, node="pve", anchor_sink=sink)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))

    out = server.audit_verify()          # must return, not raise
    assert out["ok"] is False
    assert sink.last_pin() is None       # nothing published off the tampered first-run ledger
