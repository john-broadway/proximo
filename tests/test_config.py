"""Config tests — Proximo ships with tests from day one (the 'solid' principle)."""

import pytest

from proximo.config import ProximoConfig


def _cfg(**kw) -> ProximoConfig:
    base = dict(api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x")
    base.update(kw)
    return ProximoConfig(**base)


def test_allowlist_empty_denies_all():
    # Fail-closed: an unconfigured allowlist permits nothing.
    assert not _cfg().ct_permitted("999")


def test_allowlist_star_permits_all():
    assert _cfg(ct_allowlist=frozenset({"*"})).ct_permitted("12345")


def test_allowlist_gates_to_listed_ctids():
    c = _cfg(ct_allowlist=frozenset({"100"}))
    assert c.ct_permitted("100")
    assert not c.ct_permitted("200")


def test_is_local_detection():
    assert _cfg(ssh_target="local").is_local
    assert _cfg(ssh_target="").is_local
    assert not _cfg(ssh_target="pve").is_local


def test_from_env_fails_loud_when_core_missing(monkeypatch):
    for v in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(RuntimeError):
        ProximoConfig.from_env()


def test_from_env_reports_all_missing_vars_in_one_message(monkeypatch):
    # verdict 1.15: from_env() used to do three sequential os.environ subscripts inside one
    # try, so only the FIRST missing var was ever reported per call -- an operator fixed one,
    # reran, hit the next, three cycles. All three missing required vars must be collected and
    # named in ONE RuntimeError, with the same "Missing required Proximo env var" prefix
    # existing callers match on (server.py's broad `except RuntimeError` doesn't string-match,
    # but keep the phrase anyway since it's the honest description of what happened).
    for v in ("PROXIMO_API_BASE_URL", "PROXIMO_NODE", "PROXIMO_TOKEN_PATH"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(RuntimeError, match="Missing required Proximo env var") as exc_info:
        ProximoConfig.from_env()
    msg = str(exc_info.value)
    assert "PROXIMO_API_BASE_URL" in msg, msg
    assert "PROXIMO_NODE" in msg, msg
    assert "PROXIMO_TOKEN_PATH" in msg, msg


def test_from_env_reports_only_the_actually_missing_vars(monkeypatch):
    # A partially-configured box must name only what's missing, not the whole triple.
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.delenv("PROXIMO_NODE", raising=False)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/run/x")
    with pytest.raises(RuntimeError, match="Missing required Proximo env var") as exc_info:
        ProximoConfig.from_env()
    msg = str(exc_info.value)
    assert "PROXIMO_NODE" in msg, msg
    assert "PROXIMO_API_BASE_URL" not in msg, msg
    assert "PROXIMO_TOKEN_PATH" not in msg, msg


def test_from_env_single_missing_var_message_unchanged_shape(monkeypatch):
    # Single-missing case keeps the exact historical message shape (name after the colon),
    # so any existing narrow catcher is unaffected.
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.delenv("PROXIMO_TOKEN_PATH", raising=False)
    with pytest.raises(RuntimeError, match=r"Missing required Proximo env var: PROXIMO_TOKEN_PATH$"):
        ProximoConfig.from_env()


def test_exec_is_off_by_default():
    # API-only is the safe default; in-container exec must be explicitly enabled.
    assert _cfg().enable_exec is False


def test_from_env_parses_enable_exec(monkeypatch):
    import warnings

    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/run/x")
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cfg = ProximoConfig.from_env()
    assert cfg.enable_exec is True


def test_verify_tls_defaults_to_true_when_unset(monkeypatch):
    # Fail-closed: TLS verification is ON unless explicitly disabled. (Guards against a silent flip.)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/run/x")
    monkeypatch.delenv("PROXIMO_VERIFY_TLS", raising=False)
    cfg = ProximoConfig.from_env()
    assert cfg.verify_tls is True


def test_verify_tls_false_without_ca_bundle_warns_loudly(monkeypatch):
    # Disabling verification with no CA bundle must not be silent.
    # The warning accurately reflects the actual outcome: the backend refuses to start.
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/run/x")
    monkeypatch.setenv("PROXIMO_VERIFY_TLS", "false")
    monkeypatch.delenv("PROXIMO_CA_BUNDLE", raising=False)
    with pytest.warns(UserWarning, match="(?i)fail.closed|refuse to start"):
        cfg = ProximoConfig.from_env()
    assert cfg.verify_tls is False


def test_redact_ledger_off_by_default():
    # Audit completeness is the default: ct_psql/ct_exec record the body unless explicitly opted out.
    assert _cfg().redact_ledger is False


def test_from_env_parses_redact_ledger(monkeypatch):
    import warnings

    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/run/x")
    monkeypatch.setenv("PROXIMO_LEDGER_REDACT", "1")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        cfg = ProximoConfig.from_env()
    assert cfg.redact_ledger is True


def _base_env(monkeypatch, **extra):
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/run/x")
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def test_expected_head_defaults_none(monkeypatch):
    _base_env(monkeypatch)
    assert ProximoConfig.from_env().expected_head is None


def test_expected_head_accepts_64_hex(monkeypatch):
    h = "a" * 64
    _base_env(monkeypatch, PROXIMO_AUDIT_EXPECTED_HEAD=h)
    assert ProximoConfig.from_env().expected_head == h


def test_expected_head_rejects_malformed(monkeypatch):
    _base_env(monkeypatch, PROXIMO_AUDIT_EXPECTED_HEAD="not-a-hash")
    with pytest.raises(RuntimeError, match="PROXIMO_AUDIT_EXPECTED_HEAD"):
        ProximoConfig.from_env()


def test_audit_keyed_defaults_true(monkeypatch):
    _base_env(monkeypatch)
    assert ProximoConfig.from_env().audit_keyed is True


def test_audit_keyed_opt_out_off(monkeypatch):
    # F4: disabling keyed HMAC must emit a loud warning (degraded PROVE posture).
    _base_env(monkeypatch, PROXIMO_AUDIT_KEYED="off")
    with pytest.warns(UserWarning, match="(?i)unkeyed|HMAC"):
        assert ProximoConfig.from_env().audit_keyed is False


def test_audit_keyed_opt_out_zero(monkeypatch):
    # F4: same for numeric opt-out form.
    _base_env(monkeypatch, PROXIMO_AUDIT_KEYED="0")
    with pytest.warns(UserWarning, match="(?i)unkeyed|HMAC"):
        assert ProximoConfig.from_env().audit_keyed is False


def test_audit_keyed_on_stays_true(monkeypatch):
    _base_env(monkeypatch, PROXIMO_AUDIT_KEYED="on")
    assert ProximoConfig.from_env().audit_keyed is True


# ---------------------------------------------------------------------------
# F1 — PROXIMO_SSH_TARGET charset validation (option-injection guard)
# ---------------------------------------------------------------------------

def test_ssh_target_accepts_hostname(monkeypatch):
    """Normal SSH alias/hostname must pass validation."""
    _base_env(monkeypatch, PROXIMO_SSH_TARGET="pve.example.com")
    cfg = ProximoConfig.from_env()
    assert cfg.ssh_target == "pve.example.com"


def test_ssh_target_accepts_user_at_host(monkeypatch):
    """user@host form is valid (common SSH pattern)."""
    _base_env(monkeypatch, PROXIMO_SSH_TARGET="admin@pve")
    cfg = ProximoConfig.from_env()
    assert cfg.ssh_target == "admin@pve"


def test_ssh_target_accepts_ipv4(monkeypatch):
    """IPv4 address must pass validation."""
    _base_env(monkeypatch, PROXIMO_SSH_TARGET="192.0.2.1")
    cfg = ProximoConfig.from_env()
    assert cfg.ssh_target == "192.0.2.1"


def test_ssh_target_empty_allowed_for_local_mode(monkeypatch):
    """Empty string is valid — it signals on-host (local) mode via is_local."""
    _base_env(monkeypatch, PROXIMO_SSH_TARGET="")
    cfg = ProximoConfig.from_env()
    assert cfg.ssh_target == ""
    assert cfg.is_local is True


def test_ssh_target_rejects_option_injection(monkeypatch):
    """A dash-prefix injects ssh options — must be rejected at parse time."""
    _base_env(monkeypatch, PROXIMO_SSH_TARGET="-oProxyCommand=evil")
    with pytest.raises(RuntimeError, match="PROXIMO_SSH_TARGET"):
        ProximoConfig.from_env()


def test_ssh_target_rejects_leading_dash(monkeypatch):
    """Any leading dash (not just -o) must be blocked."""
    _base_env(monkeypatch, PROXIMO_SSH_TARGET="-N")
    with pytest.raises(RuntimeError, match="PROXIMO_SSH_TARGET"):
        ProximoConfig.from_env()


def test_ssh_target_rejects_shell_metacharacters(monkeypatch):
    """Shell metacharacters in the target must be blocked."""
    _base_env(monkeypatch, PROXIMO_SSH_TARGET="pve;evil")
    with pytest.raises(RuntimeError, match="PROXIMO_SSH_TARGET"):
        ProximoConfig.from_env()


# ---------------------------------------------------------------------------
# F2 — Agent allowlist wildcard warning gated on enable_agent
# ---------------------------------------------------------------------------

def test_agent_allowlist_star_no_warn_when_agent_disabled(monkeypatch):
    """Wildcard allowlist with agent disabled must not emit a warning (cry-wolf)."""
    import warnings as _w
    _base_env(monkeypatch, PROXIMO_AGENT_ALLOWLIST="*")
    # enable_agent defaults to False; wildcard warning must be silent
    with _w.catch_warnings():
        _w.simplefilter("error", UserWarning)
        # Should not raise even though AGENT_ALLOWLIST=* is set
        try:
            ProximoConfig.from_env()
        except UserWarning as exc:
            if "agent" in str(exc).lower() and "wildcard" in str(exc).lower() or "ALL VMs" in str(exc):
                raise AssertionError(
                    "wildcard warning fired even though enable_agent is False"
                ) from exc


def test_agent_allowlist_star_warns_when_agent_enabled(monkeypatch):
    """Wildcard allowlist must warn when the agent feature is actually enabled."""
    _base_env(monkeypatch, PROXIMO_ENABLE_AGENT="1", PROXIMO_AGENT_ALLOWLIST="*")
    with pytest.warns(UserWarning, match="(?i)ALL VMs|least.privilege"):
        ProximoConfig.from_env()


# ---------------------------------------------------------------------------
# F3 — PROXIMO_VERIFY_TLS truth-by-exclusion: full falsy-set recognition
# ---------------------------------------------------------------------------

def test_verify_tls_zero_recognized_as_off(monkeypatch):
    """PROXIMO_VERIFY_TLS=0 must disable TLS (was silently ignored before)."""
    _base_env(monkeypatch, PROXIMO_VERIFY_TLS="0")
    with pytest.warns(UserWarning, match="(?i)fail.closed|refuse"):
        cfg = ProximoConfig.from_env()
    assert cfg.verify_tls is False


def test_verify_tls_no_recognized_as_off(monkeypatch):
    """PROXIMO_VERIFY_TLS=no must disable TLS."""
    _base_env(monkeypatch, PROXIMO_VERIFY_TLS="no")
    with pytest.warns(UserWarning, match="(?i)fail.closed|refuse"):
        cfg = ProximoConfig.from_env()
    assert cfg.verify_tls is False


def test_verify_tls_off_recognized_as_off(monkeypatch):
    """PROXIMO_VERIFY_TLS=off must disable TLS."""
    _base_env(monkeypatch, PROXIMO_VERIFY_TLS="off")
    with pytest.warns(UserWarning, match="(?i)fail.closed|refuse"):
        cfg = ProximoConfig.from_env()
    assert cfg.verify_tls is False


def test_verify_tls_unrecognized_warns_and_stays_on(monkeypatch):
    """An unrecognized value must emit a diagnostic warning and keep TLS enabled."""
    _base_env(monkeypatch, PROXIMO_VERIFY_TLS="maybe")
    with pytest.warns(UserWarning, match="(?i)not a recognized boolean"):
        cfg = ProximoConfig.from_env()
    assert cfg.verify_tls is True  # safe default: stays ON


# ---------------------------------------------------------------------------
# F4 — PROXIMO_AUDIT_KEYED=off must emit a startup warning
# ---------------------------------------------------------------------------

def test_audit_keyed_off_no_key_path_warns(monkeypatch):
    """Setting PROXIMO_AUDIT_KEYED=no must emit a PROVE-downgrade warning."""
    _base_env(monkeypatch, PROXIMO_AUDIT_KEYED="no")
    with pytest.warns(UserWarning, match="(?i)unkeyed|HMAC"):
        cfg = ProximoConfig.from_env()
    assert cfg.audit_keyed is False


# ---------------------------------------------------------------------------
# F4b — redact_ledger permissive default must warn, like every other
# permissive-by-default security toggle in _build().
# ---------------------------------------------------------------------------

def test_redact_ledger_off_warns_ledger_may_carry_secrets(monkeypatch):
    """PROXIMO_LEDGER_REDACT unset (the default: full command/SQL body recorded) must warn that
    ct_exec/ct_psql/pve_agent_exec write the raw command/SQL — which can carry secrets like a
    password on the argv — into the PROVE ledger."""
    _base_env(monkeypatch)  # PROXIMO_LEDGER_REDACT deliberately not set
    with pytest.warns(UserWarning, match="(?i)ledger_redact|redact_ledger"):
        cfg = ProximoConfig.from_env()
    assert cfg.redact_ledger is False


def test_redact_ledger_on_does_not_warn(monkeypatch):
    """Opting in to redaction must not trigger the permissive-default warning (cry-wolf)."""
    import warnings as _w
    _base_env(monkeypatch, PROXIMO_LEDGER_REDACT="1")
    with _w.catch_warnings(record=True) as caught:
        _w.simplefilter("always")
        cfg = ProximoConfig.from_env()
    redact_warns = [str(w.message) for w in caught
                    if "ledger_redact" in str(w.message).lower()
                    or "redact_ledger" in str(w.message).lower()]
    assert not redact_warns, f"redact-off warning fired even though redact_ledger is on: {redact_warns}"
    assert cfg.redact_ledger is True


# ---------------------------------------------------------------------------
# F5 — from_env() warning accurately describes backend behaviour (fail-closed)
# ---------------------------------------------------------------------------

def test_verify_tls_false_warning_says_fail_closed(monkeypatch):
    """The warning text must say 'fail-closed' / 'refuse to start', not imply running insecurely."""
    import warnings as _w
    _base_env(monkeypatch, PROXIMO_VERIFY_TLS="false")
    with _w.catch_warnings(record=True) as caught:
        _w.simplefilter("always")
        ProximoConfig.from_env()
    tls_warns = [str(w.message) for w in caught
                 if "PROXIMO_VERIFY_TLS" in str(w.message)]
    assert tls_warns, "expected a warning about PROXIMO_VERIFY_TLS=false"
    combined = " ".join(tls_warns).lower()
    assert "fail-closed" in combined or "refuse" in combined, (
        f"warning should say 'fail-closed' or 'refuse to start'; got: {tls_warns}"
    )
    # Must NOT claim the server is already running insecurely — that was the misleading old text
    assert "talking to the pve api without cert validation" not in combined


# --- multi-target: ProximoConfig.from_target ---

def test_from_target_builds_config():
    cfg = ProximoConfig.from_target({
        "kind": "pve",
        "base_url": "https://192.0.2.20:8006/api2/json",
        "node": "edge",
        "token_path": "/etc/proximo/edge.token",
        "ca_bundle": "/etc/proximo/edge-ca.pem",
        "verify_tls": True,
        "ssh_target": "edge-host",
    })
    assert cfg.api_base_url == "https://192.0.2.20:8006/api2/json"
    assert cfg.node == "edge"
    assert cfg.token_path == "/etc/proximo/edge.token"
    assert cfg.ca_bundle == "/etc/proximo/edge-ca.pem"
    assert cfg.ssh_target == "edge-host"


def test_from_target_missing_required_field_raises():
    with pytest.raises(RuntimeError, match="missing required field: node"):
        ProximoConfig.from_target({"kind": "pve",
                                   "base_url": "https://192.0.2.20:8006/api2/json",
                                   "token_path": "/etc/proximo/edge.token"})


def test_from_target_defaults_match_from_env_defaults():
    cfg = ProximoConfig.from_target({
        "kind": "pve", "base_url": "https://192.0.2.20:8006/api2/json",
        "node": "edge", "token_path": "/etc/proximo/edge.token",
    })
    assert cfg.verify_tls is True          # default on
    assert cfg.ssh_target == "pve"         # same default as from_env
    assert cfg.enable_exec is False        # safe default
    assert cfg.api_base_url.endswith("/api2/json")  # rstrip('/') applied


def test_from_env_ledger_needs_no_pve_api_triple(monkeypatch):
    # The instance PROVE ledger must stand up in a pure-targets deployment (no single-target env).
    # from_env_ledger reads only audit_* fields and defaults the API triple to empty — it must NOT
    # raise the "Missing required Proximo env var" that from_env does.
    monkeypatch.delenv("PROXIMO_API_BASE_URL", raising=False)
    monkeypatch.delenv("PROXIMO_NODE", raising=False)
    monkeypatch.delenv("PROXIMO_TOKEN_PATH", raising=False)
    monkeypatch.setenv("PROXIMO_LEDGER_REDACT", "1")
    cfg = ProximoConfig.from_env_ledger()
    assert cfg.api_base_url == "" and cfg.node == "" and cfg.token_path == ""
    assert cfg.redact_ledger is True          # audit_* env still read
    assert cfg.audit_keyed is True            # default preserved


def test_from_env_ledger_matches_from_env_audit_fields(monkeypatch, tmp_path):
    # In single-target mode the ledger config must be identical to the old from_env path for every
    # audit field — routing _instance_ledger through from_env_ledger must not change the ledger.
    _base_env(monkeypatch,
              PROXIMO_LEDGER_REDACT="1", PROXIMO_AUDIT_KEYED="false",
              PROXIMO_AUDIT_LOG=str(tmp_path / "x.log"))
    env, led = ProximoConfig.from_env(), ProximoConfig.from_env_ledger()
    for f in ("audit_log_path", "audit_keyed", "audit_key_path", "redact_ledger", "expected_head"):
        assert getattr(env, f) == getattr(led, f), f"{f} diverges: {getattr(env, f)} != {getattr(led, f)}"


def test_from_target_inherits_env_redact_default(monkeypatch):
    # A targets-mode operator who exports PROXIMO_LEDGER_REDACT=1 expects it to apply. The
    # per-target config (which the exec tools read as cfg.redact_ledger) must INHERIT the env
    # default, not silently drop it. Real multi-target install, 2026-07-06.
    monkeypatch.setenv("PROXIMO_LEDGER_REDACT", "1")
    cfg = ProximoConfig.from_target({
        "kind": "pve", "base_url": "https://192.0.2.20:8006/api2/json",
        "node": "edge", "token_path": "/etc/proximo/edge.token",
    })
    assert cfg.redact_ledger is True


def test_from_target_env_redact_suppresses_warning(monkeypatch):
    # The redact warning must reflect the EFFECTIVE setting — firing it when redaction is
    # actually on (via env) is the one thing a warning can't do (teaches operators to ignore it).
    import warnings as _w
    monkeypatch.setenv("PROXIMO_LEDGER_REDACT", "1")
    with _w.catch_warnings(record=True) as w:
        _w.simplefilter("always")
        ProximoConfig.from_target({
            "kind": "pve", "base_url": "https://192.0.2.20:8006/api2/json",
            "node": "edge", "token_path": "/etc/proximo/edge.token",
        })
    redact = [x for x in w if "redact" in str(x.message).lower()]
    assert not redact, f"redact warning fired despite env PROXIMO_LEDGER_REDACT=1: {redact}"


def test_from_target_explicit_redact_false_overrides_env(monkeypatch):
    # A target may still opt OUT of a redaction the env turned on — explicit block wins.
    monkeypatch.setenv("PROXIMO_LEDGER_REDACT", "1")
    cfg = ProximoConfig.from_target({
        "kind": "pve", "base_url": "https://192.0.2.20:8006/api2/json",
        "node": "edge", "token_path": "/etc/proximo/edge.token",
        "redact_ledger": False,
    })
    assert cfg.redact_ledger is False


def test_from_target_verify_false_no_ca_warns():
    with pytest.warns(UserWarning, match="refuse to"):
        ProximoConfig.from_target({
            "kind": "pve", "base_url": "https://192.0.2.20:8006/api2/json",
            "node": "edge", "token_path": "/etc/proximo/edge.token",
            "verify_tls": False,
        })


def test_from_target_bad_ssh_target_raises():
    with pytest.raises(RuntimeError, match="PROXIMO_SSH_TARGET must be"):
        ProximoConfig.from_target({
            "kind": "pve", "base_url": "https://192.0.2.20:8006/api2/json",
            "node": "edge", "token_path": "/etc/proximo/edge.token",
            "ssh_target": "-oProxyCommand=evil",
        })


def test_from_target_integer_allowlist_does_not_crash():
    # redteam LOW: TOML ct_allowlist = [100, 101] (integers) must not raise TypeError in _csv
    cfg = ProximoConfig.from_target({
        "kind": "pve", "base_url": "https://192.0.2.20:8006/api2/json",
        "node": "edge", "token_path": "/etc/proximo/edge.token",
        "ct_allowlist": [100, 101],
    })
    assert cfg.ct_permitted("100") and cfg.ct_permitted("101")


def test_from_target_verify_tls_falsy_forms():
    # redteam LOW: verify_tls=0/off/no must disable TLS (PVE already does via _VTLS_FALSY)
    for falsy in (0, "0", "off", "no", False, "false"):
        cfg = ProximoConfig.from_target({
            "kind": "pve", "base_url": "https://192.0.2.20:8006/api2/json",
            "node": "edge", "token_path": "/etc/proximo/edge.token",
            "ca_bundle": "/etc/proximo/ca.pem", "verify_tls": falsy,
        })
        assert cfg.verify_tls is False, f"verify_tls={falsy!r} should be False"


# --- Secret-file permission guard (refuse-if-world-readable) ---------------------------------
# The token and the audit HMAC key are secrets referenced by path. Write-side hygiene is
# already 0600 everywhere; this is the READ-side floor: refuse to build a config whose secret
# file is group/other-accessible (mode & 0o077), so a mis-deployed token fails LOUD, not silent.


def _env_triple(monkeypatch, token_path):
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(token_path))


def test_world_readable_token_refused(monkeypatch, tmp_path):
    tok = tmp_path / "pve.token"
    tok.write_text("user@pam!id=secret\n")
    tok.chmod(0o644)
    _env_triple(monkeypatch, tok)
    with pytest.raises(RuntimeError, match="chmod 600"):
        ProximoConfig.from_env()


def test_group_readable_token_refused(monkeypatch, tmp_path):
    tok = tmp_path / "pve.token"
    tok.write_text("user@pam!id=secret\n")
    tok.chmod(0o640)
    _env_triple(monkeypatch, tok)
    with pytest.raises(RuntimeError, match="chmod 600"):
        ProximoConfig.from_env()


def test_owner_only_token_accepted(monkeypatch, tmp_path):
    tok = tmp_path / "pve.token"
    tok.write_text("user@pam!id=secret\n")
    tok.chmod(0o600)
    _env_triple(monkeypatch, tok)
    assert ProximoConfig.from_env().token_path == str(tok)


def test_missing_token_file_skips_perm_guard(monkeypatch, tmp_path):
    # A missing token file already fails loudly at call time (run-but-not-read) —
    # the perm guard must not change that behavior by refusing at config time.
    _env_triple(monkeypatch, tmp_path / "absent.token")
    ProximoConfig.from_env()  # must not raise


def test_world_readable_audit_key_refused(monkeypatch, tmp_path):
    tok = tmp_path / "pve.token"
    tok.write_text("user@pam!id=secret\n")
    tok.chmod(0o600)
    key = tmp_path / "audit.key"
    key.write_text("hmac-key-bytes\n")
    key.chmod(0o644)
    _env_triple(monkeypatch, tok)
    monkeypatch.setenv("PROXIMO_AUDIT_KEY_PATH", str(key))
    with pytest.raises(RuntimeError, match="chmod 600"):
        ProximoConfig.from_env()


def test_from_target_world_readable_token_refused(tmp_path):
    # from_target converges on _build — a registry target gets the identical guard.
    tok = tmp_path / "edge.token"
    tok.write_text("user@pam!id=secret\n")
    tok.chmod(0o644)
    with pytest.raises(RuntimeError, match="chmod 600"):
        ProximoConfig.from_target({
            "kind": "pve", "base_url": "https://192.0.2.20:8006/api2/json",
            "node": "edge", "token_path": str(tok),
        })
