"""A2A perimeter hardening — fail-closed bind + bearer auth + Host (DNS-rebind) allowlist + card decl.

The A2A face is a network control plane over Proxmox. Proximo's thesis is fail-closed / safe-by-default;
these tests pin that the A2A front door obeys it:
  - building a PUBLIC-bound app WITHOUT an auth token is REFUSED (not merely warned)
  - when a token is set: the JSON-RPC control endpoint requires a correct Bearer token, the Host header
    is validated against an allowlist (DNS-rebind defense), and the agent card DECLARES the bearer scheme
  - localhost-default with no token still works for loopback Hosts (dev ergonomics preserved)
  - even in no-token dev mode the Host guard is installed — non-loopback Hosts are rejected (L20)
  - bare IPv6 loopback (::1) is correctly bracketed in the URL passed to build_app so startup does
    not spuriously refuse a token-free loopback bind (L21)

The Host allowlist is enforced in ALL modes (not just when a token is set), so all TestClients
that make HTTP requests must use a loopback base_url.
"""
from __future__ import annotations

import pytest
from a2a.utils.constants import AGENT_CARD_WELL_KNOWN_PATH
from starlette.testclient import TestClient

from proximo import principal, server
from proximo.a2a.app import _require_auth_for_public, build_app
from proximo.a2a.card import build_agent_card
from proximo.audit import AuditLedger
from proximo.webguard import is_public as _is_public  # the shared perimeter is the canon now

PUBLIC_URL = "http://10.1.2.3:41241/"
LOCAL = "http://localhost"  # a Host in the default allowlist
_RPC_BODY = {"jsonrpc": "2.0", "id": "1", "method": "message/send", "params": {}}


# --- fail-closed bind -----------------------------------------------------------------------------

def test_public_bind_without_token_is_refused():
    with pytest.raises(ValueError):
        build_app(PUBLIC_URL)


def test_public_bind_with_token_is_allowed():
    assert build_app(PUBLIC_URL, token="s3cret") is not None


def test_localhost_without_token_still_serves_card():
    # no regression: dev default (loopback, no token) keeps working — loopback Host is allowed
    client = TestClient(build_app(), base_url=LOCAL)
    assert client.get(AGENT_CARD_WELL_KNOWN_PATH).status_code == 200


# An empty/None/whitespace bind host means "bind all interfaces" (0.0.0.0) — the MOST public. It must
# be treated as public so the fail-closed gate refuses it without a token. (Regression: bool("") is
# False made _is_public("") read as non-public, so PROXIMO_A2A_HOST="" slipped the gate unauthenticated.)
@pytest.mark.parametrize("host", ["", "   ", None, "0.0.0.0", "::", "10.1.2.3"])  # noqa: S104 -- testing bind-all IS public
def test_bindall_or_remote_host_is_public(host):
    assert _is_public(host) is True


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_localhost_host_is_not_public(host):
    assert _is_public(host) is False


@pytest.mark.parametrize("host", ["", "   ", None])
def test_empty_bind_host_without_token_is_refused(host):
    with pytest.raises(ValueError):
        _require_auth_for_public(host, None, where="bind host")


# --- bearer auth on the control endpoint ----------------------------------------------------------

def test_rpc_without_bearer_is_401_when_token_set():
    client = TestClient(build_app(token="s3cret"), base_url=LOCAL)
    assert client.post("/", json=_RPC_BODY).status_code == 401


def test_rpc_with_wrong_bearer_is_401():
    client = TestClient(build_app(token="s3cret"), base_url=LOCAL)
    assert client.post("/", headers={"Authorization": "Bearer nope"}, json=_RPC_BODY).status_code == 401


def test_rpc_with_correct_bearer_passes_auth():
    client = TestClient(build_app(token="s3cret"), base_url=LOCAL)
    r = client.post("/", headers={"Authorization": "Bearer s3cret"}, json=_RPC_BODY)
    assert r.status_code != 401


def test_card_stays_open_even_when_token_set():
    client = TestClient(build_app(token="s3cret"), base_url=LOCAL)
    assert client.get(AGENT_CARD_WELL_KNOWN_PATH).status_code == 200


# --- Host allowlist / DNS-rebind protection -------------------------------------------------------

def test_bad_host_rejected_when_token_set():
    # a Host the server doesn't recognise is refused BEFORE auth (DNS-rebind defense)
    client = TestClient(build_app(token="s3cret"), base_url="http://evil.example.com")
    assert client.get(AGENT_CARD_WELL_KNOWN_PATH).status_code == 400


def test_allowed_host_passes_host_check():
    client = TestClient(build_app(token="s3cret"), base_url=LOCAL)
    # localhost is in the default allowlist → host check passes → card served
    assert client.get(AGENT_CARD_WELL_KNOWN_PATH).status_code == 200


def test_loopback_host_accepted_without_token():
    # dev mode (no token): Host guard IS installed; loopback Hosts are accepted
    client = TestClient(build_app(), base_url=LOCAL)
    assert client.get(AGENT_CARD_WELL_KNOWN_PATH).status_code == 200


def test_host_guard_rejects_bad_host_without_token():
    # L20 fix: even in no-token dev mode the Host guard is installed; a non-loopback Host is
    # rejected as DNS-rebind defense (the bind-host guard keeps us on loopback; this is a
    # network-layer defence-in-depth so a same-machine DNS-rebind cannot reach a mutation endpoint).
    client = TestClient(build_app(), base_url="http://evil.example.com")
    assert client.get(AGENT_CARD_WELL_KNOWN_PATH).status_code == 400


def test_custom_allowed_hosts_honored():
    client = TestClient(build_app(token="s3cret", allowed_hosts=["proxmox.lan", "localhost"]),
                        base_url="http://proxmox.lan")
    # proxmox.lan is explicitly allowed → host check passes (then auth applies on the rpc route)
    assert client.get(AGENT_CARD_WELL_KNOWN_PATH).status_code == 200
    assert client.post("/", json=_RPC_BODY).status_code == 401  # host ok, but no bearer


# --- agent card declares the bearer scheme when secured -------------------------------------------

def test_card_declares_bearer_scheme_when_secured():
    card = build_agent_card("http://127.0.0.1:41241/", secured=True)
    assert len(card.security_schemes) >= 1
    scheme = card.security_schemes["bearerAuth"]
    assert scheme.http_auth_security_scheme.scheme.lower() == "bearer"


def test_card_omits_scheme_when_not_secured():
    card = build_agent_card("http://127.0.0.1:41241/")
    assert len(card.security_schemes) == 0


def test_wildcard_allowed_hosts_warns_not_silent():
    # "*" disables the DNS-rebind guard (Starlette allow-any). It's a legitimate behind-a-proxy
    # choice, but it must NOT be silent — warn loudly (matches the MCP CT_ALLOWLIST='*' precedent).
    with pytest.warns(UserWarning, match="(?i)host|rebind"):
        build_app(token="s3cret", allowed_hosts=["*"])


# --- IPv6 loopback startup (L21) -------------------------------------------------------------------

def test_main_ipv6_loopback_starts_without_token(monkeypatch):
    """main() with PROXIMO_A2A_HOST=::1 and no token must start cleanly.

    Before the fix, main() builds 'http://::1:<port>/' — a malformed URL whose urlparse().hostname
    returns None.  None is treated as 'bind-all' (public), so build_app raises ValueError even
    though ::1 is loopback.  The fix brackets bare IPv6 addresses: 'http://[::1]:<port>/' which
    parses hostname='::1' (in _LOCALHOST_ADDRS) → correctly identified as loopback → no token needed.
    """
    import uvicorn  # noqa: PLC0415

    monkeypatch.setattr(uvicorn, "run", lambda *_a, **_kw: None)
    monkeypatch.setenv("PROXIMO_A2A_HOST", "::1")
    monkeypatch.delenv("PROXIMO_A2A_TOKEN_FILE", raising=False)
    monkeypatch.delenv("PROXIMO_A2A_SIGNING_KEY_FILE", raising=False)
    from proximo.a2a.app import main  # noqa: PLC0415
    main()  # before fix: ValueError ("non-localhost"); after fix: delegates to uvicorn.run cleanly


def test_build_app_bracketed_ipv6_loopback_accepted_without_token():
    """build_app() with a properly bracketed IPv6 loopback URL is accepted without a token.

    This is the URL shape that main() produces after the IPv6-bracketing fix (L21).  Confirms that
    urlparse('http://[::1]:41241/').hostname == '::1', which is in _LOCALHOST_ADDRS, so the
    fail-closed guard does not raise even with no token.
    """
    from starlette.applications import Starlette  # noqa: PLC0415

    assert isinstance(build_app("http://[::1]:41241/"), Starlette)


# --- Task 6: main() registers the serving face + records session entries ------------------------
#
# Mirrors test_main_ipv6_loopback_starts_without_token's shape exactly (uvicorn.run monkeypatched to
# a no-op so main() returns without a real bind) plus a `server._svc` swap (same pattern
# tests/test_principal.py's `_wire_ledger` uses) so `_record_session`'s `_ledger()` call lands on a
# tmp ledger instead of the real _instance_ledger() lru_cache.


def _ledger_lines(log_path) -> list[dict]:
    import json  # noqa: PLC0415

    if not log_path.exists():
        return []
    return [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]


def test_a2a_main_records_session_entries_with_face(monkeypatch, tmp_path):
    import uvicorn  # noqa: PLC0415

    from proximo.a2a import app as a2a_app  # noqa: PLC0415

    log = tmp_path / "audit.log"
    ledger = AuditLedger(str(log))
    monkeypatch.setattr(server, "_svc", lambda: (None, None, None, ledger))
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "svc-account")
    monkeypatch.delenv("PROXIMO_CALLER_KEYS_DIR", raising=False)
    monkeypatch.delenv("PROXIMO_A2A_TOKEN_FILE", raising=False)
    monkeypatch.delenv("PROXIMO_A2A_SIGNING_KEY_FILE", raising=False)
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)  # no real bind

    try:
        a2a_app.main()
    finally:
        principal.set_serving_face("stdio")

    lines = _ledger_lines(log)
    starts = [e for e in lines if e["action"] == "session_start"]
    ends = [e for e in lines if e["action"] == "session_end"]
    assert len(starts) == 1 and len(ends) == 1
    assert starts[0]["detail"]["face"] == "a2a"
    assert starts[0]["principal"] == {"id": "svc-account", "via": "spawn", "face": "a2a"}
    assert ends[0]["detail"]["face"] == "a2a"


def test_a2a_main_no_session_entries_when_principal_unconfigured(monkeypatch, tmp_path):
    """Byte-compat gate: an operator who hasn't opted into the principal feature sees NO session
    entries at all — same as before this feature existed."""
    import uvicorn  # noqa: PLC0415

    from proximo.a2a import app as a2a_app  # noqa: PLC0415

    log = tmp_path / "audit.log"
    ledger = AuditLedger(str(log))
    monkeypatch.setattr(server, "_svc", lambda: (None, None, None, ledger))
    monkeypatch.delenv("PROXIMO_PRINCIPAL", raising=False)
    monkeypatch.delenv("PROXIMO_CALLER_KEYS_DIR", raising=False)
    monkeypatch.delenv("PROXIMO_A2A_TOKEN_FILE", raising=False)
    monkeypatch.delenv("PROXIMO_A2A_SIGNING_KEY_FILE", raising=False)
    monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: None)  # no real bind

    try:
        a2a_app.main()
    finally:
        principal.set_serving_face("stdio")

    assert not log.exists()
