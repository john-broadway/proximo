"""Verdict 1.4 — the PVE tool call seam must not leak a raw httpx/socket connection error.

`pve_list_guests`, `pve_cluster_resources`, `pve_guest_status` — the tools README's "where an
operator actually starts" table — returned "[Errno -2] Name or service not known" verbatim on an
unreachable host, while `proximo doctor` wraps the identical failure honestly with the env vars
to check (`doctor.py`'s reachability `flags` entry). This file proves the gap RED against a
synthetic unreachable host through `pve_list_guests`/`pve_guest_status` (`https://example.invalid`
is RFC 2606's reserved, never-resolves TLD, so this is deterministic without touching a real
network), then pins the fix: `server._audited()` — the one seam every `_svc()`-consuming tool
call already funnels through — catches `httpx.TransportError` and re-raises as `ProximoError`
with the same check-these-env-vars text `doctor`'s flag produces.
"""

from __future__ import annotations

import httpx
import pytest

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.backends import ApiBackend, ProximoError
from proximo.config import ProximoConfig


def _unreachable_cfg(tmp_path) -> ProximoConfig:
    token = tmp_path / "token"
    token.write_text("root@pam!proximo=secret\n")
    token.chmod(0o600)
    return ProximoConfig(
        api_base_url="https://example.invalid",
        node="pve",
        token_path=str(token),
        ct_allowlist=frozenset(),
    )


def _wire(tmp_path, monkeypatch):
    cfg = _unreachable_cfg(tmp_path)
    api = ApiBackend(cfg)
    ledger = AuditLedger(str(tmp_path / "audit.log"))
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, None, ledger))
    return cfg, api, ledger


def test_pve_list_guests_wraps_unreachable_host_as_proximo_error(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)

    with pytest.raises(ProximoError) as exc_info:
        server.pve_list_guests()

    msg = str(exc_info.value)
    assert "PROXIMO_API_BASE_URL" in msg
    assert "PROXIMO_TOKEN_PATH" in msg


def test_pve_guest_status_wraps_unreachable_host_as_proximo_error(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)

    with pytest.raises(ProximoError) as exc_info:
        server.pve_guest_status("100")

    msg = str(exc_info.value)
    assert "PROXIMO_API_BASE_URL" in msg


def test_unreachable_error_is_not_a_bare_httpx_exception(tmp_path, monkeypatch):
    """Pin the TYPE, not just the message — a future regression that keeps some wording but goes
    back to raising the raw httpx exception must still fail this test."""
    _wire(tmp_path, monkeypatch)

    try:
        server.pve_list_guests()
    except httpx.ConnectError:
        pytest.fail("raw httpx.ConnectError leaked through the tool call seam")
    except ProximoError:
        pass


def test_unreachable_failure_still_records_to_the_ledger(tmp_path, monkeypatch):
    """The translation must not skip the PROVE ledger write — an unreachable-host failure is
    exactly the kind of event an operator wants in the audit trail."""
    import json

    _, _, ledger = _wire(tmp_path, monkeypatch)

    with pytest.raises(ProximoError):
        server.pve_list_guests()

    with open(ledger.path, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    assert any(e["action"] == "pve_list_guests" and e["outcome"] == "error" for e in entries)
