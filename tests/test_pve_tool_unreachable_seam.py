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


def test_httpstatuserror_url_is_scrubbed_from_raised_error(tmp_path, monkeypatch):
    """A 4xx/5xx from raise_for_status() carries the FULL request URL — the operator's internal
    Proxmox host:port and API path — in its str(). _audited scrubbed only TransportError before;
    an HTTPStatusError leaked the internal host into the caller's (model's) transcript. Pin that
    only the action + HTTP status survive, not the host."""
    _wire(tmp_path, monkeypatch)
    req = httpx.Request("GET", "https://pve.example.invalid:8006/api2/json/nodes/pve/status")
    resp = httpx.Response(403, request=req)

    def boom():
        raise httpx.HTTPStatusError("403 Forbidden", request=req, response=resp)

    with pytest.raises(ProximoError) as exc_info:
        server._audited("pve_guest_power", "lxc/100", boom, mutation=True)
    msg = str(exc_info.value)
    assert "pve.example.invalid" not in msg
    assert "8006" not in msg
    assert "403" in msg


def test_httpstatuserror_is_not_a_bare_httpx_exception(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)
    req = httpx.Request("GET", "https://pve.example.invalid:8006/api2/json")
    resp = httpx.Response(500, request=req)

    def boom():
        raise httpx.HTTPStatusError("500", request=req, response=resp)

    try:
        server._audited("pve_guest_power", "lxc/100", boom, mutation=True)
    except httpx.HTTPStatusError:
        pytest.fail("raw httpx.HTTPStatusError leaked through the _audited seam")
    except ProximoError:
        pass


def test_exec_timeout_records_error_timeout_and_says_may_still_be_running(tmp_path, monkeypatch):
    """L8: an in-container exec that exceeds its timeout is KILLED locally but may still run in the
    container (ssh orphans the remote pct exec). It must NOT be recorded as a plain 'error' (which
    reads as 'did not happen'); PROVE records 'error:timeout' and the caller is told it may have run."""
    import json
    import subprocess

    _, _, ledger = _wire(tmp_path, monkeypatch)

    def slow():
        raise subprocess.TimeoutExpired(cmd=["pct", "exec"], timeout=60)

    with pytest.raises(ProximoError) as exc_info:
        server._audited("ct_exec", "lxc/100", slow, mutation=True)
    msg = str(exc_info.value).lower()
    assert "still be running" in msg
    assert "60s" in msg

    with open(ledger.path, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    ct = [e for e in entries if e["action"] == "ct_exec"]
    assert ct and ct[-1]["outcome"] == "error:timeout"


def test_non_timeout_exception_still_records_plain_error(tmp_path, monkeypatch):
    """Control: a genuine (non-timeout) failure still records the plain 'error' outcome and
    re-raises the original exception unchanged."""
    import json

    _, _, ledger = _wire(tmp_path, monkeypatch)

    def boom():
        raise RuntimeError("kaboom")

    with pytest.raises(RuntimeError):
        server._audited("ct_exec", "lxc/100", boom, mutation=True)

    with open(ledger.path, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    ct = [e for e in entries if e["action"] == "ct_exec"]
    assert ct and ct[-1]["outcome"] == "error"
