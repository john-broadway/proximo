"""Structural-double tests for the PDM backend (proximo.pdm).

Mirrors test_pbs.py: mock httpx via MagicMock injected onto backend._client after
construction, assert path/param shaping, auth header format, validator rejection,
and the CA fail-closed invariant.

Live shapes for A/B groups verified (PDM 1.1, 2026-06-27).
C-group (PVE per-remote) and D-group (PBS per-remote) are live-prove-pending —
tests assert PATH + PARAM shaping only.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from proximo.backends import ProximoError
from proximo.pdm import (
    PdmBackend,
    PdmConfig,
    _check_datastore,
    _check_node,
    _check_opt,
    _check_remote,
    _check_vmid,
    _strip_secrets,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cfg(**kw) -> PdmConfig:
    """Return a PdmConfig with sensible defaults for unit tests."""
    defaults = dict(
        base_url="https://pdm.example.com:8443/api2/json",
        token_path="/run/pdm-token",  # noqa: S105
        verify_tls=True,
        ca_bundle=None,
    )
    defaults.update(kw)
    return PdmConfig(**defaults)


def _mock_backend(response_data, *, token: str = "proximo@pdm!token:secret",  # noqa: S107
                  status_code: int = 200) -> tuple[PdmBackend, MagicMock]:
    """Build a PdmBackend with a mocked httpx client.

    Returns (backend, mock_client). The mock client's .get() returns a response
    whose .json() returns {"data": response_data} and .raise_for_status() is a no-op.
    """
    cfg = _cfg()
    backend = PdmBackend(cfg)

    # Build a fake response
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = {"data": response_data}
    mock_resp.raise_for_status.return_value = None

    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp
    backend._client = mock_client

    # Stub token file read via token_path attribute on the config — we inject the token
    # by patching open at the backend level using monkeypatch in specific tests.
    # For these structural doubles we inject it differently: override _auth_header.
    backend._auth_header = lambda: {"Authorization": f"PDMAPIToken {token}"}

    return backend, mock_client


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def test_from_env_reads_required_vars(monkeypatch):
    monkeypatch.setenv("PROXIMO_PDM_BASE_URL", "https://pdm.example.com:8443")
    monkeypatch.setenv("PROXIMO_PDM_TOKEN_PATH", "/etc/proximo/pdm-token")
    monkeypatch.delenv("PROXIMO_PDM_VERIFY_TLS", raising=False)
    monkeypatch.delenv("PROXIMO_PDM_CA_BUNDLE", raising=False)
    cfg = PdmConfig.from_env()
    assert cfg.base_url == "https://pdm.example.com:8443/api2/json"
    assert cfg.token_path == "/etc/proximo/pdm-token"
    assert cfg.verify_tls is True
    assert cfg.ca_bundle is None


def test_from_env_appends_api2_json_when_absent(monkeypatch):
    monkeypatch.setenv("PROXIMO_PDM_BASE_URL", "https://pdm.example.com:8443")
    monkeypatch.setenv("PROXIMO_PDM_TOKEN_PATH", "/etc/proximo/pdm-token")
    cfg = PdmConfig.from_env()
    assert cfg.base_url.endswith("/api2/json")


def test_from_env_does_not_double_append_api2_json(monkeypatch):
    monkeypatch.setenv("PROXIMO_PDM_BASE_URL", "https://pdm.example.com:8443/api2/json")
    monkeypatch.setenv("PROXIMO_PDM_TOKEN_PATH", "/etc/proximo/pdm-token")
    cfg = PdmConfig.from_env()
    # Must not be doubled
    assert cfg.base_url.count("/api2/json") == 1


def test_from_env_missing_base_url_raises(monkeypatch):
    monkeypatch.delenv("PROXIMO_PDM_BASE_URL", raising=False)
    monkeypatch.setenv("PROXIMO_PDM_TOKEN_PATH", "/etc/proximo/pdm-token")
    with pytest.raises(RuntimeError, match="PROXIMO_PDM_BASE_URL"):
        PdmConfig.from_env()


def test_from_env_missing_token_path_raises(monkeypatch):
    monkeypatch.setenv("PROXIMO_PDM_BASE_URL", "https://pdm.example.com:8443")
    monkeypatch.delenv("PROXIMO_PDM_TOKEN_PATH", raising=False)
    with pytest.raises(RuntimeError, match="PROXIMO_PDM_TOKEN_PATH"):
        PdmConfig.from_env()


def test_from_env_verify_tls_false(monkeypatch):
    monkeypatch.setenv("PROXIMO_PDM_BASE_URL", "https://pdm.example.com:8443")
    monkeypatch.setenv("PROXIMO_PDM_TOKEN_PATH", "/etc/proximo/pdm-token")
    monkeypatch.setenv("PROXIMO_PDM_VERIFY_TLS", "false")
    # verify_tls=False with no ca_bundle warns (no raise at config time — raise is at backend time)
    import warnings
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        cfg = PdmConfig.from_env()
    assert cfg.verify_tls is False


def test_from_env_ca_bundle_set(monkeypatch):
    monkeypatch.setenv("PROXIMO_PDM_BASE_URL", "https://pdm.example.com:8443")
    monkeypatch.setenv("PROXIMO_PDM_TOKEN_PATH", "/etc/proximo/pdm-token")
    monkeypatch.setenv("PROXIMO_PDM_CA_BUNDLE", "/etc/proximo/pdm-ca.crt")
    cfg = PdmConfig.from_env()
    assert cfg.ca_bundle == "/etc/proximo/pdm-ca.crt"


# ---------------------------------------------------------------------------
# TLS / construction invariants
# ---------------------------------------------------------------------------

def test_backend_fails_closed_on_unverified_tls():
    """verify_tls=False AND no ca_bundle must raise ProximoError at construction."""
    cfg = _cfg(verify_tls=False, ca_bundle=None)
    with pytest.raises(ProximoError, match="refusing to send the PDM token"):
        PdmBackend(cfg)


def test_pdmbackend_fingerprint_refusal_names_env_var():
    # 1.6: a garbled PROXIMO_PDM_FINGERPRINT must not forward the validator's raw ValueError —
    # the message must name the exact env var and the expected shape (64-char SHA-256 hex).
    with pytest.raises(ProximoError, match="PROXIMO_PDM_FINGERPRINT") as exc_info:
        PdmBackend(_cfg(fingerprint="not-a-fingerprint"))
    assert "64" in str(exc_info.value)


def test_backend_ok_with_verify_tls_true():
    """verify_tls=True constructs successfully."""
    cfg = _cfg(verify_tls=True, ca_bundle=None)
    backend = PdmBackend(cfg)
    assert backend is not None


def test_backend_ok_with_ca_bundle_even_when_verify_false():
    """A ca_bundle overrides verify_tls=False — fails closed only when both missing."""
    # Use the real system CA bundle (a valid PEM file) so httpx_verify() can load it.
    cfg = _cfg(verify_tls=False, ca_bundle="/etc/ssl/certs/ca-certificates.crt")
    # Should not raise — ca_bundle provides verification
    backend = PdmBackend(cfg)
    assert backend.config.ca_bundle == "/etc/ssl/certs/ca-certificates.crt"


# ---------------------------------------------------------------------------
# Auth header — SPACE separator (NOT '=')
# ---------------------------------------------------------------------------

def test_auth_header_uses_space_separator(tmp_path):
    """Auth header must be 'PDMAPIToken <token>' with a SPACE, never '='."""
    token_file = tmp_path / "pdm-token"
    token_file.write_text("proximo@pdm!token:secret\n")
    cfg = _cfg(token_path=str(token_file))
    backend = PdmBackend(cfg)
    header = backend._auth_header()
    auth = header["Authorization"]
    assert auth.startswith("PDMAPIToken "), f"expected 'PDMAPIToken <token>', got: {auth!r}"
    assert "PDMAPIToken=" not in auth, "must not use '=' separator"
    assert "PBSAPIToken" not in auth
    assert "PVEAPIToken" not in auth


def test_auth_header_strips_trailing_newline(tmp_path):
    """Token files often end with a newline; strip must happen."""
    token_file = tmp_path / "pdm-token"
    token_file.write_text("proximo@pdm!token:secret\n\n")
    cfg = _cfg(token_path=str(token_file))
    backend = PdmBackend(cfg)
    auth = backend._auth_header()["Authorization"]
    assert auth == "PDMAPIToken proximo@pdm!token:secret"


def test_auth_header_read_at_call_time(tmp_path):
    """Token is read from disk on every call (supports rotation without restart)."""
    token_file = tmp_path / "pdm-token"
    token_file.write_text("first-token\n")
    cfg = _cfg(token_path=str(token_file))
    backend = PdmBackend(cfg)
    h1 = backend._auth_header()
    token_file.write_text("second-token\n")
    h2 = backend._auth_header()
    assert "first-token" in h1["Authorization"]
    assert "second-token" in h2["Authorization"]


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

def test_check_remote_valid():
    assert _check_remote("pve-cluster1") == "pve-cluster1"
    assert _check_remote("my-pbs") == "my-pbs"


def test_check_remote_rejects_slash():
    with pytest.raises(ProximoError):
        _check_remote("a/b")


def test_check_remote_rejects_newline():
    with pytest.raises(ProximoError):
        _check_remote("remote\n")


def test_check_remote_rejects_empty():
    with pytest.raises(ProximoError):
        _check_remote("")


def test_check_vmid_valid():
    assert _check_vmid(100) == "100"
    assert _check_vmid("999") == "999"
    assert _check_vmid(999999999) == "999999999"


def test_check_vmid_rejects_too_small():
    with pytest.raises(ProximoError):
        _check_vmid(99)


def test_check_vmid_rejects_zero():
    with pytest.raises(ProximoError):
        _check_vmid(0)


def test_check_vmid_rejects_non_numeric():
    with pytest.raises(ProximoError):
        _check_vmid("not-a-vmid")


def test_check_datastore_valid():
    assert _check_datastore("my-store") == "my-store"
    assert _check_datastore("backup01") == "backup01"


def test_check_datastore_rejects_slash():
    with pytest.raises(ProximoError):
        _check_datastore("a/b")


def test_check_datastore_rejects_newline():
    with pytest.raises(ProximoError):
        _check_datastore("store\n")


def test_check_node_valid():
    assert _check_node("localhost") == "localhost"
    assert _check_node("pve-node1") == "pve-node1"


def test_check_node_rejects_slash():
    with pytest.raises(ProximoError):
        _check_node("a/b")


def test_check_node_rejects_newline():
    with pytest.raises(ProximoError):
        _check_node("node\n")


# ---------------------------------------------------------------------------
# A-group: PDM self + topology — path shaping
# ---------------------------------------------------------------------------

def test_ping_calls_correct_path():
    backend, mock = _mock_backend("pong")
    result = backend.ping()
    mock.get.assert_called_once()
    path = mock.get.call_args[0][0]
    assert path == "/ping"
    assert result == "pong"


def test_version_calls_correct_path():
    data = {"release": "4", "repoid": "abc123", "version": "1.1"}
    backend, mock = _mock_backend(data)
    result = backend.version()
    mock.get.assert_called_once()
    assert mock.get.call_args[0][0] == "/version"
    assert result == data


def test_node_status_default_localhost():
    backend, mock = _mock_backend({"cpu": 0.1})
    backend.node_status()
    path = mock.get.call_args[0][0]
    assert "/nodes/localhost/status" in path


def test_node_status_custom_node():
    backend, mock = _mock_backend({"cpu": 0.1})
    backend.node_status("mynode")
    path = mock.get.call_args[0][0]
    assert "/nodes/mynode/status" in path


def test_node_status_rejects_invalid_node():
    backend, _ = _mock_backend({})
    with pytest.raises(ProximoError):
        backend.node_status("bad/node")


def test_remotes_list_calls_correct_path():
    backend, mock = _mock_backend([])
    backend.remotes_list()
    assert mock.get.call_args[0][0] == "/remotes/remote"


def test_remote_version_path_shape():
    backend, mock = _mock_backend({})
    backend.remote_version("pve-dc1")
    path = mock.get.call_args[0][0]
    assert path == "/remotes/remote/pve-dc1/version"


def test_remote_version_rejects_invalid():
    backend, _ = _mock_backend({})
    with pytest.raises(ProximoError):
        backend.remote_version("bad/name")


def test_remote_config_get_path_shape():
    backend, mock = _mock_backend({})
    backend.remote_config_get("pve-dc1")
    assert mock.get.call_args[0][0] == "/remotes/remote/pve-dc1/config"


# ---------------------------------------------------------------------------
# B-group: Fleet aggregate — path shaping
# ---------------------------------------------------------------------------

def test_resources_list_calls_correct_path():
    backend, mock = _mock_backend([])
    backend.resources_list()
    assert mock.get.call_args[0][0] == "/resources/list"


def test_resources_status_calls_correct_path():
    data = {"failed_remotes": 0, "lxc": {"running": 0}, "remotes": 0}
    backend, mock = _mock_backend(data)
    backend.resources_status()
    assert mock.get.call_args[0][0] == "/resources/status"


# ---------------------------------------------------------------------------
# C-group: PVE per-remote reads — path shaping (live-prove-pending)
# ---------------------------------------------------------------------------

def test_pve_remote_get_uses_flat_scheme():
    """The PVE proxy is FLAT: /pve/remotes/{remote}/{subpath} — no /api/1.1, no /api2/json."""
    backend, mock = _mock_backend([])
    backend._pve_remote_get("pve-dc1", "resources")
    path = mock.get.call_args[0][0]
    assert path == "/pve/remotes/pve-dc1/resources"
    assert "/api/1.1" not in path
    assert "/api2/json" not in path


def test_pve_resources_path_shape():
    backend, mock = _mock_backend([])
    backend.pve_resources("pve-dc1")
    assert mock.get.call_args[0][0] == "/pve/remotes/pve-dc1/resources"


def test_pve_resources_passes_kind_param():
    backend, mock = _mock_backend([])
    backend.pve_resources("pve-dc1", kind="vm")
    params = mock.get.call_args[1].get("params", {})
    assert params.get("kind") == "vm"


def test_pve_cluster_status_path_shape():
    backend, mock = _mock_backend([])
    backend.pve_cluster_status("pve-dc1")
    assert mock.get.call_args[0][0] == "/pve/remotes/pve-dc1/cluster-status"


def test_pve_node_list_path_shape():
    backend, mock = _mock_backend([])
    backend.pve_node_list("pve-dc1")
    assert mock.get.call_args[0][0] == "/pve/remotes/pve-dc1/nodes"


def test_pve_qemu_list_path_shape():
    backend, mock = _mock_backend([])
    backend.pve_qemu_list("pve-dc1")
    assert mock.get.call_args[0][0] == "/pve/remotes/pve-dc1/qemu"


def test_pve_qemu_list_node_is_optional_query():
    """node is an OPTIONAL query param, NOT part of the path (PDM qemu list is cluster-wide)."""
    backend, mock = _mock_backend([])
    backend.pve_qemu_list("pve-dc1", node="pve-node1")
    path = mock.get.call_args[0][0]
    assert path == "/pve/remotes/pve-dc1/qemu"
    assert "pve-node1" not in path
    params = mock.get.call_args[1].get("params", {})
    assert params.get("node") == "pve-node1"


def test_pve_qemu_config_path_shape():
    backend, mock = _mock_backend({})
    backend.pve_qemu_config("pve-dc1", 101)
    assert mock.get.call_args[0][0] == "/pve/remotes/pve-dc1/qemu/101/config"


def test_pve_qemu_config_optional_query_params():
    backend, mock = _mock_backend({})
    backend.pve_qemu_config("pve-dc1", 101, node="pve-node1", snapshot="snap1", state="current")
    params = mock.get.call_args[1].get("params", {})
    assert params.get("node") == "pve-node1"
    assert params.get("snapshot") == "snap1"
    assert params.get("state") == "current"


def test_pve_qemu_config_rejects_invalid_vmid():
    backend, _ = _mock_backend({})
    with pytest.raises(ProximoError):
        backend.pve_qemu_config("pve-dc1", 99)


def test_pve_qemu_config_defaults_state_active():
    """PDM REQUIRES `state` on qemu config (400 if omitted). It must default to
    'active' (= current config) so a plain call works. Regression: 2026-06-27 live-prove."""
    backend, mock = _mock_backend({})
    backend.pve_qemu_config("pve-dc1", 101)
    assert mock.get.call_args[1].get("params", {}).get("state") == "active"


def test_pve_qemu_config_state_always_in_params():
    """Regression guard: `state` must ALWAYS be included in params, never omitted.

    PDM rejects requests without `state` (400 error). This test guards against
    a future refactor that might make `state` conditionally included (e.g., "only
    if explicitly passed"). Both the default and explicit cases must include it.
    """
    backend, mock = _mock_backend({})

    # Case 1: state NOT explicitly passed — must default to "active"
    backend.pve_qemu_config("pve-dc1", 101)
    params_1 = mock.get.call_args[1].get("params", {})
    assert "state" in params_1, "state must always be in params dict"
    assert params_1["state"] == "active", "default state must be 'active'"

    # Reset mock for second call
    mock.reset_mock()

    # Case 2: state explicitly passed as "current" — must use that value
    backend.pve_qemu_config("pve-dc1", 101, state="current")
    params_2 = mock.get.call_args[1].get("params", {})
    assert "state" in params_2, "state must always be in params dict (even when explicit)"
    assert params_2["state"] == "current", "explicit state value must be preserved"


def test_pve_lxc_list_path_shape():
    backend, mock = _mock_backend([])
    backend.pve_lxc_list("pve-dc1")
    assert mock.get.call_args[0][0] == "/pve/remotes/pve-dc1/lxc"


def test_pve_lxc_list_node_is_optional_query():
    backend, mock = _mock_backend([])
    backend.pve_lxc_list("pve-dc1", node="pve-node1")
    path = mock.get.call_args[0][0]
    assert path == "/pve/remotes/pve-dc1/lxc"
    assert "pve-node1" not in path
    params = mock.get.call_args[1].get("params", {})
    assert params.get("node") == "pve-node1"


def test_pve_lxc_config_path_shape():
    backend, mock = _mock_backend({})
    backend.pve_lxc_config("pve-dc1", 102)
    assert mock.get.call_args[0][0] == "/pve/remotes/pve-dc1/lxc/102/config"


def test_pve_lxc_config_defaults_state_active():
    """PDM REQUIRES `state` on lxc config (400 if omitted) — same as qemu. Default 'active'.
    Regression: 2026-06-27 live-prove."""
    backend, mock = _mock_backend({})
    backend.pve_lxc_config("pve-dc1", 102)
    assert mock.get.call_args[1].get("params", {}).get("state") == "active"


def test_pve_remote_get_rejects_invalid_remote():
    backend, _ = _mock_backend([])
    with pytest.raises(ProximoError):
        backend._pve_remote_get("bad/remote", "resources")


# ---------------------------------------------------------------------------
# D-group: PBS per-remote reads — path shaping (live-verified, PDM 1.1 -> PBS 4.2)
# ---------------------------------------------------------------------------

def test_pbs_remote_get_uses_flat_scheme():
    """The PBS proxy is FLAT: /pbs/remotes/{remote}/{subpath} — no /api/1.1, no /api2/json."""
    backend, mock = _mock_backend({})
    backend._pbs_remote_get("pbs-dc1", "status")
    path = mock.get.call_args[0][0]
    assert path == "/pbs/remotes/pbs-dc1/status"
    assert "/api/1.1" not in path
    assert "/api2/json" not in path


def test_pbs_remote_status_path_shape():
    backend, mock = _mock_backend({})
    backend.pbs_remote_status("pbs-dc1")
    assert mock.get.call_args[0][0] == "/pbs/remotes/pbs-dc1/status"


def test_pbs_datastores_list_path_shape():
    backend, mock = _mock_backend([])
    backend.pbs_datastores_list("pbs-dc1")
    assert mock.get.call_args[0][0] == "/pbs/remotes/pbs-dc1/datastore"


def test_pbs_snapshots_list_path_shape():
    backend, mock = _mock_backend([])
    backend.pbs_snapshots_list("pbs-dc1", "my-store")
    assert mock.get.call_args[0][0] == "/pbs/remotes/pbs-dc1/datastore/my-store/snapshots"


def test_pbs_snapshots_list_passes_ns_param():
    backend, mock = _mock_backend([])
    backend.pbs_snapshots_list("pbs-dc1", "my-store", ns="myns")
    params = mock.get.call_args[1].get("params", {})
    assert params.get("ns") == "myns"


def test_pbs_snapshots_list_rejects_invalid_datastore():
    backend, _ = _mock_backend([])
    with pytest.raises(ProximoError):
        backend.pbs_snapshots_list("pbs-dc1", "bad/store")


@pytest.mark.parametrize("bad_ns", ["..", "a//b", "\x00", "/leading", "trailing/"])
def test_pdm_pbs_snapshots_list_rejects_invalid_ns(bad_ns):
    """FIX 1: ns must be validated via _check_namespace (mirrors pbs.snapshots_list)."""
    backend, mock = _mock_backend([])
    with pytest.raises(ProximoError):
        backend.pbs_snapshots_list("pbs-dc1", "my-store", ns=bad_ns)
    mock.get.assert_not_called()


def test_pdm_pbs_snapshots_list_accepts_valid_ns():
    backend, mock = _mock_backend([])
    backend.pbs_snapshots_list("pbs-dc1", "my-store", ns="team/prod")
    params = mock.get.call_args[1].get("params", {})
    assert params.get("ns") == "team/prod"


def test_pbs_remote_get_rejects_invalid_remote():
    backend, _ = _mock_backend([])
    with pytest.raises(ProximoError):
        backend._pbs_remote_get("bad/remote", "datastore")


# ---------------------------------------------------------------------------
# E-group: Tasks + access — path shaping
# ---------------------------------------------------------------------------

def test_tasks_list_path_shape():
    backend, mock = _mock_backend([])
    backend.tasks_list()
    assert mock.get.call_args[0][0] == "/remotes/tasks/list"


def test_acl_list_path_shape():
    backend, mock = _mock_backend([])
    backend.acl_list()
    assert mock.get.call_args[0][0] == "/access/acl"


def test_acl_list_path_filter_passed():
    backend, mock = _mock_backend([])
    backend.acl_list(path="/", exact=True)
    params = mock.get.call_args[1].get("params", {})
    assert params.get("path") == "/"
    assert params.get("exact") == 1


def test_roles_list_path_shape():
    backend, mock = _mock_backend([])
    backend.roles_list()
    assert mock.get.call_args[0][0] == "/access/roles"


def test_users_list_path_shape():
    backend, mock = _mock_backend([])
    backend.users_list()
    assert mock.get.call_args[0][0] == "/access/users"


def test_users_list_include_tokens_param():
    backend, mock = _mock_backend([])
    backend.users_list(include_tokens=True)
    params = mock.get.call_args[1].get("params", {})
    assert params.get("include_tokens") == 1


# ---------------------------------------------------------------------------
# Empty-data guard — OR [] / OR {} never blows up callers
# ---------------------------------------------------------------------------

def test_ping_null_data_returns_empty_string():
    backend, _ = _mock_backend(None)
    assert backend.ping() == ""


def test_remotes_list_null_data_returns_list():
    backend, _ = _mock_backend(None)
    assert backend.remotes_list() == []


def test_resources_status_null_data_returns_dict():
    backend, _ = _mock_backend(None)
    assert backend.resources_status() == {}


def test_pve_resources_null_data_returns_list():
    backend, _ = _mock_backend(None)
    assert backend.pve_resources("mypve") == []


# ---------------------------------------------------------------------------
# FIX 2: optional query-param hardening (_check_opt — control chars / length)
# ---------------------------------------------------------------------------

def test_check_opt_accepts_normal_value():
    assert _check_opt("vm", "kind") == "vm"


@pytest.mark.parametrize("bad", ["\x00", "a\nb", "a\tb", "x" * 257])
def test_check_opt_rejects_control_chars_and_overlong(bad):
    with pytest.raises(ProximoError):
        _check_opt(bad, "param")


def test_pve_resources_rejects_bad_kind():
    backend, mock = _mock_backend([])
    with pytest.raises(ProximoError):
        backend.pve_resources("pve-dc1", kind="vm\x00")
    mock.get.assert_not_called()


def test_pve_qemu_config_rejects_bad_snapshot():
    backend, mock = _mock_backend({})
    with pytest.raises(ProximoError):
        backend.pve_qemu_config("pve-dc1", 101, snapshot="snap\n")
    mock.get.assert_not_called()


def test_pve_qemu_config_rejects_bad_state():
    backend, mock = _mock_backend({})
    with pytest.raises(ProximoError):
        backend.pve_qemu_config("pve-dc1", 101, state="x" * 300)
    mock.get.assert_not_called()


def test_pve_lxc_config_rejects_bad_snapshot():
    backend, mock = _mock_backend({})
    with pytest.raises(ProximoError):
        backend.pve_lxc_config("pve-dc1", 102, snapshot="snap\x01")
    mock.get.assert_not_called()


def test_acl_list_rejects_bad_path():
    backend, mock = _mock_backend([])
    with pytest.raises(ProximoError):
        backend.acl_list(path="/\x00")
    mock.get.assert_not_called()


# ---------------------------------------------------------------------------
# FIX 3: defensive credential redaction (_strip_secrets)
# ---------------------------------------------------------------------------

def test_strip_secrets_removes_credential_keys():
    d = {"id": "x", "token": "sek", "password": "pw", "secret": "s",
         "key": "k", "tokensecret": "ts", "safe": "keep"}
    out = _strip_secrets(d)
    for k in ("token", "password", "secret", "key", "tokensecret"):
        assert k not in out
    assert out["safe"] == "keep"
    assert out["id"] == "x"


def test_remote_config_get_strips_secrets():
    backend, _ = _mock_backend({"id": "pve-dc1", "token": "sekret", "password": "pw"})
    out = backend.remote_config_get("pve-dc1")
    assert "token" not in out
    assert "password" not in out
    assert out["id"] == "pve-dc1"


def test_remotes_list_strips_secrets():
    backend, _ = _mock_backend([{"id": "pbs-dc1", "type": "pbs", "token": "sekret"}])
    out = backend.remotes_list()
    assert out[0]["id"] == "pbs-dc1"
    assert "token" not in out[0]


def test_users_list_strips_secrets():
    backend, _ = _mock_backend([{"userid": "u@pdm", "password": "pw", "secret": "s"}])
    out = backend.users_list()
    assert out[0]["userid"] == "u@pdm"
    assert "password" not in out[0]
    assert "secret" not in out[0]


def test_remotes_list_skips_non_dict_entries():
    backend, _ = _mock_backend([{"id": "ok"}, "junk", 42])
    out = backend.remotes_list()
    assert out == [{"id": "ok"}]


# ---------------------------------------------------------------------------
# FIX 3b: _strip_secrets — case-insensitive, recursive (dicts + lists)
# These tests are FAILING against the old shallow/case-sensitive implementation
# and PASSING against the fixed version.
# ---------------------------------------------------------------------------

def test_strip_secrets_case_insensitive():
    """Token, PASSWORD, Secret, KEY, TokenSecret must all be stripped regardless of casing."""
    d = {
        "Token": "t",
        "PASSWORD": "p",
        "Secret": "s",
        "KEY": "k",
        "TokenSecret": "ts",
        "safe": "ok",
        "id": "x",
    }
    out = _strip_secrets(d)
    for bad_key in ("Token", "PASSWORD", "Secret", "KEY", "TokenSecret"):
        assert bad_key not in out, f"expected {bad_key!r} to be stripped (case-insensitive)"
    assert out["safe"] == "ok"
    assert out["id"] == "x"


def test_strip_secrets_recursive_nested_dict():
    """A token buried in a nested dict must not survive the strip."""
    d = {
        "id": "pbs-dc1",
        "remote": {"host": "203.0.113.10", "token": "nested-secret", "port": 8007},
    }
    out = _strip_secrets(d)
    assert out["id"] == "pbs-dc1"
    assert "token" not in out["remote"], "nested token must be stripped"
    assert out["remote"]["host"] == "203.0.113.10"
    assert out["remote"]["port"] == 8007


def test_strip_secrets_nested_in_list():
    """A token buried in a dict inside a list value must not survive the strip."""
    d = {
        "members": [
            {"userid": "u@pdm", "token": "list-secret"},
            {"userid": "v@pdm", "safe": "value"},
        ]
    }
    out = _strip_secrets(d)
    assert "token" not in out["members"][0], "token inside list-of-dicts must be stripped"
    assert out["members"][0]["userid"] == "u@pdm"
    assert out["members"][1]["userid"] == "v@pdm"
    assert out["members"][1]["safe"] == "value"


def test_strip_secrets_returns_copy_not_mutates_original():
    """_strip_secrets must return a NEW dict; the original must not be modified."""
    d = {"id": "x", "token": "original-secret", "safe": "keep"}
    out = _strip_secrets(d)
    assert "token" not in out
    assert out["safe"] == "keep"
    # Original dict must be untouched (in-place pop would destroy this):
    assert "token" in d, "_strip_secrets must not mutate the original dict"
    assert d["token"] == "original-secret"


# ---------------------------------------------------------------------------
# FIX 3c: _strip_secrets — credential-shaped key VARIANTS (substring, not exact-match only)
# ---------------------------------------------------------------------------

def test_strip_secrets_catches_common_credential_key_variants():
    """Compound key names carrying a credential marker (client_secret, api_key, auth_token,
    private_key, bearer_token, ...) must be stripped too — an exact-match-only filter misses
    these while still claiming to guard against a future PDM regression handing back a secret.
    """
    d = {
        "id": "x",
        "client_secret": "SUPERSECRETVALUE",
        "api_key": "AKIA-EXAMPLE",
        "auth_token": "abc.def.ghi",
        "private_key": "-----BEGIN KEY-----",
        "bearer_token": "bearer-value",
        "safe": "keep",
    }
    out = _strip_secrets(d)
    for bad_key in ("client_secret", "api_key", "auth_token", "private_key", "bearer_token"):
        assert bad_key not in out, f"expected {bad_key!r} (credential-shaped) to be stripped"
    assert out["safe"] == "keep"
    assert out["id"] == "x"


# ---------------------------------------------------------------------------
# Fleet control — guest lifecycle mutations (increment 1).
# PDM proxies these on EXISTING guests (start/stop/shutdown/resume/migrate/
# remote-migrate/snapshot); create/clone is NOT proxiable (out of scope — see
# docs/plans/2026-07-06-pdm-fleet-control-design.md). PATH + BODY shaping asserted;
# live-prove-pending (PDM alpha).
# ---------------------------------------------------------------------------

def _mock_backend_write(response_data="UPID:node:00000000:0000:mut::",  # noqa: S107
                        *, token: str = "proximo@pdm!token:secret",  # noqa: S107
                        status_code: int = 200) -> tuple[PdmBackend, MagicMock]:
    """Like _mock_backend but also wires .post/.put/.delete to the same fake response."""
    backend, mock = _mock_backend(response_data, token=token, status_code=status_code)
    resp = mock.get.return_value
    mock.post.return_value = resp
    mock.put.return_value = resp
    mock.delete.return_value = resp
    return backend, mock


def test_guest_power_qemu_start_path_and_returns_upid():
    backend, mock = _mock_backend_write("UPID:n1:0001:start")
    upid = backend.guest_power("pve-dc1", "qemu", "100", "start")
    assert mock.post.call_args[0][0] == "/pve/remotes/pve-dc1/qemu/100/start"
    assert upid == "UPID:n1:0001:start"


def test_guest_power_lxc_stop_path():
    backend, mock = _mock_backend_write()
    backend.guest_power("pve-dc1", "lxc", "201", "stop")
    assert mock.post.call_args[0][0] == "/pve/remotes/pve-dc1/lxc/201/stop"


def test_guest_power_rejects_unknown_kind():
    backend, _ = _mock_backend_write()
    with pytest.raises(ProximoError):
        backend.guest_power("pve-dc1", "vm", "100", "start")


def test_guest_power_rejects_unknown_action():
    # PDM's proxy has no reboot; the qemu action set is start/stop/shutdown/resume.
    backend, _ = _mock_backend_write()
    with pytest.raises(ProximoError):
        backend.guest_power("pve-dc1", "qemu", "100", "reboot")


def test_guest_power_lxc_has_no_resume():
    # lxc containers do not suspend/resume — PDM exposes no lxc resume proxy.
    backend, _ = _mock_backend_write()
    with pytest.raises(ProximoError):
        backend.guest_power("pve-dc1", "lxc", "201", "resume")


def test_guest_power_rejects_remote_traversal():
    backend, _ = _mock_backend_write()
    with pytest.raises(ProximoError):
        backend.guest_power("../etc", "qemu", "100", "start")


# --- migrate (in-cluster) ---

def test_guest_migrate_qemu_path_and_target():
    backend, mock = _mock_backend_write()
    backend.guest_migrate("dc1", "qemu", "100", "node2", online=True)
    assert mock.post.call_args[0][0] == "/pve/remotes/dc1/qemu/100/migrate"
    body = mock.post.call_args[1]["json"]
    assert body["target"] == "node2"
    # PDM's Rust API demands a JSON boolean, NOT the PVE-style 1 (live-proven 2026-07-06:
    # int 1 -> 400 "Expected boolean value"). `is True` distinguishes bool from int (1 == True).
    assert body["online"] is True


def test_guest_migrate_offline_omits_online_flag():
    backend, mock = _mock_backend_write()
    backend.guest_migrate("dc1", "lxc", "201", "node2")
    assert mock.post.call_args[0][0] == "/pve/remotes/dc1/lxc/201/migrate"
    assert "online" not in mock.post.call_args[1]["json"]


def test_guest_migrate_rejects_bad_target_node():
    backend, _ = _mock_backend_write()
    with pytest.raises(ProximoError):
        backend.guest_migrate("dc1", "qemu", "100", "bad/../node")


def test_guest_migrate_target_storage_is_wrapped_as_single_element_array():
    """Audit-fixes plan Task 8 Fix B: target_storage (pdm.py:738) was sent as a bare scalar --
    the live-proven sibling guest_remote_migrate (pdm.py:763) needed array-wrapping because
    PDM's typed API rejects a scalar mapping value ('Expected array - got scalar value', 400).
    guest_migrate's target_storage is the identically-named field on the identically-shaped
    /migrate proxy endpoint, so it must be wrapped the same way rather than left as a scalar
    (untested and unverified against the same class of PDM rejection)."""
    backend, mock = _mock_backend_write()
    backend.guest_migrate("dc1", "qemu", "100", "node2", target_storage="local-lvm:local-lvm")
    body = mock.post.call_args[1]["json"]
    assert body["target-storage"] == ["local-lvm:local-lvm"]


def test_guest_migrate_omits_target_storage_when_not_given():
    backend, mock = _mock_backend_write()
    backend.guest_migrate("dc1", "qemu", "100", "node2")
    assert "target-storage" not in mock.post.call_args[1]["json"]


# --- remote-migrate (cross-remote — the world-first) ---

def test_guest_remote_migrate_qemu_path_and_required_body():
    backend, mock = _mock_backend_write()
    backend.guest_remote_migrate("dc1", "qemu", "100", target_remote="dc2",
                                 target_bridge="vmbr0:vmbr0", target_storage="local:local",
                                 target_vmid="150", online=True)
    assert mock.post.call_args[0][0] == "/pve/remotes/dc1/qemu/100/remote-migrate"
    body = mock.post.call_args[1]["json"]
    assert body["target"] == "dc2"
    # PDM's typed API rejects scalar target-bridge/target-storage ("Expected array - got
    # scalar value", HTTP 400) — they are repeatable mapping params, so send them as arrays.
    # (Live-proven 2026-07-06 against real PDM 1.1.4; the mocked test had encoded the scalar bug.)
    assert body["target-bridge"] == ["vmbr0:vmbr0"]
    assert body["target-storage"] == ["local:local"]
    assert body["target-vmid"] == "150"
    assert body["online"] is True


def test_guest_remote_migrate_delete_flag_is_json_bool():
    backend, mock = _mock_backend_write()
    backend.guest_remote_migrate("dc1", "qemu", "100", target_remote="dc2",
                                 target_bridge="vmbr0:vmbr0", target_storage="local:local",
                                 delete=True)
    assert mock.post.call_args[1]["json"]["delete"] is True


def test_guest_remote_migrate_requires_bridge_and_storage():
    backend, _ = _mock_backend_write()
    with pytest.raises(ProximoError):
        backend.guest_remote_migrate("dc1", "qemu", "100", target_remote="dc2",
                                     target_bridge="", target_storage="local:local")


# --- snapshot create / delete / rollback ---

def test_snapshot_create_path_and_body():
    backend, mock = _mock_backend_write()
    backend.snapshot_create("dc1", "qemu", "100", "snap1", description="pre-change", vmstate=True)
    assert mock.post.call_args[0][0] == "/pve/remotes/dc1/qemu/100/snapshot"
    body = mock.post.call_args[1]["json"]
    assert body["snapname"] == "snap1"
    assert body["description"] == "pre-change"
    assert body["vmstate"] is True


def test_snapshot_create_rejects_bad_snapname():
    backend, _ = _mock_backend_write()
    with pytest.raises(ProximoError):
        backend.snapshot_create("dc1", "qemu", "100", "bad/name")


def test_snapshot_delete_uses_delete_verb_and_path():
    backend, mock = _mock_backend_write()
    backend.snapshot_delete("dc1", "lxc", "201", "snap1")
    assert mock.delete.call_args[0][0] == "/pve/remotes/dc1/lxc/201/snapshot/snap1"


def test_snapshot_rollback_path():
    backend, mock = _mock_backend_write()
    backend.snapshot_rollback("dc1", "qemu", "100", "snap1")
    assert mock.post.call_args[0][0] == "/pve/remotes/dc1/qemu/100/snapshot/snap1/rollback"


# --- live-read for the planner ---

def test_guest_status_read_path():
    backend, mock = _mock_backend_write({"status": "running"})
    st = backend.guest_status("dc1", "qemu", "100")
    assert mock.get.call_args[0][0] == "/pve/remotes/dc1/qemu/100/status"
    assert st == {"status": "running"}


def test_task_status_read_path():
    backend, mock = _mock_backend_write({"status": "stopped", "exitstatus": "OK"})
    st = backend.task_status("dc1", "UPID:node:0001:")
    assert mock.get.call_args[0][0] == "/pve/remotes/dc1/tasks/UPID:node:0001:/status"
    assert st["exitstatus"] == "OK"


def test_task_status_accepts_remote_qualified_upid():
    # Live-proven 2026-07-06: PDM's proxied POSTs return a REMOTE-QUALIFIED upid
    # ("pve:<remote>!UPID:...") and its per-remote status endpoint REJECTS the bare
    # "UPID:..." form (400 "expected valid remote upid") — it requires the qualified id.
    backend, mock = _mock_backend_write({"status": "stopped", "exitstatus": "OK"})
    upid = "pve:pve-test1!UPID:pve-test1:00001685:00027201:6A4BE949:qmstart:31410:proximo-rw@pve!rw:"
    st = backend.task_status("dc1", upid)
    assert mock.get.call_args[0][0] == f"/pve/remotes/dc1/tasks/{upid}/status"
    assert st["exitstatus"] == "OK"


def test_task_status_rejects_upid_with_slash():
    backend, _ = _mock_backend_write()
    with pytest.raises(ProximoError):
        backend.task_status("dc1", "UPID/../etc")


def test_task_status_rejects_percent_encoded_traversal():
    # redteam MEDIUM: the ad-hoc "/" check missed %-encoded traversal; a real UPID allowlist
    # (must start "UPID:") rejects anything not shaped like a task id.
    backend, _ = _mock_backend_write()
    with pytest.raises(ProximoError):
        backend.task_status("dc1", "..%2f..%2fetc%2fpasswd")


def test_remote_migrate_rejects_whitespace_only_mappings():
    # redteam LOW: _check_opt(" ") returned " " (non-empty), so whitespace satisfied the
    # "required mapping" guard. Strip before the emptiness check.
    backend, _ = _mock_backend_write()
    with pytest.raises(ProximoError):
        backend.guest_remote_migrate("dc1", "qemu", "100", target_remote="dc2",
                                     target_bridge="   ", target_storage="local:local")
