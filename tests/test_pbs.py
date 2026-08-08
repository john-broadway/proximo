"""PBS (Proxmox Backup Server) lane tests — fully mocked, no live PBS.

Mirrors test_backends.py / test_cluster_ops.py style:
- _pbs_backend() uses a mock httpx transport to test PbsBackend's HTTP layer.
- _api() is a recording SimpleNamespace for tool/plan function tests.
- Validator-rejection tests use pytest.raises(ProximoError).
- Plan tests verify honest risk ratings and blast radius content.
"""

from __future__ import annotations

import pathlib
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from proximo.backends import ProximoError
from proximo.pbs import (
    PbsBackend,
    PbsConfig,
    _check_backup_id,
    _check_backup_time,
    _check_backup_type,
    _check_namespace,
    _check_namespace_component,
    _check_store,
    datastore_list,
    datastore_status,
    gc_start,
    gc_status,
    namespace_create,
    namespace_delete,
    namespace_list,
    plan_gc_start,
    plan_namespace_create,
    plan_namespace_delete,
    plan_prune,
    plan_snapshot_delete,
    plan_verify_start,
    prune,
    snapshot_delete,
    snapshots_list,
    tasks_list,
    verify_start,
)
from proximo.planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM

# ---------------------------------------------------------------------------
# PbsConfig helpers
# ---------------------------------------------------------------------------

def _cfg(**kw) -> PbsConfig:
    base = dict(
        base_url="https://pbs.example.lan:8007/api2/json",
        token_path="/run/pbs-token",
    )
    base.update(kw)
    return PbsConfig(**base)


# ---------------------------------------------------------------------------
# PbsConfig.from_env
# ---------------------------------------------------------------------------

def test_pbsconfig_from_env_reads_required_vars(monkeypatch):
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs:8007/api2/json")
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", "/run/tok")
    monkeypatch.delenv("PROXIMO_PBS_VERIFY_TLS", raising=False)
    monkeypatch.delenv("PROXIMO_PBS_CA_BUNDLE", raising=False)
    monkeypatch.delenv("PROXIMO_PBS_FINGERPRINT", raising=False)
    cfg = PbsConfig.from_env()
    assert cfg.base_url == "https://pbs:8007/api2/json"
    assert cfg.token_path == "/run/tok"  # noqa: S105
    assert cfg.verify_tls is True
    assert cfg.ca_bundle is None
    assert cfg.fingerprint is None


def test_pbsconfig_from_env_strips_trailing_slash(monkeypatch):
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs:8007/api2/json/")
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", "/run/tok")
    cfg = PbsConfig.from_env()
    assert not cfg.base_url.endswith("/")


def test_pbsconfig_from_env_optional_vars(monkeypatch):
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs:8007/api2/json")
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", "/run/tok")
    monkeypatch.setenv("PROXIMO_PBS_VERIFY_TLS", "false")
    monkeypatch.setenv("PROXIMO_PBS_CA_BUNDLE", "/etc/ssl/ca.pem")
    monkeypatch.setenv("PROXIMO_PBS_FINGERPRINT", "aa:bb:cc:dd")
    # ca_bundle IS set — no TLS warning fires (no warn context needed)
    cfg = PbsConfig.from_env()
    assert cfg.verify_tls is False
    assert cfg.ca_bundle == "/etc/ssl/ca.pem"
    assert cfg.fingerprint == "aa:bb:cc:dd"


def test_pbsconfig_from_env_missing_url_raises(monkeypatch):
    monkeypatch.delenv("PROXIMO_PBS_BASE_URL", raising=False)
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", "/run/tok")
    with pytest.raises(RuntimeError, match="PROXIMO_PBS_BASE_URL"):
        PbsConfig.from_env()


def test_pbsconfig_from_env_missing_hints_pve_path_fallback(monkeypatch):
    # When PBS isn't configured, the error should point at the PVE-path alternative that needs NO
    # PBS config — pve_backup_list against a pbs-type storage (real dogfood finding 2026-06-24).
    monkeypatch.delenv("PROXIMO_PBS_BASE_URL", raising=False)
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", "/run/tok")
    with pytest.raises(RuntimeError, match="pve_backup_list"):
        PbsConfig.from_env()


def test_pbsconfig_from_env_missing_token_path_raises(monkeypatch):
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs:8007/api2/json")
    monkeypatch.delenv("PROXIMO_PBS_TOKEN_PATH", raising=False)
    with pytest.raises(RuntimeError, match="PROXIMO_PBS_TOKEN_PATH"):
        PbsConfig.from_env()


def test_pbsconfig_from_env_warns_on_no_tls_verify_no_bundle(monkeypatch):
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs:8007/api2/json")
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", "/run/tok")
    monkeypatch.setenv("PROXIMO_PBS_VERIFY_TLS", "false")
    monkeypatch.delenv("PROXIMO_PBS_CA_BUNDLE", raising=False)
    with pytest.warns(UserWarning, match="without cert validation"):
        PbsConfig.from_env()


def test_pbsconfig_from_env_no_tls_warning_when_fingerprint_pinned(monkeypatch):
    # A fingerprint pin IS wire-enforced cert validation. The "no cert validation" warning must
    # NOT fire — matching the PMG/PDM sibling loaders, which include `and not fingerprint`.
    import warnings
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs:8007/api2/json")
    monkeypatch.setenv("PROXIMO_PBS_TOKEN_PATH", "/run/tok")
    monkeypatch.setenv("PROXIMO_PBS_VERIFY_TLS", "false")
    monkeypatch.delenv("PROXIMO_PBS_CA_BUNDLE", raising=False)
    monkeypatch.setenv("PROXIMO_PBS_FINGERPRINT", "aa:bb:cc:dd")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        cfg = PbsConfig.from_env()
    assert not any("without cert validation" in str(w.message) for w in caught)
    assert cfg.fingerprint == "aa:bb:cc:dd"


# ---------------------------------------------------------------------------
# PbsBackend._auth_header — token format + never-inlined contract
# ---------------------------------------------------------------------------

def test_auth_header_format(tmp_path):
    """Auth header must use PBSAPIToken= scheme with the full token verbatim."""
    tok = tmp_path / "token"
    tok.write_text("backup@pbs!token:secret-value\n")
    backend = PbsBackend(_cfg(token_path=str(tok)))
    header = backend._auth_header()
    assert header["Authorization"] == "PBSAPIToken=backup@pbs!token:secret-value"


def test_auth_header_uses_pbs_scheme_not_pve(tmp_path):
    """PBS uses PBSAPIToken=, NOT PVEAPIToken=."""
    tok = tmp_path / "token"
    tok.write_text("backup@pbs!token:secret\n")
    backend = PbsBackend(_cfg(token_path=str(tok)))
    header = backend._auth_header()
    assert header["Authorization"].startswith("PBSAPIToken=")
    assert "PVEAPIToken" not in header["Authorization"]


def test_auth_header_strips_whitespace(tmp_path):
    """Token file may have trailing newlines — strip them."""
    tok = tmp_path / "token"
    tok.write_text("  backup@pbs!token:secret  \n\n")
    backend = PbsBackend(_cfg(token_path=str(tok)))
    header = backend._auth_header()
    assert header["Authorization"] == "PBSAPIToken=backup@pbs!token:secret"


def test_auth_header_token_never_hardcoded(tmp_path):
    """Token must come from the file, not from a hardcoded value."""
    tok = tmp_path / "token"
    tok.write_text("backup@pbs!token:unique-sentinel-xyz\n")
    backend = PbsBackend(_cfg(token_path=str(tok)))
    header = backend._auth_header()
    # The secret 'unique-sentinel-xyz' must appear only via the file read.
    assert "unique-sentinel-xyz" in header["Authorization"]


def test_auth_header_reflects_file_change(tmp_path):
    """Token is read at call time — file change is reflected on next call."""
    tok = tmp_path / "token"
    tok.write_text("backup@pbs!token:token-v1\n")
    backend = PbsBackend(_cfg(token_path=str(tok)))
    h1 = backend._auth_header()
    tok.write_text("backup@pbs!token:token-v2\n")
    h2 = backend._auth_header()
    assert "token-v1" in h1["Authorization"]
    assert "token-v2" in h2["Authorization"]
    assert h1["Authorization"] != h2["Authorization"]


# ---------------------------------------------------------------------------
# PbsBackend HTTP methods — mock httpx transport
# ---------------------------------------------------------------------------

def _mock_backend(response_data, *, status_code: int = 200, token_content: str = "u@r!t:s") -> tuple:  # noqa: S107
    """Returns (backend, tmp_path) with a mocked httpx client."""
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json.return_value = {"data": response_data}
    mock_resp.raise_for_status = MagicMock()

    mock_client = MagicMock()
    mock_client.get.return_value = mock_resp
    mock_client.post.return_value = mock_resp
    mock_client.request.return_value = mock_resp

    tmp = pathlib.Path(tempfile.mkdtemp()) / "token"
    tmp.write_text(token_content + "\n")

    backend = PbsBackend(_cfg(token_path=str(tmp)))
    backend._client = mock_client
    return backend, mock_client


def test_get_calls_httpx_get():
    backend, mock_client = _mock_backend([{"name": "test-datastore"}])
    backend._get("/admin/datastore")
    mock_client.get.assert_called_once()
    call_args = mock_client.get.call_args
    assert call_args[0][0] == "/admin/datastore"


def test_get_with_params_passes_params():
    backend, mock_client = _mock_backend([])
    backend._get("/admin/datastore/test-datastore/snapshots", params={"ns": "team/prod"})
    call_kwargs = mock_client.get.call_args[1]
    assert call_kwargs.get("params", {}).get("ns") == "team/prod"


def test_post_calls_httpx_post():
    backend, mock_client = _mock_backend("UPID:pbs:1:0:0:0:gc:test-datastore:root@pam:")
    backend._post("/admin/datastore/test-datastore/gc")
    mock_client.post.assert_called_once()


def test_delete_calls_httpx_request_with_delete_verb():
    backend, mock_client = _mock_backend(None)
    backend._delete("/admin/datastore/test-datastore/namespace", params={"ns": "test"})
    call = mock_client.request.call_args
    assert call[0][0] == "DELETE"


def test_get_raises_for_status():
    """raise_for_status is called on every response."""
    backend, mock_client = _mock_backend([])
    backend._get("/admin/datastore")
    mock_client.get.return_value.raise_for_status.assert_called_once()


def test_auth_header_attached_to_get(tmp_path):
    tok = tmp_path / "tok"
    tok.write_text("backup@pbs!token:s3cr3t\n")
    backend, mock_client = _mock_backend([])
    backend.config = _cfg(token_path=str(tok))

    mock_resp = MagicMock()
    mock_resp.json.return_value = {"data": []}
    mock_resp.raise_for_status = MagicMock()
    mock_client.get.return_value = mock_resp

    backend._get("/admin/datastore")
    call_kwargs = mock_client.get.call_args[1]
    auth = call_kwargs.get("headers", {}).get("Authorization", "")
    assert "PBSAPIToken=" in auth


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

class TestCheckStore:
    def test_valid_store(self):
        assert _check_store("test-datastore") == "test-datastore"

    def test_valid_store_underscore(self):
        assert _check_store("local_zfs") == "local_zfs"

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_store("a/b")

    def test_rejects_dotdot(self):
        with pytest.raises(ProximoError):
            _check_store("../etc")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_store("store\n")

    def test_rejects_leading_hyphen(self):
        with pytest.raises(ProximoError):
            _check_store("-store")

    def test_rejects_space(self):
        with pytest.raises(ProximoError):
            _check_store("store name")

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_store("")


class TestCheckNamespace:
    def test_none_passes_through(self):
        assert _check_namespace(None) is None

    def test_empty_string_is_root(self):
        assert _check_namespace("") == ""

    def test_valid_simple(self):
        assert _check_namespace("team") == "team"

    def test_valid_nested(self):
        """Namespaces ARE hierarchical — slash must be allowed."""
        assert _check_namespace("team/prod") == "team/prod"

    def test_valid_deep_nested(self):
        assert _check_namespace("a/b/c/d") == "a/b/c/d"

    def test_rejects_dotdot(self):
        with pytest.raises(ProximoError):
            _check_namespace("../etc")

    def test_rejects_dotdot_in_path(self):
        with pytest.raises(ProximoError):
            _check_namespace("team/../other")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_namespace("team\nother")

    def test_rejects_double_slash(self):
        with pytest.raises(ProximoError):
            _check_namespace("team//prod")


class TestCheckBackupType:
    def test_valid_types(self):
        for bt in ("vm", "ct", "host"):
            assert _check_backup_type(bt) == bt

    def test_none_passes_through(self):
        assert _check_backup_type(None) is None

    def test_rejects_invalid(self):
        with pytest.raises(ProximoError):
            _check_backup_type("lxc")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_backup_type("vm\n")


class TestCheckBackupId:
    def test_valid_numeric(self):
        assert _check_backup_id("100") == "100"

    def test_valid_alphanumeric(self):
        assert _check_backup_id("host1") == "host1"

    def test_none_passes_through(self):
        assert _check_backup_id(None) is None

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_backup_id("100/etc")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_backup_id("100\n")


class TestCheckBackupTime:
    def test_valid_epoch(self):
        assert _check_backup_time(1717000000) == 1717000000

    def test_string_int_accepted(self):
        assert _check_backup_time("1717000000") == 1717000000

    def test_rejects_zero(self):
        with pytest.raises(ProximoError):
            _check_backup_time(0)

    def test_rejects_negative(self):
        with pytest.raises(ProximoError):
            _check_backup_time(-1)

    def test_rejects_string_non_int(self):
        with pytest.raises(ProximoError):
            _check_backup_time("not-a-time")


class TestCheckNamespaceComponent:
    def test_valid_component(self):
        assert _check_namespace_component("team") == "team"

    def test_rejects_slash(self):
        """namespace_create 'name' is a single component — no slash."""
        with pytest.raises(ProximoError):
            _check_namespace_component("a/b")

    def test_rejects_dotdot(self):
        with pytest.raises(ProximoError):
            _check_namespace_component("..")

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_namespace_component("")

    def test_rejects_newline(self):
        with pytest.raises(ProximoError):
            _check_namespace_component("name\n")


# ---------------------------------------------------------------------------
# _api() — recording SimpleNamespace for tool/plan tests
# ---------------------------------------------------------------------------

def _api() -> SimpleNamespace:
    """Minimal PBS API fake recording _get / _post / _delete calls."""
    seen: dict = {}

    def fake_get(path, params=None):
        seen["method"] = "GET"
        seen["path"] = path
        seen["params"] = params or {}
        return []

    def fake_post(path, data=None):
        seen["method"] = "POST"
        seen["path"] = path
        seen["data"] = data or {}
        return "UPID:pbs:00001:0:0:0:gc:test-datastore:root@pam:"

    def fake_delete(path, params=None):
        seen["method"] = "DELETE"
        seen["path"] = path
        seen["params"] = params or {}
        return None

    return SimpleNamespace(_get=fake_get, _post=fake_post, _delete=fake_delete, seen=seen)


# ---------------------------------------------------------------------------
# READ operations — URL shapes
# ---------------------------------------------------------------------------

class TestDatastoreList:
    def test_uses_correct_path(self):
        api = _api()
        datastore_list(api)
        assert api.seen["path"] == "/admin/datastore"
        assert api.seen["method"] == "GET"

    def test_is_not_node_scoped(self):
        api = _api()
        datastore_list(api)
        assert "/nodes/" not in api.seen["path"]

    def test_returns_list(self):
        api = _api()
        result = datastore_list(api)
        assert isinstance(result, list)

    def test_verified_shape_comment(self):
        """datastore_list uses the VERIFIED GET /admin/datastore shape from 2026-06-08."""
        # Shape: [{"gc-schedule": ..., "name": ..., "path": ...}]
        # This test confirms the function hits the verified endpoint.
        api = _api()
        api._get = lambda path, params=None: [
            {"gc-schedule": "sun 03:00", "name": "test-datastore", "path": "/datastore"}
        ]
        result = datastore_list(api)
        assert result[0]["name"] == "test-datastore"
        assert result[0]["gc-schedule"] == "sun 03:00"


class TestDatastoreStatus:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: {"total": 1000, "used": 200, "avail": 800}
        datastore_status(api, "test-datastore")
        # Verify path via a recording api
        recording = _api()
        recording._get = lambda path, params=None: (
            recording.seen.update(path=path) or {"total": 1000}
        )
        datastore_status(recording, "test-datastore")
        assert recording.seen["path"] == "/admin/datastore/test-datastore/status"

    def test_rejects_invalid_store(self):
        api = _api()
        with pytest.raises(ProximoError):
            datastore_status(api, "bad/store")

    def test_rejects_traversal_store(self):
        api = _api()
        with pytest.raises(ProximoError):
            datastore_status(api, "../etc")


class TestGcStatus:
    def test_uses_correct_path(self):
        api = _api()
        api._get = lambda path, params=None: (
            api.seen.update(path=path) or {
                "disk-bytes": 100, "disk-chunks": 5, "store": "test-datastore", "upid": None
            }
        )
        gc_status(api, "test-datastore")
        assert api.seen["path"] == "/admin/datastore/test-datastore/gc"

    def test_verified_gc_shape(self):
        """gc_status uses the VERIFIED GET /admin/datastore/{store}/gc shape from 2026-06-08."""
        api = _api()
        verified_data = {
            "disk-bytes": 12345678,
            "disk-chunks": 42,
            "index-data-bytes": 9999999,
            "index-file-count": 100,
            "next-run": 1717500000,
            "pending-bytes": 0,
            "pending-chunks": 0,
            "removed-bad": 0,
            "removed-bytes": 0,
            "removed-chunks": 0,
            "schedule": "sun 03:00",
            "still-bad": 0,
            "store": "test-datastore",
            "upid": None,
        }
        api._get = lambda path, params=None: verified_data
        result = gc_status(api, "test-datastore")
        assert result["store"] == "test-datastore"
        assert result["disk-chunks"] == 42
        assert "upid" in result

    def test_rejects_invalid_store(self):
        api = _api()
        with pytest.raises(ProximoError):
            gc_status(api, "bad/store")


class TestSnapshotsList:
    def test_no_filters_uses_base_path(self):
        api = _api()
        snapshots_list(api, "test-datastore")
        assert api.seen["path"] == "/admin/datastore/test-datastore/snapshots"
        assert api.seen["method"] == "GET"
        assert api.seen["params"] == {}

    def test_ns_filter_sent_as_param(self):
        api = _api()
        snapshots_list(api, "test-datastore", ns="team/prod")
        assert api.seen["params"].get("ns") == "team/prod"

    def test_backup_type_filter_sent_as_hyphenated_param(self):
        api = _api()
        snapshots_list(api, "test-datastore", backup_type="vm")
        assert api.seen["params"].get("backup-type") == "vm"

    def test_backup_id_filter_sent_as_hyphenated_param(self):
        api = _api()
        snapshots_list(api, "test-datastore", backup_id="100")
        assert api.seen["params"].get("backup-id") == "100"

    def test_all_filters_combined(self):
        api = _api()
        snapshots_list(api, "test-datastore", ns="team", backup_type="vm", backup_id="100")
        p = api.seen["params"]
        assert p["ns"] == "team"
        assert p["backup-type"] == "vm"
        assert p["backup-id"] == "100"

    def test_none_filters_omitted(self):
        api = _api()
        snapshots_list(api, "test-datastore", ns=None, backup_type=None, backup_id=None)
        assert api.seen["params"] == {}

    def test_rejects_invalid_store(self):
        api = _api()
        with pytest.raises(ProximoError):
            snapshots_list(api, "bad/store")

    def test_rejects_invalid_backup_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            snapshots_list(api, "test-datastore", backup_type="lxc")

    def test_rejects_traversal_in_ns(self):
        api = _api()
        with pytest.raises(ProximoError):
            snapshots_list(api, "test-datastore", ns="../etc")


class TestNamespaceList:
    def test_uses_correct_path(self):
        api = _api()
        namespace_list(api, "test-datastore")
        assert api.seen["path"] == "/admin/datastore/test-datastore/namespace"
        assert api.seen["method"] == "GET"

    def test_parent_sent_as_param(self):
        api = _api()
        namespace_list(api, "test-datastore", parent="team")
        assert api.seen["params"].get("parent") == "team"

    def test_max_depth_sent_as_hyphenated_param(self):
        api = _api()
        namespace_list(api, "test-datastore", max_depth=2)
        assert api.seen["params"].get("max-depth") == 2

    def test_none_parent_omitted(self):
        api = _api()
        namespace_list(api, "test-datastore", parent=None)
        assert "parent" not in api.seen["params"]

    def test_none_max_depth_omitted(self):
        api = _api()
        namespace_list(api, "test-datastore", max_depth=None)
        assert "max-depth" not in api.seen["params"]

    def test_rejects_invalid_max_depth(self):
        api = _api()
        with pytest.raises(ProximoError):
            namespace_list(api, "test-datastore", max_depth="bad")

    def test_rejects_invalid_store(self):
        api = _api()
        with pytest.raises(ProximoError):
            namespace_list(api, "bad/store")


class TestTasksList:
    def test_default_node_is_localhost(self):
        api = _api()
        tasks_list(api)
        assert api.seen["path"] == "/nodes/localhost/tasks"
        assert api.seen["method"] == "GET"

    def test_custom_node_interpolated_in_path(self):
        api = _api()
        api._get = lambda path, params=None: (api.seen.update(path=path) or [])
        tasks_list(api, node="pbs-node-2")
        assert api.seen["path"] == "/nodes/pbs-node-2/tasks"

    def test_no_params_by_default(self):
        api = _api()
        tasks_list(api)
        assert api.seen["params"] == {}

    def test_limit_sent_as_int_param(self):
        api = _api()
        tasks_list(api, limit=50)
        assert api.seen["params"].get("limit") == 50

    def test_running_param_passed_through(self):
        api = _api()
        tasks_list(api, running=True)
        assert api.seen["params"].get("running") is True

    def test_errors_param_passed_through(self):
        api = _api()
        tasks_list(api, errors=True)
        assert api.seen["params"].get("errors") is True

    def test_none_params_omitted(self):
        api = _api()
        tasks_list(api, limit=None, running=None, errors=None)
        assert api.seen["params"] == {}

    def test_returns_list(self):
        api = _api()
        result = tasks_list(api)
        assert isinstance(result, list)

    def test_invalid_limit_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            tasks_list(api, limit="bad")

    def test_traversal_node_rejected(self):
        # node is a URL path segment — a crafted value must not traverse/inject
        api = _api()
        for bad in ("../etc", "a/b", "node?x=1", "n\nlog"):
            with pytest.raises(ProximoError, match="invalid PBS node name"):
                tasks_list(api, node=bad)


# ---------------------------------------------------------------------------
# MUTATION operations — URL shapes, methods, bodies
# ---------------------------------------------------------------------------

class TestGcStart:
    def test_uses_correct_path_and_method(self):
        api = _api()
        gc_start(api, "test-datastore")
        assert api.seen["path"] == "/admin/datastore/test-datastore/gc"
        assert api.seen["method"] == "POST"

    def test_returns_upid_string(self):
        api = _api()
        result = gc_start(api, "test-datastore")
        assert isinstance(result, str)

    def test_rejects_invalid_store(self):
        api = _api()
        with pytest.raises(ProximoError):
            gc_start(api, "bad/store")


class TestVerifyStart:
    def test_uses_correct_path_and_method(self):
        api = _api()
        verify_start(api, "test-datastore")
        assert api.seen["path"] == "/admin/datastore/test-datastore/verify"
        assert api.seen["method"] == "POST"

    def test_empty_body_when_no_filters(self):
        api = _api()
        verify_start(api, "test-datastore")
        assert api.seen["data"] == {}

    def test_ns_sent_in_body(self):
        api = _api()
        verify_start(api, "test-datastore", ns="team")
        assert api.seen["data"].get("ns") == "team"

    def test_backup_type_sent_as_hyphenated(self):
        api = _api()
        verify_start(api, "test-datastore", backup_type="vm")
        assert api.seen["data"].get("backup-type") == "vm"

    def test_backup_id_sent_as_hyphenated(self):
        api = _api()
        verify_start(api, "test-datastore", backup_id="100")
        assert api.seen["data"].get("backup-id") == "100"

    def test_rejects_invalid_store(self):
        api = _api()
        with pytest.raises(ProximoError):
            verify_start(api, "bad/store")

    def test_rejects_invalid_backup_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            verify_start(api, "test-datastore", backup_type="docker")


class TestPrune:
    def test_uses_correct_path_and_method(self):
        api = _api()
        prune(api, "test-datastore")
        assert api.seen["path"] == "/admin/datastore/test-datastore/prune"
        assert api.seen["method"] == "POST"

    def test_dry_run_defaults_to_true(self):
        """dry_run MUST default to True — never delete without explicit opt-in."""
        api = _api()
        prune(api, "test-datastore")
        assert api.seen["data"].get("dry-run") == 1

    def test_dry_run_true_sends_dry_run_1(self):
        api = _api()
        prune(api, "test-datastore", dry_run=True)
        assert api.seen["data"].get("dry-run") == 1

    def test_dry_run_false_omits_dry_run_param(self):
        api = _api()
        prune(api, "test-datastore", dry_run=False)
        assert "dry-run" not in api.seen["data"]

    def test_keep_params_sent_as_hyphenated(self):
        api = _api()
        prune(
            api, "test-datastore",
            keep_last=3, keep_daily=7, keep_weekly=4,
            keep_monthly=6, keep_yearly=1,
            dry_run=True,
        )
        d = api.seen["data"]
        assert d["keep-last"] == 3
        assert d["keep-daily"] == 7
        assert d["keep-weekly"] == 4
        assert d["keep-monthly"] == 6
        assert d["keep-yearly"] == 1

    def test_none_keep_params_omitted(self):
        api = _api()
        prune(api, "test-datastore")
        d = api.seen["data"]
        for k in ("keep-last", "keep-daily", "keep-weekly", "keep-monthly", "keep-yearly"):
            assert k not in d

    def test_ns_sent_when_provided(self):
        api = _api()
        prune(api, "test-datastore", ns="team")
        assert api.seen["data"].get("ns") == "team"

    def test_rejects_invalid_keep_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            prune(api, "test-datastore", keep_last="bad")

    def test_rejects_invalid_store(self):
        api = _api()
        with pytest.raises(ProximoError):
            prune(api, "bad/store")


class TestSnapshotDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        snapshot_delete(api, "test-datastore", "vm", "100", 1717000000)
        assert api.seen["path"] == "/admin/datastore/test-datastore/snapshots"
        assert api.seen["method"] == "DELETE"

    def test_params_sent_as_query_hyphenated(self):
        api = _api()
        snapshot_delete(api, "test-datastore", "vm", "100", 1717000000)
        p = api.seen["params"]
        assert p["backup-type"] == "vm"
        assert p["backup-id"] == "100"
        assert p["backup-time"] == 1717000000

    def test_ns_included_when_provided(self):
        api = _api()
        snapshot_delete(api, "test-datastore", "vm", "100", 1717000000, ns="team")
        assert api.seen["params"].get("ns") == "team"

    def test_ns_omitted_when_none(self):
        api = _api()
        snapshot_delete(api, "test-datastore", "vm", "100", 1717000000)
        assert "ns" not in api.seen["params"]

    def test_rejects_invalid_backup_type(self):
        api = _api()
        with pytest.raises(ProximoError):
            snapshot_delete(api, "test-datastore", "lxc", "100", 1717000000)

    def test_rejects_bad_backup_time(self):
        api = _api()
        with pytest.raises(ProximoError):
            snapshot_delete(api, "test-datastore", "vm", "100", 0)

    def test_rejects_invalid_store(self):
        api = _api()
        with pytest.raises(ProximoError):
            snapshot_delete(api, "bad/store", "vm", "100", 1717000000)


class TestNamespaceCreate:
    def test_uses_correct_path_and_method(self):
        api = _api()
        namespace_create(api, "test-datastore", "team")
        assert api.seen["path"] == "/admin/datastore/test-datastore/namespace"
        assert api.seen["method"] == "POST"

    def test_name_sent_in_body(self):
        api = _api()
        namespace_create(api, "test-datastore", "team")
        assert api.seen["data"].get("name") == "team"

    def test_parent_sent_when_provided(self):
        api = _api()
        namespace_create(api, "test-datastore", "prod", parent="team")
        assert api.seen["data"].get("parent") == "team"

    def test_parent_omitted_when_none(self):
        api = _api()
        namespace_create(api, "test-datastore", "team")
        assert "parent" not in api.seen["data"]

    def test_rejects_name_with_slash(self):
        api = _api()
        with pytest.raises(ProximoError):
            namespace_create(api, "test-datastore", "a/b")

    def test_rejects_empty_name(self):
        api = _api()
        with pytest.raises(ProximoError):
            namespace_create(api, "test-datastore", "")


class TestNamespaceDelete:
    def test_uses_correct_path_and_method(self):
        api = _api()
        namespace_delete(api, "test-datastore", "team")
        assert api.seen["path"] == "/admin/datastore/test-datastore/namespace"
        assert api.seen["method"] == "DELETE"

    def test_ns_sent_as_query_param(self):
        api = _api()
        namespace_delete(api, "test-datastore", "team")
        assert api.seen["params"].get("ns") == "team"

    def test_delete_groups_false_omits_param(self):
        api = _api()
        namespace_delete(api, "test-datastore", "team", delete_groups=False)
        assert "delete-groups" not in api.seen["params"]

    def test_delete_groups_true_sends_1(self):
        api = _api()
        namespace_delete(api, "test-datastore", "team", delete_groups=True)
        assert api.seen["params"].get("delete-groups") == 1

    def test_rejects_empty_namespace(self):
        api = _api()
        with pytest.raises(ProximoError):
            namespace_delete(api, "test-datastore", "")

    def test_rejects_traversal_in_ns(self):
        api = _api()
        with pytest.raises(ProximoError):
            namespace_delete(api, "test-datastore", "../etc")

    def test_rejects_invalid_store(self):
        api = _api()
        with pytest.raises(ProximoError):
            namespace_delete(api, "bad/store", "team")


# ---------------------------------------------------------------------------
# PLAN operations — risk ratings, blast radius, honesty
# ---------------------------------------------------------------------------

class TestPlanGcStart:
    def test_risk_is_high(self):
        p = plan_gc_start("test-datastore")
        assert p.risk == RISK_HIGH

    def test_action_string(self):
        p = plan_gc_start("test-datastore")
        assert p.action == "pbs_gc_start"

    def test_target_includes_store(self):
        p = plan_gc_start("test-datastore")
        assert "test-datastore" in p.target

    def test_blast_mentions_no_undo(self):
        p = plan_gc_start("test-datastore")
        text = " ".join(p.blast_radius).lower()
        assert "undo" in text or "no undo" in text or "cannot" in text or "not recoverable" in text

    def test_blast_mentions_io_impact(self):
        p = plan_gc_start("test-datastore")
        text = " ".join(p.blast_radius).lower()
        assert "i/o" in text or "io" in text or "heavy" in text or "impact" in text

    def test_does_not_claim_safe(self):
        p = plan_gc_start("test-datastore")
        text = " ".join(p.blast_radius + p.risk_reasons + [p.note]).lower()
        assert "safe" not in text

    def test_rejects_invalid_store(self):
        with pytest.raises(ProximoError):
            plan_gc_start("bad/store")


class TestPlanPrune:
    def test_dry_run_true_is_low_risk(self):
        p = plan_prune("test-datastore", dry_run=True)
        assert p.risk == RISK_LOW

    def test_dry_run_false_is_high_risk(self):
        p = plan_prune("test-datastore", dry_run=False)
        assert p.risk == RISK_HIGH

    def test_dry_run_default_is_low(self):
        """dry_run defaults to True in plan_prune too."""
        p = plan_prune("test-datastore")
        assert p.risk == RISK_LOW

    def test_dry_run_true_blast_says_no_deletion(self):
        p = plan_prune("test-datastore", dry_run=True)
        text = " ".join(p.blast_radius).lower()
        assert "no backups" in text or "dry run" in text or "deletes nothing" in text

    def test_dry_run_false_blast_says_permanent_deletion(self):
        p = plan_prune("test-datastore", dry_run=False)
        text = " ".join(p.blast_radius).lower()
        assert "delete" in text or "permanent" in text

    def test_dry_run_false_blast_says_no_undo(self):
        p = plan_prune("test-datastore", dry_run=False)
        text = " ".join(p.blast_radius + [p.note]).lower()
        assert "undo" in text or "no undo" in text or "cannot" in text

    def test_low_risk_note_does_not_positively_claim_safe(self):
        """LOW means 'does not change state', NOT 'safe'. Note must not positively claim safety."""
        p = plan_prune("test-datastore", dry_run=True)
        # The note should NOT say things like "this is safe" or "operation is safe" —
        # saying "not 'safe'" (quoting the word to deny it) is fine and expected per planning doctrine.
        note = p.note.lower()
        # Check it doesn't say "is safe" or "this operation is safe" positively.
        assert "is safe" not in note
        assert "operation safe" not in note

    def test_action_string(self):
        assert plan_prune("test-datastore").action == "pbs_prune"

    def test_target_includes_store(self):
        p = plan_prune("test-datastore")
        assert "test-datastore" in p.target

    def test_rejects_invalid_store(self):
        with pytest.raises(ProximoError):
            plan_prune("bad/store")

    def test_rejects_invalid_backup_type(self):
        with pytest.raises(ProximoError):
            plan_prune("test-datastore", backup_type="lxc")


class TestPlanSnapshotDelete:
    def test_risk_is_high(self):
        p = plan_snapshot_delete("test-datastore", "vm", "100", 1717000000)
        assert p.risk == RISK_HIGH

    def test_action_string(self):
        p = plan_snapshot_delete("test-datastore", "vm", "100", 1717000000)
        assert p.action == "pbs_snapshot_delete"

    def test_blast_mentions_permanent(self):
        p = plan_snapshot_delete("test-datastore", "vm", "100", 1717000000)
        text = " ".join(p.blast_radius).lower()
        assert "permanent" in text or "no undo" in text or "cannot" in text

    def test_blast_includes_store_and_id(self):
        p = plan_snapshot_delete("test-datastore", "vm", "100", 1717000000)
        text = " ".join(p.blast_radius)
        assert "test-datastore" in text
        assert "100" in text

    def test_rejects_invalid_backup_type(self):
        with pytest.raises(ProximoError):
            plan_snapshot_delete("test-datastore", "docker", "100", 1717000000)

    def test_rejects_bad_backup_time(self):
        with pytest.raises(ProximoError):
            plan_snapshot_delete("test-datastore", "vm", "100", 0)


class TestPlanNamespaceCreate:
    def test_risk_is_low(self):
        p = plan_namespace_create("test-datastore", "team")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_namespace_create("test-datastore", "team")
        assert p.action == "pbs_namespace_create"

    def test_blast_says_additive(self):
        p = plan_namespace_create("test-datastore", "team")
        text = " ".join(p.blast_radius).lower()
        assert "additive" in text or "no data changed" in text or "no existing" in text

    def test_target_includes_store_and_name(self):
        p = plan_namespace_create("test-datastore", "team")
        assert "test-datastore" in p.target
        assert "team" in p.target

    def test_parent_reflected_in_target(self):
        p = plan_namespace_create("test-datastore", "prod", parent="team")
        assert "team" in p.target and "prod" in p.target

    def test_rejects_name_with_slash(self):
        with pytest.raises(ProximoError):
            plan_namespace_create("test-datastore", "a/b")


class TestPlanNamespaceDelete:
    def test_without_delete_groups_is_medium_risk(self):
        p = plan_namespace_delete("test-datastore", "team", delete_groups=False)
        assert p.risk == RISK_MEDIUM

    def test_with_delete_groups_is_high_risk(self):
        p = plan_namespace_delete("test-datastore", "team", delete_groups=True)
        assert p.risk == RISK_HIGH

    def test_default_delete_groups_false_is_medium(self):
        p = plan_namespace_delete("test-datastore", "team")
        assert p.risk == RISK_MEDIUM

    def test_delete_groups_high_blast_mentions_all_snapshots(self):
        p = plan_namespace_delete("test-datastore", "team", delete_groups=True)
        text = " ".join(p.blast_radius).lower()
        assert "snapshot" in text or "group" in text or "all" in text

    def test_delete_groups_high_blast_mentions_no_undo(self):
        p = plan_namespace_delete("test-datastore", "team", delete_groups=True)
        text = " ".join(p.blast_radius + [p.note]).lower()
        assert "undo" in text or "no undo" in text or "permanent" in text or "cannot" in text

    def test_delete_groups_false_blast_says_no_data_deleted(self):
        p = plan_namespace_delete("test-datastore", "team", delete_groups=False)
        text = " ".join(p.blast_radius).lower()
        assert "no backup data" in text or "not deleted" in text or "no data" in text

    def test_action_string(self):
        p = plan_namespace_delete("test-datastore", "team")
        assert p.action == "pbs_namespace_delete"

    def test_target_includes_store_and_ns(self):
        p = plan_namespace_delete("test-datastore", "team")
        assert "test-datastore" in p.target
        assert "team" in p.target

    def test_rejects_empty_ns(self):
        with pytest.raises(ProximoError):
            plan_namespace_delete("test-datastore", "")

    def test_rejects_traversal_ns(self):
        with pytest.raises(ProximoError):
            plan_namespace_delete("test-datastore", "../etc")

    def test_rejects_invalid_store(self):
        with pytest.raises(ProximoError):
            plan_namespace_delete("bad/store", "team")


class TestPlanVerifyStart:
    def test_risk_is_low(self):
        p = plan_verify_start("test-datastore")
        assert p.risk == RISK_LOW

    def test_action_string(self):
        p = plan_verify_start("test-datastore")
        assert p.action == "pbs_verify_start"

    def test_blast_says_non_destructive(self):
        p = plan_verify_start("test-datastore")
        text = " ".join(p.blast_radius).lower()
        assert "non-destructive" in text or "no data" in text or "not modified" in text

    def test_blast_mentions_io_impact(self):
        p = plan_verify_start("test-datastore")
        text = " ".join(p.blast_radius).lower()
        assert "i/o" in text or "io" in text or "heavy" in text or "impact" in text

    def test_low_risk_does_not_positively_claim_safe(self):
        """LOW = does not change state, NOT safe. Must not positively assert safety."""
        p = plan_verify_start("test-datastore")
        text = " ".join(p.blast_radius + p.risk_reasons + [p.note]).lower()
        # Saying "not 'safe'" (denying) is fine; saying "is safe" or "operation is safe" is not.
        assert "is safe" not in text
        assert "operation safe" not in text

    def test_target_includes_store(self):
        p = plan_verify_start("test-datastore")
        assert "test-datastore" in p.target

    def test_scope_filters_reflected(self):
        p = plan_verify_start("test-datastore", ns="team", backup_type="vm", backup_id="100")
        text = p.change.lower()
        assert "team" in text
        assert "vm" in text
        assert "100" in text

    def test_rejects_invalid_store(self):
        with pytest.raises(ProximoError):
            plan_verify_start("bad/store")

    def test_rejects_invalid_backup_type(self):
        with pytest.raises(ProximoError):
            plan_verify_start("test-datastore", backup_type="docker")


# ---------------------------------------------------------------------------
# PbsConfig is frozen / immutable
# ---------------------------------------------------------------------------

def test_pbsconfig_is_frozen():
    from dataclasses import FrozenInstanceError
    cfg = _cfg()
    with pytest.raises(FrozenInstanceError):
        cfg.base_url = "mutated"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Integration: Plan.as_dict() works for all plan functions
# ---------------------------------------------------------------------------

def test_all_plans_have_as_dict():
    plans = [
        plan_gc_start("test-datastore"),
        plan_prune("test-datastore"),
        plan_prune("test-datastore", dry_run=False),
        plan_snapshot_delete("test-datastore", "vm", "100", 1717000000),
        plan_namespace_create("test-datastore", "team"),
        plan_namespace_delete("test-datastore", "team"),
        plan_namespace_delete("test-datastore", "team", delete_groups=True),
        plan_verify_start("test-datastore"),
    ]
    for p in plans:
        d = p.as_dict()
        assert "action" in d
        assert "risk" in d
        assert "blast_radius" in d
        assert isinstance(d["blast_radius"], list)


# ---------------------------------------------------------------------------
# Redteam-hardening regression tests (2026-06-08)
# ---------------------------------------------------------------------------

def test_pbsbackend_fails_closed_on_unverified_tls():
    """A token-bearing backend must REFUSE to construct over unverified TLS (no ca_bundle)."""
    with pytest.raises(ProximoError):
        PbsBackend(_cfg(verify_tls=False))


def test_pbsbackend_fingerprint_refusal_names_env_var():
    # 1.6: a garbled PROXIMO_PBS_FINGERPRINT must not forward the validator's raw ValueError —
    # the message must name the exact env var and the expected shape (64-char SHA-256 hex).
    with pytest.raises(ProximoError, match="PROXIMO_PBS_FINGERPRINT") as exc_info:
        PbsBackend(_cfg(fingerprint="not-a-fingerprint"))
    assert "64" in str(exc_info.value)


def test_pbsbackend_ok_with_ca_bundle_even_when_verify_false():
    """A ca_bundle provides a trust anchor — construction is allowed."""
    backend = PbsBackend(_cfg(verify_tls=False, ca_bundle="/etc/ssl/certs/ca-certificates.crt"))
    assert backend.config.ca_bundle == "/etc/ssl/certs/ca-certificates.crt"


def test_pbsbackend_ok_with_default_verify():
    backend = PbsBackend(_cfg())  # verify_tls defaults True
    assert backend.config.verify_tls is True


def test_check_namespace_rejects_leading_slash():
    with pytest.raises(ProximoError):
        _check_namespace("/team/prod")


def test_check_namespace_rejects_trailing_slash():
    with pytest.raises(ProximoError):
        _check_namespace("team/prod/")


def test_check_namespace_allows_nested_and_root():
    assert _check_namespace("team/prod") == "team/prod"
    assert _check_namespace("") == ""
    assert _check_namespace(None) is None


def test_pbsbackend_ca_bundle_path_no_httpx_deprecation():
    """PBS backend with a CA-bundle path must not hit httpx's deprecated verify=<str>."""
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        backend = PbsBackend(_cfg(verify_tls=False, ca_bundle="/etc/ssl/certs/ca-certificates.crt"))
    assert backend._client is not None
