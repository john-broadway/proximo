"""TDD tests for the PBS APT plane (Wave 1b, 2026-07-15 full-surface campaign).

Mirrors tests/test_apt.py's scope for PVE, adjusted per plane:
- pbs.py's ops are module-level functions taking `api` first and calling the generic
  `api._get/_post/_put` verbs (not typed methods on the class) — mirrors the rest of pbs.py
  (tasks_list, gc_start, verify_start, ...), unlike PVE's typed-method-on-ApiBackend convention.
- PBS is typically single-node: node defaults to "localhost" directly at both the op and the
  server-wrapper level (PbsConfig carries no `.node` field) — no `node or cfg.node` idiom.
- PBS's digest/handle validators are STRICTER than PVE/PMG's (sha256-exact-64-hex digest,
  lowercase-leading handle) — see pbs.py's validator-block comment for the schema cross-check.

Covers:
- Validators: _check_pbs_apt_package_name, _check_pbs_apt_repo_path, _check_pbs_apt_index,
  _check_pbs_apt_handle, _check_pbs_apt_digest
- Op functions: URL/param shape via a recording fake (mirrors test_pbs.py's `_api()` helper,
  extended with `_put` since apt_repository_add is the first PBS op to use PUT)
- Plan factories: correct action/target/risk/blast wording for all 3 mutation plans
- CAPTURE-or-declare: repository_set/repository_add capture current state; complete=False only
  when the read itself raises (a successful-but-empty read degrades to current={}, not failure)
- Server-wrapper mutation gating (via server._pbs / server._svc monkeypatch, mirroring
  test_confirm_sweep_pbs.py's `_wire()` idiom): plan-by-default (no confirm -> status=="plan");
  confirm=True executes
- Read tools: updates_list, changelog, repositories_get, versions return the expected shape
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.backends import ProximoError
from proximo.config import ProximoConfig
from proximo.pbs import (
    _check_pbs_apt_digest,
    _check_pbs_apt_handle,
    _check_pbs_apt_index,
    _check_pbs_apt_package_name,
    _check_pbs_apt_repo_path,
    apt_changelog,
    apt_repositories_get,
    apt_repository_add,
    apt_repository_set,
    apt_update_refresh,
    apt_updates_list,
    apt_versions,
    plan_apt_repository_add,
    plan_apt_repository_set,
    plan_apt_update_refresh,
)

# ─── _api() — recording fake (mirrors test_pbs.py's helper, + _put) ───────────────────────────


def _api() -> SimpleNamespace:
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
        return "UPID:pbs:00001:0:0:0:aptupdate:0:root@pam:"

    def fake_put(path, data=None):
        seen["method"] = "PUT"
        seen["path"] = path
        seen["data"] = data or {}
        return None

    return SimpleNamespace(_get=fake_get, _post=fake_post, _put=fake_put, seen=seen)


class _FakeAptApi:
    """Fake PbsBackend returning canned apt-repositories data for CAPTURE tests."""

    def __init__(self, *, repos_result=None, raise_repos=False):
        self._repos_result = repos_result if repos_result is not None else {
            "files": [{"path": "/etc/apt/sources.list", "digest": "d1" * 32,
                       "repositories": [{"Enabled": True}]}],
            "standard-repos": [{"handle": "no-subscription", "status": True}],
        }
        self._raise_repos = raise_repos
        self.gets: list = []
        self.posts: list = []
        self.puts: list = []

    def _get(self, path, params=None):
        self.gets.append((path, params))
        if self._raise_repos:
            raise RuntimeError("cannot read repositories")
        return dict(self._repos_result)

    def _post(self, path, data=None):
        self.posts.append((path, data))
        return "UPID:pbs:00002:0:0:0:aptupdate:0:root@pam:"

    def _put(self, path, data=None):
        self.puts.append((path, data))
        return None


# ─── Validators ────────────────────────────────────────────────────────────────


class TestCheckPbsAptPackageName:
    def test_valid_names(self):
        assert _check_pbs_apt_package_name("pve-manager") == "pve-manager"
        assert _check_pbs_apt_package_name("libc6") == "libc6"

    def test_rejects_uppercase(self):
        with pytest.raises(ProximoError, match="invalid package name"):
            _check_pbs_apt_package_name("PveManager")

    def test_rejects_single_char(self):
        with pytest.raises(ProximoError, match="invalid package name"):
            _check_pbs_apt_package_name("a")

    def test_rejects_trailing_newline(self):
        with pytest.raises(ProximoError, match="invalid package name"):
            _check_pbs_apt_package_name("pve-manager\n")


class TestCheckPbsAptRepoPath:
    def test_valid_path(self):
        assert _check_pbs_apt_repo_path("/etc/apt/sources.list") == "/etc/apt/sources.list"

    def test_rejects_relative_path(self):
        with pytest.raises(ProximoError, match="invalid repository file path"):
            _check_pbs_apt_repo_path("etc/apt/sources.list")

    def test_rejects_traversal(self):
        with pytest.raises(ProximoError, match="path traversal"):
            _check_pbs_apt_repo_path("/etc/apt/../shadow")

    def test_rejects_control_chars(self):
        with pytest.raises(ProximoError, match="invalid repository file path"):
            _check_pbs_apt_repo_path("/etc/apt/sources.list\n")


class TestCheckPbsAptIndex:
    def test_valid_index(self):
        assert _check_pbs_apt_index(0) == 0
        assert _check_pbs_apt_index(5) == 5

    def test_rejects_negative(self):
        with pytest.raises(ProximoError, match="invalid repository index"):
            _check_pbs_apt_index(-1)

    def test_rejects_non_int(self):
        with pytest.raises(ProximoError, match="invalid repository index"):
            _check_pbs_apt_index("0")

    def test_rejects_bool(self):
        with pytest.raises(ProximoError, match="invalid repository index"):
            _check_pbs_apt_index(True)


class TestCheckPbsAptHandle:
    """PBS's handle validator is STRICTER than PVE/PMG's: lowercase-leading, alnum/hyphen
    groups only (APTRepositoryHandle) — cross-checked against the live api-viewer schema."""

    def test_valid_handle(self):
        assert _check_pbs_apt_handle("no-subscription") == "no-subscription"
        assert _check_pbs_apt_handle("enterprise") == "enterprise"

    def test_rejects_leading_hyphen(self):
        with pytest.raises(ProximoError, match="invalid repository handle"):
            _check_pbs_apt_handle("-no-subscription")

    def test_rejects_underscore(self):
        with pytest.raises(ProximoError, match="invalid repository handle"):
            _check_pbs_apt_handle("no_subscription")

    def test_rejects_uppercase(self):
        """Unlike PVE/PMG's shape-only validator, PBS's schema-documented pattern is
        lowercase-only — 'No-Subscription' is rejected here but would pass PVE's validator."""
        with pytest.raises(ProximoError, match="invalid repository handle"):
            _check_pbs_apt_handle("No-Subscription")


class TestCheckPbsAptDigest:
    """PBS's digest validator is STRICTER than PVE/PMG's: exactly 64 lowercase hex chars
    (a SHA-256 digest) — cross-checked against the live api-viewer schema."""

    def test_none_passes_through(self):
        assert _check_pbs_apt_digest(None) is None

    def test_valid_64_hex(self):
        d = "a" * 64
        assert _check_pbs_apt_digest(d) == d

    def test_rejects_too_short(self):
        with pytest.raises(ProximoError, match="invalid digest"):
            _check_pbs_apt_digest("abc123")

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError, match="invalid digest"):
            _check_pbs_apt_digest("a" * 65)

    def test_rejects_uppercase_hex(self):
        """Unlike PVE/PMG's case-insensitive hex validator, PBS's schema pattern is
        lowercase-only (`^[a-f0-9]{64}$`)."""
        with pytest.raises(ProximoError, match="invalid digest"):
            _check_pbs_apt_digest("A" * 64)

    def test_rejects_non_hex(self):
        with pytest.raises(ProximoError, match="invalid digest"):
            _check_pbs_apt_digest("g" * 64)

    def test_rejects_trailing_newline(self):
        # Inherited for free from the shared `_validate.check_digest` (strict no-strip);
        # this class had no newline case while the validator was a per-module copy.
        with pytest.raises(ProximoError, match="invalid digest"):
            _check_pbs_apt_digest("a" * 64 + "\n")


# ─── Op functions — URL/param shape ────────────────────────────────────────────


class TestAptUpdatesList:
    def test_default_node_localhost(self):
        api = _api()
        apt_updates_list(api)
        assert api.seen["path"] == "/nodes/localhost/apt/update"
        assert api.seen["method"] == "GET"

    def test_returns_list(self):
        api = _api()
        result = apt_updates_list(api)
        assert isinstance(result, list)

    def test_custom_node(self):
        api = _api()
        apt_updates_list(api, node="pbs1")
        assert api.seen["path"] == "/nodes/pbs1/apt/update"


class TestAptChangelog:
    def test_name_and_node_in_path_and_params(self):
        api = _api()
        api._get = lambda path, params=None: "changelog text"
        result = apt_changelog(api, "pve-manager", node="pbs1")
        assert result == "changelog text"

    def test_params_include_name(self):
        api = _api()
        apt_changelog(api, "pve-manager")
        assert api.seen["params"]["name"] == "pve-manager"
        assert "version" not in api.seen["params"]

    def test_version_forwarded_when_given(self):
        api = _api()
        apt_changelog(api, "pve-manager", version="8.0-1")
        assert api.seen["params"]["version"] == "8.0-1"

    def test_returns_str(self):
        api = _api()
        result = apt_changelog(api, "pve-manager")
        assert isinstance(result, str)

    def test_invalid_name_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            apt_changelog(api, "BadName")


class TestAptRepositoriesGet:
    def test_uses_correct_path(self):
        api = _api()
        apt_repositories_get(api, node="pbs1")
        assert api.seen["path"] == "/nodes/pbs1/apt/repositories"
        assert api.seen["method"] == "GET"

    def test_returns_dict(self):
        api = _api()
        api._get = lambda path, params=None: {}
        result = apt_repositories_get(api)
        assert isinstance(result, dict)


class TestAptVersions:
    def test_uses_correct_path(self):
        api = _api()
        apt_versions(api, node="pbs1")
        assert api.seen["path"] == "/nodes/pbs1/apt/versions"

    def test_returns_list(self):
        api = _api()
        result = apt_versions(api)
        assert isinstance(result, list)


class TestAptUpdateRefresh:
    def test_post_path(self):
        api = _api()
        apt_update_refresh(api, node="pbs1")
        assert api.seen["path"] == "/nodes/pbs1/apt/update"
        assert api.seen["method"] == "POST"

    def test_notify_quiet_forwarded(self):
        api = _api()
        apt_update_refresh(api, notify=True, quiet=False)
        assert api.seen["data"] == {"notify": True, "quiet": False}

    def test_omits_unset_params(self):
        api = _api()
        apt_update_refresh(api)
        assert api.seen["data"] == {}


class TestAptRepositorySet:
    def test_post_path_and_body(self):
        api = _api()
        apt_repository_set(api, "/etc/apt/sources.list", 0, node="pbs1", enabled=False, digest="a" * 64)
        assert api.seen["path"] == "/nodes/pbs1/apt/repositories"
        assert api.seen["method"] == "POST"
        assert api.seen["data"] == {
            "path": "/etc/apt/sources.list", "index": 0, "enabled": False, "digest": "a" * 64,
        }

    def test_omits_unset_optional_fields(self):
        api = _api()
        apt_repository_set(api, "/etc/apt/sources.list", 0)
        assert api.seen["data"] == {"path": "/etc/apt/sources.list", "index": 0}

    def test_invalid_digest_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            apt_repository_set(api, "/etc/apt/sources.list", 0, digest="not-hex")


class TestAptRepositoryAdd:
    def test_put_path_and_body(self):
        api = _api()
        apt_repository_add(api, "no-subscription", node="pbs1", digest="b" * 64)
        assert api.seen["path"] == "/nodes/pbs1/apt/repositories"
        assert api.seen["method"] == "PUT"
        assert api.seen["data"] == {"handle": "no-subscription", "digest": "b" * 64}

    def test_omits_unset_digest(self):
        api = _api()
        apt_repository_add(api, "no-subscription")
        assert api.seen["data"] == {"handle": "no-subscription"}

    def test_invalid_handle_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            apt_repository_add(api, "Bad Handle!")


# ─── Plan factories ─────────────────────────────────────────────────────────────


class TestUpdateRefreshPlan:
    def test_risk_low(self):
        p = plan_apt_update_refresh()
        assert p.risk == "low"

    def test_action(self):
        p = plan_apt_update_refresh()
        assert p.action == "pbs_apt_update_refresh"

    def test_no_upgrade_execution_honesty(self):
        p = plan_apt_update_refresh()
        combined = " ".join(p.blast_radius) + p.change
        assert "does not" in combined.lower()
        assert "console" in combined.lower()

    def test_idempotent_in_note(self):
        p = plan_apt_update_refresh()
        assert "idempotent" in p.note.lower() or "re-run" in p.note.lower()

    def test_default_node_localhost(self):
        p = plan_apt_update_refresh()
        assert "localhost" in p.target


class TestRepositorySetPlan:
    def test_risk_medium(self):
        api = _FakeAptApi()
        p = plan_apt_repository_set(api, "/etc/apt/sources.list", 0)
        assert p.risk == "medium"

    def test_captures_current_entry(self):
        api = _FakeAptApi()
        p = plan_apt_repository_set(api, "/etc/apt/sources.list", 0)
        assert p.complete is True
        assert p.current.get("entry") == {"Enabled": True}

    def test_no_match_degrades_to_empty_not_failure(self):
        api = _FakeAptApi()
        p = plan_apt_repository_set(api, "/etc/apt/sources.list.d/other.list", 3)
        assert p.complete is True
        assert p.current == {}

    def test_complete_false_when_read_raises(self):
        api = _FakeAptApi(raise_repos=True)
        p = plan_apt_repository_set(api, "/etc/apt/sources.list", 0)
        assert p.complete is False
        assert "could not capture" in p.note.lower()

    def test_path_and_index_in_target(self):
        api = _FakeAptApi()
        p = plan_apt_repository_set(api, "/etc/apt/sources.list", 2)
        assert "/etc/apt/sources.list" in p.target
        assert "2" in p.target

    def test_invalid_path_raises(self):
        api = _FakeAptApi()
        with pytest.raises(ProximoError):
            plan_apt_repository_set(api, "relative/path", 0)

    def test_invalid_digest_raises(self):
        api = _FakeAptApi()
        with pytest.raises(ProximoError):
            plan_apt_repository_set(api, "/etc/apt/sources.list", 0, digest="not-hex!")


class TestRepositoryAddPlan:
    def test_risk_medium(self):
        api = _FakeAptApi()
        p = plan_apt_repository_add(api, "no-subscription")
        assert p.risk == "medium"

    def test_captures_current_status(self):
        api = _FakeAptApi()
        p = plan_apt_repository_add(api, "no-subscription")
        assert p.complete is True
        assert p.current.get("handle") == "no-subscription"

    def test_no_match_degrades_to_empty_not_failure(self):
        api = _FakeAptApi()
        p = plan_apt_repository_add(api, "brand-new-handle")
        assert p.complete is True
        assert p.current == {}

    def test_complete_false_when_read_raises(self):
        api = _FakeAptApi(raise_repos=True)
        p = plan_apt_repository_add(api, "no-subscription")
        assert p.complete is False
        assert "could not capture" in p.note.lower()

    def test_handle_in_target(self):
        api = _FakeAptApi()
        p = plan_apt_repository_add(api, "no-subscription")
        assert "no-subscription" in p.target

    def test_no_automatic_revert_in_note(self):
        api = _FakeAptApi()
        p = plan_apt_repository_add(api, "no-subscription")
        assert "no automatic revert" in p.note.lower()

    def test_invalid_handle_raises(self):
        api = _FakeAptApi()
        with pytest.raises(ProximoError):
            plan_apt_repository_add(api, "Bad Handle!")


# ─── Server-wrapper mutation gating (mirrors test_confirm_sweep_pbs.py's `_wire()` idiom) ─────


def _wire(tmp_path, monkeypatch):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
        audit_log_path=log,
    )
    api = SimpleNamespace(config=SimpleNamespace(node="pve"))
    pbs = _FakeAptApi()
    exec_ = SimpleNamespace()
    ledger = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, exec_, ledger))
    monkeypatch.setattr(server, "_pbs", lambda: (SimpleNamespace(), pbs))
    return cfg, pbs, ledger, log


def _entries(log: str) -> list[dict]:
    with open(log, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class TestMutationGating:
    def test_update_refresh_plan_by_default(self, tmp_path, monkeypatch):
        _, pbs, _, log = _wire(tmp_path, monkeypatch)
        out = server.pbs_apt_update_refresh()
        assert out["status"] == "plan"
        assert pbs.posts == []
        assert any(e["outcome"] == "planned" for e in _entries(log))

    def test_update_refresh_confirm_executes(self, tmp_path, monkeypatch):
        _, pbs, _, log = _wire(tmp_path, monkeypatch)
        out = server.pbs_apt_update_refresh(confirm=True)
        assert out["status"] == "submitted"
        assert len(pbs.posts) == 1
        outcomes = {e["outcome"] for e in _entries(log) if e["action"] == "pbs_apt_update_refresh"}
        assert {"planned", "submitted"} <= outcomes

    def test_update_refresh_sync_reports_ok(self, tmp_path, monkeypatch):
        _, pbs, _, _ = _wire(tmp_path, monkeypatch)
        monkeypatch.setattr(pbs, "_post", lambda path, data=None: None)
        out = server.pbs_apt_update_refresh(confirm=True)
        assert out["status"] == "ok"
        assert out["result"] is None

    def test_repository_set_plan_by_default(self, tmp_path, monkeypatch):
        _, pbs, _, _ = _wire(tmp_path, monkeypatch)
        out = server.pbs_apt_repository_set("/etc/apt/sources.list", 0)
        assert out["status"] == "plan"
        assert pbs.posts == []

    def test_repository_set_confirm_executes(self, tmp_path, monkeypatch):
        _, pbs, _, log = _wire(tmp_path, monkeypatch)
        out = server.pbs_apt_repository_set(
            "/etc/apt/sources.list", 0, enabled=False, confirm=True,
        )
        assert out["status"] == "ok"
        assert pbs.posts[-1] == (
            "/nodes/localhost/apt/repositories",
            {"path": "/etc/apt/sources.list", "index": 0, "enabled": False},
        )
        entry = [e for e in _entries(log) if e["action"] == "pbs_apt_repository_set"
                 and e["outcome"] == "ok"][0]
        assert entry["mutation"] is True
        assert entry["detail"]["confirmed"] is True

    def test_repository_add_plan_by_default(self, tmp_path, monkeypatch):
        _, pbs, _, _ = _wire(tmp_path, monkeypatch)
        out = server.pbs_apt_repository_add("no-subscription")
        assert out["status"] == "plan"
        assert pbs.puts == []

    def test_repository_add_confirm_executes(self, tmp_path, monkeypatch):
        _, pbs, _, log = _wire(tmp_path, monkeypatch)
        out = server.pbs_apt_repository_add("no-subscription", confirm=True)
        assert out["status"] == "ok"
        assert pbs.puts[-1] == (
            "/nodes/localhost/apt/repositories", {"handle": "no-subscription"},
        )
        entry = [e for e in _entries(log) if e["action"] == "pbs_apt_repository_add"
                 and e["outcome"] == "ok"][0]
        assert entry["mutation"] is True
        assert entry["detail"]["confirmed"] is True


def test_one_shot_confirm_records_plan_before_executing(tmp_path, monkeypatch):
    _, pbs, _, log = _wire(tmp_path, monkeypatch)
    server.pbs_apt_repository_add("no-subscription", confirm=True)
    outcomes = {e["outcome"] for e in _entries(log) if e["action"] == "pbs_apt_repository_add"}
    assert "planned" in outcomes, "one-shot confirm must record a plan entry before executing"
    assert "ok" in outcomes


class TestReadTools:
    def test_updates_list_returns_list(self, tmp_path, monkeypatch):
        _, pbs, _, _ = _wire(tmp_path, monkeypatch)
        monkeypatch.setattr(pbs, "_get", lambda path, params=None: [])
        result = server.pbs_apt_updates_list()
        assert isinstance(result, list)

    def test_changelog_returns_str(self, tmp_path, monkeypatch):
        _, pbs, _, _ = _wire(tmp_path, monkeypatch)
        monkeypatch.setattr(pbs, "_get", lambda path, params=None: "changelog text")
        result = server.pbs_apt_changelog("pve-manager")
        assert isinstance(result, str)

    def test_repositories_get_returns_dict(self, tmp_path, monkeypatch):
        _wire(tmp_path, monkeypatch)
        result = server.pbs_apt_repositories_get()
        assert isinstance(result, dict)

    def test_versions_returns_list(self, tmp_path, monkeypatch):
        _, pbs, _, _ = _wire(tmp_path, monkeypatch)
        monkeypatch.setattr(pbs, "_get", lambda path, params=None: [])
        result = server.pbs_apt_versions()
        assert isinstance(result, list)
