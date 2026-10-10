"""Backup & Restore pillar tests — fully mocked, no live Proxmox.

Mirrors test_planning.py and test_backends.py:
- Op functions: real ApiBackend(_cfg()) with monkeypatched _get/_post/_delete.
  This gives us config.node="pve" for free and mirrors the existing test pattern.
- Plan functions: tiny fake apis (only the methods each plan needs).
- Every test is self-contained — no shared mutable state.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from proximo.backends import ApiBackend, ProximoError
from proximo.backup import (
    backup_delete,
    backup_list,
    plan_backup,
    plan_backup_delete,
    plan_restore,
    restore_guest,
    vzdump_backup,
)
from proximo.config import ProximoConfig
from proximo.planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM


def _cfg(**kw) -> ProximoConfig:
    base = dict(
        api_base_url="https://x:8006/api2/json",
        node="pve",
        token_path="/run/x",
        ct_allowlist=frozenset({"*"}),
    )
    base.update(kw)
    return ProximoConfig(**base)


# ── OPERATION: vzdump_backup ──────────────────────────────────────────────────


def test_vzdump_backup_posts_correct_path_and_data(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(
        api, "_post",
        lambda path, data=None: seen.update(path=path, data=data) or "UPID:pve:1:0:0:0:vzdump:102:root@pam:",
    )
    result = vzdump_backup(api, "102", "local", mode="snapshot", compress="zstd")
    assert seen["path"] == "/nodes/pve/vzdump"
    assert seen["data"] == {"vmid": "102", "storage": "local", "mode": "snapshot", "compress": "zstd"}
    assert result.startswith("UPID:")


def test_vzdump_backup_uses_provided_node(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_post", lambda path, data=None: seen.update(path=path) or "U")
    vzdump_backup(api, "102", "local", node="node2")
    assert "/nodes/node2/vzdump" in seen["path"]


def test_vzdump_backup_rejects_invalid_mode():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError, match="invalid backup mode"):
        vzdump_backup(api, "102", "local", mode="live")


def test_vzdump_backup_rejects_bad_vmid():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError):
        vzdump_backup(api, "not-a-number", "local")


def test_vzdump_backup_rejects_bad_storage():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError):
        vzdump_backup(api, "102", "stor/../../etc")


def test_vzdump_backup_rejects_bad_node():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError):
        vzdump_backup(api, "102", "local", node="bad node!")


# ── OPERATION: backup_list ────────────────────────────────────────────────────


def test_backup_list_builds_correct_path(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(
        api, "_get",
        lambda path: seen.update(path=path) or [{"volid": "local:backup/x.tar.zst", "size": 1024}],
    )
    result = backup_list(api, "local")
    assert seen["path"] == "/nodes/pve/storage/local/content?content=backup"
    assert result[0]["volid"] == "local:backup/x.tar.zst"


def test_backup_list_uses_provided_node(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_get", lambda path: seen.update(path=path) or [])
    backup_list(api, "local", node="node3")
    assert "/nodes/node3/" in seen["path"]


def test_backup_list_returns_empty_list_when_none(monkeypatch):
    api = ApiBackend(_cfg())
    monkeypatch.setattr(api, "_get", lambda path: None)
    assert backup_list(api, "local") == []


def test_backup_list_rejects_bad_storage():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError):
        backup_list(api, "stor age!")


@pytest.mark.parametrize("storage", [".", ".."])
def test_backup_list_rejects_dot_segment_storage(storage):
    # '.'/'..' pass the bare charset regex but would normalize the
    # /storage/{storage} URL segment onto a different endpoint (traversal).
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError, match="traversal"):
        backup_list(api, storage)


# ── OPERATION: backup_delete ─────────────────────────────────────────────────


_VALID_VOLID = "local:backup/vzdump-lxc-102-2026_06_08.tar.zst"


def test_backup_delete_builds_correct_path_with_encoded_volid(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    _fake_upid = "UPID:pve:2:0:0:0:delete:local:root@pam:"
    monkeypatch.setattr(api, "_delete",
                        lambda path, params=None: seen.update(path=path) or _fake_upid)
    backup_delete(api, "local", _VALID_VOLID)
    # Colons and slashes must be percent-encoded in the path segment
    assert "%3A" in seen["path"] or "%2F" in seen["path"]
    assert "/nodes/pve/storage/local/content/" in seen["path"]
    # The raw volid must NOT appear unencoded in the path
    assert _VALID_VOLID not in seen["path"]


def test_backup_delete_url_encodes_colon_and_slash(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_delete", lambda path, params=None: seen.update(path=path) or None)
    backup_delete(api, "local", _VALID_VOLID)
    # Verify specific encoding
    assert "local%3Abackup%2F" in seen["path"]


def test_backup_delete_returns_none_for_sync_delete(monkeypatch):
    """Directory storage may return None (synchronous delete) rather than a UPID.
    We must not raise on None — return it as-is."""
    api = ApiBackend(_cfg())
    monkeypatch.setattr(api, "_delete", lambda path, params=None: None)
    result = backup_delete(api, "local", _VALID_VOLID)
    assert result is None


def test_backup_delete_rejects_traversal_in_volid():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError, match="traversal"):
        backup_delete(api, "local", "local:backup/../../../etc/passwd")


@pytest.mark.parametrize("storage", [".", ".."])
def test_backup_delete_rejects_dot_segment_storage(storage):
    # '.'/'..' pass the bare charset regex but would normalize the
    # /storage/{storage} URL segment onto a different endpoint (traversal).
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError, match="traversal"):
        backup_delete(api, storage, _VALID_VOLID)


def test_backup_delete_rejects_volid_wrong_colon_count():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError):
        backup_delete(api, "local", "no-colon-at-all")


def test_backup_delete_rejects_volid_with_shell_specials():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError):
        backup_delete(api, "local", "local:backup/$(rm -rf /)")


def test_backup_delete_rejects_bad_node():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError):
        backup_delete(api, "local", _VALID_VOLID, node="bad\nnode")


# ── OPERATION: restore_guest ─────────────────────────────────────────────────


def test_restore_lxc_posts_to_lxc_endpoint_with_correct_data(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_post", lambda path, data=None: seen.update(path=path, data=data) or "U")
    restore_guest(api, "102", _VALID_VOLID, "local", kind="lxc")
    assert seen["path"] == "/nodes/pve/lxc"
    assert seen["data"]["vmid"] == "102"
    assert seen["data"]["ostemplate"] == _VALID_VOLID
    assert seen["data"]["storage"] == "local"
    assert seen["data"]["restore"] == 1
    assert "archive" not in seen["data"]


def test_restore_pool_sent_when_provided(monkeypatch):
    for kind in ("lxc", "qemu"):
        api = ApiBackend(_cfg())
        seen: dict = {}
        monkeypatch.setattr(api, "_post",
                            lambda path, data=None, _s=seen: _s.update(data=data) or "U")
        restore_guest(api, "102", _VALID_VOLID, "local", kind=kind, pool="proximo-test")
        assert seen["data"]["pool"] == "proximo-test"


def test_restore_pool_absent_when_not_provided(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_post", lambda path, data=None: seen.update(data=data) or "U")
    restore_guest(api, "102", _VALID_VOLID, "local", kind="qemu")
    assert "pool" not in seen["data"]


def test_restore_lxc_with_force_sends_force_flag(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_post", lambda path, data=None: seen.update(path=path, data=data) or "U")
    restore_guest(api, "102", _VALID_VOLID, "local", kind="lxc", force=True)
    assert seen["data"]["force"] == 1


def test_restore_qemu_posts_to_qemu_endpoint_with_correct_data(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_post", lambda path, data=None: seen.update(path=path, data=data) or "U")
    restore_guest(api, "102", _VALID_VOLID, "local", kind="qemu")
    assert seen["path"] == "/nodes/pve/qemu"
    assert seen["data"]["vmid"] == "102"
    assert seen["data"]["archive"] == _VALID_VOLID
    # QEMU restore does NOT include ostemplate or restore:1
    assert "ostemplate" not in seen["data"]
    assert "restore" not in seen["data"]


def test_restore_qemu_with_force(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_post", lambda path, data=None: seen.update(path=path, data=data) or "U")
    restore_guest(api, "102", _VALID_VOLID, "local", kind="qemu", force=True)
    assert seen["data"]["force"] == 1


def test_restore_guest_uses_provided_node(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_post", lambda path, data=None: seen.update(path=path) or "U")
    restore_guest(api, "102", _VALID_VOLID, "local", kind="lxc", node="nodeX")
    assert "/nodes/nodeX/" in seen["path"]


def test_restore_guest_rejects_bad_kind():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError):
        restore_guest(api, "102", _VALID_VOLID, "local", kind="docker")


def test_restore_guest_rejects_bad_vmid():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError):
        restore_guest(api, "lxc/../../102", _VALID_VOLID, "local")


# ── PLAN: plan_backup ─────────────────────────────────────────────────────────


def test_plan_backup_snapshot_is_low_risk():
    p = plan_backup("102", "local", mode="snapshot", kind="lxc")
    assert p.risk == RISK_LOW
    assert p.action == "pve_backup"


def test_plan_backup_snapshot_blast_mentions_online():
    p = plan_backup("102", "local", mode="snapshot")
    text = " ".join(p.blast_radius + p.risk_reasons).lower()
    assert "online" in text or "running" in text or "live" in text


def test_plan_backup_suspend_is_medium():
    p = plan_backup("102", "local", mode="suspend")
    assert p.risk == RISK_MEDIUM


def test_plan_backup_suspend_blast_mentions_pause_or_suspend():
    p = plan_backup("102", "local", mode="suspend")
    text = " ".join(p.blast_radius + p.risk_reasons).lower()
    assert "suspend" in text or "pause" in text


def test_plan_backup_stop_is_high():
    p = plan_backup("102", "local", mode="stop")
    assert p.risk == RISK_HIGH


def test_plan_backup_stop_blast_mentions_halt_or_stop():
    p = plan_backup("102", "local", mode="stop")
    text = " ".join(p.blast_radius + p.risk_reasons).lower()
    # Must warn about downtime / halting
    assert "stop" in text or "halt" in text or "offline" in text or "downtime" in text


def test_plan_backup_does_not_claim_safe():
    """LOW means 'does not change state', NOT 'safe' — must not use that word."""
    for mode in ("snapshot", "suspend", "stop"):
        p = plan_backup("102", "local", mode=mode)
        text = " ".join(p.blast_radius + p.risk_reasons).lower()
        assert "safe" not in text


def test_plan_backup_rejects_invalid_mode():
    # plan_backup now validates mode (mirroring vzdump_backup), so the plan leg
    # fails fast with a clear error instead of returning a plan whose to_proceed
    # says "re-call with confirm=true" for an operation that would always raise.
    with pytest.raises(ProximoError, match="invalid backup mode"):
        plan_backup("102", "local", mode="turbo")


def test_plan_backup_target_includes_vmid():
    p = plan_backup("102", "local")
    assert "102" in p.target


def test_plan_backup_change_mentions_storage():
    p = plan_backup("102", "local")
    assert "local" in p.change


# ── PLAN: plan_restore ────────────────────────────────────────────────────────


class _GuestExistsApi:
    """Fake api where guest_status returns a live guest dict."""

    def __init__(self, status: dict):
        self._status = status
        self.calls: list = []

    def guest_status(self, vmid, kind="lxc", node=None):
        self.calls.append((vmid, kind, node))
        return self._status


class _GuestMissingApi:
    """Fake api where guest_status raises (guest not found)."""

    def guest_status(self, vmid, kind="lxc", node=None):
        raise ProximoError(f"guest {vmid} not found")


def test_plan_restore_existing_with_force_is_high():
    api = _GuestExistsApi({"status": "running", "name": "webserver"})
    p = plan_restore(api, "102", _VALID_VOLID, force=True)
    assert p.risk == RISK_HIGH


def test_plan_restore_existing_with_force_blast_names_victim():
    api = _GuestExistsApi({"status": "running", "name": "webserver"})
    p = plan_restore(api, "102", _VALID_VOLID, force=True)
    blast = " ".join(p.blast_radius).lower()
    assert "overwrite" in blast or "destroy" in blast
    assert "102" in blast


def test_plan_restore_existing_with_force_blast_names_archive():
    api = _GuestExistsApi({"status": "running", "name": "webserver"})
    p = plan_restore(api, "102", _VALID_VOLID, force=True)
    assert _VALID_VOLID in " ".join(p.blast_radius)


def test_plan_restore_existing_with_force_blast_names_guest_name():
    api = _GuestExistsApi({"status": "stopped", "name": "myserver"})
    p = plan_restore(api, "102", _VALID_VOLID, force=True)
    blast = " ".join(p.blast_radius)
    assert "myserver" in blast


def test_plan_restore_existing_without_force_is_not_high_contradiction():
    """exists+no-force → restore FAILS → blast must NOT claim it destroys anything."""
    api = _GuestExistsApi({"status": "running", "name": "web"})
    p = plan_restore(api, "102", _VALID_VOLID, force=False)
    blast = " ".join(p.blast_radius).lower()
    # Must clearly state it will fail
    assert "fail" in blast
    # Must NOT claim destruction/overwrite (that would be contradictory — nothing is destroyed)
    assert "destroy" not in blast
    assert "overwrite" not in blast
    assert "discards all" not in blast


def test_plan_restore_existing_without_force_names_the_reason():
    api = _GuestExistsApi({"status": "running", "name": "web"})
    p = plan_restore(api, "102", _VALID_VOLID, force=False)
    reasons_text = " ".join(p.risk_reasons + p.blast_radius).lower()
    assert "force" in reasons_text
    assert "exists" in reasons_text


def test_plan_restore_not_found_is_medium():
    api = _GuestMissingApi()
    p = plan_restore(api, "102", _VALID_VOLID)
    assert p.risk == RISK_MEDIUM


def test_plan_restore_not_found_blast_says_creates():
    api = _GuestMissingApi()
    p = plan_restore(api, "102", _VALID_VOLID)
    blast = " ".join(p.blast_radius).lower()
    assert "creates" in blast or "create" in blast


def test_plan_restore_not_found_blast_names_archive():
    api = _GuestMissingApi()
    p = plan_restore(api, "102", _VALID_VOLID)
    assert _VALID_VOLID in " ".join(p.blast_radius)


def test_plan_restore_action_name():
    api = _GuestMissingApi()
    p = plan_restore(api, "102", _VALID_VOLID)
    assert p.action == "pve_restore"


def test_plan_restore_guest_status_called_with_correct_args():
    api = _GuestExistsApi({"status": "running", "name": "x"})
    plan_restore(api, "102", _VALID_VOLID, kind="lxc", node=None, force=True)
    assert api.calls == [("102", "lxc", None)]


def test_plan_restore_existing_current_has_live_facts():
    api = _GuestExistsApi({"status": "running", "name": "webserver"})
    p = plan_restore(api, "102", _VALID_VOLID, force=True)
    assert p.current.get("status") == "running"
    assert p.current.get("name") == "webserver"


# ── PLAN: plan_backup_delete ─────────────────────────────────────────────────


def test_plan_backup_delete_is_high():
    # A backup is a last-resort recovery copy; deleting it is unrecoverable -> HIGH (not MEDIUM).
    p = plan_backup_delete(_bk_api([]), "local", _VALID_VOLID)
    assert p.risk == RISK_HIGH


def test_plan_backup_delete_action_name():
    p = plan_backup_delete(_bk_api([]), "local", _VALID_VOLID)
    assert p.action == "pve_backup_delete"


def test_plan_backup_delete_blast_names_volid():
    p = plan_backup_delete(_bk_api([]), "local", _VALID_VOLID)
    blast = " ".join(p.blast_radius)
    assert _VALID_VOLID in blast


def test_plan_backup_delete_blast_says_cannot_restore():
    p = plan_backup_delete(_bk_api([]), "local", _VALID_VOLID)
    blast = " ".join(p.blast_radius).lower()
    assert "cannot restore" in blast or "restore" in blast


def test_plan_backup_delete_honest_permanent_loss():
    p = plan_backup_delete(_bk_api([]), "local", _VALID_VOLID)
    reasons = " ".join(p.risk_reasons).lower()
    assert "permanent" in reasons or "gone" in reasons or "lost" in reasons


def test_plan_backup_delete_rejects_bad_volid():
    with pytest.raises(ProximoError):
        plan_backup_delete(None, "local", "no-colon-here")


def test_plan_backup_delete_rejects_traversal():
    with pytest.raises(ProximoError, match="traversal"):
        plan_backup_delete(None, "local", "local:backup/../../etc/passwd")


def test_plan_backup_delete_rejects_bad_storage():
    with pytest.raises(ProximoError):
        plan_backup_delete(None, "storage with spaces!", _VALID_VOLID)


# ── VALIDATOR: _check_volid ───────────────────────────────────────────────────


def test_check_volid_rejects_trailing_newline():
    from proximo.backup import _check_volid
    with pytest.raises(ProximoError):
        _check_volid("local:backup/vzdump-lxc-102.tar.zst\n")


def test_check_volid_rejects_double_dot():
    from proximo.backup import _check_volid
    with pytest.raises(ProximoError, match="traversal"):
        _check_volid("local:backup/../secret")


def test_check_volid_rejects_no_colon():
    from proximo.backup import _check_volid
    with pytest.raises(ProximoError):
        _check_volid("localbackupfile.tar.zst")


def test_check_volid_accepts_pbs_snapshot_volid():
    # HIGH (2026-07-10 audit): PBS volids embed an RFC3339 snapshot time whose HH:MM:SS adds colons
    # to the PATH part — the exact volid qmrestore/pct restore consume and pve_backup_list returns.
    # The validator must accept them (colon allowed in the path, not the storage id).
    from proximo.backup import _check_volid
    v = "pbs:backup/vm/100/2026-07-09T02:00:00Z"
    assert _check_volid(v) == v

def test_check_volid_rejects_colon_or_slash_in_storage_part():
    # The STORAGE id (before the first colon) must still be strict — no slash/traversal smuggling.
    from proximo.backup import _check_volid
    with pytest.raises(ProximoError):
        _check_volid("bad/storage:backup/vm/100/2026-07-09T02:00:00Z")


def test_check_volid_rejects_shell_expansion():
    from proximo.backup import _check_volid
    with pytest.raises(ProximoError):
        _check_volid("local:backup/$(whoami).tar.zst")


def test_check_volid_accepts_valid_lxc_volid():
    from proximo.backup import _check_volid
    v = "local:backup/vzdump-lxc-102-2026_06_08-10_00_00.tar.zst"
    assert _check_volid(v) == v


def test_check_volid_accepts_valid_qemu_volid():
    from proximo.backup import _check_volid
    v = "nfs-backup:backup/vzdump-qemu-200-2026_06_08.vma.zst"
    assert _check_volid(v) == v


# ── URL-encoding correctness ──────────────────────────────────────────────────


def test_backup_delete_colon_is_encoded_not_raw(monkeypatch):
    """The volid colon must be percent-encoded as %3A in the URL path segment."""
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_delete", lambda path, params=None: seen.update(path=path) or None)
    backup_delete(api, "local", "local:backup/test.tar.zst")
    assert "local%3Abackup%2Ftest.tar.zst" in seen["path"]


# ── REGRESSION: redteam fixes (2026-06-08) ────────────────────────────────────

def test_vzdump_backup_rejects_bad_compress():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError, match="invalid compress"):
        vzdump_backup(api, "102", "local", compress="bogus")


def test_restore_guest_rejects_traversal_archive():
    api = ApiBackend(_cfg())
    with pytest.raises(ProximoError):
        restore_guest(api, "102", "local:backup/../../etc/passwd", "local")


def test_check_volid_rejects_empty_storage_and_empty_segment():
    from proximo.backup import _check_volid
    with pytest.raises(ProximoError):
        _check_volid(":backup/x.tar.zst")          # empty storage name
    with pytest.raises(ProximoError):
        _check_volid("local:backup//x.tar.zst")    # empty path segment


class _RestoreApi:
    """Fake for plan_restore: guest_status raises 404-shaped (absent) or plain (transient)."""

    def __init__(self, *, exists, transient=False):
        self.config = SimpleNamespace(node="pve")
        self._exists = exists
        self._transient = transient

    def guest_status(self, vmid, kind="lxc", node=None):
        if self._transient:
            raise RuntimeError("API timeout")  # no .response -> "unknown", not absence
        if not self._exists:
            err = RuntimeError("not found")
            err.response = SimpleNamespace(status_code=404)  # 404-shaped -> confirmed absent
            raise err
        return {"status": "running", "name": "victim"}


def test_plan_restore_transient_error_with_force_is_high_not_creates():
    # A transient read failure must NOT be reported as "creates new" when force could overwrite.
    p = plan_restore(_RestoreApi(exists=False, transient=True), "102", _VALID_VOLID, force=True)
    assert p.risk == RISK_HIGH
    assert any("could not" in b.lower() for b in p.blast_radius)
    assert not any("no existing guest is overwritten" in b.lower() for b in p.blast_radius)


def test_plan_restore_confirmed_absent_creates_new():
    p = plan_restore(_RestoreApi(exists=False), "102", _VALID_VOLID, force=True)
    assert p.risk == RISK_MEDIUM
    assert any("creates" in b.lower() for b in p.blast_radius)


def test_plan_restore_exists_with_force_is_high_overwrite():
    p = plan_restore(_RestoreApi(exists=True), "102", _VALID_VOLID, force=True)
    assert p.risk == RISK_HIGH
    assert any("overwrites" in b.lower() and "destroys" in b.lower() for b in p.blast_radius)


# ── plan_backup_delete: last-copy blast (rank 8) ─────────────────────────────

def _bk_api(backups):
    from types import SimpleNamespace

    def _get(path):
        if "/content" in path:
            return backups
        return []

    return SimpleNamespace(config=SimpleNamespace(node="pve"), _get=_get)


def test_plan_backup_delete_last_copy_is_named():
    """Deleting the ONLY backup of a guest must be named as the last recovery point."""
    api = _bk_api([{"volid": _VALID_VOLID, "vmid": 102}])
    p = plan_backup_delete(api, "local", _VALID_VOLID)
    assert p.risk == RISK_HIGH
    assert any(a["vmid"] == "102" and a["remaining"] == 0 for a in p.affected)
    assert any("last" in line.lower() for line in p.blast_radius)


def test_plan_backup_delete_siblings_remain_counted():
    api = _bk_api([
        {"volid": _VALID_VOLID, "vmid": 102},
        {"volid": "local:backup/vzdump-lxc-102-2026_06_09.tar.zst", "vmid": 102},
    ])
    p = plan_backup_delete(api, "local", _VALID_VOLID)
    assert any(a["vmid"] == "102" and a["remaining"] == 1 for a in p.affected)


def test_plan_backup_delete_other_guests_backups_dont_count():
    api = _bk_api([
        {"volid": _VALID_VOLID, "vmid": 102},
        {"volid": "local:backup/vzdump-lxc-999-2026_06_09.tar.zst", "vmid": 999},
    ])
    p = plan_backup_delete(api, "local", _VALID_VOLID)
    assert any(a["vmid"] == "102" and a["remaining"] == 0 for a in p.affected)  # 999 is a different guest


def test_plan_backup_delete_list_read_failure_is_incomplete():
    from types import SimpleNamespace

    def _get(path):
        raise RuntimeError("content read failed")

    api = SimpleNamespace(config=SimpleNamespace(node="pve"), _get=_get)
    p = plan_backup_delete(api, "local", _VALID_VOLID)
    assert p.complete is False
    assert p.risk == RISK_HIGH


# --- backup_list_sighted: an empty listing from a BLIND token is not evidence -----------------
# Live-found 2026-07-09 (freshness fence) and re-found 2026-09-16: PVE filters backup volumes OUT
# of the content listing per volume. A PVEAuditor token gets 200 + [] on a storage full of
# archives. The plain listing said "no backups" to an adopter whose token could never have seen one.

def _perm_api(monkeypatch, listing, perms):
    api = ApiBackend(_cfg())
    monkeypatch.setattr(api, "_get", lambda path: listing)
    monkeypatch.setattr(api, "access_permissions", lambda path=None: perms)
    return api


def test_sighted_returns_archives_untouched_when_listing_is_non_empty(monkeypatch):
    from proximo.backup import backup_list_sighted
    # Even a blind-looking permission map cannot hide what PVE already returned; no perms read.
    api = _perm_api(monkeypatch, [{"volid": "pbs:backup/ct/443/2026-09-16T02:00:00Z"}], None)
    def _never(path=None):
        raise AssertionError("must not be called")
    monkeypatch.setattr(api, "access_permissions", _never)
    assert backup_list_sighted(api, "pbs")[0]["volid"].startswith("pbs:backup/ct/443/")


def test_sighted_empty_listing_from_auditor_token_refuses_with_the_grant(monkeypatch):
    from proximo.backup import backup_list_sighted
    api = _perm_api(monkeypatch, [], {"/": {"Datastore.Audit": 1, "VM.Audit": 1}})
    with pytest.raises(ProximoError) as ei:
        backup_list_sighted(api, "pbs")
    msg = str(ei.value)
    assert "Datastore.AllocateSpace" in msg and "VM.Backup" in msg and "/storage/pbs" in msg
    assert "cannot see" in msg


def test_sighted_empty_listing_with_allocatespace_but_no_vm_backup_anywhere_refuses(monkeypatch):
    from proximo.backup import backup_list_sighted
    api = _perm_api(monkeypatch, [], {"/storage/pbs": {"Datastore.AllocateSpace": 1}, "/": {"VM.Audit": 1}})
    with pytest.raises(ProximoError, match="VM.Backup"):
        backup_list_sighted(api, "pbs")


def test_sighted_empty_listing_with_datastore_allocate_is_a_real_empty(monkeypatch):
    from proximo.backup import backup_list_sighted
    api = _perm_api(monkeypatch, [], {"/storage/pbs": {"Datastore.Allocate": 1}})
    assert backup_list_sighted(api, "pbs") == []


def test_sighted_empty_listing_with_allocatespace_and_vm_backup_is_a_real_empty(monkeypatch):
    from proximo.backup import backup_list_sighted
    api = _perm_api(monkeypatch, [], {"/storage": {"Datastore.AllocateSpace": 1}, "/vms": {"VM.Backup": 1}})
    assert backup_list_sighted(api, "pbs") == []


def test_sighted_empty_listing_with_unreadable_permissions_returns_empty(monkeypatch):
    from proximo.backup import backup_list_sighted
    api = ApiBackend(_cfg())
    monkeypatch.setattr(api, "_get", lambda path: [])
    monkeypatch.setattr(api, "access_permissions", lambda path=None: (_ for _ in ()).throw(RuntimeError("403")))
    # Sight is unprovable either way; a secondary failure must not turn a read into an error.
    assert backup_list_sighted(api, "pbs") == []


def test_sighted_empty_listing_with_empty_permission_map_returns_empty(monkeypatch):
    from proximo.backup import backup_list_sighted
    # A token holding nothing gets 403 on the content read, never 200 + []; an empty map here is
    # a stub or a malformed read and must not be read as proof of blindness.
    api = _perm_api(monkeypatch, [], {})
    assert backup_list_sighted(api, "pbs") == []
    api = _perm_api(monkeypatch, [], [])
    assert backup_list_sighted(api, "pbs") == []


def test_sighted_propagate_zero_on_the_leaf_is_held(monkeypatch):
    from proximo.backup import backup_list_sighted
    # PVE: the value is the PROPAGATE flag; a privilege is held iff DEFINED. `--propagate 0`
    # directly on the leaf is a real grant there (lens finding 2026-09-16: was read as blind).
    api = _perm_api(monkeypatch, [], {"/storage/pbs": {"Datastore.AllocateSpace": 0}, "/vms/100": {"VM.Backup": 0}})
    assert backup_list_sighted(api, "pbs") == []


def test_sighted_propagate_zero_on_an_ancestor_does_not_reach_the_leaf(monkeypatch):
    from proximo.backup import backup_list_sighted
    api = _perm_api(monkeypatch, [], {"/storage": {"Datastore.AllocateSpace": 0}, "/": {"VM.Backup": 1}})
    with pytest.raises(ProximoError, match="Datastore.AllocateSpace"):
        backup_list_sighted(api, "pbs")


def test_sighted_root_grant_of_datastore_allocate_is_sight(monkeypatch):
    from proximo.backup import backup_list_sighted
    api = _perm_api(monkeypatch, [], {"/": {"Datastore.Allocate": 1}})
    assert backup_list_sighted(api, "pbs") == []


def test_sighted_vm_backup_on_one_guest_is_scoped_sight_not_blindness(monkeypatch):
    from proximo.backup import backup_list_sighted
    # Decision, pinned: a token granted VM.Backup on /vms/999 alone sees only 999's archives, so
    # [] truthfully means "none for the guests you were granted"; that scope is the admin's, and
    # docs/SETUP.md says so. Blindness is reserved for a token that can see NO guest's archives.
    api = _perm_api(monkeypatch, [], {"/storage/pbs": {"Datastore.AllocateSpace": 1}, "/vms/999": {"VM.Backup": 1}})
    assert backup_list_sighted(api, "pbs") == []


# ── issue #82: a restored guest must not wear the original's network identity ────────────────
# PVE's POST /nodes/{node}/{lxc,qemu} create-from-archive takes `unique` ("Assign a unique random
# ethernet address", requires archive/restore) and `storage` ("Default storage") on BOTH kinds; the
# QEMU branch sent neither, so a restore to a new vmid put a second machine with the same MAC on
# the bridge, and the plan never said so.


def test_restore_qemu_sends_storage_as_default_storage(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_post", lambda path, data=None: seen.update(data=data) or "U")
    restore_guest(api, "102", _VALID_VOLID, "local", kind="qemu")
    assert seen["data"]["storage"] == "local"


def test_restore_new_guest_gets_unique_mac_by_default(monkeypatch):
    for kind in ("lxc", "qemu"):
        api = ApiBackend(_cfg())
        seen: dict = {}
        monkeypatch.setattr(api, "_post", lambda path, data=None, _s=seen: _s.update(data=data) or "U")
        restore_guest(api, "102", _VALID_VOLID, "local", kind=kind)
        assert seen["data"]["unique"] == 1, kind


def test_restore_force_overwrite_keeps_identity_by_default(monkeypatch):
    # Overwriting the SAME vmid in place is the one case where keeping the MAC is what the
    # operator means (DHCP reservations, firewall rules keyed on it).
    for kind in ("lxc", "qemu"):
        api = ApiBackend(_cfg())
        seen: dict = {}
        monkeypatch.setattr(api, "_post", lambda path, data=None, _s=seen: _s.update(data=data) or "U")
        restore_guest(api, "102", _VALID_VOLID, "local", kind=kind, force=True)
        assert "unique" not in seen["data"], kind


def test_restore_unique_explicit_wins_over_the_default(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_post", lambda path, data=None: seen.update(data=data) or "U")
    restore_guest(api, "102", _VALID_VOLID, "local", kind="qemu", unique=False)
    assert "unique" not in seen["data"]
    restore_guest(api, "102", _VALID_VOLID, "local", kind="qemu", force=True, unique=True)
    assert seen["data"]["unique"] == 1


def test_plan_restore_new_guest_note_says_new_mac_and_what_stays():
    p = plan_restore(_GuestMissingApi(), "102", _VALID_VOLID, kind="qemu")
    note = p.note.lower()
    assert "new mac" in note
    assert "new smbios uuid" in note      # qemu-server's restore_update_config_line regenerates it under unique
    assert "machine-id" in note          # the guest's own identity is copied, PVE cannot change it
    assert "link_down=1" in note          # how to boot a test restore beside a running original


def test_plan_restore_lxc_note_claims_no_smbios_and_no_guest_agent():
    p = plan_restore(_GuestMissingApi(), "102", _VALID_VOLID, kind="lxc")
    note = p.note.lower()
    assert "new mac" in note
    assert "smbios" not in note
    assert "guest agent" not in note


def test_plan_restore_unique_false_note_warns_shared_identity():
    p = plan_restore(_GuestMissingApi(), "102", _VALID_VOLID, kind="qemu", unique=False)
    note = p.note.lower()
    assert "stored in the archive" in note
    assert "unique=false" in note


# ── issue #82, lens round 1: the default must know WHOSE identity the archive carries ─────────
# "force keeps the MAC" is only right when the archive came from the SAME vmid it overwrites. A
# force restore of vmid 102's archive onto vmid 150 rebuilds 150 from 102's config, MAC included,
# and 102 may still be running: the #82 collision through the other door.


def test_restore_force_across_vmids_still_gets_a_unique_mac(monkeypatch):
    for kind in ("lxc", "qemu"):
        api = ApiBackend(_cfg())
        seen: dict = {}
        monkeypatch.setattr(api, "_post", lambda path, data=None, _s=seen: _s.update(data=data) or "U")
        restore_guest(api, "150", _VALID_VOLID, "local", kind=kind, force=True)  # archive is 102's
        assert seen["data"]["unique"] == 1, kind


def test_restore_lxc_explicit_unique_false_is_honoured(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_post", lambda path, data=None: seen.update(data=data) or "U")
    restore_guest(api, "150", _VALID_VOLID, "local", kind="lxc", unique=False)
    assert "unique" not in seen["data"]


def test_plan_restore_rejected_restore_carries_no_identity_note():
    # vmid exists, no force: PVE rejects the restore, so there is no identity to describe.
    p = plan_restore(_GuestExistsApi({"status": "running", "name": "x"}), "102", _VALID_VOLID, kind="qemu")
    assert p.note == ""


def test_plan_restore_force_across_vmids_note_says_new_mac():
    p = plan_restore(_GuestExistsApi({"status": "stopped", "name": "x"}), "150", _VALID_VOLID,
                     kind="qemu", force=True)
    assert "new mac" in p.note.lower()


def test_plan_restore_blast_names_the_storage_the_disks_land_on():
    p = plan_restore(_GuestMissingApi(), "150", _VALID_VOLID, kind="qemu", storage="fast-nvme")
    assert "fast-nvme" in p.change
    assert "fast-nvme" in " ".join(p.blast_radius)


# ── issue #82, lens round 2: the in-place rule must read every archive shape PVE restores from ──


class _GuestCheckFailsApi:
    """Fake api whose existence read fails for a NON-404 reason (timeout, 5xx): existence UNKNOWN."""

    def guest_status(self, vmid, kind="lxc", node=None):
        raise RuntimeError("upstream timeout")


_PBS_VM_VOLID = "pbs-test:backup/vm/102/2026-07-09T02:00:00Z"
_PBS_CT_VOLID = "pbs-test:backup/ct/150/2026-07-09T02:00:00Z"


def test_vmid_from_backup_volid_reads_vzdump_and_pbs_shapes():
    from proximo.backup import _vmid_from_backup_volid as f
    assert f(_VALID_VOLID) == "102"                                      # vzdump file archive
    assert f(_PBS_VM_VOLID) == "102"                                     # PBS snapshot, vm
    assert f(_PBS_CT_VOLID) == "150"                                     # PBS snapshot, ct
    assert f("vzdump-lxc-5-a:backup/vzdump-lxc-102-x") == "102"         # decoy in the storage id
    assert f("local:backup/vzdump-qemu-102-x/vzdump-qemu-150-y") == "150"  # the basename wins
    assert f("local:backup/vzdump-qemu-102.vma.zst") is None            # no vmid separator


def test_restore_in_place_from_a_pbs_archive_keeps_the_archive_mac(monkeypatch):
    api = ApiBackend(_cfg())
    seen: dict = {}
    monkeypatch.setattr(api, "_post", lambda path, data=None: seen.update(data=data) or "U")
    restore_guest(api, "102", _PBS_VM_VOLID, "local", kind="qemu", force=True)
    assert "unique" not in seen["data"]


def test_plan_restore_in_place_note_names_the_reason():
    p = plan_restore(_GuestExistsApi({"status": "stopped", "name": "x"}), "102", _VALID_VOLID,
                     kind="lxc", force=True)
    assert "same vmid the archive came from" in p.note


def test_plan_restore_unknown_existence_hedges_the_identity_and_storage_lines():
    p = plan_restore(_GuestCheckFailsApi(), "150", _VALID_VOLID, kind="qemu", storage="fast-nvme")
    assert "if the restore proceeds" in p.note
    storage_lines = [b for b in p.blast_radius if "fast-nvme" in b]
    assert storage_lines and "if the restore proceeds" in storage_lines[0]


def test_plan_restore_rejected_restore_names_no_storage_landing():
    p = plan_restore(_GuestExistsApi({"status": "running", "name": "x"}), "102", _VALID_VOLID,
                     kind="qemu", storage="fast-nvme")
    assert not any("land on" in b for b in p.blast_radius)


# ── issue #82 live proof (pve-test4, PVE 9.2): an ABSENT guest answers 500, not 404 ──────────
# GET /nodes/{node}/{kind}/{vmid}/status/current on a vmid that does not exist returns HTTP 500 with
# the message "Configuration file 'nodes/<node>/<kind-dir>/<vmid>.conf' does not exist". The plan's
# 404-only test therefore never confirmed absence on a real PVE: every restore to a new vmid read as
# UNKNOWN. Found when the hedge appeared on a plain new-vmid plan during the live proof.


class _Resp:
    def __init__(self, status_code, text=""):
        self.status_code, self.text = status_code, text


class _HttpErr(Exception):
    def __init__(self, resp):
        super().__init__("http")
        self.response = resp


_ABSENT_500 = _HttpErr(_Resp(
    500, '{"message":"Configuration file \'nodes/pve/qemu-server/150.conf\' does not exist\\n","data":null}'))


class _GuestRaisesApi:
    def __init__(self, exc): self._exc = exc
    def guest_status(self, vmid, kind="lxc", node=None): raise self._exc


def test_guest_absent_reads_pves_500_config_does_not_exist_as_confirmed_absent():
    from proximo.backends import guest_absent
    roster = lambda: _GuestRaisesClusterApi(_ABSENT_500, [])  # noqa: E731 - an empty cluster, fresh each call
    assert guest_absent(_HttpErr(_Resp(404))) is True
    assert guest_absent(_ABSENT_500, api=roster(), vmid="150", kind="qemu") is True
    assert guest_absent(_HttpErr(_Resp(500, '{"message":"storage \'x\' is not online","data":null}')),
                        api=roster(), vmid="150", kind="qemu") is False
    assert guest_absent(_HttpErr(_Resp(503, "")), api=roster(), vmid="150", kind="qemu") is False
    assert guest_absent(RuntimeError("timeout"), api=roster(), vmid="150", kind="qemu") is False


def test_plan_restore_absent_guest_on_real_pve_is_confirmed_not_unknown():
    api = _GuestRaisesClusterApi(_ABSENT_500, [])
    p = plan_restore(api, "150", _VALID_VOLID, kind="qemu", storage="local-lvm")
    assert "not found" in " ".join(p.risk_reasons).lower()
    assert "if the restore proceeds" not in p.note
    assert not any("could NOT confirm" in b for b in p.blast_radius)


def test_plan_restore_other_500_stays_unknown_and_hedged():
    other = _HttpErr(_Resp(500, '{"message":"storage \'x\' is not online","data":null}'))
    p = plan_restore(_GuestRaisesApi(other), "150", _VALID_VOLID, kind="qemu", storage="local-lvm")
    assert any("could NOT confirm" in b for b in p.blast_radius)
    assert "if the restore proceeds" in p.note


# ── lens round 4: "Configuration file … does not exist" means NOT ON THIS NODE, not absent ────
# The file is per node. In a cluster, reading guest 150 (alive on node B) through node A gives the
# same 500. So a 500 is "not here"; absence needs the cluster-wide roster to agree.


class _GuestRaisesClusterApi(_GuestRaisesApi):
    """500-absent on the node read; `cluster` = what /cluster/resources?type=vm lists."""

    def __init__(self, exc, cluster, cluster_raises=False):
        super().__init__(exc)
        self._cluster, self._cluster_raises = cluster, cluster_raises
        self.cluster_reads = 0
        self.config = SimpleNamespace(node="pve-a")  # the node the read went through

    def _get(self, path, **kw):
        if path.startswith("/nodes/"):   # the cloud-init plan reads /config through _get, not guest_status
            raise self._exc
        assert path.startswith("/cluster/resources"), path
        self.cluster_reads += 1
        if self._cluster_raises:
            raise RuntimeError("cluster read failed")
        return self._cluster


_ON_NODE_B = [{"vmid": 150, "type": "qemu", "node": "pve-b", "status": "running"}]


def test_guest_absent_500_needs_the_cluster_roster_to_agree():
    from proximo.backends import guest_absent
    empty = _GuestRaisesClusterApi(_ABSENT_500, [])
    assert guest_absent(_ABSENT_500, api=empty, vmid="150", kind="qemu") is True
    assert empty.cluster_reads == 1
    elsewhere = _GuestRaisesClusterApi(_ABSENT_500, _ON_NODE_B)
    assert guest_absent(_ABSENT_500, api=elsewhere, vmid="150", kind="qemu") is False
    broken = _GuestRaisesClusterApi(_ABSENT_500, [], cluster_raises=True)
    assert guest_absent(_ABSENT_500, api=broken, vmid="150", kind="qemu") is False
    # without the roster there is no absence to confirm; a 404 needs none
    assert guest_absent(_ABSENT_500) is False
    assert guest_absent(_HttpErr(_Resp(404)), api=elsewhere, vmid="150", kind="qemu") is True
    assert elsewhere.cluster_reads == 1  # the 404 did not read the roster


def test_guest_absent_500_must_name_this_guests_config_file():
    from proximo.backends import guest_absent
    other_file = _HttpErr(_Resp(
        500, '{"message":"Configuration file \'nodes/pve/qemu-server/151.conf\' does not exist\\n"}'))
    api = _GuestRaisesClusterApi(other_file, [])
    assert guest_absent(other_file, api=api, vmid="150", kind="qemu") is False
    assert guest_absent(_ABSENT_500, api=_GuestRaisesClusterApi(_ABSENT_500, []), vmid="150", kind="lxc") is False


def test_plan_restore_force_onto_a_guest_alive_on_another_node_is_not_creates_new():
    api = _GuestRaisesClusterApi(_ABSENT_500, _ON_NODE_B)
    p = plan_restore(api, "150", _VALID_VOLID, kind="qemu", force=True, storage="local-lvm")
    assert not any("no existing guest is overwritten" in b for b in p.blast_radius)
    assert any("could NOT confirm" in b for b in p.blast_radius)


def test_the_other_three_plans_confirm_absence_on_the_live_500_shape():
    from proximo.cloudinit import plan_template_convert
    from proximo.cluster_ops import plan_migrate
    from proximo.provisioning import plan_delete
    for make in (lambda a: plan_delete(a, "150", kind="qemu"),
                 lambda a: plan_template_convert(a, "150"),
                 lambda a: plan_migrate(a, "150", "pve-b", kind="qemu")):
        p = make(_GuestRaisesClusterApi(_ABSENT_500, []))
        text = " ".join(p.blast_radius + p.risk_reasons).lower()
        assert "could not" in text or "nothing would be" in text or "fail" in text  # the absent branch speaks
        assert "could not verify" not in text and "could not confirm" not in text, text  # ...not the unknown one
