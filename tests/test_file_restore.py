"""Per-guest FILE-LEVEL restore: list the files inside a backup and pull one out, on both planes.

PVE: /nodes/{node}/storage/{storage}/file-restore/{list,download} (PBS-backed volumes only;
`check_volume_access` with the 'backup' privilege = Datastore.AllocateSpace on the storage +
VM.Backup on the guest, the same ProximoBackupSight grant SETUP.md already names).
PBS: /admin/datastore/{store}/{catalog,pxar-file-download} (Datastore.Read, or Datastore.Backup
as the group's owner).

Grammar was walked live in the lab before this module existed (2026-09-16): catalog entries
carry `filepath` as base64 (root entries with a leading '/', nested ones without), requests take
base64 of a '/'-rooted path, downloads are application/octet-stream with NO Content-Length, and a
directory downloads as a zip (PK magic) or tar.zst when tar=True.
"""
from __future__ import annotations

import base64
import hashlib
import os
import stat
from types import SimpleNamespace

import httpx
import pytest

from proximo.backends import ProximoError


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


# --- path grammar -------------------------------------------------------------------------------

def test_filepath_root_and_nested_encode_as_pbs_expects():
    from proximo.file_restore import _b64path, _check_filepath
    assert _check_filepath("/") == "/"
    assert _check_filepath("/data.pxar.didx/etc/hello.txt") == "/data.pxar.didx/etc/hello.txt"
    assert _b64path("/") == _b64("/")
    assert _b64path("/a/b") == _b64("/a/b")


@pytest.mark.parametrize("bad", ["", "relative/path", "/a/../b", "/a\x00b", "/a\nb", "/" + "x" * 5000, None, 5])
def test_filepath_rejects_relative_traversal_control_and_oversize(bad):
    from proximo.file_restore import _check_filepath
    with pytest.raises(ProximoError):
        _check_filepath(bad)


def test_entries_are_decoded_for_the_reader_and_keep_the_raw_for_round_trip():
    from proximo.file_restore import _decode_entries
    raw = [{"filepath": _b64("/data.pxar.didx"), "text": "data.pxar.didx", "type": "d", "leaf": False},
           {"filepath": _b64("data.pxar.didx/etc"), "text": "etc", "type": "d", "leaf": False}]
    out = _decode_entries(raw)
    assert out[0]["path"] == "/data.pxar.didx" and out[1]["path"] == "/data.pxar.didx/etc"
    assert out[1]["filepath"] == _b64("data.pxar.didx/etc")  # raw kept


def test_entry_with_undecodable_filepath_is_kept_and_flagged_not_dropped():
    from proximo.file_restore import _decode_entries
    out = _decode_entries([{"filepath": "%%%not-base64%%%", "text": "x"}])
    assert out[0]["path"] is None and out[0]["path_error"]


# --- landing spot -------------------------------------------------------------------------------

def test_restore_settings_default_dir_and_cap(monkeypatch):
    from proximo.file_restore import restore_settings
    monkeypatch.delenv("PROXIMO_RESTORE_DIR", raising=False)
    monkeypatch.delenv("PROXIMO_RESTORE_MAX_BYTES", raising=False)
    d, cap = restore_settings()
    assert d.endswith("/.local/state/proximo/restores") and cap == 256 * 1024 * 1024


@pytest.mark.parametrize("raw", ["0", "-1", "abc", "1.5"])
def test_restore_settings_rejects_a_useless_cap(monkeypatch, raw):
    from proximo.file_restore import restore_settings
    monkeypatch.setenv("PROXIMO_RESTORE_MAX_BYTES", raw)
    with pytest.raises(ProximoError, match="PROXIMO_RESTORE_MAX_BYTES"):
        restore_settings()


def test_landing_is_a_fresh_private_subdir_with_a_private_file_and_never_overwrites(tmp_path):
    from proximo.file_restore import _landing
    p1 = _landing(str(tmp_path / "r"), "/data.pxar.didx/etc/hello.txt", is_dir=False, tar=False)
    p2 = _landing(str(tmp_path / "r"), "/data.pxar.didx/etc/hello.txt", is_dir=False, tar=False)
    assert p1 != p2 and os.path.basename(p1) == "hello.txt"
    assert stat.S_IMODE(os.stat(os.path.dirname(p1)).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(p1).st_mode) == 0o600
    assert os.path.commonpath([p1, str(tmp_path / "r")]) == str(tmp_path / "r")


def test_landing_name_is_the_sanitized_basename_and_dirs_get_an_archive_suffix(tmp_path):
    from proximo.file_restore import _landing
    assert os.path.basename(_landing(str(tmp_path), "/x/etc", True, False)) == "etc.zip"
    assert os.path.basename(_landing(str(tmp_path), "/x/etc", True, True)) == "etc.tar.zst"
    assert os.path.basename(_landing(str(tmp_path), "/x/we ird\x01name..", False, False)) == "we ird_name.."
    assert os.path.basename(_landing(str(tmp_path), "/", True, False)) == "restore.zip"


# --- the streaming primitive --------------------------------------------------------------------

def _client(handler):
    return httpx.Client(base_url="https://pbs.example:8007/api2/json", transport=httpx.MockTransport(handler))


def test_stream_to_file_writes_bytes_and_reports_sha(tmp_path):
    from proximo.file_restore import stream_to_file
    body = b"abc" * 1000
    def handler(req):
        return httpx.Response(200, content=body, headers={"content-type": "application/octet-stream"})
    dest = str(tmp_path / "out.bin")
    r = stream_to_file(_client(handler), "/x", {}, {}, dest, max_bytes=10_000)
    assert r["bytes"] == 3000 and r["sha256"] == hashlib.sha256(body).hexdigest()
    assert open(dest, "rb").read() == body


def test_stream_to_file_refuses_over_cap_mid_stream_when_no_length_header_and_removes_partial(tmp_path):
    from proximo.file_restore import stream_to_file
    def handler(req):
        return httpx.Response(200, stream=httpx.ByteStream(b"x" * 5000))  # no content-length
    dest = str(tmp_path / "out.bin")
    with pytest.raises(ProximoError, match="PROXIMO_RESTORE_MAX_BYTES"):
        stream_to_file(_client(handler), "/x", {}, {}, dest, max_bytes=4096)
    assert not os.path.exists(dest)


def test_stream_to_file_refuses_over_cap_from_content_length_before_reading(tmp_path):
    from proximo.file_restore import stream_to_file
    seen = {"read": False}
    def handler(req):
        seen["read"] = True
        return httpx.Response(200, headers={"content-length": "999999"}, stream=httpx.ByteStream(b""))
    dest = str(tmp_path / "out.bin")
    with pytest.raises(ProximoError, match="999999"):
        stream_to_file(_client(handler), "/x", {}, {}, dest, max_bytes=10)
    assert not os.path.exists(dest)


def test_stream_to_file_surfaces_the_api_error_body_and_leaves_no_file(tmp_path):
    from proximo.file_restore import stream_to_file
    def handler(req):
        return httpx.Response(403, json={"errors": {"permission": "check failed"}, "data": None})
    dest = str(tmp_path / "out.bin")
    with pytest.raises(ProximoError, match="403"):
        stream_to_file(_client(handler), "/x", {}, {}, dest, max_bytes=10)
    assert not os.path.exists(dest)


# --- PVE plane ----------------------------------------------------------------------------------

class _PveApi:
    """Mirrors ApiBackend's REAL read signature: `_get(path)` with the query IN the path. The first
    draft's fake accepted `params=` and passed while the live call raised TypeError."""
    def __init__(self, entries):
        self.config = SimpleNamespace(node="node1")
        self.entries = entries
        self.seen = []
        self._client = None

    def _auth_header(self):
        return {"Authorization": "x"}

    def _get(self, path, *, timeout=None):
        self.seen.append(path)
        self.timeout = timeout
        return self.entries


class _Api:
    """Mirrors PbsBackend: `_get(path, params=None)`."""
    def __init__(self, entries):
        self.config = SimpleNamespace(node="node1")
        self.entries = entries
        self.seen = []
        self._client = None

    def _auth_header(self):
        return {"Authorization": "x"}

    def _get(self, path, params=None):
        self.seen.append((path, params))
        return self.entries


def test_pve_list_sends_volume_and_base64_filepath_and_decodes():
    from urllib.parse import parse_qs, urlsplit

    from proximo.file_restore import pve_file_restore_list
    api = _PveApi([{"filepath": _b64("/etc"), "text": "etc", "type": "d", "leaf": False}])
    out = pve_file_restore_list(api, "pbs", "pbs:backup/ct/101/2026-09-16T02:00:00Z", "/")
    u = urlsplit(api.seen[0])
    assert u.path == "/nodes/node1/storage/pbs/file-restore/list"
    assert parse_qs(u.query) == {"volume": ["pbs:backup/ct/101/2026-09-16T02:00:00Z"], "filepath": [_b64("/")]}
    assert out[0]["path"] == "/etc"


def test_pve_download_plan_names_source_destination_cap_and_size_from_the_listing(tmp_path, monkeypatch):
    from proximo.file_restore import plan_pve_file_restore_download
    monkeypatch.setenv("PROXIMO_RESTORE_DIR", str(tmp_path))
    monkeypatch.setenv("PROXIMO_RESTORE_MAX_BYTES", "1000")
    api = _PveApi([{"filepath": _b64("etc/hello.txt"), "text": "hello.txt", "type": "f", "leaf": True, "size": 44000}])
    plan = plan_pve_file_restore_download(
        api, "pbs", "pbs:backup/ct/101/2026-09-16T02:00:00Z", "/etc/hello.txt", tar=False)
    d = plan.as_dict()
    assert plan.risk == "medium" and "pbs:backup/ct/101" in d["change"] and "/etc/hello.txt" in d["change"]
    assert str(tmp_path) in d["change"] and plan.current["size"] == 44000
    assert any("44000" in r and "1000" in r for r in plan.risk_reasons)  # over the cap: said in the plan
    assert plan.complete is True


def test_pve_download_plan_marks_incomplete_when_the_listing_fails(tmp_path, monkeypatch):
    from proximo.file_restore import plan_pve_file_restore_download
    monkeypatch.setenv("PROXIMO_RESTORE_DIR", str(tmp_path))
    class Boom(_PveApi):
        def _get(self, path, *, timeout=None):
            raise RuntimeError("500")
    plan = plan_pve_file_restore_download(
        Boom([]), "pbs", "pbs:backup/ct/101/2026-09-16T02:00:00Z", "/etc/hello.txt", tar=False)
    assert plan.complete is False and plan.current.get("size") is None


def test_pve_download_executes_through_the_stream_and_lands_in_the_dir(tmp_path, monkeypatch):
    from proximo.file_restore import pve_file_restore_download
    monkeypatch.setenv("PROXIMO_RESTORE_DIR", str(tmp_path))
    monkeypatch.setenv("PROXIMO_RESTORE_MAX_BYTES", "100000")
    body = b"hello\n" * 10
    def handler(req):
        assert req.url.path.endswith("/nodes/node1/storage/pbs/file-restore/download")
        assert req.url.params["volume"].startswith("pbs:backup/ct/101/")
        assert req.url.params["filepath"] == _b64("/etc/hello.txt") and req.url.params["tar"] == "0"
        return httpx.Response(200, content=body)
    api = _PveApi([])
    api._client = _client(handler)
    r = pve_file_restore_download(
        api, "pbs", "pbs:backup/ct/101/2026-09-16T02:00:00Z", "/etc/hello.txt", tar=False)
    assert r["bytes"] == 60 and r["sha256"] == hashlib.sha256(body).hexdigest()
    assert r["path"].startswith(str(tmp_path)) and r["remote"] == "/etc/hello.txt"
    assert open(r["path"], "rb").read() == body


# --- PBS plane ----------------------------------------------------------------------------------

def test_pbs_catalog_sends_the_snapshot_triple_and_base64_filepath():
    from proximo.file_restore import pbs_catalog_list
    api = _Api([{"filepath": _b64("/data.pxar.didx"), "text": "data.pxar.didx", "type": "d", "leaf": False}])
    out = pbs_catalog_list(api, "test-ds", "host", "fileproof", 1789600000, "/", ns=None)
    assert api.seen[0][0] == "/admin/datastore/test-ds/catalog"
    assert api.seen[0][1] == {"backup-type": "host", "backup-id": "fileproof", "backup-time": 1789600000,
                              "filepath": _b64("/")}
    assert out[0]["path"] == "/data.pxar.didx"


def test_pbs_download_hits_pxar_file_download_with_tar_flag_and_ns(tmp_path, monkeypatch):
    from proximo.file_restore import pbs_file_download
    monkeypatch.setenv("PROXIMO_RESTORE_DIR", str(tmp_path))
    def handler(req):
        assert req.url.path.endswith("/admin/datastore/test-ds/pxar-file-download")
        assert req.url.params["ns"] == "team" and req.url.params["tar"] == "1"
        return httpx.Response(200, content=b"PK\x03\x04zip")
    api = _Api([{"filepath": _b64("data.pxar.didx/etc"), "text": "etc", "type": "d", "leaf": False}])
    api._client = _client(handler)
    r = pbs_file_download(
        api, "test-ds", "host", "fileproof", 1789600000, "/data.pxar.didx/etc", ns="team", tar=True)
    assert r["path"].endswith("etc.tar.zst")


def test_download_with_no_probe_hit_and_tar_true_still_names_an_archive(tmp_path, monkeypatch):
    from proximo.file_restore import pbs_file_download
    monkeypatch.setenv("PROXIMO_RESTORE_DIR", str(tmp_path))
    api = _Api([])
    api._client = _client(lambda req: httpx.Response(200, content=b"x"))
    r = pbs_file_download(api, "test-ds", "host", "fileproof", 1789600000, "/data.pxar.didx/etc", tar=True)
    assert r["path"].endswith("etc.tar.zst")


# --- lens #4 (2026-09-17): the properties the docstring claimed and no test enforced ------------

def _pin_landing(monkeypatch, stamp="20260917T000000Z", rand="abcdef"):
    import proximo.file_restore as fr
    monkeypatch.setattr(fr.time, "strftime", lambda *a, **k: stamp)
    monkeypatch.setattr(fr.secrets, "token_hex", lambda n: rand)
    return f"restore-{stamp}-{rand}"


def test_landing_refuses_to_overwrite_a_pre_planted_file(tmp_path, monkeypatch):
    from proximo.file_restore import _landing
    sub = tmp_path / _pin_landing(monkeypatch)
    sub.mkdir(0o700)
    (sub / "hello.txt").write_bytes(b"pre-existing")
    with pytest.raises(FileExistsError):
        _landing(str(tmp_path), "/etc/hello.txt", False, False)
    assert (sub / "hello.txt").read_bytes() == b"pre-existing"


def test_landing_refuses_to_write_through_a_pre_planted_symlink(tmp_path, monkeypatch):
    from proximo.file_restore import _landing
    sub = tmp_path / _pin_landing(monkeypatch)
    sub.mkdir(0o700)
    victim = tmp_path / "victim"
    victim.write_bytes(b"do not touch")
    (sub / "hello.txt").symlink_to(victim)
    with pytest.raises(OSError):
        _landing(str(tmp_path), "/etc/hello.txt", False, False)
    assert victim.read_bytes() == b"do not touch"


def test_landing_tightens_a_pre_existing_loose_restore_dir(tmp_path):
    from proximo.file_restore import _landing
    d = tmp_path / "loose"
    d.mkdir(0o755)
    _landing(str(d), "/x", False, False)
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700


def test_landing_leaves_no_empty_subdir_when_the_name_is_too_long(tmp_path):
    from proximo.file_restore import _landing
    with pytest.raises(OSError):
        _landing(str(tmp_path), "/" + "x" * 300, False, False)
    assert list(tmp_path.iterdir()) == []


def test_finish_download_removes_its_subdir_when_the_stream_is_refused(tmp_path, monkeypatch):
    from proximo.file_restore import _finish_download
    monkeypatch.setenv("PROXIMO_RESTORE_DIR", str(tmp_path))
    client = _client(lambda req: httpx.Response(403, json={"errors": "no"}))
    with pytest.raises(ProximoError, match="403"):
        _finish_download(client, {}, "/x", {}, "/etc/hello.txt", None, False)
    assert list(tmp_path.iterdir()) == []


def test_download_over_cap_by_the_listing_is_refused_before_the_first_byte(tmp_path, monkeypatch):
    from proximo.file_restore import pbs_file_download
    monkeypatch.setenv("PROXIMO_RESTORE_DIR", str(tmp_path))
    monkeypatch.setenv("PROXIMO_RESTORE_MAX_BYTES", "1000")
    touched = {"stream": False}

    def handler(req):
        touched["stream"] = True
        return httpx.Response(200, content=b"x")
    api = _Api([{"filepath": _b64("data.pxar.didx/big"), "text": "big", "type": "f", "leaf": True, "size": 5000}])
    api._client = _client(handler)
    with pytest.raises(ProximoError, match="before the first byte"):
        pbs_file_download(api, "test-ds", "host", "fileproof", 1789600000, "/data.pxar.didx/big")
    assert touched["stream"] is False and list(tmp_path.iterdir()) == []


def test_pve_listing_uses_the_long_timeout_for_the_restore_vm_boot():
    from proximo.file_restore import _STREAM_TIMEOUT, pve_file_restore_list
    api = _PveApi([])
    pve_file_restore_list(api, "pbs", "pbs:backup/vm/100/2026-09-16T02:00:00Z", "/")
    assert api.timeout is _STREAM_TIMEOUT
