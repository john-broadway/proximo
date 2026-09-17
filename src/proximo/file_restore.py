"""Per-guest FILE-LEVEL restore: list the files inside a backup and pull one (or a directory) out.

Two planes, one landing spot:

  PVE  GET /nodes/{node}/storage/{storage}/file-restore/list      ?volume=&filepath=
       GET /nodes/{node}/storage/{storage}/file-restore/download  ?volume=&filepath=&tar=
       PBS-backed volumes only ("Currently only PBS snapshots are supported"). Permission is
       `check_volume_access` with the 'backup' privilege: Datastore.AllocateSpace on the storage +
       VM.Backup on the owner guest (or Datastore.Allocate on the storage) — the same sighted grant
       docs/SETUP.md names for seeing backups at all. VM images need proxmox-backup-file-restore on
       the node (it boots a restore VM); container/host pxar archives are read directly.
  PBS  GET /admin/datastore/{store}/catalog             ?backup-type=&backup-id=&backup-time=&ns=&filepath=
       GET /admin/datastore/{store}/pxar-file-download  ?…&filepath=&tar=
       "Requires on /datastore/{store}[/{ns}] either DATASTORE_READ for any or DATASTORE_BACKUP and
       being the owner" (src/api2/admin/datastore.rs).

Grammar, walked live in the lab 2026-09-16 before this module was written (never from the docs
summary): requests take `filepath` = base64 of a '/'-rooted path ('/' lists the archive layer:
`data.pxar.didx`, then `/data.pxar.didx/etc/...`); entries come back with `filepath` base64 —
root entries WITH a leading '/', nested ones WITHOUT — plus text/type/leaf/size/mtime; a file
downloads as application/octet-stream with NO Content-Length; a directory downloads as a zip
(PK magic) or, with tar=1, tar.zst.

Where the bytes land — decided, and boring on purpose: `PROXIMO_RESTORE_DIR` (default
~/.local/state/proximo/restores), one fresh 0700 subdirectory per download, the file 0600 and
opened O_EXCL (never overwrite, never follow a symlink), capped by `PROXIMO_RESTORE_MAX_BYTES`
(default 256 MiB) both from Content-Length when present and while streaming when it is not; an
overrun or any error removes the partial. The tool result carries the local path, byte count and
sha256 — NEVER the bytes: a backup holds guest secrets and the transcript is not where they land.
The download is a governed MUTATION (PLAN → confirm): it reads guest data out of a backup onto the
Proximo host, and the PLAN discloses source, remote path, destination and the cap, pre-reading the
entry's size from the listing and saying so when it is over the cap (`complete` stays an honesty
signal, never a gate); on execute the same size check refuses before the first byte, and the
stream-time cap holds regardless of what any listing or length header claimed.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import secrets
import time
from urllib.parse import urlencode

import httpx

from .backends import ProximoError, _check_node
from .pbs import (
    PbsBackend,
    _check_backup_id,
    _check_backup_time,
    _check_backup_type,
    _check_namespace,
    _check_store,
)
from .planning import RISK_MEDIUM, Plan
from .storage import _check_storage, _check_volid

_DEFAULT_DIR = "~/.local/state/proximo/restores"
_DEFAULT_MAX = 256 * 1024 * 1024
_MAX_PATH = 4096
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_STREAM_TIMEOUT = httpx.Timeout(600.0, connect=30.0)  # a VM-image listing boots a restore VM


# --- path grammar -------------------------------------------------------------------------------

def _check_filepath(filepath) -> str:
    """A '/'-rooted, control-free, traversal-free path (or '/' itself). Plain text in; encoded
    at the wire by _b64path. `..` is rejected here so the PLAN's remote path is the one PBS reads."""
    if not isinstance(filepath, str) or not filepath:
        raise ProximoError("filepath must be a non-empty string starting with '/' ('/' lists the archives)")
    if not filepath.startswith("/"):
        raise ProximoError(f"filepath must start with '/': {filepath!r}")
    if len(filepath) > _MAX_PATH:
        raise ProximoError(f"filepath longer than {_MAX_PATH} characters")
    if _CTRL.search(filepath):
        raise ProximoError("filepath carries a control character")
    if any(seg in ("..", ".") for seg in filepath.split("/")):
        raise ProximoError(f"filepath must not carry '.' or '..' segments: {filepath!r}")
    return filepath


def _b64path(filepath: str) -> str:
    return base64.b64encode(filepath.encode("utf-8")).decode("ascii")


def _decode_entries(entries: list) -> list[dict]:
    """Add a readable `path` to each entry (leading '/' normalised), keep the raw base64
    `filepath` for round-trip, and flag rather than drop an entry that will not decode."""
    out: list[dict] = []
    for e in entries or []:
        row = dict(e) if isinstance(e, dict) else {"raw": e}
        raw = row.get("filepath")
        try:
            decoded = base64.b64decode(raw, validate=True).decode("utf-8") if isinstance(raw, str) else None
            row["path"] = None if decoded is None else ("/" + decoded.lstrip("/"))
        except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
            row["path"] = None
            row["path_error"] = f"filepath did not decode as base64/utf-8: {type(exc).__name__}"
        out.append(row)
    return out


# --- landing spot -------------------------------------------------------------------------------

def restore_settings() -> tuple[str, int]:
    """(landing dir, byte cap) from PROXIMO_RESTORE_DIR / PROXIMO_RESTORE_MAX_BYTES. Read from the
    process environment on purpose: a PBS-only deployment has no PVE ProximoConfig to hang this on,
    and the env file loader already mirrored the file into the environment at process entry."""
    d = os.path.expanduser(os.environ.get("PROXIMO_RESTORE_DIR") or _DEFAULT_DIR)
    raw = os.environ.get("PROXIMO_RESTORE_MAX_BYTES")
    if raw is None or raw == "":
        return d, _DEFAULT_MAX
    try:
        cap = int(raw)
    except ValueError:
        cap = 0
    if cap <= 0:
        raise ProximoError(f"PROXIMO_RESTORE_MAX_BYTES must be a positive integer of bytes, got {raw!r}")
    return d, cap


def _local_name(remote: str, is_dir: bool, tar: bool) -> str:
    base = _CTRL.sub("_", remote.rstrip("/").rsplit("/", 1)[-1]) or "restore"
    if is_dir:
        base += ".tar.zst" if tar else ".zip"
    return base


def _landing(dest_dir: str, remote: str, is_dir: bool, tar: bool) -> str:
    """Create <dest_dir>/restore-<utc>-<rand>/ (0700) and return the path of a fresh 0600 file in
    it, created O_EXCL|O_NOFOLLOW so nothing is ever overwritten or written through a link."""
    os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    # A pre-existing dir keeps whatever mode it had (exist_ok never chmods); the contract here is
    # private, so tighten it. Names and timestamps of pulls are the operator's business only.
    if os.stat(dest_dir).st_mode & 0o077:
        os.chmod(dest_dir, 0o700)
    sub = os.path.join(dest_dir, f"restore-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{secrets.token_hex(3)}")
    os.mkdir(sub, 0o700)
    path = os.path.join(sub, _local_name(remote, is_dir, tar))
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        os.rmdir(sub)  # e.g. a basename over the filesystem's 255 bytes: leave no empty dir behind
        raise
    os.close(fd)
    return path


# --- the streaming primitive --------------------------------------------------------------------

def stream_to_file(client: httpx.Client, path: str, headers: dict, params: dict,
                   dest: str, max_bytes: int) -> dict:
    """GET `path` as octet-stream into `dest`, refusing over `max_bytes` from Content-Length before
    the first byte and again while streaming (the length header is usually absent). Any refusal
    or error removes the partial file. Returns {"path", "bytes", "sha256"}."""
    h = hashlib.sha256()
    n = 0
    try:
        with client.stream("GET", path, headers=headers, params=params, timeout=_STREAM_TIMEOUT) as r:
            if r.status_code >= 400:
                body = r.read().decode("utf-8", errors="replace")[:300]
                raise ProximoError(f"download refused by the API: HTTP {r.status_code} {body}")
            declared = r.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise ProximoError(
                    f"download is {declared} bytes, over PROXIMO_RESTORE_MAX_BYTES={max_bytes}; "
                    "raise the cap or pull a smaller path")
            with open(dest, "wb") as out:
                for chunk in r.iter_bytes():
                    n += len(chunk)
                    if n > max_bytes:
                        raise ProximoError(
                            f"download passed PROXIMO_RESTORE_MAX_BYTES={max_bytes} while streaming "
                            "(no length header); partial removed — raise the cap or pull a smaller path")
                    h.update(chunk)
                    out.write(chunk)
    except BaseException:
        try:
            os.unlink(dest)
        except OSError:
            pass
        raise
    return {"path": dest, "bytes": n, "sha256": h.hexdigest()}


def _finish_download(client, headers, url, params, remote, entry, tar) -> dict:
    dest_dir, cap = restore_settings()
    size = entry.get("size") if entry else None
    if size is not None and size > cap:
        raise ProximoError(
            f"{remote} is {size} bytes in the listing, over PROXIMO_RESTORE_MAX_BYTES={cap}; "
            "refused before the first byte — raise the cap or pull a smaller path")
    is_dir = _is_dir(entry, tar)
    dest = _landing(dest_dir, remote, is_dir, tar)
    try:
        got = stream_to_file(client, url, headers, params, dest, cap)
    except BaseException:
        # the landing subdir is ours and now empty; leave no trace of a refused pull
        try:
            os.rmdir(os.path.dirname(dest))
        except OSError:
            pass
        raise
    return {**got, "remote": remote, "cap_bytes": cap, "note": (
        "bytes landed on the Proximo host, not in this result; verify the sha256 before use. "
        "A directory arrives as an archive (zip, or tar.zst with tar=True).")}


def _size_probe(list_fn, remote: str) -> tuple[dict | None, str | None]:
    """Find `remote`'s own entry by listing its parent. Returns (entry, error)."""
    parent = remote.rstrip("/").rsplit("/", 1)[0] or "/"
    name = remote.rstrip("/").rsplit("/", 1)[-1]
    try:
        for e in list_fn(parent):
            if e.get("text") == name or (e.get("path") or "").rstrip("/") == remote.rstrip("/"):
                return e, None
        return None, f"no entry named {name!r} under {parent!r} in the listing"
    except Exception as exc:  # noqa: BLE001 — the plan records the probe's failure, never hides it
        return None, f"listing {parent!r} failed: {type(exc).__name__}: {exc}"


def _is_dir(entry: dict | None, tar: bool) -> bool:
    """Directory-ness from the listing; when the probe found nothing, an explicit tar=True is the
    caller saying 'this is a directory', so the local name still gets its archive suffix."""
    if entry:
        return entry.get("type") == "d"
    return bool(tar)


def _download_plan(action: str, target: str, source: str, remote: str, tar: bool,
                   list_fn) -> Plan:
    dest_dir, cap = restore_settings()
    entry, err = _size_probe(list_fn, remote)
    is_dir = bool(entry) and entry.get("type") == "d"
    size = entry.get("size") if entry else None
    reasons = [
        "reads guest data out of a backup and writes it to THIS host's disk "
        f"({dest_dir}, a fresh 0700 subdirectory, file 0600); nothing on the backup changes",
        f"capped at {cap} bytes (PROXIMO_RESTORE_MAX_BYTES); an overrun is refused and the partial removed",
    ]
    if size is not None and size > cap:
        reasons.append(f"the listing says this entry is {size} bytes, over the cap of {cap}: the "
                       "download WILL be refused unless the cap is raised")
    if is_dir:
        reasons.append("a directory downloads as an archive (" + ("tar.zst" if tar else "zip") + ")")
    if err:
        reasons.append(f"size/type unknown: {err}")
    return Plan(
        action=action, target=target,
        change=f"download {remote} from {source} to {dest_dir}/restore-<stamp>/{_local_name(remote, is_dir, tar)}",
        current={"entry": entry, "size": size, "is_dir": is_dir, "cap_bytes": cap},
        blast_radius=[f"local disk: up to {cap} bytes under {dest_dir}", "the backup itself: read only"],
        risk=RISK_MEDIUM, risk_reasons=reasons,
        note="risk is about where guest data lands, not about the backup; confirm=True executes",
        complete=err is None,
    )


# --- PVE plane ----------------------------------------------------------------------------------

def _pve_base(api, storage: str, volid: str, node: str | None) -> tuple[str, str]:
    storage = _check_storage(storage)
    volid = _check_volid(volid)
    _check_node(node)
    n = node or api.config.node
    return f"/nodes/{n}/storage/{storage}/file-restore", volid


def pve_file_restore_list(api, storage: str, volid: str, filepath: str = "/",
                          node: str | None = None) -> list[dict]:
    """GET …/file-restore/list — entries under `filepath` inside the backup `volid`."""
    base, volid = _pve_base(api, storage, volid, node)
    fp = _check_filepath(filepath)
    # ApiBackend._get takes the query IN the path (PbsBackend takes params); the fake that
    # accepted `params=` hid this until the live proof (2026-09-17). Encoded, never f-stringed.
    q = urlencode({"volume": volid, "filepath": _b64path(fp)})
    # A VM-image backup boots a restore VM on the node for this call; 30s is not enough.
    return _decode_entries(api._get(f"{base}/list?{q}", timeout=_STREAM_TIMEOUT) or [])


def plan_pve_file_restore_download(api, storage: str, volid: str, filepath: str,
                                   tar: bool = False, node: str | None = None) -> Plan:
    _pve_base(api, storage, volid, node)
    fp = _check_filepath(filepath)
    return _download_plan(
        "pve_file_restore_download", f"{storage}:{volid}", f"{volid} on storage {storage}", fp, tar,
        lambda parent: pve_file_restore_list(api, storage, volid, parent, node))


def pve_file_restore_download(api, storage: str, volid: str, filepath: str,
                              tar: bool = False, node: str | None = None) -> dict:
    """GET …/file-restore/download — stream the file (or directory archive) onto this host."""
    base, volid = _pve_base(api, storage, volid, node)
    fp = _check_filepath(filepath)
    entry, _ = _size_probe(lambda parent: pve_file_restore_list(api, storage, volid, parent, node), fp)
    params = {"volume": volid, "filepath": _b64path(fp), "tar": 1 if tar else 0}
    return _finish_download(api._client, api._auth_header(), f"{base}/download", params, fp, entry, tar)


# --- PBS plane ----------------------------------------------------------------------------------

def _pbs_params(store, backup_type, backup_id, backup_time, ns) -> tuple[str, dict]:
    store = _check_store(store)
    params = {
        "backup-type": _check_backup_type(backup_type),
        "backup-id": _check_backup_id(backup_id),
        "backup-time": _check_backup_time(backup_time),
    }
    ns = _check_namespace(ns)
    if ns is not None:
        params["ns"] = ns
    return store, params


def pbs_catalog_list(api: PbsBackend, store: str, backup_type: str, backup_id: str, backup_time,
                     filepath: str = "/", ns: str | None = None) -> list[dict]:
    """GET /admin/datastore/{store}/catalog — entries under `filepath` in one snapshot."""
    store, params = _pbs_params(store, backup_type, backup_id, backup_time, ns)
    params["filepath"] = _b64path(_check_filepath(filepath))
    return _decode_entries(api._get(f"/admin/datastore/{store}/catalog", params=params) or [])


def plan_pbs_file_download(api: PbsBackend, store: str, backup_type: str, backup_id: str, backup_time,
                           filepath: str, ns: str | None = None, tar: bool = False) -> Plan:
    store, params = _pbs_params(store, backup_type, backup_id, backup_time, ns)
    fp = _check_filepath(filepath)
    snap = f"{params['backup-type']}/{params['backup-id']}/{params['backup-time']}"
    source = f"snapshot {snap} in datastore {store}" + (f" ns {ns}" if ns else "")
    return _download_plan(
        "pbs_file_download", f"pbs/{store}" + (f"/{ns}" if ns else "") + f"/{snap}", source, fp, tar,
        lambda parent: pbs_catalog_list(api, store, backup_type, backup_id, backup_time, parent, ns))


def pbs_file_download(api: PbsBackend, store: str, backup_type: str, backup_id: str, backup_time,
                      filepath: str, ns: str | None = None, tar: bool = False) -> dict:
    """GET /admin/datastore/{store}/pxar-file-download — stream the file (or directory archive)."""
    store, params = _pbs_params(store, backup_type, backup_id, backup_time, ns)
    fp = _check_filepath(filepath)
    entry, _ = _size_probe(
        lambda parent: pbs_catalog_list(api, store, backup_type, backup_id, backup_time, parent, ns), fp)
    params.update({"filepath": _b64path(fp), "tar": 1 if tar else 0})
    return _finish_download(api._client, api._auth_header(), f"/admin/datastore/{store}/pxar-file-download",
                            params, fp, entry, tar)
