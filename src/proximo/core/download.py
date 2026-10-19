"""The download lane: a byte stream the vendor serves lands on THIS host's disk, never in an answer.

Five published GETs answer bytes, not JSON (a file pulled out of a backup on PVE or PBS, a PBS
blob or index, a quarantined mail on PMG). 0.44 served two of them as curated tools that landed
the bytes under PROXIMO_RESTORE_DIR in a fresh private subdirectory, capped by
PROXIMO_RESTORE_MAX_BYTES, and answered the local path, the byte count and the sha256, never the
bytes: a backup holds guest secrets and a transcript is not where they belong. The core keeps the
variables and the contract and makes the five a LANE: opt-in like every lane that touches this
host (PROXIMO_ENABLE_DOWNLOAD), where 0.44 asked confirm=True per pull.

THE LOCAL NAME IS THE CALLER'S, NEVER THE VENDOR'S. Content-Disposition on a quarantined mail is
attacker-authored text and a listing's names are guest-authored; the file is named from the
argument the caller sent (its basename, control bytes and separators replaced), under a directory
only this process created, opened O_EXCL|O_NOFOLLOW so nothing is overwritten or written through
a link. Any refusal or error removes the partial file and the empty directory.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import secrets
import time
from typing import Any

import httpx

from proximo.core import wire
from proximo.core.errors import ProximoError

DIR_ENV = "PROXIMO_RESTORE_DIR"
CAP_ENV = "PROXIMO_RESTORE_MAX_BYTES"
_DEFAULT_DIR = "~/.local/state/proximo/restores"
_DEFAULT_MAX = 256 * 1024 * 1024
TIMEOUT = httpx.Timeout(600.0, connect=30.0)   # a VM-image restore boots a restore VM on the node
#: the argument that names what is pulled, per address shape: a path inside a backup (pve, pbs
#: pxar; base64 on the wire), a file in a snapshot (pbs download, download-decoded), a
#: quarantined mail's id (pmg `mailid`; lens 3: the first cut said `id`, which no address publishes)
NAME_ARGS = ("filepath", "file-name", "mailid")
_UNSAFE = re.compile(r"[\x00-\x1f\x7f/\\]")


def settings() -> tuple[str, int]:
    """(landing dir, byte cap) from the environment, 0.44's variables so an operator's env carries
    over. A cap that is not a positive integer refuses by its shape."""
    d = os.path.expanduser(os.environ.get(DIR_ENV) or _DEFAULT_DIR)
    raw = os.environ.get(CAP_ENV)
    if raw is None or raw == "":
        return d, _DEFAULT_MAX
    # digits only: int() would read "1_0" as ten and "-1" as a number (lens 3)
    cap = int(raw.strip()) if raw.strip().isdigit() else 0
    if cap <= 0:
        raise ProximoError(f"{CAP_ENV} must be a positive integer of bytes, got {raw!r}")
    return d, cap


def _truthy(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def local_name(args: dict[str, Any]) -> str:
    """The file's name on this host: the basename of the caller's own naming argument (a base64
    `filepath` is decoded first, the way the vendor reads it), separators and control bytes
    replaced, `.` and `..` refused, 200 bytes at most; `.tar.zst` when the caller asked for tar."""
    key, raw = next(((k, str(args[k])) for k in NAME_ARGS if args.get(k) not in (None, "")), ("", ""))
    if key == "filepath":     # only a filepath is base64 on the wire; a mail id is itself (lens 3)
        try:
            decoded = base64.b64decode(raw, validate=True).decode("utf-8", "replace")
            raw = decoded or raw
        except (binascii.Error, ValueError):
            pass
    base = _UNSAFE.sub("_", raw.rstrip("/").rsplit("/", 1)[-1])
    base = base.encode("utf-8")[:200].decode("utf-8", "ignore")    # 200 BYTES: the filesystem's unit
    if base in ("", ".", ".."):
        base = "download"
    if _truthy(args.get("tar")):
        base += ".tar.zst"
    return base


def landing(dest_dir: str, name: str) -> str:
    """<dest_dir>/download-<utc>-<rand>/ (0700) and the path of a fresh 0600 file in it, created
    O_EXCL|O_NOFOLLOW so nothing is ever overwritten or written through a link."""
    os.makedirs(dest_dir, mode=0o700, exist_ok=True)
    if os.stat(dest_dir).st_mode & 0o077:      # exist_ok never chmods; the contract is private
        os.chmod(dest_dir, 0o700)
    sub = os.path.join(dest_dir, f"download-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{secrets.token_hex(3)}")
    os.mkdir(sub, 0o700)
    path = os.path.join(sub, name)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        os.rmdir(sub)
        raise
    os.close(fd)
    return path


def pull(client: wire.Client, path: str, params: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """GET `path` as a stream into a fresh private file; ({path, bytes, sha256}, the cap)."""
    dest_dir, cap = settings()
    dest = landing(dest_dir, local_name(params))
    try:
        return _stream(client, path, params, dest, cap), cap
    except BaseException:
        try:
            os.rmdir(os.path.dirname(dest))   # ours, and empty once the partial is gone
        except OSError:
            pass
        raise


def _stream(client: wire.Client, path: str, params: dict[str, Any], dest: str, cap: int) -> dict[str, Any]:
    """The bytes into `dest`, refused over `cap` from Content-Length before the first byte and
    again while streaming (the header is usually absent); one re-login on 401 for a ticket plane,
    the way `wire.Client.call` does. Any refusal or error removes the partial file."""
    h = hashlib.sha256()
    n = 0
    try:
        for attempt in (1, 2):
            with client._client.stream("GET", path, headers=client._headers(False),
                                       params=wire._form(params), timeout=TIMEOUT) as r:
                if r.status_code == 401 and client.spec.get("auth") == "ticket" and attempt == 1:
                    client._relogin()
                    continue
                if r.status_code != 200:
                    # ONLY A 200 IS A DOWNLOAD. A 3xx or a 204 would land an empty or an HTML
                    # "moved" page as the file with a receipt saying ok (lens 3). The body is
                    # never echoed: a 401's text can carry the credential the caller sent, and a
                    # quarantined mail's answer is attacker text; the status is what the operator
                    # needs and the receipt holds it.
                    r.read()
                    raise ProximoError(f"download refused by the API: HTTP {r.status_code}; "
                                       "the body is not echoed")
                declared = r.headers.get("content-length")
                if declared and declared.isdigit() and int(declared) > cap:
                    raise ProximoError(f"download is {declared} bytes, over {CAP_ENV}={cap}; "
                                       "raise the cap or pull a smaller path")
                with open(dest, "wb") as out:
                    for chunk in r.iter_bytes():
                        n += len(chunk)
                        if n > cap:
                            raise ProximoError(f"download passed {CAP_ENV}={cap} while streaming (no length "
                                               "header); partial removed, raise the cap or pull a smaller path")
                        h.update(chunk)
                        out.write(chunk)
                return {"path": dest, "bytes": n, "sha256": h.hexdigest()}
        raise ProximoError("download refused by the API: HTTP 401 after one re-login")
    except BaseException:
        try:
            os.unlink(dest)
        except OSError:
            pass
        raise
