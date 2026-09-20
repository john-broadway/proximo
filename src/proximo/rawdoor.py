"""The raw GET door — every published read on every plane, reachable by path.

The 2026-08-12 ruling: the estate layer computes with provenance, and the raw API stays
reachable underneath it. The curated tools are the thin hops; this is the floor under them.
Three laws keep it a door and not a hole:

  1. A path must name a read the vendor publishes. It is matched against the vendored tree
     (`proximo.apitree`) with GET as the only method BEFORE the wire is touched; a write-only
     path, a console or migration tunnel, or a path nobody publishes is refused with the
     nearest published reads named.
  2. It never launders a gate. Where a curated tool already stands guard over a read (the
     qemu-agent family behind PROXIMO_ENABLE_AGENT and its allowlist; the byte streams that
     the file-restore tools land on disk under a cap), the door refuses and names the tool.
  3. It never invents. The result is the vendor's `data` in a labelled envelope
     (`derived: false`, the published path it matched); a body over the byte cap is reported
     as truncated with its size, never handed back as a silent prefix.

Pure: no backend, no ledger. `proximo.tools.raw_door` supplies both.
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import urlencode

from proximo import apitree
from proximo.backends import ProximoError

DEFAULT_MAX_BYTES = 256 * 1024
_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_BAD_SEGMENT = re.compile(r"[\s?#]|[\x00-\x1f\x7f]")

# Published prefixes a curated tool gates; the door points at the tool instead of opening them.
# Keyed by plane; the value is the tool family and the gate it enforces.
_GATED: dict[str, tuple[tuple[str, str], ...]] = {
    "pve": (
        (
            "/nodes/{node}/qemu/{vmid}/agent",
            "pve_agent_* (PROXIMO_ENABLE_AGENT and PROXIMO_AGENT_ALLOWLIST gate every guest-agent read)",
        ),
        (
            "/nodes/{node}/storage/{storage}/file-restore/download",
            "pve_file_restore_download (bytes land on disk under a cap, never in a response)",
        ),
    ),
    "pbs": (
        ("/admin/datastore/{store}/pxar-file-download", "pbs_file_download (bytes land on disk under a cap)"),
        (
            "/admin/datastore/{store}/download",
            "a byte stream no curated tool serves yet; pbs_file_download lands pxar-file-download on disk",
        ),
        (
            "/admin/datastore/{store}/download-decoded",
            "a byte stream no curated tool serves yet; pbs_file_download lands pxar-file-download on disk",
        ),
    ),
    "pmg": (("/quarantine/download", "pmg_quarantine_* (a mail body is a stream, not a JSON read)"),),
    "pdm": (),
}
MAX_PARAM_CHARS = 4096


def _gated(published: str, prefix: str) -> bool:
    """`prefix` names a published path or a subtree of it: equal, or a child by whole segment."""
    return published == prefix or published.startswith(prefix + "/")


def validate(plane: str, path: str) -> str:
    """The published form of `path` if it is a GET the plane publishes and no curated tool
    gates; a ProximoError that says why otherwise. Runs before any backend is built."""
    if plane not in apitree.PRODUCTS:
        raise ProximoError(f"unknown plane {plane!r}: one of {', '.join(apitree.PRODUCTS)}")
    if (
        not path.startswith("/")
        or "//" in path
        or _BAD_SEGMENT.search(path)
        or ".." in path.split("/")
        or "{" in path
        or "}" in path
    ):
        raise ProximoError(
            f"malformed path {path!r}: an absolute API path with real values in it (no `{{placeholders}}`), "
            "no query string, no empty or '..' segments and no whitespace (query parameters go in `params`)"
        )
    published = apitree.find(plane, path, "GET")
    if published is None:
        near = apitree.nearest(plane, path, "GET")
        hint = f" Published GET paths nearby: {', '.join(near)}." if near else ""
        raise ProximoError(f"{plane} publishes no GET at {path!r} (a write-only path, a tunnel, or nothing).{hint}")
    for prefix, tool in _GATED[plane]:
        if _gated(published, prefix):
            raise ProximoError(f"{path!r} is gated by a curated tool; use {tool}. The raw door does not open a gate.")
    return published


def check_params(params: dict | None) -> dict:
    """Flat string/number/bool query parameters, bools in the 1/0 form Proxmox accepts."""
    out: dict = {}
    for key, value in (params or {}).items():
        if not isinstance(key, str) or not _KEY.match(key):
            raise ProximoError(f"params: key {key!r} is not a plain query name")
        if isinstance(value, bool):
            out[key] = 1 if value else 0
        elif isinstance(value, str) and len(value) > MAX_PARAM_CHARS:
            raise ProximoError(f"params: {key!r} is longer than {MAX_PARAM_CHARS} characters")
        elif isinstance(value, (str, int, float)):
            out[key] = value
        else:
            raise ProximoError(f"params: {key!r} must be a string, number or bool, not {type(value).__name__}")
    return out


def canonical(path: str) -> str:
    """One spelling per resource for the ledger target: no trailing slash."""
    return path.rstrip("/") or "/"


def with_query(path: str, params: dict) -> str:
    """For a backend whose `_get` takes no params argument: the query rides the path."""
    return f"{path}?{urlencode(params)}" if params else path


def max_bytes() -> int:
    raw = os.environ.get("PROXIMO_RAW_MAX_BYTES", "")
    try:
        return int(raw) if raw else DEFAULT_MAX_BYTES
    except ValueError:
        return DEFAULT_MAX_BYTES


def envelope(plane: str, path: str, published: str, data: object) -> dict:
    """The vendor's data, labelled raw. Over the cap: size, cap, a short head, and how to narrow."""
    body = json.dumps(data, default=str)
    out: dict = {"plane": plane, "path": path, "published": published, "method": "GET", "derived": False}
    cap = max_bytes()
    if len(body) > cap:
        out.update(
            truncated=True,
            bytes=len(body),
            cap=cap,
            head=body[:2048],
            note=(
                "response exceeds PROXIMO_RAW_MAX_BYTES; narrow it with params (the published path's own "
                "filters) or raise the cap deliberately"
            ),
        )
        return out
    out["data"] = data
    return out
