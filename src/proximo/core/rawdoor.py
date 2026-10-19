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
     Where a curated read stripped a credential (a remote's password, an ACME plugin's DNS
     keys), `core/secrets.toml` withholds the same field here and the envelope says so.
  3. It never invents. The result is the vendor's `data` in a labelled envelope
     (`derived: false`, the published path it matched); a body over the byte cap is reported
     as truncated with its size, never handed back as a silent prefix.

Pure: no backend, no ledger. `proximo.tools.raw_door` supplies both.
"""

from __future__ import annotations

import json
import os
import re
from urllib.parse import unquote, urlencode

from proximo.core import apitree
from proximo.core.errors import ProximoError

DEFAULT_MAX_BYTES = 6 * 1024   # 4K-shaped: ~1,500 tokens, one answer's share of a 4,000-token window
_KEY = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_BAD_SEGMENT = re.compile(r"[\s?#]|[\x00-\x1f\x7f]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# The guest-agent subtree: ONE definition, referenced by _GATED here and by the opt-in gate in
# `proximo.core.spine` (spine imports this constant, so the prefix is not retyped). Unlike the
# download/quarantine gates below, this is an OPT-IN gate: the engine serves these addresses when
# PROXIMO_ENABLE_AGENT is set and the VMID is on PROXIMO_AGENT_ALLOWLIST (spine.agent_refusal);
# the gate string is the raw door's pointer and the table's "this row is governed by the opt-in".
AGENT_PREFIX = "/nodes/{node}/qemu/{vmid}/agent"

# Published prefixes a curated tool gates; the door points at the tool instead of opening them.
# Keyed by plane; the value is the tool family and the gate it enforces.
_GATED: dict[str, tuple[tuple[str, str], ...]] = {
    "pve": (
        (
            # The raw GET door still points here; the engine serves this subtree through the
            # opt-in (spine.agent_refusal), so the operator sees the opt-in sentence, not this.
            # The string is unchanged from the committed table.json.gz, which stays byte-built.
            AGENT_PREFIX,
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
#: THE DOWNLOAD LANE: the gated paths that answer bytes, not JSON. The raw GET door still refuses
#: them (it answers JSON); the engine serves them through `proximo.core.download` once the
#: operator opens the lane (PROXIMO_ENABLE_DOWNLOAD), landing the bytes on disk under a cap.
STREAMS: frozenset[tuple[str, str]] = frozenset(
    (product, path) for product, entries in _GATED.items() for path, _tool in entries if path != AGENT_PREFIX)


def is_stream(product: str, path: str) -> bool:
    return (product, path) in STREAMS


MAX_PARAM_CHARS = 4096


def _gated(published: str, prefix: str) -> bool:
    """`prefix` names a published path or a subtree of it: equal, or a child by whole segment."""
    return published == prefix or published.startswith(prefix + "/")


def reject_malformed(path: str, *, allow_placeholders: bool = False) -> None:
    """Refuse a path whose spelling could make the governed string differ from the sent one.

    EXTRACTED so there is exactly ONE copy. `proximo.core.engine` governs a normalized path and
    sends an unnormalized one; without this check an adversarial lens showed `//nodes/backup` on
    pbs governed as `GET /nodes/{node}` while httpx collapses it to `/backup` -- an EXCLUDED
    protocol tunnel. Anything that a URL library may re-interpret (`//`, `..`, `?`, `#`,
    whitespace, control characters) must die here, at the spelling, before the address is
    matched and long before a credential is read.

    `allow_placeholders` lets a governance LOOKUP accept the published template spelling
    (`/nodes/{node}/status`), which a plan may legitimately ask about. It never permits one at
    the wire: `execute` refuses a path that still carries placeholders.

    A value that carries a slash (a CIDR, a volume id) rides its segment as `%2F`, so the gate
    judges the DECODED spelling too, for what breaks the door's invariants: a control character
    (a lens sent `192.0.2.0%0A%2F24`, whose `%0A` decoded into the newline that separates the
    forbid haystack's fields and split the operator's entry in two; THIS check is what kills it),
    an empty or `..` segment, and any `%` that survives one decode (`%252F`, `%zz`: what the
    vendor would make of a second decode is not ours to guess). Not a space, `#` or `?` inside a
    value: the wire gets the encoded bytes, a file name may carry them, and a lens found the
    wider rule refusing `Windows 11 Pro.iso`.
    """
    decoded = unquote(path)
    bad = (
        not path.startswith("/")
        or "//" in path
        or "//" in decoded
        or _BAD_SEGMENT.search(path)
        or _CONTROL.search(decoded)
        or ".." in decoded.split("/")
        or "%" in decoded
        or (not allow_placeholders and ("{" in path or "}" in path))
    )
    if bad:
        raise ProximoError(
            f"malformed path {path!r}: an absolute API path"
            + ("" if allow_placeholders else " with real values in it (no `{placeholders}`)")
            + ", no query string, no empty or '..' segments and no whitespace; inside a value "
              "a '/' is %2F, a control character is refused however it is spelled, and a '%' "
              "must not survive one decode (query parameters go in `params`)"
        )


def validate(plane: str, path: str) -> str:
    """The published form of `path` if it is a GET the plane publishes and no curated tool
    gates; a ProximoError that says why otherwise. Runs before any backend is built."""
    if plane not in apitree.PRODUCTS:
        raise ProximoError(f"unknown plane {plane!r}: one of {', '.join(apitree.PRODUCTS)}")
    reject_malformed(path)
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


def bounded(data: object) -> dict | None:
    """None when `data` fits the cap; else what stands in for it. ONE copy, both doors (the raw
    GET door and the governed engine): a body over the cap is reported, never handed back as a
    silent prefix and never handed back whole. A LIST is cut by rows, with `total` and
    `returned` beside the rows that fit, so the count survives the cut (a slice can never pass
    itself off as the whole population); anything else is reported by size with a short head."""
    body = json.dumps(data, default=str)
    cap = max_bytes()
    if len(body) <= cap:
        return None
    note = ("response exceeds PROXIMO_RAW_MAX_BYTES; narrow it with params (the published path's own "
            "filters) or raise the cap deliberately")
    if isinstance(data, list):
        kept, used = [], 2                      # the brackets
        for item in data:
            piece = len(json.dumps(item, default=str)) + (2 if kept else 0)   # ", " between rows
            if used + piece > cap:
                break
            kept.append(item)
            used += piece
        while kept and len(json.dumps(kept, default=str)) > cap:   # exact, whatever the encoder does
            kept.pop()
        return {"truncated": True, "bytes": len(body), "cap": cap, "total": len(data),
                "returned": len(kept), "data": kept, "note": note}
    return {"truncated": True, "bytes": len(body), "cap": cap, "head": body[:2048], "note": note}


def envelope(plane: str, path: str, published: str, data: object) -> dict:
    """The vendor's data, labelled raw. Over the cap: size, cap, a short head, and how to narrow."""
    out: dict = {"plane": plane, "path": path, "published": published, "method": "GET", "derived": False}
    over = bounded(data)
    return {**out, **over} if over else {**out, "data": data}
