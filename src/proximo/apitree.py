"""The four Proxmox API trees, vendored: every `(path, method)` the official api-viewer
publishes, one file per product under `proximo/apidoc/`. Two readers share this module so
they cannot disagree: `scripts/api_coverage.py` (how much of the tree the curated tools
reach) and `proximo.rawdoor` (whether a raw GET names a real read before the wire is touched).

Placeholder segments (`{node}`, `{vmid}`) are wildcards; a literal segment matches itself only.
"""

from __future__ import annotations

import json
import re
from functools import cache
from importlib import resources

PRODUCTS = ("pve", "pbs", "pmg", "pdm")
SOURCES = {
    "pve": "https://pve.proxmox.com/pve-docs/api-viewer/apidoc.js",
    "pbs": "https://pbs.proxmox.com/docs/api-viewer/apidoc.js",
    "pmg": "https://pmg.proxmox.com/pmg-docs/api-viewer/apidoc.js",
    "pdm": "https://pdm.proxmox.com/docs/api-viewer/apidoc.js",
}
# Not REST reads or writes; dropped from every denominator and refused at the door.
EXCLUDED_PREFIXES: dict[str, tuple[str, ...]] = {
    "pve": (),
    "pbs": ("/backup/_upgrade_", "/reader/_upgrade_"),  # the backup/reader wire protocols
    "pmg": ("/config/whitelist",),  # deprecated alias of /config/welcomelist
    "pdm": (),
}
# Exact paths that are protocol roots, not reads: GET /backup and GET /reader are the HTTP/2
# upgrade handshakes of the two wire protocols above (pbs_admin.py names them the same way).
EXCLUDED_EXACT: dict[str, tuple[str, ...]] = {"pve": (), "pbs": ("/backup", "/reader"), "pmg": (), "pdm": ()}
EXCLUDED_TAILS = (  # console and migration tunnels: a ticket, then a websocket
    "vncproxy",
    "spiceproxy",
    "termproxy",
    "vncwebsocket",
    "mtunnel",
    "mtunnelwebsocket",
    "vncshell",
    "spiceshell",
)


def norm(path: str) -> str:
    """Query dropped, every `{...}` a bare `{}`, slashes collapsed, no trailing slash."""
    path = path.split("?")[0]
    path = re.sub(r"\{[^}]*\}", "{}", path)
    return re.sub(r"/+", "/", path).rstrip("/") or "/"


def matches(lit: str, api_path: str) -> bool:
    """Segment-wise equality where a `{}` on either side matches any one segment."""
    a, b = lit.split("/"), api_path.split("/")
    return len(a) == len(b) and all(x == y or x == "{}" or y == "{}" for x, y in zip(a, b, strict=True))


def excluded(product: str, path: str) -> bool:
    return (
        path in EXCLUDED_EXACT[product]
        or path.startswith(EXCLUDED_PREFIXES[product])
        or path.rsplit("/", 1)[-1] in EXCLUDED_TAILS
    )


@cache
def raw_tree(product: str) -> tuple[tuple[str, str], ...]:
    """The vendored `(path, method)` pairs exactly as published, placeholders named."""
    text = resources.files("proximo").joinpath("apidoc", f"{product}.ops.json").read_text()
    return tuple((p, m) for p, m in json.loads(text))


@cache
def tree(product: str) -> frozenset[tuple[str, str]]:
    """Normalized operations, exclusions applied: the denominator and the door's whitelist."""
    return frozenset((norm(p), m) for p, m in raw_tree(product) if not excluded(product, norm(p)))


def find(product: str, path: str, method: str = "GET") -> str | None:
    """The published path (placeholders named) that `path` reaches with `method`, else None."""
    want = norm(path)
    for raw, m in raw_tree(product):
        if m == method and not excluded(product, norm(raw)) and matches(want, norm(raw)):
            return raw
    return None


def nearest(product: str, path: str, method: str = "GET", limit: int = 5) -> list[str]:
    """Published `method` paths sharing the longest leading segments with `path`, for a refusal
    that says where the reader could have gone instead of a bare no."""
    want = norm(path).split("/")
    scored: list[tuple[int, str]] = []
    for raw, m in raw_tree(product):
        if m != method or excluded(product, norm(raw)):
            continue
        have = norm(raw).split("/")
        common = 0
        for x, y in zip(want, have, strict=False):
            if x == y or x == "{}" or y == "{}":
                common += 1
            else:
                break
        if common > 1:
            scored.append((-common, raw))
    return [raw for _, raw in sorted(scored)[:limit]]
