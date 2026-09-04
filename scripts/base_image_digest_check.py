#!/usr/bin/env python3
"""Verify the Dockerfile's base-image digest against the registry, by script, not by eye.

Reads every digest-pinned `FROM python:<tag>@sha256:...` line in the Dockerfile, asks Docker Hub
for that tag's current index digest, and reports MATCH (the pin IS the tag head), BEHIND (the tag
has moved past the pin; a fold candidate), or UNKNOWN (registry unreadable). Also refuses a
Dockerfile whose stages disagree with each other. Exit 0 on MATCH, 1 on BEHIND or disagreement,
2 on UNKNOWN. Read-only; no docker needed.

Why (2026-09-03): the base-image fold's "verified byte for byte against the registry" was an ad
hoc one-liner nobody could re-run; a lens called it unverifiable. Now it is this file.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

_FROM = re.compile(r"^FROM python:([\w.-]+)@(sha256:[0-9a-f]{64})", re.M)
_HUB = "https://hub.docker.com/v2/repositories/library/python/tags/{tag}"


def main(argv: list[str]) -> int:
    dockerfile = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent / "Dockerfile"
    pins = _FROM.findall(dockerfile.read_text(encoding="utf-8"))
    if not pins:
        print(f"no digest-pinned python FROM line in {dockerfile}", file=sys.stderr)
        return 1
    tags = {t for t, _ in pins}
    digests = {d for _, d in pins}
    if len(tags) != 1 or len(digests) != 1:
        print(f"DISAGREE: the Dockerfile's stages pin different bases: {pins}", file=sys.stderr)
        return 1
    tag, pinned = pins[0]
    url = _HUB.format(tag=tag)
    if not url.startswith("https://hub.docker.com/"):  # one fixed host, one scheme; never a file: or custom scheme
        raise ValueError(f"refusing to open a non-registry URL: {url}")
    try:
        with urllib.request.urlopen(url, timeout=20) as r:  # noqa: S310 (scheme+host asserted above)
            head = json.load(r)["digest"]
    except (urllib.error.URLError, OSError, KeyError, ValueError) as e:
        print(f"UNKNOWN: could not read the registry for {tag}: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    if head == pinned:
        print(f"MATCH: python:{tag} pin {pinned[:19]} is the registry's tag head")
        return 0
    print(f"BEHIND: python:{tag} pin {pinned[:19]} but the tag head is {head[:19]} (fold candidate)")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
