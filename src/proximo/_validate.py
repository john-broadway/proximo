"""Plane-neutral input validators shared by the per-plane modules.

This is a small underscore-prefixed shared helper in the `backends.py` / `_secretfile.py` /
`_tls.py` precedent: the no-cross-plane rule bans plane-to-plane imports, not plane-neutral
shared mechanics. Only validators whose SHAPE is identical across planes belong here — a
validator that encodes a plane fact (a per-plane enum, a schema-specific length bound, a
divergent digest like pmg_identity's SHA-1 or PVE/PMG's permissive APT digests, hex up to
80 chars mixed-case) stays in its module. PBS's own APT digest is NOT divergent — it is the
standard strict 64-hex shape and aliases `check_digest` in pbs.py (the first pass wrongly
carried the audit's "APT digests are all divergent" claim; the lens measured it false).

`check_digest` replaced twelve per-module digest-check copies (A11 consolidation,
2026-08-11: eleven `_check_digest` + pbs.py's `_check_pbs_apt_digest`). Two deliberate
choices, made once here instead of twelve times:

- **Strict no-strip.** Three of the retired copies (pbs_access, pmg_identity, pbs_node)
  `.strip()`ped before matching, which re-admits the trailing newline the `\\Z` anchor
  exists to refuse (pbs_notifications' standing "Do NOT strip" note). Unifying strict
  narrows those three — a fail-closed tightening, pinned by their tests.
- **None passes through.** The digest is PBS/PMG's optimistic-concurrency lock and is
  optional on every surface that carries it; call sites either guard with
  `if digest is not None` or forward an omitted param as-is.
"""

from __future__ import annotations

import re
from collections.abc import Container

from .backends import ProximoError

# SHA-256 hex, exactly 64 lowercase chars — the shape every PBS/PMG config-plane 'digest'
# property documents (/^[a-f0-9]{64}$/), \Z-re-anchored per the trailing-newline-bypass
# discipline.
DIGEST_RE = re.compile(r"^[a-f0-9]{64}\Z")


def check_digest(digest: str | None) -> str | None:
    if digest is None:
        return None
    s = str(digest)
    if not DIGEST_RE.match(s):
        raise ProximoError(f"invalid digest: {digest!r} — expected 64 lowercase hex chars (SHA-256)")
    return s


def redact_secrets(d: dict, keys: Container[str]) -> dict:
    """Whole-value credential masking for plan/current dicts: any key in `keys` has its value
    swapped for "[redacted]" regardless of shape (plain string, list-of-dicts, ...) — never
    partially redacted. WHICH keys are secret is a plane fact: every module keeps its own
    key set (`_SECRET_KEYS`, `_LDAP_SECRET_KEYS`, ...), with its docstring saying why; only
    the masking mechanic is shared (A11 consolidation, 2026-08-11 — replaced fifteen
    per-module/per-family masking bodies across ten modules; sdn_objects keeps a thin
    wrapper for its url-userinfo branch)."""
    return {k: ("[redacted]" if k in keys else v) for k, v in d.items()}
