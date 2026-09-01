"""The mirror's enforcement verdict — the junction closed with Proxmox's own map.

``pct exec`` over ssh answers to no PVE privilege: it is the one channel the platform cannot
scope, and the reason the env allowlist has always existed. The mirror ends the asymmetry:
with ``PROXIMO_REACH_PRIVILEGE`` set to a PVE privilege name (the operator's chosen REACH PRIVILEGE — the
reach-audit verb prints the aliasing evidence that informs the choice; a CUSTOM ROLE carrying
one privilege decouples AI reach from human role grants, though the privilege still aliases
wherever built-in roles carry it), a container op is
permitted only where the SERVED token holds that privilege — asked of PVE per guest path
(``/access/permissions?path=/vms/<ctid>``), because the full map returns ACL-anchored paths
only while the per-path query resolves propagation and deeper-NoAccess revocation server-side
(probed live 2026-08-26). One GET per check, PVE's own resolution, zero reimplementation.

Semantics, deliberately:
- DORMANT unless the reach-privilege env is set — no query, zero behavior change (armgate's contract).
- INTERSECTION, never widening: the env allowlist is checked FIRST and still refuses on its
  own; the mirror can only narrow further. A mirror-driven estate sets the allowlist to ``*``
  and lets the token's own map be the whole boundary; the allowlist stays as the offline
  intersection and break-glass.
- FAIL-CLOSED on API failure: no reachable map, no reach. The stated availability cost — the
  break-glass for an API outage is the operator unsetting the reach privilege to fall back to the
  allowlist alone, which on a mirror-driven estate (allowlist ``*``) is a WIDENING, not a
  narrowing — the reason that flip is itself a WITNESSED reach-grant change (the privilege is a snapshot-level
  source in reachgrant.grant_snapshot — witnessed on EVERY deployment shape, pure-targets
  included, since enforcement reads the process env regardless of the env lane's health).
- The served token's map is the one that governs: disarmed (read-only token without the
  privilege) means no shell reach anywhere — the mirror composes with armgate for free.

Covered channels: ct_exec, ct_psql (the mutating shell), AND the read-only shell siblings
ct_logs / ct_diagnose — reach is reach, and journald from an unmarked guest is disclosure at
allowlist breadth; the reads stay ARM-free by the 08-24 ruling (authority and reach are
different questions) but not mirror-free.

Honest limits: enforcement runs at the TOOL seam (where the API handle lives); a caller
reaching ExecBackend directly still hits the allowlist and armgate there, but not the mirror —
the backend seam has no API client and constructing one per call would put a network dependency
inside the lowest layer. Multi-target: the privilege is env-lane only in this brick; a per-target
field follows the arm_source precedent when targets need it. The per-path keying premise
("PVE returns the propagated grant keyed under the queried path") was probed live 2026-08-26
and is exercised by every reach-audit run; a keying drift fails CLOSED (denied), never open.
A reach privilege set to WHITESPACE is a refused misconfiguration, not silent dormancy.
"""
from __future__ import annotations

import os
from typing import Any

PRIVILEGE_ENV = "PROXIMO_REACH_PRIVILEGE"


def privilege() -> str | None:
    """The configured reach privilege, or None when genuinely unset. A set-but-whitespace value is a
    MISCONFIGURATION and raises — silently treating it as dormant would fail OPEN back to
    allowlist-only reach with no signal (lens finding)."""
    raw = os.environ.get(PRIVILEGE_ENV)
    if raw is None:
        return None
    m = raw.strip()
    if not m:
        raise ValueError(f"{PRIVILEGE_ENV} is set but blank — refusing to guess between "
                         "'mirror off' and 'mirror on': unset it or name a privilege.")
    return m


def mirror_verdict(api: Any, ctid: str) -> tuple[str, dict]:
    """One check: does the served token hold the reach privilege at this guest's path?

    Returns (verdict, detail): ``off`` (dormant — no query was made), ``allowed``, ``denied``,
    or ``unavailable`` (the API did not answer — the caller must fail CLOSED). Never raises:
    the verdict is data, the refusal policy lives at the seam.
    """
    return _verdict_at(api, f"/vms/{ctid}")


def node_verdict(api: Any, node: str) -> tuple[str, dict]:
    """The same question one altitude up: does the served token hold the reach privilege at
    THE NODE's own path (``/nodes/<name>``)? Gates the host-side shell battery — the node's
    journal is disclosure at HOST breadth, wider than any one guest's. Same semantics, same
    fail-closed contract, same dormancy: one privilege governs the whole shell channel, and
    where the operator grants it (a guest path, a pool, the node) IS the reach."""
    return _verdict_at(api, f"/nodes/{node}")


def _verdict_at(api: Any, path: str) -> tuple[str, dict]:
    try:
        m = privilege()
    except ValueError as e:
        return "misconfigured", {"error": str(e)}
    if m is None:
        return "off", {}
    try:
        perms = api.access_permissions(path=path) or {}
    except Exception as e:
        return "unavailable", {"privilege": m, "error": type(e).__name__}
    if (perms.get(path) or {}).get(m):
        return "allowed", {"privilege": m}
    return "denied", {"privilege": m}
