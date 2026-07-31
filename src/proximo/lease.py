"""CONTAIN — LEASE leg: an auto-expiring TTL on `arm` (gap: fail-open-over-time).

`arm` is a token file on disk, read fresh per call — it survives session-end/crash/reboot, so
elevated write-authority never lapses on its own; only a manual `disarm` reverts it. This module
gives `arm` a TTL: elevated authority auto-expires after ``PROXIMO_ARM_TTL`` seconds, measured from
the arm token file's mtime (``arm`` installs the operator token to that path — verified empirically:
`install -m 600` with no `-p` always stamps the current mtime, so mtime IS the arm-time stamp).

**Env-read, not cfg-threaded.** ``lease_state()`` takes NO arguments and reads BOTH
``PROXIMO_ARM_TTL`` and ``PROXIMO_TOKEN_PATH`` from env fresh on every call (no caching, no process
state — same discipline as ``contain_state()``/``scope_state()``). This was a deliberate rejection
of passing ``cfg.token_path`` in: two of the five mutation seams (``_audited``'s mutation branch,
``_auto_undo``) are plane-independent — they use ``_ledger()`` precisely because ``_svc()`` raises
kind-safety for a non-PVE (pbs/pmg/pdm) active target. Threading ``cfg.token_path`` there would
either break non-PVE mutations or force ``_svc()`` into the hottest seam. An env-read is
dependency-free and works identically at all 5 seams.

Two invariants make this a safe TTL rather than a foot-gun:

- **Env unset (or ``<=0``) => never enforced.** Zero behavior change when the operator hasn't
  opted in: every existing call path stays byte-identical (same ethos as ``contain.py``).
- **Fail-closed.** Once ``PROXIMO_ARM_TTL`` is set, anything that prevents proving the lease is
  fresh reads as EXPIRED, never "assume fresh": a garbled TTL; an unset/empty ``PROXIMO_TOKEN_PATH``
  (guards the ``os.stat(None)`` ``TypeError`` footgun); an ``os.stat`` error (missing/perm/garbled
  path); a non-regular-file token path (a directory's mtime is bumped by unrelated churn inside it,
  so it isn't a valid arm-stamp); or an mtime AHEAD of the wall clock (clock skew — NTP step, VM
  migration, snapshot restore — can't prove the lease is in-window). Only a real, readable, regular
  file with an in-the-past, in-window mtime counts as a live lease.

Honest limit: this env-read gates ALL planes' mutations by the PVE token's mtime. That is correct
for the single-env deployment (one arm token = the whole write-authority), but a registry
multi-target deployment that sets ``PROXIMO_ARM_TTL`` without a ``PROXIMO_TOKEN_PATH`` in env fails
CLOSED (safe, if surprising) rather than silently ungating. mtime is also a proxy for arm-time — a
copy/touch to the past or present can still refresh or shorten the window (a forward-dated stamp now
fails closed); a signed sidecar ``armed-at`` stamp is a noted fast-follow, not built here. This
closes fail-open-over-time (the lease lapses on its own); it does not bound
in-window intent — an agent within the TTL still holds full authority (that is CONSENT's job).
"""

from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .backends import ProximoError
from .principal import ledger_principal
from .targets import ledger_remote

if TYPE_CHECKING:
    from .audit import AuditLedger

LEASE_ENV = "PROXIMO_ARM_TTL"
TOKEN_PATH_ENV = "PROXIMO_TOKEN_PATH"  # noqa: S105 -- env var NAME, not a secret value


@dataclass(frozen=True)
class LeaseState:
    """The lease reading for one call.

    ``enforced`` — the operator opted in (``PROXIMO_ARM_TTL`` set to a positive int). ``expired``
    — the lease is past its TTL (or its freshness could not be proven — fail-closed). ``age_seconds``
    / ``ttl`` — populated when known, surfaced in the refusal message and the ledger detail.
    """

    enforced: bool
    expired: bool = False
    age_seconds: int | None = None
    ttl: int | None = None


def lease_state() -> LeaseState:
    """Read the lease state fresh. See the module docstring for the two invariants."""
    raw = os.environ.get(LEASE_ENV, "").strip()
    if not raw:  # not opted in => zero behavior change
        return LeaseState(enforced=False)
    try:
        ttl = int(raw)
    except ValueError:
        return LeaseState(enforced=True, expired=True, ttl=None)  # garbled opt-in => fail-closed
    if ttl <= 0:  # explicit disable (contract §1)
        return LeaseState(enforced=False)
    path = os.environ.get(TOKEN_PATH_ENV)
    if not path:  # can't stat None => fail-closed (guards the os.stat(None) TypeError footgun)
        return LeaseState(enforced=True, expired=True, ttl=ttl)
    try:
        st = os.stat(path)  # follows symlinks: a symlink->token resolves to the token's real mtime
    except (OSError, ValueError):  # missing/perm/garbled path => fail-closed
        return LeaseState(enforced=True, expired=True, ttl=ttl)
    if not stat.S_ISREG(st.st_mode):
        # Not a regular file (a directory/device/fifo, or a symlink to one). A directory's mtime is
        # bumped by ANY entry create/delete inside it (a disarm swap, a temp file, log rotation), so
        # it is NOT a valid arm-time stamp — freshness can't be proven => fail-closed.
        return LeaseState(enforced=True, expired=True, ttl=ttl)
    now = time.time()
    if st.st_mtime > now:
        # mtime is AHEAD of the wall clock — clock skew (NTP step, VM live-migration, snapshot
        # restore) or a `touch -d <future>`. Freshness can't be proven, so fail-closed. NOTE: a
        # `max(0, ...)` clamp would be WRONG — it reads a future stamp as age 0 = "just armed" =
        # fail-OPEN. Must be an explicit fail-closed branch, not a clamp.
        return LeaseState(enforced=True, expired=True, ttl=ttl)
    age = int(now - st.st_mtime)
    return LeaseState(enforced=True, expired=age > ttl, age_seconds=age, ttl=ttl)


def enforce_lease(action: str, target: str, audit: AuditLedger, *,
                   detail: dict | None = None) -> None:
    """The SINGLE lease check for every mutation-causing call. Reads lease_state(); if not
    enforced (operator hasn't opted in, or explicitly disabled with ttl<=0), no-op (zero behavior
    change). If expired, records the blocked attempt to the PROVE ledger (outcome
    "blocked:lease_expired") and raises ProximoError BEFORE the caller's real mutating backend call
    can fire. Record BEFORE raise.

    Signature identical to ``enforce_containment``/``enforce_scope`` (no token_path param — see the
    module docstring's D1 rationale) so the 5 seam call sites are a uniform extra line. Wired
    AFTER ``enforce_scope`` and BEFORE ``enforce_consent`` (decision D3): "your arm expired, re-arm"
    is the most actionable message, so in a both-blocked case the lease outcome wins over the moot
    "no consent".
    """
    state = lease_state()
    if not state.enforced:
        return
    if not state.expired:
        return
    audit.record(action, target=target, mutation=True, outcome="blocked:lease_expired",
                 detail={**(detail or {}), "age_seconds": state.age_seconds, "ttl": state.ttl},
                 principal=ledger_principal(), remote=ledger_remote())
    raise ProximoError(
        f"arm lease expired: {action!r} refused — armed {state.age_seconds}s ago, "
        f"TTL {state.ttl}s; re-arm to continue"
    )
