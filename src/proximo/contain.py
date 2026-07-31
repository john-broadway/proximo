"""Containment gate — an out-of-band breaker read at Proximo's single mutation funnel.

The trip is a file named by the env var ``PROXIMO_CONTAIN_TRIP_PATH``, read FRESH on every
call (no caching, no process state) so an out-of-band actor can arm or clear it without
touching Proximo. Contained iff that file exists; its contents, if any, are an optional
human "reason" string surfaced in the refusal and the ledger.

Two invariants make this a safe breaker rather than a foot-gun:

- **Env unset => never contained.** Zero behavior change when the operator hasn't opted in
  (same ethos as an unset optional config): every existing call path stays byte-identical.
- **Fail-closed.** When the env IS set (the operator opted in) and the existence check itself
  errors — a permission denial, a garbled/too-long path, a non-directory component — the safe
  reading is CONTAINED, not "assume clear and keep mutating". Only an unambiguous "file is
  absent" (FileNotFoundError) reads as not-contained.

Read with ``os.stat`` (not ``os.path.exists``): ``exists`` swallows OSError/ValueError and
returns False, which would silently downgrade a perm/garbled trip to "not contained" — a
fail-OPEN breaker. ``os.stat`` lets us split "absent" (FileNotFoundError) from "errored"
(other OSError/ValueError) and honor the fail-closed contract.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .backends import ProximoError
from .principal import ledger_principal
from .targets import ledger_remote

if TYPE_CHECKING:
    from .audit import AuditLedger

TRIP_ENV = "PROXIMO_CONTAIN_TRIP_PATH"


@dataclass(frozen=True)
class ContainState:
    """The containment reading for one call. ``reason`` is an optional operator-supplied string."""

    contained: bool
    reason: str | None = None


def contain_state() -> ContainState:
    """Read the trip state fresh. See the module docstring for the two invariants."""
    path = os.environ.get(TRIP_ENV)
    if not path:  # env unset (or empty) => never contained: zero behavior change
        return ContainState(contained=False)
    try:
        os.stat(path)
    except FileNotFoundError:
        return ContainState(contained=False)  # env set but trip simply absent = normal
    except (OSError, ValueError):
        return ContainState(contained=True)  # perm/garbled/non-dir/too-long => fail-closed
    # Trip present => contained. Read an optional reason, but a read failure must never
    # un-contain — it just drops the reason.
    reason: str | None = None
    try:
        text = _read_reason(path)
        reason = text or None
    except (OSError, ValueError):
        reason = None
    return ContainState(contained=True, reason=reason)


def _read_reason(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read().strip()


def enforce_containment(action: str, target: str, audit: AuditLedger, *,
                         detail: dict | None = None) -> None:
    """The SINGLE containment check for every mutation-causing call. Reads contain_state(); if
    contained, records the blocked attempt to the PROVE ledger (outcome "contained") and raises
    ProximoError BEFORE the caller's real mutating backend call can fire.

    This is the one seam both `_audited()`'s mutation branch and any manual-audit-path tool (one
    that records its own outcomes via `audit.record(...)` instead of going through `_audited`,
    e.g. pve_agent_exec's honest "running" vs "ok" outcome, or ct_exec/ct_psql's pre-mutation
    auto-undo snapshot) must call — so a future manual-audit-path tool cannot silently mutate a
    real backend while contained. Call it BEFORE the mutating backend call, not after.
    """
    state = contain_state()
    if not state.contained:
        return
    audit.record(action, target=target, mutation=True, outcome="contained",
                 detail={**(detail or {}), **({"reason": state.reason} if state.reason else {})},
                 principal=ledger_principal(), remote=ledger_remote())
    msg = f"contained: mutation {action!r} refused (containment trip active)"
    if state.reason:
        msg += f" — {state.reason}"
    raise ProximoError(msg)
