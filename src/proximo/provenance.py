"""Provenance / scope gate (gap #3, slice 1) — arm-time declared TARGET scope.

Out-of-band file named by ``PROXIMO_SCOPE_PATH``, read FRESH on every call (no caching, no
process state — same discipline as ``contain.py``), enforced at Proximo's mutation funnel. Closes
the headline scenario: an injected instruction targeting a guest OUTSIDE the declared scope
(``delete lxc/102`` when scope is ``{lxc/900..lxc/910}``) is refused, fail-closed, before the
backend call, and audited.

Two invariants make this a safe allowlist rather than a foot-gun:

- **Env unset => unrestricted.** Zero behavior change when the operator hasn't opted in: every
  existing call path stays byte-identical.
- **Fail-closed.** When the env IS set (the operator opted in) and the scope file is
  unreadable/garbled/authorizes-nothing, the safe reading is REFUSE ALL MUTATIONS, not "assume
  unrestricted". Only an unambiguous "file is absent" (FileNotFoundError) reads as no-scope (the
  transitional armed-not-yet-written window).

Read with ``os.stat`` (not ``os.path.exists``): ``exists`` swallows OSError/ValueError and
returns False, which would silently downgrade a perm/garbled scope file to "unrestricted" — a
fail-OPEN gate. ``os.stat`` lets us split "absent" (FileNotFoundError) from "errored" (other
OSError/ValueError) and honor the fail-closed contract.

Build contract (single source of truth):
.scratch/proximo-zerotrust/specs/02b-provenance-resolved-contract.md
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .backends import ProximoError
from .principal import ledger_principal
from .targets import ledger_remote

if TYPE_CHECKING:
    from .audit import AuditLedger

SCOPE_ENV = "PROXIMO_SCOPE_PATH"

_GUEST_RE = re.compile(r"^(lxc|qemu)/[0-9]+\Z")

# A real scope file is tiny (a handful of target strings). Cap it generously so a huge/hostile
# file fails closed on size BEFORE json.load ever reads it into memory (MemoryError guard).
_MAX_SCOPE_BYTES = 1 << 20  # 1 MiB


@dataclass(frozen=True)
class ScopeState:
    """The scope reading for one call.

    ``declared`` — a scope file is in force (True) vs no scope at all (False, unrestricted).
    ``fail_closed`` — the file is present but unreadable/garbled/authorizes-nothing: refuse ALL
    mutations. ``targets`` — the allowlist of scope-keys (see ``scope_key``). ``reason`` — an
    optional operator note, audit-only, NEVER matched against a target or action.
    """

    declared: bool
    fail_closed: bool = False
    targets: frozenset[str] = field(default_factory=frozenset)
    reason: str | None = None


def scope_state() -> ScopeState:
    """Read the scope state fresh. See the module docstring for the two invariants."""
    path = os.environ.get(SCOPE_ENV)
    if not path:  # env unset (or empty) => unrestricted: zero behavior change
        return ScopeState(declared=False)
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return ScopeState(declared=False)  # env set but scope file simply absent = no-scope
    except (OSError, ValueError):
        return ScopeState(declared=True, fail_closed=True)  # perm/garbled/non-dir => fail-closed

    if st.st_size > _MAX_SCOPE_BYTES:
        return ScopeState(declared=True, fail_closed=True)  # implausibly huge => fail-closed

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:  # any parse/read failure (incl. RecursionError on deeply nested JSON) is
        # fail-closed, the correct behavior for a fail-closed gate. Exception does not catch
        # KeyboardInterrupt/SystemExit.
        return ScopeState(declared=True, fail_closed=True)

    if not isinstance(data, dict):
        return ScopeState(declared=True, fail_closed=True)

    targets = data.get("targets")
    if not isinstance(targets, list) or not targets or not all(isinstance(t, str) for t in targets):
        # missing / empty / not-a-list-of-str => a scope file that authorizes nothing refuses
        # everything (fail-closed, documented — never "assume unrestricted").
        return ScopeState(declared=True, fail_closed=True)

    reason = data.get("reason")
    if not isinstance(reason, str):
        reason = None

    return ScopeState(declared=True, targets=frozenset(targets), reason=reason)


def scope_key(target: str) -> str:
    """THE PINNED MATCHING RULE (contract §2) — do NOT drift.

    Guest targets carry `:action`/`:snapname` suffixes in their ledger string; the operator can't
    predict those. So normalize a guest-identity target (`lxc/<vmid>` or `qemu/<vmid>`, optionally
    suffixed) to its bare `kind/vmid`, and leave everything else EXACT. Normalization may only
    ever merge targets naming the SAME guest identity (kind+vmid); it must NEVER merge two
    different guests or collapse a non-guest target — e.g. `lxc/900` never matches a `qemu/900`
    scope, and `acl:prune:/vms:bob@pam` is never collapsed to `acl`.
    """
    base = target.split(":", 1)[0]  # strip a trailing :action / :snapname
    if _GUEST_RE.match(base):
        return base  # lxc/902:stop -> lxc/902 ; qemu/902 -> qemu/902
    return target  # everything else EXACT (no collapsing) — bare ctids, ACL targets, clone arrows


def enforce_scope(action: str, target: str, audit: AuditLedger, *,
                   detail: dict | None = None) -> None:
    """The SINGLE scope check for every mutation-causing call. Reads scope_state(); if no scope is
    declared, no-op (zero behavior change). If fail-closed, or the target's scope_key isn't on the
    declared allowlist, records the blocked attempt to the PROVE ledger and raises ProximoError
    BEFORE the caller's real mutating backend call can fire.

    Mirrors `enforce_containment`'s seam discipline exactly: this is the one primitive both
    `_audited()`'s mutation branch and any manual-audit-path tool (pve_agent_exec; ct_exec/ct_psql
    before their auto-undo snapshot) must call, so a future manual-audit-path tool cannot silently
    mutate a real backend outside the declared scope. Call it BEFORE the mutating backend call.
    """
    state = scope_state()
    if not state.declared:
        return
    if state.fail_closed:
        audit.record(action, target=target, mutation=True, outcome="blocked:scope_unreadable",
                     detail={**(detail or {}), **({"reason": state.reason} if state.reason else {})},
                     principal=ledger_principal(), remote=ledger_remote())
        raise ProximoError(f"scope refused: {action!r} on {target!r} (scope file unreadable, "
                            "garbled, or authorizes nothing — fail-closed)")
    key = scope_key(target)
    if key not in state.targets:
        audit.record(action, target=target, mutation=True, outcome="blocked:out_of_scope",
                     detail={**(detail or {}), "scope_key": key,
                             **({"reason": state.reason} if state.reason else {})},
                     principal=ledger_principal(), remote=ledger_remote())
        raise ProximoError(f"out of declared scope: {action!r} on {target!r} (key {key!r})")
    return  # in scope — proceed
