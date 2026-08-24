"""CONSENT — ARM leg: does the token the server serves actually carry WRITE authority?

`arm` swaps the PVE API token; the boundary it creates is enforced by **PVE's own permission
check**, which binds only the API backend. ``ct_exec``/``ct_psql`` reach into containers over
``ssh -> pct exec`` as root on the PVE host — authority that never touches the token. So on a
fully DISARMED session those tools ran anyway (found on the dogfood estate 2026-08-24: a session
whose served token was byte-identical to the read-only one executed arbitrary in-container
commands, with every existing gate satisfied).

``enforce_lease`` did not catch this and structurally could not. It proves the served token is
FRESH, never that it is the WRITE one — and ``arm.py`` deliberately stamps a fresh mtime on
*disarm* too, so a disarmed token reads as a brand-new lease. Freshness and authority are
different questions; this module asks the second one.

**The predicate, and why this direction.** Armed  <=>  the served token's bytes equal the arm
source's bytes. The tempting inverse — "armed unless it matches the read-only source" — fails
OPEN on a garbled, rotated, or truncated token: it matches neither source, so the inverse would
call it armed. Equality-with-the-arm-source fails CLOSED by construction, and it self-heals on
rotation (an unrecognized token refuses, the operator re-arms). ``PROXIMO_READONLY_SOURCE`` is
read for message quality only — "DISARMED" vs "unrecognized" — never for enforcement.

**Env-read, not cfg-threaded**, exactly like ``lease.py``/``contain.py``: ``arm_state()`` takes no
arguments and re-reads env on every call. The mutation seams are plane-independent, and threading
``cfg.token_path`` through them would break non-PVE mutations or force ``_svc()`` into the hottest
seam. Same rationale, same shape.

Two invariants, matching the house pattern:

- **``PROXIMO_ARM_SOURCE`` unset (or blank) => never enforced.** Zero behavior change for anyone
  not using the arm pattern. A mint-and-revoke deployment has no write token at rest, so there is
  nothing to compare and the gate stays dormant — which is correct, not a hole: there, no standing
  write authority exists to gate.
- **Fail-closed once opted in.** Unset/blank ``PROXIMO_TOKEN_PATH``; a missing, unreadable, empty,
  or non-regular token; an unreadable arm source; or any mismatch — every one reads as NOT armed.
  Only a readable regular file whose stripped bytes equal the arm source's counts as authority.

Honest limit: this proves the served token IS the write token, not that the write token still has
privileges at PVE (a revoked-but-present token reads armed here and 403s at the API). It closes
the ssh-path fail-open; it does not replace PVE's permission check, and is not meant to.

**No token material leaves this module** — not in ``ArmGateState``, not in a refusal message, not
in the ledger detail. A gate that leaks the credential it guards is worse than no gate.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .backends import ProximoError
from .principal import ledger_principal
from .targets import ledger_remote

if TYPE_CHECKING:
    from .audit import AuditLedger
    from .config import ProximoConfig

ARM_SOURCE_ENV = "PROXIMO_ARM_SOURCE"  # noqa: S105 -- env var NAME, not a secret value
READONLY_SOURCE_ENV = "PROXIMO_READONLY_SOURCE"  # noqa: S105 -- env var NAME
TOKEN_PATH_ENV = "PROXIMO_TOKEN_PATH"  # noqa: S105 -- env var NAME; shared with lease.py/arm.py


@dataclass(frozen=True)
class ArmGateState:
    """``enforced`` False => the operator does not use the arm pattern; ``armed`` is then moot.

    ``reason`` is a short, non-secret explanation for the ledger and the refusal text. It names
    file *conditions* only — never a path's contents.
    """

    enforced: bool
    armed: bool
    reason: str = ""


def _read_token(path: str) -> bytes | None:
    """Stripped bytes of a readable REGULAR file, else None (which always reads as NOT armed).

    A directory is rejected explicitly: ``open()`` on one raises IsADirectoryError (an OSError,
    so it would already fail closed) but naming it keeps the failure legible.
    """
    if not path:
        return None
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            return None
        with open(path, "rb") as f:
            return f.read().strip()
    except OSError:
        return None


def _same_path(a: str, b: str) -> bool:
    """True if two CONFIG VALUES name one file. Deliberately does NOT resolve symlinks or compare
    inodes: `test_a_symlinked_token_is_judged_by_its_TARGET` pins the symlink case as ARMED on
    purpose, and it is right to. `arm`/`disarm` install via temp+rename, which REPLACES a symlink
    at token_path with a regular file, so a symlink is transient and self-correcting. Two env
    vars set to the same path is neither: `disarm` would overwrite the arm source with the
    read-only token and the comparison could never mean anything again."""
    return os.path.normpath(os.path.abspath(a)) == os.path.normpath(os.path.abspath(b))


def arm_state(cfg: ProximoConfig | None = None) -> ArmGateState:
    """Read fresh and decide whether live WRITE authority is being served. Never caches.

    ``cfg`` is the config of the box the command is actually aimed at. Pass it. Without it this
    grades the process env, which is right only for the env-configured box: proximo has a target
    registry, and ``packaging/targets.example.toml`` already promises that "arming stays
    out-of-band and per-target: it swaps the token at that target's token_path". Grading the env
    while ssh -> pct exec runs against a registry target meant ARMED HERE READ AS ARMED
    EVERYWHERE. envelope.py resolves the active target for exactly this reason.

    Precedence, and every branch of it fails closed:
      * no cfg                       -> the env pair (unchanged, and the common single-box case)
      * cfg IS the env box           -> the env pair may supply what cfg leaves unset
      * cfg is a different box       -> its OWN arm_source, or NOT ARMED with a reason naming it
    """
    env_arm = os.environ.get(ARM_SOURCE_ENV, "").strip()
    env_token = os.environ.get(TOKEN_PATH_ENV, "").strip()
    env_ro = os.environ.get(READONLY_SOURCE_ENV, "").strip()

    if cfg is None:
        arm_source, token_path, readonly = env_arm, env_token, env_ro
    else:
        token_path = (cfg.token_path or "").strip()
        # Same token file => this IS the env-configured box, however it was constructed.
        # Normalized, like the degenerate-config check below: two spellings of one path are one
        # box, and disagreeing with _same_path here would refuse the env box over a trailing slash.
        is_env_box = bool(token_path) and bool(env_token) and _same_path(token_path, env_token)
        arm_source = (cfg.arm_source or "").strip() or (env_arm if is_env_box else "")
        readonly = (cfg.readonly_source or "").strip() or (env_ro if is_env_box else "")
        if not arm_source and env_arm:
            # The operator DOES use the arm pattern, just not for this box. Silence must not
            # read as permission: refuse, and say exactly which knob is missing.
            return ArmGateState(
                enforced=True, armed=False,
                reason="this target has no arm_source configured — set arm_source on its registry "
                       "entry; the default box's arm never authorizes another box")

    if not arm_source:
        return ArmGateState(enforced=False, armed=False, reason="arm pattern not configured")

    # `x == x` is not authority: one path for both sides would report ARMED forever, silently.
    if token_path and _same_path(token_path, arm_source):
        return ArmGateState(enforced=True, armed=False,
                            reason="misconfigured: the served token and the arm source are the "
                                   "same file, so the check would compare it to itself")

    served = _read_token(token_path)
    if served is None:
        return ArmGateState(enforced=True, armed=False,
                            reason="the served token is missing, unreadable, or not a regular file")
    if not served:
        # b"" == b"" would otherwise call an empty token a match against an empty arm source.
        return ArmGateState(enforced=True, armed=False, reason="the served token is empty")

    expected = _read_token(arm_source)
    if expected is None:
        return ArmGateState(enforced=True, armed=False,
                            reason="the arm source is missing, unreadable, or not a regular file")
    if served == expected:
        return ArmGateState(enforced=True, armed=True, reason="the served token is the arm source")

    # Enforcement is already decided. This only sharpens the message.
    readonly_bytes = _read_token(readonly)
    if readonly_bytes is not None and served == readonly_bytes:
        return ArmGateState(enforced=True, armed=False, reason="disarmed (serving the read-only token)")
    return ArmGateState(enforced=True, armed=False,
                        reason="the served token matches neither the arm nor the read-only source")


def enforce_arm(action: str, target: str, audit: AuditLedger, *,
                detail: dict | None = None, cfg: ProximoConfig | None = None) -> None:
    """The SINGLE write-authority check for mutations that do NOT flow through the PVE token.

    If the operator does not use the arm pattern, no-op (zero behavior change). Otherwise, unless
    the served token IS the arm source, record ``blocked:not_armed`` to the PROVE ledger and raise
    BEFORE the caller's real backend call can fire. Record BEFORE raise.

    Signature matches ``enforce_lease``/``enforce_containment``/``enforce_scope`` so the seam call
    sites stay a uniform extra line. Wired BEFORE ``enforce_lease``: "you are not armed" is more
    actionable than "your arm expired", so in a both-blocked case this outcome should win.
    """
    state = arm_state(cfg)
    if not state.enforced or state.armed:
        return
    audit.record(action, target=target, mutation=True, outcome="blocked:not_armed",
                 detail={**(detail or {}), "reason": state.reason},
                 principal=ledger_principal(), remote=ledger_remote())
    raise ProximoError(
        f"not armed: {action!r} refused — {state.reason}. This tool reaches the container over "
        "ssh, which does not carry the PVE token, so the arm is the only thing gating it. "
        "Arm the operator to continue."
    )
