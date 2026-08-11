"""Per-surface autonomy envelope — FORBID + RATE/BUDGET walls (Commit 2 of 2; design spec §11).

Origin: an autonomous agent's danger is velocity under hijack, not a single unsigned action —
trust cannot be a human pulling a lever per call. The operator declares the envelope ONCE
(at install, per product surface); the system enforces the walls by construction; the human is
on exception only. Full design: ``.scratch/proximo-zerotrust/specs/05-per-surface-autonomy-envelope.md``.

**Seam order (revised — RATE moved to after CONSENT).** This module is split into two entry
points, not one, precisely so they can straddle ``enforce_consent`` at all 5 mutation seams:
``enforce_containment -> enforce_scope -> enforce_lease -> enforce_envelope_forbid ->
enforce_consent -> enforce_envelope_rate -> <backend call>``. Rationale: an agent that
repeatedly plans+confirms actions CONSENT is going to refuse would otherwise burn the box's
entire rate budget on doomed attempts before consent ever got a say — turning the wall built to
bound a hijacked agent's velocity into a lever against the operator whose OWN approved
mutations then get refused for the rest of the window. FORBID stays an early hard wall before
consent (it is a cheap deny-list check, not a stateful spend, so putting it early costs
nothing and closes the same evasions it always did); RATE — the only half that actually
consumes shared budget — waits until consent has passed. The two halves are ALWAYS applied
separately (``enforce_envelope_forbid`` then, after consent, ``enforce_envelope_rate``) so a
consent-refused attempt spends no rate budget — there is deliberately no composed forbid-then-rate
wrapper, which would skip that sandwich.

**Forbid-list** — a set of action/sub-action strings the agent may NEVER run autonomously on the
active surface (exact name, or a substring alias like ``delete``/``destroy`` that expands to every
matching action). Two hardenings beyond a plain action-name check (design spec §11.B, closing a
3-lens redteam):

- **Composite match.** The dangerous sub-action often lives in the *target* string
  (``lxc/100:stop``, ``pve/services/sshd:stop``) or in ``detail["action"]``
  (``pmg_quarantine_action``'s delete/deliver/whitelist choice), not the bare action name.
  ``_forbidden`` matches against ``action``, ``target``, and ``detail.get("action")`` jointly
  (newline-joined so entries can't false-match across field boundaries).
- **Global floor.** ``PROXIMO_FORBID`` (global env) applies to EVERY mutation regardless of the
  active target — inescapable, and it cannot be evaded by omitting/swapping ``proximo_target``.
  Per-target ``forbid`` entries (from the ``PROXIMO_TARGETS`` registry) are surface-specific
  ADDITIONS on top of the floor, never a substitute for it: put any unconditional rule in the
  global floor, because a caller could otherwise sidestep a per-target-only rule by addressing the
  surface through a different/unnamed alias.
- **Fail-closed on an unregistered active target.** If a target is selected (``active_target()``
  is not None) but isn't present in ``load_registry()``, that is an anomaly (a stale cache, a
  registry that shrank underneath a running process) — refuse every mutation on it rather than
  silently treating it as "no envelope configured."

**Rate/budget** — a per-box, flock-guarded, sliding-window RESERVATION limiter (design spec §11.C).
A naive whole-ledger mutation count shipped here previously and was refuted by a 3-lens redteam
(concurrency races past the cap, per-instance/box contamination, no real atomicity) — it was removed
rather than patched, per the spec's "no halfass" resolution. This is the replacement, built to close
those three findings plus a name-swap evasion (lens 2 F2):

- **Box identity = ``api_base_url``** (env ``PROXIMO_API_BASE_URL``, registry ``fields["base_url"]``,
  both ``.rstrip("/")``) — never ``_svc()``, so resolution stays kind-agnostic and matches config.py's
  own normalization.
- **Per-box TIGHTEST cap.** ``_box_rate`` takes the ``min`` ``rate_max`` (and its paired window)
  configured across the env box AND every registry entry whose ``base_url`` resolves to the SAME
  box — so any operator-registered name for box X inherits X's tightest configured cap; a caller
  cannot dodge a strict cap by addressing the same physical box through a laxer/unnamed alias
  (closes lens 2 F2).
- **Reservation file, not a ledger count** (closes lens 2 F1 contamination + F3 TOCTOU). Path:
  ``<dir(audit.path)>/.proximo-rate/<sha256(base_url)[:16]>.rate`` — per-box, so no cross-target
  contamination. The whole read-prune-check-append sequence for one attempt runs under a single
  ``fcntl.flock(LOCK_EX)`` held on a stable SIDECAR ``<rate_path>.lock`` (never the data file being
  rewritten — same idiom as ``audit.py``'s ``seal_and_rotate``), so concurrent callers cannot race
  past ``rate_max``. Rewrites go to a ``tempfile.mkstemp`` in the same directory then ``os.replace()``
  — never truncate-in-place — so a crash mid-rewrite can't corrupt the slot list.
- **Corrupt/garbled data never silently drops.** An unparseable slot line counts as a USED slot
  (fail-closed, closes lens 2 F4); a garbled ``PROXIMO_RATE_MAX``/``rate_max`` collapses that box's
  cap to 0 (refuse everything on it), the same "garbled shape => fail-closed" posture the forbid
  wall already uses.
- **Multi-seam de-dup.** One logical mutation can hit ``enforce_envelope_rate`` at up to three
  seams (``ct_exec``'s own body, its ``_auto_undo`` snapshot, and ``_audited``'s execution).
  Reserving a slot at each would triple-count one attempt. ``begin_operation()`` — called once
  per fresh mutation from ``server.py::_plan()``, mirroring ``consent.py``'s
  ``set_pending_consent`` — resets a per-operation ``_rate_reserved`` ContextVar; the FIRST seam
  to reserve a slot sets it, and every later seam in the SAME operation sees it set and returns
  without reserving again. This holds regardless of where CONSENT sits relative to RATE — each of
  the 3 seams runs its own (no-op after the first) ``enforce_consent`` immediately before its own
  ``enforce_envelope_rate``, so the SAME single grant/single slot discipline applies to both.

Fail-closed invariants (consistent with the gate family):

1. Envelope unset/empty for a surface (no forbid list, no rate cap configured anywhere that matches
   this box) => inert (zero behavior change).
2. A declared-but-garbled forbid shape (not a list-of-str / comma-string) collapses to
   **forbid-all** (an internal sentinel — see ``_FORBID_ALL_SENTINEL`` — never a real action name,
   so it can't be spoofed via user config, only reached by a genuinely malformed shape). This
   applies independently to the global floor and to the active target's own forbid field — either
   garbled collapses the WHOLE effective forbid set to forbid-all, not just its own half. A garbled
   ``rate_max``/``rate_window`` on any candidate matching the active box likewise collapses that
   box's rate cap to 0 (refuse every mutation on it), independent of the forbid outcome.
3. An active target not present in the registry => forbid-all AND rate cap 0 (see above).
4. Checked before the mutating backend call at all 5 seams; reads + the dry-run ``_plan()`` are
   never gated (mirrors every other gate in the family).
5. No ``@tool`` accepts a forbid/rate_max/rate_window kwarg — out-of-band/install-only, structural
   guard.

HONEST LIMITS (rate wall, design spec §11.E — read before calling this "solved"):

- The reservation file is NOT tamper-evident, unlike the PROVE ledger. A co-located agent with
  shell/filesystem access to the reservation directory can ``rm`` or edit ``<hash>.rate`` and
  silently reset its own budget — no trace. The rate wall is a HARD cap only when the reservation
  directory sits outside the agent's write reach (the same write-boundary precondition CONSENT's
  grant dir needs — see consent.py's own HONEST LIMIT). Co-located, it is a velocity SPEED-BUMP,
  not a guarantee: CONTAIN's out-of-band kill is the real velocity backstop.
- ``base_url`` is the identity, and it is aliasable. Keying by ``base_url`` closes the agent's
  actual lever — picking among operator-REGISTERED names for the same box, since every name maps
  to an operator-fixed ``base_url`` and the tightest-cap-per-``base_url`` rule means any registered
  name for box X inherits X's tightest cap. It does NOT merge operator-registered URL VARIANTS of
  the same host (host-vs-IP, a differing port/path) — those get separate budgets, an operator
  configuration edge rather than an agent evasion; ``.rstrip("/")`` is the only normalization
  applied. Say the rate wall "narrows to URL-identity" — never that it "closes" the alias lever.
- Rate sits AFTER consent in the seam order (revised — see "Seam order" above), so a
  consent-refused attempt spends NOTHING from the box's budget; only a consent-CLEARED attempt
  counts against it. This means the rate wall no longer bounds an agent's total plan+confirm
  volley rate, only its rate of ACTUALLY-AUTHORIZED mutations — a deliberate narrowing, made so
  the wall can't be turned into a denial lever against the operator's own approved work. An
  agent that only ever plans and gets refused burns no budget and cannot be rate-limited by
  this wall at all; CONTAIN's out-of-band kill and the plan/consent themselves are what bound an
  agent that spams doomed attempts, not RATE.
- Reservation files are new local state (reuse-the-ledger was the original goal; an atomic cap
  needs atomic state, so F3 correctness wins). Stale files for decommissioned boxes linger
  harmlessly; cleanup is a fast-follow, not a correctness requirement.

Honest limits (forbid wall): per-target forbids are surface-specific ADDITIONS a caller could
sidestep by addressing the default (env-configured) box instead of a named target with its own
extra restrictions — put any rule that must be truly unconditional in the global floor, not only in
a target's registry entry. The envelope bounds forbidden ACTIONS and mutation VELOCITY on a box, not
intent — an in-envelope, in-budget action can still be wrong.
"""

from __future__ import annotations

import fcntl
import hashlib
import math
import os
import tempfile
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .backends import ProximoError
from .principal import ledger_principal
from .targets import active_target, ledger_remote, load_registry

if TYPE_CHECKING:
    from .audit import AuditLedger

FORBID_ENV = "PROXIMO_FORBID"
_RATE_MAX_ENV = "PROXIMO_RATE_MAX"
_RATE_WINDOW_ENV = "PROXIMO_RATE_WINDOW"
_RATE_WINDOW_DEFAULT = 60  # seconds — used whenever a rate_max is configured without its own window
_RESERVATION_SUBDIR = ".proximo-rate"

# Never a real action name (no tool is named this) — reached ONLY when a `forbid` field is a
# garbled shape (not a list-of-str / comma-string), or when the active target isn't registered, so
# a fail-closed forbid-all can't be spoofed or accidentally triggered by legitimate config. Kept
# human-readable so it's legible if it ever surfaces in a ledger `detail.forbid` list.
_FORBID_ALL_SENTINEL = "*forbid-all*"

# Per-operation de-dup: begin_operation() (called once per fresh mutation, from server.py::_plan(),
# mirroring consent.py's set_pending_consent) resets this to False. The first enforce_envelope seam
# in an operation that successfully reserves a rate-budget slot sets it True; later seams for the
# SAME operation (ct_exec's own body -> _auto_undo -> _audited) see it set and skip re-reserving.
_rate_reserved: ContextVar[bool] = ContextVar("proximo_rate_reserved", default=False)


def begin_operation() -> None:
    """Reset the per-operation rate-reservation flag for a FRESH mutation attempt.

    Call once per operation, before any enforce_envelope seam runs for it (server.py::_plan() is
    the single call site, executed for every plan-then-mutate tool). Without this, a leftover
    `_rate_reserved=True` from a PRIOR operation would silently let a brand-new mutation skip the
    rate check entirely — this is what keeps operations isolated from each other, the same way
    consent.py's set_pending_consent isolates CONSENT's per-operation `_consent_satisfied` flag.
    """
    _rate_reserved.set(False)


def end_operation() -> None:
    """Clear the per-operation rate-reservation flag at operation END (mutation funnel's finally).

    ``begin_operation`` resets this at the START of an operation, but only if a _plan runs — so a
    mutation seam reached WITHOUT a plan would inherit a prior operation's ``_rate_reserved=True``
    and skip reserving a slot (spending none while proceeding). Clearing at operation end makes a
    planless next mutation reserve a fresh slot instead of riding a stale reservation. Mirror of
    consent.py's ``clear_pending_consent``."""
    _rate_reserved.set(False)


@dataclass(frozen=True)
class EnvelopeConfig:
    """The resolved envelope for one call.

    ``forbid`` is lowercased/stripped/non-empty (or the ``_FORBID_ALL_SENTINEL`` singleton on a
    garbled forbid shape or an unregistered active target). ``rate_max``/``rate_window`` are the
    TIGHTEST cap configured for the active box (``None`` rate_max => rate wall inert for this box;
    ``0`` => refuse every mutation on it, fail-closed)."""

    forbid: frozenset[str]
    rate_max: int | None = None
    rate_window: int = _RATE_WINDOW_DEFAULT
    base_url: str | None = None


def _parse_forbid(value: object) -> tuple[frozenset[str], bool]:
    """Parse a raw `forbid` value (None / comma-string / list-of-str). Returns (parsed, garbled).
    Empty entries are DROPPED (an empty entry is a substring of every action = forbid-all footgun
    if it were kept) — dropping to empty is NOT the same as forbid-all; only an unparseable shape
    (not None/str/list-of-str) is garbled."""
    if value is None:
        return frozenset(), False
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, list) and all(isinstance(i, str) for i in value):
        items = value
    else:
        return frozenset(), True  # garbled shape => caller collapses to forbid-all
    return frozenset(s.strip().lower() for s in items if s.strip()), False


def _parse_int(value: object) -> tuple[int | None, bool]:
    """Parse a raw rate_max/rate_window value (None / empty-str / int-shaped str / a real int from
    TOML). Returns (parsed, garbled). None or an empty/whitespace-only string => (None, False) —
    "unset". A bool is explicitly rejected (bool is an int subclass in Python, but "true"/"false"
    is never a meaningful mutation budget). A float, or any other shape, is garbled."""
    if value is None:
        return None, False
    if isinstance(value, bool):
        return None, True
    if isinstance(value, int):
        return value, False
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None, False
        try:
            return int(s), False
        except ValueError:
            return None, True
    return None, True  # float / other shape => garbled


def _rate_candidate(max_raw: object, window_raw: object) -> tuple[int | None, int, bool]:
    """Parse one (rate_max, rate_window) candidate pair. Returns (rmax, rwin-or-default, garbled).
    A rate_window that parses to <= 0 must fail closed the same as a garbled shape: a
    non-positive window makes `cutoff = now - window >= now`, so every slot reads as
    already-expired and the cap never engages (fails OPEN). rate_max itself is untouched here —
    0 stays a valid fail-closed sentinel (_parse_int is not changed)."""
    rmax, mg = _parse_int(max_raw)
    rwin, wg = _parse_int(window_raw)
    garbled = mg or wg or (rwin is not None and rwin <= 0)
    return rmax, (rwin if rwin is not None else _RATE_WINDOW_DEFAULT), garbled


def _box_key(base_url: str) -> str:
    """Stable, non-reversible label for a box in ledger detail / the reservation filename."""
    return hashlib.sha256(base_url.encode("utf-8")).hexdigest()[:16]


def _normalize_base_url(value: object) -> str | None:
    """Shared base-url normalization: a non-empty str, stripped and trailing-slash-trimmed, or
    None for any other shape (missing/empty/non-str) — the same rule config.py's own
    api_base_url normalization applies."""
    if not isinstance(value, str) or not value:
        return None
    return value.strip().rstrip("/")


def _active_base_url() -> str | None:
    """Identity of the box THIS call is addressing — the same api_base_url config.py itself
    normalizes with .rstrip("/"). Kind-agnostic: reads only active_target()/load_registry()/env,
    never _svc() (that would import a config-building cost into every gate check). None means
    unresolvable: no active target selected and PROXIMO_API_BASE_URL is unset, or an active target
    that isn't registered / has no base_url of its own."""
    name = active_target()
    if name is not None:
        base_url = load_registry().get(name, {}).get("base_url")
    else:
        base_url = os.environ.get("PROXIMO_API_BASE_URL")
    return _normalize_base_url(base_url)


def _box_rate(base_url: str | None) -> tuple[int | None, int]:
    """The TIGHTEST (rate_max, rate_window) configured for `base_url`, scanning BOTH the env box
    (if its own base_url matches) and every PROXIMO_TARGETS registry entry whose base_url matches
    — so any name that resolves to the same physical box inherits its tightest cap (closes the
    name-swap evasion, design spec lens 2 F2). A garbled rate_max/rate_window on ANY matching
    candidate collapses the whole box to (0, default) — fail-closed, mirrors the forbid wall's
    garbled-shape handling. An unresolvable box identity (base_url=None) while a cap is clearly
    declared SOMEWHERE (env or any registry entry) is treated the same way: we cannot confirm the
    cap doesn't apply here, so refuse rather than silently ride an inert envelope. Only when NO
    rate configuration exists anywhere does an unresolvable identity mean genuinely inert (None)."""
    candidates: list[tuple[int, int]] = []
    garbled = False
    any_declared = False

    env_base_raw = os.environ.get("PROXIMO_API_BASE_URL")
    env_base = _normalize_base_url(env_base_raw)
    env_max_raw = os.environ.get(_RATE_MAX_ENV)
    env_window_raw = os.environ.get(_RATE_WINDOW_ENV)
    if env_max_raw or env_window_raw:
        any_declared = True
        if base_url is not None and env_base == base_url:
            rmax, rwin, cand_garbled = _rate_candidate(env_max_raw, env_window_raw)
            if cand_garbled:
                garbled = True
            elif rmax is not None:
                candidates.append((rmax, rwin))

    for fields in load_registry().values():
        if not isinstance(fields, dict):
            continue
        if "rate_max" not in fields and "rate_window" not in fields:
            continue
        any_declared = True
        entry_base = _normalize_base_url(fields.get("base_url"))
        if base_url is None or entry_base != base_url:
            continue
        rmax, rwin, cand_garbled = _rate_candidate(fields.get("rate_max"), fields.get("rate_window"))
        if cand_garbled:
            garbled = True
        elif rmax is not None:
            candidates.append((rmax, rwin))

    if garbled:
        return 0, _RATE_WINDOW_DEFAULT
    if base_url is None:
        return (0, _RATE_WINDOW_DEFAULT) if any_declared else (None, _RATE_WINDOW_DEFAULT)
    if not candidates:
        return None, _RATE_WINDOW_DEFAULT
    # Rank by EFFECTIVE sustained rate (rate_max/window), not raw rate_max — a shorter-window,
    # higher-count candidate (e.g. env's blanket 10/1s sanity ceiling = 864,000/day) must not
    # beat a longer-window, lower-count candidate that is actually far more restrictive (e.g. a
    # registry-declared 500/86400s = 500/day budget for the same box). window is always > 0 here
    # (a parsed-but-<=0 window is filtered into `garbled` above). Tie-break to the LARGER/tighter
    # window when the ratio is equal — this subsumes the plain rate_max-tie case too, since equal
    # rate_max with unequal windows already yields unequal ratios.
    return min(candidates, key=lambda c: (c[0] / c[1], -c[1]))


def resolve_envelope() -> EnvelopeConfig:
    """Read the envelope fresh (no caching, no process state — same discipline as every other gate
    in this family). ``PROXIMO_FORBID`` (global env) is ALWAYS read as the inescapable floor; a
    named active target's registry ``forbid`` field, if any, is UNIONED on top of it. An active
    target absent from the registry fails closed to forbid-all + rate cap 0 (see module docstring).
    The rate cap is the TIGHTEST configured for the active box (see ``_box_rate``)."""
    global_forbid, gg = _parse_forbid(os.environ.get(FORBID_ENV))

    name = active_target()
    if name is not None:
        reg = load_registry()
        if name not in reg:
            # Unregistered active target: anomaly (stale-cache exposure) => refuse everything,
            # regardless of what the global floor says.
            return EnvelopeConfig(forbid=frozenset({_FORBID_ALL_SENTINEL}),
                                   rate_max=0, rate_window=_RATE_WINDOW_DEFAULT)
        target_forbid, tg = _parse_forbid(reg[name].get("forbid"))
    else:
        target_forbid, tg = frozenset(), False

    if gg or tg:
        forbid = frozenset({_FORBID_ALL_SENTINEL})
    else:
        forbid = global_forbid | target_forbid

    base_url = _active_base_url()
    rate_max, rate_window = _box_rate(base_url)
    return EnvelopeConfig(forbid=forbid, rate_max=rate_max, rate_window=rate_window,
                           base_url=base_url)


def _forbidden(action: str, target: str, detail: dict | None, forbid: frozenset[str]) -> bool:
    """Case-insensitive composite match. The sentinel always matches. Otherwise: any forbid entry
    that is a substring of ``action``, ``target``, or ``detail["action"]`` (newline-joined so an
    entry can't false-match across a field boundary — e.g. a target ending in "..de" plus a detail
    starting with "le..." never spuriously spells "delete"). This is where the dangerous
    sub-action actually lives at several seams: ``lxc/100:stop``, ``pve/services/sshd:stop``,
    ``detail={"action": "delete"}`` for ``pmg_quarantine_action``."""
    if _FORBID_ALL_SENTINEL in forbid:
        return True
    detail_action = detail.get("action", "") if isinstance(detail, dict) else ""
    hay = "\n".join([action, target, detail_action]).lower()
    return any(entry in hay for entry in forbid)


def _rewrite_rate_file(rate_path: str, slots: list[float]) -> None:
    """Atomic rewrite: temp file in the SAME directory + os.replace() — never truncate-in-place, so
    a crash mid-write can't leave a partially-written/corrupt slot list (design spec §11.E)."""
    directory = os.path.dirname(rate_path)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".proximo-rate-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tf:
            for slot in slots:
                tf.write(f"{slot!r}\n")
        os.replace(tmp, rate_path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _rate_reserve(reservation_dir: str, base_url: str, rate_max: int, window: int) -> bool:
    """Reservation-file limiter for one box. True = allowed AND a slot was reserved.

    The whole read-prune-check-append sequence is ONE atomic critical section, held under
    fcntl.flock(LOCK_EX) on a stable SIDECAR lock file (``<rate_path>.lock`` — never the data file
    itself, which gets rewritten via temp+replace each call, so locking it would bind to an inode
    that vanishes mid-operation). flock binds to the open file DESCRIPTION, so concurrent callers —
    including sibling threads in this same process, each with their own open() of the lock file —
    genuinely serialize through this section; that is what makes the barrier concurrency test
    deterministic (design spec §11.C/§11.E, the make-or-break proof).
    """
    rate_dir = os.path.join(reservation_dir, _RESERVATION_SUBDIR)
    if os.path.islink(rate_dir):
        # A symlinked reservation directory could redirect every box's reservation writes onto an
        # arbitrary path chosen by whoever planted the link — refuse rather than write through it.
        raise OSError(f"refusing to use a symlinked reservation directory: {rate_dir!r}")
    os.makedirs(rate_dir, exist_ok=True)
    rate_path = os.path.join(rate_dir, f"{_box_key(base_url)}.rate")
    lock_path = rate_path + ".lock"

    # O_NOFOLLOW: a co-located agent that plants `<hash>.rate.lock` as a symlink must not have the
    # flock silently redirected onto (and, via O_CREAT, potentially create) an arbitrary target
    # path — that's a containment escape. Opening a symlinked lock path raises OSError (ELOOP),
    # which propagates to enforce_envelope_rate's try/except as an audited fail-closed refusal.
    with open(lock_path, "a+", encoding="utf-8",
              opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW, 0o600)) as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            now = time.time()
            cutoff = now - window
            try:
                # errors="replace": a non-UTF8 byte degrades to replacement chars rather than
                # raising UnicodeDecodeError out of this critical section — the resulting garbage
                # line still fails float() below and is handled by the corrupt-line branch
                # (self-heals on the next rewrite instead of crashing the whole reservation).
                with open(rate_path, encoding="utf-8", errors="replace") as rf:
                    raw_lines = rf.readlines()
            except FileNotFoundError:
                raw_lines = []

            kept: list[float] = []
            for line in raw_lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    slot = float(line)
                except ValueError:
                    # Corrupt/unparseable line => count it as a USED slot, timestamped now, so it
                    # never silently vanishes from the budget (fail-closed) and self-heals on the
                    # next rewrite (it's a valid float from here on).
                    kept.append(now)
                    continue
                if not math.isfinite(slot):
                    # nan/inf/-inf PARSE as floats (no ValueError), so they'd otherwise miss the
                    # corrupt-line branch above: nan/-inf read as < cutoff and silently vanish
                    # (under-count, fails open); +inf reads as >= cutoff FOREVER (retained
                    # permanently, a self-inflicted DoS). Treat exactly like an unparseable line.
                    kept.append(now)
                    continue
                if slot >= cutoff:
                    kept.append(slot)

            if len(kept) >= rate_max:
                # Persist the prune even on refusal — capped to the most-recent rate_max slots so a
                # sustained flood of corrupt/tampered lines can't grow this file without bound.
                # Keeping the NEWEST slots frees budget no sooner than the true window would.
                _rewrite_rate_file(rate_path, sorted(kept)[-rate_max:])
                return False

            kept.append(now)
            _rewrite_rate_file(rate_path, sorted(kept)[-rate_max:])
            return True
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def _resolve_envelope_audited(action: str, target: str, audit: AuditLedger,
                               detail: dict | None) -> EnvelopeConfig:
    """``resolve_envelope()``, but any exception (e.g. a transiently-malformed ``PROXIMO_TARGETS``
    file mid-write) is recorded to the PROVE ledger — outcome ``blocked:envelope_error`` — BEFORE
    raising, mirroring every other refusal path in this gate family's record-before-raise
    contract. Without this, an envelope-resolution error would leak out of
    ``enforce_envelope_forbid``/``enforce_envelope_rate`` uncaught and unaudited, even though the
    mutation is still (safely) blocked."""
    try:
        return resolve_envelope()
    except Exception as e:
        audit.record(action, target=target, mutation=True, outcome="blocked:envelope_error",
                      detail={**(detail or {}), "error": type(e).__name__},
                      principal=ledger_principal(), remote=ledger_remote())
        raise ProximoError(
            f"envelope refused: could not resolve envelope config for {action!r} on {target!r} "
            f"(fail-closed) — {type(e).__name__}"
        ) from e


def enforce_envelope_forbid(action: str, target: str, audit: AuditLedger, *,
                             detail: dict | None = None) -> None:
    """The FORBID half of the envelope check, split out so it can run BEFORE consent while the
    RATE half (``enforce_envelope_rate``) runs AFTER — see the module-level "Seam order" note.
    Cheap deny-list check: resolves the active surface's envelope and, on a match, records
    ``blocked:forbidden`` to the PROVE ledger BEFORE raising ProximoError, so the backend call
    never fires. Spends no rate budget either way.

    **Taint coupling (primary prompt-injection enforcement, opt-in — design doc
    `.scratch/taint-design-v2-2026-07-02.md` §Component 3a).** Base-envelope semantics run FIRST
    and are unchanged by any of this. Only THEN, if the session's taint marker is present
    (``taint.is_tainted`` on this ledger's directory), the pre-declared ``PROXIMO_TAINT_FORBID``
    set is checked against the SAME composite match (``_forbidden``) used for the base forbid
    wall — a garbled shape collapses to ``_FORBID_ALL_SENTINEL`` (fail-closed, exactly like
    ``resolve_envelope``'s own garble handling), and an empty/unset taint-forbid set is simply
    inert (tainted, but nothing configured to forbid). A match records a DISTINCT outcome,
    ``blocked:taint_forbidden`` — never confused with an ordinary ``blocked:forbidden`` — before
    raising. This is a hard wall with NO consent escape: it runs before ``enforce_consent`` at
    every seam, same as the base forbid check.
    """
    env = _resolve_envelope_audited(action, target, audit, detail)

    if env.forbid and _forbidden(action, target, detail, env.forbid):
        audit.record(action, target=target, mutation=True, outcome="blocked:forbidden",
                     detail={**(detail or {}), "forbid": sorted(env.forbid)},
                     principal=ledger_principal(), remote=ledger_remote())
        raise ProximoError(
            f"envelope refused: {action!r} on {target!r} is forbidden on this surface"
        )

    # Lazy import: taint.py imports envelope._parse_forbid at module load, so importing taint at
    # envelope's own module top would be circular. Deferred to call time instead.
    from .taint import is_tainted, taint_forbid_set

    # Check the env FIRST (cheap) before any filesystem stat: with PROXIMO_TAINT_FORBID unset there
    # is nothing to forbid once tainted, so a default deployment does NO is_tainted() stat at all —
    # truly inert, mirroring how the base wall above does nothing when env.forbid is empty.
    taint_forbid, garbled = taint_forbid_set()
    taint_forbid_effective = frozenset({_FORBID_ALL_SENTINEL}) if garbled else taint_forbid
    if not taint_forbid_effective:
        return  # taint-forbid not configured -> inert

    audit_path = getattr(audit, "path", None)
    if not audit_path:
        # A duck-typed AuditLedger without a real `.path` (a structural test double, never a real
        # deployment — AuditLedger always has one) can't be taint-checked: there is no filesystem
        # location to stat a marker beside. `not audit_path` (not `is None`) also catches an empty
        # `.path` (e.g. PROXIMO_AUDIT_LOG="") so os.path.dirname("") never resolves to a cwd-relative
        # marker. Mirrors enforce_envelope_rate's own early-return before touching `audit.path`.
        return
    if not is_tainted(os.path.dirname(audit_path)):
        return

    if _forbidden(action, target, detail, taint_forbid_effective):
        audit.record(action, target=target, mutation=True, outcome="blocked:taint_forbidden",
                     detail={**(detail or {}), "taint_forbid": sorted(taint_forbid_effective)},
                     principal=ledger_principal(), remote=ledger_remote())
        raise ProximoError(
            f"envelope refused: {action!r} on {target!r} is forbidden after an untrusted read "
            "on this surface"
        )


def enforce_envelope_rate(action: str, target: str, audit: AuditLedger, *,
                           detail: dict | None = None) -> None:
    """The RATE half of the envelope check — deliberately called AFTER ``enforce_consent`` at
    every mutation seam (see the module-level "Seam order" note) so a consent-refused attempt
    never spends a slot from the box's budget. Resolves the active surface's envelope fresh; an
    exhausted budget records ``blocked:rate_budget``/``blocked:rate_error`` to the PROVE ledger
    BEFORE raising ProximoError, so the backend call never fires.
    """
    env = _resolve_envelope_audited(action, target, audit, detail)

    if env.rate_max is None:
        return  # no rate cap configured for this surface -> rate wall inert

    if _rate_reserved.get():
        return  # an earlier seam in this SAME operation already reserved a slot (de-dup)

    base_url = env.base_url
    outcome = "blocked:rate_budget"
    if env.rate_max <= 0 or base_url is None:
        # rate_max<=0 is the fail-closed sentinel (garbled config / unresolvable box identity
        # while a cap is declared somewhere) — refuse without touching the reservation file.
        allowed = False
    else:
        try:
            allowed = _rate_reserve(os.path.dirname(audit.path), base_url, env.rate_max,
                                     env.rate_window)
        except Exception:
            # A reservation-file error (tampered/symlinked lock, unreadable/undecodable path, IO
            # failure) must never crash out of enforce_envelope_rate UNAUDITED — the docstring
            # promises record-before-raise for every refusal. Fail closed with a DISTINCT outcome
            # so a genuine rate-error is never confused with an ordinary over-budget refusal in
            # PROVE.
            allowed = False
            outcome = "blocked:rate_error"

    if not allowed:
        audit.record(action, target=target, mutation=True, outcome=outcome,
                     detail={**(detail or {}), "rate_max": env.rate_max,
                             "rate_window": env.rate_window, "box": _box_key(base_url or "")},
                     principal=ledger_principal(), remote=ledger_remote())
        raise ProximoError(
            f"envelope refused: {action!r} on {target!r} exceeds the rate budget for this surface"
        )
    _rate_reserved.set(True)
