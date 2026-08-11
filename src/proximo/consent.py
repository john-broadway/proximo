"""Independent CONSENT — a single-use, out-of-band, per-plan authorization gate.

Closes two zero-trust holes CONTAIN's sibling gate does not:
  * self-asserted authorization — today a mutation is gated only by ``confirm: bool``, a flag the
    AGENT sets on its own call (the subject vouching for its own request);
  * session-not-per-request trust — ``arm``/``disarm`` opens an unlimited window in which every
    ``confirm=True`` succeeds.

CONSENT is the INVERSE of CONTAIN. CONTAIN is a global DENY switch: any file at the trip path blocks
every mutation. CONSENT is ALLOW-based and per-plan: a mutation proceeds only if a correctly-named,
unexpired grant file exists for THIS EXACT plan — and consuming it is single-use. Absence blocks.

  * Out-of-band state: a directory named by ``PROXIMO_CONSENT_DIR`` that Proximo's own code NEVER
    writes into. A "grant" is a file ``<dir>/<consent_id>``; a human places it via an operator-side
    helper run from their own shell (the same trust boundary ``proximo-arm``/``proximo-disarm`` use)
    — never an MCP tool. No ``@tool()`` ever mints a grant; that is a structural invariant.
  * ``consent_id`` (``consent_id_for``) is a content hash over the DECISION-RELEVANT, STABLE fields of
    the plan the human actually read (action/target/change/risk/risk_reasons/blast_radius/affected/
    complete) — NOT the volatile ``current`` telemetry, which changes every call and would make a
    grant unmatchable within seconds. It is a correlation id, NOT a credential: the agent can compute
    the same hash from the dry-run plan it was handed. All security lives in the write-boundary on the
    grant directory (see HONEST LIMIT), not in the hash being unguessable.
  * Read FRESH every call (no caching, like ``contain_state``): a grant minted mid-session works on
    the very next call; a consumed/expired one stops working on the very next call, no restart.

Env unset => INERT (opt-in), zero behavior change for every existing deployment. FAIL-CLOSED: a set
dir that is unreadable / a garbled path / a non-directory component => REFUSE, never "assume approved
and mutate". Only an unambiguous "grant simply absent" (``FileNotFoundError``) reads as not-consented.

SINGLE CONSUME ACROSS MULTIPLE SEAMS (the load-bearing subtlety). One logical mutation can hit several
gate seams — e.g. ``ct_exec`` gates before its auto-undo snapshot, ``_auto_undo`` gates again, and
``_audited`` gates a third time. CONTAIN re-reads its trip file idempotently at each; CONSENT must NOT
consume the grant three times (the 2nd/3rd would self-race to a false refusal). So a per-operation
"satisfied" flag (a second contextvar) is set the first time a grant is consumed; downstream seams in
the same operation see it and return without touching the grant again. ``set_pending_consent`` — called
by ``_plan()`` before any mutation — resets the flag, so each fresh plan requires a fresh grant and no
"satisfied" state leaks from a prior call. Cross-call isolation rides the same per-call contextvar
context that ``active_target`` already relies on.

HONEST LIMIT (read before calling this "solved"). The ENTIRE guarantee reduces to one boundary: can
the agent's own execution context write into ``PROXIMO_CONSENT_DIR``? If the same user/filesystem that
runs the agent (an agent with a shell on the same box, running as the same user — the co-located
dogfood shape) can write a grant file there, it can self-approve and this becomes cosmetic. Unlike
``arm``/``disarm`` (whose independence comes from the outer harness refusing the agent ``!`` commands),
CONSENT has no enforcement of that boundary of its own — the deployment must provide it (a separate UID
with no grant-dir write for the agent's shell, a directory the agent cannot reach, or eventually signed
grants Proximo verifies without trusting the filesystem — the real long-term fix, out of scope here).
``config.py`` warns about this precondition, loudly, whenever ``PROXIMO_CONSENT_DIR`` is set.

CONSENT proves ONE thing: a human (whoever holds write access to the grant dir) looked at Proximo's own
rendering of this action's blast radius and approved it. It does NOT prove the request reflected the
operator's real intent (provenance — a separate control), nor bound reads/velocity, nor make the ledger
tamper-proof. ``arm`` + ``confirm`` + ``consent`` stack: disarmed => no write token; unconfirmed => a
preview; unconsented => refused here — losing any one still blocks the mutation.

CAVEAT (do not "fix" by hashing ``current``): ``blast_radius`` can embed a bucketed-but-live substring
(e.g. an uptime bucket), so a guest crossing an hour/day boundary between plan-time and confirm-time can
change its ``consent_id`` and cause a fail-closed FALSE refusal. Safe direction; the TTL is the real
valve. Hashing ``current`` to "fix" it would silently reopen the TOCTOU hole this gate exists to close.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from contextvars import ContextVar
from typing import TYPE_CHECKING, NoReturn

from .backends import ProximoError
from .principal import ledger_principal
from .taint import is_tainted, require_consent_when_tainted
from .targets import ledger_remote

if TYPE_CHECKING:
    from .audit import AuditLedger
    from .planning import Plan

CONSENT_DIR_ENV = "PROXIMO_CONSENT_DIR"
CONSENT_TTL_ENV = "PROXIMO_CONSENT_TTL_SECONDS"
_DEFAULT_TTL_SECONDS = 900  # 15 min: long enough to read a plan + type an approval, short enough that
#                             a stale grant can't be replayed hours later against a matching consent_id.

# The plan's consent_id, threaded from _plan() (the only place a Plan is in scope) to the mutation
# seams without editing ~50 tool bodies — the same shape active_target() uses. The SATISFIED flag makes
# the consume single per operation across the several seams one mutation can traverse (see docstring).
_pending_consent_id: ContextVar[str | None] = ContextVar("proximo_consent_id", default=None)
_consent_satisfied: ContextVar[bool] = ContextVar("proximo_consent_satisfied", default=False)

# consent_id is hashed over these DECISION-RELEVANT, STABLE Plan fields only. Excludes `current` (raw
# live telemetry, changes every call), `note`/`to_proceed` (static boilerplate). See the §3.2 caveat.
_STABLE_FIELDS = ("action", "target", "change", "risk", "risk_reasons",
                  "blast_radius", "affected", "complete")


def set_pending_consent(consent_id: str) -> None:
    """Record the consent_id for the mutation _plan() just built, and RESET the per-operation
    satisfied flag so this fresh plan requires a fresh grant (no 'satisfied' leaks from a prior call)."""
    _pending_consent_id.set(consent_id)
    _consent_satisfied.set(False)


def clear_pending_consent() -> None:
    """Clear the per-operation consent state at operation END (called from the mutation funnel's
    finally). The satisfied flag is reset by the NEXT plan (``set_pending_consent``), but that reset
    only fires if a _plan runs — so a mutation seam reached WITHOUT its own plan would otherwise
    inherit a prior operation's satisfied=True and skip the grant check (fail-OPEN). Clearing at
    operation end makes that impossible: after any mutation, a planless next mutation sees no plan
    and no satisfied flag, and fails closed. Also drops the stale ``consent_id`` so the refusal is
    the honest ``blocked:consent_no_plan`` rather than a phantom ``blocked:consent_required``."""
    _pending_consent_id.set(None)
    _consent_satisfied.set(False)


def consent_id_for(plan: Plan) -> str:
    """A stable content hash over the decision-relevant plan fields (see _STABLE_FIELDS / docstring).

    Deterministic and canonical (sorted keys, no whitespace) so the operator-side approve helper and
    the in-process check derive the SAME id from the SAME recorded plan. NOT a secret (§ HONEST LIMIT)."""
    stable = {k: getattr(plan, k, None) for k in _STABLE_FIELDS}
    canon = json.dumps(stable, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _ttl_seconds() -> int:
    """PROXIMO_CONSENT_TTL_SECONDS, or the default. A malformed value falls back to the default (a
    misconfigured TTL must not silently become 0 = every grant instantly expired, nor unbounded)."""
    raw = os.environ.get(CONSENT_TTL_ENV)
    if not raw:
        return _DEFAULT_TTL_SECONDS
    try:
        val = int(raw.strip())
    except (ValueError, AttributeError):
        return _DEFAULT_TTL_SECONDS
    return val if val > 0 else _DEFAULT_TTL_SECONDS


def _refuse(action: str, target: str, audit: AuditLedger, outcome: str,
            consent_id: str | None, detail: dict | None, why: str) -> NoReturn:
    """Record the blocked attempt to the tamper-evident ledger (with the consent_id so an operator can
    find/approve it) and raise — BEFORE the caller's real mutating backend call can fire."""
    audit.record(action, target=target, mutation=True, outcome=outcome,
                 detail={**(detail or {}), **({"consent_id": consent_id} if consent_id else {})},
                 principal=ledger_principal(), remote=ledger_remote())
    raise ProximoError(f"consent required: mutation {action!r} refused ({outcome}) — {why}")


def enforce_consent(action: str, target: str, audit: AuditLedger, *,
                    detail: dict | None = None) -> None:
    """The SINGLE per-plan consent check for every mutation-causing call — same signature shape as
    ``enforce_containment``. Reads the consent_id _plan() threaded through the contextvar, requires an
    out-of-band grant at ``<PROXIMO_CONSENT_DIR>/<consent_id>``, and CONSUMES it (single-use) before
    returning. Call it BEFORE the mutating backend call, at every seam enforce_containment occupies.

    Idempotent within one operation (the 'satisfied' flag): the first seam consumes the grant; later
    seams for the SAME mutation return without re-consuming, so a multi-seam op (ct_exec) is not
    self-refused. Any refusal is recorded to PROVE and raises ProximoError.

    TAINT COUPLING (Stage 4 — the in-domain residue, see .scratch/taint-design-v2-2026-07-02.md
    Component 3b): when the session is tainted (an adversarial-classified tool has returned bytes
    this session — see taint.py) AND the operator opted in via PROXIMO_TAINT_REQUIRE_CONSENT, consent
    becomes MANDATORY for this mutation even in a deployment that does not require consent globally.
    Computed once, near the top, so both the F7 fail-closed branch and (implicitly) the normal
    grant-lookup flow below see the same value for this call."""
    # Compute taint-mandatory LAZILY: only when the operator opted in via
    # PROXIMO_TAINT_REQUIRE_CONSENT do we touch audit.path / stat the taint marker. With the flag off
    # (the default) this whole coupling is inert and never reads `audit.path` — so a caller passing a
    # duck-typed ledger without a real `.path` (structural test doubles) is byte-for-byte unaffected,
    # and no is_tainted() stat is added to any existing deployment's mutation path.
    tainted_mandatory = False
    if require_consent_when_tainted():
        audit_path = getattr(audit, "path", None)
        # `if audit_path` (truthy, not `is not None`) so an empty `.path` (PROXIMO_AUDIT_LOG="") or a
        # path-less test double both skip the taint check instead of statting a cwd-relative marker.
        tainted_mandatory = bool(audit_path) and is_tainted(os.path.dirname(audit_path))

    dir_ = os.environ.get(CONSENT_DIR_ENV)
    if not dir_:  # opt-in: env unset (or empty) => inert, zero behavior change (like contain_state)
        if tainted_mandatory:
            # F7 — the fail-closed hole: tainted + PROXIMO_TAINT_REQUIRE_CONSENT set, but there is no
            # PROXIMO_CONSENT_DIR to verify a grant against. A silent no-op here would let a tainted
            # mutation through unconsented — refuse instead (record-before-raise, like every other
            # refusal path), never "assume approved and mutate".
            _refuse(action, target, audit, "blocked:taint_consent_unconfigured", None, detail,
                    "session is tainted (untrusted read) and PROXIMO_TAINT_REQUIRE_CONSENT is set, "
                    "but PROXIMO_CONSENT_DIR is not configured — cannot verify consent, fail-closed")
        return
    if _consent_satisfied.get():  # already consented THIS operation at an earlier seam — never re-consume
        return
    consent_id = _pending_consent_id.get()
    if not consent_id:
        # A mutation seam reached without _plan() populating a consent_id: no recorded plan to bind an
        # approval to => cannot verify consent => fail-closed. ("No plan, no mutation" should prevent
        # this, so it is a defensive refusal, not a normal path.)
        _refuse(action, target, audit, "blocked:consent_no_plan", None, detail,
                "no recorded plan for this mutation; consent cannot be verified (fail-closed)")

    path = os.path.join(dir_, consent_id)
    try:
        st = os.stat(path)
    except FileNotFoundError:
        # When this refusal is taint-driven, thread that into the recorded detail (outcome string
        # stays "blocked:consent_required" — same case as a non-taint global-consent deployment,
        # just with a note for DIAGNOSE that taint made this mandatory) — never change the outcome.
        no_grant_detail = {**(detail or {}), "taint_required": True} if tainted_mandatory else detail
        _refuse(action, target, audit, "blocked:consent_required", consent_id, no_grant_detail,
                f"no out-of-band grant for this exact plan — an operator approves it by placing an "
                f"empty file at {path!r} from OUTSIDE this agent (the consent_id is not a secret; "
                f"Proximo never writes it itself)")
    except (OSError, ValueError):
        # perm denied / garbled path / non-directory component in PROXIMO_CONSENT_DIR => fail-closed,
        # exactly like contain_state()'s os.stat split between clean-absent and errored.
        _refuse(action, target, audit, "blocked:consent_error", consent_id, detail,
                "consent directory unreadable or path invalid (fail-closed)")

    if (time.time() - st.st_mtime) > _ttl_seconds():
        _refuse(action, target, audit, "blocked:consent_expired", consent_id, detail,
                "grant present but older than the consent TTL — re-approve")

    # Consume atomically: the os.remove IS the authoritative "did I hold this grant" check. Its success
    # gates proceeding (not the earlier stat), making the grant single-use and race-safe with no lock —
    # only one racing caller can win the remove; the loser gets FileNotFoundError and is refused.
    try:
        os.remove(path)
    except FileNotFoundError:
        _refuse(action, target, audit, "blocked:consent_race", consent_id, detail,
                "grant consumed concurrently (single-use) — not authorized")
    except (OSError, ValueError):
        _refuse(action, target, audit, "blocked:consent_error", consent_id, detail,
                "grant present but could not be consumed (fail-closed)")

    _consent_satisfied.set(True)  # this operation is authorized; downstream seams pass without re-consume
