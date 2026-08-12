"""Proximo MCP server.

Exposes Proxmox management (REST API) and in-container exec (ssh+pct) as MCP tools.

Verified 2026-06-07 against the official `mcp` Python SDK (FastMCP): import path,
`@mcp.tool()` decorator, type-hinted params, and dict returns are current (v1.x).

Ethical spine:
- In-container exec (ct_*) is OFF by default — API-only is the safe default; enable with PROXIMO_ENABLE_EXEC.
- Every tool call is audited *with its real outcome* (errors recorded, not assumed "ok").
- Every mutating tool is confirm-gated — all of them, across every plane, not a named
  few (structurally enforced by test_server_plan.py::test_every_mutating_tool_is_confirm_gated).
- The CTID allowlist is enforced fail-closed in the exec backend.
- Secrets are never read or logged here.
"""

from __future__ import annotations

import hashlib
import inspect
import os
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from functools import cache, lru_cache
from typing import Annotated, Any

import httpx
from mcp.types import ToolAnnotations
from pydantic import Field

from . import __version__
from . import audit as audit_mod
from ._mcpcompat import MCP_MAJOR, make_server
from .audit import AuditLedger, find_rotation_archive, looks_like_head, open_ledger, read_entries
from .audit_anchor import AnchorError
from .backends import ApiBackend, ExecBackend, ProximoError, _check_vmid
from .config import ProximoConfig, load_env_file
from .consent import clear_pending_consent, consent_id_for, enforce_consent, set_pending_consent
from .contain import enforce_containment
from .envelope import (
    begin_operation,
    end_operation,
    enforce_envelope_forbid,
    enforce_envelope_rate,
)
from .lease import enforce_lease
from .pbs import (
    PbsBackend,
    PbsConfig,
)
from .pdm import (
    PdmBackend,
    PdmConfig,
)
from .planning import (
    Plan,
    command_fingerprint,
    plan_exec,
    plan_psql,
    sql_fingerprint,
    undo_snapname,
)
from .pmg import (
    PmgBackend,
    PmgConfig,
)
from .principal import ledger_principal, principal_feature_active, serving_face
from .provenance import enforce_scope
from .qemu_agent import (
    plan_agent_exec,
)
from .taint import fence_output, is_adversarial, mark_tainted, taint_tracking_on
from .targets import (
    active_target,
    ledger_remote,
    resolve_target_fields,
    target_aware,
)

BANNER = (
    "Proximo — the ethical Proxmox MCP\n"
    '  "Win the crowd and you will win your freedom."  ·  Strength and honor.\n'
)

# Per-major construction (1.x FastMCP / 2.x MCPServer subclass), advertising Proximo's OWN
# version in the `initialize` handshake — the per-major mechanics live in _mcpcompat.
mcp = make_server("proximo", __version__)


# Does the installed FastMCP.tool accept an `annotations=` kwarg? (Added to the SDK well after our
# floor of mcp>=1.2.0.) Feature-detected rather than floor-bumped: on a modern mcp every plane tool
# ships a readOnlyHint derived from its own MUTATION/READ-ONLY prose; on an older mcp the hint is
# simply absent and the prose still carries the same information — graceful, never a crash.
_MCP_TOOL_SUPPORTS_ANNOTATIONS = "annotations" in inspect.signature(mcp.tool).parameters


def _annotations_from_doc(doc: str | None) -> ToolAnnotations | None:
    """Derive MCP tool annotations from the docstring's leading marker. Clients (Claude Code among
    them) use readOnlyHint for permission-prompt policy. Read-only tools mark readOnlyHint=True;
    mutating tools mark readOnlyHint=False (destructiveHint then defaults per the MCP spec). A
    docstring with neither marker (a handful) gets no annotation rather than a guessed one."""
    if not doc:
        return None
    first = doc.lstrip().split("\n", 1)[0].strip()
    if first.startswith("READ-ONLY"):
        return ToolAnnotations(readOnlyHint=True)
    if first.startswith("MUTATION"):
        return ToolAnnotations(readOnlyHint=False)
    return None


def tool(*d_args: Any, **d_kwargs: Any):
    """Target-aware tool decorator: like FastMCP's, but the tool also advertises
    `proximo_target` and routes the call to that registered box (via the active-target
    contextvar). Apply to every plane tool. Instance-level tools that act on THIS Proximo
    (e.g. audit_verify) intentionally keep the plain FastMCP decorator — they have no
    remote to target.

    Also derives an MCP readOnlyHint from the tool's own MUTATION/READ-ONLY marker (see
    _annotations_from_doc), unless the caller passed `annotations=` explicitly. Deferred into
    `deco` because the marker lives in fn.__doc__, which isn't in scope until fn arrives.
    """
    def deco(fn):
        kwargs = dict(d_kwargs)
        if (_MCP_TOOL_SUPPORTS_ANNOTATIONS and "annotations" not in kwargs
                and (ann := _annotations_from_doc(fn.__doc__)) is not None):
            kwargs["annotations"] = ann
        return mcp.tool(*d_args, **kwargs)(target_aware(fn))

    return deco


def _resolve_pve_config(target_name: str | None) -> ProximoConfig:
    """The active PVE config: None => env box (unchanged); a name => that registry remote."""
    if target_name is None:
        return ProximoConfig.from_env()
    return ProximoConfig.from_target(resolve_target_fields(target_name, "pve"))


@cache
def _pve_backends(target_name: str | None) -> tuple[ProximoConfig, ApiBackend, ExecBackend]:
    """Build + cache the PVE config and backends per target (registry is small/bounded)."""
    cfg = _resolve_pve_config(target_name)
    return cfg, ApiBackend(cfg), ExecBackend(cfg)


@lru_cache(maxsize=1)
def _instance_ledger() -> AuditLedger:
    """The PROVE ledger is ONE chain for this Proximo instance — built from the env audit_* config,
    never per-target, so every target's ops record to the same tamper-evident chain. Uses
    from_env_ledger() (audit fields only) so a pure-targets deployment stands the ledger up WITHOUT
    the single-target PVE API triple — otherwise `proximo doctor --target X` dies on a missing
    PROXIMO_API_BASE_URL the ledger never needed."""
    return open_ledger(ProximoConfig.from_env_ledger())


def _svc() -> tuple[ProximoConfig, ApiBackend, ExecBackend, AuditLedger]:
    """Config + backends for the ACTIVE pve target (contextvar; None => env), plus the one
    instance ledger. Backends are cached per target; the ledger is the single instance chain.

    STRICT by design: a pve_* tool body calls this and uses the backend, so a non-pve active
    target (e.g. someone aimed a pve_* tool at a pbs target) RAISES here (kind safety) rather
    than silently hitting the env box. Ledger-only callers use _ledger(), which tolerates that.
    """
    cfg, api, exec_backend = _pve_backends(active_target())
    return cfg, api, exec_backend, _instance_ledger()


def _ledger() -> AuditLedger:
    """The instance PROVE ledger (one chain), plane-independent.

    Reads _svc()[3] so the tests' _svc mock still injects a test ledger. Tolerates a non-pve
    active target (a pbs_*/pmg_*/pdm_* tool's ledger call, where _svc's pve resolution raises)
    by falling back to the instance ledger directly. This is the seam the ledger helpers use.

    The broad RuntimeError catch is intentional: a non-PVE tool's ledger acquisition must not
    fail because the (unrelated) env PVE backend is misconfigured (e.g. verify_tls off w/o a CA)
    OR entirely absent — from_env() raises a plain RuntimeError (not ProximoError) on missing
    PVE env, and a PBS-only box serving the memory/wiki utility surfaces still needs its ledger.
    RuntimeError covers ProximoError (a subclass), so both shapes fall back. A genuine PVE
    problem still surfaces loudly when a pve_* tool runs, and at config-load warning time — it
    is not silently lost, only kept out of an unrelated plane's path."""
    try:
        return _svc()[3]
    except RuntimeError:
        return _instance_ledger()


def _svc_cache_clear() -> None:
    """Clear every per-target backend cache (all four planes) and the instance-ledger cache.
    Preserves the `_svc.cache_clear()` API used by the tests; one call = a full reset."""
    _pve_backends.cache_clear()
    _pbs_backends.cache_clear()
    _pmg_backends.cache_clear()
    _pdm_backends.cache_clear()
    _instance_ledger.cache_clear()


_svc.cache_clear = _svc_cache_clear  # type: ignore[attr-defined]  # preserve existing test API


def _resolve_pbs_config(target_name: str | None) -> PbsConfig:
    if target_name is None:
        return PbsConfig.from_env()
    return PbsConfig.from_target(resolve_target_fields(target_name, "pbs"))


@cache
def _pbs_backends(target_name: str | None) -> tuple[PbsConfig, PbsBackend]:
    cfg = _resolve_pbs_config(target_name)
    return cfg, PbsBackend(cfg)


def _pbs() -> tuple[PbsConfig, PbsBackend]:
    """Lazily build the PBS backend — only when a pbs_* tool is called.

    Separate service from the PVE host: needs PROXIMO_PBS_* env (fails loud if unset).
    PBS ops still record to the SAME tamper-evident ledger via _audited/_plan (_svc's
    AuditLedger) so PROVE remains one coherent chain across PVE and PBS actions.
    """
    return _pbs_backends(active_target())


_pbs.cache_clear = _pbs_backends.cache_clear  # type: ignore[attr-defined]


def _resolve_pmg_config(target_name: str | None) -> PmgConfig:
    if target_name is None:
        return PmgConfig.from_env()
    return PmgConfig.from_target(resolve_target_fields(target_name, "pmg"))


@cache
def _pmg_backends(target_name: str | None) -> tuple[PmgConfig, PmgBackend]:
    cfg = _resolve_pmg_config(target_name)
    return cfg, PmgBackend(cfg)


def _pmg() -> tuple[PmgConfig, PmgBackend]:
    """Lazily build the PMG backend — only when a pmg_* tool is called.

    Separate service from the PVE host: needs PROXIMO_PMG_* env (fails loud if unset).
    PMG ops still record to the SAME tamper-evident ledger via _audited/_plan (_svc's
    AuditLedger) so PROVE remains one coherent chain across PVE, PBS, and PMG actions.
    """
    return _pmg_backends(active_target())


_pmg.cache_clear = _pmg_backends.cache_clear  # type: ignore[attr-defined]


def _resolve_pdm_config(target_name: str | None) -> PdmConfig:
    if target_name is None:
        return PdmConfig.from_env()
    return PdmConfig.from_target(resolve_target_fields(target_name, "pdm"))


@cache
def _pdm_backends(target_name: str | None) -> tuple[PdmConfig, PdmBackend]:
    cfg = _resolve_pdm_config(target_name)
    return cfg, PdmBackend(cfg)


def _pdm() -> tuple[PdmConfig, PdmBackend]:
    """Lazily build the PDM backend — only when a pdm_* tool is called.

    Separate service from the PVE host: needs PROXIMO_PDM_* env (fails loud if unset).
    PDM ops still record to the SAME tamper-evident ledger via _audited (_svc's
    AuditLedger) so PROVE remains one coherent chain across PVE, PBS, PMG, and PDM actions.
    """
    return _pdm_backends(active_target())


_pdm.cache_clear = _pdm_backends.cache_clear  # type: ignore[attr-defined]


def _untrusted_detail(action: str, detail: dict | None) -> dict | None:
    """Stamp untrusted provenance onto the ledger detail for an adversarial-classified tool
    (`taint.ADVERSARIAL_TOOLS`) — merged OVER the caller-supplied detail so a same-named key can
    never silently shadow it. Gated on `taint_tracking_on()`, same condition as the marker write:
    taint.py's own fail-closed invariant #1 is "all taint env unset => inert, zero behavior
    change," so with no PROXIMO_TAINT_* env set the ledger detail shape for every tool — adversarial
    or not — must stay byte-for-byte what it was before this module existed. Non-adversarial
    actions, or adversarial ones while tracking is off, pass `detail` through unchanged."""
    if not (is_adversarial(action) and taint_tracking_on()):
        return detail
    return {**(detail or {}), "untrusted": True, "content_trust": "adversarial"}


def _with_intent(detail: dict | None, intent: str | None) -> dict | None:
    """Spread `intent` into a COPY of detail at call time. Reads (intent None) pass the caller's
    object through untouched, so non-mutation ledger entries stay byte-identical to before."""
    if intent is None:
        return detail
    return {**(detail or {}), "intent": intent}


def intent_id(action: str, target: str) -> str:
    """Stable id for one OPERATION, derived from what it does and what it does it to.

    DERIVED, not caller-supplied, and that is the design. A `proximo_intent` tool parameter would
    ride ~900 schemas — the same multiplication that cost 84k tokens of repeated prose and was
    just removed. Derivation costs zero schema bytes AND needs no cooperation: a client retrying
    an operation gets the same id whether or not it knows intents exist.

    (action, target) is the right key because Proxmox's own UPID identifies an ATTEMPT — a retried
    migration is a fresh UPID with no link to its predecessor. This identifies the operation across
    attempts. Two deliberate identical actions on the same target do collapse to one intent; that
    is correct for "what happened to this operation" and is why the ledger keeps every attempt's
    own entry pair rather than collapsing them.

    Truncated to 12 hex chars: it lands in every mutation's detail, and a full digest is noise in
    a forensic read. Collision across a single box's action+target space is not a security
    boundary — nothing authorizes on this value, it only groups entries for a human or a reader.
    """
    return hashlib.sha256(f"{action}\x00{target}".encode()).hexdigest()[:12]


# Verdict 1.4: a raw httpx/socket connection error ("[Errno -2] Name or service not known")
# must not leak through a tool call the way `proximo doctor`'s own reachability check already
# refuses to leak it (doctor.py's `flags` entry names the env vars instead). Keyed by action
# prefix so a pbs_*/pmg_*/pdm_* tool names ITS OWN plane's env vars rather than every plane
# parroting PVE's — all four backends (ApiBackend/PbsBackend/PmgBackend/PdmBackend) build an
# httpx.Client the same way, so this one hint table covers all of them from the one shared seam.
_UNREACHABLE_ENV_HINT: dict[str, str] = {
    "pve_": "PROXIMO_API_BASE_URL, the token file at PROXIMO_TOKEN_PATH, and TLS/CA "
            "(PROXIMO_CA_BUNDLE / PROXIMO_VERIFY_TLS)",
    "pbs_": "PROXIMO_PBS_BASE_URL, the token file at PROXIMO_PBS_TOKEN_PATH, and TLS/CA "
            "(PROXIMO_PBS_CA_BUNDLE / PROXIMO_PBS_VERIFY_TLS)",
    "pmg_": "PROXIMO_PMG_BASE_URL, the password file at PROXIMO_PMG_PASSWORD_PATH, and TLS/CA "
            "(PROXIMO_PMG_CA_BUNDLE / PROXIMO_PMG_VERIFY_TLS)",
    "pdm_": "PROXIMO_PDM_BASE_URL, the token file at PROXIMO_PDM_TOKEN_PATH, and TLS/CA "
            "(PROXIMO_PDM_CA_BUNDLE / PROXIMO_PDM_VERIFY_TLS)",
}


def _unreachable_hint(action: str) -> str:
    for prefix, hint in _UNREACHABLE_ENV_HINT.items():
        if action.startswith(prefix):
            return hint
    return _UNREACHABLE_ENV_HINT["pve_"]  # ct_*/other non-plane-prefixed actions: PVE is the host


def _end_mutation_gates() -> None:
    """Clear the per-operation CONSENT/ENVELOPE de-dup markers at the END of a mutation operation.

    ``set_pending_consent``/``begin_operation`` (in _plan) reset these at operation START — but only
    if a plan runs. A future or unusual mutation seam reached WITHOUT its own _plan would otherwise
    inherit a prior operation's satisfied/reserved marker and skip the grant consume / rate reserve
    (fail-OPEN). Clearing at operation end makes a planless next mutation fail closed instead. This
    runs at operation END, deliberately NOT as a mid-seam reset: the exec-family tools consume their
    grant at an earlier seam and reach _audited LAST, so a reset here would try to re-consume an
    already-spent grant and self-refuse. See clear_pending_consent / end_operation."""
    clear_pending_consent()
    end_operation()


def _audited(action: str, target: str, fn: Callable[[], Any], *,
             mutation: bool = False, outcome: str | Callable[[Any], str] = "ok",
             detail: dict | None = None) -> Any:
    """Public mutation/read funnel. Delegates to _audited_run, then ALWAYS clears the per-operation
    CONSENT/ENVELOPE de-dup markers when a mutation ends (A10) — including when a gate refuses after
    an earlier gate already consumed (e.g. rate-refused after consent-consumed), so no marker leaks
    to a later planless mutation. Reads (mutation=False) touch no markers and clear nothing."""
    try:
        return _audited_run(action, target, fn, mutation=mutation, outcome=outcome, detail=detail)
    finally:
        if mutation:
            _end_mutation_gates()


def _audited_run(action: str, target: str, fn: Callable[[], Any], *,
                 mutation: bool = False, outcome: str | Callable[[Any], str] = "ok",
                 detail: dict | None = None) -> Any:
    """Run fn, then audit the REAL outcome. On exception, record the error and re-raise.

    `outcome` defaults to "ok" (synchronous completion). Async ops that only *start* a task pass
    outcome="submitted" so the ledger never claims an in-flight task is done.

    `outcome` may also be a callable `(result) -> str`, resolved AFTER fn() succeeds — for the
    rare mutation whose sync-vs-async nature is only knowable from its own return value (e.g. a
    delete that returns a task UPID on some storage backends but None, already-finished, on
    others). The callable sees only the successful result: on failure the plain "error" outcome
    is recorded exactly as for a string outcome, and the callable is never invoked (there is no
    result to resolve from). If the resolver itself misbehaves AFTER fn() succeeded (raises, or
    returns a non-str), the executed mutation still gets a ledger entry — outcome
    "error:outcome_resolution_failed" — before the failure propagates; a real mutation is never
    trace-free. A plain string outcome behaves byte-for-byte as before.

    For mutation calls (mutation=True) the return is a SYMMETRIC envelope:
        {"status": <outcome>, "result": <raw fn() return>}
    where ``status`` equals the ``outcome`` recorded to the ledger — so a caller can uniformly
    read ``resp["status"]`` and it is always honest (never "ok" for an async/submitted op).

    Read calls (mutation=False) pass the raw fn() return through unchanged — no envelope.
    """
    audit = _ledger()
    # Containment gate (mutations only): an out-of-band trip (PROXIMO_CONTAIN_TRIP_PATH) refuses
    # every mutation, fail-closed, and records the blocked attempt to the same tamper-evident chain.
    # Checked BEFORE fn() so the mutation never fires; reads and the dry-run _plan() path are not
    # gated. There is no tool to clear the trip — re-arm is out-of-band, exactly like arm/disarm.
    # This is the SAME primitive (enforce_containment) that manual-audit-path tools call directly
    # (pve_agent_exec; ct_exec/ct_psql before their auto-undo snapshot) — one source of truth.
    #
    # Gate order — RATE moved to AFTER consent (envelope.py "Seam order" note): FORBID is a cheap
    # deny-list check with no budget cost, so it stays an early hard wall before consent; RATE is
    # the only gate that SPENDS shared budget, so it waits until consent has cleared. This closes
    # a real hole: an agent that repeatedly plans+confirms actions CONSENT refuses would otherwise
    # burn the whole box's rate budget on doomed attempts, denying the operator's own approved
    # mutations for the rest of the window. Same order at all 5 mutation seams.
    if mutation:
        enforce_containment(action, target, audit, detail=detail)
        enforce_scope(action, target, audit, detail=detail)
        enforce_lease(action, target, audit, detail=detail)
        enforce_envelope_forbid(action, target, audit, detail=detail)
        enforce_consent(action, target, audit, detail=detail)
        enforce_envelope_rate(action, target, audit, detail=detail)
    # TAINT (Component 2, taint.py): adversarial-classified tools carry guest/external-authored
    # bytes back to the calling agent. Set the sticky marker BEFORE fn() runs — so a call that
    # RAISES still taints (an error body can carry attacker-shaped content too), and so the
    # marker is in place before the ledger write below. A marker-WRITE failure must never crash
    # the tool call itself: is_tainted() already fails closed (any non-FileNotFound OSError/
    # ValueError -> tainted) on a broken/inaccessible marker dir, so swallowing here doesn't
    # weaken the invariant — it just keeps a filesystem hiccup from taking down an unrelated tool
    # call. Inert (no-op) unless taint_tracking_on() — default surface unchanged.
    if is_adversarial(action) and taint_tracking_on():
        try:
            mark_tainted(os.path.dirname(audit.path), action)
        except Exception as e:  # noqa: BLE001 — any marker-write failure must fail CLOSED (below)
            # FAIL-CLOSED: a taint-tracking deployment that cannot WRITE the marker must not run fn()
            # and hand back adversarial output untracked. A co-located attacker can force this branch
            # by planting a symlink at `.proximo-taint`/`.lock` (mark_tainted refuses symlinks with
            # OSError); a transient FS error would otherwise silently un-taint the session, because
            # is_tainted() then sees no marker (FileNotFoundError -> clean) and later mutations run
            # ungated. Record and refuse rather than serve untracked bytes. (The earlier "swallow —
            # is_tainted fails closed anyway" reasoning was wrong: it only holds when the marker DIR
            # is broken in a way is_tainted also trips, not when the write simply never lands.)
            # No intent here, deliberately: this refuses BEFORE fn() runs, so there is no
            # execution interval to open or close. Stamping an intent on a refusal would make
            # audit.in_flight() reason about an operation that never started.
            audit.record(action, target=target, mutation=mutation, outcome="blocked:taint_mark_failed",
                         detail=_untrusted_detail(action, {**(detail or {}), "error": type(e).__name__}),
                         principal=ledger_principal(), remote=ledger_remote())
            raise ProximoError(
                f"taint tracking is enabled but the taint marker could not be written for {action!r} "
                "— refusing to return untrusted output untracked (fail-closed)"
            ) from e
    # L16 (CLOSED — was deferred as "a deliberate design change, not a one-liner"): the window
    # between fn() firing and the outcome record below. On process death (SIGKILL/OOM/power loss)
    # in that window the mutation RAN and the ledger said nothing — PROVE could not answer "what
    # was executing when we died," which is the first question anyone asks after a crash on a
    # hypervisor. fsync only ever covered in-process crashes.
    #
    # Now: mutations pre-record an `executing` entry carrying a derived intent id, and the terminal
    # entry carries the same id. An `executing` with no partner is a stranded operation
    # (audit.in_flight). The interval lives in the SAME hash-chained log as everything else, so the
    # crash record is tamper-evident — which a side-car state file or job database could not be.
    #
    # Mutations only. A read that dies changed nothing, so pre-recording reads would double ledger
    # volume to answer a question nobody asks.
    #
    # `detail` is NOT rebound here. Several tools mutate the dict they passed in, DURING fn(), to
    # record values only knowable from the call (`raw_result`, a resolved `iface_type`), and the
    # terminal record below reads that same live object. Snapshotting it here froze those writes
    # out of the ledger — a real regression the confirm-sweep tests caught. Intent is spread in at
    # each record site instead, so every copy is taken after fn() has had its say.
    intent = intent_id(action, target) if mutation else None
    if intent is not None:
        # principal= matters MOST here: if fn() never returns (OOM/SIGKILL/host reboot) this
        # stranded entry is the ONLY record the operation will ever have — it is what
        # audit.in_flight() surfaces — so dropping who-asked loses attribution exactly for the
        # mutation nobody got to see finish.
        audit.record(action, target=target, mutation=True, outcome=audit_mod.EXECUTING,
                     detail=_untrusted_detail(action, {**(detail or {}), "intent": intent}),
                     principal=ledger_principal(), remote=ledger_remote())
    try:
        result = fn()
    except Exception as e:
        # A subprocess timeout is NOT a clean failure: exec runs `ssh <host> pct exec ...`, and
        # killing the local ssh on timeout can ORPHAN the remote command — so the in-container
        # mutation may have partly or fully run. Recording a plain "error" would tell a forensic
        # reader it did not happen. Record "error:timeout" (kept in the "error:" subtype family so
        # error-filters still catch it) so PROVE stays honest about "ran, outcome unknown".
        timed_out = isinstance(e, subprocess.TimeoutExpired)
        audit.record(action, target=target, mutation=mutation,
                     outcome="error:timeout" if timed_out else "error",
                     detail=_untrusted_detail(action, {**(_with_intent(detail, intent) or {}),
                                                       "error": type(e).__name__}),
                     principal=ledger_principal(), remote=ledger_remote())
        if timed_out:
            secs = getattr(e, "timeout", None)
            raise ProximoError(
                f"{action}: the in-container command exceeded its "
                f"{f'{int(secs)}s ' if secs else ''}timeout and was killed locally; the remote "
                "command MAY still be running in the container. Recorded as 'error:timeout' "
                "(ran, outcome unknown) — verify guest state before assuming it failed or retrying."
            ) from e
        if isinstance(e, httpx.TransportError):
            # Same class of failure `doctor` already degrades gracefully (verdict 1.4): a
            # connection-level httpx failure (DNS/refused/timeout/TLS) must not hand the caller
            # a raw OS errno string with no pointer to what to check. The ledger entry above still
            # carries the real exception type name — only what's RAISED to the caller changes.
            raise ProximoError(
                f"{action}: cannot reach / authenticate to the Proxmox API — check "
                f"{_unreachable_hint(action)}."
            ) from e
        if isinstance(e, httpx.HTTPStatusError):
            # str(HTTPStatusError) embeds the full request URL — the operator's internal Proxmox
            # host:port and API path — which FastMCP would hand back to the calling model in the
            # ToolError text. Scrub it: raise only the action and the HTTP status/reason, matching
            # the ledger, which already records only type(e).__name__.
            resp = e.response
            raise ProximoError(
                f"{action}: Proxmox API returned HTTP {resp.status_code} {resp.reason_phrase}."
            ) from e
        raise
    if callable(outcome):
        # fn() has ALREADY RUN — the mutation is real. A resolver bug (raise, or a non-str
        # return that would corrupt the ledger outcome / envelope status) must never leave an
        # executed mutation trace-free: record the resolution failure to the same tamper-evident
        # chain FIRST, then propagate — mirroring the taint-marker-failure pattern above.
        try:
            resolved_outcome = outcome(result)
            if not isinstance(resolved_outcome, str):
                raise TypeError(
                    f"outcome resolver for {action!r} returned "
                    f"{type(resolved_outcome).__name__}, expected str"
                )
        except Exception as e:
            # Carries the intent: fn() ALREADY RAN, so this is the terminal entry closing the
            # interval the `executing` record opened. Omitting it here would leave a real,
            # executed mutation looking permanently in-flight to audit.in_flight().
            audit.record(action, target=target, mutation=mutation,
                         outcome="error:outcome_resolution_failed",
                         detail=_untrusted_detail(action, {**(_with_intent(detail, intent) or {}),
                                                           "error": type(e).__name__}),
                         principal=ledger_principal(), remote=ledger_remote())
            raise
    else:
        resolved_outcome = outcome
    audit.record(action, target=target, mutation=mutation, outcome=resolved_outcome,
                 detail=_untrusted_detail(action, _with_intent(detail, intent)),
                 principal=ledger_principal(), remote=ledger_remote())
    if mutation:
        return {"status": resolved_outcome, "result": fence_output(action, result)}
    return fence_output(action, result)


def _record_plan(plan: Plan) -> None:
    """Write the previewed plan (incl. the live state it was based on) to the tamper-evident ledger,
    with outcome="planned". This is the PLAN->PROVE weld: a verified chain shows the exact preview."""
    audit = _ledger()
    audit.record(
        plan.action, target=plan.target, mutation=True, outcome="planned",
        detail={"change": plan.change, "risk": plan.risk, "risk_reasons": plan.risk_reasons,
                "blast_radius": plan.blast_radius, "current": plan.current,
                "affected": plan.affected, "complete": plan.complete},
        principal=ledger_principal(), remote=ledger_remote())


def _plan(action: str, target: str, build: Callable[[], Plan]) -> Plan:
    """Build a plan and record it — MANDATORY before any mutation (no plan, no mutation).

    Called on BOTH paths: the dry-run (confirm=False) returns it; the execute path (confirm=True)
    runs it first so every mutation is preceded by a recorded "planned" entry — a one-shot confirm
    cannot bypass the preview. If building the plan fails (e.g. plan_power's live read raises),
    audit the failed probe and re-raise; never mutate without a recorded plan.
    """
    audit = _ledger()
    try:
        plan = build()
    except Exception as e:
        audit.record(action, target=target, mutation=True, outcome="error",
                     detail={"error": type(e).__name__, "phase": "planning"},
                     principal=ledger_principal(), remote=ledger_remote())
        raise
    # The server tool name + target are AUTHORITATIVE for the ledger: stamp them onto the plan so the
    # "planned" entry pairs with the later "submitted"/"ok" entry under ONE action AND ONE target
    # (PROVE coherence) — a plan_* helper's internal label can never drift the audit trail (and shared
    # helpers like plan_create, used by both pve_create_container and pve_create_vm, record under the
    # right tool each time). 2026-07-10 audit L15: the node-lifecycle plane's factory target differed
    # from the wrapper's, so the planned and executed ledger entries carried mismatched targets.
    plan.action = action
    plan.target = target
    _record_plan(plan)
    # CONSENT: thread this plan's content id to the mutation seams and reset the per-operation
    # satisfied flag, so enforce_consent can require a per-plan out-of-band human grant. No-op
    # (inert) unless PROXIMO_CONSENT_DIR is set — zero behavior change for existing deployments.
    set_pending_consent(consent_id_for(plan))
    # RATE wall (envelope.py): reset the per-operation reservation flag for this FRESH mutation, so
    # a multi-seam op (ct_exec: its own body, _auto_undo, _audited) reserves exactly ONE rate-budget
    # slot rather than one per seam. Mirrors set_pending_consent's per-operation reset immediately
    # above.
    begin_operation()
    return plan


def run_governed(name: str, target: str, *, plan: Callable[[], Plan], execute: Callable[[], Any],
                 confirm: bool, outcome: str | Callable[[Any], str] = "ok",
                 detail: dict | None = None, surface: dict | None = None) -> Any:
    """The one governed-mutation ritual: recorded PLAN -> dry-run return, or audited execute.

    Byte-compatible with the hand-written shape it replaces at ~480 wrapper sites (A11 slice 2):

        plan = _plan(name, target, plan)
        if not confirm:
            return {"status": "plan", **plan.as_dict()}
        return _audited(name, target, execute, mutation=True, outcome=outcome,
                        detail={"confirmed": True})

    `surface` carries the rare per-tool extras (e.g. a generated-password notice) that the
    hand-written sites spread onto BOTH the plan return and the ledger detail; `detail` carries
    execute-side-only extras. "confirmed": True is stamped last, unconditionally — a converted
    site cannot forget it, which is this function's reason to exist. Two precision notes from
    the migration's adversarial pass: a `surface` key named "status" would clobber the dry-run
    marker (same exposure the hand-written spread had — pass only redaction-shaped extras), and
    "byte-compatible" means behavior + the PROVE hash chain (which canonicalizes with
    sort_keys), not on-disk ledger-line key order, which the migration may reorder. Sites with logic BETWEEN
    the gate and the execute (the 3 exec tools' manual audit paths, pdm's fail-closed auto-undo
    veto) stay hand-written by design; this covers the ritual, not the exceptions.
    """
    built = _plan(name, target, plan)
    if not confirm:
        return {"status": "plan", **built.as_dict(), **(surface or {})}
    return _audited(name, target, execute, mutation=True, outcome=outcome,
                    detail={**(surface or {}), **(detail or {}), "confirmed": True})


def _wait_task(api: ApiBackend, upid: str, node: str | None = None,
               timeout: int = 120, interval: int = 2) -> dict:
    """Poll a Proxmox task to completion. Snapshot ops are async; the auto-undo path must wait for
    the snapshot to actually finish before mutating. Raises if the task fails or times out."""
    deadline = time.monotonic() + timeout
    while True:
        st = api.task_status(upid, node)
        if st.get("status") == "stopped":
            # Strict: only an explicit "OK" passes. A stopped task that reports no exitstatus is
            # treated as failure (fail-closed), not silently assumed successful.
            exit_ = st.get("exitstatus")
            if exit_ != "OK":
                raise ProximoError(f"task {upid} did not finish OK: {exit_!r}")
            return st
        if time.monotonic() >= deadline:
            raise ProximoError(f"task {upid} timed out after {timeout}s")
        time.sleep(interval)


def _auto_undo(action: str, target: str, api: ApiBackend, vmid: str,
               detail: dict, kind: str = "lxc", node: str | None = None) -> dict:
    """Take a labeled undo snapshot and WAIT for it. On success returns the undo-point dict; on
    failure returns an {"status": "blocked:undo_unavailable"} dict (and audits it) — the caller MUST NOT
    mutate when unavailable (fail-closed: no net, no risky act)."""
    audit = _ledger()
    # Defense-in-depth: ct_exec/ct_psql already gate before calling _auto_undo, so this is a no-op
    # on those paths — but api.snapshot_create() is a REAL mutation, so any future caller that
    # forgets its own gate is still covered here.
    enforce_containment(action, target, audit, detail=detail)
    enforce_scope(action, target, audit, detail=detail)
    enforce_lease(action, target, audit, detail=detail)
    enforce_envelope_forbid(action, target, audit, detail=detail)
    enforce_consent(action, target, audit, detail=detail)
    enforce_envelope_rate(action, target, audit, detail=detail)
    snapname = undo_snapname()
    try:
        upid = api.snapshot_create(vmid, snapname, kind=kind, node=node,
                                   description="proximo auto-undo before mutation")
        _wait_task(api, upid, node=node)
    except Exception as e:
        audit.record(action, target=target, mutation=True, outcome="blocked:undo_unavailable",
                     detail={**detail, "error": type(e).__name__},
                     principal=ledger_principal(), remote=ledger_remote())
        return {
            "status": "blocked:undo_unavailable",
            "message": ("Requested an undo snapshot but it could not be created/completed (the "
                        "container's storage may not support snapshots). Command NOT run "
                        "(fail-closed). Re-run without snapshot=True to proceed unprotected."),
            "error": type(e).__name__,
        }
    audit.record(action, target=target, mutation=True, outcome="undo_point",
                 detail={"snapshot": snapname, "task": upid},
                 principal=ledger_principal(), remote=ledger_remote())
    return {"snapshot": snapname, "task": upid,
            "revert": f"pve_rollback vmid={vmid} snapname={snapname}",
            "note": ("undo points are NOT auto-pruned — they accumulate and consume storage; "
                     "delete with pve_snapshot_delete when no longer needed.")}


def _blocked(action: str, target: str, outcome: str, message: str, detail: dict | None = None,
            *, mutation: bool = True) -> dict:
    """Shared body for the four 'refuse + audit' helpers below."""
    audit = _ledger()
    audit.record(action, target=target, mutation=mutation, outcome=outcome,
                 detail=detail, principal=ledger_principal(), remote=ledger_remote())
    return {"status": outcome, "message": message}


def _blocked_allowlist(action: str, target: str, detail: dict | None = None,
                       *, mutation: bool = True) -> dict:
    """Refuse + audit a container op whose CTID isn't on the allowlist (fail-closed), as a clean dict
    — checked at the server layer BEFORE any snapshot/exec, so a forbidden CTID never gets touched.
    `mutation` must reflect the GATED tool's true class so blocked reads don't ledger as mutations."""
    return _blocked(action, target, "blocked:allowlist",
                    f"CTID {target} is not in PROXIMO_CT_ALLOWLIST (fail-closed) — add it there to permit.",
                    detail, mutation=mutation)


def _exec_disabled(action: str, target: str, detail: dict | None = None,
                   *, mutation: bool = True) -> dict:
    """In-container exec is off by default (safe). Refuse + audit; explain how to opt in.
    `mutation` must reflect the GATED tool's true class so blocked reads don't ledger as mutations."""
    return _blocked(action, target, "blocked:exec_disabled",
                    ("In-container exec is disabled (safe default: API-only). It grants near-root on the "
                     "PVE host; enable deliberately with PROXIMO_ENABLE_EXEC=1 and set PROXIMO_CT_ALLOWLIST."),
                    detail, mutation=mutation)


def _agent_disabled(action: str, target: str, detail: dict | None = None,
                    *, mutation: bool = True) -> dict:
    """qemu-agent ops are off by default. Refuse + audit; explain how to opt in.
    `mutation` must reflect the GATED tool's true class so blocked reads don't ledger as mutations."""
    return _blocked(action, target, "blocked:agent_disabled",
                    ("qemu-agent ops are disabled (safe default: API-only). "
                     "Enable with PROXIMO_ENABLE_AGENT=1 and set PROXIMO_AGENT_ALLOWLIST."),
                    detail, mutation=mutation)


def _blocked_agent_allowlist(action: str, target: str, detail: dict | None = None,
                              *, mutation: bool = True) -> dict:
    """Refuse + audit a qemu-agent op whose VMID isn't on the allowlist (fail-closed).
    `mutation` must reflect the GATED tool's true class so blocked reads don't ledger as mutations."""
    return _blocked(action, target, "blocked:allowlist",
                    f"Guest {target} is not in PROXIMO_AGENT_ALLOWLIST (fail-closed) — add it there to permit.",
                    detail, mutation=mutation)


def _agent_gate(cfg, action: str, vmid: str, *, mutation: bool) -> dict | None:
    """Shared qemu-agent gate: off-by-default, then allowlist (fail-closed), in order.
    Returns the blocked-response dict (already recorded to the ledger) if refused, or
    None to proceed. `mutation` must reflect the GATED tool's true class so blocked reads
    don't ledger as mutations."""
    if not cfg.enable_agent:
        return _agent_disabled(action, f"qemu/{vmid}", mutation=mutation)
    if not cfg.agent_permitted(vmid):
        return _blocked_agent_allowlist(action, f"qemu/{vmid}", mutation=mutation)
    return None


# --- In-container exec (ssh -> pct) — MUTATION-CAPABLE, confirm-gated ---

@tool()
def ct_exec(
    ctid: Annotated[str, Field(description="Numeric CTID of the target LXC container (allowlist-scoped).")],
    command: Annotated[list[str], Field(description="Argv list to run inside the container (not a shell string).")],
    snapshot: Annotated[bool, Field(description="Take a fail-closed auto-undo snapshot before running.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; true executes.")] = False,
) -> dict:
    """MUTATION-CAPABLE: run a command inside an LXC (ssh -> pct exec).

    Dry-run by default: without confirm=True you get a PLAN — the command plus a heuristic
    read-vs-write / destructive-pattern classification (advisory only) — recorded to the ledger.
    Re-call with confirm=True to execute. Disabled unless PROXIMO_ENABLE_EXEC is set (safe default
    is API-only). Allowlist-scoped (fail-closed) and audited.

    snapshot=True (UNDO): take an auto-undo snapshot first and WAIT for it; if it can't be made
    (e.g. storage doesn't support snapshots) the command is NOT run (fail-closed). On success the
    result carries an `undo_point` you can revert with pve_rollback.
    """
    cfg, api, exec_, audit = _svc()
    # Audit completeness is the default; PROXIMO_LEDGER_REDACT records a command fingerprint instead
    # of the argv (which can carry secrets, e.g. `--password ...`) — see audit.py + README.
    detail = command_fingerprint(command) if cfg.redact_ledger else {"command": command}
    if not cfg.enable_exec:
        return _exec_disabled("ct_exec", str(ctid), detail)
    ctid = _check_vmid(ctid)  # L07: validate CTID format at server layer before allowlist gate
    if not cfg.ct_permitted(ctid):
        return _blocked_allowlist("ct_exec", str(ctid), detail)
    plan = _plan("ct_exec", str(ctid), lambda: plan_exec(ctid, command, redact=cfg.redact_ledger))
    if not confirm:
        return {"status": "plan", "auto_snapshot": snapshot, **plan.as_dict()}

    try:
        # Containment gate BEFORE the auto-undo snapshot (which fires outside _audited) — refuse the
        # WHOLE operation while contained, not just the exec half. Same primitives + same gate order
        # _audited uses (RATE after consent — see the order comment there / envelope.py).
        enforce_containment("ct_exec", str(ctid), audit, detail=detail)
        enforce_scope("ct_exec", str(ctid), audit, detail=detail)
        enforce_lease("ct_exec", str(ctid), audit, detail=detail)
        enforce_envelope_forbid("ct_exec", str(ctid), audit, detail=detail)
        enforce_consent("ct_exec", str(ctid), audit, detail=detail)
        enforce_envelope_rate("ct_exec", str(ctid), audit, detail=detail)

        undo_point = None
        if snapshot:
            undo = _auto_undo("ct_exec", str(ctid), api, ctid, detail)
            if undo.get("status") == "blocked:undo_unavailable":
                return undo  # fail-closed: command NOT run
            undo_point = undo

        def _do() -> dict:
            r = exec_.run(ctid, command)
            out = {"returncode": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
            if undo_point:
                out["undo_point"] = undo_point
            return out

        return _audited("ct_exec", str(ctid), _do, mutation=True,
                        detail={**detail, "confirmed": True, "undo": bool(undo_point)})
    finally:
        # A10: clear the per-operation CONSENT/ENVELOPE de-dup markers when this
        # manual-audit-path mutation ends — covers the blocked:undo_unavailable EARLY
        # RETURN (which never reaches _audited) and a rate-refusal after consent already
        # consumed. Same pattern as pve_agent_exec.
        _end_mutation_gates()


@tool()
def ct_psql(
    ctid: Annotated[str, Field(description="Numeric CTID of the container running PostgreSQL (allowlist-scoped).")],
    sql: Annotated[str, Field(description="SQL to run via psql inside the container, as the database OS user.")],
    db: Annotated[str, Field(description="Target database name.")] = "postgres",
    snapshot: Annotated[bool, Field(description="Take a fail-closed auto-undo snapshot before running.")] = False,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; true executes.")] = False,
) -> dict:
    """MUTATION-CAPABLE: run SQL via psql inside a container (as the db OS user).

    Dry-run by default: without confirm=True you get a PLAN — the SQL plus a heuristic
    read/DML/DDL classification (advisory only) — recorded to the ledger. Re-call with
    confirm=True to execute.

    snapshot=True (UNDO): take an auto-undo snapshot first and WAIT for it; if it can't be made the
    SQL is NOT run (fail-closed). On success the result carries an `undo_point` (revert via pve_rollback).
    """
    cfg, api, exec_, audit = _svc()
    # Audit completeness is the default; PROXIMO_LEDGER_REDACT records a fingerprint instead of
    # the body (which can carry secrets/PII) — see audit.py + README.
    detail = {"db": db, **(sql_fingerprint(sql) if cfg.redact_ledger else {"sql": sql})}
    if not cfg.enable_exec:
        return _exec_disabled("ct_psql", str(ctid), detail)
    ctid = _check_vmid(ctid)  # L07: validate CTID format at server layer before allowlist gate
    if not cfg.ct_permitted(ctid):
        return _blocked_allowlist("ct_psql", str(ctid), detail)
    plan = _plan("ct_psql", str(ctid), lambda: plan_psql(ctid, sql, db=db, redact=cfg.redact_ledger))
    if not confirm:
        return {"status": "plan", "auto_snapshot": snapshot, **plan.as_dict()}

    try:
        # Containment gate BEFORE the auto-undo snapshot (which fires outside _audited) — refuse the
        # WHOLE operation while contained, not just the exec half. Same primitives + same gate order
        # _audited uses (RATE after consent — see the order comment there / envelope.py).
        enforce_containment("ct_psql", str(ctid), audit, detail=detail)
        enforce_scope("ct_psql", str(ctid), audit, detail=detail)
        enforce_lease("ct_psql", str(ctid), audit, detail=detail)
        enforce_envelope_forbid("ct_psql", str(ctid), audit, detail=detail)
        enforce_consent("ct_psql", str(ctid), audit, detail=detail)
        enforce_envelope_rate("ct_psql", str(ctid), audit, detail=detail)

        undo_point = None
        if snapshot:
            undo = _auto_undo("ct_psql", str(ctid), api, ctid, detail)
            if undo.get("status") == "blocked:undo_unavailable":
                return undo  # fail-closed: SQL NOT run
            undo_point = undo

        def _do() -> dict:
            r = exec_.psql(ctid, sql, db=db)
            out = {"returncode": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
            if undo_point:
                out["undo_point"] = undo_point
            return out

        return _audited("ct_psql", str(ctid), _do, mutation=True,
                        detail={**detail, "confirmed": True, "undo": bool(undo_point)})
    finally:
        # A10: clear the per-operation CONSENT/ENVELOPE de-dup markers when this
        # manual-audit-path mutation ends — covers the blocked:undo_unavailable EARLY
        # RETURN (which never reaches _audited) and a rate-refusal after consent already
        # consumed. Same pattern as pve_agent_exec.
        _end_mutation_gates()


def _anchor_moved_hint(prev_entries: int | None, cur_entries: int) -> str:
    """Explain a head that has moved past the off-box anchor pin, using pinned vs live entry counts
    so a routine forward-grow reads as benign stale-pin lag and a shrink reads as a real
    truncation/wipe alarm. The pin is intentionally NOT auto-advanced here (anti-poisoning; see
    audit_anchor.py) — re-pin deliberately once the ledger is confirmed intact."""
    base = (
        "the live ledger head has moved past the off-box anchor pin; the pin was NOT auto-advanced "
        "(advancing it on a possibly-tampered ledger would poison the anchor). "
    )
    if prev_entries is None:
        return base + "Re-pin the anchor deliberately once you've confirmed the ledger is intact."
    if cur_entries > prev_entries:
        return base + (
            f"The ledger has MORE entries than the pin ({cur_entries} > {prev_entries}) — "
            "consistent with legitimate forward growth; re-pin when you've confirmed the new "
            "entries are genuine. (A forged tail-append also grows the count, so confirm via the "
            "chain, not the count alone.)"
        )
    if cur_entries < prev_entries:
        return base + (
            f"The ledger has FEWER entries than the pin ({cur_entries} < {prev_entries}) — a "
            "TRUNCATION or WIPE signal. INVESTIGATE the ledger and the sink."
        )
    return base + (
        f"Same entry count ({cur_entries}) but a different head — the tail was rewritten or forged. "
        "INVESTIGATE."
    )


# THE READ SIDE OF PROVE. 0.29.0 records the principal on every entry and, until this tool,
# nothing could read one back — audit_verify returns ok/entries/head, so "who changed this
# guest" was unanswerable through Proximo while the answer sat on disk. Found on the real
# estate by a local qwen3:8b, which read the catalog and correctly reported that no tool
# does this. Bare like audit_verify and for the same reason: the ledger is a LOCAL file with
# no remote box to target. Resident in every mode — a PROVE chain you cannot read is a claim,
# not a control.
@mcp.tool()
def audit_entries(
    limit: Annotated[int, Field(description="Newest N entries to return (default 20).")] = 20,
    target: Annotated[str | None, Field(description="Only entries against this exact target, e.g. 'vmid=100'.")] = None,
    action: Annotated[str | None, Field(description="Only this exact tool name, e.g. 'pve_guest_config_set'.")] = None,
    principal: Annotated[str | None, Field(description="Only entries attributed to this caller id.")] = None,
    mutations_only: Annotated[bool, Field(description="Only entries that changed state.")] = False,
) -> dict:
    """READ-ONLY: WHO changed WHAT and WHEN — guest configuration changes and every other
    audited action, read back from the PROVE ledger.

    Newest first. This is how you answer "who changed this guest" or "what has this caller
    done". `matched` counts entries passing your filters, `total` counts the whole ledger,
    and `truncated` says so when `limit` cut rows. An entry with no principal returns null
    plus a note: the ledger not capturing an identity is a fact about the log, never a claim
    that nobody was responsible. This READS the chain; `audit_verify` PROVES it is intact.
    """
    return read_entries(limit=limit, target=target, action=action,
                        principal=principal, mutations_only=mutations_only)


    # THIS Proximo's one PROVE ledger chain, which has no remote box to target. It is the
    # sole intentionally-bare tool; every other tool (incl. the ct_* exec tools) is @tool().
@mcp.tool()
def audit_verify(
    expected_head: Annotated[
        str | None,
        Field(
            description="64-char hex head() value pinned off-box; verifying against it also catches "
            "tail truncation, a forged tail-append, or a full ledger replacement. Omit to fall "
            "back to PROXIMO_AUDIT_EXPECTED_HEAD."
        ),
    ] = None,
) -> dict:
    """Verify the tamper-evident audit ledger's hash chain — PROVE the log is intact.

    Pass `expected_head` (the head() value you pinned off-box) to also catch tail
    truncation, a forged tail-append, or a full file replacement — a forward walk
    alone can't see those. Falls back to PROXIMO_AUDIT_EXPECTED_HEAD when omitted.
    """
    # The ledger is a LOCAL file: a box with no (or non-PVE) config still has a chain to
    # verify, and the PROVE pillar must stand there. Same tolerance contract as _ledger();
    # from_env_ledger carries the audit_* fields including the env head pin, and never
    # demands the PVE triple. (Arena find 2026-07-30 — the fourth site of the 741211b class.)
    try:
        cfg, _, _, audit = _svc()
    except RuntimeError:
        cfg = ProximoConfig.from_env_ledger()
        audit = _instance_ledger()
    pin = expected_head if expected_head is not None else cfg.expected_head
    if pin is not None:
        # Normalize a copy-pasted head (case-insensitive hexdigest; strip stray spaces/newline) the
        # same way config does — a blank/whitespace value becomes "unpinned", not a caller error.
        pin = pin.strip().lower() or None
    if pin is not None and not looks_like_head(pin):
        # A genuinely malformed pin is a CALLER error, not tamper — raise clearly instead of
        # letting it fall through to a "head mismatch" that cries wolf.
        raise ProximoError(
            f"invalid expected_head: {pin!r} (must be a 64-char hex head() value)"
        )
    v = audit.verify(expected_head=pin)
    # When nothing is pinned, the forward walk can't see tail truncation / forged append / wipe —
    # nudge the operator to anchor the head off-box (the strong guarantee), so the feature isn't
    # silently unused. No nudge once a pin is in effect.
    hint = None if pin is not None else (
        "not pinned against tail attacks: set PROXIMO_AUDIT_EXPECTED_HEAD (or pass expected_head=) "
        "to the current 'head' value, stored off-box, to detect tail truncation / forged append / "
        "full wipe — the off-box anchor is the strong guarantee."
    )
    # A pinned "head mismatch" with the chain otherwise intact is byte-identical whether it's a tail
    # attack or a keyed-default upgrade that rotated the head. If a rotation archive sits beside the
    # ledger, say so — the stderr migration warning is often swallowed by MCP stdio clients.
    rotation_hint = None
    if not v.ok and v.broken_at is None and pin is not None:
        archive = find_rotation_archive(audit.path)
        if archive:
            rotation_hint = (
                "a keyed-default migration archive sits beside this ledger "
                f"({os.path.basename(archive)!r}). If you upgraded Proximo since you pinned, this "
                "'head mismatch' is the expected migration head-rotation — re-pin "
                "PROXIMO_AUDIT_EXPECTED_HEAD to the 'head' value above. If you did NOT just upgrade, "
                "treat this as a genuine tail-attack signal and investigate."
            )
    # Off-box anchor: if a sink is configured, keep it in step with the ledger — but SAFELY.
    # getattr keeps the tests' SimpleNamespace cfgs (no anchor_sink attr) working.
    #
    # ANTI-POISONING INVARIANT (see audit_anchor.py): the on-demand export advances the off-box pin
    # ONLY on a first run (no pin yet) or when the live head is UNCHANGED. It NEVER re-pins to a
    # head that has MOVED — otherwise a verify that just detected a truncation/wipe would overwrite
    # the good pin with the tampered head and hide the attack after the next restart. A moved head
    # is surfaced as anchor_hint (count-directional) instead; advancing the pin past it is the
    # operator's deliberate act.
    #
    # FAIL-CLOSED: a sink read or publish failure is NOT swallowed into a green verify — a
    # configured anchor that can't be reached is suspicious, so we refuse the call rather than let
    # the pin go silently stale.
    anchor = getattr(cfg, "anchor_sink", None)
    anchor_name = None
    anchor_last_export = None
    anchor_hint = None
    if anchor is not None:
        anchor_name = anchor.name
        try:
            prev = anchor.last_pin()
        except AnchorError as e:
            raise ProximoError(
                f"off-box audit anchor is unreachable: {e}. Refusing the verify (fail-closed; a "
                "verify that can't consult its own tamper anchor is not a clean check)."
            ) from e
        head_now = audit.head()
        prev_head = prev["head"] if prev else None
        # v.ok guard: NEVER publish off a ledger we just failed to verify. An interior-body tamper
        # leaves the tail head untouched, so head_now still equals the pin and this branch would
        # otherwise overwrite the anchor's good entries count with the tampered count. A failed
        # verify with a MOVED head (benign forward-growth lag, or a shrink) falls to the else and
        # still gets its directional anchor_hint — only the pin-advancing publish is withheld.
        if v.ok and (prev_head is None or prev_head == head_now):
            # First run (establish the pin) or head unchanged (idempotent re-pin): safe to publish.
            ts = datetime.now(UTC).isoformat()
            try:
                anchor.publish(head_now, ts, cfg.node, audit.path, entries=v.entries)
            except AnchorError as e:
                raise ProximoError(
                    f"off-box audit anchor export failed: {e}. The anchor pin could not be updated "
                    "— fix the sink and retry (fail-closed; the verify result is withheld so a "
                    "stale off-box pin is not mistaken for a clean check)."
                ) from e
            anchor_last_export = ts
        else:
            # Reached when the publish was withheld: either the head MOVED from the pin, or the
            # verify FAILED (v.ok False) so we refused to advance. `prev` is None on a first run
            # whose verify failed — guard it (_anchor_moved_hint already handles prev_entries None).
            # Explain which way it moved via the pinned vs live entry count so a forward-grow reads
            # as benign lag and a shrink reads as a real truncation/wipe alarm.
            anchor_hint = _anchor_moved_hint(prev.get("entries") if prev else None, v.entries)
    return {
        "ok": v.ok,
        "entries": v.entries,
        "broken_at_line": v.broken_at,
        "reason": v.reason,
        "head": audit.head(),
        "expected_head": pin,
        "keyed": audit.keyed,
        "hint": hint,
        "rotation_hint": rotation_hint,
        "anchor_sink": anchor_name,
        "anchor_last_export": anchor_last_export,
        "anchor_hint": anchor_hint,
    }


# ---------------------------------------------------------------------------
# qemu-agent plane (Wave 3) — in-guest ops via the QEMU Guest Agent
# ---------------------------------------------------------------------------

# Pace the exec-status poll loop so it never busy-waits the PVE API (mirrors _wait_task's sleep).
_AGENT_POLL_INTERVAL = 1.0


@tool()
def pve_agent_exec(
    vmid: Annotated[str, Field(description="Numeric VMID of the target QEMU guest (allowlist-scoped).")],
    command: Annotated[list[str], Field(description="Argv list to run in the guest via the qemu-agent.")],
    node: Annotated[str | None, Field(description="PVE node the guest runs on; omit to resolve automatically.")] = None,
    timeout: Annotated[int, Field(description="Seconds to poll for exit before returning status='running'.")] = 30,
    confirm: Annotated[bool, Field(description="False (default) returns a dry-run PLAN; true executes.")] = False,
) -> dict:
    """MUTATION: run a command inside a guest via the qemu-agent (async, polls for result).

    Dry-run by default: without confirm=True you get a PLAN recorded to the ledger.
    Re-call with confirm=True to execute.

    Requires PROXIMO_ENABLE_AGENT=1 and the VMID in PROXIMO_AGENT_ALLOWLIST.
    The command runs INSIDE the guest OS — no undo primitive on this plane.

    Returns status="ok" only when the agent reports the process exited.
    Returns status="running" with pid when the poll deadline is reached before exit.
    """
    cfg, api, _, audit = _svc()
    blocked = _agent_gate(cfg, "pve_agent_exec", vmid, mutation=True)
    if blocked:
        return blocked

    # Ledger redaction parity with ct_exec: a guest exec argv can carry a secret (e.g. `mysql -pPW`).
    # When PROXIMO_LEDGER_REDACT is set, store a fingerprint instead of the argv — in BOTH the plan's
    # change line (via redact=) and the execute-path audit detail.
    detail = command_fingerprint(command) if cfg.redact_ledger else {"command": command}
    plan = _plan("pve_agent_exec", f"qemu/{vmid}",
                 lambda: plan_agent_exec(vmid, command, node, redact=cfg.redact_ledger))
    if not confirm:
        return {"status": "plan", **plan.as_dict()}

    try:
        # Containment gate: this tool has a manual audit path (below) that never runs through
        # _audited(), so it must call the same primitives directly, in the SAME order (RATE after
        # consent — see the order comment in _audited / envelope.py), BEFORE the real guest-OS
        # mutation (api.agent_exec) fires — outside the try/except so a refusal here is never
        # re-caught and re-recorded as outcome="error".
        enforce_containment("pve_agent_exec", f"qemu/{vmid}", audit, detail=detail)
        enforce_scope("pve_agent_exec", f"qemu/{vmid}", audit, detail=detail)
        enforce_lease("pve_agent_exec", f"qemu/{vmid}", audit, detail=detail)
        enforce_envelope_forbid("pve_agent_exec", f"qemu/{vmid}", audit, detail=detail)
        enforce_consent("pve_agent_exec", f"qemu/{vmid}", audit, detail=detail)
        enforce_envelope_rate("pve_agent_exec", f"qemu/{vmid}", audit, detail=detail)

        # TAINT: pve_agent_exec is a manual-audit-path tool (never runs through _audited(), see the
        # comment above) but IS adversarial-classified — the guest OS controls out-data/err-data.
        # Same construction as _audited: mark BEFORE the real guest exec fires (so a call that raises
        # still taints) and FAIL-CLOSED if the marker can't be written — refuse rather than run the
        # guest exec and return its output untracked (a planted symlink on the marker dir/lock, or a
        # transient FS error, would otherwise silently un-taint the session).
        if taint_tracking_on():
            try:
                mark_tainted(os.path.dirname(audit.path), "pve_agent_exec")
            except Exception as e:  # noqa: BLE001 — any marker-write failure must fail CLOSED (below)
                audit.record("pve_agent_exec", target=f"qemu/{vmid}", mutation=True,
                             outcome="blocked:taint_mark_failed",
                             detail=_untrusted_detail("pve_agent_exec", {"error": type(e).__name__}),
                             principal=ledger_principal(), remote=ledger_remote())
                raise ProximoError(
                    "taint tracking is enabled but the taint marker could not be written for "
                    "'pve_agent_exec' — refusing to return untrusted output untracked (fail-closed)"
                ) from e

        # Execute: POST exec, then poll exec-status until exited or deadline.
        # Manual audit path so we can record honest outcome ("ok" vs "running").
        try:
            exec_result = api.agent_exec(vmid, node, command)
            pid = exec_result.get("pid")
            if pid is None:
                raise ValueError("agent exec returned no pid")  # noqa: TRY301

            # VERIFIED live (PVE 9.2): exec-status returns exited/exitcode/out-data/err-data.
            deadline = time.monotonic() + timeout
            while True:
                status = api.agent_exec_status(vmid, node, pid)
                # 'exited' arrives as a JSON bool; accept int 1 too defensively, and NEVER treat a
                # falsy/missing value as completion (that would fake an "ok" for a still-running cmd).
                if status.get("exited") in (True, 1):
                    # Process completed — honest "ok" outcome. out-data/err-data are plain text (not base64).
                    out_data = status.get("out-data", "")
                    err_data = status.get("err-data", "")
                    result = {
                        "pid": pid,
                        "exitcode": status.get("exitcode"),
                        "out-data": out_data,
                        "err-data": err_data,
                    }
                    audit.record("pve_agent_exec", target=f"qemu/{vmid}", mutation=True, outcome="ok",
                                 detail=_untrusted_detail("pve_agent_exec",
                                                          {**detail, "confirmed": True, "pid": pid}),
                                 principal=ledger_principal(), remote=ledger_remote())
                    # Fence ONLY the `result` field (the guest-controlled out-data/err-data), keeping the
                    # top-level `status` intact — same symmetric-envelope contract _audited honors for
                    # ct_exec/ct_psql. Fencing the whole {status,result} dict would bury `status` inside
                    # the JSON string and break `resp["status"]`. fence_output is a no-op unless FENCE is on.
                    return {"status": "ok", "result": fence_output("pve_agent_exec", result)}
                if time.monotonic() >= deadline:
                    # Timeout BEFORE exit observed — honest "running" outcome, never "ok". This branch
                    # carries NO guest output (the command hasn't produced out-data yet) — only status,
                    # pid, and a Proximo-authored message — so there is nothing adversarial to fence.
                    audit.record("pve_agent_exec", target=f"qemu/{vmid}", mutation=True,
                                 outcome="running",
                                 detail=_untrusted_detail(
                                     "pve_agent_exec",
                                     {**detail, "confirmed": True, "pid": pid, "timeout": timeout}),
                                 principal=ledger_principal(), remote=ledger_remote())
                    return {
                        "status": "running", "pid": pid,
                        "message": f"command is still running (pid={pid}) — did not exit within {timeout}s; "
                                   "poll pve_agent_info with command='exec-status' and the returned pid."}
                time.sleep(_AGENT_POLL_INTERVAL)  # pace polls — do not hammer the PVE API
        except Exception as e:
            audit.record("pve_agent_exec", target=f"qemu/{vmid}", mutation=True, outcome="error",
                         detail=_untrusted_detail("pve_agent_exec",
                                                  {"error": type(e).__name__, "confirmed": True}),
                         principal=ledger_principal(), remote=ledger_remote())
            raise
    finally:
        # A10: clear the per-operation CONSENT/ENVELOPE de-dup markers when this
        # manual-audit-path mutation ends (pve_agent_exec never routes through
        # _audited, so its clear is here) — including a rate-refusal after consent
        # already consumed, so no marker leaks to a later planless mutation.
        _end_mutation_gates()


# --- The door: scoping/facade layer lives in door.py (A11 3a/3b, 2026-08-11). ---
# Only what server.py itself calls is imported; every other door-owned name is reached at
# `proximo.door` directly (the 3b retarget dropped the re-export shims, catalogs included).
# proximo_call and the H1 handler stay HERE because tool registration is this module's
# import-time side effect, and the two CALL statements at the bottom keep their load-bearing
# order relative to it.
from .door import (  # noqa: E402
    _apply_surfaces,
    _slim_registry_schemas,
    _snapshot_full_catalog,
    _unknown_tool_error,
    dispatch_tool,
    escape_catalog,
)


# A tool description is a PROMPT, and this one is resident in every mode including the leanest —
# so it carries only what a model needs to ACT, and the rationale lives here where it costs no
# runtime tokens. (Measured: the first draft's four-paragraph docstring moved the lean doorway
# 555 -> 665 tokens, a 20% regression on the figure the README publishes. Pinned by
# tests/test_schema_budget.py, which is why it was caught rather than shipped.)
#
# Why it exists: scoping changes what is ADVERTISED; it must never change what is REACHABLE.
# Four layers prune the registry and every one of them could otherwise strand a working tool on
# every transport with no recovery inside a live session.
#
# Why a tool for an unconfigured plane is still reachable rather than hidden: it fails with its
# OWN named config error ("Missing required PMG env var: PROXIMO_PMG_BASE_URL"), which tells an
# operator what to fix, where "unknown tool" would send them to build something that exists.
@mcp.tool()
async def proximo_call(
    tool: Annotated[str, Field(description="Exact tool name to run, e.g. 'pve_guest_power' "
                                          "(from proximo_find_tools). Non-resident names are fine.")],
    arguments: Annotated[dict | None, Field(description="The tool's arguments as an object, e.g. "
                                            "{'vmid': 100, 'action': 'reboot'}. Get the shape from "
                                            "proximo_tool_schema. Omit/null for a no-arg tool.")] = None,
) -> Any:
    """Call any Proximo tool by exact name, including ones not in this server's listed tools.

    Get the argument shape from proximo_tool_schema first. Same gates as calling it directly:
    dry-run PLAN, ledger entry, token ACL. A smaller doorway, not a looser one.
    """
    return await dispatch_tool(server_mcp=mcp, catalog=escape_catalog(),
                               name=tool, arguments=arguments or {})



# `proximo doctor --product {pve,pbs,pmg,pdm}` mirrors `proximo mint --product`'s flag (verdict
# 1.3): SETUP.md's Step 4 ("verify YOUR boundary") was 100% PVE-flavored — a PBS/PMG/PDM-only
# operator following it literally got a bare PVE missing-env RuntimeError with no pointer to the
# one place that IS honest about their plane (`mint --product <plane>`'s own runbook).
#
# pmg_doctor is a real read-only preflight tool and gets a real dispatch; pbs/pdm have no doctor
# tool at all yet, so those two refuse HONESTLY — naming the runbook and a real read tool that
# does exist — rather than pretending to check something that isn't there.
_DOCTOR_NO_TOOL_REMEDY: dict[str, str] = {
    "pbs": "no pbs_doctor tool exists yet — run `proximo mint --product pbs` for the onboarding "
           "runbook (its own verify step is the live connectivity check), or call pbs_version / "
           "pbs_datastores_list directly once PROXIMO_PBS_BASE_URL and PROXIMO_PBS_TOKEN_PATH "
           "are set.",
    "pdm": "no pdm_doctor tool exists yet — run `proximo mint --product pdm` for the onboarding "
           "runbook (its own verify step is the live connectivity check), or call pdm_ping / "
           "pdm_version directly once PROXIMO_PDM_BASE_URL and PROXIMO_PDM_TOKEN_PATH are set.",
}

# base-url env var per OTHER plane, used only to point a PVE-default doctor failure at the plane
# the operator actually configured, instead of a bare missing-env error naming vars they never
# intended to set (PBS-only-walk verdict finding: SETUP.md's Step 4 dead-ends this operator).
_OTHER_PLANE_BASE_URL_ENV: dict[str, str] = {
    "pbs": "PROXIMO_PBS_BASE_URL",
    "pmg": "PROXIMO_PMG_BASE_URL",
    "pdm": "PROXIMO_PDM_BASE_URL",
}


def _configured_other_planes(exclude: str) -> list[str]:
    """Which OTHER planes look configured (their base-url env var is set), in a stable order."""
    return [p for p in ("pbs", "pmg", "pdm")
            if p != exclude and os.environ.get(_OTHER_PLANE_BASE_URL_ENV[p])]


def _run_doctor(product: str, target: str | None) -> dict:
    """Dispatch `proximo doctor --product <product>` to the right doctor tool, or refuse honestly
    if none exists for that plane. Looks up `pve_doctor`/`pmg_doctor` as globals (not a
    module-load-time dict) so a test's `monkeypatch.setattr(server, "pve_doctor", ...)` is always
    what actually gets called."""
    tools = {"pve": pve_doctor, "pmg": pmg_doctor}
    if product not in tools:
        raise ProximoError(_DOCTOR_NO_TOOL_REMEDY[product])
    try:
        return tools[product](proximo_target=target)
    except RuntimeError as e:
        # The verdict's core case: `proximo doctor` defaults to pve, so a PBS/PMG/PDM-only
        # operator running it bare hits PVE's own missing-env error — even though THEIR plane
        # is fine. Point at the plane that's actually configured instead of leaving them at a
        # dead end naming env vars they never intended to set.
        if product == "pve" and "Missing required Proximo env var" in str(e):
            other = _configured_other_planes("pve")
            if other:
                plane = other[0]
                pointer = (f"`proximo doctor --product {plane}`" if plane in tools
                           else f"`proximo mint --product {plane}`'s onboarding runbook "
                                f"(no {plane}_doctor tool exists yet)")
                raise ProximoError(
                    f"no PVE env is configured ({e}), but {_OTHER_PLANE_BASE_URL_ENV[plane]} is "
                    f"set — pve is only the CLI default; run {pointer} instead of --product pve."
                ) from e
        raise


def _record_session(kind: str) -> None:
    """Arrival/departure entries — only when the principal feature is configured (byte-compat)."""
    if not principal_feature_active():
        return
    _ledger().record(kind, target="proximo", mutation=False,
                     detail={"face": serving_face()}, principal=ledger_principal(),
                     remote=ledger_remote())


def _announce_estate_memory() -> None:
    """Name the estate-memory file on startup, every start, while it is on.

    EXTERNAL VET 2026-08-02: estate memory went default-on in 0.30.0, so every existing install
    silently gained a plaintext file inventorying its guests, nodes and targets. The rails around
    that file are solid (0600 before sqlite opens it, O_NOFOLLOW) and the reviewer said so; the
    objection was to a DEFAULT that appears unannounced. A search index defaulting on is a small
    ask, an infrastructure inventory is a larger one, and an operator cannot weigh a file they
    were never told about. So: keep the default, name the file — path included, because
    "memory is on" is not actionable and a path is.

    Deliberately unconditional rather than once-per-box: a line the operator has already read
    costs one line, and a state file nobody knows about costs them the choice.
    """
    from proximo.memory import memory_enabled, memory_path
    if not memory_enabled():
        return
    print(f"proximo: estate memory ON — local inventory at {memory_path()} "
          f"(nothing leaves this box; PROXIMO_MEMORY=0 opts out, "
          f"PROXIMO_MEMORY_PATH moves it)", file=sys.stderr)


def _load_receipt_denylist():
    """Compile PROXIMO_RECEIPT_DENYLIST (operator bare-name list) at the impure CLI edge, so
    receipt.py stays I/O-free. Returns a compiled pattern or None; warns loudly (never silently
    drops the requested redaction) if the env is set but the file is unreadable."""
    from proximo.receipt import compile_denylist
    deny_path = os.environ.get("PROXIMO_RECEIPT_DENYLIST")
    if not deny_path:
        return None
    try:
        with open(deny_path, encoding="utf-8") as df:
            toks = [ln.strip() for ln in df if ln.strip() and not ln.lstrip().startswith("#")]
        return compile_denylist(toks)
    except OSError as e:
        print(f"warning: PROXIMO_RECEIPT_DENYLIST={deny_path!r} unreadable ({e}); bare estate names "
              "were NOT redacted from free text — read the receipt before you share it.",
              file=sys.stderr)
        return None


def _print_stdio_usage() -> None:
    print(
        "proximo — Proxmox MCP server (stdio) + operator CLI.\n\n"
        "Usage:\n"
        "  proximo                start the MCP stdio server (wire into an MCP client)\n"
        "  proximo doctor         read-only token/config preflight (never starts the server)\n"
        "  proximo mint           print a least-privilege credential runbook\n"
        "  proximo badge ...      mint / inspect a caller badge\n"
        "  proximo arm | disarm   operator arm-lease control\n"
        "  proximo reap           drop an expired arm lease\n"
        "  proximo hello          connectivity smoke\n\n"
        "Network faces are separate console scripts: proximo-http, proximo-mcp-http, proximo-a2a\n"
        "(each --help too). Configuration is via PROXIMO_* env — see packaging/proximo.env.example."
    )


def _cmd_badge() -> None:
    """`proximo badge mint|inspect` — extracted from main() to keep main under the mccabe
    ceiling (the badge subcommand carries its own argparse + mint/inspect branches)."""
    import argparse
    import json as _json

    from .principal import _b64url_dec, mint_badge, public_jwk
    parser = argparse.ArgumentParser(prog="proximo badge")
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mint")
    m.add_argument("--key", required=True, help="EC P-256 private key PEM (caller keeps this)")
    m.add_argument("--sub", required=True, help="caller name — must match the pinned filename stem")
    m.add_argument("--exp", default=None, help="optional lifetime, e.g. 90d / 12h / 30m")
    m.add_argument("--jwk-out", default=None, help="where to write the public .jwk to pin")
    i = sub.add_parser("inspect")
    i.add_argument("badge")
    args = parser.parse_args(sys.argv[2:])
    try:
        if args.cmd == "mint":
            # Same floor every other secret this codebase loads by path gets (PVE/PBS/PMG/PDM
            # tokens, bearer-token files, the A2A signing key). This one mints identities, so
            # it is not a weaker class of secret — it was just the one that never got wired.
            from ._secretfile import refuse_exposed_secret  # noqa: PLC0415

            refuse_exposed_secret(args.key, "caller badge signing key")
            with open(args.key, "rb") as f:
                pem = f.read()
            exp = None
            if args.exp:
                try:
                    unit = {"s": 1, "m": 60, "h": 3600, "d": 86400}[args.exp[-1]]
                    exp = int(time.time()) + int(args.exp[:-1]) * unit
                except (KeyError, ValueError) as e:
                    raise ValueError(
                        f"malformed --exp {args.exp!r} — expected <int><s|m|h|d>, e.g. 90d") from e
            jwk = public_jwk(pem, args.sub)
            if args.jwk_out:
                out = args.jwk_out
            else:
                # Default is "beside the key" (never cwd-relative), and --sub must be a bare
                # filename stem — reject anything a path separator would let escape that
                # directory (basename() alone would silently swallow the traversal instead
                # of refusing it, so also require safe == args.sub).
                safe = os.path.basename(args.sub)
                if not safe or safe in (".", "..") or safe != args.sub:
                    raise ValueError(
                        f"--sub {args.sub!r} is not a safe filename stem for the default "
                        f"JWK path; pass --jwk-out explicitly")
                out = os.path.join(os.path.dirname(os.path.abspath(args.key)), f"{safe}.jwk")
            if os.path.islink(out):
                raise ValueError(f"refusing to write JWK to a symlink: {out}")
            with open(out, "w", encoding="utf-8") as f:
                _json.dump(jwk, f, indent=2)
            print(mint_badge(pem, args.sub, exp=exp))
            if exp is None:
                print("no --exp given — badge expires after the default 30d (never minted "
                      "without an expiry); pass --exp <int><s|m|h|d> to change the lifetime.",
                      file=sys.stderr)
            print(f"pinned public key written to {out} — copy it into the operator's "
                  f"PROXIMO_CALLER_KEYS_DIR", file=sys.stderr)
        else:
            h_b64, p_b64, _ = args.badge.strip().split(".")
            print(_json.dumps({"header": _json.loads(_b64url_dec(h_b64)),
                               "payload": _json.loads(_b64url_dec(p_b64)),
                               "note": "NOT VERIFIED — inspection only"}, indent=2))
    except Exception as e:
        print(f"proximo badge: {e}", file=sys.stderr)
        raise SystemExit(1) from None


def main() -> None:
    # Source ~/.config/proximo/proximo.env FIRST (before doctor or any from_env) so a PROXIMO_* var
    # set in the documented file actually reaches the stdio server — otherwise it is silently ignored,
    # which is fail-dangerous for a security gate like PROXIMO_CONSENT_DIR. Real/inline env still wins.
    load_env_file()
    # `proximo --help` / `proximo -h` (help as the FIRST arg) prints usage and exits — never starts
    # the stdio server and never applies surfaces. A subcommand's own --help (e.g. `proximo doctor
    # --help`) is left to that subcommand and not intercepted here. (Single-branch form — no boolean
    # operator — to stay under the mccabe ceiling: sys.argv[1:2] is ["-h"]/["--help"] or something else.)
    if sys.argv[1:2] in (["-h"], ["--help"]):
        _print_stdio_usage()
        raise SystemExit(0)
    # Scope the registry only where the registry is USED: `doctor` reports what this box serves,
    # and the server itself serves it. The other CLI verbs neither serve nor report tools — and
    # since the 0.30 flip the DEFAULT path announces itself (the lean-mode line on stderr), which
    # would prefix every `proximo badge`/`mint` error with scoping noise (pinned by
    # test_badge_cli's err.startswith contracts).
    if not (len(sys.argv) > 1 and sys.argv[1] in ("mint", "arm", "disarm", "reap", "hello",
                                                  "badge")):
        try:
            _apply_surfaces()
        except ValueError as e:
            print(f"proximo: {e}", file=sys.stderr)
            raise SystemExit(1) from None
        _announce_estate_memory()
    # `proximo doctor` — verify your token/config (read-only preflight) BEFORE wiring Proximo into
    # an AI client. Prints what THIS token can and cannot do; never starts the server.
    if len(sys.argv) > 1 and sys.argv[1] == "doctor":
        import argparse
        import json

        from proximo.mint import PRODUCTS
        parser = argparse.ArgumentParser(prog="proximo doctor", add_help=False)
        parser.add_argument("--target", default=None,
                            help="Named target from PROXIMO_TARGETS registry to probe.")
        parser.add_argument("--product", default="pve", choices=PRODUCTS,
                            help=f"one of: {', '.join(PRODUCTS)} (default: pve; mirrors "
                                 "`proximo mint --product`)")
        parser.add_argument("--receipt", action="store_true",
                            help="render the run as one pasteable artifact, with node and cluster "
                                 "names, addresses, storage/pool ids, users, realms and API token "
                                 "ids removed. Nothing is transmitted — sharing it is your call.")
        args = parser.parse_args(sys.argv[2:])
        try:
            result = _run_doctor(args.product, args.target)
        except Exception as e:  # config/token/connectivity problem — give a plain message, not a trace
            print(f"proximo doctor: {e}", file=sys.stderr)
            raise SystemExit(1) from None
        # Credential-free by construction: `result` is doctor_check's advisory report — version,
        # capability lists, and config POSTURE (node, base_url, TLS bools, CA path, allowlist
        # counts). The token secret / PMG password are read only to build the auth header and are
        # never serialized into this report (verified: the secret appears 0x in the output). The
        # CodeQL py/clear-text-logging-sensitive-data flag here is a taint over-approximation
        # through the shared config object, not a real disclosure.
        if args.receipt:
            from datetime import datetime

            from proximo import __version__
            from proximo.receipt import render
            # The clock AND the optional bare-name denylist live at this impure edge on purpose, so
            # `render` stays pure/I/O-free and the same report always produces the same artifact.
            print(render(result, version=__version__,
                         generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         deny=_load_receipt_denylist()),
                  end="")
            return
        print(json.dumps(result, indent=2))
        return
    # `proximo mint` — print-only onboarding recipe: create → write → grant → wire → verify.
    # Prints the exact runbook for a least-privilege credential per product; makes NO API call,
    # never handles a secret, and never starts the server. Hands off to `proximo doctor`.
    if len(sys.argv) > 1 and sys.argv[1] == "mint":
        import argparse
        import json

        from proximo.mint import PRODUCTS, build_recipe, render_text
        parser = argparse.ArgumentParser(prog="proximo mint")
        parser.add_argument("--product", default="pve",
                            help=f"one of: {', '.join(PRODUCTS)} (default: pve)")
        parser.add_argument("--user", default=None,
                            help="service user (default: proximo@<product-realm>)")
        parser.add_argument("--token-name", default="mcp",
                            help="token name (default: mcp; unused for pmg)")
        parser.add_argument("--token-file", default=None,
                            help="credential file (default: ~/.config/proximo/<product>.token)")
        parser.add_argument("--write", action="store_true",
                            help="print the scoped WRITE grant instead of the read-only default")
        parser.add_argument("--json", action="store_true",
                            help="emit the recipe as structured JSON (mirrors doctor)")
        args = parser.parse_args(sys.argv[2:])
        try:
            recipe = build_recipe(product=args.product, user=args.user,
                                  token_name=args.token_name, token_file=args.token_file,
                                  write=args.write)
        except ValueError as e:
            print(f"proximo mint: {e}", file=sys.stderr)
            raise SystemExit(2) from None
        print(json.dumps(recipe, indent=2) if args.json else render_text(recipe))
        return
    # `proximo arm` / `proximo disarm` — the write-authority toggle: swap the token the server
    # reads per call. It PERFORMS the swap and then DISCLOSES whether the arm is a real boundary
    # or merely advisory, because that is a question of file ownership rather than of code (same
    # honesty the CONTAIN breaker gets in SECURITY.md). It grants nothing new: anyone who can run
    # this could already `cp` the arm source into place. The mint-and-revoke deployment has no
    # write token at rest to swap — that one uses `proximo mint --write`.
    if len(sys.argv) > 1 and sys.argv[1] in ("arm", "disarm"):
        import argparse
        import json

        from proximo.arm import ArmError, as_dict, do_arm, do_disarm
        from proximo.arm import render_text as render_arm_text
        verb = sys.argv[1]
        parser = argparse.ArgumentParser(prog=f"proximo {verb}")
        parser.add_argument("--session", default=None,
                            help="session key to scope this toggle to (default: "
                                 "$PROXIMO_SESSION_KEY, else the global token path)")
        parser.add_argument("--json", action="store_true",
                            help="emit the result as structured JSON (mirrors doctor/mint)")
        args = parser.parse_args(sys.argv[2:])
        try:
            result = (do_arm(session=args.session) if verb == "arm"
                      else do_disarm(session=args.session))
        except ArmError as e:
            print(f"proximo {verb}: {e}", file=sys.stderr)
            raise SystemExit(2) from None
        print(json.dumps(as_dict(result), indent=2) if args.json else render_arm_text(result))
        return
    # `proximo reap` — put the write key back for sessions that ENDED while armed. Liveness is the
    # KERNEL's answer: a serving process holds a shared flock for its whole life, so an exclusive
    # try succeeds only once every holder is gone. No age heuristic, nothing client-specific.
    if len(sys.argv) > 1 and sys.argv[1] == "reap":
        import argparse
        import json

        from proximo.arm import reap_as_dict, reap_stale_arms, render_reap
        parser = argparse.ArgumentParser(prog="proximo reap")
        parser.add_argument("--dry-run", action="store_true",
                            help="report the decisions and change nothing")
        parser.add_argument("--json", action="store_true",
                            help="emit the decisions as structured JSON (mirrors doctor/mint)")
        args = parser.parse_args(sys.argv[2:])
        decisions = reap_stale_arms(dry_run=args.dry_run)
        print(json.dumps(reap_as_dict(decisions, dry_run=args.dry_run), indent=2) if args.json
              else render_reap(decisions, dry_run=args.dry_run))
        return
    # `proximo hello` — the print-only agent front door: the six-move welcome, sharp
    # edges first, the ask last. Makes NO API call, sends nothing, never starts the
    # server.
    if len(sys.argv) > 1 and sys.argv[1] == "hello":
        import argparse
        import json

        from proximo.hello import build_greeting
        from proximo.hello import render_text as render_hello
        parser = argparse.ArgumentParser(prog="proximo hello")
        parser.add_argument("--json", action="store_true",
                            help="emit the greeting as structured JSON (mirrors doctor/mint)")
        args = parser.parse_args(sys.argv[2:])
        greeting = build_greeting()
        print(json.dumps(greeting, indent=2) if args.json else render_hello(greeting))
        return
    # `proximo badge` — offline caller-badge mint (signs with an operator-held EC P-256
    # private key, never touches the network) and a NEVER-VERIFYING inspect for debugging a
    # badge's claims. Makes NO API call, writes NO session/ledger entries, never starts the
    # server.
    if len(sys.argv) > 1 and sys.argv[1] == "badge":
        _cmd_badge()
        return
    # Register as a live holder of this session's arm, if it has one. This is the entire liveness
    # signal `proximo reap` reads: the kernel drops this lock on exit, crash or kill, so a session
    # that ENDED while armed becomes visible without any heartbeat, TTL, or client-specific probe.
    # Best-effort by contract (see arm.hold_session_lock) — it must never keep the server from
    # starting, and an arm that goes unheld only ever ends up disarmed, never over-privileged.
    from proximo.arm import hold_session_lock
    _arm_lock = hold_session_lock()
    if _arm_lock:
        print(f"proximo: holding the session arm lock ({_arm_lock})", file=sys.stderr)
    print(BANNER, file=sys.stderr)
    _record_session("session_start")
    try:
        mcp.run()
    finally:
        _record_session("session_end")


# --- Re-exports: every tool moved to proximo.tools.* is re-imported here by name so that
# (a) importing proximo.server still registers every tool with FastMCP as a side effect
#     (the exact count is machine-checked by tests/test_tool_count.py, not asserted in prose here),
# and (b) the existing `server.<tool_name>` surface (direct-call tests, CLI, introspection
# sweeps that do `getattr(server, name)`) keeps working unchanged. ---
from proximo import prompts as _prompts  # noqa: E402,F401  # safe-runbook MCP prompts (registration side effect)
from proximo.tools.memory_tools import (  # noqa: E402,F401
    proximo_baseline,
    proximo_recall,
)
from proximo.tools.pbs import (  # noqa: E402,F401
    pbs_apt_changelog,
    pbs_apt_repositories_get,
    pbs_apt_repository_add,
    pbs_apt_repository_set,
    pbs_apt_update_refresh,
    pbs_apt_updates_list,
    pbs_apt_versions,
    pbs_datastore_create,
    pbs_datastore_delete,
    pbs_datastore_get,
    pbs_datastore_status,
    pbs_datastore_update,
    pbs_datastores_list,
    pbs_gc_start,
    pbs_gc_status,
    pbs_group_change_owner,
    pbs_jobs_list,
    pbs_namespace_create,
    pbs_namespace_delete,
    pbs_namespaces_list,
    pbs_prune,
    pbs_remote_create,
    pbs_remote_delete,
    pbs_remote_get,
    pbs_remote_update,
    pbs_remotes_list,
    pbs_snapshot_delete,
    pbs_snapshot_notes_set,
    pbs_snapshot_protected_set,
    pbs_snapshots_list,
    pbs_tasks_list,
    pbs_traffic_control_delete,
    pbs_traffic_control_upsert,
    pbs_traffic_controls_list,
    pbs_verify_start,
)
from proximo.tools.pbs_access import (  # noqa: E402,F401
    pbs_acl_get,
    pbs_acl_update,
    pbs_permissions_get,
    pbs_realm_ad_create,
    pbs_realm_ad_delete,
    pbs_realm_ad_get,
    pbs_realm_ad_list,
    pbs_realm_ad_update,
    pbs_realm_ldap_create,
    pbs_realm_ldap_delete,
    pbs_realm_ldap_get,
    pbs_realm_ldap_list,
    pbs_realm_ldap_update,
    pbs_realm_openid_create,
    pbs_realm_openid_delete,
    pbs_realm_openid_get,
    pbs_realm_openid_list,
    pbs_realm_openid_update,
    pbs_realm_pam_get,
    pbs_realm_pam_set,
    pbs_realm_pbs_get,
    pbs_realm_pbs_set,
    pbs_roles_list,
    pbs_tfa_add,
    pbs_tfa_delete,
    pbs_tfa_entry_get,
    pbs_tfa_list,
    pbs_tfa_unlock,
    pbs_tfa_update,
    pbs_tfa_user_get,
    pbs_tfa_webauthn_get,
    pbs_tfa_webauthn_set,
    pbs_token_create,
    pbs_token_delete,
    pbs_token_update,
    pbs_user_create,
    pbs_user_delete,
    pbs_user_get,
    pbs_user_token_get,
    pbs_user_tokens_list,
    pbs_user_update,
    pbs_users_list,
)
from proximo.tools.pbs_acme import (  # noqa: E402,F401
    pbs_acme_account_create,
    pbs_acme_account_delete,
    pbs_acme_account_get,
    pbs_acme_account_list,
    pbs_acme_account_update,
    pbs_acme_cert_order,
    pbs_acme_cert_renew,
    pbs_acme_challenge_schema,
    pbs_acme_directories,
    pbs_acme_plugin_create,
    pbs_acme_plugin_delete,
    pbs_acme_plugin_get,
    pbs_acme_plugin_update,
    pbs_acme_plugins_list,
    pbs_acme_tos,
)
from proximo.tools.pbs_admin import (  # noqa: E402,F401
    pbs_admin_gc_jobs_list,
    pbs_admin_prune_jobs_list,
    pbs_admin_sync_jobs_list,
    pbs_admin_traffic_control_status,
    pbs_admin_verify_jobs_list,
    pbs_node_config_get,
    pbs_node_config_set,
    pbs_node_identity,
    pbs_node_report,
    pbs_node_rrd,
    pbs_pull,
    pbs_push,
    pbs_version,
)
from proximo.tools.pbs_datastore_admin import (  # noqa: E402,F401
    pbs_datastore_active_operations,
    pbs_datastore_mount,
    pbs_datastore_prune,
    pbs_datastore_rrd,
    pbs_datastore_s3_refresh,
    pbs_datastore_unmount,
    pbs_datastores_usage,
    pbs_group_delete,
    pbs_group_move,
    pbs_group_notes_get,
    pbs_group_notes_set,
    pbs_groups_list,
    pbs_namespace_move,
    pbs_remote_scan,
    pbs_remote_scan_groups,
    pbs_remote_scan_namespaces,
    pbs_snapshot_protected_get,
)
from proximo.tools.pbs_disks import (  # noqa: E402,F401
    pbs_node_disk_directory_create,
    pbs_node_disk_directory_delete,
    pbs_node_disk_directory_list,
    pbs_node_disk_initgpt,
    pbs_node_disk_smart,
    pbs_node_disk_wipe,
    pbs_node_disk_zfs_create,
    pbs_node_disk_zfs_get,
    pbs_node_disk_zfs_list,
    pbs_node_disks_list,
)
from proximo.tools.pbs_metrics import (  # noqa: E402,F401
    pbs_metrics_influxdb_http_create,
    pbs_metrics_influxdb_http_delete,
    pbs_metrics_influxdb_http_get,
    pbs_metrics_influxdb_http_list,
    pbs_metrics_influxdb_http_update,
    pbs_metrics_influxdb_udp_create,
    pbs_metrics_influxdb_udp_delete,
    pbs_metrics_influxdb_udp_get,
    pbs_metrics_influxdb_udp_list,
    pbs_metrics_influxdb_udp_update,
    pbs_metrics_servers_list,
    pbs_metrics_status,
)
from proximo.tools.pbs_node import (  # noqa: E402,F401
    pbs_node_cert_delete,
    pbs_node_cert_upload,
    pbs_node_certificates_list,
    pbs_node_dns_get,
    pbs_node_dns_set,
    pbs_node_journal,
    pbs_node_network_iface_create,
    pbs_node_network_iface_delete,
    pbs_node_network_iface_get,
    pbs_node_network_iface_update,
    pbs_node_network_list,
    pbs_node_network_reload,
    pbs_node_network_revert,
    pbs_node_service_control,
    pbs_node_service_status,
    pbs_node_services_list,
    pbs_node_status,
    pbs_node_subscription_check,
    pbs_node_subscription_delete,
    pbs_node_subscription_get,
    pbs_node_subscription_set,
    pbs_node_syslog,
    pbs_node_task_log,
    pbs_node_task_status,
    pbs_node_task_stop,
    pbs_node_time_get,
    pbs_node_time_set,
)
from proximo.tools.pbs_notifications import (  # noqa: E402,F401
    pbs_notification_endpoint_create,
    pbs_notification_endpoint_delete,
    pbs_notification_endpoint_get,
    pbs_notification_endpoint_list,
    pbs_notification_endpoint_update,
    pbs_notification_matcher_delete,
    pbs_notification_matcher_field_values,
    pbs_notification_matcher_fields,
    pbs_notification_matcher_get,
    pbs_notification_matcher_set,
    pbs_notification_matchers_list,
    pbs_notification_target_test,
    pbs_notification_targets_list,
)
from proximo.tools.pbs_s3 import (  # noqa: E402,F401
    pbs_encryption_key_create,
    pbs_encryption_key_delete,
    pbs_encryption_key_list,
    pbs_encryption_key_toggle_archive,
    pbs_s3_check,
    pbs_s3_client_create,
    pbs_s3_client_delete,
    pbs_s3_client_get,
    pbs_s3_client_list,
    pbs_s3_client_update,
    pbs_s3_list_buckets,
    pbs_s3_reset_counters,
)
from proximo.tools.pbs_tape_config import (  # noqa: E402,F401
    pbs_tape_changer_create,
    pbs_tape_changer_delete,
    pbs_tape_changer_get,
    pbs_tape_changer_list,
    pbs_tape_changer_update,
    pbs_tape_drive_create,
    pbs_tape_drive_delete,
    pbs_tape_drive_get,
    pbs_tape_drive_list,
    pbs_tape_drive_update,
    pbs_tape_scan_changers,
    pbs_tape_scan_drives,
)
from proximo.tools.pbs_tape_jobs import (  # noqa: E402,F401
    pbs_tape_backup,
    pbs_tape_backup_job_create,
    pbs_tape_backup_job_delete,
    pbs_tape_backup_job_get,
    pbs_tape_backup_job_list,
    pbs_tape_backup_job_run,
    pbs_tape_backup_job_update,
    pbs_tape_media_content,
    pbs_tape_media_destroy,
    pbs_tape_media_list,
    pbs_tape_media_move,
    pbs_tape_media_sets,
    pbs_tape_media_status_get,
    pbs_tape_media_status_set,
    pbs_tape_restore,
)
from proximo.tools.pbs_tape_media import (  # noqa: E402,F401
    pbs_tape_key_create,
    pbs_tape_key_delete,
    pbs_tape_key_get,
    pbs_tape_key_list,
    pbs_tape_key_update_password,
    pbs_tape_pool_create,
    pbs_tape_pool_delete,
    pbs_tape_pool_get,
    pbs_tape_pool_list,
    pbs_tape_pool_update,
)
from proximo.tools.pbs_tape_ops import (  # noqa: E402,F401
    pbs_tape_changer_status,
    pbs_tape_changer_transfer,
    pbs_tape_drive_barcode_label_media,
    pbs_tape_drive_cartridge_memory,
    pbs_tape_drive_catalog,
    pbs_tape_drive_clean,
    pbs_tape_drive_eject,
    pbs_tape_drive_format,
    pbs_tape_drive_inventory,
    pbs_tape_drive_inventory_update,
    pbs_tape_drive_label_media,
    pbs_tape_drive_load_media,
    pbs_tape_drive_load_slot,
    pbs_tape_drive_read_label,
    pbs_tape_drive_restore_key,
    pbs_tape_drive_rewind,
    pbs_tape_drive_status,
    pbs_tape_drive_unload,
    pbs_tape_drive_volume_statistics,
)
from proximo.tools.pdm import (  # noqa: E402,F401
    pdm_acl_list,
    pdm_node_status,
    pdm_pbs_datastores_list,
    pdm_pbs_remote_status,
    pdm_pbs_snapshots_list,
    pdm_ping,
    pdm_pve_cluster_status,
    pdm_pve_lxc_config,
    pdm_pve_lxc_list,
    pdm_pve_node_list,
    pdm_pve_qemu_config,
    pdm_pve_qemu_list,
    pdm_pve_resources,
    pdm_remote_config_get,
    pdm_remote_version,
    pdm_remotes_list,
    pdm_resources_list,
    pdm_resources_status,
    pdm_roles_list,
    pdm_tasks_list,
    pdm_users_list,
    pdm_version,
)
from proximo.tools.pdm_fleet import (  # noqa: E402,F401
    pdm_pve_lxc_migrate,
    pdm_pve_lxc_power,
    pdm_pve_lxc_remote_migrate,
    pdm_pve_lxc_snapshot_create,
    pdm_pve_lxc_snapshot_delete,
    pdm_pve_lxc_snapshot_rollback,
    pdm_pve_qemu_migrate,
    pdm_pve_qemu_power,
    pdm_pve_qemu_remote_migrate,
    pdm_pve_qemu_snapshot_create,
    pdm_pve_qemu_snapshot_delete,
    pdm_pve_qemu_snapshot_rollback,
)
from proximo.tools.pmg_apt import (  # noqa: E402,F401
    pmg_apt_changelog,
    pmg_apt_repositories_get,
    pmg_apt_repository_add,
    pmg_apt_repository_set,
    pmg_apt_update_refresh,
    pmg_apt_updates_list,
    pmg_apt_versions,
)
from proximo.tools.pmg_identity import (  # noqa: E402,F401
    pmg_access_realm_create,
    pmg_access_realm_delete,
    pmg_access_realm_get,
    pmg_access_realm_list,
    pmg_access_realm_update,
    pmg_access_tfa_add,
    pmg_access_tfa_delete,
    pmg_access_tfa_get,
    pmg_access_tfa_list,
    pmg_access_tfa_update,
    pmg_access_tfa_user_list,
    pmg_access_user_create,
    pmg_access_user_delete,
    pmg_access_user_get,
    pmg_access_user_unlock_tfa,
    pmg_access_user_update,
    pmg_cluster_create,
    pmg_cluster_join,
    pmg_cluster_join_info,
    pmg_cluster_node_add,
    pmg_cluster_nodes_list,
    pmg_cluster_status,
    pmg_cluster_update_fingerprints,
    pmg_config_admin_get,
    pmg_config_admin_update,
    pmg_config_clamav_get,
    pmg_config_clamav_update,
    pmg_config_mail_update,
    pmg_config_spamquar_get,
    pmg_config_spamquar_update,
    pmg_config_tfa_webauthn_get,
    pmg_config_tfa_webauthn_update,
    pmg_config_virusquar_get,
    pmg_config_virusquar_update,
)
from proximo.tools.pmg_mail import (  # noqa: E402,F401
    pmg_acme_account_create,
    pmg_acme_account_delete,
    pmg_acme_account_get,
    pmg_acme_account_list,
    pmg_acme_account_update,
    pmg_acme_challenge_schema,
    pmg_acme_directories,
    pmg_acme_meta,
    pmg_acme_plugin_create,
    pmg_acme_plugin_delete,
    pmg_acme_plugin_get,
    pmg_acme_plugin_list,
    pmg_acme_plugin_update,
    pmg_acme_tos,
    pmg_action_objects_list,
    pmg_backup_create,
    pmg_customscores_apply,
    pmg_customscores_create,
    pmg_customscores_delete,
    pmg_customscores_get,
    pmg_customscores_list,
    pmg_customscores_revert_all,
    pmg_customscores_update,
    pmg_dkim_domain_create,
    pmg_dkim_domain_delete,
    pmg_dkim_domain_get,
    pmg_dkim_domain_update,
    pmg_dkim_domains_list,
    pmg_dkim_selector_generate,
    pmg_dkim_selector_get,
    pmg_dkim_selectors_list,
    pmg_doctor,
    pmg_domain_create,
    pmg_domain_delete,
    pmg_domain_get,
    pmg_domain_update,
    pmg_domains_list,
    pmg_fetchmail_create,
    pmg_fetchmail_delete,
    pmg_fetchmail_get,
    pmg_fetchmail_list,
    pmg_fetchmail_update,
    pmg_ldap_group_members_get,
    pmg_ldap_groups_list,
    pmg_ldap_profile_config_get,
    pmg_ldap_profile_config_update,
    pmg_ldap_profile_create,
    pmg_ldap_profile_delete,
    pmg_ldap_profile_sync,
    pmg_ldap_profiles_list,
    pmg_ldap_user_emails_get,
    pmg_ldap_users_list,
    pmg_mimetypes_list,
    pmg_mynetworks_add,
    pmg_mynetworks_get,
    pmg_mynetworks_list,
    pmg_mynetworks_remove,
    pmg_mynetworks_update,
    pmg_node_cert_acme_order,
    pmg_node_cert_acme_renew,
    pmg_node_cert_acme_revoke,
    pmg_node_cert_custom_delete,
    pmg_node_cert_custom_upload,
    pmg_node_pbs_jobs_list,
    pmg_node_pbs_snapshot_create,
    pmg_node_pbs_snapshot_forget,
    pmg_node_pbs_snapshot_get,
    pmg_node_pbs_snapshot_restore,
    pmg_node_pbs_snapshot_verify,
    pmg_node_pbs_snapshots_list,
    pmg_node_pbs_timer_create,
    pmg_node_pbs_timer_delete,
    pmg_node_pbs_timer_get,
    pmg_node_rrddata,
    pmg_node_status,
    pmg_node_syslog,
    pmg_pbs_remote_create,
    pmg_pbs_remote_delete,
    pmg_pbs_remote_get,
    pmg_pbs_remote_list,
    pmg_pbs_remote_update,
    pmg_postfix_flush,
    pmg_postfix_qshape,
    pmg_quarantine_action,
    pmg_quarantine_attachment,
    pmg_quarantine_attachments_list,
    pmg_quarantine_blocklist_add,
    pmg_quarantine_blocklist_list,
    pmg_quarantine_blocklist_remove,
    pmg_quarantine_content_get,
    pmg_quarantine_link_get,
    pmg_quarantine_sendlink,
    pmg_quarantine_spam,
    pmg_quarantine_spamstatus,
    pmg_quarantine_spamusers,
    pmg_quarantine_users_list,
    pmg_quarantine_virus,
    pmg_quarantine_virusstatus,
    pmg_quarantine_welcomelist_add,
    pmg_quarantine_welcomelist_list,
    pmg_quarantine_welcomelist_remove,
    pmg_regextest,
    pmg_relay_config,
    pmg_ruledb_digest,
    pmg_ruledb_rule_actions_list,
    pmg_ruledb_rule_from_list,
    pmg_ruledb_rule_get,
    pmg_ruledb_rule_to_list,
    pmg_ruledb_rule_what_list,
    pmg_ruledb_rule_when_list,
    pmg_ruledb_rules_list,
    pmg_service_control,
    pmg_service_status,
    pmg_spam_config,
    pmg_spam_config_update,
    pmg_statistics_contact,
    pmg_statistics_detail,
    pmg_statistics_domains,
    pmg_statistics_mail,
    pmg_statistics_mailcount,
    pmg_statistics_maildistribution,
    pmg_statistics_receiver,
    pmg_statistics_recent,
    pmg_statistics_recentreceivers,
    pmg_statistics_recentsenders,
    pmg_statistics_rejectcount,
    pmg_statistics_sender,
    pmg_statistics_spamscores,
    pmg_statistics_virus,
    pmg_tasks_list,
    pmg_tls_inbound_domains_create,
    pmg_tls_inbound_domains_delete,
    pmg_tls_inbound_domains_list,
    pmg_tlspolicy_create,
    pmg_tlspolicy_delete,
    pmg_tlspolicy_get,
    pmg_tlspolicy_list,
    pmg_tlspolicy_update,
    pmg_tracker_detail,
    pmg_tracker_list,
    pmg_transport_create,
    pmg_transport_delete,
    pmg_transport_get,
    pmg_transport_list,
    pmg_transport_update,
    pmg_what_group_get,
    pmg_what_group_objects,
    pmg_what_groups_list,
    pmg_when_group_get,
    pmg_when_group_objects,
    pmg_when_groups_list,
    pmg_who_group_get,
    pmg_who_group_objects,
    pmg_who_groups_list,
)
from proximo.tools.pmg_node import (  # noqa: E402,F401
    pmg_node_backup_delete,
    pmg_node_backup_list,
    pmg_node_backup_restore,
    pmg_node_certificates_info,
    pmg_node_clamav_database_get,
    pmg_node_clamav_database_update,
    pmg_node_config_get,
    pmg_node_config_set,
    pmg_node_dns_get,
    pmg_node_dns_set,
    pmg_node_journal,
    pmg_node_network_create,
    pmg_node_network_delete,
    pmg_node_network_get,
    pmg_node_network_list,
    pmg_node_network_reload,
    pmg_node_network_revert,
    pmg_node_network_update,
    pmg_node_postfix_discard_verify_cache,
    pmg_node_postfix_queue_action,
    pmg_node_postfix_queue_delete_all,
    pmg_node_postfix_queue_delete_queue,
    pmg_node_postfix_queue_list,
    pmg_node_postfix_queue_message_delete,
    pmg_node_postfix_queue_message_deliver,
    pmg_node_postfix_queue_message_get,
    pmg_node_report,
    pmg_node_service_reload,
    pmg_node_service_restart,
    pmg_node_service_start,
    pmg_node_service_stop,
    pmg_node_services_list,
    pmg_node_spamassassin_rules_get,
    pmg_node_spamassassin_rules_update,
    pmg_node_subscription_check,
    pmg_node_subscription_delete,
    pmg_node_subscription_get,
    pmg_node_subscription_set,
    pmg_node_task_log,
    pmg_node_task_status,
    pmg_node_task_stop,
    pmg_node_time_get,
    pmg_node_time_set,
)
from proximo.tools.pmg_rules import (  # noqa: E402,F401
    pmg_action_bcc_create,
    pmg_action_bcc_get,
    pmg_action_bcc_update,
    pmg_action_delete,
    pmg_action_disclaimer_create,
    pmg_action_disclaimer_get,
    pmg_action_disclaimer_update,
    pmg_action_field_create,
    pmg_action_field_get,
    pmg_action_field_update,
    pmg_action_notification_create,
    pmg_action_notification_get,
    pmg_action_notification_update,
    pmg_action_removeattachments_create,
    pmg_action_removeattachments_get,
    pmg_action_removeattachments_update,
    pmg_ruledb_reset,
    pmg_ruledb_rule_action_attach,
    pmg_ruledb_rule_action_detach,
    pmg_ruledb_rule_action_groups_list,
    pmg_ruledb_rule_create,
    pmg_ruledb_rule_delete,
    pmg_ruledb_rule_from_attach,
    pmg_ruledb_rule_from_detach,
    pmg_ruledb_rule_to_attach,
    pmg_ruledb_rule_to_detach,
    pmg_ruledb_rule_update,
    pmg_ruledb_rule_what_attach,
    pmg_ruledb_rule_what_detach,
    pmg_ruledb_rule_when_attach,
    pmg_ruledb_rule_when_detach,
    pmg_what_group_create,
    pmg_what_group_delete,
    pmg_what_group_update,
    pmg_what_object_add,
    pmg_what_object_delete,
    pmg_what_object_get,
    pmg_what_object_update,
    pmg_when_group_create,
    pmg_when_group_delete,
    pmg_when_group_update,
    pmg_when_object_add,
    pmg_when_object_delete,
    pmg_when_object_get,
    pmg_when_object_update,
    pmg_who_group_create,
    pmg_who_group_delete,
    pmg_who_group_update,
    pmg_who_object_add,
    pmg_who_object_delete,
    pmg_who_object_get,
    pmg_who_object_update,
)
from proximo.tools.pmg_welcomelist import (  # noqa: E402,F401
    pmg_welcomelist_object_add,
    pmg_welcomelist_object_delete,
    pmg_welcomelist_object_get,
    pmg_welcomelist_object_update,
    pmg_welcomelist_objects_list,
)
from proximo.tools.pve_access import (  # noqa: E402,F401
    pve_acl_list,
    pve_acl_modify,
    pve_acl_prune,
    pve_group_create,
    pve_group_delete,
    pve_group_get,
    pve_group_update,
    pve_groups_list,
    pve_overbroad_grants,
    pve_realm_create,
    pve_realm_delete,
    pve_realm_get,
    pve_realm_update,
    pve_realms_list,
    pve_role_create,
    pve_role_delete,
    pve_role_update,
    pve_roles_list,
    pve_tfa_delete,
    pve_tfa_get,
    pve_tfa_list,
    pve_token_create,
    pve_token_revoke,
    pve_tokens_list,
    pve_user_create,
    pve_user_delete,
    pve_user_get,
    pve_user_update,
    pve_users_list,
)
from proximo.tools.pve_agent import (  # noqa: E402,F401
    pve_agent_file_read,
    pve_agent_file_write,
    pve_agent_fs,
    pve_agent_info,
    pve_agent_set_password,
)
from proximo.tools.pve_apt import (  # noqa: E402,F401
    pve_apt_changelog,
    pve_apt_repositories_get,
    pve_apt_repository_add,
    pve_apt_repository_set,
    pve_apt_update_refresh,
    pve_apt_updates_list,
    pve_apt_versions,
)
from proximo.tools.pve_backup import (  # noqa: E402,F401
    pbs_job_create,
    pbs_job_delete,
    pbs_job_run,
    pbs_job_update,
    pbs_realm_sync,
    pve_backup,
    pve_backup_delete,
    pve_backup_freshness,
    pve_backup_job_create,
    pve_backup_job_delete,
    pve_backup_job_list,
    pve_backup_job_update,
    pve_backup_list,
    pve_replication_create,
    pve_replication_delete,
    pve_replication_update,
    pve_restore,
)
from proximo.tools.pve_ceph import (  # noqa: E402,F401
    pve_ceph_cfg_db,
    pve_ceph_cfg_raw,
    pve_ceph_cfg_value,
    pve_ceph_cmd_safety,
    pve_ceph_crush,
    pve_ceph_flag_get,
    pve_ceph_flag_set,
    pve_ceph_flags_list,
    pve_ceph_flags_set,
    pve_ceph_fs_create,
    pve_ceph_fs_destroy,
    pve_ceph_fs_list,
    pve_ceph_init,
    pve_ceph_log,
    pve_ceph_mds_create,
    pve_ceph_mds_destroy,
    pve_ceph_mds_list,
    pve_ceph_metadata,
    pve_ceph_mgr_create,
    pve_ceph_mgr_destroy,
    pve_ceph_mgr_list,
    pve_ceph_mon_create,
    pve_ceph_mon_destroy,
    pve_ceph_mon_list,
    pve_ceph_osd_create,
    pve_ceph_osd_destroy,
    pve_ceph_osd_in,
    pve_ceph_osd_lv_info,
    pve_ceph_osd_metadata,
    pve_ceph_osd_out,
    pve_ceph_osd_scrub,
    pve_ceph_osd_tree,
    pve_ceph_pool_create,
    pve_ceph_pool_destroy,
    pve_ceph_pool_list,
    pve_ceph_pool_set,
    pve_ceph_pool_status,
    pve_ceph_rules,
    pve_ceph_service_restart,
    pve_ceph_service_start,
    pve_ceph_service_stop,
    pve_ceph_status,
)
from proximo.tools.pve_certs import (  # noqa: E402,F401
    pve_acme_account_create,
    pve_acme_account_delete,
    pve_acme_account_update,
    pve_acme_cert_order,
    pve_acme_cert_renew,
    pve_acme_cert_revoke,
    pve_acme_plugin_create,
    pve_acme_plugin_delete,
    pve_acme_plugin_update,
    pve_node_acme_domains_set,
)
from proximo.tools.pve_cluster import (  # noqa: E402,F401
    pve_cluster_resources,
    pve_cluster_status,
    pve_guest_migrate,
    pve_ha_groups_list,
    pve_ha_resource_add,
    pve_ha_resource_remove,
    pve_ha_resources_list,
    pve_ha_rule_create,
    pve_ha_rule_delete,
    pve_ha_rule_update,
    pve_ha_rules_list,
    pve_pool_create,
    pve_pool_delete,
    pve_pool_get,
    pve_pool_update,
    pve_pools_list,
    pve_storage_config_get,
    pve_storage_config_list,
    pve_storage_create,
    pve_storage_delete,
    pve_storage_update,
    pve_task_log,
    pve_task_stop,
    pve_task_wait,
    pve_tasks_list,
)
from proximo.tools.pve_firewall import (  # noqa: E402,F401
    pve_firewall_alias_create,
    pve_firewall_alias_delete,
    pve_firewall_alias_list,
    pve_firewall_alias_update,
    pve_firewall_ipset_create,
    pve_firewall_ipset_delete,
    pve_firewall_ipset_entry_add,
    pve_firewall_ipset_entry_remove,
    pve_firewall_options_get,
    pve_firewall_options_set,
    pve_firewall_rule_add,
    pve_firewall_rule_remove,
    pve_firewall_rule_update,
    pve_firewall_rules_list,
    pve_firewall_security_group_create,
    pve_firewall_security_group_delete,
    pve_firewall_set_enabled,
    pve_ipset_list,
    pve_security_groups_list,
)
from proximo.tools.pve_guest import (  # noqa: E402,F401
    ct_diagnose,
    ct_logs,
    pve_clone,
    pve_cloudinit_get,
    pve_cloudinit_set,
    pve_create_container,
    pve_create_vm,
    pve_delete_guest,
    pve_diagnose,
    pve_disk_move,
    pve_disk_resize,
    pve_doctor,
    pve_guest_config_get,
    pve_guest_config_revert,
    pve_guest_config_set,
    pve_guest_power,
    pve_guest_status,
    pve_list_guests,
    pve_node_status,
    pve_rollback,
    pve_snapshot_create,
    pve_snapshot_delete,
    pve_snapshot_list,
    pve_storage_content,
    pve_storage_content_delete,
    pve_storage_download,
    pve_storage_status,
    pve_task_status,
    pve_template_convert,
)
from proximo.tools.pve_network import (  # noqa: E402,F401
    pve_network_apply,
    pve_network_iface_create,
    pve_network_iface_update,
    pve_network_list,
    pve_sdn_apply,
    pve_sdn_dry_run,
    pve_sdn_lock_acquire,
    pve_sdn_lock_release,
    pve_sdn_rollback,
    pve_sdn_subnet_create,
    pve_sdn_subnet_delete,
    pve_sdn_subnet_get,
    pve_sdn_subnet_list,
    pve_sdn_subnet_update,
    pve_sdn_vnet_create,
    pve_sdn_vnet_delete,
    pve_sdn_vnet_get,
    pve_sdn_vnet_mac_vrf,
    pve_sdn_vnet_update,
    pve_sdn_vnets_list,
    pve_sdn_zone_bridges,
    pve_sdn_zone_content,
    pve_sdn_zone_create,
    pve_sdn_zone_delete,
    pve_sdn_zone_get,
    pve_sdn_zone_ip_vrf,
    pve_sdn_zone_status_list,
    pve_sdn_zone_update,
    pve_sdn_zones_list,
)
from proximo.tools.pve_node import (  # noqa: E402,F401
    pve_node_cert_delete,
    pve_node_cert_upload,
    pve_node_disk_initgpt,
    pve_node_disk_smart,
    pve_node_disk_wipe,
    pve_node_disks_list,
    pve_node_dns_set,
    pve_node_hosts_get,
    pve_node_hosts_set,
    pve_node_migrateall,
    pve_node_startall,
    pve_node_stopall,
    pve_node_storage_backend_create,
    pve_node_storage_backend_delete,
    pve_node_storage_backend_list,
    pve_node_time_get,
    pve_node_time_set,
)
from proximo.tools.pve_observability import (  # noqa: E402,F401
    pve_hardware_list,
    pve_mapping_pci_create,
    pve_mapping_pci_delete,
    pve_mapping_pci_list,
    pve_mapping_pci_update,
    pve_mapping_usb_create,
    pve_mapping_usb_delete,
    pve_mapping_usb_list,
    pve_mapping_usb_update,
    pve_metrics_server_delete,
    pve_metrics_server_list,
    pve_metrics_server_set,
    pve_node_certificates,
    pve_node_dns,
    pve_node_journal,
    pve_node_rrddata,
    pve_node_service_control,
    pve_node_service_status,
    pve_node_services_list,
    pve_node_subscription,
    pve_node_syslog,
    pve_notification_endpoint_create,
    pve_notification_endpoint_delete,
    pve_notification_endpoint_list,
    pve_notification_endpoint_update,
    pve_notification_matcher_delete,
    pve_notification_matcher_set,
    pve_notification_test,
)
from proximo.tools.pve_sdn_fabrics import (  # noqa: E402,F401
    pve_sdn_fabric_create,
    pve_sdn_fabric_delete,
    pve_sdn_fabric_get,
    pve_sdn_fabric_node_create,
    pve_sdn_fabric_node_delete,
    pve_sdn_fabric_node_get,
    pve_sdn_fabric_node_update,
    pve_sdn_fabric_nodes_list,
    pve_sdn_fabric_nodes_list_all,
    pve_sdn_fabric_status_interfaces,
    pve_sdn_fabric_status_neighbors,
    pve_sdn_fabric_status_routes,
    pve_sdn_fabric_update,
    pve_sdn_fabrics_all,
    pve_sdn_fabrics_list,
)
from proximo.tools.pve_sdn_firewall import (  # noqa: E402,F401
    pve_sdn_vnet_firewall_options_get,
    pve_sdn_vnet_firewall_options_set,
    pve_sdn_vnet_firewall_rule_add,
    pve_sdn_vnet_firewall_rule_get,
    pve_sdn_vnet_firewall_rule_remove,
    pve_sdn_vnet_firewall_rule_update,
    pve_sdn_vnet_firewall_rules_list,
    pve_sdn_vnet_ip_create,
    pve_sdn_vnet_ip_delete,
    pve_sdn_vnet_ip_update,
)
from proximo.tools.pve_sdn_objects import (  # noqa: E402,F401
    pve_sdn_controller_create,
    pve_sdn_controller_delete,
    pve_sdn_controller_get,
    pve_sdn_controller_update,
    pve_sdn_controllers_list,
    pve_sdn_dns_create,
    pve_sdn_dns_delete,
    pve_sdn_dns_get,
    pve_sdn_dns_list,
    pve_sdn_dns_update,
    pve_sdn_ipam_create,
    pve_sdn_ipam_delete,
    pve_sdn_ipam_get,
    pve_sdn_ipam_status,
    pve_sdn_ipam_update,
    pve_sdn_ipams_list,
)
from proximo.tools.pve_sdn_routing import (  # noqa: E402,F401
    pve_sdn_prefix_list_create,
    pve_sdn_prefix_list_delete,
    pve_sdn_prefix_list_entries_list,
    pve_sdn_prefix_list_entry_create,
    pve_sdn_prefix_list_entry_delete,
    pve_sdn_prefix_list_entry_get,
    pve_sdn_prefix_list_entry_update,
    pve_sdn_prefix_list_get,
    pve_sdn_prefix_list_update,
    pve_sdn_prefix_lists_list,
    pve_sdn_route_map_entries_list,
    pve_sdn_route_map_entries_list_all,
    pve_sdn_route_map_entry_create,
    pve_sdn_route_map_entry_delete,
    pve_sdn_route_map_entry_get,
    pve_sdn_route_map_entry_update,
    pve_sdn_route_maps_list,
)
from proximo.tools.wiki_tools import (  # noqa: E402,F401
    proximo_wiki,
    proximo_wiki_read,
)

# Every tool is registered by now (registration is an import side effect of the blocks above), so
# this is the first point where the whole surface can be slimmed in one pass. Import-time, not
# main()-time, so embedders and the test suite see the same payload the stdio server serves.
_slim_registry_schemas()

# The escape hatch's dispatch source, frozen here: every decorator has fired and no scoping layer
# has run. AFTER slimming, deliberately — the snapshot holds references to the same Tool objects,
# so a caller reaching a tool by name gets the same slimmed schema tools/list would have shown.
_snapshot_full_catalog()


# H1: a direct tools/call for a NON-resident name would otherwise dead-end on the SDK's bare
# "Unknown tool: X" (tool_manager raises it, the wire layer turns it into an error result) —
# no did-you-mean, no pointer to proximo_call. On the dynamic default door only the ~6 facade tools
# are resident, so an agent naming a real tool directly, or fabricating a verb-order variant, lands
# exactly here. A dead-end error is what makes an agent fabricate the NEXT wrong name; give it a
# recoverable pointer instead. Per major: on 1.x, re-registering the CallToolRequest handler below
# is last-write-wins over FastMCP's own (resident tools still dispatch through FastMCP's original
# handler unchanged). On 2.x the same WIRE outcome is built into the server at construction —
# _mcpcompat.make_server returns a subclass whose public call_tool override raises the pointer for
# non-resident names (the wire's _handle_call_tool awaits that public method), so there is nothing
# to re-register here. The IN-PROCESS mcp.call_tool differs by major for non-residents (1.x: the
# SDK's own ToolError; 2.x: the pointer) — scope + pin in _mcpcompat.make_server's docstring.
if MCP_MAJOR == 1:
    _fastmcp_call_tool = mcp.call_tool  # FastMCP's own handler (bound), captured before we replace it

    @mcp._mcp_server.call_tool(validate_input=False)  # match FastMCP's own registration flag
    async def _proximo_call_tool(name: str, arguments: dict):
        if name not in mcp._tool_manager._tools:
            raise ProximoError(_unknown_tool_error(name))
        return await _fastmcp_call_tool(name, arguments)


if __name__ == "__main__":
    main()
