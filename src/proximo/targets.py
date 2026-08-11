"""Native multi-target: a registry of named Proxmox remotes + per-call target selection.

One Proximo instance can address many boxes (PVE/PBS/PMG/PDM, internal or external).
A target is selected per call via the `proximo_target` tool parameter; the selection rides
a ContextVar so the four plane resolvers — and every internal helper that re-resolves —
auto-route to the same box. No target => the env-configured box (`from_env`), unchanged.
"""
from __future__ import annotations

import contextvars
import functools
import inspect
import os
import tomllib
from functools import lru_cache
from typing import Annotated, get_args, get_origin

from pydantic import BeforeValidator, Field

from .backends import ProximoError

# Params that name a Proxmox object ID. Their descriptions say "Numeric VMID/CTID", so an agent
# naturally sends the int `100` — but they are typed `str` (a VMID is an opaque token that must
# never be arithmetic'd), and pydantic v2 REJECTS an int for a `str` field before any body runs,
# costing a wasted round-trip per call. A BeforeValidator coerces int -> str at the boundary, so
# the natural int call is accepted and every tool body still receives the str it already expects.
# Injected once here (target_aware wraps every plane tool), not edited into ~48 wrappers.
_ID_PARAM_NAMES = frozenset({"vmid", "ctid"})


def _coerce_object_id(v):
    return str(v) if isinstance(v, int) else v


def _with_id_coercion(annotation):
    """Add the int->str BeforeValidator to a vmid/ctid param's annotation, preserving its existing
    Annotated metadata (the Field description) and its base `str` type (so the schema is unchanged
    and the description still reads Numeric — the runtime just stops rejecting the int)."""
    if get_origin(annotation) is Annotated:
        base, *meta = get_args(annotation)
        return Annotated[(base, BeforeValidator(_coerce_object_id), *meta)]
    return Annotated[annotation, BeforeValidator(_coerce_object_id)]

VALID_KINDS = frozenset({"pve", "pbs", "pmg", "pdm"})

# Per-call active target. None => the env-configured default box.
_active_target: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "proximo_active_target", default=None
)


def active_target() -> str | None:
    return _active_target.get()


def ledger_remote() -> str | None:
    """The value recorded in the PROVE ledger's `remote` field (None on the default path)."""
    return _active_target.get()


@lru_cache(maxsize=16)
def _parse_registry(path: str, mtime: float) -> dict[str, dict]:
    """Parse + validate one registry file. Cached by (path, mtime) — re-reads when the file
    changes. Exceptions are NOT cached, so a malformed file re-raises on each call."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        raise ProximoError(f"PROXIMO_TARGETS is not valid TOML ({path}): {e}") from e
    targets = data.get("targets", {})
    if not isinstance(targets, dict):
        raise ProximoError("PROXIMO_TARGETS: [targets] must be a table of named remotes")
    for name, fields in targets.items():
        if not isinstance(fields, dict):
            raise ProximoError(f"PROXIMO_TARGETS: target {name!r} must be a table")
        kind = fields.get("kind")
        if kind not in VALID_KINDS:
            raise ProximoError(
                f"PROXIMO_TARGETS: target {name!r} has unknown kind {kind!r} "
                f"(valid: {sorted(VALID_KINDS)})"
            )
    return targets


def load_registry() -> dict[str, dict]:
    """Parse PROXIMO_TARGETS into {name: fields}. Empty dict when unset. Fail-loud otherwise."""
    path = os.environ.get("PROXIMO_TARGETS")
    if not path:
        return {}
    try:
        mtime = os.path.getmtime(path)
    except OSError as e:
        raise ProximoError(f"PROXIMO_TARGETS points to a missing file: {path}") from e
    return _parse_registry(path, mtime)


def resolve_target_fields(name: str, expected_kind: str) -> dict:
    """Look up `name`, asserting it is of `expected_kind`. Fail-loud on every miss."""
    reg = load_registry()
    if not reg:
        raise ProximoError(
            f"no target registry configured (set PROXIMO_TARGETS); cannot resolve target {name!r}"
        )
    if name not in reg:
        raise ProximoError(f"unknown target {name!r}")  # don't enumerate the registry to callers
    fields = reg[name]
    kind = fields.get("kind")
    if kind != expected_kind:
        raise ProximoError(
            f"target {name!r} is kind {kind!r}, not usable by a {expected_kind.upper()} tool"
        )
    return fields


# Real type object (NOT a string) so FastMCP's inspect.signature(..., eval_str=True) is a no-op for it.
# The Field description propagates into EVERY target-aware tool's input schema at once — without it,
# `proximo_target` shows up undocumented on ~all multi-target tools (0% schema coverage).
#
# KEEP IT SHORT. This string is duplicated onto ~900 tools, so its cost to a client's context is
# its length x the whole surface: the original 374-char version spent ~84k tokens of the tools/list
# payload restating the same paragraph, more than a third of all schema bytes. One clause is the
# budget (tests/test_schema_budget.py). The long-form explanation lives in docs/SETUP.md, which is
# read once by a human, instead of ~900 times by a model.
_TARGET_DESC = "Configured target name to run against; omit for the default box."
_TARGET_PARAM = inspect.Parameter(
    "proximo_target",
    inspect.Parameter.KEYWORD_ONLY,
    default=None,
    annotation=Annotated[str | None, Field(description=_TARGET_DESC)],
)


def target_aware(fn):
    """Wrap a tool so it advertises `proximo_target` and routes the call to that box.

    The wrapped fn's body is untouched: it still calls `_svc()` etc., which read the contextvar.
    """
    @functools.wraps(fn)
    def wrapper(*args, proximo_target: str | None = None, **kwargs):
        token = _active_target.set(proximo_target)
        try:
            return fn(*args, **kwargs)
        finally:
            _active_target.reset(token)

    sig = inspect.signature(fn)
    params = list(sig.parameters.values())
    insert_at = len(params)
    for i, p in enumerate(params):
        if p.kind is inspect.Parameter.VAR_KEYWORD:
            insert_at = i
            break
        # Widen a vmid/ctid param so pydantic coerces an int argument to str instead of rejecting
        # it (see _with_id_coercion). Keyed on the param NAME, so it never touches an unrelated str.
        if p.name in _ID_PARAM_NAMES and p.annotation is not inspect.Parameter.empty:
            params[i] = p.replace(annotation=_with_id_coercion(p.annotation))
    params.insert(insert_at, _TARGET_PARAM)
    wrapper.__signature__ = sig.replace(parameters=params)  # type: ignore[attr-defined]
    return wrapper
