"""The target registry, read by the core: one Proximo, many boxes (parity row B16, multi-target).

`PROXIMO_TARGETS` names a TOML file of `[targets.<name>]` tables, each a box of one `kind` (pve,
pbs, pmg, pdm) with its `base_url`, its secret by path, its arm pair and its envelope. 0.44 read
it in `proximo.targets` and routed a call with a context variable; the core reads it HERE and the
doors hand the engine a `wire.Plane` built from the entry, explicitly, per call. The engine already
governs a Plane (its own arm pair, its forbid added to the floor, its rate against the env's with
the tightest winning, its name on every receipt as `remote`, undo refusing a capture taken on
another box), so a target is one argument at the door and nothing new in the engine.

Moved, not copied: `proximo.targets` and `proximo.envelope` import these names, so 0.44 and the
core read one parser and one box-rate rule. Stdlib only (the core's closure is httpx and nothing
else), and an error here never names the registry's path or a secret's: since the REST and A2A
doors, a ProximoError's text reaches a network caller. An unknown name is not told what exists.
"""
from __future__ import annotations

import os
import tomllib
from functools import lru_cache

from proximo.core import spine, wire
from proximo.core.errors import ProximoError

VALID_KINDS = frozenset({"pve", "pbs", "pmg", "pdm"})
ENV = "PROXIMO_TARGETS"


@lru_cache(maxsize=16)
def _parse_registry(path: str, mtime: float) -> dict[str, dict]:
    """Parse and validate one registry file. Cached by (path, mtime): it re-reads when the file
    changes. Exceptions are NOT cached, so a malformed file re-raises on each call."""
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        # The registry's path is the operator's; a REST or A2A caller reading this error is not.
        raise ProximoError(f"{ENV} is not valid TOML: {e}") from e
    except (OSError, UnicodeDecodeError) as e:
        # A directory, a file this process cannot open, bytes that are not text (lens 3): a
        # refusal in the door's words, by kind, never a traceback carrying the path.
        raise ProximoError(f"{ENV} could not be read as a registry ({type(e).__name__})") from e
    targets = data.get("targets", {})
    if not isinstance(targets, dict):
        raise ProximoError(f"{ENV}: [targets] must be a table of named remotes")
    for name, fields in targets.items():
        if not isinstance(fields, dict):
            raise ProximoError(f"{ENV}: target {name!r} must be a table")
        kind = fields.get("kind")
        if kind not in VALID_KINDS:
            raise ProximoError(f"{ENV}: target {name!r} has unknown kind {kind!r} "
                               f"(valid: {sorted(VALID_KINDS)})")
    return targets


def load_registry() -> dict[str, dict]:
    """{name: fields} from PROXIMO_TARGETS. Empty when unset; loud when set and unreadable."""
    path = os.environ.get(ENV)
    if not path:
        return {}
    try:
        mtime = os.path.getmtime(path)
    except OSError as e:
        raise ProximoError(f"{ENV} points to a file this process cannot read") from e
    return _parse_registry(path, mtime)


def resolve_target_fields(name: str, expected_kind: str) -> dict:
    """The entry named `name`, asserting it is of `expected_kind`. Loud on every miss, and an
    unknown name is never answered with the names that do exist."""
    reg = load_registry()
    if not reg:
        raise ProximoError(f"no target registry configured (set {ENV}); cannot resolve target {name!r}")
    if name not in reg:
        raise ProximoError(f"unknown target {name!r}")
    fields = reg[name]
    kind = fields.get("kind")
    if kind != expected_kind:
        raise ProximoError(f"target {name!r} is kind {kind!r}, not usable by a {expected_kind.upper()} tool")
    return fields


def normalize_base_url(value: object) -> str | None:
    """A box's identity: a non-empty string, stripped, its trailing slash trimmed; else None."""
    if not isinstance(value, str) or not value:
        return None
    return value.strip().rstrip("/")


def rate_candidate(max_raw: object, window_raw: object) -> tuple[int | None, int, bool]:
    """One (rate_max, rate_window) pair: (max, window or the default, garbled). A window that
    parses to 0 or less is garbled: every slot would read as expired and the cap never engage."""
    rmax, mg = spine._parse_int(max_raw)
    rwin, wg = spine._parse_int(window_raw)
    garbled = mg or wg or (rwin is not None and rwin <= 0)
    return rmax, (rwin if rwin is not None else spine._RATE_WINDOW_DEFAULT), garbled


def box_rate(base_url: str | None) -> tuple[int | None, int]:
    """The TIGHTEST (rate_max, rate_window) declared for the box at `base_url`, across the env box
    (when its own base_url is this one) and every registry entry at the same base_url: a second
    name for one box is not a second budget (0.44's name-swap evasion, closed). A garbled pair on
    any of them collapses the box to (0, default). An unknown box while a cap is declared anywhere
    is refused the same way; only when nothing declares a cap is an unknown box uncapped (None)."""
    default = spine._RATE_WINDOW_DEFAULT
    candidates: list[tuple[int, int]] = []
    garbled = any_declared = False
    env_max, env_win = os.environ.get(spine.RATE_MAX_ENV), os.environ.get(spine.RATE_WINDOW_ENV)
    if env_max or env_win:
        any_declared = True
        if base_url is not None and normalize_base_url(os.environ.get("PROXIMO_API_BASE_URL")) == base_url:
            rmax, rwin, bad = rate_candidate(env_max, env_win)
            garbled = garbled or bad
            if not bad and rmax is not None:
                candidates.append((rmax, rwin))
    for fields in load_registry().values():
        if not isinstance(fields, dict) or ("rate_max" not in fields and "rate_window" not in fields):
            continue
        any_declared = True
        if base_url is None or normalize_base_url(fields.get("base_url")) != base_url:
            continue
        rmax, rwin, bad = rate_candidate(fields.get("rate_max"), fields.get("rate_window"))
        garbled = garbled or bad
        if not bad and rmax is not None:
            candidates.append((rmax, rwin))
    if garbled:
        return 0, default
    if base_url is None:
        return (0, default) if any_declared else (None, default)
    if not candidates:
        return None, default
    # The tightest by EFFECTIVE sustained rate (max/window), a longer window breaking a tie: a
    # 10-per-second ceiling must not beat a 500-per-day budget on the same box.
    return min(candidates, key=lambda c: (c[0] / c[1], -c[1]))


def plane(product: str, name: str | None) -> wire.Plane | None:
    """The Plane a door hands the engine for `target=name` on `product`, or None for the env box.

    The entry is resolved by the plane's kind (a pbs target is not a pve box), its rate is the
    BOX's (`box_rate` at its base_url), and every refusal is said without the secret's path."""
    if name is None:
        return None
    if not isinstance(name, str) or not name.strip():
        raise ProximoError("target must be a registered target's name")
    fields = resolve_target_fields(name, product)
    rate_max, rate_window = box_rate(normalize_base_url(fields.get("base_url")))
    try:
        return wire.plane_from_target(product, name, {**fields, "rate_max": rate_max, "rate_window": rate_window})
    except ProximoError:
        raise
    except RuntimeError as e:
        # The one RuntimeError on this path is the secret-file check: a file other users can read.
        # Its own text names the path, and the answer may be a network caller's; say the fix.
        raise ProximoError(f"target {name!r} is not usable: the secret file its registry entry names "
                           f"is readable by other users on this box (chmod 600 it)") from e
