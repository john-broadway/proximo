"""The operator's env file, sourced once at a door's entry.

A daemon gets `proximo.env` from systemd's `EnvironmentFile`; a stdio door sees only the MCP
client's inline `env` block, and a shell door sees the shell. The documented place for an
operator's `PROXIMO_*` settings is `~/.config/proximo/proximo.env` (`PROXIMO_ENV_FILE` to point
elsewhere), and a door that does not read it is fail-DANGEROUS for a gate set there (`PROXIMO_FORBID`,
an arm source, the audit log path): the operator believes the gate stands, the door never saw it.
The 0.44 commands sourced the file; at the default-command swap (2026-10-17) the core doors took
that over, with the same contract:

- only `PROXIMO_*` keys, never PATH or a loader variable: the file configures Proximo, not the process;
- only keys the process environment does NOT already hold: the real or inline env always wins, so an
  inline-config deployment is unaffected;
- a key the environment holds with a DIFFERENT value is named as SHADOWED on stderr (the key, never
  the value): that line in the file is dead, and an operator editing it gets nothing. An allowlist
  (`PROXIMO_CT_ALLOWLIST`, `PROXIMO_AGENT_ALLOWLIST`) is compared as the grant the core parses, so a
  reordered or differently spaced list of the same ids is NOT a difference; `source` tells an
  allowlist refusal which store fed the value;
- a missing file is a silent no-op; an unreadable one is one stderr line.

Stdlib only.
"""
from __future__ import annotations

import os
import sys

DEFAULT_PATH = "~/.config/proximo/proximo.env"
PATH_ENV = "PROXIMO_ENV_FILE"


def parse(lines: list[str]) -> dict[str, str]:
    """`KEY=value` lines, `export` and matching surrounding quotes stripped, comments and blanks
    skipped, PROXIMO_ keys only."""
    out: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        if key.startswith("PROXIMO_"):
            out[key] = val
    return out


def _fresh_state() -> dict[str, set[str]]:
    return {"loaded": set(), "shadowed": set(), "same": set()}


# What the last `load` saw, per key: filled from the file, shadowed by a different value, or held by
# both with the same value. Keys only, never a value or a path: a refusal reads it to say where an
# allowlist came from (`source`).
_STATE: dict[str, set[str]] = _fresh_state()


def _allowlist_keys() -> frozenset[str]:
    from proximo.core import spine  # noqa: PLC0415  (spine is the parser's home; no import cycle at load)
    return frozenset({spine.SHELL_ALLOWLIST_ENV, spine.AGENT_ALLOWLIST_ENV})


def differs(key: str, env_value: str, file_value: str) -> bool:
    """Whether the environment's value for `key` really differs from the file's copy. An allowlist
    compares as the grant the core would parse (a reordered list of the same ids, or the same ids
    spaced differently, is the SAME grant: calling it shadowed sends the operator to hunt a change
    that is not there); every other key compares as text. The parser is the core's own."""
    if key in _allowlist_keys():
        from proximo.core import spine  # noqa: PLC0415
        return spine._parse_allowlist(env_value) != spine._parse_allowlist(file_value)
    return env_value != file_value


def source(key: str) -> str:
    """Where `key`'s effective value came from, as of the last `load`, in words an operator can act
    on and with no path or value in them. A restart applies any edit: the value is read at launch."""
    if key in _STATE["loaded"]:
        where = "the env file"
    elif key in _STATE["shadowed"]:
        where = ("the process environment; the copy in the env file is SHADOWED (it holds a different "
                 "grant) and is never read")
    elif key in _STATE["same"]:
        where = "the process environment (the env file holds the same grant)"
    elif key in os.environ:
        where = "the process environment"
    else:
        where = "nowhere: it is unset, so the allowlist is empty (deny-all)"
    return where


def load(*, announce: bool = True, prog: str = "proximo") -> tuple[list[str], list[str]]:
    """Source the file into `os.environ` for the keys it does not hold; return (loaded, shadowed)
    where shadowed names the keys the environment holds with a different value. `announce=False`
    keeps stderr clean for the verbs whose stderr is a pinned contract (badge, mint)."""
    path = os.environ.get(PATH_ENV) or os.path.expanduser(DEFAULT_PATH)
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
        return [], []
    except OSError as e:
        print(f"{prog}: could not read env file {path!r}: {e}", file=sys.stderr)
        return [], []
    loaded: list[str] = []
    shadowed: list[str] = []
    _STATE.update(_fresh_state())
    for key, val in parse(lines).items():
        if key in os.environ:
            if differs(key, os.environ[key], val):
                shadowed.append(key)
                _STATE["shadowed"].add(key)
            else:
                _STATE["same"].add(key)
            continue
        os.environ[key] = val
        loaded.append(key)
        _STATE["loaded"].add(key)
    if announce and loaded:
        print(f"{prog}: loaded {len(loaded)} setting(s) from {path}: {', '.join(sorted(loaded))}", file=sys.stderr)
    if announce and shadowed:
        print(f"{prog}: {len(shadowed)} key(s) in {path} SHADOWED by the process environment and NOT applied: "
              f"{', '.join(sorted(shadowed))}. The process environment wins; edit that, then restart.",
              file=sys.stderr)
    return loaded, shadowed
