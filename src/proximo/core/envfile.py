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
  the value): that line in the file is dead, and an operator editing it gets nothing;
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
    for key, val in parse(lines).items():
        if key in os.environ:
            if os.environ[key] != val:
                shadowed.append(key)
            continue
        os.environ[key] = val
        loaded.append(key)
    if announce and loaded:
        print(f"{prog}: loaded {len(loaded)} setting(s) from {path}: {', '.join(sorted(loaded))}", file=sys.stderr)
    if announce and shadowed:
        print(f"{prog}: {len(shadowed)} key(s) in {path} SHADOWED by the process environment and NOT applied: "
              f"{', '.join(sorted(shadowed))}. The process environment wins; edit that, then restart.",
              file=sys.stderr)
    return loaded, shadowed
