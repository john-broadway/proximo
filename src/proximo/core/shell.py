"""The container shell wire: `pct exec` over ssh, with the HTTP client's shape (B5, 2026-10-03).

The vendor publishes no REST address for running a command inside a container, so 0.44 shelled
out beside the API path. The core keeps ONE governed path: `records/shell.toml` authors the calls
as rows of the one JSON, govern and the pillars treat them like any other, and only the wire differs.
`ShellClient.call(method, path, params)` answers the call `engine.execute` makes of every client.

What this wire adds over 0.44's:
- non-interactive ssh (`BatchMode`, `ConnectTimeout`): a password prompt can no longer hang a call;
- THE SPLIT-TARGET GUARD: the remote first checks that the host it reached IS the path's `{node}`.
  0.44 shelled to one `PROXIMO_SSH_TARGET` whatever node the caller meant, and a lab session found
  on 2026-09-04 that it would land in a production container while every API read said "lab".
  Here the mismatch exits SPLIT_EXIT before `pct` runs, and the call is refused naming both hosts.
- no default target: unset is a refusal, never a fallback to a production alias;
- every stream bounded by the one cap (`rawdoor.bounded`): the core never caps a mutation's answer.
"""
from __future__ import annotations

import errno
import json
import os
import re
import secrets
import shlex
import subprocess
from typing import Any

from proximo.core import rawdoor
from proximo.core.errors import ProximoError

TARGET_ENV = "PROXIMO_SSH_TARGET"
TIMEOUT = 60
# The operator's wait for one shell call (#106): whole seconds, 1 to MAX_TIMEOUT (the task wait's own cap).
TIMEOUT_ENV = "PROXIMO_SHELL_TIMEOUT"
MAX_TIMEOUT = 600
_SECONDS = re.compile(r"[0-9]{1,4}\Z", re.ASCII)
SPLIT_EXIT = 254                        # ours: the host is not the path's node, nothing ran
SSH_EXIT = 255                          # ssh's own failure, never the command's
SSH_OPTS = ("-o", "BatchMode=yes", "-o", "ConnectTimeout=10")
# An ssh destination, never an option: a leading `-` would be read as `-oProxyCommand=...`.
_TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]*\Z")
_NODE_PATTERN = r"[A-Za-z0-9][A-Za-z0-9.-]*"
_NODE = re.compile(_NODE_PATTERN + r"\Z")
_PATH = re.compile(r"/nodes/(?P<node>" + _NODE_PATTERN
                   + r")(?:/lxc/(?P<vmid>[0-9]+))?/(?P<op>exec|psql|logs|probe)\Z")   # ASCII digits, as pct reads
_HOST_OPS = frozenset({"probe"})         # the host lane reads its fixed battery; it runs nothing else
_UNIT = re.compile(r"[A-Za-z0-9@_:.][A-Za-z0-9@_:.-]*\Z")
MAX_LINES = 1000
# DIAGNOSE's in-container battery (B3), 0.44's `backends.CONTAINER_PROBES` verbatim: the argv is
# fixed HERE and a caller names a KEY, never argv, so the probe row cannot express a mutation.
PROBES: dict[str, tuple[str, ...]] = {
    "failed_units": ("systemctl", "--failed", "--no-legend", "--no-pager"),
    "disk": ("df", "-h"),
    "recent_errors": ("journalctl", "-p", "err", "-n", "40", "--no-pager"),
    "memory": ("free", "-m"),
    "listening": ("ss", "-tlnp"),
}
# The HOST's battery (the node shell lane), 0.44's `backends.NODE_PROBES` verbatim. There is
# deliberately no free-argv host exec, as in 0.44: the metal's mutation lane stays undoored.
NODE_PROBES: dict[str, tuple[str, ...]] = {
    "failed_units": ("systemctl", "--failed", "--no-legend", "--no-pager"),
    "pve_services": ("systemctl", "list-units", "--no-legend", "--no-pager",
                     "pveproxy.service", "pvedaemon.service", "pve-cluster.service",
                     "pvestatd.service", "pvescheduler.service"),
    "recent_errors": ("journalctl", "-p", "err", "-n", "40", "--no-pager"),
    "disk": ("df", "-h"),
    "memory": ("free", "-m"),
    "versions": ("pveversion", "-v"),
    "cluster": ("pvecm", "status"),
}


def _run(argv: list[str], timeout: int) -> tuple[int, str, str]:
    """The ONE place a process is spawned, so a test can stand a recorder here and be sure nothing
    else does. argv is a list: no local shell ever parses it."""
    done = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout, check=False)  # noqa: S603 a list argv, no shell; the remote half is shlex-quoted
    return done.returncode, done.stdout, done.stderr


def target() -> str:
    t = os.environ.get(TARGET_ENV, "")
    if not t:
        raise ProximoError(f"{TARGET_ENV} is not set; the shell lanes have no host to reach "
                           "(there is no default: name the ssh alias of the node)")
    if not valid_destination(t):
        raise ProximoError(f"{TARGET_ENV} is not an ssh destination (letters, digits, . _ @ -, not "
                           "starting with -); refused before anything dials")
    return t


def valid_destination(value: str) -> bool:
    """A plain OpenSSH destination, never an option or shell fragment."""
    return _TARGET.fullmatch(value) is not None


def valid_node(value: str) -> bool:
    """A node component accepted by the concrete shell path grammar."""
    return _NODE.fullmatch(value) is not None


def resolve_target(cfg: Any = None, path: str | None = None) -> str:
    """Resolve a shell path to its SSH destination without creating a client or dialing."""
    name = getattr(cfg, "name", None)
    if not name:
        return target()
    match = _match(path or "")
    if match is None:
        raise ProximoError(f"target {name!r} needs a concrete shell path with a PVE node")
    node = match["node"]
    nodes = dict(getattr(cfg, "nodes", ()))
    if node not in nodes:
        raise ProximoError(f"target {name!r} has no SSH destination mapped for node {node!r}; "
                           "add it under [targets.<name>.nodes]")
    destination = nodes[node]
    if not valid_destination(destination):
        # Plane is frozen, but fail closed if a caller constructed one outside the registry loader.
        raise ProximoError(f"target {name!r} has an unsafe SSH destination for node {node!r}")
    return destination


def timeout() -> int:
    """The wait `PROXIMO_SHELL_TIMEOUT` names, or TIMEOUT when it is unset or empty. Set to anything but whole
    seconds from 1 to MAX_TIMEOUT, every shell call refuses: a wait the operator did not mean is never guessed,
    and the value is not echoed."""
    raw = os.environ.get(TIMEOUT_ENV, "").strip()
    if not raw:
        return TIMEOUT
    if not _SECONDS.match(raw) or not 1 <= int(raw) <= MAX_TIMEOUT:
        raise ProximoError(f"{TIMEOUT_ENV} must be whole seconds from 1 to {MAX_TIMEOUT}; "
                           "refused before anything dials")
    return int(raw)


def timeout_report() -> tuple[int | None, list[str]]:
    """For the doctor: the effective wait and no flag, or None and the one flag sentence (never the value)."""
    try:
        return timeout(), []
    except ProximoError:
        return None, [f"the shell timeout is garbled: {TIMEOUT_ENV} is not whole seconds from 1 to "
                      f"{MAX_TIMEOUT}, so every shell call refuses"]


def client(cfg: Any = None, *, path: str | None = None) -> ShellClient:
    """Build the existing single-destination SSH client for this concrete path, with the operator's wait."""
    return ShellClient(resolve_target(cfg, path), timeout())


def _match(path: str) -> re.Match | None:
    m = _PATH.match(path or "")
    return m if m is not None and (m["vmid"] is not None or m["op"] in _HOST_OPS) else None


def dialable(path: str) -> bool:
    """Whether a concrete path is one this wire can dial; the table's load asks it of every row."""
    return _match(path) is not None


def lane_of(path: str) -> str:
    """The opt-in lane of a shell row by its own shape: inside a container, or the host itself."""
    return "shell" if "/lxc/" in path else "node"


def argv_for(op: str, params: dict[str, Any], host: bool = False) -> list[str]:
    """The command run inside the container (or, `host`, by the node itself), as a list. Shapes are 0.44's."""
    if op == "exec":
        cmd = params.get("command")
        if isinstance(cmd, str):              # the shell door's k=v: a JSON array is still an argv
            try:
                cmd = json.loads(cmd)
            except ValueError:
                cmd = None
        if not isinstance(cmd, list) or not cmd or not all(isinstance(a, str) for a in cmd):
            raise ProximoError("exec: `command` is an argv list of strings, not a shell string")
        return list(cmd)
    if op == "psql":
        sql, db = params.get("sql"), params.get("db", "postgres")
        if not isinstance(sql, str) or not sql.strip():
            raise ProximoError("psql: `sql` is required")
        if not isinstance(db, str) or not db:
            raise ProximoError("psql: `db` must be a database name")
        inner = f"psql -d {shlex.quote(db)} -v ON_ERROR_STOP=1 -c {shlex.quote(sql)}"
        return ["su", "postgres", "-c", inner]
    if op == "logs":
        unit, lines = params.get("unit"), params.get("lines", 50)
        if not isinstance(unit, str) or not _UNIT.match(unit):
            raise ProximoError("logs: `unit` must be a systemd unit name (letters, digits, @ _ : . -, "
                               "not starting with -)")
        if isinstance(lines, bool) or not isinstance(lines, int) or not 1 <= lines <= MAX_LINES:
            raise ProximoError(f"logs: `lines` must be a whole number from 1 to {MAX_LINES}")
        return ["journalctl", "-u", unit, "-n", str(lines), "--no-pager"]
    if op == "probe":
        fixed = NODE_PROBES if host else PROBES
        key = params.get("probe")
        if not isinstance(key, str) or key not in fixed:
            raise ProximoError(f"probe: `probe` is one of the fixed battery: {', '.join(fixed)}")
        return list(fixed[key])
    raise ProximoError(f"{op!r} is not a container shell operation")


class ShellClient:
    """`call(method, path, params)` over ssh. `path` is the CONCRETE address govern judged."""

    def __init__(self, ssh_target: str, timeout: int = TIMEOUT) -> None:
        self.target, self.timeout = ssh_target, timeout

    def remote(self, node: str, vmid: str | None, argv: list[str], split: str, ran: str) -> str:
        """The host-side script. Two per-call markers make the outcome unforgeable: `pct exec`
        passes the container command's own exit code through, so 254 or 255 alone cannot tell
        "our guard refused" or "ssh failed" from "the command exited 254"; a container process
        cannot see the host's command line, so it cannot print a marker it was never shown. With no
        `vmid` the host runs the argv itself, after the same guard (the node shell lane)."""
        run = f"pct exec {vmid} -- {shlex.join(argv)}" if vmid is not None else shlex.join(argv)
        return (f'test "$(hostname)" = {shlex.quote(node)} || {{ echo "proximo-split-{split} $(hostname)" >&2; '
                f"exit {SPLIT_EXIT}; }}; echo proximo-ran-{ran} >&2; exec {run}")

    def call(self, method: str, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        m = _match(path)
        if m is None:
            raise ProximoError(f"{method} {path} is not a shell address")
        node, vmid, op = m["node"], m["vmid"], m["op"]
        where = f"container {vmid}" if vmid is not None else f"node {node}"
        split, ran = secrets.token_hex(16), secrets.token_hex(16)
        remote = self.remote(node, vmid, argv_for(op, dict(params or {}), host=vmid is None), split, ran)
        try:
            rc, out, err = _run(["ssh", *SSH_OPTS, self.target, remote], self.timeout)
        except subprocess.TimeoutExpired:
            raise ProximoError(f"no answer from {self.target} within {self.timeout}s; the command on "
                               f"{where} may still be running") from None
        except (OSError, ValueError) as exc:
            # Raised by the spawn itself (no ssh, no permission, a NUL in argv, argv too long): ssh
            # never started, so nothing ran. Any other OSError came after ssh started (communicate).
            if isinstance(exc, (FileNotFoundError, PermissionError, ValueError)) or exc.errno == errno.E2BIG:
                raise ProximoError(f"ssh to {self.target} could not be started ({type(exc).__name__}); "
                                   f"nothing ran on {where}") from None
            raise ProximoError(f"the ssh session to {self.target} failed after it started ({type(exc).__name__}); "
                               f"the command on {where} may have run, outcome unknown") from None
        mark = f"proximo-ran-{ran}\n"
        if mark in err:     # the guard passed and pct was started: rc is the command's own
            # Before the marker: ssh's or the host's own lines (a known_hosts notice, an rc file).
            # After it: the command's stderr. Only this call's marker splits them.
            err = err.split(mark, 1)[1]
        elif rc == SPLIT_EXIT and f"proximo-split-{split} " in err:
            host = err.split(f"proximo-split-{split} ", 1)[1].split("\n", 1)[0].strip()[:64]
            raise ProximoError(f"the ssh target {self.target} answers as {host!r}, not node {node}; "
                               f"nothing ran")
        elif rc == SSH_EXIT:
            # ssh's stderr names hosts, keys and paths, and nothing ran, so there is no receipt row
            # to hold it: the text is DROPPED, not relocated. The operator reproduces it with the
            # same ssh line; a REST or A2A caller reading this answer does not get it.
            raise ProximoError(f"ssh to {self.target} failed before the command ran (exit {rc})")
        else:
            raise ProximoError(f"the host behind {self.target} did not start the command (exit {rc}); "
                               f"nothing ran on {where}")
        result: dict[str, Any] = {"returncode": rc, "stdout": out, "stderr": err}
        if rc == SSH_EXIT:   # past the ran marker: the command's own 255, or ssh cut off mid-run
            result["exit_ambiguous"] = ("255 is also ssh's own exit: the command started, and either it "
                                        "exited 255 or the connection dropped before it finished")
        return _bounded(result)


#: bytes and tokens a mutation's answer spends beside its data: header, undo capture, intent
ENVELOPE_ROOM = (450, 160)


def _bounded(result: dict[str, Any]) -> dict[str, Any]:
    """The one cap (PROXIMO_RAW_MAX_BYTES), split between the two streams, so the exit code always
    survives and each stream says when it was cut (`truncated`: its original length). The core never
    caps a mutation's answer, so the wire does; `rawdoor.bounded` would fold the code into a head."""
    # THE ENVELOPE IS SPENT FIRST: this result rides in an answer with a header (address, tier, undo ...),
    # so the streams get the cap less what that costs, or the answer would be cut again at the door.
    room = rawdoor.answer_cap().minus(*ENVELOPE_ROOM)
    if rawdoor.bounded(result, room) is None:
        return result
    per = max(room.bytes // 2 - 128, 0)
    per_tokens = None if room.tokens is None else max(room.tokens // 2 - 64, 0)

    def over(text: str) -> bool:
        """Past its half in bytes, or (when a token cap is on) in estimated tokens: command output
        is the densest text the door returns (hashes, addresses, escapes)."""
        enc = json.dumps(text)
        return len(enc) > per or (per_tokens is not None and rawdoor.estimate_tokens(enc) > per_tokens)

    out, cut = dict(result), {}
    for name in ("stdout", "stderr"):
        s = result[name]
        if over(s):
            cut[name] = len(s)
            while s and over(s):
                s = s[: max(int(len(s) * 0.85) - 1, 0)]
            out[name] = s
    out["truncated"] = cut
    return out
