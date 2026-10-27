"""The off-box anchor: PROVE's head, pinned where this box cannot rewrite it, and read back.

The ledger's hash chain catches an edited, inserted, reordered or removed INTERIOR row. A cut or
wiped TAIL leaves a chain that verifies clean on its own. Only a head pinned somewhere the writer
cannot reach sees that, and the manual pin (`audit_verify(expected_head=...)`,
`PROXIMO_AUDIT_EXPECTED_HEAD`) leaves the copying to a human. 0.44's `audit_anchor.py` automated
it; the 0.45 cut dropped it with its wrappers ("no core mechanism"), and this restores it in the
core's idiom: opt-in by env, inert when unset, and once set, anything that prevents PROVING the
tail reads as refused.

    PROXIMO_AUDIT_ANCHOR_SINK       file | http | none (unset is none)
    PROXIMO_AUDIT_ANCHOR_FILE_PATH  the file sink: a path the operator keeps out of the agent's reach
    PROXIMO_AUDIT_ANCHOR_URL        the http sink: PUT stores the pin, GET reads it, 404 is empty
    PROXIMO_AUDIT_ANCHOR_TOKEN_PATH an optional bearer token for the http sink, read by PATH
    PROXIMO_AUDIT_ANCHOR_CA_BUNDLE  an optional private CA for an https sink
    PROXIMO_AUDIT_ANCHOR_INTERVAL   seconds between publishes, default 60; 0 publishes every write
    PROXIMO_AUDIT_ANCHOR_REARM      1 lets ONE publish into an EMPTY sink of a ledger that was anchored
                                    before (the operator's act; unset it again afterwards)

WHEN. After a ledger write (the instance ledger `open_ledger` hands out), at most once per
interval: first by a small state file beside the ledger (not a security boundary: it only saves
the network round trip, so the shell door, one short process per call, does not fetch the pin on
every call), then by the age of the pin itself, which holds across hosts. Interval 0 publishes on
every write and so reads the sink and walks the whole chain each time: O(N) in the ledger's rows
per write. Use it for a small ledger or a test, not a busy one. Every sink call (read or write)
has a TOTAL wall-clock deadline and a 4 KB cap on what it will read, so a receiver that trickles or
floods cannot hold or fatten a ledger write; the http client trusts no proxy environment variable
and follows no redirect. The file sink writes the pin 0600, atomically (temp file, fsync, rename),
and fsyncs the directory after the rename. A publish failure NEVER fails
the call that wrote the row. It shows as the anchor reading `unreachable`, `empty` or `stale` in
`audit_verify` and in doctor's PROVE station, which read the sink back themselves.

THE PIN ONLY MOVES FORWARD ALONG A CHAIN THAT STILL HOLDS IT. 0.44 learned this late: a design
that publishes the head on every write lets an attacker cut the tail, wait for the next honest
row, and have the anchor vouch for the cut chain for good. Here a publish first reads the pin and
walks the whole chain (every HMAC); it publishes only when the chain verifies, holds the pinned
row, and has more rows than the pin recorded. Otherwise the pin is left alone and the anchor reads
`diverged`. A pin that has VANISHED is the same threat (a transient 404, a wiped store, or an
attacker's delete, then one honest write on a cut chain), so the first successful publish writes an
`audit_anchor` row into the ledger, and a ledger holding that row never publishes into an empty
sink: the anchor reads `empty` until the operator re-arms with PROXIMO_AUDIT_ANCHOR_REARM=1, which
lets one publish through (and records a second `audit_anchor` row saying so). Re-anchoring after a
deliberate rotation is likewise the operator's act, never a side effect of a write or a verify.

WHAT IT PROVES, which is what the env pin proves: the anchored head is a row the chain must still
HOLD. A cut below it, a wipe and a replaced file fail. Rows after it pass but are NOT verified:
`unwatched_rows` says how many and `note` says so in a sentence (a cut that stays above the pinned
row reads ok), and `tail_verified` is true only when the anchored head IS the chain's head.
The rows inside the publish interval, and a PUT that races a second writer, are the named
limits; detection is the guarantee, not prevention, and the sink must be less compromisable than
this box or the anchor is a comfort. Proximo cannot prove that for you.

NOT RESTORED from 0.44: the syslog and journal sinks. They were write-only witnesses that could
never be read back, so they could not make `audit_verify` refuse; a collector-side comparison is
the operator's. `file` and `http` are the sinks that can be proven against.

No path, URL or secret is ever in an answer: stations report state and counts, never where
(the doctor's law). Errors here are fixed phrases that name an env VARIABLE, never its value.
stdlib only, plus the httpx the core already depends on (imported when an http sink is used).
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import tempfile
import threading
import time
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urlsplit

from proximo.core.errors import ProximoError
from proximo.core.ledger import (
    GENESIS_HASH,
    AuditLedger,
    ledger_key,
    looks_like_head,
    parse_lines,
    read_log,
    verify_lines,
)
from proximo.core.secretfile import safe_text

ENV_SINK = "PROXIMO_AUDIT_ANCHOR_SINK"
ENV_FILE = "PROXIMO_AUDIT_ANCHOR_FILE_PATH"
ENV_URL = "PROXIMO_AUDIT_ANCHOR_URL"
ENV_TOKEN = "PROXIMO_AUDIT_ANCHOR_TOKEN_PATH"  # noqa: S105 -- the NAME of a variable that holds a path
ENV_CA = "PROXIMO_AUDIT_ANCHOR_CA_BUNDLE"
ENV_INTERVAL = "PROXIMO_AUDIT_ANCHOR_INTERVAL"
ENV_REARM = "PROXIMO_AUDIT_ANCHOR_REARM"
ANCHOR_ACTION = "audit_anchor"

DEFAULT_INTERVAL = 60
#: A pin that is not the chain's head and is older than this many intervals (floored) is STALE:
#: either nothing has been publishing, or nothing could.
STALE_INTERVALS, STALE_FLOOR = 10, 600
#: A pin is one small JSON object. Anything larger is not a pin.
_MAX_PIN_BYTES = 4096
_HTTP_TIMEOUT = 3.0
#: The TOTAL wall-clock a sink call may take, however slowly the far end sends.
_DEADLINE = 5.0
#: Test seam: the clock.
_clock = time.time
_publishing = False


class AnchorError(Exception):
    """The sink could not be published to or read. The text is a fixed phrase: no path, URL or
    secret (the sink's own exception text is never carried)."""


def _validate(raw: bytes) -> dict[str, Any]:
    """The one read path every sink shares: bytes to a pin, or AnchorError."""
    if len(raw) > _MAX_PIN_BYTES:
        raise AnchorError("the sink holds something larger than a pin")
    try:
        pin = json.loads(raw)
        head, at, entries = pin["head"], pin["at"], pin["entries"]
    except (ValueError, KeyError, TypeError, RecursionError):
        raise AnchorError("the sink's pin is corrupt or incomplete") from None
    if not isinstance(head, str) or not looks_like_head(head) or head == GENESIS_HASH:
        raise AnchorError("the sink's pin holds a malformed head")
    if (type(at) is not int or type(entries) is not int or entries < 1 or at < 0):
        raise AnchorError("the sink's pin holds a malformed field")
    return {"head": head, "at": at, "entries": entries}


class Sink(ABC):
    @abstractmethod
    def fetch(self) -> dict[str, Any] | None:
        """The pin, or None when the sink is reachable and empty. AnchorError otherwise."""

    @abstractmethod
    def publish(self, pin: dict[str, Any]) -> None:
        """Store the pin, replacing any. AnchorError on any failure."""


class FileSink(Sink):
    """A path the operator keeps beyond the agent's reach (a mount this box writes but cannot
    rewrite, a root-owned directory). Written atomically so a reader never sees half a pin."""

    def __init__(self, path: str):
        self._path = os.path.expanduser(path)

    def fetch(self) -> dict[str, Any] | None:
        directory = os.path.dirname(self._path) or "."
        if not os.path.isdir(directory):
            raise AnchorError("the file sink's directory is not there")
        try:
            with open(self._path, "rb") as f:
                raw = f.read(_MAX_PIN_BYTES + 1)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise AnchorError(f"the file sink cannot be read ({type(exc).__name__})") from None
        return _validate(raw)

    def publish(self, pin: dict[str, Any]) -> None:
        directory = os.path.dirname(self._path) or "."
        tmp: str | None = None
        try:
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".proximo-anchor-")   # 0600
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(pin, f, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._path)
            tmp = None
            dfd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(dfd)          # the rename itself must survive a crash
            finally:
                os.close(dfd)
        except OSError as exc:
            raise AnchorError(f"the file sink cannot be written ({type(exc).__name__})") from None
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass


class HttpSink(Sink):
    """One resource on a receiver the operator names, ideally another host: GET answers the
    stored body (404 when empty), PUT stores it. A redirect is NOT followed: a pin store that
    moves is a tamper signal. No proxy variable is honoured: a proxy could answer for the sink."""

    def __init__(self, url: str, token_path: str | None, ca_bundle: str | None):
        self._url, self._token_path, self._ca = url, token_path, ca_bundle

    def _client(self):
        import httpx  # noqa: PLC0415 -- only when an http sink is configured

        from proximo.core.tls import httpx_verify  # noqa: PLC0415
        verify: Any = True
        if self._ca:
            try:
                verify = httpx_verify(self._ca)
            except (OSError, ValueError):
                raise AnchorError("the CA bundle could not be loaded") from None
        return httpx.Client(verify=verify, timeout=_HTTP_TIMEOUT, follow_redirects=False, trust_env=False)

    def _headers(self) -> dict[str, str]:
        if not self._token_path:
            return {}
        from proximo.core.secretfile import read_secret  # noqa: PLC0415
        try:
            token = read_secret(self._token_path, "anchor bearer token file", floor=True)
        except Exception:  # noqa: BLE001 -- the floor's own text names the path; say only that it failed
            raise AnchorError("the token file is unreadable or exposed") from None
        if not token:
            raise AnchorError("the token file is empty")
        return {"Authorization": f"Bearer {token}"}

    def _call(self, method: str, body: dict[str, Any] | None, read_body: bool) -> tuple[int, bytes]:
        """One request under a TOTAL deadline. A worker thread does the I/O and the caller waits at
        most `_DEADLINE`; the worker streams the answer, stops at the size cap and at its own
        deadline, so a trickle or a flood ends instead of piling up behind an abandoned call."""
        out: dict[str, Any] = {}

        def work() -> None:
            import httpx  # noqa: PLC0415
            deadline = time.monotonic() + _DEADLINE
            try:
                headers = self._headers()
                with self._client() as c, c.stream(method, self._url, headers=headers, json=body) as r:
                    buf = bytearray()
                    if read_body and r.status_code == 200:
                        for chunk in r.iter_bytes():
                            buf += chunk
                            if len(buf) > _MAX_PIN_BYTES:
                                raise AnchorError("the sink holds something larger than a pin")
                            if time.monotonic() > deadline:
                                raise AnchorError("the http sink did not finish answering in time")
                    out["v"] = (r.status_code, bytes(buf))
            except AnchorError as exc:
                out["e"] = exc
            except httpx.HTTPError as exc:
                out["e"] = AnchorError(f"the http sink cannot be reached ({type(exc).__name__})")
            except Exception as exc:  # noqa: BLE001 -- whatever it was, the sink did not answer
                out["e"] = AnchorError(f"the http sink failed ({type(exc).__name__})")

        t = threading.Thread(target=work, daemon=True, name="proximo-anchor")
        t.start()
        t.join(_DEADLINE)
        if t.is_alive():
            raise AnchorError("the http sink did not answer in time")
        if "e" in out:
            raise out["e"]
        return out["v"]

    def fetch(self) -> dict[str, Any] | None:
        status, raw = self._call("GET", None, True)
        if status == 404:
            return None
        if status != 200:
            raise AnchorError(f"the http sink answered {status} to a read")
        return _validate(raw)

    def publish(self, pin: dict[str, Any]) -> None:
        status, _ = self._call("PUT", pin, False)
        if status not in (200, 201, 204):
            raise AnchorError(f"the http sink answered {status} to a write")


class Anchor:
    """A configured anchor: a sink and an interval, or `problem` saying why it cannot be built
    (and then every verify refuses, since a switch set that cannot be honoured proves nothing)."""

    def __init__(self, sink: Sink | None, interval: int, identity: str, problem: str | None = None):
        self.sink, self.interval, self.identity, self.problem = sink, interval, identity, problem

    @property
    def stale_after(self) -> int:
        return max(STALE_INTERVALS * self.interval, STALE_FLOOR)

    # -- publish -----------------------------------------------------------------------------

    def after_write(self, ledger: AuditLedger) -> None:
        """Called after a ledger write. Never raises, never blocks the write beyond the sink's
        own short timeout; every failure shows later as the anchor's state."""
        if self.sink is None:
            return
        try:
            self._publish_if_due(self.sink, ledger)
        except Exception:  # noqa: BLE001, S110 -- bookkeeping must not outrank the write; verify/doctor read the sink
            pass

    def _publish_if_due(self, sink: Sink, ledger: AuditLedger) -> None:
        global _publishing  # noqa: PLW0603 -- the row this writes must not publish again
        if _publishing:
            return
        now = _clock()
        if self.interval > 0:
            last = _read_state(ledger.path, self.identity)
            if last is not None and 0 <= now - last < self.interval:
                return                               # inside the window: no network round trip
            _write_state(ledger.path, self.identity, now)
        pin = sink.fetch()
        if pin is not None and self.interval > 0 and now - pin["at"] < self.interval:
            return                                   # another process published inside the window
        lines = read_log(ledger.path)
        rows = parse_lines(lines)
        rearm = bool(os.environ.get(ENV_REARM, "").strip())
        if pin is None and not rearm and any(r.get("action") == ANCHOR_ACTION for r in rows):
            return                                   # anchored before and the pin is gone: empty, not re-armed
        held = verify_lines(lines, ledger.key, None, pin["head"] if pin else None)
        if not held.ok:
            return                                   # a broken chain, a cut below the pin: never publish
        if pin is not None and pin["entries"] >= held.entries:
            return                                   # the pin is not behind: never backward, never sideways
        sink.publish({"head": rows[-1]["entry_hash"], "at": int(now), "entries": held.entries})
        if pin is None:                              # the first publish (or a re-arm): say so in the chain
            _publishing = True
            try:
                ledger.record(ANCHOR_ACTION, target="ledger", detail={"rearmed": rearm})
            finally:
                _publishing = False
            lines = read_log(ledger.path)
            rows = parse_lines(lines)
            sink.publish({"head": rows[-1]["entry_hash"], "at": int(now), "entries": len(rows)})

    # -- read back ---------------------------------------------------------------------------

    def check(self, lines: list[str], key: bytes | None) -> dict[str, Any]:
        """The anchor's answer about `lines` (the ledger's rows, read once). `ok` is whether the
        anchor PROVES anything wrong or nothing: False for every state but present/stale."""
        if self.problem or self.sink is None:
            return {"state": "misconfigured", "ok": False, "reason": self.problem or "no sink"}
        try:
            pin = self.sink.fetch()
        except AnchorError as exc:
            return {"state": "unreachable", "ok": False, "reason": str(exc)}
        if pin is None:
            return {"state": "empty", "ok": False, "rearm": ENV_REARM,
                    "reason": "nothing is published to the anchor, so the tail is unproven (the first write "
                              "publishes; a ledger anchored before is not re-anchored until the operator "
                              f"sets {ENV_REARM}=1 for one write)"}
        v = verify_lines(lines, key, None, pin["head"])
        if not v.ok:
            return {"state": "diverged", "ok": False, "reason": v.reason or "the chain does not hold the anchor",
                    "broken_at": v.broken_at}
        rows = parse_lines(lines)
        exact = bool(rows) and rows[-1].get("entry_hash") == pin["head"]
        age = max(0, int(_clock()) - pin["at"])
        behind = 0 if exact else max(0, v.entries - pin["entries"])
        state = "present" if exact or age <= self.stale_after else "stale"
        out = {"state": state, "ok": True, "head_is_chain_head": exact, "behind": behind,
               "unwatched_rows": behind, "age_seconds": age, "stale_after_seconds": self.stale_after}
        if behind:
            out["note"] = (f"{behind} row(s) after the anchored head are not verified: a cut that stays above "
                           "the anchored row would still read ok")
        return out


def from_env() -> Anchor | None:
    """None when no sink is set (inert: nothing published, nothing read, no other anchor variable
    consulted). Otherwise an Anchor, with `problem` set when it cannot be honoured."""
    sink_name = os.environ.get(ENV_SINK, "").strip().lower()
    if sink_name in ("", "none"):
        return None
    interval = DEFAULT_INTERVAL
    raw_interval = os.environ.get(ENV_INTERVAL, "").strip()
    if raw_interval:
        try:
            interval = int(raw_interval)
            if interval < 0:
                raise ValueError
        except ValueError:
            return Anchor(None, DEFAULT_INTERVAL, "", f"{ENV_INTERVAL} must be a whole number of seconds, 0 or more")
    if sink_name == "file":
        path = os.environ.get(ENV_FILE, "").strip()
        if not path:
            return Anchor(None, interval, "", f"{ENV_SINK}=file needs {ENV_FILE}")
        if not os.path.isabs(os.path.expanduser(path)):
            return Anchor(None, interval, "", f"{ENV_FILE} must be an absolute path (a relative one means "
                                              "something different to every door's working directory)")
        return Anchor(FileSink(path), interval, f"file:{path}")
    if sink_name == "http":
        url = os.environ.get(ENV_URL, "").strip()
        if not url:
            return Anchor(None, interval, "", f"{ENV_SINK}=http needs {ENV_URL}")
        if not _transport_ok(url):
            return Anchor(None, interval, "", f"{ENV_URL} must be https (plain http only to loopback)")
        ca = os.environ.get(ENV_CA, "").strip() or None
        if ca:
            from proximo.core.tls import httpx_verify  # noqa: PLC0415
            try:
                httpx_verify(ca)
            except (OSError, ValueError):
                return Anchor(None, interval, "", f"{ENV_CA} could not be loaded")
        return Anchor(HttpSink(url, os.environ.get(ENV_TOKEN, "").strip() or None, ca), interval, f"http:{url}")
    return Anchor(None, interval, "", f"{ENV_SINK} names a sink this build does not have (file, http)")


def _transport_ok(url: str) -> bool:
    """https always; http only to loopback, where there is no network for an on-path attacker.
    0.44 allowed plain http with a warning; a pin read over a wire anyone can edit proves nothing."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        return False
    if parts.scheme == "https":
        return bool(host)
    if parts.scheme != "http":
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _state_path(log_path: str) -> str:
    return log_path + ".anchor"


def _read_state(log_path: str, identity: str) -> float | None:
    """The last attempt for THIS sink, from the file beside the ledger. Not a security boundary: an
    agent that edits it can only make publishes rarer, which `stale` then says."""
    try:
        with open(_state_path(log_path), encoding="utf-8") as f:
            st = json.load(f)
        if st["sink"] == hashlib.sha256(identity.encode()).hexdigest()[:16] and type(st["at"]) in (int, float):
            return float(st["at"])
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def _write_state(log_path: str, identity: str, at: float) -> None:
    try:
        with open(_state_path(log_path), "w", encoding="utf-8") as f:
            json.dump({"sink": hashlib.sha256(identity.encode()).hexdigest()[:16], "at": at}, f)
    except OSError:
        pass


def after_write(ledger: AuditLedger) -> None:
    """The hook `open_ledger` installs. Reads the environment each time, so a switch set in the
    env file takes effect at the next write and an unset one is inert."""
    a = from_env()
    if a is not None:
        a.after_write(ledger)


def inspect_ledger(log_path: str, key: bytes | None) -> dict[str, Any] | None:
    """The anchor's answer about the ledger at `log_path`, or None when no anchor is set. A missing
    log is the empty chain (a wiped or deleted ledger must fail against a pin, not read as
    "nothing was recorded")."""
    a = from_env()
    if a is None:
        return None
    try:
        lines = read_log(log_path)
    except ProximoError:
        lines = []
    return a.check(lines, key)


_RAISE = (f"{ENV_SINK}=file (with {ENV_FILE}) or =http (with {ENV_URL}): the ledger's head is then "
          "published off-box and audit_verify catches a cut or wiped tail with no human copying it")


def station(lcfg: Any, flags: list[str]) -> dict[str, Any]:
    """Doctor's PROVE anchor station; the one flag it raises is appended to `flags`. absent = not
    asked for; present = the chain holds the pin and the pin is the head or fresh; stale = held but
    behind and old (nothing is publishing, or nothing can); empty / unreachable = the sink cannot
    vouch; diverged = the chain does not hold the pin; misconfigured = the switch cannot be honoured.
    State and counts, never a path, URL or token."""
    try:
        try:
            key = ledger_key(lcfg)
        except (OSError, ValueError):
            key = None
        answer = inspect_ledger(lcfg.audit_log_path, key)
    except OSError as exc:
        answer = {"state": "unreachable", "ok": False, "reason": f"the ledger cannot be read ({type(exc).__name__})"}
    if answer is None:
        flags.append("PROVE has no off-box anchor: a cut or wiped ledger tail is invisible unless you copy "
                     "the head somewhere this box cannot write")
        return {"state": "absent", "standing": False, "raise": _RAISE}
    out = {k: v for k, v in answer.items() if k not in ("ok", "reason")}
    state = out["state"]
    out["standing"] = state == "present"
    why = safe_text(str(answer.get("reason", "")), limit=200, paths=True)
    said = {"stale": "the PROVE anchor is stale: the pinned head is held by the chain but behind it and old; "
                     "the rows after it are unwatched",
            "diverged": f"the PROVE anchor is DIVERGED: {why}; the chain no longer holds the head pinned "
                        "off-box (a cut tail, a wipe, or a replaced ledger)"}
    if state != "present":
        flags.append(said.get(state, f"the PROVE anchor is {state}: {why}"))
    return out
