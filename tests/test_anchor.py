"""THE OFF-BOX ANCHOR: the ledger's head is published where this box cannot rewrite it, and read back.

The hash chain catches an edited, inserted, reordered or removed interior row. A cut or wiped TAIL
leaves a chain that verifies clean on its own; only a head pinned somewhere the writer cannot reach
sees it. 0.44's `audit_anchor.py` automated that pin (the manual one, `expected_head`, survived the
cut). These tests port the intent of its 62 tests to the core's idiom: opt-in by env, a publish
that never fails the write, a read-back that refuses when it cannot prove, no path or secret in any
answer, and one rule 0.44 learned late and this keeps from the start: a pin only ever moves
FORWARD along a chain that still holds it (a cut tail followed by one honest write must not
re-pin the anchor to the cut chain).
"""
from __future__ import annotations

import http.server
import json
import os
import threading
import time
import tracemalloc

import pytest

from proximo.core import anchor, doctor
from proximo.core.doors import mcp as door
from proximo.core.ledger import LedgerConfig, open_ledger

MARK = "zq9x-anchor-marker"          # rides in every path and secret an answer must never print


@pytest.fixture
def box(monkeypatch, tmp_path):
    for var in list(os.environ):
        if var.startswith("PROXIMO_AUDIT_ANCHOR"):
            monkeypatch.delenv(var)
    monkeypatch.delenv("PROXIMO_AUDIT_EXPECTED_HEAD", raising=False)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    return tmp_path


@pytest.fixture
def pin_file(box, monkeypatch):
    out = box / f"{MARK}-offbox"
    out.mkdir()
    path = out / "head.json"
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SINK", "file")
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_FILE_PATH", str(path))
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_INTERVAL", "0")           # every write, unless a test says
    return path


def _ledger():
    return open_ledger(LedgerConfig.from_env())


def _row(led, n=0):
    return led.record("row", target=f"/x/{n}", mutation=False, outcome="ok", detail={})


def _pinned(path):
    return json.loads(path.read_text())


def _log():
    return open(os.environ["PROXIMO_AUDIT_LOG"], encoding="utf-8").read()


def _cut(rows_kept):
    lines = _log().splitlines(keepends=True)
    open(os.environ["PROXIMO_AUDIT_LOG"], "w", encoding="utf-8").writelines(lines[:rows_kept])


# --- inert unless asked --------------------------------------------------------------------------

def test_unset_is_inert_nothing_published_nothing_read(box, monkeypatch, tmp_path):
    """No sink, no anchor: other anchor variables alone switch nothing on, and a sink that would
    explode if touched is never touched."""
    stray = tmp_path / "stray.json"
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_FILE_PATH", str(stray))
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_URL", "https://pins.invalid/head")
    assert anchor.from_env() is None
    led = _ledger()
    _row(led)
    assert not stray.exists()
    out = door.audit_verify()
    assert out["ok"] is True and "anchor" not in out
    assert doctor.run()["pillars"]["PROVE"]["anchor"]["state"] == "absent"
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SINK", "none")
    assert anchor.from_env() is None


# --- publish -------------------------------------------------------------------------------------

def test_a_write_publishes_the_head_and_no_path(pin_file):
    led = _ledger()
    _row(led)
    pin = _pinned(pin_file)
    assert pin["head"] == led.head()
    assert pin["entries"] >= 1 and isinstance(pin["at"], int)
    assert MARK not in pin_file.read_text() and os.environ["PROXIMO_AUDIT_LOG"] not in pin_file.read_text()
    _row(led, 1)
    assert _pinned(pin_file)["head"] == led.head()


def test_publishing_is_rate_limited_and_shared_between_processes(pin_file, monkeypatch):
    """Rate limit by a small state file beside the ledger (a new process knows the last attempt
    with no network round trip) AND by the age of the pin itself (another host's publish)."""
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_INTERVAL", "300")
    clock = [1_000_000.0]
    monkeypatch.setattr(anchor, "_clock", lambda: clock[0])
    fetches = []
    real = anchor.FileSink.fetch
    monkeypatch.setattr(anchor.FileSink, "fetch", lambda self: fetches.append(1) or real(self))
    led = _ledger()
    _row(led)
    first = _pinned(pin_file)
    n = len(fetches)
    _row(led, 1)
    _row(open_ledger(LedgerConfig.from_env()), 2)               # "another process": a fresh ledger object
    assert _pinned(pin_file) == first and len(fetches) == n     # inside the window: no publish, NO fetch
    clock[0] += 301
    _row(led, 3)
    assert _pinned(pin_file)["head"] == led.head()              # the window passed: published
    second = _pinned(pin_file)
    os.unlink(anchor._state_path(os.environ["PROXIMO_AUDIT_LOG"]))   # state lost: the pin's own age speaks
    _row(led, 4)
    assert _pinned(pin_file) == second
    clock[0] += 301
    os.unlink(anchor._state_path(os.environ["PROXIMO_AUDIT_LOG"]))
    _row(led, 5)
    assert _pinned(pin_file)["head"] == led.head()
    assert _pinned(pin_file)["at"] == int(clock[0])


def test_a_publish_failure_never_fails_the_write_and_is_visible(pin_file):
    os.rmdir(pin_file.parent)                                  # the off-box mount is gone
    led = _ledger()
    entry = _row(led)                                          # the write that triggered the publish
    assert entry["entry_hash"] == led.head()                   # lands; the call that wrote the row is whole
    out = door.audit_verify()
    assert out["ok"] is False and out["anchor"]["state"] == "unreachable"
    assert doctor.run()["pillars"]["PROVE"]["anchor"]["state"] == "unreachable"


def test_a_pin_that_is_not_moving_reads_stale_in_both_voices(pin_file, monkeypatch):
    clock = [1_000_000.0]
    monkeypatch.setattr(anchor, "_clock", lambda: clock[0])
    led = _ledger()
    _row(led)
    assert door.audit_verify()["anchor"]["state"] == "present"
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SINK", "file")
    saved = pin_file.read_text()
    _row(led, 1)                                               # publish works now ...
    pin_file.write_text(saved)                                 # ... but pretend it stopped: the pin lags
    clock[0] += 100_000
    out = door.audit_verify()
    assert out["anchor"]["state"] == "stale" and out["anchor"]["behind"] >= 1
    assert out["ok"] is True and out["tail_verified"] is False  # held, but the tail past it is unwatched
    station = doctor.run()["pillars"]["PROVE"]["anchor"]
    assert station["state"] == "stale" and station["standing"] is False


# --- audit_verify reads it back ------------------------------------------------------------------

def test_the_anchored_head_is_a_row_the_chain_must_still_hold(pin_file, monkeypatch):
    """The same semantics as the env pin (test_the_env_pin_is_a_row_the_chain_must_still_hold):
    later rows are fine; a cut below the pin, a wipe and a replaced file are not."""
    led = _ledger()
    _row(led, 100)
    _row(led)
    anchored = led.head()
    out = door.audit_verify()
    assert out["ok"] is True and out["anchor"]["state"] == "present"
    assert out["tail_verified"] is True and out["anchor"]["head_is_chain_head"] is True
    assert "pinned" in out and out["pinned"] is None
    pin_file_text = pin_file.read_text()
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_INTERVAL", "99999")   # ordinary activity the pin does not follow
    _row(led, 1)
    _row(led, 2)
    out = door.audit_verify()
    assert out["ok"] is True and out["anchor"]["state"] == "present"
    assert out["tail_verified"] is False                       # a held row says nothing of a row forged after it
    assert out["anchor"]["behind"] == 2 and pin_file.read_text() == pin_file_text
    _cut(1)                                                    # cut BELOW the pin
    out = door.audit_verify()
    assert out["ok"] is False and out["anchor"]["state"] == "diverged" and "anchor" in out["reason"]
    assert out["tail_verified"] is False
    assert _pinned(pin_file)["head"] == anchored                # reading it back never moves it


def test_a_wiped_or_deleted_ledger_fails_against_the_anchor(pin_file):
    led = _ledger()
    _row(led)
    log = os.environ["PROXIMO_AUDIT_LOG"]
    open(log, "w").close()                                     # wiped
    assert door.audit_verify()["ok"] is False
    os.unlink(log)                                             # deleted: not "nothing has been recorded"
    out = door.audit_verify()
    assert out["ok"] is False and out["anchor"]["state"] == "diverged"


def test_a_replaced_file_fails(pin_file, tmp_path, monkeypatch):
    led = _ledger()
    _row(led)
    other = tmp_path / "other"
    other.mkdir()
    fresh = open_ledger(LedgerConfig(audit_log_path=str(other / "audit.log")))
    _row(fresh)
    open(os.environ["PROXIMO_AUDIT_LOG"], "w").write((other / "audit.log").read_text())
    (tmp_path / "audit.key").write_bytes((other / "audit.key").read_bytes())
    assert door.audit_verify()["ok"] is False


def test_an_unreadable_or_empty_anchor_is_refused_not_passed(pin_file):
    """Once set, anything that prevents PROVING reads as refused: a sink that cannot be read, one
    holding garbage, and one holding nothing after rows exist are all ok: False."""
    led = _ledger()
    _row(led)
    pin_file.write_text("not json at all")
    out = door.audit_verify()
    assert out["ok"] is False and out["anchor"]["state"] == "unreachable"
    pin_file.write_text(json.dumps({"head": "nope", "at": 1, "entries": 1}))
    assert door.audit_verify()["ok"] is False
    pin_file.write_text(json.dumps({"head": "0" * 64, "at": "x", "entries": 1}))
    assert door.audit_verify()["ok"] is False                  # a field of the wrong shape is corruption
    pin_file.unlink()                                          # the pin was removed: nothing proves the tail
    out = door.audit_verify()
    assert out["ok"] is False and out["anchor"]["state"] == "empty"
    assert doctor.run()["pillars"]["PROVE"]["anchor"]["state"] == "empty"


def test_the_argument_and_env_pins_still_work_beside_it(pin_file, monkeypatch):
    led = _ledger()
    _row(led)
    old = led.head()
    _row(led, 1)
    monkeypatch.setenv("PROXIMO_AUDIT_EXPECTED_HEAD", old)
    out = door.audit_verify()
    assert out["ok"] is True and out["pinned"] == "env" and out["anchor"]["state"] == "present"
    out = door.audit_verify(expected_head=old)                 # an exact old head is a head mismatch
    assert out["ok"] is False and "head mismatch" in out["reason"]


# --- anti-poisoning ------------------------------------------------------------------------------

def test_a_cut_chain_followed_by_an_honest_write_does_not_repin_the_anchor(pin_file):
    """0.44's late lesson. The naive design publishes the head on every write; an attacker who
    cuts the tail waits for the next legitimate row and the anchor now vouches for the cut
    chain, for good. A pin moves only along a chain that still holds it."""
    led = _ledger()
    for i in range(3):
        _row(led, i)
    anchored = _pinned(pin_file)
    _cut(1)
    for i in range(10, 16):                                    # honest writes on the cut chain, outgrowing the pin
        _row(_ledger(), i)
    assert _pinned(pin_file) == anchored                       # NOT re-pinned
    out = door.audit_verify()
    assert out["ok"] is False and out["anchor"]["state"] == "diverged"


def test_a_pin_never_moves_backward(pin_file):
    led = _ledger()
    for i in range(3):
        _row(led, i)
    newer = pin_file.read_text()
    pin_file.write_text(json.dumps({**json.loads(newer), "entries": 99}))   # a pin ahead of the chain
    bumped = pin_file.read_text()
    _row(led, 5)
    assert pin_file.read_text() == bumped


def test_a_corrupt_chain_is_never_published(pin_file):
    led = _ledger()
    _row(led)
    good = pin_file.read_text()
    lines = _log().splitlines(keepends=True)
    lines[0] = lines[0].replace('"outcome":"ok"', '"outcome":"OK"', 1)
    open(os.environ["PROXIMO_AUDIT_LOG"], "w", encoding="utf-8").writelines(lines)
    _row(led, 2)
    assert pin_file.read_text() == good


# --- configuration -------------------------------------------------------------------------------

def test_misconfiguration_is_refused_and_never_fails_a_write(box, monkeypatch):
    cases = [
        ({"PROXIMO_AUDIT_ANCHOR_SINK": "file"}, "PROXIMO_AUDIT_ANCHOR_FILE_PATH"),
        ({"PROXIMO_AUDIT_ANCHOR_SINK": "http"}, "PROXIMO_AUDIT_ANCHOR_URL"),
        ({"PROXIMO_AUDIT_ANCHOR_SINK": "http", "PROXIMO_AUDIT_ANCHOR_URL": "http://pins.example.com/head"}, "https"),
        ({"PROXIMO_AUDIT_ANCHOR_SINK": "http", "PROXIMO_AUDIT_ANCHOR_URL": "ftp://x/y"}, "https"),
        ({"PROXIMO_AUDIT_ANCHOR_SINK": "file", "PROXIMO_AUDIT_ANCHOR_FILE_PATH": "head.json"}, "absolute"),
        ({"PROXIMO_AUDIT_ANCHOR_SINK": "syslog"}, "file, http"),
        ({"PROXIMO_AUDIT_ANCHOR_SINK": "journal"}, "file, http"),
        ({"PROXIMO_AUDIT_ANCHOR_SINK": "file", "PROXIMO_AUDIT_ANCHOR_FILE_PATH": "/x",
          "PROXIMO_AUDIT_ANCHOR_INTERVAL": "soon"}, "PROXIMO_AUDIT_ANCHOR_INTERVAL"),
        ({"PROXIMO_AUDIT_ANCHOR_SINK": "http", "PROXIMO_AUDIT_ANCHOR_URL": "https://pins.example.com/head",
          "PROXIMO_AUDIT_ANCHOR_CA_BUNDLE": "/nonexistent/ca.pem"}, "PROXIMO_AUDIT_ANCHOR_CA_BUNDLE"),
    ]
    for env, names in cases:
        for k in [k for k in os.environ if k.startswith("PROXIMO_AUDIT_ANCHOR")]:
            monkeypatch.delenv(k)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        a = anchor.from_env()
        assert a is not None and a.problem and names in a.problem, (env, a and a.problem)
        assert "/nonexistent" not in a.problem and "example.com" not in a.problem
        led = _ledger()
        _row(led)                                              # the write goes through
        out = door.audit_verify()
        assert out["ok"] is False and out["anchor"]["state"] == "misconfigured", env
        assert doctor.run()["pillars"]["PROVE"]["anchor"]["state"] == "misconfigured"
        os.unlink(os.environ["PROXIMO_AUDIT_LOG"])
        os.unlink(os.path.join(os.path.dirname(os.environ["PROXIMO_AUDIT_LOG"]), "audit.key"))


# --- the http sink -------------------------------------------------------------------------------

class _PinStore(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.server.requests.append(("GET", self.headers.get("Authorization")))
        self.server.paths.append(self.path)
        mode = self.server.mode
        if mode == "redirect":
            self.send_response(301)
            self.send_header("Location", "/elsewhere")
            self.end_headers()
            return
        if mode == "boom":
            self.send_response(500)
            self.end_headers()
            return
        if mode == "padded":                  # a VALID pin, padded: only the size cap refuses it
            body = json.dumps({**json.loads(self.server.pin), "pad": "x" * 100_000}).encode()
        elif mode == "slowheaders":           # the headers never finish: no body chunk for a reader to count
            try:
                self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Pad: ")
                for _ in range(40):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.2)
            except OSError:
                pass
            return
        elif mode in ("trickle", "big"):
            total = 100_000 if mode == "trickle" else 200_000_000
            self.send_response(200)
            self.send_header("Content-Length", str(total))
            self.end_headers()
            try:
                for _ in range(total // (1 if mode == "trickle" else 65536)):
                    self.wfile.write(b"x" if mode == "trickle" else b"x" * 65536)
                    self.wfile.flush()
                    if mode == "trickle":
                        time.sleep(0.2)
                    self.server.sent += 1
            except OSError:
                pass
            return
        elif self.server.pin is None:
            self.send_response(404)
            self.end_headers()
            return
        else:
            body = self.server.pin
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        self.server.requests.append(("PUT", self.headers.get("Authorization")))
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n)
        if self.server.put_status in (200, 201, 204):
            self.server.pin = body
        self.send_response(self.server.put_status)
        if self.server.put_status in (301, 302):
            self.send_header("Location", "/elsewhere")
        self.end_headers()


@pytest.fixture
def receiver(box, monkeypatch):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _PinStore)
    srv.pin, srv.mode, srv.requests, srv.paths = None, "ok", [], []
    srv.put_status, srv.sent = 204, 0
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SINK", "http")
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_URL", f"http://127.0.0.1:{srv.server_address[1]}/{MARK}/head")
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_INTERVAL", "0")
    yield srv
    srv.shutdown()
    srv.server_close()


def test_http_sink_publishes_and_reads_back(receiver):
    led = _ledger()
    _row(led)
    assert json.loads(receiver.pin)["head"] == led.head()
    out = door.audit_verify()
    assert out["ok"] is True and out["anchor"]["state"] == "present" and out["tail_verified"] is True
    open(os.environ["PROXIMO_AUDIT_LOG"], "w").close()
    assert door.audit_verify()["ok"] is False                   # a wipe, caught through the receiver


def test_http_sink_sends_the_token_by_reference_and_never_prints_it(receiver, monkeypatch, tmp_path):
    tok = tmp_path / f"{MARK}-token"
    tok.write_text("anchor-token-bytes-123456")
    tok.chmod(0o600)
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_TOKEN_PATH", str(tok))
    led = _ledger()
    _row(led)
    assert ("PUT", "Bearer anchor-token-bytes-123456") in receiver.requests
    out = json.dumps([door.audit_verify(), doctor.run()])
    assert "anchor-token-bytes-123456" not in out and MARK not in out and "127.0.0.1" not in out
    tok.chmod(0o644)                                           # an exposed token file is refused before bytes leave
    receiver.requests.clear()
    _row(led, 1)
    assert receiver.requests == []
    assert door.audit_verify()["ok"] is False


@pytest.mark.parametrize("mode", ["redirect", "boom", "padded"])
def test_http_sink_fails_closed_never_follows_a_redirect(receiver, mode):
    led = _ledger()
    _row(led)
    receiver.mode = mode
    out = door.audit_verify()
    assert out["ok"] is False and out["anchor"]["state"] == "unreachable"
    assert "/elsewhere" not in receiver.paths                  # the redirect target is never requested


@pytest.mark.parametrize("status", [403, 500, 301, 404])
def test_http_sink_refused_put_is_visible_and_the_write_stands(receiver, status):
    receiver.put_status = status
    led = _ledger()
    entry = _row(led)
    assert entry["entry_hash"] == led.head()
    assert receiver.pin is None
    out = door.audit_verify()
    assert out["ok"] is False and out["anchor"]["state"] == "empty"   # nothing ever landed


@pytest.mark.parametrize("status", [200, 201, 204])
def test_http_sink_accepts_the_success_statuses_of_a_put(receiver, status):
    receiver.put_status = status
    _row(_ledger())
    assert receiver.pin is not None


def test_a_slow_trickle_cannot_hold_a_write_past_the_deadline(receiver, monkeypatch):
    """A server sending one byte per 0.2 s never trips a per-operation timeout. The sink has a TOTAL
    wall-clock deadline, so the write returns when it passes."""
    led = _ledger()
    _row(led)
    receiver.mode = "trickle"
    monkeypatch.setattr(anchor, "_DEADLINE", 1.0)
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_INTERVAL", "0")
    t0 = time.monotonic()
    out = door.audit_verify()
    entry = _row(led, 1)                                        # a write that fetches the pin first
    assert time.monotonic() - t0 < 4.0
    assert entry["entry_hash"] == led.head()
    assert out["ok"] is False and out["anchor"]["state"] == "unreachable"


def test_a_trickle_of_headers_is_cut_by_the_total_deadline(receiver, monkeypatch):
    led = _ledger()
    _row(led)
    receiver.mode = "slowheaders"
    monkeypatch.setattr(anchor, "_DEADLINE", 1.0)
    t0 = time.monotonic()
    out = door.audit_verify()
    assert time.monotonic() - t0 < 4.0 and out["anchor"]["state"] == "unreachable"


def test_the_worker_ends_with_its_own_deadline_not_only_the_callers(receiver, monkeypatch):
    """After the caller gave up on a trickle, the abandoned worker must end too, not read for ever."""
    _row(_ledger())
    receiver.mode = "trickle"
    monkeypatch.setattr(anchor, "_DEADLINE", 0.6)

    def mine():
        return {t for t in threading.enumerate() if t.name == "proximo-anchor"}
    before = mine()                                            # workers a neighbouring test left behind
    door.audit_verify()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline and mine() - before:
        time.sleep(0.1)
    assert not (mine() - before)


def test_a_huge_body_is_stopped_at_the_cap_not_buffered(receiver):
    led = _ledger()
    _row(led)
    receiver.mode = "big"
    tracemalloc.start()
    t0 = time.monotonic()
    out = door.audit_verify()
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert out["anchor"]["state"] == "unreachable"
    assert peak < 2_000_000 and time.monotonic() - t0 < 5.0
    assert receiver.sent < 2000                                 # of 3000+ chunks: it hung up early


def test_the_http_client_ignores_proxy_environment(receiver, monkeypatch):
    """httpx trusts HTTP_PROXY by default, so a proxy could answer for the sink and "plain http only
    to loopback" would mean nothing."""
    proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _PinStore)
    proxy.pin, proxy.mode, proxy.requests, proxy.paths, proxy.put_status, proxy.sent = None, "ok", [], [], 204, 0
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{proxy.server_address[1]}")
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{proxy.server_address[1]}")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    try:
        _row(_ledger())
        assert receiver.pin is not None and proxy.requests == []
    finally:
        proxy.shutdown()
        proxy.server_close()


def test_the_client_is_built_with_a_timeout_no_redirects_and_no_env(receiver, monkeypatch):
    import httpx
    seen = {}
    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: seen.update(kw) or real(**kw))
    _row(_ledger())
    assert seen["trust_env"] is False and seen["follow_redirects"] is False
    assert seen["timeout"] is not None and seen["timeout"] > 0


def test_a_non_loopback_http_url_is_refused_but_https_and_loopback_are_not(box, monkeypatch):
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SINK", "http")
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_URL", "https://pins.example.com/head")
    assert anchor.from_env().problem is None
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_URL", "http://localhost:9/head")
    assert anchor.from_env().problem is None
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_URL", "http://pins.example.com/head")
    assert anchor.from_env().problem is not None


# --- doctor's station ----------------------------------------------------------------------------

def test_doctors_station_names_the_state_and_never_where(pin_file):
    led = _ledger()
    for i in range(3):
        _row(led, i)
    r = doctor.run()
    st = r["pillars"]["PROVE"]["anchor"]
    assert st["state"] == "present" and st["standing"] is True and r["anchor"] == st
    assert not any("anchor" in f for f in r["flags"])
    _cut(1)
    r = doctor.run()
    assert r["pillars"]["PROVE"]["anchor"]["state"] == "diverged"
    assert r["pillars"]["PROVE"]["standing"] is False                # a chain that lost its pin is not whole
    assert any("DIVERGED" in f for f in r["flags"]) and r["complete"] is False
    assert MARK not in json.dumps(r) and str(pin_file.parent) not in json.dumps(r)


def test_doctor_names_an_absent_anchor_as_advice_with_the_line_that_raises_it(box):
    r = doctor.run()
    st = r["pillars"]["PROVE"]["anchor"]
    assert st["state"] == "absent" and "PROXIMO_AUDIT_ANCHOR_SINK=" in st["raise"]
    assert any(f.startswith("PROVE has no off-box anchor") for f in r["flags"])
    assert "PROVE has no off-box anchor" in doctor._ADVISORY      # advice, not incompleteness


# --- pins the sink must refuse -------------------------------------------------------------------

_H = "ab" * 32


@pytest.mark.parametrize("pin", [
    {"head": "0" * 64, "at": 1, "entries": 1},                 # the genesis head names no row
    {"head": _H, "at": -1, "entries": 1},
    {"head": _H, "at": True, "entries": 1},
    {"head": _H, "at": 1, "entries": True},
    {"head": _H, "at": 1, "entries": 0},
    {"head": _H, "at": 1.5, "entries": 1},
    {"head": _H.upper(), "at": 1, "entries": 1},
    {"head": _H, "at": 1},
])
def test_a_malformed_pin_is_refused(pin_file, pin):
    _row(_ledger())
    pin_file.write_text(json.dumps(pin))
    out = door.audit_verify()
    assert out["ok"] is False and out["anchor"]["state"] == "unreachable"


def test_a_valid_but_oversized_pin_file_is_refused(pin_file):
    led = _ledger()
    _row(led)
    pin_file.write_text(json.dumps({**_pinned(pin_file), "pad": "x" * 100_000}))
    assert door.audit_verify()["anchor"]["state"] == "unreachable"


# --- the file sink writes atomically and tidily ---------------------------------------------------

def test_the_file_sink_replaces_atomically_and_leaves_no_temp_file(pin_file, monkeypatch):
    led = _ledger()
    _row(led)
    before = pin_file.read_text()
    assert sorted(os.listdir(pin_file.parent)) == ["head.json"]
    monkeypatch.setattr(os, "replace", lambda *a: (_ for _ in ()).throw(OSError("boom")))
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_INTERVAL", "0")
    _row(led, 1)                                               # the publish fails; the write stands
    assert pin_file.read_text() == before                      # the old pin is whole, never half-written
    assert sorted(os.listdir(pin_file.parent)) == ["head.json"]   # and the temp file is gone


def test_the_directory_is_synced_after_the_replace(pin_file, monkeypatch):
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: synced.append(os.fstat(fd).st_mode) or real(fd))
    _row(_ledger())
    import stat
    assert any(stat.S_ISDIR(m) for m in synced)
    assert stat.S_IMODE(pin_file.stat().st_mode) == 0o600


# --- once anchored, an empty sink is not silently re-armed ----------------------------------------

def test_a_vanished_pin_is_not_republished_by_an_honest_write(receiver, monkeypatch):
    """A transient 404 (or a wiped store) after the ledger was anchored must not let the next
    honest write re-anchor a chain that may have been cut. The state is `empty` until the operator
    re-arms."""
    led = _ledger()
    _row(led)
    assert receiver.pin is not None
    receiver.pin = None                                        # the store lost the pin
    for i in range(3):
        _row(led, i)
    assert receiver.pin is None
    out = door.audit_verify()
    assert out["ok"] is False and out["anchor"]["state"] == "empty"
    assert door.audit_verify()["anchor"]["rearm"] == "PROXIMO_AUDIT_ANCHOR_REARM"
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_REARM", "1")      # the operator's act
    _row(led, 9)
    assert receiver.pin is not None
    monkeypatch.delenv("PROXIMO_AUDIT_ANCHOR_REARM")
    assert door.audit_verify()["ok"] is True


def test_the_first_ever_publish_is_not_blocked_and_records_that_the_ledger_was_anchored(pin_file):
    led = _ledger()
    _row(led)
    rows = [json.loads(x) for x in _log().splitlines()]
    assert [r["action"] for r in rows].count("audit_anchor") == 1
    assert "path" not in json.dumps(rows[-1]) and str(pin_file) not in _log()
    _row(led, 1)
    assert [json.loads(x)["action"] for x in _log().splitlines()].count("audit_anchor") == 1


# --- plain words about what is unwatched ---------------------------------------------------------

def test_rows_after_the_pin_are_said_to_be_unwatched(pin_file, monkeypatch):
    led = _ledger()
    _row(led)
    out = door.audit_verify()
    assert out["anchor"]["unwatched_rows"] == 0 and "note" not in out["anchor"]
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_INTERVAL", "99999")
    _row(led, 1)
    _row(led, 2)
    out = door.audit_verify()
    assert out["ok"] is True
    assert out["anchor"]["unwatched_rows"] == 2
    assert "2 row(s)" in out["anchor"]["note"] and "not verified" in out["anchor"]["note"]
    _cut(len(_log().splitlines()) - 1)                         # a cut that stays above the pinned row reads ok ...
    out = door.audit_verify()
    assert out["ok"] is True and out["tail_verified"] is False   # ... and says the tail is not verified
    assert out["anchor"]["unwatched_rows"] == 1


def test_doctor_with_the_ledger_missing_is_diverged_not_absent(pin_file):
    _row(_ledger())
    os.unlink(os.environ["PROXIMO_AUDIT_LOG"])
    st = doctor.run()["pillars"]["PROVE"]["anchor"]
    assert st["state"] == "diverged"


def test_a_whitespace_padded_pin_file_is_refused_and_a_huge_one_is_not_read_whole(pin_file):
    _row(_ledger())
    pin_file.write_text(pin_file.read_text() + " " * 5000)        # valid JSON, over the cap
    assert door.audit_verify()["anchor"]["state"] == "unreachable"
    with open(pin_file, "r+") as f:                                # a 300 MB sparse file
        f.truncate(300_000_000)
    tracemalloc.start()
    out = door.audit_verify()
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert out["anchor"]["state"] == "unreachable" and peak < 5_000_000
