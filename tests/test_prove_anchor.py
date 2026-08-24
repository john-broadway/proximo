"""Off-box PROVE anchor — smallest first slice (file sink + on-demand export).

Automates the strong PROVE guarantee: pin the ledger head() OFF-BOX and verify against it,
so tail truncation / full wipe / forged append become visible without manual copy-paste.

Three sinks: the FileSink (write head as JSON to a file — e.g. an NFS mount that Proximo can
POST-to-but-not-rewrite; the first slice), the HttpSink (GET/PUT one pin resource on a remote
receiver; 2026-08-20 — exercised below against a real threaded stdlib server, every fail-closed
direction included), and the SyslogSink (the WRITE-ONLY witness: fetches_pins=False, appends a
frame per clean verify; same day — exercised against real TCP/unix/TLS collectors, hostile
header fields included), plus config-load auto-pin and on-demand export from audit_verify().
A journal sink and a background export thread remain deliberate later extensions and are NOT
exercised here.

FAIL-CLOSED is the whole point: a configured-but-unreachable anchor is SUSPICIOUS, never
silently skipped. The tests below assert refusal (AnchorError / RuntimeError / ProximoError)
on every unreachable/corrupt path, so a fail-OPEN regression can't slip in green.
"""

from __future__ import annotations

import http.server
import json
import socket
import socketserver
import threading
import warnings
from types import SimpleNamespace

import pytest

from proximo.audit import AuditLedger
from proximo.audit_anchor import AnchorError, FileSink, build_anchor_sink
from proximo.backends import ProximoError
from proximo.config import ProximoConfig

_HEAD = "a" * 64
_OTHER_HEAD = "b" * 64


# --- FileSink: publish + fetch round-trip -----------------------------------------------------


def test_anchor_file_sink_publish_and_fetch(tmp_path):
    """FileSink.publish writes the head off-box; last_head() reads exactly that value back."""
    sink = FileSink(str(tmp_path / "anchor.json"))
    sink.publish(_HEAD, "2026-07-01T00:00:00+00:00", "pve", "/var/log/audit.log")
    assert sink.last_head() == _HEAD
    # Payload carries the documented shape (head + provenance), stored as parseable JSON.
    payload = json.loads((tmp_path / "anchor.json").read_text())
    assert payload["head"] == _HEAD
    assert payload["node"] == "pve"
    assert payload["ledger_path"] == "/var/log/audit.log"
    assert payload["ts"] == "2026-07-01T00:00:00+00:00"


def test_anchor_file_sink_publish_overwrites(tmp_path):
    """Idempotent: publishing a newer head overwrites the prior pin (latest head always wins)."""
    sink = FileSink(str(tmp_path / "anchor.json"))
    sink.publish(_HEAD, "t1", "pve", "/l")
    sink.publish(_OTHER_HEAD, "t2", "pve", "/l")
    assert sink.last_head() == _OTHER_HEAD


def test_anchor_file_sink_last_head_none_on_first_run(tmp_path):
    """Sink reachable but empty (file absent, parent dir present) => None (normal first run)."""
    sink = FileSink(str(tmp_path / "anchor.json"))
    assert sink.last_head() is None


# --- FileSink: fail-closed on every unreachable / corrupt path --------------------------------


def test_anchor_file_sink_missing_dir_publish_fail_closed(tmp_path):
    """Publish into a nonexistent parent directory => AnchorError (never a silent no-op)."""
    sink = FileSink(str(tmp_path / "nope" / "anchor.json"))
    with pytest.raises(AnchorError):
        sink.publish(_HEAD, "t", "pve", "/l")


def test_anchor_file_sink_missing_dir_fetch_fail_closed(tmp_path):
    """last_head() when the destination DIRECTORY is gone => AnchorError, NOT None.

    A missing file whose parent exists is a legit first run (None). A missing *directory* means
    the sink is unreachable/misconfigured — treat it as suspicious and fail closed, so config
    can refuse to start rather than run with tail-attack detection silently disabled.
    """
    sink = FileSink(str(tmp_path / "nope" / "anchor.json"))
    with pytest.raises(AnchorError):
        sink.last_head()


def test_anchor_file_sink_corrupt_fail_closed(tmp_path):
    """A non-JSON anchor file => AnchorError (corruption/tamper of the sink itself)."""
    p = tmp_path / "anchor.json"
    p.write_text("not json {{{")
    with pytest.raises(AnchorError):
        FileSink(str(p)).last_head()


def test_anchor_file_sink_malformed_head_fail_closed(tmp_path):
    """A JSON anchor whose 'head' isn't a 64-hex head() value => AnchorError."""
    p = tmp_path / "anchor.json"
    p.write_text(json.dumps({"head": "deadbeef"}))
    with pytest.raises(AnchorError):
        FileSink(str(p)).last_head()


def test_anchor_file_sink_missing_head_key_fail_closed(tmp_path):
    """A JSON anchor with no 'head' key => AnchorError (not a silent None)."""
    p = tmp_path / "anchor.json"
    p.write_text(json.dumps({"ts": "t"}))
    with pytest.raises(AnchorError):
        FileSink(str(p)).last_head()


# --- build_anchor_sink: config-factory validation ---------------------------------------------


def test_build_anchor_sink_none_disabled():
    assert build_anchor_sink("none", None) is None
    assert build_anchor_sink("", None) is None


def test_build_anchor_sink_file_requires_path():
    with pytest.raises(RuntimeError, match="(?i)PROXIMO_AUDIT_ANCHOR_FILE_PATH"):
        build_anchor_sink("file", None)


def test_build_anchor_sink_unknown_type_fails():
    with pytest.raises(RuntimeError, match="(?i)not a recognized sink"):
        build_anchor_sink("s3", None)


def test_build_anchor_sink_file_ok(tmp_path):
    sink = build_anchor_sink("file", str(tmp_path / "anchor.json"))
    assert isinstance(sink, FileSink)
    assert sink.name == "file"


# --- config wiring: from_env parses + auto-pins, fails closed ---------------------------------


def _base_env(monkeypatch, **extra):
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "pve")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "/run/x")
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def test_config_anchor_none_by_default(monkeypatch):
    _base_env(monkeypatch)
    assert ProximoConfig.from_env().anchor_sink is None


def test_config_from_env_file_anchor(monkeypatch, tmp_path):
    anchor = tmp_path / "anchor.json"
    FileSink(str(anchor)).publish(_HEAD, "t", "pve", "/l")
    _base_env(
        monkeypatch,
        PROXIMO_AUDIT_ANCHOR_SINK="file",
        PROXIMO_AUDIT_ANCHOR_FILE_PATH=str(anchor),
    )
    cfg = ProximoConfig.from_env()
    assert isinstance(cfg.anchor_sink, FileSink)
    # No manual pin => the off-box anchor auto-pins expected_head (tail-attack detection is now on).
    assert cfg.expected_head == _HEAD


def test_config_file_anchor_empty_sink_first_run_no_pin(monkeypatch, tmp_path):
    """Configured sink but empty (first run) => sink wired, expected_head stays unpinned (None)."""
    _base_env(
        monkeypatch,
        PROXIMO_AUDIT_ANCHOR_SINK="file",
        PROXIMO_AUDIT_ANCHOR_FILE_PATH=str(tmp_path / "anchor.json"),
    )
    cfg = ProximoConfig.from_env()
    assert isinstance(cfg.anchor_sink, FileSink)
    assert cfg.expected_head is None


def test_config_file_anchor_missing_path_fails(monkeypatch, tmp_path):
    """Configured anchor whose destination directory is gone => REFUSE to start (fail-closed)."""
    _base_env(
        monkeypatch,
        PROXIMO_AUDIT_ANCHOR_SINK="file",
        PROXIMO_AUDIT_ANCHOR_FILE_PATH=str(tmp_path / "gone" / "anchor.json"),
    )
    with pytest.raises(RuntimeError, match="(?i)anchor"):
        ProximoConfig.from_env()


def test_config_file_anchor_requires_path_fails(monkeypatch):
    """sink=file with no PROXIMO_AUDIT_ANCHOR_FILE_PATH => refuse to start."""
    _base_env(monkeypatch, PROXIMO_AUDIT_ANCHOR_SINK="file")
    monkeypatch.delenv("PROXIMO_AUDIT_ANCHOR_FILE_PATH", raising=False)
    with pytest.raises(RuntimeError, match="(?i)PROXIMO_AUDIT_ANCHOR_FILE_PATH"):
        ProximoConfig.from_env()


def test_config_manual_pin_differs_from_sink_warns(monkeypatch, tmp_path):
    """Manual pin AND sink pin, differing => warn but HONOR the manual pin (sink is advisory)."""
    anchor = tmp_path / "anchor.json"
    FileSink(str(anchor)).publish(_OTHER_HEAD, "t", "pve", "/l")
    _base_env(
        monkeypatch,
        PROXIMO_AUDIT_EXPECTED_HEAD=_HEAD,
        PROXIMO_AUDIT_ANCHOR_SINK="file",
        PROXIMO_AUDIT_ANCHOR_FILE_PATH=str(anchor),
    )
    with pytest.warns(UserWarning, match="(?i)manual|differs|anchor"):
        cfg = ProximoConfig.from_env()
    assert cfg.expected_head == _HEAD  # manual pin wins


def test_config_manual_pin_matches_sink_no_warn(monkeypatch, tmp_path):
    """Manual pin == sink pin => no drift warning."""
    anchor = tmp_path / "anchor.json"
    FileSink(str(anchor)).publish(_HEAD, "t", "pve", "/l")
    _base_env(
        monkeypatch,
        PROXIMO_AUDIT_EXPECTED_HEAD=_HEAD,
        PROXIMO_AUDIT_ANCHOR_SINK="file",
        PROXIMO_AUDIT_ANCHOR_FILE_PATH=str(anchor),
        # Opt in to ledger redaction so the (unrelated) permissive-default warning doesn't trip
        # the blanket "any UserWarning is a failure" check below — this test is about anchor drift.
        PROXIMO_LEDGER_REDACT="1",
    )
    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        cfg = ProximoConfig.from_env()
    assert cfg.expected_head == _HEAD


# --- server.audit_verify(): on-demand export + anchor metadata --------------------------------


def _wire_audit(monkeypatch, tmp_path, *, anchor_sink=None, cfg_head=None):
    import proximo.server as server

    led = AuditLedger(str(tmp_path / "audit.log"))
    cfg = SimpleNamespace(expected_head=cfg_head, node="pve", anchor_sink=anchor_sink)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))
    return server, led


def test_audit_verify_with_file_anchor_on_demand(monkeypatch, tmp_path):
    """audit_verify with a configured sink exports the live head on-demand and reports it."""
    import proximo.server as server  # noqa: F401  (imported for symmetry / clarity)

    anchor = tmp_path / "anchor.json"
    sink = FileSink(str(anchor))
    srv, led = _wire_audit(monkeypatch, tmp_path, anchor_sink=sink)
    led.record("a", target="t1")

    out = srv.audit_verify()
    assert out["ok"] is True
    assert out["anchor_sink"] == "file"
    assert out["anchor_last_export"] is not None
    # The sink now holds the CURRENT head — the anchor tracked the ledger automatically.
    assert sink.last_head() == led.head()


def test_audit_verify_no_anchor_reports_null_metadata(monkeypatch, tmp_path):
    """No sink configured => anchor metadata is present-but-null (legible, backward-compatible)."""
    srv, led = _wire_audit(monkeypatch, tmp_path, anchor_sink=None)
    led.record("a", target="t1")
    out = srv.audit_verify()
    assert out["anchor_sink"] is None
    assert out["anchor_last_export"] is None


def test_audit_verify_forward_growth_holds_pin_and_hints_forward(monkeypatch, tmp_path):
    """Legit forward growth past an EXISTING off-box pin: the pin is HELD (never auto-advanced, so a
    truncation can't ride the same path to poison it), and the anchor_hint says the ledger grew
    FORWARD (benign stale-pin lag) rather than firing a silent tamper alarm. The anti-poisoning
    invariant wearing its benign face — the count discriminates forward growth from a shrink."""
    anchor = tmp_path / "anchor.json"
    sink = FileSink(str(anchor))
    srv, led = _wire_audit(monkeypatch, tmp_path, anchor_sink=sink)
    led.record("a", target="t1")
    pinned = led.head()
    sink.publish(pinned, "t0", "pve", str(led.path), entries=1)   # an EXISTING pin at 1 entry
    led.record("b", target="t2")                                   # ledger grows forward -> 2 entries

    import proximo.server as server
    cfg = SimpleNamespace(expected_head=pinned, node="pve", anchor_sink=sink)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))
    out = server.audit_verify()

    assert out["ok"] is False and "head mismatch" in out["reason"]
    assert out["anchor_hint"] is not None and "forward" in out["anchor_hint"].lower()
    assert out["anchor_last_export"] is None          # pin was NOT auto-advanced
    assert sink.last_head() == pinned                 # pin HELD at the pre-growth head


def test_audit_verify_anchor_publish_failure_fails_closed(monkeypatch, tmp_path):
    """On-demand export failure => the audit_verify call FAILS (fail-closed), never silent success.

    A configured anchor that can't be written is suspicious; the operator must see it, not get a
    green verify while the off-box pin silently went stale.
    """
    from proximo.backends import ProximoError

    class _BrokenSink(FileSink):
        def publish(self, head, ts, node, ledger_path, entries=None):
            raise AnchorError("sink down")

    broken = _BrokenSink(str(tmp_path / "anchor.json"))
    srv, led = _wire_audit(monkeypatch, tmp_path, anchor_sink=broken)
    led.record("a", target="t1")
    with pytest.raises(ProximoError, match="(?i)anchor"):
        srv.audit_verify()


# --- Anti-poisoning invariant: audit_verify must NEVER move the pin to a tampered head ---------
# The whole value of the off-box anchor is detecting tail truncation / wipe. If a verify that
# DETECTS an attack then re-pins the anchor to the tampered head, the attack becomes permanently
# invisible after the next restart re-pins from the poisoned anchor. The single invariant below —
# "the pin never changes to a head other than the previously-pinned one" — catches truncation,
# full wipe, and the expected_head='' one-shot in one assertion.


def _truncate_last_entry(log_path):
    lines = log_path.read_text().splitlines()
    log_path.write_text(("\n".join(lines[:-1]) + "\n") if len(lines) > 1 else "")


def test_audit_verify_truncation_does_not_poison_pin(monkeypatch, tmp_path):
    """Ledger truncated after the pin => audit_verify reports ok:False AND leaves the pin UNCHANGED
    (it must not re-publish the tampered head over the good off-box pin)."""
    import proximo.server as server

    sink = FileSink(str(tmp_path / "anchor.json"))
    led = AuditLedger(str(tmp_path / "audit.log"))
    led.record("a", target="t1")
    led.record("b", target="t2")
    led.record("c", target="t3")
    pinned = led.head()
    sink.publish(pinned, "t0", "pve", str(led.path))   # establish the off-box pin at H3

    _truncate_last_entry(tmp_path / "audit.log")        # attacker lops the last entry -> head H2

    cfg = SimpleNamespace(expected_head=pinned, node="pve", anchor_sink=sink)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))
    out = server.audit_verify()

    assert out["ok"] is False                           # truncation detected
    assert sink.last_head() == pinned                   # INVARIANT: pin NOT poisoned


def test_audit_verify_empty_expected_head_does_not_poison_pin(monkeypatch, tmp_path):
    """The one-shot: expected_head='' normalizes to no pin, so verify can't see truncation on its
    own (ok:True) — but the on-demand export must STILL not advance the off-box pin to the
    truncated head."""
    import proximo.server as server

    sink = FileSink(str(tmp_path / "anchor.json"))
    led = AuditLedger(str(tmp_path / "audit.log"))
    led.record("a", target="t1")
    led.record("b", target="t2")
    pinned = led.head()
    sink.publish(pinned, "t0", "pve", str(led.path))

    _truncate_last_entry(tmp_path / "audit.log")

    cfg = SimpleNamespace(expected_head=None, node="pve", anchor_sink=sink)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, None, None, led))
    server.audit_verify(expected_head="")

    assert sink.last_head() == pinned                   # INVARIANT: pin NOT poisoned


# --- HttpSink — the off-box anchor over the wire (2026-08-20, finding 3's named extension) ---
#
# A tiny threaded stdlib server plays the pin store: GET returns the stored pin (404 when
# empty — the unambiguous first run), PUT stores the body. Port 0, assigned port read back,
# so parallel test runs cannot collide. Each test builds its own server + state.

class _PinStore(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep pytest output clean
        pass

    def do_GET(self):
        self.server.requests.append(("GET", self.headers.get("Authorization")))
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
        if mode == "garbage":
            body = b"not json at all"
        elif mode == "badhead":
            body = b'{"head": "nope", "ts": "t", "node": "n", "ledger_path": "p"}'
        elif self.server.pin is None:
            self.send_response(404)
            self.end_headers()
            return
        else:
            body = self.server.pin
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        self.server.requests.append(("PUT", self.headers.get("Authorization")))
        if self.server.mode == "refuse-put":
            self.send_response(403)
            self.end_headers()
            return
        n = int(self.headers.get("Content-Length", 0))
        self.server.pin = self.rfile.read(n)
        self.send_response(204)
        self.end_headers()


def _pin_server(mode="ok"):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _PinStore)
    srv.pin = None
    srv.mode = mode
    srv.requests = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/pin"


def _http_sink(url, **kw):
    from proximo.audit_anchor import HttpSink
    return HttpSink(url, **kw)


def test_http_sink_roundtrip_publish_then_fetch():
    srv, url = _pin_server()
    try:
        s = _http_sink(url)
        head = "a" * 64
        s.publish(head, "2026-08-20T00:00:00+00:00", "node-a", "/var/log/a.log", entries=7)
        pin = s.last_pin()
        assert pin["head"] == head and pin["entries"] == 7 and pin["node"] == "node-a"
        assert s.last_head() == head
    finally:
        srv.shutdown()


def test_http_sink_404_is_the_unambiguous_first_run():
    srv, url = _pin_server()
    try:
        assert _http_sink(url).last_pin() is None
    finally:
        srv.shutdown()


def test_http_sink_server_error_fails_closed():
    srv, url = _pin_server(mode="boom")
    try:
        with pytest.raises(AnchorError, match="500"):
            _http_sink(url).last_pin()
    finally:
        srv.shutdown()


def test_http_sink_garbage_body_fails_closed():
    srv, url = _pin_server(mode="garbage")
    try:
        with pytest.raises(AnchorError, match="corrupt"):
            _http_sink(url).last_pin()
    finally:
        srv.shutdown()


def test_http_sink_malformed_head_fails_closed():
    srv, url = _pin_server(mode="badhead")
    try:
        with pytest.raises(AnchorError, match="malformed"):
            _http_sink(url).last_pin()
    finally:
        srv.shutdown()


def test_http_sink_refused_put_fails_closed():
    srv, url = _pin_server(mode="refuse-put")
    try:
        with pytest.raises(AnchorError, match="403"):
            _http_sink(url).publish("a" * 64, "t", "n", "p")
    finally:
        srv.shutdown()


def test_http_sink_connection_refused_fails_closed():
    # Bind-then-close guarantees an unassigned port.
    import socket
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        dead = sk.getsockname()[1]
    with pytest.raises(AnchorError):
        _http_sink(f"http://127.0.0.1:{dead}/pin").last_pin()


def test_http_sink_does_not_follow_a_redirect():
    """A 3xx on a pin store is suspicious and must fail closed WITHOUT being followed — a
    client that chased the Location and failed at the second hop would pass a naive
    raises-check while having already leaked the request wherever it was pointed."""
    srv, url = _pin_server(mode="redirect")
    try:
        with pytest.raises(AnchorError, match="301"):
            _http_sink(url).last_pin()
        assert len(srv.requests) == 1, "the redirect was followed — fail-closed means ONE request"
    finally:
        srv.shutdown()


def test_http_sink_sends_the_bearer_token_by_reference(tmp_path):
    tok = tmp_path / "anchor.tok"
    tok.write_text("sekrit-anchor-token")
    tok.chmod(0o600)
    srv, url = _pin_server()
    try:
        s = _http_sink(url, token_path=str(tok))
        s.publish("b" * 64, "t", "n", "p")
        assert s.last_pin()["head"] == "b" * 64
        auths = {a for _, a in srv.requests}
        assert auths == {"Bearer sekrit-anchor-token"}
    finally:
        srv.shutdown()


def test_http_sink_refuses_an_exposed_token_file(tmp_path):
    tok = tmp_path / "anchor.tok"
    tok.write_text("sekrit-anchor-token")
    tok.chmod(0o644)  # group/other-readable — the shared secret-file floor must refuse
    srv, url = _pin_server()
    try:
        with pytest.raises(RuntimeError, match="group/other-accessible"):
            _http_sink(url, token_path=str(tok)).last_pin()
        assert srv.requests == [], "the request went out despite the exposed token file"
    finally:
        srv.shutdown()


def test_build_anchor_sink_http_requires_a_url():
    from proximo.audit_anchor import build_anchor_sink
    with pytest.raises(RuntimeError, match="PROXIMO_AUDIT_ANCHOR_URL"):
        build_anchor_sink("http", None)


def test_build_anchor_sink_unknown_sink_names_the_supported_set():
    # "udp" doubles as the documented refused transport: it is not a sink type either.
    # (This test's probe used to be "syslog" — which became a KNOWN sink the same day.)
    from proximo.audit_anchor import build_anchor_sink
    with pytest.raises(RuntimeError, match="'http'"):
        build_anchor_sink("udp", None)


def test_build_anchor_sink_plain_http_warns_https_does_not():
    from proximo.audit_anchor import build_anchor_sink
    with pytest.warns(UserWarning, match="plaintext"):
        assert build_anchor_sink("http", None, url="http://pins.example/p").name == "http"
    import warnings as _w
    with _w.catch_warnings():
        _w.simplefilter("error")  # any warning would raise
        assert build_anchor_sink("http", None, url="https://pins.example/p").name == "http"


def test_config_wires_the_http_sink_and_startup_autopin(monkeypatch, tmp_path):
    """END TO END through the fail-closed startup path: env vars -> HttpSink built ->
    last_head() fetched at config load -> expected_head auto-pinned to it."""
    from proximo.config import ProximoConfig
    srv, url = _pin_server()
    try:
        # Seed the store with a pin, as if a prior run published it.
        _http_sink(url).publish("c" * 64, "t", "node-a", "/var/log/a.log", entries=3)
        monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
        monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SINK", "http")
        monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_URL", url)
        monkeypatch.delenv("PROXIMO_AUDIT_EXPECTED_HEAD", raising=False)
        cfg = ProximoConfig.from_env_ledger()
        assert cfg.anchor_sink is not None and cfg.anchor_sink.name == "http"
        assert cfg.expected_head == "c" * 64
    finally:
        srv.shutdown()


def test_http_sink_ca_bundle_routes_through_the_tls_seam():
    """ca_bundle must build an SSLContext via _tls.httpx_verify at CONSTRUCTION — never the
    deprecated verify=<str> form (lens catch: this was the one client site bypassing the house
    seam, and this channel is the last place a deprecation should age into breakage). Warnings
    are errors here, so the deprecated path cannot come back silently."""
    import ssl
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        s = _http_sink("https://pins.example/p",
                       ca_bundle="/etc/ssl/certs/ca-certificates.crt")  # same path test_backends uses
    assert isinstance(s._verify, ssl.SSLContext)


def test_http_sink_bad_ca_bundle_refuses_at_construction(tmp_path):
    """A bad CA path fails fast at BUILD (the fail-closed config startup), not on first request."""
    with pytest.raises(RuntimeError, match="PROXIMO_AUDIT_ANCHOR_CA_BUNDLE"):
        _http_sink("https://pins.example/p", ca_bundle=str(tmp_path / "no-such-ca.pem"))


# --- SyslogSink — the WRITE-ONLY witness sink (2026-08-20, the module's named extension) ------
#
# Syslog can carry a head OUT but can never hand it back, so this sink is a different trust
# shape: fetches_pins=False, every clean verify APPENDS to the collector's trail (the
# SECURITY.md "root-only append log" sentence, mechanized), and automatic startup verification
# is honestly unavailable. A collector double captures frames; TLS gets real teeth via a
# minted cert (cryptography, a dev dep).

class _TcpCollector(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class _FrameHandler(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            self.server.frames.append(line)


def _tcp_collector():
    srv = _TcpCollector(("127.0.0.1", 0), _FrameHandler)
    srv.frames = []
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"127.0.0.1:{srv.server_address[1]}"


def _syslog_sink(address, **kw):
    from proximo.audit_anchor import SyslogSink
    return SyslogSink(address, **kw)


def _wait_frames(srv, n, tries=200):
    """Wait for `n` frames, then FAIL AS A TIMEOUT rather than returning short.

    This used to return whatever had arrived after 2.5s, so a scheduling starvation under full
    suite load surfaced downstream as `assert len(frames) == 2` failing with 1 — which reads like
    the sink dropped a frame, i.e. a protocol bug, and sent a 2026-08-24 session hunting one. The
    collector is a daemon thread on an ephemeral port; when this box is busy it simply does not
    get scheduled inside the window. Say so in the message, and give it 10s of headroom.
    """
    import time
    for _ in range(tries):
        if len(srv.frames) >= n:
            return srv.frames
        time.sleep(0.05)
    raise AssertionError(
        f"timed out after {tries * 0.05:.0f}s waiting for {n} syslog frame(s); got "
        f"{len(srv.frames)}. This is a collector-thread scheduling timeout under load, NOT the "
        f"sink dropping frames — check machine load before suspecting the protocol.")


def test_syslog_sink_appends_one_clean_frame_per_publish():
    srv, addr = _tcp_collector()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # plaintext warn tested on its own below
            s = _syslog_sink(addr)
        s.publish("d" * 64, "2026-08-20T14:00:00+00:00", "node-a", "/var/log/a.log", entries=9)
        s.publish("e" * 64, "2026-08-20T14:01:00+00:00", "node-a", "/var/log/a.log", entries=10)
        frames = _wait_frames(srv, 2)
        # The append TRAIL is this sink's entire value: two publishes = two frames, each a
        # clean single-line frame carrying its own head.
        #
        # ARRIVAL ORDER IS DELIBERATELY NOT ASSERTED, and this used to be, which made the test
        # flaky and lied about why. `publish` opens a NEW connection per call and the collector
        # is a ThreadingTCPServer, so two independent handler threads append to one list. TCP
        # orders bytes WITHIN a connection and promises nothing ACROSS two. Measured on this
        # harness 2026-08-24: 4 of 300 runs recorded the second head first, and under full-suite
        # load the rate is far higher. It surfaced downstream as a head mismatch, which reads
        # like the sink writing the wrong head, i.e. a protocol bug, and cost a session real
        # time. No product doc claims arrival order (they claim append-only, which holds and is
        # a different property); a consumer orders the trail by `ts` or by the chain itself.
        assert len(frames) == 2
        heads = []
        for frame in frames:
            assert frame.endswith(b"\n") and frame.count(b"\n") == 1
            assert frame.startswith(b"<134>1 ")  # local0(16)*8 + info(6) = 134
            heads.append(json.loads(frame.decode().split("AUDITHEAD - ", 1)[1])["head"])
        assert sorted(heads) == sorted(("d" * 64, "e" * 64)), heads
    finally:
        srv.shutdown()


def test_syslog_sink_hostile_header_fields_cannot_forge_a_second_frame():
    """LF is the frame delimiter, so an embedded newline in a header field would forge a second
    syslog record. Header slots carry a SANITIZED token; full fidelity lives in the JSON, where
    json.dumps escapes control characters."""
    srv, addr = _tcp_collector()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            s = _syslog_sink(addr)
        s.publish("f" * 64, "t", "pwn\nhost injected", "/var/\nlog/x")
        frames = _wait_frames(srv, 1)
        assert len(frames) == 1, "hostile node/path forged extra frames"
        frame = frames[0]
        assert frame.count(b"\n") == 1 and frame.endswith(b"\n")
        header = frame.decode().split("AUDITHEAD - ", 1)[0]
        assert "pwn\nhost" not in header and " injected" not in header.split(" ", 3)[3]
        payload = json.loads(frame.decode().split("AUDITHEAD - ", 1)[1])
        assert payload["node"] == "pwn\nhost injected"  # fidelity preserved where escaping rules
    finally:
        srv.shutdown()


def test_syslog_sink_connection_refused_fails_closed():
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        dead = sk.getsockname()[1]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = _syslog_sink(f"127.0.0.1:{dead}")
    with pytest.raises(AnchorError):
        s.publish("a" * 64, "t", "n", "p")


def test_syslog_sink_unix_socket_datagram(tmp_path):
    sock_path = str(tmp_path / "log.sock")
    rx = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    rx.bind(sock_path)
    rx.settimeout(5)
    try:
        _syslog_sink(sock_path).publish("a" * 64, "t", "node-a", "/l")
        frame = rx.recv(65536)
        assert frame.startswith(b"<134>1 ") and (b"a" * 64) in frame
    finally:
        rx.close()


def test_syslog_sink_unix_socket_missing_names_both_transports(tmp_path):
    """A dead unix socket path must fail naming BOTH attempted socket types — a quiet
    datagram->stream fallback that then fails quietly would hide which transport was wrong."""
    with pytest.raises(AnchorError, match="(?s)datagram.*stream|stream.*datagram"):
        _syslog_sink(str(tmp_path / "no-such.sock")).publish("a" * 64, "t", "n", "p")


def test_syslog_sink_is_write_only_and_says_so():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s = _syslog_sink("127.0.0.1:1")
    assert s.fetches_pins is False
    with pytest.raises(AnchorError, match="write-only"):
        s.last_pin()


def test_syslog_sink_plaintext_tcp_warns_unix_does_not(tmp_path):
    with pytest.warns(UserWarning, match="plaintext"):
        _syslog_sink("collector.example:6514")
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _syslog_sink(str(tmp_path / "log.sock"))  # unix socket: no transport question


def _mint_cert(tmp_path, cn="127.0.0.1"):
    """A throwaway self-signed cert for the TLS teeth (cryptography is a dev dep)."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(key, hashes.SHA256()))
    certf = tmp_path / "cert.pem"
    keyf = tmp_path / "key.pem"
    certf.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyf.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return str(certf), str(keyf)


def _tls_collector(certf, keyf):
    import ssl as _ssl
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certf, keyf)
    srv = _TcpCollector(("127.0.0.1", 0), _FrameHandler)
    srv.frames = []
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"127.0.0.1:{srv.server_address[1]}"


def test_syslog_sink_tls_verifies_against_the_ca_bundle(tmp_path):
    """CA bundle set => the TCP frame rides TLS, verified against that CA (RFC 5425 shape)."""
    certf, keyf = _mint_cert(tmp_path)
    srv, addr = _tls_collector(certf, keyf)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # TLS mode: no plaintext warning may fire
            s = _syslog_sink(addr, ca_bundle=certf)
        s.publish("b" * 64, "t", "node-a", "/l")
        frames = _wait_frames(srv, 1)
        assert len(frames) == 1 and (b"b" * 64) in frames[0]
    finally:
        srv.shutdown()


def test_syslog_sink_tls_refuses_an_untrusted_collector(tmp_path):
    """The wrong CA must refuse BEFORE any frame is handed over — that is the whole point of
    TLS on the tamper channel."""
    certf, keyf = _mint_cert(tmp_path)
    other_ca, _ = _mint_cert(tmp_path / "other") if (tmp_path / "other").mkdir() is None else (None, None)
    srv, addr = _tls_collector(certf, keyf)
    try:
        s = _syslog_sink(addr, ca_bundle=other_ca)
        with pytest.raises(AnchorError):
            s.publish("c" * 64, "t", "n", "p")
        assert srv.frames == [], "a frame reached an untrusted collector"
    finally:
        srv.shutdown()


def test_build_anchor_sink_syslog_requires_an_address():
    with pytest.raises(RuntimeError, match="PROXIMO_AUDIT_ANCHOR_SYSLOG_ADDRESS"):
        build_anchor_sink("syslog", None)


def test_build_anchor_sink_unknown_sink_names_every_supported_sink():
    """The refusal must LIST what is supported, so a typo is self-correcting.

    This test used to spell the unknown sink "journal" — a plausible name that did not exist.
    It exists now (2026-08-23), which is exactly why the assertion is on the LIST rather than
    on one example: the example went stale, the contract did not.
    """
    with pytest.raises(RuntimeError) as e:
        build_anchor_sink("not-a-sink", None)
    msg = str(e.value)
    for supported in ("none", "file", "http", "syslog", "journal"):
        assert f"'{supported}'" in msg


def test_config_syslog_sink_skips_the_fetch_and_warns_only_when_unpinned(monkeypatch, tmp_path):
    """Write-only sink: startup must NOT fetch (nothing to fetch), must still start, and warns
    that tail detection is not automatic ONLY when no manual pin covers it."""
    srv, addr = _tcp_collector()
    try:
        monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
        monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SINK", "syslog")
        monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SYSLOG_ADDRESS", addr)
        monkeypatch.delenv("PROXIMO_AUDIT_EXPECTED_HEAD", raising=False)
        with pytest.warns(UserWarning, match="write-only"):
            cfg = ProximoConfig.from_env_ledger()
        assert cfg.anchor_sink is not None and cfg.anchor_sink.name == "syslog"
        assert cfg.expected_head is None
        # With a manual pin, detection is covered — the write-only warn must NOT fire.
        monkeypatch.setenv("PROXIMO_AUDIT_EXPECTED_HEAD", "a" * 64)
        with warnings.catch_warnings():
            warnings.simplefilter("error", UserWarning)
            # the plaintext-TCP build warn would also trip error-mode; silence it selectively
            warnings.filterwarnings("ignore", message=".*plaintext.*")
            cfg = ProximoConfig.from_env_ledger()
        assert cfg.expected_head == "a" * 64
    finally:
        srv.shutdown()


class _WriteOnlyDouble:
    """Capturing double for the audit_verify branch: publish recorded, last_pin FORBIDDEN."""
    name = "syslog"
    fetches_pins = False

    def __init__(self):
        self.published = []

    def publish(self, head, ts, node, ledger_path, entries=None):
        self.published.append(head)

    def last_pin(self):
        raise AssertionError("audit_verify fetched from a write-only sink — the flag was ignored")

    def last_head(self):
        raise AssertionError("audit_verify fetched from a write-only sink — the flag was ignored")


def _wire_verify_with_sink(tmp_path, monkeypatch, sink):
    import proximo.server as server_mod
    from proximo.audit import AuditLedger as _AL
    led = _AL(str(tmp_path / "audit.log"))
    cfg = SimpleNamespace(expected_head=None, node="node-a", anchor_sink=sink)
    monkeypatch.setattr(server_mod, "_svc", lambda: (cfg, None, None, led))
    return server_mod, led


def test_audit_verify_write_only_sink_appends_on_clean_never_fetches(tmp_path, monkeypatch):
    """The verify branch honors fetches_pins: no fetch (the double raises if fetched), and every
    CLEAN verify appends — two verifies, two heads on the trail."""
    sink = _WriteOnlyDouble()
    server_mod, led = _wire_verify_with_sink(tmp_path, monkeypatch, sink)
    led.record("a", target="t1")
    out1 = server_mod.audit_verify()
    led.record("b", target="t1")
    out2 = server_mod.audit_verify()
    assert out1["ok"] and out2["ok"]
    assert sink.published == [out1["head"], out2["head"]], "the append trail did not accumulate"
    assert out2["anchor_last_export"] is not None


def test_audit_verify_write_only_sink_withholds_publish_on_a_failed_verify(tmp_path, monkeypatch):
    """The v.ok guard holds for the witness sink too: a tampered ledger appends NOTHING."""
    sink = _WriteOnlyDouble()
    server_mod, led = _wire_verify_with_sink(tmp_path, monkeypatch, sink)
    led.record("a", target="t1")
    led.record("b", target="t1")
    # Interior tamper: flip a byte in the FIRST line so the chain walk fails.
    lp = tmp_path / "audit.log"
    lines = lp.read_bytes().splitlines(keepends=True)
    lines[0] = lines[0].replace(b'"a"', b'"x"', 1)
    lp.write_bytes(b"".join(lines))
    out = server_mod.audit_verify()
    assert not out["ok"]
    assert sink.published == [], "a failed verify appended its head to the witness trail"


def test_audit_verify_write_only_failed_hint_never_says_re_pin_the_anchor(tmp_path, monkeypatch):
    """Lens catch: the failed-verify hint used to be _anchor_moved_hint's 'the pin was NOT
    auto-advanced... Re-pin the anchor' — an instruction that is structurally impossible on a
    write-only sink (its last_pin always raises), handed out on exactly the RECOMMENDED
    syslog+manual-pin pairing whenever the manual pin goes stale. The write-only hint must
    name the real remedies and never the impossible one."""
    sink = _WriteOnlyDouble()
    server_mod, led = _wire_verify_with_sink(tmp_path, monkeypatch, sink)
    led.record("a", target="t1")
    led.record("b", target="t1")
    lp = tmp_path / "audit.log"
    lines = lp.read_bytes().splitlines(keepends=True)
    lines[0] = lines[0].replace(b'"a"', b'"x"', 1)
    lp.write_bytes(b"".join(lines))
    out = server_mod.audit_verify()
    assert not out["ok"]
    assert out["anchor_hint"] is not None
    assert "Re-pin the anchor" not in out["anchor_hint"]
    assert "witness trail" in out["anchor_hint"]
    assert "PROXIMO_AUDIT_EXPECTED_HEAD" in out["anchor_hint"]


def test_audit_verify_flagless_sink_fails_loud_not_silent(tmp_path, monkeypatch):
    """The designed default, proven at the COMPOSITE path: a sink that forgets fetches_pins
    gets getattr's True default, its last_pin IS called, the AnchorError surfaces as a
    refused verify — loud, never a silent skip."""
    class _FlaglessSink:  # no fetches_pins attribute at all
        name = "flagless"

        def last_pin(self):
            raise AnchorError("flagless sink cannot fetch")

        def publish(self, *a, **k):
            raise AssertionError("publish reached despite the refused fetch")

    server_mod, led = _wire_verify_with_sink(tmp_path, monkeypatch, _FlaglessSink())
    led.record("a", target="t1")
    with pytest.raises(ProximoError, match="unreachable"):
        server_mod.audit_verify()


# --- JournalSink — the systemd write-only witness (the module's last named extension) ---------
#
# Same trust shape as syslog (fetches_pins=False, append-only trail), different wire: journald's
# native protocol over a unix DATAGRAM socket. The forgery class is the same and the defence is
# different — journald separates fields with LF, but its protocol has a length-prefixed binary
# form for values that contain one, so fidelity is kept STRUCTURALLY rather than sanitized away.

def _journal_socket(tmp_path):
    """A real AF_UNIX datagram socket standing in for /run/systemd/journal/socket."""
    path = str(tmp_path / "journal.sock")
    sk = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sk.bind(path)
    sk.settimeout(5)
    return sk, path


def _parse_journal(datagram: bytes) -> dict:
    """Parse journald's native export-ish framing: KEY=value\\n, or KEY\\n<u64 LE len>\\n<raw>\\n."""
    import struct
    fields, i = {}, 0
    while i < len(datagram):
        nl = datagram.index(b"\n", i)
        line = datagram[i:nl]
        if b"=" in line:
            k, v = line.split(b"=", 1)
            fields[k.decode()] = v.decode()
            i = nl + 1
        else:
            key = line.decode()
            (size,) = struct.unpack("<Q", datagram[nl + 1:nl + 9])
            start = nl + 9
            fields[key] = datagram[start:start + size].decode()
            i = start + size + 1
    return fields


def test_journal_sink_is_write_only_and_says_so():
    from proximo.audit_anchor import JournalSink
    s = JournalSink("/run/systemd/journal/socket")
    assert s.name == "journal"
    assert s.fetches_pins is False
    # A write-only sink must RAISE, never return a fake first-run None that a caller
    # would read as "the anchor is empty" — the syslog lesson, held here too.
    with pytest.raises(AnchorError):
        s.last_pin()


def test_journal_sink_publishes_one_datagram_with_the_head(tmp_path):
    from proximo.audit_anchor import JournalSink
    sk, path = _journal_socket(tmp_path)
    try:
        s = JournalSink(path)
        s.publish("d" * 64, "2026-08-23T22:00:00+00:00", "node-a", "/var/log/a.log", entries=9)
        fields = _parse_journal(sk.recv(65536))
        assert fields["PROXIMO_HEAD"] == "d" * 64
        assert fields["PROXIMO_NODE"] == "node-a"
        assert fields["PROXIMO_ENTRIES"] == "9"
        assert fields["SYSLOG_IDENTIFIER"] == "proximo-anchor"
        assert json.loads(fields["PROXIMO_ANCHOR_JSON"])["head"] == "d" * 64
    finally:
        sk.close()


def test_journal_sink_appends_a_trail_not_a_pin(tmp_path):
    """Two publishes are two records. The append trail IS this sink's value."""
    from proximo.audit_anchor import JournalSink
    sk, path = _journal_socket(tmp_path)
    try:
        s = JournalSink(path)
        s.publish("d" * 64, "t1", "n", "/p", entries=1)
        s.publish("e" * 64, "t2", "n", "/p", entries=2)
        heads = [_parse_journal(sk.recv(65536))["PROXIMO_HEAD"] for _ in range(2)]
        assert heads == ["d" * 64, "e" * 64]
    finally:
        sk.close()


def test_journal_sink_newline_in_a_value_cannot_forge_a_field(tmp_path):
    """LF separates journald fields, so a raw newline in a value would inject one. The protocol's
    length-prefixed binary form carries it instead — fidelity kept, forgery impossible."""
    from proximo.audit_anchor import JournalSink
    sk, path = _journal_socket(tmp_path)
    try:
        s = JournalSink(path)
        s.publish("f" * 64, "t", "pwn\nPRIORITY=0", "/var/\nlog/x")
        fields = _parse_journal(sk.recv(65536))
        assert fields["PROXIMO_NODE"] == "pwn\nPRIORITY=0"   # fidelity, not sanitized away
        assert fields["PRIORITY"] == "6"                      # the injection did NOT take
        assert fields["PROXIMO_LEDGER_PATH"] == "/var/\nlog/x"
    finally:
        sk.close()


def test_journal_sink_unreachable_socket_fails_closed(tmp_path):
    """A publish that cannot fail is not a check. A unix datagram to a missing socket DOES fail."""
    from proximo.audit_anchor import JournalSink
    missing = str(tmp_path / "not-there.sock")
    s = JournalSink(missing)
    with pytest.raises(AnchorError) as e:
        s.publish("a" * 64, "t", "n", "/p")
    assert missing in str(e.value)


def test_build_anchor_sink_knows_journal_and_defaults_its_socket(tmp_path):
    from proximo.audit_anchor import JournalSink, build_anchor_sink
    s = build_anchor_sink("journal", None)
    assert isinstance(s, JournalSink)
    assert s.address == "/run/systemd/journal/socket"
    override = str(tmp_path / "other.sock")
    s2 = build_anchor_sink("journal", None, journal_socket=override)
    assert s2.address == override


def test_unknown_sink_error_lists_journal():
    from proximo.audit_anchor import build_anchor_sink
    with pytest.raises(RuntimeError) as e:
        build_anchor_sink("nope", None)
    assert "journal" in str(e.value)


def test_config_journal_sink_skips_the_fetch_and_warns_only_when_unpinned(monkeypatch, tmp_path):
    """The write-only path is generic (it keys off fetches_pins). This proves the JOURNAL sink
    actually rides it rather than merely looking like it should: startup must not fetch, must
    still start, and must warn that tail detection is not automatic when nothing pins it."""
    sk, path = _journal_socket(tmp_path)
    try:
        monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
        monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SINK", "journal")
        monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_JOURNAL_SOCKET", path)
        monkeypatch.delenv("PROXIMO_AUDIT_EXPECTED_HEAD", raising=False)
        with pytest.warns(UserWarning, match="write-only"):
            cfg = ProximoConfig.from_env_ledger()
        assert cfg.anchor_sink is not None and cfg.anchor_sink.name == "journal"
        assert cfg.anchor_sink.fetches_pins is False
        # With a manual pin, detection is covered — the write-only warn must NOT fire.
        monkeypatch.setenv("PROXIMO_AUDIT_EXPECTED_HEAD", "a" * 64)
        with warnings.catch_warnings():
            warnings.simplefilter("error", UserWarning)
            cfg = ProximoConfig.from_env_ledger()
        assert cfg.expected_head == "a" * 64
    finally:
        sk.close()
