"""Off-box PROVE anchor — automated ledger-head pinning for tail-attack detection.

The PROVE ledger's forward hash-chain walk (``audit.py``) catches interior tampering — reorder,
insert, alter, remove of a *middle* entry — but is BLIND to TAIL operations: truncating the last
N entries, wiping the file wholesale, or forging an appended tail all leave a chain that verifies
clean on its own. The documented strong guarantee is to pin the ledger ``head()`` OFF-BOX and pass
it back as ``expected_head`` (see ``AuditLedger.verify``). Today that pin is a manual copy-paste;
this module automates it.

An :class:`AnchorSink` publishes the current head to an off-box destination and fetches the last
pinned head back, so on startup the live ledger is verified against the anchor with no operator
action. Three sinks ship: :class:`FileSink` (write the head as JSON to a file — e.g. an NFS
mount or object store that Proximo can write-but-not-rewrite; the first slice),
:class:`HttpSink` (GET/PUT one pin resource on a remote receiver — a different HOST, which is
where the trust model wants the anchor; added 2026-08-20), and :class:`SyslogSink` (the
WRITE-ONLY witness — appends every clean verify's head to a collector's trail and can never
read one back; same day; see its docstring for the trade). Config-load auto-pin and on-demand
export from ``audit_verify`` are sink-agnostic across the readable sinks and skip the fetch
for write-only ones. A journal sink and a background export thread are deliberate later
extensions.

TLS ON THE HTTP SINK, deliberately not configurable OFF: there is no
``PROXIMO_AUDIT_ANCHOR_VERIFY_TLS`` knob and its absence is a refusal, not an oversight — this
channel exists to detect tampering, so a switch that turns off transport verification on it
would be self-defeating. A private CA is supported (``PROXIMO_AUDIT_ANCHOR_CA_BUNDLE``); a
plain ``http://`` URL is allowed but warns loudly at build (see build_anchor_sink — the
FileSink-over-NFS precedent: no transport crypto there either, and the honesty note below,
not the config surface, carries the trust model).

HONESTY — where the guarantee actually rests. The anchor removes the manual step; it does NOT add
cryptography. Its entire value depends on the sink being **less-compromisable than this box**: a
separate host or an append-only / write-protected store, monitored independently. An attacker who
can rewrite the sink can supply any head and defeat the anchor. Proximo cannot prove the sink's own
integrity — that is the operator's job. Detection, not prevention, remains the guarantee.

FAIL-CLOSED. A configured sink is a declared dependency. If it is unreachable — a missing
destination directory, an unreadable/corrupt anchor file, or a malformed pinned head — the sink
raises :class:`AnchorError`, and the config layer turns that into a hard refusal to start. A
configured-but-unreachable anchor means tail-attack detection is silently gone, so we fail loud,
never skip. Only an unambiguous "sink reachable but empty" (a legit first run) reads as ``None``.

POINT-IN-TIME LIMIT (inherent, same as a manual ``PROXIMO_AUDIT_EXPECTED_HEAD``). The pin is ONE
hash: verifying the live ledger against it catches a ledger that DIVERGED or went BACKWARDS
(truncation / wipe / fork), but a ledger that legitimately grew FORWARD past the pin also fails the
equality check. So the anchor is at its strongest as a startup / at-rest check (ledger == last
export before any new appends).

ANTI-POISONING RULE (the security invariant — see ``server.audit_verify``). The on-demand export
advances the pin ONLY on a first run (no pin yet) or when the live head is UNCHANGED from the pin —
it NEVER overwrites an existing pin once the head has MOVED. That is deliberate: auto-advancing the
pin on every verify (the naive design) lets a verify that just DETECTED a truncation re-pin the
anchor to the tampered head, making the attack permanently invisible after the next restart. So
advancing the pin past a moved head is the operator's DELIBERATE act, never a silent side-effect of
a verify. A moved head is surfaced as ``anchor_hint`` — using the pinned vs live entry COUNT to say
whether the ledger grew FORWARD (benign stale-pin lag; re-pin when confirmed) or went BACKWARD (a
truncation/wipe signal to investigate). Walking the chain to confirm a forward advance is genuine
(the old pin still appears as an interior hash) is a deliberate later extension; until then the pin
stays put and the count-direction hint keeps a routine op from reading as tampering.
"""

from __future__ import annotations

import json
import os
import socket
import tempfile
import warnings
from abc import ABC, abstractmethod

import httpx

from ._secretfile import refuse_exposed_secret
from ._tls import httpx_verify
from .audit import looks_like_head

# Sink types recognized by build_anchor_sink(). "file" shipped as the first slice; "http" and
# "syslog" (the write-only witness) arrived 2026-08-20 — the module's own named extensions,
# built out after finding 3 of the external end-to-end report pointed at the anchor. A journal
# sink and a background export thread remain the deliberate later extensions.
# "none" (and "") = disabled.
_KNOWN_SINKS = frozenset({"none", "file", "http", "syslog"})


class AnchorError(Exception):
    """Publishing to, or fetching from, the off-box anchor sink failed.

    Raised on any unreachable / corrupt / malformed-pin condition. The config layer maps this to a
    fail-closed startup refusal; the on-demand export path maps it to a refused ``audit_verify``.
    """


class AnchorSink(ABC):
    """Publish — and, for readable sinks, fetch — audit-ledger heads off-box.

    See the module docstring for the trust model. Not every sink can read its pin back:
    ``fetches_pins`` declares the capability, and the two consumers (config's startup
    auto-pin, ``server.audit_verify``'s re-pin branch) check it before fetching."""

    fetches_pins: bool = True
    """Whether ``last_pin()`` can read the pin back. Write-only sinks (syslog) set False,
    and their ``last_pin`` RAISES — never a fake first-run ``None`` — so a consumer that
    forgets to check this flag fails LOUD (a refused verify), never silently."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short sink identifier surfaced in ``audit_verify`` output (e.g. ``"file"``)."""

    @abstractmethod
    def publish(self, head: str, ts: str, node: str, ledger_path: str,
                entries: int | None = None) -> None:
        """Write ``head`` (+ provenance, incl. the ledger ``entries`` count) to the sink,
        overwriting any prior pin. Idempotent.

        Raises :class:`AnchorError` on any I/O failure — never a silent no-op.
        """

    @abstractmethod
    def last_pin(self) -> dict | None:
        """Return the most recent pinned payload (``{head, ts, node, ledger_path, entries?}``), or
        ``None`` if the sink is reachable but empty (a legit first run).

        Raises :class:`AnchorError` if the sink is unreachable or its stored pin is corrupt /
        malformed — or if the sink is write-only (``fetches_pins`` False), where fetching is a
        caller bug and must fail loud. ``None`` is reserved for the unambiguous first-run case
        of a READABLE sink (fail-closed elsewhere).
        """

    def last_head(self) -> str | None:
        """The most recent pinned head, or ``None`` on a legit first run. Delegates to
        :meth:`last_pin` so every sink shares one read/validate path."""
        pin = self.last_pin()
        return pin["head"] if pin else None


def _validate_pin(text: str, source: str) -> dict:
    """Parse and validate a stored pin payload — ONE read/validate path for every sink.

    Extracted from FileSink.last_pin (2026-08-20, when the http sink arrived) so a second sink
    cannot drift its validation. Behavior-preserving; the error PHRASING was normalized around
    the ``source`` label (an earlier draft claimed "verbatim" — a lens disproved it against the
    pre-extraction text, and nothing matches on the old wording). Raises AnchorError on garbage
    JSON, a missing 'head', or a malformed head value; ``source`` names the sink in the error."""
    try:
        payload = json.loads(text)
        head = payload["head"]
    except (ValueError, KeyError, TypeError) as e:
        raise AnchorError(
            f"{source} is corrupt or missing a 'head' field: {e}"
        ) from e
    if not isinstance(head, str) or not looks_like_head(head):
        raise AnchorError(
            f"pinned head in {source} is malformed "
            f"(expected a 64-char hex head() value) — treat as sink corruption/tamper"
        )
    return payload


class FileSink(AnchorSink):
    """Pin the ledger head to a file — the portable slice sink.

    The file is meant to live OFF-BOX (an NFS/SMB mount, an object-store gateway, a synced path)
    where this box can write the latest head but cannot rewrite history. Locally it is also handy
    for testing. The head is stored as a small JSON object ``{"head", "ts", "node", "ledger_path"}``
    and written atomically (temp file + ``os.replace``) so a reader never sees a half-written pin.
    """

    def __init__(self, path: str):
        self.path = os.path.expanduser(path)

    @property
    def name(self) -> str:
        return "file"

    def publish(self, head: str, ts: str, node: str, ledger_path: str,
                entries: int | None = None) -> None:
        payload: dict = {"head": head, "ts": ts, "node": node, "ledger_path": ledger_path}
        if entries is not None:
            payload["entries"] = entries
        directory = os.path.dirname(self.path) or "."
        tmp: str | None = None
        try:
            # Atomic publish: write a temp file in the destination dir, fsync, then rename over the
            # anchor. mkstemp raises (OSError) if `directory` is missing — that is the fail-closed
            # "destination unreachable" signal, wrapped as AnchorError below.
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".proximo-anchor-")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, separators=(",", ":"))
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            tmp = None  # renamed away; nothing to clean up
        except (OSError, ValueError) as e:
            raise AnchorError(
                f"file anchor sink: cannot publish head to {self.path!r}: {e}"
            ) from e
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def last_pin(self) -> dict | None:
        try:
            with open(self.path, encoding="utf-8") as f:
                text = f.read()
        except FileNotFoundError:
            # File absent. If its parent dir exists, the sink is reachable but empty => first run.
            # If the parent dir is GONE, the sink is unreachable/misconfigured => fail closed.
            parent = os.path.dirname(self.path) or "."
            if os.path.isdir(parent):
                return None
            raise AnchorError(
                f"file anchor sink: destination directory {parent!r} does not exist "
                f"(configured but unreachable — fail closed)"
            ) from None
        except (OSError, ValueError) as e:
            raise AnchorError(f"file anchor sink: cannot read {self.path!r}: {e}") from e
        return _validate_pin(text, f"file anchor sink {self.path!r}")


class HttpSink(AnchorSink):
    """Pin the ledger head to one HTTP resource — GET fetches the pin, PUT stores it.

    The receiver is meant to live on a DIFFERENT HOST (that is the whole point: less
    compromisable than this box), and any endpoint that answers GET with the stored body,
    404 when empty, and accepts PUT works — a WebDAV location, an object-store gateway, a
    ten-line receiver. Same JSON payload the FileSink writes; same one validation path.

    Fail-closed shape mirrors FileSink: ONLY a 404 on GET reads as "reachable but empty"
    (the legit first run). Any other non-2xx, a connection/TLS/timeout error, garbage body,
    or a 3xx — deliberately NOT followed; a redirected pin store is a tamper signal, and
    following it would hand the request to wherever Location points — raises AnchorError.

    The bearer token, when configured, is read from a FILE per call (rotation on disk is
    picked up, same read-fresh posture as the contain trip) and the shared secret-file
    permission floor refuses an exposed token before any request carries it.
    """

    _TIMEOUT = 10.0  # seconds; the anchor is consulted at startup and on audit_verify, not hot

    def __init__(self, url: str, token_path: str | None = None, ca_bundle: str | None = None):
        self.url = url
        self.token_path = token_path
        self.ca_bundle = ca_bundle
        # Through the house TLS seam (_tls.httpx_verify), same as every backend client — the
        # raw-string verify= form is deprecated in httpx and this channel is the last place a
        # deprecation should be allowed to age into breakage (lens catch 2026-08-20: this was
        # the one construction site bypassing the seam). Loaded EAGERLY, so a bad CA path
        # refuses at build/config time (the fail-closed startup), never on the first request.
        try:
            self._verify = httpx_verify(ca_bundle) if ca_bundle else True
        except OSError as e:
            raise RuntimeError(
                f"PROXIMO_AUDIT_ANCHOR_CA_BUNDLE {ca_bundle!r} could not be loaded: {e}"
            ) from e

    @property
    def name(self) -> str:
        return "http"

    def _headers(self) -> dict:
        if not self.token_path:
            return {}
        # Per-call, fail-closed BEFORE any bytes leave: perms floor first, then read.
        refuse_exposed_secret(self.token_path, "anchor bearer token file")
        try:
            with open(self.token_path, encoding="utf-8") as f:
                token = f.read().strip()
        except OSError as e:
            raise AnchorError(
                f"http anchor sink: cannot read token file {self.token_path!r}: {e}"
            ) from e
        if not token:
            raise AnchorError(
                f"http anchor sink: token file {self.token_path!r} is empty (fail-closed)"
            )
        return {"Authorization": f"Bearer {token}"}

    def _client(self) -> httpx.Client:
        # trust_env stays default (True): an env-configured egress proxy still cannot forge a
        # pin on an https:// URL — CONNECT tunneling keeps TLS end-to-end against the real
        # receiver's certificate — and a deployment that needs a proxy to reach its pin store
        # is legitimate. Stated here so the module's no-weakening posture reads as considered,
        # not as having missed the proxy env vars.
        return httpx.Client(verify=self._verify, timeout=self._TIMEOUT,
                            follow_redirects=False)

    def publish(self, head: str, ts: str, node: str, ledger_path: str,
                entries: int | None = None) -> None:
        payload: dict = {"head": head, "ts": ts, "node": node, "ledger_path": ledger_path}
        if entries is not None:
            payload["entries"] = entries
        try:
            with self._client() as c:
                r = c.put(self.url, json=payload, headers=self._headers())
        except httpx.HTTPError as e:
            raise AnchorError(f"http anchor sink: cannot publish head to {self.url!r}: {e}") from e
        if r.status_code not in (200, 201, 204):
            raise AnchorError(
                f"http anchor sink: publish to {self.url!r} answered {r.status_code} "
                f"(fail-closed; expected 200/201/204)"
            )

    def last_pin(self) -> dict | None:
        try:
            with self._client() as c:
                r = c.get(self.url, headers=self._headers())
        except httpx.HTTPError as e:
            raise AnchorError(f"http anchor sink: cannot fetch pin from {self.url!r}: {e}") from e
        if r.status_code == 404:
            # The ONE unambiguous "reachable but empty" signal — the legit first run.
            return None
        if r.status_code != 200:
            raise AnchorError(
                f"http anchor sink: fetch from {self.url!r} answered {r.status_code} "
                f"(fail-closed; only 200 = pin, 404 = first run)"
            )
        return _validate_pin(r.text, f"http anchor sink {self.url!r}")


class SyslogSink(AnchorSink):
    """Append the ledger head to a syslog collector — the WRITE-ONLY witness sink.

    This is SECURITY.md's "have root independently retain each published head: a root-only
    append log" sentence, mechanized: syslog's append-only nature at the collector is exactly
    the retained-history property the anchor's trust model asks the operator to provide. The
    trade is stated as the limit it is: **syslog cannot hand a pin back**, so ``fetches_pins``
    is False, automatic startup verification is NOT available with this sink alone (pair it
    with ``PROXIMO_AUDIT_EXPECTED_HEAD``, a readable sink, or collector-side comparison), and
    every clean ``audit_verify`` APPENDS the current head to the trail instead of re-pinning
    one resource. The anti-poisoning v.ok guard still holds: a failed verify appends nothing.

    Transports — chosen so a publish can always FAIL, because a publish that cannot fail is
    not a check: a unix socket path (``/dev/log`` — datagram first, stream if the socket
    refuses datagrams, an AnchorError naming BOTH attempts if neither connects), or
    ``host:port`` TCP — TLS-wrapped and verified against ``PROXIMO_AUDIT_ANCHOR_CA_BUNDLE``
    when it is set (the RFC 5425 shape), plaintext with a loud build-time warning otherwise.
    **UDP is NOT supported**: a fire-and-forget datagram to a remote host cannot report
    failure, so a "publish" over it would read as done whether or not anything received it.

    Frames are RFC 5424-shaped, LF-terminated (RFC 6587 non-transparent framing). Header
    slots carry SANITIZED tokens only — LF is the frame delimiter, so a raw header field
    could forge a second record; full fidelity travels in the JSON payload, where
    ``json.dumps`` escapes control characters.
    """

    fetches_pins = False
    _TIMEOUT = 10.0  # seconds; same posture as HttpSink

    def __init__(self, address: str, ca_bundle: str | None = None):
        self.address = address
        self.ca_bundle = ca_bundle
        if address.startswith("/"):
            self._unix, self._host, self._port = address, None, None
        else:
            host, sep, port = address.rpartition(":")
            if not sep or not port.isdigit():
                raise RuntimeError(
                    f"PROXIMO_AUDIT_ANCHOR_SYSLOG_ADDRESS must be a unix socket path "
                    f"(starts with /) or host:port for TCP, got {address!r}"
                )
            self._unix, self._host, self._port = None, host, int(port)
            if ca_bundle:
                # Eager, like HttpSink: a bad CA path refuses at build/config time.
                try:
                    self._ssl_ctx = httpx_verify(ca_bundle)
                except OSError as e:
                    raise RuntimeError(
                        f"PROXIMO_AUDIT_ANCHOR_CA_BUNDLE {ca_bundle!r} could not be loaded: {e}"
                    ) from e
            else:
                self._ssl_ctx = None
                # Same stance, same rationale as the http sink's plain-http warn: warn, not
                # refuse (the FileSink-over-NFS precedent), but loudly — on the tamper channel
                # a plaintext hop lets an on-path attacker drop or alter the witnessed heads.
                warnings.warn(
                    "PROXIMO_AUDIT_ANCHOR_SYSLOG_ADDRESS is plaintext TCP — an on-path "
                    "attacker can drop or alter witnessed heads in transit. Set "
                    "PROXIMO_AUDIT_ANCHOR_CA_BUNDLE to speak TLS (RFC 5425) to the collector "
                    "unless this hop is genuinely trusted.",
                    stacklevel=2,
                )

    @property
    def name(self) -> str:
        return "syslog"

    @staticmethod
    def _header_token(value: str, extra: str = "._-") -> str:
        """RFC-safe header token: alnum plus ``extra``, capped, '-' when empty. EVERY header
        slot goes through this — the frame delimiter is LF, so a header field must be
        structurally incapable of carrying one (or any whitespace, which splits RFC 5424
        fields). Full fidelity travels in the JSON payload instead."""
        cleaned = "".join(c for c in value if c.isalnum() or c in extra)[:48]
        return cleaned or "-"

    def _frame(self, payload: dict, ts: str, node: str) -> bytes:
        # PRI 134 = facility local0 (16) * 8 + severity info (6). RFC 5424 header, JSON MSG.
        # The TIMESTAMP slot keeps the ISO-8601 charset (:.+- on top of alnum); node keeps
        # hostname charset. Both are tokens, never raw input.
        line = (f"<134>1 {self._header_token(ts, extra=':.+-')} "
                f"{self._header_token(node)} proximo-anchor - AUDITHEAD - "
                f"{json.dumps(payload, separators=(',', ':'))}\n")
        return line.encode()

    def publish(self, head: str, ts: str, node: str, ledger_path: str,
                entries: int | None = None) -> None:
        payload: dict = {"head": head, "ts": ts, "node": node, "ledger_path": ledger_path}
        if entries is not None:
            payload["entries"] = entries
        frame = self._frame(payload, ts, node)
        if self._unix is not None:
            self._send_unix(frame)
        else:
            self._send_tcp(frame)

    def _send_unix(self, frame: bytes) -> None:
        # /dev/log is SOCK_DGRAM on Linux; some syslogds listen SOCK_STREAM. Try datagram,
        # then stream — and if NEITHER connects, name both attempts: a quiet fallback that
        # then fails quietly would hide which transport was wrong.
        errors = []
        for kind, label in ((socket.SOCK_DGRAM, "datagram"), (socket.SOCK_STREAM, "stream")):
            try:
                with socket.socket(socket.AF_UNIX, kind) as sk:
                    sk.settimeout(self._TIMEOUT)
                    sk.connect(self._unix)
                    sk.sendall(frame)
                return
            except OSError as e:
                errors.append(f"{label}: {e}")
        raise AnchorError(
            f"syslog anchor sink: cannot publish to unix socket {self._unix!r} "
            f"({'; '.join(errors)})"
        )

    def _send_tcp(self, frame: bytes) -> None:
        try:
            with socket.create_connection((self._host, self._port),
                                          timeout=self._TIMEOUT) as sk:
                if self._ssl_ctx is not None:
                    with self._ssl_ctx.wrap_socket(sk, server_hostname=self._host) as tls:
                        tls.sendall(frame)
                else:
                    sk.sendall(frame)
        except OSError as e:  # ssl.SSLError subclasses OSError — cert refusal lands here too
            raise AnchorError(
                f"syslog anchor sink: cannot publish to {self.address!r}: {e}"
            ) from e

    def last_pin(self) -> dict | None:
        raise AnchorError(
            "syslog anchor sink is write-only: it appends heads to the collector's trail and "
            "cannot read a pin back — check fetches_pins before fetching"
        )


def build_anchor_sink(sink_type: str, file_path: str | None, url: str | None = None,
                      token_path: str | None = None, ca_bundle: str | None = None,
                      syslog_address: str | None = None) -> AnchorSink | None:
    """Instantiate the configured anchor sink, or ``None`` when disabled (``"none"``/``""``).

    Raises ``RuntimeError`` (a config error) on an unknown sink type, a ``"file"`` sink with no
    path, an ``"http"`` sink with no URL, or a ``"syslog"`` sink with no address — a
    misconfigured anchor must fail loud at load, not silently disable tail-attack detection.
    Reaching a READABLE sink (fetching ``last_head()``) is the caller's fail-closed step;
    write-only sinks (``fetches_pins`` False) have nothing to fetch and the caller skips it.
    """
    sink = (sink_type or "none").strip().lower()
    if sink in ("", "none"):
        return None
    if sink not in _KNOWN_SINKS:
        raise RuntimeError(
            f"PROXIMO_AUDIT_ANCHOR_SINK={sink!r} is not a recognized sink "
            f"(supported: 'none', 'file', 'http', 'syslog')"
        )
    if sink == "syslog":
        if not syslog_address or not syslog_address.strip():
            raise RuntimeError(
                "PROXIMO_AUDIT_ANCHOR_SYSLOG_ADDRESS is required for the syslog sink "
                "(a unix socket path like /dev/log, or host:port for TCP)"
            )
        return SyslogSink(syslog_address.strip(),
                          ca_bundle=(ca_bundle or "").strip() or None)
    if sink == "http":
        if not url or not url.strip():
            raise RuntimeError(
                "PROXIMO_AUDIT_ANCHOR_SINK=http requires PROXIMO_AUDIT_ANCHOR_URL "
                "(the off-box pin resource to GET/PUT the ledger head on)"
            )
        u = url.strip()
        if u.startswith("http://"):
            # Warn, not refuse — the FileSink-over-NFS precedent: that transport has no
            # crypto either, and the module's HONESTY note (not the config surface) carries
            # the trust model. But say it loudly, because on a tamper anchor a plaintext hop
            # means an on-path attacker can serve back any pin they like.
            warnings.warn(
                "PROXIMO_AUDIT_ANCHOR_URL is plaintext http:// — an on-path attacker can "
                "rewrite the pin in transit, which defeats the anchor against that attacker. "
                "Use https:// (PROXIMO_AUDIT_ANCHOR_CA_BUNDLE for a private CA) unless this "
                "hop is genuinely trusted.",
                stacklevel=2,
            )
        elif not u.startswith("https://"):
            raise RuntimeError(
                f"PROXIMO_AUDIT_ANCHOR_URL must be an http(s):// URL, got {u!r}"
            )
        return HttpSink(u, token_path=(token_path or "").strip() or None,
                        ca_bundle=(ca_bundle or "").strip() or None)
    # sink == "file"
    if not file_path or not file_path.strip():
        raise RuntimeError(
            "PROXIMO_AUDIT_ANCHOR_SINK=file requires PROXIMO_AUDIT_ANCHOR_FILE_PATH "
            "(the off-box file to pin the ledger head to)"
        )
    return FileSink(file_path.strip())
