"""TLS verify helper shared by the PVE and PBS backends.

httpx deprecated passing a CA-bundle *path* string to ``verify=``; the documented
replacement is an ``ssl.SSLContext``. ``verify=True``/``verify=False`` (bool) are
unchanged. Both backends send an API-token secret over the wire, so they share one
implementation to keep their TLS behavior identical.
"""

from __future__ import annotations

import hashlib
import re
import ssl


def httpx_verify(value: bool | str) -> bool | ssl.SSLContext:
    """Translate a verify setting into an httpx ``verify=`` value without the deprecated str form.

    - ``bool`` (True/False): passed through unchanged.
    - ``str``: treated as a CA-bundle path and loaded into a default SSL context
      (``cafile=``). The file is read eagerly here, so a bad CA path fails fast at
      backend construction rather than on the first request — the right tradeoff for
      a backend that sends a token secret over the wire.

    Note ``isinstance(True, str)`` is False, so bool values never hit the str branch.

    The pinned context enables ``VERIFY_X509_PARTIAL_CHAIN`` so the pin means the same
    thing on every interpreter: trust exactly this file as an anchor. Python 3.13
    changed the defaults ``create_default_context()`` applies (3.12 sets neither
    ``VERIFY_X509_STRICT`` nor ``VERIFY_X509_PARTIAL_CHAIN``; 3.13 sets both), and
    without partial chain a pinned *leaf* is not an anchor at all — the same pinned
    file that verified under 3.13 failed under 3.12 with "unable to get local issuer
    certificate". Pinning a node's leaf is the robust choice against Proxmox: it
    generates its cluster CA with ``CA:TRUE`` but no ``keyUsage`` extension, and a
    strict-verifying stack rejects that CA outright ("CA cert does not include key
    usage extension") whatever this flag says.

    ``VERIFY_X509_STRICT`` is deliberately left alone. Adding it would break CA pins
    on 3.12, and clearing it on 3.13 would quietly relax conformance checking the
    operator never asked us to relax.
    """
    if isinstance(value, str):
        ctx = ssl.create_default_context(cafile=value)
        ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        return ctx
    return value


_FP_RE = re.compile(r"^[0-9a-f]{64}$")


def normalize_fingerprint(value: str) -> str:
    """Normalize a SHA-256 certificate fingerprint to 64 lowercase hex chars.

    Accepts the colon-separated uppercase form the PBS GUI displays (AA:BB:...:FF),
    bare hex in either case, and surrounding whitespace. Anything else raises
    ``ValueError`` — a garbled pin must refuse loudly at construction, never
    degrade into "no pin".
    """
    fp = value.strip().replace(":", "").lower()
    if not _FP_RE.match(fp):
        raise ValueError(
            f"invalid certificate fingerprint {value!r} — expected the SHA-256 hash as "
            "64 hex chars, with or without colons (the form the PBS GUI displays)"
        )
    return fp


class _FingerprintPinnedContext(ssl.SSLContext):
    """An SSLContext that accepts exactly ONE server certificate: the pinned SHA-256.

    Chain/hostname validation is intentionally OFF — the pin *replaces* it (the
    proxmox-backup-client ``--fingerprint`` idiom for self-signed PBS boxes). The
    check runs inside ``wrap_socket`` immediately after the handshake, so on a
    mismatch the socket is closed before one byte of HTTP (i.e. the token header)
    leaves the client. Sync-transport only: httpx.Client reaches wrap_socket;
    an async client (wrap_bio) would bypass the check, so keep this off async paths.
    """

    _pin: str  # set by fingerprint_pinned_context()

    def wrap_socket(self, *args, **kwargs):  # type: ignore[override]
        ssock = super().wrap_socket(*args, **kwargs)
        try:
            der = ssock.getpeercert(binary_form=True)
            observed = hashlib.sha256(der).hexdigest() if der else None
            if observed != self._pin:
                raise ssl.SSLCertVerificationError(
                    f"server certificate fingerprint mismatch: pinned {self._pin}, "
                    f"observed {observed or 'no certificate'} — refusing before any "
                    "request (token never sent)"
                )
        except BaseException:
            ssock.close()
            raise
        return ssock


def fingerprint_pinned_context(fingerprint: str) -> ssl.SSLContext:
    """Build a client SSLContext pinned to one server-cert SHA-256 (see the class note).

    Raises ``ValueError`` on a garbled fingerprint — callers surface that as their
    own construction-time error.
    """
    pin = normalize_fingerprint(fingerprint)
    ctx = _FingerprintPinnedContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # the pin, not the name, is the identity
    ctx.verify_mode = ssl.CERT_NONE  # chain validation replaced by the exact-cert pin
    ctx._pin = pin
    return ctx


_VTLS_FALSY = frozenset({"0", "false", "off", "no"})


def parse_verify_tls(value: object) -> bool:
    """True unless ``value`` is a recognized falsy form. Handles a TOML bool/int (False, 0),
    a TOML/env string ("0", "false", "off", "no" — any case), and the env default. Everything
    else => verification ON (fail-secure). Shared so PBS/PMG/PDM match PVE's falsy semantics."""
    return str(value).strip().lower() not in _VTLS_FALSY
