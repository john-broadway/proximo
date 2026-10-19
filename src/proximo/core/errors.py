"""The one exception the spine speaks, and the message discipline it carries."""
from __future__ import annotations

from .secretfile import redact

_FINGERPRINT_ENV_VARS = {
    "PVE": "PROXIMO_FINGERPRINT",
    "PBS": "PROXIMO_PBS_FINGERPRINT",
    "PMG": "PROXIMO_PMG_FINGERPRINT",
    "PDM": "PROXIMO_PDM_FINGERPRINT",
}


class ProximoError(RuntimeError):
    """Operational error surfaced to the caller (never carries secrets).

    "Never" is enforced, not hoped: the message is passed through the output scrubber at
    construction, so a registered secret or an auth-header shape that reached an f-string
    (an API body, an argv, an echoed request) leaves as `<redacted>`."""

    def __init__(self, *args: object) -> None:
        if args and isinstance(args[0], str):
            args = (redact(args[0]), *args[1:])
        super().__init__(*args)


def fingerprint_refused(plane: str, error: ValueError) -> ProximoError:
    """Translate a garbled cert-pin ValueError (from fingerprint_pinned_context) into a
    remedy-naming refusal, so the message names the exact env var for that plane and the
    expected shape instead of forwarding the validator's raw ValueError with no pointer to the fix.
    """
    env_var = _FINGERPRINT_ENV_VARS[plane]
    return ProximoError(
        f"invalid {plane} fingerprint for {env_var} — expected the 64-char SHA-256 hex "
        f"digest (e.g. from `openssl x509 -fingerprint -sha256 -noout -in cert.pem`), "
        f"got: {error}"
    )
