"""SIGNET — ES256/JWS signing for Proximo's A2A Agent Card.

Thin, ES256-enforcing wrappers over the a2a-sdk signing helpers (``a2a.utils.signing``). Signing
goes THROUGH the SDK so canonicalization (RFC 8785 JCS) matches every compliant verifier. We always
pin ``alg=ES256`` (asymmetric) — never the SDK's ``HS256`` default — and verify with an ES256-only
allowlist, closing the JWT algorithm-confusion class.

Spec notes are internal and not in the public tree.
"""
from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from a2a.types import AgentCard
from a2a.utils.signing import (
    ProtectedHeader,
    create_agent_card_signer,
    create_signature_verifier,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwt import PyJWK


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class OperatorKey:
    """The operator's A2A signing key: private PEM (for signing) + public key + stable ``kid``."""

    private_pem: bytes
    public_key: ec.EllipticCurvePublicKey
    kid: str


def _p256_xy(pub: ec.EllipticCurvePublicKey) -> tuple[str, str]:
    nums = pub.public_numbers()
    return _b64url(nums.x.to_bytes(32, "big")), _b64url(nums.y.to_bytes(32, "big"))


def _thumbprint(pub: ec.EllipticCurvePublicKey) -> str:
    """RFC 7638 JWK thumbprint over the canonical required members — a stable, derived ``kid``."""
    x, y = _p256_xy(pub)
    members = {"crv": "P-256", "kty": "EC", "x": x, "y": y}
    canon = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url(hashlib.sha256(canon).digest())


def load_operator_key(path: str | Path) -> OperatorKey:
    """Load an EC P-256 private key (PEM) and derive its thumbprint ``kid``."""
    pem = Path(path).read_bytes()
    priv = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(priv, ec.EllipticCurvePrivateKey) or not isinstance(priv.curve, ec.SECP256R1):
        raise ValueError("A2A signing key must be an EC P-256 (prime256v1) private key for ES256.")
    pub = priv.public_key()
    return OperatorKey(private_pem=pem, public_key=pub, kid=_thumbprint(pub))


def sign_card(card: AgentCard, key: OperatorKey, *, jku: str | None = None) -> AgentCard:
    """Press an ES256/JOSE seal onto the card (mutates in place, returns it).

    ``alg`` is pinned to ES256 — never the SDK's HS256 default — so the seal is asymmetric and
    cannot be forged from the public key.
    """
    header: ProtectedHeader = {"alg": "ES256", "typ": "JOSE", "kid": key.kid, "jku": jku}
    signer = create_agent_card_signer(signing_key=key.private_pem, protected_header=header)
    return signer(card)


def make_verifier(key: OperatorKey) -> Callable[[AgentCard], None]:
    """An ES256-ONLY verifier bound to the operator's pinned public key.

    The ``algorithms=['ES256']`` allowlist refuses HS256/symmetric seals outright — closing the JWT
    algorithm-confusion class: a forger cannot downgrade to HMAC even if they know the public key.
    Raises ``SignatureVerificationError`` if no signature verifies.
    """

    pub_pem = key.public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    def key_provider(kid: str | None, jku: str | None) -> bytes:
        return pub_pem

    return create_signature_verifier(key_provider=key_provider, algorithms=["ES256"])


def verifier_for_jwk(jwk: dict[str, str]) -> Callable[[AgentCard], None]:
    """An ES256-only verifier pinned to a single trusted public JWK — the CLIENT-side safe pattern.

    The operator's public JWK must be obtained OUT-OF-BAND (pinned / trust-on-first-use), NOT fetched
    from a card's ``jku``. This verifier binds to that one key and IGNORES whatever ``kid``/``jku`` a
    card presents — so a MITM cannot substitute their own key by pointing ``jku`` at an attacker JWKS.
    A card whose seal does not verify under the pinned key (or that carries no seal) is refused with
    ``SignatureVerificationError``.
    """
    pinned = PyJWK.from_dict(jwk)

    def key_provider(kid: str | None, jku: str | None) -> PyJWK:
        return pinned

    return create_signature_verifier(key_provider=key_provider, algorithms=["ES256"])


def public_jwk(key: OperatorKey) -> dict[str, str]:
    """The operator's PUBLIC key as a JWK (RFC 7517) — public point only, no private scalar 'd'."""
    x, y = _p256_xy(key.public_key)
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": y,
        "kid": key.kid,
        "use": "sig",
        "alg": "ES256",
    }


def jwks(key: OperatorKey) -> dict[str, list[dict[str, str]]]:
    """A JWK Set wrapping the operator's public key — served at ``/.well-known/jwks.json``."""
    return {"keys": [public_jwk(key)]}
