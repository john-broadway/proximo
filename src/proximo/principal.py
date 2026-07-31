"""Principal-in-ledger: WHO asked, on every PROVE entry (spec 2026-07-16).

Two layers. The NAME TAG: the operator declares who this instance serves
(``PROXIMO_PRINCIPAL``) and every ledger entry carries it. The CAMERA: on network faces a
caller may present a signed ES256 badge (``Proximo-Principal`` header) verified against
operator-pinned keys — see the crypto half below (Task 4 adds it).

Identity, never authority: the Proxmox token remains the only authorization boundary.
Base-import-safe: no starlette / cryptography imports at module top.
"""
from __future__ import annotations

import base64
import contextvars
import dataclasses
import hashlib
import json
import os
import stat
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Only for static typing — the real import stays inside _require_crypto() so the module
    # remains base-import-safe (import proximo.principal must not require `cryptography`).
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

_MAX_ID_LEN = 120

# Per-request verified caller (network faces). None => no verified caller in this context.
_active_caller: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "proximo_active_caller", default=None
)

_serving_face: str = "stdio"


def sanitize_id(raw: str) -> str:
    """Printable, single-line, length-capped — same posture as audit._sanitize_target."""
    cleaned = "".join(ch for ch in raw if ch.isprintable() and ch not in "\r\n")
    return cleaned.strip()[:_MAX_ID_LEN]


def process_principal() -> str | None:
    """The operator-declared name tag (``PROXIMO_PRINCIPAL``). None when unset/blank."""
    raw = os.environ.get("PROXIMO_PRINCIPAL", "")
    return sanitize_id(raw) or None


def set_serving_face(face: str) -> None:
    """Which door this process serves ("stdio" | "http" | "a2a" | ...). Set once per entrypoint."""
    global _serving_face
    _serving_face = sanitize_id(face) or "stdio"


def serving_face() -> str:
    return _serving_face


def set_active_caller(caller: str | None) -> contextvars.Token:
    return _active_caller.set(caller)


def reset_active_caller(token: contextvars.Token) -> None:
    _active_caller.reset(token)


def principal_feature_active() -> bool:
    """True when the operator configured either layer — gates session entries (byte-compat)."""
    return bool(process_principal() or os.environ.get("PROXIMO_CALLER_KEYS_DIR"))


def ledger_principal() -> dict | None:
    """The ``principal`` object for a PROVE entry — verified caller wins, else the name tag."""
    caller = _active_caller.get()
    if caller:
        return {"id": caller, "via": "verified", "face": _serving_face}
    tag = process_principal()
    if tag:
        return {"id": tag, "via": "spawn", "face": _serving_face}
    return None


# --- badge crypto (the camera) -----------------------------------------------------------
#
# Compact JWS, ES256 only. A caller badge is minted offline (mint_badge) against an operator's
# EC P-256 private key, pinned as a public JWK (public_jwk) named `<sub>.jwk` in a pin directory,
# and verified (verify_badge) on the receiving face against that pin store (load_pins). No
# authority flows from a badge — it names WHO, the Proxmox token still gates WHAT.


class BadgeError(ValueError):
    """A badge that must not be trusted. Message never echoes the badge itself."""


@dataclasses.dataclass(frozen=True)
class PinnedCaller:
    name: str
    kid: str
    public_key: EllipticCurvePublicKey


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_dec(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _thumbprint(x: str, y: str) -> str:
    """RFC 7638 JWK thumbprint over the fixed EC P-256 member set, sorted + separator-canonical."""
    canon = json.dumps({"crv": "P-256", "kty": "EC", "x": x, "y": y},
                        separators=(",", ":"), sort_keys=True)
    return _b64url(hashlib.sha256(canon.encode()).digest())


def _require_crypto():
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        return ec, utils, hashes, serialization
    except ImportError as e:
        raise RuntimeError(
            "caller badges need the 'cryptography' package — install the [http], [a2a] or "
            "[mcp-http] extra"
        ) from e


def public_jwk(private_key_pem: bytes, name: str) -> dict:
    """The public JWK an operator pins as ``<name>.jwk``."""
    _, _, _, serialization = _require_crypto()
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    nums = key.public_key().public_numbers()
    x, y = (_b64url(n.to_bytes(32, "big")) for n in (nums.x, nums.y))
    return {"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": _thumbprint(x, y),
            "proximo_caller": sanitize_id(name)}


def mint_badge(private_key_pem: bytes, sub: str, *, iat: int | None = None,
               exp: int | None = None) -> str:
    """Sign a compact ES256 badge claiming ``sub``, under ``private_key_pem``."""
    ec_mod, utils, hashes, serialization = _require_crypto()
    key = serialization.load_pem_private_key(private_key_pem, password=None)
    jwk = public_jwk(private_key_pem, sub)
    header = {"alg": "ES256", "typ": "JOSE", "kid": jwk["kid"]}
    payload: dict = {"sub": sanitize_id(sub), "iat": iat or int(time.time())}
    if exp is not None:
        payload["exp"] = exp
    signing_input = f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}." \
                    f"{_b64url(json.dumps(payload, separators=(',', ':')).encode())}"
    der = key.sign(signing_input.encode(), ec_mod.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)          # DER -> raw R||S (JOSE form)
    return f"{signing_input}.{_b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


_PINS_CACHE: dict[str, tuple[tuple[int, int], dict[str, PinnedCaller]]] = {}


def load_pins_live(dir_path: str) -> dict[str, PinnedCaller]:
    """`load_pins` behind a stat-gated cache, so the pin store stays live for a RUNNING process.

    SECURITY.md tells operators that deleting a caller's pin file IS the revocation. That was only
    true of a fresh `load_pins()`: the perimeter loaded pins ONCE at app-build time and held the
    dict for the process lifetime, so a deleted caller kept being honoured until restart. Re-stat
    the directory on each protected request and reload only when it changed — create, delete and
    rename all move the directory's mtime, so the documented revocation and enrolment paths both
    take effect immediately, at the cost of one `stat` per request rather than a full re-read.

    RESIDUAL, stated rather than implied: rewriting an EXISTING pin file in place does not move the
    directory's mtime and so is not picked up until the next directory change or a restart. That
    edit requires ownership of the file — `load_pins` refuses group- or world-writable pins — so it
    is not a path a third party can take.
    """
    try:
        st = os.stat(dir_path)
    except OSError as e:
        raise RuntimeError(f"PROXIMO_CALLER_KEYS_DIR={dir_path!r} unreadable: {e}") from e
    stamp = (st.st_mtime_ns, st.st_ctime_ns)
    hit = _PINS_CACHE.get(dir_path)
    if hit is not None and hit[0] == stamp:
        return hit[1]
    pins = load_pins(dir_path)
    _PINS_CACHE[dir_path] = (stamp, pins)
    return pins


def load_pins(dir_path: str) -> dict[str, PinnedCaller]:
    """Pin store: ``<name>.jwk`` files. Fail-LOUD (RuntimeError) on a bad dir / symlink / perms."""
    _require_crypto()  # friendly named-extra error before ANY cryptography symbol is touched
    from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, EllipticCurvePublicNumbers
    try:
        entries = sorted(os.listdir(dir_path))
    except OSError as e:
        raise RuntimeError(f"PROXIMO_CALLER_KEYS_DIR={dir_path!r} unreadable: {e}") from e
    # The DIRECTORY itself may be a symlink — checked here, not just per-file below. A symlinked
    # pin dir redirects the whole trust store in one hop, which is strictly worse than any single
    # redirected pin file, and the per-file islink() check cannot see it.
    if os.path.islink(dir_path):
        raise RuntimeError(f"PROXIMO_CALLER_KEYS_DIR={dir_path!r} is a symlink — refusing.")
    st = os.stat(dir_path)
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError(
            f"PROXIMO_CALLER_KEYS_DIR={dir_path!r} is group- or world-writable — refusing.")
    pins: dict[str, PinnedCaller] = {}
    for fname in entries:
        if not fname.endswith(".jwk"):
            continue
        fpath = os.path.join(dir_path, fname)
        if os.path.islink(fpath):
            # Checked BEFORE any open — refuses even a dangling symlink (no target to redirect
            # onto yet: it's the redirection capability itself that's refused, not just a
            # currently-reachable escape). O_NOFOLLOW on the open below is defense in depth.
            raise RuntimeError(f"pin file {fpath!r} is a symlink — refusing.")
        # A tight directory does not protect a loose file inside it. Anyone who can rewrite one
        # .jwk substitutes that caller's public key and silently becomes them, so the per-file
        # mode is its own floor rather than something the directory check covers.
        if os.stat(fpath).st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise RuntimeError(f"pin file {fpath!r} is group- or world-writable — refusing.")
        # One guard from raw file bytes through the constructed EC point: any parse/shape
        # failure along the way (non-JSON garbage, JSON that isn't an object, a dict missing
        # x/y or carrying malformed base64, an (x, y) pair off the curve) fails loud as the
        # contract's RuntimeError — never a raw traceback, never an echo of the file's content.
        try:
            with open(fpath, encoding="utf-8",
                      opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW)) as f:
                jwk = json.load(f)
            if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
                raise RuntimeError(f"pin file {fpath!r}: only EC P-256 JWKs are accepted.")
            x_b, y_b = _b64url_dec(jwk["x"]), _b64url_dec(jwk["y"])
            pub = EllipticCurvePublicNumbers(
                int.from_bytes(x_b, "big"), int.from_bytes(y_b, "big"), SECP256R1()).public_key()
        except OSError as e:
            # Closes the islink()-check-to-open() TOCTOU window: a symlink planted in the
            # instant between the check above and this open trips O_NOFOLLOW (ELOOP), which
            # must still surface as the contract's RuntimeError, not a raw OSError.
            raise RuntimeError(f"pin file {fpath!r} could not be read safely") from e
        except RuntimeError:
            raise   # the kty/crv mismatch above already carries its own specific message
        except Exception as e:
            # json.JSONDecodeError (non-JSON content), AttributeError (valid JSON that isn't
            # an object — list/string/number/null), KeyError (missing x/y), binascii.Error /
            # ValueError (malformed base64 or a coordinate pair off the curve) all land here.
            raise RuntimeError(f"pin file {fpath!r}: invalid EC P-256 JWK") from e
        kid = _thumbprint(jwk["x"], jwk["y"])   # recomputed — never trusted from the file's own kid
        name = sanitize_id(fname[:-4])
        if kid in pins:
            raise RuntimeError(
                f"PROXIMO_CALLER_KEYS_DIR: pin files for {pins[kid].name!r} and {name!r} resolve "
                "to the same key — refusing ambiguous identity binding")
        # The mirror case, and the one that actually grants authority: two DIFFERENT keys whose
        # filenames sanitize to the same identity. sanitize_id strips control bytes and POSIX
        # filenames may carry them, so `fleet-7.jwk` and `fleet-7\x01.jwk` are distinct files
        # that both mean 'fleet-7' — two unrelated holders authenticating as one caller, which
        # is precisely the ambiguity the kid check above exists to refuse.
        if any(p.name == name for p in pins.values()):
            raise RuntimeError(
                f"PROXIMO_CALLER_KEYS_DIR: two pin files resolve to the same identity {name!r} "
                "— refusing ambiguous identity binding")
        pins[kid] = PinnedCaller(name=name, kid=kid, public_key=pub)
    return pins


def verify_badge(badge: str, pins: dict[str, PinnedCaller], *, now: int | None = None) -> str:
    """Verify a compact ES256 badge against the pin store. Returns the verified sub."""
    ec_mod, utils, hashes, _ = _require_crypto()
    try:
        h_b64, p_b64, s_b64 = badge.strip().split(".")
        header = json.loads(_b64url_dec(h_b64))
        payload = json.loads(_b64url_dec(p_b64))
        sig = _b64url_dec(s_b64)
        if not isinstance(header, dict) or not isinstance(payload, dict):
            # A structurally-valid JWS always carries JSON *objects* for header/payload — an
            # int/str/list/null here is not a signature-verification question at all, it's a
            # malformed badge, and must not reach a bare `.get()` (AttributeError) below.
            raise ValueError("header/payload must be JSON objects")
    except Exception as e:
        raise BadgeError("malformed badge") from e
    if header.get("alg") != "ES256":                       # structural — before ANY key handling
        raise BadgeError("badge alg must be ES256")
    pin = pins.get(str(header.get("kid", "")))
    if pin is None:
        raise BadgeError("badge kid matches no pinned caller")
    if len(sig) != 64:                                      # JOSE raw R||S length, before DER conv
        raise BadgeError("malformed badge signature")
    der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"),
                                      int.from_bytes(sig[32:], "big"))
    try:
        pin.public_key.verify(der, f"{h_b64}.{p_b64}".encode(), ec_mod.ECDSA(hashes.SHA256()))
    except Exception as e:
        raise BadgeError("badge signature does not verify") from e
    if sanitize_id(str(payload.get("sub", ""))) != pin.name:
        raise BadgeError("badge sub does not match the pinned name for this key")
    exp = payload.get("exp")
    if exp is not None:
        try:
            exp_ts = int(exp)
        except (TypeError, ValueError, OverflowError) as e:
            # non-numeric (TypeError/ValueError) or non-finite — json accepts the Infinity/
            # -Infinity/NaN extension by default, and int(float("inf")) raises OverflowError.
            # Refuse, but do not claim a check that never ran: nothing here was compared
            # against the clock, so "expired" would assert a state the code never evaluated.
            raise BadgeError("badge exp claim is malformed") from e
        if exp_ts <= (now if now is not None else int(time.time())):
            raise BadgeError("badge expired")
    return pin.name
