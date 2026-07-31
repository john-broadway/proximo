"""Badge crypto: ES256-only, pinned callers, sub-binding (spec 2026-07-16)."""
import base64
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from proximo.principal import BadgeError, load_pins, mint_badge, public_jwk, verify_badge


def _keypair_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _mint_raw(pem: bytes, header: object, payload: object) -> str:
    """Sign an arbitrary (possibly non-dict) header/payload pair directly — bypasses
    mint_badge's dict-shaped payload, so verify_badge's structural guards can be exercised
    against a badge that carries a genuinely valid signature."""
    key = serialization.load_pem_private_key(pem, password=None)
    signing_input = f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(payload).encode())}"
    der = key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return f"{signing_input}.{_b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


@pytest.fixture()
def pin_dir(tmp_path):
    pem = _keypair_pem()
    jwk = public_jwk(pem, "fleet-7")
    (tmp_path / "fleet-7.jwk").write_text(json.dumps(jwk))
    return str(tmp_path), pem


def test_round_trip(pin_dir):
    d, pem = pin_dir
    badge = mint_badge(pem, "fleet-7")
    assert verify_badge(badge, load_pins(d)) == "fleet-7"


def test_tamper_refused(pin_dir):
    d, pem = pin_dir
    h, p, s = mint_badge(pem, "fleet-7").split(".")
    forged_payload = p[:-2] + ("AA" if p[-2:] != "AA" else "BB")
    with pytest.raises(BadgeError):
        verify_badge(f"{h}.{forged_payload}.{s}", load_pins(d))


def test_alg_confusion_refused(pin_dir):
    """HS256 / none in the header is refused STRUCTURALLY, before any key handling."""
    import base64
    d, pem = pin_dir
    _, p, s = mint_badge(pem, "fleet-7").split(".")
    for alg in ("HS256", "none", ""):
        hdr = base64.urlsafe_b64encode(
            json.dumps({"alg": alg, "typ": "JOSE"}).encode()).rstrip(b"=").decode()
        with pytest.raises(BadgeError, match="ES256"):
            verify_badge(f"{hdr}.{p}.{s}", load_pins(d))


def test_sub_binding(pin_dir, tmp_path):
    """A valid signature under pinned key A claiming name B is refused."""
    d, pem = pin_dir
    badge = mint_badge(pem, "ci-runner")     # signed by fleet-7's key, claims ci-runner
    with pytest.raises(BadgeError, match="sub"):
        verify_badge(badge, load_pins(d))


def test_unpinned_key_refused(pin_dir):
    d, _ = pin_dir
    stranger = _keypair_pem()
    with pytest.raises(BadgeError):
        verify_badge(mint_badge(stranger, "fleet-7"), load_pins(d))


def test_exp_absent_accepted_present_enforced(pin_dir):
    d, pem = pin_dir
    now = int(time.time())
    assert verify_badge(mint_badge(pem, "fleet-7"), load_pins(d)) == "fleet-7"          # badge model
    ok = mint_badge(pem, "fleet-7", exp=now + 60)
    assert verify_badge(ok, load_pins(d), now=now) == "fleet-7"
    stale = mint_badge(pem, "fleet-7", exp=now - 1)
    with pytest.raises(BadgeError, match="expired"):
        verify_badge(stale, load_pins(d), now=now)


def test_pin_file_symlink_refused(tmp_path):
    pem = _keypair_pem()
    real = tmp_path / "real.jwk"
    real.write_text(json.dumps(public_jwk(pem, "fleet-7")))
    os.symlink(real, tmp_path / "fleet-7.jwk")
    real.rename(tmp_path / "not-a-jwk")      # leave only the symlink named fleet-7.jwk
    with pytest.raises(RuntimeError, match="symlink"):
        load_pins(str(tmp_path))


def test_pin_load_missing_dir_fail_loud():
    with pytest.raises(RuntimeError):
        load_pins("/nonexistent/callers")


def test_revocation_is_unpin(pin_dir):
    d, pem = pin_dir
    badge = mint_badge(pem, "fleet-7")
    os.unlink(os.path.join(d, "fleet-7.jwk"))
    with pytest.raises(BadgeError):
        verify_badge(badge, load_pins(d))


# --- review round: exception hygiene — every failure path is BadgeError / RuntimeError,
# never a raw traceback (findings 1-4 of the 2026-07-16 adversarial review) ---


def test_header_not_dict_refused(pin_dir):
    """A header that decodes to non-dict JSON (int/str/list/null) must not crash `.get()` —
    it must be refused as a malformed badge, UNAUTHENTICATED, no signature needed."""
    d, pem = pin_dir
    _, p, s = mint_badge(pem, "fleet-7").split(".")
    hdr = _b64u(json.dumps(5).encode())
    with pytest.raises(BadgeError):
        verify_badge(f"{hdr}.{p}.{s}", load_pins(d))


def test_payload_not_dict_refused(pin_dir):
    """A validly-signed badge whose payload decodes to non-dict JSON must not crash
    `.get("sub")` — refused as malformed, not a raw AttributeError."""
    d, pem = pin_dir
    jwk = public_jwk(pem, "fleet-7")
    header = {"alg": "ES256", "typ": "JOSE", "kid": jwk["kid"]}
    badge = _mint_raw(pem, header, ["not", "a", "dict"])
    with pytest.raises(BadgeError):
        verify_badge(badge, load_pins(d))


def test_load_pins_malformed_jwk_missing_x_refused(tmp_path):
    """An EC/P-256 JWK missing its `x` member must fail loud (RuntimeError), not KeyError."""
    pem = _keypair_pem()
    jwk = public_jwk(pem, "fleet-7")
    del jwk["x"]
    (tmp_path / "fleet-7.jwk").write_text(json.dumps(jwk))
    with pytest.raises(RuntimeError):
        load_pins(str(tmp_path))


def test_exp_non_numeric_refused(pin_dir):
    """A validly-signed badge with a non-numeric `exp` must not crash `int(exp)` — refused
    as BadgeError, not a raw ValueError."""
    d, pem = pin_dir
    jwk = public_jwk(pem, "fleet-7")
    header = {"alg": "ES256", "typ": "JOSE", "kid": jwk["kid"]}
    payload = {"sub": "fleet-7", "iat": int(time.time()), "exp": "never"}
    badge = _mint_raw(pem, header, payload)
    with pytest.raises(BadgeError):
        verify_badge(badge, load_pins(d))


def test_exp_infinite_refused(pin_dir):
    """A validly-signed badge with `exp: Infinity` (json accepts the non-finite extension by
    default) must not crash `int(exp)` with OverflowError — refused as BadgeError."""
    d, pem = pin_dir
    jwk = public_jwk(pem, "fleet-7")
    header = {"alg": "ES256", "typ": "JOSE", "kid": jwk["kid"]}
    payload = {"sub": "fleet-7", "iat": int(time.time()), "exp": float("inf")}
    badge = _mint_raw(pem, header, payload)
    with pytest.raises(BadgeError):
        verify_badge(badge, load_pins(d))


def test_load_pins_missing_cryptography_gives_friendly_error(tmp_path, monkeypatch):
    """Without `cryptography` installed, load_pins must fail with a friendly, named-extra
    RuntimeError — never a raw ImportError — even before touching the (empty) pin dir."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError, match="cryptography"):
        load_pins(str(tmp_path))


# --- sibling gaps (same fail-loud contract class, closed 2026-07-16 follow-up) ---


def test_load_pins_non_dict_jwk_refused(tmp_path):
    """A `.jwk` file holding valid JSON that isn't an object (list/string/...) must fail
    loud (RuntimeError naming the file), not crash `jwk.get(...)` with AttributeError."""
    (tmp_path / "fleet-7.jwk").write_text(json.dumps([1, 2, 3]))
    with pytest.raises(RuntimeError, match="fleet-7"):
        load_pins(str(tmp_path))


def test_load_pins_malformed_json_refused(tmp_path):
    """A `.jwk` file holding non-JSON garbage must fail loud (RuntimeError naming the file),
    not propagate a raw json.JSONDecodeError."""
    (tmp_path / "fleet-7.jwk").write_text("not json{{{")
    with pytest.raises(RuntimeError, match="fleet-7"):
        load_pins(str(tmp_path))


# --- redteam fix wave (2026-07-16): duplicate-kid collision + group-writable pin dir ---


def test_duplicate_kid_same_key_different_names_refused(tmp_path):
    """Two `.jwk` files carrying the SAME EC public key under DIFFERENT names must fail
    loud, not silently collapse to one pin-store entry (last-sorted filename wins) and
    lock out the shadowed legitimate caller."""
    pem = _keypair_pem()
    jwk = public_jwk(pem, "alice")
    (tmp_path / "alice.jwk").write_text(json.dumps(jwk))
    (tmp_path / "zzz-bot.jwk").write_text(json.dumps(jwk))
    with pytest.raises(RuntimeError, match="alice.*zzz-bot|zzz-bot.*alice"):
        load_pins(str(tmp_path))


def test_pin_dir_group_writable_refused(pin_dir):
    """A group-writable pin dir (0o775) must be refused — not just world-writable."""
    d, _pem = pin_dir
    os.chmod(d, 0o775)  # noqa: S103 -- deliberately permissive, proving load_pins refuses it
    with pytest.raises(RuntimeError, match="group- or world-writable"):
        load_pins(d)


def test_pin_dir_normal_permissions_still_accepted(pin_dir):
    """Regression guard: a harmless world-READABLE (not writable) dir of public keys, mode
    0o755, must still load fine — the group/world-writable refusal must not over-restrict
    normal permissions."""
    d, _pem = pin_dir
    os.chmod(d, 0o755)  # noqa: S103 -- normal world-readable dir of PUBLIC keys, not writable
    pins = load_pins(d)
    assert len(pins) == 1


# --- pin-store hardening: three holes an adversarial lens proved live (2026-07-31) -----------
#
# The directory-level checks gave false confidence. `load_pins` stat'd the DIRECTORY for
# group/world-writability and islink'd each FILE — so a world-writable pin file inside a tight
# directory, and a symlinked directory, both sailed through. And duplicate KEYS were refused
# while duplicate NAMES were not, so two unrelated keys could authenticate as one identity.

def test_pin_directory_that_is_itself_a_symlink_is_refused(tmp_path):
    """The old test with this name symlinked a pin FILE inside a real dir — the DIRECTORY
    itself was never checked, so a symlinked pin dir was followed transparently."""
    real = tmp_path / "real-pins"
    real.mkdir()
    (real / "fleet-7.jwk").write_text(json.dumps(public_jwk(_keypair_pem(), "fleet-7")))
    link = tmp_path / "pins"
    os.symlink(real, link)
    with pytest.raises(RuntimeError, match="symlink"):
        load_pins(str(link))


def test_group_or_world_writable_pin_file_is_refused(tmp_path):
    """A tight directory does not protect a loose file inside it: anyone who can rewrite one
    .jwk silently substitutes that caller's public key and becomes them."""
    (tmp_path / "fleet-7.jwk").write_text(json.dumps(public_jwk(_keypair_pem(), "fleet-7")))
    os.chmod(tmp_path / "fleet-7.jwk", 0o666)  # noqa: S103 -- the loose mode IS the thing under test
    os.chmod(tmp_path, 0o755)  # noqa: S103 -- a TIGHT dir, so only the file mode can fail it
    with pytest.raises(RuntimeError, match="writable"):
        load_pins(str(tmp_path))


def test_two_pin_files_resolving_to_the_same_name_are_refused(tmp_path):
    """sanitize_id strips control bytes, and POSIX filenames may contain them — so
    ``fleet-7.jwk`` and ``fleet-7\\x01.jwk`` are two DIFFERENT keys that both resolve to the
    identity 'fleet-7'. Duplicate kid was already refused; duplicate NAME was not."""
    (tmp_path / "fleet-7.jwk").write_text(json.dumps(public_jwk(_keypair_pem(), "fleet-7")))
    (tmp_path / "fleet-7\x01.jwk").write_text(json.dumps(public_jwk(_keypair_pem(), "fleet-7")))
    os.chmod(tmp_path, 0o755)  # noqa: S103 -- a TIGHT dir, so only the file mode can fail it
    with pytest.raises(RuntimeError, match="same identity|ambiguous"):
        load_pins(str(tmp_path))
