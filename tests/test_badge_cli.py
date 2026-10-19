"""`proximo badge mint|inspect`: the operator-usable mint path (spec 2026-07-16).

Since the default-command swap (2026-10-17) `proximo` is the core's stdio door and `badge` is a
verb it hands to the shell door (`proximo.core.doors.cli.badge_main`), so these drive
`proximo.core.doors.mcp.main(argv)` with the server build stubbed to raise: a verb must never
build a server. `mint` is verified as a real round-trip against the JWK it writes, never a string
check. The exit for a refused verb is the shell door's usage code, 3, one prefixed line, no
traceback.
"""
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from proximo.core.doors import mcp
from proximo.core.perimeter.badge import _b64url_dec, load_pins, verify_badge

PREFIX = "proximo-core badge: "


@pytest.fixture(autouse=True)
def _never_a_server(monkeypatch):
    monkeypatch.setattr(mcp, "build_server", lambda *a, **k: (_ for _ in ()).throw(AssertionError("server built")))


def _keypair_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _write_key(tmp_path, name="key.pem"):
    """Write a signing key the way an operator should hold one: 0600.

    These fixtures used to inherit the default umask, i.e. a world-readable private key, and
    `proximo badge mint` accepted it silently. It no longer does (refuse_exposed_secret, the same
    floor as every other secret loaded by path), so the fixture now models correct practice
    instead of the bad practice the CLI used to tolerate.
    """
    pem = _keypair_pem()
    path = tmp_path / name
    path.write_bytes(pem)
    os.chmod(path, 0o600)
    return path


def _refused(argv, capsys) -> str:
    assert mcp.main(argv) == 3
    err = capsys.readouterr().err
    assert err.startswith(PREFIX)
    assert "Traceback" not in err
    return err


def test_badge_mint_round_trips_against_written_jwk(tmp_path, capsys):
    key_path = _write_key(tmp_path)
    jwk_out = tmp_path / "fleet-7.jwk"
    assert mcp.main(["badge", "mint", "--key", str(key_path), "--sub", "fleet-7", "--jwk-out", str(jwk_out)]) == 0
    captured = capsys.readouterr()
    badge = captured.out.strip()
    assert badge                                     # stdout carries the badge
    assert jwk_out.exists()                          # JWK written to --jwk-out
    assert "PROXIMO_CALLER_KEYS_DIR" in captured.err  # pin-file hint on stderr, not stdout
    assert badge not in captured.err                 # stdout stays clean of the hint
    pins = load_pins(str(tmp_path))
    assert verify_badge(badge, pins) == "fleet-7"     # real round-trip, not a string check


def test_badge_mint_exp_flag_lands_expected_lifetime(tmp_path, capsys):
    key_path = _write_key(tmp_path)
    before = int(time.time())
    assert mcp.main(["badge", "mint", "--key", str(key_path), "--sub", "fleet-7", "--exp", "90d",
                     "--jwk-out", str(tmp_path / "fleet-7.jwk")]) == 0
    badge = capsys.readouterr().out.strip()
    _h, p_b64, _s = badge.split(".")
    payload = json.loads(_b64url_dec(p_b64))
    expected = before + 90 * 86400
    assert abs(payload["exp"] - expected) <= 5        # a few seconds' slack


def test_badge_inspect_prints_sub_and_not_verified_note(tmp_path, capsys):
    key_path = _write_key(tmp_path)
    assert mcp.main(["badge", "mint", "--key", str(key_path), "--sub", "fleet-7",
                     "--jwk-out", str(tmp_path / "fleet-7.jwk")]) == 0
    badge = capsys.readouterr().out.strip()
    assert mcp.main(["badge", "inspect", badge]) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["payload"]["sub"] == "fleet-7"
    assert "NOT VERIFIED" in parsed["note"]


def test_badge_mint_bad_key_path_refuses_no_traceback(tmp_path, capsys):
    _refused(["badge", "mint", "--key", str(tmp_path / "does-not-exist.pem"), "--sub", "fleet-7"], capsys)


def test_badge_mint_malformed_exp_refuses_no_traceback(tmp_path, capsys):
    key_path = _write_key(tmp_path)
    err = _refused(["badge", "mint", "--key", str(key_path), "--sub", "fleet-7", "--exp", "90x"], capsys)
    assert "--exp" in err


def test_badge_inspect_malformed_badge_refuses_no_traceback(capsys):
    # Too few "."-parts to split into header/payload/signature: fail loud, never traceback.
    _refused(["badge", "inspect", "not-a-badge"], capsys)


def test_badge_mint_default_jwk_out_writes_beside_key(tmp_path, monkeypatch, capsys):
    # No --jwk-out: the contract is "beside the key", not cwd-relative; chdir elsewhere to prove it.
    key_dir = tmp_path / "keydir"
    key_dir.mkdir()
    key_path = _write_key(key_dir)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    assert mcp.main(["badge", "mint", "--key", str(key_path), "--sub", "fleet-7"]) == 0
    badge = capsys.readouterr().out.strip()
    assert (key_dir / "fleet-7.jwk").exists()        # written BESIDE the key, not in cwd
    assert not (elsewhere / "fleet-7.jwk").exists()  # definitely not cwd-relative
    assert verify_badge(badge, load_pins(str(key_dir))) == "fleet-7"


def test_badge_mint_unsafe_sub_no_jwk_out_refuses(tmp_path, capsys):
    # A --sub carrying path-traversal segments must not be used to build the default --jwk-out
    # path (which would write outside the intended directory): refuse loudly, point at --jwk-out.
    key_path = _write_key(tmp_path)
    err = _refused(["badge", "mint", "--key", str(key_path), "--sub", "e/../vil"], capsys)
    assert "--jwk-out" in err
    assert not (tmp_path / "vil.jwk").exists()       # nothing escaped or landed anywhere


def test_badge_mint_default_jwk_out_symlink_refused(tmp_path, capsys):
    # A symlink already sitting at the default `<sub>.jwk` target is refused, mirroring
    # load_pins' read-side symlink guard; re-minting over a REGULAR file stays legit.
    key_path = _write_key(tmp_path)
    target = tmp_path / "elsewhere.jwk"
    target.write_text("{}")
    os.symlink(target, tmp_path / "fleet-7.jwk")
    err = _refused(["badge", "mint", "--key", str(key_path), "--sub", "fleet-7"], capsys)
    assert "symlink" in err
    assert target.read_text() == "{}"                # symlink target left untouched


def test_badge_mint_refuses_a_world_readable_private_key(tmp_path, capsys):
    """Every other secret this codebase loads by path goes through refuse_exposed_secret (PVE
    token, PBS/PMG/PDM creds, bearer-token files, the A2A signing key). The badge signing key,
    an EC private key that mints identities, is the same class of secret, same floor."""
    key = tmp_path / "caller.pem"
    key.write_bytes(_keypair_pem())
    os.chmod(key, 0o644)  # noqa: S103 -- the exposed mode IS the thing under test
    err = _refused(["badge", "mint", "--key", str(key), "--sub", "fleet-7",
                    "--jwk-out", str(tmp_path / "o.jwk")], capsys)
    assert "group" in err or "world" in err or "readable" in err
