"""`proximo badge mint/inspect` — the operator-usable mint path (spec 2026-07-16).

Drives server.main() the same way tests/test_main_module.py drives doctor/mint/hello:
monkeypatch sys.argv + capsys, assert stdout/stderr/SystemExit. `mint` is verified as a
real round-trip against the JWK it writes — never a string check.
"""
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import proximo.server as srv
from proximo.principal import _b64url_dec, load_pins, verify_badge


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


def test_badge_mint_round_trips_against_written_jwk(tmp_path, monkeypatch, capsys):
    key_path = _write_key(tmp_path)
    jwk_out = tmp_path / "fleet-7.jwk"
    monkeypatch.setattr(srv.sys, "argv",
                        ["proximo", "badge", "mint", "--key", str(key_path),
                         "--sub", "fleet-7", "--jwk-out", str(jwk_out)])
    ran = {}
    monkeypatch.setattr(srv.mcp, "run", lambda *a, **k: ran.__setitem__("server", True))

    srv.main()

    captured = capsys.readouterr()
    badge = captured.out.strip()
    assert badge                                   # stdout carries the badge
    assert jwk_out.exists()                         # JWK written to --jwk-out
    assert "PROXIMO_CALLER_KEYS_DIR" in captured.err  # pin-file hint on stderr, not stdout
    assert badge not in captured.err                # stdout stays clean of the hint

    pins = load_pins(str(tmp_path))
    assert verify_badge(badge, pins) == "fleet-7"    # real round-trip, not a string check
    assert "server" not in ran                       # badge mode never starts the MCP server


def test_badge_mint_exp_flag_lands_expected_lifetime(tmp_path, monkeypatch, capsys):
    key_path = _write_key(tmp_path)
    before = int(time.time())
    monkeypatch.setattr(srv.sys, "argv",
                        ["proximo", "badge", "mint", "--key", str(key_path),
                         "--sub", "fleet-7", "--exp", "90d",
                         "--jwk-out", str(tmp_path / "fleet-7.jwk")])
    monkeypatch.setattr(srv.mcp, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError))

    srv.main()

    badge = capsys.readouterr().out.strip()
    _h, p_b64, _s = badge.split(".")
    payload = json.loads(_b64url_dec(p_b64))
    expected = before + 90 * 86400
    assert abs(payload["exp"] - expected) <= 5        # a few seconds' slack


def test_badge_inspect_prints_sub_and_not_verified_note(tmp_path, monkeypatch, capsys):
    key_path = _write_key(tmp_path)
    jwk_out = tmp_path / "fleet-7.jwk"
    monkeypatch.setattr(srv.sys, "argv",
                        ["proximo", "badge", "mint", "--key", str(key_path),
                         "--sub", "fleet-7", "--jwk-out", str(jwk_out)])
    monkeypatch.setattr(srv.mcp, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    srv.main()
    badge = capsys.readouterr().out.strip()

    monkeypatch.setattr(srv.sys, "argv", ["proximo", "badge", "inspect", badge])
    srv.main()

    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["payload"]["sub"] == "fleet-7"
    assert "NOT VERIFIED" in parsed["note"]


def test_badge_mint_bad_key_path_exits_1_no_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(srv.sys, "argv",
                        ["proximo", "badge", "mint",
                         "--key", str(tmp_path / "does-not-exist.pem"),
                         "--sub", "fleet-7"])

    with pytest.raises(SystemExit) as exc:
        srv.main()

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("proximo badge: ")
    assert "Traceback" not in err


def test_badge_mint_malformed_exp_exits_1_no_traceback(tmp_path, monkeypatch, capsys):
    key_path = _write_key(tmp_path)
    monkeypatch.setattr(srv.sys, "argv",
                        ["proximo", "badge", "mint", "--key", str(key_path),
                         "--sub", "fleet-7", "--exp", "90x"])

    with pytest.raises(SystemExit) as exc:
        srv.main()

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("proximo badge: ")
    assert "Traceback" not in err


def test_badge_inspect_malformed_badge_exits_1_no_traceback(monkeypatch, capsys):
    # Too few "."-parts to split into header/payload/signature — must fail loud, not traceback.
    monkeypatch.setattr(srv.sys, "argv", ["proximo", "badge", "inspect", "not-a-badge"])

    with pytest.raises(SystemExit) as exc:
        srv.main()

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("proximo badge: ")
    assert "Traceback" not in err


def test_badge_mint_default_jwk_out_writes_beside_key(tmp_path, monkeypatch, capsys):
    # No --jwk-out: contract is "beside the key," not cwd-relative — chdir elsewhere to prove it.
    key_dir = tmp_path / "keydir"
    key_dir.mkdir()
    key_path = _write_key(key_dir)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    monkeypatch.setattr(srv.sys, "argv",
                        ["proximo", "badge", "mint", "--key", str(key_path), "--sub", "fleet-7"])
    monkeypatch.setattr(srv.mcp, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError))

    srv.main()

    badge = capsys.readouterr().out.strip()
    expected_jwk = key_dir / "fleet-7.jwk"
    assert expected_jwk.exists()                    # written BESIDE the key, not in cwd
    assert not (elsewhere / "fleet-7.jwk").exists()  # definitely not cwd-relative

    pins = load_pins(str(key_dir))
    assert verify_badge(badge, pins) == "fleet-7"    # round-trips against the default-path JWK


def test_badge_mint_unsafe_sub_no_jwk_out_exits_1(tmp_path, monkeypatch, capsys):
    # A --sub carrying path-traversal segments must not be silently used to build the default
    # --jwk-out path (which would let it write outside the intended directory) — refuse loudly
    # and point the caller at --jwk-out instead.
    key_path = _write_key(tmp_path)
    monkeypatch.setattr(srv.sys, "argv",
                        ["proximo", "badge", "mint", "--key", str(key_path),
                         "--sub", "e/../vil"])

    with pytest.raises(SystemExit) as exc:
        srv.main()

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("proximo badge: ")
    assert "Traceback" not in err
    assert not (tmp_path / "vil.jwk").exists()       # confirms nothing escaped/landed anywhere


def test_badge_mint_default_jwk_out_symlink_refused(tmp_path, monkeypatch, capsys):
    # A symlink already sitting at the default `<sub>.jwk` target must be refused, mirroring
    # load_pins' read-side symlink guard — re-minting over a REGULAR file stays legit, only
    # a symlink target is refused.
    key_path = _write_key(tmp_path)
    target = tmp_path / "elsewhere.jwk"
    target.write_text("{}")
    link = tmp_path / "fleet-7.jwk"
    os.symlink(target, link)
    monkeypatch.setattr(srv.sys, "argv",
                        ["proximo", "badge", "mint", "--key", str(key_path), "--sub", "fleet-7"])

    with pytest.raises(SystemExit) as exc:
        srv.main()

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert err.startswith("proximo badge: ")
    assert "Traceback" not in err
    assert "symlink" in err
    assert target.read_text() == "{}"                # symlink target left untouched


def test_badge_mint_refuses_a_world_readable_private_key(tmp_path, monkeypatch, capsys):
    """Every other secret this codebase loads by path goes through refuse_exposed_secret (PVE
    token, PBS/PMG/PDM creds, bearer-token files, the A2A signing key). The badge signing key —
    an EC private key that mints identities — was opened with a plain open(), so minting against
    a chmod 644 key succeeded silently. Same class of secret, same floor."""
    key = tmp_path / "caller.pem"
    key.write_bytes(_keypair_pem())
    os.chmod(key, 0o644)  # noqa: S103 -- the exposed mode IS the thing under test
    monkeypatch.setattr("sys.argv", ["proximo", "badge", "mint", "--key", str(key),
                                     "--sub", "fleet-7", "--jwk-out", str(tmp_path / "o.jwk")])
    with pytest.raises(SystemExit) as e:
        srv.main()
    assert e.value.code == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "group" in err or "world" in err or "readable" in err
