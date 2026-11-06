"""`proximo-core arm|disarm` (and `proximo arm|disarm`): CONSENT's switch, the operator's hand.

THE TICKET IS THE ARM (2026-11-05). `arm` logs the operator in from a terminal of their own and
serves the vendor's ticket; `disarm` installs the read-only token. The verb's login, prompts and
refusals are pinned in `test_ticket_is_the_arm.py`; this file keeps what the verbs do to the served
FILE and the ledger: atomic installs, the directory on a fresh state dir, the one disarm that lies
(a read-only source byte-identical to a job's write token), retired switches, the shell door's
dispatch. Retired with the token swap (2026-11-05): the tests that pinned `arm` copying the write
token's bytes and reading GET /version with them before serving (the login IS that check now).
"""
from __future__ import annotations

import json
import os
import time

import httpx
import pytest

from proximo.core import wire
from proximo.core.doors import cli, mcp

SIG = "Zm9v0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab"


def _ticket(user: str = "u@pam", age: int = 10) -> str:
    return f"PVE:{user}:{int(time.time()) - age:08X}::{SIG}"


@pytest.fixture
def box(tmp_path, monkeypatch):
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":   # the pin on the real file stays
            monkeypatch.delenv(var)
    write, ro, served = tmp_path / "write.tok", tmp_path / "ro.tok", tmp_path / "served.tok"
    write.write_text("u@pam!w=11111111-1111-1111-1111-111111111111")      # a job's pair, still honoured
    ro.write_text("u@pam!r=22222222-2222-2222-2222-222222222222")
    served.write_text(ro.read_text())
    for p in (write, ro, served):
        p.chmod(0o600)
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", str(write))
    monkeypatch.setenv("PROXIMO_READONLY_SOURCE", str(ro))
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(served))
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.invalid:8006/api2/json")
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    return tmp_path


@pytest.fixture
def terminal(monkeypatch):
    """A terminal on stdin, a silent prompt answered 'pw', and a vendor that hands out a ticket for it."""
    monkeypatch.setattr(cli.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(cli, "_prompt_secret", lambda label: "pw")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": {"ticket": _ticket(), "CSRFPreventionToken": "CSRF:1:x",
                                                  "username": "u@pam"}})
    real = httpx.Client

    def build(**kw):
        return real(transport=httpx.MockTransport(handler), **{k: v for k, v in kw.items() if k != "verify"})
    monkeypatch.setattr(wire.httpx, "Client", build)
    return seen


def _rows(box):
    log = box / "audit.log"
    return [json.loads(x) for x in log.read_text().splitlines() if x.strip()] if log.exists() else []


def _served_is_ticket(path) -> bool:
    return path.read_text().startswith("{") and "ticket" in json.loads(path.read_text())


def test_arm_serves_a_ticket_atomically_and_records_a_row(box, terminal, capsys):
    assert cli.main(["arm"]) == 0
    served = box / "served.tok"
    assert _served_is_ticket(served)
    assert oct(served.stat().st_mode & 0o777) == "0o600"
    assert not [p for p in box.iterdir() if p.name.startswith(".tok.")]   # no temp file left behind
    assert "ARMED" in capsys.readouterr().out
    assert [(r["action"], r["detail"]["armed"]) for r in _rows(box)] == [("core.arm", True)]


def test_arm_creates_the_served_tokens_directory_on_a_fresh_state_dir(box, terminal, monkeypatch, capsys):
    """alexdelprete, #114: on an empty state dir `arm` died with ENOENT on served/.tok.<rand>; the served
    token's own directory is made (0700) when it is missing. A missing grandparent is still the operator's."""
    served = box / "state" / "served" / "token"
    (box / "state").mkdir()
    assert cli.main(["arm", "--serve", str(served)]) == 0
    assert _served_is_ticket(served)
    assert oct(served.parent.stat().st_mode & 0o777) == "0o700" and oct(served.stat().st_mode & 0o777) == "0o600"
    assert cli.main(["arm", "--serve", str(box / "nowhere" / "served" / "token")]) != 0
    assert not (box / "nowhere").exists()
    assert "arm" in capsys.readouterr().err


def test_two_arms_racing_on_a_fresh_state_dir_both_arm(box, terminal, monkeypatch, capsys):
    """Lens 3: the loser of a mkdir race found the directory the winner made and failed rc 3 with no token.
    The race is replayed by hand: isdir answers False, then mkdir finds the directory there."""
    served = box / "state2" / "served" / "token"
    (box / "state2").mkdir()
    real_mkdir = os.mkdir

    def racing_mkdir(path, mode=0o777, *a, **kw):
        real_mkdir(path, 0o700)                                              # the other arm wins the race
        raise FileExistsError(17, "File exists", path)

    monkeypatch.setattr(os, "mkdir", racing_mkdir)
    assert cli.main(["arm", "--serve", str(served)]) == 0
    assert _served_is_ticket(served)
    monkeypatch.setattr(os, "mkdir", real_mkdir)
    (box / "state3").mkdir()
    (box / "state3" / "served").write_text("a file where the directory should be")
    assert cli.main(["arm", "--serve", str(box / "state3" / "served" / "token")]) != 0   # a file in the way refuses
    assert "arm" in capsys.readouterr().err


def test_disarm_restores_the_read_only_token_and_records_a_row(box, terminal, capsys):
    assert cli.main(["arm"]) == 0
    assert cli.main(["disarm", "--json"]) == 0
    assert (box / "served.tok").read_text() == (box / "ro.tok").read_text()
    assert [r["action"] for r in _rows(box)] == ["core.arm", "core.disarm"]


def test_disarm_json_is_the_result(box, capsys):
    assert cli.main(["disarm", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"armed": False, "target": str(box / "served.tok"), "plane": "pve"}


def test_the_stdio_door_hands_arm_and_disarm_to_the_shell_door(box, terminal, monkeypatch):
    monkeypatch.setattr(mcp, "build_server", lambda *a, **k: (_ for _ in ()).throw(AssertionError("built")))
    assert mcp.main(["arm"]) == 0
    assert _served_is_ticket(box / "served.tok")
    assert mcp.main(["disarm"]) == 0
    assert (box / "served.tok").read_text() == (box / "ro.tok").read_text()


@pytest.mark.parametrize(("verb", "env"), [("disarm", "PROXIMO_READONLY_SOURCE"), ("arm", "PROXIMO_TOKEN_PATH"),
                                           ("disarm", "PROXIMO_TOKEN_PATH")])
def test_an_unset_source_or_target_refuses_and_changes_nothing(box, terminal, verb, env, monkeypatch, capsys):
    monkeypatch.delenv(env)
    before = (box / "served.tok").read_text()
    assert cli.main([verb]) == 3
    err = capsys.readouterr().err
    assert err.startswith(f"proximo-core {verb}: ") and env in err and "Traceback" not in err
    assert (box / "served.tok").read_text() == before
    assert _rows(box) == []


def test_a_symlinked_served_path_refuses(box, terminal, monkeypatch, capsys):
    link = box / "served-link.tok"
    os.symlink(box / "served.tok", link)
    for verb in ("arm", "disarm"):
        assert cli.main([verb, "--serve", str(link)]) == 3
        assert "symlink" in capsys.readouterr().err
    assert (box / "served.tok").read_text() == (box / "ro.tok").read_text()


def test_disarm_refuses_when_the_read_only_source_is_a_jobs_write_token(box, terminal, monkeypatch, capsys):
    """The one disarm that lies: installing a job's write token and reporting DISARMED. Refused,
    nothing changed, no row."""
    (box / "ro.tok").write_text((box / "write.tok").read_text())
    assert cli.main(["arm"]) == 0
    assert cli.main(["disarm"]) == 3
    err = capsys.readouterr().err
    assert "byte-identical" in err and "Nothing was changed" in err
    assert _served_is_ticket(box / "served.tok")
    assert [r["action"] for r in _rows(box)] == ["core.arm"]


def test_the_control_the_engine_reads_the_ticket_on_the_next_call(box, terminal):
    """The verb is only worth having if the predicate the engine runs reads the file the verb
    wrote: armed after `arm`, not armed after `disarm`, no restart."""
    from proximo.core import arm  # noqa: PLC0415

    class Cfg:
        product = "pve"
        base_url = "https://pve.invalid:8006/api2/json"
        token_path = str(box / "served.tok")
        arm_source = None
        readonly_source = str(box / "ro.tok")
    assert arm.arm_state(Cfg()).armed is False
    assert cli.main(["arm"]) == 0
    assert arm.arm_state(Cfg()).armed is True
    assert cli.main(["disarm"]) == 0
    assert arm.arm_state(Cfg()).armed is False


def test_an_exposed_read_only_source_refuses_like_every_other_secret_by_path(box, capsys):
    """0.44 installed from a group- or world-readable source and called it ADVISORY; the core
    refuses it, the floor `refuse_exposed_secret` gives every secret loaded by path (lens round 2)."""
    (box / "ro.tok").chmod(0o644)
    before = (box / "served.tok").read_text()
    assert cli.main(["disarm"]) == 3
    err = capsys.readouterr().err
    assert "readable" in err or "mode" in err
    assert (box / "served.tok").read_text() == before


@pytest.mark.parametrize("switch", ["PROXIMO_SURFACES", "PROXIMO_SCOPE_PATH", "PROXIMO_ARM_TTL"])
def test_a_retired_switch_never_keeps_write_authority_live(box, terminal, switch, monkeypatch, capsys):
    """Lens 2 (10-18): the shell door refused retired switches before the verbs, so `disarm`
    could not drop write authority and `doctor` could not say why. Disarm and doctor run past
    it; arm still refuses, since the operator may believe the retired gate bounds the ticket."""
    assert cli.main(["arm"]) == 0
    monkeypatch.setenv(switch, "/vms/100" if switch != "PROXIMO_ARM_TTL" else "900")
    assert cli.main(["disarm"]) == 0
    assert (box / "served.tok").read_text() == (box / "ro.tok").read_text()
    capsys.readouterr()
    assert cli.main(["arm"]) == 3
    assert switch in capsys.readouterr().err
    assert (box / "served.tok").read_text() == (box / "ro.tok").read_text()
    cli.main(["doctor"])
    assert switch in capsys.readouterr().out


def test_disarm_never_asks_the_vendor(box, monkeypatch, capsys):
    from proximo.core import engine  # noqa: PLC0415
    monkeypatch.setattr(engine, "_client", lambda *a, **k: (_ for _ in ()).throw(AssertionError("dialled")))
    monkeypatch.setattr(wire.httpx, "Client", lambda **kw: (_ for _ in ()).throw(AssertionError("dialled")))
    assert cli.main(["disarm"]) == 0
    assert (box / "served.tok").read_text() == (box / "ro.tok").read_text()


@pytest.mark.parametrize("verb", ["arm", "disarm"])
def test_a_rename_that_fails_leaves_no_staged_copy(box, terminal, monkeypatch, capsys, verb):
    before = (box / "served.tok").read_text()

    def failing_replace(src, dst):
        raise OSError(5, "I/O error", dst)
    monkeypatch.setattr(os, "replace", failing_replace)
    assert cli.main([verb]) == 3
    assert (box / "served.tok").read_text() == before
    assert not [p for p in box.iterdir() if p.name.startswith(".tok.")]
