"""`proximo-core arm|disarm` (and `proximo arm|disarm`): CONSENT's switch, the operator's hand.

The 0.44 `proximo arm` installed the write token at the served path with per-session arms and a
`reap` of stale ones; that half was LEASE, retired to the vendor's own `expire`. The core keeps
the predicate (`core.arm`: armed <=> served bytes == arm source bytes) and, since the swap's lens
(2026-10-17) found the verb reachable by no command, this verb: global, atomic, recorded, and
refusing the one disarm that would lie (a read-only source byte-identical to the write token).
"""
from __future__ import annotations

import json
import os

import pytest

from proximo.core.doors import cli, mcp


@pytest.fixture
def box(tmp_path, monkeypatch):
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":   # the pin on the real file stays
            monkeypatch.delenv(var)
    write, ro, served = tmp_path / "write.tok", tmp_path / "ro.tok", tmp_path / "served.tok"
    write.write_text("u@pam!w=11111111-1111-1111-1111-111111111111")
    ro.write_text("u@pam!r=22222222-2222-2222-2222-222222222222")
    served.write_text(ro.read_text())
    for p in (write, ro, served):
        p.chmod(0o600)
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", str(write))
    monkeypatch.setenv("PROXIMO_READONLY_SOURCE", str(ro))
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(served))
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    return tmp_path


def _rows(box):
    log = box / "audit.log"
    return [json.loads(x) for x in log.read_text().splitlines() if x.strip()] if log.exists() else []


def test_arm_installs_the_write_token_bytes_atomically_and_records_a_row(box, capsys):
    assert cli.main(["arm"]) == 0
    served = box / "served.tok"
    assert served.read_text() == (box / "write.tok").read_text()
    assert oct(served.stat().st_mode & 0o777) == "0o600"
    assert not [p for p in box.iterdir() if p.name.startswith(".tok.")]   # no temp file left behind
    assert "ARMED" in capsys.readouterr().out
    assert [(r["action"], r["detail"]["armed"]) for r in _rows(box)] == [("core.arm", True)]


def test_arm_creates_the_served_tokens_directory_on_a_fresh_state_dir(box, monkeypatch, capsys):
    """alexdelprete, #114: on an empty state dir `arm` died with ENOENT on served/.tok.<rand>; the served
    token's own directory is made (0700) when it is missing. A missing grandparent is still the operator's."""
    served = box / "state" / "served" / "token"
    (box / "state").mkdir()
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(served))
    assert cli.main(["arm"]) == 0
    assert served.read_text() == (box / "write.tok").read_text()
    assert oct(served.parent.stat().st_mode & 0o777) == "0o700" and oct(served.stat().st_mode & 0o777) == "0o600"
    assert [(r["action"], r["detail"]["armed"]) for r in _rows(box)] == [("core.arm", True)]
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(box / "nowhere" / "served" / "token"))
    assert cli.main(["arm"]) != 0
    assert not (box / "nowhere").exists()
    assert "arm" in capsys.readouterr().err


def test_two_arms_racing_on_a_fresh_state_dir_both_arm(box, monkeypatch, capsys):
    """Lens 3: the loser of a mkdir race found the directory the winner made and failed rc 3 with no token.
    The race is replayed by hand: isdir answers False, then mkdir finds the directory there."""
    served = box / "state2" / "served" / "token"
    (box / "state2").mkdir()
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(served))
    real_mkdir = os.mkdir

    def racing_mkdir(path, mode=0o777, *a, **kw):
        real_mkdir(path, 0o700)                                              # the other arm wins the race
        raise FileExistsError(17, "File exists", path)

    monkeypatch.setattr(os, "mkdir", racing_mkdir)
    assert cli.main(["arm"]) == 0
    assert served.read_text() == (box / "write.tok").read_text()
    monkeypatch.setattr(os, "mkdir", real_mkdir)
    (box / "state3").mkdir()
    (box / "state3" / "served").write_text("a file where the directory should be")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(box / "state3" / "served" / "token"))
    assert cli.main(["arm"]) != 0                                            # a file in the way still refuses
    assert "arm" in capsys.readouterr().err


def test_disarm_restores_the_read_only_token_and_records_a_row(box, capsys):
    assert cli.main(["arm"]) == 0
    assert cli.main(["disarm", "--json"]) == 0
    assert (box / "served.tok").read_text() == (box / "ro.tok").read_text()
    assert [r["action"] for r in _rows(box)] == ["core.arm", "core.disarm"]


def test_disarm_json_is_the_result(box, capsys):
    assert cli.main(["disarm", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"armed": False, "target": str(box / "served.tok")}


def test_the_stdio_door_hands_arm_and_disarm_to_the_shell_door(box, monkeypatch):
    monkeypatch.setattr(mcp, "build_server", lambda *a, **k: (_ for _ in ()).throw(AssertionError("built")))
    assert mcp.main(["arm"]) == 0
    assert (box / "served.tok").read_text() == (box / "write.tok").read_text()
    assert mcp.main(["disarm"]) == 0
    assert (box / "served.tok").read_text() == (box / "ro.tok").read_text()


@pytest.mark.parametrize(("verb", "env"), [("arm", "PROXIMO_ARM_SOURCE"), ("disarm", "PROXIMO_READONLY_SOURCE"),
                                           ("arm", "PROXIMO_TOKEN_PATH")])
def test_an_unset_source_or_target_refuses_and_changes_nothing(box, verb, env, monkeypatch, capsys):
    monkeypatch.delenv(env)
    before = (box / "served.tok").read_text()
    assert cli.main([verb]) == 3
    err = capsys.readouterr().err
    assert err.startswith(f"proximo-core {verb}: ") and env in err and "Traceback" not in err
    assert (box / "served.tok").read_text() == before
    assert _rows(box) == []


def test_a_symlinked_source_refuses(box, monkeypatch, capsys):
    link = box / "link.tok"
    os.symlink(box / "write.tok", link)
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", str(link))
    assert cli.main(["arm"]) == 3
    assert "symlink" in capsys.readouterr().err
    assert (box / "served.tok").read_text() == (box / "ro.tok").read_text()


def test_a_symlinked_served_path_refuses(box, monkeypatch, capsys):
    link = box / "served-link.tok"
    os.symlink(box / "served.tok", link)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(link))
    assert cli.main(["arm"]) == 3
    assert "symlink" in capsys.readouterr().err
    assert (box / "served.tok").read_text() == (box / "ro.tok").read_text()


def test_disarm_refuses_when_the_read_only_source_is_the_write_token(box, monkeypatch, capsys):
    """The one disarm that lies: installing the write token and reporting DISARMED. Refused,
    nothing changed, no row."""
    (box / "ro.tok").write_text((box / "write.tok").read_text())
    assert cli.main(["arm"]) == 0
    assert cli.main(["disarm"]) == 3
    err = capsys.readouterr().err
    assert "byte-identical" in err and "Nothing was changed" in err
    assert (box / "served.tok").read_text() == (box / "write.tok").read_text()
    assert [r["action"] for r in _rows(box)] == ["core.arm"]


def test_the_control_the_engine_reads_the_swap_on_the_next_call(box):
    """The verb is only worth having if the predicate the engine runs reads the file the verb
    wrote: armed after `arm`, not armed after `disarm`, no restart."""
    from proximo.core import arm  # noqa: PLC0415

    class Cfg:
        token_path = str(box / "served.tok")
        arm_source = str(box / "write.tok")
        readonly_source = str(box / "ro.tok")
    assert arm.arm_state(Cfg()).armed is False
    assert cli.main(["arm"]) == 0
    assert arm.arm_state(Cfg()).armed is True
    assert cli.main(["disarm"]) == 0
    assert arm.arm_state(Cfg()).armed is False


@pytest.mark.parametrize(("verb", "name"), [("arm", "write.tok"), ("disarm", "ro.tok")])
def test_an_exposed_source_refuses_like_every_other_secret_by_path(box, verb, name, capsys):
    """0.44 installed from a group- or world-readable source and called it ADVISORY; the core
    refuses it, the floor `refuse_exposed_secret` gives every secret loaded by path (lens round 2)."""
    (box / name).chmod(0o644)
    before = (box / "served.tok").read_text()
    assert cli.main([verb]) == 3
    err = capsys.readouterr().err
    assert "readable" in err or "mode" in err
    assert (box / "served.tok").read_text() == before


@pytest.mark.parametrize("switch", ["PROXIMO_SURFACES", "PROXIMO_SCOPE_PATH", "PROXIMO_ARM_TTL"])
def test_a_retired_switch_never_keeps_write_authority_live(box, switch, monkeypatch, capsys):
    """Lens 2 (10-18): the shell door refused retired switches before the verbs, so `disarm`
    could not drop write authority and `doctor` could not say why. Disarm and doctor run past
    it; arm still refuses, since the operator may believe the retired gate bounds the token."""
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
