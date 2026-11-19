"""The README's claims, held to the code: the findings of the 2026-11-19 read that a test can state.

`test_fact_*` pins what the code does, the evidence a sentence was measured against. The rest hold
each cure: the sentences John ruled, present word for word with the old phrase gone, and the
behaviour each finding asked for. Every one of them was a strict xfail first and failed for its
stated reason before its fix landed.

Not here, because no test can state them: what a receipt keeps of a shell command, and the
webhook arguments.
"""

from __future__ import annotations

import importlib
import json
import os
import pathlib
import re
import sys

import pytest

from proximo.core import arm, engine, shell, wire
from proximo.core.doors import cli
from proximo.core.doors import mcp as door
from proximo.core.ledger import LedgerConfig, open_ledger

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _text(name: str) -> str:
    """A file's words with every run of whitespace as one space: AGENTS.md and SECURITY.md are
    hard-wrapped, and a re-wrap must not turn a sentence test green or red."""
    return " ".join((ROOT / name).read_text(encoding="utf-8").split())


#: an open, tiered mutation the vendor publishes, with a concrete path
POOL = ("pve", "POST", "/pools", {"poolid": "claims-probe"})
BOX = "https://pve.invalid:8006/api2/json"


class Recorder:
    """A wire that records and answers, never dials."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []

    def call(self, method, path, params=None):
        self.calls.append((method, path, dict(params or {})))
        return [] if method == "GET" else None


@pytest.fixture
def wired(armed_plane, monkeypatch):
    """An armed pve box whose wire is a recorder, reachable by the env too (the shell door
    builds its plane from the environment)."""
    rec = Recorder()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: rec)
    monkeypatch.delenv("PROXIMO_TARGETS", raising=False)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", armed_plane.base_url)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", armed_plane.token_path)
    os.chmod(armed_plane.token_path, 0o600)       # a usable token: a plan's own reads then reach the recorder too
    return armed_plane, rec


@pytest.fixture
def unarmed(tmp_path, monkeypatch):
    """A pve box with a token and no arm configured at all: the real `arm_state` decides."""
    tok = tmp_path / "token"
    tok.write_text("t")
    os.chmod(tok, 0o600)
    for var in ("PROXIMO_ARM_SOURCE", "PROXIMO_READONLY_SOURCE", "PROXIMO_TOKEN_PATH", "PROXIMO_API_BASE_URL",
                "PROXIMO_TARGETS", "PROXIMO_ENABLE_AGENT", "PROXIMO_AGENT_ALLOWLIST", "PROXIMO_ENABLE_EXEC",
                "PROXIMO_CT_ALLOWLIST", "PROXIMO_CONTAIN_TRIP_PATH", "PROXIMO_CONSENT_DIR"):
        monkeypatch.delenv(var, raising=False)
    return wire.Plane("pve", BOX, str(tok))


def _writes(rec: Recorder) -> list[tuple[str, str, dict]]:
    return [c for c in rec.calls if c[0] != "GET"]


def _served_mutations() -> list[engine.Row]:
    """What an armed operator can reach: open and tiered, or behind a lane's switch."""
    return [r for r in engine.table().values()
            if r.access == engine.MUTATE and not r.excluded and not r.held
            and (r.lane or not r.gate) and r.tier in engine.TIERS]


# --- the sentences: cured in phase 1 by the words John ruled, 2026-11-19; held here ------------------

#: id -> (file, the phrase that says more than the code does, the replacement he agreed to)
SENTENCES = {
    "s1-first-call": ("README.md", "No mutation runs on the first call",
                      "Read-only by default. A mutation called without `confirm=true` returns its plan and "
                      "changes nothing; with it, the plan is written to the ledger before anything moves."),
    "s3-live-target": ("README.md", "the verdict, the live target, the exact change, the blast radius",
                       "the verdict, the exact change, the blast radius, and the live target where the vendor "
                       "publishes a read for it"),
    "s5-lxc-row": ("README.md", "opt-in, fail-closed allowlist, judged like any mutation",
                   "opt-in, fail-closed allowlist of containers, judged like any mutation"),
    "s3-plan-row": ("README.md", "Every mutation first returns a recorded preview",
                    "Called without `confirm=true`, a mutation returns its preview: the exact change, the live "
                    "state where the vendor publishes a read for it, blast radius, an advisory risk rating."),
    "s4-arm": ("README.md", "Four more controls ship off until configured",
               "**ARM** stands from the start: no mutation runs until an arm is configured and the served token "
               "*is* the write token. Three more controls ship off until configured:"),
    "s6-lanes": ("README.md", "each behind its own switch and allowlist",
                 "each behind its own switch, the guest lanes behind an allowlist too; a command is judged like "
                 "any mutation, a lane's read like any read"),
    # ruled 2026-11-19: once the shell door plans by default, his first sentence is true again and goes back
    "s2-confirm": ("README.md", "the shell command runs unless `--plan` is given",
                   "the plan reads the target first; nothing moves without `confirm=true`, an arm and a tier"),
    "s5-safe-by-default": ("README.md", "Each is scoped by its own fail-closed allowlist.",
                           "Each is scoped by its own fail-closed allowlist of guests; inside an allowed guest "
                           "the command is the caller's."),
    "s8-agents": ("AGENTS.md", "Every call lands in a keyed hash-chained audit log",
                  "A mutation's plan lands in a keyed hash-chained audit log before it runs; `audit_verify` "
                  "checks the chain"),
    "s9-structural": ("SECURITY.md", "PLAN·PROVE·UNDO·DIAGNOSE are structural",
                      "PLAN·PROVE·DIAGNOSE are structural (no configuration removes them); UNDO stands unless "
                      "you opt out."),
    "s1-security-plan-row": ("SECURITY.md", "no chance to review first",
                             "A mutation landing with no recorded plan: no verdict, no blast-radius judgement, no "
                             "live target where the vendor publishes a read for it"),
    "s3-setup": ("docs/SETUP.md", "the verdict, the live target and the exact change, before anything runs",
                 "the verdict, the exact change, and the live target where the vendor publishes a read for it, "
                 "before anything runs"),
    "s6-arena": ("docs/arena.md", "opened by an operator switch, judged like any mutation",
                 "opened by an operator switch: a command is judged like any mutation, a read like any read"),
    "s6-security": ("SECURITY.md", "each is bounded by its own fail-closed allowlist",
                    "the two guest lanes are each bounded by a fail-closed allowlist of guests, the download lane "
                    "by its byte cap, and the node lane by its fixed read-only battery; a command is judged like "
                    "any mutation, a lane's read like any read."),
    # an ADDED sentence: there is no old phrase to be gone (None), only his words to be there
    "c1-same-user": ("README.md", None,
                     "These controls hold against a caller through the door; a process running as the door's own "
                     "user is outside them, and `proximo doctor` says what it can reach."),
    "c4-pmg-login": ("SECURITY.md", "every login is a ledger row",
                     "That login is the wire's own and is not a ledger row; every call it serves is."),
}


@pytest.mark.parametrize("name", sorted(SENTENCES))
def test_the_sentence_is_the_one_he_ruled(name):
    """Both halves: the old phrase gone AND his replacement there, word for word. Absence alone
    passed on a one-character edit that left the claim standing (the lens on this file)."""
    file, old, new = SENTENCES[name]
    text = _text(file)
    assert " ".join(new.split()) in text, f"{file} does not carry the ruled sentence"
    if old is not None:
        assert " ".join(old.split()) not in text, f"{file} still says: {old}"


# --- S1: a first call with confirm runs ------------------------------------------------------------

def test_fact_s1_a_first_call_with_confirm_runs(wired):
    cfg, rec = wired
    plane, method, path, args = POOL
    out = door.call(plane, method, path, args, confirm=True, cfg=cfg)
    assert _writes(rec) == [("POST", "/pools", {"poolid": "claims-probe"})], (out, rec.calls)


def test_fact_s1_the_same_call_without_confirm_touches_nothing(wired):
    cfg, rec = wired
    plane, method, path, args = POOL
    out = door.call(plane, method, path, args, cfg=cfg)
    assert out["status"] == "plan" and out["allowed"] is True and _writes(rec) == []


# --- S2 / C5: the shell door runs a bare mutation --------------------------------------------------

def test_c5_the_shell_door_plans_unless_told_to_run(wired, capsys):
    """His ruling: the shell door plans by default, like the other four doors. A bare
    mutation prints its plan, runs nothing, and exits 3 with a line on stderr: a script written
    when a bare call ran must not read exit 0 and believe it happened."""
    _, rec = wired
    bare = ["pve", "POST", "/pools", "poolid=claims-probe"]
    assert cli.main(bare) == cli.EXIT_USAGE
    said = capsys.readouterr()
    assert json.loads(said.out)["allowed"] is True and "--confirm" in said.err
    assert _writes(rec) == [], "a bare shell call reached the wire"
    assert cli.main([*bare, "--plan"]) == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out)["allowed"] is True and _writes(rec) == []
    assert cli.main([*bare, "--confirm"]) == cli.EXIT_OK
    assert len(_writes(rec)) == 1, "told to run, it did not"


def test_fact_c5_a_read_on_the_shell_door_needs_no_flag(wired, capsys):
    _, rec = wired
    assert cli.main(["pve", "GET", "/pools"]) == cli.EXIT_OK
    assert [c[0] for c in rec.calls] == ["GET"]


def test_c5_plan_wins_over_confirm(wired, monkeypatch, capsys):
    """The lens ran `undo <id> --plan --confirm` and the restore RAN: a line that asks for the plan
    mutates nothing, whatever else it says."""
    _, rec = wired
    assert cli.main(["pve", "POST", "/pools", "poolid=claims-probe", "--plan", "--confirm"]) == cli.EXIT_OK
    assert _writes(rec) == []
    seen: dict = {}
    monkeypatch.setattr(cli.undo, "restore", lambda ref, **kw: seen.update(kw) or {"status": "plan", "allowed": True})
    assert cli.main(["pve", "undo", "abcdef012345", "--plan", "--confirm"]) == cli.EXIT_OK
    assert seen["confirm"] is False
    assert cli.main(["pve", "undo", "abcdef012345", "--confirm"]) == cli.EXIT_OK
    assert seen["confirm"] is True


def test_c5_a_refused_bare_mutation_is_the_spines_no_not_the_callers_mistake(unarmed, monkeypatch, capsys):
    """Exit 2, never 3: a script must still tell "the spine said no" from "you forgot --confirm"."""
    monkeypatch.setenv("PROXIMO_API_BASE_URL", unarmed.base_url)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", unarmed.token_path)
    assert cli.main(["pve", "POST", "/pools", "poolid=claims-probe"]) == cli.EXIT_REFUSED
    said = capsys.readouterr()
    assert json.loads(said.out)["needs"] == "arm" and "--confirm" not in said.err


def test_c5_a_plan_greets_nobody_and_a_run_does(wired, monkeypatch, capsys):
    """A bare mutation is a plan now: it must not write the grant row a run writes first."""
    from proximo.core import reach
    greeted = []
    monkeypatch.setattr(reach, "greet", lambda prog, face: greeted.append(face) or True)
    cli.main(["pve", "POST", "/pools", "poolid=claims-probe"])
    cli.main(["pve", "POST", "/pools", "poolid=claims-probe", "--plan"])
    cli.main(["pve", "POST", "/pools", "poolid=claims-probe", "--plan", "--confirm"])
    assert greeted == []
    cli.main(["pve", "POST", "/pools", "poolid=claims-probe", "--confirm"])
    assert greeted == ["cli"]


# --- S3: live state only where there is a read -----------------------------------------------------

def test_fact_s3_some_served_mutations_have_no_read_to_show_live_state():
    """By the engine's own rule for the read that shows a target (`_read_of`), not by `twin` alone:
    a parent's `/current` counts, a gated twin does not."""
    served = _served_mutations()
    cannot = [r for r in served if engine._read_of(r)[0] is None]
    assert 0 < len(cannot) < len(served), (len(cannot), len(served))


# --- S4: with no arm configured, nothing mutates ---------------------------------------------------

def test_fact_s4_with_no_arm_configured_no_mutation_runs(unarmed):
    assert arm.arm_state(unarmed).armed is False
    verdict = engine.govern(engine.resolve("pve", "POST", "/pools"), cfg=unarmed, path="/pools",
                            args={"poolid": "x"})
    assert verdict.allowed is False and verdict.needs == "arm"


# --- S5: the allowlist lists guests; the command is the caller's -----------------------------------

EXEC = "/nodes/n1/lxc/105/exec"


def test_fact_s5_an_allowed_guest_takes_any_command(armed_plane, monkeypatch):
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "105")
    row = engine.resolve("pve", "POST", EXEC)
    anything = {"command": ["sh", "-c", "anything at all; and more"]}
    assert engine.govern(row, cfg=armed_plane, path=EXEC, args=anything).allowed is True
    assert shell.argv_for("exec", anything) == anything["command"]
    other = "/nodes/n1/lxc/106/exec"
    refused = engine.govern(engine.resolve("pve", "POST", other), cfg=armed_plane, path=other, args=anything)
    assert refused.allowed is False and "106" in refused.reason


# --- S6: a lane's read is a read -------------------------------------------------------------------

AGENT_READ = "/nodes/n1/qemu/105/agent/get-osinfo"


def test_fact_s6_a_lanes_read_needs_its_switch_and_no_arm(unarmed, monkeypatch):
    row = engine.resolve("pve", "GET", AGENT_READ)
    assert row.lane == "agent" and row.access == engine.READ
    assert engine.govern(row, cfg=unarmed, path=AGENT_READ).allowed is False          # the lane is off
    monkeypatch.setenv("PROXIMO_ENABLE_AGENT", "1")
    monkeypatch.setenv("PROXIMO_AGENT_ALLOWLIST", "105")
    assert arm.arm_state(unarmed).armed is False
    assert engine.govern(row, cfg=unarmed, path=AGENT_READ).allowed is True


def test_fact_s6_every_lane_has_reads():
    lanes = {r.lane for r in engine.table().values() if r.lane and r.access == engine.READ}
    assert lanes == {"agent", "download", "shell", "node"}, lanes


# --- S7 / C6: audit_verify "on every door, always" -------------------------------------------------

def _two_rows(tmp_path) -> pathlib.Path:
    log = tmp_path / "claims-audit.log"
    led = open_ledger(LedgerConfig(audit_log_path=str(log)))
    led.record("claims.one", target="/x", mutation=False, outcome="ok", detail={})
    led.record("claims.two", target="/y", mutation=False, outcome="ok", detail={})
    return log


def test_c6_the_shell_door_verifies_the_chain_and_catches_an_edit(tmp_path, monkeypatch, capsys):
    log = _two_rows(tmp_path)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(log))
    assert cli.main(["audit", "verify"]) == cli.EXIT_OK
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True and out["entries"] == 2
    log.write_text(log.read_text().replace("/x", "/z", 1))
    assert cli.main(["audit", "verify"]) == cli.EXIT_REFUSED
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_c6_a_ledger_that_cannot_be_read_does_not_verify(tmp_path, monkeypatch, capsys):
    """The lens appended one byte that is not text and got a traceback and exit 1: a script
    branching on 2 read a tampered ledger as a crash, not as a chain that does not hold."""
    log = _two_rows(tmp_path)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(log))
    with open(log, "ab") as f:
        f.write(b"\xff\n")
    assert cli.main(["audit", "verify"]) == cli.EXIT_REFUSED
    assert json.loads(capsys.readouterr().out)["ok"] is False
    assert cli.main(["audit", "entries"]) == cli.EXIT_REFUSED
    folder = tmp_path / "a-directory"
    folder.mkdir()
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(folder))
    assert cli.main(["audit", "verify"]) == cli.EXIT_REFUSED


@pytest.mark.parametrize("argv", [[], ["verify", "--nope"], ["entries", "--limit", "-1"], ["entries", "--limit", "0"],
                                  ["entries", "--limit"], ["entries", "--limit", "9999"], ["sideways"]])
def test_c6_what_the_audit_verb_does_not_take_is_the_callers_mistake(argv, capsys):
    assert cli.main(["audit", *argv]) == cli.EXIT_USAGE
    assert capsys.readouterr().err.count("usage:") == 1


def test_c6_the_audit_verb_reads_and_makes_nothing(tmp_path, monkeypatch, capsys):
    """It says it is a read: on a box with no ledger it must not mint the key or write a row."""
    home = tmp_path / "fresh"
    home.mkdir()
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(home / "audit.log"))
    monkeypatch.delenv("PROXIMO_AUDIT_EXPECTED_HEAD", raising=False)
    cli.main(["audit", "verify"])
    cli.main(["audit", "entries"])
    capsys.readouterr()
    assert list(home.iterdir()) == []


def test_c6_the_shell_door_reads_the_entries(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(_two_rows(tmp_path)))
    assert cli.main(["audit", "entries"]) == cli.EXIT_OK
    assert "claims.two" in capsys.readouterr().out


# --- S10 / C10: the numbers nobody checks ----------------------------------------------------------

def _run_lines(workflow: pathlib.Path) -> list[str]:
    """The command lines of a workflow's `run:` steps: comments and step names are not commands."""
    out, block = [], None
    for raw in workflow.read_text(encoding="utf-8").splitlines():
        line = raw.split(" #", 1)[0].rstrip()
        indent = len(line) - len(line.lstrip())
        if block is not None:
            if line.strip() and indent <= block:
                block = None
            elif line.strip() and not line.lstrip().startswith("#"):
                out.append(line.strip())
                continue
        m = re.match(r"\s*(?:- )?run:\s*(.*)$", line)
        if m:
            if m.group(1) in ("|", ">", "|-", ">-"):
                block = indent
            elif m.group(1):
                out.append(m.group(1))
    return out


def test_c10_public_ci_runs_pyright():
    """The README says "pyright clean". The gitea runner checks it; the public one does not."""
    assert any("pyright" in c for c in _run_lines(ROOT / ".github" / "workflows" / "ci.yml"))


def test_s10_the_copy_gate_refuses_a_test_count_that_is_not_the_suites():
    sys.path.insert(0, str(ROOT / "scripts"))
    copy_ripple_check = importlib.import_module("copy_ripple_check")
    wrong = "refused, armed or not). **1 in-process tests** (ruff + pyright clean) pin the engine"
    right = wrong.replace("**1 in", "**6,689 in")
    assert copy_ripple_check.check_test_count(wrong, 6689)
    assert copy_ripple_check.check_test_count(right, 6689) == []


def test_s10_the_copy_gate_refuses_a_wire_count_that_was_not_measured():
    """README said 5,544 bytes for a month; the door answered 4,039."""
    sys.path.insert(0, str(ROOT / "scripts"))
    copy_ripple_check = importlib.import_module("copy_ripple_check")
    said = "Measured on this release, `tools/list` over stdio is 5,544 bytes on the wire"
    assert copy_ripple_check.check_wire_bytes(said, 4039)
    assert copy_ripple_check.check_wire_bytes(said.replace("5,544", "4,039"), 4039) == []
    assert copy_ripple_check.check_wire_bytes("no figure stated", 4039) == []


# --- C1: the arm source has no mode floor ----------------------------------------------------------

def _pair(tmp_path, source_mode: int) -> wire.Plane:
    served, source, readonly = tmp_path / "served", tmp_path / "arm-source", tmp_path / "ro"
    served.write_text("write-token\n")
    source.write_text("write-token\n")
    readonly.write_text("read-token\n")
    for f in (served, readonly):
        os.chmod(f, 0o600)
    os.chmod(source, source_mode)
    return wire.Plane("pve", BOX, str(served), arm_source=str(source), readonly_source=str(readonly))


def test_fact_c1_a_private_arm_source_arms(tmp_path):
    assert arm.arm_state(_pair(tmp_path, 0o600)).armed is True


def test_c1_a_directory_as_arm_source_is_not_told_to_chmod(tmp_path):
    cfg = _pair(tmp_path, 0o600)
    os.unlink(cfg.arm_source)
    os.mkdir(cfg.arm_source, 0o755)
    state = arm.arm_state(cfg)
    assert state.armed is False and "chmod" not in state.reason, state


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_c1_an_arm_source_others_can_read_does_not_arm(tmp_path, mode):
    state = arm.arm_state(_pair(tmp_path, mode))
    assert state.armed is False and "chmod 600" in state.reason, state


# --- S6: which lane has an allowlist ---------------------------------------------------------------

def test_fact_s6_the_guest_lanes_have_an_allowlist_and_the_other_two_do_not():
    from proximo.core import spine
    listed = {lane: entry[1] is not None for lane, entry in spine._LANES.items()}
    assert listed == {"shell": True, "agent": True, "node": False, "download": False}, listed


# --- C1.1: the same-user boundary, said by the doctor ----------------------------------------------

def test_c1_the_doctor_says_what_its_own_user_can_write_and_names_no_path(tmp_path, monkeypatch):
    from proximo.core import doctor, sameuser
    log = _two_rows(tmp_path)                         # makes the ledger key beside it, owned by this user
    for var in ("PROXIMO_ARM_SOURCE", "PROXIMO_INSTRUCTIONS", "PROXIMO_RUNBOOKS_DIR"):
        monkeypatch.delenv(var, raising=False)
    flags: list[str] = []
    kinds = sameuser.station(LedgerConfig(audit_log_path=str(log)), flags)
    assert kinds == ["the ledger key"] and len(flags) == 1
    words_file = tmp_path / "site.txt"
    words_file.write_text("site rules")
    monkeypatch.setenv("PROXIMO_INSTRUCTIONS", str(words_file))
    assert "the operator's words" in doctor.sameuser.station(LedgerConfig(audit_log_path=str(log)), [],
                                                             doctor.words.held())
    assert flags[0].startswith(sameuser.ADVISORY[0]) and str(tmp_path) not in flags[0]
    assert flags[0].startswith(doctor._ADVISORY), "the flag must sort as advice, never as a fault"
    from proximo.core import receipt
    assert receipt.flag_code(flags[0]) == "same-user-can-write"


def test_c1_a_door_that_holds_none_of_them_is_told_nothing(tmp_path, monkeypatch):
    from proximo.core import sameuser
    for var in ("PROXIMO_ARM_SOURCE", "PROXIMO_INSTRUCTIONS", "PROXIMO_RUNBOOKS_DIR"):
        monkeypatch.delenv(var, raising=False)
    flags: list[str] = []
    assert sameuser.station(LedgerConfig(audit_log_path=str(tmp_path / "no" / "audit.log")), flags) == []
    assert flags == []
    monkeypatch.setattr(sameuser, "_mine", lambda path: False)       # a door run as another user
    assert sameuser.station(LedgerConfig(audit_log_path=str(_two_rows(tmp_path))), flags) == [] and flags == []


# --- C2: a missing ledger answers ok: null ---------------------------------------------------------

@pytest.fixture
def no_ledger(monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "never-written.log"))
    for var in ("PROXIMO_AUDIT_EXPECTED_HEAD", "PROXIMO_AUDIT_ANCHOR_SINK"):
        monkeypatch.delenv(var, raising=False)


def test_c2_an_emptied_ledger_is_not_called_ok_either(tmp_path, monkeypatch):
    """Truncating the file to nothing passed where deleting it did not (the lens)."""
    log = tmp_path / "emptied.log"
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(log))
    for var in ("PROXIMO_AUDIT_EXPECTED_HEAD", "PROXIMO_AUDIT_ANCHOR_SINK"):
        monkeypatch.delenv(var, raising=False)
    from proximo.core import doctor, receipt
    for emptied in ("", "\n", "  \n\n \n", "\r\n"):       # one newline beat a size check (the second lens)
        log.write_text(emptied)
        assert door.audit_verify()["ok"] is None, repr(emptied)
        section, _ = doctor._ledger(LedgerConfig(audit_log_path=str(log)), [])
        assert section["chain"] == "no rows", (repr(emptied), section)
    assert receipt._chain("no rows") == "no rows"               # the receipt prints it, not `[text]`
    log.write_text("")
    monkeypatch.setenv("PROXIMO_AUDIT_EXPECTED_HEAD", "ab" * 32)  # a pin names a row the ledger must hold
    assert door.audit_verify()["ok"] is False


def test_c2_an_archive_with_no_rows_is_not_called_ok(tmp_path, monkeypatch):
    log = _two_rows(tmp_path)
    (tmp_path / "claims-audit.log.unkeyed-empty").write_text("")
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(log))
    out = door.audit_verify(path="claims-audit.log.unkeyed-empty")
    assert out["ok"] is None and out["entries"] == 0


def test_c3_no_cap_trims_the_line_that_says_the_outcome_was_lost():
    from proximo.core import rawdoor
    assert "receipt" in rawdoor.PROTECTED and "receipt" in rawdoor._KEEP


def test_c2_the_doctor_does_not_call_a_fresh_box_ok(tmp_path):
    from proximo.core import doctor
    section, chain_ok = doctor._ledger(LedgerConfig(audit_log_path=str(tmp_path / "none.log")), [])
    assert section["chain"] == "no rows" and chain_ok is True


def test_c2_a_missing_ledger_is_not_called_ok(no_ledger, capsys):
    out = door.audit_verify()
    assert out["ok"] is None and out["entries"] == 0 and "nothing was verified" in out["note"]
    assert cli.main(["audit", "verify"]) == cli.EXIT_REFUSED          # the shell: only a plain yes exits 0
    assert json.loads(capsys.readouterr().out)["ok"] is None


# --- C3: an outcome row that could not be written --------------------------------------------------

class _LosesTheOutcome:
    """The real ledger, except that the row written AFTER the wire cannot be written."""

    def __init__(self, real, rec):
        self._real, self._rec = real, rec

    def record(self, action, **kw):
        if _writes(self._rec):
            raise OSError("no space left on device")
        return self._real.record(action, **kw)

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_fact_c3_a_healthy_answer_says_nothing_about_a_lost_record(wired):
    cfg, rec = wired
    plane, method, path, args = POOL
    out = door.call(plane, method, path, args, confirm=True, cfg=cfg)
    assert len(_writes(rec)) == 1 and "not recorded" not in json.dumps(out)


def test_c3_the_answer_says_when_its_outcome_was_not_recorded(wired, monkeypatch):
    cfg, rec = wired
    real_open = engine.open_ledger
    monkeypatch.setattr(engine, "open_ledger", lambda c: _LosesTheOutcome(real_open(c), rec))
    plane, method, path, args = POOL
    out = door.call(plane, method, path, args, confirm=True, cfg=cfg)
    assert len(_writes(rec)) == 1, "the mutation itself must still have run"
    assert "outcome not recorded" in out["receipt"], out


# --- C7: log-shaped reads without the untrusted label ----------------------------------------------

_LOG_SHAPED = re.compile(r"/(log|logs|syslog|journal|changelog)$")


def test_fact_c7_the_label_is_already_on_most_log_shaped_reads():
    logs = [r for r in engine.table().values() if r.method == "GET" and not r.excluded and _LOG_SHAPED.search(r.path)]
    assert sum(1 for r in logs if r.untrusted) > len(logs) / 2


def test_c7_every_log_shaped_read_carries_the_untrusted_label():
    logs = [r for r in engine.table().values() if r.method == "GET" and not r.excluded and _LOG_SHAPED.search(r.path)]
    bare = sorted(f"{r.product} {r.path}" for r in logs if not r.untrusted)
    assert bare == [], bare
