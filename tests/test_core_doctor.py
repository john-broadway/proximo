"""DOCTOR: the gate diagnoses itself (parity row B6, `harden` folded in; the 0.45 bar: "keep, small").

0.44's `proximo doctor` was a 676-line preflight that translated the token's PVE privileges into a
capability vocabulary with role hints, and `proximo harden` printed which agent-binding stations
stood with a recipe for each empty one. The core's doctor is the operator's verb at setup, CLI
only (the six tools are the 4K window): it reads the record, each plane's configuration, arm
state and reach (the vendor's own `/version` and `/access/permissions`, bounded, never
translated: bar 4, nothing re-does Proxmox's RBAC), the ledger's chain, and which of the six
pillars stand, with the line that would raise an empty one. Stations report yes, NEVER where: no
switch's path, no secret's path, no token byte in the answer. Flags are advisory and move no exit
code; the exit codes are the shell door's contract (0 ran whole, 3 nothing configured, 4 a plane
unreachable or the chain unjudgeable), never 2, which is the spine's own refusal.
"""
from __future__ import annotations

import json
import os

import httpx
import pytest

from proximo.core import doctor, engine, spine
from proximo.core.doors import cli
from proximo.core.errors import ProximoError
from proximo.core.ledger import LedgerConfig

MARK = "zq9x-secret-marker"                 # rides in every path a doctor must never print


class Wire:
    """Answers the two reads the doctor makes; `fail` names a path whose read raises."""

    def __init__(self, fail: str | None = None):
        self.calls: list[tuple[str, str]] = []
        self.fail = fail

    def call(self, method, path, params=None):
        self.calls.append((method, path))
        if self.fail and path.startswith(self.fail):
            req = httpx.Request(method, "https://pve.invalid:8006/api2/json" + path)
            raise httpx.HTTPStatusError("401", request=req, response=httpx.Response(401, request=req))
        if path == "/version":
            return {"version": "9.2.2", "release": "9.2", "repoid": "b9984c6d90a4bd80"}
        if path == "/access/permissions":
            return {"/": {"Sys.Audit": 1}, "/vms/101": {"VM.Audit": 1, "VM.PowerMgmt": 1},
                    "/storage/local": {"Datastore.Audit": 1}}
        raise AssertionError(f"the doctor read {method} {path}, which it must not")


def _rows():
    log = os.environ["PROXIMO_AUDIT_LOG"]
    if not os.path.exists(log):
        return []
    with open(log, encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]


@pytest.fixture
def box(armed_plane, monkeypatch, tmp_path):
    """The env box IS the pve plane: doctor reads it from the environment like a door does."""
    os.chmod(armed_plane.token_path, 0o600)                       # the wire refuses a readable secret
    monkeypatch.setenv("PROXIMO_API_BASE_URL", armed_plane.base_url)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", armed_plane.token_path)
    for var in ("PROXIMO_PBS_BASE_URL", "PROXIMO_PBS_TOKEN_PATH", "PROXIMO_PMG_BASE_URL", "PROXIMO_PMG_CREDENTIAL_PATH",
                "PROXIMO_PMG_PASSWORD_PATH", "PROXIMO_PDM_BASE_URL", "PROXIMO_PDM_TOKEN_PATH", "PROXIMO_TARGETS",
                "PROXIMO_SSH_TARGET", "PROXIMO_RESTORE_DIR"):
        monkeypatch.delenv(var, raising=False)
    w = Wire()
    monkeypatch.setattr(engine, "_client", lambda product, c=None: w)
    return w


def _report(**kw):
    return doctor.run(**kw)


# --- the record ----------------------------------------------------------------------------------

def test_the_record_section_counts_what_the_table_holds(box):
    r = _report()
    rec = r["record"]
    assert rec["rows"] > 1500 and rec["mutations"] > 500 and rec["held"] == 20 and rec["creates"] == 5
    assert rec["tiered"] + rec["held"] == rec["mutations"]                 # the arena: tiered or held, nothing else
    assert rec["untrusted"] > 0 and "refused" not in rec


def test_a_record_that_does_not_parse_is_the_first_thing_the_doctor_says(box, monkeypatch):
    """`table()` raises on a bad tiers.toml and every mutation is refused until it parses: the
    doctor reports the words and keeps going, never a traceback, never silence."""
    def boom():
        raise ProximoError("tiers.toml is not a readable TOML table (TOMLDecodeError): every mutation is refused")
    monkeypatch.setattr(engine, "table", boom)
    r = _report()
    assert r["record"] == {"refused": "tiers.toml is not a readable TOML table (TOMLDecodeError): every mutation "
                                      "is refused"}
    assert any("record" in f and "refused" in f for f in r["flags"]) and r["complete"] is False
    assert "planes" in r and "ledger" in r                                  # it went on


def test_a_bad_undo_record_refuses_the_build_and_the_report_counts_the_judged_creates(box, records):
    """A create line without its why never ships: the build refuses it by name, so the report has
    no undo.toml of its own to flag; it counts the judged creates the rows carry."""
    with pytest.raises(ProximoError, match="undo.toml: create line .* without a why"):
        records(**{"undo.toml": '[create]\n"pve:POST /access/users/{userid}/token/{tokenid}" = { why = "short" }\n'})
    r = _report()
    assert r["record"]["creates"] == 5 and not any("undo.toml" in f for f in r["flags"])


# --- the planes ----------------------------------------------------------------------------------

def test_the_env_plane_is_configured_armed_and_reached_through_receipted_reads(box):
    r = _report()
    pve = r["planes"]["pve"]
    assert pve["configured"] is True and pve["base_url"] == "https://pve.invalid:8006/api2/json"
    assert pve["arm"] == {"enforced": True, "armed": True, "reason": "armed"}
    assert pve["reach"]["version"] == "9.2.2"
    assert pve["reach"]["permissions"] == {"paths": 3, "sample": ["/", "/storage/local", "/vms/101"]}
    assert box.calls == [("GET", "/version"), ("GET", "/access/permissions")]
    reads = [x for x in _rows() if x["action"] == "core.execute" and x["outcome"] == "ok"]
    assert [x["target"] for x in reads] == ["/version", "/access/permissions"]     # receipted like any read
    assert r["complete"] is True and r["exit"] == cli.EXIT_OK


def test_an_unconfigured_plane_names_every_missing_variable_the_way_the_wire_does(box):
    r = _report()
    assert r["planes"]["pbs"] == {"configured": False, "missing": ["PROXIMO_PBS_BASE_URL", "PROXIMO_PBS_TOKEN_PATH"]}
    assert r["planes"]["pmg"]["missing"] == ["PROXIMO_PMG_BASE_URL",
                                             "PROXIMO_PMG_CREDENTIAL_PATH (or PROXIMO_PMG_PASSWORD_PATH)"]
    assert r["planes"]["pdm"]["configured"] is False


def test_pmg_publishes_no_permissions_read_and_the_section_says_so(box, monkeypatch, tmp_path):
    cred = tmp_path / f"{MARK}-pmg.cred"
    cred.write_text("api@pmg\nhunter2\n")
    cred.chmod(0o600)
    monkeypatch.setenv("PROXIMO_PMG_BASE_URL", "https://pmg.invalid:8006/api2/json")
    monkeypatch.setenv("PROXIMO_PMG_CREDENTIAL_PATH", str(cred))
    r = _report()
    pmg = r["planes"]["pmg"]
    assert pmg["configured"] is True and pmg["reach"]["version"] == "9.2.2"
    assert pmg["reach"]["permissions"] == {"skipped": "pmg publishes no GET /access/permissions"}


def test_a_plane_the_vendor_refuses_is_a_flag_an_incomplete_report_and_exit_4(box):
    box.fail = "/version"
    r = _report()
    assert r["planes"]["pve"]["reach"]["version"] == {"error": "HTTPStatusError", "status": 401}
    assert "permissions" not in r["planes"]["pve"]["reach"]                  # nothing read past a closed door
    assert any("pve" in f and "reach" in f for f in r["flags"])
    assert r["complete"] is False and r["exit"] == cli.EXIT_VENDOR


def test_no_plane_configured_is_exit_3_with_the_variables_named(box, monkeypatch):
    monkeypatch.delenv("PROXIMO_API_BASE_URL")
    monkeypatch.delenv("PROXIMO_TOKEN_PATH")
    r = _report()
    assert all(p["configured"] is False for p in r["planes"].values())
    assert r["exit"] == cli.EXIT_USAGE and any("no plane" in f for f in r["flags"])


def test_the_arm_reason_names_file_conditions_never_a_path(box, monkeypatch, tmp_path):
    arm = tmp_path / f"{MARK}-write.token"
    arm.write_text("write-token-bytes")
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", str(arm))
    monkeypatch.setattr(engine.arm, "arm_state",
                        lambda cfg=None: engine.arm.ArmGateState(True, False, "arm source present, token not swapped"))
    r = _report()
    assert r["planes"]["pve"]["arm"]["armed"] is False and MARK not in json.dumps(r)


def test_targets_are_counted_and_named_never_located(box, monkeypatch, tmp_path):
    reg = tmp_path / f"{MARK}-targets.toml"
    reg.write_text('[targets.east]\nkind = "pve"\nbase_url = "https://east.invalid:8006/api2/json"\n'
                   'token_path = "/nonexistent/tok"\n')
    monkeypatch.setenv("PROXIMO_TARGETS", str(reg))
    r = _report()
    assert r["targets"] == {"configured": True, "count": 1, "names": ["east"]}
    assert MARK not in json.dumps(r) and "east.invalid" not in json.dumps(r["targets"])


# --- the ledger (PROVE) --------------------------------------------------------------------------

def test_the_ledger_section_reads_the_chain_keyed_and_whole(box):
    r = _report()
    led = r["ledger"]
    assert led["keyed"] is True and led["key_readable"] is True and led["chain"] == "ok"
    assert led["rows"] >= 2 and led["in_flight"] == 0
    assert r["pillars"]["PROVE"]["standing"] is True


def test_an_unkeyed_log_is_sealed_at_the_doctors_own_arrival_and_the_archive_is_named(box):
    """The ledger is keyed, always, since the cut (2026-10-18); what can still be unkeyed is the
    LOG a 0.44 box opted out of (or a writer that bypassed the door). The doctor arrives through
    the door like every verb, so the door seals that log and starts the keyed one before the
    report reads it: the report says so, by the archive's name, and PROVE stands on the live
    chain. The archive is evidence too; the flag says how to verify it."""
    from proximo.core.ledger import AuditLedger
    log = os.environ["PROXIMO_AUDIT_LOG"]
    AuditLedger(log).record("legacy", target="/x")                          # a bare SHA-256 row, 0.44's opt-out
    r = _report()
    led = r["ledger"]
    assert led["mode"] == "keyed" and led["keyed"] is True and led["chain"] == "ok"
    assert led["sealed_archive"].startswith("proximo-test-audit.log.unkeyed-")
    assert any("sealed rotation archive" in f and "audit_verify(path=" in f for f in r["flags"])
    assert r["pillars"]["PROVE"]["standing"] is True
    assert _report()["ledger"]["sealed_archive"] == led["sealed_archive"]


def test_a_tampered_row_breaks_the_chain_and_prove_falls_with_exit_4(box):
    _report()                                                               # two rows on the chain
    log = os.environ["PROXIMO_AUDIT_LOG"]
    lines = open(log, encoding="utf-8").read().splitlines(keepends=True)
    i = next(n for n, x in enumerate(lines) if '"outcome":"ok"' in x)
    lines[i] = lines[i].replace('"outcome":"ok"', '"outcome":"OK"', 1)     # one byte of history rewritten
    open(log, "w", encoding="utf-8").writelines(lines)
    r = _report()
    assert r["ledger"]["chain"].startswith("broken at ") and r["pillars"]["PROVE"]["standing"] is False
    assert r["complete"] is False and r["exit"] == cli.EXIT_VENDOR and any("chain" in f for f in r["flags"])


def test_an_open_executing_row_is_counted_in_flight_and_flagged(box, monkeypatch):
    row = engine.resolve("pve", "PUT", "/nodes/pve1/qemu/101/config")
    engine._record(LedgerConfig.from_env(), "core.execute", engine.Row(**{**row.__dict__, "tier": "restorable"}),
                   outcome="executing", detail={"intent": "deadbeef", "undo": {"captured": False}},
                   called="/nodes/pve1/qemu/101/config")
    r = _report()
    assert r["ledger"]["in_flight"] == 1 and any("in flight" in f for f in r["flags"])


# --- the pillars (harden folded in) --------------------------------------------------------------

def test_the_six_pillars_are_reported_and_an_empty_one_carries_the_line_that_raises_it(box):
    r = _report()
    p = r["pillars"]
    assert set(p) == {"PLAN", "CONSENT", "PROVE", "UNDO", "DIAGNOSE", "CONTAIN"}
    assert p["PLAN"]["standing"] is True and p["UNDO"] == {"standing": True, "creates_judged": 5}
    assert p["CONSENT"]["standing"] is False and "PROXIMO_CONSENT_DIR=" in p["CONSENT"]["raise"]
    assert p["CONTAIN"]["trip"] == {"configured": False, "tripped": False}
    assert "PROXIMO_CONTAIN_TRIP_PATH=" in p["CONTAIN"]["raise"]
    assert p["CONTAIN"]["rate"] == {"max": None, "window": 60} and p["CONTAIN"]["forbid"] == 0
    assert p["CONTAIN"]["taint"] == {"track": False, "forbid": False, "require_consent": False, "fence": False}
    assert p["DIAGNOSE"]["lanes"] == {"agent": {"open": False}, "shell": {"open": False}, "node": {"open": False},
                                      "download": {"open": False}}
    assert any("CONSENT" in f for f in r["flags"]) and any("CONTAIN" in f for f in r["flags"])


def test_a_raised_pillar_reports_standing_through_the_spines_own_readers(box, monkeypatch, tmp_path):
    consent = tmp_path / f"{MARK}-consent"
    consent.mkdir()
    trip = tmp_path / f"{MARK}-trip"
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(consent))
    monkeypatch.setenv("PROXIMO_CONSENT_TTL_SECONDS", "120")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))
    monkeypatch.setenv("PROXIMO_RATE_MAX", "5")
    monkeypatch.setenv("PROXIMO_RATE_WINDOW", "600")
    monkeypatch.setenv("PROXIMO_FORBID", "purge=1,DELETE /nodes")
    monkeypatch.setenv("PROXIMO_TAINT_TRACK", "1")
    monkeypatch.setenv("PROXIMO_TAINT_FENCE", "1")
    monkeypatch.setenv("PROXIMO_ENABLE_EXEC", "1")
    monkeypatch.setenv("PROXIMO_CT_ALLOWLIST", "101,102")
    monkeypatch.setenv("PROXIMO_ENABLE_NODE_SHELL", "1")
    r = _report()
    p = r["pillars"]
    assert p["CONSENT"] == {"standing": True, "ttl_seconds": 120}
    assert p["CONTAIN"]["trip"] == {"configured": True, "tripped": False}
    assert p["CONTAIN"]["rate"] == {"max": 5, "window": 600} and p["CONTAIN"]["forbid"] == 2
    assert p["CONTAIN"]["taint"]["track"] is True and p["CONTAIN"]["taint"]["fence"] is True
    assert p["DIAGNOSE"]["lanes"]["shell"] == {"open": True, "allowlist": 2}
    assert p["DIAGNOSE"]["lanes"]["node"] == {"open": True}
    assert not any("CONSENT" in f for f in r["flags"])
    trip.write_text("stopped by the operator at 03:00")
    r = _report()
    assert r["pillars"]["CONTAIN"]["trip"] == {"configured": True, "tripped": True,
                                               "reason": "stopped by the operator at 03:00"}
    assert any("tripped" in f for f in r["flags"])
    assert MARK not in json.dumps(r)


def test_a_retired_switch_is_flagged_with_the_spines_own_sentence(box, monkeypatch):
    monkeypatch.setenv("PROXIMO_SCOPE_PATH", "/x/scope.toml")
    r = _report()
    assert r["retired"] == [spine.retired_refusal().reason] and any("PROXIMO_SCOPE_PATH" in f for f in r["flags"])
    assert "/x/scope.toml" not in json.dumps(r)


# --- disclosure: yes, never where ------------------------------------------------------------------

def test_no_path_of_a_switch_or_a_secret_and_no_token_byte_reaches_the_answer(box, monkeypatch, tmp_path):
    """THE RULE IS A TEST. Every path the operator could set carries the marker; the token file's
    bytes are distinctive; the whole JSON must carry neither. The control plants one path."""
    tok = tmp_path / f"{MARK}-token"
    tok.write_text(f"root@pam!x={MARK}-TOKEN-BYTES")
    tok.chmod(0o600)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(tok))
    for var in ("PROXIMO_ARM_SOURCE", "PROXIMO_READONLY_SOURCE", "PROXIMO_CONSENT_DIR", "PROXIMO_CONTAIN_TRIP_PATH",
                "PROXIMO_RESTORE_DIR", "PROXIMO_AUDIT_KEY_PATH"):
        monkeypatch.setenv(var, str(tmp_path / f"{MARK}-{var.lower()}"))
    (tmp_path / f"{MARK}-proximo_consent_dir").mkdir()
    r = _report()
    text = json.dumps(r)
    assert MARK not in text and "TOKEN-BYTES" not in text, text
    assert os.environ["PROXIMO_AUDIT_LOG"] not in text                       # the ledger's path stays out too
    planted = {**r, "where": os.environ["PROXIMO_CONSENT_DIR"]}
    assert MARK in json.dumps(planted)                                      # the control: a path would be seen


# --- the door ------------------------------------------------------------------------------------

def test_the_shell_door_dispatches_doctor_like_mint_and_prints_only_json(box, capsys):
    rc = cli.main(["doctor"])
    out = capsys.readouterr()
    r = json.loads(out.out)
    assert rc == cli.EXIT_OK and r["complete"] is True and "exit" not in r      # the code is the process's, not a field
    assert out.err == ""


def test_the_shell_door_exit_follows_the_report(box, capsys):
    box.fail = "/version"
    assert cli.main(["doctor"]) == cli.EXIT_VENDOR
    json.loads(capsys.readouterr().out)


def test_doctor_takes_no_arguments(box, capsys):
    assert cli.main(["doctor", "pve"]) == cli.EXIT_USAGE
    assert "doctor takes no arguments" in capsys.readouterr().err


def test_the_module_stays_small():
    """The 0.45 bar sorted doctor as "keep, small". 0.44's was 676 lines + 167 of harden."""
    import inspect
    # 252: PROVE's anchor station added two lines here; its words and logic live in core/anchor.py.
    assert len([x for x in inspect.getsource(doctor).splitlines() if x.strip()]) <= 252


def test_the_wires_own_refusal_of_a_readable_secret_is_said_without_its_path(box, monkeypatch, tmp_path):
    """`Plane.from_env` names the file and the chmod for the operator's terminal; in a report that
    could be pasted anywhere, the path is a locator and goes out scrubbed."""
    tok = tmp_path / f"{MARK}-loose.token"
    tok.write_text("root@pam!x=abc")
    tok.chmod(0o644)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(tok))
    r = _report()
    pve = r["planes"]["pve"]
    assert pve["configured"] is False and "mode 644" in pve["error"] and MARK not in json.dumps(r)


# --- the lens fold (2026-10-09) --------------------------------------------------------------------

def test_a_read_the_door_cut_is_an_error_never_a_clean_read_of_nothing(box, monkeypatch):
    """LENS, MAJOR: a size-cut envelope has no `data`; the doctor read it as version None and
    "0 permissions" and said complete. A cut is named with its bytes and the report is not whole."""
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "50")
    r = _report()
    reach = r["planes"]["pve"]["reach"]
    assert reach["version"]["error"] == "cut" and reach["version"]["bytes"] > 50 and reach["version"]["cap"] == 50
    assert "permissions" not in reach                                      # a cut version is a closed door too
    assert r["complete"] is False and any("pve" in f and "cut" in f for f in r["flags"])


def test_a_cut_permissions_read_says_what_it_holds_is_not_known(box, monkeypatch):
    big = {f"/vms/{n}": {"VM.Audit": 1} for n in range(100, 400)}
    monkeypatch.setattr(box, "call",
                        lambda m, p, params=None: big if p == "/access/permissions" else {"version": "9.2.2"})
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "2000")
    r = _report()
    reach = r["planes"]["pve"]["reach"]
    assert reach["version"] == "9.2.2" and reach["permissions"]["error"] == "cut"
    assert any("cut by the door" in f and "not known" in f for f in r["flags"]) and r["complete"] is False


def test_the_trip_files_text_is_one_bounded_line_with_no_path(box, monkeypatch, tmp_path):
    """LENS, MAJOR: the trip file's whole content went out verbatim. A mis-pointed trip path is
    any file; a token file was dumped whole. Bounded, scrubbed, one line."""
    trip = tmp_path / f"{MARK}-trip"
    # (a fake path shape: the release leak audit refuses a root-path literal anywhere in the tree)
    trip.write_text("stopped: see /opt/lab/secret.key and " + "x" * 500 + "\nline two")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))
    r = _report()
    reason = r["pillars"]["CONTAIN"]["trip"]["reason"]
    assert "/opt/lab/secret.key" not in json.dumps(r) and "\n" not in reason and len(reason) <= 220
    assert "line two" not in reason or len(reason) <= 220


def test_a_tripped_box_is_not_a_complete_report(box, monkeypatch, tmp_path):
    """LENS, MINOR folded with the lines above: the advisory prefix "CONTAIN" covered "CONTAIN is
    tripped", so a box refusing every mutation reported complete."""
    trip = tmp_path / f"{MARK}-trip"
    trip.write_text("halt")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", str(trip))
    r = _report()
    assert r["pillars"]["CONTAIN"]["trip"]["tripped"] is True and r["complete"] is False and r["exit"] == cli.EXIT_OK


# --- every refusal the report repeats goes out scrubbed (2026-10-09) -----------------------------
# The lens named the trip line and the wire's refusal; the record, undo.toml, registry and read
# refusals still repeated `str(exc)` whole. No raise text that reaches these four sites carries a
# path today (tiers/undo/taint/secrets name their file by bare name, the registry names its env
# var; the ledger's `no ledger at <path>` does, and `_ledger` drops it, never repeating it), so
# these drive a ProximoError that does, to pin the policy for the next text that will: a refusal
# the report repeats is a locator seam like any other, and it goes through the one scrubber.

_LOCATED = f"refused: /opt/{MARK}/record.toml is not readable, see 'C:\\lab\\{MARK}\\x' and https://box.invalid:8006/x"


def _raises(*_a, **_k):
    raise ProximoError(_LOCATED)


def test_a_located_record_refusal_is_repeated_without_the_locator(box, monkeypatch):
    monkeypatch.setattr(engine, "table", _raises)
    r = _report()
    assert MARK not in json.dumps(r) and "box.invalid" not in json.dumps(r)
    assert r["record"] == {"refused": "refused: <path> is not readable, see <path> and <url>"}
    assert any("the record is refused" in f and "<path>" in f for f in r["flags"])


def test_a_located_registry_refusal_is_repeated_without_the_locator(box, monkeypatch, tmp_path):
    monkeypatch.setenv("PROXIMO_TARGETS", str(tmp_path / f"{MARK}-targets.toml"))
    monkeypatch.setattr(doctor.registry, "load_registry", _raises)
    r = _report()
    assert MARK not in json.dumps(r)
    assert r["targets"] == {"configured": True, "error": "refused: <path> is not readable, see <path> and <url>"}
    assert any("target registry" in f and "<path>" in f for f in r["flags"])


def test_a_located_spine_refusal_of_a_read_is_repeated_without_the_locator(box, monkeypatch):
    monkeypatch.setattr(engine, "execute", _raises)
    r = _report()
    assert MARK not in json.dumps(r)
    assert r["planes"]["pve"]["reach"]["version"] == {"error": "refused",
                                                      "reason": "refused: <path> is not readable, see <path> and <url>"}


def test_an_advisory_consent_box_says_so_in_the_health_report(box, monkeypatch, tmp_path):
    # the exception is visible everywhere it could be mistaken for a lock, DIAGNOSE included
    consent = tmp_path / f"{MARK}-consent"
    consent.mkdir()
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(consent))
    monkeypatch.setenv("PROXIMO_CONSENT_SAME_USER", "advisory")
    r = _report()
    assert r["pillars"]["CONSENT"]["advisory"] is True
    assert any("advisory" in f and "speed bump" in f for f in r["flags"]), r["flags"]
