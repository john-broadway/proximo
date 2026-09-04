"""`proximo harden` — the guided erection of the operator-ground pillars.

Pins: (1) posture flips per-station with the env, (2) recipes render ONLY for empty stations
(a standing pillar gets a checkmark, not instructions), (3) the disclosure rule: a configured
path's VALUE never appears in the output — same rule as doctor's spine block (a hijacked
session must not learn where the operator put their switch), (4) --check exits 1 when any core
gated station (CONSENT/CONTAIN/PROVE-ANCHOR — ARM is reported, never gated: mint-and-revoke
is a documented correct posture with a forever-empty ARM station) is empty, 0 when the gated
three stand, (5) the CLI verb prints and exits without starting the server or applying
surface scoping.
"""
from __future__ import annotations

import pytest

import proximo.server as srv
from proximo import harden

CORE = ("CONSENT", "CONTAIN", "PROVE-ANCHOR", "MIRROR", "ARM")


def _clear(monkeypatch):
    for var in ("PROXIMO_CONSENT_DIR", "PROXIMO_CONTAIN_TRIP_PATH",
                "PROXIMO_AUDIT_ANCHOR_SINK", "PROXIMO_AUDIT_EXPECTED_HEAD",
                "PROXIMO_ARM_SOURCE", "PROXIMO_ARM_TTL", "PROXIMO_SCOPE_PATH",
                "PROXIMO_REACH_PRIVILEGE",
                "PROXIMO_TAINT_TRACK", "PROXIMO_TAINT_FORBID", "PROXIMO_FORBID",
                "PROXIMO_RATE_MAX"):
        monkeypatch.delenv(var, raising=False)


def test_posture_all_empty(monkeypatch):
    _clear(monkeypatch)
    stations = {s.name: s for s in harden.posture()}
    assert set(CORE) <= set(stations)
    for name in CORE:
        assert stations[name].configured is False


def test_posture_flips_per_station(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", "/somewhere/consent")
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SINK", "file")
    stations = {s.name: s for s in harden.posture()}
    assert stations["CONSENT"].configured is True
    assert stations["PROVE-ANCHOR"].configured is True
    assert stations["CONTAIN"].configured is False
    assert stations["ARM"].configured is False


def test_anchor_none_sink_is_not_configured(monkeypatch):
    # PROXIMO_AUDIT_ANCHOR_SINK=none is the explicit OFF value — it must not count.
    _clear(monkeypatch)
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SINK", "none")
    stations = {s.name: s for s in harden.posture()}
    assert stations["PROVE-ANCHOR"].configured is False


def test_render_recipes_only_for_empty(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", "/x/trip")
    out = harden.render(harden.posture())
    assert "CONTAIN" in out and "standing" in out.lower()
    assert "PROXIMO_CONTAIN_TRIP_PATH" not in out  # standing station: checkmark, no recipe
    assert "PROXIMO_CONSENT_DIR" in out            # empty station's recipe present
    assert "outside the agent" in out.lower()    # the placement law is stated
    assert "verify:" in out.lower()              # every empty station ends in a verify line


def test_disclosure_rule_no_path_values(monkeypatch):
    # The output may say a pillar stands; it must NEVER say where.
    _clear(monkeypatch)
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", "/secret/place/consent")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", "/secret/place/trip")
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", "/secret/place/arm.token")
    out = harden.render(harden.posture())
    assert "/secret/place" not in out


def test_check_exit_codes(monkeypatch):
    _clear(monkeypatch)
    assert harden.check_exit(harden.posture()) == 1
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", "/a")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", "/b")
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SINK", "syslog")
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", "/c")
    assert harden.check_exit(harden.posture()) == 0


def test_check_never_gates_on_arm(monkeypatch):
    # Lens finding: mint-and-revoke deployments hold NO standing write token — a documented
    # CORRECT posture (armgate: "the gate stays dormant — which is correct, not a hole").
    # --check must stay green there or its cron teeth bite a legitimate estate forever.
    _clear(monkeypatch)
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", "/a")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", "/b")
    monkeypatch.setenv("PROXIMO_AUDIT_ANCHOR_SINK", "journal")
    assert harden.check_exit(harden.posture()) == 0  # ARM empty, still green
    stations = {s.name: s for s in harden.posture()}
    assert stations["ARM"].configured is False       # ...but still REPORTED honestly


def test_anchor_recipe_names_both_families_and_the_syslog_var(monkeypatch):
    # Lens finding: the first draft claimed startup verifies (it only seeds the pin) and
    # omitted the REQUIRED syslog address var. The recipe must carry the honest split.
    _clear(monkeypatch)
    out = harden.render(harden.posture())
    assert "PROXIMO_AUDIT_ANCHOR_SYSLOG_ADDRESS" in out
    assert "WRITE-ONLY" in out and "FETCHABLE" in out
    assert "audit_verify TOOL" in out            # verify line names the tool, not a CLI verb
    assert "proximo audit_verify" not in out     # that CLI verb does not exist


def test_cli_prints_and_never_serves(monkeypatch, capsys):
    _clear(monkeypatch)
    monkeypatch.setattr(srv.sys, "argv", ["proximo", "harden"])
    served = {}
    monkeypatch.setattr(srv.mcp, "run", lambda *a, **k: served.__setitem__("ran", True))
    srv.main()
    out = capsys.readouterr().out
    assert "CONSENT" in out and "CONTAIN" in out and "ARM" in out
    assert "ran" not in served, "harden must never start the server"


def test_cli_check_flag_exits_nonzero_when_empty(monkeypatch, capsys):
    _clear(monkeypatch)
    monkeypatch.setattr(srv.sys, "argv", ["proximo", "harden", "--check"])
    monkeypatch.setattr(srv.mcp, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError))
    with pytest.raises(SystemExit) as ei:
        srv.main()
    assert ei.value.code == 1


def test_harden_verb_skips_surface_scoping(monkeypatch):
    # mint/arm/badge-class verbs skip _apply_surfaces (scoping noise would prefix their
    # output); harden must be in that club. The verb tuple moved out of main() on
    # 2026-09-03 (one tuple, _QUIET_STDERR_VERBS, now gates the scoping line AND the
    # env-file loader's lines), so the membership is asserted on the tuple and the gate
    # order on main()'s source.
    import inspect
    assert "harden" in srv._QUIET_STDERR_VERBS, "harden missing from the quiet-verb tuple"
    import re
    src = inspect.getsource(srv.main)
    # The gate must be THE condition on the _apply_surfaces call, not merely a substring that
    # appears somewhere earlier in main() (lens B: `if True:` in front of _apply_surfaces left
    # the loader's own `announce=not _quiet_stderr_verb()` in place and a substring search green).
    assert re.search(r"if not _quiet_stderr_verb\(\):\s*\n\s*try:\s*\n\s*_apply_surfaces\(\)", src), \
        "main() must gate _apply_surfaces() on `if not _quiet_stderr_verb():` directly"


def test_mirror_station_reported_never_check_gated(monkeypatch):
    # Dormant-unset is the mirror's own contract and allowlist-only estates are a documented
    # correct posture — so MIRROR reports (with the reach-audit recipe) but --check must not
    # bite an estate that never sets the privilege (the ARM precedent).
    _clear(monkeypatch)
    stations = {s.name: s for s in harden.posture()}
    assert stations["MIRROR"].configured is False
    assert "MIRROR" not in harden._CHECK_GATED
    assert "reach-audit" in stations["MIRROR"].recipe
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    stations = {s.name: s for s in harden.posture()}
    assert stations["MIRROR"].configured is True
