"""pve_doctor — connectivity + token-permission preflight (unit + PROVE seam).

The doctor is read-only and onboarding-facing: it answers "is my config/token right, and what
can this token actually DO?" before a stranger wires Proximo into an MCP client. Same advisory,
never-overclaim posture as DIAGNOSE; routes through the ledger (mutation=False) like other reads.
"""
from __future__ import annotations

import json
import os
import sys
from types import SimpleNamespace

import pytest

import proximo.door as door
import proximo.server as server
from proximo import targets
from proximo.audit import AuditLedger
from proximo.config import ProximoConfig
from proximo.doctor import doctor_check
from proximo.principal import public_jwk


def _cfg(**kw):
    base = dict(node="pve", api_base_url="https://pve.example:8006/api2/json",
               enable_exec=False, verify_tls=True, ca_bundle=None, ct_allowlist=frozenset())
    base.update(kw)
    return SimpleNamespace(**base)


class _DoctorApi:
    def __init__(self, *, version=None, version_raises=False, perms=None, perms_raises=False, config=None):
        self._version = version if version is not None else {"release": "8.2", "version": "8.2.1"}
        self._version_raises = version_raises
        self._perms = perms if perms is not None else {"/": {"Sys.Audit": 1, "VM.Audit": 1}}
        self._perms_raises = perms_raises
        self.config = config or _cfg()

    def version(self):
        if self._version_raises:
            raise RuntimeError("connect timeout")
        return self._version

    def access_permissions(self, path=None):
        if self._perms_raises:
            raise RuntimeError("403 permission denied")
        return self._perms


def test_reachable_and_version():
    out = doctor_check(_DoctorApi())
    assert out["reachable"] is True
    assert out["version"].get("version") == "8.2.1"
    assert out["complete"] is True


def test_surfaces_block_reports_planes_and_scoping():
    """doctor answers "364 is a lot" itself: per-plane configured/served + the scoping reason."""
    out = doctor_check(_DoctorApi())
    s = out["surfaces"]
    assert s["served_tools"] > 300                      # full registry in the unit context
    assert {"pve", "pbs", "pmg", "pdm"} <= set(s["planes"])
    assert "PROXIMO_SURFACES" in s["note"]
    assert "scoping" in s


def test_surfaces_reflects_a_configured_plane(monkeypatch):
    """A configured plane shows configured=True; an unconfigured one offers how to enable it."""
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs.example.lan:8007/api2/json")
    monkeypatch.delenv("PROXIMO_PMG_BASE_URL", raising=False)
    monkeypatch.delenv("PROXIMO_TARGETS", raising=False)
    s = doctor_check(_DoctorApi())["surfaces"]
    assert s["planes"]["pbs"]["configured"] is True
    assert s["planes"]["pmg"]["configured"] is False
    # pmg tools are still in the full unit registry, so it reports served>0 here; when NOT served
    # (a live auto-scoped server) it would carry enable_with. Assert the enable hint exists in code path:
    assert "scoping" in s


def test_unreachable_flags_and_incomplete():
    out = doctor_check(_DoctorApi(version_raises=True))
    assert out["reachable"] is False
    assert any("reach" in f.lower() or "authenticat" in f.lower() for f in out["flags"])
    assert out["complete"] is False


def test_capability_can_when_priv_present():
    out = doctor_check(_DoctorApi(perms={"/": {"VM.Audit": 1, "VM.PowerMgmt": 1}}))
    cans = " ".join(c["capability"].lower() for c in out["token"]["can"])
    assert "power" in cans


def test_capability_cannot_has_needs_and_hint():
    out = doctor_check(_DoctorApi(perms={"/": {"VM.Audit": 1}}))  # read-only token, no power
    power = [c for c in out["token"]["cannot"] if "power" in c["capability"].lower()]
    assert power, "power should be in the cannot list for a read-only token"
    assert "VM.PowerMgmt" in " ".join(power[0]["needs"])
    assert power[0]["hint"] and "pveum acl modify" in power[0]["hint"]


def test_scoped_grant_is_noted_not_root():
    # snapshot only granted on a pool path, not at root — doctor must say it's scoped there.
    out = doctor_check(_DoctorApi(perms={"/": {"VM.Audit": 1}, "/pool/proximo-test": {"VM.Snapshot": 1}}))
    snap = [c for c in out["token"]["can"]
            if "snapshot" in c["capability"].lower() or "undo" in c["capability"].lower()]
    assert snap, "snapshot capability should be present (granted on the pool)"
    assert any("/pool/proximo-test" in s.get("scope", "") for s in snap)


def test_no_permissions_is_flagged():
    out = doctor_check(_DoctorApi(perms={}))
    assert any("no permission" in f.lower() or "cannot read or act" in f.lower() for f in out["flags"])


def test_perms_read_failure_is_flagged_not_crash():
    out = doctor_check(_DoctorApi(perms_raises=True))
    assert out["reachable"] is True  # version() still worked
    assert any("permission" in f.lower() for f in out["flags"])
    assert out["complete"] is False


def test_config_readiness_surfaced():
    out = doctor_check(_DoctorApi(config=_cfg(enable_exec=False, verify_tls=False, ca_bundle=None)))
    assert out["config"]["exec_enabled"] is False
    assert out["config"]["node"] == "pve"
    assert any("tls" in f.lower() for f in out["flags"])  # TLS off + no CA bundle warned


def test_rollback_not_overclaimed_without_rollback_priv():
    # VM.Snapshot (create) but NOT VM.Snapshot.Rollback — must NOT claim the UNDO/rollback works.
    out = doctor_check(_DoctorApi(perms={"/": {"VM.Audit": 1, "VM.Snapshot": 1}}))
    can = " ".join(c["capability"].lower() for c in out["token"]["can"])
    assert "create restore points" in can  # snapshot create IS available
    rollback_cannot = [c for c in out["token"]["cannot"] if "rollback" in c["capability"].lower()]
    assert rollback_cannot, "rollback must be in CANNOT without VM.Snapshot.Rollback"
    assert "VM.Snapshot.Rollback" in " ".join(rollback_cannot[0]["needs"])


def test_reconfigure_partial_is_labelled():
    # Only one VM.Config.* priv — capability is present but must be labelled partial, not full.
    out = doctor_check(_DoctorApi(perms={"/": {"VM.Config.Network": 1}}))
    recfg = [c for c in out["token"]["can"] if "reconfigure" in c["capability"].lower()]
    assert recfg and "partial" in recfg[0]["capability"].lower()
    assert "VM.Config.Network" in recfg[0]["capability"]


def test_users_and_acls_are_split():
    # Permissions.Modify (ACLs) does NOT imply User.Modify (users) — they're distinct powers.
    out = doctor_check(_DoctorApi(perms={"/": {"Permissions.Modify": 1}}))
    can = " ".join(c["capability"].lower() for c in out["token"]["can"])
    cannot = " ".join(c["capability"].lower() for c in out["token"]["cannot"])
    assert "tokens / acls" in can
    assert "manage users" in cannot


# --- seam: pve_doctor through the server records to the PROVE ledger as a read (mutation=False) ---

def test_pve_doctor_records_read_to_ledger(tmp_path, monkeypatch):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
                        audit_log_path=log)
    api = _DoctorApi(config=cfg)  # api.config is a real ProximoConfig here
    ledger = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, None, ledger))

    out = server.pve_doctor()
    assert out["reachable"] is True
    with open(log, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    assert any(e["action"] == "pve_doctor" and e["outcome"] == "ok" and e["mutation"] is False
               for e in entries)


# --- target routing: pve_doctor(proximo_target=...) sets the contextvar before _svc() fires ---
# This is a characterization test — target_aware already wraps pve_doctor, so it is GREEN today.
# It guards against regressions that would remove the target routing from this tool.

def test_pve_doctor_routes_to_named_target(monkeypatch):
    """pve_doctor(proximo_target="mybox") must set _active_target to "mybox" for the duration
    of the call — captured here via a patched _svc() that reads the contextvar."""
    captured = {}

    class _FakeLedger:
        def record(self, action, *, target, mutation=False, outcome="ok", detail=None,
                   remote=None, principal=None):
            return {}

    def _fake_svc():
        captured["target"] = targets._active_target.get()
        cfg = SimpleNamespace(node="pve", api_base_url="https://pve.example:8006/api2/json",
                              enable_exec=False, verify_tls=True, ca_bundle=None,
                              ct_allowlist=frozenset())
        api = _DoctorApi(config=cfg)
        return cfg, api, None, _FakeLedger()

    monkeypatch.setattr(server, "_svc", _fake_svc)
    server.pve_doctor(proximo_target="mybox")
    assert captured["target"] == "mybox"


def test_pve_doctor_default_target_is_none(monkeypatch):
    """Calling pve_doctor() with no proximo_target must leave _active_target as None (default path)."""
    captured = {}

    class _FakeLedger:
        def record(self, action, *, target, mutation=False, outcome="ok", detail=None,
                   remote=None, principal=None):
            return {}

    def _fake_svc():
        captured["target"] = targets._active_target.get()
        cfg = SimpleNamespace(node="pve", api_base_url="https://pve.example:8006/api2/json",
                              enable_exec=False, verify_tls=True, ca_bundle=None,
                              ct_allowlist=frozenset())
        api = _DoctorApi(config=cfg)
        return cfg, api, None, _FakeLedger()

    monkeypatch.setattr(server, "_svc", _fake_svc)
    server.pve_doctor()
    assert captured["target"] is None


# --- CLI: `proximo doctor --target <name>` passes proximo_target=<name> to pve_doctor ---

def test_cli_doctor_passes_target_to_pve_doctor(monkeypatch, capsys):
    """CLI: `proximo doctor --target mybox` must call pve_doctor(proximo_target="mybox").
    RED before the server.py change (current main() calls pve_doctor() with no args)."""
    called = {}

    def _stub(**kw):
        called.update(kw)
        return {}

    monkeypatch.setattr(server, "pve_doctor", _stub)
    monkeypatch.setattr(sys, "argv", ["proximo", "doctor", "--target", "mybox"])
    server.main()
    assert called.get("proximo_target") == "mybox"


def test_cli_doctor_no_target_defaults_to_none(monkeypatch, capsys):
    """CLI: `proximo doctor` (no --target) must call pve_doctor(proximo_target=None)."""
    called = {}

    def _stub(**kw):
        called.update(kw)
        return {}

    monkeypatch.setattr(server, "pve_doctor", _stub)
    monkeypatch.setattr(sys, "argv", ["proximo", "doctor"])
    server.main()
    assert called.get("proximo_target") is None


# --- CLI: `proximo doctor --product {pve,pbs,pmg,pdm}` mirrors `proximo mint --product` ------
#
# Verdict 1.3: `proximo doctor` was hardcoded to pve_doctor with no product flag, so SETUP.md's
# own mandated Step 4 dead-ends a PBS-only operator with a raw PVE missing-env error. pmg_doctor
# is a real tool and gets a real dispatch; pbs/pdm have no doctor tool yet, so those two REFUSE
# honestly (naming the mint runbook / a real read tool) rather than pretending to check anything.

def test_cli_doctor_default_product_is_pve(monkeypatch):
    """No --product given: behavior is unchanged — still calls pve_doctor."""
    called = {}

    def _stub(**kw):
        called.update(kw)
        return {}

    monkeypatch.setattr(server, "pve_doctor", _stub)
    monkeypatch.setattr(sys, "argv", ["proximo", "doctor"])
    server.main()
    assert called.get("proximo_target") is None


def test_cli_doctor_product_pve_explicit_still_honors_target(monkeypatch):
    called = {}

    def _stub(**kw):
        called.update(kw)
        return {}

    monkeypatch.setattr(server, "pve_doctor", _stub)
    monkeypatch.setattr(sys, "argv", ["proximo", "doctor", "--product", "pve", "--target", "mybox"])
    server.main()
    assert called.get("proximo_target") == "mybox"


def test_cli_doctor_product_pmg_dispatches_to_pmg_doctor_not_pve(monkeypatch):
    """PMG has a real doctor tool (pmg_doctor) — --product pmg must call IT."""
    called = {}
    pve_called = {"hit": False}

    def _pmg_stub(**kw):
        called.update(kw)
        return {}

    def _pve_stub(**kw):
        pve_called["hit"] = True
        return {}

    monkeypatch.setattr(server, "pmg_doctor", _pmg_stub)
    monkeypatch.setattr(server, "pve_doctor", _pve_stub)
    monkeypatch.setattr(sys, "argv", ["proximo", "doctor", "--product", "pmg"])
    server.main()
    assert called.get("proximo_target") is None
    assert pve_called["hit"] is False


def test_cli_doctor_product_pbs_refuses_honestly_no_doctor_tool(monkeypatch, capsys):
    """PBS has no pbs_doctor tool yet — refuse with the remedy that DOES exist (mint's runbook),
    never a raw missing-env error naming PVE's own vars."""
    monkeypatch.setattr(sys, "argv", ["proximo", "doctor", "--product", "pbs"])
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "pbs_doctor" in err
    assert "mint --product pbs" in err
    assert "PROXIMO_API_BASE_URL" not in err  # never the PVE-flavored dead end


def test_cli_doctor_product_pdm_refuses_honestly_no_doctor_tool(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["proximo", "doctor", "--product", "pdm"])
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "pdm_doctor" in err
    assert "mint --product pdm" in err


def test_cli_doctor_unknown_product_rejected(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["proximo", "doctor", "--product", "bogus"])
    with pytest.raises(SystemExit):
        server.main()


def test_cli_doctor_default_pve_missing_env_points_at_configured_pbs_plane(monkeypatch, capsys):
    """The verdict's core case: a PBS-only operator runs bare `proximo doctor` (CLI default is
    still pve). Instead of the raw "Missing required Proximo env var: PROXIMO_API_BASE_URL..."
    dead end, the failure must point at the plane that IS actually configured."""
    def _pve_stub(**kw):
        raise RuntimeError(
            "Missing required Proximo env var: PROXIMO_API_BASE_URL, PROXIMO_NODE, PROXIMO_TOKEN_PATH"
        )

    monkeypatch.setattr(server, "pve_doctor", _pve_stub)
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs.example.lan:8007/api2/json")
    monkeypatch.delenv("PROXIMO_PMG_BASE_URL", raising=False)
    monkeypatch.delenv("PROXIMO_PDM_BASE_URL", raising=False)
    # Setting a plane's base-url env var makes _apply_surfaces()'s autoscope see it as
    # configured — main() calls that BEFORE the doctor block, and it PERMANENTLY prunes the
    # shared, process-wide `server.mcp` tool registry, breaking unrelated tests later in the
    # same pytest process. Turn it off: this test is about the doctor dispatch message, not
    # surface-scoping, and PROXIMO_AUTOSCOPE doesn't affect _configured_other_planes() (which
    # reads the env var directly).
    monkeypatch.setenv("PROXIMO_AUTOSCOPE", "off")
    monkeypatch.setattr(sys, "argv", ["proximo", "doctor"])
    with pytest.raises(SystemExit) as exc:
        server.main()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "mint --product pbs" in err
    assert "PROXIMO_PBS_BASE_URL" in err


# --- The spine section: four pillars standing, two sockets yours to erect ---

def test_spine_reports_four_standing_pillars(monkeypatch):
    monkeypatch.delenv("PROXIMO_CONSENT_DIR", raising=False)
    monkeypatch.delenv("PROXIMO_CONTAIN_TRIP_PATH", raising=False)
    out = doctor_check(_DoctorApi())
    standing = " ".join(out["spine"]["standing"])
    for pillar in ("PLAN", "PROVE", "UNDO", "DIAGNOSE"):
        assert pillar in standing
    assert len(out["spine"]["standing"]) == 4


def test_spine_sockets_unconfigured_hand_over_the_tools(monkeypatch):
    """Unset CONSENT/CONTAIN must read as an empty socket WITH the erection recipe —
    surface the incompleteness and hand the operator the stone, never a false clean bill."""
    monkeypatch.delenv("PROXIMO_CONSENT_DIR", raising=False)
    monkeypatch.delenv("PROXIMO_CONTAIN_TRIP_PATH", raising=False)
    out = doctor_check(_DoctorApi())
    yours = out["spine"]["yours_to_erect"]
    for name, env in (("CONSENT", "PROXIMO_CONSENT_DIR"), ("CONTAIN", "PROXIMO_CONTAIN_TRIP_PATH")):
        assert yours[name]["configured"] is False
        assert env in yours[name]["erect_with"]
        assert "out" in yours[name]["erect_with"].lower()  # names the out-of-band requirement
    assert "outside" in out["spine"]["note"].lower()  # the note states the out-of-band doctrine


def test_spine_sockets_configured_report_standing(monkeypatch):
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", "/run/operator/consent")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", "/run/operator/contain.trip")
    out = doctor_check(_DoctorApi())
    yours = out["spine"]["yours_to_erect"]
    assert yours["CONSENT"]["configured"] is True
    assert yours["CONTAIN"]["configured"] is True


def test_spine_carries_no_secret_material_and_no_socket_values(monkeypatch):
    """The spine section reports configured yes/no — never the configured PATHS themselves
    (a consent-dir/trip-path location is exactly what a hijacked session shouldn't learn
    from a doctor call; the operator knows where they put their own switch)."""
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", "/run/operator/secret-consent-location")
    monkeypatch.setenv("PROXIMO_CONTAIN_TRIP_PATH", "/run/operator/secret-trip-location")
    out = doctor_check(_DoctorApi())
    rendered = json.dumps(out["spine"])
    assert "secret-consent-location" not in rendered
    assert "secret-trip-location" not in rendered


# --- No-secret-material invariant (CodeQL alert #75 guard) ---

def test_doctor_report_carries_no_secret_material(tmp_path):
    """`proximo doctor` prints its report as clear text (server.main json.dumps) — the report
    must never carry secret VALUES, even though the backend object it is built from has read
    them (that object-level flow is exactly what CodeQL py/clear-text-logging flags). Secrets
    stay by-reference (paths) end to end; this test pins that invariant with sentinels planted
    on every secret-bearing seam. Sentinels are low-entropy by design (gitleaks entropy rules)."""
    token_secret = "sentinel-doctor-token-secret-value"
    pmg_password = "sentinel-doctor-pmg-password-value"
    token_file = tmp_path / "token"
    token_file.write_text(f"root@pam!proximo={token_secret}\n")
    cfg = _cfg(token_path=str(token_file))
    api = _DoctorApi(config=cfg)
    # Simulate a backend that has ALREADY read its secrets — the taint source in the alert.
    api.auth_header = f"PVEAPIToken=root@pam!proximo={token_secret}"
    api.pmg_password = pmg_password

    rendered = json.dumps(doctor_check(api))  # exactly what the CLI prints

    assert token_secret not in rendered
    assert pmg_password not in rendered
    assert "PVEAPIToken" not in rendered
    assert token_file.read_text().strip() not in rendered


# --- increment 5: doctor must name the facade it is actually serving -------------------------
#
# doctor exists to tell an operator what THIS box serves. The dynamic line hard-coded "3 tools
# resident"; with memory on the facade is 4. A count doctor states from a constant instead of
# from the composition is the same defect class this file already caught once, when doctor said
# "auto-scoped" on a box actually scoped by PROXIMO_TOOLSETS.

def _leaned_registry(monkeypatch):
    """Install a real leaned registry as `server.mcp`, the way main() leaves it before doctor runs.

    These two tests used to assert "4"/"3" against the UNLEANED global registry, which meant they
    could only ever be checking a constant doctor computed from PROXIMO_MEMORY. Once the count
    became derived (external vet, 2026-08-02 — doctor was promising a `proximo_recall` that
    scoping had pruned), the constant had nothing behind it. Leaning a registry here is what
    makes the number under test the number an operator actually gets.

    LEAN_CATALOG is module-global and apply_lean assigns it, so it is saved/restored via
    monkeypatch rather than left for the next test to inherit.
    """
    from proximo._mcpcompat import ServerClass
    monkeypatch.setattr(door, "LEAN_CATALOG", dict(door.LEAN_CATALOG))  # door owns it (A11 3a)
    m = ServerClass("probe")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    door.apply_lean(m)
    monkeypatch.setattr(server, "mcp", m)
    return m


def test_dynamic_scoping_line_counts_the_memory_first_facade(monkeypatch):
    monkeypatch.setenv("PROXIMO_TOOLSETS", "dynamic")
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    m = _leaned_registry(monkeypatch)
    assert "proximo_recall" in m._tool_manager._tools          # precondition, not an assumption
    scoping = doctor_check(_DoctorApi())["surfaces"]["scoping"]
    assert "5 facade tools resident" in scoping, scoping
    assert "proximo_recall" in scoping


def test_dynamic_scoping_line_stays_four_without_memory(monkeypatch):
    monkeypatch.setenv("PROXIMO_TOOLSETS", "dynamic")
    monkeypatch.setenv("PROXIMO_MEMORY", "0")   # memory is default-on since the 0.30 flip
    m = _leaned_registry(monkeypatch)
    assert "proximo_recall" not in m._tool_manager._tools
    scoping = doctor_check(_DoctorApi())["surfaces"]["scoping"]
    assert "4 facade tools resident" in scoping, scoping
    assert "proximo_recall" not in scoping


def test_surfaces_note_does_not_hardcode_a_facade_size(monkeypatch):
    """The note sits directly under `scoping`; a constant there contradicts the derived count."""
    monkeypatch.setenv("PROXIMO_MEMORY", "1")
    note = doctor_check(_DoctorApi())["surfaces"]["note"]
    assert "3-tool" not in note


def test_surfaces_report_names_the_default_door_on_a_utility_only_config(monkeypatch):
    """A utility-only config (memory/wiki, no data plane) gets the default dynamic door, and
    the scoping text must say it is the DEFAULT — never a claim that utilities were
    'auto-scoped to' as if they were data planes (the stale pre-widening {"exec"} bug this
    test originally pinned, ultra review 2026-07-30; the 0.30 flip retired the branch that
    said 'no plane configured yet — serving the full surface')."""
    from proximo import doctor

    for var in ("PROXIMO_SURFACES", "PROXIMO_TOOLSETS", "PROXIMO_AUTOSCOPE",
                "PROXIMO_MEMORY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(door, "configured_surfaces", lambda: {"memory", "wiki"})
    rep = doctor._surfaces_report()
    assert rep["scoping"].startswith("dynamic facade (the default)"), rep["scoping"]


# --- Principal block: name tag, caller pins, the empty-pins lockout warning ---


def test_principal_unconfigured(monkeypatch):
    """No PROXIMO_PRINCIPAL AND no PROXIMO_CALLER_KEYS_DIR => principal block reports unconfigured."""
    monkeypatch.delenv("PROXIMO_PRINCIPAL", raising=False)
    monkeypatch.delenv("PROXIMO_CALLER_KEYS_DIR", raising=False)
    out = doctor_check(_DoctorApi())
    principal = out.get("principal")
    assert principal is not None
    assert principal["process_principal"] is None
    assert principal["caller_pins"]["configured"] is False
    assert principal["caller_pins"]["dir"] is None
    assert principal["caller_pins"]["enrolled"] is None
    assert "no principal configured" in principal["caller_pins"]["note"]


def test_principal_pins_with_zero_enrolled(monkeypatch, tmp_path):
    """PROXIMO_CALLER_KEYS_DIR set to empty dir => configured, 0 enrolled, lockout warning."""
    monkeypatch.delenv("PROXIMO_PRINCIPAL", raising=False)
    pins_dir = str(tmp_path)
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", pins_dir)
    out = doctor_check(_DoctorApi())
    principal = out.get("principal")
    assert principal is not None
    assert principal["process_principal"] is None
    assert principal["caller_pins"]["configured"] is True
    assert principal["caller_pins"]["dir"] == pins_dir
    assert principal["caller_pins"]["enrolled"] == 0
    assert "0 enrolled" in principal["caller_pins"]["note"]
    assert "ALL callers will be refused" in principal["caller_pins"]["note"]


def test_principal_pins_with_one_enrolled(monkeypatch, tmp_path):
    """PROXIMO_CALLER_KEYS_DIR with 1 valid .jwk file => enrolled==1, positive note."""
    # Create a keypair and mint a public JWK
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    jwk = public_jwk(pem, "test-caller")

    # Write the JWK to a .jwk file
    pins_dir = str(tmp_path)
    (tmp_path / "test-caller.jwk").write_text(json.dumps(jwk))

    monkeypatch.delenv("PROXIMO_PRINCIPAL", raising=False)
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", pins_dir)

    out = doctor_check(_DoctorApi())
    principal = out.get("principal")
    assert principal is not None
    assert principal["process_principal"] is None
    assert principal["caller_pins"]["configured"] is True
    assert principal["caller_pins"]["dir"] == pins_dir
    assert principal["caller_pins"]["enrolled"] == 1
    assert "1 caller" in principal["caller_pins"]["note"]


def test_principal_pins_malformed_degrades_gracefully(monkeypatch, tmp_path):
    """PROXIMO_CALLER_KEYS_DIR with malformed .jwk => configured=True, enrolled=None, error in note."""
    pins_dir = str(tmp_path)
    # Write a malformed JWK file (non-JSON garbage)
    (tmp_path / "fleet-7.jwk").write_text("not json{{{")

    monkeypatch.delenv("PROXIMO_PRINCIPAL", raising=False)
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", pins_dir)

    out = doctor_check(_DoctorApi())
    principal = out.get("principal")
    # Doctor must not crash; must have the principal block
    assert principal is not None
    assert principal["process_principal"] is None
    assert principal["caller_pins"]["configured"] is True
    assert principal["caller_pins"]["dir"] == pins_dir
    assert principal["caller_pins"]["enrolled"] is None
    # Note must carry the error string from load_pins
    assert "invalid" in principal["caller_pins"]["note"].lower()


def test_principal_name_tag_only_no_pins(monkeypatch):
    """PROXIMO_PRINCIPAL set, PROXIMO_CALLER_KEYS_DIR unset => process_principal carries name, configured=False."""
    monkeypatch.setenv("PROXIMO_PRINCIPAL", "my-instance")
    monkeypatch.delenv("PROXIMO_CALLER_KEYS_DIR", raising=False)

    out = doctor_check(_DoctorApi())
    principal = out.get("principal")
    assert principal is not None
    assert principal["process_principal"] == "my-instance"
    assert principal["caller_pins"]["configured"] is False
    assert principal["caller_pins"]["dir"] is None
    assert principal["caller_pins"]["enrolled"] is None
    assert "name tag set" in principal["caller_pins"]["note"]
    assert "no caller pins" in principal["caller_pins"]["note"]


def test_doctor_reports_whether_the_ledger_redacts():
    """doctor's config block is 'the safety/posture signals a stranger needs to see' by its own
    comment, and it already surfaces exec, TLS and the CT allowlist. It never surfaced whether the
    PROVE ledger fingerprints command bodies or writes them whole — the one posture signal that
    decides whether a password on an argv lands in a durable file.

    Driven through the config object doctor actually reads (api.config), not the environment: an
    earlier version of this test set PROXIMO_LEDGER_REDACT and asserted on the result, which could
    never have worked because doctor_check takes cfg off the api double and never consults env.
    """
    import copy  # noqa: PLC0415

    def _with(redact):
        c = copy.copy(_cfg())
        c.redact_ledger = redact
        return _DoctorApi(config=c)

    on, off = _with(True), _with(False)
    assert doctor_check(on)["config"]["ledger_redaction"] is True
    assert doctor_check(off)["config"]["ledger_redaction"] is False, (
        "an operator turning redaction OFF cannot see that in doctor — the one place they would look")


def test_surfaces_note_does_not_promise_more_than_dynamic_mode_delivers():
    """Catches the claim that shipped false in 0.29.0: "everything still callable".

    The note is a payload the MODEL reads, so it is a prompt, and an unqualified superlative in
    it is the shape that produced the RRD "today" bug. On a PVE-only box `PROXIMO_TOOLSETS=
    dynamic` snapshots its catalog AFTER autoscope prunes (server.py:1260-1263), so the callable
    set is what THIS BOX SERVES (measured: 310), not the 904-tool estate the README names in the
    same breath.

    Pinned as an exact substring rather than a regex over meaning: a regex over prose is a
    phrase list wearing a semantic costume, and this one has to survive rewording being
    DELIBERATE. If you change the wording, change this line and say why.

    Mutant it kills: restoring "with everything still callable" (the 0.29.0 text). Not vacuous —
    the positive assertion pins the qualifier, so deleting the word "serves" alone turns it red.
    """
    note = doctor_check(_DoctorApi())["surfaces"]["note"]

    assert "everything this box serves still callable" in note, (
        "the dynamic-mode claim lost its scoping qualifier; unqualified, it promises the whole "
        "estate is callable when only what this box serves is")
    assert "with everything still callable" not in note, (
        "the unqualified 0.29.0 claim is back — it is false on any autoscoped box, which is "
        "every real deployment")


# --- the scoping line must describe the box, not the env (external re-vet, 2026-08-02) --------
#
# Two defects shipped together and a mutation run proved BOTH were unpinned: mutating
# _searchable_narrowing to return the wrong string for the surfaces case, and deleting its
# `!= "all"` branch, each survived the entire 11k suite. A doctor line no test reads is prose.

def test_narrowing_names_the_mechanism_that_actually_ran(monkeypatch):
    """_searchable_narrowing renders the EFFECTIVE spec; the caller resolves precedence."""
    from proximo.doctor import _searchable_narrowing
    # an explicit plane spec: surfaces pruned, autoscope never ran
    assert _searchable_narrowing("pve,pbs", False) == "narrowed to PROXIMO_SURFACES=pve,pbs"
    # `all`: autoscope overridden, nothing pruned — NOT the same as a plane spec
    assert _searchable_narrowing("all", False) == "NOT plane-narrowed (PROXIMO_SURFACES=all)"
    # no spec: autoscope is the mechanism, and its off-switch is reported as its own case
    assert _searchable_narrowing("", False) == "still auto-scoped to configured planes"
    assert _searchable_narrowing("", True) == "NOT plane-narrowed (PROXIMO_AUTOSCOPE=off)"
    # the four cases are genuinely distinct strings — a collapsed branch cannot hide here
    assert len({_searchable_narrowing("pve", False), _searchable_narrowing("all", False),
                _searchable_narrowing("", False), _searchable_narrowing("", True)}) == 4


def test_toolsets_dynamic_outranks_surfaces_so_surfaces_is_not_reported(monkeypatch):
    """PROXIMO_TOOLSETS=dynamic IGNORES PROXIMO_SURFACES — doctor must not credit the ignored var.

    The dangerous direction is `SURFACES=all` + `TOOLSETS=dynamic`: autoscope really does prune,
    and doctor used to answer "NOT plane-narrowed" while hundreds of tools had been removed.
    """
    from proximo import doctor
    for var in ("PROXIMO_TOOLS", "PROXIMO_AUTOSCOPE"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_TOOLSETS", "dynamic")
    monkeypatch.setenv("PROXIMO_SURFACES", "pmg")
    rep = doctor._surfaces_report()
    assert "PROXIMO_SURFACES" not in rep["scoping"], rep["scoping"]
    assert "auto-scoped" in rep["scoping"], rep["scoping"]

    monkeypatch.setenv("PROXIMO_SURFACES", "all")
    rep = doctor._surfaces_report()
    assert "NOT plane-narrowed" not in rep["scoping"], rep["scoping"]


def test_facade_count_and_memory_first_are_read_from_the_registry(monkeypatch):
    """Doctor must not promise a tool the prune removed.

    Under PROXIMO_SURFACES=pve,pbs the `memory` utility surface is not named, so proximo_recall
    is scoped away — but doctor derived "memory-first" from PROXIMO_MEMORY (an env var that is
    still ON) and told a model to call a tool this box does not serve.
    """
    from proximo import doctor
    from proximo._mcpcompat import ServerClass
    for var in ("PROXIMO_TOOLS", "PROXIMO_TOOLSETS", "PROXIMO_AUTOSCOPE", "PROXIMO_TARGETS",
                "PROXIMO_PMG_BASE_URL", "PROXIMO_PDM_BASE_URL", "PROXIMO_ENABLE_EXEC"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_MEMORY", "1")          # memory is ON at the env level...
    monkeypatch.setenv("PROXIMO_SURFACES", "pve,pbs")  # ...but not among the named planes
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.example.lan:8006/api2/json")
    monkeypatch.setenv("PROXIMO_PBS_BASE_URL", "https://pbs.example.lan:8007/api2/json")

    m = ServerClass("probe")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    door._apply_surfaces(m)
    monkeypatch.setattr(server, "mcp", m)

    rep = doctor._surfaces_report()
    assert "proximo_recall" not in m._tool_manager._tools     # precondition: really pruned
    assert "memory-first" not in rep["scoping"], rep["scoping"]
    assert "proximo_recall" not in rep["scoping"], rep["scoping"]
    assert f"{rep['served_tools'] - 2} facade tools resident" in rep["scoping"], rep["scoping"]


def test_enable_with_is_absent_for_a_plane_you_already_configured(monkeypatch):
    """`enable_with` answers "how do I light up a plane I do not have" — nothing else.

    Keyed on served==0 alone it fired for CONFIGURED planes too, because under the facade every
    plane serves 0 resident tools by design. A PVE box on the default door was told to "set
    PROXIMO_API_BASE_URL (or add a pve target)" that it had already set. Absent capability and
    non-resident capability are different facts (external vet, 2026-08-02).
    """
    from proximo import doctor
    from proximo._mcpcompat import ServerClass
    for var in ("PROXIMO_TOOLS", "PROXIMO_TOOLSETS", "PROXIMO_SURFACES", "PROXIMO_AUTOSCOPE",
                "PROXIMO_TARGETS", "PROXIMO_PBS_BASE_URL", "PROXIMO_PMG_BASE_URL",
                "PROXIMO_PDM_BASE_URL", "PROXIMO_ENABLE_EXEC"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://pve.example.lan:8006/api2/json")

    m = ServerClass("probe")
    m._tool_manager._tools = dict(server.mcp._tool_manager._tools)
    monkeypatch.setattr(door, "LEAN_CATALOG", dict(door.LEAN_CATALOG))  # door owns it (A11 3a)
    door._apply_surfaces(m)                       # default door => facade => 0 resident per plane
    monkeypatch.setattr(server, "mcp", m)

    planes = doctor._surfaces_report()["planes"]
    assert planes["pve"]["configured"] is True
    assert planes["pve"]["served_tools"] == 0       # precondition: the facade really is the door
    assert "enable_with" not in planes["pve"], (
        f"told a configured plane to configure itself: {planes['pve']}")
    # ...and a plane that genuinely is not configured STILL gets its instruction.
    assert planes["pmg"]["configured"] is False
    assert "enable_with" in planes["pmg"]


def test_reach_grant_block_reports_resolved_lanes():
    # Brick 1 of the grant model: doctor reads back the RESOLVED reach grant — the actual
    # CTIDs, both lanes, plus a digest an operator can compare across boxes/restarts.
    from proximo import reachgrant
    out = doctor_check(_DoctorApi(config=_cfg(ct_allowlist=frozenset({"102", "101"}),
                                              agent_allowlist=frozenset())))
    rg = out["config"]["reach_grant"]
    assert rg["ct"] == ["101", "102"]
    assert rg["agent"] == []
    # lane_digest, NOT digest: the ledger's reach_grant digest covers the whole instance
    # snapshot; two incomparable values under one name would invite a false-alarm compare.
    # `mirror` sits BESIDE the digest, not inside it — a live tri-state read, digested only
    # by the serve-time instance snapshot.
    lanes = {k: v for k, v in rg.items() if k not in ("lane_digest", "mirror")}
    assert rg["lane_digest"] == reachgrant.grant_digest(lanes)


def test_reach_grant_receipt_view_carries_counts_never_ids():
    # --receipt strips estate shape; bare CTIDs match no redaction pattern, so the receipt
    # view must swap the id lists for counts BEFORE render ever sees them.
    from proximo import reachgrant
    block = {"ct": ["101", "102", "103"], "agent": ["205"],
             "lane_digest": "abcd1234abcd1234"}
    safe = reachgrant.receipt_view(block)
    assert safe == {"ct_count": 3, "agent_count": 1, "digest": "abcd1234abcd1234"}
    assert "ct" not in safe and "agent" not in safe


def test_reach_grant_star_reported_as_star():
    out = doctor_check(_DoctorApi(config=_cfg(ct_allowlist=frozenset({"*"}))))
    assert out["config"]["reach_grant"]["ct"] == ["*"]
    from proximo import reachgrant
    assert reachgrant.receipt_view(out["config"]["reach_grant"])["ct_count"] == "*"


def test_reach_grant_block_reports_mirror_tristate(monkeypatch):
    # The mirror is the one config that decides whether the shell channel obeys the served
    # token's own PVE map — doctor must answer "is the mirror on?" in one read. Misconfigured
    # (set-but-whitespace, which REFUSES every shell op) is reported, never raised: an
    # operator runs doctor precisely to learn why everything is refusing.
    from proximo import doctor as doctor_mod
    monkeypatch.delenv("PROXIMO_REACH_PRIVILEGE", raising=False)
    assert doctor_mod._mirror_state() == {"privilege": None, "state": "dormant"}
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    assert doctor_mod._mirror_state() == {"privilege": "ProximoReach", "state": "enforcing"}
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "   ")
    out = doctor_mod._mirror_state()
    assert out["state"] == "misconfigured" and out["privilege"] is None and "blank" in out["error"]


def test_reach_grant_receipt_carries_mirror_state(monkeypatch):
    # A privilege NAME appears in every ACL entry PVE serves — it is not estate shape, so the
    # receipt keeps the tri-state while still stripping the id rosters.
    from proximo import reachgrant
    monkeypatch.setenv("PROXIMO_REACH_PRIVILEGE", "ProximoReach")
    block = {"ct": ["101", "102"], "agent": [], "lane_digest": "abcd",
             "mirror": {"privilege": "ProximoReach", "state": "enforcing"}}
    safe = reachgrant.receipt_view(block)
    assert safe["ct_count"] == 2 and "101" not in str(safe.values())
    assert safe["mirror"] == {"privilege": "ProximoReach", "state": "enforcing"}


# ─── the allowlist's SOURCE (2026-09-02 incident: the refusal pointed at a shadowed file) ─────

def test_doctor_reports_where_the_ct_allowlist_came_from():
    out = doctor_check(_DoctorApi(config=_cfg(ct_allowlist=frozenset({"101"}),
                                              ct_allowlist_source="the process environment (planted)")))
    assert out["config"]["ct_allowlist_source"] == "the process environment (planted)"


def test_doctor_flags_a_shadowed_key_whose_value_differs(monkeypatch):
    """A file key the process environment shadows WITH A DIFFERENT VALUE is the 09-02 hazard: the
    operator edits the file, nothing changes, the refusal repeats. That belongs in flags, not only
    in a passive field. Same-value shadows are dead lines, not hazards: no flag (the control)."""
    import proximo.config as config
    state = config._fresh_env_file_state()
    state["path"] = "/planted/proximo.env"
    state["shadowed"] = {"PROXIMO_CT_ALLOWLIST": True, "PROXIMO_NODE": False}
    monkeypatch.setattr(config, "_ENV_FILE_STATE", state)
    out = doctor_check(_DoctorApi(config=_cfg(ct_allowlist=frozenset({"101"}))))
    hits = [f for f in out["flags"] if "PROXIMO_CT_ALLOWLIST" in f]
    assert len(hits) == 1 and "shadowed" in hits[0].lower() and "restart" in hits[0], out["flags"]
    assert not any("PROXIMO_NODE" in f for f in out["flags"])          # same value: no flag
    assert out["complete"] is True                                       # advisory, never incomplete


def test_doctor_has_no_shadow_flag_when_nothing_is_shadowed(monkeypatch):
    import proximo.config as config
    monkeypatch.setattr(config, "_ENV_FILE_STATE", config._fresh_env_file_state())
    out = doctor_check(_DoctorApi(config=_cfg(ct_allowlist=frozenset({"101"}))))
    assert not any("shadow" in f.lower() for f in out["flags"])


def test_doctor_shadow_flags_are_alphabetical_regardless_of_insertion_order(monkeypatch):
    """Lens survivor 2: the flag loop must sort; the first test's dict happened to be alphabetical
    already, so dropping sorted() went unseen. Reverse insertion order here."""
    import proximo.config as config
    state = config._fresh_env_file_state()
    state["path"] = "/planted/proximo.env"
    state["shadowed"] = {"PROXIMO_NODE": True, "PROXIMO_CT_ALLOWLIST": True}
    monkeypatch.setattr(config, "_ENV_FILE_STATE", state)
    out = doctor_check(_DoctorApi(config=_cfg(ct_allowlist=frozenset({"101"}))))
    shadow = [f for f in out["flags"] if "shadowed" in f.lower()]
    assert [f.split(" ")[0] for f in shadow] == ["PROXIMO_CT_ALLOWLIST", "PROXIMO_NODE"], shadow


def test_doctor_shadow_flag_names_both_launch_shapes(monkeypatch):
    import proximo.config as config
    state = config._fresh_env_file_state()
    state["path"] = "/planted/proximo.env"
    state["shadowed"] = {"PROXIMO_CT_ALLOWLIST": True}
    monkeypatch.setattr(config, "_ENV_FILE_STATE", state)
    out = doctor_check(_DoctorApi(config=_cfg(ct_allowlist=frozenset({"101"}))))
    flag = next(f for f in out["flags"] if "PROXIMO_CT_ALLOWLIST" in f)
    assert "mcpServers" in flag and "EnvironmentFile" in flag, flag


# --- the split target: API here, exec there (found live-proving, 2026-09-04) ---------------
# The documented lab pattern sets a lab base_url/token/pin/audit-log by script env and says
# nothing about PROXIMO_SSH_TARGET or the allowlist. Both then fall back to the shared env file,
# so `proximo doctor` truthfully reported api_base_url=lab, node=pve-test1, ssh_target=pve and 22
# PRODUCTION CTIDs in one config. A session that believes it is in the lab and calls ct_exec would
# land in a production container. Mocks cannot see this; it needs a real second target.

@pytest.fixture(autouse=True)
def _no_env_leak():
    """`load_env_file()` writes the file's keys straight into os.environ, BYPASSING monkeypatch —
    `test_allowlist_remedy.py` carries the same fixture and says so in its docstring. Without it
    the helpers below leak PROXIMO_* into every test that runs after them, which is a whole-suite
    ordering bug that passes file-by-file. Strip only what the test added."""
    before = {k: v for k, v in os.environ.items() if k.startswith("PROXIMO_")}
    yield
    for k in [k for k in os.environ if k.startswith("PROXIMO_")]:
        if k not in before:
            os.environ.pop(k, None)
        elif os.environ[k] != before[k]:
            os.environ[k] = before[k]


@pytest.fixture(autouse=True)
def _ssh_config_is_not_consulted(monkeypatch):
    """This box's own ~/.ssh/config resolves `pve` to an address, so the split-target tests would
    flip on the machine they run on. The resolver is a seam: default it to the literal host here;
    the tests that exercise resolution set their own mapping."""
    import proximo.doctor as doctor
    monkeypatch.setattr(doctor, "_ssh_config_host", lambda target: target.rpartition("@")[2].lower())


import proximo.doctor as _doctor_mod  # noqa: E402  (the seam's REAL function, captured before any fixture patches it)

_REAL_SSH_CONFIG_HOST = getattr(_doctor_mod, "_ssh_config_host", None)


def _doctor_with(monkeypatch, **env):
    import proximo.config as config
    import proximo.doctor as doctor
    monkeypatch.setattr(config, "_ENV_FILE_STATE", config._fresh_env_file_state())
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    config.load_env_file(announce=False)   # the real entry point does this before from_env()

    cfg = config.ProximoConfig.from_env()

    class _Api:
        def __init__(self, c):
            self.config = c
        def version(self):
            return {"version": "9.2.2"}
        def access_permissions(self):
            return {}
    return doctor.doctor_check(_Api(cfg))


def _exec_cfg(monkeypatch, tmp_path, *, api_host, ssh_target, allow="420,1494", **extra):
    envfile = tmp_path / "proximo.env"
    envfile.write_text("# empty\n")
    monkeypatch.setenv("PROXIMO_ENV_FILE", str(envfile))
    env = dict(
        PROXIMO_API_BASE_URL=f"https://{api_host}:8006/api2/json",
        PROXIMO_NODE="n1",
        PROXIMO_TOKEN_PATH="/run/x",
        PROXIMO_FINGERPRINT="aa" * 32,
        PROXIMO_VERIFY_TLS="false",
        PROXIMO_ENABLE_EXEC="1",
        PROXIMO_CT_ALLOWLIST=allow,
        PROXIMO_SSH_TARGET=ssh_target,
    )
    env.update(extra)
    return _doctor_with(monkeypatch, **env)


def test_split_target_fires_when_exec_lands_on_a_different_host(monkeypatch, tmp_path):
    """The incident: the API was pointed at the lab while ct_exec still went to production.

    The FIRST cut of this check compared which config STORE fed each value, which is not the
    hazard. A lens showed it stayed silent on the remedy the message itself recommends: put the
    api url and the allowlist in the same store, leave PROXIMO_SSH_TARGET in the file, and exec
    still lands on prod with the flag quiet. Compare the HOSTS."""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="lab-node", ssh_target="prod-pve")
    said = " ".join(rep.get("flags", []))
    assert "SPLIT TARGET" in said, said
    assert "lab-node" in said and "prod-pve" in said, said
    assert rep["config"]["exec_lands_on"] == "prod-pve"


def test_split_target_fires_even_when_one_store_feeds_everything(monkeypatch, tmp_path):
    """THE CASE THE STORE-COMPARISON MISSED. One store, two hosts, still a split."""
    envfile = tmp_path / "proximo.env"
    envfile.write_text(
        "PROXIMO_API_BASE_URL=https://lab-node:8006/api2/json\n"
        "PROXIMO_NODE=n1\nPROXIMO_TOKEN_PATH=/run/x\nPROXIMO_ENABLE_EXEC=1\n"
        "PROXIMO_CT_ALLOWLIST=420\nPROXIMO_SSH_TARGET=prod-pve\nPROXIMO_FINGERPRINT=" + "aa" * 32 + "\n"
    )
    monkeypatch.setenv("PROXIMO_ENV_FILE", str(envfile))
    rep = _doctor_with(monkeypatch)
    said = " ".join(rep.get("flags", []))
    assert "SPLIT TARGET" in said, said


def test_split_target_is_quiet_when_the_api_host_is_the_exec_host(monkeypatch, tmp_path):
    """CONTROL: the ordinary single-machine deployment must stay quiet."""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="pve", ssh_target="pve")
    said = " ".join(rep.get("flags", []))
    assert "SPLIT TARGET" not in said, said
    assert rep["config"]["exec_lands_on"] == "pve"


# --- lens round 2 on the rebuilt check (2026-09-05): seven findings, three surviving mutants ---

def test_split_target_ignores_the_ssh_user(monkeypatch, tmp_path):
    """`user@host` is a documented ssh_target form. The compare must read the HOST; the remedy
    of the first rebuild ("set PROXIMO_SSH_TARGET to match the API host") told an operator to
    drop the scoped service account."""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="prod-pve", ssh_target="svc-exec@prod-pve")
    said = " ".join(rep.get("flags", []))
    assert "SPLIT TARGET" not in said, said
    assert rep["config"]["exec_lands_on"] == "svc-exec@prod-pve"


def test_split_target_compares_hosts_case_insensitively(monkeypatch, tmp_path):
    """urlsplit lowercases the API host; ssh_target is stored verbatim. Same machine, one case."""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="Prod-PVE", ssh_target="Prod-PVE")
    assert "SPLIT TARGET" not in " ".join(rep.get("flags", []))


def test_the_remedy_is_followable_with_an_ip_host(monkeypatch, tmp_path):
    """Live-proved 2026-09-05: with the API by IP, setting ssh_target to the lab's HOSTNAME kept
    the flag firing. The remedy must work when followed literally: the charset admits an IP.
    (RFC 5737 documentation address: the first draft carried the lab's real IP and the leak
    audit refused it, the 09-04 trap walked into again.)"""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="192.0.2.51", ssh_target="192.0.2.51")
    assert "SPLIT TARGET" not in " ".join(rep.get("flags", []))


def test_split_target_fires_for_on_host_exec_with_a_remote_api(monkeypatch, tmp_path):
    """FINDING 1, the one that mattered: is_local exempted the hazard entirely. On-host mode runs
    `pct` on the box Proximo runs on; if the API reads another machine, that IS a split, and a
    lens deleted the is_local guard with 60 tests staying green."""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="lab-node", ssh_target="")
    said = " ".join(rep.get("flags", []))
    assert "SPLIT TARGET" in said and "lab-node" in said, said
    assert rep["config"]["exec_lands_on"].startswith("this host")


@pytest.mark.parametrize("api_host", ["localhost", "127.0.0.1", "this-box"])
def test_on_host_exec_is_quiet_when_the_api_is_this_host(monkeypatch, tmp_path, api_host):
    """CONTROL for finding 1: an on-host deployment that points the API at itself stays quiet."""
    import proximo.doctor as doctor
    monkeypatch.setattr(doctor.socket, "gethostname", lambda: "This-Box")
    rep = _exec_cfg(monkeypatch, tmp_path, api_host=api_host, ssh_target="local")
    assert "SPLIT TARGET" not in " ".join(rep.get("flags", []))
    assert rep["config"]["exec_lands_on"].startswith("this host")


def test_split_target_reports_where_exec_lands_even_with_a_deny_all_allowlist(monkeypatch, tmp_path):
    """Mutant m3 (drop `and allow`) survived: the deny-all path reported nothing about where exec
    would land, one allowlist edit away from live exec on the wrong host."""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="lab-node", ssh_target="prod-pve", allow="")
    said = " ".join(rep.get("flags", []))
    assert "SPLIT TARGET" in said, said
    assert rep["config"]["exec_lands_on"] == "prod-pve"


def test_split_target_cannot_compare_a_hostless_api_url_and_says_so(monkeypatch, tmp_path):
    """FINDING 6: an empty API host made the compare impossible and the check went quiet, with
    exec fully armed. Say what could not be checked instead of nothing."""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="", ssh_target="prod-pve")
    said = " ".join(rep.get("flags", []))
    assert "names no host" in said and "prod-pve" in said, said
    assert rep["config"]["exec_lands_on"] == "prod-pve"


def test_split_target_covers_the_node_shell_too(monkeypatch, tmp_path):
    """FINDING 7: node_probe/node_logs run `ssh <ssh_target>` under enable_node_shell, with no
    allowlist at all, and sat outside the check."""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="lab-node", ssh_target="prod-pve", allow="",
                    PROXIMO_ENABLE_EXEC="0", PROXIMO_ENABLE_NODE_SHELL="true")
    said = " ".join(rep.get("flags", []))
    assert "SPLIT TARGET" in said and "node_probe" in said, said
    assert rep["config"]["exec_lands_on"] == "prod-pve"


def test_split_target_resolves_an_ssh_alias_through_ssh_config(monkeypatch, tmp_path):
    """Run from the refreshed venv against this box's own production config, the flag fired
    forever: the API by IP, the ssh target the alias `pve`, and `ssh -G pve` resolving to that
    very IP. An alias is not a different machine; ssh's own config says where it goes."""
    import proximo.doctor as doctor
    monkeypatch.setattr(doctor, "_ssh_config_host",
                        lambda target: {"svc@pve-alias": "192.0.2.10"}[target])
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="192.0.2.10", ssh_target="svc@pve-alias")
    assert "SPLIT TARGET" not in " ".join(rep.get("flags", []))
    assert rep["config"]["exec_lands_on"] == "svc@pve-alias"


def test_split_target_names_the_resolved_host_when_it_still_differs(monkeypatch, tmp_path):
    """CONTROL: an alias that resolves elsewhere is a split, and the flag names where."""
    import proximo.doctor as doctor
    monkeypatch.setattr(doctor, "_ssh_config_host", lambda target: "192.0.2.99")
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="192.0.2.10", ssh_target="pve-alias")
    said = " ".join(rep.get("flags", []))
    assert "SPLIT TARGET" in said and "192.0.2.99" in said, said


def test_hostname_from_ssh_g_output_reads_the_hostname_line_only():
    """The parser over ssh -G's real output shape: many `key value` lines, one `hostname`."""
    import proximo.doctor as doctor
    out = "user root\nhostname 192.0.2.10\nport 22\naddressfamily any\n"
    assert doctor._hostname_from_ssh_g(out) == "192.0.2.10"
    assert doctor._hostname_from_ssh_g("user root\nport 22\n") is None
    assert doctor._hostname_from_ssh_g("hostnamex y\nhostname Prod-PVE\n") == "prod-pve"


def test_ssh_config_host_falls_back_to_the_literal_host_without_ssh(monkeypatch):
    """No ssh binary (a CI runner, a container): the literal host, lowercased, user stripped."""
    import proximo.doctor as doctor
    real = _REAL_SSH_CONFIG_HOST
    monkeypatch.setattr(doctor.shutil, "which", lambda name: None)
    assert real("svc@Prod-PVE") == "prod-pve"


def test_split_target_treats_every_name_for_this_host_as_one_host(monkeypatch, tmp_path):
    """Lens round 2: api `localhost` against ssh_target `127.0.0.1` fired, and the remedy told the
    operator to set ssh_target to `localhost`, which is an is_local SENTINEL and silently changes
    the code path. Both names are this host; compare them as one."""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="localhost", ssh_target="127.0.0.1")
    assert "SPLIT TARGET" not in " ".join(rep.get("flags", []))
    assert rep["config"]["exec_lands_on"] == "127.0.0.1"


def _fake_ssh(tmp_path, body: str):
    """A stand-in `ssh` binary: records its argv to a file and prints `body`. Lets the REAL
    resolver run end to end without this box's ssh config, which the brief forbids consulting."""
    argv_file = tmp_path / "argv.txt"
    exe = tmp_path / "ssh"
    exe.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAKE_SSH_ARGV\"\n" + body)
    exe.chmod(0o755)
    return exe, argv_file


def test_the_real_resolver_returns_the_alias_hostname_from_ssh_g(monkeypatch, tmp_path):
    """LENS ROUND 3, mutant b2 survived: the resolver's success path (run `ssh -G`, parse, return
    the HostName) had never executed under test. Every doctor test stubs the seam and the one
    real-function test forces `which("ssh")` to None. A fake ssh binary runs the real path."""
    exe, argv_file = _fake_ssh(tmp_path, "printf 'user root\\nhostname 192.0.2.77\\nport 22\\n'\n")
    monkeypatch.setenv("FAKE_SSH_ARGV", str(argv_file))
    import proximo.doctor as doctor
    monkeypatch.setattr(doctor.shutil, "which", lambda name: str(exe))
    assert _REAL_SSH_CONFIG_HOST("svc@lab-alias") == "192.0.2.77"
    argv = argv_file.read_text().split("\n")
    assert argv[:2] == ["-G", "--"], argv          # mutant b5: `--` ends ssh's options
    assert argv[2] == "svc@lab-alias", argv         # the whole target, user included, goes to ssh


def test_the_real_resolver_falls_back_to_the_literal_host_when_ssh_says_nothing(monkeypatch, tmp_path):
    """CONTROL: an ssh that prints no hostname line (or fails) leaves the literal host."""
    exe, argv_file = _fake_ssh(tmp_path, "exit 255\n")
    monkeypatch.setenv("FAKE_SSH_ARGV", str(argv_file))
    import proximo.doctor as doctor
    monkeypatch.setattr(doctor.shutil, "which", lambda name: str(exe))
    assert _REAL_SSH_CONFIG_HOST("svc@Lab-Alias") == "lab-alias"


def test_the_remedy_names_local_when_the_api_is_this_host(monkeypatch, tmp_path):
    """LENS ROUND 3, mutant b4 survived: the branch that stops the remedy from naming a value
    that is itself an is_local sentinel had no test. API at this host, exec resolving elsewhere:
    the remedy must say `local`, not `'127.0.0.1'`."""
    import proximo.doctor as doctor
    monkeypatch.setattr(doctor, "_ssh_config_host", lambda target: "192.0.2.99")
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="127.0.0.1", ssh_target="far-alias")
    said = " ".join(rep.get("flags", []))
    assert "SPLIT TARGET" in said and "'local'" in said, said
    assert "'127.0.0.1';" not in said, said


def test_the_resolver_seam_is_actually_stubbed_for_this_file():
    """THE FIXTURE'S OWN CONTROL: the autouse stub is the only thing keeping these tests off this
    box's real ssh config (where `pve` resolves to an address). Prove it is wired, not merely
    registered by name."""
    import proximo.doctor as doctor
    assert _REAL_SSH_CONFIG_HOST is not None and callable(_REAL_SSH_CONFIG_HOST)
    assert doctor._ssh_config_host is not _REAL_SSH_CONFIG_HOST
    assert doctor._ssh_config_host("svc@Prod-PVE") == "prod-pve"


def test_no_shell_feature_means_no_landing_host_and_no_split_flag(monkeypatch, tmp_path):
    """CONTROL: with neither exec nor the node shell enabled nothing ssh-es anywhere, so there is
    no landing host to report and no split to flag, whatever ssh_target says."""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="lab-node", ssh_target="prod-pve",
                    PROXIMO_ENABLE_EXEC="0")
    assert "SPLIT TARGET" not in " ".join(rep.get("flags", []))
    assert "exec_lands_on" not in rep["config"]


def test_split_target_is_quiet_on_a_pure_targets_config(monkeypatch, tmp_path):
    """CONTROL for the false positive the store-comparison had: a from_target config, one machine,
    every value from the same registry entry, and PROXIMO_API_BASE_URL unset in the environment."""
    import proximo.config as config
    import proximo.doctor as doctor
    monkeypatch.setattr(config, "_ENV_FILE_STATE", config._fresh_env_file_state())
    for v in ("PROXIMO_API_BASE_URL", "PROXIMO_SSH_TARGET", "PROXIMO_CT_ALLOWLIST"):
        monkeypatch.delenv(v, raising=False)
    cfg = config.ProximoConfig.from_target({
        "base_url": "https://pve:8006/api2/json", "node": "n1", "token_path": "/run/x",
        "ct_allowlist": ["420"], "enable_exec": True, "ssh_target": "pve",
        "fingerprint": "aa" * 32, "verify_tls": False,
    })

    class _Api:
        def __init__(self, c): self.config = c
        def version(self): return {"version": "9.2.2"}
        def access_permissions(self): return {}
    said = " ".join(doctor.doctor_check(_Api(cfg)).get("flags", []))
    assert "SPLIT TARGET" not in said, said


def test_doctor_tls_flag_counts_the_fingerprint_too(monkeypatch, tmp_path):
    """The sibling of the config.py fix, 40 lines above the new code IN THE FILE I EDITED and
    missed on the first pass: doctor is the 'run this FIRST' preflight, and it still told a
    pinned deployment its API traffic was not cert-validated."""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="pve", ssh_target="pve")
    said = " ".join(rep.get("flags", []))
    assert "not cert-validated" not in said, said
    assert rep["config"].get("fingerprint"), "doctor must SHOW the pin, or a reader cannot see it"


# ── this host's own addresses and names: the FOURTH cut of the split-target check (2026-09-05) ──
# The third cut resolved the ssh alias and treated loopback plus the kernel hostname as this host.
# Its sibling, filed the same night: Proximo ON the PVE node with the API at the node's own LAN
# address, or at the FQDN PVE writes into /etc/hosts, still read as another machine.

_REAL_INTERFACE_ADDRESSES = getattr(_doctor_mod, "_interface_addresses", None)
_REAL_HOSTS_FILE_NAMES = getattr(_doctor_mod, "_hosts_file_names", None)


@pytest.fixture(autouse=True)
def _this_box_is_not_consulted(monkeypatch):
    """The runner's own interfaces and /etc/hosts would put THAT machine's addresses into the
    this-host set, so a test's documentation address could read as local on one box and remote on
    another. Both readers are seams: default them to empty here (hostname-only, the third cut's
    set); the tests that exercise them set their own answers. `raising=False` so a renamed seam is
    reported by the pin test below, by name, instead of erroring every test in this file."""
    import proximo.doctor as doctor
    monkeypatch.setattr(doctor, "_interface_addresses", lambda: frozenset(), raising=False)
    monkeypatch.setattr(doctor, "_hosts_file_names", lambda addrs: frozenset(), raising=False)


def test_the_address_seams_are_actually_stubbed_for_this_file():
    """THE FIXTURE'S OWN CONTROL, the resolver pin's twin: both readers exist, both are replaced,
    and the loopback names are still there without them."""
    import proximo.doctor as doctor
    assert callable(_REAL_INTERFACE_ADDRESSES) and callable(_REAL_HOSTS_FILE_NAMES)
    assert doctor._interface_addresses is not _REAL_INTERFACE_ADDRESSES
    assert doctor._hosts_file_names is not _REAL_HOSTS_FILE_NAMES
    assert doctor._this_host_names() >= {"localhost", "127.0.0.1", "::1"}


def _own_addresses(monkeypatch, *addrs):
    import proximo.doctor as doctor
    monkeypatch.setattr(doctor, "_interface_addresses", lambda: frozenset(addrs), raising=False)


def test_on_host_exec_is_quiet_when_the_api_is_this_hosts_own_address(monkeypatch, tmp_path):
    """THE ALIAS FIRE'S SIBLING: the this-host set was loopback plus the kernel hostname, so
    Proximo ON the PVE node with the API at the node's own LAN address (`https://<node-ip>:8006`,
    the common on-host shape) fired SPLIT TARGET forever. An address bound to this machine's own
    interfaces is this host."""
    _own_addresses(monkeypatch, "192.0.2.10")
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="192.0.2.10", ssh_target="local")
    assert "SPLIT TARGET" not in " ".join(rep.get("flags", []))
    assert rep["config"]["exec_lands_on"].startswith("this host")


def test_on_host_exec_still_fires_when_the_api_is_an_address_this_host_does_not_own(monkeypatch, tmp_path):
    """DIRECTION B, the control for the test above: an address NOT bound here is still another
    machine. Without this, `this host = every address` passes the quiet test."""
    _own_addresses(monkeypatch, "192.0.2.10")
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="192.0.2.99", ssh_target="local")
    said = " ".join(rep.get("flags", []))
    assert "SPLIT TARGET" in said and "192.0.2.99" in said, said


def test_split_target_treats_this_hosts_own_address_as_this_host_on_the_ssh_side(monkeypatch, tmp_path):
    """One set serves both sides: API at loopback, ssh target this machine's own LAN address (a
    container on the node under host networking, its ssh hop pointed back at the node)."""
    _own_addresses(monkeypatch, "192.0.2.10")
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="localhost", ssh_target="192.0.2.10")
    assert "SPLIT TARGET" not in " ".join(rep.get("flags", []))


def test_on_host_exec_is_quiet_when_the_api_is_this_hosts_fqdn_from_etc_hosts(monkeypatch, tmp_path):
    """PVE requires `/etc/hosts` to carry `<ip> <fqdn> <short>` for the node and addresses the API
    by that FQDN, while `socket.gethostname()` is the SHORT name. The names /etc/hosts gives one
    of this machine's own addresses are this host's names; that file is local, so still no DNS.
    The reader is handed the interface set (a reader handed an empty set finds no such line)."""
    import proximo.doctor as doctor
    _own_addresses(monkeypatch, "192.0.2.10")
    monkeypatch.setattr(
        doctor, "_hosts_file_names",
        lambda addrs: frozenset({"pve1.example", "pve1"}) if "192.0.2.10" in addrs else frozenset(),
        raising=False)
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="pve1.example", ssh_target="local")
    assert "SPLIT TARGET" not in " ".join(rep.get("flags", []))


@pytest.mark.parametrize("api_host", ["[0:0:0:0:0:0:0:1]", "[0::1]"])
def test_an_ip_literal_compares_by_address_not_by_spelling(monkeypatch, tmp_path, api_host):
    """`::1` has many spellings. urlsplit strips the brackets; the compare canonicalizes any
    parseable literal on both sides, so a spelling difference is not a split."""
    rep = _exec_cfg(monkeypatch, tmp_path, api_host=api_host, ssh_target="local")
    assert "SPLIT TARGET" not in " ".join(rep.get("flags", []))


def test_canonical_host_compares_ip_literals_by_address_and_names_by_lowercase():
    import proximo.doctor as doctor
    assert doctor._canonical_host("0:0::1") == "::1"
    assert doctor._canonical_host("Prod-PVE") == "prod-pve"
    assert doctor._canonical_host(" 192.0.2.10 ") == "192.0.2.10"
    assert doctor._canonical_host("") == ""


# Captured from a Linux kernel's own files, addresses moved to documentation ranges.
_FIB_TRIE_SAMPLE = """\
Main:
  +-- 0.0.0.0/0 3 0 5
     +-- 0.0.0.0/4 2 0 2
        |-- 0.0.0.0
           /0 universe UNICAST
        +-- 192.0.2.0/24 2 0 1
           |-- 192.0.2.0
              /24 link UNICAST
           |-- 192.0.2.71
              /32 host LOCAL
           |-- 192.0.2.255
              /32 link BROADCAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     +-- 198.51.100.0/24 2 0 1
        |-- 198.51.100.0
           /24 link UNICAST
        |-- 198.51.100.71
           /32 host LOCAL
        |-- 198.51.100.255
           /32 link BROADCAST
"""

_IF_INET6_SAMPLE = (
    "fe800000000000000000000000000001 02 40 20 80     eth0\n"
    "00000000000000000000000000000001 01 80 10 80       lo\n"
    "20010db8000000000000000000000071 02 40 00 80     eth0\n"
)

_HOSTS_SAMPLE = """\
127.0.0.1\tlocalhost
::1\t\tlocalhost ip6-localhost ip6-loopback
ff02::1\t\tip6-allnodes
ff02::2\t\tip6-allrouters
# --- BEGIN PVE ---
192.0.2.71 pve1.example pve1
# --- END PVE ---
192.0.2.210 pbs-test   # a neighbour, not this machine
127.0.1.1 Debian-Short
"""


def _proc_files(monkeypatch, tmp_path, fib=_FIB_TRIE_SAMPLE, inet6=_IF_INET6_SAMPLE, hosts=_HOSTS_SAMPLE):
    """Point the three readers at tmp copies; `None` for a file that does not exist."""
    import proximo.doctor as doctor
    for name, body in (("_PROC_FIB_TRIE", fib), ("_PROC_IF_INET6", inet6), ("_HOSTS_FILE", hosts)):
        path = tmp_path / name
        if body is not None:
            path.write_text(body)
        monkeypatch.setattr(doctor, name, str(path), raising=False)


def test_the_real_address_reader_takes_local_leaves_from_fib_trie_and_every_if_inet6_line(monkeypatch, tmp_path):
    """The real readers over the kernel's own shapes. IPv4: only a leaf followed by `/32 host
    LOCAL` is this machine; the network, the broadcast and the `/8 host LOCAL` loopback net are
    not. IPv6: every line, in canonical compressed text."""
    _proc_files(monkeypatch, tmp_path)
    assert _REAL_INTERFACE_ADDRESSES() == frozenset({
        "192.0.2.71", "198.51.100.71", "127.0.0.1",
        "fe80::1", "::1", "2001:db8::71",
    })


@pytest.mark.parametrize("fib, inet6", [
    (None, None),                                            # off Linux: neither file exists
    ("", ""),                                                # empty files
    ("not a trie\n|-- nonsense\n   /32 host LOCAL\n", "zz 00 00 00 00 lo\n"),   # unparseable
])
def test_the_real_address_reader_is_empty_on_any_failure(monkeypatch, tmp_path, fib, inet6):
    """CONTROL: no file, or a file the parser cannot read, yields the empty set and the check
    degrades to hostname-only. It never raises: doctor is what an operator runs to learn why
    something ELSE is failing."""
    _proc_files(monkeypatch, tmp_path, fib=fib, inet6=inet6)
    assert _REAL_INTERFACE_ADDRESSES() == frozenset()


def test_the_real_address_reader_keeps_the_good_lines_around_a_bad_one(monkeypatch, tmp_path):
    """One unreadable if_inet6 line does not lose the rest of the file."""
    _proc_files(monkeypatch, tmp_path, fib="", inet6="zz 00 00 00 00 lo\n" + _IF_INET6_SAMPLE)
    assert _REAL_INTERFACE_ADDRESSES() == frozenset({"fe80::1", "::1", "2001:db8::71"})


def test_the_real_hosts_reader_takes_names_only_from_loopback_and_own_address_lines(monkeypatch, tmp_path):
    """The PVE-written line names this node by FQDN and short name; a neighbour's line does not
    name this host, a multicast line does not either, comments are dropped, names are lowercased,
    and Debian's `127.0.1.1 <name>` convention is loopback."""
    _proc_files(monkeypatch, tmp_path)
    own = frozenset({"192.0.2.71"})
    assert _REAL_HOSTS_FILE_NAMES(own) == frozenset({
        "localhost", "ip6-localhost", "ip6-loopback", "pve1.example", "pve1", "debian-short"})
    assert _REAL_HOSTS_FILE_NAMES(frozenset()) == frozenset({
        "localhost", "ip6-localhost", "ip6-loopback", "debian-short"})


def test_the_real_hosts_reader_is_empty_without_a_hosts_file(monkeypatch, tmp_path):
    _proc_files(monkeypatch, tmp_path, hosts=None)
    assert _REAL_HOSTS_FILE_NAMES(frozenset({"192.0.2.71"})) == frozenset()


def test_this_host_names_assembles_loopback_hostname_addresses_and_hosts_names(monkeypatch, tmp_path):
    """The set the check compares against, end to end through the REAL readers over the samples."""
    import proximo.doctor as doctor
    _proc_files(monkeypatch, tmp_path)
    monkeypatch.setattr(doctor, "_interface_addresses", _REAL_INTERFACE_ADDRESSES, raising=False)
    monkeypatch.setattr(doctor, "_hosts_file_names", _REAL_HOSTS_FILE_NAMES, raising=False)
    monkeypatch.setattr(doctor.socket, "gethostname", lambda: "PVE1")
    names = doctor._this_host_names()
    assert {"localhost", "127.0.0.1", "::1", "pve1", "192.0.2.71", "198.51.100.71",
            "2001:db8::71", "pve1.example"} <= names, names
    assert not {"pbs-test", "192.0.2.210", "192.0.2.255", "127.0.0.0"} & names, names


# ── lens round 4 (2026-09-05): three survivors, all gaps in the tests above, none in the code ──

def test_the_real_address_reader_keeps_the_good_lines_after_an_unparseable_one(monkeypatch, tmp_path):
    """LENS ROUND 4, survivor 1: the "bad line" sample above is two characters, so it takes the
    length `continue` and never reaches the parse handler; `except ValueError: break` in EITHER
    reader stayed green. A head that is the right length but not hex, and a leaf that is not an
    address, each cost only that line, never the addresses after it."""
    _proc_files(monkeypatch, tmp_path,
                fib="|-- nonsense\n   /32 host LOCAL\n|-- 192.0.2.71\n   /32 host LOCAL\n",
                inet6="zz" * 16 + " 01 80 10 80 lo\n" + "00000000000000000000000000000001 01 80 10 80 lo\n")
    assert _REAL_INTERFACE_ADDRESSES() == frozenset({"192.0.2.71", "::1"})


def test_the_real_address_reader_does_not_mint_an_address_from_a_short_hex_head(monkeypatch, tmp_path):
    """LENS ROUND 4, survivor 2: the 32-digit guard had no test that could fail without it. A head
    that is valid hex but the wrong length (`deadbeef`) is an integer, and without the guard it
    mints `::dead:beef` into this host's names."""
    _proc_files(monkeypatch, tmp_path, fib="",
                inet6="deadbeef 02 40 20 80 eth0\n" + "00000000000000000000000000000001 01 80 10 80 lo\n")
    assert _REAL_INTERFACE_ADDRESSES() == frozenset({"::1"})


def test_the_ssh_side_of_the_compare_is_canonical_too(monkeypatch, tmp_path):
    """LENS ROUND 4, survivor 3: only the API side's canonicalization was pinned. `ssh -G` prints
    HostName as the operator's config spells it, so a differently spelled IPv6 literal for this
    host must still read as this host on the ssh side."""
    import proximo.doctor as doctor
    monkeypatch.setattr(doctor, "_ssh_config_host", lambda target: "0:0:0:0:0:0:0:1")
    rep = _exec_cfg(monkeypatch, tmp_path, api_host="[::1]", ssh_target="lab-alias")
    assert "SPLIT TARGET" not in " ".join(rep.get("flags", []))
