"""pve_doctor — connectivity + token-permission preflight (unit + PROVE seam).

The doctor is read-only and onboarding-facing: it answers "is my config/token right, and what
can this token actually DO?" before a stranger wires Proximo into an MCP client. Same advisory,
never-overclaim posture as DIAGNOSE; routes through the ledger (mutation=False) like other reads.
"""
from __future__ import annotations

import json
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
