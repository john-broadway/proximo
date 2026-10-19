"""Each plane's own arm pair from env: PBS and PDM can be armed on the env box, PMG says why not.

Until 2026-09-28 only the pve plane read an arm pair from env; every PBS, PMG and PDM mutation
through the core refused "no arm_source". Registry targets already carried a pair per target; the
env box now does too, by plane: `PROXIMO_PBS_ARM_SOURCE` / `PROXIMO_PBS_READONLY_SOURCE`, and the
same with `PDM_`. PVE's `PROXIMO_ARM_SOURCE` never arms another plane.

PBS and PDM tokens carry the identity inside the file (`user@realm!tokenid=secret`), so swapping
the file swaps a read-only token for a write one. PMG logs in with a username from env and a
password file: a swap changes only the password, so one account's read-only and arm files would
be the same secret and read as armed forever. In that PASSWORD mode PMG stays refused, and the
refusal says why. In CREDENTIAL mode (2026-09-28, parity row B12) the file is two lines,
`user@realm` then the password: the identity rides in the file like a token's, the swap changes
who logs in, and PMG arms by its own pair like PBS and PDM.
"""
from __future__ import annotations

import os

import pytest

from proximo.core import arm, engine, wire

_ROW = {"pbs": ("POST", "/pull"), "pdm": ("POST", "/access/users"), "pmg": ("POST", "/config/ldap")}


def _secret(tmp_path, name, value):
    p = tmp_path / name
    p.write_text(value)
    p.chmod(0o600)
    return str(p)


@pytest.fixture
def env(monkeypatch, tmp_path):
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var not in ("PROXIMO_AUDIT_LOG", "PROXIMO_ENV_FILE"):
            monkeypatch.delenv(var)
    return tmp_path


def _plane(monkeypatch, tmp, product, served, *, arm_to=None, ro_to=None):
    p = f"PROXIMO_{product.upper()}_"
    monkeypatch.setenv(f"{p}BASE_URL", f"https://{product}.invalid:8007/api2/json")
    secret_var = f"{p}PASSWORD_PATH" if product == "pmg" else f"{p}TOKEN_PATH"
    monkeypatch.setenv(secret_var, _secret(tmp, f"{product}.served", served))
    if arm_to is not None:
        monkeypatch.setenv(f"{p}ARM_SOURCE", _secret(tmp, f"{product}.arm", arm_to))
    if ro_to is not None:
        monkeypatch.setenv(f"{p}READONLY_SOURCE", _secret(tmp, f"{product}.ro", ro_to))
    return wire.Plane.from_env(product)


def _verdict(product, cfg):
    method, path = _ROW[product]
    row = engine.resolve(product, method, path)
    assert row.tier, f"the premise: {row.address} is tiered, so ARM is the only question"
    return engine.govern(row, cfg=cfg, path=path)


@pytest.mark.parametrize("product", ["pbs", "pdm"])
def test_the_planes_own_pair_arms_it_and_disarms_it(monkeypatch, env, product):
    armed = _plane(monkeypatch, env, product, "u@pbs!w=WRITE", arm_to="u@pbs!w=WRITE", ro_to="u@pbs!r=READ")
    assert _verdict(product, armed).needs != "arm"
    disarmed = _plane(monkeypatch, env, product, "u@pbs!r=READ", arm_to="u@pbs!w=WRITE", ro_to="u@pbs!r=READ")
    v = _verdict(product, disarmed)
    assert not v.allowed and v.needs == "arm" and "read-only" in v.reason


@pytest.mark.parametrize("product", ["pbs", "pdm"])
def test_pves_pair_never_arms_another_plane(monkeypatch, env, product):
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", _secret(env, "pve.arm", "u@pbs!w=WRITE"))
    cfg = _plane(monkeypatch, env, product, "u@pbs!w=WRITE")      # same bytes as PVE's arm source
    v = _verdict(product, cfg)
    assert not v.allowed and v.needs == "arm" and f"PROXIMO_{product.upper()}_ARM_SOURCE" in v.reason


def test_pmg_is_refused_and_says_why(monkeypatch, env):
    cfg = _plane(monkeypatch, env, "pmg", "pw", arm_to="pw")
    assert cfg.arm_source is None
    v = _verdict("pmg", cfg)
    assert not v.allowed and v.needs == "arm" and "password" in v.reason


@pytest.mark.parametrize("product", ["pve", "pbs"])
def test_an_arm_and_read_only_source_holding_one_secret_is_refused(monkeypatch, env, product):
    """Two paths, one secret: the served token always equals the arm source, so the gate would
    read ARMED forever. Only the same PATH was refused before."""
    if product == "pve":
        monkeypatch.setenv("PROXIMO_TOKEN_PATH", _secret(env, "pve.served", "same"))
        monkeypatch.setenv("PROXIMO_ARM_SOURCE", _secret(env, "pve.arm", "same"))
        monkeypatch.setenv("PROXIMO_READONLY_SOURCE", _secret(env, "pve.ro", "same"))
        state = arm.arm_state()
    else:
        state = arm.arm_state(_plane(monkeypatch, env, product, "same", arm_to="same", ro_to="same"))
    assert state.enforced and not state.armed and "same secret" in state.reason


@pytest.mark.parametrize("product", ["pbs", "pmg", "pdm"])
def test_with_no_config_given_pves_arm_does_not_arm_another_plane(monkeypatch, env, product):
    """THE DOORS PASS NO CONFIG for the env box: the shell door and the MCP door call govern with
    cfg=None, and `arm_state(None)` grades the PVE env pair. So with PVE armed, a tiered PBS,
    PMG or PDM mutation through either door read as ARMED. Found 2026-09-28 wiring the planes'
    own pairs; the registry path had been hardened against exactly this, the env path had not."""
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", _secret(env, "pve.served", "u@pam!w=PVEWRITE"))
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", _secret(env, "pve.arm", "u@pam!w=PVEWRITE"))
    assert arm.arm_state().armed, "the premise: PVE is armed"
    _plane(monkeypatch, env, product, "u@pbs!r=READ")
    method, path = _ROW[product]
    v = engine.govern(engine.resolve(product, method, path), path=path)
    assert not v.allowed and v.needs == "arm"


def test_with_no_config_given_the_planes_own_pair_still_arms_it(monkeypatch, env):
    _plane(monkeypatch, env, "pbs", "u@pbs!w=WRITE", arm_to="u@pbs!w=WRITE", ro_to="u@pbs!r=READ")
    v = engine.govern(engine.resolve("pbs", "POST", "/pull"), path="/pull")
    assert v.needs != "arm"


# --- LENS FOLD (sonnet, 2026-09-28, 2 BLOCKING), each watched red first --------------------------

def test_another_plane_at_pves_url_and_token_file_is_not_the_env_box(monkeypatch, env):
    """`is_env_box` matched token file + base URL and never the product: a pbs Plane that shared
    both (a copy-pasted env) inherited PVE's arm, and a disruptive PBS mutation governed ALLOWED."""
    url = "https://box.invalid:8006/api2/json"
    served = _secret(env, "pve.served", "SHARED")
    monkeypatch.setenv("PROXIMO_API_BASE_URL", url)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", served)
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", _secret(env, "pve.arm", "SHARED"))
    assert arm.arm_state().armed, "the premise: PVE is armed"
    pbs = wire.Plane(product="pbs", base_url=url, token_path=served)
    assert not arm.arm_state(pbs).armed
    v = engine.govern(engine.resolve("pbs", "POST", "/pull"), cfg=pbs, path="/pull")
    assert not v.allowed and v.needs == "arm"


def test_a_registry_pmg_target_with_an_arm_source_is_still_refused(env):
    """PMG has no pair on ANY path: a registry entry's arm_source equal to the served password
    armed it, while the docs said PMG mutations stay refused."""
    fields = {"base_url": "https://pmg.invalid:8006/api2/json",
              "password_path": _secret(env, "pmg.pw", "same"), "username": "root@pam",
              "arm_source": _secret(env, "pmg.arm", "same")}
    cfg = wire.plane_from_target("pmg", "lab-pmg", fields)
    state = arm.arm_state(cfg)
    assert not state.armed and "password" in state.reason


# --- PMG CREDENTIAL MODE (parity row B12, 2026-09-28) ---------------------------------------------

AUDIT = "audit@pmg\nREADPW"
ADMIN = "admin@pmg\nWRITEPW"


def _pmg_cred(monkeypatch, tmp, served, *, arm_to=None, ro_to=None):
    monkeypatch.setenv("PROXIMO_PMG_BASE_URL", "https://pmg.invalid:8006/api2/json")
    monkeypatch.setenv("PROXIMO_PMG_CREDENTIAL_PATH", _secret(tmp, "pmg.cred", served))
    if arm_to is not None:
        monkeypatch.setenv("PROXIMO_PMG_ARM_SOURCE", _secret(tmp, "pmg.arm", arm_to))
    if ro_to is not None:
        monkeypatch.setenv("PROXIMO_PMG_READONLY_SOURCE", _secret(tmp, "pmg.ro", ro_to))
    return wire.Plane.from_env("pmg")


def test_pmg_credential_mode_arms_by_its_own_pair_and_disarms(monkeypatch, env):
    armed = _pmg_cred(monkeypatch, env, ADMIN, arm_to=ADMIN, ro_to=AUDIT)
    assert armed.credential and _verdict("pmg", armed).needs != "arm"
    disarmed = _pmg_cred(monkeypatch, env, AUDIT, arm_to=ADMIN, ro_to=AUDIT)
    v = _verdict("pmg", disarmed)
    assert not v.allowed and v.needs == "arm" and "read-only" in v.reason


def test_the_swap_changes_who_logs_in(monkeypatch, env):
    """The point of the mode: armed and disarmed are two USERS, read from the file the arm compared."""
    assert wire.pmg_login(_pmg_cred(monkeypatch, env, ADMIN)) == ("admin@pmg", "WRITEPW")
    assert wire.pmg_login(_pmg_cred(monkeypatch, env, AUDIT)) == ("audit@pmg", "READPW")


def test_the_client_posts_the_files_user_not_a_default(monkeypatch, env):
    cfg = _pmg_cred(monkeypatch, env, AUDIT)
    client = wire.Client(cfg)
    sent = {}

    class _R:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": {"ticket": "T", "CSRFPreventionToken": "C"}}

    monkeypatch.setattr(client._client, "post", lambda url, data: sent.update(data) or _R())
    client._login()
    assert sent == {"username": "audit@pmg", "password": "READPW"}


@pytest.mark.parametrize("body", ["READPW", "audit@pmg\n", "audit\nREADPW", "audit@pmg\nREAD\nPW"])
def test_a_malformed_credential_file_refuses_by_shape_never_content(monkeypatch, env, body):
    cfg = _pmg_cred(monkeypatch, env, body)
    with pytest.raises(engine.ProximoError, match="two lines") as e:
        wire.pmg_login(cfg)
    assert "READ" not in str(e.value) and "audit" not in str(e.value)


def test_pmg_credential_mode_with_no_pair_is_refused_by_name(monkeypatch, env):
    v = _verdict("pmg", _pmg_cred(monkeypatch, env, ADMIN))
    assert not v.allowed and v.needs == "arm" and "PROXIMO_PMG_ARM_SOURCE" in v.reason


def test_one_user_in_both_files_is_one_secret_and_refused(monkeypatch, env):
    state = arm.arm_state(_pmg_cred(monkeypatch, env, ADMIN, arm_to=ADMIN, ro_to=ADMIN))
    assert not state.armed and "same secret" in state.reason


def test_pves_arm_never_arms_pmg_credential_mode_with_no_config_given(monkeypatch, env):
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", _secret(env, "pve.served", ADMIN))
    monkeypatch.setenv("PROXIMO_ARM_SOURCE", _secret(env, "pve.arm", ADMIN))
    assert arm.arm_state().armed, "the premise: PVE is armed with the same bytes"
    _pmg_cred(monkeypatch, env, ADMIN)
    method, path = _ROW["pmg"]
    v = engine.govern(engine.resolve("pmg", method, path), path=path)
    assert not v.allowed and v.needs == "arm"


def test_with_no_config_given_pmgs_own_pair_arms_it(monkeypatch, env):
    _pmg_cred(monkeypatch, env, ADMIN, arm_to=ADMIN, ro_to=AUDIT)
    method, path = _ROW["pmg"]
    assert engine.govern(engine.resolve("pmg", method, path), path=path).needs != "arm"


def test_credential_and_password_both_set_is_refused(monkeypatch, env):
    monkeypatch.setenv("PROXIMO_PMG_PASSWORD_PATH", _secret(env, "pmg.pw", "READPW"))
    with pytest.raises(RuntimeError, match="not both"):
        _pmg_cred(monkeypatch, env, ADMIN)


def test_a_registry_pmg_target_in_credential_mode_arms_by_its_pair(env):
    fields = {"base_url": "https://pmg.invalid:8006/api2/json",
              "credential_path": _secret(env, "pmg.cred", ADMIN),
              "arm_source": _secret(env, "pmg.arm", ADMIN), "readonly_source": _secret(env, "pmg.ro", AUDIT)}
    cfg = wire.plane_from_target("pmg", "lab-pmg", fields)
    assert cfg.credential and arm.arm_state(cfg).armed
    with pytest.raises(engine.ProximoError, match="one way to log in"):
        wire.plane_from_target("pmg", "lab-pmg", {**fields, "password_path": fields["credential_path"]})


def test_both_modes_set_reads_refused_at_plan_time_not_only_at_the_wire(monkeypatch, env):
    """env_arm_view graded credential mode from one variable and never saw the other; govern said
    ARMED and the client build refused only after the spending gates (lens 2026-09-28)."""
    _pmg_cred(monkeypatch, env, ADMIN, arm_to=ADMIN, ro_to=AUDIT)
    monkeypatch.setenv("PROXIMO_PMG_PASSWORD_PATH", _secret(env, "pmg.pw", "READPW"))
    method, path = _ROW["pmg"]
    v = engine.govern(engine.resolve("pmg", method, path), path=path)
    assert not v.allowed and v.needs == "arm" and "both set" in v.reason


def test_a_bom_is_not_part_of_the_user(monkeypatch, env):
    assert wire.pmg_login(_pmg_cred(monkeypatch, env, "\ufeffaudit@pmg\nREADPW"))[0] == "audit@pmg"
