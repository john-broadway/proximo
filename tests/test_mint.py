"""MINT — the print-only onboarding recipe builder (see docs/plans/2026-07-06-mint-helper-design.md (internal-only)).

Pure-unit: no live host, no env, no I/O. The file-format separator assertions (= / : / password)
are the regression guard for the exact bug that motivated the helper — a wrong separator
yields a bare 401 with no hint.
"""

import pytest

from proximo.mint import PRODUCTS, build_recipe, render_text

STEP_KEYS = ["create", "write", "grant", "wire", "verify"]


def _step(recipe, key):
    return next(s for s in recipe["steps"] if s["key"] == key)


def _commands(recipe, key):
    return "\n".join(_step(recipe, key)["commands"])


def _notes(recipe, key):
    return "\n".join(_step(recipe, key)["notes"])


# ---------------------------------------------------------------- shape

def test_recipe_shape_and_step_order():
    r = build_recipe("pve")
    assert r["product"] == "pve"
    assert r["user"] == "proximo@pve"
    assert r["token_name"] == "mcp"
    assert r["token_file"] == "~/.config/proximo/pve.token"
    assert r["write"] is False
    assert [s["key"] for s in r["steps"]] == STEP_KEYS


def test_unknown_product_errors_listing_valid_set():
    with pytest.raises(ValueError, match="unknown product"):
        build_recipe("esx")
    with pytest.raises(ValueError, match="pve, pbs, pmg, pdm"):
        build_recipe("esx")


def test_custom_args_propagate():
    r = build_recipe("pve", user="ops@pam", token_name="agent",
                     token_file="/etc/proximo/edge.token")
    assert r["user"] == "ops@pam"
    assert "ops@pam!agent" in _commands(r, "create")
    assert "/etc/proximo/edge.token" in _commands(r, "create")


# ---------------------------------------------------------------- pve

def test_pve_create_leads_with_pvesh_json_capture():
    c = _commands(build_recipe("pve"), "create")
    assert "pvesh create /access/users/proximo@pve/token/mcp --privsep 1 --output-format json" in c
    assert "> ~/.config/proximo/pve.token" in c        # secret straight to the file
    assert "umask 177" in c
    # pveum token add prints-once (the reviewer's trap) — mint must NOT lead with it
    assert "pveum user token add" not in c


def test_pve_file_format_is_equals_separator():
    r = build_recipe("pve")
    assert "proximo@pve!mcp=" in _commands(r, "create")   # the capture writes authid=SECRET
    assert "proximo@pve!mcp=SECRET" in _notes(r, "write")  # the format is stated for hand-minters
    assert "chmod 600" in _commands(r, "write")


def test_pve_grant_defaults_read_only_token_acl():
    c = _commands(build_recipe("pve"), "grant")
    assert "pveum acl modify / --tokens 'proximo@pve!mcp' --roles PVEAuditor" in c
    # privsep gotcha: the token's OWN acl, said out loud
    assert "own acl" in _notes(build_recipe("pve"), "grant").lower()


def test_pve_grant_covers_token_AND_user():
    # issue #24 (alexdelprete): a --privsep 1 token's effective perms are the INTERSECTION of
    # the user's ACL and the token's ACL. A freshly-created user (SETUP.md creates one) has NO
    # ACL of its own, so granting the token alone leaves the intersection empty — the token
    # authenticates but can do NOTHING. Both grants are required, always, not situationally.
    r = build_recipe("pve")
    c = _commands(r, "grant")
    assert "pveum acl modify / --tokens 'proximo@pve!mcp' --roles PVEAuditor" in c
    assert "pveum acl modify / --users 'proximo@pve' --roles PVEAuditor" in c
    notes = _notes(r, "grant").lower()
    assert "intersection" in notes


def test_pve_write_flag_grant_covers_token_AND_user():
    r = build_recipe("pve", write=True)
    c = _commands(r, "grant")
    assert "--tokens 'proximo@pve!mcp' --roles PVEVMAdmin" in c
    assert "--users 'proximo@pve' --roles PVEVMAdmin" in c


def test_pve_write_flag_swaps_grant():
    r = build_recipe("pve", write=True)
    c = _commands(r, "grant")
    assert "PVEVMAdmin" in c
    assert "PVEAuditor" not in c
    assert r["write"] is True


def test_pve_wire_env_triple():
    c = _commands(build_recipe("pve"), "wire")
    assert "PROXIMO_API_BASE_URL" in c
    assert "PROXIMO_NODE" in c
    assert "PROXIMO_TOKEN_PATH=~/.config/proximo/pve.token" in c
    assert 'kind = "pve"' in c                          # the targets-registry alternative


def test_pve_verify_is_doctor():
    c = _commands(build_recipe("pve"), "verify")
    assert "proximo doctor" in c


# ---------------------------------------------------------------- pbs

def test_pbs_create_uses_generate_token_json_capture():
    c = _commands(build_recipe("pbs"), "create")
    assert ("proxmox-backup-manager user generate-token proximo@pbs mcp"
            " --output-format json") in c
    assert "proxmox-backup-manager user create proximo@pbs" in c
    assert "> ~/.config/proximo/pbs.token" in c
    assert "umask 177" in c


def test_pbs_file_format_is_colon_separator():
    r = build_recipe("pbs")
    assert "proximo@pbs!mcp:" in _commands(r, "create")
    assert "proximo@pbs!mcp:SECRET" in _notes(r, "write")
    assert "proximo@pbs!mcp=" not in _commands(r, "create")   # the PVE '=' trap must NOT leak in
    assert "chmod 600" in _commands(r, "write")


def test_pbs_grant_defaults_read_only_and_write_swaps():
    ro = _commands(build_recipe("pbs"), "grant")
    assert "proxmox-backup-manager acl update / Audit --auth-id 'proximo@pbs!mcp'" in ro
    rw = _commands(build_recipe("pbs", write=True), "grant")
    assert "DatastoreAdmin" in rw
    assert " Audit " not in rw


def test_pbs_wire_env():
    c = _commands(build_recipe("pbs"), "wire")
    assert "PROXIMO_PBS_BASE_URL=https://<pbs-host>:8007/api2/json" in c
    assert "PROXIMO_PBS_TOKEN_PATH=~/.config/proximo/pbs.token" in c
    assert 'kind = "pbs"' in c


def test_pbs_verify_auth_smoke_then_doctor():
    r = build_recipe("pbs")
    c = _commands(r, "verify")
    assert "PBSAPIToken=$(cat ~/.config/proximo/pbs.token)" in c
    assert "/api2/json/version" in c
    assert "doctor" in (c + _notes(r, "verify"))


# ---------------------------------------------------------------- pdm

def test_pdm_create_is_a_rest_recipe_with_cookie_jar():
    c = _commands(build_recipe("pdm"), "create")
    assert "https://<pdm-host>:8443/api2/json/access/ticket" in c
    assert "-c /tmp/proximo-pdm.cookie" in c                      # PDM 1.1: ticket = HttpOnly cookie
    assert "CSRFPreventionToken" in c
    assert "/access/users/proximo@pdm/token/mcp" in c
    assert "read -rsp" in c                                       # root password never in argv/history
    assert "pveum" not in c                                       # no CLI verb exists — REST only
    assert "umask 177" in c


def test_pdm_file_format_is_colon_separator():
    r = build_recipe("pdm")
    assert "proximo@pdm!mcp:" in _commands(r, "create")
    assert "proximo@pdm!mcp:SECRET" in _notes(r, "write")
    assert "proximo@pdm!mcp=" not in _commands(r, "create")


def test_pdm_grant_covers_token_AND_user():
    r = build_recipe("pdm")
    c = _commands(r, "grant")
    assert "auth-id=proximo@pdm!mcp" in c        # the token's own ACL
    assert "'auth-id=proximo@pdm'" in c          # AND the user's — privsep intersection
    assert "role=Auditor" in c
    notes = _notes(r, "grant").lower()
    assert "privilege-separated" in notes and "user" in notes


def test_pdm_write_flag_swaps_grant():
    c = _commands(build_recipe("pdm", write=True), "grant")
    assert "role=Administrator" in c
    assert "role=Auditor" not in c


def test_pdm_wire_env():
    c = _commands(build_recipe("pdm"), "wire")
    assert "PROXIMO_PDM_BASE_URL=https://<pdm-host>:8443" in c
    assert "PROXIMO_PDM_TOKEN_PATH=~/.config/proximo/pdm.token" in c
    assert 'kind = "pdm"' in c


def test_pdm_verify_space_separated_header_then_doctor():
    r = build_recipe("pdm")
    c = _commands(r, "verify")
    assert "PDMAPIToken $(cat ~/.config/proximo/pdm.token)" in c   # SPACE header, not '='
    assert "doctor" in (c + _notes(r, "verify"))


# ---------------------------------------------------------------- pmg

def test_pmg_create_is_user_plus_password_not_token():
    r = build_recipe("pmg")
    c = _commands(r, "create")
    assert "openssl rand -base64 30 > ~/.config/proximo/pmg.token" in c
    assert "pmgsh create /config/users --userid proximo@pmg" in c
    assert "--password \"$(cat" in c                 # read from the file, never retyped
    assert "token" not in _step(r, "create")["title"].lower()   # PMG has no API tokens
    assert "generate-token" not in c


def test_pmg_write_step_says_password_file():
    r = build_recipe("pmg")
    assert "chmod 600 ~/.config/proximo/pmg.token" in _commands(r, "write")
    notes = _notes(r, "write").lower()
    assert "password" in notes
    assert "no api token" in notes or "no token" in notes


def test_pmg_grant_defaults_audit_and_write_swaps_admin():
    ro = _commands(build_recipe("pmg"), "grant")
    assert "pmgsh set /config/users/proximo@pmg --role audit" in ro
    rw = build_recipe("pmg", write=True)
    assert "--role admin" in _commands(rw, "grant")
    assert "coarse" in _notes(rw, "grant").lower()   # admin = full control, said out loud


def test_pmg_wire_env_includes_username():
    c = _commands(build_recipe("pmg"), "wire")
    assert "PROXIMO_PMG_BASE_URL=https://<pmg-host>:8006/api2/json" in c
    assert "PROXIMO_PMG_PASSWORD_PATH=~/.config/proximo/pmg.token" in c
    assert "PROXIMO_PMG_USERNAME=proximo@pmg" in c   # default is root@pam — must be overridden
    assert 'kind = "pmg"' in c


def test_pmg_verify_ticket_login_then_doctor():
    r = build_recipe("pmg")
    c = _commands(r, "verify")
    assert "/api2/json/access/ticket" in c
    assert "username=proximo@pmg" in c
    assert "doctor" in (c + _notes(r, "verify"))


def test_all_products_have_builders():
    for p in PRODUCTS:
        assert build_recipe(p)["product"] == p


# ---------------------------------------------------------------- invariants (all products)

@pytest.mark.parametrize("product", PRODUCTS)
def test_every_recipe_has_the_five_steps_in_order(product):
    r = build_recipe(product)
    assert [s["key"] for s in r["steps"]] == STEP_KEYS
    for s in r["steps"]:
        assert s["title"]
        assert s["commands"]


@pytest.mark.parametrize("product", PRODUCTS)
def test_every_recipe_locks_the_file_to_600(product):
    joined = "\n".join(c for s in build_recipe(product)["steps"] for c in s["commands"])
    assert "chmod 600" in joined or "umask 177" in joined


@pytest.mark.parametrize("product", PRODUCTS)
def test_every_verify_step_hands_off_to_doctor(product):
    s = _step(build_recipe(product), "verify")
    assert "doctor" in "\n".join(s["commands"] + s["notes"])


@pytest.mark.parametrize("product", PRODUCTS)
def test_default_user_and_file_per_product(product):
    r = build_recipe(product)
    assert r["user"] == f"proximo@{product}"
    assert r["token_file"] == f"~/.config/proximo/{product}.token"


@pytest.mark.parametrize("product", PRODUCTS)
def test_no_secret_placeholder_ever_echoes(product):
    """No recipe command prints a captured secret to stdout — capture goes straight to the file."""
    for s in build_recipe(product)["steps"]:
        for c in s["commands"]:
            for line in c.split("\n"):
                if "print(" in line and "value" in line.lower():
                    block = c  # the python -c capture must be piped into a redirect
                    assert "> " in block


# ---------------------------------------------------------------- renderer

def test_render_text_header_and_numbered_steps():
    out = render_text(build_recipe("pve"))
    assert out.startswith("proximo mint — pve onboarding (read-only)")
    assert "[1/5] create — " in out
    assert "[5/5] verify — " in out


def test_render_text_write_mode_in_header():
    assert "(write)" in render_text(build_recipe("pve", write=True)).splitlines()[0]


def test_render_text_indents_commands_and_prefixes_notes():
    out = render_text(build_recipe("pbs"))
    assert "\n    proxmox-backup-manager user create proximo@pbs" in out
    assert "\n  note: " in out


def test_render_text_indents_every_line_of_multiline_blocks():
    out = render_text(build_recipe("pdm"))
    for line in out.splitlines():
        if "curl -sk" in line:
            assert line.startswith("    ")
