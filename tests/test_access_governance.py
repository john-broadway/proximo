"""ROLES & REALMS GOVERNANCE pillar tests — fully mocked, no live Proxmox.

Mirrors test_access.py / test_cluster_ops.py style:
- _api() / _put_api() fakes record calls; assertions verify URL/param shapes.
- _users_api() / _acl_api() supply read results for plan functions.
- plan_* tests verify risk, blast text, read-failure honesty (mirrors plan_migrate contract).
- Validator-rejection tests use pytest.raises(ProximoError).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from proximo.access_governance import (
    _check_realmid,
    _is_builtin_realm,
    _is_builtin_role,
    plan_realm_create,
    plan_realm_delete,
    plan_realm_update,
    plan_role_create,
    plan_role_delete,
    plan_role_update,
    plan_tfa_delete,
    realm_create,
    realm_delete,
    realm_get,
    realm_update,
    realms_list,
    role_create,
    role_delete,
    role_update,
    tfa_delete,
    tfa_get,
    tfa_list,
)
from proximo.backends import ProximoError
from proximo.planning import RISK_HIGH, RISK_MEDIUM

# ---------------------------------------------------------------------------
# Shared fakes
# ---------------------------------------------------------------------------

def _api(node: str = "pve") -> SimpleNamespace:
    """Fake api recording _get / _post / _delete / _put calls."""
    seen: dict = {}

    def fake_get(path):
        seen["method"] = "GET"
        seen["path"] = path
        return []

    def fake_post(path, data=None):
        seen["method"] = "POST"
        seen["path"] = path
        seen["data"] = data or {}
        return None

    def fake_delete(path, params=None):
        seen["method"] = "DELETE"
        seen["path"] = path
        seen["params"] = params
        return None

    def fake_put(path, data=None):
        seen["method"] = "PUT"
        seen["path"] = path
        seen["data"] = data or {}
        return None

    return SimpleNamespace(
        config=SimpleNamespace(node=node),
        _get=fake_get,
        _post=fake_post,
        _delete=fake_delete,
        _put=fake_put,
        seen=seen,
    )


def _acl_api(acl_entries: list[dict], raise_on_get: bool = False, status_code: int | None = None):
    """Fake for plan_role_delete — returns ACL entries or raises."""
    def fake_get(path):
        if raise_on_get:
            if status_code == 404:
                err = RuntimeError("not found")
                err.response = SimpleNamespace(status_code=404)
                raise err
            raise RuntimeError("api unavailable")
        if path == "/access/acl":
            return list(acl_entries)
        return []

    return SimpleNamespace(config=SimpleNamespace(node="pve"), _get=fake_get)


def _users_api(user_entries: list[dict], raise_on_get: bool = False, status_code: int | None = None):
    """Fake for plan_realm_delete — returns user entries or raises."""
    def fake_get(path):
        if raise_on_get:
            if status_code == 404:
                err = RuntimeError("not found")
                err.response = SimpleNamespace(status_code=404)
                raise err
            raise RuntimeError("api unavailable")
        if path == "/access/users":
            return list(user_entries)
        return []

    return SimpleNamespace(config=SimpleNamespace(node="pve"), _get=fake_get)


# ---------------------------------------------------------------------------
# _check_realmid validator
# ---------------------------------------------------------------------------

def test_check_realmid_accepts_simple_alnum():
    assert _check_realmid("pam") == "pam"


def test_check_realmid_accepts_with_hyphen():
    assert _check_realmid("my-ldap") == "my-ldap"


def test_check_realmid_accepts_with_underscore():
    assert _check_realmid("corp_ad") == "corp_ad"


def test_check_realmid_accepts_with_dot():
    assert _check_realmid("example.com") == "example.com"


def test_check_realmid_rejects_leading_hyphen():
    with pytest.raises(ProximoError):
        _check_realmid("-bad")


def test_check_realmid_rejects_dot_dot_traversal():
    # consistency with the other id validators: no embedded '..' (defense-in-depth, even though the
    # charset already forbids '/', so it can't form a collapsible path segment)
    with pytest.raises(ProximoError):
        _check_realmid("a..b")


def test_check_realmid_rejects_leading_dot():
    with pytest.raises(ProximoError):
        _check_realmid(".bad")


def test_check_realmid_rejects_slash():
    with pytest.raises(ProximoError):
        _check_realmid("bad/realm")


def test_check_realmid_rejects_embedded_newline():
    with pytest.raises(ProximoError):
        _check_realmid("realm\nevil")


def test_check_realmid_rejects_space():
    with pytest.raises(ProximoError):
        _check_realmid("bad realm")


def test_check_realmid_rejects_empty():
    with pytest.raises(ProximoError):
        _check_realmid("")


def test_check_realmid_rejects_at_sign():
    with pytest.raises(ProximoError):
        _check_realmid("bad@realm")


# ---------------------------------------------------------------------------
# _is_builtin_role helper
# ---------------------------------------------------------------------------

def test_is_builtin_role_administrator():
    assert _is_builtin_role("Administrator") is True


def test_is_builtin_role_pveadmin():
    assert _is_builtin_role("PVEAdmin") is True


def test_is_builtin_role_noaccess():
    assert _is_builtin_role("NoAccess") is True


def test_is_builtin_role_pvevmadmin():
    assert _is_builtin_role("PVEVMAdmin") is True


def test_is_builtin_role_pveauditor():
    assert _is_builtin_role("PVEAuditor") is True


def test_is_builtin_role_custom_is_false():
    assert _is_builtin_role("MyCustomRole") is False


def test_is_builtin_role_empty_is_false():
    assert _is_builtin_role("") is False


# ---------------------------------------------------------------------------
# _is_builtin_realm helper
# ---------------------------------------------------------------------------

def test_is_builtin_realm_pam():
    assert _is_builtin_realm("pam") is True


def test_is_builtin_realm_pve():
    assert _is_builtin_realm("pve") is True


def test_is_builtin_realm_ldap_is_false():
    assert _is_builtin_realm("corp-ldap") is False


def test_is_builtin_realm_openid_is_false():
    assert _is_builtin_realm("myoidc") is False


# ---------------------------------------------------------------------------
# realms_list — GET /access/domains
# ---------------------------------------------------------------------------

def test_realms_list_calls_correct_path():
    api = _api()
    realms_list(api)
    assert api.seen["path"] == "/access/domains"
    assert api.seen["method"] == "GET"


def test_realms_list_returns_list():
    api = _api()
    result = realms_list(api)
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# realm_get — GET /access/domains/{realm}
# ---------------------------------------------------------------------------

def test_realm_get_calls_correct_path():
    api = _api()
    realm_get(api, "pam")
    assert api.seen["path"] == "/access/domains/pam"
    assert api.seen["method"] == "GET"


def test_realm_get_returns_dict():
    api = _api()
    result = realm_get(api, "pam")
    assert isinstance(result, dict)


def test_realm_get_rejects_invalid_realm():
    api = _api()
    with pytest.raises(ProximoError):
        realm_get(api, "bad/realm")


def test_realm_get_rejects_newline_in_realm():
    api = _api()
    with pytest.raises(ProximoError):
        realm_get(api, "realm\nevil")


# ---------------------------------------------------------------------------
# tfa_list — GET /access/tfa
# ---------------------------------------------------------------------------

def test_tfa_list_calls_correct_path():
    api = _api()
    tfa_list(api)
    assert api.seen["path"] == "/access/tfa"
    assert api.seen["method"] == "GET"


def test_tfa_list_returns_list():
    api = _api()
    result = tfa_list(api)
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# role_create — POST /access/roles
# ---------------------------------------------------------------------------

def test_role_create_posts_correct_path():
    api = _api()
    role_create(api, "MyRole")
    assert api.seen["path"] == "/access/roles"
    assert api.seen["method"] == "POST"


def test_role_create_sends_roleid_in_body():
    api = _api()
    role_create(api, "MyRole")
    assert api.seen["data"]["roleid"] == "MyRole"


def test_role_create_sends_privs_when_provided():
    api = _api()
    role_create(api, "MyRole", privs="VM.PowerMgmt,VM.Config.Disk")
    assert api.seen["data"]["privs"] == "VM.PowerMgmt,VM.Config.Disk"


def test_role_create_omits_privs_when_not_provided():
    api = _api()
    role_create(api, "MyRole")
    assert "privs" not in api.seen["data"]


def test_role_create_rejects_invalid_roleid():
    api = _api()
    with pytest.raises(ProximoError):
        role_create(api, "bad role!")


def test_role_create_rejects_roleid_with_slash():
    api = _api()
    with pytest.raises(ProximoError):
        role_create(api, "bad/role")


def test_role_create_rejects_newline_in_privs():
    """Freetext injection guard: privs is stored in PVE's line-based role.cfg — a newline
    would corrupt it, same class of guard access_users.py already applies to comment/email."""
    api = _api()
    with pytest.raises(ProximoError):
        role_create(api, "MyRole", privs="VM.PowerMgmt\ninjected")


# ---------------------------------------------------------------------------
# role_update — PUT /access/roles/{roleid}
# ---------------------------------------------------------------------------

def test_role_update_puts_correct_path():
    api = _api()
    role_update(api, "MyRole")
    assert api.seen["path"] == "/access/roles/MyRole"
    assert api.seen["method"] == "PUT"


def test_role_update_sends_privs_when_provided():
    api = _api()
    role_update(api, "MyRole", privs="VM.PowerMgmt")
    assert api.seen["data"]["privs"] == "VM.PowerMgmt"


def test_role_update_omits_privs_when_not_provided():
    api = _api()
    role_update(api, "MyRole")
    assert "privs" not in api.seen["data"]


def test_role_update_sends_append_1_when_true():
    api = _api()
    role_update(api, "MyRole", privs="VM.PowerMgmt", append=True)
    assert api.seen["data"]["append"] == 1


def test_role_update_sends_append_0_when_false():
    api = _api()
    role_update(api, "MyRole", privs="VM.PowerMgmt", append=False)
    assert api.seen["data"]["append"] == 0


def test_role_update_omits_append_when_none():
    api = _api()
    role_update(api, "MyRole", privs="VM.PowerMgmt")
    assert "append" not in api.seen["data"]


def test_role_update_rejects_invalid_roleid():
    api = _api()
    with pytest.raises(ProximoError):
        role_update(api, "bad role!")


def test_role_update_rejects_newline_in_privs():
    api = _api()
    with pytest.raises(ProximoError):
        role_update(api, "MyRole", privs="VM.PowerMgmt\ninjected")


# ---------------------------------------------------------------------------
# role_delete — DELETE /access/roles/{roleid}
# ---------------------------------------------------------------------------

def test_role_delete_deletes_correct_path():
    api = _api()
    role_delete(api, "MyRole")
    assert api.seen["path"] == "/access/roles/MyRole"
    assert api.seen["method"] == "DELETE"


def test_role_delete_rejects_invalid_roleid():
    api = _api()
    with pytest.raises(ProximoError):
        role_delete(api, "bad role!")


# ---------------------------------------------------------------------------
# realm_create — POST /access/domains
# ---------------------------------------------------------------------------

def test_realm_create_posts_correct_path():
    api = _api()
    realm_create(api, "myldap", "ldap")
    assert api.seen["path"] == "/access/domains"
    assert api.seen["method"] == "POST"


def test_realm_create_sends_realm_and_type():
    api = _api()
    realm_create(api, "myldap", "ldap")
    assert api.seen["data"]["realm"] == "myldap"
    assert api.seen["data"]["type"] == "ldap"


def test_realm_create_sends_comment_when_provided():
    api = _api()
    realm_create(api, "myldap", "ldap", comment="Corporate LDAP")
    assert api.seen["data"]["comment"] == "Corporate LDAP"


def test_realm_create_omits_comment_when_not_provided():
    api = _api()
    realm_create(api, "myldap", "ldap")
    assert "comment" not in api.seen["data"]


def test_realm_create_rejects_newline_in_comment():
    """Freetext injection guard: comment is stored in PVE's line-based domains.cfg — a
    newline would corrupt it, same class of guard access_users.py already applies."""
    api = _api()
    with pytest.raises(ProximoError):
        realm_create(api, "myldap", "ldap", comment="injected\nnewline")


def test_realm_create_accepts_pam_type():
    api = _api()
    realm_create(api, "extrapam", "pam")
    assert api.seen["data"]["type"] == "pam"


def test_realm_create_accepts_pve_type():
    api = _api()
    realm_create(api, "extrapve", "pve")
    assert api.seen["data"]["type"] == "pve"


def test_realm_create_accepts_ad_type():
    api = _api()
    realm_create(api, "corp", "ad")
    assert api.seen["data"]["type"] == "ad"


def test_realm_create_accepts_openid_type():
    api = _api()
    realm_create(api, "myoidc", "openid")
    assert api.seen["data"]["type"] == "openid"


def test_realm_create_rejects_invalid_type():
    api = _api()
    with pytest.raises(ProximoError):
        realm_create(api, "bad", "kerberos")


def test_realm_create_rejects_invalid_realm():
    api = _api()
    with pytest.raises(ProximoError):
        realm_create(api, "bad/realm", "ldap")


# ---------------------------------------------------------------------------
# realm_create / realm_update — type-specific options passthrough
# (2026-06-09: live smoke proved PVE rejects a typed realm without its mandatory
#  type-specific fields, e.g. ldap needs server1/base_dn — so options is now supported)
# ---------------------------------------------------------------------------

def test_realm_create_merges_options_into_body():
    api = _api()
    realm_create(api, "myldap", "ldap",
                 options={"server1": "ldap.example.com", "base_dn": "dc=example,dc=com",
                          "user_attr": "uid"})
    assert api.seen["data"]["server1"] == "ldap.example.com"
    assert api.seen["data"]["base_dn"] == "dc=example,dc=com"
    assert api.seen["data"]["user_attr"] == "uid"
    # core fields still present
    assert api.seen["data"]["realm"] == "myldap"
    assert api.seen["data"]["type"] == "ldap"


def test_realm_create_options_passthrough_is_verbatim():
    # version-agnostic: an arbitrary key lands in the body unchanged (no key remapping).
    # openid uses hyphenated keys (issuer-url/client-id) — verified live on PVE 9.2.
    api = _api()
    realm_create(api, "myoidc", "openid",
                 options={"issuer-url": "https://idp.example.com", "client-id": "abc123"})
    assert api.seen["data"]["issuer-url"] == "https://idp.example.com"
    assert api.seen["data"]["client-id"] == "abc123"


def test_realm_create_ad_options_passthrough():
    # AD uses domain/server1 (verified live on PVE 9.2) — guard the docstring's claim
    api = _api()
    realm_create(api, "corp", "ad", options={"domain": "corp.local", "server1": "dc1.corp.local"})
    assert api.seen["data"]["domain"] == "corp.local"
    assert api.seen["data"]["server1"] == "dc1.corp.local"
    assert api.seen["data"]["type"] == "ad"


def test_realm_create_options_none_keeps_minimal_body():
    api = _api()
    realm_create(api, "myldap", "ldap")
    assert set(api.seen["data"].keys()) == {"realm", "type"}


def test_realm_create_options_cannot_clobber_core_fields():
    # a caller's options must not override realm/type (resource identity / injection guard)
    api = _api()
    realm_create(api, "myldap", "ldap", options={"realm": "evil", "type": "pam"})
    assert api.seen["data"]["realm"] == "myldap"
    assert api.seen["data"]["type"] == "ldap"


def test_realm_update_merges_options_into_body():
    api = _api()
    realm_update(api, "myldap", options={"server1": "new.example.com"})
    assert api.seen["data"]["server1"] == "new.example.com"


def test_realm_update_options_cannot_clobber_comment():
    # explicit comment param wins over an options['comment']
    api = _api()
    realm_update(api, "myldap", comment="real", options={"comment": "evil"})
    assert api.seen["data"]["comment"] == "real"


# ---------------------------------------------------------------------------
# realm_update — PUT /access/domains/{realm}
# ---------------------------------------------------------------------------

def test_realm_update_puts_correct_path():
    api = _api()
    realm_update(api, "myldap", comment="Updated")
    assert api.seen["path"] == "/access/domains/myldap"
    assert api.seen["method"] == "PUT"


def test_realm_update_sends_comment_when_provided():
    api = _api()
    realm_update(api, "myldap", comment="Updated comment")
    assert api.seen["data"]["comment"] == "Updated comment"


def test_realm_update_sends_empty_body_when_no_args():
    api = _api()
    realm_update(api, "myldap")
    assert api.seen["data"] == {}


def test_realm_update_rejects_invalid_realm():
    api = _api()
    with pytest.raises(ProximoError):
        realm_update(api, "bad realm!", comment="x")


def test_realm_update_rejects_newline_in_comment():
    api = _api()
    with pytest.raises(ProximoError):
        realm_update(api, "myldap", comment="injected\nnewline")


# ---------------------------------------------------------------------------
# realm_delete — DELETE /access/domains/{realm}
# ---------------------------------------------------------------------------

def test_realm_delete_deletes_correct_path():
    api = _api()
    realm_delete(api, "myldap")
    assert api.seen["path"] == "/access/domains/myldap"
    assert api.seen["method"] == "DELETE"


def test_realm_delete_rejects_invalid_realm():
    api = _api()
    with pytest.raises(ProximoError):
        realm_delete(api, "bad/realm")


# ---------------------------------------------------------------------------
# plan_role_create
# ---------------------------------------------------------------------------

def test_plan_role_create_is_medium_risk():
    p = plan_role_create("MyRole")
    assert p.risk == RISK_MEDIUM


def test_plan_role_create_action_string():
    p = plan_role_create("MyRole")
    assert p.action == "pve_role_create"


def test_plan_role_create_target_contains_roleid():
    p = plan_role_create("MyRole")
    assert "MyRole" in p.target


def test_plan_role_create_blast_mentions_acl_inert():
    p = plan_role_create("MyRole")
    text = " ".join(p.blast_radius).lower()
    assert "acl" in text or "inert" in text or "until" in text


def test_plan_role_create_with_privs_in_blast():
    p = plan_role_create("MyRole", privs="VM.PowerMgmt")
    text = " ".join(p.blast_radius)
    assert "VM.PowerMgmt" in text


def test_plan_role_create_without_privs_notes_empty_role():
    p = plan_role_create("MyRole")
    text = " ".join(p.blast_radius).lower()
    assert "no privilege" in text or "empty" in text


def test_plan_role_create_rejects_invalid_roleid():
    with pytest.raises(ProximoError):
        plan_role_create("bad role!")


# ---------------------------------------------------------------------------
# plan_role_update — risk classification and built-in guard
# ---------------------------------------------------------------------------

def test_plan_role_update_custom_role_is_medium():
    api = _api()
    p = plan_role_update(api, "MyRole")
    assert p.risk == RISK_MEDIUM


def test_plan_role_update_builtin_role_is_high():
    api = _api()
    p = plan_role_update(api, "PVEVMAdmin")
    assert p.risk == RISK_HIGH


def test_plan_role_update_pvesdnadmin_is_builtin_high():
    """PVESDNAdmin is a built-in — must be RISK_HIGH with a built-in warning, not MEDIUM."""
    api = _api()
    p = plan_role_update(api, "PVESDNAdmin")
    assert p.risk == RISK_HIGH
    blast_text = " ".join(p.blast_radius).lower()
    assert "built-in" in blast_text or "may refuse" in blast_text or "system role" in blast_text


def test_plan_role_update_administrator_is_high():
    api = _api()
    p = plan_role_update(api, "Administrator")
    assert p.risk == RISK_HIGH


def test_plan_role_update_builtin_blast_warns_pve_may_refuse():
    api = _api()
    p = plan_role_update(api, "PVEAdmin")
    text = " ".join(p.blast_radius).lower()
    assert "built-in" in text or "may refuse" in text or "system role" in text


def test_plan_role_update_builtin_blast_warns_acl_blast():
    api = _api()
    p = plan_role_update(api, "NoAccess")
    text = " ".join(p.blast_radius).lower()
    assert "acl" in text or "all" in text or "every" in text


def test_plan_role_update_administrator_names_super_role():
    api = _api()
    p = plan_role_update(api, "Administrator")
    text = " ".join(p.blast_radius).lower()
    assert "administrator" in text or "super" in text or "all" in text


def test_plan_role_update_append_true_mentioned_in_blast():
    api = _api()
    p = plan_role_update(api, "MyRole", privs="VM.PowerMgmt", append=True)
    text = " ".join(p.blast_radius).lower()
    assert "append" in text or "add" in text or "added" in text


def test_plan_role_update_append_false_mentions_replace():
    api = _api()
    p = plan_role_update(api, "MyRole", privs="VM.PowerMgmt", append=False)
    text = " ".join(p.blast_radius).lower()
    assert "replace" in text or "replaced" in text


def test_plan_role_update_action_string():
    api = _api()
    p = plan_role_update(api, "MyRole")
    assert p.action == "pve_role_update"


def test_plan_role_update_target_contains_roleid():
    api = _api()
    p = plan_role_update(api, "MyRole")
    assert "MyRole" in p.target


def test_plan_role_update_rejects_invalid_roleid():
    api = _api()
    with pytest.raises(ProximoError):
        plan_role_update(api, "bad role!")


# ---------------------------------------------------------------------------
# plan_role_delete — built-in guard + ACL read honesty
# ---------------------------------------------------------------------------

def test_plan_role_delete_builtin_refuses_with_high():
    api = _acl_api([])
    p = plan_role_delete(api, "Administrator")
    assert p.risk == RISK_HIGH


def test_plan_role_delete_builtin_blast_says_refused():
    api = _acl_api([])
    p = plan_role_delete(api, "Administrator")
    text = " ".join(p.blast_radius).lower()
    assert "refused" in text or "reject" in text or "built-in" in text


def test_plan_role_delete_builtin_pveadmin_refuses():
    api = _acl_api([])
    p = plan_role_delete(api, "PVEAdmin")
    text = " ".join(p.blast_radius).lower()
    assert "refused" in text or "reject" in text


def test_plan_role_delete_custom_no_acl_refs_is_high_zero_count():
    api = _acl_api([])
    p = plan_role_delete(api, "MyCustomRole")
    assert p.risk == RISK_HIGH
    text = " ".join(p.blast_radius).lower()
    assert "0" in text or "unused" in text or "no acl" in text or "0 acl" in text


def test_plan_role_delete_custom_with_acl_refs_names_count():
    entries = [
        {"path": "/vms/100", "ugid": "user@pam", "roleid": "MyCustomRole", "type": "user"},
        {"path": "/vms/200", "ugid": "other@pam", "roleid": "MyCustomRole", "type": "user"},
    ]
    api = _acl_api(entries)
    p = plan_role_delete(api, "MyCustomRole")
    assert p.risk == RISK_HIGH
    text = " ".join(p.blast_radius)
    assert "2" in text


def test_plan_role_delete_acl_read_failure_is_high_and_discloses():
    """Read failure → disclose uncertainty, maintain RISK_HIGH; mirror plan_migrate."""
    api = _acl_api([], raise_on_get=True)
    p = plan_role_delete(api, "MyCustomRole")
    assert p.risk == RISK_HIGH
    text = " ".join(p.blast_radius).lower()
    assert "could not" in text or "unavailable" in text or "absence" in text


def test_plan_role_delete_acl_read_failure_not_claimed_safe():
    api = _acl_api([], raise_on_get=True)
    p = plan_role_delete(api, "MyCustomRole")
    text = " ".join(p.blast_radius + p.risk_reasons).lower()
    assert "not a safety signal" in text or "absence" in text


def test_plan_role_delete_acl_404_is_high_and_discloses():
    """404 on ACL read → disclose plainly; mirror plan_migrate 404 branch."""
    api = _acl_api([], raise_on_get=True, status_code=404)
    p = plan_role_delete(api, "MyCustomRole")
    assert p.risk == RISK_HIGH
    text = " ".join(p.blast_radius).lower()
    assert "could not" in text or "404" in text or "absence" in text


def test_plan_role_delete_action_string():
    api = _acl_api([])
    p = plan_role_delete(api, "MyCustomRole")
    assert p.action == "pve_role_delete"


def test_plan_role_delete_target_contains_roleid():
    api = _acl_api([])
    p = plan_role_delete(api, "MyCustomRole")
    assert "MyCustomRole" in p.target


def test_plan_role_delete_rejects_invalid_roleid():
    api = _acl_api([])
    with pytest.raises(ProximoError):
        plan_role_delete(api, "bad role!")


def test_plan_role_delete_pvepooladmin_is_builtin_refused():
    """PVEPoolAdmin is a real built-in — must get the refuse branch, not 0-refs-unused."""
    api = _acl_api([])
    p = plan_role_delete(api, "PVEPoolAdmin")
    assert p.risk == RISK_HIGH
    blast_text = " ".join(p.blast_radius).lower()
    # Must see the built-in refuse message
    assert "refused" in blast_text or "built-in" in blast_text or "reject" in blast_text
    # Must NOT have followed the "0 acl grants ... unused" custom-role path
    assert "unused" not in blast_text and "0 acl" not in blast_text


def test_plan_role_delete_acl_read_uses_correct_path():
    """The ACL read must hit /access/acl (not some other endpoint)."""
    seen_paths: list[str] = []

    def fake_get(path):
        seen_paths.append(path)
        return []

    api = SimpleNamespace(config=SimpleNamespace(node="pve"), _get=fake_get)
    plan_role_delete(api, "MyCustomRole")
    assert "/access/acl" in seen_paths


# ---------------------------------------------------------------------------
# plan_realm_create
# ---------------------------------------------------------------------------

def test_plan_realm_create_is_medium_risk():
    p = plan_realm_create("myldap", "ldap")
    assert p.risk == RISK_MEDIUM


def test_plan_realm_create_action_string():
    p = plan_realm_create("myldap", "ldap")
    assert p.action == "pve_realm_create"


def test_plan_realm_create_target_contains_realm():
    p = plan_realm_create("myldap", "ldap")
    assert "myldap" in p.target


def test_plan_realm_create_blast_warns_misconfig():
    p = plan_realm_create("myldap", "ldap")
    text = " ".join(p.blast_radius).lower()
    assert "misconfig" in text or "unintended" in text or "misconfigur" in text


def test_plan_realm_create_advises_required_options_when_missing():
    # ldap with no options → soft, non-blocking advisory that type-specific fields go in options
    p = plan_realm_create("myldap", "ldap")
    text = " ".join(p.blast_radius).lower()
    assert "options" in text
    assert "server1" in text  # names a real PVE 9.2-verified required key
    assert p.risk == RISK_MEDIUM  # advisory only — does NOT escalate or block


def test_plan_realm_create_surfaces_supplied_options():
    p = plan_realm_create("myldap", "ldap", options={"server1": "x", "base_dn": "y"})
    text = (p.change + " " + " ".join(p.blast_radius)).lower()
    assert "options" in text
    # advisory-when-missing must NOT fire when options ARE supplied
    assert "will reject this create if they are missing" not in " ".join(p.blast_radius).lower()


def test_plan_realm_create_rejects_invalid_realm():
    with pytest.raises(ProximoError):
        plan_realm_create("bad/realm", "ldap")


def test_plan_realm_create_rejects_invalid_realm_type():
    with pytest.raises(ProximoError):
        plan_realm_create("myrealm", "kerberos")


def test_plan_realm_create_accepts_all_valid_types():
    for t in ("pam", "pve", "ldap", "ad", "openid"):
        p = plan_realm_create(f"testrealm_{t}", t)
        assert p.risk == RISK_MEDIUM


# ---------------------------------------------------------------------------
# plan_realm_update — built-in guard
# ---------------------------------------------------------------------------

def test_plan_realm_update_custom_is_medium():
    api = _api()
    p = plan_realm_update(api, "myldap")
    assert p.risk == RISK_MEDIUM


def test_plan_realm_update_pam_is_high():
    api = _api()
    p = plan_realm_update(api, "pam")
    assert p.risk == RISK_HIGH


def test_plan_realm_update_pve_is_high():
    api = _api()
    p = plan_realm_update(api, "pve")
    assert p.risk == RISK_HIGH


def test_plan_realm_update_pam_blast_warns_lockout():
    api = _api()
    p = plan_realm_update(api, "pam")
    text = " ".join(p.blast_radius).lower()
    assert "lockout" in text or "all login" in text or "breaking" in text or "break" in text or "logins" in text


def test_plan_realm_update_builtin_blast_says_builtin():
    api = _api()
    p = plan_realm_update(api, "pve")
    text = " ".join(p.blast_radius).lower()
    assert "built-in" in text or "system realm" in text


def test_plan_realm_update_action_string():
    api = _api()
    p = plan_realm_update(api, "myldap")
    assert p.action == "pve_realm_update"


def test_plan_realm_update_target_contains_realm():
    api = _api()
    p = plan_realm_update(api, "myldap")
    assert "myldap" in p.target


def test_plan_realm_update_rejects_invalid_realm():
    api = _api()
    with pytest.raises(ProximoError):
        plan_realm_update(api, "bad/realm")


# ---------------------------------------------------------------------------
# plan_realm_delete — built-in guard + user-list read honesty
# ---------------------------------------------------------------------------

def test_plan_realm_delete_builtin_pam_refuses_with_high():
    api = _users_api([])
    p = plan_realm_delete(api, "pam")
    assert p.risk == RISK_HIGH


def test_plan_realm_delete_builtin_pam_blast_mentions_lockout():
    api = _users_api([])
    p = plan_realm_delete(api, "pam")
    text = " ".join(p.blast_radius).lower()
    assert "lockout" in text or "total" in text


def test_plan_realm_delete_builtin_pve_refuses_with_high():
    api = _users_api([])
    p = plan_realm_delete(api, "pve")
    assert p.risk == RISK_HIGH


def test_plan_realm_delete_builtin_blast_says_refused():
    api = _users_api([])
    p = plan_realm_delete(api, "pam")
    text = " ".join(p.blast_radius).lower()
    assert "refused" in text or "reject" in text or "built-in" in text


def test_plan_realm_delete_custom_no_users_is_high_zero_count():
    api = _users_api([])
    p = plan_realm_delete(api, "myldap")
    assert p.risk == RISK_HIGH
    text = " ".join(p.blast_radius).lower()
    assert "0" in text or "unused" in text or "no user" in text or "0 user" in text


def test_plan_realm_delete_custom_with_users_names_count():
    users = [
        {"userid": "alice@myldap"},
        {"userid": "bob@myldap"},
        {"userid": "carol@pam"},  # different realm — should NOT count
    ]
    api = _users_api(users)
    p = plan_realm_delete(api, "myldap")
    assert p.risk == RISK_HIGH
    text = " ".join(p.blast_radius)
    assert "2" in text


def test_plan_realm_delete_does_not_count_other_realm_users():
    """Users from other realms must not be counted in the blast."""
    users = [
        {"userid": "alice@pam"},
        {"userid": "bob@pve"},
    ]
    api = _users_api(users)
    p = plan_realm_delete(api, "myldap")
    text = " ".join(p.blast_radius)
    # Should show 0 users for myldap
    assert "0" in text or "unused" in text


def test_plan_realm_delete_user_read_failure_is_high_and_discloses():
    """Read failure → disclose uncertainty, maintain RISK_HIGH; mirror plan_migrate."""
    api = _users_api([], raise_on_get=True)
    p = plan_realm_delete(api, "myldap")
    assert p.risk == RISK_HIGH
    text = " ".join(p.blast_radius).lower()
    assert "could not" in text or "unavailable" in text or "absence" in text


def test_plan_realm_delete_user_read_failure_not_claimed_safe():
    api = _users_api([], raise_on_get=True)
    p = plan_realm_delete(api, "myldap")
    text = " ".join(p.blast_radius + p.risk_reasons).lower()
    assert "not a safety signal" in text or "absence" in text


def test_plan_realm_delete_user_read_404_is_high_and_discloses():
    """404 on user-list read → disclose plainly."""
    api = _users_api([], raise_on_get=True, status_code=404)
    p = plan_realm_delete(api, "myldap")
    assert p.risk == RISK_HIGH
    text = " ".join(p.blast_radius).lower()
    assert "could not" in text or "404" in text or "absence" in text


def test_plan_realm_delete_action_string():
    api = _users_api([])
    p = plan_realm_delete(api, "myldap")
    assert p.action == "pve_realm_delete"


def test_plan_realm_delete_target_contains_realm():
    api = _users_api([])
    p = plan_realm_delete(api, "myldap")
    assert "myldap" in p.target


def test_plan_realm_delete_user_read_uses_correct_path():
    """The user-list read must hit /access/users."""
    seen_paths: list[str] = []

    def fake_get(path):
        seen_paths.append(path)
        return []

    api = SimpleNamespace(config=SimpleNamespace(node="pve"), _get=fake_get)
    plan_realm_delete(api, "myldap")
    assert "/access/users" in seen_paths


def test_plan_realm_delete_rejects_invalid_realm():
    api = _users_api([])
    with pytest.raises(ProximoError):
        plan_realm_delete(api, "bad/realm")


def test_plan_realm_delete_blast_mentions_irreversible():
    api = _users_api([])
    p = plan_realm_delete(api, "myldap")
    text = " ".join(p.blast_radius + p.risk_reasons).lower()
    assert "irreversible" in text or "permanent" in text or "reconfigur" in text


# ---------------------------------------------------------------------------
# TFA read-only guard — no mutation functions must exist in the module
# ---------------------------------------------------------------------------

def test_tfa_scope_delete_only_no_enrollment():
    """TFA scope (2026-06-14): tfa_delete is intentionally exposed; ENROLLMENT/create/update are
    NOT — enrollment is an interactive TOTP/WebAuthn challenge-response, deliberately out of scope.
    """
    import proximo.access_governance as _mod

    names = {n for n in dir(_mod) if "tfa" in n.lower()}
    # delete IS in scope now
    assert "tfa_delete" in names
    # enrollment / create / update / revoke must NOT have landed
    forbidden = {"create", "update", "revoke", "enroll"}
    leaked = [n for n in names if any(v in n.lower() for v in forbidden)]
    assert leaked == [], f"unexpected TFA mutation(s) — only delete is in scope: {leaked}"


# ===========================================================================
# TFA — tfa_get (read) / tfa_delete (mutation)
# Grounded against live PVE 9.1.7 schema (2026-06-14):
#   GET    /access/tfa/{userid}            list a user's TFA entries
#   GET    /access/tfa/{userid}/{id}        fetch one entry
#   DELETE /access/tfa/{userid}/{id}        {password?}   delete a TFA factor
# Enrollment (POST) is intentionally OUT — it is an interactive TOTP/WebAuthn challenge.
# Deleting a factor WEAKENS account security (RISK_HIGH). `password` is a SECRET — it flows to
# the API but must NOT appear in plan/audit output.
# ===========================================================================


def test_tfa_get_lists_user_entries():
    api = _api()
    tfa_get(api, "root@pam")
    assert api.seen["method"] == "GET"
    assert api.seen["path"] == "/access/tfa/root@pam"


def test_tfa_get_specific_entry():
    api = _api()
    tfa_get(api, "root@pam", "totp:LABEL")
    assert api.seen["path"] == "/access/tfa/root@pam/totp:LABEL"


def test_tfa_get_rejects_bad_userid():
    api = _api()
    with pytest.raises(ProximoError):
        tfa_get(api, "bad userid!!")


def test_tfa_get_rejects_bad_id():
    api = _api()
    with pytest.raises(ProximoError):
        tfa_get(api, "root@pam", "../../x")


def test_tfa_delete_path():
    api = _api()
    tfa_delete(api, "root@pam", "totp:LABEL")
    assert api.seen["method"] == "DELETE"
    assert api.seen["path"] == "/access/tfa/root@pam/totp:LABEL"


def test_tfa_delete_includes_password_when_given():
    api = _api()
    tfa_delete(api, "root@pam", "totp:LABEL", password="secret")
    assert api.seen["params"]["password"] == "secret"


def test_tfa_delete_omits_password_when_absent():
    api = _api()
    tfa_delete(api, "root@pam", "totp:LABEL")
    assert "password" not in (api.seen["params"] or {})


def test_tfa_delete_rejects_traversal_id():
    api = _api()
    with pytest.raises(ProximoError):
        tfa_delete(api, "root@pam", "../../zones/x")


def test_tfa_delete_request_failure_does_not_leak_password():
    """The acting user's password travels as a DELETE query param (backends.py sends `params`
    as the httpx query string). A request failure there (e.g. the live-verified 403 under API
    token auth) must never surface the raw underlying exception — httpx's HTTPStatusError embeds
    the full request URL, including the query string, in str(exception)."""
    secret = "super-secret-password"  # noqa: S105 — test sentinel, not a real credential

    def fake_delete(path, params=None):
        raise RuntimeError(f"Client error '403 Forbidden' for url 'https://pve.example/{path}?password={secret}'")

    api = SimpleNamespace(config=SimpleNamespace(node="pve"), _delete=fake_delete)
    with pytest.raises(ProximoError) as exc_info:
        tfa_delete(api, "root@pam", "totp:LABEL", password=secret)
    assert secret not in str(exc_info.value)
    assert "RuntimeError" in str(exc_info.value)


def test_plan_tfa_delete_is_high_and_reads_current():
    entries = [{"id": "totp:LABEL", "description": "phone"}, {"id": "recovery"}]
    api = SimpleNamespace(config=SimpleNamespace(node="pve"), _get=lambda p: entries)
    plan = plan_tfa_delete(api, "root@pam", "totp:LABEL")
    assert plan.risk == RISK_HIGH
    assert any("factor" in b.lower() for b in plan.blast_radius)


def test_plan_tfa_delete_does_not_leak_password():
    # plan never takes a password; ensure no secret-shaped field appears
    api = SimpleNamespace(config=SimpleNamespace(node="pve"), _get=lambda p: [])
    plan = plan_tfa_delete(api, "root@pam", "totp:LABEL")
    blob = (plan.change + " " + " ".join(plan.blast_radius)).lower()
    assert "password" not in blob


def test_plan_tfa_delete_read_failure_discloses_uncertainty():
    # module contract: read failure -> disclose uncertainty + maintain RISK_HIGH (sibling pattern)
    api = SimpleNamespace(
        config=SimpleNamespace(node="pve"),
        _get=lambda p: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    plan = plan_tfa_delete(api, "root@pam", "totp:LABEL")
    assert plan.risk == RISK_HIGH
    assert any("could not read" in b.lower() or "not a safety signal" in b.lower()
               for b in plan.blast_radius)


# ---------------------------------------------------------------------------
# Blast-radius coverage (rank 7): role_update / realm_update name the principals
# they re-privilege / lock out — mirroring their delete siblings.
# Spec: docs/specs/2026-06-19-disk-move-blast-radius.md (internal-only) (coverage push)
# ---------------------------------------------------------------------------

def test_plan_role_update_names_affected_acl_grants():
    from proximo.access_governance import plan_role_update
    api = _acl_api([
        {"ugid": "alice@pve", "path": "/vms/100", "roleid": "CustomRole"},
        {"ugid": "bob@pve", "path": "/", "roleid": "OtherRole"},
    ])
    p = plan_role_update(api, "CustomRole", privs="VM.Console")
    assert any(a["principal"] == "alice@pve" and a["path"] == "/vms/100" for a in p.affected)
    assert all(a.get("roleid") == "CustomRole" for a in p.affected)   # only the matching role
    assert p.complete is True


def test_plan_role_update_acl_read_failure_is_incomplete():
    from proximo.access_governance import plan_role_update
    api = _acl_api([], raise_on_get=True)
    p = plan_role_update(api, "CustomRole", privs="VM.Console")
    assert p.complete is False
    assert any("could not" in line.lower() for line in p.blast_radius)


def test_plan_realm_update_names_affected_users():
    from proximo.access_governance import plan_realm_update
    api = _users_api([{"userid": "alice@corp"}, {"userid": "bob@pve"}])
    p = plan_realm_update(api, "corp", comment="x")
    assert any(a["userid"] == "alice@corp" for a in p.affected)
    assert all(a["userid"].endswith("@corp") for a in p.affected)
    assert p.complete is True


def test_plan_realm_update_users_read_failure_is_incomplete():
    from proximo.access_governance import plan_realm_update
    api = _users_api([], raise_on_get=True)
    p = plan_realm_update(api, "corp", comment="x")
    assert p.complete is False
