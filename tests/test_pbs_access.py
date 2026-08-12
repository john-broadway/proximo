"""PBS access governance plane tests (Wave 2a identity core + Wave 2b realms/TFA, full-surface
campaign) — fully mocked, no live PBS.

Mirrors test_pbs_config.py / test_access.py style:
- _api() is a recording SimpleNamespace fake for backend-function tests (path/verb/payload shape).
- Validator-rejection tests use pytest.raises(ProximoError).
- Plan tests verify honest risk ratings, blast-radius content, and CAPTURE-or-declare behavior.
- Secret tests: user 'password' (create-only) is unconditionally redacted; token 'value'/'secret'
  never appear in ANY plan factory (pbs_access.py's plan_token_create/plan_token_update don't even
  accept a secret-bearing parameter) — the end-to-end never-in-ledger promise is held at the
  wrapper/confirm-sweep layer (tests/test_confirm_sweep_pbs.py), not here.

Covers (Wave 2a): validators (userid/token-name/auth-id/group id/ACL path/role id/digest);
backend functions for all 14 ops (7 read, 7 mutation); plan factories (risk ratings, blast-radius
content, CAPTURE-or-declare); module structure.

Covers (Wave 2b): validators (tfa id, tfa type); realm backend functions for AD/LDAP/OpenID (5
ops each) + PAM/PBS (2 ops each) — exact path/verb/payload; TFA backend functions (9 ops); realm
+ TFA plan factories (RISK_MEDIUM across the board per the wave's own risk table); the
client-key redaction helper.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from proximo.backends import ProximoError
from proximo.pbs_access import (
    _check_acl_path,
    _check_authid,
    _check_digest,
    _check_groupid,
    _check_roleid,
    _check_tfa_id,
    _check_tfa_type,
    _check_tokenname,
    _check_userid,
    _client_key_redacted_detail,
    _password_redacted_detail,
    acl_get,
    acl_update,
    permissions_get,
    plan_acl_update,
    plan_realm_ad_create,
    plan_realm_ad_delete,
    plan_realm_ad_update,
    plan_realm_ldap_create,
    plan_realm_ldap_delete,
    plan_realm_ldap_update,
    plan_realm_openid_create,
    plan_realm_openid_delete,
    plan_realm_openid_update,
    plan_realm_pam_set,
    plan_realm_pbs_set,
    plan_tfa_add,
    plan_tfa_delete,
    plan_tfa_unlock,
    plan_tfa_update,
    plan_tfa_webauthn_set,
    plan_token_create,
    plan_token_delete,
    plan_token_update,
    plan_user_create,
    plan_user_delete,
    plan_user_update,
    realm_ad_create,
    realm_ad_delete,
    realm_ad_get,
    realm_ad_list,
    realm_ad_update,
    realm_ldap_create,
    realm_ldap_delete,
    realm_ldap_get,
    realm_ldap_list,
    realm_ldap_update,
    realm_openid_create,
    realm_openid_delete,
    realm_openid_get,
    realm_openid_list,
    realm_openid_update,
    realm_pam_get,
    realm_pam_set,
    realm_pbs_get,
    realm_pbs_set,
    roles_list,
    tfa_add,
    tfa_delete,
    tfa_entry_get,
    tfa_list,
    tfa_unlock,
    tfa_update,
    tfa_user_get,
    tfa_webauthn_get,
    tfa_webauthn_set,
    token_create,
    token_delete,
    token_update,
    user_create,
    user_delete,
    user_get,
    user_token_get,
    user_tokens_list,
    user_update,
    users_list,
)
from proximo.planning import RISK_HIGH, RISK_MEDIUM

# ---------------------------------------------------------------------------
# Fake API
# ---------------------------------------------------------------------------

def _api(get_return=None, raise_on_get=None) -> SimpleNamespace:
    """Minimal PBS API fake recording _get/_post/_put/_delete calls."""
    seen: dict = {}

    def fake_get(path, params=None):
        seen["get_path"] = path
        seen["get_params"] = params
        if raise_on_get is not None:
            raise raise_on_get
        return get_return

    def fake_post(path, data=None):
        seen["post_path"] = path
        seen["post_data"] = data
        return {"tokenid": "test@pbs!tok", "value": "FAKE-PBS-SECRET-sentinel"}

    def fake_put(path, data=None):
        seen["put_path"] = path
        seen["put_data"] = data
        return None

    def fake_delete(path, params=None):
        seen["delete_path"] = path
        seen["delete_params"] = params
        return None

    return SimpleNamespace(
        _get=fake_get, _post=fake_post, _put=fake_put, _delete=fake_delete, seen=seen,
    )


# ---------------------------------------------------------------------------
# Module structure
# ---------------------------------------------------------------------------

def test_module_docstring_names_both_secret_classes_and_exclusion():
    import proximo.pbs_access as m
    doc = m.__doc__ or ""
    assert "password" in doc.lower()
    assert "value" in doc or "secret" in doc.lower()
    assert "EXCLUSION" in doc


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

class TestCheckUserid:
    def test_valid(self):
        assert _check_userid("automation@pbs") == "automation@pbs"

    def test_valid_permissive_user_part(self):
        # PBS's own regex allows almost anything in the user part except whitespace/colon/
        # slash/control chars (unlike PVE's tighter alnum/._- charset).
        assert _check_userid("weird+user.name@pbs") == "weird+user.name@pbs"

    def test_rejects_missing_realm(self):
        with pytest.raises(ProximoError):
            _check_userid("noRealm")

    def test_rejects_whitespace(self):
        with pytest.raises(ProximoError):
            _check_userid("bad user@pbs")

    def test_rejects_colon(self):
        with pytest.raises(ProximoError):
            _check_userid("bad:user@pbs")

    def test_rejects_traversal(self):
        with pytest.raises(ProximoError, match="traversal"):
            _check_userid("..@pbs")


class TestCheckTokenname:
    def test_valid(self):
        assert _check_tokenname("ci-token") == "ci-token"

    def test_rejects_bang(self):
        with pytest.raises(ProximoError):
            _check_tokenname("user@pbs!name")

    def test_rejects_traversal(self):
        # ".." is already rejected by the charset regex (a token-name must start with a
        # letter/digit/underscore) before the dedicated traversal guard is even reached —
        # unlike userid, where the traversal guard is load-bearing (see TestCheckUserid).
        with pytest.raises(ProximoError):
            _check_tokenname("..")


class TestCheckAuthid:
    def test_valid_bare_userid(self):
        assert _check_authid("automation@pbs") == "automation@pbs"

    def test_valid_full_tokenid(self):
        assert _check_authid("automation@pbs!ci-token") == "automation@pbs!ci-token"

    def test_rejects_malformed(self):
        with pytest.raises(ProximoError):
            _check_authid("not-an-authid")


class TestCheckGroupid:
    def test_valid(self):
        assert _check_groupid("backup-admins") == "backup-admins"

    def test_rejects_whitespace(self):
        with pytest.raises(ProximoError):
            _check_groupid("bad group")


class TestCheckAclPath:
    def test_root(self):
        assert _check_acl_path("/") == "/"

    def test_segment(self):
        assert _check_acl_path("/datastore/ds1") == "/datastore/ds1"

    def test_rejects_traversal(self):
        with pytest.raises(ProximoError, match="traversal"):
            _check_acl_path("/datastore/..")

    def test_rejects_trailing_slash(self):
        with pytest.raises(ProximoError):
            _check_acl_path("/datastore/")


class TestCheckRoleid:
    def test_valid(self):
        assert _check_roleid("DatastoreAdmin") == "DatastoreAdmin"

    def test_rejects_empty(self):
        with pytest.raises(ProximoError):
            _check_roleid("")

    def test_rejects_special_chars(self):
        with pytest.raises(ProximoError):
            _check_roleid("Bad;Role")


class TestCheckDigest:
    def test_none_passthrough(self):
        assert _check_digest(None) is None

    def test_valid(self):
        d = "a" * 64
        assert _check_digest(d) == d

    def test_rejects_wrong_length(self):
        with pytest.raises(ProximoError):
            _check_digest("abc123")

    def test_rejects_uppercase(self):
        with pytest.raises(ProximoError):
            _check_digest("A" * 64)

    def test_rejects_trailing_newline(self):
        # A11 tightening: the retired per-module copy .strip()ped before matching, which
        # re-admitted the trailing newline the \Z anchor exists to refuse.
        with pytest.raises(ProximoError):
            _check_digest("a" * 64 + "\n")


def test_password_redacted_detail_only_when_supplied():
    assert _password_redacted_detail(None) == {}
    assert _password_redacted_detail("real-secret") == {"password": "[redacted]"}


# ---------------------------------------------------------------------------
# Backend functions — users
# ---------------------------------------------------------------------------

class TestUsersList:
    def test_default_no_params(self):
        api = _api(get_return=[])
        users_list(api)
        assert api.seen["get_path"] == "/access/users"
        assert api.seen["get_params"] is None

    def test_include_tokens_sends_param(self):
        api = _api(get_return=[])
        users_list(api, include_tokens=True)
        assert api.seen["get_params"] == {"include_tokens": True}

    def test_returns_list_on_none(self):
        api = _api(get_return=None)
        assert users_list(api) == []


class TestUserGet:
    def test_path(self):
        api = _api(get_return={"userid": "a@pbs"})
        user_get(api, "a@pbs")
        assert api.seen["get_path"] == "/access/users/a@pbs"

    def test_invalid_userid_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            user_get(api, "bad user")


class TestUserCreate:
    def test_minimal_payload(self):
        api = _api()
        user_create(api, "newuser@pbs")
        assert api.seen["post_path"] == "/access/users"
        assert api.seen["post_data"] == {"userid": "newuser@pbs"}

    def test_full_payload_with_password(self):
        api = _api()
        user_create(
            api, "newuser@pbs", comment="c", email="e@x.com", enable=True, expire=123,
            firstname="F", lastname="L", password="s3cr3t-not-real",
        )
        assert api.seen["post_data"] == {
            "userid": "newuser@pbs", "comment": "c", "email": "e@x.com", "enable": True,
            "expire": 123, "firstname": "F", "lastname": "L", "password": "s3cr3t-not-real",
        }

    def test_password_omitted_when_none(self):
        api = _api()
        user_create(api, "newuser@pbs")
        assert "password" not in api.seen["post_data"]


class TestUserUpdate:
    def test_partial_payload(self):
        api = _api()
        user_update(api, "u@pbs", comment="new comment")
        assert api.seen["put_path"] == "/access/users/u@pbs"
        assert api.seen["put_data"] == {"comment": "new comment"}

    def test_delete_props_comma_joined(self):
        api = _api()
        user_update(api, "u@pbs", delete_props=["comment", "email"])
        assert api.seen["put_data"]["delete"] == "comment,email"

    def test_digest_forwarded(self):
        api = _api()
        d = "b" * 64
        user_update(api, "u@pbs", comment="x", digest=d)
        assert api.seen["put_data"]["digest"] == d

    def test_no_password_param_exists(self):
        import inspect
        assert "password" not in inspect.signature(user_update).parameters


class TestUserDelete:
    def test_path_no_params(self):
        api = _api()
        user_delete(api, "gone@pbs")
        assert api.seen["delete_path"] == "/access/users/gone@pbs"
        assert api.seen["delete_params"] is None

    def test_digest_forwarded(self):
        api = _api()
        d = "c" * 64
        user_delete(api, "gone@pbs", digest=d)
        assert api.seen["delete_params"] == {"digest": d}


# ---------------------------------------------------------------------------
# Backend functions — tokens
# ---------------------------------------------------------------------------

class TestUserTokensList:
    def test_path(self):
        api = _api(get_return=[])
        user_tokens_list(api, "u@pbs")
        assert api.seen["get_path"] == "/access/users/u@pbs/token"


class TestUserTokenGet:
    def test_path(self):
        api = _api(get_return={})
        user_token_get(api, "u@pbs", "mytoken")
        assert api.seen["get_path"] == "/access/users/u@pbs/token/mytoken"


class TestTokenCreate:
    def test_minimal(self):
        api = _api()
        result = token_create(api, "u@pbs", "mytoken")
        assert api.seen["post_path"] == "/access/users/u@pbs/token/mytoken"
        assert api.seen["post_data"] is None
        assert result["value"] == "FAKE-PBS-SECRET-sentinel"

    def test_full_payload(self):
        api = _api()
        token_create(api, "u@pbs", "mytoken", comment="c", enable=False, expire=999)
        assert api.seen["post_data"] == {"comment": "c", "enable": False, "expire": 999}

    def test_no_privsep_param_exists(self):
        # PBS's schema has NO privsep-equivalent on token create (unlike PVE) — never invent one.
        import inspect
        assert "privsep" not in inspect.signature(token_create).parameters


class TestTokenUpdate:
    def test_minimal(self):
        api = _api()
        token_update(api, "u@pbs", "mytoken")
        assert api.seen["put_path"] == "/access/users/u@pbs/token/mytoken"
        assert api.seen["put_data"] is None

    def test_regenerate_sends_true(self):
        api = _api()
        token_update(api, "u@pbs", "mytoken", regenerate=True)
        assert api.seen["put_data"] == {"regenerate": True}

    def test_delete_props_comma_joined(self):
        api = _api()
        token_update(api, "u@pbs", "mytoken", delete_props=["comment"])
        assert api.seen["put_data"]["delete"] == "comment"


class TestTokenDelete:
    def test_path(self):
        api = _api()
        token_delete(api, "u@pbs", "mytoken")
        assert api.seen["delete_path"] == "/access/users/u@pbs/token/mytoken"
        assert api.seen["delete_params"] is None


# ---------------------------------------------------------------------------
# Backend functions — ACL / roles / permissions
# ---------------------------------------------------------------------------

class TestAclGet:
    def test_no_params(self):
        api = _api(get_return=[])
        acl_get(api)
        assert api.seen["get_path"] == "/access/acl"
        assert api.seen["get_params"] is None

    def test_path_and_exact(self):
        api = _api(get_return=[])
        acl_get(api, path="/datastore/ds1", exact=True)
        assert api.seen["get_params"] == {"path": "/datastore/ds1", "exact": True}


class TestAclUpdate:
    def test_grant_with_auth_id(self):
        api = _api()
        acl_update(api, "/datastore/ds1", "DatastoreAdmin", auth_id="alice@pbs")
        assert api.seen["put_path"] == "/access/acl"
        assert api.seen["put_data"] == {
            "path": "/datastore/ds1", "role": "DatastoreAdmin", "auth-id": "alice@pbs",
        }

    def test_grant_with_group(self):
        api = _api()
        acl_update(api, "/datastore/ds1", "DatastoreAudit", group="auditors")
        assert api.seen["put_data"] == {
            "path": "/datastore/ds1", "role": "DatastoreAudit", "group": "auditors",
        }

    def test_revoke_sends_delete_true(self):
        api = _api()
        acl_update(api, "/", "Admin", auth_id="alice@pbs", delete=True)
        assert api.seen["put_data"]["delete"] is True

    def test_propagate_forwarded(self):
        api = _api()
        acl_update(api, "/", "Admin", auth_id="alice@pbs", propagate=False)
        assert api.seen["put_data"]["propagate"] is False

    def test_requires_exactly_one_principal_neither(self):
        api = _api()
        with pytest.raises(ProximoError, match="exactly one"):
            acl_update(api, "/", "Admin")

    def test_requires_exactly_one_principal_both(self):
        api = _api()
        with pytest.raises(ProximoError, match="exactly one"):
            acl_update(api, "/", "Admin", auth_id="alice@pbs", group="auditors")


class TestRolesList:
    def test_no_params(self):
        api = _api(get_return=[])
        roles_list(api)
        assert api.seen["get_path"] == "/access/roles"


class TestPermissionsGet:
    def test_no_params(self):
        api = _api(get_return={})
        permissions_get(api)
        assert api.seen["get_path"] == "/access/permissions"
        assert api.seen["get_params"] is None

    def test_auth_id_and_path(self):
        api = _api(get_return={})
        permissions_get(api, auth_id="alice@pbs", path="/datastore/ds1")
        assert api.seen["get_params"] == {"auth-id": "alice@pbs", "path": "/datastore/ds1"}


# ---------------------------------------------------------------------------
# Plan factories
# ---------------------------------------------------------------------------

class TestPlanUserCreate:
    def test_risk_medium(self):
        p = plan_user_create("newuser@pbs")
        assert p.risk == RISK_MEDIUM
        assert p.action == "pbs_user_create"

    def test_no_password_param_exists(self):
        import inspect
        assert "password" not in inspect.signature(plan_user_create).parameters


class TestPlanUserUpdate:
    def test_risk_medium_and_captures_current(self):
        api = _api(get_return={"userid": "u@pbs", "comment": "old"})
        p = plan_user_update(api, "u@pbs", comment="new")
        assert p.risk == RISK_MEDIUM
        assert p.current == {"userid": "u@pbs", "comment": "old"}
        assert p.complete is True

    def test_capture_failure_sets_incomplete(self):
        api = _api(raise_on_get=RuntimeError("boom"))
        p = plan_user_update(api, "u@pbs", comment="new")
        assert p.complete is False

    def test_enable_false_flagged_in_blast(self):
        api = _api(get_return={})
        p = plan_user_update(api, "u@pbs", enable=False)
        assert any("login" in line.lower() for line in p.blast_radius)


class TestPlanUserDelete:
    def test_risk_medium(self):
        api = _api(get_return={"userid": "u@pbs"})
        p = plan_user_delete(api, "u@pbs")
        assert p.risk == RISK_MEDIUM

    def test_blast_names_permanence(self):
        api = _api(get_return={"userid": "u@pbs"})
        p = plan_user_delete(api, "u@pbs")
        joined = " ".join(p.blast_radius).lower()
        assert "permanent" in joined or "no undo" in joined or "irreversib" in joined


class TestPlanTokenCreate:
    def test_risk_medium(self):
        p = plan_token_create("u@pbs", "mytoken")
        assert p.risk == RISK_MEDIUM

    def test_no_secret_param_exists(self):
        import inspect
        params = inspect.signature(plan_token_create).parameters
        assert "value" not in params and "secret" not in params

    def test_blast_never_expires_note(self):
        p = plan_token_create("u@pbs", "mytoken")
        assert any("never expires" in line.lower() or "no expiration" in line.lower()
                   for line in p.blast_radius)

    def test_ttl_shaped_expire_warns(self):
        p = plan_token_create("u@pbs", "mytoken", expire=86400)
        joined = " ".join(p.blast_radius).lower()
        assert "ttl" in joined or "duration" in joined or "already" in joined

    def test_plan_dict_never_contains_secret_shaped_value(self):
        p = plan_token_create("u@pbs", "mytoken", comment="CI pipeline token")
        d = p.as_dict()
        # The plan never had a secret to leak in the first place (PURE, no API call) — this
        # locks that structural guarantee rather than grepping for a specific fake value.
        assert "value" not in d and "secret" not in d


class TestPlanTokenUpdate:
    def test_risk_medium_default(self):
        p = plan_token_update("u@pbs", "mytoken", comment="x")
        assert p.risk == RISK_MEDIUM

    def test_risk_high_on_regenerate(self):
        p = plan_token_update("u@pbs", "mytoken", regenerate=True)
        assert p.risk == RISK_HIGH

    def test_regenerate_blast_names_new_secret(self):
        p = plan_token_update("u@pbs", "mytoken", regenerate=True)
        joined = " ".join(p.blast_radius).lower()
        assert "secret" in joined
        assert "invalidat" in joined or "immediately" in joined


class TestPlanTokenDelete:
    def test_risk_medium(self):
        p = plan_token_delete("u@pbs", "mytoken")
        assert p.risk == RISK_MEDIUM

    def test_blast_names_permanence(self):
        p = plan_token_delete("u@pbs", "mytoken")
        joined = " ".join(p.blast_radius).lower()
        assert "irreversib" in joined or "permanent" in joined or "no undo" in joined


class TestPlanAclUpdate:
    def test_risk_always_high_grant(self):
        api = _api(get_return=[])
        p = plan_acl_update(api, "/datastore/ds1", "DatastoreAdmin", auth_id="alice@pbs")
        assert p.risk == RISK_HIGH

    def test_risk_always_high_revoke(self):
        api = _api(get_return=[])
        p = plan_acl_update(api, "/", "Admin", auth_id="alice@pbs", delete=True)
        assert p.risk == RISK_HIGH

    def test_blast_names_grants_or_revokes_authority(self):
        api = _api(get_return=[])
        p_grant = plan_acl_update(api, "/datastore/ds1", "DatastoreAdmin", auth_id="alice@pbs")
        joined = " ".join(p_grant.blast_radius).lower()
        assert "grant" in joined or "authority" in joined or "privilege" in joined

        p_revoke = plan_acl_update(api, "/", "Admin", auth_id="alice@pbs", delete=True)
        joined_r = " ".join(p_revoke.blast_radius).lower()
        assert "revoke" in joined_r or "remove" in joined_r

    def test_requires_exactly_one_principal(self):
        api = _api(get_return=[])
        with pytest.raises(ProximoError, match="exactly one"):
            plan_acl_update(api, "/", "Admin")

    def test_capture_failure_sets_incomplete(self):
        api = _api(raise_on_get=RuntimeError("boom"))
        p = plan_acl_update(api, "/", "Admin", auth_id="alice@pbs")
        assert p.complete is False


# ===========================================================================
# Wave 2b — PBS realms (AD/LDAP/OpenID/PAM/PBS) + TFA
# ===========================================================================

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

class TestCheckTfaId:
    def test_valid(self):
        assert _check_tfa_id("totp-0") == "totp-0"

    def test_valid_with_colon(self):
        assert _check_tfa_id("webauthn:0") == "webauthn:0"

    def test_rejects_leading_symbol(self):
        with pytest.raises(ProximoError):
            _check_tfa_id(":bad")

    def test_rejects_traversal(self):
        # ".." is already rejected by the charset regex (must start with a letter/digit) before
        # the dedicated traversal guard is even reached — same shape as _check_tokenname's
        # identical case above.
        with pytest.raises(ProximoError):
            _check_tfa_id("..")


class TestCheckTfaType:
    def test_valid_each(self):
        for t in ("totp", "u2f", "webauthn", "recovery", "yubico"):
            assert _check_tfa_type(t) == t

    def test_rejects_unknown(self):
        with pytest.raises(ProximoError):
            _check_tfa_type("bogus")


def test_client_key_redacted_detail_only_when_supplied():
    assert _client_key_redacted_detail(None) == {}
    assert _client_key_redacted_detail("real-secret") == {"client-key": "[redacted]"}


# ---------------------------------------------------------------------------
# Backend functions — realms: AD
# ---------------------------------------------------------------------------

class TestRealmAdList:
    def test_path(self):
        api = _api(get_return=[])
        realm_ad_list(api)
        assert api.seen["get_path"] == "/config/access/ad"


class TestRealmAdGet:
    def test_path(self):
        api = _api(get_return={})
        realm_ad_get(api, "corp")
        assert api.seen["get_path"] == "/config/access/ad/corp"


class TestRealmAdCreate:
    def test_minimal_payload(self):
        api = _api()
        realm_ad_create(api, "corp", "ad1.example.com")
        assert api.seen["post_path"] == "/config/access/ad"
        assert api.seen["post_data"] == {"realm": "corp", "server1": "ad1.example.com"}

    def test_full_payload_with_password(self):
        api = _api()
        realm_ad_create(
            api, "corp", "ad1.example.com", base_dn="dc=corp", bind_dn="cn=svc",
            capath="/etc/ssl/certs", comment="c", default=True, filter="(f)", mode="ldaps",
            password="bindpass-not-real", port=636, server2="ad2.example.com",
            sync_attributes="email=mail", sync_defaults_options="enable-new=1",
            user_classes="person,user", verify=True,
        )
        assert api.seen["post_data"] == {
            "realm": "corp", "server1": "ad1.example.com", "base-dn": "dc=corp",
            "bind-dn": "cn=svc", "capath": "/etc/ssl/certs", "comment": "c", "default": True,
            "filter": "(f)", "mode": "ldaps", "port": 636, "server2": "ad2.example.com",
            "sync-attributes": "email=mail", "sync-defaults-options": "enable-new=1",
            "user-classes": "person,user", "verify": True, "password": "bindpass-not-real",
        }

    def test_password_omitted_when_none(self):
        api = _api()
        realm_ad_create(api, "corp", "ad1.example.com")
        assert "password" not in api.seen["post_data"]


class TestRealmAdUpdate:
    def test_partial_payload(self):
        api = _api()
        realm_ad_update(api, "corp", comment="new")
        assert api.seen["put_path"] == "/config/access/ad/corp"
        assert api.seen["put_data"] == {"comment": "new"}

    def test_delete_props_comma_joined(self):
        api = _api()
        realm_ad_update(api, "corp", delete_props=["comment", "bind-dn"])
        assert api.seen["put_data"]["delete"] == "comment,bind-dn"

    def test_digest_forwarded(self):
        api = _api()
        d = "a" * 64
        realm_ad_update(api, "corp", comment="x", digest=d)
        assert api.seen["put_data"]["digest"] == d

    def test_no_realm_key_in_body(self):
        api = _api()
        realm_ad_update(api, "corp", comment="x")
        assert "realm" not in api.seen["put_data"]


class TestRealmAdDelete:
    def test_path_no_params(self):
        api = _api()
        realm_ad_delete(api, "corp")
        assert api.seen["delete_path"] == "/config/access/ad/corp"
        assert api.seen["delete_params"] is None

    def test_digest_forwarded(self):
        api = _api()
        d = "b" * 64
        realm_ad_delete(api, "corp", digest=d)
        assert api.seen["delete_params"] == {"digest": d}


# ---------------------------------------------------------------------------
# Backend functions — realms: LDAP (base_dn/user_attr REQUIRED on create)
# ---------------------------------------------------------------------------

class TestRealmLdapList:
    def test_path(self):
        api = _api(get_return=[])
        realm_ldap_list(api)
        assert api.seen["get_path"] == "/config/access/ldap"


class TestRealmLdapGet:
    def test_path(self):
        api = _api(get_return={})
        realm_ldap_get(api, "corp")
        assert api.seen["get_path"] == "/config/access/ldap/corp"


class TestRealmLdapCreate:
    def test_minimal_payload_includes_required_fields(self):
        api = _api()
        realm_ldap_create(api, "corp", "ldap1.example.com", "dc=corp", "uid")
        assert api.seen["post_path"] == "/config/access/ldap"
        assert api.seen["post_data"] == {
            "realm": "corp", "server1": "ldap1.example.com",
            "user-attr": "uid", "base-dn": "dc=corp",
        }

    def test_password_redaction_never_applies_here_only_at_wrapper(self):
        # The backend op itself forwards the real password — redaction is a server-layer
        # concern (tools/pbs_access.py), not this function's job.
        api = _api()
        realm_ldap_create(api, "corp", "s1", "dc=corp", "uid", password="realpass-not-real")
        assert api.seen["post_data"]["password"] == "realpass-not-real"


class TestRealmLdapUpdate:
    def test_partial_payload_all_optional(self):
        api = _api()
        realm_ldap_update(api, "corp", comment="new")
        assert api.seen["put_path"] == "/config/access/ldap/corp"
        assert api.seen["put_data"] == {"comment": "new"}

    def test_user_attr_and_base_dn_optional_here(self):
        api = _api()
        realm_ldap_update(api, "corp", base_dn="dc=new", user_attr="sAMAccountName")
        assert api.seen["put_data"] == {"base-dn": "dc=new", "user-attr": "sAMAccountName"}


class TestRealmLdapDelete:
    def test_path(self):
        api = _api()
        realm_ldap_delete(api, "corp")
        assert api.seen["delete_path"] == "/config/access/ldap/corp"


# ---------------------------------------------------------------------------
# Backend functions — realms: OpenID
# ---------------------------------------------------------------------------

class TestRealmOpenidList:
    def test_path(self):
        api = _api(get_return=[])
        realm_openid_list(api)
        assert api.seen["get_path"] == "/config/access/openid"


class TestRealmOpenidGet:
    def test_path(self):
        api = _api(get_return={})
        realm_openid_get(api, "sso")
        assert api.seen["get_path"] == "/config/access/openid/sso"


class TestRealmOpenidCreate:
    def test_minimal_payload(self):
        api = _api()
        realm_openid_create(api, "sso", "https://issuer.example.com", "client-abc")
        assert api.seen["post_path"] == "/config/access/openid"
        assert api.seen["post_data"] == {
            "realm": "sso", "issuer-url": "https://issuer.example.com",
            "client-id": "client-abc",
        }

    def test_full_payload_with_client_key(self):
        api = _api()
        realm_openid_create(
            api, "sso", "https://issuer.example.com", "client-abc",
            client_key="oauthsecret-not-real", comment="c", default=True,
            acr_values="urn:x", audiences="aud1", autocreate=True, prompt="login",
            scopes="email profile", username_claim="sub",
        )
        assert api.seen["post_data"] == {
            "realm": "sso", "issuer-url": "https://issuer.example.com",
            "client-id": "client-abc", "comment": "c", "default": True,
            "acr-values": "urn:x", "audiences": "aud1", "autocreate": True, "prompt": "login",
            "scopes": "email profile", "username-claim": "sub",
            "client-key": "oauthsecret-not-real",
        }

    def test_client_key_omitted_when_none(self):
        api = _api()
        realm_openid_create(api, "sso", "https://issuer.example.com", "client-abc")
        assert "client-key" not in api.seen["post_data"]


class TestRealmOpenidUpdate:
    def test_partial_payload(self):
        api = _api()
        realm_openid_update(api, "sso", comment="new")
        assert api.seen["put_path"] == "/config/access/openid/sso"
        assert api.seen["put_data"] == {"comment": "new"}

    def test_delete_props_comma_joined(self):
        api = _api()
        realm_openid_update(api, "sso", delete_props=["comment", "prompt"])
        assert api.seen["put_data"]["delete"] == "comment,prompt"

    def test_username_claim_is_create_only_not_in_update_signature(self):
        # username-claim is absent from PUT /config/access/openid/{realm}'s schema (create-only),
        # and that PUT is additionalProperties:false — sending it hard-fails the WHOLE request
        # server-side. It must NOT be an update parameter at all.
        import inspect
        assert "username_claim" not in inspect.signature(realm_openid_update).parameters

    def test_username_claim_present_on_create(self):
        # Contrast: it IS a valid create field, so it must still reach the create payload.
        api = _api()
        realm_openid_create(api, "sso", "https://issuer.example.com", "client-abc",
                            username_claim="sub")
        assert api.seen["post_data"]["username-claim"] == "sub"


class TestRealmOpenidDelete:
    def test_path(self):
        api = _api()
        realm_openid_delete(api, "sso")
        assert api.seen["delete_path"] == "/config/access/openid/sso"


# ---------------------------------------------------------------------------
# Backend functions — realms: PAM / PBS built-in (GET/PUT only, no realm-name path param)
# ---------------------------------------------------------------------------

class TestRealmPamGetSet:
    def test_get_path(self):
        api = _api(get_return={})
        realm_pam_get(api)
        assert api.seen["get_path"] == "/config/access/pam"

    def test_set_path_and_payload(self):
        api = _api()
        realm_pam_set(api, comment="local admin", default=True)
        assert api.seen["put_path"] == "/config/access/pam"
        assert api.seen["put_data"] == {"comment": "local admin", "default": True}

    def test_set_delete_props_and_digest(self):
        api = _api()
        d = "c" * 64
        realm_pam_set(api, delete_props=["comment"], digest=d)
        assert api.seen["put_data"] == {"delete": "comment", "digest": d}


class TestRealmPbsGetSet:
    def test_get_path(self):
        api = _api(get_return={})
        realm_pbs_get(api)
        assert api.seen["get_path"] == "/config/access/pbs"

    def test_set_path_and_payload(self):
        api = _api()
        realm_pbs_set(api, comment="built-in", default=False)
        assert api.seen["put_path"] == "/config/access/pbs"
        assert api.seen["put_data"] == {"comment": "built-in", "default": False}


# ---------------------------------------------------------------------------
# Backend functions — TFA
# ---------------------------------------------------------------------------

class TestTfaList:
    def test_path(self):
        api = _api(get_return=[])
        tfa_list(api)
        assert api.seen["get_path"] == "/access/tfa"


class TestTfaUserGet:
    def test_path(self):
        api = _api(get_return=[])
        tfa_user_get(api, "u@pbs")
        assert api.seen["get_path"] == "/access/tfa/u@pbs"


class TestTfaAdd:
    def test_minimal_payload(self):
        api = _api()
        tfa_add(api, "u@pbs", "totp", totp="otpauth://totp/x", value="123456")
        assert api.seen["post_path"] == "/access/tfa/u@pbs"
        assert api.seen["post_data"] == {
            "type": "totp", "totp": "otpauth://totp/x", "value": "123456",
        }

    def test_recovery_type_no_extra_fields_required(self):
        api = _api()
        tfa_add(api, "u@pbs", "recovery")
        assert api.seen["post_data"] == {"type": "recovery"}

    def test_invalid_type_raises(self):
        api = _api()
        with pytest.raises(ProximoError):
            tfa_add(api, "u@pbs", "bogus")

    def test_password_forwarded_by_backend(self):
        # Redaction is a server-layer concern — the backend op forwards the real value.
        api = _api()
        tfa_add(api, "u@pbs", "totp", password="realpass-not-real")
        assert api.seen["post_data"]["password"] == "realpass-not-real"


class TestTfaEntryGet:
    def test_path(self):
        api = _api(get_return=None)
        tfa_entry_get(api, "u@pbs", "totp-0")
        assert api.seen["get_path"] == "/access/tfa/u@pbs/totp-0"


class TestTfaUpdate:
    def test_partial_payload(self):
        api = _api()
        tfa_update(api, "u@pbs", "totp-0", description="new desc")
        assert api.seen["put_path"] == "/access/tfa/u@pbs/totp-0"
        assert api.seen["put_data"] == {"description": "new desc"}

    def test_enable_false(self):
        api = _api()
        tfa_update(api, "u@pbs", "totp-0", enable=False)
        assert api.seen["put_data"] == {"enable": False}


class TestTfaDelete:
    def test_path_no_params(self):
        api = _api()
        tfa_delete(api, "u@pbs", "totp-0")
        assert api.seen["delete_path"] == "/access/tfa/u@pbs/totp-0"
        assert api.seen["delete_params"] is None

    def test_password_forwarded(self):
        api = _api()
        tfa_delete(api, "u@pbs", "totp-0", password="realpass-not-real")
        assert api.seen["delete_params"] == {"password": "realpass-not-real"}


class TestTfaUnlock:
    def test_path(self):
        api = _api()
        tfa_unlock(api, "u@pbs")
        assert api.seen["put_path"] == "/access/users/u@pbs/unlock-tfa"

    def test_returns_bool(self):
        api = _api()
        api._put = lambda path, data=None: True
        assert tfa_unlock(api, "u@pbs") is True


class TestTfaWebauthnGetSet:
    def test_get_path(self):
        api = _api(get_return={})
        tfa_webauthn_get(api)
        assert api.seen["get_path"] == "/config/access/tfa/webauthn"

    def test_set_path_and_payload(self):
        api = _api()
        tfa_webauthn_set(api, rp_id="pbs.example.com", origin="https://pbs.example.com",
                         rp_name="PBS", allow_subdomains=False)
        assert api.seen["put_path"] == "/config/access/tfa/webauthn"
        assert api.seen["put_data"] == {
            "id": "pbs.example.com", "origin": "https://pbs.example.com",
            "rp": "PBS", "allow-subdomains": False,
        }

    def test_set_delete_props_and_digest(self):
        api = _api()
        d = "d" * 64
        tfa_webauthn_set(api, delete_props=["origin"], digest=d)
        assert api.seen["put_data"] == {"delete": "origin", "digest": d}


# ---------------------------------------------------------------------------
# Plan factories — realms
# ---------------------------------------------------------------------------

class TestPlanRealmAdCreate:
    def test_risk_medium(self):
        p = plan_realm_ad_create("corp", "ad1.example.com")
        assert p.risk == RISK_MEDIUM
        assert p.action == "pbs_realm_ad_create"

    def test_no_password_param_exists(self):
        import inspect
        assert "password" not in inspect.signature(plan_realm_ad_create).parameters


class TestPlanRealmAdUpdate:
    def test_risk_medium_and_captures_current(self):
        api = _api(get_return={"realm": "corp", "comment": "old"})
        p = plan_realm_ad_update(api, "corp", comment="new")
        assert p.risk == RISK_MEDIUM
        assert p.current == {"realm": "corp", "comment": "old"}
        assert p.complete is True

    def test_capture_failure_sets_incomplete(self):
        api = _api(raise_on_get=RuntimeError("boom"))
        p = plan_realm_ad_update(api, "corp", comment="new")
        assert p.complete is False


class TestPlanRealmAdDelete:
    def test_risk_medium(self):
        api = _api(get_return={"realm": "corp"})
        p = plan_realm_ad_delete(api, "corp")
        assert p.risk == RISK_MEDIUM

    def test_blast_names_permanence_and_login_impact(self):
        api = _api(get_return={"realm": "corp"})
        p = plan_realm_ad_delete(api, "corp")
        joined = " ".join(p.blast_radius).lower()
        assert "permanent" in joined
        assert "log in" in joined or "login" in joined


class TestPlanRealmLdapCreate:
    def test_risk_medium(self):
        p = plan_realm_ldap_create("corp", "s1", "dc=corp", "uid")
        assert p.risk == RISK_MEDIUM


class TestPlanRealmLdapUpdate:
    def test_risk_medium_and_captures_current(self):
        api = _api(get_return={"realm": "corp", "comment": "old"})
        p = plan_realm_ldap_update(api, "corp", comment="new")
        assert p.risk == RISK_MEDIUM
        assert p.current == {"realm": "corp", "comment": "old"}
        assert p.complete is True

    def test_capture_failure_sets_incomplete(self):
        api = _api(raise_on_get=RuntimeError("boom"))
        p = plan_realm_ldap_update(api, "corp", comment="new")
        assert p.complete is False


class TestPlanRealmLdapDelete:
    def test_risk_medium(self):
        api = _api(get_return={})
        p = plan_realm_ldap_delete(api, "corp")
        assert p.risk == RISK_MEDIUM


class TestPlanRealmOpenidCreate:
    def test_risk_medium(self):
        p = plan_realm_openid_create("sso", "https://issuer.example.com", "client-abc")
        assert p.risk == RISK_MEDIUM

    def test_no_client_key_param_exists(self):
        import inspect
        assert "client_key" not in inspect.signature(plan_realm_openid_create).parameters


class TestPlanRealmOpenidUpdate:
    def test_risk_medium(self):
        api = _api(get_return={})
        p = plan_realm_openid_update(api, "sso", comment="x")
        assert p.risk == RISK_MEDIUM


class TestPlanRealmOpenidDelete:
    def test_risk_medium(self):
        api = _api(get_return={})
        p = plan_realm_openid_delete(api, "sso")
        assert p.risk == RISK_MEDIUM


class TestPlanRealmPamSet:
    def test_risk_medium_and_no_lockout_language(self):
        api = _api(get_return={})
        p = plan_realm_pam_set(api, comment="x")
        assert p.risk == RISK_MEDIUM
        joined = " ".join(p.blast_radius).lower()
        assert "no lockout" in joined or "cannot be deleted" in joined

    def test_capture_failure_sets_incomplete(self):
        api = _api(raise_on_get=RuntimeError("boom"))
        p = plan_realm_pam_set(api, comment="x")
        assert p.complete is False


class TestPlanRealmPbsSet:
    def test_risk_medium(self):
        api = _api(get_return={})
        p = plan_realm_pbs_set(api, comment="x")
        assert p.risk == RISK_MEDIUM


# ---------------------------------------------------------------------------
# Plan factories — TFA
# ---------------------------------------------------------------------------

class TestPlanTfaAdd:
    def test_risk_medium(self):
        p = plan_tfa_add("u@pbs", "totp")
        assert p.risk == RISK_MEDIUM
        assert p.action == "pbs_tfa_add"

    def test_no_secret_bearing_params_exist(self):
        import inspect
        params = inspect.signature(plan_tfa_add).parameters
        assert "password" not in params
        assert "totp" not in params
        assert "value" not in params
        assert "challenge" not in params

    def test_recovery_type_blast_names_server_generated_codes(self):
        p = plan_tfa_add("u@pbs", "recovery")
        joined = " ".join(p.blast_radius).lower()
        assert "recovery" in joined
        assert "ledger" in joined or "surface" in joined

    def test_plan_dict_never_contains_secret_shaped_keys(self):
        p = plan_tfa_add("u@pbs", "recovery")
        d = p.as_dict()
        assert "recovery" not in d and "challenge" not in d


class TestPlanTfaUpdate:
    def test_risk_medium_and_captures_current(self):
        api = _api(get_return={"id": "totp-0", "enable": True})
        p = plan_tfa_update(api, "u@pbs", "totp-0", enable=False)
        assert p.risk == RISK_MEDIUM
        assert p.complete is True

    def test_enable_false_flagged_in_blast(self):
        api = _api(get_return={})
        p = plan_tfa_update(api, "u@pbs", "totp-0", enable=False)
        assert any("disables" in line.lower() for line in p.blast_radius)


class TestPlanTfaDelete:
    def test_risk_high(self):
        # HIGH, not MEDIUM: removing a 2FA factor weakens authentication (lockout / account-
        # takeover enabler), same semantics PVE's own plan_tfa_delete rates HIGH — and this plane
        # guards backups.
        api = _api(get_return=[{"id": "totp-0"}])
        p = plan_tfa_delete(api, "u@pbs", "totp-0")
        assert p.risk == RISK_HIGH

    def test_blast_names_permanence(self):
        api = _api(get_return=[{"id": "totp-0"}])
        p = plan_tfa_delete(api, "u@pbs", "totp-0")
        joined = " ".join(p.blast_radius).lower()
        assert "permanent" in joined or "no undo" in joined

    def test_blast_names_account_takeover_risk(self):
        api = _api(get_return=[{"id": "totp-0"}])
        p = plan_tfa_delete(api, "u@pbs", "totp-0")
        joined = " ".join(p.blast_radius).lower()
        assert "takeover" in joined or "weakens" in joined

    def test_last_factor_warns_lockout(self):
        api = _api(get_return=[{"id": "totp-0"}])
        p = plan_tfa_delete(api, "u@pbs", "totp-0")
        joined = " ".join(p.blast_radius).lower()
        assert "last" in joined and "unable to log in" in joined


class TestPlanTfaUnlock:
    def test_risk_high(self):
        # HIGH, not MEDIUM: clearing the TOTP lockout removes the anti-brute-force throttle on a
        # 6-digit keyspace — an authentication-weakening act.
        p = plan_tfa_unlock("u@pbs")
        assert p.risk == RISK_HIGH
        assert p.action == "pbs_tfa_unlock"

    def test_blast_names_bruteforce_risk(self):
        p = plan_tfa_unlock("u@pbs")
        joined = " ".join(p.blast_radius).lower()
        assert "brute" in joined or "throttle" in joined


class TestPlanTfaWebauthnSet:
    def test_risk_medium_and_captures_current(self):
        api = _api(get_return={"id": "pbs.example.com"})
        p = plan_tfa_webauthn_set(api, rp_id="new.example.com")
        assert p.risk == RISK_MEDIUM
        assert p.complete is True

    def test_rp_id_change_warns_break_all_credentials(self):
        api = _api(get_return={})
        p = plan_tfa_webauthn_set(api, rp_id="new.example.com")
        joined = " ".join(p.blast_radius).lower()
        assert "will break every" in joined

    def test_origin_change_warns_may_break(self):
        api = _api(get_return={})
        p = plan_tfa_webauthn_set(api, origin="https://new.example.com")
        joined = " ".join(p.blast_radius).lower()
        assert "may break" in joined
