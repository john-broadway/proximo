"""PMG identity backend/validator/plan-factory unit tests (Wave 9h AND 9i, full-surface campaign).

Mirrors `test_pmg_node.py`'s structure (fully mocked, no live PMG, no server/FastMCP involved) —
the Wave 9a review's own lesson (a server-level confirm-sweep alone left validators/plan-factory
branches with zero direct coverage) applies here too: this file closes that gap directly against
the backend/plan-factory functions in `proximo.pmg_identity`.

Sections (9h, unchanged from that landing):
 1. Validators — _check_userid, _check_realm, _check_role (incl. RULING 3's admin-equivalent
    set), _check_realm_type, _check_tfa_type (Fact 5: no 'yubico'), _check_tfa_id, _check_digest,
    _is_admin_equivalent.
 2. Secret redaction/strip helpers — _user_secret_redacted_detail (the THREE user secrets, Fact
    3), _tfa_password_redacted_detail, _client_key_redacted_detail, _strip_user_secret_fields,
    _strip_realm_client_key.
 3. Backend functions — realm CRUD (path/param construction, Fact 2's no-digest divergence on
    user endpoints), user CRUD, TFA CRUD, path/param construction with raising/falsy fakes.
 4. Plan factories — CAPTURE-or-declare success/failure branches; RULING 3's conditional
    risk on user_create/user_update (incl. the fail-open-to-HIGH branch on a failed capture);
    plan_user_delete's last-admin-equivalent-account footgun warning (reusing access_permissions);
    plan_user_unlock_tfa's MEDIUM (Fact 8, documented PBS divergence); plan_tfa_delete's HIGH
    (Fact 9, matches the PBS twin).

Section 9i (this addition, appended at the end of this file):
 5. 9i validators/helpers — _check_digest_sha1 (Fact 15 SHA1 divergence), _redact_pmg_http_proxy
    (Fact 14), _join_password_redacted_detail, _join_delete/_delete_prop_list,
    _require_at_least_one_config_field, _flag_if_narrower.
 6. 9i backend functions — the 6 global-config GET/PUT families (path/wire-field construction),
    the 3 cluster reads, the 4 cluster mutations (path/param construction).
 7. 9i plan factories — CAPTURE-or-declare success/failure branches for all 6 config families;
    direction-aware blast_radius assertions (demo/clamav in admin; scan-limit narrowing/
    archiveblockencrypted in clamav; tls/spf/relay-smarthost in mail; quarantinelink/authmode in
    spamquar; allowhrefs in virusquar; id/origin/rp in webauthn); the at-least-one-field guard;
    RULING 1's no-undo first line + third-party-credential line for cluster create/join;
    plan_cluster_join's password-never-received discipline.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from proximo.backends import ProximoError
from proximo.planning import RISK_HIGH, RISK_MEDIUM
from proximo.pmg_identity import (
    _ADMIN_EQUIVALENT_ROLES,
    _NON_ADMIN_ROLES,
    _REALM_TYPE_ENUM,
    _ROLE_ENUM,
    _TFA_TYPES,
    _check_digest,
    _check_digest_sha1,
    _check_realm,
    _check_realm_type,
    _check_role,
    _check_tfa_id,
    _check_tfa_type,
    _check_userid,
    _classify_captured_role,
    _client_key_redacted_detail,
    _delete_prop_list,
    _flag_if_narrower,
    _is_admin_equivalent,
    _join_delete,
    _join_password_redacted_detail,
    _redact_pmg_http_proxy,
    _reject_dot_traversal,
    _require_at_least_one_config_field,
    _strip_realm_client_key,
    _strip_user_secret_fields,
    _tfa_password_redacted_detail,
    _user_secret_redacted_detail,
    admin_config_get,
    admin_config_update,
    clamav_config_get,
    clamav_config_update,
    cluster_create,
    cluster_join,
    cluster_join_info,
    cluster_node_add,
    cluster_nodes_list,
    cluster_status,
    cluster_update_fingerprints,
    mail_config_update,
    plan_admin_config_update,
    plan_clamav_config_update,
    plan_cluster_create,
    plan_cluster_join,
    plan_cluster_node_add,
    plan_cluster_update_fingerprints,
    plan_mail_config_update,
    plan_realm_create,
    plan_realm_delete,
    plan_realm_update,
    plan_spamquar_config_update,
    plan_tfa_add,
    plan_tfa_delete,
    plan_tfa_update,
    plan_tfa_webauthn_config_update,
    plan_user_create,
    plan_user_delete,
    plan_user_unlock_tfa,
    plan_user_update,
    plan_virusquar_config_update,
    realm_create,
    realm_delete,
    realm_get,
    realm_list,
    realm_update,
    spamquar_config_get,
    spamquar_config_update,
    tfa_add,
    tfa_delete,
    tfa_entry_get,
    tfa_list,
    tfa_update,
    tfa_user_list,
    tfa_webauthn_config_get,
    tfa_webauthn_config_update,
    user_create,
    user_delete,
    user_get,
    user_unlock_tfa,
    user_update,
    virusquar_config_get,
    virusquar_config_update,
)


def _api(get_return=None, raise_on_get=False):
    """Path-recording fake PmgBackend — mirrors test_pmg_node.py's `_api()`."""
    seen: dict = {}

    def fake_get(path, params=None):
        seen["method"] = "GET"
        seen["path"] = path
        seen["params"] = params
        if raise_on_get:
            raise ProximoError(f"simulated read failure for {path}")
        if get_return is not None:
            return get_return
        return {}

    def fake_post(path, data=None):
        seen["method"] = "POST"
        seen["path"] = path
        seen["data"] = data
        return None

    def fake_put(path, data=None):
        seen["method"] = "PUT"
        seen["path"] = path
        seen["data"] = data
        return None

    def fake_delete(path, params=None):
        seen["method"] = "DELETE"
        seen["path"] = path
        seen["params"] = params
        return None

    return SimpleNamespace(seen=seen, _get=fake_get, _post=fake_post, _put=fake_put, _delete=fake_delete)


def _raising_get_api(exc: Exception):
    def fake_get(path, params=None):
        raise exc
    return SimpleNamespace(_get=fake_get)


# ---------------------------------------------------------------------------
# 1. Validators
# ---------------------------------------------------------------------------


class TestCheckUserid:
    def test_accepts_valid_shape(self):
        assert _check_userid("alice@pmg") == "alice@pmg"

    def test_accepts_min_length_4(self):
        # shortest valid: 1-char user + '@' + 2-char realm = 4 chars total (schema minLength 4)
        assert _check_userid("a@bb") == "a@bb"

    def test_rejects_too_short(self):
        with pytest.raises(ProximoError):
            _check_userid("a@b")  # 3 chars, schema requires >=4

    def test_rejects_too_long(self):
        with pytest.raises(ProximoError):
            _check_userid("a" * 61 + "@pmg")  # 65 chars, >64

    def test_rejects_missing_at(self):
        with pytest.raises(ProximoError):
            _check_userid("aliceatpmg")

    def test_rejects_whitespace(self):
        with pytest.raises(ProximoError):
            _check_userid("ali ce@pmg")

    def test_strips_surrounding_whitespace(self):
        assert _check_userid("  alice@pmg  ") == "alice@pmg"

    def test_rejects_dot_traversal_in_userid(self):
        with pytest.raises(ProximoError):
            _check_userid("..@pmg")


class TestCheckRealm:
    def test_accepts_valid_realm(self):
        assert _check_realm("pmg") == "pmg"

    def test_accepts_32_char_upper_bound(self):
        s = "a" * 32
        assert _check_realm(s) == s

    def test_rejects_33_char_too_long(self):
        with pytest.raises(ProximoError):
            _check_realm("a" * 33)

    def test_rejects_leading_dot(self):
        with pytest.raises(ProximoError):
            _check_realm(".pmg")

    def test_rejects_lone_dot(self):
        with pytest.raises(ProximoError):
            _check_realm(".")

    def test_rejects_embedded_dotdot(self):
        with pytest.raises(ProximoError):
            _check_realm("re..alm")

    def test_rejects_slash(self):
        with pytest.raises(ProximoError):
            _check_realm("re/alm")


class TestCheckRole:
    @pytest.mark.parametrize("role", sorted(_ROLE_ENUM))
    def test_accepts_all_declared_roles(self, role):
        assert _check_role(role) == role

    def test_rejects_unknown_role(self):
        with pytest.raises(ProximoError):
            _check_role("superuser")

    def test_rejects_empty_string(self):
        with pytest.raises(ProximoError):
            _check_role("")

    def test_role_enum_is_the_five_pmg_values(self):
        # Schema fact: {root, admin, helpdesk, qmanager, audit} — no more, no fewer.
        assert _ROLE_ENUM == {"root", "admin", "helpdesk", "qmanager", "audit"}


class TestAdminEquivalent:
    @pytest.mark.parametrize("role", sorted(_ADMIN_EQUIVALENT_ROLES))
    def test_admin_equivalent_roles_are_true(self, role):
        assert _is_admin_equivalent(role) is True

    @pytest.mark.parametrize("role", ["helpdesk", "qmanager", "audit"])
    def test_non_admin_roles_are_false(self, role):
        assert _is_admin_equivalent(role) is False

    def test_none_is_false(self):
        assert _is_admin_equivalent(None) is False

    def test_admin_equivalent_set_is_root_and_admin_only(self):
        # RULING 3's binding admin-equivalent set — exactly these two, not the whole enum.
        assert _ADMIN_EQUIVALENT_ROLES == {"root", "admin"}


class TestClassifyCapturedRole:
    """Wave 9h review Critical fix: tri-state resolution of a ROLE VALUE READ FROM A SUCCESSFUL
    CAPTURE (never for caller-supplied role, which _check_role already exact-match validates).
    'admin'/'safe' are confident resolutions; 'unknown' means the caller must fail OPEN to HIGH
    exactly like a capture exception — never silently read as confirmed non-admin."""

    def test_non_admin_role_set_is_the_enum_minus_admin_equivalent(self):
        assert _NON_ADMIN_ROLES == {"helpdesk", "qmanager", "audit"}
        assert _NON_ADMIN_ROLES == _ROLE_ENUM - _ADMIN_EQUIVALENT_ROLES

    @pytest.mark.parametrize("role", sorted(_ADMIN_EQUIVALENT_ROLES))
    def test_exact_admin_role_present_is_admin(self, role):
        assert _classify_captured_role(role, True) == "admin"

    @pytest.mark.parametrize("role", sorted(_NON_ADMIN_ROLES))
    def test_exact_non_admin_role_present_is_safe(self, role):
        assert _classify_captured_role(role, True) == "safe"

    def test_role_key_absent_is_unknown(self):
        # Branch (b): a schema-plausible capture that simply omits the 'role' key.
        assert _classify_captured_role(None, False) == "unknown"

    def test_role_value_none_with_key_present_is_unknown(self):
        # Branch (c): the key IS present but its value is null.
        assert _classify_captured_role(None, True) == "unknown"

    def test_unrecognized_future_role_string_is_unknown(self):
        # Branch (f): a value that is not an exact match for ANY known PMG role.
        assert _classify_captured_role("superduperrole", True) == "unknown"

    @pytest.mark.parametrize("role", ["Admin", "ADMIN", "Root", "rOOt", " admin", "admin "])
    def test_case_or_whitespace_variant_of_admin_role_is_admin(self, role):
        # Branch (g): a case-variant of an admin-equivalent role must NOT resolve to "safe" —
        # fails open to "admin" (a server echoing admin authority in unexpected case/whitespace
        # is not evidence of non-admin status).
        assert _classify_captured_role(role, True) == "admin"

    @pytest.mark.parametrize("role", ["Helpdesk", "HELPDESK", "Qmanager", "Audit"])
    def test_case_variant_of_non_admin_role_is_unknown_not_safe(self, role):
        # A case-variant of a KNOWN NON-ADMIN role is NOT treated as confirmed-safe either —
        # only an EXACT match to the known-safe set resolves "safe"; anything else fails open.
        assert _classify_captured_role(role, True) == "unknown"

    def test_non_string_value_is_unknown(self):
        assert _classify_captured_role(123, True) == "unknown"
        assert _classify_captured_role(["admin"], True) == "unknown"

    def test_empty_string_is_unknown(self):
        assert _classify_captured_role("", True) == "unknown"


class TestCheckRealmType:
    @pytest.mark.parametrize("rt", sorted(_REALM_TYPE_ENUM))
    def test_accepts_all_declared_types(self, rt):
        assert _check_realm_type(rt) == rt

    def test_rejects_ad(self):
        # Fact 10: PMG has NO 'ad'/'ldap' realm types on this unified endpoint (unlike PBS).
        with pytest.raises(ProximoError):
            _check_realm_type("ad")

    def test_rejects_ldap(self):
        with pytest.raises(ProximoError):
            _check_realm_type("ldap")

    def test_realm_type_enum_is_exactly_three(self):
        assert _REALM_TYPE_ENUM == {"oidc", "pam", "pmg"}


class TestCheckTfaType:
    @pytest.mark.parametrize("t", sorted(_TFA_TYPES))
    def test_accepts_all_declared_types(self, t):
        assert _check_tfa_type(t) == t

    def test_rejects_yubico(self):
        # Fact 5: PMG's TFA type enum has only 4 members — no 'yubico' (PBS has 5).
        with pytest.raises(ProximoError):
            _check_tfa_type("yubico")

    def test_tfa_types_enum_is_exactly_four(self):
        assert _TFA_TYPES == {"totp", "u2f", "webauthn", "recovery"}


class TestCheckTfaId:
    def test_accepts_alnum(self):
        assert _check_tfa_id("abc123") == "abc123"

    def test_rejects_lone_dot(self):
        with pytest.raises(ProximoError):
            _check_tfa_id(".")

    def test_rejects_embedded_dotdot(self):
        with pytest.raises(ProximoError):
            _check_tfa_id("ab..cd")

    def test_rejects_leading_colon(self):
        with pytest.raises(ProximoError):
            _check_tfa_id(":abc")


class TestCheckDigest:
    def test_none_passes_through(self):
        assert _check_digest(None) is None

    def test_accepts_valid_sha256_hex(self):
        s = "a" * 64
        assert _check_digest(s) == s

    def test_rejects_too_short(self):
        with pytest.raises(ProximoError):
            _check_digest("abc123")

    def test_rejects_uppercase_hex(self):
        with pytest.raises(ProximoError):
            _check_digest("A" * 64)

    def test_rejects_non_hex(self):
        with pytest.raises(ProximoError):
            _check_digest("z" * 64)

    def test_rejects_trailing_newline(self):
        # A11 tightening: the retired per-module copy .strip()ped before matching, which
        # re-admitted the trailing newline the \Z anchor exists to refuse.
        with pytest.raises(ProximoError):
            _check_digest("a" * 64 + "\n")


def test_reject_dot_traversal_raises_on_lone_dot():
    with pytest.raises(ProximoError):
        _reject_dot_traversal(".", "userid")


def test_reject_dot_traversal_passes_normal_value():
    _reject_dot_traversal("alice@pmg", "userid")  # no raise


# ---------------------------------------------------------------------------
# 2. Secret redaction / strip helpers
# ---------------------------------------------------------------------------


class TestUserSecretRedactedDetail:
    def test_all_none_yields_empty_dict(self):
        assert _user_secret_redacted_detail(None, None, None) == {}

    def test_password_only(self):
        assert _user_secret_redacted_detail("s3cr3t", None, None) == {"password": "[redacted]"}

    def test_crypt_pass_only(self):
        assert _user_secret_redacted_detail(None, "$6$salt$hash", None) == {"crypt_pass": "[redacted]"}

    def test_keys_only(self):
        # Fact 3 — the THIRD secret this build found.
        assert _user_secret_redacted_detail(None, None, "yubikey-id-1") == {"keys": "[redacted]"}

    def test_all_three_supplied(self):
        detail = _user_secret_redacted_detail("pw", "$6$s$h", "yk1")
        assert detail == {
            "password": "[redacted]", "crypt_pass": "[redacted]", "keys": "[redacted]",
        }


class TestTfaPasswordRedactedDetail:
    def test_none_yields_empty(self):
        assert _tfa_password_redacted_detail(None) == {}

    def test_supplied_is_redacted(self):
        assert _tfa_password_redacted_detail("currentpw") == {"password": "[redacted]"}


class TestClientKeyRedactedDetail:
    def test_none_yields_empty(self):
        assert _client_key_redacted_detail(None) == {}

    def test_supplied_is_redacted(self):
        assert _client_key_redacted_detail("oidc-secret") == {"client-key": "[redacted]"}


class TestStripUserSecretFields:
    def test_strips_all_three_when_present(self):
        resp = {"userid": "alice@pmg", "password": "leaked", "crypt_pass": "leaked2",
                "keys": "leaked3", "role": "audit"}
        stripped = _strip_user_secret_fields(resp)
        assert stripped == {"userid": "alice@pmg", "role": "audit"}

    def test_passthrough_when_absent(self):
        resp = {"userid": "alice@pmg", "role": "audit"}
        assert _strip_user_secret_fields(resp) == resp


class TestStripRealmClientKey:
    def test_strips_client_key(self):
        resp = {"realm": "myrealm", "type": "oidc", "client-key": "leaked"}
        assert _strip_realm_client_key(resp) == {"realm": "myrealm", "type": "oidc"}

    def test_passthrough_when_absent(self):
        resp = {"realm": "myrealm", "type": "pam"}
        assert _strip_realm_client_key(resp) == resp


# ---------------------------------------------------------------------------
# 3. Backend functions — Auth realms
# ---------------------------------------------------------------------------


def test_realm_list_path():
    api = _api(get_return=[{"realm": "pam", "type": "pam"}])
    result = realm_list(api)
    assert api.seen["path"] == "/access/auth-realm"
    assert result == [{"realm": "pam", "type": "pam"}]


def test_realm_get_strips_client_key():
    api = _api(get_return={"realm": "myrealm", "type": "oidc", "client-key": "leaked"})
    result = realm_get(api, "myrealm")
    assert api.seen["path"] == "/access/auth-realm/myrealm"
    assert "client-key" not in result


def test_realm_create_path_and_required_fields():
    api = _api()
    realm_create(api, "myrealm", "oidc", issuer_url="https://idp.example.com", client_id="cid")
    assert api.seen["method"] == "POST"
    assert api.seen["path"] == "/access/auth-realm"
    assert api.seen["data"]["realm"] == "myrealm"
    assert api.seen["data"]["type"] == "oidc"
    assert api.seen["data"]["issuer-url"] == "https://idp.example.com"
    assert api.seen["data"]["client-id"] == "cid"


def test_realm_create_rejects_invalid_type():
    api = _api()
    with pytest.raises(ProximoError):
        realm_create(api, "myrealm", "ad")


def test_realm_create_forwards_client_key_raw_to_backend():
    api = _api()
    realm_create(api, "myrealm", "oidc", client_key="s3cr3t")
    assert api.seen["data"]["client-key"] == "s3cr3t"


def test_realm_update_path_no_type_field():
    api = _api()
    realm_update(api, "myrealm", comment="updated")
    assert api.seen["method"] == "PUT"
    assert api.seen["path"] == "/access/auth-realm/myrealm"
    assert "type" not in api.seen["data"]
    assert "realm" not in api.seen["data"]


def test_realm_update_forwards_digest():
    api = _api()
    realm_update(api, "myrealm", digest="a" * 64)
    assert api.seen["data"]["digest"] == "a" * 64


def test_realm_update_rejects_bad_digest():
    api = _api()
    with pytest.raises(ProximoError):
        realm_update(api, "myrealm", digest="not-hex")


def test_realm_delete_path_no_digest_param():
    api = _api()
    realm_delete(api, "myrealm")
    assert api.seen["method"] == "DELETE"
    assert api.seen["path"] == "/access/auth-realm/myrealm"
    # Fact 2: this endpoint's schema declares only 'realm' — no digest support at all.
    assert api.seen["params"] is None


# ---------------------------------------------------------------------------
# 3. Backend functions — Local users
# ---------------------------------------------------------------------------


def test_user_get_strips_all_three_secrets():
    api = _api(get_return={"userid": "alice@pmg", "role": "audit",
                           "password": "x", "crypt_pass": "y", "keys": "z"})
    result = user_get(api, "alice@pmg")
    assert api.seen["path"] == "/access/users/alice@pmg"
    assert result == {"userid": "alice@pmg", "role": "audit"}


def test_user_create_role_required_and_forwarded():
    api = _api()
    user_create(api, "alice@pmg", "admin")
    assert api.seen["method"] == "POST"
    assert api.seen["path"] == "/access/users"
    assert api.seen["data"]["userid"] == "alice@pmg"
    assert api.seen["data"]["role"] == "admin"


def test_user_create_rejects_invalid_role():
    api = _api()
    with pytest.raises(ProximoError):
        user_create(api, "alice@pmg", "superuser")


def test_user_create_forwards_all_three_secrets_raw():
    api = _api()
    user_create(api, "alice@pmg", "audit", password="pw", crypt_pass="$6$s$h", keys="yk1")
    assert api.seen["data"]["password"] == "pw"
    assert api.seen["data"]["crypt_pass"] == "$6$s$h"
    assert api.seen["data"]["keys"] == "yk1"


def test_user_create_omits_secrets_when_not_given():
    api = _api()
    user_create(api, "alice@pmg", "audit")
    assert "password" not in api.seen["data"]
    assert "crypt_pass" not in api.seen["data"]
    assert "keys" not in api.seen["data"]


def test_user_create_realm_defaults_to_none_when_omitted():
    api = _api()
    user_create(api, "alice@pmg", "audit")
    assert "realm" not in api.seen["data"]


def test_user_update_path_no_digest_param_in_signature():
    api = _api()
    user_update(api, "alice@pmg", comment="hi")
    assert api.seen["method"] == "PUT"
    assert api.seen["path"] == "/access/users/alice@pmg"
    # Fact 2: no digest param exists on this function's signature at all (schema-verified absent).
    import inspect
    assert "digest" not in inspect.signature(user_update).parameters


def test_user_update_role_optional_and_forwarded_when_given():
    api = _api()
    user_update(api, "alice@pmg", role="helpdesk")
    assert api.seen["data"]["role"] == "helpdesk"


def test_user_update_forwards_delete_props():
    api = _api()
    user_update(api, "alice@pmg", delete_props=["comment", "email"])
    assert api.seen["data"]["delete"] == "comment,email"


def test_user_delete_path_no_digest_param_in_signature():
    api = _api()
    user_delete(api, "alice@pmg")
    assert api.seen["method"] == "DELETE"
    assert api.seen["path"] == "/access/users/alice@pmg"
    import inspect
    assert "digest" not in inspect.signature(user_delete).parameters


def test_user_unlock_tfa_path_and_bool_return():
    api = _api(get_return=None)
    api._put = lambda path, data=None: True
    result = user_unlock_tfa(api, "alice@pmg")
    assert result is True


# ---------------------------------------------------------------------------
# 3. Backend functions — TFA
# ---------------------------------------------------------------------------


def test_tfa_list_path():
    api = _api(get_return=[{"userid": "alice@pmg", "entries": []}])
    tfa_list(api)
    assert api.seen["path"] == "/access/tfa"


def test_tfa_user_list_path():
    api = _api(get_return=[{"id": "totp1", "type": "totp"}])
    result = tfa_user_list(api, "alice@pmg")
    assert api.seen["path"] == "/access/tfa/alice@pmg"
    assert result == [{"id": "totp1", "type": "totp"}]


def test_tfa_entry_get_path():
    api = _api(get_return={"id": "totp1", "type": "totp", "enable": True})
    result = tfa_entry_get(api, "alice@pmg", "totp1")
    assert api.seen["path"] == "/access/tfa/alice@pmg/totp1"
    assert result["id"] == "totp1"


def test_tfa_add_rejects_yubico():
    api = _api()
    with pytest.raises(ProximoError):
        tfa_add(api, "alice@pmg", "yubico")


def test_tfa_add_forwards_password_and_type():
    api = _api()
    api._post = lambda path, data=None: {"id": "new1"}
    result = tfa_add(api, "alice@pmg", "totp", password="currentpw", totp="otpauth://...")
    assert result == {"id": "new1"}


def test_tfa_add_recovery_response_carries_codes():
    api = _api()
    api._post = lambda path, data=None: {"id": "rec1", "recovery": ["code1", "code2"]}
    result = tfa_add(api, "alice@pmg", "recovery")
    assert result["recovery"] == ["code1", "code2"]


def test_tfa_update_path():
    api = _api()
    tfa_update(api, "alice@pmg", "totp1", enable=False)
    assert api.seen["method"] == "PUT"
    assert api.seen["path"] == "/access/tfa/alice@pmg/totp1"
    assert api.seen["data"]["enable"] is False


def test_tfa_delete_forwards_password_param():
    api = _api()
    tfa_delete(api, "alice@pmg", "totp1", password="currentpw")
    assert api.seen["method"] == "DELETE"
    assert api.seen["path"] == "/access/tfa/alice@pmg/totp1"
    assert api.seen["params"]["password"] == "currentpw"


def test_tfa_delete_omits_password_when_not_given():
    api = _api()
    tfa_delete(api, "alice@pmg", "totp1")
    assert api.seen["params"] is None


# ---------------------------------------------------------------------------
# 4. Plan factories — Auth realms
# ---------------------------------------------------------------------------


def test_plan_realm_create_is_pure_and_medium():
    plan = plan_realm_create("myrealm", "pam")
    assert plan.risk == RISK_MEDIUM
    assert "myrealm" in plan.target
    assert "myrealm" in plan.change


def test_plan_realm_create_flags_autocreate_admin_authority_vector():
    plan = plan_realm_create("myrealm", "oidc", autocreate=True, autocreate_role="admin")
    assert any("admin-equivalent role" in b for b in plan.blast_radius)


def test_plan_realm_create_does_not_flag_when_autocreate_role_is_audit():
    plan = plan_realm_create("myrealm", "oidc", autocreate=True, autocreate_role="audit")
    assert not any("admin-equivalent role" in b for b in plan.blast_radius)


def test_plan_realm_update_captures_current():
    api = _api(get_return={"realm": "myrealm", "type": "oidc", "comment": "old"})
    plan = plan_realm_update(api, "myrealm", comment="new")
    assert plan.complete is True
    assert plan.current["comment"] == "old"
    assert plan.risk == RISK_MEDIUM


def test_plan_realm_update_degrades_honestly_on_capture_failure():
    api = _raising_get_api(ProximoError("boom"))
    plan = plan_realm_update(api, "myrealm", comment="new")
    assert plan.complete is False
    assert "Could not capture" in plan.note


def test_plan_realm_delete_captures_current_and_warns_permanent():
    api = _api(get_return={"realm": "myrealm", "type": "pam"})
    plan = plan_realm_delete(api, "myrealm")
    assert plan.risk == RISK_MEDIUM
    assert any("PERMANENTLY" in b for b in plan.blast_radius)


# ---------------------------------------------------------------------------
# 4. Plan factories — Local users (RULING 3)
# ---------------------------------------------------------------------------


class TestPlanUserCreateRuling3:
    @pytest.mark.parametrize("role", ["root", "admin"])
    def test_admin_equivalent_role_is_high(self, role):
        plan = plan_user_create("alice@pmg", role)
        assert plan.risk == RISK_HIGH
        assert any("ADMIN-EQUIVALENT" in b for b in plan.blast_radius)

    @pytest.mark.parametrize("role", ["helpdesk", "qmanager", "audit"])
    def test_non_admin_role_is_medium(self, role):
        plan = plan_user_create("alice@pmg", role)
        assert plan.risk == RISK_MEDIUM
        assert not any("ADMIN-EQUIVALENT" in b for b in plan.blast_radius)

    def test_rejects_invalid_role(self):
        with pytest.raises(ProximoError):
            plan_user_create("alice@pmg", "superuser")

    def test_disabled_create_is_flagged(self):
        plan = plan_user_create("alice@pmg", "audit", enable=False)
        assert any("DISABLED" in b for b in plan.blast_radius)

    def test_no_password_param_accepted(self):
        # Deliberate: the plan factory has NO parameter that could carry a secret at all.
        import inspect
        params = inspect.signature(plan_user_create).parameters
        assert "password" not in params
        assert "crypt_pass" not in params
        assert "keys" not in params


class TestPlanUserUpdateRuling3:
    def test_supplied_admin_role_is_high(self):
        api = _api(get_return={"userid": "alice@pmg", "role": "audit"})
        plan = plan_user_update(api, "alice@pmg", role="admin")
        assert plan.risk == RISK_HIGH
        assert plan.complete is True

    def test_supplied_non_admin_role_is_medium(self):
        api = _api(get_return={"userid": "alice@pmg", "role": "admin"})
        plan = plan_user_update(api, "alice@pmg", role="helpdesk")
        assert plan.risk == RISK_MEDIUM

    def test_omitted_role_resolves_from_capture_admin(self):
        api = _api(get_return={"userid": "alice@pmg", "role": "admin"})
        plan = plan_user_update(api, "alice@pmg", comment="hi")
        assert plan.risk == RISK_HIGH
        assert any("CURRENTLY admin-equivalent" in b for b in plan.blast_radius)

    def test_omitted_role_resolves_from_capture_non_admin(self):
        api = _api(get_return={"userid": "alice@pmg", "role": "audit"})
        plan = plan_user_update(api, "alice@pmg", comment="hi")
        assert plan.risk == RISK_MEDIUM

    def test_capture_failure_fails_open_to_high(self):
        # Honest choice: cannot resolve effective role -> HIGH, never silently MEDIUM.
        api = _raising_get_api(ProximoError("boom"))
        plan = plan_user_update(api, "alice@pmg", comment="hi")
        assert plan.complete is False
        assert plan.risk == RISK_HIGH

    # -- Wave 9h review Critical fix: every branch of the fail-open resolution --------------

    def test_role_key_absent_from_successful_capture_fails_open_to_high(self):
        # Empirical repro 1 (branch b): the capture SUCCEEDS (complete would trivially be True
        # under the old logic) but the response is schema-plausible per Fact 3 and simply omits
        # 'role' entirely. Must NOT silently resolve MEDIUM.
        api = _api(get_return={"userid": "alice@pmg", "comment": "no role field returned by this PMG install"})
        plan = plan_user_update(api, "alice@pmg", comment="hi")
        assert plan.risk == RISK_HIGH
        assert plan.complete is False

    def test_role_value_none_fails_open_to_high(self):
        # Branch (c): the key IS present but null.
        api = _api(get_return={"userid": "alice@pmg", "role": None})
        plan = plan_user_update(api, "alice@pmg", comment="hi")
        assert plan.risk == RISK_HIGH
        assert plan.complete is False

    def test_unrecognized_future_role_string_fails_open_to_high(self):
        # Branch (f): a value that doesn't exactly match any known PMG role.
        api = _api(get_return={"userid": "alice@pmg", "role": "superduperrole"})
        plan = plan_user_update(api, "alice@pmg", comment="hi")
        assert plan.risk == RISK_HIGH
        assert plan.complete is False

    @pytest.mark.parametrize("role_value", ["Admin", "ADMIN", "Root"])
    def test_case_variant_of_admin_role_from_capture_is_high(self, role_value):
        # Branch (g): case-variant of an admin-equivalent role -> still HIGH.
        api = _api(get_return={"userid": "alice@pmg", "role": role_value})
        plan = plan_user_update(api, "alice@pmg", comment="hi")
        assert plan.risk == RISK_HIGH

    def test_known_admin_role_from_capture_is_high(self):
        # Branch (d), restated directly against the review's own repro shape.
        api = _api(get_return={"userid": "alice@pmg", "role": "admin"})
        plan = plan_user_update(api, "alice@pmg", comment="hi")
        assert plan.risk == RISK_HIGH

    def test_known_non_admin_role_from_capture_is_medium(self):
        # Branch (e): the ONLY branch allowed to resolve MEDIUM.
        api = _api(get_return={"userid": "alice@pmg", "role": "helpdesk"})
        plan = plan_user_update(api, "alice@pmg", comment="hi")
        assert plan.risk == RISK_MEDIUM
        assert plan.complete is True

    def test_enable_false_flagged(self):
        api = _api(get_return={"userid": "alice@pmg", "role": "audit"})
        plan = plan_user_update(api, "alice@pmg", enable=False)
        assert any("STOPS LOGIN" in b for b in plan.blast_radius)

    def test_no_password_param_accepted(self):
        import inspect
        params = inspect.signature(plan_user_update).parameters
        assert "password" not in params
        assert "crypt_pass" not in params
        assert "keys" not in params


class TestPlanUserDeleteLastAdminFootgun:
    def test_deleting_non_admin_no_warning(self):
        api = _api(get_return={"userid": "alice@pmg", "role": "audit"})
        plan = plan_user_delete(api, "alice@pmg")
        assert plan.risk == RISK_MEDIUM
        assert not any("LAST ENABLED ADMIN" in b for b in plan.blast_radius)

    def test_deleting_the_only_admin_warns(self, monkeypatch):
        import proximo.pmg_identity as pmg_identity

        api = _api(get_return={"userid": "alice@pmg", "role": "admin", "enable": True})
        monkeypatch.setattr(
            pmg_identity, "access_permissions",
            lambda api: [{"userid": "alice@pmg", "role": "admin", "enable": True}],
        )
        plan = plan_user_delete(api, "alice@pmg")
        assert any("LAST ENABLED ADMIN" in b for b in plan.blast_radius)
        assert any("lockout footgun" in r for r in plan.risk_reasons)

    def test_deleting_one_of_several_admins_no_warning(self, monkeypatch):
        import proximo.pmg_identity as pmg_identity

        api = _api(get_return={"userid": "alice@pmg", "role": "admin", "enable": True})
        monkeypatch.setattr(
            pmg_identity, "access_permissions",
            lambda api: [
                {"userid": "alice@pmg", "role": "admin", "enable": True},
                {"userid": "bob@pmg", "role": "root", "enable": True},
            ],
        )
        plan = plan_user_delete(api, "alice@pmg")
        assert not any("LAST ENABLED ADMIN" in b for b in plan.blast_radius)

    def test_disabled_admins_dont_count_toward_the_safety_net(self, monkeypatch):
        # A disabled admin can't log in either — deleting the last ENABLED admin is still the
        # footgun even if a disabled admin account technically still exists.
        import proximo.pmg_identity as pmg_identity

        api = _api(get_return={"userid": "alice@pmg", "role": "admin", "enable": True})
        monkeypatch.setattr(
            pmg_identity, "access_permissions",
            lambda api: [
                {"userid": "alice@pmg", "role": "admin", "enable": True},
                {"userid": "old@pmg", "role": "admin", "enable": False},
            ],
        )
        plan = plan_user_delete(api, "alice@pmg")
        assert any("LAST ENABLED ADMIN" in b for b in plan.blast_radius)

    def test_capture_failure_degrades_honestly(self):
        api = _raising_get_api(ProximoError("boom"))
        plan = plan_user_delete(api, "alice@pmg")
        assert plan.complete is False
        assert any("COULD NOT CONFIRM" in b for b in plan.blast_radius)

    # -- Wave 9h review Critical fix: every branch of the fail-open resolution --------------

    def test_role_key_absent_still_warns_via_list_fallback(self, monkeypatch):
        # Empirical repro 2 (branch b), byte-for-byte: alice IS genuinely the sole enabled admin
        # per the LIST, but the single-user GET (schema-thin) happens not to echo 'role' at all.
        # The last-admin warning must still fire -- this is the Critical finding's own repro.
        import proximo.pmg_identity as pmg_identity

        api = _api(get_return={"userid": "alice@pmg", "comment": "no role field in this GET response"})
        monkeypatch.setattr(
            pmg_identity, "access_permissions",
            lambda api: [{"userid": "alice@pmg", "role": "admin", "enable": True}],
        )
        plan = plan_user_delete(api, "alice@pmg")
        assert any("LAST ENABLED ADMIN" in b for b in plan.blast_radius)
        assert plan.risk == RISK_MEDIUM  # delete stays flat MEDIUM; only the warning changes

    def test_role_value_none_still_warns_via_list_fallback(self, monkeypatch):
        # Branch (c).
        import proximo.pmg_identity as pmg_identity

        api = _api(get_return={"userid": "alice@pmg", "role": None})
        monkeypatch.setattr(
            pmg_identity, "access_permissions",
            lambda api: [{"userid": "alice@pmg", "role": "admin", "enable": True}],
        )
        plan = plan_user_delete(api, "alice@pmg")
        assert any("LAST ENABLED ADMIN" in b for b in plan.blast_radius)

    def test_unrecognized_future_role_string_resolves_via_list_fallback(self, monkeypatch):
        # Branch (f).
        import proximo.pmg_identity as pmg_identity

        api = _api(get_return={"userid": "alice@pmg", "role": "superduperrole"})
        monkeypatch.setattr(
            pmg_identity, "access_permissions",
            lambda api: [{"userid": "alice@pmg", "role": "admin", "enable": True}],
        )
        plan = plan_user_delete(api, "alice@pmg")
        assert any("LAST ENABLED ADMIN" in b for b in plan.blast_radius)

    def test_case_variant_admin_role_in_capture_still_checks_last_admin(self, monkeypatch):
        # Branch (g).
        import proximo.pmg_identity as pmg_identity

        api = _api(get_return={"userid": "alice@pmg", "role": "Admin", "enable": True})
        monkeypatch.setattr(
            pmg_identity, "access_permissions",
            lambda api: [{"userid": "alice@pmg", "role": "admin", "enable": True}],
        )
        plan = plan_user_delete(api, "alice@pmg")
        assert any("LAST ENABLED ADMIN" in b for b in plan.blast_radius)

    def test_role_key_absent_but_list_confirms_non_admin_no_warning(self, monkeypatch):
        # The list resolves the ambiguity cleanly to non-admin -- no lockout risk, no warning,
        # and no need to fall back to the "could not confirm" caution either.
        import proximo.pmg_identity as pmg_identity

        api = _api(get_return={"userid": "alice@pmg", "comment": "no role field"})
        monkeypatch.setattr(
            pmg_identity, "access_permissions",
            lambda api: [{"userid": "alice@pmg", "role": "helpdesk", "enable": True}],
        )
        plan = plan_user_delete(api, "alice@pmg")
        assert not any("LAST ENABLED ADMIN" in b for b in plan.blast_radius)
        assert not any("COULD NOT CONFIRM" in b for b in plan.blast_radius)
        assert plan.complete is True

    def test_role_unresolvable_even_via_list_fails_open_with_explicit_warning(self, monkeypatch):
        # Option (b) fallback: the target isn't even in the list -- genuinely can't resolve;
        # must warn explicitly rather than silently proceeding as if non-admin.
        import proximo.pmg_identity as pmg_identity

        api = _api(get_return={"userid": "alice@pmg", "comment": "no role field"})
        monkeypatch.setattr(pmg_identity, "access_permissions", lambda api: [])
        plan = plan_user_delete(api, "alice@pmg")
        assert any("COULD NOT CONFIRM" in b for b in plan.blast_radius)
        assert plan.complete is False
        # Distinct from the real "sole admin" warning (whose text also contains the substring
        # "LAST ENABLED ADMIN") -- assert the actual affirmative marker didn't ALSO fire.
        assert not any("MAY BE THE LAST ENABLED ADMIN" in b for b in plan.blast_radius)


class TestPlanUserUnlockTfa:
    def test_is_high_matching_pbs_twin(self):
        # Wave 9h review Major 1: escalated from the dispatch instruction's MEDIUM to HIGH,
        # matching the shipped PBS twin (pbs_access.py's plan_tfa_unlock, RISK_HIGH for the
        # IDENTICAL wire endpoint) — no argued technical reason PMG's is less dangerous.
        plan = plan_user_unlock_tfa("alice@pmg")
        assert plan.risk == RISK_HIGH

    def test_is_pure_no_api_call_needed(self):
        # No `api` parameter at all — confirmed by signature.
        import inspect
        assert "api" not in inspect.signature(plan_user_unlock_tfa).parameters


# ---------------------------------------------------------------------------
# 4. Plan factories — TFA
# ---------------------------------------------------------------------------


def test_plan_tfa_add_is_medium():
    plan = plan_tfa_add("alice@pmg", "totp")
    assert plan.risk == RISK_MEDIUM


def test_plan_tfa_add_rejects_yubico():
    with pytest.raises(ProximoError):
        plan_tfa_add("alice@pmg", "yubico")


def test_plan_tfa_add_recovery_flags_one_time_codes():
    plan = plan_tfa_add("alice@pmg", "recovery")
    assert any("ONE-TIME recovery codes" in b for b in plan.blast_radius)


def test_plan_tfa_add_non_recovery_no_codes_mention():
    plan = plan_tfa_add("alice@pmg", "totp")
    assert not any("recovery codes" in b for b in plan.blast_radius)


def test_plan_tfa_update_captures_current():
    api = _api(get_return={"id": "totp1", "type": "totp", "enable": True})
    plan = plan_tfa_update(api, "alice@pmg", "totp1", enable=False)
    assert plan.risk == RISK_MEDIUM
    assert plan.current["id"] == "totp1"
    assert any("disables this factor" in b for b in plan.blast_radius)


def test_plan_tfa_update_degrades_honestly_on_capture_failure():
    api = _raising_get_api(ProximoError("boom"))
    plan = plan_tfa_update(api, "alice@pmg", "totp1")
    assert plan.complete is False


class TestPlanTfaDeleteMatchesPbsTwin:
    def test_is_high_matching_pbs_twin(self):
        # Fact 9: HIGH, matching the shipped PBS twin exactly — a reasoned upward divergence
        # from the draft's own un-argued MEDIUM guess.
        api = _api(get_return=[{"id": "totp1"}])
        plan = plan_tfa_delete(api, "alice@pmg", "totp1")
        assert plan.risk == RISK_HIGH

    def test_flags_last_factor_lockout(self):
        api = _api(get_return=[{"id": "totp1"}])
        plan = plan_tfa_delete(api, "alice@pmg", "totp1")
        assert any("LAST factor" in b for b in plan.blast_radius)

    def test_no_lockout_flag_when_multiple_factors(self):
        api = _api(get_return=[{"id": "totp1"}, {"id": "totp2"}])
        plan = plan_tfa_delete(api, "alice@pmg", "totp1")
        assert not any("LAST factor" in b for b in plan.blast_radius)

    def test_degrades_honestly_on_capture_failure(self):
        api = _raising_get_api(ProximoError("boom"))
        plan = plan_tfa_delete(api, "alice@pmg", "totp1")
        assert plan.complete is False
        assert plan.risk == RISK_HIGH  # unconditional, capture failure doesn't change the tier


# ===========================================================================
# CHUNK 9i — Global appliance config + cluster bootstrap/join
# ===========================================================================

# ---------------------------------------------------------------------------
# 5. Validators / helpers — 9i additions
# ---------------------------------------------------------------------------

class TestCheckDigestSha1:
    def test_none_passes_through(self):
        assert _check_digest_sha1(None) is None

    def test_valid_40_char_hex(self):
        assert _check_digest_sha1("a" * 40) == "a" * 40

    def test_rejects_64_char_digest(self):
        # the SHA256-shaped digest this module's OTHER config families use must NOT validate here
        with pytest.raises(ProximoError):
            _check_digest_sha1("a" * 64)

    def test_rejects_uppercase(self):
        with pytest.raises(ProximoError):
            _check_digest_sha1("A" * 40)

    def test_rejects_too_short(self):
        with pytest.raises(ProximoError):
            _check_digest_sha1("a" * 39)

    def test_rejects_trailing_newline(self):
        # A11 adjudication: this was the LAST digest validator still .strip()ping before its
        # \Z-anchored match — the strip re-admitted the trailing newline the anchor refuses.
        # Divergent shape (SHA-1), same strict no-strip law as every sibling.
        with pytest.raises(ProximoError):
            _check_digest_sha1("a" * 40 + "\n")

    def test_rejects_surrounding_whitespace(self):
        with pytest.raises(ProximoError):
            _check_digest_sha1(" " + "a" * 40)


class TestRedactPmgHttpProxy:
    def test_none_passes_through(self):
        assert _redact_pmg_http_proxy(None) is None

    def test_no_at_sign_passes_through_unchanged(self):
        assert _redact_pmg_http_proxy("http://proxy.example.com:8080") == "http://proxy.example.com:8080"

    def test_masks_userinfo_last_at_rsplit(self):
        out = _redact_pmg_http_proxy("http://user:pass@proxy.example.com:8080")
        assert out == "http://[redacted]@proxy.example.com:8080"
        assert "pass" not in out

    def test_password_containing_at_sign_fully_masked(self):
        # last-@ rsplit (never first) — a host part never legally contains '@' (RFC 3986).
        out = _redact_pmg_http_proxy("http://user:p@ss@proxy.example.com:8080")
        assert out == "http://[redacted]@proxy.example.com:8080"
        assert "p@ss" not in out
        assert "pass" not in out.replace("[redacted]", "")


class TestJoinPasswordRedactedDetail:
    def test_none_returns_empty(self):
        assert _join_password_redacted_detail(None) == {}

    def test_present_returns_redacted_marker_only(self):
        detail = _join_password_redacted_detail("real-password-value")
        assert detail == {"password": "[redacted]"}
        assert "real-password-value" not in str(detail)


class TestJoinDeleteAndDeletePropList:
    def test_join_delete_none(self):
        assert _join_delete(None) is None

    def test_join_delete_list(self):
        assert _join_delete(["a", "b"]) == "a,b"

    def test_join_delete_preformatted_string(self):
        assert _join_delete("a,b") == "a,b"

    def test_delete_prop_list_none(self):
        assert _delete_prop_list(None) == []

    def test_delete_prop_list_from_list(self):
        assert _delete_prop_list(["a", "b"]) == ["a", "b"]

    def test_delete_prop_list_from_comma_string(self):
        assert _delete_prop_list("a,b,c") == ["a", "b", "c"]


class TestRequireAtLeastOneConfigField:
    def test_raises_when_all_none_and_no_delete(self):
        with pytest.raises(ProximoError):
            _require_at_least_one_config_field("pmg_config_admin_update", {"a": None, "b": None}, None)

    def test_passes_with_one_field_set(self):
        _require_at_least_one_config_field("pmg_config_admin_update", {"a": None, "b": True}, None)

    def test_passes_with_delete_props_only(self):
        _require_at_least_one_config_field("pmg_config_admin_update", {"a": None}, ["a"])


class TestFlagIfNarrower:
    """Wave 9i review MAJOR fix: `_flag_if_narrower` is now tri-state on `current`'s usability —
    present-and-comparable / genuinely-absent-or-unusable-but-capture-succeeded (fails OPEN: warns
    + returns True) / genuinely-absent-or-unusable-but-capture-already-failed (stays silent —
    `capture_ok=False` means the caller's outer try/except already disclosed this via
    note_capture, so a second warning here would be redundant, not additive)."""

    def test_flags_when_new_lower_than_current(self):
        blast: list = []
        result = _flag_if_narrower(blast, {"archivemaxfiles": 1000}, "archivemaxfiles", 500, "archivemaxfiles")
        assert any("narrows" in b for b in blast)
        assert result is False

    def test_no_flag_when_new_higher(self):
        blast: list = []
        result = _flag_if_narrower(blast, {"archivemaxfiles": 1000}, "archivemaxfiles", 2000, "archivemaxfiles")
        assert blast == []
        assert result is False

    def test_undetermined_when_current_missing_and_capture_ok(self):
        blast: list = []
        result = _flag_if_narrower(
            blast, {}, "archivemaxfiles", 500, "archivemaxfiles", capture_ok=True,
        )
        assert any("could not confirm" in b for b in blast)
        assert result is True

    def test_silent_when_current_missing_and_capture_already_failed(self):
        blast: list = []
        result = _flag_if_narrower(
            blast, {}, "archivemaxfiles", 500, "archivemaxfiles", capture_ok=False,
        )
        assert blast == []
        assert result is False

    def test_undetermined_on_non_numeric_current_when_capture_ok(self):
        blast: list = []
        result = _flag_if_narrower(
            blast, {"archivemaxfiles": "not-a-number"}, "archivemaxfiles", 500, "archivemaxfiles",
            capture_ok=True,
        )
        assert any("could not confirm" in b for b in blast)
        assert result is True

    def test_silent_on_non_numeric_current_when_capture_already_failed(self):
        blast: list = []
        result = _flag_if_narrower(
            blast, {"archivemaxfiles": "not-a-number"}, "archivemaxfiles", 500, "archivemaxfiles",
            capture_ok=False,
        )
        assert blast == []
        assert result is False

    def test_default_capture_ok_is_true(self):
        """The default (no explicit capture_ok) fails OPEN — matches every other tri-state
        resolver in this module (`_classify_captured_role`'s own default posture)."""
        blast: list = []
        result = _flag_if_narrower(blast, {}, "archivemaxfiles", 500, "archivemaxfiles")
        assert result is True


# ---------------------------------------------------------------------------
# 6. Backend functions — 9i additions
# ---------------------------------------------------------------------------

class TestAdminConfigBackend:
    def test_get_path(self):
        api = _api(get_return={"email": "admin@x"})
        result = admin_config_get(api)
        assert api.seen["path"] == "/config/admin"
        assert result["email"] == "admin@x"

    def test_get_masks_http_proxy_when_present(self):
        api = _api(get_return={"http_proxy": "http://u:p@host:8080"})
        result = admin_config_get(api)
        assert result["http_proxy"] == "http://[redacted]@host:8080"

    def test_update_path_and_forwards_fields(self):
        api = _api()
        admin_config_update(api, demo=True, clamav=False)
        assert api.seen["method"] == "PUT"
        assert api.seen["path"] == "/config/admin"
        assert api.seen["data"]["demo"] is True
        assert api.seen["data"]["clamav"] is False

    def test_update_forwards_http_proxy_raw(self):
        api = _api()
        admin_config_update(api, http_proxy="http://u:p@host:8080")
        assert api.seen["data"]["http_proxy"] == "http://u:p@host:8080"

    def test_update_forwards_delete_and_digest(self):
        api = _api()
        admin_config_update(api, delete_props=["demo"], digest="a" * 64)
        assert api.seen["data"]["delete"] == "demo"
        assert api.seen["data"]["digest"] == "a" * 64

    def test_update_rejects_bad_digest(self):
        api = _api()
        with pytest.raises(ProximoError):
            admin_config_update(api, digest="not-hex")

    def test_update_wire_hyphenated_field_names(self):
        api = _api()
        admin_config_update(api, admin_mail_from="x@y", consent_text="hi", dkim_use_domain="header")
        assert api.seen["data"]["admin-mail-from"] == "x@y"
        assert api.seen["data"]["consent-text"] == "hi"
        assert api.seen["data"]["dkim-use-domain"] == "header"


class TestClamavConfigBackend:
    def test_get_path(self):
        api = _api(get_return={"scriptedupdates": True})
        clamav_config_get(api)
        assert api.seen["path"] == "/config/clamav"

    def test_update_forwards_fields(self):
        api = _api()
        clamav_config_update(api, archivemaxfiles=500, scriptedupdates=False)
        assert api.seen["path"] == "/config/clamav"
        assert api.seen["data"]["archivemaxfiles"] == 500
        assert api.seen["data"]["scriptedupdates"] is False


class TestMailConfigBackend:
    def test_update_path_and_wire_names(self):
        api = _api()
        mail_config_update(api, accept_broken_mime=True, filter_timeout=100, queue_lifetime=10, log_headers=True)
        assert api.seen["path"] == "/config/mail"
        assert api.seen["data"]["accept-broken-mime"] is True
        assert api.seen["data"]["filter-timeout"] == 100
        assert api.seen["data"]["queue-lifetime"] == 10
        assert api.seen["data"]["log-headers"] is True

    def test_update_forwards_relay_and_smarthost(self):
        api = _api()
        mail_config_update(api, relay="relay.example.com", smarthost="smarthost.example.com")
        assert api.seen["data"]["relay"] == "relay.example.com"
        assert api.seen["data"]["smarthost"] == "smarthost.example.com"

    def test_update_forwards_tls_and_spf(self):
        api = _api()
        mail_config_update(api, tls=False, spf=False)
        assert api.seen["data"]["tls"] is False
        assert api.seen["data"]["spf"] is False


class TestSpamquarConfigBackend:
    def test_get_path(self):
        api = _api(get_return={"authmode": "ldap"})
        spamquar_config_get(api)
        assert api.seen["path"] == "/config/spamquar"

    def test_update_forwards_quarantinelink_and_authmode(self):
        api = _api()
        spamquar_config_update(api, quarantinelink=True, authmode="ticket")
        assert api.seen["path"] == "/config/spamquar"
        assert api.seen["data"]["quarantinelink"] is True
        assert api.seen["data"]["authmode"] == "ticket"


class TestVirusquarConfigBackend:
    def test_get_path(self):
        api = _api(get_return={"allowhrefs": False})
        virusquar_config_get(api)
        assert api.seen["path"] == "/config/virusquar"

    def test_update_forwards_allowhrefs(self):
        api = _api()
        virusquar_config_update(api, allowhrefs=True)
        assert api.seen["path"] == "/config/virusquar"
        assert api.seen["data"]["allowhrefs"] is True


class TestTfaWebauthnConfigBackend:
    def test_get_path(self):
        api = _api(get_return={"rp": "PMG"})
        tfa_webauthn_config_get(api)
        assert api.seen["path"] == "/config/tfa/webauthn"

    def test_update_wire_field_and_id_underscore_mapping(self):
        api = _api()
        tfa_webauthn_config_update(api, id_="mail.example.com", origin="https://mail.example.com")
        assert api.seen["path"] == "/config/tfa/webauthn"
        assert api.seen["data"]["id"] == "mail.example.com"
        assert api.seen["data"]["origin"] == "https://mail.example.com"

    def test_update_uses_sha1_digest_not_sha256(self):
        api = _api()
        tfa_webauthn_config_update(api, digest="a" * 40)
        assert api.seen["data"]["digest"] == "a" * 40

    def test_update_rejects_64_char_digest(self):
        api = _api()
        with pytest.raises(ProximoError):
            tfa_webauthn_config_update(api, digest="a" * 64)


class TestClusterReadsBackend:
    def test_cluster_join_info_path(self):
        api = _api(get_return={"ip": "10.0.0.1", "fingerprint": "aa:bb"})
        result = cluster_join_info(api)
        assert api.seen["path"] == "/config/cluster/join"
        assert result["ip"] == "10.0.0.1"

    def test_cluster_nodes_list_path(self):
        api = _api(get_return=[{"cid": 1, "name": "node1"}])
        cluster_nodes_list(api)
        assert api.seen["path"] == "/config/cluster/nodes"

    def test_cluster_status_path_no_params(self):
        api = _api(get_return=[])
        cluster_status(api)
        assert api.seen["path"] == "/config/cluster/status"
        assert api.seen["params"] is None

    def test_cluster_status_forwards_list_single_node(self):
        api = _api(get_return=[])
        cluster_status(api, list_single_node=True)
        assert api.seen["params"] == {"list_single_node": True}


class TestClusterMutationsBackend:
    def test_cluster_create_path_no_body(self):
        api = _api()
        cluster_create(api)
        assert api.seen["method"] == "POST"
        assert api.seen["path"] == "/config/cluster/create"

    def test_cluster_join_forwards_all_three_required_fields(self):
        api = _api()
        cluster_join(api, "ab:cd", "10.0.0.5", "real-master-password")
        assert api.seen["path"] == "/config/cluster/join"
        assert api.seen["data"]["fingerprint"] == "ab:cd"
        assert api.seen["data"]["master_ip"] == "10.0.0.5"
        assert api.seen["data"]["password"] == "real-master-password"

    def test_cluster_node_add_forwards_required_fields(self):
        # _api()'s fake_post always returns None regardless of get_return (that fixture only
        # feeds _get) — cluster_node_add's `or []` fallback then yields an empty list; this
        # asserts the CALL shape (verb/path/data), not a fabricated non-fake return value.
        api = _api()
        result = cluster_node_add(api, "fp", "hostkey", "10.0.0.6", "node2", "rootkey")
        assert api.seen["path"] == "/config/cluster/nodes"
        assert api.seen["data"]["fingerprint"] == "fp"
        assert api.seen["data"]["hostrsapubkey"] == "hostkey"
        assert api.seen["data"]["ip"] == "10.0.0.6"
        assert api.seen["data"]["name"] == "node2"
        assert api.seen["data"]["rootrsapubkey"] == "rootkey"
        assert result == []

    def test_cluster_node_add_forwards_max_cid_only_when_given(self):
        api = _api(get_return=[])
        cluster_node_add(api, "fp", "hostkey", "10.0.0.6", "node2", "rootkey")
        assert "maxcid" not in api.seen["data"]
        cluster_node_add(api, "fp", "hostkey", "10.0.0.6", "node2", "rootkey", max_cid=5)
        assert api.seen["data"]["maxcid"] == 5

    def test_cluster_update_fingerprints_path_no_body(self):
        api = _api()
        cluster_update_fingerprints(api)
        assert api.seen["method"] == "POST"
        assert api.seen["path"] == "/config/cluster/update-fingerprints"


# ---------------------------------------------------------------------------
# 7. Plan factories — 9i additions
# ---------------------------------------------------------------------------

class TestPlanAdminConfigUpdate:
    def test_raises_when_no_fields(self):
        api = _api(get_return={})
        with pytest.raises(ProximoError):
            plan_admin_config_update(api)

    def test_is_medium(self):
        api = _api(get_return={})
        plan = plan_admin_config_update(api, demo=False)
        assert plan.risk == RISK_MEDIUM

    def test_flags_demo_true(self):
        api = _api(get_return={})
        plan = plan_admin_config_update(api, demo=True)
        assert any("STOPS THE SMTP FILTER" in b for b in plan.blast_radius)

    def test_no_demo_flag_when_demo_false(self):
        api = _api(get_return={})
        plan = plan_admin_config_update(api, demo=False)
        assert not any("STOPS THE SMTP FILTER" in b for b in plan.blast_radius)

    def test_flags_clamav_false(self):
        api = _api(get_return={})
        plan = plan_admin_config_update(api, clamav=False)
        assert any("disables ClamAV" in b for b in plan.blast_radius)

    def test_no_clamav_flag_when_clamav_true(self):
        api = _api(get_return={})
        plan = plan_admin_config_update(api, clamav=True)
        assert not any("disables ClamAV" in b for b in plan.blast_radius)

    def test_masks_http_proxy_in_display(self):
        api = _api(get_return={})
        plan = plan_admin_config_update(api, http_proxy="http://u:p@host:80")
        dumped = str(plan.blast_radius) + plan.change
        assert "http://u:p@host" not in dumped

    def test_discloses_delete_props(self):
        api = _api(get_return={})
        plan = plan_admin_config_update(api, delete_props=["demo", "email"])
        assert any("DELETES 'demo'" in b for b in plan.blast_radius)
        assert any("DELETES 'email'" in b for b in plan.blast_radius)

    def test_degrades_honestly_on_capture_failure(self):
        api = _raising_get_api(ProximoError("boom"))
        plan = plan_admin_config_update(api, demo=True)
        assert plan.complete is False


class TestPlanClamavConfigUpdate:
    def test_raises_when_no_fields(self):
        api = _api(get_return={})
        with pytest.raises(ProximoError):
            plan_clamav_config_update(api)

    def test_is_medium(self):
        api = _api(get_return={})
        plan = plan_clamav_config_update(api, scriptedupdates=True)
        assert plan.risk == RISK_MEDIUM

    def test_flags_archiveblockencrypted_weakening(self):
        api = _api(get_return={"archiveblockencrypted": True})
        plan = plan_clamav_config_update(api, archiveblockencrypted=False)
        assert any("encrypted-archive heuristic" in b for b in plan.blast_radius)

    def test_no_flag_when_archiveblockencrypted_was_already_off(self):
        api = _api(get_return={"archiveblockencrypted": False})
        plan = plan_clamav_config_update(api, archiveblockencrypted=False)
        assert not any("encrypted-archive heuristic" in b for b in plan.blast_radius)

    def test_flags_narrowing_scan_limit(self):
        api = _api(get_return={"archivemaxfiles": 1000})
        plan = plan_clamav_config_update(api, archivemaxfiles=100)
        assert any("narrows" in b for b in plan.blast_radius)
        assert plan.complete is True

    def test_no_flag_when_scan_limit_raised(self):
        api = _api(get_return={"archivemaxfiles": 1000})
        plan = plan_clamav_config_update(api, archivemaxfiles=2000)
        assert not any("narrows" in b for b in plan.blast_radius)
        assert plan.complete is True

    # -- Wave 9i review MAJOR fix: fail-open when a SUCCESSFUL capture omits the direction key --

    def test_archiveblockencrypted_undetermined_when_key_absent_on_successful_capture(self):
        api = _api(get_return={})  # capture SUCCEEDS (no exception) but key is genuinely absent
        plan = plan_clamav_config_update(api, archiveblockencrypted=False)
        assert any("could not confirm" in b for b in plan.blast_radius)
        assert plan.complete is False

    def test_archiveblockencrypted_no_duplicate_warning_on_capture_failure(self):
        api = _raising_get_api(ProximoError("boom"))
        plan = plan_clamav_config_update(api, archiveblockencrypted=False)
        # existing behavior unchanged: complete=False via the outer capture-failure branch, and
        # no DUPLICATE per-field "could not confirm" line (note_capture already discloses this).
        assert plan.complete is False
        assert not any("could not confirm" in b for b in plan.blast_radius)

    def test_scan_limit_undetermined_when_key_absent_on_successful_capture(self):
        api = _api(get_return={})
        plan = plan_clamav_config_update(api, archivemaxfiles=500)
        assert any("could not confirm" in b for b in plan.blast_radius)
        assert plan.complete is False

    def test_scan_limit_no_duplicate_warning_on_capture_failure(self):
        api = _raising_get_api(ProximoError("boom"))
        plan = plan_clamav_config_update(api, archivemaxfiles=500)
        assert plan.complete is False
        assert not any("could not confirm" in b for b in plan.blast_radius)


class TestPlanMailConfigUpdate:
    def test_raises_when_no_fields(self):
        api = _api(get_return={})
        with pytest.raises(ProximoError):
            plan_mail_config_update(api)

    def test_is_medium(self):
        api = _api(get_return={})
        plan = plan_mail_config_update(api, banner="hi")
        assert plan.risk == RISK_MEDIUM

    def test_flags_tls_false(self):
        api = _api(get_return={})
        plan = plan_mail_config_update(api, tls=False)
        assert any("disables TLS" in b for b in plan.blast_radius)

    def test_flags_spf_false(self):
        api = _api(get_return={})
        plan = plan_mail_config_update(api, spf=False)
        assert any("disables Sender Policy Framework" in b for b in plan.blast_radius)

    def test_flags_relay_change(self):
        api = _api(get_return={})
        plan = plan_mail_config_update(api, relay="new-relay.example.com")
        assert any("routing" in b.lower() for b in plan.blast_radius)

    def test_flags_smarthost_change(self):
        api = _api(get_return={})
        plan = plan_mail_config_update(api, smarthost="new-smarthost.example.com")
        assert any("routing" in b.lower() for b in plan.blast_radius)

    def test_no_routing_flag_when_neither_set(self):
        api = _api(get_return={})
        plan = plan_mail_config_update(api, banner="hi")
        assert not any("routing" in b.lower() for b in plan.blast_radius)

    def test_captures_via_relay_config_read(self):
        api = _api(get_return={"banner": "old-banner"})
        plan = plan_mail_config_update(api, banner="new-banner")
        assert plan.current["banner"] == "old-banner"

    def test_degrades_honestly_on_capture_failure(self):
        api = _raising_get_api(ProximoError("boom"))
        plan = plan_mail_config_update(api, banner="hi")
        assert plan.complete is False


class TestPlanSpamquarConfigUpdate:
    def test_raises_when_no_fields(self):
        api = _api(get_return={})
        with pytest.raises(ProximoError):
            plan_spamquar_config_update(api)

    def test_flags_quarantinelink_true(self):
        api = _api(get_return={})
        plan = plan_spamquar_config_update(api, quarantinelink=True)
        assert any("accessible without authentication" in b for b in plan.blast_radius)

    def test_no_flag_when_quarantinelink_false(self):
        api = _api(get_return={})
        plan = plan_spamquar_config_update(api, quarantinelink=False)
        assert not any("accessible without authentication" in b for b in plan.blast_radius)

    def test_flags_authmode_weakening_from_ldap(self):
        api = _api(get_return={"authmode": "ldap"})
        plan = plan_spamquar_config_update(api, authmode="ticket")
        assert any("authmode weakens" in b for b in plan.blast_radius)

    def test_flags_authmode_weakening_from_ldapticket(self):
        api = _api(get_return={"authmode": "ldapticket"})
        plan = plan_spamquar_config_update(api, authmode="ticket")
        assert any("authmode weakens" in b for b in plan.blast_radius)

    def test_no_flag_when_authmode_unchanged_direction(self):
        api = _api(get_return={"authmode": "ticket"})
        plan = plan_spamquar_config_update(api, authmode="ldap")
        assert not any("authmode weakens" in b for b in plan.blast_radius)
        assert plan.complete is True

    # -- Wave 9i review MAJOR fix: fail-open when a SUCCESSFUL capture omits `authmode` --

    def test_authmode_undetermined_when_key_absent_on_successful_capture(self):
        api = _api(get_return={})  # capture SUCCEEDS (no exception) but authmode is genuinely absent
        plan = plan_spamquar_config_update(api, authmode="ticket")
        assert any("could not confirm" in b for b in plan.blast_radius)
        assert plan.complete is False

    def test_authmode_no_duplicate_warning_on_capture_failure(self):
        api = _raising_get_api(ProximoError("boom"))
        plan = plan_spamquar_config_update(api, authmode="ticket")
        assert plan.complete is False
        assert not any("could not confirm" in b for b in plan.blast_radius)


class TestPlanVirusquarConfigUpdate:
    def test_raises_when_no_fields(self):
        api = _api(get_return={})
        with pytest.raises(ProximoError):
            plan_virusquar_config_update(api)

    def test_flags_allowhrefs_true(self):
        api = _api(get_return={})
        plan = plan_virusquar_config_update(api, allowhrefs=True)
        assert any("phishing" in b for b in plan.blast_radius)

    def test_no_flag_when_allowhrefs_false(self):
        api = _api(get_return={})
        plan = plan_virusquar_config_update(api, allowhrefs=False)
        assert not any("phishing" in b for b in plan.blast_radius)


class TestPlanTfaWebauthnConfigUpdate:
    def test_raises_when_no_fields(self):
        api = _api(get_return={})
        with pytest.raises(ProximoError):
            plan_tfa_webauthn_config_update(api)

    def test_flags_id_change_will_break(self):
        api = _api(get_return={})
        plan = plan_tfa_webauthn_config_update(api, id_="mail.example.com")
        assert any("WILL break existing WebAuthn credentials" in b for b in plan.blast_radius)

    def test_flags_origin_change_may_break(self):
        api = _api(get_return={})
        plan = plan_tfa_webauthn_config_update(api, origin="https://mail.example.com")
        assert any("MAY break existing WebAuthn credentials" in b for b in plan.blast_radius)

    def test_flags_rp_change_may_break(self):
        api = _api(get_return={})
        plan = plan_tfa_webauthn_config_update(api, rp="PMG")
        assert any("MAY break existing WebAuthn credentials" in b for b in plan.blast_radius)

    def test_no_break_flags_when_only_allow_subdomains_changes(self):
        api = _api(get_return={})
        plan = plan_tfa_webauthn_config_update(api, allow_subdomains=False)
        assert not any("break existing WebAuthn credentials" in b for b in plan.blast_radius)


class TestPlanClusterCreate:
    def test_is_high(self):
        api = _api(get_return=[{"cid": 0}])
        plan = plan_cluster_create(api)
        assert plan.risk == RISK_HIGH

    def test_first_blast_line_is_no_undo(self):
        api = _api(get_return=[{"cid": 0}])
        plan = plan_cluster_create(api)
        assert "NO UNDO" in plan.blast_radius[0]
        assert "visibility into un-clustering" in plan.blast_radius[0]

    def test_no_backup_escape_hatch_claimed(self):
        api = _api(get_return=[{"cid": 0}])
        plan = plan_cluster_create(api)
        dumped = " ".join(plan.blast_radius)
        assert "pmg_backup_create" not in dumped

    def test_flags_when_already_multi_node(self):
        api = _api(get_return=[{"cid": 0}, {"cid": 1}])
        plan = plan_cluster_create(api)
        assert any("already" in b for b in plan.blast_radius)

    def test_degrades_honestly_on_capture_failure(self):
        api = _raising_get_api(ProximoError("boom"))
        plan = plan_cluster_create(api)
        assert plan.complete is False
        assert plan.risk == RISK_HIGH  # unconditional


class TestPlanClusterJoin:
    def test_is_high(self):
        api = _api(get_return=[{"cid": 0}])
        plan = plan_cluster_join(api, "ab:cd", "10.0.0.5")
        assert plan.risk == RISK_HIGH

    def test_first_blast_line_is_no_undo(self):
        api = _api(get_return=[{"cid": 0}])
        plan = plan_cluster_join(api, "ab:cd", "10.0.0.5")
        assert "NO UNDO" in plan.blast_radius[0]

    def test_flags_third_party_credential(self):
        api = _api(get_return=[{"cid": 0}])
        plan = plan_cluster_join(api, "ab:cd", "10.0.0.5")
        dumped = " ".join(plan.blast_radius)
        assert "THIRD-PARTY" in dumped
        assert "superuser password" in dumped

    def test_signature_takes_no_password_param(self):
        # deliberate discipline: the plan factory must not even be ABLE to receive the secret.
        import inspect
        sig = inspect.signature(plan_cluster_join)
        assert "password" not in sig.parameters

    def test_degrades_honestly_on_capture_failure(self):
        api = _raising_get_api(ProximoError("boom"))
        plan = plan_cluster_join(api, "ab:cd", "10.0.0.5")
        assert plan.complete is False
        assert plan.risk == RISK_HIGH  # unconditional


class TestPlanClusterNodeAdd:
    def test_is_medium(self):
        plan = plan_cluster_node_add("fp", "hostkey", "10.0.0.6", "node2", "rootkey")
        assert plan.risk == RISK_MEDIUM

    def test_names_node_in_change(self):
        plan = plan_cluster_node_add("fp", "hostkey", "10.0.0.6", "node2", "rootkey")
        assert "node2" in plan.change
        assert "10.0.0.6" in plan.change


class TestPlanClusterUpdateFingerprints:
    def test_is_medium(self):
        plan = plan_cluster_update_fingerprints()
        assert plan.risk == RISK_MEDIUM
        assert plan.risk != RISK_HIGH
