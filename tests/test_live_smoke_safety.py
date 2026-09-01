"""Unit tests for the live-smoke prod-target guard (`scripts/live-smoke/safety.py`).

The guard is the SECOND, code-level safety layer for the mutate/destroy live-smoke tier:
it refuses to operate on any VMID/storage that is not explicitly allowlisted as a test
target (default-deny). It must NOT hardcode production identifiers — an allowlist names
only the test surface, so prod is refused by construction without ever being named (which
also keeps this public-shipping file leak-free).

Loaded via importlib because `scripts/live-smoke/` is not an importable package — mirrors
`tests/test_live_smoke_orchestrator.py`.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_PATH = Path(__file__).parent.parent / "scripts" / "live-smoke" / "safety.py"
_spec = importlib.util.spec_from_file_location("live_smoke_safety", _PATH)
safety = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = safety
_spec.loader.exec_module(safety)


# --- parse_vmid_range ---------------------------------------------------------

def test_parse_range_well_formed():
    assert safety.parse_vmid_range("90000-90099") == (90000, 90099)


def test_parse_range_empty_is_none():
    assert safety.parse_vmid_range("") is None
    assert safety.parse_vmid_range("   ") is None


def test_parse_range_malformed_raises():
    with pytest.raises(safety.SmokeSafetyError):
        safety.parse_vmid_range("garbage")


def test_parse_range_inverted_bounds_raises():
    with pytest.raises(safety.SmokeSafetyError):
        safety.parse_vmid_range("90099-90000")


# --- Allowlist membership -----------------------------------------------------

def test_explicit_vmid_permitted():
    al = safety.Allowlist(vmids=frozenset({100, 101, 102}), vmid_range=None, storages=frozenset({"test"}))
    assert al.permits_vmid(100) is True


def test_range_vmid_permitted_inclusive():
    al = safety.Allowlist(vmids=frozenset(), vmid_range=(90000, 90099), storages=frozenset())
    assert al.permits_vmid(90000) is True   # lower bound inclusive
    assert al.permits_vmid(90099) is True   # upper bound inclusive
    assert al.permits_vmid(90050) is True


def test_vmid_outside_both_refused():
    al = safety.Allowlist(vmids=frozenset({100}), vmid_range=(90000, 90099), storages=frozenset())
    assert al.permits_vmid(101) is False     # a prod CTID — refused, never named in source


# --- assert_test_target (the guard the smokes/orchestrator call) --------------

def test_assert_allows_test_vmid_and_storage():
    al = safety.Allowlist(vmids=frozenset({100}), vmid_range=None, storages=frozenset({"test"}))
    # must not raise
    safety.assert_test_target(al, vmid=100, storage="test")


def test_assert_refuses_prod_vmid_without_naming_others():
    al = safety.Allowlist(vmids=frozenset({100}), vmid_range=(90000, 90099), storages=frozenset({"test"}))
    with pytest.raises(safety.SmokeSafetyError) as ei:
        safety.assert_test_target(al, vmid=102)   # a prod CTID
    msg = str(ei.value)
    assert "102" in msg                      # names the rejected target
    assert "101" not in msg and "8007" not in msg   # does NOT leak other prod ids


def test_assert_refuses_prod_storage():
    al = safety.Allowlist(vmids=frozenset({100}), vmid_range=None, storages=frozenset({"test"}))
    with pytest.raises(safety.SmokeSafetyError):
        safety.assert_test_target(al, vmid=100, storage="local-lvm")   # prod storage


def test_assert_normalizes_string_vmid():
    # smokes read env strings; the guard must coerce before comparing
    al = safety.Allowlist(vmids=frozenset({100}), vmid_range=None, storages=frozenset({"test"}))
    safety.assert_test_target(al, vmid="100")           # allowed, no raise
    with pytest.raises(safety.SmokeSafetyError):
        safety.assert_test_target(al, vmid="101")


def test_assert_default_deny_empty_allowlist():
    al = safety.Allowlist(vmids=frozenset(), vmid_range=None, storages=frozenset())
    with pytest.raises(safety.SmokeSafetyError):
        safety.assert_test_target(al, vmid=100)


def test_assert_noop_when_nothing_to_check():
    al = safety.Allowlist(vmids=frozenset(), vmid_range=None, storages=frozenset())
    # passing neither vmid nor storage checks nothing — harmless no-op
    safety.assert_test_target(al)


# --- load_allowlist (env-driven config) ---------------------------------------

def test_load_allowlist_from_env():
    env = {
        "PROXIMO_SMOKE_TEST_VMIDS": "100, 101 ,102",
        "PROXIMO_SMOKE_VMID_RANGE": "90000-90099",
        "PROXIMO_SMOKE_TEST_STORAGES": "test, scratch",
    }
    al = safety.load_allowlist(env)
    assert al.vmids == frozenset({100, 101, 102})
    assert al.vmid_range == (90000, 90099)
    assert al.storages == frozenset({"test", "scratch"})


def test_load_allowlist_defaults_storage_to_test():
    al = safety.load_allowlist({})
    assert al.storages == frozenset({"test"})
    assert al.vmids == frozenset()
    assert al.vmid_range is None


# --- PBS endpoint guard (refuse prod PBS) -------------------------------------

def test_pbs_host_parses_host_and_port():
    assert safety.pbs_host("https://pbs-test:8007/api2/json") == "pbs-test"
    assert safety.pbs_host("https://192.0.2.7:8007/api2/json") == "192.0.2.7"


def test_pbs_host_garbage_raises():
    with pytest.raises(safety.SmokeSafetyError):
        safety.pbs_host("not-a-url")


def test_assert_test_pbs_allows_allowlisted_host():
    safety.assert_test_pbs("https://pbs-test:8007/api2/json", frozenset({"pbs-test"}))  # no raise


def test_assert_test_pbs_refuses_prod_without_naming_others():
    with pytest.raises(safety.SmokeSafetyError) as ei:
        safety.assert_test_pbs("https://192.0.2.7:8007/api2/json", frozenset({"pbs-test"}))
    msg = str(ei.value)
    assert "192.0.2.7" in msg            # names the rejected host
    assert "pbs-test" not in msg          # does not echo the allowed/test names back


def test_assert_test_pbs_default_deny_empty_allowlist():
    with pytest.raises(safety.SmokeSafetyError):
        safety.assert_test_pbs("https://pbs-test:8007/api2/json", frozenset())


def test_load_pbs_allowlist_from_env():
    al = safety.load_pbs_allowlist({"PROXIMO_SMOKE_PBS_HOSTS": "pbs-test, pbs-test.localdomain"})
    assert al == frozenset({"pbs-test", "pbs-test.localdomain"})


def test_load_pbs_allowlist_empty_is_empty():
    assert safety.load_pbs_allowlist({}) == frozenset()


# --- access-CRUD identity guard (refuse prod users/roles/tokens) ---------------
# The access-mgmt token CANNOT be ACL-scoped to "test identities only" (PVE has no such scoping), so
# this code guard is the SOLE safety layer: a smoke may only create/delete identities whose name starts
# with an allowlisted test prefix. Default-deny — every prod identity is refused by omission.

def test_assert_identity_allows_test_prefixed_user():
    safety.assert_test_identity("proximo-cismoke@pbs", frozenset({"proximo-cismoke"}))  # no raise


def test_assert_identity_allows_test_prefixed_role():
    safety.assert_test_identity("ProximoCISmoke", frozenset({"ProximoCISmoke"}))  # no raise


def test_assert_identity_refuses_prod_user():
    for prod in ("root@pam", "proximo@pve", "claude@pam"):
        with pytest.raises(safety.SmokeSafetyError):
            safety.assert_test_identity(prod, frozenset({"proximo-cismoke"}))


def test_assert_identity_refuses_prod_role():
    # the test prefix must not be a prefix OF a prod role — ProximoTest must be refused
    with pytest.raises(safety.SmokeSafetyError):
        safety.assert_test_identity("ProximoTest", frozenset({"ProximoCISmoke"}))


def test_assert_identity_default_deny_empty_allowlist():
    with pytest.raises(safety.SmokeSafetyError):
        safety.assert_test_identity("proximo-cismoke@pbs", frozenset())


def test_assert_identity_message_names_only_the_rejected():
    with pytest.raises(safety.SmokeSafetyError) as ei:
        safety.assert_test_identity("root@pam", frozenset({"proximo-cismoke"}))
    assert "root@pam" in str(ei.value)
    assert "proximo@pve" not in str(ei.value) and "claude@pam" not in str(ei.value)


def test_load_identity_allowlist_from_env():
    al = safety.load_identity_allowlist({"PROXIMO_SMOKE_IDENTITY_PREFIXES": "proximo-cismoke, ProximoCISmoke"})
    assert al == frozenset({"proximo-cismoke", "ProximoCISmoke"})


def test_load_identity_allowlist_empty_is_empty():
    assert safety.load_identity_allowlist({}) == frozenset()
