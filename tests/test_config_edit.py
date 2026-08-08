"""GUEST CONFIG EDIT tests — fully mocked, no live Proxmox.

Mirrors test_provisioning.py / test_backup.py:
- Op tests: SimpleNamespace fakes that record _get / _client.request / _auth_header calls.
- Plan tests: fakes that supply _get + config.node.
- Validator tests: pytest.raises(ProximoError).

Axes covered:
- URL / param construction for GET and PUT.
- plan_config_get: pure, no I/O.
- plan_config_set: diff, blast_radius, risk, reboot hint, read-error resilience.
- plan_config_revert: validation, diff, to_delete, read-error resilience.
- guest_config_get: path + return.
- guest_config_set: prior capture, PUT body, digest forwarding, delete param.
- guest_config_revert: strip-computed, allowlist enforcement, delete-key computation.
- Validator rejects: bad vmid/kind/node, disallowed keys, None prior_config.
- PLAN-before-mutation contract: plan functions can be called independently of the op
  and surface honest facts (including read-error uncertainty).
- UNDO capture: guest_config_set returns prior_config in its result.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from proximo.backends import ProximoError
from proximo.config_edit import (
    _allowed_key,
    _strip_computed,
    guest_config_get,
    guest_config_revert,
    guest_config_set,
    plan_config_get,
    plan_config_revert,
    plan_config_set,
)
from proximo.planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM

# ---------------------------------------------------------------------------
# Test fakes
# ---------------------------------------------------------------------------

def _fake_api(node: str = "pve", config_data: dict | None = None,
              raise_on_get: bool = False):
    """Fake api with _get, _client.request, _auth_header, and config.node.

    put_calls accumulates (path, data) tuples to assert against.
    """
    cfg = config_data if config_data is not None else {
        "cores": 2, "memory": 512, "onboot": 1, "digest": "deadbeef",
    }
    put_calls: list[tuple[str, dict]] = []

    def fake_get(path):
        if raise_on_get:
            raise RuntimeError("simulated get failure")
        return dict(cfg)

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": None}

    class FakeClient:
        def request(self, method, path, headers=None, data=None):
            put_calls.append((method, path, dict(data or {})))
            return FakeResponse()

    def fake_auth():
        return {"Authorization": "PVEAPIToken=fake"}

    client = FakeClient()

    def fake_form(d):
        # mirror ApiBackend._form: bool->1/0, drop None
        return {k: (1 if v is True else 0 if v is False else v)
                for k, v in (d or {}).items() if v is not None}

    def fake_put(path, data=None):
        # mirror ApiBackend._put so _put_config exercises the real coercion path
        r = client.request("PUT", path, headers=fake_auth(), data=fake_form(data))
        return r.json().get("data")

    api = SimpleNamespace(
        config=SimpleNamespace(node=node),
        _get=fake_get,
        _client=client,
        _auth_header=fake_auth,
        _put=fake_put,
        put_calls=put_calls,
    )
    return api


# ---------------------------------------------------------------------------
# _allowed_key — unit tests (no API call)
# ---------------------------------------------------------------------------

def test_allowed_key_cores_both_kinds():
    assert _allowed_key("cores", "lxc")
    assert _allowed_key("cores", "qemu")


def test_allowed_key_memory_both_kinds():
    assert _allowed_key("memory", "lxc")
    assert _allowed_key("memory", "qemu")


def test_allowed_key_net_indexed_allowed():
    assert _allowed_key("net0", "lxc")
    assert _allowed_key("net3", "qemu")


def test_allowed_key_net_without_digit_denied():
    assert not _allowed_key("net", "lxc")


def test_allowed_key_rootfs_denied():
    assert not _allowed_key("rootfs", "lxc")


def test_allowed_key_hookscript_denied():
    assert not _allowed_key("hookscript", "lxc")


def test_allowed_key_args_denied():
    assert not _allowed_key("args", "qemu")


def test_allowed_key_features_denied():
    assert not _allowed_key("features", "lxc")


def test_allowed_key_unprivileged_denied():
    assert not _allowed_key("unprivileged", "lxc")


def test_allowed_key_description_both_kinds():
    assert _allowed_key("description", "lxc")
    assert _allowed_key("description", "qemu")


def test_allowed_key_onboot_both_kinds():
    assert _allowed_key("onboot", "lxc")
    assert _allowed_key("onboot", "qemu")


def test_allowed_key_hostname_lxc_only():
    assert _allowed_key("hostname", "lxc")
    assert not _allowed_key("hostname", "qemu")


def test_allowed_key_name_qemu_only():
    assert _allowed_key("name", "qemu")
    assert not _allowed_key("name", "lxc")


def test_allowed_key_mp0_denied():
    assert not _allowed_key("mp0", "lxc")


def test_allowed_key_scsi0_denied():
    assert not _allowed_key("scsi0", "qemu")


# ---------------------------------------------------------------------------
# _strip_computed — unit tests
# ---------------------------------------------------------------------------

def test_strip_computed_removes_digest():
    result = _strip_computed({"digest": "abc", "cores": 2})
    assert "digest" not in result
    assert result["cores"] == 2


def test_strip_computed_removes_lock():
    result = _strip_computed({"lock": "migrate", "memory": 512})
    assert "lock" not in result


def test_strip_computed_removes_lxc_dot_keys():
    result = _strip_computed({"lxc.1": "lxc.cgroup2.devices.deny", "onboot": 1})
    assert "lxc.1" not in result
    assert "onboot" in result


def test_strip_computed_leaves_safe_keys():
    d = {"cores": 4, "memory": 1024, "description": "hi"}
    assert _strip_computed(d) == d


# ---------------------------------------------------------------------------
# guest_config_get — path shape
# ---------------------------------------------------------------------------

def test_guest_config_get_builds_correct_lxc_path():
    seen: list[str] = []
    api = _fake_api()
    api._get = lambda path: seen.append(path) or {"cores": 2}
    guest_config_get(api, "102")
    assert len(seen) == 1
    assert seen[0] == "/nodes/pve/lxc/102/config"


def test_guest_config_get_builds_correct_qemu_path():
    seen: list[str] = []
    api = _fake_api()
    api._get = lambda path: seen.append(path) or {}
    guest_config_get(api, "200", kind="qemu")
    assert seen[0] == "/nodes/pve/qemu/200/config"


def test_guest_config_get_uses_explicit_node():
    seen: list[str] = []
    api = _fake_api(node="pve2")
    api._get = lambda path: seen.append(path) or {}
    guest_config_get(api, "102", node="pve1")
    assert "/nodes/pve1/" in seen[0]


def test_guest_config_get_uses_config_node_when_none():
    seen: list[str] = []
    api = _fake_api(node="nodeX")
    api._get = lambda path: seen.append(path) or {}
    guest_config_get(api, "102")
    assert "/nodes/nodeX/" in seen[0]


def test_guest_config_get_returns_dict():
    api = _fake_api(config_data={"cores": 4, "memory": 1024})
    result = guest_config_get(api, "102")
    assert result["cores"] == 4


def test_guest_config_get_rejects_nonnumeric_vmid():
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_get(api, "abc")


def test_guest_config_get_rejects_bad_kind():
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_get(api, "102", kind="docker")


def test_guest_config_get_rejects_invalid_node():
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_get(api, "102", node="bad/node")


# ---------------------------------------------------------------------------
# guest_config_set — path, PUT body, prior capture, digest, delete param
# ---------------------------------------------------------------------------

def test_put_config_coerces_bool_and_drops_none():
    # M8/L11: _put_config must route through _form — a bool reaches the wire as 1/0, None is omitted
    from proximo.config_edit import _put_config
    api = _fake_api()
    _put_config(api, "/nodes/pve/lxc/102/config", {"onboot": True, "skip": None})
    _, _, data = api.put_calls[0]
    assert data["onboot"] == 1
    assert data["onboot"] is not True
    assert "skip" not in data


def test_guest_config_set_issues_put_to_correct_lxc_path():
    api = _fake_api()
    guest_config_set(api, "102", {"cores": 4})
    assert len(api.put_calls) == 1
    method, path, _ = api.put_calls[0]
    assert method == "PUT"
    assert path == "/nodes/pve/lxc/102/config"


def test_guest_config_set_issues_put_to_correct_qemu_path():
    api = _fake_api()
    guest_config_set(api, "200", {"cores": 4}, kind="qemu")
    method, path, _ = api.put_calls[0]
    assert path == "/nodes/pve/qemu/200/config"


def test_guest_config_set_uses_explicit_node():
    api = _fake_api(node="pve2")
    guest_config_set(api, "102", {"cores": 4}, node="pve1")
    _, path, _ = api.put_calls[0]
    assert "/nodes/pve1/" in path


def test_guest_config_set_uses_config_node_when_none():
    api = _fake_api(node="nodeY")
    guest_config_set(api, "102", {"cores": 4})
    _, path, _ = api.put_calls[0]
    assert "/nodes/nodeY/" in path


def test_guest_config_set_puts_changed_keys():
    api = _fake_api(config_data={"cores": 2, "digest": "abc"})
    guest_config_set(api, "102", {"cores": 8, "memory": 1024})
    _, _, data = api.put_calls[0]
    assert data["cores"] == 8
    assert data["memory"] == 1024


def test_guest_config_set_forwards_digest_for_optimistic_lock():
    api = _fake_api(config_data={"cores": 2, "digest": "deadbeef"})
    guest_config_set(api, "102", {"cores": 4})
    _, _, data = api.put_calls[0]
    assert data["digest"] == "deadbeef"


def test_guest_config_set_no_digest_when_absent_in_config():
    api = _fake_api(config_data={"cores": 2})  # no digest
    guest_config_set(api, "102", {"cores": 4})
    _, _, data = api.put_calls[0]
    assert "digest" not in data


def test_guest_config_set_delete_param_for_none_values():
    api = _fake_api(config_data={"cores": 2, "description": "old", "digest": "x"})
    guest_config_set(api, "102", {"description": None})
    _, _, data = api.put_calls[0]
    assert "delete" in data
    assert "description" in data["delete"]


def test_guest_config_set_no_delete_param_when_no_none_values():
    api = _fake_api()
    guest_config_set(api, "102", {"cores": 4})
    _, _, data = api.put_calls[0]
    assert "delete" not in data


def test_guest_config_set_returns_prior_config():
    api = _fake_api(config_data={"cores": 2, "memory": 512, "digest": "abc"})
    result = guest_config_set(api, "102", {"cores": 4})
    assert "prior_config" in result
    assert result["prior_config"]["cores"] == 2


def test_guest_config_set_returns_applied_keys():
    api = _fake_api()
    result = guest_config_set(api, "102", {"cores": 4, "memory": 1024})
    assert "cores" in result["applied"]
    assert "memory" in result["applied"]


def test_guest_config_set_returns_deleted_keys():
    api = _fake_api(config_data={"description": "x", "digest": "y"})
    result = guest_config_set(api, "102", {"description": None})
    assert "description" in result["deleted"]


def test_guest_config_set_rejects_disallowed_key():
    api = _fake_api()
    with pytest.raises(ProximoError, match="disallowed"):
        guest_config_set(api, "102", {"hookscript": "local:snippets/evil.sh"})


def test_guest_config_set_rejects_rootfs():
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_set(api, "102", {"rootfs": "local-lvm:8"})


def test_guest_config_set_rejects_nonnumeric_vmid():
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_set(api, "abc", {"cores": 4})


def test_guest_config_set_rejects_bad_kind():
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_set(api, "102", {"cores": 4}, kind="kvm")


def test_guest_config_set_rejects_invalid_node():
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_set(api, "102", {"cores": 4}, node="node\ninjected")


def test_guest_config_set_rejects_non_dict_changes():
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_set(api, "102", "cores=4")  # type: ignore[arg-type]


def test_guest_config_set_rejects_hostname_on_qemu():
    """hostname is LXC-only; QEMU guests must reject it."""
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_set(api, "200", {"hostname": "mything"}, kind="qemu")


def test_guest_config_set_allows_hostname_on_lxc():
    api = _fake_api()
    result = guest_config_set(api, "102", {"hostname": "mybox"}, kind="lxc")
    assert "hostname" in result["applied"]


def test_guest_config_set_rejects_name_on_lxc():
    """name is QEMU-only; LXC must reject it."""
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_set(api, "102", {"name": "mybox"}, kind="lxc")


def test_guest_config_set_allows_name_on_qemu():
    api = _fake_api()
    result = guest_config_set(api, "200", {"name": "myvm"}, kind="qemu")
    assert "name" in result["applied"]


# ---------------------------------------------------------------------------
# guest_config_revert — strip computed, allowlist, delete computation
# ---------------------------------------------------------------------------

def test_guest_config_revert_issues_put_to_correct_path():
    prior = {"cores": 2, "memory": 512}
    api = _fake_api(config_data={"cores": 4, "memory": 1024, "digest": "x"})
    guest_config_revert(api, "102", prior)
    method, path, _ = api.put_calls[0]
    assert method == "PUT"
    assert path == "/nodes/pve/lxc/102/config"


def test_guest_config_revert_restores_prior_values():
    prior = {"cores": 2, "memory": 512}
    api = _fake_api(config_data={"cores": 4, "memory": 1024, "digest": "xyz"})
    guest_config_revert(api, "102", prior)
    _, _, data = api.put_calls[0]
    assert data["cores"] == 2
    assert data["memory"] == 512


def test_guest_config_revert_strips_digest_from_prior_and_uses_current_digest():
    # prior_config may carry an old digest; we must forward the CURRENT digest.
    prior = {"cores": 2, "digest": "olddigest"}
    api = _fake_api(config_data={"cores": 4, "digest": "currentdigest"})
    guest_config_revert(api, "102", prior)
    _, _, data = api.put_calls[0]
    assert data["digest"] == "currentdigest"
    # The old digest must not go into the body as a data key alongside current
    # (it IS included once via the current-digest path)
    count = sum(1 for (_, _, d) in api.put_calls if d.get("digest") == "olddigest")
    assert count == 0


def test_guest_config_revert_deletes_keys_absent_from_prior():
    # "description" exists now but was absent in prior -> should be in delete param.
    prior = {"cores": 2, "memory": 512}
    api = _fake_api(config_data={"cores": 4, "memory": 1024,
                                  "description": "old", "digest": "x"})
    guest_config_revert(api, "102", prior)
    _, _, data = api.put_calls[0]
    assert "delete" in data
    assert "description" in data["delete"]


def test_guest_config_revert_no_delete_when_prior_has_all_keys():
    prior = {"cores": 2, "memory": 512, "onboot": 1}
    api = _fake_api(config_data={"cores": 4, "memory": 1024, "onboot": 0, "digest": "x"})
    guest_config_revert(api, "102", prior)
    _, _, data = api.put_calls[0]
    assert "delete" not in data


def test_guest_config_revert_returns_reverted_keys():
    prior = {"cores": 2, "memory": 512}
    api = _fake_api(config_data={"cores": 4, "memory": 1024, "digest": "x"})
    result = guest_config_revert(api, "102", prior)
    assert "cores" in result["reverted_to_keys"]
    assert "memory" in result["reverted_to_keys"]


def test_guest_config_revert_returns_deleted():
    prior = {"cores": 2}
    api = _fake_api(config_data={"cores": 4, "description": "bye", "digest": "x"})
    result = guest_config_revert(api, "102", prior)
    assert "description" in result["deleted"]


def test_guest_config_revert_drops_disallowed_key_in_prior():
    # A prior snapshot containing a non-settable/dangerous key must NOT be applied — revert
    # restores only the safe allowlisted subset (dropping is safer than refusing and lets revert
    # work on real configs). The dangerous key never reaches the PUT body.
    prior = {"cores": 2, "hookscript": "local:snippets/evil.sh"}
    api = _fake_api(config_data={"cores": 4})
    result = guest_config_revert(api, "102", prior)
    _, _, data = api.put_calls[0]
    assert "hookscript" not in data          # dropped, never written
    assert data["cores"] == 2                # safe key still reverted
    assert "hookscript" in result["skipped_unsettable"]


def test_guest_config_revert_skips_pve_managed_keys_from_real_config():
    # Regression (live-found 2026-06-08): a real QEMU config GET carries auto-generated keys
    # (meta, smbios1, vmgenid) that the SET allowlist refuses. Revert must SKIP them, not fail.
    prior = {"cores": 1, "meta": "creation-qemu=9.0", "smbios1": "uuid=abc", "vmgenid": "def"}
    api = _fake_api(config_data={"cores": 2})
    result = guest_config_revert(api, "102", prior)  # must NOT raise
    _, _, data = api.put_calls[0]
    assert data["cores"] == 1
    for k in ("meta", "smbios1", "vmgenid"):
        assert k not in data
        assert k in result["skipped_unsettable"]


def test_guest_config_revert_rejects_non_dict_prior():
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_revert(api, "102", "not-a-dict")  # type: ignore[arg-type]


def test_guest_config_revert_rejects_nonnumeric_vmid():
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_revert(api, "bad", {"cores": 2})


def test_guest_config_revert_rejects_bad_kind():
    api = _fake_api()
    with pytest.raises(ProximoError):
        guest_config_revert(api, "102", {"cores": 2}, kind="xen")


# ---------------------------------------------------------------------------
# plan_config_get — pure, no API call
# ---------------------------------------------------------------------------

def test_plan_config_get_is_low_risk():
    p = plan_config_get("102")
    assert p.risk == RISK_LOW


def test_plan_config_get_action_string():
    p = plan_config_get("102")
    assert p.action == "pve_guest_config_get"


def test_plan_config_get_target_includes_kind_and_vmid():
    p = plan_config_get("102", kind="lxc")
    assert "lxc/102" == p.target


def test_plan_config_get_qemu_target():
    p = plan_config_get("200", kind="qemu")
    assert "qemu/200" == p.target


def test_plan_config_get_blast_says_read_only():
    p = plan_config_get("102")
    assert any("read-only" in b.lower() or "no changes" in b.lower() for b in p.blast_radius)


def test_plan_config_get_rejects_nonnumeric_vmid():
    with pytest.raises(ProximoError):
        plan_config_get("abc")


def test_plan_config_get_rejects_bad_kind():
    with pytest.raises(ProximoError):
        plan_config_get("102", kind="kvm")


# ---------------------------------------------------------------------------
# plan_config_set — diff, blast_radius, risk, reboot hint, read-error
# ---------------------------------------------------------------------------

def test_plan_config_set_is_medium_risk():
    api = _fake_api(config_data={"cores": 2, "digest": "x"})
    p = plan_config_set(api, "102", {"cores": 4})
    assert p.risk == RISK_MEDIUM


def test_plan_config_set_action_string():
    api = _fake_api()
    p = plan_config_set(api, "102", {"cores": 4})
    assert p.action == "pve_guest_config_set"


# --- host-boundary crossings: the allowlist admits net/usb/serial by key name, but a value
# that attaches to a host bridge or passes a host device in is a HIGH-risk host crossing the
# plan must name, not a routine MEDIUM edit. ---

def test_plan_config_set_net_bridge_is_high_risk_and_named():
    api = _fake_api()
    p = plan_config_set(api, "102", {"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0"})
    assert p.risk == RISK_HIGH
    blast = " ".join(p.blast_radius).lower()
    assert "vmbr0" in blast and "bridge" in blast


def test_plan_config_set_usb_host_passthrough_is_high_risk_and_named():
    api = _fake_api()
    p = plan_config_set(api, "200", {"usb0": "host=1050:0407"}, kind="qemu")
    assert p.risk == RISK_HIGH
    blast = " ".join(p.blast_radius).lower()
    assert "host device" in blast or "host-resource" in blast


def test_plan_config_set_serial_host_device_is_high_risk():
    api = _fake_api()
    p = plan_config_set(api, "200", {"serial0": "/dev/ttyS0"}, kind="qemu")
    assert p.risk == RISK_HIGH


def test_plan_config_set_usb_mapping_passthrough_is_high_risk():
    # PVE resource-mapping form: usb0=mapping=<id> passes a host device in exactly as host= does.
    api = _fake_api()
    p = plan_config_set(api, "200", {"usb0": "mapping=host-yubikey"}, kind="qemu")
    assert p.risk == RISK_HIGH
    blast = " ".join(p.blast_radius).lower()
    assert "host device" in blast or "host-resource" in blast


def test_plan_config_set_ordinary_net_without_bridge_stays_medium():
    # A net value with no host-bridge attach is not a host crossing.
    api = _fake_api()
    p = plan_config_set(api, "200", {"net0": "virtio=AA:BB:CC:DD:EE:FF"}, kind="qemu")
    assert p.risk == RISK_MEDIUM


def test_plan_config_set_target_includes_kind_vmid():
    api = _fake_api()
    p = plan_config_set(api, "102", {"cores": 4})
    assert p.target == "lxc/102"


def test_plan_config_set_diff_shows_old_and_new():
    api = _fake_api(config_data={"cores": 2, "digest": "x"})
    p = plan_config_set(api, "102", {"cores": 8})
    assert p.current["diff"]["cores"]["from"] == 2
    assert p.current["diff"]["cores"]["to"] == 8


def test_plan_config_set_diff_shows_unset_for_new_key():
    api = _fake_api(config_data={"cores": 2, "digest": "x"})
    p = plan_config_set(api, "102", {"description": "hello"})
    assert p.current["diff"]["description"]["from"] == "<unset>"


def test_plan_config_set_diff_shows_deleted_for_none():
    api = _fake_api(config_data={"cores": 2, "description": "old", "digest": "x"})
    p = plan_config_set(api, "102", {"description": None})
    assert p.current["diff"]["description"]["to"] == "<deleted>"


def test_plan_config_set_reboot_hint_for_cpu():
    api = _fake_api(config_data={"cores": 2, "digest": "x"})
    p = plan_config_set(api, "102", {"cores": 4})
    assert any("reboot" in b.lower() for b in p.blast_radius)


def test_plan_config_set_no_reboot_hint_for_safe_key():
    api = _fake_api(config_data={"description": "old", "digest": "x"})
    p = plan_config_set(api, "102", {"description": "new"})
    assert not any("reboot" in b.lower() for b in p.blast_radius)


def test_plan_config_set_captures_current_config():
    api = _fake_api(config_data={"cores": 2, "memory": 512, "digest": "x"})
    p = plan_config_set(api, "102", {"cores": 4})
    assert p.current["config"]["cores"] == 2
    assert p.current["config"]["memory"] == 512


def test_plan_config_set_masks_cipassword_in_current_config():
    # Guest config GET may return cloud-init secrets (e.g. cipassword) inline. The plan's
    # Plan.current is written verbatim to the tamper-evident PROVE ledger on every call
    # (even confirm=False) — the raw secret must never land there.
    api = _fake_api(config_data={"cores": 2, "cipassword": "SUPERSECRET", "digest": "x"})
    p = plan_config_set(api, "102", {"cores": 4})
    assert p.current["config"]["cipassword"] != "SUPERSECRET"
    assert "SUPERSECRET" not in str(p.current)


def test_plan_config_set_handles_read_error_gracefully():
    api = _fake_api(raise_on_get=True)
    p = plan_config_set(api, "102", {"cores": 4})
    # Must not raise; must disclose the uncertainty in blast_radius.
    assert any("failed" in b.lower() or "incomplete" in b.lower() for b in p.blast_radius)


def test_plan_config_set_rejects_disallowed_key():
    api = _fake_api()
    with pytest.raises(ProximoError):
        plan_config_set(api, "102", {"hookscript": "local:snippets/evil.sh"})


def test_plan_config_set_rejects_nonnumeric_vmid():
    api = _fake_api()
    with pytest.raises(ProximoError):
        plan_config_set(api, "not-a-number", {"cores": 4})


def test_plan_config_set_rejects_bad_kind():
    api = _fake_api()
    with pytest.raises(ProximoError):
        plan_config_set(api, "102", {"cores": 4}, kind="docker")


def test_plan_config_set_rejects_non_dict_changes():
    api = _fake_api()
    with pytest.raises(ProximoError):
        plan_config_set(api, "102", "cores=4")  # type: ignore[arg-type]


def test_plan_config_set_change_string_contains_key_value():
    api = _fake_api(config_data={"cores": 2, "digest": "x"})
    p = plan_config_set(api, "102", {"cores": 8})
    assert "cores" in p.change
    assert "8" in p.change


# ---------------------------------------------------------------------------
# plan_config_revert — validation, diff, to_delete, read-error
# ---------------------------------------------------------------------------

def test_plan_config_revert_is_medium_risk():
    api = _fake_api()
    p = plan_config_revert(api, "102", {"cores": 2})
    assert p.risk == RISK_MEDIUM


def test_plan_config_revert_action_string():
    api = _fake_api()
    p = plan_config_revert(api, "102", {"cores": 2})
    assert p.action == "pve_guest_config_revert"


def test_plan_config_revert_target_includes_kind_vmid():
    api = _fake_api()
    p = plan_config_revert(api, "102", {"cores": 2})
    assert p.target == "lxc/102"


def test_plan_config_revert_diff_shows_key_changes():
    api = _fake_api(config_data={"cores": 4, "memory": 1024, "digest": "x"})
    p = plan_config_revert(api, "102", {"cores": 2, "memory": 512})
    diff = p.current["diff"]
    assert diff["cores"]["from"] == 4
    assert diff["cores"]["to"] == 2


def test_plan_config_revert_shows_keys_to_delete():
    api = _fake_api(config_data={"cores": 4, "description": "gone", "digest": "x"})
    p = plan_config_revert(api, "102", {"cores": 2})
    # "description" is in current but not in prior → should appear in blast or change
    text = " ".join(p.blast_radius + [p.change]).lower()
    assert "description" in text or "delete" in text


def test_plan_config_revert_no_diff_when_values_match():
    api = _fake_api(config_data={"cores": 2, "memory": 512, "digest": "x"})
    p = plan_config_revert(api, "102", {"cores": 2, "memory": 512})
    # No diff entries for matching values
    assert "cores" not in p.current["diff"]
    assert "memory" not in p.current["diff"]


def test_plan_config_revert_handles_read_error_gracefully():
    api = _fake_api(raise_on_get=True)
    p = plan_config_revert(api, "102", {"cores": 2})
    assert any("failed" in b.lower() or "incomplete" in b.lower() for b in p.blast_radius)


def test_plan_config_revert_drops_disallowed_key_in_prior():
    # The plan must not refuse a real prior that carries non-settable keys — it discloses that
    # they are left as-is rather than raising (mirrors guest_config_revert's drop behavior).
    api = _fake_api(config_data={"cores": 4})
    p = plan_config_revert(api, "102", {"cores": 2, "hookscript": "local:snippets/evil.sh"})
    assert any("not reverted" in b.lower() or "non-settable" in b.lower() for b in p.blast_radius)


def test_plan_config_revert_rejects_non_dict_prior():
    api = _fake_api()
    with pytest.raises(ProximoError):
        plan_config_revert(api, "102", "not-a-dict")  # type: ignore[arg-type]


def test_plan_config_revert_rejects_nonnumeric_vmid():
    api = _fake_api()
    with pytest.raises(ProximoError):
        plan_config_revert(api, "abc", {"cores": 2})


def test_plan_config_revert_rejects_bad_kind():
    api = _fake_api()
    with pytest.raises(ProximoError):
        plan_config_revert(api, "102", {"cores": 2}, kind="kvm")


def test_plan_config_revert_stores_prior_in_current():
    api = _fake_api(config_data={"cores": 4, "digest": "x"})
    p = plan_config_revert(api, "102", {"cores": 2})
    assert "prior_config" in p.current
    assert p.current["prior_config"]["cores"] == 2


def test_plan_config_revert_masks_cipassword_in_current_config():
    # Same secret-leak class as plan_config_set: the live-read snapshot lands in Plan.current
    # (written to the PROVE ledger unconditionally) and must never carry a raw cipassword.
    api = _fake_api(config_data={"cores": 4, "cipassword": "SUPERSECRET", "digest": "x"})
    p = plan_config_revert(api, "102", {"cores": 2})
    assert "SUPERSECRET" not in str(p.current)


def test_plan_config_revert_reboot_hint_for_cores():
    api = _fake_api(config_data={"cores": 4, "digest": "x"})
    p = plan_config_revert(api, "102", {"cores": 2})
    assert any("reboot" in b.lower() for b in p.blast_radius)


# ---------------------------------------------------------------------------
# UNDO contract: plan before mutate is satisfiable (independent call)
# ---------------------------------------------------------------------------

def test_plan_before_set_is_independent_of_mutation():
    """plan_config_set can be called independently; result is a Plan (not a side-effect)."""
    api = _fake_api(config_data={"cores": 2, "digest": "x"})
    p = plan_config_set(api, "102", {"cores": 4})
    # No PUT calls — planning is read-only.
    assert len(api.put_calls) == 0
    assert p.risk == RISK_MEDIUM


def test_plan_before_revert_is_independent_of_mutation():
    api = _fake_api(config_data={"cores": 4, "digest": "x"})
    plan_config_revert(api, "102", {"cores": 2})
    assert len(api.put_calls) == 0


def test_prior_config_from_set_feeds_revert():
    """End-to-end UNDO: the prior_config returned by guest_config_set can be passed
    straight to plan_config_revert / guest_config_revert — no manual key filtering."""
    api = _fake_api(config_data={"cores": 2, "memory": 512, "digest": "old"})
    result = guest_config_set(api, "102", {"cores": 4})
    prior = result["prior_config"]
    # Simulate updated config for the revert call.
    api2 = _fake_api(config_data={"cores": 4, "memory": 512, "digest": "new"})
    revert_result = guest_config_revert(api2, "102", prior)
    assert "cores" in revert_result["reverted_to_keys"]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_guest_config_set_empty_changes_issues_put_with_only_digest():
    """An empty changes dict with a digest-bearing config still issues a PUT."""
    api = _fake_api(config_data={"cores": 2, "digest": "abc"})
    result = guest_config_set(api, "102", {})
    assert result["applied"] == []
    assert result["deleted"] == []
    # A PUT is issued (empty body is a valid noop on the API; confirm at smoke).
    assert len(api.put_calls) == 1


def test_guest_config_set_multiple_deletes_joined_in_delete_param():
    api = _fake_api(config_data={"description": "x", "tags": "y", "digest": "z"})
    guest_config_set(api, "102", {"description": None, "tags": None})
    _, _, data = api.put_calls[0]
    assert "delete" in data
    delete_val = data["delete"]
    assert "description" in delete_val
    assert "tags" in delete_val


def test_plan_config_set_net_key_allowed():
    api = _fake_api(config_data={"cores": 2, "digest": "x"})
    p = plan_config_set(api, "102", {"net0": "name=eth0,bridge=vmbr0"})
    assert "net0" in p.current["diff"]


def test_plan_config_set_indexed_net_high_number_allowed():
    api = _fake_api(config_data={"digest": "x"})
    p = plan_config_set(api, "102", {"net7": "name=eth7,bridge=vmbr0"})
    assert "net7" in p.current["diff"]


# --- C-1: plan reads live config from the TARGET node, not the configured default ----------------


def test_plan_config_set_reads_from_target_node():
    # C-1: on a multi-node cluster the plan must read live config from the SAME node the mutation
    # will write to (node param), not api.config.node — otherwise the recorded PROVE snapshot is
    # taken from the wrong node and the previewed diff is factually wrong.
    seen: list[str] = []
    api = _fake_api(node="default-node")
    api._get = lambda path: seen.append(path) or {"cores": "1"}
    plan_config_set(api, "105", {"cores": "2"}, kind="lxc", node="pve2")
    assert seen[0] == "/nodes/pve2/lxc/105/config"


def test_plan_config_revert_reads_from_target_node():
    seen: list[str] = []
    api = _fake_api(node="default-node")
    api._get = lambda path: seen.append(path) or {"cores": "1"}
    plan_config_revert(api, "105", {"cores": "1"}, kind="lxc", node="pve2")
    assert seen[0] == "/nodes/pve2/lxc/105/config"


def test_plan_config_set_defaults_to_config_node_when_node_omitted():
    # No regression: when node is not passed, it still falls back to the configured default node.
    seen: list[str] = []
    api = _fake_api(node="default-node")
    api._get = lambda path: seen.append(path) or {"cores": "1"}
    plan_config_set(api, "105", {"cores": "2"}, kind="lxc")
    assert seen[0] == "/nodes/default-node/lxc/105/config"
