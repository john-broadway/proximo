"""PROVISION pillar tests — create / clone / delete guests.

Fully mocked, no live Proxmox. Mirrors test_planning.py / test_backends.py style:
- _FakeApi records calls on the mock; assertions verify URL+params shapes.
- plan_* tests use a lightweight fake that supplies list_guests / guest_status.
- Validator-rejection tests use pytest.raises(ProximoError).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from proximo.backends import ProximoError
from proximo.planning import RISK_HIGH, RISK_MEDIUM
from proximo.provisioning import (
    clone_guest,
    create_container,
    create_vm,
    delete_guest,
    plan_clone,
    plan_create,
    plan_delete,
)

# ---------------------------------------------------------------------------
# Test fakes
# ---------------------------------------------------------------------------

def _api(node: str = "pve"):
    """A fake api object that records _post / _delete calls and carries config.node."""
    seen: dict = {}

    def fake_post(path, data=None):
        seen["method"] = "POST"
        seen["path"] = path
        seen["data"] = data
        return "UPID:pve:00001:0:0:0:vzcreate:100:root@pam:"

    def fake_delete(path, params=None):
        seen["method"] = "DELETE"
        seen["path"] = path
        seen["params"] = params
        return "UPID:pve:00002:0:0:0:vzdelete:100:root@pam:"

    api = SimpleNamespace(
        config=SimpleNamespace(node=node),
        _post=fake_post,
        _delete=fake_delete,
        seen=seen,
    )
    return api


class _ListApi:
    """Fake api for plan_create / plan_clone: supplies list_guests + config.node (+ optional source
    guest config for the SDN-bridge disclosure)."""

    def __init__(self, guests: list[dict], node: str = "pve", raise_on_list: bool = False,
                 vm_config: dict | None = None):
        self._guests = guests
        self.config = SimpleNamespace(node=node)
        self._raise = raise_on_list
        self._vm_config = vm_config
        self.list_calls: list = []

    def list_guests(self, node=None):
        # Node-scoped, like the real ApiBackend: a guest carrying a different 'node' is NOT returned
        # (guests without a 'node' key are returned for any node — keeps older tests unchanged).
        self.list_calls.append(node)
        if self._raise:
            raise RuntimeError("api unavailable")
        return [g for g in self._guests if g.get("node") in (None, node)]

    def _get(self, path):
        # cluster_resources(api, "vm") -> cluster-wide guest list (VMIDs are cluster-unique).
        if "cluster/resources" in path:
            if self._raise:
                raise RuntimeError("api unavailable")
            return self._guests
        # plan_clone reads the source guest config to disclose its NIC bridges; other paths -> {}.
        return (self._vm_config or {}) if path.endswith("/config") else {}


class _StatusApi:
    """Fake api for plan_delete: supplies guest_status + config.node."""

    def __init__(self, status: dict | None, node: str = "pve", raise_on_status: bool = False):
        self._status = status
        self.config = SimpleNamespace(node=node)
        self._raise = raise_on_status
        self.status_calls: list = []

    def guest_status(self, vmid, kind="lxc", node=None):
        self.status_calls.append((vmid, kind, node))
        if self._raise:
            raise RuntimeError("transient API error")  # no .response -> "unknown" (not absence)
        if self._status is None:
            err = RuntimeError("not found")
            err.response = SimpleNamespace(status_code=404)  # 404-shaped -> "confirmed absent"
            raise err
        return self._status


# ---------------------------------------------------------------------------
# create_container: path + data shapes
# ---------------------------------------------------------------------------

def test_create_container_builds_correct_path():
    api = _api()
    create_container(api, "200", "local:vztmpl/debian-12.tar.zst", "local-lvm")
    assert api.seen["path"] == "/nodes/pve/lxc"
    assert api.seen["method"] == "POST"


def test_create_container_sends_required_fields():
    api = _api()
    create_container(api, "200", "local:vztmpl/debian-12.tar.zst", "local-lvm")
    d = api.seen["data"]
    assert d["vmid"] == "200"
    assert d["ostemplate"] == "local:vztmpl/debian-12.tar.zst"
    assert d["storage"] == "local-lvm"


def test_create_container_passes_extra_opts():
    api = _api()
    create_container(api, "200", "local:vztmpl/debian-12.tar.zst", "local-lvm",
                     hostname="mybox", memory=512)
    d = api.seen["data"]
    assert d["hostname"] == "mybox"
    assert d["memory"] == 512


def test_create_container_uses_explicit_node():
    api = _api(node="pve2")
    create_container(api, "200", "local:vztmpl/debian-12.tar.zst", "local-lvm", node="pve1")
    assert "/nodes/pve1/" in api.seen["path"]


def test_create_container_uses_config_node_when_none():
    api = _api(node="pve2")
    create_container(api, "200", "local:vztmpl/debian-12.tar.zst", "local-lvm")
    assert "/nodes/pve2/" in api.seen["path"]


def test_create_container_returns_upid():
    api = _api()
    result = create_container(api, "200", "local:vztmpl/debian-12.tar.zst", "local-lvm")
    assert result.startswith("UPID:")


# ---------------------------------------------------------------------------
# create_vm: path + data shapes
# ---------------------------------------------------------------------------

def test_create_vm_builds_correct_path():
    api = _api()
    create_vm(api, "300")
    assert api.seen["path"] == "/nodes/pve/qemu"
    assert api.seen["method"] == "POST"


def test_create_vm_sends_vmid():
    api = _api()
    create_vm(api, "300")
    assert api.seen["data"]["vmid"] == "300"


def test_create_vm_passes_extra_opts():
    api = _api()
    create_vm(api, "300", name="win11", memory=4096, cores=4)
    d = api.seen["data"]
    assert d["name"] == "win11"
    assert d["memory"] == 4096
    assert d["cores"] == 4


def test_create_vm_uses_config_node_when_none():
    api = _api(node="node3")
    create_vm(api, "300")
    assert "/nodes/node3/" in api.seen["path"]


def test_create_vm_uses_explicit_node():
    api = _api()
    create_vm(api, "300", node="node7")
    assert "/nodes/node7/" in api.seen["path"]


# ---------------------------------------------------------------------------
# clone_guest: path + data shapes, flag handling
# ---------------------------------------------------------------------------

def test_clone_guest_lxc_builds_correct_path():
    api = _api()
    clone_guest(api, "200", "201", kind="lxc")
    assert api.seen["path"] == "/nodes/pve/lxc/200/clone"
    assert api.seen["method"] == "POST"


def test_clone_guest_qemu_builds_correct_path():
    api = _api()
    clone_guest(api, "300", "301", kind="qemu")
    assert api.seen["path"] == "/nodes/pve/qemu/300/clone"


def test_clone_guest_sends_newid():
    api = _api()
    clone_guest(api, "200", "201")
    assert api.seen["data"]["newid"] == "201"


def test_clone_guest_full_false_does_not_send_full():
    api = _api()
    clone_guest(api, "200", "201", full=False)
    assert "full" not in api.seen["data"]


def test_clone_guest_full_true_sends_full_1():
    api = _api()
    clone_guest(api, "200", "201", full=True)
    assert api.seen["data"]["full"] == 1


def test_clone_guest_name_sent_when_provided():
    api = _api()
    clone_guest(api, "200", "201", name="newbox")
    assert api.seen["data"]["name"] == "newbox"


def test_clone_guest_pool_sent_when_provided():
    api = _api()
    clone_guest(api, "200", "201", pool="proximo-test")
    assert api.seen["data"]["pool"] == "proximo-test"


def test_clone_guest_pool_absent_when_not_provided():
    api = _api()
    clone_guest(api, "200", "201")
    assert "pool" not in api.seen["data"]


def test_clone_guest_name_absent_when_not_provided():
    api = _api()
    clone_guest(api, "200", "201")
    assert "name" not in api.seen["data"]


def test_clone_guest_uses_explicit_node():
    api = _api()
    clone_guest(api, "200", "201", node="pve3")
    assert "/nodes/pve3/" in api.seen["path"]


def test_clone_guest_uses_config_node_when_none():
    api = _api(node="nodeA")
    clone_guest(api, "200", "201")
    assert "/nodes/nodeA/" in api.seen["path"]


def test_clone_guest_storage_sent_when_provided_with_full():
    api = _api()
    clone_guest(api, "200", "201", full=True, storage="test")
    assert api.seen["data"]["storage"] == "test"
    assert api.seen["data"]["full"] == 1


def test_clone_guest_storage_absent_when_not_provided():
    api = _api()
    clone_guest(api, "200", "201", full=True)
    assert "storage" not in api.seen["data"]


def test_clone_guest_storage_requires_full_clone():
    # PVE only honors a target storage for a FULL clone — a linked clone must stay on the source
    # storage. Refuse loudly rather than send a request PVE will reject confusingly.
    api = _api()
    with pytest.raises(ProximoError):
        clone_guest(api, "200", "201", full=False, storage="test")
    assert api.seen == {}  # nothing was sent


# ---------------------------------------------------------------------------
# delete_guest: path + param shapes, flag handling
# ---------------------------------------------------------------------------

def test_delete_guest_builds_correct_lxc_path():
    api = _api()
    delete_guest(api, "200")
    assert api.seen["path"] == "/nodes/pve/lxc/200"
    assert api.seen["method"] == "DELETE"


def test_delete_guest_builds_correct_qemu_path():
    api = _api()
    delete_guest(api, "300", kind="qemu")
    assert api.seen["path"] == "/nodes/pve/qemu/300"


def test_delete_guest_no_flags_sends_no_params():
    api = _api()
    delete_guest(api, "200")
    # Either None or empty dict is acceptable — no param injection
    assert not api.seen.get("params")


def test_delete_guest_purge_true_sends_purge_1():
    api = _api()
    delete_guest(api, "200", purge=True)
    assert api.seen["params"]["purge"] == 1


def test_delete_guest_force_true_sends_force_1():
    api = _api()
    delete_guest(api, "200", force=True)
    assert api.seen["params"]["force"] == 1


def test_delete_guest_purge_and_force_both_sent():
    api = _api()
    delete_guest(api, "200", purge=True, force=True)
    assert api.seen["params"]["purge"] == 1
    assert api.seen["params"]["force"] == 1


def test_delete_guest_uses_config_node_when_none():
    api = _api(node="nodeB")
    delete_guest(api, "200")
    assert "/nodes/nodeB/" in api.seen["path"]


def test_delete_guest_uses_explicit_node():
    api = _api()
    delete_guest(api, "200", node="pve5")
    assert "/nodes/pve5/" in api.seen["path"]


def test_delete_guest_returns_upid():
    api = _api()
    result = delete_guest(api, "200")
    assert result.startswith("UPID:")


# ---------------------------------------------------------------------------
# Validator rejections — bad ids are caught before touching the URL
# ---------------------------------------------------------------------------

def test_create_container_rejects_nonnumeric_vmid():
    api = _api()
    with pytest.raises(ProximoError):
        create_container(api, "abc", "tmpl", "storage")


def test_create_vm_rejects_nonnumeric_vmid():
    api = _api()
    with pytest.raises(ProximoError):
        create_vm(api, "100; reboot")


def test_clone_guest_rejects_nonnumeric_vmid():
    api = _api()
    with pytest.raises(ProximoError):
        clone_guest(api, "abc", "201")


def test_clone_guest_rejects_nonnumeric_newid():
    api = _api()
    with pytest.raises(ProximoError):
        clone_guest(api, "200", "abc")


def test_delete_guest_rejects_nonnumeric_vmid():
    api = _api()
    with pytest.raises(ProximoError):
        delete_guest(api, "abc")


def test_clone_guest_rejects_unsupported_kind():
    api = _api()
    with pytest.raises(ProximoError):
        clone_guest(api, "200", "201", kind="docker")


def test_delete_guest_rejects_bad_kind():
    api = _api()
    with pytest.raises(ProximoError):
        delete_guest(api, "200", kind="kvm")


def test_create_container_rejects_empty_ostemplate():
    api = _api()
    with pytest.raises(ProximoError):
        create_container(api, "200", "", "local-lvm")


def test_create_container_rejects_empty_storage():
    api = _api()
    with pytest.raises(ProximoError):
        create_container(api, "200", "local:vztmpl/debian.tar.zst", "")


def test_create_container_rejects_invalid_node():
    api = _api()
    with pytest.raises(ProximoError):
        create_container(api, "200", "tmpl", "storage", node="bad/node")


def test_delete_guest_rejects_invalid_node():
    api = _api()
    with pytest.raises(ProximoError):
        delete_guest(api, "200", node="node\ninjected")


# ---------------------------------------------------------------------------
# plan_create
# ---------------------------------------------------------------------------

def test_plan_create_unprivileged_lxc_is_medium():
    # An explicitly unprivileged LXC is the isolated, MEDIUM-risk case.
    api = _ListApi([])
    p = plan_create(api, "500", "lxc", None, {"unprivileged": 1})
    assert p.risk == RISK_MEDIUM


def test_plan_create_qemu_is_medium():
    # QEMU has no privileged/unprivileged notion — never escalated on that axis.
    api = _ListApi([])
    p = plan_create(api, "500", "qemu")
    assert p.risk == RISK_MEDIUM


def test_plan_create_action_string():
    api = _ListApi([])
    p = plan_create(api, "500", "lxc", None, {"unprivileged": 1})
    assert p.action == "pve_create"


def test_plan_create_default_lxc_is_privileged_high():
    # PVE creates LXC PRIVILEGED by default (real param `unprivileged` default 0). A create with
    # no options — the common path — is privileged and must flag HIGH, not MEDIUM.
    api = _ListApi([])
    p = plan_create(api, "500")
    assert p.risk == RISK_HIGH
    assert any("privileged" in b.lower() for b in p.blast_radius)


def test_plan_create_explicit_unprivileged_zero_is_high():
    # The real key is `unprivileged`; unprivileged=0 == privileged. (The old code checked a
    # non-existent `privileged` key, so this created-privileged container read as MEDIUM.)
    api = _ListApi([])
    p = plan_create(api, "500", "lxc", None, {"unprivileged": 0})
    assert p.risk == RISK_HIGH
    assert any("privileged" in b.lower() for b in p.blast_radius)


def test_plan_create_surfaces_options_and_redacts_password():
    # the plan must reflect the real create params (trust spine) but never echo the password
    api = _ListApi([])
    p = plan_create(api, "500", "lxc", None, {"cores": 4, "password": "hunter2"})
    assert "cores" in p.change
    assert "hunter2" not in p.change
    assert "[redacted]" in p.change


def test_plan_create_free_vmid_names_new_guest():
    api = _ListApi([{"vmid": 100}, {"vmid": 101}])
    p = plan_create(api, "500")
    assert not any("fail" in b.lower() for b in p.blast_radius)
    assert any("500" in b for b in p.blast_radius)


def test_plan_create_detects_collision_int_vmid():
    # Proxmox returns vmid as int — must still detect the collision.
    api = _ListApi([{"vmid": 500}])
    p = plan_create(api, "500")
    assert any("already in use" in b.lower() or "fail" in b.lower() for b in p.blast_radius)


def test_plan_create_collision_blast_not_contradictory():
    # When vmid is taken, blast_radius must NOT also say "new … will be created".
    api = _ListApi([{"vmid": 500}])
    p = plan_create(api, "500")
    assert not any("will be created" in b for b in p.blast_radius)


def test_plan_create_discloses_unavailable_check():
    # If list_guests raises, uncertainty must be surfaced — not silently "all clear".
    api = _ListApi([], raise_on_list=True)
    p = plan_create(api, "500")
    text = " ".join(p.blast_radius + p.risk_reasons).lower()
    assert "could not confirm" in text or "unavailable" in text or "collision check" in text


def test_plan_create_collision_check_is_cluster_wide():
    # L14 (2026-07-10 audit): VMIDs are cluster-unique. A vmid taken on ANOTHER node must be caught —
    # the old node-scoped check missed it and the plan wrongly promised a clean create.
    api = _ListApi([{"vmid": 500, "node": "othernode"}])
    p = plan_create(api, "500", node="pve2")
    assert any("already in use" in b.lower() or "fail" in b.lower() for b in p.blast_radius)


def test_plan_create_falls_back_to_node_scope_and_discloses(monkeypatch):
    # When the cluster-wide read is unavailable, fall back to the node-scoped check AND disclose it.
    import proximo.provisioning as prov

    def _boom(_api, _rtype=None):
        raise RuntimeError("cluster read unavailable")

    monkeypatch.setattr(prov, "cluster_resources", _boom)
    api = _ListApi([])
    p = plan_create(api, "500", node="pve2")
    assert api.list_calls[-1] == "pve2"
    assert any("node-scoped" in b.lower() for b in p.blast_radius)


def test_plan_create_uses_config_node_for_target_when_none():
    api = _ListApi([], node="confignode")
    p = plan_create(api, "500")
    assert "lxc/500" in p.target


def test_plan_create_qemu_kind_in_target():
    api = _ListApi([])
    p = plan_create(api, "600", kind="qemu")
    assert "qemu/600" in p.target


def test_plan_create_rejects_nonnumeric_vmid():
    api = _ListApi([])
    with pytest.raises(ProximoError):
        plan_create(api, "abc")


def test_plan_create_rejects_bad_kind():
    api = _ListApi([])
    with pytest.raises(ProximoError):
        plan_create(api, "500", kind="docker")


# ---------------------------------------------------------------------------
# plan_clone
# ---------------------------------------------------------------------------

def test_plan_clone_is_medium_risk():
    api = _ListApi([])
    p = plan_clone(api, "200", "201")
    assert p.risk == RISK_MEDIUM


def test_plan_clone_action_string():
    api = _ListApi([])
    p = plan_clone(api, "200", "201")
    assert p.action == "pve_clone"


def test_plan_clone_surfaces_name_and_pool():
    # name and pool change what executes (pool controls who can manage the clone) — plan must show them
    api = _ListApi([{"vmid": 200}])
    p = plan_clone(api, "200", "201", name="web", pool="prod")
    blast = " ".join(p.blast_radius)
    assert "web" in blast and "prod" in blast
    assert "web" in p.change and "prod" in p.change


def test_plan_clone_names_source_and_target():
    api = _ListApi([])
    p = plan_clone(api, "200", "201")
    assert "200" in p.change and "201" in p.change


def test_plan_clone_detects_collision_int_vmid():
    # newid 201 already in use as int
    api = _ListApi([{"vmid": 201}])
    p = plan_clone(api, "200", "201")
    assert any("already in use" in b.lower() or "fail" in b.lower() for b in p.blast_radius)


def test_plan_clone_free_newid_names_clone():
    api = _ListApi([{"vmid": 200}])  # source exists but newid 201 is free
    p = plan_clone(api, "200", "201")
    assert not any("fail" in b.lower() for b in p.blast_radius)
    assert any("201" in b for b in p.blast_radius)


def test_plan_clone_collision_blast_not_contradictory():
    api = _ListApi([{"vmid": 201}])
    p = plan_clone(api, "200", "201")
    assert not any("clones" in b and "→" in b for b in p.blast_radius)


def test_plan_clone_discloses_unavailable_check():
    api = _ListApi([], raise_on_list=True)
    p = plan_clone(api, "200", "201")
    text = " ".join(p.blast_radius + p.risk_reasons).lower()
    assert "could not confirm" in text or "unavailable" in text or "collision check" in text


def test_plan_clone_discloses_target_storage():
    # storage is only valid for a FULL clone; disclose it on that path.
    api = _ListApi([{"vmid": 200}])  # source exists, newid 201 free
    p = plan_clone(api, "200", "201", full=True, storage="targetstore")
    assert any("targetstore" in b for b in p.blast_radius)


def test_plan_clone_default_is_linked_not_independent():
    # The DEFAULT (full=False) is a LINKED clone (template-dependent), NOT a "new independent guest".
    # The plan must not claim the opposite (same class as the firewall-precedence honesty bug).
    api = _ListApi([{"vmid": 200}])
    text = " ".join(plan_clone(api, "200", "201").blast_radius).lower()
    assert "linked" in text
    assert "independent" not in text


def test_plan_clone_full_is_independent():
    api = _ListApi([{"vmid": 200}])
    text = " ".join(plan_clone(api, "200", "201", full=True).blast_radius).lower()
    assert "independent" in text or "full clone" in text
    assert "linked" not in text


def test_plan_clone_storage_without_full_warns_it_will_be_refused():
    # clone_guest REJECTS storage without full=True — the dry-run must say so, not preview it as viable.
    api = _ListApi([{"vmid": 200}])
    text = " ".join(plan_clone(api, "200", "201", storage="fast").blast_radius).lower()
    assert "refused" in text or "requires full" in text


def test_plan_clone_discloses_sdn_bridge_requirement():
    # PVE 8 requires SDN.Use on the bridge to clone a guest carrying a NIC — the plan should say so.
    api = _ListApi([{"vmid": 200}],
                   vm_config={"net0": "virtio=AA:BB:CC,bridge=vmbr0", "scsi0": "local:vm-200-disk-0,size=8G"})
    p = plan_clone(api, "200", "201")
    text = " ".join(p.blast_radius)
    assert "vmbr0" in text and "SDN.Use" in text


def test_plan_clone_no_nic_no_sdn_disclosure():
    api = _ListApi([{"vmid": 200}], vm_config={"scsi0": "local:vm-200-disk-0,size=8G"})  # no net*
    p = plan_clone(api, "200", "201")
    assert not any("SDN.Use" in b for b in p.blast_radius)


def test_plan_clone_rejects_nonnumeric_vmid():
    api = _ListApi([])
    with pytest.raises(ProximoError):
        plan_clone(api, "abc", "201")


def test_plan_clone_rejects_nonnumeric_newid():
    api = _ListApi([])
    with pytest.raises(ProximoError):
        plan_clone(api, "200", "xyz")


def test_plan_clone_rejects_bad_kind():
    api = _ListApi([])
    with pytest.raises(ProximoError):
        plan_clone(api, "200", "201", kind="notreal")


# ---------------------------------------------------------------------------
# plan_delete
# ---------------------------------------------------------------------------

def _stub_clean_cascade(monkeypatch):
    """Make plan_delete's cascade a no-op clean result, so these tests isolate provisioning logic.
    (The cascade engine is covered by tests/test_blast_guest_destroy.py + test_server_plan.py.)"""
    import proximo.provisioning as P
    from proximo.blast import GuestDestroyBlastResult

    monkeypatch.setattr(
        P,
        "guest_destroy_blast",
        lambda api, vmid, kind, node, purge, force: GuestDestroyBlastResult(
            summary_lines=[], affected=[], risk=RISK_HIGH, risk_reasons=[], complete=True
        ),
    )


def test_plan_delete_is_high_risk(monkeypatch):
    _stub_clean_cascade(monkeypatch)
    api = _StatusApi({"status": "running", "name": "mybox"})
    p = plan_delete(api, "200")
    assert p.risk == RISK_HIGH


def test_plan_delete_action_string(monkeypatch):
    _stub_clean_cascade(monkeypatch)
    api = _StatusApi({"status": "running", "name": "mybox"})
    p = plan_delete(api, "200")
    assert p.action == "pve_delete"


def test_plan_delete_blast_names_guest_permanently_destroyed(monkeypatch):
    _stub_clean_cascade(monkeypatch)
    api = _StatusApi({"status": "running", "name": "mybox"})
    p = plan_delete(api, "200")
    text = " ".join(p.blast_radius).lower()
    assert "permanently destroys" in text
    assert "irreversible" in text
    assert not any("could not" in b.lower() for b in p.blast_radius)


def test_plan_delete_blast_includes_name_and_status(monkeypatch):
    _stub_clean_cascade(monkeypatch)
    api = _StatusApi({"status": "stopped", "name": "oldbox"})
    p = plan_delete(api, "200")
    text = " ".join(p.blast_radius)
    assert "oldbox" in text
    assert "stopped" in text


def test_plan_delete_purge_false_no_purge_action_in_blast(monkeypatch):
    # purge=False: the blast must NOT claim that purge actions will fire (removing from HA/backup).
    # The cascade disclaimer may mention "purge" as a parameter name — that is informational and OK.
    _stub_clean_cascade(monkeypatch)
    api = _StatusApi({"status": "running", "name": "mybox"})
    p = plan_delete(api, "200", purge=False)
    # The dedicated "purge" action line only appears when purge=True
    assert not any(
        ("backup jobs" in b.lower() or "ha" in b.lower() or "replication" in b.lower())
        and "purge=true" in b.lower()
        for b in p.blast_radius
    )


def test_plan_delete_purge_true_adds_purge_to_blast(monkeypatch):
    _stub_clean_cascade(monkeypatch)
    api = _StatusApi({"status": "running", "name": "mybox"})
    p = plan_delete(api, "200", purge=True)
    assert any("(purge=true)" in b.lower() for b in p.blast_radius)


def test_plan_delete_purge_in_change_string(monkeypatch):
    _stub_clean_cascade(monkeypatch)
    api = _StatusApi({"status": "running", "name": "mybox"})
    p = plan_delete(api, "200", purge=True)
    assert "purge" in p.change.lower()


def test_plan_delete_not_found_stays_high_risk():
    # Not-found: op would fail, but RISK_HIGH is maintained (plan_rollback precedent).
    api = _StatusApi(None)
    p = plan_delete(api, "200")
    assert p.risk == RISK_HIGH


def test_plan_delete_not_found_blast_says_will_fail():
    api = _StatusApi(None)
    p = plan_delete(api, "200")
    assert any("will fail" in b.lower() or "not found" in b.lower() for b in p.blast_radius)


def test_plan_delete_not_found_blast_not_contradictory():
    # When not found, blast_radius must NOT also say "PERMANENTLY destroys" — nothing is destroyed.
    api = _StatusApi(None)
    p = plan_delete(api, "200")
    assert not any("permanently destroys" in b.lower() for b in p.blast_radius)


def test_plan_delete_transient_error_is_high_and_discloses_uncertainty():
    # A non-404 (transient) status read must NOT be reported as "nothing destroyed" — that would be
    # false safety on the most destructive op. It stays HIGH and discloses the uncertainty.
    api = _StatusApi(None, raise_on_status=True)
    p = plan_delete(api, "200")
    assert p.risk == RISK_HIGH
    assert any("could not verify" in b.lower() for b in p.blast_radius)
    # must NOT claim the harmless "nothing would be destroyed" when existence is unknown
    assert not any("nothing would be destroyed" in b.lower() for b in p.blast_radius)


def test_plan_delete_check_failed_is_incomplete():
    # A non-404 error (check_failed path): existence is UNKNOWN → complete must be False.
    # The blast-radius enumeration cannot be complete when we don't know if the guest exists.
    api = _StatusApi(None, raise_on_status=True)
    p = plan_delete(api, "200")
    assert p.complete is False
    assert p.risk == RISK_HIGH
    assert not p.affected


def test_plan_delete_reads_live_status_for_current(monkeypatch):
    _stub_clean_cascade(monkeypatch)
    api = _StatusApi({"status": "running", "name": "live-box"})
    p = plan_delete(api, "200")
    assert p.current.get("status") == "running"
    assert p.current.get("name") == "live-box"


def test_plan_delete_populates_target(monkeypatch):
    _stub_clean_cascade(monkeypatch)
    api = _StatusApi({"status": "stopped", "name": "x"})
    p = plan_delete(api, "200", kind="qemu")
    assert p.target == "qemu/200"


def test_plan_delete_rejects_nonnumeric_vmid():
    api = _StatusApi({"status": "running", "name": "x"})
    with pytest.raises(ProximoError):
        plan_delete(api, "not-a-number")


def test_plan_delete_rejects_bad_kind():
    api = _StatusApi({"status": "running", "name": "x"})
    with pytest.raises(ProximoError):
        plan_delete(api, "200", kind="xen")


# ── REGRESSION: redteam fixes (2026-06-08) ────────────────────────────────────

def test_plan_create_detects_leading_zero_collision():
    # '0500' must collide with an existing int 500 (numeric compare, not string equality).
    api = _ListApi([{"vmid": 500}])
    p = plan_create(api, "0500")
    assert any("already in use" in b.lower() or "fail" in b.lower() for b in p.blast_radius)


def test_plan_clone_discloses_missing_source():
    # newid free, but the source guest does not exist -> the plan must say the clone will fail.
    api = _ListApi([{"vmid": 999}])
    p = plan_clone(api, "200", "201")
    assert any("source" in b.lower() and ("not found" in b.lower() or "fail" in b.lower())
               for b in p.blast_radius)
