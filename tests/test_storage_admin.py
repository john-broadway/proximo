"""Storage administration (storage.cfg CRUD) tests.

Fully mocked, no live Proxmox. Mirrors test_cluster_ops.py style:
- _api() SimpleNamespace fake recording _get / _post / _put / _delete calls.
- URL + param assertions; pytest.raises(ProximoError) for validator tests.
- plan_* honesty tests: risk level, blast radius content, no false safety claims.

All these endpoints are Smoke-confirm only (never verified against a live PVE).
The tests validate the implementation's internal contract — URL shapes, body
field names, risk assignments — not live PVE behavior.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from proximo.backends import ProximoError
from proximo.planning import RISK_HIGH, RISK_MEDIUM, Plan
from proximo.storage_admin import (
    _check_storage_type,
    plan_storage_create,
    plan_storage_delete,
    plan_storage_update,
    storage_config_get,
    storage_config_list,
    storage_create,
    storage_delete,
    storage_update,
)

# ---------------------------------------------------------------------------
# Shared fake
# ---------------------------------------------------------------------------

def _api(node: str = "pve") -> SimpleNamespace:
    """Minimal API fake that records _get / _post / _put / _delete calls."""
    seen: dict = {}

    def fake_get(path):
        seen["method"] = "GET"
        seen["path"] = path
        return []

    def fake_post(path, data=None):
        seen["method"] = "POST"
        seen["path"] = path
        seen["data"] = data or {}
        return None  # storage create is a synchronous pmxcfs write

    def fake_put(path, data=None):
        seen["method"] = "PUT"
        seen["path"] = path
        seen["data"] = data or {}
        return None  # storage update is a synchronous pmxcfs write

    def fake_delete(path, params=None):
        seen["method"] = "DELETE"
        seen["path"] = path
        seen["params"] = params
        return None  # storage delete is a synchronous pmxcfs write

    return SimpleNamespace(
        config=SimpleNamespace(node=node),
        _get=fake_get,
        _post=fake_post,
        _put=fake_put,
        _delete=fake_delete,
        seen=seen,
    )


# ---------------------------------------------------------------------------
# _check_storage_type — validator
# ---------------------------------------------------------------------------

def test_check_storage_type_accepts_dir():
    assert _check_storage_type("dir") == "dir"


def test_check_storage_type_accepts_nfs():
    assert _check_storage_type("nfs") == "nfs"


def test_check_storage_type_accepts_all_valid_types():
    valid = ["dir", "nfs", "cifs", "lvm", "lvmthin", "zfspool", "pbs", "cephfs", "rbd", "iscsi"]
    for t in valid:
        assert _check_storage_type(t) == t


def test_check_storage_type_rejects_unknown():
    with pytest.raises(ProximoError, match="unsupported storage type"):
        _check_storage_type("badtype")


def test_check_storage_type_rejects_empty():
    with pytest.raises(ProximoError):
        _check_storage_type("")


def test_check_storage_type_rejects_docker():
    """'docker' is not a PVE storage driver."""
    with pytest.raises(ProximoError):
        _check_storage_type("docker")


# ---------------------------------------------------------------------------
# storage_config_list — cluster-scoped GET /storage
# ---------------------------------------------------------------------------

def test_storage_config_list_uses_correct_path():
    api = _api()
    storage_config_list(api)
    assert api.seen["path"] == "/storage"
    assert api.seen["method"] == "GET"


def test_storage_config_list_is_not_node_scoped():
    api = _api()
    storage_config_list(api)
    assert "/nodes/" not in api.seen["path"]


def test_storage_config_list_returns_list():
    api = _api()
    result = storage_config_list(api)
    assert isinstance(result, list)


def test_storage_config_list_returns_empty_list_on_none():
    """Verify or-[] fallback: _get returning None gives an empty list."""
    api = _api()
    api._get = lambda path: None
    result = storage_config_list(api)
    assert result == []


# ---------------------------------------------------------------------------
# storage_config_get — cluster-scoped GET /storage/{storage}
# ---------------------------------------------------------------------------

def test_storage_config_get_uses_correct_path():
    api = _api()
    storage_config_get(api, "local")
    assert api.seen["path"] == "/storage/local"
    assert api.seen["method"] == "GET"


def test_storage_config_get_is_not_node_scoped():
    api = _api()
    storage_config_get(api, "local")
    assert "/nodes/" not in api.seen["path"]


def test_storage_config_get_includes_storage_in_path():
    api = _api()
    storage_config_get(api, "local-zfs")
    assert "local-zfs" in api.seen["path"]


def test_storage_config_get_returns_dict():
    api = _api()
    api._get = lambda path: {"storage": "local", "type": "dir"}
    result = storage_config_get(api, "local")
    assert isinstance(result, dict)
    assert result.get("type") == "dir"


def test_storage_config_get_returns_empty_dict_on_none():
    api = _api()
    api._get = lambda path: None
    result = storage_config_get(api, "local")
    assert result == {}


def test_storage_config_get_rejects_invalid_storage_name():
    api = _api()
    with pytest.raises(ProximoError):
        storage_config_get(api, "bad storage!")


# ---------------------------------------------------------------------------
# storage_create — POST /storage
# ---------------------------------------------------------------------------

def test_storage_create_uses_correct_path_and_method():
    api = _api()
    storage_create(api, "mystore", "dir", path="/mnt/data")
    assert api.seen["path"] == "/storage"
    assert api.seen["method"] == "POST"


def test_storage_create_is_not_node_scoped():
    api = _api()
    storage_create(api, "mystore", "dir", path="/mnt/data")
    assert "/nodes/" not in api.seen["path"]


def test_storage_create_sends_storage_in_body():
    api = _api()
    storage_create(api, "mystore", "dir")
    assert api.seen["data"]["storage"] == "mystore"


def test_storage_create_sends_type_not_storage_type_in_body():
    """PVE body key is 'type', NOT 'storage_type' — critical shape check."""
    api = _api()
    storage_create(api, "mystore", "dir")
    assert "type" in api.seen["data"]
    assert "storage_type" not in api.seen["data"]
    assert api.seen["data"]["type"] == "dir"


def test_storage_create_sends_content_when_provided():
    api = _api()
    storage_create(api, "mystore", "dir", content="iso,images")
    assert api.seen["data"]["content"] == "iso,images"


def test_storage_create_omits_content_when_none():
    api = _api()
    storage_create(api, "mystore", "dir")
    assert "content" not in api.seen["data"]


def test_storage_create_sends_path_when_provided():
    api = _api()
    storage_create(api, "mystore", "dir", path="/mnt/data")
    assert api.seen["data"]["path"] == "/mnt/data"


def test_storage_create_omits_path_when_none():
    api = _api()
    storage_create(api, "mystore", "nfs", server="10.0.0.1")
    assert "path" not in api.seen["data"]


def test_storage_create_sends_server_when_provided():
    api = _api()
    storage_create(api, "nfs1", "nfs", server="10.0.0.1", export="/data")
    assert api.seen["data"]["server"] == "10.0.0.1"


def test_storage_create_sends_export_when_provided():
    api = _api()
    storage_create(api, "nfs1", "nfs", server="10.0.0.1", export="/data")
    assert api.seen["data"]["export"] == "/data"


def test_storage_create_sends_nodes_when_provided():
    api = _api()
    storage_create(api, "mystore", "dir", nodes="pve1,pve2")
    assert api.seen["data"]["nodes"] == "pve1,pve2"


def test_storage_create_omits_nodes_when_none():
    api = _api()
    storage_create(api, "mystore", "dir")
    assert "nodes" not in api.seen["data"]


def test_storage_create_sends_disable_as_1_when_true():
    """PVE uses 1/0 integers for boolean fields, not true/false strings."""
    api = _api()
    storage_create(api, "mystore", "dir", disable=True)
    assert api.seen["data"]["disable"] == 1


def test_storage_create_omits_disable_when_false():
    """disable=False (default) should NOT appear in the body — omit it."""
    api = _api()
    storage_create(api, "mystore", "dir", disable=False)
    assert "disable" not in api.seen["data"]


def test_storage_create_sends_shared_as_1_when_true():
    api = _api()
    storage_create(api, "mystore", "dir", shared=True)
    assert api.seen["data"]["shared"] == 1


def test_storage_create_omits_shared_for_intrinsically_shared_type():
    """PVE fixes shared=1 for network-backed types and its API REJECTS an explicit
    'shared' property for them ("500 unexpected property 'shared'" — live-proven for
    nfs on PVE 9.2, 2026-07-05). shared=True intent is already satisfied: omit it."""
    api = _api()
    storage_create(api, "mystore", "nfs", server="10.0.0.1", export="/srv/x", shared=True)
    assert "shared" not in api.seen["data"]


def test_storage_create_omits_shared_when_false():
    api = _api()
    storage_create(api, "mystore", "dir", shared=False)
    assert "shared" not in api.seen["data"]


def test_storage_create_rejects_invalid_storage_name():
    api = _api()
    with pytest.raises(ProximoError):
        storage_create(api, "bad name!", "dir")


def test_storage_create_rejects_invalid_storage_type():
    api = _api()
    with pytest.raises(ProximoError):
        storage_create(api, "mystore", "gluster")


def test_storage_create_all_types_accepted():
    for t in ["dir", "nfs", "cifs", "lvm", "lvmthin", "zfspool", "pbs", "cephfs", "rbd", "iscsi"]:
        api = _api()
        storage_create(api, "mystore", t)
        assert api.seen["data"]["type"] == t


# ---------------------------------------------------------------------------
# storage_update — PUT /storage/{storage}
# ---------------------------------------------------------------------------

def test_storage_update_uses_correct_path_and_method():
    api = _api()
    storage_update(api, "local", content="iso,backup")
    assert api.seen["path"] == "/storage/local"
    assert api.seen["method"] == "PUT"


def test_storage_update_is_not_node_scoped():
    api = _api()
    storage_update(api, "local", content="iso")
    assert "/nodes/" not in api.seen["path"]


def test_storage_update_includes_storage_in_path():
    api = _api()
    storage_update(api, "my-storage", content="backup")
    assert "my-storage" in api.seen["path"]


def test_storage_update_sends_content_when_provided():
    api = _api()
    storage_update(api, "local", content="iso,backup,images")
    assert api.seen["data"]["content"] == "iso,backup,images"


def test_storage_update_omits_content_when_none():
    api = _api()
    storage_update(api, "local")
    assert "content" not in api.seen["data"]


def test_storage_update_sends_nodes_when_provided():
    api = _api()
    storage_update(api, "local", nodes="pve1,pve2")
    assert api.seen["data"]["nodes"] == "pve1,pve2"


def test_storage_update_omits_nodes_when_none():
    api = _api()
    storage_update(api, "local")
    assert "nodes" not in api.seen["data"]


def test_storage_update_sends_disable_true_as_1():
    """disable=True must send integer 1, not True/string."""
    api = _api()
    storage_update(api, "local", disable=True)
    assert api.seen["data"]["disable"] == 1


def test_storage_update_sends_disable_false_as_0():
    """disable=False must send integer 0 (re-enable), not omit it."""
    api = _api()
    storage_update(api, "local", disable=False)
    assert api.seen["data"]["disable"] == 0


def test_storage_update_omits_disable_when_none():
    """disable=None means 'leave unchanged' — must NOT appear in the body."""
    api = _api()
    storage_update(api, "local", disable=None)
    assert "disable" not in api.seen["data"]


def test_storage_update_sends_shared_true_as_1():
    api = _api()
    storage_update(api, "local", shared=True)
    assert api.seen["data"]["shared"] == 1


def test_storage_update_sends_shared_false_as_0():
    api = _api()
    storage_update(api, "local", shared=False)
    assert api.seen["data"]["shared"] == 0


def test_storage_update_omits_shared_when_none():
    api = _api()
    storage_update(api, "local", shared=None)
    assert "shared" not in api.seen["data"]


def test_storage_update_sends_delete_when_provided():
    api = _api()
    storage_update(api, "local", delete="nodes,content")
    assert api.seen["data"]["delete"] == "nodes,content"


def test_storage_update_omits_delete_when_none():
    api = _api()
    storage_update(api, "local")
    assert "delete" not in api.seen["data"]


def test_storage_update_empty_body_when_all_none():
    """All-None args → empty PUT body (let PVE handle it)."""
    api = _api()
    storage_update(api, "local")
    assert api.seen["data"] == {}


def test_storage_update_rejects_invalid_storage_name():
    api = _api()
    with pytest.raises(ProximoError):
        storage_update(api, "bad name!")


# ---------------------------------------------------------------------------
# storage_delete — DELETE /storage/{storage}
# ---------------------------------------------------------------------------

def test_storage_delete_uses_correct_path_and_method():
    api = _api()
    storage_delete(api, "local")
    assert api.seen["path"] == "/storage/local"
    assert api.seen["method"] == "DELETE"


def test_storage_delete_is_not_node_scoped():
    api = _api()
    storage_delete(api, "local")
    assert "/nodes/" not in api.seen["path"]


def test_storage_delete_includes_storage_in_path():
    api = _api()
    storage_delete(api, "local-zfs")
    assert "local-zfs" in api.seen["path"]


def test_storage_delete_can_return_none():
    """Storage delete is a synchronous pmxcfs write — null return is normal."""
    api = _api()
    result = storage_delete(api, "local")
    assert result is None


def test_storage_delete_rejects_invalid_storage_name():
    api = _api()
    with pytest.raises(ProximoError):
        storage_delete(api, "has space!")


# ---------------------------------------------------------------------------
# plan_storage_create — risk, blast radius, action string
# ---------------------------------------------------------------------------

def test_plan_storage_create_is_medium_risk():
    p = plan_storage_create("mystore", "dir", path="/mnt/data")
    assert p.risk == RISK_MEDIUM


def test_plan_storage_create_action_string():
    p = plan_storage_create("mystore", "dir")
    assert p.action == "pve_storage_create"


def test_plan_storage_create_target_includes_storage():
    p = plan_storage_create("mystore", "dir")
    assert "mystore" in p.target


def test_plan_storage_create_change_includes_storage_and_type():
    p = plan_storage_create("mystore", "nfs", server="10.0.0.1")
    assert "mystore" in p.change
    assert "nfs" in p.change


def test_plan_storage_create_blast_mentions_storage_cfg():
    p = plan_storage_create("mystore", "dir")
    text = " ".join(p.blast_radius).lower()
    assert "storage.cfg" in text or "storage definition" in text


def test_plan_storage_create_blast_mentions_undo_path():
    p = plan_storage_create("mystore", "dir")
    text = " ".join(p.blast_radius).lower()
    assert "storage_delete" in text or "undo" in text or "remove" in text


def test_plan_storage_create_blast_mentions_misconfig_risk():
    p = plan_storage_create("mystore", "nfs", server="10.0.0.1")
    text = " ".join(p.blast_radius).lower()
    assert "misconfigur" in text or "fail" in text or "mount" in text


def test_plan_storage_create_blast_includes_storage_name():
    p = plan_storage_create("mystore", "dir")
    assert any("mystore" in b for b in p.blast_radius)


def test_plan_storage_create_disabled_state_shows_in_blast():
    p = plan_storage_create("mystore", "dir", disable=True)
    text = " ".join(p.blast_radius).lower()
    assert "disabled" in text or "disable" in text


def test_plan_storage_create_has_note_with_smoke_confirm():
    p = plan_storage_create("mystore", "dir")
    assert "smoke-confirm" in p.note.lower() or "confirm" in p.note.lower()


def test_plan_storage_create_rejects_invalid_storage_name():
    with pytest.raises(ProximoError):
        plan_storage_create("bad name!", "dir")


def test_plan_storage_create_rejects_invalid_storage_type():
    with pytest.raises(ProximoError):
        plan_storage_create("mystore", "badtype")


# ---------------------------------------------------------------------------
# plan_storage_update — risk, blast radius, disable=True access-loss line
# ---------------------------------------------------------------------------

def test_plan_storage_update_is_medium_risk():
    p = plan_storage_update(_api(), "local", content="iso,backup")
    assert p.risk == RISK_MEDIUM


def test_plan_storage_update_disable_true_is_still_medium_risk():
    """disable=True is still RISK_MEDIUM — not escalated to HIGH."""
    p = plan_storage_update(_api(), "local", disable=True)
    assert p.risk == RISK_MEDIUM


def test_plan_storage_update_action_string():
    p = plan_storage_update(_api(), "local", content="iso")
    assert p.action == "pve_storage_update"


def test_plan_storage_update_target_includes_storage():
    p = plan_storage_update(_api(), "mystore")
    assert "mystore" in p.target


def test_plan_storage_update_change_includes_storage():
    p = plan_storage_update(_api(), "mystore", content="backup")
    assert "mystore" in p.change


def test_plan_storage_update_blast_mentions_cluster_wide():
    p = plan_storage_update(_api(), "local", content="iso")
    text = " ".join(p.blast_radius).lower()
    assert "cluster" in text or "storage.cfg" in text or "storage definition" in text


def test_plan_storage_update_disable_true_blast_mentions_guest_access_loss():
    """When disable=True, blast MUST warn that guests lose disk access."""
    p = plan_storage_update(_api(), "local", disable=True)
    text = " ".join(p.blast_radius).lower()
    assert "access" in text or "lose" in text or "crash" in text or "disk" in text


def test_plan_storage_update_disable_true_blast_mentions_running_guests():
    p = plan_storage_update(_api(), "local", disable=True)
    text = " ".join(p.blast_radius)
    # Must explicitly call out guest/VM/container impact
    assert any(
        word in text.lower()
        for word in ("guest", "vm", "container", "running", "disk")
    )


def test_plan_storage_update_nodes_change_blast_mentions_access_loss():
    """Changing nodes list also needs to call out excluded-node access loss."""
    p = plan_storage_update(_api(), "local", nodes="pve1")
    text = " ".join(p.blast_radius).lower()
    assert "access" in text or "lose" in text or "excluded" in text


def test_plan_storage_update_blast_mentions_undo_path():
    p = plan_storage_update(_api(), "local", content="iso")
    text = " ".join(p.blast_radius).lower()
    assert "undo" in text or "inverse" in text or "restore" in text


def test_plan_storage_update_no_fields_still_builds_plan():
    """All-None args is allowed — the plan just says no fields provided."""
    p = plan_storage_update(_api(), "local")
    assert isinstance(p, Plan)
    assert any("no fields provided" in s for s in p.blast_radius)
    assert p.risk == RISK_MEDIUM


def test_plan_storage_update_has_smoke_confirm_note():
    p = plan_storage_update(_api(), "local", delete="nodes")
    assert "smoke-confirm" in p.note.lower() or "confirm" in p.note.lower()


def test_plan_storage_update_rejects_invalid_storage_name():
    with pytest.raises(ProximoError):
        plan_storage_update(_api(), "bad name!")


# ---------------------------------------------------------------------------
# plan_storage_delete — RISK_HIGH, blast radius completeness
# ---------------------------------------------------------------------------

def test_plan_storage_delete_is_high_risk():
    p = plan_storage_delete(_api(), "local")
    assert p.risk == RISK_HIGH


def test_plan_storage_delete_action_string():
    p = plan_storage_delete(_api(), "local")
    assert p.action == "pve_storage_delete"


def test_plan_storage_delete_target_includes_storage():
    p = plan_storage_delete(_api(), "mystore")
    assert "mystore" in p.target


def test_plan_storage_delete_change_includes_storage():
    p = plan_storage_delete(_api(), "mystore")
    assert "mystore" in p.change


def test_plan_storage_delete_blast_says_cluster_wide():
    p = plan_storage_delete(_api(), "local")
    text = " ".join(p.blast_radius).lower()
    assert "cluster" in text or "cluster-wide" in text or "all nodes" in text


def test_plan_storage_delete_blast_says_guest_disks_inaccessible():
    """Blast MUST warn that guest disks become inaccessible to PVE."""
    p = plan_storage_delete(_api(), "local")
    text = " ".join(p.blast_radius).lower()
    assert "inaccessible" in text or "lose access" in text or "cannot access" in text


def test_plan_storage_delete_blast_says_backups_not_listable_or_restorable():
    """Blast MUST mention backup listability/restorability impact."""
    p = plan_storage_delete(_api(), "local")
    text = " ".join(p.blast_radius).lower()
    assert "backup" in text
    assert "restor" in text or "listable" in text or "list" in text


def test_plan_storage_delete_blast_says_data_not_erased():
    """Blast MUST clarify that on-disk data is NOT erased — PVE loses the handle."""
    p = plan_storage_delete(_api(), "local")
    text = " ".join(p.blast_radius).lower()
    # Must have a NOT erase / does not erase / data remains style sentence
    assert "not erase" in text or "does not erase" in text or "data remains" in text or "not deleted" in text


def test_plan_storage_delete_blast_says_no_auto_undo():
    """Blast MUST say there is no automatic undo."""
    p = plan_storage_delete(_api(), "local")
    text = " ".join(p.blast_radius).lower()
    assert "no" in text and ("undo" in text or "automatic" in text or "recovery" in text)


def test_plan_storage_delete_blast_says_re_add_to_recover():
    """Blast MUST mention re-adding the definition as the recovery path."""
    p = plan_storage_delete(_api(), "local")
    text = " ".join(p.blast_radius).lower()
    assert "re-add" in text or "re add" in text or "add the definition" in text or "add the storage" in text


def test_plan_storage_delete_blast_includes_storage_name():
    p = plan_storage_delete(_api(), "mystore")
    assert any("mystore" in b for b in p.blast_radius)


def test_plan_storage_delete_has_smoke_confirm_note():
    p = plan_storage_delete(_api(), "local")
    assert "smoke-confirm" in p.note.lower() or "confirm" in p.note.lower()


def test_plan_storage_delete_rejects_invalid_storage_name():
    with pytest.raises(ProximoError):
        plan_storage_delete(_api(), "bad name!")


def test_plan_storage_delete_rejects_storage_with_space():
    with pytest.raises(ProximoError):
        plan_storage_delete(_api(), "local store")


# ---------------------------------------------------------------------------
# Cluster-scope contract — none of these endpoints belong under /nodes/
# ---------------------------------------------------------------------------

def test_storage_config_list_not_under_nodes():
    api = _api()
    storage_config_list(api)
    assert "/nodes/" not in api.seen["path"]


def test_storage_config_get_not_under_nodes():
    api = _api()
    storage_config_get(api, "local")
    assert "/nodes/" not in api.seen["path"]


def test_storage_create_not_under_nodes():
    api = _api()
    storage_create(api, "mystore", "dir")
    assert "/nodes/" not in api.seen["path"]


def test_storage_update_not_under_nodes():
    api = _api()
    storage_update(api, "local", content="iso")
    assert "/nodes/" not in api.seen["path"]


def test_storage_delete_not_under_nodes():
    api = _api()
    storage_delete(api, "local")
    assert "/nodes/" not in api.seen["path"]


# ---------------------------------------------------------------------------
# Regression tests for reviewed fixes
# ---------------------------------------------------------------------------

# Item 1 — plan/exec drift: padded type stripped before plan text is built
def test_plan_storage_create_padded_type_previews_stripped():
    """plan_storage_create(' dir ') must preview 'dir', not ' dir '."""
    p = plan_storage_create("mystore", " dir ")
    # The stripped form must appear in the change summary and blast
    assert "type=dir" in " ".join(p.blast_radius)
    assert "type= dir" not in " ".join(p.blast_radius)
    assert "dir" in p.change
    assert " dir " not in p.change


# Item 2 — fake "risk table" overclaim removed from plan_storage_update risk_reasons
def test_plan_storage_update_risk_reasons_no_risk_table_overclaim():
    """risk_reasons must NOT claim a 'pre-classified risk table' — that table doesn't exist."""
    p = plan_storage_update(_api(), "local", disable=True)
    combined = " ".join(p.risk_reasons).lower()
    assert "risk table" not in combined
    assert "pre-classified risk table" not in combined


def test_plan_storage_update_risk_reasons_honest_phrasing():
    """risk_reasons must contain honest phrasing about blast radius / reversibility."""
    p = plan_storage_update(_api(), "local", disable=True)
    combined = " ".join(p.risk_reasons).lower()
    assert "blast radius" in combined or "not automatically reversible" in combined or "reversible" in combined


# Item 3 — disable=True undo overclaim: re-enable ≠ guest recovery
def test_plan_storage_update_disable_true_blast_honesty_on_undo():
    """disable=True blast must say guests that lost their disk may need a restart,
    and that config reversal does not equal guest recovery."""
    p = plan_storage_update(_api(), "local", disable=True)
    text = " ".join(p.blast_radius).lower()
    # Must contain the recovery-honesty qualifier — restart or config reversal phrasing
    assert "restart" in text or "config reversal" in text


# Item 4 — _check_storage imported from storage.py; dot-only names are a pre-existing gap
# Smoke-confirm: _STORAGE_RE = ^[A-Za-z0-9._-]+\Z in storage.py permits "." and ".." as
# valid storage IDs — this is pre-existing behavior; not changed here. No rejection test.


# Item 5 — operator-trusted note present in both plan_storage_create and plan_storage_update
def test_plan_storage_create_note_mentions_operator_trusted():
    """plan_storage_create note must say path/server/export/content/nodes are operator-trusted."""
    p = plan_storage_create("mystore", "nfs", server="10.0.0.1", export="/data")
    assert "operator-trusted" in p.note.lower()


def test_plan_storage_update_note_mentions_operator_trusted():
    """plan_storage_update note must say content/nodes/delete are operator-trusted strings."""
    p = plan_storage_update(_api(), "local", content="iso,backup", nodes="pve1")
    assert "operator-trusted" in p.note.lower()


# ---------------------------------------------------------------------------
# Blast-radius enrichment (plans read the cluster to NAME affected guests)
# ---------------------------------------------------------------------------

def _blast_api(rows, configs=None):
    """Path-aware fake for blast enumeration: /cluster/resources -> rows; /config -> configs[vmid]."""
    configs = configs or {}

    def _get(path):
        if path == "/cluster/resources":
            return rows
        if path.endswith("/config"):
            return configs[path.strip("/").split("/")[3]]
        return None

    return SimpleNamespace(_get=_get, config=SimpleNamespace(node="pve"))


def test_plan_storage_delete_names_affected_guests_and_keeps_high():
    rows = [{"vmid": "101", "type": "qemu", "node": "pve1", "name": "web", "status": "running"}]
    configs = {"101": {"scsi0": "nas:101/d.qcow2,size=8G", "bootdisk": "scsi0"}}
    plan = plan_storage_delete(_blast_api(rows, configs), "nas")
    assert plan.risk == RISK_HIGH                              # floor maintained
    assert any("qemu/101" in line for line in plan.blast_radius)
    assert plan.affected and plan.affected[0]["resource"] == "qemu/101"
    # generic floor still present (engine PREPENDS, never replaces)
    assert any("does NOT erase on-disk data" in line for line in plan.blast_radius)


def test_plan_storage_update_disable_escalates_to_high_when_only_copy_running():
    rows = [{"vmid": "101", "type": "qemu", "node": "pve1", "name": "db", "status": "running"}]
    configs = {"101": {"scsi0": "nas:101/d.qcow2,size=8G", "bootdisk": "scsi0"}}
    plan = plan_storage_update(_blast_api(rows, configs), "nas", disable=True)
    assert plan.risk == RISK_HIGH                              # escalated from MEDIUM
    assert plan.affected and plan.affected[0]["resource"] == "qemu/101"


def test_plan_storage_update_non_disable_does_not_enumerate():
    plan = plan_storage_update(_blast_api([]), "nas", content="images,iso")
    assert plan.risk == RISK_MEDIUM and plan.affected == []
    assert any("updates storage definition 'nas'" in line for line in plan.blast_radius)
