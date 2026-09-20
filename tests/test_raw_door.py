"""The raw GET door: any published read on any plane, validated against the vendored tree
before the wire is touched, refused where a curated tool already stands guard, audited under
its own name. Controls both ways on every refusal class."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import proximo.door as door
import proximo.server as server
from proximo import apitree, rawdoor
from proximo.audit import AuditLedger
from proximo.backends import ProximoError
from proximo.config import ProximoConfig

# --- apitree ---------------------------------------------------------------------------------


def test_find_names_the_published_path_for_a_concrete_read():
    assert apitree.find("pve", "/version") == "/version"
    assert apitree.find("pve", "/nodes/x1/qemu/100/status/current") == "/nodes/{node}/qemu/{vmid}/status/current"
    assert apitree.find("pdm", "/pve/remotes/lab/resources") == "/pve/remotes/{remote}/resources"


def test_find_is_method_exact_and_honours_exclusions():
    assert apitree.find("pve", "/nodes/x1/qemu/100/status/start") is None  # POST only
    assert apitree.find("pve", "/nodes/x1/qemu/100/vncwebsocket") is None  # a tunnel, GET in the tree
    assert apitree.find("pbs", "/backup/_upgrade_/blob") is None  # the wire protocol
    assert apitree.find("pbs", "/backup") is None and apitree.find("pbs", "/reader") is None  # its handshake roots
    assert apitree.find("pve", "/nodes/x1/qemu/100/status/start", "POST") is not None


def test_nearest_stays_under_the_same_prefix():
    near = apitree.nearest("pve", "/nodes/x1/qemu/100/status/nope")
    assert near and all(p.startswith("/nodes/{node}/qemu/{vmid}") for p in near)
    assert "/nodes/{node}/qemu/{vmid}/status/current" in near


# --- rawdoor.validate ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "version",
        "/version?full=1",
        "/nodes/../access",
        "//version",
        "/ver sion",
        "/version\n",
        "/nodes/x1/qemu/100/../101/config",
    ],
)
def test_validate_refuses_malformed_paths_before_the_tree(path):
    with pytest.raises(ProximoError, match="malformed"):
        rawdoor.validate("pve", path)


def test_validate_refuses_an_unknown_plane():
    with pytest.raises(ProximoError, match="plane"):
        rawdoor.validate("pdx", "/version")


def test_validate_refuses_a_write_only_path_and_names_reads_nearby():
    with pytest.raises(ProximoError) as e:
        rawdoor.validate("pve", "/nodes/x1/qemu/100/status/start")
    assert "no GET" in str(e.value) and "/nodes/{node}/qemu/{vmid}/status/current" in str(e.value)


def test_validate_refuses_the_tunnels():
    with pytest.raises(ProximoError, match="no GET"):
        rawdoor.validate("pve", "/nodes/x1/qemu/100/vncwebsocket")


@pytest.mark.parametrize(
    ("plane", "path", "pointer"),
    [
        ("pve", "/nodes/x1/qemu/100/agent/file-read", "pve_agent"),
        ("pve", "/nodes/x1/qemu/100/agent/get-users", "pve_agent"),
        ("pve", "/nodes/x1/storage/pbs/file-restore/download", "pve_file_restore_download"),
        ("pbs", "/admin/datastore/main/pxar-file-download", "pbs_file_download"),
        ("pbs", "/admin/datastore/main/download", "byte stream"),
        ("pbs", "/admin/datastore/main/download-decoded", "byte stream"),
        ("pmg", "/quarantine/download", "pmg_"),
    ],
)
def test_validate_refuses_what_a_curated_tool_already_gates(plane, path, pointer):
    """The laundering loophole: a raw door that accepts a gated read bypasses the gate."""
    with pytest.raises(ProximoError) as e:
        rawdoor.validate(plane, path)
    assert "gated" in str(e.value) and pointer in str(e.value)


def test_validate_accepts_a_published_read_and_returns_its_published_form():
    assert rawdoor.validate("pve", "/nodes/x1/qemu/100/pending") == "/nodes/{node}/qemu/{vmid}/pending"
    assert rawdoor.validate("pbs", "/admin/datastore/main/snapshots") == "/admin/datastore/{store}/snapshots"


# --- rawdoor.params --------------------------------------------------------------------------


def test_params_are_typed_and_bools_take_the_wire_form():
    assert rawdoor.check_params({"full": True, "node": "x1", "limit": 5, "off": False}) == {
        "full": 1,
        "node": "x1",
        "limit": 5,
        "off": 0,
    }
    assert rawdoor.check_params(None) == {}


@pytest.mark.parametrize("bad", [{"a b": 1}, {"x": {"y": 1}}, {"x": [1]}, {"": 1}, {"x": None}, {"x": "v" * 4097}])
def test_params_refuse_nested_or_odd_shapes(bad):
    with pytest.raises(ProximoError, match="params"):
        rawdoor.check_params(bad)


# --- the tool through the funnel -----------------------------------------------------------------


class _Api:
    """PVE-shaped: _get(path, *, timeout=None), no params kwarg."""

    def __init__(self, data=None):
        self.calls, self.data = [], data

    def _get(self, path, *, timeout=None):
        self.calls.append(path)
        return self.data


class _Planar:
    """PBS/PMG/PDM-shaped: _get(path, params=None)."""

    def __init__(self, data=None):
        self.calls, self.data = [], data

    def _get(self, path, params=None):
        self.calls.append((path, params))
        return self.data


def _wire(tmp_path, monkeypatch, api=None, pbs=None, pmg=None, pdm=None):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="x1", token_path="/run/x", audit_log_path=log)
    ledger = AuditLedger(log)
    api = api or _Api({"version": "9.2"})
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, SimpleNamespace(), ledger))
    monkeypatch.setattr(server, "_pbs", lambda: (SimpleNamespace(), pbs or _Planar([{"store": "main"}])))
    monkeypatch.setattr(server, "_pmg", lambda: (SimpleNamespace(), pmg or _Planar({"ok": 1})))
    monkeypatch.setattr(server, "_pdm", lambda: (SimpleNamespace(), pdm or _Planar([{"id": "lab"}])))
    return api, log


def _entries(log):
    try:
        return [json.loads(line) for line in open(log)]
    except FileNotFoundError:
        return []


def test_pve_read_encodes_params_into_the_path_and_lands_in_the_ledger(tmp_path, monkeypatch):
    api, log = _wire(tmp_path, monkeypatch)
    out = server.proximo_api_get("pve", "/nodes/x1/qemu/100/status/current", {"full": True})
    assert api.calls == ["/nodes/x1/qemu/100/status/current?full=1"]
    assert out == {
        "plane": "pve",
        "path": "/nodes/x1/qemu/100/status/current",
        "published": "/nodes/{node}/qemu/{vmid}/status/current",
        "method": "GET",
        "derived": False,
        "data": {"version": "9.2"},
    }
    e = _entries(log)[-1]
    assert e["action"] == "proximo_api_get" and e["target"] == "pve:/nodes/x1/qemu/100/status/current"
    assert e["outcome"] == "ok" and e.get("mutation") in (False, None)


def test_other_planes_pass_params_as_a_kwarg(tmp_path, monkeypatch):
    pbs, pdm = _Planar([1]), _Planar([2])
    _wire(tmp_path, monkeypatch, pbs=pbs, pdm=pdm)
    server.proximo_api_get("pbs", "/admin/datastore/main/snapshots", {"ns": "a"})
    server.proximo_api_get("pdm", "/remotes")
    assert pbs.calls == [("/admin/datastore/main/snapshots", {"ns": "a"})]
    assert pdm.calls == [("/remotes", {})]


def test_a_refusal_never_reaches_the_wire_and_is_not_ledgered_as_ok(tmp_path, monkeypatch):
    api, log = _wire(tmp_path, monkeypatch)
    with pytest.raises(ProximoError):
        server.proximo_api_get("pve", "/nodes/x1/qemu/100/agent/file-read")
    assert api.calls == []
    assert all(e["action"] != "proximo_api_get" or e["outcome"] != "ok" for e in _entries(log))


def test_an_unconfigured_plane_is_a_clean_refusal(tmp_path, monkeypatch):
    _wire(tmp_path, monkeypatch)

    def _boom():
        raise RuntimeError("missing PROXIMO_PBS_BASE_URL")

    monkeypatch.setattr(server, "_pbs", _boom)
    with pytest.raises(ProximoError, match="pbs.*not configured"):
        server.proximo_api_get("pbs", "/version")


def test_a_gate_prefix_matches_whole_segments_only():
    assert rawdoor._gated("/a/b/c", "/a/b") and rawdoor._gated("/a/b", "/a/b")
    assert not rawdoor._gated("/a/bc", "/a/b") and not rawdoor._gated("/a", "/a/b")


def test_the_ledger_target_is_one_spelling_per_resource(tmp_path, monkeypatch):
    _, log = _wire(tmp_path, monkeypatch)
    server.proximo_api_get("pve", "/version/")
    assert _entries(log)[-1]["target"] == "pve:/version"


def test_the_cap_is_a_strict_ceiling(monkeypatch):
    data = {"k": "v"}
    exact = len(json.dumps(data))
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", str(exact))
    assert "data" in rawdoor.envelope("pve", "/v", "/v", data)
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", str(exact - 1))
    assert rawdoor.envelope("pve", "/v", "/v", data)["truncated"] is True


def test_a_response_over_the_cap_is_labelled_not_truncated_silently(tmp_path, monkeypatch):
    big = {"rows": ["x" * 100] * 50}
    _wire(tmp_path, monkeypatch, api=_Api(big))
    monkeypatch.setenv("PROXIMO_RAW_MAX_BYTES", "1024")
    out = server.proximo_api_get("pve", "/version")
    assert out["truncated"] is True and out["bytes"] > 1024 and out["cap"] == 1024
    assert "data" not in out and out["head"].startswith('{"rows"') and "params" in out["note"]


# --- residency, hints, receipt ----------------------------------------------------------------


def test_the_door_has_its_own_toolset_is_not_resident_in_the_facade_and_is_marked_read_only():
    assert door.TOOLSETS["raw"] == ("proximo_api_get",)
    assert "proximo_api_get" not in door._ALWAYS_REGISTERED  # the lean facade is a token budget
    assert "proximo_api_get" in door.escape_catalog(server.mcp)  # what proximo_read / proximo_call dispatch from
    assert server.proximo_api_get.__doc__.lstrip().startswith("READ-ONLY:")


def test_the_door_adds_nothing_to_the_coverage_receipt():
    """The receipt counts curated reach. The door reaches everything, and its refusal table names
    paths it will NOT open; neither may read as coverage."""
    import re
    import sys
    from pathlib import Path

    src = Path(server.__file__).parent
    tool_lits = re.findall(r"""["'](/[a-z][^"']*)["']""", (src / "tools" / "raw_door.py").read_text())
    assert not tool_lits, tool_lits
    sys.path.insert(0, str(src.parent.parent / "scripts"))
    import api_coverage as cov

    lits = {lit for lit, _ in cov.source_literals()["pmg"]}
    assert "/quarantine/download" not in lits  # named only by rawdoor.py, as a refusal
