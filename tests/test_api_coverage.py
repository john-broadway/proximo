"""The coverage receipt must be able to fail: a planted reached path shows touched, a planted
unreached one shows untouched, and the denominator states its exclusions."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import api_coverage as cov  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def _tree(tmp_path: Path, product: str, ops: list[tuple[str, str]]) -> Path:
    d = tmp_path / "apidoc"
    d.mkdir(exist_ok=True)
    for p in cov.PRODUCTS:
        (d / f"{p}.ops.json").write_text(json.dumps(ops if p == product else []))
    return d


def _src(tmp_path: Path, name: str, body: str) -> Path:
    s = tmp_path / "src"
    s.mkdir(exist_ok=True)
    (s / name).write_text(body)
    return s


def test_control_reached_and_unreached(tmp_path):
    src = _src(
        tmp_path,
        "backends.py",
        """
class B:
    def _snap_base(self, vmid, kind, node):
        return f"/nodes/{node}/{kind}/{vmid}/snapshot"
    def rollback(self, vmid, snap):
        return self._post(f"{self._snap_base(vmid, 'qemu', 'n')}/{snap}/rollback")
    def status(self, node, vmid):
        return self._get(f"/nodes/{node}/qemu/{vmid}/status/current?full=1")
""",
    )
    tree = _tree(
        tmp_path,
        "pve",
        [
            ("/nodes/{node}/qemu/{vmid}/snapshot/{snapname}/rollback", "POST"),
            ("/nodes/{node}/qemu/{vmid}/status/current", "GET"),
            ("/nodes/{node}/qemu/{vmid}/sendkey", "PUT"),
        ],
    )
    r = cov.measure(src, tree)["pve"]
    assert r["strict"] == 2 and r["touched"] == 2 and r["ops"] == 3
    assert r["untouched_paths"] == ["/nodes/{}/qemu/{}/sendkey"]


def test_module_helper_with_multiline_signature_expands_through_a_local(tmp_path):
    src = _src(
        tmp_path,
        "firewall.py",
        """
def _fw_base(
    api,
    scope,
) -> str:
    if scope == "cluster":
        return "/cluster/firewall"
    return f"/nodes/{n}/{kind}/{vmid}/firewall"


def rules_list(api, scope):
    base = _fw_base(api, scope)
    return api._get(f"{base}/rules") or []
""",
    )
    tree = _tree(
        tmp_path,
        "pve",
        [
            ("/cluster/firewall/rules", "GET"),
            ("/nodes/{node}/qemu/{vmid}/firewall/rules", "GET"),
            ("/nodes/{node}/lxc/{vmid}/firewall/rules", "GET"),
            ("/nodes/{node}/lxc/{vmid}/firewall/log", "GET"),
        ],
    )
    r = cov.measure(src, tree)["pve"]
    assert r["strict"] == 3 and r["untouched_paths"] == ["/nodes/{}/lxc/{}/firewall/log"]


def test_subpath_passed_to_a_proxy_helper_and_a_tuple_unpacked_base(tmp_path):
    src = _src(
        tmp_path,
        "pdm.py",
        """
class P:
    def _pve_remote_get(self, remote, subpath):
        path = f"/pve/remotes/{r}/{subpath.lstrip('/')}"
        return self._get(path)
    def _base(self, storage):
        return f"/nodes/{n}/storage/{storage}/file-restore", storage
    def resources(self, remote):
        return self._pve_remote_get(remote, "resources")
    def config(self, remote, kind, vmid):
        return self._pve_remote_get(remote, f"{kind}/{vmid}/config")
    def listing(self, storage):
        base, volid = self._base(storage)
        return self._get(f"{base}/list?volume={volid}")
""",
    )
    tree = _tree(
        tmp_path,
        "pdm",
        [
            ("/pve/remotes/{remote}/resources", "GET"),
            ("/pve/remotes/{remote}/qemu/{vmid}/config", "GET"),
            ("/pve/remotes/{remote}/qemu/{vmid}/status/start", "POST"),
            ("/nodes/{node}/storage/{storage}/file-restore/list", "GET"),
        ],
    )
    r = cov.measure(src, tree)["pdm"]
    assert r["strict"] == 3 and r["untouched_paths"] == ["/pve/remotes/{}/qemu/{}/status/start"]


def test_wrapper_forwards_its_parameter_to_the_proxy(tmp_path):
    src = _src(
        tmp_path,
        "pdm.py",
        """
class P:
    def _pve_remote_get(self, remote, subpath, params=None):
        path = f"/pve/remotes/{r}/{subpath.lstrip('/')}"
        return self._get(path)
    def _guest_list(self, kind, remote, node=None):
        return self._pve_remote_get(remote, kind, None) or []
    def qemu(self, remote):
        return self._guest_list("qemu", remote)
    def lxc(self, remote):
        return self._guest_list(kind="lxc", remote=remote)
""",
    )
    tree = _tree(
        tmp_path,
        "pdm",
        [
            ("/pve/remotes/{remote}/qemu", "GET"),
            ("/pve/remotes/{remote}/lxc", "GET"),
            ("/pve/remotes/{remote}/options", "GET"),
        ],
    )
    r = cov.measure(src, tree)["pdm"]
    assert r["touched"] == 2 and r["untouched_paths"] == ["/pve/remotes/{}/options"]


def test_slot_gated_by_an_allowlist_expands_to_its_members_only(tmp_path):
    src = _src(
        tmp_path,
        "backends.py",
        """
_INFO = frozenset({
    "ping", "info",
})
_FS = frozenset({"fstrim"})
_ALL = _INFO | _FS

class B:
    def agent_simple(self, vmid, command):
        if command not in _ALL:
            raise ValueError(command)
        path = f"/nodes/{n}/qemu/{vmid}/agent/{command}"
        return self._get(path)
""",
    )
    tree = _tree(
        tmp_path,
        "pve",
        [
            ("/nodes/{node}/qemu/{vmid}/agent/ping", "GET"),
            ("/nodes/{node}/qemu/{vmid}/agent/fstrim", "GET"),
            ("/nodes/{node}/qemu/{vmid}/agent/shutdown", "POST"),
        ],
    )
    r = cov.measure(src, tree)["pve"]
    assert r["touched"] == 2 and r["untouched_paths"] == ["/nodes/{}/qemu/{}/agent/shutdown"]


def test_owners_reset_at_module_level_between_defs():
    lines = ["def a():", "    x = 1", "", 'PATH = "/nodes"', "def b(", "    p,", ") -> str:", "    return p"]
    assert cov._owners(lines) == ["a", "a", "a", None, "b", "b", "b", "b"]


def test_method_unknown_counts_touched_not_strict(tmp_path):
    src = _src(tmp_path, "backends.py", 'PATH = f"/nodes/{n}/qemu/{v}/agent/ping"\n')
    tree = _tree(tmp_path, "pve", [("/nodes/{node}/qemu/{vmid}/agent/ping", "POST")])
    r = cov.measure(src, tree)["pve"]
    assert (r["strict"], r["touched"]) == (0, 1)


def test_exclusions_leave_the_denominator(tmp_path):
    src = _src(tmp_path, "pbs.py", "")
    tree = _tree(
        tmp_path,
        "pbs",
        [
            ("/backup/_upgrade_/blob", "POST"),
            ("/nodes/{node}/status", "GET"),
            ("/nodes/{node}/termproxy", "POST"),
        ],
    )
    assert cov.measure(src, tree)["pbs"]["ops"] == 1


def test_module_name_routes_the_product(tmp_path):
    src = _src(tmp_path, "pdm_fleet.py", 'x = self._get("/remotes")\n')
    tree = _tree(tmp_path, "pdm", [("/remotes", "GET")])
    (tmp_path / "b").mkdir()
    tree_pve = _tree(tmp_path / "b", "pve", [("/remotes", "GET")])
    assert cov.measure(src, tree)["pdm"]["strict"] == 1
    assert cov.measure(src, tree_pve)["pve"]["strict"] == 0


@pytest.mark.parametrize("product", cov.PRODUCTS)
def test_vendored_trees_are_nonempty_and_dated(product):
    ops = json.loads((cov.APIDOC / f"{product}.ops.json").read_text())
    assert len(ops) > 100 and all(m in ("GET", "POST", "PUT", "DELETE") for _, m in ops)
    assert f"`{product}.ops.json`" in (cov.APIDOC / "README.md").read_text()


def test_a_tool_module_credits_its_plane_with_exactly_the_helpers_it_imports(tmp_path):
    src = _src(
        tmp_path,
        "pbs_access.py",
        """
def user_get(api, userid):
    return api._get(f"/access/users/{userid}")

def realm_ad_list(api):
    return api._get("/config/access/ad")
""",
    )
    (src / "tools").mkdir()
    (src / "tools" / "pdm_access.py").write_text("from proximo.pbs_access import (\n    user_get,\n)\n")
    tree = _tree(tmp_path, "pdm", [("/access/users/{userid}", "GET"), ("/config/access/ad", "GET")])
    (tmp_path / "b").mkdir()
    tree_pbs = _tree(tmp_path / "b", "pbs", [("/access/users/{userid}", "GET"), ("/config/access/ad", "GET")])
    assert cov.measure(src, tree)["pdm"]["untouched_paths"] == ["/config/access/ad"]
    assert cov.measure(src, tree_pbs)["pbs"]["untouched_paths"] == []


def test_real_tree_controls():
    """Against the real package, both ways. If one of these ships, move it to the other list."""
    r = cov.measure()
    reached = {
        "pve": ["/nodes/{}/qemu/{}/snapshot/{}/rollback", "/nodes/{}/qemu/{}/agent/fstrim"],
        "pdm": ["/pve/remotes/{}/qemu", "/pve/remotes/{}/lxc", "/access/permissions", "/access/users/{}/token/{}"],
    }
    unreached = {
        "pve": ["/nodes/{}/qemu/{}/sendkey", "/nodes/{}/qemu/{}/agent/shutdown"],
        "pdm": ["/pve/remotes/{}/options", "/pve/remotes/{}/cluster-nextid", "/config/access/ad"],
    }
    for product, paths in reached.items():
        assert not set(paths) & set(r[product]["untouched_paths"]), product
    for product, paths in unreached.items():
        assert set(paths) <= set(r[product]["untouched_paths"]), product
    # the proxy's own slot never counts: dropping the filter would credit every sibling
    assert "/pve/remotes/{}/{}" not in {lit for lit, _ in cov.source_literals()["pdm"]}
