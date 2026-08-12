"""Tests for native multi-target: registry parse, resolution, contextvar, wrapper."""
import textwrap

import pytest

from proximo import targets
from proximo._mcpcompat import tool_input_schema
from proximo.backends import ProximoError


def _write_registry(tmp_path, body: str) -> str:
    p = tmp_path / "targets.toml"
    p.write_text(textwrap.dedent(body))
    return str(p)


def test_no_env_var_means_empty_registry(monkeypatch):
    monkeypatch.delenv("PROXIMO_TARGETS", raising=False)
    assert targets.load_registry() == {}


def test_active_target_defaults_none():
    assert targets.active_target() is None


def test_load_registry_parses_named_targets(monkeypatch, tmp_path):
    reg = _write_registry(tmp_path, """
        [targets.edge-pve]
        kind = "pve"
        base_url = "https://192.0.2.20:8006/api2/json"
        node = "edge"
        token_path = "/etc/proximo/edge.token"
    """)
    monkeypatch.setenv("PROXIMO_TARGETS", reg)
    r = targets.load_registry()
    assert set(r) == {"edge-pve"}
    assert r["edge-pve"]["kind"] == "pve"
    assert r["edge-pve"]["node"] == "edge"


def test_resolve_unknown_target_raises(monkeypatch, tmp_path):
    reg = _write_registry(tmp_path, """
        [targets.edge-pve]
        kind = "pve"
        base_url = "https://192.0.2.20:8006/api2/json"
        node = "edge"
        token_path = "/etc/proximo/edge.token"
    """)
    monkeypatch.setenv("PROXIMO_TARGETS", reg)
    with pytest.raises(ProximoError, match="unknown target"):
        targets.resolve_target_fields("nope", "pve")


def test_resolve_without_registry_raises(monkeypatch):
    monkeypatch.delenv("PROXIMO_TARGETS", raising=False)
    with pytest.raises(ProximoError, match="no target registry"):
        targets.resolve_target_fields("edge-pve", "pve")


def test_resolve_kind_mismatch_raises(monkeypatch, tmp_path):
    reg = _write_registry(tmp_path, """
        [targets.edge-pbs]
        kind = "pbs"
        base_url = "https://192.0.2.7:8007"
        token_path = "/etc/proximo/pbs.token"
    """)
    monkeypatch.setenv("PROXIMO_TARGETS", reg)
    with pytest.raises(ProximoError, match="is kind 'pbs', not usable by a PVE tool"):
        targets.resolve_target_fields("edge-pbs", "pve")


def test_load_registry_missing_file_raises(monkeypatch):
    monkeypatch.setenv("PROXIMO_TARGETS", "/nonexistent/targets.toml")
    with pytest.raises(ProximoError, match="missing file"):
        targets.load_registry()


def test_load_registry_bad_toml_raises(monkeypatch, tmp_path):
    p = tmp_path / "bad.toml"
    p.write_text("this is = = not toml")
    monkeypatch.setenv("PROXIMO_TARGETS", str(p))
    with pytest.raises(ProximoError, match="not valid TOML"):
        targets.load_registry()


def test_unknown_kind_raises(monkeypatch, tmp_path):
    reg = _write_registry(tmp_path, """
        [targets.weird]
        kind = "vsphere"
        base_url = "https://192.0.2.99:8006/api2/json"
    """)
    monkeypatch.setenv("PROXIMO_TARGETS", reg)
    with pytest.raises(ProximoError, match="unknown kind 'vsphere'"):
        targets.load_registry()


def test_target_aware_injects_proximo_target_into_fastmcp_schema():
    """The de-risk gate: FastMCP must advertise proximo_target from the injected __signature__,
    route it to the contextvar, and reset it after the call."""
    import anyio

    from proximo._mcpcompat import ServerClass

    captured = {}
    m = ServerClass("spike")

    @m.tool()
    @targets.target_aware
    def sample(vmid: str, node: str | None = None) -> dict:
        captured["active"] = targets.active_target()
        return {"vmid": vmid, "node": node}

    # 1. The generated input schema advertises proximo_target — WITH a description, so it
    #    isn't an undocumented parameter on every multi-target tool (Glama/agent legibility).
    tools = anyio.run(m.list_tools)
    sample_tool = next(t for t in tools if t.name == "sample")
    target_schema = tool_input_schema(sample_tool)["properties"]["proximo_target"]
    assert target_schema.get("description"), "proximo_target must carry a schema description"
    assert "target" in target_schema["description"].lower()

    # 2. Calling with proximo_target routes the contextvar; the body never sees the kwarg.
    anyio.run(lambda: m.call_tool("sample", {"vmid": "131", "proximo_target": "edge-pve"}))
    assert captured["active"] == "edge-pve"

    # 3. The contextvar is reset after the call (no leak across calls).
    assert targets.active_target() is None


def test_unknown_target_error_does_not_enumerate_registry(monkeypatch, tmp_path):
    # redteam LOW: the error must NOT leak the full list of registered target names to the caller.
    reg = _write_registry(tmp_path, """
        [targets.secret-box-name]
        kind = "pve"
        base_url = "https://192.0.2.20:8006/api2/json"
        node = "edge"
        token_path = "/etc/proximo/edge.token"
    """)
    monkeypatch.setenv("PROXIMO_TARGETS", reg)
    with pytest.raises(ProximoError) as ei:
        targets.resolve_target_fields("nope", "pve")
    assert "secret-box-name" not in str(ei.value)


def test_load_registry_reparses_when_file_changes(monkeypatch, tmp_path):
    import os
    p = tmp_path / "targets.toml"
    p.write_text('[targets.a]\nkind="pve"\nbase_url="https://192.0.2.1:8006/api2/json"\nnode="a"\ntoken_path="/t"\n')
    monkeypatch.setenv("PROXIMO_TARGETS", str(p))
    assert set(targets.load_registry()) == {"a"}
    p.write_text('[targets.b]\nkind="pbs"\nbase_url="https://192.0.2.7:8007"\ntoken_path="/t"\n')
    st = p.stat()
    os.utime(str(p), (st.st_atime + 10, st.st_mtime + 10))  # force a new mtime
    assert set(targets.load_registry()) == {"b"}, "cached registry not invalidated on file change"


# --- M3: vmid/ctid params accept an int and hand the body a str (pydantic would else reject int) --
def test_vmid_int_is_coerced_to_str_at_the_boundary():
    """An agent naturally sends the 'Numeric VMID' as an int; the param is typed str (a VMID is an
    opaque token). target_aware injects an int->str coercion so pydantic accepts the int and the
    body still receives the str it expects. Proven through FastMCP's validated call path."""
    from typing import Annotated

    from pydantic import Field

    from proximo._mcpcompat import ServerClass

    seen = {}

    def probe(vmid: Annotated[str, Field(description="Numeric VMID or CTID.")]) -> dict:
        seen["type"] = type(vmid).__name__
        seen["value"] = vmid
        return {"ok": True}

    m = ServerClass("proximo-m3-test")
    m.tool(name="probe")(targets.target_aware(probe))

    import anyio
    anyio.run(lambda: m._tool_manager.call_tool("probe", {"vmid": 100}, context=None))
    assert seen["type"] == "str"   # body got a str, not an int
    assert seen["value"] == "100"  # coerced from the int


def test_plain_str_vmid_still_passes_through():
    from typing import Annotated

    from pydantic import Field

    from proximo._mcpcompat import ServerClass

    seen = {}

    def probe(ctid: Annotated[str, Field(description="Numeric CTID.")]) -> dict:
        seen["value"] = ctid
        return {"ok": True}

    m = ServerClass("proximo-m3-test2")
    m.tool(name="probe")(targets.target_aware(probe))

    import anyio
    anyio.run(lambda: m._tool_manager.call_tool("probe", {"ctid": "105"}, context=None))
    assert seen["value"] == "105"  # a string still works unchanged
