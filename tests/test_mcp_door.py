"""The MCP door: six tools over the engine, driven in process on whichever SDK major is installed,
and once over the real stdio wire.

Every refusal must reach the CLIENT as text it can act on. On mcp 2.x the SDK sanitizes any
non-ToolError raised in a tool body to "Error executing tool <name>", which is how the 0.44
dogfood server once read every refusal as a bare tool name; the seam's `call_tool` override
translates a ProximoError back. `test_a_refusal_reaches_the_client_as_its_own_words` is the
control for that, and it was watched go red with the override disabled.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys

import pytest

mcp_sdk = pytest.importorskip("mcp", reason="the [mcp] extra is not installed")

from proximo.core import engine, mcpcompat  # noqa: E402
from proximo.core.doors import mcp as door  # noqa: E402
from proximo.core.errors import ProximoError  # noqa: E402
from proximo.core.ledger import LedgerConfig, open_ledger  # noqa: E402


def _call(server, name, args):
    """One in-process tools/call, normalised to the tool's own return value."""
    result = asyncio.run(server.call_tool(name, args))
    out = mcpcompat.in_process_result(result)
    if isinstance(out, tuple):          # 1.x: (content_blocks, structured)
        blocks, structured = out
        return structured if structured else json.loads(blocks[0].text)
    if isinstance(out, dict):
        return out.get("result", out)   # 2.x wraps a non-dict return as {"result": ...}
    return json.loads(out[0].text)


@pytest.fixture
def server(monkeypatch, tmp_path):
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":   # the pin on the real file stays
            monkeypatch.delenv(var)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    return door.build_server()


def test_the_six_tools_and_their_hints(server):
    """readOnlyHint is what a client's permission policy reads: five True, and proximo_call is
    the ONE tool that can mutate (a restore rides on it as method=undo, B2)."""
    tools = server._tool_manager._tools
    assert sorted(tools) == ["audit_entries", "audit_verify", "proximo_call", "proximo_find",
                             "proximo_plan", "proximo_read"]
    if mcpcompat.TOOL_SUPPORTS_ANNOTATIONS:
        hints = {n: mcpcompat.annotations_read_only(t.annotations) for n, t in tools.items()}
        assert hints == {"audit_entries": True, "audit_verify": True, "proximo_call": False,
                         "proximo_find": True, "proximo_plan": True, "proximo_read": True}


def test_the_input_schemas_are_pinned(server):
    """The names proximo_read / proximo_call / audit_* exist on the 0.44 server with OTHER
    argument shapes. These are the new shapes; a drift here is a breaking change and must be
    a deliberate edit of this table."""
    tools = server._tool_manager._tools
    want = {
        "proximo_find": {"query", "plane", "limit"},
        "proximo_plan": {"plane", "method", "path", "args"},
        "proximo_read": {"plane", "path", "params", "fields", "since", "wait", "diagnose"},   # wait (B4), diagnose (B3)
        "proximo_call": {"plane", "method", "path", "args", "confirm", "wait"},    # wait (B4)
        "audit_entries": {"limit", "target", "action", "mutations_only"},
        "audit_verify": {"expected_head", "path"},
    }
    got = {n: set(t.parameters["properties"]) for n, t in tools.items()}
    assert got == want


def test_plan_answers_on_a_box_that_holds_no_credential(server):
    out = _call(server, "proximo_plan", {"plane": "pve", "method": "DELETE", "path": "/nodes/x/qemu/1"})
    assert out["allowed"] is False and out["needs"] == "arm" and out["access"] == "mutate"
    assert "purge" in out["published_parameters"]
    out = _call(server, "proximo_plan", {"plane": "pve", "method": "GET", "path": "/nodes/x/status"})
    assert out["allowed"] is True and out["access"] == "read"


def test_find_matches_every_term_and_says_when_it_truncates(server):
    out = _call(server, "proximo_find", {"query": "qemu snapshot", "plane": "pve", "limit": 3})
    assert out["total"] > 3 and out["truncated"] is True and len(out["matches"]) == 3
    for m in out["matches"]:
        hay = f"{m['path']} {' '.join(m['params'])}"
        assert "qemu" in hay and "snapshot" in hay, m
    out = _call(server, "proximo_find", {"query": "no-such-thing-anywhere"})
    assert out["matches"] == [] and "note" in out


def test_a_refusal_reaches_the_client_as_its_own_words(server):
    """Unconfigured estate: proximo_read must say so in the door's words, never a traceback and
    never the SDK's bare tool name. Planted control: with the seam's call_tool override
    disabled, this assertion sees 'Error executing tool proximo_read' and nothing else."""
    res = asyncio.run(server.call_tool("proximo_read", {"plane": "pve", "path": "/nodes/x/status"})) \
        if mcpcompat.MCP_MAJOR == 1 else None
    if mcpcompat.MCP_MAJOR == 2:
        with pytest.raises(mcpcompat.ToolError) as e:
            asyncio.run(server.call_tool("proximo_read", {"plane": "pve", "path": "/nodes/x/status"}))
        text = str(e.value)
    else:  # 1.x shows the refusal verbatim in the result; the SDK raises ToolError on the wire
        text = str(res)
    assert "not configured" in text and "PROXIMO_API_BASE_URL" in text, text


def test_call_refuses_a_read_and_an_unarmed_mutation_and_receipts_the_latter(server, tmp_path):
    read = {"plane": "pve", "method": "GET", "path": "/nodes/x/status"}
    mutate = {"plane": "pve", "method": "DELETE", "path": "/nodes/x/qemu/1", "confirm": True}
    with pytest.raises((mcpcompat.ToolError, ProximoError), match="is a read"):
        asyncio.run(server.call_tool("proximo_call", read))
    with pytest.raises((mcpcompat.ToolError, ProximoError), match="not armed"):
        asyncio.run(server.call_tool("proximo_call", mutate))
    # PLAN BY DEFAULT: the same call without confirm is the plan, touches nothing, refuses nothing.
    plan = _call(server, "proximo_call", {k: v for k, v in mutate.items() if k != "confirm"})
    assert plan["status"] == "plan" and plan["allowed"] is False and plan["needs"] == "arm"
    rows = [json.loads(line) for line in (tmp_path / "audit.log").read_text().splitlines()]
    assert [r["action"] for r in rows][-1] == "core.refuse" and rows[-1]["target"] == "/nodes/x/qemu/1"


def test_the_doors_receipt_and_a_direct_ledger_row_verify_as_one_chain(server, tmp_path):
    """The claim the 09-21 session made and got wrong, asserted for THIS door: a row the MCP
    door's own open_ledger writes and a row this door's refusal writes are one keyed chain,
    and no archive appears."""
    cfg = LedgerConfig(audit_log_path=str(tmp_path / "audit.log"))
    open_ledger(cfg).record("mcp.row", target="/x", mutation=False, outcome="ok", detail={})
    mutate = {"plane": "pve", "method": "DELETE", "path": "/nodes/x/qemu/1", "confirm": True}
    with pytest.raises((mcpcompat.ToolError, ProximoError)):
        asyncio.run(server.call_tool("proximo_call", mutate))
    v = open_ledger(cfg).verify()
    assert v.ok and v.entries == 2, v
    assert not list(tmp_path.glob("audit.log.unkeyed-*"))
    out = _call(server, "audit_verify", {})
    assert out["ok"] is True and out["entries"] == 2 and out["keyed"] is True


def test_the_unknown_tool_pointer_names_the_doors_own_tools(server):
    if mcpcompat.MCP_MAJOR != 2:
        pytest.skip("the in-process unknown-tool pointer is the 2.x seam; 1.x raises the SDK's ToolError")
    with pytest.raises(ProximoError, match="proximo_plan"):
        asyncio.run(server.call_tool("pve_vm_start", {}))


def test_the_door_over_the_real_stdio_wire(tmp_path):
    """A subprocess of `python -m proximo.core.doors.mcp`, no estate configured: tools/list carries
    the hints, proximo_plan answers, and a mutation plan says what would change the answer."""
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = {k: v for k, v in os.environ.items() if not k.startswith("PROXIMO_") or k == "PROXIMO_ENV_FILE"}
    env["PROXIMO_AUDIT_LOG"] = str(tmp_path / "audit.log")
    params = StdioServerParameters(command=sys.executable, args=["-m", "proximo.core.doors.mcp"], env=env)

    async def drive():
        async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
            init = await asyncio.wait_for(s.initialize(), timeout=30)
            assert mcpcompat.init_server_info(init).name == "proximo"
            tools = await asyncio.wait_for(s.list_tools(), timeout=30)
            hints = {t.name: mcpcompat.annotations_read_only(t.annotations) for t in tools.tools}
            assert hints["proximo_call"] is False and hints["proximo_read"] is True
            # proximo_plan declares no `confirm`: this call carried one for years and the SDK dropped
            # it. Undeclared arguments are refused now (lens 3, 2026-10-05), so the plan's own args.
            mutate = {"plane": "pve", "method": "DELETE", "path": "/nodes/x/qemu/1"}
            res = await asyncio.wait_for(s.call_tool("proximo_plan", mutate), timeout=30)
            assert not mcpcompat.result_is_error(res)
            stray = await asyncio.wait_for(s.call_tool("proximo_plan", {**mutate, "confirm": True}), timeout=30)
            assert mcpcompat.result_is_error(stray) and "confirm" in stray.content[0].text
            body = json.loads(res.content[0].text)
            assert body["allowed"] is False and body["needs"] == "arm"
            read = {"plane": "pve", "path": "/nodes/x/status"}
            res = await asyncio.wait_for(s.call_tool("proximo_read", read), timeout=30)
            assert mcpcompat.result_is_error(res) and "not configured" in res.content[0].text

    asyncio.run(drive())


def test_the_door_without_the_sdk_says_which_extra(monkeypatch):
    """A missing SDK is one line naming what to install, never a traceback."""
    monkeypatch.setitem(sys.modules, "proximo.core.mcpcompat", None)
    with pytest.raises(ProximoError, match=r"pip install proximo-proxmox"):
        door.build_server()


def test_the_engine_is_what_the_door_calls():
    """No second engine: the door's plan is engine.resolve + engine.govern, nothing else."""
    row = engine.resolve("pve", "GET", "/nodes/x/status")
    assert door.plan("pve", "GET", "/nodes/x/status")["address"] == row.address


# --- the second lens round, pinned -----------------------------------------------------------

def test_a_vendor_error_reaches_the_client_without_the_estates_address(server, monkeypatch, tmp_path):
    """httpx names host, port and path in its message. On 1.x that reached the client verbatim;
    on 2.x it became a bare tool name. Now it is the door's words with the locators stripped."""
    tok = tmp_path / "tok"
    tok.write_text("user@pam!t=s\n")
    tok.chmod(0o600)
    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://estate.invalid:8006/api2/json")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(tok))
    import httpx

    def forbidden(request):
        return httpx.Response(403, json={"errors": {"perm": "denied"}})
    real = engine.wire.Client.__init__

    def patched(self, cfg):
        real(self, cfg)
        self._client = httpx.Client(base_url=cfg.base_url, transport=httpx.MockTransport(forbidden))
    monkeypatch.setattr(engine.wire.Client, "__init__", patched)
    with pytest.raises((mcpcompat.ToolError, ProximoError)) as e:
        asyncio.run(server.call_tool("proximo_read", {"plane": "pve", "path": "/nodes/x/status"}))
    text = str(e.value)
    assert "403" in text and "vendor" in text, text
    assert "estate.invalid" not in text and "8006" not in text and "/nodes/x/status" not in text, text


def test_audit_verify_is_a_read_and_mints_no_key(server, tmp_path):
    """`open_ledger` is the writer's door and creates the HMAC key on first use. A tool that
    advertises readOnlyHint must not establish the box's signing identity as a side effect."""
    before = sorted(os.listdir(tmp_path))
    out = _call(server, "audit_verify", {})
    assert out["entries"] == 0 and "note" in out
    assert sorted(os.listdir(tmp_path)) == before, "audit_verify created files"
    # and on a real keyed ledger it verifies with the key that exists, still creating nothing
    cfg = LedgerConfig(audit_log_path=str(tmp_path / "audit.log"))
    open_ledger(cfg).record("row", target="/x", mutation=False, outcome="ok", detail={})
    after = sorted(os.listdir(tmp_path))
    out = _call(server, "audit_verify", {})
    assert out["ok"] is True and out["entries"] == 1 and out["keyed"] is True
    assert sorted(os.listdir(tmp_path)) == after


def test_the_env_pin_is_a_row_the_chain_must_still_hold(server, tmp_path, monkeypatch):
    """PROXIMO_AUDIT_EXPECTED_HEAD is a static value and the head moves on every row, so an exact
    match went red on the first legitimate row (lens 3, 10-18). The env pin is a row the chain must
    still HOLD: later rows are fine; a cut below it, or a replaced file, is not. The argument stays
    exact: a caller passing a fresh off-box head is asking about the tail."""
    log = tmp_path / "audit.log"
    cfg = LedgerConfig(audit_log_path=str(log))
    led = open_ledger(cfg)
    led.record("row", target="/x", mutation=False, outcome="ok", detail={})
    pinned = led.head()
    monkeypatch.setenv("PROXIMO_AUDIT_EXPECTED_HEAD", f" {pinned.upper()} ")   # normalised, like 0.44
    led.record("row", target="/y", mutation=False, outcome="ok", detail={})     # ordinary activity
    out = _call(server, "audit_verify", {})
    assert out["ok"] is True and out["pinned"] == "env", out
    assert out["tail_verified"] is False          # a held row says nothing about a row forged after it
    exact = _call(server, "audit_verify", {"expected_head": pinned})              # the argument: the tail
    assert exact["ok"] is False and "head mismatch" in exact["reason"] and exact["pinned"] == "argument"
    assert _call(server, "audit_verify", {"expected_head": led.head()})["tail_verified"] is True
    log.write_text("")                                                            # wiped below the pin
    out = _call(server, "audit_verify", {})
    assert out["ok"] is False and "pinned row" in out["reason"], out
    other = tmp_path / "other"
    other.mkdir()
    fresh = open_ledger(LedgerConfig(audit_log_path=str(other / "audit.log")))
    fresh.record("row", target="/x", mutation=False, outcome="ok", detail={})
    log.write_text((other / "audit.log").read_text())                             # a replaced file
    (tmp_path / "audit.key").write_bytes((other / "audit.key").read_bytes())
    assert _call(server, "audit_verify", {})["ok"] is False
    monkeypatch.setenv("PROXIMO_AUDIT_EXPECTED_HEAD", "not-a-head")
    with pytest.raises((mcpcompat.ToolError, ProximoError), match="PROXIMO_AUDIT_EXPECTED_HEAD") as e:
        asyncio.run(server.call_tool("audit_verify", {}))
    assert "not-a-head" not in str(e.value)                                       # the env value is not echoed
    with pytest.raises((mcpcompat.ToolError, ProximoError), match="expected_head"):
        asyncio.run(server.call_tool("audit_verify", {"expected_head": "zz"}))


def test_find_refuses_a_negative_limit(server):
    with pytest.raises((mcpcompat.ToolError, ProximoError), match="0 or more"):
        asyncio.run(server.call_tool("proximo_find", {"query": "qemu", "limit": -1}))


# --- the stdio door's own main, driven (the swap's lens, 2026-10-17: a grep is not a drive) -----

def _rows(path):
    import json  # noqa: PLC0415
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()] if path.exists() else []


@pytest.fixture
def clean_env(monkeypatch):
    for var in list(os.environ):
        if var.startswith("PROXIMO_") and var != "PROXIMO_ENV_FILE":   # the pin on the real file stays
            monkeypatch.delenv(var)


def test_the_stdio_door_stamps_both_session_rows_even_when_serving_crashes(clean_env, tmp_path, monkeypatch):
    """`main` writes session_start before `server.run()` and session_end in a finally; a plant that
    keeps the words and loses the calls (`if False: record(...)`) is red here, not only in the
    face contract's text scan."""
    from proximo.core.doors import mcp  # noqa: PLC0415
    log = tmp_path / "audit.log"
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(log))

    class _Boom:
        def run(self):
            raise RuntimeError("stdin closed")
    monkeypatch.setattr(mcp, "build_server", lambda *a, **k: _Boom())
    with pytest.raises(RuntimeError, match="stdin closed"):
        mcp.main([])
    kinds = [(r["action"], r["target"]) for r in _rows(log)]
    assert kinds == [("session_start", "face/stdio"), ("session_end", "face/stdio")]


@pytest.mark.parametrize("switch", ["PROXIMO_SURFACES", "PROXIMO_SCOPE_PATH", "PROXIMO_ARM_TTL"])
def test_the_stdio_door_refuses_a_retired_switch_before_it_builds(clean_env, switch, monkeypatch, capsys):
    """The network doors refuse PROXIMO_SURFACES at start; the stdio door refuses it and the two
    gates retired to the vendor (SCOPE, LEASE) the same way: told at the door, never served wider."""
    from proximo.core.doors import mcp  # noqa: PLC0415
    monkeypatch.setenv(switch, "/vms/100" if switch != "PROXIMO_ARM_TTL" else "900")
    monkeypatch.setattr(mcp, "build_server", lambda *a, **k: (_ for _ in ()).throw(AssertionError("built")))
    assert mcp.main([]) == 3
    assert switch in capsys.readouterr().err
