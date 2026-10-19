"""End-to-end: a real MCP client drives `python -m proximo` over the stdio transport.

The other tests call the tool functions directly; this is the only one that exercises the
*protocol* on the default command: the `initialize` handshake (the server advertising Proximo's
OWN version, not the MCP SDK's), `tools/list`, and a clean `tools/call` round-trip. Since the
default-command swap (2026-10-17) `python -m proximo` is the core door: six tools, every published
address. No live Proxmox: `audit_verify` reads a temp ledger, and the estate is unconfigured so
nothing real is touched.
"""
import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import proximo
from proximo.core.mcpcompat import init_server_info, result_is_error

CORE_TOOLS = {"proximo_find", "proximo_plan", "proximo_read", "proximo_call", "audit_entries", "audit_verify"}


def _params(tmp_path) -> StdioServerParameters:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PROXIMO_") or k == "PROXIMO_ENV_FILE"}
    env["PROXIMO_AUDIT_LOG"] = str(tmp_path / "e2e-audit.log")
    return StdioServerParameters(command=sys.executable, args=["-m", "proximo"], env=env)


async def test_mcp_stdio_transport_end_to_end(tmp_path):
    async with stdio_client(_params(tmp_path)) as (read, write):
        async with ClientSession(read, write) as session:
            init = await asyncio.wait_for(session.initialize(), timeout=30)
            info = init_server_info(init)
            assert info.name == "proximo"
            assert info.version == proximo.__version__

            tools = await asyncio.wait_for(session.list_tools(), timeout=30)
            names = {t.name for t in tools.tools}
            assert names == CORE_TOOLS, names

            found = await asyncio.wait_for(
                session.call_tool("proximo_find", {"query": "guest status"}), timeout=30)
            assert result_is_error(found) is False
            found_text = " ".join(getattr(c, "text", "") or "" for c in (found.content or []))
            assert "/nodes/" in found_text  # the table is reachable through the door

            res = await asyncio.wait_for(session.call_tool("audit_verify", {}), timeout=30)
            assert result_is_error(res) is False
            text = " ".join(getattr(c, "text", "") or "" for c in (res.content or []))
            assert "ok" in text and "true" in text.lower()
