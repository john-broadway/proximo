"""The served tool surface has a checksum an operator can pin.

Field read 2026-09-20: a rival ships a compile-time-fixed MCP tool registry with a SHA-256 an
operator pins across deploys; Proximo's manifest was a file, not a pin. The checksum here is
over what THIS process serves — name, description and input schema of every registered tool,
after auto-scoping, slimming and the door choice — so it is per config, and the docs say so.
`PROXIMO_TOOLS_PIN=<sha256>` refuses to start on a mismatch (the same ValueError path every
other refused config takes), and `proximo tools-checksum` prints it."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys

import pytest

from proximo import _mcpcompat as compat
from proximo import door


def _probe(desc_a: str = "READ-ONLY: a."):
    srv = compat.make_server("checksum-probe", version="0.0.0")

    @srv.tool()
    def alpha(x: int) -> dict:
        """READ-ONLY: a."""
        return {"x": x}

    alpha_tool = srv._tool_manager._tools["alpha"]  # noqa: SLF001
    alpha_tool.description = desc_a

    @srv.tool()
    def beta() -> dict:
        """READ-ONLY: b."""
        return {}

    return srv


def test_checksum_is_deterministic_and_counts_the_served_tools():
    a, n = door.surface_checksum(_probe())
    b, m = door.surface_checksum(_probe())
    assert a == b and n == m == 2
    assert len(a) == 64 and int(a, 16) >= 0


def test_checksum_moves_when_a_description_or_schema_moves():
    base, _ = door.surface_checksum(_probe())
    desc, _ = door.surface_checksum(_probe(desc_a="READ-ONLY: a, reworded."))
    assert desc != base
    srv = _probe()
    srv._tool_manager._tools["beta"].parameters["properties"]["y"] = {"type": "string"}  # noqa: SLF001
    schema, _ = door.surface_checksum(srv)
    assert schema != base and schema != desc


def test_checksum_is_the_sha256_of_the_canonical_surface():
    """Pin the recipe, not just the property: sorted by name, sort_keys JSON, no whitespace."""
    srv = _probe()
    rows = sorted(
        [
            {"name": t.name, "description": t.description or "", "parameters": t.parameters}
            for t in srv._tool_manager._tools.values()  # noqa: SLF001
        ],
        key=lambda r: r["name"],
    )
    want = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert door.surface_checksum(srv)[0] == want


def test_pin_match_passes_and_mismatch_refuses(monkeypatch):
    srv = _probe()
    hexd, _ = door.surface_checksum(srv)
    monkeypatch.setenv("PROXIMO_TOOLS_PIN", "sha256:" + hexd.upper())  # prefix and case tolerated
    door.enforce_tools_pin(srv)  # no raise
    monkeypatch.setenv("PROXIMO_TOOLS_PIN", "0" * 64)
    with pytest.raises(ValueError) as exc:
        door.enforce_tools_pin(srv)
    assert hexd in str(exc.value) and "0" * 64 in str(exc.value)
    monkeypatch.setenv("PROXIMO_TOOLS_PIN", "not-a-hash")
    with pytest.raises(ValueError, match="64 hex"):
        door.enforce_tools_pin(srv)
    monkeypatch.delenv("PROXIMO_TOOLS_PIN")
    door.enforce_tools_pin(srv)  # unset = not enforced


def test_the_real_surface_hashes_the_same_in_two_fresh_processes(tmp_path):
    """The number an operator writes down must not depend on the process that computed it: a
    nondeterministic step in schema generation or slimming would make the pin a coin flip."""
    tok = str(tmp_path / "tok")
    code = (
        "import os; os.environ['PROXIMO_API_BASE_URL']='https://x:8006/api2/json'; os.environ['PROXIMO_NODE']='x1';"
        f"os.environ['PROXIMO_TOKEN_PATH']={tok!r};"
        "from proximo import door; import proximo.server as s; door._apply_surfaces(s.mcp);"
        "print(door.surface_checksum(s.mcp)[0])"
    )
    (tmp_path / "tok").write_text("u@pam!t=deterministic-probe-secret")
    (tmp_path / "tok").chmod(0o600)
    outs = []
    for _ in range(2):
        r = subprocess.run(  # noqa: S603 — our own interpreter, our own literal code
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=120, check=False
        )
        assert r.returncode == 0, r.stderr[-800:]
        outs.append(r.stdout.strip().splitlines()[-1])
    assert outs[0] == outs[1] and len(outs[0]) == 64, outs


def test_apply_surfaces_prints_the_checksum_and_enforces_the_pin(monkeypatch, capsys):
    """Every caller of _apply_surfaces (the stdio server, doctor) gets the stamp and the gate."""
    import proximo.server as server

    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "x1")
    saved = dict(server.mcp._tool_manager._tools)  # noqa: SLF001
    try:
        door._apply_surfaces(server.mcp)
        err = capsys.readouterr().err
        hexd, n = door.surface_checksum(server.mcp)
        assert f"tool surface sha256 {hexd} ({n} tools served)" in err
        monkeypatch.setenv("PROXIMO_TOOLS_PIN", "f" * 64)
        with pytest.raises(ValueError, match="PROXIMO_TOOLS_PIN"):
            door._apply_surfaces(server.mcp)
    finally:
        server.mcp._tool_manager._tools.clear()  # noqa: SLF001
        server.mcp._tool_manager._tools.update(saved)  # noqa: SLF001


def test_cli_tools_checksum_prints_hash_and_count(monkeypatch, capsys):
    import proximo.server as server

    monkeypatch.setenv("PROXIMO_API_BASE_URL", "https://x:8006/api2/json")
    monkeypatch.setenv("PROXIMO_NODE", "x1")
    monkeypatch.setattr(sys, "argv", ["proximo", "tools-checksum"])
    saved = dict(server.mcp._tool_manager._tools)  # noqa: SLF001
    try:
        server.main()
        out = capsys.readouterr().out.strip()
        hexd, n = door.surface_checksum(server.mcp)
        assert out == f"{hexd}  {n} tools"
    finally:
        server.mcp._tool_manager._tools.clear()  # noqa: SLF001
        server.mcp._tool_manager._tools.update(saved)  # noqa: SLF001
