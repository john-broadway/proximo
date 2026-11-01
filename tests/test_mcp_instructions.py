"""The operator's MCP `instructions` (issue #123): served in `initialize` when set, absent when not,
and a set-but-unusable file refuses the door without naming its path.

`InitializeResult.instructions` is spelled the same on both SDK majors, so no seam accessor is needed."""
import asyncio
import os
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from proximo.core import doctor, instructions
from proximo.core.doors import mcp as door
from proximo.core.errors import ProximoError

TEXT = "Targets: pve, pbs, pdm. Every call names a target.\nCT exec: add snapshot: true.\n"


def _file(tmp_path, data: bytes):
    path = tmp_path / "site-rules.md"
    path.write_bytes(data)
    return path


def test_unset_sends_nothing(monkeypatch):
    monkeypatch.delenv(instructions.ENV, raising=False)
    assert instructions.load() is None
    assert instructions.station([]) == {"configured": False}


def test_set_is_the_files_text_unchanged(tmp_path, monkeypatch):
    monkeypatch.setenv(instructions.ENV, str(_file(tmp_path, TEXT.encode())))
    assert instructions.load() == TEXT
    flags: list[str] = []
    assert instructions.station(flags) == {"configured": True, "bytes": len(TEXT.encode()), "cap": instructions.CAP}
    assert flags == []


def test_exactly_the_cap_is_served(tmp_path, monkeypatch):
    monkeypatch.setenv(instructions.ENV, str(_file(tmp_path, b"x" * instructions.CAP)))
    assert len(instructions.load() or "") == instructions.CAP


@pytest.mark.parametrize(("data", "said"), [
    (b"x" * (instructions.CAP + 1), "over"),
    (b"\xff\xfe not utf-8", "UTF-8"),
    (b"  \n\t\n", "empty"),
])
def test_set_and_unusable_refuses_and_never_names_the_path(tmp_path, monkeypatch, data, said):
    path = _file(tmp_path, data)
    monkeypatch.setenv(instructions.ENV, str(path))
    with pytest.raises(ProximoError, match=said) as e:
        instructions.load()
    assert instructions.ENV in str(e.value) and str(path) not in str(e.value) and path.name not in str(e.value)
    flags: list[str] = []
    section = instructions.station(flags)
    assert section["configured"] is True and said in section["error"]
    assert len(flags) == 1 and str(path) not in flags[0]


def test_a_missing_file_refuses_the_door(tmp_path, monkeypatch):
    monkeypatch.setenv(instructions.ENV, str(tmp_path / "nope.md"))
    with pytest.raises(ProximoError, match="cannot read"):
        door.build_server()


def test_doctor_reports_the_section_and_its_flag_is_not_advisory(tmp_path, monkeypatch):
    monkeypatch.setenv(instructions.ENV, str(_file(tmp_path, b"")))
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "audit.log"))
    report = doctor.run()
    assert report["instructions"]["configured"] is True and "empty" in report["instructions"]["error"]
    assert report["complete"] is False                     # a door that will not start is not a whole box


def _params(tmp_path, extra: dict[str, str]) -> StdioServerParameters:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PROXIMO_") or k == "PROXIMO_ENV_FILE"}
    env["PROXIMO_AUDIT_LOG"] = str(tmp_path / "audit.log")
    return StdioServerParameters(command=sys.executable, args=["-m", "proximo"], env={**env, **extra})


async def _initialize(params: StdioServerParameters):
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        return await asyncio.wait_for(s.initialize(), timeout=30)


def test_initialize_carries_the_text_over_the_real_stdio_wire(tmp_path):
    init = asyncio.run(_initialize(_params(tmp_path, {instructions.ENV: str(_file(tmp_path, TEXT.encode()))})))
    assert init.instructions == TEXT


def test_initialize_carries_none_when_unset(tmp_path):
    init = asyncio.run(_initialize(_params(tmp_path, {})))
    assert init.instructions is None
