"""The operator's instructions (issue #123, widened): the text of the file `PROXIMO_INSTRUCTIONS`
names, read through the one guarded reader. A set and unusable file sends none, and the sentence
that says why names the variable and never the path or a byte of the file.

`InitializeResult.instructions` is spelled the same on both SDK majors, so no seam accessor is needed."""
import asyncio
import json
import os
import subprocess
import sys

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from proximo.core import doctor, instructions, receipt, wordsfile
from proximo.core.errors import ProximoError

TEXT = "Targets: pve, pbs, pdm. Every call names a target.\nCT exec: add snapshot: true.\n"
SECRET = "PVEAPIToken=root@pam!x=5b1d6a8e-not-a-real-one"  # noqa: S105 -- a made-up token, to be found nowhere


def _file(tmp_path, data: bytes, name: str = "site-rules.md"):
    folder = tmp_path / "words"
    folder.mkdir(exist_ok=True)
    path = folder / name
    path.write_bytes(data)
    return path


def _station(flags: list[str]):
    return instructions.station(flags, doctor._said)


def _never_says(path, *texts: str) -> None:
    for text in texts:
        assert str(path) not in text and path.name not in text and str(path.parent) not in text


def test_unset_sends_nothing(monkeypatch):
    monkeypatch.delenv(instructions.ENV, raising=False)
    assert instructions.load() is None
    assert _station([]) == {"configured": False}


def test_whitespace_only_is_unset(monkeypatch):
    monkeypatch.setenv(instructions.ENV, "  \t ")
    assert instructions.load() is None
    assert _station([]) == {"configured": False}


def test_set_is_the_files_text_unchanged(tmp_path, monkeypatch):
    monkeypatch.setenv(instructions.ENV, str(_file(tmp_path, TEXT.encode())))
    assert instructions.load() == TEXT
    flags: list[str] = []
    assert _station(flags) == {"configured": True, "bytes": len(TEXT.encode()), "cap": instructions.CAP}
    assert flags == []


def test_exactly_the_cap_is_served(tmp_path, monkeypatch):
    monkeypatch.setenv(instructions.ENV, str(_file(tmp_path, b"x" * instructions.CAP)))
    assert len(instructions.load() or "") == instructions.CAP


def test_over_the_soft_size_is_served_with_advice_that_never_says_where(tmp_path, monkeypatch):
    path = _file(tmp_path, b"x" * (instructions.SOFT + 1))
    monkeypatch.setenv(instructions.ENV, str(path))
    assert instructions.load() is not None                 # served whole: the soft size refuses nothing
    flags: list[str] = []
    assert _station(flags)["bytes"] == instructions.SOFT + 1
    assert len(flags) == 1 and flags[0].startswith(doctor._ADVISORY) and "truncate" in flags[0]
    _never_says(path, flags[0])
    at_soft: list[str] = []
    monkeypatch.setenv(instructions.ENV, str(_file(tmp_path, b"x" * instructions.SOFT)))
    _station(at_soft)
    assert at_soft == []


def test_a_byte_order_mark_is_never_served(tmp_path, monkeypatch):
    monkeypatch.setenv(instructions.ENV, str(_file(tmp_path, b"\xef\xbb\xbf" + TEXT.encode())))
    assert instructions.load() == TEXT


def test_a_tilde_is_the_home_folder(tmp_path, monkeypatch):
    _file(tmp_path, TEXT.encode())
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv(instructions.ENV, "~/words/site-rules.md")
    assert instructions.load() == TEXT


def _fifo(tmp_path):
    path = tmp_path / "words" / "pipe.md"
    path.parent.mkdir(exist_ok=True)
    os.mkfifo(path)
    return path


def _folder(tmp_path):
    path = tmp_path / "words" / "a-folder.md"
    path.mkdir(parents=True)
    return path


@pytest.mark.parametrize(("make", "said"), [
    (lambda t: _file(t, b"x" * (instructions.CAP + 1)), "over"),
    (lambda t: _file(t, b"x" * (instructions.CAP * 100)), "over"),      # the read is bounded: still "over"
    (lambda t: _file(t, b"\xff\xfe not utf-8"), "UTF-8"),
    (lambda t: _file(t, b"  \n\t\n"), "empty"),
    (lambda t: _file(t, b""), "empty"),
    (lambda t: _file(t, b"\xef\xbb\xbf"), "empty"),                     # nothing but a byte-order mark
    (lambda t: t / "words" / "nope.md", "cannot read"),
    (_folder, "regular file"),                                          # a second OSError shape, not FileNotFound
    (_fifo, "regular file"),                                            # and it does not wait for a writer
])
def test_set_and_unusable_is_refused_by_load_and_never_names_the_path(tmp_path, monkeypatch, make, said):
    path = make(tmp_path)
    monkeypatch.setenv(instructions.ENV, str(path))
    with pytest.raises(ProximoError, match=said) as e:
        instructions.load()
    assert instructions.ENV in str(e.value)
    flags: list[str] = []
    section = _station(flags)
    assert section == {"configured": True, "error": section["error"]}   # exactly these keys: no `path`, ever
    assert said in section["error"]
    assert len(flags) == 1 and flags[0].startswith("the instructions are set and unusable")
    assert not flags[0].startswith(doctor._ADVISORY)
    _never_says(path, str(e.value), json.dumps(section), flags[0])


# --- the guard: a credential is never served (A3) -----------------------------------------------

def _token(tmp_path, monkeypatch):
    folder = tmp_path / "config"
    folder.mkdir()
    token = folder / "pve.token"
    token.write_text(SECRET)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(token))
    return token


def _link(tmp_path, token):
    path = tmp_path / "words" / "rules.md"
    path.parent.mkdir(exist_ok=True)
    path.symlink_to(token)
    return path


def _hard(tmp_path, token):
    path = tmp_path / "words" / "rules.md"
    path.parent.mkdir(exist_ok=True)
    os.link(token, path)
    return path


@pytest.mark.parametrize("reach", [lambda t, token: token, _link, _hard])
def test_a_token_file_is_never_served_however_it_is_reached(tmp_path, monkeypatch, reach):
    path = reach(tmp_path, _token(tmp_path, monkeypatch))
    monkeypatch.setenv(instructions.ENV, str(path))
    with pytest.raises(ProximoError, match="PROXIMO_TOKEN_PATH names: a credential is never served") as e:
        instructions.load()
    flags: list[str] = []
    section = _station(flags)
    said = (str(e.value), json.dumps(section), *flags)
    assert len(flags) == 1 and "PROXIMO_TOKEN_PATH" in flags[0]         # the VARIABLE collided with
    _never_says(path, *said)
    assert not any(SECRET in s or "5b1d6a8e" in s for s in said)


def test_a_file_inside_a_folder_another_variable_names_is_never_served(tmp_path, monkeypatch):
    folder = tmp_path / "consent"
    folder.mkdir()
    (folder / "grant.md").write_text(TEXT)
    monkeypatch.setenv("PROXIMO_CONSENT_DIR", str(folder))
    monkeypatch.setenv(instructions.ENV, str(folder / "grant.md"))
    with pytest.raises(ProximoError, match="PROXIMO_CONSENT_DIR names: a credential is never served"):
        instructions.load()


def test_a_file_with_a_second_name_is_never_served(tmp_path, monkeypatch):
    path = _file(tmp_path, TEXT.encode())
    os.link(path, tmp_path / "words" / "second-name.md")
    monkeypatch.setenv(instructions.ENV, str(path))
    with pytest.raises(ProximoError, match=r"a second name \(a hard link\)"):
        instructions.load()


def test_a_registry_that_cannot_be_read_proves_nothing_so_nothing_is_served(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_TARGETS", str(tmp_path / "targets-that-is-not-there.toml"))
    path = _file(tmp_path, TEXT.encode())
    monkeypatch.setenv(instructions.ENV, str(path))
    with pytest.raises(ProximoError) as e:
        instructions.load()
    assert "PROXIMO_TARGETS could not be read, so nothing proves this file is not a credential" in str(e.value)
    _never_says(path, str(e.value))


def test_a_platform_that_cannot_say_where_a_file_is_has_its_own_sentence(tmp_path, monkeypatch):
    def nowhere(fd):
        raise wordsfile.Refused(wordsfile.UNPROVEN, "this platform")
    monkeypatch.setattr(wordsfile, "_where", nowhere)
    monkeypatch.setenv(instructions.ENV, str(_file(tmp_path, TEXT.encode())))
    with pytest.raises(ProximoError) as e:
        instructions.load()
    assert "this platform cannot say where an opened file really is" in str(e.value)
    assert "this platform could not be read" not in str(e.value)


def test_the_documented_layout_is_served(tmp_path, monkeypatch):
    """The positive control for a reader that refuses on doubt: the words file beside the env file
    and a token file, in one config folder, the layout SETUP and the env example show."""
    token = _token(tmp_path, monkeypatch)
    env_file = token.parent / "proximo.env"
    env_file.write_text("PROXIMO_API_BASE_URL=https://pve.example:8006/api2/json\n")
    monkeypatch.setenv("PROXIMO_ENV_FILE", str(env_file))
    words = token.parent / "instructions.md"
    words.write_text(TEXT)
    monkeypatch.setenv(instructions.ENV, str(words))
    assert instructions.load() == TEXT


# --- the name this variable had on the unmerged branch -------------------------------------------

def test_the_old_name_alone_is_not_read_and_doctor_says_so(tmp_path, monkeypatch):
    monkeypatch.delenv(instructions.ENV, raising=False)
    monkeypatch.setenv(instructions.OLD, str(_file(tmp_path, TEXT.encode())))
    assert instructions.load() is None
    flags: list[str] = []
    assert _station(flags) == {"configured": False}
    assert flags == ["PROXIMO_MCP_INSTRUCTIONS is set and is not read: the variable is PROXIMO_INSTRUCTIONS"]
    assert not flags[0].startswith(doctor._ADVISORY)


def test_both_names_on_one_file_serves_it_and_still_says_the_old_name_is_not_read(tmp_path, monkeypatch):
    """Whoever ran the unmerged branch adds the new name and leaves the old one: the file is their
    words, not a credential, so it is served, and the old name is still flagged until it is unset."""
    path = _file(tmp_path, TEXT.encode())
    monkeypatch.setenv(instructions.OLD, str(path))
    monkeypatch.setenv(instructions.ENV, str(path))
    assert instructions.load() == TEXT
    flags: list[str] = []
    assert _station(flags)["bytes"] == len(TEXT.encode())
    assert len(flags) == 1 and flags[0].startswith("PROXIMO_MCP_INSTRUCTIONS is set and is not read")


# --- doctor and its receipt ------------------------------------------------------------------------

def test_doctor_reports_the_section_and_its_flag_is_not_advisory(tmp_path, monkeypatch):
    path = _file(tmp_path, b"")
    monkeypatch.setenv(instructions.ENV, str(path))
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(tmp_path / "state" / "audit.log"))
    report = doctor.run()
    assert set(report["instructions"]) == {"configured", "error"}
    assert report["instructions"]["configured"] is True and "empty" in report["instructions"]["error"]
    [flag] = [f for f in report["flags"] if "instructions" in f]
    assert not flag.startswith(doctor._ADVISORY)           # set, and no caller receives it: not a whole box
    assert report["complete"] is False
    _never_says(path, json.dumps(report["instructions"]), flag)


def test_the_refusal_doctor_repeats_goes_through_doctors_own_scrubber(tmp_path, monkeypatch):
    monkeypatch.setenv(instructions.ENV, str(_file(tmp_path, b"")))
    flags: list[str] = []
    section = instructions.station(flags, lambda exc: "<scrubbed>")
    assert section == {"configured": True, "error": "<scrubbed>"}
    assert flags == ["the instructions are set and unusable, so no caller receives them: <scrubbed>"]


def test_the_receipt_carries_the_section_and_codes_every_flag(tmp_path, monkeypatch):
    monkeypatch.setenv(instructions.OLD, "anything")
    monkeypatch.setenv(instructions.ENV, str(_file(tmp_path, b"x" * (instructions.SOFT + 1))))
    flags: list[str] = []
    section = _station(flags)
    allowed = receipt.allowed({"instructions": section, "flags": flags})
    assert allowed["instructions"] == {"configured": True, "bytes": instructions.SOFT + 1, "cap": instructions.CAP}
    assert sorted(receipt.flag_code(f) for f in flags) == ["instructions-long", "old-instructions-name"]
    monkeypatch.setenv(instructions.ENV, str(_file(tmp_path, b"")))
    unusable: list[str] = []
    refused = receipt.allowed({"instructions": _station(unusable), "flags": unusable})["instructions"]
    assert refused == {"configured": True, "error": receipt.TEXT}       # that there is a reason, never its words
    assert "instructions-unusable" in [receipt.flag_code(f) for f in unusable]


# --- the real stdio wire -----------------------------------------------------------------------------

def _env(tmp_path, extra: dict[str, str]) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("PROXIMO_") or k == "PROXIMO_ENV_FILE"}
    env["PROXIMO_AUDIT_LOG"] = str(tmp_path / "state" / "audit.log")
    return {**env, **extra}


def _params(tmp_path, extra: dict[str, str]) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "proximo"], env=_env(tmp_path, extra))


async def _initialize(params: StdioServerParameters):
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        return await asyncio.wait_for(s.initialize(), timeout=30)


def test_initialize_carries_the_text_over_the_real_stdio_wire(tmp_path):
    init = asyncio.run(_initialize(_params(tmp_path, {instructions.ENV: str(_file(tmp_path, TEXT.encode()))})))
    assert init.instructions == TEXT


def test_initialize_carries_none_when_unset(tmp_path):
    init = asyncio.run(_initialize(_params(tmp_path, {})))
    assert init.instructions is None


def test_a_bad_file_still_serves_the_door_with_none(tmp_path):
    init = asyncio.run(_initialize(_params(tmp_path, {instructions.ENV: str(_file(tmp_path, b"\xff\xfe"))})))
    assert init.instructions is None


def test_the_old_name_sends_nothing_over_the_real_stdio_wire(tmp_path):
    init = asyncio.run(_initialize(_params(tmp_path, {instructions.OLD: str(_file(tmp_path, TEXT.encode()))})))
    assert init.instructions is None


def test_a_named_pipe_hangs_neither_the_door_nor_doctor(tmp_path):
    """A4: each in its own process, each done inside 20 seconds; a hang is killed by the timeout."""
    extra = {instructions.ENV: str(_fifo(tmp_path))}

    async def door():
        async with stdio_client(_params(tmp_path, extra)) as (r, w), ClientSession(r, w) as s:
            return await asyncio.wait_for(s.initialize(), timeout=20)
    assert asyncio.run(door()).instructions is None
    done = subprocess.run([sys.executable, "-m", "proximo", "doctor"], env=_env(tmp_path, extra),  # noqa: S603
                          capture_output=True, text=True, timeout=20, check=False)
    assert "the instructions are set and unusable" in done.stdout + done.stderr
    assert "regular file" in done.stdout + done.stderr
