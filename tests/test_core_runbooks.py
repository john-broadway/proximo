"""The operator's runbooks (`core/runbooks.py`): which files in the folder are served, and why not.

A runbook is text a model follows, so it is held to the address rules Proximo's own five are
tested with, made strict. Every refusal here names the runbook by its file's name and, for an
address, the method and path as written: never a folder, never another byte of the file."""
import asyncio
import json

import pytest

from proximo.core import doctor, engine, prompts, receipt, runbooks, words, wordsfile
from proximo.core.doors import mcp as door
from proximo.core.errors import ProximoError

SOUND = "# Drain a node\n\nplane: pve\n\n1. proximo_read pve GET /nodes/{node}/status, fields=\"all\".\n2. Stop.\n"
FIVE = {fn.__name__ for fn in prompts.RUNBOOKS}


def _body(steps: str, plane: str = "pve", title: str = "# A job") -> str:
    return f"{title}\n\nplane: {plane}\n\n{steps}\n"


@pytest.fixture
def folder(tmp_path, monkeypatch):
    path = tmp_path / "runbooks"
    path.mkdir()
    monkeypatch.setenv(runbooks.ENV, str(path))
    monkeypatch.delenv("PROXIMO_INSTRUCTIONS", raising=False)
    return path


def _reason(text: str) -> str:
    with pytest.raises(ProximoError) as e:
        runbooks.check("job", text)
    return str(e.value)


# --- one file ---------------------------------------------------------------------------------------

def test_a_sound_runbook_is_its_file_behind_one_fixed_line():
    book = runbooks.check("drain_node", SOUND)
    assert (book.name, book.title, book.plane) == ("drain_node", "Drain a node", "pve")
    assert book.text == "Operator runbook (not Proximo's): drain_node.\n\n" + SOUND


def test_crlf_line_ends_and_blank_lines_before_the_plane_are_read():
    assert runbooks.check("job", "# A job\r\n\r\n\r\nplane: pbs\r\nGET /version\r\n").plane == "pbs"


@pytest.mark.parametrize("plane", ["pve", "pbs", "pmg", "pdm"])
def test_each_plane_is_checked_against_its_own_table(plane):
    assert runbooks.check("job", _body("Read GET /version first.", plane)).plane == plane


@pytest.mark.parametrize("text", [
    "Drain a node\n\nplane: pve\n\nGET /version\n",                      # no `# `
    "#Drain\n\nplane: pve\n\nGET /version\n",                             # no space
    "# \n\nplane: pve\n\nGET /version\n",                                 # empty
    "# " + "x" * 81 + "\n\nplane: pve\n\nGET /version\n",                 # over 80
    "# A\x1b[31m job\n\nplane: pve\n\nGET /version\n",                    # a control character
])
def test_a_title_that_is_not_a_title_refuses(text):
    assert "its first line is not a title" in _reason(text)


@pytest.mark.parametrize("second", [
    "GET /version", "plane: esx", "plane:pve", "Plane: pve", "plane: pve pbs", "plane: "])
def test_a_missing_or_malformed_plane_refuses(second):
    assert "the line after its title is not `plane: `" in _reason(f"# A job\n\n{second}\n\nGET /version\n")


def test_rule_1_a_runbook_that_names_no_address_refuses():
    assert "names no address" in _reason(_body("Look at the node, then stop."))


def test_rule_2_an_address_the_plane_does_not_publish_refuses_and_is_quoted():
    assert _reason(_body("Call GET /nodes/{node}/nope.")) == \
        "it names an address pve does not publish: GET /nodes/{node}/nope"
    assert "pmg does not publish: GET /nodes/{node}/qemu" in _reason(_body("GET /nodes/{node}/qemu", "pmg"))


def test_every_address_is_checked_not_only_the_first():
    assert _reason(_body("GET /version, then GET /nodes/{node}/status, then POST /nodes/{node}/nope.")) == \
        "it names an address pve does not publish: POST /nodes/{node}/nope"
    assert "straight after a path" in _reason(_body("GET /version, then GET /nodes/pve1.lab/status"))


@pytest.mark.parametrize(("written", "plane"), [
    ("POST /nodes/{node}/{execute}", "pve"),                   # held, would be judged as /nodes/{node}/aplinfo
    ("POST /nodes/{node}/qemu/{vmid}/{termproxy}", "pve"),     # excluded, would be judged as .../agent
    ("POST /access/{ticket}", "pve"),                          # held, would be judged as /access/domains
    ("GET /nodes/{n}/status", "pve"),                          # not the vendor's spelling
    ("GET /{anything}", "pve"),
    ("GET /nodes/{node}/status/", "pve"),                      # a trailing slash is not the vendor's spelling
])
def test_a_template_is_the_vendors_own_spelling_or_it_refuses(written, plane):
    """A `{x}` is "some value here" to the resolver, so a made-up one would hide the address it stands
    for behind a sibling. Found by the lens on 9ec610be."""
    assert "a template pve does not publish in that spelling" in _reason(_body(written, plane))


def test_a_concrete_path_to_a_held_address_refuses():
    assert _reason(_body("POST /nodes/pve1/execute")) == \
        "it names an address Proximo does not call: POST /nodes/pve1/execute"


@pytest.mark.parametrize("written", [
    "https://pve.lab:8006/api2/json/nodes/pve1/status/stop", "curl -X POST .../api2/extjs/access/ticket",
    "https://pve:8006/API2/json/nodes/pve1/execute"])
def test_a_vendor_api_url_refuses(written):
    assert "a vendor API URL" in _reason(_body(f"First GET /version. Then {written}"))


def test_rule_2_a_long_path_is_quoted_cut():
    reason = _reason(_body("GET /" + "a" * 600))
    assert reason.endswith("GET /" + "a" * 119) and len(reason) < 200


@pytest.mark.parametrize(("address", "what"), [("GET /backup", "excluded"), ("DELETE /access/ticket", "held")])
def test_rule_3_a_published_address_proximo_does_not_call_refuses(address, what):
    method, path = address.split(" ")
    row = engine.table()[("pbs", method, path)]                              # the control: it IS published
    assert bool(row.excluded) if what == "excluded" else bool(row.held)
    assert _reason(_body(f"Then {address}.", "pbs")) == f"it names an address Proximo does not call: {address}"


@pytest.mark.parametrize("written", [
    "GET /nodes/pve1.lab/status",          # the check would have judged /nodes/pve1
    "GET /nodes/{node}/status?x=1",
    "GET /nodes/{node}/status*",
    "GET /nodes/{node}/status.then",
])
def test_rule_4_anything_but_sentence_punctuation_after_a_path_refuses(written):
    assert "something is written straight after a path" in _reason(_body(f"Call {written} now."))


@pytest.mark.parametrize("written", [
    "GET /nodes/{node}/status.", "GET /nodes/{node}/status,", "`GET /nodes/{node}/status`.",
    "(GET /nodes/{node}/status)", "\"GET /nodes/{node}/status\"", "GET /nodes/{node}/status?",
    "GET /nodes/{node}/status",
])
def test_rule_4_a_sentence_may_end_after_a_path(written):
    assert runbooks.check("job", _body(f"Call {written}")).plane == "pve"


@pytest.mark.parametrize("written", [
    "get /nodes/{node}/status",                    # a lowercase method
    "**GET** /nodes/{node}/status",                # formatting between the two
    "GET  /nodes/{node}/status",                   # two spaces
    "GET\n/nodes/{node}/status",                   # split over a line
    "| GET | /nodes/{node}/status |",              # split over a table cell
    'path="/nodes/{node}/status"',                 # the tools' own form
    "PATCH /nodes/{node}/status",                  # a method the table does not have
    "see /etc/network/interfaces",                 # a filesystem path: the stated cost
    "post /pools",                                 # one segment, lowercase
    "POST to //nodes/{node}/execute",               # a doubled slash (lens 2)
    "`//access/ticket`",
    "-/nodes/{node}/execute", "{/nodes/{node}/execute}", "}/nodes/{node}/execute", "(/nodes/{node}/execute)",
    "**POST** /pools",
    "then /version alone",
])
def test_rule_5_a_path_without_its_method_refuses(written):
    assert "a path without its method" in _reason(_body(f"First GET /version. Then {written} and stop."))


def test_a_url_and_a_one_segment_word_are_not_paths():
    text = _body("First GET /version. Docs: https://pve.proxmox.com/wiki/Backup and/or the n/a case.")
    assert runbooks.check("job", text).plane == "pve"


# --- the folder -------------------------------------------------------------------------------------

def test_unset_is_none(monkeypatch):
    monkeypatch.delenv(runbooks.ENV, raising=False)
    assert runbooks.load() is None


def test_only_files_named_like_runbooks_are_candidates_and_the_rest_are_counted(folder):
    (folder / "drain_node.md").write_text(SOUND)
    others = ("README.md", "notes.txt", "Drain.md", "a-b.md", "9lives.md", "x" * 41 + ".md", ".hidden.md", "a.md.bak")
    for other in others:
        (folder / other).write_text(SOUND)
    (folder / "sub").mkdir()
    got = runbooks.load()
    assert [b.name for b in got.served] == ["drain_node"] and got.refused == () and got.ignored == 9


def test_a7_one_sound_runbook_among_five_that_are_not(folder, monkeypatch):
    for name, steps in {
        "unpublished": "GET /nodes/{node}/nope", "no_address": "Look, then stop.",
        "lowercase": "get /nodes/{node}/status", "bare_path": "GET /version then /nodes/{node}/status",
    }.items():
        (folder / f"{name}.md").write_text(_body(steps))
    (folder / "excluded.md").write_text(_body("GET /backup", "pbs"))
    (folder / "sound.md").write_text(SOUND)
    got = runbooks.load()
    assert [b.name for b in got.served] == ["sound"]
    assert sorted(r.name for r in got.refused) == ["bare_path", "excluded", "lowercase", "no_address", "unpublished"]
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(folder.parent / "state" / "audit.log"))
    report = doctor.run()
    assert report["runbooks"] == {"configured": True, "served": 1, "refused": 5, "ignored": 0, "cap": 8192, "max": 32}
    flags = [f for f in report["flags"] if f.startswith("an operator runbook is not served: ")]
    assert len(flags) == 5 and not any(f.startswith(doctor._ADVISORY) for f in flags)
    assert report["complete"] is False
    assert not any(str(folder) in f or folder.name + "/" in f for f in report["flags"])
    names = [p.name for p in asyncio.run(door.build_server(words=words.at_start(bearer=True)).list_prompts())]
    assert sorted(names) == sorted([*FIVE, "sound"])


def test_a8_a_file_with_the_name_of_one_of_the_five_is_refused_unopened(folder, monkeypatch):
    (folder / "safe_backup.md").write_text(SOUND)
    opened: list[str] = []
    real = wordsfile.read
    monkeypatch.setattr(wordsfile, "read", lambda path, cap: opened.append(path) or real(path, cap))
    got = runbooks.load()
    assert got.served == () and got.refused == (
        runbooks.Refusal("safe_backup", "that is the name of one of Proximo's own runbooks"),)
    assert opened == []
    args = {"guest": "105"}

    def text(server):
        return asyncio.run(server.get_prompt("safe_backup", args)).messages[0].content.text
    assert text(door.build_server(words=words.at_start(bearer=True))) == text(door.build_server())


@pytest.mark.parametrize(("make", "reason"), [
    (lambda f, t: (f / "job.md").write_bytes(b"x" * (runbooks.CAP + 1)), "it is over 8192 bytes"),
    (lambda f, t: (f / "job.md").write_bytes(b"\xff\xfe"), "it is not UTF-8 text"),
    (lambda f, t: (f / "job.md").write_bytes(b""), "it is empty"),
    (lambda f, t: (f / "job.md").mkdir(), "it is not a regular file"),
    (lambda f, t: (f / "job.md").symlink_to(t),
     "it is a file that PROXIMO_TOKEN_PATH names: a credential is never served"),
    (lambda f, t: (f / "job.md").symlink_to(f / "gone.md"), "this process cannot read it"),
])
def test_a_runbook_file_meets_the_same_guard_as_the_instructions(folder, tmp_path, monkeypatch, make, reason):
    token = tmp_path / "pve.token"
    token.write_text("# A job\n\nplane: pve\n\nGET /version PVEAPIToken=not-a-real-one\n")
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(token))
    make(folder, token)
    got = runbooks.load()
    assert got.served == () and got.refused == (runbooks.Refusal("job", reason),)


def test_a_second_hard_link_to_a_runbook_refuses_both_names(folder):
    (folder / "one.md").write_text(SOUND)
    (folder / "two.md").hardlink_to(folder / "one.md")
    got = runbooks.load()
    assert got.served == ()
    assert {r.reason for r in got.refused} == {"it has a second name (a hard link): a words file has one"}


@pytest.mark.parametrize("make", [
    lambda p: p.rmdir(),                                   # not there
    lambda p: (p.rmdir(), p.write_text("x")),              # a file
    lambda p: [(p / f"e{i}").touch() for i in range(runbooks.FOLDER_MAX + 1)],     # one over, exactly
])
def test_a14_an_unusable_folder_costs_the_runbooks_never_the_door(folder, monkeypatch, capsys, make):
    make(folder)
    with pytest.raises(ProximoError) as e:
        runbooks.load()
    assert runbooks.ENV in str(e.value) and str(folder) not in str(e.value)
    got = words.at_start(bearer=True)
    err = capsys.readouterr().err
    assert got.runbooks == () and err.count("\n") == 1 and "no caller receives the operator's runbooks" in err
    assert str(folder) not in err
    assert {p.name for p in asyncio.run(door.build_server(words=got).list_prompts())} == FIVE
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(folder.parent / "state" / "audit.log"))
    report = doctor.run()
    assert set(report["runbooks"]) == {"configured", "cap", "max", "error"}
    [flag] = [f for f in report["flags"] if "runbooks" in f]
    assert flag.startswith("the runbooks folder is set and unusable") and not flag.startswith(doctor._ADVISORY)
    assert str(folder) not in json.dumps(report["runbooks"]) + flag


def test_exactly_the_folder_limit_is_read(folder):
    for i in range(runbooks.FOLDER_MAX):
        (folder / f"e{i}").touch()
    assert runbooks.load().ignored == runbooks.FOLDER_MAX


def test_a15_only_the_first_32_by_name_are_opened_and_one_flag_carries_the_count(folder, monkeypatch):
    for i in range(33):
        (folder / f"job_{i:02d}.md").write_text(SOUND)
    opened: list[str] = []
    real = wordsfile.read
    monkeypatch.setattr(wordsfile, "read", lambda path, cap: opened.append(path) or real(path, cap))
    got = runbooks.load()
    assert len(opened) == 32 and got.unread == 1
    assert [b.name for b in got.served] == [f"job_{i:02d}" for i in range(32)]           # in name order
    assert runbooks.said(got) == ["the runbooks folder holds 33 runbook files and only the first 32 by name are read"]


def test_a_refusal_is_said_once_at_start_and_the_sound_ones_are_served(folder, capsys):
    (folder / "sound.md").write_text(SOUND)
    (folder / "bad.md").write_text(_body("GET /nodes/{node}/nope"))
    got = words.at_start(bearer=True)
    assert [b.name for b in got.runbooks] == ["sound"]
    assert capsys.readouterr().err == (
        "proximo: an operator runbook is not served: bad: it names an address pve does not publish: "
        "GET /nodes/{node}/nope\n")


def test_a_door_with_no_bearer_lists_and_opens_nothing(folder, monkeypatch, capsys):
    (folder / "sound.md").write_text(SOUND)
    monkeypatch.setattr(runbooks, "load", lambda: pytest.fail("the folder was read for a door with no bearer"))
    assert words.at_start(bearer=False).runbooks == ()
    assert "no bearer token" in capsys.readouterr().err


# --- the prompt a caller sees -------------------------------------------------------------------------

def test_an_operator_runbook_is_a_prompt_with_no_arguments_and_one_fixed_description(folder):
    (folder / "drain_node.md").write_text(SOUND)
    server = door.build_server(words=words.at_start(bearer=True))
    [prompt] = [p for p in asyncio.run(server.list_prompts()) if p.name == "drain_node"]
    assert prompt.description == "Operator runbook (not Proximo's)." and not prompt.arguments
    assert getattr(prompt, "title", "Drain a node") == "Drain a node"
    got = asyncio.run(server.get_prompt("drain_node", {}))
    assert got.messages[0].content.text == "Operator runbook (not Proximo's): drain_node.\n\n" + SOUND
    assert {t.name for t in asyncio.run(server.list_tools())} == {
        "audit_entries", "audit_verify", "proximo_call", "proximo_find", "proximo_plan", "proximo_read"}


def test_a6_the_receipt_carries_counts_and_codes_never_a_name(folder):
    (folder / "sound.md").write_text(SOUND)
    (folder / "secret_project.md").write_text(_body("nothing"))
    for i in range(33):
        (folder / f"job_{i:02d}.md").write_text(SOUND)
    flags: list[str] = []
    section = words.station(flags, doctor._said)["runbooks"]
    assert receipt.allowed({"runbooks": section})["runbooks"] == {
        "configured": True, "served": 32, "refused": 0, "ignored": 0}
    assert [receipt.flag_code(f) for f in flags] == ["runbooks-over"]
    (folder / "aaa_first.md").write_text(_body("nothing"))
    flags = []
    words.station(flags, doctor._said)
    assert sorted(receipt.flag_code(f) for f in flags) == ["runbook-refused", "runbooks-over"]
    folder.joinpath("aaa_first.md").unlink()
    for path in folder.iterdir():
        path.unlink()
    folder.rmdir()
    flags = []
    unusable = words.station(flags, doctor._said)["runbooks"]
    assert receipt.allowed({"runbooks": unusable})["runbooks"] == {"configured": True, "error": receipt.TEXT}
    assert [receipt.flag_code(f) for f in flags] == ["runbooks-unusable"]


def test_two_runbooks_each_serve_their_own_text(folder):
    (folder / "first.md").write_text(_body("GET /version", title="# First"))
    (folder / "second.md").write_text(_body("GET /nodes", title="# Second"))
    server = door.build_server(words=words.at_start(bearer=True))
    for name, title in (("first", "# First"), ("second", "# Second")):
        text = asyncio.run(server.get_prompt(name, {})).messages[0].content.text
        assert text.startswith(f"Operator runbook (not Proximo's): {name}.\n\n{title}\n")


def test_a_served_runbook_over_the_small_model_size_is_advice_never_a_refusal(folder):
    (folder / "long.md").write_text(_body("GET /version\n" + "Wait for the operator. " * 90))
    (folder / "short.md").write_text(SOUND)
    got = runbooks.load()
    assert [b.name for b in got.served] == ["long", "short"] and got.refused == ()
    flags: list[str] = []
    section = words.station(flags, doctor._said)["runbooks"]
    assert section["served"] == 2 and len(flags) == 1
    size = len(got.served[0].text)
    assert size > runbooks.SOFT
    assert flags[0].startswith(f"an operator runbook is over 1800 characters ({size}): long: ")
    assert flags[0].startswith(doctor._ADVISORY) and receipt.flag_code(flags[0]) == "runbook-long"
    at: list[str] = []
    exact = _body("GET /version")
    exact += "x" * (runbooks.SOFT - len(runbooks.check("long", exact).text))
    (folder / "long.md").write_text(exact)
    assert len(runbooks.load().served[0].text) == runbooks.SOFT
    words.station(at, doctor._said)
    assert at == []
