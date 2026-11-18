"""The one read at a door's start (`core/words.py`): both halves of the operator's words, read
once, each refusal said once on stderr, and nothing read at all for a door with no bearer."""
import pytest

from proximo.core import instructions, words, wordsfile

TEXT = "Every call names a target.\n"


@pytest.fixture
def rules(tmp_path, monkeypatch):
    for name in (instructions.ENV, instructions.OLD, "PROXIMO_RUNBOOKS_DIR"):
        monkeypatch.delenv(name, raising=False)
    folder = tmp_path / "words"
    folder.mkdir()
    path = folder / "rules.md"
    path.write_text(TEXT)
    return path


def test_nothing_set_is_none_and_silent(rules, capsys):
    assert words.at_start(bearer=True) == words.NONE == words.Words(None, (), ())
    assert words.at_start(bearer=False) == words.NONE
    assert capsys.readouterr().err == ""


def test_a_good_file_is_the_text_and_silent(rules, monkeypatch, capsys):
    monkeypatch.setenv(instructions.ENV, str(rules))
    assert words.at_start(bearer=True) == words.Words(TEXT, (), ())
    assert capsys.readouterr().err == ""


def test_a_refused_file_is_said_once_on_stderr_and_never_where(rules, monkeypatch, capsys):
    rules.write_bytes(b"\xff\xfe")
    monkeypatch.setenv(instructions.ENV, str(rules))
    got = words.at_start(bearer=True)
    err = capsys.readouterr().err
    assert got.instructions is None and len(got.said) == 1
    assert err == got.said[0] + "\n"
    assert err.startswith("proximo: PROXIMO_INSTRUCTIONS is not UTF-8 text; no caller receives the instructions")
    assert str(rules) not in err and rules.name not in err


def test_a_door_with_no_bearer_reads_nothing_and_says_why_once(rules, monkeypatch, capsys):
    monkeypatch.setenv(instructions.ENV, str(rules))
    reads: list[str] = []
    monkeypatch.setattr(wordsfile, "read", lambda path, cap: reads.append(path) or TEXT)
    got = words.at_start(bearer=False)
    assert got.instructions is None and got.runbooks == ()
    assert reads == []                                     # not read and withheld: never opened
    assert got.said == ("proximo: this door has no bearer token, so the operator's words are not served on it",)
    assert capsys.readouterr().err == got.said[0] + "\n"


def test_the_runbooks_variable_alone_also_earns_the_no_bearer_line(rules, monkeypatch, capsys):
    monkeypatch.setenv("PROXIMO_RUNBOOKS_DIR", str(rules.parent))
    assert len(words.at_start(bearer=False).said) == 1
    assert "no bearer token" in capsys.readouterr().err


@pytest.mark.parametrize("bearer", [True, False])
def test_the_old_name_is_said_at_start_bearer_or_not(rules, monkeypatch, capsys, bearer):
    monkeypatch.setenv(instructions.OLD, str(rules))
    got = words.at_start(bearer=bearer)
    assert got.instructions is None
    assert got.said == ("proximo: PROXIMO_MCP_INSTRUCTIONS is set and is not read: "
                        "the variable is PROXIMO_INSTRUCTIONS",)
    assert capsys.readouterr().err == got.said[0] + "\n"
