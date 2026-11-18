"""The one reader for the operator's words refuses on doubt (`core/wordsfile.py`).

The lens on PR #124 pointed the instructions variable at a 0600 token file, at a symlink to it and
at `/proc/self/environ`: each was served verbatim to every client, and doctor called the token
file healthy. It pointed it at a named pipe and the door hung with no message. Those probes are
the first tests here, red before the reader existed.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

from proximo.core import wordsfile
from proximo.core.wordsfile import Refused

TOKEN = "root@pam!agent=6f1c0b9e-0000-4000-8000-000000000000\n"  # noqa: S105 -- a made-up token's shape
CAP = 64


def _refusal(path, cap=CAP) -> Refused:
    with pytest.raises(Refused) as caught:
        wordsfile.read(str(path), cap)
    return caught.value


@pytest.fixture
def token(tmp_path, monkeypatch):
    """A credential this process is configured to hold, named by one of its own variables."""
    path = tmp_path / "secrets" / "pve.token"
    path.parent.mkdir()
    path.write_text(TOKEN)
    path.chmod(0o600)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", str(path))
    return path


def test_a_plain_text_file_is_its_text(tmp_path):
    words = tmp_path / "rules.md"
    words.write_text("Every call names a target.\n")
    assert wordsfile.read(str(words), CAP) == "Every call names a target.\n"


def test_the_token_file_itself_is_never_served(token):
    refused = _refusal(token)
    assert (refused.kind, refused.collides) == (wordsfile.SECRET, "PROXIMO_TOKEN_PATH")


def test_a_symlink_to_the_token_file_is_the_same_file(token, tmp_path):
    link = tmp_path / "rules.md"
    link.symlink_to(token)
    refused = _refusal(link)
    assert (refused.kind, refused.collides) == (wordsfile.SECRET, "PROXIMO_TOKEN_PATH")


def test_a_hard_link_to_the_token_file_is_the_same_file(token, tmp_path):
    link = tmp_path / "rules.md"
    os.link(token, link)
    refused = _refusal(link)
    assert (refused.kind, refused.collides) == (wordsfile.SECRET, "PROXIMO_TOKEN_PATH")


def test_the_ledger_and_its_key_are_never_served(tmp_path, monkeypatch):
    log = tmp_path / "state" / "audit.log"
    log.parent.mkdir()
    log.write_text("{}\n")
    (log.parent / "audit.key").write_text("k" * 32)
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(log))
    monkeypatch.delenv("PROXIMO_AUDIT_KEY_PATH", raising=False)
    assert _refusal(log).collides == "PROXIMO_AUDIT_LOG"
    assert _refusal(log.parent / "audit.key").collides == "PROXIMO_AUDIT_KEY_PATH"


def test_the_words_own_variables_are_not_secrets(tmp_path, monkeypatch):
    """The instructions file may sit inside the runbooks folder, and each names itself."""
    folder = tmp_path / "words"
    folder.mkdir()
    words = folder / "rules.md"
    words.write_text("Site rules.\n")
    monkeypatch.setenv("PROXIMO_RUNBOOKS_DIR", str(folder))
    monkeypatch.setenv("PROXIMO_INSTRUCTIONS", str(words))
    assert wordsfile.read(str(words), CAP) == "Site rules.\n"


def test_a_folder_a_device_and_a_missing_file_are_refused_by_kind(tmp_path):
    assert _refusal(tmp_path).kind == wordsfile.NOT_REGULAR
    assert _refusal("/dev/null").kind == wordsfile.NOT_REGULAR
    assert _refusal(tmp_path / "absent.md").kind == wordsfile.UNREADABLE


def test_the_read_is_bounded_by_the_cap(tmp_path):
    exact, over = tmp_path / "exact.md", tmp_path / "over.md"
    exact.write_bytes(b"a" * CAP)
    over.write_bytes(b"a" * (CAP + 1))
    assert wordsfile.read(str(exact), CAP) == "a" * CAP
    assert _refusal(over).kind == wordsfile.OVER


def test_a_huge_file_costs_one_bounded_read(tmp_path, monkeypatch):
    huge = tmp_path / "huge.md"
    huge.write_bytes(b"a" * 1_000_000)
    asked: list[int] = []
    real = os.read

    def counting(fd, n):
        asked.append(n)
        return real(fd, n)
    monkeypatch.setattr(wordsfile.os, "read", counting)
    assert _refusal(huge).kind == wordsfile.OVER
    assert sum(asked) <= CAP + 1 and max(asked) <= CAP + 1


def test_a_byte_order_mark_is_dropped_and_a_mark_alone_is_empty(tmp_path):
    marked, alone = tmp_path / "marked.md", tmp_path / "alone.md"
    marked.write_bytes(b"\xef\xbb\xbfSite rules.\n")
    alone.write_bytes(b"\xef\xbb\xbf")
    assert wordsfile.read(str(marked), CAP) == "Site rules.\n"
    assert _refusal(alone).kind == wordsfile.EMPTY


def test_bytes_that_are_not_utf8_and_a_file_of_whitespace_are_refused_by_kind(tmp_path):
    latin, blank = tmp_path / "latin.md", tmp_path / "blank.md"
    latin.write_bytes(b"caf\xe9\n")
    blank.write_bytes(b" \n\t\n")
    assert _refusal(latin).kind == wordsfile.NOT_UTF8
    assert _refusal(blank).kind == wordsfile.EMPTY


def test_a_home_relative_path_is_expanded(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "rules.md").write_text("Site rules.\n")
    assert wordsfile.read("~/rules.md", CAP) == "Site rules.\n"


def test_a_refusal_carries_no_path_and_no_byte_of_the_file(token, tmp_path):
    link = tmp_path / "rules.md"
    link.symlink_to(token)
    refused = _refusal(link)
    said = f"{refused!s} {refused!r} {refused.args} {refused.collides}"
    assert str(tmp_path) not in said and "6f1c0b9e" not in said and "rules.md" not in said


def test_a_named_pipe_never_blocks_the_read(tmp_path):
    """In a child with a clock: a reader that opens the pipe blocking would hang this suite."""
    pipe = tmp_path / "pipe.md"
    os.mkfifo(pipe)
    code = ("import sys; from proximo.core import wordsfile\n"
            "try:\n    wordsfile.read(sys.argv[1], 64)\n"
            "except wordsfile.Refused as e:\n    print(e.kind)\n")
    done = subprocess.run([sys.executable, "-c", code, str(pipe)], capture_output=True, text=True,  # noqa: S603
                          timeout=20, check=False, env={**os.environ})
    assert done.stdout.strip() == wordsfile.NOT_REGULAR, done.stderr[-400:]


def test_the_ledger_at_its_default_path_is_never_served(tmp_path, monkeypatch):
    """No variable names it: the ledger and its key are where the core puts them by default."""
    from proximo.core import ledger
    log = tmp_path / "state" / "audit.log"
    log.parent.mkdir()
    log.write_text("{}\n")
    (log.parent / "audit.key").write_text("k" * 32)
    monkeypatch.delenv("PROXIMO_AUDIT_LOG", raising=False)
    monkeypatch.delenv("PROXIMO_AUDIT_KEY_PATH", raising=False)
    monkeypatch.setattr(ledger, "DEFAULT_AUDIT_LOG", str(log))
    assert _refusal(log).collides == "PROXIMO_AUDIT_LOG"
    assert _refusal(log.parent / "audit.key").collides == "PROXIMO_AUDIT_KEY_PATH"


def test_a_file_inside_a_folder_a_variable_names_is_never_served(tmp_path, monkeypatch):
    keys = tmp_path / "caller-keys"
    (keys / "deep").mkdir(parents=True)
    (keys / "deep" / "alice.pem").write_text("-----BEGIN PUBLIC KEY-----\n")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(keys))
    assert _refusal(keys / "deep" / "alice.pem").collides == "PROXIMO_CALLER_KEYS_DIR"
    reached = tmp_path / "rules.md"
    reached.symlink_to(keys / "deep" / "alice.pem")          # a second road to the same place
    assert _refusal(reached).collides == "PROXIMO_CALLER_KEYS_DIR"


def test_a_file_with_a_second_name_is_never_served(tmp_path, monkeypatch):
    """A hard link is how a file in a guarded folder is reached from outside it, and no walk of the
    folder is needed to refuse it: a words file has one name."""
    keys = tmp_path / "caller-keys"
    keys.mkdir()
    (keys / "alice.pem").write_text("-----BEGIN PUBLIC KEY-----\n")
    monkeypatch.setenv("PROXIMO_CALLER_KEYS_DIR", str(keys))
    outside = tmp_path / "rules.md"
    os.link(keys / "alice.pem", outside)
    assert _refusal(outside).kind == wordsfile.LINKED
    plain, twin = tmp_path / "plain.md", tmp_path / "twin.md"
    plain.write_text("Site rules.\n")
    os.link(plain, twin)                                     # no secret anywhere: still two names
    assert _refusal(plain).kind == wordsfile.LINKED


def test_a_credential_named_by_a_relative_path_is_the_file_the_core_would_read(tmp_path, monkeypatch):
    """The core opens `PROXIMO_TOKEN_PATH=pve.token` against the working folder; so does the guard."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "pve.token").write_text(TOKEN)
    monkeypatch.setenv("PROXIMO_TOKEN_PATH", "pve.token")
    assert _refusal(tmp_path / "pve.token").collides == "PROXIMO_TOKEN_PATH"


def test_a_variable_that_names_no_file_and_the_root_guard_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv("PROXIMO_HTTP_PORT", "8080")
    monkeypatch.setenv("PROXIMO_PVE_BASE_URL", "https://pve.example.invalid:8006")
    monkeypatch.setenv("PROXIMO_STORE_DIR", "/")             # the root is no one's folder
    words = tmp_path / "rules.md"
    words.write_text("Site rules.\n")
    assert wordsfile.read(str(words), CAP) == "Site rules.\n"


@pytest.mark.skipif(not os.path.exists("/proc/self/environ"), reason="no procfs on this platform")
def test_the_process_environment_is_never_served(tmp_path):
    """`fstat` calls it a regular file; it holds every secret in the environment (the #124 lens)."""
    assert _refusal("/proc/self/environ", 1 << 20).kind == wordsfile.NOT_REGULAR
    link = tmp_path / "rules.md"
    link.symlink_to("/proc/self/environ")
    assert _refusal(link, 1 << 20).kind == wordsfile.NOT_REGULAR


def test_a_registry_that_is_set_and_unreadable_proves_nothing_so_nothing_is_served(tmp_path, monkeypatch):
    from proximo.core import registry
    monkeypatch.setenv(registry.ENV, str(tmp_path / "absent-targets.toml"))
    words = tmp_path / "rules.md"
    words.write_text("Site rules.\n")
    refused = _refusal(words)
    assert (refused.kind, refused.collides) == (wordsfile.UNPROVEN, registry.ENV)


def test_what_the_core_keeps_beside_the_ledger_is_never_served(tmp_path, monkeypatch):
    """Named by no variable: the memory file and its sidecars, the store folder, a sealed archive."""
    state = tmp_path / "state"
    (state / "store").mkdir(parents=True)
    log = state / "audit.log"
    for name in ("audit.log", "audit.log.unkeyed-20261116-abcdef01", "memory.db", "memory.db-wal"):
        (state / name).write_text("x\n")
    (state / "store" / "answer.json").write_text("{}\n")
    monkeypatch.setenv("PROXIMO_AUDIT_LOG", str(log))
    for var in ("PROXIMO_MEMORY_PATH", "PROXIMO_STORE_DIR"):
        monkeypatch.delenv(var, raising=False)
    assert _refusal(state / "audit.log.unkeyed-20261116-abcdef01").collides == "PROXIMO_AUDIT_LOG"
    assert _refusal(state / "memory.db").collides == "PROXIMO_MEMORY_PATH"
    assert _refusal(state / "memory.db-wal").collides == "PROXIMO_MEMORY_PATH"
    assert _refusal(state / "store" / "answer.json").collides == "PROXIMO_STORE_DIR"
    beside = state / "rules.md"                              # beside the ledger and none of the above: served
    beside.write_text("Site rules.\n")
    assert wordsfile.read(str(beside), CAP) == "Site rules.\n"


def test_a_platform_that_cannot_say_where_the_open_file_is_serves_nothing(tmp_path, monkeypatch):
    """The folder guard is decided on where the DESCRIPTOR is. Looking the name up a second time
    would decide it on a name that can be swapped after the open, so there is no such fallback."""
    words = tmp_path / "rules.md"
    words.write_text("Site rules.\n")
    real_isdir = os.path.isdir
    monkeypatch.setattr(wordsfile.os.path, "isdir", lambda p: False if p == "/proc/self/fd" else real_isdir(p))
    monkeypatch.delattr(wordsfile.fcntl, "F_GETPATH", raising=False)
    refused = _refusal(words)
    assert (refused.kind, refused.collides) == (wordsfile.UNPROVEN, "this platform")



@pytest.mark.parametrize("root", ["/proc", "/sys", "/dev"])
def test_each_kernel_filesystem_is_refused_by_where_the_opened_file_really_is(tmp_path, monkeypatch, root):
    """One case per root, so dropping any of the three goes red (the lens's mutation of `/dev` did not)."""
    path = tmp_path / "words.md"
    path.write_text("text")
    assert wordsfile.read(str(path), 100) == "text"                     # the control: served where it is
    monkeypatch.setattr(wordsfile, "_where", lambda fd: f"{root}/self/words.md")
    with pytest.raises(wordsfile.Refused) as e:
        wordsfile.read(str(path), 100)
    assert e.value.kind == wordsfile.NOT_REGULAR
