"""The banner: one copy of the art, on every surface that normally carries one.

John, 2026-09-26: block letters (his pick, draft A), no door image, and under them the line he
still loves in his own rendering: "Win the crowd, Win your freedom", centred inside the letters.
The art lives once, in `proximo.core.doors`; the install script's heredoc is a second copy by
necessity (bash), so a test holds the two together.
"""
from __future__ import annotations

import pathlib
import re

from proximo.core import doors
from proximo.core.doors import cli, mcp

SLOGAN = "Win the crowd, Win your freedom"


def test_the_banner_is_ascii_and_his_line_sits_centred_inside_the_letters():
    lines = doors.BANNER.rstrip("\n").split("\n")
    assert all(ord(c) < 128 for c in doors.BANNER)
    assert lines[-1].strip() == SLOGAN
    widest = max(len(line) for line in lines[:-1])
    lead = len(lines[-1]) - len(lines[-1].lstrip())
    assert lead == (widest - len(SLOGAN)) // 2 and len(lines[-1]) <= widest, (lead, widest)


def test_the_shell_doors_help_ends_with_the_banner(capsys):
    assert cli.main(["--help"]) == 0   # the door maps argparse's exit to its own codes
    out = capsys.readouterr().out
    assert doors.BANNER.rstrip("\n") in out


def test_the_mcp_door_prints_the_banner_on_stderr_at_start(monkeypatch, capsys):
    class _Server:
        def run(self):
            pass
    monkeypatch.setattr(mcp, "build_server", lambda: _Server())
    assert mcp.main([]) == 0   # an explicit argv: `main()` reads sys.argv, which is pytest's here
    assert doors.BANNER.rstrip("\n") in capsys.readouterr().err


def test_the_install_script_carries_the_same_banner():
    sh = pathlib.Path(__file__).resolve().parents[1] / "packaging" / "lxc" / "ct" / "proximo.sh"
    m = re.search(r"<<'PROXIMO_BANNER'\n(.*?)\nPROXIMO_BANNER\n", sh.read_text(), re.S)
    assert m, "the install script's banner heredoc"
    assert m.group(1) == doors.BANNER.rstrip("\n")
