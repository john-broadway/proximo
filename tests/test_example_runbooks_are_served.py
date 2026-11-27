"""The example runbooks in `packaging/runbooks/` are held to the loader that serves a runbook.

They are what an operator copies into `PROXIMO_RUNBOOKS_DIR`. An address the vendor renames, a rule
the loader gains, or a file added under a name the loader ignores would otherwise ship as an example
that Proximo itself refuses (contributed by kevwillow, #141; the check promised on that PR).
"""
from __future__ import annotations

import pathlib
import re
import shutil

from proximo.core import runbooks

_REPO = pathlib.Path(__file__).resolve().parent.parent
_EXAMPLES = _REPO / "packaging" / "runbooks"


def _on_disk() -> list[str]:
    return sorted(p.name for p in _EXAMPLES.iterdir())


def test_every_example_runbook_is_served_and_nothing_in_the_folder_is_left_out(monkeypatch):
    monkeypatch.setenv(runbooks.ENV, str(_EXAMPLES))
    folder = runbooks.load()
    assert folder is not None
    assert [(r.name, r.reason) for r in folder.refused] == []
    assert (folder.ignored, folder.unread) == (0, 0)
    served = sorted(f"{r.name}.md" for r in folder.served)
    assert served == _on_disk() and served          # every file on disk, and the folder is not empty


def test_the_check_is_not_vacuous_a_broken_copy_is_refused_and_a_misnamed_one_ignored(monkeypatch, tmp_path):
    shutil.copytree(_EXAMPLES, tmp_path / "rb")
    first = _on_disk()[0]
    broken = tmp_path / "rb" / first
    broken.write_text(broken.read_text() + "\n1. GET /nodes/{n}/status\n")       # a template pve does not publish
    (tmp_path / "rb" / "restore-test.md").write_text((_EXAMPLES / first).read_text())   # a hyphen: not a runbook name
    monkeypatch.setenv(runbooks.ENV, str(tmp_path / "rb"))
    folder = runbooks.load()
    assert folder is not None
    assert [r.name for r in folder.refused] == [first.removesuffix(".md")]
    assert folder.ignored == 1
    assert len(folder.served) == len(_on_disk()) - 1


def test_setup_names_every_example_runbook_and_no_other():
    setup = (_REPO / "docs" / "SETUP.md").read_text()
    line = next(ln for ln in setup.splitlines() if "packaging/runbooks/" in ln)
    assert sorted(set(re.findall(r"`([a-z_]+\.md)`", line))) == _on_disk()
