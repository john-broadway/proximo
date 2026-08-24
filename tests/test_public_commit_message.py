"""The public release commit must carry its reason.

Six releases shipped to public `main` with the bare body "release: vX.Y.Z", so the commit
list a visitor reads showed no reason for any push while the reasoning sat on the internal
mirror. These pin the helper that ends that: the CHANGELOG entry becomes the commit body,
and a missing entry refuses LOUDLY rather than producing an empty message.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from public_commit_message import build, entry_for  # noqa: E402

SAMPLE = """# Changelog

## [0.9.0] — 2026-01-02

**A headline.** Some prose.

- A bullet that explains the change.

## [0.8.0] — 2026-01-01

- The older one, which must NOT leak into 0.9.0's message.
"""


def test_entry_is_the_version_section_only():
    got = entry_for("0.9.0", SAMPLE)
    assert "A bullet that explains the change." in got
    assert "must NOT leak" not in got, "the next release's entry bled into this one"
    assert not got.startswith("## ["), "the heading belongs to the commit subject, not the body"


def test_message_leads_with_the_release_subject_then_the_reason():
    msg = build("0.9.0", SAMPLE)
    first, blank, *rest = msg.splitlines()
    assert first == "release: v0.9.0"
    assert blank == "", "git needs a blank line between subject and body"
    assert "A headline." in msg
    assert "CHANGELOG.md" in msg, "the body should point a reader at the full record"


def test_missing_entry_refuses_instead_of_producing_an_empty_body():
    # The whole failure mode: an empty message is what shipped six times. Refusing is the fix.
    with pytest.raises(SystemExit) as e:
        build("1.2.3", SAMPLE)
    assert "1.2.3" in str(e.value)


def test_the_live_changelog_head_version_builds_a_real_message():
    """Runs against the REAL CHANGELOG, so the helper cannot pass on a fixture alone."""
    root = Path(__file__).resolve().parent.parent
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    version = text.split("## [", 1)[1].split("]", 1)[0]
    msg = build(version, text)
    assert msg.startswith(f"release: v{version}\n\n")
    assert len(msg) > 200, "a real release message should not be a stub"


def test_cli_exits_nonzero_and_prints_nothing_on_a_missing_version():
    """A caller pipes stdout into git commit-tree; on refusal it must get an empty stdout AND
    a non-zero exit, never a half-message."""
    root = Path(__file__).resolve().parent.parent
    r = subprocess.run(  # noqa: S603 — fixed argv, same idiom as test_requirements_lock
        [sys.executable, str(root / "scripts" / "public_commit_message.py"), "99.99.99"],
        capture_output=True, text=True)
    assert r.returncode != 0
    assert r.stdout == ""
