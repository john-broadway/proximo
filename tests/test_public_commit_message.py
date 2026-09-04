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
    assert first == "release: v0.9.0: a headline", (
        "the SUBJECT must carry the one-line reason — it is the only text GitHub shows "
        "beside files and in the commit list (bare subjects shipped 0.36.1-0.39.0)")
    assert blank == "", "git needs a blank line between subject and body"
    assert "A headline." in msg
    assert "CHANGELOG.md" in msg, "the body should point a reader at the full record"


def test_an_entry_with_no_opening_thesis_refuses_instead_of_shipping_bare():
    no_thesis = SAMPLE.replace("**A headline.** Some prose.", "Some prose without a thesis.")
    with pytest.raises(SystemExit) as e:
        build("0.9.0", no_thesis)
    assert "thesis" in str(e.value)


def test_a_whitespace_only_thesis_refuses_instead_of_crashing():
    hollow = SAMPLE.replace("**A headline.**", "** **")
    with pytest.raises(SystemExit) as e:
        build("0.9.0", hollow)
    assert "empty" in str(e.value)


def test_an_immediately_closed_bold_refuses_instead_of_capturing_a_later_span():
    """`****` must fail as "no thesis", not run away and grab an unrelated bold span.

    Mechanics lens, 2026-09-04: the old `\\*\\*(.+?)\\*\\*` needed one character, so a literal
    `****` skipped forward and captured a LATER bold span as the thesis, producing a 2476-char
    runaway. It was caught only because the length ceiling happened to trip, which is the wrong
    check saving the release; a shorter accidental match would have shipped a nonsense subject.
    """
    # The fixture needs a LATER bold span inside the same entry, or the old pattern simply
    # found no closing pair and refused anyway — a test that passes for the wrong reason.
    # Verified: against the old `(.+?)` this input yields the subject
    # "release: v0.9.0: ** Some prose with a", short enough to slip past the length ceiling.
    runaway = """# Changelog

## [0.9.0] — 2026-01-02

****

Some prose with a **later bold span** that is not the thesis at all.
"""
    with pytest.raises(SystemExit) as e:
        build("0.9.0", runaway)
    assert "thesis" in str(e.value)


def test_a_thesis_may_carry_nested_emphasis():
    """The stricter opening-bold pattern must not reject a legitimate *emphasis* inside."""
    nested = SAMPLE.replace("**A headline.**", "**A headline with *emphasis* in it.**")
    assert "a headline with *emphasis* in it" in build("0.9.0", nested).splitlines()[0]


def test_an_overlong_thesis_refuses_instead_of_shipping_an_unreadable_subject():
    longwinded = SAMPLE.replace(
        "**A headline.**",
        "**A thesis that rambles on far past any reasonable subject-line ceiling for a git "
        "commit message and keeps going.**")
    with pytest.raises(SystemExit) as e:
        build("0.9.0", longwinded)
    assert "72" in str(e.value)


def test_a_multiline_thesis_collapses_to_one_subject_line():
    wrapped = SAMPLE.replace("**A headline.**", "**A headline\nacross lines.**")
    msg = build("0.9.0", wrapped)
    assert msg.splitlines()[0] == "release: v0.9.0: a headline across lines"


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
    assert msg.startswith(f"release: v{version}: ")
    assert msg.splitlines()[0] != f"release: v{version}", "a bare subject is the old defect"
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
