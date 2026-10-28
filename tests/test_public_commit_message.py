"""The public release commit must carry its reason.

Six releases shipped to public `main` with the bare body "release: vX.Y.Z", so the commit
list a visitor reads showed no reason for any push while the reasoning sat on the internal
mirror. These pin the helper that ends that: the CHANGELOG entry becomes the commit body,
and a missing entry refuses LOUDLY rather than producing an empty message.
"""
from __future__ import annotations

import os
import re
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


# --- Co-authored-by trailers: every outside author in the release range is named ----------
#
# 0.49.1 shipped RavenLiao's #107 as a port inside the one curated commit, authored by the
# owner, so 580/580 of his lines went public under the owner's name and the contributors graph
# never saw him (John, 2026-10-27: "this is shady as fuck"). The graph reads commit author and
# Co-authored-by on main; the curated commit is the only commit, so it must carry every author
# and co-author of the internal range as trailers. The owner is the commit's author already.

from public_commit_message import coauthor_trailers, minting_ident, previous_version, range_idents  # noqa: E402

OWNER = "John Broadway <271895126+john-broadway@users.noreply.github.com>"


def test_outside_authors_become_trailers_and_the_owner_does_not():
    idents = [OWNER, "RavenLiao <ravenliao@163.com>", OWNER,
              "dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>"]
    got = coauthor_trailers(idents, owner=OWNER)
    assert got == [
        "Co-authored-by: RavenLiao <ravenliao@163.com>",
        "Co-authored-by: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
    ]


def test_the_same_person_as_author_and_co_author_is_named_once():
    idents = ["Claude Opus 5.5 <noreply@anthropic.com>", "claude opus 5.5 <NOREPLY@anthropic.com>",
              "RavenLiao <ravenliao@163.com>"]
    got = coauthor_trailers(idents, owner=OWNER)
    assert len(got) == 2
    assert got[0].startswith("Co-authored-by: Claude Opus 5.5 <")
    assert got[1] == "Co-authored-by: RavenLiao <ravenliao@163.com>"


def test_the_owner_is_matched_by_email_not_display_name():
    idents = ["john broadway <271895126+john-broadway@users.noreply.github.com>",
              "John Broadway <someone-else@example.com>"]
    got = coauthor_trailers(idents, owner=OWNER)
    assert got == ["Co-authored-by: John Broadway <someone-else@example.com>"]


def test_a_malformed_ident_refuses_instead_of_minting_a_broken_trailer():
    with pytest.raises(SystemExit):
        coauthor_trailers(["not an ident"], owner=OWNER)
    with pytest.raises(SystemExit):
        coauthor_trailers(["Name <no-at-sign>"], owner=OWNER)
    with pytest.raises(SystemExit):
        coauthor_trailers(["Name <a@b>\nCo-authored-by: smuggled <x@y>"], owner=OWNER)


def test_trailers_close_the_message_after_a_blank_line():
    msg = build("0.9.0", SAMPLE, coauthors=["Co-authored-by: RavenLiao <ravenliao@163.com>"])
    lines = msg.rstrip("\n").splitlines()
    assert lines[-1] == "Co-authored-by: RavenLiao <ravenliao@163.com>"
    assert lines[-2] == "", "git reads trailers only as the last paragraph"
    assert msg.endswith("\n")


def test_no_outside_authors_means_no_trailer_block():
    msg = build("0.9.0", SAMPLE, coauthors=[])
    assert "Co-authored-by" not in msg
    assert msg == build("0.9.0", SAMPLE)


def _git(cwd: Path, *args: str, env: dict[str, str] | None = None) -> str:
    r = subprocess.run(["git", *args], capture_output=True, text=True, cwd=cwd,  # noqa: S603, S607
                       env=env, check=True)
    return r.stdout


def test_the_release_range_names_every_author_and_co_author_but_the_minter(tmp_path):
    """End to end on a throwaway repo, so it holds on every runner: a tagged previous release,
    then commits by the owner (with a Co-Authored-By trailer), an outside author and a bot. The
    trailers name the outside author, the bot and the co-author once each, never the owner."""
    repo = tmp_path / "repo"
    repo.mkdir()
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
           "GIT_AUTHOR_NAME": "Owner", "GIT_AUTHOR_EMAIL": "owner@example.com",
           "GIT_COMMITTER_NAME": "Owner", "GIT_COMMITTER_EMAIL": "owner@example.com"}
    _git(repo, "init", "-q", env=env)

    def commit(msg: str, name: str = "Owner", email: str = "owner@example.com") -> None:
        (repo / "f").write_text(msg, encoding="utf-8")
        _git(repo, "add", "f", env=env)
        _git(repo, "commit", "-q", "-m", msg,
             env={**env, "GIT_AUTHOR_NAME": name, "GIT_AUTHOR_EMAIL": email})

    commit("previous release")
    _git(repo, "tag", "v0.8.0", env=env)
    commit("owner's own work\n\nCo-Authored-By: Claude Example <noreply@example.com>")
    commit("Route calls by node", "Outside Person", "outside@example.com")
    commit("bump an action", "dependabot[bot]", "1+dependabot[bot]@users.noreply.github.com")
    commit("more of the same\n\nCo-Authored-By: Claude Example <noreply@example.com>")

    old = os.environ.copy()
    os.environ.update(env)
    try:
        owner = minting_ident(repo)
        idents = range_idents(repo, "0.8.0")
    finally:
        os.environ.clear()
        os.environ.update(old)
    assert owner == "Owner <owner@example.com>"
    trailers = coauthor_trailers(idents, owner=owner)
    assert trailers == [
        "Co-authored-by: Claude Example <noreply@example.com>",
        "Co-authored-by: Outside Person <outside@example.com>",
        "Co-authored-by: dependabot[bot] <1+dependabot[bot]@users.noreply.github.com>",
    ]
    msg = build("0.9.0", SAMPLE, trailers)
    assert msg.rstrip("\n").splitlines()[-3:] == trailers
    # the first release has no previous tag and no range; a missing tag for a named one refuses
    assert range_idents(repo, None) == []
    with pytest.raises(SystemExit, match="no local tag v0.7.0"):
        range_idents(repo, "0.7.0")


def _previous_tag_present() -> bool:
    root = Path(__file__).resolve().parent.parent
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    heads = [v for v in re.findall(r"^## \[([^\]]+)\]", text, re.M) if v.lower() != "unreleased"]
    if len(heads) < 2:
        return False
    r = subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/v{heads[1]}^{{commit}}"],  # noqa: S603, S607
                       capture_output=True, text=True, cwd=root)
    return r.returncode == 0


@pytest.mark.skipif(not _previous_tag_present(),
                    reason="shallow checkout without the previous release tag (GitHub's test job); "
                           "the tmp-repo test above proves the mechanism there")
def test_cli_on_the_real_repo_ends_with_well_formed_trailers_naming_no_minter():
    """On a full clone (gitea CI, the release box): the head CHANGELOG version's range is
    v<previous>..HEAD, and every trailer is `Name <email>`, none the minting identity."""
    root = Path(__file__).resolve().parent.parent
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    version = next(v for v in re.findall(r"^## \[([^\]]+)\]", text, re.M) if v.lower() != "unreleased")
    r = subprocess.run(  # noqa: S603
        [sys.executable, str(root / "scripts" / "public_commit_message.py"), version],
        capture_output=True, text=True, cwd=root)
    assert r.returncode == 0, r.stderr
    trailers = [ln for ln in r.stdout.splitlines() if ln.startswith("Co-authored-by: ")]
    assert trailers, "a release range with no outside author at all would be the first ever"
    minter = _git(root, "var", "GIT_AUTHOR_IDENT").rsplit(" ", 2)[0]
    for t in trailers:
        assert re.fullmatch(r"Co-authored-by: [^<>\n]+ <[^<>@\s]+@[^<>@\s]+>", t), t
        assert t != f"Co-authored-by: {minter}"
    assert r.stdout.rstrip("\n").splitlines()[-1] == trailers[-1]


def test_two_names_on_one_address_stay_two_lines():
    """The Claude models share one address; which one wrote is part of the record."""
    idents = ["Claude Opus 5.5 <noreply@anthropic.com>", "Claude Fable 5.1 <noreply@anthropic.com>"]
    got = coauthor_trailers(idents, owner=OWNER)
    assert got == ["Co-authored-by: Claude Opus 5.5 <noreply@anthropic.com>",
                   "Co-authored-by: Claude Fable 5.1 <noreply@anthropic.com>"]


def test_unreleased_is_refused_by_name():
    with pytest.raises(SystemExit, match="not a release"):
        previous_version("Unreleased", "## [Unreleased]\n\n## [0.9.0]\n")


def test_previous_version_skips_unreleased_and_ends_at_the_first_entry():
    text = "## [Unreleased]\n\n## [0.9.0]\n\n## [0.8.0]\n"
    assert previous_version("0.9.0", text) == "0.8.0"
    assert previous_version("0.8.0", text) is None
