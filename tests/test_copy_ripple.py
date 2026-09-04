"""The always-on copy-drift gate — the story is told once, zones fill slots, nothing accretes.

Companion to test_version_consistency.py: that gate pins version STRINGS; this one pins
copy SHAPE. Canon: docs/plans/internal/COPY-CANON.md (internal-only).
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import copy_ripple_check  # noqa: E402
import version_tools  # noqa: E402

CURRENT = version_tools.read_pyproject_version(REPO_ROOT)


def test_live_repo_copy_is_clean():
    problems = copy_ripple_check.check_repo(REPO_ROOT)
    assert problems == [], "copy drift:\n" + "\n".join(problems)


# --- unit behavior, on synthetic content ---------------------------------


def test_new_in_block_must_match_current_version():
    problems = copy_ripple_check.check_new_in("> **New in 0.1.0 — old.**", "0.2.0")
    assert any("New in" in p for p in problems)
    assert copy_ripple_check.check_new_in("> **New in 0.2.0 — theme.**", "0.2.0") == []


def test_new_in_block_must_not_stack_releases():
    stacked = "> **New in 0.3.0 — a.**\n> **New in 0.2.0 — b.**"
    problems = copy_ripple_check.check_new_in(stacked, "0.3.0")
    assert any("exactly one" in p for p in problems)


_BADGE = (
    "> 📦 **`{v}`**: on [PyPI](https://pypi.org/project/proximo-proxmox/), "
    "[GitHub](https://github.com/john-broadway/proximo/releases/tag/v{t}), and "
    "[GHCR](https://github.com/john-broadway/proximo/pkgs/container/proximo) (signed image)."
)


def test_install_badge_must_name_the_current_version():
    # 2026-09-04: a mechanics lens set this badge to 0.31.0 on the 0.39.1 tree and the whole
    # gate still answered "copy: consistent", exit 0. It is the first line under "Install &
    # run" — the one place a visitor looks to answer "what version is this".
    stale = _BADGE.format(v="0.31.0", t="0.31.0")
    problems = copy_ripple_check.check_install_badge(stale, "0.39.1")
    assert any("0.31.0" in p for p in problems), problems

    ok = _BADGE.format(v="0.39.1", t="0.39.1")
    assert copy_ripple_check.check_install_badge(ok, "0.39.1") == []


def test_install_badge_checks_the_release_tag_url_too():
    """The badge carries the version twice; a half-done ripple moves only the backticks."""
    half = _BADGE.format(v="0.39.1", t="0.39.0")
    problems = copy_ripple_check.check_install_badge(half, "0.39.1")
    assert any("0.39.0" in p for p in problems), problems


def test_a_missing_install_badge_is_itself_a_finding():
    """Deleting the line must not be the way to silence the rule."""
    problems = copy_ripple_check.check_install_badge("no badge here", "0.39.1")
    assert any("no" in p and "badge" in p for p in problems), problems


def test_status_carries_only_the_current_release():
    # 2026-07-16 law: exactly ONE 🩸 bullet — history lives in CHANGELOG.md.
    stacked = "- 🩸 **0.9.0** — thing\n- 🩸 **0.8.0** — thing"
    problems = copy_ripple_check.check_status(stacked, "0.9.0")
    assert any("CHANGELOG" in p for p in problems), problems

    ok = "- 🩸 **0.9.0** — thing"
    assert copy_ripple_check.check_status(ok, "0.9.0") == []

    stale_top = "- 🩸 **0.8.0** — thing"
    problems = copy_ripple_check.check_status(stale_top, "0.9.0")
    assert any("top" in p.lower() for p in problems)


def test_readme_line_fence():
    fence = copy_ripple_check.MAX_README_LINES
    assert fence == 300  # raise only deliberately, with COPY-CANON updated to match


def test_tool_count_claims_must_agree():
    text = "It has 364 tools. Later: 360 MCP tools."
    problems = copy_ripple_check.check_tool_counts({"README.md": text}, canonical=364)
    assert any("360" in p for p in problems)


def test_tool_count_ignores_scoped_registration_examples():
    text = (
        "364 tools is the whole estate.\n"
        "`PROXIMO_SURFACES=pve,exec` registers only those planes (that pair = 194 tools).\n"
    )
    assert copy_ripple_check.check_tool_counts({"README.md": text}, canonical=364) == []


def test_tool_count_arrow_line_is_not_a_blanket_exemption():
    # Regression (redteam 2026-07-09): the gate exempted ANY line containing "→",
    # so a stale total could hide behind an arrow. Arrows are not an exemption.
    text = "The estate grew → 300 tools in this wave."
    problems = copy_ripple_check.check_tool_counts({"README.md": text}, canonical=364)
    assert any("300" in p for p in problems), problems


def test_tool_count_delta_form_is_not_a_total_claim():
    # "+12 tools" is a per-release increment, not a total — never checked as one.
    text = "> (+12 tools → **364**, incl. cross-remote migrate)"
    assert copy_ripple_check.check_tool_counts({"README.md": text}, canonical=364) == []


def test_tool_count_historical_status_bullets_are_pinned_history():
    # A non-current 🩸 bullet is a point-in-time fact; its old total is not drift.
    hist = "- 🩸 **0.17.0** — fleet control (+12 → 300 tools): power\n"
    assert (
        copy_ripple_check.check_tool_counts(
            {"README.md": hist}, canonical=364, current="0.18.0"
        )
        == []
    )
    # But the CURRENT bullet's total is a live claim and must agree.
    cur = "- 🩸 **0.18.0** — this wave (grew to 300 tools)\n"
    problems = copy_ripple_check.check_tool_counts(
        {"README.md": cur}, canonical=364, current="0.18.0"
    )
    assert any("300" in p for p in problems), problems


def test_version_literals_in_receipt_docs_must_be_current():
    # Regression (2026-07-13 truth audit): VERIFY.md's worked examples and SECURITY.md's
    # support table sat two releases stale — nothing gated version literals in the
    # receipt docs. Any semver literal there is a live claim and must be current.
    stale = "curl https://pypi.org/integrity/x/0.20.0/x-0.20.0.whl and v0.20.0 examples"
    problems = copy_ripple_check.check_version_literals({"VERIFY.md": stale}, "0.21.0")
    assert any("0.20.0" in p for p in problems), problems

    fresh = "curl https://pypi.org/integrity/x/0.21.0/x-0.21.0.whl — v0.21.0"
    assert copy_ripple_check.check_version_literals({"VERIFY.md": fresh}, "0.21.0") == []


def test_version_literals_ignore_two_part_versions():
    # "PVE 9.2" / "TLS 1.3" / "Python 3.13" are platform versions, not release claims.
    text = "Works with PVE 9.2, TLS 1.3, Python 3.13."
    assert copy_ripple_check.check_version_literals({"SECURITY.md": text}, "0.21.0") == []


def test_version_literals_ignore_ip_addresses():
    # A dotted-quad is an address, not a release claim (127.0.0.1 ≠ version "127.0.0").
    text = "binds 127.0.0.1:41242 by default; 0.0.0.0 is public."
    assert copy_ripple_check.check_version_literals({"THREAT_MODEL.md": text}, "0.21.0") == []


def test_tagline_must_survive_on_metadata_surfaces():
    files = {"pyproject.toml": 'description = "A cool Proxmox helper."'}
    problems = copy_ripple_check.check_tagline(files)
    assert any("hand the keys" in p for p in problems)
    files = {"pyproject.toml": 'description = "The Proxmox MCP you can hand the keys."'}
    assert copy_ripple_check.check_tagline(files) == []


def test_satellite_must_carry_current_version():
    problems = copy_ripple_check.check_satellite_text("v0.1.0 is live", "0.2.0", "index.html")
    assert problems and "0.2.0" in problems[0]
    assert copy_ripple_check.check_satellite_text("v0.2.0 is live", "0.2.0", "x") == []
