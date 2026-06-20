"""The always-on version-drift gate: pyproject == __init__ == CHANGELOG-has-entry."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import version_tools  # noqa: E402


def test_live_repo_is_version_consistent():
    problems = version_tools.check_consistency(REPO_ROOT)
    assert problems == [], "version drift:\n" + "\n".join(problems)


def test_checker_flags_a_mismatch(tmp_path):
    # Build a tiny fake repo with a deliberate pyproject/__init__ mismatch.
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1.2.3"\n', encoding="utf-8"
    )
    pkg = tmp_path / "src" / "proximo"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text("## [1.2.3]\n", encoding="utf-8")
    problems = version_tools.check_consistency(tmp_path)
    assert any("!=" in p for p in problems)


def test_checker_flags_missing_changelog_entry(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\nversion = "1.2.3"\n', encoding="utf-8"
    )
    pkg = tmp_path / "src" / "proximo"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text('__version__ = "1.2.3"\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text("## [Unreleased]\n", encoding="utf-8")
    problems = version_tools.check_consistency(tmp_path)
    assert any("CHANGELOG" in p for p in problems)


def _release_repo(tmp_path: Path, pyproj_ver: str, top_changelog_ver: str | None = None) -> Path:
    top = top_changelog_ver or pyproj_ver
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\nname = "x"\nversion = "{pyproj_ver}"\n', encoding="utf-8"
    )
    pkg = tmp_path / "src" / "proximo"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(f'__version__ = "{pyproj_ver}"\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(
        f"## [Unreleased]\n\n## [{top}]\n", encoding="utf-8"
    )
    return tmp_path


def test_release_check_passes_when_all_aligned(tmp_path):
    root = _release_repo(tmp_path, "0.6.1")
    assert version_tools.check_release(root, "0.6.1") == []


def test_release_check_flags_tag_mismatch(tmp_path):
    root = _release_repo(tmp_path, "0.6.1")
    problems = version_tools.check_release(root, "0.6.2")
    assert any("tag" in p for p in problems)


def test_release_check_flags_changelog_not_top(tmp_path):
    # pyproject 0.6.1, but the top released CHANGELOG heading is 0.7.0 (out of order).
    root = _release_repo(tmp_path, "0.6.1", top_changelog_ver="0.7.0")
    problems = version_tools.check_release(root, "0.6.1")
    assert any("CHANGELOG top" in p for p in problems)
