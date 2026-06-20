"""Unit tests for version_tools.set_version (operates on a tmp sandbox)."""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import version_tools  # noqa: E402


def _sandbox(tmp_path: Path, version: str) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        f'[build-system]\nrequires = ["hatchling"]\n\n'
        f'[project]\nname = "proximo-proxmox"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    pkg = tmp_path / "src" / "proximo"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    return tmp_path


def test_set_version_updates_both_files(tmp_path):
    root = _sandbox(tmp_path, "0.6.0")
    version_tools.set_version(root, "0.7.0")
    assert version_tools.read_pyproject_version(root) == "0.7.0"
    assert version_tools.read_init_version(root) == "0.7.0"


def test_set_version_is_idempotent(tmp_path):
    root = _sandbox(tmp_path, "0.7.0")
    version_tools.set_version(root, "0.7.0")
    assert version_tools.read_pyproject_version(root) == "0.7.0"
