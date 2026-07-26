"""requirements/{runtime,dev}.txt are exports of uv.lock — fail loud when they drift.

CI and the Dockerfile install with `pip --require-hashes` against these files; a stale
export silently pins yesterday's dependency set. This test re-exports from uv.lock and
compares the requirement lines (header comments carry the generating command/path, so
only non-comment content is compared). Skips where uv isn't installed (the pip-installed
CI env) — the dev environment and the release gate both run it with uv present.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Scoped per-test, NOT module-level. A module-level skipif here would also disable the
# tracked-lockfile guard below, which needs git and not uv — and that guard is the one
# that has to survive in a uv-less environment.
_needs_uv = pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")
_needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

_EXPORTS = {
    "runtime.txt": ["--no-dev", "--no-emit-project"],
    "dev.txt": ["--extra", "dev", "--no-emit-project"],
}


def _content_lines(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if ln and not ln.lstrip().startswith("#")]


@_needs_uv
@pytest.mark.parametrize("name", sorted(_EXPORTS))
def test_requirements_export_matches_uv_lock(name, tmp_path):
    committed = REPO_ROOT / "requirements" / name
    assert committed.exists(), f"requirements/{name} missing — run scripts/gen_requirements.sh"

    out = tmp_path / name
    # --frozen: export from the lock AS COMMITTED. Without it a stale lock is silently
    # re-resolved first, and the test then compares the export against a lock nobody
    # reviewed — it would pass while the pins moved underneath.
    subprocess.run(  # noqa: S603 — fixed argv (same idiom as gen_lobehub_manifest)
        ["uv", "export", "--frozen", *_EXPORTS[name],  # noqa: S607
         "--format", "requirements-txt", "-o", str(out)],
        cwd=REPO_ROOT, check=True, capture_output=True,
    )
    assert _content_lines(committed.read_text()) == _content_lines(out.read_text()), (
        f"requirements/{name} has drifted from uv.lock — run scripts/gen_requirements.sh "
        f"and commit the result."
    )


@_needs_git
def test_uv_lock_is_tracked_by_git():
    """The lock is the first link in the chain that ships the container.

    uv.lock -> gen_requirements.sh -> hash-pinned requirements/*.txt -> `pip
    --require-hashes` -> image + SBOM. If the lock is untracked it exists on exactly one
    machine, and every other clone regenerates those pins from a fresh resolution: a
    2026-07-26 check found ~20 packages moving, including the shipped runtime (uvicorn
    0.49.0 -> 0.51.0). The exports are then reproducible artifacts of nothing.

    Being a library and committing a lock are not in tension. The lock never enters the
    wheel, so no `pip install proximo-proxmox` consumer is constrained by it.
    """
    tracked = subprocess.run(  # noqa: S603 — fixed argv
        ["git", "ls-files", "--error-unmatch", "uv.lock"],  # noqa: S607
        cwd=REPO_ROOT, capture_output=True,
    )
    assert tracked.returncode == 0, (
        "uv.lock is not tracked by git. requirements/*.txt are exports of it, so an "
        "untracked lock makes every committed pin unreproducible off this one machine. "
        "Remove the uv.lock line from .gitignore and commit the lock."
    )
