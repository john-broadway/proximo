"""The Dockerfile's two stages pin ONE base digest (lens B, 2026-09-03).

A base-image bump moves both FROM lines; a partial bump (one stage moved, one left) builds and
scans fine and ships a runtime on a different base than the one that built the wheel. No test
guarded the agreement: a desync mutant survived every suite. This one pins it, and the shape of
the pin (tag + full sha256), so a hand edit that drops the digest is loud too.
"""

from __future__ import annotations

import re
from pathlib import Path

_FROM = re.compile(r"^FROM (python:3\.13-slim)@(sha256:[0-9a-f]{64})(?: AS \w+)?$", re.M)


def _dockerfile() -> str:
    return (Path(__file__).resolve().parent.parent / "Dockerfile").read_text(encoding="utf-8")


def test_both_stages_pin_the_same_base_digest():
    pins = _FROM.findall(_dockerfile())
    assert len(pins) == 2, f"expected two digest-pinned FROM lines, found {pins}"
    assert pins[0][1] == pins[1][1], f"build and runtime stages pin different digests: {pins}"


def test_every_from_line_is_digest_pinned():
    froms = [ln for ln in _dockerfile().splitlines() if ln.startswith("FROM ")]
    assert froms and all(_FROM.match(ln) for ln in froms), froms


# --- the security-patch layer must actually run (2026-09-13) ---------------------------------
# The Dockerfile's `apt-get upgrade` exists so a newly-disclosed base CVE with a fix is remediated
# on the next build. Every image build uses `cache-from: type=gha`, and the RUN line never changes,
# so BuildKit replayed the layer: `#14 [stage-1 2/6] RUN apt-get update && apt-get upgrade -y ...
# #14 CACHED`. The patch step had not executed in months, while the comment above it still promised
# it had. Published 0.40.0 and 0.41.0 images scanned identically: 3 CRITICAL + 9 HIGH, all with
# fixes available. The fix is an ARG whose value changes per run; these tests are what stop a
# FOURTH build site being added tomorrow without it.

_BPA = "docker/build-push-action"
_EPOCH = "APT_SECURITY_EPOCH"


def _workflow_paths() -> list[Path]:
    # *.y*ml, not *.yml: GitHub Actions accepts .yaml equally, and a lens defeated the first
    # draft of this guard with a `nightly-image.yaml` carrying no build-arg.
    root = Path(__file__).resolve().parent.parent
    return sorted(
        p
        for d in (".github/workflows", ".gitea/workflows")
        for pat in ("*.yml", "*.yaml")
        for p in (root / d).glob(pat)
    )


def _build_steps(text: str) -> list[str]:
    """Every list item that invokes build-push-action, as its own block of lines.

    Plain-text, not yaml: PyYAML is importable here but is not a declared dependency, and a guard
    that can vanish with its import is not a guard.
    """
    # Comments are stripped first: a lens defeated the first draft by satisfying the guard with
    # `# APT_SECURITY_EPOCH=...` in a comment inside an otherwise-broken step.
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    starts = [i for i, ln in enumerate(lines) if re.match(r"^\s*-\s", ln)]
    steps = []
    for n, i in enumerate(starts):
        end = starts[n + 1] if n + 1 < len(starts) else len(lines)
        block = "\n".join(lines[i:end])
        # A raw `docker build`/`buildx build` in a `run:` is an image build too; the first draft
        # keyed on the action alone and a lens walked past it with a shell build.
        if _BPA in block or re.search(r"docker\s+(buildx\s+)?build\b", block):
            steps.append(block)
    return steps


def _code_lines(df: str) -> list[tuple[int, str]]:
    """(index, line) for real instructions only.

    The first draft of this test anchored on `df.index("apt-get upgrade")`, which matched the
    PROSE above the RUN, not the RUN: it compared two comment offsets and failed a correct
    Dockerfile. Comments here discuss the very instructions being asserted, so they have to go.
    """
    return [(i, ln) for i, ln in enumerate(df.splitlines()) if not ln.lstrip().startswith("#")]


def test_the_runtime_stage_declares_and_uses_the_cache_busting_arg():
    code = _code_lines(_dockerfile())
    arg = [i for i, ln in code if ln.startswith(f"ARG {_EPOCH}")]
    upgrade = [i for i, ln in code if "apt-get upgrade" in ln]
    assert arg, f"the runtime stage must declare ARG {_EPOCH}"
    assert upgrade, "expected an `apt-get upgrade` instruction in the runtime stage"
    # ARG scope is PER STAGE. An ARG declared in the build stage, or hoisted above the first
    # FROM as a global, expands to EMPTY in the runtime stage: the layer then caches forever
    # while every other assertion here still passes. A lens defeated the first draft both ways,
    # because it compared flat line indices and never located a stage boundary.
    froms = [i for i, ln in code if ln.startswith("FROM ")]
    stage_start = max((i for i in froms if i < upgrade[0]), default=-1)
    assert stage_start >= 0, "expected a FROM before the apt-get upgrade"
    in_stage = [i for i in arg if stage_start < i < upgrade[0]]
    assert in_stage, (
        f"ARG {_EPOCH} must be declared in the SAME stage as the apt-get upgrade "
        f"(after the FROM on line {stage_start + 1}, before line {upgrade[0] + 1}); "
        f"found it only at line(s) {[i + 1 for i in arg]}. ARG scope is per-stage: outside it, "
        f"the reference expands empty and the layer caches forever."
    )
    # Declaring is not enough to be sure: Docker documents the cache miss on an ARG's first USE.
    # Referencing it inside the RUN makes the invalidation unambiguous on every builder. The RUN
    # is the instruction block from the last RUN at or before the upgrade, through the upgrade.
    run_start = max(i for i, ln in code if ln.startswith("RUN ") and i <= upgrade[0])
    block = "\n".join(ln for i, ln in code if run_start <= i <= upgrade[0])
    assert f"${{{_EPOCH}}}" in block or f"${_EPOCH}" in block, (
        f"{_EPOCH} must be REFERENCED inside the apt RUN, not only declared:\n{block}"
    )


def test_every_image_build_passes_the_cache_busting_arg():
    missing = []
    found = 0
    for path in _workflow_paths():
        for block in _build_steps(path.read_text(encoding="utf-8")):
            found += 1
            name = next(
                (ln.strip() for ln in block.splitlines() if "name:" in ln), block.splitlines()[0]
            )
            if f"{_EPOCH}=" not in block:
                missing.append(f"{path.name}: {name}")
    assert found >= 3, f"expected to find the image build steps, found {found}"
    assert not missing, (
        "these image builds do not pass the cache-busting build-arg, so their "
        f"`apt-get upgrade` layer replays from cache and ships stale packages: {missing}"
    )
