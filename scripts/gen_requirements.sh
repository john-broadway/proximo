#!/usr/bin/env bash
# Regenerate the hash-pinned lockfiles in requirements/ — the files CI, the release
# workflows, and the Dockerfile install with `pip --require-hashes`.
#
#   runtime.txt  <- uv.lock (base deps; the image + the wheel-SBOM env)
#   dev.txt      <- uv.lock (base + dev extra; CI test env)
#   build.txt    <- build.in  (build backend: build/hatchling/editables), pinned
#                   consistently with dev.txt so the two files co-install
#   sbom.txt     <- sbom.in   (cyclonedx-bom), pinned consistently with runtime.txt
#
# Run after ANY dependency change (pyproject, uv lock), and COMMIT uv.lock alongside the
# four exports — the lock is tracked, and a lock that moves without its exports is the
# drift this guards against (pyasn1 sat two days at 0.6.3 in dev.txt while the lock said
# 0.6.4). tests/test_requirements_lock.py fails when the exported pair drifts from uv.lock
# and when the lock is untracked; the ci.yml `requirements-drift` job runs that guard in an
# environment that has uv, because the `test` job installs with pip and would skip it.
# release.sh regenerates + verifies all four in its gate.
set -euo pipefail
cd "$(dirname "$0")/.."

uv export --no-dev --no-emit-project --format requirements-txt -o requirements/runtime.txt
uv export --extra dev --no-emit-project --format requirements-txt -o requirements/dev.txt
uv pip compile --generate-hashes --universal -c requirements/dev.txt requirements/build.in -o requirements/build.txt
uv pip compile --generate-hashes --universal -c requirements/runtime.txt requirements/sbom.in -o requirements/sbom.txt
