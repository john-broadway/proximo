# Proximo — self-contained, sovereign, on-demand.
# The MCP client launches it per session: `docker run -i --rm ... proximo` (stdio).
# Base pinned by digest for reproducible builds; the readable tag stays for humans.
# Dependabot's `docker` ecosystem bumps the digest weekly and Trivy re-scans the base
# on every push to main + weekly; the build layer also applies Debian's current security
# patches (apt-get upgrade below), so fixes land at build time, not only on the digest bump.
# That last clause holds ONLY while every build site passes APT_SECURITY_EPOCH — see the long
# note above that RUN for the period when the cache tied it back to the digest bump.
#
# NOTE for whoever reviews the next digest-bump PR: trivy.yml has no `pull_request` trigger
# (by design, fork PRs cannot hold `security-events: write`), so a base-image bump PR showing
# all-green has NOT been image-scanned. That green speaks for the tests, never for the gate
# that governs this line. Dispatch the scan yourself (gh workflow run trivy.yml
# --ref <the PR branch>) before you believe it.
#
# Two stages so the WHOLE dependency chain is hash-pinned (requirements/*.txt, exported
# from uv.lock) and the final image carries neither the build tooling nor the source tree.
# That last clause was a claim this file made and the image did not keep until 2026-08-23:
# multi-stage removed the SOURCE tree but the runtime stage still installed with pip and left
# it there. The strip at the end of the runtime RUN is what makes the sentence true.

FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285 AS build

WORKDIR /app
# Allow-list copy: only what the wheel build needs. The working tree is never copied
# wholesale, so a local `docker build` can't bake stray secrets (.env, keys, tokens)
# into the published image.
COPY pyproject.toml README.md LICENSE ./
COPY requirements/build.txt ./requirements/build.txt
COPY src/ ./src/
# Hash-pinned build backend, then build the wheel with NO isolated env — the isolated
# env would pip-install hatchling unpinned behind our back.
RUN pip install --no-cache-dir --require-hashes -r requirements/build.txt \
 && python -m build --wheel --no-isolation

FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285

# openssh-client powers the in-container exec edge (ssh -> pct). Everything else is bundled by pip,
# so the image is self-contained and the host stays untouched.
# `apt-get upgrade` applies Debian's current security patches at build time, so a newly-disclosed
# base CVE that already has a fix (e.g. liblzma5 CVE-2026-34743 -> 5.8.1-1+deb13u1) is remediated
# on the next build instead of waiting for the weekly Dependabot digest bump to carry it.
#
# The "not only on the digest bump" half of that was false until 2026-09-13, and the cache is why.
# Every build site passes `cache-from: type=gha` and this RUN line never changes, so BuildKit
# replayed the layer (`#14 [stage-1 2/6] RUN apt-get update ... #14 CACHED`). The layer DID run,
# but only ever incidentally: when the pinned digest below moved (invalidating everything after
# it), or when the GHA cache entry aged out. Its last two executions were 2026-08-31 and
# 2026-09-04, the second forced by the digest bump in be15230. Never once because a security fix
# was published. So the control was pinned to exactly the cadence it was written to escape.
#
# What that cost, measured from the published images' own OCI configs: 0.41.0 was built
# 2026-09-13 and shipped the 2026-09-04 apt layer, byte-identical to 0.40.0's (same diff_id), so
# the two scan identically at 3 CRITICAL + 9 HIGH Debian CVEs. Debian 13.7 published every one of
# those fixes on 2026-09-12. The image was one day behind the archive at release, and would have
# stayed behind indefinitely: the pin below is ALREADY the newest python:3.13-slim, so there is no
# digest bump pending to carry them, and the digest bump was the only thing that ever did.
#
# APT_SECURITY_EPOCH decouples the two for real. CI passes the run id, so the value differs per
# run and this layer is rebuilt. It is REFERENCED inside the RUN rather than only declared,
# because Docker documents the cache miss on an ARG's first USE, and it is declared in THIS stage
# because ARG scope is per-stage: from the build stage or above the first FROM it would expand
# empty here and cache forever. run_attempt rides along with run_id so a "re-run all jobs" on a
# failed release gets a fresh epoch too, rather than replaying the one that failed.
# The `=0` default is deliberate: a plain local `docker build` with no --build-arg caches this
# layer with no signal. CI is the path that ships, and CI always passes a value.
# Cost: the apt step itself. The hash-pinned pip install below is
# downstream, but it already rebuilt on every release anyway, because the wheel changes each time.
# Measured `image` job durations: the run that rebuilt this whole chain (v0.39.1) took 3m47s, the
# two that replayed it took 4m25s and 4m20s. Rebuilding was not the slower path.
# tests/test_dockerfile_pins.py holds BOTH halves, the ARG here and the build-arg at every call
# site, including a raw `docker build` and a .yaml workflow, so a fourth image build added later
# cannot quietly go back to shipping stale packages.
#
# One seam this opens, on purpose: trivy.yml and release.yml now build with different epochs, so
# the scanned apt layer is no longer the byte-identical one the release ships. It was, until now
# (that is what the shared diff_id above means). The release layer is always the fresher of the
# two, so the drift runs safe, but the gate no longer speaks for the exact bytes.
ARG APT_SECURITY_EPOCH=0
RUN echo "apt security epoch: ${APT_SECURITY_EPOCH}" \
 && apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Runtime deps hash-pinned from the lockfile; the wheel itself installed --no-deps so
# nothing can ride in unpinned beside it.
COPY requirements/runtime.txt ./requirements/runtime.txt
COPY --from=build /app/dist/ /tmp/dist/
# ...then REMOVE the installer itself. Both HIGH findings that made 08-17 decline this very
# digest live in one place: pip's vendored tree (`pip/_vendor/vendor.txt` pins setuptools 70.3.0
# and msgpack). They are not two problems, they are one, and neither is a Proximo dependency.
# The runtime never installs anything, so pip is pure attack surface and pure CVE surface here.
# `pip uninstall -y` exits 0 on an absent package, so this holds whatever the base ships.
# pip goes LAST, because the earlier uninstalls need it.
RUN pip install --no-cache-dir --require-hashes -r requirements/runtime.txt \
 && pip install --no-cache-dir --no-deps /tmp/dist/*.whl \
 && rm -rf /tmp/dist \
 && pip uninstall -y setuptools wheel \
 && pip uninstall -y pip

# MCP stdio server — no daemon, no open port. Launched on demand by the client.
ENTRYPOINT ["proximo"]
