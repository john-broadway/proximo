# Proximo — self-contained, sovereign, on-demand.
# The MCP client launches it per session: `docker run -i --rm ... proximo` (stdio).
# Base pinned by digest for reproducible builds; the readable tag stays for humans.
# Dependabot's `docker` ecosystem bumps the digest weekly and Trivy re-scans the base
# on every push to main + weekly; the build layer also applies Debian's current security
# patches (apt-get upgrade below), so fixes land at build time, not only on the digest bump.
#
# Two stages so the WHOLE dependency chain is hash-pinned (requirements/*.txt, exported
# from uv.lock) and the final image carries neither the build tooling nor the source tree.

FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91 AS build

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

FROM python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

# openssh-client powers the in-container exec edge (ssh -> pct). Everything else is bundled by pip,
# so the image is self-contained and the host stays untouched.
# `apt-get upgrade` applies Debian's current security patches at build time, so a newly-disclosed
# base CVE that already has a fix (e.g. liblzma5 CVE-2026-34743 -> 5.8.1-1+deb13u1) is remediated
# on the next build instead of waiting for the weekly Dependabot digest bump to carry it.
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Runtime deps hash-pinned from the lockfile; the wheel itself installed --no-deps so
# nothing can ride in unpinned beside it.
COPY requirements/runtime.txt ./requirements/runtime.txt
COPY --from=build /app/dist/ /tmp/dist/
RUN pip install --no-cache-dir --require-hashes -r requirements/runtime.txt \
 && pip install --no-cache-dir --no-deps /tmp/dist/*.whl \
 && rm -rf /tmp/dist

# MCP stdio server — no daemon, no open port. Launched on demand by the client.
ENTRYPOINT ["proximo"]
