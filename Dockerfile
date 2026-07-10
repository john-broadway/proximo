# Proximo — self-contained, sovereign, on-demand.
# The MCP client launches it per session: `docker run -i --rm ... proximo` (stdio).
# Base pinned by digest for reproducible builds; the readable tag stays for humans.
# Dependabot's `docker` ecosystem bumps the digest weekly and Trivy re-scans the base
# on every push to main + weekly, so it still receives upstream security updates
# without floating at build time.
FROM python:3.14-slim@sha256:b877e50bd90de10af8d82c57a022fc2e0dc731c5320d762a27986facfc3355c1

# openssh-client powers the in-container exec edge (ssh -> pct). Everything else is bundled by pip,
# so the image is self-contained and the host stays untouched.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# Allow-list copy: only what `pip install .` needs (hatchling builds the wheel from
# src/). The working tree is never copied wholesale, so a local `docker build` can't
# bake stray secrets (.env, keys, tokens) into the published image.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir .

# MCP stdio server — no daemon, no open port. Launched on demand by the client.
ENTRYPOINT ["proximo"]
