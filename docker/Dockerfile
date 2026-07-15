# Minimal, single-purpose sandbox container: takes a URL, opens it in
# headless Chromium, takes screenshots, extracts telemetry, writes JSON.
# No Xvfb, no VNC, no extension, no persistent API service — this is a
# CLI tool that runs once per invocation and exits. Backend Team's own
# Celery worker/orchestrator container invokes this (via `docker run`
# per job, or `docker exec` against a running instance — see
# ../DOCKER_ARCHITECTURE_IDEATION.md for the two options) and reads the
# output back off a shared Docker volume.
FROM python:3.11-slim

# System deps: only what headless Chromium itself needs to run, plus
# libzbar0 for QR detection (pyzbar). No Xvfb, no x11vnc, no supervisor
# — there's no display to render to and nothing to supervise; this
# container runs one process (the CLI script) and exits.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    wget gnupg ca-certificates \
    fonts-liberation libnss3 libatk-bridge2.0-0 libgtk-3-0 libgbm1 \
    libasound2 libxss1 libxshmfence1 libx11-xcb1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY docker/requirements.txt .
# NOTE: deliberately NOT running `playwright install-deps chromium`.
# It resolves an OS package list by distro/codename detection and pulls
# in ttf-ubuntu-font-family on a Debian "trixie"-based image, which
# doesn't exist on Debian and fails the build. The apt-get list above
# already covers what headless Chromium actually needs.
RUN pip install --no-cache-dir -r requirements.txt
# Note: testing/ and batch evaluation harnesses are deliberately excluded
# from this image so only the single-scan production engine is shipped.
COPY backend/ ./backend/

# Non-root, capability-dropped at the docker-compose/run level (see
# docker-compose.yml: cap_drop: ALL). Chromium runs with --no-sandbox to
# match (see phishing_sandbox_scan.py) — its own internal sandbox wants
# capabilities this container deliberately doesn't have; the
# container/non-root-user boundary is the real isolation layer here,
# same tradeoff Playwright's own official Docker images make.
RUN useradd --create-home --shell /bin/bash sandbox \
    && mkdir -p /app/output \
    && chown -R sandbox:sandbox /app

USER sandbox

# Browser binary download happens AFTER switching to the runtime user —
# Playwright caches it under $HOME/.cache/ms-playwright. Downloading it
# as root would put it under /root/.cache, invisible to this container's
# actual runtime user, surfacing as a confusing "Executable doesn't
# exist" error at run time rather than at build time.
RUN playwright install chromium

# /app/output is the shared-Docker-volume mount point for the
# multi-container pattern — mount your shared volume here, and pass
# --output-dir /app/output on the command line so results land where a
# downstream container (or Backend Team's own orchestrator) expects
# them. See ../DOCKER_ARCHITECTURE_IDEATION.md.
VOLUME ["/app/output"]

ENTRYPOINT ["python", "backend/phishing_sandbox_scan.py"]
# No CMD default URL — always pass one explicitly:
#   docker run --rm sandbox:latest https://example.com
#   docker run --rm -v shared_scans:/app/output sandbox:latest \
#       https://example.com --output-dir /app/output
