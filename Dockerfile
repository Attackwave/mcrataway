# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim

RUN groupadd --gid 1000 mcrataway \
    && useradd --uid 1000 --gid mcrataway --create-home --shell /bin/bash mcrataway

COPY --from=build /install /usr/local

# All state (config.yaml, quarantine/, history/, rules/, auth token) lives
# under MCRATAWAY_HOME — mount a volume here to persist it across
# container restarts/recreates. See --home-dir/MCRATAWAY_HOME in
# docs/ARCHITECTURE.md for the same mechanism used outside Docker.
ENV MCRATAWAY_HOME=/data
# MCRATAWAY_HOST/MCRATAWAY_PORT let `serve` be configured the container
# way (docker run -e ...) instead of appending --host/--port every time;
# unset by default so the CLI's own 127.0.0.1:8765 default still applies.
# MCRATAWAY_TOKEN pins the auth token instead of a fresh random one being
# generated (and only logged) on every container restart.
RUN mkdir -p /data && chown mcrataway:mcrataway /data

USER mcrataway
WORKDIR /home/mcrataway

# GUI/API port (mcrataway serve). Irrelevant for one-off `scan` runs.
EXPOSE 8765

# The image bundles both the CLI and the web UI — same entrypoint either
# way, e.g.:
#   docker run -v mods:/scan mcrataway scan /scan --auto
#   docker run -p 8765:8765 -v mcrataway-data:/data mcrataway serve --host 0.0.0.0
# --host 0.0.0.0 is required for `serve` in a container: the default
# 127.0.0.1 bind (mcrataway's normal, deliberately loopback-only default)
# is only reachable from inside the container's own network namespace, so
# -p 8765:8765 alone would silently connect to nothing.
ENTRYPOINT ["mcrataway"]
CMD ["--help"]
