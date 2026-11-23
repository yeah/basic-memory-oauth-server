# Single image for all three Python services (gateway, Basic Memory, WsgiDAV).
# They share one dependency set (the uv project), so one build serves all of
# them; each compose service merely runs a different command.
FROM python:3.12-slim

# uv for fast dependency installation.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

# gosu lets the entrypoint fix volume ownership as root and then drop to an
# unprivileged user to run the actual process.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 app

ENV HOME=/home/app \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH=/app/.venv/bin:$PATH

WORKDIR /app

# Install dependencies first, for better layer caching. uv.lock is optional:
# the trailing * tolerates its absence (pyproject.toml still matches, so COPY
# succeeds). With a committed lockfile present, uv uses it; without one, uv
# resolves from pyproject.toml. Drop --frozen so a missing/stale lock is fine.
COPY pyproject.toml uv.lock* ./
RUN uv sync --no-dev

# Application code and the container WsgiDAV config.
COPY auth_gateway.py file_probe.py ./
COPY docker/wsgidav.yaml ./docker/wsgidav.yaml
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
