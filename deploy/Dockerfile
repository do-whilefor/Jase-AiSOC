FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_HTTP_TIMEOUT=60 \
    UV_LINK_MODE=copy

WORKDIR /app
RUN python -m pip install --no-cache-dir uv==0.8.24

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable


FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f AS runtime

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN groupadd --gid 10001 blue-team \
    && useradd --uid 10001 --gid blue-team --no-create-home --shell /usr/sbin/nologin blue-team \
    && mkdir -p /app /var/lib/blue-team/evidence \
    && chown -R blue-team:blue-team /app /var/lib/blue-team

WORKDIR /app
COPY --from=builder --chown=blue-team:blue-team /app/.venv /app/.venv
COPY --chown=blue-team:blue-team alembic.ini ./
COPY --chown=blue-team:blue-team migrations ./migrations

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2)"]

CMD ["blue-team-api"]
