FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_HTTP_TIMEOUT=60 \
    UV_LINK_MODE=copy

WORKDIR /app
RUN python -m pip install --no-cache-dir uv==0.8.24

COPY pyproject.toml uv.lock README.md ./
COPY src ./src
COPY dist-rust ./dist-rust
RUN uv sync --locked --no-dev --no-editable \
    && rust_wheel="$(find dist-rust -maxdepth 1 -type f -name '*.whl' -print -quit)" \
    && test -n "$rust_wheel" \
    && .venv/bin/python -m pip install --no-deps "$rust_wheel" \
    && .venv/bin/python -c "import aisoc_rust; print(aisoc_rust.version())" \
    && rm -rf dist-rust


FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f AS runtime

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN groupadd --gid 10001 aisoc \
    && useradd --uid 10001 --gid aisoc --no-create-home --shell /usr/sbin/nologin aisoc \
    && mkdir -p /app /var/lib/aisoc/evidence \
    && chown -R aisoc:aisoc /app /var/lib/aisoc

WORKDIR /app
COPY --from=builder --chown=aisoc:aisoc /app/.venv /app/.venv
COPY --chown=aisoc:aisoc alembic.ini ./
COPY --chown=aisoc:aisoc migrations ./migrations

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2)"]

CMD ["aisoc-api"]
