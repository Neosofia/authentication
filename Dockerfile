# syntax=docker/dockerfile:1.7

# Multi-stage build for Authentication Service
# cedarpy 4.8.1 builds much faster against the glibc manylinux wheel than on Alpine.
ARG PYTHON_IMAGE=python:3.14-slim@sha256:c845af9399020c7e562969a13689e929074a10fd057acd1b1fad06a2fb068e97

# Stage 0: SQL audit templates
FROM ghcr.io/neosofia/sql-template:v0.5.0 AS templates

# Stage 1: Build environment
FROM ${PYTHON_IMAGE} AS build-base

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /repo

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

# Install uv
RUN pip install --no-cache-dir uv

# Copy dependency files first (minimal layer - only changes when deps change)
COPY pyproject.toml ./
COPY uv.lock ./

# Install production dependencies without installing the local project.
FROM build-base AS prod-deps
RUN --mount=type=cache,id=uv-cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable --no-install-project

# Stage 2: CI — extends build-base with dev deps and tests; not used in production
# Build with: docker build --target ci -t authentication-ci .
FROM build-base AS ci

RUN --mount=type=cache,id=uv-cache,target=/root/.cache/uv \
    uv sync --frozen --all-groups --no-editable --no-install-project
COPY alembic.ini ./
COPY src ./src
COPY tests ./tests
COPY policies ./policies
COPY openapi.json ./
RUN mkdir /reports

ENV PATH="/repo/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/repo"

# Stage 3: Runtime environment
FROM ${PYTHON_IMAGE} AS runtime

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends bash openssl \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN groupadd --system app \
    && useradd --system --gid app --create-home --home-dir /home/app app

WORKDIR /app

# Copy virtual environment from dependency stage
COPY --from=prod-deps /repo/.venv /app/.venv

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app"

# Copy source code, config, and local env helper assets
COPY src ./src
COPY alembic.ini ./
COPY openapi.json ./
COPY policies ./policies
COPY scripts ./scripts
COPY .env.example ./

# Copy audit templates purely utilizing Docker infrastructure
COPY --from=templates /sql/audit /app/audit-templates

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8014/health')" || exit 1

USER app

# Run the service
CMD ["/bin/sh", "-c", "python -m gunicorn -c src/gunicorn.py src.app:app"]
