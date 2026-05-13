# Multi-stage build for Authentication Service
# Stage 0: SQL audit templates
FROM ghcr.io/neosofia/sql-template:v0.4.2 AS templates

# Stage 1: Build environment
FROM python:3.14-alpine@sha256:dd4d2bd5b53d9b25a51da13addf2be586beebd5387e289e798e4083d94ca837a AS builder

# Build tools needed for C-extension packages (asyncpg, cryptography, bcrypt, cffi)
RUN apk add --no-cache gcc musl-dev libffi-dev postgresql-dev

WORKDIR /repo

# Install uv
RUN pip install --no-cache-dir uv

# Copy dependency files first (minimal layer - only changes when deps change)
COPY pyproject.toml ./
COPY uv.lock ./

# Install dependencies with uv from the repo root
WORKDIR /repo
RUN uv sync --no-dev --no-editable

# Copy source code last (code changes don't invalidate dependency layer)
COPY src ./src
COPY alembic.ini ./

# Stage 2: CI — extends builder with dev deps and tests; not used in production
# Build with: docker build --target ci -t authentication-ci .
FROM builder AS ci

WORKDIR /repo
RUN uv sync --all-groups --no-editable
COPY tests ./tests
COPY openapi.json ./
RUN mkdir /reports

ENV PATH="/repo/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/repo"

# Stage 3: Runtime environment
FROM python:3.14-alpine@sha256:dd4d2bd5b53d9b25a51da13addf2be586beebd5387e289e798e4083d94ca837a

# Runtime shared libraries needed by C extensions and local env setup
RUN apk add --no-cache bash openssl libffi libpq && addgroup -S app && adduser -S -G app app

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /repo/.venv /app/.venv

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app"

# Copy source code, config, and local env helper assets
COPY src ./src
COPY alembic.ini ./
COPY openapi.json ./
COPY scripts ./scripts
COPY .env.example ./

# Copy audit templates purely utilizing Docker infrastructure
COPY --from=templates /sql/audit /app/audit-templates

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8014/api/health')" || exit 1

USER app

# Run the service
CMD ["/bin/sh", "-c", "python -m alembic upgrade head && python -m gunicorn -c src/gunicorn.py src.app:app"]
