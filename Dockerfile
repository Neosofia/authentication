# Multi-stage build for Authentication Service
# Stage 1: Build environment
FROM python:3.14-alpine AS builder

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
# Build with: docker build --target ci -t pdc-authentication-ci .
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
FROM python:3.14-alpine

# Runtime shared libraries needed by C extensions
RUN apk add --no-cache libffi libpq

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /repo/.venv /app/.venv

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app"

# Copy source code, config, and static files
COPY src ./src
COPY alembic.ini ./
COPY templates ./src/templates
COPY static ./static
COPY openapi.json ./

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/api/health')" || exit 1

# Run the service
CMD ["/bin/sh", "-c", "python -m alembic upgrade head && python -m flask --app src.main:app run --host 0.0.0.0 --port 8000"]
