"""Org-kind allow-list for ``neosofia:tenant_type`` (from ``VALID_TENANT_TYPES`` env)."""

from __future__ import annotations

from functools import lru_cache

from src.config import settings


@lru_cache(maxsize=1)
def valid_tenant_types() -> frozenset[str]:
    return frozenset(
        part.strip() for part in settings.valid_tenant_types.split(",") if part.strip()
    )
