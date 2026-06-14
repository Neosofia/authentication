"""OpenAPI write planners for service registry REST routes."""
from __future__ import annotations

from typing import Any

_UPDATABLE_FIELDS = frozenset({"name", "slug", "base_url"})


def plan_create_from_openapi() -> dict[str, Any]:
    """Normalize OpenAPI-validated body for Cedar and persistence."""
    from flask import g

    body = dict(g.planned_body)
    return {
        "name": str(body.get("name", "")).strip(),
        "slug": str(body.get("slug", "")).strip(),
        "base_url": str(body.get("base_url", "")).strip(),
    }


def plan_update_from_openapi() -> dict[str, Any]:
    """Extract updatable fields from OpenAPI-validated PUT body."""
    from flask import g, request

    slug = str(request.view_args["slug"])
    validated = dict(g.validated_body)
    updates = {
        key: str(value).strip()
        for key, value in validated.items()
        if key in _UPDATABLE_FIELDS and isinstance(value, str)
    }
    if not updates:
        raise ValueError("no updatable fields provided")
    return {"slug": slug, **updates}
