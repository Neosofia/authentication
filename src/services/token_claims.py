"""Human JWT claims sourced only from the Authentication database (no User service on critical path)."""

from __future__ import annotations

import uuid as _uuid
from typing import Any

from sqlalchemy.orm import Session

from src.bootstrap.logging import log_event
from src.models.tenant import Tenant
from src.models.user import User
from src.services.tenant_types import valid_tenant_types

PATIENT_ACTOR_ROLE_PREFIX = "patient."


def resolve_tenant_type(value: str | None) -> str | None:
    """Return a valid tenant type or None — never guess platform."""
    if value is None:
        return None
    tenant_type = str(value).strip()
    if not tenant_type:
        return None
    if tenant_type not in valid_tenant_types():
        log_event("invalid_tenant_type_ignored", tenant_type=tenant_type)
        return None
    return tenant_type


def roles_for_jwt(full_slugs: list[str], tenant_type: str) -> list[str]:
    """Map registry slugs (platform.admin) to JWT/Cedar short names (admin)."""
    prefix = f"{tenant_type}."
    names: list[str] = []
    seen: set[str] = set()
    for slug in full_slugs:
        if slug.startswith(prefix):
            name = slug[len(prefix) :]
        elif slug.startswith(PATIENT_ACTOR_ROLE_PREFIX):
            name = slug[len(PATIENT_ACTOR_ROLE_PREFIX) :]
        elif "." not in slug:
            name = slug
        else:
            continue
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def human_token_claims(
    db: Session,
    *,
    user_uuid: str | None,
    tenant_uuid: str | None,
) -> tuple[str | None, list[str]]:
    """
    Resolve tenant_type and Tier-2 roles for JWT from local Auth rows only.

    tenant_type is omitted from the JWT when unset on the tenant row.
    roles may be empty until best-effort User provisioning updates the mirror.
    """
    tenant_type: str | None = None
    if tenant_uuid:
        try:
            tenant = db.get(Tenant, _uuid.UUID(str(tenant_uuid)))
            if tenant is not None:
                tenant_type = resolve_tenant_type(tenant.type)
        except ValueError:
            pass

    if not user_uuid or tenant_type is None:
        return tenant_type, []

    try:
        user = db.get(User, _uuid.UUID(str(user_uuid)))
    except ValueError:
        return tenant_type, []

    if user is None or not user.roles:
        return tenant_type, []

    return tenant_type, roles_for_jwt(list(user.roles), tenant_type)


def cache_roles_mirror(
    db: Session,
    *,
    user_uuid: str,
    tenant_uuid: str,
    registry_payload: dict[str, Any],
) -> None:
    """Update the local roles mirror after a successful User provision response."""
    try:
        user_id = _uuid.UUID(str(user_uuid))
    except ValueError:
        return

    user = db.get(User, user_id)
    if user is None:
        return

    raw = registry_payload.get("roles")
    if not isinstance(raw, list):
        return

    user.roles = [str(slug) for slug in raw if str(slug).strip()]

    try:
        tenant_id = _uuid.UUID(str(tenant_uuid))
    except ValueError:
        tenant_id = None
    if tenant_id is not None:
        tenant = db.get(Tenant, tenant_id)
        if tenant is not None and not tenant.type:
            for slug in user.roles:
                if "." not in slug:
                    continue
                inferred_prefix = slug.split(".", 1)[0]
                if inferred_prefix == "patient":
                    continue
                inferred = resolve_tenant_type(inferred_prefix)
                if inferred:
                    tenant.type = inferred
                    break

    db.commit()
