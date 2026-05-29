"""
Cedar entity builders and per-route entity sets for the authentication service.

Route → action → resource:

| Route | Action | Resource |
|-------|--------|----------|
| GET /api/v1/tenants/{tenant_uuid} | tenant:read | authentication::Tenant |
| GET /api/v1/profiles/{profile_id} | profile:read | authentication::Profile |
| GET/POST /api/services | service:list, service:create | authentication::ServiceCatalog |
| GET/PUT/POST … /api/services/{slug} | service:read, update, rotate, audit:read | authentication::Service |
"""
from __future__ import annotations

from typing import Any

from authorization_in_the_middle.entities import build_entity_payload
from flask import g, request

from src.config import settings

NAMESPACE = "authentication"
SERVICE_CATALOG_ID = "service-catalog"


def _jwt_claims() -> dict[str, Any]:
    claims = getattr(g, "jwt_claims", {})
    if not claims.get("sub"):
        raise ValueError("missing sub")
    return claims


def principal_sub() -> str:
    return str(_jwt_claims()["sub"])


def resolve_principal() -> dict[str, Any]:
    return build_principal_entity_from_claims(_jwt_claims())


def _principal_attrs(claims: dict[str, Any]) -> dict[str, Any]:
    ns = settings.jwt_claim_namespace
    roles = claims.get(f"{ns}:roles", [])
    if not isinstance(roles, list):
        roles = []
    tenant_uuid = claims.get(f"{ns}:tenant_uuid")
    sub = str(claims["sub"])
    return {
        "uuid": sub,
        "tenantId": str(tenant_uuid) if tenant_uuid else "",
        "isOperator": "operator" in roles,
    }


def build_principal_entity_from_claims(claims: dict[str, Any]) -> dict[str, Any]:
    return build_entity_payload(
        f"{NAMESPACE}::User",
        str(claims["sub"]),
        _principal_attrs(claims),
    )


def build_tenant_entity(tenant_uuid: str) -> dict[str, Any]:
    tenant_id = str(tenant_uuid)
    return build_entity_payload(
        f"{NAMESPACE}::Tenant",
        tenant_id,
        {"tenantId": tenant_id},
    )


def build_profile_resource_entity(profile_id: str, _row: dict[str, Any]) -> dict[str, Any]:
    owner = str(profile_id)
    return build_entity_payload(
        f"{NAMESPACE}::Profile",
        owner,
        {"ownerUuid": owner},
    )


def build_service_catalog_entity() -> dict[str, Any]:
    return build_entity_payload(f"{NAMESPACE}::ServiceCatalog", SERVICE_CATALOG_ID, {})


def build_service_entity(slug: str) -> dict[str, Any]:
    return build_entity_payload(
        f"{NAMESPACE}::Service",
        slug,
        {"slug": slug},
    )


def tenant_entities() -> list[dict[str, Any]]:
    return [
        resolve_principal(),
        build_tenant_entity(request.view_args["tenant_uuid"]),
    ]


def service_catalog_entities() -> list[dict[str, Any]]:
    return [
        resolve_principal(),
        build_service_catalog_entity(),
    ]


def service_entities() -> list[dict[str, Any]]:
    return [
        resolve_principal(),
        build_service_entity(request.view_args["slug"]),
    ]
