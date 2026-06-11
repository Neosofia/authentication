"""Cedar principal and entity builders for SDK REST inference."""
from __future__ import annotations

from typing import Any

from authorization_in_the_middle.entities import build_entity_payload, entity_uid
from authorization_in_the_middle.flask_identity import jwt_claim_principal_attributes
from flask import g

from src.config import settings

NAMESPACE = "authentication"
SERVICE_CATALOG_ID = "service-catalog"


def _claims() -> dict[str, Any]:
    claims = getattr(g, "jwt_claims", {})
    if not claims.get("sub"):
        raise ValueError("missing sub")
    return claims


def _jwt_claim(name: str) -> str:
    return f"{settings.jwt_claim_namespace}:{name}"


def principal_sub() -> str:
    return str(_claims()["sub"])


def principal_token_type() -> str:
    claims = _claims()
    return str(claims.get(_jwt_claim("token_type")) or claims.get("token_type") or "human")


def build_service_principal_entity(service_slug: str, claims: dict[str, Any]) -> dict[str, Any]:
    return build_entity_payload(
        f"{NAMESPACE}::Service",
        service_slug,
        {
            "serviceSlug": service_slug,
            "tokenType": str(claims.get(_jwt_claim("token_type")) or claims.get("token_type") or ""),
        },
    )


def resolve_principal() -> dict[str, Any]:
    claims = _claims()
    sub, ptype, attributes = jwt_claim_principal_attributes(claims, default_type="User")
    if attributes.get("token_type") == "service":
        return build_service_principal_entity(sub, claims)
    entity = build_entity_payload(f"{NAMESPACE}::{ptype}", sub, attributes)
    actors = entity.get("attrs", {}).get("actors", [])
    if not isinstance(actors, list):
        actors = []
    entity["attrs"]["isOperator"] = "operator" in actors
    return entity


def build_service_catalog_entity() -> dict[str, Any]:
    return build_entity_payload(f"{NAMESPACE}::ServiceCatalog", SERVICE_CATALOG_ID, {})


def build_service_resource_entity(slug: str, _resource: dict[str, Any] | None = None) -> dict[str, Any]:
    return build_entity_payload(f"{NAMESPACE}::Service", slug, {"slug": slug})


def build_tenant_resource_entity(tenant_uuid: str, _resource: dict[str, Any] | None = None) -> dict[str, Any]:
    tenant_id = str(tenant_uuid)
    return build_entity_payload(f"{NAMESPACE}::Tenant", tenant_id, {"tenantId": tenant_id})


def idp_observability_entities() -> list[dict[str, Any]]:
    return [
        resolve_principal(),
        build_entity_payload(f"{NAMESPACE}::IdpObservability", "idp-observability", {}),
    ]


def idp_observability_resource_uid() -> str:
    return entity_uid(f"{NAMESPACE}::IdpObservability", "idp-observability")
