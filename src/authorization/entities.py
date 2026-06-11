"""Cedar principal and entity builders for SDK REST inference."""
from __future__ import annotations

from typing import Any

from authorization_in_the_middle import extract_jwt_principal_entity
from authorization_in_the_middle.entities import build_entity_payload, entity_uid
from flask import g

NAMESPACE = "authentication"
SERVICE_CATALOG_ID = "service-catalog"


def principal_sub() -> str:
    return str(_claims()["sub"])


def resolve_principal() -> dict[str, Any]:
    entity = extract_jwt_principal_entity(NAMESPACE, default_type="User")
    actors = entity.get("attrs", {}).get("actors", [])
    if not isinstance(actors, list):
        actors = []
    entity["attrs"]["isOperator"] = "operator" in actors
    return entity


def _claims() -> dict[str, Any]:
    claims = getattr(g, "jwt_claims", {})
    if not claims.get("sub"):
        raise ValueError("missing sub")
    return claims


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
