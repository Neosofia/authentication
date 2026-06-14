"""Cedar principal and entity builders for SDK REST inference."""
from __future__ import annotations

from typing import Any

from authorization_in_the_middle.flask_identity import jwt_claim_principal_attributes, resolve_jwt_principal
from flask import g

NAMESPACE = "authentication"


def _claims() -> dict[str, Any]:
    claims = getattr(g, "jwt_claims", {}) or {}
    if not claims.get("sub"):
        raise ValueError("missing sub")
    return claims


def principal_sub() -> str:
    return str(_claims()["sub"])


def principal_token_type() -> str:
    claims = _claims()
    _, _, attrs = jwt_claim_principal_attributes(claims)
    return str(attrs.get("token_type") or attrs.get("tokenType") or claims.get("token_type") or "human")


def resolve_principal() -> dict[str, Any]:
    return resolve_jwt_principal(NAMESPACE)


def registry_service_cedar_attrs(row: dict[str, Any]) -> dict[str, Any]:
    slug = str(row.get("slug") or "")
    return {"slug": slug}


def registry_tenant_cedar_attrs(row: dict[str, Any]) -> dict[str, Any]:
    tenant_id = str(row.get("tenant_uuid") or row.get("tenantId") or "")
    return {"tenantId": tenant_id}


def idp_observability_entities() -> list[dict[str, Any]]:
    from authorization_in_the_middle.entities import build_entity_payload

    return [
        resolve_principal(),
        build_entity_payload(f"{NAMESPACE}::IdpObservability", "idp-observability", {}),
    ]


def idp_observability_resource_uid() -> str:
    from authorization_in_the_middle.entities import entity_uid

    return entity_uid(f"{NAMESPACE}::IdpObservability", "idp-observability")
