"""
WorkOS bridge — extracts platform claims from WorkOS session responses.

Constitution §VI: Fail-closed on missing or invalid tenant membership.
All users must belong to a tenant; roleless authentication is rejected.

Platform tenant claims (workos_tenant_id, workos_tenant_name, tenant_uuid) are read
only from the WorkOS access-token JWT custom-claims template — no fallbacks.
"""

import uuid
from functools import lru_cache
from typing import Any

import jwt
from jwt import PyJWKClient

from src.config import settings
from src.bootstrap.extensions import workos_client
from src.bootstrap.logging import log_event, log_exception

WORKOS_TOKEN_ISSUER = "https://api.workos.com"


def _is_valid_workos_issuer(issuer: Any) -> bool:
    if not isinstance(issuer, str) or not issuer.strip():
        return False
    return issuer.rstrip("/") == WORKOS_TOKEN_ISSUER


def _get_nested_value(source: Any, path: str) -> Any:
    if source is None:
        return None

    parts = path.split('.')
    current = source
    for part in parts:
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(part)
        else:
            current = getattr(current, part, None)
    return current


def _resolve_workos_value(auth_response: Any, *paths: str) -> Any:
    for path in paths:
        value = _get_nested_value(auth_response, path)
        if value is not None:
            return value
    return None


def _non_empty_str(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def provision_user_external_id(user_id: str, user_data: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    if _non_empty_str(user_data.get("external_id")):
        return user_data, False

    new_person_id = str(uuid.uuid7())
    try:
        updated_user = workos_client.user_management.update_user(
            id=user_id,
            external_id=new_person_id,
        )
        log_event("person_id_generated", user_id=user_id, person_id=new_person_id)
        return updated_user.to_dict(), True
    except Exception as exc:
        log_exception("person_id_generation_error", exc, user_id=user_id)
        return user_data, False


def provision_organization_external_id(workos_tenant_id: str) -> bool:
    try:
        workos_client.organizations.update_organization(
            id=workos_tenant_id,
            external_id=str(uuid.uuid7()),
        )
        log_event("tenant_uuid_provisioned", workos_tenant_id=workos_tenant_id)
        return True
    except Exception as exc:
        log_exception(
            "tenant_uuid_provision_error",
            exc,
            workos_tenant_id=workos_tenant_id,
        )
        return False


def refresh_workos_session(auth_response: Any, *, workos_tenant_id: str) -> Any:
    refresh_token = getattr(auth_response, "refresh_token", None)
    if not refresh_token:
        log_event(
            "session_refresh_skipped",
            reason="no refresh_token",
            workos_tenant_id=workos_tenant_id,
        )
        return auth_response

    try:
        return workos_client.user_management.authenticate_with_refresh_token(
            refresh_token=refresh_token,
            organization_id=workos_tenant_id,
        )
    except Exception as exc:
        log_exception(
            "session_refresh_error",
            exc,
            workos_tenant_id=workos_tenant_id,
        )
        return auth_response


def prepare_auth_session(auth_response: Any) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    user = getattr(auth_response, "user", None)
    user_id = getattr(user, "id", "unknown") if user else "unknown"
    user_data = user.to_dict() if user else {}

    user_data, user_provisioned = provision_user_external_id(user_id, user_data)

    token_claims = decode_access_token_claims(auth_response)
    workos_tenant_id = _non_empty_str(token_claims.get("workos_tenant_id")) or ""
    tenant_uuid_missing = not _non_empty_str(token_claims.get("tenant_uuid"))

    if tenant_uuid_missing:
        provision_organization_external_id(workos_tenant_id)

    if user_provisioned or tenant_uuid_missing:
        auth_response = refresh_workos_session(auth_response, workos_tenant_id=workos_tenant_id)
        user = getattr(auth_response, "user", None)
        if user:
            user_data = user.to_dict()

    return auth_response, user_data, extract_platform_claims(auth_response)


@lru_cache(maxsize=1)
def _workos_jwks_client() -> PyJWKClient:
    return PyJWKClient(workos_client.user_management.get_jwks_url())


def decode_access_token_claims(auth_response: Any, access_token_str: str | None = None) -> dict[str, Any]:
    access_token = access_token_str or getattr(auth_response, "access_token", None)
    if not access_token:
        return {}

    try:
        signing_key = _workos_jwks_client().get_signing_key_from_jwt(access_token)
        decoded = jwt.decode(
            access_token,
            signing_key.key,
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False},
        )
        if not _is_valid_workos_issuer(decoded.get("iss")):
            # Custom AuthKit domains use a non-default iss; signature was verified via WorkOS JWKS.
            log_event("workos_access_token_unexpected_issuer", issuer=decoded.get("iss"))
        if decoded.get("client_id") != settings.workos_client_id:
            raise jwt.InvalidTokenError("client_id mismatch")
        return decoded if isinstance(decoded, dict) else {}
    except Exception as exc:
        log_exception("workos_access_token_decode_failed", exc)
        return {}


def extract_platform_claims(
    auth_response,
    *,
    access_token_str: str | None = None,
) -> dict:
    valid_roles = frozenset(r.strip() for r in settings.valid_roles.split(",") if r.strip())

    user = getattr(auth_response, "user", None)
    if isinstance(user, dict):
        user_id = user.get("id", "unknown")
    else:
        user_id = getattr(user, "id", "unknown") if user else "unknown"

    access_token_claims = decode_access_token_claims(auth_response, access_token_str)

    workos_roles = access_token_claims.get("roles")
    workos_role = access_token_claims.get("role")

    # Custom-claims template only — no org_id, organization_id, or API fallbacks.
    workos_tenant_id = _non_empty_str(access_token_claims.get("workos_tenant_id"))
    workos_tenant_name = _non_empty_str(access_token_claims.get("workos_tenant_name"))
    tenant_uuid = _non_empty_str(access_token_claims.get("tenant_uuid"))

    if not workos_tenant_id:
        log_event(
            "token_rejected_no_workos_tenant_id",
            user_id=user_id,
            reason="missing workos_tenant_id in template",
        )
        raise ValueError("User has no workos_tenant_id in token; token issuance denied")

    if not tenant_uuid:
        log_event(
            "token_rejected_no_tenant_uuid",
            user_id=user_id,
            workos_tenant_id=workos_tenant_id,
            reason="missing tenant_uuid in template",
        )
        raise ValueError("User has no tenant_uuid in token; token issuance denied")

    roles: list[str] = []
    if workos_roles is not None:
        if isinstance(workos_roles, str):
            workos_roles = [workos_roles]
        for role in workos_roles:
            if role in valid_roles and role not in roles:
                roles.append(role)
    elif workos_role is not None:
        if workos_role in valid_roles:
            roles.append(workos_role)

    if not roles:
        log_event(
            "token_rejected_no_valid_roles",
            user_id=user_id,
            workos_tenant_id=workos_tenant_id,
            valid_roles=list(valid_roles),
            workos_roles=workos_roles,
            workos_role=workos_role,
        )
        raise ValueError(
            "User has no valid roles; token issuance denied. "
            "Verify that WorkOS roles match VALID_ROLES."
        )

    user_uuid = _non_empty_str(_resolve_workos_value(auth_response, "user.external_id"))

    return {
        "workos_tenant_id": workos_tenant_id,
        "workos_tenant_name": workos_tenant_name,
        "tenant_uuid": tenant_uuid,
        "user_uuid": user_uuid,
        "roles": roles,
    }
