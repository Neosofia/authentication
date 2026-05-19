"""
WorkOS bridge — extracts platform claims from WorkOS session responses.

Constitution §VI: Fail-closed on missing or invalid org membership.
All users must belong to an tenant; roleless authentication is rejected.
"""

from typing import Any
import jwt

from src.config import settings
from src.bootstrap.logging import log_event


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


def _decode_access_token_claims(auth_response: Any, access_token_str: str | None = None) -> dict[str, Any]:
    access_token = access_token_str or getattr(auth_response, "access_token", None)
    if not access_token:
        return {}

    try:
        decoded = jwt.decode(access_token, options={"verify_signature": False})
        return decoded if isinstance(decoded, dict) else {}
    except Exception as exc:
        log_event("workos_access_token_decode_failed", error_class=type(exc).__name__)
        return {}


def extract_platform_claims(auth_response, *, access_token_str: str | None = None) -> dict:
    valid_roles = frozenset(r.strip() for r in settings.valid_roles.split(",") if r.strip())

    user = getattr(auth_response, "user", None)
    if isinstance(user, dict):
        user_id = user.get("id", "unknown")
    else:
        user_id = getattr(user, "id", "unknown") if user else "unknown"

    access_token_claims = _decode_access_token_claims(auth_response, access_token_str)

    # Roles come from the access token JWT claims, not the auth response object
    workos_roles = access_token_claims.get("roles")
    workos_role = access_token_claims.get("role")
    
    # Contract: Extract the truth ONLY from Custom Claims
    workos_tenant_id = access_token_claims.get("workos_tenant_id")
    workos_tenant_name = access_token_claims.get("workos_tenant_name")
    tenant_uuid = access_token_claims.get("tenant_uuid")
    
    if not workos_tenant_id:
        log_event(
            "token_rejected_no_org",
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

    user_uuid = _resolve_workos_value(auth_response, "user.external_id")

    return {
        "workos_tenant_id": workos_tenant_id,
        "workos_tenant_name": workos_tenant_name,
        "tenant_uuid": tenant_uuid,
        "user_uuid": user_uuid,
        "roles": roles,
    }
