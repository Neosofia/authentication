"""
WorkOS bridge — extracts platform claims from WorkOS session responses.

Constitution §VI: Fail-closed on missing or invalid org membership.
All users must belong to an organization; roleless authentication is rejected.
"""

from typing import Any

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


def extract_platform_claims(auth_response) -> dict:
    """
    Extract platform claims from a WorkOS session authenticate response
    (AuthenticateWithSessionCookieSuccessResponse).

    The SDK surfaces role and organization_id directly on the response — no
    JWT decoding required.

    Requires the user to have an org membership with a valid role.
    Rejects missing or unknown roles fail-closed.

    Args:
        auth_response: WorkOS AuthenticateWithSessionCookieSuccessResponse

    Returns:
        {
            "tenant_id": str,        # org ID from WorkOS organization_id
            "roles": list[str],      # WorkOS role slug wrapped in a list
        }

    Raises:
        ValueError: If the user has no org membership or an unrecognised role

    References:
        CWE-863 (Incorrect Authorization), CWE-269 (Improper Access Control)
    """
    valid_roles = frozenset(r.strip() for r in settings.valid_roles.split(",") if r.strip())
    workos_roles = getattr(auth_response, "roles", None)
    workos_role = getattr(auth_response, "role", None)
    organization_id = getattr(auth_response, "organization_id", None)

    user = getattr(auth_response, "user", None)
    if isinstance(user, dict):
        user_id = user.get("id", "unknown")
    else:
        user_id = getattr(user, "id", "unknown") if user else "unknown"

    if organization_id is None:
        log_event(
            "token_rejected_no_org",
            user_id=user_id,
            reason="user has no organization membership",
        )
        raise ValueError("User has no organization membership; token issuance denied")

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
            organization_id=organization_id,
            valid_roles=list(valid_roles),
            workos_roles=workos_roles,
            workos_role=workos_role,
        )
        raise ValueError(
            "User has no valid roles; token issuance denied. "
            "Verify that WorkOS roles match VALID_ROLES."
        )

    actor_uuid = _resolve_workos_value(
        auth_response,
        f"urn:{settings.jwt_claim_namespace}:actor_uuid",
        "user.external_id",
    )

    tenant_uuid = _resolve_workos_value(
        auth_response,
        f"urn:{settings.jwt_claim_namespace}:tenant_uuid",
        "organization.external_id",
    )

    return {
        "tenant_id": organization_id,
        "roles": roles,
        "actor_uuid": actor_uuid,
        "tenant_uuid": tenant_uuid,
    }
