"""
WorkOS bridge — extracts platform claims from WorkOS session responses.

Constitution §VI: Fail-closed on missing or invalid org membership.
All users must belong to an organization; roleless authentication is rejected.
"""

from src.config import settings
from src.bootstrap.logging import log_event


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
    workos_role: str | None = getattr(auth_response, "role", None)
    organization_id: str | None = getattr(auth_response, "organization_id", None)

    user = getattr(auth_response, "user", None)
    if isinstance(user, dict):
        user_id = user.get("id", "unknown")
    else:
        user_id = getattr(user, "id", "unknown") if user else "unknown"

    if workos_role is None or organization_id is None:
        log_event(
            "token_rejected_no_org",
            user_id=user_id,
            reason="user has no organization membership",
        )
        raise ValueError("User has no organization membership; token issuance denied")

    if workos_role not in valid_roles:
        log_event(
            "token_rejected_unknown_role",
            user_id=user_id,
            workos_role=workos_role,
            reason="role not in allow-list",
        )
        raise ValueError(
            f"WorkOS role '{workos_role}' is not in the allow-list {valid_roles}. "
            "Update VALID_ROLES env var if this is a newly provisioned role."
        )

    return {
        "tenant_id": organization_id,
        "roles": [workos_role],
    }
