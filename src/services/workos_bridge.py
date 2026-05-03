"""
WorkOS bridge — extracts platform claims from WorkOS session responses.

Constitution §VI: Fail-closed on invalid or unexpected user types.
Valid user types are defined here as the source of truth (pending migration to
Authorization Service API in spec/016-authorization-service/spec.md).
"""

from src.logging_config import log_event

# ── Valid User Types (M2 Validation) ─────────────────────────────────────────
# Define the canonical set of valid user types.
# Users with WorkOS roles outside this set are rejected at token issuance (fail closed).
# TODO (M2.1): Replace with API call to Authorization Service endpoint /api/valid-user-types
#              (see spec/016-authorization-service/spec.md for design).
VALID_USER_TYPES = frozenset({"clinician", "patient"})

# Map WorkOS role slugs → user_type
# Handles role normalization (e.g., "nurse" → "clinician" if desired in future)
WORKOS_ROLE_TO_USER_TYPE = {
    "clinician": "clinician",
    "org-clinician": "clinician",  # WorkOS org-based role
    "member": "clinician",  # WorkOS sandbox/org membership default role
    # "nurse": "clinician",  # Example: can normalize if needed in future
    # Add more mappings as WorkOS roles expand
}


def extract_platform_claims(auth_response) -> dict:
    """
    Extract platform claims from a WorkOS session authenticate response
    (AuthenticateWithSessionCookieSuccessResponse).

    The SDK surfaces role and organization_id directly on the response — no
    JWT decoding required.

    Validates that WorkOS role maps to a known user_type (M2).
    Rejects unknown roles with fail-closed behavior.

    Args:
        auth_response: WorkOS AuthenticateWithSessionCookieSuccessResponse

    Returns:
        {
            "user_type": str,        # Validated user type (clinician or patient)
            "tenant_id": str | None, # org ID; None for patients
            "roles": list[str],      # [user_type] for non-patients, [] for patients
        }

    Raises:
        ValueError: If WorkOS role does not map to a valid user type

    References:
        CWE-863 (Incorrect Authorization), CWE-269 (Improper Access Control)
    """
    workos_role: str | None = getattr(auth_response, "role", None)
    organization_id: str | None = getattr(auth_response, "organization_id", None)
    
    user = getattr(auth_response, "user", None)
    if isinstance(user, dict):
        user_id = user.get("id", "unknown")
    else:
        user_id = getattr(user, "id", "unknown") if user else "unknown"

    # Users with no org membership have role=None — treat as patients
    if workos_role is None:
        user_type = "patient"
    else:
        # Map WorkOS role to user type
        user_type = WORKOS_ROLE_TO_USER_TYPE.get(workos_role)
        
        if user_type is None:
            # Unknown role: fail closed (M2)
            log_event(
                "invalid_user_type_rejected",
                user_id=user_id,
                workos_role=workos_role,
                reason="role not in allow-list"
            )
            raise ValueError(
                f"WorkOS role '{workos_role}' does not map to a valid user type. "
                f"Valid types: {VALID_USER_TYPES}. "
                f"If this is a new role, update WORKOS_ROLE_TO_USER_TYPE mapping."
            )
    
    # Final validation: ensure mapped type is valid
    if user_type not in VALID_USER_TYPES:
        log_event(
            "invalid_user_type_rejected",
            user_id=user_id,
            workos_role=workos_role,
            mapped_type=user_type,
            reason="mapped type not in valid set"
        )
        raise ValueError(f"Mapped user type '{user_type}' not in {VALID_USER_TYPES}")
    
    tenant_id: str | None = organization_id or None
    roles: list[str] = [user_type] if user_type != "patient" else []

    return {
        "user_type": user_type,
        "tenant_id": tenant_id,
        "roles": roles,
    }
