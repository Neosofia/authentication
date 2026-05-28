"""Compatibility exports for the WorkOS identity-provider adapter."""

from src.services.idp.workos import (  # noqa: F401
    WORKOS_TOKEN_ISSUER,
    WorkOSIdentityProvider,
    decode_access_token_claims,
    extract_platform_claims,
    extract_platform_identity,
    prepare_auth_session,
    provision_organization_external_id,
    provision_user_external_id,
    refresh_workos_session,
)
