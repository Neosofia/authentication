"""
WorkOS identity-provider adapter.

Owns WorkOS SDK calls, sealed-session handling, refresh semantics, claim mapping,
and external-id provisioning for the generic authentication routes.
"""

import uuid
from functools import lru_cache
from typing import Any

import jwt
from jwt import PyJWKClient
from workos import WorkOSClient
from workos.session import seal_session_from_auth_response, unseal_data

from src.bootstrap.logging import log_event, log_exception
from src.config import settings
from src.services.idp.base import AuthenticatedSession, PlatformIdentity

WORKOS_TOKEN_ISSUER = "https://api.workos.com"


class WorkOSIdentityProvider:
    name = "workos"

    def __init__(self) -> None:
        self.client = WorkOSClient(
            api_key=settings.workos_api_key,
            client_id=settings.workos_client_id,
            request_timeout=5,
            max_retries=1,
        )

    def authorization_url(self, *, state: str, code_challenge: str) -> str:
        return self.client.user_management.get_authorization_url(
            provider="authkit",
            redirect_uri=settings.workos_redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method="S256",
        )

    def exchange_code(self, *, code: str, code_verifier: str) -> AuthenticatedSession:
        auth_response = self.client.user_management.authenticate_with_code_pkce(
            code=code,
            code_verifier=code_verifier,
        )
        auth_response, user_data, _identity = prepare_auth_session(
            auth_response,
            client=self.client,
        )
        sealed_session = seal_session_from_auth_response(
            access_token=auth_response.access_token,
            refresh_token=auth_response.refresh_token,
            user=user_data,
            impersonator=(
                auth_response.impersonator.to_dict() if auth_response.impersonator else None
            ),
            cookie_password=settings.workos_cookie_password,
        )
        return AuthenticatedSession(
            idp_user_id=_idp_user_id(auth_response),
            provider_response=auth_response,
            sealed_session=sealed_session,
        )

    def authenticate_session(self, sealed: str) -> AuthenticatedSession | None:
        session = self.client.user_management.load_sealed_session(
            session_data=sealed,
            cookie_password=settings.workos_cookie_password,
        )
        auth_response = session.authenticate()

        if not getattr(auth_response, "authenticated", False):
            auth_response = session.refresh()

        if not getattr(auth_response, "authenticated", False):
            return None

        sealed_session = getattr(auth_response, "sealed_session", None)
        session_to_unseal = sealed_session or sealed
        raw_access_token = None
        try:
            raw_session = unseal_data(session_to_unseal, settings.workos_cookie_password)
            raw_access_token = raw_session.get("access_token")
        except Exception:
            raw_access_token = None

        return AuthenticatedSession(
            idp_user_id=_idp_user_id(auth_response),
            provider_response=auth_response,
            sealed_session=sealed_session,
            raw_access_token=raw_access_token,
        )

    def revoke_session(self, sealed: str, *, return_to: str) -> str | None:
        session = self.client.user_management.load_sealed_session(
            session_data=sealed,
            cookie_password=settings.workos_cookie_password,
        )
        session_id = _resolve_workos_session_id(session)
        if not session_id:
            return None
        return self.client.user_management.get_logout_url(
            session_id=session_id,
            return_to=return_to,
        )

    def to_platform_identity(self, session: AuthenticatedSession) -> PlatformIdentity:
        return extract_platform_identity(
            session.provider_response,
            access_token_str=session.raw_access_token,
        )


# Backwards-compatible singleton for existing adapter-level tests/helpers.
workos_client = WorkOSIdentityProvider().client


def _resolve_workos_session_id(session: Any) -> str | None:
    auth_response = session.authenticate()
    if getattr(auth_response, "authenticated", False):
        return auth_response.session_id

    refresh_response = session.refresh()
    if getattr(refresh_response, "authenticated", False):
        return refresh_response.session_id

    return None


def _is_valid_workos_issuer(issuer: Any) -> bool:
    if not isinstance(issuer, str) or not issuer.strip():
        return False
    return issuer.rstrip("/") == WORKOS_TOKEN_ISSUER


def _get_nested_value(source: Any, path: str) -> Any:
    if source is None:
        return None

    parts = path.split(".")
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


def _idp_user_id(auth_response: Any) -> str:
    user = getattr(auth_response, "user", None)
    if isinstance(user, dict):
        return user.get("id") or "unknown"
    return getattr(user, "id", "unknown") if user else "unknown"


def provision_user_external_id(
    user_id: str,
    user_data: dict[str, Any],
    *,
    client: WorkOSClient | None = None,
) -> tuple[dict[str, Any], bool]:
    if _non_empty_str(user_data.get("external_id")):
        return user_data, False

    client = client or workos_client
    new_person_id = str(uuid.uuid7())
    try:
        updated_user = client.user_management.update_user(
            id=user_id,
            external_id=new_person_id,
        )
        log_event("person_id_generated", user_id=user_id, person_id=new_person_id)
        return updated_user.to_dict(), True
    except Exception as exc:
        log_exception("person_id_generation_error", exc, user_id=user_id)
        return user_data, False


def provision_organization_external_id(
    idp_tenant_id: str,
    *,
    client: WorkOSClient | None = None,
) -> bool:
    client = client or workos_client
    try:
        client.organizations.update_organization(
            id=idp_tenant_id,
            external_id=str(uuid.uuid7()),
        )
        log_event("tenant_uuid_provisioned", idp_tenant_id=idp_tenant_id)
        return True
    except Exception as exc:
        log_exception(
            "tenant_uuid_provision_error",
            exc,
            idp_tenant_id=idp_tenant_id,
        )
        return False


def refresh_workos_session(
    auth_response: Any,
    *,
    idp_tenant_id: str,
    client: WorkOSClient | None = None,
) -> Any:
    refresh_token = getattr(auth_response, "refresh_token", None)
    if not refresh_token:
        log_event(
            "session_refresh_skipped",
            reason="no refresh_token",
            idp_tenant_id=idp_tenant_id,
        )
        return auth_response

    client = client or workos_client
    try:
        return client.user_management.authenticate_with_refresh_token(
            refresh_token=refresh_token,
            organization_id=idp_tenant_id,
        )
    except Exception as exc:
        log_exception(
            "session_refresh_error",
            exc,
            idp_tenant_id=idp_tenant_id,
        )
        return auth_response


def prepare_auth_session(
    auth_response: Any,
    *,
    client: WorkOSClient | None = None,
) -> tuple[Any, dict[str, Any], PlatformIdentity]:
    user = getattr(auth_response, "user", None)
    user_id = getattr(user, "id", "unknown") if user else "unknown"
    user_data = user.to_dict() if user else {}

    user_data, user_provisioned = provision_user_external_id(user_id, user_data, client=client)

    token_claims = decode_access_token_claims(auth_response)
    idp_tenant_id = _non_empty_str(token_claims.get("workos_tenant_id")) or ""
    tenant_uuid_missing = not _non_empty_str(token_claims.get("tenant_uuid"))

    if tenant_uuid_missing:
        provision_organization_external_id(idp_tenant_id, client=client)

    if user_provisioned or tenant_uuid_missing:
        auth_response = refresh_workos_session(
            auth_response,
            idp_tenant_id=idp_tenant_id,
            client=client,
        )
        user = getattr(auth_response, "user", None)
        if user:
            user_data = user.to_dict()

    return auth_response, user_data, extract_platform_identity(auth_response)


@lru_cache(maxsize=1)
def _workos_jwks_client() -> PyJWKClient:
    return PyJWKClient(workos_client.user_management.get_jwks_url())


def decode_access_token_claims(
    auth_response: Any,
    access_token_str: str | None = None,
) -> dict[str, Any]:
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
            log_event("workos_access_token_unexpected_issuer", issuer=decoded.get("iss"))
        if decoded.get("client_id") != settings.workos_client_id:
            raise jwt.InvalidTokenError("client_id mismatch")
        return decoded if isinstance(decoded, dict) else {}
    except Exception as exc:
        log_exception("workos_access_token_decode_failed", exc)
        return {}


def extract_platform_identity(
    auth_response: Any,
    *,
    access_token_str: str | None = None,
) -> PlatformIdentity:
    valid_roles = frozenset(r.strip() for r in settings.valid_roles.split(",") if r.strip())
    user_id = _idp_user_id(auth_response)
    access_token_claims = decode_access_token_claims(auth_response, access_token_str)

    workos_roles = access_token_claims.get("roles")
    workos_role = access_token_claims.get("role")

    idp_tenant_id = _non_empty_str(access_token_claims.get("workos_tenant_id"))
    tenant_name = _non_empty_str(access_token_claims.get("workos_tenant_name"))
    tenant_uuid = _non_empty_str(access_token_claims.get("tenant_uuid"))

    if not idp_tenant_id:
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
            idp_tenant_id=idp_tenant_id,
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
            idp_tenant_id=idp_tenant_id,
            valid_roles=list(valid_roles),
            provider_roles=workos_roles,
            provider_role=workos_role,
        )
        raise ValueError(
            "User has no valid roles; token issuance denied. "
            "Verify that IdP roles match VALID_ROLES."
        )

    user_uuid = _non_empty_str(_resolve_workos_value(auth_response, "user.external_id"))
    user = getattr(auth_response, "user", None)
    user_data = user if isinstance(user, dict) else user.to_dict() if user else {}
    profile = {
        key: value
        for key in ("first_name", "last_name", "email")
        if isinstance((value := user_data.get(key)), str)
    }

    return PlatformIdentity(
        user_uuid=user_uuid,
        tenant_uuid=tenant_uuid,
        idp_user_id=user_id,
        idp_tenant_id=idp_tenant_id,
        tenant_name=tenant_name,
        roles=roles,
        profile=profile,
    )


def extract_platform_claims(
    auth_response: Any,
    *,
    access_token_str: str | None = None,
) -> dict[str, Any]:
    identity = extract_platform_identity(auth_response, access_token_str=access_token_str)
    return {
        "idp_tenant_id": identity.idp_tenant_id,
        "tenant_name": identity.tenant_name,
        "tenant_uuid": identity.tenant_uuid,
        "user_uuid": identity.user_uuid,
        "roles": identity.roles,
    }
