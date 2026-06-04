from dataclasses import asdict, dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class PlatformIdentity:
    user_uuid: str | None
    tenant_uuid: str | None
    idp_user_id: str
    idp_tenant_id: str
    tenant_name: str | None
    actors: list[str]
    profile: dict[str, str] = field(default_factory=dict)
    tenant_type: str | None = None


@dataclass(frozen=True)
class AuthenticatedSession:
    idp_user_id: str
    provider_response: Any
    sealed_session: str | None = None
    raw_access_token: str | None = None


@dataclass(frozen=True)
class FailedAuthenticationEvent:
    """Provider-neutral failed sign-in event for operator observability."""

    id: str
    occurred_at: str
    method: str
    status: str
    idp_user_id: str | None = None
    email: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    ip_address: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FailedAuthenticationPage:
    items: list[FailedAuthenticationEvent]
    before: str | None = None
    after: str | None = None


class IdentityProvider(Protocol):
    name: str

    def authorization_url(self, *, state: str, code_challenge: str) -> str:
        raise NotImplementedError

    def exchange_code(self, *, code: str, code_verifier: str) -> AuthenticatedSession:
        raise NotImplementedError

    def authenticate_session(self, sealed: str) -> AuthenticatedSession | None:
        raise NotImplementedError

    def revoke_session(self, sealed: str, *, return_to: str) -> str | None:
        raise NotImplementedError

    def to_platform_identity(self, session: AuthenticatedSession) -> PlatformIdentity:
        raise NotImplementedError

    def list_failed_authentication_events(
        self,
        *,
        limit: int,
        before: str | None = None,
        after: str | None = None,
    ) -> FailedAuthenticationPage:
        """List recent failed authentication attempts from the identity provider."""
        raise NotImplementedError
