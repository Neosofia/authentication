from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class PlatformIdentity:
    user_uuid: str | None
    tenant_uuid: str | None
    idp_user_id: str
    idp_tenant_id: str
    tenant_name: str | None
    roles: list[str]
    profile: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class AuthenticatedSession:
    idp_user_id: str
    provider_response: Any
    sealed_session: str | None = None
    raw_access_token: str | None = None


class IdentityProvider(Protocol):
    name: str

    def authorization_url(self, *, state: str, code_challenge: str) -> str: ...

    def exchange_code(self, *, code: str, code_verifier: str) -> AuthenticatedSession: ...

    def authenticate_session(self, sealed: str) -> AuthenticatedSession | None: ...

    def revoke_session(self, sealed: str, *, return_to: str) -> str | None: ...

    def to_platform_identity(self, session: AuthenticatedSession) -> PlatformIdentity: ...
