from functools import lru_cache

from src.config import settings
from src.services.idp.base import (
    AuthenticatedSession,
    FailedAuthenticationEvent,
    FailedAuthenticationPage,
    IdentityProvider,
    PlatformIdentity,
)
from src.services.idp.workos import WorkOSIdentityProvider

_IDP_FACTORIES = {"workos": WorkOSIdentityProvider}


@lru_cache(maxsize=1)
def get_idp() -> IdentityProvider:
    provider = settings.idp_provider.strip().lower()
    try:
        return _IDP_FACTORIES[provider]()
    except KeyError as exc:
        raise ValueError(f"Unsupported IDP_PROVIDER: {settings.idp_provider}") from exc


__all__ = [
    "AuthenticatedSession",
    "FailedAuthenticationEvent",
    "FailedAuthenticationPage",
    "IdentityProvider",
    "PlatformIdentity",
    "get_idp",
]
