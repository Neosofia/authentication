from functools import lru_cache

from src.config import settings
from src.services.idp.base import AuthenticatedSession, IdentityProvider, PlatformIdentity
from src.services.idp.workos import WorkOSIdentityProvider


@lru_cache(maxsize=1)
def get_idp() -> IdentityProvider:
    provider = settings.idp_provider.strip().lower()
    if provider == "workos":
        return WorkOSIdentityProvider()
    raise ValueError(f"Unsupported IDP_PROVIDER: {settings.idp_provider}")


__all__ = ["AuthenticatedSession", "IdentityProvider", "PlatformIdentity", "get_idp"]
