"""Operator-facing identity-provider observability (provider-agnostic facade)."""

from src.bootstrap.logging import log_exception
from src.services.idp import get_idp
from src.services.idp.base import FailedAuthenticationPage


class IdpObservabilityUnavailableError(Exception):
    """Identity provider events API is unreachable or returned an error."""


class IdpObservabilityUnsupportedError(Exception):
    """Configured identity provider does not expose failed-authentication events."""


def list_failed_authentications(
    *,
    limit: int,
    before: str | None = None,
    after: str | None = None,
) -> dict:
    idp = get_idp()
    list_events = getattr(idp, "list_failed_authentication_events", None)
    if list_events is None:
        raise IdpObservabilityUnsupportedError(idp.name)

    try:
        page: FailedAuthenticationPage = list_events(
            limit=limit,
            before=before,
            after=after,
        )
    except NotImplementedError as exc:
        raise IdpObservabilityUnsupportedError(idp.name) from exc
    except Exception as exc:
        log_exception("idp_failed_authentications_fetch_failed", exc, idp=idp.name)
        raise IdpObservabilityUnavailableError from exc

    return {
        "items": [item.to_dict() for item in page.items],
        "limit": limit,
        "before": page.before,
        "after": page.after,
    }
