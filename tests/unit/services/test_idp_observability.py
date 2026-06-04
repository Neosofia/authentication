from unittest.mock import MagicMock, patch

import pytest

from src.services.idp.base import FailedAuthenticationEvent, FailedAuthenticationPage
from src.services.idp_observability import (
    IdpObservabilityUnavailableError,
    IdpObservabilityUnsupportedError,
    list_failed_authentications,
)


def test_list_failed_authentications_returns_serialized_items():
    page = FailedAuthenticationPage(
        items=[
            FailedAuthenticationEvent(
                id="event_1",
                occurred_at="2026-06-04T10:00:00Z",
                method="password",
                status="failed",
            )
        ],
        after="event_1",
    )
    mock_idp = MagicMock()
    mock_idp.name = "workos"
    mock_idp.list_failed_authentication_events.return_value = page

    with patch("src.services.idp_observability.get_idp", return_value=mock_idp):
        payload = list_failed_authentications(limit=5)

    assert payload["limit"] == 5
    assert payload["after"] == "event_1"
    assert payload["items"][0]["method"] == "password"


def test_list_failed_authentications_unsupported_when_method_missing():
    class _OtherIdp:
        name = "other"

    with patch("src.services.idp_observability.get_idp", return_value=_OtherIdp()):
        with pytest.raises(IdpObservabilityUnsupportedError):
            list_failed_authentications(limit=5)


def test_list_failed_authentications_unavailable_on_provider_error():
    mock_idp = MagicMock()
    mock_idp.name = "workos"
    mock_idp.list_failed_authentication_events.side_effect = RuntimeError("timeout")

    with patch("src.services.idp_observability.get_idp", return_value=mock_idp):
        with pytest.raises(IdpObservabilityUnavailableError):
            list_failed_authentications(limit=5)
