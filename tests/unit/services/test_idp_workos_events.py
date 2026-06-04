from datetime import datetime, timezone
from unittest.mock import MagicMock

from src.services.idp.base import FailedAuthenticationEvent
from src.services.idp.workos import (
    WorkOSIdentityProvider,
    _method_from_workos_event_name,
    _workos_event_to_failed_authentication,
)


def test_method_from_workos_event_name():
    assert _method_from_workos_event_name("authentication.password_failed") == "password"
    assert _method_from_workos_event_name("authentication.oauth_failed") == "oauth"
    assert _method_from_workos_event_name("other") is None


def test_workos_event_to_failed_authentication_maps_fields():
    event = MagicMock()
    event.to_dict.return_value = {
        "id": "event_01",
        "event": "authentication.password_failed",
        "created_at": datetime(2026, 6, 4, 10, 18, 14, tzinfo=timezone.utc),
        "data": {
            "type": "password",
            "status": "failed",
            "user_id": "user_01",
            "email": "ops@example.com",
            "ip_address": "203.0.113.1",
            "error": {
                "code": "invalid_credentials",
                "message": "Invalid credentials",
            },
        },
    }

    mapped = _workos_event_to_failed_authentication(event)
    assert mapped == FailedAuthenticationEvent(
        id="event_01",
        occurred_at="2026-06-04T10:18:14Z",
        method="password",
        status="failed",
        idp_user_id="user_01",
        email="ops@example.com",
        error_code="invalid_credentials",
        error_message="Invalid credentials",
        ip_address="203.0.113.1",
    )


def test_list_failed_authentication_events_delegates_to_workos_events_api():
    provider = WorkOSIdentityProvider.__new__(WorkOSIdentityProvider)
    mock_client = MagicMock()
    provider.client = mock_client

    event = MagicMock()
    event.to_dict.return_value = {
        "id": "event_02",
        "event": "authentication.sso_failed",
        "created_at": "2026-06-01T00:00:00Z",
        "data": {"type": "sso", "status": "failed"},
    }
    mock_page = MagicMock()
    mock_page.data = [event]
    mock_page.list_metadata = MagicMock(before=None, after="event_02")
    mock_client.events.list_events.return_value = mock_page

    page = provider.list_failed_authentication_events(limit=10, after="event_03")

    mock_client.events.list_events.assert_called_once()
    call_kwargs = mock_client.events.list_events.call_args.kwargs
    assert call_kwargs["limit"] == 10
    assert call_kwargs["after"] == "event_03"
    assert call_kwargs["order"] == "desc"
    assert "authentication.password_failed" in call_kwargs["events"]
    assert len(page.items) == 1
    assert page.items[0].method == "sso"
    assert page.after == "event_02"
