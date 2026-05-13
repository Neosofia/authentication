import bcrypt
import uuid
from unittest.mock import MagicMock, patch

from src.models.service import Service
from src.models.service_credential import ServiceCredential
from src.services.service_tokens import InvalidClientError, issue_service_token


def test_issue_service_token_rejects_unknown_service():
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session = MagicMock()
    mock_session.execute.return_value = mock_result

    try:
        issue_service_token("unknown-service", "secret", mock_session, audience="target-service")
    except InvalidClientError:
        pass
    else:
        raise AssertionError("Expected InvalidClientError")


@patch("src.services.service_tokens.log_event")
def test_issue_service_token_rejects_missing_audience(mock_log):
    requester = Service(
        uuid=uuid.uuid7(),
        name="Requester Service",
        slug="requester-service",
        base_url="https://requester.local",
    )
    credential = ServiceCredential(
        service_uuid=requester.uuid,
        hashed_secret=bcrypt.hashpw(b"secret", bcrypt.gensalt()).decode(),
        service=requester,
    )

    mock_result_requester = MagicMock()
    mock_result_requester.scalar_one_or_none.return_value = credential

    mock_session = MagicMock()
    mock_session.execute.return_value = mock_result_requester

    try:
        issue_service_token("requester-service", "secret", mock_session, audience=None)
    except InvalidClientError:
        pass
    else:
        raise AssertionError("Expected InvalidClientError")


@patch("src.services.service_tokens.log_event")
def test_issue_service_token_rejects_invalid_audience_slug(mock_log):
    requester = Service(
        uuid=uuid.uuid7(),
        name="Requester Service",
        slug="requester-service",
        base_url="https://requester.local",
    )
    credential = ServiceCredential(
        service_uuid=requester.uuid,
        hashed_secret=bcrypt.hashpw(b"secret", bcrypt.gensalt()).decode(),
        service=requester,
    )

    mock_result_requester = MagicMock()
    mock_result_requester.scalar_one_or_none.return_value = credential
    mock_result_target = MagicMock()
    mock_result_target.scalar_one_or_none.return_value = None

    mock_session = MagicMock()
    mock_session.execute.side_effect = [mock_result_requester, mock_result_target]

    try:
        issue_service_token("requester-service", "secret", mock_session, audience="invalid-service")
    except InvalidClientError:
        pass
    else:
        raise AssertionError("Expected InvalidClientError")
