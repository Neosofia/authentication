from unittest.mock import patch, MagicMock
import jwt

from src.services.idp import AuthenticatedSession, PlatformIdentity
from src.services.service_tokens import InvalidClientError

class MockConnectionError(Exception):
    """Simulates a network timeout class."""
    pass


def _identity():
    return PlatformIdentity(
        user_uuid="user-uuid",
        tenant_uuid="tenant-uuid",
        idp_user_id="user_123",
        idp_tenant_id="org_123",
        tenant_name="Test Org",
        roles=["admin"],
        profile={},
    )


def _session(sealed_session=None):
    return AuthenticatedSession(
        idp_user_id="user_123",
        provider_response=MagicMock(),
        sealed_session=sealed_session,
    )


# If the grant type is not "session" or "client_credentials",
# the token endpoint should emit a 400 Bad Request with an unsupported grant string.
@patch("src.routes.token.log_event")
def test_unsupported_grant_type(mock_log, client):
    response = client.post("/api/token", data={"grant_type": "password"})
    assert response.status_code == 400
    assert response.json == {"error": "unsupported_grant_type"}


def test_unsupported_json_grant_type(client):
    response = client.post("/api/token", json={"grant_type": "password"})
    assert response.status_code == 400
    assert response.json == {"error": "unsupported_grant_type"}


# When attempting a session grant (the default), if there is no wos_session
# cookie present, the endpoint should return a 401 Unauthenticated.
@patch("src.routes.token.log_event")
def test_session_grant_no_cookie(mock_log, client):
    response = client.post("/api/token")
    assert response.status_code == 401
    assert response.json == {"error": "unauthenticated"}


# When a valid looking wos_session cookie is sent, but the session is
# expired or invalid upstream on WorkOS, a 401 should be returned.
@patch("src.routes.token.log_event")
@patch("src.routes.token.get_idp")
def test_session_grant_invalid_session(mock_get_idp, mock_log, client):
    client.set_cookie("wos_session", "dummy")
    mock_get_idp.return_value.authenticate_session.return_value = None

    response = client.post("/api/token")
    assert response.status_code == 401
    assert response.json == {"error": "session invalid or expired"}


# If WorkOS cannot be reached due to a network or connection timeout,
# the service should translate the exception into a 503 Provider Unavailable.
@patch("src.routes.token.log_event")
@patch("src.routes.token.get_idp")
def test_session_grant_idp_timeout(mock_get_idp, mock_log, client):
    client.set_cookie("wos_session", "dummy")
    mock_get_idp.return_value.name = "fake"
    mock_get_idp.return_value.authenticate_session.side_effect = MockConnectionError("Connection timed out")

    response = client.post("/api/token")
    assert response.status_code == 503
    mock_log.assert_called_once_with("idp_unavailable", provider="fake", error_class="MockConnectionError")
    assert response.json == {"error": "authentication provider unavailable"}


# If token construction fails internally (e.g. an unexpected runtime exception),
# a 500 error should be triggered alongside a telemetry log for platform_token_error.
@patch("src.routes.token.log_exception")
@patch("src.routes.token.get_idp")
@patch("src.routes.token.tokens")
def test_session_grant_internal_error(mock_issuer, mock_get_idp, mock_log, client):
    client.set_cookie("wos_session", "dummy")
    fake_idp = mock_get_idp.return_value
    fake_idp.authenticate_session.return_value = _session()
    fake_idp.to_platform_identity.return_value = _identity()
    mock_issuer.issue_token.side_effect = Exception("Signing error")

    response = client.post("/api/token")
    assert response.status_code == 500
    mock_log.assert_called_once()
    assert mock_log.call_args[0][0] == "platform_token_error"


# When using the client_credentials grant, if the Authorization header
# cannot be cleanly padded/decoded as base64, the route should safely
# catch the decode exception and return a 401 invalid_client.
@patch("src.routes.token.log_event")
def test_client_credentials_invalid_base64(mock_log, client):
    response = client.post("/api/token", data={"grant_type": "client_credentials"}, headers={"Authorization": "Basic not_base64_@@@"})
    assert response.status_code == 401
    assert response.json == {"error": "invalid_client"}


# If client credentials grant is requested but the client ID and secret
# are neither in the header nor the body payload, it should reject with a 401.
@patch("src.routes.token.log_event")
def test_client_credentials_missing_auth(mock_log, client):
    response = client.post("/api/token", data={"grant_type": "client_credentials"})
    assert response.status_code == 401
    assert response.json == {"error": "invalid_client"}


# If a service uses a valid client_id but the secret does not match the database check,
# the service issues a clean InvalidClientError converted to 401.
@patch("src.routes.token.log_event")
@patch("src.routes.token.issue_service_token")
@patch("src.routes.token.SessionLocal")
def test_client_credentials_invalid_client(mock_db, mock_issue, mock_log, client):
    mock_issue.side_effect = InvalidClientError("Bad secret")
    response = client.post("/api/token", data={"grant_type": "client_credentials", "client_id": "test", "client_secret": "bad"})
    assert response.status_code == 401


# If the database offline or a deep internal error halts service token generation,
# it should result in a 500 error alongside service_token_error telemetry.
@patch("src.routes.token.log_exception")
@patch("src.routes.token.issue_service_token")
@patch("src.routes.token.SessionLocal")
def test_client_credentials_internal_error(mock_db, mock_issue, mock_log, client):
    mock_issue.side_effect = Exception("DB offline")
    response = client.post("/api/token", data={"grant_type": "client_credentials", "client_id": "test", "client_secret": "bad"})
    assert response.status_code == 500
    mock_log.assert_called_once()
    assert mock_log.call_args[0][0] == "service_token_error"


# token-inspect requires a valid Bearer token format; missing it entirely
# drops connection logic with a 401 error.
def test_token_inspect_missing_bearer(client):
    response = client.get("/api/token-inspect")
    assert response.status_code == 401
    assert response.json == {"error": "missing Bearer token"}


# The inspect endpoint is a debug decoder and does not validate signature,
# issuer, or audience. It only rejects malformed JWTs.
@patch("src.routes.token.pyjwt.decode")
def test_token_inspect_invalid_token(mock_decode, client):
    mock_decode.side_effect = jwt.InvalidTokenError("Malformed token")
    response = client.get("/api/token-inspect", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 400
    assert response.json == {"error": "invalid token"}
