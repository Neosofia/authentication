import base64
from unittest.mock import patch, MagicMock
import jwt

from src.services.service_tokens import InvalidClientError

class MockConnectionError(Exception):
    """Simulates a network timeout class."""
    pass


# If the grant type is not "session" or "client_credentials",
# the token endpoint should emit a 400 Bad Request with an unsupported grant string.
@patch("src.routes.token.log_event")
def test_unsupported_grant_type(mock_log, client):
    response = client.post("/api/token", data={"grant_type": "password"})
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
@patch("src.routes.token.workos_client")
def test_session_grant_invalid_session(mock_workos, mock_log, client):
    client.set_cookie("wos_session", "dummy")
    mock_session = MagicMock()
    mock_auth_response = MagicMock(authenticated=False)
    mock_session.authenticate.return_value = mock_auth_response
    mock_session.refresh.return_value = mock_auth_response
    mock_workos.user_management.load_sealed_session.return_value = mock_session
    
    response = client.post("/api/token")
    assert response.status_code == 401
    assert response.json == {"error": "session invalid or expired"}


# If WorkOS cannot be reached due to a network or connection timeout,
# the service should translate the exception into a 503 Provider Unavailable.
@patch("src.routes.token.log_event")
@patch("src.routes.token.workos_client")
def test_session_grant_workos_timeout(mock_workos, mock_log, client):
    client.set_cookie("wos_session", "dummy")
    mock_workos.user_management.load_sealed_session.side_effect = MockConnectionError("Connection timed out")
    
    response = client.post("/api/token")
    assert response.status_code == 503
    mock_log.assert_called_once_with("workos_unavailable", error_class="MockConnectionError")
    assert response.json == {"error": "authentication provider unavailable"}


# If token construction fails internally (e.g. an unexpected runtime exception),
# a 500 error should be triggered alongside a telemetry log for platform_token_error.
@patch("src.routes.token.log_event")
@patch("src.routes.token.workos_client")
@patch("src.routes.token.tokens")
@patch("src.routes.token.workos_bridge")
def test_session_grant_internal_error(mock_bridge, mock_issuer, mock_workos, mock_log, client):
    client.set_cookie("wos_session", "dummy")
    mock_session = MagicMock()
    mock_auth_response = MagicMock(authenticated=True)
    mock_session.authenticate.return_value = mock_auth_response
    mock_workos.user_management.load_sealed_session.return_value = mock_session
    mock_bridge.extract_platform_claims.return_value = {"roles": [], "tenant_id": None}
    
    mock_issuer.issue_token.side_effect = Exception("Signing error")
    
    response = client.post("/api/token")
    assert response.status_code == 500
    mock_log.assert_called_once_with("platform_token_error", error_class="Exception")


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
@patch("src.routes.token.log_event")
@patch("src.routes.token.issue_service_token")
@patch("src.routes.token.SessionLocal")
def test_client_credentials_internal_error(mock_db, mock_issue, mock_log, client):
    mock_issue.side_effect = Exception("DB offline")
    response = client.post("/api/token", data={"grant_type": "client_credentials", "client_id": "test", "client_secret": "bad"})
    assert response.status_code == 500
    mock_log.assert_called_once_with("service_token_error", error_class="Exception")


# token-inspect requires a valid Bearer token format; missing it entirely
# drops connection logic with a 401 error.
def test_token_inspect_missing_bearer(client):
    response = client.get("/api/token-inspect")
    assert response.status_code == 401
    assert response.json == {"error": "missing Bearer token"}


# The inspect endpoint delegates token verification to PyJWT. If a token
# evaluates as expired via its internal claims, we catch and return 401.
@patch("src.routes.token.pyjwt.decode")
def test_token_inspect_expired(mock_decode, client):
    mock_decode.side_effect = jwt.ExpiredSignatureError("Expired")
    response = client.get("/api/token-inspect", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 401
    assert response.json == {"error": "token expired"}


# If the PyJWT validation evaluates the token signature algorithm against
# our public keys incorrectly (indicating forgery/tampering), catch and block with 401.
@patch("src.routes.token.pyjwt.decode")
def test_token_inspect_invalid_signature(mock_decode, client):
    mock_decode.side_effect = jwt.InvalidSignatureError("Bad sig")
    response = client.get("/api/token-inspect", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 401
    assert response.json == {"error": "invalid signature"}


# A JWT passed without the specific audience parameter required for our service
# throws an error we intercept and drop cleanly.
@patch("src.routes.token.pyjwt.decode")
def test_token_inspect_invalid_audience(mock_decode, client):
    mock_decode.side_effect = jwt.InvalidAudienceError("Bad scope")
    response = client.get("/api/token-inspect", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 401
    assert response.json == {"error": "token not intended for this service"}


# A token signed from an unexpected network location or environment
# will have a mismatched issuer claim and trigger this 401 branch.
@patch("src.routes.token.pyjwt.decode")
def test_token_inspect_invalid_issuer(mock_decode, client):
    mock_decode.side_effect = jwt.InvalidIssuerError("Bad scope")
    response = client.get("/api/token-inspect", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 401
    assert response.json == {"error": "token from unauthorized issuer"}
