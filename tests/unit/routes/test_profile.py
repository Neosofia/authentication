from unittest.mock import patch, MagicMock
import jwt

def test_profile_missing_bearer(client):
    response = client.get("/api/profile")
    assert response.status_code == 401
    assert response.json["error"] == "unauthenticated"

@patch("authentication_in_the_middle.decorators.pyjwt.decode")
def test_profile_expired_token(mock_decode, client):
    mock_decode.side_effect = jwt.ExpiredSignatureError("Expired")
    response = client.get("/api/profile", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 401
    assert response.json["error"] == "unauthenticated"

@patch("authentication_in_the_middle.decorators.pyjwt.decode")
def test_profile_invalid_token(mock_decode, client):
    mock_decode.side_effect = jwt.InvalidTokenError("Bad token format")
    response = client.get("/api/profile", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 401
    assert response.json["error"] == "unauthenticated"

@patch("authentication_in_the_middle.decorators.pyjwt.decode")
def test_profile_missing_sub_claim(mock_decode, client):
    mock_decode.return_value = {"iss": "test_issuer", "aud": "test_audience"}
    response = client.get("/api/profile", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 401
    assert response.json == {"error": "invalid token", "message": "Missing sub claim"}

@patch("src.routes.profile.log_event")
@patch("src.routes.profile.workos_client")
@patch("authentication_in_the_middle.decorators.pyjwt.decode")
def test_profile_workos_user_fetch_failed(mock_decode, mock_workos, mock_log, client):
    mock_decode.return_value = {"sub": "user_123"}
    mock_workos.user_management.get_user.side_effect = Exception("User API down")
    
    response = client.get("/api/profile", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 503
    assert response.json == {"error": "failed to fetch user profile"}
    mock_log.assert_called_once_with("workos_user_fetch_failed", error_class="Exception", user_id="user_123")

@patch("src.routes.profile.log_event")
@patch("src.routes.profile.workos_client")
@patch("authentication_in_the_middle.decorators.pyjwt.decode")
def test_profile_workos_org_fetch_failed(mock_decode, mock_workos, mock_log, client):
    mock_decode.return_value = {"sub": "user_123", "neosofia:tenant_id": "org_123"}
    
    mock_user = MagicMock()
    mock_user.first_name = "Alice"
    mock_user.last_name = "Smith"
    mock_user.email = "alice@example.com"
    mock_workos.user_management.get_user.return_value = mock_user
    
    mock_workos.organizations.get_organization.side_effect = Exception("Org API down")
    
    response = client.get("/api/profile", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 200
    assert response.json["organization_name"] == "Unknown Organization"
    mock_log.assert_called_once_with("workos_org_fetch_failed", error_class="Exception", org_id="org_123")
