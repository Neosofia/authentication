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
@patch("src.routes.profile.SessionLocal")
@patch("authentication_in_the_middle.decorators.pyjwt.decode")
def test_profile_db_fetch_user_failed(mock_decode, mock_db_session, mock_log, client):
    mock_decode.return_value = {"sub": "019e02b4-47e1-778a-9331-476e9f927bd9"}
    mock_db = MagicMock()
    mock_db_session.return_value.__enter__.return_value = mock_db
    mock_db.scalar.side_effect = Exception("DB down")
    
    response = client.get("/api/profile", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 503
    assert response.json == {"error": "failed to fetch user profile"}
    mock_log.assert_called_once_with("profile_db_fetch_failed", error_class="Exception", user_uuid="019e02b4-47e1-778a-9331-476e9f927bd9")

@patch("src.routes.profile.SessionLocal")
@patch("authentication_in_the_middle.decorators.pyjwt.decode")
def test_profile_db_fetch_org_missing(mock_decode, mock_db_session, client):
    mock_decode.return_value = {"sub": "019e02b4-47e1-778a-9331-476e9f927bd9", "neosofia:tenant_uuid": "019e02e1-94e1-722b-bd61-f7f95fb1604c"}
    
    # Return user, but None for org
    mock_db = MagicMock()
    mock_db_session.return_value.__enter__.return_value = mock_db
    mock_user = MagicMock()
    mock_user.first_name = "Alice"
    mock_user.last_name = "Smith"
    mock_user.email = "alice@example.com"
    mock_db.scalar.side_effect = [mock_user, None]
    
    response = client.get("/api/profile", headers={"Authorization": "Bearer 123"})
    assert response.status_code == 200
    assert response.json["tenant_name"] == "Unknown Tenant"


