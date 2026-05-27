import os
from unittest.mock import ANY, MagicMock, patch

from src.app import create_app
from src.config import settings


def _production_settings():
    return settings.__class__(
        env="production",
        app_database_url=os.environ["APP_DATABASE_URL"],
        migration_database_url=os.environ["MIGRATION_DATABASE_URL"],
        csrf_secret_key=os.environ["CSRF_SECRET_KEY"],
        workos_cookie_password=os.environ["WORKOS_COOKIE_PASSWORD"],
        valid_roles=os.environ["VALID_ROLES"],
        jwt_private_key_pem=os.environ["JWT_PRIVATE_KEY_PEM"],
        jwt_public_key_pem=os.environ["JWT_PUBLIC_KEY_PEM"],
        workos_api_key=os.environ["WORKOS_API_KEY"],
        workos_client_id=os.environ["WORKOS_CLIENT_ID"],
        workos_redirect_uri="https://auth.example.com/callback",
        frontend_url="https://example.com",
    )


def test_jwks_allows_plain_http_in_production():
    """Private-mesh JWKS fetch uses HTTP; must not 302 to HTTPS."""
    import src.app as app_module

    original = app_module.settings
    app_module.settings = _production_settings()
    try:
        response = create_app().test_client().get("/.well-known/jwks.json")
        assert response.status_code == 200
        assert response.headers.get("Location") is None
        assert "keys" in response.get_json()
    finally:
        app_module.settings = original


def test_callback_csrf_state_mismatch_logs_and_redirects(client):
    with patch("src.routes.auth.log_event") as mock_log_event:
        # Act: Provide an auth code and provider state, but NO state cookie
        response = client.get("/callback?code=fake_code&state=provider_state")

        # 1. Assert we create a log we can monitor for
        mock_log_event.assert_called_once_with(
            "oauth_state_mismatch",
            reason="CSRF/session fixation attempt detected or state expired",
            has_state_param=True,
            has_state_cookie=False,
        )

        # 2. Assert redirect to login
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]

@patch("src.routes.auth.log_event")
def test_callback_oauth_error(mock_log_event, client):
    response = client.get("/callback?error=access_denied")
    mock_log_event.assert_called_once_with("oauth_callback_error", error="access_denied", reason="OAuth provider returned error")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

@patch("src.routes.auth.log_event")
def test_callback_missing_code(mock_log_event, client):
    response = client.get("/callback")
    mock_log_event.assert_called_once_with("oauth_callback_error", reason="No authorization code received")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

@patch("src.routes.auth.log_event")
def test_callback_pkce_missing(mock_log_event, client):
    with client.session_transaction() as sess:
        sess["oauth_state"] = "test_state"
    response = client.get("/callback?code=fake_code&state=test_state")
    mock_log_event.assert_called_once_with(
        "pkce_verifier_missing",
        reason="Code verifier not found in cookie; PKCE validation will fail"
    )
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]

@patch("src.routes.auth.log_exception")
@patch("src.routes.auth.workos_client")
def test_callback_exception(mock_client, mock_log_exception, client):
    with client.session_transaction() as sess:
        sess["oauth_state"] = "test_state"
        sess["code_verifier"] = "test_verifier"
    mock_client.user_management.authenticate_with_code_pkce.side_effect = Exception("Auth failed")
    
    response = client.get("/callback?code=fake_code&state=test_state")
    mock_log_exception.assert_called_once_with("callback_error", ANY, method="workos")
    assert response.status_code == 302
    assert response.headers["Location"] == settings.frontend_url

@patch("src.routes.auth.log_event")
def test_logout_no_session(mock_log_event, client):
    response = client.get("/logout")
    mock_log_event.assert_called_once_with("logout_failure", reason="No session found")
    assert response.status_code == 302
    assert response.headers["Location"] == settings.frontend_url

@patch("src.routes.auth.log_exception")
@patch("src.routes.auth.workos_client")
def test_logout_exception(mock_client, mock_log_exception, client):
    client.set_cookie("wos_session", "dummy-session")
    mock_client.user_management.load_sealed_session.side_effect = Exception("Logout failed")

    response = client.get("/logout")
    mock_log_exception.assert_called_once_with("logout_failure", ANY)
    assert response.status_code == 302
    assert response.headers["Location"] == settings.frontend_url


@patch("src.routes.auth.log_event")
@patch("src.routes.auth.workos_client")
def test_logout_uses_authenticate_before_refresh(mock_client, mock_log_event, client):
    session = MagicMock()
    session.authenticate.return_value = MagicMock(authenticated=True, session_id="session_abc")
    mock_client.user_management.load_sealed_session.return_value = session
    mock_client.user_management.get_logout_url.return_value = "https://workos.example.com/logout"

    client.set_cookie("wos_session", "dummy-session")
    client.get("/logout")

    session.refresh.assert_not_called()
    mock_client.user_management.get_logout_url.assert_called_once_with(
        session_id="session_abc",
        return_to=settings.frontend_url,
    )
    
@patch("src.routes.auth.log_exception")
@patch("src.services.jwks.load_pem_public_key")
def test_jwks_not_rsa(mock_load_pem, mock_log_exception, client):
    mock_load_pem.return_value = "not_an_rsa_key"
    response = client.get("/.well-known/jwks.json")
    mock_log_exception.assert_called_once_with("jwks_error", ANY, reason="invalid public key")
    assert response.status_code == 500
    assert response.json == {"error": "failed to build JWKS"}

@patch("src.routes.auth.log_exception")
@patch("src.services.jwks.load_pem_public_key")
def test_jwks_exception(mock_load_pem, mock_log_exception, client):
    mock_load_pem.side_effect = Exception("Bad key")
    response = client.get("/.well-known/jwks.json")
    mock_log_exception.assert_called_once_with("jwks_error", ANY)
    assert response.status_code == 500
    assert response.json == {"error": "failed to build JWKS"}

def test_jwks_single_key(client):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    keys = response.json["keys"]
    assert len(keys) == 1
    assert keys[0]["kty"] == "RSA"
    assert keys[0]["alg"] == "RS256"
    assert "kid" in keys[0]

def test_jwks_dual_key_during_rotation(client):
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    def _gen_pub_pem():
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return k.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    active_pem = _gen_pub_pem()
    previous_pem = _gen_pub_pem()

    with patch("src.routes.auth.settings") as mock_settings:
        mock_settings.jwt_public_key_pem = active_pem
        mock_settings.jwt_previous_public_key_pem = previous_pem
        response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    keys = response.json["keys"]
    assert len(keys) == 2
    kids = {k["kid"] for k in keys}
    assert len(kids) == 2  # distinct kid per key
