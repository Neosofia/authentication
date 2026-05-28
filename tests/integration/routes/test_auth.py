from unittest.mock import MagicMock, patch

from src.config import settings
from src.services.idp import get_idp
from tests.conftest import encode_test_access_token


def _auth_response():
    user = MagicMock(id="user_123", external_id="12345678-1234-5678-1234-567812345678")
    user.to_dict.return_value = {
        "id": "user_123",
        "external_id": "12345678-1234-5678-1234-567812345678",
        "first_name": "Ada",
        "last_name": "Lovelace",
        "email": "ada@example.com",
    }

    response = MagicMock()
    response.access_token = encode_test_access_token(
        {
            "workos_tenant_id": "org_123",
            "workos_tenant_name": "Test Org",
            "tenant_uuid": "019e02e1-94e1-722b-bd61-f7f95fb1604c",
            "roles": ["admin"],
        }
    )
    response.refresh_token = "refresh-token"
    response.user = user
    response.impersonator = None
    response.authenticated = True
    response.session_id = "session_123"
    response.sealed_session = None
    return response


def _clear_idp_cache():
    get_idp.cache_clear()


def test_login_happy_path_uses_configured_provider(client):
    redirect_url = "https://idp.example.com/oauth"

    _clear_idp_cache()
    with patch("src.services.idp.workos.WorkOSClient") as mock_workos_client:
        mock_workos_client.return_value.user_management.get_authorization_url.return_value = (
            redirect_url
        )
        response = client.get("/login")
    _clear_idp_cache()

    assert response.status_code == 302
    assert response.headers["Location"] == redirect_url

    with client.session_transaction() as sess:
        assert "oauth_state" in sess
        assert "code_verifier" in sess



def test_callback_happy_path(client):
    _clear_idp_cache()
    with (
        patch("src.services.idp.workos.WorkOSClient") as mock_workos_client,
        patch("src.services.idp.workos.seal_session_from_auth_response", return_value="sealed"),
        patch("src.services.identity.SessionLocal") as mock_db,
    ):
        workos_client = mock_workos_client.return_value
        workos_client.user_management.authenticate_with_code_pkce.return_value = _auth_response()
        mock_db.return_value.__enter__.return_value.scalar.side_effect = [None, None]

        with client.session_transaction() as sess:
            sess["oauth_state"] = "test_state"
            sess["code_verifier"] = "verifier-value"
        response = client.get("/callback?code=authorization_code&state=test_state")
    _clear_idp_cache()

    assert response.status_code == 302
    assert response.headers["Location"] == settings.frontend_auth_callback_url()
    workos_client.user_management.authenticate_with_code_pkce.assert_called_once_with(
        code="authorization_code",
        code_verifier="verifier-value",
    )
    assert mock_db.called
    assert any("wos_session=" in h for h in response.headers.getlist("Set-Cookie"))



def test_logout_happy_path(client):
    logout_url = "https://idp.example.com/logout"

    _clear_idp_cache()
    with patch("src.services.idp.workos.WorkOSClient") as mock_workos_client:
        workos_client = mock_workos_client.return_value
        sealed_session = workos_client.user_management.load_sealed_session.return_value
        auth_response = MagicMock(authenticated=True, session_id="session_123")
        sealed_session.authenticate.return_value = auth_response
        workos_client.user_management.get_logout_url.return_value = logout_url

        client.set_cookie("wos_session", "dummy-session")
        response = client.get("/logout")
    _clear_idp_cache()

    assert response.status_code == 302
    assert response.headers["Location"] == logout_url
    workos_client.user_management.load_sealed_session.assert_called_once_with(
        session_data="dummy-session",
        cookie_password=settings.workos_cookie_password,
    )
    workos_client.user_management.get_logout_url.assert_called_once_with(
        session_id="session_123",
        return_to=settings.frontend_url,
    )
    assert any("wos_session=;" in header for header in response.headers.getlist("Set-Cookie"))



def test_jwks_endpoint(client, api_spec, validate_response):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    validate_response(api_spec, "/.well-known/jwks.json", "get", 200, response.json)
