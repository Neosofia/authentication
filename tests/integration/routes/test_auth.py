from unittest.mock import patch, MagicMock

from src.config import settings
from tests.conftest import encode_test_access_token


def test_login_happy_path(client):
    redirect_url = "https://workos.example.com/oauth"

    with patch("src.routes.auth.workos_client") as mock_workos:
        mock_workos.user_management.get_authorization_url.return_value = redirect_url

        response = client.get("/login")

        assert response.status_code == 302
        assert response.headers["Location"] == redirect_url

        with client.session_transaction() as sess:
            assert "oauth_state" in sess
            assert "code_verifier" in sess


def test_callback_happy_path(client):
    initial = MagicMock(refresh_token="refresh-token", impersonator=None)
    initial.user = MagicMock(id="user_123")
    initial.user.to_dict.return_value = {"id": "user_123"}
    initial.access_token = encode_test_access_token(
        {"workos_tenant_id": "org_123", "workos_tenant_name": "Test Org", "role": "admin"},
    )

    refreshed = MagicMock(refresh_token="refresh-token", impersonator=None)
    refreshed.user = MagicMock(id="user_123", external_id="user-uuid")
    refreshed.user.to_dict.return_value = {"id": "user_123", "external_id": "user-uuid"}
    refreshed.access_token = encode_test_access_token(
        {
            "workos_tenant_id": "org_123",
            "workos_tenant_name": "Test Org",
            "tenant_uuid": "019e02e1-94e1-722b-bd61-f7f95fb1604c",
            "role": "admin",
        },
    )

    with (
        patch("src.routes.auth.workos_client") as mock_wos,
        patch("src.services.workos_bridge.workos_client", mock_wos),
        patch("src.routes.auth.seal_session_from_auth_response", return_value="sealed"),
        patch("src.routes.auth.sync_identity_data"),
    ):
        mock_wos.user_management.authenticate_with_code_pkce.return_value = initial
        mock_wos.user_management.update_user.return_value = MagicMock(
            to_dict=MagicMock(return_value={"id": "user_123", "external_id": "user-uuid"})
        )
        mock_wos.user_management.authenticate_with_refresh_token.return_value = refreshed

        with client.session_transaction() as sess:
            sess["oauth_state"] = "test_state"
            sess["code_verifier"] = "verifier-value"
        response = client.get("/callback?code=authorization_code&state=test_state")

    assert response.status_code == 302
    assert response.headers["Location"] == settings.frontend_auth_callback_url()
    mock_wos.organizations.update_organization.assert_called_once()
    mock_wos.user_management.authenticate_with_refresh_token.assert_called_once()
    assert any("wos_session=" in h for h in response.headers.getlist("Set-Cookie"))


def test_logout_happy_path(client):
    logout_url = "https://workos.example.com/logout"
    session = MagicMock()
    session.authenticate.return_value = MagicMock(authenticated=False)
    session.refresh.return_value = MagicMock(authenticated=True, session_id="session_123")

    with patch("src.routes.auth.workos_client") as mock_workos:
        mock_workos.user_management.load_sealed_session.return_value = session
        mock_workos.user_management.get_logout_url.return_value = logout_url

        client.set_cookie("wos_session", "dummy-session")
        response = client.get("/logout")

        assert response.status_code == 302
        assert response.headers["Location"] == logout_url
        mock_workos.user_management.get_logout_url.assert_called_once_with(
            session_id="session_123",
            return_to=settings.frontend_url,
        )
        assert any("wos_session=;" in header for header in response.headers.getlist("Set-Cookie"))


def test_jwks_endpoint(client, api_spec, validate_response):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    validate_response(api_spec, "/.well-known/jwks.json", "get", 200, response.json)
