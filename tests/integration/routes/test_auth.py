from unittest.mock import MagicMock, patch

from src.config import settings
from src.services.idp import AuthenticatedSession, PlatformIdentity


def _identity():
    return PlatformIdentity(
        user_uuid="user-uuid",
        tenant_uuid="019e02e1-94e1-722b-bd61-f7f95fb1604c",
        idp_user_id="user_123",
        idp_tenant_id="org_123",
        tenant_name="Test Org",
        roles=["admin"],
        profile={"first_name": "Ada", "last_name": "Lovelace", "email": "ada@example.com"},
    )


def test_login_happy_path_uses_configured_provider(client):
    redirect_url = "https://idp.example.com/oauth"

    with patch("src.routes.auth.get_idp") as mock_get_idp:
        mock_get_idp.return_value.name = "fake"
        mock_get_idp.return_value.authorization_url.return_value = redirect_url

        response = client.get("/login")

        assert response.status_code == 302
        assert response.headers["Location"] == redirect_url

        with client.session_transaction() as sess:
            assert "oauth_state" in sess
            assert "code_verifier" in sess



def test_callback_happy_path_with_fake_provider(client):
    provider_session = AuthenticatedSession(
        idp_user_id="user_123",
        provider_response=MagicMock(),
        sealed_session="sealed",
    )

    with (
        patch("src.routes.auth.get_idp") as mock_get_idp,
        patch("src.routes.auth.sync_identity_data") as mock_sync_identity,
    ):
        fake_idp = mock_get_idp.return_value
        fake_idp.name = "fake"
        fake_idp.exchange_code.return_value = provider_session
        fake_idp.to_platform_identity.return_value = _identity()

        with client.session_transaction() as sess:
            sess["oauth_state"] = "test_state"
            sess["code_verifier"] = "verifier-value"
        response = client.get("/callback?code=authorization_code&state=test_state")

    assert response.status_code == 302
    assert response.headers["Location"] == settings.frontend_auth_callback_url()
    fake_idp.exchange_code.assert_called_once_with(
        code="authorization_code",
        code_verifier="verifier-value",
    )
    mock_sync_identity.assert_called_once()
    assert mock_sync_identity.call_args.kwargs["idp_tenant_id"] == "org_123"
    assert any("wos_session=" in h for h in response.headers.getlist("Set-Cookie"))



def test_logout_happy_path(client):
    logout_url = "https://idp.example.com/logout"

    with patch("src.routes.auth.get_idp") as mock_get_idp:
        mock_get_idp.return_value.revoke_session.return_value = logout_url

        client.set_cookie("wos_session", "dummy-session")
        response = client.get("/logout")

        assert response.status_code == 302
        assert response.headers["Location"] == logout_url
        mock_get_idp.return_value.revoke_session.assert_called_once_with(
            "dummy-session",
            return_to=settings.frontend_url,
        )
        assert any("wos_session=;" in header for header in response.headers.getlist("Set-Cookie"))



def test_jwks_endpoint(client, api_spec, validate_response):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    validate_response(api_spec, "/.well-known/jwks.json", "get", 200, response.json)
