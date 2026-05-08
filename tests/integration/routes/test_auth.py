from unittest.mock import patch, MagicMock


def test_login_happy_path(client):
    redirect_url = "https://workos.example.com/oauth"

    with patch("src.routes.auth.workos_client") as mock_workos:
        mock_workos.user_management.get_authorization_url.return_value = redirect_url

        response = client.get("/login")

        assert response.status_code == 302
        assert response.headers["Location"] == redirect_url
        cookie_headers = response.headers.getlist("Set-Cookie")
        assert any("oauth_state=" in header for header in cookie_headers)
        assert any("code_verifier=" in header for header in cookie_headers)


def test_callback_happy_path(client):
    code = "authorization_code"
    state = "test_state"
    sealed_value = "sealed-session-value"

    auth_response = MagicMock()
    auth_response.user = MagicMock(id="user_123")
    # Missing external_id on user triggers user UUID generation
    auth_response.user.to_dict.return_value = {"id": "user_123"}
    auth_response.access_token = "access-token"
    auth_response.refresh_token = "refresh-token"
    auth_response.impersonator = None
    auth_response.organization_id = "org_123"

    updated_user = MagicMock()
    updated_user.to_dict.return_value = {"id": "user_123", "external_id": "user-uuid"}

    org = MagicMock()
    # Missing external_id on org triggers org UUID generation
    org.external_id = None

    with patch("src.routes.auth.workos_client") as mock_workos, patch("src.routes.auth.seal_session_from_auth_response") as mock_seal:
        mock_workos.user_management.authenticate_with_code_pkce.return_value = auth_response
        mock_workos.user_management.update_user.return_value = updated_user
        mock_workos.organizations.get_organization.return_value = org
        mock_seal.return_value = sealed_value

        client.set_cookie("oauth_state", state)
        client.set_cookie("code_verifier", "verifier-value")

        response = client.get(f"/callback?code={code}&state={state}")

        assert response.status_code == 302
        assert response.headers["Location"] == "/"
        cookie_headers = response.headers.getlist("Set-Cookie")
        assert any("wos_session=" in header for header in cookie_headers)
        assert any("oauth_state=;" in header for header in cookie_headers)
        assert any("code_verifier=;" in header for header in cookie_headers)


def test_logout_happy_path(client):
    logout_url = "https://workos.example.com/logout"

    session = MagicMock()
    session.get_logout_url.return_value = logout_url

    with patch("src.routes.auth.workos_client") as mock_workos:
        mock_workos.user_management.load_sealed_session.return_value = session

        client.set_cookie("wos_session", "dummy-session")
        response = client.get("/logout")

        assert response.status_code == 302
        assert response.headers["Location"] == logout_url
        cookie_headers = response.headers.getlist("Set-Cookie")
        assert any("wos_session=;" in header for header in cookie_headers)


def test_csrf_token_endpoint(client):
    response = client.get("/csrf-token")
    assert response.status_code == 200
    assert response.json and "csrfToken" in response.json


def test_jwks_endpoint(client, api_spec, validate_response):
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    validate_response(api_spec, "/.well-known/jwks.json", "get", 200, response.json)
