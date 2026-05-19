from unittest.mock import patch, MagicMock


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
    code = "authorization_code"
    state = "test_state"
    sealed_value = "sealed-session-value"

    auth_response = MagicMock()
    auth_response.user = MagicMock(id="user_123")
    # Missing external_id on user triggers user UUID generation
    auth_response.user.to_dict.return_value = {"id": "user_123"}
    auth_response.roles = ["admin"]
    auth_response.access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ3b3Jrb3NfdGVuYW50X2lkIjoib3JnXzEyMyIsIndvcmtvc190ZW5hbnRfbmFtZSI6IlRlc3QgT3JnIiwidGVuYW50X3V1aWQiOiIwMTllMDJlMS05NGUxLTcyMmItYmQ2MS1mN2Y5NWZiMTYwNGMiLCJyb2xlIjoiYWRtaW4ifQ.fake_sig"
    auth_response.refresh_token = "refresh-token"
    auth_response.impersonator = None
    auth_response.workos_tenant_id = "org_123"

    updated_user = MagicMock()
    updated_user.to_dict.return_value = {"id": "user_123", "external_id": "user-uuid"}

    org = MagicMock()
    # Missing external_id on org triggers org UUID generation
    org.external_id = None

    with patch("src.routes.auth.workos_client") as mock_workos, patch("src.routes.auth.seal_session_from_auth_response") as mock_seal:
        mock_workos.user_management.authenticate_with_code_pkce.return_value = auth_response
        mock_workos.user_management.update_user.return_value = updated_user
        mock_workos.tenants.get_tenant.return_value = org
        mock_seal.return_value = sealed_value

        with client.session_transaction() as sess:
            sess["oauth_state"] = state
            sess["code_verifier"] = "verifier-value"

        response = client.get(f"/callback?code={code}&state={state}")

        assert response.status_code == 302
        assert response.headers["Location"] == "/"
        cookie_headers = response.headers.getlist("Set-Cookie")
        assert any("wos_session=" in header for header in cookie_headers)
        
        with client.session_transaction() as sess:
            assert "oauth_state" not in sess
            assert "code_verifier" not in sess


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
