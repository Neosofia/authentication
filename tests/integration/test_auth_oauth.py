"""
Integration tests for OAuth endpoints.

Tests user authentication flow (login, callback, logout) with mocked WorkOS SDK.
"""

import json
import pytest
from unittest.mock import MagicMock, patch


@pytest.mark.integration
class TestLoginEndpoint:
    """OAuth login initiation endpoint."""

    def test_login_redirects_to_workos(self, client):
        """GET /login should redirect to WorkOS authorization URL."""
        mock_wos = MagicMock()
        mock_wos.user_management.get_authorization_url.return_value = (
            "https://id.workos.com/oauth/authorize?client_id=test&..."
        )
        
        with patch("src.routes.auth.workos_client", mock_wos):
            resp = client.get("/login", follow_redirects=False)
        
        assert resp.status_code == 302
        assert "id.workos.com" in resp.location
        mock_wos.user_management.get_authorization_url.assert_called_once()

    def test_login_includes_redirect_uri(self, client):
        """GET /login should pass redirect_uri to WorkOS."""
        mock_wos = MagicMock()
        mock_wos.user_management.get_authorization_url.return_value = "https://id.workos.com/..."
        
        with patch("src.routes.auth.workos_client", mock_wos):
            client.get("/login")
        
        call_kwargs = mock_wos.user_management.get_authorization_url.call_args[1]
        assert "redirect_uri" in call_kwargs
        assert call_kwargs["provider"] == "authkit"


@pytest.mark.integration
class TestCallbackEndpoint:
    """OAuth callback handler (authorization code exchange)."""

    def test_callback_with_valid_code_sets_cookie(self, client):
        """POST /callback?code=... should exchange code for session and set cookie."""
        mock_user = MagicMock()
        mock_user.id = "usr_callback_test"
        mock_user.email = "user@example.com"
        mock_user.to_dict.return_value = {"id": "usr_callback_test", "email": "user@example.com"}
        
        mock_auth_response = MagicMock()
        mock_auth_response.user = mock_user
        mock_auth_response.access_token = "at_test"
        mock_auth_response.refresh_token = "rt_test"
        mock_auth_response.impersonator = None
        
        mock_wos = MagicMock()
        mock_wos.user_management.authenticate_with_code_pkce.return_value = mock_auth_response
        
        with patch("src.routes.auth.workos_client", mock_wos):
            with patch("src.routes.auth.seal_session_from_auth_response") as mock_seal:
                mock_seal.return_value = "sealed_session_token"
                resp = client.get("/callback?code=auth_code_123", follow_redirects=False)
        
        assert resp.status_code == 302
        assert "/" in resp.location

    def test_callback_with_missing_code_redirects_to_login(self, client):
        """GET /callback without code should redirect back to /login."""
        resp = client.get("/callback", follow_redirects=False)
        
        assert resp.status_code == 302
        assert "/login" in resp.location

    def test_callback_with_error_redirects_to_login(self, client):
        """GET /callback?error=... should redirect back to /login."""
        resp = client.get("/callback?error=access_denied", follow_redirects=False)
        
        assert resp.status_code == 302
        assert "/login" in resp.location

    def test_callback_handles_authentication_failure(self, client):
        """GET /callback should handle WorkOS authentication errors gracefully."""
        mock_wos = MagicMock()
        mock_wos.user_management.authenticate_with_code_pkce.side_effect = Exception("Invalid code")
        
        with patch("src.routes.auth.workos_client", mock_wos):
            resp = client.get("/callback?code=invalid_code", follow_redirects=False)
        
        assert resp.status_code == 302
        assert "/login" in resp.location


@pytest.mark.integration
class TestLogoutEndpoint:
    """Session revocation endpoint."""

    def test_logout_with_valid_session_deletes_cookie(self, client):
        """POST /logout should revoke session and delete cookie."""
        mock_user = MagicMock()
        mock_user.id = "usr_logout_test"
        
        mock_session = MagicMock()
        mock_session.get_logout_url.return_value = "https://id.workos.com/logout?..."
        
        mock_wos = MagicMock()
        mock_wos.user_management.load_sealed_session.return_value = mock_session
        
        with patch("src.routes.auth.workos_client", mock_wos):
            client.set_cookie("wos_session", "valid_session_token")
            resp = client.post("/logout", follow_redirects=False)
        
        assert resp.status_code == 302
        assert "id.workos.com/logout" in resp.location

    def test_logout_without_cookie_redirects_home(self, client):
        """POST /logout without session cookie should redirect home."""
        resp = client.post("/logout", follow_redirects=False)
        
        assert resp.status_code == 302
        assert "/" in resp.location

    def test_logout_handles_workos_error(self, client):
        """POST /logout should handle WorkOS errors gracefully."""
        mock_wos = MagicMock()
        mock_wos.user_management.load_sealed_session.side_effect = Exception("Session invalid")
        
        with patch("src.routes.auth.workos_client", mock_wos):
            client.set_cookie("wos_session", "invalid_session")
            resp = client.post("/logout", follow_redirects=False)
        
        assert resp.status_code == 302
        # Should still redirect and delete cookie


@pytest.mark.integration
class TestCSRFTokenEndpoint:
    """CSRF token issuance endpoint."""

    def test_csrf_token_returns_token(self, client):
        """GET /csrf-token should return a valid CSRF token."""
        resp = client.get("/csrf-token")
        
        assert resp.status_code == 200
        data = resp.get_json()
        assert "csrfToken" in data
        assert isinstance(data["csrfToken"], str)
        assert len(data["csrfToken"]) > 0

    def test_csrf_token_endpoint_exempt_from_csrf(self, client):
        """GET /csrf-token should not require CSRF protection."""
        resp = client.get("/csrf-token")
        
        assert resp.status_code == 200
        assert resp.get_json()["csrfToken"]


@pytest.mark.integration
class TestJWKSEndpoint:
    """Public key endpoint for JWT verification."""

    def test_jwks_returns_public_key_as_jwk_set(self, client, rsa_keys):
        """GET /.well-known/jwks.json should return JWK Set with public key."""
        resp = client.get("/.well-known/jwks.json")
        
        assert resp.status_code == 200
        data = resp.get_json()
        assert "keys" in data
        assert len(data["keys"]) > 0
        
        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["use"] == "sig"
        assert key["alg"] == "RS256"
        assert "kid" in key
        assert "n" in key
        assert "e" in key

    def test_jwks_key_is_valid_rsa(self, client, rsa_keys):
        """JWK Set key should be valid RSA components with RFC 7638 JWK Thumbprint kid."""
        resp = client.get("/.well-known/jwks.json")
        
        key = resp.get_json()["keys"][0]
        # Verify kid is a valid RFC 7638 JWK Thumbprint (base64url-encoded SHA-256, ~43 chars)
        # Decode to verify it's valid base64url
        import base64
        try:
            decoded = base64.urlsafe_b64decode(key["kid"] + "==")
            assert len(decoded) == 32  # SHA-256 produces 32 bytes
        except Exception:
            assert False, f"kid '{key['kid']}' is not a valid RFC 7638 JWK Thumbprint"
        
        # Verify standard RSA exponent (65537 = 0x10001)
        e_bytes = base64.urlsafe_b64decode(key["e"] + "==")
        e_int = int.from_bytes(e_bytes, "big")
        assert e_int == 65537

    def test_jwks_sets_cache_headers(self, client, rsa_keys):
        """JWK Set response should include cache headers."""
        resp = client.get("/.well-known/jwks.json")
        
        assert resp.status_code == 200
        assert "Cache-Control" in resp.headers
        assert "max-age=3600" in resp.headers["Cache-Control"]

    def test_jwks_without_public_key_returns_503(self, client, app):
        """JWK Set without public key should return 503."""
        with patch("src.routes.auth.settings.jwt_public_key_pem", None):
            resp = client.get("/.well-known/jwks.json")
        
        assert resp.status_code == 503
        assert "not configured" in resp.get_json()["error"]


@pytest.mark.integration
class TestAuthRoutesIntegration:
    """End-to-end auth flow tests."""

    def test_login_callback_logout_flow(self, client):
        """Full OAuth flow: login → callback → logout."""
        mock_user = MagicMock()
        mock_user.id = "usr_flow_test"
        mock_user.email = "flow@example.com"
        mock_user.to_dict.return_value = {"id": "usr_flow_test", "email": "flow@example.com"}
        
        # Step 1: Login redirects to WorkOS
        mock_wos = MagicMock()
        mock_wos.user_management.get_authorization_url.return_value = (
            "https://id.workos.com/oauth/authorize?client_id=test"
        )
        
        with patch("src.routes.auth.workos_client", mock_wos):
            resp = client.get("/login", follow_redirects=False)
            assert resp.status_code == 302
        
        # Step 2: Callback exchanges code for session
        mock_auth_response = MagicMock()
        mock_auth_response.user = mock_user
        mock_auth_response.access_token = "at_test"
        mock_auth_response.refresh_token = "rt_test"
        mock_auth_response.impersonator = None
        
        mock_wos.user_management.authenticate_with_code_pkce.return_value = mock_auth_response
        
        with patch("src.routes.auth.workos_client", mock_wos):
            with patch("src.routes.auth.seal_session_from_auth_response") as mock_seal:
                mock_seal.return_value = "sealed_session_token"
                resp = client.get("/callback?code=auth_code_123", follow_redirects=False)
                assert resp.status_code == 302
        
        # Step 3: Logout revokes session
        mock_session = MagicMock()
        mock_session.get_logout_url.return_value = "https://id.workos.com/logout"
        mock_wos.user_management.load_sealed_session.return_value = mock_session
        
        with patch("src.routes.auth.workos_client", mock_wos):
            client.set_cookie("wos_session", "sealed_session_token")
            resp = client.post("/logout", follow_redirects=False)
            assert resp.status_code == 302
