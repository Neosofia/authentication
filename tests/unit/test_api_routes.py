"""
Unit tests for API route error handling and edge cases.

Tests error paths, malformed inputs, and configuration issues
without requiring database or complex mocking.
"""

import base64
import pytest
from unittest.mock import MagicMock, patch


@pytest.mark.unit
class TestSessionGrantErrorHandling:
    """Error handling in session grant flow."""

    def test_workos_network_error_returns_503(self, client):
        """WorkOS network errors should return 503."""
        mock_wos = MagicMock()
        mock_wos.user_management.load_sealed_session.side_effect = ConnectionError("network error")
        
        with patch("src.routes.api.workos_client", mock_wos):
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token")
        
        assert resp.status_code == 503
        assert "unavailable" in resp.get_json()["error"]

    def test_workos_dns_error_returns_503(self, client):
        """WorkOS DNS resolution errors should return 503."""
        mock_wos = MagicMock()
        mock_wos.user_management.load_sealed_session.side_effect = OSError("Connection error: name lookup failed")
        
        with patch("src.routes.api.workos_client", mock_wos):
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token")
        
        assert resp.status_code == 503
        assert "unavailable" in resp.get_json()["error"]

    def test_workos_other_exception_propagates(self, client):
        """Other WorkOS exceptions should propagate (not caught)."""
        mock_wos = MagicMock()
        mock_wos.user_management.load_sealed_session.side_effect = ValueError("unexpected error")
        
        with patch("src.routes.api.workos_client", mock_wos):
            client.set_cookie("wos_session", "valid")
            # Should not catch ValueError, route will 500
            with pytest.raises(ValueError):
                client.post("/api/token")


@pytest.mark.unit
class TestClientCredentialsErrorHandling:
    """Error handling in client credentials grant."""

    def test_invalid_base64_auth_header(self, client):
        """Invalid Base64 in Authorization header should return 401."""
        resp = client.post(
            "/api/token",
            headers={"Authorization": "Basic !!!invalid-base64!!!"},
            data={"grant_type": "client_credentials"}
        )
        
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_client"

    def test_basic_auth_missing_colon(self, client):
        """Basic auth without colon separator should return 401."""
        invalid_auth = "Basic " + base64.b64encode(b"clientidonly").decode()
        resp = client.post(
            "/api/token",
            headers={"Authorization": invalid_auth},
            data={"grant_type": "client_credentials"}
        )
        
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_client"

    def test_empty_client_id_returns_401(self, client):
        """Empty client_id should return 401."""
        resp = client.post(
            "/api/token",
            data={"grant_type": "client_credentials", "client_id": "", "client_secret": "secret"}
        )
        
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_client"

    def test_empty_client_secret_returns_401(self, client):
        """Empty client_secret should return 401."""
        resp = client.post(
            "/api/token",
            data={"grant_type": "client_credentials", "client_id": "client", "client_secret": ""}
        )
        
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_client"


@pytest.mark.unit
class TestAuthorizationHeaderParsing:
    """Authorization header parsing edge cases."""

    def test_bearer_token_with_extra_spaces(self, client):
        """Bearer token with extra spaces should be rejected."""
        resp = client.get("/api/token-inspect", headers={"Authorization": "Bearer   token"})
        
        assert resp.status_code == 401
        assert "invalid token" in resp.get_json()["error"]

    def test_bearer_case_insensitive(self, client):
        """Bearer token check should be case-sensitive (only 'Bearer' works)."""
        resp = client.get("/api/token-inspect", headers={"Authorization": "bearer token"})
        
        assert resp.status_code == 401
        assert "Bearer token" in resp.get_json()["error"]

    def test_missing_authorization_header(self, client):
        """Missing Authorization header should return 401."""
        resp = client.get("/api/token-inspect")
        
        assert resp.status_code == 401
        assert "Bearer token" in resp.get_json()["error"]

    def test_empty_authorization_header(self, client):
        """Empty Authorization header should return 401."""
        resp = client.get("/api/token-inspect", headers={"Authorization": ""})
        
        assert resp.status_code == 401
        assert "Bearer token" in resp.get_json()["error"]


@pytest.mark.unit
class TestContentTypeHandling:
    """Content-Type and request body parsing."""

    def test_grant_type_from_json_body(self, client):
        """grant_type from JSON body should be parsed."""
        resp = client.post(
            "/api/token",
            json={"grant_type": "implicit"}
        )
        
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "unsupported_grant_type"

    def test_grant_type_from_form_body(self, client):
        """grant_type from form body should be parsed."""
        resp = client.post(
            "/api/token",
            data={"grant_type": "implicit"}
        )
        
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "unsupported_grant_type"

    def test_malformed_json_body_ignored(self, client):
        """Malformed JSON should be silently ignored (grant_type defaults to session)."""
        resp = client.post(
            "/api/token",
            data="{invalid json}",
            content_type="application/json"
        )
        
        # Should be treated as session grant (no cookie → 401)
        assert resp.status_code == 401


@pytest.mark.unit
class TestCSRFExemption:
    """CSRF exemption for API endpoints."""

    def test_csrf_exempt_on_token_endpoint(self, client):
        """POST /api/token should be CSRF exempt."""
        resp = client.post("/api/token")
        # Would fail CSRF check if not exempt, but we get 401 (unauthenticated) instead
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "unauthenticated"

    def test_csrf_exempt_on_me_endpoint(self, client):
        """GET /api/token-inspect should be CSRF exempt."""
        resp = client.get("/api/token-inspect")
        # Would fail CSRF check if not exempt, but we get 401 instead
        assert resp.status_code == 401
        assert "Bearer token" in resp.get_json()["error"]

    def test_csrf_exempt_on_health_endpoint(self, client):
        """GET /api/health should be CSRF exempt."""
        session_factory = MagicMock()
        mock_db = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__enter__.return_value = mock_db
        mock_cm.__exit__.return_value = False
        session_factory.return_value = mock_cm
        
        with patch("src.routes.api.SessionLocal", session_factory):
            resp = client.get("/api/health")
        
        assert resp.status_code == 200
