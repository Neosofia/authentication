"""
Integration tests for /api/token endpoint.

Tests the real Flask route handler and JWT signing against mocked WorkOS SDK responses.
"""

import base64

import jwt as pyjwt
import pytest
from unittest.mock import MagicMock, patch

from src.services.machine_svc import InvalidClientError


BASIC_EMR = "Basic " + base64.b64encode(b"test-service:secret").decode()


@pytest.mark.integration
class TestTokenSessionGrantIntegration:
    """Session grant tests with mocked WorkOS SDK."""

    def test_no_cookie_returns_401(self, client):
        """Missing wos_session cookie should return 401."""
        resp = client.post("/api/token")
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "unauthenticated"

    def test_expired_session_returns_401(self, client, mock_workos_auth):
        """Invalid WorkOS session should return 401."""
        _, patch_ctx = mock_workos_auth(authenticated=False)
        with patch_ctx:
            client.set_cookie("wos_session", "stale")
            resp = client.post("/api/token")
        assert resp.status_code == 401
        assert "invalid or expired" in resp.get_json()["error"]

    def test_valid_session_returns_jwt(self, client, mock_workos_auth):
        """Valid WorkOS session should return 200 with JWT."""
        _, patch_ctx = mock_workos_auth(user_id="usr_test", role="clinician", org_id="org_test")
        with patch_ctx:
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "access_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 900

    def test_jwt_has_correct_claims(self, client, rsa_keys, jwt_issuer, mock_workos_auth):
        """Issued JWT must contain platform claims."""
        _, patch_ctx = mock_workos_auth(user_id="usr_abc", role="clinician", org_id="org_xyz")
        with patch_ctx:
            client.set_cookie("wos_session", "valid")
            token = client.post("/api/token").get_json()["access_token"]
        claims = pyjwt.decode(
            token,
            rsa_keys["public"],
            algorithms=["RS256"],
            issuer=jwt_issuer,
            audience="neosofia-auth-svc",
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
        assert claims["sub"] == "usr_abc"
        assert claims["iss"] == jwt_issuer
        assert claims["aud"] == "neosofia-auth-svc"
        assert claims["neosofia:token_type"] == "human"
        assert claims["neosofia:roles"] == ["clinician"]
        assert claims["neosofia:tenant_id"] == "org_xyz"
        assert "jti" in claims
        assert "exp" in claims

    def test_no_org_membership_returns_500(self, client, mock_workos_auth):
        """Users with no org membership must be rejected at token issuance."""
        _, patch_ctx = mock_workos_auth(user_id="usr_no_org", role=None, org_id=None)
        with patch_ctx:
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token")
        assert resp.status_code == 500

    def test_workos_timeout_returns_503(self, client):
        """WorkOS timeout should return 503."""
        mock_wos = MagicMock()
        mock_wos.user_management.load_sealed_session.side_effect = TimeoutError("connection timeout")
        with patch("src.routes.api.workos_client", mock_wos):
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token")
        assert resp.status_code == 503
        assert "unavailable" in resp.get_json()["error"]

    def test_workos_connection_error_returns_503(self, client):
        """WorkOS connection error should return 503."""
        mock_wos = MagicMock()
        mock_wos.user_management.load_sealed_session.side_effect = ConnectionError("connection refused")
        with patch("src.routes.api.workos_client", mock_wos):
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token")
        assert resp.status_code == 503
        assert "unavailable" in resp.get_json()["error"]


@pytest.mark.integration
class TestHealthEndpoint:
    """Health check endpoint tests."""

    def test_health_ok(self, client, mock_session):
        """Health endpoint should return 200 when healthy."""
        session_factory, _ = mock_session
        with patch("src.routes.api.SessionLocal", session_factory):
            resp = client.get("/api/health")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"

    def test_health_db_timeout(self, client, mock_session):
        """Health endpoint should return 503 on database timeout."""
        session_factory, mock_db = mock_session
        mock_db.execute.side_effect = TimeoutError("database timeout")
        with patch("src.routes.api.SessionLocal", session_factory):
            resp = client.get("/api/health")
        assert resp.status_code == 503
        assert resp.get_json()["status"] == "error"
        assert "timeout" in resp.get_json()["detail"]

    def test_health_db_error(self, client, mock_session):
        """Health endpoint should return 503 on database error."""
        session_factory, mock_db = mock_session
        mock_db.execute.side_effect = Exception("database connection refused")
        with patch("src.routes.api.SessionLocal", session_factory):
            resp = client.get("/api/health")
        assert resp.status_code == 503
        assert resp.get_json()["status"] == "error"
        assert "unavailable" in resp.get_json()["detail"]


@pytest.mark.integration
class TestMeEndpoint:
    """JWT validation endpoint tests."""

    def test_me_requires_bearer_token(self, client):
        """Missing Bearer token should return 401."""
        resp = client.get("/api/me")
        assert resp.status_code == 401
        assert "Bearer token" in resp.get_json()["error"]

    def test_me_rejects_invalid_bearer_format(self, client):
        """Invalid Authorization header should return 401."""
        resp = client.get("/api/me", headers={"Authorization": "Basic abc123"})
        assert resp.status_code == 401
        assert "Bearer token" in resp.get_json()["error"]

    def test_me_accepts_valid_jwt(self, client, mock_workos_auth):
        """Valid JWT should return decoded claims."""
        _, patch_ctx = mock_workos_auth(user_id="usr_test", role="clinician", org_id="org_test")
        with patch_ctx:
            client.set_cookie("wos_session", "valid")
            token = client.post("/api/token").get_json()["access_token"]
        resp = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        claims = resp.get_json()
        assert claims["sub"] == "usr_test"
        assert claims["neosofia:token_type"] == "human"

    def test_me_rejects_expired_jwt(self, client, rsa_keys, jwt_issuer):
        """Expired JWT should return 401."""
        import time
        expired_claims = {
            "sub": "usr_test",
            "iss": jwt_issuer,
            "aud": "neosofia-auth-svc",
            "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,
        }
        expired_token = pyjwt.encode(expired_claims, rsa_keys["private"], algorithm="RS256")
        resp = client.get("/api/me", headers={"Authorization": f"Bearer {expired_token}"})
        assert resp.status_code == 401
        assert "expired" in resp.get_json()["error"]

    def test_me_rejects_invalid_jwt(self, client):
        """Malformed JWT should return 401."""
        resp = client.get("/api/me", headers={"Authorization": "Bearer not.a.jwt"})
        assert resp.status_code == 401
        assert "invalid token" in resp.get_json()["error"]

    def test_me_rejects_jwt_signed_with_wrong_key(self, client, jwt_issuer):
        """JWT signed with wrong key should return 401."""
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        from cryptography.hazmat.primitives import serialization as _ser
        import time

        wrong_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
        wrong_pem = wrong_key.private_bytes(
            _ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption()
        ).decode()
        token = pyjwt.encode(
            {"sub": "usr_test", "iss": jwt_issuer, "aud": "neosofia-auth-svc",
             "iat": int(time.time()), "exp": int(time.time()) + 3600},
            wrong_pem, algorithm="RS256",
        )
        resp = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401
        assert "invalid signature" in resp.get_json()["error"]


@pytest.mark.integration
class TestClientCredentialsGrant:
    """Machine-to-machine authentication via client_credentials grant."""

    def test_client_credentials_unsupported_without_db(self, client):
        """Client credentials should return 503 if database not configured."""
        with patch("src.routes.api.settings.database_url", None):
            resp = client.post(
                "/api/token",
                data={"grant_type": "client_credentials", "client_id": "test", "client_secret": "test"}
            )
        assert resp.status_code == 503
        assert "database not configured" in resp.get_json()["error"]

    def test_client_credentials_basic_auth_valid(self, client, mock_session):
        """Valid Basic auth should issue machine token."""
        session_factory, _ = mock_session
        with patch("src.routes.api.issue_machine_token", return_value="machine_token_xyz"), \
             patch("src.routes.api.SessionLocal", session_factory):
            resp = client.post(
                "/api/token",
                headers={"Authorization": BASIC_EMR},
                data={"grant_type": "client_credentials"},
            )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["access_token"] == "machine_token_xyz"
        assert data["token_type"] == "Bearer"

    def test_client_credentials_form_body(self, client, mock_session):
        """Form body client_id/client_secret should be accepted."""
        session_factory, _ = mock_session
        with patch("src.routes.api.issue_machine_token", return_value="machine_token_xyz"), \
             patch("src.routes.api.SessionLocal", session_factory):
            resp = client.post(
                "/api/token",
                data={"grant_type": "client_credentials", "client_id": "test-service", "client_secret": "secret"},
            )
        assert resp.status_code == 200
        assert resp.get_json()["access_token"] == "machine_token_xyz"

    def test_client_credentials_invalid_basic_auth(self, client):
        """Malformed Basic auth should return 401."""
        resp = client.post(
            "/api/token",
            headers={"Authorization": "Basic not-valid-base64!!!"},
            data={"grant_type": "client_credentials"},
        )
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_client"

    def test_client_credentials_missing_credentials(self, client):
        """Missing client credentials should return 401."""
        resp = client.post("/api/token", data={"grant_type": "client_credentials"})
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_client"

    def test_client_credentials_invalid_credentials(self, client, mock_session):
        """Invalid client credentials should return 401."""
        session_factory, _ = mock_session
        with patch("src.routes.api.issue_machine_token", side_effect=InvalidClientError("unknown client")), \
             patch("src.routes.api.SessionLocal", session_factory):
            resp = client.post(
                "/api/token",
                headers={"Authorization": BASIC_EMR},
                data={"grant_type": "client_credentials"},
            )
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_client"


@pytest.mark.integration
class TestTokenGrantTypeValidation:
    """Grant type validation tests."""

    def test_unsupported_grant_type_returns_400(self, client):
        """Unsupported grant_type should return 400."""
        resp = client.post("/api/token", json={"grant_type": "implicit"})
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "unsupported_grant_type"

    def test_session_grant_type_explicit(self, client, mock_workos_auth):
        """Explicit grant_type=session should work."""
        _, patch_ctx = mock_workos_auth(user_id="usr_test", role="clinician", org_id="org_test")
        with patch_ctx:
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token", json={"grant_type": "session"})
        assert resp.status_code == 200
        assert "access_token" in resp.get_json()

