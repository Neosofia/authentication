"""
Contract tests for Authentication Service API.

Validates responses against published JSON schemas from specs/contracts/.
Each test loads a response and validates it against the corresponding schema.
"""

import json
import pathlib
import pytest
import jwt as pyjwt
import jsonschema
from unittest.mock import MagicMock, patch


import os

# Load shared log schema from centralized schemas repo (Neosofia/schemas)
# Set SCHEMAS_DIR to the local checkout of https://github.com/Neosofia/schemas
_SCHEMAS_DIR = pathlib.Path(os.environ["SCHEMAS_DIR"])
LOG_SCHEMA_FILE = _SCHEMAS_DIR / "log-v1.0.0.json"


def _get_log_schema():
    """Load the log JSON Schema from the monorepo schemas directory."""
    if not LOG_SCHEMA_FILE.exists():
        raise FileNotFoundError(f"Log schema not found at {LOG_SCHEMA_FILE}")
    
    with open(LOG_SCHEMA_FILE) as f:
        return json.load(f)


@pytest.mark.contract
class TestTokenResponseContract:
    """Tests for POST /api/token response contract."""

    def test_session_grant_response_conforms_to_schema(self, client, mock_workos_auth, schemas):
        """Session grant token response must conform to OpenAPI TokenResponse schema."""
        mock_wos, patch_context = mock_workos_auth(user_id="usr_test", role="clinician", org_id="org_test")
        
        with patch_context:
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token")
        
        assert resp.status_code == 200
        data = resp.get_json()
        
        # Validate against OpenAPI schema
        jsonschema.validate(data, schemas["TokenResponse"])
        
        # Sanity: token should be non-empty
        assert len(data["access_token"]) > 50

    def test_jwt_claims_conform_to_contract_schema(self, client, rsa_keys, mock_workos_auth, schemas, jwt_issuer):
        """Decoded JWT claims must conform to OpenAPI PlatformJWTClaims schema."""
        mock_wos, patch_context = mock_workos_auth(user_id="usr_123", role="clinician", org_id="org_456")
        
        with patch_context:
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token")
        
        assert resp.status_code == 200
        token = resp.get_json()["access_token"]
        claims = pyjwt.decode(
            token, 
            rsa_keys["public"], 
            algorithms=["RS256"],
            issuer=jwt_issuer,
            audience="neosofia-auth-svc",
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
        
        # Validate claims against OpenAPI schema
        jsonschema.validate(claims, schemas["PlatformJWTClaims"])
        
        # Verify role-specific claims
        assert claims["neosofia:user_type"] == "clinician"
        assert "neosofia:tenant_id" in claims

    def test_patient_token_claims_conform_to_contract(self, client, rsa_keys, mock_workos_auth, schemas, jwt_issuer):
        """Patient token claims must not include tenant_id."""
        mock_wos, patch_context = mock_workos_auth(user_id="usr_patient", role=None, org_id=None)
        
        with patch_context:
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token")
        
        token = resp.get_json()["access_token"]
        claims = pyjwt.decode(
            token,
            rsa_keys["public"],
            algorithms=["RS256"],
            issuer=jwt_issuer,
            audience="neosofia-auth-svc",
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
        
        jsonschema.validate(claims, schemas["PlatformJWTClaims"])
        
        assert claims["neosofia:user_type"] == "patient"
        assert "neosofia:tenant_id" not in claims


@pytest.mark.contract
class TestErrorResponseContract:
    """Tests for error response contract."""

    def test_401_error_conforms_to_schema(self, client, schemas):
        """401 error responses must conform to OpenAPI ErrorResponse schema."""
        resp = client.post("/api/token")
        assert resp.status_code == 401
        
        jsonschema.validate(resp.get_json(), schemas["ErrorResponse"])

    def test_503_error_conforms_to_schema(self, client, schemas):
        """503 error responses must conform to OpenAPI ErrorResponse schema."""
        mock_wos = MagicMock()
        mock_wos.user_management.load_sealed_session.side_effect = ConnectionError("connection failed")
        
        with patch("src.routes.api.workos_client", mock_wos):
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token")
        
        assert resp.status_code == 503
        jsonschema.validate(resp.get_json(), schemas["ErrorResponse"])


@pytest.mark.contract
class TestMeEndpointContract:
    """Tests for GET /api/me response contract."""

    def test_me_response_echoes_jwt_claims(self, client, make_jwt, schemas):
        """GET /api/me response must echo decoded JWT claims conforming to schema."""
        token = make_jwt(sub="usr_123", user_type="clinician", tenant_id="org_456")
        resp = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
        
        assert resp.status_code == 200
        data = resp.get_json()
        
        # Response should conform to PlatformJWTClaims schema (it echoes claims back)
        jsonschema.validate(data, schemas["PlatformJWTClaims"])
        
        # Verify echoed values
        assert data["sub"] == "usr_123"
        assert data["neosofia:user_type"] == "clinician"
        assert data["neosofia:tenant_id"] == "org_456"

    def test_me_401_without_token(self, client, schemas):
        """GET /api/me without token must return 401 conforming to error schema."""
        resp = client.get("/api/me")
        assert resp.status_code == 401
        jsonschema.validate(resp.get_json(), schemas["ErrorResponse"])

    def test_me_401_expired_token(self, client, make_jwt, schemas):
        """GET /api/me with expired token must return 401 conforming to error schema."""
        token = make_jwt(exp_offset=-1)
        resp = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401
        jsonschema.validate(resp.get_json(), schemas["ErrorResponse"])


@pytest.mark.contract
class TestLoggingContract:
    """Tests for log structure (Constitution §I, §X)."""

    def test_logs_are_valid_json(self, client, mock_workos_auth, log_capture):
        """All logs must be valid JSON format."""
        mock_wos, patch_context = mock_workos_auth(user_id="usr_123", role="clinician", org_id="org_456")
        
        with patch_context:
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token")
        
        assert resp.status_code == 200
        assert len(log_capture) > 0, "Expected at least one log entry"
        
        # All log_capture entries are already parsed JSON dicts (handled by fixture)
        # This test verifies they all parse correctly
        for i, log in enumerate(log_capture):
            assert isinstance(log, dict), f"Log {i} must be a dict, got {type(log)}"
            assert "timestamp" in log, f"Log {i} missing 'timestamp' field"
            assert "level" in log, f"Log {i} missing 'level' field"

    def test_logs_conform_to_log_schema(self, client, mock_workos_auth, log_capture):
        """All logs must conform to the Neosofia log JSON schema."""
        mock_wos, patch_context = mock_workos_auth(user_id="usr_123", role="clinician", org_id="org_456")
        
        with patch_context:
            client.set_cookie("wos_session", "valid")
            resp = client.post("/api/token")
        
        assert resp.status_code == 200
        assert len(log_capture) > 0, "Expected at least one log entry"
        
        # Load shared log schema
        log_schema = _get_log_schema()
        
        # Validate each log against schema
        for log in log_capture:
            jsonschema.validate(log, log_schema)
