"""
Shared fixtures for the authentication service test suite.

Environment variables are set at module level so they are in place before any
src.* module is imported by pytest during collection.
"""

import os
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from testcontainers.postgres import PostgresContainer

# Must be set before any src.* import so extensions.py and main.py can init.
os.environ.setdefault("CSRF_SECRET_KEY", "test-csrf-secret-key-32-chars-ok!")
os.environ.setdefault("WORKOS_COOKIE_PASSWORD", "test-cookie-password-32-chars-ok!")
os.environ.setdefault("WORKOS_API_KEY", "sk_test_PLACEHOLDER_0000000000000000")
os.environ.setdefault("WORKOS_CLIENT_ID", "client_test_PLACEHOLDER_0000000000")
os.environ.setdefault("JWT_PRIVATE_KEY_PEM", "placeholder")
os.environ.setdefault("JWT_PUBLIC_KEY_PEM", "placeholder")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost/test_db")
os.environ.setdefault("ENV", "test")


@pytest.fixture(scope="session")
def rsa_keys():
    """Generate a throwaway RSA 2048 keypair shared across the whole test session."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return {"private": private_pem, "public": public_pem}


@pytest.fixture(scope="session")
def postgres_container():
    """Spin up a real PostgreSQL container for integration tests."""
    container = PostgresContainer(image="postgres:16-alpine", user="test", password="test", dbname="test_db")
    with container as postgres:
        yield postgres


@pytest.fixture(scope="session")
def app(rsa_keys):
    """Create the Flask application once for the entire test session with real keys."""
    # Set real keys before importing any src.* modules
    os.environ["JWT_PRIVATE_KEY_PEM"] = rsa_keys["private"]
    os.environ["JWT_PUBLIC_KEY_PEM"] = rsa_keys["public"]
    os.environ["JWT_ISSUER"] = "https://auth.test.local"
    
    # Reload the settings module to pick up the new environment variables
    import importlib
    import src.config
    importlib.reload(src.config)
    
    from src.main import create_app

    flask_app = create_app(config={
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,    # disable CSRF in tests
        "RATELIMIT_ENABLED": False,   # disable rate limiting in tests
    })
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def jwt_issuer():
    """Return the configured JWT issuer value from settings."""
    from src.config import settings
    return settings.jwt_issuer


@pytest.fixture
def make_jwt(rsa_keys, jwt_issuer):
    """
    Returns a factory that creates signed platform JWTs using the test keypair.
    Keyword args mirror the platform JWT claim set.
    """
    from src.config import settings
    ns = settings.jwt_claim_namespace

    def _factory(
        *,
        sub: str = "usr_test",
        user_type: str = "clinician",
        roles: list[str] | None = None,
        tenant_id: str | None = "org_test",
        exp_offset: int = 900,
    ) -> str:
        now = int(datetime.now(timezone.utc).timestamp())
        claims: dict = {
            "sub": sub,
            "iss": jwt_issuer,
            "aud": "neosofia-auth-svc",
            "iat": now,
            "exp": now + exp_offset,
            "jti": str(uuid.uuid4()),
            f"{ns}:user_type": user_type,
            f"{ns}:roles": roles if roles is not None else [user_type],
        }
        if tenant_id:
            claims[f"{ns}:tenant_id"] = tenant_id
        return pyjwt.encode(claims, rsa_keys["private"], algorithm="RS256")

    return _factory


@pytest.fixture
def log_capture():
    """
    Capture all log records emitted during a test.
    
    Returns a list of parsed JSON log entries.
    Each entry is a dict with: timestamp, level, message, event_type (if present), ...extra fields.
    
    Usage:
        def test_something(client, log_capture):
            resp = client.get("/login")
            assert len(log_capture) > 0
            log = log_capture[0]
            assert log["event_type"] == "login_initiated"
            assert "timestamp" in log
            assert "level" in log
    """
    import json
    import logging
    
    logs = []
    
    class ListHandler(logging.Handler):
        def emit(self, record):
            try:
                # Format the record using the same JSONFormatter
                from src.logging_config import JSONFormatter
                formatter = JSONFormatter()
                message = formatter.format(record)
                logs.append(json.loads(message))
            except Exception:
                # If parsing fails, store the raw record for debugging
                logs.append({"error": "failed to parse log", "raw": str(record)})
    
    handler = ListHandler()
    logger = logging.getLogger("auth")
    logger.addHandler(handler)
    
    yield logs
    
    logger.removeHandler(handler)


@pytest.fixture
def mock_workos_auth():
    """
    Factory fixture that creates a mocked WorkOS session for contract and integration tests.
    
    Returns: (mock_wos, patch_context) tuple
    
    Usage:
        def test_something(client, mock_workos_auth):
            mock_wos, patch_context = mock_workos_auth(user_id="usr_123", role="clinician", org_id="org_456")
            with patch_context:
                resp = client.post("/api/token")
    """
    def _factory(user_id="usr_test", role=None, org_id=None, authenticated=True):
        mock_user = MagicMock()
        mock_user.id = user_id
        
        mock_auth = MagicMock()
        mock_auth.authenticated = authenticated
        mock_auth.user = mock_user
        mock_auth.role = role
        mock_auth.organization_id = org_id
        
        mock_session = MagicMock()
        mock_session.authenticate.return_value = mock_auth
        
        mock_wos = MagicMock()
        mock_wos.user_management.load_sealed_session.return_value = mock_session
        
        from unittest.mock import patch
        return mock_wos, patch("src.routes.api.workos_client", mock_wos)
    
    return _factory


@pytest.fixture
def schemas():
    """
    Load API response schemas from OpenAPI specification.
    
    Extracts schema definitions from the service's OpenAPI 3.0 spec
    (openapi.json) and returns them as a dict keyed by schema name.
    
    Returns dict mapping schema name to parsed JSON schema.
    
    Usage:
        def test_response(client, schemas):
            resp = client.post("/api/token")
            jsonschema.validate(resp.get_json(), schemas["TokenResponse"])
    """
    import json
    import pathlib
    
    # Load openapi.json from service root
    openapi_file = pathlib.Path(__file__).parent.parent / "openapi.json"
    
    if not openapi_file.exists():
        pytest.fail(f"OpenAPI spec not found at {openapi_file}")
    
    with open(openapi_file) as f:
        openapi_spec = json.load(f)
    
    # Extract schemas from components/schemas
    return openapi_spec.get("components", {}).get("schemas", {})


# ── Fixture decorators for test categorization ────────────────────────────────

def pytest_configure(config):
    """Register custom markers for test pyramid levels."""
    config.addinivalue_line("markers", "unit: mark test as a unit test")
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "contract: mark test as a contract test")