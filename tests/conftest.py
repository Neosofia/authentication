import base64
import json
import os
import time

import jwt
import pytest
from pathlib import Path
from jsonschema import validate
from jsonschema.validators import _RefResolver
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from unittest.mock import MagicMock, patch

# Generate a test RSA keypair
test_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
TEST_PRIVATE_KEY_PEM = test_private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode("utf-8")
TEST_PUBLIC_KEY_PEM = test_private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode("utf-8")


def encode_test_access_token(claims: dict) -> str:
    """Encode a mock WorkOS access-token JWT for tests."""
    now = int(time.time())
    payload = {
        "iss": "https://api.workos.com",
        "sub": "user_123",
        "client_id": os.environ["WORKOS_CLIENT_ID"],
        "iat": now,
        "exp": now + 3600,
        **claims,
    }
    return jwt.encode(payload, TEST_PRIVATE_KEY_PEM, algorithm="RS256")


@pytest.fixture(autouse=True)
def _mock_workos_access_token_jwks():
    signing_key = MagicMock()
    signing_key.key = TEST_PUBLIC_KEY_PEM
    jwks_client = MagicMock()
    jwks_client.get_signing_key_from_jwt.return_value = signing_key
    with patch("src.services.idp.workos._workos_jwks_client", return_value=jwks_client):
        yield


# Set required environment variables before importing app
os.environ["CSRF_SECRET_KEY"] = "test-csrf-secret"
os.environ["WORKOS_COOKIE_PASSWORD"] = "test-cookie-password-must-be-min-32-chars-long"
os.environ["ENV"] = "test"
os.environ["JWT_PRIVATE_KEY_PEM"] = base64.b64encode(TEST_PRIVATE_KEY_PEM.encode("utf-8")).decode("utf-8")
os.environ["JWT_PUBLIC_KEY_PEM"] = base64.b64encode(TEST_PUBLIC_KEY_PEM.encode("utf-8")).decode("utf-8")
os.environ["VALID_ACTORS"] = "operator,study,clinician,patient,demo"
os.environ["VALID_TENANT_TYPES"] = "platform,cro,sponsor,site,smo"
os.environ["APP_DATABASE_URL"] = "postgresql+psycopg://app:dummy@localhost/dummy"
os.environ["MIGRATION_DATABASE_URL"] = "postgresql+psycopg://auth:dummy@localhost/dummy"
os.environ["WORKOS_API_KEY"] = "sk_test_dummy_key"
os.environ["WORKOS_CLIENT_ID"] = "client_test_dummy_id"
os.environ["WORKOS_REDIRECT_URI"] = "http://localhost:8014/callback"
os.environ["AUTHENTICATION_CLIENT_SECRET"] = "test-authentication-client-secret"

from src.app import create_app

@pytest.fixture
def api_spec():
    spec_path = Path(__file__).parent.parent / "openapi.json"
    with open(spec_path) as f:
        return json.load(f)

@pytest.fixture
def validate_response():
    def _validate(spec, endpoint, method, status_code, data):
        try:
            schema = spec["paths"][endpoint][method]["responses"][str(status_code)]["content"]["application/json"]["schema"]
        except KeyError:
            return 
        
        resolver = _RefResolver.from_schema(spec)
        validate(instance=data, schema=schema, resolver=resolver)
    return _validate

@pytest.fixture
def app():
    app = create_app()
    app.config["TESTING"] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()
