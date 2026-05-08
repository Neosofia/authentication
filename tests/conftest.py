import base64
import json
import os
import pytest
from pathlib import Path
from jsonschema import validate
from jsonschema.validators import _RefResolver
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

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

# Set required environment variables before importing app
os.environ["CSRF_SECRET_KEY"] = "test-csrf-secret"
os.environ["WORKOS_COOKIE_PASSWORD"] = "test-cookie-password-must-be-min-32-chars-long"
os.environ["ENV"] = "test"
os.environ["JWT_PRIVATE_KEY_PEM"] = base64.b64encode(TEST_PRIVATE_KEY_PEM.encode("utf-8")).decode("utf-8")
os.environ["JWT_PUBLIC_KEY_PEM"] = base64.b64encode(TEST_PUBLIC_KEY_PEM.encode("utf-8")).decode("utf-8")
os.environ["JWT_ISSUER"] = "http://testserver"
os.environ["VALID_ROLES"] = "admin,user"

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
