import bcrypt
import base64
import jwt
import uuid
from unittest.mock import patch, MagicMock
from src.config import settings
from src.models.service_credential import ServiceCredential


def test_token_unauthorized(client, api_spec, validate_response):
    response = client.post("/api/token", data={})
    assert response.status_code in [400, 401]
    validate_response(api_spec, "/api/token", "post", response.status_code, response.json)

def test_token_inspect_unauthorized(client, api_spec, validate_response):
    response = client.get("/api/token-inspect")
    assert response.status_code == 401
    validate_response(api_spec, "/api/token-inspect", "get", 401, response.json)

def test_token_client_credentials_happy_path(client, api_spec, validate_response):
    client_id = "test_client_id"
    client_secret = "test_secret"
    hashed = bcrypt.hashpw(client_secret.encode(), bcrypt.gensalt()).decode()
    
    from src.models.service import Service

    service = Service(
        uuid=uuid.uuid7(),
        name="Test Service",
        slug="test-service",
        base_url="https://test-service.local",
    )
    mock_cred = ServiceCredential(
        service_uuid=service.uuid,
        hashed_secret=hashed,
        service=service,
    )
    
    with patch("src.routes.token.SessionLocal") as mock_db:
        mock_session = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_session
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_cred
        
        credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        
        response = client.post("/api/token", data={"grant_type": "client_credentials", "audience": "test-service"}, headers={
            "Authorization": f"Basic {credentials}"
        })
        
        assert response.status_code == 200
        validate_response(api_spec, "/api/token", "post", 200, response.json)

        token = response.json["access_token"]
        decoded = jwt.decode(
            token,
            settings.jwt_public_key_pem,
            algorithms=["RS256"],
            issuer=settings.jwt_issuer,
            audience="test-service",
        )
        assert decoded["aud"] == "test-service"


def test_token_session_grant_happy_path(client, api_spec, validate_response):
    auth_response = MagicMock()
    auth_response.authenticated = True
    auth_response.user = {"id": "user_123"}
    auth_response.role = "admin"
    auth_response.organization_id = "tenant_456"
    auth_response.access_token = "workos-access-token"
    auth_response.refresh_token = "workos-refresh-token"
    auth_response.impersonator = None
    auth_response.sealed_session = "dummy-sealed-session"

    session = MagicMock()
    session.authenticate.return_value = auth_response

    with patch("src.services.workos_bridge.settings.valid_roles", "admin,user"), patch("src.routes.token.workos_client") as mock_workos:
        mock_workos.user_management.load_sealed_session.return_value = session

        client.set_cookie("wos_session", "dummy-session")
        response = client.post("/api/token", data={})

        assert response.status_code == 200
        validate_response(api_spec, "/api/token", "post", 200, response.json)


def test_token_inspect_happy_path(client, api_spec, validate_response, app):
    with app.app_context():
        from src.services.tokens import issue_token
        from src.config import settings
        service_token = issue_token(
            sub="test_service",
            token_type="service",
            roles=[],
            tenant_id=None,
            ttl_secs=3600,
            private_key_pem=settings.jwt_private_key_pem,
            issuer=settings.jwt_issuer,
            audience="test-service",
            public_key_pem=settings.jwt_public_key_pem,
        )

    response = client.get("/api/token-inspect", headers={
        "Authorization": f"Bearer {service_token}"
    })
    
    assert response.status_code == 200
    validate_response(api_spec, "/api/token-inspect", "get", 200, response.json)