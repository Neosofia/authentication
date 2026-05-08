import bcrypt
import base64
from unittest.mock import patch, MagicMock
from src.models.machine_credential import MachineCredential


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
    
    mock_cred = MachineCredential(
        service_name=client_id,
        hashed_secret=hashed,
        active=True,
    )
    
    with patch("src.routes.token.SessionLocal") as mock_db:
        mock_session = MagicMock()
        mock_db.return_value.__enter__.return_value = mock_session
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_cred
        
        credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        
        response = client.post("/api/token", data={"grant_type": "client_credentials"}, headers={
            "Authorization": f"Basic {credentials}"
        })
        
        assert response.status_code == 200
        validate_response(api_spec, "/api/token", "post", 200, response.json)


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
        from src.services.token_issuer import issue_token
        from src.config import settings
        machine_token = issue_token(
            sub="test_service",
            token_type="machine",
            roles=[],
            tenant_id=None,
            ttl_secs=3600,
            private_key_pem=settings.jwt_private_key_pem,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            public_key_pem=settings.jwt_public_key_pem,
        )

    response = client.get("/api/token-inspect", headers={
        "Authorization": f"Bearer {machine_token}"
    })
    
    assert response.status_code == 200
    validate_response(api_spec, "/api/token-inspect", "get", 200, response.json)