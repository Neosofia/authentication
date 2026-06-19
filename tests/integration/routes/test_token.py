import bcrypt
import base64
import jwt
import uuid
from unittest.mock import patch, MagicMock
from src.config import settings
from src.models.service_credential import ServiceCredential
from src.services.idp import get_idp
from src.services.idp.workos import reset_workos_client
from tests.conftest import encode_test_access_token


def _clear_idp_cache():
    get_idp.cache_clear()
    reset_workos_client()


def _workos_auth_response():
    user = MagicMock(id="user_123", external_id="12345678-1234-5678-1234-567812345678")
    user.to_dict.return_value = {
        "id": "user_123",
        "external_id": "12345678-1234-5678-1234-567812345678",
    }

    response = MagicMock(authenticated=True, session_id="session_123")
    response.user = user
    response.access_token = encode_test_access_token(
        {
            "workos_tenant_id": "org_123",
            "workos_tenant_name": "Test Org",
            "tenant_uuid": "019e02e1-94e1-722b-bd61-f7f95fb1601f",
            "roles": ["operator"],
        }
    )
    response.sealed_session = "dummy-sealed-session"
    return response


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
        mock_result_cred = MagicMock()
        mock_result_cred.one_or_none.return_value = (mock_cred, service)
        mock_result_target = MagicMock()
        mock_result_target.scalar_one_or_none.return_value = service
        mock_session.execute.side_effect = [mock_result_cred, mock_result_target]

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
            audience="test-service",
        )
        assert decoded["aud"] == "test-service"
        assert decoded["sub"] == client_id
        assert decoded["azp"] == client_id
        assert decoded[f"{settings.jwt_claim_namespace}:service_uuid"] == str(service.uuid)


def test_token_client_credentials_rejects_invalid_secret(client, api_spec, validate_response):
    client_id = "test_client_id"
    actual_secret = "test_secret"
    hashed = bcrypt.hashpw(actual_secret.encode(), bcrypt.gensalt()).decode()

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
        mock_result_cred = MagicMock()
        mock_result_cred.one_or_none.return_value = (mock_cred, service)
        mock_result_target = MagicMock()
        mock_result_target.scalar_one_or_none.return_value = service
        mock_session.execute.side_effect = [mock_result_cred, mock_result_target]

        wrong_secret = "bad_secret"
        credentials = base64.b64encode(f"{client_id}:{wrong_secret}".encode()).decode()

        response = client.post("/api/token", data={"grant_type": "client_credentials", "audience": "test-service"}, headers={
            "Authorization": f"Basic {credentials}"
        })

    assert response.status_code == 401
    validate_response(api_spec, "/api/token", "post", 401, response.json)


def test_token_session_grant_happy_path(client, api_spec, validate_response):
    _clear_idp_cache()
    mock_db = MagicMock()
    mock_db.get.return_value = None
    with (
        patch("src.services.idp.workos.WorkOSClient") as mock_workos_client,
        patch("src.services.idp.workos.unseal_data") as mock_unseal_data,
        patch("src.routes.token.SessionLocal") as mock_session_local,
    ):
        mock_session_local.return_value.__enter__.return_value = mock_db
        auth_response = _workos_auth_response()
        sealed_session = mock_workos_client.return_value.user_management.load_sealed_session.return_value
        sealed_session.authenticate.return_value = auth_response
        mock_unseal_data.return_value = {"access_token": auth_response.access_token}
        client.set_cookie("wos_session", "dummy-session")
        response = client.post("/api/token", data={})
    _clear_idp_cache()

    assert response.status_code == 200
    cookie_headers = response.headers.getlist("Set-Cookie")
    assert any("wos_session=dummy-sealed-session" in header for header in cookie_headers)
    assert any("SameSite=None" in header for header in cookie_headers)
    assert any("Secure" in header for header in cookie_headers)
    validate_response(api_spec, "/api/token", "post", 200, response.json)


def test_token_inspect_happy_path(client, api_spec, validate_response, app):
    with app.app_context():
        from src.services.tokens import issue_token
        from src.config import settings
        service_token = issue_token(
            sub="test_service",
            token_type="service",
            actors=None,
            tenant_uuid=None,
            ttl_secs=3600,
            private_key_pem=settings.jwt_private_key_pem,
            audience="test-service",
            public_key_pem=settings.jwt_public_key_pem,
        )

    response = client.get("/api/token-inspect", headers={
        "Authorization": f"Bearer {service_token}"
    })
    
    assert response.status_code == 200
    validate_response(api_spec, "/api/token-inspect", "get", 200, response.json)
    assert "neosofia:roles" not in response.json