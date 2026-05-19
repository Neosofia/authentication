import uuid
from unittest.mock import patch

from src.config import settings
from src.services.service_management import ConflictError, InvalidAuditSourceError, NotFoundError, CredentialNotFoundError
from src.services.tokens import issue_token


def _get_token(app, roles):
    with app.app_context():
        return issue_token(
            sub="12345678-1234-5678-1234-567812345678",
            token_type="human",
            roles=roles,
            tenant_uuid="019e02e1-94e1-722b-bd61-f7f95fb1601f",
            ttl_secs=3600,
            private_key_pem=settings.jwt_private_key_pem,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_web_audience,
            public_key_pem=settings.jwt_public_key_pem,
        )


def test_services_create_conflict_returns_409(client, app):
    token = _get_token(app, ["admin"])

    with patch("src.routes.services.SessionLocal"), \
         patch("src.routes.services.service_management.create_service", side_effect=ConflictError("service name or slug or base_url already exists")):
        response = client.post(
            "/api/services",
            json={"name": "New Service", "slug": "existing-service", "base_url": "http://test"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 409
    assert response.json["error"] == "service name or slug or base_url already exists"


def test_services_update_conflict_returns_409(client, app):
    token = _get_token(app, ["admin"])

    with patch("src.routes.services.SessionLocal"), \
         patch("src.routes.services.service_management.update_service", side_effect=ConflictError("name, slug, or base_url already in use")):
        response = client.put(
            "/api/services/existing-service",
            json={"name": "Updated Service", "slug": "existing-service", "base_url": "http://test"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 409
    assert response.json["error"] == "name, slug, or base_url already in use"


def test_services_create_missing_fields_returns_400(client, app):
    token = _get_token(app, ["admin"])

    with patch("src.routes.services.SessionLocal"):
        response = client.post(
            "/api/services",
            json={"name": "New Service", "slug": "new-service"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400
    assert response.json["error"] == "missing required fields (name, slug, base_url)"


def test_services_update_no_fields_returns_400(client, app):
    token = _get_token(app, ["admin"])

    with patch("src.routes.services.SessionLocal"):
        response = client.put(
            "/api/services/existing-service",
            json={"not_a_field": "value"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400
    assert response.json["error"] == "no updatable fields provided"


def test_services_create_invalid_json_returns_400(client, app):
    token = _get_token(app, ["admin"])

    with patch("src.routes.services.SessionLocal"):
        response = client.post(
            "/api/services",
            data="not-json",
            content_type="application/json",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400


def test_services_update_invalid_json_returns_400(client, app):
    token = _get_token(app, ["admin"])

    with patch("src.routes.services.SessionLocal"):
        response = client.put(
            "/api/services/existing-service",
            data="not-json",
            content_type="application/json",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400


@patch("authentication_in_the_middle.decorators.pyjwt.decode")
def test_services_require_admin_without_admin_role_returns_403(mock_decode, client):
    mock_decode.return_value = {
        "sub": "019e02e1-94e1-722b-bd61-f7f95fb1602a",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_web_audience,
        "neosofia:roles": ["user"],
        "sub": "12345678-1234-5678-1234-567812345678",
    }

    with patch("src.routes.services.SessionLocal"):
        response = client.get(
            "/api/services",
            headers={"Authorization": "Bearer 123"},
        )

    assert response.status_code == 403
    assert response.json["error"] == "forbidden"
    assert response.json["message"] == "requires admin role"


@patch("authentication_in_the_middle.decorators.pyjwt.decode")
def test_services_require_admin_missing_user_uuid_returns_401(mock_decode, client):
    mock_decode.return_value = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_web_audience,
        "neosofia:roles": ["admin"],
    }

    with patch("src.routes.services.SessionLocal"):
        response = client.get(
            "/api/services",
            headers={"Authorization": "Bearer 123"},
        )

    assert response.status_code == 401
    assert response.json["error"] == "unauthenticated"
    assert response.json["message"] == "re-authenticate to obtain a platform identity"


@patch("authentication_in_the_middle.decorators.pyjwt.decode")
def test_services_require_admin_invalid_user_uuid_returns_401(mock_decode, client):
    mock_decode.return_value = {
        "sub": "019e02e1-94e1-722b-bd61-f7f95fb1602a",
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_web_audience,
        "neosofia:roles": ["admin"],
        "sub": "not-a-uuid",
    }

    with patch("src.routes.services.SessionLocal"):
        response = client.get(
            "/api/services",
            headers={"Authorization": "Bearer 123"},
        )

    assert response.status_code == 401
    assert response.json["error"] == "unauthenticated"
    assert response.json["message"] == "re-authenticate to obtain a platform identity"


def test_services_get_not_found_returns_404(client, app):
    token = _get_token(app, ["admin"])

    with patch("src.routes.services.SessionLocal"), \
         patch("src.routes.services.service_management.rotate_service", side_effect=CredentialNotFoundError("service credential not found")):
        response = client.post(
            "/api/services/existing-service/rotate",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 404
    assert response.json["error"] == "no credential"


def test_services_get_audits_not_found_returns_404(client, app):
    token = _get_token(app, ["admin"])

    with patch("src.routes.services.SessionLocal"), \
         patch("src.routes.services.service_management.get_service", side_effect=NotFoundError("service not found")):
        response = client.get(
            "/api/services/missing-service/audits?source=service",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 404
    assert response.json["error"] == "not found"


def test_services_get_audits_invalid_source_returns_400(client, app):
    token = _get_token(app, ["admin"])

    with patch("src.routes.services.SessionLocal"), \
         patch("src.routes.services.service_management.get_service", return_value={
             "uuid": str(uuid.uuid7()),
             "slug": "test-service",
         }), \
         patch("src.routes.services.service_management.get_service_audits", side_effect=InvalidAuditSourceError("source must be 'service' or 'credential'")):
        response = client.get(
            "/api/services/test-service/audits?source=invalid",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400
    assert response.json["error"] == "invalid source"
    assert response.json["message"] == "source must be 'service' or 'credential'"
