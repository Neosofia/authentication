import uuid
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from sqlalchemy.exc import IntegrityError

from src.config import settings
from src.models.service import Service
from src.models.service_credential import ServiceCredential


def _get_token(app, roles):
    with app.app_context():
        from src.services.tokens import issue_token
        return issue_token(
            sub="12345678-1234-5678-1234-567812345678",
            token_type="human",
            roles=roles,
            tenant_id="tenant_456",
            ttl_secs=3600,
            private_key_pem=settings.jwt_private_key_pem,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_web_audience,
            public_key_pem=settings.jwt_public_key_pem,
        )


def test_services_unauthorized(client):
    response = client.get("/api/services")
    assert response.status_code == 401


def test_services_forbidden(client, app):
    token = _get_token(app, ["user"])
    response = client.get("/api/services", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_services_list_success(client, app):
    token = _get_token(app, ["admin"])
    service = Service(
        uuid=uuid.uuid7(),
        name="Test Service",
        slug="test-service",
        base_url="http://test-service",
    )
    credential = ServiceCredential(
        uuid=uuid.uuid7(),
        service_uuid=service.uuid,
        hashed_secret="secret",
        service=service,
    )

    mock_db = MagicMock()
    mock_db.__enter__.return_value = mock_db
    mock_db.scalar.return_value = 1
    mock_db.execute.return_value.all.return_value = [(service, credential)]

    with patch("src.routes.services.SessionLocal", return_value=mock_db):
        response = client.get("/api/services", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json["items"][0]["name"] == "Test Service"
    assert response.json["total"] == 1


def test_services_create_missing_fields(client, app):
    token = _get_token(app, ["platform-admin"])
    response = client.post("/api/services", json={"name": "test"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 400


def test_services_create_success(client, app):
    token = _get_token(app, ["admin"])
    mock_db = MagicMock()
    mock_db.__enter__.return_value = mock_db
    mock_db.add = MagicMock()
    mock_db.flush = MagicMock()
    mock_db.commit = MagicMock()

    with patch("src.routes.services.SessionLocal", return_value=mock_db):
        response = client.post("/api/services", json={
            "name": "New Service",
            "slug": "new-service",
            "base_url": "http://new"
        }, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 201
    assert "client_secret" in response.json
    assert mock_db.commit.called


def test_services_create_conflict(client, app):
    token = _get_token(app, ["admin"])
    mock_db = MagicMock()
    mock_db.__enter__.return_value = mock_db
    mock_db.add = MagicMock()
    mock_db.flush = MagicMock()
    mock_db.commit.side_effect = IntegrityError("msg", "params", "orig")
    mock_db.rollback = MagicMock()

    with patch("src.routes.services.SessionLocal", return_value=mock_db):
        response = client.post("/api/services", json={
            "name": "New Service",
            "slug": "new-service",
            "base_url": "http://new"
        }, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 409
    assert mock_db.rollback.called


def test_services_get_not_found(client, app):
    token = _get_token(app, ["admin"])
    mock_db = MagicMock()
    mock_db.__enter__.return_value = mock_db
    mock_db.scalar.return_value = None

    with patch("src.routes.services.SessionLocal", return_value=mock_db):
        response = client.get("/api/services/missing-service", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 404


def test_services_update_no_fields(client, app):
    token = _get_token(app, ["admin"])
    response = client.put(
        "/api/services/existing-service",
        json={"not_a_field": "value"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400


def test_services_update_conflict(client, app):
    token = _get_token(app, ["admin"])
    service = Service(
        uuid=uuid.uuid7(),
        name="Existing Service",
        slug="existing-service",
        base_url="http://existing",
    )

    mock_db = MagicMock()
    mock_db.__enter__.return_value = mock_db
    mock_db.scalar.side_effect = [service]
    mock_db.commit.side_effect = IntegrityError("msg", "params", "orig")
    mock_db.rollback = MagicMock()

    with patch("src.routes.services.SessionLocal", return_value=mock_db):
        response = client.put(
            "/api/services/existing-service",
            json={"name": "Updated Service"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 409
    assert mock_db.rollback.called


def test_services_rotate_success(client, app):
    token = _get_token(app, ["admin"])
    service = Service(
        uuid=uuid.uuid7(),
        name="Test Service",
        slug="test-service",
        base_url="http://test-service",
    )
    credential = ServiceCredential(
        uuid=uuid.uuid7(),
        service_uuid=service.uuid,
        hashed_secret="old-hash",
        service=service,
    )

    mock_db = MagicMock()
    mock_db.__enter__.return_value = mock_db
    mock_db.scalar.side_effect = [service, credential]
    mock_db.commit = MagicMock()

    with patch("src.routes.services.SessionLocal", return_value=mock_db):
        response = client.post("/api/services/test-service/rotate", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json["slug"] == "test-service"
    assert response.json["client_secret"]
    assert mock_db.commit.called


def test_services_get_audits_invalid_source(client, app):
    token = _get_token(app, ["admin"])
    service = Service(
        name="Test Service",
        slug="test-service",
        base_url="http://test-service",
    )
    credential = ServiceCredential(
        service_uuid=service.uuid,
        hashed_secret="secret",
        service=service,
    )

    mock_db = MagicMock()
    mock_db.__enter__.return_value = mock_db
    mock_db.scalar.side_effect = [service, credential]

    with patch("src.routes.services.SessionLocal", return_value=mock_db):
        response = client.get(
            "/api/services/test-service/audits?source=invalid",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400
    assert response.json["error"] == "invalid source"


def test_services_get_success(client, app):
    token = _get_token(app, ["admin"])
    service = Service(
        uuid=uuid.uuid7(),
        name="Test Service",
        slug="test-service",
        base_url="http://test-service",
    )
    credential = ServiceCredential(
        uuid=uuid.uuid7(),
        service_uuid=service.uuid,
        hashed_secret="secret",
        service=service,
    )

    mock_db = MagicMock()
    mock_db.__enter__.return_value = mock_db
    mock_db.scalar.side_effect = [service, credential]

    with patch("src.routes.services.SessionLocal", return_value=mock_db):
        response = client.get("/api/services/test-service", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json["name"] == "Test Service"
    assert response.json["credential_uuid"] == str(credential.uuid)


def test_services_update_success(client, app):
    token = _get_token(app, ["admin"])
    service = Service(
        name="Existing Service",
        slug="existing-service",
        base_url="http://existing",
    )

    mock_db = MagicMock()
    mock_db.__enter__.return_value = mock_db
    mock_db.scalar.return_value = service
    mock_db.commit = MagicMock()

    with patch("src.routes.services.SessionLocal", return_value=mock_db):
        response = client.put(
            "/api/services/existing-service",
            json={"name": "Updated Service"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    assert response.json["name"] == "Updated Service"
    assert mock_db.commit.called

