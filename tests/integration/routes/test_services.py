from unittest.mock import patch, MagicMock
from src.models.service import Service

def _get_token(app, roles):
    with app.app_context():
        from src.services.token_issuer import issue_token
        from src.config import settings
        return issue_token(
            sub="user_123",
            token_type="human",
            roles=roles,
            tenant_id="tenant_456",
            ttl_secs=3600,
            private_key_pem=settings.jwt_private_key_pem,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            public_key_pem=settings.jwt_public_key_pem,
        )

def test_services_unauthorized(client):
    response = client.get("/api/services")
    assert response.status_code == 401

def test_services_forbidden(client, app):
    token = _get_token(app, ["user"]) # Non-admin role
    response = client.get("/api/services", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403

class MockService:
    uuid = "12345678-1234-5678-1234-567812345678"
    name = "Test"
    slug = "test"
    base_url = "http://test"

def test_services_list_success(client, app):
    token = _get_token(app, ["admin"])

    mock_db_session = MagicMock()
    # Mock context manager
    mock_db_session.__enter__.return_value = mock_db_session
    mock_db_session.scalars.return_value.all.return_value = [MockService()]

    with patch("src.routes.services.SessionLocal", return_value=mock_db_session):
        response = client.get("/api/services", headers={"Authorization": f"Bearer {token}"})
    
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0]["name"] == "Test"

def test_services_create_missing_fields(client, app):
    token = _get_token(app, ["platform-admin"])
    response = client.post("/api/services", json={"name": "test"}, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 400

def test_services_create_success(client, app):
    token = _get_token(app, ["admin"])

    mock_db_session = MagicMock()
    mock_db_session.__enter__.return_value = mock_db_session

    with patch("src.routes.services.SessionLocal", return_value=mock_db_session):
        response = client.post("/api/services", json={
            "name": "New Service",
            "slug": "new-service",
            "base_url": "http://new"
        }, headers={"Authorization": f"Bearer {token}"})
    
    assert response.status_code == 201
    assert "client_secret" in response.json
    assert response.json["name"] == "New Service"

def test_services_create_conflict(client, app):
    from sqlalchemy.exc import IntegrityError
    token = _get_token(app, ["admin"])

    mock_db_session = MagicMock()
    mock_db_session.__enter__.return_value = mock_db_session
    mock_db_session.commit.side_effect = IntegrityError("msg", "params", "orig")

    with patch("src.routes.services.SessionLocal", return_value=mock_db_session):
        response = client.post("/api/services", json={
            "name": "New Service",
            "slug": "new-service",
            "base_url": "http://new"
        }, headers={"Authorization": f"Bearer {token}"})
    
    assert response.status_code == 409

def test_services_list_exception(client, app):
    token = _get_token(app, ["admin"])

    mock_db_session = MagicMock()
    mock_db_session.__enter__.return_value = mock_db_session
    mock_db_session.scalars.side_effect = Exception("DB error")

    with patch("src.routes.services.SessionLocal", return_value=mock_db_session):
        response = client.get("/api/services", headers={"Authorization": f"Bearer {token}"})
    
    assert response.status_code == 500

def test_services_create_exception(client, app):
    token = _get_token(app, ["admin"])

    mock_db_session = MagicMock()
    mock_db_session.__enter__.side_effect = Exception("DB Error")

    with patch("src.routes.services.SessionLocal", return_value=mock_db_session):
        response = client.post("/api/services", json={
            "name": "New Service",
            "slug": "new-service",
            "base_url": "http://new"
        }, headers={"Authorization": f"Bearer {token}"})
    
    assert response.status_code == 500
