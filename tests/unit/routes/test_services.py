import uuid
from unittest.mock import patch

from src.config import settings
from src.services.service_management import ConflictError, InvalidAuditSourceError, NotFoundError, CredentialNotFoundError
from src.services.tokens import issue_token


def _get_token(app, actors):
    with app.app_context():
        return issue_token(
            sub="12345678-1234-5678-1234-567812345678",
            token_type="human",
            actors=actors,
            tenant_uuid="019e02e1-94e1-722b-bd61-f7f95fb1601f",
            ttl_secs=3600,
            private_key_pem=settings.jwt_private_key_pem,
            audience=settings.jwt_web_audience,
            public_key_pem=settings.jwt_public_key_pem,
        )


def test_services_create_conflict_returns_409(client, app):
    token = _get_token(app, ["operator"])

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
    token = _get_token(app, ["operator"])

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
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"):
        response = client.post(
            "/api/services",
            json={"name": "New Service", "slug": "new-service"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400
    assert response.json["error"] == "missing required fields (name, slug, base_url)"


def test_services_update_no_fields_returns_400(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"):
        response = client.put(
            "/api/services/existing-service",
            json={"not_a_field": "value"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400
    assert response.json["error"] == "no updatable fields provided"


def test_services_create_invalid_json_returns_400(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"):
        response = client.post(
            "/api/services",
            data="not-json",
            content_type="application/json",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400


def test_services_update_invalid_json_returns_400(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"):
        response = client.put(
            "/api/services/existing-service",
            data="not-json",
            content_type="application/json",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400


@patch("authentication_in_the_middle.decorators.pyjwt.decode")
def test_services_require_operator_without_operator_role_returns_403(mock_decode, client):
    mock_decode.return_value = {
        "sub": "019e02e1-94e1-722b-bd61-f7f95fb1602a",
        "aud": settings.jwt_web_audience,
        "neosofia:actors": ["user"],
    }

    with patch("src.routes.services.SessionLocal"):
        response = client.get(
            "/api/services",
            headers={"Authorization": "Bearer 123"},
        )

    assert response.status_code == 403
    assert response.json["error"] == "forbidden"


def test_services_rotate_credential_not_found_returns_404(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"), \
         patch("src.routes.services.service_management.rotate_service", side_effect=CredentialNotFoundError("service credential not found")):
        response = client.post(
            "/api/services/existing-service/rotate",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 404
    assert response.json["error"] == "no credential"


def test_services_get_audits_not_found_returns_404(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"), \
         patch("src.routes.services.service_management.get_service", side_effect=NotFoundError("service not found")):
        response = client.get(
            "/api/services/missing-service/audits?source=service",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 404
    assert response.json["error"] == "not found"


def test_services_get_audits_invalid_source_returns_400(client, app):
    token = _get_token(app, ["operator"])

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


def test_services_list_invalid_pagination_returns_400(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"):
        response = client.get(
            "/api/services?page=abc",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400
    assert response.json["error"] == "invalid pagination"


def test_services_get_audits_invalid_pagination_returns_400(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"):
        response = client.get(
            "/api/services/test-service/audits?source=service&page_size=not-a-number",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400
    assert response.json["error"] == "invalid pagination"


def test_services_legacy_admin_role_returns_403(client, app):
    token = _get_token(app, ["admin"])

    with patch("src.routes.services.SessionLocal"):
        response = client.get(
            "/api/services",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 403
    assert response.json["error"] == "forbidden"


def test_services_operator_role_allowed(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"), \
         patch(
             "src.routes.services.service_management.list_services",
             return_value=([], 0),
         ):
        response = client.get(
            "/api/services",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200


def test_services_list_database_error_returns_500(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"), \
         patch(
             "src.routes.services.service_management.list_services",
             side_effect=RuntimeError("db"),
         ):
        response = client.get(
            "/api/services",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 500
    assert response.json["error"] == "database error"


def test_services_create_database_error_returns_500(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"), \
         patch(
             "src.routes.services.service_management.create_service",
             side_effect=RuntimeError("db"),
         ):
        response = client.post(
            "/api/services",
            json={"name": "Svc", "slug": "svc", "base_url": "http://svc"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 500


def test_services_get_database_error_returns_500(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"), \
         patch(
             "src.routes.services.service_management.get_service",
             side_effect=RuntimeError("db"),
         ):
        response = client.get(
            "/api/services/svc",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 500


def test_services_update_empty_body_returns_400(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"):
        response = client.put(
            "/api/services/svc",
            json={},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400
    assert response.json["error"] == "request body required"


def test_services_update_no_updatable_fields_returns_400(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"):
        response = client.put(
            "/api/services/svc",
            json={"unknown": "x"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 400
    assert response.json["error"] == "no updatable fields provided"


def test_services_update_not_found_returns_404(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"), \
         patch(
             "src.routes.services.service_management.update_service",
             side_effect=NotFoundError("service not found"),
         ):
        response = client.put(
            "/api/services/missing",
            json={"name": "Renamed"},
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 404


def test_services_rotate_service_not_found_returns_404(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"), \
         patch(
             "src.routes.services.service_management.rotate_service",
             side_effect=NotFoundError("service not found"),
         ):
        response = client.post(
            "/api/services/missing/rotate",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 404


def test_services_get_audits_success_returns_200(client, app):
    token = _get_token(app, ["operator"])
    service_uuid = str(uuid.uuid7())

    with patch("src.routes.services.SessionLocal"), \
         patch(
             "src.routes.services.service_management.get_service",
             return_value={"uuid": service_uuid, "slug": "test-service"},
         ), \
         patch(
             "src.routes.services.service_management.get_service_audits",
             return_value=([{"history_uuid": str(uuid.uuid7())}], 1),
         ):
        response = client.get(
            "/api/services/test-service/audits?source=service",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    assert response.json["total"] == 1
    assert response.json["service_uuid"] == service_uuid


def test_services_list_catalog_audits_success_returns_200(client, app):
    token = _get_token(app, ["operator"])

    with patch("src.routes.services.SessionLocal"), \
         patch(
             "src.routes.services.service_management.list_catalog_audits",
             return_value=[{"history_uuid": str(uuid.uuid7()), "source": "service", "slug": "chat"}],
         ):
        response = client.get(
            "/api/services/audits?limit=10",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    assert len(response.json["items"]) == 1


def test_services_list_catalog_audits_invalid_limit_returns_400(client, app):
    token = _get_token(app, ["operator"])

    response = client.get(
        "/api/services/audits?limit=not-a-number",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 400
    assert response.json["error"] == "invalid limit"
