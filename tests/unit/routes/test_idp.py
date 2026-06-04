from unittest.mock import patch

from src.config import settings
from src.services.idp_observability import (
    IdpObservabilityUnavailableError,
    IdpObservabilityUnsupportedError,
)
from src.services.tokens import issue_token


def _operator_token(app):
    with app.app_context():
        return issue_token(
            sub="12345678-1234-5678-1234-567812345678",
            token_type="human",
            actors=["operator"],
            tenant_uuid="019e02e1-94e1-722b-bd61-f7f95fb1601f",
            ttl_secs=3600,
            private_key_pem=settings.jwt_private_key_pem,
            audience=settings.jwt_web_audience,
            public_key_pem=settings.jwt_public_key_pem,
        )


def test_failed_authentications_unauthorized(client):
    response = client.get("/api/idp/failed-authentications")
    assert response.status_code == 401


def test_failed_authentications_forbidden_without_operator(client, app):
    with app.app_context():
        token = issue_token(
            sub="12345678-1234-5678-1234-567812345678",
            token_type="human",
            actors=["clinician"],
            tenant_uuid="019e02e1-94e1-722b-bd61-f7f95fb1601f",
            ttl_secs=3600,
            private_key_pem=settings.jwt_private_key_pem,
            audience=settings.jwt_web_audience,
            public_key_pem=settings.jwt_public_key_pem,
        )
    response = client.get(
        "/api/idp/failed-authentications",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_failed_authentications_invalid_limit(client, app):
    token = _operator_token(app)
    response = client.get(
        "/api/idp/failed-authentications?limit=abc",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 400


def test_failed_authentications_success(client, app):
    token = _operator_token(app)
    payload = {
        "items": [{"id": "event_1", "method": "password", "status": "failed"}],
        "limit": 25,
        "before": None,
        "after": "event_1",
    }

    with patch(
        "src.routes.idp.idp_observability.list_failed_authentications",
        return_value=payload,
    ):
        response = client.get(
            "/api/idp/failed-authentications",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 200
    assert response.json["items"][0]["id"] == "event_1"
    assert response.json["after"] == "event_1"


def test_failed_authentications_idp_unavailable(client, app):
    token = _operator_token(app)
    with patch(
        "src.routes.idp.idp_observability.list_failed_authentications",
        side_effect=IdpObservabilityUnavailableError,
    ):
        response = client.get(
            "/api/idp/failed-authentications",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 503


def test_failed_authentications_idp_unsupported(client, app):
    token = _operator_token(app)
    with patch(
        "src.routes.idp.idp_observability.list_failed_authentications",
        side_effect=IdpObservabilityUnsupportedError("other"),
    ):
        response = client.get(
            "/api/idp/failed-authentications",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 501
