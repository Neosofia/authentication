from unittest.mock import patch

import pytest
from werkzeug.exceptions import NotFound

from src.config import settings
from src.services.tokens import issue_token

pytestmark = pytest.mark.unit


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


def test_get_tenant_not_found_returns_404(client, app):
    token = _operator_token(app)

    with patch("src.routes.tenants.SessionLocal"), \
         patch(
             "src.routes.tenants.tenant_management.get_tenant_or_404",
             side_effect=NotFound(),
         ):
        response = client.get(
            "/api/v1/tenants/00000000-0000-7000-8000-000000000001",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 404
    assert response.json["error"] == "not found"


def test_get_tenant_database_error_returns_503(client, app):
    token = _operator_token(app)

    with patch("src.routes.tenants.SessionLocal"), \
         patch(
             "src.routes.tenants.tenant_management.get_tenant_or_404",
             side_effect=RuntimeError("db"),
         ):
        response = client.get(
            "/api/v1/tenants/00000000-0000-7000-8000-000000000001",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert response.status_code == 503
    assert response.json["error"] == "failed to fetch tenant"
