from unittest.mock import MagicMock, patch

from src.config import settings


def _get_token(app, *, roles: list[str], tenant_uuid: str):
    with app.app_context():
        from src.services.tokens import issue_token

        return issue_token(
            sub="019e02e1-94e1-722b-bd61-f7f95fb1602a",
            token_type="human",
            actors=roles,
            tenant_uuid=tenant_uuid,
            ttl_secs=3600,
            private_key_pem=settings.jwt_private_key_pem,
            audience=settings.jwt_web_audience,
            public_key_pem=settings.jwt_public_key_pem,
        )


TENANT_UUID = "019e02e1-94e1-722b-bd61-f7f95fb1601f"
OTHER_TENANT = "019e02e1-94e1-722b-bd61-f7f95fb1604d"


def test_get_tenant_unauthorized(client):
    response = client.get(f"/api/v1/tenants/{TENANT_UUID}")
    assert response.status_code == 401


def test_get_tenant_forbidden_for_other_org(client, app):
    token = _get_token(app, roles=["clinician"], tenant_uuid=TENANT_UUID)
    response = client.get(
        f"/api/v1/tenants/{OTHER_TENANT}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_get_tenant_self_allowed(client, app, api_spec, validate_response):
    token = _get_token(app, roles=["clinician"], tenant_uuid=TENANT_UUID)
    mock_tenant = MagicMock()
    mock_tenant.uuid = TENANT_UUID
    mock_tenant.name = "Acme Corp"
    mock_tenant.idp_id = "org_123"

    with patch("src.routes.tenants.SessionLocal") as mock_session:
        mock_db = MagicMock()
        mock_session.return_value.__enter__.return_value = mock_db
        with patch(
            "src.routes.tenants.tenant_management.get_tenant_or_404",
            return_value={
                "uuid": TENANT_UUID,
                "name": "Acme Corp",
                "display_code": "1034",
                "idp_id": "org_123",
                "type": "platform",
            },
        ):
            response = client.get(
                f"/api/v1/tenants/{TENANT_UUID}",
                headers={"Authorization": f"Bearer {token}"},
            )

    assert response.status_code == 200
    assert response.json["name"] == "Acme Corp"
    validate_response(api_spec, "/api/v1/tenants/{tenant_uuid}", "get", 200, response.json)


def test_get_tenant_operator_can_read_any(client, app):
    token = _get_token(app, roles=["operator"], tenant_uuid=TENANT_UUID)
    with patch("src.routes.tenants.SessionLocal") as mock_session:
        mock_db = MagicMock()
        mock_session.return_value.__enter__.return_value = mock_db
        with patch(
            "src.routes.tenants.tenant_management.get_tenant_or_404",
            return_value={
                "uuid": OTHER_TENANT,
                "name": "Other Org",
                "display_code": None,
                "idp_id": "org_456",
                "type": "cro",
            },
        ):
            response = client.get(
                f"/api/v1/tenants/{OTHER_TENANT}",
                headers={"Authorization": f"Bearer {token}"},
            )
    assert response.status_code == 200
    assert response.json["uuid"] == OTHER_TENANT
