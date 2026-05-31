from unittest.mock import MagicMock

import pytest

from src.services.idp import PlatformIdentity
from src.services import user_provisioning

pytestmark = pytest.mark.unit


def _identity(**overrides) -> PlatformIdentity:
    data = {
        "user_uuid": "00000000-0000-7000-8000-000000000002",
        "tenant_uuid": "00000000-0000-7000-8000-000000000001",
        "idp_user_id": "user_123",
        "idp_tenant_id": "org_123",
        "tenant_name": "Test Org",
        "roles": ["operator"],
        "profile": {
            "first_name": "Ada",
            "last_name": "Lovelace",
            "email": "ada@example.com",
        },
    }
    data.update(overrides)
    return PlatformIdentity(**data)


def test_identity_payload_requires_user_uuid():
    with pytest.raises(ValueError, match="user_uuid"):
        user_provisioning._identity_payload(_identity(user_uuid=None))


def test_provision_user_registry_sync_puts_identity(monkeypatch):
    mock_db = MagicMock()
    mock_session = MagicMock()
    mock_session.return_value.__enter__.return_value = mock_db
    mock_put = MagicMock(return_value=MagicMock(status_code=201))

    monkeypatch.setattr(user_provisioning.settings, "authentication_client_secret", "secret")
    monkeypatch.setattr(user_provisioning, "SessionLocal", mock_session)
    monkeypatch.setattr(
        user_provisioning,
        "get_service",
        MagicMock(return_value={"base_url": "http://user:8018"}),
    )
    monkeypatch.setattr(user_provisioning, "issue_service_token", MagicMock(return_value="jwt"))
    monkeypatch.setattr(user_provisioning.httpx, "put", mock_put)

    assert user_provisioning._provision_user_registry_sync(_identity()) is True
    mock_put.assert_called_once_with(
        "http://user:8018/api/v1/users/00000000-0000-7000-8000-000000000002",
        json={
            "tenant_uuid": "00000000-0000-7000-8000-000000000001",
            "idp_id": "user_123",
            "first_name": "Ada",
            "last_name": "Lovelace",
            "email": "ada@example.com",
            "tier1_roles": ["operator"],
        },
        headers={"Authorization": "Bearer jwt"},
        timeout=user_provisioning.settings.user_provisioning_http_timeout_secs,
    )


def test_provision_user_registry_sync_returns_false_without_secret(monkeypatch):
    monkeypatch.setattr(user_provisioning.settings, "authentication_client_secret", None)

    assert user_provisioning._provision_user_registry_sync(_identity()) is False


def test_provision_user_registry_sync_returns_false_on_http_error(monkeypatch):
    mock_session = MagicMock()
    mock_session.return_value.__enter__.return_value = MagicMock()
    monkeypatch.setattr(user_provisioning.settings, "authentication_client_secret", "secret")
    monkeypatch.setattr(user_provisioning, "SessionLocal", mock_session)
    monkeypatch.setattr(
        user_provisioning,
        "get_service",
        MagicMock(return_value={"base_url": "http://user:8018/"}),
    )
    monkeypatch.setattr(user_provisioning, "issue_service_token", MagicMock(return_value="jwt"))
    monkeypatch.setattr(
        user_provisioning.httpx,
        "put",
        MagicMock(return_value=MagicMock(status_code=503)),
    )

    assert user_provisioning._provision_user_registry_sync(_identity()) is False


def test_provision_user_registry_respects_disable_flag(monkeypatch):
    monkeypatch.setattr(user_provisioning.settings, "user_provisioning_enabled", False)

    assert user_provisioning.provision_user_registry(_identity()) is None