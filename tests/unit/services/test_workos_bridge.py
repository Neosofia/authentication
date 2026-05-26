from unittest.mock import MagicMock, patch

import jwt
import pytest

from src.services.workos_bridge import (
    extract_platform_claims,
    prepare_auth_session,
    provision_organization_external_id,
)

_ORG = "org_123"


def _auth(claims, *, user_data=None, refresh="refresh-token"):
    r = MagicMock()
    r.access_token = jwt.encode(claims, "secret", algorithm="HS256")
    r.refresh_token = refresh
    r.user = MagicMock(id="user_123", external_id=(user_data or {}).get("external_id"))
    r.user.to_dict.return_value = user_data or {"id": "user_123"}
    return r


@pytest.mark.parametrize(
    "claims,match",
    [
        ({"workos_tenant_name": "Acme Corp", "tenant_uuid": "019e02e1-94e1-722b-bd61-f7f95fb1604c"}, "workos_tenant_id"),
        ({"workos_tenant_id": _ORG, "workos_tenant_name": "Acme Corp"}, "tenant_uuid"),
    ],
)
def test_extract_platform_claims_rejects_incomplete_token(claims, match):
    with pytest.raises(ValueError, match=match):
        extract_platform_claims(_auth(claims))


@patch("src.services.workos_bridge.workos_client")
def test_provision_organization_external_id_returns_false_on_error(mock_wos):
    mock_wos.organizations.update_organization.side_effect = RuntimeError("unavailable")
    assert provision_organization_external_id(_ORG) is False


@patch("src.services.workos_bridge.workos_client")
def test_prepare_auth_session_rejects_when_tenant_uuid_stays_missing(mock_wos):
    mock_wos.organizations.update_organization.side_effect = RuntimeError("unavailable")
    auth = _auth(
        {"workos_tenant_id": _ORG, "role": "admin"},
        refresh=None,
        user_data={"id": "user_123", "external_id": "person-uuid"},
    )

    with pytest.raises(ValueError, match="tenant_uuid"):
        prepare_auth_session(auth)

    mock_wos.user_management.authenticate_with_refresh_token.assert_not_called()
