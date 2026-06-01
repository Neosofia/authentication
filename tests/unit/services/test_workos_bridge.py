from unittest.mock import MagicMock, patch

import pytest

from src.services.workos_bridge import (
    WorkOSIdentityProvider,
    decode_access_token_claims,
    extract_platform_claims,
    prepare_auth_session,
    provision_organization_external_id,
)
from tests.conftest import encode_test_access_token

_ORG = "org_123"


def _auth(claims, *, user_data=None, refresh="refresh-token"):
    r = MagicMock()
    r.access_token = encode_test_access_token(claims)
    r.refresh_token = refresh
    r.user = MagicMock(id="user_123", external_id=(user_data or {}).get("external_id"))
    r.user.to_dict.return_value = user_data or {"id": "user_123"}
    return r


@pytest.mark.parametrize(
    "claims,missing_field",
    [
        ({"workos_tenant_name": "Acme Corp", "tenant_uuid": "019e02e1-94e1-722b-bd61-f7f95fb1604c"}, "workos_tenant_id"),
        ({"workos_tenant_id": _ORG, "workos_tenant_name": "Acme Corp"}, "tenant_uuid"),
    ],
)
def test_extract_platform_claims_rejects_incomplete_token(claims, missing_field):
    with pytest.raises(ValueError, match=missing_field):
        extract_platform_claims(_auth(claims))


@patch("src.services.idp.workos.workos_client")
def test_provision_organization_external_id_returns_false_on_error(mock_wos):
    mock_wos.organizations.update_organization.side_effect = RuntimeError("unavailable")
    assert provision_organization_external_id(_ORG) is False


@patch("src.services.idp.workos.workos_client")
def test_prepare_auth_session_rejects_when_tenant_uuid_stays_missing(mock_wos):
    mock_wos.organizations.update_organization.side_effect = RuntimeError("unavailable")
    auth = _auth(
        {"workos_tenant_id": _ORG, "role": "operator"},
        refresh=None,
        user_data={"id": "user_123", "external_id": "person-uuid"},
    )

    with pytest.raises(ValueError, match="tenant_uuid"):
        prepare_auth_session(auth)

    mock_wos.user_management.authenticate_with_refresh_token.assert_not_called()


def test_decode_access_token_claims_rejects_wrong_client_id():
    token = encode_test_access_token({"role": "operator"})

    with patch("src.services.idp.workos.settings.workos_client_id", "other_client"):
        assert decode_access_token_claims(MagicMock(access_token=token)) == {}


def test_decode_access_token_claims_accepts_custom_authkit_issuer():
    token = encode_test_access_token(
        {"role": "operator", "iss": "https://my-env.authkit.app/"}
    )

    claims = decode_access_token_claims(MagicMock(access_token=token))
    assert claims.get("role") == "operator"


def test_decode_access_token_claims_without_access_token():
    assert decode_access_token_claims(MagicMock(access_token=None)) == {}


def test_extract_platform_claims_accepts_single_role_claim():
    claims = extract_platform_claims(
        _auth(
            {
                "workos_tenant_id": _ORG,
                "workos_tenant_name": "Acme Corp",
                "tenant_uuid": "019e02e1-94e1-722b-bd61-f7f95fb1604c",
                "role": "operator",
            },
            user_data={"id": "user_123", "external_id": "person-uuid"},
        )
    )

    assert claims["actors"] == ["operator"]


@patch("src.services.idp.workos.unseal_data", return_value={"access_token": "raw-token"})
def test_workos_provider_authenticate_session_attempts_refresh_when_auth_fails(mock_unseal):
    provider = WorkOSIdentityProvider.__new__(WorkOSIdentityProvider)
    provider.client = MagicMock()
    sealed_session = provider.client.user_management.load_sealed_session.return_value
    sealed_session.authenticate.return_value = MagicMock(authenticated=False)
    refreshed = MagicMock(
        authenticated=True,
        sealed_session="refreshed-session",
        user=MagicMock(id="user_123"),
    )
    sealed_session.refresh.return_value = refreshed

    session = provider.authenticate_session("old-session")

    assert session.idp_user_id == "user_123"
    assert session.sealed_session == "refreshed-session"
    assert session.raw_access_token == "raw-token"
    mock_unseal.assert_called_once_with(
        "refreshed-session",
        "test-cookie-password-must-be-min-32-chars-long",
    )


def test_workos_provider_revoke_session_returns_none_when_session_invalid():
    provider = WorkOSIdentityProvider.__new__(WorkOSIdentityProvider)
    provider.client = MagicMock()
    sealed_session = provider.client.user_management.load_sealed_session.return_value
    sealed_session.authenticate.return_value = MagicMock(authenticated=False)
    sealed_session.refresh.return_value = MagicMock(authenticated=False)

    assert provider.revoke_session("sealed", return_to="https://app.example.com") is None
    provider.client.user_management.get_logout_url.assert_not_called()
