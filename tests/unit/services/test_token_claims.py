import uuid
from unittest.mock import MagicMock

import pytest

from src.models.tenant import Tenant
from src.models.user import User
from src.services.token_claims import (
    cache_roles_mirror,
    human_token_claims,
    roles_for_jwt,
    resolve_tenant_type,
)

pytestmark = pytest.mark.unit

TENANT_ID = uuid.UUID("019e02e1-94e1-722b-bd61-f7f95fb1601f")
USER_ID = uuid.UUID("00000000-0000-7000-8000-000000000002")


def test_roles_for_jwt_strips_tenant_prefix():
    assert roles_for_jwt(["platform.admin", "platform.audit"], "platform") == [
        "admin",
        "audit",
    ]


def test_resolve_tenant_type_never_defaults_platform():
    assert resolve_tenant_type("platform") == "platform"
    assert resolve_tenant_type(None) is None
    assert resolve_tenant_type("") is None
    assert resolve_tenant_type("not-a-type") is None


def test_human_token_claims_reads_local_mirror_only():
    mock_db = MagicMock()
    mock_db.get.side_effect = lambda model, pk: {
        (Tenant, TENANT_ID): Tenant(
            uuid=TENANT_ID,
            name="Acme",
            idp_id="org_1",
            type="platform",
        ),
        (User, USER_ID): User(
            uuid=USER_ID,
            idp_id="user_1",
            roles=["platform.admin"],
        ),
    }.get((model, pk))

    tenant_type, roles = human_token_claims(
        mock_db,
        user_uuid=str(USER_ID),
        tenant_uuid=str(TENANT_ID),
    )

    assert tenant_type == "platform"
    assert roles == ["admin"]


def test_human_token_claims_omits_type_when_unset():
    mock_db = MagicMock()
    mock_db.get.side_effect = lambda model, pk: {
        (Tenant, TENANT_ID): Tenant(
            uuid=TENANT_ID,
            name="Acme",
            idp_id="org_1",
            type=None,
        ),
        (User, USER_ID): User(
            uuid=USER_ID,
            idp_id="user_1",
            roles=["platform.admin"],
        ),
    }.get((model, pk))

    tenant_type, roles = human_token_claims(
        mock_db,
        user_uuid=str(USER_ID),
        tenant_uuid=str(TENANT_ID),
    )

    assert tenant_type is None
    assert roles == []


def test_roles_for_jwt_skips_foreign_tenant_slugs():
    assert roles_for_jwt(["cro.admin", "platform.admin"], "platform") == ["admin"]


def test_roles_for_jwt_accepts_short_names_without_prefix():
    assert roles_for_jwt(["admin", "audit"], "platform") == ["admin", "audit"]


def test_roles_for_jwt_maps_patient_actor_slug_on_site_tenant():
    assert roles_for_jwt(["patient.self", "site.clinical"], "site") == [
        "self",
        "clinical",
    ]


def test_resolve_tenant_type_rejects_patient_org_kind():
    assert resolve_tenant_type("patient") is None


def test_human_token_claims_invalid_uuids_return_empty_roles():
    mock_db = MagicMock()
    tenant_type, roles = human_token_claims(
        mock_db,
        user_uuid="not-a-uuid",
        tenant_uuid="also-not-a-uuid",
    )
    assert tenant_type is None
    assert roles == []
    mock_db.get.assert_not_called()


def test_human_token_claims_missing_user_returns_type_only():
    mock_db = MagicMock()
    mock_db.get.return_value = Tenant(
        uuid=TENANT_ID,
        name="Acme",
        idp_id="org_1",
        type="platform",
    )

    tenant_type, roles = human_token_claims(
        mock_db,
        user_uuid=None,
        tenant_uuid=str(TENANT_ID),
    )

    assert tenant_type == "platform"
    assert roles == []


def test_human_token_claims_user_without_roles():
    mock_db = MagicMock()
    mock_db.get.side_effect = lambda model, pk: {
        (Tenant, TENANT_ID): Tenant(
            uuid=TENANT_ID,
            name="Acme",
            idp_id="org_1",
            type="platform",
        ),
        (User, USER_ID): User(uuid=USER_ID, idp_id="user_1", roles=[]),
    }.get((model, pk))

    tenant_type, roles = human_token_claims(
        mock_db,
        user_uuid=str(USER_ID),
        tenant_uuid=str(TENANT_ID),
    )

    assert tenant_type == "platform"
    assert roles == []


def test_cache_roles_mirror_updates_user_and_infers_tenant_type():
    mock_db = MagicMock()
    tenant = Tenant(uuid=TENANT_ID, name="Acme", idp_id="org_1", type=None)
    user = User(uuid=USER_ID, idp_id="user_1", roles=[])

    def get_model(model, pk):
        if model is Tenant and pk == TENANT_ID:
            return tenant
        if model is User and pk == USER_ID:
            return user
        return None

    mock_db.get.side_effect = get_model

    cache_roles_mirror(
        mock_db,
        user_uuid=str(USER_ID),
        tenant_uuid=str(TENANT_ID),
        registry_payload={"roles": ["platform.admin", "platform.audit"]},
    )

    assert user.roles == ["platform.admin", "platform.audit"]
    assert tenant.type == "platform"
    mock_db.commit.assert_called_once()


def test_cache_roles_mirror_skips_patient_slug_for_type_inference():
    mock_db = MagicMock()
    tenant = Tenant(uuid=TENANT_ID, name="Site", idp_id="org_1", type=None)
    user = User(uuid=USER_ID, idp_id="user_1", roles=[])

    def get_model(model, pk):
        if model is Tenant and pk == TENANT_ID:
            return tenant
        if model is User and pk == USER_ID:
            return user
        return None

    mock_db.get.side_effect = get_model

    cache_roles_mirror(
        mock_db,
        user_uuid=str(USER_ID),
        tenant_uuid=str(TENANT_ID),
        registry_payload={"roles": ["patient.self"]},
    )

    assert user.roles == ["patient.self"]
    assert tenant.type is None
    mock_db.commit.assert_called_once()


def test_cache_roles_mirror_noop_on_invalid_input():
    mock_db = MagicMock()
    cache_roles_mirror(
        mock_db,
        user_uuid="bad",
        tenant_uuid=str(TENANT_ID),
        registry_payload={"roles": ["platform.admin"]},
    )
    mock_db.get.assert_not_called()
    mock_db.commit.assert_not_called()

    user = User(uuid=USER_ID, idp_id="user_1", roles=[])
    mock_db.get.return_value = user
    cache_roles_mirror(
        mock_db,
        user_uuid=str(USER_ID),
        tenant_uuid=str(TENANT_ID),
        registry_payload={"roles": "not-a-list"},
    )
    mock_db.commit.assert_not_called()
