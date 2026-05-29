import uuid
from unittest.mock import MagicMock

import pytest
from werkzeug.exceptions import NotFound

from src.models.tenant import Tenant
from src.services import tenant_management

pytestmark = pytest.mark.unit

TENANT_ID = uuid.UUID("019e02e1-94e1-722b-bd61-f7f95fb1601f")


def _tenant_row() -> Tenant:
    row = Tenant(uuid=TENANT_ID, name="Acme Corp", idp_id="org_123", change_type=1)
    return row


def test_get_tenant_or_404_invalid_uuid():
    mock_db = MagicMock()
    with pytest.raises(NotFound):
        tenant_management.get_tenant_or_404(mock_db, "not-a-uuid")


def test_get_tenant_or_404_missing():
    mock_db = MagicMock()
    mock_db.scalar.return_value = None
    with pytest.raises(NotFound):
        tenant_management.get_tenant_or_404(mock_db, str(TENANT_ID))


def test_get_tenant_or_404_returns_dict():
    mock_db = MagicMock()
    mock_db.scalar.return_value = _tenant_row()
    result = tenant_management.get_tenant_or_404(mock_db, str(TENANT_ID))
    assert result == {"uuid": str(TENANT_ID), "name": "Acme Corp", "idp_id": "org_123"}
