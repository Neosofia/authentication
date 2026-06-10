import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

from src.services.service_management import (
    list_catalog_audits,
    get_service_audits,
)


def _make_mock_db(rows):
    mock_db = MagicMock()
    mock_db.scalar.return_value = len(rows)
    execute_result = MagicMock()
    execute_result.mappings.return_value.all.return_value = rows
    mock_db.execute.return_value = execute_result
    return mock_db


def test_get_service_audits_handles_current_service_row_with_null_history_uuid():
    service_uuid = str(uuid.uuid7())
    live_row = {
        "history_uuid": None,
        "uuid": service_uuid,
        "name": "Test Service",
        "slug": "test-service",
        "base_url": "http://test-service",
        "changed_at": datetime.now(timezone.utc),
        "changed_by_uuid": uuid.uuid7(),
        "changed_by_type": 1,
        "change_type": 1,
    }
    audit_row = {
        "history_uuid": uuid.uuid7(),
        "uuid": service_uuid,
        "name": "Test Service",
        "slug": "test-service",
        "base_url": "http://test-service",
        "changed_at": datetime.now(timezone.utc),
        "changed_by_uuid": uuid.uuid7(),
        "changed_by_type": 1,
        "change_type": 2,
    }
    mock_db = _make_mock_db([live_row, audit_row])

    items, total = get_service_audits(mock_db, service_uuid, "service", 1, 5)

    assert total == 2
    assert items[0]["history_uuid"] is None
    assert items[1]["history_uuid"] == str(audit_row["history_uuid"])
    assert items[0]["name"] == "Test Service"
    assert items[0]["changed_by_name"] is None
    assert items[1]["changed_by_name"] is None


def test_get_service_audits_handles_current_credential_row_with_null_history_uuid():
    service_uuid = str(uuid.uuid7())
    live_row = {
        "history_uuid": None,
        "uuid": uuid.uuid7(),
        "service_uuid": service_uuid,
        "name": None,
        "slug": None,
        "base_url": None,
        "changed_at": datetime.now(timezone.utc),
        "changed_by_uuid": uuid.uuid7(),
        "changed_by_type": 1,
        "change_type": 1,
    }
    audit_row = {
        "history_uuid": uuid.uuid7(),
        "uuid": uuid.uuid7(),
        "service_uuid": service_uuid,
        "name": None,
        "slug": None,
        "base_url": None,
        "changed_at": datetime.now(timezone.utc),
        "changed_by_uuid": uuid.uuid7(),
        "changed_by_type": 2,
        "change_type": 2,
    }
    mock_db = _make_mock_db([live_row, audit_row])

    items, total = get_service_audits(mock_db, service_uuid, "credential", 1, 5)

    assert total == 2
    assert items[0]["history_uuid"] is None
    assert items[1]["history_uuid"] == str(audit_row["history_uuid"])
    assert items[0]["credential_uuid"] == str(live_row["uuid"])
    assert items[0]["changed_by_name"] is None
    assert items[1]["changed_by_name"] is None


def test_list_catalog_audits_maps_rows():
    changed_at = datetime.now(timezone.utc)
    credential_uuid = uuid.uuid7()
    row = {
        "history_uuid": uuid.uuid7(),
        "source": "credential",
        "slug": "chat",
        "credential_uuid": credential_uuid,
        "name": None,
        "base_url": None,
        "changed_at": changed_at,
        "changed_by_uuid": uuid.uuid7(),
        "changed_by_type": 1,
        "change_type": 2,
    }
    mock_db = MagicMock()
    execute_result = MagicMock()
    execute_result.mappings.return_value.all.return_value = [row]
    mock_db.execute.return_value = execute_result

    items = list_catalog_audits(mock_db, 5)

    assert len(items) == 1
    assert items[0]["source"] == "credential"
    assert items[0]["slug"] == "chat"
    assert items[0]["credential_uuid"] == str(credential_uuid)
    assert items[0]["changed_at"] == changed_at.isoformat()
