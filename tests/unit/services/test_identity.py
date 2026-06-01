from unittest.mock import MagicMock, patch

from src.services.identity import sync_identity_data

DEFAULT_IDENTITY_PAYLOAD = {
    "user_uuid": "12345678-1234-5678-1234-567812345678",
    "tenant_uuid": "87654321-4321-8765-4321-876543218765",
    "idp_user_id": "google-oauth2|12345",
    "idp_tenant_id": "org_123",
    "tenant_name": "Acme Corp",
}


@patch("src.services.identity.SessionLocal")
def test_sync_identity_data_inserts(mock_db_session):
    mock_db = MagicMock()
    mock_db_session.return_value.__enter__.return_value = mock_db

    mock_db.scalar.side_effect = [None, None]

    sync_identity_data(**DEFAULT_IDENTITY_PAYLOAD)

    assert mock_db.add.call_count == 2
    assert mock_db.commit.call_count == 2
    tenant, user = mock_db.add.call_args_list[0].args[0], mock_db.add.call_args_list[1].args[0]
    assert tenant.idp_id == "org_123"
    assert user.idp_id == "google-oauth2|12345"


@patch("src.services.identity.SessionLocal")
def test_sync_identity_data_updates_tenant_name(mock_db_session):
    mock_db = MagicMock()
    mock_db_session.return_value.__enter__.return_value = mock_db

    mock_org = MagicMock()
    mock_org.name = "Old Name"
    mock_user = MagicMock()

    mock_db.scalar.side_effect = [mock_org, mock_user]

    sync_identity_data(**DEFAULT_IDENTITY_PAYLOAD)

    assert mock_org.name == "Acme Corp"
    assert mock_db.commit.call_count == 2


@patch("src.services.identity.threading.Thread")
@patch("src.services.identity.log_event")
def test_sync_identity_data_timeout(mock_log, mock_thread_class):
    mock_thread = MagicMock()
    mock_thread_class.return_value = mock_thread
    mock_thread.is_alive.return_value = True

    sync_identity_data(**DEFAULT_IDENTITY_PAYLOAD)

    mock_log.assert_called_once_with(
        "identity_sync_timeout",
        idp_user_id="google-oauth2|12345",
        idp_tenant_id="org_123",
    )


@patch("src.services.identity.SessionLocal")
def test_sync_identity_data_sets_tenant_type_on_existing_row(mock_db_session):
    mock_db = MagicMock()
    mock_db_session.return_value.__enter__.return_value = mock_db

    mock_org = MagicMock()
    mock_org.uuid = "87654321-4321-8765-4321-876543218765"
    mock_user = MagicMock()
    mock_user.uuid = "12345678-1234-5678-1234-567812345678"

    mock_db.scalar.side_effect = [mock_org, mock_user]

    sync_identity_data(
        **DEFAULT_IDENTITY_PAYLOAD,
        tenant_type="platform",
    )

    assert mock_org.type == "platform"
    assert mock_db.commit.call_count == 2


def _immediate_thread(target=None, **kwargs):
    class _T:
        def start(self):
            target()

        def join(self, timeout=None):
            pass

        def is_alive(self):
            return False

    return _T()


@patch("src.services.identity.log_exception")
@patch("src.services.identity.SessionLocal")
@patch("src.services.identity.threading.Thread", side_effect=_immediate_thread)
def test_sync_identity_data_logs_sync_error(mock_thread, mock_db_session, mock_log_exc):
    mock_db = MagicMock()
    mock_db_session.return_value.__enter__.return_value = mock_db
    mock_db.scalar.side_effect = RuntimeError("db failure")

    sync_identity_data(**DEFAULT_IDENTITY_PAYLOAD)

    assert any(
        call.args[0] == "identity_sync_error"
        for call in mock_log_exc.call_args_list
    )
