import pytest
import time
from unittest.mock import patch, MagicMock
from src.services.identity import sync_identity_data

@patch("src.services.identity.SessionLocal")
def test_sync_identity_data_inserts(mock_db_session):
    mock_db = MagicMock()
    mock_db_session.return_value.__enter__.return_value = mock_db
    
    mock_db.scalar.side_effect = [None, None]
    
    sync_identity_data(
        user_uuid="12345678-1234-5678-1234-567812345678",
        tenant_uuid="87654321-4321-8765-4321-876543218765",
        idp_user_id="google-oauth2|12345",
        first_name="Jane",
        last_name="Doe",
        email="jane@example.com",
        idp_tenant_id="org_123",
        tenant_name="Acme Corp",
    )
    
    assert mock_db.add.call_count == 2
    assert mock_db.commit.call_count == 2

@patch("src.services.identity.SessionLocal")
def test_sync_identity_data_updates(mock_db_session):
    mock_db = MagicMock()
    mock_db_session.return_value.__enter__.return_value = mock_db
    
    mock_org = MagicMock()
    mock_org.name = "Old Name"
    mock_user = MagicMock()
    mock_user.first_name = "Old First"
    mock_user.last_name = "Old Last"
    mock_user.email = "old@example.com"
    
    mock_db.scalar.side_effect = [mock_org, mock_user]
    
    sync_identity_data(
        user_uuid="12345678-1234-5678-1234-567812345678",
        tenant_uuid="87654321-4321-8765-4321-876543218765",
        idp_user_id="google-oauth2|12345",
        first_name="Jane",
        last_name="Doe",
        email="jane@example.com",
        idp_tenant_id="org_123",
        tenant_name="Acme Corp",
    )
    
    assert mock_org.name == "Acme Corp"
    assert mock_user.first_name == "Jane"
    assert mock_db.commit.call_count == 2 # tenant updated and user updated

@patch("src.services.identity.threading.Thread")
@patch("src.services.identity.log_event")
def test_sync_identity_data_timeout(mock_log, mock_thread_class):
    mock_thread = MagicMock()
    mock_thread_class.return_value = mock_thread
    mock_thread.is_alive.return_value = True # Simulate timeout
    
    sync_identity_data(
        user_uuid="12345678-1234-5678-1234-567812345678",
        tenant_uuid="87654321-4321-8765-4321-876543218765",
        idp_user_id="google-oauth2|12345",
        first_name="Jane",
        last_name="Doe",
        email="jane@example.com",
        idp_tenant_id="org_123",
        tenant_name="Acme Corp",
    )

    mock_log.assert_called_once_with(
        "identity_sync_timeout",
        idp_user_id="google-oauth2|12345",
        idp_tenant_id="org_123",
    )
