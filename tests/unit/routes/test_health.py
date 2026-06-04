import os
from unittest.mock import patch

import pytest
from importlib.metadata import version
from sqlalchemy.exc import OperationalError

from src.app import create_app

_AUTH_VERSION = version("authentication")

pytestmark = pytest.mark.unit


def _production_settings():
    from src.config import Settings

    return Settings(
        env="production",
        app_database_url=os.environ["APP_DATABASE_URL"],
        migration_database_url=os.environ["MIGRATION_DATABASE_URL"],
        csrf_secret_key=os.environ["CSRF_SECRET_KEY"],
        workos_cookie_password=os.environ["WORKOS_COOKIE_PASSWORD"],
        valid_actors=os.environ["VALID_ACTORS"],
        jwt_private_key_pem=os.environ["JWT_PRIVATE_KEY_PEM"],
        jwt_public_key_pem=os.environ["JWT_PUBLIC_KEY_PEM"],
        authentication_client_secret=os.environ["AUTHENTICATION_CLIENT_SECRET"],
        workos_api_key=os.environ["WORKOS_API_KEY"],
        workos_client_id=os.environ["WORKOS_CLIENT_ID"],
        workos_redirect_uri="https://auth.example.com/callback",
        frontend_url="https://example.com",
    )


@patch("src.routes.health.SessionLocal")
def test_health_allows_plain_http_in_production(mock_session):
    """Railway's internal probe uses HTTP; /health must not 302 to HTTPS."""
    import src.app as app_module

    mock_session.return_value.__enter__.return_value.execute.return_value = None
    original = app_module.settings
    app_module.settings = _production_settings()
    try:
        response = create_app().test_client().get("/health")
        assert response.status_code == 200
        assert response.headers.get("Location") is None
        assert response.get_json() == {"status": "ok", "version": _AUTH_VERSION}
    finally:
        app_module.settings = original


# If the database connection times out, we want the pod to remain alive 
# but log that we are in a degraded state (cannot issue service tokens).
@patch("src.routes.health.SessionLocal")
@patch("src.routes.health.log_event")
def test_health_timeout(mock_log, mock_session, client):
    mock_db = mock_session.return_value.__enter__.return_value
    mock_db.execute.side_effect = TimeoutError("Simulated timeout")

    response = client.get("/health")
    
    assert response.status_code == 200
    assert response.json == {
        "status": "degraded",
        "version": _AUTH_VERSION,
        "detail": "database timeout, service JWTs can not be issued",
    }
    mock_log.assert_called_once_with("health_check_degraded", reason="database timeout")

# If the database is completely inaccessible (e.g., generic exception like OperationalError),
# the health check returns a 503 to signal orchestrators to restart or stop traffic.
@patch("src.routes.health.SessionLocal")
@patch("src.routes.health.log_exception")
def test_health_exception(mock_log, mock_session, client):
    mock_db = mock_session.return_value.__enter__.return_value
    mock_db.execute.side_effect = OperationalError("SELECT 1", {}, "DB down")

    response = client.get("/health")
    
    assert response.status_code == 503
    assert response.json == {
        "status": "error",
        "version": _AUTH_VERSION,
        "detail": "database unavailable",
    }
    mock_log.assert_called_once()
    assert mock_log.call_args[0][0] == "health_check_failed"
