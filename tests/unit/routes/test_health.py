from unittest.mock import patch
from sqlalchemy.exc import OperationalError

# If the database connection times out, we want the pod to remain alive 
# but log that we are in a degraded state (cannot issue machine tokens).
@patch("src.routes.health.SessionLocal")
@patch("src.routes.health.log_event")
def test_health_timeout(mock_log, mock_session, client):
    mock_db = mock_session.return_value.__enter__.return_value
    mock_db.execute.side_effect = TimeoutError("Simulated timeout")

    response = client.get("/health")
    
    assert response.status_code == 200
    assert response.json == {"status": "degraded", "detail": "database timeout, machine JWTs can not be issued"}
    mock_log.assert_called_once_with("health_check_degraded", reason="database timeout")

# If the database is completely inaccessible (e.g., generic exception like OperationalError),
# the health check returns a 503 to signal orchestrators to restart or stop traffic.
@patch("src.routes.health.SessionLocal")
@patch("src.routes.health.log_event")
def test_health_exception(mock_log, mock_session, client):
    mock_db = mock_session.return_value.__enter__.return_value
    mock_db.execute.side_effect = OperationalError("SELECT 1", {}, "DB down")

    response = client.get("/health")
    
    assert response.status_code == 503
    assert response.json == {"status": "error", "detail": "database unavailable"}
    mock_log.assert_called_once_with("health_check_failed", error_class="OperationalError")
