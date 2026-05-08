from unittest.mock import patch

def test_health_endpoint(client, api_spec, validate_response):
    with patch("src.routes.health.SessionLocal"):
        response = client.get("/health")
        assert response.status_code == 200
        validate_response(api_spec, "/health", "get", 200, response.json)