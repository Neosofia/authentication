def test_openapi_spec_not_served(client):
    """OpenAPI contract lives in-repo only; it must not be exposed over HTTP."""
    response = client.get("/openapi.json")
    assert response.status_code == 404
