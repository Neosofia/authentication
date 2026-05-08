def test_openapi_endpoint(client, api_spec, validate_response):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    validate_response(api_spec, "/openapi.json", "get", 200, response.json)
