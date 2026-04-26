import json
import os
import pathlib
import pytest
import jsonschema


# Load the OpenAPI 3.0.0 schema from centralized schemas repo (Neosofia/schemas)
# Set SCHEMAS_DIR to the local checkout of https://github.com/Neosofia/schemas
_SCHEMAS_DIR = pathlib.Path(os.environ["SCHEMAS_DIR"])
OPENAPI_3_0_0_SCHEMA_FILE = _SCHEMAS_DIR / "openapi-v3.0.json"


def _get_openapi_3_0_0_schema():
    """Load the OpenAPI 3.0.0 JSON Schema from the monorepo schemas directory."""
    if not OPENAPI_3_0_0_SCHEMA_FILE.exists():
        raise FileNotFoundError(f"OpenAPI 3.0.0 schema not found at {OPENAPI_3_0_0_SCHEMA_FILE}")
    
    with open(OPENAPI_3_0_0_SCHEMA_FILE) as f:
        return json.load(f)


@pytest.mark.integration
class TestOpenAPIEndpoint:
    """Tests for GET /api/openapi.json endpoint."""

    def test_openapi_spec_conforms_to_openapi_3_0_schema(self, client):
        """
        OpenAPI specification must conform to OpenAPI 3.0.0 JSON Schema.
        
        This validates that our openapi.json is a valid OpenAPI 3.0.0 document
        by checking it against the shared OpenAPI 3.0.0 JSON Schema stored in
        schemas/openapi-3.0.0.json.
        
        All services must conform to this schema to ensure API consistency.
        
        Ref: https://spec.openapis.org/oas/3.0/schema/json
        """
        resp = client.get("/api/openapi.json")
        assert resp.status_code == 200
        spec = resp.get_json()
        
        # Load shared OpenAPI 3.0.0 schema
        openapi_schema = _get_openapi_3_0_0_schema()
        
        # Validate spec against OpenAPI 3.0.0 schema
        jsonschema.validate(spec, openapi_schema)