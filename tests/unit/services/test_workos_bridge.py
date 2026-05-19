from unittest.mock import MagicMock
import pytest
from src.services.workos_bridge import extract_platform_claims
import jwt

def _auth_response_with_token(token_claims):
    auth_response = MagicMock()
    auth_response.user.id = "user_123"
    auth_response.user.external_id = "user_uuid_123"
    auth_response.access_token = jwt.encode(token_claims, "secret", algorithm="HS256")
    return auth_response

def test_extract_platform_claims_happy_path():
    claims_payload = {
        "workos_tenant_id": "org_123",
        "workos_tenant_name": "Acme Corp",
        "tenant_uuid": "019e02e1-94e1-722b-bd61-f7f95fb1604c",
        "role": "admin",
    }
    auth_response = _auth_response_with_token(claims_payload)
    
    result = extract_platform_claims(auth_response)
    
    assert result["workos_tenant_id"] == "org_123"
    assert result["workos_tenant_name"] == "Acme Corp"
    assert result["tenant_uuid"] == "019e02e1-94e1-722b-bd61-f7f95fb1604c"
    assert result["roles"] == ["admin"]

def test_extract_platform_claims_missing_workos_tenant_id():
    claims_payload = {
        "workos_tenant_name": "Acme Corp",
        "tenant_uuid": "019e02e1-94e1-722b-bd61-f7f95fb1604c"
    }
    auth_response = _auth_response_with_token(claims_payload)
    
    with pytest.raises(ValueError, match="User has no workos_tenant_id"):
        extract_platform_claims(auth_response)

def test_extract_platform_claims_missing_tenant_uuid():
    claims_payload = {
        "workos_tenant_id": "org_123",
        "workos_tenant_name": "Acme Corp"
    }
    auth_response = _auth_response_with_token(claims_payload)
    
    with pytest.raises(ValueError, match="User has no tenant_uuid"):
        extract_platform_claims(auth_response)

