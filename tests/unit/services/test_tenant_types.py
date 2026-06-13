import pytest

from src.services.tenant_types import valid_tenant_types

pytestmark = pytest.mark.unit


def test_valid_tenant_types_from_env():
    assert "platform" in valid_tenant_types()
    assert "site" in valid_tenant_types()
    assert "patient" not in valid_tenant_types()
