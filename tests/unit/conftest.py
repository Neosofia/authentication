"""
Unit test configuration.

Registers @pytest.mark.unit marker for filtering.
All fixtures are inherited from root conftest.py.
"""


def pytest_configure(config):
    """Register unit marker."""
    config.addinivalue_line(
        "markers",
        "unit: mark test as a unit test (pure functions, zero I/O)"
    )


