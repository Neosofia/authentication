
def pytest_configure(config):
    """Register integration marker."""
    config.addinivalue_line(
        "markers",
        "integration: mark test as an integration test (real database, mocked HTTP)"
    )
