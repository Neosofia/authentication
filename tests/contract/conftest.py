def pytest_configure(config):
    """Register contract marker."""
    config.addinivalue_line(
        "markers",
        "contract: mark test as a contract test (API response shape, claim structure, logging)"
    )
