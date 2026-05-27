import os
import subprocess
import time
import requests
import pytest
from testcontainers.core.container import DockerContainer

# The image tag we'll build and use for testing
IMAGE_TAG = "auth-svc-test:latest"

@pytest.fixture(scope="session", autouse=True)
def build_container_image():
    """Build the Docker image once per test session."""
    # Find the repo root which has the Dockerfile
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
    subprocess.run(
        ["docker", "build", "-t", IMAGE_TAG, "."],
        cwd=repo_root,
        check=True,
        stdout=subprocess.DEVNULL, # keep logs clean
    )
    yield
    # Cleanup is optional; docker image rm auth-svc-test:latest

@pytest.fixture(scope="module")
def app_container():
    """Spin up the built container, mocking dependencies so it won't crash.
    We skip the Alembic migration by overriding the command, ensuring Gunicorn
    starts even without a real Postgres database attached. This makes the test rock solid.
    """
    container = DockerContainer(IMAGE_TAG)
    container.with_env("VALID_ROLES", "admin,user")
    container.with_env("JWT_PRIVATE_KEY_PEM", "DEFAULT_PRIVATE_KEY")
    container.with_env("JWT_PUBLIC_KEY_PEM", "DEFAULT_PUBLIC_KEY")
    container.with_env("APP_DATABASE_URL", "postgresql+psycopg://app:dummy@localhost/dummy")
    container.with_env("MIGRATION_DATABASE_URL", "postgresql+psycopg://auth:dummy@localhost/dummy")
    container.with_env("ENV", "test")
    container.with_env("CSRF_SECRET_KEY", "dummy_csrf_secret")
    container.with_env("WORKOS_API_KEY", "sk_test_dummy_key")
    container.with_env("WORKOS_CLIENT_ID", "client_test_dummy_id")
    container.with_env("WORKOS_COOKIE_PASSWORD", "dummy_cookie_password_32_chars_long_xxxxxx")
    container.with_env("WORKOS_REDIRECT_URI", "http://localhost:8014/callback")
    container.with_env("PORT", "7014")
    # Override command to bypass migrations since we aren't spinning up a DB container
    container.with_command("/bin/sh -c 'python -m gunicorn -c src/gunicorn.py src.app:app'")
    container.with_exposed_ports(7014)
    
    with container as c:
        # Wait for the container to become ready by polling the port
        port = c.get_exposed_port(7014)
        host = c.get_container_host_ip()
        url = f"http://{host}:{port}/health"

        # Health endpoint returns 503 when the DB is offline.
        # We manually wait since testcontainers generic wrappers expect 200 HTTP codes.
        start = time.time()
        ready = False
        while time.time() - start < 15:
            try:
                requests.get(url, timeout=1)
                # App is up! (It may be 503 due to missing DB, but it responded)
                ready = True
                break
            except requests.exceptions.RequestException:
                time.sleep(0.5)
        
        if not ready:
            pytest.fail("Container did not become ready in time.")
            
        yield f"http://{host}:{port}"


def test_container_builds_and_runs(app_container):
    """Test that the container starts up and serves the health endpoint.
    Since we didn't provide a real database, we expect a 503 with a 'database unavailable' detail.
    This proves the container env vars load, routing works, and Gunicorn is healthy.
    """
    res = requests.get(f"{app_container}/health")
    assert res.status_code == 200 or res.status_code == 503 
    
    # Since DB is fake, it's 503
    if res.status_code == 503:
        assert res.json() == {"status": "error", "detail": "database unavailable"}
    else:
        assert res.json() == {"status": "ok"}
