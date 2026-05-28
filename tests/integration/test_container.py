import os
import subprocess
import time
import psycopg
import requests
import pytest
from testcontainers.core.container import DockerContainer
from testcontainers.postgres import PostgresContainer

pytestmark = [pytest.mark.integration, pytest.mark.slow]

# The image tag we'll build and use for testing
IMAGE_TAG = "auth-svc-test:latest"


def _normalize_to_psycopg_sqlalchemy_url(url: str) -> str:
    if url.startswith("postgresql+psycopg2://"):
        return url.replace("postgresql+psycopg2://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


def _replace_db_user(url: str, user: str, password: str) -> str:
    return url.replace("://test:test@", f"://{user}:{password}@", 1)


def _replace_db_host(url: str, host: str) -> str:
    return url.replace("@localhost:", f"@{host}:", 1)


def _normalize_to_psycopg_conn_url(url: str) -> str:
    return url.replace("postgresql+psycopg://", "postgresql://", 1)

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
    """Start app container with real Postgres but run migrations separately (Railway style)."""
    with PostgresContainer("postgres:18") as pg:
        migration_url_host = _normalize_to_psycopg_sqlalchemy_url(pg.get_connection_url())
        migration_url_container = _replace_db_host(migration_url_host, "host.docker.internal")
        app_url_container = _replace_db_user(
            migration_url_container, "app", "auth_app_password_123"
        )

        container = DockerContainer(IMAGE_TAG)
        container.with_kwargs(extra_hosts={"host.docker.internal": "host-gateway"})
        container.with_env("VALID_ROLES", "admin,user")
        container.with_env("JWT_PRIVATE_KEY_PEM", "DEFAULT_PRIVATE_KEY")
        container.with_env("JWT_PUBLIC_KEY_PEM", "DEFAULT_PUBLIC_KEY")
        container.with_env("APP_DATABASE_URL", app_url_container)
        container.with_env("MIGRATION_DATABASE_URL", migration_url_container)
        container.with_env("ENV", "test")
        container.with_env("CSRF_SECRET_KEY", "dummy_csrf_secret")
        container.with_env("WORKOS_API_KEY", "sk_test_dummy_key")
        container.with_env("WORKOS_CLIENT_ID", "client_test_dummy_id")
        container.with_env("WORKOS_COOKIE_PASSWORD", "dummy_cookie_password_32_chars_long_xxxxxx")
        container.with_env("WORKOS_REDIRECT_URI", "http://localhost:8014/callback")
        container.with_env("PORT", "7014")
        container.with_command("/bin/sh -c 'python -m gunicorn -c src/gunicorn.py src.app:app'")
        container.with_exposed_ports(7014)

        with container as c:
            port = c.get_exposed_port(7014)
            host = c.get_container_host_ip()
            base_url = f"http://{host}:{port}"
            start = time.time()
            while time.time() - start < 20:
                try:
                    requests.get(f"{base_url}/health", timeout=1)
                    break
                except requests.exceptions.RequestException:
                    time.sleep(0.5)
            else:
                pytest.fail("Container did not become ready in time.")
            app_url_host = _replace_db_user(migration_url_host, "app", "auth_app_password_123")
            yield {
                "base_url": base_url,
                "migration_url": migration_url_host,
                "app_url": app_url_host,
                "container_id": c.get_wrapped_container().id,
            }


def test_container_builds_and_runs(app_container):
    """Run migrations post-start, then assert health is fully ready."""
    subprocess.run(
        ["docker", "exec", app_container["container_id"], "python", "-m", "alembic", "upgrade", "head"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    # Verify auditing is correctly configured.
    with psycopg.connect(_normalize_to_psycopg_conn_url(app_container["migration_url"])) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT count(*)
                FROM public.services_history
                WHERE slug = 'authentication'
                  AND changed_by_uuid = '00000000-0000-7000-8000-000000000000'::uuid
                  AND changed_by_type = 2
                """
            )
            assert cur.fetchone()[0] == 1
    start = time.time()
    while time.time() - start < 20:
        try:
            res = requests.get(f"{app_container['base_url']}/health", timeout=1)
            if res.status_code == 200:
                assert res.json() == {"status": "ok"}
                return
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.5)
    pytest.fail("Health endpoint did not become ready after migration.")
