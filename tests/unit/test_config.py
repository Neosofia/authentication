import pytest

from src.config import Settings

pytestmark = pytest.mark.unit

_BASE = dict(
    env="test",
    csrf_secret_key="test-csrf",
    workos_api_key="sk_test_dummy_key",
    workos_client_id="client_test_dummy_id",
    workos_cookie_password="test-cookie-password-must-be-min-32-chars-long",
    workos_redirect_uri="http://localhost:8014/callback",
    valid_roles="admin",
    jwt_private_key_pem="DEFAULT_PRIVATE_KEY",
    jwt_public_key_pem="DEFAULT_PUBLIC_KEY",
)

MIGRATION_URL = "postgresql+psycopg://auth:supersecret@localhost:5432/auth"
APP_URL = "postgresql+psycopg://app:appsecret@localhost:5432/auth"


def test_accepts_database_urls():
    Settings(
        **_BASE,
        migration_database_url=MIGRATION_URL,
        app_database_url=APP_URL,
    )


def test_rejects_blank_migration_database_url():
    with pytest.raises(ValueError, match="MIGRATION_DATABASE_URL must be set"):
        Settings(
            **_BASE,
            migration_database_url="",
            app_database_url=APP_URL,
        )


def test_rejects_blank_app_database_url():
    with pytest.raises(ValueError, match="APP_DATABASE_URL must be set"):
        Settings(
            **_BASE,
            migration_database_url=MIGRATION_URL,
            app_database_url="   ",
        )


def test_rejects_same_database_user():
    url = "postgresql+psycopg://auth:secret@localhost:5432/auth"
    with pytest.raises(ValueError, match="different users"):
        Settings(
            **_BASE,
            migration_database_url=url,
            app_database_url=url,
        )


def test_empty_env_int_uses_default(monkeypatch):
    """Railway and similar platforms inject empty strings for unset optional vars."""
    monkeypatch.setenv("PORT", "")
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "")
    settings = Settings(
        **_BASE,
        migration_database_url=MIGRATION_URL,
        app_database_url=APP_URL,
    )
    assert settings.port == 8014
    assert settings.trusted_proxy_hops == 1


def test_normalizes_empty_pgport_in_database_urls():
    settings = Settings(
        **_BASE,
        migration_database_url="postgresql+psycopg://auth:secret@db-host:/auth",
        app_database_url="postgresql+psycopg://app:secret@db-host:/auth",
    )
    assert "@db-host:5432/auth" in settings.migration_database_url
    assert "@db-host:5432/auth" in settings.app_database_url


def test_rejects_blank_required_env_var():
    with pytest.raises(ValueError, match="WORKOS_REDIRECT_URI must be set"):
        Settings(
            **{**_BASE, "workos_redirect_uri": ""},
            migration_database_url=MIGRATION_URL,
            app_database_url=APP_URL,
        )
