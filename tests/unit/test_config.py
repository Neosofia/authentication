import pytest

from src.config import Settings

pytestmark = pytest.mark.unit

_BASE = dict(
    env="test",
    csrf_secret_key="test-csrf",
    workos_cookie_password="test-cookie-password-must-be-min-32-chars-long",
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
