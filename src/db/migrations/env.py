import os

from alembic import context
from sqlalchemy import create_engine

from src.config import settings
from src.db.engine import Base

# Import all models so their tables are registered on Base.metadata
from src.models.user import User, UserHistory  # noqa: F401
from src.models.tenant import Tenant, TenantHistory  # noqa: F401
from src.models.service import Service, ServiceHistory  # noqa: F401
from src.models.service_credential import ServiceCredential, ServiceCredentialHistory  # noqa: F401

config = context.config
if config.config_file_name is not None:
    # Skip fileConfig — the alembic.ini logging section is incomplete and
    # we rely on src.bootstrap.logging.setup_logging() for the application.
    pass

target_metadata = Base.metadata

# Migrations run as the superuser. Fall back to DATABASE_URL so plain
# `alembic upgrade head` still works in environments that only set one URL.
_migration_url = os.environ.get("MIGRATION_DATABASE_URL") or settings.database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_migration_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_migration_url)
    with engine.begin() as connection:
        do_run_migrations(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
