from alembic import context
from importlib import import_module
from sqlalchemy import create_engine

from src.config import settings
from src.db.engine import Base

# Import all models so their tables are registered on Base.metadata.
# import_module keeps the import for Alembic metadata while avoiding
# unused local-name warnings from CodeQL.
import_module("src.models.user")
import_module("src.models.tenant")
import_module("src.models.service")
import_module("src.models.service_credential")

config = context.config
if config.config_file_name is not None:
    # Skip fileConfig — the alembic.ini logging section is incomplete and
    # we rely on src.bootstrap.logging.setup_logging() for the application.
    pass

target_metadata = Base.metadata

# Migrations run as the superuser; settings validates both database URLs on import.
_migration_url = settings.migration_database_url


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
