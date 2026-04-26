import asyncio
import os

from dotenv import load_dotenv
from alembic import context

from src.env import get_env_file_path

load_dotenv(get_env_file_path())  # loads the selected env file from cwd before anything reads env vars
from sqlalchemy.ext.asyncio import create_async_engine

from src.db.engine import Base

# Import all models so their tables are registered on Base.metadata
import src.models  # noqa: F401

config = context.config
if config.config_file_name is not None:
    # Skip fileConfig — the alembic.ini logging section is incomplete and
    # we rely on src.logging_config.setup_logging() for the application.
    pass

target_metadata = Base.metadata


def get_url() -> str:
    url = os.getenv("DATABASE_URL", "")
    if not url:
        raise ValueError("DATABASE_URL environment variable is required")
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=get_url(),
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


async def run_async_migrations() -> None:
    engine = create_async_engine(get_url())
    async with engine.begin() as conn:
        await conn.run_sync(do_run_migrations)
    await engine.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
