"""000 init db

Revision ID: 000
Revises: 
Create Date: 2026-05-12
"""
import os

import sqlalchemy as sa
from alembic import op
from sqlalchemy.engine import make_url

from src.config import settings

revision = "000"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    app_password = make_url(settings.app_database_url).password
    conn = op.get_bind()
    quoted_password = conn.execute(
        sa.text("SELECT quote_literal(:password)"),
        {"password": app_password},
    ).scalar_one()

    # Migrations run as the superuser; the app connects as app (APP_DATABASE_URL).
    op.execute(
        f"""
        DO $$
        BEGIN
            CREATE ROLE app WITH LOGIN PASSWORD {quoted_password};
        EXCEPTION WHEN duplicate_object THEN NULL;
        END $$;
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            EXECUTE format(
                'GRANT CONNECT ON DATABASE %I TO app',
                current_database()
            );
        END $$;
        """
    )
    op.execute("GRANT USAGE ON SCHEMA public TO app")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE ON TABLES TO app"
    )

    template_dir = "/app/audit-templates"
    if not os.path.exists(template_dir):
        template_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../../../../templates/sql/audit")
        )

    for file in ("01_dml_hooks.sql", "02_ddl_setup.sql", "03_ddl_protection.sql", "04_views.sql"):
        file_path = os.path.join(template_dir, file)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Audit template not found: {file_path}")
        with open(file_path, "r") as f:
            op.execute(f.read())

    op.execute("GRANT USAGE ON SCHEMA audit TO app")


def downgrade() -> None:
    raise Exception(
        "000_init_db is irreversible — dropping the audit schema would destroy all audit history. "
        "To reset, drop and recreate the database."
    )
