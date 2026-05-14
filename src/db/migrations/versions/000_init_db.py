"""000 init db

Revision ID: 000
Revises: 
Create Date: 2026-05-12
"""
import os
from alembic import op

revision = "000"
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Create restricted app role used by the running service.
    # Migrations run as the superuser (MIGRATION_DATABASE_URL); the app
    # connects as app (DATABASE_URL) which is fully subject to RLS.
    # In production, pre-create this role with a strong password before
    # running migrations — the DO block silently skips if it already exists.
    op.execute("""
        DO $$
        BEGIN
            CREATE ROLE app WITH LOGIN PASSWORD 'dev_only_app';
        EXCEPTION WHEN duplicate_object THEN NULL;
        END
        $$;
    """)
    op.execute("""
        DO $$
        BEGIN
            EXECUTE format(
                'GRANT CONNECT ON DATABASE %I TO app',
                current_database()
            );
        END
        $$;
    """)
    op.execute("GRANT USAGE ON SCHEMA public TO app")
    # All tables created by subsequent migrations automatically inherit these privileges.
    op.execute("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO app")

    template_dir = '/app/audit-templates'
    if not os.path.exists(template_dir):
        # Fallback for local development if running outside Docker
        template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../../templates/sql/audit'))
    
    files = ['01_dml_hooks.sql', '02_ddl_setup.sql', '03_ddl_protection.sql', '04_views.sql']
    for file in files:
        file_path = os.path.join(template_dir, file)
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                # Using execute to run the raw SQL blocks
                op.execute(f.read())
        else:
            raise FileNotFoundError(f"Audit template not found: {file_path}")

    # The audit trigger function lives in the audit schema — grant access so the
    # trigger can fire when app performs DML on tracked tables.
    op.execute("GRANT USAGE ON SCHEMA audit TO app")

def downgrade() -> None:
    raise Exception(
        "000_init_db is irreversible — dropping the audit schema would destroy all audit history. "
        "To reset, drop and recreate the database."
    )
