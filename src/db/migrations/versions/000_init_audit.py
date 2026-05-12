"""000 init audit

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

def downgrade() -> None:
    op.execute("DROP SCHEMA IF EXISTS audit CASCADE")
