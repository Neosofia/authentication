"""add users and tenants

Revision ID: 003
Revises: 002
Create Date: 2026-05-19
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None

def upgrade() -> None:
    # Tenants Table
    op.create_table('tenants',
        sa.Column('uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('idp_id', sa.Text(), nullable=False, comment='The unchanging provider tenant ID (e.g. WorkOS org_123)'),
        sa.Column('name', sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint('uuid'),
        sa.UniqueConstraint('idp_id')
    )
    
    # Users Table
    op.create_table('users',
        sa.Column('uuid', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('idp_id', sa.Text(), nullable=False, comment='The unchanging provider subject ID (e.g. WorkOS user_123)'),
        sa.Column('first_name', sa.Text(), nullable=True),
        sa.Column('last_name', sa.Text(), nullable=True),
        sa.Column('email', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('uuid'),
        sa.UniqueConstraint('idp_id')
    )

def downgrade() -> None:
    raise NotImplementedError("Downgrade is disabled to preserve immutable audit history.")
