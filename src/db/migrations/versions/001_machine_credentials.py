"""001 machine credentials

Revision ID: 001
Revises:
Create Date: 2026-04-20
"""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = "000"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "machine_credentials",
        sa.Column("uuid", sa.UUID(), nullable=False, server_default=sa.text("uuidv7()")),
        sa.Column("service_name", sa.Text(), nullable=False),
        sa.Column("hashed_secret", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.PrimaryKeyConstraint("uuid"),
        sa.UniqueConstraint("service_name"),
    )
    op.create_index("ix_machine_credentials_service_name", "machine_credentials", ["service_name"])

def downgrade() -> None:
    # Downgrades that destroy tables are strictly prohibited to ensure the
    # immutability and preservation of forensic audit history.
    raise NotImplementedError("Downgrade is disabled to preserve immutable audit history.")
