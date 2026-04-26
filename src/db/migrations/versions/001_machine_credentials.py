"""001 machine credentials

Revision ID: 001
Revises:
Create Date: 2026-04-20
"""
from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "machine_credentials",
        sa.Column("client_uuid", sa.UUID(), nullable=False, server_default=sa.text("gen_random_uuid()")),
        sa.Column("service_name", sa.Text(), nullable=False),
        sa.Column("hashed_secret", sa.Text(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("client_uuid"),
        sa.UniqueConstraint("service_name"),
    )
    op.create_index("ix_machine_credentials_service_name", "machine_credentials", ["service_name"])


def downgrade() -> None:
    op.drop_index("ix_machine_credentials_service_name", table_name="machine_credentials")
    op.drop_table("machine_credentials")
