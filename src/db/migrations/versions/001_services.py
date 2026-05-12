"""001 services and service credentials

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
        "services",
        sa.Column("uuid", sa.UUID(), nullable=False, server_default=sa.text("uuidv7()")),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("slug", sa.Text(), nullable=False),
        sa.Column("base_url", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("uuid"),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("slug"),
        sa.UniqueConstraint("base_url"),
    )
    op.create_index("ix_services_name", "services", ["name"])
    op.create_index("ix_services_slug", "services", ["slug"])

    op.create_table(
        "service_credentials",
        sa.Column("uuid", sa.UUID(), nullable=False, server_default=sa.text("uuidv7()")),
        sa.Column("service_uuid", sa.UUID(), sa.ForeignKey("services.uuid", ondelete="CASCADE"), nullable=False),
        sa.Column("hashed_secret", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("uuid"),
        sa.UniqueConstraint("service_uuid"),
    )
    op.create_index("ix_service_credentials_service_uuid", "service_credentials", ["service_uuid"])

def downgrade() -> None:
    # Downgrades that destroy tables are strictly prohibited to ensure the
    # immutability and preservation of forensic audit history.
    raise NotImplementedError("Downgrade is disabled to preserve immutable audit history.")
