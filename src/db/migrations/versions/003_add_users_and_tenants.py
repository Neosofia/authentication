"""003 users and tenants

Revision ID: 003
Revises: 002
Create Date: 2026-05-19
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "idp_id",
            sa.Text(),
            nullable=False,
            comment="The unchanging provider tenant ID (e.g. WorkOS org_123)",
        ),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "display_code",
            sa.Text(),
            nullable=True,
            comment="Human-facing org shorthand (e.g. site number 1034)",
        ),
        sa.Column(
            "type",
            sa.Text(),
            nullable=True,
            comment="Org kind: platform, cro, sponsor, site, smo (ADR-0014)",
        ),
        sa.PrimaryKeyConstraint("uuid"),
        sa.UniqueConstraint("idp_id"),
    )

    op.create_table(
        "users",
        sa.Column("uuid", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "idp_id",
            sa.Text(),
            nullable=False,
            comment="The unchanging provider subject ID (e.g. WorkOS user_123)",
        ),
        sa.Column(
            "roles",
            postgresql.ARRAY(sa.Text()),
            nullable=False,
            server_default="{}",
            comment="Mirror of User registry roles (T2); updated on best-effort provision",
        ),
        sa.PrimaryKeyConstraint("uuid"),
        sa.UniqueConstraint("idp_id"),
    )


def downgrade() -> None:
    raise NotImplementedError("Downgrade is disabled to preserve immutable audit history.")
