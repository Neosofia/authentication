"""004 register user service

Revision ID: 004
Revises: 003
Create Date: 2026-05-29
"""
from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None

SERVICE_NAME = "User Service"
SERVICE_SLUG = "user"
SERVICE_BASE_URL = "http://user:8018"


def upgrade() -> None:
    sys_uuid = uuid.UUID("00000000-0000-7000-8000-000000000000")
    op.get_bind().execute(
        sa.text(
            """
            INSERT INTO services (uuid, name, slug, base_url, changed_by_uuid, changed_by_type)
            VALUES (:uuid, :name, :slug, :base_url, :changed_by_uuid, :changed_by_type)
            ON CONFLICT (slug) DO UPDATE
              SET name = EXCLUDED.name,
                  base_url = EXCLUDED.base_url
            """
        ).bindparams(
            uuid=uuid.uuid7(),
            name=SERVICE_NAME,
            slug=SERVICE_SLUG,
            base_url=SERVICE_BASE_URL,
            changed_by_uuid=sys_uuid,
            changed_by_type=2,
        )
    )


def downgrade() -> None:
    raise NotImplementedError("Downgrade is disabled to preserve immutable audit history.")