"""005 user service base url

Revision ID: 005
Revises: 004
Create Date: 2026-05-31
"""
from __future__ import annotations

import os

from alembic import op
import sqlalchemy as sa

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def _user_service_base_url() -> str:
    explicit = os.environ.get("USER_SERVICE_BASE_URL", "").strip()
    if explicit:
        return explicit.rstrip("/")
    # Docker Compose service name; set USER_SERVICE_BASE_URL in cloud migrate jobs.
    return "http://user:8018"


def upgrade() -> None:
    op.get_bind().execute(
        sa.text(
            """
            UPDATE services
            SET base_url = :base_url
            WHERE slug = 'user'
            """
        ).bindparams(base_url=_user_service_base_url())
    )


def downgrade() -> None:
    raise NotImplementedError("Downgrade is disabled to preserve immutable audit history.")
