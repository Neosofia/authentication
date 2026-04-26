"""002 seed test service credential

Inserts a fixed machine credential for ``test-service`` used for manual testing.
The secret is ``secret`` — this is intentionally a well-known dev/test credential,
not a production secret.

Revision ID: 002
Revises: 001
Create Date: 2026-04-26
"""
from __future__ import annotations

import uuid

import bcrypt
from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None

SERVICE_NAME = "test-service"
# Well-known dev/test secret — matches the value hard-coded in the test UI.
_SECRET = "secret"
_HASHED = bcrypt.hashpw(_SECRET.encode(), bcrypt.gensalt()).decode()


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            INSERT INTO machine_credentials (client_uuid, service_name, hashed_secret, active)
            VALUES (:uuid, :service_name, :hashed_secret, true)
            ON CONFLICT (service_name) DO UPDATE
              SET hashed_secret = EXCLUDED.hashed_secret,
                  active = true
            """
        ).bindparams(
            uuid=uuid.uuid4(),
            service_name=SERVICE_NAME,
            hashed_secret=_HASHED,
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text("DELETE FROM machine_credentials WHERE service_name = :name").bindparams(
            name=SERVICE_NAME
        )
    )
