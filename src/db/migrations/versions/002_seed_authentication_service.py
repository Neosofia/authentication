"""002 seed authentication service

Inserts a fixed service and credential for ``authentication`` used for manual local testing.
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

SERVICE_NAME = "Authentication"
SERVICE_SLUG = "authentication"
SERVICE_BASE_URL = "http://authentication:8014"

# Well-known dev/test secret — matches the value hard-coded in the test UI.
_SECRET = "secret"
_HASHED = bcrypt.hashpw(_SECRET.encode(), bcrypt.gensalt()).decode()


def upgrade() -> None:
    # Set standard audit context for standard bootstrap records
    # We use a well-known Nil-Epoch v7 UUID to represent the "System Migration Actor".
    # This provides auditors a deterministic story for how these rows were created.
    sys_uuid = "00000000-0000-7000-8000-000000000000"
    op.execute(f"SET LOCAL app.current_actor_uuid = '{sys_uuid}'")
    op.execute("SET LOCAL app.current_actor_type = '2'")  # Service

    conn = op.get_bind()
    service_uuid = conn.execute(
        sa.text(
            """
            INSERT INTO services (uuid, name, slug, base_url)
            VALUES (:uuid, :name, :slug, :base_url)
            ON CONFLICT (name) DO UPDATE
              SET slug = EXCLUDED.slug,
                  base_url = EXCLUDED.base_url
            RETURNING uuid
            """
        ).bindparams(
            uuid=uuid.uuid7(),
            name=SERVICE_NAME,
            slug=SERVICE_SLUG,
            base_url=SERVICE_BASE_URL,
        )
    ).scalar_one()

    conn.execute(
        sa.text(
            """
            INSERT INTO service_credentials (uuid, service_uuid, hashed_secret)
            VALUES (:uuid, :service_uuid, :hashed_secret)
            ON CONFLICT (service_uuid) DO UPDATE
              SET hashed_secret = EXCLUDED.hashed_secret
            """
        ).bindparams(
            uuid=uuid.uuid7(),
            service_uuid=service_uuid,
            hashed_secret=_HASHED,
        )
    )


def downgrade() -> None:
    raise NotImplementedError("Downgrade is disabled to preserve immutable audit history.")
