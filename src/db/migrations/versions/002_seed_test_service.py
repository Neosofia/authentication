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
    # Set standard audit context for standard bootstrap records
    # We use a well-known Nil-Epoch v7 UUID to represent the "System Migration Actor".
    # This provides auditors a deterministic story for how these rows were created.
    sys_uuid = "00000000-0000-7000-8000-000000000000"
    op.execute(f"SET LOCAL app.current_actor_uuid = '{sys_uuid}'")
    op.execute("SET LOCAL app.current_actor_type = '2'")  # Service

    op.execute(
        sa.text(
            """
            INSERT INTO machine_credentials (uuid, service_name, hashed_secret, active)
            VALUES (:uuid, :service_name, :hashed_secret, true)
            ON CONFLICT (service_name) DO UPDATE
              SET hashed_secret = EXCLUDED.hashed_secret,
                  active = true
            """
        ).bindparams(
            uuid=uuid.uuid7(),
            service_name=SERVICE_NAME,
            hashed_secret=_HASHED,
        )
    )


def downgrade() -> None:
    raise NotImplementedError("Downgrade is disabled to preserve immutable audit history.")
