"""002 seed authentication service

Registers the authentication platform service and bootstraps its first service
credential with a randomly generated secret.

The plaintext secret is printed once during this migration. Only the bcrypt hash
is stored in ``service_credentials`` and cannot be recovered from the database.

Revision ID: 002
Revises: 001
Create Date: 2026-04-26
"""
from __future__ import annotations

import uuid

from alembic import op
import sqlalchemy as sa

from src.db.migrations.bootstrap_credentials import (
    announce_service_credential,
    generate_service_credential,
)

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None

SERVICE_NAME = "Authentication"
SERVICE_SLUG = "authentication"
SERVICE_BASE_URL = "http://authentication:8014"


def upgrade() -> None:
    # Use a well-known Nil-Epoch v7 UUID to represent the "System Migration Actor".
    # This provides auditors a deterministic story for how these rows were created.
    sys_uuid = uuid.UUID("00000000-0000-7000-8000-000000000000")

    conn = op.get_bind()
    service_uuid = conn.execute(
        sa.text(
            """
            INSERT INTO services (uuid, name, slug, base_url, changed_by_uuid, changed_by_type)
            VALUES (:uuid, :name, :slug, :base_url, :changed_by_uuid, :changed_by_type)
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
            changed_by_uuid=sys_uuid,
            changed_by_type=2,
        )
    ).scalar_one()

    plain_secret, hashed_secret = generate_service_credential()
    inserted_uuid = conn.execute(
        sa.text(
            """
            INSERT INTO service_credentials (uuid, service_uuid, hashed_secret, changed_by_uuid, changed_by_type)
            VALUES (:uuid, :service_uuid, :hashed_secret, :changed_by_uuid, :changed_by_type)
            ON CONFLICT (service_uuid) DO NOTHING
            RETURNING uuid
            """
        ).bindparams(
            uuid=uuid.uuid7(),
            service_uuid=service_uuid,
            hashed_secret=hashed_secret,
            changed_by_uuid=sys_uuid,
            changed_by_type=2,
        )
    ).scalar_one_or_none()

    if inserted_uuid is not None:
        announce_service_credential(SERVICE_SLUG, plain_secret)


def downgrade() -> None:
    raise NotImplementedError("Downgrade is disabled to preserve immutable audit history.")
