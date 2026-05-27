"""Shared helpers for bootstrapping service credentials in Alembic migrations."""

from __future__ import annotations

import secrets

import bcrypt


def generate_service_credential() -> tuple[str, str]:
    plain_secret = secrets.token_urlsafe(32)
    hashed_secret = bcrypt.hashpw(plain_secret.encode(), bcrypt.gensalt()).decode()
    return plain_secret, hashed_secret


def announce_service_credential(slug: str, plain_secret: str) -> None:
    print(
        f"[authentication bootstrap] service slug={slug!r} "
        f"client_id={slug!r} client_secret={plain_secret!r} "
        "(capture now; only the bcrypt hash is stored in service_credentials)"
    )
