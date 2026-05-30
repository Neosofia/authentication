"""Shared helpers for bootstrapping service credentials in Alembic migrations."""

from __future__ import annotations

import os
import secrets

import bcrypt


def hash_service_credential(plain_secret: str) -> str:
    return bcrypt.hashpw(plain_secret.encode(), bcrypt.gensalt()).decode()


def generate_service_credential() -> tuple[str, str]:
    plain_secret = secrets.token_urlsafe(32)
    hashed_secret = hash_service_credential(plain_secret)
    return plain_secret, hashed_secret


def required_service_credential_from_env(env_var_name: str) -> tuple[str, str]:
    plain_secret = (os.environ.get(env_var_name) or "").strip()
    if not plain_secret:
        raise RuntimeError(
            f"{env_var_name} must be set before running this migration. "
            "Fix the environment and rerun Alembic; the operator must provision this secret manually."
        )
    return plain_secret, hash_service_credential(plain_secret)


def announce_service_credential(slug: str, plain_secret: str) -> None:
    print(
        f"[authentication bootstrap] service slug={slug!r} "
        f"client_id={slug!r} client_secret={plain_secret!r} "
        "(capture now; only the bcrypt hash is stored in service_credentials)"
    )
