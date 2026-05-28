#!/usr/bin/env python3
"""Bootstrap a .env for the authentication service.

Usage:
    cd authentication
    uv run python scripts/setup-env.py              # host dev (localhost:5014)
    uv run python scripts/setup-env.py --for-compose  # full stack in Docker

Copies .env.example → .env (unless .env exists and --force is not set), then generates:
  CSRF_SECRET_KEY, WORKOS_COOKIE_PASSWORD, JWT keypair, POSTGRES_PASSWORD,
  MIGRATION_DATABASE_URL password, and APP_DATABASE_URL password.

Environment:
    ENV_FILE  Deprecated alias for --env-file (default: <service>/.env)
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import secrets
import sys
from pathlib import Path
from urllib.parse import quote

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.engine import make_url

SERVICE_DIR = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = SERVICE_DIR / ".env.example"
POSTGRES_EXAMPLE = SERVICE_DIR / ".env.postgres.example"
POSTGRES_FILE = SERVICE_DIR / ".env.postgres"
COMPOSE_DB_HOST = "auth-postgres"
COMPOSE_DB_PORT = 5432


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bootstrap authentication service .env")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing .env and regenerate all secrets",
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        default=None,
        help="Target env file path (default: <service>/.env)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print the env file to stdout after writing (for docker compose run redirects)",
    )
    parser.add_argument(
        "--for-compose",
        action="store_true",
        help="Point database URLs at auth-postgres:5432 for docker compose up",
    )
    return parser.parse_args()


def _set_env_line(content: str, key: str, value: str) -> str:
    pattern = rf"^{re.escape(key)}=.*$"
    replacement = f"{key}={value}"
    if re.search(pattern, content, flags=re.MULTILINE):
        return re.sub(pattern, replacement, content, count=1, flags=re.MULTILINE)
    return content.rstrip() + f"\n{replacement}\n"


def _read_env_value(content: str, key: str) -> str:
    match = re.search(rf"^{re.escape(key)}=(.*)$", content, flags=re.MULTILINE)
    return match.group(1).strip() if match else ""


def _read_database_url(content: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}=(.*)$", content, flags=re.MULTILINE)
    return match.group(1).strip() if match else None


def _log(message: str, *, stdout_mode: bool) -> None:
    stream = sys.stderr if stdout_mode else sys.stdout
    print(message, file=stream)


def _copy_example(env_file: Path, example: Path, force: bool, *, stdout_mode: bool) -> None:
    if env_file.exists() and not force:
        _log(f"{env_file.name} already exists — skipping copy (use --force to overwrite)", stdout_mode=stdout_mode)
        return
    env_file.write_text(example.read_text())
    _log(f"Created {env_file.name} from {example.name}", stdout_mode=stdout_mode)


def _generate_secrets(content: str, *, stdout_mode: bool) -> str:
    content = _set_env_line(content, "CSRF_SECRET_KEY", secrets.token_hex(32))
    _log("Generated CSRF_SECRET_KEY", stdout_mode=stdout_mode)

    cookie_password = base64.urlsafe_b64encode(os.urandom(32)).decode()
    content = _set_env_line(content, "WORKOS_COOKIE_PASSWORD", cookie_password)
    _log("Generated WORKOS_COOKIE_PASSWORD", stdout_mode=stdout_mode)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    content = _set_env_line(
        content,
        "JWT_PRIVATE_KEY_PEM",
        base64.b64encode(private_pem.encode()).decode(),
    )
    content = _set_env_line(
        content,
        "JWT_PUBLIC_KEY_PEM",
        base64.b64encode(public_pem.encode()).decode(),
    )
    _log("Generated JWT_PRIVATE_KEY_PEM / JWT_PUBLIC_KEY_PEM as Base64 strings", stdout_mode=stdout_mode)
    return content


def _maybe_generate_postgres_password(force: bool, *, stdout_mode: bool) -> str | None:
    if not POSTGRES_EXAMPLE.exists():
        return None

    _copy_example(POSTGRES_FILE, POSTGRES_EXAMPLE, force, stdout_mode=stdout_mode)
    content = POSTGRES_FILE.read_text()
    password = _read_env_value(content, "POSTGRES_PASSWORD")
    if password and not force:
        return password

    password = secrets.token_hex(32)
    POSTGRES_FILE.write_text(_set_env_line(content, "POSTGRES_PASSWORD", password))
    _log("Generated POSTGRES_PASSWORD in .env.postgres", stdout_mode=stdout_mode)
    return password


def _rewrite_database_urls_for_compose(content: str) -> str:
    for key in ("MIGRATION_DATABASE_URL", "APP_DATABASE_URL"):
        raw_url = _read_database_url(content, key)
        if raw_url is None:
            continue
        url = make_url(raw_url)
        content = _set_env_line(
            content,
            key,
            str(url.set(host=COMPOSE_DB_HOST, port=COMPOSE_DB_PORT)),
        )
    return content


def _maybe_set_database_url_password(
    content: str,
    key: str,
    password: str,
    force: bool,
    *,
    stdout_mode: bool,
) -> str:
    raw_url = _read_database_url(content, key)
    if raw_url is None:
        return content

    url = make_url(raw_url)
    if url.password and not force:
        _log(f"{key} already configured — skipping password generation", stdout_mode=stdout_mode)
        return content

    encoded_password = quote(password, safe="")
    updated = str(url.set(password=encoded_password))
    _log(f"Generated {key} password", stdout_mode=stdout_mode)
    return _set_env_line(content, key, updated)


def main() -> int:
    args = _parse_args()
    env_file = args.env_file
    if env_file is None:
        env_file = Path(os.environ.get("ENV_FILE", SERVICE_DIR / ".env"))

    if not ENV_EXAMPLE.exists():
        print(f"Missing {ENV_EXAMPLE}", file=sys.stderr)
        return 1

    _copy_example(env_file, ENV_EXAMPLE, args.force, stdout_mode=args.stdout)
    content = env_file.read_text()
    if args.for_compose:
        content = _rewrite_database_urls_for_compose(content)
        _log(
            f"Database URLs use {COMPOSE_DB_HOST}:{COMPOSE_DB_PORT} (--for-compose)",
            stdout_mode=args.stdout,
        )
    content = _generate_secrets(content, stdout_mode=args.stdout)

    postgres_password = _maybe_generate_postgres_password(args.force, stdout_mode=args.stdout)
    if postgres_password:
        content = _maybe_set_database_url_password(
            content,
            "MIGRATION_DATABASE_URL",
            postgres_password,
            args.force,
            stdout_mode=args.stdout,
        )

    app_password = secrets.token_hex(32)
    content = _maybe_set_database_url_password(
        content,
        "APP_DATABASE_URL",
        app_password,
        args.force,
        stdout_mode=args.stdout,
    )
    env_file.write_text(content)

    if args.stdout:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")
        return 0

    print()
    print("✓ .env is ready.")
    print()
    print("Still required — fill these in manually:")
    print("  WORKOS_CLIENT_ID  — WorkOS Dashboard → API Keys")
    print("  WORKOS_API_KEY    — WorkOS Dashboard → API Keys")
    print()
    print("Then start the service:")
    if args.for_compose:
        print("  docker compose up -d auth-postgres authentication")
    else:
        print("  docker compose up -d auth-postgres")
        print("  uv run alembic upgrade head")
        print("  uv run python -m gunicorn -c src/gunicorn.py src.app:app")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
