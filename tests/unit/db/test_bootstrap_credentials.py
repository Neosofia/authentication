import bcrypt
import pytest

from src.db.migrations.bootstrap_credentials import (
    generate_service_credential,
    required_service_credential_from_env,
)


def test_generate_service_credential_round_trips_with_bcrypt():
    plain_secret, hashed_secret = generate_service_credential()

    assert plain_secret
    assert bcrypt.checkpw(plain_secret.encode(), hashed_secret.encode())


def test_required_service_credential_from_env_hashes_existing_secret(monkeypatch):
    monkeypatch.setenv("AUTHENTICATION_CLIENT_SECRET", "env-sourced-secret")

    plain_secret, hashed_secret = required_service_credential_from_env("AUTHENTICATION_CLIENT_SECRET")

    assert plain_secret == "env-sourced-secret"
    assert bcrypt.checkpw(plain_secret.encode(), hashed_secret.encode())


def test_required_service_credential_from_env_rejects_blank_env_var(monkeypatch):
    monkeypatch.delenv("AUTHENTICATION_CLIENT_SECRET", raising=False)

    with pytest.raises(RuntimeError, match="AUTHENTICATION_CLIENT_SECRET must be set"):
        required_service_credential_from_env("AUTHENTICATION_CLIENT_SECRET")
