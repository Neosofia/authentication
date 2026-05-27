import bcrypt

from src.db.migrations.bootstrap_credentials import generate_service_credential


def test_generate_service_credential_round_trips_with_bcrypt():
    plain_secret, hashed_secret = generate_service_credential()

    assert plain_secret
    assert bcrypt.checkpw(plain_secret.encode(), hashed_secret.encode())
