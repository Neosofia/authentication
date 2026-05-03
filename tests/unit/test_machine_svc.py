"""
Unit tests for machine_svc — credential lookup, bcrypt verification, token issuance.

All DB I/O is mocked; bcrypt is exercised with real hashes to ensure the
constant-time comparison path is covered.
"""

import bcrypt
import pytest
from unittest.mock import MagicMock, patch

from src.services.machine_svc import InvalidClientError, issue_machine_token


def _make_credential(service_name: str, secret: str, active: bool = True) -> MagicMock:
    """Build a MagicMock that looks like a MachineCredential row."""
    cred = MagicMock()
    cred.service_name = service_name
    cred.hashed_secret = bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()
    cred.active = active
    return cred


def _db_with(credential):
    """Return a mock Session whose scalar_one_or_none returns *credential*."""
    mock_db = MagicMock()
    mock_db.execute.return_value.scalar_one_or_none.return_value = credential
    return mock_db


@pytest.mark.unit
class TestIssueMachineToken:

    def test_valid_credential_returns_token(self, rsa_keys):
        """Valid service name + matching secret → token_issuer is called and result returned."""
        cred = _make_credential("payment-svc", "correct-secret")
        db = _db_with(cred)

        with patch("src.services.machine_svc.token_issuer.issue_token", return_value="signed.jwt.token"):
            token = issue_machine_token("payment-svc", "correct-secret", db)

        assert token == "signed.jwt.token"

    def test_unknown_service_raises_invalid_client(self):
        """Service not in DB → InvalidClientError, not a timing leak."""
        db = _db_with(None)  # scalar_one_or_none returns None

        with pytest.raises(InvalidClientError):
            issue_machine_token("ghost-svc", "any-secret", db)

    def test_wrong_secret_raises_invalid_client(self):
        """Correct service name but wrong secret → InvalidClientError."""
        cred = _make_credential("payment-svc", "real-secret")
        db = _db_with(cred)

        with pytest.raises(InvalidClientError):
            issue_machine_token("payment-svc", "wrong-secret", db)

    def test_inactive_credential_raises_invalid_client(self):
        """Active=False credential is treated same as missing → InvalidClientError."""
        # The query filters active=True, so scalar_one_or_none returns None for inactive rows.
        db = _db_with(None)

        with pytest.raises(InvalidClientError):
            issue_machine_token("payment-svc", "correct-secret", db)

    def test_issued_token_is_machine_type(self, app, rsa_keys):
        """Token issued for machine credential carries token_type=machine claim."""
        import jwt as pyjwt
        from src.config import settings

        cred = _make_credential("audit-svc", "s3cr3t")
        db = _db_with(cred)

        # Patch machine_svc's reference to settings to use the real keys loaded by the app fixture
        with patch("src.services.machine_svc.settings") as mock_settings:
            mock_settings.jwt_private_key_pem = rsa_keys["private"]
            mock_settings.jwt_issuer = settings.jwt_issuer
            mock_settings.jwt_claim_namespace = settings.jwt_claim_namespace
            mock_settings.machine_token_ttl_secs = 300
            token = issue_machine_token("audit-svc", "s3cr3t", db)

        claims = pyjwt.decode(
            token,
            rsa_keys["public"],
            algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False},
        )
        assert claims["neosofia:token_type"] == "machine"
        assert claims["sub"] == "audit-svc"
        assert claims["azp"] == "audit-svc"
        assert claims["neosofia:roles"] == []

    def test_unknown_service_still_calls_bcrypt(self):
        """Constant-time path: dummy bcrypt.checkpw is called even for unknown service."""
        db = _db_with(None)

        with patch("src.services.machine_svc.bcrypt.checkpw") as mock_checkpw:
            mock_checkpw.return_value = True  # return value irrelevant; we just count calls
            with pytest.raises(InvalidClientError):
                issue_machine_token("ghost-svc", "any", db)
            mock_checkpw.assert_called_once()
