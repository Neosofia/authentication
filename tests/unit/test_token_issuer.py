"""
Unit tests for token_issuer module — pure JWT signing logic.
"""

import uuid
from datetime import datetime, timezone

import jwt as pyjwt
import pytest

from src.services.token_issuer import issue_token


@pytest.mark.unit
class TestIssueToken:
    """Tests for issue_token pure function."""

    def test_creates_valid_rs256_jwt(self, rsa_keys):
        """Issued JWT is valid RS256 and can be decoded with public key."""
        token = issue_token(
            sub="usr_123",
            user_type="clinician",
            roles=["clinician"],
            tenant_id="org_xyz",
            ttl_secs=900,
            private_key_pem=rsa_keys["private"],
            issuer="https://auth.test.local",
        )
        
        # Should decode without error
        claims = pyjwt.decode(
            token,
            rsa_keys["public"],
            algorithms=["RS256"],
            issuer="https://auth.test.local",
            audience="neosofia-auth-svc",
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
        assert claims is not None

    def test_includes_required_claims(self, rsa_keys):
        """JWT contains all required platform claims."""
        now_before = int(datetime.now(timezone.utc).timestamp())
        token = issue_token(
            sub="usr_123",
            user_type="clinician",
            roles=["clinician"],
            tenant_id="org_xyz",
            ttl_secs=900,
            private_key_pem=rsa_keys["private"],
            issuer="https://auth.test.local",
        )
        now_after = int(datetime.now(timezone.utc).timestamp())
        
        claims = pyjwt.decode(
            token,
            rsa_keys["public"],
            algorithms=["RS256"],
            issuer="https://auth.test.local",
            audience="neosofia-auth-svc",
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
        
        assert claims["sub"] == "usr_123"
        assert claims["iss"] == "https://auth.test.local"
        assert claims["aud"] == "neosofia-auth-svc"
        assert claims["neosofia:user_type"] == "clinician"
        assert claims["neosofia:roles"] == ["clinician"]
        assert claims["neosofia:tenant_id"] == "org_xyz"
        assert "jti" in claims
        assert "iat" in claims
        assert "exp" in claims
        
        # Verify expiry is correct
        assert claims["exp"] - claims["iat"] == 900
        assert now_before <= claims["iat"] <= now_after

    def test_jti_is_uuid(self, rsa_keys):
        """JWT ID is a valid UUID."""
        token = issue_token(
            sub="usr_123",
            user_type="clinician",
            roles=[],
            tenant_id=None,
            ttl_secs=900,
            private_key_pem=rsa_keys["private"],
            issuer="https://auth.test.local",
        )
        claims = pyjwt.decode(
            token,
            rsa_keys["public"],
            algorithms=["RS256"],
            issuer="https://auth.test.local",
            audience="neosofia-auth-svc",
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
        
        # Should not raise
        uuid.UUID(claims["jti"])

    def test_patient_has_no_tenant_claim(self, rsa_keys):
        """Patient tokens omit neosofia:tenant_id claim."""
        token = issue_token(
            sub="usr_patient",
            user_type="patient",
            roles=[],
            tenant_id=None,
            ttl_secs=900,
            private_key_pem=rsa_keys["private"],
            issuer="https://auth.test.local",
        )
        claims = pyjwt.decode(
            token,
            rsa_keys["public"],
            algorithms=["RS256"],
            issuer="https://auth.test.local",
            audience="neosofia-auth-svc",
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
        
        assert "neosofia:tenant_id" not in claims
        assert claims["neosofia:user_type"] == "patient"

    def test_service_token_empty_roles(self, rsa_keys):
        """Service tokens have empty roles list."""
        token = issue_token(
            sub="payment-svc",
            user_type="service",
            roles=[],
            tenant_id=None,
            ttl_secs=300,
            private_key_pem=rsa_keys["private"],
            issuer="https://auth.test.local",
        )
        claims = pyjwt.decode(
            token,
            rsa_keys["public"],
            algorithms=["RS256"],
            issuer="https://auth.test.local",
            audience="neosofia-auth-svc",
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
        
        assert claims["neosofia:user_type"] == "service"
        assert claims["neosofia:roles"] == []
        assert "neosofia:tenant_id" not in claims

    def test_ttl_affects_expiry(self, rsa_keys):
        """Different TTL values produce different expiry times."""
        token_900 = issue_token(
            sub="usr_123",
            user_type="clinician",
            roles=["clinician"],
            tenant_id="org_xyz",
            ttl_secs=900,
            private_key_pem=rsa_keys["private"],
            issuer="https://auth.test.local",
        )
        
        token_300 = issue_token(
            sub="usr_123",
            user_type="clinician",
            roles=["clinician"],
            tenant_id="org_xyz",
            ttl_secs=300,
            private_key_pem=rsa_keys["private"],
            issuer="https://auth.test.local",
        )
        
        claims_900 = pyjwt.decode(
            token_900,
            rsa_keys["public"],
            algorithms=["RS256"],
            issuer="https://auth.test.local",
            audience="neosofia-auth-svc",
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
        claims_300 = pyjwt.decode(
            token_300,
            rsa_keys["public"],
            algorithms=["RS256"],
            issuer="https://auth.test.local",
            audience="neosofia-auth-svc",
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
        
        assert claims_900["exp"] - claims_900["iat"] == 900
        assert claims_300["exp"] - claims_300["iat"] == 300

    def test_multiple_roles(self, rsa_keys):
        """JWT can contain multiple roles."""
        token = issue_token(
            sub="usr_clinician",
            user_type="clinician",
            roles=["clinician", "supervisor", "researcher"],
            tenant_id="org_xyz",
            ttl_secs=900,
            private_key_pem=rsa_keys["private"],
            issuer="https://auth.test.local",
        )
        claims = pyjwt.decode(
            token,
            rsa_keys["public"],
            algorithms=["RS256"],
            issuer="https://auth.test.local",
            audience="neosofia-auth-svc",
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
        
        assert set(claims["neosofia:roles"]) == {"clinician", "supervisor", "researcher"}

    def test_wrong_key_fails_verification(self, rsa_keys):
        """Token signed with key A fails verification with key B."""
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        from cryptography.hazmat.primitives import serialization as _ser
        
        other_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
        other_pem = other_key.private_bytes(
            _ser.Encoding.PEM,
            _ser.PrivateFormat.TraditionalOpenSSL,
            _ser.NoEncryption(),
        ).decode()
        
        token = issue_token(
            sub="usr_123",
            user_type="clinician",
            roles=["clinician"],
            tenant_id="org_xyz",
            ttl_secs=900,
            private_key_pem=other_pem,
            issuer="https://auth.test.local",
        )
        
        # Decode with wrong key should fail
        with pytest.raises(pyjwt.InvalidSignatureError):
            pyjwt.decode(token, rsa_keys["public"], algorithms=["RS256"])
