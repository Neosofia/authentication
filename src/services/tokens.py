import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import cast

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

def _compute_kid(public_key_pem: str) -> str:
    """Compute the RFC 7638 JWK Thumbprint for a given RSA public key."""
    pub_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(pub_key, RSAPublicKey):
        raise TypeError("public key must be an RSA public key")
    pub_numbers = cast(RSAPublicKey, pub_key).public_numbers()

    def _b64url_uint(n: int) -> str:
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    n_b64 = _b64url_uint(pub_numbers.n)
    e_b64 = _b64url_uint(pub_numbers.e)

    thumbprint_data = json.dumps(
        {"e": e_b64, "kty": "RSA", "n": n_b64},
        separators=(",", ":"),
        sort_keys=True,
    )
    thumbprint_hash = hashlib.sha256(thumbprint_data.encode()).digest()
    return base64.urlsafe_b64encode(thumbprint_hash).rstrip(b"=").decode()


def issue_token(
    sub: str,
    token_type: str,
    roles: list[str],
    tenant_id: str | None,
    ttl_secs: int,
    private_key_pem: str,
    issuer: str,
    audience: str,
    claim_namespace: str = "neosofia",
    azp: str | None = None,
    public_key_pem: str | None = None,
) -> str:
    """
    Sign and return a compact RS256 platform JWT.

    Claims:
      sub              — user ID or service name (RFC 7519)
      iss              — configured issuer URL (RFC 7519)
      aud              — intended audience (RFC 7519)
      iat / exp        — issued-at and expiry (RFC 7519)
      jti              — UUID v7 for replay detection (RFC 7519)
      azp              — authorized party / client_id (service tokens, RFC 7519)
      {ns}:token_type  — "human" | "service"
      {ns}:token_version — integer schema version (increment on breaking changes)
      {ns}:roles       — list of roles (empty for service tokens without org membership)
      {ns}:tenant_id   — org ID (omitted for service credentials; present for all human tokens)

    The claim namespace prefix (default "neosofia") is set via the
    JWT_CLAIM_NAMESPACE env var, allowing forks to use their own namespace
    without code changes.

    Ref: RFC 7519 (JWT Claims), Constitution §VII (stateless validation)
    """
    now = int(datetime.now(timezone.utc).timestamp())
    ns = claim_namespace
    claims: dict = {
        "sub": sub,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + ttl_secs,
        "jti": str(uuid.uuid7()),
        f"{ns}:token_type": token_type,
        f"{ns}:token_version": 1,
        f"{ns}:roles": roles,
    }
    if azp:
        claims["azp"] = azp
    if tenant_id:
        claims[f"{ns}:tenant_id"] = tenant_id

    headers = {}
    if public_key_pem:
        headers["kid"] = _compute_kid(public_key_pem)

    return jwt.encode(claims, private_key_pem, algorithm="RS256", headers=headers)
