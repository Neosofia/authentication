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
    roles: list[str] | None,
    tenant_id: str | None,
    ttl_secs: int,
    private_key_pem: str,
    issuer: str,
    audience: str | list[str],
    claim_namespace: str = "neosofia",
    azp: str | None = None,
    public_key_pem: str | None = None,
    actor_uuid: str | None = None,
    tenant_uuid: str | None = None,
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
      {ns}:roles       — list of roles (absent for service tokens by default)
      {ns}:tenant_id   — WorkOS org ID (present for all human tokens)
      {ns}:actor_uuid  — platform UUID for the user (from WorkOS user external_id)
      {ns}:tenant_uuid — platform UUID for the org (from WorkOS org external_id)

    The claim namespace prefix (default "neosofia") is set via the
    JWT_CLAIM_NAMESPACE env var, allowing forks to use their own namespace
    without code changes.

    Ref: RFC 7519 (JWT Claims), Constitution §VII (scalability by design / stateless validation)
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
    }
    if roles is not None:
        claims[f"{ns}:roles"] = roles
    if azp:
        claims["azp"] = azp
    if tenant_id:
        claims[f"{ns}:tenant_id"] = tenant_id
    if actor_uuid:
        claims[f"{ns}:actor_uuid"] = actor_uuid
    if tenant_uuid:
        claims[f"{ns}:tenant_uuid"] = tenant_uuid

    headers = {}
    if public_key_pem:
        headers["kid"] = _compute_kid(public_key_pem)

    return jwt.encode(claims, private_key_pem, algorithm="RS256", headers=headers)
