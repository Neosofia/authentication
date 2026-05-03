import uuid
from datetime import datetime, timezone

import jwt

# Audience claim for JWT validation (RFC 7519 §4.1.3)
# Pins tokens to this service; downstream services validate against this
AUDIENCE = "neosofia-auth-svc"


def issue_token(
    sub: str,
    token_type: str,
    roles: list[str],
    tenant_id: str | None,
    ttl_secs: int,
    private_key_pem: str,
    issuer: str,
    claim_namespace: str = "neosofia",
    azp: str | None = None,
) -> str:
    """
    Sign and return a compact RS256 platform JWT.

    Claims:
      sub              — user ID or service name (RFC 7519)
      iss              — configured issuer URL (RFC 7519)
      aud              — intended audience (RFC 7519)
      iat / exp        — issued-at and expiry (RFC 7519)
      jti              — UUID v4 for replay detection (RFC 7519)
      azp              — authorized party / client_id (machine tokens, RFC 7519)
      {ns}:token_type  — "human" | "machine"
      {ns}:token_version — integer schema version (increment on breaking changes)
      {ns}:roles       — list of roles (empty for machine tokens without org membership)
      {ns}:tenant_id   — org ID (omitted for machine credentials; present for all human tokens)

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
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + ttl_secs,
        "jti": str(uuid.uuid4()),
        f"{ns}:token_type": token_type,
        f"{ns}:token_version": 1,
        f"{ns}:roles": roles,
    }
    if azp:
        claims["azp"] = azp
    if tenant_id:
        claims[f"{ns}:tenant_id"] = tenant_id

    return jwt.encode(claims, private_key_pem, algorithm="RS256")
