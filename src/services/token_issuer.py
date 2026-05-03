import uuid
from datetime import datetime, timezone

import jwt

# Audience claim for JWT validation (RFC 7519 §4.1.3)
# Pins tokens to this service; downstream services validate against this
AUDIENCE = "neosofia-auth-svc"


def issue_token(
    sub: str,
    user_type: str,
    roles: list[str],
    tenant_id: str | None,
    ttl_secs: int,
    private_key_pem: str,
    issuer: str,
) -> str:
    """
    Sign and return a compact RS256 platform JWT.

    Claims:
      sub            — user ID or service name
      iss            — configured issuer URL
      aud            — intended audience (audience claim for security)
      iat / exp      — issued-at and expiry (epoch seconds)
      jti            — UUID v4 for replay detection
      neosofia:user_type  — clinician | patient | machine
      neosofia:roles      — list of roles (mirrors user_type for humans)
      neosofia:tenant_id  — org ID (omitted for patients and machine credentials)
    
    Ref: RFC 7519 (JWT Claims), Constitution §VII (stateless validation)
    """
    now = int(datetime.now(timezone.utc).timestamp())
    claims: dict = {
        "sub": sub,
        "iss": issuer,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + ttl_secs,
        "jti": str(uuid.uuid4()),
        "neosofia:user_type": user_type,
        "neosofia:roles": roles,
    }
    if tenant_id:
        claims["neosofia:tenant_id"] = tenant_id

    return jwt.encode(claims, private_key_pem, algorithm="RS256")
