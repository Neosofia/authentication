import uuid
from datetime import datetime, timezone

import jwt

from src.services.jwks import compute_kid


def issue_token(
    sub: str,
    token_type: str,
    actors: list[str] | None,
    tenant_uuid: str | None,
    ttl_secs: int,
    private_key_pem: str,
    audience: str | list[str],
    claim_namespace: str = "neosofia",
    azp: str | None = None,
    public_key_pem: str | None = None,
    tenant_type: str | None = None,
    roles: list[str] | None = None,
    service_uuid: str | None = None,
) -> str:
    """
    Sign and return a compact RS256 platform JWT.

    Claims:
      sub              — platform UUID for the user or service name (RFC 7519)
      aud              — intended audience (RFC 7519)
      iat / exp        — issued-at and expiry (RFC 7519)
      jti              — UUID v7 for replay detection (RFC 7519)
      azp              — authorized party / client_id (service tokens, RFC 7519)
      {ns}:token_type  — "human" | "service"
      {ns}:token_version — integer schema version (increment on breaking changes)
      {ns}:service_uuid — platform registry UUID for service tokens (audit attribution)
      {ns}:actors      — Tier-1 actor classes (operator, clinician, patient)
      {ns}:roles       — Tier-2 role short names within tenant_type (e.g. admin, audit)
      {ns}:tenant_uuid — platform UUID for the org (present for all human tokens)
      {ns}:tenant_type — org kind (platform, cro, sponsor, site, smo)

    The claim namespace prefix (default "neosofia") is set via the
    JWT_CLAIM_NAMESPACE env var, allowing forks to use their own namespace
    without code changes.

    Ref: RFC 7519 (JWT Claims), Constitution §VII (scalability by design / stateless validation)
    """
    now = int(datetime.now(timezone.utc).timestamp())
    ns = claim_namespace
    claims: dict = {
        "sub": sub,
        "aud": audience,
        "iat": now,
        "exp": now + ttl_secs,
        "jti": str(uuid.uuid7()),
        f"{ns}:token_type": token_type,
        f"{ns}:token_version": 1,
    }
    if actors is not None:
        claims[f"{ns}:actors"] = actors
    if azp:
        claims["azp"] = azp
    if tenant_uuid:
        claims[f"{ns}:tenant_uuid"] = tenant_uuid
    if tenant_type:
        claims[f"{ns}:tenant_type"] = tenant_type
    if roles is not None:
        claims[f"{ns}:roles"] = roles
    if service_uuid:
        claims[f"{ns}:service_uuid"] = service_uuid

    headers = {}
    if public_key_pem:
        headers["kid"] = compute_kid(public_key_pem)

    return jwt.encode(claims, private_key_pem, algorithm="RS256", headers=headers)
