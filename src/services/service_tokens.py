import bcrypt
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.config import settings
from src.bootstrap.logging import log_event
from src.models.service import Service
from src.models.service_credential import ServiceCredential
from src.services import tokens


class InvalidClientError(Exception):
    pass


# Pre-compute a dummy bcrypt hash at module load time for constant-time comparison (CWE-208 mitigation)
# This prevents timing side-channels when verifying unknown service credentials
_DUMMY_SECRET = b"dummy_secret_for_timing_constant_verification"
_DUMMY_HASH = bcrypt.hashpw(_DUMMY_SECRET, bcrypt.gensalt())


def issue_service_token(
    service_name: str,
    client_secret: str,
    db: Session,
    audience: str | None = None,
) -> str:
    """
    Verify a service credential and issue a platform JWT with user_type='service'.
    Raises InvalidClientError (→ 401) on any mismatch or inactive credential.
    Uses constant-time comparison to prevent timing attacks (CWE-208).
    """
    result = db.execute(
        select(ServiceCredential)
        .join(Service, ServiceCredential.service_uuid == Service.uuid)
        .where(
            Service.slug == service_name,
        )
    )
    credential = result.scalar_one_or_none()

    if credential is None:
        # Use pre-computed dummy hash to maintain constant timing for all requests
        bcrypt.checkpw(_DUMMY_SECRET, _DUMMY_HASH)
        log_event("service_auth_failure", reason="unknown_service", service=service_name)
        raise InvalidClientError("invalid_client")

    secret_bytes = client_secret.encode("utf-8")
    hashed_bytes = credential.hashed_secret.encode("utf-8")

    if not bcrypt.checkpw(secret_bytes, hashed_bytes):
        log_event("service_auth_failure", reason="bad_secret", service=service_name)
        raise InvalidClientError("invalid_client")

    token = tokens.issue_token(
        sub=service_name,
        token_type="service",
        roles=[],
        tenant_id=None,
        ttl_secs=settings.service_token_ttl_secs,
        private_key_pem=settings.jwt_private_key_pem,
        issuer=settings.jwt_issuer,
        audience=audience or settings.jwt_audience,
        claim_namespace=settings.jwt_claim_namespace,
        azp=service_name,
        public_key_pem=settings.jwt_public_key_pem,
    )
    log_event("service_token_issued", service=service_name)
    return token
