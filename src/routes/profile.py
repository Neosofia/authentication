from flask import Blueprint, jsonify, g
from authentication_in_the_middle.decorators import with_authentication

from src.config import settings
from src.bootstrap.extensions import csrf
from src.bootstrap.logging import log_event
from src.db.engine import SessionLocal
from src.models.user import User
from src.models.tenant import Tenant

bp = Blueprint("profile", __name__, url_prefix="/api")


@bp.route("/profile")
@csrf.exempt
@with_authentication(
    public_key=settings.jwt_public_key_pem,
    issuer=settings.jwt_issuer,
    audience=settings.jwt_web_audience,
    enforce_active_role=False
)
def profile():
    """
    Retrieve user profile and tenant details using the platform JWT.

    Verifies the Bearer token (RS256), then uses the `sub` (local user UUID) and
    `neosofia:tenant_uuid` (local tenant UUID) claims to fetch profile data from the
    local cache database.
    """
    claims = getattr(g, "jwt_claims", {})
    user_uuid = claims.get("sub")
    if not user_uuid:
        return jsonify({"error": "invalid token", "message": "Missing sub claim"}), 401

    tenant_uuid = claims.get(f"{settings.jwt_claim_namespace}:tenant_uuid")

    first_name = ""
    last_name = ""
    email = ""
    tenant_name = "Unknown Tenant"

    try:
        with SessionLocal() as db:
            user = db.scalar(select(User).filter_by(uuid=user_uuid))
            if user:
                first_name = user.first_name or ""
                last_name = user.last_name or ""
                email = user.email or ""
                
            if tenant_uuid:
                tenant = db.scalar(select(Tenant).filter_by(uuid=tenant_uuid))
                if tenant:
                    tenant_name = tenant.name
    except Exception as e:
        log_event("profile_db_fetch_failed", error_class=type(e).__name__, user_uuid=user_uuid)
        return jsonify({"error": "failed to fetch user profile"}), 503

    roles = claims.get(f"{settings.jwt_claim_namespace}:roles", [])

    return jsonify({
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "tenant_name": tenant_name,
        "roles": roles,
    })
