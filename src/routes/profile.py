from authorization_in_the_middle.security import with_security
from flask import Blueprint, g, jsonify
from sqlalchemy import select

from src.bootstrap.capabilities import Capabilities
from src.bootstrap.logging import log_exception
from src.config import settings
from src.db.engine import SessionLocal
from src.models.tenant import Tenant
from src.models.user import User

bp = Blueprint("profile", __name__, url_prefix="/api/v1/profiles")


@bp.route("/<profile_id>", methods=["GET"])
@with_security(
    action=Capabilities.PROFILE_READ,
    rate_limit="60 per minute",
    enforce_active_role=False,
)
def profile(profile_id: str):
    """
    Retrieve user profile and tenant details for the given profile id (platform user UUID).

    Verifies the Bearer token (RS256), then loads identity and tenant rows from the local cache.
    """
    claims = getattr(g, "jwt_claims", {})
    tenant_uuid = claims.get(f"{settings.jwt_claim_namespace}:tenant_uuid")

    first_name = ""
    last_name = ""
    email = ""
    tenant_name = "Unknown Tenant"

    try:
        with SessionLocal() as db:
            user = db.scalar(select(User).filter_by(uuid=profile_id))
            if user:
                first_name = user.first_name or ""
                last_name = user.last_name or ""
                email = user.email or ""

            if tenant_uuid:
                tenant = db.scalar(select(Tenant).filter_by(uuid=tenant_uuid))
                if tenant:
                    tenant_name = tenant.name
    except Exception as e:
        log_exception("profile_db_fetch_failed", e, user_uuid=profile_id)
        return jsonify({"error": "failed to fetch user profile"}), 503

    roles = claims.get(f"{settings.jwt_claim_namespace}:roles", [])
    tier1_roles = roles if isinstance(roles, list) else []
    is_operator = "operator" in tier1_roles

    body = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "tenant_uuid": tenant_uuid,
        "tenant_name": tenant_name,
        "roles": tier1_roles,
    }
    if is_operator and user:
        body["uuid"] = profile_id
        body["idp_id"] = user.idp_id

    return jsonify(body)
