import jwt as pyjwt
from flask import Blueprint, jsonify, request

from src.config import settings
from src.bootstrap.extensions import csrf, workos_client
from src.bootstrap.logging import log_event

bp = Blueprint("profile", __name__, url_prefix="/api")


@bp.route("/profile")
@csrf.exempt
def profile():
    """
    Retrieve user profile and organization details using the platform JWT.

    Verifies the Bearer token (RS256), then uses the `sub` (WorkOS user ID) and
    `neosofia:tenant_id` (org ID) claims to call WorkOS directly — no session
    cookie unseal required.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "unauthenticated"}), 401

    raw_token = auth_header[7:]
    try:
        decoded = pyjwt.decode(
            raw_token,
            settings.jwt_public_key_pem,
            algorithms=["RS256"],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
    except pyjwt.ExpiredSignatureError:
        return jsonify({"error": "token expired"}), 401
    except pyjwt.InvalidTokenError:
        return jsonify({"error": "invalid token"}), 401

    user_id = decoded.get("sub")
    if not user_id:
        return jsonify({"error": "invalid token", "message": "Missing sub claim"}), 401

    tenant_id = decoded.get(f"{settings.jwt_claim_namespace}:tenant_id")

    try:
        wos_user = workos_client.user_management.get_user(user_id)
        first_name = getattr(wos_user, "first_name", "") or ""
        last_name = getattr(wos_user, "last_name", "") or ""
        email = getattr(wos_user, "email", "") or ""
    except Exception as e:
        log_event("workos_user_fetch_failed", error_class=type(e).__name__, user_id=user_id)
        return jsonify({"error": "failed to fetch user profile"}), 503

    org_name = "Unknown Organization"
    if tenant_id:
        try:
            org = workos_client.organizations.get_organization(tenant_id)
            org_name = org.name
        except Exception as e:
            log_event("workos_org_fetch_failed", error_class=type(e).__name__, org_id=tenant_id)

    roles = decoded.get(f"{settings.jwt_claim_namespace}:roles", [])

    return jsonify({
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "organization_name": org_name,
        "roles": roles,
    })
