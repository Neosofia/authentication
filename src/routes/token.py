import base64

import jwt as pyjwt
from flask import Blueprint, jsonify, make_response, request

from src.config import settings
from src.db.engine import SessionLocal
from src.bootstrap.extensions import limiter
from src.bootstrap.logging import exc_type_name, log_event, log_exception
from src.services.cookies import IDP_SESSION_COOKIE_NAME, set_idp_session_cookie
from src.services.idp import get_idp
from src.services import tokens
from src.services.service_tokens import InvalidClientError, issue_service_token
from src.services.token_claims import human_token_claims

bp = Blueprint("token", __name__, url_prefix="/api")


@bp.route("/token", methods=["POST"])
@limiter.limit("20 per minute")
def token():
    """
    Issue platform JWT via OAuth2 implicit or client_credentials flow.

    Supports two authorization methods:

    1. **Session Grant (implicit)**: Issues human JWT from IdP session cookie.
       - No body required, token from session cookie
       - Returns: {"access_token": "<jwt>", "token_type": "Bearer", "expires_in": <seconds>}
       - Status: 200 (success), 401 (no session), 503 (provider unavailable)

    2. **Client Credentials**: Issues service JWT for service-to-service auth.
       - Requires: grant_type=client_credentials, Basic auth with client_id:client_secret
       - Looks up service credential, verifies secret via bcrypt, issues RS256 JWT
       - Returns: {"access_token": "<jwt>", "token_type": "Bearer", "expires_in": <seconds>}
       - Status: 200 (success), 401 (invalid credentials), 503 (DB/config unavailable)

    Ref: specs/014-authentication-service.md, RFC 6749 (OAuth2)
    """
    if request.is_json:
        grant_type = (request.get_json(silent=True) or {}).get("grant_type")
    else:
        grant_type = request.form.get("grant_type")

    if grant_type == "client_credentials":
        return _handle_client_credentials()

    if grant_type and grant_type != "session":
        return jsonify({"error": "unsupported_grant_type"}), 400

    return _handle_session_grant()


def _handle_session_grant():
    sealed = request.cookies.get(IDP_SESSION_COOKIE_NAME)
    if not sealed:
        return jsonify({"error": "unauthenticated"}), 401

    idp = get_idp()
    try:
        provider_session = idp.authenticate_session(sealed)
        if provider_session is None:
            return jsonify({"error": "session invalid or expired"}), 401
    except Exception as e:
        exc_name = exc_type_name(e)
        error_text = exc_name.lower() + type(e).__module__.lower() + str(e).lower()
        network_markers = ("timeout", "connect", "network", "unreachable", "connection")
        if any(marker in error_text for marker in network_markers):
            log_event("idp_unavailable", provider=idp.name, error_class=exc_name)
            return jsonify({"error": "authentication provider unavailable"}), 503
        raise

    try:
        identity = idp.to_platform_identity(provider_session)
        sub = identity.user_uuid or identity.idp_user_id

        with SessionLocal() as db:
            tenant_type, registry_roles = human_token_claims(
                db,
                user_uuid=identity.user_uuid,
                tenant_uuid=identity.tenant_uuid,
            )

        platform_token = tokens.issue_token(
            sub=sub,
            token_type="human",
            actors=identity.actors,
            tenant_uuid=identity.tenant_uuid,
            tenant_type=tenant_type,
            roles=registry_roles,
            ttl_secs=settings.access_token_ttl_secs,
            private_key_pem=settings.jwt_private_key_pem,
            audience=settings.jwt_web_audience,
            claim_namespace=settings.jwt_claim_namespace,
            public_key_pem=settings.jwt_public_key_pem,
        )
        log_event("platform_token_issued", user_id=identity.idp_user_id)

        response = make_response(jsonify({
            "access_token": platform_token,
            "token_type": "Bearer",
            "expires_in": settings.access_token_ttl_secs,
        }))

        if provider_session.sealed_session:
            set_idp_session_cookie(response, provider_session.sealed_session)

        return response
    except Exception as e:
        log_exception("platform_token_error", e)
        return jsonify({"error": "token issuance failed"}), 500


def _handle_client_credentials():
    """OAuth2 client_credentials grant for service-to-service tokens."""
    if not settings.app_database_url:
        return jsonify({"error": "database not configured"}), 503

    body: dict = request.get_json(silent=True) or {}

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            return jsonify({"error": "invalid_client"}), 401
    else:
        client_id = request.form.get("client_id") or body.get("client_id", "")
        client_secret = request.form.get("client_secret") or body.get("client_secret", "")

    requested_audience = request.form.get("audience") or body.get("audience")

    if not client_id or not client_secret:
        return jsonify({"error": "invalid_client"}), 401

    try:
        with SessionLocal() as db:
            service_token = issue_service_token(
                client_id,
                client_secret,
                db,
                audience=requested_audience,
            )

        return jsonify({
            "access_token": service_token,
            "token_type": "Bearer",
            "expires_in": settings.service_token_ttl_secs,
        })
    except InvalidClientError:
        return jsonify({"error": "invalid_client"}), 401
    except Exception as e:
        log_exception("service_token_error", e)
        return jsonify({"error": "token issuance failed"}), 500


@bp.route("/token-inspect")
@limiter.limit("10 per minute")
def token_inspect():
    """
    Decode a platform JWT and return its claims for debugging.

    Expects Bearer token in Authorization header. This endpoint does not validate
    issuer, audience, or signature; it only rejects malformed or invalid JWTs.
    The returned payload is a debug dump. Downstream services must still validate
    tokens in production.

    Request: Authorization: Bearer token
    Response: decoded JWT claims
    Status: 200 (valid), 400 (invalid token)

    Ref: RFC 7519 (JWT Claims), RFC 7523
    """
    if not settings.is_non_production:
        return jsonify({"error": "not_found"}), 404

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "missing Bearer token"}), 401

    raw_token = auth_header[7:]
    try:
        decoded = pyjwt.decode(
            raw_token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_iss": False,
                "verify_aud": False,
            },
        )
        return jsonify(decoded)
    except pyjwt.InvalidTokenError:
        return jsonify({"error": "invalid token"}), 400
