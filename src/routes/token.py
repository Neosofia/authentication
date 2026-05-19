import base64
import json
import os
import pathlib

import jwt as pyjwt
from flask import Blueprint, jsonify, make_response, request

from src.config import settings
from src.db.engine import SessionLocal
from src.bootstrap.extensions import cookie_password, csrf, is_development, limiter, workos_client
from src.bootstrap.logging import log_event
from src.services import tokens, workos_bridge
from src.services.service_tokens import InvalidClientError, issue_service_token

bp = Blueprint("token", __name__, url_prefix="/api")

# Cache the OpenAPI spec in memory (loaded once at startup)
_openapi_spec_cache = None


def _load_openapi_spec():
    """Load and cache the OpenAPI specification."""
    global _openapi_spec_cache

    if _openapi_spec_cache is not None:
        return _openapi_spec_cache

    openapi_file = pathlib.Path(__file__).parent.parent.parent / "openapi.json"

    if not openapi_file.exists():
        raise FileNotFoundError(f"OpenAPI specification not found at {openapi_file}")

    with open(openapi_file) as f:
        _openapi_spec_cache = json.load(f)

    return _openapi_spec_cache


@bp.route("/token", methods=["POST"])
@csrf.exempt
@limiter.limit("20 per minute")
def token():
    """
    Issue platform JWT via OAuth2 implicit or client_credentials flow.

    Supports two authorization methods:

    1. **Session Grant (implicit)**: Issues human JWT from sealed WorkOS session cookie.
       - No body required, token from wos_session cookie
       - Returns: {"access_token": "<jwt>", "token_type": "Bearer", "expires_in": <seconds>}
       - Status: 200 (success), 401 (no session), 503 (WorkOS unavailable)

    2. **Client Credentials**: Issues service JWT for service-to-service auth.
       - Requires: grant_type=client_credentials, Basic auth with client_id:client_secret
       - Looks up service credential, verifies secret via bcrypt, issues RS256 JWT
       - Returns: {"access_token": "<jwt>", "token_type": "Bearer", "expires_in": <seconds>}
       - Status: 200 (success), 401 (invalid credentials), 503 (DB/config unavailable)

    Ref: specs/014-authentication-service/spec.md, RFC 6749 (OAuth2)
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
    sealed = request.cookies.get("wos_session")
    if not sealed:
        return jsonify({"error": "unauthenticated"}), 401

    try:
        session = workos_client.user_management.load_sealed_session(
            session_data=sealed,
            cookie_password=cookie_password,
        )
        auth_response = session.authenticate()

        # If the WorkOS short-lived access token is expired, attempt to refresh it
        if not auth_response.authenticated:
            auth_response = session.refresh()

        if not auth_response.authenticated:
            return jsonify({"error": "session invalid or expired"}), 401
    except Exception as e:
        exc_name = type(e).__name__
        if any(w in exc_name.lower() + type(e).__module__.lower() + str(e).lower() for w in ("timeout", "connect", "network", "unreachable", "connection")):
            log_event("workos_unavailable", error_class=exc_name)
            return jsonify({"error": "authentication provider unavailable"}), 503
        raise

    try:
        user = getattr(auth_response, "user", None)
        sub = (user.get("id") if isinstance(user, dict) else getattr(user, "id", None)) or "unknown"

        claims = workos_bridge.extract_platform_claims(auth_response)
        user_uuid = claims.get("user_uuid")
        tenant_uuid = claims.get("tenant_uuid")

        platform_token = tokens.issue_token(
            sub=user_uuid or sub,
            token_type="human",
            roles=claims["roles"],
            tenant_id=tenant_uuid or claims.get("tenant_id"),
            ttl_secs=settings.access_token_ttl_secs,
            private_key_pem=settings.jwt_private_key_pem,
            issuer=settings.jwt_issuer,
            audience=settings.jwt_web_audience,
            claim_namespace=settings.jwt_claim_namespace,
            public_key_pem=settings.jwt_public_key_pem,
        )
        log_event("platform_token_issued", user_id=sub)

        response = make_response(jsonify({
            "access_token": platform_token,
            "token_type": "Bearer",
            "expires_in": settings.access_token_ttl_secs,
        }))

        # If the session was refreshed, persist the newly sealed session back to the client
        sealed_session = getattr(auth_response, "sealed_session", None)
        if sealed_session:
            response.set_cookie(
                "wos_session",
                sealed_session,
                secure=not is_development,
                httponly=True,
                samesite="lax",
                path="/",
            )

        return response
    except Exception as e:
        log_event("platform_token_error", error_class=type(e).__name__)
        return jsonify({"error": "token issuance failed"}), 500


def _handle_client_credentials():
    """OAuth2 client_credentials grant for service-to-service tokens."""
    if not settings.database_url:
        return jsonify({"error": "database not configured"}), 503

    # Support both application/x-www-form-urlencoded and application/json bodies
    body: dict = request.get_json(silent=True) or {}

    # Extract client_id / client_secret from Authorization: Basic or request body
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
                audience=requested_audience
            )

        return jsonify({
            "access_token": service_token,
            "token_type": "Bearer",
            "expires_in": settings.service_token_ttl_secs,
        })
    except InvalidClientError:
        return jsonify({"error": "invalid_client"}), 401
    except Exception as e:
        log_event("service_token_error", error_class=type(e).__name__)
        return jsonify({"error": "token issuance failed"}), 500


@bp.route("/token-inspect")
@csrf.exempt
@limiter.limit("10 per minute")
def token_inspect():
    """
    Decode a platform JWT and return its claims for debugging.

    Expects Bearer token in Authorization header. This endpoint does not validate
    issuer, audience, or signature; it only rejects malformed or invalid JWTs.
    The returned payload is a debug dump. Downstream services must still validate
    tokens in production.

    Request: Authorization: Bearer <platform-jwt>
    Response: decoded JWT claims
    Status: 200 (valid), 400 (invalid token)

    Ref: RFC 7519 (JWT Claims), RFC 7523 (Bearer token)
    """
    if os.getenv("ENV", "production").lower() not in ("development", "test"):
        return jsonify({"error": "not_found"}), 404

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "missing Bearer token"}), 401

    raw_token = auth_header[7:]
    try:
        # Decode the JWT payload for debugging only; do not validate audience or issuer.
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
