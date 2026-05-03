import base64
import json
import pathlib

import jwt as pyjwt
from flask import Blueprint, jsonify, request
from flask_wtf.csrf import CSRFError, validate_csrf
from sqlalchemy import text

from src.config import settings
from src.db.engine import SessionLocal
from src.extensions import csrf, workos_client, cookie_password, limiter
from src.logging_config import log_event
from src.services import token_issuer, workos_bridge
from src.services.machine_svc import InvalidClientError, issue_machine_token

bp = Blueprint("api", __name__, url_prefix="/api")

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
       - Returns: {\"access_token\": \"<jwt>\", \"token_type\": \"Bearer\", \"expires_in\": <seconds>}
       - Status: 200 (success), 401 (no session), 503 (WorkOS unavailable)
    
    2. **Client Credentials**: Issues machine JWT for service-to-service auth.
       - Requires: grant_type=client_credentials, Basic auth with client_id:client_secret
       - Looks up MachineCredential, verifies secret via bcrypt, issues RS256 JWT
       - Returns: {\"access_token\": \"<jwt>\", \"token_type\": \"Bearer\", \"expires_in\": <seconds>}
       - Status: 200 (success), 401 (invalid credentials), 503 (DB/config unavailable)
    
    Ref: specs/014-authentication-service/spec.md, RFC 6749 (OAuth2), contracts/token-issuance.md
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
    if not settings.jwt_private_key_pem or not settings.jwt_public_key_pem:
        return jsonify({"error": "JWT keys not configured"}), 503

    sealed = request.cookies.get("wos_session")
    if not sealed:
        return jsonify({"error": "unauthenticated"}), 401

    try:
        session = workos_client.user_management.load_sealed_session(
            session_data=sealed,
            cookie_password=cookie_password,
        )
        auth_response = session.authenticate()
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
        platform_token = token_issuer.issue_token(
            sub=sub,
            token_type="human",
            roles=claims["roles"],
            tenant_id=claims.get("tenant_id"),
            ttl_secs=settings.access_token_ttl_secs,
            private_key_pem=settings.jwt_private_key_pem,
            issuer=settings.jwt_issuer,
            claim_namespace=settings.jwt_claim_namespace,
        )
        log_event("platform_token_issued", user_id=sub)
        return jsonify({
            "access_token": platform_token,
            "token_type": "Bearer",
            "expires_in": settings.access_token_ttl_secs,
        })
    except Exception as e:
        log_event("platform_token_error", error_class=type(e).__name__)
        return jsonify({"error": "token issuance failed"}), 500


def _handle_client_credentials():
    """OAuth2 client_credentials grant for machine-to-machine tokens."""
    if not settings.jwt_private_key_pem:
        return jsonify({"error": "JWT keys not configured"}), 503
    if not settings.database_url:
        return jsonify({"error": "database not configured"}), 503

    # Extract client_id / client_secret from Authorization: Basic or form body
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            return jsonify({"error": "invalid_client"}), 401
    else:
        client_id = request.form.get("client_id", "")
        client_secret = request.form.get("client_secret", "")

    if not client_id or not client_secret:
        return jsonify({"error": "invalid_client"}), 401

    try:
        with SessionLocal() as db:
            machine_token = issue_machine_token(client_id, client_secret, db)

        return jsonify({
            "access_token": machine_token,
            "token_type": "Bearer",
            "expires_in": settings.machine_token_ttl_secs,
        })
    except InvalidClientError:
        return jsonify({"error": "invalid_client"}), 401
    except Exception as e:
        log_event("machine_token_error", error_class=type(e).__name__)
        return jsonify({"error": "token issuance failed"}), 500


@bp.route("/me")
@csrf.exempt
def me():
    """
    Validate platform JWT and return decoded claims.
    
    Expects Bearer token in Authorization header. Verifies RS256 signature against
    JWT public key (cached from JWKS endpoint), validates issuer and audience claims,
    and enforces required claims (exp, iat, iss, sub, aud). Returns decoded claims
    without requiring WorkOS API call — enabling stateless, distributed JWT validation
    throughout the platform services (Constitution §VII).
    
    Validation ensures tokens are:
    - Signed by this issuer (iss claim)
    - Intended for this service (aud claim)
    - Not expired (exp claim)
    - Contain required fields (sub, iat)
    
    Request: Authorization: Bearer <platform-jwt>
    Response: {\"sub\": \"<user_id>\", \"neosofia:token_type\": \"<human|machine>\", \"neosofia:roles\": [...], \"neosofia:tenant_id\": \"<id>\", \"exp\": <timestamp>, ...}
    Status: 200 (valid), 401 (missing/invalid/expired token), 503 (JWT key not configured)
    
    Ref: RFC 7519 (JWT Claims), RFC 7523 (Bearer token), specs/014-authentication-service/spec.md (FR-002: JWT validation)
    """
    if not settings.jwt_public_key_pem:
        return jsonify({"error": "JWT public key not configured"}), 503

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "missing Bearer token"}), 401

    raw_token = auth_header[7:]
    try:
        # Validate issuer, audience, and required claims (CWE-347 mitigation)
        from src.services.token_issuer import AUDIENCE
        decoded = pyjwt.decode(
            raw_token,
            settings.jwt_public_key_pem,
            algorithms=["RS256"],
            issuer=settings.jwt_issuer,
            audience=AUDIENCE,
            options={"require": ["exp", "iat", "iss", "sub", "aud"]},
        )
        return jsonify(decoded)
    except pyjwt.ExpiredSignatureError:
        return jsonify({"error": "token expired"}), 401
    except pyjwt.InvalidSignatureError:
        return jsonify({"error": "invalid signature"}), 401
    except pyjwt.InvalidAudienceError:
        return jsonify({"error": "token not intended for this service"}), 401
    except pyjwt.InvalidIssuerError:
        return jsonify({"error": "token from unauthorized issuer"}), 401
    except pyjwt.InvalidTokenError as e:
        return jsonify({"error": f"invalid token: {e}"}), 401


@bp.route("/health")
@csrf.exempt
def health():
    """
    Liveness and readiness probe for Kubernetes/Docker orchestration.
    
    Executes SELECT 1 query against PostgreSQL with 5-second timeout.
    Returns 200 if database is reachable, 503 if timeout or error.
    Used by load balancers and container orchestrators to route traffic.
    
    Response: {\"status\": \"ok\", \"timestamp\": \"<iso8601>\"} or {\"status\": \"error\", \"detail\": \"<reason>\"}
    Status: 200 (healthy), 503 (unhealthy)
    
    Ref: Kubernetes probes (livenessProbe, readinessProbe)
    """
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        return jsonify({"status": "ok"}), 200
    except TimeoutError:
        log_event("health_check_failed", reason="database timeout")
        return jsonify({"status": "error", "detail": "database timeout"}), 503
    except Exception as e:
        log_event("health_check_failed", error_class=type(e).__name__)
        return jsonify({"status": "error", "detail": "database unavailable"}), 503


