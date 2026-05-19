import base64
import hashlib
import json
import os
import secrets
import uuid
from typing import cast

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from flask import Blueprint, jsonify, make_response, redirect, request, url_for, session
from flask_wtf.csrf import generate_csrf
from workos.session import seal_session_from_auth_response

from src.config import settings
from src.bootstrap.extensions import cookie_password, csrf, limiter, workos_client
from src.bootstrap.logging import log_event
from src.db.engine import SessionLocal
from src.services.identity import sync_identity_data
from src.services import workos_bridge

bp = Blueprint("auth", __name__)


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


@bp.route("/login")
@limiter.limit("60 per minute")
def login():
    """
    Initiate OAuth authorization flow with WorkOS.
    
    Generates authorization URL via WorkOS AuthKit provider and redirects user
    to login/MFA consent screen. Callback handler will exchange authorization
    code for tokens and seal session cookie. Includes CSRF-safe state parameter
    to prevent session fixation attacks (RFC 6819, RFC 7636).
    
    Returns: 302 redirect to WorkOS authorization endpoint
    Ref: ADR-0007 (never roll your own authentication), specs/014-authentication-service/spec.md
    """
    redirect_uri = os.getenv("WORKOS_REDIRECT_URI", "http://localhost:8014/callback")
    
    # Generate cryptographically random state for CSRF protection (RFC 6819 §4.4.1.8)
    oauth_state = secrets.token_urlsafe(32)
    
    # Generate PKCE code verifier and challenge (RFC 7636) for code interception protection
    # code_verifier: 43-128 character string; use max length for security
    code_verifier = secrets.token_urlsafe(96)[:128]
    # code_challenge: SHA256(verifier) encoded as base64url
    code_challenge = _base64url_encode(hashlib.sha256(code_verifier.encode()).digest())
    
    authorization_url = workos_client.user_management.get_authorization_url(
        provider="authkit",
        redirect_uri=redirect_uri,
        state=oauth_state,
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )
    
    # Store state and PKCE verifier encrypted in Flask's session object
    session["oauth_state"] = oauth_state
    session["code_verifier"] = code_verifier

    response = make_response(redirect(authorization_url))

    log_event("login_initiated", redirect_uri=redirect_uri)
    return response


@bp.route("/callback")
@limiter.limit("60 per minute")
def callback():
    """
    OAuth authorization code exchange and session establishment.
    
    Exchanges WorkOS authorization code for access/refresh tokens and user info.
    Seals tokens and user data into an encrypted HTTP-only cookie for subsequent
    session validation. Verifies OAuth state parameter to prevent CSRF/session fixation.
    Handles missing code, OAuth errors, or state mismatch by redirecting to login.
    
    Returns: 302 redirect to / on success, /login on error
    Ref: specs/014-authentication-service/spec.md (sealed session, token sealing), RFC 6819 §4.4.1.8
    """
    code = request.args.get("code")
    error = request.args.get("error")
    state_from_provider = request.args.get("state")

    if error:
        log_event("oauth_callback_error", error=error, reason="OAuth provider returned error")
        return redirect(url_for("auth.login"))

    if not code:
        log_event("oauth_callback_error", reason="No authorization code received")
        return redirect(url_for("auth.login"))
    
    # Verify OAuth state parameter (CSRF protection)
    state_from_cookie = session.pop("oauth_state", None)
    if not state_from_provider or not state_from_cookie or state_from_provider != state_from_cookie:
        log_event(
            "oauth_state_mismatch",
            reason="CSRF/session fixation attempt detected or state expired",
            has_state_param=bool(state_from_provider),
            has_state_cookie=bool(state_from_cookie),
        )
        response = make_response(redirect(url_for("auth.login")))
        return response
    
    # Retrieve PKCE code verifier from cookie (RFC 7636) for code interception protection
    code_verifier = session.pop("code_verifier", None)
    if not code_verifier:
        log_event(
            "pkce_verifier_missing",
            reason="Code verifier not found in cookie; PKCE validation will fail",
        )
        response = make_response(redirect(url_for("auth.login")))
        return response

    try:
        # Use PKCE-specific method for code exchange with code_verifier
        auth_response = workos_client.user_management.authenticate_with_code_pkce(
            code=code,
            code_verifier=code_verifier,
        )

        user_id = auth_response.user.id if auth_response.user else "unknown"
        user_data = auth_response.user.to_dict() if auth_response.user else {}

        # Check for UUIDv7 (Person ID) on WorkOS User, or generate/persist one
        if "external_id" not in user_data or not user_data.get("external_id"):
            new_person_id = str(uuid.uuid7())
            
            # Persist the newly generated Person ID to WorkOS User
            try:
                updated_user = workos_client.user_management.update_user(
                    id=user_id,
                    external_id=new_person_id,
                )
                user_data = updated_user.to_dict()
                log_event("person_id_generated", user_id=user_id, person_id=new_person_id)
            except Exception as e:
                log_event("person_id_generation_error", error_class=type(e).__name__, user_id=user_id)
                # Keep going with the old user data so login does not fail entirely
        # We now rely exclusively on the WorkOS Custom Claims template.
        # No SDK API calls, no DB lookups, no mapping fallbacks.
        claims = workos_bridge.extract_platform_claims(auth_response)
        
        # Best effort DB sync for caching profile data
        sync_identity_data(
            user_uuid=claims.get("user_uuid"),
            tenant_uuid=claims.get("tenant_uuid"),
            idp_user_id=user_id,
            first_name=user_data.get("first_name"),
            last_name=user_data.get("last_name"),
            email=user_data.get("email"),
            idp_tenant_id=claims.get("workos_tenant_id"),
            tenant_name=claims.get("workos_tenant_name"),
        )

        sealed_session = seal_session_from_auth_response(
            access_token=auth_response.access_token,
            refresh_token=auth_response.refresh_token,
            user=user_data,
            impersonator=auth_response.impersonator.to_dict() if auth_response.impersonator else None,
            cookie_password=cookie_password,
        )

        response = make_response(redirect(os.getenv("FRONTEND_URL", "/")))
        response.set_cookie(
            "wos_session",
            sealed_session,
            secure=True,
            httponly=True,
            samesite="none",
            path="/",
        )
        # Clean up OAuth state and PKCE cookies after successful exchange
        log_event("authentication_success", user_id=user_id, method="workos")
        return response

    except Exception as e:
        # Log only the exception class for safe diagnostics.
        log_event(
            "callback_error",
            error_class=type(e).__name__,
            method="workos",
        )
        response = make_response(redirect(url_for("auth.login")))
        return response


@bp.route("/logout", methods=["POST", "GET"])
@csrf.exempt
def logout():
    """
    Session revocation and cookie cleanup.
    
    Loads sealed session, revokes it with WorkOS (invalidating refresh tokens),
    and deletes wos_session cookie. Gracefully handles missing session or errors.
    
    Returns: 302 redirect to / after revoking session and clearing cookie
    Ref: specs/014-authentication-service/spec.md (session revocation)
    """
    try:
        sealed_session = request.cookies.get("wos_session")
        if not sealed_session:
            log_event("logout_failure", reason="No session found")
            return redirect(os.getenv("FRONTEND_URL", "/"))

        session = workos_client.user_management.load_sealed_session(
            session_data=sealed_session,
            cookie_password=cookie_password,
        )
        logout_url = session.get_logout_url()
        response = make_response(redirect(logout_url))
        response.delete_cookie("wos_session")
        log_event("session_revoked", reason="User initiated logout")
        return response

    except Exception as e:
        log_event("logout_failure", error_class=type(e).__name__)
        response = make_response(redirect(os.getenv("FRONTEND_URL", "/")))
        response.delete_cookie("wos_session")
        return response


@bp.route("/csrf-token")
def csrf_token():
    """
    Issue CSRF token for API requests.
    
    Generates Flask-WTF CSRF token for inclusion in subsequent POST/PUT/DELETE requests.
    Token is bound to session and validated by @csrf.protect middleware.
    
    Returns: {\"csrfToken\": \"<token>\"}
    Ref: Flask-WTF CSRF protection (defense in depth)
    """
    token = generate_csrf()
    log_event("csrf_token_issued")
    return jsonify({"csrfToken": token})


def _pem_to_jwk(pem: str) -> dict:
    """Convert a PEM-encoded RSA public key to a JWK dict (RFC 7517 / RFC 7638)."""
    pub_key = load_pem_public_key(pem.encode())
    if not isinstance(pub_key, RSAPublicKey):
        raise ValueError("key is not RSA")
    pub_numbers = cast(RSAPublicKey, pub_key).public_numbers()

    def _b64url_uint(n: int) -> str:
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    n_b64 = _b64url_uint(pub_numbers.n)
    e_b64 = _b64url_uint(pub_numbers.e)

    # kid: RFC 7638 JWK Thumbprint (SHA-256 hash of canonical JSON representation)
    thumbprint_data = json.dumps(
        {"e": e_b64, "kty": "RSA", "n": n_b64},
        separators=(",", ":"),
        sort_keys=True,
    )
    kid = base64.urlsafe_b64encode(
        hashlib.sha256(thumbprint_data.encode()).digest()
    ).rstrip(b"=").decode()

    return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n_b64, "e": e_b64}


@bp.route("/.well-known/jwks.json")
@csrf.exempt
def jwks():
    """
    Publish RSA public key(s) as JWK Set for JWT validation.

    Returns the active key and, during key-rotation overlap, the previous key
    (JWT_PREVIOUS_PUBLIC_KEY_PEM) so consumers can verify tokens signed by
    either key while they drain.  Downstream services fetch once at startup and
    cache for 1 hour (kid lookup by RFC 7638 thumbprint).

    Response: {"keys": [{...}, ...]}  — 1 key normally, 2 during rotation overlap.
    Cache-Control: max-age=3600 (1 hour)

    Ref: RFC 7517 (JWK), RFC 7518 (JWA), RFC 7638 (JWK Thumbprint)
    """
    try:
        keys = [_pem_to_jwk(settings.jwt_public_key_pem)]
        if settings.jwt_previous_public_key_pem:
            keys.append(_pem_to_jwk(settings.jwt_previous_public_key_pem))
        response = jsonify({"keys": keys})
        response.headers["Cache-Control"] = "public, max-age=3600"
        return response
    except ValueError as exc:
        log_event("jwks_error", reason="invalid public key", error_class=type(exc).__name__)
        return jsonify({"error": "failed to build JWKS"}), 500
    except Exception as exc:
        log_event("jwks_error", error_class=type(exc).__name__)
        return jsonify({"error": "failed to build JWKS"}), 500
