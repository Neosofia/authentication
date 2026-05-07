import base64
import hashlib
import json
import os
import secrets
import uuid

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from flask import Blueprint, jsonify, make_response, redirect, request, url_for
from flask_wtf.csrf import generate_csrf
from workos.session import seal_session_from_auth_response

from src.config import settings
from src.extensions import workos_client, cookie_password, is_development, csrf, limiter
from src.logging_config import log_event

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
    
    response = make_response(redirect(authorization_url))
    # Store state in HttpOnly, Secure, SameSite cookie (5 minute TTL)
    response.set_cookie(
        "oauth_state",
        oauth_state,
        max_age=300,  # 5 minutes
        secure=not is_development,
        httponly=True,
        samesite="lax",
        path="/",
    )
    # Store PKCE code verifier in HttpOnly, Secure, SameSite cookie (same 5 minute TTL)
    response.set_cookie(
        "code_verifier",
        code_verifier,
        max_age=300,  # 5 minutes
        secure=not is_development,
        httponly=True,
        samesite="lax",
        path="/",
    )
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
    state_from_cookie = request.cookies.get("oauth_state")
    if not state_from_provider or not state_from_cookie or state_from_provider != state_from_cookie:
        log_event(
            "oauth_state_mismatch",
            reason="CSRF/session fixation attempt detected or state expired",
            has_state_param=bool(state_from_provider),
            has_state_cookie=bool(state_from_cookie),
        )
        response = make_response(redirect(url_for("auth.login")))
        response.delete_cookie("oauth_state", path="/")
        response.delete_cookie("code_verifier", path="/")
        return response
    
    # Retrieve PKCE code verifier from cookie (RFC 7636) for code interception protection
    code_verifier = request.cookies.get("code_verifier")
    if not code_verifier:
        log_event(
            "pkce_verifier_missing",
            reason="Code verifier not found in cookie; PKCE validation will fail",
        )
        response = make_response(redirect(url_for("auth.login")))
        response.delete_cookie("oauth_state", path="/")
        response.delete_cookie("code_verifier", path="/")
        return response

    try:
        # Use PKCE-specific method for code exchange with code_verifier
        auth_response = workos_client.user_management.authenticate_with_code_pkce(
            code=code,
            code_verifier=code_verifier,
        )

        user_email = auth_response.user.email if auth_response.user else "unknown"
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

        # Check for UUIDv7 on WorkOS Organization, or generate/persist one
        organization_id = getattr(auth_response, "organization_id", None)
        if organization_id:
            try:
                org = workos_client.organizations.get_organization(id=organization_id)
                if not getattr(org, "external_id", None):
                    new_org_id = str(uuid.uuid7())
                    workos_client.organizations.update_organization(
                        id=organization_id,
                        external_id=new_org_id,
                    )
                    log_event("org_internal_id_generated", organization_id=organization_id, internal_org_id=new_org_id)
            except Exception as e:
                log_event("org_id_generation_error", error_class=type(e).__name__, organization_id=organization_id)

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
            secure=not is_development,
            httponly=True,
            samesite="lax",
            path="/",
        )
        # Clean up OAuth state and PKCE cookies after successful exchange
        response.delete_cookie("oauth_state", path="/")
        response.delete_cookie("code_verifier", path="/")
        log_event("authentication_success", user_id=user_id, method="workos")
        return response

    except Exception as e:
        # Log error class and message for debugging (allows distinguishing error types)
        log_event(
            "callback_error",
            error_class=type(e).__name__,
            method="workos",
        )
        response = make_response(redirect(url_for("auth.login")))
        response.delete_cookie("oauth_state", path="/")
        response.delete_cookie("code_verifier", path="/")
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
    Ref: Flask-WTF CSRF protection (Constitution §VIII: defense in depth)
    """
    token = generate_csrf()
    log_event("csrf_token_issued")
    return jsonify({"csrfToken": token})


@bp.route("/.well-known/jwks.json")
@csrf.exempt
def jwks():
    """
    Publish RSA public key as JWK Set for JWT validation.
    
    Returns RSA public key in JWK Set format (RFC 7517). Downstream services
    fetch once at startup and cache for 1 hour. Enables offline JWT validation
    without requiring WorkOS API call for every token (Constitution §VII: stateless).
    
    Response: {\"keys\": [{\"kty\": \"RSA\", \"use\": \"sig\", \"alg\": \"RS256\", \"kid\": \"<kid>\", \"n\": \"<modulus>\", \"e\": \"<exponent>\"}]}
    Cache-Control: max-age=3600 (1 hour)
    
    Ref: RFC 7517 (JWK), RFC 7518 (JWA), specs/014-authentication-service/spec.md (FR-004: JWKS publication)
    """
    if not settings.jwt_public_key_pem:
        return jsonify({"error": "JWT public key not configured"}), 503

    try:
        pub_key = load_pem_public_key(settings.jwt_public_key_pem.encode())
        if not isinstance(pub_key, RSAPublicKey):
            return jsonify({"error": "key is not RSA"}), 500
        pub_numbers = pub_key.public_numbers()

        def _b64url_uint(n: int) -> str:
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

        n_b64 = _b64url_uint(pub_numbers.n)
        e_b64 = _b64url_uint(pub_numbers.e)

        # kid: RFC 7638 JWK Thumbprint (SHA-256 hash of canonical JSON representation)
        # Allows key identification without relying on key-specific fields like modulus
        thumbprint_data = json.dumps(
            {"e": e_b64, "kty": "RSA", "n": n_b64},  # Alphabetically sorted, required fields only
            separators=(",", ":"),  # Compact JSON (no whitespace)
            sort_keys=True,
        )
        thumbprint_hash = hashlib.sha256(thumbprint_data.encode()).digest()
        kid = base64.urlsafe_b64encode(thumbprint_hash).rstrip(b"=").decode()

        jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": n_b64,
            "e": e_b64,
        }
        response = jsonify({"keys": [jwk]})
        response.headers["Cache-Control"] = "public, max-age=3600"
        return response
    except Exception as e:
        log_event("jwks_error", error_class=type(e).__name__)
        return jsonify({"error": "failed to build JWKS"}), 500
