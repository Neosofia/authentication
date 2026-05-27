import base64
import hashlib
import secrets

from flask import Blueprint, jsonify, make_response, redirect, request, url_for, session
from workos.session import seal_session_from_auth_response

from src.config import settings
from src.bootstrap.extensions import limiter, talisman, workos_client
from src.bootstrap.logging import log_event, log_exception
from src.services.cookies import clear_wos_session_cookie, set_wos_session_cookie
from src.services.jwks import pem_to_jwk
from src.services.identity import sync_identity_data
from src.services import workos_bridge

bp = Blueprint("auth", __name__)


def _resolve_workos_session_id(session) -> str | None:
    auth_response = session.authenticate()
    if getattr(auth_response, "authenticated", False):
        return auth_response.session_id

    refresh_response = session.refresh()
    if getattr(refresh_response, "authenticated", False):
        return refresh_response.session_id

    return None


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
    Ref: ADR-0007 (never roll your own authentication), specs/014-authentication-service.md
    """
    redirect_uri = settings.workos_redirect_uri
    
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
    Ref: specs/014-authentication-service.md (sealed session, token sealing), RFC 6819 §4.4.1.8
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
        auth_response, user_data, claims = workos_bridge.prepare_auth_session(auth_response)
        
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
            cookie_password=settings.workos_cookie_password,
        )

        response = make_response(redirect(settings.frontend_auth_callback_url()))
        set_wos_session_cookie(response, sealed_session)
        # Clean up OAuth state and PKCE cookies after successful exchange
        log_event(
            "authentication_success",
            user_id=user_id,
            user_uuid=claims.get("user_uuid"),
            method="workos",
        )
        return response

    except Exception as e:
        # Log only the exception class for safe diagnostics.
        log_exception("callback_error", e, method="workos")
        # Return to the UI — not /login — so a failed callback does not re-enter WorkOS immediately.
        response = make_response(redirect(settings.frontend_url))
        return response


@bp.route("/logout", methods=["POST", "GET"])
@limiter.limit("60 per minute")
def logout():
    """
    Session revocation and cookie cleanup.
    
    Loads sealed session, revokes it with WorkOS (invalidating refresh tokens),
    and deletes wos_session cookie. Gracefully handles missing session or errors.
    
    Returns: 302 redirect to / after revoking session and clearing cookie
    Ref: specs/014-authentication-service.md (session revocation)
    """
    frontend_url = settings.frontend_url

    try:
        sealed_session = request.cookies.get("wos_session")
        if not sealed_session:
            log_event("logout_failure", reason="No session found")
            return clear_wos_session_cookie(make_response(redirect(frontend_url)))

        session = workos_client.user_management.load_sealed_session(
            session_data=sealed_session,
            cookie_password=settings.workos_cookie_password,
        )
        session_id = _resolve_workos_session_id(session)

        if session_id:
            logout_url = workos_client.user_management.get_logout_url(
                session_id=session_id,
                return_to=frontend_url,
            )
            response = make_response(redirect(logout_url))
            log_event("session_revoked", reason="User initiated logout")
        else:
            log_event("logout_failure", reason="Could not resolve WorkOS session for logout")
            response = make_response(redirect(frontend_url))

        return clear_wos_session_cookie(response)

    except Exception as e:
        log_exception("logout_failure", e)
        return clear_wos_session_cookie(make_response(redirect(frontend_url)))


@bp.route("/.well-known/jwks.json")
@talisman(force_https=False)
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
        keys = [pem_to_jwk(settings.jwt_public_key_pem)]
        if settings.jwt_previous_public_key_pem:
            keys.append(pem_to_jwk(settings.jwt_previous_public_key_pem))
        response = jsonify({"keys": keys})
        response.headers["Cache-Control"] = "public, max-age=3600"
        return response
    except ValueError as exc:
        log_exception("jwks_error", exc, reason="invalid public key")
        return jsonify({"error": "failed to build JWKS"}), 500
    except Exception as exc:
        log_exception("jwks_error", exc)
        return jsonify({"error": "failed to build JWKS"}), 500
