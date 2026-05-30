import base64
import hashlib
import secrets

from flask import Blueprint, jsonify, make_response, redirect, request, url_for, session

from src.config import settings
from src.bootstrap.extensions import limiter, talisman
from src.bootstrap.logging import log_event, log_exception
from src.services.cookies import (
    IDP_SESSION_COOKIE_NAME,
    clear_idp_session_cookie,
    set_idp_session_cookie,
)
from src.services.idp import get_idp
from src.services.jwks import pem_to_jwk
from src.services.identity import sync_identity_data
from src.services.user_provisioning import provision_user_registry

bp = Blueprint("auth", __name__)


def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


@bp.route("/login")
@limiter.limit("60 per minute")
def login():
    """
    Initiate OAuth authorization flow with the configured identity provider.

    Generates an authorization URL and redirects the user to the provider login
    screen. Callback handler will exchange authorization code for a provider
    session cookie. Includes CSRF-safe state parameter to prevent session
    fixation attacks (RFC 6819, RFC 7636).

    Returns: 302 redirect to provider authorization endpoint
    Ref: ADR-0007 (never roll your own authentication), specs/014-authentication-service.md
    """
    # Generate cryptographically random state for CSRF protection (RFC 6819 §4.4.1.8)
    oauth_state = secrets.token_urlsafe(32)

    # Generate PKCE code verifier and challenge (RFC 7636) for code interception protection
    # code_verifier: 43-128 character string; use max length for security
    code_verifier = secrets.token_urlsafe(96)[:128]
    # code_challenge: SHA256(verifier) encoded as base64url
    code_challenge = _base64url_encode(hashlib.sha256(code_verifier.encode()).digest())

    idp = get_idp()
    authorization_url = idp.authorization_url(
        state=oauth_state,
        code_challenge=code_challenge,
    )

    # Store state and PKCE verifier encrypted in Flask's session object
    session["oauth_state"] = oauth_state
    session["code_verifier"] = code_verifier

    response = make_response(redirect(authorization_url))

    log_event("login_initiated", provider=idp.name)
    return response


@bp.route("/callback")
@limiter.limit("60 per minute")
def callback():
    """
    OAuth authorization code exchange and session establishment.

    Exchanges authorization code for provider session data and maps the upstream
    response to platform identity fields. Verifies OAuth state parameter to
    prevent CSRF/session fixation. Handles missing code, OAuth errors, or state
    mismatch by redirecting to login.

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

    idp = get_idp()
    try:
        provider_session = idp.exchange_code(code=code, code_verifier=code_verifier)
        identity = idp.to_platform_identity(provider_session)

        # Best effort DB sync for caching profile data
        sync_identity_data(
            user_uuid=identity.user_uuid,
            tenant_uuid=identity.tenant_uuid,
            idp_user_id=identity.idp_user_id,
            first_name=identity.profile.get("first_name"),
            last_name=identity.profile.get("last_name"),
            email=identity.profile.get("email"),
            idp_tenant_id=identity.idp_tenant_id,
            tenant_name=identity.tenant_name,
        )
        provision_user_registry(identity)

        response = make_response(redirect(settings.frontend_auth_callback_url()))
        if provider_session.sealed_session:
            set_idp_session_cookie(response, provider_session.sealed_session)
        # Clean up OAuth state and PKCE cookies after successful exchange
        log_event(
            "authentication_success",
            user_id=identity.idp_user_id,
            user_uuid=identity.user_uuid,
            method=idp.name,
        )
        return response

    except Exception as e:
        # Log only the exception class for safe diagnostics.
        log_exception("callback_error", e, method=idp.name)
        # Return to the UI — not /login — so a failed callback does not re-enter IdP immediately.
        response = make_response(redirect(settings.frontend_url))
        return response


@bp.route("/logout", methods=["POST", "GET"])
@limiter.limit("60 per minute")
def logout():
    """
    Session revocation and cookie cleanup.

    Loads the provider session, asks the IdP adapter for a logout URL, and
    deletes the browser session cookie. Gracefully handles missing session or
    errors.

    Returns: 302 redirect to / after revoking session and clearing cookie
    Ref: specs/014-authentication-service.md (session revocation)
    """
    frontend_url = settings.frontend_url

    try:
        sealed_session = request.cookies.get(IDP_SESSION_COOKIE_NAME)
        if not sealed_session:
            log_event("logout_failure", reason="No session found")
            return clear_idp_session_cookie(make_response(redirect(frontend_url)))

        logout_url = get_idp().revoke_session(sealed_session, return_to=frontend_url)

        if logout_url:
            response = make_response(redirect(logout_url))
            log_event("session_revoked", reason="User initiated logout")
        else:
            log_event("logout_failure", reason="Could not resolve IdP session for logout")
            response = make_response(redirect(frontend_url))

        return clear_idp_session_cookie(response)

    except Exception as e:
        log_exception("logout_failure", e)
        return clear_idp_session_cookie(make_response(redirect(frontend_url)))


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
