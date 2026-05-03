from functools import wraps

from flask import Blueprint, make_response, redirect, render_template, request, url_for
from flask_wtf.csrf import generate_csrf
from markupsafe import escape

from src.extensions import workos_client, cookie_password, is_development
from src.logging_config import log_event
from authentication_in_the_middle import with_auth

bp = Blueprint("ui", __name__, template_folder="../templates")

# Create the with_auth decorator with dependencies bound
_with_auth = with_auth(workos_client, cookie_password, is_development, log_event)


if is_development:
    @bp.route("/test")
    @_with_auth
    def test():
        """
        Demo protected route using @with_auth decorator.
        
        Development-only endpoint to validate session authentication middleware.
        Returns 302 redirect to /login if session is invalid, otherwise renders protected content.
        
        Ref: specs/014-authentication-service (with_auth decorator pattern)
        """
        return "<h1>Protected</h1><p>You are authenticated.</p><p><a href='/'>Back</a></p>"


@bp.route("/")
def index():
    """
    Homepage with conditional authentication display.
    
    Renders user information (name, email) if a valid WorkOS session exists,
    otherwise displays login prompt. Validates sealed session and authenticates
    without making external requests.
    
    Ref: specs/014-authentication-service/spec.md (human session validation)
    """
    user_name = None
    user_email = None
    authenticated = False

    sealed = request.cookies.get("wos_session")
    if sealed:
        try:
            session = workos_client.user_management.load_sealed_session(
                session_data=sealed,
                cookie_password=cookie_password,
            )
            auth_response = session.authenticate()
            user = getattr(auth_response, "user", None)
            if auth_response.authenticated and user:
                authenticated = True
                first_name = (user.get("first_name") if isinstance(user, dict) else user.first_name) or ""
                last_name = (user.get("last_name") if isinstance(user, dict) else user.last_name) or ""
                email = (user.get("email") if isinstance(user, dict) else user.email) or ""
                user_name = escape(f"{first_name} {last_name}".strip())
                user_email = escape(email)
                log_event("homepage_session_valid")
        except Exception as e:
            log_event("homepage_session_validation_error", error_class=type(e).__name__)
    else:
        log_event("homepage_accessed", session_status="no_session")

    return render_template(
        "index.html",
        authenticated=authenticated,
        user_name=user_name,
        user_email=user_email,
        csrf_token=generate_csrf(),
    )
