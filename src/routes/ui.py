from functools import wraps

from flask import Blueprint, make_response, redirect, render_template, request, url_for
from flask_wtf.csrf import generate_csrf
from markupsafe import escape

from src.extensions import workos_client, cookie_password, is_development
from src.logging_config import log_event

bp = Blueprint("ui", __name__, template_folder="../templates")


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
    new_sealed_session = None

    if sealed:
        try:
            session = workos_client.user_management.load_sealed_session(
                session_data=sealed,
                cookie_password=cookie_password,
            )
            auth_response = session.authenticate()
            
            if not auth_response.authenticated:
                auth_response = session.refresh()
                if auth_response.authenticated and hasattr(auth_response, "sealed_session"):
                    new_sealed_session = auth_response.sealed_session

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

    response = make_response(render_template(
        "index.html",
        authenticated=authenticated,
        user_name=user_name,
        user_email=user_email,
        csrf_token=generate_csrf(),
    ))

    if new_sealed_session:
        response.set_cookie(
            "wos_session",
            new_sealed_session,
            secure=not is_development,
            httponly=True,
            samesite="lax",
            path="/",
        )

    return response
