import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()

# Extensions must be imported after load_dotenv so env vars are available.
from src.config import settings  # noqa: E402
from src.extensions import csrf, cookie_password, limiter  # noqa: E402
from src.logging_config import setup_logging  # noqa: E402
from src.routes import auth, ui, api  # noqa: E402

_TEMPLATE_FOLDER = str(Path(__file__).parent.parent / "templates")
_STATIC_FOLDER = str(Path(__file__).parent.parent / "static")


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__, template_folder=_TEMPLATE_FOLDER, static_folder=_STATIC_FOLDER, static_url_path="/static")

    if config:
        app.config.update(config)

    csrf_secret = os.getenv("CSRF_SECRET_KEY")
    if not csrf_secret:
        raise ValueError("CSRF_SECRET_KEY environment variable is required")
    if not cookie_password:
        raise ValueError("WORKOS_COOKIE_PASSWORD environment variable is required")

    app.config["SECRET_KEY"] = csrf_secret
    app.config["WTF_CSRF_FIELD_NAME"] = "_csrf"
    # Reject request bodies larger than this to prevent body-flood DoS.
    # Bodies here are only form fields / small JSON; JWTs arrive in headers, not bodies.
    # Override via MAX_CONTENT_LENGTH env var (bytes). Default: 16 KiB.
    app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH", 16_384))

    setup_logging()
    csrf.init_app(app)
    limiter.init_app(app)

    app.register_blueprint(ui.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(api.bp)

    # Pre-load OpenAPI spec at startup to fail fast if it's missing or invalid
    api._load_openapi_spec()

    # Initialize security headers (L2: Flask-Talisman only in production)
    # In development, CSP can be restrictive; production deployments require strict headers
    is_development = os.getenv("ENV", "production").lower() in ("development", "test")

    if not is_development:
        # Trust the single Traefik reverse proxy sitting in front of us.
        # ProxyFix makes Flask honour X-Forwarded-Proto/Host so that
        # url_for() generates https:// URLs and Talisman's force_https
        # doesn't redirect-loop behind the TLS-terminating proxy.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
        Talisman(
            app,
            force_https=True,  # Enforce HTTPS in production
            strict_transport_security=True,
            strict_transport_security_max_age=31536000,  # 1 year HSTS
            strict_transport_security_include_subdomains=True,
            content_security_policy={
                "default-src": ["'self'"],
                "script-src": ["'self'"],  # Only allow scripts from same origin (static/app.js)
                "style-src": ["'self'"],  # CSS only from same origin
                "img-src": ["'self'", "data:"],  # Images and data URIs
                "font-src": ["'self'"],  # Fonts only from same origin
                "frame-ancestors": ["'none'"],  # Prevent clickjacking
                "base-uri": ["'self'"],  # Restrict base tag
                "form-action": ["'self'"],  # Restrict form submissions
            },
            referrer_policy="strict-origin-when-cross-origin",  # Control referer leakage
        )

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("AUTHENTICATION_PORT", 8014))
    debug = os.getenv("ENV", "production").lower() == "development"
    app.run(debug=debug, port=port)



