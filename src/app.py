import os

from dotenv import load_dotenv
from flask import Flask
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()  # no-op in containers where env vars come from the runtime

# Extensions must be imported after load_dotenv so env vars are available.
from src.config import settings  # noqa: E402
from src.bootstrap.extensions import csrf, cookie_password, limiter  # noqa: E402
from src.bootstrap.logging import setup_logging  # noqa: E402
from src.routes import auth, token, profile, health, openapi  # noqa: E402


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)

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

    app.register_blueprint(auth.bp)
    app.register_blueprint(token.bp)
    app.register_blueprint(profile.bp)
    app.register_blueprint(health.bp)
    app.register_blueprint(openapi.bp)


    # Pre-load OpenAPI spec at startup to fail fast if it's missing or invalid
    token._load_openapi_spec()

    # Initialize security headers (L2: Flask-Talisman only in production)
    # In development, CSP can be restrictive; production deployments require strict headers
    is_development = os.getenv("ENV", "production").lower() in ("development", "test")

    if not is_development:
        # Trust the reverse proxy in front of the service (Traefik on PVE/AWS,
        # or Railway's internal router). ProxyFix makes Flask honour
        # X-Forwarded-Proto/Host so url_for() generates https:// URLs and
        # Talisman's force_https doesn't redirect-loop behind the TLS-terminating
        # proxy. Set TRUSTED_PROXY_HOPS=2 if a CDN sits in front of the proxy.
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=settings.trusted_proxy_hops,
            x_proto=settings.trusted_proxy_hops,
            x_host=settings.trusted_proxy_hops,
            x_prefix=settings.trusted_proxy_hops,
        )
        Talisman(
            app,
            force_https=True,
            strict_transport_security=True,
            strict_transport_security_max_age=31536000,
            strict_transport_security_include_subdomains=True,
            content_security_policy={
                "default-src": ["'self'"],
                "script-src": ["'self'"],
                "style-src": ["'self'"],
                "img-src": ["'self'", "data:"],
                "font-src": ["'self'"],
                "frame-ancestors": ["'none'"],
                "base-uri": ["'self'"],
                "form-action": ["'self'"],
            },
            referrer_policy="strict-origin-when-cross-origin",
        )

    return app


app = create_app()
