from dotenv import load_dotenv
from flask import Flask
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()  # no-op in containers where env vars come from the runtime

# Extensions must be imported after load_dotenv so env vars are available.
from authorization_in_the_middle import CedarEvaluator, FilesystemPolicySetSource  # noqa: E402
from src.config import settings  # noqa: E402
from src.bootstrap.extensions import limiter, talisman  # noqa: E402
from src.bootstrap.logging import setup_logging  # noqa: E402
from src.authorization.entities import NAMESPACE  # noqa: E402
from src.routes import auth, idp, token, health, services, tenants  # noqa: E402


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)

    if config:
        app.config.update(config)

    app.config["SECRET_KEY"] = settings.csrf_secret_key

    # Configure CORS to explicitly trust the FRONTEND_URL if it is separated.
    # We must allow credentials so sealed session cookies can be sent by the frontend browser.
    CORS(app, origins=[settings.frontend_url], supports_credentials=True, max_age=86400)

    # Reject request bodies larger than this to prevent body-flood DoS.
    # Bodies here are only form fields / small JSON; JWTs arrive in headers, not bodies.
    app.config["MAX_CONTENT_LENGTH"] = settings.max_content_length

    setup_logging()
    limiter.init_app(app)

    app.config["JWT_PUBLIC_KEY"] = settings.jwt_public_key_pem
    app.config["JWT_AUDIENCE"] = settings.jwt_web_audience
    app.config["JWT_CLAIM_NAMESPACE"] = settings.jwt_claim_namespace
    app.config["CEDAR_NAMESPACE"] = NAMESPACE

    policy_source = FilesystemPolicySetSource(
        settings.authorization_policies_dir,
        cache_ttl=settings.authorization_policy_cache_ttl,
    )
    app.extensions["cedar_evaluator"] = CedarEvaluator(policy_source=policy_source)

    # Public routes (no Cedar): health, OIDC login/callback/logout, JWKS, token issuance.
    # Protected routes use @with_security + policies/policy.cedar: tenants, services, idp.
    app.register_blueprint(auth.bp)
    app.register_blueprint(token.bp)
    app.register_blueprint(health.bp)
    app.register_blueprint(services.bp)
    app.register_blueprint(tenants.bp)
    app.register_blueprint(idp.bp)

    # Initialize security headers (L2: Flask-Talisman only in production)
    # In development, CSP can be restrictive; production deployments require strict headers
    if not settings.is_non_production:
        # Trust the reverse proxy in front of the service (like Railway's internal
        # router or AWS ALB). ProxyFix makes Flask honour X-Forwarded-Proto/Host
        # so url_for() generates https:// URLs and Talisman's force_https doesn't
        # redirect-loop behind the TLS-terminating proxy.
        app.wsgi_app = ProxyFix(
            app.wsgi_app,
            x_for=settings.trusted_proxy_hops,
            x_proto=settings.trusted_proxy_hops,
            x_host=settings.trusted_proxy_hops,
            x_prefix=settings.trusted_proxy_hops,
        )
        talisman.init_app(
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
