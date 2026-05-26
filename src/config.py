import base64
import json
import logging
import os

from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


def _load_secrets_manager() -> dict:
    """Fetch the secret bundle from AWS Secrets Manager.

    Triggered only when AWS_SECRETS_ARN is present in the environment.
    The secret is expected to be a JSON object whose keys map 1:1 to
    Settings field names (upper-cased env var names).

    Returns an empty dict when AWS_SECRETS_ARN is not set, allowing the
    normal pydantic-settings env-var / .env fallback to take over
    (local-dev path).
    """
    arn = os.environ.get("AWS_SECRETS_ARN")
    if not arn:
        return {}

    try:
        import boto3  # imported lazily — not required for local-dev

        client = boto3.client(
            "secretsmanager",
            endpoint_url=os.environ.get("AWS_ENDPOINT_URL"),
            region_name=os.environ.get("AWS_REGION", "us-east-1"),
        )
        response = client.get_secret_value(SecretId=arn)
        bundle: dict = json.loads(response["SecretString"])
        logger.info("Loaded config from AWS Secrets Manager")
        return bundle
    except Exception as exc:  # noqa: BLE001
        # Surface as a hard startup failure — a misconfigured secret store
        # must not silently fall back to empty/default values in cloud envs.
        raise RuntimeError(
            f"Failed to load secrets from AWS Secrets Manager ({arn}): {exc}"
        ) from exc


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    database_url: str = ""
    jwt_private_key_pem: str = ""
    jwt_public_key_pem: str = ""
    jwt_previous_public_key_pem: str = ""  # set during key rotation overlap window
    jwt_claim_namespace: str = "neosofia"
    env: str = "production"
    jwt_web_audience: str | list[str] = "authentication"
    valid_roles: str  # required; comma-separated WorkOS org membership roles, e.g. "admin,member"
    access_token_ttl_secs: int = 900   # 15 minutes
    service_token_ttl_secs: int = 300  # 5 minutes
    port: int = 8014
    trusted_proxy_hops: int = 1  # set to 0 in tests; increase for CDN + load balancer topologies
    web_concurrency: int = 2
    gunicorn_threads: int = 2
    gunicorn_timeout: int = 30
    gunicorn_keepalive: int = 5
    log_level: str = "info"
    frontend_url: str = "http://localhost:5173"
    csrf_secret_key: str = ""
    workos_api_key: str = ""
    workos_client_id: str = ""
    workos_cookie_password: str = ""
    workos_redirect_uri: str = "http://localhost:8014/callback"
    ratelimit_storage_uri: str = "memory://"
    max_content_length: int = 16_384

    @property
    def is_non_production(self) -> bool:
        return self.env.lower() in ("development", "test")

    def frontend_auth_callback_url(self) -> str:
        base = self.frontend_url.rstrip("/")
        if not base:
            return "/?auth=callback"
        return f"{base}?auth=callback"

    def model_post_init(self, __context: object) -> None:
        if not self.database_url.strip():
            raise ValueError("DATABASE_URL must be set")

        if not self.csrf_secret_key.strip():
            raise ValueError("CSRF_SECRET_KEY must be set")

        if not self.workos_cookie_password.strip():
            raise ValueError("WORKOS_COOKIE_PASSWORD must be set")

        if not self.valid_roles.strip():
            raise ValueError("VALID_ROLES must be set to a non-empty comma-separated list of accepted WorkOS org roles")
            
        if not self.jwt_private_key_pem or not self.jwt_public_key_pem:
            raise ValueError("JWT_PRIVATE_KEY_PEM and JWT_PUBLIC_KEY_PEM must be set")

        if self.env.lower() not in ("development", "test"):
            if not self.frontend_url.strip():
                raise ValueError("FRONTEND_URL must be set in non-development environments")
            if self.frontend_url.startswith("http://") and "localhost" not in self.frontend_url:
                raise ValueError("FRONTEND_URL must use https in non-development environments")
            
        if isinstance(self.jwt_web_audience, str) and "," in self.jwt_web_audience:
            object.__setattr__(self, "jwt_web_audience", [a.strip() for a in self.jwt_web_audience.split(",")])

        if isinstance(self.jwt_web_audience, str):
            object.__setattr__(self, "jwt_web_audience", [self.jwt_web_audience])

        if isinstance(self.jwt_web_audience, list):
            object.__setattr__(
                self,
                "jwt_web_audience",
                [a.strip() for a in self.jwt_web_audience if isinstance(a, str) and a.strip()],
            )

        # Decode base64 PEM keys injected via environment variables
        if self.jwt_private_key_pem and self.jwt_private_key_pem != "DEFAULT_PRIVATE_KEY":
            try:
                decoded = base64.b64decode(self.jwt_private_key_pem).decode("utf-8")
                object.__setattr__(self, "jwt_private_key_pem", decoded)
            except Exception as e:
                raise ValueError(f"Failed to decode base64 jwt_private_key_pem: {e}")
                
        if self.jwt_public_key_pem and self.jwt_public_key_pem != "DEFAULT_PUBLIC_KEY":
            try:
                decoded = base64.b64decode(self.jwt_public_key_pem).decode("utf-8")
                object.__setattr__(self, "jwt_public_key_pem", decoded)
            except Exception as e:
                raise ValueError(f"Failed to decode base64 jwt_public_key_pem: {e}")

        if self.jwt_previous_public_key_pem:
            try:
                decoded = base64.b64decode(self.jwt_previous_public_key_pem).decode("utf-8")
                object.__setattr__(self, "jwt_previous_public_key_pem", decoded)
            except Exception as e:
                raise ValueError(f"Failed to decode base64 jwt_previous_public_key_pem: {e}")


def _build_settings() -> Settings:
    """Construct Settings, merging Secrets Manager values when available.

    Priority (highest → lowest):
      1. Real environment variables (allows targeted overrides in any env)
      2. AWS Secrets Manager bundle  (cloud-dev / staging / prod)
      3. .env file                   (local-dev fallback)
      4. Field defaults
    """
    sm_values = _load_secrets_manager()
    if sm_values:
        # Inject fetched values as environment variables so pydantic-settings
        # picks them up at its normal env-var priority level, while still
        # allowing explicit env vars (e.g. set in docker-compose.cloud.yml)
        # to override individual keys.
        for key, value in sm_values.items():
            os.environ.setdefault(key, str(value))
    return Settings()  # type: ignore[call-arg]


# Module-level singleton — loaded once at import time.
settings = _build_settings()
