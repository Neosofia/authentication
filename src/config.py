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
        logger.info("Loaded config from Secrets Manager: %s", arn)
        return bundle
    except Exception as exc:  # noqa: BLE001
        # Surface as a hard startup failure — a misconfigured secret store
        # must not silently fall back to empty/default values in cloud envs.
        raise RuntimeError(
            f"Failed to load secrets from AWS Secrets Manager ({arn}): {exc}"
        ) from exc


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".local.env", extra="ignore")

    database_url: str = ""
    jwt_private_key_pem: str = ""
    jwt_public_key_pem: str = ""
    jwt_issuer: str = "https://auth.pdc.local"
    access_token_ttl_secs: int = 900   # 15 minutes
    machine_token_ttl_secs: int = 300  # 5 minutes

    def model_post_init(self, __context: object) -> None:
        # Docker Compose / shell env sourcing can pass PEM keys with literal \n
        # instead of real newlines. Normalize both fields here so callers always
        # receive valid PEM strings regardless of how they were injected.
        if self.jwt_private_key_pem:
            object.__setattr__(
                self, "jwt_private_key_pem", self.jwt_private_key_pem.replace("\\n", "\n")
            )
        if self.jwt_public_key_pem:
            object.__setattr__(
                self, "jwt_public_key_pem", self.jwt_public_key_pem.replace("\\n", "\n")
            )


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
    return Settings()


# Module-level singleton — loaded once at import time.
settings = _build_settings()
