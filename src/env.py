import os
from pathlib import Path

ENV_FILE_MAP = {
    "local": ".local.env",
    "development": ".dev.env",
    "dev": ".dev.env",
    "staging": ".staging.env",
    "production": ".prod.env",
    "prod": ".prod.env",
}


def _normalize_env_value(value: str | None) -> str:
    if value is None:
        return ""
    return value.strip().lower()


def get_env_file_path() -> Path | None:
    """Return the env file path to load for this process.

    Behavior:
      - If ENV_FILE is explicitly set, use that path.
      - Otherwise ENV must be set to one of the supported values.
      - For normal runtime environments, the selected file must exist.
      - For `ENV=test`, fall back to direct environment variables when no
        `.test.env` file is present.
    """
    explicit = os.environ.get("ENV_FILE")
    if explicit:
        path = Path(explicit)
        if not path.exists():
            raise FileNotFoundError(
                f"Explicit env file specified by ENV_FILE does not exist: {path}"
            )
        return path

    env_name = _normalize_env_value(os.environ.get("ENV"))
    if not env_name:
        raise RuntimeError(
            "ENV is required when ENV_FILE is not set. "
            "Set ENV=local|development|staging|production or set ENV_FILE explicitly."
        )

    env_file = Path(ENV_FILE_MAP.get(env_name, f".{env_name}.env"))
    if env_file.exists():
        return env_file

    if env_name == "test":
        return None

    raise FileNotFoundError(
        f"Environment file for ENV={env_name} does not exist: {env_file}"
    )
