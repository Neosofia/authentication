from pathlib import Path


def get_env_file_path() -> Path | None:
    """Return .env if it exists in the current working directory, else None.

    When None is returned, pydantic-settings falls back to real environment
    variables — the correct behaviour inside containers and CI.
    """
    path = Path(".env")
    return path if path.exists() else None
