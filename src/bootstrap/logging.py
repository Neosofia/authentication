"""Logging configuration using logenvelope for structured JSON logging."""

from logenvelope import log_event as _log_event
from logenvelope import setup_logging as _setup_logging


def setup_logging(name: str = "auth", level: str | None = None) -> None:
    """Initialize logenvelope for this service."""
    _setup_logging(name, level)


def exc_type_name(exc: BaseException) -> str:
    """Exception class name for structured logs (no message / PII)."""
    return type(exc).__name__


def log_exception(event_type: str, exc: BaseException, **fields) -> None:
    """Log an event with error_class set to the exception type name."""
    _log_event(event_type, error_class=exc_type_name(exc), **fields)


# Re-export from logenvelope
log_event = _log_event

__all__ = ["exc_type_name", "log_event", "log_exception", "setup_logging"]
