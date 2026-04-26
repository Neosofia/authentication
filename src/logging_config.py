"""
Logging configuration using logenvelope for structured JSON logging.

All authentication events are logged using the log envelope schema.
"""

from logenvelope import JSONFormatter, log_event as _log_event
from logenvelope import setup_logging as _setup_logging


def setup_logging(name: str = "auth") -> None:
    """Initialize logenvelope for this service."""
    _setup_logging(name)


# Re-export from logenvelope
log_event = _log_event

__all__ = ["JSONFormatter", "log_event", "setup_logging"]
