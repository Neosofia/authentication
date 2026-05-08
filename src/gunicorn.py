import logging
import sys

from gunicorn.glogging import Logger
from logenvelope.formatter import JSONFormatter

from src.config import settings

# --- Gunicorn Configuration ---
bind = f"0.0.0.0:{settings.port}"
workers = settings.web_concurrency
threads = settings.gunicorn_threads
timeout = settings.gunicorn_timeout
keepalive = settings.gunicorn_keepalive
preload_app = True
accesslog = "-"
errorlog = "/dev/stdout"
loglevel = settings.log_level
logger_class = "src.gunicorn.JSONLogger"

# --- Custom Logger ---
class JSONLogger(Logger):
    def setup(self, cfg) -> None:  # type: ignore[override]
        super().setup(cfg)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter(default_event_type="http.access"))
        for log in (self.error_log, self.access_log):
            log.handlers = [handler]
            log.propagate = False
