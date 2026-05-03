import logging
import sys

from gunicorn.glogging import Logger

from logenvelope.formatter import JSONFormatter


class JSONLogger(Logger):
    def setup(self, cfg) -> None:  # type: ignore[override]
        super().setup(cfg)
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter(default_event_type="http.access"))
        for log in (self.error_log, self.access_log):
            log.handlers = [handler]
            log.propagate = False
