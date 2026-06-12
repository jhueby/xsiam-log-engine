from __future__ import annotations

import logging
import json
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)


class DiagRingHandler(logging.Handler):
    """Writes log records to the in-memory diagnostics ring buffer."""

    def emit(self, record: logging.LogRecord) -> None:
        from utils.diagnostics import get_buffer
        buf = get_buffer()
        if record.levelno < buf.threshold():
            return
        entry: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name.split(".")[-1],
            "message": record.getMessage(),
        }
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        buf.append(entry)


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    has_stream = any(isinstance(h, logging.StreamHandler) and not isinstance(h, DiagRingHandler)
                     for h in logger.handlers)
    has_diag = any(isinstance(h, DiagRingHandler) for h in logger.handlers)

    if not has_stream:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
    if not has_diag:
        logger.addHandler(DiagRingHandler())

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger
