"""
Sentinel-43 Logging Setup

Responsibilities:
- Configure logging from Settings
- Support console + optional file logging
- Optional JSON logs for production
- Idempotent and thread-safe
- NO side effects on import

This module must be called explicitly.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

# Public API
__all__ = ["configure_logging"]


# ----------------------------
# Internal state
# ----------------------------

_LOGGING_LOCK = threading.Lock()
_LOGGING_CONFIGURED = False


# ----------------------------
# Formatters
# ----------------------------

class JsonFormatter(logging.Formatter):
    """
    Minimal JSON log formatter.
    Designed for ingestion by log pipelines.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """
    Human-readable formatter for dev / local runs.
    """

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


# ----------------------------
# Core setup
# ----------------------------

def configure_logging(settings) -> None:
    """
    Configure global logging based on Settings.

    Safe to call multiple times.
    First call wins.
    """
    global _LOGGING_CONFIGURED

    if _LOGGING_CONFIGURED:
        return

    with _LOGGING_LOCK:
        if _LOGGING_CONFIGURED:
            return

        level = getattr(settings, "log_level", "INFO")
        use_json = bool(getattr(settings, "log_json", False))
        log_to_file = bool(getattr(settings, "log_to_file", False))

        root = logging.getLogger()
        root.setLevel(level)

        formatter = JsonFormatter() if use_json else TextFormatter()

        handlers: list[logging.Handler] = []

        # ----------------------------
        # Console handler (always)
        # ----------------------------
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        handlers.append(console)

        # ----------------------------
        # File handler (optional)
        # ----------------------------
        if log_to_file:
            try:
                log_dir: Path = getattr(settings, "log_dir")
                log_dir.mkdir(parents=True, exist_ok=True)

                logfile = log_dir / "sentinel43.log"

                file_handler = logging.handlers.RotatingFileHandler(
                    logfile,
                    maxBytes=50 * 1024 * 1024,  # 50 MB
                    backupCount=10,
                    encoding="utf-8",
                )
                file_handler.setFormatter(formatter)
                handlers.append(file_handler)

            except Exception as exc:
                # Fall back to console-only logging
                logging.basicConfig(level=level)
                logging.getLogger(__name__).warning(
                    "File logging disabled due to error: %s", exc
                )

        # ----------------------------
        # Attach handlers (cleanly)
        # ----------------------------
        # Remove any pre-existing handlers to avoid duplicates
        for h in list(root.handlers):
            root.removeHandler(h)

        for h in handlers:
            root.addHandler(h)

        # ----------------------------
        # Tame noisy libraries
        # ----------------------------
        logging.getLogger("uvicorn").setLevel(logging.INFO)
        logging.getLogger("uvicorn.error").setLevel(logging.INFO)
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

        logging.getLogger("asyncio").setLevel(logging.WARNING)

        _LOGGING_CONFIGURED = True

        logging.getLogger(__name__).info(
            "Logging configured | level=%s | json=%s | file=%s",
            level,
            use_json,
            log_to_file,
        )