from __future__ import annotations

import json
import logging
import os
import sys
import urllib.request
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


LOGGING_MODULE_ID = os.getenv("S43_LOGGING_MODULE_ID", "sentinel43-logging")
LOGGING_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")

WATCHTOWER_URL = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
WATCHTOWER_TIMEOUT = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))

_VALID_LEVELS = {
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "CRITICAL",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _watchtower_report(status: str, event: str, details: dict[str, Any] | None = None) -> None:
    payload = {
        "name": LOGGING_MODULE_ID,
        "status": status,
        "version": LOGGING_VERSION,
        "details": {
            "event": event,
            "timestamp": utc_now(),
            **(details or {}),
        },
    }

    try:
        request = urllib.request.Request(
            f"{WATCHTOWER_URL}/watchtower/dependencies/report",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(request, timeout=WATCHTOWER_TIMEOUT)
    except Exception:
        pass


def _normalize_log_level(value: str | None) -> int:
    level = (value or os.getenv("SENTINEL_LOG_LEVEL", "INFO")).strip().upper()

    if level not in _VALID_LEVELS:
        _watchtower_report(
            "degraded",
            "invalid_log_level",
            {
                "raw_value": value,
                "default_used": "INFO",
            },
        )
        level = "INFO"

    return getattr(logging, level)


def init_logging(
    *,
    level: str | None = None,
    log_dir: str | Path | None = None,
    log_to_file: bool | None = None,
) -> None:
    root = logging.getLogger()

    if root.handlers:
        return

    resolved_level = _normalize_log_level(level)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(resolved_level)
    stream_handler.setFormatter(formatter)

    root.setLevel(resolved_level)
    root.addHandler(stream_handler)

    should_log_to_file = (
        str(os.getenv("SENTINEL_LOG_TO_FILE", "true")).strip().lower()
        in {"1", "true", "yes", "y", "on"}
        if log_to_file is None
        else log_to_file
    )

    if should_log_to_file:
        try:
            target_dir = Path(log_dir or os.getenv("SENTINEL_LOG_DIR", "./logs"))
            target_dir.mkdir(parents=True, exist_ok=True)

            file_handler = RotatingFileHandler(
                target_dir / "sentinel43.log",
                maxBytes=int(os.getenv("SENTINEL_LOG_MAX_BYTES", "5242880")),
                backupCount=int(os.getenv("SENTINEL_LOG_BACKUP_COUNT", "5")),
                encoding="utf-8",
            )
            file_handler.setLevel(resolved_level)
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)

        except Exception as exc:
            root.warning("File logging setup failed: %s", exc)

            _watchtower_report(
                "degraded",
                "file_logging_setup_failed",
                {
                    "error": str(exc),
                    "exception_type": type(exc).__name__,
                },
            )

    _watchtower_report(
        "online",
        "logging_initialized",
        {
            "level": logging.getLevelName(resolved_level),
            "file_logging": should_log_to_file,
        },
    )


def get_logger(name: str) -> logging.Logger:
    if not logging.getLogger().handlers:
        init_logging()

    return logging.getLogger(name)


__all__ = [
    "init_logging",
    "get_logger",
]