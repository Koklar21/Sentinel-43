# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# Sentinel-43 is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 core logging configuration."""

from __future__ import annotations

import logging
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Final

from .config import Settings, ensure_runtime_directories, settings


LOG_FORMAT: Final[str] = (
    "%(asctime)sZ | "
    "%(levelname)-8s | "
    "%(name)s | "
    "%(message)s"
)

DATE_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S"

DEFAULT_MAX_LOG_BYTES: Final[int] = 10 * 1024 * 1024
DEFAULT_BACKUP_COUNT: Final[int] = 10

_SENTINEL_HANDLER_MARKER: Final[str] = "_sentinel43_handler"


class UTCFormatter(logging.Formatter):
    """Logging formatter that emits timestamps in UTC."""

    converter = time.gmtime


def _is_sentinel_handler(handler: logging.Handler) -> bool:
    return bool(getattr(handler, _SENTINEL_HANDLER_MARKER, False))


def _mark_sentinel_handler(handler: logging.Handler) -> None:
    setattr(handler, _SENTINEL_HANDLER_MARKER, True)


def _resolve_level(config: Settings) -> int:
    level = getattr(logging, config.log_level.upper(), None)

    if not isinstance(level, int):
        raise ValueError(
            f"Invalid configured log level: {config.log_level!r}"
        )

    return level


def setup_logging(
    config: Settings = settings,
    *,
    enable_console: bool = True,
    enable_file: bool = True,
    max_log_bytes: int = DEFAULT_MAX_LOG_BYTES,
    backup_count: int = DEFAULT_BACKUP_COUNT,
) -> None:
    """
    Configure Sentinel-43 logging.

    Safe to call repeatedly. Only handlers created by Sentinel-43 are
    considered when determining whether setup has already occurred.
    Existing third-party/root handlers are left untouched.
    """
    if max_log_bytes < 1:
        raise ValueError("max_log_bytes must be greater than zero")

    if backup_count < 0:
        raise ValueError("backup_count must not be negative")

    root_logger = logging.getLogger()
    level = _resolve_level(config)

    root_logger.setLevel(level)

    formatter = UTCFormatter(
        LOG_FORMAT,
        DATE_FORMAT,
    )

    sentinel_handlers = [
        handler
        for handler in root_logger.handlers
        if _is_sentinel_handler(handler)
    ]

    if sentinel_handlers:
        for handler in sentinel_handlers:
            handler.setLevel(level)
            handler.setFormatter(formatter)
        return

    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(formatter)
        _mark_sentinel_handler(console_handler)
        root_logger.addHandler(console_handler)

    if enable_file:
        try:
            ensure_runtime_directories(config)

            log_file: Path = config.log_file

            file_handler = RotatingFileHandler(
                filename=log_file,
                maxBytes=max_log_bytes,
                backupCount=backup_count,
                encoding="utf-8",
                delay=True,
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            _mark_sentinel_handler(file_handler)
            root_logger.addHandler(file_handler)

        except OSError:
            # Console logging remains available. Do not recursively log this
            # failure through a handler that may itself be broken.
            print(
                f"Sentinel-43 warning: unable to configure file logging at "
                f"{config.log_file}",
                file=sys.stderr,
            )


def get_logger(name: str) -> logging.Logger:
    """Return a named logger within the configured logging hierarchy."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("logger name must be a non-empty string")

    return logging.getLogger(name.strip())


__all__ = [
    "DATE_FORMAT",
    "LOG_FORMAT",
    "UTCFormatter",
    "get_logger",
    "setup_logging",
]
