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

"""Sentinel-43 logging configuration.

Responsibilities:
    - configure Sentinel-owned console/file handlers
    - support text or JSON formatting
    - remain explicit, idempotent, and thread-safe
    - avoid import-time side effects
    - avoid removing handlers owned by other runtimes

Call configure_logging() explicitly during application startup.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final


__all__ = [
    "JsonFormatter",
    "TextFormatter",
    "configure_logging",
    "reset_logging_configuration",
]


_LOGGING_LOCK = threading.RLock()
_SENTINEL_HANDLER_MARKER: Final[str] = "_sentinel43_owned_handler"
_VALID_LEVELS: Final[frozenset[str]] = frozenset(
    {
        "CRITICAL",
        "ERROR",
        "WARNING",
        "INFO",
        "DEBUG",
        "NOTSET",
    }
)


class JsonFormatter(logging.Formatter):
    """Minimal UTC JSON formatter for structured log ingestion."""

    def format(
        self,
        record: logging.LogRecord,
    ) -> str:
        timestamp = datetime.fromtimestamp(
            record.created,
            tz=timezone.utc,
        ).isoformat()

        payload: dict[str, Any] = {
            "ts": timestamp,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }

        if record.exc_info:
            payload[
                "exception"
            ] = self.formatException(
                record.exc_info
            )

        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(
                ",",
                ":",
            ),
        )


class TextFormatter(logging.Formatter):
    """Human-readable UTC formatter for local/development use."""

    converter = time.gmtime

    def __init__(self) -> None:
        super().__init__(
            fmt=(
                "%(asctime)sZ | "
                "%(levelname)-8s | "
                "%(name)-24s | "
                "%(message)s"
            ),
            datefmt="%Y-%m-%dT%H:%M:%S",
        )


def _normalize_level(
    value: Any,
) -> str:
    level = str(
        value
        or "INFO"
    ).strip().upper()

    if level not in _VALID_LEVELS:
        raise ValueError(
            f"invalid log level {value!r}; "
            f"expected one of {sorted(_VALID_LEVELS)}"
        )

    return level


def _sentinel_handlers(
    root: logging.Logger,
) -> list[logging.Handler]:
    return [
        handler
        for handler in root.handlers
        if getattr(
            handler,
            _SENTINEL_HANDLER_MARKER,
            False,
        )
    ]


def _mark_owned(
    handler: logging.Handler,
) -> logging.Handler:
    setattr(
        handler,
        _SENTINEL_HANDLER_MARKER,
        True,
    )
    return handler


def configure_logging(
    settings: Any,
    *,
    enable_console: bool = True,
    enable_file: bool | None = None,
    max_log_bytes: int = 50 * 1024 * 1024,
    backup_count: int = 10,
) -> None:
    """Configure Sentinel-owned logging handlers.

    Repeated calls replace only handlers created by this module.
    Handlers owned by Uvicorn, tests, embedding hosts, or other libraries
    are left untouched.
    """
    if max_log_bytes < 1:
        raise ValueError(
            "max_log_bytes must be >= 1"
        )

    if backup_count < 0:
        raise ValueError(
            "backup_count must be >= 0"
        )

    level = _normalize_level(
        getattr(
            settings,
            "log_level",
            "INFO",
        )
    )

    use_json = bool(
        getattr(
            settings,
            "log_json",
            False,
        )
    )

    if enable_file is None:
        enable_file = bool(
            getattr(
                settings,
                "log_to_file",
                False,
            )
        )

    formatter: logging.Formatter = (
        JsonFormatter()
        if use_json
        else TextFormatter()
    )

    with _LOGGING_LOCK:
        root = logging.getLogger()
        root.setLevel(
            level
        )

        new_handlers: list[
            logging.Handler
        ] = []

        if enable_console:
            console = _mark_owned(
                logging.StreamHandler()
            )

            console.setLevel(
                level
            )
            console.setFormatter(
                formatter
            )

            new_handlers.append(
                console
            )

        file_logging_enabled = False

        if enable_file:
            log_dir_raw = getattr(
                settings,
                "log_dir",
                None,
            )

            if log_dir_raw is None:
                logging.getLogger(
                    __name__
                ).warning(
                    "File logging requested but settings.log_dir is missing; "
                    "continuing without file logging."
                )
            else:
                try:
                    log_dir = Path(
                        log_dir_raw
                    )

                    log_dir.mkdir(
                        parents=True,
                        exist_ok=True,
                    )

                    logfile = (
                        log_dir
                        / "sentinel43.log"
                    )

                    file_handler = _mark_owned(
                        logging.handlers.RotatingFileHandler(
                            logfile,
                            maxBytes=max_log_bytes,
                            backupCount=backup_count,
                            encoding="utf-8",
                        )
                    )

                    file_handler.setLevel(
                        level
                    )
                    file_handler.setFormatter(
                        formatter
                    )

                    new_handlers.append(
                        file_handler
                    )

                    file_logging_enabled = True

                except OSError:
                    logging.getLogger(
                        __name__
                    ).warning(
                        "File logging unavailable; continuing with remaining handlers.",
                        exc_info=True,
                    )

        for handler in _sentinel_handlers(
            root
        ):
            root.removeHandler(
                handler
            )

            try:
                handler.close()
            except Exception:
                pass

        for handler in new_handlers:
            root.addHandler(
                handler
            )

        logging.getLogger(
            "uvicorn"
        ).setLevel(
            logging.INFO
        )

        logging.getLogger(
            "uvicorn.error"
        ).setLevel(
            logging.INFO
        )

        logging.getLogger(
            "uvicorn.access"
        ).setLevel(
            logging.WARNING
        )

        logging.getLogger(
            "asyncio"
        ).setLevel(
            logging.WARNING
        )

        logging.getLogger(
            __name__
        ).info(
            "Logging configured | level=%s | json=%s | console=%s | file=%s",
            level,
            use_json,
            enable_console,
            file_logging_enabled,
        )


def reset_logging_configuration() -> None:
    """Remove only Sentinel-owned handlers.

    Primarily useful for tests or controlled application reloads.
    """
    with _LOGGING_LOCK:
        root = logging.getLogger()

        for handler in _sentinel_handlers(
            root
        ):
            root.removeHandler(
                handler
            )

            try:
                handler.close()
            except Exception:
                pass
