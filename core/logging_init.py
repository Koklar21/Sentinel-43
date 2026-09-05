# =============================================================================
# Sentinel-43
#
# Copyright (c) 2026 Justin Armstrong
# All Rights Reserved.
#
# This file is part of the Sentinel-43 platform and constitutes original
# intellectual property of the copyright holder.
#
# Sentinel-43 is distributed under a dual-license model:
#
#   1. GNU Affero General Public License (AGPL v3.0)
#      for open-source use, modification, and distribution.
#
#   2. Commercial License
#      for proprietary, enterprise, government, or other commercial use
#      not permitted under the AGPL v3.0.
#
# Unauthorized copying, redistribution, relicensing, reverse engineering,
# or commercial exploitation outside the terms of the applicable license
# is strictly prohibited.
#
# By accessing, modifying, distributing, or using this software, you agree
# to comply with the terms of the applicable license.
#
# License Information:
# AGPL v3.0: https://www.gnu.org/licenses/agpl-3.0.en.html
#
# Commercial Licensing:
# Contact the copyright holder for commercial licensing terms.
#
# Sentinel-43™
# Original Work and Protected Intellectual Property.
# =============================================================================

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


LOGGING_MODULE_ID = os.getenv("S43_LOGGING_MODULE_ID", "sentinel43-logging")
LOGGING_VERSION = os.getenv("SENTINEL_VERSION", "0.1.0")

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
    # DEFECT_INVENTORY.md D-16: this used to build the request without the
    # internal service token, so it 401'd against Watchtower on every call
    # and the bare `except Exception: pass` swallowed that silently — an
    # invalid SENTINEL_LOG_LEVEL never actually reached Watchtower. Deferred
    # import: this module initializes logging very early in process startup
    # and must not take on an import-time dependency on core.monitoring.
    from core.monitoring.watchtower_client import watchtower_request

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
    watchtower_request("POST", "/watchtower/dependencies/report", payload)


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
