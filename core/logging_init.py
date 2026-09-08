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

Explicit configuration only.

No environment reads.
No Watchtower/network reporting.
No import-time configuration.
No implicit initialization from get_logger().
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Final


_VALID_LEVELS: Final[frozenset[str]] = frozenset(
    {
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    }
)

_SENTINEL_HANDLER_MARKER: Final[str] = "_s43_owned_handler"

_DEFAULT_FORMAT: Final[str] = (
    "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    level: str = "INFO"
    log_to_file: bool = False
    log_file: Path | None = None
    max_bytes: int = 5 * 1024 * 1024
    backup_count: int = 5

    def __post_init__(self) -> None:
        normalized_level = str(
            self.level
        ).strip().upper()

        if normalized_level not in _VALID_LEVELS:
            raise ValueError(
                f"invalid log level {self.level!r}; "
                f"expected one of {sorted(_VALID_LEVELS)}"
            )

        if self.log_to_file and self.log_file is None:
            raise ValueError(
                "log_file is required when log_to_file is true"
            )

        if not 1024 <= self.max_bytes <= 1024 * 1024 * 1024:
            raise ValueError(
                "max_bytes must be between 1024 and 1073741824"
            )

        if not 0 <= self.backup_count <= 100:
            raise ValueError(
                "backup_count must be between 0 and 100"
            )

        object.__setattr__(
            self,
            "level",
            normalized_level,
        )

        if self.log_file is not None:
            object.__setattr__(
                self,
                "log_file",
                Path(
                    self.log_file
                ),
            )


def _mark_sentinel_handler(
    handler: logging.Handler,
) -> logging.Handler:
    setattr(
        handler,
        _SENTINEL_HANDLER_MARKER,
        True,
    )
    return handler


def _is_sentinel_handler(
    handler: logging.Handler,
) -> bool:
    return bool(
        getattr(
            handler,
            _SENTINEL_HANDLER_MARKER,
            False,
        )
    )


def configure_logging(
    config: LoggingConfig,
) -> None:
    """Configure Sentinel-owned root handlers.

    Existing non-Sentinel handlers are preserved. Existing Sentinel-owned
    handlers are replaced so repeated explicit configuration is deterministic.
    """
    if not isinstance(
        config,
        LoggingConfig,
    ):
        raise TypeError(
            "config must be LoggingConfig"
        )

    root = logging.getLogger()
    level = getattr(
        logging,
        config.level,
    )

    formatter = logging.Formatter(
        _DEFAULT_FORMAT
    )

    for handler in tuple(
        root.handlers
    ):
        if _is_sentinel_handler(
            handler
        ):
            root.removeHandler(
                handler
            )
            try:
                handler.close()
            except Exception:
                pass

    stream_handler = _mark_sentinel_handler(
        logging.StreamHandler(
            sys.stdout
        )
    )
    stream_handler.setLevel(
        level
    )
    stream_handler.setFormatter(
        formatter
    )

    root.setLevel(
        level
    )
    root.addHandler(
        stream_handler
    )

    if not config.log_to_file:
        return

    assert config.log_file is not None

    try:
        file_handler = _mark_sentinel_handler(
            RotatingFileHandler(
                config.log_file,
                maxBytes=config.max_bytes,
                backupCount=config.backup_count,
                encoding="utf-8",
            )
        )

        file_handler.setLevel(
            level
        )
        file_handler.setFormatter(
            formatter
        )
        root.addHandler(
            file_handler
        )

    except OSError:
        # Console logging remains available. Startup policy may choose whether
        # inability to open the configured file is fatal.
        root.exception(
            "Sentinel file logging could not be configured"
        )


def reset_logging() -> None:
    """Remove and close only Sentinel-owned handlers."""
    root = logging.getLogger()

    for handler in tuple(
        root.handlers
    ):
        if not _is_sentinel_handler(
            handler
        ):
            continue

        root.removeHandler(
            handler
        )

        try:
            handler.close()
        except Exception:
            pass


def get_logger(
    name: str,
) -> logging.Logger:
    """Return a logger without configuring global logging as a side effect."""
    if not isinstance(
        name,
        str,
    ) or not name.strip():
        raise ValueError(
            "logger name must not be empty"
        )

    return logging.getLogger(
        name.strip()
    )


# Compatibility alias for older callers.
init_logging = configure_logging


__all__ = [
    "LoggingConfig",
    "configure_logging",
    "get_logger",
    "init_logging",
    "reset_logging",
]
