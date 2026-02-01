"""
Central logging initialization for Sentinel-43.

Rules:
- Initialized ONCE.
- No implicit side effects.
- Structured, predictable output.
- Safe for multi-module, multi-thread use.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional

# ---------------------------
# Configuration Defaults
# ---------------------------

LOG_LEVEL = os.getenv("SENTINEL_LOG_LEVEL", "INFO").upper()
LOG_DIR = Path(os.getenv("SENTINEL_LOG_DIR", "logs"))
LOG_FILE = os.getenv("SENTINEL_LOG_FILE", "sentinel43.log")

MAX_BYTES = int(os.getenv("SENTINEL_LOG_MAX_BYTES", 10 * 1024 * 1024))  # 10 MB
BACKUP_COUNT = int(os.getenv("SENTINEL_LOG_BACKUP_COUNT", 5))

LOG_FORMAT = (
    "%(asctime)s | %(levelname)s | %(name)s | "
    "%(filename)s:%(lineno)d | %(message)s"
)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


# ---------------------------
# Internal State Guard
# ---------------------------

_INITIALIZED = False


# ---------------------------
# Initialization
# ---------------------------

def init_logging(force: bool = False) -> None:
    """
    Initialize global logging configuration.

    Args:
        force: Reinitialize logging even if already initialized.
               Use sparingly. Future-you will regret abusing this.
    """
    global _INITIALIZED

    if _INITIALIZED and not force:
        return

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    root_logger.setLevel(LOG_LEVEL)

    # Remove any pre-existing handlers to avoid duplication
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(LOG_LEVEL)
    console_handler.setFormatter(formatter)

    # Rotating File Handler
    file_handler = logging.handlers.RotatingFileHandler(
        LOG_DIR / LOG_FILE,
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(LOG_LEVEL)
    file_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    # Silence noisy third-party libs
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    _INITIALIZED = True


# ---------------------------
# Logger Access
# ---------------------------

def get_logger(name: Optional[str] = None) -> logging.Logger:
    """
    Retrieve a module-specific logger.

    Logging must be initialized before use.
    """
    if not _INITIALIZED:
        init_logging()

    return logging.getLogger(name)