# =============================================================================
# Sentinel-43 Security Platform
# Core Logging Module
# =============================================================================

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .config import settings, LOG_ROOT


# =============================================================================
# Log Format
# =============================================================================

LOG_FORMAT = (
    "%(asctime)s | "
    "%(levelname)-8s | "
    "%(name)s | "
    "%(message)s"
)

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


# =============================================================================
# Logger Setup
# =============================================================================

def setup_logging() -> None:
    """
    Initializes Sentinel-43 logging system.
    Safe to call multiple times.
    """

    root_logger = logging.getLogger()

    if root_logger.handlers:
        return  # already configured

    level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    root_logger.setLevel(level)

    formatter = logging.Formatter(
        LOG_FORMAT,
        DATE_FORMAT
    )

    # --------------------------------------------------
    # Console Handler
    # --------------------------------------------------

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(level)

    root_logger.addHandler(console_handler)

    # --------------------------------------------------
    # File Handler (Rotating)
    # --------------------------------------------------

    log_file: Path = settings.LOG_FILE

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10,
        encoding="utf-8",
    )

    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)

    root_logger.addHandler(file_handler)


# =============================================================================
# Module Logger Access
# =============================================================================

def get_logger(name: str) -> logging.Logger:
    """
    Returns a properly configured Sentinel logger.
    """

    return logging.getLogger(name)


# =============================================================================
# Initialize Automatically
# =============================================================================

setup_logging()


# =============================================================================
# Export
# =============================================================================

__all__ = [
    "setup_logging",
    "get_logger",
]