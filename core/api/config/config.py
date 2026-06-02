# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 API configuration."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Final

logger = logging.getLogger(__name__)

_VALID_LOG_LEVELS: Final[set[str]] = {
    "DEBUG",
    "INFO",
    "WARNING",
    "ERROR",
    "CRITICAL",
}

_TRUE_VALUES: Final[set[str]] = {"1", "true", "t", "yes", "y", "on"}
_FALSE_VALUES: Final[set[str]] = {"0", "false", "f", "no", "n", "off"}

DEFAULT_ENGINE_FACTORY: Final[str] = "core.api.deps:dev_engine_factory"
DEFAULT_STORE_FACTORY: Final[str] = "core.api.deps:dev_store_factory"


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None:
        return default

    value = value.strip()
    return value if value else default


def _env_bool(name: str, default: bool = False) -> bool:
    value = _env(name)
    if value is None:
        return default

    normalized = value.lower()

    if normalized in _TRUE_VALUES:
        return True

    if normalized in _FALSE_VALUES:
        return False

    logger.warning(
        "Invalid boolean for %s=%r; using default %s",
        name,
        value,
        default,
    )
    return default


def _env_int(name: str, default: int) -> int:
    value = _env(name)
    if value is None:
        return default

    try:
        return int(value)
    except ValueError:
        logger.warning(
            "Invalid integer for %s=%r; using default %d",
            name,
            value,
            default,
        )
        return default


def _normalize_log_level(value: str | None, default: str = "INFO") -> str:
    level = (value or "").strip().upper()

    if level in _VALID_LOG_LEVELS:
        return level

    logger.warning("Invalid log level %r; using default %s", value, default)
    return default


def _normalize_environment(value: str | None) -> str:
    environment = (value or "development").strip().lower()
    return environment or "development"


def _normalize_cors_origins(value: str | None) -> tuple[str, ...]:
    raw = (value or "").strip()

    if not raw or raw == "*":
        return ("*",)

    origins = tuple(item.strip() for item in raw.split(",") if item.strip())
    return origins if origins else ("*",)


@dataclass(frozen=True, slots=True)
class ApiConfig:
    service_name: str = "sentinel-43-api"
    version: str = "0.1.0"

    host: str = "0.0.0.0"
    port: int = 8000

    log_level: str = "INFO"
    docs_enabled: bool = True
    cors_allow_origins: tuple[str, ...] = ("*",)

    engine_factory: str = DEFAULT_ENGINE_FACTORY
    store_factory: str = DEFAULT_STORE_FACTORY

    environment: str = "development"


def load_config() -> ApiConfig:
    config = ApiConfig(
        service_name=_env("SENTINEL_SERVICE_NAME", "sentinel-43-api"),
        version=_env("SENTINEL_VERSION", "0.1.0"),
        host=_env("SENTINEL_HOST", "0.0.0.0"),
        port=_env_int("SENTINEL_PORT", 8000),
        log_level=_normalize_log_level(_env("SENTINEL_LOG_LEVEL", "INFO")),
        docs_enabled=_env_bool("SENTINEL_DOCS_ENABLED", True),
        cors_allow_origins=_normalize_cors_origins(
            _env("SENTINEL_CORS_ALLOW_ORIGINS", "*")
        ),
        engine_factory=_env("SENTINEL_ENGINE_FACTORY", DEFAULT_ENGINE_FACTORY),
        store_factory=_env("SENTINEL_STORE_FACTORY", DEFAULT_STORE_FACTORY),
        environment=_normalize_environment(
            _env("SENTINEL_ENVIRONMENT", "development")
        ),
    )

    if config.environment == "production" and config.docs_enabled:
        logger.warning(
            "Docs are enabled in production; set SENTINEL_DOCS_ENABLED=false"
        )

    return config


__all__ = [
    "ApiConfig",
    "load_config",
    "DEFAULT_ENGINE_FACTORY",
    "DEFAULT_STORE_FACTORY",
]
