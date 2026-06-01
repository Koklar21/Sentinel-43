# =============================================================================
# Copyright (c) 2026 Justin [LastName or Entity]
#
# Sentinel is dual-licensed:
#   (1) AGPL-3.0-or-later, or
#   (2) a commercial license (see COMMERCIAL_LICENSE.md).
#
# SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Sentinel-Commercial
# =============================================================================

"""Sentinel-43 API configuration.

Docker-safe config module for core.api.config.

Exports:
- ApiConfig
- load_config
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


DEFAULT_ENGINE_FACTORY = "core.api.deps:dev_engine_factory"
DEFAULT_STORE_FACTORY = "core.api.deps:dev_store_factory"


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.getenv(name)
    if value is None:
        return default

    value = value.strip()
    return value if value else default


def _env_bool(name: str, default: bool = False) -> bool:
    value = _env(name)
    if value is None:
        return default

    return value.lower() in {"1", "true", "t", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    value = _env(name)
    if value is None:
        return default

    try:
        return int(value)
    except ValueError:
        return default


def _normalize_log_level(value: str | None, default: str = "INFO") -> str:
    level = (value or "").strip().upper()
    return level if level in _VALID_LOG_LEVELS else default


def _normalize_cors_origins(value: str | None) -> str:
    raw = (value or "").strip()

    if not raw or raw == "*":
        return "*"

    origins = [item.strip() for item in raw.split(",") if item.strip()]
    return ",".join(origins) if origins else "*"


@dataclass(frozen=True, slots=True)
class ApiConfig:
    service_name: str = "sentinel-43-api"
    version: str = "0.1.0"

    host: str = "0.0.0.0"
    port: int = 8080

    log_level: str = "INFO"
    docs_enabled: bool = True
    cors_allow_origins: str = "*"

    engine_factory: str = DEFAULT_ENGINE_FACTORY
    store_factory: str = DEFAULT_STORE_FACTORY

    environment: str = "development"


def load_config() -> ApiConfig:
    """Load API configuration from environment variables."""

    return ApiConfig(
        service_name=_env("SENTINEL_SERVICE_NAME", "sentinel-43-api") or "sentinel-43-api",
        version=_env("SENTINEL_VERSION", "0.1.0") or "0.1.0",
        host=_env("SENTINEL_HOST", "0.0.0.0") or "0.0.0.0",
        port=_env_int("SENTINEL_PORT", 8080),
        log_level=_normalize_log_level(_env("SENTINEL_LOG_LEVEL", "INFO")),
        docs_enabled=_env_bool("SENTINEL_DOCS_ENABLED", True),
        cors_allow_origins=_normalize_cors_origins(
            _env("SENTINEL_CORS_ALLOW_ORIGINS", "*")
        ),
        engine_factory=_env("SENTINEL_ENGINE_FACTORY", DEFAULT_ENGINE_FACTORY)
        or DEFAULT_ENGINE_FACTORY,
        store_factory=_env("SENTINEL_STORE_FACTORY", DEFAULT_STORE_FACTORY)
        or DEFAULT_STORE_FACTORY,
        environment=_env("SENTINEL_ENVIRONMENT", "development") or "development",
    )


__all__ = [
    "ApiConfig",
    "load_config",
    "DEFAULT_ENGINE_FACTORY",
    "DEFAULT_STORE_FACTORY",
]
