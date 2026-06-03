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

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final

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

CONFIG_MODULE_ID: Final[str] = os.getenv("S43_CONFIG_MODULE_ID", "sentinel43-api-config")
CONFIG_VERSION: Final[str] = os.getenv("SENTINEL_VERSION", "0.1.0")
WATCHTOWER_URL: Final[str] = os.getenv("S43_WATCHTOWER_URL", "http://s43-watchtower:9100").rstrip("/")
WATCHTOWER_TIMEOUT: Final[float] = float(os.getenv("S43_WATCHTOWER_TIMEOUT", "2.0"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _watchtower_request(
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = f"{WATCHTOWER_URL}{path}"
    data = None
    headers = {"Content-Type": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        url=url,
        data=data,
        headers=headers,
        method=method.upper(),
    )

    try:
        with urllib.request.urlopen(request, timeout=WATCHTOWER_TIMEOUT) as response:
            body = response.read().decode("utf-8")
            if not body:
                return {"status_code": response.status}

            parsed = json.loads(body)
            if isinstance(parsed, dict):
                parsed.setdefault("status_code", response.status)
                return parsed

            return {"status_code": response.status, "body": parsed}

    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            detail = str(exc)

        return {
            "error": "watchtower_http_error",
            "status_code": exc.code,
            "detail": detail,
        }

    except Exception as exc:
        return {
            "error": "watchtower_unreachable",
            "detail": str(exc),
        }


def _register_config_with_watchtower() -> None:
    payload = {
        "module_id": CONFIG_MODULE_ID,
        "module_type": "api-config",
        "version": CONFIG_VERSION,
        "endpoint": None,
        "capabilities": [
            "environment_loading",
            "env_validation",
            "log_level_validation",
            "cors_normalization",
            "production_safety_warning",
            "config_drift_reporting",
        ],
        "metadata": {
            "timestamp": utc_now(),
        },
    }

    _watchtower_request("POST", "/watchtower/modules/register", payload)


def _report_config_status(
    status: str,
    event: str,
    details: dict[str, Any] | None = None,
) -> None:
    _register_config_with_watchtower()

    payload = {
        "name": CONFIG_MODULE_ID,
        "status": status,
        "version": CONFIG_VERSION,
        "details": {
            "event": event,
            "timestamp": utc_now(),
            **(details or {}),
        },
    }

    _watchtower_request("POST", "/watchtower/dependencies/report", payload)


def _report_config_event(
    status: str,
    event: str,
    details: dict[str, Any] | None = None,
) -> None:
    payload = {
        "event": {
            "kind": "config",
            "source": CONFIG_MODULE_ID,
            "status": status,
            "drift_detected": status in {"degraded", "failed"},
            "details": {
                "event": event,
                "timestamp": utc_now(),
                **(details or {}),
            },
        }
    }

    _watchtower_request("POST", "/watchtower/analyze", payload)


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

    _report_config_status(
        status="degraded",
        event="invalid_boolean_env",
        details={
            "env_name": name,
            "raw_value": value,
            "default_used": default,
        },
    )

    _report_config_event(
        status="degraded",
        event="invalid_boolean_env",
        details={
            "env_name": name,
            "raw_value": value,
            "default_used": default,
        },
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

        _report_config_status(
            status="degraded",
            event="invalid_integer_env",
            details={
                "env_name": name,
                "raw_value": value,
                "default_used": default,
            },
        )

        _report_config_event(
            status="degraded",
            event="invalid_integer_env",
            details={
                "env_name": name,
                "raw_value": value,
                "default_used": default,
            },
        )

        return default


def _normalize_log_level(value: str | None, default: str = "INFO") -> str:
    level = (value or "").strip().upper()

    if level in _VALID_LOG_LEVELS:
        return level

    logger.warning("Invalid log level %r; using default %s", value, default)

    _report_config_status(
        status="degraded",
        event="invalid_log_level",
        details={
            "raw_value": value,
            "default_used": default,
            "valid_levels": sorted(_VALID_LOG_LEVELS),
        },
    )

    _report_config_event(
        status="degraded",
        event="invalid_log_level",
        details={
            "raw_value": value,
            "default_used": default,
            "valid_levels": sorted(_VALID_LOG_LEVELS),
        },
    )

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

    def safe_dict(self) -> dict[str, Any]:
        return {
            "service_name": self.service_name,
            "version": self.version,
            "port": self.port,
            "log_level": self.log_level,
            "docs_enabled": self.docs_enabled,
            "cors_allow_origins": self.cors_allow_origins,
            "engine_factory": self.engine_factory,
            "store_factory": self.store_factory,
            "environment": self.environment,
        }


def load_config() -> ApiConfig:
    _report_config_status(
        status="online",
        event="config_load_started",
        details={},
    )

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

        _report_config_status(
            status="degraded",
            event="docs_enabled_in_production",
            details={
                "environment": config.environment,
                "docs_enabled": config.docs_enabled,
            },
        )

        _report_config_event(
            status="degraded",
            event="docs_enabled_in_production",
            details={
                "environment": config.environment,
                "docs_enabled": config.docs_enabled,
            },
        )

    _report_config_status(
        status="online",
        event="config_loaded",
        details={
            "config": config.safe_dict(),
        },
    )

    return config


__all__ = [
    "ApiConfig",
    "load_config",
    "DEFAULT_ENGINE_FACTORY",
    "DEFAULT_STORE_FACTORY",
]